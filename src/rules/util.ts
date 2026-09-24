import type * as A from "../parser/ast.ts";
import { walk } from "../parser/walk.ts";
import type { FileContext } from "../engine/types.ts";
import type { GmlFile } from "../project/loader.ts";
import { getBuiltinFunction, getBuiltinVariable } from "../semantic/builtins.ts";
import type { ProjectIndex } from "../semantic/project-index.ts";
import type { FileScopes } from "../semantic/scope.ts";

export const LOOP_TYPES = new Set(["WhileStatement", "DoUntilStatement", "RepeatStatement", "ForStatement"]);
export const FUNCTION_TYPES = new Set(["FunctionDeclaration", "FunctionExpression"]);

/** Names that suggest a secret or credential. */
export const SENSITIVE_NAME = /(pass(word|wd|phrase)?|pwd|secret|api_?key|apikey|access_?key|private_?key|auth(_?token)?|token|session_?(id|key|token)|credential|client_?secret|bearer|jwt|webhook)/i;
/** Names that look sensitive but are not (keyboard keys, token counters...). */
export const NOT_SENSITIVE_NAME = /(key(board|code|_?press|_?check|_?up|_?down|_?left|_?right|_?count|frame|_?map|_?index|_?name|s_?held)|token_?(count|index|type|list|pos)|passive|pass_?(through|count|index)|bypass|compass|password_?(length|field|box|input|prompt|label|hint|min|max)|_?public_?key)/i;

export function isSensitiveName(name: string): boolean {
  return SENSITIVE_NAME.test(name) && !NOT_SENSITIVE_NAME.test(name);
}

/** Inside a loop of the current function (does not cross function boundaries). */
export function isInLoop(ancestors: readonly A.Node[]): boolean {
  for (let i = ancestors.length - 1; i >= 0; i--) {
    const t = ancestors[i].type;
    if (FUNCTION_TYPES.has(t)) return false;
    if (LOOP_TYPES.has(t)) return true;
  }
  return false;
}

/** Inside a nested function (method, callback) rather than the event/script body itself. */
export function isInFunction(ancestors: readonly A.Node[]): boolean {
  return ancestors.some((a) => FUNCTION_TYPES.has(a.type));
}

/** Resolves an expression to a compile-time string when possible. */
export function staticString(expr: A.Expression | null | undefined, index: ProjectIndex, depth = 0): string | undefined {
  if (!expr || depth > 8) return undefined;
  switch (expr.type) {
    case "StringLiteral":
      return expr.value;
    case "TemplateString":
      return expr.expressions.length === 0 ? expr.quasis[0] : undefined;
    case "BinaryExpression":
      if (expr.operator === "+") {
        const l = staticString(expr.left, index, depth + 1);
        const r = staticString(expr.right, index, depth + 1);
        return l !== undefined && r !== undefined ? l + r : undefined;
      }
      return undefined;
    case "Identifier": {
      const macro = index.macros.get(expr.name);
      if (macro?.length === 1 && macro[0].node.value) return staticString(macro[0].node.value, index, depth + 1);
      return undefined;
    }
    default:
      return undefined;
  }
}

/** The leading constant text of a string expression: `"http://" + host` → `http://`. */
export function staticPrefix(expr: A.Expression | null | undefined, index: ProjectIndex, depth = 0): string | undefined {
  if (!expr || depth > 8) return undefined;
  const full = staticString(expr, index, depth);
  if (full !== undefined) return full;
  if (expr.type === "BinaryExpression" && expr.operator === "+") return staticPrefix(expr.left, index, depth + 1);
  if (expr.type === "TemplateString") return expr.quasis[0];
  return undefined;
}

export type StaticType = "string" | "number" | "unknown";

/** Best-effort static type of an expression, used to find string + number additions. */
export function staticType(expr: A.Expression, ctx: { index: ProjectIndex; scopes: FileScopes }, depth = 0): StaticType {
  if (depth > 10) return "unknown";
  switch (expr.type) {
    case "StringLiteral":
    case "TemplateString":
      return "string";
    case "NumberLiteral":
      return "number";
    case "BooleanLiteral":
      return "number";
    case "UnaryExpression":
      return expr.operator === "-" || expr.operator === "+" || expr.operator === "~" ? (staticType(expr.argument, ctx, depth + 1) === "number" ? "number" : "unknown") : "unknown";
    case "BinaryExpression": {
      if (expr.operator === "+") {
        const l = staticType(expr.left, ctx, depth + 1);
        const r = staticType(expr.right, ctx, depth + 1);
        if (l === "string" || r === "string") return l === r || l === "unknown" || r === "unknown" ? "string" : "unknown";
        return l === "number" && r === "number" ? "number" : "unknown";
      }
      if (["-", "*", "/", "%", "div", "&", "|", "^", "<<", ">>"].includes(expr.operator)) {
        return "number";
      }
      if (["==", "!=", "<", "<=", ">", ">=", "&&", "||", "^^"].includes(expr.operator)) return "number";
      return "unknown";
    }
    case "CallExpression": {
      if (expr.callee.type !== "Identifier") return "unknown";
      const ref = ctx.scopes.refOf.get(expr.callee);
      if (ref && ref.binding.kind !== "free") return "unknown";
      if (ctx.index.globalFunctions.has(expr.callee.name)) return "unknown";
      const fn = getBuiltinFunction(expr.callee.name);
      if (!fn) return "unknown";
      if (fn.returnType === "String") return "string";
      if (fn.returnType === "Real" || fn.returnType === "Bool") return "number";
      return "unknown";
    }
    case "Identifier": {
      const ref = ctx.scopes.refOf.get(expr);
      if (ref?.binding.kind === "local") return localType(ref.binding.decl.name, ref.binding.decl, ctx, depth);
      if (ref && ref.binding.kind === "free" && !ctx.index.macros.has(expr.name)) {
        if (!ctx.index.assignedNames.has(expr.name)) {
          const v = getBuiltinVariable(expr.name);
          if (v && (v.type === "Real" || v.type === "Bool")) return "number";
          return "unknown";
        }
        return numericInstanceVars(ctx.index).has(expr.name) ? "number" : "unknown";
      }
      return "unknown";
    }
    default:
      return "unknown";
  }
}

const numericVarCache = new WeakMap<ProjectIndex, Set<string>>();

/**
 * Instance/struct variable names whose every assignment in the project is a number
 * literal or arithmetic on numbers (e.g. `hp = 3`, `hp -= 1`, `hp++`).
 */
export function numericInstanceVars(index: ProjectIndex): Set<string> {
  const cached = numericVarCache.get(index);
  if (cached) return cached;
  const numeric = new Set<string>();
  const poisoned = new Set<string>();
  for (const obj of index.project.objects.values()) for (const p of obj.properties) poisoned.add(p);
  const isNumber = (e: A.Expression): boolean => {
    switch (e.type) {
      case "NumberLiteral":
        return true;
      case "UnaryExpression":
        return (e.operator === "-" || e.operator === "+") && isNumber(e.argument);
      case "BinaryExpression":
        return ["-", "*", "/", "%", "div"].includes(e.operator) || (e.operator === "+" && isNumber(e.left) && isNumber(e.right));
      case "CallExpression": {
        if (e.callee.type !== "Identifier" || index.globalFunctions.has(e.callee.name)) return false;
        const fn = getBuiltinFunction(e.callee.name);
        return fn?.returnType === "Real";
      }
      default:
        return false;
    }
  };
  const record = (name: string, value: A.Expression | null, op: string) => {
    if (poisoned.has(name)) return;
    const ok = op === "-=" || op === "*=" || op === "/=" || op === "%=" || op === "++" || op === "--" || ((op === "=" || op === "+=") && value !== null && isNumber(value));
    if (ok) numeric.add(name);
    else {
      poisoned.add(name);
      numeric.delete(name);
    }
  };
  const nameOf = (t: A.Expression): string | undefined => (t.type === "Identifier" ? t.name : t.type === "MemberExpression" ? t.property.name : undefined);
  for (const [file, scopes] of index.scopes) {
    walk(file.ast, (n) => {
      if (n.type === "AssignmentExpression") {
        const name = nameOf(n.left);
        if (!name) return;
        if (n.left.type === "Identifier" && scopes.refOf.get(n.left)?.binding.kind !== "free") return;
        record(name, n.right, n.operator);
      } else if (n.type === "UpdateExpression") {
        const name = nameOf(n.argument);
        if (name) record(name, null, n.operator);
      } else if (n.type === "StructProperty") {
        const key = n.key.type === "Identifier" ? n.key.name : n.key.value;
        if (n.value) record(key, n.value, "=");
        else poisoned.add(key);
      } else if (n.type === "VarDeclarator") {
        // A local with the same name is a different variable; nothing to record.
      }
    });
  }
  // Variables also set through reflection could hold anything.
  for (const name of numeric) if (index.stringLiterals.has(name)) numeric.delete(name);
  numericVarCache.set(index, numeric);
  return numeric;
}

function localType(_name: string, decl: import("../semantic/scope.ts").LocalDecl, ctx: { index: ProjectIndex; scopes: FileScopes }, depth: number): StaticType {
  // A local whose declaration and every assignment have the same static type.
  if (decl.kind !== "var") return "unknown";
  const declarator = findDeclarator(decl.id, ctx.scopes);
  if (!declarator?.init) return "unknown";
  const t = staticType(declarator.init, ctx, depth + 1);
  if (t === "unknown") return t;
  for (const w of decl.writes) {
    const assign = writeValue(w.id, ctx.scopes);
    if (!assign) return "unknown";
    if (assign.operator === "+=" && t === "string") continue; // string += anything stays a string (or errors)
    if (assign.operator !== "=" || staticType(assign.right, ctx, depth + 1) !== t) return "unknown";
  }
  return t;
}

const declaratorCache = new WeakMap<FileScopes, Map<A.Identifier, A.VarDeclarator>>();
const writeCache = new WeakMap<FileScopes, Map<A.Identifier, A.AssignmentExpression>>();

function buildCaches(scopes: FileScopes): void {
  const decls = new Map<A.Identifier, A.VarDeclarator>();
  const writes = new Map<A.Identifier, A.AssignmentExpression>();
  walk(scopes.root.node, (n) => {
    if (n.type === "VarDeclarator") decls.set(n.id, n);
    else if (n.type === "AssignmentExpression" && n.left.type === "Identifier") writes.set(n.left, n);
  });
  declaratorCache.set(scopes, decls);
  writeCache.set(scopes, writes);
}

export function findDeclarator(id: A.Identifier, scopes: FileScopes): A.VarDeclarator | undefined {
  if (!declaratorCache.has(scopes)) buildCaches(scopes);
  return declaratorCache.get(scopes)!.get(id);
}

function writeValue(id: A.Identifier, scopes: FileScopes): A.AssignmentExpression | undefined {
  if (!writeCache.has(scopes)) buildCaches(scopes);
  return writeCache.get(scopes)!.get(id);
}

/** Structural equality ignoring positions and parentheses. */
export function sameExpression(a: A.Node, b: A.Node): boolean {
  if (a.type !== b.type) return false;
  switch (a.type) {
    case "Identifier":
      return a.name === (b as A.Identifier).name;
    case "NumberLiteral":
      return a.value === (b as A.NumberLiteral).value;
    case "StringLiteral":
      return a.value === (b as A.StringLiteral).value;
    case "BooleanLiteral":
      return a.value === (b as A.BooleanLiteral).value;
    case "MemberExpression": {
      const o = b as A.MemberExpression;
      return a.property.name === o.property.name && sameExpression(a.object, o.object);
    }
    case "IndexExpression": {
      const o = b as A.IndexExpression;
      return a.accessor === o.accessor && a.indices.length === o.indices.length && sameExpression(a.object, o.object) && a.indices.every((x, i) => sameExpression(x, o.indices[i]));
    }
    case "UnaryExpression": {
      const o = b as A.UnaryExpression;
      return a.operator === o.operator && sameExpression(a.argument, o.argument);
    }
    case "BinaryExpression": {
      const o = b as A.BinaryExpression;
      return a.operator === o.operator && sameExpression(a.left, o.left) && sameExpression(a.right, o.right);
    }
    case "CallExpression": {
      const o = b as A.CallExpression;
      return a.arguments.length === o.arguments.length && sameExpression(a.callee, o.callee) && a.arguments.every((x, i) => sameExpression(x, o.arguments[i]));
    }
    default:
      return false;
  }
}

/** True when evaluating the expression cannot change state (no calls, assignments, ++/--). */
export function isSideEffectFree(expr: A.Expression): boolean {
  let pure = true;
  walk(expr, (n, c) => {
    if (n.type === "CallExpression" || n.type === "NewExpression" || n.type === "UpdateExpression" || n.type === "AssignmentExpression") {
      pure = false;
      c.skip();
    } else if (n.type === "FunctionExpression") c.skip();
  });
  return pure;
}

/** `self.x` → `x`, for comparing lvalues. */
export function normalizeSelf(expr: A.Expression): A.Expression {
  if (expr.type === "MemberExpression" && expr.object.type === "Identifier" && expr.object.name === "self") return expr.property;
  return expr;
}

export function describeEvent(file: GmlFile): string {
  if (file.event) return `the ${file.event.displayName} event of \`${file.resource}\``;
  return `\`${file.resource}\``;
}

/** Call name for `foo(...)` when `foo` is not shadowed by a local variable. */
export function builtinCallName(call: A.CallExpression, ctx: Pick<FileContext, "scopes">): string | undefined {
  if (call.callee.type !== "Identifier") return undefined;
  const ref = ctx.scopes.refOf.get(call.callee);
  if (ref && ref.binding.kind !== "free") return undefined;
  return call.callee.name;
}

export function code(s: string): string {
  return "`" + s + "`";
}

/**
 * Local-variable scope resolution for GML.
 *
 * GML semantics modelled here:
 * - `var` is function-scoped and takes effect textually: a reference before the
 *   declaration refers to an instance variable.
 * - Functions do NOT capture locals of enclosing functions (no closures). A nested
 *   function/method that names an outer `var` actually reads an instance variable.
 * - `with` blocks keep the current function's locals.
 */
import type * as A from "../parser/ast.ts";
import { forEachChild } from "../parser/walk.ts";

export interface LocalDecl {
  name: string;
  id: A.Identifier;
  kind: "var" | "param" | "static" | "catch";
  scope: Scope;
  reads: Reference[];
  writes: Reference[];
}

export interface Scope {
  node: A.Program | A.FunctionNode;
  parent: Scope | null;
  locals: Map<string, LocalDecl[]>;
  /** Uses `argument`, `argument_count` or `argumentN`. */
  usesArguments: boolean;
  children: Scope[];
}

export type Binding =
  | { kind: "local"; decl: LocalDecl }
  /** A local of an enclosing function, which GML does not capture. */
  | { kind: "uncaptured"; decl: LocalDecl }
  /** Not a local: instance/global variable, builtin, asset, function... */
  | { kind: "free" };

export interface Reference {
  id: A.Identifier;
  binding: Binding;
  access: "read" | "write" | "readwrite";
  /** Used as the callee of a call or `new`. */
  isCallee: boolean;
  scope: Scope;
  /** Nesting depth of `with` blocks at this reference (within the current function). */
  withDepth: number;
  /** Inside a `#macro` body (resolved at the use site, not here). */
  inMacro: boolean;
}

export interface FileScopes {
  root: Scope;
  refs: Reference[];
  refOf: Map<A.Identifier, Reference>;
  scopeOf: Map<A.Node, Scope>;
  /** `globalvar` names declared in this file. */
  globalvars: A.Identifier[];
}

export function resolveScopes(program: A.Program): FileScopes {
  const root: Scope = { node: program, parent: null, locals: new Map(), usesArguments: false, children: [] };
  const result: FileScopes = { root, refs: [], refOf: new Map(), scopeOf: new Map([[program, root]]), globalvars: [] };
  let scope = root;
  let withDepth = 0;
  let inMacro = false;

  const declare = (id: A.Identifier, kind: LocalDecl["kind"], target: Scope = scope) => {
    const decl: LocalDecl = { name: id.name, id, kind, scope: target, reads: [], writes: [] };
    const list = target.locals.get(id.name);
    if (list) list.push(decl);
    else target.locals.set(id.name, [decl]);
  };

  const lookup = (s: Scope, name: string, at: number): LocalDecl | undefined => {
    const list = s.locals.get(name);
    if (!list) return undefined;
    let found: LocalDecl | undefined;
    for (const d of list) if (d.kind === "param" || d.id.start < at) found = d;
    return found;
  };

  const reference = (id: A.Identifier, access: Reference["access"], isCallee: boolean) => {
    if (id.name === "argument" || id.name === "argument_count" || /^argument\d+$/.test(id.name)) scope.usesArguments = true;
    let binding: Binding = { kind: "free" };
    if (!inMacro) {
      const local = lookup(scope, id.name, id.start);
      if (local) binding = { kind: "local", decl: local };
      else {
        for (let s = scope.parent; s; s = s.parent) {
          const outer = lookup(s, id.name, id.start);
          if (outer) {
            binding = { kind: "uncaptured", decl: outer };
            break;
          }
        }
      }
    }
    const ref: Reference = { id, binding, access, isCallee, scope, withDepth, inMacro };
    if (binding.kind === "local") {
      if (access !== "write") binding.decl.reads.push(ref);
      if (access !== "read") binding.decl.writes.push(ref);
    }
    result.refs.push(ref);
    result.refOf.set(id, ref);
  };

  const visitExpr = (node: A.Node, access: Reference["access"] = "read", isCallee = false): void => {
    if (node.type === "Identifier") {
      reference(node, access, isCallee);
      return;
    }
    visit(node);
  };

  /** Assignment targets: `a[i] = v` (and `a[i][j] = v`) creates or modifies `a` itself. */
  const visitTarget = (target: A.Expression, access: Reference["access"]) => {
    if (target.type === "IndexExpression") {
      let root: A.Expression = target;
      const indices: A.Expression[] = [];
      while (root.type === "IndexExpression") {
        indices.push(...root.indices);
        root = root.object;
      }
      if (root.type === "Identifier") {
        reference(root, "readwrite", false);
        indices.forEach((i) => visitExpr(i));
        return;
      }
    }
    visitExpr(target, access);
  };

  const visitFunction = (fn: A.FunctionNode) => {
    const fnScope: Scope = { node: fn, parent: scope, locals: new Map(), usesArguments: false, children: [] };
    scope.children.push(fnScope);
    result.scopeOf.set(fn, fnScope);
    const saved = scope;
    const savedWith = withDepth;
    scope = fnScope;
    withDepth = 0;
    for (const p of fn.params) declare(p.id, "param");
    for (const p of fn.params) if (p.init) visitExpr(p.init);
    if (fn.parent) {
      reference(fn.parent.id, "read", true);
      fn.parent.arguments.forEach((a) => visitExpr(a));
    }
    visit(fn.body);
    scope = saved;
    withDepth = savedWith;
  };

  const visit = (node: A.Node): void => {
    switch (node.type) {
      case "VarDeclaration":
        for (const d of node.declarations) {
          if (d.init) visitExpr(d.init);
          if (node.kind === "globalvar") result.globalvars.push(d.id);
          else declare(d.id, node.kind === "static" ? "static" : "var");
        }
        return;
      case "FunctionDeclaration":
      case "FunctionExpression":
        visitFunction(node);
        return;
      case "AssignmentExpression":
        visitExpr(node.right);
        visitTarget(node.left, node.operator === "=" ? "write" : "readwrite");
        return;
      case "UpdateExpression":
        visitTarget(node.argument, "readwrite");
        return;
      case "CallExpression":
      case "NewExpression":
        visitExpr(node.callee, "read", true);
        node.arguments.forEach((a) => visitExpr(a));
        return;
      case "MemberExpression":
        // Writes through `a.b = x` read `a`; the property name is not a variable.
        visitExpr(node.object);
        return;
      case "IndexExpression":
        visitExpr(node.object);
        node.indices.forEach((i) => visitExpr(i));
        return;
      case "StructProperty":
        if (node.value) visitExpr(node.value);
        else if (node.key.type === "Identifier") reference(node.key, "read", false); // shorthand `{ x }`
        return;
      case "TryStatement":
        visit(node.block);
        if (node.param) declare(node.param, "catch");
        if (node.handler) visit(node.handler);
        if (node.finalizer) visit(node.finalizer);
        return;
      case "WithStatement":
        visitExpr(node.object);
        withDepth++;
        visit(node.body);
        withDepth--;
        return;
      case "MacroDeclaration":
        if (node.value) {
          const saved = inMacro;
          inMacro = true;
          visitExpr(node.value);
          inMacro = saved;
        }
        return;
      case "EnumDeclaration":
        node.members.forEach((m) => m.init && visitExpr(m.init));
        return;
      case "Identifier":
        reference(node, "read", false);
        return;
      default:
        forEachChild(node, (child) => visitExpr(child));
    }
  };

  program.body.forEach((s) => visit(s));
  return result;
}

/** The innermost function (or program) scope containing `node`. */
export function enclosingScope(scopes: FileScopes, ancestors: readonly A.Node[]): Scope {
  for (let i = ancestors.length - 1; i >= 0; i--) {
    const s = scopes.scopeOf.get(ancestors[i]);
    if (s) return s;
  }
  return scopes.root;
}

import type * as A from "./ast.ts";

/** Calls `cb` for each direct child node of `node`, in source order. */
export function forEachChild(node: A.Node, cb: (child: A.Node) => void): void {
  switch (node.type) {
    case "Program":
    case "BlockStatement":
      node.body.forEach(cb);
      break;
    case "VarDeclaration":
      node.declarations.forEach(cb);
      break;
    case "VarDeclarator":
      cb(node.id);
      if (node.init) cb(node.init);
      break;
    case "ExpressionStatement":
      cb(node.expression);
      break;
    case "IfStatement":
      cb(node.test);
      cb(node.consequent);
      if (node.alternate) cb(node.alternate);
      break;
    case "WhileStatement":
      cb(node.test);
      cb(node.body);
      break;
    case "DoUntilStatement":
      cb(node.body);
      cb(node.test);
      break;
    case "RepeatStatement":
      cb(node.count);
      cb(node.body);
      break;
    case "ForStatement":
      if (node.init) cb(node.init);
      if (node.test) cb(node.test);
      if (node.update) cb(node.update);
      cb(node.body);
      break;
    case "SwitchStatement":
      cb(node.discriminant);
      node.cases.forEach(cb);
      break;
    case "SwitchCase":
      if (node.test) cb(node.test);
      node.body.forEach(cb);
      break;
    case "WithStatement":
      cb(node.object);
      cb(node.body);
      break;
    case "ReturnStatement":
      if (node.argument) cb(node.argument);
      break;
    case "ThrowStatement":
    case "DeleteStatement":
      cb(node.argument);
      break;
    case "TryStatement":
      cb(node.block);
      if (node.param) cb(node.param);
      if (node.handler) cb(node.handler);
      if (node.finalizer) cb(node.finalizer);
      break;
    case "EnumDeclaration":
      cb(node.id);
      node.members.forEach(cb);
      break;
    case "EnumMember":
      cb(node.id);
      if (node.init) cb(node.init);
      break;
    case "MacroDeclaration":
      cb(node.id);
      if (node.value) cb(node.value);
      break;
    case "FunctionDeclaration":
    case "FunctionExpression":
      if (node.id) cb(node.id);
      node.params.forEach(cb);
      if (node.parent) cb(node.parent);
      cb(node.body);
      break;
    case "Parameter":
      cb(node.id);
      if (node.init) cb(node.init);
      break;
    case "ConstructorParent":
      cb(node.id);
      node.arguments.forEach(cb);
      break;
    case "TemplateString":
      node.expressions.forEach(cb);
      break;
    case "ArrayExpression":
      node.elements.forEach(cb);
      break;
    case "StructExpression":
      node.properties.forEach(cb);
      break;
    case "StructProperty":
      cb(node.key);
      if (node.value) cb(node.value);
      break;
    case "UnaryExpression":
    case "UpdateExpression":
      cb(node.argument);
      break;
    case "BinaryExpression":
    case "AssignmentExpression":
      cb(node.left);
      cb(node.right);
      break;
    case "ConditionalExpression":
      cb(node.test);
      cb(node.consequent);
      cb(node.alternate);
      break;
    case "CallExpression":
    case "NewExpression":
      cb(node.callee);
      node.arguments.forEach(cb);
      break;
    case "MemberExpression":
      cb(node.object);
      cb(node.property);
      break;
    case "IndexExpression":
      cb(node.object);
      node.indices.forEach(cb);
      break;
    default:
      break;
  }
}

export interface WalkContext {
  /** Ancestors of the current node, outermost first. */
  readonly ancestors: readonly A.Node[];
  /** Skip the children of the current node. */
  skip(): void;
}

/** Depth-first pre-order traversal with ancestor tracking. */
export function walk(root: A.Node, enter: (node: A.Node, ctx: WalkContext) => void, leave?: (node: A.Node, ctx: WalkContext) => void): void {
  const ancestors: A.Node[] = [];
  let skipped = false;
  const ctx: WalkContext = {
    ancestors,
    skip() {
      skipped = true;
    },
  };
  const visit = (node: A.Node) => {
    skipped = false;
    enter(node, ctx);
    if (!skipped) {
      ancestors.push(node);
      forEachChild(node, visit);
      ancestors.pop();
    }
    skipped = false;
    leave?.(node, ctx);
  };
  visit(root);
}

/** Collects all descendant nodes (including `root`) matching a predicate. */
export function findAll<T extends A.Node>(root: A.Node, pred: (n: A.Node) => n is T, options: { crossFunctions?: boolean } = {}): T[] {
  const out: T[] = [];
  walk(root, (n, ctx) => {
    if (n !== root && !options.crossFunctions && (n.type === "FunctionDeclaration" || n.type === "FunctionExpression")) {
      ctx.skip();
      return;
    }
    if (pred(n)) out.push(n);
  });
  return out;
}

/** Name of a call's callee when it is a plain identifier (`foo(...)`). */
export function calleeName(call: A.CallExpression | A.NewExpression): string | undefined {
  return call.callee.type === "Identifier" ? call.callee.name : undefined;
}

export function isCallTo(node: A.Node, names: string | ReadonlySet<string> | readonly string[]): node is A.CallExpression {
  if (node.type !== "CallExpression" || node.callee.type !== "Identifier") return false;
  const name = node.callee.name;
  if (typeof names === "string") return name === names;
  if (Array.isArray(names)) return names.includes(name);
  return (names as ReadonlySet<string>).has(name);
}

/** The root identifier name of an lvalue chain: `a.b[0].c` → `a`. */
export function rootIdentifier(expr: A.Expression): A.Identifier | undefined {
  let e: A.Expression = expr;
  while (true) {
    if (e.type === "Identifier") return e;
    if (e.type === "MemberExpression" || e.type === "IndexExpression") e = e.object;
    else return undefined;
  }
}

/** A stable textual key for simple lvalues: `a`, `self.a`, `global.a`, `a.b`. */
export function accessPath(expr: A.Expression): string | undefined {
  if (expr.type === "Identifier") return expr.name;
  if (expr.type === "MemberExpression") {
    const base = accessPath(expr.object);
    return base === undefined ? undefined : `${base}.${expr.property.name}`;
  }
  return undefined;
}

/** Statements that unconditionally leave the current block. */
export function isTerminator(stmt: A.Statement): boolean {
  switch (stmt.type) {
    case "ReturnStatement":
    case "ExitStatement":
    case "BreakStatement":
    case "ContinueStatement":
    case "ThrowStatement":
      return true;
    case "BlockStatement":
      return stmt.body.length > 0 && isTerminator(stmt.body[stmt.body.length - 1]);
    case "IfStatement":
      return stmt.alternate !== null && isTerminator(stmt.consequent) && isTerminator(stmt.alternate);
    default:
      return false;
  }
}

/** Whether `stmt` always exits the enclosing function/event (return/exit/throw). */
export function alwaysExits(stmt: A.Statement): boolean {
  switch (stmt.type) {
    case "ReturnStatement":
    case "ExitStatement":
    case "ThrowStatement":
      return true;
    case "BlockStatement":
      return stmt.body.some(alwaysExits);
    case "IfStatement":
      return stmt.alternate !== null && alwaysExits(stmt.consequent) && alwaysExits(stmt.alternate);
    default:
      return false;
  }
}

/**
 * AST for GameMaker Language (GML), covering GMS 2.3+ syntax plus the legacy forms
 * that still compile (begin/end blocks, `=` as comparison, 2D array indexing, ...).
 *
 * Every node records `start`/`end` UTF-16 offsets into its source file. Line and
 * column numbers are computed on demand through `SourceText.position()`.
 */

export interface BaseNode {
  type: string;
  start: number;
  end: number;
  /** True when the expression was wrapped in parentheses in the source. */
  parenthesized?: boolean;
}

export interface Comment {
  kind: "line" | "block";
  value: string;
  start: number;
  end: number;
}

export interface ParseError {
  message: string;
  start: number;
  end: number;
}

// ---------------------------------------------------------------------------
// Statements

export interface Program extends BaseNode {
  type: "Program";
  body: Statement[];
  comments: Comment[];
  errors: ParseError[];
}

export interface BlockStatement extends BaseNode {
  type: "BlockStatement";
  body: Statement[];
}

export interface VarDeclarator extends BaseNode {
  type: "VarDeclarator";
  id: Identifier;
  init: Expression | null;
}

export interface VarDeclaration extends BaseNode {
  type: "VarDeclaration";
  kind: "var" | "globalvar" | "static";
  declarations: VarDeclarator[];
}

export interface ExpressionStatement extends BaseNode {
  type: "ExpressionStatement";
  expression: Expression;
}

export interface IfStatement extends BaseNode {
  type: "IfStatement";
  test: Expression;
  consequent: Statement;
  alternate: Statement | null;
}

export interface WhileStatement extends BaseNode {
  type: "WhileStatement";
  test: Expression;
  body: Statement;
}

export interface DoUntilStatement extends BaseNode {
  type: "DoUntilStatement";
  body: Statement;
  test: Expression;
}

export interface RepeatStatement extends BaseNode {
  type: "RepeatStatement";
  count: Expression;
  body: Statement;
}

export interface ForStatement extends BaseNode {
  type: "ForStatement";
  init: Statement | null;
  test: Expression | null;
  update: Statement | null;
  body: Statement;
}

export interface SwitchCase extends BaseNode {
  type: "SwitchCase";
  /** `null` for `default:` */
  test: Expression | null;
  body: Statement[];
}

export interface SwitchStatement extends BaseNode {
  type: "SwitchStatement";
  discriminant: Expression;
  cases: SwitchCase[];
}

export interface WithStatement extends BaseNode {
  type: "WithStatement";
  object: Expression;
  body: Statement;
}

export interface BreakStatement extends BaseNode {
  type: "BreakStatement";
}

export interface ContinueStatement extends BaseNode {
  type: "ContinueStatement";
}

export interface ExitStatement extends BaseNode {
  type: "ExitStatement";
}

export interface ReturnStatement extends BaseNode {
  type: "ReturnStatement";
  argument: Expression | null;
}

export interface ThrowStatement extends BaseNode {
  type: "ThrowStatement";
  argument: Expression;
}

export interface DeleteStatement extends BaseNode {
  type: "DeleteStatement";
  argument: Expression;
}

export interface TryStatement extends BaseNode {
  type: "TryStatement";
  block: BlockStatement;
  param: Identifier | null;
  handler: BlockStatement | null;
  finalizer: BlockStatement | null;
}

export interface EnumMember extends BaseNode {
  type: "EnumMember";
  id: Identifier;
  init: Expression | null;
}

export interface EnumDeclaration extends BaseNode {
  type: "EnumDeclaration";
  id: Identifier;
  members: EnumMember[];
}

export interface MacroDeclaration extends BaseNode {
  type: "MacroDeclaration";
  id: Identifier;
  /** `#macro Config:NAME value` */
  config: string | null;
  /** Raw source text of the macro body. */
  body: string;
  bodyStart: number;
  /** The body parsed as an expression, when it is one. */
  value: Expression | null;
}

export interface Parameter extends BaseNode {
  type: "Parameter";
  id: Identifier;
  init: Expression | null;
}

export interface ConstructorParent extends BaseNode {
  type: "ConstructorParent";
  id: Identifier;
  arguments: Expression[];
}

export interface FunctionDeclaration extends BaseNode {
  type: "FunctionDeclaration";
  id: Identifier;
  params: Parameter[];
  body: BlockStatement;
  isConstructor: boolean;
  parent: ConstructorParent | null;
}

export interface EmptyStatement extends BaseNode {
  type: "EmptyStatement";
}

export type Statement =
  | BlockStatement
  | VarDeclaration
  | ExpressionStatement
  | IfStatement
  | WhileStatement
  | DoUntilStatement
  | RepeatStatement
  | ForStatement
  | SwitchStatement
  | WithStatement
  | BreakStatement
  | ContinueStatement
  | ExitStatement
  | ReturnStatement
  | ThrowStatement
  | DeleteStatement
  | TryStatement
  | EnumDeclaration
  | MacroDeclaration
  | FunctionDeclaration
  | EmptyStatement
  | PatternEllipsis;

// ---------------------------------------------------------------------------
// Expressions

export interface Identifier extends BaseNode {
  type: "Identifier";
  name: string;
}

export interface NumberLiteral extends BaseNode {
  type: "NumberLiteral";
  value: number;
  raw: string;
}

export interface StringLiteral extends BaseNode {
  type: "StringLiteral";
  value: string;
  raw: string;
}

export interface BooleanLiteral extends BaseNode {
  type: "BooleanLiteral";
  value: boolean;
}

export interface TemplateString extends BaseNode {
  type: "TemplateString";
  /** Literal text chunks; always `expressions.length + 1` entries. */
  quasis: string[];
  expressions: Expression[];
}

export interface ArrayExpression extends BaseNode {
  type: "ArrayExpression";
  elements: Expression[];
}

export interface StructProperty extends BaseNode {
  type: "StructProperty";
  key: Identifier | StringLiteral;
  /** `null` for shorthand `{ name }` */
  value: Expression | null;
}

export interface StructExpression extends BaseNode {
  type: "StructExpression";
  properties: (StructProperty | PatternEllipsis)[];
}

export interface FunctionExpression extends BaseNode {
  type: "FunctionExpression";
  id: Identifier | null;
  params: Parameter[];
  body: BlockStatement;
  isConstructor: boolean;
  parent: ConstructorParent | null;
}

export type UnaryOperator = "!" | "-" | "+" | "~";

export interface UnaryExpression extends BaseNode {
  type: "UnaryExpression";
  operator: UnaryOperator;
  argument: Expression;
}

export interface UpdateExpression extends BaseNode {
  type: "UpdateExpression";
  operator: "++" | "--";
  prefix: boolean;
  argument: Expression;
}

export type BinaryOperator =
  | "??"
  | "||"
  | "^^"
  | "&&"
  | "|"
  | "^"
  | "&"
  | "=="
  | "!="
  | "<"
  | "<="
  | ">"
  | ">="
  | "<<"
  | ">>"
  | "+"
  | "-"
  | "*"
  | "/"
  | "%"
  | "div";

export interface BinaryExpression extends BaseNode {
  type: "BinaryExpression";
  /** Normalized operator (`and` → `&&`, `mod` → `%`, `<>` → `!=`, legacy `=` → `==`). */
  operator: BinaryOperator;
  /** The operator exactly as written. */
  rawOperator: string;
  left: Expression;
  right: Expression;
}

export interface ConditionalExpression extends BaseNode {
  type: "ConditionalExpression";
  test: Expression;
  consequent: Expression;
  alternate: Expression;
}

export type AssignmentOperator =
  | "="
  | "+="
  | "-="
  | "*="
  | "/="
  | "%="
  | "&="
  | "|="
  | "^="
  | "<<="
  | ">>="
  | "??=";

export interface AssignmentExpression extends BaseNode {
  type: "AssignmentExpression";
  operator: AssignmentOperator;
  left: Expression;
  right: Expression;
}

export interface CallExpression extends BaseNode {
  type: "CallExpression";
  callee: Expression;
  arguments: Expression[];
}

export interface NewExpression extends BaseNode {
  type: "NewExpression";
  callee: Expression;
  arguments: Expression[];
}

export interface MemberExpression extends BaseNode {
  type: "MemberExpression";
  object: Expression;
  property: Identifier;
}

/** `""` plain, `|` list, `?` map, `#` grid, `@` array by reference, `$` struct */
export type Accessor = "" | "|" | "?" | "#" | "@" | "$";

export interface IndexExpression extends BaseNode {
  type: "IndexExpression";
  object: Expression;
  accessor: Accessor;
  indices: Expression[];
}

// Pattern-only nodes (used by custom pattern rules, never produced for game code)

export interface Metavariable extends BaseNode {
  type: "Metavariable";
  name: string;
}

export interface PatternEllipsis extends BaseNode {
  type: "PatternEllipsis";
}

export type Expression =
  | Identifier
  | NumberLiteral
  | StringLiteral
  | BooleanLiteral
  | TemplateString
  | ArrayExpression
  | StructExpression
  | FunctionExpression
  | UnaryExpression
  | UpdateExpression
  | BinaryExpression
  | ConditionalExpression
  | AssignmentExpression
  | CallExpression
  | NewExpression
  | MemberExpression
  | IndexExpression
  | Metavariable
  | PatternEllipsis;

export type FunctionNode = FunctionDeclaration | FunctionExpression;

export type Node =
  | Program
  | Statement
  | Expression
  | VarDeclarator
  | SwitchCase
  | EnumMember
  | Parameter
  | ConstructorParent
  | StructProperty;

export function isFunctionNode(node: Node): node is FunctionNode {
  return node.type === "FunctionDeclaration" || node.type === "FunctionExpression";
}

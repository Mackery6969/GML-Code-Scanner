import type * as A from "./ast.ts";
import { tokenize, type Token } from "./lexer.ts";

export interface ParseOptions {
  /** Enable `$NAME` metavariables and `...` wildcards (custom pattern rules). */
  patternMode?: boolean;
}

class ParseFailure extends Error {
  readonly start: number;
  readonly end: number;
  constructor(message: string, start: number, end: number) {
    super(message);
    this.start = start;
    this.end = end;
  }
}

const KEYWORDS = new Set([
  "var",
  "globalvar",
  "static",
  "if",
  "then",
  "else",
  "while",
  "do",
  "until",
  "for",
  "repeat",
  "switch",
  "case",
  "default",
  "break",
  "continue",
  "exit",
  "return",
  "with",
  "function",
  "new",
  "delete",
  "try",
  "catch",
  "finally",
  "throw",
  "enum",
  "begin",
  "end",
  "and",
  "or",
  "not",
  "xor",
  "mod",
  "div",
]);

const STATEMENT_KEYWORDS = new Set([
  "var",
  "globalvar",
  "static",
  "if",
  "while",
  "do",
  "for",
  "repeat",
  "switch",
  "case",
  "default",
  "break",
  "continue",
  "exit",
  "return",
  "with",
  "function",
  "delete",
  "try",
  "throw",
  "enum",
]);

interface BinaryOpInfo {
  prec: number;
  op: A.BinaryOperator;
}

const BINARY_OPS: Record<string, BinaryOpInfo> = {
  "??": { prec: 1, op: "??" },
  "||": { prec: 2, op: "||" },
  or: { prec: 2, op: "||" },
  "^^": { prec: 3, op: "^^" },
  xor: { prec: 3, op: "^^" },
  "&&": { prec: 4, op: "&&" },
  and: { prec: 4, op: "&&" },
  "|": { prec: 5, op: "|" },
  "^": { prec: 6, op: "^" },
  "&": { prec: 7, op: "&" },
  "==": { prec: 8, op: "==" },
  "!=": { prec: 8, op: "!=" },
  "<>": { prec: 8, op: "!=" },
  "=": { prec: 8, op: "==" },
  "<": { prec: 9, op: "<" },
  "<=": { prec: 9, op: "<=" },
  ">": { prec: 9, op: ">" },
  ">=": { prec: 9, op: ">=" },
  "<<": { prec: 10, op: "<<" },
  ">>": { prec: 10, op: ">>" },
  "+": { prec: 11, op: "+" },
  "-": { prec: 11, op: "-" },
  "*": { prec: 12, op: "*" },
  "/": { prec: 12, op: "/" },
  "%": { prec: 12, op: "%" },
  mod: { prec: 12, op: "%" },
  div: { prec: 12, op: "div" },
};

const ASSIGN_OPS = new Set(["=", ":=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>=", "??="]);

const ACCESSORS: Record<string, A.Accessor> = { "[": "", "[|": "|", "[?": "?", "[#": "#", "[@": "@", "[$": "$" };

export function parse(source: string, options: ParseOptions = {}): A.Program {
  const lexed = tokenize(source, { patternMode: options.patternMode });
  const parser = new Parser(source, lexed.tokens, options.patternMode ?? false);
  const body = parser.parseProgramBody();
  const errors = [...lexed.errors, ...parser.errors].sort((a, b) => a.start - b.start);
  return { type: "Program", body, comments: lexed.comments, errors, start: 0, end: source.length };
}

/**
 * Parses a custom-rule pattern. Tries a single expression first, then falls back to
 * a statement list.
 */
export function parsePattern(source: string): { node: A.Expression | A.Statement[]; errors: A.ParseError[] } {
  const lexed = tokenize(source, { patternMode: true });
  const exprParser = new Parser(source, lexed.tokens, true);
  try {
    const expr = exprParser.parseExpression();
    exprParser.eatSemicolons();
    if (exprParser.atEof() && exprParser.errors.length === 0) {
      return { node: expr, errors: lexed.errors };
    }
  } catch (e) {
    if (!(e instanceof ParseFailure)) throw e;
  }
  const stmtParser = new Parser(source, lexed.tokens, true);
  const body = stmtParser.parseProgramBody();
  return { node: body, errors: [...lexed.errors, ...stmtParser.errors] };
}

class Parser {
  private i = 0;
  readonly errors: A.ParseError[] = [];
  private readonly src: string;
  private readonly tokens: Token[];
  private readonly patternMode: boolean;

  constructor(src: string, tokens: Token[], patternMode: boolean) {
    this.src = src;
    this.tokens = tokens;
    this.patternMode = patternMode;
  }

  // -------------------------------------------------------------------------
  // Token helpers

  private get tok(): Token {
    return this.tokens[this.i];
  }

  private peek(k = 1): Token {
    return this.tokens[Math.min(this.i + k, this.tokens.length - 1)];
  }

  private get prevEnd(): number {
    return this.i > 0 ? this.tokens[this.i - 1].end : 0;
  }

  atEof(): boolean {
    return this.tok.kind === "eof";
  }

  private isPunct(v: string, t: Token = this.tok): boolean {
    return t.kind === "punct" && t.value === v;
  }

  private isWord(v: string, t: Token = this.tok): boolean {
    return t.kind === "ident" && t.value === v;
  }

  private eatPunct(v: string): boolean {
    if (this.isPunct(v)) {
      this.i++;
      return true;
    }
    return false;
  }

  private eatWord(v: string): boolean {
    if (this.isWord(v)) {
      this.i++;
      return true;
    }
    return false;
  }

  private fail(message: string, t: Token = this.tok): never {
    throw new ParseFailure(message, t.start, Math.max(t.end, t.start + 1));
  }

  private describe(t: Token): string {
    if (t.kind === "eof") return "end of file";
    if (t.kind === "string") return "string";
    if (t.kind === "define") return "#define";
    if (t.kind === "template") return "template string";
    if (t.kind === "macro") return "#macro";
    return `'${t.value}'`;
  }

  private expectPunct(v: string): Token {
    if (!this.isPunct(v)) this.fail(`Expected '${v}' but found ${this.describe(this.tok)}`);
    return this.tokens[this.i++];
  }

  private expectIdentifier(): A.Identifier {
    const t = this.tok;
    if (t.kind === "metavar") {
      this.i++;
      return { type: "Identifier", name: "$" + t.value, start: t.start, end: t.end };
    }
    if (t.kind !== "ident" || KEYWORDS.has(t.value)) this.fail(`Expected identifier but found ${this.describe(t)}`);
    this.i++;
    return { type: "Identifier", name: t.value, start: t.start, end: t.end };
  }

  /** Property names after `.` and struct keys may be keywords. */
  private expectPropertyName(): A.Identifier {
    const t = this.tok;
    if (t.kind === "metavar") {
      this.i++;
      return { type: "Identifier", name: "$" + t.value, start: t.start, end: t.end };
    }
    if (t.kind !== "ident") this.fail(`Expected property name but found ${this.describe(t)}`);
    this.i++;
    return { type: "Identifier", name: t.value, start: t.start, end: t.end };
  }

  eatSemicolons(): void {
    while (this.isPunct(";")) this.i++;
  }

  // -------------------------------------------------------------------------
  // Statements

  parseProgramBody(): A.Statement[] {
    const atDefine = () => this.tok.kind === "define";
    const body = this.parseStatementList(atDefine);
    // Legacy/extension files: each `#define name` section is a separate script function.
    while (atDefine()) {
      const t = this.tokens[this.i++];
      const nameStart = Number(t.raw);
      const stmts = this.parseStatementList(atDefine);
      const end = this.prevEnd;
      body.push({
        type: "FunctionDeclaration",
        id: { type: "Identifier", name: t.value, start: nameStart, end: nameStart + t.value.length },
        params: [],
        body: { type: "BlockStatement", body: stmts, start: t.end, end: Math.max(end, t.end) },
        isConstructor: false,
        parent: null,
        start: t.start,
        end: Math.max(end, t.end),
      });
    }
    return body;
  }

  private parseStatementList(isEnd: () => boolean): A.Statement[] {
    const body: A.Statement[] = [];
    while (!this.atEof() && !isEnd()) {
      const before = this.i;
      try {
        const stmt = this.parseStatement();
        if (stmt.type !== "EmptyStatement") body.push(stmt);
      } catch (e) {
        if (!(e instanceof ParseFailure)) throw e;
        this.errors.push({ message: e.message, start: e.start, end: e.end });
        this.synchronize(before, isEnd);
      }
    }
    return body;
  }

  private synchronize(before: number, isEnd: () => boolean): void {
    if (this.i === before) this.i++;
    while (!this.atEof()) {
      const t = this.tok;
      if (this.isPunct(";")) {
        this.i++;
        return;
      }
      if (this.isPunct("}") || isEnd()) return;
      if (t.kind === "define") return;
      if (t.nlBefore && ((t.kind === "ident" && STATEMENT_KEYWORDS.has(t.value)) || t.kind === "macro")) return;
      this.i++;
    }
  }

  private parseStatement(): A.Statement {
    const t = this.tok;
    if (t.kind === "macro") return this.parseMacro();
    if (t.kind === "punct") {
      if (t.value === "{") return this.parseBlock();
      if (t.value === ";") {
        this.i++;
        return { type: "EmptyStatement", start: t.start, end: t.end };
      }
      if (t.value === "..." && this.patternMode) {
        this.i++;
        this.eatSemicolons();
        return { type: "PatternEllipsis", start: t.start, end: t.end };
      }
    }
    if (t.kind === "ident") {
      switch (t.value) {
        case "begin":
          return this.parseBlock();
        case "var":
        case "globalvar":
          return this.finishSimple(this.parseVarDeclaration());
        case "static":
          return this.finishSimple(this.parseVarDeclaration());
        case "if":
          return this.parseIf();
        case "while":
          return this.parseWhile();
        case "do":
          return this.parseDo();
        case "repeat":
          return this.parseRepeat();
        case "for":
          return this.parseFor();
        case "switch":
          return this.parseSwitch();
        case "with":
          return this.parseWith();
        case "break":
          this.i++;
          return this.finishSimple({ type: "BreakStatement", start: t.start, end: t.end });
        case "continue":
          this.i++;
          return this.finishSimple({ type: "ContinueStatement", start: t.start, end: t.end });
        case "exit":
          this.i++;
          return this.finishSimple({ type: "ExitStatement", start: t.start, end: t.end });
        case "return":
          return this.parseReturn();
        case "throw": {
          this.i++;
          const argument = this.parseExpression();
          return this.finishSimple({ type: "ThrowStatement", argument, start: t.start, end: argument.end });
        }
        case "delete": {
          this.i++;
          const argument = this.parseExpression();
          return this.finishSimple({ type: "DeleteStatement", argument, start: t.start, end: argument.end });
        }
        case "try":
          return this.parseTry();
        case "enum":
          return this.parseEnum();
        case "function":
          if (this.peek().kind === "ident" || this.peek().kind === "metavar") return this.parseFunctionDeclaration();
          break;
        case "case":
        case "default":
          this.fail(`'${t.value}' outside of a switch statement`);
          break;
        case "else":
          this.fail("'else' without a matching 'if'");
          break;
        case "until":
          this.fail("'until' without a matching 'do'");
          break;
      }
    }
    return this.parseExpressionStatement();
  }

  private finishSimple<T extends A.Statement>(stmt: T): T {
    this.eatSemicolons();
    return stmt;
  }

  private parseBlock(): A.BlockStatement {
    const open = this.tok;
    const usesBegin = this.isWord("begin");
    this.i++;
    const close = usesBegin ? () => this.isWord("end") || this.isPunct("}") : () => this.isPunct("}");
    const body = this.parseStatementList(close);
    let end = this.prevEnd;
    if (close()) {
      end = this.tok.end;
      this.i++;
    } else {
      this.errors.push({ message: `Missing closing '${usesBegin ? "end" : "}"}'`, start: open.start, end: open.end });
    }
    this.eatSemicolons();
    return { type: "BlockStatement", body, start: open.start, end };
  }

  private parseMacro(): A.MacroDeclaration {
    const t = this.tokens[this.i++];
    const m = t.macro!;
    let value: A.Expression | null = null;
    if (m.body.trim()) {
      const lexed = tokenize(this.src, { start: m.bodyStart, end: m.bodyEnd, patternMode: this.patternMode });
      const sub = new Parser(this.src, lexed.tokens, this.patternMode);
      try {
        const expr = sub.parseExpression();
        sub.eatSemicolons();
        if (sub.atEof() && lexed.errors.length === 0) value = expr;
      } catch (e) {
        if (!(e instanceof ParseFailure)) throw e;
      }
    }
    return {
      type: "MacroDeclaration",
      id: { type: "Identifier", name: m.name, start: m.nameStart, end: m.nameEnd },
      config: m.config,
      body: m.body,
      bodyStart: m.bodyStart,
      value,
      start: t.start,
      end: t.end,
    };
  }

  private parseVarDeclaration(): A.VarDeclaration {
    const kw = this.tokens[this.i++];
    const kind = kw.value as A.VarDeclaration["kind"];
    const declarations: A.VarDeclarator[] = [];
    do {
      const id = this.expectIdentifier();
      let init: A.Expression | null = null;
      if (this.isPunct("=") || this.isPunct(":=")) {
        this.i++;
        init = this.parseExpression();
      }
      declarations.push({ type: "VarDeclarator", id, init, start: id.start, end: init ? init.end : id.end });
    } while (this.eatPunct(","));
    return { type: "VarDeclaration", kind, declarations, start: kw.start, end: this.prevEnd };
  }

  private parseIf(): A.IfStatement {
    const kw = this.tokens[this.i++];
    const test = this.parseExpression();
    this.eatWord("then");
    const consequent = this.parseStatement();
    let alternate: A.Statement | null = null;
    if (this.eatWord("else")) alternate = this.parseStatement();
    return { type: "IfStatement", test, consequent, alternate, start: kw.start, end: (alternate ?? consequent).end };
  }

  private parseWhile(): A.WhileStatement {
    const kw = this.tokens[this.i++];
    const test = this.parseExpression();
    this.eatWord("do");
    const body = this.parseStatement();
    return { type: "WhileStatement", test, body, start: kw.start, end: body.end };
  }

  private parseDo(): A.DoUntilStatement {
    const kw = this.tokens[this.i++];
    const body = this.parseStatement();
    if (!this.eatWord("until")) {
      if (this.isWord("while")) this.fail("GML uses 'do ... until (condition)', not 'do ... while'");
      this.fail(`Expected 'until' but found ${this.describe(this.tok)}`);
    }
    const test = this.parseExpression();
    this.eatSemicolons();
    return { type: "DoUntilStatement", body, test, start: kw.start, end: test.end };
  }

  private parseRepeat(): A.RepeatStatement {
    const kw = this.tokens[this.i++];
    const count = this.parseExpression();
    const body = this.parseStatement();
    return { type: "RepeatStatement", count, body, start: kw.start, end: body.end };
  }

  private parseFor(): A.ForStatement {
    const kw = this.tokens[this.i++];
    this.expectPunct("(");
    let init: A.Statement | null = null;
    if (!this.isPunct(";")) {
      init = this.isWord("var") || this.isWord("static") ? this.parseVarDeclaration() : this.parseExpressionStatement(false);
    }
    this.expectPunct(";");
    let test: A.Expression | null = null;
    if (!this.isPunct(";")) test = this.parseExpression();
    this.expectPunct(";");
    let update: A.Statement | null = null;
    if (!this.isPunct(")")) update = this.parseExpressionStatement(false);
    this.eatPunct(";");
    this.expectPunct(")");
    const body = this.parseStatement();
    return { type: "ForStatement", init, test, update, body, start: kw.start, end: body.end };
  }

  private parseSwitch(): A.SwitchStatement {
    const kw = this.tokens[this.i++];
    const discriminant = this.parseExpression();
    const open = this.tok;
    const usesBegin = this.isWord("begin");
    if (!usesBegin) this.expectPunct("{");
    else this.i++;
    const isClose = () => (usesBegin ? this.isWord("end") : false) || this.isPunct("}");
    const cases: A.SwitchCase[] = [];
    const isCaseStart = () => this.isWord("case") || this.isWord("default");
    while (!this.atEof() && !isClose()) {
      const ct = this.tok;
      if (this.patternMode && this.isPunct("...")) {
        this.i++;
        cases.push({ type: "SwitchCase", test: { type: "PatternEllipsis", start: ct.start, end: ct.end }, body: [], start: ct.start, end: ct.end });
        this.eatSemicolons();
        continue;
      }
      let test: A.Expression | null = null;
      if (this.eatWord("case")) {
        try {
          test = this.parseExpression();
          this.expectPunct(":");
        } catch (e) {
          if (!(e instanceof ParseFailure)) throw e;
          this.errors.push({ message: e.message, start: e.start, end: e.end });
          while (!this.atEof() && !this.isPunct(":") && !isClose() && !isCaseStart()) this.i++;
          this.eatPunct(":");
        }
      } else if (this.eatWord("default")) {
        if (!this.eatPunct(":")) this.errors.push({ message: "Expected ':' after 'default'", start: ct.start, end: ct.end });
      } else {
        // Statements before the first case: record and parse them so recovery continues.
        this.errors.push({ message: "Statement in switch body outside of any case", start: ct.start, end: ct.end });
        this.parseStatementList(() => isCaseStart() || isClose());
        continue;
      }
      const body = this.parseStatementList(() => isCaseStart() || isClose());
      cases.push({ type: "SwitchCase", test, body, start: ct.start, end: this.prevEnd });
    }
    let end = this.prevEnd;
    if (isClose()) {
      end = this.tok.end;
      this.i++;
    } else {
      this.errors.push({ message: "Missing closing '}' for switch", start: open.start, end: open.end });
    }
    this.eatSemicolons();
    return { type: "SwitchStatement", discriminant, cases, start: kw.start, end };
  }

  private parseWith(): A.WithStatement {
    const kw = this.tokens[this.i++];
    const object = this.parseExpression();
    const body = this.parseStatement();
    return { type: "WithStatement", object, body, start: kw.start, end: body.end };
  }

  private parseReturn(): A.ReturnStatement {
    const kw = this.tokens[this.i++];
    const t = this.tok;
    const noArg =
      this.isPunct(";") ||
      this.isPunct("}") ||
      t.kind === "eof" ||
      this.isWord("case") ||
      this.isWord("default") ||
      this.isWord("end") ||
      this.isWord("else") ||
      (t.nlBefore && t.kind === "ident" && STATEMENT_KEYWORDS.has(t.value));
    const argument = noArg ? null : this.parseExpression();
    this.eatSemicolons();
    return { type: "ReturnStatement", argument, start: kw.start, end: argument ? argument.end : kw.end };
  }

  private parseTry(): A.TryStatement {
    const kw = this.tokens[this.i++];
    const block = this.parseBlock();
    let param: A.Identifier | null = null;
    let handler: A.BlockStatement | null = null;
    let finalizer: A.BlockStatement | null = null;
    if (this.eatWord("catch")) {
      const paren = this.eatPunct("(");
      if (!(paren && this.isPunct(")"))) param = this.expectIdentifier();
      if (paren) this.expectPunct(")");
      handler = this.parseBlock();
    }
    if (this.eatWord("finally")) finalizer = this.parseBlock();
    return { type: "TryStatement", block, param, handler, finalizer, start: kw.start, end: this.prevEnd };
  }

  private parseEnum(): A.EnumDeclaration {
    const kw = this.tokens[this.i++];
    const id = this.expectIdentifier();
    this.expectPunct("{");
    const members: A.EnumMember[] = [];
    while (!this.isPunct("}") && !this.atEof()) {
      const mid = this.expectPropertyName();
      let init: A.Expression | null = null;
      if (this.eatPunct("=")) init = this.parseExpression();
      members.push({ type: "EnumMember", id: mid, init, start: mid.start, end: init ? init.end : mid.end });
      if (!this.eatPunct(",")) break;
    }
    const close = this.expectPunct("}");
    this.eatSemicolons();
    return { type: "EnumDeclaration", id, members, start: kw.start, end: close.end };
  }

  private parseFunctionDeclaration(): A.FunctionDeclaration {
    const fn = this.parseFunctionCommon();
    if (!fn.id) this.fail("Expected function name");
    this.eatSemicolons();
    return { ...fn, type: "FunctionDeclaration", id: fn.id };
  }

  private parseFunctionCommon(): A.FunctionExpression {
    const kw = this.tokens[this.i++]; // function
    let id: A.Identifier | null = null;
    if (this.tok.kind === "ident" || this.tok.kind === "metavar") id = this.expectIdentifier();
    this.expectPunct("(");
    const params: A.Parameter[] = [];
    while (!this.isPunct(")")) {
      if (this.patternMode && this.isPunct("...")) {
        const t = this.tokens[this.i++];
        params.push({ type: "Parameter", id: { type: "Identifier", name: "...", start: t.start, end: t.end }, init: null, start: t.start, end: t.end });
      } else {
        const pid = this.expectIdentifier();
        let init: A.Expression | null = null;
        if (this.eatPunct("=")) init = this.parseExpression();
        params.push({ type: "Parameter", id: pid, init, start: pid.start, end: init ? init.end : pid.end });
      }
      if (!this.eatPunct(",")) break;
    }
    this.expectPunct(")");
    let parent: A.ConstructorParent | null = null;
    if (this.isPunct(":")) {
      const colon = this.tokens[this.i++];
      const pid = this.expectIdentifier();
      const args = this.isPunct("(") ? this.parseArguments() : [];
      parent = { type: "ConstructorParent", id: pid, arguments: args, start: colon.start, end: this.prevEnd };
    }
    const isConstructor = this.eatWord("constructor");
    if (!this.isPunct("{") && !this.isWord("begin")) this.fail(`Expected '{' but found ${this.describe(this.tok)}`);
    const body = this.parseBlock();
    return { type: "FunctionExpression", id, params, body, isConstructor, parent, start: kw.start, end: body.end };
  }

  private parseExpressionStatement(consumeSemicolon = true): A.Statement {
    const start = this.tok.start;
    const left = this.parseUnary();
    let expression: A.Expression;
    if (this.tok.kind === "punct" && ASSIGN_OPS.has(this.tok.value)) {
      const opTok = this.tokens[this.i++];
      const right = this.parseExpression();
      const operator = (opTok.value === ":=" ? "=" : opTok.value) as A.AssignmentOperator;
      expression = { type: "AssignmentExpression", operator, left, right, start: left.start, end: right.end };
    } else {
      expression = this.parseTernaryRest(this.parseBinaryRest(left, 1));
    }
    if (consumeSemicolon) this.eatSemicolons();
    return { type: "ExpressionStatement", expression, start, end: expression.end };
  }

  // -------------------------------------------------------------------------
  // Expressions

  parseExpression(): A.Expression {
    return this.parseTernaryRest(this.parseBinary(1));
  }

  private parseTernaryRest(test: A.Expression): A.Expression {
    if (!this.isPunct("?")) return test;
    this.i++;
    const consequent = this.parseExpression();
    this.expectPunct(":");
    const alternate = this.parseExpression();
    return { type: "ConditionalExpression", test, consequent, alternate, start: test.start, end: alternate.end };
  }

  private binaryInfo(t: Token): BinaryOpInfo | undefined {
    if (t.kind === "punct" || t.kind === "ident") return Object.hasOwn(BINARY_OPS, t.value) ? BINARY_OPS[t.value] : undefined;
    return undefined;
  }

  private parseBinary(minPrec: number): A.Expression {
    return this.parseBinaryRest(this.parseUnary(), minPrec);
  }

  private parseBinaryRest(left: A.Expression, minPrec: number): A.Expression {
    while (true) {
      const t = this.tok;
      const info = this.binaryInfo(t);
      if (!info || info.prec < minPrec) return left;
      this.i++;
      const rightAssoc = info.op === "??";
      const right = this.parseBinary(rightAssoc ? info.prec : info.prec + 1);
      left = { type: "BinaryExpression", operator: info.op, rawOperator: t.value, left, right, start: left.start, end: right.end };
    }
  }

  private parseUnary(): A.Expression {
    const t = this.tok;
    if (t.kind === "punct" && (t.value === "!" || t.value === "-" || t.value === "+" || t.value === "~")) {
      this.i++;
      const argument = this.parseUnary();
      return { type: "UnaryExpression", operator: t.value as A.UnaryOperator, argument, start: t.start, end: argument.end };
    }
    if (this.isWord("not")) {
      this.i++;
      const argument = this.parseUnary();
      return { type: "UnaryExpression", operator: "!", argument, start: t.start, end: argument.end };
    }
    if (t.kind === "punct" && (t.value === "++" || t.value === "--")) {
      this.i++;
      const argument = this.parseUnary();
      return { type: "UpdateExpression", operator: t.value as "++" | "--", prefix: true, argument, start: t.start, end: argument.end };
    }
    return this.parsePostfix();
  }

  private parsePostfix(): A.Expression {
    let expr = this.parsePrimary();
    while (true) {
      const t = this.tok;
      if (t.kind !== "punct") break;
      if (t.value === ".") {
        this.i++;
        const property = this.expectPropertyName();
        expr = { type: "MemberExpression", object: expr, property, start: expr.start, end: property.end };
      } else if (t.value === "(") {
        const args = this.parseArguments();
        expr = { type: "CallExpression", callee: expr, arguments: args, start: expr.start, end: this.prevEnd };
      } else if (Object.hasOwn(ACCESSORS, t.value)) {
        this.i++;
        const indices: A.Expression[] = [];
        do {
          indices.push(this.parseExpression());
        } while (this.eatPunct(","));
        this.expectPunct("]");
        expr = { type: "IndexExpression", object: expr, accessor: ACCESSORS[t.value], indices, start: expr.start, end: this.prevEnd };
      } else if ((t.value === "++" || t.value === "--") && !t.nlBefore) {
        this.i++;
        expr = { type: "UpdateExpression", operator: t.value, prefix: false, argument: expr, start: expr.start, end: t.end };
      } else {
        break;
      }
    }
    return expr;
  }

  private parseArguments(): A.Expression[] {
    this.expectPunct("(");
    const args: A.Expression[] = [];
    while (!this.isPunct(")")) {
      if (this.isPunct(",")) {
        // GML allows omitted arguments: f(a,,b) passes undefined.
        const t = this.tok;
        args.push({ type: "Identifier", name: "undefined", start: t.start, end: t.start });
        this.i++;
        continue;
      }
      args.push(this.parseExpression());
      if (!this.eatPunct(",")) break;
    }
    this.expectPunct(")");
    return args;
  }

  private parsePrimary(): A.Expression {
    const t = this.tok;
    switch (t.kind) {
      case "number":
        this.i++;
        return { type: "NumberLiteral", value: t.num ?? 0, raw: t.raw ?? t.value, start: t.start, end: t.end };
      case "string":
        this.i++;
        return { type: "StringLiteral", value: t.value, raw: t.raw ?? t.value, start: t.start, end: t.end };
      case "template":
        this.i++;
        return this.buildTemplate(t);
      case "metavar":
        this.i++;
        return { type: "Metavariable", name: t.value, start: t.start, end: t.end };
      case "ident":
        return this.parseIdentifierLike(t);
      case "punct":
        switch (t.value) {
          case "(": {
            this.i++;
            const expr = this.parseExpression();
            const close = this.expectPunct(")");
            expr.parenthesized = true;
            void close;
            return expr;
          }
          case "[":
            return this.parseArrayLiteral();
          case "{":
            return this.parseStructLiteral();
          case "...":
            if (this.patternMode) {
              this.i++;
              return { type: "PatternEllipsis", start: t.start, end: t.end };
            }
        }
    }
    this.fail(`Unexpected ${this.describe(t)}`);
  }

  private parseIdentifierLike(t: Token): A.Expression {
    switch (t.value) {
      case "true":
      case "false":
        this.i++;
        return { type: "BooleanLiteral", value: t.value === "true", start: t.start, end: t.end };
      case "function":
        return this.parseFunctionCommon();
      case "new":
        return this.parseNew();
    }
    if (KEYWORDS.has(t.value)) this.fail(`Unexpected keyword '${t.value}'`);
    this.i++;
    return { type: "Identifier", name: t.value, start: t.start, end: t.end };
  }

  private parseNew(): A.NewExpression {
    const kw = this.tokens[this.i++];
    let callee: A.Expression = this.expectIdentifier();
    while (this.isPunct(".")) {
      this.i++;
      const property = this.expectPropertyName();
      callee = { type: "MemberExpression", object: callee, property, start: callee.start, end: property.end };
    }
    const args = this.isPunct("(") ? this.parseArguments() : [];
    return { type: "NewExpression", callee, arguments: args, start: kw.start, end: this.prevEnd };
  }

  private parseArrayLiteral(): A.ArrayExpression {
    const open = this.tokens[this.i++];
    const elements: A.Expression[] = [];
    while (!this.isPunct("]")) {
      elements.push(this.parseExpression());
      if (!this.eatPunct(",")) break;
    }
    const close = this.expectPunct("]");
    return { type: "ArrayExpression", elements, start: open.start, end: close.end };
  }

  private parseStructLiteral(): A.StructExpression {
    const open = this.tokens[this.i++];
    const properties: (A.StructProperty | A.PatternEllipsis)[] = [];
    while (!this.isPunct("}")) {
      const kt = this.tok;
      if (this.patternMode && this.isPunct("...")) {
        this.i++;
        properties.push({ type: "PatternEllipsis", start: kt.start, end: kt.end });
      } else {
        let key: A.Identifier | A.StringLiteral;
        if (kt.kind === "string") {
          this.i++;
          key = { type: "StringLiteral", value: kt.value, raw: kt.raw ?? kt.value, start: kt.start, end: kt.end };
        } else if (kt.kind === "number") {
          this.i++;
          key = { type: "StringLiteral", value: kt.value, raw: kt.value, start: kt.start, end: kt.end };
        } else {
          key = this.expectPropertyName();
        }
        let value: A.Expression | null = null;
        if (this.eatPunct(":")) value = this.parseExpression();
        properties.push({ type: "StructProperty", key, value, start: key.start, end: value ? value.end : key.end });
      }
      if (!this.eatPunct(",")) {
        // Tolerate missing commas between properties on separate lines.
        if (this.isPunct("}") || !this.tok.nlBefore) break;
      }
    }
    const close = this.expectPunct("}");
    return { type: "StructExpression", properties, start: open.start, end: close.end };
  }

  private buildTemplate(t: Token): A.TemplateString {
    const parts = t.template!;
    const expressions: A.Expression[] = [];
    for (const [s, e] of parts.exprRanges) {
      const lexed = tokenize(this.src, { start: s, end: e, patternMode: this.patternMode });
      const sub = new Parser(this.src, lexed.tokens, this.patternMode);
      try {
        const expr = sub.parseExpression();
        if (!sub.atEof()) sub.fail(`Unexpected ${sub.describe(sub.tok)} in template expression`);
        expressions.push(expr);
      } catch (err) {
        if (!(err instanceof ParseFailure)) throw err;
        this.errors.push({ message: err.message, start: err.start, end: err.end });
        expressions.push({ type: "Identifier", name: "undefined", start: s, end: e });
      }
      this.errors.push(...lexed.errors, ...sub.errors);
    }
    return { type: "TemplateString", quasis: parts.quasis, expressions, start: t.start, end: t.end };
  }
}

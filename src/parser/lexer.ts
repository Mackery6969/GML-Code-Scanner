import type { Comment, ParseError } from "./ast.ts";

export type TokenKind = "ident" | "number" | "string" | "template" | "punct" | "macro" | "define" | "metavar" | "eof";

export interface TemplateParts {
  quasis: string[];
  /** Absolute [start, end) offsets of each `{expression}` body. */
  exprRanges: [number, number][];
}

export interface MacroInfo {
  name: string;
  nameStart: number;
  nameEnd: number;
  config: string | null;
  body: string;
  bodyStart: number;
  bodyEnd: number;
}

export interface Token {
  kind: TokenKind;
  /** Identifier name, punctuator text, raw number text, or decoded string value. */
  value: string;
  start: number;
  end: number;
  /** A line break appears between the previous token and this one. */
  nlBefore: boolean;
  num?: number;
  raw?: string;
  template?: TemplateParts;
  macro?: MacroInfo;
}

const PUNCTUATORS = [
  "??=",
  "<<=",
  ">>=",
  "...",
  "==",
  "!=",
  "<>",
  "<=",
  ">=",
  "&&",
  "||",
  "^^",
  "++",
  "--",
  "+=",
  "-=",
  "*=",
  "/=",
  "%=",
  "&=",
  "|=",
  "^=",
  "??",
  "<<",
  ">>",
  ":=",
  "{",
  "}",
  "(",
  ")",
  "[",
  "]",
  ";",
  ",",
  ".",
  ":",
  "?",
  "+",
  "-",
  "*",
  "/",
  "%",
  "&",
  "|",
  "^",
  "~",
  "!",
  "<",
  ">",
  "=",
  "@",
  "#",
];

/** Keywords after which an operand (not an operator/accessor) is expected. */
const OPERAND_PREFIX_KEYWORDS = new Set([
  "return",
  "case",
  "and",
  "or",
  "not",
  "xor",
  "mod",
  "div",
  "then",
  "until",
  "throw",
  "if",
  "while",
  "repeat",
  "with",
  "delete",
  "new",
  "var",
  "static",
  "else",
  "do",
  "begin",
  "end",
]);

const isIdentStart = (c: number) => (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 95;
const isIdentPart = (c: number) => isIdentStart(c) || (c >= 48 && c <= 57);
const isDigit = (c: number) => c >= 48 && c <= 57;
const isHex = (c: number) => isDigit(c) || (c >= 65 && c <= 70) || (c >= 97 && c <= 102);

export interface LexResult {
  tokens: Token[];
  comments: Comment[];
  errors: ParseError[];
}

export interface LexOptions {
  /** Enable `$NAME` metavariables and `...` for pattern rules. */
  patternMode?: boolean;
  start?: number;
  end?: number;
}

export function tokenize(source: string, options: LexOptions = {}): LexResult {
  return new Lexer(source, options).run();
}

class Lexer {
  private pos: number;
  private readonly limit: number;
  private readonly tokens: Token[] = [];
  private readonly comments: Comment[] = [];
  private readonly errors: ParseError[] = [];
  private nlBefore = false;
  private readonly patternMode: boolean;
  private readonly src: string;

  constructor(src: string, options: LexOptions) {
    this.src = src;
    this.pos = options.start ?? 0;
    this.limit = options.end ?? src.length;
    this.patternMode = options.patternMode ?? false;
  }

  run(): LexResult {
    while (true) {
      this.skipTrivia();
      if (this.pos >= this.limit) break;
      this.next();
    }
    this.tokens.push({ kind: "eof", value: "", start: this.limit, end: this.limit, nlBefore: true });
    return { tokens: this.tokens, comments: this.comments, errors: this.errors };
  }

  private code(offset = 0): number {
    const p = this.pos + offset;
    return p < this.limit ? this.src.charCodeAt(p) : -1;
  }

  private push(tok: Omit<Token, "nlBefore">): void {
    this.tokens.push({ ...tok, nlBefore: this.nlBefore });
    this.nlBefore = false;
  }

  private error(message: string, start: number, end: number): void {
    this.errors.push({ message, start, end });
  }

  private skipTrivia(): void {
    while (this.pos < this.limit) {
      const c = this.code();
      if (c === 10) {
        this.nlBefore = true;
        this.pos++;
      } else if (c === 32 || c === 9 || c === 13 || c === 11 || c === 12 || c === 0xfeff || c === 0xa0) {
        this.pos++;
      } else if (c === 92 /* \ line continuation (macros) */ && this.isLineContinuation(this.pos)) {
        this.pos++;
      } else if (c === 47 && this.code(1) === 47) {
        const start = this.pos;
        while (this.pos < this.limit && this.code() !== 10) this.pos++;
        this.comments.push({ kind: "line", value: this.src.slice(start + 2, this.pos).replace(/\r$/, ""), start, end: this.pos });
      } else if (c === 47 && this.code(1) === 42) {
        const start = this.pos;
        const close = this.src.indexOf("*/", this.pos + 2);
        const end = close < 0 || close + 2 > this.limit ? this.limit : close + 2;
        if (close < 0 || close + 2 > this.limit) this.error("Unterminated block comment", start, end);
        const value = this.src.slice(start + 2, close < 0 ? end : close);
        if (value.includes("\n")) this.nlBefore = true;
        this.comments.push({ kind: "block", value, start, end });
        this.pos = end;
      } else if (c === 35 /* # */ && this.isDirective()) {
        if (this.startsWithWord("macro") || this.startsWithWord("define")) return; // become tokens
        // #region / #endregion / #define and friends: ignore the rest of the line
        while (this.pos < this.limit && this.code() !== 10) this.pos++;
      } else {
        return;
      }
    }
  }

  private isLineContinuation(p: number): boolean {
    let i = p + 1;
    while (i < this.limit && (this.src.charCodeAt(i) === 32 || this.src.charCodeAt(i) === 9 || this.src.charCodeAt(i) === 13)) i++;
    return i >= this.limit || this.src.charCodeAt(i) === 10;
  }

  /** `#` followed by a word that is not a 6-digit colour literal. */
  private isDirective(): boolean {
    if (!isIdentStart(this.code(1))) return false;
    return !this.isColorLiteral();
  }

  private isColorLiteral(): boolean {
    for (let i = 1; i <= 6; i++) if (!isHex(this.code(i))) return false;
    return !isIdentPart(this.code(7));
  }

  private startsWithWord(word: string): boolean {
    if (this.src.startsWith(word, this.pos + 1)) return !isIdentPart(this.code(word.length + 1));
    return false;
  }

  private prevEndsOperand(): boolean {
    const prev = this.tokens[this.tokens.length - 1];
    if (!prev) return false;
    switch (prev.kind) {
      case "number":
      case "string":
      case "template":
      case "metavar":
        return true;
      case "ident":
        return !OPERAND_PREFIX_KEYWORDS.has(prev.value);
      case "punct":
        return prev.value === ")" || prev.value === "]" || prev.value === "}" || prev.value === "++" || prev.value === "--";
      default:
        return false;
    }
  }

  private next(): void {
    const start = this.pos;
    const c = this.code();

    if (c === 35 && this.startsWithWord("macro")) return this.readMacro();
    if (c === 35 && this.startsWithWord("define")) return this.readDefine();

    if (isIdentStart(c)) {
      while (isIdentPart(this.code())) this.pos++;
      this.push({ kind: "ident", value: this.src.slice(start, this.pos), start, end: this.pos });
      return;
    }

    if (isDigit(c) || (c === 46 && isDigit(this.code(1)) && !this.prevEndsOperand())) return this.readNumber();

    if (c === 36 /* $ */) {
      if (this.code(1) === 34 || this.code(1) === 39) return this.readTemplate();
      if (this.patternMode && this.isUpperMetavar()) {
        this.pos++;
        while (isIdentPart(this.code())) this.pos++;
        this.push({ kind: "metavar", value: this.src.slice(start + 1, this.pos), start, end: this.pos });
        return;
      }
      if (isHex(this.code(1))) {
        this.pos++;
        while (isHex(this.code()) || this.code() === 95) this.pos++;
        const raw = this.src.slice(start, this.pos);
        this.push({ kind: "number", value: raw, raw, num: parseInt(raw.slice(1).replace(/_/g, ""), 16), start, end: this.pos });
        return;
      }
    }

    if (c === 35 /* # */ && this.isColorLiteral()) {
      this.pos += 7;
      const raw = this.src.slice(start, this.pos);
      const rgb = parseInt(raw.slice(1), 16);
      // GameMaker stores colours as BGR.
      const bgr = ((rgb & 0xff) << 16) | (rgb & 0xff00) | ((rgb >> 16) & 0xff);
      this.push({ kind: "number", value: raw, raw, num: bgr, start, end: this.pos });
      return;
    }

    if (c === 64 /* @ */ && (this.code(1) === 34 || this.code(1) === 39)) return this.readVerbatimString();
    if (c === 34 /* " */) return this.readString(34, true);
    if (c === 39 /* ' */) return this.readString(39, false);

    if (c === 91 /* [ */ && this.prevEndsOperand()) {
      const n = this.code(1);
      // [| [? [# [@ [$ accessors
      if (n === 124 || n === 63 || n === 35 || n === 64 || n === 36) {
        this.pos += 2;
        this.push({ kind: "punct", value: this.src.slice(start, this.pos), start, end: this.pos });
        return;
      }
    }

    for (const p of PUNCTUATORS) {
      if (this.src.startsWith(p, this.pos) && this.pos + p.length <= this.limit) {
        if (p === "..." && !this.patternMode) continue;
        this.pos += p.length;
        this.push({ kind: "punct", value: p, start, end: this.pos });
        return;
      }
    }

    this.pos++;
    this.error(`Unexpected character '${this.src[start]}'`, start, this.pos);
  }

  private isUpperMetavar(): boolean {
    // `$A`..`$F` would otherwise read as hex; in pattern mode an uppercase name is a metavariable.
    let i = 1;
    while (isIdentPart(this.code(i))) {
      const ch = this.code(i);
      if (ch >= 97 && ch <= 122) return false;
      i++;
    }
    return i > 1;
  }

  private readNumber(): void {
    const start = this.pos;
    if (this.code() === 48 && (this.code(1) === 120 || this.code(1) === 88)) {
      this.pos += 2;
      while (isHex(this.code()) || this.code() === 95) this.pos++;
      const raw = this.src.slice(start, this.pos);
      this.push({ kind: "number", value: raw, raw, num: parseInt(raw.slice(2).replace(/_/g, ""), 16), start, end: this.pos });
      return;
    }
    if (this.code() === 48 && (this.code(1) === 98 || this.code(1) === 66) && (this.code(2) === 48 || this.code(2) === 49)) {
      this.pos += 2;
      while (this.code() === 48 || this.code() === 49 || this.code() === 95) this.pos++;
      const raw = this.src.slice(start, this.pos);
      this.push({ kind: "number", value: raw, raw, num: parseInt(raw.slice(2).replace(/_/g, ""), 2), start, end: this.pos });
      return;
    }
    while (isDigit(this.code()) || this.code() === 95) this.pos++;
    if (this.code() === 46 && isDigit(this.code(1))) {
      this.pos++;
      while (isDigit(this.code()) || this.code() === 95) this.pos++;
    } else if (this.code() === 46 && !isIdentStart(this.code(1)) && this.code(1) !== 46) {
      this.pos++; // `1.` is a valid real
    }
    if ((this.code() === 101 || this.code() === 69) && (isDigit(this.code(1)) || ((this.code(1) === 43 || this.code(1) === 45) && isDigit(this.code(2))))) {
      this.pos += 2;
      while (isDigit(this.code())) this.pos++;
    }
    const raw = this.src.slice(start, this.pos);
    this.push({ kind: "number", value: raw, raw, num: Number(raw.replace(/_/g, "")), start, end: this.pos });
  }

  private readString(quote: number, escapes: boolean): void {
    const start = this.pos;
    this.pos++;
    let value = "";
    let chunkStart = this.pos;
    while (true) {
      if (this.pos >= this.limit) {
        this.error("Unterminated string literal", start, this.pos);
        value += this.src.slice(chunkStart, this.pos);
        break;
      }
      const c = this.code();
      if (c === quote) {
        value += this.src.slice(chunkStart, this.pos);
        this.pos++;
        break;
      }
      if (escapes && c === 92) {
        value += this.src.slice(chunkStart, this.pos);
        value += this.readEscape();
        chunkStart = this.pos;
        continue;
      }
      if (c === 10) this.nlBefore = this.nlBefore; // raw newlines are tolerated (legacy)
      this.pos++;
    }
    this.push({ kind: "string", value, raw: this.src.slice(start, this.pos), start, end: this.pos });
  }

  private readEscape(): string {
    this.pos++; // backslash
    const c = this.src[this.pos];
    this.pos++;
    switch (c) {
      case "n":
        return "\n";
      case "r":
        return "\r";
      case "t":
        return "\t";
      case "b":
        return "\b";
      case "f":
        return "\f";
      case "v":
        return "\v";
      case "a":
        return "\x07";
      case "0":
        return "\0";
      case "x": {
        const m = /^[0-9a-fA-F]{1,2}/.exec(this.src.slice(this.pos, this.pos + 2));
        if (!m) return "x";
        this.pos += m[0].length;
        return String.fromCharCode(parseInt(m[0], 16));
      }
      case "u": {
        if (this.src[this.pos] === "{") {
          const close = this.src.indexOf("}", this.pos);
          if (close > 0 && close - this.pos <= 8) {
            const cp = parseInt(this.src.slice(this.pos + 1, close), 16);
            this.pos = close + 1;
            return Number.isFinite(cp) ? String.fromCodePoint(cp) : "";
          }
        }
        const m = /^[0-9a-fA-F]{1,6}/.exec(this.src.slice(this.pos, this.pos + 6));
        if (!m) return "u";
        this.pos += m[0].length;
        return String.fromCodePoint(parseInt(m[0], 16));
      }
      case "\r":
        if (this.src[this.pos] === "\n") this.pos++;
        return "";
      case "\n":
        return "";
      case undefined:
        return "";
      default:
        return c;
    }
  }

  private readVerbatimString(): void {
    const start = this.pos;
    const quote = this.src[this.pos + 1];
    const close = this.src.indexOf(quote, this.pos + 2);
    if (close < 0 || close >= this.limit) {
      this.error("Unterminated string literal", start, this.limit);
      this.pos = this.limit;
    } else {
      this.pos = close + 1;
    }
    const value = this.src.slice(start + 2, Math.max(start + 2, this.pos - 1));
    if (value.includes("\n")) this.nlBefore = this.nlBefore;
    this.push({ kind: "string", value, raw: this.src.slice(start, this.pos), start, end: this.pos });
  }

  private readTemplate(): void {
    const start = this.pos;
    const quote = this.code(1);
    this.pos += 2;
    const quasis: string[] = [];
    const exprRanges: [number, number][] = [];
    let text = "";
    while (true) {
      if (this.pos >= this.limit) {
        this.error("Unterminated template string", start, this.pos);
        break;
      }
      const c = this.code();
      if (c === quote) {
        this.pos++;
        break;
      }
      if (c === 92) {
        text += this.readEscape();
        continue;
      }
      if (c === 123 /* { */) {
        quasis.push(text);
        text = "";
        const exprStart = ++this.pos;
        let depth = 0;
        while (this.pos < this.limit) {
          const d = this.code();
          if (d === 34 || d === 39) {
            this.skipQuoted(d);
            continue;
          }
          if (d === 123) depth++;
          else if (d === 125) {
            if (depth === 0) break;
            depth--;
          }
          this.pos++;
        }
        exprRanges.push([exprStart, this.pos]);
        if (this.pos < this.limit) this.pos++; // }
        continue;
      }
      text += this.src[this.pos];
      this.pos++;
    }
    quasis.push(text);
    this.push({ kind: "template", value: "", raw: this.src.slice(start, this.pos), template: { quasis, exprRanges }, start, end: this.pos });
  }

  private skipQuoted(quote: number): void {
    this.pos++;
    while (this.pos < this.limit && this.code() !== quote) {
      if (this.code() === 92) this.pos++;
      this.pos++;
    }
    this.pos++;
  }

  /** `#define name` starts a new script in legacy/extension .gml files. */
  private readDefine(): void {
    const start = this.pos;
    this.pos += "#define".length;
    while (this.code() === 32 || this.code() === 9) this.pos++;
    const nameStart = this.pos;
    while (isIdentPart(this.code())) this.pos++;
    const name = this.src.slice(nameStart, this.pos);
    this.push({ kind: "define", value: name, raw: String(nameStart), start, end: this.pos });
    while (this.pos < this.limit && this.code() !== 10) this.pos++;
  }

  private readMacro(): void {
    const start = this.pos;
    this.pos += "#macro".length;
    while (this.code() === 32 || this.code() === 9) this.pos++;
    const nameStart = this.pos;
    while (isIdentPart(this.code())) this.pos++;
    let name = this.src.slice(nameStart, this.pos);
    let config: string | null = null;
    let realNameStart = nameStart;
    if (this.code() === 58 /* : */ && isIdentStart(this.code(1))) {
      config = name;
      this.pos++;
      realNameStart = this.pos;
      while (isIdentPart(this.code())) this.pos++;
      name = this.src.slice(realNameStart, this.pos);
    }
    const nameEnd = this.pos;
    if (!name) this.error("Expected macro name", start, this.pos);
    while (this.code() === 32 || this.code() === 9) this.pos++;
    const bodyStart = this.pos;
    let bodyEnd = this.pos;
    // Body runs to end of line; a trailing backslash continues it. Stop at `//` comments.
    while (this.pos < this.limit) {
      const c = this.code();
      if (c === 34 || c === 39) {
        const q = c;
        this.pos++;
        while (this.pos < this.limit && this.code() !== q && this.code() !== 10) {
          if (this.code() === 92 && q === 34) this.pos++;
          this.pos++;
        }
        if (this.code() === q) this.pos++;
        bodyEnd = this.pos;
        continue;
      }
      if (c === 47 && this.code(1) === 47) {
        const cstart = this.pos;
        while (this.pos < this.limit && this.code() !== 10) this.pos++;
        this.comments.push({ kind: "line", value: this.src.slice(cstart + 2, this.pos).replace(/\r$/, ""), start: cstart, end: this.pos });
        break;
      }
      if (c === 92 && this.isLineContinuation(this.pos)) {
        while (this.pos < this.limit && this.code() !== 10) this.pos++;
        this.pos++;
        continue;
      }
      if (c === 10) break;
      this.pos++;
      if (c !== 13 && c !== 32 && c !== 9) bodyEnd = this.pos;
    }
    const body = this.src.slice(bodyStart, bodyEnd);
    this.push({
      kind: "macro",
      value: name,
      start,
      end: bodyEnd > nameEnd ? bodyEnd : nameEnd,
      macro: { name, nameStart: realNameStart, nameEnd, config, body, bodyStart, bodyEnd },
    });
  }
}

#!/usr/bin/env node

// src/cli.ts
import { existsSync as existsSync3, mkdirSync, writeFileSync } from "node:fs";
import { dirname as dirname2, join as join5, resolve as resolve2 } from "node:path";
import { parseArgs } from "node:util";

// src/engine/config.ts
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

// src/project/yy.ts
function parseYy(text) {
  return JSON.parse(stripTrailingCommas(text.replace(/^﻿/, "")));
}
function tryParseYy(text) {
  try {
    const v = parseYy(text);
    return v && typeof v === "object" ? v : void 0;
  } catch {
    return void 0;
  }
}
function stripTrailingCommas(text) {
  let out = "";
  let inString = false;
  let chunkStart = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (inString) {
      if (c === 92) i++;
      else if (c === 34) inString = false;
      continue;
    }
    if (c === 34) {
      inString = true;
    } else if (c === 44) {
      let j = i + 1;
      while (j < text.length && /\s/.test(text[j])) j++;
      if (text[j] === "}" || text[j] === "]") {
        out += text.slice(chunkStart, i);
        chunkStart = i + 1;
      }
    }
  }
  return out + text.slice(chunkStart);
}
function yyName(obj) {
  if (!obj || typeof obj !== "object") return void 0;
  const o = obj;
  const n = o.name ?? o["%Name"];
  return typeof n === "string" ? n : void 0;
}
function yyRef(value) {
  if (!value || typeof value !== "object") return void 0;
  const o = value;
  if (typeof o.name === "string" && typeof o.path === "string") return { name: o.name, path: o.path };
  return void 0;
}
function yyArray(value) {
  return Array.isArray(value) ? value : [];
}
function scanYypResources(text) {
  const out = [];
  const header = /"resources"\s*:\s*\[/.exec(text);
  if (!header) return out;
  const start = header.index + header[0].length;
  const end = findArrayEnd(text, start);
  const re = /"id"\s*:\s*\{\s*"name"\s*:\s*"((?:[^"\\]|\\.)*)"\s*,\s*"path"\s*:\s*"((?:[^"\\]|\\.)*)"/g;
  re.lastIndex = start;
  for (let m = re.exec(text); m && m.index < end; m = re.exec(text)) {
    out.push({ name: m[1], path: m[2], start: m.index, end: m.index + m[0].length });
  }
  return out;
}
function findArrayEnd(text, from) {
  let depth = 1;
  let inString = false;
  for (let i = from; i < text.length; i++) {
    const c = text[i];
    if (inString) {
      if (c === "\\") i++;
      else if (c === '"') inString = false;
    } else if (c === '"') inString = true;
    else if (c === "[" || c === "{") depth++;
    else if (c === "]" || c === "}") {
      depth--;
      if (depth === 0) return i;
    }
  }
  return text.length;
}

// src/engine/config.ts
var CONFIG_FILE_NAMES = [".gmlscan.json", "gmlscan.json", ".github/gmlscan.json"];
function defaultConfig() {
  return {
    suite: "default",
    rules: {},
    ignore: [],
    threatModels: ["remote"],
    globalPrefixes: [],
    taint: { sources: [], sinks: [], sanitizers: [] },
    patterns: []
  };
}
function parseJsonc(text) {
  let out = "";
  let i = 0;
  let inString = false;
  while (i < text.length) {
    const c = text[i];
    if (inString) {
      out += c;
      if (c === "\\") {
        out += text[i + 1] ?? "";
        i += 2;
        continue;
      }
      if (c === '"') inString = false;
      i++;
    } else if (c === '"') {
      inString = true;
      out += c;
      i++;
    } else if (c === "/" && text[i + 1] === "/") {
      while (i < text.length && text[i] !== "\n") i++;
    } else if (c === "/" && text[i + 1] === "*") {
      const close = text.indexOf("*/", i + 2);
      i = close < 0 ? text.length : close + 2;
    } else {
      out += c;
      i++;
    }
  }
  return JSON.parse(stripTrailingCommas(out));
}
var ConfigError = class extends Error {
};
function loadConfig(root, explicitPath) {
  const candidates = explicitPath ? [explicitPath] : CONFIG_FILE_NAMES.map((n) => join(root, n));
  for (const path of candidates) {
    if (!existsSync(path)) {
      if (explicitPath) throw new ConfigError(`Config file not found: ${path}`);
      continue;
    }
    let raw;
    try {
      raw = parseJsonc(readFileSync(path, "utf8"));
    } catch (e) {
      throw new ConfigError(`Invalid JSON in ${path}: ${e.message}`);
    }
    return { ...resolveConfig(validate(raw, path)), path };
  }
  return defaultConfig();
}
var SUITES = ["default", "security-extended", "security-and-quality", "all"];
function validate(raw, path) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new ConfigError(`${path}: expected a JSON object`);
  const c = raw;
  if (c.suite !== void 0 && !SUITES.includes(c.suite)) throw new ConfigError(`${path}: "suite" must be one of ${SUITES.join(", ")}`);
  if (c.threatModels !== void 0 && (!Array.isArray(c.threatModels) || c.threatModels.some((t) => t !== "remote" && t !== "local"))) {
    throw new ConfigError(`${path}: "threatModels" must be an array of "remote" / "local"`);
  }
  for (const [id, setting] of Object.entries(c.rules ?? {})) {
    const sev = typeof setting === "string" ? setting : setting?.severity;
    if (sev !== void 0 && !["off", "error", "warning", "note"].includes(sev)) {
      throw new ConfigError(`${path}: rules["${id}"] must be "off", "error", "warning" or "note"`);
    }
  }
  for (const p of c.patterns ?? []) {
    if (!p.id || !p.pattern || !p.message) throw new ConfigError(`${path}: each pattern rule needs "id", "pattern" and "message"`);
  }
  return c;
}
function resolveConfig(c) {
  const d = defaultConfig();
  return {
    suite: c.suite ?? d.suite,
    rules: c.rules ?? {},
    ignore: c.ignore ?? [],
    runtime: c.runtime,
    threatModels: c.threatModels ?? d.threatModels,
    globalPrefixes: c.globalPrefixes ?? [],
    taint: {
      sources: c.taint?.sources ?? [],
      sinks: c.taint?.sinks ?? [],
      sanitizers: c.taint?.sanitizers ?? []
    },
    patterns: c.patterns ?? []
  };
}
function globToRegExp(glob) {
  let g = glob.replace(/\\/g, "/").replace(/^\.\//, "");
  const anchored = g.startsWith("/");
  if (anchored) g = g.slice(1);
  let re = "";
  for (let i = 0; i < g.length; i++) {
    const c = g[i];
    if (c === "*") {
      if (g[i + 1] === "*") {
        const slash = g[i + 2] === "/";
        re += slash ? "(?:.*/)?" : ".*";
        i += slash ? 2 : 1;
      } else re += "[^/]*";
    } else if (c === "?") re += "[^/]";
    else re += /[.+^${}()|[\]\\]/.test(c) ? "\\" + c : c;
  }
  const prefix = anchored || g.includes("/") ? "^" : "^(?:.*/)?";
  return new RegExp(`${prefix}${re}(?:/.*)?$`);
}
function makeIgnoreMatcher(globs) {
  const res = globs.map(globToRegExp);
  return (p) => res.some((r) => r.test(p));
}

// src/engine/scanner.ts
import { resolve } from "node:path";

// src/parser/walk.ts
function forEachChild(node, cb) {
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
function walk(root, enter, leave) {
  const ancestors = [];
  let skipped = false;
  const ctx = {
    ancestors,
    skip() {
      skipped = true;
    }
  };
  const visit = (node) => {
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
function isTerminator(stmt) {
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
function alwaysExits(stmt) {
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

// src/project/loader.ts
import { existsSync as existsSync2, lstatSync, readdirSync, readFileSync as readFileSync2, statSync } from "node:fs";
import { basename, dirname, isAbsolute, join as join2, normalize, relative, sep } from "node:path";

// src/parser/lexer.ts
var PUNCTUATORS = [
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
  "#"
];
var OPERAND_PREFIX_KEYWORDS = /* @__PURE__ */ new Set([
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
  "end"
]);
var isIdentStart = (c) => c >= 65 && c <= 90 || c >= 97 && c <= 122 || c === 95;
var isIdentPart = (c) => isIdentStart(c) || c >= 48 && c <= 57;
var isDigit = (c) => c >= 48 && c <= 57;
var isHex = (c) => isDigit(c) || c >= 65 && c <= 70 || c >= 97 && c <= 102;
function tokenize(source, options = {}) {
  return new Lexer(source, options).run();
}
var Lexer = class {
  pos;
  limit;
  tokens = [];
  comments = [];
  errors = [];
  nlBefore = false;
  patternMode;
  src;
  constructor(src, options) {
    this.src = src;
    this.pos = options.start ?? 0;
    this.limit = options.end ?? src.length;
    this.patternMode = options.patternMode ?? false;
  }
  run() {
    while (true) {
      this.skipTrivia();
      if (this.pos >= this.limit) break;
      this.next();
    }
    this.tokens.push({ kind: "eof", value: "", start: this.limit, end: this.limit, nlBefore: true });
    return { tokens: this.tokens, comments: this.comments, errors: this.errors };
  }
  code(offset = 0) {
    const p = this.pos + offset;
    return p < this.limit ? this.src.charCodeAt(p) : -1;
  }
  push(tok) {
    this.tokens.push({ ...tok, nlBefore: this.nlBefore });
    this.nlBefore = false;
  }
  error(message, start, end) {
    this.errors.push({ message, start, end });
  }
  skipTrivia() {
    while (this.pos < this.limit) {
      const c = this.code();
      if (c === 10) {
        this.nlBefore = true;
        this.pos++;
      } else if (c === 32 || c === 9 || c === 13 || c === 11 || c === 12 || c === 65279 || c === 160) {
        this.pos++;
      } else if (c === 92 && this.isLineContinuation(this.pos)) {
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
      } else if (c === 35 && this.isDirective()) {
        if (this.startsWithWord("macro") || this.startsWithWord("define")) return;
        while (this.pos < this.limit && this.code() !== 10) this.pos++;
      } else {
        return;
      }
    }
  }
  isLineContinuation(p) {
    let i = p + 1;
    while (i < this.limit && (this.src.charCodeAt(i) === 32 || this.src.charCodeAt(i) === 9 || this.src.charCodeAt(i) === 13)) i++;
    return i >= this.limit || this.src.charCodeAt(i) === 10;
  }
  /** `#` followed by a word that is not a 6-digit colour literal. */
  isDirective() {
    if (!isIdentStart(this.code(1))) return false;
    return !this.isColorLiteral();
  }
  isColorLiteral() {
    for (let i = 1; i <= 6; i++) if (!isHex(this.code(i))) return false;
    return !isIdentPart(this.code(7));
  }
  startsWithWord(word) {
    if (this.src.startsWith(word, this.pos + 1)) return !isIdentPart(this.code(word.length + 1));
    return false;
  }
  prevEndsOperand() {
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
  next() {
    const start = this.pos;
    const c = this.code();
    if (c === 35 && this.startsWithWord("macro")) return this.readMacro();
    if (c === 35 && this.startsWithWord("define")) return this.readDefine();
    if (isIdentStart(c)) {
      while (isIdentPart(this.code())) this.pos++;
      this.push({ kind: "ident", value: this.src.slice(start, this.pos), start, end: this.pos });
      return;
    }
    if (isDigit(c) || c === 46 && isDigit(this.code(1)) && !this.prevEndsOperand()) return this.readNumber();
    if (c === 36) {
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
    if (c === 35 && this.isColorLiteral()) {
      this.pos += 7;
      const raw = this.src.slice(start, this.pos);
      const rgb = parseInt(raw.slice(1), 16);
      const bgr = (rgb & 255) << 16 | rgb & 65280 | rgb >> 16 & 255;
      this.push({ kind: "number", value: raw, raw, num: bgr, start, end: this.pos });
      return;
    }
    if (c === 64 && (this.code(1) === 34 || this.code(1) === 39)) return this.readVerbatimString();
    if (c === 34) return this.readString(34, true);
    if (c === 39) return this.readString(39, false);
    if (c === 91 && this.prevEndsOperand()) {
      const n = this.code(1);
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
  isUpperMetavar() {
    let i = 1;
    while (isIdentPart(this.code(i))) {
      const ch = this.code(i);
      if (ch >= 97 && ch <= 122) return false;
      i++;
    }
    return i > 1;
  }
  readNumber() {
    const start = this.pos;
    if (this.code() === 48 && (this.code(1) === 120 || this.code(1) === 88)) {
      this.pos += 2;
      while (isHex(this.code()) || this.code() === 95) this.pos++;
      const raw2 = this.src.slice(start, this.pos);
      this.push({ kind: "number", value: raw2, raw: raw2, num: parseInt(raw2.slice(2).replace(/_/g, ""), 16), start, end: this.pos });
      return;
    }
    if (this.code() === 48 && (this.code(1) === 98 || this.code(1) === 66) && (this.code(2) === 48 || this.code(2) === 49)) {
      this.pos += 2;
      while (this.code() === 48 || this.code() === 49 || this.code() === 95) this.pos++;
      const raw2 = this.src.slice(start, this.pos);
      this.push({ kind: "number", value: raw2, raw: raw2, num: parseInt(raw2.slice(2).replace(/_/g, ""), 2), start, end: this.pos });
      return;
    }
    while (isDigit(this.code()) || this.code() === 95) this.pos++;
    if (this.code() === 46 && isDigit(this.code(1))) {
      this.pos++;
      while (isDigit(this.code()) || this.code() === 95) this.pos++;
    } else if (this.code() === 46 && !isIdentStart(this.code(1)) && this.code(1) !== 46) {
      this.pos++;
    }
    if ((this.code() === 101 || this.code() === 69) && (isDigit(this.code(1)) || (this.code(1) === 43 || this.code(1) === 45) && isDigit(this.code(2)))) {
      this.pos += 2;
      while (isDigit(this.code())) this.pos++;
    }
    const raw = this.src.slice(start, this.pos);
    this.push({ kind: "number", value: raw, raw, num: Number(raw.replace(/_/g, "")), start, end: this.pos });
  }
  readString(quote, escapes) {
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
      if (c === 10) this.nlBefore = this.nlBefore;
      this.pos++;
    }
    this.push({ kind: "string", value, raw: this.src.slice(start, this.pos), start, end: this.pos });
  }
  readEscape() {
    this.pos++;
    const c = this.src[this.pos];
    this.pos++;
    switch (c) {
      case "n":
        return "\n";
      case "r":
        return "\r";
      case "t":
        return "	";
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
      case void 0:
        return "";
      default:
        return c;
    }
  }
  readVerbatimString() {
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
  readTemplate() {
    const start = this.pos;
    const quote = this.code(1);
    this.pos += 2;
    const quasis = [];
    const exprRanges = [];
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
      if (c === 123) {
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
        if (this.pos < this.limit) this.pos++;
        continue;
      }
      text += this.src[this.pos];
      this.pos++;
    }
    quasis.push(text);
    this.push({ kind: "template", value: "", raw: this.src.slice(start, this.pos), template: { quasis, exprRanges }, start, end: this.pos });
  }
  skipQuoted(quote) {
    this.pos++;
    while (this.pos < this.limit && this.code() !== quote) {
      if (this.code() === 92) this.pos++;
      this.pos++;
    }
    this.pos++;
  }
  /** `#define name` starts a new script in legacy/extension .gml files. */
  readDefine() {
    const start = this.pos;
    this.pos += "#define".length;
    while (this.code() === 32 || this.code() === 9) this.pos++;
    const nameStart = this.pos;
    while (isIdentPart(this.code())) this.pos++;
    const name = this.src.slice(nameStart, this.pos);
    this.push({ kind: "define", value: name, raw: String(nameStart), start, end: this.pos });
    while (this.pos < this.limit && this.code() !== 10) this.pos++;
  }
  readMacro() {
    const start = this.pos;
    this.pos += "#macro".length;
    while (this.code() === 32 || this.code() === 9) this.pos++;
    const nameStart = this.pos;
    while (isIdentPart(this.code())) this.pos++;
    let name = this.src.slice(nameStart, this.pos);
    let config = null;
    let realNameStart = nameStart;
    if (this.code() === 58 && isIdentStart(this.code(1))) {
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
      macro: { name, nameStart: realNameStart, nameEnd, config, body, bodyStart, bodyEnd }
    });
  }
};

// src/parser/parser.ts
var ParseFailure = class extends Error {
  start;
  end;
  constructor(message, start, end) {
    super(message);
    this.start = start;
    this.end = end;
  }
};
var KEYWORDS = /* @__PURE__ */ new Set([
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
  "div"
]);
var STATEMENT_KEYWORDS = /* @__PURE__ */ new Set([
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
  "enum"
]);
var BINARY_OPS = {
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
  div: { prec: 12, op: "div" }
};
var ASSIGN_OPS = /* @__PURE__ */ new Set(["=", ":=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>=", "??="]);
var ACCESSORS = { "[": "", "[|": "|", "[?": "?", "[#": "#", "[@": "@", "[$": "$" };
function parse(source, options = {}) {
  const lexed = tokenize(source, { patternMode: options.patternMode });
  const parser = new Parser(source, lexed.tokens, options.patternMode ?? false);
  const body = parser.parseProgramBody();
  const errors = [...lexed.errors, ...parser.errors].sort((a, b) => a.start - b.start);
  return { type: "Program", body, comments: lexed.comments, errors, start: 0, end: source.length };
}
function parsePattern(source) {
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
var Parser = class _Parser {
  i = 0;
  errors = [];
  src;
  tokens;
  patternMode;
  constructor(src, tokens, patternMode) {
    this.src = src;
    this.tokens = tokens;
    this.patternMode = patternMode;
  }
  // -------------------------------------------------------------------------
  // Token helpers
  get tok() {
    return this.tokens[this.i];
  }
  peek(k = 1) {
    return this.tokens[Math.min(this.i + k, this.tokens.length - 1)];
  }
  get prevEnd() {
    return this.i > 0 ? this.tokens[this.i - 1].end : 0;
  }
  atEof() {
    return this.tok.kind === "eof";
  }
  isPunct(v, t = this.tok) {
    return t.kind === "punct" && t.value === v;
  }
  isWord(v, t = this.tok) {
    return t.kind === "ident" && t.value === v;
  }
  eatPunct(v) {
    if (this.isPunct(v)) {
      this.i++;
      return true;
    }
    return false;
  }
  eatWord(v) {
    if (this.isWord(v)) {
      this.i++;
      return true;
    }
    return false;
  }
  fail(message, t = this.tok) {
    throw new ParseFailure(message, t.start, Math.max(t.end, t.start + 1));
  }
  describe(t) {
    if (t.kind === "eof") return "end of file";
    if (t.kind === "string") return "string";
    if (t.kind === "define") return "#define";
    if (t.kind === "template") return "template string";
    if (t.kind === "macro") return "#macro";
    return `'${t.value}'`;
  }
  expectPunct(v) {
    if (!this.isPunct(v)) this.fail(`Expected '${v}' but found ${this.describe(this.tok)}`);
    return this.tokens[this.i++];
  }
  expectIdentifier() {
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
  expectPropertyName() {
    const t = this.tok;
    if (t.kind === "metavar") {
      this.i++;
      return { type: "Identifier", name: "$" + t.value, start: t.start, end: t.end };
    }
    if (t.kind !== "ident") this.fail(`Expected property name but found ${this.describe(t)}`);
    this.i++;
    return { type: "Identifier", name: t.value, start: t.start, end: t.end };
  }
  eatSemicolons() {
    while (this.isPunct(";")) this.i++;
  }
  // -------------------------------------------------------------------------
  // Statements
  parseProgramBody() {
    const atDefine = () => this.tok.kind === "define";
    const body = this.parseStatementList(atDefine);
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
        end: Math.max(end, t.end)
      });
    }
    return body;
  }
  parseStatementList(isEnd) {
    const body = [];
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
  synchronize(before, isEnd) {
    if (this.i === before) this.i++;
    while (!this.atEof()) {
      const t = this.tok;
      if (this.isPunct(";")) {
        this.i++;
        return;
      }
      if (this.isPunct("}") || isEnd()) return;
      if (t.kind === "define") return;
      if (t.nlBefore && (t.kind === "ident" && STATEMENT_KEYWORDS.has(t.value) || t.kind === "macro")) return;
      this.i++;
    }
  }
  parseStatement() {
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
  finishSimple(stmt) {
    this.eatSemicolons();
    return stmt;
  }
  parseBlock() {
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
  parseMacro() {
    const t = this.tokens[this.i++];
    const m = t.macro;
    let value = null;
    if (m.body.trim()) {
      const lexed = tokenize(this.src, { start: m.bodyStart, end: m.bodyEnd, patternMode: this.patternMode });
      const sub = new _Parser(this.src, lexed.tokens, this.patternMode);
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
      end: t.end
    };
  }
  parseVarDeclaration() {
    const kw = this.tokens[this.i++];
    const kind = kw.value;
    const declarations = [];
    do {
      const id = this.expectIdentifier();
      let init = null;
      if (this.isPunct("=") || this.isPunct(":=")) {
        this.i++;
        init = this.parseExpression();
      }
      declarations.push({ type: "VarDeclarator", id, init, start: id.start, end: init ? init.end : id.end });
    } while (this.eatPunct(","));
    return { type: "VarDeclaration", kind, declarations, start: kw.start, end: this.prevEnd };
  }
  parseIf() {
    const kw = this.tokens[this.i++];
    const test = this.parseExpression();
    this.eatWord("then");
    const consequent = this.parseStatement();
    let alternate = null;
    if (this.eatWord("else")) alternate = this.parseStatement();
    return { type: "IfStatement", test, consequent, alternate, start: kw.start, end: (alternate ?? consequent).end };
  }
  parseWhile() {
    const kw = this.tokens[this.i++];
    const test = this.parseExpression();
    this.eatWord("do");
    const body = this.parseStatement();
    return { type: "WhileStatement", test, body, start: kw.start, end: body.end };
  }
  parseDo() {
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
  parseRepeat() {
    const kw = this.tokens[this.i++];
    const count = this.parseExpression();
    const body = this.parseStatement();
    return { type: "RepeatStatement", count, body, start: kw.start, end: body.end };
  }
  parseFor() {
    const kw = this.tokens[this.i++];
    this.expectPunct("(");
    let init = null;
    if (!this.isPunct(";")) {
      init = this.isWord("var") || this.isWord("static") ? this.parseVarDeclaration() : this.parseExpressionStatement(false);
    }
    this.expectPunct(";");
    let test = null;
    if (!this.isPunct(";")) test = this.parseExpression();
    this.expectPunct(";");
    let update = null;
    if (!this.isPunct(")")) update = this.parseExpressionStatement(false);
    this.eatPunct(";");
    this.expectPunct(")");
    const body = this.parseStatement();
    return { type: "ForStatement", init, test, update, body, start: kw.start, end: body.end };
  }
  parseSwitch() {
    const kw = this.tokens[this.i++];
    const discriminant = this.parseExpression();
    const open = this.tok;
    const usesBegin = this.isWord("begin");
    if (!usesBegin) this.expectPunct("{");
    else this.i++;
    const isClose = () => (usesBegin ? this.isWord("end") : false) || this.isPunct("}");
    const cases = [];
    const isCaseStart = () => this.isWord("case") || this.isWord("default");
    while (!this.atEof() && !isClose()) {
      const ct = this.tok;
      if (this.patternMode && this.isPunct("...")) {
        this.i++;
        cases.push({ type: "SwitchCase", test: { type: "PatternEllipsis", start: ct.start, end: ct.end }, body: [], start: ct.start, end: ct.end });
        this.eatSemicolons();
        continue;
      }
      let test = null;
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
  parseWith() {
    const kw = this.tokens[this.i++];
    const object = this.parseExpression();
    const body = this.parseStatement();
    return { type: "WithStatement", object, body, start: kw.start, end: body.end };
  }
  parseReturn() {
    const kw = this.tokens[this.i++];
    const t = this.tok;
    const noArg = this.isPunct(";") || this.isPunct("}") || t.kind === "eof" || this.isWord("case") || this.isWord("default") || this.isWord("end") || this.isWord("else") || t.nlBefore && t.kind === "ident" && STATEMENT_KEYWORDS.has(t.value);
    const argument = noArg ? null : this.parseExpression();
    this.eatSemicolons();
    return { type: "ReturnStatement", argument, start: kw.start, end: argument ? argument.end : kw.end };
  }
  parseTry() {
    const kw = this.tokens[this.i++];
    const block = this.parseBlock();
    let param = null;
    let handler = null;
    let finalizer = null;
    if (this.eatWord("catch")) {
      const paren = this.eatPunct("(");
      if (!(paren && this.isPunct(")"))) param = this.expectIdentifier();
      if (paren) this.expectPunct(")");
      handler = this.parseBlock();
    }
    if (this.eatWord("finally")) finalizer = this.parseBlock();
    return { type: "TryStatement", block, param, handler, finalizer, start: kw.start, end: this.prevEnd };
  }
  parseEnum() {
    const kw = this.tokens[this.i++];
    const id = this.expectIdentifier();
    this.expectPunct("{");
    const members = [];
    while (!this.isPunct("}") && !this.atEof()) {
      const mid = this.expectPropertyName();
      let init = null;
      if (this.eatPunct("=")) init = this.parseExpression();
      members.push({ type: "EnumMember", id: mid, init, start: mid.start, end: init ? init.end : mid.end });
      if (!this.eatPunct(",")) break;
    }
    const close = this.expectPunct("}");
    this.eatSemicolons();
    return { type: "EnumDeclaration", id, members, start: kw.start, end: close.end };
  }
  parseFunctionDeclaration() {
    const fn = this.parseFunctionCommon();
    if (!fn.id) this.fail("Expected function name");
    this.eatSemicolons();
    return { ...fn, type: "FunctionDeclaration", id: fn.id };
  }
  parseFunctionCommon() {
    const kw = this.tokens[this.i++];
    let id = null;
    if (this.tok.kind === "ident" || this.tok.kind === "metavar") id = this.expectIdentifier();
    this.expectPunct("(");
    const params = [];
    while (!this.isPunct(")")) {
      if (this.patternMode && this.isPunct("...")) {
        const t = this.tokens[this.i++];
        params.push({ type: "Parameter", id: { type: "Identifier", name: "...", start: t.start, end: t.end }, init: null, start: t.start, end: t.end });
      } else {
        const pid = this.expectIdentifier();
        let init = null;
        if (this.eatPunct("=")) init = this.parseExpression();
        params.push({ type: "Parameter", id: pid, init, start: pid.start, end: init ? init.end : pid.end });
      }
      if (!this.eatPunct(",")) break;
    }
    this.expectPunct(")");
    let parent = null;
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
  parseExpressionStatement(consumeSemicolon = true) {
    const start = this.tok.start;
    const left = this.parseUnary();
    let expression;
    if (this.tok.kind === "punct" && ASSIGN_OPS.has(this.tok.value)) {
      const opTok = this.tokens[this.i++];
      const right = this.parseExpression();
      const operator = opTok.value === ":=" ? "=" : opTok.value;
      expression = { type: "AssignmentExpression", operator, left, right, start: left.start, end: right.end };
    } else {
      expression = this.parseTernaryRest(this.parseBinaryRest(left, 1));
    }
    if (consumeSemicolon) this.eatSemicolons();
    return { type: "ExpressionStatement", expression, start, end: expression.end };
  }
  // -------------------------------------------------------------------------
  // Expressions
  parseExpression() {
    return this.parseTernaryRest(this.parseBinary(1));
  }
  parseTernaryRest(test) {
    if (!this.isPunct("?")) return test;
    this.i++;
    const consequent = this.parseExpression();
    this.expectPunct(":");
    const alternate = this.parseExpression();
    return { type: "ConditionalExpression", test, consequent, alternate, start: test.start, end: alternate.end };
  }
  binaryInfo(t) {
    if (t.kind === "punct" || t.kind === "ident") return Object.hasOwn(BINARY_OPS, t.value) ? BINARY_OPS[t.value] : void 0;
    return void 0;
  }
  parseBinary(minPrec) {
    return this.parseBinaryRest(this.parseUnary(), minPrec);
  }
  parseBinaryRest(left, minPrec) {
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
  parseUnary() {
    const t = this.tok;
    if (t.kind === "punct" && (t.value === "!" || t.value === "-" || t.value === "+" || t.value === "~")) {
      this.i++;
      const argument = this.parseUnary();
      return { type: "UnaryExpression", operator: t.value, argument, start: t.start, end: argument.end };
    }
    if (this.isWord("not")) {
      this.i++;
      const argument = this.parseUnary();
      return { type: "UnaryExpression", operator: "!", argument, start: t.start, end: argument.end };
    }
    if (t.kind === "punct" && (t.value === "++" || t.value === "--")) {
      this.i++;
      const argument = this.parseUnary();
      return { type: "UpdateExpression", operator: t.value, prefix: true, argument, start: t.start, end: argument.end };
    }
    return this.parsePostfix();
  }
  parsePostfix() {
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
        const indices = [];
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
  parseArguments() {
    this.expectPunct("(");
    const args = [];
    while (!this.isPunct(")")) {
      if (this.isPunct(",")) {
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
  parsePrimary() {
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
  parseIdentifierLike(t) {
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
  parseNew() {
    const kw = this.tokens[this.i++];
    let callee = this.expectIdentifier();
    while (this.isPunct(".")) {
      this.i++;
      const property = this.expectPropertyName();
      callee = { type: "MemberExpression", object: callee, property, start: callee.start, end: property.end };
    }
    const args = this.isPunct("(") ? this.parseArguments() : [];
    return { type: "NewExpression", callee, arguments: args, start: kw.start, end: this.prevEnd };
  }
  parseArrayLiteral() {
    const open = this.tokens[this.i++];
    const elements = [];
    while (!this.isPunct("]")) {
      elements.push(this.parseExpression());
      if (!this.eatPunct(",")) break;
    }
    const close = this.expectPunct("]");
    return { type: "ArrayExpression", elements, start: open.start, end: close.end };
  }
  parseStructLiteral() {
    const open = this.tokens[this.i++];
    const properties = [];
    while (!this.isPunct("}")) {
      const kt = this.tok;
      if (this.patternMode && this.isPunct("...")) {
        this.i++;
        properties.push({ type: "PatternEllipsis", start: kt.start, end: kt.end });
      } else {
        let key;
        if (kt.kind === "string") {
          this.i++;
          key = { type: "StringLiteral", value: kt.value, raw: kt.raw ?? kt.value, start: kt.start, end: kt.end };
        } else if (kt.kind === "number") {
          this.i++;
          key = { type: "StringLiteral", value: kt.value, raw: kt.value, start: kt.start, end: kt.end };
        } else {
          key = this.expectPropertyName();
        }
        let value = null;
        if (this.eatPunct(":")) value = this.parseExpression();
        properties.push({ type: "StructProperty", key, value, start: key.start, end: value ? value.end : key.end });
      }
      if (!this.eatPunct(",")) {
        if (this.isPunct("}") || !this.tok.nlBefore) break;
      }
    }
    const close = this.expectPunct("}");
    return { type: "StructExpression", properties, start: open.start, end: close.end };
  }
  buildTemplate(t) {
    const parts = t.template;
    const expressions = [];
    for (const [s, e] of parts.exprRanges) {
      const lexed = tokenize(this.src, { start: s, end: e, patternMode: this.patternMode });
      const sub = new _Parser(this.src, lexed.tokens, this.patternMode);
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
};

// src/project/events.ts
var EVENT_TYPES = {
  Create: 0,
  Destroy: 1,
  Alarm: 2,
  Step: 3,
  Collision: 4,
  Keyboard: 5,
  Mouse: 6,
  Other: 7,
  Draw: 8,
  KeyPress: 9,
  KeyRelease: 10,
  Trigger: 11,
  CleanUp: 12,
  Gesture: 13,
  PreCreate: 14
};
var OTHER_NAMES = {
  0: "Outside Room",
  1: "Intersect Boundary",
  2: "Game Start",
  3: "Game End",
  4: "Room Start",
  5: "Room End",
  6: "No More Lives",
  7: "Animation End",
  8: "Path Ended",
  9: "No More Health",
  30: "Close Button",
  58: "Animation Update",
  59: "Animation Event",
  60: "Async - Image Loaded",
  61: "Async - Sound Loaded",
  62: "Async - HTTP",
  63: "Async - Dialog",
  66: "Async - In-App Purchase",
  67: "Async - Cloud",
  68: "Async - Networking",
  69: "Async - Steam",
  70: "Async - Social",
  71: "Async - Push Notification",
  72: "Async - Save/Load",
  73: "Async - Audio Recording",
  74: "Async - Audio Playback",
  75: "Async - System",
  76: "Broadcast Message"
};
var DRAW_NAMES = {
  0: "Draw",
  64: "Draw GUI",
  65: "Window Resize",
  72: "Draw Begin",
  73: "Draw End",
  74: "Draw GUI Begin",
  75: "Draw GUI End",
  76: "Pre-Draw",
  77: "Post-Draw"
};
var STEP_NAMES = { 0: "Step", 1: "Begin Step", 2: "End Step" };
function parseEventFileName(base) {
  const m = /^([A-Za-z]+)_(.+)$/.exec(base);
  if (!m) return void 0;
  const kind = m[1];
  if (!Object.hasOwn(EVENT_TYPES, kind)) return void 0;
  const eventType = EVENT_TYPES[kind];
  if (kind === "Collision") {
    return { kind, num: 0, collisionObject: m[2], displayName: `Collision (${m[2]})`, eventType };
  }
  const num = Number(m[2]);
  if (!Number.isInteger(num)) return void 0;
  let displayName;
  switch (kind) {
    case "Step":
      displayName = STEP_NAMES[num] ?? `Step ${num}`;
      break;
    case "Draw":
      displayName = DRAW_NAMES[num] ?? `Draw ${num}`;
      break;
    case "Other":
      displayName = num >= 10 && num <= 25 ? `User Event ${num - 10}` : num >= 40 && num <= 47 ? `Outside View ${num - 40}` : num >= 50 && num <= 57 ? `Intersect View ${num - 50} Boundary` : OTHER_NAMES[num] ?? `Other ${num}`;
      break;
    case "Alarm":
      displayName = `Alarm ${num}`;
      break;
    case "CleanUp":
      displayName = "Clean Up";
      break;
    case "PreCreate":
      displayName = "Pre-Create";
      break;
    case "KeyPress":
      displayName = `Key Press ${num}`;
      break;
    case "KeyRelease":
      displayName = `Key Release ${num}`;
      break;
    default:
      displayName = num === 0 && (kind === "Create" || kind === "Destroy") ? kind : `${kind} ${num}`;
  }
  return { kind, num, displayName, eventType };
}
function isStepEvent(e) {
  return e?.kind === "Step";
}
function isDrawEvent(e) {
  return e?.kind === "Draw" && e.num !== 65;
}
function isPerFrameEvent(e) {
  return isStepEvent(e) || isDrawEvent(e);
}

// src/project/source.ts
var SourceText = class {
  text;
  lineStarts;
  constructor(text) {
    this.text = text;
  }
  starts() {
    if (!this.lineStarts) {
      const starts = [0];
      for (let i = 0; i < this.text.length; i++) if (this.text.charCodeAt(i) === 10) starts.push(i + 1);
      this.lineStarts = starts;
    }
    return this.lineStarts;
  }
  position(offset) {
    const starts = this.starts();
    let lo = 0;
    let hi = starts.length - 1;
    while (lo < hi) {
      const mid = lo + hi + 1 >> 1;
      if (starts[mid] <= offset) lo = mid;
      else hi = mid - 1;
    }
    return { line: lo + 1, column: offset - starts[lo] + 1 };
  }
  /** Text of a 1-based line without its line terminator. */
  lineText(line) {
    const starts = this.starts();
    const s = starts[line - 1];
    if (s === void 0) return "";
    const e = line < starts.length ? starts[line] - 1 : this.text.length;
    return this.text.slice(s, e).replace(/\r$/, "");
  }
  get lineCount() {
    return this.starts().length;
  }
};

// src/project/loader.ts
var SKIP_DIRS = /* @__PURE__ */ new Set([".git", "node_modules", ".svn", ".hg", ".vs", ".vscode", ".idea", "dist", "build", "Build", "tmp", "temp"]);
var CODE_DIRS = ["objects", "scripts", "rooms", "timelines", "extensions"];
var RESOURCE_DIRS = ["objects", "scripts", "rooms", "sprites", "sounds", "fonts", "paths", "timelines", "tilesets", "shaders", "sequences", "animcurves", "extensions", "notes", "particles"];
var REFERENCE_DIRS = ["rooms", "sequences", "objects", "timelines"];
var TEXT_EXTENSIONS = /* @__PURE__ */ new Set([".ini", ".json", ".txt", ".cfg", ".conf", ".xml", ".yml", ".yaml", ".env", ".properties", ".plist", ".csv", ".toml"]);
var MAX_AUX_FILE_SIZE = 512 * 1024;
var toPosix = (p) => p.split(sep).join("/");
function loadWorkspace(rootAbs, options = {}) {
  const isIgnored = options.isIgnored ?? (() => false);
  const ws = { rootAbs, projects: [], auxiliaryFiles: [] };
  const rel = (abs) => toPosix(relative(rootAbs, abs));
  const projectDirs = [];
  const looseGml = [];
  const visit = (dir) => {
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    const yyp = entries.find((e) => e.isFile() && e.name.endsWith(".yyp"));
    if (yyp && !isIgnored(rel(join2(dir, yyp.name)))) {
      projectDirs.push(join2(dir, yyp.name));
      return;
    }
    for (const e of entries) {
      const abs = join2(dir, e.name);
      const r = rel(abs);
      if (isIgnored(r)) continue;
      if (e.isDirectory()) {
        if (!SKIP_DIRS.has(e.name)) visit(abs);
      } else if (e.name.endsWith(".gml")) {
        looseGml.push(abs);
      } else if (isWorkspaceAuxFile(r)) {
        ws.auxiliaryFiles.push(r);
      }
    }
  };
  visit(rootAbs);
  const workflows = join2(rootAbs, ".github", "workflows");
  if (existsSync2(workflows)) {
    for (const f of readdirSync(workflows)) if (/\.ya?ml$/.test(f)) ws.auxiliaryFiles.push(rel(join2(workflows, f)));
  }
  for (const yypAbs of projectDirs) ws.projects.push(loadProject(rootAbs, yypAbs, isIgnored));
  if (looseGml.length > 0) {
    const loose = emptyProject(basename(rootAbs), "", rootAbs);
    for (const abs of looseGml) addGmlFile(loose, rootAbs, abs);
    buildObjectsFromFiles(loose, rootAbs);
    ws.projects.push(loose);
  }
  return ws;
}
function isWorkspaceAuxFile(relPath) {
  const name = relPath.split("/").pop() ?? "";
  return name === ".env" || name.startsWith(".env.") || name === "um.json" || name === "licence.plist";
}
function emptyProject(name, rootRel, rootAbs) {
  return {
    name,
    rootRel,
    rootAbs,
    resources: /* @__PURE__ */ new Map(),
    objects: /* @__PURE__ */ new Map(),
    files: [],
    roomInstances: /* @__PURE__ */ new Set(),
    extensionFunctions: /* @__PURE__ */ new Map(),
    extensionConstants: /* @__PURE__ */ new Set(),
    yyReferences: /* @__PURE__ */ new Map(),
    auxiliaryFiles: []
  };
}
function readText(abs) {
  try {
    if (lstatSync(abs).isSymbolicLink()) return void 0;
    return readFileSync2(abs, "utf8");
  } catch {
    return void 0;
  }
}
function isContainedPath(p) {
  if (isAbsolute(p) || /^[a-zA-Z]:/.test(p) || p.startsWith("\\")) return false;
  return !normalize(p).split(/[\\/]/).includes("..");
}
function listDirs(abs) {
  try {
    return readdirSync(abs, { withFileTypes: true }).filter((e) => e.isDirectory()).map((e) => e.name);
  } catch {
    return [];
  }
}
function listFiles(abs) {
  try {
    return readdirSync(abs, { withFileTypes: true }).filter((e) => e.isFile()).map((e) => e.name);
  } catch {
    return [];
  }
}
function loadProject(wsRoot, yypAbs, isIgnored) {
  const rootAbs = dirname(yypAbs);
  const rel = (abs) => toPosix(relative(wsRoot, abs));
  const project = emptyProject(basename(yypAbs, ".yyp"), rel(rootAbs), rootAbs);
  const prefix = project.rootRel ? project.rootRel + "/" : "";
  const yypText = readText(yypAbs) ?? "";
  const data = tryParseYy(yypText);
  const metaData = data?.MetaData;
  project.yyp = {
    relPath: rel(yypAbs),
    absPath: yypAbs,
    source: new SourceText(yypText),
    data,
    entries: scanYypResources(yypText),
    ideVersion: typeof metaData?.IDEVersion === "string" ? metaData.IDEVersion : void 0
  };
  const addResource = (name, type, yyPath) => {
    const list = project.resources.get(name) ?? [];
    let info = list.find((r) => r.yyRelPath === prefix + yyPath);
    if (!info) {
      info = { name, type, yyRelPath: prefix + yyPath, inYyp: false, onDisk: false, yypEntries: [] };
      list.push(info);
      project.resources.set(name, list);
    }
    return info;
  };
  const uncontained = /* @__PURE__ */ new Set();
  for (const entry of project.yyp.entries) {
    const info = addResource(entry.name, entry.path.split("/")[0], entry.path);
    info.inYyp = true;
    info.yypEntries.push(entry);
    if (!isContainedPath(entry.path)) uncontained.add(info);
  }
  for (const type of RESOURCE_DIRS) {
    const typeDir = join2(rootAbs, type);
    for (const name of listDirs(typeDir)) {
      if (existsSync2(join2(typeDir, name, `${name}.yy`))) addResource(name, type, `${type}/${name}/${name}.yy`).onDisk = true;
    }
  }
  for (const list of project.resources.values()) {
    for (const r of list) if (!r.onDisk && r.inYyp && !uncontained.has(r)) r.onDisk = existsSync2(join2(wsRoot, r.yyRelPath));
  }
  for (const dir of CODE_DIRS) {
    const typeDir = join2(rootAbs, dir);
    for (const name of listDirs(typeDir)) {
      const resDir = join2(typeDir, name);
      if (isIgnored(rel(resDir))) continue;
      for (const f of listFiles(resDir)) {
        if (!f.endsWith(".gml")) continue;
        const abs = join2(resDir, f);
        if (!isIgnored(rel(abs))) addGmlFile(project, wsRoot, abs);
      }
    }
  }
  buildObjectsFromFiles(project, wsRoot);
  loadRooms(project, wsRoot);
  loadExtensions(project, wsRoot);
  collectYyReferences(project);
  for (const sub of ["options", "extensions"]) collectAux(project, wsRoot, join2(rootAbs, sub), (n) => n.endsWith(".yy") || n.endsWith(".json"), isIgnored);
  collectAux(project, wsRoot, join2(rootAbs, "datafiles"), (n) => TEXT_EXTENSIONS.has(extOf(n)), isIgnored);
  return project;
}
function extOf(name) {
  const i = name.lastIndexOf(".");
  return i < 0 ? "" : name.slice(i).toLowerCase();
}
function collectAux(project, wsRoot, dirAbs, accept, isIgnored) {
  const walkDir = (d, depth) => {
    if (depth > 6) return;
    let entries;
    try {
      entries = readdirSync(d, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const abs = join2(d, e.name);
      const r = toPosix(relative(wsRoot, abs));
      if (isIgnored(r)) continue;
      if (e.isDirectory()) walkDir(abs, depth + 1);
      else if (accept(e.name)) {
        try {
          if (statSync(abs).size <= MAX_AUX_FILE_SIZE) project.auxiliaryFiles.push(r);
        } catch {
        }
      }
    }
  };
  walkDir(dirAbs, 0);
}
function addGmlFile(project, wsRoot, abs) {
  const text = readText(abs) ?? "";
  const relPath = toPosix(relative(wsRoot, abs));
  const parts = relPath.split("/");
  const file = parts[parts.length - 1];
  const base = file.slice(0, -4);
  const owner = parts[parts.length - 2] ?? base;
  const typeDir = parts[parts.length - 3];
  let kind = "script";
  let resource = base;
  let event;
  if (typeDir === "objects") {
    event = parseEventFileName(base);
    kind = "object-event";
    resource = owner;
  } else if (typeDir === "scripts") {
    resource = owner;
  } else if (typeDir === "rooms") {
    kind = base.startsWith("InstanceCreationCode") ? "instance-creation" : "room-creation";
    resource = owner;
  } else if (typeDir === "timelines") {
    kind = "timeline-moment";
    resource = owner;
  } else if (parts.includes("extensions")) {
    kind = "extension";
  }
  const gml = { relPath, absPath: abs, source: new SourceText(text), ast: parse(text), kind, resource, event, project };
  project.files.push(gml);
  return gml;
}
function buildObjectsFromFiles(project, wsRoot) {
  const objectDirs = /* @__PURE__ */ new Map();
  for (const f of project.files) {
    if (f.kind === "object-event") objectDirs.set(f.resource, dirname(f.absPath));
  }
  for (const [name, list] of project.resources) {
    for (const r of list) if (r.type === "objects" && r.onDisk) objectDirs.set(name, dirname(join2(wsRoot, r.yyRelPath)));
  }
  for (const [name, dirAbs] of objectDirs) {
    const yyAbs = join2(dirAbs, `${name}.yy`);
    const yy = existsSync2(yyAbs) ? tryParseYy(readText(yyAbs) ?? "") : void 0;
    const info = {
      name,
      yyRelPath: toPosix(relative(wsRoot, yyAbs)),
      parent: yyRef(yy?.parentObjectId)?.name,
      properties: yyArray(yy?.properties).map(yyName).filter((n) => !!n),
      events: project.files.filter((f) => f.kind === "object-event" && f.resource === name),
      eventList: yy ? yyArray(yy.eventList).map((e) => {
        const ev = e;
        return { eventType: Number(ev.eventType), eventNum: Number(ev.eventNum), collisionObject: yyRef(ev.collisionObjectId)?.name };
      }) : void 0,
      persistent: yy?.persistent === true
    };
    project.objects.set(name, info);
  }
}
function loadRooms(project, wsRoot) {
  for (const [, list] of project.resources) {
    for (const r of list) {
      if (r.type !== "rooms" || !r.onDisk) continue;
      const yy = tryParseYy(readText(join2(wsRoot, r.yyRelPath)) ?? "");
      if (!yy) continue;
      const visitLayers = (layers) => {
        for (const layer of layers) {
          const l = layer;
          for (const inst of yyArray(l.instances)) {
            const n = yyName(inst);
            if (n) project.roomInstances.add(n);
          }
          visitLayers(yyArray(l.layers));
        }
      };
      visitLayers(yyArray(yy.layers));
    }
  }
}
function loadExtensions(project, wsRoot) {
  for (const [, list] of project.resources) {
    for (const r of list) {
      if (r.type !== "extensions" || !r.onDisk) continue;
      const yy = tryParseYy(readText(join2(wsRoot, r.yyRelPath)) ?? "");
      if (!yy) continue;
      for (const file of yyArray(yy.files)) {
        const f = file;
        for (const fn of yyArray(f.functions)) {
          const def = fn;
          const n = yyName(def);
          if (n) project.extensionFunctions.set(n, { extension: r.name, argCount: typeof def.argCount === "number" ? def.argCount : -1 });
        }
        for (const c of yyArray(f.constants)) {
          const n = yyName(c) ?? c.constantName;
          if (typeof n === "string") project.extensionConstants.add(n);
        }
      }
    }
  }
}
function collectYyReferences(project) {
  const refRe = /\{\s*"name"\s*:\s*"([^"]+)"\s*,\s*"path"\s*:\s*"([a-z]+)\//g;
  for (const [, list] of project.resources) {
    for (const r of list) {
      if (!r.onDisk || !REFERENCE_DIRS.includes(r.type)) continue;
      const text = readText(join2(project.rootAbs, r.yyRelPath.slice(project.rootRel ? project.rootRel.length + 1 : 0)));
      if (!text) continue;
      for (const m of text.matchAll(refRe)) {
        if (m[1] === r.name) continue;
        const set = project.yyReferences.get(m[1]) ?? /* @__PURE__ */ new Set();
        set.add(r.name);
        project.yyReferences.set(m[1], set);
      }
    }
  }
}

// src/semantic/builtins.json
var builtins_default = {
  $comment: "Generated by scripts/gen-builtins.ts from GameMaker runtime GmlSpec.xml + fnames. Do not edit by hand.",
  runtimes: ["2026.0.0.23", "2022.0.1.30"],
  functions: {
    abs: [1, 1, "Real", 2, 3],
    achievement_available: [0, 0, "Bool", 3, 3],
    achievement_event: [1, 1, "Undefined", 1, 3],
    achievement_get_challenges: [0, 0, "Undefined", 1, 3],
    achievement_get_info: [1, 1, "Undefined", 3, 3],
    achievement_get_pic: [1, 1, "Undefined", 1, 3],
    achievement_increment: [2, 2, "Undefined", 1, 3],
    achievement_load_friends: [0, 0, "Undefined", 1, 3],
    achievement_load_leaderboard: [4, 4, "Undefined", 1, 3],
    achievement_load_progress: [0, 0, "Undefined", 1, 3],
    achievement_login: [0, 0, "Undefined", 1, 3],
    achievement_login_status: [0, 0, "Bool", 3, 3],
    achievement_logout: [0, 0, "Undefined", 1, 3],
    achievement_post: [2, 2, "Undefined", 1, 3],
    achievement_post_score: [2, 2, "Undefined", 1, 3],
    achievement_reset: [0, 0, "Undefined", 1, 3],
    achievement_send_challenge: [5, 5, "Undefined", 1, 3],
    achievement_show: [2, 2, "Undefined", 1, 3],
    achievement_show_achievements: [0, 0, "Undefined", 1, 3],
    achievement_show_challenge_notifications: [3, 3, "Undefined", 1, 3],
    achievement_show_leaderboards: [0, 0, "Undefined", 1, 3],
    ads_disable: [1, 1, "Undefined", 1, 3],
    ads_enable: [3, 3, "Undefined", 1, 3],
    ads_engagement_active: [0, 0, "Undefined", 3, 3],
    ads_engagement_available: [0, 0, "Undefined", 3, 3],
    ads_engagement_launch: [0, 0, "Undefined", 1, 3],
    ads_event: [1, 1, "Undefined", 1, 3],
    ads_event_preload: [1, 1, "Undefined", 1, 3],
    ads_get_display_height: [1, 1, "Real", 3, 3],
    ads_get_display_width: [1, 1, "Real", 3, 3],
    ads_interstitial_available: [0, 0, "Bool", 3, 3],
    ads_interstitial_display: [0, 0, "Bool", 1, 3],
    ads_move: [3, 3, "Undefined", 1, 3],
    ads_set_reward_callback: [1, 1, "Undefined", 1, 3],
    ads_setup: [2, 2, "Undefined", 1, 3],
    alarm_get: [1, 1, "Real", 2, 3],
    alarm_set: [2, 2, "Undefined", 0, 3],
    analytics_event: [1, 1, "Undefined", 1, 3],
    analytics_event_ext: [3, -1, "Undefined", 1, 3],
    angle_difference: [2, 2, "Real", 2, 3],
    animcurve_channel_evaluate: [2, 2, "Real", 2, 3],
    animcurve_channel_new: [0, 0, "Struct.AnimCurveChannel", 2, 3],
    animcurve_create: [0, 0, "Struct.AnimCurve", 0, 3],
    animcurve_destroy: [1, 1, "Undefined", 0, 3],
    animcurve_exists: [1, 1, "Bool", 2, 3],
    animcurve_get: [1, 1, "Struct.AnimCurve", 2, 3],
    animcurve_get_channel: [2, 2, "Struct.AnimCurveChannel", 2, 3],
    animcurve_get_channel_index: [2, 2, "Real", 2, 3],
    animcurve_point_new: [0, 0, "Struct.AnimCurvePoint", 2, 3],
    ansi_char: [1, 1, "String", 2, 3],
    application_get_position: [0, 0, "Array[Real]", 2, 3],
    application_surface_draw_enable: [1, 1, "Undefined", 0, 3],
    application_surface_enable: [1, 1, "Undefined", 0, 3],
    application_surface_is_draw_enabled: [0, 0, "Bool", 2, 1],
    application_surface_is_enabled: [0, 0, "Bool", 2, 3],
    arccos: [1, 1, "Real", 2, 3],
    arcsin: [1, 1, "Real", 2, 3],
    arctan: [1, 1, "Real", 2, 3],
    arctan2: [2, 2, "Real", 2, 3],
    array_all: [2, 4, "Bool", 2, 1],
    array_any: [2, 4, "Bool", 2, 1],
    array_concat: [2, -1, "Array", 2, 1],
    array_contains: [2, 4, "Bool", 2, 1],
    array_contains_ext: [2, 5, "Bool", 2, 1],
    array_copy: [5, 5, "Undefined", 0, 3],
    array_copy_while: [2, 4, "Array", 2, 1],
    array_create: [1, 2, "Array[ArgumentIdentity]", 2, 3],
    array_create_ext: [2, 2, "Array", 2, 1],
    array_delete: [3, 3, "Undefined", 0, 3],
    array_equals: [2, 2, "Bool", 2, 3],
    array_filter: [2, 4, "Array", 2, 1],
    array_filter_ext: [2, 4, "Real", 0, 1],
    array_find_index: [2, 4, "Real", 2, 1],
    array_first: [1, 1, "ArgumentIdentity", 2, 1],
    array_foreach: [2, 4, "Undefined", 0, 1],
    array_get: [2, 2, "Any", 2, 3],
    array_get_index: [2, 4, "Real", 2, 1],
    array_height_2d: [1, 1, "Real", 3, 3],
    array_insert: [3, -1, "Undefined", 0, 3],
    array_intersection: [2, -1, "Array", 2, 1],
    array_last: [1, 1, "ArgumentIdentity", 2, 1],
    array_length: [1, 1, "Real", 2, 3],
    array_length_1d: [1, 1, "Real", 3, 3],
    array_length_2d: [2, 2, "Real", 3, 3],
    array_map: [2, 4, "Array", 2, 1],
    array_map_ext: [2, 4, "Real", 0, 1],
    array_pop: [1, 1, "ArgumentIdentity", 0, 3],
    array_push: [2, -1, "Undefined", 0, 3],
    array_reduce: [2, 5, "Any", 2, 1],
    array_resize: [2, 2, "Undefined", 0, 3],
    array_reverse: [1, 3, "Array", 2, 1],
    array_reverse_ext: [1, 3, "Real", 0, 1],
    array_set: [3, 3, "Undefined", 0, 3],
    array_shift: [1, 1, "ArgumentIdentity", 0, 1],
    array_shuffle: [1, 3, "Array", 2, 1],
    array_shuffle_ext: [1, 3, "Undefined", 0, 1],
    array_sort: [2, 2, "Undefined", 0, 3],
    array_union: [2, -1, "Array", 2, 1],
    array_unique: [1, 3, "Array", 2, 1],
    array_unique_ext: [1, 3, "Real", 0, 1],
    asset_add_tags: [2, 3, "Bool", 0, 3],
    asset_clear_tags: [1, 2, "Bool", 0, 3],
    asset_get_ids: [1, 1, "Array[Asset]", 2, 1],
    asset_get_index: [1, 1, "Asset", 2, 3],
    asset_get_tags: [1, 2, "Array[String]", 2, 3],
    asset_get_type: [1, 1, "Constant.AssetType", 2, 3],
    asset_has_any_tag: [2, 3, "Bool", 2, 3],
    asset_has_tags: [2, 3, "Bool", 2, 3],
    asset_remove_tags: [2, 3, "Bool", 0, 3],
    audio_bus_clear_emitters: [1, 1, "Undefined", 0, 1],
    audio_bus_create: [0, 0, "Struct.AudioBus", 0, 1],
    audio_bus_get_emitters: [1, 1, "Array[Id.AudioEmitter]", 2, 1],
    audio_channel_num: [1, 1, "Undefined", 0, 3],
    audio_create_buffer_sound: [6, 6, "Asset.GMSound", 0, 3],
    audio_create_play_queue: [3, 3, "Real", 0, 3],
    audio_create_stream: [1, 1, "Asset.GMSound", 0, 3],
    audio_create_sync_group: [1, 1, "Id.AudioSyncGroup", 0, 3],
    audio_debug: [1, 1, "Undefined", 0, 3],
    audio_destroy_stream: [1, 1, "Real", 2, 3],
    audio_destroy_sync_group: [1, 1, "Undefined", 0, 3],
    audio_effect_create: [1, 2, "Struct.AudioEffect", 0, 1],
    audio_emitter_bus: [2, 2, "Undefined", 0, 1],
    audio_emitter_create: [0, 0, "Id.AudioEmitter", 0, 3],
    audio_emitter_exists: [1, 1, "Bool", 2, 3],
    audio_emitter_falloff: [4, 4, "Undefined", 0, 3],
    audio_emitter_free: [1, 1, "Undefined", 0, 3],
    audio_emitter_gain: [2, 3, "Undefined", 0, 3],
    audio_emitter_get_bus: [1, 1, "Struct.AudioBus", 2, 1],
    audio_emitter_get_gain: [1, 1, "Real", 2, 3],
    audio_emitter_get_listener_mask: [1, 1, "Real", 2, 3],
    audio_emitter_get_pitch: [1, 1, "Real", 2, 3],
    audio_emitter_get_vx: [1, 1, "Real", 2, 3],
    audio_emitter_get_vy: [1, 1, "Real", 2, 3],
    audio_emitter_get_vz: [1, 1, "Real", 2, 3],
    audio_emitter_get_x: [1, 1, "Real", 2, 3],
    audio_emitter_get_y: [1, 1, "Real", 2, 3],
    audio_emitter_get_z: [1, 1, "Real", 2, 3],
    audio_emitter_pitch: [2, 2, "Undefined", 0, 3],
    audio_emitter_position: [4, 4, "Undefined", 0, 3],
    audio_emitter_set_listener_mask: [2, 2, "Undefined", 0, 3],
    audio_emitter_velocity: [4, 4, "Undefined", 0, 3],
    audio_exists: [1, 1, "Bool", 2, 3],
    audio_falloff_set_model: [1, 1, "Undefined", 0, 3],
    audio_free_buffer_sound: [1, 1, "Undefined", 0, 3],
    audio_free_play_queue: [1, 1, "Undefined", 0, 3],
    audio_get_listener_count: [0, 0, "Real", 2, 3],
    audio_get_listener_info: [1, 1, "Id.DsMap", 2, 3],
    audio_get_listener_mask: [0, 0, "Real", 2, 3],
    audio_get_master_gain: [1, 1, "Real", 2, 3],
    audio_get_name: [1, 1, "String", 2, 3],
    audio_get_recorder_count: [0, 0, "Real", 2, 3],
    audio_get_recorder_info: [1, 1, "Real", 2, 3],
    audio_get_type: [1, 1, "Real", 2, 3],
    audio_group_get_assets: [1, 1, "Array[Asset.GMSound]", 2, 1],
    audio_group_get_gain: [1, 1, "Real", 2, 1],
    audio_group_is_loaded: [1, 1, "Bool", 2, 3],
    audio_group_load: [1, 1, "Bool", 0, 3],
    audio_group_load_progress: [1, 1, "Real", 2, 3],
    audio_group_name: [1, 1, "String", 2, 3],
    audio_group_set_gain: [2, 3, "Undefined", 0, 3],
    audio_group_stop_all: [1, 1, "Undefined", 0, 3],
    audio_group_unload: [1, 1, "Bool", 0, 3],
    audio_is_paused: [1, 1, "Bool", 2, 3],
    audio_is_playing: [1, 1, "Bool", 2, 3],
    audio_listener_get_data: [1, 1, "Id.DsMap", 2, 3],
    audio_listener_orientation: [6, 6, "Undefined", 0, 3],
    audio_listener_position: [3, 3, "Undefined", 0, 3],
    audio_listener_set_orientation: [7, 7, "Undefined", 0, 3],
    audio_listener_set_position: [4, 4, "Undefined", 0, 3],
    audio_listener_set_velocity: [4, 4, "Undefined", 0, 3],
    audio_listener_velocity: [3, 3, "Undefined", 0, 3],
    audio_master_gain: [1, 1, "Undefined", 0, 3],
    audio_music_gain: [2, 2, "Undefined", 1, 3],
    audio_music_is_playing: [0, 0, "Bool", 3, 3],
    audio_pause_all: [0, 0, "Undefined", 0, 3],
    audio_pause_music: [0, 0, "Undefined", 1, 3],
    audio_pause_sound: [1, 1, "Undefined", 0, 3],
    audio_pause_sync_group: [1, 1, "Undefined", 0, 3],
    audio_play_in_sync_group: [2, 2, "Id.Buffer", 0, 3],
    audio_play_music: [2, 2, "Undefined", 1, 3],
    audio_play_sound: [3, 7, "Id.Sound", 0, 3],
    audio_play_sound_at: [9, 13, "Id.Sound", 0, 3],
    audio_play_sound_ext: [1, 1, "Id.Sound", 0, 1],
    audio_play_sound_on: [4, 8, "Id.Sound", 0, 3],
    audio_queue_sound: [4, 4, "Undefined", 0, 3],
    audio_resume_all: [0, 0, "Undefined", 0, 3],
    audio_resume_music: [0, 0, "Undefined", 1, 3],
    audio_resume_sound: [1, 1, "Undefined", 0, 3],
    audio_resume_sync_group: [1, 1, "Undefined", 0, 3],
    audio_set_listener_mask: [1, 1, "Undefined", 0, 3],
    audio_set_master_gain: [2, 2, "Undefined", 0, 3],
    audio_sound_gain: [2, 3, "Undefined", 0, 3],
    audio_sound_get_asset: [1, 1, "Asset.GMSound", 2, 1],
    audio_sound_get_audio_group: [1, 1, "Asset.GMAudioGroup", 2, 1],
    audio_sound_get_gain: [1, 1, "Real", 2, 3],
    audio_sound_get_listener_mask: [1, 1, "Real", 2, 3],
    audio_sound_get_loop: [1, 1, "Bool", 2, 1],
    audio_sound_get_loop_end: [1, 1, "Real", 2, 1],
    audio_sound_get_loop_start: [1, 1, "Real", 2, 1],
    audio_sound_get_pitch: [1, 1, "Real", 2, 3],
    audio_sound_get_track_position: [1, 1, "Real", 2, 3],
    audio_sound_is_playable: [1, 1, "Bool", 2, 3],
    audio_sound_length: [1, 1, "Real", 2, 3],
    audio_sound_loop: [2, 2, "Undefined", 0, 1],
    audio_sound_loop_end: [2, 2, "Undefined", 0, 1],
    audio_sound_loop_start: [2, 2, "Undefined", 0, 1],
    audio_sound_pitch: [2, 2, "Undefined", 0, 3],
    audio_sound_set_listener_mask: [2, 2, "Undefined", 0, 3],
    audio_sound_set_track_position: [2, 2, "Undefined", 0, 3],
    audio_start_recording: [1, 1, "Real", 0, 3],
    audio_start_sync_group: [1, 1, "Undefined", 0, 3],
    audio_stop_all: [0, 0, "Undefined", 0, 3],
    audio_stop_music: [0, 0, "Undefined", 1, 3],
    audio_stop_recording: [1, 1, "Undefined", 0, 3],
    audio_stop_sound: [1, 1, "Undefined", 0, 3],
    audio_stop_sync_group: [1, 1, "Undefined", 0, 3],
    audio_sync_group_debug: [1, 1, "Undefined", 0, 3],
    audio_sync_group_get_track_pos: [1, 1, "Real", 2, 3],
    audio_sync_group_is_paused: [1, 1, "Bool", 2, 1],
    audio_sync_group_is_playing: [1, 1, "Bool", 2, 3],
    audio_system: [0, 0, "Undefined", 3, 3],
    audio_system_is_available: [0, 0, "Bool", 2, 3],
    audio_system_is_initialised: [0, 0, "Bool", 2, 1],
    audio_throw_on_error: [1, 1, "Undefined", 0, 1],
    base64_decode: [1, 1, "String", 2, 3],
    base64_encode: [1, 1, "String", 2, 3],
    bool: [1, 1, "Bool", 2, 3],
    browser_input_capture: [1, 1, "Undefined", 0, 3],
    buffer_async_group_begin: [1, 1, "Undefined", 0, 3],
    buffer_async_group_end: [0, 0, "Real", 0, 3],
    buffer_async_group_option: [2, 2, "Undefined", 0, 3],
    buffer_base64_decode: [1, 1, "Id.Buffer", 2, 3],
    buffer_base64_decode_ext: [3, 3, "Undefined", 0, 3],
    buffer_base64_encode: [3, 3, "String", 2, 3],
    buffer_compress: [3, 3, "Real", 0, 3],
    buffer_copy: [5, 5, "Undefined", 0, 3],
    buffer_copy_from_vertex_buffer: [5, 5, "Undefined", 0, 3],
    buffer_copy_stride: [8, 8, "Undefined", 0, 1],
    buffer_crc32: [3, 3, "Real", 2, 3],
    buffer_create: [3, 3, "Id.Buffer", 0, 3],
    buffer_create_from_vertex_buffer: [3, 3, "Id.Buffer", 0, 3],
    buffer_create_from_vertex_buffer_ext: [5, 5, "Id.Buffer", 0, 3],
    buffer_decompress: [1, 1, "Id.Buffer", 0, 3],
    buffer_delete: [1, 1, "Undefined", 0, 3],
    buffer_exists: [1, 1, "Bool", 2, 3],
    buffer_fill: [5, 5, "Undefined", 0, 3],
    buffer_get_address: [1, 1, "Pointer", 2, 3],
    buffer_get_alignment: [1, 1, "Real", 2, 3],
    buffer_get_size: [1, 1, "Real", 2, 3],
    buffer_get_surface: [3, 3, "Undefined", 0, 3],
    buffer_get_surface_depth: [3, 3, "Bool", 0, 1],
    buffer_get_type: [1, 1, "Constant.BufferType", 2, 3],
    buffer_get_used_size: [1, 1, "Real", 2, 1],
    buffer_load: [1, 1, "Id.Buffer", 0, 3],
    buffer_load_async: [4, 4, "Real", 0, 3],
    buffer_load_ext: [3, 3, "Undefined", 0, 3],
    buffer_load_partial: [5, 5, "Real", 0, 3],
    buffer_md5: [3, 3, "String", 2, 3],
    buffer_peek: [3, 3, "ArgumentIdentity", 2, 3],
    buffer_poke: [4, 4, "Undefined", 0, 3],
    buffer_read: [2, 2, "ArgumentIdentity", 0, 3],
    buffer_resize: [2, 2, "Undefined", 0, 3],
    buffer_save: [2, 2, "Undefined", 0, 3],
    buffer_save_async: [4, 4, "Real", 0, 3],
    buffer_save_ext: [4, 4, "Undefined", 0, 3],
    buffer_seek: [3, 3, "Real", 0, 3],
    buffer_set_surface: [3, 3, "Undefined", 0, 3],
    buffer_set_surface_depth: [3, 3, "Bool", 0, 1],
    buffer_set_used_size: [2, 2, "Undefined", 0, 3],
    buffer_sha1: [3, 3, "String", 2, 3],
    buffer_sizeof: [1, 1, "Real", 2, 3],
    buffer_tell: [1, 1, "Real", 2, 3],
    buffer_write: [3, 3, "Constant.BufferErrorType", 0, 3],
    call_cancel: [1, 1, "Undefined", 0, 3],
    call_later: [3, 4, "Id.TimeSource", 0, 3],
    camera_apply: [1, 1, "Undefined", 0, 3],
    camera_copy_transforms: [2, 2, "Undefined", 0, 1],
    camera_create: [0, 0, "Id.Camera", 0, 3],
    camera_create_view: [4, 10, "Id.Camera", 0, 3],
    camera_destroy: [1, 1, "Undefined", 0, 3],
    camera_get_active: [0, 0, "Id.Camera", 2, 3],
    camera_get_begin_script: [1, 1, "Function", 2, 3],
    camera_get_default: [0, 0, "Id.Camera", 2, 3],
    camera_get_end_script: [1, 1, "Function", 2, 3],
    camera_get_proj_mat: [1, 1, "Array[Real]", 2, 3],
    camera_get_update_script: [1, 1, "Function", 2, 3],
    camera_get_view_angle: [1, 1, "Real", 2, 3],
    camera_get_view_border_x: [1, 1, "Real", 2, 3],
    camera_get_view_border_y: [1, 1, "Real", 2, 3],
    camera_get_view_height: [1, 1, "Real", 2, 3],
    camera_get_view_mat: [1, 1, "Array[Real]", 2, 3],
    camera_get_view_speed_x: [1, 1, "Real", 2, 3],
    camera_get_view_speed_y: [1, 1, "Real", 2, 3],
    camera_get_view_target: [1, 1, "Id.Instance", 2, 3],
    camera_get_view_width: [1, 1, "Real", 2, 3],
    camera_get_view_x: [1, 1, "Real", 2, 3],
    camera_get_view_y: [1, 1, "Real", 2, 3],
    camera_set_begin_script: [2, 2, "Undefined", 0, 3],
    camera_set_default: [1, 1, "Undefined", 0, 3],
    camera_set_end_script: [2, 2, "Undefined", 0, 3],
    camera_set_proj_mat: [2, 2, "Undefined", 0, 3],
    camera_set_update_script: [2, 2, "Undefined", 0, 3],
    camera_set_view_angle: [2, 2, "Undefined", 0, 3],
    camera_set_view_border: [3, 3, "Undefined", 0, 3],
    camera_set_view_mat: [2, 2, "Undefined", 0, 3],
    camera_set_view_pos: [3, 3, "Undefined", 0, 3],
    camera_set_view_size: [3, 3, "Undefined", 0, 3],
    camera_set_view_speed: [3, 3, "Undefined", 0, 3],
    camera_set_view_target: [2, 2, "Undefined", 0, 3],
    ceil: [1, 1, "Real", 2, 3],
    choose: [2, -1, "ArgumentIdentity", 2, 3],
    chr: [1, 1, "String", 2, 3],
    clamp: [3, 3, "Real", 2, 3],
    clickable_add: [6, 6, "Real", 2, 3],
    clickable_add_ext: [8, 8, "Real", 2, 3],
    clickable_change: [4, 4, "Undefined", 0, 3],
    clickable_change_ext: [6, 6, "Undefined", 0, 3],
    clickable_delete: [1, 1, "Undefined", 0, 3],
    clickable_exists: [1, 1, "Bool", 2, 3],
    clickable_set_style: [2, 2, "Undefined", 0, 3],
    clipboard_get_text: [0, 0, "String", 2, 3],
    clipboard_has_text: [0, 0, "Bool", 2, 3],
    clipboard_set_text: [1, 1, "Undefined", 0, 3],
    cloud_file_save: [2, 2, "Real", 1, 3],
    cloud_string_save: [2, 2, "Real", 3, 3],
    cloud_synchronise: [0, 0, "Real", 3, 3],
    code_is_compiled: [0, 0, "Bool", 2, 3],
    collision_circle: [6, 6, "Id.Instance", 2, 3],
    collision_circle_list: [8, 8, "Real", 0, 3],
    collision_ellipse: [7, 7, "Id.Instance", 2, 3],
    collision_ellipse_list: [9, 9, "Real", 0, 3],
    collision_line: [7, 7, "Id.Instance", 2, 3],
    collision_line_list: [9, 9, "Real", 0, 3],
    collision_point: [5, 5, "Id.Instance", 2, 3],
    collision_point_list: [7, 7, "Real", 0, 3],
    collision_rectangle: [7, 7, "Id.Instance", 2, 3],
    collision_rectangle_list: [9, 9, "Real", 0, 3],
    color_get_blue: [1, 1, "Real", 2, 3],
    color_get_green: [1, 1, "Real", 2, 3],
    color_get_hue: [1, 1, "Real", 2, 3],
    color_get_red: [1, 1, "Real", 2, 3],
    color_get_saturation: [1, 1, "Real", 2, 3],
    color_get_value: [1, 1, "Real", 2, 3],
    colour_get_blue: [1, 1, "Real", 2, 3],
    colour_get_green: [1, 1, "Real", 2, 3],
    colour_get_hue: [1, 1, "Real", 2, 3],
    colour_get_red: [1, 1, "Real", 2, 3],
    colour_get_saturation: [1, 1, "Real", 2, 3],
    colour_get_value: [1, 1, "Real", 2, 3],
    cos: [1, 1, "Real", 2, 3],
    darccos: [1, 1, "Real", 2, 3],
    darcsin: [1, 1, "Real", 2, 3],
    darctan: [1, 1, "Real", 2, 3],
    darctan2: [2, 2, "Real", 2, 3],
    date_compare_date: [2, 2, "Real", 2, 3],
    date_compare_datetime: [2, 2, "Real", 2, 3],
    date_compare_time: [2, 2, "Real", 2, 3],
    date_create_datetime: [6, 6, "Real", 2, 3],
    date_current_datetime: [0, 0, "Real", 2, 3],
    date_date_of: [1, 1, "Real", 2, 3],
    date_date_string: [1, 1, "String", 2, 3],
    date_datetime_string: [1, 1, "String", 2, 3],
    date_day_span: [2, 2, "Real", 2, 3],
    date_days_in_month: [1, 1, "Real", 2, 3],
    date_days_in_year: [1, 1, "Real", 2, 3],
    date_get_day: [1, 1, "Real", 2, 3],
    date_get_day_of_year: [1, 1, "Real", 2, 3],
    date_get_hour: [1, 1, "Real", 2, 3],
    date_get_hour_of_year: [1, 1, "Real", 2, 3],
    date_get_minute: [1, 1, "Real", 2, 3],
    date_get_minute_of_year: [1, 1, "Real", 2, 3],
    date_get_month: [1, 1, "Real", 2, 3],
    date_get_second: [1, 1, "Real", 2, 3],
    date_get_second_of_year: [1, 1, "Real", 2, 3],
    date_get_timezone: [0, 0, "Real", 2, 3],
    date_get_week: [1, 1, "Real", 2, 3],
    date_get_weekday: [1, 1, "Real", 2, 3],
    date_get_year: [1, 1, "Real", 2, 3],
    date_hour_span: [2, 2, "Real", 2, 3],
    date_inc_day: [2, 2, "Real", 0, 3],
    date_inc_hour: [2, 2, "Real", 0, 3],
    date_inc_minute: [2, 2, "Real", 2, 3],
    date_inc_month: [2, 2, "Real", 0, 3],
    date_inc_second: [2, 2, "Real", 0, 3],
    date_inc_week: [2, 2, "Real", 0, 3],
    date_inc_year: [2, 2, "Real", 0, 3],
    date_is_today: [1, 1, "Bool", 2, 3],
    date_leap_year: [1, 1, "Bool", 2, 3],
    date_minute_span: [2, 2, "Real", 2, 3],
    date_month_span: [2, 2, "Real", 2, 3],
    date_second_span: [2, 2, "Real", 2, 3],
    date_set_timezone: [1, 1, "Undefined", 0, 3],
    date_time_of: [1, 1, "Real", 2, 3],
    date_time_string: [1, 1, "String", 2, 3],
    date_valid_datetime: [6, 6, "Bool", 2, 3],
    date_week_span: [2, 2, "Real", 2, 3],
    date_year_span: [2, 2, "Real", 2, 3],
    db_to_lin: [1, 1, "Real", 2, 1],
    dbg_add_font_glyphs: [1, 3, "Undefined", 0, 1],
    dbg_button: [2, 4, "Pointer.DbgControl", 0, 1],
    dbg_checkbox: [1, 2, "Pointer.DbgControl", 0, 1],
    dbg_color: [1, 2, "Pointer.DbgControl", 0, 1],
    dbg_colour: [1, 2, "Pointer.DbgControl", 0, 1],
    dbg_control_delete: [1, 1, "Bool", 0, 1],
    dbg_control_exists: [1, 1, "Undefined", 0, 1],
    dbg_drop_down: [2, 4, "Pointer.DbgControl", 0, 1],
    dbg_get_gamepad_input: [0, 0, "Real", 2, 1],
    dbg_same_line: [0, 0, "Pointer.DbgControl", 0, 1],
    dbg_section: [1, 2, "Pointer.Section", 0, 1],
    dbg_section_delete: [1, 1, "Bool", 0, 1],
    dbg_section_exists: [1, 1, "Bool", 0, 1],
    dbg_set_section: [1, 1, "Bool", 0, 1],
    dbg_set_view: [1, 1, "Bool", 0, 1],
    dbg_slider: [1, 5, "Pointer.DbgControl", 0, 1],
    dbg_slider_int: [1, 5, "Pointer.DbgControl", 0, 1],
    dbg_sprite: [2, 5, "Pointer.DbgControl", 0, 1],
    dbg_sprite_button: [3, 9, "Pointer.DbgControl", 0, 1],
    dbg_text: [1, 1, "Pointer.DbgControl", 0, 1],
    dbg_text_input: [1, 3, "Pointer.DbgControl", 0, 1],
    dbg_text_separator: [1, 2, "Pointer.DbgControl", 0, 1],
    dbg_view: [2, 6, "Pointer.View", 0, 1],
    dbg_view_delete: [1, 1, "Bool", 0, 1],
    dbg_view_exists: [1, 1, "Bool", 0, 1],
    dbg_watch: [1, 2, "Pointer.DbgControl", 0, 1],
    dcos: [1, 1, "Real", 2, 3],
    debug_event: [1, 2, "Struct", 0, 3],
    debug_get_callstack: [0, 1, "Array[String]", 2, 3],
    debug_input_playback: [1, 1, "Undefined", 0, 1],
    debug_input_record: [1, 1, "Undefined", 0, 1],
    debug_input_save: [1, 1, "Undefined", 0, 1],
    degtorad: [1, 1, "Real", 2, 3],
    device_get_tilt_x: [0, 0, "Real", 2, 3],
    device_get_tilt_y: [0, 0, "Real", 2, 3],
    device_get_tilt_z: [0, 0, "Real", 2, 3],
    device_is_keypad_open: [0, 0, "Bool", 2, 3],
    device_mouse_check_button: [2, 2, "Bool", 2, 3],
    device_mouse_check_button_pressed: [2, 2, "Bool", 2, 3],
    device_mouse_check_button_released: [2, 2, "Bool", 2, 3],
    device_mouse_dbclick_enable: [1, 1, "Bool", 0, 3],
    device_mouse_raw_x: [1, 1, "Real", 2, 3],
    device_mouse_raw_y: [1, 1, "Real", 2, 3],
    device_mouse_x: [1, 1, "Real", 2, 3],
    device_mouse_x_to_gui: [1, 1, "Real", 2, 3],
    device_mouse_y: [1, 1, "Real", 2, 3],
    device_mouse_y_to_gui: [1, 1, "Real", 2, 3],
    directory_create: [1, 1, "Bool", 0, 3],
    directory_destroy: [1, 1, "Undefined", 0, 3],
    directory_exists: [1, 1, "Bool", 2, 3],
    display_get_dpi_x: [0, 0, "Real", 2, 3],
    display_get_dpi_y: [0, 0, "Real", 2, 3],
    display_get_frequency: [0, 0, "Real", 2, 3],
    display_get_gui_height: [0, 0, "Real", 2, 3],
    display_get_gui_width: [0, 0, "Real", 2, 3],
    display_get_height: [0, 0, "Real", 2, 3],
    display_get_orientation: [0, 0, "Real", 2, 3],
    display_get_sleep_margin: [0, 0, "Real", 2, 3],
    display_get_timing_method: [0, 0, "Constant.TimingMethod", 2, 3],
    display_get_width: [0, 0, "Real", 2, 3],
    display_mouse_get_x: [0, 0, "Real", 2, 3],
    display_mouse_get_y: [0, 0, "Real", 2, 3],
    display_mouse_set: [2, 2, "Undefined", 0, 3],
    display_reset: [2, 2, "Real", 0, 3],
    display_set_gui_maximise: [0, 4, "Undefined", 0, 3],
    display_set_gui_maximize: [0, 4, "Undefined", 0, 3],
    display_set_gui_size: [2, 2, "Undefined", 0, 3],
    display_set_sleep_margin: [1, 1, "Undefined", 0, 3],
    display_set_timing_method: [1, 1, "Undefined", 0, 3],
    display_set_ui_visibility: [1, 1, "Undefined", 0, 3],
    distance_to_object: [1, 1, "Real", 2, 3],
    distance_to_point: [2, 2, "Real", 2, 3],
    dot_product: [4, 4, "Real", 2, 3],
    dot_product_3d: [6, 6, "Real", 2, 3],
    dot_product_3d_normalised: [6, 6, "Real", 2, 3],
    dot_product_3d_normalized: [6, 6, "Real", 2, 3],
    dot_product_normalised: [4, 4, "Real", 2, 3],
    dot_product_normalized: [4, 4, "Real", 2, 3],
    draw_arrow: [5, 5, "Undefined", 0, 3],
    draw_button: [5, 5, "Undefined", 0, 3],
    draw_circle: [4, 4, "Undefined", 0, 3],
    draw_circle_color: [6, 6, "Undefined", 0, 3],
    draw_circle_colour: [6, 6, "Undefined", 0, 3],
    draw_clear: [1, 1, "Undefined", 0, 3],
    draw_clear_alpha: [2, 2, "Undefined", 0, 3],
    draw_clear_depth: [1, 1, "Undefined", 0, 1],
    draw_clear_ext: [0, 4, "Undefined", 0, 1],
    draw_clear_stencil: [1, 1, "Undefined", 0, 1],
    draw_ellipse: [5, 5, "Undefined", 0, 3],
    draw_ellipse_color: [7, 7, "Undefined", 0, 3],
    draw_ellipse_colour: [7, 7, "Undefined", 0, 3],
    draw_enable_drawevent: [1, 1, "Undefined", 0, 3],
    draw_enable_skeleton_blend_override: [1, 1, "Undefined", 0, 1],
    draw_enable_skeleton_blendmodes: [1, 1, "Undefined", 0, 3],
    draw_enable_svg_aa: [1, 1, "Undefined", 0, 1],
    draw_enable_swf_aa: [1, 1, "Undefined", 0, 3],
    draw_flush: [0, 0, "Undefined", 0, 3],
    draw_get_alpha: [0, 0, "Real", 2, 3],
    draw_get_circle_precision: [0, 0, "Real", 0, 1],
    draw_get_color: [0, 0, "Constant.Color", 2, 3],
    draw_get_colour: [0, 0, "Real", 2, 3],
    draw_get_enable_skeleton_blend_override: [0, 0, "Bool", 2, 1],
    draw_get_enable_skeleton_blendmodes: [0, 0, "Bool", 2, 3],
    draw_get_font: [0, 0, "Asset.GMFont", 2, 3],
    draw_get_halign: [0, 0, "Constant.HAlign", 2, 3],
    draw_get_lighting: [0, 0, "Bool", 2, 3],
    draw_get_svg_aa_level: [0, 0, "Real", 2, 1],
    draw_get_swf_aa_level: [0, 0, "Real", 2, 3],
    draw_get_valign: [0, 0, "Constant.VAlign", 2, 3],
    draw_getpixel: [2, 2, "Real", 2, 3],
    draw_getpixel_ext: [2, 2, "Real", 2, 3],
    draw_healthbar: [11, 11, "Undefined", 0, 3],
    draw_highscore: [4, 4, "Undefined", 0, 3],
    draw_light_define_ambient: [1, 1, "Undefined", 0, 3],
    draw_light_define_direction: [5, 5, "Undefined", 0, 3],
    draw_light_define_point: [6, 6, "Undefined", 0, 3],
    draw_light_enable: [2, 2, "Undefined", 0, 3],
    draw_light_get: [1, 1, "Array", 2, 3],
    draw_light_get_ambient: [0, 0, "Real", 2, 3],
    draw_line: [4, 4, "Undefined", 0, 3],
    draw_line_color: [6, 6, "Undefined", 0, 3],
    draw_line_colour: [6, 6, "Undefined", 0, 3],
    draw_line_width: [5, 5, "Undefined", 0, 3],
    draw_line_width_color: [7, 7, "Undefined", 0, 3],
    draw_line_width_colour: [7, 7, "Undefined", 0, 3],
    draw_path: [4, 4, "Undefined", 0, 3],
    draw_point: [2, 2, "Undefined", 0, 3],
    draw_point_color: [3, 3, "Undefined", 0, 3],
    draw_point_colour: [3, 3, "Undefined", 0, 3],
    draw_primitive_begin: [1, 1, "Undefined", 0, 3],
    draw_primitive_begin_texture: [2, 2, "Undefined", 0, 3],
    draw_primitive_end: [0, 0, "Undefined", 0, 3],
    draw_rectangle: [5, 5, "Undefined", 0, 3],
    draw_rectangle_color: [9, 9, "Undefined", 0, 3],
    draw_rectangle_colour: [9, 9, "Undefined", 0, 3],
    draw_roundrect: [5, 5, "Undefined", 0, 3],
    draw_roundrect_color: [7, 7, "Undefined", 0, 3],
    draw_roundrect_color_ext: [9, 9, "Undefined", 0, 3],
    draw_roundrect_colour: [7, 7, "Undefined", 0, 3],
    draw_roundrect_colour_ext: [9, 9, "Undefined", 0, 3],
    draw_roundrect_ext: [7, 7, "Undefined", 0, 3],
    draw_self: [0, 0, "Undefined", 0, 3],
    draw_set_alpha: [1, 1, "Undefined", 0, 3],
    draw_set_circle_precision: [1, 1, "Undefined", 0, 3],
    draw_set_color: [1, 1, "Undefined", 0, 3],
    draw_set_colour: [1, 1, "Undefined", 0, 3],
    draw_set_font: [1, 1, "Undefined", 0, 3],
    draw_set_halign: [1, 1, "Undefined", 0, 3],
    draw_set_lighting: [1, 1, "Undefined", 0, 3],
    draw_set_svg_aa_level: [1, 1, "Undefined", 0, 1],
    draw_set_swf_aa_level: [1, 1, "Undefined", 0, 3],
    draw_set_valign: [1, 1, "Undefined", 0, 3],
    draw_skeleton: [11, 11, "Undefined", 0, 3],
    draw_skeleton_collision: [9, 9, "Undefined", 0, 3],
    draw_skeleton_instance: [11, 11, "Undefined", 0, 3],
    draw_skeleton_time: [11, 11, "Undefined", 0, 3],
    draw_sprite: [4, 4, "Undefined", 0, 3],
    draw_sprite_ext: [9, 9, "Undefined", 0, 3],
    draw_sprite_general: [16, 16, "Undefined", 0, 3],
    draw_sprite_part: [8, 8, "Undefined", 0, 3],
    draw_sprite_part_ext: [12, 12, "Undefined", 0, 3],
    draw_sprite_pos: [11, 11, "Undefined", 0, 3],
    draw_sprite_stretched: [6, 6, "Undefined", 0, 3],
    draw_sprite_stretched_ext: [8, 8, "Undefined", 0, 3],
    draw_sprite_tiled: [4, 4, "Undefined", 0, 3],
    draw_sprite_tiled_ext: [8, 8, "Undefined", 0, 3],
    draw_surface: [3, 3, "Undefined", 0, 3],
    draw_surface_ext: [8, 8, "Undefined", 0, 3],
    draw_surface_general: [15, 15, "Undefined", 0, 3],
    draw_surface_part: [7, 7, "Undefined", 0, 3],
    draw_surface_part_ext: [11, 11, "Undefined", 0, 3],
    draw_surface_stretched: [5, 5, "Undefined", 0, 3],
    draw_surface_stretched_ext: [7, 7, "Undefined", 0, 3],
    draw_surface_tiled: [3, 3, "Undefined", 0, 3],
    draw_surface_tiled_ext: [7, 7, "Undefined", 0, 3],
    draw_text: [3, 3, "Undefined", 0, 3],
    draw_text_color: [8, 8, "Undefined", 0, 3],
    draw_text_colour: [8, 8, "Undefined", 0, 3],
    draw_text_ext: [5, 5, "Undefined", 0, 3],
    draw_text_ext_color: [10, 10, "Undefined", 0, 3],
    draw_text_ext_colour: [10, 10, "Undefined", 0, 3],
    draw_text_ext_transformed: [8, 8, "Undefined", 0, 3],
    draw_text_ext_transformed_color: [13, 13, "Undefined", 0, 3],
    draw_text_ext_transformed_colour: [13, 13, "Undefined", 0, 3],
    draw_text_transformed: [6, 6, "Undefined", 0, 3],
    draw_text_transformed_color: [11, 11, "Undefined", 0, 3],
    draw_text_transformed_colour: [11, 11, "Undefined", 0, 3],
    draw_texture_flush: [0, 0, "Undefined", 0, 3],
    draw_tile: [5, 5, "Real", 0, 3],
    draw_tilemap: [3, 3, "Undefined", 0, 3],
    draw_triangle: [7, 7, "Undefined", 0, 3],
    draw_triangle_color: [10, 10, "Undefined", 0, 3],
    draw_triangle_colour: [10, 10, "Undefined", 0, 3],
    draw_vertex: [2, 2, "Undefined", 0, 3],
    draw_vertex_color: [4, 4, "Undefined", 0, 3],
    draw_vertex_colour: [4, 4, "Undefined", 0, 3],
    draw_vertex_texture: [4, 4, "Undefined", 0, 3],
    draw_vertex_texture_color: [6, 6, "Undefined", 0, 3],
    draw_vertex_texture_colour: [6, 6, "Undefined", 0, 3],
    ds_exists: [2, 2, "Bool", 2, 3],
    ds_grid_add: [4, 4, "Undefined", 0, 3],
    ds_grid_add_disk: [5, 5, "Undefined", 0, 3],
    ds_grid_add_grid_region: [8, 8, "Undefined", 0, 3],
    ds_grid_add_region: [6, 6, "Undefined", 0, 3],
    ds_grid_clear: [2, 2, "Undefined", 0, 3],
    ds_grid_copy: [2, 2, "Undefined", 0, 3],
    ds_grid_create: [2, 2, "Id.DsGrid", 0, 3],
    ds_grid_destroy: [1, 1, "Undefined", 0, 3],
    ds_grid_get: [3, 3, "ArgumentIdentity", 2, 3],
    ds_grid_get_disk_max: [4, 4, "ArgumentIdentity", 2, 3],
    ds_grid_get_disk_mean: [4, 4, "ArgumentIdentity", 2, 3],
    ds_grid_get_disk_min: [4, 4, "ArgumentIdentity", 2, 3],
    ds_grid_get_disk_sum: [4, 4, "ArgumentIdentity", 2, 3],
    ds_grid_get_max: [5, 5, "ArgumentIdentity", 2, 3],
    ds_grid_get_mean: [5, 5, "ArgumentIdentity", 2, 3],
    ds_grid_get_min: [5, 5, "ArgumentIdentity", 2, 3],
    ds_grid_get_sum: [5, 5, "Real", 2, 3],
    ds_grid_height: [1, 1, "Real", 2, 3],
    ds_grid_multiply: [4, 4, "Undefined", 0, 3],
    ds_grid_multiply_disk: [5, 5, "Undefined", 0, 3],
    ds_grid_multiply_grid_region: [8, 8, "Undefined", 0, 3],
    ds_grid_multiply_region: [6, 6, "Undefined", 0, 3],
    ds_grid_read: [2, 3, "Undefined", 0, 3],
    ds_grid_resize: [3, 3, "Undefined", 0, 3],
    ds_grid_set: [4, 4, "Undefined", 0, 3],
    ds_grid_set_disk: [5, 5, "Undefined", 0, 3],
    ds_grid_set_grid_region: [8, 8, "Undefined", 0, 3],
    ds_grid_set_region: [6, 6, "Undefined", 0, 3],
    ds_grid_shuffle: [1, 1, "Undefined", 0, 3],
    ds_grid_sort: [3, 3, "Undefined", 0, 3],
    ds_grid_to_mp_grid: [2, 3, "Undefined", 0, 1],
    ds_grid_value_disk_exists: [5, 5, "Bool", 2, 3],
    ds_grid_value_disk_x: [5, 5, "Real", 2, 3],
    ds_grid_value_disk_y: [5, 5, "Real", 2, 3],
    ds_grid_value_exists: [6, 6, "Bool", 2, 3],
    ds_grid_value_x: [6, 6, "Real", 2, 3],
    ds_grid_value_y: [6, 6, "Real", 2, 3],
    ds_grid_width: [1, 1, "Real", 2, 3],
    ds_grid_write: [1, 1, "String", 2, 3],
    ds_list_add: [2, -1, "Undefined", 0, 3],
    ds_list_clear: [1, 1, "Undefined", 0, 3],
    ds_list_copy: [2, 2, "Undefined", 0, 3],
    ds_list_create: [0, 0, "Id.DsList", 0, 3],
    ds_list_delete: [2, 2, "Undefined", 0, 3],
    ds_list_destroy: [1, 1, "Undefined", 0, 3],
    ds_list_empty: [1, 1, "Bool", 2, 3],
    ds_list_find_index: [2, 2, "Real", 2, 3],
    ds_list_find_value: [2, 2, "ArgumentIdentity", 2, 3],
    ds_list_insert: [3, 3, "Undefined", 0, 3],
    ds_list_is_list: [2, 2, "Bool", 2, 3],
    ds_list_is_map: [2, 2, "Bool", 2, 3],
    ds_list_mark_as_list: [2, 2, "Real", 0, 3],
    ds_list_mark_as_map: [2, 2, "Real", 0, 3],
    ds_list_read: [2, 3, "Undefined", 0, 3],
    ds_list_replace: [3, 3, "Undefined", 0, 3],
    ds_list_set: [2, -1, "Undefined", 0, 3],
    ds_list_shuffle: [1, 1, "Undefined", 0, 3],
    ds_list_size: [1, 1, "Real", 2, 3],
    ds_list_sort: [2, 2, "Undefined", 0, 3],
    ds_list_write: [1, 1, "String", 2, 3],
    ds_map_add: [3, 3, "Bool", 0, 3],
    ds_map_add_list: [3, 3, "Undefined", 0, 3],
    ds_map_add_map: [3, 3, "Undefined", 0, 3],
    ds_map_clear: [1, 1, "Undefined", 0, 3],
    ds_map_copy: [2, 2, "Undefined", 0, 3],
    ds_map_create: [0, 0, "Id.DsMap", 0, 3],
    ds_map_delete: [2, 2, "Undefined", 0, 3],
    ds_map_destroy: [1, 1, "Undefined", 0, 3],
    ds_map_empty: [1, 1, "Bool", 2, 3],
    ds_map_exists: [2, 2, "Bool", 2, 3],
    ds_map_find_first: [1, 1, "Any", 2, 3],
    ds_map_find_last: [1, 1, "Any", 2, 3],
    ds_map_find_next: [2, 2, "Any", 2, 3],
    ds_map_find_previous: [2, 2, "Any", 2, 3],
    ds_map_find_value: [2, 2, "ArgumentIdentity", 2, 3],
    ds_map_is_list: [2, 2, "Bool", 2, 3],
    ds_map_is_map: [2, 2, "Bool", 2, 3],
    ds_map_keys_to_array: [1, 2, "Array[Any]", 2, 3],
    ds_map_read: [2, 3, "Undefined", 0, 3],
    ds_map_replace: [3, 3, "Bool", 0, 3],
    ds_map_replace_list: [3, 3, "Undefined", 0, 3],
    ds_map_replace_map: [3, 3, "Undefined", 0, 3],
    ds_map_secure_load: [1, 1, "Id.DsMap", 0, 3],
    ds_map_secure_load_buffer: [1, 1, "Id.DsMap", 0, 3],
    ds_map_secure_save: [2, 2, "Bool", 0, 3],
    ds_map_secure_save_buffer: [2, 2, "Real", 0, 3],
    ds_map_set: [3, 3, "Undefined", 0, 3],
    ds_map_size: [1, 1, "Real", 2, 3],
    ds_map_values_to_array: [1, 2, "Array[Any]", 2, 3],
    ds_map_write: [1, 1, "String", 2, 3],
    ds_priority_add: [3, 3, "Undefined", 0, 3],
    ds_priority_change_priority: [3, 3, "Undefined", 0, 3],
    ds_priority_clear: [1, 1, "Undefined", 0, 3],
    ds_priority_copy: [2, 2, "Undefined", 0, 3],
    ds_priority_create: [0, 0, "Id.DsPriority", 0, 3],
    ds_priority_delete_max: [1, 1, "ArgumentIdentity", 0, 3],
    ds_priority_delete_min: [1, 1, "ArgumentIdentity", 0, 3],
    ds_priority_delete_value: [2, 2, "Undefined", 0, 3],
    ds_priority_destroy: [1, 1, "Undefined", 0, 3],
    ds_priority_empty: [1, 1, "Bool", 2, 3],
    ds_priority_find_max: [1, 1, "ArgumentIdentity", 2, 3],
    ds_priority_find_min: [1, 1, "ArgumentIdentity", 2, 3],
    ds_priority_find_priority: [2, 2, "Real", 2, 3],
    ds_priority_read: [2, 3, "Undefined", 0, 3],
    ds_priority_size: [1, 1, "Real", 2, 3],
    ds_priority_write: [1, 1, "String", 2, 3],
    ds_queue_clear: [1, 1, "Undefined", 0, 3],
    ds_queue_copy: [2, 2, "Undefined", 0, 3],
    ds_queue_create: [0, 0, "Id.DsQueue", 0, 3],
    ds_queue_dequeue: [1, 1, "ArgumentIdentity", 0, 3],
    ds_queue_destroy: [1, 1, "Undefined", 0, 3],
    ds_queue_empty: [1, 1, "Bool", 2, 3],
    ds_queue_enqueue: [1, -1, "Undefined", 0, 3],
    ds_queue_head: [1, 1, "ArgumentIdentity", 2, 3],
    ds_queue_read: [2, 3, "Undefined", 0, 3],
    ds_queue_size: [1, 1, "Real", 2, 3],
    ds_queue_tail: [1, 1, "ArgumentIdentity", 2, 3],
    ds_queue_write: [1, 1, "String", 2, 3],
    ds_set_precision: [1, 1, "Undefined", 0, 3],
    ds_stack_clear: [1, 1, "Undefined", 0, 3],
    ds_stack_copy: [2, 2, "Undefined", 0, 3],
    ds_stack_create: [0, 0, "Id.DsStack", 0, 3],
    ds_stack_destroy: [1, 1, "Undefined", 0, 3],
    ds_stack_empty: [1, 1, "Bool", 2, 3],
    ds_stack_pop: [1, 1, "ArgumentIdentity", 0, 3],
    ds_stack_push: [2, -1, "Undefined", 0, 3],
    ds_stack_read: [2, 3, "Undefined", 0, 3],
    ds_stack_size: [1, 1, "Real", 2, 3],
    ds_stack_top: [1, 1, "ArgumentIdentity", 2, 3],
    ds_stack_write: [1, 1, "String", 2, 3],
    dsin: [1, 1, "Real", 2, 3],
    dtan: [1, 1, "Real", 2, 3],
    effect_clear: [0, 0, "Undefined", 0, 3],
    effect_create_above: [5, 5, "Undefined", 1, 3],
    effect_create_below: [5, 5, "Undefined", 1, 3],
    effect_create_depth: [6, 6, "Undefined", 0, 1],
    effect_create_layer: [6, 6, "Undefined", 0, 1],
    environment_get_variable: [1, 1, "String", 2, 3],
    event_inherited: [0, 0, "Undefined", 0, 3],
    event_perform: [2, 2, "Undefined", 0, 3],
    event_perform_async: [2, 2, "Undefined", 0, 3],
    event_perform_object: [3, 3, "Undefined", 0, 3],
    event_user: [1, 1, "Undefined", 0, 3],
    exception_unhandled_handler: [1, 1, "Function", 0, 3],
    exp: [1, 1, "Real", 2, 3],
    extension_exists: [1, 1, "Bool", 2, 3],
    extension_get_option_count: [1, 1, "Real", 2, 3],
    extension_get_option_names: [1, 1, "Array.String", 2, 3],
    extension_get_option_value: [2, 2, "Any", 2, 3],
    extension_get_options: [1, 1, "Struct", 2, 3],
    extension_get_version: [1, 1, "String", 2, 1],
    external_call: [1, -1, "Any", 0, 3],
    external_define: [5, -1, "Id.ExternalCall", 0, 3],
    external_free: [1, 1, "Undefined", 0, 3],
    file_attributes: [2, 2, "Bool", 0, 3],
    file_bin_close: [1, 1, "Undefined", 0, 3],
    file_bin_open: [2, 2, "Id.BinaryFile", 0, 3],
    file_bin_position: [1, 1, "Real", 2, 3],
    file_bin_read_byte: [1, 1, "Real", 0, 3],
    file_bin_rewrite: [1, 1, "Undefined", 0, 3],
    file_bin_seek: [2, 2, "Undefined", 0, 3],
    file_bin_size: [1, 1, "Real", 2, 3],
    file_bin_write_byte: [2, 2, "Real", 0, 3],
    file_copy: [2, 2, "Real", 0, 3],
    file_delete: [1, 1, "Bool", 0, 3],
    file_exists: [1, 1, "Bool", 2, 3],
    file_find_close: [0, 0, "Undefined", 0, 3],
    file_find_first: [2, 2, "String", 0, 3],
    file_find_next: [0, 0, "String", 0, 3],
    file_rename: [2, 2, "Bool", 0, 3],
    file_text_close: [1, 1, "Undefined", 0, 3],
    file_text_eof: [1, 1, "Bool", 2, 3],
    file_text_eoln: [1, 1, "Bool", 0, 3],
    file_text_open_append: [1, 1, "Id.TextFile", 0, 3],
    file_text_open_from_string: [1, 1, "Id.TextFile", 0, 3],
    file_text_open_read: [1, 1, "Id.TextFile", 0, 3],
    file_text_open_write: [1, 1, "Id.TextFile", 0, 3],
    file_text_read_real: [1, 1, "Real", 0, 3],
    file_text_read_string: [1, 1, "String", 0, 3],
    file_text_readln: [1, 1, "String", 0, 3],
    file_text_write_real: [2, 2, "Real", 0, 3],
    file_text_write_string: [2, 2, "Real", 0, 3],
    file_text_writeln: [1, 1, "Real", 0, 3],
    filename_change_ext: [2, 2, "String", 0, 3],
    filename_dir: [1, 1, "String", 2, 3],
    filename_drive: [1, 1, "String", 2, 3],
    filename_ext: [1, 1, "String", 2, 3],
    filename_name: [1, 1, "String", 2, 3],
    filename_path: [1, 1, "String", 2, 3],
    flexpanel_calculate_layout: [1, 5, "Undefined", 0, 1],
    flexpanel_create_node: [0, 1, "Pointer.FlexpanelNode", 0, 1],
    flexpanel_delete_node: [1, 2, "Undefined", 0, 1],
    flexpanel_get_rounding_scale: [0, 0, "Real", 2, 1],
    flexpanel_node_get_child: [2, 2, "Pointer.FlexpanelNode", 0, 1],
    flexpanel_node_get_child_hash: [2, 2, "Pointer.FlexpanelNode", 0, 1],
    flexpanel_node_get_data: [1, 1, "Struct", 0, 1],
    flexpanel_node_get_measure_function: [1, 1, "Function", 0, 1],
    flexpanel_node_get_name: [1, 1, "String", 2, 1],
    flexpanel_node_get_num_children: [1, 1, "Real", 0, 1],
    flexpanel_node_get_parent: [1, 1, "Pointer.FlexpanelNode", 2, 1],
    flexpanel_node_get_struct: [1, 1, "Struct", 0, 1],
    flexpanel_node_insert_child: [3, 3, "Undefined", 0, 1],
    flexpanel_node_layout_get_position: [1, 2, "Struct", 2, 1],
    flexpanel_node_remove_all_children: [1, 1, "Undefined", 0, 1],
    flexpanel_node_remove_child: [2, 2, "Undefined", 0, 1],
    flexpanel_node_set_data: [2, 2, "Any", 0, 1],
    flexpanel_node_set_measure_function: [2, 2, "undefined", 0, 1],
    flexpanel_node_set_name: [2, 2, "undefined", 0, 1],
    flexpanel_node_style_get_align_content: [1, 1, "Enum.flexpanel_align", 2, 1],
    flexpanel_node_style_get_align_items: [1, 1, "Enum.flexpanel_align", 2, 1],
    flexpanel_node_style_get_align_self: [1, 1, "Enum.flexpanel_align", 2, 1],
    flexpanel_node_style_get_aspect_ratio: [1, 1, "Real", 2, 1],
    flexpanel_node_style_get_border: [2, 2, "Real", 2, 1],
    flexpanel_node_style_get_direction: [1, 1, "Enum.flexpanel_direction", 2, 1],
    flexpanel_node_style_get_display: [1, 1, "Enum.flexpanel_display", 2, 1],
    flexpanel_node_style_get_flex: [1, 1, "Real", 2, 1],
    flexpanel_node_style_get_flex_basis: [1, 1, "Struct", 2, 1],
    flexpanel_node_style_get_flex_direction: [1, 1, "Enum.flexpanel_flex_direction", 2, 1],
    flexpanel_node_style_get_flex_grow: [1, 1, "Real", 2, 1],
    flexpanel_node_style_get_flex_shrink: [1, 1, "Real", 2, 1],
    flexpanel_node_style_get_flex_wrap: [1, 1, "Enum.flexpanel_wrap", 2, 1],
    flexpanel_node_style_get_gap: [2, 2, "Real", 2, 1],
    flexpanel_node_style_get_height: [1, 1, "Struct", 2, 1],
    flexpanel_node_style_get_justify_content: [1, 1, "Enum.flexpanel_justify", 2, 1],
    flexpanel_node_style_get_margin: [2, 2, "Struct", 2, 1],
    flexpanel_node_style_get_max_height: [1, 1, "Struct", 2, 1],
    flexpanel_node_style_get_max_width: [1, 1, "Struct", 2, 1],
    flexpanel_node_style_get_min_height: [1, 1, "Struct", 2, 1],
    flexpanel_node_style_get_min_width: [1, 1, "Struct", 2, 1],
    flexpanel_node_style_get_padding: [2, 2, "Struct", 2, 1],
    flexpanel_node_style_get_position: [2, 2, "Struct", 2, 1],
    flexpanel_node_style_get_position_type: [1, 1, "Enum.flexpanel_position_type", 2, 1],
    flexpanel_node_style_get_width: [1, 1, "Struct", 2, 1],
    flexpanel_node_style_set_align_content: [2, 2, "Undefined", 0, 1],
    flexpanel_node_style_set_align_items: [2, 2, "Undefined", 0, 1],
    flexpanel_node_style_set_align_self: [2, 2, "Undefined", 0, 1],
    flexpanel_node_style_set_aspect_ratio: [2, 2, "Undefined", 0, 1],
    flexpanel_node_style_set_border: [3, 3, "Undefined", 0, 1],
    flexpanel_node_style_set_direction: [2, 2, "Undefined", 0, 1],
    flexpanel_node_style_set_display: [2, 2, "Undefined", 0, 1],
    flexpanel_node_style_set_flex: [2, 2, "Undefined", 0, 1],
    flexpanel_node_style_set_flex_basis: [3, 3, "Undefined", 0, 1],
    flexpanel_node_style_set_flex_direction: [2, 2, "Undefined", 0, 1],
    flexpanel_node_style_set_flex_grow: [2, 2, "Undefined", 0, 1],
    flexpanel_node_style_set_flex_shrink: [2, 2, "Undefined", 0, 1],
    flexpanel_node_style_set_flex_wrap: [2, 2, "Undefined", 0, 1],
    flexpanel_node_style_set_gap: [3, 3, "Undefined", 0, 1],
    flexpanel_node_style_set_height: [3, 3, "Undefined", 0, 1],
    flexpanel_node_style_set_justify_content: [2, 2, "Undefined", 0, 1],
    flexpanel_node_style_set_margin: [3, 4, "Undefined", 0, 1],
    flexpanel_node_style_set_max_height: [3, 3, "Undefined", 0, 1],
    flexpanel_node_style_set_max_width: [3, 3, "Undefined", 0, 1],
    flexpanel_node_style_set_min_height: [3, 3, "Undefined", 0, 1],
    flexpanel_node_style_set_min_width: [3, 3, "Undefined", 0, 1],
    flexpanel_node_style_set_padding: [3, 4, "Undefined", 0, 1],
    flexpanel_node_style_set_position: [4, 4, "Undefined", 0, 1],
    flexpanel_node_style_set_position_type: [2, 2, "Undefined", 0, 1],
    flexpanel_node_style_set_width: [3, 3, "Undefined", 0, 1],
    flexpanel_set_rounding_scale: [1, 1, "Undefined", 0, 1],
    floor: [1, 1, "Real", 2, 3],
    font_add: [6, 6, "Asset.GMFont", 0, 3],
    font_add_enable_aa: [1, 1, "Undefined", 0, 3],
    font_add_get_enable_aa: [0, 0, "Bool", 2, 3],
    font_add_sprite: [4, 4, "Asset.GMFont", 0, 3],
    font_add_sprite_ext: [4, 4, "Asset.GMFont", 0, 3],
    font_cache_glyph: [2, 2, "Undefined", 0, 3],
    font_delete: [1, 1, "Undefined", 0, 3],
    font_enable_effects: [2, 3, "Undefined", 0, 1],
    font_enable_sdf: [2, 2, "Undefined", 0, 1],
    font_exists: [1, 1, "Bool", 2, 3],
    font_get_bold: [1, 1, "Bool", 2, 3],
    font_get_first: [1, 1, "Real", 3, 3],
    font_get_fontname: [1, 1, "String", 2, 3],
    font_get_info: [1, 1, "Struct.FontInfo", 2, 3],
    font_get_italic: [1, 1, "Bool", 2, 3],
    font_get_last: [1, 1, "Real", 2, 3],
    font_get_name: [1, 1, "String", 2, 3],
    font_get_sdf_enabled: [1, 1, "Bool", 2, 1],
    font_get_sdf_spread: [1, 1, "Real", 2, 1],
    font_get_size: [1, 1, "Real", 2, 3],
    font_get_texture: [1, 1, "Pointer.Texture", 2, 3],
    font_get_uvs: [1, 1, "Array[Real]", 2, 3],
    font_replace_sprite: [5, 5, "Undefined", 0, 3],
    font_replace_sprite_ext: [5, 5, "Undefined", 0, 3],
    font_sdf_spread: [2, 2, "Undefined", 0, 1],
    font_set_cache_size: [2, 2, "Undefined", 0, 3],
    frac: [1, 1, "Real", 2, 3],
    fx_create: [1, 1, "Struct.Fx", 0, 3],
    fx_get_name: [1, 1, "String", 2, 3],
    fx_get_parameter: [2, 2, "Any", 2, 3],
    fx_get_parameter_names: [1, 1, "Array[String]", 2, 3],
    fx_get_parameters: [1, 1, "Struct", 2, 3],
    fx_get_single_layer: [1, 1, "Bool", 2, 3],
    fx_set_parameter: [3, 3, "Undefined", 0, 3],
    fx_set_parameters: [2, 2, "Undefined", 0, 3],
    fx_set_single_layer: [2, 2, "Undefined", 0, 3],
    game_change: [2, 2, "Undefined", 0, 1],
    game_end: [0, 1, "Undefined", 0, 3],
    game_get_speed: [1, 1, "Real", 2, 3],
    game_load: [1, 1, "Undefined", 1, 3],
    game_load_buffer: [1, 1, "Undefined", 0, 3],
    game_restart: [0, 0, "Undefined", 0, 3],
    game_save: [1, 1, "Undefined", 1, 3],
    game_save_buffer: [1, 1, "Undefined", 0, 3],
    game_set_speed: [2, 2, "Undefined", 0, 3],
    gamepad_axis_count: [1, 1, "Real", 2, 3],
    gamepad_axis_value: [2, 2, "Real", 2, 3],
    gamepad_button_check: [2, 2, "Bool", 2, 3],
    gamepad_button_check_pressed: [2, 2, "Bool", 2, 3],
    gamepad_button_check_released: [2, 2, "Bool", 2, 3],
    gamepad_button_count: [1, 1, "Real", 2, 3],
    gamepad_button_value: [2, 2, "Real", 2, 3],
    gamepad_enumerate: [0, 0, "Undefined", 2, 1],
    gamepad_get_axis_deadzone: [1, 1, "Real", 2, 3],
    gamepad_get_button_threshold: [1, 1, "Real", 2, 3],
    gamepad_get_description: [1, 1, "String", 2, 3],
    gamepad_get_device_count: [0, 0, "Real", 2, 3],
    gamepad_get_guid: [1, 1, "String", 2, 3],
    gamepad_get_mapping: [1, 1, "String", 2, 3],
    gamepad_get_option: [2, 2, "Real", 2, 3],
    gamepad_hat_count: [1, 1, "Real", 2, 3],
    gamepad_hat_value: [2, 2, "Real", 2, 3],
    gamepad_is_connected: [1, 1, "Bool", 2, 3],
    gamepad_is_supported: [0, 0, "Bool", 2, 3],
    gamepad_remove_mapping: [1, 1, "Undefined", 0, 3],
    gamepad_set_axis_deadzone: [2, 2, "Undefined", 0, 3],
    gamepad_set_button_threshold: [2, 2, "Undefined", 0, 3],
    gamepad_set_color: [2, 2, "Undefined", 0, 3],
    gamepad_set_colour: [2, 2, "Undefined", 0, 3],
    gamepad_set_option: [3, 3, "Undefined", 0, 3],
    gamepad_set_vibration: [3, 3, "Undefined", 0, 3],
    gamepad_test_mapping: [2, 2, "Undefined", 0, 3],
    gc_collect: [0, 0, "Undefined", 0, 3],
    gc_enable: [1, 1, "Undefined", 0, 3],
    gc_get_stats: [0, 0, "Struct.GCStats", 2, 3],
    gc_get_target_frame_time: [0, 0, "Real", 2, 3],
    gc_is_enabled: [0, 0, "Bool", 2, 3],
    gc_target_frame_time: [1, 1, "Undefined", 0, 3],
    gesture_double_tap_distance: [1, 1, "Undefined", 0, 3],
    gesture_double_tap_time: [1, 1, "Undefined", 0, 3],
    gesture_drag_distance: [1, 1, "Undefined", 0, 3],
    gesture_drag_time: [1, 1, "Undefined", 0, 3],
    gesture_flick_speed: [1, 1, "Undefined", 0, 3],
    gesture_get_double_tap_distance: [0, 0, "Real", 2, 3],
    gesture_get_double_tap_time: [0, 0, "Real", 2, 3],
    gesture_get_drag_distance: [0, 0, "Real", 2, 3],
    gesture_get_drag_time: [0, 0, "Real", 2, 3],
    gesture_get_flick_speed: [0, 0, "Real", 2, 3],
    gesture_get_pinch_angle_away: [0, 0, "Real", 2, 3],
    gesture_get_pinch_angle_towards: [0, 0, "Real", 2, 3],
    gesture_get_pinch_distance: [0, 0, "Real", 2, 3],
    gesture_get_rotate_angle: [0, 0, "Real", 2, 3],
    gesture_get_rotate_time: [0, 0, "Real", 2, 3],
    gesture_get_tap_count: [0, 0, "Bool", 2, 3],
    gesture_pinch_angle_away: [1, 1, "Real", 0, 3],
    gesture_pinch_angle_towards: [1, 1, "Real", 0, 3],
    gesture_pinch_distance: [1, 1, "Real", 2, 3],
    gesture_rotate_angle: [1, 1, "Real", 0, 3],
    gesture_rotate_time: [1, 1, "Real", 0, 3],
    gesture_tap_count: [1, 1, "Undefined", 0, 3],
    get_integer: [2, 2, "Real", 3, 3],
    get_integer_async: [2, 2, "Real", 2, 3],
    get_login_async: [2, 2, "Real", 0, 3],
    get_open_filename: [2, 2, "String", 0, 3],
    get_open_filename_ext: [4, 4, "String", 0, 3],
    get_save_filename: [2, 2, "String", 0, 3],
    get_save_filename_ext: [4, 4, "String", 0, 3],
    get_string: [2, 2, "String", 3, 3],
    get_string_async: [2, 2, "Real", 2, 3],
    get_timer: [0, 0, "Real", 2, 3],
    gif_add_surface: [3, 6, "Real", 0, 3],
    gif_open: [2, 3, "Id.Gif", 0, 3],
    gif_save: [2, 2, "Real", 0, 3],
    gif_save_buffer: [1, 1, "Real", 0, 3],
    gml_pragma: [1, -1, "Undefined", 0, 3],
    gml_release_mode: [1, 1, "Undefined", 0, 3],
    gpu_get_alphatestenable: [0, 0, "Bool", 2, 3],
    gpu_get_alphatestref: [0, 0, "Real", 2, 3],
    gpu_get_blendenable: [0, 0, "Bool", 2, 3],
    gpu_get_blendequation: [0, 0, "Constant.BlendModeEquation", 2, 1],
    gpu_get_blendequation_sepalpha: [0, 0, "Array[Constant.BlendModeEquation]", 2, 1],
    gpu_get_blendmode: [0, 0, "Constant.BlendMode", 2, 3],
    gpu_get_blendmode_dest: [0, 0, "Constant.BlendModeFactor", 2, 3],
    gpu_get_blendmode_destalpha: [0, 0, "Constant.BlendModeFactor", 2, 3],
    gpu_get_blendmode_ext: [0, 0, "Array[Constant.BlendModeFactor]", 2, 3],
    gpu_get_blendmode_ext_sepalpha: [0, 0, "Array[Constant.BlendModeFactor]", 2, 3],
    gpu_get_blendmode_src: [0, 0, "Constant.BlendModeFactor", 2, 3],
    gpu_get_blendmode_srcalpha: [0, 0, "Constant.BlendModeFactor", 2, 3],
    gpu_get_colorwriteenable: [0, 0, "Array[Bool]", 2, 3],
    gpu_get_colourwriteenable: [0, 0, "Array[Bool]", 2, 3],
    gpu_get_cullmode: [0, 0, "Constant.CullMode", 2, 3],
    gpu_get_depth: [0, 0, "Real", 2, 1],
    gpu_get_fog: [0, 0, "Array[Real]", 2, 3],
    gpu_get_scissor: [0, 0, "Struct", 2, 1],
    gpu_get_sprite_cull: [0, 0, "Bool", 2, 1],
    gpu_get_state: [0, 0, "Id.DsMap", 2, 3],
    gpu_get_stencil_depth_fail: [0, 0, "Constant.StencilOp", 2, 1],
    gpu_get_stencil_enable: [0, 0, "Bool", 2, 1],
    gpu_get_stencil_fail: [0, 0, "Constant.StencilOp", 2, 1],
    gpu_get_stencil_func: [0, 0, "Constant.ZFunction", 2, 1],
    gpu_get_stencil_pass: [0, 0, "Constant.StencilOp", 2, 1],
    gpu_get_stencil_read_mask: [0, 0, "Real", 2, 1],
    gpu_get_stencil_ref: [0, 0, "Real", 2, 1],
    gpu_get_stencil_write_mask: [0, 0, "Real", 2, 1],
    gpu_get_tex_filter: [0, 0, "Bool", 2, 3],
    gpu_get_tex_filter_ext: [1, 1, "Bool", 2, 3],
    gpu_get_tex_max_aniso: [0, 0, "Real", 2, 3],
    gpu_get_tex_max_aniso_ext: [1, 1, "Real", 2, 3],
    gpu_get_tex_max_mip: [0, 0, "Real", 2, 3],
    gpu_get_tex_max_mip_ext: [1, 1, "Real", 2, 3],
    gpu_get_tex_min_mip: [0, 0, "Real", 2, 3],
    gpu_get_tex_min_mip_ext: [1, 1, "Real", 2, 3],
    gpu_get_tex_mip_bias: [0, 0, "Real", 2, 3],
    gpu_get_tex_mip_bias_ext: [1, 1, "Real", 2, 3],
    gpu_get_tex_mip_enable: [0, 0, "Real", 2, 3],
    gpu_get_tex_mip_enable_ext: [1, 1, "Real", 2, 3],
    gpu_get_tex_mip_filter: [0, 0, "Real", 2, 3],
    gpu_get_tex_mip_filter_ext: [1, 1, "Real", 2, 3],
    gpu_get_tex_repeat: [0, 0, "Bool", 2, 3],
    gpu_get_tex_repeat_ext: [1, 1, "Bool", 2, 3],
    gpu_get_texfilter: [0, 0, "Bool", 2, 3],
    gpu_get_texfilter_ext: [1, 1, "Bool", 2, 3],
    gpu_get_texrepeat: [0, 0, "Bool", 2, 3],
    gpu_get_texrepeat_ext: [1, 1, "Bool", 2, 3],
    gpu_get_zfunc: [0, 0, "Constant.ZFunction", 2, 3],
    gpu_get_ztestenable: [0, 0, "Bool", 2, 3],
    gpu_get_zwriteenable: [0, 0, "Bool", 2, 3],
    gpu_pop_state: [0, 0, "Undefined", 0, 3],
    gpu_push_state: [0, 0, "Undefined", 0, 3],
    gpu_set_alphatestenable: [1, 1, "Undefined", 0, 3],
    gpu_set_alphatestref: [1, 1, "Undefined", 0, 3],
    gpu_set_blendenable: [1, 1, "Undefined", 0, 3],
    gpu_set_blendequation: [1, 1, "Undefined", 0, 1],
    gpu_set_blendequation_sepalpha: [2, 2, "Undefined", 0, 1],
    gpu_set_blendmode: [1, 1, "Undefined", 0, 3],
    gpu_set_blendmode_ext: [2, 2, "Undefined", 0, 3],
    gpu_set_blendmode_ext_sepalpha: [4, 4, "Undefined", 0, 3],
    gpu_set_colorwriteenable: [1, 4, "Undefined", 0, 3],
    gpu_set_colourwriteenable: [1, 4, "Undefined", 0, 3],
    gpu_set_cullmode: [1, 1, "Undefined", 0, 3],
    gpu_set_depth: [1, 1, "Undefined", 0, 1],
    gpu_set_fog: [1, 4, "Undefined", 0, 3],
    gpu_set_scissor: [1, 4, "Undefined", 0, 1],
    gpu_set_sprite_cull: [1, 1, "Undefined", 0, 1],
    gpu_set_state: [1, 1, "Undefined", 0, 3],
    gpu_set_stencil_depth_fail: [1, 1, "Undefined", 0, 1],
    gpu_set_stencil_enable: [1, 1, "Undefined", 0, 1],
    gpu_set_stencil_fail: [1, 1, "Undefined", 0, 1],
    gpu_set_stencil_func: [1, 1, "Undefined", 0, 1],
    gpu_set_stencil_pass: [1, 1, "Undefined", 0, 1],
    gpu_set_stencil_read_mask: [1, 1, "Undefined", 0, 1],
    gpu_set_stencil_ref: [1, 1, "Undefined", 0, 1],
    gpu_set_stencil_write_mask: [1, 1, "Undefined", 0, 1],
    gpu_set_tex_filter: [1, 1, "Undefined", 0, 3],
    gpu_set_tex_filter_ext: [2, 2, "Undefined", 0, 3],
    gpu_set_tex_max_aniso: [1, 1, "Undefined", 0, 3],
    gpu_set_tex_max_aniso_ext: [2, 2, "Undefined", 0, 3],
    gpu_set_tex_max_mip: [1, 1, "Undefined", 0, 3],
    gpu_set_tex_max_mip_ext: [2, 2, "Undefined", 0, 3],
    gpu_set_tex_min_mip: [1, 1, "Undefined", 0, 3],
    gpu_set_tex_min_mip_ext: [2, 2, "Undefined", 0, 3],
    gpu_set_tex_mip_bias: [1, 1, "Undefined", 0, 3],
    gpu_set_tex_mip_bias_ext: [2, 2, "Undefined", 0, 3],
    gpu_set_tex_mip_enable: [1, 1, "Undefined", 0, 3],
    gpu_set_tex_mip_enable_ext: [2, 2, "Undefined", 0, 3],
    gpu_set_tex_mip_filter: [1, 1, "Undefined", 0, 3],
    gpu_set_tex_mip_filter_ext: [2, 2, "Undefined", 0, 3],
    gpu_set_tex_repeat: [1, 1, "Undefined", 0, 3],
    gpu_set_tex_repeat_ext: [2, 2, "Undefined", 0, 3],
    gpu_set_texfilter: [1, 1, "Undefined", 0, 3],
    gpu_set_texfilter_ext: [2, 2, "Undefined", 0, 3],
    gpu_set_texrepeat: [1, 1, "Undefined", 0, 3],
    gpu_set_texrepeat_ext: [2, 2, "Undefined", 0, 3],
    gpu_set_zfunc: [1, 1, "Undefined", 0, 3],
    gpu_set_ztestenable: [1, 1, "Undefined", 0, 3],
    gpu_set_zwriteenable: [1, 1, "Undefined", 0, 3],
    gx_share: [1, 4, "Real", 0, 1],
    gxc_file_sync: [0, -1, "Any", 0, 1],
    gxc_input_playback: [1, 1, "Any", 0, 3],
    gxc_pause_movie_recording: [0, 0, "Any", 0, 3],
    gxc_record_input_playback: [1, 1, "Any", 0, 3],
    gxc_resume_movie_recording: [0, 0, "Any", 0, 3],
    gxc_save_input_playback: [1, 1, "Any", 0, 3],
    gxc_start_movie_recording: [4, 4, "Any", 0, 3],
    gxc_stop_movie_recording: [1, 1, "Any", 0, 3],
    handle_parse: [1, 1, "Asset", 2, 1],
    highscore_add: [2, 2, "Undefined", 0, 3],
    highscore_clear: [0, 0, "Undefined", 0, 3],
    highscore_name: [1, 1, "String", 2, 3],
    highscore_value: [1, 1, "Real", 0, 3],
    http_get: [1, 1, "Real", 0, 3],
    http_get_connect_timeout: [0, 0, "String", 2, 1],
    http_get_file: [2, 2, "Real", 0, 3],
    http_get_request_crossorigin: [0, 0, "String", 2, 3],
    http_post_string: [2, 2, "Real", 2, 3],
    http_request: [4, 4, "Real", 0, 3],
    http_set_connect_timeout: [1, 1, "Undefined", 0, 1],
    http_set_request_crossorigin: [1, 1, "Undefined", 0, 3],
    iap_acquire: [2, 2, "Undefined", 1, 3],
    iap_activate: [1, 1, "Undefined", 1, 3],
    iap_consume: [1, 1, "Undefined", 1, 3],
    iap_enumerate_products: [1, 1, "Undefined", 3, 3],
    iap_product_details: [2, 2, "Undefined", 3, 3],
    iap_purchase_details: [2, 2, "Undefined", 3, 3],
    iap_restore_all: [0, 0, "Undefined", 1, 3],
    iap_status: [0, 0, "Bool", 3, 3],
    ini_close: [0, 0, "String", 0, 3],
    ini_key_delete: [2, 2, "Undefined", 0, 3],
    ini_key_exists: [2, 2, "Bool", 2, 3],
    ini_open: [1, 1, "Undefined", 0, 3],
    ini_open_from_string: [1, 1, "Undefined", 0, 3],
    ini_read_real: [3, 3, "Real", 2, 3],
    ini_read_string: [3, 3, "String", 2, 3],
    ini_section_delete: [1, 1, "Undefined", 0, 3],
    ini_section_exists: [1, 1, "Bool", 2, 3],
    ini_write_real: [3, 3, "Undefined", 0, 3],
    ini_write_string: [3, 3, "Undefined", 0, 3],
    instance_activate_all: [0, 1, "Undefined", 0, 3],
    instance_activate_layer: [1, 1, "Undefined", 0, 3],
    instance_activate_object: [1, 2, "Undefined", 0, 3],
    instance_activate_region: [5, 6, "Undefined", 0, 3],
    instance_change: [2, 2, "Undefined", 1, 3],
    instance_copy: [1, 1, "Id.Instance", 0, 3],
    instance_create_depth: [4, 5, "Id.Instance", 0, 3],
    instance_create_layer: [4, 5, "Id.Instance", 0, 3],
    instance_deactivate_all: [1, 2, "Undefined", 0, 3],
    instance_deactivate_layer: [1, 1, "Undefined", 0, 3],
    instance_deactivate_object: [1, 2, "Undefined", 0, 3],
    instance_deactivate_region: [6, 7, "Undefined", 0, 3],
    instance_destroy: [0, 2, "Undefined", 0, 3],
    instance_exists: [1, 1, "Bool", 2, 3],
    instance_find: [2, 2, "Id.Instance", 2, 3],
    instance_furthest: [3, 3, "Id.Instance", 2, 3],
    instance_id_get: [1, 1, "Real", 2, 3],
    instance_nearest: [3, 3, "Id.Instance", 2, 3],
    instance_number: [1, 1, "Real", 2, 3],
    instance_place: [3, 3, "Id.Instance", 2, 3],
    instance_place_list: [5, 5, "Real", 0, 3],
    instance_position: [3, 3, "Id.Instance", 2, 3],
    instance_position_list: [5, 5, "Real", 0, 3],
    instanceof: [1, 1, "String", 2, 3],
    int64: [1, 1, "Real", 2, 3],
    io_clear: [0, 0, "Undefined", 0, 3],
    irandom: [1, 1, "Real", 2, 3],
    irandom_range: [2, 2, "Real", 2, 3],
    is_array: [1, 1, "Bool", 2, 3],
    is_bool: [1, 1, "Bool", 2, 3],
    is_callable: [1, 1, "Bool", 2, 1],
    is_debug_overlay_open: [0, 0, "Bool", 2, 1],
    is_handle: [1, 1, "Bool", 2, 1],
    is_infinity: [1, 1, "Bool", 2, 3],
    is_instanceof: [2, 2, "Bool", 2, 1],
    is_int32: [1, 1, "Bool", 2, 3],
    is_int64: [1, 1, "Bool", 2, 3],
    is_keyboard_used_debug_overlay: [0, 0, "Bool", 2, 1],
    is_matrix: [1, 1, "Bool", 3, 2],
    is_method: [1, 1, "Bool", 2, 3],
    is_mouse_over_debug_overlay: [0, 0, "Bool", 2, 1],
    is_nan: [1, 1, "Bool", 2, 3],
    is_numeric: [1, 1, "Bool", 2, 3],
    is_ptr: [1, 1, "Bool", 2, 3],
    is_real: [1, 1, "Bool", 2, 3],
    is_string: [1, 1, "Bool", 2, 3],
    is_struct: [1, 1, "Bool", 2, 3],
    is_undefined: [1, 1, "Bool", 2, 3],
    is_vec3: [1, 1, "Bool", 3, 2],
    is_vec4: [1, 1, "Bool", 3, 2],
    json_decode: [1, 1, "Any", 2, 3],
    json_encode: [1, 2, "String", 2, 3],
    json_parse: [1, 3, "Any", 2, 3],
    json_stringify: [1, 3, "String", 2, 3],
    keyboard_check: [1, 1, "Bool", 2, 3],
    keyboard_check_direct: [1, 1, "Bool", 2, 3],
    keyboard_check_pressed: [1, 1, "Bool", 2, 3],
    keyboard_check_released: [1, 1, "Bool", 2, 3],
    keyboard_clear: [1, 1, "Undefined", 0, 3],
    keyboard_get_map: [1, 1, "Real", 2, 3],
    keyboard_get_numlock: [0, 0, "Bool", 2, 3],
    keyboard_key_press: [1, 1, "Undefined", 0, 3],
    keyboard_key_release: [1, 1, "Undefined", 0, 3],
    keyboard_set_map: [2, 2, "Bool", 0, 3],
    keyboard_set_numlock: [1, 1, "Undefined", 0, 3],
    keyboard_unset_map: [0, 0, "Undefined", 0, 3],
    keyboard_virtual_height: [0, 0, "Real", 2, 3],
    keyboard_virtual_hide: [0, 0, "Undefined", 0, 3],
    keyboard_virtual_set_position: [2, 2, "Undefined", 0, 1],
    keyboard_virtual_show: [4, 4, "Undefined", 0, 3],
    keyboard_virtual_status: [0, 0, "Bool", 2, 3],
    layer_add_instance: [2, 2, "Undefined", 0, 3],
    layer_background_alpha: [2, 2, "Undefined", 0, 3],
    layer_background_blend: [2, 2, "Undefined", 0, 3],
    layer_background_change: [2, 2, "Undefined", 0, 3],
    layer_background_create: [2, 2, "Id.BackgroundElement", 0, 3],
    layer_background_destroy: [1, 1, "Undefined", 0, 3],
    layer_background_exists: [2, 2, "Bool", 2, 3],
    layer_background_get_alpha: [1, 1, "Real", 2, 3],
    layer_background_get_blend: [1, 1, "Constant.Color", 2, 3],
    layer_background_get_htiled: [1, 1, "Bool", 2, 3],
    layer_background_get_id: [1, 1, "Id.BackgroundElement", 2, 3],
    layer_background_get_index: [1, 1, "Real", 2, 3],
    layer_background_get_speed: [1, 1, "Real", 2, 3],
    layer_background_get_sprite: [1, 1, "Asset.GMSprite", 2, 3],
    layer_background_get_stretch: [1, 1, "Bool", 2, 3],
    layer_background_get_visible: [1, 1, "Bool", 2, 3],
    layer_background_get_vtiled: [1, 1, "Bool", 2, 3],
    layer_background_get_xscale: [1, 1, "Real", 2, 3],
    layer_background_get_yscale: [1, 1, "Real", 2, 3],
    layer_background_htiled: [2, 2, "Undefined", 0, 3],
    layer_background_index: [2, 2, "Undefined", 0, 3],
    layer_background_speed: [2, 2, "Undefined", 0, 3],
    layer_background_sprite: [2, 2, "Undefined", 0, 3],
    layer_background_stretch: [2, 2, "Undefined", 0, 3],
    layer_background_visible: [2, 2, "Undefined", 0, 3],
    layer_background_vtiled: [2, 2, "Undefined", 0, 3],
    layer_background_xscale: [2, 2, "Undefined", 0, 3],
    layer_background_yscale: [2, 2, "Undefined", 0, 3],
    layer_clear_fx: [1, 1, "Undefined", 0, 3],
    layer_create: [1, 2, "Id.Layer", 0, 3],
    layer_depth: [2, 2, "Undefined", 0, 3],
    layer_destroy: [1, 1, "Undefined", 0, 3],
    layer_destroy_instances: [1, 1, "Undefined", 0, 3],
    layer_element_move: [2, 2, "Undefined", 0, 3],
    layer_enable_fx: [2, 2, "Undefined", 0, 3],
    layer_exists: [1, 1, "Bool", 2, 3],
    layer_force_draw_depth: [2, 2, "Undefined", 0, 3],
    layer_fx_is_enabled: [1, 1, "Bool", 0, 3],
    layer_get_all: [0, 0, "Array[Id.Layer]", 2, 3],
    layer_get_all_elements: [1, 1, "Array[Any]", 2, 3],
    layer_get_depth: [1, 1, "Real", 2, 3],
    layer_get_element_layer: [1, 1, "Id.Layer", 2, 3],
    layer_get_element_type: [1, 1, "Constant.LayerElementType", 2, 3],
    layer_get_flexpanel_node: [1, 1, "Pointer.FlexpanelNode", 2, 1],
    layer_get_forced_depth: [0, 0, "Real", 2, 3],
    layer_get_fx: [1, 1, "Struct.Fx", 2, 3],
    layer_get_hspeed: [1, 1, "Real", 2, 3],
    layer_get_id: [1, 1, "Id.Layer", 2, 3],
    layer_get_id_at_depth: [1, 1, "Array[Id.Layer]", 2, 3],
    layer_get_name: [1, 1, "String", 2, 3],
    layer_get_script_begin: [1, 1, "Function", 2, 3],
    layer_get_script_end: [1, 1, "Function", 2, 3],
    layer_get_shader: [1, 1, "Asset.GMShader", 2, 3],
    layer_get_target_room: [0, 0, "Asset.GMRoom", 2, 3],
    layer_get_type: [1, 1, "Constant.LayerType", 2, 1],
    layer_get_visible: [1, 1, "Bool", 2, 3],
    layer_get_vspeed: [1, 1, "Real", 2, 3],
    layer_get_x: [1, 1, "Real", 2, 3],
    layer_get_y: [1, 1, "Real", 2, 3],
    layer_has_instance: [2, 2, "Bool", 2, 3],
    layer_hspeed: [2, 2, "Undefined", 0, 3],
    layer_instance_get_instance: [1, 1, "Id.Instance", 2, 3],
    layer_is_draw_depth_forced: [0, 0, "Real", 2, 3],
    layer_particle_alpha: [2, 2, "Undefined", 0, 1],
    layer_particle_angle: [2, 2, "Undefined", 0, 1],
    layer_particle_blend: [2, 2, "Undefined", 0, 1],
    layer_particle_get_alpha: [1, 1, "Real", 0, 1],
    layer_particle_get_angle: [1, 1, "Real", 0, 1],
    layer_particle_get_blend: [1, 1, "Constant.Color", 0, 1],
    layer_particle_get_id: [2, 2, "Id.ParticleElement", 2, 1],
    layer_particle_get_instance: [1, 1, "Id.ParticleSystem", 2, 1],
    layer_particle_get_system: [1, 1, "Asset.GMParticleSystem", 2, 1],
    layer_particle_get_x: [1, 1, "Real", 0, 1],
    layer_particle_get_xscale: [1, 1, "Real", 2, 1],
    layer_particle_get_y: [1, 1, "Real", 0, 1],
    layer_particle_get_yscale: [1, 1, "Rela", 2, 1],
    layer_particle_x: [2, 2, "Undefined", 0, 1],
    layer_particle_xscale: [2, 2, "Undefined", 0, 1],
    layer_particle_y: [2, 2, "Undefined", 0, 1],
    layer_particle_yscale: [2, 2, "Undefined", 0, 1],
    layer_reset_target_room: [0, 0, "Undefined", 0, 3],
    layer_script_begin: [2, 2, "Undefined", 0, 3],
    layer_script_end: [2, 2, "Undefined", 0, 3],
    layer_sequence_alpha: [2, 2, "Undefined", 0, 1],
    layer_sequence_angle: [2, 2, "Undefined", 0, 3],
    layer_sequence_blend: [2, 2, "Undefined", 0, 1],
    layer_sequence_create: [4, 4, "Id.SequenceElement", 0, 3],
    layer_sequence_destroy: [1, 1, "Undefined", 0, 3],
    layer_sequence_exists: [2, 2, "Bool", 2, 3],
    layer_sequence_get_angle: [1, 1, "Real", 2, 3],
    layer_sequence_get_headdir: [1, 1, "Constant.SequenceDirection", 2, 3],
    layer_sequence_get_headpos: [1, 1, "Real", 2, 3],
    layer_sequence_get_instance: [1, 1, "Struct.SequenceInstance", 2, 3],
    layer_sequence_get_length: [1, 1, "Real", 2, 3],
    layer_sequence_get_sequence: [1, 1, "Struct.Sequence", 2, 3],
    layer_sequence_get_speedscale: [1, 1, "Real", 2, 3],
    layer_sequence_get_x: [1, 1, "Real", 2, 3],
    layer_sequence_get_xscale: [1, 1, "Real", 2, 3],
    layer_sequence_get_y: [1, 1, "Real", 2, 3],
    layer_sequence_get_yscale: [1, 1, "Real", 2, 3],
    layer_sequence_headdir: [2, 2, "Undefined", 0, 3],
    layer_sequence_headpos: [2, 2, "Undefined", 0, 3],
    layer_sequence_is_finished: [1, 1, "Bool", 2, 3],
    layer_sequence_is_paused: [1, 1, "Bool", 2, 3],
    layer_sequence_pause: [1, 1, "Undefined", 0, 3],
    layer_sequence_play: [1, 1, "Undefined", 0, 3],
    layer_sequence_speedscale: [2, 2, "Undefined", 0, 3],
    layer_sequence_x: [2, 2, "Undefined", 0, 3],
    layer_sequence_xscale: [2, 2, "Undefined", 0, 3],
    layer_sequence_y: [2, 2, "Undefined", 0, 3],
    layer_sequence_yscale: [2, 2, "Undefined", 0, 3],
    layer_set_fx: [2, 2, "Undefined", 0, 3],
    layer_set_target_room: [1, 1, "Undefined", 0, 3],
    layer_set_visible: [2, 2, "Undefined", 0, 3],
    layer_shader: [2, 2, "Undefined", 0, 3],
    layer_sprite_alpha: [2, 2, "Undefined", 0, 3],
    layer_sprite_angle: [2, 2, "Undefined", 0, 3],
    layer_sprite_blend: [2, 2, "Undefined", 0, 3],
    layer_sprite_change: [2, 2, "Undefined", 0, 3],
    layer_sprite_create: [4, 4, "Id.SpriteElement", 0, 3],
    layer_sprite_destroy: [1, 1, "Undefined", 0, 3],
    layer_sprite_exists: [2, 2, "Bool", 2, 3],
    layer_sprite_get_alpha: [1, 1, "Real", 2, 3],
    layer_sprite_get_angle: [1, 1, "Real", 2, 3],
    layer_sprite_get_blend: [1, 1, "Constant.Color", 2, 3],
    layer_sprite_get_id: [2, 2, "Id.SpriteElement", 2, 3],
    layer_sprite_get_index: [1, 1, "Real", 2, 3],
    layer_sprite_get_speed: [1, 1, "Real", 2, 3],
    layer_sprite_get_sprite: [1, 1, "Asset.GMSprite", 2, 3],
    layer_sprite_get_x: [1, 1, "Real", 2, 3],
    layer_sprite_get_xscale: [1, 1, "Real", 2, 3],
    layer_sprite_get_y: [1, 1, "Real", 2, 3],
    layer_sprite_get_yscale: [1, 1, "Real", 2, 3],
    layer_sprite_index: [2, 2, "Undefined", 0, 3],
    layer_sprite_speed: [2, 2, "Undefined", 0, 3],
    layer_sprite_x: [2, 2, "Undefined", 0, 3],
    layer_sprite_xscale: [2, 2, "Undefined", 0, 3],
    layer_sprite_y: [2, 2, "Undefined", 0, 3],
    layer_sprite_yscale: [2, 2, "Undefined", 0, 3],
    layer_text_alpha: [2, 2, "Undefined", 0, 1],
    layer_text_angle: [2, 2, "Undefined", 0, 1],
    layer_text_blend: [2, 2, "Undefined", 0, 1],
    layer_text_charspacing: [2, 2, "Undefined", 0, 1],
    layer_text_create: [5, 5, "Id.TextElement", 0, 1],
    layer_text_destroy: [1, 1, "Undefined", 0, 1],
    layer_text_exists: [2, 2, "Bool", 2, 1],
    layer_text_font: [2, 2, "Undefined", 0, 1],
    layer_text_frameh: [2, 2, "Undefined", 0, 1],
    layer_text_framew: [2, 2, "Undefined", 0, 1],
    layer_text_get_alpha: [1, 1, "Real", 2, 1],
    layer_text_get_angle: [1, 1, "Real", 2, 1],
    layer_text_get_blend: [1, 1, "Constant.Color", 2, 1],
    layer_text_get_charspacing: [1, 1, "Real", 2, 1],
    layer_text_get_font: [1, 1, "Asset.GMFont", 2, 1],
    layer_text_get_frameh: [1, 1, "Real", 2, 1],
    layer_text_get_framew: [1, 1, "Real", 2, 1],
    layer_text_get_halign: [1, 1, "Constant.TextAlign", 2, 1],
    layer_text_get_id: [2, 2, "Id.TextElement", 2, 1],
    layer_text_get_linespacing: [1, 1, "Real", 2, 1],
    layer_text_get_origin: [1, 1, "Constant.TextOrigin", 2, 1],
    layer_text_get_paragraphspacing: [1, 1, "Real", 2, 1],
    layer_text_get_text: [1, 1, "String", 2, 1],
    layer_text_get_valign: [1, 1, "Constant.TextAlign", 2, 1],
    layer_text_get_wrap: [1, 1, "Real", 2, 1],
    layer_text_get_wrapmode: [1, 1, "Constant.TextWrap", 2, 1],
    layer_text_get_x: [1, 1, "Real", 2, 1],
    layer_text_get_xorigin: [1, 1, "Real", 2, 1],
    layer_text_get_xscale: [1, 1, "Real", 2, 1],
    layer_text_get_y: [1, 1, "Real", 2, 1],
    layer_text_get_yorigin: [1, 1, "Real", 2, 1],
    layer_text_get_yscale: [1, 1, "Real", 2, 1],
    layer_text_halign: [2, 2, "Undefined", 0, 1],
    layer_text_linespacing: [2, 2, "Undefined", 0, 1],
    layer_text_origin: [2, 2, "Undefined", 0, 1],
    layer_text_paragraphspacing: [2, 2, "Undefined", 0, 1],
    layer_text_text: [2, 2, "Undefined", 0, 1],
    layer_text_valign: [2, 2, "Undefined", 0, 1],
    layer_text_wrap: [2, 2, "Undefined", 0, 1],
    layer_text_wrapmode: [2, 2, "Undefined", 0, 1],
    layer_text_x: [2, 2, "Undefined", 0, 1],
    layer_text_xorigin: [2, 2, "Undefined", 0, 1],
    layer_text_xscale: [2, 2, "Undefined", 0, 1],
    layer_text_y: [2, 2, "Undefined", 0, 1],
    layer_text_yorigin: [2, 2, "Undefined", 0, 1],
    layer_text_yscale: [2, 2, "Undefined", 0, 1],
    layer_tile_alpha: [2, 2, "Undefined", 1, 3],
    layer_tile_blend: [2, 2, "Undefined", 1, 3],
    layer_tile_change: [2, 2, "Undefined", 1, 3],
    layer_tile_create: [8, 8, "Id.TileElementId", 1, 3],
    layer_tile_destroy: [1, 1, "Undefined", 1, 3],
    layer_tile_exists: [2, 2, "Bool", 3, 3],
    layer_tile_get_alpha: [1, 1, "Real", 3, 3],
    layer_tile_get_blend: [1, 1, "Constant.Color", 3, 3],
    layer_tile_get_region: [1, 1, "Array[Real]", 3, 3],
    layer_tile_get_sprite: [1, 1, "Asset.GMSprite", 3, 3],
    layer_tile_get_visible: [1, 1, "Bool", 3, 3],
    layer_tile_get_x: [1, 1, "Real", 3, 3],
    layer_tile_get_xscale: [1, 1, "Real", 3, 3],
    layer_tile_get_y: [1, 1, "Real", 3, 3],
    layer_tile_get_yscale: [1, 1, "Real", 3, 3],
    layer_tile_region: [5, 5, "Undefined", 1, 3],
    layer_tile_visible: [2, 2, "Undefined", 1, 3],
    layer_tile_x: [2, 2, "Undefined", 1, 3],
    layer_tile_xscale: [2, 2, "Undefined", 1, 3],
    layer_tile_y: [2, 2, "Undefined", 1, 3],
    layer_tile_yscale: [2, 2, "Undefined", 1, 3],
    layer_tilemap_create: [6, 6, "Id.TileMapElement", 0, 3],
    layer_tilemap_destroy: [1, 1, "Undefined", 0, 3],
    layer_tilemap_exists: [2, 2, "Bool", 2, 3],
    layer_tilemap_get_colmask: [1, 1, "Asset.GMSprite", 2, 1],
    layer_tilemap_get_id: [1, 1, "Id.TileMapElement", 2, 3],
    layer_tilemap_set_colmask: [2, 2, "Real", 0, 1],
    layer_vspeed: [2, 2, "Undefined", 0, 3],
    layer_x: [2, 2, "Undefined", 0, 3],
    layer_y: [2, 2, "Undefined", 0, 3],
    lengthdir_x: [2, 2, "Real", 2, 3],
    lengthdir_y: [2, 2, "Real", 2, 3],
    lerp: [3, 3, "Real", 2, 3],
    lin_to_db: [1, 1, "Real", 2, 1],
    ln: [1, 1, "Real", 2, 3],
    load_csv: [1, 1, "Id.DsGrid", 2, 3],
    log10: [1, 1, "Real", 2, 3],
    log2: [1, 1, "Real", 2, 3],
    logn: [2, 2, "Real", 2, 3],
    mac_refresh_receipt_validation: [0, 0, "Undefined", 0, 1],
    make_color_hsv: [3, 3, "Constant.Color", 2, 3],
    make_color_rgb: [3, 3, "Constant.Color", 2, 3],
    make_colour_hsv: [3, 3, "Real", 2, 3],
    make_colour_rgb: [3, 3, "Real", 2, 3],
    math_get_epsilon: [0, 0, "Real", 2, 3],
    math_set_epsilon: [1, 1, "Real", 0, 3],
    matrix_build: [9, 10, "Array[Real]", 2, 3],
    matrix_build_identity: [0, 0, "Array[Real]", 2, 3],
    matrix_build_lookat: [9, 10, "Array[Real]", 2, 3],
    matrix_build_projection_ortho: [4, 5, "Array[Real]", 2, 3],
    matrix_build_projection_perspective: [4, 5, "Array[Real]", 2, 3],
    matrix_build_projection_perspective_fov: [4, 5, "Array[Real]", 2, 3],
    matrix_get: [1, 2, "Array[Real]", 2, 3],
    matrix_inverse: [1, 2, "Array[Real]", 0, 1],
    matrix_multiply: [2, 3, "Array[Real]", 0, 3],
    matrix_set: [2, 2, "Undefined", 0, 3],
    matrix_stack_clear: [0, 0, "Undefined", 0, 3],
    matrix_stack_is_empty: [0, 0, "Bool", 2, 3],
    matrix_stack_pop: [0, 0, "Undefined", 0, 3],
    matrix_stack_push: [1, 1, "Undefined", 0, 3],
    matrix_stack_set: [1, 1, "Undefined", 0, 3],
    matrix_stack_top: [0, 0, "Array[Real]", 2, 3],
    matrix_transform_vertex: [4, 6, "Array[Real]", 0, 3],
    max: [2, -1, "Real", 2, 3],
    md5_file: [1, 1, "String", 2, 3],
    md5_string_unicode: [1, 1, "String", 2, 3],
    md5_string_utf8: [1, 1, "String", 2, 3],
    mean: [2, -1, "Real", 2, 3],
    median: [2, -1, "Real", 2, 3],
    merge_color: [3, 3, "Constant.Color", 2, 3],
    merge_colour: [3, 3, "Real", 2, 3],
    method: [2, 2, "Function", 2, 3],
    method_call: [1, 4, "Any", 0, 1],
    method_get_index: [1, 1, "Asset.GMScript", 2, 3],
    method_get_self: [1, 1, "Struct,Id.Instance", 2, 3],
    min: [2, -1, "Real", 2, 3],
    motion_add: [2, 2, "Undefined", 0, 3],
    motion_set: [2, 2, "Undefined", 0, 3],
    mouse_check_button: [1, 1, "Bool", 2, 3],
    mouse_check_button_pressed: [1, 1, "Bool", 2, 3],
    mouse_check_button_released: [1, 1, "Bool", 2, 3],
    mouse_clear: [1, 1, "Bool", 0, 3],
    mouse_wheel_down: [0, 0, "Bool", 2, 3],
    mouse_wheel_up: [0, 0, "Bool", 2, 3],
    move_and_collide: [3, 8, "Array", 0, 3],
    move_bounce_all: [1, 1, "Undefined", 0, 3],
    move_bounce_solid: [1, 1, "Undefined", 0, 3],
    move_contact_all: [2, 2, "Undefined", 0, 3],
    move_contact_solid: [2, 2, "Undefined", 0, 3],
    move_outside_all: [2, 2, "Undefined", 0, 3],
    move_outside_solid: [2, 2, "Undefined", 0, 3],
    move_random: [2, 2, "Undefined", 0, 3],
    move_snap: [2, 2, "Undefined", 0, 3],
    move_towards_point: [3, 3, "Undefined", 0, 3],
    move_wrap: [3, 3, "Undefined", 0, 3],
    mp_grid_add_cell: [3, 3, "Undefined", 0, 3],
    mp_grid_add_instances: [3, 3, "Undefined", 0, 3],
    mp_grid_add_rectangle: [5, 5, "Undefined", 0, 3],
    mp_grid_clear_all: [1, 1, "Bool", 0, 3],
    mp_grid_clear_cell: [3, 3, "Bool", 0, 3],
    mp_grid_clear_rectangle: [5, 5, "Bool", 0, 3],
    mp_grid_create: [6, 6, "Id.MpGrid", 0, 3],
    mp_grid_destroy: [1, 1, "Undefined", 0, 3],
    mp_grid_draw: [1, 1, "Bool", 0, 3],
    mp_grid_get_cell: [3, 3, "Real", 2, 3],
    mp_grid_path: [7, 7, "Bool", 0, 3],
    mp_grid_to_ds_grid: [2, 2, "Bool", 0, 3],
    mp_linear_path: [5, 5, "Bool", 0, 3],
    mp_linear_path_object: [5, 5, "Bool", 0, 3],
    mp_linear_step: [4, 4, "Bool", 0, 3],
    mp_linear_step_object: [4, 4, "Bool", 0, 3],
    mp_potential_path: [6, 6, "Bool", 0, 3],
    mp_potential_path_object: [6, 6, "Bool", 0, 3],
    mp_potential_settings: [4, 4, "Undefined", 0, 3],
    mp_potential_step: [4, 4, "Bool", 0, 3],
    mp_potential_step_object: [4, 4, "Bool", 0, 3],
    nameof: [1, 1, "String", 2, 1],
    network_connect: [3, 3, "Real", 0, 3],
    network_connect_async: [3, 3, "Real", 0, 3],
    network_connect_raw: [3, 3, "Real", 0, 3],
    network_connect_raw_async: [3, 3, "Real", 0, 3],
    network_create_server: [3, 3, "Real", 0, 3],
    network_create_server_raw: [3, 3, "Real", 0, 3],
    network_create_socket: [1, 1, "Id.Socket", 0, 3],
    network_create_socket_ext: [2, 2, "Id.Socket", 0, 3],
    network_destroy: [1, 1, "Undefined", 0, 3],
    network_resolve: [1, 1, "String", 2, 3],
    network_send_broadcast: [4, 4, "Real", 0, 3],
    network_send_packet: [3, 3, "Real", 0, 3],
    network_send_raw: [3, 4, "Real", 0, 3],
    network_send_udp: [5, 5, "Real", 0, 3],
    network_send_udp_raw: [5, 5, "Real", 0, 3],
    network_set_config: [2, 3, "String", 0, 3],
    network_set_timeout: [3, 3, "Undefined", 0, 3],
    object_exists: [1, 1, "Bool", 2, 3],
    object_get_mask: [1, 1, "Asset.GMSprite", 2, 3],
    object_get_name: [1, 1, "String", 2, 3],
    object_get_parent: [1, 1, "Asset.GMObject", 2, 3],
    object_get_persistent: [1, 1, "Bool", 2, 3],
    object_get_physics: [1, 1, "Bool", 2, 3],
    object_get_solid: [1, 1, "Bool", 2, 3],
    object_get_sprite: [1, 1, "Asset.GMSprite", 2, 3],
    object_get_visible: [1, 1, "Bool", 2, 3],
    object_is_ancestor: [2, 2, "Bool", 2, 3],
    object_set_mask: [2, 2, "Undefined", 0, 3],
    object_set_persistent: [2, 2, "Undefined", 0, 3],
    object_set_solid: [2, 2, "Undefined", 0, 3],
    object_set_sprite: [2, 2, "Undefined", 0, 3],
    object_set_visible: [2, 2, "Undefined", 0, 3],
    ord: [1, 1, "Real", 2, 3],
    os_check_permission: [1, 1, "Real", 0, 3],
    os_get_config: [0, 0, "String", 2, 3],
    os_get_info: [0, 0, "Id.DsMap", 2, 3],
    os_get_language: [0, 0, "String", 2, 3],
    os_get_region: [0, 0, "String", 2, 3],
    os_is_network_connected: [0, 1, "Bool", 2, 3],
    os_is_paused: [0, 0, "Bool", 2, 3],
    os_lock_orientation: [1, 1, "Undefined", 0, 3],
    os_powersave_enable: [1, 1, "Undefined", 0, 3],
    os_request_permission: [1, -1, "Undefined", 0, 3],
    os_set_orientation_lock: [2, 2, "Undefined", 0, 3],
    parameter_count: [0, 0, "Real", 2, 3],
    parameter_string: [1, 1, "String", 2, 3],
    part_emitter_burst: [4, 4, "Undefined", 0, 3],
    part_emitter_clear: [2, 2, "Undefined", 0, 3],
    part_emitter_create: [1, 1, "Id.ParticleEmitter", 0, 3],
    part_emitter_delay: [5, 5, "Undefined", 0, 1],
    part_emitter_destroy: [2, 2, "Undefined", 0, 3],
    part_emitter_destroy_all: [1, 1, "Undefined", 0, 3],
    part_emitter_enable: [3, 3, "Undefined", 0, 1],
    part_emitter_exists: [2, 2, "Bool", 2, 3],
    part_emitter_interval: [5, 5, "Undefined", 0, 1],
    part_emitter_region: [8, 8, "Undefined", 0, 3],
    part_emitter_relative: [3, 3, "Undefined", 0, 1],
    part_emitter_stream: [4, 4, "Undefined", 0, 3],
    part_particles_burst: [4, 4, "Undefined", 0, 1],
    part_particles_clear: [1, 1, "Undefined", 0, 3],
    part_particles_count: [1, 1, "Real", 2, 3],
    part_particles_create: [5, 5, "Undefined", 0, 3],
    part_particles_create_color: [6, 6, "Undefined", 0, 3],
    part_particles_create_colour: [6, 6, "Undefined", 0, 3],
    part_system_angle: [2, 2, "Undefined", 0, 1],
    part_system_automatic_draw: [2, 2, "Undefined", 0, 3],
    part_system_automatic_update: [2, 2, "Undefined", 0, 3],
    part_system_clear: [1, 1, "Undefined", 0, 3],
    part_system_color: [3, 3, "Undefined", 0, 1],
    part_system_colour: [3, 3, "Undefined", 0, 1],
    part_system_create: [0, 1, "Id.ParticleSystem", 0, 3],
    part_system_create_layer: [2, 3, "Id.ParticleSystem", 0, 3],
    part_system_depth: [2, 2, "Undefined", 0, 3],
    part_system_destroy: [1, 1, "Undefined", 0, 3],
    part_system_draw_order: [2, 2, "Undefined", 0, 3],
    part_system_drawit: [1, 1, "Undefined", 0, 3],
    part_system_exists: [1, 1, "Bool", 2, 3],
    part_system_get_info: [1, 1, "Struct", 2, 1],
    part_system_get_layer: [1, 1, "Id.Layer", 2, 3],
    part_system_global_space: [2, 2, "Undefined", 0, 1],
    part_system_layer: [2, 2, "Undefined", 0, 3],
    part_system_position: [3, 3, "Undefined", 0, 3],
    part_system_update: [1, 1, "Undefined", 0, 3],
    part_type_alpha1: [2, 2, "Undefined", 0, 3],
    part_type_alpha2: [3, 3, "Undefined", 0, 3],
    part_type_alpha3: [4, 4, "Undefined", 0, 3],
    part_type_blend: [2, 2, "Undefined", 0, 3],
    part_type_clear: [1, 1, "Undefined", 0, 3],
    part_type_color1: [2, 2, "Undefined", 0, 3],
    part_type_color2: [3, 3, "Undefined", 0, 3],
    part_type_color3: [4, 4, "Undefined", 0, 3],
    part_type_color_hsv: [7, 7, "Undefined", 0, 3],
    part_type_color_mix: [3, 3, "Undefined", 0, 3],
    part_type_color_rgb: [7, 7, "Undefined", 0, 3],
    part_type_colour1: [2, 2, "Undefined", 0, 3],
    part_type_colour2: [3, 3, "Undefined", 0, 3],
    part_type_colour3: [4, 4, "Undefined", 0, 3],
    part_type_colour_hsv: [7, 7, "Undefined", 0, 3],
    part_type_colour_mix: [3, 3, "Undefined", 0, 3],
    part_type_colour_rgb: [7, 7, "Undefined", 0, 3],
    part_type_create: [0, 0, "Id.ParticleType", 0, 3],
    part_type_death: [3, 3, "Undefined", 0, 3],
    part_type_destroy: [1, 1, "Undefined", 0, 3],
    part_type_direction: [5, 5, "Undefined", 0, 3],
    part_type_exists: [1, 1, "Bool", 2, 3],
    part_type_gravity: [3, 3, "Undefined", 0, 3],
    part_type_life: [3, 3, "Undefined", 0, 3],
    part_type_orientation: [6, 6, "Undefined", 0, 3],
    part_type_scale: [3, 3, "Undefined", 0, 3],
    part_type_shape: [2, 2, "Undefined", 0, 3],
    part_type_size: [5, 5, "Undefined", 0, 3],
    part_type_size_x: [5, 5, "Undefined", 0, 1],
    part_type_size_y: [5, 5, "Undefined", 0, 1],
    part_type_speed: [5, 5, "Undefined", 0, 3],
    part_type_sprite: [5, 5, "Undefined", 0, 3],
    part_type_step: [3, 3, "Undefined", 0, 3],
    part_type_subimage: [2, 2, "Undefined", 0, 1],
    particle_add: [1, 1, "Asset.GMParticleSystem", 0, 1],
    particle_delete: [1, 1, "Undefined", 0, 1],
    particle_exists: [1, 1, "Bool", 2, 1],
    particle_get_info: [1, 1, "Struct", 2, 1],
    path_add: [0, 0, "Asset.GMPath", 0, 3],
    path_add_point: [4, 4, "Undefined", 0, 3],
    path_append: [2, 2, "Undefined", 0, 3],
    path_assign: [2, 2, "Undefined", 0, 3],
    path_change_point: [5, 5, "Undefined", 0, 3],
    path_clear_points: [1, 1, "Undefined", 0, 3],
    path_delete: [1, 1, "Undefined", 0, 3],
    path_delete_point: [2, 2, "Undefined", 0, 3],
    path_duplicate: [1, 1, "Asset.GMPath", 0, 3],
    path_end: [0, 0, "Undefined", 0, 3],
    path_exists: [1, 1, "Bool", 2, 3],
    path_flip: [1, 1, "Undefined", 0, 3],
    path_get_closed: [1, 1, "Bool", 2, 3],
    path_get_kind: [1, 1, "Bool", 2, 3],
    path_get_length: [1, 1, "Real", 2, 3],
    path_get_name: [1, 1, "String", 2, 3],
    path_get_number: [1, 1, "Real", 2, 3],
    path_get_point_speed: [2, 2, "Real", 2, 3],
    path_get_point_x: [2, 2, "Real", 2, 3],
    path_get_point_y: [2, 2, "Real", 2, 3],
    path_get_precision: [1, 1, "Real", 2, 3],
    path_get_speed: [2, 2, "Real", 2, 3],
    path_get_x: [2, 2, "Real", 2, 3],
    path_get_y: [2, 2, "Real", 2, 3],
    path_insert_point: [5, 5, "Undefined", 0, 3],
    path_mirror: [1, 1, "Undefined", 0, 3],
    path_rescale: [3, 3, "Undefined", 0, 3],
    path_reverse: [1, 1, "Undefined", 0, 3],
    path_rotate: [2, 2, "Undefined", 0, 3],
    path_set_closed: [2, 2, "Undefined", 0, 3],
    path_set_kind: [2, 2, "Undefined", 0, 3],
    path_set_precision: [2, 2, "Undefined", 0, 3],
    path_shift: [3, 3, "Undefined", 0, 3],
    path_start: [4, 4, "Undefined", 0, 3],
    physics_apply_angular_impulse: [1, 1, "Undefined", 0, 3],
    physics_apply_force: [4, 4, "Undefined", 0, 3],
    physics_apply_impulse: [4, 4, "Undefined", 0, 3],
    physics_apply_local_force: [4, 4, "Undefined", 0, 3],
    physics_apply_local_impulse: [4, 4, "Undefined", 0, 3],
    physics_apply_torque: [1, 1, "Undefined", 0, 3],
    physics_debug: [1, 1, "Undefined", 0, 1],
    physics_draw_debug: [0, 0, "Undefined", 0, 3],
    physics_fixture_add_point: [3, 3, "Undefined", 0, 3],
    physics_fixture_bind: [2, 2, "Id.PhysicsFixtureBound", 0, 3],
    physics_fixture_bind_ext: [4, 4, "Id.PhysicsFixtureBound", 0, 3],
    physics_fixture_create: [0, 0, "Id.PhysicsFixture", 0, 3],
    physics_fixture_delete: [1, 1, "Undefined", 0, 3],
    physics_fixture_set_angular_damping: [2, 2, "Undefined", 0, 3],
    physics_fixture_set_awake: [2, 2, "Undefined", 0, 3],
    physics_fixture_set_box_shape: [3, 3, "Undefined", 0, 3],
    physics_fixture_set_chain_shape: [2, 2, "Undefined", 0, 3],
    physics_fixture_set_circle_shape: [2, 2, "Undefined", 0, 3],
    physics_fixture_set_collision_group: [2, 2, "Undefined", 0, 3],
    physics_fixture_set_density: [2, 2, "Undefined", 0, 3],
    physics_fixture_set_edge_shape: [5, 5, "Undefined", 0, 3],
    physics_fixture_set_friction: [2, 2, "Undefined", 0, 3],
    physics_fixture_set_kinematic: [1, 1, "Undefined", 0, 3],
    physics_fixture_set_linear_damping: [2, 2, "Undefined", 0, 3],
    physics_fixture_set_polygon_shape: [1, 1, "Undefined", 0, 3],
    physics_fixture_set_restitution: [2, 2, "Undefined", 0, 3],
    physics_fixture_set_sensor: [2, 2, "Undefined", 0, 3],
    physics_get_density: [1, 1, "Real", 2, 3],
    physics_get_friction: [1, 1, "Real", 2, 3],
    physics_get_restitution: [1, 1, "Real", 2, 3],
    physics_joint_delete: [1, 1, "Undefined", 0, 3],
    physics_joint_distance_create: [7, 7, "Id.PhysicsJoint", 0, 3],
    physics_joint_enable_motor: [2, 2, "Undefined", 0, 3],
    physics_joint_friction_create: [7, 7, "Id.PhysicsJoint", 0, 3],
    physics_joint_gear_create: [5, 5, "Id.PhysicsJoint", 0, 3],
    physics_joint_get_value: [2, 2, "Real", 2, 3],
    physics_joint_prismatic_create: [13, 13, "Id.PhysicsJoint", 0, 3],
    physics_joint_pulley_create: [12, 12, "Id.PhysicsJoint", 0, 3],
    physics_joint_revolute_create: [11, 11, "Id.PhysicsJoint", 0, 3],
    physics_joint_rope_create: [8, 8, "Id.PhysicsJoint", 0, 3],
    physics_joint_set_value: [3, 3, "Undefined", 0, 3],
    physics_joint_weld_create: [8, 8, "Id.PhysicsJoint", 0, 3],
    physics_joint_wheel_create: [12, 12, "Id.PhysicsJoint", 0, 3],
    physics_mass_properties: [4, 4, "Undefined", 0, 3],
    physics_particle_count: [0, 0, "Real", 2, 3],
    physics_particle_create: [8, 8, "Id.PhysicsParticle", 0, 3],
    physics_particle_delete: [1, 1, "Undefined", 0, 3],
    physics_particle_delete_region_box: [4, 4, "Undefined", 0, 3],
    physics_particle_delete_region_circle: [3, 3, "Undefined", 0, 3],
    physics_particle_delete_region_poly: [1, 1, "Undefined", 0, 3],
    physics_particle_draw: [4, 4, "Undefined", 0, 3],
    physics_particle_draw_ext: [9, 9, "Undefined", 0, 3],
    physics_particle_get_damping: [0, 0, "Real", 2, 3],
    physics_particle_get_data: [2, 2, "Id.Buffer", 2, 3],
    physics_particle_get_data_particle: [3, 3, "Id.Buffer", 2, 3],
    physics_particle_get_density: [0, 0, "Real", 2, 3],
    physics_particle_get_gravity_scale: [0, 0, "Real", 2, 3],
    physics_particle_get_group_flags: [1, 1, "Real", 2, 3],
    physics_particle_get_max_count: [0, 0, "Real", 2, 3],
    physics_particle_get_radius: [0, 0, "Real", 2, 3],
    physics_particle_group_add_point: [2, 2, "Undefined", 0, 3],
    physics_particle_group_begin: [12, 12, "Undefined", 0, 3],
    physics_particle_group_box: [2, 2, "Undefined", 0, 3],
    physics_particle_group_circle: [1, 1, "Undefined", 0, 3],
    physics_particle_group_count: [1, 1, "Real", 2, 3],
    physics_particle_group_delete: [1, 1, "Undefined", 0, 3],
    physics_particle_group_end: [0, 0, "Id.PhysicsParticleGroup", 0, 3],
    physics_particle_group_get_ang_vel: [1, 1, "Real", 2, 3],
    physics_particle_group_get_angle: [1, 1, "Real", 2, 3],
    physics_particle_group_get_centre_x: [1, 1, "Real", 2, 3],
    physics_particle_group_get_centre_y: [1, 1, "Real", 2, 3],
    physics_particle_group_get_data: [3, 3, "Id.Buffer", 2, 3],
    physics_particle_group_get_inertia: [1, 1, "Real", 2, 3],
    physics_particle_group_get_mass: [1, 1, "Real", 2, 3],
    physics_particle_group_get_vel_x: [1, 1, "Real", 2, 3],
    physics_particle_group_get_vel_y: [1, 1, "Real", 2, 3],
    physics_particle_group_get_x: [1, 1, "Real", 2, 3],
    physics_particle_group_get_y: [1, 1, "Real", 2, 3],
    physics_particle_group_join: [2, 2, "Undefined", 0, 3],
    physics_particle_group_polygon: [0, 0, "Undefined", 0, 3],
    physics_particle_set_category_flags: [2, 2, "Undefined", 0, 3],
    physics_particle_set_damping: [1, 1, "Undefined", 0, 3],
    physics_particle_set_density: [1, 1, "Undefined", 0, 3],
    physics_particle_set_flags: [2, 2, "Real", 0, 3],
    physics_particle_set_gravity_scale: [1, 1, "Undefined", 0, 3],
    physics_particle_set_group_flags: [2, 2, "Undefined", 0, 3],
    physics_particle_set_max_count: [1, 1, "Undefined", 0, 3],
    physics_particle_set_radius: [1, 1, "Undefined", 0, 3],
    physics_pause_enable: [1, 1, "Undefined", 0, 3],
    physics_raycast: [5, 7, "Array", 0, 1],
    physics_remove_fixture: [2, 2, "Undefined", 0, 3],
    physics_set_density: [2, 2, "Undefined", 0, 3],
    physics_set_friction: [2, 2, "Undefined", 0, 3],
    physics_set_restitution: [2, 2, "Undefined", 0, 3],
    physics_test_overlap: [4, 4, "Bool", 2, 3],
    physics_world_create: [1, 1, "Undefined", 0, 3],
    physics_world_draw_debug: [1, 1, "Undefined", 0, 3],
    physics_world_gravity: [2, 2, "Undefined", 0, 3],
    physics_world_update_iterations: [1, 1, "Undefined", 0, 3],
    physics_world_update_speed: [1, 1, "Undefined", 0, 3],
    place_empty: [2, 3, "Bool", 2, 3],
    place_free: [2, 2, "Bool", 2, 3],
    place_meeting: [3, 3, "Bool", 2, 3],
    place_snapped: [2, 2, "Bool", 2, 3],
    point_direction: [4, 4, "Real", 2, 3],
    point_distance: [4, 4, "Real", 2, 3],
    point_distance_3d: [6, 6, "Real", 2, 3],
    point_in_circle: [5, 5, "Bool", 2, 3],
    point_in_rectangle: [6, 6, "Bool", 2, 3],
    point_in_triangle: [8, 8, "Bool", 2, 3],
    position_change: [4, 4, "Undefined", 1, 3],
    position_destroy: [2, 2, "Undefined", 0, 3],
    position_empty: [2, 2, "Bool", 2, 3],
    position_meeting: [3, 3, "Bool", 2, 3],
    power: [2, 2, "Real", 2, 3],
    ptr: [1, 1, "Pointer", 2, 3],
    push_cancel_local_notification: [1, 1, "Real", 1, 3],
    push_get_application_badge_number: [0, 0, "Real", 3, 3],
    push_get_first_local_notification: [1, 1, "Real", 3, 3],
    push_get_next_local_notification: [1, 1, "Real", 3, 3],
    push_local_notification: [4, 4, "Undefined", 1, 3],
    push_set_application_badge_number: [1, 1, "Undefined", 1, 3],
    radtodeg: [1, 1, "Real", 2, 3],
    random: [1, 1, "Real", 2, 3],
    random_get_seed: [0, 0, "Real", 2, 3],
    random_range: [2, 2, "Real", 2, 3],
    random_set_seed: [1, 2, "Undefined", 0, 3],
    randomise: [0, 0, "Real", 0, 3],
    randomize: [0, 0, "Undefined", 0, 3],
    real: [1, 1, "Real", 2, 3],
    rectangle_in_circle: [7, 7, "Real", 2, 3],
    rectangle_in_rectangle: [8, 8, "Real", 2, 3],
    rectangle_in_triangle: [10, 10, "Real", 2, 3],
    ref_create: [2, 3, "Id.DbgRef", 0, 1],
    rollback_chat: [1, 2, "Undefined", 0, 3],
    rollback_create_game: [1, 3, "Undefined", 0, 3],
    rollback_define_extra_network_latency: [1, 1, "Undefined", 0, 3],
    rollback_define_input: [1, 1, "Undefined", 0, 3],
    rollback_define_input_frame_delay: [1, 1, "Undefined", 0, 3],
    rollback_define_mock_input: [2, 2, "Undefined", 0, 3],
    rollback_define_player: [1, 2, "Undefined", 0, 3],
    rollback_display_events: [1, 1, "Undefined", 0, 3],
    rollback_get_info: [0, 1, "Struct", 2, 3],
    rollback_get_input: [0, 1, "Struct", 2, 3],
    rollback_get_player_prefs: [0, 1, "Any", 2, 3],
    rollback_join_game: [0, 1, "Bool", 0, 3],
    rollback_leave_game: [0, 0, "Undefined", 0, 3],
    rollback_set_player_prefs: [1, 1, "Undefined", 0, 3],
    rollback_start_game: [0, 0, "Undefined", 0, 3],
    rollback_sync_on_frame: [0, 0, "Bool", 0, 3],
    rollback_use_late_join: [0, 0, "Any", 0, 1],
    rollback_use_manual_start: [0, 0, "Undefined", 0, 3],
    rollback_use_player_prefs: [0, 1, "Undefined", 0, 3],
    rollback_use_random_input: [1, 1, "Undefined", 0, 3],
    room_add: [0, 0, "Asset.GMRoom", 0, 3],
    room_assign: [2, 2, "Undefined", 0, 3],
    room_duplicate: [1, 1, "Asset.GMRoom", 0, 3],
    room_exists: [1, 1, "Bool", 2, 3],
    room_get_camera: [2, 2, "Id.Camera", 2, 3],
    room_get_info: [1, 7, "Struct", 2, 1],
    room_get_name: [1, 1, "String", 2, 3],
    room_get_viewport: [2, 2, "Array[Real]", 2, 3],
    room_goto: [1, 1, "Undefined", 0, 3],
    room_goto_next: [0, 0, "Undefined", 0, 3],
    room_goto_previous: [0, 0, "Undefined", 0, 3],
    room_instance_add: [4, 4, "Id.Instance", 2, 3],
    room_instance_clear: [1, 1, "Undefined", 0, 3],
    room_next: [1, 1, "Asset.GMRoom", 0, 3],
    room_previous: [1, 1, "Asset.GMRoom", 0, 3],
    room_restart: [0, 0, "Undefined", 0, 3],
    room_set_background_color: [3, 3, "Undefined", 1, 3],
    room_set_background_colour: [3, 3, "Undefined", 1, 3],
    room_set_camera: [3, 3, "Undefined", 0, 3],
    room_set_height: [2, 2, "Undefined", 0, 3],
    room_set_persistent: [2, 2, "Undefined", 0, 3],
    room_set_view_enabled: [2, 2, "Undefined", 0, 3],
    room_set_viewport: [7, 7, "Undefined", 0, 3],
    room_set_width: [2, 2, "Undefined", 0, 3],
    round: [1, 1, "Real", 2, 3],
    scheduler_resolution_get: [0, 0, "Real", 2, 3],
    scheduler_resolution_set: [1, 1, "Undefined", 0, 3],
    screen_save: [1, 1, "Undefined", 0, 3],
    screen_save_part: [5, 5, "Undefined", 0, 3],
    script_execute: [1, -1, "Any", 0, 3],
    script_execute_ext: [1, 4, "Any", 0, 3],
    script_exists: [1, 1, "Bool", 2, 3],
    script_get_name: [1, 1, "String", 2, 3],
    sequence_create: [0, 0, "Struct.Sequence", 0, 3],
    sequence_destroy: [1, 1, "Undefined", 0, 3],
    sequence_exists: [1, 1, "Bool", 2, 3],
    sequence_get: [1, 1, "Struct.Sequence", 2, 3],
    sequence_get_objects: [1, 1, "Array[Asset.GMObject]", 2, 3],
    sequence_instance_override_object: [3, 3, "Undefined", 0, 3],
    sequence_keyframe_new: [1, 1, "Struct.Keyframe", 2, 3],
    sequence_keyframedata_new: [1, 1, "Struct", 2, 3],
    sequence_track_new: [1, 1, "Struct.Track", 2, 3],
    sha1_file: [1, 1, "String", 2, 3],
    sha1_string_unicode: [1, 1, "String", 2, 3],
    sha1_string_utf8: [1, 1, "String", 2, 3],
    shader_current: [0, 0, "Asset.GMShader", 2, 3],
    shader_enable_corner_id: [1, 1, "Undefined", 0, 3],
    shader_get_name: [1, 1, "String", 2, 3],
    shader_get_sampler_index: [2, 2, "Id.Sampler", 2, 3],
    shader_get_uniform: [2, 2, "Id.Uniform", 2, 3],
    shader_is_compiled: [1, 1, "Bool", 2, 3],
    shader_reset: [0, 0, "Undefined", 0, 3],
    shader_set: [1, 1, "Undefined", 0, 3],
    shader_set_uniform_f: [2, 5, "Undefined", 0, 3],
    shader_set_uniform_f_array: [2, 2, "Undefined", 0, 3],
    shader_set_uniform_f_buffer: [4, 4, "Undefined", 0, 1],
    shader_set_uniform_i: [2, 5, "Undefined", 0, 3],
    shader_set_uniform_i_array: [2, 2, "Undefined", 0, 3],
    shader_set_uniform_matrix: [1, 1, "Undefined", 0, 3],
    shader_set_uniform_matrix_array: [2, 2, "Undefined", 0, 3],
    shaders_are_supported: [0, 0, "Bool", 2, 3],
    shop_leave_rating: [4, 4, "Undefined", 0, 3],
    show_debug_log: [1, 1, "Undefined", 0, 1],
    show_debug_message: [1, -1, "Undefined", 0, 3],
    show_debug_message_ext: [2, -1, "Undefined", 0, 1],
    show_debug_overlay: [1, 6, "Undefined", 0, 3],
    show_error: [2, 2, "Undefined", 0, 3],
    show_message: [1, 1, "Undefined", 0, 3],
    show_message_async: [1, 1, "Real", 0, 3],
    show_question: [1, 1, "Bool", 2, 3],
    show_question_async: [1, 1, "Real", 0, 3],
    sign: [1, 1, "Real", 2, 3],
    sin: [1, 1, "Real", 2, 3],
    skeleton_animation_clear: [1, 3, "Undefined", 0, 3],
    skeleton_animation_get: [0, 0, "String", 2, 3],
    skeleton_animation_get_duration: [1, 1, "Real", 2, 3],
    skeleton_animation_get_event_frames: [2, 2, "Array[Real]", 2, 3],
    skeleton_animation_get_ext: [1, 1, "String", 2, 3],
    skeleton_animation_get_frame: [1, 1, "Real", 2, 3],
    skeleton_animation_get_frames: [1, 1, "Real", 2, 3],
    skeleton_animation_get_position: [1, 1, "Real", 2, 3],
    skeleton_animation_is_finished: [1, 1, "Bool", 2, 3],
    skeleton_animation_is_looping: [1, 1, "Bool", 2, 3],
    skeleton_animation_list: [2, 2, "Undefined", 0, 3],
    skeleton_animation_mix: [3, 3, "Undefined", 0, 3],
    skeleton_animation_set: [1, 2, "Undefined", 0, 3],
    skeleton_animation_set_ext: [2, 3, "Undefined", 0, 3],
    skeleton_animation_set_frame: [2, 2, "Undefined", 0, 3],
    skeleton_animation_set_position: [2, 2, "Undefined", 0, 3],
    skeleton_attachment_create: [8, 8, "Any", 0, 3],
    skeleton_attachment_create_color: [10, 10, "Undefined", 0, 3],
    skeleton_attachment_create_colour: [10, 10, "Any", 0, 3],
    skeleton_attachment_destroy: [1, 1, "Any", 0, 1],
    skeleton_attachment_exists: [1, 1, "Bool", 2, 1],
    skeleton_attachment_get: [1, 1, "String", 2, 3],
    skeleton_attachment_replace: [8, 8, "Any", 2, 1],
    skeleton_attachment_replace_color: [10, 10, "Any", 2, 1],
    skeleton_attachment_replace_colour: [10, 10, "Any", 2, 1],
    skeleton_attachment_set: [2, 2, "String", 0, 3],
    skeleton_bone_data_get: [2, 2, "Undefined", 0, 3],
    skeleton_bone_data_set: [2, 2, "Undefined", 0, 3],
    skeleton_bone_list: [2, 2, "Undefined", 0, 3],
    skeleton_bone_state_get: [2, 2, "Undefined", 0, 3],
    skeleton_bone_state_set: [2, 2, "Undefined", 0, 3],
    skeleton_collision_draw_set: [1, 1, "Undefined", 0, 3],
    skeleton_find_slot: [3, 3, "Undefined", 0, 3],
    skeleton_get_bounds: [1, 1, "Array[Real]", 2, 3],
    skeleton_get_minmax: [0, 0, "Array[Real]", 2, 3],
    skeleton_get_num_bounds: [0, 0, "Real", 2, 3],
    skeleton_skin_create: [2, 2, "Struct.SkeletonSkin", 0, 3],
    skeleton_skin_get: [0, 0, "String", 2, 3],
    skeleton_skin_list: [2, 2, "Undefined", 0, 3],
    skeleton_skin_set: [1, 1, "Undefined", 0, 3],
    skeleton_slot_alpha_get: [1, 1, "Real", 2, 3],
    skeleton_slot_color_get: [1, 1, "Real", 2, 3],
    skeleton_slot_color_set: [3, 3, "Undefined", 0, 3],
    skeleton_slot_colour_get: [1, 1, "Real", 2, 3],
    skeleton_slot_colour_set: [3, 3, "Undefined", 0, 3],
    skeleton_slot_data: [2, 2, "Undefined", 0, 3],
    skeleton_slot_data_instance: [1, 1, "Undefined", 0, 3],
    skeleton_slot_list: [2, 2, "Undefined", 0, 3],
    sphere_is_visible: [4, 4, "Bool", 2, 1],
    sprite_add: [6, 6, "Asset.GMSprite", 0, 3],
    sprite_add_ext: [5, 5, "Asset.GMSprite", 0, 1],
    sprite_add_from_surface: [8, 8, "Undefined", 0, 3],
    sprite_assign: [2, 2, "Undefined", 0, 3],
    sprite_collision_mask: [9, 9, "Undefined", 0, 3],
    sprite_create_from_surface: [9, 9, "Asset.GMSprite", 0, 3],
    sprite_delete: [1, 1, "Bool", 0, 3],
    sprite_duplicate: [1, 1, "Asset.GMSprite", 0, 3],
    sprite_exists: [1, 1, "Bool", 2, 3],
    sprite_flush: [1, 1, "Real", 0, 3],
    sprite_flush_multi: [1, 1, "Real", 0, 3],
    sprite_get_bbox_bottom: [1, 1, "Real", 2, 3],
    sprite_get_bbox_left: [1, 1, "Real", 2, 3],
    sprite_get_bbox_mode: [1, 1, "Constant.BBoxMode", 2, 3],
    sprite_get_bbox_right: [1, 1, "Real", 2, 3],
    sprite_get_bbox_top: [1, 1, "Real", 2, 3],
    sprite_get_convex_hull: [1, 3, "Array[Real]", 2, 1],
    sprite_get_height: [1, 1, "Real", 2, 3],
    sprite_get_info: [1, 1, "Struct.SpriteInfo", 2, 3],
    sprite_get_name: [1, 1, "String", 2, 3],
    sprite_get_nineslice: [1, 1, "Struct", 2, 3],
    sprite_get_number: [1, 1, "Real", 2, 3],
    sprite_get_speed: [1, 1, "Real", 2, 3],
    sprite_get_speed_type: [1, 1, "Constant.SpriteSpeed", 2, 3],
    sprite_get_texture: [2, 2, "Pointer.Texture", 2, 3],
    sprite_get_tpe: [2, 2, "Real", 2, 3],
    sprite_get_uvs: [2, 2, "Array[Real]", 2, 3],
    sprite_get_width: [1, 1, "Real", 2, 3],
    sprite_get_xoffset: [1, 1, "Real", 2, 3],
    sprite_get_yoffset: [1, 1, "Real", 2, 3],
    sprite_merge: [2, 2, "Undefined", 0, 3],
    sprite_nineslice_create: [0, 0, "Struct", 0, 3],
    sprite_prefetch: [1, 1, "Real", 0, 3],
    sprite_prefetch_multi: [1, 1, "Real", 0, 3],
    sprite_replace: [7, 7, "Undefined", 0, 3],
    sprite_save: [3, 3, "Undefined", 0, 3],
    sprite_save_strip: [2, 2, "Undefined", 0, 3],
    sprite_set_alpha_from_sprite: [2, 2, "Undefined", 0, 3],
    sprite_set_bbox: [5, 5, "Undefined", 0, 3],
    sprite_set_bbox_mode: [2, 2, "Undefined", 0, 3],
    sprite_set_cache_size: [2, 2, "Undefined", 0, 3],
    sprite_set_cache_size_ext: [3, 3, "Undefined", 0, 3],
    sprite_set_nineslice: [2, 2, "Undefined", 0, 3],
    sprite_set_offset: [3, 3, "Undefined", 0, 3],
    sprite_set_speed: [3, 3, "Undefined", 0, 3],
    sqr: [1, 1, "Real", 2, 3],
    sqrt: [1, 1, "Real", 2, 3],
    static_get: [1, 1, "Struct", 2, 1],
    static_set: [2, 2, "Undefined", 0, 1],
    string: [1, -1, "String", 2, 3],
    string_byte_at: [2, 2, "Real", 2, 3],
    string_byte_length: [1, 1, "Real", 2, 3],
    string_char_at: [2, 2, "String", 2, 3],
    string_concat: [1, -1, "String", 2, 3],
    string_concat_ext: [1, 3, "String", 2, 3],
    string_copy: [3, 3, "String", 2, 3],
    string_count: [2, 2, "Real", 2, 3],
    string_delete: [3, 3, "String", 2, 3],
    string_digits: [1, 1, "String", 2, 3],
    string_ends_with: [2, 2, "Bool", 2, 3],
    string_ext: [2, 2, "String", 2, 3],
    string_foreach: [2, 4, "Undefined", 0, 3],
    string_format: [3, 3, "String", 2, 3],
    string_hash_to_newline: [1, 1, "String", 2, 3],
    string_height: [1, 1, "Real", 2, 3],
    string_height_ext: [3, 3, "Real", 2, 3],
    string_insert: [3, 3, "String", 2, 3],
    string_join: [2, -1, "String", 2, 3],
    string_join_ext: [2, 4, "String", 2, 3],
    string_last_pos: [2, 2, "Real", 2, 3],
    string_last_pos_ext: [3, 3, "Real", 2, 3],
    string_length: [1, 1, "Real", 2, 3],
    string_letters: [1, 1, "String", 2, 3],
    string_lettersdigits: [1, 1, "String", 2, 3],
    string_lower: [1, 1, "String", 2, 3],
    string_ord_at: [2, 2, "Real", 2, 3],
    string_pos: [2, 2, "Real", 2, 3],
    string_pos_ext: [3, 3, "Real", 2, 3],
    string_repeat: [2, 2, "String", 2, 3],
    string_replace: [3, 3, "String", 2, 3],
    string_replace_all: [3, 3, "String", 2, 3],
    string_set_byte_at: [3, 3, "String", 0, 3],
    string_split: [2, 4, "Array[String]", 2, 3],
    string_split_ext: [2, 4, "Array[String]", 2, 3],
    string_starts_with: [2, 2, "Bool", 2, 3],
    string_trim: [1, 2, "String", 2, 3],
    string_trim_end: [1, 2, "String", 2, 3],
    string_trim_start: [1, 2, "String", 2, 3],
    string_upper: [1, 1, "String", 2, 3],
    string_width: [1, 1, "Real", 2, 3],
    string_width_ext: [3, 3, "Real", 2, 3],
    struct_exists: [2, 2, "Bool", 2, 1],
    struct_exists_from_hash: [2, 2, "Bool", 2, 1],
    struct_foreach: [2, 2, "Undefined", 0, 1],
    struct_get: [2, 2, "Any", 2, 1],
    struct_get_from_hash: [2, 2, "Any", 2, 1],
    struct_get_names: [1, 1, "Array[String]", 2, 1],
    struct_names_count: [1, 1, "Real", 2, 1],
    struct_remove: [2, 2, "Undefined", 0, 1],
    struct_remove_from_hash: [2, 2, "Undefined", 0, 1],
    struct_set: [3, 3, "Undefined", 0, 1],
    struct_set_from_hash: [3, 3, "Undefined", 0, 1],
    surface_copy: [4, 4, "Undefined", 0, 3],
    surface_copy_part: [8, 8, "Undefined", 0, 3],
    surface_create: [2, 3, "Id.Surface", 0, 3],
    surface_create_ext: [3, 3, "Id.Surface", 0, 3],
    surface_depth_disable: [1, 1, "Undefined", 0, 3],
    surface_exists: [1, 1, "Bool", 2, 3],
    surface_format_is_supported: [0, 1, "Bool", 2, 1],
    surface_free: [1, 1, "Undefined", 0, 3],
    surface_get_depth_disable: [0, 0, "Bool", 2, 3],
    surface_get_format: [1, 1, "Constant.SurfaceFormatType", 2, 1],
    surface_get_height: [1, 1, "Real", 2, 3],
    surface_get_target: [0, 0, "Id.Surface", 2, 3],
    surface_get_target_depth: [0, 0, "Id.Surface", 2, 1],
    surface_get_target_ext: [1, 1, "Id.Surface", 2, 3],
    surface_get_texture: [1, 1, "Pointer.Texture", 2, 3],
    surface_get_texture_depth: [1, 1, "Pointer.Texture", 2, 1],
    surface_get_width: [1, 1, "Real", 2, 3],
    surface_getpixel: [3, 3, "Real", 2, 3],
    surface_getpixel_ext: [3, 3, "Real", 2, 3],
    surface_has_depth: [1, 1, "Bool", 2, 1],
    surface_reset_target: [0, 0, "Undefined", 0, 3],
    surface_resize: [3, 3, "Undefined", 0, 3],
    surface_save: [2, 2, "Undefined", 0, 3],
    surface_save_part: [6, 6, "Undefined", 0, 3],
    surface_set_target: [1, 2, "Bool", 0, 3],
    surface_set_target_ext: [2, 2, "Bool", 0, 3],
    tag_get_asset_ids: [2, 2, "Array[Asset]", 2, 3],
    tag_get_assets: [1, 1, "Array[String]", 2, 3],
    tan: [1, 1, "Real", 2, 3],
    texture_debug_messages: [1, 1, "Undefined", 0, 3],
    texture_flush: [1, 1, "Undefined", 0, 3],
    texture_get_height: [1, 1, "Real", 2, 3],
    texture_get_texel_height: [1, 1, "Real", 2, 3],
    texture_get_texel_width: [1, 1, "Real", 2, 3],
    texture_get_uvs: [1, 1, "Array[Real]", 2, 3],
    texture_get_width: [1, 1, "Real", 2, 3],
    texture_global_scale: [1, 1, "Undefined", 0, 3],
    texture_is_ready: [1, 1, "Bool", 2, 3],
    texture_prefetch: [1, 1, "Undefined", 0, 3],
    texture_set_stage: [2, 2, "Undefined", 0, 3],
    texturegroup_add: [3, 3, "Undefined", 0, 1],
    texturegroup_delete: [1, 1, "Bool", 0, 1],
    texturegroup_exists: [1, 1, "Bool", 2, 1],
    texturegroup_get_fonts: [1, 1, "Array[Asset.GMFont]", 2, 3],
    texturegroup_get_names: [0, 0, "Array[String]", 2, 1],
    texturegroup_get_sprites: [1, 1, "Array[Asset.GMSprite]", 2, 3],
    texturegroup_get_status: [1, 1, "Real", 2, 3],
    texturegroup_get_textures: [1, 1, "Array[Id.Texture]", 2, 3],
    texturegroup_get_tilesets: [1, 1, "Array[Asset.GMTileSet]", 2, 3],
    texturegroup_load: [1, 2, "Undefined", 0, 3],
    texturegroup_set_mode: [1, 3, "Undefined", 0, 3],
    texturegroup_unload: [1, 1, "Undefined", 0, 3],
    tile_get_empty: [1, 1, "Bool", 2, 3],
    tile_get_flip: [1, 1, "Bool", 2, 3],
    tile_get_index: [1, 1, "Real", 2, 3],
    tile_get_mirror: [1, 1, "Bool", 2, 3],
    tile_get_rotate: [1, 1, "Bool", 2, 3],
    tile_set_empty: [1, 1, "Real", 0, 3],
    tile_set_flip: [2, 2, "Real", 0, 3],
    tile_set_index: [2, 2, "Real", 0, 3],
    tile_set_mirror: [2, 2, "Real", 0, 3],
    tile_set_rotate: [2, 2, "Real", 0, 3],
    tilemap_clear: [2, 2, "Undefined", 0, 3],
    tilemap_get: [3, 3, "Real", 2, 3],
    tilemap_get_at_pixel: [3, 3, "Real", 2, 3],
    tilemap_get_cell_x_at_pixel: [3, 3, "Real", 2, 3],
    tilemap_get_cell_y_at_pixel: [3, 3, "Real", 2, 3],
    tilemap_get_frame: [1, 1, "Real", 2, 3],
    tilemap_get_global_mask: [0, 0, "Real", 2, 3],
    tilemap_get_height: [1, 1, "Real", 2, 3],
    tilemap_get_mask: [1, 1, "Real", 2, 3],
    tilemap_get_tile_height: [1, 1, "Real", 2, 3],
    tilemap_get_tile_width: [1, 1, "Real", 2, 3],
    tilemap_get_tileset: [1, 1, "Asset.GMTileSet", 2, 3],
    tilemap_get_width: [1, 1, "Real", 2, 3],
    tilemap_get_x: [1, 1, "Real", 2, 3],
    tilemap_get_y: [1, 1, "Real", 2, 3],
    tilemap_set: [4, 4, "Bool", 0, 3],
    tilemap_set_at_pixel: [4, 4, "Bool", 0, 3],
    tilemap_set_global_mask: [1, 1, "Undefined", 0, 3],
    tilemap_set_height: [2, 2, "Undefined", 0, 3],
    tilemap_set_mask: [2, 2, "Undefined", 0, 3],
    tilemap_set_width: [2, 2, "Undefined", 0, 3],
    tilemap_tileset: [2, 2, "Undefined", 0, 3],
    tilemap_x: [2, 2, "Undefined", 0, 3],
    tilemap_y: [2, 2, "Undefined", 0, 3],
    tileset_get_info: [1, 1, "Struct.TileSetInfo", 2, 1],
    tileset_get_name: [1, 1, "String", 2, 3],
    tileset_get_texture: [1, 1, "Pointer.Texture", 2, 3],
    tileset_get_uvs: [1, 1, "Array[Real]", 2, 3],
    time_bpm_to_seconds: [1, 1, "Real", 2, 3],
    time_seconds_to_bpm: [1, 1, "Real", 2, 3],
    time_source_create: [4, 7, "Id.TimeSource", 0, 3],
    time_source_destroy: [1, 2, "Undefined", 0, 3],
    time_source_exists: [1, 1, "Bool", 2, 3],
    time_source_get_children: [1, 1, "Array[Id.TimeSource]", 2, 3],
    time_source_get_parent: [1, 1, "Id.TimeSource", 2, 3],
    time_source_get_period: [1, 1, "Real", 2, 3],
    time_source_get_reps_completed: [1, 1, "Real", 2, 3],
    time_source_get_reps_remaining: [1, 1, "Real", 2, 3],
    time_source_get_state: [1, 1, "Constant.TimeSourceState", 2, 3],
    time_source_get_time_remaining: [1, 1, "Real", 2, 3],
    time_source_get_units: [1, 1, "Constant.TimeSourceUnits", 2, 3],
    time_source_pause: [1, 1, "Undefined", 0, 3],
    time_source_reconfigure: [4, 7, "Undefined", 0, 3],
    time_source_reset: [1, 1, "Undefined", 0, 3],
    time_source_resume: [1, 1, "Undefined", 0, 3],
    time_source_start: [1, 1, "Undefined", 0, 3],
    time_source_stop: [1, 1, "Undefined", 0, 3],
    timeline_add: [0, 0, "Asset.GMTimeline", 0, 3],
    timeline_clear: [1, 1, "Undefined", 0, 3],
    timeline_delete: [1, 1, "Undefined", 0, 3],
    timeline_exists: [1, 1, "Bool", 2, 3],
    timeline_get_name: [1, 1, "String", 2, 3],
    timeline_max_moment: [1, 1, "Real", 2, 3],
    timeline_moment_add_script: [3, 3, "Undefined", 0, 3],
    timeline_moment_clear: [2, 2, "Undefined", 0, 3],
    timeline_size: [1, 1, "Real", 2, 3],
    typeof: [1, 1, "String", 2, 3],
    url_get_domain: [0, 0, "String", 2, 3],
    url_open: [1, 1, "Undefined", 0, 3],
    url_open_ext: [2, 2, "Undefined", 0, 3],
    url_open_full: [3, 3, "Undefined", 0, 3],
    uwp_appbar_add_element: [7, 7, "Undefined", 1, 3],
    uwp_appbar_enable: [1, 1, "Undefined", 1, 3],
    uwp_appbar_remove_element: [1, 1, "Undefined", 1, 3],
    uwp_device_touchscreen_available: [0, 0, "Undefined", 3, 3],
    uwp_livetile_badge_clear: [0, 0, "Undefined", 1, 3],
    uwp_livetile_badge_notification: [1, 1, "Undefined", 1, 3],
    uwp_livetile_notification_begin: [1, 1, "Undefined", 1, 3],
    uwp_livetile_notification_end: [0, 0, "Undefined", 1, 3],
    uwp_livetile_notification_expiry: [1, 1, "Undefined", 3, 3],
    uwp_livetile_notification_image_add: [1, 1, "Undefined", 1, 3],
    uwp_livetile_notification_secondary_begin: [2, 2, "Undefined", 1, 3],
    uwp_livetile_notification_tag: [1, 1, "Undefined", 1, 3],
    uwp_livetile_notification_template_add: [1, 1, "Undefined", 1, 3],
    uwp_livetile_notification_text_add: [1, 1, "Undefined", 1, 3],
    uwp_livetile_queue_enable: [0, 1, "Undefined", 1, 3],
    uwp_livetile_tile_clear: [0, 0, "Undefined", 1, 3],
    uwp_secondarytile_badge_clear: [1, 1, "Undefined", 1, 3],
    uwp_secondarytile_badge_notification: [2, 2, "Undefined", 1, 3],
    uwp_secondarytile_delete: [1, 1, "Undefined", 1, 3],
    uwp_secondarytile_pin: [8, 8, "Undefined", 1, 3],
    uwp_secondarytile_tile_clear: [1, 1, "Undefined", 1, 3],
    variable_clone: [1, 2, "Any", 2, 1],
    variable_get_hash: [1, 1, "Real", 2, 1],
    variable_global_exists: [1, 1, "Bool", 2, 3],
    variable_global_get: [1, 1, "Any", 2, 3],
    variable_global_set: [2, 2, "Undefined", 0, 3],
    variable_instance_exists: [2, 2, "Bool", 2, 3],
    variable_instance_get: [2, 2, "Any", 2, 3],
    variable_instance_get_names: [1, 1, "Array[String]", 2, 3],
    variable_instance_names_count: [1, 1, "Real", 2, 3],
    variable_instance_set: [3, 3, "Undefined", 0, 3],
    variable_struct_exists: [2, 2, "Bool", 2, 3],
    variable_struct_get: [2, 2, "Any", 2, 3],
    variable_struct_get_names: [1, 1, "Array[String]", 2, 3],
    variable_struct_names_count: [1, 1, "Real", 2, 3],
    variable_struct_remove: [2, 2, "Undefined", 0, 3],
    variable_struct_set: [3, 3, "Undefined", 0, 3],
    vector_sprite_cache_get_limit: [0, 0, "Real", 2, 1],
    vector_sprite_cache_get_max_used: [0, 0, "Real", 2, 1],
    vector_sprite_cache_get_oldest_entry_age: [0, 0, "Real", 2, 1],
    vector_sprite_cache_get_prune_age: [0, 0, "Real", 2, 1],
    vector_sprite_cache_get_prune_fraction: [0, 0, "Real", 2, 1],
    vector_sprite_cache_get_used: [0, 0, "Real", 2, 1],
    vector_sprite_cache_limit: [1, 1, "Undefined", 0, 1],
    vector_sprite_cache_prune_age: [1, 1, "Undefined", 0, 1],
    vector_sprite_cache_prune_fraction: [1, 1, "Undefined", 0, 1],
    vertex_argb: [2, 2, "Undefined", 0, 3],
    vertex_begin: [2, 2, "Undefined", 0, 3],
    vertex_buffer_exists: [1, 1, "Bool", 2, 1],
    vertex_color: [3, 3, "Undefined", 0, 3],
    vertex_colour: [3, 3, "Undefined", 0, 3],
    vertex_create_buffer: [0, 0, "Id.VertexBuffer", 0, 3],
    vertex_create_buffer_ext: [1, 1, "Id.VertexBuffer", 0, 3],
    vertex_create_buffer_from_buffer: [2, 2, "Id.VertexBuffer", 0, 3],
    vertex_create_buffer_from_buffer_ext: [4, 4, "Id.VertexBuffer", 0, 3],
    vertex_delete_buffer: [1, 1, "Undefined", 0, 3],
    vertex_end: [1, 1, "Undefined", 0, 3],
    vertex_float1: [2, 2, "Undefined", 0, 3],
    vertex_float2: [3, 3, "Undefined", 0, 3],
    vertex_float3: [4, 4, "Undefined", 0, 3],
    vertex_float4: [5, 5, "Undefined", 0, 3],
    vertex_format_add_color: [0, 0, "Undefined", 0, 3],
    vertex_format_add_colour: [0, 0, "Undefined", 0, 3],
    vertex_format_add_custom: [2, 2, "Undefined", 0, 3],
    vertex_format_add_normal: [0, 0, "Undefined", 0, 3],
    vertex_format_add_position: [0, 0, "Undefined", 0, 3],
    vertex_format_add_position_3d: [0, 0, "Undefined", 0, 3],
    vertex_format_add_texcoord: [0, 0, "Undefined", 0, 3],
    vertex_format_add_textcoord: [0, 0, "Undefined", 3, 3],
    vertex_format_begin: [0, 0, "Undefined", 0, 3],
    vertex_format_delete: [1, 1, "Undefined", 0, 3],
    vertex_format_end: [0, 0, "Id.VertexFormat", 0, 3],
    vertex_format_exists: [1, 1, "Bool", 0, 1],
    vertex_format_get_info: [1, 1, "Struct.VertexFormatInfo", 2, 1],
    vertex_freeze: [1, 1, "Undefined", 0, 3],
    vertex_get_buffer_size: [1, 1, "Real", 2, 3],
    vertex_get_number: [1, 1, "Real", 2, 3],
    vertex_normal: [4, 4, "Undefined", 0, 3],
    vertex_position: [3, 3, "Undefined", 0, 3],
    vertex_position_3d: [4, 4, "Undefined", 0, 3],
    vertex_submit: [3, 3, "Undefined", 0, 3],
    vertex_submit_ext: [5, 5, "Undefined", 0, 1],
    vertex_texcoord: [3, 3, "Undefined", 0, 3],
    vertex_ubyte4: [5, 5, "Undefined", 0, 3],
    vertex_update_buffer_from_buffer: [3, 5, "Undefined", 0, 1],
    vertex_update_buffer_from_vertex: [3, 5, "Undefined", 0, 1],
    video_close: [0, 0, "Undefined", 0, 3],
    video_draw: [0, 0, "Array[Real]", 0, 3],
    video_enable_loop: [1, 1, "Undefined", 0, 3],
    video_get_duration: [0, 0, "Real", 2, 3],
    video_get_format: [0, 0, "Constant.VideoFormat", 2, 3],
    video_get_position: [0, 0, "Real", 2, 3],
    video_get_status: [0, 0, "Constant.VideoStatus", 2, 3],
    video_get_volume: [0, 0, "Real", 2, 3],
    video_is_looping: [0, 0, "Bool", 2, 3],
    video_open: [1, 1, "Undefined", 0, 3],
    video_pause: [0, 0, "Undefined", 0, 3],
    video_resume: [0, 0, "Undefined", 0, 3],
    video_seek_to: [1, 1, "Undefined", 0, 3],
    video_set_volume: [1, 1, "Undefined", 0, 3],
    view_get_camera: [1, 1, "Real", 2, 3],
    view_get_hport: [1, 1, "Real", 2, 3],
    view_get_surface_id: [1, 1, "Id.Surface", 2, 3],
    view_get_visible: [1, 1, "Bool", 2, 3],
    view_get_wport: [1, 1, "Real", 2, 3],
    view_get_xport: [1, 1, "Real", 2, 3],
    view_get_yport: [1, 1, "Real", 2, 3],
    view_set_camera: [2, 2, "Undefined", 0, 3],
    view_set_hport: [2, 2, "Real", 0, 3],
    view_set_surface_id: [2, 2, "Undefined", 0, 3],
    view_set_visible: [2, 2, "Undefined", 0, 3],
    view_set_wport: [2, 2, "Real", 0, 3],
    view_set_xport: [2, 2, "Undefined", 0, 3],
    view_set_yport: [2, 2, "Undefined", 0, 3],
    virtual_key_add: [5, 5, "Real", 0, 3],
    virtual_key_delete: [1, 1, "Undefined", 0, 3],
    virtual_key_hide: [1, 1, "Undefined", 0, 3],
    virtual_key_show: [1, 1, "Undefined", 0, 3],
    wallpaper_set_config: [1, 1, "Undefined", 0, 1],
    wallpaper_set_subscriptions: [1, 1, "Undefined", 0, 1],
    weak_ref_alive: [1, 1, "Bool", 2, 3],
    weak_ref_any_alive: [1, 3, "Bool", 2, 3],
    weak_ref_create: [1, 1, "Struct.WeakRef", 0, 3],
    win8_appbar_add_element: [6, 6, "Undefined", 1, 3],
    win8_appbar_enable: [1, 1, "Undefined", 1, 3],
    win8_appbar_remove_element: [1, 1, "Undefined", 1, 3],
    win8_device_touchscreen_available: [0, 0, "Undefined", 3, 3],
    win8_license_initialize_sandbox: [1, 1, "Undefined", 1, 3],
    win8_license_trial_version: [0, 0, "Undefined", 3, 3],
    win8_livetile_badge_clear: [0, 0, "Undefined", 1, 3],
    win8_livetile_badge_notification: [1, 1, "Undefined", 1, 3],
    win8_livetile_notification_begin: [1, 1, "Undefined", 1, 3],
    win8_livetile_notification_end: [0, 0, "Undefined", 1, 3],
    win8_livetile_notification_expiry: [1, 1, "Undefined", 3, 3],
    win8_livetile_notification_image_add: [1, 1, "Undefined", 1, 3],
    win8_livetile_notification_secondary_begin: [2, 2, "Undefined", 1, 3],
    win8_livetile_notification_tag: [1, 1, "Undefined", 1, 3],
    win8_livetile_notification_text_add: [1, 1, "Undefined", 1, 3],
    win8_livetile_queue_enable: [1, 1, "Undefined", 1, 3],
    win8_livetile_tile_clear: [0, 0, "Undefined", 1, 3],
    win8_livetile_tile_notification: [4, 4, "Undefined", 1, 3],
    win8_search_add_suggestions: [1, 1, "Undefined", 1, 3],
    win8_search_disable: [0, 0, "Undefined", 1, 3],
    win8_search_enable: [1, 1, "Undefined", 1, 3],
    win8_secondarytile_badge_notification: [2, 2, "Undefined", 1, 3],
    win8_secondarytile_delete: [1, 1, "Undefined", 1, 3],
    win8_secondarytile_pin: [8, 8, "Undefined", 1, 3],
    win8_settingscharm_add_entry: [2, 2, "Undefined", 1, 3],
    win8_settingscharm_add_html_entry: [3, 3, "Undefined", 1, 3],
    win8_settingscharm_add_xaml_entry: [5, 5, "Undefined", 1, 3],
    win8_settingscharm_get_xaml_property: [3, 3, "Undefined", 3, 3],
    win8_settingscharm_remove_entry: [1, 1, "Undefined", 1, 3],
    win8_settingscharm_set_xaml_property: [4, 4, "Undefined", 1, 3],
    win8_share_file: [4, 4, "Undefined", 1, 3],
    win8_share_image: [4, 4, "Undefined", 1, 3],
    win8_share_screenshot: [3, 3, "Undefined", 1, 3],
    win8_share_text: [4, 4, "Undefined", 1, 3],
    win8_share_url: [4, 4, "Undefined", 1, 3],
    window_center: [0, 0, "Undefined", 0, 3],
    window_device: [0, 0, "Pointer", 3, 3],
    window_enable_borderless_fullscreen: [1, 1, "Undefined", 0, 1],
    window_get_borderless_fullscreen: [0, 0, "Undefined", 2, 1],
    window_get_caption: [0, 0, "String", 2, 3],
    window_get_color: [0, 0, "Constant.Color", 2, 3],
    window_get_colour: [0, 0, "Constant.Color", 2, 3],
    window_get_cursor: [0, 0, "Constant.Cursor", 2, 3],
    window_get_fullscreen: [0, 0, "Bool", 2, 3],
    window_get_height: [0, 0, "Real", 2, 3],
    window_get_showborder: [0, 0, "Bool", 2, 1],
    window_get_visible_rects: [4, 4, "Array[Real]", 2, 3],
    window_get_width: [0, 0, "Real", 2, 3],
    window_get_x: [0, 0, "Real", 2, 3],
    window_get_y: [0, 0, "Real", 2, 3],
    window_handle: [0, 0, "Pointer", 2, 3],
    window_has_focus: [0, 0, "Bool", 2, 3],
    window_minimise: [0, 0, "Undefined", 2, 1],
    window_minimize: [0, 0, "Undefined", 2, 1],
    window_mouse_get_delta_x: [0, 0, "Real", 2, 1],
    window_mouse_get_delta_y: [0, 0, "Real", 2, 1],
    window_mouse_get_locked: [0, 0, "Bool", 2, 1],
    window_mouse_get_x: [0, 0, "Real", 2, 3],
    window_mouse_get_y: [0, 0, "Real", 2, 3],
    window_mouse_set: [2, 2, "Undefined", 0, 3],
    window_mouse_set_locked: [1, 1, "Undefined", 0, 1],
    window_post_message: [1, 1, "Undefined", 0, 1],
    window_restore: [0, 0, "Undefined", 2, 1],
    window_set_caption: [1, 1, "Undefined", 0, 3],
    window_set_color: [1, 1, "Undefined", 0, 3],
    window_set_colour: [1, 1, "Undefined", 0, 3],
    window_set_cursor: [1, 1, "Undefined", 0, 3],
    window_set_fullscreen: [1, 1, "Undefined", 0, 3],
    window_set_max_height: [1, 1, "Undefined", 0, 3],
    window_set_max_width: [1, 1, "Undefined", 0, 3],
    window_set_min_height: [1, 1, "Undefined", 0, 3],
    window_set_min_width: [1, 1, "Undefined", 0, 3],
    window_set_position: [2, 2, "Undefined", 0, 3],
    window_set_rectangle: [4, 4, "Undefined", 0, 3],
    window_set_showborder: [1, 1, "Undefined", 0, 1],
    window_set_size: [2, 2, "Undefined", 0, 3],
    window_view_mouse_get_x: [1, 1, "Real", 2, 3],
    window_view_mouse_get_y: [1, 1, "Real", 2, 3],
    window_views_mouse_get_x: [0, 0, "Real", 2, 3],
    window_views_mouse_get_y: [0, 0, "Real", 2, 3],
    winphone_license_trial_version: [0, 0, "Undefined", 3, 3],
    winphone_tile_back_content: [1, 1, "Undefined", 1, 3],
    winphone_tile_back_content_wide: [1, 1, "Undefined", 1, 3],
    winphone_tile_back_image: [1, 1, "Undefined", 1, 3],
    winphone_tile_back_image_wide: [1, 1, "Undefined", 1, 3],
    winphone_tile_back_title: [1, 1, "Undefined", 1, 3],
    winphone_tile_background_color: [1, 1, "Undefined", 1, 3],
    winphone_tile_background_colour: [1, 1, "Undefined", 1, 3],
    winphone_tile_count: [1, 1, "Undefined", 1, 3],
    winphone_tile_cycle_images: [0, 2, "Undefined", 1, 3],
    winphone_tile_front_image: [1, 1, "Undefined", 1, 3],
    winphone_tile_front_image_small: [1, 1, "Undefined", 1, 3],
    winphone_tile_front_image_wide: [1, 1, "Undefined", 1, 3],
    winphone_tile_icon_image: [1, 1, "Undefined", 1, 3],
    winphone_tile_small_background_image: [1, 1, "Undefined", 3, 3],
    winphone_tile_small_icon_image: [1, 1, "Undefined", 1, 3],
    winphone_tile_title: [1, 1, "Undefined", 1, 3],
    winphone_tile_wide_content: [2, 2, "Undefined", 1, 3],
    zip_add_file: [3, 3, "Real", 0, 1],
    zip_create: [0, 0, "Struct.Zip", 0, 1],
    zip_save: [0, 2, "Real", 0, 1],
    zip_unzip: [2, 2, "Real", 2, 3],
    zip_unzip_async: [2, 2, "Real", 2, 1]
  },
  variables: {
    ANSI_CHARSET: ["Any", 1, 3],
    ARABIC_CHARSET: ["Any", 1, 3],
    BALTIC_CHARSET: ["Any", 1, 3],
    CHINESEBIG5_CHARSET: ["Any", 1, 3],
    DEFAULT_CHARSET: ["Any", 1, 3],
    EASTEUROPE_CHARSET: ["Any", 1, 3],
    GB2312_CHARSET: ["Any", 1, 3],
    GREEK_CHARSET: ["Any", 1, 3],
    HANGEUL_CHARSET: ["Any", 1, 3],
    HEBREW_CHARSET: ["Any", 1, 3],
    JOHAB_CHARSET: ["Any", 1, 3],
    MAC_CHARSET: ["Any", 1, 3],
    OEM_CHARSET: ["Any", 1, 3],
    RUSSIAN_CHARSET: ["Any", 1, 3],
    SHIFTJIS_CHARSET: ["Any", 1, 3],
    SYMBOL_CHARSET: ["Any", 1, 3],
    THAI_CHARSET: ["Any", 1, 3],
    TURKISH_CHARSET: ["Any", 1, 3],
    VIETNAMESE_CHARSET: ["Any", 1, 3],
    achievement_achievement_info: ["Any", 1, 3],
    achievement_filter_all_players: ["Any", 1, 3],
    achievement_filter_favorites_only: ["Any", 1, 3],
    achievement_filter_friends_only: ["Any", 1, 3],
    achievement_friends_info: ["Any", 1, 3],
    achievement_leaderboard_info: ["Any", 1, 3],
    achievement_our_info: ["Any", 1, 3],
    achievement_pic_loaded: ["Any", 1, 3],
    achievement_show_achievement: ["Any", 1, 3],
    achievement_show_bank: ["Any", 1, 3],
    achievement_show_friend_picker: ["Any", 1, 3],
    achievement_show_leaderboard: ["Any", 1, 3],
    achievement_show_profile: ["Any", 1, 3],
    achievement_show_purchase_prompt: ["Any", 1, 3],
    achievement_show_ui: ["Any", 1, 3],
    achievement_type_achievement_challenge: ["Any", 1, 3],
    achievement_type_score_challenge: ["Any", 1, 3],
    alarm: ["Array[Real]", 4, 3],
    application_surface: ["Id.Surface", 2, 3],
    argument: ["ArgumentIdentity", 0, 3],
    argument0: ["ArgumentIdentity", 0, 3],
    argument1: ["ArgumentIdentity", 0, 3],
    argument10: ["ArgumentIdentity", 0, 3],
    argument11: ["ArgumentIdentity", 0, 3],
    argument12: ["ArgumentIdentity", 0, 3],
    argument13: ["ArgumentIdentity", 0, 3],
    argument14: ["ArgumentIdentity", 0, 3],
    argument15: ["ArgumentIdentity", 0, 3],
    argument2: ["ArgumentIdentity", 0, 3],
    argument3: ["ArgumentIdentity", 0, 3],
    argument4: ["ArgumentIdentity", 0, 3],
    argument5: ["ArgumentIdentity", 0, 3],
    argument6: ["ArgumentIdentity", 0, 3],
    argument7: ["ArgumentIdentity", 0, 3],
    argument8: ["ArgumentIdentity", 0, 3],
    argument9: ["ArgumentIdentity", 0, 3],
    argument_count: ["Real", 2, 3],
    argument_relative: ["Real", 3, 3],
    async_load: ["Id.DsMap", 2, 3],
    background_color: ["Constant.Color", 1, 3],
    background_colour: ["Constant.Color", 1, 3],
    background_showcolor: ["Bool", 1, 3],
    background_showcolour: ["Real", 1, 3],
    bbox_bottom: ["Real", 6, 3],
    bbox_left: ["Real", 6, 3],
    bbox_right: ["Real", 6, 3],
    bbox_top: ["Real", 6, 3],
    bm_complex: ["Any", 1, 3],
    browser_height: ["Real", 2, 3],
    browser_width: ["Real", 2, 3],
    buffer_surface_copy: ["Any", 1, 3],
    button_type: ["Any", 1, 3],
    cache_directory: ["String", 2, 1],
    caption_health: ["String", 1, 3],
    caption_lives: ["String", 1, 3],
    caption_score: ["String", 1, 3],
    collision_space: ["colspace", 6, 1],
    current_day: ["Real", 2, 3],
    current_hour: ["Real", 2, 3],
    current_minute: ["Real", 2, 3],
    current_month: ["Real", 2, 3],
    current_second: ["Real", 2, 3],
    current_time: ["Real", 2, 3],
    current_weekday: ["Real", 2, 3],
    current_year: ["Real", 2, 3],
    cursor_sprite: ["Asset.GMSprite", 0, 3],
    debug_mode: ["Bool", 2, 3],
    delta_time: ["Real", 2, 3],
    depth: ["Real", 4, 3],
    direction: ["Real", 4, 3],
    display_aa: ["Real", 2, 3],
    drawn_by_sequence: ["Bool", 4, 3],
    error_last: ["Bool", 1, 3],
    error_occurred: ["Bool", 1, 3],
    ev_close_button: ["Any", 1, 3],
    event_action: ["Real", 3, 3],
    event_data: ["Id.DsMap", 2, 3],
    event_number: ["Constant.EventNumber", 6, 3],
    event_object: ["Asset.GMObject", 6, 3],
    event_type: ["Constant.EventType", 6, 3],
    font_texture_page_size: ["Real", 0, 3],
    fps: ["Real", 2, 3],
    fps_real: ["Real", 2, 3],
    friction: ["Real", 4, 3],
    game_display_name: ["String", 2, 3],
    game_id: ["Real", 3, 3],
    game_project_name: ["String", 2, 3],
    game_save_id: ["String", 2, 3],
    gamemaker_pro: ["Bool", 3, 3],
    gamemaker_registered: ["Bool", 3, 3],
    gamemaker_version: ["Any", 1, 3],
    gravity: ["Real", 4, 3],
    gravity_direction: ["Real", 4, 3],
    health: ["Real", 1, 3],
    hspeed: ["Real", 4, 3],
    iap_data: ["Undefined", 3, 3],
    id: ["Id.Instance", 6, 3],
    image_alpha: ["Real", 4, 3],
    image_angle: ["Real", 4, 3],
    image_blend: ["Constant.Color", 4, 3],
    image_index: ["Real", 4, 3],
    image_number: ["Real", 6, 3],
    image_speed: ["Real", 4, 3],
    image_xscale: ["Real", 4, 3],
    image_yscale: ["Real", 4, 3],
    in_collision_tree: ["Bool", 6, 3],
    in_sequence: ["Bool", 4, 3],
    input_type: ["Any", 1, 3],
    instance_count: ["Real", 6, 3],
    instance_id: ["Array[Id.Instance]", 6, 3],
    keyboard_key: ["Constant.VirtualKey", 0, 3],
    keyboard_lastchar: ["String", 0, 3],
    keyboard_lastkey: ["Constant.VirtualKey", 0, 3],
    keyboard_string: ["String", 0, 3],
    layer: ["Id.Layer", 4, 3],
    lives: ["Real", 1, 3],
    longMessage: ["Any", 6, 3],
    managed: ["Bool", 6, 3],
    mask_index: ["Asset.GMSprite", 4, 3],
    message: ["Any", 6, 3],
    mouse_button: ["Constant.MouseButton", 0, 3],
    mouse_lastbutton: ["Constant.MouseButton", 0, 3],
    mouse_x: ["Real", 2, 3],
    mouse_y: ["Real", 2, 3],
    object_index: ["Asset.GMObject", 6, 3],
    on_ui_layer: ["Bool", 6, 1],
    os_browser: ["Constant.BrowserType", 2, 3],
    os_device: ["Constant.DeviceType", 3, 3],
    os_type: ["Constant.OperatingSystem", 2, 3],
    os_version: ["Real", 2, 3],
    path_endaction: ["Constant.PathAction", 4, 3],
    path_index: ["Asset.GMPath", 6, 3],
    path_orientation: ["Real", 4, 3],
    path_position: ["Real", 4, 3],
    path_positionprevious: ["Real", 4, 3],
    path_scale: ["Real", 4, 3],
    path_speed: ["Real", 4, 3],
    persistent: ["Bool", 4, 3],
    phy_active: ["Bool", 4, 3],
    phy_angular_damping: ["Real", 4, 3],
    phy_angular_velocity: ["Real", 4, 3],
    phy_bullet: ["Bool", 4, 3],
    phy_col_normal_x: ["Real", 6, 3],
    phy_col_normal_y: ["Real", 6, 3],
    phy_collision_points: ["Real", 6, 3],
    phy_collision_x: ["Array[Real]", 6, 3],
    phy_collision_y: ["Array[Real]", 6, 3],
    phy_com_x: ["Real", 6, 3],
    phy_com_y: ["Real", 6, 3],
    phy_dynamic: ["Bool", 6, 3],
    phy_fixed_rotation: ["Bool", 4, 3],
    phy_inertia: ["Real", 6, 3],
    phy_kinematic: ["Bool", 6, 3],
    phy_linear_damping: ["Real", 4, 3],
    phy_linear_velocity_x: ["Real", 4, 3],
    phy_linear_velocity_y: ["Real", 4, 3],
    phy_mass: ["Real", 6, 3],
    phy_position_x: ["Real", 4, 3],
    phy_position_xprevious: ["Real", 6, 3],
    phy_position_y: ["Real", 4, 3],
    phy_position_yprevious: ["Real", 6, 3],
    phy_rotation: ["Real", 4, 3],
    phy_sleeping: ["Bool", 6, 3],
    phy_speed: ["Real", 6, 3],
    phy_speed_x: ["Real", 4, 3],
    phy_speed_y: ["Real", 4, 3],
    player_avatar_sprite: ["Asset.GMSprite", 6, 3],
    player_avatar_url: ["String", 6, 3],
    player_id: ["Real", 6, 3],
    player_local: ["Bool", 6, 3],
    player_type: ["String", 6, 3],
    player_user_id: ["String", 6, 3],
    program_directory: ["String", 2, 3],
    rollback_api_server: ["String", 2, 3],
    rollback_confirmed_frame: ["Real", 2, 3],
    rollback_current_frame: ["Real", 2, 3],
    rollback_event_id: ["Real", 2, 3],
    rollback_event_param: ["Asset.GMObject", 2, 3],
    rollback_game_running: ["Bool", 2, 3],
    room: ["Asset.GMRoom", 0, 3],
    room_caption: ["String", 1, 3],
    room_first: ["Asset.GMRoom", 2, 3],
    room_height: ["Real", 0, 3],
    room_last: ["Asset.GMRoom", 2, 3],
    room_persistent: ["Bool", 0, 3],
    room_speed: ["Real", 1, 3],
    room_width: ["Real", 0, 3],
    score: ["Real", 1, 3],
    script: ["Any", 6, 3],
    sequence_instance: ["Struct.SequenceInstance", 6, 3],
    show_health: ["Bool", 1, 3],
    show_lives: ["Bool", 1, 3],
    show_score: ["Bool", 1, 3],
    solid: ["Bool", 4, 3],
    speed: ["Real", 4, 3],
    sprite_height: ["Real", 6, 3],
    sprite_index: ["Asset.GMSprite", 4, 3],
    sprite_width: ["Real", 6, 3],
    sprite_xoffset: ["Real", 6, 3],
    sprite_yoffset: ["Real", 6, 3],
    stacktrace: ["Any", 6, 3],
    temp_directory: ["String", 2, 3],
    text_type: ["Any", 1, 3],
    timeline_index: ["Asset.GMTimeline", 4, 3],
    timeline_loop: ["Bool", 4, 3],
    timeline_position: ["Real", 4, 3],
    timeline_running: ["Bool", 4, 3],
    timeline_speed: ["Real", 4, 3],
    view_angle: ["Array[Real]", 3, 1],
    view_camera: ["Array[Id.Camera]", 0, 3],
    view_current: ["Real", 2, 3],
    view_enabled: ["Bool", 0, 3],
    view_hborder: ["Array[Real]", 3, 1],
    view_hport: ["Array[Real]", 0, 3],
    view_hspeed: ["Array[Real]", 3, 1],
    view_hview: ["Array[Real]", 3, 1],
    view_object: ["Array[Real]", 3, 1],
    view_surface_id: ["Array[Id.Surface]", 0, 3],
    view_vborder: ["Array[Real]", 3, 1],
    view_visible: ["Array[Bool]", 0, 3],
    view_vspeed: ["Array[Real]", 3, 1],
    view_wport: ["Array[Real]", 0, 3],
    view_wview: ["Array[Real]", 3, 1],
    view_xport: ["Array[Real]", 0, 3],
    view_xview: ["Array[Real]", 3, 1],
    view_yport: ["Array[Real]", 0, 3],
    view_yview: ["Array[Real]", 3, 1],
    visible: ["Bool", 4, 3],
    vspeed: ["Real", 4, 3],
    wallpaper_config: ["Asset.GMObject", 2, 1],
    wallpaper_subscription_data: ["Any", 0, 1],
    webgl_enabled: ["Bool", 2, 3],
    working_directory: ["String", 2, 3],
    x: ["Real", 4, 3],
    xprevious: ["Real", 4, 3],
    xstart: ["Real", 4, 3],
    y: ["Real", 4, 3],
    yprevious: ["Real", 4, 3],
    ystart: ["Real", 4, 3]
  },
  constants: {
    AudioEffectType: ["Any", 0, 1],
    AudioLFOType: ["Any", 0, 1],
    GM_build_date: ["Real", 0, 3],
    GM_build_type: ["String", 0, 3],
    GM_is_sandboxed: ["Bool", 0, 1],
    GM_project_filename: ["String", 0, 3],
    GM_runtime_type: ["String", 0, 1],
    GM_runtime_version: ["String", 0, 3],
    GM_version: ["String", 0, 3],
    NaN: ["Real", 0, 3],
    _GMFILE_: ["String", 0, 1],
    _GMFUNCTION_: ["String", 0, 1],
    _GMLINE_: ["Real", 0, 1],
    achievement_achievement_info: ["Real", 1, 3],
    achievement_friends_info: ["Real", 1, 3],
    achievement_leaderboard_info: ["Real", 1, 3],
    achievement_our_info: ["Real", 1, 3],
    achievement_pic_loaded: ["Real", 1, 3],
    achievement_show_achievement: ["Real", 1, 3],
    achievement_show_bank: ["Real", 1, 3],
    achievement_show_friend_picker: ["Real", 1, 3],
    achievement_show_leaderboard: ["Real", 1, 3],
    achievement_show_profile: ["Real", 1, 3],
    achievement_show_purchase_prompt: ["Real", 1, 3],
    achievement_show_ui: ["Real", 1, 3],
    all: ["Id.Instance", 0, 3],
    animcurvetype_bezier: ["Real", 0, 3],
    animcurvetype_catmullrom: ["Real", 0, 3],
    animcurvetype_linear: ["Real", 0, 3],
    asset_animationcurve: ["Real", 0, 3],
    asset_font: ["Real", 0, 3],
    asset_object: ["Real", 0, 3],
    asset_particlesystem: ["Real", 0, 1],
    asset_path: ["Real", 0, 3],
    asset_room: ["Real", 0, 3],
    asset_script: ["Real", 0, 3],
    asset_sequence: ["Real", 0, 3],
    asset_shader: ["Real", 0, 3],
    asset_sound: ["Real", 0, 3],
    asset_sprite: ["Real", 0, 3],
    asset_tiles: ["Real", 0, 3],
    asset_timeline: ["Real", 0, 3],
    asset_unknown: ["Real", 0, 3],
    audio_3D: ["Real", 1, 2],
    audio_3d: ["Real", 0, 3],
    audio_bus_main: ["Struct.AudioBus", 0, 1],
    audio_falloff_exponent_distance: ["Real", 0, 3],
    audio_falloff_exponent_distance_clamped: ["Real", 0, 3],
    audio_falloff_exponent_distance_scaled: ["Real", 0, 3],
    audio_falloff_inverse_distance: ["Real", 0, 3],
    audio_falloff_inverse_distance_clamped: ["Real", 0, 3],
    audio_falloff_inverse_distance_scaled: ["Real", 0, 3],
    audio_falloff_linear_distance: ["Real", 0, 3],
    audio_falloff_linear_distance_clamped: ["Real", 0, 3],
    audio_falloff_none: ["Real", 0, 3],
    audio_mono: ["Real", 0, 3],
    audio_new_system: ["Real", 1, 3],
    audio_old_system: ["Real", 1, 3],
    audio_stereo: ["Real", 0, 3],
    bboxkind_diamond: ["Real", 0, 3],
    bboxkind_ellipse: ["Real", 0, 3],
    bboxkind_precise: ["Real", 0, 3],
    bboxkind_rectangular: ["Real", 0, 3],
    bboxkind_spine: ["Real", 0, 1],
    bboxmode_automatic: ["Real", 0, 3],
    bboxmode_fullimage: ["Real", 0, 3],
    bboxmode_manual: ["Real", 0, 3],
    bm_add: ["Real", 0, 3],
    bm_dest_alpha: ["Real", 0, 3],
    bm_dest_color: ["Real", 0, 3],
    bm_dest_colour: ["Real", 0, 3],
    bm_eq_add: ["Real", 0, 1],
    bm_eq_max: ["Real", 0, 1],
    bm_eq_min: ["Real", 0, 1],
    bm_eq_reverse_subtract: ["Real", 0, 1],
    bm_eq_subtract: ["Real", 0, 1],
    bm_inv_dest_alpha: ["Real", 0, 3],
    bm_inv_dest_color: ["Real", 0, 3],
    bm_inv_dest_colour: ["Real", 0, 3],
    bm_inv_src_alpha: ["Real", 0, 3],
    bm_inv_src_color: ["Real", 0, 3],
    bm_inv_src_colour: ["Real", 0, 3],
    bm_max: ["Real", 0, 3],
    bm_min: ["Real", 0, 1],
    bm_normal: ["Real", 0, 3],
    bm_one: ["Real", 0, 3],
    bm_reverse_subtract: ["Real", 0, 1],
    bm_src_alpha: ["Real", 0, 3],
    bm_src_alpha_sat: ["Real", 0, 3],
    bm_src_color: ["Real", 0, 3],
    bm_src_colour: ["Real", 0, 3],
    bm_subtract: ["Real", 0, 3],
    bm_zero: ["Real", 0, 3],
    browser_chrome: ["Real", 0, 3],
    browser_edge: ["Real", 0, 3],
    browser_firefox: ["Real", 0, 3],
    browser_ie: ["Real", 0, 3],
    browser_ie_mobile: ["Real", 0, 3],
    browser_not_a_browser: ["Real", 0, 3],
    browser_opera: ["Real", 0, 3],
    browser_safari: ["Real", 0, 3],
    browser_safari_mobile: ["Real", 0, 3],
    browser_tizen: ["Real", 0, 3],
    browser_unknown: ["Real", 0, 3],
    browser_windows_store: ["Real", 0, 3],
    buffer_bool: ["Real", 0, 3],
    buffer_error_general: ["Real", 0, 1],
    buffer_error_invalid_type: ["Real", 0, 1],
    buffer_error_out_of_space: ["Real", 0, 1],
    buffer_f16: ["Real", 0, 3],
    buffer_f32: ["Real", 0, 3],
    buffer_f64: ["Real", 0, 3],
    buffer_fast: ["Real", 0, 3],
    buffer_fixed: ["Real", 0, 3],
    buffer_grow: ["Real", 0, 3],
    buffer_s16: ["Real", 0, 3],
    buffer_s32: ["Real", 0, 3],
    buffer_s8: ["Real", 0, 3],
    buffer_seek_end: ["Real", 0, 3],
    buffer_seek_relative: ["Real", 0, 3],
    buffer_seek_start: ["Real", 0, 3],
    buffer_string: ["Real", 0, 3],
    buffer_text: ["Real", 0, 3],
    buffer_u16: ["Real", 0, 3],
    buffer_u32: ["Real", 0, 3],
    buffer_u64: ["Real", 0, 3],
    buffer_u8: ["Real", 0, 3],
    buffer_vbuffer: ["Real", 0, 3],
    buffer_wrap: ["Real", 0, 3],
    c_aqua: ["Real", 0, 3],
    c_black: ["Real", 0, 3],
    c_blue: ["Real", 0, 3],
    c_dkgray: ["Real", 0, 3],
    c_dkgrey: ["Real", 0, 3],
    c_fuchsia: ["Real", 0, 3],
    c_gray: ["Real", 0, 3],
    c_green: ["Real", 0, 3],
    c_grey: ["Real", 0, 3],
    c_lime: ["Real", 0, 3],
    c_ltgray: ["Real", 0, 3],
    c_ltgrey: ["Real", 0, 3],
    c_maroon: ["Real", 0, 3],
    c_navy: ["Real", 0, 3],
    c_olive: ["Real", 0, 3],
    c_orange: ["Real", 0, 3],
    c_purple: ["Real", 0, 3],
    c_red: ["Real", 0, 3],
    c_silver: ["Real", 0, 3],
    c_teal: ["Real", 0, 3],
    c_white: ["Real", 0, 3],
    c_yellow: ["Real", 0, 3],
    cmpfunc_always: ["Real", 0, 3],
    cmpfunc_equal: ["Real", 0, 3],
    cmpfunc_greater: ["Real", 0, 3],
    cmpfunc_greaterequal: ["Real", 0, 3],
    cmpfunc_less: ["Real", 0, 3],
    cmpfunc_lessequal: ["Real", 0, 3],
    cmpfunc_never: ["Real", 0, 3],
    cmpfunc_notequal: ["Real", 0, 3],
    colspace: ["Any", 0, 1],
    cr_appstart: ["Real", 0, 3],
    cr_arrow: ["Real", 0, 3],
    cr_beam: ["Real", 0, 3],
    cr_cross: ["Real", 0, 3],
    cr_default: ["Real", 0, 3],
    cr_drag: ["Real", 0, 3],
    cr_handpoint: ["Real", 0, 3],
    cr_hourglass: ["Real", 0, 3],
    cr_none: ["Real", 0, 3],
    cr_size_all: ["Real", 0, 3],
    cr_size_nesw: ["Real", 0, 3],
    cr_size_ns: ["Real", 0, 3],
    cr_size_nwse: ["Real", 0, 3],
    cr_size_we: ["Real", 0, 3],
    cr_uparrow: ["Real", 0, 3],
    cull_clockwise: ["Real", 0, 3],
    cull_counterclockwise: ["Real", 0, 3],
    cull_noculling: ["Real", 0, 3],
    debug_input_filter_keyboard: ["Real", 0, 1],
    debug_input_filter_mouse: ["Real", 0, 1],
    debug_input_filter_touch: ["Real", 0, 1],
    device_emulator: ["Real", 0, 3],
    device_ios_ipad: ["Real", 0, 3],
    device_ios_ipad_retina: ["Real", 0, 3],
    device_ios_iphone: ["Real", 0, 3],
    device_ios_iphone5: ["Real", 0, 3],
    device_ios_iphone6: ["Real", 0, 3],
    device_ios_iphone6plus: ["Real", 0, 3],
    device_ios_iphone_retina: ["Real", 0, 3],
    device_ios_unknown: ["Real", 0, 3],
    device_tablet: ["Real", 0, 3],
    display_landscape: ["Real", 0, 3],
    display_landscape_flipped: ["Real", 0, 3],
    display_portrait: ["Real", 0, 3],
    display_portrait_flipped: ["Real", 0, 3],
    dll_cdecl: ["Real", 0, 3],
    dll_stdcall: ["Real", 0, 3],
    ds_type_grid: ["Real", 0, 3],
    ds_type_list: ["Real", 0, 3],
    ds_type_map: ["Real", 0, 3],
    ds_type_priority: ["Real", 0, 3],
    ds_type_queue: ["Real", 0, 3],
    ds_type_stack: ["Real", 0, 3],
    ef_cloud: ["Real", 0, 3],
    ef_ellipse: ["Real", 0, 3],
    ef_explosion: ["Real", 0, 3],
    ef_firework: ["Real", 0, 3],
    ef_flare: ["Real", 0, 3],
    ef_rain: ["Real", 0, 3],
    ef_ring: ["Real", 0, 3],
    ef_smoke: ["Real", 0, 3],
    ef_smokeup: ["Real", 0, 3],
    ef_snow: ["Real", 0, 3],
    ef_spark: ["Real", 0, 3],
    ef_star: ["Real", 0, 3],
    ev_alarm: ["Real", 0, 3],
    ev_animation_end: ["Real", 0, 3],
    ev_animation_event: ["Real", 0, 3],
    ev_animation_update: ["Real", 0, 3],
    ev_async_audio_playback: ["Real", 0, 3],
    ev_async_audio_playback_ended: ["Real", 0, 1],
    ev_async_audio_recording: ["Real", 0, 3],
    ev_async_dialog: ["Real", 0, 3],
    ev_async_push_notification: ["Real", 0, 3],
    ev_async_save_load: ["Real", 0, 3],
    ev_async_social: ["Real", 0, 3],
    ev_async_system_event: ["Real", 0, 3],
    ev_async_web: ["Real", 0, 3],
    ev_async_web_cloud: ["Real", 0, 3],
    ev_async_web_iap: ["Real", 0, 3],
    ev_async_web_image_load: ["Real", 0, 3],
    ev_async_web_networking: ["Real", 0, 3],
    ev_async_web_steam: ["Real", 0, 3],
    ev_audio_playback: ["Real", 1, 3],
    ev_audio_playback_ended: ["Real", 1, 1],
    ev_audio_recording: ["Real", 1, 3],
    ev_boundary: ["Real", 0, 3],
    ev_boundary_view0: ["Real", 0, 3],
    ev_boundary_view1: ["Real", 0, 3],
    ev_boundary_view2: ["Real", 0, 3],
    ev_boundary_view3: ["Real", 0, 3],
    ev_boundary_view4: ["Real", 0, 3],
    ev_boundary_view5: ["Real", 0, 3],
    ev_boundary_view6: ["Real", 0, 3],
    ev_boundary_view7: ["Real", 0, 3],
    ev_broadcast_message: ["Real", 0, 3],
    ev_cleanup: ["Real", 0, 3],
    ev_collision: ["Real", 0, 3],
    ev_create: ["Real", 0, 3],
    ev_destroy: ["Real", 0, 3],
    ev_dialog_async: ["Real", 1, 3],
    ev_draw: ["Real", 0, 3],
    ev_draw_begin: ["Real", 0, 3],
    ev_draw_end: ["Real", 0, 3],
    ev_draw_normal: ["Real", 0, 1],
    ev_draw_post: ["Real", 0, 3],
    ev_draw_pre: ["Real", 0, 3],
    ev_end_of_path: ["Real", 0, 3],
    ev_game_end: ["Real", 0, 3],
    ev_game_start: ["Real", 0, 3],
    ev_gesture: ["Real", 0, 3],
    ev_gesture_double_tap: ["Real", 0, 3],
    ev_gesture_drag_end: ["Real", 0, 3],
    ev_gesture_drag_start: ["Real", 0, 3],
    ev_gesture_dragging: ["Real", 0, 3],
    ev_gesture_flick: ["Real", 0, 3],
    ev_gesture_pinch_end: ["Real", 0, 3],
    ev_gesture_pinch_in: ["Real", 0, 3],
    ev_gesture_pinch_out: ["Real", 0, 3],
    ev_gesture_pinch_start: ["Real", 0, 3],
    ev_gesture_rotate_end: ["Real", 0, 3],
    ev_gesture_rotate_start: ["Real", 0, 3],
    ev_gesture_rotating: ["Real", 0, 3],
    ev_gesture_tap: ["Real", 0, 3],
    ev_global_gesture_double_tap: ["Real", 0, 3],
    ev_global_gesture_drag_end: ["Real", 0, 3],
    ev_global_gesture_drag_start: ["Real", 0, 3],
    ev_global_gesture_dragging: ["Real", 0, 3],
    ev_global_gesture_flick: ["Real", 0, 3],
    ev_global_gesture_pinch_end: ["Real", 0, 3],
    ev_global_gesture_pinch_in: ["Real", 0, 3],
    ev_global_gesture_pinch_out: ["Real", 0, 3],
    ev_global_gesture_pinch_start: ["Real", 0, 3],
    ev_global_gesture_rotate_end: ["Real", 0, 3],
    ev_global_gesture_rotate_start: ["Real", 0, 3],
    ev_global_gesture_rotating: ["Real", 0, 3],
    ev_global_gesture_tap: ["Real", 0, 3],
    ev_global_left_button: ["Real", 0, 3],
    ev_global_left_press: ["Real", 0, 3],
    ev_global_left_release: ["Real", 0, 3],
    ev_global_middle_button: ["Real", 0, 3],
    ev_global_middle_press: ["Real", 0, 3],
    ev_global_middle_release: ["Real", 0, 3],
    ev_global_right_button: ["Real", 0, 3],
    ev_global_right_press: ["Real", 0, 3],
    ev_global_right_release: ["Real", 0, 3],
    ev_gui: ["Real", 0, 3],
    ev_gui_begin: ["Real", 0, 3],
    ev_gui_end: ["Real", 0, 3],
    ev_joystick1_button1: ["Real", 1, 3],
    ev_joystick1_button2: ["Real", 1, 3],
    ev_joystick1_button3: ["Real", 1, 3],
    ev_joystick1_button4: ["Real", 1, 3],
    ev_joystick1_button5: ["Real", 1, 3],
    ev_joystick1_button6: ["Real", 1, 3],
    ev_joystick1_button7: ["Real", 1, 3],
    ev_joystick1_button8: ["Real", 1, 3],
    ev_joystick1_down: ["Real", 1, 3],
    ev_joystick1_left: ["Real", 1, 3],
    ev_joystick1_right: ["Real", 1, 3],
    ev_joystick1_up: ["Real", 1, 3],
    ev_joystick2_button1: ["Real", 1, 3],
    ev_joystick2_button2: ["Real", 1, 3],
    ev_joystick2_button3: ["Real", 1, 3],
    ev_joystick2_button4: ["Real", 1, 3],
    ev_joystick2_button5: ["Real", 1, 3],
    ev_joystick2_button6: ["Real", 1, 3],
    ev_joystick2_button7: ["Real", 1, 3],
    ev_joystick2_button8: ["Real", 1, 3],
    ev_joystick2_down: ["Real", 1, 3],
    ev_joystick2_left: ["Real", 1, 3],
    ev_joystick2_right: ["Real", 1, 3],
    ev_joystick2_up: ["Real", 1, 3],
    ev_keyboard: ["Real", 0, 3],
    ev_keypress: ["Real", 0, 3],
    ev_keyrelease: ["Real", 0, 3],
    ev_left_button: ["Real", 0, 3],
    ev_left_press: ["Real", 0, 3],
    ev_left_release: ["Real", 0, 3],
    ev_middle_button: ["Real", 0, 3],
    ev_middle_press: ["Real", 0, 3],
    ev_middle_release: ["Real", 0, 3],
    ev_mouse: ["Real", 0, 3],
    ev_mouse_enter: ["Real", 0, 3],
    ev_mouse_leave: ["Real", 0, 3],
    ev_mouse_wheel_down: ["Real", 0, 3],
    ev_mouse_wheel_up: ["Real", 0, 3],
    ev_no_button: ["Real", 0, 3],
    ev_no_more_health: ["Real", 1, 3],
    ev_no_more_lives: ["Real", 1, 3],
    ev_other: ["Real", 0, 3],
    ev_outside: ["Real", 0, 3],
    ev_outside_view0: ["Real", 0, 3],
    ev_outside_view1: ["Real", 0, 3],
    ev_outside_view2: ["Real", 0, 3],
    ev_outside_view3: ["Real", 0, 3],
    ev_outside_view4: ["Real", 0, 3],
    ev_outside_view5: ["Real", 0, 3],
    ev_outside_view6: ["Real", 0, 3],
    ev_outside_view7: ["Real", 0, 3],
    ev_pre_create: ["Any", 0, 3],
    ev_push_notification: ["Real", 1, 3],
    ev_right_button: ["Real", 0, 3],
    ev_right_press: ["Real", 0, 3],
    ev_right_release: ["Real", 0, 3],
    ev_room_end: ["Real", 0, 3],
    ev_room_start: ["Real", 0, 3],
    ev_social: ["Real", 1, 3],
    ev_step: ["Real", 0, 3],
    ev_step_begin: ["Real", 0, 3],
    ev_step_end: ["Real", 0, 3],
    ev_step_normal: ["Real", 0, 3],
    ev_system_event: ["Real", 1, 3],
    ev_trigger: ["Real", 1, 3],
    ev_user0: ["Real", 0, 3],
    ev_user1: ["Real", 0, 3],
    ev_user10: ["Real", 0, 3],
    ev_user11: ["Real", 0, 3],
    ev_user12: ["Real", 0, 3],
    ev_user13: ["Real", 0, 3],
    ev_user14: ["Real", 0, 3],
    ev_user15: ["Real", 0, 3],
    ev_user2: ["Real", 0, 3],
    ev_user3: ["Real", 0, 3],
    ev_user4: ["Real", 0, 3],
    ev_user5: ["Real", 0, 3],
    ev_user6: ["Real", 0, 3],
    ev_user7: ["Real", 0, 3],
    ev_user8: ["Real", 0, 3],
    ev_user9: ["Real", 0, 3],
    ev_web_async: ["Real", 1, 3],
    ev_web_cloud: ["Real", 1, 3],
    ev_web_iap: ["Real", 1, 3],
    ev_web_image_load: ["Real", 1, 3],
    ev_web_networking: ["Real", 1, 3],
    ev_web_sound_load: ["Real", 1, 3],
    ev_web_steam: ["Real", 1, 3],
    fa_archive: ["Real", 0, 3],
    fa_bottom: ["Real", 0, 3],
    fa_center: ["Real", 0, 3],
    fa_directory: ["Real", 0, 3],
    fa_hidden: ["Real", 0, 3],
    fa_left: ["Real", 0, 3],
    fa_middle: ["Real", 0, 3],
    fa_none: ["Real", 0, 1],
    fa_readonly: ["Real", 0, 3],
    fa_right: ["Real", 0, 3],
    fa_sysfile: ["Real", 0, 3],
    fa_top: ["Real", 0, 3],
    fa_volumeid: ["Real", 0, 3],
    false: ["Bool", 0, 3],
    flexpanel_align: ["Any", 0, 1],
    flexpanel_direction: ["Any", 0, 1],
    flexpanel_display: ["Any", 0, 1],
    flexpanel_edge: ["Any", 0, 1],
    flexpanel_flex_direction: ["Any", 0, 1],
    flexpanel_gutter: ["Any", 0, 1],
    flexpanel_justify: ["Any", 0, 1],
    flexpanel_position_type: ["Any", 0, 1],
    flexpanel_unit: ["Any", 0, 1],
    flexpanel_wrap: ["Any", 0, 1],
    gamespeed_fps: ["Real", 0, 3],
    gamespeed_microseconds: ["Real", 0, 3],
    global: ["Real", 0, 3],
    gp_axis_acceleration_x: ["Real", 0, 3],
    gp_axis_acceleration_y: ["Real", 0, 3],
    gp_axis_acceleration_z: ["Real", 0, 3],
    gp_axis_angular_velocity_x: ["Real", 0, 3],
    gp_axis_angular_velocity_y: ["Real", 0, 3],
    gp_axis_angular_velocity_z: ["Real", 0, 3],
    gp_axis_orientation_w: ["Real", 0, 3],
    gp_axis_orientation_x: ["Real", 0, 3],
    gp_axis_orientation_y: ["Real", 0, 3],
    gp_axis_orientation_z: ["Real", 0, 3],
    gp_axislh: ["Real", 0, 3],
    gp_axislv: ["Real", 0, 3],
    gp_axisrh: ["Real", 0, 3],
    gp_axisrv: ["Real", 0, 3],
    gp_extra1: ["Real", 0, 1],
    gp_extra2: ["Real", 0, 1],
    gp_extra3: ["Real", 0, 1],
    gp_extra4: ["Real", 0, 1],
    gp_extra5: ["Real", 0, 1],
    gp_extra6: ["Real", 0, 1],
    gp_face1: ["Real", 0, 3],
    gp_face2: ["Real", 0, 3],
    gp_face3: ["Real", 0, 3],
    gp_face4: ["Real", 0, 3],
    gp_home: ["Real", 0, 1],
    gp_padd: ["Real", 0, 3],
    gp_paddlel: ["Real", 0, 1],
    gp_paddlelb: ["Real", 0, 1],
    gp_paddler: ["Real", 0, 1],
    gp_paddlerb: ["Real", 0, 1],
    gp_padl: ["Real", 0, 3],
    gp_padr: ["Real", 0, 3],
    gp_padu: ["Real", 0, 3],
    gp_select: ["Real", 0, 3],
    gp_shoulderl: ["Real", 0, 3],
    gp_shoulderlb: ["Real", 0, 3],
    gp_shoulderr: ["Real", 0, 3],
    gp_shoulderrb: ["Real", 0, 3],
    gp_start: ["Real", 0, 3],
    gp_stickl: ["Real", 0, 3],
    gp_stickr: ["Real", 0, 3],
    gp_touchpadbutton: ["Real", 0, 1],
    gxc_input_record_gamepad: ["Any", 0, 3],
    gxc_input_record_keyboard: ["Any", 0, 3],
    gxc_input_record_mouse: ["Any", 0, 3],
    gxc_input_record_touch: ["Any", 0, 3],
    iap_available: ["Real", 0, 3],
    iap_canceled: ["Real", 0, 3],
    iap_ev_consume: ["Real", 0, 3],
    iap_ev_product: ["Real", 0, 3],
    iap_ev_purchase: ["Real", 0, 3],
    iap_ev_restore: ["Real", 0, 3],
    iap_ev_storeload: ["Real", 0, 3],
    iap_failed: ["Real", 0, 3],
    iap_purchased: ["Real", 0, 3],
    iap_refunded: ["Real", 0, 3],
    iap_status_available: ["Real", 0, 3],
    iap_status_loading: ["Real", 0, 3],
    iap_status_processing: ["Real", 0, 3],
    iap_status_restoring: ["Real", 0, 3],
    iap_status_unavailable: ["Real", 0, 3],
    iap_status_uninitialised: ["Real", 0, 3],
    iap_storeload_failed: ["Real", 0, 3],
    iap_storeload_ok: ["Real", 0, 3],
    iap_unavailable: ["Real", 0, 3],
    infinity: ["Real", 0, 3],
    kbv_autocapitalize_characters: ["Real", 0, 3],
    kbv_autocapitalize_none: ["Real", 0, 3],
    kbv_autocapitalize_sentences: ["Real", 0, 3],
    kbv_autocapitalize_words: ["Real", 0, 3],
    kbv_returnkey_continue: ["Real", 0, 3],
    kbv_returnkey_default: ["Real", 0, 3],
    kbv_returnkey_done: ["Real", 0, 3],
    kbv_returnkey_emergency: ["Real", 0, 3],
    kbv_returnkey_go: ["Real", 0, 3],
    kbv_returnkey_google: ["Real", 0, 3],
    kbv_returnkey_join: ["Real", 0, 3],
    kbv_returnkey_next: ["Real", 0, 3],
    kbv_returnkey_route: ["Real", 0, 3],
    kbv_returnkey_search: ["Real", 0, 3],
    kbv_returnkey_send: ["Real", 0, 3],
    kbv_returnkey_yahoo: ["Real", 0, 3],
    kbv_type_ascii: ["Real", 0, 3],
    kbv_type_default: ["Real", 0, 3],
    kbv_type_email: ["Real", 0, 3],
    kbv_type_numbers: ["Real", 0, 3],
    kbv_type_phone: ["Real", 0, 3],
    kbv_type_phone_name: ["Real", 0, 3],
    kbv_type_url: ["Real", 0, 3],
    layer_type_room: ["Real", 0, 1],
    layer_type_ui_display: ["Real", 0, 1],
    layer_type_ui_viewports: ["Real", 0, 1],
    layer_type_unknown: ["Real", 0, 1],
    layerelementtype_background: ["Real", 0, 3],
    layerelementtype_instance: ["Real", 0, 3],
    layerelementtype_oldtilemap: ["Real", 0, 3],
    layerelementtype_particlesystem: ["Real", 0, 3],
    layerelementtype_sequence: ["Real", 0, 3],
    layerelementtype_sprite: ["Real", 0, 3],
    layerelementtype_text: ["Real", 0, 1],
    layerelementtype_tile: ["Real", 0, 3],
    layerelementtype_tilemap: ["Real", 0, 3],
    layerelementtype_undefined: ["Real", 0, 3],
    leaderboard_type_number: ["Real", 1, 3],
    leaderboard_type_time_mins_secs: ["Real", 1, 3],
    lighttype_dir: ["Real", 0, 3],
    lighttype_point: ["Real", 0, 3],
    m_axisx: ["Real", 0, 3],
    m_axisx_gui: ["Real", 0, 3],
    m_axisy: ["Real", 0, 3],
    m_axisy_gui: ["Real", 0, 3],
    m_scroll_down: ["Real", 0, 3],
    m_scroll_up: ["Real", 0, 3],
    matrix_projection: ["Real", 0, 3],
    matrix_view: ["Real", 0, 3],
    matrix_world: ["Real", 0, 3],
    mb_any: ["Real", 0, 3],
    mb_left: ["Real", 0, 3],
    mb_middle: ["Real", 0, 3],
    mb_none: ["Real", 0, 3],
    mb_right: ["Real", 0, 3],
    mb_side1: ["Real", 0, 3],
    mb_side2: ["Real", 0, 3],
    mip_markedonly: ["Real", 0, 3],
    mip_off: ["Real", 0, 3],
    mip_on: ["Real", 0, 3],
    network_config_avoid_time_wait: ["Real", 0, 3],
    network_config_connect_timeout: ["Real", 0, 3],
    network_config_disable_multicast: ["Real", 0, 1],
    network_config_disable_reliable_udp: ["Real", 0, 3],
    network_config_enable_multicast: ["Real", 0, 1],
    network_config_enable_reliable_udp: ["Real", 0, 3],
    network_config_message_size_limit: ["Real", 0, 1],
    network_config_use_non_blocking_socket: ["Real", 0, 3],
    network_config_websocket_protocol: ["Real", 0, 3],
    network_connect_active: ["Real", 0, 1],
    network_connect_blocking: ["Real", 0, 3],
    network_connect_nonblocking: ["Real", 0, 3],
    network_connect_none: ["Real", 0, 3],
    network_connect_passive: ["Real", 0, 1],
    network_send_binary: ["Real", 0, 3],
    network_send_text: ["Real", 0, 3],
    network_socket_bluetooth: ["Real", 0, 3],
    network_socket_tcp: ["Real", 0, 3],
    network_socket_udp: ["Real", 0, 3],
    network_socket_ws: ["Real", 0, 3],
    network_socket_wss: ["Real", 0, 3],
    network_type_connect: ["Real", 0, 3],
    network_type_data: ["Real", 0, 3],
    network_type_disconnect: ["Real", 0, 3],
    network_type_down: ["Real", 0, 3],
    network_type_non_blocking_connect: ["Real", 0, 3],
    network_type_up: ["Real", 0, 3],
    network_type_up_failed: ["Real", 0, 3],
    nineslice_blank: ["Real", 0, 3],
    nineslice_bottom: ["Real", 0, 3],
    nineslice_center: ["Real", 0, 3],
    nineslice_centre: ["Real", 0, 3],
    nineslice_hide: ["Real", 0, 3],
    nineslice_left: ["Real", 0, 3],
    nineslice_mirror: ["Real", 0, 3],
    nineslice_repeat: ["Real", 0, 3],
    nineslice_right: ["Real", 0, 3],
    nineslice_stretch: ["Real", 0, 3],
    nineslice_top: ["Real", 0, 3],
    noone: ["Id.Instance", 0, 3],
    of_challenge_lose: ["Real", 1, 3],
    of_challenge_tie: ["Real", 1, 3],
    of_challenge_win: ["Real", 1, 3],
    origin_bottomcentre: ["Real", 0, 1],
    origin_bottomleft: ["Real", 0, 1],
    origin_bottomright: ["Real", 0, 1],
    origin_middlecentre: ["Real", 0, 1],
    origin_middleleft: ["Real", 0, 1],
    origin_middleright: ["Real", 0, 1],
    origin_topcentre: ["Real", 0, 1],
    origin_topleft: ["Real", 0, 1],
    origin_topright: ["Real", 0, 1],
    os_android: ["Real", 0, 3],
    os_gdk: ["Real", 0, 3],
    os_gxgames: ["Real", 0, 3],
    os_ios: ["Real", 0, 3],
    os_linux: ["Real", 0, 3],
    os_macosx: ["Real", 0, 3],
    os_operagx: ["Real", 0, 3],
    os_permission_denied: ["Real", 0, 3],
    os_permission_denied_dont_request: ["Real", 0, 3],
    os_permission_granted: ["Real", 0, 3],
    os_ps3: ["Real", 1, 3],
    os_ps4: ["Real", 0, 3],
    os_ps5: ["Real", 0, 3],
    os_psvita: ["Real", 1, 3],
    os_switch: ["Real", 0, 3],
    os_switch2: ["Real", 0, 1],
    os_tvos: ["Real", 0, 3],
    os_unknown: ["Real", 0, 3],
    os_uwp: ["Real", 1, 3],
    os_win32: ["Real", 1, 3],
    os_win8native: ["Real", 1, 3],
    os_windows: ["Real", 0, 3],
    os_winphone: ["Real", 1, 3],
    os_xboxone: ["Real", 1, 3],
    os_xboxseriesxs: ["Real", 0, 3],
    other: ["Id.Instance", 0, 3],
    path_action_continue: ["Real", 0, 3],
    path_action_restart: ["Real", 0, 3],
    path_action_reverse: ["Real", 0, 3],
    path_action_stop: ["Real", 0, 3],
    phy_debug_render_aabb: ["Real", 0, 3],
    phy_debug_render_collision_pairs: ["Real", 0, 3],
    phy_debug_render_coms: ["Real", 0, 3],
    phy_debug_render_core_shapes: ["Real", 0, 3],
    phy_debug_render_joints: ["Real", 0, 3],
    phy_debug_render_obb: ["Real", 0, 3],
    phy_debug_render_shapes: ["Real", 0, 3],
    phy_joint_anchor_1_x: ["Real", 0, 3],
    phy_joint_anchor_1_y: ["Real", 0, 3],
    phy_joint_anchor_2_x: ["Real", 0, 3],
    phy_joint_anchor_2_y: ["Real", 0, 3],
    phy_joint_angle: ["Real", 0, 3],
    phy_joint_angle_limits: ["Real", 0, 3],
    phy_joint_damping_ratio: ["Real", 0, 3],
    phy_joint_frequency: ["Real", 0, 3],
    phy_joint_length_1: ["Real", 0, 3],
    phy_joint_length_2: ["Real", 0, 3],
    phy_joint_lower_angle_limit: ["Real", 0, 3],
    phy_joint_max_force: ["Real", 0, 3],
    phy_joint_max_length: ["Real", 0, 3],
    phy_joint_max_motor_force: ["Real", 0, 3],
    phy_joint_max_motor_torque: ["Real", 0, 3],
    phy_joint_max_torque: ["Real", 0, 3],
    phy_joint_motor_force: ["Real", 0, 3],
    phy_joint_motor_speed: ["Real", 0, 3],
    phy_joint_motor_torque: ["Real", 0, 3],
    phy_joint_reaction_force_x: ["Real", 0, 3],
    phy_joint_reaction_force_y: ["Real", 0, 3],
    phy_joint_reaction_torque: ["Real", 0, 3],
    phy_joint_speed: ["Real", 0, 3],
    phy_joint_translation: ["Real", 0, 3],
    phy_joint_upper_angle_limit: ["Real", 0, 3],
    phy_particle_data_flag_category: ["Real", 0, 3],
    phy_particle_data_flag_color: ["Real", 0, 3],
    phy_particle_data_flag_colour: ["Real", 0, 3],
    phy_particle_data_flag_position: ["Real", 0, 3],
    phy_particle_data_flag_typeflags: ["Real", 0, 3],
    phy_particle_data_flag_velocity: ["Real", 0, 3],
    phy_particle_flag_colormixing: ["Real", 0, 3],
    phy_particle_flag_colourmixing: ["Real", 0, 3],
    phy_particle_flag_elastic: ["Real", 0, 3],
    phy_particle_flag_powder: ["Real", 0, 3],
    phy_particle_flag_spring: ["Real", 0, 3],
    phy_particle_flag_tensile: ["Real", 0, 3],
    phy_particle_flag_viscous: ["Real", 0, 3],
    phy_particle_flag_wall: ["Real", 0, 3],
    phy_particle_flag_water: ["Real", 0, 3],
    phy_particle_flag_zombie: ["Real", 0, 3],
    phy_particle_group_flag_rigid: ["Real", 0, 3],
    phy_particle_group_flag_solid: ["Real", 0, 3],
    pi: ["Real", 0, 3],
    pointer_invalid: ["Pointer", 0, 3],
    pointer_null: ["Pointer", 0, 3],
    pr_linelist: ["Real", 0, 3],
    pr_linestrip: ["Real", 0, 3],
    pr_pointlist: ["Real", 0, 3],
    pr_trianglefan: ["Real", 0, 3],
    pr_trianglelist: ["Real", 0, 3],
    pr_trianglestrip: ["Real", 0, 3],
    ps_distr_gaussian: ["Real", 0, 3],
    ps_distr_invgaussian: ["Real", 0, 3],
    ps_distr_linear: ["Real", 0, 3],
    ps_mode_burst: ["Real", 0, 1],
    ps_mode_stream: ["Real", 0, 1],
    ps_shape_diamond: ["Real", 0, 3],
    ps_shape_ellipse: ["Real", 0, 3],
    ps_shape_line: ["Real", 0, 3],
    ps_shape_rectangle: ["Real", 0, 3],
    pt_shape_circle: ["Real", 0, 3],
    pt_shape_cloud: ["Real", 0, 3],
    pt_shape_disk: ["Real", 0, 3],
    pt_shape_explosion: ["Real", 0, 3],
    pt_shape_flare: ["Real", 0, 3],
    pt_shape_line: ["Real", 0, 3],
    pt_shape_pixel: ["Real", 0, 3],
    pt_shape_ring: ["Real", 0, 3],
    pt_shape_smoke: ["Real", 0, 3],
    pt_shape_snow: ["Real", 0, 3],
    pt_shape_spark: ["Real", 0, 3],
    pt_shape_sphere: ["Real", 0, 3],
    pt_shape_square: ["Real", 0, 3],
    pt_shape_star: ["Real", 0, 3],
    rollback_chat_message: ["Real", 0, 3],
    rollback_connect_error: ["Real", 0, 3],
    rollback_connect_info: ["Real", 0, 3],
    rollback_connected_to_peer: ["Real", 0, 3],
    rollback_connection_rejected: ["Real", 0, 1],
    rollback_disconnected_from_peer: ["Real", 0, 3],
    rollback_end_game: ["Real", 0, 1],
    rollback_game_full: ["Real", 0, 3],
    rollback_game_info: ["Real", 0, 3],
    rollback_game_interrupted: ["Real", 0, 3],
    rollback_game_resumed: ["Real", 0, 3],
    rollback_high_latency: ["Real", 0, 1],
    rollback_player_prefs: ["Real", 0, 3],
    rollback_protocol_rejected: ["Real", 0, 1],
    rollback_synchronized_with_peer: ["Real", 0, 3],
    rollback_synchronizing_with_peer: ["Real", 0, 3],
    self: ["Id.Instance", 0, 3],
    seqaudiokey_loop: ["Real", 0, 3],
    seqaudiokey_oneshot: ["Real", 0, 3],
    seqdir_left: ["Real", 0, 3],
    seqdir_right: ["Real", 0, 3],
    seqinterpolation_assign: ["Real", 0, 3],
    seqinterpolation_lerp: ["Real", 0, 3],
    seqplay_loop: ["Real", 0, 3],
    seqplay_oneshot: ["Real", 0, 3],
    seqplay_pingpong: ["Real", 0, 3],
    seqtextkey_bottom: ["Real", 0, 3],
    seqtextkey_center: ["Real", 0, 3],
    seqtextkey_justify: ["Real", 0, 3],
    seqtextkey_left: ["Real", 0, 3],
    seqtextkey_middle: ["Real", 0, 3],
    seqtextkey_right: ["Real", 0, 3],
    seqtextkey_top: ["Real", 0, 3],
    seqtracktype_audio: ["Real", 0, 3],
    seqtracktype_audioeffect: ["Real", 0, 1],
    seqtracktype_bool: ["Real", 0, 3],
    seqtracktype_clipmask: ["Real", 0, 3],
    seqtracktype_clipmask_mask: ["Real", 0, 3],
    seqtracktype_clipmask_subject: ["Real", 0, 3],
    seqtracktype_color: ["Real", 0, 3],
    seqtracktype_colour: ["Real", 0, 3],
    seqtracktype_empty: ["Real", 0, 3],
    seqtracktype_graphic: ["Real", 0, 3],
    seqtracktype_group: ["Real", 0, 3],
    seqtracktype_instance: ["Real", 0, 3],
    seqtracktype_message: ["Real", 0, 3],
    seqtracktype_moment: ["Real", 0, 3],
    seqtracktype_particlesystem: ["Real", 0, 1],
    seqtracktype_real: ["Real", 0, 3],
    seqtracktype_sequence: ["Real", 0, 3],
    seqtracktype_spriteframes: ["Real", 0, 3],
    seqtracktype_string: ["Real", 0, 3],
    seqtracktype_text: ["Real", 0, 3],
    sprite_add_ext_error_cancelled: ["Real", 0, 1],
    sprite_add_ext_error_decompressfailed: ["Real", 0, 1],
    sprite_add_ext_error_loadfailed: ["Real", 0, 1],
    sprite_add_ext_error_setupfailed: ["Real", 0, 1],
    sprite_add_ext_error_spritenotfound: ["Real", 0, 1],
    sprite_add_ext_error_unknown: ["Real", 0, 1],
    spritespeed_framespergameframe: ["Real", 0, 3],
    spritespeed_framespersecond: ["Real", 0, 3],
    stencilop_decr: ["Real", 0, 1],
    stencilop_decr_wrap: ["Real", 0, 1],
    stencilop_incr: ["Real", 0, 1],
    stencilop_incr_wrap: ["Real", 0, 1],
    stencilop_invert: ["Real", 0, 1],
    stencilop_keep: ["Real", 0, 1],
    stencilop_replace: ["Real", 0, 1],
    stencilop_zero: ["Real", 0, 1],
    surface_r16float: ["Real", 0, 1],
    surface_r32float: ["Real", 0, 1],
    surface_r8unorm: ["Real", 0, 1],
    surface_rg8unorm: ["Real", 0, 1],
    surface_rgba16float: ["Real", 0, 1],
    surface_rgba32float: ["Real", 0, 1],
    surface_rgba4unorm: ["Real", 0, 1],
    surface_rgba8unorm: ["Real", 0, 1],
    textalign_bottom: ["Real", 0, 1],
    textalign_center: ["Real", 0, 1],
    textalign_justify: ["Real", 0, 1],
    textalign_left: ["Real", 0, 1],
    textalign_middle: ["Real", 0, 1],
    textalign_right: ["Real", 0, 1],
    textalign_top: ["Real", 0, 1],
    texturegroup_status_fetched: ["Real", 0, 3],
    texturegroup_status_loaded: ["Real", 0, 3],
    texturegroup_status_loading: ["Real", 0, 3],
    texturegroup_status_unloaded: ["Real", 0, 3],
    textwrap_default: ["Real", 0, 1],
    textwrap_splitwords: ["Real", 0, 1],
    tf_anisotropic: ["Real", 0, 3],
    tf_linear: ["Real", 0, 3],
    tf_point: ["Real", 0, 3],
    tile_flip: ["Real", 0, 3],
    tile_index_mask: ["Real", 0, 3],
    tile_mirror: ["Real", 0, 3],
    tile_rotate: ["Real", 0, 3],
    time_source_expire_after: ["Real", 0, 3],
    time_source_expire_nearest: ["Real", 0, 3],
    time_source_game: ["Real", 0, 3],
    time_source_global: ["Real", 0, 3],
    time_source_state_active: ["Real", 0, 3],
    time_source_state_initial: ["Real", 0, 3],
    time_source_state_paused: ["Real", 0, 3],
    time_source_state_stopped: ["Real", 0, 3],
    time_source_units_frames: ["Real", 0, 3],
    time_source_units_seconds: ["Real", 0, 3],
    timezone_local: ["Real", 0, 3],
    timezone_utc: ["Real", 0, 3],
    tm_countvsyncs: ["Real", 0, 3],
    tm_countvsyncs_winalt: ["Real", 0, 1],
    tm_sleep: ["Real", 0, 3],
    tm_systemtiming: ["Real", 0, 1],
    true: ["Bool", 0, 3],
    ty_real: ["Real", 0, 3],
    ty_string: ["Real", 0, 3],
    undefined: ["Undefined", 0, 3],
    vertex_type_color: ["Real", 0, 3],
    vertex_type_colour: ["Real", 0, 3],
    vertex_type_float1: ["Real", 0, 3],
    vertex_type_float2: ["Real", 0, 3],
    vertex_type_float3: ["Real", 0, 3],
    vertex_type_float4: ["Real", 0, 3],
    vertex_type_ubyte4: ["Real", 0, 3],
    vertex_usage_binormal: ["Real", 0, 3],
    vertex_usage_blendindices: ["Real", 0, 3],
    vertex_usage_blendweight: ["Real", 0, 3],
    vertex_usage_color: ["Real", 0, 3],
    vertex_usage_colour: ["Real", 0, 3],
    vertex_usage_depth: ["Real", 0, 3],
    vertex_usage_fog: ["Real", 0, 3],
    vertex_usage_normal: ["Real", 0, 3],
    vertex_usage_position: ["Real", 0, 3],
    vertex_usage_psize: ["Real", 0, 3],
    vertex_usage_sample: ["Real", 0, 3],
    vertex_usage_tangent: ["Real", 0, 3],
    vertex_usage_texcoord: ["Real", 0, 3],
    vertex_usage_textcoord: ["Real", 1, 3],
    video_format_rgba: ["Real", 0, 3],
    video_format_yuv: ["Real", 0, 3],
    video_status_closed: ["Real", 0, 3],
    video_status_paused: ["Real", 0, 3],
    video_status_playing: ["Real", 0, 3],
    video_status_preparing: ["Real", 0, 3],
    vk_add: ["Real", 0, 3],
    vk_alt: ["Real", 0, 3],
    vk_anykey: ["Real", 0, 3],
    vk_backspace: ["Real", 0, 3],
    vk_control: ["Real", 0, 3],
    vk_decimal: ["Real", 0, 3],
    vk_delete: ["Real", 0, 3],
    vk_divide: ["Real", 0, 3],
    vk_down: ["Real", 0, 3],
    vk_end: ["Real", 0, 3],
    vk_enter: ["Real", 0, 3],
    vk_escape: ["Real", 0, 3],
    vk_f1: ["Real", 0, 3],
    vk_f10: ["Real", 0, 3],
    vk_f11: ["Real", 0, 3],
    vk_f12: ["Real", 0, 3],
    vk_f2: ["Real", 0, 3],
    vk_f3: ["Real", 0, 3],
    vk_f4: ["Real", 0, 3],
    vk_f5: ["Real", 0, 3],
    vk_f6: ["Real", 0, 3],
    vk_f7: ["Real", 0, 3],
    vk_f8: ["Real", 0, 3],
    vk_f9: ["Real", 0, 3],
    vk_home: ["Real", 0, 3],
    vk_insert: ["Real", 0, 3],
    vk_lalt: ["Real", 0, 3],
    vk_lcontrol: ["Real", 0, 3],
    vk_left: ["Real", 0, 3],
    vk_lshift: ["Real", 0, 3],
    vk_multiply: ["Real", 0, 3],
    vk_nokey: ["Real", 0, 3],
    vk_numpad0: ["Real", 0, 3],
    vk_numpad1: ["Real", 0, 3],
    vk_numpad2: ["Real", 0, 3],
    vk_numpad3: ["Real", 0, 3],
    vk_numpad4: ["Real", 0, 3],
    vk_numpad5: ["Real", 0, 3],
    vk_numpad6: ["Real", 0, 3],
    vk_numpad7: ["Real", 0, 3],
    vk_numpad8: ["Real", 0, 3],
    vk_numpad9: ["Real", 0, 3],
    vk_pagedown: ["Real", 0, 3],
    vk_pageup: ["Real", 0, 3],
    vk_pause: ["Real", 0, 3],
    vk_printscreen: ["Real", 0, 3],
    vk_ralt: ["Real", 0, 3],
    vk_rcontrol: ["Real", 0, 3],
    vk_return: ["Real", 0, 3],
    vk_right: ["Real", 0, 3],
    vk_rshift: ["Real", 0, 3],
    vk_shift: ["Real", 0, 3],
    vk_space: ["Real", 0, 3],
    vk_subtract: ["Real", 0, 3],
    vk_tab: ["Real", 0, 3],
    vk_up: ["Real", 0, 3]
  },
  enums: {
    AudioEffectType: ["Bitcrusher", "Delay", "Gain", "HPF2", "LPF2", "Reverb1", "Tremolo", "PeakEQ", "HiShelf", "LoShelf", "EQ", "Compressor"],
    AudioLFOType: ["InvSawtooth", "Sawtooth", "Sine", "Square", "Triangle"],
    colspace: ["room", "ui_view", "ui_display", "colspace_all"],
    flexpanel_align: ["auto", "flex_start", "center", "flex_end", "stretch", "baseline", "space_between", "space_around", "space_evenly"],
    flexpanel_direction: ["inherit", "LTR", "RTL"],
    flexpanel_display: ["flex", "none"],
    flexpanel_edge: ["left", "top", "right", "bottom", "start", "_end", "horizontal", "vertical", "all_edges"],
    flexpanel_flex_direction: ["column", "column_reverse", "row", "row_reverse"],
    flexpanel_gutter: ["column", "row", "all_gutters"],
    flexpanel_justify: ["start", "center", "flex_end", "space_between", "space_around", "space_evenly"],
    flexpanel_position_type: ["static", "relative", "absolute"],
    flexpanel_unit: ["point", "percent", "auto"],
    flexpanel_wrap: ["no_wrap", "wrap", "reverse"]
  }
};

// src/semantic/builtins.ts
var F_DEPRECATED = 1;
var F_PURE = 2;
var V_DEPRECATED = 1;
var V_READONLY = 2;
var V_INSTANCE = 4;
var functions = builtins_default.functions;
var variables = builtins_default.variables;
var constants = builtins_default.constants;
var KNOWN_RUNTIMES = builtins_default.runtimes;
function getBuiltinFunction(name) {
  if (!Object.hasOwn(functions, name)) return void 0;
  const [minArgs, maxArgs, returnType, flags, runtimeMask] = functions[name];
  return {
    name,
    minArgs,
    maxArgs,
    returnType,
    deprecated: (flags & F_DEPRECATED) !== 0,
    pure: (flags & F_PURE) !== 0,
    runtimeMask
  };
}
function getBuiltinVariable(name) {
  const isConst = Object.hasOwn(constants, name);
  if (!isConst && !Object.hasOwn(variables, name)) return void 0;
  const [type, flags, runtimeMask] = isConst ? constants[name] : variables[name];
  return {
    name,
    type,
    deprecated: (flags & V_DEPRECATED) !== 0,
    readonly: isConst || (flags & V_READONLY) !== 0,
    instance: (flags & V_INSTANCE) !== 0,
    constant: isConst,
    runtimeMask
  };
}
function isBuiltinFunction(name) {
  return Object.hasOwn(functions, name);
}
function isBuiltinIdentifier(name) {
  return Object.hasOwn(variables, name) || Object.hasOwn(constants, name) || BUILTIN_KEYWORD_VALUES.has(name);
}
var BUILTIN_KEYWORD_VALUES = /* @__PURE__ */ new Set(["self", "other", "all", "noone", "global", "undefined", "true", "false", "infinity", "NaN", "pi"]);
function isArgumentVariable(name) {
  return name === "argument" || name === "argument_count" || /^argument\d+$/.test(name);
}
function resolveRuntimeIndex(version) {
  if (!version) return -1;
  const line = version.split(".").slice(0, 2).join(".");
  return KNOWN_RUNTIMES.findIndex((v) => v.split(".").slice(0, 2).join(".") === line);
}
function availableInRuntime(runtimeMask, runtimeIndex) {
  return runtimeIndex < 0 || (runtimeMask & 1 << runtimeIndex) !== 0;
}
var LEGACY_REPLACEMENTS = {
  instance_create: "instance_create_layer() or instance_create_depth()",
  execute_string: "a function or method (runtime code evaluation was removed)",
  execute_file: "a function or method (runtime code evaluation was removed)",
  object_event_add: "a method variable",
  background_get_width: "sprite_get_width()",
  background_get_height: "sprite_get_height()",
  draw_background: "draw_sprite() or a background layer",
  draw_background_ext: "draw_sprite_ext() or a background layer",
  sound_play: "audio_play_sound()",
  sound_loop: "audio_play_sound() with loop = true",
  sound_stop: "audio_stop_sound()",
  sound_isplaying: "audio_is_playing()",
  view_xview: "camera_get_view_x(view_camera[0])",
  view_yview: "camera_get_view_y(view_camera[0])",
  d3d_start: "gpu_set_ztestenable() / gpu_set_zwriteenable()",
  d3d_end: "gpu_set_ztestenable(false)",
  d3d_set_fog: "gpu_set_fog()",
  d3d_transform_set_identity: "matrix_set(matrix_world, matrix_build_identity())",
  draw_set_blend_mode: "gpu_set_blendmode()",
  draw_set_blend_mode_ext: "gpu_set_blendmode_ext()",
  draw_set_alpha_test: "gpu_set_alphatestenable()",
  texture_set_interpolation: "gpu_set_texfilter()",
  texture_set_repeat: "gpu_set_texrepeat()",
  array_length_1d: "array_length()",
  array_length_2d: "array_length(array[index])",
  array_height_2d: "array_length()",
  joystick_exists: "gamepad_is_connected()",
  window_set_region_size: "window_set_size()",
  instance_change: "instance_destroy() + instance_create_*()",
  room_speed: "game_get_speed(gamespeed_fps)"
};

// src/semantic/scope.ts
function resolveScopes(program) {
  const root = { node: program, parent: null, locals: /* @__PURE__ */ new Map(), usesArguments: false, children: [] };
  const result = { root, refs: [], refOf: /* @__PURE__ */ new Map(), scopeOf: /* @__PURE__ */ new Map([[program, root]]), globalvars: [] };
  let scope = root;
  let withDepth = 0;
  let inMacro = false;
  const declare = (id, kind, target = scope) => {
    const decl = { name: id.name, id, kind, scope: target, reads: [], writes: [] };
    const list = target.locals.get(id.name);
    if (list) list.push(decl);
    else target.locals.set(id.name, [decl]);
  };
  const lookup = (s, name, at) => {
    const list = s.locals.get(name);
    if (!list) return void 0;
    let found;
    for (const d of list) if (d.kind === "param" || d.id.start < at) found = d;
    return found;
  };
  const reference = (id, access, isCallee) => {
    if (id.name === "argument" || id.name === "argument_count" || /^argument\d+$/.test(id.name)) scope.usesArguments = true;
    let binding = { kind: "free" };
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
    const ref = { id, binding, access, isCallee, scope, withDepth, inMacro };
    if (binding.kind === "local") {
      if (access !== "write") binding.decl.reads.push(ref);
      if (access !== "read") binding.decl.writes.push(ref);
    }
    result.refs.push(ref);
    result.refOf.set(id, ref);
  };
  const visitExpr = (node, access = "read", isCallee = false) => {
    if (node.type === "Identifier") {
      reference(node, access, isCallee);
      return;
    }
    visit(node);
  };
  const visitTarget = (target, access) => {
    if (target.type === "IndexExpression") {
      let root2 = target;
      const indices = [];
      while (root2.type === "IndexExpression") {
        indices.push(...root2.indices);
        root2 = root2.object;
      }
      if (root2.type === "Identifier") {
        reference(root2, "readwrite", false);
        indices.forEach((i) => visitExpr(i));
        return;
      }
    }
    visitExpr(target, access);
  };
  const visitFunction = (fn) => {
    const fnScope = { node: fn, parent: scope, locals: /* @__PURE__ */ new Map(), usesArguments: false, children: [] };
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
  const visit = (node) => {
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
        visitExpr(node.object);
        return;
      case "IndexExpression":
        visitExpr(node.object);
        node.indices.forEach((i) => visitExpr(i));
        return;
      case "StructProperty":
        if (node.value) visitExpr(node.value);
        else if (node.key.type === "Identifier") reference(node.key, "read", false);
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

// src/semantic/project-index.ts
var VARIABLE_SETTERS = {
  variable_instance_set: { nameArg: 1, global: false },
  variable_struct_set: { nameArg: 1, global: false },
  struct_set: { nameArg: 1, global: false },
  variable_global_set: { nameArg: 0, global: true }
};
var DYNAMIC_ASSET_LOOKUPS = /* @__PURE__ */ new Set(["asset_get_index", "script_execute_ext", "variable_global_get", "variable_instance_get", "struct_get", "variable_struct_get", "method_call"]);
var ProjectIndex = class {
  project;
  scopes = /* @__PURE__ */ new Map();
  /** Script-level functions by name (a name with 2+ entries is a duplicate). */
  globalFunctions = /* @__PURE__ */ new Map();
  /** Every function (global, method, nested) keyed by its AST node. */
  functionsByNode = /* @__PURE__ */ new Map();
  /** Named methods defined in each object's events. */
  methodsByObject = /* @__PURE__ */ new Map();
  macros = /* @__PURE__ */ new Map();
  enums = /* @__PURE__ */ new Map();
  /** `global.x`, `globalvar x`, variable_global_set("x"), top-level script assignments. */
  globalVariables = /* @__PURE__ */ new Set();
  /** Names declared with `globalvar` anywhere in the project. */
  globalvarNames = /* @__PURE__ */ new Set();
  /** Every name assigned as an instance or struct variable anywhere in the project. */
  assignedNames = /* @__PURE__ */ new Set();
  /** Instance variables assigned directly in each object's own code or variable definitions. */
  instanceVariables = /* @__PURE__ */ new Map();
  /** Identifier references (reads, writes, calls) by name, excluding declarations. */
  identifierRefs = /* @__PURE__ */ new Map();
  /** Identifier references grouped by the resource that makes them. */
  refsByResource = /* @__PURE__ */ new Map();
  /** Values of all string literals (resource names looked up dynamically). */
  stringLiterals = /* @__PURE__ */ new Set();
  /** Asset name → resource type (objects, sprites, ...), including unregistered folders. */
  assets = /* @__PURE__ */ new Map();
  /** The project sets variables through computed names (`variable_instance_set(id, name, v)`). */
  usesDynamicVariableNames = false;
  /** The project looks up assets through computed names (`asset_get_index("obj_" + n)`). */
  usesDynamicAssetNames = false;
  /** Index into KNOWN_RUNTIMES of the project's runtime, or -1 if unknown. */
  runtimeIndex;
  constructor(project, runtimeOverride) {
    this.project = project;
    this.runtimeIndex = resolveRuntimeIndex(runtimeOverride ?? project.yyp?.ideVersion);
    for (const [name, list] of project.resources) {
      const registered = list.find((r) => r.inYyp) ?? list[0];
      this.assets.set(name, registered.type);
    }
    for (const obj of project.objects.values()) {
      if (!this.assets.has(obj.name)) this.assets.set(obj.name, "objects");
      for (const p of obj.properties) {
        this.instanceVars(obj.name).add(p);
        this.assignedNames.add(p);
      }
    }
    for (const file of project.files) {
      if (file.kind === "script" && !this.assets.has(file.resource)) this.assets.set(file.resource, "scripts");
      this.indexFile(file);
    }
    for (const info of this.functionsByNode.values()) {
      if (info.isGlobal || info.file.kind !== "object-event" || info.name === "<anonymous>") continue;
      let methods = this.methodsByObject.get(info.file.resource);
      if (!methods) this.methodsByObject.set(info.file.resource, methods = /* @__PURE__ */ new Map());
      push(methods, info.name, info);
    }
  }
  instanceVars(object) {
    let set = this.instanceVariables.get(object);
    if (!set) {
      set = /* @__PURE__ */ new Set();
      this.instanceVariables.set(object, set);
    }
    return set;
  }
  indexFile(file) {
    const scopes = resolveScopes(file.ast);
    this.scopes.set(file, scopes);
    const owner = file.kind === "object-event" ? file.resource : void 0;
    const resourceRefs = this.refsByResource.get(file.resource) ?? /* @__PURE__ */ new Set();
    this.refsByResource.set(file.resource, resourceRefs);
    for (const ref of scopes.refs) {
      const name = ref.id.name;
      this.identifierRefs.set(name, (this.identifierRefs.get(name) ?? 0) + 1);
      resourceRefs.add(name);
      if (ref.binding.kind !== "free" || ref.access === "read" || ref.inMacro) continue;
      if (ref.scope === scopes.root && file.kind === "script" && ref.withDepth === 0) {
        this.globalVariables.add(name);
      }
      this.assignedNames.add(name);
      if (owner && ref.withDepth === 0) this.instanceVars(owner).add(name);
    }
    for (const g of scopes.globalvars) {
      this.globalVariables.add(g.name);
      this.globalvarNames.add(g.name);
    }
    const topLevel = new Set(file.ast.body);
    walk(file.ast, (node, ctx) => {
      switch (node.type) {
        case "FunctionDeclaration":
        case "FunctionExpression": {
          const name = node.id?.name ?? this.functionNameFromContext(ctx.ancestors);
          const info = {
            name: name ?? "<anonymous>",
            node,
            file,
            scope: scopes.scopeOf.get(node),
            isConstructor: node.isConstructor,
            isGlobal: node.type === "FunctionDeclaration" && topLevel.has(node) && (file.kind === "script" || file.kind === "extension")
          };
          this.functionsByNode.set(node, info);
          if (info.isGlobal && name) push(this.globalFunctions, name, info);
          if (node.type === "FunctionDeclaration" && !info.isGlobal && name) {
            this.assignedNames.add(name);
            if (owner) this.instanceVars(owner).add(name);
          }
          break;
        }
        case "MacroDeclaration":
          push(this.macros, node.id.name, { node, file });
          break;
        case "EnumDeclaration":
          push(this.enums, node.id.name, { node, file });
          break;
        case "VarDeclaration":
          if (node.kind === "static") for (const d of node.declarations) this.assignedNames.add(d.id.name);
          break;
        case "AssignmentExpression":
          this.recordMemberWrite(node.left, owner);
          break;
        case "UpdateExpression":
          this.recordMemberWrite(node.argument, owner);
          break;
        case "StructProperty":
          this.assignedNames.add(node.key.type === "Identifier" ? node.key.name : node.key.value);
          break;
        case "StringLiteral":
          this.stringLiterals.add(node.value);
          break;
        case "CallExpression":
          this.recordCall(node);
          break;
      }
    });
  }
  functionNameFromContext(ancestors) {
    const parent = ancestors[ancestors.length - 1];
    if (parent?.type === "AssignmentExpression") {
      if (parent.left.type === "Identifier") return parent.left.name;
      if (parent.left.type === "MemberExpression") return parent.left.property.name;
    }
    if (parent?.type === "VarDeclarator") return parent.id.name;
    if (parent?.type === "StructProperty") return parent.key.type === "Identifier" ? parent.key.name : parent.key.value;
    return void 0;
  }
  recordMemberWrite(target, owner) {
    if (target.type === "MemberExpression") {
      const name = target.property.name;
      if (target.object.type === "Identifier" && target.object.name === "global") this.globalVariables.add(name);
      else {
        this.assignedNames.add(name);
        if (owner && target.object.type === "Identifier" && target.object.name === "self") this.instanceVars(owner).add(name);
      }
    } else if (target.type === "IndexExpression" && target.accessor === "$") {
      const key = target.indices[0];
      if (key?.type === "StringLiteral") {
        if (target.object.type === "Identifier" && target.object.name === "global") this.globalVariables.add(key.value);
        else this.assignedNames.add(key.value);
      } else if (target.object.type === "Identifier" && (target.object.name === "self" || target.object.name === "global" || target.object.name === "id")) {
        this.usesDynamicVariableNames = true;
      }
    }
  }
  recordCall(call) {
    if (call.callee.type !== "Identifier") return;
    const name = call.callee.name;
    const setter = VARIABLE_SETTERS[name];
    if (setter) {
      const arg = call.arguments[setter.nameArg];
      if (arg?.type === "StringLiteral") {
        if (setter.global) this.globalVariables.add(arg.value);
        else this.assignedNames.add(arg.value);
      } else if (arg) {
        this.usesDynamicVariableNames = true;
      }
    }
    if (DYNAMIC_ASSET_LOOKUPS.has(name)) {
      const arg = call.arguments[name === "script_execute_ext" || name === "method_call" ? 0 : name.startsWith("variable_instance") || name.includes("struct") ? 1 : 0];
      if (arg && arg.type !== "StringLiteral" && arg.type !== "Identifier") this.usesDynamicAssetNames = true;
      if (arg?.type === "Identifier" && name === "asset_get_index") this.usesDynamicAssetNames = true;
    }
  }
  /** Names that resolve globally without any declaration in the file. */
  isKnownGlobal(name) {
    return isBuiltinIdentifier(name) || isBuiltinFunction(name) || isArgumentVariable(name) || this.globalFunctions.has(name) || this.assets.has(name) || this.macros.has(name) || this.enums.has(name) || this.project.extensionFunctions.has(name) || this.project.extensionConstants.has(name) || this.project.roomInstances.has(name) || this.globalVariables.has(name);
  }
  /** Callable without a local/instance binding: builtins, script functions, scripts, extensions. */
  isKnownFunction(name) {
    return isBuiltinFunction(name) || this.globalFunctions.has(name) || this.assets.get(name) === "scripts" || this.project.extensionFunctions.has(name);
  }
  /** Resolves a call target by name to project functions (global first, then methods of the object). */
  resolveFunction(name, file) {
    const globals = this.globalFunctions.get(name);
    if (globals) return globals;
    if (file.kind !== "object-event") return [];
    return this.methodsByObject.get(file.resource)?.get(name) ?? [];
  }
};
function push(map, key, value) {
  const list = map.get(key);
  if (list) list.push(value);
  else map.set(key, [value]);
}

// src/rules/util.ts
var LOOP_TYPES = /* @__PURE__ */ new Set(["WhileStatement", "DoUntilStatement", "RepeatStatement", "ForStatement"]);
var FUNCTION_TYPES = /* @__PURE__ */ new Set(["FunctionDeclaration", "FunctionExpression"]);
var SENSITIVE_NAME = /(pass(word|wd|phrase)?|pwd|secret|api_?key|apikey|access_?key|private_?key|auth(_?token)?|token|session_?(id|key|token)|credential|client_?secret|bearer|jwt|webhook)/i;
var NOT_SENSITIVE_NAME = /(key(board|code|_?press|_?check|_?up|_?down|_?left|_?right|_?count|frame|_?map|_?index|_?name|s_?held)|token_?(count|index|type|list|pos)|passive|pass_?(through|count|index)|bypass|compass|password_?(length|field|box|input|prompt|label|hint|min|max)|_?public_?key)/i;
function isSensitiveName(name) {
  return SENSITIVE_NAME.test(name) && !NOT_SENSITIVE_NAME.test(name);
}
function isInLoop(ancestors) {
  for (let i = ancestors.length - 1; i >= 0; i--) {
    const t = ancestors[i].type;
    if (FUNCTION_TYPES.has(t)) return false;
    if (LOOP_TYPES.has(t)) return true;
  }
  return false;
}
function staticString(expr, index, depth = 0) {
  if (!expr || depth > 8) return void 0;
  switch (expr.type) {
    case "StringLiteral":
      return expr.value;
    case "TemplateString":
      return expr.expressions.length === 0 ? expr.quasis[0] : void 0;
    case "BinaryExpression":
      if (expr.operator === "+") {
        const l = staticString(expr.left, index, depth + 1);
        const r = staticString(expr.right, index, depth + 1);
        return l !== void 0 && r !== void 0 ? l + r : void 0;
      }
      return void 0;
    case "Identifier": {
      const macro = index.macros.get(expr.name);
      if (macro?.length === 1 && macro[0].node.value) return staticString(macro[0].node.value, index, depth + 1);
      return void 0;
    }
    default:
      return void 0;
  }
}
function staticPrefix(expr, index, depth = 0) {
  if (!expr || depth > 8) return void 0;
  const full = staticString(expr, index, depth);
  if (full !== void 0) return full;
  if (expr.type === "BinaryExpression" && expr.operator === "+") return staticPrefix(expr.left, index, depth + 1);
  if (expr.type === "TemplateString") return expr.quasis[0];
  return void 0;
}
function staticType(expr, ctx, depth = 0) {
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
      return expr.operator === "-" || expr.operator === "+" || expr.operator === "~" ? staticType(expr.argument, ctx, depth + 1) === "number" ? "number" : "unknown" : "unknown";
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
var numericVarCache = /* @__PURE__ */ new WeakMap();
function numericInstanceVars(index) {
  const cached = numericVarCache.get(index);
  if (cached) return cached;
  const numeric = /* @__PURE__ */ new Set();
  const poisoned = /* @__PURE__ */ new Set();
  for (const obj of index.project.objects.values()) for (const p of obj.properties) poisoned.add(p);
  const isNumber = (e) => {
    switch (e.type) {
      case "NumberLiteral":
        return true;
      case "UnaryExpression":
        return (e.operator === "-" || e.operator === "+") && isNumber(e.argument);
      case "BinaryExpression":
        return ["-", "*", "/", "%", "div"].includes(e.operator) || e.operator === "+" && isNumber(e.left) && isNumber(e.right);
      case "CallExpression": {
        if (e.callee.type !== "Identifier" || index.globalFunctions.has(e.callee.name)) return false;
        const fn = getBuiltinFunction(e.callee.name);
        return fn?.returnType === "Real";
      }
      default:
        return false;
    }
  };
  const record = (name, value, op) => {
    if (poisoned.has(name)) return;
    const ok = op === "-=" || op === "*=" || op === "/=" || op === "%=" || op === "++" || op === "--" || (op === "=" || op === "+=") && value !== null && isNumber(value);
    if (ok) numeric.add(name);
    else {
      poisoned.add(name);
      numeric.delete(name);
    }
  };
  const nameOf = (t) => t.type === "Identifier" ? t.name : t.type === "MemberExpression" ? t.property.name : void 0;
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
      }
    });
  }
  for (const name of numeric) if (index.stringLiterals.has(name)) numeric.delete(name);
  numericVarCache.set(index, numeric);
  return numeric;
}
function localType(_name, decl, ctx, depth) {
  if (decl.kind !== "var") return "unknown";
  const declarator = findDeclarator(decl.id, ctx.scopes);
  if (!declarator?.init) return "unknown";
  const t = staticType(declarator.init, ctx, depth + 1);
  if (t === "unknown") return t;
  for (const w of decl.writes) {
    const assign = writeValue(w.id, ctx.scopes);
    if (!assign) return "unknown";
    if (assign.operator === "+=" && t === "string") continue;
    if (assign.operator !== "=" || staticType(assign.right, ctx, depth + 1) !== t) return "unknown";
  }
  return t;
}
var declaratorCache = /* @__PURE__ */ new WeakMap();
var writeCache = /* @__PURE__ */ new WeakMap();
function buildCaches(scopes) {
  const decls = /* @__PURE__ */ new Map();
  const writes = /* @__PURE__ */ new Map();
  walk(scopes.root.node, (n) => {
    if (n.type === "VarDeclarator") decls.set(n.id, n);
    else if (n.type === "AssignmentExpression" && n.left.type === "Identifier") writes.set(n.left, n);
  });
  declaratorCache.set(scopes, decls);
  writeCache.set(scopes, writes);
}
function findDeclarator(id, scopes) {
  if (!declaratorCache.has(scopes)) buildCaches(scopes);
  return declaratorCache.get(scopes).get(id);
}
function writeValue(id, scopes) {
  if (!writeCache.has(scopes)) buildCaches(scopes);
  return writeCache.get(scopes).get(id);
}
function sameExpression(a, b) {
  if (a.type !== b.type) return false;
  switch (a.type) {
    case "Identifier":
      return a.name === b.name;
    case "NumberLiteral":
      return a.value === b.value;
    case "StringLiteral":
      return a.value === b.value;
    case "BooleanLiteral":
      return a.value === b.value;
    case "MemberExpression": {
      const o = b;
      return a.property.name === o.property.name && sameExpression(a.object, o.object);
    }
    case "IndexExpression": {
      const o = b;
      return a.accessor === o.accessor && a.indices.length === o.indices.length && sameExpression(a.object, o.object) && a.indices.every((x, i) => sameExpression(x, o.indices[i]));
    }
    case "UnaryExpression": {
      const o = b;
      return a.operator === o.operator && sameExpression(a.argument, o.argument);
    }
    case "BinaryExpression": {
      const o = b;
      return a.operator === o.operator && sameExpression(a.left, o.left) && sameExpression(a.right, o.right);
    }
    case "CallExpression": {
      const o = b;
      return a.arguments.length === o.arguments.length && sameExpression(a.callee, o.callee) && a.arguments.every((x, i) => sameExpression(x, o.arguments[i]));
    }
    default:
      return false;
  }
}
function isSideEffectFree(expr) {
  let pure = true;
  walk(expr, (n, c) => {
    if (n.type === "CallExpression" || n.type === "NewExpression" || n.type === "UpdateExpression" || n.type === "AssignmentExpression") {
      pure = false;
      c.skip();
    } else if (n.type === "FunctionExpression") c.skip();
  });
  return pure;
}
function normalizeSelf(expr) {
  if (expr.type === "MemberExpression" && expr.object.type === "Identifier" && expr.object.name === "self") return expr.property;
  return expr;
}
function describeEvent(file) {
  if (file.event) return `the ${file.event.displayName} event of \`${file.resource}\``;
  return `\`${file.resource}\``;
}
function builtinCallName(call, ctx) {
  if (call.callee.type !== "Identifier") return void 0;
  const ref = ctx.scopes.refOf.get(call.callee);
  if (ref && ref.binding.kind !== "free") return void 0;
  return call.callee.name;
}
function code(s) {
  return "`" + s + "`";
}

// src/rules/correctness.ts
var plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;
var undefinedFunction = {
  meta: {
    id: "gml/undefined-function",
    name: "UndefinedFunction",
    category: "correctness",
    severity: "error",
    precision: "high",
    tier: "default",
    short: "Call to a function that does not exist.",
    full: "The called name is not a built-in function, a script function, an extension function, or a variable holding a method anywhere in the project. GameMaker will fail to compile or throw at runtime.",
    help: `A function is called that cannot be found anywhere in the project: it is not a GameMaker built-in (for the runtimes this scanner knows), not declared with \`function\` in a script, not an extension function, and no variable with that name is ever assigned (which rules out method variables).

This is usually a typo, a function that was renamed or deleted, or a GameMaker Studio 1.x function that no longer exists.

**How to fix:** correct the name, restore the missing script, or replace the legacy call with its modern equivalent.

\`\`\`gml
// Bad
instance_create(x, y, obj_bullet);      // removed in GameMaker Studio 2
scr_playr_hurt(10);                     // typo

// Good
instance_create_layer(x, y, "Instances", obj_bullet);
scr_player_hurt(10);
\`\`\``
  },
  file(ctx) {
    if (!ctx.index.project.yyp) return;
    const reported = /* @__PURE__ */ new Set();
    const check = (callee, isNew) => {
      if (callee.type !== "Identifier") return;
      const name = callee.name;
      const ref = ctx.scopes.refOf.get(callee);
      if (!ref || ref.binding.kind !== "free" || reported.has(name)) return;
      const { index } = ctx;
      if (index.isKnownFunction(name) || index.isKnownGlobal(name) || index.assignedNames.has(name)) return;
      if (ctx.config.globalPrefixes.some((p) => name.startsWith(p))) return;
      reported.add(name);
      const legacy = LEGACY_REPLACEMENTS[name];
      const message = legacy ? `${code(name)} was removed in GameMaker Studio 2; use ${legacy} instead.` : `Undefined ${isNew ? "constructor" : "function"} ${code(name)}: no built-in, script function, extension function or method variable has this name.`;
      ctx.report(callee, message);
    };
    return {
      CallExpression: (n) => check(n.callee, false),
      NewExpression: (n) => check(n.callee, true)
    };
  }
};
var runtimeUnavailableFunction = {
  meta: {
    id: "gml/runtime-unavailable",
    name: "RuntimeUnavailable",
    category: "correctness",
    severity: "error",
    precision: "very-high",
    tier: "default",
    short: "Built-in function does not exist in the project's target runtime.",
    full: "The function exists in some GameMaker runtime, but not in the runtime this project targets (from the .yyp IDEVersion or the `runtime` setting).",
    help: `The project targets a GameMaker runtime (read from \`MetaData.IDEVersion\` in the .yyp, or the \`runtime\` config option) in which this function does not exist. It was either added in a later release or removed.

**How to fix:** upgrade the project's runtime, or use an alternative available in your runtime. If the target runtime is wrong, set \`"runtime"\` in \`.gmlscan.json\`.`
  },
  file(ctx) {
    const rt = ctx.index.runtimeIndex;
    if (rt < 0) return;
    return {
      CallExpression(n) {
        if (n.callee.type !== "Identifier") return;
        const ref = ctx.scopes.refOf.get(n.callee);
        if (ref && ref.binding.kind !== "free") return;
        const fn = getBuiltinFunction(n.callee.name);
        if (!fn || availableInRuntime(fn.runtimeMask, rt) || ctx.index.globalFunctions.has(fn.name) || ctx.index.assignedNames.has(fn.name)) return;
        ctx.report(n.callee, `${code(fn.name)} is not available in GameMaker runtime ${KNOWN_RUNTIMES[rt]} (this project's target).`);
      }
    };
  }
};
function jsdocOptionalParams(fn) {
  const out = /* @__PURE__ */ new Set();
  const text = fn.file.source.text;
  let i = fn.node.start;
  const lines = [];
  while (i > 0) {
    const lineStart = text.lastIndexOf("\n", i - 2) + 1;
    const line = text.slice(lineStart, i).trim();
    if (!line.startsWith("//")) break;
    lines.push(line);
    i = lineStart;
  }
  for (const l of lines) {
    const m = /@(?:param|arg|argument)\s+(?:\{[^}]*\}\s*)?\[([A-Za-z_]\w*)/.exec(l);
    if (m) out.add(m[1]);
  }
  return out;
}
function handlesMissingArgument(fn, param) {
  let handled = false;
  walk(fn.node.body, (n, c) => {
    if (handled) return c.skip();
    if (n.type === "Identifier" && n.name === "argument_count") handled = true;
    else if (n.type === "CallExpression" && n.callee.type === "Identifier" && n.callee.name === "is_undefined" && n.arguments[0]?.type === "Identifier" && n.arguments[0].name === param) handled = true;
    else if (n.type === "BinaryExpression" && (n.operator === "??" || n.operator === "==" || n.operator === "!=")) {
      const sides = [n.left, n.right];
      if (sides.some((s) => s.type === "Identifier" && s.name === param) && (n.operator === "??" || sides.some((s) => s.type === "Identifier" && s.name === "undefined"))) handled = true;
    } else if (n.type === "AssignmentExpression" && n.operator === "??=" && n.left.type === "Identifier" && n.left.name === param) handled = true;
  });
  return handled;
}
var wrongArgumentCount = {
  meta: {
    id: "gml/wrong-argument-count",
    name: "WrongArgumentCount",
    category: "correctness",
    severity: "error",
    precision: "high",
    tier: "default",
    short: "Function called with the wrong number of arguments.",
    full: "Built-in functions reject calls with too few or too many arguments at compile time. For script functions, extra arguments are silently ignored and missing required ones arrive as `undefined`.",
    help: `GameMaker checks argument counts for built-in functions: calling one with too few or too many arguments is a compile error.

For your own functions, extra arguments are ignored (unless the function reads \`argument[n]\`), and missing arguments become \`undefined\`, which usually causes a crash later. A parameter counts as optional when it has a default value (\`function f(a, b = 0)\`), is documented as optional (\`/// @param [b]\`), or the function checks it with \`is_undefined\`, \`??\` or \`argument_count\`.

\`\`\`gml
// Bad
draw_text(x, y);                 // missing the string argument
scr_damage(other, 10, true);     // scr_damage(target, amount) ignores "true"

// Good
draw_text(x, y, "Hello");
scr_damage(other, 10);
\`\`\``
  },
  file(ctx) {
    const checkCall = (n) => {
      if (n.callee.type !== "Identifier") return;
      const name = n.callee.name;
      const ref = ctx.scopes.refOf.get(n.callee);
      if (!ref || ref.binding.kind !== "free") return;
      const argc = n.arguments.length;
      const { index } = ctx;
      const userFns = index.globalFunctions.get(name);
      if (!userFns && n.type === "CallExpression" && !index.assignedNames.has(name)) {
        const fn2 = getBuiltinFunction(name);
        if (fn2) {
          if (argc < fn2.minArgs) ctx.report(n, `Missing required argument for function ${code(name)}: expected at least ${plural(fn2.minArgs, "argument")}, got ${argc}.`);
          else if (fn2.maxArgs >= 0 && argc > fn2.maxArgs) ctx.report(n.arguments[fn2.maxArgs], `Too many arguments for function ${code(name)}: expected at most ${fn2.maxArgs}, got ${argc}.`);
          return;
        }
        const ext = index.project.extensionFunctions.get(name);
        if (ext && ext.argCount >= 0 && argc !== ext.argCount) {
          ctx.report(n, `Extension function ${code(name)} is declared with ${plural(ext.argCount, "argument")} in ${ext.extension}, but called with ${argc}.`, { severity: "note" });
        }
        return;
      }
      if (!userFns || userFns.length !== 1) return;
      const fn = userFns[0];
      const params = fn.node.params;
      if (argc > params.length && !fn.scope.usesArguments) {
        ctx.report(n.arguments[params.length], `Extra argument for function ${code(name)}: it declares ${plural(params.length, "parameter")} but is called with ${argc}.`, { severity: "warning" });
        return;
      }
      if (argc < params.length) {
        const optional = jsdocOptionalParams(fn);
        const missing = params.slice(argc).find((p) => !p.init && !optional.has(p.id.name) && !handlesMissingArgument(fn, p.id.name));
        if (missing) ctx.report(n, `Missing required argument ${code(missing.id.name)} for function ${code(name)}.`, { severity: "warning" });
      }
    };
    return { CallExpression: checkCall, NewExpression: checkCall };
  }
};
var deprecatedFunction = {
  meta: {
    id: "gml/deprecated",
    name: "DeprecatedBuiltin",
    category: "correctness",
    severity: "warning",
    precision: "very-high",
    tier: "default",
    short: "Use of a deprecated or obsolete built-in.",
    full: "The built-in function or variable is marked obsolete by GameMaker and may be removed or behave differently in newer runtimes.",
    help: `GameMaker marks this function or variable as obsolete. Obsolete built-ins may be removed in future runtimes, are often slower, and are hidden from autocomplete.

**How to fix:** switch to the replacement listed in the GameMaker manual. Common ones:

| Obsolete | Replacement |
| --- | --- |
| \`array_length_1d(a)\` | \`array_length(a)\` |
| \`array_height_2d(a)\` | \`array_length(a)\` |
| \`room_speed\` | \`game_get_speed(gamespeed_fps)\` / \`game_set_speed()\` |
| \`view_xview[0]\` | \`camera_get_view_x(view_camera[0])\` |
| \`draw_set_blend_mode\` | \`gpu_set_blendmode\` |`
  },
  file(ctx) {
    const first = /* @__PURE__ */ new Map();
    const add2 = (node, message) => {
      const entry = first.get(node.name);
      if (entry) entry.count++;
      else first.set(node.name, { node, message, count: 1 });
    };
    return {
      "file:exit"() {
        for (const e of first.values()) ctx.report(e.node, e.count > 1 ? `${e.message} (${e.count} uses in this file)` : e.message);
      },
      Identifier(n) {
        const ref = ctx.scopes.refOf.get(n);
        if (!ref || ref.binding.kind !== "free" || ref.inMacro) return;
        const name = n.name;
        const { index } = ctx;
        if (index.globalFunctions.has(name) || index.macros.has(name) || index.assets.has(name)) return;
        if (ref.isCallee) {
          const fn = getBuiltinFunction(name);
          if (!fn?.deprecated || index.assignedNames.has(name)) return;
          if (!availableInRuntime(fn.runtimeMask, index.runtimeIndex)) return;
          const alt = LEGACY_REPLACEMENTS[name];
          add2(n, `${code(name)} is deprecated${alt ? `; use ${alt} instead` : ""}.`);
        } else {
          const v = getBuiltinVariable(name);
          if (!v?.deprecated || index.assignedNames.has(name) || index.globalVariables.has(name)) return;
          const alt = LEGACY_REPLACEMENTS[name];
          add2(n, `Built-in variable ${code(name)} is deprecated${alt ? `; use ${alt} instead` : ""}.`);
        }
      }
    };
  }
};
var OBJECT_ASSET = "objects";
var ASSET_PREFIXES = [
  ["spr_", "sprite"],
  ["obj_", "object"],
  ["snd_", "sound"],
  ["sfx_", "sound"],
  ["mus_", "sound"],
  ["rm_", "room"],
  ["fnt_", "font"],
  ["shd_", "shader"],
  ["sh_", "shader"],
  ["scr_", "script"],
  ["bg_", "sprite"],
  ["ts_", "tile set"],
  ["tl_", "timeline"],
  ["seq_", "sequence"],
  ["pth_", "path"]
];
var undefinedVariable = {
  meta: {
    id: "gml/undefined-variable",
    name: "UndeclaredVariable",
    category: "correctness",
    severity: "warning",
    precision: "high",
    tier: "default",
    short: "Variable is read but never assigned anywhere in the project.",
    full: 'Reading a variable that is never set crashes with "variable not set before reading it". The name is not a local, built-in, asset, macro, enum, or any instance/struct/global variable assigned anywhere in the project.',
    help: `This variable is read, but nothing in the project ever assigns it: not as a local (\`var\`), an instance or struct variable, an object Variable Definition, a \`global.\` variable, a macro, an enum or an asset. At runtime GameMaker stops with *"variable ... not set before reading it"*.

It is usually a typo or a variable that was renamed in one place but not another.

**How to fix:** fix the spelling, or initialise the variable (usually in the Create event).

\`\`\`gml
// Create event
move_speed = 4;

// Step event (bad: typo)
x += move_sped;

// Step event (good)
x += move_speed;
\`\`\`

If your project defines globals by naming convention (for example everything prefixed \`g_\`), add the prefix to \`globalPrefixes\` in \`.gmlscan.json\`.`
  },
  file(ctx) {
    if (!ctx.index.project.yyp) return;
    const reported = /* @__PURE__ */ new Set();
    const { index } = ctx;
    const known = (name) => index.isKnownGlobal(name) || index.assignedNames.has(name) || ctx.config.globalPrefixes.some((p) => name.startsWith(p)) || index.project.extensionFunctions.has(name);
    return {
      Identifier(n) {
        const ref = ctx.scopes.refOf.get(n);
        if (!ref || ref.binding.kind !== "free" || ref.isCallee || ref.inMacro || ref.access === "write") return;
        if (known(n.name) || reported.has(n.name)) return;
        reported.add(n.name);
        const asset = ASSET_PREFIXES.find(([p]) => n.name.startsWith(p));
        if (asset) ctx.report(n, `${code(n.name)} looks like a ${asset[1]} name, but no ${asset[1]} with this name exists in the project (deleted or renamed?); reading it crashes with "variable not set".`);
        else ctx.report(n, `Undeclared variable ${code(n.name)}: it is read here but never assigned anywhere in the project.`);
      },
      MemberExpression(n) {
        if (n.object.type !== "Identifier") return;
        const parent = ctx.ancestors[ctx.ancestors.length - 1];
        const isWrite = parent?.type === "AssignmentExpression" && parent.left === n && parent.operator === "=";
        if (isWrite) return;
        const base = n.object.name;
        const prop2 = n.property.name;
        const baseRef = ctx.scopes.refOf.get(n.object);
        if (baseRef && baseRef.binding.kind !== "free") return;
        if (base === "global") {
          if (index.globalVariables.has(prop2) || index.usesDynamicVariableNames || getBuiltinVariable(prop2)) return;
          if (reported.has(`global.${prop2}`)) return;
          reported.add(`global.${prop2}`);
          ctx.report(n, `${code(`global.${prop2}`)} is read here but never assigned anywhere in the project.`);
          return;
        }
        if (index.assets.get(base) !== OBJECT_ASSET) return;
        if (index.assignedNames.has(prop2) || getBuiltinVariable(prop2) || isBuiltinFunction(prop2) || index.usesDynamicVariableNames) return;
        const key = `${base}.${prop2}`;
        if (reported.has(key)) return;
        reported.add(key);
        ctx.report(n.property, `${code(key)}: no object assigns a variable named ${code(prop2)}.`);
      }
    };
  }
};
var uncapturedLocal = {
  meta: {
    id: "gml/uncaptured-local",
    name: "UncapturedLocal",
    category: "correctness",
    severity: "warning",
    precision: "very-high",
    tier: "default",
    short: "Nested function uses a local variable of the enclosing function.",
    full: "GML functions do not capture the local (`var`) variables of the function they are defined in. Inside the nested function the name refers to an instance or struct variable instead.",
    help: `GML has no closures. A function or method defined inside another function (for example a callback passed to \`array_foreach\`) **cannot see the outer function's \`var\` locals**. The name inside the callback refers to an instance or struct variable instead, which usually doesn't exist and crashes with *"variable not set before reading it"*.

**How to fix:** pass the value explicitly, bind it with \`method()\`, or keep it in a struct.

\`\`\`gml
// Bad
var total = 0;
array_foreach(scores, function(s) {
    total += s;          // not the local "total"
});

// Good
var ctx = { total: 0 };
array_foreach(scores, method(ctx, function(s) {
    total += s;          // "self" is ctx
}));

// Also good
var total = 0;
for (var i = 0; i < array_length(scores); i++) total += scores[i];
\`\`\``
  },
  file(ctx) {
    const reported = /* @__PURE__ */ new Set();
    return {
      Identifier(n) {
        const ref = ctx.scopes.refOf.get(n);
        if (!ref || ref.binding.kind !== "uncaptured") return;
        const key = `${ref.binding.decl.id.start}:${ref.scope.node.start}`;
        if (reported.has(key)) return;
        reported.add(key);
        const declLine = ctx.locate(ref.binding.decl.id).startLine;
        ctx.report(n, `${code(n.name)} is a local variable of the enclosing function (line ${declLine}), but GML functions don't capture outer locals; here it refers to an instance or struct variable.`, {
          related: [{ location: ctx.locate(ref.binding.decl.id), message: `${code(n.name)} declared here` }]
        });
      }
    };
  }
};
var stringNumberAddition = {
  meta: {
    id: "gml/string-number-addition",
    name: "StringNumberAddition",
    category: "correctness",
    severity: "error",
    precision: "high",
    tier: "default",
    short: "Adding a string and a number throws a runtime error.",
    full: 'GML does not convert numbers to strings when using `+`. Concatenating a string with a number stops the game with "unable to add a number to string".',
    help: `Unlike JavaScript, GML does **not** convert numbers to strings with \`+\`. Adding a string and a number stops the game with *"unable to add a number to string"*.

**How to fix:** convert the number with \`string()\`, or use a template string.

\`\`\`gml
// Bad
draw_text(10, 10, "Score: " + score);
draw_text(10, 30, "X: " + x);

// Good
draw_text(10, 10, "Score: " + string(score));
draw_text(10, 30, $"X: {x}");
\`\`\``
  },
  file(ctx) {
    const check = (node, left, right) => {
      const l = staticType(left, ctx);
      const r = staticType(right, ctx);
      if (l === "string" && r === "number" || l === "number" && r === "string") {
        const num = l === "number" ? left : right;
        ctx.report(node, `Adding a string and a number stops the game with "unable to add a number to string"; wrap the number in string(): ${code(`string(${ctx.file.source.text.slice(num.start, num.end)})`)}.`);
      }
    };
    return {
      BinaryExpression(n) {
        if (n.operator === "+") check(n, n.left, n.right);
      },
      AssignmentExpression(n) {
        if (n.operator === "+=") check(n, n.left, n.right);
      }
    };
  }
};
var unreachableCode = {
  meta: {
    id: "gml/unreachable-code",
    name: "UnreachableCode",
    category: "correctness",
    severity: "warning",
    precision: "very-high",
    tier: "default",
    short: "Code after return/exit/break/continue/throw never runs.",
    full: "Statements that directly follow an unconditional `return`, `exit`, `break`, `continue` or `throw` in the same block can never execute.",
    help: `These statements come directly after an unconditional \`return\`, \`exit\`, \`break\`, \`continue\` or \`throw\`, so they never run. Often this is leftover debug code, or an \`exit\` that was meant to be inside an \`if\`.

\`\`\`gml
// Bad
if (hp <= 0)
    instance_destroy();
    exit;              // runs every time; everything below is dead
x += hspeed;

// Good
if (hp <= 0) {
    instance_destroy();
    exit;
}
x += hspeed;
\`\`\``
  },
  file(ctx) {
    const checkList = (body) => {
      for (let i = 0; i < body.length - 1; i++) {
        if (!isTerminator(body[i])) continue;
        const next = body.slice(i + 1).find((s) => s.type !== "FunctionDeclaration" && s.type !== "MacroDeclaration" && s.type !== "EnumDeclaration" && s.type !== "EmptyStatement" && s.type !== "BreakStatement");
        if (next) ctx.report(next, "Unreachable code: it follows an unconditional exit from this block.");
        return;
      }
    };
    return {
      BlockStatement: (n) => checkList(n.body),
      Program: (n) => checkList(n.body),
      SwitchCase: (n) => checkList(n.body)
    };
  }
};
var emptyStatementBody = {
  meta: {
    id: "gml/empty-statement-body",
    name: "EmptyStatementBody",
    category: "correctness",
    severity: "warning",
    precision: "very-high",
    tier: "default",
    short: "Stray semicolon makes an if/loop body empty.",
    full: "A semicolon directly after `if (...)`, `while (...)`, `for (...)`, `repeat (...)` or `with (...)` becomes the whole body; the following block always runs (or the loop never ends).",
    help: `A semicolon right after the condition is an empty statement, and it becomes the entire body. The block that follows is **not** controlled by the condition.

\`\`\`gml
// Bad: the block always runs
if (keyboard_check_pressed(vk_space)); {
    jump();
}

// Good
if (keyboard_check_pressed(vk_space)) {
    jump();
}
\`\`\``
  },
  file(ctx) {
    const check = (body, what) => {
      if (body?.type === "EmptyStatement") ctx.report(body, `Empty ${what} body: the semicolon ends the statement, so the code after it is not controlled by the ${what}.`);
    };
    return {
      IfStatement: (n) => check(n.consequent, "if"),
      WhileStatement: (n) => check(n.body, "while"),
      ForStatement: (n) => check(n.body, "for"),
      RepeatStatement: (n) => check(n.body, "repeat"),
      WithStatement: (n) => check(n.body, "with")
    };
  }
};
function isAlwaysTrue(e) {
  if (!e) return true;
  return e.type === "BooleanLiteral" && e.value || e.type === "NumberLiteral" && e.value >= 0.5;
}
function isAlwaysFalse(e) {
  return e.type === "BooleanLiteral" && !e.value || e.type === "NumberLiteral" && e.value < 0.5;
}
function loopHasExit(body) {
  let found = false;
  const visit = (node, loopDepth, switchDepth) => {
    if (found) return;
    switch (node.type) {
      case "FunctionDeclaration":
      case "FunctionExpression":
        return;
      case "ReturnStatement":
      case "ExitStatement":
      case "ThrowStatement":
        found = true;
        return;
      case "BreakStatement":
        if (loopDepth === 0 && switchDepth === 0) found = true;
        return;
      case "CallExpression":
        if (node.callee.type === "Identifier" && (node.callee.name === "game_end" || node.callee.name === "game_restart")) found = true;
        break;
    }
    const isLoop = node.type === "WhileStatement" || node.type === "DoUntilStatement" || node.type === "ForStatement" || node.type === "RepeatStatement";
    forEachChild(node, (c) => visit(c, loopDepth + (isLoop ? 1 : 0), switchDepth + (node.type === "SwitchStatement" ? 1 : 0)));
  };
  visit(body, 0, 0);
  return found;
}
var infiniteLoop = {
  meta: {
    id: "gml/infinite-loop",
    name: "InfiniteLoop",
    category: "correctness",
    severity: "error",
    precision: "high",
    tier: "default",
    short: "Loop can never terminate and will freeze the game.",
    full: "The loop condition is always true and the body contains no `break`, `return`, `exit` or `throw`. GameMaker is single-threaded, so the game hangs.",
    help: `The loop condition never becomes false and nothing inside the loop leaves it. GameMaker runs your code on the main thread, so the game freezes and has to be killed.

Note that \`break\` inside a \`switch\` exits the switch, not the surrounding loop.

\`\`\`gml
// Bad
while (true) {
    if (ready) break;   // fine
}
while (true) {
    x += 1;             // freezes
}

// Good: bound the loop or add an exit
repeat (100) { x += 1; }
\`\`\``
  },
  file(ctx) {
    return {
      WhileStatement(n) {
        if (isAlwaysTrue(n.test) && !loopHasExit(n.body)) ctx.report(n.test, "Infinite loop: the condition is always true and the body never breaks out, which freezes the game.");
      },
      ForStatement(n) {
        if (isAlwaysTrue(n.test) && !loopHasExit(n.body)) ctx.report(n.test ?? n, "Infinite loop: this for loop has no terminating condition and the body never breaks out.");
      },
      DoUntilStatement(n) {
        if (isAlwaysFalse(n.test) && !loopHasExit(n.body)) ctx.report(n.test, "Infinite loop: `until` is always false and the body never breaks out.");
      }
    };
  }
};
var selfAssignment = {
  meta: {
    id: "gml/self-assignment",
    name: "SelfAssignment",
    category: "correctness",
    severity: "warning",
    precision: "very-high",
    tier: "default",
    short: "Variable is assigned to itself.",
    full: "Assigning a variable to itself has no effect and usually indicates a typo (for example `x = x` instead of `x = other.x`).",
    help: `\`a = a\` does nothing. This is usually a typo, most often inside \`with\` where \`other.\` was forgotten.

\`\`\`gml
// Bad
with (obj_follower) {
    x = x;
}

// Good
with (obj_follower) {
    x = other.x;
}
\`\`\``
  },
  file(ctx) {
    return {
      AssignmentExpression(n) {
        if (n.operator !== "=") return;
        const l = normalizeSelf(n.left);
        const r = normalizeSelf(n.right);
        if (!sameExpression(l, r) || !isSideEffectFree(n.right)) return;
        ctx.report(n, `${code(ctx.file.source.text.slice(n.left.start, n.left.end))} is assigned to itself; this has no effect.`);
      }
    };
  }
};
var selfComparison = {
  meta: {
    id: "gml/self-comparison",
    name: "SelfComparison",
    category: "correctness",
    severity: "warning",
    precision: "very-high",
    tier: "default",
    short: "Expression is compared with itself.",
    full: "Comparing an expression with itself always gives the same result and usually indicates a copy-paste error.",
    help: `Comparing something with itself is always true (\`==\`, \`<=\`, \`>=\`) or always false (\`!=\`, \`<\`, \`>\`). This is almost always a copy-paste error.

\`\`\`gml
// Bad
if (other.team == other.team) { ... }

// Good
if (team == other.team) { ... }
\`\`\``
  },
  file(ctx) {
    const ops = /* @__PURE__ */ new Set(["==", "!=", "<", "<=", ">", ">="]);
    return {
      BinaryExpression(n) {
        if (!ops.has(n.operator) || !isSideEffectFree(n.left)) return;
        if (!sameExpression(normalizeSelf(n.left), normalizeSelf(n.right))) return;
        const always = n.operator === "==" || n.operator === "<=" || n.operator === ">=";
        ctx.report(n, `Comparing an expression with itself is always ${always ? "true" : "false"}.`);
      }
    };
  }
};
function caseKey(e, text) {
  switch (e.type) {
    case "NumberLiteral":
      return `n:${e.value}`;
    case "StringLiteral":
      return `s:${e.value}`;
    case "BooleanLiteral":
      return `n:${e.value ? 1 : 0}`;
    case "Identifier":
      return `i:${e.name}`;
    case "MemberExpression":
      return `m:${text.slice(e.start, e.end).replace(/\s+/g, "")}`;
    case "UnaryExpression":
      return e.operator === "-" && e.argument.type === "NumberLiteral" ? `n:${-e.argument.value}` : void 0;
    default:
      return void 0;
  }
}
var duplicateCase = {
  meta: {
    id: "gml/duplicate-case",
    name: "DuplicateCase",
    category: "correctness",
    severity: "warning",
    precision: "very-high",
    tier: "default",
    short: "Switch has the same case label twice.",
    full: "Only the first matching case runs; the duplicate case body is unreachable.",
    help: `Two \`case\` labels in the same \`switch\` have the same value. Only the first one can ever match, so the second body is dead code. Usually one of them should be a different value.

\`\`\`gml
switch (state) {
    case STATE.IDLE: ...; break;
    case STATE.IDLE: ...; break;   // Bad: meant STATE.RUN
}
\`\`\``
  },
  file(ctx) {
    return {
      SwitchStatement(n) {
        const seen = /* @__PURE__ */ new Map();
        for (const c of n.cases) {
          if (!c.test) continue;
          const key = caseKey(c.test, ctx.file.source.text);
          if (!key) continue;
          const first = seen.get(key);
          if (first) ctx.report(c.test, `Duplicate case label ${code(ctx.file.source.text.slice(c.test.start, c.test.end))}; only the first case with this value can match.`, { related: [{ location: ctx.locate(first), message: "First occurrence" }] });
          else seen.set(key, c.test);
        }
      }
    };
  }
};
var divisionByZero = {
  meta: {
    id: "gml/division-by-zero",
    name: "DivisionByZero",
    category: "correctness",
    severity: "error",
    precision: "very-high",
    tier: "default",
    short: "Division or modulo by the constant zero.",
    full: 'Dividing by zero (`/`, `div`, `mod`, `%`) stops the game with a "Divide by zero" error.',
    help: `Dividing by the literal \`0\` with \`/\`, \`div\`, \`mod\` or \`%\` stops the game with *"DoDiv :: Divide by zero"* (or DoMod).

**How to fix:** divide by the intended value, or guard the division.`
  },
  file(ctx) {
    const isZero = (e) => e.type === "NumberLiteral" && e.value === 0;
    return {
      BinaryExpression(n) {
        if ((n.operator === "/" || n.operator === "%" || n.operator === "div") && isZero(n.right)) ctx.report(n, `Division by zero (${code(n.rawOperator + " 0")}) stops the game with a runtime error.`);
      },
      AssignmentExpression(n) {
        if ((n.operator === "/=" || n.operator === "%=") && isZero(n.right)) ctx.report(n, `Division by zero (${code(n.operator + " 0")}) stops the game with a runtime error.`);
      }
    };
  }
};
var readonlyAssignment = {
  meta: {
    id: "gml/readonly-assignment",
    name: "ReadonlyAssignment",
    category: "correctness",
    severity: "error",
    precision: "high",
    tier: "default",
    short: "Assignment to a read-only built-in variable or constant.",
    full: "GameMaker rejects assignments to read-only built-in variables (such as `fps`, `id`, `object_index`) and constants.",
    help: `This built-in variable or constant is read-only. GameMaker reports a compile error (or ignores the write, depending on the target).

**How to fix:** use the setter function, if one exists (for example \`game_set_speed()\` instead of writing to \`fps\`), or use a different variable name for your own data.`
  },
  file(ctx) {
    const check = (target) => {
      const t = normalizeSelf(target);
      if (t.type !== "Identifier") return;
      if (t !== target) {
      } else {
        const ref = ctx.scopes.refOf.get(t);
        if (!ref || ref.binding.kind !== "free") return;
      }
      const v = getBuiltinVariable(t.name);
      if (!v || !v.readonly) return;
      if (ctx.index.macros.has(t.name) || ctx.index.enums.has(t.name)) return;
      ctx.report(target, `${code(t.name)} is a read-only built-in ${v.constant ? "constant" : "variable"}.`);
    };
    return {
      AssignmentExpression: (n) => check(n.left),
      UpdateExpression: (n) => check(n.argument)
    };
  }
};
var globalScopeSelf = {
  meta: {
    id: "gml/global-scope-self",
    name: "GlobalScopeSelf",
    category: "correctness",
    severity: "warning",
    precision: "high",
    tier: "default",
    short: "`self`/`other` used in script global scope.",
    full: "Code at the top level of a script (outside any function) runs once at game start in global scope, where `self` and `other` refer to the global struct.",
    help: `Since GameMaker Studio 2.3, code at the top level of a script (outside any \`function\`) runs **once at game start in global scope**. There, \`self\` and \`other\` refer to the global struct, not an instance. That is almost never intended.

**How to fix:** move the code into a function, or use \`global.\` explicitly.

\`\`\`gml
// scr_player (bad): runs once at game start, "self" is global
self.hp = 100;

// good
function player_init() {
    hp = 100;
}
\`\`\``
  },
  file(ctx) {
    if (ctx.file.kind !== "script") return;
    return {
      Identifier(n) {
        if (n.name !== "self" && n.name !== "other") return;
        const ref = ctx.scopes.refOf.get(n);
        if (!ref || ref.binding.kind !== "free" || ref.scope !== ctx.scopes.root || ref.withDepth > 0 || ref.inMacro) return;
        ctx.report(n, `${code(n.name)} refers to the global scope here, which is probably unintentional.`);
      }
    };
  }
};
var CORRECTNESS_RULES = [
  undefinedFunction,
  runtimeUnavailableFunction,
  wrongArgumentCount,
  deprecatedFunction,
  undefinedVariable,
  uncapturedLocal,
  stringNumberAddition,
  unreachableCode,
  emptyStatementBody,
  infiniteLoop,
  selfAssignment,
  selfComparison,
  duplicateCase,
  divisionByZero,
  readonlyAssignment,
  globalScopeSelf
];

// src/rules/gamemaker.ts
var RESOURCE_PAIRS = {
  ds_list_create: ["ds_list_destroy"],
  ds_map_create: ["ds_map_destroy"],
  ds_grid_create: ["ds_grid_destroy"],
  ds_queue_create: ["ds_queue_destroy"],
  ds_stack_create: ["ds_stack_destroy"],
  ds_priority_create: ["ds_priority_destroy"],
  json_decode: ["ds_map_destroy"],
  ds_map_secure_load: ["ds_map_destroy"],
  surface_create: ["surface_free"],
  surface_create_ext: ["surface_free"],
  buffer_create: ["buffer_delete"],
  buffer_load: ["buffer_delete"],
  buffer_base64_decode: ["buffer_delete"],
  buffer_decompress: ["buffer_delete"],
  part_system_create: ["part_system_destroy"],
  part_system_create_layer: ["part_system_destroy"],
  part_type_create: ["part_type_destroy"],
  vertex_create_buffer: ["vertex_delete_buffer"],
  vertex_create_buffer_ext: ["vertex_delete_buffer"],
  vertex_create_buffer_from_buffer: ["vertex_delete_buffer"],
  vertex_create_buffer_from_buffer_ext: ["vertex_delete_buffer"],
  sprite_add: ["sprite_delete"],
  sprite_add_ext: ["sprite_delete"],
  sprite_create_from_surface: ["sprite_delete"],
  sprite_duplicate: ["sprite_delete"],
  audio_create_stream: ["audio_destroy_stream"],
  audio_create_buffer_sound: ["audio_free_buffer_sound"],
  audio_create_sync_group: ["audio_destroy_sync_group"],
  camera_create: ["camera_destroy"],
  camera_create_view: ["camera_destroy"],
  mp_grid_create: ["mp_grid_destroy"],
  path_add: ["path_delete"],
  font_add: ["font_delete"],
  font_add_sprite: ["font_delete"],
  font_add_sprite_ext: ["font_delete"],
  time_source_create: ["time_source_destroy"],
  animcurve_create: ["animcurve_destroy"],
  physics_fixture_create: ["physics_fixture_delete"],
  network_create_socket: ["network_destroy"],
  network_create_socket_ext: ["network_destroy"],
  network_create_server: ["network_destroy"],
  network_create_server_raw: ["network_destroy"]
};
var OWNERSHIP_TRANSFER = /* @__PURE__ */ new Set(["ds_map_add_list", "ds_map_add_map", "ds_map_replace_list", "ds_map_replace_map", "ds_list_mark_as_list", "ds_list_mark_as_map"]);
var ALL_DESTROYERS = new Set(Object.values(RESOURCE_PAIRS).flat());
function tailName(e) {
  if (!e) return void 0;
  if (e.type === "Identifier") return e.name;
  if (e.type === "MemberExpression") return e.property.name;
  return void 0;
}
var releaseCache = /* @__PURE__ */ new WeakMap();
function projectReleases(index) {
  let info = releaseCache.get(index);
  if (info) return info;
  info = { released: /* @__PURE__ */ new Map(), transferred: /* @__PURE__ */ new Set(), surfaceChecked: /* @__PURE__ */ new Set() };
  for (const file of index.project.files) {
    walk(file.ast, (n) => {
      if (n.type !== "CallExpression" || n.callee.type !== "Identifier") return;
      const name = n.callee.name;
      if (ALL_DESTROYERS.has(name)) {
        const t = tailName(n.arguments[0]);
        if (t) {
          const set = info.released.get(name) ?? /* @__PURE__ */ new Set();
          set.add(t);
          info.released.set(name, set);
        }
      } else if (OWNERSHIP_TRANSFER.has(name)) {
        for (const a of n.arguments.slice(1)) {
          const t = tailName(a);
          if (t) info.transferred.add(t);
        }
      } else if (!isBuiltinFunction(name)) {
        for (const a of n.arguments) {
          const t = tailName(a);
          if (t) info.transferred.add(t);
        }
      }
    });
  }
  releaseCache.set(index, info);
  return info;
}
function creatorOf(e) {
  if (e?.type === "CallExpression" && e.callee.type === "Identifier" && Object.hasOwn(RESOURCE_PAIRS, e.callee.name)) return e.callee.name;
  return void 0;
}
function parentMap(root) {
  const parents = /* @__PURE__ */ new Map();
  const visit = (n) => forEachChild(n, (c) => {
    parents.set(c, n);
    visit(c);
  });
  visit(root);
  return parents;
}
var STORING = /* @__PURE__ */ new Set([
  "ds_list_add",
  "ds_list_insert",
  "ds_list_set",
  "ds_list_replace",
  "ds_map_add",
  "ds_map_set",
  "ds_map_replace",
  "ds_grid_set",
  "ds_grid_add",
  "ds_queue_enqueue",
  "ds_stack_push",
  "ds_priority_add",
  "array_push",
  "array_insert",
  "array_set",
  "struct_set",
  "variable_struct_set",
  "variable_instance_set",
  "variable_global_set",
  "method",
  ...OWNERSHIP_TRANSFER
]);
var CONSUMING = /* @__PURE__ */ new Set(["font_add_sprite", "font_add_sprite_ext", "part_type_sprite", "layer_sprite_create", "layer_background_sprite", "sprite_merge", "sprite_assign", "part_system_automatic_draw", "time_source_start"]);
function localEscapes(decl, parents) {
  for (const ref of decl.reads) {
    const p = parents.get(ref.id);
    if (!p) return true;
    if (p.type === "CallExpression" && p.callee !== ref.id && p.callee.type === "Identifier") {
      const fn = p.callee.name;
      if (!isBuiltinFunction(fn) || CONSUMING.has(fn)) return true;
      if (STORING.has(fn) && p.arguments[0] !== ref.id) return true;
      continue;
    }
    if (p.type === "BinaryExpression" && (p.operator === "==" || p.operator === "!=")) continue;
    if (p.type === "UnaryExpression" && p.operator === "!") continue;
    if (p.type === "IfStatement" || p.type === "WhileStatement") continue;
    return true;
  }
  return false;
}
var resourceLeak = {
  meta: {
    id: "gml/resource-leak",
    name: "ResourceLeak",
    category: "correctness",
    severity: "warning",
    precision: "high",
    tier: "default",
    short: "Dynamically created resource is never destroyed.",
    full: "Data structures, surfaces, buffers, sprites and similar resources are not garbage collected. Creating them without a matching destroy/free call leaks memory (every frame, when it happens in a Step or Draw event).",
    help: `GameMaker does **not** garbage-collect data structures (\`ds_list\`, \`ds_map\`, ...), surfaces, buffers, dynamically added sprites, particle systems, vertex buffers and similar resources. Each \`*_create\` needs a matching destroy call, or memory grows until the game crashes. This is worst in Step and Draw events, which run every frame.

| Created with | Free with |
| --- | --- |
| \`ds_list_create\`, \`ds_map_create\`, \`json_decode\` ... | \`ds_list_destroy\`, \`ds_map_destroy\` ... |
| \`surface_create\` | \`surface_free\` |
| \`buffer_create\`, \`buffer_load\` | \`buffer_delete\` |
| \`sprite_add\`, \`sprite_create_from_surface\` | \`sprite_delete\` |
| \`part_system_create\` | \`part_system_destroy\` |

**How to fix:** destroy temporary resources before the function ends. For resources stored in instance variables, free them in the object's **Clean Up** event. Better still, use arrays and structs, which *are* garbage collected.

\`\`\`gml
// Bad: leaks a list every step
var hits = ds_list_create();
instance_place_list(x, y, obj_enemy, hits, false);

// Good
var hits = ds_list_create();
instance_place_list(x, y, obj_enemy, hits, false);
// ...
ds_list_destroy(hits);
\`\`\``
  },
  file(ctx) {
    let parents;
    const perFrame = ctx.file.kind === "object-event" && isPerFrameEvent(ctx.file.event);
    return {
      VarDeclarator(n) {
        const creator = creatorOf(n.init);
        if (!creator) return;
        const ref = findLocal(ctx, n.id);
        if (!ref) return;
        parents ??= parentMap(ctx.file.ast);
        const destroyers = RESOURCE_PAIRS[creator];
        const destroyed = ref.reads.some((r) => {
          const p = parents.get(r.id);
          return p?.type === "CallExpression" && p.callee.type === "Identifier" && destroyers.includes(p.callee.name);
        });
        if (destroyed || localEscapes(ref, parents)) return;
        const inRoot = ctx.enclosingFunction() === null;
        const when = perFrame && inRoot ? " every frame" : " each time this code runs";
        ctx.report(n, `${code(`${creator}()`)} result in local ${code(n.id.name)} is never freed with ${destroyers.map((d) => code(d + "()")).join(" / ")}; this leaks memory${when}.`);
      },
      AssignmentExpression(n) {
        if (n.operator !== "=") return;
        const creator = creatorOf(n.right);
        if (!creator || ctx.file.kind !== "object-event") return;
        let name;
        if (n.left.type === "Identifier") {
          const ref = ctx.scopes.refOf.get(n.left);
          if (!ref || ref.binding.kind !== "free" || ref.withDepth > 0) return;
          name = n.left.name;
        } else if (n.left.type === "MemberExpression" && n.left.object.type === "Identifier" && n.left.object.name === "self") {
          name = n.left.property.name;
        }
        if (!name) return;
        if (ctx.index.project.objects.get(ctx.file.resource)?.persistent) return;
        const rel = projectReleases(ctx.index);
        const destroyers = RESOURCE_PAIRS[creator];
        if (destroyers.some((d) => rel.released.get(d)?.has(name)) || rel.transferred.has(name)) return;
        const where = perFrame && ctx.enclosingFunction() === null ? " This runs every frame, so it leaks continuously." : "";
        ctx.report(n, `${code(name)} holds a ${code(`${creator}()`)} result that is never freed with ${destroyers.map((d) => code(d + "()")).join(" / ")} anywhere in the project; free it in the Clean Up event.${where}`);
      }
    };
  }
};
function findLocal(ctx, id) {
  const scope = scopeContaining(ctx.scopes.root, id);
  const list = scope?.locals.get(id.name);
  return list?.find((d) => d.id === id);
}
function scopeContaining(scope, id) {
  for (const list of scope.locals.values()) if (list.some((d) => d.id === id)) return scope;
  for (const child of scope.children) {
    if (id.start >= child.node.start && id.end <= child.node.end) {
      const found = scopeContaining(child, id);
      if (found) return found;
    }
  }
  return void 0;
}
var SURFACE_USES = {
  surface_set_target: 0,
  surface_set_target_ext: 1,
  surface_get_texture: 0,
  surface_copy: 0,
  surface_copy_part: 0,
  surface_resize: 0,
  surface_getpixel: 0,
  surface_getpixel_ext: 0,
  draw_surface: 0,
  draw_surface_ext: 0,
  draw_surface_part: 0,
  draw_surface_part_ext: 0,
  draw_surface_stretched: 0,
  draw_surface_stretched_ext: 0,
  draw_surface_tiled: 0,
  draw_surface_tiled_ext: 0,
  draw_surface_general: 0
};
var surfaceExistsCheck = {
  meta: {
    id: "gml/surface-exists-check",
    name: "SurfaceWithoutExistsCheck",
    category: "correctness",
    severity: "warning",
    precision: "high",
    tier: "default",
    short: "Surface is used without checking surface_exists().",
    full: "Surfaces live in video memory and can be destroyed at any time (window resize, alt-tab, device loss). Using one that no longer exists crashes the game.",
    help: `Surfaces are **volatile**: the GPU can discard them at any moment, for example when the window is resized or minimised, on alt-tab, or on mobile when the app is backgrounded. Drawing to or with a surface that no longer exists stops the game with an error.

**How to fix:** check \`surface_exists()\` every time before using the surface, and recreate it if needed.

\`\`\`gml
// Draw event
if (!surface_exists(surf)) {
    surf = surface_create(room_width, room_height);
}
surface_set_target(surf);
draw_clear_alpha(c_black, 0);
// ...
surface_reset_target();
draw_surface(surf, 0, 0);
\`\`\``
  },
  file(ctx) {
    const surfaceVars = projectSurfaceVars(ctx.index);
    if (surfaceVars.size === 0) return;
    const checked = /* @__PURE__ */ new Set();
    const createdHere = /* @__PURE__ */ new Map();
    const uses = [];
    return {
      CallExpression(n) {
        if (n.callee.type !== "Identifier") return;
        const fn = n.callee.name;
        if (fn === "surface_exists") {
          const t2 = tailName(n.arguments[0]);
          if (t2) checked.add(t2);
          return;
        }
        if (!Object.hasOwn(SURFACE_USES, fn)) return;
        const arg = n.arguments[SURFACE_USES[fn]];
        const t = tailName(arg);
        if (!t || !surfaceVars.has(t) || !arg) return;
        if (arg.type === "Identifier" && ctx.scopes.refOf.get(arg)?.binding.kind === "local") return;
        uses.push({ name: t, node: n });
      },
      AssignmentExpression(n) {
        if (n.operator === "=" && (creatorOf(n.right) === "surface_create" || creatorOf(n.right) === "surface_create_ext")) {
          const t = tailName(n.left);
          if (t && !createdHere.has(t)) createdHere.set(t, n.start);
        }
      },
      "file:exit"() {
        const reported = /* @__PURE__ */ new Set();
        for (const u of uses) {
          if (checked.has(u.name) || reported.has(u.name)) continue;
          const created = createdHere.get(u.name);
          if (created !== void 0 && created < u.node.start) continue;
          reported.add(u.name);
          ctx.report(u.node, `Surface ${code(u.name)} is used without a ${code("surface_exists()")} check in ${describeEvent(ctx.file)}; surfaces can be lost at any time (resize, alt-tab), which crashes the game.`);
        }
      }
    };
  }
};
var surfaceVarCache = /* @__PURE__ */ new WeakMap();
function projectSurfaceVars(index) {
  let set = surfaceVarCache.get(index);
  if (set) return set;
  set = /* @__PURE__ */ new Set();
  for (const file of index.project.files) {
    walk(file.ast, (n) => {
      if (n.type === "AssignmentExpression" && n.operator === "=" && (creatorOf(n.right) === "surface_create" || creatorOf(n.right) === "surface_create_ext")) {
        const t = tailName(n.left);
        if (t) set.add(t);
      }
    });
  }
  surfaceVarCache.set(index, set);
  return set;
}
var STATE_PAIRS = [
  { open: ["surface_set_target", "surface_set_target_ext"], close: "surface_reset_target", what: "surface target" },
  { open: ["shader_set"], close: "shader_reset", what: "shader" },
  { open: ["gpu_push_state"], close: "gpu_pop_state", what: "GPU state" },
  { open: ["matrix_stack_push"], close: "matrix_stack_pop", what: "matrix stack" },
  { open: ["draw_primitive_begin", "draw_primitive_begin_texture"], close: "draw_primitive_end", what: "primitive" },
  { open: ["vertex_begin"], close: "vertex_end", what: "vertex buffer" },
  { open: ["file_text_open_read", "file_text_open_write", "file_text_open_append", "file_text_open_from_string"], close: "file_text_close", what: "text file" },
  { open: ["file_bin_open"], close: "file_bin_close", what: "binary file" },
  { open: ["ini_open", "ini_open_from_string"], close: "ini_close", what: "INI file" }
];
var unbalancedState = {
  meta: {
    id: "gml/unbalanced-state",
    name: "UnbalancedState",
    category: "correctness",
    severity: "warning",
    precision: "medium",
    tier: "default",
    short: "Begin/end call pair is unbalanced (surface target, shader, file, INI...).",
    full: "Calls such as `surface_set_target`/`surface_reset_target`, `shader_set`/`shader_reset`, `ini_open`/`ini_close` and `file_text_open_*`/`file_text_close` must be balanced within the same event or function.",
    help: `Some GameMaker calls open a state that must be closed again in the same event or function:

| Open | Close | If left open |
| --- | --- | --- |
| \`surface_set_target\` | \`surface_reset_target\` | everything else draws into the surface |
| \`shader_set\` | \`shader_reset\` | the shader applies to all later drawing |
| \`gpu_push_state\` | \`gpu_pop_state\` | the state stack overflows |
| \`ini_open\` | \`ini_close\` | changes are not saved, and the next \`ini_open\` fails |
| \`file_text_open_*\` | \`file_text_close\` | the file handle leaks and the file stays locked |

**How to fix:** make sure every path through the code closes what it opened, including early \`exit\`s.

\`\`\`gml
ini_open("settings.ini");
volume = ini_read_real("audio", "volume", 1);
ini_close();   // required
\`\`\``
  },
  file(ctx) {
    const check = (body, isEventRoot) => {
      const calls = [];
      let callsUserFunction = false;
      walk(body, (n, c) => {
        if (n !== body && (n.type === "FunctionDeclaration" || n.type === "FunctionExpression")) return c.skip();
        if (n.type === "CallExpression" && n.callee.type === "Identifier") {
          calls.push(n);
          if (!isBuiltinFunction(n.callee.name)) callsUserFunction = true;
        }
      });
      if (!isEventRoot || callsUserFunction) return;
      for (const pair of STATE_PAIRS) {
        const opens = calls.filter((c) => pair.open.includes(c.callee.name));
        if (opens.length === 0 || calls.some((c) => c.callee.name === pair.close)) continue;
        const node = opens[0];
        ctx.report(node, `${code(`${node.callee.name}()`)} is never followed by ${code(`${pair.close}()`)} in ${describeEvent(ctx.file)}; the ${pair.what} stays open.`);
      }
    };
    return {
      Program(n) {
        check(n, ctx.file.kind === "object-event");
      }
    };
  }
};
var NON_RENDERING_DRAW = /^draw_(set_|get_|enable_|light|texture_flush|flush|clear)/;
var drawOutsideDrawEvent = {
  meta: {
    id: "gml/draw-outside-draw-event",
    name: "DrawOutsideDrawEvent",
    category: "correctness",
    severity: "warning",
    precision: "high",
    tier: "default",
    short: "Drawing function called outside a Draw event.",
    full: "Drawing functions only have a visible effect in Draw events (or while a surface target is set). Called from Step, Create or Alarm events they do nothing on screen.",
    help: `GameMaker clears and redraws the screen in the Draw events. Drawing calls made in Step, Create, Alarm or other non-Draw events have **no visible effect**, unless a surface target is set with \`surface_set_target()\`.

**How to fix:** move the drawing code into a Draw (or Draw GUI) event, and keep the logic that decides *what* to draw in Step.

\`\`\`gml
// Step event (bad)
draw_text(x, y - 16, name);

// Draw event (good)
draw_self();
draw_text(x, y - 16, name);
\`\`\``
  },
  file(ctx) {
    const file = ctx.file;
    if (file.kind !== "object-event" || !file.event || file.event.kind === "Draw") return;
    let hasSurfaceTarget = false;
    let callsUserFunction = false;
    let first;
    const targetSetters = surfaceTargetFunctions(ctx.index);
    return {
      CallExpression(n) {
        if (n.callee.type !== "Identifier") return;
        const name = n.callee.name;
        if (name === "surface_set_target" || name === "surface_set_target_ext") hasSurfaceTarget = true;
        if (!isBuiltinFunction(name)) {
          if (targetSetters.has(name)) callsUserFunction = true;
          return;
        }
        if (ctx.enclosingFunction() !== null) return;
        if (!first && name.startsWith("draw_") && !NON_RENDERING_DRAW.test(name)) first = n;
      },
      "file:exit"() {
        if (!first || hasSurfaceTarget || callsUserFunction) return;
        const name = first.callee.name;
        ctx.report(first, `${code(`${name}()`)} is called in ${describeEvent(file)}; drawing only shows up in Draw events (or while a surface target is set).`);
      }
    };
  }
};
var surfaceSetterCache = /* @__PURE__ */ new WeakMap();
function surfaceTargetFunctions(index) {
  let set = surfaceSetterCache.get(index);
  if (set) return set;
  set = /* @__PURE__ */ new Set();
  for (const [name, infos] of index.globalFunctions) {
    for (const info of infos) {
      walk(info.node.body, (n) => {
        if (n.type === "CallExpression" && n.callee.type === "Identifier" && n.callee.name.startsWith("surface_set_target")) set.add(name);
      });
    }
  }
  surfaceSetterCache.set(index, set);
  return set;
}
var AUDIO_PLAY = /* @__PURE__ */ new Set(["audio_play_sound", "audio_play_sound_at", "audio_play_sound_on", "audio_play_sound_ext"]);
var INSTANCE_CREATE = /* @__PURE__ */ new Set(["instance_create_layer", "instance_create_depth"]);
function containsExit(node) {
  let found = false;
  walk(node, (n, c) => {
    if (found) return c.skip();
    if (n.type === "FunctionExpression" || n.type === "FunctionDeclaration") return c.skip();
    if (n.type === "ExitStatement" || n.type === "ReturnStatement") found = true;
  });
  return found;
}
var perFrameAction = {
  meta: {
    id: "gml/unconditional-per-frame-action",
    name: "UnconditionalPerFrameAction",
    category: "correctness",
    severity: "warning",
    precision: "high",
    tier: "default",
    short: "Alarm reset, sound or instance creation runs unconditionally every frame.",
    full: "Code at the top level of a Step or Draw event runs 60+ times per second. Setting an alarm there means it never fires; playing a sound or creating an instance there repeats every frame.",
    help: `Step and Draw events run every frame (typically 60 times per second). At the top level of these events, without any condition:

- **\`alarm[n] = ...\`** restarts the alarm every frame, so it **never fires**.
- **\`audio_play_sound(...)\`** starts a new copy of the sound every frame.
- **\`instance_create_*(...)\`** spawns a new instance every frame.

**How to fix:** put the action behind a condition (a key press, a timer, a state change), or move one-time setup to the Create event.

\`\`\`gml
// Step event (bad)
alarm[0] = 60;

// Good: only start the alarm when it isn't already running
if (alarm[0] < 0) alarm[0] = 60;
\`\`\``
  },
  file(ctx) {
    const file = ctx.file;
    if (file.kind !== "object-event" || !(isStepEvent(file.event) || isDrawEvent(file.event))) return;
    return {
      Program(program) {
        const destroysSelf = program.body.some((s) => s.type === "ExpressionStatement" && s.expression.type === "CallExpression" && s.expression.callee.type === "Identifier" && s.expression.callee.name === "instance_destroy" && s.expression.arguments.length === 0);
        for (const stmt of program.body) {
          if (stmt.type === "IfStatement" || stmt.type === "SwitchStatement" || stmt.type === "WithStatement") {
            if (containsExit(stmt)) return;
            continue;
          }
          let expr = null;
          if (stmt.type === "ExpressionStatement") expr = stmt.expression;
          else if (stmt.type === "VarDeclaration" && stmt.declarations.length === 1) expr = stmt.declarations[0].init;
          if (!expr) continue;
          if (expr.type === "AssignmentExpression" && expr.operator === "=" && expr.left.type === "IndexExpression" && expr.left.object.type === "Identifier" && expr.left.object.name === "alarm") {
            const ref = ctx.scopes.refOf.get(expr.left.object);
            if (ref?.binding.kind === "free") ctx.report(expr, `${code("alarm[...]")} is reset unconditionally in ${describeEvent(file)}, which runs every frame, so the alarm never fires.`);
            continue;
          }
          const call = expr.type === "AssignmentExpression" ? expr.right : expr;
          if (call.type !== "CallExpression" || call.callee.type !== "Identifier" || destroysSelf) continue;
          const name = call.callee.name;
          if (AUDIO_PLAY.has(name)) ctx.report(call, `${code(`${name}()`)} runs unconditionally in ${describeEvent(file)}, so a new copy of the sound starts every frame.`);
          else if (INSTANCE_CREATE.has(name)) ctx.report(call, `${code(`${name}()`)} runs unconditionally in ${describeEvent(file)}, so a new instance is created every frame.`);
        }
      }
    };
  }
};
var GAMEMAKER_RULES = [resourceLeak, surfaceExistsCheck, unbalancedState, drawOutsideDrawEvent, perFrameAction];

// src/rules/maintainability.ts
var legacyEquality = {
  meta: {
    id: "gml/legacy-equality",
    name: "LegacyEquality",
    category: "maintainability",
    severity: "note",
    precision: "very-high",
    tier: "quality",
    short: "`=` used as a comparison.",
    full: "GML accepts `=` as a comparison inside expressions for backwards compatibility, but it reads like an assignment. Use `==`.",
    help: `GML still accepts a single \`=\` as a comparison inside expressions (for GameMaker 8 compatibility), but it reads like an assignment and hides real mistakes.

\`\`\`gml
if (state = "idle") { ... }    // before
if (state == "idle") { ... }   // after
\`\`\``
  },
  file(ctx) {
    return {
      BinaryExpression(n) {
        if (n.rawOperator === "=") ctx.report(n, "Use `==` for comparisons; `=` here is legacy comparison syntax.");
      }
    };
  }
};
var globalvarDeclaration = {
  meta: {
    id: "gml/globalvar",
    name: "GlobalvarDeclaration",
    category: "maintainability",
    severity: "note",
    precision: "very-high",
    tier: "quality",
    short: "`globalvar` is deprecated.",
    full: "`globalvar` declarations are deprecated. Use the `global.` prefix instead.",
    help: `\`globalvar\` is deprecated. It makes globals indistinguishable from instance variables and may be removed in future versions.

\`\`\`gml
globalvar coins; coins = 0;   // before
global.coins = 0;             // after
\`\`\``
  },
  file(ctx) {
    return {
      VarDeclaration(n) {
        if (n.kind === "globalvar") ctx.report(n, `${code("globalvar")} is deprecated; use ${code(`global.${n.declarations[0]?.id.name ?? "name"}`)} instead.`);
      }
    };
  }
};
var legacyArray2d = {
  meta: {
    id: "gml/legacy-array-2d",
    name: "LegacyArray2D",
    category: "maintainability",
    severity: "note",
    precision: "very-high",
    tier: "quality",
    short: "Legacy `a[i, j]` 2D array syntax.",
    full: "Since GameMaker 2.3 arrays are one-dimensional and nested; `a[i, j]` is legacy syntax for `a[i][j]`.",
    help: `GameMaker 2.3 replaced 2D arrays with arrays of arrays. \`a[i, j]\` still compiles as \`a[i][j]\`, but it is legacy syntax and doesn't work with array functions the way you might expect.

\`\`\`gml
grid[i, j] = 0;    // before
grid[i][j] = 0;    // after
\`\`\``
  },
  file(ctx) {
    return {
      IndexExpression(n) {
        if ((n.accessor === "" || n.accessor === "@") && n.indices.length === 2) ctx.report(n, "Legacy 2D array syntax; write `a[i][j]` instead of `a[i, j]`.");
      }
    };
  }
};
var legacyArguments = {
  meta: {
    id: "gml/legacy-arguments",
    name: "LegacyArgumentVariables",
    category: "maintainability",
    severity: "note",
    precision: "high",
    tier: "quality",
    short: "`argument0`/`argument[n]` used instead of named parameters.",
    full: "Functions declared with `function` can use named parameters, which are clearer and checked by tooling.",
    help: `Named parameters are clearer than \`argument0\`/\`argument[n]\`, can have default values, and let tools check calls.

\`\`\`gml
function scr_damage() { hp -= argument0; }          // before
function scr_damage(amount) { hp -= amount; }       // after
\`\`\`

\`argument_count\` and \`argument[i]\` remain the right tool for genuinely variadic functions.`
  },
  file(ctx) {
    const reported = /* @__PURE__ */ new Set();
    return {
      Identifier(n) {
        if (!/^argument\d+$/.test(n.name)) return;
        const ref = ctx.scopes.refOf.get(n);
        const fn = ctx.enclosingFunction();
        if (!ref || ref.binding.kind !== "free" || !fn || reported.has(fn)) return;
        reported.add(fn);
        ctx.report(n, `${code(n.name)} is legacy; declare named parameters on the function instead.`);
      }
    };
  }
};
var implicitGlobal = {
  meta: {
    id: "gml/implicit-global",
    name: "ImplicitGlobal",
    category: "maintainability",
    severity: "note",
    precision: "high",
    tier: "quality",
    short: "Assignment in script global scope creates a hidden global.",
    full: "Top-level script code runs in global scope, so `name = value` there creates `global.name`, which instances cannot read as `name`.",
    help: `Script code outside any function runs once at game start in **global scope**. A plain assignment there (\`speed_max = 4;\`) creates \`global.speed_max\`. Instances then read \`speed_max\` as their *own* (undefined) instance variable, not the global.

**How to fix:** write \`global.speed_max = 4;\` explicitly (and read it as \`global.speed_max\`), or use a \`#macro\` for constants.`
  },
  file(ctx) {
    if (ctx.file.kind !== "script") return;
    const reported = /* @__PURE__ */ new Set();
    return {
      Identifier(n) {
        const ref = ctx.scopes.refOf.get(n);
        if (!ref || ref.binding.kind !== "free" || ref.access === "read" || ref.scope !== ctx.scopes.root || ref.withDepth > 0 || ref.inMacro) return;
        if (reported.has(n.name) || ctx.index.globalvarNames.has(n.name)) return;
        reported.add(n.name);
        ctx.report(n, `${code(n.name)} is assigned in global scope, which creates ${code(`global.${n.name}`)}; write it as ${code(`global.${n.name}`)} to make that explicit.`);
      }
    };
  }
};
function jsdocParams(text, fnStart) {
  const params = [];
  let i = fnStart;
  while (i > 0) {
    const lineStart = text.lastIndexOf("\n", i - 2) + 1;
    const raw = text.slice(lineStart, i);
    const line = raw.trim();
    if (!line.startsWith("//")) break;
    const m = /@(?:param|arg|argument)\s+(?:\{[^}]*\}\s*)?\[?([A-Za-z_]\w*)/.exec(line);
    if (m) {
      const offset = lineStart + raw.indexOf(m[1], raw.indexOf("@"));
      params.unshift({ name: m[1], start: offset, end: offset + m[1].length });
    }
    i = lineStart;
  }
  return params;
}
var jsdocParamMismatch = {
  meta: {
    id: "gml/jsdoc-param-mismatch",
    name: "JsdocParamMismatch",
    category: "maintainability",
    severity: "note",
    precision: "high",
    tier: "quality",
    short: "JSDoc `@param` does not match the function's parameters.",
    full: "The `/// @param` comments above a function name parameters that differ from the declared ones, which misleads Feather, Stitch and readers.",
    help: `The \`/// @param\` documentation above this function doesn't match its declared parameters. GameMaker's Feather and editor extensions such as Stitch use these comments for autocomplete and type hints, so a stale comment gives wrong hints.

\`\`\`gml
/// @param {Id.Instance} target
/// @param {Real} amount
function scr_damage(target, dmg) { ... }   // "amount" vs "dmg"
\`\`\``
  },
  file(ctx) {
    return {
      FunctionDeclaration(n) {
        const docs = jsdocParams(ctx.file.source.text, n.start);
        if (docs.length === 0 || n.params.length === 0) return;
        for (let i = 0; i < docs.length; i++) {
          const p = n.params[i];
          if (!p) {
            ctx.report(docs[i], `JSDoc documents parameter ${code(docs[i].name)}, but function ${code(n.id.name)} has only ${n.params.length}.`);
            return;
          }
          if (p.id.name !== docs[i].name) {
            ctx.report(docs[i], `Parameter name mismatch: JSDoc says ${code(docs[i].name)} but parameter ${i + 1} of ${code(n.id.name)} is ${code(p.id.name)}.`);
            return;
          }
        }
      }
    };
  }
};
var missingEventInherited = {
  meta: {
    id: "gml/missing-event-inherited",
    name: "MissingEventInherited",
    category: "maintainability",
    severity: "note",
    precision: "medium",
    tier: "quality",
    short: "Child object overrides a parent event without calling event_inherited().",
    full: "When a child object defines an event its parent also defines, the parent's code does not run unless the child calls `event_inherited()`.",
    help: `When a child object defines an event that its parent also defines, the child's version **replaces** the parent's. The parent's code (often initialisation in Create) only runs if the child calls \`event_inherited()\`.

This is sometimes intentional (a full override). If it isn't, add the call:

\`\`\`gml
// obj_enemy_bat, Create event
event_inherited();   // runs obj_enemy's Create first
flying = true;
\`\`\``
  },
  project(ctx) {
    const { project } = ctx;
    const eventKey = (f) => f.event ? `${f.event.kind}_${f.event.collisionObject ?? f.event.num}` : "";
    for (const obj of project.objects.values()) {
      if (!obj.parent) continue;
      for (const ev of obj.events) {
        if (!ev.event || ev.event.kind !== "Create") continue;
        const key = eventKey(ev);
        let ancestor = project.objects.get(obj.parent);
        const seen = /* @__PURE__ */ new Set();
        let parentHas;
        while (ancestor && !seen.has(ancestor.name)) {
          seen.add(ancestor.name);
          if (ancestor.events.some((e) => eventKey(e) === key)) {
            parentHas = ancestor.name;
            break;
          }
          ancestor = ancestor.parent ? project.objects.get(ancestor.parent) : void 0;
        }
        if (!parentHas) continue;
        let calls = false;
        walk(ev.ast, (n) => {
          if (n.type === "CallExpression" && n.callee.type === "Identifier" && n.callee.name === "event_inherited") calls = true;
        });
        if (calls) continue;
        ctx.report(ctx.locate(ev, { start: 0, end: 0 }), `${code(obj.name)} overrides the ${ev.event.displayName} event of ${code(parentHas)} without calling event_inherited(), so the parent's ${ev.event.displayName} code does not run.`);
      }
    }
  }
};
var unusedLocal = {
  meta: {
    id: "gml/unused-local",
    name: "UnusedLocal",
    category: "maintainability",
    severity: "note",
    precision: "high",
    tier: "quality",
    short: "Local variable is never read.",
    full: "A `var` local is declared (and maybe assigned) but its value is never used.",
    help: `This local variable is never read. Remove it, or use it. An unused local often points to a typo elsewhere, where a similar name is used instead.`
  },
  file(ctx) {
    const visitScope = (scope) => {
      for (const decls of scope.locals.values()) {
        for (const d of decls) {
          if (d.kind !== "var" || d.reads.length > 0 || d.name === "_") continue;
          if (decls.some((o) => o !== d && o.reads.length > 0)) continue;
          ctx.report(d.id, `Unused local variable ${code(d.name)}.`);
        }
      }
      scope.children.forEach(visitScope);
    };
    return { "file:exit": () => visitScope(ctx.scopes.root) };
  }
};
var constantCondition = {
  meta: {
    id: "gml/constant-condition",
    name: "ConstantCondition",
    category: "maintainability",
    severity: "note",
    precision: "high",
    tier: "quality",
    short: "`if` condition is a constant.",
    full: "An `if` whose condition is a literal always takes the same branch; often leftover debug code.",
    help: `An \`if (true)\` / \`if (false)\` / \`if (0)\` always takes the same branch. It is usually leftover debugging code. If you need a debug toggle, use a \`#macro\` so it is clearly intentional:

\`\`\`gml
#macro DEBUG_DRAW false
if (DEBUG_DRAW) { ... }
\`\`\``
  },
  file(ctx) {
    return {
      IfStatement(n) {
        const t = n.test;
        if (t.type === "BooleanLiteral" || t.type === "NumberLiteral") {
          const truthy = t.type === "BooleanLiteral" ? t.value : t.value >= 0.5;
          ctx.report(t, `This condition is always ${truthy ? "true" : "false"}.`);
        }
      }
    };
  }
};
var switchFallthrough = {
  meta: {
    id: "gml/switch-fallthrough",
    name: "SwitchFallthrough",
    category: "correctness",
    severity: "warning",
    precision: "medium",
    tier: "quality",
    short: "Switch case falls through to the next case.",
    full: "A non-empty `case` without `break`, `return`, `exit` or `continue` continues into the next case's code.",
    help: `This \`case\` has code but no \`break\`, so execution continues into the next case. That is a classic source of bugs. If it's intentional, add a \`// fallthrough\` comment to make that clear (this also silences the warning).

\`\`\`gml
switch (dir) {
    case 0: x += 1;          // falls into case 1
    case 1: y += 1; break;
}
\`\`\``
  },
  file(ctx) {
    const comments = ctx.file.ast.comments;
    return {
      SwitchStatement(n) {
        for (let i = 0; i < n.cases.length - 1; i++) {
          const c = n.cases[i];
          if (c.body.length === 0) continue;
          const last = c.body[c.body.length - 1];
          if (isTerminator(last)) continue;
          const next = n.cases[i + 1];
          const annotated = comments.some((cm) => cm.start >= last.end && cm.end <= next.start + 1 && /fall(s)?[\s-]?through/i.test(cm.value));
          if (annotated) continue;
          ctx.report(c.test ?? c, "This case falls through into the next one; add `break` (or a `// fallthrough` comment if intentional).");
        }
      }
    };
  }
};
var duplicateStructKey = {
  meta: {
    id: "gml/duplicate-struct-key",
    name: "DuplicateStructKey",
    category: "correctness",
    severity: "warning",
    precision: "very-high",
    tier: "default",
    short: "Struct literal defines the same key twice.",
    full: "The later value silently overwrites the earlier one.",
    help: `The same key appears twice in a struct literal; the second value silently overwrites the first. One of them is probably misspelled.

\`\`\`gml
var stats = { hp: 10, speed: 2, hp: 12 };   // hp is 12
\`\`\``
  },
  file(ctx) {
    return {
      StructExpression(n) {
        const seen = /* @__PURE__ */ new Map();
        for (const p of n.properties) {
          if (p.type !== "StructProperty") continue;
          const key = p.key.type === "Identifier" ? p.key.name : p.key.value;
          const first = seen.get(key);
          if (first) ctx.report(p.key, `Duplicate struct key ${code(key)}; this value overwrites the earlier one.`, { related: [{ location: ctx.locate(first), message: "First definition" }] });
          else seen.set(key, p.key);
        }
      }
    };
  }
};
var MAINTAINABILITY_RULES = [
  legacyEquality,
  globalvarDeclaration,
  legacyArray2d,
  legacyArguments,
  implicitGlobal,
  jsdocParamMismatch,
  missingEventInherited,
  unusedLocal,
  constantCondition,
  switchFallthrough,
  duplicateStructKey
];

// src/rules/performance.ts
var EXPENSIVE = {};
var add = (names, info) => names.forEach((n) => EXPENSIVE[n] = info);
add(["file_text_open_read", "file_text_open_write", "file_text_open_append", "file_bin_open", "ini_open", "buffer_load", "buffer_save", "buffer_save_ext", "game_save", "game_load", "file_find_first", "directory_exists", "file_exists", "json_load"], {
  severity: "warning",
  why: "touches the disk every frame",
  evenWhenConditional: false
});
add(["sprite_add", "sprite_add_ext", "font_add", "audio_create_stream", "background_add"], {
  severity: "warning",
  why: "loads a file from disk every frame (and leaks the asset unless it is deleted)",
  evenWhenConditional: false
});
add(["surface_getpixel", "surface_getpixel_ext", "draw_getpixel", "draw_getpixel_ext", "buffer_get_surface", "sprite_create_from_surface"], {
  severity: "warning",
  why: "reads pixels back from the GPU every frame, which stalls the rendering pipeline",
  evenWhenConditional: false
});
add(["shader_get_uniform", "shader_get_sampler_index", "shader_get_uniform_buffer", "layer_get_id", "asset_get_index", "layer_get_all_elements", "tag_get_assets", "tag_get_asset_ids"], {
  severity: "note",
  why: "looks up the same handle every frame; look it up once (for example in the Create event) and store it in a variable",
  evenWhenConditional: true
});
add(["json_parse", "json_stringify", "json_decode", "json_encode"], {
  severity: "note",
  why: "parses or serialises JSON every frame",
  evenWhenConditional: false
});
var CONDITIONAL_TYPES = /* @__PURE__ */ new Set(["IfStatement", "SwitchStatement", "ConditionalExpression", "WithStatement"]);
var perFrameExpensiveCall = {
  meta: {
    id: "gml/per-frame-expensive-call",
    name: "PerFrameExpensiveCall",
    category: "performance",
    severity: "warning",
    precision: "high",
    tier: "default",
    short: "Expensive call (disk I/O, GPU readback, handle lookup) every frame.",
    full: "Step and Draw events run every frame. File access, loading assets, reading pixels from surfaces and looking up shader uniforms or layers there costs time on every frame and is a common cause of stutter.",
    help: `Step and Draw events run every frame. Some calls are fine once but expensive every frame:

- **Disk I/O** (\`file_text_open_*\`, \`ini_open\`, \`buffer_load\`, \`sprite_add\` ...): blocks the game while the OS reads or writes.
- **GPU readback** (\`surface_getpixel\`, \`draw_getpixel\`, \`buffer_get_surface\`): forces the CPU to wait for the GPU.
- **Handle lookups** (\`shader_get_uniform\`, \`layer_get_id\`, \`asset_get_index\`): string lookups that always return the same value.
- **JSON** (\`json_parse\`, \`json_stringify\`): allocates heavily.

**How to fix:** do the work once, in the Create event or when something changes, and cache the result.

\`\`\`gml
// Create event
u_time = shader_get_uniform(sh_wave, "u_time");

// Draw event
shader_set(sh_wave);
shader_set_uniform_f(u_time, current_time / 1000);
draw_self();
shader_reset();
\`\`\``
  },
  file(ctx) {
    const file = ctx.file;
    if (file.kind !== "object-event" || !isPerFrameEvent(file.event)) return;
    return {
      CallExpression(n) {
        const name = builtinCallName(n, ctx);
        if (!name || !Object.hasOwn(EXPENSIVE, name) || ctx.enclosingFunction() !== null) return;
        const info = EXPENSIVE[name];
        const conditional = ctx.ancestors.some((a) => CONDITIONAL_TYPES.has(a.type));
        if (conditional && !info.evenWhenConditional) return;
        if (isLazyInit(n, ctx)) return;
        ctx.report(n, `${code(`${name}()`)} in ${describeEvent(file)} ${info.why}.`, { severity: info.severity });
      }
    };
  }
};
function isLazyInit(call, ctx) {
  const parent = ctx.ancestors[ctx.ancestors.length - 1];
  let target;
  if (parent?.type === "AssignmentExpression" && parent.right === call) {
    target = parent.left.type === "Identifier" ? parent.left.name : parent.left.type === "MemberExpression" ? parent.left.property.name : void 0;
  }
  if (!target) return false;
  return ctx.ancestors.some((a) => {
    if (a.type !== "IfStatement") return false;
    let mentions2 = false;
    walk(a.test, (n) => {
      if (n.type === "Identifier" && n.name === target || n.type === "MemberExpression" && n.property.name === target) mentions2 = true;
    });
    return mentions2;
  });
}
var stringCharAtLoop = {
  meta: {
    id: "gml/string-char-at-loop",
    name: "StringCharAtInLoop",
    category: "performance",
    severity: "note",
    precision: "high",
    tier: "default",
    short: "Character-by-character string loop is quadratic.",
    full: "GameMaker strings are UTF-8, so `string_char_at(s, i)` scans from the start of the string on every call. Looping over a string this way takes O(n\xB2) time.",
    help: `GameMaker stores strings as UTF-8, so finding the *i*-th character means scanning from the start of the string. Calling \`string_char_at\` (or \`string_ord_at\`, or \`string_copy(s, i, 1)\`) inside a loop over the string is therefore **O(n\xB2)**. This is noticeable for long strings (dialogue, save files, level data).

**How to fix:** use \`string_foreach()\` (GameMaker 2023.1+), or iterate bytes with \`string_byte_at\` when the text is ASCII.

\`\`\`gml
// Slow
for (var i = 1; i <= string_length(text); i++) {
    var ch = string_char_at(text, i);
}

// Fast
string_foreach(text, function(ch, pos) {
    // ...
});
\`\`\``
  },
  file(ctx) {
    const hasForeach = (() => {
      const fn = getBuiltinFunction("string_foreach");
      return !!fn && availableInRuntime(fn.runtimeMask, ctx.index.runtimeIndex);
    })();
    const reported = /* @__PURE__ */ new Set();
    return {
      CallExpression(n) {
        const name = builtinCallName(n, ctx);
        if (name !== "string_char_at" && name !== "string_ord_at" && !(name === "string_copy" && n.arguments[2]?.type === "NumberLiteral" && n.arguments[2].value === 1)) return;
        const loop = innermostLoop(ctx.ancestors);
        if (!loop || reported.has(loop)) return;
        const counter = loopCounter(loop);
        if (!counter || !mentions(n.arguments[1], counter)) return;
        reported.add(loop);
        const fix = hasForeach ? "use string_foreach()" : "iterate bytes with string_byte_at() for ASCII text";
        ctx.report(n, `${code(`${name}()`)} indexed by the loop counter makes this loop O(n\xB2) on UTF-8 strings; ${fix}.`);
      }
    };
  }
};
function innermostLoop(ancestors) {
  for (let i = ancestors.length - 1; i >= 0; i--) {
    if (FUNCTION_TYPES.has(ancestors[i].type)) return void 0;
    if (LOOP_TYPES.has(ancestors[i].type)) return ancestors[i];
  }
  return void 0;
}
function loopCounter(loop) {
  if (loop.type === "ForStatement" && loop.init) {
    if (loop.init.type === "VarDeclaration") return loop.init.declarations[0]?.id.name;
    if (loop.init.type === "ExpressionStatement" && loop.init.expression.type === "AssignmentExpression" && loop.init.expression.left.type === "Identifier") return loop.init.expression.left.name;
  }
  if (loop.type === "WhileStatement" || loop.type === "RepeatStatement" || loop.type === "DoUntilStatement") {
    let counter;
    walk(loop, (n) => {
      if (!counter && n.type === "UpdateExpression" && n.argument.type === "Identifier") counter = n.argument.name;
      if (!counter && n.type === "AssignmentExpression" && (n.operator === "+=" || n.operator === "-=") && n.left.type === "Identifier") counter = n.left.name;
    });
    return counter;
  }
  return void 0;
}
function mentions(expr, name) {
  if (!expr) return false;
  let found = false;
  walk(expr, (n) => {
    if (n.type === "Identifier" && n.name === name) found = true;
  });
  return found;
}
var instanceNumberExists = {
  meta: {
    id: "gml/instance-number-as-exists",
    name: "InstanceNumberAsExists",
    category: "performance",
    severity: "note",
    precision: "very-high",
    tier: "default",
    short: "`instance_number(obj) > 0` should be `instance_exists(obj)`.",
    full: "`instance_number` counts every instance, while `instance_exists` stops at the first one found.",
    help: `\`instance_number(obj) > 0\` counts **all** instances of the object just to learn whether there is at least one. \`instance_exists(obj)\` stops at the first match, and reads better.

\`\`\`gml
// Before
if (instance_number(obj_enemy) > 0) { ... }
if (instance_number(obj_enemy) == 0) { ... }

// After
if (instance_exists(obj_enemy)) { ... }
if (!instance_exists(obj_enemy)) { ... }
\`\`\``
  },
  file(ctx) {
    const isCount = (e) => e.type === "CallExpression" && builtinCallName(e, ctx) === "instance_number";
    const num = (e) => e.type === "NumberLiteral" ? e.value : void 0;
    return {
      BinaryExpression(n) {
        let call;
        let op = n.operator;
        let value;
        if (isCount(n.left)) {
          call = n.left;
          value = num(n.right);
        } else if (isCount(n.right)) {
          call = n.right;
          value = num(n.left);
          op = { "<": ">", ">": "<", "<=": ">=", ">=": "<=" }[op] ?? op;
        }
        if (!call || value === void 0) return;
        const exists = op === ">" && value === 0 || op === ">=" && value === 1 || op === "!=" && value === 0;
        const notExists = op === "==" && value === 0 || op === "<" && value === 1 || op === "<=" && value === 0;
        if (!exists && !notExists) return;
        const arg = ctx.file.source.text.slice(call.arguments[0]?.start ?? call.start, call.arguments[0]?.end ?? call.end);
        ctx.report(n, `Use ${code(`${notExists ? "!" : ""}instance_exists(${arg})`)} instead of counting every instance with instance_number().`);
      }
    };
  }
};
var LENGTH_FUNCTIONS = /* @__PURE__ */ new Set(["array_length", "ds_list_size", "ds_map_size", "string_length", "ds_grid_width", "ds_grid_height", "ds_queue_size", "ds_stack_size", "ds_priority_size", "buffer_get_size", "instance_number", "struct_names_count", "variable_struct_names_count"]);
var MUTATORS = /^(array_(push|insert|delete|pop|shift|resize|copy|sort|reverse|filter_ext|map_ext|unique_ext)|ds_(list|map|grid|queue|stack|priority)_(add|insert|delete|clear|set|replace|resize|copy|read|enqueue|dequeue|push|pop|delete_min|delete_max|shuffle|sort)|instance_(create_layer|create_depth|destroy|activate|deactivate)|buffer_resize|struct_remove|variable_struct_remove)/;
var loopInvariantLength = {
  meta: {
    id: "gml/loop-invariant-length",
    name: "LoopInvariantLength",
    category: "performance",
    severity: "note",
    precision: "medium",
    tier: "quality",
    short: "Collection length recomputed on every loop iteration.",
    full: "The loop condition calls a size function (array_length, ds_list_size, string_length...) on a collection the loop does not modify. Caching it in a local avoids a function call per iteration.",
    help: `The loop condition calls \`array_length()\` (or \`ds_list_size()\`, \`string_length()\` ...) on every iteration, but the loop never changes the collection's size. Caching the length in a local saves a function call per iteration, which matters in tight loops that run every frame.

\`\`\`gml
// Before
for (var i = 0; i < array_length(enemies); i++) { ... }

// After
for (var i = 0, n = array_length(enemies); i < n; i++) { ... }
\`\`\``
  },
  file(ctx) {
    return {
      ForStatement(n) {
        if (!n.test) return;
        let lengthCall;
        walk(n.test, (e) => {
          if (!lengthCall && e.type === "CallExpression" && LENGTH_FUNCTIONS.has(builtinCallName(e, ctx) ?? "")) lengthCall = e;
        });
        const target = lengthCall?.arguments[0];
        if (!lengthCall || !target || target.type !== "Identifier" && target.type !== "MemberExpression") return;
        if (modifies(n.body, target) || n.update && modifies(n.update, target)) return;
        const name = lengthCall.callee.name;
        ctx.report(lengthCall, `${code(`${name}()`)} is re-evaluated on every iteration; the loop doesn't change ${code(ctx.file.source.text.slice(target.start, target.end))}, so cache the size in a local before the loop.`);
      }
    };
  }
};
function modifies(body, target) {
  let found = false;
  walk(body, (n, c) => {
    if (found) return c.skip();
    if (n.type === "AssignmentExpression" || n.type === "UpdateExpression") {
      const lhs = n.type === "AssignmentExpression" ? n.left : n.argument;
      let base = lhs;
      while (base.type === "IndexExpression" || base.type === "MemberExpression" && !sameExpression(base, target)) base = base.object;
      if (sameExpression(base, target) || sameExpression(lhs, target)) found = true;
    } else if (n.type === "CallExpression" && n.callee.type === "Identifier") {
      const name = n.callee.name;
      if (MUTATORS.test(name) && n.arguments.some((a) => sameExpression(a, target))) found = true;
      else if (!getBuiltinFunction(name) && n.arguments.some((a) => sameExpression(a, target))) found = true;
    }
  });
  return found;
}
var redundantScriptExecute = {
  meta: {
    id: "gml/redundant-script-execute",
    name: "RedundantScriptExecute",
    category: "performance",
    severity: "note",
    precision: "very-high",
    tier: "quality",
    short: "`script_execute` with a constant function; call it directly.",
    full: "`script_execute(fn, args...)` with a known function is slower than `fn(args...)` and hides the call from compile-time checks.",
    help: `Calling \`script_execute(scr_name, a, b)\` with a fixed function is slower than calling \`scr_name(a, b)\` directly, and it hides the call from argument checks and "find references".

\`\`\`gml
// Before
script_execute(scr_player_hurt, 10);
// After
scr_player_hurt(10);
\`\`\``
  },
  file(ctx) {
    return {
      CallExpression(n) {
        if (builtinCallName(n, ctx) !== "script_execute") return;
        const target = n.arguments[0];
        if (target?.type !== "Identifier") return;
        const ref = ctx.scopes.refOf.get(target);
        if (ref?.binding.kind !== "free" || !ctx.index.globalFunctions.has(target.name)) return;
        const args = n.arguments.slice(1).map((a) => ctx.file.source.text.slice(a.start, a.end)).join(", ");
        ctx.report(n, `Call ${code(`${target.name}(${args})`)} directly instead of through script_execute().`);
      }
    };
  }
};
var LITERAL_ACCESS = {
  variable_instance_get: { nameArg: 1, direct: (a, n) => `${a[0]}.${n}` },
  variable_instance_set: { nameArg: 1, direct: (a, n) => `${a[0]}.${n} = ${a[2]}` },
  variable_struct_get: { nameArg: 1, direct: (a, n) => `${a[0]}.${n}` },
  variable_struct_set: { nameArg: 1, direct: (a, n) => `${a[0]}.${n} = ${a[2]}` },
  struct_get: { nameArg: 1, direct: (a, n) => `${a[0]}.${n}` },
  struct_set: { nameArg: 1, direct: (a, n) => `${a[0]}.${n} = ${a[2]}` },
  variable_global_get: { nameArg: 0, direct: (_a, n) => `global.${n}` },
  variable_global_set: { nameArg: 0, direct: (a, n) => `global.${n} = ${a[1]}` }
};
var literalVariableAccess = {
  meta: {
    id: "gml/literal-variable-access",
    name: "LiteralVariableAccess",
    category: "performance",
    severity: "note",
    precision: "very-high",
    tier: "quality",
    short: "Reflection call with a constant name; use direct access.",
    full: '`variable_instance_get(inst, "hp")` and similar calls with a literal name are slower than `inst.hp` and invisible to static checks. `asset_get_index("spr_x")` with a literal name should reference the asset directly.',
    help: `Reflection functions look variables up by string at runtime. With a constant name, direct access is faster, clearer, and visible to static analysis.

\`\`\`gml
// Before
var hp = variable_instance_get(target, "hp");
variable_global_set("score", 0);
sprite_index = asset_get_index("spr_player_run");

// After
var hp = target.hp;
global.score = 0;
sprite_index = spr_player_run;
\`\`\`

Referencing assets directly also keeps them from being removed by "remove unused assets".`
  },
  file(ctx) {
    return {
      CallExpression(n) {
        const name = builtinCallName(n, ctx);
        if (!name) return;
        if (name === "asset_get_index") {
          const s = staticString(n.arguments[0], ctx.index);
          if (s && ctx.index.assets.has(s) && n.arguments[0]?.type === "StringLiteral") ctx.report(n, `Reference the asset ${code(s)} directly instead of looking it up by name with asset_get_index().`);
          return;
        }
        const spec = LITERAL_ACCESS[name];
        if (!spec) return;
        const lit = n.arguments[spec.nameArg];
        if (lit?.type !== "StringLiteral" || !/^[A-Za-z_]\w*$/.test(lit.value)) return;
        const args = n.arguments.map((a) => ctx.file.source.text.slice(a.start, a.end));
        ctx.report(n, `Use ${code(spec.direct(args, lit.value))} instead of ${name}() with a constant name.`);
      }
    };
  }
};
var mathShortcut = {
  meta: {
    id: "gml/math-shortcut",
    name: "MathShortcut",
    category: "performance",
    severity: "note",
    precision: "very-high",
    tier: "quality",
    short: "Use sqr()/sqrt()/point_distance() instead of power().",
    full: "`power(x, 2)` is slower than `sqr(x)`, `power(x, 0.5)` is slower than `sqrt(x)`, and hand-written distance formulas can use `point_distance`.",
    help: `\`power()\` handles arbitrary exponents and is slower than the specialised functions:

| Instead of | Use |
| --- | --- |
| \`power(x, 2)\` | \`sqr(x)\` or \`x * x\` |
| \`power(x, 0.5)\` | \`sqrt(x)\` |
| \`sqrt(sqr(x2 - x1) + sqr(y2 - y1))\` | \`point_distance(x1, y1, x2, y2)\` |`
  },
  file(ctx) {
    const isSquare = (e) => e.type === "CallExpression" && (builtinCallName(e, ctx) === "sqr" || builtinCallName(e, ctx) === "power" && e.arguments[1]?.type === "NumberLiteral" && e.arguments[1].value === 2) || e.type === "BinaryExpression" && e.operator === "*" && sameExpression(e.left, e.right);
    return {
      CallExpression(n) {
        const name = builtinCallName(n, ctx);
        if (name === "power" && n.arguments[1]?.type === "NumberLiteral") {
          const exp = n.arguments[1].value;
          const base = ctx.file.source.text.slice(n.arguments[0].start, n.arguments[0].end);
          if (exp === 2) ctx.report(n, `Use ${code(`sqr(${base})`)} instead of power(..., 2).`);
          else if (exp === 0.5) ctx.report(n, `Use ${code(`sqrt(${base})`)} instead of power(..., 0.5).`);
        } else if (name === "sqrt" && n.arguments[0]?.type === "BinaryExpression" && n.arguments[0].operator === "+") {
          const sum = n.arguments[0];
          if (isSquare(sum.left) && isSquare(sum.right)) ctx.report(n, "This looks like a distance calculation; use point_distance(x1, y1, x2, y2) (or point_distance_3d) instead.");
        }
      }
    };
  }
};
var nestedWithPerFrame = {
  meta: {
    id: "gml/nested-with-per-frame",
    name: "NestedWithPerFrame",
    category: "performance",
    severity: "note",
    precision: "medium",
    tier: "quality",
    short: "Nested `with` loops over objects every frame (O(n\xD7m)).",
    full: "A `with (obj_a)` inside another `with (obj_b)` in a Step or Draw event visits every pair of instances every frame.",
    help: `\`with (object)\` loops over every instance of that object. Nesting two of them in a Step or Draw event visits every **pair** of instances, every frame. With 100 of each that is 10,000 iterations per frame.

**How to fix:** use collision functions (\`instance_place_list\`, \`collision_circle_list\`), spatial partitioning, or cache the results.`
  },
  file(ctx) {
    const file = ctx.file;
    if (file.kind !== "object-event" || !isPerFrameEvent(file.event)) return;
    const isObjectLoop = (e) => e.type === "Identifier" && (ctx.index.assets.get(e.name) === "objects" || e.name === "all");
    return {
      WithStatement(n) {
        if (!isObjectLoop(n.object) || ctx.enclosingFunction()) return;
        const outer = ctx.ancestors.find((a) => a.type === "WithStatement" && isObjectLoop(a.object));
        if (outer) ctx.report(n, `Nested ${code("with")} over objects in ${describeEvent(file)} visits every pair of instances every frame.`);
      }
    };
  }
};
var stringConcatInLoop = {
  meta: {
    id: "gml/string-concat-in-loop",
    name: "StringConcatInLoop",
    category: "performance",
    severity: "note",
    precision: "medium",
    tier: "quality",
    short: "String built by repeated concatenation in a loop.",
    full: "Each `s += ...` creates a new string and copies the old one, so building a long string in a loop is O(n\xB2).",
    help: `Strings are immutable: every \`s += piece\` allocates a new string and copies everything built so far. In a loop this is **O(n\xB2)**.

**How to fix:** collect the pieces in an array and join them once, or write to a text buffer.

\`\`\`gml
// Before
var out = "";
for (var i = 0; i < array_length(lines); i++) out += lines[i] + "\\n";

// After
var out = string_join_ext("\\n", lines);
\`\`\``
  },
  file(ctx) {
    const reported = /* @__PURE__ */ new Set();
    return {
      AssignmentExpression(n) {
        if (n.operator !== "+=" || n.left.type !== "Identifier" || !isInLoop(ctx.ancestors)) return;
        const ref = ctx.scopes.refOf.get(n.left);
        if (ref?.binding.kind !== "local") return;
        const key = `${ref.binding.decl.id.start}`;
        if (reported.has(key)) return;
        let stringy = n.right.type === "StringLiteral" || n.right.type === "TemplateString";
        if (!stringy && n.right.type === "BinaryExpression") walk(n.right, (e) => {
          if (e.type === "StringLiteral" || e.type === "TemplateString") stringy = true;
        });
        if (!stringy) return;
        reported.add(key);
        ctx.report(n, `${code(n.left.name)} is built by repeated string concatenation inside a loop (O(n\xB2)); collect the pieces in an array and join them once.`);
      }
    };
  }
};
var PERFORMANCE_RULES = [
  perFrameExpensiveCall,
  stringCharAtLoop,
  instanceNumberExists,
  loopInvariantLength,
  redundantScriptExecute,
  literalVariableAccess,
  mathShortcut,
  nestedWithPerFrame,
  stringConcatInLoop
];

// src/rules/project.ts
function yypLocation(ctx, entry) {
  const yyp = ctx.project.yyp;
  return ctx.locateText(yyp.relPath, yyp.source, entry);
}
function fileLocation(relPath) {
  return { file: relPath, startLine: 1, startColumn: 1, endLine: 1, endColumn: 1 };
}
var duplicateResource = {
  meta: {
    id: "gml/duplicate-resource",
    name: "DuplicateResource",
    category: "project",
    severity: "error",
    precision: "very-high",
    tier: "default",
    short: "Resource is registered twice in the .yyp, or two resources share a name.",
    full: "A resource listed more than once in the project file, or two resources with the same name, make GameMaker crash or fail to load the project. This usually comes from a bad merge.",
    help: `The \`.yyp\` project file lists the same resource more than once, or two different resources have the same name. GameMaker crashes or refuses to load the project, and asset references become ambiguous. This almost always comes from a merge conflict resolved by keeping both sides.

**How to fix:** open the \`.yyp\` in a text editor and delete the duplicate entry in \`"resources"\`, or rename one of the clashing resources in the IDE.`
  },
  project(ctx) {
    const yyp = ctx.project.yyp;
    if (!yyp) return;
    const byPath = /* @__PURE__ */ new Map();
    for (const e of yyp.entries) {
      const key = e.path.toLowerCase();
      byPath.set(key, [...byPath.get(key) ?? [], e]);
    }
    for (const entries of byPath.values()) {
      for (const dup of entries.slice(1)) {
        ctx.report(yypLocation(ctx, dup), `${code(dup.name)} (${dup.path}) is registered ${entries.length} times in ${yyp.relPath.split("/").pop()}; GameMaker crashes when a resource is listed twice.`, {
          related: [{ location: yypLocation(ctx, entries[0]), message: "First entry" }]
        });
      }
    }
    const byName = /* @__PURE__ */ new Map();
    for (const e of yyp.entries) {
      const list = byName.get(e.name) ?? [];
      if (!list.some((x) => x.path.toLowerCase() === e.path.toLowerCase())) list.push(e);
      byName.set(e.name, list);
    }
    for (const [name, entries] of byName) {
      if (entries.length < 2) continue;
      for (const dup of entries.slice(1)) {
        ctx.report(yypLocation(ctx, dup), `Two resources are named ${code(name)} (${entries[0].path} and ${dup.path}); asset names must be unique.`, {
          related: [{ location: yypLocation(ctx, entries[0]), message: "Other resource with this name" }]
        });
      }
    }
  }
};
var missingResourceFile = {
  meta: {
    id: "gml/missing-resource-file",
    name: "MissingResourceFile",
    category: "project",
    severity: "error",
    precision: "very-high",
    tier: "default",
    short: "Resource registered in the .yyp has no .yy file on disk.",
    full: "The project file references a resource whose .yy file does not exist, so GameMaker cannot load the project.",
    help: `The \`.yyp\` lists a resource whose \`.yy\` file is missing. GameMaker fails to load the project. This happens when a resource folder was deleted or renamed outside the IDE, or not committed.

**How to fix:** restore (or commit) the resource folder, or remove the entry from \`"resources"\` in the \`.yyp\`.`
  },
  project(ctx) {
    const yyp = ctx.project.yyp;
    if (!yyp) return;
    for (const list of ctx.project.resources.values()) {
      for (const r of list) {
        if (!r.inYyp || r.onDisk) continue;
        for (const e of r.yypEntries) ctx.report(yypLocation(ctx, e), `${code(r.name)} is registered in the project, but ${r.yyRelPath} does not exist; GameMaker cannot load the project.`);
      }
    }
  }
};
function firstReference(ctx, names, exclude) {
  for (const [file, scopes] of ctx.index.scopes) {
    if (file.resource === exclude) continue;
    for (const ref of scopes.refs) {
      if (ref.binding.kind === "free" && names.has(ref.id.name)) return ctx.locate(file, ref.id);
    }
  }
  return void 0;
}
var unregisteredResource = {
  meta: {
    id: "gml/unregistered-resource",
    name: "UnregisteredResource",
    category: "project",
    severity: "error",
    precision: "high",
    tier: "default",
    short: "Resource folder exists on disk but is not registered in the .yyp.",
    full: "GameMaker only loads resources listed in the project file. A resource folder that is not registered is ignored, and code that uses it fails to compile.",
    help: `GameMaker only loads resources that are listed in the \`.yyp\` project file. This resource's folder and \`.yy\` exist on disk, but it isn't registered, so GameMaker ignores it. Any code that uses it (the object, or the functions in the script) fails to compile.

This usually happens when a resource folder was copied in from another project, or after a merge that lost the \`.yyp\` change.

**How to fix:** re-add the resource through the IDE (*Add Existing* / drag it into the Asset Browser), or add a \`{"id":{"name":"...","path":"..."}}\` entry to \`"resources"\` in the \`.yyp\`. If the folder is left over, delete it.`
  },
  project(ctx) {
    const { project, index } = ctx;
    if (!project.yyp) return;
    for (const list of project.resources.values()) {
      for (const r of list) {
        if (r.inYyp || !r.onDisk) continue;
        const names = /* @__PURE__ */ new Set([r.name]);
        if (r.type === "scripts") {
          for (const [fname, infos] of index.globalFunctions) if (infos.some((i) => i.file.resource === r.name && i.file.kind === "script")) names.add(fname);
        }
        const used = firstReference(ctx, names, r.name);
        const yypName = project.yyp.relPath.split("/").pop();
        if (used) {
          ctx.report(used, `This uses ${r.type === "scripts" && !names.has(r.name) ? "a function from " : ""}${code(r.name)}, but ${r.yyRelPath} is not registered in ${yypName}; GameMaker ignores unregistered resources, so this fails to compile.`, {
            related: [{ location: fileLocation(r.yyRelPath), message: "Unregistered resource" }]
          });
        } else {
          ctx.report(fileLocation(r.yyRelPath), `${r.type.replace(/s$/, "")} ${code(r.name)} exists on disk but is not registered in ${yypName}; GameMaker ignores it.`, { severity: "warning" });
        }
      }
    }
  }
};
var orphanedEventFile = {
  meta: {
    id: "gml/orphaned-event-file",
    name: "OrphanedEventFile",
    category: "project",
    severity: "warning",
    precision: "high",
    tier: "default",
    short: "Object event file is not listed in the object's .yy (it never runs), or a listed event has no file.",
    full: "An object's events are defined by the `eventList` in its .yy file. An event .gml file that is not listed there is never compiled or run.",
    help: `An object's events are defined by the \`eventList\` in its \`.yy\` file. A \`Step_0.gml\` (or similar) file that isn't listed there **is never compiled or run**, even though it sits in the object's folder. The reverse, an event listed without its \`.gml\` file, makes GameMaker complain when loading the project.

This usually comes from merges where the \`.yy\` change and the \`.gml\` file ended up out of sync.

**How to fix:** re-create the event in the IDE (paste the code back in), or add or remove the matching entry in the object's \`.yy\` \`eventList\`.`
  },
  project(ctx) {
    const { project } = ctx;
    if (!project.yyp) return;
    const guid = /^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$/i;
    for (const obj of project.objects.values()) {
      if (!obj.eventList) continue;
      const matched = /* @__PURE__ */ new Set();
      for (const file of obj.events) {
        const ev = file.event;
        if (!ev) continue;
        if (ev.collisionObject && guid.test(ev.collisionObject)) continue;
        const idx = obj.eventList.findIndex((e, i) => !matched.has(i) && e.eventType === ev.eventType && (ev.kind === "Collision" ? e.collisionObject === ev.collisionObject : e.eventNum === ev.num));
        if (idx >= 0) matched.add(idx);
        else ctx.report(ctx.locate(file, { start: 0, end: 0 }), `${ev.displayName} event file of ${code(obj.name)} is not listed in ${obj.yyRelPath}, so this code never runs.`);
      }
      obj.eventList.forEach((e, i) => {
        if (matched.has(i)) return;
        if (e.eventType === 4 && e.collisionObject === void 0) return;
        const hasFile = obj.events.some((f) => f.event?.eventType === e.eventType && (e.eventType === 4 ? f.event.collisionObject === e.collisionObject || guid.test(f.event.collisionObject ?? "") : f.event.num === e.eventNum));
        if (!hasFile) ctx.report(fileLocation(obj.yyRelPath), `${code(obj.name)} lists an event (type ${e.eventType}, number ${e.collisionObject ?? e.eventNum}) whose .gml file is missing.`);
      });
    }
  }
};
var unusedObject = {
  meta: {
    id: "gml/unused-object",
    name: "UnusedObject",
    category: "project",
    severity: "note",
    precision: "medium",
    tier: "default",
    short: "Object is never placed, created, inherited from or referenced.",
    full: "No room, sequence, other object, code or string literal refers to this object, so it can never exist in the game.",
    help: `Nothing refers to this object: it isn't placed in any room or sequence, no other object inherits from it or collides with it, no code outside its own events mentions it, and no string literal names it (for \`asset_get_index\`). It can never exist at runtime.

**How to fix:** delete it if it's dead, or suppress this note (\`// gmlscan-ignore-file gml/unused-object\` in one of its events, or list it in \`ignore\`) if it's created in a way the scanner can't see.`
  },
  project(ctx) {
    const { project, index } = ctx;
    if (!project.yyp) return;
    for (const obj of project.objects.values()) {
      const registered = project.resources.get(obj.name)?.some((r) => r.inYyp && r.type === "objects");
      if (!registered) continue;
      if (project.yyReferences.get(obj.name)?.size) continue;
      if (index.stringLiterals.has(obj.name)) continue;
      let used = false;
      for (const [resource, names] of index.refsByResource) {
        if (resource !== obj.name && names.has(obj.name)) {
          used = true;
          break;
        }
      }
      if (used) continue;
      const loc = obj.events[0] ? ctx.locate(obj.events[0], { start: 0, end: 0 }) : fileLocation(obj.yyRelPath);
      ctx.report(loc, `Unused object ${code(obj.name)}: it is not placed in any room or sequence, not inherited from, and not referenced by other code.${index.usesDynamicAssetNames ? " (The project looks up some assets by computed names, which the scanner cannot follow.)" : ""}`);
    }
  }
};
var unusedFunction = {
  meta: {
    id: "gml/unused-function",
    name: "UnusedFunction",
    category: "project",
    severity: "note",
    precision: "medium",
    tier: "default",
    short: "Script function is never called or referenced.",
    full: "The global function is never called, passed as a value, or named in a string anywhere in the project.",
    help: `This script function is never called, passed as a callback, or named in a string anywhere in the project. It's dead code (or only used by code the scanner doesn't see, such as extensions or dynamic \`asset_get_index\` lookups with computed names).

**How to fix:** delete it, or suppress the note if it's part of a library API.`
  },
  project(ctx) {
    const { index } = ctx;
    if (!ctx.project.yyp) return;
    for (const [name, infos] of index.globalFunctions) {
      if (infos.length !== 1) continue;
      const fn = infos[0];
      const total = index.identifierRefs.get(name) ?? 0;
      let self = 0;
      for (const ref of index.scopes.get(fn.file)?.refs ?? []) {
        if (ref.id.name === name && ref.id.start >= fn.node.start && ref.id.end <= fn.node.end) self++;
      }
      if (total - self > 0 || index.stringLiterals.has(name)) continue;
      const decl = fn.node.type === "FunctionDeclaration" ? fn.node.id : fn.node;
      ctx.report(ctx.locate(fn.file, decl), `Unused function ${code(name)}.`);
    }
  }
};
var duplicateFunction = {
  meta: {
    id: "gml/duplicate-function",
    name: "DuplicateFunction",
    category: "project",
    severity: "warning",
    precision: "very-high",
    tier: "default",
    short: "Global function defined more than once, or clashing with an asset name.",
    full: "Two scripts declare a function with the same name (only one wins at runtime), or a function has the same name as an asset.",
    help: `Script functions are global, so two with the same name clash: only one of them is used at runtime, and which one depends on compile order. A function that shares its name with an asset (sprite, object, sound ...) shadows or is shadowed by that asset.

**How to fix:** rename one of them. A common convention is a prefix per system, for example \`player_move\` and \`enemy_move\`.`
  },
  project(ctx) {
    const { index } = ctx;
    for (const [name, infos] of index.globalFunctions) {
      for (const dup of infos.slice(1)) {
        const first = infos[0];
        ctx.report(ctx.locate(dup.file, dup.node.type === "FunctionDeclaration" ? dup.node.id : dup.node), `Function ${code(name)} is also defined in ${first.file.relPath}; only one definition is used at runtime.`, {
          related: [{ location: ctx.locate(first.file, first.node.type === "FunctionDeclaration" ? first.node.id : first.node), message: "Other definition" }]
        });
      }
      const assetType = index.assets.get(name);
      const fn = infos[0];
      if (assetType && !(assetType === "scripts" && fn.file.resource === name)) {
        ctx.report(ctx.locate(fn.file, fn.node.type === "FunctionDeclaration" ? fn.node.id : fn.node), `Function ${code(name)} has the same name as ${assetType.replace(/s$/, "")} asset ${code(name)}.`);
      }
    }
  }
};
var duplicateMacro = {
  meta: {
    id: "gml/duplicate-macro",
    name: "DuplicateMacro",
    category: "project",
    severity: "error",
    precision: "very-high",
    tier: "default",
    short: "Macro defined more than once for the same configuration.",
    full: "GameMaker macros are global; defining the same macro twice (for the same configuration) is an error.",
    help: `Macros are global. Defining the same macro twice for the same configuration is a compile error, or one silently wins.

Configuration-specific macros are fine:

\`\`\`gml
#macro API_URL "https://api.example.com"
#macro Debug:API_URL "http://localhost:8080"   // OK: different configuration
\`\`\``
  },
  project(ctx) {
    for (const [name, decls] of ctx.index.macros) {
      const byConfig = /* @__PURE__ */ new Map();
      for (const d of decls) {
        const key = d.node.config ?? "";
        byConfig.set(key, [...byConfig.get(key) ?? [], d]);
      }
      for (const [config, list] of byConfig) {
        for (const dup of list.slice(1)) {
          ctx.report(ctx.locate(dup.file, dup.node.id), `Macro ${code(config ? `${config}:${name}` : name)} is already defined in ${list[0].file.relPath}.`, {
            related: [{ location: ctx.locate(list[0].file, list[0].node.id), message: "First definition" }]
          });
        }
      }
    }
  }
};
var duplicateEnum = {
  meta: {
    id: "gml/duplicate-enum",
    name: "DuplicateEnum",
    category: "project",
    severity: "error",
    precision: "very-high",
    tier: "default",
    short: "Enum or enum member defined more than once.",
    full: "Enums are global; two enums with the same name, or two members with the same name in one enum, are compile errors.",
    help: `Enums are global. Two enums with the same name, or a repeated member inside one enum, won't compile (or silently conflict).`
  },
  project(ctx) {
    for (const [name, decls] of ctx.index.enums) {
      for (const dup of decls.slice(1)) {
        ctx.report(ctx.locate(dup.file, dup.node.id), `Enum ${code(name)} is already defined in ${decls[0].file.relPath}.`, {
          related: [{ location: ctx.locate(decls[0].file, decls[0].node.id), message: "First definition" }]
        });
      }
      for (const d of decls) {
        const seen = /* @__PURE__ */ new Set();
        for (const m of d.node.members) {
          if (seen.has(m.id.name)) ctx.report(ctx.locate(d.file, m.id), `Enum member ${code(`${name}.${m.id.name}`)} is defined twice.`);
          seen.add(m.id.name);
        }
      }
    }
  }
};
var PROJECT_RULES = [
  duplicateResource,
  missingResourceFile,
  unregisteredResource,
  orphanedEventFile,
  unusedObject,
  unusedFunction,
  duplicateFunction,
  duplicateMacro,
  duplicateEnum
];

// src/rules/security.ts
import { join as join3 } from "node:path";

// src/analysis/taint.ts
var SINK_KINDS = ["code-injection", "path-injection", "command-injection", "variable-injection", "url-redirect", "unsafe-deserialization"];
var SOURCE_FUNCTIONS = {
  get_string: { threat: "local", description: "user input from get_string()" },
  get_integer: { threat: "local", description: "user input from get_integer()" },
  clipboard_get_text: { threat: "local", description: "clipboard contents" },
  parameter_string: { threat: "local", description: "a command-line argument" },
  environment_get_variable: { threat: "local", description: "an environment variable" },
  get_open_filename: { threat: "local", description: "a user-chosen file name" },
  get_open_filename_ext: { threat: "local", description: "a user-chosen file name" },
  get_save_filename: { threat: "local", description: "a user-chosen file name" },
  get_save_filename_ext: { threat: "local", description: "a user-chosen file name" },
  file_text_read_string: { threat: "local", description: "text read from a file" },
  file_text_readln: { threat: "local", description: "text read from a file" },
  file_text_read_real: { threat: "local", description: "a number read from a file" },
  file_bin_read_byte: { threat: "local", description: "a byte read from a file" },
  ini_read_string: { threat: "local", description: "a value read from an INI file" },
  ini_read_real: { threat: "local", description: "a value read from an INI file" },
  buffer_load: { threat: "local", description: "a buffer loaded from a file" },
  // Common networking extensions (Steamworks, etc.)
  steam_lobby_get_data: { threat: "remote", description: "Steam lobby data (set by other players)" },
  steam_lobby_get_member_data: { threat: "remote", description: "Steam lobby member data (set by other players)" },
  steam_lobby_get_owner_data: { threat: "remote", description: "Steam lobby data (set by other players)" }
};
var ASYNC_EVENT_SOURCES = {
  62: { threat: "remote", description: "an HTTP response" },
  63: { threat: "local", description: "text entered in a dialog" },
  67: { threat: "remote", description: "cloud save data" },
  68: { threat: "remote", description: "a network packet" },
  69: { threat: "remote", description: "Steam callback data" },
  70: { threat: "remote", description: "social/Discord callback data" },
  71: { threat: "remote", description: "a push notification" },
  72: { threat: "local", description: "loaded save data" },
  76: { threat: "remote", description: "broadcast message data" }
};
var SAFE_ASYNC_KEYS = /* @__PURE__ */ new Set(["id", "status", "http_status", "type", "socket", "port", "size", "event_type", "succeeded", "contentLength", "sizeDownloaded", "ip", "server", "result_code", "url"]);
var isSelfOrGlobal = (call) => {
  const a = call.arguments[0];
  return a?.type === "Identifier" && (a.name === "self" || a.name === "global" || a.name === "id" || a.name === "other");
};
var SINKS = {};
var sink = (names, args, kind, when) => {
  for (const n of names) (SINKS[n] ??= []).push({ args, kind, when });
};
sink(["script_execute", "script_execute_ext", "method_call", "event_perform_object", "callv"], [0], "code-injection");
sink(["method"], [1], "code-injection");
sink(["external_define"], [0, 1], "code-injection");
sink(["instance_create_layer", "instance_create_depth"], [3], "code-injection");
sink(["instance_change"], [0], "code-injection");
sink(["file_text_open_read", "file_text_open_write", "file_text_open_append", "file_bin_open", "file_delete", "ini_open", "directory_create", "directory_destroy", "file_find_first", "buffer_load", "game_save", "game_load", "screen_save", "screen_save_part", "audio_create_stream", "font_add", "sprite_add", "sprite_add_ext", "background_add"], [0], "path-injection");
sink(["file_copy", "file_rename", "zip_unzip", "zip_unzip_async"], [0, 1], "path-injection");
sink(["buffer_save", "buffer_save_ext", "buffer_save_async", "surface_save", "surface_save_part", "sprite_save_strip", "buffer_load_ext", "buffer_load_partial"], [1], "path-injection");
sink(["sprite_save"], [2], "path-injection");
sink(["http_get_file"], [1], "path-injection");
sink(["execute_shell", "execute_shell_simple", "ExecuteShell", "execute_program", "shell_execute", "ShellExecute", "process_execute", "ProcessExecute", "process_execute_async", "system", "shell_run", "run_command"], [0, 1], "command-injection");
sink(["variable_instance_set", "variable_instance_get"], [1], "variable-injection");
sink(["variable_global_set", "variable_global_get"], [0], "variable-injection");
sink(["variable_struct_set", "struct_set", "variable_struct_get", "struct_get"], [1], "variable-injection", isSelfOrGlobal);
sink(["url_open", "url_open_ext", "url_open_full"], [0], "url-redirect");
sink(["http_get", "http_get_file", "http_post_string", "http_request"], [0], "url-redirect");
sink(["ds_map_read", "ds_list_read", "ds_grid_read", "ds_queue_read", "ds_stack_read", "ds_priority_read"], [1], "unsafe-deserialization");
sink(["game_load_buffer"], [0], "unsafe-deserialization");
var PROPAGATORS = {};
var prop = (names, from, numeric = false) => {
  for (const n of names) PROPAGATORS[n] = { from, numeric };
};
prop(["string", "string_concat", "string_concat_ext", "string_join", "string_join_ext", "string_ext", "array_concat"], "all");
prop(
  ["string_upper", "string_lower", "string_copy", "string_delete", "string_insert", "string_replace", "string_replace_all", "string_trim", "string_trim_start", "string_trim_end", "string_char_at", "string_letters", "string_lettersdigits", "string_repeat", "string_split", "string_split_ext", "string_hash_to_newline", "string_format", "string_ext"],
  [0]
);
prop(["string_insert"], [0, 1]);
prop(["filename_path", "filename_dir", "filename_drive", "filename_ext", "filename_change_ext"], [0]);
prop(["base64_decode", "base64_encode", "json_parse", "json_decode", "json_stringify", "json_encode", "buffer_base64_decode", "buffer_base64_encode"], [0]);
prop(["ds_map_find_value", "ds_map_find_first", "ds_map_find_last", "ds_map_find_next", "ds_map_find_previous", "ds_map_keys_to_array", "ds_map_values_to_array", "ds_list_find_value", "ds_grid_get", "ds_queue_dequeue", "ds_queue_head", "ds_queue_tail", "ds_stack_pop", "ds_stack_top", "ds_priority_find_max", "ds_priority_find_min", "ds_priority_delete_max", "ds_priority_delete_min"], [0]);
prop(["struct_get", "variable_struct_get", "variable_instance_get", "array_get", "array_pop", "array_shift", "array_first", "array_last", "array_filter", "array_map", "array_copy_while", "array_reverse", "struct_get_names", "variable_struct_get_names"], [0]);
prop(["buffer_read", "buffer_peek", "buffer_read_ext"], [0]);
prop(["asset_get_index", "real", "int64", "floor", "ceil", "round", "abs", "string_digits"], [0], true);
var MUTATORS2 = {
  ds_list_add: "rest",
  ds_list_insert: [2],
  ds_list_set: [2],
  ds_list_replace: [2],
  ds_map_add: [1, 2],
  ds_map_set: [1, 2],
  ds_map_replace: [1, 2],
  ds_grid_set: [3],
  ds_queue_enqueue: "rest",
  ds_stack_push: "rest",
  ds_priority_add: [1],
  array_push: "rest",
  array_insert: "rest",
  array_set: [2],
  struct_set: [2],
  variable_struct_set: [2],
  buffer_write: [2],
  buffer_poke: [3],
  buffer_copy: [0]
};
var PATH_SANITIZERS = /* @__PURE__ */ new Set(["filename_name"]);
var CLEANSERS = /* @__PURE__ */ new Set(["md5_string_utf8", "md5_string_unicode", "sha1_string_utf8", "sha1_string_unicode", "sha256_string_utf8", "crc32_string", "string_length", "string_byte_length", "string_pos", "string_pos_ext", "string_last_pos", "string_count", "array_length", "ds_list_size", "ds_map_size", "is_string", "is_real", "is_numeric", "is_undefined", "is_struct", "is_array", "file_exists", "ds_map_exists", "variable_struct_exists", "struct_exists", "array_contains", "ds_list_find_index", "array_get_index"]);
var ALLOW_LIST_CHECKS = /* @__PURE__ */ new Set(["array_contains", "ds_map_exists", "variable_struct_exists", "struct_exists", "variable_instance_exists", "variable_global_exists", "asset_has_tags"]);
var INDEX_CHECKS = /* @__PURE__ */ new Set(["ds_list_find_index", "array_get_index"]);
var MAX_FACTS = 4;
var MAX_PATH = 14;
function analyzeTaint(index, config) {
  return new TaintEngine(index, config).run();
}
var TaintEngine = class {
  index;
  threats;
  sources;
  sinks;
  sanitizers;
  objectStore = /* @__PURE__ */ new Map();
  globalStore = /* @__PURE__ */ new Map();
  summaries = /* @__PURE__ */ new Map();
  findings = /* @__PURE__ */ new Map();
  version = 0;
  // Per-unit context
  unit;
  scopes;
  state = /* @__PURE__ */ new Map();
  withOwner = [];
  constructor(index, config) {
    this.index = index;
    this.threats = new Set(config.threatModels);
    this.sources = { ...SOURCE_FUNCTIONS };
    for (const s of config.taint.sources) this.sources[s.function] = { threat: s.kind ?? "remote", description: s.description ?? `data returned by ${s.function}()` };
    this.sinks = { ...SINKS };
    for (const s of config.taint.sinks) {
      const kind = SINK_KINDS.includes(s.kind) ? s.kind : "code-injection";
      this.sinks[s.function] = [...this.sinks[s.function] ?? [], { args: s.arguments, kind }];
    }
    this.sanitizers = new Set(config.taint.sanitizers);
  }
  run() {
    const units = [];
    for (const file of this.index.project.files) {
      const owner = file.kind === "object-event" ? file.resource : void 0;
      units.push({ file, body: file.ast.body, owner });
    }
    for (const fn of this.index.functionsByNode.values()) {
      units.push({ file: fn.file, body: fn.node.body.body, fn, owner: fn.file.kind === "object-event" ? fn.file.resource : void 0 });
      this.summaries.set(fn.node, { paramToReturn: /* @__PURE__ */ new Map(), paramToSink: /* @__PURE__ */ new Map(), returnFacts: [] });
    }
    for (let pass = 0; pass < 8; pass++) {
      const before = this.version;
      for (const u of units) this.analyzeUnit(u);
      if (this.version === before) break;
    }
    return { findings: [...this.findings.values()] };
  }
  // -------------------------------------------------------------------------
  analyzeUnit(unit) {
    this.unit = unit;
    this.scopes = this.index.scopes.get(unit.file);
    this.state = /* @__PURE__ */ new Map();
    this.withOwner = [unit.owner];
    if (unit.fn) {
      unit.fn.node.params.forEach((p, i) => {
        this.state.set(p.id.name, [{ origin: { kind: "param", index: i }, numeric: false, path: [this.step(p.id, `parameter ${p.id.name}`)] }]);
      });
    }
    this.execList(unit.body);
  }
  step(node, message) {
    return { file: this.unit.file, start: node.start, end: node.end, message };
  }
  get owner() {
    return this.withOwner[this.withOwner.length - 1];
  }
  // --- statements ----------------------------------------------------------
  execList(list) {
    for (const s of list) this.exec(s);
  }
  exec(s) {
    switch (s.type) {
      case "BlockStatement":
        this.execList(s.body);
        return;
      case "VarDeclaration":
        for (const d of s.declarations) {
          const facts = d.init ? this.ev(d.init) : [];
          if (s.kind === "globalvar") continue;
          this.clearFields(d.id.name);
          this.state.set(d.id.name, this.extend(facts, d.id, `${d.id.name}`));
        }
        return;
      case "ExpressionStatement":
        this.execExpressionStatement(s.expression);
        return;
      case "IfStatement":
        this.execIf(s);
        return;
      case "WhileStatement":
        this.ev(s.test);
        this.loop(() => {
          this.ev(s.test);
          this.exec(s.body);
        });
        return;
      case "DoUntilStatement":
        this.loop(() => {
          this.exec(s.body);
          this.ev(s.test);
        });
        return;
      case "RepeatStatement":
        this.ev(s.count);
        this.loop(() => this.exec(s.body));
        return;
      case "ForStatement":
        if (s.init) this.exec(s.init);
        this.loop(() => {
          if (s.test) this.ev(s.test);
          this.exec(s.body);
          if (s.update) this.exec(s.update);
        });
        return;
      case "SwitchStatement":
        this.execSwitch(s);
        return;
      case "WithStatement": {
        this.ev(s.object);
        const target = s.object.type === "Identifier" && this.index.assets.get(s.object.name) === "objects" ? s.object.name : void 0;
        this.withOwner.push(target);
        this.exec(s.body);
        this.withOwner.pop();
        return;
      }
      case "ReturnStatement":
        if (s.argument) this.recordReturn(this.ev(s.argument), s.argument);
        return;
      case "ThrowStatement":
      case "DeleteStatement":
        this.ev(s.argument);
        return;
      case "TryStatement": {
        const before = this.clone(this.state);
        this.exec(s.block);
        const afterTry = this.state;
        this.state = this.join(before, afterTry);
        if (s.param) this.state.set(s.param.name, []);
        if (s.handler) this.exec(s.handler);
        this.state = this.join(afterTry, this.state);
        if (s.finalizer) this.exec(s.finalizer);
        return;
      }
      default:
        return;
    }
  }
  execExpressionStatement(e) {
    if (e.type === "AssignmentExpression") {
      let facts = this.ev(e.right);
      if (e.operator !== "=") facts = union(facts, this.ev(e.left));
      this.assign(e.left, facts, e);
      return;
    }
    this.ev(e);
  }
  loop(body) {
    for (let i = 0; i < 2; i++) {
      const before = this.clone(this.state);
      body();
      this.state = this.join(before, this.state);
    }
  }
  execIf(s) {
    this.ev(s.test);
    const guards = this.guards(s.test);
    const base = this.state;
    const t = this.clone(base);
    this.sanitize(t, guards.whenTrue);
    const f = this.clone(base);
    this.sanitize(f, guards.whenFalse);
    this.state = t;
    this.exec(s.consequent);
    const afterT = this.state;
    this.state = f;
    if (s.alternate) this.exec(s.alternate);
    const afterF = this.state;
    const tExits = alwaysExits(s.consequent);
    const fExits = s.alternate ? alwaysExits(s.alternate) : false;
    if (tExits && !fExits) this.state = afterF;
    else if (fExits && !tExits) this.state = afterT;
    else this.state = this.join(afterT, afterF);
  }
  execSwitch(s) {
    this.ev(s.discriminant);
    const key = this.keyOf(s.discriminant);
    const base = this.state;
    let joined = this.clone(base);
    for (const c of s.cases) {
      if (c.test) this.ev(c.test);
      this.state = this.clone(base);
      if (key && c.test && isConstant(c.test)) this.state.set(key, []);
      this.execList(c.body);
      joined = this.join(joined, this.state);
    }
    this.state = joined;
  }
  // --- guards --------------------------------------------------------------
  guards(test) {
    const none = { whenTrue: /* @__PURE__ */ new Set(), whenFalse: /* @__PURE__ */ new Set() };
    switch (test.type) {
      case "UnaryExpression":
        if (test.operator === "!") {
          const g = this.guards(test.argument);
          return { whenTrue: g.whenFalse, whenFalse: g.whenTrue };
        }
        return none;
      case "BinaryExpression": {
        if (test.operator === "&&") {
          const l = this.guards(test.left);
          const r = this.guards(test.right);
          return { whenTrue: /* @__PURE__ */ new Set([...l.whenTrue, ...r.whenTrue]), whenFalse: intersect(l.whenFalse, r.whenFalse) };
        }
        if (test.operator === "||") {
          const l = this.guards(test.left);
          const r = this.guards(test.right);
          return { whenTrue: intersect(l.whenTrue, r.whenTrue), whenFalse: /* @__PURE__ */ new Set([...l.whenFalse, ...r.whenFalse]) };
        }
        if (test.operator === "==" || test.operator === "!=") {
          const [v, c] = isConstant(test.right) ? [test.left, test.right] : isConstant(test.left) ? [test.right, test.left] : [void 0, void 0];
          if (v && c) {
            const key = this.keyOf(v);
            if (key) return test.operator === "==" ? { whenTrue: /* @__PURE__ */ new Set([key]), whenFalse: /* @__PURE__ */ new Set() } : { whenTrue: /* @__PURE__ */ new Set(), whenFalse: /* @__PURE__ */ new Set([key]) };
          }
          const call = test.left.type === "CallExpression" ? test.left : test.right.type === "CallExpression" ? test.right : void 0;
          const other = call === test.left ? test.right : test.left;
          if (call && call.callee.type === "Identifier" && INDEX_CHECKS.has(call.callee.name) && other.type === "UnaryExpression" && other.operator === "-") {
            const key = this.keyOf(call.arguments[1]);
            if (key) return test.operator === "!=" ? { whenTrue: /* @__PURE__ */ new Set([key]), whenFalse: /* @__PURE__ */ new Set() } : { whenTrue: /* @__PURE__ */ new Set(), whenFalse: /* @__PURE__ */ new Set([key]) };
          }
        }
        if (test.operator === ">=" || test.operator === ">") {
          if (test.left.type === "CallExpression" && test.left.callee.type === "Identifier" && INDEX_CHECKS.has(test.left.callee.name)) {
            const key = this.keyOf(test.left.arguments[1]);
            if (key) return { whenTrue: /* @__PURE__ */ new Set([key]), whenFalse: /* @__PURE__ */ new Set() };
          }
        }
        return none;
      }
      case "CallExpression":
        if (test.callee.type === "Identifier" && ALLOW_LIST_CHECKS.has(test.callee.name)) {
          const key = this.keyOf(test.arguments[1]);
          if (key) return { whenTrue: /* @__PURE__ */ new Set([key]), whenFalse: /* @__PURE__ */ new Set() };
        }
        return none;
      default:
        return none;
    }
  }
  sanitize(state, keys) {
    for (const k of keys) state.set(k, []);
  }
  /** State key for a local variable or local field access, e.g. `cmd`, `data.cmd`. */
  keyOf(e) {
    if (!e) return void 0;
    if (e.type === "Identifier") {
      const ref = this.scopes.refOf.get(e);
      return ref?.binding.kind === "local" ? e.name : void 0;
    }
    if (e.type === "MemberExpression") {
      const base = this.keyOf(e.object);
      return base ? `${base}.${e.property.name}` : void 0;
    }
    return void 0;
  }
  // --- assignment ----------------------------------------------------------
  assign(target, facts, node) {
    const label = this.unit.file.source.text.slice(target.start, target.end);
    const stepped = this.extend(facts, node, label);
    switch (target.type) {
      case "Identifier": {
        const ref = this.scopes.refOf.get(target);
        if (ref?.binding.kind === "local") {
          this.clearFields(target.name);
          this.state.set(target.name, stepped);
        } else if (ref?.binding.kind === "free") {
          if (this.index.globalVariables.has(target.name) && !this.owner) this.addTo(this.globalStore, target.name, stepped);
          else if (this.owner) this.addTo(this.objectState(this.owner), target.name, stepped);
        }
        return;
      }
      case "MemberExpression": {
        const base = target.object;
        const prop2 = target.property.name;
        if (base.type === "Identifier") {
          if (base.name === "global") return this.addTo(this.globalStore, prop2, stepped);
          if (base.name === "self" && this.owner) return this.addTo(this.objectState(this.owner), prop2, stepped);
          if (this.index.assets.get(base.name) === "objects") return this.addTo(this.objectState(base.name), prop2, stepped);
        }
        const key = this.keyOf(target);
        if (key) this.state.set(key, stepped);
        return;
      }
      case "IndexExpression": {
        if (facts.length === 0) return;
        const root = target.object;
        if (root.type === "IndexExpression" || root.type === "MemberExpression" || root.type === "Identifier") this.assign(root, union(facts, this.ev(root)), node);
        return;
      }
    }
  }
  clearFields(name) {
    const prefix = name + ".";
    for (const k of [...this.state.keys()]) if (k.startsWith(prefix)) this.state.delete(k);
  }
  objectState(obj) {
    let s = this.objectStore.get(obj);
    if (!s) {
      s = /* @__PURE__ */ new Map();
      this.objectStore.set(obj, s);
    }
    return s;
  }
  /** Weak update of a shared (instance/global) store; bumps the version when it grows. */
  addTo(store, key, facts) {
    if (facts.length === 0) return;
    const existing = store.get(key) ?? [];
    const merged = union(existing, facts.filter((f) => f.origin.kind === "source"));
    if (merged.length !== existing.length) {
      store.set(key, merged);
      this.version++;
    }
  }
  recordReturn(facts, node) {
    const fn = this.unit.fn;
    if (!fn) return;
    const summary = this.summaries.get(fn.node);
    for (const f of this.extend(facts, node, "returned")) {
      if (f.origin.kind === "param") {
        if (!summary.paramToReturn.has(f.origin.index)) {
          summary.paramToReturn.set(f.origin.index, { path: f.path, numeric: f.numeric, pathSafe: f.pathSafe === true });
          this.version++;
        }
      } else if (summary.returnFacts.length < MAX_FACTS && !summary.returnFacts.some((r) => sameOrigin(r, f))) {
        summary.returnFacts.push(f);
        this.version++;
      }
    }
  }
  // --- expressions ---------------------------------------------------------
  ev(e) {
    switch (e.type) {
      case "Identifier":
        return this.evIdentifier(e);
      case "MemberExpression":
        return this.evMember(e);
      case "IndexExpression":
        return this.evIndex(e);
      case "CallExpression":
        return this.evCall(e);
      case "NewExpression":
        e.arguments.forEach((a) => this.ev(a));
        return [];
      case "BinaryExpression": {
        const l = this.ev(e.left);
        const r = this.ev(e.right);
        switch (e.operator) {
          case "+":
            if (r.length && /^[a-z][a-z0-9+.-]*:\/\//i.test(staticLeftmost(e.left) ?? "")) return union(l, r.map((f) => ({ ...f, pathSafe: true })));
            return union(l, r);
          case "??":
            return union(l, r);
          case "-":
          case "*":
          case "/":
          case "%":
          case "div":
          case "&":
          case "|":
          case "^":
          case "<<":
          case ">>":
            return union(l, r).map(asNumeric);
          default:
            return [];
        }
      }
      case "ConditionalExpression":
        this.ev(e.test);
        return union(this.ev(e.consequent), this.ev(e.alternate));
      case "TemplateString":
        return e.expressions.reduce((acc, x) => union(acc, this.ev(x)), []);
      case "ArrayExpression":
        return e.elements.reduce((acc, x) => union(acc, this.ev(x)), []);
      case "StructExpression":
        return e.properties.reduce((acc, p) => p.type === "StructProperty" && p.value ? union(acc, this.ev(p.value)) : acc, []);
      case "UnaryExpression": {
        const a = this.ev(e.argument);
        return e.operator === "!" ? [] : a.map(asNumeric);
      }
      case "UpdateExpression":
        this.ev(e.argument);
        return [];
      case "AssignmentExpression":
        this.execExpressionStatement(e);
        return [];
      default:
        return [];
    }
  }
  evIdentifier(e) {
    const ref = this.scopes.refOf.get(e);
    if (ref?.binding.kind === "local") return this.state.get(e.name) ?? [];
    if (ref?.binding.kind !== "free" && ref) return [];
    const name = e.name;
    if (name === "async_load") {
      const src = this.asyncSource();
      return src ? this.sourceFact(src.threat, `async_load (${src.description})`, e) : [];
    }
    if (name === "keyboard_string") return this.sourceFact("local", "keyboard_string (text typed by the player)", e);
    const argMatch = /^argument(\d+)$/.exec(name);
    if (argMatch && this.unit.fn) return [{ origin: { kind: "param", index: Number(argMatch[1]) }, numeric: false, path: [this.step(e, name)] }];
    if (this.owner && !this.index.globalVariables.has(name)) return this.objectStore.get(this.owner)?.get(name) ?? [];
    return this.globalStore.get(name) ?? (this.owner ? this.objectStore.get(this.owner)?.get(name) ?? [] : []);
  }
  evMember(e) {
    const key = this.keyOf(e);
    if (key && this.state.has(key)) return this.state.get(key);
    const base = e.object;
    const prop2 = e.property.name;
    if (base.type === "Identifier") {
      if (base.name === "global") return this.globalStore.get(prop2) ?? [];
      if (base.name === "self") return this.owner ? this.objectStore.get(this.owner)?.get(prop2) ?? [] : [];
      if (this.index.assets.get(base.name) === "objects") return this.objectStore.get(base.name)?.get(prop2) ?? [];
    }
    return this.ev(base);
  }
  evIndex(e) {
    const idxFacts = e.indices.map((i) => this.ev(i));
    void idxFacts;
    if (e.object.type === "Identifier") {
      const ref = this.scopes.refOf.get(e.object);
      if (e.object.name === "async_load" && ref?.binding.kind === "free") {
        const k = e.indices[0];
        if (k?.type === "StringLiteral" && SAFE_ASYNC_KEYS.has(k.value)) return [];
        const src = this.asyncSource();
        if (!src) return [];
        const label = this.unit.file.source.text.slice(e.start, e.end).replace(/\s+/g, " ");
        return this.sourceFact(src.threat, `${label} (${src.description})`, e);
      }
      if (e.object.name === "argument" && ref?.binding.kind === "free" && this.unit.fn && e.indices[0]?.type === "NumberLiteral") {
        return [{ origin: { kind: "param", index: e.indices[0].value }, numeric: false, path: [this.step(e, "argument")] }];
      }
    }
    return this.ev(e.object);
  }
  /** What `async_load` holds depends on the async event it is read in. */
  asyncSource() {
    const ev = this.unit.file.event;
    if (this.unit.file.kind !== "object-event" || ev?.kind !== "Other") return { threat: "remote", description: "async event data" };
    return ASYNC_EVENT_SOURCES[ev.num] ?? (ev.num >= 60 && ev.num <= 76 ? void 0 : { threat: "remote", description: "async event data" });
  }
  sourceFact(threat, description, node) {
    if (!this.threats.has(threat)) return [];
    const step = this.step(node, description);
    return [{ origin: { kind: "source", threat, description, step }, numeric: false, path: [step] }];
  }
  evCall(call) {
    const args = call.arguments.map((a) => this.ev(a));
    const callee = call.callee;
    if (callee.type !== "Identifier") {
      this.ev(callee);
      return [];
    }
    const ref = this.scopes.refOf.get(callee);
    if (ref && ref.binding.kind !== "free") return [];
    const name = callee.name;
    if (this.sanitizers.has(name) || CLEANSERS.has(name)) return [];
    const userFns = this.index.resolveFunction(name, this.unit.file);
    if (userFns.length > 0) return this.applySummaries(userFns, call, args, name);
    if (name === "script_execute" && call.arguments[0]?.type === "Identifier") {
      const target = this.index.resolveFunction(call.arguments[0].name, this.unit.file);
      if (target.length > 0) {
        this.checkSinks(name, call, args);
        return this.applySummaries(target, call, args.slice(1), call.arguments[0].name, 1);
      }
    }
    this.checkSinks(name, call, args);
    const mut = MUTATORS2[name];
    if (mut && call.arguments[0]) {
      const idx = mut === "rest" ? call.arguments.map((_, i) => i).slice(1) : mut;
      const facts = idx.reduce((acc, i) => union(acc, args[i] ?? []), []);
      if (facts.length) this.assign(call.arguments[0], union(facts, args[0] ?? []), call);
    }
    const source = this.sources[name];
    if (source) return this.sourceFact(source.threat, source.description, call);
    const p = PROPAGATORS[name];
    if (p) {
      const from = p.from === "all" ? args.map((_, i) => i) : p.from;
      let facts = from.reduce((acc, i) => union(acc, args[i] ?? []), []);
      if (p.numeric) facts = facts.map(asNumeric);
      return this.extend(facts, call, `${name}(...)`);
    }
    if (PATH_SANITIZERS.has(name)) return (args[0] ?? []).map((f) => ({ ...f, pathSafe: true }));
    return [];
  }
  applySummaries(fns, call, args, name, argOffset = 0) {
    let result = [];
    for (const fn of fns) {
      const summary = this.summaries.get(fn.node);
      if (!summary) continue;
      for (const [i, sinks] of summary.paramToSink) {
        const argNode = call.arguments[i + argOffset];
        for (const fact of args[i] ?? []) {
          for (const { hit, path } of sinks) {
            const callStep = this.step(argNode ?? call, `passed to ${name}() as ${fn.node.params[i]?.id.name ?? `argument ${i}`}`);
            this.flowToSink(fact, hit, [...fact.path, callStep, ...path]);
          }
        }
      }
      for (const [i, inner] of summary.paramToReturn) {
        for (const fact of args[i] ?? []) {
          const callStep = this.step(call, `returned from ${name}()`);
          result = union(result, [
            {
              ...fact,
              numeric: fact.numeric || inner.numeric,
              pathSafe: fact.pathSafe || inner.pathSafe,
              path: trimPath([...fact.path, ...inner.path.slice(1), callStep])
            }
          ]);
        }
      }
      result = union(result, summary.returnFacts.map((f) => ({ ...f, path: trimPath([...f.path, this.step(call, `returned from ${name}()`)]) })));
    }
    return result;
  }
  checkSinks(name, call, args) {
    const models = this.sinks[name];
    if (!models) return;
    for (const m of models) {
      if (m.when && !m.when(call)) continue;
      for (const i of m.args) {
        const arg = call.arguments[i];
        if (!arg) continue;
        for (const fact of args[i] ?? []) {
          if (fact.numeric && m.kind !== "code-injection" && m.kind !== "variable-injection") continue;
          if (fact.pathSafe && m.kind === "path-injection") continue;
          const hit = { kind: m.kind, fn: name, file: this.unit.file, call, arg };
          this.flowToSink(fact, hit, [...fact.path, this.step(arg, `${name}() argument`)]);
        }
      }
    }
  }
  flowToSink(fact, hit, path) {
    if (fact.origin.kind === "source") {
      if (!this.threats.has(fact.origin.threat)) return;
      const src = fact.origin.step;
      const key = `${hit.kind}|${hit.file.relPath}|${hit.arg.start}|${src.file.relPath}|${src.start}`;
      if (!this.findings.has(key)) this.findings.set(key, { kind: hit.kind, sink: hit, source: fact.origin, path: trimPath(path) });
      return;
    }
    const fn = this.unit.fn;
    if (!fn) return;
    const summary = this.summaries.get(fn.node);
    const list = summary.paramToSink.get(fact.origin.index) ?? [];
    if (!list.some((x) => x.hit.call === hit.call && x.hit.arg === hit.arg)) {
      list.push({ hit, path: trimPath(path) });
      summary.paramToSink.set(fact.origin.index, list);
      this.version++;
    }
  }
  // --- utilities -----------------------------------------------------------
  extend(facts, node, label) {
    if (facts.length === 0) return facts;
    const step = this.step(node, label);
    return facts.map((f) => ({ ...f, path: trimPath([...f.path, step]) }));
  }
  clone(s) {
    return new Map(s);
  }
  join(a, b) {
    const out = new Map(a);
    for (const [k, v] of b) out.set(k, union(out.get(k) ?? [], v));
    return out;
  }
};
function staticLeftmost(e) {
  if (e.type === "StringLiteral") return e.value;
  if (e.type === "TemplateString") return e.quasis[0];
  if (e.type === "BinaryExpression" && e.operator === "+") return staticLeftmost(e.left);
  return void 0;
}
function isConstant(e) {
  return e.type === "StringLiteral" || e.type === "NumberLiteral" || e.type === "BooleanLiteral" || e.type === "MemberExpression" && e.object.type === "Identifier" || e.type === "UnaryExpression" && e.argument.type === "NumberLiteral";
}
function sameOrigin(a, b) {
  if (a.origin.kind !== b.origin.kind || a.numeric !== b.numeric) return false;
  if (a.origin.kind === "param") return a.origin.index === b.origin.index;
  const sa = a.origin.step;
  const sb = b.origin.step;
  return sa.file === sb.file && sa.start === sb.start;
}
function union(a, b) {
  if (b.length === 0) return a;
  if (a.length === 0) return b.slice(0, MAX_FACTS);
  const out = [...a];
  for (const f of b) {
    if (out.length >= MAX_FACTS) break;
    const i = out.findIndex((o) => sameOrigin(o, f));
    if (i < 0) out.push(f);
    else if (f.path.length < out[i].path.length) out[i] = f;
  }
  return out;
}
function intersect(a, b) {
  return new Set([...a].filter((x) => b.has(x)));
}
function asNumeric(f) {
  return f.numeric ? f : { ...f, numeric: true };
}
function trimPath(path) {
  const out = [];
  for (const s of path) {
    const prev = out[out.length - 1];
    if (prev && prev.file === s.file && prev.start === s.start && prev.end === s.end) {
      if (!prev.message.includes(s.message)) out[out.length - 1] = { ...prev, message: `${prev.message}; ${s.message}` };
      continue;
    }
    out.push(s);
  }
  if (out.length <= MAX_PATH) return out;
  return [...out.slice(0, 3), ...out.slice(out.length - (MAX_PATH - 3))];
}

// src/rules/security.ts
function taintResults(ctx) {
  return ctx.shared("taint", () => analyzeTaint(ctx.index, ctx.config));
}
function toFlow(ctx, steps) {
  return steps.map((s) => ({ location: ctx.locate(s.file, s), message: s.message }));
}
var SINK_IMPACT = {
  "code-injection": "which lets whoever controls that data run arbitrary scripts or create arbitrary objects",
  "path-injection": "which lets whoever controls that data read, overwrite or delete arbitrary files",
  "command-injection": "which lets whoever controls that data run commands on the player's machine",
  "variable-injection": "which lets whoever controls that data read or overwrite any variable (for example `global.is_admin`)",
  "url-redirect": "which lets whoever controls that data send requests to, or open, any URL",
  "unsafe-deserialization": "which can crash the game or load attacker-shaped data structures"
};
function taintRule(kind, meta) {
  return {
    meta: { ...meta, kind: "path-problem", category: "security" },
    project(ctx) {
      for (const f of taintResults(ctx).findings) {
        if (f.kind !== kind) continue;
        const sinkLoc = ctx.locate(f.sink.file, f.sink.arg);
        ctx.report(sinkLoc, `${code(`${f.sink.fn}()`)} receives ${f.source.description}, ${SINK_IMPACT[kind]}.`, {
          flow: toFlow(ctx, f.path),
          related: [{ location: ctx.locate(f.source.step.file, f.source.step), message: "Untrusted data enters here" }]
        });
      }
    }
  };
}
var THREAT_NOTE = `By default only **remote** sources are tracked (data received in async networking/HTTP events, Steam lobby data). Set \`"threatModels": ["remote", "local"]\` in \`.gmlscan.json\` to also treat files, INI values, command-line arguments, the clipboard and \`keyboard_string\` as untrusted (useful for mod-loading or multiplayer save sharing).

Custom sources, sinks and sanitizers (for example your own networking extension) can be declared under \`"taint"\` in \`.gmlscan.json\`.`;
var codeInjection = taintRule("code-injection", {
  id: "gml/code-injection",
  name: "CodeInjection",
  severity: "error",
  precision: "high",
  tier: "default",
  securitySeverity: 9.3,
  cwe: [94, 470],
  short: "Untrusted data selects which script, method or object runs.",
  full: "Data from the network (or another untrusted source) reaches script_execute, method, instance_create_* or a similar call, letting a remote party choose which code runs.",
  help: `Data received from the network (or another untrusted source) decides **which script, method, DLL function or object** is used. Anyone who controls that data (a malicious server, another player, a man-in-the-middle) can then call any function in your game, not only the ones you intended.

A common pattern is \`script_execute(asset_get_index(packet.command))\`.

**How to fix:** map incoming values to an explicit allow-list instead of looking functions up by name.

\`\`\`gml
// Bad
var data = json_parse(async_load[? "result"]);
script_execute(asset_get_index(data.action));

// Good
static handlers = {
    move:  net_handle_move,
    chat:  net_handle_chat,
};
var data = json_parse(async_load[? "result"]);
if (variable_struct_exists(handlers, data.action)) {
    handlers[$ data.action](data);
}
\`\`\`

${THREAT_NOTE}`
});
var pathInjection = taintRule("path-injection", {
  id: "gml/path-injection",
  name: "PathInjection",
  severity: "error",
  precision: "high",
  tier: "default",
  securitySeverity: 7.5,
  cwe: [22, 73],
  short: "Untrusted data used as a file path.",
  full: "A file name built from untrusted data can escape the save directory (`../`) or point at arbitrary files once the GameMaker sandbox is disabled.",
  help: `A file path is built from untrusted data. With the file-system sandbox disabled (common for desktop games and mod loaders), values like \`../../AppData/...\` can read, overwrite or delete arbitrary files. Even inside the sandbox they can clobber other save files or config.

**How to fix:** never use received text as a path. Map it to known file names, or strip directories with \`filename_name()\` and validate the characters.

\`\`\`gml
// Bad
var slot = async_load[? "result"];
file_delete(slot + ".sav");

// Good
var slot = real(string_digits(async_load[? "result"]));
if (slot >= 0 && slot < 3) file_delete("save" + string(slot) + ".sav");
\`\`\`

${THREAT_NOTE}`
});
var commandInjection = taintRule("command-injection", {
  id: "gml/command-injection",
  name: "CommandInjection",
  severity: "error",
  precision: "high",
  tier: "default",
  securitySeverity: 9.8,
  cwe: [78],
  short: "Untrusted data reaches a shell/process execution extension.",
  full: "Data from an untrusted source reaches an extension function that runs shell commands or programs (execute_shell, ShellExecute, ...).",
  help: `An extension function that runs programs or shell commands (\`execute_shell\`, \`ShellExecute\`, \`execute_program\` ...) receives untrusted data. This lets an attacker run arbitrary commands on the player's computer: full remote code execution.

**How to fix:** never pass received data to a shell. If you must launch something, use a fixed program and a strict allow-list of arguments.

${THREAT_NOTE}`
});
var variableInjection = taintRule("variable-injection", {
  id: "gml/variable-injection",
  name: "VariableInjection",
  severity: "warning",
  precision: "high",
  tier: "default",
  securitySeverity: 7.3,
  cwe: [915],
  short: "Untrusted data chooses which variable is read or written.",
  full: "variable_instance_set/variable_global_set (and friends) with a name taken from untrusted data allows overwriting any variable, such as health, currency or admin flags.",
  help: `A variable **name** comes from untrusted data. In multiplayer or online games this lets a remote party read or overwrite *any* variable: \`global.coins\`, \`global.is_admin\`, \`hp\` ... This is the GML equivalent of a mass-assignment vulnerability.

**How to fix:** only accept an explicit list of names.

\`\`\`gml
// Bad
var msg = json_parse(async_load[? "result"]);
variable_instance_set(id, msg.key, msg.value);

// Good
static allowed = ["emote", "skin"];
if (array_contains(allowed, msg.key)) variable_instance_set(id, msg.key, msg.value);
\`\`\`

${THREAT_NOTE}`
});
var untrustedUrl = taintRule("url-redirect", {
  id: "gml/untrusted-url",
  name: "UntrustedUrl",
  severity: "warning",
  precision: "high",
  tier: "extended",
  securitySeverity: 6.1,
  cwe: [601, 918],
  short: "Untrusted data used as a URL to open or request.",
  full: "url_open or http_* called with a URL taken from untrusted data can send players to phishing pages or make the game request attacker-chosen addresses.",
  help: `A URL taken from untrusted data is opened in the player's browser (\`url_open\`) or requested by the game (\`http_get\`, \`http_request\` ...). Attackers can use it to send players to phishing pages, or make the game contact arbitrary hosts, including local-network addresses.

**How to fix:** only open URLs from a fixed list, or at least check the host against an allow-list.

${THREAT_NOTE}`
});
var unsafeDeserialization = taintRule("unsafe-deserialization", {
  id: "gml/unsafe-deserialization",
  name: "UnsafeDeserialization",
  severity: "warning",
  precision: "medium",
  tier: "extended",
  securitySeverity: 5.9,
  cwe: [502],
  short: "Untrusted data passed to ds_*_read / game_load_buffer.",
  full: "The ds_*_read functions and game_load_buffer trust their input's structure; malformed data from an untrusted source can crash the game or inject unexpected values.",
  help: `\`ds_map_read\`, \`ds_list_read\`, \`ds_grid_read\` and \`game_load_buffer\` decode GameMaker's internal serialisation format and assume the data is well-formed. Feeding them network data lets a remote party crash the game or smuggle nested data structures into it.

**How to fix:** exchange JSON (\`json_parse\`) and validate every field you read.

${THREAT_NOTE}`
});
var SECRET_PATTERNS = [
  { name: "AWS access key", re: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { name: "GitHub token", re: /\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b/ },
  { name: "Discord bot token", re: /\b[MN][A-Za-z\d_-]{23,27}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27,40}\b/ },
  { name: "Discord webhook URL", re: /https:\/\/(?:canary\.|ptb\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]{20,}/ },
  { name: "Slack token", re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/ },
  { name: "Slack webhook URL", re: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/]{20,}/ },
  { name: "Stripe secret key", re: /\b(sk|rk)_live_[0-9a-zA-Z]{20,}\b/ },
  { name: "Google API key", re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { name: "OpenAI API key", re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}\b/ },
  { name: "Anthropic API key", re: /\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}\b/ },
  { name: "SendGrid API key", re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/ },
  { name: "Twilio API key", re: /\bSK[0-9a-f]{32}\b/ },
  { name: "Mailgun API key", re: /\bkey-[0-9a-zA-Z]{32}\b/ },
  { name: "private key", re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----/ },
  { name: "JSON Web Token", re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/ },
  { name: "credentials in URL", re: /\b[a-z][a-z0-9+.-]*:\/\/[^\s/:@"']{1,64}:[^\s/:@"']{3,64}@[^\s/"']+/i }
];
var PLACEHOLDER = /^(your|my|insert|enter|replace|change|put|todo|xxx|example|sample|dummy|test|placeholder|none|null|undefined|secret|password|token|api[_-]?key)[_\s-]?|^<.*>$|^\$\{.*\}$|^\*+$|^x+$|^(.)\1+$/i;
function redactLine(line, secret) {
  const masked = secret.length <= 8 ? "****" : `${secret.slice(0, 4)}****`;
  return line.split(secret).join(masked).trim();
}
function entropy(s) {
  const counts = /* @__PURE__ */ new Map();
  for (const c of s) counts.set(c, (counts.get(c) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}
function looksLikeSecretValue(v) {
  return v.length >= 16 && v.length <= 512 && !/\s/.test(v) && !PLACEHOLDER.test(v) && entropy(v) >= 3.3 && /[0-9]/.test(v) && /[A-Za-z]/.test(v) && !/^https?:\/\/[^@]*$/.test(v) && !/^[a-z_]+$/.test(v);
}
function matchSecret(value) {
  return SECRET_PATTERNS.find((p) => p.re.test(value));
}
function assignedName(ancestors, literal) {
  const p = ancestors[ancestors.length - 1];
  if (!p) return void 0;
  if (p.type === "VarDeclarator" && p.init === literal) return p.id.name;
  if (p.type === "AssignmentExpression" && p.right === literal) {
    const l = p.left;
    if (l.type === "Identifier") return l.name;
    if (l.type === "MemberExpression") return l.property.name;
    if (l.type === "IndexExpression" && l.indices[0]?.type === "StringLiteral") return l.indices[0].value;
  }
  if (p.type === "StructProperty" && p.value === literal) return p.key.type === "Identifier" ? p.key.name : p.key.value;
  if (p.type === "MacroDeclaration") return p.id.name;
  if (p.type === "CallExpression" && p.callee.type === "Identifier" && /^(ds_map_(add|set|replace)|struct_set|variable_struct_set|variable_global_set|variable_instance_set)$/.test(p.callee.name)) {
    const keyArg = p.arguments[p.callee.name === "variable_global_set" ? 0 : 1];
    if (keyArg?.type === "StringLiteral" && keyArg !== literal) return keyArg.value;
  }
  return void 0;
}
var hardcodedSecret = {
  meta: {
    id: "gml/hardcoded-secret",
    name: "HardcodedSecret",
    category: "security",
    severity: "error",
    precision: "high",
    tier: "default",
    securitySeverity: 8.1,
    cwe: [798, 312],
    short: "API key, token, password or private key hard-coded in the project.",
    full: "Secrets in GML code, project options, datafiles or CI workflows ship to every player (or everyone with repository access). GameMaker builds can be decompiled, so treat any embedded secret as public.",
    help: `A credential (API key, bot token, webhook URL, password, private key ...) is written directly into the project.

- **In GML code or \`datafiles/\`:** it is compiled into the game. VM builds can be decompiled with tools like UndertaleModTool, and even YYC builds keep string literals readable, so **every player can extract it**.
- **In \`options/\`, extension settings or CI workflows:** anyone with access to the repository can read it.

**How to fix:**
1. **Revoke and rotate the secret now.** Assume it has already leaked.
2. Keep privileged keys on a server you control; the game talks to your server, not directly to the third-party API.
3. For CI (for example a GameMaker access key for Igor), use GitHub Actions secrets: \`\${{ secrets.GM_ACCESS_KEY }}\`.
4. Remove it from git history (\`git filter-repo\`), since deleting it in a new commit is not enough.`
  },
  file(ctx) {
    const snippetFor = (node, secret) => ({ snippet: redactLine(ctx.file.source.lineText(ctx.locate(node).startLine), secret) });
    const check = (node, value) => {
      const pattern = matchSecret(value);
      if (pattern) {
        const secret = pattern.re.exec(value)?.[0] ?? value;
        ctx.report(node, `Hard-coded ${pattern.name} in game code; it ships inside the build where players can extract it. Revoke it and move it server-side.`, snippetFor(node, secret));
        return;
      }
      const name = assignedName(ctx.ancestors, node);
      if (name && isSensitiveName(name) && looksLikeSecretValue(value)) {
        ctx.report(node, `${code(name)} is assigned what looks like a hard-coded secret; anything in GML ships inside the build where players can extract it.`, snippetFor(node, value));
      }
    };
    return {
      StringLiteral: (n) => check(n, n.value),
      TemplateString: (n) => {
        if (n.expressions.length === 0) check(n, n.quasis[0]);
      },
      MacroDeclaration: (n) => {
        if (n.value?.type === "StringLiteral" && isSensitiveName(n.id.name) && looksLikeSecretValue(n.value.value) && !matchSecret(n.value.value)) {
          ctx.report(n.value, `Macro ${code(n.id.name)} contains what looks like a hard-coded secret; macros are compiled into the build.`, snippetFor(n.value, n.value.value));
        }
      }
    };
  },
  project(ctx) {
    for (const rel of ctx.project.auxiliaryFiles) scanTextFile(ctx, rel);
  }
};
var KEY_VALUE = /["']?([A-Za-z0-9_.-]*?(?:pass(?:word|wd)?|pwd|secret|api[_-]?key|apikey|access[_-]?key|private[_-]?key|auth[_-]?token|token|client[_-]?secret|webhook)[A-Za-z0-9_.-]*)["']?\s*[:=]\s*["']?([^"'\s,}#]{16,})/gi;
function scanTextFile(ctx, rel) {
  const text = readText(join3(ctx.workspaceRoot, rel));
  if (text === void 0) return;
  const source = new SourceText(text);
  const isWorkflow = /\.github\/workflows\//.test(rel);
  const inShipped = rel.includes("/datafiles/") || rel.startsWith("datafiles/");
  const where = inShipped ? "a datafile that ships with the game, where players can read it" : isWorkflow ? "a CI workflow; use ${{ secrets.NAME }} instead" : "a file committed to the repository";
  for (const p of SECRET_PATTERNS) {
    const re = new RegExp(p.re.source, p.re.flags.includes("g") ? p.re.flags : p.re.flags + "g");
    for (const m of text.matchAll(re)) {
      const loc = ctx.locateText(rel, source, { start: m.index, end: m.index + m[0].length });
      ctx.report(loc, `Hard-coded ${p.name} in ${where}. Revoke it and remove it from the repository history.`, { snippet: redactLine(source.lineText(loc.startLine), m[0]) });
    }
  }
  for (const m of text.matchAll(KEY_VALUE)) {
    const [, key, value] = m;
    if (/public/i.test(key) || /\$\{\{/.test(m[0]) || !isSensitiveName(key) || !looksLikeSecretValue(value) || matchSecret(value)) continue;
    const start = m.index + m[0].lastIndexOf(value);
    const loc = ctx.locateText(rel, source, { start, end: start + value.length });
    ctx.report(loc, `${code(key)} looks like a hard-coded secret in ${where}.`, { snippet: redactLine(source.lineText(loc.startLine), value) });
  }
}
var HTTP_FUNCTIONS = { http_get: 0, http_get_file: 0, http_post_string: 0, http_request: 0, http_get_request_crossorigin: 0 };
var LOCAL_HOST = /^http:\/\/(localhost|127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|\[::1\])/i;
var insecureHttp = {
  meta: {
    id: "gml/insecure-http",
    name: "InsecureHttp",
    category: "security",
    severity: "warning",
    precision: "high",
    tier: "default",
    securitySeverity: 5.9,
    cwe: [319],
    short: "HTTP request over plain http://.",
    full: "Requests over http:// can be read and modified by anyone on the network path (public Wi-Fi, ISPs), including login tokens, save data and downloaded content.",
    help: `This request uses plain \`http://\`. Anyone between the player and the server (public Wi-Fi, a compromised router, the ISP) can read it (tokens, passwords, save data) and **modify the response**, which is especially dangerous if the game acts on what it downloads.

**How to fix:** use \`https://\`. Development servers on \`localhost\` or LAN addresses are not reported. Use a configuration-specific macro to switch URLs:

\`\`\`gml
#macro API_URL "https://api.example.com"
#macro Debug:API_URL "http://localhost:8080"
http_get(API_URL + "/scores");
\`\`\``
  },
  file(ctx) {
    return {
      CallExpression(n) {
        const name = builtinCallName(n, ctx);
        if (!name || !Object.hasOwn(HTTP_FUNCTIONS, name)) return;
        const url = staticPrefix(n.arguments[HTTP_FUNCTIONS[name]], ctx.index);
        if (!url || !/^http:\/\//i.test(url) || LOCAL_HOST.test(url)) return;
        ctx.report(n.arguments[HTTP_FUNCTIONS[name]], `${code(`${name}()`)} uses unencrypted ${code(url.length > 60 ? url.slice(0, 57) + "..." : url)}; use https:// so the request can't be read or tampered with.`);
      }
    };
  }
};
var HASH_FUNCTIONS = /* @__PURE__ */ new Set(["md5_string_utf8", "md5_string_unicode", "md5_buffer", "md5_file", "sha1_string_utf8", "sha1_string_unicode", "sha1_buffer", "sha1_file"]);
var PASSWORDISH = /(pass(word|wd|phrase)?|pwd|pin_?code|credential)/i;
var weakHash = {
  meta: {
    id: "gml/weak-password-hash",
    name: "WeakPasswordHash",
    category: "security",
    severity: "warning",
    precision: "medium",
    tier: "extended",
    securitySeverity: 7.5,
    cwe: [916, 328],
    short: "Password hashed with MD5/SHA-1.",
    full: "MD5 and SHA-1 are fast and unsalted; password hashes made with them are cracked in seconds.",
    help: `MD5 and SHA-1 are **fast** hashes. Billions of guesses per second on a GPU recover typical passwords almost instantly, and without a salt identical passwords give identical hashes.

**How to fix:** don't handle password hashing in the game client. Send the password over HTTPS to your server and hash it there with a password-hashing function (Argon2, bcrypt, scrypt). For integrity checks of save files use \`sha256\` or an HMAC with a server-held key, and remember that a key shipped in the client can be extracted.`
  },
  file(ctx) {
    return {
      CallExpression(n) {
        const name = builtinCallName(n, ctx);
        if (!name || !HASH_FUNCTIONS.has(name)) return;
        const argText = ctx.file.source.text.slice(n.arguments[0]?.start ?? n.start, n.arguments[0]?.end ?? n.end);
        const target = assignedName(ctx.ancestors, n) ?? "";
        if (!PASSWORDISH.test(argText) && !PASSWORDISH.test(target)) return;
        ctx.report(n, `${code(`${name}()`)} is used on a password; MD5/SHA-1 password hashes are cracked in seconds. Hash passwords server-side with Argon2/bcrypt.`);
      }
    };
  }
};
var RANDOM_FUNCTIONS = /* @__PURE__ */ new Set(["random", "irandom", "random_range", "irandom_range", "choose"]);
var TOKENISH = /(token|session|nonce|salt|secret|password|passwd|otp|auth|uuid|guid|api_?key|invite_?code|verification)/i;
var insecureRandomness = {
  meta: {
    id: "gml/insecure-randomness",
    name: "InsecureRandomness",
    category: "security",
    severity: "warning",
    precision: "medium",
    tier: "extended",
    securitySeverity: 5.3,
    cwe: [338],
    short: "Security token generated with random()/irandom().",
    full: "GameMaker's random functions are a seedable PRNG meant for gameplay; values derived from them are predictable and must not be used as tokens, session ids or salts.",
    help: `\`random\`, \`irandom\`, \`choose\` ... use a fast pseudo-random generator meant for gameplay. It is seeded predictably (\`random_set_seed\`, or the same seed on every run unless you call \`randomize()\`), so values derived from it can be guessed.

**How to fix:** generate session tokens, invite codes and similar values **on your server** with a cryptographically secure generator, and send them to the client.`
  },
  file(ctx) {
    const reported = /* @__PURE__ */ new Set();
    return {
      CallExpression(n) {
        const name = builtinCallName(n, ctx);
        if (!name || !RANDOM_FUNCTIONS.has(name)) return;
        for (let i = ctx.ancestors.length - 1; i >= 0; i--) {
          const a = ctx.ancestors[i];
          if (a.type === "FunctionDeclaration" || a.type === "FunctionExpression") {
            if (a.type === "FunctionDeclaration" && TOKENISH.test(a.id.name) && !reported.has(a)) {
              reported.add(a);
              ctx.report(n, `${code(`${name}()`)} is used to build ${code(a.id.name)}; GameMaker's PRNG is predictable, so generate security tokens on a server.`);
            }
            return;
          }
          const target = a.type === "VarDeclarator" ? a.id.name : a.type === "AssignmentExpression" ? a.left.type === "Identifier" ? a.left.name : a.left.type === "MemberExpression" ? a.left.property.name : void 0 : void 0;
          if (target) {
            if (TOKENISH.test(target) && !reported.has(a)) {
              reported.add(a);
              ctx.report(n, `${code(`${name}()`)} generates ${code(target)}; GameMaker's PRNG is predictable, so it must not be used for tokens, session ids or salts.`);
            }
            return;
          }
        }
      }
    };
  }
};
var LOG_FUNCTIONS = /* @__PURE__ */ new Set(["show_debug_message", "show_debug_message_ext", "show_message", "show_message_async", "show_error", "debug_log", "log", "trace"]);
var sensitiveDataLogged = {
  meta: {
    id: "gml/sensitive-data-logged",
    name: "SensitiveDataLogged",
    category: "security",
    severity: "warning",
    precision: "medium",
    tier: "extended",
    securitySeverity: 4.3,
    cwe: [532],
    short: "Password, token or key written to the debug log or a message box.",
    full: "Debug output ends up in log files, crash reports and screenshots or streams; secrets written there leak.",
    help: `A password, token or key is passed to \`show_debug_message\` (or similar). Debug output ends up in log files on the player's machine, in crash reports, and in bug-report screenshots and streams.

**How to fix:** log that the value exists, not the value itself, for example \`show_debug_message("token received: " + string(string_length(token)) + " chars")\`, or strip debug output from release builds with a configuration macro.`
  },
  file(ctx) {
    return {
      CallExpression(n) {
        const name = n.callee.type === "Identifier" ? n.callee.name : void 0;
        if (!name || !LOG_FUNCTIONS.has(name)) return;
        for (const arg of n.arguments) {
          let hit;
          const visit = (e) => {
            if (hit) return;
            if (e.type === "Identifier" && isSensitiveName(e.name)) hit = e.name;
            else if (e.type === "MemberExpression") {
              if (isSensitiveName(e.property.name)) hit = ctx.file.source.text.slice(e.start, e.end);
              else visit(e.object);
            } else if (e.type === "IndexExpression" && e.indices[0]?.type === "StringLiteral" && isSensitiveName(e.indices[0].value)) hit = ctx.file.source.text.slice(e.start, e.end);
            else if (e.type === "BinaryExpression") {
              visit(e.left);
              visit(e.right);
            } else if (e.type === "TemplateString") e.expressions.forEach(visit);
            else if (e.type === "CallExpression" && e.callee.type === "Identifier" && (e.callee.name === "string" || e.callee.name === "json_stringify")) e.arguments.forEach(visit);
          };
          visit(arg);
          if (hit) {
            ctx.report(arg, `${code(hit)} is written to ${code(`${name}()`)}; secrets in logs leak through log files, crash reports and screenshots.`);
            return;
          }
        }
      }
    };
  }
};
var SECURITY_RULES = [codeInjection, pathInjection, commandInjection, variableInjection, untrustedUrl, unsafeDeserialization, hardcodedSecret, insecureHttp, weakHash, insecureRandomness, sensitiveDataLogged];

// src/rules/index.ts
var SYNTAX_ERROR_RULE = {
  meta: {
    id: "gml/syntax-error",
    name: "SyntaxError",
    category: "correctness",
    severity: "error",
    precision: "high",
    tier: "default",
    short: "GML syntax error.",
    full: "The file contains a syntax error; GameMaker will refuse to compile it.",
    help: `The scanner could not parse this code, and GameMaker won't compile it either.

If GameMaker **does** compile the file, the scanner's parser is missing some syntax. Please open an issue with the snippet, and suppress it meanwhile with \`// gmlscan-ignore-file gml/syntax-error\`.`
  },
  file(ctx) {
    for (const err of ctx.file.ast.errors.slice(0, 10)) ctx.report(err, `Syntax error: ${err.message}.`);
  }
};
var ALL_RULES = [...CORRECTNESS_RULES, ...GAMEMAKER_RULES, ...SECURITY_RULES, ...PERFORMANCE_RULES, ...MAINTAINABILITY_RULES, ...PROJECT_RULES];

// src/rules/patterns.ts
var IGNORED_KEYS = /* @__PURE__ */ new Set(["type", "start", "end", "parenthesized", "raw", "rawOperator", "bodyStart", "comments", "errors"]);
function isEllipsis(n) {
  if (!n || typeof n !== "object") return false;
  const node = n;
  return node.type === "PatternEllipsis" || node.type === "Parameter" && node.id.name === "..." || node.type === "ExpressionStatement" && node.expression.type === "PatternEllipsis";
}
function isNode(v) {
  return !!v && typeof v === "object" && typeof v.type === "string";
}
function match(p, n, b) {
  if (p.type === "PatternEllipsis") return true;
  if (p.type === "Metavariable") return bind(p.name, n, b);
  if (p.type === "Identifier" && p.name.startsWith("$") && p.name.length > 1) {
    if (n.type !== "Identifier") return false;
    return bind(p.name.slice(1), n, b);
  }
  if (p.type === "ExpressionStatement" && p.expression.type === "Metavariable" && n.type !== "ExpressionStatement") return false;
  if (p.type !== n.type) return false;
  const pr = p;
  const nr = n;
  for (const key of Object.keys(pr)) {
    if (IGNORED_KEYS.has(key)) continue;
    const pv = pr[key];
    const nv = nr[key];
    if (Array.isArray(pv)) {
      if (!Array.isArray(nv) || !matchList(pv, nv, 0, 0, b)) return false;
    } else if (isNode(pv)) {
      if (!isNode(nv) || !match(pv, nv, b)) return false;
    } else if (pv === null) {
      if (key === "alternate" || key === "init" || key === "argument") continue;
      if (nv !== null) return false;
    } else if (pv !== nv) {
      return false;
    }
  }
  return true;
}
function bind(name, n, b) {
  const existing = b.get(name);
  if (existing) return sameExpression(existing, n);
  b.set(name, n);
  return true;
}
function matchList(ps, ns, i, j, b) {
  if (i === ps.length) return j === ns.length;
  if (isEllipsis(ps[i])) {
    for (let k = j; k <= ns.length; k++) {
      const trial2 = new Map(b);
      if (matchList(ps, ns, i + 1, k, trial2)) {
        for (const [key, v] of trial2) b.set(key, v);
        return true;
      }
    }
    return false;
  }
  if (j >= ns.length) return false;
  const trial = new Map(b);
  if (!match(ps[i], ns[j], trial) || !matchList(ps, ns, i + 1, j + 1, trial)) return false;
  for (const [key, v] of trial) b.set(key, v);
  return true;
}
function createPatternRules(configs) {
  return configs.map((cfg) => {
    const sources = Array.isArray(cfg.pattern) ? cfg.pattern : [cfg.pattern];
    const compiled = sources.map((src) => {
      const { node, errors } = parsePattern(src);
      if (errors.length) throw new ConfigError(`Pattern rule "${cfg.id}": cannot parse pattern \`${src}\`: ${errors[0].message}`);
      if (Array.isArray(node) && node.length === 0) throw new ConfigError(`Pattern rule "${cfg.id}": pattern is empty`);
      return { node };
    });
    const where = Object.entries(cfg.where ?? {}).map(([k, v]) => {
      try {
        return [k.replace(/^\$/, ""), new RegExp(v)];
      } catch (e) {
        throw new ConfigError(`Pattern rule "${cfg.id}": invalid regex for ${k}: ${e.message}`);
      }
    });
    const id = cfg.id.includes("/") ? cfg.id : `custom/${cfg.id}`;
    const rule = {
      meta: {
        id,
        name: id.replace(/^.*\//, "").replace(/(^|[-_])(\w)/g, (_, _s, c) => c.toUpperCase()),
        category: cfg.category ?? "correctness",
        severity: cfg.severity ?? "warning",
        precision: "high",
        tier: "default",
        short: cfg.message.replace(/\$[A-Z_][A-Z0-9_]*/g, "\u2026"),
        full: cfg.message.replace(/\$[A-Z_][A-Z0-9_]*/g, "\u2026"),
        help: cfg.help ?? `Custom rule defined in \`.gmlscan.json\`.

Pattern:

\`\`\`gml
${sources.join("\n")}
\`\`\``
      },
      file(ctx) {
        if (cfg.events?.length) {
          const ev = ctx.file.event;
          if (!ev || !cfg.events.some((e) => e === ev.kind || e === ev.displayName)) return;
        }
        const visitors = {};
        const report = (node, b) => {
          for (const [name, re] of where) {
            const bound = b.get(name);
            if (!bound || !re.test(ctx.file.source.text.slice(bound.start, bound.end))) return;
          }
          const message = cfg.message.replace(/\$([A-Z_][A-Z0-9_]*)/g, (m, name) => {
            const bound = b.get(name);
            return bound ? ctx.file.source.text.slice(bound.start, bound.end) : m;
          });
          ctx.report(node, message);
        };
        for (const c of compiled) addVisitors(visitors, c, report);
        return visitors;
      }
    };
    return rule;
  });
}
function addVisitors(visitors, c, report) {
  const on = (type, fn) => {
    const prev = visitors[type];
    visitors[type] = prev ? (n) => {
      prev(n);
      fn(n);
    } : fn;
  };
  const single = !Array.isArray(c.node) ? c.node : c.node.length === 1 ? c.node[0] : void 0;
  if (single) {
    const target = single.type === "ExpressionStatement" ? single.expression : single;
    if (target.type === "Metavariable" || target.type === "PatternEllipsis") throw new ConfigError("A pattern must not consist of only a metavariable or `...`");
    on(target.type, (n) => {
      const b = /* @__PURE__ */ new Map();
      if (match(target, n, b)) report(n, b);
    });
    return;
  }
  const stmts = c.node;
  const seq = (list) => {
    for (let s = 0; s < list.length; s++) {
      const b = /* @__PURE__ */ new Map();
      if (matchList([...stmts, { type: "PatternEllipsis", start: 0, end: 0 }], list.slice(s), 0, 0, b)) {
        report(list[s], b);
      }
    }
  };
  on("Program", (n) => seq(n.body));
  on("BlockStatement", (n) => seq(n.body));
  on("SwitchCase", (n) => seq(n.body));
}

// src/engine/suppress.ts
var Suppressions = class _Suppressions {
  lines = /* @__PURE__ */ new Map();
  file;
  static fromComments(comments, source) {
    const s = new _Suppressions();
    for (const c of comments) {
      const m = /gmlscan-(?:ignore|disable)-(next-line|line|file)\b([^\n]*)/.exec(c.value);
      if (!m) continue;
      const ids = parseIds(m[2]);
      const line = source.position(c.start).line;
      if (m[1] === "file") s.file = merge(s.file, ids);
      else if (m[1] === "line") s.add(line, ids);
      else s.add(source.position(c.end).line + 1, ids);
    }
    return s;
  }
  add(line, ids) {
    this.lines.set(line, merge(this.lines.get(line), ids));
  }
  isSuppressed(ruleId, line) {
    return matches(this.file, ruleId) || matches(this.lines.get(line), ruleId);
  }
};
function parseIds(text) {
  const list = text.split("--")[0].split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);
  return list.length ? new Set(list.map((id) => id.includes("/") ? id : `gml/${id}`)) : "all";
}
function merge(a, b) {
  if (a === "all" || b === "all") return "all";
  return /* @__PURE__ */ new Set([...a ?? [], ...b]);
}
function matches(set, ruleId) {
  return set === "all" || set !== void 0 && set.has(ruleId);
}

// src/engine/scanner.ts
var FUNCTION_TYPES2 = /* @__PURE__ */ new Set(["FunctionDeclaration", "FunctionExpression"]);
var SEVERITY_RANK = { error: 0, warning: 1, note: 2 };
function exceedsThreshold(result, failOn) {
  if (failOn === "none") return false;
  const limit = SEVERITY_RANK[failOn];
  return result.findings.some((f) => SEVERITY_RANK[f.severity] <= limit);
}
function isRuleInSuite(meta, suite) {
  switch (suite) {
    case "default":
      return meta.tier === "default";
    case "security-extended":
      return meta.tier === "default" || meta.tier === "extended" && meta.category === "security";
    case "security-and-quality":
    case "all":
      return true;
  }
}
function selectRules(config, rules, onlyRules) {
  const selected = [];
  for (const rule of rules) {
    const setting = config.rules[rule.meta.id];
    const level = typeof setting === "string" ? setting : setting?.severity;
    if (onlyRules && !onlyRules.includes(rule.meta.id)) continue;
    if (level === "off") continue;
    if (level === void 0 && !onlyRules && !isRuleInSuite(rule.meta, config.suite)) continue;
    selected.push({ rule, severity: level ?? rule.meta.severity });
  }
  return selected;
}
function scan(options) {
  const started = performance.now();
  const root = resolve(options.root);
  const config = { ...options.config ?? loadConfig(root, options.configPath) };
  if (options.suite) config.suite = options.suite;
  if (options.runtime) config.runtime = options.runtime;
  if (options.threatModels?.length) config.threatModels = options.threatModels;
  const rules = [...ALL_RULES, SYNTAX_ERROR_RULE, ...createPatternRules(config.patterns)];
  const selected = selectRules(config, rules, options.onlyRules);
  const severityOf = new Map(selected.map((s) => [s.rule.meta.id, s.severity]));
  const isIgnored = makeIgnoreMatcher(config.ignore);
  const workspace = loadWorkspace(root, { isIgnored });
  const findings = [];
  const internalErrors = [];
  const projects = [];
  let filesScanned = 0;
  workspace.projects[0]?.auxiliaryFiles.push(...workspace.auxiliaryFiles);
  for (const project of workspace.projects) {
    const index = new ProjectIndex(project, config.runtime);
    projects.push({
      name: project.name,
      yyp: project.yyp?.relPath,
      files: project.files.length,
      runtime: config.runtime ?? project.yyp?.ideVersion,
      runtimeChecks: index.runtimeIndex >= 0
    });
    filesScanned += project.files.length;
    const projectFindings = [];
    const makeFinding = (ruleId, location, message, source, extras) => ({
      ruleId,
      severity: extras?.severity ?? severityOf.get(ruleId) ?? "warning",
      message,
      location,
      related: extras?.related,
      flow: extras?.flow,
      snippet: extras?.snippet ?? source?.lineText(location.startLine).trim()
    });
    for (const file of project.files) {
      runFileRules(file, index, config, selected, projectFindings, internalErrors, makeFinding);
    }
    const sharedCache = /* @__PURE__ */ new Map();
    const sources = new Map(project.files.map((f) => [f.relPath, f.source]));
    if (project.yyp) sources.set(project.yyp.relPath, project.yyp.source);
    for (const { rule } of selected) {
      if (!rule.project) continue;
      const ctx = {
        workspaceRoot: root,
        project,
        index,
        config,
        report: (location, message, extras) => projectFindings.push(makeFinding(rule.meta.id, location, message, sources.get(location.file), extras)),
        locate: (file, span) => locate(file.relPath, file.source, span),
        locateText: (relPath, source, span) => {
          sources.set(relPath, source);
          return locate(relPath, source, span);
        },
        shared: (key, compute) => {
          if (!sharedCache.has(key)) sharedCache.set(key, compute());
          return sharedCache.get(key);
        }
      };
      try {
        rule.project(ctx);
      } catch (e) {
        internalErrors.push({ ruleId: rule.meta.id, message: errorMessage(e) });
      }
    }
    findings.push(...applySuppressions(projectFindings, project, isIgnored));
  }
  return {
    findings: dedupeAndSort(findings),
    rules: selected.map((s) => s.rule.meta),
    projects,
    filesScanned,
    durationMs: performance.now() - started,
    config,
    internalErrors
  };
}
function runFileRules(file, index, config, selected, out, internalErrors, makeFinding) {
  const scopes = index.scopes.get(file);
  let ancestors = [];
  const handlers = /* @__PURE__ */ new Map();
  const exitHandlers = [];
  for (const { rule } of selected) {
    if (!rule.file) continue;
    const ctx = {
      file,
      index,
      scopes,
      config,
      get ancestors() {
        return ancestors;
      },
      enclosingFunction() {
        for (let i = ancestors.length - 1; i >= 0; i--) {
          const a = ancestors[i];
          if (FUNCTION_TYPES2.has(a.type)) return a;
        }
        return null;
      },
      report: (span, message, extras) => out.push(makeFinding(rule.meta.id, locate(file.relPath, file.source, span), message, file.source, extras)),
      locate: (span) => locate(file.relPath, file.source, span)
    };
    let visitors;
    try {
      visitors = rule.file(ctx);
    } catch (e) {
      internalErrors.push({ ruleId: rule.meta.id, file: file.relPath, message: errorMessage(e) });
      continue;
    }
    if (!visitors) continue;
    for (const [key, fn] of Object.entries(visitors)) {
      if (!fn) continue;
      if (key === "file:exit") {
        exitHandlers.push({ ruleId: rule.meta.id, fn });
        continue;
      }
      const list = handlers.get(key) ?? [];
      list.push({ ruleId: rule.meta.id, fn });
      handlers.set(key, list);
    }
  }
  if (handlers.size === 0 && exitHandlers.length === 0) return;
  const failed = /* @__PURE__ */ new Set();
  const call = (ruleId, fn) => {
    if (failed.has(ruleId)) return;
    try {
      fn();
    } catch (e) {
      failed.add(ruleId);
      internalErrors.push({ ruleId, file: file.relPath, message: errorMessage(e) });
    }
  };
  walk(
    file.ast,
    (node, wctx) => {
      ancestors = wctx.ancestors;
      const hs = handlers.get(node.type);
      if (hs) for (const h of hs) call(h.ruleId, () => h.fn(node));
    },
    (node, wctx) => {
      ancestors = wctx.ancestors;
      const hs = handlers.get(`exit:${node.type}`);
      if (hs) for (const h of hs) call(h.ruleId, () => h.fn(node));
    }
  );
  ancestors = [];
  for (const h of exitHandlers) call(h.ruleId, h.fn);
}
function locate(relPath, source, span) {
  const s = source.position(span.start);
  const e = source.position(Math.max(span.end, span.start));
  return { file: relPath, startLine: s.line, startColumn: s.column, endLine: e.line, endColumn: e.line === s.line && e.column === s.column ? e.column + 1 : e.column };
}
function applySuppressions(findings, project, isIgnored) {
  const byFile = /* @__PURE__ */ new Map();
  for (const f of project.files) byFile.set(f.relPath, Suppressions.fromComments(f.ast.comments, f.source));
  return findings.filter((f) => !isIgnored(f.location.file) && !byFile.get(f.location.file)?.isSuppressed(f.ruleId, f.location.startLine));
}
function dedupeAndSort(findings) {
  const seen = /* @__PURE__ */ new Set();
  const out = [];
  for (const f of findings) {
    const l = f.location;
    const key = `${f.ruleId}|${l.file}|${l.startLine}|${l.startColumn}|${l.endLine}|${l.endColumn}|${f.message}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(f);
  }
  const rank = { error: 0, warning: 1, note: 2 };
  return out.sort(
    (a, b) => a.location.file.localeCompare(b.location.file) || a.location.startLine - b.location.startLine || a.location.startColumn - b.location.startColumn || rank[a.severity] - rank[b.severity] || a.ruleId.localeCompare(b.ruleId)
  );
}
function errorMessage(e) {
  return e instanceof Error ? `${e.message}${e.stack ? `
${e.stack.split("\n").slice(1, 4).join("\n")}` : ""}` : String(e);
}

// src/report/text.ts
var ANSI = {
  reset: "\x1B[0m",
  bold: "\x1B[1m",
  dim: "\x1B[2m",
  red: "\x1B[31m",
  yellow: "\x1B[33m",
  blue: "\x1B[34m",
  cyan: "\x1B[36m",
  green: "\x1B[32m",
  underline: "\x1B[4m"
};
function formatText(result, options) {
  const c = (code2, s) => options.color ? ANSI[code2] + s + ANSI.reset : s;
  const sevColor = { error: "red", warning: "yellow", note: "blue" };
  const lines = [];
  const byFile = /* @__PURE__ */ new Map();
  for (const f of result.findings) {
    const list = byFile.get(f.location.file) ?? [];
    list.push(f);
    byFile.set(f.location.file, list);
  }
  for (const [file, findings] of byFile) {
    lines.push("", c("underline", file));
    for (const f of findings) {
      const pos = `${f.location.startLine}:${f.location.startColumn}`.padEnd(8);
      lines.push(`  ${c("dim", pos)} ${c(sevColor[f.severity], f.severity.padEnd(7))} ${f.message}  ${c("dim", f.ruleId)}`);
      if (f.snippet) lines.push(`  ${" ".repeat(8)} ${c("dim", "\u2502 " + truncate(f.snippet, 110))}`);
      if (options.showPaths && f.flow && f.flow.length > 1) {
        f.flow.forEach((s, i) => {
          const arrow = i === 0 ? "source" : i === f.flow.length - 1 ? "sink  " : "step  ";
          lines.push(`  ${" ".repeat(8)} ${c("cyan", arrow)} ${c("dim", `${s.location.file}:${s.location.startLine}`)} ${s.message}`);
        });
      }
    }
  }
  const counts = { error: 0, warning: 0, note: 0 };
  for (const f of result.findings) counts[f.severity]++;
  const total = result.findings.length;
  lines.push("");
  for (const p of result.projects) {
    const rt = p.runtime ? `, runtime ${p.runtime}${p.runtimeChecks ? "" : " (no exact runtime data: availability checks off)"}` : "";
    lines.push(c("dim", `Project ${p.name}${p.yyp ? ` (${p.yyp})` : " (no .yyp)"}: ${p.files} GML files${rt}`));
  }
  const summary = `${total} problem${total === 1 ? "" : "s"} (${counts.error} error${counts.error === 1 ? "" : "s"}, ${counts.warning} warning${counts.warning === 1 ? "" : "s"}, ${counts.note} note${counts.note === 1 ? "" : "s"}) in ${result.filesScanned} files, ${result.rules.length} rules, ${(result.durationMs / 1e3).toFixed(1)}s`;
  lines.push(total === 0 ? c("green", `\u2714 ${summary}`) : c(counts.error ? "red" : "yellow", c("bold", `\u2716 ${summary}`)));
  for (const e of result.internalErrors.slice(0, 5)) lines.push(c("yellow", `internal error in ${e.ruleId}${e.file ? ` (${e.file})` : ""}: ${e.message.split("\n")[0]}`));
  return lines.join("\n") + "\n";
}
function truncate(s, n) {
  return s.length > n ? s.slice(0, n - 1) + "\u2026" : s;
}

// src/report/sarif.ts
import { createHash } from "node:crypto";
import { join as join4, relative as relative2, sep as sep2 } from "node:path";
import { pathToFileURL } from "node:url";
var LEVEL = { error: "error", warning: "warning", note: "note" };
var PROBLEM_SEVERITY = { error: "error", warning: "warning", note: "recommendation" };
function ruleTags(meta) {
  const tags = [meta.category];
  if (meta.category === "correctness" || meta.category === "project") tags.push("reliability");
  if (meta.category === "security") tags.push("security");
  for (const cwe of meta.cwe ?? []) tags.push(`external/cwe/cwe-${String(cwe).padStart(3, "0")}`);
  tags.push("gml", "gamemaker");
  return [...new Set(tags)];
}
function toSarif(result, options) {
  const uriBase = options.uriBase ?? options.scanRoot;
  const toUri = (file) => relative2(uriBase, join4(options.scanRoot, file)).split(sep2).join("/");
  const ruleIndex = /* @__PURE__ */ new Map();
  const rules = result.rules.map((meta, i) => {
    ruleIndex.set(meta.id, i);
    return {
      id: meta.id,
      name: meta.name,
      shortDescription: { text: meta.short },
      fullDescription: { text: meta.full },
      help: { text: stripMarkdown(meta.help), markdown: meta.help },
      helpUri: `${options.informationUri}/blob/main/docs/rules.md#${meta.id.replace(/[^a-z0-9]+/gi, "").toLowerCase()}`,
      defaultConfiguration: { level: LEVEL[meta.severity] },
      properties: {
        tags: ruleTags(meta),
        kind: meta.kind ?? "problem",
        precision: meta.precision,
        "problem.severity": PROBLEM_SEVERITY[meta.severity],
        ...meta.securitySeverity !== void 0 ? { "security-severity": meta.securitySeverity.toFixed(1) } : {}
      }
    };
  });
  const physical = (loc) => ({
    artifactLocation: { uri: toUri(loc.file), uriBaseId: "%SRCROOT%" },
    region: { startLine: loc.startLine, startColumn: loc.startColumn, endLine: loc.endLine, endColumn: loc.endColumn }
  });
  const occurrences = /* @__PURE__ */ new Map();
  const results = result.findings.map((f) => {
    const basis = `${f.ruleId}\0${toUri(f.location.file)}\0${(f.snippet ?? "").replace(/\s+/g, " ")}`;
    const n = (occurrences.get(basis) ?? 0) + 1;
    occurrences.set(basis, n);
    const hash = createHash("sha256").update(`${basis}\0${n}`).digest("hex").slice(0, 32);
    const out = {
      ruleId: f.ruleId,
      ...ruleIndex.has(f.ruleId) ? { ruleIndex: ruleIndex.get(f.ruleId) } : {},
      level: LEVEL[f.severity],
      message: { text: f.message },
      locations: [{ physicalLocation: physical(f.location) }],
      partialFingerprints: { primaryLocationLineHash: `${hash}:1` }
    };
    if (f.related?.length) {
      out.relatedLocations = f.related.map((r, i) => ({ id: i + 1, physicalLocation: physical(r.location), message: { text: r.message } }));
    }
    if (f.flow?.length) {
      out.codeFlows = [
        {
          threadFlows: [
            {
              locations: f.flow.map((s) => ({ location: { physicalLocation: physical(s.location), message: { text: s.message } } }))
            }
          ]
        }
      ];
    }
    return out;
  });
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: options.toolName,
            semanticVersion: options.toolVersion,
            version: options.toolVersion,
            informationUri: options.informationUri,
            rules
          }
        },
        automationDetails: { id: `${options.category ?? "gml-code-scanner"}/` },
        originalUriBaseIds: { "%SRCROOT%": { uri: pathToFileURL(uriBase + sep2).href } },
        invocations: [
          {
            executionSuccessful: true,
            toolExecutionNotifications: result.internalErrors.map((e) => ({
              level: "warning",
              message: { text: `Rule ${e.ruleId} failed${e.file ? ` on ${e.file}` : ""}: ${e.message.split("\n")[0]}` }
            }))
          }
        ],
        results,
        columnKind: "utf16CodeUnits"
      }
    ]
  };
}
function stripMarkdown(md) {
  return md.replace(/```[a-z]*\n?/g, "").replace(/\*\*(.+?)\*\*/g, "$1").replace(/`([^`]+)`/g, "$1");
}

// package.json
var package_default = {
  name: "gml-code-scanner",
  version: "1.0.0",
  description: "Static analysis and security scanning for GameMaker (GML) projects. Finds bugs and vulnerabilities and reports them as SARIF for GitHub code scanning.",
  type: "module",
  license: "MIT",
  author: "Mackery",
  repository: {
    type: "git",
    url: "git+https://github.com/Mackery6969/GML-Code-Scanner.git"
  },
  homepage: "https://github.com/Mackery6969/GML-Code-Scanner#readme",
  bugs: {
    url: "https://github.com/Mackery6969/GML-Code-Scanner/issues"
  },
  keywords: [
    "gamemaker",
    "gml",
    "static-analysis",
    "sarif",
    "code-scanning",
    "security",
    "linter",
    "github-action"
  ],
  bin: {
    gmlscan: "dist/cli.js"
  },
  files: [
    "dist/cli.js",
    "README.md",
    "LICENSE"
  ],
  engines: {
    node: ">=20"
  },
  scripts: {
    build: "node scripts/build.ts",
    typecheck: "tsc",
    test: 'node --test "test/**/*.test.ts"',
    docs: "node src/cli.ts --list-rules --format markdown --output docs/rules.md",
    check: "npm run typecheck && npm test && npm run build && npm run docs",
    scan: "node src/cli.ts",
    "gen:builtins": "node scripts/gen-builtins.ts"
  },
  devDependencies: {
    "@types/node": "^24.13.6",
    esbuild: "^0.28.2",
    typescript: "^7.0.2"
  }
};

// src/version.ts
var TOOL_NAME = "GML Code Scanner";
var VERSION = package_default.version;
var REPOSITORY_URL = "https://github.com/Mackery6969/GML-Code-Scanner";

// src/cli.ts
var HELP = `${TOOL_NAME} ${VERSION}: static analysis for GameMaker (GML) projects

Usage: gmlscan [path] [options]

  path                      Project or repository directory to scan (default: .)

Output:
  -f, --format <fmt>        text (default), json, or sarif
  -o, --output <file>       Write the report to a file instead of stdout
      --sarif <file>        Also write a SARIF report (for GitHub code scanning)
      --paths               Show source \u2192 sink data-flow paths in text output
      --no-color            Disable colours

Analysis:
  -c, --config <file>       Config file (default: .gmlscan.json in the scanned directory)
      --suite <name>        default | security-extended | security-and-quality | all
      --rule <id>           Only run this rule (repeatable)
      --runtime <version>   Target GameMaker runtime (default: from the .yyp IDEVersion)
      --threat-model <m>    remote and/or local (repeatable; default: remote)
      --fail-on <level>     Exit with 1 when findings at this level exist:
                            error (default), warning, note, none

Other:
      --list-rules          List all rules (use --format markdown for docs)
      --init                Write a starter .gmlscan.json
  -v, --version             Print the version
  -h, --help                Show this help

Suppress a finding with a comment:  // gmlscan-ignore-next-line gml/rule-id
Docs: ${REPOSITORY_URL}
`;
function listRules(format) {
  const rules = [...ALL_RULES, SYNTAX_ERROR_RULE].map((r) => r.meta);
  if (format === "json") return JSON.stringify(rules, null, 2) + "\n";
  if (format === "markdown") {
    const suites = ["default", "security-extended", "security-and-quality"];
    const out = [
      "# Rules",
      "",
      "<!-- Generated by `gmlscan --list-rules --format markdown`. Do not edit by hand. -->",
      "",
      "| Rule | Severity | Category | Suites |",
      "| --- | --- | --- | --- |"
    ];
    for (const m of rules) {
      const inSuites = suites.filter((s) => isRuleInSuite(m, s)).map((s) => `\`${s}\``).join(", ");
      out.push(`| [\`${m.id}\`](#${m.id.replace(/[^a-z0-9]+/gi, "").toLowerCase()}) | ${m.severity} | ${m.category} | ${inSuites} |`);
    }
    for (const m of rules) {
      out.push("", `## ${m.id}`, "", `<a id="${m.id.replace(/[^a-z0-9]+/gi, "").toLowerCase()}"></a>`, "", `**${m.short}**`, "");
      const facts = [`Severity: ${m.severity}`, `Precision: ${m.precision}`, `Category: ${m.category}`];
      if (m.securitySeverity !== void 0) facts.push(`Security severity: ${m.securitySeverity.toFixed(1)}`);
      if (m.cwe?.length) facts.push(`CWE: ${m.cwe.map((c) => `[CWE-${c}](https://cwe.mitre.org/data/definitions/${c}.html)`).join(", ")}`);
      out.push(facts.join(" \xB7 "), "", m.help);
    }
    return out.join("\n") + "\n";
  }
  const width = Math.max(...rules.map((m) => m.id.length));
  return rules.map((m) => `${m.id.padEnd(width)}  ${m.severity.padEnd(7)}  ${m.tier.padEnd(8)}  ${m.short}`).join("\n") + "\n";
}
var STARTER_CONFIG = `{
  // GML Code Scanner configuration. See ${REPOSITORY_URL}#configuration
  // Query suite: default | security-extended | security-and-quality | all
  "suite": "default",

  // Turn rules off or change their severity: "off" | "error" | "warning" | "note"
  "rules": {
    // "gml/unused-function": "off"
  },

  // Paths to skip (globs, relative to this file)
  "ignore": [
    // "extensions/**",
    // "scripts/vendor_*/**"
  ],

  // Untrusted data to track: "remote" (network/HTTP) and optionally "local" (files, user input)
  "threatModels": ["remote"],

  // Variables with these prefixes are treated as declared globals
  "globalPrefixes": [],

  // Taint models for your own extensions, e.g. a custom networking DLL:
  "taint": {
    "sources": [
      // { "function": "net_receive_string", "kind": "remote" }
    ],
    "sinks": [
      // { "function": "my_dll_run", "arguments": [0], "kind": "command-injection" }
    ],
    "sanitizers": []
  },

  // Custom pattern rules ($X = metavariable, ... = anything)
  "patterns": [
    // {
    //   "id": "no-debug-overlay",
    //   "pattern": "show_debug_overlay(true)",
    //   "message": "Remove the debug overlay before release.",
    //   "severity": "warning"
    // }
  ]
}
`;
function main(argv) {
  let args;
  try {
    args = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        format: { type: "string", short: "f" },
        output: { type: "string", short: "o" },
        sarif: { type: "string" },
        paths: { type: "boolean" },
        "no-color": { type: "boolean" },
        config: { type: "string", short: "c" },
        suite: { type: "string" },
        rule: { type: "string", multiple: true },
        runtime: { type: "string" },
        "threat-model": { type: "string", multiple: true },
        "fail-on": { type: "string" },
        "list-rules": { type: "boolean" },
        init: { type: "boolean" },
        version: { type: "boolean", short: "v" },
        help: { type: "boolean", short: "h" }
      }
    });
  } catch (e) {
    process.stderr.write(`gmlscan: ${e.message}

${HELP}`);
    return 2;
  }
  const o = args.values;
  if (o.help) {
    process.stdout.write(HELP);
    return 0;
  }
  if (o.version) {
    process.stdout.write(`${VERSION}
`);
    return 0;
  }
  if (o["list-rules"]) {
    const text = listRules(o.format ?? "text");
    if (o.output) {
      mkdirSync(dirname2(resolve2(o.output)), { recursive: true });
      writeFileSync(o.output, text);
    } else process.stdout.write(text);
    return 0;
  }
  const root = resolve2(args.positionals[0] ?? ".");
  if (!existsSync3(root)) {
    process.stderr.write(`gmlscan: path not found: ${root}
`);
    return 2;
  }
  if (o.init) {
    const target = join5(root, CONFIG_FILE_NAMES[0]);
    if (existsSync3(target)) {
      process.stderr.write(`gmlscan: ${target} already exists
`);
      return 2;
    }
    writeFileSync(target, STARTER_CONFIG);
    process.stdout.write(`Wrote ${target}
`);
    return 0;
  }
  const format = o.format ?? "text";
  if (!["text", "json", "sarif"].includes(format)) {
    process.stderr.write(`gmlscan: unknown format "${format}" (expected text, json or sarif)
`);
    return 2;
  }
  const failOn = o["fail-on"] ?? "error";
  if (!["error", "warning", "note", "none"].includes(failOn)) {
    process.stderr.write(`gmlscan: --fail-on must be error, warning, note or none
`);
    return 2;
  }
  const suites = ["default", "security-extended", "security-and-quality", "all"];
  if (o.suite && !suites.includes(o.suite)) {
    process.stderr.write(`gmlscan: --suite must be one of ${suites.join(", ")}
`);
    return 2;
  }
  const threats = o["threat-model"];
  if (threats?.some((t) => t !== "remote" && t !== "local")) {
    process.stderr.write(`gmlscan: --threat-model must be remote or local
`);
    return 2;
  }
  let result;
  try {
    result = scan({
      root,
      configPath: o.config ? resolve2(o.config) : void 0,
      suite: o.suite,
      onlyRules: o.rule,
      runtime: o.runtime,
      threatModels: threats
    });
  } catch (e) {
    if (e instanceof ConfigError) {
      process.stderr.write(`gmlscan: ${e.message}
`);
      return 2;
    }
    throw e;
  }
  const sarifOf = () => JSON.stringify(toSarif(result, { toolName: TOOL_NAME, toolVersion: VERSION, informationUri: REPOSITORY_URL, scanRoot: root }), null, 2) + "\n";
  let report;
  if (format === "sarif") report = sarifOf();
  else if (format === "json") report = JSON.stringify({ version: VERSION, projects: result.projects, findings: result.findings, filesScanned: result.filesScanned, durationMs: Math.round(result.durationMs) }, null, 2) + "\n";
  else report = formatText(result, { color: !o["no-color"] && !o.output && process.stdout.isTTY === true && !process.env.NO_COLOR, showPaths: o.paths });
  if (o.output) {
    mkdirSync(dirname2(resolve2(o.output)), { recursive: true });
    writeFileSync(o.output, report);
    process.stderr.write(`Wrote ${result.findings.length} findings to ${o.output}
`);
  } else {
    process.stdout.write(report);
  }
  if (o.sarif) {
    mkdirSync(dirname2(resolve2(o.sarif)), { recursive: true });
    writeFileSync(o.sarif, sarifOf());
  }
  return exceedsThreshold(result, failOn) ? 1 : 0;
}
var invokedDirectly = process.argv[1] && /(?:cli\.(?:ts|js)|gmlscan)$/.test(process.argv[1].replace(/\\/g, "/"));
if (invokedDirectly) process.exitCode = main(process.argv.slice(2));
export {
  main
};

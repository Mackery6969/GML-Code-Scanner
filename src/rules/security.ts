import { readFileSync } from "node:fs";
import { join } from "node:path";
import type * as A from "../parser/ast.ts";
import type { FlowStep, ProjectContext, Rule, RuleMeta } from "../engine/types.ts";
import { analyzeTaint, type SinkKind, type Step, type TaintAnalysis } from "../analysis/taint.ts";
import { SourceText } from "../project/source.ts";
import { builtinCallName, code, isSensitiveName, staticPrefix } from "./util.ts";

// ---------------------------------------------------------------------------
// Taint-tracking rules

function taintResults(ctx: ProjectContext): TaintAnalysis {
  return ctx.shared("taint", () => analyzeTaint(ctx.index, ctx.config));
}

function toFlow(ctx: ProjectContext, steps: Step[]): FlowStep[] {
  return steps.map((s) => ({ location: ctx.locate(s.file, s), message: s.message }));
}

const SINK_IMPACT: Record<SinkKind, string> = {
  "code-injection": "which lets whoever controls that data run arbitrary scripts or create arbitrary objects",
  "path-injection": "which lets whoever controls that data read, overwrite or delete arbitrary files",
  "command-injection": "which lets whoever controls that data run commands on the player's machine",
  "variable-injection": "which lets whoever controls that data read or overwrite any variable (for example `global.is_admin`)",
  "url-redirect": "which lets whoever controls that data send requests to, or open, any URL",
  "unsafe-deserialization": "which can crash the game or load attacker-shaped data structures",
};

function taintRule(kind: SinkKind, meta: Omit<RuleMeta, "kind" | "category">): Rule {
  return {
    meta: { ...meta, kind: "path-problem", category: "security" },
    project(ctx) {
      for (const f of taintResults(ctx).findings) {
        if (f.kind !== kind) continue;
        const sinkLoc = ctx.locate(f.sink.file, f.sink.arg);
        ctx.report(sinkLoc, `${code(`${f.sink.fn}()`)} receives ${f.source.description}, ${SINK_IMPACT[kind]}.`, {
          flow: toFlow(ctx, f.path),
          related: [{ location: ctx.locate(f.source.step.file, f.source.step), message: "Untrusted data enters here" }],
        });
      }
    },
  };
}

const THREAT_NOTE = `By default only **remote** sources are tracked (data received in async networking/HTTP events, Steam lobby data). Set \`"threatModels": ["remote", "local"]\` in \`.gmlscan.json\` to also treat files, INI values, command-line arguments, the clipboard and \`keyboard_string\` as untrusted (useful for mod-loading or multiplayer save sharing).

Custom sources, sinks and sanitizers (for example your own networking extension) can be declared under \`"taint"\` in \`.gmlscan.json\`.`;

export const codeInjection = taintRule("code-injection", {
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

${THREAT_NOTE}`,
});

export const pathInjection = taintRule("path-injection", {
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

${THREAT_NOTE}`,
});

export const commandInjection = taintRule("command-injection", {
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

${THREAT_NOTE}`,
});

export const variableInjection = taintRule("variable-injection", {
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

${THREAT_NOTE}`,
});

export const untrustedUrl = taintRule("url-redirect", {
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

${THREAT_NOTE}`,
});

export const unsafeDeserialization = taintRule("unsafe-deserialization", {
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

${THREAT_NOTE}`,
});

// ---------------------------------------------------------------------------
// Hard-coded secrets

interface SecretPattern {
  name: string;
  re: RegExp;
}

const SECRET_PATTERNS: SecretPattern[] = [
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
  { name: "credentials in URL", re: /\b[a-z][a-z0-9+.-]*:\/\/[^\s/:@"']{1,64}:[^\s/:@"']{3,64}@[^\s/"']+/i },
];

const PLACEHOLDER = /^(your|my|insert|enter|replace|change|put|todo|xxx|example|sample|dummy|test|placeholder|none|null|undefined|secret|password|token|api[_-]?key)[_\s-]?|^<.*>$|^\$\{.*\}$|^\*+$|^x+$|^(.)\1+$/i;

function entropy(s: string): number {
  const counts = new Map<string, number>();
  for (const c of s) counts.set(c, (counts.get(c) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function looksLikeSecretValue(v: string): boolean {
  return v.length >= 16 && v.length <= 512 && !/\s/.test(v) && !PLACEHOLDER.test(v) && entropy(v) >= 3.3 && /[0-9]/.test(v) && /[A-Za-z]/.test(v) && !/^https?:\/\/[^@]*$/.test(v) && !/^[a-z_]+$/.test(v);
}

function matchSecret(value: string): SecretPattern | undefined {
  return SECRET_PATTERNS.find((p) => p.re.test(value));
}

/** Name of the variable/key a string literal is assigned to, if any. */
function assignedName(ancestors: readonly A.Node[], literal: A.Node): string | undefined {
  const p = ancestors[ancestors.length - 1];
  if (!p) return undefined;
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
  return undefined;
}

export const hardcodedSecret: Rule = {
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
4. Remove it from git history (\`git filter-repo\`), since deleting it in a new commit is not enough.`,
  },
  file(ctx) {
    const check = (node: A.StringLiteral | A.TemplateString, value: string) => {
      const pattern = matchSecret(value);
      if (pattern) {
        ctx.report(node, `Hard-coded ${pattern.name} in game code; it ships inside the build where players can extract it. Revoke it and move it server-side.`);
        return;
      }
      const name = assignedName(ctx.ancestors, node);
      if (name && isSensitiveName(name) && looksLikeSecretValue(value)) {
        ctx.report(node, `${code(name)} is assigned what looks like a hard-coded secret; anything in GML ships inside the build where players can extract it.`);
      }
    };
    return {
      StringLiteral: (n) => check(n, n.value),
      TemplateString: (n) => {
        if (n.expressions.length === 0) check(n, n.quasis[0]);
      },
      MacroDeclaration: (n) => {
        if (n.value?.type === "StringLiteral" && isSensitiveName(n.id.name) && looksLikeSecretValue(n.value.value) && !matchSecret(n.value.value)) {
          ctx.report(n.value, `Macro ${code(n.id.name)} contains what looks like a hard-coded secret; macros are compiled into the build.`);
        }
      },
    };
  },
  project(ctx) {
    for (const rel of ctx.project.auxiliaryFiles) scanTextFile(ctx, rel);
  },
};

const KEY_VALUE = /["']?([A-Za-z0-9_.-]*?(?:pass(?:word|wd)?|pwd|secret|api[_-]?key|apikey|access[_-]?key|private[_-]?key|auth[_-]?token|token|client[_-]?secret|webhook)[A-Za-z0-9_.-]*)["']?\s*[:=]\s*["']?([^"'\s,}#]{16,})/gi;

export function scanTextFile(ctx: ProjectContext, rel: string): void {
  let text: string;
  try {
    text = readFileSync(join(ctx.workspaceRoot, rel), "utf8");
  } catch {
    return;
  }
  const source = new SourceText(text);
  const isWorkflow = /\.github\/workflows\//.test(rel);
  const inShipped = rel.includes("/datafiles/") || rel.startsWith("datafiles/");
  const where = inShipped ? "a datafile that ships with the game, where players can read it" : isWorkflow ? "a CI workflow; use ${{ secrets.NAME }} instead" : "a file committed to the repository";
  for (const p of SECRET_PATTERNS) {
    const re = new RegExp(p.re.source, p.re.flags.includes("g") ? p.re.flags : p.re.flags + "g");
    for (const m of text.matchAll(re)) {
      ctx.report(ctx.locateText(rel, source, { start: m.index!, end: m.index! + m[0].length }), `Hard-coded ${p.name} in ${where}. Revoke it and remove it from the repository history.`);
    }
  }
  for (const m of text.matchAll(KEY_VALUE)) {
    const [, key, value] = m;
    if (/public/i.test(key) || /\$\{\{/.test(m[0]) || !isSensitiveName(key) || !looksLikeSecretValue(value) || matchSecret(value)) continue;
    const start = m.index! + m[0].lastIndexOf(value);
    ctx.report(ctx.locateText(rel, source, { start, end: start + value.length }), `${code(key)} looks like a hard-coded secret in ${where}.`);
  }
}

// ---------------------------------------------------------------------------

const HTTP_FUNCTIONS: Record<string, number> = { http_get: 0, http_get_file: 0, http_post_string: 0, http_request: 0, http_get_request_crossorigin: 0 };
const LOCAL_HOST = /^http:\/\/(localhost|127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|\[::1\])/i;

export const insecureHttp: Rule = {
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
\`\`\``,
  },
  file(ctx) {
    return {
      CallExpression(n) {
        const name = builtinCallName(n, ctx);
        if (!name || !Object.hasOwn(HTTP_FUNCTIONS, name)) return;
        const url = staticPrefix(n.arguments[HTTP_FUNCTIONS[name]], ctx.index);
        if (!url || !/^http:\/\//i.test(url) || LOCAL_HOST.test(url)) return;
        ctx.report(n.arguments[HTTP_FUNCTIONS[name]], `${code(`${name}()`)} uses unencrypted ${code(url.length > 60 ? url.slice(0, 57) + "..." : url)}; use https:// so the request can't be read or tampered with.`);
      },
    };
  },
};

const HASH_FUNCTIONS = new Set(["md5_string_utf8", "md5_string_unicode", "md5_buffer", "md5_file", "sha1_string_utf8", "sha1_string_unicode", "sha1_buffer", "sha1_file"]);
const PASSWORDISH = /(pass(word|wd|phrase)?|pwd|pin_?code|credential)/i;

export const weakHash: Rule = {
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

**How to fix:** don't handle password hashing in the game client. Send the password over HTTPS to your server and hash it there with a password-hashing function (Argon2, bcrypt, scrypt). For integrity checks of save files use \`sha256\` or an HMAC with a server-held key, and remember that a key shipped in the client can be extracted.`,
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
      },
    };
  },
};

const RANDOM_FUNCTIONS = new Set(["random", "irandom", "random_range", "irandom_range", "choose"]);
const TOKENISH = /(token|session|nonce|salt|secret|password|passwd|otp|auth|uuid|guid|api_?key|invite_?code|verification)/i;

export const insecureRandomness: Rule = {
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

**How to fix:** generate session tokens, invite codes and similar values **on your server** with a cryptographically secure generator, and send them to the client.`,
  },
  file(ctx) {
    const reported = new Set<A.Node>();
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
          const target = a.type === "VarDeclarator" ? a.id.name : a.type === "AssignmentExpression" ? (a.left.type === "Identifier" ? a.left.name : a.left.type === "MemberExpression" ? a.left.property.name : undefined) : undefined;
          if (target) {
            if (TOKENISH.test(target) && !reported.has(a)) {
              reported.add(a);
              ctx.report(n, `${code(`${name}()`)} generates ${code(target)}; GameMaker's PRNG is predictable, so it must not be used for tokens, session ids or salts.`);
            }
            return;
          }
        }
      },
    };
  },
};

const LOG_FUNCTIONS = new Set(["show_debug_message", "show_debug_message_ext", "show_message", "show_message_async", "show_error", "debug_log", "log", "trace"]);

export const sensitiveDataLogged: Rule = {
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

**How to fix:** log that the value exists, not the value itself, for example \`show_debug_message("token received: " + string(string_length(token)) + " chars")\`, or strip debug output from release builds with a configuration macro.`,
  },
  file(ctx) {
    return {
      CallExpression(n) {
        const name = n.callee.type === "Identifier" ? n.callee.name : undefined;
        if (!name || !LOG_FUNCTIONS.has(name)) return;
        for (const arg of n.arguments) {
          let hit: string | undefined;
          const visit = (e: A.Node) => {
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
      },
    };
  },
};

export const SECURITY_RULES: Rule[] = [codeInjection, pathInjection, commandInjection, variableInjection, untrustedUrl, unsafeDeserialization, hardcodedSecret, insecureHttp, weakHash, insecureRandomness, sensitiveDataLogged];

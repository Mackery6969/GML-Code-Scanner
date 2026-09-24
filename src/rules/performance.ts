import type * as A from "../parser/ast.ts";
import { walk } from "../parser/walk.ts";
import type { FileContext, Rule, Severity } from "../engine/types.ts";
import { isPerFrameEvent } from "../project/events.ts";
import { availableInRuntime, getBuiltinFunction } from "../semantic/builtins.ts";
import { FUNCTION_TYPES, LOOP_TYPES, builtinCallName, code, describeEvent, isInLoop, sameExpression, staticString } from "./util.ts";

interface ExpensiveCall {
  severity: Severity;
  why: string;
  /** Report even when inside a condition. */
  evenWhenConditional: boolean;
}

const EXPENSIVE: Record<string, ExpensiveCall> = {};
const add = (names: string[], info: ExpensiveCall) => names.forEach((n) => (EXPENSIVE[n] = info));
add(["file_text_open_read", "file_text_open_write", "file_text_open_append", "file_bin_open", "ini_open", "buffer_load", "buffer_save", "buffer_save_ext", "game_save", "game_load", "file_find_first", "directory_exists", "file_exists", "json_load"], {
  severity: "warning",
  why: "touches the disk every frame",
  evenWhenConditional: false,
});
add(["sprite_add", "sprite_add_ext", "font_add", "audio_create_stream", "background_add"], {
  severity: "warning",
  why: "loads a file from disk every frame (and leaks the asset unless it is deleted)",
  evenWhenConditional: false,
});
add(["surface_getpixel", "surface_getpixel_ext", "draw_getpixel", "draw_getpixel_ext", "buffer_get_surface", "sprite_create_from_surface"], {
  severity: "warning",
  why: "reads pixels back from the GPU every frame, which stalls the rendering pipeline",
  evenWhenConditional: false,
});
add(["shader_get_uniform", "shader_get_sampler_index", "shader_get_uniform_buffer", "layer_get_id", "asset_get_index", "layer_get_all_elements", "tag_get_assets", "tag_get_asset_ids"], {
  severity: "note",
  why: "looks up the same handle every frame; look it up once (for example in the Create event) and store it in a variable",
  evenWhenConditional: true,
});
add(["json_parse", "json_stringify", "json_decode", "json_encode"], {
  severity: "note",
  why: "parses or serialises JSON every frame",
  evenWhenConditional: false,
});

const CONDITIONAL_TYPES = new Set(["IfStatement", "SwitchStatement", "ConditionalExpression", "WithStatement"]);

export const perFrameExpensiveCall: Rule = {
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
\`\`\``,
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
      },
    };
  },
};

/** `if (u == -1) u = shader_get_uniform(...)`: the result is cached. */
function isLazyInit(call: A.CallExpression, ctx: FileContext): boolean {
  const parent = ctx.ancestors[ctx.ancestors.length - 1];
  let target: string | undefined;
  if (parent?.type === "AssignmentExpression" && parent.right === call) {
    target = parent.left.type === "Identifier" ? parent.left.name : parent.left.type === "MemberExpression" ? parent.left.property.name : undefined;
  }
  if (!target) return false;
  return ctx.ancestors.some((a) => {
    if (a.type !== "IfStatement") return false;
    let mentions = false;
    walk(a.test, (n) => {
      if ((n.type === "Identifier" && n.name === target) || (n.type === "MemberExpression" && n.property.name === target)) mentions = true;
    });
    return mentions;
  });
}

export const stringCharAtLoop: Rule = {
  meta: {
    id: "gml/string-char-at-loop",
    name: "StringCharAtInLoop",
    category: "performance",
    severity: "note",
    precision: "high",
    tier: "default",
    short: "Character-by-character string loop is quadratic.",
    full: "GameMaker strings are UTF-8, so `string_char_at(s, i)` scans from the start of the string on every call. Looping over a string this way takes O(n²) time.",
    help: `GameMaker stores strings as UTF-8, so finding the *i*-th character means scanning from the start of the string. Calling \`string_char_at\` (or \`string_ord_at\`, or \`string_copy(s, i, 1)\`) inside a loop over the string is therefore **O(n²)**. This is noticeable for long strings (dialogue, save files, level data).

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
\`\`\``,
  },
  file(ctx) {
    const hasForeach = (() => {
      const fn = getBuiltinFunction("string_foreach");
      return !!fn && availableInRuntime(fn.runtimeMask, ctx.index.runtimeIndex);
    })();
    const reported = new Set<A.Node>();
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
        ctx.report(n, `${code(`${name}()`)} indexed by the loop counter makes this loop O(n²) on UTF-8 strings; ${fix}.`);
      },
    };
  },
};

function innermostLoop(ancestors: readonly A.Node[]): A.Node | undefined {
  for (let i = ancestors.length - 1; i >= 0; i--) {
    if (FUNCTION_TYPES.has(ancestors[i].type)) return undefined;
    if (LOOP_TYPES.has(ancestors[i].type)) return ancestors[i];
  }
  return undefined;
}

function loopCounter(loop: A.Node): string | undefined {
  if (loop.type === "ForStatement" && loop.init) {
    if (loop.init.type === "VarDeclaration") return loop.init.declarations[0]?.id.name;
    if (loop.init.type === "ExpressionStatement" && loop.init.expression.type === "AssignmentExpression" && loop.init.expression.left.type === "Identifier") return loop.init.expression.left.name;
  }
  if (loop.type === "WhileStatement" || loop.type === "RepeatStatement" || loop.type === "DoUntilStatement") {
    // `while (i <= n) { ...; i++; }`: any variable incremented in the body counts.
    let counter: string | undefined;
    walk(loop, (n) => {
      if (!counter && n.type === "UpdateExpression" && n.argument.type === "Identifier") counter = n.argument.name;
      if (!counter && n.type === "AssignmentExpression" && (n.operator === "+=" || n.operator === "-=") && n.left.type === "Identifier") counter = n.left.name;
    });
    return counter;
  }
  return undefined;
}

function mentions(expr: A.Expression | undefined, name: string): boolean {
  if (!expr) return false;
  let found = false;
  walk(expr, (n) => {
    if (n.type === "Identifier" && n.name === name) found = true;
  });
  return found;
}

export const instanceNumberExists: Rule = {
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
\`\`\``,
  },
  file(ctx) {
    const isCount = (e: A.Expression) => e.type === "CallExpression" && builtinCallName(e, ctx) === "instance_number";
    const num = (e: A.Expression) => (e.type === "NumberLiteral" ? e.value : undefined);
    return {
      BinaryExpression(n) {
        let call: A.Expression | undefined;
        let op = n.operator as string;
        let value: number | undefined;
        if (isCount(n.left)) {
          call = n.left;
          value = num(n.right);
        } else if (isCount(n.right)) {
          call = n.right;
          value = num(n.left);
          op = ({ "<": ">", ">": "<", "<=": ">=", ">=": "<=" } as Record<string, string>)[op] ?? op;
        }
        if (!call || value === undefined) return;
        const exists = (op === ">" && value === 0) || (op === ">=" && value === 1) || (op === "!=" && value === 0);
        const notExists = (op === "==" && value === 0) || (op === "<" && value === 1) || (op === "<=" && value === 0);
        if (!exists && !notExists) return;
        const arg = ctx.file.source.text.slice((call as A.CallExpression).arguments[0]?.start ?? call.start, (call as A.CallExpression).arguments[0]?.end ?? call.end);
        ctx.report(n, `Use ${code(`${notExists ? "!" : ""}instance_exists(${arg})`)} instead of counting every instance with instance_number().`);
      },
    };
  },
};

const LENGTH_FUNCTIONS = new Set(["array_length", "ds_list_size", "ds_map_size", "string_length", "ds_grid_width", "ds_grid_height", "ds_queue_size", "ds_stack_size", "ds_priority_size", "buffer_get_size", "instance_number", "struct_names_count", "variable_struct_names_count"]);
const MUTATORS = /^(array_(push|insert|delete|pop|shift|resize|copy|sort|reverse|filter_ext|map_ext|unique_ext)|ds_(list|map|grid|queue|stack|priority)_(add|insert|delete|clear|set|replace|resize|copy|read|enqueue|dequeue|push|pop|delete_min|delete_max|shuffle|sort)|instance_(create_layer|create_depth|destroy|activate|deactivate)|buffer_resize|struct_remove|variable_struct_remove)/;

export const loopInvariantLength: Rule = {
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
\`\`\``,
  },
  file(ctx) {
    return {
      ForStatement(n) {
        if (!n.test) return;
        let lengthCall: A.CallExpression | undefined;
        walk(n.test, (e) => {
          if (!lengthCall && e.type === "CallExpression" && LENGTH_FUNCTIONS.has(builtinCallName(e, ctx) ?? "")) lengthCall = e;
        });
        const target = lengthCall?.arguments[0];
        if (!lengthCall || !target || (target.type !== "Identifier" && target.type !== "MemberExpression")) return;
        if (modifies(n.body, target) || (n.update && modifies(n.update, target))) return;
        const name = (lengthCall.callee as A.Identifier).name;
        ctx.report(lengthCall, `${code(`${name}()`)} is re-evaluated on every iteration; the loop doesn't change ${code(ctx.file.source.text.slice(target.start, target.end))}, so cache the size in a local before the loop.`);
      },
    };
  },
};

function modifies(body: A.Node, target: A.Expression): boolean {
  let found = false;
  walk(body, (n, c) => {
    if (found) return c.skip();
    if (n.type === "AssignmentExpression" || n.type === "UpdateExpression") {
      const lhs = n.type === "AssignmentExpression" ? n.left : n.argument;
      let base: A.Expression = lhs;
      while (base.type === "IndexExpression" || (base.type === "MemberExpression" && !sameExpression(base, target))) base = base.object;
      if (sameExpression(base, target) || sameExpression(lhs, target)) found = true;
    } else if (n.type === "CallExpression" && n.callee.type === "Identifier") {
      const name = n.callee.name;
      if (MUTATORS.test(name) && n.arguments.some((a) => sameExpression(a, target))) found = true;
      // Unknown functions might modify it.
      else if (!getBuiltinFunction(name) && n.arguments.some((a) => sameExpression(a, target))) found = true;
    }
  });
  return found;
}

export const redundantScriptExecute: Rule = {
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
\`\`\``,
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
      },
    };
  },
};

const LITERAL_ACCESS: Record<string, { nameArg: number; direct: (args: string[], name: string) => string }> = {
  variable_instance_get: { nameArg: 1, direct: (a, n) => `${a[0]}.${n}` },
  variable_instance_set: { nameArg: 1, direct: (a, n) => `${a[0]}.${n} = ${a[2]}` },
  variable_struct_get: { nameArg: 1, direct: (a, n) => `${a[0]}.${n}` },
  variable_struct_set: { nameArg: 1, direct: (a, n) => `${a[0]}.${n} = ${a[2]}` },
  struct_get: { nameArg: 1, direct: (a, n) => `${a[0]}.${n}` },
  struct_set: { nameArg: 1, direct: (a, n) => `${a[0]}.${n} = ${a[2]}` },
  variable_global_get: { nameArg: 0, direct: (_a, n) => `global.${n}` },
  variable_global_set: { nameArg: 0, direct: (a, n) => `global.${n} = ${a[1]}` },
};

export const literalVariableAccess: Rule = {
  meta: {
    id: "gml/literal-variable-access",
    name: "LiteralVariableAccess",
    category: "performance",
    severity: "note",
    precision: "very-high",
    tier: "quality",
    short: "Reflection call with a constant name; use direct access.",
    full: "`variable_instance_get(inst, \"hp\")` and similar calls with a literal name are slower than `inst.hp` and invisible to static checks. `asset_get_index(\"spr_x\")` with a literal name should reference the asset directly.",
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

Referencing assets directly also keeps them from being removed by "remove unused assets".`,
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
      },
    };
  },
};

export const mathShortcut: Rule = {
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
| \`sqrt(sqr(x2 - x1) + sqr(y2 - y1))\` | \`point_distance(x1, y1, x2, y2)\` |`,
  },
  file(ctx) {
    const isSquare = (e: A.Expression) =>
      (e.type === "CallExpression" && (builtinCallName(e, ctx) === "sqr" || (builtinCallName(e, ctx) === "power" && e.arguments[1]?.type === "NumberLiteral" && e.arguments[1].value === 2))) ||
      (e.type === "BinaryExpression" && e.operator === "*" && sameExpression(e.left, e.right));
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
      },
    };
  },
};

export const nestedWithPerFrame: Rule = {
  meta: {
    id: "gml/nested-with-per-frame",
    name: "NestedWithPerFrame",
    category: "performance",
    severity: "note",
    precision: "medium",
    tier: "quality",
    short: "Nested `with` loops over objects every frame (O(n×m)).",
    full: "A `with (obj_a)` inside another `with (obj_b)` in a Step or Draw event visits every pair of instances every frame.",
    help: `\`with (object)\` loops over every instance of that object. Nesting two of them in a Step or Draw event visits every **pair** of instances, every frame. With 100 of each that is 10,000 iterations per frame.

**How to fix:** use collision functions (\`instance_place_list\`, \`collision_circle_list\`), spatial partitioning, or cache the results.`,
  },
  file(ctx) {
    const file = ctx.file;
    if (file.kind !== "object-event" || !isPerFrameEvent(file.event)) return;
    const isObjectLoop = (e: A.Expression) => (e.type === "Identifier" && (ctx.index.assets.get(e.name) === "objects" || e.name === "all"));
    return {
      WithStatement(n) {
        if (!isObjectLoop(n.object) || ctx.enclosingFunction()) return;
        const outer = ctx.ancestors.find((a) => a.type === "WithStatement" && isObjectLoop(a.object));
        if (outer) ctx.report(n, `Nested ${code("with")} over objects in ${describeEvent(file)} visits every pair of instances every frame.`);
      },
    };
  },
};

export const stringConcatInLoop: Rule = {
  meta: {
    id: "gml/string-concat-in-loop",
    name: "StringConcatInLoop",
    category: "performance",
    severity: "note",
    precision: "medium",
    tier: "quality",
    short: "String built by repeated concatenation in a loop.",
    full: "Each `s += ...` creates a new string and copies the old one, so building a long string in a loop is O(n²).",
    help: `Strings are immutable: every \`s += piece\` allocates a new string and copies everything built so far. In a loop this is **O(n²)**.

**How to fix:** collect the pieces in an array and join them once, or write to a text buffer.

\`\`\`gml
// Before
var out = "";
for (var i = 0; i < array_length(lines); i++) out += lines[i] + "\\n";

// After
var out = string_join_ext("\\n", lines);
\`\`\``,
  },
  file(ctx) {
    const reported = new Set<string>();
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
        ctx.report(n, `${code(n.left.name)} is built by repeated string concatenation inside a loop (O(n²)); collect the pieces in an array and join them once.`);
      },
    };
  },
};

export const PERFORMANCE_RULES: Rule[] = [
  perFrameExpensiveCall,
  stringCharAtLoop,
  instanceNumberExists,
  loopInvariantLength,
  redundantScriptExecute,
  literalVariableAccess,
  mathShortcut,
  nestedWithPerFrame,
  stringConcatInLoop,
];

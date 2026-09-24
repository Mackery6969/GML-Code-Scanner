import type * as A from "../parser/ast.ts";
import { forEachChild, walk } from "../parser/walk.ts";
import type { FileContext, Rule } from "../engine/types.ts";
import { isDrawEvent, isPerFrameEvent, isStepEvent } from "../project/events.ts";
import { isBuiltinFunction } from "../semantic/builtins.ts";
import type { ProjectIndex } from "../semantic/project-index.ts";
import type { LocalDecl, Scope } from "../semantic/scope.ts";
import { code, describeEvent } from "./util.ts";

/** Constructor → matching destructor(s). */
export const RESOURCE_PAIRS: Record<string, string[]> = {
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
  network_create_server_raw: ["network_destroy"],
};

/** Functions that take ownership of a data structure passed as a later argument. */
const OWNERSHIP_TRANSFER = new Set(["ds_map_add_list", "ds_map_add_map", "ds_map_replace_list", "ds_map_replace_map", "ds_list_mark_as_list", "ds_list_mark_as_map"]);

const ALL_DESTROYERS = new Set(Object.values(RESOURCE_PAIRS).flat());

/** Last name in an lvalue chain: `hp`, `self.hp`, `other.inv` → `inv`. */
function tailName(e: A.Expression | undefined): string | undefined {
  if (!e) return undefined;
  if (e.type === "Identifier") return e.name;
  if (e.type === "MemberExpression") return e.property.name;
  return undefined;
}

interface ReleaseInfo {
  /** destroyer name → names it is called on anywhere in the project */
  released: Map<string, Set<string>>;
  /** Names handed to an owner (ds_map_add_list...) or wrapped in user functions. */
  transferred: Set<string>;
  /** Names checked with surface_exists(). */
  surfaceChecked: Set<string>;
}

const releaseCache = new WeakMap<ProjectIndex, ReleaseInfo>();

function projectReleases(index: ProjectIndex): ReleaseInfo {
  let info = releaseCache.get(index);
  if (info) return info;
  info = { released: new Map(), transferred: new Set(), surfaceChecked: new Set() };
  for (const file of index.project.files) {
    walk(file.ast, (n) => {
      if (n.type !== "CallExpression" || n.callee.type !== "Identifier") return;
      const name = n.callee.name;
      if (ALL_DESTROYERS.has(name)) {
        const t = tailName(n.arguments[0]);
        if (t) {
          const set = info!.released.get(name) ?? new Set();
          set.add(t);
          info!.released.set(name, set);
        }
      } else if (OWNERSHIP_TRANSFER.has(name)) {
        for (const a of n.arguments.slice(1)) {
          const t = tailName(a);
          if (t) info!.transferred.add(t);
        }
      } else if (!isBuiltinFunction(name)) {
        // Passing the handle to a project function may release it there.
        for (const a of n.arguments) {
          const t = tailName(a);
          if (t) info!.transferred.add(t);
        }
      }
    });
  }
  releaseCache.set(index, info);
  return info;
}

function creatorOf(e: A.Expression | null | undefined): string | undefined {
  if (e?.type === "CallExpression" && e.callee.type === "Identifier" && Object.hasOwn(RESOURCE_PAIRS, e.callee.name)) return e.callee.name;
  return undefined;
}

/** Map from node to parent for one file (built lazily). */
function parentMap(root: A.Node): Map<A.Node, A.Node> {
  const parents = new Map<A.Node, A.Node>();
  const visit = (n: A.Node) =>
    forEachChild(n, (c) => {
      parents.set(c, n);
      visit(c);
    });
  visit(root);
  return parents;
}

/** Built-ins that keep a reference to a handle passed as a value (not as the target). */
const STORING = new Set([
  "ds_list_add", "ds_list_insert", "ds_list_set", "ds_list_replace", "ds_map_add", "ds_map_set", "ds_map_replace",
  "ds_grid_set", "ds_grid_add", "ds_queue_enqueue", "ds_stack_push", "ds_priority_add", "array_push", "array_insert",
  "array_set", "struct_set", "variable_struct_set", "variable_instance_set", "variable_global_set", "method",
  ...OWNERSHIP_TRANSFER,
]);
/** Built-ins that keep using a resource passed in any position. */
const CONSUMING = new Set(["font_add_sprite", "font_add_sprite_ext", "part_type_sprite", "layer_sprite_create", "layer_background_sprite", "sprite_merge", "sprite_assign", "part_system_automatic_draw", "time_source_start"]);

/**
 * Whether a local handle escapes its function: returned, stored somewhere, or passed
 * to a project function (which may free it). Passing it to ordinary built-ins, such as
 * `instance_place_list(..., list)` or `ds_list_size(list)`, is just a use.
 */
function localEscapes(decl: LocalDecl, parents: Map<A.Node, A.Node>): boolean {
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

export const resourceLeak: Rule = {
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
\`\`\``,
  },
  file(ctx) {
    let parents: Map<A.Node, A.Node> | undefined;
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
          const p = parents!.get(r.id);
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
        let name: string | undefined;
        if (n.left.type === "Identifier") {
          const ref = ctx.scopes.refOf.get(n.left);
          if (!ref || ref.binding.kind !== "free" || ref.withDepth > 0) return;
          name = n.left.name;
        } else if (n.left.type === "MemberExpression" && n.left.object.type === "Identifier" && n.left.object.name === "self") {
          name = n.left.property.name;
        }
        if (!name) return;
        // Persistent controllers live for the whole game; their structures are freed at exit.
        if (ctx.index.project.objects.get(ctx.file.resource)?.persistent) return;
        const rel = projectReleases(ctx.index);
        const destroyers = RESOURCE_PAIRS[creator];
        if (destroyers.some((d) => rel.released.get(d)?.has(name)) || rel.transferred.has(name)) return;
        const where = perFrame && ctx.enclosingFunction() === null ? " This runs every frame, so it leaks continuously." : "";
        ctx.report(n, `${code(name)} holds a ${code(`${creator}()`)} result that is never freed with ${destroyers.map((d) => code(d + "()")).join(" / ")} anywhere in the project; free it in the Clean Up event.${where}`);
      },
    };
  },
};

function findLocal(ctx: FileContext, id: A.Identifier): LocalDecl | undefined {
  const scope = scopeContaining(ctx.scopes.root, id);
  const list = scope?.locals.get(id.name);
  return list?.find((d) => d.id === id);
}

function scopeContaining(scope: Scope, id: A.Identifier): Scope | undefined {
  for (const list of scope.locals.values()) if (list.some((d) => d.id === id)) return scope;
  for (const child of scope.children) {
    if (id.start >= child.node.start && id.end <= child.node.end) {
      const found = scopeContaining(child, id);
      if (found) return found;
    }
  }
  return undefined;
}

const SURFACE_USES: Record<string, number> = {
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
  draw_surface_general: 0,
};

export const surfaceExistsCheck: Rule = {
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
\`\`\``,
  },
  file(ctx) {
    const surfaceVars = projectSurfaceVars(ctx.index);
    if (surfaceVars.size === 0) return;
    const checked = new Set<string>();
    const createdHere = new Map<string, number>();
    const uses: { name: string; node: A.Node }[] = [];
    return {
      CallExpression(n) {
        if (n.callee.type !== "Identifier") return;
        const fn = n.callee.name;
        if (fn === "surface_exists") {
          const t = tailName(n.arguments[0]);
          if (t) checked.add(t);
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
        const reported = new Set<string>();
        for (const u of uses) {
          if (checked.has(u.name) || reported.has(u.name)) continue;
          const created = createdHere.get(u.name);
          if (created !== undefined && created < u.node.start) continue;
          reported.add(u.name);
          ctx.report(u.node, `Surface ${code(u.name)} is used without a ${code("surface_exists()")} check in ${describeEvent(ctx.file)}; surfaces can be lost at any time (resize, alt-tab), which crashes the game.`);
        }
      },
    };
  },
};

const surfaceVarCache = new WeakMap<ProjectIndex, Set<string>>();
function projectSurfaceVars(index: ProjectIndex): Set<string> {
  let set = surfaceVarCache.get(index);
  if (set) return set;
  set = new Set();
  for (const file of index.project.files) {
    walk(file.ast, (n) => {
      if (n.type === "AssignmentExpression" && n.operator === "=" && (creatorOf(n.right) === "surface_create" || creatorOf(n.right) === "surface_create_ext")) {
        const t = tailName(n.left);
        if (t) set!.add(t);
      }
    });
  }
  surfaceVarCache.set(index, set);
  return set;
}

interface Pair {
  open: string[];
  close: string;
  what: string;
}

const STATE_PAIRS: Pair[] = [
  { open: ["surface_set_target", "surface_set_target_ext"], close: "surface_reset_target", what: "surface target" },
  { open: ["shader_set"], close: "shader_reset", what: "shader" },
  { open: ["gpu_push_state"], close: "gpu_pop_state", what: "GPU state" },
  { open: ["matrix_stack_push"], close: "matrix_stack_pop", what: "matrix stack" },
  { open: ["draw_primitive_begin", "draw_primitive_begin_texture"], close: "draw_primitive_end", what: "primitive" },
  { open: ["vertex_begin"], close: "vertex_end", what: "vertex buffer" },
  { open: ["file_text_open_read", "file_text_open_write", "file_text_open_append", "file_text_open_from_string"], close: "file_text_close", what: "text file" },
  { open: ["file_bin_open"], close: "file_bin_close", what: "binary file" },
  { open: ["ini_open", "ini_open_from_string"], close: "ini_close", what: "INI file" },
];

export const unbalancedState: Rule = {
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
\`\`\``,
  },
  file(ctx) {
    const check = (body: A.Node, isEventRoot: boolean) => {
      const calls: A.CallExpression[] = [];
      let callsUserFunction = false;
      walk(body, (n, c) => {
        if (n !== body && (n.type === "FunctionDeclaration" || n.type === "FunctionExpression")) return c.skip();
        if (n.type === "CallExpression" && n.callee.type === "Identifier") {
          calls.push(n);
          if (!isBuiltinFunction(n.callee.name)) callsUserFunction = true;
        }
      });
      // Counting opens against closes breaks down with branches, so only the clear case
      // is reported: an event that opens something and never closes it, without calling
      // project functions that might (begin/end helper pairs).
      if (!isEventRoot || callsUserFunction) return;
      for (const pair of STATE_PAIRS) {
        const opens = calls.filter((c) => pair.open.includes((c.callee as A.Identifier).name));
        if (opens.length === 0 || calls.some((c) => (c.callee as A.Identifier).name === pair.close)) continue;
        const node = opens[0];
        ctx.report(node, `${code(`${(node.callee as A.Identifier).name}()`)} is never followed by ${code(`${pair.close}()`)} in ${describeEvent(ctx.file)}; the ${pair.what} stays open.`);
      }
    };
    return {
      Program(n) {
        check(n, ctx.file.kind === "object-event");
      },
    };
  },
};

const NON_RENDERING_DRAW = /^draw_(set_|get_|enable_|light|texture_flush|flush|clear)/;

export const drawOutsideDrawEvent: Rule = {
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
\`\`\``,
  },
  file(ctx) {
    const file = ctx.file;
    if (file.kind !== "object-event" || !file.event || file.event.kind === "Draw") return;
    let hasSurfaceTarget = false;
    let callsUserFunction = false;
    let first: A.CallExpression | undefined;
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
        const name = (first.callee as A.Identifier).name;
        ctx.report(first, `${code(`${name}()`)} is called in ${describeEvent(file)}; drawing only shows up in Draw events (or while a surface target is set).`);
      },
    };
  },
};

const surfaceSetterCache = new WeakMap<ProjectIndex, Set<string>>();
/** Script functions that (directly) call surface_set_target. */
function surfaceTargetFunctions(index: ProjectIndex): Set<string> {
  let set = surfaceSetterCache.get(index);
  if (set) return set;
  set = new Set();
  for (const [name, infos] of index.globalFunctions) {
    for (const info of infos) {
      walk(info.node.body, (n) => {
        if (n.type === "CallExpression" && n.callee.type === "Identifier" && n.callee.name.startsWith("surface_set_target")) set!.add(name);
      });
    }
  }
  surfaceSetterCache.set(index, set);
  return set;
}

const AUDIO_PLAY = new Set(["audio_play_sound", "audio_play_sound_at", "audio_play_sound_on", "audio_play_sound_ext"]);
const INSTANCE_CREATE = new Set(["instance_create_layer", "instance_create_depth"]);

function containsExit(node: A.Node): boolean {
  let found = false;
  walk(node, (n, c) => {
    if (found) return c.skip();
    if (n.type === "FunctionExpression" || n.type === "FunctionDeclaration") return c.skip();
    if (n.type === "ExitStatement" || n.type === "ReturnStatement") found = true;
  });
  return found;
}

export const perFrameAction: Rule = {
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
\`\`\``,
  },
  file(ctx) {
    const file = ctx.file;
    if (file.kind !== "object-event" || !(isStepEvent(file.event) || isDrawEvent(file.event))) return;
    return {
      Program(program) {
        // An unconditional instance_destroy() means the object only lives for one frame.
        const destroysSelf = program.body.some((s) => s.type === "ExpressionStatement" && s.expression.type === "CallExpression" && s.expression.callee.type === "Identifier" && s.expression.callee.name === "instance_destroy" && s.expression.arguments.length === 0);
        for (const stmt of program.body) {
          if (stmt.type === "IfStatement" || stmt.type === "SwitchStatement" || stmt.type === "WithStatement") {
            if (containsExit(stmt)) return; // everything after is conditional
            continue;
          }
          let expr: A.Expression | null = null;
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
      },
    };
  },
};

export const GAMEMAKER_RULES: Rule[] = [resourceLeak, surfaceExistsCheck, unbalancedState, drawOutsideDrawEvent, perFrameAction];

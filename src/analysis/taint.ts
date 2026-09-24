/**
 * Inter-procedural taint tracking for GML (in the spirit of CodeQL's data-flow library).
 *
 * Untrusted data (network/HTTP async events, files, user input) is followed through
 * local variables, instance variables, globals, struct fields, containers and calls to
 * project functions (via per-function summaries) until it reaches a dangerous
 * function argument (a "sink"). Each finding carries the full source → sink path.
 *
 * The analysis is flow-sensitive within a function body, flow-insensitive for instance
 * and global variables, and iterates to a fixpoint over the whole project.
 */
import type * as A from "../parser/ast.ts";
import { alwaysExits } from "../parser/walk.ts";
import type { ResolvedConfig, ThreatModel } from "../engine/config.ts";
import type { GmlFile } from "../project/loader.ts";
import type { FunctionInfo, ProjectIndex } from "../semantic/project-index.ts";
import type { FileScopes } from "../semantic/scope.ts";

export type SinkKind = "code-injection" | "path-injection" | "command-injection" | "variable-injection" | "url-redirect" | "unsafe-deserialization";

export const SINK_KINDS: SinkKind[] = ["code-injection", "path-injection", "command-injection", "variable-injection", "url-redirect", "unsafe-deserialization"];

export interface Step {
  file: GmlFile;
  start: number;
  end: number;
  message: string;
}

interface SourceOrigin {
  kind: "source";
  threat: ThreatModel;
  description: string;
  step: Step;
}

interface ParamOrigin {
  kind: "param";
  index: number;
}

interface Fact {
  origin: SourceOrigin | ParamOrigin;
  /** The value is a number derived from tainted data (still dangerous as a script/asset index). */
  numeric: boolean;
  /** Cannot traverse directories: built on a URL prefix, or passed through filename_name(). */
  pathSafe?: boolean;
  path: Step[];
}

interface ReturnFlow {
  path: Step[];
  numeric: boolean;
  pathSafe: boolean;
}

type State = Map<string, Fact[]>;

export interface SinkHit {
  kind: SinkKind;
  fn: string;
  file: GmlFile;
  call: A.CallExpression;
  arg: A.Expression;
}

export interface TaintFinding {
  kind: SinkKind;
  sink: SinkHit;
  source: SourceOrigin;
  /** Steps from the source to the sink argument (inclusive). */
  path: Step[];
}

interface Summary {
  paramToReturn: Map<number, ReturnFlow>;
  paramToSink: Map<number, { hit: SinkHit; path: Step[] }[]>;
  returnFacts: Fact[];
}

// ---------------------------------------------------------------------------
// Models

interface SourceModel {
  threat: ThreatModel;
  description: string;
}

const SOURCE_FUNCTIONS: Record<string, SourceModel> = {
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
  steam_lobby_get_owner_data: { threat: "remote", description: "Steam lobby data (set by other players)" },
};

/** Data carried by async_load in each async event (Other_N). Missing entries carry no untrusted data. */
const ASYNC_EVENT_SOURCES: Record<number, SourceModel> = {
  62: { threat: "remote", description: "an HTTP response" },
  63: { threat: "local", description: "text entered in a dialog" },
  67: { threat: "remote", description: "cloud save data" },
  68: { threat: "remote", description: "a network packet" },
  69: { threat: "remote", description: "Steam callback data" },
  70: { threat: "remote", description: "social/Discord callback data" },
  71: { threat: "remote", description: "a push notification" },
  72: { threat: "local", description: "loaded save data" },
  76: { threat: "remote", description: "broadcast message data" },
};

/** async_load keys that do not carry attacker-controlled content. */
const SAFE_ASYNC_KEYS = new Set(["id", "status", "http_status", "type", "socket", "port", "size", "event_type", "succeeded", "contentLength", "sizeDownloaded", "ip", "server", "result_code", "url"]);

interface SinkModel {
  args: number[];
  kind: SinkKind;
  /** Extra condition on the call (e.g. only when writing to self/global). */
  when?: (call: A.CallExpression) => boolean;
}

const isSelfOrGlobal = (call: A.CallExpression) => {
  const a = call.arguments[0];
  return a?.type === "Identifier" && (a.name === "self" || a.name === "global" || a.name === "id" || a.name === "other");
};

const SINKS: Record<string, SinkModel[]> = {};
const sink = (names: string[], args: number[], kind: SinkKind, when?: SinkModel["when"]) => {
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

/** Result carries taint from these argument indices (`"all"` = every argument). */
const PROPAGATORS: Record<string, { from: number[] | "all"; numeric?: boolean }> = {};
const prop = (names: string[], from: number[] | "all", numeric = false) => {
  for (const n of names) PROPAGATORS[n] = { from, numeric };
};
prop(["string", "string_concat", "string_concat_ext", "string_join", "string_join_ext", "string_ext", "array_concat"], "all");
prop(
  ["string_upper", "string_lower", "string_copy", "string_delete", "string_insert", "string_replace", "string_replace_all", "string_trim", "string_trim_start", "string_trim_end", "string_char_at", "string_letters", "string_lettersdigits", "string_repeat", "string_split", "string_split_ext", "string_hash_to_newline", "string_format", "string_ext"],
  [0],
);
prop(["string_insert"], [0, 1]);
prop(["filename_path", "filename_dir", "filename_drive", "filename_ext", "filename_change_ext"], [0]);
prop(["base64_decode", "base64_encode", "json_parse", "json_decode", "json_stringify", "json_encode", "buffer_base64_decode", "buffer_base64_encode"], [0]);
prop(["ds_map_find_value", "ds_map_find_first", "ds_map_find_last", "ds_map_find_next", "ds_map_find_previous", "ds_map_keys_to_array", "ds_map_values_to_array", "ds_list_find_value", "ds_grid_get", "ds_queue_dequeue", "ds_queue_head", "ds_queue_tail", "ds_stack_pop", "ds_stack_top", "ds_priority_find_max", "ds_priority_find_min", "ds_priority_delete_max", "ds_priority_delete_min"], [0]);
prop(["struct_get", "variable_struct_get", "variable_instance_get", "array_get", "array_pop", "array_shift", "array_first", "array_last", "array_filter", "array_map", "array_copy_while", "array_reverse", "struct_get_names", "variable_struct_get_names"], [0]);
prop(["buffer_read", "buffer_peek", "buffer_read_ext"], [0]);
prop(["asset_get_index", "real", "int64", "floor", "ceil", "round", "abs", "string_digits"], [0], true);

/** Container writes: taint flows from value args into the container (arg 0). */
const MUTATORS: Record<string, number[] | "rest"> = {
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
  buffer_copy: [0],
};

const PATH_SANITIZERS = new Set(["filename_name"]);

/** Functions whose results never carry attacker-controlled content. */
const CLEANSERS = new Set(["md5_string_utf8", "md5_string_unicode", "sha1_string_utf8", "sha1_string_unicode", "sha256_string_utf8", "crc32_string", "string_length", "string_byte_length", "string_pos", "string_pos_ext", "string_last_pos", "string_count", "array_length", "ds_list_size", "ds_map_size", "is_string", "is_real", "is_numeric", "is_undefined", "is_struct", "is_array", "file_exists", "ds_map_exists", "variable_struct_exists", "struct_exists", "array_contains", "ds_list_find_index", "array_get_index"]);

const ALLOW_LIST_CHECKS = new Set(["array_contains", "ds_map_exists", "variable_struct_exists", "struct_exists", "variable_instance_exists", "variable_global_exists", "asset_has_tags"]);
const INDEX_CHECKS = new Set(["ds_list_find_index", "array_get_index"]);

// ---------------------------------------------------------------------------

const MAX_FACTS = 4;
const MAX_PATH = 14;

interface Unit {
  file: GmlFile;
  body: A.Statement[];
  fn?: FunctionInfo;
  /** Object whose instance variables `self` refers to. */
  owner?: string;
}

export interface TaintAnalysis {
  findings: TaintFinding[];
}

export function analyzeTaint(index: ProjectIndex, config: ResolvedConfig): TaintAnalysis {
  return new TaintEngine(index, config).run();
}

class TaintEngine {
  private readonly index: ProjectIndex;
  private readonly threats: Set<ThreatModel>;
  private readonly sources: Record<string, SourceModel>;
  private readonly sinks: Record<string, SinkModel[]>;
  private readonly sanitizers: Set<string>;
  private readonly objectStore = new Map<string, State>();
  private readonly globalStore: State = new Map();
  private readonly summaries = new Map<A.FunctionNode, Summary>();
  private readonly findings = new Map<string, TaintFinding>();
  private version = 0;

  // Per-unit context
  private unit!: Unit;
  private scopes!: FileScopes;
  private state: State = new Map();
  private withOwner: (string | undefined)[] = [];

  constructor(index: ProjectIndex, config: ResolvedConfig) {
    this.index = index;
    this.threats = new Set(config.threatModels);
    this.sources = { ...SOURCE_FUNCTIONS };
    for (const s of config.taint.sources) this.sources[s.function] = { threat: s.kind ?? "remote", description: s.description ?? `data returned by ${s.function}()` };
    this.sinks = { ...SINKS };
    for (const s of config.taint.sinks) {
      const kind = (SINK_KINDS as string[]).includes(s.kind) ? (s.kind as SinkKind) : "code-injection";
      this.sinks[s.function] = [...(this.sinks[s.function] ?? []), { args: s.arguments, kind }];
    }
    this.sanitizers = new Set(config.taint.sanitizers);
  }

  run(): TaintAnalysis {
    const units: Unit[] = [];
    for (const file of this.index.project.files) {
      const owner = file.kind === "object-event" ? file.resource : undefined;
      units.push({ file, body: file.ast.body, owner });
    }
    for (const fn of this.index.functionsByNode.values()) {
      units.push({ file: fn.file, body: fn.node.body.body, fn, owner: fn.file.kind === "object-event" ? fn.file.resource : undefined });
      this.summaries.set(fn.node, { paramToReturn: new Map(), paramToSink: new Map(), returnFacts: [] });
    }
    for (let pass = 0; pass < 8; pass++) {
      const before = this.version;
      for (const u of units) this.analyzeUnit(u);
      if (this.version === before) break;
    }
    return { findings: [...this.findings.values()] };
  }

  // -------------------------------------------------------------------------

  private analyzeUnit(unit: Unit): void {
    this.unit = unit;
    this.scopes = this.index.scopes.get(unit.file)!;
    this.state = new Map();
    this.withOwner = [unit.owner];
    if (unit.fn) {
      unit.fn.node.params.forEach((p, i) => {
        this.state.set(p.id.name, [{ origin: { kind: "param", index: i }, numeric: false, path: [this.step(p.id, `parameter ${p.id.name}`)] }]);
      });
    }
    this.execList(unit.body);
  }

  private step(node: { start: number; end: number }, message: string): Step {
    return { file: this.unit.file, start: node.start, end: node.end, message };
  }

  private get owner(): string | undefined {
    return this.withOwner[this.withOwner.length - 1];
  }

  // --- statements ----------------------------------------------------------

  private execList(list: A.Statement[]): void {
    for (const s of list) this.exec(s);
  }

  private exec(s: A.Statement): void {
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
        const target = s.object.type === "Identifier" && this.index.assets.get(s.object.name) === "objects" ? s.object.name : undefined;
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

  private execExpressionStatement(e: A.Expression): void {
    if (e.type === "AssignmentExpression") {
      let facts = this.ev(e.right);
      if (e.operator !== "=") facts = union(facts, this.ev(e.left));
      this.assign(e.left, facts, e);
      return;
    }
    this.ev(e);
  }

  private loop(body: () => void): void {
    for (let i = 0; i < 2; i++) {
      const before = this.clone(this.state);
      body();
      this.state = this.join(before, this.state);
    }
  }

  private execIf(s: A.IfStatement): void {
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

  private execSwitch(s: A.SwitchStatement): void {
    this.ev(s.discriminant);
    const key = this.keyOf(s.discriminant);
    const base = this.state;
    let joined = this.clone(base);
    for (const c of s.cases) {
      if (c.test) this.ev(c.test);
      this.state = this.clone(base);
      // Inside `case "literal":` the discriminant equals a constant.
      if (key && c.test && isConstant(c.test)) this.state.set(key, []);
      this.execList(c.body);
      joined = this.join(joined, this.state);
    }
    this.state = joined;
  }

  // --- guards --------------------------------------------------------------

  private guards(test: A.Expression): { whenTrue: Set<string>; whenFalse: Set<string> } {
    const none = { whenTrue: new Set<string>(), whenFalse: new Set<string>() };
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
          return { whenTrue: new Set([...l.whenTrue, ...r.whenTrue]), whenFalse: intersect(l.whenFalse, r.whenFalse) };
        }
        if (test.operator === "||") {
          const l = this.guards(test.left);
          const r = this.guards(test.right);
          return { whenTrue: intersect(l.whenTrue, r.whenTrue), whenFalse: new Set([...l.whenFalse, ...r.whenFalse]) };
        }
        if (test.operator === "==" || test.operator === "!=") {
          const [v, c] = isConstant(test.right) ? [test.left, test.right] : isConstant(test.left) ? [test.right, test.left] : [undefined, undefined];
          if (v && c) {
            const key = this.keyOf(v);
            if (key) return test.operator === "==" ? { whenTrue: new Set([key]), whenFalse: new Set() } : { whenTrue: new Set(), whenFalse: new Set([key]) };
          }
          // ds_list_find_index(list, x) != -1
          const call = test.left.type === "CallExpression" ? test.left : test.right.type === "CallExpression" ? test.right : undefined;
          const other = call === test.left ? test.right : test.left;
          if (call && call.callee.type === "Identifier" && INDEX_CHECKS.has(call.callee.name) && other.type === "UnaryExpression" && other.operator === "-") {
            const key = this.keyOf(call.arguments[1]);
            if (key) return test.operator === "!=" ? { whenTrue: new Set([key]), whenFalse: new Set() } : { whenTrue: new Set(), whenFalse: new Set([key]) };
          }
        }
        if (test.operator === ">=" || test.operator === ">") {
          if (test.left.type === "CallExpression" && test.left.callee.type === "Identifier" && INDEX_CHECKS.has(test.left.callee.name)) {
            const key = this.keyOf(test.left.arguments[1]);
            if (key) return { whenTrue: new Set([key]), whenFalse: new Set() };
          }
        }
        return none;
      }
      case "CallExpression":
        if (test.callee.type === "Identifier" && ALLOW_LIST_CHECKS.has(test.callee.name)) {
          const key = this.keyOf(test.arguments[1]);
          if (key) return { whenTrue: new Set([key]), whenFalse: new Set() };
        }
        return none;
      default:
        return none;
    }
  }

  private sanitize(state: State, keys: Set<string>): void {
    for (const k of keys) state.set(k, []);
  }

  /** State key for a local variable or local field access, e.g. `cmd`, `data.cmd`. */
  private keyOf(e: A.Expression | undefined): string | undefined {
    if (!e) return undefined;
    if (e.type === "Identifier") {
      const ref = this.scopes.refOf.get(e);
      return ref?.binding.kind === "local" ? e.name : undefined;
    }
    if (e.type === "MemberExpression") {
      const base = this.keyOf(e.object);
      return base ? `${base}.${e.property.name}` : undefined;
    }
    return undefined;
  }

  // --- assignment ----------------------------------------------------------

  private assign(target: A.Expression, facts: Fact[], node: A.Node): void {
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
        const prop = target.property.name;
        if (base.type === "Identifier") {
          if (base.name === "global") return this.addTo(this.globalStore, prop, stepped);
          if (base.name === "self" && this.owner) return this.addTo(this.objectState(this.owner), prop, stepped);
          if (this.index.assets.get(base.name) === "objects") return this.addTo(this.objectState(base.name), prop, stepped);
        }
        const key = this.keyOf(target);
        if (key) this.state.set(key, stepped);
        return;
      }
      case "IndexExpression": {
        // Writing into an array/map/struct taints the container.
        if (facts.length === 0) return;
        const root = target.object;
        if (root.type === "IndexExpression" || root.type === "MemberExpression" || root.type === "Identifier") this.assign(root, union(facts, this.ev(root)), node);
        return;
      }
    }
  }

  private clearFields(name: string): void {
    const prefix = name + ".";
    for (const k of [...this.state.keys()]) if (k.startsWith(prefix)) this.state.delete(k);
  }

  private objectState(obj: string): State {
    let s = this.objectStore.get(obj);
    if (!s) {
      s = new Map();
      this.objectStore.set(obj, s);
    }
    return s;
  }

  /** Weak update of a shared (instance/global) store; bumps the version when it grows. */
  private addTo(store: State, key: string, facts: Fact[]): void {
    if (facts.length === 0) return;
    const existing = store.get(key) ?? [];
    const merged = union(existing, facts.filter((f) => f.origin.kind === "source"));
    if (merged.length !== existing.length) {
      store.set(key, merged);
      this.version++;
    }
  }

  private recordReturn(facts: Fact[], node: A.Node): void {
    const fn = this.unit.fn;
    if (!fn) return;
    const summary = this.summaries.get(fn.node)!;
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

  private ev(e: A.Expression): Fact[] {
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
            // "https://host/" + tainted is a URL, not a file path.
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
        return e.expressions.reduce<Fact[]>((acc, x) => union(acc, this.ev(x)), []);
      case "ArrayExpression":
        return e.elements.reduce<Fact[]>((acc, x) => union(acc, this.ev(x)), []);
      case "StructExpression":
        return e.properties.reduce<Fact[]>((acc, p) => (p.type === "StructProperty" && p.value ? union(acc, this.ev(p.value)) : acc), []);
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

  private evIdentifier(e: A.Identifier): Fact[] {
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
    return this.globalStore.get(name) ?? (this.owner ? (this.objectStore.get(this.owner)?.get(name) ?? []) : []);
  }

  private evMember(e: A.MemberExpression): Fact[] {
    const key = this.keyOf(e);
    if (key && this.state.has(key)) return this.state.get(key)!;
    const base = e.object;
    const prop = e.property.name;
    if (base.type === "Identifier") {
      if (base.name === "global") return this.globalStore.get(prop) ?? [];
      if (base.name === "self") return this.owner ? (this.objectStore.get(this.owner)?.get(prop) ?? []) : [];
      if (this.index.assets.get(base.name) === "objects") return this.objectStore.get(base.name)?.get(prop) ?? [];
    }
    // A field of a tainted struct is tainted.
    return this.ev(base);
  }

  private evIndex(e: A.IndexExpression): Fact[] {
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
  private asyncSource(): SourceModel | undefined {
    const ev = this.unit.file.event;
    if (this.unit.file.kind !== "object-event" || ev?.kind !== "Other") return { threat: "remote", description: "async event data" };
    return ASYNC_EVENT_SOURCES[ev.num] ?? (ev.num >= 60 && ev.num <= 76 ? undefined : { threat: "remote", description: "async event data" });
  }

  private sourceFact(threat: ThreatModel, description: string, node: A.Node): Fact[] {
    if (!this.threats.has(threat)) return [];
    const step = this.step(node, description);
    return [{ origin: { kind: "source", threat, description, step }, numeric: false, path: [step] }];
  }

  private evCall(call: A.CallExpression): Fact[] {
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

    // Project functions: apply summaries.
    const userFns = this.index.resolveFunction(name, this.unit.file);
    if (userFns.length > 0) return this.applySummaries(userFns, call, args, name);

    // script_execute(fn, args...) with a known function behaves like fn(args...).
    if (name === "script_execute" && call.arguments[0]?.type === "Identifier") {
      const target = this.index.resolveFunction(call.arguments[0].name, this.unit.file);
      if (target.length > 0) {
        this.checkSinks(name, call, args);
        return this.applySummaries(target, call, args.slice(1), call.arguments[0].name, 1);
      }
    }

    this.checkSinks(name, call, args);

    const mut = MUTATORS[name];
    if (mut && call.arguments[0]) {
      const idx = mut === "rest" ? call.arguments.map((_, i) => i).slice(1) : mut;
      const facts = idx.reduce<Fact[]>((acc, i) => union(acc, args[i] ?? []), []);
      if (facts.length) this.assign(call.arguments[0], union(facts, args[0] ?? []), call);
    }

    const source = this.sources[name];
    if (source) return this.sourceFact(source.threat, source.description, call);

    const p = PROPAGATORS[name];
    if (p) {
      const from = p.from === "all" ? args.map((_, i) => i) : p.from;
      let facts = from.reduce<Fact[]>((acc, i) => union(acc, args[i] ?? []), []);
      if (p.numeric) facts = facts.map(asNumeric);
      return this.extend(facts, call, `${name}(...)`);
    }
    if (PATH_SANITIZERS.has(name)) return (args[0] ?? []).map((f) => ({ ...f, pathSafe: true }));
    return [];
  }

  private applySummaries(fns: FunctionInfo[], call: A.CallExpression, args: Fact[][], name: string, argOffset = 0): Fact[] {
    let result: Fact[] = [];
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
              path: trimPath([...fact.path, ...inner.path.slice(1), callStep]),
            },
          ]);
        }
      }
      result = union(result, summary.returnFacts.map((f) => ({ ...f, path: trimPath([...f.path, this.step(call, `returned from ${name}()`)]) })));
    }
    return result;
  }

  private checkSinks(name: string, call: A.CallExpression, args: Fact[][]): void {
    const models = this.sinks[name];
    if (!models) return;
    // Only built-ins or functions not defined by the project (extensions) are sinks.
    for (const m of models) {
      if (m.when && !m.when(call)) continue;
      for (const i of m.args) {
        const arg = call.arguments[i];
        if (!arg) continue;
        for (const fact of args[i] ?? []) {
          if (fact.numeric && m.kind !== "code-injection" && m.kind !== "variable-injection") continue;
          if (fact.pathSafe && m.kind === "path-injection") continue;
          const hit: SinkHit = { kind: m.kind, fn: name, file: this.unit.file, call, arg };
          this.flowToSink(fact, hit, [...fact.path, this.step(arg, `${name}() argument`)]);
        }
      }
    }
  }

  private flowToSink(fact: Fact, hit: SinkHit, path: Step[]): void {
    if (fact.origin.kind === "source") {
      if (!this.threats.has(fact.origin.threat)) return;
      const src = fact.origin.step;
      const key = `${hit.kind}|${hit.file.relPath}|${hit.arg.start}|${src.file.relPath}|${src.start}`;
      if (!this.findings.has(key)) this.findings.set(key, { kind: hit.kind, sink: hit, source: fact.origin, path: trimPath(path) });
      return;
    }
    const fn = this.unit.fn;
    if (!fn) return;
    const summary = this.summaries.get(fn.node)!;
    const list = summary.paramToSink.get(fact.origin.index) ?? [];
    if (!list.some((x) => x.hit.call === hit.call && x.hit.arg === hit.arg)) {
      list.push({ hit, path: trimPath(path) });
      summary.paramToSink.set(fact.origin.index, list);
      this.version++;
    }
  }

  // --- utilities -----------------------------------------------------------

  private extend(facts: Fact[], node: A.Node, label: string): Fact[] {
    if (facts.length === 0) return facts;
    const step = this.step(node, label);
    return facts.map((f) => ({ ...f, path: trimPath([...f.path, step]) }));
  }

  private clone(s: State): State {
    return new Map(s);
  }

  private join(a: State, b: State): State {
    const out = new Map(a);
    for (const [k, v] of b) out.set(k, union(out.get(k) ?? [], v));
    return out;
  }
}

/** Leading string literal of a concatenation chain. */
function staticLeftmost(e: A.Expression): string | undefined {
  if (e.type === "StringLiteral") return e.value;
  if (e.type === "TemplateString") return e.quasis[0];
  if (e.type === "BinaryExpression" && e.operator === "+") return staticLeftmost(e.left);
  return undefined;
}

function isConstant(e: A.Expression): boolean {
  return e.type === "StringLiteral" || e.type === "NumberLiteral" || e.type === "BooleanLiteral" || (e.type === "MemberExpression" && e.object.type === "Identifier") || (e.type === "UnaryExpression" && e.argument.type === "NumberLiteral");
}

function sameOrigin(a: Fact, b: Fact): boolean {
  if (a.origin.kind !== b.origin.kind || a.numeric !== b.numeric) return false;
  if (a.origin.kind === "param") return a.origin.index === (b.origin as ParamOrigin).index;
  const sa = a.origin.step;
  const sb = (b.origin as SourceOrigin).step;
  return sa.file === sb.file && sa.start === sb.start;
}

function union(a: Fact[], b: Fact[]): Fact[] {
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

function intersect(a: Set<string>, b: Set<string>): Set<string> {
  return new Set([...a].filter((x) => b.has(x)));
}

function asNumeric(f: Fact): Fact {
  return f.numeric ? f : { ...f, numeric: true };
}

function trimPath(path: Step[]): Step[] {
  // Merge consecutive steps at the same span, then keep the first and last steps when too long.
  const out: Step[] = [];
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

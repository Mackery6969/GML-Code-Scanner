import { existsSync, lstatSync, readdirSync, readFileSync, statSync } from "node:fs";
import { basename, dirname, isAbsolute, join, normalize, relative, sep } from "node:path";
import type { Program } from "../parser/ast.ts";
import { parse } from "../parser/parser.ts";
import { parseEventFileName, type EventInfo } from "./events.ts";
import { SourceText } from "./source.ts";
import { scanYypResources, tryParseYy, yyArray, yyName, yyRef, type YypResourceEntry } from "./yy.ts";

export type CodeUnitKind = "script" | "object-event" | "room-creation" | "instance-creation" | "timeline-moment" | "extension";

export interface GmlFile {
  /** Path relative to the workspace root, with forward slashes. */
  relPath: string;
  absPath: string;
  source: SourceText;
  ast: Program;
  kind: CodeUnitKind;
  /** Owning resource: script, object, room or timeline name. */
  resource: string;
  event?: EventInfo;
  project: Project;
}

export interface ResourceInfo {
  name: string;
  /** Resource folder, e.g. `objects`, `sprites`. */
  type: string;
  /** Workspace-relative path of the resource's .yy file. */
  yyRelPath: string;
  /** Listed in the .yyp `resources` array. */
  inYyp: boolean;
  /** The .yy file exists on disk. */
  onDisk: boolean;
  yypEntries: YypResourceEntry[];
}

export interface ObjectEventRef {
  eventType: number;
  eventNum: number;
  collisionObject?: string;
}

export interface ObjectInfo {
  name: string;
  yyRelPath: string;
  parent?: string;
  /** Variable Definitions set in the IDE. */
  properties: string[];
  events: GmlFile[];
  /** Event list declared in the object's .yy (undefined when the .yy is missing). */
  eventList?: ObjectEventRef[];
  persistent: boolean;
}

export interface YypInfo {
  relPath: string;
  absPath: string;
  source: SourceText;
  /** Parsed JSON; undefined when the file is malformed. */
  data?: Record<string, unknown>;
  entries: YypResourceEntry[];
  ideVersion?: string;
}

export interface Project {
  name: string;
  /** Workspace-relative project directory ("" for the workspace root). */
  rootRel: string;
  rootAbs: string;
  yyp?: YypInfo;
  resources: Map<string, ResourceInfo[]>;
  objects: Map<string, ObjectInfo>;
  files: GmlFile[];
  /** Names of instances placed in rooms (`inst_1A2B3C4D`), usable as global identifiers. */
  roomInstances: Set<string>;
  extensionFunctions: Map<string, { extension: string; argCount: number }>;
  extensionConstants: Set<string>;
  /** Asset name → names of .yy resources that reference it (rooms, sequences, child objects). */
  yyReferences: Map<string, Set<string>>;
  /** Non-GML files worth scanning for secrets (options, extensions, datafiles). */
  auxiliaryFiles: string[];
}

export interface Workspace {
  rootAbs: string;
  projects: Project[];
  /** Workspace-level files (CI workflows, .env) worth scanning for secrets. */
  auxiliaryFiles: string[];
}

export interface LoadOptions {
  /** Returns true for workspace-relative paths (files or directories) to skip. */
  isIgnored?: (relPath: string) => boolean;
}

const SKIP_DIRS = new Set([".git", "node_modules", ".svn", ".hg", ".vs", ".vscode", ".idea", "dist", "build", "Build", "tmp", "temp"]);
const CODE_DIRS = ["objects", "scripts", "rooms", "timelines", "extensions"];
const RESOURCE_DIRS = ["objects", "scripts", "rooms", "sprites", "sounds", "fonts", "paths", "timelines", "tilesets", "shaders", "sequences", "animcurves", "extensions", "notes", "particles"];
const REFERENCE_DIRS = ["rooms", "sequences", "objects", "timelines"];
const TEXT_EXTENSIONS = new Set([".ini", ".json", ".txt", ".cfg", ".conf", ".xml", ".yml", ".yaml", ".env", ".properties", ".plist", ".csv", ".toml"]);
const MAX_AUX_FILE_SIZE = 512 * 1024;

const toPosix = (p: string) => p.split(sep).join("/");

export function loadWorkspace(rootAbs: string, options: LoadOptions = {}): Workspace {
  const isIgnored = options.isIgnored ?? (() => false);
  const ws: Workspace = { rootAbs, projects: [], auxiliaryFiles: [] };
  const rel = (abs: string) => toPosix(relative(rootAbs, abs));

  const projectDirs: string[] = [];
  const looseGml: string[] = [];

  // Discover .yyp projects and loose .gml files outside them.
  const visit = (dir: string) => {
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    const yyp = entries.find((e) => e.isFile() && e.name.endsWith(".yyp"));
    if (yyp && !isIgnored(rel(join(dir, yyp.name)))) {
      projectDirs.push(join(dir, yyp.name));
      return; // everything below belongs to this project
    }
    for (const e of entries) {
      const abs = join(dir, e.name);
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
  const workflows = join(rootAbs, ".github", "workflows");
  if (existsSync(workflows)) {
    for (const f of readdirSync(workflows)) if (/\.ya?ml$/.test(f)) ws.auxiliaryFiles.push(rel(join(workflows, f)));
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

function isWorkspaceAuxFile(relPath: string): boolean {
  const name = relPath.split("/").pop() ?? "";
  return name === ".env" || name.startsWith(".env.") || name === "um.json" || name === "licence.plist";
}

function emptyProject(name: string, rootRel: string, rootAbs: string): Project {
  return {
    name,
    rootRel,
    rootAbs,
    resources: new Map(),
    objects: new Map(),
    files: [],
    roomInstances: new Set(),
    extensionFunctions: new Map(),
    extensionConstants: new Set(),
    yyReferences: new Map(),
    auxiliaryFiles: [],
  };
}

/** Reads a regular file; symlinks are refused so a scanned repo can't point the scanner elsewhere. */
export function readText(abs: string): string | undefined {
  try {
    if (lstatSync(abs).isSymbolicLink()) return undefined;
    return readFileSync(abs, "utf8");
  } catch {
    return undefined;
  }
}

/** A .yyp resource path that stays inside the project (no absolute paths, no `..`). */
function isContainedPath(p: string): boolean {
  if (isAbsolute(p) || /^[a-zA-Z]:/.test(p) || p.startsWith("\\")) return false;
  return !normalize(p).split(/[\\/]/).includes("..");
}

function listDirs(abs: string): string[] {
  try {
    return readdirSync(abs, { withFileTypes: true })
      .filter((e) => e.isDirectory())
      .map((e) => e.name);
  } catch {
    return [];
  }
}

function listFiles(abs: string): string[] {
  try {
    return readdirSync(abs, { withFileTypes: true })
      .filter((e) => e.isFile())
      .map((e) => e.name);
  } catch {
    return [];
  }
}

function loadProject(wsRoot: string, yypAbs: string, isIgnored: (rel: string) => boolean): Project {
  const rootAbs = dirname(yypAbs);
  const rel = (abs: string) => toPosix(relative(wsRoot, abs));
  const project = emptyProject(basename(yypAbs, ".yyp"), rel(rootAbs), rootAbs);
  const prefix = project.rootRel ? project.rootRel + "/" : "";

  const yypText = readText(yypAbs) ?? "";
  const data = tryParseYy(yypText);
  const metaData = data?.MetaData as Record<string, unknown> | undefined;
  project.yyp = {
    relPath: rel(yypAbs),
    absPath: yypAbs,
    source: new SourceText(yypText),
    data,
    entries: scanYypResources(yypText),
    ideVersion: typeof metaData?.IDEVersion === "string" ? metaData.IDEVersion : undefined,
  };

  const addResource = (name: string, type: string, yyPath: string): ResourceInfo => {
    const list = project.resources.get(name) ?? [];
    let info = list.find((r) => r.yyRelPath === prefix + yyPath);
    if (!info) {
      info = { name, type, yyRelPath: prefix + yyPath, inYyp: false, onDisk: false, yypEntries: [] };
      list.push(info);
      project.resources.set(name, list);
    }
    return info;
  };

  const uncontained = new Set<ResourceInfo>();
  for (const entry of project.yyp.entries) {
    const info = addResource(entry.name, entry.path.split("/")[0], entry.path);
    info.inYyp = true;
    info.yypEntries.push(entry);
    if (!isContainedPath(entry.path)) uncontained.add(info);
  }

  for (const type of RESOURCE_DIRS) {
    const typeDir = join(rootAbs, type);
    for (const name of listDirs(typeDir)) {
      if (existsSync(join(typeDir, name, `${name}.yy`))) addResource(name, type, `${type}/${name}/${name}.yy`).onDisk = true;
    }
  }
  // Entries whose .yy lives somewhere unexpected (renamed folders) still count if the file exists.
  for (const list of project.resources.values()) {
    for (const r of list) if (!r.onDisk && r.inYyp && !uncontained.has(r)) r.onDisk = existsSync(join(wsRoot, r.yyRelPath));
  }

  // Ignored paths are still loaded: their functions, macros and assets are part of the
  // project. The scanner only drops findings reported inside them.
  for (const dir of CODE_DIRS) {
    const typeDir = join(rootAbs, dir);
    for (const name of listDirs(typeDir)) {
      const resDir = join(typeDir, name);
      for (const f of listFiles(resDir)) {
        if (f.endsWith(".gml")) addGmlFile(project, wsRoot, join(resDir, f));
      }
    }
  }

  buildObjectsFromFiles(project, wsRoot);
  loadRooms(project, wsRoot);
  loadExtensions(project, wsRoot);
  collectYyReferences(project);

  for (const sub of ["options", "extensions"]) collectAux(project, wsRoot, join(rootAbs, sub), (n) => n.endsWith(".yy") || n.endsWith(".json"), isIgnored);
  collectAux(project, wsRoot, join(rootAbs, "datafiles"), (n) => TEXT_EXTENSIONS.has(extOf(n)), isIgnored);
  return project;
}

function extOf(name: string): string {
  const i = name.lastIndexOf(".");
  return i < 0 ? "" : name.slice(i).toLowerCase();
}

function collectAux(project: Project, wsRoot: string, dirAbs: string, accept: (name: string) => boolean, isIgnored: (rel: string) => boolean): void {
  const walkDir = (d: string, depth: number) => {
    if (depth > 6) return;
    let entries;
    try {
      entries = readdirSync(d, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const abs = join(d, e.name);
      const r = toPosix(relative(wsRoot, abs));
      if (isIgnored(r)) continue;
      if (e.isDirectory()) walkDir(abs, depth + 1);
      else if (accept(e.name)) {
        try {
          if (statSync(abs).size <= MAX_AUX_FILE_SIZE) project.auxiliaryFiles.push(r);
        } catch {
          // unreadable: skip
        }
      }
    }
  };
  walkDir(dirAbs, 0);
}

/** Classifies a .gml file by its location: objects/<obj>/<Event>.gml, scripts/<name>/..., rooms/... */
function addGmlFile(project: Project, wsRoot: string, abs: string): GmlFile {
  const text = readText(abs) ?? "";
  const relPath = toPosix(relative(wsRoot, abs));
  const parts = relPath.split("/");
  const file = parts[parts.length - 1];
  const base = file.slice(0, -4);
  const owner = parts[parts.length - 2] ?? base;
  const typeDir = parts[parts.length - 3];
  let kind: CodeUnitKind = "script";
  let resource = base;
  let event: EventInfo | undefined;
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
  const gml: GmlFile = { relPath, absPath: abs, source: new SourceText(text), ast: parse(text), kind, resource, event, project };
  project.files.push(gml);
  return gml;
}

function buildObjectsFromFiles(project: Project, wsRoot: string): void {
  const objectDirs = new Map<string, string>();
  for (const f of project.files) {
    if (f.kind === "object-event") objectDirs.set(f.resource, dirname(f.absPath));
  }
  // Objects registered in the project may have no code at all.
  for (const [name, list] of project.resources) {
    for (const r of list) if (r.type === "objects" && r.onDisk) objectDirs.set(name, dirname(join(wsRoot, r.yyRelPath)));
  }
  for (const [name, dirAbs] of objectDirs) {
    const yyAbs = join(dirAbs, `${name}.yy`);
    const yy = existsSync(yyAbs) ? tryParseYy(readText(yyAbs) ?? "") : undefined;
    const info: ObjectInfo = {
      name,
      yyRelPath: toPosix(relative(wsRoot, yyAbs)),
      parent: yyRef(yy?.parentObjectId)?.name,
      properties: yyArray(yy?.properties).map(yyName).filter((n): n is string => !!n),
      events: project.files.filter((f) => f.kind === "object-event" && f.resource === name),
      eventList: yy
        ? yyArray(yy.eventList).map((e) => {
            const ev = e as Record<string, unknown>;
            return { eventType: Number(ev.eventType), eventNum: Number(ev.eventNum), collisionObject: yyRef(ev.collisionObjectId)?.name };
          })
        : undefined,
      persistent: yy?.persistent === true,
    };
    project.objects.set(name, info);
  }
}

function loadRooms(project: Project, wsRoot: string): void {
  for (const [, list] of project.resources) {
    for (const r of list) {
      if (r.type !== "rooms" || !r.onDisk) continue;
      const yy = tryParseYy(readText(join(wsRoot, r.yyRelPath)) ?? "");
      if (!yy) continue;
      const visitLayers = (layers: unknown[]) => {
        for (const layer of layers) {
          const l = layer as Record<string, unknown>;
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

function loadExtensions(project: Project, wsRoot: string): void {
  for (const [, list] of project.resources) {
    for (const r of list) {
      if (r.type !== "extensions" || !r.onDisk) continue;
      const yy = tryParseYy(readText(join(wsRoot, r.yyRelPath)) ?? "");
      if (!yy) continue;
      for (const file of yyArray(yy.files)) {
        const f = file as Record<string, unknown>;
        for (const fn of yyArray(f.functions)) {
          const def = fn as Record<string, unknown>;
          const n = yyName(def);
          // `args` lists the real parameters; `argCount` is often 0 and only meaningful as -1 (variadic).
          const argCount = def.argCount === -1 ? -1 : Array.isArray(def.args) ? def.args.length : typeof def.argCount === "number" ? def.argCount : -1;
          if (n) project.extensionFunctions.set(n, { extension: r.name, argCount });
        }
        for (const c of yyArray(f.constants)) {
          const n = yyName(c) ?? (c as Record<string, unknown>).constantName;
          if (typeof n === "string") project.extensionConstants.add(n);
        }
      }
    }
  }
}

/** Records which resources reference which assets via `{"name":..,"path":..}` refs in .yy files. */
function collectYyReferences(project: Project): void {
  const refRe = /\{\s*"name"\s*:\s*"([^"]+)"\s*,\s*"path"\s*:\s*"([a-z]+)\//g;
  for (const [, list] of project.resources) {
    for (const r of list) {
      if (!r.onDisk || !REFERENCE_DIRS.includes(r.type)) continue;
      const text = readText(join(project.rootAbs, r.yyRelPath.slice(project.rootRel ? project.rootRel.length + 1 : 0)));
      if (!text) continue;
      for (const m of text.matchAll(refRe)) {
        if (m[1] === r.name) continue;
        const set = project.yyReferences.get(m[1]) ?? new Set();
        set.add(r.name);
        project.yyReferences.set(m[1], set);
      }
    }
  }
}

import { mkdirSync, mkdtempSync, rmSync, writeFileSync, existsSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after } from "node:test";
import { defaultConfig, type Config, resolveConfig } from "../src/engine/config.ts";
import { scan, type ScanResult } from "../src/engine/scanner.ts";
import type { Finding, Suite } from "../src/engine/types.ts";
import { parseEventFileName } from "../src/project/events.ts";

const created: string[] = [];
after(() => {
  for (const d of created) rmSync(d, { recursive: true, force: true });
});

export interface ProjectOptions {
  /** Generate a .yyp (and missing .yy files). Default true. */
  yyp?: boolean;
  /** Resource folders to leave out of the .yyp (to simulate unregistered resources). */
  unregistered?: string[];
  /** Extra raw entries for the .yyp resources array. */
  extraEntries?: string[];
  ideVersion?: string;
}

/** Writes a throwaway GameMaker project to a temp directory and returns its path. */
export function writeProject(files: Record<string, string>, options: ProjectOptions = {}): string {
  const dir = mkdtempSync(join(tmpdir(), "gmlscan-test-"));
  created.push(dir);
  for (const [rel, content] of Object.entries(files)) {
    const abs = join(dir, rel);
    mkdirSync(dirname(abs), { recursive: true });
    writeFileSync(abs, content);
  }
  if (options.yyp === false) return dir;

  const entries: string[] = [];
  for (const type of ["objects", "scripts", "rooms", "sprites"]) {
    const typeDir = join(dir, type);
    if (!existsSync(typeDir)) continue;
    for (const name of readdirSync(typeDir)) {
      const yy = join(typeDir, name, `${name}.yy`);
      if (!existsSync(yy)) {
        if (type === "objects") {
          const events = readdirSync(join(typeDir, name))
            .filter((f) => f.endsWith(".gml"))
            .map((f) => parseEventFileName(f.slice(0, -4)))
            .filter((e) => e !== undefined)
            .map((e) => `{"resourceType":"GMEvent","resourceVersion":"1.0","name":"","collisionObjectId":${e.collisionObject ? `{"name":"${e.collisionObject}","path":"objects/${e.collisionObject}/${e.collisionObject}.yy",}` : "null"},"eventNum":${e.num},"eventType":${e.eventType},"isDnD":false,},`);
          writeFileSync(yy, `{\n  "resourceType": "GMObject",\n  "name": "${name}",\n  "eventList": [\n    ${events.join("\n    ")}\n  ],\n  "parentObjectId": null,\n  "persistent": false,\n  "properties": [],\n}\n`);
        } else {
          writeFileSync(yy, `{\n  "resourceType": "GM${type[0].toUpperCase()}${type.slice(1, -1)}",\n  "name": "${name}",\n  "layers": [],\n}\n`);
        }
      }
      if (!options.unregistered?.includes(name)) entries.push(`    {"id":{"name":"${name}","path":"${type}/${name}/${name}.yy",},"order":0,},`);
    }
  }
  entries.push(...(options.extraEntries ?? []));
  const yyp = `{\n  "resourceType": "GMProject",\n  "resourceVersion": "1.6",\n  "name": "TestGame",\n  "resources": [\n${entries.join("\n")}\n  ],\n  "MetaData": {\n    "IDEVersion": "${options.ideVersion ?? "2023.1.1.62"}",\n  },\n}\n`;
  writeFileSync(join(dir, "TestGame.yyp"), yyp);
  return dir;
}

export interface ScanFilesOptions extends ProjectOptions {
  suite?: Suite;
  rules?: string[];
  config?: Config;
}

export function scanProject(dir: string, options: ScanFilesOptions = {}): ScanResult {
  return scan({ root: dir, config: options.config ? resolveConfig(options.config) : defaultConfig(), suite: options.suite ?? "all", onlyRules: options.rules });
}

export function scanFiles(files: Record<string, string>, options: ScanFilesOptions = {}): Finding[] {
  const result = scanProject(writeProject(files, options), options);
  if (result.internalErrors.length) throw new Error(`Internal errors: ${JSON.stringify(result.internalErrors, null, 2)}`);
  return result.findings;
}

/** Findings for one rule. */
export function findingsFor(files: Record<string, string>, ruleId: string, options: ScanFilesOptions = {}): Finding[] {
  return scanFiles(files, { ...options, rules: [ruleId] });
}

/** A one-event object project: `objects/obj_test/<event>.gml`. */
export function eventCode(code: string, event = "Step_0", extra: Record<string, string> = {}): Record<string, string> {
  return { [`objects/obj_test/${event}.gml`]: code, ...extra };
}

export function scriptCode(code: string, name = "scr_test", extra: Record<string, string> = {}): Record<string, string> {
  return { [`scripts/${name}/${name}.gml`]: code, ...extra };
}

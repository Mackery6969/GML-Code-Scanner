/**
 * GameMaker .yy/.yyp files are JSON with trailing commas. From 2024.x the format
 * also prefixes some keys (`%Name`, `$GMObject`); `yyName` reads either spelling.
 */
export function parseYy(text: string): unknown {
  return JSON.parse(stripTrailingCommas(text.replace(/^﻿/, "")));
}

export function tryParseYy(text: string): Record<string, unknown> | undefined {
  try {
    const v = parseYy(text);
    return v && typeof v === "object" ? (v as Record<string, unknown>) : undefined;
  } catch {
    return undefined;
  }
}

export function stripTrailingCommas(text: string): string {
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
    } else if (c === 44 /* , */) {
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

export function yyName(obj: unknown): string | undefined {
  if (!obj || typeof obj !== "object") return undefined;
  const o = obj as Record<string, unknown>;
  const n = o.name ?? o["%Name"];
  return typeof n === "string" ? n : undefined;
}

export interface YyRef {
  name: string;
  path: string;
}

export function yyRef(value: unknown): YyRef | undefined {
  if (!value || typeof value !== "object") return undefined;
  const o = value as Record<string, unknown>;
  if (typeof o.name === "string" && typeof o.path === "string") return { name: o.name, path: o.path };
  return undefined;
}

export function yyArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

/** A resource entry in the .yyp with its location in the raw text. */
export interface YypResourceEntry {
  name: string;
  path: string;
  start: number;
  end: number;
}

/** Finds `"id":{"name":..., "path":...}` entries inside the `resources` array. */
export function scanYypResources(text: string): YypResourceEntry[] {
  const out: YypResourceEntry[] = [];
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

function findArrayEnd(text: string, from: number): number {
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

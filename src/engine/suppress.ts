import type { Comment } from "../parser/ast.ts";
import type { SourceText } from "../project/source.ts";

/**
 * Inline suppressions:
 *   // gmlscan-ignore-next-line gml/rule-a, gml/rule-b -- reason
 *   foo(); // gmlscan-ignore-line
 *   // gmlscan-ignore-file gml/unused-local
 * Omitting rule ids suppresses every rule.
 */
export class Suppressions {
  private readonly lines = new Map<number, Set<string> | "all">();
  private file: Set<string> | "all" | undefined;

  static fromComments(comments: Comment[], source: SourceText): Suppressions {
    const s = new Suppressions();
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

  private add(line: number, ids: Set<string> | "all"): void {
    this.lines.set(line, merge(this.lines.get(line), ids));
  }

  isSuppressed(ruleId: string, line: number): boolean {
    return matches(this.file, ruleId) || matches(this.lines.get(line), ruleId);
  }
}

function parseIds(text: string): Set<string> | "all" {
  const list = text
    .split("--")[0]
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
  return list.length ? new Set(list.map((id) => (id.includes("/") ? id : `gml/${id}`))) : "all";
}

function merge(a: Set<string> | "all" | undefined, b: Set<string> | "all"): Set<string> | "all" {
  if (a === "all" || b === "all") return "all";
  return new Set([...(a ?? []), ...b]);
}

function matches(set: Set<string> | "all" | undefined, ruleId: string): boolean {
  return set === "all" || (set !== undefined && set.has(ruleId));
}

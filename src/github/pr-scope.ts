/**
 * Limits pull request feedback to what the pull request changed. On repositories with
 * code scanning, GitHub already highlights only new alerts; without it (private repos
 * without GitHub Code Security), annotations for every pre-existing finding would bury
 * the ones a pull request introduces.
 */
import type { Finding } from "../engine/types.ts";

export type PrScope = "changed-lines" | "changed-files" | "all";

/** Repository-relative path → added/modified line numbers, or "all" (new or unparsable file). */
export type ChangedLines = Map<string, Set<number> | "all">;

interface PullFile {
  filename: string;
  status: string;
  patch?: string;
}

/** Line numbers (in the new file) that a unified diff adds or modifies. */
export function addedLines(patch: string): Set<number> {
  const lines = new Set<number>();
  let next = 0;
  for (const line of patch.split("\n")) {
    const hunk = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(line);
    if (hunk) {
      next = Number(hunk[1]);
      continue;
    }
    if (line.startsWith("+")) lines.add(next++);
    else if (line.startsWith(" ")) next++;
    // "-" lines don't exist in the new file; "\ No newline" markers are ignored.
  }
  return lines;
}

export async function fetchPullRequestChanges(opts: { token: string; apiUrl: string; repository: string; pull: number }): Promise<ChangedLines> {
  const changes: ChangedLines = new Map();
  const base = opts.apiUrl.replace(/\/$/, "");
  // The API returns at most 3000 files (30 pages of 100).
  for (let page = 1; page <= 30; page++) {
    const res = await fetch(`${base}/repos/${opts.repository}/pulls/${opts.pull}/files?per_page=100&page=${page}`, {
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `Bearer ${opts.token}`,
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "gml-code-scanner",
      },
    });
    if (!res.ok) throw new Error(`Could not list the pull request's files (HTTP ${res.status}). Give the workflow \`permissions: pull-requests: read\`.`);
    const files = (await res.json()) as PullFile[];
    for (const f of files) {
      if (f.status === "removed") continue;
      // No patch means a new, binary or very large file: treat every line as changed.
      changes.set(f.filename, f.status === "added" || !f.patch ? "all" : addedLines(f.patch));
    }
    if (files.length < 100) break;
  }
  return changes;
}

export function inScope(finding: Finding, changes: ChangedLines, toRepoPath: (file: string) => string, scope: PrScope): boolean {
  if (scope === "all") return true;
  const lines = changes.get(toRepoPath(finding.location.file));
  if (!lines) return false;
  if (scope === "changed-files" || lines === "all") return true;
  for (let l = finding.location.startLine; l <= finding.location.endLine; l++) if (lines.has(l)) return true;
  return false;
}

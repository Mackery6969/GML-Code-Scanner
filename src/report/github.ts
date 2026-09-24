import type { ScanResult } from "../engine/scanner.ts";
import type { Finding, Severity } from "../engine/types.ts";

/** Escaping rules for GitHub Actions workflow commands. */
function escapeData(s: string): string {
  return s.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
}

function escapeProperty(s: string): string {
  return escapeData(s).replace(/:/g, "%3A").replace(/,/g, "%2C");
}

const COMMAND: Record<Severity, string> = { error: "error", warning: "warning", note: "notice" };
const RANK: Record<Severity, number> = { error: 0, warning: 1, note: 2 };

/**
 * Workflow commands that show findings as inline annotations on the PR diff.
 * `toRepoPath` maps a finding path (relative to the scan root) to a repository path.
 */
export function formatAnnotations(findings: Finding[], toRepoPath: (file: string) => string, max: number): string {
  const sorted = [...findings].sort((a, b) => RANK[a.severity] - RANK[b.severity]);
  return sorted
    .slice(0, max)
    .map((f) => {
      const l = f.location;
      const props = [`file=${escapeProperty(toRepoPath(l.file))}`, `line=${l.startLine}`, `col=${l.startColumn}`, `endLine=${l.endLine}`];
      if (l.endLine === l.startLine) props.push(`endColumn=${l.endColumn}`);
      props.push(`title=${escapeProperty(f.ruleId)}`);
      return `::${COMMAND[f.severity]} ${props.join(",")}::${escapeData(f.message)}`;
    })
    .join("\n");
}

export interface SummaryLinks {
  serverUrl?: string;
  repository?: string;
  sha?: string;
}

/** Markdown for $GITHUB_STEP_SUMMARY. */
export function formatStepSummary(result: ScanResult, toRepoPath: (file: string) => string, links: SummaryLinks, maxRows = 50): string {
  const counts = { error: 0, warning: 0, note: 0 };
  const byRule = new Map<string, { count: number; severity: Severity }>();
  for (const f of result.findings) {
    counts[f.severity]++;
    const r = byRule.get(f.ruleId) ?? { count: 0, severity: f.severity };
    r.count++;
    if (RANK[f.severity] < RANK[r.severity]) r.severity = f.severity;
    byRule.set(f.ruleId, r);
  }
  const icon: Record<Severity, string> = { error: "🔴", warning: "🟡", note: "🔵" };
  const out: string[] = ["## GML Code Scanner", ""];
  if (result.findings.length === 0) {
    out.push(`✅ No problems found in ${result.filesScanned} GML files (${result.rules.length} rules).`);
    return out.join("\n") + "\n";
  }
  out.push(`| | Errors | Warnings | Notes | Files | Rules |`, `|---|---:|---:|---:|---:|---:|`);
  out.push(`| **Total** | ${counts.error} | ${counts.warning} | ${counts.note} | ${result.filesScanned} | ${result.rules.length} |`, "");
  out.push("<details><summary>Findings by rule</summary>", "", "| Rule | Count |", "|---|---:|");
  for (const [id, r] of [...byRule].sort((a, b) => RANK[a[1].severity] - RANK[b[1].severity] || b[1].count - a[1].count)) out.push(`| ${icon[r.severity]} \`${id}\` | ${r.count} |`);
  out.push("", "</details>", "");
  const link = (f: Finding) => {
    const path = toRepoPath(f.location.file);
    const text = `${path}:${f.location.startLine}`;
    if (!links.serverUrl || !links.repository || !links.sha) return `\`${text}\``;
    return `[${text}](${links.serverUrl}/${links.repository}/blob/${links.sha}/${encodeURI(path)}#L${f.location.startLine})`;
  };
  const sorted = [...result.findings].sort((a, b) => RANK[a.severity] - RANK[b.severity]);
  out.push("| | Location | Rule | Message |", "|---|---|---|---|");
  for (const f of sorted.slice(0, maxRows)) out.push(`| ${icon[f.severity]} | ${link(f)} | \`${f.ruleId}\` | ${f.message.replace(/\|/g, "\\|").replace(/\n/g, " ")} |`);
  if (sorted.length > maxRows) out.push("", `…and ${sorted.length - maxRows} more. Download the SARIF file or open the Security tab for the full list.`);
  return out.join("\n") + "\n";
}

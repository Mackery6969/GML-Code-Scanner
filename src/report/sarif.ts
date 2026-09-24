import { createHash } from "node:crypto";
import { join, relative, sep } from "node:path";
import { pathToFileURL } from "node:url";
import type { ScanResult } from "../engine/scanner.ts";
import type { Finding, RuleMeta, SourceLocation } from "../engine/types.ts";

export interface SarifOptions {
  toolName: string;
  toolVersion: string;
  informationUri: string;
  /** Absolute path the findings' `file` paths are relative to (the scan root). */
  scanRoot: string;
  /** Absolute path SARIF URIs should be relative to (the repository root). Defaults to scanRoot. */
  uriBase?: string;
  /** Distinguishes multiple analyses of one commit (GitHub code scanning "category"). */
  category?: string;
}

const LEVEL: Record<Finding["severity"], string> = { error: "error", warning: "warning", note: "note" };
const PROBLEM_SEVERITY: Record<Finding["severity"], string> = { error: "error", warning: "warning", note: "recommendation" };

function ruleTags(meta: RuleMeta): string[] {
  const tags: string[] = [meta.category];
  if (meta.category === "correctness" || meta.category === "project") tags.push("reliability");
  if (meta.category === "security") tags.push("security");
  for (const cwe of meta.cwe ?? []) tags.push(`external/cwe/cwe-${String(cwe).padStart(3, "0")}`);
  tags.push("gml", "gamemaker");
  return [...new Set(tags)];
}

export function toSarif(result: ScanResult, options: SarifOptions): object {
  const uriBase = options.uriBase ?? options.scanRoot;
  const toUri = (file: string) => relative(uriBase, join(options.scanRoot, file)).split(sep).join("/");
  const ruleIndex = new Map<string, number>();
  const rules = result.rules.map((meta, i) => {
    ruleIndex.set(meta.id, i);
    return {
      id: meta.id,
      name: meta.name,
      shortDescription: { text: meta.short },
      fullDescription: { text: meta.full },
      help: { text: stripMarkdown(meta.help), markdown: meta.help },
      helpUri: `${options.informationUri}/blob/main/docs/rules.md#${meta.id.replace(/[^a-z0-9]+/gi, "").toLowerCase()}`,
      defaultConfiguration: { level: LEVEL[meta.severity] },
      properties: {
        tags: ruleTags(meta),
        kind: meta.kind ?? "problem",
        precision: meta.precision,
        "problem.severity": PROBLEM_SEVERITY[meta.severity],
        ...(meta.securitySeverity !== undefined ? { "security-severity": meta.securitySeverity.toFixed(1) } : {}),
      },
    };
  });

  const physical = (loc: SourceLocation) => ({
    artifactLocation: { uri: toUri(loc.file), uriBaseId: "%SRCROOT%" },
    region: { startLine: loc.startLine, startColumn: loc.startColumn, endLine: loc.endLine, endColumn: loc.endColumn },
  });

  const occurrences = new Map<string, number>();
  const results = result.findings.map((f) => {
    // Stable across unrelated edits: rule + file + normalised line text (+ occurrence).
    const basis = `${f.ruleId}\0${toUri(f.location.file)}\0${(f.snippet ?? "").replace(/\s+/g, " ")}`;
    const n = (occurrences.get(basis) ?? 0) + 1;
    occurrences.set(basis, n);
    const hash = createHash("sha256").update(`${basis}\0${n}`).digest("hex").slice(0, 32);
    const out: Record<string, unknown> = {
      ruleId: f.ruleId,
      ...(ruleIndex.has(f.ruleId) ? { ruleIndex: ruleIndex.get(f.ruleId) } : {}),
      level: LEVEL[f.severity],
      message: { text: f.message },
      locations: [{ physicalLocation: physical(f.location) }],
      partialFingerprints: { primaryLocationLineHash: `${hash}:1` },
    };
    if (f.related?.length) {
      out.relatedLocations = f.related.map((r, i) => ({ id: i + 1, physicalLocation: physical(r.location), message: { text: r.message } }));
    }
    if (f.flow?.length) {
      out.codeFlows = [
        {
          threadFlows: [
            {
              locations: f.flow.map((s) => ({ location: { physicalLocation: physical(s.location), message: { text: s.message } } })),
            },
          ],
        },
      ];
    }
    return out;
  });

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: options.toolName,
            semanticVersion: options.toolVersion,
            version: options.toolVersion,
            informationUri: options.informationUri,
            rules,
          },
        },
        automationDetails: { id: `${options.category ?? "gml-code-scanner"}/` },
        originalUriBaseIds: { "%SRCROOT%": { uri: pathToFileURL(uriBase + sep).href } },
        invocations: [
          {
            executionSuccessful: true,
            toolExecutionNotifications: result.internalErrors.map((e) => ({
              level: "warning",
              message: { text: `Rule ${e.ruleId} failed${e.file ? ` on ${e.file}` : ""}: ${e.message.split("\n")[0]}` },
            })),
          },
        ],
        results,
        columnKind: "utf16CodeUnits",
      },
    ],
  };
}

function stripMarkdown(md: string): string {
  return md
    .replace(/```[a-z]*\n?/g, "")
    .replace(/\*\*(.+?)\*\*/g, "$1")
    .replace(/`([^`]+)`/g, "$1");
}

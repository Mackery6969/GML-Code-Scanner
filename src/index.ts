/** Library entry point: use the scanner programmatically (editor extensions, tooling). */
export { scan, isRuleInSuite, type ScanOptions, type ScanResult, type ProjectSummary } from "./engine/scanner.ts";
export { loadConfig, defaultConfig, type Config, type ResolvedConfig, type PatternRuleConfig } from "./engine/config.ts";
export type { Finding, Rule, RuleMeta, Severity, SourceLocation, Suite } from "./engine/types.ts";
export { parse, parsePattern } from "./parser/parser.ts";
export type * as AST from "./parser/ast.ts";
export { toSarif } from "./report/sarif.ts";
export { formatText } from "./report/text.ts";
export { ALL_RULES } from "./rules/index.ts";
export { VERSION } from "./version.ts";

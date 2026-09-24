import type { Rule } from "../engine/types.ts";
import { CORRECTNESS_RULES } from "./correctness.ts";
import { GAMEMAKER_RULES } from "./gamemaker.ts";
import { MAINTAINABILITY_RULES } from "./maintainability.ts";
import { PERFORMANCE_RULES } from "./performance.ts";
import { PROJECT_RULES } from "./project.ts";
import { SECURITY_RULES } from "./security.ts";

/** Reported by the scanner itself from parser errors. */
export const SYNTAX_ERROR_RULE: Rule = {
  meta: {
    id: "gml/syntax-error",
    name: "SyntaxError",
    category: "correctness",
    severity: "error",
    precision: "high",
    tier: "default",
    short: "GML syntax error.",
    full: "The file contains a syntax error; GameMaker will refuse to compile it.",
    help: `The scanner could not parse this code, and GameMaker won't compile it either.

If GameMaker **does** compile the file, the scanner's parser is missing some syntax. Please open an issue with the snippet, and suppress it meanwhile with \`// gmlscan-ignore-file gml/syntax-error\`.`,
  },
  file(ctx) {
    for (const err of ctx.file.ast.errors.slice(0, 10)) ctx.report(err, `Syntax error: ${err.message}.`);
  },
};

export const ALL_RULES: Rule[] = [...CORRECTNESS_RULES, ...GAMEMAKER_RULES, ...SECURITY_RULES, ...PERFORMANCE_RULES, ...MAINTAINABILITY_RULES, ...PROJECT_RULES];

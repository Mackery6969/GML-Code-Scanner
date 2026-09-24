/**
 * User-defined pattern rules (the scanner's lightweight "query language").
 *
 * A pattern is GML with metavariables and wildcards:
 *   show_debug_message($MSG)          any call, binding the argument to $MSG
 *   instance_create_layer(..., $OBJ)  `...` matches any number of arguments
 *   if ($C) { ... }                   `...` matches any statements
 *
 * Metavariables are `$` followed by an uppercase name. In patterns, write hex
 * numbers as 0xFF (not $FF).
 */
import type * as A from "../parser/ast.ts";
import { parsePattern } from "../parser/parser.ts";
import { ConfigError, type PatternRuleConfig } from "../engine/config.ts";
import type { Rule, Visitors } from "../engine/types.ts";
import { sameExpression } from "./util.ts";

type Bindings = Map<string, A.Node>;

const IGNORED_KEYS = new Set(["type", "start", "end", "parenthesized", "raw", "rawOperator", "bodyStart", "comments", "errors"]);

function isEllipsis(n: unknown): boolean {
  if (!n || typeof n !== "object") return false;
  const node = n as A.Node;
  return node.type === "PatternEllipsis" || (node.type === "Parameter" && node.id.name === "...") || (node.type === "ExpressionStatement" && node.expression.type === "PatternEllipsis");
}

function isNode(v: unknown): v is A.Node {
  return !!v && typeof v === "object" && typeof (v as A.Node).type === "string";
}

function match(p: A.Node, n: A.Node, b: Bindings): boolean {
  if (p.type === "PatternEllipsis") return true;
  if (p.type === "Metavariable") return bind(p.name, n, b);
  if (p.type === "Identifier" && p.name.startsWith("$") && p.name.length > 1) {
    if (n.type !== "Identifier") return false;
    return bind(p.name.slice(1), n, b);
  }
  // `$X;` as a statement matches any expression statement
  if (p.type === "ExpressionStatement" && p.expression.type === "Metavariable" && n.type !== "ExpressionStatement") return false;
  if (p.type !== n.type) return false;
  const pr = p as unknown as Record<string, unknown>;
  const nr = n as unknown as Record<string, unknown>;
  for (const key of Object.keys(pr)) {
    if (IGNORED_KEYS.has(key)) continue;
    const pv = pr[key];
    const nv = nr[key];
    if (Array.isArray(pv)) {
      if (!Array.isArray(nv) || !matchList(pv as A.Node[], nv as A.Node[], 0, 0, b)) return false;
    } else if (isNode(pv)) {
      if (!isNode(nv) || !match(pv, nv, b)) return false;
    } else if (pv === null) {
      // An omitted `else` in the pattern matches code with or without one.
      if (key === "alternate" || key === "init" || key === "argument") continue;
      if (nv !== null) return false;
    } else if (pv !== nv) {
      return false;
    }
  }
  return true;
}

function bind(name: string, n: A.Node, b: Bindings): boolean {
  const existing = b.get(name);
  if (existing) return sameExpression(existing, n);
  b.set(name, n);
  return true;
}

function matchList(ps: A.Node[], ns: A.Node[], i: number, j: number, b: Bindings): boolean {
  if (i === ps.length) return j === ns.length;
  if (isEllipsis(ps[i])) {
    for (let k = j; k <= ns.length; k++) {
      const trial = new Map(b);
      if (matchList(ps, ns, i + 1, k, trial)) {
        for (const [key, v] of trial) b.set(key, v);
        return true;
      }
    }
    return false;
  }
  if (j >= ns.length) return false;
  const trial = new Map(b);
  if (!match(ps[i], ns[j], trial) || !matchList(ps, ns, i + 1, j + 1, trial)) return false;
  for (const [key, v] of trial) b.set(key, v);
  return true;
}

interface CompiledPattern {
  node: A.Expression | A.Statement[];
}

export function createPatternRules(configs: PatternRuleConfig[]): Rule[] {
  return configs.map((cfg) => {
    const sources = Array.isArray(cfg.pattern) ? cfg.pattern : [cfg.pattern];
    const compiled: CompiledPattern[] = sources.map((src) => {
      const { node, errors } = parsePattern(src);
      if (errors.length) throw new ConfigError(`Pattern rule "${cfg.id}": cannot parse pattern \`${src}\`: ${errors[0].message}`);
      if (Array.isArray(node) && node.length === 0) throw new ConfigError(`Pattern rule "${cfg.id}": pattern is empty`);
      return { node };
    });
    const where = Object.entries(cfg.where ?? {}).map(([k, v]) => {
      try {
        return [k.replace(/^\$/, ""), new RegExp(v)] as const;
      } catch (e) {
        throw new ConfigError(`Pattern rule "${cfg.id}": invalid regex for ${k}: ${(e as Error).message}`);
      }
    });
    const id = cfg.id.includes("/") ? cfg.id : `custom/${cfg.id}`;
    const rule: Rule = {
      meta: {
        id,
        name: id.replace(/^.*\//, "").replace(/(^|[-_])(\w)/g, (_, _s, c: string) => c.toUpperCase()),
        category: cfg.category ?? "correctness",
        severity: cfg.severity ?? "warning",
        precision: "high",
        tier: "default",
        short: cfg.message.replace(/\$[A-Z_][A-Z0-9_]*/g, "…"),
        full: cfg.message.replace(/\$[A-Z_][A-Z0-9_]*/g, "…"),
        help: cfg.help ?? `Custom rule defined in \`.gmlscan.json\`.\n\nPattern:\n\n\`\`\`gml\n${sources.join("\n")}\n\`\`\``,
      },
      file(ctx) {
        if (cfg.events?.length) {
          const ev = ctx.file.event;
          if (!ev || !cfg.events.some((e) => e === ev.kind || e === ev.displayName)) return;
        }
        const visitors: Record<string, (n: A.Node) => void> = {};
        const report = (node: A.Node, b: Bindings) => {
          for (const [name, re] of where) {
            const bound = b.get(name);
            if (!bound || !re.test(ctx.file.source.text.slice(bound.start, bound.end))) return;
          }
          const message = cfg.message.replace(/\$([A-Z_][A-Z0-9_]*)/g, (m, name: string) => {
            const bound = b.get(name);
            return bound ? ctx.file.source.text.slice(bound.start, bound.end) : m;
          });
          ctx.report(node, message);
        };
        for (const c of compiled) addVisitors(visitors, c, report);
        return visitors as Visitors;
      },
    };
    return rule;
  });
}

function addVisitors(visitors: Record<string, (n: A.Node) => void>, c: CompiledPattern, report: (n: A.Node, b: Bindings) => void): void {
  const on = (type: string, fn: (n: A.Node) => void) => {
    const prev = visitors[type];
    visitors[type] = prev
      ? (n) => {
          prev(n);
          fn(n);
        }
      : fn;
  };
  const single = !Array.isArray(c.node) ? c.node : c.node.length === 1 ? c.node[0] : undefined;
  if (single) {
    // A lone expression statement pattern also matches the bare expression.
    const target = single.type === "ExpressionStatement" ? single.expression : single;
    if (target.type === "Metavariable" || target.type === "PatternEllipsis") throw new ConfigError("A pattern must not consist of only a metavariable or `...`");
    on(target.type, (n) => {
      const b: Bindings = new Map();
      if (match(target, n, b)) report(n, b);
    });
    return;
  }
  const stmts = c.node as A.Statement[];
  const seq = (list: A.Statement[]) => {
    for (let s = 0; s < list.length; s++) {
      const b: Bindings = new Map();
      if (matchList([...stmts, { type: "PatternEllipsis", start: 0, end: 0 }], list.slice(s), 0, 0, b)) {
        report(list[s], b);
      }
    }
  };
  on("Program", (n) => seq((n as A.Program).body));
  on("BlockStatement", (n) => seq((n as A.BlockStatement).body));
  on("SwitchCase", (n) => seq((n as A.SwitchCase).body));
}

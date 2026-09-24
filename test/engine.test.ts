import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { globToRegExp, parseJsonc } from "../src/engine/config.ts";
import { toSarif } from "../src/report/sarif.ts";
import { formatAnnotations } from "../src/report/github.ts";
import { eventCode, findingsFor, scanFiles, scanProject, writeProject } from "./helpers.ts";

describe("config", () => {
  it("parses JSON with comments and trailing commas", () => {
    assert.deepEqual(parseJsonc(`{ // c\n "a": [1, 2,], /* x */ "b": "//not a comment", }`), { a: [1, 2], b: "//not a comment" });
  });

  it("matches globs like .gitignore", () => {
    assert.ok(globToRegExp("extensions/**").test("extensions/foo/bar.gml"));
    assert.ok(globToRegExp("*.gml").test("scripts/a/a.gml"));
    assert.ok(globToRegExp("scripts/vendor_*/**").test("scripts/vendor_input/vendor_input.gml"));
    assert.ok(!globToRegExp("scripts/vendor_*/**").test("scripts/mine/mine.gml"));
  });

  it("rule settings turn rules off and change severity", () => {
    const files = eventCode("exit; x = 1;");
    assert.equal(scanFiles(files, { config: { rules: { "gml/unreachable-code": "off" } } }).filter((f) => f.ruleId === "gml/unreachable-code").length, 0);
    const [f] = scanFiles(files, { config: { rules: { "gml/unreachable-code": "error" } }, suite: "default" }).filter((x) => x.ruleId === "gml/unreachable-code");
    assert.equal(f.severity, "error");
  });

  it("ignore globs exclude files", () => {
    const files = { ...eventCode("exit; x = 1;"), "scripts/vendor_lib/vendor_lib.gml": "exit; y = 2;" };
    const f = scanFiles(files, { config: { ignore: ["scripts/vendor_*/**"] }, rules: ["gml/unreachable-code"] });
    assert.equal(f.length, 1);
  });

  it("suites select rules", () => {
    const dir = writeProject(eventCode("x = 1;"));
    const ids = (suite: "default" | "security-extended" | "security-and-quality") => new Set(scanProject(dir, { suite }).rules.map((r) => r.id));
    assert.ok(ids("default").has("gml/code-injection"));
    assert.ok(!ids("default").has("gml/untrusted-url"));
    assert.ok(ids("security-extended").has("gml/untrusted-url"));
    assert.ok(!ids("security-extended").has("gml/unused-local"));
    assert.ok(ids("security-and-quality").has("gml/unused-local"));
  });
});

describe("suppressions", () => {
  it("honours ignore comments", () => {
    const code = `// gmlscan-ignore-next-line gml/unreachable-code\nexit; x = 1;\nexit; y = 2; // gmlscan-ignore-line\n`;
    assert.equal(findingsFor(eventCode(code), "gml/unreachable-code").length, 0);
    assert.equal(findingsFor(eventCode(`// gmlscan-ignore-file unreachable-code\nexit; x = 1;`), "gml/unreachable-code").length, 0);
    assert.equal(findingsFor(eventCode(`// gmlscan-ignore-next-line gml/other-rule\nexit; x = 1;`), "gml/unreachable-code").length, 1);
  });
});

describe("custom pattern rules", () => {
  it("matches metavariables, ellipsis and constraints", () => {
    const config = {
      patterns: [
        { id: "no-debug-overlay", pattern: "show_debug_overlay(true)", message: "Remove the debug overlay." },
        { id: "no-obj-create", pattern: "instance_create_layer(..., $OBJ)", message: "Creating $OBJ directly", where: { $OBJ: "^obj_enemy" } },
        { id: "step-only", pattern: "room_goto($R)", message: "room change in step: $R", events: ["Step"] },
      ],
    };
    const files = eventCode(`show_debug_overlay(true); show_debug_overlay(false); instance_create_layer(0, 0, "I", obj_enemy_bat); instance_create_layer(0, 0, "I", obj_coin); room_goto(rm_next);`);
    const f = scanFiles(files, { config, suite: "default" }).filter((x) => x.ruleId.startsWith("custom/"));
    assert.deepEqual(f.map((x) => x.message).sort(), ["Creating obj_enemy_bat directly", "Remove the debug overlay.", "room change in step: rm_next"]);
  });

  it("matches statement sequences", () => {
    const config = { patterns: [{ id: "open-no-close", pattern: "ini_open($F); ...; ini_close();", message: "ini used" }] };
    const f = scanFiles(eventCode(`ini_open("a"); v = 1; ini_close();`, "Create_0"), { config, suite: "default" }).filter((x) => x.ruleId === "custom/open-no-close");
    assert.equal(f.length, 1);
  });
});

describe("reports", () => {
  it("produces valid SARIF with paths, fingerprints and rule metadata", () => {
    const dir = writeProject(eventCode(`var cmd = async_load[? "result"]; script_execute(asset_get_index(cmd));`, "Other_62"));
    const result = scanProject(dir, { suite: "default" });
    const sarif = toSarif(result, { toolName: "GML Code Scanner", toolVersion: "1.0.0", informationUri: "https://example.com", scanRoot: dir }) as any;
    assert.equal(sarif.version, "2.1.0");
    const run = sarif.runs[0];
    const res = run.results.find((r: any) => r.ruleId === "gml/code-injection");
    assert.ok(res, "has the code-injection result");
    assert.equal(run.tool.driver.rules[res.ruleIndex].id, "gml/code-injection");
    assert.equal(run.tool.driver.rules[res.ruleIndex].properties["security-severity"], "9.3");
    assert.ok(run.tool.driver.rules[res.ruleIndex].properties.tags.includes("external/cwe/cwe-094"));
    assert.equal(res.locations[0].physicalLocation.artifactLocation.uri, "objects/obj_test/Other_62.gml");
    assert.ok(res.codeFlows[0].threadFlows[0].locations.length >= 2);
    assert.match(res.partialFingerprints.primaryLocationLineHash, /^[0-9a-f]{32}:1$/);
    // Fingerprints are stable across runs.
    const again = toSarif(scanProject(dir, { suite: "default" }), { toolName: "x", toolVersion: "1", informationUri: "https://example.com", scanRoot: dir }) as any;
    assert.equal(again.runs[0].results.find((r: any) => r.ruleId === "gml/code-injection").partialFingerprints.primaryLocationLineHash, res.partialFingerprints.primaryLocationLineHash);
  });

  it("formats GitHub annotations with escaping", () => {
    const out = formatAnnotations(
      [{ ruleId: "gml/x", severity: "warning", message: "50% done\nnext", location: { file: "a,b.gml", startLine: 3, startColumn: 2, endLine: 3, endColumn: 5 } }],
      (f) => `game/${f}`,
      10,
    );
    assert.equal(out, "::warning file=game/a%2Cb.gml,line=3,col=2,endLine=3,endColumn=5,title=gml/x::50%25 done%0Anext");
  });
});

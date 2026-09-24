import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";
import { scan } from "../src/engine/scanner.ts";
import { defaultConfig } from "../src/engine/config.ts";

const SAMPLE = fileURLToPath(new URL("./fixtures/sample-game", import.meta.url));

describe("sample game fixture", () => {
  const result = scan({ root: SAMPLE, config: defaultConfig() });
  const found = (ruleId: string, file?: string) => result.findings.filter((f) => f.ruleId === ruleId && (!file || f.location.file === file));

  it("finds every planted bug with the default suite", () => {
    const expected: [string, string][] = [
      ["gml/undefined-variable", "objects/obj_player/Step_0.gml"],
      ["gml/unconditional-per-frame-action", "objects/obj_player/Step_0.gml"],
      ["gml/empty-statement-body", "objects/obj_player/Step_0.gml"],
      ["gml/draw-outside-draw-event", "objects/obj_player/Step_0.gml"],
      ["gml/instance-number-as-exists", "objects/obj_player/Step_0.gml"],
      ["gml/string-number-addition", "objects/obj_player/Draw_0.gml"],
      ["gml/surface-exists-check", "objects/obj_player/Draw_0.gml"],
      ["gml/resource-leak", "objects/obj_player/Create_0.gml"],
      ["gml/uncaptured-local", "scripts/scr_util/scr_util.gml"],
      ["gml/code-injection", "scripts/scr_util/scr_util.gml"],
      ["gml/path-injection", "objects/obj_net/Other_62.gml"],
      ["gml/variable-injection", "objects/obj_net/Other_62.gml"],
      ["gml/hardcoded-secret", "objects/obj_net/Create_0.gml"],
      ["gml/hardcoded-secret", "datafiles/config.ini"],
      ["gml/insecure-http", "objects/obj_net/Create_0.gml"],
      ["gml/duplicate-resource", "SampleGame.yyp"],
      ["gml/unused-object", "objects/obj_hud/Draw_64.gml"],
      ["gml/unused-function", "scripts/scr_util/scr_util.gml"],
    ];
    const missing = expected.filter(([rule, file]) => found(rule, file).length === 0);
    assert.deepEqual(missing, [], `missing findings:\n${missing.map((m) => m.join(" in ")).join("\n")}`);
    assert.deepEqual(result.internalErrors, []);
  });

  it("traces the network packet through run_command() to script_execute()", () => {
    const [f] = found("gml/code-injection");
    const files = f.flow!.map((s) => s.location.file);
    assert.equal(files[0], "objects/obj_net/Other_68.gml");
    assert.equal(files[files.length - 1], "scripts/scr_util/scr_util.gml");
  });

  it("reports no false positives on correct lines", () => {
    // move_speed is assigned in Create; string(move_speed) is fine.
    assert.equal(result.findings.filter((f) => f.location.file === "objects/obj_player/Draw_0.gml" && f.location.startLine === 3).length, 0);
    assert.equal(found("gml/undefined-function").length, 0);
  });
});

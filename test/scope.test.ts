import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { parse } from "../src/parser/parser.ts";
import { resolveScopes } from "../src/semantic/scope.ts";

function bindings(src: string): Record<string, string[]> {
  const scopes = resolveScopes(parse(src));
  const out: Record<string, string[]> = {};
  for (const r of scopes.refs) (out[r.id.name] ??= []).push(`${r.binding.kind}:${r.access}`);
  return out;
}

describe("scope resolution", () => {
  it("binds locals only after their declaration", () => {
    const b = bindings(`hp = 1; var hp = 2; hp += 1;`);
    assert.deepEqual(b.hp, ["free:write", "local:readwrite"]);
  });

  it("treats parameters as locals", () => {
    const b = bindings(`function f(a) { return a + b; }`);
    assert.deepEqual(b.a, ["local:read"]);
    assert.deepEqual(b.b, ["free:read"]);
  });

  it("does not capture outer locals in nested functions", () => {
    const b = bindings(`function f() { var total = 0; array_foreach(arr, function(v) { total += v; }); return total; }`);
    assert.deepEqual(b.total, ["uncaptured:readwrite", "local:read"]);
  });

  it("keeps locals inside with blocks", () => {
    const b = bindings(`var n = 1; with (obj_enemy) { hp -= n; }`);
    assert.deepEqual(b.n, ["local:read"]);
  });

  it("counts index assignment as writing the array variable", () => {
    const b = bindings(`inventory[0] = 5;`);
    assert.deepEqual(b.inventory, ["free:readwrite"]);
  });

  it("marks argument usage", () => {
    const scopes = resolveScopes(parse(`function f() { return argument0 + argument_count; }`));
    assert.equal(scopes.root.children[0].usesArguments, true);
  });
});

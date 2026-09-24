import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { after, describe, it } from "node:test";
import type { Finding } from "../src/engine/types.ts";
import { addedLines, fetchPullRequestChanges, inScope } from "../src/github/pr-scope.ts";

const finding = (file: string, startLine: number, endLine = startLine): Finding => ({
  ruleId: "gml/x",
  severity: "error",
  message: "m",
  location: { file, startLine, startColumn: 1, endLine, endColumn: 2 },
});

describe("pull request scope", () => {
  it("parses added lines from a unified diff", () => {
    const patch = ["@@ -1,4 +1,5 @@", " keep", "-old", "+new1", "+new2", " keep", "@@ -20,2 +21,3 @@", " ctx", "+added", " ctx", "\\ No newline at end of file"].join("\n");
    assert.deepEqual([...addedLines(patch)].sort((a, b) => a - b), [2, 3, 22]);
  });

  it("matches findings to changed lines and files", () => {
    const changes = new Map<string, Set<number> | "all">([
      ["game/objects/obj_a/Step_0.gml", new Set([10, 11])],
      ["game/scripts/new/new.gml", "all"],
    ]);
    const toRepo = (f: string) => `game/${f}`;
    assert.equal(inScope(finding("objects/obj_a/Step_0.gml", 10), changes, toRepo, "changed-lines"), true);
    assert.equal(inScope(finding("objects/obj_a/Step_0.gml", 9, 10), changes, toRepo, "changed-lines"), true);
    assert.equal(inScope(finding("objects/obj_a/Step_0.gml", 3), changes, toRepo, "changed-lines"), false);
    assert.equal(inScope(finding("objects/obj_a/Step_0.gml", 3), changes, toRepo, "changed-files"), true);
    assert.equal(inScope(finding("scripts/new/new.gml", 99), changes, toRepo, "changed-lines"), true);
    assert.equal(inScope(finding("objects/obj_b/Step_0.gml", 1), changes, toRepo, "changed-files"), false);
    assert.equal(inScope(finding("objects/obj_b/Step_0.gml", 1), changes, toRepo, "all"), true);
  });

  it("fetches changed files from the API with pagination", async () => {
    const pages: Record<string, unknown[]> = {
      "1": Array.from({ length: 100 }, (_, i) => ({ filename: `f${i}.gml`, status: "modified", patch: "@@ -1 +1 @@\n+x" })),
      "2": [
        { filename: "new.gml", status: "added" },
        { filename: "gone.gml", status: "removed" },
        { filename: "big.gml", status: "modified" },
      ],
    };
    const server = createServer((req, res) => {
      const page = new URL(req.url!, "http://x").searchParams.get("page")!;
      if (req.headers.authorization !== "Bearer tok") {
        res.writeHead(403).end("{}");
        return;
      }
      res.writeHead(200, { "Content-Type": "application/json" }).end(JSON.stringify(pages[page] ?? []));
    });
    server.listen(0);
    after(() => server.close());
    const apiUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    const changes = await fetchPullRequestChanges({ token: "tok", apiUrl, repository: "o/r", pull: 5 });
    assert.equal(changes.size, 102);
    assert.deepEqual([...(changes.get("f0.gml") as Set<number>)], [1]);
    assert.equal(changes.get("new.gml"), "all");
    assert.equal(changes.get("big.gml"), "all");
    assert.equal(changes.has("gone.gml"), false);
    await assert.rejects(fetchPullRequestChanges({ token: "bad", apiUrl, repository: "o/r", pull: 5 }), /pull-requests: read/);
  });
});

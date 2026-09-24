import assert from "node:assert/strict";
import { createServer, type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";
import { after, describe, it } from "node:test";
import { gunzipSync } from "node:zlib";
import { UploadError, uploadSarif } from "../src/github/upload.ts";

interface Captured {
  method?: string;
  url?: string;
  auth?: string;
  body?: Record<string, unknown>;
}

function mockGitHub(handler: (req: IncomingMessage, body: string) => { status: number; json: unknown }) {
  const captured: Captured[] = [];
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (d) => (body += d));
    req.on("end", () => {
      captured.push({ method: req.method, url: req.url, auth: req.headers.authorization, body: body ? JSON.parse(body) : undefined });
      const out = handler(req, body);
      res.writeHead(out.status, { "Content-Type": "application/json" });
      res.end(JSON.stringify(out.json));
    });
  });
  server.listen(0);
  after(() => server.close());
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return { url, captured };
}

const base = { token: "t0k", repository: "me/game", ref: "refs/pull/7/merge", sha: "abc123", toolName: "GML Code Scanner", log: () => {}, pollIntervalMs: 10 };

describe("code scanning upload", () => {
  it("uploads gzipped SARIF and waits for processing", async () => {
    let polls = 0;
    const gh = mockGitHub((req) => {
      if (req.method === "POST") return { status: 202, json: { id: "42", url: "x" } };
      polls++;
      return { status: 200, json: { processing_status: polls < 2 ? "pending" : "complete" } };
    });
    const sarif = { version: "2.1.0", runs: [] };
    const res = await uploadSarif(sarif, { ...base, apiUrl: gh.url, waitForProcessing: true });
    assert.deepEqual(res, { id: "42", status: "complete", errors: [] });
    const post = gh.captured[0];
    assert.equal(post.url, "/repos/me/game/code-scanning/sarifs");
    assert.equal(post.auth, "Bearer t0k");
    assert.equal(post.body!.ref, "refs/pull/7/merge");
    assert.equal(post.body!.commit_sha, "abc123");
    assert.deepEqual(JSON.parse(gunzipSync(Buffer.from(post.body!.sarif as string, "base64")).toString()), sarif);
    assert.equal(gh.captured[1].url, "/repos/me/game/code-scanning/sarifs/42");
  });

  it("reports processing failures", async () => {
    const gh = mockGitHub((req) => (req.method === "POST" ? { status: 202, json: { id: "1" } } : { status: 200, json: { processing_status: "failed", errors: ["bad location"] } }));
    const res = await uploadSarif({}, { ...base, apiUrl: gh.url, waitForProcessing: true });
    assert.equal(res.status, "failed");
    assert.deepEqual(res.errors, ["bad location"]);
  });

  it("flags unavailable code scanning", async () => {
    const gh = mockGitHub(() => ({ status: 403, json: { message: "Advanced Security must be enabled for this repository to use code scanning." } }));
    await assert.rejects(
      uploadSarif({}, { ...base, apiUrl: gh.url, waitForProcessing: false }),
      (e: unknown) => e instanceof UploadError && e.unavailable && /Advanced Security/.test(e.message),
    );
  });
});

/**
 * Uploads SARIF to GitHub code scanning via the REST API, so the action works as a
 * single step (like CodeQL's analyze step) without github/codeql-action/upload-sarif.
 */
import { gzipSync } from "node:zlib";

export interface UploadOptions {
  token: string;
  /** e.g. https://api.github.com (GITHUB_API_URL on GitHub Enterprise Server). */
  apiUrl: string;
  /** owner/repo */
  repository: string;
  /** refs/heads/main or refs/pull/123/merge */
  ref: string;
  sha: string;
  checkoutUri?: string;
  toolName: string;
  /** Poll until GitHub has processed the upload (reports processing errors). */
  waitForProcessing: boolean;
  /** First poll delay in ms (grows 1.5x per poll, up to 10 s). */
  pollIntervalMs?: number;
  log: (message: string) => void;
}

export interface UploadResult {
  id: string;
  status: "complete" | "pending" | "failed";
  errors: string[];
}

export class UploadError extends Error {
  readonly status: number;
  /** Code scanning is unavailable (not enabled, no Code Security, fork PR, missing permission). */
  readonly unavailable: boolean;
  constructor(message: string, status: number, unavailable: boolean) {
    super(message);
    this.status = status;
    this.unavailable = unavailable;
  }
}

const MAX_GZIP_BYTES = 10 * 1024 * 1024;

async function request(url: string, init: RequestInit & { token: string }): Promise<Response> {
  const { token, ...rest } = init;
  return fetch(url, {
    ...rest,
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${token}`,
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "gml-code-scanner",
      ...(rest.body ? { "Content-Type": "application/json" } : {}),
    },
  });
}

export async function uploadSarif(sarif: object, opts: UploadOptions): Promise<UploadResult> {
  const gz = gzipSync(Buffer.from(JSON.stringify(sarif)));
  if (gz.length > MAX_GZIP_BYTES) {
    throw new UploadError(`SARIF is ${(gz.length / 1024 / 1024).toFixed(1)} MB compressed; GitHub accepts at most 10 MB. Narrow the scan with "ignore" or a smaller suite.`, 413, false);
  }
  const base = opts.apiUrl.replace(/\/$/, "");
  const res = await request(`${base}/repos/${opts.repository}/code-scanning/sarifs`, {
    method: "POST",
    token: opts.token,
    body: JSON.stringify({
      commit_sha: opts.sha,
      ref: opts.ref,
      sarif: gz.toString("base64"),
      tool_name: opts.toolName,
      ...(opts.checkoutUri ? { checkout_uri: opts.checkoutUri } : {}),
    }),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    let message = body;
    try {
      message = (JSON.parse(body) as { message?: string }).message ?? body;
    } catch {
      // not JSON
    }
    const unavailable = res.status === 403 || res.status === 404;
    throw new UploadError(`GitHub rejected the SARIF upload (HTTP ${res.status}): ${message}`, res.status, unavailable);
  }
  const { id } = (await res.json()) as { id: string };
  opts.log(`Uploaded results to code scanning (upload id ${id}).`);
  if (!opts.waitForProcessing) return { id, status: "pending", errors: [] };

  // Processing normally takes a few seconds; give up waiting after two minutes.
  const deadline = Date.now() + 120_000;
  let delay = opts.pollIntervalMs ?? 2_000;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, delay));
    delay = Math.min(delay * 1.5, 10_000);
    const poll = await request(`${base}/repos/${opts.repository}/code-scanning/sarifs/${id}`, { method: "GET", token: opts.token });
    if (!poll.ok) {
      // 404 right after upload is normal while GitHub registers it.
      if (poll.status === 404) continue;
      return { id, status: "pending", errors: [`Could not check processing status (HTTP ${poll.status}).`] };
    }
    const status = (await poll.json()) as { processing_status: string; errors?: string[] | null };
    if (status.processing_status === "complete") return { id, status: "complete", errors: [] };
    if (status.processing_status === "failed") return { id, status: "failed", errors: status.errors ?? ["Processing failed."] };
  }
  return { id, status: "pending", errors: [] };
}

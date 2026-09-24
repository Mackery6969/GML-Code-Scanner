/**
 * Bundles the GitHub Action (dist/index.js) and the CLI (dist/cli.js) into single
 * dependency-free files. dist/ is committed: GitHub runs actions straight from the repo.
 */
import { build } from "esbuild";
import { rmSync } from "node:fs";

rmSync(new URL("../dist", import.meta.url), { recursive: true, force: true });

const common = {
  bundle: true,
  platform: "node" as const,
  target: "node20",
  format: "esm" as const,
  sourcemap: false,
  legalComments: "none" as const,
  logLevel: "info" as const,
};

await build({ ...common, entryPoints: ["src/action.ts"], outfile: "dist/index.js" });
await build({ ...common, entryPoints: ["src/cli.ts"], outfile: "dist/cli.js" });

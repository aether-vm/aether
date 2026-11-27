import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";

// Compiled to dist/test-build/tests/, three levels below the package root.
const root = new URL("../../../", import.meta.url);

type Pkg = { files: string[]; scripts: Record<string, string> };
const pkg = (): Pkg => JSON.parse(readFileSync(new URL("package.json", root), "utf8")) as Pkg;

describe("package metadata", () => {
  it("lists only files that exist in the package directory", () => {
    for (const entry of pkg().files.filter((f) => !f.startsWith("!"))) {
      assert.ok(existsSync(new URL(entry, root)), `package.json files entry ${entry} is missing`);
    }
  });

  it("builds before packing and leaves the test build out of the package", () => {
    assert.equal(pkg().scripts.prepack, "npm run build");
    // Under `npm test`, run that same npm through node: plain `npm` is `npm.cmd` on Windows,
    // which execFile cannot start.
    const args = ["pack", "--dry-run", "--json", "--ignore-scripts"];
    const opts = { cwd: fileURLToPath(root), encoding: "utf8" } as const;
    const npmCli = process.env.npm_execpath;
    const out = npmCli
      ? execFileSync(process.execPath, [npmCli, ...args], opts)
      : execFileSync("npm", args, opts);
    const [{ files }] = JSON.parse(out) as [{ files: { path: string }[] }];
    const paths = files.map((f) => f.path);
    // `npm test` builds first, so the entry points must be in what it packs.
    for (const want of ["README.md", "dist/index.js", "dist/index.d.ts", "proto/forkloom/v1/runtime.proto"]) {
      assert.ok(paths.includes(want), `${want} missing from: ${paths.join(" ")}`);
    }
    assert.deepEqual(paths.filter((p) => p.startsWith("dist/test-build/")), []);
  });

  it("pins dependencies with a lockfile", () => {
    assert.ok(existsSync(new URL("package-lock.json", root)), "package-lock.json is missing");
  });
});

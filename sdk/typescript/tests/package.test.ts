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
    const out = execFileSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], {
      cwd: fileURLToPath(root),
      encoding: "utf8",
    });
    const [{ files }] = JSON.parse(out) as [{ files: { path: string }[] }];
    const paths = files.map((f) => f.path);
    assert.ok(paths.includes("README.md"), paths.join(" "));
    assert.deepEqual(paths.filter((p) => p.startsWith("dist/test-build/")), []);
  });

  it("pins dependencies with a lockfile", () => {
    assert.ok(existsSync(new URL("package-lock.json", root)), "package-lock.json is missing");
  });
});

#!/usr/bin/env node
/**
 * Copy ../../proto/forkloom/v1/runtime.proto into ./proto/forkloom/v1/runtime.proto
 * so @forkloom-vm/sdk is self-contained when published to npm.
 *
 * Usage:
 *   node scripts/sync-proto.mjs          # sync proto into sdk/typescript/proto/
 *   node scripts/sync-proto.mjs --check  # verify bundled copy matches repo proto
 */

import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const sdkRoot = resolve(__dirname, "..");
const repoProto = resolve(sdkRoot, "..", "..", "proto", "forkloom", "v1", "runtime.proto");
const localProto = resolve(sdkRoot, "proto", "forkloom", "v1", "runtime.proto");

function normalizeLf(buf) {
  return buf.toString("utf8").replace(/\r\n/g, "\n");
}

const checkOnly = process.argv.includes("--check");

if (!existsSync(repoProto)) {
  console.error(`Source proto not found: ${repoProto}`);
  process.exit(1);
}

const sourceContent = normalizeLf(readFileSync(repoProto));

if (checkOnly) {
  if (!existsSync(localProto)) {
    console.error(`Bundled proto missing: ${localProto}\nRun: npm run sync-proto`);
    process.exit(1);
  }
  const localContent = normalizeLf(readFileSync(localProto));
  if (localContent !== sourceContent) {
    console.error(`Bundled proto is out of date with ${repoProto}\nRun: npm run sync-proto`);
    process.exit(1);
  }
  console.log("TypeScript bundled runtime.proto is up to date.");
  process.exit(0);
}

mkdirSync(dirname(localProto), { recursive: true });
writeFileSync(localProto, sourceContent, "utf8");
console.log(`Synced runtime.proto -> ${localProto}`);

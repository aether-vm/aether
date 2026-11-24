import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";

export const PROTO_LOADER_OPTIONS: protoLoader.Options = {
  keepCase: false,
  longs: String,
  enums: String,
  defaults: true,
  oneofs: true,
};

const __dirname = dirname(fileURLToPath(import.meta.url));

/**
 * Resolve `forkloom/v1/runtime.proto`, checking the bundled package copy first
 * (for published npm installs) and falling back to the monorepo root proto.
 */
export function resolveProtoPath(): string {
  const candidates = [
    // Compiled dist/proto.js -> ../proto/forkloom/v1/runtime.proto
    resolve(__dirname, "..", "proto", "forkloom", "v1", "runtime.proto"),
    // Compiled dist/test-build/src/proto.js -> ../../../proto/forkloom/v1/runtime.proto
    resolve(__dirname, "..", "..", "..", "proto", "forkloom", "v1", "runtime.proto"),
    // Monorepo fallback from dist/
    resolve(__dirname, "..", "..", "..", "..", "proto", "forkloom", "v1", "runtime.proto"),
    // Monorepo fallback from dist/test-build/src/
    resolve(__dirname, "..", "..", "..", "..", "..", "proto", "forkloom", "v1", "runtime.proto"),
  ];
  for (const candidate of candidates) {
    if (existsSync(candidate)) {
      return candidate;
    }
  }
  throw new Error(
    `Unable to locate forkloom/v1/runtime.proto (searched: ${candidates.join(", ")})`,
  );
}

export interface ForkloomGrpcPackage {
  forkloom: {
    v1: {
      SystemService: grpc.ServiceClientConstructor;
      FrameService: grpc.ServiceClientConstructor;
      WorldService: grpc.ServiceClientConstructor;
    };
  };
}

let cachedPackageDef: protoLoader.PackageDefinition | undefined;
let cachedPackage: ForkloomGrpcPackage | undefined;

export function loadForkloomPackageDefinition(): protoLoader.PackageDefinition {
  if (!cachedPackageDef) {
    const protoPath = resolveProtoPath();
    const includeDir = resolve(dirname(protoPath), "..", "..");
    cachedPackageDef = protoLoader.loadSync(protoPath, {
      ...PROTO_LOADER_OPTIONS,
      includeDirs: [includeDir],
    });
  }
  return cachedPackageDef;
}

export function loadForkloomPackage(): ForkloomGrpcPackage {
  if (!cachedPackage) {
    cachedPackage = grpc.loadPackageDefinition(
      loadForkloomPackageDefinition(),
    ) as unknown as ForkloomGrpcPackage;
  }
  return cachedPackage;
}

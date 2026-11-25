import { randomUUID } from "node:crypto";

/** Lockstep client version matching `agentd`. */
export const CLIENT_VERSION = "0.1.0-alpha.0";
/** Required `forkloom.v1` API major version verified during `NegotiateVersion`. */
export const SUPPORTED_API_MAJOR = 1;
/** Default client identifier sent in `NegotiateVersionRequest.clientName`. */
export const DEFAULT_CLIENT_NAME = "forkloom-ts";
/** Default `agentd` Unix Domain Socket path (`crates/agentd/src/transport.rs`). */
export const DEFAULT_SOCKET_PATH = "/run/forkloom/agentd.sock";
/** Default gRPC UDS target URI. */
export const DEFAULT_TARGET = `unix://${DEFAULT_SOCKET_PATH}`;
/** Environment variable overriding the default socket path. */
export const SOCKET_ENV_VAR = "FORKLOOM_SOCKET";

export type Uint64Input = number | bigint | string;

export enum FrameDurability {
  UNSPECIFIED = "FRAME_DURABILITY_UNSPECIFIED",
  DURABLE = "FRAME_DURABILITY_DURABLE",
  VOLATILE = "FRAME_DURABILITY_VOLATILE",
}

export enum FrameStateKind {
  UNSPECIFIED = "FRAME_STATE_UNSPECIFIED",
  PREPARING = "FRAME_STATE_PREPARING",
  COMMITTED = "FRAME_STATE_COMMITTED",
  DELETING = "FRAME_STATE_DELETING",
}

export enum WorldStateKind {
  UNSPECIFIED = "WORLD_STATE_UNSPECIFIED",
  RUNNING = "WORLD_STATE_RUNNING",
  DESTROYED = "WORLD_STATE_DESTROYED",
  LOST = "WORLD_STATE_LOST",
}

export enum DriverKind {
  UNSPECIFIED = "DRIVER_KIND_UNSPECIFIED",
  NAMESPACE = "DRIVER_KIND_NAMESPACE",
  FIRECRACKER = "DRIVER_KIND_FIRECRACKER",
}

export enum OutputStreamKind {
  UNSPECIFIED = "OUTPUT_STREAM_UNSPECIFIED",
  STDOUT = "OUTPUT_STREAM_STDOUT",
  STDERR = "OUTPUT_STREAM_STDERR",
}

export enum ErrorCode {
  UNSPECIFIED = 0,
  WORLD_LOST = 1,
  OUTCOME_UNKNOWN = 2,
  FENCED_OUT = 3,
  FRAME_NOT_FOUND = 4,
  WORLD_NOT_FOUND = 5,
  TIMELINE_NOT_FOUND = 6,
  TIMELINE_CAS_MISMATCH = 7,
  IDEMPOTENCY_CONFLICT = 8,
  OWNER_MISMATCH = 9,
  RESOURCE_EXHAUSTED = 10,
  UNSAFE_PATCH = 11,
  DISK_NOT_CLEAN = 12,
  INVALID_ARGUMENT = 13,
  DRIVER_UNAVAILABLE = 14,
  WORLD_NOT_RUNNING = 15,
  VOLATILE_IN_TIMELINE_FORBIDDEN = 16,
  PIN_NOT_FOUND = 17,
  FRAME_MARKED_FOR_DELETION = 18,
  PREPARED_FRAME_ABORTED = 19,
  INTERNAL = 20,
}

export interface IdempotencyKey {
  owner: string;
  requestId: string;
}

export interface FencingToken {
  value: bigint;
}

export type FencingTokenInput = Uint64Input | FencingToken;

export interface PinSpec {
  pinId: string;
  owner: string;
  leaseTtlMs?: Uint64Input;
}

export interface HoldInfo {
  kind: string;
  detail: string;
  expiresAtMs: bigint;
}

export interface FrameInfo {
  frameId: string;
  owner: string;
  durability: FrameDurability;
  state: FrameStateKind;
  parentFrameId: string;
  labels: Record<string, string>;
  diskClean: boolean;
  createdEpoch: bigint;
  committedAtMs: bigint;
  objects: string[];
  holds: HoldInfo[];
  markedForReclaim: boolean;
}

export interface TimelineInfo {
  name: string;
  owner: string;
  headFrameId: string;
}

export interface WorldInfo {
  worldId: string;
  owner: string;
  baseFrameId: string;
  driver: DriverKind;
  state: WorldStateKind;
  labels: Record<string, string>;
  fencingToken: FencingToken;
  originEpoch: bigint;
  lostInEpoch: bigint;
  endedAtMs: bigint;
  endReason: string;
}

export interface BoundedOutput {
  head: Uint8Array;
  tail: Uint8Array;
  totalBytes: bigint;
  omittedBytes: bigint;
  truncated: boolean;
}

export interface PatchEntry {
  path: string;
  kind: string;
  sizeBytes: bigint;
}

export interface NegotiateVersionRequest {
  clientName?: string;
  clientVersion?: string;
  supportedApiMajor?: number;
}

export interface NegotiateVersionResponse {
  daemonVersion: string;
  apiMajor: number;
  apiMinor: number;
  daemonEpoch: bigint;
  enabledDrivers: string[];
}

export interface ImportTarOptions {
  owner: string;
  tarData: Uint8Array | AsyncIterable<Uint8Array> | Iterable<Uint8Array>;
  durability?: FrameDurability;
  parentFrameId?: string;
  labels?: Record<string, string>;
  pin?: PinSpec;
  timelineName?: string;
  expectedOldTimelineHead?: string;
  idempotencyKey?: IdempotencyKey;
  chunkSize?: number;
  timeoutMs?: number;
}

export interface ImportTarResponse {
  frame: FrameInfo;
  timeline?: TimelineInfo;
  bytesReceived: bigint;
}

export interface GetFrameResponse {
  frame: FrameInfo;
}

export interface ListFramesRequest {
  owner?: string;
  labelSelector?: Record<string, string>;
  includeNonCommitted?: boolean;
}

export interface ListFramesResponse {
  frames: FrameInfo[];
}

export interface PinFrameResponse {
  hold: HoldInfo;
}

export interface RenewPinResponse {
  expiresAtMs: bigint;
  persistedToDisk: boolean;
}

export interface DeleteFrameResponse {
  deleted: boolean;
  deferred: boolean;
  remainingHolds: number;
}

export interface AdvanceTimelineRequest {
  timeline: string;
  owner: string;
  newHeadFrameId: string;
  expectedOldFrameId?: string;
  idempotencyKey?: IdempotencyKey;
}

export interface AdvanceTimelineResponse {
  timeline: TimelineInfo;
  previousHeadFrameId: string;
}

export interface DeleteTimelineRequest {
  timeline: string;
  owner: string;
  idempotencyKey?: IdempotencyKey;
}

export interface DeleteTimelineResponse {
  releasedHeadFrameId: string;
}

export interface ExportPatchRequest {
  targetFrameId: string;
  owner: string;
  baseFrameId?: string;
}

export interface ExportPatchResponse {
  baseFrameId: string;
  targetFrameId: string;
  unifiedDiff: Uint8Array;
  entries: PatchEntry[];
  blake3Hex: string;
}

export interface CreateWorldRequest {
  owner: string;
  baseFrameId: string;
  driver?: DriverKind;
  labels?: Record<string, string>;
  leaseTtlMs?: Uint64Input;
  idempotencyKey?: IdempotencyKey;
}

export interface CreateWorldResponse {
  world: WorldInfo;
}

export interface GetWorldResponse {
  world: WorldInfo;
}

export interface DestroyWorldRequest {
  worldId: string;
  owner: string;
  fencingToken: FencingTokenInput;
  idempotencyKey?: IdempotencyKey;
}

export interface DestroyWorldResponse {
  world: WorldInfo;
}

export interface AcquireFenceResponse {
  fencingToken: FencingToken;
}

export interface RenewWorldLeaseRequest {
  worldId: string;
  owner: string;
  fencingToken: FencingTokenInput;
}

export interface RenewWorldLeaseResponse {
  renewedTtlMs: bigint;
}

export interface ExecRequest {
  worldId: string;
  owner: string;
  fencingToken: FencingTokenInput;
  argv: string[];
  env?: Record<string, string>;
  cwd?: string;
  timeoutMs?: Uint64Input;
  maxOutputBytes?: number;
  stream?: boolean;
  /**
   * Start the command in the background and run it until the World is destroyed. The result then
   * carries no exit code and no output, and `timeoutMs` must be unset or 0.
   */
  detached?: boolean;
  idempotencyKey?: IdempotencyKey;
}

export interface ExecOutputChunk {
  stream: OutputStreamKind;
  seq: bigint;
  data: Uint8Array;
}

export interface ExecResult {
  execId: string;
  hasExitCode: boolean;
  exitCode: number;
  hasSignal: boolean;
  signal: number;
  timedOut: boolean;
  cgroupKilled: boolean;
  durationMs: bigint;
  stdout: BoundedOutput;
  stderr: BoundedOutput;
  replayedFromCache: boolean;
}

export type ExecEvent =
  | { kind: "chunk"; chunk: ExecOutputChunk }
  | { kind: "result"; result: ExecResult };

export interface CheckpointRequest {
  worldId: string;
  owner: string;
  fencingToken: FencingTokenInput;
  durability?: FrameDurability;
  labels?: Record<string, string>;
  pin?: PinSpec;
  timelineName?: string;
  expectedOldTimelineHead?: string;
  performSyncfs?: boolean;
  idempotencyKey?: IdempotencyKey;
}

export interface CheckpointResponse {
  frame: FrameInfo;
  timeline?: TimelineInfo;
}

const URI_SCHEME_RE = /^[a-zA-Z][a-zA-Z0-9+.-]*:/;
const HOST_PORT_RE = /^(?:\[[^\]]+\]|[a-zA-Z0-9.-]+):\d+$/;

/**
 * Normalize a socket path or gRPC target into a gRPC channel target string.
 * Defaults to `$FORKLOOM_SOCKET` or `unix:///run/forkloom/agentd.sock`.
 */
export function normalizeTarget(target?: string): string {
  const raw = (target ?? process.env[SOCKET_ENV_VAR] ?? DEFAULT_SOCKET_PATH).trim();
  const value = raw.length > 0 ? raw : DEFAULT_SOCKET_PATH;

  if (value.startsWith("unix://") || value.startsWith("unix:")) {
    return value;
  }
  if (HOST_PORT_RE.test(value) || URI_SCHEME_RE.test(value)) {
    return value;
  }
  if (value.startsWith("/")) {
    return `unix://${value}`;
  }
  return `unix:${value}`;
}

export function idempotencyKey(owner: string, requestId?: string): IdempotencyKey {
  if (!owner) {
    throw new RangeError("owner must be non-empty");
  }
  const rid = requestId ?? randomUUID().replace(/-/g, "");
  if (!rid) {
    throw new RangeError("requestId must be non-empty");
  }
  return { owner, requestId: rid };
}

export function fencingToken(value: FencingTokenInput): FencingToken {
  const raw = typeof value === "object" && value !== null ? value.value : value;
  const bi = toBigInt(raw);
  if (bi <= 0n) {
    throw new RangeError("fencingToken must be a positive integer");
  }
  return { value: bi };
}

export function pinSpec(pinId: string, owner: string, leaseTtlMs: Uint64Input = 0): PinSpec {
  if (!pinId) {
    throw new RangeError("pinId must be non-empty");
  }
  if (!owner) {
    throw new RangeError("owner must be non-empty");
  }
  if (toBigInt(leaseTtlMs) < 0n) {
    throw new RangeError("leaseTtlMs must be >= 0");
  }
  return { pinId, owner, leaseTtlMs };
}

export function toBigInt(value: Uint64Input | undefined | null): bigint {
  if (value === undefined || value === null || value === "") {
    return 0n;
  }
  if (typeof value === "bigint") {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value) || !Number.isInteger(value)) {
      throw new RangeError(`Expected integer uint64 value, got ${value}`);
    }
    return BigInt(value);
  }
  return BigInt(value);
}

export function toUint64String(value: Uint64Input | undefined): string {
  return toBigInt(value).toString();
}

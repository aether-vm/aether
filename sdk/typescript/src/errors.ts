import * as grpc from "@grpc/grpc-js";
import { ErrorCode } from "./types.js";

/** Binary gRPC trailing metadata key carrying protobuf-encoded `forkloom.v1.ErrorDetail`. */
export const ERROR_DETAIL_BIN_KEY = "x-forkloom-error-bin";
/** ASCII gRPC trailing metadata key carrying the canonical `ErrorCode` enum name. */
export const ERROR_CODE_ASCII_KEY = "x-forkloom-error-code";

export interface ErrorDetail {
  code: ErrorCode;
  codeName: string;
  message: string;
  resourceId: string;
  currentFencingToken: bigint;
  presentedFencingToken: bigint;
  originEpoch: bigint;
  lostInEpoch: bigint;
}

const CODE_TO_NAME: Record<ErrorCode, string> = {
  [ErrorCode.UNSPECIFIED]: "ERROR_CODE_UNSPECIFIED",
  [ErrorCode.WORLD_LOST]: "ERROR_CODE_WORLD_LOST",
  [ErrorCode.OUTCOME_UNKNOWN]: "ERROR_CODE_OUTCOME_UNKNOWN",
  [ErrorCode.FENCED_OUT]: "ERROR_CODE_FENCED_OUT",
  [ErrorCode.FRAME_NOT_FOUND]: "ERROR_CODE_FRAME_NOT_FOUND",
  [ErrorCode.WORLD_NOT_FOUND]: "ERROR_CODE_WORLD_NOT_FOUND",
  [ErrorCode.TIMELINE_NOT_FOUND]: "ERROR_CODE_TIMELINE_NOT_FOUND",
  [ErrorCode.TIMELINE_CAS_MISMATCH]: "ERROR_CODE_TIMELINE_CAS_MISMATCH",
  [ErrorCode.IDEMPOTENCY_CONFLICT]: "ERROR_CODE_IDEMPOTENCY_CONFLICT",
  [ErrorCode.OWNER_MISMATCH]: "ERROR_CODE_OWNER_MISMATCH",
  [ErrorCode.RESOURCE_EXHAUSTED]: "ERROR_CODE_RESOURCE_EXHAUSTED",
  [ErrorCode.UNSAFE_PATCH]: "ERROR_CODE_UNSAFE_PATCH",
  [ErrorCode.DISK_NOT_CLEAN]: "ERROR_CODE_DISK_NOT_CLEAN",
  [ErrorCode.INVALID_ARGUMENT]: "ERROR_CODE_INVALID_ARGUMENT",
  [ErrorCode.DRIVER_UNAVAILABLE]: "ERROR_CODE_DRIVER_UNAVAILABLE",
  [ErrorCode.WORLD_NOT_RUNNING]: "ERROR_CODE_WORLD_NOT_RUNNING",
  [ErrorCode.VOLATILE_IN_TIMELINE_FORBIDDEN]: "ERROR_CODE_VOLATILE_IN_TIMELINE_FORBIDDEN",
  [ErrorCode.PIN_NOT_FOUND]: "ERROR_CODE_PIN_NOT_FOUND",
  [ErrorCode.FRAME_MARKED_FOR_DELETION]: "ERROR_CODE_FRAME_MARKED_FOR_DELETION",
  [ErrorCode.PREPARED_FRAME_ABORTED]: "ERROR_CODE_PREPARED_FRAME_ABORTED",
  [ErrorCode.INTERNAL]: "ERROR_CODE_INTERNAL",
};

const NAME_TO_CODE = new Map<string, ErrorCode>();
for (const [codeStr, name] of Object.entries(CODE_TO_NAME)) {
  const code = Number(codeStr) as ErrorCode;
  NAME_TO_CODE.set(name, code);
  NAME_TO_CODE.set(name.replace(/^ERROR_CODE_/, ""), code);
}

export function errorCodeName(code: ErrorCode | number): string {
  return CODE_TO_NAME[code as ErrorCode] ?? `ERROR_CODE_UNKNOWN(${code})`;
}

export function parseErrorCodeName(raw: string): ErrorCode {
  const normalized = raw.trim().toUpperCase();
  return NAME_TO_CODE.get(normalized) ?? ErrorCode.UNSPECIFIED;
}

// ============================================================================
// Pure proto3 wire codec for `forkloom.v1.ErrorDetail` (zero native deps)
// ============================================================================

const textDecoder = new TextDecoder("utf-8", { fatal: false });
const textEncoder = new TextEncoder();

function readVarint(buf: Uint8Array, offset: number): [bigint, number] {
  let result = 0n;
  let shift = 0n;
  let pos = offset;
  while (pos < buf.length) {
    const byte = buf[pos]!;
    pos += 1;
    result |= BigInt(byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) {
      return [result, pos];
    }
    shift += 7n;
    if (shift > 70n) {
      throw new Error("Malformed protobuf varint in ErrorDetail");
    }
  }
  throw new Error("Truncated protobuf varint in ErrorDetail");
}

function writeVarint(out: number[], value: bigint): void {
  let v = BigInt.asUintN(64, value);
  while (v >= 0x80n) {
    out.push(Number((v & 0x7fn) | 0x80n));
    v >>= 7n;
  }
  out.push(Number(v));
}

function writeTag(out: number[], fieldNumber: number, wireType: number): void {
  writeVarint(out, BigInt((fieldNumber << 3) | wireType));
}

function writeStringField(out: number[], fieldNumber: number, value: string): void {
  if (value.length === 0) return;
  const encoded = textEncoder.encode(value);
  writeTag(out, fieldNumber, 2);
  writeVarint(out, BigInt(encoded.length));
  for (let i = 0; i < encoded.length; i += 1) {
    out.push(encoded[i]!);
  }
}

/** Encode a `forkloom.v1.ErrorDetail` payload to standard proto3 wire bytes. */
export function encodeErrorDetail(detail: Partial<ErrorDetail>): Buffer {
  const out: number[] = [];
  if (detail.code !== undefined && detail.code !== ErrorCode.UNSPECIFIED) {
    writeTag(out, 1, 0);
    writeVarint(out, BigInt(detail.code));
  }
  if (detail.message) {
    writeStringField(out, 2, detail.message);
  }
  if (detail.resourceId) {
    writeStringField(out, 3, detail.resourceId);
  }
  if (detail.currentFencingToken && detail.currentFencingToken !== 0n) {
    writeTag(out, 4, 0);
    writeVarint(out, detail.currentFencingToken);
  }
  if (detail.presentedFencingToken && detail.presentedFencingToken !== 0n) {
    writeTag(out, 5, 0);
    writeVarint(out, detail.presentedFencingToken);
  }
  if (detail.originEpoch && detail.originEpoch !== 0n) {
    writeTag(out, 6, 0);
    writeVarint(out, detail.originEpoch);
  }
  if (detail.lostInEpoch && detail.lostInEpoch !== 0n) {
    writeTag(out, 7, 0);
    writeVarint(out, detail.lostInEpoch);
  }
  return Buffer.from(out);
}

/** Decode protobuf-encoded `forkloom.v1.ErrorDetail` from `x-forkloom-error-bin`. */
export function decodeErrorDetail(raw: Uint8Array): ErrorDetail {
  let code: ErrorCode = ErrorCode.UNSPECIFIED;
  let message = "";
  let resourceId = "";
  let currentFencingToken = 0n;
  let presentedFencingToken = 0n;
  let originEpoch = 0n;
  let lostInEpoch = 0n;

  let pos = 0;
  while (pos < raw.length) {
    const [tag, afterTag] = readVarint(raw, pos);
    pos = afterTag;
    const fieldNumber = Number(tag >> 3n);
    const wireType = Number(tag & 0x7n);

    if (wireType === 0) {
      const [val, next] = readVarint(raw, pos);
      pos = next;
      switch (fieldNumber) {
        case 1:
          code = Number(val) as ErrorCode;
          break;
        case 4:
          currentFencingToken = val;
          break;
        case 5:
          presentedFencingToken = val;
          break;
        case 6:
          originEpoch = val;
          break;
        case 7:
          lostInEpoch = val;
          break;
        default:
          break;
      }
    } else if (wireType === 2) {
      const [lenBig, afterLen] = readVarint(raw, pos);
      const len = Number(lenBig);
      if (afterLen + len > raw.length) {
        throw new Error("Truncated length-delimited field in ErrorDetail");
      }
      const slice = raw.subarray(afterLen, afterLen + len);
      pos = afterLen + len;
      if (fieldNumber === 2) {
        message = textDecoder.decode(slice);
      } else if (fieldNumber === 3) {
        resourceId = textDecoder.decode(slice);
      }
    } else if (wireType === 1) {
      if (pos + 8 > raw.length) {
        throw new Error("Truncated 64-bit field in ErrorDetail");
      }
      pos += 8;
    } else if (wireType === 5) {
      if (pos + 4 > raw.length) {
        throw new Error("Truncated 32-bit field in ErrorDetail");
      }
      pos += 4;
    } else {
      throw new Error(`Unsupported protobuf wire type ${wireType} in ErrorDetail`);
    }
  }

  return {
    code,
    codeName: errorCodeName(code),
    message,
    resourceId,
    currentFencingToken,
    presentedFencingToken,
    originEpoch,
    lostInEpoch,
  };
}

// ============================================================================
// Structured Error Hierarchy
// ============================================================================

export interface ForkloomErrorInit {
  errorCode?: ErrorCode;
  grpcCode?: grpc.status;
  detail?: ErrorDetail;
  cause?: unknown;
}

export class ForkloomError extends Error {
  readonly errorCode: ErrorCode;
  readonly grpcCode?: grpc.status;
  readonly detail?: ErrorDetail;

  constructor(message: string, init: ForkloomErrorInit = {}) {
    super(message, init.cause !== undefined ? { cause: init.cause } : undefined);
    this.name = new.target.name;
    this.errorCode = init.errorCode ?? ErrorCode.UNSPECIFIED;
    this.grpcCode = init.grpcCode;
    this.detail = init.detail;
  }

  get resourceId(): string {
    return this.detail?.resourceId ?? "";
  }

  get currentFencingToken(): bigint {
    return this.detail?.currentFencingToken ?? 0n;
  }

  get presentedFencingToken(): bigint {
    return this.detail?.presentedFencingToken ?? 0n;
  }

  get originEpoch(): bigint {
    return this.detail?.originEpoch ?? 0n;
  }

  get lostInEpoch(): bigint {
    return this.detail?.lostInEpoch ?? 0n;
  }
}

export class VersionSkewError extends ForkloomError {
  readonly daemonApiMajor?: number;
  readonly supportedApiMajor: number;
  readonly daemonVersion: string;

  constructor(
    message: string,
    init: ForkloomErrorInit & {
      daemonApiMajor?: number;
      supportedApiMajor?: number;
      daemonVersion?: string;
    } = {},
  ) {
    super(message, { ...init, errorCode: ErrorCode.INVALID_ARGUMENT });
    this.daemonApiMajor = init.daemonApiMajor;
    this.supportedApiMajor = init.supportedApiMajor ?? 1;
    this.daemonVersion = init.daemonVersion ?? "";
  }
}

export class NotNegotiatedError extends ForkloomError {}
export class WorldLostError extends ForkloomError {}
export class OutcomeUnknownError extends ForkloomError {}
export class FencedOutError extends ForkloomError {}
export class FrameNotFoundError extends ForkloomError {}
export class WorldNotFoundError extends ForkloomError {}
export class TimelineNotFoundError extends ForkloomError {}
export class TimelineCasMismatchError extends ForkloomError {}
export class IdempotencyConflictError extends ForkloomError {}
export class OwnerMismatchError extends ForkloomError {}
export class ResourceExhaustedError extends ForkloomError {}
export class UnsafePatchError extends ForkloomError {}
export class DiskNotCleanError extends ForkloomError {}
export class InvalidArgumentError extends ForkloomError {}
export class DriverUnavailableError extends ForkloomError {}
export class WorldNotRunningError extends ForkloomError {}
export class VolatileInTimelineForbiddenError extends ForkloomError {}
export class PinNotFoundError extends ForkloomError {}
export class FrameMarkedForDeletionError extends ForkloomError {}
export class PreparedFrameAbortedError extends ForkloomError {}
export class InternalError extends ForkloomError {}

type ErrorCtor = new (message: string, init?: ForkloomErrorInit) => ForkloomError;

export const ERROR_CODE_CLASSES: Partial<Record<ErrorCode, ErrorCtor>> = {
  [ErrorCode.WORLD_LOST]: WorldLostError,
  [ErrorCode.OUTCOME_UNKNOWN]: OutcomeUnknownError,
  [ErrorCode.FENCED_OUT]: FencedOutError,
  [ErrorCode.FRAME_NOT_FOUND]: FrameNotFoundError,
  [ErrorCode.WORLD_NOT_FOUND]: WorldNotFoundError,
  [ErrorCode.TIMELINE_NOT_FOUND]: TimelineNotFoundError,
  [ErrorCode.TIMELINE_CAS_MISMATCH]: TimelineCasMismatchError,
  [ErrorCode.IDEMPOTENCY_CONFLICT]: IdempotencyConflictError,
  [ErrorCode.OWNER_MISMATCH]: OwnerMismatchError,
  [ErrorCode.RESOURCE_EXHAUSTED]: ResourceExhaustedError,
  [ErrorCode.UNSAFE_PATCH]: UnsafePatchError,
  [ErrorCode.DISK_NOT_CLEAN]: DiskNotCleanError,
  [ErrorCode.INVALID_ARGUMENT]: InvalidArgumentError,
  [ErrorCode.DRIVER_UNAVAILABLE]: DriverUnavailableError,
  [ErrorCode.WORLD_NOT_RUNNING]: WorldNotRunningError,
  [ErrorCode.VOLATILE_IN_TIMELINE_FORBIDDEN]: VolatileInTimelineForbiddenError,
  [ErrorCode.PIN_NOT_FOUND]: PinNotFoundError,
  [ErrorCode.FRAME_MARKED_FOR_DELETION]: FrameMarkedForDeletionError,
  [ErrorCode.PREPARED_FRAME_ABORTED]: PreparedFrameAbortedError,
  [ErrorCode.INTERNAL]: InternalError,
};

/**
 * Decode a `@grpc/grpc-js` `ServiceError` carrying `x-forkloom-error-bin` /
 * `x-forkloom-error-code` metadata into the matching `ForkloomError` subclass.
 */
export function fromGrpcError(err: unknown): ForkloomError {
  if (err instanceof ForkloomError) {
    return err;
  }
  const svc = err as Partial<grpc.ServiceError>;
  const grpcCode = typeof svc.code === "number" ? svc.code : undefined;
  const fallbackMessage =
    typeof svc.details === "string" && svc.details.length > 0
      ? svc.details
      : err instanceof Error
        ? err.message
        : String(err);

  let detail: ErrorDetail | undefined;
  let code: ErrorCode = ErrorCode.UNSPECIFIED;

  const md = svc.metadata;
  if (md instanceof grpc.Metadata) {
    const binValues = md.get(ERROR_DETAIL_BIN_KEY);
    if (binValues.length > 0) {
      const first = binValues[0];
      const bytes =
        first instanceof Uint8Array
          ? first
          : typeof first === "string"
            ? Buffer.from(first, "base64")
            : undefined;
      if (bytes) {
        try {
          detail = decodeErrorDetail(bytes);
          code = detail.code;
        } catch {
          detail = undefined;
        }
      }
    }

    if (code === ErrorCode.UNSPECIFIED) {
      const asciiValues = md.get(ERROR_CODE_ASCII_KEY);
      if (asciiValues.length > 0) {
        const first = asciiValues[0];
        const rawCode =
          typeof first === "string"
            ? first
            : first instanceof Uint8Array
              ? Buffer.from(first).toString("utf8")
              : "";
        code = parseErrorCodeName(rawCode);
        if (!detail && code !== ErrorCode.UNSPECIFIED) {
          detail = {
            code,
            codeName: errorCodeName(code),
            message: fallbackMessage,
            resourceId: "",
            currentFencingToken: 0n,
            presentedFencingToken: 0n,
            originEpoch: 0n,
            lostInEpoch: 0n,
          };
        }
      }
    }
  }

  const message = detail && detail.message.length > 0 ? detail.message : fallbackMessage;
  const Ctor = ERROR_CODE_CLASSES[code] ?? ForkloomError;
  return new Ctor(message, {
    errorCode: code,
    grpcCode,
    detail,
    cause: err,
  });
}

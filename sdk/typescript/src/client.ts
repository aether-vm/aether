import * as grpc from "@grpc/grpc-js";
import { loadForkloomPackage } from "./proto.js";
import {
  ForkloomError,
  NotNegotiatedError,
  VersionSkewError,
  fromGrpcError,
} from "./errors.js";
import {
  AcquireFenceResponse,
  AdvanceTimelineRequest,
  AdvanceTimelineResponse,
  BoundedOutput,
  CLIENT_VERSION,
  CheckpointRequest,
  CheckpointResponse,
  CreateWorldRequest,
  CreateWorldResponse,
  DEFAULT_CLIENT_NAME,
  DeleteFrameResponse,
  DeleteTimelineRequest,
  DeleteTimelineResponse,
  DestroyWorldRequest,
  DestroyWorldResponse,
  DriverKind,
  ExecEvent,
  ExecOutputChunk,
  ExecRequest,
  ExecResult,
  ExportPatchRequest,
  ExportPatchResponse,
  FrameDurability,
  FrameInfo,
  FrameStateKind,
  GetFrameResponse,
  GetWorldResponse,
  HoldInfo,
  IdempotencyKey,
  ImportTarOptions,
  ImportTarResponse,
  ListFramesRequest,
  ListFramesResponse,
  NegotiateVersionRequest,
  NegotiateVersionResponse,
  OutputStreamKind,
  PatchEntry,
  PinFrameResponse,
  PinSpec,
  RenewPinResponse,
  RenewWorldLeaseRequest,
  RenewWorldLeaseResponse,
  SUPPORTED_API_MAJOR,
  TimelineInfo,
  WorldInfo,
  WorldStateKind,
  fencingToken,
  normalizeTarget,
  toBigInt,
  toUint64String,
} from "./types.js";

export const DEFAULT_IMPORT_CHUNK_SIZE = 64 * 1024;

export interface ForkloomClientOptions {
  /** Unix Domain Socket path or gRPC target URI. Defaults to `$FORKLOOM_SOCKET` or `unix:///run/forkloom/agentd.sock`. */
  target?: string;
  clientName?: string;
  clientVersion?: string;
  /** Default per-RPC timeout in milliseconds. */
  timeoutMs?: number;
  /** Automatically execute `NegotiateVersion` before the first stateful RPC. Defaults to `true`. */
  autoNegotiate?: boolean;
  channelOptions?: grpc.ChannelOptions;
}

export interface CallOptions {
  timeoutMs?: number;
}

// ============================================================================
// Wire <-> Typed DTO mappers
// ============================================================================

/* eslint-disable @typescript-eslint/no-explicit-any */
function mapHold(raw: any): HoldInfo {
  return {
    kind: raw?.kind ?? "",
    detail: raw?.detail ?? "",
    expiresAtMs: toBigInt(raw?.expiresAtMs),
  };
}

function mapFrame(raw: any): FrameInfo {
  return {
    frameId: raw?.frameId ?? "",
    owner: raw?.owner ?? "",
    durability: (raw?.durability ?? FrameDurability.UNSPECIFIED) as FrameDurability,
    state: (raw?.state ?? FrameStateKind.UNSPECIFIED) as FrameStateKind,
    parentFrameId: raw?.parentFrameId ?? "",
    labels: raw?.labels ? { ...raw.labels } : {},
    diskClean: Boolean(raw?.diskClean),
    createdEpoch: toBigInt(raw?.createdEpoch),
    committedAtMs: toBigInt(raw?.committedAtMs),
    objects: Array.isArray(raw?.objects) ? [...raw.objects] : [],
    holds: Array.isArray(raw?.holds) ? raw.holds.map(mapHold) : [],
    markedForReclaim: Boolean(raw?.markedForReclaim),
  };
}

function mapTimeline(raw: any): TimelineInfo | undefined {
  if (!raw || !raw.name) {
    return undefined;
  }
  return {
    name: raw.name,
    owner: raw.owner ?? "",
    headFrameId: raw.headFrameId ?? "",
  };
}

function mapWorld(raw: any): WorldInfo {
  return {
    worldId: raw?.worldId ?? "",
    owner: raw?.owner ?? "",
    baseFrameId: raw?.baseFrameId ?? "",
    driver: (raw?.driver ?? DriverKind.UNSPECIFIED) as DriverKind,
    state: (raw?.state ?? WorldStateKind.UNSPECIFIED) as WorldStateKind,
    labels: raw?.labels ? { ...raw.labels } : {},
    fencingToken: { value: toBigInt(raw?.fencingToken?.value) },
    originEpoch: toBigInt(raw?.originEpoch),
    lostInEpoch: toBigInt(raw?.lostInEpoch),
    endedAtMs: toBigInt(raw?.endedAtMs),
    endReason: raw?.endReason ?? "",
  };
}

function mapBoundedOutput(raw: any): BoundedOutput {
  return {
    head: raw?.head ? Buffer.from(raw.head) : Buffer.alloc(0),
    tail: raw?.tail ? Buffer.from(raw.tail) : Buffer.alloc(0),
    totalBytes: toBigInt(raw?.totalBytes),
    omittedBytes: toBigInt(raw?.omittedBytes),
    truncated: Boolean(raw?.truncated),
  };
}

function mapPatchEntry(raw: any): PatchEntry {
  return {
    path: raw?.path ?? "",
    kind: raw?.kind ?? "",
    sizeBytes: toBigInt(raw?.sizeBytes),
  };
}

function mapExecChunk(raw: any): ExecOutputChunk {
  return {
    stream: (raw?.stream ?? OutputStreamKind.UNSPECIFIED) as OutputStreamKind,
    seq: toBigInt(raw?.seq),
    data: raw?.data ? Buffer.from(raw.data) : Buffer.alloc(0),
  };
}

function mapExecResult(raw: any): ExecResult {
  return {
    execId: raw?.execId ?? "",
    hasExitCode: Boolean(raw?.hasExitCode),
    exitCode: Number(raw?.exitCode ?? 0),
    hasSignal: Boolean(raw?.hasSignal),
    signal: Number(raw?.signal ?? 0),
    timedOut: Boolean(raw?.timedOut),
    cgroupKilled: Boolean(raw?.cgroupKilled),
    durationMs: toBigInt(raw?.durationMs),
    stdout: mapBoundedOutput(raw?.stdout),
    stderr: mapBoundedOutput(raw?.stderr),
    replayedFromCache: Boolean(raw?.replayedFromCache),
  };
}

function encodePin(pin?: PinSpec): Record<string, unknown> | undefined {
  if (!pin) return undefined;
  return {
    pinId: pin.pinId,
    owner: pin.owner,
    leaseTtlMs: toUint64String(pin.leaseTtlMs),
  };
}

function encodeIdem(idem?: IdempotencyKey): Record<string, unknown> | undefined {
  if (!idem) return undefined;
  return {
    owner: idem.owner,
    requestId: idem.requestId,
  };
}

async function* iterateChunks(
  tarData: Uint8Array | AsyncIterable<Uint8Array> | Iterable<Uint8Array>,
  chunkSize: number,
): AsyncIterable<Buffer> {
  if (chunkSize <= 0) {
    throw new RangeError("chunkSize must be > 0");
  }
  if (tarData instanceof Uint8Array) {
    for (let offset = 0; offset < tarData.byteLength; offset += chunkSize) {
      yield Buffer.from(
        tarData.subarray(offset, Math.min(offset + chunkSize, tarData.byteLength)),
      );
    }
    return;
  }
  const source: AsyncIterable<Uint8Array> | Iterable<Uint8Array> = tarData;
  for await (const chunk of source) {
    if (chunk.byteLength === 0) continue;
    if (chunk.byteLength <= chunkSize) {
      yield Buffer.from(chunk);
    } else {
      for (let offset = 0; offset < chunk.byteLength; offset += chunkSize) {
        yield Buffer.from(
          chunk.subarray(offset, Math.min(offset + chunkSize, chunk.byteLength)),
        );
      }
    }
  }
}

/**
 * Thin gRPC client for `agentd`'s `forkloom.v1` services over Unix Domain Socket.
 */
export class ForkloomClient {
  readonly target: string;
  readonly clientName: string;
  readonly clientVersion: string;
  readonly defaultTimeoutMs?: number;

  private readonly autoNegotiate: boolean;
  private readonly systemClient: grpc.Client & Record<string, any>;
  private readonly frameClient: grpc.Client & Record<string, any>;
  private readonly worldClient: grpc.Client & Record<string, any>;
  private negotiatedInfo?: NegotiateVersionResponse;
  private negotiatingPromise?: Promise<NegotiateVersionResponse>;

  constructor(options: ForkloomClientOptions = {}) {
    this.target = normalizeTarget(options.target);
    this.clientName = options.clientName ?? DEFAULT_CLIENT_NAME;
    this.clientVersion = options.clientVersion ?? CLIENT_VERSION;
    this.defaultTimeoutMs = options.timeoutMs;
    this.autoNegotiate = options.autoNegotiate ?? true;

    const pkg = loadForkloomPackage();
    const creds = grpc.credentials.createInsecure();
    const channelOpts = options.channelOptions;

    this.systemClient = new pkg.forkloom.v1.SystemService(
      this.target,
      creds,
      channelOpts,
    ) as unknown as grpc.Client & Record<string, any>;
    this.frameClient = new pkg.forkloom.v1.FrameService(
      this.target,
      creds,
      channelOpts,
    ) as unknown as grpc.Client & Record<string, any>;
    this.worldClient = new pkg.forkloom.v1.WorldService(
      this.target,
      creds,
      channelOpts,
    ) as unknown as grpc.Client & Record<string, any>;
  }

  /** Create a client and immediately execute the mandatory `NegotiateVersion` handshake. */
  static async connect(options: ForkloomClientOptions = {}): Promise<ForkloomClient> {
    const client = new ForkloomClient(options);
    try {
      await client.negotiateVersion(undefined, { timeoutMs: options.timeoutMs });
      return client;
    } catch (err) {
      client.close();
      throw err;
    }
  }

  /** Cached `NegotiateVersionResponse` from the last successful handshake. */
  get serverInfo(): NegotiateVersionResponse | undefined {
    return this.negotiatedInfo;
  }

  /** Close underlying gRPC client channels. */
  close(): void {
    this.systemClient.close();
    this.frameClient.close();
    this.worldClient.close();
  }

  [Symbol.dispose](): void {
    this.close();
  }

  private grpcCallOptions(opts?: CallOptions): grpc.CallOptions {
    const timeoutMs = opts?.timeoutMs ?? this.defaultTimeoutMs;
    if (timeoutMs !== undefined) {
      return { deadline: new Date(Date.now() + timeoutMs) };
    }
    return {};
  }

  private unary<TResp>(
    client: grpc.Client & Record<string, any>,
    method: string,
    request: Record<string, unknown>,
    opts?: CallOptions,
  ): Promise<TResp> {
    return new Promise<TResp>((resolve, reject) => {
      client[method](
        request,
        this.grpcCallOptions(opts),
        (err: grpc.ServiceError | null, response: TResp) => {
          if (err) {
            reject(fromGrpcError(err));
          } else {
            resolve(response);
          }
        },
      );
    });
  }

  private async ensureNegotiated(opts?: CallOptions): Promise<void> {
    if (this.negotiatedInfo) {
      return;
    }
    if (!this.autoNegotiate) {
      throw new NotNegotiatedError(
        "negotiateVersion() must succeed before issuing stateful Forkloom RPCs",
      );
    }
    if (!this.negotiatingPromise) {
      this.negotiatingPromise = this.negotiateVersion(undefined, opts).finally(() => {
        this.negotiatingPromise = undefined;
      });
    }
    await this.negotiatingPromise;
  }

  // ==========================================================================
  // SystemService (1 RPC)
  // ==========================================================================

  async negotiateVersion(
    req: NegotiateVersionRequest = {},
    opts?: CallOptions,
  ): Promise<NegotiateVersionResponse> {
    const supportedApiMajor = req.supportedApiMajor ?? SUPPORTED_API_MAJOR;
    let raw: any;
    try {
      raw = await this.unary<any>(
        this.systemClient,
        "NegotiateVersion",
        {
          clientName: req.clientName ?? this.clientName,
          clientVersion: req.clientVersion ?? this.clientVersion,
          supportedApiMajor,
        },
        opts,
      );
    } catch (err) {
      const fErr = fromGrpcError(err);
      if (
        fErr.grpcCode === grpc.status.FAILED_PRECONDITION &&
        (fErr.message.toLowerCase().includes("api_major") ||
          fErr.message.toLowerCase().includes("version"))
      ) {
        throw new VersionSkewError(fErr.message, {
          supportedApiMajor,
          grpcCode: fErr.grpcCode,
          detail: fErr.detail,
          cause: err,
        });
      }
      throw fErr;
    }

    const resp: NegotiateVersionResponse = {
      daemonVersion: raw?.daemonVersion ?? "",
      apiMajor: Number(raw?.apiMajor ?? 0),
      apiMinor: Number(raw?.apiMinor ?? 0),
      daemonEpoch: toBigInt(raw?.daemonEpoch),
      enabledDrivers: Array.isArray(raw?.enabledDrivers) ? [...raw.enabledDrivers] : [],
    };

    if (resp.apiMajor !== SUPPORTED_API_MAJOR) {
      throw new VersionSkewError(
        `Incompatible Forkloom daemon API major version: daemon serves v${resp.apiMajor}.${resp.apiMinor} (daemonVersion=${JSON.stringify(resp.daemonVersion)}), client requires api_major == ${SUPPORTED_API_MAJOR}`,
        {
          daemonApiMajor: resp.apiMajor,
          supportedApiMajor: SUPPORTED_API_MAJOR,
          daemonVersion: resp.daemonVersion,
        },
      );
    }

    this.negotiatedInfo = resp;
    return resp;
  }

  // ==========================================================================
  // FrameService (9 RPCs)
  // ==========================================================================

  async importTar(options: ImportTarOptions): Promise<ImportTarResponse> {
    const callOpts: CallOptions = { timeoutMs: options.timeoutMs };
    await this.ensureNegotiated(callOpts);

    const chunkSize = options.chunkSize ?? DEFAULT_IMPORT_CHUNK_SIZE;
    const header = {
      owner: options.owner,
      durability: options.durability ?? FrameDurability.DURABLE,
      parentFrameId: options.parentFrameId ?? "",
      labels: options.labels ?? {},
      pin: encodePin(options.pin),
      timelineName: options.timelineName ?? "",
      expectedOldTimelineHead: options.expectedOldTimelineHead ?? "",
      idempotencyKey: encodeIdem(options.idempotencyKey),
    };

    return new Promise<ImportTarResponse>((resolve, reject) => {
      const stream: grpc.ClientWritableStream<any> = this.frameClient.ImportTar(
        this.grpcCallOptions(callOpts),
        (err: grpc.ServiceError | null, raw: any) => {
          if (err) {
            reject(fromGrpcError(err));
          } else {
            resolve({
              frame: mapFrame(raw?.frame),
              timeline: mapTimeline(raw?.timeline),
              bytesReceived: toBigInt(raw?.bytesReceived),
            });
          }
        },
      );

      (async () => {
        try {
          stream.write({ header });
          for await (const chunk of iterateChunks(options.tarData, chunkSize)) {
            if (!stream.write({ data: chunk })) {
              await new Promise<void>((res) => stream.once("drain", res));
            }
          }
          stream.end();
        } catch (err) {
          stream.cancel();
          reject(err);
        }
      })();
    });
  }

  async getFrame(frameId: string, opts?: CallOptions): Promise<GetFrameResponse> {
    await this.ensureNegotiated(opts);
    const raw = await this.unary<any>(this.frameClient, "GetFrame", { frameId }, opts);
    return { frame: mapFrame(raw?.frame) };
  }

  async listFrames(
    req: ListFramesRequest = {},
    opts?: CallOptions,
  ): Promise<ListFramesResponse> {
    await this.ensureNegotiated(opts);
    const raw = await this.unary<any>(
      this.frameClient,
      "ListFrames",
      {
        owner: req.owner ?? "",
        labelSelector: req.labelSelector ?? {},
        includeNonCommitted: Boolean(req.includeNonCommitted),
      },
      opts,
    );
    return {
      frames: Array.isArray(raw?.frames) ? raw.frames.map(mapFrame) : [],
    };
  }

  async pinFrame(
    frameId: string,
    pin: PinSpec,
    opts?: CallOptions,
  ): Promise<PinFrameResponse> {
    await this.ensureNegotiated(opts);
    const raw = await this.unary<any>(
      this.frameClient,
      "PinFrame",
      { frameId, pin: encodePin(pin) },
      opts,
    );
    return { hold: mapHold(raw?.hold) };
  }

  async renewPin(
    frameId: string,
    pinId: string,
    owner: string,
    opts?: CallOptions,
  ): Promise<RenewPinResponse> {
    await this.ensureNegotiated(opts);
    const raw = await this.unary<any>(
      this.frameClient,
      "RenewPin",
      { frameId, pinId, owner },
      opts,
    );
    return {
      expiresAtMs: toBigInt(raw?.expiresAtMs),
      persistedToDisk: Boolean(raw?.persistedToDisk),
    };
  }

  async deleteFrame(
    frameId: string,
    owner: string,
    idempotencyKey?: IdempotencyKey,
    opts?: CallOptions,
  ): Promise<DeleteFrameResponse> {
    await this.ensureNegotiated(opts);
    const raw = await this.unary<any>(
      this.frameClient,
      "DeleteFrame",
      { frameId, owner, idempotencyKey: encodeIdem(idempotencyKey) },
      opts,
    );
    return {
      deleted: Boolean(raw?.deleted),
      deferred: Boolean(raw?.deferred),
      remainingHolds: Number(raw?.remainingHolds ?? 0),
    };
  }

  async advanceTimeline(
    req: AdvanceTimelineRequest,
    opts?: CallOptions,
  ): Promise<AdvanceTimelineResponse> {
    await this.ensureNegotiated(opts);
    const raw = await this.unary<any>(
      this.frameClient,
      "AdvanceTimeline",
      {
        timeline: req.timeline,
        owner: req.owner,
        expectedOldFrameId: req.expectedOldFrameId ?? "",
        newHeadFrameId: req.newHeadFrameId,
        idempotencyKey: encodeIdem(req.idempotencyKey),
      },
      opts,
    );
    return {
      timeline: mapTimeline(raw?.timeline) ?? {
        name: req.timeline,
        owner: req.owner,
        headFrameId: req.newHeadFrameId,
      },
      previousHeadFrameId: raw?.previousHeadFrameId ?? "",
    };
  }

  async deleteTimeline(
    req: DeleteTimelineRequest,
    opts?: CallOptions,
  ): Promise<DeleteTimelineResponse> {
    await this.ensureNegotiated(opts);
    const raw = await this.unary<any>(
      this.frameClient,
      "DeleteTimeline",
      {
        timeline: req.timeline,
        owner: req.owner,
        idempotencyKey: encodeIdem(req.idempotencyKey),
      },
      opts,
    );
    return {
      releasedHeadFrameId: raw?.releasedHeadFrameId ?? "",
    };
  }

  async exportPatch(
    req: ExportPatchRequest,
    opts?: CallOptions,
  ): Promise<ExportPatchResponse> {
    await this.ensureNegotiated(opts);
    const raw = await this.unary<any>(
      this.frameClient,
      "ExportPatch",
      {
        targetFrameId: req.targetFrameId,
        baseFrameId: req.baseFrameId ?? "",
        owner: req.owner,
      },
      opts,
    );
    return {
      baseFrameId: raw?.baseFrameId ?? "",
      targetFrameId: raw?.targetFrameId ?? "",
      unifiedDiff: raw?.unifiedDiff ? Buffer.from(raw.unifiedDiff) : Buffer.alloc(0),
      entries: Array.isArray(raw?.entries) ? raw.entries.map(mapPatchEntry) : [],
      blake3Hex: raw?.blake3Hex ?? "",
    };
  }

  // ==========================================================================
  // WorldService (7 RPCs)
  // ==========================================================================

  async createWorld(
    req: CreateWorldRequest,
    opts?: CallOptions,
  ): Promise<CreateWorldResponse> {
    await this.ensureNegotiated(opts);
    const raw = await this.unary<any>(
      this.worldClient,
      "CreateWorld",
      {
        owner: req.owner,
        baseFrameId: req.baseFrameId,
        driver: req.driver ?? DriverKind.NAMESPACE,
        labels: req.labels ?? {},
        leaseTtlMs: toUint64String(req.leaseTtlMs),
        idempotencyKey: encodeIdem(req.idempotencyKey),
      },
      opts,
    );
    return { world: mapWorld(raw?.world) };
  }

  async getWorld(worldId: string, opts?: CallOptions): Promise<GetWorldResponse> {
    await this.ensureNegotiated(opts);
    const raw = await this.unary<any>(this.worldClient, "GetWorld", { worldId }, opts);
    return { world: mapWorld(raw?.world) };
  }

  async destroyWorld(
    req: DestroyWorldRequest,
    opts?: CallOptions,
  ): Promise<DestroyWorldResponse> {
    await this.ensureNegotiated(opts);
    const tok = fencingToken(req.fencingToken);
    const raw = await this.unary<any>(
      this.worldClient,
      "DestroyWorld",
      {
        worldId: req.worldId,
        owner: req.owner,
        fencingToken: { value: tok.value.toString() },
        idempotencyKey: encodeIdem(req.idempotencyKey),
      },
      opts,
    );
    return { world: mapWorld(raw?.world) };
  }

  async acquireFence(
    worldId: string,
    owner: string,
    opts?: CallOptions,
  ): Promise<AcquireFenceResponse> {
    await this.ensureNegotiated(opts);
    const raw = await this.unary<any>(
      this.worldClient,
      "AcquireFence",
      { worldId, owner },
      opts,
    );
    return {
      fencingToken: { value: toBigInt(raw?.fencingToken?.value) },
    };
  }

  async renewWorldLease(
    req: RenewWorldLeaseRequest,
    opts?: CallOptions,
  ): Promise<RenewWorldLeaseResponse> {
    await this.ensureNegotiated(opts);
    const tok = fencingToken(req.fencingToken);
    const raw = await this.unary<any>(
      this.worldClient,
      "RenewWorldLease",
      {
        worldId: req.worldId,
        owner: req.owner,
        fencingToken: { value: tok.value.toString() },
      },
      opts,
    );
    return {
      renewedTtlMs: toBigInt(raw?.renewedTtlMs),
    };
  }

  /** Execute a command in a World and stream `ExecEvent`s (`WorldService.Exec`). */
  async *exec(req: ExecRequest, opts?: CallOptions): AsyncIterable<ExecEvent> {
    await this.ensureNegotiated(opts);
    const tok = fencingToken(req.fencingToken);
    const stream: grpc.ClientReadableStream<any> = this.worldClient.Exec(
      {
        worldId: req.worldId,
        owner: req.owner,
        fencingToken: { value: tok.value.toString() },
        argv: req.argv,
        env: req.env ?? {},
        cwd: req.cwd ?? "",
        timeoutMs: toUint64String(req.timeoutMs),
        maxOutputBytes: req.maxOutputBytes ?? 0,
        stream: req.stream ?? true,
        idempotencyKey: encodeIdem(req.idempotencyKey),
      },
      this.grpcCallOptions(opts),
    );

    try {
      for await (const raw of stream) {
        if (raw?.event === "chunk" || raw?.chunk) {
          yield { kind: "chunk", chunk: mapExecChunk(raw.chunk) };
        } else if (raw?.event === "result" || raw?.result) {
          yield { kind: "result", result: mapExecResult(raw.result) };
        }
      }
    } catch (err) {
      throw fromGrpcError(err);
    }
  }

  /** Consume an `Exec` stream, optionally invoking `onChunk`, and return the terminal `ExecResult`. */
  async execCollect(
    req: ExecRequest,
    onChunk?: (chunk: ExecOutputChunk) => void,
    opts?: CallOptions,
  ): Promise<ExecResult> {
    let terminal: ExecResult | undefined;
    for await (const ev of this.exec(req, opts)) {
      if (ev.kind === "chunk") {
        onChunk?.(ev.chunk);
      } else {
        terminal = ev.result;
      }
    }
    if (!terminal) {
      throw new ForkloomError("Exec stream terminated without a terminal ExecResult");
    }
    return terminal;
  }

  async checkpoint(
    req: CheckpointRequest,
    opts?: CallOptions,
  ): Promise<CheckpointResponse> {
    await this.ensureNegotiated(opts);
    const tok = fencingToken(req.fencingToken);
    const raw = await this.unary<any>(
      this.worldClient,
      "Checkpoint",
      {
        worldId: req.worldId,
        owner: req.owner,
        fencingToken: { value: tok.value.toString() },
        durability: req.durability ?? FrameDurability.DURABLE,
        labels: req.labels ?? {},
        pin: encodePin(req.pin),
        timelineName: req.timelineName ?? "",
        expectedOldTimelineHead: req.expectedOldTimelineHead ?? "",
        performSyncfs: Boolean(req.performSyncfs),
        idempotencyKey: encodeIdem(req.idempotencyKey),
      },
      opts,
    );
    return {
      frame: mapFrame(raw?.frame),
      timeline: mapTimeline(raw?.timeline),
    };
  }
}
/* eslint-enable @typescript-eslint/no-explicit-any */

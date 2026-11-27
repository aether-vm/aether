import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import * as grpc from "@grpc/grpc-js";
import {
  CLIENT_VERSION,
  DEFAULT_SOCKET_PATH,
  DEFAULT_TARGET,
  DiskNotCleanError,
  DriverKind,
  ERROR_CODE_ASCII_KEY,
  ERROR_DETAIL_BIN_KEY,
  ErrorCode,
  FencedOutError,
  ForkloomClient,
  FrameDurability,
  FrameNotFoundError,
  FrameStateKind,
  IdempotencyConflictError,
  NotNegotiatedError,
  OutcomeUnknownError,
  OutputStreamKind,
  SUPPORTED_API_MAJOR,
  TimelineCasMismatchError,
  UnsafePatchError,
  VersionSkewError,
  WorldLostError,
  WorldNotFoundError,
  WorldStateKind,
  decodeErrorDetail,
  encodeErrorDetail,
  errorCodeName,
  fencingToken,
  idempotencyKey,
  loadForkloomPackage,
  normalizeTarget,
  pinSpec,
  type ErrorDetail,
} from "../src/index.js";

interface PendingError {
  grpcCode: grpc.status;
  detail: Partial<ErrorDetail>;
  includeBin: boolean;
  includeAscii: boolean;
}

interface MockState {
  apiMajor: number;
  apiMinor: number;
  lastExec?: any;
  daemonVersion: string;
  daemonEpoch: bigint;
  negotiateCalls: number;
  importedHeader: Record<string, unknown> | undefined;
  importedBytes: Buffer;
  nextError: PendingError | undefined;
  execMidStreamError: PendingError | undefined;
  recordedCalls: string[];
}

function makeGrpcError(pending: PendingError): grpc.ServiceError {
  const md = new grpc.Metadata();
  if (pending.includeBin) {
    md.add(ERROR_DETAIL_BIN_KEY, encodeErrorDetail(pending.detail));
  }
  if (pending.includeAscii && pending.detail.code !== undefined) {
    md.add(ERROR_CODE_ASCII_KEY, errorCodeName(pending.detail.code));
  }
  const err = new Error(pending.detail.message ?? "mock error") as grpc.ServiceError;
  err.code = pending.grpcCode;
  err.details = pending.detail.message ?? "mock error";
  err.metadata = md;
  return err;
}

function createMockServer(): Promise<{
  target: string;
  state: MockState;
  close: () => Promise<void>;
}> {
  const pkg = loadForkloomPackage();
  const server = new grpc.Server();
  const state: MockState = {
    apiMajor: 1,
    apiMinor: 0,
    daemonVersion: "0.1.0-alpha.0",
    daemonEpoch: 7n,
    negotiateCalls: 0,
    importedHeader: undefined,
    importedBytes: Buffer.alloc(0),
    nextError: undefined,
    execMidStreamError: undefined,
    recordedCalls: [],
  };

  const popError = (): grpc.ServiceError | undefined => {
    if (!state.nextError) return undefined;
    const p = state.nextError;
    state.nextError = undefined;
    return makeGrpcError(p);
  };

  const sampleFrame = (frameId = "frm_01", owner = "alice") => ({
    frameId,
    owner,
    durability: FrameDurability.DURABLE,
    state: FrameStateKind.COMMITTED,
    parentFrameId: "frm_00",
    labels: { env: "test" },
    diskClean: true,
    createdEpoch: state.daemonEpoch.toString(),
    committedAtMs: "1700000000000",
    objects: ["rootfs.subvol"],
    holds: [{ kind: "pin", detail: "p1", expiresAtMs: "1700000060000" }],
    markedForReclaim: false,
  });

  const sampleWorld = (worldId = "wld_01", owner = "alice") => ({
    worldId,
    owner,
    baseFrameId: "frm_01",
    driver: DriverKind.NAMESPACE,
    state: WorldStateKind.RUNNING,
    labels: { task: "swe" },
    fencingToken: { value: "1" },
    originEpoch: state.daemonEpoch.toString(),
    lostInEpoch: "0",
    endedAtMs: "0",
    endReason: "",
  });

  /* eslint-disable @typescript-eslint/no-explicit-any */
  server.addService(pkg.forkloom.v1.SystemService.service, {
    NegotiateVersion(_call: any, cb: any) {
      state.negotiateCalls += 1;
      state.recordedCalls.push("NegotiateVersion");
      const err = popError();
      if (err) return cb(err);
      cb(null, {
        daemonVersion: state.daemonVersion,
        apiMajor: state.apiMajor,
        apiMinor: state.apiMinor,
        daemonEpoch: state.daemonEpoch.toString(),
        enabledDrivers: ["namespace", "firecracker"],
      });
    },
  });

  server.addService(pkg.forkloom.v1.FrameService.service, {
    ImportTar(call: any, cb: any) {
      state.recordedCalls.push("ImportTar");
      const err = popError();
      if (err) return cb(err);
      let header: Record<string, any> | undefined;
      const chunks: Buffer[] = [];
      call.on("data", (msg: any) => {
        if (msg.chunk === "header" || msg.header) {
          header = msg.header;
        } else if (msg.chunk === "data" || msg.data) {
          chunks.push(Buffer.from(msg.data));
        }
      });
      call.on("end", () => {
        const payload = Buffer.concat(chunks);
        state.importedHeader = header;
        state.importedBytes = payload;
        const owner = header?.owner ?? "alice";
        cb(null, {
          frame: sampleFrame("frm_imported", owner),
          timeline: header?.timelineName
            ? { name: header.timelineName, owner, headFrameId: "frm_imported" }
            : undefined,
          bytesReceived: payload.byteLength.toString(),
        });
      });
    },
    GetFrame(call: any, cb: any) {
      state.recordedCalls.push("GetFrame");
      const err = popError();
      if (err) return cb(err);
      cb(null, { frame: sampleFrame(call.request.frameId) });
    },
    ListFrames(call: any, cb: any) {
      state.recordedCalls.push("ListFrames");
      const err = popError();
      if (err) return cb(err);
      cb(null, { frames: [sampleFrame("frm_01", call.request.owner || "alice")] });
    },
    PinFrame(call: any, cb: any) {
      state.recordedCalls.push("PinFrame");
      const err = popError();
      if (err) return cb(err);
      cb(null, {
        hold: {
          kind: "pin",
          detail: `${call.request.pin.pinId} (owner=${call.request.pin.owner})`,
          expiresAtMs: "1700000060000",
        },
      });
    },
    RenewPin(_call: any, cb: any) {
      state.recordedCalls.push("RenewPin");
      const err = popError();
      if (err) return cb(err);
      cb(null, { expiresAtMs: "1700000120000", persistedToDisk: true });
    },
    DeleteFrame(_call: any, cb: any) {
      state.recordedCalls.push("DeleteFrame");
      const err = popError();
      if (err) return cb(err);
      cb(null, { deleted: true, deferred: false, remainingHolds: 0 });
    },
    AdvanceTimeline(call: any, cb: any) {
      state.recordedCalls.push("AdvanceTimeline");
      const err = popError();
      if (err) return cb(err);
      cb(null, {
        timeline: {
          name: call.request.timeline,
          owner: call.request.owner,
          headFrameId: call.request.newHeadFrameId,
        },
        previousHeadFrameId: call.request.expectedOldFrameId,
      });
    },
    DeleteTimeline(_call: any, cb: any) {
      state.recordedCalls.push("DeleteTimeline");
      const err = popError();
      if (err) return cb(err);
      cb(null, { releasedHeadFrameId: "frm_01" });
    },
    ExportPatch(call: any, cb: any) {
      state.recordedCalls.push("ExportPatch");
      const err = popError();
      if (err) return cb(err);
      cb(null, {
        baseFrameId: call.request.baseFrameId || "frm_00",
        targetFrameId: call.request.targetFrameId,
        unifiedDiff: Buffer.from("--- a/hello.txt\n+++ b/hello.txt\n@@ -1 +1 @@\n-old\n+new\n"),
        entries: [{ path: "hello.txt", kind: "modify", sizeBytes: "4" }],
        blake3Hex: "b".repeat(64),
      });
    },
  });

  server.addService(pkg.forkloom.v1.WorldService.service, {
    CreateWorld(call: any, cb: any) {
      state.recordedCalls.push("CreateWorld");
      const err = popError();
      if (err) return cb(err);
      cb(null, { world: sampleWorld("wld_created", call.request.owner) });
    },
    GetWorld(call: any, cb: any) {
      state.recordedCalls.push("GetWorld");
      const err = popError();
      if (err) return cb(err);
      cb(null, { world: sampleWorld(call.request.worldId) });
    },
    DestroyWorld(call: any, cb: any) {
      state.recordedCalls.push("DestroyWorld");
      const err = popError();
      if (err) return cb(err);
      cb(null, {
        world: {
          ...sampleWorld(call.request.worldId, call.request.owner),
          state: WorldStateKind.DESTROYED,
          endReason: "ClientRequested",
        },
      });
    },
    AcquireFence(_call: any, cb: any) {
      state.recordedCalls.push("AcquireFence");
      const err = popError();
      if (err) return cb(err);
      cb(null, { fencingToken: { value: "2" } });
    },
    RenewWorldLease(_call: any, cb: any) {
      state.recordedCalls.push("RenewWorldLease");
      const err = popError();
      if (err) return cb(err);
      cb(null, { renewedTtlMs: "600000" });
    },
    Exec(call: any) {
      state.recordedCalls.push("Exec");
      state.lastExec = call.request;
      const err = popError();
      if (err) {
        call.emit("error", err);
        return;
      }
      call.write({
        chunk: {
          stream: OutputStreamKind.STDOUT,
          seq: "1",
          data: Buffer.from("hello "),
        },
      });
      if (state.execMidStreamError) {
        const streamErr = makeGrpcError(state.execMidStreamError);
        state.execMidStreamError = undefined;
        call.emit("error", streamErr);
        return;
      }
      call.write({
        chunk: {
          stream: OutputStreamKind.STDERR,
          seq: "2",
          data: Buffer.from("warn\n"),
        },
      });
      call.write({
        chunk: {
          stream: OutputStreamKind.STDOUT,
          seq: "3",
          data: Buffer.from("world\n"),
        },
      });
      call.write({
        result: {
          execId: "exec_01",
          hasExitCode: true,
          exitCode: 0,
          hasSignal: false,
          signal: 0,
          timedOut: false,
          cgroupKilled: false,
          durationMs: "12",
          stdout: { head: Buffer.from("hello world\n"), tail: Buffer.alloc(0), totalBytes: "12", omittedBytes: "0", truncated: false },
          stderr: { head: Buffer.from("warn\n"), tail: Buffer.alloc(0), totalBytes: "5", omittedBytes: "0", truncated: false },
          replayedFromCache: false,
        },
      });
      call.end();
    },
    Checkpoint(call: any, cb: any) {
      state.recordedCalls.push("Checkpoint");
      const err = popError();
      if (err) return cb(err);
      cb(null, {
        frame: sampleFrame("frm_ckpt", call.request.owner),
        timeline: call.request.timelineName
          ? {
              name: call.request.timelineName,
              owner: call.request.owner,
              headFrameId: "frm_ckpt",
            }
          : undefined,
      });
    },
  });
  /* eslint-enable @typescript-eslint/no-explicit-any */

  let tempSockDir: string | undefined;
  let bindTarget: string;
  if (process.platform !== "win32") {
    tempSockDir = mkdtempSync(join(tmpdir(), "forkloom-ts-uds-"));
    bindTarget = `unix://${join(tempSockDir, "agentd.sock")}`;
  } else {
    bindTarget = "127.0.0.1:0";
  }

  return new Promise((resolve, reject) => {
    server.bindAsync(bindTarget, grpc.ServerCredentials.createInsecure(), (err, port) => {
      if (err) {
        if (tempSockDir) rmSync(tempSockDir, { recursive: true, force: true });
        return reject(err);
      }
      const target = process.platform !== "win32" ? bindTarget : `127.0.0.1:${port}`;
      resolve({
        target,
        state,
        close: () =>
          new Promise<void>((res) => {
            server.forceShutdown();
            if (tempSockDir) rmSync(tempSockDir, { recursive: true, force: true });
            res();
          }),
      });
    });
  });
}

describe("@forkloom-vm/sdk", () => {
  let target = "";
  let state!: MockState;
  let closeServer!: () => Promise<void>;

  before(async () => {
    const srv = await createMockServer();
    target = srv.target;
    state = srv.state;
    closeServer = srv.close;
  });

  after(async () => {
    await closeServer();
  });

  it("normalizes UDS targets and validates helpers", () => {
    const prevEnv = process.env.FORKLOOM_SOCKET;
    delete process.env.FORKLOOM_SOCKET;
    try {
      assert.equal(normalizeTarget(), DEFAULT_TARGET);
      assert.equal(normalizeTarget("/run/forkloom/agentd.sock"), DEFAULT_TARGET);
      assert.equal(normalizeTarget("unix:///tmp/custom.sock"), "unix:///tmp/custom.sock");
      assert.equal(normalizeTarget("./local.sock"), "unix:./local.sock");
      assert.equal(normalizeTarget("127.0.0.1:50051"), "127.0.0.1:50051");

      process.env.FORKLOOM_SOCKET = "/tmp/env-agentd.sock";
      assert.equal(normalizeTarget(), "unix:///tmp/env-agentd.sock");
    } finally {
      if (prevEnv === undefined) delete process.env.FORKLOOM_SOCKET;
      else process.env.FORKLOOM_SOCKET = prevEnv;
    }

    const k1 = idempotencyKey("alice");
    assert.equal(k1.owner, "alice");
    assert.equal(k1.requestId.length, 32);
    assert.throws(() => idempotencyKey("", "req-1"), RangeError);

    assert.equal(fencingToken(42).value, 42n);
    assert.equal(fencingToken(99n).value, 99n);
    assert.throws(() => fencingToken(0), RangeError);

    const p = pinSpec("pin-1", "alice", 30_000);
    assert.equal(p.pinId, "pin-1");
    assert.equal(DEFAULT_SOCKET_PATH, "/run/forkloom/agentd.sock");
    assert.equal(CLIENT_VERSION, "0.1.1-alpha.0");
  });

  it("round-trips ErrorDetail binary proto3 codec losslessly", () => {
    const encoded = encodeErrorDetail({
      code: ErrorCode.FENCED_OUT,
      message: "stale token",
      resourceId: "wld_123",
      currentFencingToken: 9_007_199_254_740_995n,
      presentedFencingToken: 42n,
      originEpoch: 11n,
      lostInEpoch: 12n,
    });
    const decoded = decodeErrorDetail(encoded);
    assert.equal(decoded.code, ErrorCode.FENCED_OUT);
    assert.equal(decoded.codeName, "ERROR_CODE_FENCED_OUT");
    assert.equal(decoded.message, "stale token");
    assert.equal(decoded.resourceId, "wld_123");
    assert.equal(decoded.currentFencingToken, 9_007_199_254_740_995n);
    assert.equal(decoded.presentedFencingToken, 42n);
    assert.equal(decoded.originEpoch, 11n);
    assert.equal(decoded.lostInEpoch, 12n);
  });

  it("covers all 17 RPCs including streaming importTar and exec", async () => {
    state.apiMajor = 1;
    state.recordedCalls = [];
    const client = await ForkloomClient.connect({ target });
    try {
      assert.equal(client.serverInfo?.apiMajor, SUPPORTED_API_MAJOR);
      assert.equal(client.serverInfo?.daemonEpoch, 7n);

      // 2. ImportTar (client-streaming)
      const payload = Buffer.concat([
        Buffer.from("tar-header"),
        Buffer.alloc(100, 0x78),
        Buffer.from("tar-footer"),
      ]);
      const imp = await client.importTar({
        owner: "alice",
        tarData: payload,
        durability: FrameDurability.DURABLE,
        labels: { repo: "forkloom" },
        pin: pinSpec("p-init", "alice", 60_000),
        timelineName: "main",
        idempotencyKey: idempotencyKey("alice", "imp-1"),
        chunkSize: 32,
      });
      assert.equal(imp.frame.frameId, "frm_imported");
      assert.equal(imp.timeline?.name, "main");
      assert.equal(imp.bytesReceived, BigInt(payload.byteLength));
      assert.deepEqual(state.importedBytes, payload);

      // 3. GetFrame
      const gf = await client.getFrame("frm_01");
      assert.equal(gf.frame.frameId, "frm_01");

      // 4. ListFrames
      const lf = await client.listFrames({ owner: "alice", labelSelector: { env: "test" } });
      assert.equal(lf.frames.length, 1);

      // 5. PinFrame
      const pf = await client.pinFrame("frm_01", pinSpec("p2", "alice", 15_000));
      assert.equal(pf.hold.kind, "pin");

      // 6. RenewPin
      const rp = await client.renewPin("frm_01", "p2", "alice");
      assert.equal(rp.persistedToDisk, true);

      // 7. AdvanceTimeline
      const at = await client.advanceTimeline({
        timeline: "main",
        owner: "alice",
        newHeadFrameId: "frm_02",
        expectedOldFrameId: "frm_01",
        idempotencyKey: idempotencyKey("alice", "adv-1"),
      });
      assert.equal(at.timeline.headFrameId, "frm_02");
      assert.equal(at.previousHeadFrameId, "frm_01");

      // 8. DeleteTimeline
      const dt = await client.deleteTimeline({
        timeline: "main",
        owner: "alice",
        idempotencyKey: idempotencyKey("alice", "dt-1"),
      });
      assert.equal(dt.releasedHeadFrameId, "frm_01");

      // 9. ExportPatch
      const ep = await client.exportPatch({
        targetFrameId: "frm_02",
        owner: "alice",
        baseFrameId: "frm_01",
      });
      assert.match(Buffer.from(ep.unifiedDiff).toString("utf8"), /\+new/);
      assert.equal(ep.entries[0]?.path, "hello.txt");

      // 10. DeleteFrame
      const df = await client.deleteFrame("frm_01", "alice", idempotencyKey("alice", "df-1"));
      assert.equal(df.deleted, true);

      // 11. CreateWorld
      const cw = await client.createWorld({
        owner: "alice",
        baseFrameId: "frm_01",
        driver: DriverKind.NAMESPACE,
        leaseTtlMs: 60_000,
        idempotencyKey: idempotencyKey("alice", "cw-1"),
      });
      const wid = cw.world.worldId;
      assert.equal(wid, "wld_created");
      assert.equal(cw.world.fencingToken.value, 1n);

      // 12. GetWorld
      const gw = await client.getWorld(wid);
      assert.equal(gw.world.worldId, wid);

      // 13. AcquireFence
      const af = await client.acquireFence(wid, "alice");
      const tok = af.fencingToken;
      assert.equal(tok.value, 2n);

      // 14. RenewWorldLease
      const rl = await client.renewWorldLease({ worldId: wid, owner: "alice", fencingToken: tok });
      assert.equal(rl.renewedTtlMs, 600_000n);

      // 15. Exec (AsyncIterable streaming)
      const stdoutParts: Buffer[] = [];
      let terminalExitCode = -1;
      for await (const ev of client.exec({
        worldId: wid,
        owner: "alice",
        fencingToken: tok,
        argv: ["/bin/echo", "hello world"],
        env: { FOO: "bar" },
        cwd: "/workspace",
        timeoutMs: 5_000,
        maxOutputBytes: 4096,
        stream: true,
        idempotencyKey: idempotencyKey("alice", "exec-1"),
      })) {
        if (ev.kind === "chunk" && ev.chunk.stream === OutputStreamKind.STDOUT) {
          stdoutParts.push(Buffer.from(ev.chunk.data));
        } else if (ev.kind === "result") {
          terminalExitCode = ev.result.exitCode;
        }
      }
      assert.equal(Buffer.concat(stdoutParts).toString("utf8"), "hello world\n");
      assert.equal(terminalExitCode, 0);

      // Also test execCollect helper
      const collectedChunks: string[] = [];
      const execRes = await client.execCollect(
        { worldId: wid, owner: "alice", fencingToken: tok.value, argv: ["/bin/true"] },
        (chunk) => collectedChunks.push(Buffer.from(chunk.data).toString("utf8")),
      );
      assert.equal(execRes.execId, "exec_01");
      assert.deepEqual(collectedChunks, ["hello ", "warn\n", "world\n"]);

      // 16. Checkpoint
      const ck = await client.checkpoint({
        worldId: wid,
        owner: "alice",
        fencingToken: tok,
        durability: FrameDurability.DURABLE,
        timelineName: "main",
        performSyncfs: true,
        idempotencyKey: idempotencyKey("alice", "ckpt-1"),
      });
      assert.equal(ck.frame.frameId, "frm_ckpt");
      assert.equal(ck.timeline?.name, "main");

      // 17. DestroyWorld
      const dw = await client.destroyWorld({
        worldId: wid,
        owner: "alice",
        fencingToken: tok,
        idempotencyKey: idempotencyKey("alice", "dw-1"),
      });
      assert.equal(dw.world.state, WorldStateKind.DESTROYED);

      const expected = [
        "NegotiateVersion",
        "ImportTar",
        "GetFrame",
        "ListFrames",
        "PinFrame",
        "RenewPin",
        "DeleteFrame",
        "AdvanceTimeline",
        "DeleteTimeline",
        "ExportPatch",
        "CreateWorld",
        "GetWorld",
        "DestroyWorld",
        "AcquireFence",
        "RenewWorldLease",
        "Exec",
        "Checkpoint",
      ];
      assert.equal(expected.length, 17);
      for (const rpc of expected) {
        assert.ok(state.recordedCalls.includes(rpc), `missing recorded RPC ${rpc}`);
      }
    } finally {
      client.close();
    }
  });

  it("enforces mandatory NegotiateVersion and rejects api_major skew", async () => {
    state.apiMajor = 1;
    const manual = new ForkloomClient({ target, autoNegotiate: false });
    try {
      await assert.rejects(() => manual.getFrame("frm_01"), NotNegotiatedError);
      const info = await manual.negotiateVersion();
      assert.equal(info.apiMajor, 1);
      const gf = await manual.getFrame("frm_01");
      assert.equal(gf.frame.frameId, "frm_01");
    } finally {
      manual.close();
    }

    state.apiMajor = 2;
    const skewed = new ForkloomClient({ target });
    try {
      await assert.rejects(
        () => skewed.negotiateVersion(),
        (err: unknown) => {
          assert.ok(err instanceof VersionSkewError);
          assert.equal(err.daemonApiMajor, 2);
          assert.equal(err.supportedApiMajor, 1);
          return true;
        },
      );
      await assert.rejects(() => skewed.listFrames({ owner: "alice" }), VersionSkewError);
    } finally {
      skewed.close();
      state.apiMajor = 1;
    }
  });

  it("sends detached Exec only to daemons that know it", async () => {
    const client = new ForkloomClient({ target });
    const req = { worldId: "wld_01", owner: "alice", fencingToken: 1, argv: ["/bin/server"], detached: true };
    try {
      await assert.rejects(() => client.execCollect(req), /apiMinor/);
      state.apiMinor = 1;
      await client.negotiateVersion();
      await client.execCollect(req);
      assert.equal(state.lastExec.detached, true);
    } finally {
      state.apiMinor = 0;
      client.close();
    }
  });

  it("decodes x-forkloom-error-bin and x-forkloom-error-code into typed errors", async () => {
    const client = await ForkloomClient.connect({ target });
    try {
      const cases: Array<{
        grpcCode: grpc.status;
        detail: Partial<ErrorDetail>;
        Ctor: new (...args: never[]) => Error;
      }> = [
        {
          grpcCode: grpc.status.FAILED_PRECONDITION,
          detail: {
            code: ErrorCode.WORLD_LOST,
            message: "world lost across restart",
            resourceId: "wld_99",
            originEpoch: 3n,
            lostInEpoch: 4n,
          },
          Ctor: WorldLostError,
        },
        {
          grpcCode: grpc.status.FAILED_PRECONDITION,
          detail: {
            code: ErrorCode.OUTCOME_UNKNOWN,
            message: "exec outcome unknown",
            resourceId: "wld_99",
            originEpoch: 3n,
            lostInEpoch: 4n,
          },
          Ctor: OutcomeUnknownError,
        },
        {
          grpcCode: grpc.status.FAILED_PRECONDITION,
          detail: {
            code: ErrorCode.FENCED_OUT,
            message: "stale fencing token",
            resourceId: "wld_99",
            currentFencingToken: 9n,
            presentedFencingToken: 4n,
          },
          Ctor: FencedOutError,
        },
        {
          grpcCode: grpc.status.ALREADY_EXISTS,
          detail: {
            code: ErrorCode.IDEMPOTENCY_CONFLICT,
            message: "idempotency conflict",
            resourceId: "req-123",
          },
          Ctor: IdempotencyConflictError,
        },
        {
          grpcCode: grpc.status.FAILED_PRECONDITION,
          detail: {
            code: ErrorCode.DISK_NOT_CLEAN,
            message: "disk not clean",
            resourceId: "frm_dirty",
          },
          Ctor: DiskNotCleanError,
        },
        {
          grpcCode: grpc.status.INVALID_ARGUMENT,
          detail: {
            code: ErrorCode.UNSAFE_PATCH,
            message: "path traversal rejected",
          },
          Ctor: UnsafePatchError,
        },
        {
          grpcCode: grpc.status.ABORTED,
          detail: {
            code: ErrorCode.TIMELINE_CAS_MISMATCH,
            message: "cas mismatch",
            resourceId: "main",
          },
          Ctor: TimelineCasMismatchError,
        },
        {
          grpcCode: grpc.status.NOT_FOUND,
          detail: {
            code: ErrorCode.FRAME_NOT_FOUND,
            message: "frame missing",
            resourceId: "frm_404",
          },
          Ctor: FrameNotFoundError,
        },
      ];

      for (const tc of cases) {
        state.nextError = {
          grpcCode: tc.grpcCode,
          detail: tc.detail,
          includeBin: true,
          includeAscii: true,
        };
        await assert.rejects(
          () => client.getFrame("frm_01"),
          (err: unknown) => {
            assert.ok(err instanceof tc.Ctor, `expected ${tc.Ctor.name}, got ${String(err)}`);
            const fe = err as InstanceType<typeof WorldLostError>;
            assert.equal(fe.grpcCode, tc.grpcCode);
            assert.equal(fe.errorCode, tc.detail.code);
            assert.equal(fe.message, tc.detail.message);
            assert.equal(fe.resourceId, tc.detail.resourceId ?? "");
            assert.equal(fe.currentFencingToken, tc.detail.currentFencingToken ?? 0n);
            assert.equal(fe.presentedFencingToken, tc.detail.presentedFencingToken ?? 0n);
            assert.equal(fe.originEpoch, tc.detail.originEpoch ?? 0n);
            assert.equal(fe.lostInEpoch, tc.detail.lostInEpoch ?? 0n);
            return true;
          },
        );
      }

      // ASCII-only x-forkloom-error-code fallback
      state.nextError = {
        grpcCode: grpc.status.NOT_FOUND,
        detail: {
          code: ErrorCode.WORLD_NOT_FOUND,
          message: "world not found ascii-only",
        },
        includeBin: false,
        includeAscii: true,
      };
      await assert.rejects(() => client.getWorld("wld_missing"), WorldNotFoundError);

      // Mid-stream Exec error decoding
      state.execMidStreamError = {
        grpcCode: grpc.status.FAILED_PRECONDITION,
        detail: {
          code: ErrorCode.OUTCOME_UNKNOWN,
          message: "daemon restarted mid-exec",
          resourceId: "wld_01",
          originEpoch: 7n,
          lostInEpoch: 8n,
        },
        includeBin: true,
        includeAscii: true,
      };
      const received: string[] = [];
      await assert.rejects(
        async () => {
          for await (const ev of client.exec({
            worldId: "wld_01",
            owner: "alice",
            fencingToken: 1,
            argv: ["/bin/sleep", "10"],
          })) {
            if (ev.kind === "chunk") {
              received.push(Buffer.from(ev.chunk.data).toString("utf8"));
            }
          }
        },
        (err: unknown) => {
          assert.ok(err instanceof OutcomeUnknownError);
          assert.equal(err.originEpoch, 7n);
          assert.equal(err.lostInEpoch, 8n);
          return true;
        },
      );
      assert.deepEqual(received, ["hello "]);
    } finally {
      client.close();
    }
  });
});

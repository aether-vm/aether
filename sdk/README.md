# Forkloom Thin SDKs (`Python` & `TypeScript`)

Thin gRPC clients generated directly from `../../proto/forkloom/v1/runtime.proto`.

- **`python/` (`forkloom-vm`, `0.1.0a0`)**: Primary SDK for RL training loops, MCTS sampling, and SWE-bench evaluation pipelines.
- **`typescript/` (`@forkloom-vm/sdk`, `0.1.0-alpha.0`)**: Primary SDK for Node.js CI orchestration and `forkloom-mcp`.

> **Design Rules**:
> - Strictly **thin over gRPC** (no `napi-rs` or `PyO3` native binary matrix prior to `v1.0`).
> - Default transport is **Unix Domain Socket** (`unix:///run/forkloom/agentd.sock` or `$FORKLOOM_SOCKET`), matching `agentd`'s `0600` UDS-only security boundary.
> - Mandatory `SystemService.NegotiateVersion` handshake verifying `api_major == 1` before issuing stateful RPCs.
> - Structured gRPC error metadata (`x-forkloom-error-bin` / `x-forkloom-error-code`) decoded into typed exceptions (`WorldLostError`, `OutcomeUnknownError`, `FencedOutError`, `IdempotencyConflictError`, `DiskNotCleanError`, `UnsafePatchError`, etc.).

---

## Python Quickstart (`forkloom-vm`)

```bash
cd sdk/python
pip install -e ".[dev]"
python scripts/gen_proto.py --check
pytest
```

```python
from forkloom_vm import (
    DriverKind,
    FencedOutError,
    ForkloomClient,
    FrameDurability,
    WorldLostError,
    idempotency_key,
)

# Connects to $FORKLOOM_SOCKET or unix:///run/forkloom/agentd.sock
# and runs the mandatory SystemService.NegotiateVersion (api_major == 1) handshake.
with ForkloomClient.connect("unix:///run/forkloom/agentd.sock") as client:
    # 1. Stream a tar archive into an immutable Base Frame
    with open("repo.tar", "rb") as fh:
        base = client.import_tar(
            "alice",
            fh,
            durability=FrameDurability.FRAME_DURABILITY_DURABLE,
            timeline_name="main",
            idempotency_key=idempotency_key("alice"),
        )

    # 2. Spawn a stateful sandbox World and run a streaming command
    world = client.create_world(
        "alice",
        base.frame.frame_id,
        driver=DriverKind.DRIVER_KIND_NAMESPACE,
        idempotency_key=idempotency_key("alice"),
    ).world
    token = world.fencing_token

    try:
        result = client.exec_collect(
            world.world_id,
            "alice",
            token,
            ["pytest", "-q"],
            cwd="/workspace",
            idempotency_key=idempotency_key("alice"),
            on_chunk=lambda c: print(c.data.decode("utf-8", errors="replace"), end=""),
        )
        print("exit_code:", result.exit_code)
    except (WorldLostError, FencedOutError) as err:
        print(f"structured error: {err.error_code} resource={err.resource_id}")

    # 3. Checkpoint and export a validated unified diff patch
    ckpt = client.checkpoint(
        world.world_id,
        "alice",
        token,
        timeline_name="main",
        expected_old_timeline_head=base.frame.frame_id,
        perform_syncfs=True,
        idempotency_key=idempotency_key("alice"),
    )
    patch = client.export_patch(ckpt.frame.frame_id, "alice", base_frame_id=base.frame.frame_id)
    print(patch.unified_diff.decode("utf-8"))
    client.destroy_world(world.world_id, "alice", token)
```

---

## TypeScript Quickstart (`@forkloom-vm/sdk`)

```bash
cd sdk/typescript
npm install
npm run check-proto
npm run typecheck
npm test
```

```ts
import { readFileSync } from "node:fs";
import {
  DriverKind,
  FencedOutError,
  ForkloomClient,
  FrameDurability,
  WorldLostError,
  idempotencyKey,
} from "@forkloom-vm/sdk";

// Connects to $FORKLOOM_SOCKET or unix:///run/forkloom/agentd.sock
// and runs the mandatory SystemService.NegotiateVersion (api_major == 1) handshake.
const client = await ForkloomClient.connect({
  target: "unix:///run/forkloom/agentd.sock",
});

try {
  // 1. Stream a tar archive into an immutable Base Frame
  const base = await client.importTar({
    owner: "alice",
    tarData: readFileSync("repo.tar"),
    durability: FrameDurability.DURABLE,
    timelineName: "main",
    idempotencyKey: idempotencyKey("alice"),
  });

  // 2. Spawn a World and stream Exec output chunks + terminal ExecResult
  const { world } = await client.createWorld({
    owner: "alice",
    baseFrameId: base.frame.frameId,
    driver: DriverKind.NAMESPACE,
    idempotencyKey: idempotencyKey("alice"),
  });
  const token = world.fencingToken;

  try {
    for await (const ev of client.exec({
      worldId: world.worldId,
      owner: "alice",
      fencingToken: token,
      argv: ["npm", "test"],
      cwd: "/workspace",
      idempotencyKey: idempotencyKey("alice"),
    })) {
      if (ev.kind === "chunk") {
        process.stdout.write(ev.chunk.data);
      } else {
        console.log("exitCode:", ev.result.exitCode);
      }
    }
  } catch (err) {
    if (err instanceof WorldLostError || err instanceof FencedOutError) {
      console.error(`structured error: ${err.errorCode} resource=${err.resourceId}`);
    } else {
      throw err;
    }
  }

  // 3. Checkpoint and export a validated unified diff patch
  const ckpt = await client.checkpoint({
    worldId: world.worldId,
    owner: "alice",
    fencingToken: token,
    timelineName: "main",
    expectedOldTimelineHead: base.frame.frameId,
    performSyncfs: true,
    idempotencyKey: idempotencyKey("alice"),
  });
  const patch = await client.exportPatch({
    targetFrameId: ckpt.frame.frameId,
    baseFrameId: base.frame.frameId,
    owner: "alice",
  });
  console.log(Buffer.from(patch.unifiedDiff).toString("utf8"));
  await client.destroyWorld({ worldId: world.worldId, owner: "alice", fencingToken: token });
} finally {
  client.close();
}
```

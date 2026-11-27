# `@forkloom-vm/sdk` (TypeScript SDK)

Thin gRPC client for the Forkloom stateful sandbox runtime, for Node.js.

Design rules shared by both SDKs: [`sdk/README.md`](https://github.com/forkloom-vm/forkloom/blob/main/sdk/README.md).

## Quickstart

```bash
cd sdk/typescript
npm ci
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

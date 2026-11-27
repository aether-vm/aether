# `forkloom-vm` (Python SDK)

Thin gRPC client for the Forkloom stateful sandbox runtime.

Design rules shared by both SDKs: [`sdk/README.md`](https://github.com/forkloom-vm/forkloom/blob/main/sdk/README.md).

## Quickstart

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

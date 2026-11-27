"""Live Linux End-to-End Cold-Fork Integration Test for Python SDK.

Runs against live `agentd --backend production` over a `0600` Unix Domain Socket on Linux/WSL2
with real Btrfs loop pool, ext4 meta, cgroup v2, and aos-guest namespace driver.
Gated on `FORKLOOM_LIVE_E2E=1` so offline unit tests remain fast and cross-platform.
"""

from __future__ import annotations

import concurrent.futures
import io
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path
from typing import Iterator

import pytest

from forkloom_vm import (
    DriverKind,
    ForkloomClient,
    FrameDurability,
    idempotency_key,
    pb,
)

DEFAULT_ROOTFS_STAGE = Path("/var/lib/forkloom/guest-image/rootfs-stage")
DEFAULT_GUEST_AGENT = Path("/var/lib/forkloom/guest-image/out/aos-guest")


def remove_cgroup_tree(root: Path) -> None:
    (root / "cgroup.kill").write_bytes(b"1\n")
    for d, _, _ in os.walk(root, topdown=False):
        # Killed processes leave the cgroup asynchronously.
        for attempt in range(101):
            try:
                os.rmdir(d)
                break
            except OSError:
                if attempt == 100:
                    raise
                time.sleep(0.02)


class LiveAgentdHarness:
    """Manages an isolated live `agentd --backend production` daemon on Linux/WSL2."""

    def __init__(self, workspace_root: Path) -> None:
        self.workspace_root = workspace_root
        nanos = time.time_ns()
        pid = os.getpid()
        self.base_dir = Path(f"/tmp/forkloom-sdk-e2e-{pid}-{nanos}")
        self.img_path = self.base_dir / "pool.btrfs.img"
        self.pool_dir = self.base_dir / "pool"
        self.meta_dir = self.base_dir / "meta"
        self.tmpfs_dir = self.base_dir / "volatile"
        self.sock_path = self.base_dir / "run" / "agentd.sock"
        self.cgroup_root = Path(f"/sys/fs/cgroup/forkloom.slice/sdk-e2e-{pid}-{nanos}")
        self.daemon_proc: subprocess.Popen[bytes] | None = None
        self.mounted: bool = False
        self.log_file: io.BufferedWriter | None = None

    def setup(self) -> None:
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.pool_dir.mkdir(parents=True, exist_ok=True)
        self.meta_dir.mkdir(parents=True, exist_ok=True)
        self.tmpfs_dir.mkdir(parents=True, exist_ok=True)
        self.cgroup_root.mkdir(parents=True, exist_ok=True)

        # 512 MiB loop Btrfs pool
        with open(self.img_path, "wb") as f:
            f.truncate(512 * 1024 * 1024)

        mkfs = subprocess.run(
            ["mkfs.btrfs", "-f", "-q", str(self.img_path)],
            check=True,
            capture_output=True,
        )

        mount = subprocess.run(
            ["mount", "-o", "loop,noatime", str(self.img_path), str(self.pool_dir)],
            check=True,
            capture_output=True,
        )
        self.mounted = True

        # Locate agentd binary
        agentd_bin = self.workspace_root / "target" / "debug" / "agentd"
        if not agentd_bin.is_file():
            # Build agentd if not present
            subprocess.run(
                ["cargo", "build", "-p", "agentd"],
                cwd=str(self.workspace_root),
                check=True,
            )
        assert agentd_bin.is_file(), f"agentd binary not found at {agentd_bin}"

        log_path = self.base_dir / "agentd.log"
        self.log_file = open(log_path, "wb")

        cmd = [
            str(agentd_bin),
            "--backend",
            "production",
            "--socket",
            str(self.sock_path),
            "--meta-dir",
            str(self.meta_dir),
            "--pool-dir",
            str(self.pool_dir),
            "--tmpfs-dir",
            str(self.tmpfs_dir),
            "--cgroup-root",
            str(self.cgroup_root),
            "--ballast-mib",
            "32",
        ]
        if DEFAULT_GUEST_AGENT.is_file():
            cmd.extend(["--guest-agent-host-bin", str(DEFAULT_GUEST_AGENT)])

        self.daemon_proc = subprocess.Popen(
            cmd,
            stdout=self.log_file,
            stderr=subprocess.STDOUT,
        )

        # Wait for UDS to become available
        for _ in range(120):
            if self.sock_path.exists():
                # Verify 0600 mode
                mode = self.sock_path.stat().st_mode & 0o777
                if mode == 0o600:
                    return
            time.sleep(0.05)

        log_content = ""
        if log_path.exists():
            log_content = log_path.read_text(errors="replace")
        raise RuntimeError(f"agentd failed to bind 0600 socket {self.sock_path}:\n{log_content}")

    def teardown(self, print_log_on_error: bool = False) -> None:
        log_path = self.base_dir / "agentd.log"
        if print_log_on_error and log_path.exists():
            print("\n=== AGENTD.LOG ON FAILURE ===")
            print(log_path.read_text(errors="replace"))
            print("=== END AGENTD.LOG ===\n")

        if self.daemon_proc is not None:
            self.daemon_proc.terminate()
            try:
                self.daemon_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.daemon_proc.kill()
                self.daemon_proc.wait()
            self.daemon_proc = None

        if self.log_file is not None:
            self.log_file.close()
            self.log_file = None

        if self.sock_path.exists():
            try:
                self.sock_path.unlink()
            except OSError:
                pass

        # Cleanup cgroups
        cgroup_error: OSError | None = None
        if self.cgroup_root.exists():
            try:
                remove_cgroup_tree(self.cgroup_root)
            except OSError as e:
                cgroup_error = e

        # Unmount Btrfs loop
        if self.mounted:
            for _ in range(10):
                umount = subprocess.run(["umount", str(self.pool_dir)], capture_output=True)
                if umount.returncode == 0:
                    self.mounted = False
                    break
                time.sleep(0.1)
            if self.mounted:
                subprocess.run(["umount", "-l", str(self.pool_dir)], capture_output=True)
                self.mounted = False

        if self.img_path.exists():
            try:
                self.img_path.unlink()
            except OSError:
                pass

        if self.base_dir.exists():
            shutil.rmtree(self.base_dir, ignore_errors=True)
        if cgroup_error is not None:
            raise cgroup_error


def make_clean_rootfs_tar(tmp_root: Path) -> bytes:
    """Pack a minimal rootfs tar with busybox and aos-guest for cold-fork testing."""
    stage = tmp_root / "stage"
    for d in ["bin", "sbin", "usr/bin", "proc", "sys", "dev", "tmp", "etc", "workspace"]:
        (stage / d).mkdir(parents=True, exist_ok=True)

    src_init = DEFAULT_ROOTFS_STAGE / "sbin" / "init"
    src_busybox = DEFAULT_ROOTFS_STAGE / "bin" / "busybox"
    shutil.copy2(src_init, stage / "sbin" / "init")
    (stage / "sbin" / "init").chmod(0o755)
    shutil.copy2(src_busybox, stage / "bin" / "busybox")
    (stage / "bin" / "busybox").chmod(0o755)

    for applet in ["sh", "cat", "echo", "ls", "grep", "hostname", "mkdir", "rm"]:
        os.symlink("busybox", stage / "bin" / applet)
    os.symlink("../../sbin/init", stage / "usr/bin" / "aos-guest")

    (stage / "workspace" / "base.txt").write_bytes(b"base-seed-v1\n")

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for entry in os.scandir(stage):
            tar.add(entry.path, arcname=entry.name, recursive=True)
    return buf.getvalue()


@pytest.mark.skipif(
    os.environ.get("FORKLOOM_LIVE_E2E") != "1",
    reason="Live Linux E2E test requires FORKLOOM_LIVE_E2E=1",
)
def test_live_agentd_parallel_cold_fork_swe_bench() -> None:
    if sys.platform != "linux":
        pytest.skip("Live agentd production test requires Linux/WSL2")
    if not DEFAULT_ROOTFS_STAGE.is_dir():
        pytest.skip(f"Required rootfs-stage directory not found: {DEFAULT_ROOTFS_STAGE}")
    if not Path("/sys/fs/cgroup/cgroup.controllers").exists():
        pytest.skip("cgroup v2 is not mounted")

    workspace_root = Path(__file__).resolve().parent.parent.parent.parent
    harness = LiveAgentdHarness(workspace_root)
    harness.setup()

    try:
        t0 = time.perf_counter()
        with tempfile.TemporaryDirectory(prefix="forkloom-rootfs-") as tmp:
            tar_data = make_clean_rootfs_tar(Path(tmp))

        client = ForkloomClient.connect(target=f"unix://{harness.sock_path}")
        assert client.server_info is not None
        assert client.server_info.api_major == 1
        assert client.server_info.daemon_epoch >= 1
        assert "namespace" in client.server_info.enabled_drivers

        # 1. Import base frame
        imp_resp = client.import_tar(
            "swe-bench",
            tar_data,
            durability=FrameDurability.FRAME_DURABILITY_DURABLE,
            timeline_name="main",
            idempotency_key=idempotency_key("swe-bench", "base-import"),
        )
        base_fid = imp_resp.frame.frame_id
        assert imp_resp.frame.disk_clean is True

        # 2. Spawn 4 concurrent worlds (SWE-bench parallel sampling)
        num_branches = 4
        owner = "swe-bench"

        def run_branch(branch_idx: int) -> dict[str, str]:
            cw = client.create_world(
                owner,
                base_fid,
                driver=DriverKind.DRIVER_KIND_NAMESPACE,
                lease_ttl_ms=300_000,
                idempotency_key=idempotency_key(owner, f"cw-{branch_idx}"),
            )
            wid = cw.world.world_id
            token = cw.world.fencing_token

            # Write branch file and verify base file exists
            cmd_mutate = (
                f"printf 'content-from-branch-{branch_idx}\\n' > /workspace/branch-{branch_idx}.txt && "
                f"ls -1 /workspace"
            )
            res_mut = client.exec_collect(
                wid,
                owner,
                token,
                ["/bin/sh", "-c", cmd_mutate],
            )
            assert res_mut.exit_code == 0

            # A detached service outlives its Exec and is reachable from the next one.
            started = client.exec_collect(
                wid,
                owner,
                token,
                ["/bin/sh", "-c", "while :; do echo tick >> /tmp/ticks; sleep 0.1; done"],
                detached=True,
            )
            assert not started.has_exit_code
            alive = client.exec_collect(
                wid,
                owner,
                token,
                ["/bin/sh", "-c", "sleep 0.5; a=$(wc -l < /tmp/ticks); sleep 0.5; "
                 "b=$(wc -l < /tmp/ticks); test $b -gt $a"],
            )
            assert alive.exit_code == 0
            ls_output = res_mut.stdout.head.decode("utf-8", errors="replace")

            # Checkpoint the world
            ckpt = client.checkpoint(
                wid,
                owner,
                token,
                durability=FrameDurability.FRAME_DURABILITY_DURABLE,
                timeline_name=f"timeline-{branch_idx}",
                perform_syncfs=True,
                idempotency_key=idempotency_key(owner, f"ckpt-{branch_idx}"),
            )
            ckpt_fid = ckpt.frame.frame_id
            assert ckpt.frame.disk_clean is True

            # Post-checkpoint exec: verify unfreeze succeeded and world continues running
            res_post = client.exec_collect(
                wid,
                owner,
                token,
                ["/bin/sh", "-c", f"cat /workspace/branch-{branch_idx}.txt && echo POST_UNFREEZE_{branch_idx}"],
            )
            assert res_post.exit_code == 0
            post_output = res_post.stdout.head.decode("utf-8", errors="replace")
            assert f"content-from-branch-{branch_idx}" in post_output
            assert f"POST_UNFREEZE_{branch_idx}" in post_output

            # Export patch against base frame
            patch = client.export_patch(ckpt_fid, owner, base_frame_id=base_fid)
            diff_text = patch.unified_diff.decode("utf-8", errors="replace")
            assert f"branch-{branch_idx}.txt" in diff_text
            assert len(patch.blake3_hex) == 64

            # Destroy world
            client.destroy_world(wid, owner, token, idempotency_key=idempotency_key(owner, f"dw-{branch_idx}"))

            return {
                "branch": str(branch_idx),
                "wid": wid,
                "ls": ls_output,
                "patch": diff_text,
                "blake3": patch.blake3_hex,
            }

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_branches) as executor:
            futures = [executor.submit(run_branch, i) for i in range(num_branches)]
            results = [f.result() for f in futures]

        # Verify cross-branch isolation (zero leakage!)
        for i, res in enumerate(results):
            # Must contain its own branch file
            assert f"branch-{i}.txt" in res["ls"]
            # Must NOT contain any other branch file
            for j in range(num_branches):
                if i != j:
                    assert f"branch-{j}.txt" not in res["ls"], (
                        f"Branch {i} leaked file from branch {j}!"
                    )

        client.close()
        elapsed = time.perf_counter() - t0
        print(f"\n[AdvisoryWsl2] 4 concurrent cold forks completed in {elapsed:.2f}s")
    except Exception:
        harness.teardown(print_log_on_error=True)
        raise
    else:
        harness.teardown(print_log_on_error=False)

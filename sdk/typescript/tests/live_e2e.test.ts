import assert from "node:assert/strict";
import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import {
  closeSync,
  copyFileSync,
  createWriteStream,
  existsSync,
  ftruncateSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readdirSync,
  readFileSync,
  rmdirSync,
  rmSync,
  statSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import {
  DriverKind,
  ForkloomClient,
  FrameDurability,
  idempotencyKey,
} from "../src/index.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOTFS_STAGE = "/var/lib/forkloom/guest-image/rootfs-stage";
const GUEST_AGENT = "/var/lib/forkloom/guest-image/out/aos-guest";

const isLiveE2e = process.env.FORKLOOM_LIVE_E2E === "1";
const isLinux = process.platform === "linux";

describe("TypeScript SDK Live agentd E2E", { skip: !isLiveE2e || !isLinux }, () => {
  let sockPath = process.env.FORKLOOM_LIVE_SOCKET ?? "";
  let baseDir = "";
  let poolDir = "";
  let imgPath = "";
  let cgroupRoot = "";
  let daemonProc: ChildProcess | undefined;
  let mounted = false;

  before(() => {
    if (sockPath && existsSync(sockPath)) {
      baseDir = mkdtempSync(join(tmpdir(), "forkloom-ts-live-"));
      return;
    }
    if (!existsSync(ROOTFS_STAGE) || !existsSync("/sys/fs/cgroup/cgroup.controllers")) {
      return;
    }

    const nanos = Date.now() * 1_000_000 + (process.hrtime()[1] % 1_000_000);
    const pid = process.pid;
    baseDir = `/tmp/forkloom-ts-e2e-${pid}-${nanos}`;
    poolDir = join(baseDir, "pool");
    const metaDir = join(baseDir, "meta");
    const tmpfsDir = join(baseDir, "volatile");
    imgPath = join(baseDir, "pool.btrfs.img");
    cgroupRoot = `/sys/fs/cgroup/forkloom.slice/ts-e2e-${pid}-${nanos}`;
    sockPath = join(baseDir, "run", "agentd.sock");

    mkdirSync(poolDir, { recursive: true });
    mkdirSync(metaDir, { recursive: true });
    mkdirSync(tmpfsDir, { recursive: true });
    mkdirSync(cgroupRoot, { recursive: true });
    mkdirSync(dirname(sockPath), { recursive: true, mode: 0o700 });

    const fd = openSync(imgPath, "w");
    ftruncateSync(fd, 512 * 1024 * 1024);
    closeSync(fd);
    execFileSync("mkfs.btrfs", ["-f", "-q", imgPath]);
    execFileSync("mount", ["-o", "loop,noatime", imgPath, poolDir]);
    mounted = true;

    let repoRoot = resolve(__dirname, "..");
    for (let i = 0; i < 8; i += 1) {
      if (existsSync(join(repoRoot, "target", "debug", "agentd")) || existsSync(join(repoRoot, "Cargo.toml"))) {
        break;
      }
      repoRoot = dirname(repoRoot);
    }
    const agentdBin = join(repoRoot, "target", "debug", "agentd");
    if (!existsSync(agentdBin)) {
      const cargoEnv = {
        ...process.env,
        PATH: `/root/.cargo/bin:/usr/local/cargo/bin:${process.env.PATH ?? ""}`,
      };
      execFileSync("cargo", ["build", "-p", "agentd"], { cwd: repoRoot, env: cargoEnv });
    }

    const logFile = openSync(join(baseDir, "agentd.log"), "w");
    const args = [
      "--backend",
      "production",
      "--socket",
      sockPath,
      "--meta-dir",
      metaDir,
      "--pool-dir",
      poolDir,
      "--tmpfs-dir",
      tmpfsDir,
      "--cgroup-root",
      cgroupRoot,
      "--ballast-mib",
      "32",
    ];
    if (existsSync(GUEST_AGENT)) {
      args.push("--guest-agent-host-bin", GUEST_AGENT);
    }

    daemonProc = spawn(agentdBin, args, { stdio: ["ignore", logFile, logFile] });
    closeSync(logFile);

    for (let i = 0; i < 120; i += 1) {
      if (existsSync(sockPath)) {
        const mode = statSync(sockPath).mode & 0o777;
        if (mode === 0o600) return;
      }
      execFileSync("sleep", ["0.05"]);
    }
    throw new Error(`agentd failed to bind 0600 socket at ${sockPath}`);
  });

  after(() => {
    if (daemonProc) {
      daemonProc.kill();
      daemonProc = undefined;
    }
    if (cgroupRoot && existsSync(cgroupRoot)) {
      try {
        const entries = readdirSync(cgroupRoot);
        for (const entry of entries) {
          const p = join(cgroupRoot, entry);
          try {
            writeFileSync(join(p, "cgroup.kill"), "1\n");
            writeFileSync(join(p, "cgroup.freeze"), "0\n");
            for (const sub of readdirSync(p)) {
              const sp = join(p, sub);
              writeFileSync(join(sp, "cgroup.kill"), "1\n");
              writeFileSync(join(sp, "cgroup.freeze"), "0\n");
              rmdirSync(sp);
            }
            rmdirSync(p);
          } catch {}
        }
        rmdirSync(cgroupRoot);
      } catch {}
    }
    if (mounted) {
      for (let i = 0; i < 10; i += 1) {
        try {
          execFileSync("umount", [poolDir]);
          mounted = false;
          break;
        } catch {
          execFileSync("sleep", ["0.1"]);
        }
      }
      if (mounted) {
        try {
          execFileSync("umount", ["-l", poolDir]);
          mounted = false;
        } catch {}
      }
    }
    if (imgPath && existsSync(imgPath)) {
      try {
        unlinkSync(imgPath);
      } catch {}
    }
    if (baseDir && existsSync(baseDir)) {
      try {
        rmSync(baseDir, { recursive: true, force: true });
      } catch {}
    }
  });

  it("completes full cold-fork lifecycle against production agentd", async () => {
    if (!sockPath || !existsSync(sockPath)) {
      return;
    }

    const t0 = performance.now();
    const client = await ForkloomClient.connect({ target: `unix://${sockPath}` });
    try {
      assert.equal(client.serverInfo?.apiMajor, 1);
      assert.ok(client.serverInfo!.daemonEpoch >= 1n);

      // Create minimal rootfs tar
      const prepDir = join(baseDir, "rootfs-prep");
      for (const d of ["bin", "sbin", "usr/bin", "proc", "sys", "dev", "tmp", "etc", "workspace"]) {
        mkdirSync(join(prepDir, d), { recursive: true });
      }
      copyFileSync(join(ROOTFS_STAGE, "sbin/init"), join(prepDir, "sbin/init"));
      copyFileSync(join(ROOTFS_STAGE, "bin/busybox"), join(prepDir, "bin/busybox"));
      execFileSync("chmod", ["0755", join(prepDir, "sbin/init"), join(prepDir, "bin/busybox")]);
      for (const app of ["sh", "cat", "echo", "ls", "grep", "hostname", "mkdir", "rm"]) {
        symlinkSync("busybox", join(prepDir, "bin", app));
      }
      symlinkSync("../../sbin/init", join(prepDir, "usr/bin/aos-guest"));
      writeFileSync(join(prepDir, "workspace/app.txt"), "hello-live-ts\n");

      const tarPath = join(baseDir, "rootfs.tar");
      execFileSync("tar", ["--format=ustar", "-cf", tarPath, "-C", prepDir, "."]);
      const tarData = readFileSync(tarPath);

      // 1. importTar
      const imp = await client.importTar({
        owner: "ts-live",
        tarData,
        durability: FrameDurability.DURABLE,
        timelineName: "main",
        idempotencyKey: idempotencyKey("ts-live", "imp-1"),
      });
      const baseFid = imp.frame.frameId;
      assert.ok(baseFid.length > 0);
      assert.equal(imp.frame.diskClean, true);

      // 2. createWorld
      const { world } = await client.createWorld({
        owner: "ts-live",
        baseFrameId: baseFid,
        driver: DriverKind.NAMESPACE,
        idempotencyKey: idempotencyKey("ts-live", "cw-1"),
      });
      const wid = world.worldId;
      const tok = world.fencingToken;

      // 3. exec file mutation
      const execRes = await client.execCollect({
        worldId: wid,
        owner: "ts-live",
        fencingToken: tok,
        argv: [
          "/bin/sh",
          "-c",
          "printf 'ts-mutation-ok\\n' > /workspace/ts-out.txt && cat /workspace/ts-out.txt",
        ],
      });
      assert.equal(execRes.exitCode, 0);
      assert.match(Buffer.from(execRes.stdout.head).toString("utf8"), /ts-mutation-ok/);

      // 4. checkpoint
      const ckpt = await client.checkpoint({
        worldId: wid,
        owner: "ts-live",
        fencingToken: tok,
        durability: FrameDurability.DURABLE,
        timelineName: "main",
        expectedOldTimelineHead: baseFid,
        performSyncfs: true,
        idempotencyKey: idempotencyKey("ts-live", "ckpt-1"),
      });
      assert.equal(ckpt.frame.diskClean, true);

      // 5. post-checkpoint exec: verify unfreeze
      const postExec = await client.execCollect({
        worldId: wid,
        owner: "ts-live",
        fencingToken: tok,
        argv: ["/bin/sh", "-c", "cat /workspace/ts-out.txt && echo POST_UNFREEZE_TS"],
      });
      assert.equal(postExec.exitCode, 0);
      assert.match(Buffer.from(postExec.stdout.head).toString("utf8"), /POST_UNFREEZE_TS/);

      // 6. exportPatch
      const patch = await client.exportPatch({
        targetFrameId: ckpt.frame.frameId,
        baseFrameId: baseFid,
        owner: "ts-live",
      });
      const diffText = Buffer.from(patch.unifiedDiff).toString("utf8");
      assert.match(diffText, /ts-out\.txt/);
      assert.equal(patch.blake3Hex.length, 64);

      // 7. destroyWorld
      const dw = await client.destroyWorld({
        worldId: wid,
        owner: "ts-live",
        fencingToken: tok,
        idempotencyKey: idempotencyKey("ts-live", "dw-1"),
      });
      assert.equal(dw.world.state, "WORLD_STATE_DESTROYED");

      const elapsed = (performance.now() - t0) / 1000;
      console.log(`\n[AdvisoryWsl2] TypeScript live E2E completed in ${elapsed.toFixed(2)}s`);
    } finally {
      client.close();
    }
  });
});

# 跨设备研发交接与进度基线（Handoff & Progress State）

> **最新同步状态**：**Phase 1 Cold Fork MVP `v0.1.0` 已正式封版（Sealed & Tagged `v0.1.0`）！** 全仓 8 大核心 Rust crate（`aos-types`, `aos-store`, `aos-meta`, `aos-sandbox`, `aos-gw`, `aos-guest`, `agentd`, `aos-cli`）及 Python（`forkloom-vm` `0.1.0a0`）/ TypeScript（`@forkloom-vm/sdk` `0.1.0-alpha.0`）双语薄 gRPC-over-UDS SDK 已在 Windows 与原生 Linux / WSL2（`wsl -d Forkloom-Dev`，Ubuntu 24.04，Linux `6.18.58.1-WSL2`）完成全链路实机闭环验证，全部通过红队 `fsck` 终审门禁（**`0 P0 / 0 P1`**）。下一里程碑：**Phase 2 — Firecracker Live Hot-Fork Engine（`v0.5`）**。

---

## 一、在新电脑上一键恢复研发环境（Linux 裸金属或 Windows + WSL2）

### 1. 克隆组织仓库（切记克隆在原生 Linux 文件系统，严禁放在 `/mnt/c`）
```bash
mkdir -p ~/work/forkloom-vm && cd ~/work/forkloom-vm
git clone git@github.com:forkloom-vm/.github.git dot-github
git clone git@github.com:forkloom-vm/forkloom.git forkloom
```

### 2. 安装系统与虚拟化依赖（Ubuntu 22.04 / 24.04）
```bash
sudo apt-get update && sudo apt-get install -y \
  btrfs-progs xfsprogs e2fsprogs protobuf-compiler clang pkg-config \
  libssl-dev iproute2 nftables conntrack jq unzip musl-tools curl build-essential \
  busybox-static python3-venv
sudo modprobe btrfs
sudo usermod -aG kvm,disk $USER
# 安装 Rust 稳定版与 musl 静态目标
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
~/.cargo/bin/rustup target add x86_64-unknown-linux-musl
# 安装官方 Firecracker & Jailer (v1.10.1+) 至 /usr/local/bin/
```

### 3. 构建 `aos-guest` 并准备实机测试 rootfs（root 执行）
实机测试读取仓库外的 `/var/lib/forkloom/guest-image/`，**缺失时会打印 `skipping` 并计为通过**；切换到改动了 `aos-guest` 的提交后，须重新执行末尾的构建与复制。
```bash
cd ~/work/forkloom-vm/forkloom
G=/var/lib/forkloom/guest-image; R=$G/rootfs-stage
mkdir -p $G/out $R/{bin,dev,etc,lib,lib64,proc,root,run,sbin,sys,tmp,usr/bin,usr/sbin,var/tmp}
chmod 1777 $R/tmp
cp "$(command -v busybox)" $R/bin/busybox
for app in $($R/bin/busybox --list); do [ "$app" = busybox ] || ln -sf busybox "$R/bin/$app"; done
cp -L "$(command -v ip)" "$(command -v ss)" $R/usr/bin/
for lib in $(ldd "$(command -v ip)" "$(command -v ss)" | grep -oE '/[^ ]+\.so[^ ]*' | sort -u); do
  case "$lib" in */ld-linux*) d=$R/lib64 ;; *) d=$R/lib/x86_64-linux-gnu ;; esac
  mkdir -p $d && cp -L "$lib" $d/
done
ln -sfn /sbin/init $R/usr/bin/aos-guest
echo 'root:x:0:0:root:/root:/bin/sh' > $R/etc/passwd
echo 'root:x:0:' > $R/etc/group
echo forkloom-guest > $R/etc/hostname
printf '127.0.0.1 localhost\n::1 localhost\n' > $R/etc/hosts
cargo build -p aos-guest --locked --release --target x86_64-unknown-linux-musl
cp target/x86_64-unknown-linux-musl/release/aos-guest $G/out/aos-guest
cp target/x86_64-unknown-linux-musl/release/aos-guest $R/sbin/init
```

### 4. 验证全仓编译与测试全绿（root 执行）
```bash
cd ~/work/forkloom-vm/forkloom
cargo test --workspace --locked --no-fail-fast 2>&1 | tee /tmp/forkloom-test.log
grep -c skipping /tmp/forkloom-test.log   # 必须为 0
cargo test -p aos-store --test linux_btrfs_live --locked -- --ignored
# Python SDK：安装 SDK 本身及 dev 依赖（其中固定 grpcio-tools 1.85.3，其他版本生成的桩代码会使 --check 失败）
python3 -m venv ~/work/forkloom-vm/venv
~/work/forkloom-vm/venv/bin/pip install -e "./sdk/python[dev]"
(cd sdk/python && ~/work/forkloom-vm/venv/bin/python scripts/gen_proto.py --check)
(cd sdk/python && FORKLOOM_LIVE_E2E=1 ~/work/forkloom-vm/venv/bin/python -m pytest -q)
# TypeScript SDK：需要 Linux 版 Node >= 20。Ubuntu 24.04 源里的 nodejs 是 18，需另装（如 nvm 或 NodeSource）；
# WSL 下注意不要误用 Windows 的 npm。npm test 会先构建再测试
(cd sdk/typescript && npm ci && FORKLOOM_LIVE_E2E=1 npm test)
```

### 5. 在新电脑上无缝唤醒分级特战队（IDE 无关）
在原生 Linux / WSL2 环境直接打开 `~/work/forkloom-vm/forkloom`（支持 Antigravity Swarm / Antigravity IDE / Cursor / VS Code 等任意客户端）。根目录的 `AGENTS.md` 会自动注入五条工程红线与 5 个角色（`fsck` 外部评审 / `Arch-Zero` / `Forge` / `Mach` / `Scout`；原 `SDK` 并入 `Mach`，`monitor` 已取消）。直接对主控会话说：
> **“请阅读 `AGENTS.md` 和 `docs/HANDOFF.md`，按 `Arch-Zero` 总控身份接手项目，基于 `v0.1.0` 冷分叉封版基线启动 Phase 2（Firecracker 热分叉引擎 `v0.5`）。”**

---

## 二、已完成里程碑与关键架构实测结论（重要！）

1. **组织、品牌重构与主仓基建已就位**：
   - **项目更名完成**：已全面从早期代号完成向 **`Forkloom`**（`forkloom-vm/forkloom`、`forkloom.redb`、`/var/lib/forkloom/`、`proto/forkloom/v1/`）的品牌重构与代码对齐。
   - [`forkloom-vm/.github`](https://github.com/forkloom-vm/.github)：组织门面、`SECURITY.md` 与 `ORGANIZATION_PLAN.md`。
   - [`forkloom-vm/forkloom`](https://github.com/forkloom-vm/forkloom)：Cargo Workspace、gRPC `proto/forkloom/v1/runtime.proto`（含版本协商）、Python/TS 瘦 SDK 包声明，以及经红队 `fsck` Gate 1 准入的权威规范文档（含 `ARCHITECTURE_V2.md` v2.1/v2.2 补强与 `INFRA_REQUIREMENTS.md`）。
2. **`crates/aos-types` 已完成并通过 `fsck` Gate 2 代码审计（零 `unsafe`，45 项单测通过）**：
   - 128-bit 规范编码 `WorldId` / `FrameId`、`BootId`、`EpochId`；
   - 真实 `fsync` 屏障构造的 `Persisted<T>`（含 `fsync_subvolume`）、绑定 `BootId` 的 `Ephemeral<T>`、脱敏强校验的 `Untrusted<T>`；
   - 跨平台补丁路径校验器 `PatchPathValidator`（拦截路径穿越、多跳符号链接链逃逸与环路、全变体 `.git` / `.gitmodules`、Windows 保留名及大小写/Unicode 折叠冲突）。
3. **`crates/aos-meta` 已完成并通过 `fsck` Gate 2 代码审计（零 `unsafe`，54 项测试全绿）**：
   - 完整实现 `redb` 单写者唯一提交点（`Preparing -> Committed` 原子状态机、T1/T2 耐久证明与 `verify_unchanged` 校验、幂等键摘要、`TimelineRecord` 归属权 CAS、单调时钟 Pin/World 租约与围栏令牌）；
   - 完整实现 **R0 ~ R6 唯回滚崩溃恢复流水线**（R0 池锁/`POOL_UUID`/`SYS_SCHEMA`/空库保护/分盘守卫，只读 R0/R6 前置熔断与缺失已提交对象反查，R1 纪元递增/跨重启作废 `Volatile` 帧/Pin 租约续期，R2 网关围栏与旧纪元强杀/标记 `WorldState::Lost`，R3 回滚 `Preparing`，R4/R5 完成 `Deleting` 与延迟回收，R6 大小池孤儿熔断阈值与 `quarantine/epoch-<n>/` 隔离宽限期）；
   - 54 项测试（含 50 轮随机故障恢复模型测试 `crash_loop.rs` 及 14 项 Gate 2 回归测试）在 Windows 与 `x86_64-unknown-linux-musl` 交叉编译下全绿，已获 `fsck` 代码审计 `PASS`（Linux 原生 `statfs`/实时崩溃路径待 Linux 主机实测复核）。
4. **`crates/aos-guest` 与 `guest-image/` 已完成并通过 `fsck` Gate 2 代码审计（14 项测试全绿）**：
   - `crates/aos-guest`：4 字节大端长度前缀 JSON 帧协议 v1（`Ping`/`Exec`/`FreezeAndSync`/`PostForkReseed`）、有界流式头尾截断、Reconnect-safe 状态机、受限 `aos.workload/exec-<id>` 子 cgroup 与无竞态 PID-1 孤儿回收、`RNDADDENTROPY`/`RNDRESEEDCRNG` 熵重种与纯 Rust `NETLINK_SOCK_DIAG`/`SOCK_DESTROY`（保留 `127.0.0.0/8`、`::1`、`::ffff:127.0.0.0/104` 回环与 `TCP_LISTEN`/`TCP_TIME_WAIT`）；
   - `guest-image/`：Linux 6.6 LTS 无模块 Firecracker 配置片段（41 项必选 Kconfig 含 `CONFIG_PCI=y` + `CONFIG_ACPI=y` + `CONFIG_VMGENID=y`、`CONFIG_VIRTIO_PCI=n`、`CONFIG_INET_TCP_DIAG=y` + `CONFIG_INET_DIAG_DESTROY=y`）、确定性构建脚本与 fail-closed 只读无网 `inspector.cpio.zst` 构建脚本（含 GPL-2.0 合规声明与 `SHA256SUMS`）。
5. **`benchmarks/phase0-harness` 全量 F0-1 ~ F0-8 实测归档（Track A Gate 2 `PASS`）**：
   - **F0-1 ~ F0-4 存储与池满死锁（`benchmarks/reports/wsl2-baseline/`）**：
     - **[已触发转向并采纳] `redb` 元数据库必须与 Btrfs 数据池分盘/分文件系统存放**：F0-1 同池快照令 `redb` P99 升至 `55.2 ms`（宿主 `ext4` P50 `1.85 ms` / P99 `10.6 ms`）；F0-4 写满 `ENOSPC` 时同池 64B 墓碑删除 100% 失败，释放 `ballast` 后回收率 `99.91%`。确立 `forkloom.redb` 存于宿主独立 `ext4/XFS`（`/var/lib/forkloom/meta/`）。
     - **块镜像保持标准 `Btrfs CoW`**（F0-2），导入封存前预刷 Git index（F0-3）。
   - **F0-5 ~ F0-8 实机 KVM 热分叉与随机强杀恢复（`benchmarks/reports/wsl2-ryzen5800h/`，`Authority: AdvisoryWsl2`，仅作功能与崩溃语义证伪，延迟数字不可外发）**：
     - **F0-8（100 轮实机 `SIGKILL` + cgroup v2 `cgroup.kill`）— `PASS`**：真 `ext4` `meta/` + `Btrfs` `pool/` + `tmpfs` `volatile/`（`allow_same_fs=false`），`live_orphans_killed_by_r2=100`、`preparing_rolled_back=193`、`deleting_completed=37`、`worlds_marked_lost=106`、`orphans_quarantined=10`、`simulated_reboots=5`（含 `tmpfs` 清空）、`final_committed=26`，R6 熔断探针 `tripped=true, objects_untouched=true`，**7 项零泄漏/零丢失指标全部为 `0`**。
     - **F0-6（512 MiB × 4 克隆 `MAP_PRIVATE` + `tmpfs` 配额）— `PASS`**：Sum RSS `62.7 MiB` vs Sum PSS `19.3 MiB`（**3.25x 去重 / 69.2% 物理内存共享**，单克隆 `Private_Dirty` ~`1.31 MiB`）；`tmpfs` 256 MiB 配额超限优雅返回 `ENOSPC` 且 **`oom_kill_delta=0`**。
     - **F0-5（512 MiB 恢复至 `aos-guest` 首条 `Exec /bin/uname -r` 返回）— `PASS`**：冷恢复 `mincore` 捕获 **14.2%** 工作集（`72.64 MiB`，4 extents）；Advisory 端到端 p50：`cold_cache` `90.8 ms`、`hot_cache` `42.9 ms`（对比纯 VMM API `2.32 ms`，印证铁律 2）、`mincore+WILLNEED` `83.4 ms`（含预热）/ `71.6 ms`（预热后）。
     - **F0-7（2 路并发隔离 `netns` 克隆唯一性与回环存活）— `PASS`**：`aos-guest` PID-1 自动拉起 `lo`（零手工 `ip link set lo up`），`FCVMGID:00` + `RNDADDENTROPY`/`RNDRESEEDCRNG` 产出 **2/2 唯一 64B `/dev/urandom`（251/512-bit 汉明距离）**，`NETLINK_SOCK_DIAG` `SOCK_DESTROY` 在 **`0.04 ms`** 内切断外部 TCP（`ECONNABORTED`）同时原 `127.0.0.1:18080` 回环连接池持续正常收发。
   - **[重要实机硬件发现 — AMD Zen 3 + Linux 6.18 KVM + Firecracker v1.10.1]**：在 AMD Ryzen 7 5800H（Zen 3）+ Linux 6.18 宿主内核上恢复 Firecracker `v1.10.1` 快照时，因 `KVM_GET_XSAVE` / `KVM_SET_XSAVE` 未覆盖完整 `XSAVES` 状态，Guest 执行 `XRSTORS` 会触发 `#GP`（`Bad FPU state detected at restore_fpregs_from_fpstate`）。**对策**：Guest `boot_args` 必须携带 **`noxsaves`**，或在 Phase 1/2 将 Firecracker 基线升级至 **`v1.11+ / v1.12+`（启用 `KVM_GET_XSAVE2`）**。
6. **Phase 1 Cold Fork MVP（`v0.1.0`）全栈完成并通过 `fsck` Gate 终审（`0 P0 / 0 P1`）**：
   - **`crates/aos-store`（Btrfs `TreeStore` + `openat2` + 零信任补丁导出，`#58 PASS`）**：
     - 编译期密封 `StorageKind`（`Tree` vs `Block`，`BlockImageHandle` 零宿主 `mount` API 并带 `compile_fail` doctest）；
     - Linux Btrfs 池护栏（拒绝 `/mnt/*`、`9p`、非 `BTRFS_SUPER_MAGIC`、`autodefrag` 及已启用 `qgroups`）与 `ballast` 预分配/池满 `ENOSPC` 自动释放重试；
     - `openat2(RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS)` 逐级受限解包 `import_tar` + `BTRFS_SUBVOL_RDONLY` + `PersistProof::fsync_subvolume`、`create_writable_clone`、`snapshot_readonly`、`destroy_subvolume`、`TreeStoreRecoveryHooks` 及经 `Untrusted<RawPatchBundle>` -> `PatchPathValidator` 强校验的 `export_patch`（含 3 项 Linux 实机 loop-Btrfs 集成测试）。
   - **`crates/aos-sandbox`（加固 `NamespaceDriver` 冷分叉与冻结/解冻，`#61 / #72 PASS`）**：
     - `clone3(CLONE_INTO_CGROUP | CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWUTS | CLONE_NEWNET)` 原子落入 `/sys/fs/cgroup/forkloom.slice/epoch-<e>/w-<id>`；
     - `pivot_root(".", ".")` + `MNT_DETACH`、`/tmp`（64m）与 `/dev/shm`（64m）配额挂载、`SYS_close_range(4, ~0U, CLOSE_RANGE_CLOEXEC)`、全能力集清零、`PR_SET_NO_NEW_PRIVS` 及纯 Rust `x86_64` `seccomp-bpf`（`BTRFS_IOCTL_MAGIC 0x94` 返回 `EOPNOTSUPP`，`clone3` 返回 `ENOSYS` 回退 `clone(2)`，阻断 19 项高危系统调用）；
     - 宿主侧 `WorldHandle::freeze_and_sync`（冻结 `w-<id>` cgroup + `syncfs`）与 `WorldHandle::unfreeze`（支持 `Checkpoint` 后沙箱无缝继续执行）及 `destroy()`（`cgroup.kill` 零残留进程）。
   - **`crates/aos-gw`（零信任出网网关与哈希链加密审计，`#79 PASS`）**：
     - `EpochFenceRegistry` 绑定 `(slot_id, world_id, daemon_epoch)`，`advance_epoch` 立即作废旧纪元绑定并触发 `CancellationToken` 中断在途流；
     - `L1ProxyServer` 显式 HTTP/1.1 反向代理（`host + path_prefix + methods` 细粒度路由、宿主侧凭证注入、反路径走私及直连已校验 `SocketAddr` 的反 DNS 重绑定 SSRF 防护）；
     - `DomainAllowlist` L3 域名白名单（默认 `NXDOMAIN`、阻断 34 类多租户共享 CDN 后缀及 UDP/QUIC-443）；
     - `ReflectionScanner` 跨任意分块边界滑动窗口防凭证反射扫描（Raw / Base64 多相移 / Hex / URL 编码）；
     - `AuditStore` 独立 `0600` 密钥槽（存于 `redb` 之外）+ `XChaCha20-Poly1305` 与 `blake3` 哈希链加密审计段（`.aseg`）+ 双遍覆写 `crypto_shred`。
   - **`proto/forkloom/v1` + `crates/agentd` + `crates/aos-cli`（控制面与生产全链路闭环，`#63 / #74 / #87 PASS`）**：
     - 完整 17 项 gRPC 接口（`SystemService::NegotiateVersion`、`FrameService` 9 项含流式 `ImportTar`、`WorldService` 7 项含流式 `Exec` 与 `Checkpoint`），携带 `x-forkloom-error-bin` 结构化 `ErrorDetail`（`WorldLost` / `OutcomeUnknown` / `FencedOut`）及全参数长度前缀 BLAKE3 幂等摘要与 per-key 并发锁；
     - 严格仅监听 `0600` Unix Domain Socket（`0700` 父目录 + 符号链接拒绝，**零 TCP 监听端口**）；
     - `--backend production` 全量接入 `TreeStoreBackend`、`NamespaceSandboxBackend`、`ProductionRecoveryHooks`（R2 推进 `aos-gw` 纪元围栏 + 强杀旧纪元 cgroup + 回收残留世界子卷，R3–R6 Btrfs 子卷清理）及 `DestroyWorld` 自动解绑网关槽位与 `AuditStore::crypto_shred`（含 `linux_cold_fork_e2e.rs` 与 `gateway_integration_tests.rs` 实机测试全绿）。
   - **`sdk/python` & `sdk/typescript`（双语薄 gRPC-over-UDS SDK 与并发冷分叉 E2E，`#78 / #91 PASS`）**：
     - Python `forkloom-vm`（`0.1.0a0`）与 TypeScript `@forkloom-vm/sdk`（`0.1.0-alpha.0`）完整覆盖 17 项 RPC、强制 `NegotiateVersion` 握手、自动规范化 `unix://` `:authority` 头及 20 类结构化异常解码；
     - WSL2 Linux 实机接入 `agentd --backend production` 端到端测试全绿：Python 4 路 SWE-bench 并发冷分叉采样 + 隔离变更 + `Checkpoint` + 解冻继续执行 + `ExportPatch` 耗时 **`0.31s` [`AdvisoryWsl2`]**，TypeScript 实机全链路 E2E 耗时 **`0.30s` [`AdvisoryWsl2`]**，测试后验证 **`0` 残留进程、`0` Btrfs 挂载、`0` loop 设备、`0` 残留子 cgroup**。

---

## 三、下一阶段任务清单（Next：Phase 2 — Firecracker Live Hot-Fork Engine `v0.5`）

1. **`crates/aos-store` `BlockStore` 与 `Inspector VM` 块级补丁提取（`Forge` 负责）**：
   - 实现 `BlockStore`（`StoreObject<Block>` Btrfs `FICLONE` 块镜像克隆、零宿主挂载铁律）与只读无网 `Inspector VM`（`inspector.cpio.zst`）块级 Diff 提取并接入 `Untrusted<RawPatchBundle>` -> `PatchPathValidator`。
2. **`crates/aos-sandbox` `FirecrackerDriver` 热分叉与 `Volatile`/`Durable` 双档记忆帧（`Forge` 负责）**：
   - 严格按 `Guest FreezeAndSync -> VMM Paused -> Snapshot Create -> Disk FICLONE -> fsync -> VMM Resume -> PostForkReseed (VMGenID + 熵重种 + SOCK_DESTROY)` 顺序实现微虚拟机热快照与 O(1) `MAP_PRIVATE` 内存共享恢复；
   - 在 AMD Zen 3 + Linux 6.18 宿主默认启用 `noxsaves` 或升级 Firecracker `v1.11+`（`KVM_GET_XSAVE2`）。
3. **`agentd` / `aos-cli` / SDK 热分叉编排与池水位保护（`Mach` 负责）**：
   - 在 `agentd` 接入 `FirecrackerDriver`（`--driver firecracker`）、`Volatile` `tmpfs` 配额水位监控与 `Durable` 异步晋升（Promotion）。
4. **已登记的非阻塞 P2 演进项（Phase 2/3 收敛）**：
   - `aos-store`：`safe_tar` 在 `reject_dotgit=false` 时将常规文件/硬链接 `.git` 代理路径一并纳入整包大小写/Unicode-NFD 折叠冲突检查；`import_local_dir` 改为流式管道以限制超大本地工作区峰值 RSS。
   - `agentd` + `aos-gw`：Phase 3 启用强制加密审计时，在 `CreateWorld` 传播 `AuditStore::ensure_world` I/O 错误，并在启动恢复阶段自动清扫已 `Destroyed` 世界的残留 `.key` 槽位。
   - `sdk/typescript`：`live_e2e.test.ts` 在外部传入 `FORKLOOM_LIVE_SOCKET` 模式下使用独立临时目录初始化 `baseDir` 并显式关闭临时文件描述符。
5. **Track B 裸金属基准补采（待租用 Stage 1 裸金属主机）**：在非嵌套裸金属 NVMe 主机补采 `F0-1/F0-2/F0-5/F0-6` 与 Phase 1/2 可外发权威延迟及 16 路克隆 `PSS` 基线。

> **备忘**：按 `AGENTS.md` 现行编制，主会话（`Arch-Zero`）负责研发，`fsck` 由创始人在外部调用 Gemini 系模型评审（主审 `gemini-4-carbon-high`，第二意见 `gemini-4-neon-high`），写代码与评审的模型来自不同厂商。`ARCHITECTURE_V2.md` 第七节（v2.2 补强）与 `meta/forkloom.redb` 独立 `ext4/XFS` 分盘定论已在 Phase 1 `v0.1.0` 生产代码中 100% 落地验证。

# 跨设备研发交接与进度基线（Handoff & Progress State）

> **最新同步状态**：**Phase 0 Track A Gate 2 全面通过（`PASS`）！** `F0-1 ~ F0-8` 全部八大证伪实验已在原生 Linux / WSL2 KVM（`wsl -d Forkloom-Dev`，Ubuntu 24.04，Linux `6.18.58.1-WSL2`，AMD Ryzen 7 5800H `svm=8`，Firecracker `v1.10.1`，自研 Guest Linux `6.6.87` + 静态 `aos-guest` PID-1）实机跑通并通过红队 `fsck` Gate 2 审计（`0 P0 / 0 P1`）。**Phase 1（MVP v0.1：`aos-store` / `aos-sandbox` / `proto/forkloom/v1` / `agentd` / `aos-cli`）现已正式启动（Active）！**（正式性能基线仍须按铁律 2 在 Track B 裸金属采集。）

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
  libssl-dev iproute2 nftables conntrack jq unzip musl-tools curl build-essential
sudo modprobe btrfs
sudo usermod -aG kvm,disk $USER
# 安装 Rust 稳定版与 musl 静态目标
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
~/.cargo/bin/rustup target add x86_64-unknown-linux-musl
# 安装官方 Firecracker & Jailer (v1.10.1+) 至 /usr/local/bin/
```

### 3. 验证全仓编译与单测全绿
```bash
cd ~/work/forkloom-vm/forkloom
cargo test --workspace
```

### 4. 在新电脑上无缝唤醒 5 人特战队（IDE 无关）
在原生 Linux / WSL2 环境直接打开 `~/work/forkloom-vm/forkloom`（支持 Antigravity Swarm / Antigravity IDE / Cursor / VS Code 等任意客户端）。根目录的 `AGENTS.md` 会自动注入工程红线与当前 Swarm 异构编制（`Arch-Zero` / `fsck` / `Forge` / `Mach` / `Scout`）。直接对主控会话说：
> **“请阅读 `AGENTS.md` 和 `docs/HANDOFF.md`，按 `Arch-Zero` 总控身份接手项目，继续推进 Phase 0 下半场（F0-5 ~ F0-8）与 Gate 2 评审。”**

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

---

## 三、当前阶段任务清单（Active：Phase 1 MVP v0.1 单机冷分叉闭环）

1. **`crates/aos-store`（`store` 负责）**：实现编译期双模隔离（`Tree` / `Block`）、Btrfs `TreeStore` 池护栏（拒绝 `qgroups` / `autodefrag`、管理 `ballast`）、`openat2(RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS)` 安全 `import_tar`、`create_writable_clone` / `snapshot_readonly` / `destroy_subvolume` 及经 `Untrusted<PatchBundle>` + `PatchPathValidator` 强校验的 `export_patch`。
2. **`crates/aos-sandbox`（`Forge` 负责）**：实现 `SandboxDriver` + `NamespaceDriver`（`userns`/`mountns`/`pivot_root`/`pidns`/`ipcns`/`utsns`/`netns`、`clone3(CLONE_INTO_CGROUP)`、`PR_SET_NO_NEW_PRIVS` + 降权、严格 `seccomp-bpf` 含 `BTRFS_IOCTL_MAGIC` 返回 `EOPNOTSUPP`）并经继承 `socketpair` 与沙箱内静态 `aos-guest` 通信。
3. **`proto/forkloom/v1/runtime.proto` + `crates/agentd` + `crates/aos-cli`（`Mach` 负责）**：完善 `FrameService` / `WorldService` gRPC 契约（含 `IdempotencyKey`、`FencingToken`、`WorldLost`/`OutcomeUnknown`/`FencedOut` 语义）、构建仅监听 `0600` Unix Domain Socket 的 `agentd` 控制面（接入 `aos-meta` 与 `TreeStore`/`NamespaceDriver` 抽象）及配套 `aos` CLI。
4. **Track B 裸金属基准补采（待租用 Stage 1 裸金属主机）**：在非嵌套裸金属 NVMe 主机补采 `F0-1/F0-2/F0-5/F0-6` 可外发权威延迟与 16 路克隆 `PSS` 基线。

> **备忘**：`ARCHITECTURE_V2.md` 已新增第七节《控制面编排契约、统一客体代理与扩展隔离边界（v2.2 架构补强）》（统一 `aos-guest` 客体代理、分层幂等与 `WorldLost`/`OutcomeUnknown` 契约、租约分层与围栏令牌、`NamespaceDriver` 加固基线、远程控制面前置隔离），路线图顺延为第八节；同时已将 `meta/forkloom.redb` 位置表述对齐上文分盘定论。另将 **Linux 6.7+ Btrfs `squota` 快照性能测试**列入 Phase 1 `TreeStore` 单沙箱配额前置验证候选。

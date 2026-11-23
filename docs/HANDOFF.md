# 跨设备研发交接与进度基线（Handoff & Progress State）

> **最新同步状态**：`forkloom` 品牌重构（`forkloom-vm/forkloom`）已完成；Phase 0 上半场（F0-1 ~ F0-4）已实测归档；`crates/aos-types`（45 项测试）、`crates/aos-meta`（R0-R6 崩溃恢复与单写者提交状态机，54 项测试）与 `crates/aos-guest` + `guest-image/`（14 项测试，Linux 6.6 最小内核配置与只读 Inspector initramfs）均已通过红队 `fsck` **Gate 2 代码审计（`PASS`）**；`benchmarks/phase0-harness` F0-5 ~ F0-8 运行器已落地，待在原生 Linux + KVM 主机执行实测以完成 Phase 0 结项。

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
5. **`benchmarks/phase0-harness` 及 F0-1 ~ F0-4 实测结论（报告位于 `benchmarks/reports/wsl2-baseline/`）**：
   - **[已触发转向并采纳] `redb` 元数据库必须与 Btrfs 数据池分盘/分文件系统存放**：
     - F0-1 实测同池 Btrfs 快照全局事务使 `redb` 提交 P99 升至 `55.2 ms`（宿主 `ext4` 对照组 P50 仅 `1.85 ms`、P99 `10.6 ms`）；
     - F0-4 实测 Btrfs 数据池写满 `ENOSPC` 时，同池 64B 墓碑删除事务 100% 失败，而释放 `ballast` 压舱文件后子卷销毁与空间回收 100% 恢复（回收率 `99.91%`）。因此 **`forkloom.redb` 正式确立存放在宿主独立 `ext4/XFS` 路径（如 `/var/lib/forkloom/meta/forkloom.redb`），不放入 `/var/lib/forkloom/pool/` Btrfs 池内**。
   - **块镜像存储后端保持标准 `Btrfs CoW`**：F0-2 实测在 50,000 随机写碎片 extent + 脏页场景下，`btrfs-cow` 克隆耗时显著优于默认 `xfs-reflink`，且 `btrfs-nocow` 无明显优势，故保留默认 CoW 与数据校验和（待在裸金属主机上二次复核绝对延迟）。
   - **分叉后 Git 索引行为明确**：F0-3 证实 `mkfs.ext4 -d` 免挂载物化 UID/GID/权限零偏差；Btrfs 子卷快照改变 `st_dev` 会令分叉后首次 `git status` 重刷一次 index，导入封存前应预刷 index。

---

## 三、下一阶段紧接任务清单（Next Up：原生 Linux + KVM 实机压测与 Phase 0 结项）

1. **在原生 Linux / KVM 环境构建最小 Guest 镜像**（`guest-image/build-kernel.sh` + `guest-image/build-inspector-initramfs.sh`）：编译 Linux 6.6 LTS `vmlinux`（校验全部 41 项必选 Kconfig），交叉构建 `x86_64-unknown-linux-musl` 静态 `aos-guest` 并打包最小根文件系统与 `inspector.cpio.zst`。
2. **在原生 Linux + KVM 主机跑通 `F0-5` ~ `F0-8` 实机证伪报告**（`phase0-harness`，正式性能基线必须在裸金属 Linux KVM 采集）：
   - `f0-8-kill9-recovery`：在独立 `meta/`（ext4/XFS）与 `pool/`（Btrfs）分文件系统 + cgroup v2 `cgroup.kill` 环境下完成 100 轮实机随机 `kill -9` 恢复压测；
   - `f0-5-fc-restore`：采集冷缓存 / 热缓存 / `mincore` + `fadvise(WILLNEED)` 三档恢复至 `aos-guest` 首条 `vsock` 命令返回延迟；
   - `f0-6-mem-sharing`：采集磁盘池（`Durable`）与配额 `tmpfs`（`Volatile`）快照写出耗时、`tmpfs` 超配额 `ENOSPC` / 零 OOM 校验及多克隆 `/proc/<pid>/smaps_rollup` 物理共享率（PSS）；
   - `f0-7-clone-unique`：实机验证 `VMGenID` + `RNDADDENTROPY`/`RNDRESEEDCRNG` 熵池发散、外部 TCP 立即切断及 `127.0.0.1` 回环连接池存活。
3. **红队 `fsck` Gate 2 实机报告签收与 Phase 1 启动**：归档 F0-5 ~ F0-8 实机报告，正式进入 Phase 1（`aos-store` / `aos-sandbox` / `aos-gw` / `agentd`）。

> **备忘**：`ARCHITECTURE_V2.md` 已新增第七节《控制面编排契约、统一客体代理与扩展隔离边界（v2.2 架构补强）》（统一 `aos-guest` 客体代理、分层幂等与 `WorldLost`/`OutcomeUnknown` 契约、租约分层与围栏令牌、`NamespaceDriver` 加固基线、远程控制面前置隔离），路线图顺延为第八节；同时已将 `meta/forkloom.redb` 位置表述对齐上文分盘定论。另将 **Linux 6.7+ Btrfs `squota` 快照性能测试**列入 Phase 1 `TreeStore` 单沙箱配额前置验证候选。

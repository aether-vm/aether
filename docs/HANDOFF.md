# 跨设备研发交接与进度基线（Handoff & Progress State）

> **最新同步状态**：Phase 0 上半场（存储与池满死锁证伪 F0-1 ~ F0-4）已实测完成并归档，待启动 Phase 0 下半场（Firecracker 热分叉与随机强杀恢复 F0-5 ~ F0-8）。

---

## 一、在新电脑上一键恢复研发环境（Linux 裸金属或 Windows + WSL2）

### 1. 克隆组织仓库（切记克隆在原生 Linux 文件系统，严禁放在 `/mnt/c`）
```bash
mkdir -p ~/work/aether-vm && cd ~/work/aether-vm
git clone git@github.com:aether-vm/.github.git dot-github
git clone git@github.com:aether-vm/aether.git aether
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
cd ~/work/aether-vm/aether
cargo test --workspace
```

### 4. 在新电脑的 Cursor 中无缝唤醒 5 人特战队
使用 Cursor（若为 Windows 请点左下角远程图标 `Connect to WSL`）直接打开 `~/work/aether-vm/aether`。根目录的 `AGENTS.md` 会自动注入会话上下文。直接对新会话的主控模型说：
> **“请阅读 `AGENTS.md` 和 `docs/HANDOFF.md`，按 `Arch-Zero` 总控身份接手项目，继续推进 Phase 0 下半场（F0-5 ~ F0-8）。”**

---

## 二、已完成里程碑与关键架构实测结论（重要！）

1. **组织与主仓基建已就位**：
   - [`aether-vm/.github`](https://github.com/aether-vm/.github)：组织门面、`SECURITY.md` 与 `ORGANIZATION_PLAN.md`。
   - [`aether-vm/aether`](https://github.com/aether-vm/aether)：Cargo Workspace、gRPC `proto/aether/v1/runtime.proto`（含版本协商）、Python/TS 瘦 SDK 包声明，以及三份经红队 `fsck` Gate 1 准入的权威规范文档。
2. **`crates/aos-types` 已完成（零 `unsafe`，42 项单测通过）**：
   - 128-bit 规范编码 `WorldId` / `FrameId`、`BootId`、`EpochId`；
   - 真实 `fsync` 屏障构造的 `Persisted<T>`、绑定 `BootId` 的 `Ephemeral<T>`、脱敏强校验的 `Untrusted<T>`；
   - 跨平台补丁路径校验器 `PatchPathValidator`（拦截路径穿越、符号链接逃逸、全变体 `.git`、Windows 保留名及大小写/Unicode 折叠冲突）。
3. **`benchmarks/phase0-harness` 及 F0-1 ~ F0-4 实测结论（报告位于 `benchmarks/reports/wsl2-baseline/`）**：
   - **[已触发转向并采纳] `redb` 元数据库必须与 Btrfs 数据池分盘/分文件系统存放**：
     - F0-1 实测同池 Btrfs 快照全局事务使 `redb` 提交 P99 升至 `55.2 ms`（宿主 `ext4` 对照组 P50 仅 `1.85 ms`、P99 `10.6 ms`）；
     - F0-4 实测 Btrfs 数据池写满 `ENOSPC` 时，同池 64B 墓碑删除事务 100% 失败，而释放 `ballast` 压舱文件后子卷销毁与空间回收 100% 恢复（回收率 `99.91%`）。因此 **`aether.redb` 正式确立存放在宿主独立 `ext4/XFS` 路径（如 `/var/lib/aether/meta/aether.redb`），不放入 `/var/lib/aether/pool/` Btrfs 池内**。
   - **块镜像存储后端保持标准 `Btrfs CoW`**：F0-2 实测在 50,000 随机写碎片 extent + 脏页场景下，`btrfs-cow` 克隆耗时显著优于默认 `xfs-reflink`，且 `btrfs-nocow` 无明显优势，故保留默认 CoW 与数据校验和（待在裸金属主机上二次复核绝对延迟）。
   - **分叉后 Git 索引行为明确**：F0-3 证实 `mkfs.ext4 -d` 免挂载物化 UID/GID/权限零偏差；Btrfs 子卷快照改变 `st_dev` 会令分叉后首次 `git status` 重刷一次 index，导入封存前应预刷 index。

---

## 三、下一阶段紧接任务清单（Next Up：Phase 0 下半场 F0-5 ~ F0-8）

1. **构建最小化测试用 Guest 内核与 `aos-guest` 原型**（`guest-image/` + `crates/aos-guest`）：开启 `CONFIG_VMGENID=y`、`CONFIG_HW_RANDOM_VIRTIO=y`、`CONFIG_INET_DIAG_DESTROY=y`、`CONFIG_CGROUP_FREEZER=y`、`CONFIG_VSOCKETS=y`。
2. **实现并跑通 `F0-5` & `F0-6`**：测量 Firecracker 快照恢复至 `vsock` 首条命令返回延迟（冷缓存 / 热缓存 / `mincore` + `fadvise(WILLNEED)` 预热）及 `File Backend (MAP_PRIVATE)` 多克隆物理内存共享率（PSS）。
3. **实现并跑通 `F0-7`**：验证热分叉恢复后随机数熵池发散、`ss -K` 秒断外部连接及 Guest 内 `127.0.0.1` 回环连接存活。
4. **实现 `crates/aos-meta` 最小提交恢复状态机并跑通 `F0-8`**：100 次随机 `kill -9` 强杀恢复零孤儿泄漏验证，随后提请红队 `fsck` 进行 **Gate 2（Phase 0 结项与 Phase 1 准入）** 评审。

> **备忘**：`ARCHITECTURE_V2.md` 已新增第七节《控制面编排契约、统一客体代理与扩展隔离边界（v2.2 架构补强）》（统一 `aos-guest` 客体代理、分层幂等与 `WorldLost`/`OutcomeUnknown` 契约、租约分层与围栏令牌、`NamespaceDriver` 加固基线、远程控制面前置隔离），路线图顺延为第八节；同时已将 `meta/aether.redb` 位置表述对齐上文分盘定论。另将 **Linux 6.7+ Btrfs `squota` 快照性能测试**列入 Phase 1 `TreeStore` 单沙箱配额前置验证候选。

# Forkloom 研发与压测基础设施环境规格书（Infrastructure & Testbed Requirements）

> **文档定位**：回答"创始人该找什么机器、什么时候租什么服务器、机器到手怎么 30 秒验收"。本文**不定义任何性能指标或门禁阈值**，指标与转向门禁的唯一权威源仍是 [`PHASE0_FALSIFICATION.md`](./PHASE0_FALSIFICATION.md)。  
> **对齐来源**：`PHASE0_FALSIFICATION.md`（F0-1 ~ F0-8、双轨基线、红队铁律 2）、`ARCHITECTURE_V2.md`（v2.1 存储池布局 / 热快照顺序 / 恢复协议）、`HANDOFF.md`（已实测结论与环境恢复步骤）、`AGENTS.md`（五条工程红线）、`README.md`（仓库布局、`guest-image/` 内核约束）。  
> **红队铁律 2（本文全程适用）**：任何未注明**宿主机硬件型号、内核版本、底层文件系统、供电状态（有无 PLP）与页缓存冷热前提**的性能数字一律无效。**WSL2（L2 嵌套虚拟化）只验证功能正确性与崩溃语义，其延迟数字严禁对外发布为性能基线。** 附录 A 提供一键采集这些前提的"环境指纹"命令，每份压测报告必须附带。

---

## 0. 对齐说明与已识别的文档差异（请创始人知悉）

| # | 差异点 | 本文处理方式 |
| :--- | :--- | :--- |
| 1 | `PHASE0_FALSIFICATION.md` §1.1 记录的本地机为 Surface Pro 8（i5-1135G7 / C 盘剩余 ~56GB）；创始人当前实际可用主机为 **i5-9400 6C/6T、16GB RAM、`C:` 仅剩 ~7.5GB**。 | A2 章节按**当前实际主机**编写（更严苛）。`PHASE0_FALSIFICATION.md` §1.1 待创始人确认后另行同步，本文不改动该唯一指标源。 |
| 2 | `ARCHITECTURE_V2.md` §3.1 / §4.2 仍以 `pool/` 下的 `meta/` 描述 `redb`；`HANDOFF.md` §二（F0-1 实测 P99 `55.2 ms`、F0-4 同池墓碑事务 100% 失败）已定论 **`forkloom.redb` 必须放在 Btrfs 池之外的独立 `ext4/XFS`**。 | 本文一律按 `HANDOFF.md` 定论：`/var/lib/forkloom/meta`（`ext4/XFS`）与 `/var/lib/forkloom/pool`（Btrfs）**分文件系统**。架构书措辞待 Gate 2 后由 `Arch-Zero` 统一修订。 |
| 3 | `HANDOFF.md` 记录 F0-2 在 WSL2 上 `btrfs-cow` 优于默认 `xfs-reflink`，但明确"待裸金属二次复核绝对延迟"。 | Track B Stage 1 **必须预留 XFS（`reflink=1`）对照分区**，不得因 WSL2 结论省略。 |
| 4 | Phase 0 手册要求 WSL2 存储池 `<= 12 GiB`，`AGENTS.md` 红线 1 写 `<= 16 GiB`。 | 取默认 **12 GiB**、绝对上限 **16 GiB**（两者不冲突，取更严者为默认）。 |

---

## 一、双轨制测试台总体策略（为什么拆成两类机器）

**核心矛盾**：功能与崩溃语义正确性需要"随时可跑、7×24 在线、零边际成本"的机器；而权威性能数字需要"无嵌套虚拟化损耗、独占 NVMe、真实 ECC 内存"的机器——后者贵，不应常开。拆开后，**日常 95% 的工作量在 Track A 零云成本完成，只有需要对外发布数字的那几个小时才在 Track B 付费**。

| 维度 | **Track A：常驻功能与崩溃语义验证台** | **Track B：按需云端裸金属性能与高密度基准台** |
| :--- | :--- | :--- |
| 形态 | 本地物理机 / 局域网闲置主机（A1，首选）；Windows 11 + WSL2（A2，备选） | 云或托管**真裸金属**，按小时租用（或短租），测完立即释放 |
| 成本模型 | 一次性硬件投入 / 零增量云成本，7×24 可开 | 按阶段、按小时计费；每次开机前必须在 Track A 完成**彩排** |
| 承担工作 | 日常 Rust 内核研发、Guest 内核编译、`F0-5 ~ F0-8` **功能**可行性、`kill -9` 崩溃恢复验证、Phase 1~3 日常集成测试 | `F0-1 ~ F0-2` 裸金属复核、`F0-5 ~ F0-6` 大规格多克隆延迟与 `PSS` 共享率、Phase 1 SWE-bench 并发评测、Phase 2 万次分叉烤机、Phase 3 `aos-gw` 吞吐压测 |
| 可发布的数字 | A1（原生 Linux 裸机）：可发布，但须按铁律 2 标注规格；A2（WSL2）：**严禁发布延迟数字** | 权威基线唯一来源（须附环境指纹） |
| 禁止事项 | A2 严禁在 `/mnt/c` 跑实验；严禁把 WSL 显示的 950G 当真实容量 | 严禁普通云虚机（无 `/dev/kvm`）；严禁 L2 嵌套云虚机冒充裸金属 |

### 1.1 任务 → 机器分配矩阵

| 工作项 | Track A1 | Track A2 (WSL2) | Track B | 备注 |
| :--- | :---: | :---: | :---: | :--- |
| Rust 日常编译 / `cargo test --workspace` | ✅ | ✅ | — | |
| Guest Linux 内核编译（`guest-image/`） | ✅ 推荐 | ⚠️ 可行但慢 | — | A2 需放 WSL 原生盘，勿碰 `/mnt/c` |
| `F0-1 ~ F0-4`（存储、池满） | ✅ 复跑 | ✅ 已完成（`HANDOFF.md`，仅作功能结论） | ✅ **裸金属复核绝对延迟** | WSL2 数字已标注不可发布 |
| `F0-5`（恢复到首条命令延迟） | ✅ 功能 + 相对对比 | ⚠️ 仅 512MiB 烟雾验证 | ✅ **权威采集（512MiB / 2GiB）** | 须分冷缓存 / 全热 / `mincore`+`WILLNEED` 三档 |
| `F0-6`（快照耗时 + `PSS` 共享率） | ✅ 4~8 克隆 | ⚠️ 256~512MiB × 4 | ✅ **16 克隆、`Volatile tmpfs` 16GiB 配额实测** | |
| `F0-7`（唯一性 / 回环连接存活） | ✅ | ✅ | — | 纯功能语义 |
| `F0-8`（`kill -9` ×100 零孤儿） | ✅ | ✅ | ✅ Stage 3 长稳复核 | 纯崩溃语义，Track A 即可结项 |
| Phase 1 SWE-bench 并发评测 | 功能回归 | ❌ | ✅ Stage 2 | |
| Phase 2 万次分叉烤机 / 故障注入 | 小规模预演 | ❌ | ✅ Stage 3 | |
| Phase 3 `aos-gw` 吞吐压测 | 功能回归 | ❌ | ✅ Stage 3 | 需额外压测发生机 |

---

## 二、Track A：本地常驻可行性验证机规格

### 2.1 首选 A1：局域网独立 x86_64 闲置物理机 / 迷你主机 / 工作站（原生 Linux，零嵌套损耗）

| 项目 | 最低要求 | 推荐配置 | 说明 |
| :--- | :--- | :--- | :--- |
| **CPU 架构** | **x86_64**，Intel **VT-x + EPT** 或 AMD **AMD-V + RVI（NPT）** | 同左 | Phase 0 基线与 Firecracker `VMGenID` 路径锁定 `x86_64`；**暂不以 ARM64（Apple Silicon / Graviton 等）为主测架构**，不对其做性能或兼容性承诺。 |
| **核心数** | 6~8 物理核 | **8C/16T 及以上** | 需同时承载 `cargo` 编译、多个 Firecracker 实例与池 I/O 压力。 |
| **CPU 备注** | 官方 Firecracker 支持矩阵之外的消费级 CPU 可用于功能验证 | 非混合架构（无 P/E 核）更利于低抖动 | Intel 12 代及以后 P/E 混合核计时有抖动，做计时实验需 `taskset` 绑定 P 核；Firecracker 快照跨 CPU 型号恢复不保证，`Durable Frame` 元数据按 `ARCHITECTURE_V2.md` 要求记录版本指纹。 |
| **内存** | 16 GB | **32 GB DDR4/DDR5** | 32 GB 方便跑 8 克隆 + `tmpfs`（`Volatile`）配额实验；无需 ECC。 |
| **磁盘** | NVMe SSD ≥ 256 GB | **NVMe SSD 512 GB** | 必须是 NVMe（SATA 可用于功能验证但不具备参考价值）。分盘铁律见 §2.3。 |
| **BIOS 必开** | Intel VT-x / VT-d 或 AMD SVM（含 IOMMU 可选） | 同左 | 关闭会干扰计时的深度省电（C-state 深睡 / 降频），或在 OS 内将 governor 切为 `performance`（见 §4.1 脚本）。 |
| **操作系统** | Ubuntu 22.04 LTS **HWE** 内核 ≥ **6.5**（备选） | **Ubuntu 24.04 LTS Server**，内核 ≥ **6.8**（首选） | 与 `HANDOFF.md` §一（22.04 / 24.04）一致；Server 版无桌面，减少后台噪声。 |
| **网络 / 接入** | 千兆有线、局域网**固定 IP**（路由器 DHCP 绑定或静态） | 同左 | 开启 OpenSSH Server；当前主力机配置 **SSH 免密登录**；被控机配置 `sudo NOPASSWD`（见下）。 |

**SSH 免密与 sudo 免密（在主力机 / 被控机上执行）**：

```bash
# 主力机（Windows PowerShell 或 WSL）：生成密钥并分发到 Linux 机器
ssh-keygen -t ed25519 -C "forkloom-founder"
ssh-copy-id <user>@<固定IP>          # Windows 无 ssh-copy-id 时手工追加公钥到 ~/.ssh/authorized_keys

# Linux 被控机：开启 SSH，授予 sudo 免密（仅限该专用测试机！）
sudo apt-get install -y openssh-server && sudo systemctl enable --now ssh
echo "<user> ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/90-forkloom-dev
sudo chmod 0440 /etc/sudoers.d/90-forkloom-dev && sudo visudo -c
```

> 安全提示：`NOPASSWD:ALL` 与 `disk` 组（`HANDOFF.md` 要求）等同于 root 权限，**仅限不存放敏感数据的专用测试机**；Track B 云机用完即毁，不要复用个人密钥之外的任何凭据。

**A1 参考机型示例（非采购推荐，仅帮助找机器）**：近 5~6 年的 8 核 x86 迷你主机 / 小型工作站（如 Ryzen 5/7 5000 系或更新、Intel 10~11 代 i5/i7 级别）+ 32GB 内存 + 512GB NVMe。闲置老台式机满足上表即可。

### 2.2 备选 A2：复用当前 Windows 11 主机（WSL2 L2 嵌套虚拟化模式）

**适用场景**：只在没有 A1 机器时过渡；只做**功能与崩溃语义**验证，**不产出可发布性能数字**（`AGENTS.md` 红线 1）。

| 项目 | 当前实际值 | 硬性限制与配置 |
| :--- | :--- | :--- |
| 主机 | `i5-9400`，6C/**6T**（无超线程），16GB RAM | 嵌套虚拟化需 Win11 + 开启 VT-x；`/dev/kvm` 需在 WSL 内可用且当前用户在 `kvm` 组。 |
| 系统盘 | **`C:` 仅剩 ~7.5GB** | **严禁将 WSL2 发行版 / VHDX / 存储池放在 C 盘**。必须放 `E:\wsl\` 或 `D:\wsl\`。 |
| WSL 发行版位置 | — | 新装：`wsl --import Ubuntu-24.04 E:\wsl\Ubuntu-24.04 <rootfs.tar>`；已装在 C 盘的发行版：`wsl --manage <发行版> --move E:\wsl\<目录>`（WSL ≥ 2.3），或 `wsl --export` + `--import` 迁移后 `--unregister` 原发行版。 |
| `.wslconfig`（`C:\Users\<用户>\.wslconfig`，文件很小可留 C 盘） | — | `memory=8GB`、`processors=6`、`nestedVirtualization=true`；改完 `wsl --shutdown`。 |
| 存储池封顶 | WSL 虚拟盘会显示 ~950G | **默认 `12 GiB`，绝对上限 `16 GiB`**（Phase 0 手册 / `AGENTS.md`）；池文件放 WSL 原生路径 `/var/lib/forkloom/`，**严禁触碰 `/mnt/c`、`/mnt/e`**；`ballast` 按池大小比例缩小（生产为 `2GiB`）。 |
| 可跑规格 | — | **`256MiB ~ 512MiB × 4` 个克隆**的功能验证；`2GiB` 规格仅限单实例冒烟，不跑多克隆。 |
| 数字使用规则 | — | 报告必须写明 `WSL2 L2 nested`；**严禁将延迟数字作为正式指标发布**，仅可用于相对对比与功能结论。 |
| 内核 | `6.6.x-microsoft-standard-WSL2`（Phase 0 手册记录值） | 低于 Track A1 / B 的 `6.8` 要求，属已知差异，已在铁律 2 标注范围内。 |

### 2.3 存储分盘铁律与目录 / 分区落地方案（Track A 与 Track B 通用）

**铁律**（`HANDOFF.md` 定论 + `AGENTS.md` 红线 3/4）：

1. **`/var/lib/forkloom/meta/`（含 `forkloom.redb`、加密审计 `audit/`）** 必须位于**宿主原生 `ext4` 或 `XFS`**；
2. **`/var/lib/forkloom/pool/`** 为**独立 Btrfs 存储池**（`TreeStore` 子卷 + `BlockStore` 稀疏块镜像 `FICLONE`），**不得与 `meta/` 同一文件系统**；
3. Btrfs 池**禁用 `qgroups` 与 `autodefrag`**；块镜像**不设全局 `NOCOW`**（保留 CoW 与校验和）；预分配 `ballast` 压舱文件（生产 `2GiB`）；
4. `Volatile Frame` 的内存镜像放独立配额 `tmpfs`（`size=` 硬封顶，超限返回 `ResourceExhausted` 而非触发宿主 OOM）。

**三种落地层级**（越靠上越接近"真实 NVMe 物理极限"，越靠下越只适合功能验证）：

| 层级 | 方案 | 适用 | 能否产出正式性能数字 |
| :--- | :--- | :--- | :--- |
| **L1 独立分区 / 独立盘（首选）** | `meta` 用 `ext4/XFS` 分区；`pool` 用**裸 NVMe 分区直接 `mkfs.btrfs`**；另留 XFS 分区做 F0-2 对照 | Track B；Track A1 有空闲分区 / 第二块盘时 | ✅（须附环境指纹） |
| **L2 同盘多分区** | 单块 NVMe 上划分 3 个分区（见下表），分区间共享同一块 SSD 的 GC/写缓存 | Track A1 单盘机器 | ⚠️ 仅相对对比，须注明"同盘分区" |
| **L3 Loop 文件池（兜底）** | 根盘 `ext4` 上 `truncate -s <size> pool.img` → `mkfs.btrfs` → `mount -o loop` | Track A2 WSL2、无空闲分区的 A1 | ❌ 含 loop 层与宿主文件系统叠加开销，仅限功能验证 |

**L1/L2 参考分区（单块 512GB NVMe，Track A1）**：

| 分区 | 大小 | 文件系统 | 挂载点 | 用途 |
| :--- | :--- | :--- | :--- | :--- |
| `p1` | 1 GiB | FAT32 | `/boot/efi` | UEFI |
| `p2` | ~120 GiB | `ext4` | `/`，含 `/var/lib/forkloom/meta` | 系统、`forkloom.redb`、审计日志 |
| `p3` | ~250 GiB | **Btrfs**（`mkfs.btrfs -L forkloom-pool`） | `/var/lib/forkloom/pool` | 存储池 |
| `p4` | ~100 GiB | XFS（`mkfs.xfs -m reflink=1`） | `/var/lib/forkloom-xfs-ctl` | F0-2 对照组 |
| 余量 | ≥ 10% 不分区 | — | — | SSD 过量预留，降低稳态写放大 |

```bash
# ===== L1/L2：独立分区（示例设备名 /dev/nvme0n1p3 / p4，务必先 lsblk 核对！以下命令破坏性） =====
sudo mkfs.btrfs -f -L forkloom-pool /dev/nvme0n1p3
sudo mkfs.xfs  -f -m reflink=1 -L forkloom-xfs /dev/nvme0n1p4
sudo mkdir -p /var/lib/forkloom/{meta,pool,volatile} /var/lib/forkloom-xfs-ctl
# 用 UUID 写入 fstab（noatime；nosuid,nodev：沙箱写入的文件保留宿主属主，agentd 另把 pool 目录设为 0700；不加 autodefrag；不启用 qgroups）
echo "UUID=$(sudo blkid -s UUID -o value /dev/nvme0n1p3) /var/lib/forkloom/pool btrfs noatime,nosuid,nodev 0 0" | sudo tee -a /etc/fstab
echo "UUID=$(sudo blkid -s UUID -o value /dev/nvme0n1p4) /var/lib/forkloom-xfs-ctl xfs noatime 0 0" | sudo tee -a /etc/fstab
sudo mount -a

# ===== L3：Loop 文件池（WSL2 / 无空闲分区时；WSL2 严格 <= 12~16GiB） =====
sudo mkdir -p /var/lib/forkloom/{meta,pool,volatile} /var/lib/forkloom/img
sudo truncate -s 12G /var/lib/forkloom/img/pool.img        # WSL2 默认 12G，上限 16G
sudo mkfs.btrfs -f -L forkloom-pool /var/lib/forkloom/img/pool.img
sudo mount -o loop,noatime,nosuid,nodev /var/lib/forkloom/img/pool.img /var/lib/forkloom/pool
# 注意：pool.img 与 meta/ 虽同在根盘 ext4，但 pool 内部是独立 Btrfs 文件系统，
#       满足"meta 与 pool 分文件系统"的功能语义；性能数字仍不可发布。

# ===== 通用：Volatile tmpfs 硬配额（A1: 4G / A2: 2G / Track B Stage 1: 16G） =====
sudo mount -t tmpfs -o size=4G,mode=0700 tmpfs /var/lib/forkloom/volatile

# ===== 通用：确认池护栏（只读） =====
findmnt -no FSTYPE,OPTIONS -T /var/lib/forkloom/pool    # 期望 btrfs，且 OPTIONS 不含 autodefrag
findmnt -no FSTYPE -T /var/lib/forkloom/meta            # 期望 ext4 或 xfs
sudo btrfs qgroup show /var/lib/forkloom/pool 2>&1 | head -n1   # 期望 "quotas not enabled" 类提示
```

> **全新 SSD 稳态预处理（Track B 必做，Track A1 推荐）**：对**不含数据**的新盘先 `sudo blkdiscard /dev/nvmeXn1`（**破坏性**）再分区，并在正式采集前对池区预写 / `fstrim`，避免"空盘虚高"。每次采集前的页缓存状态（`drop_caches` 冷 / 全热 / `WILLNEED` 预热）按 Phase 0 手册 F0-5 要求显式记录。

---

## 三、Track B：真实性能基准与分阶段压测服务器规格

> **通用硬规则**：
> 1. 必须是**真裸金属**或明确提供 `/dev/kvm` 且**非嵌套**的独占整机；开机后第一件事跑 §5 脚本（`TRACK=B`），出现 `[FAIL]` 立即释放，不开始计费采集。
> 2. 存储必须是**本地直通 NVMe**（实例存储 / 本地盘）。**网络块存储（如 AWS EBS、各云厂商云盘）不得作为 fsync / FICLONE 延迟基线盘。**
> 3. 开机前先在 Track A 用**同一套脚本与同一份 `phase0-harness`** 彩排，确认脚本无误再开机，避免为调试脚本付费。
> 4. 报告附环境指纹（附录 A）。

### 3.1 分阶段规格对比矩阵

| 项目 | **Stage 1：Phase 0 结项权威基准** | **Stage 2：Phase 1 SWE-bench 冷分叉并发评测 / MVP v0.1** | **Stage 3：Phase 2 & 3 热分叉烤机 / 长稳 / `aos-gw` 压测** |
| :--- | :--- | :--- | :--- |
| 对应实验 | `F0-1 ~ F0-2` 裸金属复核；`F0-5 ~ F0-6` 大规格多克隆延迟与 `PSS`；顺带复跑 `F0-3 ~ F0-4` 取绝对值 | SWE-bench 真实仓库 Btrfs 子卷冷分叉并发评测；5 万小文件物化；MVP v0.1 发布基准 | Firecracker 高密度热分叉烤机；万次分叉销毁无泄漏；随机 `kill -9` 故障注入长稳；`aos-gw` L1/L2/L3 吞吐压测 |
| **预计租期**（估算，非承诺） | 核心采集 **2~4 小时**；计费窗口建议留 +1h 装机缓冲 | 每轮评测约 8~24 小时 × 2~3 轮（可多次短租） | 每轮烤机约 24~72 小时 × 1~2 轮；v1.0 发布前一轮 72h 长稳 |
| **机型** | 真裸金属：AWS `*.metal` / 阿里云神龙 `ecs.ebm*` / Hetzner Dedicated / Vultr Bare Metal / 腾讯云黑石 | 同左（优先裸金属，保证数字可发布） | 同左（须裸金属） |
| **CPU** | x86_64 **≥ 16 物理核**；Intel Xeon Ice Lake / Sapphire Rapids 或 AMD EPYC Milan / Genoa | **16~32 物理核** | **32~64 物理核** |
| **内存** | **64 ~ 128 GB ECC** | **64 ~ 128 GB ECC** | **128 ~ 256 GB ECC** |
| **存储** | **本地直通 NVMe × 2**（或单盘 ≥ 500 GB 划两个独立分区），详见 §3.2 | **≥ 1 TB 本地 NVMe**（数十个大型 Docker/OCI 评测镜像 + 5 万小文件物化 + 高并发 Btrfs 子卷冷分叉） | **双企业级 NVMe，各 ≥ 1~2 TB，优选带 PLP（掉电保护）**，用于验证高频 `fsync` 真实延迟 |
| **网络** | 公网出向即可（拉工具链、Firecracker 二进制） | **稳定公网带宽**（拉取 OCI 镜像与 GitHub 数据集；建议同区域私有 registry / 对象存储缓存预构建镜像） | 同 Stage 2；**另需 1 台压测发生机**（见 §3.3），与被测机同机房 / 同 VPC，≥ 10GbE 内网更佳 |
| **内核** | Ubuntu 24.04，Linux **≥ 6.8** | 同左 | 同左（`>= 6.8`） |
| **关键产出** | Phase 0 结项 Gate 2 的权威数字（附环境指纹） | MVP v0.1 发布基准报告 | v0.5 / v1.0 烤机报告：零泄漏、零孤儿、`fsync` P99、网关吞吐 |

> Stage 2 补充：SWE-bench 镜像体积随子集（Lite / Verified / Full）和是否保留 env 层差异很大，**1 TB 是 Lite/Verified 子集的起步规格**；Full 全量评测应按实际镜像清单扩盘，并在评测结束后及时 `docker system prune`。若用云虚机（非裸金属）执行 Stage 2，只可用于**功能与吞吐回归**，对外数字必须注明虚拟化层并受铁律 2 约束。

### 3.2 Stage 1 磁盘与文件系统布局（权威采集的关键）

| 盘 / 分区 | 文件系统 | 挂载点 | 内容 | 设计意图 |
| :--- | :--- | :--- | :--- | :--- |
| **NVMe-0（或分区 1）** | `ext4` 或 `XFS` | `/`（系统）与 `/var/lib/forkloom/meta` | `forkloom.redb`、加密审计日志 `audit/`（不含池内对象） | `redb` `fsync` 与池快照事务**物理隔离**，复核 F0-1 的 P99 门禁（`> 50ms` 即转向）。 |
| **NVMe-1（或分区 2，≥ 250 GB）** | **原生裸分区 `Btrfs`**（**不用 loop 文件层**） | `/var/lib/forkloom/pool` | `TreeStore` 子卷、`BlockStore` 块镜像 | 去掉 loop 层开销，测出真实 NVMe 物理极限；禁 `qgroups`、`autodefrag`。 |
| **NVMe-1 预留小分区（≥ 100 GB）** | `XFS`（`mkfs.xfs -m reflink=1`，必要时调 `cowextsize`） | `/var/lib/forkloom-xfs-ctl` | F0-2 对照组 | 在**同一块盘**上与 Btrfs 对比 `FICLONE + fsync`，排除盘间差异。 |
| **内存盘** | `tmpfs`，`size=16G` | `/var/lib/forkloom/volatile` | `Volatile Frame` 内存镜像 | 实测配额耗尽时返回 `ResourceExhausted` 而不触发宿主 OOM；与 `16 GiB` 配额实验口径一致。 |

**Stage 1 内存推算**：`2 GiB × 16` 路克隆并发恢复（即便 `MAP_PRIVATE` 共享，**冷缓存与脏页峰值**仍需余量）+ `16 GiB` `tmpfs` + 冷/热页缓存对比 + 宿主与工具链开销 ⇒ **最低 64 GB，推荐 128 GB ECC**。

单盘 500 GB 机器参考切分：`~80 GB ext4（/ + meta）` / `~280 GB Btrfs` / `~100 GB XFS 对照` / 余量不分区。

### 3.3 Stage 3 附加：压测发生机与测量要求

| 项目 | 要求 |
| :--- | :--- |
| 压测发生机（`aos-gw` 吞吐 / 并发连接） | 8 核 / 16 GB 即可，Ubuntu 24.04，与被测机**同可用区 / 同机房**，避免公网抖动污染延迟；记录两机之间 RTT |
| PLP 与写缓存 | 记录 `nvme id-ctrl` 的 `vwc`（易失写缓存）与盘型号；**无 PLP 的消费级盘上的 `fsync` 数字不得与企业盘混用**（附录 A 自动采集） |
| 长稳监控 | `node_exporter` 或 `sar`/`iostat` 日志落盘；烤机期间监控 `ENOSPC`、`dmesg` I/O error、孤儿对象计数、`netns/veth` 残留 |

### 3.4 厂商选型提示与控成本（价格以厂商官网为准，本文不报价）

| 厂商 / 产品 | 要点与注意事项 |
| :--- | :--- |
| AWS `*.metal` | 真裸金属，按秒计费。**务必选带本地 NVMe 实例存储的型号**（如 `*d.metal` 系列，具体规格以购买时控制台为准）；**EBS 不能当 NVMe 基准盘**；实例存储停机即丢，数据先回传。规格普遍偏大，Stage 1 按 2~4 小时用完即释放。 |
| 阿里云神龙 `ecs.ebm*` | 弹性裸金属，选带本地 NVMe 的规格族，确认实例族是否提供本地盘（而非纯云盘）。 |
| Hetzner Dedicated（AX / EX 系列） | 性价比高、本地 NVMe；**通常按月计费且有开通费**，更适合 Stage 2/3 的多轮长租而非 2 小时 Stage 1；选 ECC 内存型号，具体在售型号以官网当期为准。 |
| Vultr Bare Metal | 提供按小时计费的裸金属，适合 Stage 1 短租；选本地 NVMe 规格并确认 CPU 世代。 |
| 腾讯云黑石 | 物理机托管，确认计费周期与本地盘配置。 |

**控成本规则**：① 先 Track A 彩排；② 镜像 / 数据集预置到同区域对象存储，避免在计费时间内重复拉取；③ Stage 1 单次开机将 `F0-1/2/5/6` 一次性脚本化跑完，重复取 P50/P99；④ 采集完成**立即回传结果后释放**；⑤ 严禁在 Track B 上做日常开发。

**采购避坑清单**：

| 坑 | 后果 |
| :--- | :--- |
| 买到不支持 `/dev/kvm` 的普通云虚机 | Firecracker 无法运行 |
| 买到 L2 嵌套虚拟化的云虚机并当裸金属 | 数字被嵌套损耗污染，违反铁律 2 |
| 用云盘 / EBS 测 `fsync`、`FICLONE` | 测到的是网络存储而非 NVMe |
| 内核 < 6.8 或云镜像默认旧内核 | 与基线不一致，需重装 / 升级 HWE |
| 无 ECC 内存做长稳烤机 | 位翻转导致无法归因的偶发失败 |
| 消费级 NVMe 无 PLP 却当"生产 fsync 延迟" | 数字不可比，须在报告中标注 |

---

## 四、统一软件栈、内核模块与 Guest 内核编译要求

### 4.1 宿主机一键初始化脚本（Ubuntu 22.04 / 24.04，x86_64）

> 依据 `HANDOFF.md` §一 与 `PHASE0_FALSIFICATION.md` §二。**脚本会安装软件、加载内核模块、修改用户组；执行前请创始人授权（Phase 0 手册要求）。** 以普通用户（具备 sudo）运行，执行后需**重新登录**使 `kvm`/`disk` 组生效。

```bash
#!/usr/bin/env bash
# forkloom-host-setup.sh —— Forkloom 研发 / 压测宿主机一键初始化（需 sudo；非只读）
set -euo pipefail
FC_VER="${FC_VER:-v1.10.1}"                    # 锁定 Firecracker >= v1.10.1
ARCH="$(uname -m)"; [ "$ARCH" = "x86_64" ] || { echo "仅支持 x86_64"; exit 1; }

# 1) 系统依赖（编译工具链 + 文件系统 + 网络 + 内核编译依赖 + 测量工具）
sudo apt-get update
sudo apt-get install -y \
  build-essential pkg-config clang curl git jq unzip musl-tools libssl-dev protobuf-compiler \
  btrfs-progs xfsprogs e2fsprogs iproute2 nftables conntrack \
  openssh-server fio nvme-cli smartmontools sysstat numactl linux-tools-common \
  bc flex bison libelf-dev libncurses-dev dwarves cpio rsync kmod xz-utils

# 2) 内核模块：立即加载 + 开机持久化
#    kvm_intel / kvm_amd 二选一由 CPU 决定；vhost_vsock 见下方说明
CPU_KVM="kvm_intel"; grep -qw svm /proc/cpuinfo && CPU_KVM="kvm_amd"
MODS="kvm $CPU_KVM vhost_vsock vsock btrfs tun nf_tables nf_conntrack veth"
for m in $MODS; do sudo modprobe "$m" || echo "WARN: 模块 $m 加载失败（WSL2 / 精简内核可能内置或缺失）"; done
printf '%s\n' $MODS | sudo tee /etc/modules-load.d/forkloom.conf >/dev/null
# 说明：Firecracker 自身的 vsock 经 UDS 多路复用，并不依赖 vhost_vsock；
#       加载它是为对齐项目验收清单并便于对照调试，缺失在 §5 脚本中仅为 WARN。

# 3) 用户组（HANDOFF.md：kvm,disk）
sudo usermod -aG kvm,disk "$USER"

# 4) cgroup v2 校验（Ubuntu 22.04/24.04 默认 unified；否则需 systemd.unified_cgroup_hierarchy=1 并重启）
[ "$(stat -fc %T /sys/fs/cgroup)" = "cgroup2fs" ] || echo "FAIL: 未启用 cgroup v2，请在内核引导参数加 systemd.unified_cgroup_hierarchy=1"
echo "cgroup controllers: $(cat /sys/fs/cgroup/cgroup.controllers)"    # 需含 cpu memory pids io cpuset

# 5) CPU governor 切 performance（计时实验期间；重启后失效）
for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
  [ -w "$g" ] || sudo test -e "$g" || continue; echo performance | sudo tee "$g" >/dev/null
done

# 6) Rust 稳定版 + musl 静态目标（aos-guest 为静态 musl PID-1）
if ! command -v rustup >/dev/null; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
fi
. "$HOME/.cargo/env"
rustup target add x86_64-unknown-linux-musl

# 7) 官方 Firecracker + Jailer（锁定版本，校验 sha256）
cd "$(mktemp -d)"
BASE="https://github.com/firecracker-microvm/firecracker/releases/download/${FC_VER}"
curl -fsSLO "${BASE}/firecracker-${FC_VER}-${ARCH}.tgz"
curl -fsSLO "${BASE}/firecracker-${FC_VER}-${ARCH}.tgz.sha256.txt" \
  && sha256sum -c "firecracker-${FC_VER}-${ARCH}.tgz.sha256.txt" \
  || echo "WARN: 未取得或未通过 sha256 校验文件，请对照发布页手工核验后再继续"
tar xzf "firecracker-${FC_VER}-${ARCH}.tgz"
sudo install -m 0755 "release-${FC_VER}-${ARCH}/firecracker-${FC_VER}-${ARCH}" /usr/local/bin/firecracker
sudo install -m 0755 "release-${FC_VER}-${ARCH}/jailer-${FC_VER}-${ARCH}"      /usr/local/bin/jailer
firecracker --version | head -n1; jailer --version | head -n1

echo "完成。请重新登录（或 newgrp kvm）后运行 §5 就绪验收脚本。"
```

**WSL2（A2）补充**：先 `sudo usermod -aG kvm $USER` 后 `wsl --shutdown` 重启；`modprobe` 失败项以 §5 脚本输出为准（WSL 内核未必提供 `vhost_vsock` / 可加载 `btrfs` 模块，若 Btrfs 不可用则 A2 无法完成存储相关实验，应改用 A1）。

### 4.2 Guest Linux 微虚拟机内核编译要求

**基线**：Guest 内核 **≥ 5.18**（`CONFIG_VMGENID` 自 5.18 起），推荐 **6.1 LTS**（Firecracker 官方验证的 Guest 版本）；以 Firecracker 官方仓库 `resources/guest_configs/microvm-kernel-ci-x86_64-6.1.config` 为起点，再叠加下表必开项。内核源码构建脚本须随 `guest-image/` 保留，遵守 **GPL-2.0-only**（`README.md`）。

**必开编译项**（全部 `=y`，Guest 不依赖模块加载）：

| 配置项 | 作用 / 对应实验 |
| :--- | :--- |
| `CONFIG_VMGENID=y`（依赖 `CONFIG_ACPI=y`） | 快照恢复后内核感知"克隆事件"并触发 RNG 重播种（F0-7） |
| `CONFIG_HW_RANDOM=y`、`CONFIG_HW_RANDOM_VIRTIO=y` | 宿主熵注入与 `RNDRESEEDCRNG` 路径（F0-7） |
| `CONFIG_INET_DIAG=y`、`CONFIG_INET_TCP_DIAG=y`、**`CONFIG_INET_DIAG_DESTROY=y`** | `ss -K` 秒断外部 TCP 连接、保留 `127.0.0.1` 回环连接（F0-7） |
| `CONFIG_CGROUPS=y`、**`CONFIG_CGROUP_FREEZER=y`**、`CONFIG_MEMCG=y`、`CONFIG_CGROUP_PIDS=y` | `aos.workload/cgroup.freeze` 冻结（热快照 Step 1，F0-5/6） |
| `CONFIG_VSOCKETS=y`、**`CONFIG_VIRTIO_VSOCKETS=y`** | `aos-guest` ↔ `agentd` 通道、首条命令延迟测量（F0-5） |
| `CONFIG_VIRTIO=y`、`CONFIG_VIRTIO_MMIO=y`、`CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES=y`、`CONFIG_VIRTIO_BLK=y`、`CONFIG_VIRTIO_NET=y` | Firecracker MMIO 设备：块盘与网络 |
| `CONFIG_EXT4_FS=y`、`CONFIG_DEVTMPFS=y`、`CONFIG_DEVTMPFS_MOUNT=y`、`CONFIG_TMPFS=y`、`CONFIG_PROC_FS=y`、`CONFIG_SYSFS=y` | 根文件系统（`mkfs.ext4 -d` 物化的镜像）与 PID-1 基础环境 |
| `CONFIG_KVM_GUEST=y`、`CONFIG_PARAVIRT=y`、`CONFIG_SERIAL_8250=y`、`CONFIG_SERIAL_8250_CONSOLE=y` | kvm-clock / 串口调试 |
| `CONFIG_BLK_DEV_INITRD=y`（并启用所用压缩格式） | `Inspector VM` 的 initramfs（无网只读补丁提取） |

```bash
# guest-image 内核构建示意（在 Linux 原生文件系统中执行；KVER 取 6.1 LTS 最新补丁号）
KVER="6.1.<最新补丁号>"
curl -fsSLO "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${KVER}.tar.xz" && tar xf "linux-${KVER}.tar.xz" && cd "linux-${KVER}"
cp /path/to/firecracker/resources/guest_configs/microvm-kernel-ci-x86_64-6.1.config .config

for o in ACPI VMGENID HW_RANDOM HW_RANDOM_VIRTIO INET_DIAG INET_TCP_DIAG INET_DIAG_DESTROY \
         CGROUPS CGROUP_FREEZER MEMCG CGROUP_PIDS VSOCKETS VIRTIO_VSOCKETS \
         VIRTIO VIRTIO_MMIO VIRTIO_MMIO_CMDLINE_DEVICES VIRTIO_BLK VIRTIO_NET \
         EXT4_FS DEVTMPFS DEVTMPFS_MOUNT TMPFS BLK_DEV_INITRD KVM_GUEST PARAVIRT; do
  ./scripts/config --enable "$o"
done
make olddefconfig
make -j"$(nproc)" vmlinux

# 关键：olddefconfig 会静默丢弃未满足依赖的选项，必须回读校验（任一缺失即 FAIL）
for o in VMGENID HW_RANDOM_VIRTIO INET_DIAG INET_TCP_DIAG INET_DIAG_DESTROY CGROUP_FREEZER VSOCKETS VIRTIO_VSOCKETS; do
  grep -qx "CONFIG_${o}=y" .config && echo "[OK]   CONFIG_${o}=y" || echo "[FAIL] CONFIG_${o} 未启用"
done
sha256sum vmlinux .config      # 记录摘要：快照元数据须绑定 Guest 内核摘要（ARCHITECTURE_V2.md）
```

---

## 五、机器就位后的 30 秒一键验收（Readiness Check Script）

**用法**：复制整段到新 Linux 机器终端运行。**完全只读**（不修改系统、不写文件；`sudo -n true` 仅探测免密）。`TRACK=A`（默认）或 `TRACK=B`（更严：嵌套虚拟化与内核不达标直接 `[FAIL]`）。

- `[FAIL]`：硬件 / 内核 / 虚拟化等**不达标或必须修复**项；
- `[WARN]`：可由 §4.1 脚本补齐或属推荐项（含 A2 的 WSL 降级提示）；
- 全部无 `[FAIL]` 才算合格（退出码 `0`）。

```bash
#!/usr/bin/env bash
# forkloom-readiness.sh —— 只读自检。用法：TRACK=A|B bash forkloom-readiness.sh
TRACK="${TRACK:-A}"
POOL="${FORKLOOM_POOL:-/var/lib/forkloom/pool}"; META="${FORKLOOM_META:-/var/lib/forkloom/meta}"
P=0; W=0; F=0
ok(){ printf '[OK]   %s\n' "$*"; P=$((P+1)); }
warn(){ printf '[WARN] %s\n' "$*"; W=$((W+1)); }
fail(){ printf '[FAIL] %s\n' "$*"; F=$((F+1)); }
ver_ge(){ [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]; }   # ver_ge A B  =>  A >= B
echo "== Forkloom Readiness | TRACK=$TRACK | host=$(hostname) | $(date -Is) =="

# 1) 架构
[ "$(uname -m)" = "x86_64" ] && ok "架构 x86_64" || fail "架构 $(uname -m)（Phase 0 基线锁定 x86_64）"

# 2) 操作系统与内核
. /etc/os-release 2>/dev/null
case "${ID:-}-${VERSION_ID:-}" in
  ubuntu-24.04) ok "OS Ubuntu 24.04（首选）";;
  ubuntu-22.04) warn "OS Ubuntu 22.04（备选，需 HWE 内核 >= 6.5）";;
  *)            warn "OS ${PRETTY_NAME:-unknown}（推荐 Ubuntu 24.04 LTS）";;
esac
kv="$(uname -r | sed 's/[^0-9.].*//')"
if   ver_ge "$kv" 6.8; then ok "内核 $(uname -r) >= 6.8"
elif ver_ge "$kv" 6.5 && [ "$TRACK" = A ]; then warn "内核 $(uname -r)（Track A 可接受 >= 6.5；推荐 >= 6.8）"
else fail "内核 $(uname -r) 过低（Track B 要求 >= 6.8；Track A 最低 6.5）"; fi

# 3) CPU 虚拟化扩展 + 是否裸金属
cpuf="$(grep -m1 -o -w -E 'vmx|svm' /proc/cpuinfo)"
[ -n "$cpuf" ] && ok "CPU 虚拟化扩展: $cpuf ($(lscpu | awk -F: '/Model name/{gsub(/^ +/,"",$2);print $2}'))" \
               || fail "CPU 无 vmx/svm（BIOS 未开 VT-x/SVM，或在无嵌套的虚机内）"
virt="$(systemd-detect-virt 2>/dev/null || true)"
case "$virt" in
  none) ok "裸金属（systemd-detect-virt=none）";;
  wsl)  [ "$TRACK" = B ] && fail "WSL2 不能作为 Track B（L2 嵌套，数字不可发布）" \
                          || warn "WSL2 L2 嵌套：仅限功能与崩溃语义，延迟数字严禁发布";;
  "")   warn "无法判定虚拟化类型（缺少 systemd-detect-virt）";;
  *)    [ "$TRACK" = B ] && fail "运行在虚拟机内（$virt）：不是裸金属，不得作为 Track B 基准" \
                          || warn "运行在虚拟机内（$virt）：嵌套虚拟化，数字不可发布";;
esac

# 4) /dev/kvm、vhost-vsock
if [ -e /dev/kvm ]; then
  [ -r /dev/kvm ] && [ -w /dev/kvm ] && ok "/dev/kvm 存在且当前用户可读写" \
    || fail "/dev/kvm 存在但当前用户无权限（sudo usermod -aG kvm \$USER 后重新登录）"
else fail "/dev/kvm 不存在（未加载 kvm 模块 / BIOS 未开虚拟化 / 虚机不支持）"; fi
[ -e /dev/vhost-vsock ] && ok "/dev/vhost-vsock 存在" \
  || warn "/dev/vhost-vsock 不存在（sudo modprobe vhost_vsock；Firecracker 自身 vsock 走 UDS，不阻塞）"

# 5) cgroup v2 与控制器
if [ "$(stat -fc %T /sys/fs/cgroup 2>/dev/null)" = "cgroup2fs" ]; then
  ok "cgroup v2（unified）已启用"
  miss=""; ctl=" $(cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null) "
  for c in cpu memory pids io cpuset; do case "$ctl" in *" $c "*) ;; *) miss="$miss $c";; esac; done
  [ -z "$miss" ] && ok "cgroup 控制器齐备（cpu memory pids io cpuset）" || warn "根 cgroup 缺少控制器:$miss"
else fail "未启用 cgroup v2（需 systemd.unified_cgroup_hierarchy=1）"; fi

# 6) 文件系统：btrfs / xfs / ext4 内核支持与工具
if grep -qw btrfs /proc/filesystems; then ok "内核已支持 btrfs"
elif modinfo btrfs >/dev/null 2>&1; then warn "btrfs 模块存在但未加载（sudo modprobe btrfs）"
else fail "内核无 btrfs 支持"; fi
grep -qw xfs /proc/filesystems && ok "内核已支持 xfs" || { modinfo xfs >/dev/null 2>&1 && warn "xfs 模块未加载" || fail "内核无 xfs 支持（F0-2 对照组需要）"; }
for t in mkfs.btrfs mkfs.xfs mkfs.ext4 btrfs; do command -v $t >/dev/null && ok "工具 $t" || warn "缺少 $t（运行 §4.1 脚本）"; done

# 7) 内存
mem="$(awk '/MemTotal/{printf "%d",$2/1048576}' /proc/meminfo)"   # 取整 GiB（标称 16/32/64/128 实测约 15/31/62/125）
if [ "$TRACK" = B ]; then
  [ "$mem" -ge 124 ] && ok "内存 ${mem} GiB（>= 128 标称，Stage 1~3 推荐）" \
  || { [ "$mem" -ge 62 ] && warn "内存 ${mem} GiB（>= 64 标称，仅满足 Stage 1/2 下限；Stage 3 需 128~256）" || fail "内存 ${mem} GiB < 64（Track B 下限）"; }
  grep -qi 'ecc' <(sudo -n dmidecode -t memory 2>/dev/null) && ok "检测到 ECC 内存" || warn "未能确认 ECC（需 sudo dmidecode -t memory 人工核对）"
else
  [ "$mem" -ge 31 ] && ok "内存 ${mem} GiB（>= 32 推荐）" || { [ "$mem" -ge 15 ] && warn "内存 ${mem} GiB（>= 16 最低；推荐 32）" || fail "内存 ${mem} GiB < 16"; }
fi

# 8) 磁盘：目标路径可用空间、NVMe、meta/pool 分盘铁律
tgt=""; for d in "$POOL" "$META" /var/lib/forkloom /var/lib /; do [ -d "$d" ] && { tgt="$d"; break; }; done
free="$(df -BG --output=avail "$tgt" | tail -n1 | tr -dc 0-9)"
if [ "$TRACK" = B ]; then lo=200; rec=400; else lo=40; rec=150; fi
[ "$free" -ge "$rec" ] && ok "可用空间 ${free} GiB @ $tgt" || { [ "$free" -ge "$lo" ] && warn "可用空间 ${free} GiB @ $tgt（建议 >= ${rec}）" || fail "可用空间仅 ${free} GiB @ $tgt（< ${lo}）"; }
grep -qi microsoft /proc/version && warn "WSL2：虚拟盘显示容量不代表宿主剩余空间；池必须封顶 <= 12~16 GiB 且虚拟盘位于 E:/D:，严禁 C 盘"
[ -d /sys/class/nvme ] && [ -n "$(ls /sys/class/nvme 2>/dev/null)" ] && ok "检测到 NVMe 设备" || warn "未检测到本机 NVMe 设备（WSL/虚机/SATA 不具备性能参考价值）"
case "$(pwd)" in /mnt/*) fail "当前目录位于 /mnt/*（9p 挂载），严禁在此运行实验";; esac
if [ -d "$POOL" ] && [ -d "$META" ]; then
  pf="$(findmnt -no FSTYPE -T "$POOL")"; mf="$(findmnt -no FSTYPE -T "$META")"
  [ "$pf" = btrfs ] && ok "pool 位于 btrfs" || fail "pool 文件系统为 '$pf'（必须 btrfs）"
  case "$mf" in ext4|xfs) ok "meta 位于 $mf";; *) fail "meta 文件系统为 '$mf'（必须 ext4/xfs，且不得是 btrfs）";; esac
  [ "$(stat -c %d "$POOL")" != "$(stat -c %d "$META")" ] && ok "meta 与 pool 为不同文件系统（分盘铁律）" || fail "meta 与 pool 同一文件系统（违反分盘铁律）"
  findmnt -no OPTIONS -T "$POOL" | grep -qw autodefrag && fail "pool 挂载含 autodefrag（必须禁用）"
  case "$(findmnt -no SOURCE -T "$POOL")" in /dev/loop*) warn "pool 为 loop 文件池：仅功能验证，性能数字不可发布";; esac
else warn "尚未创建 $POOL / $META（按 §2.3 建池后重跑）"; fi

# 9) 其他：governor、sudo、SSH、工具链
gov="/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"
if [ -r "$gov" ]; then [ "$(cat $gov)" = performance ] && ok "CPU governor=performance" || warn "CPU governor=$(cat $gov)（计时实验前切 performance）"
else warn "无 cpufreq governor 接口（虚机/WSL 属正常）"; fi
sudo -n true 2>/dev/null && ok "sudo NOPASSWD 可用" || warn "sudo 需要密码（按 §2.1 配置 NOPASSWD）"
systemctl is-active --quiet ssh 2>/dev/null && ok "OpenSSH Server 运行中" || warn "OpenSSH Server 未运行"
if command -v firecracker >/dev/null; then
  fv="$(firecracker --version 2>/dev/null | head -n1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)"
  ver_ge "${fv:-0}" 1.10.1 && ok "firecracker $fv >= 1.10.1" || fail "firecracker ${fv:-未知} < 1.10.1"
else warn "未安装 firecracker（运行 §4.1 脚本）"; fi
command -v jailer >/dev/null && ok "jailer 已安装" || warn "未安装 jailer"
command -v rustc >/dev/null && ok "rustc $(rustc --version | cut -d' ' -f2)" || warn "未安装 Rust（rustup）"
(rustup target list --installed 2>/dev/null | grep -q x86_64-unknown-linux-musl) && ok "rust target x86_64-unknown-linux-musl" || warn "缺少 musl target"
for t in nft conntrack ss protoc; do command -v $t >/dev/null && ok "工具 $t" || warn "缺少 $t"; done

echo "== 汇总：OK=$P WARN=$W FAIL=$F =="
[ "$F" -eq 0 ] && echo "结论：硬性项全部通过（请逐条处理 WARN 后开工）" || echo "结论：存在 FAIL，机器不合格或需修复后再验收"
exit $([ "$F" -eq 0 ] && echo 0 || echo 1)
```

**典型预期输出**：Track A1 全新机器（未装软件）应只有软件类 `[WARN]`；运行 §4.1 后再跑应全部 `[OK]`；Track B 云机若出现 `运行在虚拟机内` 的 `[FAIL]`，说明买成了虚机，**立即释放，勿开始采集**。

---

## 附录 A：测量环境指纹采集（铁律 2 落地）

每份基准报告（含 Track A1 / Track B）必须附带下列输出。命令为只读（部分需 `sudo`，无权限时会降级跳过）：

```bash
#!/usr/bin/env bash
# env-fingerprint.sh —— 采集"硬件型号 / 内核 / 文件系统 / 供电 / 页缓存"前提
POOL="${FORKLOOM_POOL:-/var/lib/forkloom/pool}"; META="${FORKLOOM_META:-/var/lib/forkloom/meta}"
echo "## time:        $(date -Is)"
echo "## host:        $(hostname)  virt=$(systemd-detect-virt 2>/dev/null || echo unknown)"
echo "## cpu:         $(lscpu | awk -F: '/Model name/{gsub(/^ +/,"",$2);print $2}')  cores=$(nproc)  governor=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo n/a)"
echo "## board:       $(cat /sys/class/dmi/id/sys_vendor 2>/dev/null) $(cat /sys/class/dmi/id/product_name 2>/dev/null)"
echo "## mem:         $(awk '/MemTotal/{printf "%.1f GiB",$2/1048576}' /proc/meminfo)  THP=$(cat /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null)"
echo "## kernel:      $(uname -r)   os=$(. /etc/os-release; echo $PRETTY_NAME)"
echo "## firecracker: $(firecracker --version 2>/dev/null | head -n1)   jailer: $(jailer --version 2>/dev/null | head -n1)"
echo "## guest-kernel sha256: $(sha256sum "${GUEST_VMLINUX:-/dev/null}" 2>/dev/null | cut -c1-16)"
for p in "$META" "$POOL" /var/lib/forkloom/volatile; do
  [ -e "$p" ] && echo "## fs[$p]: $(findmnt -no SOURCE,FSTYPE,OPTIONS -T "$p")"
done
echo "## vm.dirty_ratio=$(sysctl -n vm.dirty_ratio) dirty_background_ratio=$(sysctl -n vm.dirty_background_ratio)"
echo "## page-cache state: <请在报告中显式写明：drop_caches 冷 / 全热 / mincore+fadvise(WILLNEED) 预热>"
echo "## disks:"; lsblk -dno NAME,MODEL,SIZE,ROTA,TRAN 2>/dev/null
for d in /dev/nvme?n1; do [ -e "$d" ] && sudo -n nvme id-ctrl "$d" 2>/dev/null | grep -E '^(mn|fr|vwc|oncs) ' | sed "s|^|## $d: |"; done
echo "## power/PLP: <云裸金属写厂商型号；本地盘请核对规格书是否具备 PLP；记录是否外接 UPS>"
```

**报告模板最小字段**（缺一不可，否则按铁律 2 作废）：`机型/CPU/内存` · `内核版本` · `meta / pool 文件系统与挂载选项` · `是否 loop / 是否同盘分区` · `盘型号与 PLP/vwc` · `页缓存冷热前提` · `Firecracker / Guest 内核摘要` · `是否裸金属（virt=none）`。

---

## 附录 B：快速决策清单（给创始人）

1. **现在就能开工**：优先找一台满足 §2.1 的局域网 x86_64 机器（Ubuntu 24.04、32GB、512GB NVMe）→ 跑 §4.1 → 跑 §5（`TRACK=A`）→ `F0-5 ~ F0-8` 全部在此推进。
2. **没有 A1 机器**：用 A2（WSL2 放 `E:\wsl\`，池 ≤ 12 GiB），只做 `256~512MiB × 4` 功能验证，**不发布数字**。
3. **Phase 0 结项（Gate 2）前**：开 **Stage 1** 裸金属 2~4 小时（先 Track A 彩排），采集 `F0-1/2/5/6` 权威数字并附环境指纹，随后立即释放。
4. **Phase 1 / Phase 2 / Phase 3** 分别在对应阶段按 §3.1 矩阵开 Stage 2 / Stage 3，不提前租、不常开。

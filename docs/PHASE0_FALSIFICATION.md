# Phase 0 内核原语证伪实验手册（Falsification & Baseline Suite）

> **唯一指标权威源**：本文档是 Phase 0 全部实验项、测量边界条件与转向门禁（Pivot Gate）的唯一权威定义。  
> **红队准则约束（铁律 2）**：任何未注明宿主机硬件型号、内核版本、底层文件系统、供电状态与页缓存冷热前提的性能数字一律无效。WSL2（L2 嵌套虚拟化）仅用于验证**功能正确性与崩溃语义**，对外发布的性能延迟基线必须在**独立裸金属 Linux 主机**上采集。

---

## 一、实验环境双轨基线

### 1.1 本地功能与崩溃语义验证台（当前开发机）
- **宿主硬件**：Surface Pro 8（i5-1135G7 8 逻辑核，16GB RAM，C 盘物理剩余 ~56GB）
- **WSL2 环境**：Ubuntu 22.04.5 LTS，内核 `6.6.87.2-microsoft-standard-WSL2`（建议 `.wslconfig` 分配 `8GB` 内存）
- **物理空间安全红线**：实验 Btrfs / XFS 存储池文件或独立 VHDX 容量**严格限制在 `12 GiB` 以内**（严禁信任 WSL2 虚拟盘显示的 950G，防止写爆宿主机 C 盘引发底层 I/O 错误）；代码与池必须位于 WSL 原生路径 `~/work/forkloom-vm/` 与 `/var/lib/forkloom/`，严禁触碰 `/mnt/c`。

### 1.2 性能延迟基准台（待接入裸金属 / 支持 KVM 的独立 Linux 服务器）
- **推荐配置**：x86_64 裸金属（≥ 16 核 / 64GB~128GB RAM / 独立 NVMe SSD 分区），Ubuntu 24.04 LTS（Linux ≥ 6.8）。

---

## 二、启动前一次性环境初始化清单（需创始人授权后由 `Mach` 执行）

1. 将当前 WSL 用户加入 `kvm` 组并重启 WSL（`sudo usermod -aG kvm $USER` -> `wsl --shutdown`），验证 `/dev/kvm` 非 root 可读写。
2. 安装内核实验与编译工具链：`sudo apt-get update && sudo apt-get install -y btrfs-progs xfsprogs e2fsprogs protobuf-compiler clang pkg-config libssl-dev iproute2 nftables conntrack` 并加载 `sudo modprobe btrfs`。
3. 在 WSL 内安装原生 Rust 工具链（`rustup` stable + `x86_64-unknown-linux-musl` target）。
4. 下载锁定版本的官方 `firecracker` 与 `jailer` 静态二进制，准备最小化 Linux `vmlinux`（≥ 5.18，开启 `CONFIG_VMGENID`、`CONFIG_HW_RANDOM_VIRTIO`、`CONFIG_INET_DIAG_DESTROY`）。

---

## 三、八大必测证伪实验项（F0-1 ~ F0-8）

| 编号 | 实验名称 | 具体测试负载与测量边界条件 | 证伪/转向判据（Pivot / Kill Criteria） |
| :--- | :--- | :--- | :--- |
| **F0-1** | **Btrfs 并发子卷快照与删除吞吐** | 在持续后台随机写负载 + 同池 `redb` `fsync` 并发竞争下，连续创建并异步销毁 1,000 个只读/可写子卷（确认禁用 `qgroups`），记录 P50/P99 延迟。 | 若同池 Btrfs 快照全局事务阻塞导致 `redb` 提交 P99 > `50ms`，则将 `meta/forkloom.redb` 移出 Btrfs 池放到宿主原生 `ext4/XFS` 目录。 |
| **F0-2** | **块镜像碎片与脏页下的 `FICLONE` 暂停耗时对比** | 对比三组后端：① Btrfs 默认 CoW 稀疏 `ext4` 镜像；② Btrfs `chattr +C` 镜像；③ **XFS (`reflink=1` + `cowextsize`) 对照组**。分别在 `1k / 10k / 100k` 个随机写 extent 及不同宿主页缓存脏页量（`0MB / 256MB / 1GB`）下测量 `FICLONE + fsync` 耗时。 | **核心转向门禁**：若 Btrfs CoW 块镜像在 `50k` extent 下单次克隆耗时 > `100ms` 而 XFS 显著更稳，则 `BlockStore` 正式切为独立 XFS 后端。 |
| **F0-3** | **5 万小文件免挂载导入与分叉后 `git status` 行为** | 构造含 5 万文件（大型 `node_modules` + Git 仓库）的目录树：① 在一致 `userns` 下测试解包 + `mkfs.ext4 -d` 物化耗时与 UID 正确性；② 子卷分叉后实测首次 `git status` 是否因 `st_dev/ctime` 触发全盘重哈希。 | 验证物化耗时线性系数与 UID 零偏移；若 `git status` 触发全扫，记录需要在导入阶段预刷 Git index 的工程对策。 |
| **F0-4** | **池满（`ENOSPC`）死锁与压舱石恢复演练** | 将 Btrfs 池人为写至 `ENOSPC`，验证：① 此时 `meta/` 下的 `redb` 能否提交删除状态事务；② 删除 `ballast` 压舱文件后，子卷销毁与空间回收是否 100% 恢复正常。 | 若池满导致同池 `redb` 无法提交墓碑事务，则强制规定 `meta/` 必须与数据池分盘存放。 |
| **F0-5** | **Firecracker 端到端恢复至首条命令可用延迟** | 锁定 512MiB / 2GiB VM，严格分三档测量从发起 `snapshot/load` 到 **Guest 内经 `vsock` 执行首条命令返回结果**的总延迟：① `drop_caches` 冷缓存；② 页缓存全热；③ 基于 `mincore` 位图执行 `fadvise(WILLNEED)` 预热工作集。 | 量化缺页风暴真实惩罚与 `WILLNEED` 预取收益，杜绝用纯 VMM API 返回时间充当可用延迟。 |
| **F0-6** | **内存快照捕获耗时与 `MAP_PRIVATE` 物理共享率** | ① 测量 512MiB / 2GiB VM 在磁盘池（`Durable`）与配额 `tmpfs`（`Volatile`）上的快照写出耗时；② 从同一快照用 `File Backend` 恢复 4~8 个克隆（裸金属测 16 个），通过 `/proc/<pid>/smaps_rollup` 实测真实 `PSS` vs `Private_Dirty`。 | 验证 $N$ 路克隆确实共享干净物理页；确认 `tmpfs` 超配额时可优雅拦截而不触发宿主 OOM。 |
| **F0-7** | **克隆唯一性与本地回环连接存活验证** | 从运行着本地服务（监听 `127.0.0.1`）且持有一条外部 TCP 连接的母 VM 热分叉 2 个子实例：验证 `VMGenID` + `RNDRESEEDCRNG` 后 `/dev/urandom` 输出完全发散、`ss -K` 成功秒断外部连接、且内部 `127.0.0.1` 连接池继续正常读写。 | 验证 Guest 内核编译项齐备且热分叉核心价值（保内部预热连接、断外部副作用连接）100% 成立。 |
| **F0-8** | **`kill -9` 随机故障注入与零孤儿/隔离区恢复** | 在高频并发创建/销毁 `Preparing` 与 `Committed` 帧循环中随机 `kill -9` 压测进程，重启运行 R0~R6 恢复逻辑（含 `CLONE_INTO_CGROUP` + `cgroup.kill` + 孤儿阈值熔断与 `quarantine/` 隔离）。 | 连续 100 次随机强杀重启后：零残留子进程、零残留 `netns/veth`、零未登记孤儿对象、零误删已提交帧。 |

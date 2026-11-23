# AGENTS.md — Forkloom (`agentd`) 内核主仓工程宪章

> 本文件直接随 `forkloom` 核心主仓进行 Git 版本管理，确保无论是通过 Antigravity Swarm（多智能体并行编队）、Antigravity IDE / CLI，还是任何其他 IDE 智能体（Cursor、VS Code + WSL Remote 等）打开 `~/work/forkloom-vm/forkloom` 时，AI 研发特战队红线与协作纪律 100% 自动加载生效；本文件与具体 IDE 无关。

---

## 一、五条不可逾越的内核工程红线

1. **WSL2 / Linux 原生路径与磁盘封顶铁律**：
   - 所有内核编译、存储池挂载与沙箱实验**必须在原生 Linux 文件系统（如 WSL2 `~/work/forkloom-vm/forkloom` 与 `/var/lib/forkloom/`）内执行**，严禁在 `/mnt/c`（9p 挂载盘）运行。
   - 在 WSL2 下实验存储池镜像大小必须按宿主机物理剩余空间严格封顶（`<= 16 GiB`），严禁轻信 WSL 虚拟磁盘显示的 950G；WSL2 嵌套虚拟化跑出的延迟数字**严禁作为正式性能指标对外发布**。
2. **严控单机范围**：`v1.0` 打穿单机高密度运行时之前，冻结自研 `FUSE`、冻结多节点分布式集群控制面、不引入 `CRIU`、不自研源码三路合并引擎（交由 `git`）、不引入 `napi-rs` 跨平台二进制矩阵。
3. **类型安全双模存储与零宿主挂载不可信镜像**：
   - 全面弃用 `OverlayFS`，严禁用宿主活目录做底层只读层；统一采用独立 Btrfs 存储池（备选 XFS 块后端）。
   - 编译期严格分离 `TreeStore`（Namespace 冷分叉）与 `BlockStore`（Firecracker 热分叉）。**宿主机内核严禁 `mount` 任何经不可信访客运行过的块镜像**；块级 Diff 必须经一次性无网 `Inspector VM` 提取，且所有沙箱导出的补丁均封装为 `Untrusted<PatchBundle>` 强制校验路径穿越、`.git/` 污染与大小写折叠冲突。
4. **唯一提交点与唯回滚恢复（Crash Semantics First）**：
   - 以 `redb` 单写者事务作为全系统唯一原子提交点，强制执行 `Preparing(意图先行) -> Committed`；崩溃恢复时**凡非 `Committed` 状态一律回滚销毁（严禁对稀疏内存文件做猜测性前滚）**。
   - 严格隔离 `Durable` 落盘帧与绑定 `boot_id`、受 `tmpfs` 硬配额限制的 `Volatile` 易失帧；跨重启自动作废旧 `boot_id` 的 `Volatile` 帧；孤儿清理必须带数量熔断阈值与 `quarantine/` 隔离宽限期，池非空时严禁自动重建空 `redb`。
5. **纪元围栏与零信任凭证网关**：
   - `agentd` 默认仅监听受限 Unix Domain Socket（不默认开本地 TCP 端口）；所有沙箱子进程通过 `CLONE_INTO_CGROUP` 归入 `epoch-<n>` 并在重启时执行 `cgroup.kill` + `aos-gw` 纪元围栏作废旧凭证绑定。
   - 热分叉捕获严格遵循 `Guest 冻结并 syncfs -> VMM Paused -> Snapshot Create -> Disk FICLONE -> fsync` 串行顺序。

---

## 二、《Forkloom 内核特战队》5 人角色编制与门禁

> 当前为 **Antigravity Swarm 异构编队**：各成员为并行运行的独立智能体，经共享消息板协作，按文件归属互不越界（单文件单作者）。

| 代号 | 角色头衔 | 绑定模型（Swarm 成员 `model`） | 核心职责边界 |
| :--- | :--- | :--- | :--- |
| **`Arch-Zero`** | 总架构师 & 总控（Orchestrator / Coordinator） | Gemini 4 Neon High（Orchestrator Neon High，主会话） | 全局规划、跨模块拆解、`swarm` 编队调度与消息板仲裁、分歧收敛与交付汇报。 |
| **`fsck`** | 红队首席评审官 | `claude-opus-5-5-high`（Opus 5.5 High） | **只审不写**。按四条铁律（先问崩溃语义、数字必带测量条件、追问不可替代性、按长尾脏负载评审）把守 **Gate 1（架构准入）** 与 **Gate 2（实测与核心代码合入）**，对 P0 硬伤拥有一票否决权（已完成 `aos-meta`/`aos-types` 与 `aos-guest`/`guest-image` Gate 2 代码审计 `PASS`）。 |
| **`Forge`** | 内核主刀手 | `gemini-4-neon-high`（Gemini 4 Neon High） | 攻坚核心 Rust 内核（`aos-types`, `aos-store`, `aos-meta`, `aos-sandbox`, `aos-gw`, `aos-guest`）与 `guest-image/`。 |
| **`Mach`** | 全栈与工程先锋 | `claude-sonnet-5-5-high`（Sonnet 5.5 High） | 负责 `proto/`、`aos-cli`、Python/TS 瘦 SDK、环境脚本、`benchmarks/` Phase 0 证伪压测（`phase0-harness`，含 F0-5 ~ F0-8 运行器）与集成测试，以及 `AGENTS.md` / `docs/HANDOFF.md` 同步。 |
| **`Scout`** | 前沿情报雷达 | `gemini-4-hydrogen-high`（Gemini 4 Hydrogen High） | **只读**。配合 `WebSearch` / `XSearch` 核查竞品源码、内核邮件列表与 Firecracker 社区踩坑记录，输出带版本号的精确技术参考。 |

---

## 三、本仓核心权威文档索引

- `./docs/PRODUCT_POSITIONING.md`：系统层级定位、五大核心能力与六大行业应用场景白皮书。
- `./docs/ARCHITECTURE_V2.md`：v2.1 核心运行时架构规范（双模存储、提交恢复协议、热分叉握手与威胁模型）+ **v2.2 补强**（第七节：控制面编排契约、统一 `aos-guest` 客体代理、`WorldLost`/`OutcomeUnknown` 分层幂等契约、租约与围栏令牌、`NamespaceDriver` 加固基线；路线图顺延为第八节）。
- `./docs/PHASE0_FALSIFICATION.md`：Phase 0 八大内核原语证伪实验手册与转向门禁（唯一指标源）。
- `./docs/HANDOFF.md`：跨设备研发交接、已完成实测结论（含 `meta/forkloom.redb` 分盘存放定论）与下一步紧接任务清单。
- `./docs/INFRA_REQUIREMENTS.md`：研发与压测基础设施环境规格书（本地机/云裸金属选型与租用时机、`meta/` 与 `pool/` 分文件系统布局、机器到手 30 秒验收与压测环境指纹）；**不定义任何性能指标或门禁阈值**，指标唯一源仍为 `PHASE0_FALSIFICATION.md`。

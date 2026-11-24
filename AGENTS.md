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

## 二、《Forkloom 内核特战队》角色编制、模型分档与门禁

> 当前为 **Antigravity Swarm 异构分级编队**：各成员为并行运行的独立智能体，经共享消息板协作，按文件归属互不越界（单文件单作者），并按任务重要程度与推理复杂度实行严格的**模型分档与动态升降档机制**。

| 代号 | 角色头衔 | 重要程度与分档 | 默认模型（首选 -> 配额回退） | 动态升降档规则与核心职责边界 |
| :--- | :--- | :--- | :--- | :--- |
| **`fsck`** | 红队首席评审官 | **P0 守门（`High`）** | 首选 `gemini-4-carbon-high` / `claude-opus-5-5-high`<br>回退 `gemini-4-argon-high` | **只审不写，P0 一票否决**。按四条铁律（先问崩溃语义、数字必带测量条件、追问不可替代性、按长尾脏负载评审）把守 Gate 1 / Gate 2 / 发布门禁；仅非核心文档或小改动复审可临时降 `medium`。 |
| **`Forge`** | 内核主刀手 | **P0/P1 内核（默认 `Medium`，攻坚升 `High`）** | 默认 `gemini-4-neon-medium`<br>攻坚 `gemini-4-neon-high` | 负责核心 Rust 内核（`aos-types`, `aos-store`, `aos-meta`, `aos-sandbox`, `aos-guest`）与 `guest-image/`。日常实现与测试默认 `Medium`；仅攻坚 `unsafe` syscall、`seccomp-bpf`、KVM / Firecracker 热分叉或内核 Kconfig 时临时升 `gemini-4-neon-high`。 |
| **`Arch-Zero`** (`coordinator`) | 总架构师 & 总控调度 | **P1 调度（`Medium`）** | `gemini-4-neon-medium`<br>（或 `gemini-4-argon-medium`） | **不直接改代码**。负责全局架构规划、跨模块契约拆解、`swarm` 编队生命周期与模型升降档调度、消息板仲裁与里程碑交付收敛。 |
| **`Mach`** | 全栈与控制面工程先锋 | **P1 工程（`Medium`）** | 首选 `claude-sonnet-5-5-medium`<br>回退 `gemini-4-argon-medium` | 负责 `proto/`、`agentd`、`aos-cli`、`aos-gw` 集成维护、`benchmarks/`（`phase0-harness` 实测压测与报告归档）、Git 原子提交/推送，以及 `AGENTS.md` / `docs/HANDOFF.md` 同步。 |
| **`SDK`** | 多语言瘦客户端工程师 | **P2 胶水/测试（`Flash Medium`）** | 首选 `gemini-3.8-flash-medium`<br>回退 `gemini-4-argon-medium` | 负责 `sdk/python`（`forkloom-vm`）、`sdk/typescript`（`@forkloom-vm/sdk`）薄 gRPC-over-UDS 客户端封装、Proto 代码生成与跨语言端到端集成测试。 |
| **`Scout`** | 前沿情报雷达 | **P2 调研（`Flash Medium`）** | 默认 `gemini-3.8-flash-medium`<br>深研 `gemini-4-hydrogen-medium` | **只读**。核查内核 uapi ABI、竞品源码、内核邮件列表与 Firecracker 社区踩坑记录，输出带精确版本号与字节布局的技术参考；深度内核/社区源码调研可临时升 `gemini-4-hydrogen-medium`。 |
| **`monitor`** | 消息板停滞监控 | **P3 巡检（`Flash Low`）** | `gemini-3.8-flash-low` | **只读定时巡检**。监控编队消息板是否出现全体停滞，按需精准唤醒下一责任人，零业务代码开销。 |

**模型分档与编队精简纪律**：
1. **严禁全员默认 `High`**：`High` 档位严格保留给红队 P0 终审门禁（`fsck`）及高危内核/安全边界攻坚（`Forge` 临时升档），常规工程、SDK 胶水与巡检一律采用 `Medium` / `Flash Medium` / `Flash Low`。
2. **专项短期工位按需拉起、即审即退**：如 Phase 1 独立模块攻坚工位（`store`、`gw`、`meta-fixer` 等）按里程碑按需拉起，经 `fsck PASS` 并入主线后即刻 `kill` 退役，长期维护统一归口 `Forge` 与 `Mach`。
3. **配额预警平滑切换**：触发配额预警时必须使用 `swarm model` 原地保留上下文切换至回退/降档模型，严禁使用 `kill + add` 丢弃会话历史，并在文档或汇报中如实记录。

---

## 三、本仓核心权威文档索引

- `./docs/PRODUCT_POSITIONING.md`：系统层级定位、五大核心能力与六大行业应用场景白皮书。
- `./docs/ARCHITECTURE_V2.md`：v2.1 核心运行时架构规范（双模存储、提交恢复协议、热分叉握手与威胁模型）+ **v2.2 补强**（第七节：控制面编排契约、统一 `aos-guest` 客体代理、`WorldLost`/`OutcomeUnknown` 分层幂等契约、租约与围栏令牌、`NamespaceDriver` 加固基线；路线图顺延为第八节）。
- `./docs/PHASE0_FALSIFICATION.md`：Phase 0 八大内核原语证伪实验手册与转向门禁（唯一指标源）。
- `./docs/HANDOFF.md`：跨设备研发交接、已完成实测结论（含 `meta/forkloom.redb` 分盘存放定论）与下一步紧接任务清单。
- `./docs/INFRA_REQUIREMENTS.md`：研发与压测基础设施环境规格书（本地机/云裸金属选型与租用时机、`meta/` 与 `pool/` 分文件系统布局、机器到手 30 秒验收与压测环境指纹）；**不定义任何性能指标或门禁阈值**，指标唯一源仍为 `PHASE0_FALSIFICATION.md`。

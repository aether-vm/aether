//! `agentd` binary entrypoint: opens `MetaEngine::open_and_recover` and serves `forkloom.v1`
//! gRPC strictly over a `0600` Unix Domain Socket.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use aos_gw::{AuditStore, EpochFenceRegistry};
use aos_meta::{FsArtifactBackend, MetaConfig, MetaEngine, RecoveryHooks, SystemClock};
use aos_sandbox::{GuestAgentSource, ResourceLimits, DEFAULT_CGROUP_SLICE_ROOT};
use aos_store::{TreeStore, TreeStoreConfig};
use aos_types::{BootId, EpochId};
use clap::{Parser, ValueEnum};

use agentd::backend::{
    InMemorySandboxBackend, LocalDevTreeBackend, NamespaceSandboxBackend, NamespaceSandboxConfig,
    ProductionRecoveryHooks, SandboxBackend, TreeBackend, TreeStoreBackend,
};
use agentd::service::AgentdService;
use agentd::transport::{serve_uds, DEFAULT_SOCKET_PATH};

/// How often expired world leases are looked for (pure memory unless one is due).
const LEASE_REAP_INTERVAL: Duration = Duration::from_secs(1);
/// How often expired pins, deferred deletions, quarantine and old records are collected.
const GC_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum BackendMode {
    /// Local directory + in-memory sandbox backend (cross-platform tests & development).
    Dev,
    /// Production Linux Btrfs `TreeStore` + hardened `NamespaceDriver` (`clone3` + `seccomp-bpf`).
    Production,
}

#[derive(Parser, Debug)]
#[command(
    name = "agentd",
    version,
    about = "Forkloom control-plane daemon (gRPC over 0600 Unix Domain Socket only)"
)]
struct Cli {
    /// Unix Domain Socket path (created with 0600 permissions inside a 0700 directory).
    #[arg(long, env = "FORKLOOM_SOCKET", default_value = DEFAULT_SOCKET_PATH)]
    socket: PathBuf,
    /// Execution & storage backend mode (`dev` or `production`).
    #[arg(long, value_enum, env = "FORKLOOM_BACKEND", default_value_t = BackendMode::Dev)]
    backend: BackendMode,
    /// Metadata directory holding `forkloom.redb` (MUST be ext4/XFS outside Btrfs pool).
    #[arg(long, default_value = "/var/lib/forkloom/meta")]
    meta_dir: PathBuf,
    /// Storage pool root (`POOL_UUID`, `objects/`, `worlds/`, `quarantine/`, `ballast`, `.lock`).
    #[arg(long, default_value = "/var/lib/forkloom/pool")]
    pool_dir: PathBuf,
    /// Quota-limited tmpfs directory for volatile memory objects.
    #[arg(long, default_value = "/var/lib/forkloom/volatile")]
    tmpfs_dir: PathBuf,
    /// Allow `meta_dir` and `pool_dir` on the same filesystem (development/testing ONLY).
    #[arg(long, default_value_t = false)]
    allow_same_fs: bool,
    /// Allow `TreeStore` on a non-Btrfs filesystem in `production` mode (testing ONLY).
    #[arg(long, default_value_t = false)]
    allow_non_btrfs: bool,
    /// Emergency Btrfs ballast file size in MiB for `production` mode (`0` disables pre-allocation).
    #[arg(long, default_value_t = 64)]
    ballast_mib: u64,
    /// Path to `aos-guest` inside the sandbox rootfs (or mount target when `--guest-agent-host-bin` is set).
    #[arg(long, default_value = "/sbin/init")]
    guest_agent: PathBuf,
    /// Optional host static `aos-guest` binary to bind-mount read-only onto `--guest-agent`.
    #[arg(long)]
    guest_agent_host_bin: Option<PathBuf>,
    /// Host cgroup v2 slice root for `NamespaceDriver` and R2 stale-epoch cleanup.
    #[arg(long, default_value = DEFAULT_CGROUP_SLICE_ROOT)]
    cgroup_root: PathBuf,
    /// Disable cgroup v2 `CLONE_INTO_CGROUP` in `production` mode (testing ONLY).
    #[arg(long, default_value_t = false)]
    no_cgroup: bool,
    /// Disable `CLONE_NEWUSER` in `production` mode (testing ONLY).
    #[arg(long, default_value_t = false)]
    no_userns: bool,
    /// Per-world memory limit in MiB for `production` mode; swap is disabled along with it
    /// (`0` = unlimited memory and swap).
    #[arg(long, default_value_t = 2048)]
    world_memory_max_mib: u64,
    /// Per-world limit on processes and threads for `production` mode (`0` = unlimited).
    #[arg(long, default_value_t = 512)]
    world_pids_max: u64,
    /// Per-world CPU limit in percent of one CPU for `production` mode (`0` = unlimited).
    #[arg(long, default_value_t = 0)]
    world_cpu_max_percent: u32,
    /// Maximum `ImportTar` streaming payload in MiB.
    #[arg(long, default_value_t = 256)]
    max_import_mib: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    std::fs::create_dir_all(&cli.tmpfs_dir)?;

    let mut cfg = MetaConfig::new(&cli.meta_dir, &cli.pool_dir);
    cfg.allow_same_fs_for_testing = cli.allow_same_fs;

    let boot_id = current_boot_id()?;
    let gateway_fence = Arc::new(EpochFenceRegistry::new(EpochId::FIRST));
    let audit_store = Arc::new(
        AuditStore::open(
            cli.meta_dir.join("audit"),
            cli.meta_dir.join("audit-keys"),
        )
        .map_err(|e| anyhow!("AuditStore::open failed: {e}"))?,
    );

    let (meta, summary, tree, sandbox): (
        MetaEngine,
        _,
        Arc<dyn TreeBackend>,
        Arc<dyn SandboxBackend>,
    ) = match cli.backend {
        BackendMode::Dev => {
            let hooks: Box<dyn RecoveryHooks> = Box::new(FsArtifactBackend::new(&cli.tmpfs_dir));
            let (meta, summary) =
                MetaEngine::open_and_recover(cfg, boot_id, hooks, Arc::new(SystemClock))
                    .map_err(|e| anyhow!("MetaEngine::open_and_recover failed: {e}"))?;
            let _ = gateway_fence.advance_epoch(meta.daemon_epoch());
            let worlds_dir = cli.pool_dir.join("worlds");
            let tree: Arc<dyn TreeBackend> = Arc::new(LocalDevTreeBackend::new(worlds_dir));
            let sandbox: Arc<dyn SandboxBackend> = Arc::new(InMemorySandboxBackend::new());
            (meta, summary, tree, sandbox)
        }
        BackendMode::Production => {
            let mut store_cfg = TreeStoreConfig::new(&cli.pool_dir)
                .with_ballast_bytes(cli.ballast_mib.saturating_mul(1024 * 1024));
            store_cfg.allow_non_btrfs_for_testing = cli.allow_non_btrfs;
            let store = TreeStore::open(store_cfg)
                .map_err(|e| anyhow!("TreeStore::open failed: {e}"))?;
            let ballast = store.ballast_status().map_or(0, |b| b.actual_bytes);
            if ballast < cli.ballast_mib.saturating_mul(1024 * 1024) {
                eprintln!(
                    "agentd: warning: pool is too full for its {} MiB ballast; running with {} MiB until the next start",
                    cli.ballast_mib,
                    ballast / (1024 * 1024)
                );
            }
            let hooks: Box<dyn RecoveryHooks> = Box::new(
                ProductionRecoveryHooks::new(store.clone(), &cli.tmpfs_dir, &cli.cgroup_root)
                    .with_gateway_fence(gateway_fence.clone()),
            );
            let (meta, summary) =
                MetaEngine::open_and_recover(cfg, boot_id, hooks, Arc::new(SystemClock))
                    .map_err(|e| anyhow!("MetaEngine::open_and_recover failed: {e}"))?;

            let guest_source = match cli.guest_agent_host_bin {
                Some(host_path) => GuestAgentSource::BindMountHostBinary {
                    host_path,
                    guest_mount_path: cli.guest_agent,
                },
                None => GuestAgentSource::InRootfs(cli.guest_agent),
            };
            let mut sbx_cfg = NamespaceSandboxConfig::new(meta.daemon_epoch());
            sbx_cfg.guest_agent = guest_source;
            sbx_cfg.cgroup_root = cli.cgroup_root;
            sbx_cfg.enable_cgroup = !cli.no_cgroup;
            sbx_cfg.enable_userns = !cli.no_userns;
            sbx_cfg.limits = ResourceLimits {
                memory_max_bytes: (cli.world_memory_max_mib > 0)
                    .then(|| cli.world_memory_max_mib.saturating_mul(1024 * 1024)),
                pids_max: (cli.world_pids_max > 0).then_some(cli.world_pids_max),
                cpu_max_percent: (cli.world_cpu_max_percent > 0)
                    .then_some(cli.world_cpu_max_percent),
            };

            let tree: Arc<dyn TreeBackend> = Arc::new(TreeStoreBackend::new(store));
            let sandbox: Arc<dyn SandboxBackend> = Arc::new(NamespaceSandboxBackend::new(sbx_cfg));
            (meta, summary, tree, sandbox)
        }
    };

    eprintln!(
        "agentd: recovered backend={:?} epoch={} boot_changed={} preparing_rolled_back={} deleting_completed={} worlds_marked_lost={} orphans_quarantined={}",
        cli.backend,
        summary.new_epoch,
        summary.boot_changed,
        summary.preparing_rolled_back,
        summary.deleting_completed,
        summary.worlds_marked_lost,
        summary.orphans_quarantined,
    );

    let service = AgentdService::with_max_import_bytes(
        meta,
        tree,
        sandbox,
        cli.max_import_mib.saturating_mul(1024 * 1024),
    )
    .with_gateway(gateway_fence, Some(audit_store));

    let reaper = service.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(LEASE_REAP_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let svc = reaper.clone();
            match tokio::task::spawn_blocking(move || svc.reap_expired_worlds()).await {
                Ok(Ok(expired)) => {
                    for wid in expired {
                        eprintln!("agentd: reaped world {wid} (lease expired)");
                    }
                }
                Ok(Err(e)) => eprintln!("agentd: lease reaper failed: {e}"),
                Err(e) => eprintln!("agentd: lease reaper panicked: {e}"),
            }
        }
    });

    let collector = service.clone();
    tokio::spawn(async move {
        let mut tick =
            tokio::time::interval_at(tokio::time::Instant::now() + GC_INTERVAL, GC_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut last_failures = Vec::new();
        loop {
            tick.tick().await;
            let svc = collector.clone();
            match tokio::task::spawn_blocking(move || svc.collect_garbage()).await {
                Ok(Ok(r)) => {
                    if r.pins_expired + r.frames_deleted + r.quarantine_purged > 0 {
                        eprintln!(
                            "agentd: gc pins_expired={} frames_deleted={} quarantine_purged={}",
                            r.pins_expired, r.frames_deleted, r.quarantine_purged
                        );
                    }
                    if r.failures != last_failures {
                        for f in &r.failures {
                            eprintln!("agentd: gc could not delete {f} (will retry)");
                        }
                        last_failures = r.failures;
                    }
                }
                Ok(Err(e)) => eprintln!("agentd: gc failed: {e}"),
                Err(e) => eprintln!("agentd: gc panicked: {e}"),
            }
        }
    });

    eprintln!(
        "agentd: listening on unix://{} (mode 0600, epoch {})",
        cli.socket.display(),
        service.daemon_epoch()
    );
    serve_uds(&cli.socket, service, async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await
}

fn current_boot_id() -> Result<BootId> {
    #[cfg(target_os = "linux")]
    {
        BootId::current().map_err(|e| anyhow!("reading host boot_id: {e}"))
    }
    #[cfg(not(target_os = "linux"))]
    {
        BootId::parse("00000000-0000-4000-8000-000000000001")
            .map_err(|e| anyhow!("fallback dev boot_id: {e}"))
    }
}

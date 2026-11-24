//! `agentd` binary entrypoint: opens `MetaEngine::open_and_recover` and serves `forkloom.v1`
//! gRPC strictly over a `0600` Unix Domain Socket.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use aos_meta::{FsArtifactBackend, MetaConfig, MetaEngine, SystemClock};
use aos_types::BootId;
use clap::Parser;

use agentd::backend::{InMemorySandboxBackend, LocalDevTreeBackend};
use agentd::service::AgentdService;
use agentd::transport::{serve_uds, DEFAULT_SOCKET_PATH};

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
    /// Metadata directory holding `forkloom.redb` (MUST be ext4/XFS outside Btrfs pool).
    #[arg(long, default_value = "/var/lib/forkloom/meta")]
    meta_dir: PathBuf,
    /// Storage pool root (`POOL_UUID`, `objects/`, `quarantine/`, `.lock`).
    #[arg(long, default_value = "/var/lib/forkloom/pool")]
    pool_dir: PathBuf,
    /// Quota-limited tmpfs directory for volatile memory objects.
    #[arg(long, default_value = "/var/lib/forkloom/volatile")]
    tmpfs_dir: PathBuf,
    /// Allow `meta_dir` and `pool_dir` on the same filesystem (development/testing ONLY).
    #[arg(long, default_value_t = false)]
    allow_same_fs: bool,
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
    let (meta, summary) = MetaEngine::open_and_recover(
        cfg,
        boot_id,
        Box::new(FsArtifactBackend::new(&cli.tmpfs_dir)),
        Arc::new(SystemClock),
    )
    .map_err(|e| anyhow!("MetaEngine::open_and_recover failed: {e}"))?;

    eprintln!(
        "agentd: recovered epoch={} boot_changed={} preparing_rolled_back={} deleting_completed={} worlds_marked_lost={} orphans_quarantined={}",
        summary.new_epoch,
        summary.boot_changed,
        summary.preparing_rolled_back,
        summary.deleting_completed,
        summary.worlds_marked_lost,
        summary.orphans_quarantined,
    );

    let worlds_dir = cli.pool_dir.join("worlds");
    let tree = Arc::new(LocalDevTreeBackend::new(worlds_dir));
    let sandbox = Arc::new(InMemorySandboxBackend::new());
    let service = AgentdService::with_max_import_bytes(
        meta,
        tree,
        sandbox,
        cli.max_import_mib.saturating_mul(1024 * 1024),
    );

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

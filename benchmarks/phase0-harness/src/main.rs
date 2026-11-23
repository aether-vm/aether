//! `phase0-harness` CLI (`F0-1` .. `F0-8`).
//!
//! Run Linux kernel experiments (`f0-1`..`f0-7`) as root (`sudo -E`) on native Linux storage, e.g.:
//!
//! ```text
//! sudo -E ./target/release/phase0-harness --root /var/lib/forkloom/phase0 f0-1-btrfs-snap --pool-mib 3072
//! ```
//!
//! `f0-8-kill9-recovery` (and `env`) also execute cross-platform against real `aos-meta` for local
//! multi-process crash-injection testing.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Result;
use clap::{Parser, Subcommand};
use phase0_harness::env::EnvHeader;
use phase0_harness::report::{write_report, ExpOutput};
use phase0_harness::{exp_f0_8, Ctx};

#[derive(Parser, Debug)]
#[command(
    name = "phase0-harness",
    version,
    about = "Forkloom Phase 0 falsification suite (WSL2 numbers are ADVISORY only)"
)]
struct Cli {
    /// Pool root (on Linux must be native storage; /mnt/* and 9p are refused).
    #[arg(long, global = true, default_value = "/var/lib/forkloom/phase0")]
    root: PathBuf,
    /// Report output directory.
    #[arg(long, global = true, default_value = "benchmarks/reports/wsl2-baseline")]
    out: PathBuf,
    /// Hard cap for any pool in GiB (never above 12).
    #[arg(long, global = true, default_value_t = 4, value_parser = clap::value_parser!(u64).range(1..=12))]
    max_pool_gib: u64,
    /// PRNG seed for reproducible workloads.
    #[arg(long, global = true, default_value_t = 0xAE7E_0001)]
    seed: u64,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Collect and print/save the environment header only.
    Env,
    /// Unmount everything under --root, detach loop devices and delete leftover images (Linux only).
    Cleanup,
    /// F0-1: Btrfs concurrent snapshot/destroy vs same-pool redb commit latency (Linux only).
    #[command(name = "f0-1-btrfs-snap")]
    F01 {
        #[arg(long, default_value_t = 3072)]
        pool_mib: u64,
        #[arg(long, default_value_t = 1000)]
        subvols: usize,
        #[arg(long, default_value_t = 256)]
        load_mib: u64,
        #[arg(long, default_value_t = 5)]
        baseline_secs: u64,
        #[arg(long, default_value_t = 2)]
        commit_interval_ms: u64,
    },
    /// F0-2: FICLONE+fsync matrix (btrfs-cow, btrfs-nocow, xfs) (Linux only).
    #[command(name = "f0-2-ficlone-matrix")]
    F02 {
        #[arg(long, default_value_t = 3072)]
        pool_mib: u64,
        #[arg(long, value_delimiter = ',', default_value = "1000,10000,50000")]
        extents: Vec<u64>,
        #[arg(long, value_delimiter = ',', default_value = "0,256")]
        dirty_mib: Vec<u64>,
        #[arg(long, default_value_t = 5)]
        reps: usize,
    },
    /// F0-3: small-file import, mkfs.ext4 -d materialisation, git status after fork (Linux only).
    #[command(name = "f0-3-mkfs-git")]
    F03 {
        #[arg(long, default_value_t = 4096)]
        pool_mib: u64,
        #[arg(long, value_delimiter = ',', default_value = "10000,50000")]
        files: Vec<u64>,
    },
    /// F0-4: ENOSPC deadlock and ballast recovery (Linux only).
    #[command(name = "f0-4-enospc-ballast")]
    F04 {
        #[arg(long, default_value_t = 2048)]
        pool_mib: u64,
        #[arg(long, default_value_t = 64)]
        ballast_mib: u64,
        #[arg(long, default_value_t = 128)]
        victim_mib: u64,
    },
    /// F0-5: Firecracker restore -> first `aos-guest` vsock command latency (cold / hot / mincore+WILLNEED).
    #[command(name = "f0-5-fc-restore")]
    F05 {
        #[arg(long, default_value = "/usr/local/bin/firecracker")]
        firecracker_bin: PathBuf,
        #[arg(long)]
        snapshot_path: PathBuf,
        #[arg(long)]
        mem_file_path: PathBuf,
        #[arg(long, default_value = "./v.sock")]
        vsock_uds: PathBuf,
        #[arg(long, default_value_t = 5000)]
        vsock_port: u32,
        /// Optional guest command argv to Exec after Ping (comma-separated, e.g. `/bin/true`).
        #[arg(long, value_delimiter = ',')]
        probe_argv: Vec<String>,
        #[arg(long, default_value_t = 512)]
        vm_mem_mib: u64,
        #[arg(long, default_value_t = 5)]
        reps: usize,
        #[arg(long)]
        mincore_profile: Option<PathBuf>,
        #[arg(long, default_value_t = 5000)]
        vsock_timeout_ms: u64,
    },
    /// F0-6: Snapshot capture latency & N-clone MAP_PRIVATE physical sharing (smaps_rollup).
    #[command(name = "f0-6-mem-sharing", alias = "f0-6-snapshot-share")]
    F06 {
        #[arg(long, default_value = "/usr/local/bin/firecracker")]
        firecracker_bin: PathBuf,
        #[arg(long)]
        snapshot_path: PathBuf,
        #[arg(long)]
        mem_file_path: PathBuf,
        #[arg(long)]
        mother_api_sock: Option<PathBuf>,
        #[arg(long, default_value_t = 512)]
        vm_mem_mib: u64,
        #[arg(long, default_value_t = 4)]
        clones: usize,
        #[arg(long)]
        volatile_tmpfs_mib: Option<u64>,
        #[arg(long, default_value_t = 256)]
        tmpfs_quota_mib: u64,
        #[arg(long, default_value_t = 3)]
        capture_reps: usize,
        #[arg(long)]
        vsock_uds: Option<PathBuf>,
        #[arg(long, default_value_t = 5000)]
        vsock_port: u32,
    },
    /// F0-7: Clone uniqueness (VMGenID + RNDRESEEDCRNG) & loopback survival (SOCK_DESTROY / ss -K).
    #[command(name = "f0-7-clone-unique", alias = "f0-7-clone-uniqueness")]
    F07 {
        #[arg(long, default_value = "/usr/local/bin/firecracker")]
        firecracker_bin: PathBuf,
        #[arg(long)]
        snapshot_path: PathBuf,
        #[arg(long)]
        mem_file_path: PathBuf,
        #[arg(long, default_value = "./v.sock")]
        vsock_uds: PathBuf,
        #[arg(long, default_value_t = 5000)]
        vsock_port: u32,
        #[arg(long, default_value_t = 2)]
        clones: usize,
        #[arg(long, default_value_t = 64)]
        entropy_bytes: usize,
        #[arg(long, default_value_t = 100)]
        max_sever_ms: u64,
        #[arg(long, default_value_t = 5000)]
        vsock_timeout_ms: u64,
        /// Optional guest socket probe argv (comma-separated) emitting JSON verification fields.
        #[arg(long, value_delimiter = ',')]
        socket_probe_argv: Vec<String>,
        /// Optional TAP device name baked into mother snapshot; isolates each clone in its own `ip netns`.
        #[arg(long)]
        netns_tap: Option<String>,
    },
    /// F0-8: Multi-process kill -9 fault injection & aos-meta R0~R6 zero-orphan recovery.
    #[command(name = "f0-8-kill9-recovery", alias = "f0-8-killnine")]
    F08 {
        #[arg(long, default_value_t = 100)]
        rounds: usize,
        #[arg(long)]
        meta_dir: Option<PathBuf>,
        #[arg(long)]
        pool_dir: Option<PathBuf>,
        #[arg(long)]
        tmpfs_dir: Option<PathBuf>,
        #[arg(long, default_value_t = 35)]
        max_kill_delay_ms: u64,
        #[arg(long, default_value_t = 20)]
        reboot_every: usize,
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        allow_same_fs: bool,
        #[arg(long)]
        cgroup_root: Option<PathBuf>,
    },
    /// Internal child worker process spawned by `f0-8-kill9-recovery`.
    #[command(name = "f0-8-worker", hide = true)]
    F08Worker {
        #[arg(long)]
        meta_dir: PathBuf,
        #[arg(long)]
        pool_dir: PathBuf,
        #[arg(long)]
        tmpfs_dir: PathBuf,
        #[arg(long)]
        boot_id: String,
        #[arg(long)]
        seed: u64,
        #[arg(long)]
        round: usize,
        #[arg(long)]
        now_ms: u64,
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        allow_same_fs: bool,
        #[arg(long)]
        cgroup_root: Option<PathBuf>,
    },
}

fn real_main() -> Result<ExitCode> {
    let cli = Cli::parse();
    let argv: Vec<String> = std::env::args().collect();

    // Hidden child worker executes directly without root/report ceremony.
    if let Cmd::F08Worker {
        meta_dir,
        pool_dir,
        tmpfs_dir,
        boot_id,
        seed,
        round,
        now_ms,
        allow_same_fs,
        cgroup_root,
    } = cli.cmd
    {
        exp_f0_8::run_worker(&exp_f0_8::WorkerArgs {
            meta_dir,
            pool_dir,
            tmpfs_dir,
            boot_id,
            seed,
            round,
            now_ms,
            allow_same_fs,
            cgroup_root,
        })?;
        return Ok(ExitCode::SUCCESS);
    }

    let ctx = Ctx {
        root: cli.root.clone(),
        out: cli.out.clone(),
        max_pool_gib: cli.max_pool_gib,
        seed: cli.seed,
    };

    // Handle cross-platform commands first (`env`, `f0-8-kill9-recovery`).
    match &cli.cmd {
        Cmd::Env => {
            let env = EnvHeader::collect(&cli.root, argv);
            let o = ExpOutput {
                id: "ENV",
                slug: "env",
                json: serde_json::json!({ "note": "environment header only" }),
                md: "Environment header only (no experiment run).\n".into(),
            };
            let (j, m) = write_report(&cli.out, &o, &env)?;
            println!("{}", env.to_markdown());
            println!("wrote {} and {}", j.display(), m.display());
            return Ok(ExitCode::SUCCESS);
        }
        Cmd::F08 {
            rounds,
            meta_dir,
            pool_dir,
            tmpfs_dir,
            max_kill_delay_ms,
            reboot_every,
            allow_same_fs,
            cgroup_root,
        } => {
            #[cfg(target_os = "linux")]
            phase0_harness::pool::validate_root(&cli.root)?;
            let env = EnvHeader::collect(&cli.root, argv);
            let f08_root = cli.root.join("f0-8");
            let out = exp_f0_8::run(
                &ctx,
                &exp_f0_8::Args {
                    rounds: *rounds,
                    meta_dir: meta_dir.clone().unwrap_or_else(|| f08_root.join("meta")),
                    pool_dir: pool_dir.clone().unwrap_or_else(|| f08_root.join("pool")),
                    tmpfs_dir: tmpfs_dir.clone().unwrap_or_else(|| f08_root.join("tmpfs")),
                    max_kill_delay_ms: *max_kill_delay_ms,
                    reboot_every: *reboot_every,
                    allow_same_fs: *allow_same_fs,
                    cgroup_root: cgroup_root.clone(),
                    worker_exe: None,
                },
            )?;
            let passed = out.json["passed"].as_bool().unwrap_or(false);
            let (j, m) = write_report(&cli.out, &out, &env)?;
            println!("{}\nwrote {} and {}", out.md, j.display(), m.display());
            return Ok(if passed {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            });
        }
        _ => {}
    }

    run_linux_cmd(&cli, &ctx, argv)
}

#[cfg(not(target_os = "linux"))]
fn run_linux_cmd(_cli: &Cli, _ctx: &Ctx, _argv: Vec<String>) -> Result<ExitCode> {
    eprintln!(
        "This subcommand requires Linux (run inside WSL2/Linux + KVM, never on /mnt/c). \
         On Windows, `env` and `f0-8-kill9-recovery` are supported natively."
    );
    Ok(ExitCode::from(2))
}

#[cfg(target_os = "linux")]
fn run_linux_cmd(cli: &Cli, ctx: &Ctx, argv: Vec<String>) -> Result<ExitCode> {
    use anyhow::ensure;
    use phase0_harness::pool::{cleanup, validate_root};
    use phase0_harness::{exp_f0_1, exp_f0_2, exp_f0_3, exp_f0_4, exp_f0_5, exp_f0_6, exp_f0_7};

    validate_root(&cli.root)?;
    let cap_mib = cli.max_pool_gib * 1024;
    let check = |mib: u64| -> Result<()> {
        ensure!(
            mib <= cap_mib,
            "--pool-mib {mib} exceeds --max-pool-gib {} ({cap_mib} MiB)",
            cli.max_pool_gib
        );
        Ok(())
    };
    let env = EnvHeader::collect(&cli.root, argv);

    let out: ExpOutput = match &cli.cmd {
        Cmd::Cleanup => {
            let rep = cleanup(&cli.root)?;
            println!("{}", serde_json::to_string_pretty(&rep)?);
            if rep.is_clean() {
                println!(
                    "cleanup: CLEAN (0 residual mounts, 0 residual loop devices, 0 residual .img files)"
                );
                return Ok(ExitCode::SUCCESS);
            }
            eprintln!("cleanup: residue remains (see above)");
            return Ok(ExitCode::from(1));
        }
        Cmd::F01 {
            pool_mib,
            subvols,
            load_mib,
            baseline_secs,
            commit_interval_ms,
        } => {
            check(*pool_mib)?;
            exp_f0_1::run(
                ctx,
                &exp_f0_1::Args {
                    pool_mib: *pool_mib,
                    subvols: *subvols,
                    load_mib: *load_mib,
                    baseline_secs: *baseline_secs,
                    commit_interval_ms: *commit_interval_ms,
                },
            )?
        }
        Cmd::F02 {
            pool_mib,
            extents,
            dirty_mib,
            reps,
        } => {
            check(*pool_mib)?;
            exp_f0_2::run(
                ctx,
                &exp_f0_2::Args {
                    pool_mib: *pool_mib,
                    extents: extents.clone(),
                    dirty_mib: dirty_mib.clone(),
                    reps: *reps,
                },
            )?
        }
        Cmd::F03 { pool_mib, files } => {
            check(*pool_mib)?;
            exp_f0_3::run(
                ctx,
                &exp_f0_3::Args {
                    pool_mib: *pool_mib,
                    files: files.clone(),
                },
            )?
        }
        Cmd::F04 {
            pool_mib,
            ballast_mib,
            victim_mib,
        } => {
            check(*pool_mib)?;
            exp_f0_4::run(
                ctx,
                &exp_f0_4::Args {
                    pool_mib: *pool_mib,
                    ballast_mib: *ballast_mib,
                    victim_mib: *victim_mib,
                },
            )?
        }
        Cmd::F05 {
            firecracker_bin,
            snapshot_path,
            mem_file_path,
            vsock_uds,
            vsock_port,
            probe_argv,
            vm_mem_mib,
            reps,
            mincore_profile,
            vsock_timeout_ms,
        } => exp_f0_5::run(
            ctx,
            &exp_f0_5::Args {
                firecracker_bin: firecracker_bin.clone(),
                snapshot_path: snapshot_path.clone(),
                mem_file_path: mem_file_path.clone(),
                vsock_uds: vsock_uds.clone(),
                vsock_port: *vsock_port,
                probe_argv: probe_argv.clone(),
                vm_mem_mib: *vm_mem_mib,
                reps: *reps,
                mincore_profile: mincore_profile.clone(),
                vsock_timeout_ms: *vsock_timeout_ms,
            },
        )?,
        Cmd::F06 {
            firecracker_bin,
            snapshot_path,
            mem_file_path,
            mother_api_sock,
            vm_mem_mib,
            clones,
            volatile_tmpfs_mib,
            tmpfs_quota_mib,
            capture_reps,
            vsock_uds,
            vsock_port,
        } => exp_f0_6::run(
            ctx,
            &exp_f0_6::Args {
                firecracker_bin: firecracker_bin.clone(),
                snapshot_path: snapshot_path.clone(),
                mem_file_path: mem_file_path.clone(),
                mother_api_sock: mother_api_sock.clone(),
                vm_mem_mib: *vm_mem_mib,
                clones: *clones,
                volatile_tmpfs_mib: *volatile_tmpfs_mib,
                tmpfs_quota_mib: *tmpfs_quota_mib,
                capture_reps: *capture_reps,
                vsock_uds: vsock_uds.clone(),
                vsock_port: *vsock_port,
            },
        )?,
        Cmd::F07 {
            firecracker_bin,
            snapshot_path,
            mem_file_path,
            vsock_uds,
            vsock_port,
            clones,
            entropy_bytes,
            max_sever_ms,
            vsock_timeout_ms,
            socket_probe_argv,
            netns_tap,
        } => exp_f0_7::run(
            ctx,
            &exp_f0_7::Args {
                firecracker_bin: firecracker_bin.clone(),
                snapshot_path: snapshot_path.clone(),
                mem_file_path: mem_file_path.clone(),
                vsock_uds: vsock_uds.clone(),
                vsock_port: *vsock_port,
                clones: *clones,
                entropy_bytes: *entropy_bytes,
                max_sever_ms: *max_sever_ms,
                vsock_timeout_ms: *vsock_timeout_ms,
                socket_probe_argv: socket_probe_argv.clone(),
                netns_tap: netns_tap.clone(),
            },
        )?,
        Cmd::Env | Cmd::F08 { .. } | Cmd::F08Worker { .. } => unreachable!("handled above"),
    };
    let (j, m) = write_report(&cli.out, &out, &env)?;
    println!("{}\nwrote {} and {}", out.md, j.display(), m.display());
    if out.json.get("passed").and_then(serde_json::Value::as_bool) == Some(false) {
        return Ok(ExitCode::from(1));
    }
    Ok(ExitCode::SUCCESS)
}

fn main() -> ExitCode {
    match real_main() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(1)
        }
    }
}

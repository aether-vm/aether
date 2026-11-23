//! `phase0-harness` CLI (Linux only).
//!
//! Run as root (`sudo -E`) from the repository root, e.g.
//!
//! ```text
//! sudo -E ./target/release/phase0-harness --root /var/lib/forkloom/phase0 f0-1-btrfs-snap --pool-mib 3072
//! ```

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("phase0-harness only supports Linux (run it inside WSL2/Linux, never on /mnt/c)");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
mod cli {
    use std::path::PathBuf;
    use std::process::ExitCode;

    use anyhow::{ensure, Result};
    use clap::{Parser, Subcommand};
    use phase0_harness::env::EnvHeader;
    use phase0_harness::pool::{cleanup, validate_root};
    use phase0_harness::report::{write_report, ExpOutput};
    use phase0_harness::{exp_f0_1, exp_f0_2, exp_f0_3, exp_f0_4, Ctx};

    #[derive(Parser, Debug)]
    #[command(name = "phase0-harness", version, about = "Forkloom Phase 0 falsification suite (WSL2 numbers are ADVISORY only)")]
    struct Cli {
        /// Pool root (must be native Linux storage; /mnt/* and 9p are refused).
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
        /// Unmount everything under --root, detach loop devices and delete leftover images.
        Cleanup,
        /// F0-1: Btrfs concurrent snapshot/destroy vs same-pool redb commit latency.
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
        /// F0-2: FICLONE+fsync matrix (btrfs-cow, btrfs-nocow, xfs).
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
        /// F0-3: small-file import, mkfs.ext4 -d materialisation, git status after fork.
        #[command(name = "f0-3-mkfs-git")]
        F03 {
            #[arg(long, default_value_t = 4096)]
            pool_mib: u64,
            #[arg(long, value_delimiter = ',', default_value = "10000,50000")]
            files: Vec<u64>,
        },
        /// F0-4: ENOSPC deadlock and ballast recovery.
        #[command(name = "f0-4-enospc-ballast")]
        F04 {
            #[arg(long, default_value_t = 2048)]
            pool_mib: u64,
            #[arg(long, default_value_t = 64)]
            ballast_mib: u64,
            #[arg(long, default_value_t = 128)]
            victim_mib: u64,
        },
        /// F0-5: Firecracker restore -> first vsock command latency (not implemented).
        #[command(name = "f0-5-fc-restore")]
        F05,
        /// F0-6: snapshot capture time and MAP_PRIVATE sharing (not implemented).
        #[command(name = "f0-6-snapshot-share")]
        F06,
        /// F0-7: clone uniqueness and loopback survival (not implemented).
        #[command(name = "f0-7-clone-uniqueness")]
        F07,
        /// F0-8: kill -9 fault injection and recovery (not implemented).
        #[command(name = "f0-8-killnine")]
        F08,
    }

    fn real_main() -> Result<ExitCode> {
        let cli = Cli::parse();
        let argv: Vec<String> = std::env::args().collect();

        match &cli.cmd {
            Cmd::F05 => return not_impl(phase0_harness::f0_5()),
            Cmd::F06 => return not_impl(phase0_harness::f0_6()),
            Cmd::F07 => return not_impl(phase0_harness::f0_7()),
            Cmd::F08 => return not_impl(phase0_harness::f0_8()),
            _ => {}
        }

        validate_root(&cli.root)?;
        let ctx = Ctx { root: cli.root.clone(), out: cli.out.clone(), max_pool_gib: cli.max_pool_gib, seed: cli.seed };
        let cap_mib = cli.max_pool_gib * 1024;
        let check = |mib: u64| -> Result<()> {
            ensure!(mib <= cap_mib, "--pool-mib {mib} exceeds --max-pool-gib {} ({cap_mib} MiB)", cli.max_pool_gib);
            Ok(())
        };
        let env = EnvHeader::collect(&cli.root, argv);

        let out: ExpOutput = match &cli.cmd {
            Cmd::Env => {
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
            Cmd::Cleanup => {
                let rep = cleanup(&cli.root)?;
                println!("{}", serde_json::to_string_pretty(&rep)?);
                if rep.is_clean() {
                    println!("cleanup: CLEAN (0 residual mounts, 0 residual loop devices, 0 residual .img files)");
                    return Ok(ExitCode::SUCCESS);
                }
                eprintln!("cleanup: residue remains (see above)");
                return Ok(ExitCode::from(1));
            }
            Cmd::F01 { pool_mib, subvols, load_mib, baseline_secs, commit_interval_ms } => {
                check(*pool_mib)?;
                exp_f0_1::run(
                    &ctx,
                    &exp_f0_1::Args {
                        pool_mib: *pool_mib,
                        subvols: *subvols,
                        load_mib: *load_mib,
                        baseline_secs: *baseline_secs,
                        commit_interval_ms: *commit_interval_ms,
                    },
                )?
            }
            Cmd::F02 { pool_mib, extents, dirty_mib, reps } => {
                check(*pool_mib)?;
                exp_f0_2::run(
                    &ctx,
                    &exp_f0_2::Args { pool_mib: *pool_mib, extents: extents.clone(), dirty_mib: dirty_mib.clone(), reps: *reps },
                )?
            }
            Cmd::F03 { pool_mib, files } => {
                check(*pool_mib)?;
                exp_f0_3::run(&ctx, &exp_f0_3::Args { pool_mib: *pool_mib, files: files.clone() })?
            }
            Cmd::F04 { pool_mib, ballast_mib, victim_mib } => {
                check(*pool_mib)?;
                exp_f0_4::run(
                    &ctx,
                    &exp_f0_4::Args { pool_mib: *pool_mib, ballast_mib: *ballast_mib, victim_mib: *victim_mib },
                )?
            }
            Cmd::F05 | Cmd::F06 | Cmd::F07 | Cmd::F08 => unreachable!("handled above"),
        };
        let (j, m) = write_report(&cli.out, &out, &env)?;
        println!("{}\nwrote {} and {}", out.md, j.display(), m.display());
        Ok(ExitCode::SUCCESS)
    }

    fn not_impl(r: Result<(), phase0_harness::NotImplemented>) -> Result<ExitCode> {
        if let Err(e) = r {
            eprintln!("{e}");
        }
        Ok(ExitCode::from(3))
    }

    pub fn main() -> ExitCode {
        match real_main() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("error: {e:#}");
                ExitCode::from(1)
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    cli::main()
}

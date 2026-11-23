//! Forkloom Phase 0 falsification harness (`F0-1` .. `F0-8`).
//!
//! WARNING: numbers produced under WSL2 (nested virtualisation, ext4-on-VHDX backing store, loop
//! devices on top of it) are **advisory only** - they validate functional correctness and crash /
//! ENOSPC semantics. Performance baselines must be re-collected on bare-metal Linux
//! (see `docs/PHASE0_FALSIFICATION.md` section 1.2).
//!
//! Linux-specific kernel experiments (`F0-1`..`F0-4`, `ioctls`, `pool`) are gated with
//! `#[cfg(target_os = "linux")]` so cross-platform analysis, reporting, Firecracker/guest
//! verification schemas, and the `F0-8` multi-process `aos-meta` crash-recovery suite compile and
//! test cleanly on Windows development hosts as well.

pub mod env;
#[cfg(target_os = "linux")]
pub mod exp_f0_1;
#[cfg(target_os = "linux")]
pub mod exp_f0_2;
#[cfg(target_os = "linux")]
pub mod exp_f0_3;
#[cfg(target_os = "linux")]
pub mod exp_f0_4;
pub mod exp_f0_5;
pub mod exp_f0_6;
pub mod exp_f0_7;
pub mod exp_f0_8;
pub mod firecracker;
#[cfg(target_os = "linux")]
pub mod ioctls;
#[cfg(target_os = "linux")]
pub mod pool;
pub mod report;
pub mod stats;
pub mod util;

use std::path::PathBuf;

/// Shared context handed to every experiment.
#[derive(Debug, Clone)]
pub struct Ctx {
    /// Pool root directory (default `/var/lib/forkloom/phase0`).
    pub root: PathBuf,
    /// Report output directory.
    pub out: PathBuf,
    /// Hard cap for any pool, in GiB (`<= 12`).
    pub max_pool_gib: u64,
    /// PRNG seed for reproducible workloads.
    pub seed: u64,
}

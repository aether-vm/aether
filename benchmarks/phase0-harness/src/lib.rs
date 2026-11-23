//! Forkloom Phase 0 falsification harness (Linux only).
//!
//! WARNING: numbers produced under WSL2 (nested virtualisation, ext4-on-VHDX backing store, loop
//! devices on top of it) are **advisory only** - they validate functional correctness and crash /
//! ENOSPC semantics. Performance baselines must be re-collected on bare-metal Linux
//! (see `docs/PHASE0_FALSIFICATION.md` section 1.2).

#![cfg(target_os = "linux")]

pub mod env;
pub mod exp_f0_1;
pub mod exp_f0_2;
pub mod exp_f0_3;
pub mod exp_f0_4;
pub mod ioctls;
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

/// Returned by experiments that are specified (see `docs/PHASE0_FALSIFICATION.md`) but whose
/// implementation has not landed yet (`f0-5` .. `f0-8`).
#[derive(Debug, Clone)]
pub struct NotImplemented {
    /// Experiment id, e.g. `F0-5`.
    pub id: &'static str,
    /// What is missing / what it will need.
    pub reason: &'static str,
}

impl std::fmt::Display for NotImplemented {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NotImplemented: {} - {}", self.id, self.reason)
    }
}

impl std::error::Error for NotImplemented {}

/// `F0-5`: Firecracker snapshot/load -> first vsock command latency.
pub fn f0_5() -> Result<(), NotImplemented> {
    Err(NotImplemented {
        id: "F0-5",
        reason: "needs a vmlinux (>=5.18, VMGENID/virtio-rng) + rootfs with vsock agent; \
                 measure cold/hot/mincore+WILLNEED restore-to-first-command latency (planned: Mach, after guest-image lands)",
    })
}

/// `F0-6`: snapshot capture time and MAP_PRIVATE physical sharing.
pub fn f0_6() -> Result<(), NotImplemented> {
    Err(NotImplemented {
        id: "F0-6",
        reason: "needs F0-5 guest image; measure snapshot write time on pool vs quota tmpfs and \
                 N-clone PSS vs Private_Dirty via /proc/<pid>/smaps_rollup",
    })
}

/// `F0-7`: clone uniqueness (VMGenID/RNDRESEEDCRNG) and loopback connection survival.
pub fn f0_7() -> Result<(), NotImplemented> {
    Err(NotImplemented {
        id: "F0-7",
        reason: "needs F0-5 guest image with CONFIG_VMGENID + CONFIG_INET_DIAG_DESTROY; verify urandom \
                 divergence, `ss -K` on external TCP and surviving 127.0.0.1 pool",
    })
}

/// `F0-8`: `kill -9` fault injection and zero-orphan recovery.
pub fn f0_8() -> Result<(), NotImplemented> {
    Err(NotImplemented {
        id: "F0-8",
        reason: "needs aos-meta (redb commit point) + aos-sandbox (CLONE_INTO_CGROUP, cgroup.kill) recovery R0-R6 from Forge",
    })
}

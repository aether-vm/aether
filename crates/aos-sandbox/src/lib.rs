//! Forkloom sandbox runtime drivers (`aos-sandbox`).
//!
//! Phase 1 delivers [`NamespaceDriver`] (cold-fork Linux namespace driver with
//! `userns`, `mountns`/`pivot_root`, `pidns`, `ipcns`, `utsns`, isolated `netns`,
//! `clone3(CLONE_INTO_CGROUP)`, capability drop, `PR_SET_NO_NEW_PRIVS`, and
//! strict `seccomp-bpf` returning `EOPNOTSUPP` on `BTRFS_IOCTL_MAGIC`).
//!
//! All host-to-guest execution speaks `aos-guest`'s framed v1 protocol over an
//! inherited `socketpair` — the host NEVER operates directly on `TreeStore`
//! subvolume files for `Exec` (`ARCHITECTURE_V2.md` §7.1).
//!
//! Every module except `#[cfg(target_os = "linux")] pub mod linux_sys` enforces
//! `#![forbid(unsafe_code)]`.

#![cfg_attr(not(target_os = "linux"), forbid(unsafe_code))]
#![deny(unsafe_code)]

pub mod client;
pub mod config;
pub mod driver;
pub mod error;
pub mod namespace;
pub mod seccomp;

#[cfg(target_os = "linux")]
pub mod linux_sys;

pub use client::GuestRpcClient;
pub use config::{
    DEFAULT_CGROUP_SLICE_ROOT, DEFAULT_HANDSHAKE_TIMEOUT, ExecOutputChunk, ExecReply, ExecRequest,
    FreezeOptions, FreezeReply, GuestAgentSource, IdMapRange, NetnsMode, PingReply, SeccompPolicy,
    SpawnWorldSpec, WorldInfo,
};
pub use driver::{RpcWorldBackend, SandboxDriver, WorldBackend, WorldHandle};
pub use error::SandboxError;
pub use namespace::NamespaceDriver;
pub use seccomp::{
    AUDIT_ARCH_X86_64, BLOCKED_EPERM_SYSCALLS, BTRFS_IOCTL_MAGIC, CLONE_NEW_ALL_MASK,
    CLONE_NEWUSER, ENOSYS, EOPNOTSUPP, EPERM, SECCOMP_RET_ALLOW, SECCOMP_RET_KILL_PROCESS,
    SeccompData, SockFilter, build_x86_64_baseline_filter, eval_filter, ret_errno,
};

//! Pure-Rust Linux `x86_64` seccomp-BPF filter compiler & cBPF evaluator.
//!
//! Enforces `docs/ARCHITECTURE_V2.md` §5.1 and §7.4 hardening baseline:
//! - Validates `AUDIT_ARCH_X86_64` and rejects x32 ABI syscalls (`KILL_PROCESS`).
//! - Intercepts `ioctl(fd, cmd, ...)` where `((cmd >> 8) & 0xFF) == 0x94` (`BTRFS_IOCTL_MAGIC`)
//!   and returns **`EOPNOTSUPP`** (`SECCOMP_RET_ERRNO | 95`), NEVER `SECCOMP_RET_KILL`,
//!   so `cp` and standard tools gracefully fall back to regular copies instead of dying on `SIGSYS`.
//! - Blocks nested namespace creation:
//!   - `clone(flags, ...)` with any `CLONE_NEW*` bit (including `CLONE_NEWUSER`) -> `EPERM`
//!   - `clone3` -> `ENOSYS` (so glibc/musl `pthread_create` transparently falls back to `clone(2)`!)
//!   - `unshare`, `setns` -> `EPERM`
//! - Blocks mount family (`mount`, `umount2`, `pivot_root`, `open_tree`, `move_mount`,
//!   `fsopen`, `fsconfig`, `fsmount`, `fspick`, `mount_setattr`) -> `EPERM`
//! - Blocks `io_uring_*`, `bpf`, `ptrace`, `kexec_load`, `kexec_file_load` -> `EPERM`
//!
//! Compiled with `#![forbid(unsafe_code)]` and includes a pure-Rust cBPF VM evaluator
//! so every jump offset, bitmask, and return code is unit-tested cross-platform.

#![forbid(unsafe_code)]

// ---------------------------------------------------------------------------
// Linux cBPF & seccomp ABI constants (x86_64)
// ---------------------------------------------------------------------------

pub const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
pub const X32_SYSCALL_BIT: u32 = 0x4000_0000;

pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
pub const SECCOMP_RET_ALLOW: u32 = 0x7FFF_0000;
pub const SECCOMP_RET_DATA: u32 = 0x0000_FFFF;

// Linux x86_64 errno values.
pub const EPERM: u32 = 1;
pub const ENOSYS: u32 = 38;
pub const EOPNOTSUPP: u32 = 95;

// Linux `BTRFS_IOCTL_MAGIC` (`include/uapi/linux/btrfs.h`).
pub const BTRFS_IOCTL_MAGIC: u32 = 0x94;

// Linux `CLONE_NEW*` flags (`include/uapi/linux/sched.h`).
pub const CLONE_NEWTIME: u32 = 0x0000_0080;
pub const CLONE_NEWNS: u32 = 0x0002_0000;
pub const CLONE_NEWCGROUP: u32 = 0x0200_0000;
pub const CLONE_NEWUTS: u32 = 0x0400_0000;
pub const CLONE_NEWIPC: u32 = 0x0800_0000;
pub const CLONE_NEWUSER: u32 = 0x1000_0000;
pub const CLONE_NEWPID: u32 = 0x2000_0000;
pub const CLONE_NEWNET: u32 = 0x4000_0000;
pub const CLONE_NEW_ALL_MASK: u32 = CLONE_NEWTIME
    | CLONE_NEWNS
    | CLONE_NEWCGROUP
    | CLONE_NEWUTS
    | CLONE_NEWIPC
    | CLONE_NEWUSER
    | CLONE_NEWPID
    | CLONE_NEWNET;

// Exact Linux x86_64 syscall numbers (`arch/x86/entry/syscalls/syscall_64.tbl`).
pub mod nr {
    pub const IOCTL: u32 = 16;
    pub const CLONE: u32 = 56;
    pub const PTRACE: u32 = 101;
    pub const PIVOT_ROOT: u32 = 155;
    pub const MOUNT: u32 = 165;
    pub const UMOUNT2: u32 = 166;
    pub const KEXEC_LOAD: u32 = 246;
    pub const UNSHARE: u32 = 272;
    pub const SETNS: u32 = 308;
    pub const KEXEC_FILE_LOAD: u32 = 320;
    pub const BPF: u32 = 321;
    pub const IO_URING_SETUP: u32 = 425;
    pub const IO_URING_ENTER: u32 = 426;
    pub const IO_URING_REGISTER: u32 = 427;
    pub const OPEN_TREE: u32 = 428;
    pub const MOVE_MOUNT: u32 = 429;
    pub const FSOPEN: u32 = 430;
    pub const FSCONFIG: u32 = 431;
    pub const FSMOUNT: u32 = 432;
    pub const FSPICK: u32 = 433;
    pub const CLONE3: u32 = 435;
    pub const MOUNT_SETATTR: u32 = 442;
}

/// Unconditionally blocked syscalls returning `EPERM` per `ARCHITECTURE_V2.md` §7.4.
pub const BLOCKED_EPERM_SYSCALLS: &[u32] = &[
    nr::UNSHARE,
    nr::SETNS,
    nr::MOUNT,
    nr::UMOUNT2,
    nr::PIVOT_ROOT,
    nr::OPEN_TREE,
    nr::MOVE_MOUNT,
    nr::FSOPEN,
    nr::FSCONFIG,
    nr::FSMOUNT,
    nr::FSPICK,
    nr::MOUNT_SETATTR,
    nr::IO_URING_SETUP,
    nr::IO_URING_ENTER,
    nr::IO_URING_REGISTER,
    nr::BPF,
    nr::PTRACE,
    nr::KEXEC_LOAD,
    nr::KEXEC_FILE_LOAD,
];

// cBPF instruction opcodes (`include/uapi/linux/bpf_common.h`, `filter.h`).
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;

const BPF_ALU: u16 = 0x04;
const BPF_AND: u16 = 0x50;
const BPF_RSH: u16 = 0x70;

const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_JGE: u16 = 0x30;
const BPF_JSET: u16 = 0x40;
const BPF_K: u16 = 0x00;

const BPF_RET: u16 = 0x06;

// Offsets inside `struct seccomp_data` (x86_64 little-endian):
//   u32 nr                  @ 0
//   u32 arch                @ 4
//   u64 instruction_pointer @ 8
//   u64 args[6]             @ 16 (arg i low32 = 16 + 8*i, high32 = 20 + 8*i)
const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;
const OFF_ARG0_LO: u32 = 16;
const OFF_ARG1_LO: u32 = 24;

/// Exact C ABI layout of Linux `struct sock_filter`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

impl SockFilter {
    pub const fn stmt(code: u16, k: u32) -> Self {
        Self {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }

    pub const fn jump(code: u16, k: u32, jt: u8, jf: u8) -> Self {
        Self { code, jt, jf, k }
    }
}

/// Pure-Rust mirror of Linux `struct seccomp_data` for cross-platform BPF evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeccompData {
    pub nr: u32,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub args: [u64; 6],
}

impl SeccompData {
    pub const fn x86_64(nr: u32, args: [u64; 6]) -> Self {
        Self {
            nr,
            arch: AUDIT_ARCH_X86_64,
            instruction_pointer: 0,
            args,
        }
    }

    /// Read a little-endian 32-bit word at byte offset `off` inside `struct seccomp_data`.
    pub fn load_word(&self, off: u32) -> Option<u32> {
        match off {
            0 => Some(self.nr),
            4 => Some(self.arch),
            8 => Some(self.instruction_pointer as u32),
            12 => Some((self.instruction_pointer >> 32) as u32),
            16..=60 if off.is_multiple_of(4) => {
                let idx = ((off - 16) / 8) as usize;
                let hi = !(off - 16).is_multiple_of(8);
                let val = self.args[idx];
                Some(if hi { (val >> 32) as u32 } else { val as u32 })
            }
            _ => None,
        }
    }
}

/// Build the return value for `SECCOMP_RET_ERRNO | errno`.
pub const fn ret_errno(errno: u32) -> u32 {
    SECCOMP_RET_ERRNO | (errno & SECCOMP_RET_DATA)
}

/// Compile the strict §7.4 + §5.1 `x86_64` seccomp-BPF program.
///
/// Uses a clean two-pass layout with explicit terminal return instructions at the end
/// so jump offsets are small, audited, and guaranteed within `u8` range.
pub fn build_x86_64_baseline_filter() -> Vec<SockFilter> {
    let mut prog = Vec::with_capacity(64);

    // Reserve indices for our 5 terminal return instructions at the end; we will
    // assemble the body first and patch jumps cleanly via helper offsets.
    //
    // Layout:
    //   [0]  LD arch
    //   [1]  JEQ AUDIT_ARCH_X86_64 -> next (jt=0), else -> KILL_PROCESS
    //   [2]  LD nr
    //   [3]  JGE X32_SYSCALL_BIT -> KILL_PROCESS, else -> next
    //   [4]  JEQ SYS_ioctl -> ioctl_check, else -> next
    //   [5]  JEQ SYS_clone -> clone_check, else -> next
    //   [6]  JEQ SYS_clone3 -> RET_ENOSYS, else -> next
    //   [7..7+N] JEQ blocked_nr -> RET_EPERM, else -> next
    //   [...] RET_ALLOW
    //   [ioctl_check]:
    //        LD args[1]_lo
    //        RSH 8
    //        AND 0xFF
    //        JEQ 0x94 -> RET_EOPNOTSUPP, else -> RET_ALLOW
    //   [clone_check]:
    //        LD args[0]_lo
    //        JSET CLONE_NEW_ALL_MASK -> RET_EPERM, else -> RET_ALLOW
    //   [terminals]:
    //        RET_ALLOW
    //        RET_EPERM
    //        RET_ENOSYS
    //        RET_EOPNOTSUPP
    //        RET_KILL_PROCESS

    let n_blocked = BLOCKED_EPERM_SYSCALLS.len();

    // Compute exact instruction indices ahead of time.
    let idx_arch_check = 1usize;
    let idx_x32_check = 3usize;
    let idx_ioctl_branch = 4usize;
    let idx_clone_branch = 5usize;
    let idx_clone3_branch = 6usize;
    let idx_blocked_start = 7usize;
    let idx_fallthrough_allow = idx_blocked_start + n_blocked;

    let idx_ioctl_check = idx_fallthrough_allow + 1; // 4 insns: LD, RSH, AND, JEQ
    let idx_clone_check = idx_ioctl_check + 4; // 2 insns: LD, JSET

    let idx_ret_allow = idx_clone_check + 2;
    let idx_ret_eperm = idx_ret_allow + 1;
    let idx_ret_enosys = idx_ret_eperm + 1;
    let idx_ret_eopnotsupp = idx_ret_enosys + 1;
    let idx_ret_kill = idx_ret_eopnotsupp + 1;

    let rel = |from: usize, to: usize| -> u8 {
        let delta = to
            .checked_sub(from + 1)
            .expect("seccomp BPF jumps must always move forward");
        u8::try_from(delta).expect("seccomp BPF jump offset fits in u8")
    };

    // [0..1] Arch check
    prog.push(SockFilter::stmt(BPF_LD | BPF_W | BPF_ABS, OFF_ARCH));
    prog.push(SockFilter::jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        AUDIT_ARCH_X86_64,
        0,
        rel(idx_arch_check, idx_ret_kill),
    ));

    // [2..3] Load nr & reject x32 ABI bit
    prog.push(SockFilter::stmt(BPF_LD | BPF_W | BPF_ABS, OFF_NR));
    prog.push(SockFilter::jump(
        BPF_JMP | BPF_JGE | BPF_K,
        X32_SYSCALL_BIT,
        rel(idx_x32_check, idx_ret_kill),
        0,
    ));

    // [4] ioctl -> ioctl_check
    prog.push(SockFilter::jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        nr::IOCTL,
        rel(idx_ioctl_branch, idx_ioctl_check),
        0,
    ));

    // [5] clone -> clone_check
    prog.push(SockFilter::jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        nr::CLONE,
        rel(idx_clone_branch, idx_clone_check),
        0,
    ));

    // [6] clone3 -> ENOSYS (triggers clean fallback to clone(2) for glibc/musl threads!)
    prog.push(SockFilter::jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        nr::CLONE3,
        rel(idx_clone3_branch, idx_ret_enosys),
        0,
    ));

    // [7..7+N] Unconditionally blocked syscalls -> EPERM
    for (i, &sys_nr) in BLOCKED_EPERM_SYSCALLS.iter().enumerate() {
        let here = idx_blocked_start + i;
        prog.push(SockFilter::jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            sys_nr,
            rel(here, idx_ret_eperm),
            0,
        ));
    }

    // Fallthrough allow
    debug_assert_eq!(prog.len(), idx_fallthrough_allow);
    prog.push(SockFilter::stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    // [ioctl_check]: ((args[1] as u32 >> 8) & 0xFF) == 0x94 -> EOPNOTSUPP else ALLOW
    debug_assert_eq!(prog.len(), idx_ioctl_check);
    prog.push(SockFilter::stmt(BPF_LD | BPF_W | BPF_ABS, OFF_ARG1_LO));
    prog.push(SockFilter::stmt(BPF_ALU | BPF_RSH | BPF_K, 8));
    prog.push(SockFilter::stmt(BPF_ALU | BPF_AND | BPF_K, 0xFF));
    let idx_ioctl_cmp = prog.len();
    prog.push(SockFilter::jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        BTRFS_IOCTL_MAGIC,
        rel(idx_ioctl_cmp, idx_ret_eopnotsupp),
        rel(idx_ioctl_cmp, idx_ret_allow),
    ));

    // [clone_check]: (args[0] as u32 & CLONE_NEW_ALL_MASK) != 0 -> EPERM else ALLOW
    debug_assert_eq!(prog.len(), idx_clone_check);
    prog.push(SockFilter::stmt(BPF_LD | BPF_W | BPF_ABS, OFF_ARG0_LO));
    let idx_clone_cmp = prog.len();
    prog.push(SockFilter::jump(
        BPF_JMP | BPF_JSET | BPF_K,
        CLONE_NEW_ALL_MASK,
        rel(idx_clone_cmp, idx_ret_eperm),
        rel(idx_clone_cmp, idx_ret_allow),
    ));

    // Terminals
    debug_assert_eq!(prog.len(), idx_ret_allow);
    prog.push(SockFilter::stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    debug_assert_eq!(prog.len(), idx_ret_eperm);
    prog.push(SockFilter::stmt(BPF_RET | BPF_K, ret_errno(EPERM)));
    debug_assert_eq!(prog.len(), idx_ret_enosys);
    prog.push(SockFilter::stmt(BPF_RET | BPF_K, ret_errno(ENOSYS)));
    debug_assert_eq!(prog.len(), idx_ret_eopnotsupp);
    prog.push(SockFilter::stmt(BPF_RET | BPF_K, ret_errno(EOPNOTSUPP)));
    debug_assert_eq!(prog.len(), idx_ret_kill);
    prog.push(SockFilter::stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

    prog
}

/// Evaluate a classic BPF seccomp program against `data` in pure Rust.
///
/// Mirrors the Linux kernel's `BPF_PROG_RUN` semantics for the instruction subset
/// used by seccomp filters, enabling exhaustive cross-platform verification of
/// jump offsets, masks, and return codes.
pub fn eval_filter(program: &[SockFilter], data: &SeccompData) -> Result<u32, String> {
    let mut pc = 0usize;
    let mut acc: u32 = 0;

    while pc < program.len() {
        let insn = program[pc];
        match insn.code {
            c if c == (BPF_LD | BPF_W | BPF_ABS) => {
                acc = data
                    .load_word(insn.k)
                    .ok_or_else(|| format!("out-of-bounds seccomp_data load at offset {}", insn.k))?;
                pc += 1;
            }
            c if c == (BPF_ALU | BPF_RSH | BPF_K) => {
                acc = acc.wrapping_shr(insn.k);
                pc += 1;
            }
            c if c == (BPF_ALU | BPF_AND | BPF_K) => {
                acc &= insn.k;
                pc += 1;
            }
            c if c == (BPF_JMP | BPF_JEQ | BPF_K) => {
                let jump = if acc == insn.k { insn.jt } else { insn.jf } as usize;
                pc += 1 + jump;
            }
            c if c == (BPF_JMP | BPF_JGE | BPF_K) => {
                let jump = if acc >= insn.k { insn.jt } else { insn.jf } as usize;
                pc += 1 + jump;
            }
            c if c == (BPF_JMP | BPF_JSET | BPF_K) => {
                let jump = if (acc & insn.k) != 0 { insn.jt } else { insn.jf } as usize;
                pc += 1 + jump;
            }
            c if c == (BPF_RET | BPF_K) => {
                return Ok(insn.k);
            }
            other => {
                return Err(format!("unsupported cBPF opcode 0x{other:04x} at pc={pc}"));
            }
        }
    }
    Err("seccomp BPF program terminated without RET instruction".to_owned())
}

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
//! - Blocks `io_uring_*`, `bpf`, `ptrace`, `kexec_load`, `kexec_file_load` and the keyring calls
//!   (`add_key`, `request_key`, `keyctl`) -> `EPERM`
//! - Keeps workloads, which share `aos-guest`'s uid, off PID 1 -> `EPERM`:
//!   - `prlimit64` on any pid but `0` (every thread id of `aos-guest` shares its limits)
//!   - `setpriority` / `ioprio_set` on process groups, users, or PID 1
//!   - `sched_setparam`, `sched_setscheduler`, `sched_setaffinity`, `sched_setattr` on PID 1
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
    pub const SETPRIORITY: u32 = 141;
    pub const SCHED_SETPARAM: u32 = 142;
    pub const SCHED_SETSCHEDULER: u32 = 144;
    pub const PIVOT_ROOT: u32 = 155;
    pub const MOUNT: u32 = 165;
    pub const UMOUNT2: u32 = 166;
    pub const SCHED_SETAFFINITY: u32 = 203;
    pub const KEXEC_LOAD: u32 = 246;
    pub const ADD_KEY: u32 = 248;
    pub const REQUEST_KEY: u32 = 249;
    pub const KEYCTL: u32 = 250;
    pub const IOPRIO_SET: u32 = 251;
    pub const UNSHARE: u32 = 272;
    pub const PRLIMIT64: u32 = 302;
    pub const SETNS: u32 = 308;
    pub const SCHED_SETATTR: u32 = 314;
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
    nr::ADD_KEY,
    nr::REQUEST_KEY,
    nr::KEYCTL,
];

/// `setpriority(2)` `which` value for a single process.
const PRIO_PROCESS: u32 = 0;
/// `ioprio_set(2)` `which` value for a single process.
const IOPRIO_WHO_PROCESS: u32 = 1;
/// The only pid `aos-guest` can have inside the world's pid namespace.
const GUEST_PID: u32 = 1;

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

/// Jump targets inside the program, resolved by [`Asm::finish`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Label {
    Allow,
    Eperm,
    Enosys,
    Eopnotsupp,
    Kill,
    IoctlCheck,
    CloneCheck,
    OwnPidOnly,
    NotGuestPid,
    PrioCheck,
    IoprioCheck,
}

/// Minimal forward-only cBPF assembler: every jump names a label or falls through.
#[derive(Default)]
struct Asm {
    prog: Vec<SockFilter>,
    labels: Vec<(Label, usize)>,
    jumps: Vec<(usize, Option<Label>, Option<Label>)>,
}

impl Asm {
    fn stmt(&mut self, code: u16, k: u32) {
        self.prog.push(SockFilter::stmt(code, k));
    }

    /// Conditional jump against `k`; `None` falls through to the next instruction.
    fn jump(&mut self, code: u16, k: u32, jt: Option<Label>, jf: Option<Label>) {
        self.jumps.push((self.prog.len(), jt, jf));
        self.prog.push(SockFilter::jump(code, k, 0, 0));
    }

    fn label(&mut self, label: Label) {
        self.labels.push((label, self.prog.len()));
    }

    fn finish(mut self) -> Vec<SockFilter> {
        for &(from, jt, jf) in &self.jumps {
            let rel = |target: Option<Label>| -> u8 {
                let Some(label) = target else { return 0 };
                let to = self
                    .labels
                    .iter()
                    .find(|(l, _)| *l == label)
                    .map(|(_, i)| *i)
                    .expect("seccomp BPF label must be placed");
                let delta = to
                    .checked_sub(from + 1)
                    .expect("seccomp BPF jumps must always move forward");
                u8::try_from(delta).expect("seccomp BPF jump offset fits in u8")
            };
            let (t, f) = (rel(jt), rel(jf));
            self.prog[from].jt = t;
            self.prog[from].jf = f;
        }
        self.prog
    }
}

/// Compile the strict §7.4 + §5.1 `x86_64` seccomp-BPF program.
///
/// Layout: arch and x32 checks, one `JEQ` per syscall that needs a decision (jumping to an
/// argument check or straight to a return), fallthrough `ALLOW`, the argument checks, then the
/// shared terminal returns. All jumps move forward and fit in `u8`.
pub fn build_x86_64_baseline_filter() -> Vec<SockFilter> {
    use Label::*;
    const JEQ: u16 = BPF_JMP | BPF_JEQ | BPF_K;
    const LD: u16 = BPF_LD | BPF_W | BPF_ABS;
    let mut a = Asm::default();

    // Wrong architecture or x32 ABI -> KILL_PROCESS.
    a.stmt(LD, OFF_ARCH);
    a.jump(JEQ, AUDIT_ARCH_X86_64, None, Some(Kill));
    a.stmt(LD, OFF_NR);
    a.jump(BPF_JMP | BPF_JGE | BPF_K, X32_SYSCALL_BIT, Some(Kill), None);

    // Dispatch on the syscall number (still in the accumulator).
    let dispatch = [
        (nr::IOCTL, IoctlCheck),
        (nr::CLONE, CloneCheck),
        // ENOSYS makes glibc/musl `pthread_create` fall back to clone(2).
        (nr::CLONE3, Enosys),
        (nr::PRLIMIT64, OwnPidOnly),
        (nr::SETPRIORITY, PrioCheck),
        (nr::IOPRIO_SET, IoprioCheck),
        (nr::SCHED_SETPARAM, NotGuestPid),
        (nr::SCHED_SETSCHEDULER, NotGuestPid),
        (nr::SCHED_SETAFFINITY, NotGuestPid),
        (nr::SCHED_SETATTR, NotGuestPid),
    ];
    for (sys_nr, target) in dispatch {
        a.jump(JEQ, sys_nr, Some(target), None);
    }
    for &sys_nr in BLOCKED_EPERM_SYSCALLS {
        a.jump(JEQ, sys_nr, Some(Eperm), None);
    }
    a.stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

    // ((args[1] as u32 >> 8) & 0xFF) == BTRFS_IOCTL_MAGIC -> EOPNOTSUPP.
    a.label(IoctlCheck);
    a.stmt(LD, OFF_ARG1_LO);
    a.stmt(BPF_ALU | BPF_RSH | BPF_K, 8);
    a.stmt(BPF_ALU | BPF_AND | BPF_K, 0xFF);
    a.jump(JEQ, BTRFS_IOCTL_MAGIC, Some(Eopnotsupp), Some(Allow));

    // Any CLONE_NEW* flag -> EPERM.
    a.label(CloneCheck);
    a.stmt(LD, OFF_ARG0_LO);
    a.jump(BPF_JMP | BPF_JSET | BPF_K, CLONE_NEW_ALL_MASK, Some(Eperm), Some(Allow));

    // Pid arguments are C ints, so the low word is what the kernel uses.
    a.label(OwnPidOnly);
    a.stmt(LD, OFF_ARG0_LO);
    a.jump(JEQ, 0, Some(Allow), Some(Eperm));

    // setpriority(which, who) / ioprio_set(which, who): one process, and not PID 1.
    for (label, single_process) in [(PrioCheck, PRIO_PROCESS), (IoprioCheck, IOPRIO_WHO_PROCESS)] {
        a.label(label);
        a.stmt(LD, OFF_ARG0_LO);
        a.jump(JEQ, single_process, None, Some(Eperm));
        a.stmt(LD, OFF_ARG1_LO);
        a.jump(JEQ, GUEST_PID, Some(Eperm), Some(Allow));
    }

    a.label(NotGuestPid);
    a.stmt(LD, OFF_ARG0_LO);
    a.jump(JEQ, GUEST_PID, Some(Eperm), Some(Allow));

    for (label, ret) in [
        (Allow, SECCOMP_RET_ALLOW),
        (Eperm, ret_errno(EPERM)),
        (Enosys, ret_errno(ENOSYS)),
        (Eopnotsupp, ret_errno(EOPNOTSUPP)),
        (Kill, SECCOMP_RET_KILL_PROCESS),
    ] {
        a.label(label);
        a.stmt(BPF_RET | BPF_K, ret);
    }
    a.finish()
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

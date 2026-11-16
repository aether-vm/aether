//! Automatic experiment environment header.
//!
//! Per `docs/PHASE0_FALSIFICATION.md` (red-team rule 2) a performance number without hardware,
//! kernel, filesystem, power and page-cache context is invalid. Every report embeds this header.

use std::path::Path;

use serde::Serialize;

use crate::util::{dirty_kib, iso8601_utc, meminfo_kib, tool_version, unix_now};

/// How much weight a report's performance numbers carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Authority {
    /// WSL2 (L2 nested virtualisation, loop-on-ext4-on-VHDX): functional / crash-semantics evidence only.
    AdvisoryWsl2,
    /// Non-virtualised Linux host: may be published as a baseline.
    BareMetalBaseline,
    /// Could not classify; treat as advisory.
    UnknownAdvisory,
}

/// Collected environment.
#[derive(Debug, Clone, Serialize)]
pub struct EnvHeader {
    /// UTC collection time.
    pub collected_at: String,
    /// Authority level of the numbers in the report.
    pub authority: Authority,
    /// Human explanation of `authority`.
    pub authority_note: String,
    /// Hardware as declared by the operator/docs (cannot be verified from inside WSL2).
    pub host_declared: String,
    /// `/proc/sys/kernel/osrelease`.
    pub kernel_release: String,
    /// First line of `/proc/version`.
    pub kernel_version_line: String,
    /// Whether the kernel identifies as Microsoft/WSL.
    pub is_wsl2: bool,
    /// CPU model name.
    pub cpu_model: String,
    /// Logical CPUs visible.
    pub logical_cpus: usize,
    /// MemTotal in MiB.
    pub mem_total_mib: u64,
    /// MemAvailable in MiB at collection time.
    pub mem_available_mib: u64,
    /// Page-cache `Dirty:` KiB at collection time.
    pub dirty_kib_at_start: u64,
    /// Page-cache `Cached:` MiB at collection time.
    pub cached_mib_at_start: u64,
    /// Kernel boot id.
    pub boot_id: String,
    /// effective uid.
    pub euid: u32,
    /// `/dev/kvm` present.
    pub kvm_present: bool,
    /// Pool root and the filesystem hosting it.
    pub pool_root: String,
    /// Filesystem type name of the pool root.
    pub pool_root_fs: String,
    /// Power state (battery/AC); not observable under WSL2.
    pub power_state: String,
    /// Tool versions.
    pub tools: Vec<(String, String)>,
    /// Command line.
    pub argv: Vec<String>,
}

fn fs_name(path: &Path) -> String {
    match nix::sys::statfs::statfs(path) {
        Ok(s) => {
            let magic = s.filesystem_type().0 as u64 & 0xffff_ffff;
            match magic {
                0x9123_683e => "btrfs".into(),
                0x5846_5342 => "xfs".into(),
                0xef53 => "ext2/3/4".into(),
                0x0102_1997 => "9p (v9fs)".into(),
                0x0102_1994 => "tmpfs".into(),
                0x794c_7630 => "overlayfs".into(),
                other => format!("unknown(0x{other:x})"),
            }
        }
        Err(e) => format!("statfs failed: {e}"),
    }
}

fn read_trim(path: &str) -> String {
    std::fs::read_to_string(path).map(|s| s.trim().to_owned()).unwrap_or_else(|_| "unknown".into())
}

fn power_state() -> String {
    let dir = Path::new("/sys/class/power_supply");
    let names: Vec<String> = std::fs::read_dir(dir)
        .map(|rd| rd.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect())
        .unwrap_or_default();
    if names.is_empty() {
        "unknown (no /sys/class/power_supply; host AC/battery state is not visible from WSL2)".into()
    } else {
        let mut parts = Vec::new();
        for n in names {
            let st = read_trim(&format!("/sys/class/power_supply/{n}/status"));
            let on = read_trim(&format!("/sys/class/power_supply/{n}/online"));
            parts.push(format!("{n}: status={st} online={on}"));
        }
        parts.join("; ")
    }
}

impl EnvHeader {
    /// Collect everything (best effort, never fails).
    #[must_use]
    pub fn collect(pool_root: &Path, argv: Vec<String>) -> Self {
        let kernel_release = read_trim("/proc/sys/kernel/osrelease");
        let version_line = read_trim("/proc/version");
        let lower = format!("{kernel_release} {version_line}").to_lowercase();
        let is_wsl2 = lower.contains("microsoft") || lower.contains("wsl");
        let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
        let cpu_model = cpuinfo
            .lines()
            .find_map(|l| l.strip_prefix("model name"))
            .and_then(|r| r.split(':').nth(1))
            .map_or_else(|| "unknown".into(), |s| s.trim().to_owned());
        let logical_cpus = cpuinfo.lines().filter(|l| l.starts_with("processor")).count();
        let (authority, authority_note) = if is_wsl2 {
            (
                Authority::AdvisoryWsl2,
                "WSL2 = nested virtualisation + loop devices on ext4-on-VHDX + host page cache beneath. \
                 Valid for functional/crash-semantics conclusions; latency/throughput numbers MUST NOT be \
                 published as baselines (docs/PHASE0_FALSIFICATION.md section 1)."
                    .to_owned(),
            )
        } else {
            (
                Authority::UnknownAdvisory,
                "Not WSL2, but bare-metal status is not asserted by this tool; verify manually before publishing."
                    .to_owned(),
            )
        };
        let boot_id = aos_types::BootId::current().map_or_else(|e| format!("error: {e}"), |b| b.to_string());
        let tools = vec![
            ("rustc".to_owned(), tool_version("rustc", &["--version"])),
            ("btrfs-progs".to_owned(), tool_version("btrfs", &["--version"])),
            ("xfsprogs (mkfs.xfs)".to_owned(), tool_version("mkfs.xfs", &["-V"])),
            ("e2fsprogs (mkfs.ext4)".to_owned(), tool_version("mkfs.ext4", &["-V"])),
            ("git".to_owned(), tool_version("git", &["--version"])),
            ("losetup".to_owned(), tool_version("losetup", &["--version"])),
            ("firecracker".to_owned(), tool_version("firecracker", &["--version"])),
        ];
        Self {
            collected_at: iso8601_utc(unix_now()),
            authority,
            authority_note,
            host_declared: "Surface Pro 8, i5-1135G7, 16 GiB RAM (as declared in docs/PHASE0_FALSIFICATION.md section 1.1; \
                            not verifiable from inside WSL2)"
                .into(),
            kernel_release,
            kernel_version_line: version_line,
            is_wsl2,
            cpu_model,
            logical_cpus,
            mem_total_mib: meminfo_kib("MemTotal:") / 1024,
            mem_available_mib: meminfo_kib("MemAvailable:") / 1024,
            dirty_kib_at_start: dirty_kib(),
            cached_mib_at_start: meminfo_kib("Cached:") / 1024,
            boot_id,
            euid: nix::unistd::geteuid().as_raw(),
            kvm_present: Path::new("/dev/kvm").exists(),
            pool_root: pool_root.display().to_string(),
            pool_root_fs: fs_name(pool_root.parent().filter(|_| !pool_root.exists()).unwrap_or(pool_root)),
            power_state: power_state(),
            tools,
            argv,
        }
    }

    /// Markdown rendering.
    #[must_use]
    pub fn to_markdown(&self) -> String {
        let mut s = String::new();
        s.push_str("## Environment header\n\n");
        s.push_str(&format!(
            "> **Authority: `{:?}`** - {}\n\n",
            self.authority, self.authority_note
        ));
        s.push_str("| Field | Value |\n| --- | --- |\n");
        let mut row = |k: &str, v: &str| s.push_str(&format!("| {k} | {} |\n", v.replace('|', "\\|")));
        row("Collected at (UTC)", &self.collected_at);
        row("Declared host hardware", &self.host_declared);
        row("CPU (as seen by guest)", &format!("{} x {}", self.logical_cpus, self.cpu_model));
        row("Memory", &format!("{} MiB total, {} MiB available", self.mem_total_mib, self.mem_available_mib));
        row("Page cache at start", &format!("Cached {} MiB, Dirty {} KiB", self.cached_mib_at_start, self.dirty_kib_at_start));
        row("Kernel", &format!("{} (WSL2: {})", self.kernel_release, self.is_wsl2));
        row("Kernel version line", &self.kernel_version_line);
        row("boot_id", &self.boot_id);
        row("euid / /dev/kvm", &format!("{} / {}", self.euid, self.kvm_present));
        row("Pool root", &format!("{} (fs: {})", self.pool_root, self.pool_root_fs));
        row("Power state", &self.power_state);
        for (k, v) in &self.tools {
            row(k, v);
        }
        row("Command", &self.argv.join(" "));
        s.push('\n');
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_never_panics_and_classifies_wsl() {
        let h = EnvHeader::collect(Path::new("/tmp"), vec!["x".into()]);
        assert!(h.logical_cpus >= 1);
        assert!(h.mem_total_mib > 0);
        assert_eq!(h.authority == Authority::AdvisoryWsl2, h.is_wsl2);
        let md = h.to_markdown();
        assert!(md.contains("Authority"));
        assert!(md.contains("boot_id"));
        let j = serde_json::to_string(&h).unwrap();
        assert!(j.contains("collected_at"));
    }
}

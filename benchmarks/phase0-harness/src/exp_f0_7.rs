//! F0-7: Clone uniqueness (`VMGenID` + `RNDADDENTROPY`/`RNDRESEEDCRNG`) and loopback survival
//! (`NETLINK_SOCK_DIAG`/`SOCK_DESTROY` & `ss -K` severing external TCP while keeping
//! `127.0.0.1` / `[::1]` alive).
//!
//! Verified kernel & ABI constants (see `docs/PHASE0_FALSIFICATION.md` F0-7,
//! `crates/aos-guest/src/netlink_tcp.rs`, and Scout #7):
//! * `RNDRESEEDCRNG` (`<uapi/linux/random.h>`): `_IO('R', 0x07)` = `0x5207`.
//! * `RNDADDENTROPY` (`<uapi/linux/random.h>`): `_IOW('R', 0x03, int[2])` = `0x4008_5203`.
//! * Required moduleless guest `vmlinux` Kconfig: `CONFIG_PCI=y`, `CONFIG_ACPI=y`,
//!   `CONFIG_VMGENID=y`, `CONFIG_HW_RANDOM_VIRTIO=y`, `CONFIG_INET_DIAG=y`,
//!   `CONFIG_INET_TCP_DIAG=y`, `CONFIG_INET_DIAG_DESTROY=y`.
//! * Exact `ss -K` fallback filter (matching `aos-guest::netlink_tcp::ss_kill_fallback_args()`):
//!   `state connected ( not dst 127.0.0.0/8 and not dst [::1] and not dst [::ffff:127.0.0.0/104] )`

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::PathBuf;

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::report::ExpOutput;

/// `<uapi/linux/random.h>` `_IO('R', 0x07)` — force immediate ChaCha20 CRNG reseed.
pub const RNDRESEEDCRNG_IOCTL: u64 = 0x5207;
/// `<uapi/linux/random.h>` `_IOW('R', 0x03, int[2])` — mix bytes AND credit entropy bits.
pub const RNDADDENTROPY_IOCTL: u64 = 0x4008_5203;
/// Exact `ss -K -t` filter expression severing external TCP while keeping loopback sockets alive
/// and excluding `LISTEN`/`TIME-WAIT` (`state connected`).
pub const SS_KILL_EXTERNAL_FILTER: &str =
    "state connected ( not dst 127.0.0.0/8 and not dst [::1] and not dst [::ffff:127.0.0.0/104] )";
/// Minimum healthy pairwise Hamming distance (bits) for 64-byte (512-bit) `/dev/urandom` samples.
pub const MIN_ENTROPY_HAMMING_BITS_64B: u32 = 128;

/// CLI / runner parameters for F0-7.
#[derive(Debug, Clone)]
pub struct Args {
    /// Path to `firecracker` binary (v1.10+ / v1.11+).
    pub firecracker_bin: PathBuf,
    /// Path to mother `vmstate` captured with an established loopback pool + external TCP socket.
    pub snapshot_path: PathBuf,
    /// Path to mother memory snapshot file.
    pub mem_file_path: PathBuf,
    /// Relative or absolute path to Firecracker's host `virtio-vsock` UDS.
    pub vsock_uds: PathBuf,
    /// Guest `AF_VSOCK` port where `aos-guest` listens.
    pub vsock_port: u32,
    /// Number of clones to restore from the identical mother snapshot (default 2).
    pub clones: usize,
    /// Number of bytes sampled from `/dev/urandom` per clone (default 64).
    pub entropy_bytes: usize,
    /// Maximum acceptable latency (ms) for an external TCP socket to report severed.
    pub max_sever_ms: u64,
    /// Per-clone vsock timeout in ms.
    pub vsock_timeout_ms: u64,
    /// Optional guest probe argv executed via `aos-guest` `Exec` to verify loopback pool echo &
    /// external socket RST after `PostForkReseed` (must emit JSON with `external_tcp_severed`,
    /// `external_sever_ms`, `loopback_pool_survived`, and optional `vmgenid_changed`).
    pub socket_probe_argv: Vec<String>,
}

/// Returns `true` iff `ip` is a loopback address that MUST survive post-fork external socket kill
/// (`127.0.0.0/8`, `::1`, or IPv4-mapped `::ffff:127.0.0.0/104`).
#[must_use]
pub fn is_loopback_target(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                return true;
            }
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return mapped.is_loopback();
            }
            false
        }
    }
}

/// Validate that an `ss -K` filter preserves IPv4, IPv6, and IPv4-mapped loopback destinations
/// and restricts to `state connected` (excluding `LISTEN`/`TIME-WAIT`).
pub fn validate_ss_filter(filter: &str) -> Result<()> {
    ensure!(
        filter.contains("state connected"),
        "ss -K filter must restrict to `state connected` (excluding LISTEN/TIME-WAIT)"
    );
    ensure!(
        filter.contains("not dst 127.0.0.0/8"),
        "ss -K filter must exclude IPv4 loopback 127.0.0.0/8"
    );
    ensure!(
        filter.contains("not dst [::1]"),
        "ss -K filter must exclude bracketed IPv6 loopback [::1]"
    );
    ensure!(
        filter.contains("not dst [::ffff:127.0.0.0/104]"),
        "ss -K filter must exclude IPv4-mapped loopback [::ffff:127.0.0.0/104]"
    );
    Ok(())
}

/// Per-clone verification evidence returned via `aos-guest` framed v1 `PostForkReseed` + `Exec`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloneUniquenessSample {
    /// Clone index (`0..clones`).
    pub clone_idx: usize,
    /// Hex-encoded 64B OS-CSPRNG host entropy injected via `PostForkReseed`.
    pub injected_host_entropy_hex: String,
    /// Raw bytes read from `/dev/urandom` inside the clone after reseed.
    pub urandom_sample: Vec<u8>,
    /// Whether `VMGenID` / ACPI notification or reseed ACK was confirmed.
    pub vmgenid_changed: bool,
    /// External TCP sockets destroyed by `aos-guest` (`ReseedAck.killed_tcp_sockets`).
    pub killed_tcp_sockets: u64,
    /// Loopback sockets preserved by `aos-guest` (`ReseedAck.preserved_loopback_sockets`).
    pub preserved_loopback_sockets: u64,
    /// Whether the pre-fork external TCP connection reported severed immediately.
    pub external_tcp_severed: bool,
    /// Observed time (ms) until the pre-fork external socket returned RST/EOF/ECONNRESET.
    pub external_sever_ms: f64,
    /// Whether the pre-fork established `127.0.0.1` loopback connection continued passing traffic.
    pub loopback_pool_survived: bool,
    /// Detail or error diagnostic from guest probe.
    pub detail: String,
}

/// Aggregate entropy-divergence evaluation across all clones.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyDivergence {
    /// Number of clones checked.
    pub clone_count: usize,
    /// Expected sample size in bytes.
    pub sample_bytes: usize,
    /// Number of distinct `/dev/urandom` outputs observed.
    pub unique_samples: usize,
    /// Minimum pairwise Hamming distance (bits) across all `(i, j)` pairs (`i < j`).
    pub min_hamming_bits: u32,
    /// True iff no sample is all-zero, all samples are unique, and Hamming distance is healthy.
    pub passed: bool,
}

/// Compute Hamming distance in bits between two equal-length byte slices.
#[must_use]
pub fn hamming_bits(a: &[u8], b: &[u8]) -> u32 {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| (x ^ y).count_ones())
        .sum()
}

/// Evaluate `/dev/urandom` divergence across `N >= 2` clones.
#[must_use]
pub fn evaluate_entropy(samples: &[CloneUniquenessSample], expected_bytes: usize) -> EntropyDivergence {
    let clone_count = samples.len();
    let mut set = BTreeSet::new();
    let mut any_bad_len_or_zero = false;
    for s in samples {
        if s.urandom_sample.len() != expected_bytes || s.urandom_sample.iter().all(|&b| b == 0) {
            any_bad_len_or_zero = true;
        }
        set.insert(s.urandom_sample.as_slice());
    }

    let mut min_hamming = if clone_count >= 2 { u32::MAX } else { 0 };
    for i in 0..clone_count {
        for j in (i + 1)..clone_count {
            let d = hamming_bits(&samples[i].urandom_sample, &samples[j].urandom_sample);
            if d < min_hamming {
                min_hamming = d;
            }
        }
    }

    // Scale minimum threshold proportionally to sample length (128 bits for 64B = 25% of bits).
    let min_required = ((expected_bytes as u32) * 8) / 4;
    let passed = clone_count >= 2
        && !any_bad_len_or_zero
        && set.len() == clone_count
        && min_hamming >= min_required;

    EntropyDivergence {
        clone_count,
        sample_bytes: expected_bytes,
        unique_samples: set.len(),
        min_hamming_bits: min_hamming,
        passed,
    }
}

/// Complete F0-7 report payload.
#[derive(Debug, Clone, Serialize)]
pub struct F07Report {
    /// Verified `RNDRESEEDCRNG` ioctl number.
    pub rndreseedcrng_ioctl: String,
    /// Verified `RNDADDENTROPY` ioctl number.
    pub rndaddentropy_ioctl: String,
    /// Verified `ss -K` external filter.
    pub ss_kill_filter: String,
    /// Entropy divergence analysis.
    pub entropy: EntropyDivergence,
    /// True iff every clone severed its external TCP connection within `max_sever_ms`.
    pub all_external_severed: bool,
    /// True iff every clone preserved its pre-fork `127.0.0.1` loopback connection pool.
    pub all_loopback_survived: bool,
    /// Overall pass verdict.
    pub passed: bool,
    /// Per-clone samples.
    pub clones: Vec<CloneUniquenessSample>,
}

/// Build standard JSON + Markdown `ExpOutput` for F0-7.
#[must_use]
pub fn build_report(
    entropy_bytes: usize,
    max_sever_ms: u64,
    clones: Vec<CloneUniquenessSample>,
) -> ExpOutput {
    let entropy = evaluate_entropy(&clones, entropy_bytes);
    let all_external_severed = !clones.is_empty()
        && clones
            .iter()
            .all(|c| c.external_tcp_severed && c.external_sever_ms <= max_sever_ms as f64);
    let all_loopback_survived = !clones.is_empty() && clones.iter().all(|c| c.loopback_pool_survived);
    let passed = entropy.passed && all_external_severed && all_loopback_survived;

    let report = F07Report {
        rndreseedcrng_ioctl: format!("0x{RNDRESEEDCRNG_IOCTL:04x}"),
        rndaddentropy_ioctl: format!("0x{RNDADDENTROPY_IOCTL:08x}"),
        ss_kill_filter: SS_KILL_EXTERNAL_FILTER.to_owned(),
        entropy,
        all_external_severed,
        all_loopback_survived,
        passed,
        clones,
    };

    let mut md = String::new();
    md.push_str("## F0-7: Clone Uniqueness & Loopback Connection Survival\n\n");
    md.push_str(&format!(
        "- Verdict: **{}**\n",
        if report.passed { "PASS" } else { "FAIL" }
    ));
    md.push_str(&format!(
        "- Entropy divergence: **{}/{}** unique {}B samples, min pairwise Hamming distance = **{} bits** (pass={})\n",
        report.entropy.unique_samples,
        report.entropy.clone_count,
        report.entropy.sample_bytes,
        report.entropy.min_hamming_bits,
        report.entropy.passed,
    ));
    md.push_str(&format!(
        "- External TCP severed (`SOCK_DESTROY` / `ss -K`, <= {max_sever_ms} ms): **{}**\n",
        report.all_external_severed
    ));
    md.push_str(&format!(
        "- Loopback (`127.0.0.1` / `[::1]`) pool survived: **{}**\n",
        report.all_loopback_survived
    ));
    md.push_str(&format!(
        "- Kernel ABI: `RNDADDENTROPY={}`, `RNDRESEEDCRNG={}`, filter=`{}`\n\n",
        report.rndaddentropy_ioctl, report.rndreseedcrng_ioctl, report.ss_kill_filter
    ));
    md.push_str("| Clone | Killed Ext TCP | Kept Loopback | External Severed | Sever (ms) | Loopback Survived | Detail |\n");
    md.push_str("| ---: | ---: | ---: | :---: | ---: | :---: | :--- |\n");
    for c in &report.clones {
        md.push_str(&format!(
            "| {} | {} | {} | {} | {:.2} | {} | {} |\n",
            c.clone_idx,
            c.killed_tcp_sockets,
            c.preserved_loopback_sockets,
            c.external_tcp_severed,
            c.external_sever_ms,
            c.loopback_pool_survived,
            c.detail.replace('|', "\\|")
        ));
    }
    md.push('\n');

    ExpOutput {
        id: "F0-7",
        slug: "f0-7-clone-unique",
        json: json!(report),
        md,
    }
}

/// Format bytes as lowercase hex.
#[must_use]
pub fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

/// Decode lowercase/uppercase hex string into bytes.
pub fn decode_hex(s: &str) -> Result<Vec<u8>> {
    ensure!(s.len().is_multiple_of(2), "hex string must have even length");
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in s.as_bytes().chunks_exact(2) {
        let hi = hex_nibble(pair[0])?;
        let lo = hex_nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => anyhow::bail!("invalid hex byte: 0x{b:02x}"),
    }
}

/// Generate 64 bytes of fresh cryptographic entropy from the OS CSPRNG (`getrandom`).
pub fn os_csprng_64() -> Result<[u8; 64]> {
    let mut buf = [0u8; 64];
    getrandom::fill(&mut buf).map_err(|e| anyhow::anyhow!("OS CSPRNG getrandom failed: {e}"))?;
    Ok(buf)
}

/// Execute F0-7 against real Firecracker clones + `aos-guest` framed v1 protocol (Linux + KVM).
#[cfg(target_os = "linux")]
pub fn run(ctx: &crate::Ctx, args: &Args) -> Result<ExpOutput> {
    use std::path::Path;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use anyhow::Context;

    use crate::firecracker::linux::{vsock_exchange_framed, FcClient, FcProcess};
    use crate::firecracker::{
        guest_exec_request, guest_post_fork_reseed_request, parse_guest_exec_result,
        parse_guest_reseed_ack, SnapshotLoadParams,
    };

    ensure!(
        Path::new("/dev/kvm").exists(),
        "F0-7 requires /dev/kvm on a Linux KVM host"
    );
    ensure!(args.clones >= 2, "--clones must be >= 2");
    validate_ss_filter(SS_KILL_EXTERNAL_FILTER)?;
    ensure!(
        args.snapshot_path.exists() && args.mem_file_path.exists(),
        "snapshot_path and mem_file_path must exist"
    );

    let work_root = ctx.root.join("f0-7");
    let _ = std::fs::remove_dir_all(&work_root);
    std::fs::create_dir_all(&work_root)?;

    let timeout = Duration::from_millis(args.vsock_timeout_ms);
    let mut clones = Vec::with_capacity(args.clones);
    let mut guards = Vec::with_capacity(args.clones);

    for idx in 0..args.clones {
        let clone_dir = work_root.join(format!("clone-{idx}"));
        std::fs::create_dir_all(&clone_dir)?;
        let api_sock = clone_dir.join("fc.api.sock");
        let fc = FcProcess::spawn(
            &args.firecracker_bin,
            &api_sock,
            &clone_dir,
            Duration::from_secs(5),
        )?;
        let client = FcClient::new(&api_sock);
        client.load_snapshot(&SnapshotLoadParams::file_backend(
            &args.snapshot_path,
            &args.mem_file_path,
            false,
            true,
        ))?;

        let vsock_path = if args.vsock_uds.is_absolute() {
            args.vsock_uds.clone()
        } else {
            clone_dir.join(&args.vsock_uds)
        };

        // 1) Generate 64 bytes from real OS CSPRNG (never SplitMix64) and send `PostForkReseed`.
        let host_entropy = os_csprng_64()?;
        let entropy_hex = encode_hex(&host_entropy);
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        let req_base = ((idx as u64) + 1) * 100;

        let t_reseed = Instant::now();
        let reseed_req = guest_post_fork_reseed_request(
            req_base + 1,
            &host_entropy,
            now.as_secs() as i64,
            now.subsec_nanos(),
            true,
            Some(&format!("f0-7-clone-{idx}")),
        )?;
        let (ack_bytes, _) =
            vsock_exchange_framed(&vsock_path, args.vsock_port, &reseed_req, timeout)?;
        let ack = parse_guest_reseed_ack(&ack_bytes, req_base + 1)?;
        let reseed_ms = t_reseed.elapsed().as_secs_f64() * 1e3;
        ensure!(
            ack.entropy_injected_bytes == 64 && ack.crng_reseeded && ack.unfrozen,
            "clone {idx}: incomplete PostForkReseed ack: {ack:?}"
        );

        // 2) Sample `/dev/urandom` inside the clone via `aos-guest` v1 `Exec`.
        let rng_argv = vec![
            "dd".to_owned(),
            "if=/dev/urandom".to_owned(),
            format!("bs={}", args.entropy_bytes),
            "count=1".to_owned(),
            "status=none".to_owned(),
        ];
        let rng_req = guest_exec_request(
            req_base + 2,
            &format!("f07-rng-{idx}"),
            &rng_argv,
            args.vsock_timeout_ms,
        )?;
        let (rng_bytes, _) =
            vsock_exchange_framed(&vsock_path, args.vsock_port, &rng_req, timeout)?;
        let rng_res = parse_guest_exec_result(&rng_bytes, req_base + 2)?;
        ensure!(
            rng_res.exit_code == Some(0) && rng_res.stdout.len() == args.entropy_bytes,
            "clone {idx}: /dev/urandom sample failed (exit={:?}, len={})",
            rng_res.exit_code,
            rng_res.stdout.len()
        );

        // 3) Verify external TCP severing & loopback connection pool survival via guest probe Exec
        //    (when `--socket-probe-argv` is provided) or fall back to `ReseedAck` kernel counters.
        let (vmgenid_changed, external_tcp_severed, external_sever_ms, loopback_pool_survived, detail) =
            if !args.socket_probe_argv.is_empty() {
                let probe_req = guest_exec_request(
                    req_base + 3,
                    &format!("f07-sock-{idx}"),
                    &args.socket_probe_argv,
                    args.vsock_timeout_ms,
                )?;
                let (probe_bytes, _) =
                    vsock_exchange_framed(&vsock_path, args.vsock_port, &probe_req, timeout)?;
                let probe_res = parse_guest_exec_result(&probe_bytes, req_base + 3)?;
                ensure!(
                    probe_res.exit_code == Some(0),
                    "clone {idx}: socket probe failed (exit={:?}): {}",
                    probe_res.exit_code,
                    String::from_utf8_lossy(&probe_res.stderr)
                );
                let v: serde_json::Value = serde_json::from_slice(&probe_res.stdout)
                    .context("parse guest socket probe JSON stdout")?;
                (
                    v["vmgenid_changed"].as_bool().unwrap_or(ack.crng_reseeded),
                    v["external_tcp_severed"].as_bool().unwrap_or(false),
                    v["external_sever_ms"].as_f64().unwrap_or(reseed_ms),
                    v["loopback_pool_survived"].as_bool().unwrap_or(false),
                    v["detail"].as_str().unwrap_or("probe ok").to_owned(),
                )
            } else {
                (
                    ack.crng_reseeded,
                    ack.killed_tcp_sockets > 0,
                    reseed_ms,
                    ack.preserved_loopback_sockets > 0,
                    format!(
                        "reseed_ack(killed_ext={},preserved_lo={})",
                        ack.killed_tcp_sockets, ack.preserved_loopback_sockets
                    ),
                )
            };

        clones.push(CloneUniquenessSample {
            clone_idx: idx,
            injected_host_entropy_hex: entropy_hex,
            urandom_sample: rng_res.stdout,
            vmgenid_changed,
            killed_tcp_sockets: ack.killed_tcp_sockets,
            preserved_loopback_sockets: ack.preserved_loopback_sockets,
            external_tcp_severed,
            external_sever_ms,
            loopback_pool_survived,
            detail,
        });
        guards.push(fc);
    }
    drop(guards);

    Ok(build_report(args.entropy_bytes, args.max_sever_ms, clones))
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn loopback_classifier_and_ss_filter_rules() {
        validate_ss_filter(SS_KILL_EXTERNAL_FILTER).unwrap();
        assert!(validate_ss_filter("( not dst 127.0.0.0/8 )").is_err());
        assert!(is_loopback_target(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(is_loopback_target(IpAddr::V4(Ipv4Addr::new(127, 42, 0, 9))));
        assert!(is_loopback_target(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(is_loopback_target(IpAddr::V6(
            "::ffff:127.0.0.1".parse().unwrap()
        )));
        assert!(!is_loopback_target(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(!is_loopback_target(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        assert!(!is_loopback_target(IpAddr::V6("2001:db8::1".parse().unwrap())));
    }

    #[test]
    fn entropy_divergence_passes_for_os_csprng_and_rejects_identical() {
        let a = os_csprng_64().unwrap().to_vec();
        let b = os_csprng_64().unwrap().to_vec();
        assert_ne!(a, b);

        let good = vec![
            CloneUniquenessSample {
                clone_idx: 0,
                injected_host_entropy_hex: "aa".into(),
                urandom_sample: a.clone(),
                vmgenid_changed: true,
                killed_tcp_sockets: 1,
                preserved_loopback_sockets: 2,
                external_tcp_severed: true,
                external_sever_ms: 1.2,
                loopback_pool_survived: true,
                detail: "ok".into(),
            },
            CloneUniquenessSample {
                clone_idx: 1,
                injected_host_entropy_hex: "bb".into(),
                urandom_sample: b,
                vmgenid_changed: true,
                killed_tcp_sockets: 1,
                preserved_loopback_sockets: 2,
                external_tcp_severed: true,
                external_sever_ms: 1.4,
                loopback_pool_survived: true,
                detail: "ok".into(),
            },
        ];
        let out = build_report(64, 100, good);
        assert_eq!(out.id, "F0-7");
        assert_eq!(out.slug, "f0-7-clone-unique");
        assert_eq!(out.json["passed"], true);
        assert!(
            out.json["entropy"]["min_hamming_bits"].as_u64().unwrap()
                >= u64::from(MIN_ENTROPY_HAMMING_BITS_64B)
        );

        // Identical RNG output across clones MUST FAIL!
        let bad = vec![
            CloneUniquenessSample {
                clone_idx: 0,
                injected_host_entropy_hex: "aa".into(),
                urandom_sample: a.clone(),
                vmgenid_changed: false,
                killed_tcp_sockets: 1,
                preserved_loopback_sockets: 2,
                external_tcp_severed: true,
                external_sever_ms: 1.0,
                loopback_pool_survived: true,
                detail: "dup".into(),
            },
            CloneUniquenessSample {
                clone_idx: 1,
                injected_host_entropy_hex: "bb".into(),
                urandom_sample: a,
                vmgenid_changed: false,
                killed_tcp_sockets: 1,
                preserved_loopback_sockets: 2,
                external_tcp_severed: true,
                external_sever_ms: 1.0,
                loopback_pool_survived: true,
                detail: "dup".into(),
            },
        ];
        let out_bad = build_report(64, 100, bad);
        assert_eq!(out_bad.json["passed"], false);
        assert_eq!(out_bad.json["entropy"]["passed"], false);
    }

    #[test]
    fn hex_roundtrip() {
        let raw = [0x00, 0x0f, 0xab, 0xff];
        let h = encode_hex(&raw);
        assert_eq!(h, "000fabff");
        assert_eq!(decode_hex(&h).unwrap(), raw);
    }
}

//! Cross-platform unit and integration tests for `aos-guest`.
//!
//! Exercises framing, base64 payloads, bounded head/tail truncation, cgroup v2
//! parsing & controller polling, Netlink `SOCK_DIAG`/`SOCK_DESTROY` wire layout
//! & loopback classification, state machine transitions, and end-to-end
//! `AgentServer` round-trips including simulated `VIRTIO_VSOCK_EVENT_TRANSPORT_RESET`
//! reconnects after snapshot restore.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Cursor};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aos_guest::base64::{self, Base64Error};
use aos_guest::cgroup::{
    CgroupError, CgroupEvents, CgroupV2Controller, parse_cgroup_events, sub_cgroup_path,
    validate_exec_id,
};
use aos_guest::codec::{CodecError, FrameCodec};
use aos_guest::netlink_tcp::{
    AF_INET, AF_INET6, INET_DIAG_MSG_LEN, INET_DIAG_REQ_V2_LEN, InetDiagMsg, InetDiagSockId,
    KILLABLE_TCP_STATES_MASK, NLMSG_DONE, NLMSG_ERROR, NLMSG_HDRLEN, ParsedNetlinkFrame,
    ParsedNetlinkMsg, SOCK_DESTROY, SOCK_DIAG_BY_FAMILY, SocketAction, TCP_CLOSE_WAIT,
    TCP_ESTABLISHED, TCP_LISTEN, TCP_SYN_RECV, TCP_SYN_SENT, TCP_TIME_WAIT,
    build_tcp_destroy_request, build_tcp_dump_request, classify_tcp_socket, is_loopback_ip,
    parse_netlink_frames, parse_netlink_messages, ss_kill_fallback_args,
};
use aos_guest::protocol::{
    AgentState, BytesPayload, ErrorCode, GuestRequest, GuestResponse, OutputStream,
    PROTOCOL_VERSION, RESEED_ENTROPY_LEN, RequestEnvelope, ResponseEnvelope,
};
use aos_guest::server::{
    AgentServer, BackendError, ExecOutcome, ExecSpec, GuestBackend, SocketKillReport, SyncOutcome,
    max_allowed_output_bytes, max_allowed_stream_chunk_bytes,
};
use aos_guest::state::{AgentStateMachine, StateError};
use aos_guest::truncation::{HeadTailBuffer, drain_stream};

// ---------------------------------------------------------------------------
// 1. Base64 tests
// ---------------------------------------------------------------------------

#[test]
fn base64_rfc4648_vectors_and_binary_roundtrip() {
    let vectors = [
        (&b""[..], ""),
        (b"f", "Zg=="),
        (b"fo", "Zm8="),
        (b"foo", "Zm9v"),
        (b"foob", "Zm9vYg=="),
        (b"fooba", "Zm9vYmE="),
        (b"foobar", "Zm9vYmFy"),
    ];
    for (raw, expected) in vectors {
        assert_eq!(base64::encode(raw), expected);
        assert_eq!(base64::decode(expected).unwrap(), raw);
    }

    // All 256 byte values round-trip losslessly.
    let all_bytes: Vec<u8> = (0u8..=255).collect();
    let encoded = base64::encode(&all_bytes);
    assert_eq!(base64::decode(&encoded).unwrap(), all_bytes);
}

#[test]
fn base64_rejects_malformed_inputs() {
    assert_eq!(base64::decode("abc"), Err(Base64Error::InvalidLength(3)));
    assert!(matches!(
        base64::decode("ab$d"),
        Err(Base64Error::InvalidByte { offset: 2, byte: b'$' })
    ));
    assert_eq!(base64::decode("Zg==AAAA"), Err(Base64Error::InvalidPadding));
    assert_eq!(base64::decode("Zh=="), Err(Base64Error::NonCanonicalTrailingBits));
    assert_eq!(base64::decode("Zm9="), Err(Base64Error::NonCanonicalTrailingBits));
}

// ---------------------------------------------------------------------------
// 2. Length-prefixed JSON FrameCodec tests
// ---------------------------------------------------------------------------

#[test]
fn codec_roundtrip_multiple_frames_and_clean_eof() {
    let codec = FrameCodec::default();
    let mut wire = Vec::new();

    let req1 = RequestEnvelope::new(1, GuestRequest::Ping { nonce: 42 });
    let req2 = RequestEnvelope::new(
        2,
        GuestRequest::FreezeAndSync {
            pre_freeze_hook: Some(vec!["/bin/true".into()]),
            freeze_timeout_ms: Some(1000),
            sync_paths: vec!["/".into()],
            perform_syncfs: true,
        },
    );

    codec.write_frame(&mut wire, &req1).unwrap();
    codec.write_frame(&mut wire, &req2).unwrap();

    let mut cursor = Cursor::new(wire);
    let d1: Option<RequestEnvelope> = codec.read_frame(&mut cursor).unwrap();
    let d2: Option<RequestEnvelope> = codec.read_frame(&mut cursor).unwrap();
    let d3: Option<RequestEnvelope> = codec.read_frame(&mut cursor).unwrap();

    assert_eq!(d1, Some(req1));
    assert_eq!(d2, Some(req2));
    assert_eq!(d3, None);
}

#[test]
fn codec_rejects_zero_oversized_and_truncated_frames() {
    let codec = FrameCodec::new(64);

    // Length prefix 0 must be rejected.
    let mut zero = Cursor::new(0u32.to_be_bytes().to_vec());
    assert!(matches!(
        codec.read_frame::<_, RequestEnvelope>(&mut zero),
        Err(CodecError::ZeroLengthFrame)
    ));

    // Oversized frame rejected BEFORE allocating payload.
    let mut huge = Cursor::new(1024u32.to_be_bytes().to_vec());
    assert!(matches!(
        codec.read_frame::<_, RequestEnvelope>(&mut huge),
        Err(CodecError::FrameTooLarge { len: 1024, max: 64 })
    ));

    // Write-side limit also enforced.
    let big_req = RequestEnvelope::new(
        9,
        GuestRequest::PostForkReseed {
            entropy: BytesPayload::from(vec![0xAB; 64]),
            wall_time_secs: 1_700_000_000,
            wall_time_nanos: 0,
            kill_external_tcp: true,
            unfreeze_timeout_ms: None,
            world_id: None,
        },
    );
    let mut sink = Vec::new();
    assert!(matches!(
        codec.write_frame(&mut sink, &big_req),
        Err(CodecError::FrameTooLarge { .. })
    ));

    // Truncated header (2 bytes).
    let mut short_hdr = Cursor::new(vec![0u8, 1]);
    assert!(matches!(
        codec.read_frame::<_, RequestEnvelope>(&mut short_hdr),
        Err(CodecError::TruncatedFrame { expected: 4, got: 2 })
    ));

    // Truncated payload (claims 20 bytes, has 5).
    let mut short_body = Vec::new();
    short_body.extend_from_slice(&20u32.to_be_bytes());
    short_body.extend_from_slice(b"hello");
    let mut cur = Cursor::new(short_body);
    assert!(matches!(
        codec.read_frame::<_, RequestEnvelope>(&mut cur),
        Err(CodecError::TruncatedFrame { expected: 20, got: 5 })
    ));
}

// ---------------------------------------------------------------------------
// 3. Bounded Head/Tail Truncation tests
// ---------------------------------------------------------------------------

#[test]
fn head_tail_buffer_boundary_cases() {
    // Budget = 0 still accounts total_bytes and marks truncated when non-empty.
    let mut zero = HeadTailBuffer::new(0);
    zero.push(b"abcdef");
    let out = zero.finish();
    assert!(out.truncated);
    assert_eq!(out.total_bytes, 6);
    assert_eq!(out.omitted_bytes, 6);
    assert!(out.head.is_empty());
    assert!(out.tail.is_empty());

    // Budget = 1: head_cap = 1, tail_cap = 0.
    let mut one = HeadTailBuffer::new(1);
    one.push(b"xyz");
    let out = one.finish();
    assert!(out.truncated);
    assert_eq!(out.head.as_slice(), b"x");
    assert!(out.tail.is_empty());
    assert_eq!(out.omitted_bytes, 2);
    assert_eq!(out.total_bytes, 3);

    // Exact boundary: total_bytes == budget -> NOT truncated, contiguous in `head`.
    let mut exact = HeadTailBuffer::new(10);
    exact.push(b"0123");
    exact.push(b"456789");
    let out = exact.finish();
    assert!(!out.truncated);
    assert_eq!(out.omitted_bytes, 0);
    assert_eq!(out.total_bytes, 10);
    assert_eq!(out.head.as_slice(), b"0123456789");
    assert!(out.tail.is_empty());

    // One byte over budget: total_bytes == budget + 1 -> truncated by 1 byte.
    let mut over1 = HeadTailBuffer::new(10);
    over1.push(b"0123456789X");
    let out = over1.finish();
    assert!(out.truncated);
    assert_eq!(out.head.as_slice(), b"01234");
    assert_eq!(out.tail.as_slice(), b"6789X");
    assert_eq!(out.omitted_bytes, 1);
    assert_eq!(out.total_bytes, 11);
    assert_eq!(
        out.head.len() as u64 + out.omitted_bytes + out.tail.len() as u64,
        out.total_bytes
    );
}

#[test]
fn drain_stream_drains_large_input_and_preserves_head_tail_invariant() {
    let mut payload = Vec::with_capacity(100_000);
    for i in 0..100_000usize {
        payload.push((i % 251) as u8);
    }

    let mut streamed = Vec::new();
    let bounded = drain_stream(Cursor::new(&payload), 1024, 333, |chunk| {
        streamed.extend_from_slice(chunk);
        Ok(())
    })
    .unwrap();

    // Every single byte was streamed/drained continuously without loss.
    assert_eq!(streamed, payload);

    // Retained output stays strictly bounded to 1024 bytes (512 head + 512 tail).
    assert!(bounded.truncated);
    assert_eq!(bounded.total_bytes, 100_000);
    assert_eq!(bounded.head.len(), 512);
    assert_eq!(bounded.tail.len(), 512);
    assert_eq!(bounded.omitted_bytes, 100_000 - 1024);
    assert_eq!(bounded.head.as_slice(), &payload[..512]);
    assert_eq!(bounded.tail.as_slice(), &payload[100_000 - 512..]);

    let rendered = bounded.render_lossy_with_marker();
    assert!(rendered.contains("truncated 98976 bytes of 100000 total"));
}

// ---------------------------------------------------------------------------
// 4. Cgroup v2 parsing, validation & simulated filesystem polling tests
// ---------------------------------------------------------------------------

#[test]
fn cgroup_events_parsing_and_exec_id_validation() {
    let parsed = parse_cgroup_events("populated 1\nfrozen 0\n").unwrap();
    assert_eq!(
        parsed,
        CgroupEvents {
            populated: true,
            frozen: false
        }
    );

    let frozen = parse_cgroup_events("populated 1\nfrozen 1\nextra_key 99\n").unwrap();
    assert_eq!(
        frozen,
        CgroupEvents {
            populated: true,
            frozen: true
        }
    );

    assert_eq!(
        parse_cgroup_events("populated 1\n"),
        Err(CgroupError::MissingEventsKey("frozen"))
    );
    assert!(matches!(
        parse_cgroup_events("populated 1\nfrozen 2\n"),
        Err(CgroupError::InvalidEventsValue { .. })
    ));

    // exec_id path-traversal defense.
    assert!(validate_exec_id("run-01_a.b").is_ok());
    assert!(validate_exec_id("").is_err());
    assert!(validate_exec_id(".").is_err());
    assert!(validate_exec_id("..").is_err());
    assert!(validate_exec_id("../escape").is_err());
    assert!(validate_exec_id("a/b").is_err());
    assert!(validate_exec_id("a\\b").is_err());
    assert!(validate_exec_id("bad\0id").is_err());
    assert!(validate_exec_id(&"x".repeat(65)).is_err());

    let p = sub_cgroup_path(&PathBuf::from("/sys/fs/cgroup/aos.workload"), "job-7").unwrap();
    assert!(p.ends_with("exec-job-7"));
}

fn unique_temp_dir(prefix: &str) -> PathBuf {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "aos-guest-test-{prefix}-{}-{nanos}-{seq}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn cgroup_controller_freeze_poll_and_subcgroup_lifecycle() {
    let root = unique_temp_dir("cgroup");
    fs::write(root.join("cgroup.freeze"), "0").unwrap();
    fs::write(root.join("cgroup.events"), "populated 1\nfrozen 0\n").unwrap();

    let ctrl = CgroupV2Controller::new(&root);

    // Spawn a simulated kernel thread that transitions cgroup.events to `frozen 1`
    // shortly after observing `cgroup.freeze == 1`.
    let root_bg = root.clone();
    let kernel_sim = thread::spawn(move || {
        for _ in 0..100 {
            if fs::read_to_string(root_bg.join("cgroup.freeze"))
                .unwrap_or_default()
                .trim()
                == "1"
            {
                thread::sleep(Duration::from_millis(15));
                fs::write(root_bg.join("cgroup.events"), "populated 1\nfrozen 1\n").unwrap();
                break;
            }
            thread::sleep(Duration::from_millis(2));
        }
    });

    let elapsed = ctrl
        .set_freeze_and_wait(true, Duration::from_secs(2))
        .unwrap();
    kernel_sim.join().unwrap();
    assert!(elapsed < Duration::from_secs(2));
    assert!(ctrl.read_events().unwrap().frozen);

    // Verify timeout fires if cgroup never flips back to frozen=0.
    let err = ctrl
        .set_freeze_and_wait(false, Duration::from_millis(30))
        .unwrap_err();
    assert!(matches!(
        err,
        CgroupError::FreezeWaitTimeout {
            expected: false,
            ..
        }
    ));

    // Sub-cgroup creation, collision rejection, cgroup.kill, pids parsing, and cleanup.
    let sub = ctrl.create_exec_subcgroup("cmd-99").unwrap();
    // Colliding exec_id MUST fail rather than silently reusing the existing sub-cgroup.
    assert!(matches!(
        ctrl.create_exec_subcgroup("cmd-99"),
        Err(CgroupError::Io { .. })
    ));
    fs::write(sub.join("cgroup.kill"), "0").unwrap();
    fs::write(sub.join("cgroup.procs"), "1234\n5678\n").unwrap();
    assert_eq!(ctrl.read_pids(&sub).unwrap(), vec![1234, 5678]);
    assert!(ctrl.trigger_cgroup_kill(&sub).unwrap());
    assert_eq!(fs::read_to_string(sub.join("cgroup.kill")).unwrap(), "1");

    let _ = fs::remove_dir_all(&root);
}

// ---------------------------------------------------------------------------
// 5. Netlink SOCK_DIAG / SOCK_DESTROY & Loopback Preservation tests
// ---------------------------------------------------------------------------

fn make_diag_msg(family: u8, state: u8, src: IpAddr, dst: IpAddr, sport: u16, dport: u16) -> InetDiagMsg {
    let encode_ip = |ip: IpAddr| -> [u8; 16] {
        let mut raw = [0u8; 16];
        match ip {
            IpAddr::V4(v4) => raw[..4].copy_from_slice(&v4.octets()),
            IpAddr::V6(v6) => raw.copy_from_slice(&v6.octets()),
        }
        raw
    };
    InetDiagMsg {
        family,
        state,
        timer: 0,
        retrans: 0,
        id: InetDiagSockId {
            sport_be: sport.to_be_bytes(),
            dport_be: dport.to_be_bytes(),
            src_raw: encode_ip(src),
            dst_raw: encode_ip(dst),
            iface: 0,
            cookie: [0x11223344, 0x55667788],
        },
        expires: 0,
        rqueue: 0,
        wqueue: 0,
        uid: 0,
        inode: 42,
    }
}

fn encode_diag_nlmsg(msg: &InetDiagMsg) -> Vec<u8> {
    let total_len = (NLMSG_HDRLEN + INET_DIAG_MSG_LEN) as u32;
    let mut buf = Vec::with_capacity(total_len as usize);
    buf.extend_from_slice(&total_len.to_ne_bytes());
    buf.extend_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
    buf.extend_from_slice(&0u16.to_ne_bytes());
    buf.extend_from_slice(&1u32.to_ne_bytes());
    buf.extend_from_slice(&0u32.to_ne_bytes());

    buf.push(msg.family);
    buf.push(msg.state);
    buf.push(msg.timer);
    buf.push(msg.retrans);
    msg.id.encode_into(&mut buf);
    buf.extend_from_slice(&msg.expires.to_ne_bytes());
    buf.extend_from_slice(&msg.rqueue.to_ne_bytes());
    buf.extend_from_slice(&msg.wqueue.to_ne_bytes());
    buf.extend_from_slice(&msg.uid.to_ne_bytes());
    buf.extend_from_slice(&msg.inode.to_ne_bytes());
    buf
}

#[test]
fn netlink_tcp_loopback_classification_and_wire_encoding() {
    assert!(is_loopback_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    assert!(is_loopback_ip(IpAddr::V4(Ipv4Addr::new(127, 12, 34, 56))));
    assert!(is_loopback_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    assert!(is_loopback_ip(IpAddr::V6(
        Ipv4Addr::new(127, 0, 0, 1).to_ipv6_mapped()
    )));
    assert!(!is_loopback_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
    assert!(!is_loopback_ip(IpAddr::V6(
        Ipv4Addr::new(10, 0, 0, 2).to_ipv6_mapped()
    )));

    // Loopback connections preserved.
    let lo_v4 = make_diag_msg(
        AF_INET,
        TCP_ESTABLISHED,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        54321,
        5432,
    );
    assert_eq!(classify_tcp_socket(&lo_v4), SocketAction::PreserveLoopback);

    let lo_v6 = make_diag_msg(
        AF_INET6,
        TCP_ESTABLISHED,
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        40000,
        6379,
    );
    assert_eq!(classify_tcp_socket(&lo_v6), SocketAction::PreserveLoopback);

    let lo_mapped = make_diag_msg(
        AF_INET6,
        TCP_ESTABLISHED,
        IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped()),
        IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped()),
        40001,
        8080,
    );
    assert_eq!(
        classify_tcp_socket(&lo_mapped),
        SocketAction::PreserveLoopback
    );

    // External connections killed across active states.
    for st in [TCP_ESTABLISHED, TCP_SYN_SENT, TCP_CLOSE_WAIT] {
        let ext = make_diag_msg(
            AF_INET,
            st,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            45000,
            443,
        );
        assert_eq!(classify_tcp_socket(&ext), SocketAction::Kill);
    }

    // LISTEN, SYN_RECV (request_sock), and TIME_WAIT sockets skipped.
    let listen = make_diag_msg(
        AF_INET,
        TCP_LISTEN,
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        8080,
        0,
    );
    assert_eq!(classify_tcp_socket(&listen), SocketAction::SkipState);

    let syn_recv = make_diag_msg(
        AF_INET,
        TCP_SYN_RECV,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        443,
        55555,
    );
    assert_eq!(classify_tcp_socket(&syn_recv), SocketAction::SkipState);

    let time_wait = make_diag_msg(
        AF_INET,
        TCP_TIME_WAIT,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        45000,
        443,
    );
    assert_eq!(classify_tcp_socket(&time_wait), SocketAction::SkipState);

    // Wire builders produce exact Linux struct sizes and state masks.
    let dump = build_tcp_dump_request(AF_INET, 7);
    assert_eq!(dump.len(), NLMSG_HDRLEN + INET_DIAG_REQ_V2_LEN);
    assert_eq!(u16::from_ne_bytes([dump[4], dump[5]]), SOCK_DIAG_BY_FAMILY);

    let ext = make_diag_msg(
        AF_INET,
        TCP_ESTABLISHED,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        44444,
        443,
    );
    let destroy = build_tcp_destroy_request(&ext, 8);
    assert_eq!(destroy.len(), NLMSG_HDRLEN + INET_DIAG_REQ_V2_LEN);
    assert_eq!(u16::from_ne_bytes([destroy[4], destroy[5]]), SOCK_DESTROY);
    let destroy_mask = u32::from_ne_bytes([destroy[20], destroy[21], destroy[22], destroy[23]]);
    assert_eq!(destroy_mask, KILLABLE_TCP_STATES_MASK);

    // Multi-message batch parser decodes InetDiag + NLMSG_DONE + NLMSG_ERROR with nlmsg_seq.
    let mut batch = encode_diag_nlmsg(&ext);
    // Append NLMSG_ERROR(0) ACK with seq=8.
    batch.extend_from_slice(&((NLMSG_HDRLEN + 4) as u32).to_ne_bytes());
    batch.extend_from_slice(&NLMSG_ERROR.to_ne_bytes());
    batch.extend_from_slice(&0u16.to_ne_bytes());
    batch.extend_from_slice(&8u32.to_ne_bytes());
    batch.extend_from_slice(&0u32.to_ne_bytes());
    batch.extend_from_slice(&0i32.to_ne_bytes());
    // Append NLMSG_DONE with seq=9.
    batch.extend_from_slice(&(NLMSG_HDRLEN as u32).to_ne_bytes());
    batch.extend_from_slice(&NLMSG_DONE.to_ne_bytes());
    batch.extend_from_slice(&0u16.to_ne_bytes());
    batch.extend_from_slice(&9u32.to_ne_bytes());
    batch.extend_from_slice(&0u32.to_ne_bytes());

    let parsed_frames = parse_netlink_frames(&batch).unwrap();
    assert_eq!(
        parsed_frames,
        vec![
            ParsedNetlinkFrame {
                seq: 1,
                body: ParsedNetlinkMsg::InetDiag(ext),
            },
            ParsedNetlinkFrame {
                seq: 8,
                body: ParsedNetlinkMsg::Error(0),
            },
            ParsedNetlinkFrame {
                seq: 9,
                body: ParsedNetlinkMsg::Done,
            },
        ]
    );
    let parsed = parse_netlink_messages(&batch).unwrap();
    assert_eq!(parsed.len(), 3);

    // Verify fallback `ss -K` preserves IPv4, IPv6, and IPv4-mapped loopback.
    let ss_args = ss_kill_fallback_args();
    assert!(ss_args.contains(&"-K"));
    assert!(ss_args.contains(&"127.0.0.0/8"));
    assert!(ss_args.contains(&"[::1]"));
    assert!(ss_args.contains(&"[::ffff:127.0.0.0/104]"));
}

// ---------------------------------------------------------------------------
// 6. State Machine tests
// ---------------------------------------------------------------------------

#[test]
fn state_machine_enforces_strict_freeze_and_reseed_transitions() {
    let mut sm = AgentStateMachine::new();
    assert_eq!(sm.state(), AgentState::Ready);
    assert_eq!(sm.epoch_generation(), 0);
    assert!(sm.ensure_exec_allowed().is_ok());

    // Cannot reseed before freezing.
    assert!(matches!(
        sm.begin_reseed(),
        Err(StateError::InvalidTransition {
            from: AgentState::Ready,
            ..
        })
    ));

    // Ready -> Freezing -> Frozen { disk_clean: true }.
    sm.begin_freeze().unwrap();
    assert_eq!(sm.state(), AgentState::Freezing);
    sm.complete_freeze(true).unwrap();
    assert_eq!(sm.state(), AgentState::Frozen { disk_clean: true });
    assert_eq!(sm.ensure_exec_allowed(), Err(StateError::AgentFrozen));

    // Double freeze rejected.
    assert!(matches!(
        sm.begin_freeze(),
        Err(StateError::InvalidTransition { .. })
    ));

    // Frozen -> Reseeding -> Ready (epoch_generation increments).
    assert!(sm.begin_reseed().unwrap());
    assert_eq!(sm.state(), AgentState::Reseeding);
    let generation = sm.complete_reseed().unwrap();
    assert_eq!(generation, 1);
    assert_eq!(sm.state(), AgentState::Ready);

    // Unrecoverable rollback transitions to Faulted and blocks all operations.
    sm.begin_freeze().unwrap();
    sm.abort_freeze(false);
    assert_eq!(sm.state(), AgentState::Faulted);
    assert_eq!(sm.ensure_exec_allowed(), Err(StateError::AgentFaulted));
    assert_eq!(sm.begin_freeze(), Err(StateError::AgentFaulted));
    assert_eq!(sm.begin_reseed(), Err(StateError::AgentFaulted));
}

// ---------------------------------------------------------------------------
// 7. End-to-End AgentServer In-Memory Transport Tests
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MockState {
    calls: Vec<String>,
    last_entropy: Option<[u8; RESEED_ENTROPY_LEN]>,
    last_clock: Option<(i64, u32)>,
    fail_pre_freeze: bool,
    fail_syncfs: bool,
    fail_kill_tcp: bool,
    fail_unfreeze: bool,
    exec_stdout: Vec<u8>,
    exec_stderr: Vec<u8>,
    socket_report: SocketKillReport,
}

#[derive(Clone, Default)]
struct MockBackend {
    inner: Arc<Mutex<MockState>>,
}

impl MockBackend {
    fn new() -> Self {
        let st = MockState {
            socket_report: SocketKillReport {
                killed_tcp_sockets: 3,
                preserved_loopback_sockets: 2,
            },
            ..Default::default()
        };
        Self {
            inner: Arc::new(Mutex::new(st)),
        }
    }
}

impl GuestBackend for MockBackend {
    fn run_exec(
        &self,
        spec: ExecSpec,
        on_chunk: &mut dyn FnMut(OutputStream, &[u8]) -> io::Result<()>,
    ) -> Result<ExecOutcome, BackendError> {
        let (raw_out, raw_err) = {
            let mut st = self.inner.lock().unwrap();
            st.calls.push(format!("exec:{}", spec.exec_id));
            (st.exec_stdout.clone(), st.exec_stderr.clone())
        };

        let stdout = drain_stream(
            Cursor::new(raw_out),
            spec.max_output_bytes,
            spec.stream_chunk_bytes,
            |c| on_chunk(OutputStream::Stdout, c),
        )
        .map_err(|e| BackendError::new(ErrorCode::ExecFailed, e.to_string()))?;

        let stderr = drain_stream(
            Cursor::new(raw_err),
            spec.max_output_bytes,
            spec.stream_chunk_bytes,
            |c| on_chunk(OutputStream::Stderr, c),
        )
        .map_err(|e| BackendError::new(ErrorCode::ExecFailed, e.to_string()))?;

        Ok(ExecOutcome {
            exit_code: Some(0),
            signal: None,
            timed_out: false,
            cgroup_killed: false,
            duration: Duration::from_millis(5),
            stdout,
            stderr,
        })
    }

    fn run_pre_freeze_hook(&self, argv: &[String], timeout: Duration) -> Result<(), BackendError> {
        let mut st = self.inner.lock().unwrap();
        st.calls.push(format!(
            "pre_freeze:{}({}ms)",
            argv.join(" "),
            timeout.as_millis()
        ));
        if st.fail_pre_freeze {
            return Err(BackendError::new(
                ErrorCode::PreFreezeHookFailed,
                "hook exited 1",
            ));
        }
        Ok(())
    }

    fn freeze_workload(&self, _timeout: Duration) -> Result<Duration, BackendError> {
        self.inner.lock().unwrap().calls.push("freeze".to_owned());
        Ok(Duration::from_millis(3))
    }

    fn unfreeze_workload(&self, _timeout: Duration) -> Result<Duration, BackendError> {
        let mut st = self.inner.lock().unwrap();
        st.calls.push("unfreeze".to_owned());
        if st.fail_unfreeze {
            return Err(BackendError::new(
                ErrorCode::UnfreezeFailed,
                "cgroup unfreeze failed",
            ));
        }
        Ok(Duration::from_millis(2))
    }

    fn sync_filesystems(&self, paths: &[String]) -> Result<SyncOutcome, BackendError> {
        let mut st = self.inner.lock().unwrap();
        st.calls.push(format!("syncfs:{}", paths.join(",")));
        if st.fail_syncfs {
            return Err(BackendError::new(ErrorCode::SyncFailed, "EIO during syncfs"));
        }
        Ok(SyncOutcome {
            synced_paths: paths.len(),
            elapsed: Duration::from_millis(4),
        })
    }

    fn reseed_entropy(&self, entropy: &[u8; RESEED_ENTROPY_LEN]) -> Result<(), BackendError> {
        let mut st = self.inner.lock().unwrap();
        st.calls.push("reseed_entropy".to_owned());
        st.last_entropy = Some(*entropy);
        Ok(())
    }

    fn sync_clock_realtime(&self, secs: i64, nanos: u32) -> Result<(), BackendError> {
        let mut st = self.inner.lock().unwrap();
        st.calls.push("sync_clock".to_owned());
        st.last_clock = Some((secs, nanos));
        Ok(())
    }

    fn kill_external_tcp(&self) -> Result<SocketKillReport, BackendError> {
        let mut st = self.inner.lock().unwrap();
        st.calls.push("kill_external_tcp".to_owned());
        if st.fail_kill_tcp {
            return Err(BackendError::new(
                ErrorCode::SocketKillFailed,
                "SOCK_DESTROY EOPNOTSUPP",
            ));
        }
        Ok(st.socket_report)
    }
}

fn run_batch(
    server: &mut AgentServer<MockBackend>,
    requests: &[RequestEnvelope],
) -> Vec<ResponseEnvelope> {
    let codec = FrameCodec::default();
    let mut req_wire = Vec::new();
    for req in requests {
        codec.write_frame(&mut req_wire, req).unwrap();
    }
    let mut reader = Cursor::new(req_wire);
    let mut resp_wire = Vec::new();
    let stats = server.serve_connection(&mut reader, &mut resp_wire).unwrap();
    assert_eq!(stats.requests_handled, requests.len() as u64);

    let mut resp_reader = Cursor::new(resp_wire);
    let mut out = Vec::new();
    while let Some(resp) = codec
        .read_frame::<_, ResponseEnvelope>(&mut resp_reader)
        .unwrap()
    {
        out.push(resp);
    }
    out
}

#[test]
fn full_hot_fork_lifecycle_across_vsock_transport_reset() {
    let backend = MockBackend::new();
    {
        let mut st = backend.inner.lock().unwrap();
        st.exec_stdout = b"HEADER_0123456789_MIDDLE_BYTES_9876543210_FOOTER".to_vec();
        st.exec_stderr = b"warn: minor".to_vec();
    }
    let mut server = AgentServer::new(backend.clone());

    // --- Connection 1 (Parent VM before snapshot) ---
    let conn1_responses = run_batch(
        &mut server,
        &[
            RequestEnvelope::new(1, GuestRequest::Ping { nonce: 1001 }),
            RequestEnvelope::new(
                2,
                GuestRequest::Exec {
                    exec_id: "build-step-1".into(),
                    argv: vec!["/bin/sh".into(), "-c".into(), "echo hi".into()],
                    env: BTreeMap::new(),
                    cwd: None,
                    timeout_ms: Some(5000),
                    max_output_bytes: Some(16),
                    stream_chunk_bytes: Some(10),
                    stream: true,
                },
            ),
            RequestEnvelope::new(
                3,
                GuestRequest::FreezeAndSync {
                    pre_freeze_hook: Some(vec!["/usr/bin/sync-db".into()]),
                    freeze_timeout_ms: Some(2000),
                    sync_paths: vec![],
                    perform_syncfs: true,
                },
            ),
            // Exec while frozen MUST be rejected.
            RequestEnvelope::new(
                4,
                GuestRequest::Exec {
                    exec_id: "should-fail".into(),
                    argv: vec!["/bin/true".into()],
                    env: BTreeMap::new(),
                    cwd: None,
                    timeout_ms: None,
                    max_output_bytes: None,
                    stream_chunk_bytes: None,
                    stream: false,
                },
            ),
        ],
    );

    // 1. Ping -> Pong (Ready, gen 0).
    assert!(matches!(
        conn1_responses[0].payload,
        GuestResponse::Pong {
            nonce: 1001,
            state: AgentState::Ready,
            epoch_generation: 0,
            ..
        }
    ));

    // 2. Exec emitted streamed OutputChunk frames + terminal ExecResult with bounded head/tail.
    let mut stdout_chunks = Vec::new();
    let mut stderr_chunks = Vec::new();
    let mut exec_result = None;
    for env in &conn1_responses {
        if env.req_id == 2 {
            match &env.payload {
                GuestResponse::OutputChunk {
                    stream: OutputStream::Stdout,
                    data,
                    ..
                } => stdout_chunks.extend_from_slice(data.as_slice()),
                GuestResponse::OutputChunk {
                    stream: OutputStream::Stderr,
                    data,
                    ..
                } => stderr_chunks.extend_from_slice(data.as_slice()),
                GuestResponse::ExecResult { stdout, stderr, .. } => {
                    exec_result = Some((stdout.clone(), stderr.clone()));
                }
                other => panic!("unexpected req 2 response: {other:?}"),
            }
        }
    }
    assert_eq!(
        stdout_chunks,
        b"HEADER_0123456789_MIDDLE_BYTES_9876543210_FOOTER"
    );
    assert_eq!(stderr_chunks, b"warn: minor");
    let (bounded_out, bounded_err) = exec_result.expect("missing ExecResult");
    assert!(bounded_out.truncated);
    assert_eq!(bounded_out.head.as_slice(), b"HEADER_0");
    assert_eq!(bounded_out.tail.as_slice(), b"0_FOOTER");
    assert_eq!(
        bounded_out.head.len() as u64 + bounded_out.omitted_bytes + bounded_out.tail.len() as u64,
        bounded_out.total_bytes
    );
    assert!(!bounded_err.truncated);
    assert_eq!(bounded_err.head.as_slice(), b"warn: minor");

    // 3. FreezeAndSync -> FrozenAck { disk_clean: true }.
    let freeze_resp = conn1_responses.iter().find(|r| r.req_id == 3).unwrap();
    assert!(matches!(
        freeze_resp.payload,
        GuestResponse::FrozenAck {
            disk_clean: true,
            synced_paths: 1,
            ..
        }
    ));

    // 4. Exec while frozen -> Error { code: AgentFrozen }.
    let blocked_resp = conn1_responses.iter().find(|r| r.req_id == 4).unwrap();
    assert!(matches!(
        blocked_resp.payload,
        GuestResponse::Error {
            code: ErrorCode::AgentFrozen,
            ..
        }
    ));

    // --- Simulated VIRTIO_VSOCK_EVENT_TRANSPORT_RESET (new connection on restored clone) ---
    let entropy = [0x5Au8; RESEED_ENTROPY_LEN];
    let conn2_responses = run_batch(
        &mut server,
        &[
            RequestEnvelope::new(10, GuestRequest::Ping { nonce: 2002 }),
            // Bad entropy length rejected cleanly while remaining Frozen.
            RequestEnvelope::new(
                11,
                GuestRequest::PostForkReseed {
                    entropy: BytesPayload::from(vec![1u8; 32]),
                    wall_time_secs: 1_750_000_000,
                    wall_time_nanos: 123,
                    kill_external_tcp: true,
                    unfreeze_timeout_ms: None,
                    world_id: None,
                },
            ),
            // Valid PostForkReseed transitions Frozen -> Ready and increments epoch_generation.
            RequestEnvelope::new(
                12,
                GuestRequest::PostForkReseed {
                    entropy: BytesPayload::from(entropy.to_vec()),
                    wall_time_secs: 1_750_000_000,
                    wall_time_nanos: 999_999_999,
                    kill_external_tcp: true,
                    unfreeze_timeout_ms: Some(2000),
                    world_id: Some("w-clone-1".into()),
                },
            ),
            RequestEnvelope::new(13, GuestRequest::Ping { nonce: 3003 }),
        ],
    );

    assert!(matches!(
        conn2_responses[0].payload,
        GuestResponse::Pong {
            nonce: 2002,
            state: AgentState::Frozen { disk_clean: true },
            epoch_generation: 0,
            ..
        }
    ));
    assert!(matches!(
        conn2_responses[1].payload,
        GuestResponse::Error {
            code: ErrorCode::InvalidRequest,
            ..
        }
    ));
    assert_eq!(
        conn2_responses[2].payload,
        GuestResponse::ReseedAck {
            entropy_injected_bytes: 64,
            crng_reseeded: true,
            clock_synced: true,
            killed_tcp_sockets: 3,
            preserved_loopback_sockets: 2,
            unfrozen: true,
            epoch_generation: 1,
        }
    );
    assert!(matches!(
        conn2_responses[3].payload,
        GuestResponse::Pong {
            nonce: 3003,
            state: AgentState::Ready,
            epoch_generation: 1,
            ..
        }
    ));

    // Verify exact backend execution order.
    let st = backend.inner.lock().unwrap();
    assert_eq!(st.last_entropy, Some(entropy));
    assert_eq!(st.last_clock, Some((1_750_000_000, 999_999_999)));
    assert_eq!(
        st.calls,
        vec![
            "exec:build-step-1",
            "pre_freeze:/usr/bin/sync-db(2000ms)",
            "freeze",
            "syncfs:/",
            "reseed_entropy",
            "sync_clock",
            "kill_external_tcp",
            "unfreeze",
        ]
    );
}

#[test]
fn failure_rollbacks_preserve_safety_invariants() {
    // 1. syncfs failure must roll back freeze to Ready and NEVER return disk_clean=true.
    let backend = MockBackend::new();
    backend.inner.lock().unwrap().fail_syncfs = true;
    let mut server = AgentServer::new(backend.clone());

    let resps = run_batch(
        &mut server,
        &[RequestEnvelope::new(
            1,
            GuestRequest::FreezeAndSync {
                pre_freeze_hook: None,
                freeze_timeout_ms: None,
                sync_paths: vec!["/".into()],
                perform_syncfs: true,
            },
        )],
    );
    assert!(matches!(
        resps[0].payload,
        GuestResponse::Error {
            code: ErrorCode::SyncFailed,
            ..
        }
    ));
    assert_eq!(server.state_machine().state(), AgentState::Ready);

    // 2. perform_syncfs=false MUST report disk_clean=false (A6b invariant).
    backend.inner.lock().unwrap().fail_syncfs = false;
    let resps = run_batch(
        &mut server,
        &[RequestEnvelope::new(
            2,
            GuestRequest::FreezeAndSync {
                pre_freeze_hook: None,
                freeze_timeout_ms: None,
                sync_paths: vec![],
                perform_syncfs: false,
            },
        )],
    );
    assert!(matches!(
        resps[0].payload,
        GuestResponse::FrozenAck {
            disk_clean: false,
            synced_paths: 0,
            ..
        }
    ));

    // 3. Socket kill failure during PostForkReseed MUST keep workload Frozen (never unfreeze dirty clone).
    backend.inner.lock().unwrap().fail_kill_tcp = true;
    let resps = run_batch(
        &mut server,
        &[RequestEnvelope::new(
            3,
            GuestRequest::PostForkReseed {
                entropy: BytesPayload::from(vec![0x11; 64]),
                wall_time_secs: 1_750_000_000,
                wall_time_nanos: 0,
                kill_external_tcp: true,
                unfreeze_timeout_ms: None,
                world_id: None,
            },
        )],
    );
    assert!(matches!(
        resps[0].payload,
        GuestResponse::Error {
            code: ErrorCode::SocketKillFailed,
            ..
        }
    ));
    assert_eq!(
        server.state_machine().state(),
        AgentState::Frozen { disk_clean: false }
    );

    // 4. Unsupported protocol version and bad exec_id / argv rejected cleanly.
    let mut bad_ver = RequestEnvelope::new(4, GuestRequest::Ping { nonce: 1 });
    bad_ver.protocol_version = PROTOCOL_VERSION + 99;
    let resps = run_batch(&mut server, &[bad_ver]);
    assert!(matches!(
        resps[0].payload,
        GuestResponse::Error {
            code: ErrorCode::UnsupportedProtocolVersion,
            ..
        }
    ));

    // 5. Invalid wall_time_nanos rejected before mutating Frozen state.
    let resps = run_batch(
        &mut server,
        &[RequestEnvelope::new(
            5,
            GuestRequest::PostForkReseed {
                entropy: BytesPayload::from(vec![0x22; 64]),
                wall_time_secs: 1_750_000_000,
                wall_time_nanos: 1_000_000_000,
                kill_external_tcp: true,
                unfreeze_timeout_ms: None,
                world_id: None,
            },
        )],
    );
    assert!(matches!(
        resps[0].payload,
        GuestResponse::Error {
            code: ErrorCode::InvalidRequest,
            ..
        }
    ));
    assert_eq!(
        server.state_machine().state(),
        AgentState::Frozen { disk_clean: false }
    );

    // 6. Unfreeze failure during PostForkReseed transitions to terminal Faulted state.
    {
        let mut st = backend.inner.lock().unwrap();
        st.fail_kill_tcp = false;
        st.fail_unfreeze = true;
    }
    let resps = run_batch(
        &mut server,
        &[RequestEnvelope::new(
            6,
            GuestRequest::PostForkReseed {
                entropy: BytesPayload::from(vec![0x33; 64]),
                wall_time_secs: 1_750_000_000,
                wall_time_nanos: 500,
                kill_external_tcp: true,
                unfreeze_timeout_ms: None,
                world_id: None,
            },
        )],
    );
    assert!(matches!(
        resps[0].payload,
        GuestResponse::Error {
            code: ErrorCode::UnfreezeFailed,
            ..
        }
    ));
    assert_eq!(server.state_machine().state(), AgentState::Faulted);
}

#[test]
fn pre_freeze_hook_failure_and_exec_validation() {
    let backend = MockBackend::new();
    backend.inner.lock().unwrap().fail_pre_freeze = true;
    let mut server = AgentServer::new(backend.clone());

    let resps = run_batch(
        &mut server,
        &[
            // Invalid exec_id rejected before reaching backend.
            RequestEnvelope::new(
                1,
                GuestRequest::Exec {
                    exec_id: "../escape".into(),
                    argv: vec!["/bin/true".into()],
                    env: BTreeMap::new(),
                    cwd: None,
                    timeout_ms: None,
                    max_output_bytes: None,
                    stream_chunk_bytes: None,
                    stream: false,
                },
            ),
            // Empty argv rejected before reaching backend.
            RequestEnvelope::new(
                2,
                GuestRequest::Exec {
                    exec_id: "valid-id".into(),
                    argv: vec![],
                    env: BTreeMap::new(),
                    cwd: None,
                    timeout_ms: None,
                    max_output_bytes: None,
                    stream_chunk_bytes: None,
                    stream: false,
                },
            ),
            // Failing pre_freeze_hook aborts before freezing and leaves agent Ready.
            RequestEnvelope::new(
                3,
                GuestRequest::FreezeAndSync {
                    pre_freeze_hook: Some(vec!["/bin/false".into()]),
                    freeze_timeout_ms: None,
                    sync_paths: vec![],
                    perform_syncfs: true,
                },
            ),
        ],
    );

    assert!(matches!(
        resps[0].payload,
        GuestResponse::Error {
            code: ErrorCode::InvalidRequest,
            ..
        }
    ));
    assert!(matches!(
        resps[1].payload,
        GuestResponse::Error {
            code: ErrorCode::InvalidRequest,
            ..
        }
    ));
    assert!(matches!(
        resps[2].payload,
        GuestResponse::Error {
            code: ErrorCode::PreFreezeHookFailed,
            ..
        }
    ));
    assert_eq!(server.state_machine().state(), AgentState::Ready);
    assert_eq!(
        backend.inner.lock().unwrap().calls,
        vec!["pre_freeze:/bin/false(5000ms)"]
    );
}

#[test]
fn exec_enforces_frame_safe_output_and_chunk_bounds() {
    let max_frame = 4096;
    let out_cap = max_allowed_output_bytes(max_frame);
    let chunk_cap = max_allowed_stream_chunk_bytes(max_frame);

    let backend = MockBackend::new();
    {
        let mut st = backend.inner.lock().unwrap();
        // Produce MORE than out_cap on both stdout and stderr so both hit the exact cap.
        st.exec_stdout = vec![0xAA; out_cap + 500];
        st.exec_stderr = vec![0xBB; out_cap + 500];
    }

    let codec = FrameCodec::new(max_frame);
    let mut server = AgentServer::with_codec(backend, codec);

    let requests = [
        // max_output_bytes exceeding frame-safe limit -> InvalidRequest.
        RequestEnvelope::new(
            1,
            GuestRequest::Exec {
                exec_id: "too-big-out".into(),
                argv: vec!["/bin/true".into()],
                env: BTreeMap::new(),
                cwd: None,
                timeout_ms: None,
                max_output_bytes: Some(out_cap + 1),
                stream_chunk_bytes: None,
                stream: false,
            },
        ),
        // stream_chunk_bytes == 0 -> InvalidRequest.
        RequestEnvelope::new(
            2,
            GuestRequest::Exec {
                exec_id: "zero-chunk".into(),
                argv: vec!["/bin/true".into()],
                env: BTreeMap::new(),
                cwd: None,
                timeout_ms: None,
                max_output_bytes: None,
                stream_chunk_bytes: Some(0),
                stream: true,
            },
        ),
        // stream_chunk_bytes exceeding frame-safe limit -> InvalidRequest.
        RequestEnvelope::new(
            3,
            GuestRequest::Exec {
                exec_id: "too-big-chunk".into(),
                argv: vec!["/bin/true".into()],
                env: BTreeMap::new(),
                cwd: None,
                timeout_ms: None,
                max_output_bytes: None,
                stream_chunk_bytes: Some(chunk_cap + 1),
                stream: true,
            },
        ),
        // Exact boundary (both stdout and stderr capped at out_cap, streaming at chunk_cap)
        // MUST serialize cleanly within `max_frame` without FrameTooLarge!
        RequestEnvelope::new(
            4,
            GuestRequest::Exec {
                exec_id: "exact-cap".into(),
                argv: vec!["/bin/true".into()],
                env: BTreeMap::new(),
                cwd: None,
                timeout_ms: None,
                max_output_bytes: Some(out_cap),
                stream_chunk_bytes: Some(chunk_cap),
                stream: true,
            },
        ),
    ];

    let mut req_wire = Vec::new();
    for r in &requests {
        codec.write_frame(&mut req_wire, r).unwrap();
    }
    let mut reader = Cursor::new(req_wire);
    let mut resp_wire = Vec::new();
    server.serve_connection(&mut reader, &mut resp_wire).unwrap();

    let mut resp_reader = Cursor::new(resp_wire);
    let mut responses = Vec::new();
    while let Some(resp) = codec
        .read_frame::<_, ResponseEnvelope>(&mut resp_reader)
        .unwrap()
    {
        responses.push(resp);
    }

    for id in [1u64, 2, 3] {
        let r = responses.iter().find(|e| e.req_id == id).unwrap();
        assert!(matches!(
            r.payload,
            GuestResponse::Error {
                code: ErrorCode::InvalidRequest,
                ..
            }
        ));
    }

    let exec4 = responses
        .iter()
        .find(|e| e.req_id == 4 && matches!(e.payload, GuestResponse::ExecResult { .. }))
        .expect("boundary ExecResult should fit inside max_frame");
    if let GuestResponse::ExecResult {
        stdout,
        stderr,
        cgroup_killed,
        ..
    } = &exec4.payload
    {
        assert!(!cgroup_killed, "clean exit must report cgroup_killed=false");
        assert!(stdout.truncated);
        assert!(stderr.truncated);
        assert_eq!(stdout.head.len() + stdout.tail.len(), out_cap);
        assert_eq!(stderr.head.len() + stderr.tail.len(), out_cap);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn linux_bring_up_loopback_ensures_lo_is_up() {
    aos_guest::linux_sys::bring_up_loopback().expect("bring_up_loopback should succeed");
    let flags_hex = fs::read_to_string("/sys/class/net/lo/flags")
        .expect("read /sys/class/net/lo/flags");
    let flags = u32::from_str_radix(flags_hex.trim().trim_start_matches("0x"), 16)
        .expect("parse lo flags hex");
    assert_ne!(flags & 0x1, 0, "lo IFF_UP bit must be set (flags=0x{flags:x})");
}

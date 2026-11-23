//! Pure-Rust Linux `NETLINK_SOCK_DIAG` / `SOCK_DESTROY` wire protocol and loopback filter.
//!
//! Enables killing stale external TCP connections after Firecracker snapshot restore
//! while strictly preserving loopback (`127.0.0.0/8`, `::1`, `::ffff:127.0.0.0/104`)
//! and `TCP_LISTEN` sockets — with zero `unsafe` code and zero runtime dependency on
//! `iproute2` (while also providing `ss -K` fallback command arguments).

#![forbid(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use thiserror::Error;

// Linux UAPI constants (`linux/netlink.h`, `linux/sock_diag.h`, `linux/inet_diag.h`).
pub const NETLINK_SOCK_DIAG: i32 = 4;

pub const NLMSG_NOOP: u16 = 1;
pub const NLMSG_ERROR: u16 = 2;
pub const NLMSG_DONE: u16 = 3;
pub const SOCK_DIAG_BY_FAMILY: u16 = 20;
pub const SOCK_DESTROY: u16 = 21;

pub const NLM_F_REQUEST: u16 = 0x0001;
pub const NLM_F_ACK: u16 = 0x0004;
pub const NLM_F_ROOT: u16 = 0x0100;
pub const NLM_F_MATCH: u16 = 0x0200;
pub const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;

pub const AF_INET: u8 = 2;
pub const AF_INET6: u8 = 10;
pub const IPPROTO_TCP: u8 = 6;

// Linux TCP state numbers (`include/net/tcp_states.h`).
pub const TCP_ESTABLISHED: u8 = 1;
pub const TCP_SYN_SENT: u8 = 2;
pub const TCP_SYN_RECV: u8 = 3;
pub const TCP_FIN_WAIT1: u8 = 4;
pub const TCP_FIN_WAIT2: u8 = 5;
pub const TCP_TIME_WAIT: u8 = 6;
pub const TCP_CLOSE: u8 = 7;
pub const TCP_CLOSE_WAIT: u8 = 8;
pub const TCP_LAST_ACK: u8 = 9;
pub const TCP_LISTEN: u8 = 10;
pub const TCP_CLOSING: u8 = 11;

/// Bitmask of active/half-open TCP states eligible for post-fork external socket destruction.
///
/// Explicitly excludes `TCP_LISTEN` (`1 << 10`), `TCP_SYN_RECV` (`1 << 3`, kernel
/// request_sock where `inet_diag_destroy` returns `EOPNOTSUPP`), `TCP_TIME_WAIT`,
/// and `TCP_CLOSE` so pre-warmed local servers continue accepting connections after fork.
pub const KILLABLE_TCP_STATES_MASK: u32 = (1 << TCP_ESTABLISHED)
    | (1 << TCP_SYN_SENT)
    | (1 << TCP_FIN_WAIT1)
    | (1 << TCP_FIN_WAIT2)
    | (1 << TCP_CLOSE_WAIT)
    | (1 << TCP_LAST_ACK)
    | (1 << TCP_CLOSING);

pub const NLMSG_HDRLEN: usize = 16;
pub const INET_DIAG_SOCKID_LEN: usize = 48;
pub const INET_DIAG_REQ_V2_LEN: usize = 56;
pub const INET_DIAG_MSG_LEN: usize = 72;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NetlinkParseError {
    #[error("truncated netlink header: {len} bytes remaining")]
    TruncatedHeader { len: usize },
    #[error("invalid netlink message length {nlmsg_len} (must be >= {NLMSG_HDRLEN} and <= {available})")]
    InvalidLength { nlmsg_len: usize, available: usize },
    #[error("truncated inet_diag_msg payload: expected >= {INET_DIAG_MSG_LEN}, got {got}")]
    TruncatedInetDiagMsg { got: usize },
    #[error("truncated nlmsgerr payload: expected >= 4, got {got}")]
    TruncatedErrorPayload { got: usize },
}

/// Rust representation of Linux `struct inet_diag_sockid` (48 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InetDiagSockId {
    pub sport_be: [u8; 2],
    pub dport_be: [u8; 2],
    pub src_raw: [u8; 16],
    pub dst_raw: [u8; 16],
    pub iface: u32,
    pub cookie: [u32; 2],
}

impl InetDiagSockId {
    pub fn zeroed() -> Self {
        Self {
            sport_be: [0; 2],
            dport_be: [0; 2],
            src_raw: [0; 16],
            dst_raw: [0; 16],
            iface: 0,
            cookie: [0; 2],
        }
    }

    pub fn sport(&self) -> u16 {
        u16::from_be_bytes(self.sport_be)
    }

    pub fn dport(&self) -> u16 {
        u16::from_be_bytes(self.dport_be)
    }

    pub fn src_ip(&self, family: u8) -> Option<IpAddr> {
        decode_sockid_ip(family, &self.src_raw)
    }

    pub fn dst_ip(&self, family: u8) -> Option<IpAddr> {
        decode_sockid_ip(family, &self.dst_raw)
    }

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.sport_be);
        out.extend_from_slice(&self.dport_be);
        out.extend_from_slice(&self.src_raw);
        out.extend_from_slice(&self.dst_raw);
        out.extend_from_slice(&self.iface.to_ne_bytes());
        out.extend_from_slice(&self.cookie[0].to_ne_bytes());
        out.extend_from_slice(&self.cookie[1].to_ne_bytes());
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < INET_DIAG_SOCKID_LEN {
            return None;
        }
        let sport_be = [bytes[0], bytes[1]];
        let dport_be = [bytes[2], bytes[3]];
        let mut src_raw = [0u8; 16];
        src_raw.copy_from_slice(&bytes[4..20]);
        let mut dst_raw = [0u8; 16];
        dst_raw.copy_from_slice(&bytes[20..36]);
        let iface = u32::from_ne_bytes([bytes[36], bytes[37], bytes[38], bytes[39]]);
        let c0 = u32::from_ne_bytes([bytes[40], bytes[41], bytes[42], bytes[43]]);
        let c1 = u32::from_ne_bytes([bytes[44], bytes[45], bytes[46], bytes[47]]);
        Some(Self {
            sport_be,
            dport_be,
            src_raw,
            dst_raw,
            iface,
            cookie: [c0, c1],
        })
    }
}

fn decode_sockid_ip(family: u8, raw: &[u8; 16]) -> Option<IpAddr> {
    match family {
        AF_INET => Some(IpAddr::V4(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]))),
        AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from(*raw))),
        _ => None,
    }
}

/// Decoded `struct inet_diag_msg` header (72 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InetDiagMsg {
    pub family: u8,
    pub state: u8,
    pub timer: u8,
    pub retrans: u8,
    pub id: InetDiagSockId,
    pub expires: u32,
    pub rqueue: u32,
    pub wqueue: u32,
    pub uid: u32,
    pub inode: u32,
}

impl InetDiagMsg {
    pub fn decode(bytes: &[u8]) -> Result<Self, NetlinkParseError> {
        if bytes.len() < INET_DIAG_MSG_LEN {
            return Err(NetlinkParseError::TruncatedInetDiagMsg { got: bytes.len() });
        }
        let id = InetDiagSockId::decode(&bytes[4..52])
            .ok_or(NetlinkParseError::TruncatedInetDiagMsg { got: bytes.len() })?;
        Ok(Self {
            family: bytes[0],
            state: bytes[1],
            timer: bytes[2],
            retrans: bytes[3],
            id,
            expires: u32::from_ne_bytes([bytes[52], bytes[53], bytes[54], bytes[55]]),
            rqueue: u32::from_ne_bytes([bytes[56], bytes[57], bytes[58], bytes[59]]),
            wqueue: u32::from_ne_bytes([bytes[60], bytes[61], bytes[62], bytes[63]]),
            uid: u32::from_ne_bytes([bytes[64], bytes[65], bytes[66], bytes[67]]),
            inode: u32::from_ne_bytes([bytes[68], bytes[69], bytes[70], bytes[71]]),
        })
    }
}

/// Classification of a TCP socket during post-fork external connection cleanup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketAction {
    /// External (non-loopback) active TCP socket: MUST be destroyed via `SOCK_DESTROY`.
    Kill,
    /// Pure loopback TCP socket (`127.0.0.0/8`, `::1`, or `::ffff:127.0.0.0/104`): MUST be preserved.
    PreserveLoopback,
    /// Non-killable state (e.g., `TCP_LISTEN`, `TCP_TIME_WAIT`, `TCP_CLOSE`): leave untouched.
    SkipState,
}

/// Returns `true` for IPv4 `127.0.0.0/8`, IPv6 `::1`, and IPv4-mapped IPv6 `::ffff:127.0.0.0/104`.
pub fn is_loopback_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
    }
}

/// Decide whether a discovered TCP socket should be destroyed, preserved as loopback, or skipped.
pub fn classify_tcp_socket(msg: &InetDiagMsg) -> SocketAction {
    if msg.state >= 32 || (KILLABLE_TCP_STATES_MASK & (1u32 << msg.state)) == 0 {
        return SocketAction::SkipState;
    }
    let Some(src) = msg.id.src_ip(msg.family) else {
        return SocketAction::SkipState;
    };
    let Some(dst) = msg.id.dst_ip(msg.family) else {
        return SocketAction::SkipState;
    };

    if is_loopback_ip(src) && is_loopback_ip(dst) {
        SocketAction::PreserveLoopback
    } else {
        SocketAction::Kill
    }
}

/// Build a `NETLINK_SOCK_DIAG` dump request for all killable TCP sockets in `family` (`AF_INET` or `AF_INET6`).
pub fn build_tcp_dump_request(family: u8, seq: u32) -> Vec<u8> {
    let total_len = (NLMSG_HDRLEN + INET_DIAG_REQ_V2_LEN) as u32;
    let mut buf = Vec::with_capacity(total_len as usize);

    // struct nlmsghdr (16 bytes)
    buf.extend_from_slice(&total_len.to_ne_bytes());
    buf.extend_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
    buf.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    buf.extend_from_slice(&seq.to_ne_bytes());
    buf.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_pid = 0 (kernel)

    // struct inet_diag_req_v2 (56 bytes)
    buf.push(family);
    buf.push(IPPROTO_TCP);
    buf.push(0); // idiag_ext
    buf.push(0); // pad
    buf.extend_from_slice(&KILLABLE_TCP_STATES_MASK.to_ne_bytes());
    InetDiagSockId::zeroed().encode_into(&mut buf);

    debug_assert_eq!(buf.len(), total_len as usize);
    buf
}

/// Build a `SOCK_DESTROY` netlink request targeting one specific TCP socket.
pub fn build_tcp_destroy_request(msg: &InetDiagMsg, seq: u32) -> Vec<u8> {
    let total_len = (NLMSG_HDRLEN + INET_DIAG_REQ_V2_LEN) as u32;
    let mut buf = Vec::with_capacity(total_len as usize);

    // struct nlmsghdr (16 bytes)
    buf.extend_from_slice(&total_len.to_ne_bytes());
    buf.extend_from_slice(&SOCK_DESTROY.to_ne_bytes());
    buf.extend_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
    buf.extend_from_slice(&seq.to_ne_bytes());
    buf.extend_from_slice(&0u32.to_ne_bytes());

    // struct inet_diag_req_v2 (56 bytes)
    // Use KILLABLE_TCP_STATES_MASK rather than a single state bit so a socket
    // transitioning between dump and destroy (e.g. SYN_SENT -> ESTABLISHED) is
    // still matched and destroyed cleanly.
    buf.push(msg.family);
    buf.push(IPPROTO_TCP);
    buf.push(0); // idiag_ext
    buf.push(0); // pad
    buf.extend_from_slice(&KILLABLE_TCP_STATES_MASK.to_ne_bytes());
    msg.id.encode_into(&mut buf);

    debug_assert_eq!(buf.len(), total_len as usize);
    buf
}

/// Parsed item from a `NETLINK_SOCK_DIAG` response datagram with its `nlmsg_seq`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedNetlinkFrame {
    pub seq: u32,
    pub body: ParsedNetlinkMsg,
}

/// Parsed payload from a `NETLINK_SOCK_DIAG` response datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedNetlinkMsg {
    InetDiag(InetDiagMsg),
    Done,
    /// Kernel `NLMSG_ERROR` with errno (`0` means ACK success, negative is `-errno`).
    Error(i32),
    Noop,
}

#[inline]
fn nlmsg_align(len: usize) -> usize {
    (len + 3) & !3
}

/// Parse one or more concatenated netlink messages from a `recv()` buffer,
/// preserving each message's `nlmsg_seq` for reply correlation.
pub fn parse_netlink_frames(mut buf: &[u8]) -> Result<Vec<ParsedNetlinkFrame>, NetlinkParseError> {
    let mut out = Vec::new();

    while !buf.is_empty() {
        if buf.len() < NLMSG_HDRLEN {
            return Err(NetlinkParseError::TruncatedHeader { len: buf.len() });
        }
        let nlmsg_len = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        let nlmsg_type = u16::from_ne_bytes([buf[4], buf[5]]);
        let nlmsg_seq = u32::from_ne_bytes([buf[8], buf[9], buf[10], buf[11]]);

        if nlmsg_len < NLMSG_HDRLEN || nlmsg_len > buf.len() {
            return Err(NetlinkParseError::InvalidLength {
                nlmsg_len,
                available: buf.len(),
            });
        }

        let payload = &buf[NLMSG_HDRLEN..nlmsg_len];
        match nlmsg_type {
            NLMSG_NOOP => out.push(ParsedNetlinkFrame {
                seq: nlmsg_seq,
                body: ParsedNetlinkMsg::Noop,
            }),
            NLMSG_DONE => {
                out.push(ParsedNetlinkFrame {
                    seq: nlmsg_seq,
                    body: ParsedNetlinkMsg::Done,
                });
                break;
            }
            NLMSG_ERROR => {
                if payload.len() < 4 {
                    return Err(NetlinkParseError::TruncatedErrorPayload { got: payload.len() });
                }
                let err_code = i32::from_ne_bytes([payload[0], payload[1], payload[2], payload[3]]);
                out.push(ParsedNetlinkFrame {
                    seq: nlmsg_seq,
                    body: ParsedNetlinkMsg::Error(err_code),
                });
            }
            SOCK_DIAG_BY_FAMILY => {
                let diag = InetDiagMsg::decode(payload)?;
                out.push(ParsedNetlinkFrame {
                    seq: nlmsg_seq,
                    body: ParsedNetlinkMsg::InetDiag(diag),
                });
            }
            _ => {}
        }

        let step = nlmsg_align(nlmsg_len);
        if step >= buf.len() {
            break;
        }
        buf = &buf[step..];
    }

    Ok(out)
}

/// Convenience wrapper returning just the message bodies without sequence numbers.
pub fn parse_netlink_messages(buf: &[u8]) -> Result<Vec<ParsedNetlinkMsg>, NetlinkParseError> {
    Ok(parse_netlink_frames(buf)?
        .into_iter()
        .map(|f| f.body)
        .collect())
}

/// Fallback `ss -K` command arguments for external TCP socket termination.
///
/// Uses `ss -K -t` (`iproute2`) with explicit non-loopback destination filters so
/// `127.0.0.0/8`, `[::1]`, and IPv4-mapped `[::ffff:127.0.0.0/104]` connections
/// remain alive, while `state connected` excludes `LISTEN` and `TIME-WAIT` sockets.
pub fn ss_kill_fallback_args() -> &'static [&'static str] {
    &[
        "-K",
        "-t",
        "state",
        "connected",
        "(",
        "not",
        "dst",
        "127.0.0.0/8",
        "and",
        "not",
        "dst",
        "[::1]",
        "and",
        "not",
        "dst",
        "[::ffff:127.0.0.0/104]",
        ")",
    ]
}

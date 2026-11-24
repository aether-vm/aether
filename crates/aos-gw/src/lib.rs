//! Forkloom Zero-Trust Egress Gateway & Audit Engine (`aos-gw`).
//!
//! Everything in this crate is `#![forbid(unsafe_code)]`.
//!
//! | module | purpose |
//! | --- | --- |
//! | [`epoch`] | Thread-safe `(slot_id, world_id, daemon_epoch)` fence registry with monotonic `advance_epoch` and immediate in-flight cancellation |
//! | [`policy`] | Fine-grained capability rules (`host + path_prefix + methods`), host-side credential injection, path smuggling guards, and SSRF IP blocklist |
//! | [`l1_proxy`] | Real async HTTP/1.1 reverse-proxy gateway (TCP / UDS / §7.4 pre-bound `netns` listener fd handoff) |
//! | [`l3_allowlist`] | Strict L3 domain allowlist (`NXDOMAIN` default), multi-tenant shared CDN rejection, and UDP / QUIC-443 denial |
//! | [`reflection`] | Sliding-window multi-pattern anti-reflection scanner across arbitrary chunk boundaries (raw, Base64, URL-encoded, hex) |
//! | [`audit`] | Segmented XChaCha20-Poly1305 encrypted `blake3` hash-chained audit log (`audit/<world>/<seq>.aseg`) and independent `0600` key-slot `crypto_shred` |

#![forbid(unsafe_code)]

pub mod audit;
pub mod epoch;
pub mod error;
pub mod l1_proxy;
pub mod l3_allowlist;
pub mod policy;
pub mod reflection;

pub use audit::{AuditOutcome, AuditRecord, AuditStore, ChainVerificationReport, SegmentReceipt};
pub use epoch::{
    ActiveConnectionGuard, BindingKey, EpochAdvanceReport, EpochFenceRegistry, SlotBinding, SlotId,
};
pub use error::{GwError, Result};
pub use l1_proxy::{GatewayListener, L1ProxyHandle, L1ProxyServer};
pub use l3_allowlist::{
    DnsDecision, DnsDenyReason, DnsRcode, DomainAllowlist, DomainRule, EgressDecision,
    EgressDenyReason, SHARED_MULTI_TENANT_CDN_SUFFIXES, TransportProtocol,
    build_nxdomain_wire_response, is_shared_multi_tenant_cdn,
};
pub use policy::{
    AllowedMethod, CapabilityPolicy, CredentialInjection, CredentialKind, HOP_BY_HOP_HEADERS,
    ProxyLimits, ReflectionAction, RouteMatch, RouteRule, SecretValue, SsrfPolicy,
};
pub use reflection::{
    EncodingVariant, OwnedReflectionStream, REDACTION_MARKER, ReflectionMatch, ReflectionScanner,
    ReflectionStream,
};

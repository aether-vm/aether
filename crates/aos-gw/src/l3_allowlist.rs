//! L3 Allowlist DNS & Egress Policy (ARCHITECTURE_V2 §6).
//!
//! Enforces:
//! - Strict domain allowlist (exact + explicit wildcard policy).
//! - Non-allowlisted domains return `NXDOMAIN`.
//! - Explicit rejection of multi-tenant shared CDN / PaaS blind passthrough domains
//!   (`*.cloudfront.net`, `*.fastly.net`, `*.akamaized.net`, `*.workers.dev`, `*.pages.dev`,
//!   `*.appspot.com`, etc.) at both rule-registration and query-evaluation time.
//! - Explicit UDP denial (including QUIC on UDP/443).

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::error::{GwError, Result};
use crate::policy::SsrfPolicy;

/// Multi-tenant shared CDN and PaaS domain suffixes forbidden from L3 blind passthrough.
///
/// Allowing blind L3 passthrough to a shared CDN allows domain-fronting / cross-tenant
/// egress smuggling because multiple unrelated tenants share the same edge IPs.
/// Access to specific APIs behind a CDN must go through L1 explicit reverse proxy rules.
pub const SHARED_MULTI_TENANT_CDN_SUFFIXES: &[&str] = &[
    "cloudfront.net",
    "fastly.net",
    "fastlylb.net",
    "akamaized.net",
    "akamaihd.net",
    "akamaiedge.net",
    "edgekey.net",
    "edgesuite.net",
    "workers.dev",
    "pages.dev",
    "r2.dev",
    "trycloudflare.com",
    "appspot.com",
    "cloudfunctions.net",
    "run.app",
    "web.app",
    "firebaseapp.com",
    "storage.googleapis.com",
    "azureedge.net",
    "azurewebsites.net",
    "blob.core.windows.net",
    "amazonaws.com",
    "herokuapp.com",
    "vercel.app",
    "netlify.app",
    "fly.dev",
    "ondigitalocean.app",
    "github.io",
    "gitlab.io",
    "ngrok.io",
    "ngrok-free.app",
    "cdn.jsdelivr.net",
    "unpkg.com",
];

/// Two-label public suffixes that must never be wildcarded (`*.co.uk`, etc.).
const PUBLIC_TWO_LABEL_SUFFIXES: &[&str] = &[
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.cn", "net.cn", "org.cn", "com.au", "net.au",
    "co.jp", "ne.jp", "or.jp", "co.kr", "com.br", "com.sg", "com.hk", "com.tw",
];

/// DNS response code returned by L3 policy evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnsRcode {
    /// Query permitted (`NOERROR`, RCODE 0).
    NoError = 0,
    /// Query denied (`NXDOMAIN`, RCODE 3).
    NxDomain = 3,
}

/// Reason an L3 DNS query was denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnsDenyReason {
    /// Query domain failed DNS syntax validation or was a raw IP literal.
    InvalidDomain,
    /// Domain belongs to a forbidden multi-tenant shared CDN / PaaS suffix.
    SharedMultiTenantCdn,
    /// Domain did not match any allowlist rule.
    NotAllowlisted,
}

/// Result of evaluating a domain query against an L3 [`DomainAllowlist`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsDecision {
    /// Domain is explicitly allowlisted (`NOERROR`).
    Allow {
        /// Canonicalized domain name.
        domain: String,
        /// The rule that matched.
        matched_rule: String,
    },
    /// Domain is denied with `NXDOMAIN`.
    Deny {
        /// Always `DnsRcode::NxDomain` per ARCHITECTURE_V2 §6.
        rcode: DnsRcode,
        /// Structured denial reason.
        reason: DnsDenyReason,
    },
}

impl DnsDecision {
    /// Returns `true` if allowed.
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow { .. })
    }

    /// DNS RCODE for this decision.
    #[must_use]
    pub const fn rcode(&self) -> DnsRcode {
        match self {
            Self::Allow { .. } => DnsRcode::NoError,
            Self::Deny { rcode, .. } => *rcode,
        }
    }
}

/// Transport protocol for L3 egress checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransportProtocol {
    /// TCP connection.
    Tcp,
    /// UDP datagram (explicitly forbidden, including QUIC/443).
    Udp,
}

/// Reason an L3 network egress attempt was denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EgressDenyReason {
    /// QUIC over UDP/443 is explicitly prohibited.
    QuicUdp443Forbidden,
    /// All UDP egress is prohibited (`nftables` drops UDP).
    UdpForbidden,
    /// TCP destination port is not in the permitted port list.
    PortNotAllowed,
    /// Target domain was denied by the L3 allowlist (`NXDOMAIN`).
    DomainDenied(DnsDenyReason),
    /// Resolved IP address is blocked by the SSRF policy.
    SsrfBlocked,
}

/// Result of evaluating a full L3 egress request `(protocol, domain, port, resolved_ip)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressDecision {
    /// Egress allowed.
    Allow,
    /// Egress denied with explicit reason.
    Deny(EgressDenyReason),
}

/// Single L3 domain allowlist rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainRule {
    /// Matches ONLY the exact canonical domain (e.g. `api.github.com`).
    Exact(String),
    /// Single-label wildcard `*.example.com` matching `sub.example.com` (RFC 6125),
    /// NOT `example.com` itself and NOT `a.b.example.com`.
    WildcardSingleLabel(String),
    /// Explicit multi-level subdomain rule `**.example.com` matching `sub.example.com`
    /// and `a.b.example.com`, NOT `example.com` itself.
    SubdomainSuffix(String),
}

impl DomainRule {
    /// Parse a rule string:
    /// - `"api.github.com"` -> [`DomainRule::Exact`]
    /// - `"*.github.com"` -> [`DomainRule::WildcardSingleLabel`]
    /// - `"**.github.com"` -> [`DomainRule::SubdomainSuffix`]
    ///
    /// Rejects invalid domains, overly broad wildcards (`*`, `*.com`, `*.co.uk`), and any
    /// multi-tenant shared CDN suffix (e.g. `*.cloudfront.net`, `*.workers.dev`).
    pub fn parse(raw: &str) -> Result<Self> {
        let trimmed = raw.trim();
        if let Some(rest) = trimmed.strip_prefix("**.") {
            let base = normalize_domain(rest)?;
            validate_wildcard_base(&base, trimmed)?;
            if is_shared_multi_tenant_cdn(&base) {
                return Err(GwError::SharedCdnForbidden {
                    domain: trimmed.to_owned(),
                });
            }
            Ok(Self::SubdomainSuffix(base))
        } else if let Some(rest) = trimmed.strip_prefix("*.") {
            let base = normalize_domain(rest)?;
            validate_wildcard_base(&base, trimmed)?;
            if is_shared_multi_tenant_cdn(&base) {
                return Err(GwError::SharedCdnForbidden {
                    domain: trimmed.to_owned(),
                });
            }
            Ok(Self::WildcardSingleLabel(base))
        } else if trimmed.contains('*') {
            Err(GwError::InvalidDomain {
                pattern: trimmed.to_owned(),
                reason: "wildcards are only permitted as leading '*.' or '**.'",
            })
        } else {
            let domain = normalize_domain(trimmed)?;
            if is_shared_multi_tenant_cdn(&domain) {
                return Err(GwError::SharedCdnForbidden {
                    domain: trimmed.to_owned(),
                });
            }
            Ok(Self::Exact(domain))
        }
    }

    /// Canonical textual representation of this rule.
    #[must_use]
    pub fn as_pattern(&self) -> String {
        match self {
            Self::Exact(d) => d.clone(),
            Self::WildcardSingleLabel(base) => format!("*.{base}"),
            Self::SubdomainSuffix(base) => format!("**.{base}"),
        }
    }

    /// Match a canonicalized domain against this rule.
    #[must_use]
    pub fn matches_canonical(&self, canonical_domain: &str) -> bool {
        match self {
            Self::Exact(d) => canonical_domain == d,
            Self::WildcardSingleLabel(base) => {
                let Some(prefix) = canonical_domain.strip_suffix(base.as_str()) else {
                    return false;
                };
                let Some(label) = prefix.strip_suffix('.') else {
                    return false;
                };
                !label.is_empty() && !label.contains('.')
            }
            Self::SubdomainSuffix(base) => {
                let Some(prefix) = canonical_domain.strip_suffix(base.as_str()) else {
                    return false;
                };
                let Some(sub) = prefix.strip_suffix('.') else {
                    return false;
                };
                !sub.is_empty()
            }
        }
    }
}

/// L3 domain allowlist & transport egress policy.
#[derive(Debug, Clone)]
pub struct DomainAllowlist {
    rules: Vec<DomainRule>,
    allowed_tcp_ports: Vec<u16>,
    ssrf: SsrfPolicy,
}

impl Default for DomainAllowlist {
    fn default() -> Self {
        Self::new()
    }
}

impl DomainAllowlist {
    /// Create a deny-all L3 allowlist permitting TCP/443 once domains are added,
    /// blocking all UDP (including QUIC/443), all multi-tenant CDNs, and all SSRF IPs.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            allowed_tcp_ports: vec![443],
            ssrf: SsrfPolicy::strict(),
        }
    }

    /// Build from an iterator of rule strings.
    pub fn from_patterns<I, S>(patterns: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut list = Self::new();
        for p in patterns {
            list.add_pattern(p.as_ref())?;
        }
        Ok(list)
    }

    /// Parse and add a domain allowlist rule.
    pub fn add_pattern(&mut self, pattern: &str) -> Result<&mut Self> {
        let rule = DomainRule::parse(pattern)?;
        self.rules.push(rule);
        Ok(self)
    }

    /// Configure permitted TCP egress ports (default: `[443]`).
    ///
    /// UDP ports can NEVER be allowed because UDP/QUIC egress is unconditionally denied.
    pub fn with_allowed_tcp_ports(mut self, ports: Vec<u16>) -> Result<Self> {
        if ports.is_empty() || ports.contains(&0) {
            return Err(GwError::InvalidPolicy(
                "allowed_tcp_ports must be non-empty and contain no port 0".into(),
            ));
        }
        self.allowed_tcp_ports = ports;
        Ok(self)
    }

    /// Override the SSRF IP policy (defaults to [`SsrfPolicy::strict`]).
    #[must_use]
    pub fn with_ssrf(mut self, ssrf: SsrfPolicy) -> Self {
        self.ssrf = ssrf;
        self
    }

    /// Evaluate a DNS lookup for `domain`.
    ///
    /// Non-allowlisted domains, malformed domains, and multi-tenant shared CDNs ALWAYS
    /// return [`DnsRcode::NxDomain`].
    #[must_use]
    pub fn evaluate_dns(&self, domain: &str) -> DnsDecision {
        let Ok(canonical) = normalize_domain(domain) else {
            return DnsDecision::Deny {
                rcode: DnsRcode::NxDomain,
                reason: DnsDenyReason::InvalidDomain,
            };
        };

        if is_shared_multi_tenant_cdn(&canonical) {
            return DnsDecision::Deny {
                rcode: DnsRcode::NxDomain,
                reason: DnsDenyReason::SharedMultiTenantCdn,
            };
        }

        for rule in &self.rules {
            if rule.matches_canonical(&canonical) {
                return DnsDecision::Allow {
                    domain: canonical,
                    matched_rule: rule.as_pattern(),
                };
            }
        }

        DnsDecision::Deny {
            rcode: DnsRcode::NxDomain,
            reason: DnsDenyReason::NotAllowlisted,
        }
    }

    /// Evaluate a full L3 egress attempt (protocol + port + domain + optional resolved IP).
    ///
    /// Explicitly denies ALL UDP traffic (distinguishing QUIC UDP/443), non-allowed TCP ports,
    /// non-allowlisted / shared-CDN domains, and SSRF-blocked IP addresses.
    #[must_use]
    pub fn evaluate_egress(
        &self,
        protocol: TransportProtocol,
        domain: &str,
        port: u16,
        resolved_ip: Option<IpAddr>,
    ) -> EgressDecision {
        match protocol {
            TransportProtocol::Udp => {
                if port == 443 {
                    return EgressDecision::Deny(EgressDenyReason::QuicUdp443Forbidden);
                }
                return EgressDecision::Deny(EgressDenyReason::UdpForbidden);
            }
            TransportProtocol::Tcp => {
                if !self.allowed_tcp_ports.contains(&port) {
                    return EgressDecision::Deny(EgressDenyReason::PortNotAllowed);
                }
            }
        }

        if let DnsDecision::Deny { reason, .. } = self.evaluate_dns(domain) {
            return EgressDecision::Deny(EgressDenyReason::DomainDenied(reason));
        }

        if let Some(ip) = resolved_ip
            && self.ssrf.check_ip(ip).is_err()
        {
            return EgressDecision::Deny(EgressDenyReason::SsrfBlocked);
        }

        EgressDecision::Allow
    }
}

/// Returns `true` if `canonical_domain` equals or is a subdomain of any known multi-tenant
/// shared CDN / PaaS suffix.
#[must_use]
pub fn is_shared_multi_tenant_cdn(canonical_domain: &str) -> bool {
    SHARED_MULTI_TENANT_CDN_SUFFIXES.iter().any(|suffix| {
        canonical_domain == *suffix
            || canonical_domain
                .strip_suffix(suffix)
                .is_some_and(|prefix| prefix.ends_with('.'))
    })
}

/// Canonicalize and validate a DNS domain name (rejects raw IP literals, empty labels,
/// invalid characters, and overlong domains).
pub fn normalize_domain(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(GwError::InvalidDomain {
            pattern: raw.to_owned(),
            reason: "empty domain",
        });
    }
    let lowered = trimmed.to_ascii_lowercase();
    let stripped = lowered.strip_suffix('.').unwrap_or(&lowered);
    if stripped.is_empty() || stripped.len() > 253 {
        return Err(GwError::InvalidDomain {
            pattern: raw.to_owned(),
            reason: "domain length must be 1..=253 bytes",
        });
    }
    // Reject raw IP literals (must not bypass domain allowlists).
    if stripped.parse::<IpAddr>().is_ok() || stripped.contains(':') {
        return Err(GwError::InvalidDomain {
            pattern: raw.to_owned(),
            reason: "IP literals are not valid domain names",
        });
    }
    if stripped.starts_with('.') || stripped.ends_with('.') || stripped.contains("..") {
        return Err(GwError::InvalidDomain {
            pattern: raw.to_owned(),
            reason: "empty or leading/trailing dot label",
        });
    }
    let mut label_count = 0usize;
    for label in stripped.split('.') {
        label_count += 1;
        if label.is_empty() || label.len() > 63 {
            return Err(GwError::InvalidDomain {
                pattern: raw.to_owned(),
                reason: "label length must be 1..=63 bytes",
            });
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(GwError::InvalidDomain {
                pattern: raw.to_owned(),
                reason: "label must not start or end with '-'",
            });
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(GwError::InvalidDomain {
                pattern: raw.to_owned(),
                reason: "label contains invalid DNS characters",
            });
        }
    }
    if label_count < 2 {
        return Err(GwError::InvalidDomain {
            pattern: raw.to_owned(),
            reason: "single-label domains are not permitted in L3 allowlist",
        });
    }
    Ok(stripped.to_owned())
}

fn validate_wildcard_base(base: &str, original: &str) -> Result<()> {
    let labels: Vec<&str> = base.split('.').collect();
    if labels.len() < 2 {
        return Err(GwError::InvalidDomain {
            pattern: original.to_owned(),
            reason: "wildcard base must have at least two labels",
        });
    }
    if PUBLIC_TWO_LABEL_SUFFIXES.contains(&base) {
        return Err(GwError::InvalidDomain {
            pattern: original.to_owned(),
            reason: "wildcarding a public suffix is forbidden",
        });
    }
    Ok(())
}

/// Build an RFC 1035 wire-format `NXDOMAIN` response packet from a raw DNS query packet.
///
/// Copies the transaction ID and first question section while setting `QR = 1`, `RA = 1`,
/// `RCODE = 3 (NXDOMAIN)`, and zero answer/authority/additional counts.
pub fn build_nxdomain_wire_response(query: &[u8]) -> Result<Vec<u8>> {
    if query.len() < 12 {
        return Err(GwError::InvalidDnsPacket("DNS header shorter than 12 bytes"));
    }
    let qdcount = u16::from_be_bytes([query[4], query[5]]);
    if qdcount == 0 {
        return Err(GwError::InvalidDnsPacket("DNS query has zero questions"));
    }

    // Parse QNAME of the first question without pointer jumps to find end of Question section.
    let mut pos = 12usize;
    let mut jumped = false;
    loop {
        if pos >= query.len() {
            return Err(GwError::InvalidDnsPacket("truncated DNS QNAME"));
        }
        let len = query[pos];
        if len == 0 {
            pos += 1;
            break;
        }
        if (len & 0xc0) != 0 {
            jumped = true;
            break;
        }
        pos = pos
            .checked_add(1 + usize::from(len))
            .ok_or(GwError::InvalidDnsPacket("DNS QNAME length overflow"))?;
    }
    if jumped {
        return Err(GwError::InvalidDnsPacket(
            "compressed pointer in DNS question is unsupported",
        ));
    }
    let question_end = pos
        .checked_add(4)
        .ok_or(GwError::InvalidDnsPacket("DNS question overflow"))?;
    if question_end > query.len() {
        return Err(GwError::InvalidDnsPacket("truncated QTYPE/QCLASS"));
    }

    let mut resp = Vec::with_capacity(question_end);
    // TXID
    resp.push(query[0]);
    resp.push(query[1]);
    // Flags: QR=1 (0x80), preserve OPCODE & RD from query[2]; RA=1 (0x80), RCODE=3 (NXDOMAIN)
    let flags_hi = 0x80 | (query[2] & 0x79);
    let flags_lo = 0x80 | (DnsRcode::NxDomain as u8);
    resp.push(flags_hi);
    resp.push(flags_lo);
    // QDCOUNT = 1, ANCOUNT = 0, NSCOUNT = 0, ARCOUNT = 0
    resp.extend_from_slice(&1u16.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes());
    // Copy exact Question section
    resp.extend_from_slice(&query[12..question_end]);
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_and_wildcard_matching_and_nxdomain() {
        let allowlist =
            DomainAllowlist::from_patterns(["api.openai.com", "*.github.com", "**.pypi.org"])
                .unwrap();

        // Exact match (case-insensitive + optional trailing dot).
        assert!(allowlist.evaluate_dns("api.openai.com").is_allowed());
        assert!(allowlist.evaluate_dns("API.OPENAI.COM.").is_allowed());
        assert_eq!(
            allowlist.evaluate_dns("openai.com"),
            DnsDecision::Deny {
                rcode: DnsRcode::NxDomain,
                reason: DnsDenyReason::NotAllowlisted,
            }
        );

        // Single-label wildcard: matches `api.github.com`, NOT `github.com`, NOT `a.b.github.com`,
        // NOT `evilgithub.com`.
        assert!(allowlist.evaluate_dns("api.github.com").is_allowed());
        assert_eq!(allowlist.evaluate_dns("github.com").rcode(), DnsRcode::NxDomain);
        assert_eq!(
            allowlist.evaluate_dns("a.b.github.com").rcode(),
            DnsRcode::NxDomain
        );
        assert_eq!(
            allowlist.evaluate_dns("evilgithub.com").rcode(),
            DnsRcode::NxDomain
        );

        // Multi-level subdomain wildcard: matches both 1-level and 2-level, NOT apex.
        assert!(allowlist.evaluate_dns("files.pypi.org").is_allowed());
        assert!(allowlist.evaluate_dns("a.b.pypi.org").is_allowed());
        assert_eq!(allowlist.evaluate_dns("pypi.org").rcode(), DnsRcode::NxDomain);

        // Non-allowlisted and IP literals -> NXDOMAIN.
        assert_eq!(
            allowlist.evaluate_dns("evil.example.com").rcode(),
            DnsRcode::NxDomain
        );
        assert_eq!(
            allowlist.evaluate_dns("1.1.1.1").rcode(),
            DnsRcode::NxDomain
        );
    }

    #[test]
    fn rejects_shared_multi_tenant_cdns_and_overbroad_wildcards() {
        for cdn in [
            "*.cloudfront.net",
            "d1234abcd.cloudfront.net",
            "*.fastly.net",
            "pkg.fastly.net",
            "*.akamaized.net",
            "*.workers.dev",
            "my-worker.workers.dev",
            "*.pages.dev",
            "*.appspot.com",
            "*.vercel.app",
            "*.amazonaws.com",
        ] {
            assert!(
                matches!(DomainRule::parse(cdn), Err(GwError::SharedCdnForbidden { .. })),
                "CDN pattern must be rejected: {cdn}"
            );
        }

        // Also denied at query time with explicit SharedMultiTenantCdn reason.
        let list = DomainAllowlist::from_patterns(["api.example.com"]).unwrap();
        assert_eq!(
            list.evaluate_dns("d111111abcdef8.cloudfront.net"),
            DnsDecision::Deny {
                rcode: DnsRcode::NxDomain,
                reason: DnsDenyReason::SharedMultiTenantCdn,
            }
        );

        // Overbroad wildcards rejected.
        for bad in ["*", "*.com", "*.co.uk", "api.*.com", "localhost"] {
            assert!(DomainRule::parse(bad).is_err(), "must reject {bad}");
        }
    }

    #[test]
    fn udp_and_quic_443_are_explicitly_denied() {
        let list = DomainAllowlist::from_patterns(["api.openai.com"]).unwrap();
        let pub_ip: IpAddr = "1.1.1.1".parse().unwrap();

        assert_eq!(
            list.evaluate_egress(TransportProtocol::Tcp, "api.openai.com", 443, Some(pub_ip)),
            EgressDecision::Allow
        );
        assert_eq!(
            list.evaluate_egress(TransportProtocol::Udp, "api.openai.com", 443, Some(pub_ip)),
            EgressDecision::Deny(EgressDenyReason::QuicUdp443Forbidden)
        );
        assert_eq!(
            list.evaluate_egress(TransportProtocol::Udp, "api.openai.com", 53, Some(pub_ip)),
            EgressDecision::Deny(EgressDenyReason::UdpForbidden)
        );
        assert_eq!(
            list.evaluate_egress(TransportProtocol::Tcp, "api.openai.com", 80, Some(pub_ip)),
            EgressDecision::Deny(EgressDenyReason::PortNotAllowed)
        );
        assert_eq!(
            list.evaluate_egress(
                TransportProtocol::Tcp,
                "api.openai.com",
                443,
                Some("169.254.169.254".parse().unwrap()),
            ),
            EgressDecision::Deny(EgressDenyReason::SsrfBlocked)
        );
    }

    #[test]
    fn nxdomain_wire_response_preserves_txid_and_sets_rcode_3() {
        // Minimal DNS query for `evil.com` (A, IN) with TXID 0x1234.
        let query: Vec<u8> = vec![
            0x12, 0x34, // TXID
            0x01, 0x00, // Flags (RD=1)
            0x00, 0x01, // QDCOUNT=1
            0x00, 0x00, // ANCOUNT=0
            0x00, 0x00, // NSCOUNT=0
            0x00, 0x00, // ARCOUNT=0
            4, b'e', b'v', b'i', b'l', 3, b'c', b'o', b'm', 0, // QNAME
            0x00, 0x01, // QTYPE=A
            0x00, 0x01, // QCLASS=IN
        ];
        let resp = build_nxdomain_wire_response(&query).unwrap();
        assert_eq!(&resp[0..2], &[0x12, 0x34]);
        assert_eq!(resp[2] & 0x80, 0x80); // QR=1
        assert_eq!(resp[3] & 0x0f, 3); // RCODE=NXDOMAIN
        assert_eq!(&resp[12..], &query[12..]);
    }
}

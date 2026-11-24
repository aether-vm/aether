//! Capability policies, host-side credential injection specs, path/method matching,
//! and SSRF IP validation for `aos-gw` (ARCHITECTURE_V2 §2.2, §6, §7.4).

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use http::Method;
use http::header::HeaderName;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{GwError, Result};
use crate::l3_allowlist::DomainAllowlist;

/// Minimum byte length for a registered secret to avoid degenerate false positives.
pub const MIN_SECRET_LEN: usize = 4;

/// Hop-by-hop and security-sensitive headers that MUST NOT be injected as custom credentials
/// and MUST be stripped between client and upstream.
pub const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "proxy-connection",
];

/// Additional headers forbidden as custom credential targets.
const FORBIDDEN_INJECTION_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "content-encoding",
    "content-type",
    "cookie",
];

/// Host-side secret material zeroized on drop and never exposed via `Debug` or `Display`.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretValue {
    bytes: Zeroizing<Vec<u8>>,
}

impl SecretValue {
    /// Construct a validated secret string suitable for HTTP header injection.
    ///
    /// Rejects secrets shorter than [`MIN_SECRET_LEN`] bytes or containing CR/LF/NUL/control bytes.
    pub fn new(secret: impl Into<String>) -> Result<Self> {
        let s = secret.into();
        let raw = s.into_bytes();
        if raw.len() < MIN_SECRET_LEN {
            return Err(GwError::InvalidPolicy(format!(
                "secret must be at least {MIN_SECRET_LEN} bytes"
            )));
        }
        if raw
            .iter()
            .any(|&b| b == b'\r' || b == b'\n' || b == 0 || b < 0x20 || b == 0x7f)
        {
            return Err(GwError::InvalidPolicy(
                "secret contains disallowed control/CR/LF bytes".into(),
            ));
        }
        Ok(Self {
            bytes: Zeroizing::new(raw),
        })
    }

    /// Raw secret bytes (host-side use only: credential injection and reflection scanner).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Secret as UTF-8 string slice (guaranteed ASCII printable by constructor).
    #[must_use]
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(self.bytes.as_slice()).unwrap_or("")
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretValue([REDACTED])")
    }
}

/// Host-side credential injection rule.
///
/// Real secret bytes live strictly in `aos-gw` host memory and are NEVER placed into
/// sandbox memory, environment variables, or filesystem mounts.
#[derive(Debug, Clone)]
pub struct CredentialInjection {
    /// Non-secret label used in audit logs and reflection alerts (e.g. `"openai-api-key"`).
    pub label: String,
    /// Injection mode (Bearer token or custom HTTP header).
    pub kind: CredentialKind,
    /// Optional placeholder string that the sandbox request MUST supply in the target header
    /// in order for host-side replacement to occur. When `None`, the gateway strips any
    /// sandbox-supplied value and unconditionally injects the credential for matching routes.
    pub require_placeholder: Option<String>,
}

/// Kind of host-side HTTP credential header to inject.
#[derive(Debug, Clone)]
pub enum CredentialKind {
    /// Injects `Authorization: Bearer <token>`.
    Bearer(SecretValue),
    /// Injects `<header_name>: <value>`.
    CustomHeader {
        /// Validated lowercase HTTP header name.
        header_name: String,
        /// Secret header value.
        value: SecretValue,
    },
}

impl CredentialInjection {
    /// Create a Bearer token injection rule.
    pub fn bearer(label: impl Into<String>, token: SecretValue) -> Result<Self> {
        let label = validate_label(label.into())?;
        Ok(Self {
            label,
            kind: CredentialKind::Bearer(token),
            require_placeholder: None,
        })
    }

    /// Create a custom header injection rule (e.g. `x-api-key`).
    pub fn custom_header(
        label: impl Into<String>,
        header_name: impl AsRef<str>,
        value: SecretValue,
    ) -> Result<Self> {
        let label = validate_label(label.into())?;
        let name = header_name.as_ref().trim().to_ascii_lowercase();
        let parsed = HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
            GwError::InvalidPolicy(format!("invalid credential header name: {name:?}"))
        })?;
        let canonical = parsed.as_str();
        if HOP_BY_HOP_HEADERS.contains(&canonical)
            || FORBIDDEN_INJECTION_HEADERS.contains(&canonical)
        {
            return Err(GwError::InvalidPolicy(format!(
                "header {canonical:?} cannot be used for credential injection"
            )));
        }
        Ok(Self {
            label,
            kind: CredentialKind::CustomHeader {
                header_name: canonical.to_owned(),
                value,
            },
            require_placeholder: None,
        })
    }

    /// Require that the sandbox send a specific placeholder value in the target header
    /// before the gateway substitutes the real credential.
    pub fn with_placeholder(mut self, placeholder: impl Into<String>) -> Result<Self> {
        let ph = placeholder.into();
        if ph.is_empty()
            || ph
                .bytes()
                .any(|b| b == b'\r' || b == b'\n' || b == 0 || b < 0x20 || b == 0x7f)
        {
            return Err(GwError::InvalidPolicy(
                "invalid credential placeholder".into(),
            ));
        }
        self.require_placeholder = Some(ph);
        Ok(self)
    }

    /// Target HTTP header name (lowercase).
    #[must_use]
    pub fn header_name(&self) -> &str {
        match &self.kind {
            CredentialKind::Bearer(_) => "authorization",
            CredentialKind::CustomHeader { header_name, .. } => header_name.as_str(),
        }
    }

    /// Underlying secret value (host-side use only).
    #[must_use]
    pub fn secret(&self) -> &SecretValue {
        match &self.kind {
            CredentialKind::Bearer(v) => v,
            CredentialKind::CustomHeader { value, .. } => value,
        }
    }

    /// Formatted header value to inject on the upstream request.
    #[must_use]
    pub fn formatted_header_value(&self) -> Zeroizing<String> {
        match &self.kind {
            CredentialKind::Bearer(v) => Zeroizing::new(format!("Bearer {}", v.as_str())),
            CredentialKind::CustomHeader { value, .. } => {
                Zeroizing::new(value.as_str().to_owned())
            }
        }
    }
}

fn validate_label(label: String) -> Result<String> {
    if label.is_empty() || label.len() > 64 {
        return Err(GwError::InvalidPolicy(
            "credential label must be 1..=64 bytes".into(),
        ));
    }
    if !label
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err(GwError::InvalidPolicy(format!(
            "credential label contains invalid characters: {label:?}"
        )));
    }
    Ok(label)
}

/// Allowed HTTP methods for L1 reverse proxy capability rules.
///
/// `CONNECT` and `TRACE` are intentionally excluded from L1 (see ARCHITECTURE_V2 §7.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AllowedMethod {
    /// HTTP GET.
    Get,
    /// HTTP POST.
    Post,
    /// HTTP PUT.
    Put,
    /// HTTP PATCH.
    Patch,
    /// HTTP DELETE.
    Delete,
    /// HTTP HEAD.
    Head,
    /// HTTP OPTIONS.
    Options,
}

impl AllowedMethod {
    /// Convert from `http::Method`; returns `None` for disallowed methods (e.g. `CONNECT`, `TRACE`).
    #[must_use]
    pub fn from_http(method: &Method) -> Option<Self> {
        match *method {
            Method::GET => Some(Self::Get),
            Method::POST => Some(Self::Post),
            Method::PUT => Some(Self::Put),
            Method::PATCH => Some(Self::Patch),
            Method::DELETE => Some(Self::Delete),
            Method::HEAD => Some(Self::Head),
            Method::OPTIONS => Some(Self::Options),
            _ => None,
        }
    }

    /// Canonical uppercase ASCII name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
            Self::Head => "HEAD",
            Self::Options => "OPTIONS",
        }
    }
}

/// Fine-grained L1 capability rule scoped to **host + path_prefix + allowed HTTP methods**.
#[derive(Debug, Clone)]
pub struct RouteRule {
    /// Canonical lowercase target host matched against incoming `Host` header.
    pub host: String,
    /// Upstream TCP port (default 80 for HTTP/1.1 reverse proxy).
    pub upstream_port: u16,
    /// Optional explicit upstream socket address (e.g. for loopback test servers).
    /// Still validated against [`SsrfPolicy`] before connecting.
    pub upstream_connect_addr: Option<SocketAddr>,
    /// Normalized path prefix (always starts with `/`, e.g. `"/v1/chat"` or `"/"`).
    pub path_prefix: String,
    /// Non-empty set of allowed HTTP methods for this route.
    pub allowed_methods: Vec<AllowedMethod>,
    /// Optional host-side credential to inject for requests matching this route.
    pub credential: Option<CredentialInjection>,
}

impl RouteRule {
    /// Build a validated route rule.
    pub fn new(
        host: impl AsRef<str>,
        upstream_port: u16,
        path_prefix: impl AsRef<str>,
        allowed_methods: Vec<AllowedMethod>,
    ) -> Result<Self> {
        let canonical_host = canonicalize_route_host(host.as_ref())?;
        if upstream_port == 0 {
            return Err(GwError::InvalidPolicy(
                "upstream_port must be non-zero".into(),
            ));
        }
        let canonical_prefix = validate_path_prefix(path_prefix.as_ref())?;
        if allowed_methods.is_empty() {
            return Err(GwError::InvalidPolicy(
                "route rule must allow at least one HTTP method".into(),
            ));
        }
        Ok(Self {
            host: canonical_host,
            upstream_port,
            upstream_connect_addr: None,
            path_prefix: canonical_prefix,
            allowed_methods,
            credential: None,
        })
    }

    /// Attach a host-side credential injection rule.
    #[must_use]
    pub fn with_credential(mut self, credential: CredentialInjection) -> Self {
        self.credential = Some(credential);
        self
    }

    /// Set an explicit upstream socket address override (still subject to [`SsrfPolicy`]).
    #[must_use]
    pub fn with_upstream_addr(mut self, addr: SocketAddr) -> Self {
        self.upstream_connect_addr = Some(addr);
        self.upstream_port = addr.port();
        self
    }

    /// Check whether `(canonical_host, validated_path)` matches this rule's host and path prefix.
    #[must_use]
    pub fn matches_host_and_path(&self, canonical_host: &str, path: &str) -> bool {
        if self.host != canonical_host {
            return false;
        }
        path_matches_prefix(path, &self.path_prefix)
    }

    /// Check whether `method` is allowed by this rule.
    #[must_use]
    pub fn allows_method(&self, method: AllowedMethod) -> bool {
        self.allowed_methods.contains(&method)
    }

    /// Formatted `Host` header value sent to upstream.
    #[must_use]
    pub fn upstream_host_header(&self) -> String {
        if self.upstream_port == 80 {
            self.host.clone()
        } else if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.upstream_port)
        } else {
            format!("{}:{}", self.host, self.upstream_port)
        }
    }
}

/// Canonicalize a route host (hostname or IP literal, without port or brackets).
pub fn canonicalize_route_host(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 253 {
        return Err(GwError::InvalidPolicy(format!(
            "invalid host length: {raw:?}"
        )));
    }
    if trimmed.bytes().any(|b| {
        b.is_ascii_whitespace()
            || matches!(b, b'/' | b'\\' | b'@' | b'?' | b'#' | 0)
            || b < 0x20
            || b == 0x7f
    }) {
        return Err(GwError::InvalidPolicy(format!(
            "host contains forbidden characters: {raw:?}"
        )));
    }
    // Strip optional IPv6 brackets for canonical representation.
    let unbracketed = if trimmed.starts_with('[') && trimmed.ends_with(']') {
        &trimmed[1..trimmed.len() - 1]
    } else {
        trimmed
    };
    if let Ok(ip) = unbracketed.parse::<IpAddr>() {
        return Ok(ip.to_string());
    }
    let lowered = unbracketed.to_ascii_lowercase();
    let stripped = lowered.strip_suffix('.').unwrap_or(&lowered);
    if stripped.is_empty()
        || stripped.starts_with('.')
        || stripped.contains("..")
        || stripped.contains(':')
    {
        return Err(GwError::InvalidPolicy(format!(
            "malformed hostname: {raw:?}"
        )));
    }
    for label in stripped.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(GwError::InvalidPolicy(format!(
                "invalid hostname label {label:?} in {raw:?}"
            )));
        }
    }
    Ok(stripped.to_owned())
}

/// Parse an incoming HTTP `Host` header value into `(canonical_host, optional_port)`.
pub fn parse_http_host_header(raw: &str) -> Result<(String, Option<u16>)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(GwError::InvalidPolicy("empty Host header".into()));
    }
    if trimmed.starts_with('[') {
        // IPv6 literal: `[::1]` or `[::1]:8080`
        let close = trimmed
            .find(']')
            .ok_or_else(|| GwError::InvalidPolicy("unclosed IPv6 Host header".into()))?;
        let host_part = &trimmed[..=close];
        let rest = &trimmed[close + 1..];
        let port = if rest.is_empty() {
            None
        } else if let Some(port_str) = rest.strip_prefix(':') {
            let p: u16 = port_str
                .parse()
                .map_err(|_| GwError::InvalidPolicy("invalid port in Host header".into()))?;
            if p == 0 {
                return Err(GwError::InvalidPolicy("port 0 in Host header".into()));
            }
            Some(p)
        } else {
            return Err(GwError::InvalidPolicy(
                "trailing garbage after IPv6 Host header".into(),
            ));
        };
        Ok((canonicalize_route_host(host_part)?, port))
    } else if let Some((h, p_str)) = trimmed.rsplit_once(':') {
        // Must be host:port (not an unbracketed IPv6).
        if h.contains(':') {
            return Err(GwError::InvalidPolicy(
                "unbracketed IPv6 in Host header".into(),
            ));
        }
        let p: u16 = p_str
            .parse()
            .map_err(|_| GwError::InvalidPolicy("invalid port in Host header".into()))?;
        if p == 0 {
            return Err(GwError::InvalidPolicy("port 0 in Host header".into()));
        }
        Ok((canonicalize_route_host(h)?, Some(p)))
    } else {
        Ok((canonicalize_route_host(trimmed)?, None))
    }
}

/// Validate a configured `path_prefix` (must begin with `/`, no query/fragment/traversal).
pub fn validate_path_prefix(prefix: &str) -> Result<String> {
    if !prefix.starts_with('/') {
        return Err(GwError::InvalidPolicy(format!(
            "path_prefix must start with '/': {prefix:?}"
        )));
    }
    if prefix.contains('?') || prefix.contains('#') {
        return Err(GwError::InvalidPolicy(format!(
            "path_prefix must not contain query or fragment: {prefix:?}"
        )));
    }
    validate_request_path(prefix)?;
    // Strip trailing slashes except for root `"/"`.
    let trimmed = if prefix.len() > 1 {
        prefix.trim_end_matches('/')
    } else {
        prefix
    };
    if trimmed.is_empty() {
        Ok("/".to_owned())
    } else {
        Ok(trimmed.to_owned())
    }
}

/// Strictly validate an incoming HTTP request path against traversal and smuggling bypasses.
///
/// Rejects:
/// - non-leading-`/` paths
/// - NUL, CR/LF, control chars, backslashes `\`
/// - `.` or `..` path segments
/// - percent-encoded `.` (`%2e`), `/` (`%2f`), `\` (`%5c`), NUL (`%00`)
pub fn validate_request_path(path: &str) -> Result<()> {
    if !path.starts_with('/') {
        return Err(GwError::InvalidPolicy("request path must start with '/'".into()));
    }
    if path
        .bytes()
        .any(|b| b == 0 || b == b'\\' || b < 0x20 || b == 0x7f)
    {
        return Err(GwError::InvalidPolicy(
            "request path contains forbidden byte".into(),
        ));
    }
    // Reject percent-encoded traversal characters (%2e, %2f, %5c, %00) case-insensitively.
    let bytes = path.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(GwError::InvalidPolicy(
                    "incomplete percent-encoding in request path".into(),
                ));
            }
            let hi = hex_nibble(bytes[i + 1]).ok_or_else(|| {
                GwError::InvalidPolicy("invalid percent-encoding in request path".into())
            })?;
            let lo = hex_nibble(bytes[i + 2]).ok_or_else(|| {
                GwError::InvalidPolicy("invalid percent-encoding in request path".into())
            })?;
            let decoded = (hi << 4) | lo;
            if matches!(decoded, 0 | b'.' | b'/' | b'\\' | b'\r' | b'\n') {
                return Err(GwError::InvalidPolicy(
                    "forbidden percent-encoded traversal character in request path".into(),
                ));
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    // Check dot-segments and empty double-slash normalization ambiguities.
    for seg in path.split('/') {
        if seg == "." || seg == ".." {
            return Err(GwError::InvalidPolicy(
                "dot-segment traversal not allowed in request path".into(),
            ));
        }
    }
    if path.contains("//") {
        return Err(GwError::InvalidPolicy(
            "repeated slashes not allowed in request path".into(),
        ));
    }
    Ok(())
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Segment-boundary-safe prefix check.
///
/// `"/v1/api"` matches `"/v1/api"` and `"/v1/api/chat"`, but does NOT match `"/v1/api2"`.
#[must_use]
pub fn path_matches_prefix(path: &str, prefix: &str) -> bool {
    if prefix == "/" {
        return path.starts_with('/');
    }
    if path == prefix {
        return true;
    }
    if let Some(rest) = path.strip_prefix(prefix) {
        prefix.ends_with('/') || rest.starts_with('/')
    } else {
        false
    }
}

/// SSRF upstream IP validation policy.
///
/// By default ([`SsrfPolicy::strict`]), denies loopback, RFC1918 private networks, link-local
/// (including cloud metadata `169.254.169.254`), CGNAT (`100.64.0.0/10`), multicast,
/// unspecified, IPv6 ULA/link-local, NAT64, and IPv4-mapped IPv6 encodings of blocked IPv4 ranges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SsrfPolicy {
    /// Test-only escape hatch allowing loopback (`127.0.0.1` / `::1`) while still blocking
    /// metadata (`169.254.169.254`), RFC1918, link-local, CGNAT, and multicast ranges.
    allow_loopback: bool,
}

impl Default for SsrfPolicy {
    fn default() -> Self {
        Self::strict()
    }
}

impl SsrfPolicy {
    /// Production default: block all non-globally-routable IPs (loopback, RFC1918, link-local,
    /// cloud metadata `169.254.169.254`, CGNAT, multicast, reserved, IPv4-mapped IPv6).
    #[must_use]
    pub const fn strict() -> Self {
        Self {
            allow_loopback: false,
        }
    }

    /// Explicit test-only override allowing local loopback (`127.0.0.1` / `::1`) integration tests.
    ///
    /// Cloud metadata (`169.254.169.254`), RFC1918 private networks, link-local, and multicast
    /// remain strictly blocked even under this override.
    #[must_use]
    pub const fn allow_loopback_for_tests() -> Self {
        Self {
            allow_loopback: true,
        }
    }

    /// Validate an upstream IP address against the SSRF blocklist.
    pub fn check_ip(&self, ip: IpAddr) -> Result<()> {
        match ip {
            IpAddr::V4(v4) => self.check_ipv4(v4),
            IpAddr::V6(v6) => self.check_ipv6(v6),
        }
    }

    fn check_ipv4(&self, ip: Ipv4Addr) -> Result<()> {
        let [a, b, c, _d] = ip.octets();
        if a == 127 {
            if self.allow_loopback && ip == Ipv4Addr::LOCALHOST {
                return Ok(());
            }
            return Err(GwError::SsrfBlocked {
                ip: IpAddr::V4(ip),
                reason: "loopback address (127.0.0.0/8)",
            });
        }
        if a == 0 {
            return Err(GwError::SsrfBlocked {
                ip: IpAddr::V4(ip),
                reason: "unspecified/this-network (0.0.0.0/8)",
            });
        }
        if a == 10 {
            return Err(GwError::SsrfBlocked {
                ip: IpAddr::V4(ip),
                reason: "RFC1918 private network (10.0.0.0/8)",
            });
        }
        if a == 100 && (64..=127).contains(&b) {
            return Err(GwError::SsrfBlocked {
                ip: IpAddr::V4(ip),
                reason: "CGNAT shared address space (100.64.0.0/10)",
            });
        }
        if a == 169 && b == 254 {
            return Err(GwError::SsrfBlocked {
                ip: IpAddr::V4(ip),
                reason: "link-local / cloud metadata (169.254.0.0/16)",
            });
        }
        if a == 172 && (16..=31).contains(&b) {
            return Err(GwError::SsrfBlocked {
                ip: IpAddr::V4(ip),
                reason: "RFC1918 private network (172.16.0.0/12)",
            });
        }
        if a == 192 && b == 168 {
            return Err(GwError::SsrfBlocked {
                ip: IpAddr::V4(ip),
                reason: "RFC1918 private network (192.168.0.0/16)",
            });
        }
        if a == 192 && b == 0 && c == 0 {
            return Err(GwError::SsrfBlocked {
                ip: IpAddr::V4(ip),
                reason: "IETF protocol assignment (192.0.0.0/24)",
            });
        }
        if (a == 192 && b == 0 && c == 2)
            || (a == 198 && b == 51 && c == 100)
            || (a == 203 && b == 0 && c == 113)
        {
            return Err(GwError::SsrfBlocked {
                ip: IpAddr::V4(ip),
                reason: "TEST-NET documentation range",
            });
        }
        if a == 198 && (18..=19).contains(&b) {
            return Err(GwError::SsrfBlocked {
                ip: IpAddr::V4(ip),
                reason: "benchmarking range (198.18.0.0/15)",
            });
        }
        if a >= 224 {
            return Err(GwError::SsrfBlocked {
                ip: IpAddr::V4(ip),
                reason: "multicast/reserved/broadcast (224.0.0.0/3)",
            });
        }
        Ok(())
    }

    fn check_ipv6(&self, ip: Ipv6Addr) -> Result<()> {
        // Unwrap IPv4-mapped IPv6 (::ffff:a.b.c.d) to prevent SSRF bypasses like ::ffff:169.254.169.254.
        if let Some(v4) = ip.to_ipv4_mapped() {
            return self.check_ipv4(v4).map_err(|_| GwError::SsrfBlocked {
                ip: IpAddr::V6(ip),
                reason: "IPv4-mapped IPv6 targets blocked IPv4 range",
            });
        }
        if ip.is_loopback() {
            if self.allow_loopback {
                return Ok(());
            }
            return Err(GwError::SsrfBlocked {
                ip: IpAddr::V6(ip),
                reason: "IPv6 loopback (::1)",
            });
        }
        if ip.is_unspecified() {
            return Err(GwError::SsrfBlocked {
                ip: IpAddr::V6(ip),
                reason: "IPv6 unspecified (::)",
            });
        }
        let segs = ip.segments();
        // Deprecated IPv4-compatible IPv6 (::/96)
        if segs[0..6] == [0, 0, 0, 0, 0, 0] {
            return Err(GwError::SsrfBlocked {
                ip: IpAddr::V6(ip),
                reason: "deprecated IPv4-compatible IPv6 (::/96)",
            });
        }
        // NAT64 well-known (64:ff9b::/96) and local-use (64:ff9b:1::/48)
        if segs[0] == 0x0064 && segs[1] == 0xff9b {
            return Err(GwError::SsrfBlocked {
                ip: IpAddr::V6(ip),
                reason: "NAT64 translation prefix (64:ff9b::)",
            });
        }
        // Discard-only (100::/64)
        if segs[0] == 0x0100 && segs[1] == 0 && segs[2] == 0 && segs[3] == 0 {
            return Err(GwError::SsrfBlocked {
                ip: IpAddr::V6(ip),
                reason: "IPv6 discard prefix (100::/64)",
            });
        }
        // Unique local address (fc00::/7)
        if (segs[0] & 0xfe00) == 0xfc00 {
            return Err(GwError::SsrfBlocked {
                ip: IpAddr::V6(ip),
                reason: "IPv6 unique local private address (fc00::/7)",
            });
        }
        // Link-local (fe80::/10)
        if (segs[0] & 0xffc0) == 0xfe80 {
            return Err(GwError::SsrfBlocked {
                ip: IpAddr::V6(ip),
                reason: "IPv6 link-local (fe80::/10)",
            });
        }
        // Multicast (ff00::/8)
        if (segs[0] & 0xff00) == 0xff00 {
            return Err(GwError::SsrfBlocked {
                ip: IpAddr::V6(ip),
                reason: "IPv6 multicast (ff00::/8)",
            });
        }
        // Documentation (2001:db8::/32)
        if segs[0] == 0x2001 && segs[1] == 0x0db8 {
            return Err(GwError::SsrfBlocked {
                ip: IpAddr::V6(ip),
                reason: "IPv6 documentation prefix (2001:db8::/32)",
            });
        }
        Ok(())
    }
}

/// Action taken by the streaming anti-reflection scanner when a secret match is detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ReflectionAction {
    /// Immediately abort the upstream response stream before any matched secret byte is forwarded.
    #[default]
    Abort,
    /// Replace every matched secret occurrence with `[REDACTED_SECRET]` while continuing the stream.
    Redact,
}

/// Hard size and timeout caps enforced on every L1 proxy request and response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyLimits {
    /// Maximum total bytes permitted across all HTTP request/response headers.
    pub max_header_bytes: usize,
    /// Maximum number of headers permitted on a request or response.
    pub max_header_count: usize,
    /// Maximum incoming request body size in bytes.
    pub max_request_body_bytes: usize,
    /// Maximum upstream response body size in bytes.
    pub max_response_body_bytes: usize,
    /// Timeout when connecting to upstream TCP socket.
    pub upstream_connect_timeout: Duration,
    /// Timeout waiting for upstream response headers.
    pub upstream_response_timeout: Duration,
}

impl Default for ProxyLimits {
    fn default() -> Self {
        Self {
            max_header_bytes: 16 * 1024,
            max_header_count: 64,
            max_request_body_bytes: 4 * 1024 * 1024,
            max_response_body_bytes: 16 * 1024 * 1024,
            upstream_connect_timeout: Duration::from_secs(10),
            upstream_response_timeout: Duration::from_secs(30),
        }
    }
}

/// Full egress capability policy bound to a `(slot_id, world_id, daemon_epoch)` tuple.
#[derive(Debug, Clone)]
pub struct CapabilityPolicy {
    /// Fine-grained L1 reverse proxy route rules (host + path_prefix + methods + credential).
    pub routes: Vec<RouteRule>,
    /// Optional L3 DNS / egress domain allowlist attached to this world.
    pub l3_allowlist: Option<DomainAllowlist>,
    /// SSRF IP blocklist policy (defaults to [`SsrfPolicy::strict`]).
    pub ssrf: SsrfPolicy,
    /// Request/response header, body, and timeout limits.
    pub limits: ProxyLimits,
    /// Action taken when upstream response reflects a registered secret.
    pub reflection_action: ReflectionAction,
}

impl Default for CapabilityPolicy {
    fn default() -> Self {
        Self {
            routes: Vec::new(),
            l3_allowlist: None,
            ssrf: SsrfPolicy::strict(),
            limits: ProxyLimits::default(),
            reflection_action: ReflectionAction::Abort,
        }
    }
}

/// Result of matching an incoming `(host, path, method)` against a [`CapabilityPolicy`].
#[derive(Debug)]
pub enum RouteMatch<'a> {
    /// Request matched an authorized route rule.
    Allowed(&'a RouteRule),
    /// Host + path matched at least one route, but the HTTP method is forbidden.
    MethodNotAllowed,
    /// No route matched the requested host and path prefix.
    Denied,
}

impl CapabilityPolicy {
    /// Create an empty deny-all policy with strict SSRF and default limits.
    #[must_use]
    pub fn deny_all() -> Self {
        Self::default()
    }

    /// Add an L1 route rule.
    #[must_use]
    pub fn with_route(mut self, rule: RouteRule) -> Self {
        self.routes.push(rule);
        self
    }

    /// Attach an L3 domain allowlist.
    #[must_use]
    pub fn with_l3_allowlist(mut self, allowlist: DomainAllowlist) -> Self {
        self.l3_allowlist = Some(allowlist);
        self
    }

    /// Configure the SSRF policy (use [`SsrfPolicy::allow_loopback_for_tests`] only in tests).
    #[must_use]
    pub fn with_ssrf(mut self, ssrf: SsrfPolicy) -> Self {
        self.ssrf = ssrf;
        self
    }

    /// Configure header/body/timeout limits.
    #[must_use]
    pub fn with_limits(mut self, limits: ProxyLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Configure anti-reflection action (`Abort` vs `Redact`).
    #[must_use]
    pub fn with_reflection_action(mut self, action: ReflectionAction) -> Self {
        self.reflection_action = action;
        self
    }

    /// Match an incoming request against all configured L1 routes.
    ///
    /// Prefers the most specific (longest `path_prefix`) matching route when multiple rules
    /// match `(host, path, method)`.
    #[must_use]
    pub fn match_route(&self, canonical_host: &str, path: &str, method: AllowedMethod) -> RouteMatch<'_> {
        let mut best_allowed: Option<&RouteRule> = None;
        let mut saw_host_path_match = false;

        for rule in &self.routes {
            if rule.matches_host_and_path(canonical_host, path) {
                saw_host_path_match = true;
                if rule.allows_method(method) {
                    match best_allowed {
                        None => best_allowed = Some(rule),
                        Some(prev) if rule.path_prefix.len() > prev.path_prefix.len() => {
                            best_allowed = Some(rule);
                        }
                        _ => {}
                    }
                }
            }
        }

        if let Some(rule) = best_allowed {
            RouteMatch::Allowed(rule)
        } else if saw_host_path_match {
            RouteMatch::MethodNotAllowed
        } else {
            RouteMatch::Denied
        }
    }

    /// Iterate over all `(label, SecretValue)` credentials registered in this policy.
    pub fn registered_secrets(&self) -> Vec<(String, &SecretValue)> {
        self.routes
            .iter()
            .filter_map(|r| {
                r.credential
                    .as_ref()
                    .map(|c| (c.label.clone(), c.secret()))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_prefix_respects_segment_boundaries() {
        assert!(path_matches_prefix("/v1/chat", "/v1/chat"));
        assert!(path_matches_prefix("/v1/chat/completions", "/v1/chat"));
        assert!(!path_matches_prefix("/v1/chat2", "/v1/chat"));
        assert!(!path_matches_prefix("/v1/cha", "/v1/chat"));
        assert!(path_matches_prefix("/anything", "/"));
    }

    #[test]
    fn request_path_rejects_traversal_and_encoded_smuggling() {
        assert!(validate_request_path("/v1/chat/completions").is_ok());
        assert!(validate_request_path("/v1/models/gpt-4o%20mini").is_ok());

        for bad in [
            "v1/chat",
            "/v1/../admin",
            "/v1/./admin",
            "/v1/%2e%2e/admin",
            "/v1/%2E%2E/admin",
            "/v1/chat%2fadmin",
            "/v1/chat%5cadmin",
            "/v1/chat\\admin",
            "/v1/chat%00admin",
            "/v1//admin",
            "/v1/chat\r\nInjected: 1",
        ] {
            assert!(
                validate_request_path(bad).is_err(),
                "path should have been rejected: {bad:?}"
            );
        }
    }

    #[test]
    fn ssrf_strict_blocks_private_loopback_metadata_and_v4_mapped_v6() {
        let strict = SsrfPolicy::strict();
        for blocked in [
            "127.0.0.1",
            "127.0.0.2",
            "0.0.0.0",
            "10.0.0.1",
            "100.64.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.1.1",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "::",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "::ffff:10.0.0.5",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "ff02::1",
            "64:ff9b::169.254.169.254",
        ] {
            let ip: IpAddr = blocked.parse().unwrap();
            assert!(strict.check_ip(ip).is_err(), "must block {blocked}");
        }

        for allowed in ["1.1.1.1", "8.8.8.8", "93.184.216.34", "2606:4700:4700::1111"] {
            let ip: IpAddr = allowed.parse().unwrap();
            assert!(strict.check_ip(ip).is_ok(), "must allow public IP {allowed}");
        }

        // Test loopback override allows ONLY 127.0.0.1 / ::1, still blocks metadata & RFC1918!
        let test_ssrf = SsrfPolicy::allow_loopback_for_tests();
        assert!(test_ssrf.check_ip("127.0.0.1".parse().unwrap()).is_ok());
        assert!(test_ssrf.check_ip("::1".parse().unwrap()).is_ok());
        assert!(test_ssrf.check_ip("169.254.169.254".parse().unwrap()).is_err());
        assert!(test_ssrf.check_ip("10.0.0.1".parse().unwrap()).is_err());
        assert!(test_ssrf.check_ip("::ffff:169.254.169.254".parse().unwrap()).is_err());
    }

    #[test]
    fn secret_value_debug_redacts() {
        let s = SecretValue::new("sk-super-secret-value-999").unwrap();
        let dbg = format!("{s:?}");
        assert!(!dbg.contains("super-secret"));
        assert!(dbg.contains("REDACTED"));
    }

    #[test]
    fn credential_rejects_hop_by_hop_and_control_bytes() {
        let s = SecretValue::new("valid-secret-1234").unwrap();
        assert!(CredentialInjection::custom_header("bad", "Host", s.clone()).is_err());
        assert!(CredentialInjection::custom_header("bad", "Connection", s.clone()).is_err());
        assert!(CredentialInjection::custom_header("bad", "Transfer-Encoding", s.clone()).is_err());
        assert!(CredentialInjection::custom_header("good", "X-Api-Key", s).is_ok());
        assert!(SecretValue::new("bad\r\nheader").is_err());
    }
}

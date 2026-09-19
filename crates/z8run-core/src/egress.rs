//! Outbound network policy for flow nodes (A-03, A-04).
//!
//! Flows are authored by any registered user and run on the server, so every
//! node that opens a connection goes through this module. In `strict` mode
//! (the default) destinations on loopback, private, link-local (cloud
//! metadata), CGNAT and other non-public ranges are refused unless the
//! operator lists them in `Z8_EGRESS_ALLOW`.
//!
//! HTTP is enforced at every step a request can take:
//! - [`EgressClient`] checks the scheme and literal-IP hosts before sending.
//! - Hostnames resolve through [`PolicyResolver`], and the connection uses only
//!   the addresses that passed, so DNS rebinding cannot swap in another IP.
//! - Every redirect hop is checked again.
//! - Response bodies are read with a size cap (`Z8_EGRESS_MAX_RESPONSE_BYTES`).
//!
//! Non-HTTP nodes (database, MQTT) call [`check_host`] before connecting.
//!
//! Environment:
//! - `Z8_EGRESS_POLICY`: `strict` (default) or `permissive` (no filtering).
//! - `Z8_EGRESS_ALLOW`: comma-separated IPs, CIDRs or hostnames that are
//!   always allowed, e.g. `127.0.0.1,10.0.5.0/24,ollama`.
//! - `Z8_EGRESS_MAX_RESPONSE_BYTES`: response body cap (default 10 MiB).

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use ipnet::IpNet;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::{Method, RequestBuilder, Response, Url};
use tracing::{info, warn};

/// Default response body cap (10 MiB).
const DEFAULT_MAX_RESPONSE_BYTES: usize = 10 * 1024 * 1024;
/// Redirect hops followed before giving up.
const MAX_REDIRECTS: usize = 10;

/// Ranges refused in strict mode: everything that is not the public internet.
/// IPv4-mapped IPv6 addresses are canonicalized first, so the IPv4 entries
/// cover them too.
const BLOCKED_RANGES: &[&str] = &[
    "0.0.0.0/8",       // "this" network
    "10.0.0.0/8",      // private
    "100.64.0.0/10",   // carrier-grade NAT
    "127.0.0.0/8",     // loopback
    "169.254.0.0/16",  // link-local, cloud metadata (169.254.169.254)
    "172.16.0.0/12",   // private
    "192.0.0.0/24",    // IETF protocol assignments
    "192.0.2.0/24",    // documentation
    "192.168.0.0/16",  // private
    "198.18.0.0/15",   // benchmarking
    "198.51.100.0/24", // documentation
    "203.0.113.0/24",  // documentation
    "224.0.0.0/4",     // multicast
    "240.0.0.0/4",     // reserved, broadcast
    "::/128",          // unspecified
    "::1/128",         // loopback
    "64:ff9b::/96",    // NAT64 (maps onto IPv4, including private ranges)
    "64:ff9b:1::/48",  // local-use NAT64
    "100::/64",        // discard
    "2001::/32",       // Teredo
    "2001:db8::/32",   // documentation
    "2002::/16",       // 6to4 (embeds an IPv4 address)
    "fc00::/7",        // unique local
    "fe80::/10",       // link-local
    "ff00::/8",        // multicast
];

static BLOCKED: LazyLock<Vec<IpNet>> = LazyLock::new(|| {
    BLOCKED_RANGES
        .iter()
        .map(|r| r.parse().expect("valid built-in range"))
        .collect()
});

/// Why an outbound call was refused or failed.
#[derive(Debug, thiserror::Error)]
pub enum EgressError {
    #[error("invalid URL: {0}")]
    InvalidUrl(String),
    #[error("scheme '{0}' is not allowed; use http or https")]
    Scheme(String),
    #[error("destination {0} is blocked by the egress policy; allow it with Z8_EGRESS_ALLOW")]
    Blocked(String),
    #[error("could not resolve {0}: {1}")]
    Resolve(String, String),
    #[error("response body exceeds the {0} byte limit")]
    TooLarge(usize),
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    #[error("invalid JSON response: {0}")]
    Json(#[from] serde_json::Error),
}

impl From<EgressError> for String {
    fn from(e: EgressError) -> Self {
        e.to_string()
    }
}

impl From<EgressError> for crate::error::Z8Error {
    fn from(e: EgressError) -> Self {
        crate::error::Z8Error::Internal(e.to_string())
    }
}

/// Egress filtering mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressMode {
    /// Refuse non-public destinations unless allow-listed.
    Strict,
    /// No destination filtering (single-operator installs on trusted networks).
    Permissive,
}

/// Where flows may connect, and how much they may read back.
#[derive(Debug, Clone)]
pub struct EgressPolicy {
    mode: EgressMode,
    allow_nets: Vec<IpNet>,
    allow_hosts: Vec<String>,
    max_response_bytes: usize,
}

impl EgressPolicy {
    /// Strict policy with an allow list (IPs, CIDRs or hostnames).
    pub fn strict(allow: &str) -> Self {
        let mut policy = Self {
            mode: EgressMode::Strict,
            allow_nets: Vec::new(),
            allow_hosts: Vec::new(),
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        };
        for entry in allow.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            if let Ok(net) = entry.parse::<IpNet>() {
                policy.allow_nets.push(net);
            } else if let Ok(ip) = entry.parse::<IpAddr>() {
                policy.allow_nets.push(IpNet::from(ip.to_canonical()));
            } else {
                policy.allow_hosts.push(normalize_host(entry));
            }
        }
        policy
    }

    /// Policy that allows every destination.
    pub fn permissive() -> Self {
        Self {
            mode: EgressMode::Permissive,
            ..Self::strict("")
        }
    }

    /// Overrides the response body cap.
    pub fn with_max_response_bytes(mut self, max: usize) -> Self {
        self.max_response_bytes = max;
        self
    }

    /// Reads `Z8_EGRESS_POLICY`, `Z8_EGRESS_ALLOW` and
    /// `Z8_EGRESS_MAX_RESPONSE_BYTES`. Unknown policy values fall back to
    /// strict.
    pub fn from_env() -> Self {
        let mode = std::env::var("Z8_EGRESS_POLICY").unwrap_or_default();
        let mut policy = match mode.trim().to_ascii_lowercase().as_str() {
            "permissive" => Self::permissive(),
            "" | "strict" => Self::strict(&std::env::var("Z8_EGRESS_ALLOW").unwrap_or_default()),
            other => {
                warn!(value = other, "Unknown Z8_EGRESS_POLICY; using strict");
                Self::strict(&std::env::var("Z8_EGRESS_ALLOW").unwrap_or_default())
            }
        };
        if let Some(max) = std::env::var("Z8_EGRESS_MAX_RESPONSE_BYTES")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .filter(|v| *v > 0)
        {
            policy.max_response_bytes = max;
        }
        policy
    }

    pub fn mode(&self) -> EgressMode {
        self.mode
    }

    pub fn max_response_bytes(&self) -> usize {
        self.max_response_bytes
    }

    fn host_allowed(&self, host: &str) -> bool {
        self.mode == EgressMode::Permissive
            || self.allow_hosts.iter().any(|h| *h == normalize_host(host))
    }

    /// Whether a connection to `ip` is allowed.
    pub fn check_ip(&self, ip: IpAddr) -> Result<(), EgressError> {
        let ip = ip.to_canonical();
        if self.mode == EgressMode::Permissive
            || self.allow_nets.iter().any(|n| n.contains(&ip))
            || !BLOCKED.iter().any(|n| n.contains(&ip))
        {
            Ok(())
        } else {
            Err(EgressError::Blocked(ip.to_string()))
        }
    }

    /// Checks what can be decided without DNS: the scheme and, when the host
    /// is an IP literal, the address itself. Hostnames are checked when they
    /// resolve.
    pub fn check_url(&self, url: &Url) -> Result<(), EgressError> {
        if !matches!(url.scheme(), "http" | "https") {
            return Err(EgressError::Scheme(url.scheme().to_string()));
        }
        match url.host() {
            Some(url::Host::Ipv4(ip)) => self.check_ip(IpAddr::V4(ip)),
            Some(url::Host::Ipv6(ip)) => self.check_ip(IpAddr::V6(ip)),
            Some(url::Host::Domain(_)) => Ok(()),
            None => Err(EgressError::InvalidUrl("missing host".to_string())),
        }
    }

    /// Keeps the resolved addresses this policy allows for `host`. Fails when
    /// none are left, naming the first refused address.
    fn filter_resolved(
        &self,
        host: &str,
        addrs: Vec<SocketAddr>,
    ) -> Result<Vec<SocketAddr>, EgressError> {
        if self.host_allowed(host) {
            return Ok(addrs);
        }
        let mut refused = None;
        let allowed: Vec<SocketAddr> = addrs
            .into_iter()
            .filter(|a| match self.check_ip(a.ip()) {
                Ok(()) => true,
                Err(e) => {
                    refused.get_or_insert(e);
                    false
                }
            })
            .collect();
        match (allowed.is_empty(), refused) {
            (false, _) => Ok(allowed),
            (true, Some(EgressError::Blocked(ip))) => {
                Err(EgressError::Blocked(format!("{host} ({ip})")))
            }
            (true, _) => Err(EgressError::Resolve(
                host.to_string(),
                "no addresses".to_string(),
            )),
        }
    }

    /// Resolves `host` and returns the addresses a connection may use.
    pub async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, EgressError> {
        let host = host.trim_start_matches('[').trim_end_matches(']');
        if let Ok(ip) = host.parse::<IpAddr>() {
            self.check_ip(ip)?;
            return Ok(vec![SocketAddr::new(ip, port)]);
        }
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
            .await
            .map_err(|e| EgressError::Resolve(host.to_string(), e.to_string()))?
            .collect();
        self.filter_resolved(host, addrs)
    }
}

fn normalize_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// DNS resolver that only hands reqwest addresses the policy allows.
struct PolicyResolver {
    policy: Arc<EgressPolicy>,
}

impl Resolve for PolicyResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let policy = Arc::clone(&self.policy);
        Box::pin(async move {
            // reqwest sets the port on the returned addresses itself.
            let addrs = policy.resolve(name.as_str(), 0).await?;
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

/// HTTP client bound to an [`EgressPolicy`]. Cheap to clone.
#[derive(Clone)]
pub struct EgressClient {
    inner: reqwest::Client,
    policy: Arc<EgressPolicy>,
}

impl EgressClient {
    #[allow(clippy::disallowed_methods)] // the one sanctioned construction
    pub fn new(policy: EgressPolicy) -> Self {
        let policy = Arc::new(policy);
        let redirect_policy = Arc::clone(&policy);
        let mut builder = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .dns_resolver(Arc::new(PolicyResolver {
                policy: Arc::clone(&policy),
            }))
            .redirect(reqwest::redirect::Policy::custom(move |attempt| {
                if attempt.previous().len() >= MAX_REDIRECTS {
                    return attempt.error("too many redirects");
                }
                match redirect_policy.check_url(attempt.url()) {
                    Ok(()) => attempt.follow(),
                    Err(e) => attempt.error(e),
                }
            }));
        if policy.mode == EgressMode::Strict {
            // A proxy would resolve and connect on our behalf, out of reach of
            // the resolver above.
            builder = builder.no_proxy();
        }
        let inner = builder.build().expect("HTTP client configuration is valid");
        Self { inner, policy }
    }

    pub fn policy(&self) -> &EgressPolicy {
        &self.policy
    }

    /// Starts a request after checking the URL against the policy.
    pub fn request(
        &self,
        method: Method,
        url: impl AsRef<str>,
    ) -> Result<RequestBuilder, EgressError> {
        let url = Url::parse(url.as_ref()).map_err(|e| EgressError::InvalidUrl(e.to_string()))?;
        self.policy.check_url(&url)?;
        Ok(self.inner.request(method, url))
    }

    pub fn get(&self, url: impl AsRef<str>) -> Result<RequestBuilder, EgressError> {
        self.request(Method::GET, url)
    }

    pub fn post(&self, url: impl AsRef<str>) -> Result<RequestBuilder, EgressError> {
        self.request(Method::POST, url)
    }

    pub fn put(&self, url: impl AsRef<str>) -> Result<RequestBuilder, EgressError> {
        self.request(Method::PUT, url)
    }

    pub fn patch(&self, url: impl AsRef<str>) -> Result<RequestBuilder, EgressError> {
        self.request(Method::PATCH, url)
    }

    pub fn delete(&self, url: impl AsRef<str>) -> Result<RequestBuilder, EgressError> {
        self.request(Method::DELETE, url)
    }

    pub fn head(&self, url: impl AsRef<str>) -> Result<RequestBuilder, EgressError> {
        self.request(Method::HEAD, url)
    }

    /// Reads the body, failing once it passes the policy's size cap.
    pub async fn read_bytes(&self, mut resp: Response) -> Result<Vec<u8>, EgressError> {
        let max = self.policy.max_response_bytes;
        if resp.content_length().is_some_and(|len| len > max as u64) {
            return Err(EgressError::TooLarge(max));
        }
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await? {
            if body.len() + chunk.len() > max {
                return Err(EgressError::TooLarge(max));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }

    /// Reads the body as text (lossy UTF-8), capped like [`Self::read_bytes`].
    pub async fn read_text(&self, resp: Response) -> Result<String, EgressError> {
        let bytes = self.read_bytes(resp).await?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    /// Parses the body as JSON, capped like [`Self::read_bytes`].
    pub async fn read_json<T: serde::de::DeserializeOwned>(
        &self,
        resp: Response,
    ) -> Result<T, EgressError> {
        let bytes = self.read_bytes(resp).await?;
        Ok(serde_json::from_slice(&bytes)?)
    }
}

static CLIENT: LazyLock<EgressClient> = LazyLock::new(|| {
    let policy = EgressPolicy::from_env();
    match policy.mode {
        EgressMode::Strict => info!(
            allow_nets = ?policy.allow_nets,
            allow_hosts = ?policy.allow_hosts,
            max_response_bytes = policy.max_response_bytes,
            "Egress policy: strict"
        ),
        EgressMode::Permissive => warn!(
            "Egress policy: permissive; flows can reach any address this server can, \
             including localhost and internal networks"
        ),
    }
    EgressClient::new(policy)
});

/// The process-wide client, configured from the environment on first use.
pub fn client() -> &'static EgressClient {
    &CLIENT
}

/// Formats a request error with its causes, so a refusal by the resolver
/// ("blocked by the egress policy") is visible instead of a generic
/// "error sending request".
pub fn describe(e: &reqwest::Error) -> String {
    let mut text = e.to_string();
    let mut source = std::error::Error::source(e);
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

/// Checks a non-HTTP destination (database, MQTT broker) against the
/// process-wide policy.
pub async fn check_host(host: &str, port: u16) -> Result<(), EgressError> {
    client().policy.resolve(host, port).await.map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn strict_blocks_internal_ranges_and_allows_public() {
        let policy = EgressPolicy::strict("");
        for blocked in [
            "127.0.0.1",
            "10.1.2.3",
            "172.20.0.5",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "64:ff9b::a00:1",
        ] {
            assert!(
                policy.check_ip(ip(blocked)).is_err(),
                "{blocked} must be blocked"
            );
        }
        for public in ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"] {
            assert!(
                policy.check_ip(ip(public)).is_ok(),
                "{public} must be allowed"
            );
        }
    }

    #[test]
    fn allow_list_opens_specific_ranges_only() {
        let policy = EgressPolicy::strict("127.0.0.1, 10.0.5.0/24, Ollama.");
        assert!(policy.check_ip(ip("127.0.0.1")).is_ok());
        assert!(policy.check_ip(ip("::ffff:127.0.0.1")).is_ok());
        assert!(policy.check_ip(ip("127.0.0.2")).is_err());
        assert!(policy.check_ip(ip("10.0.5.9")).is_ok());
        assert!(policy.check_ip(ip("10.0.6.9")).is_err());
        assert!(policy.host_allowed("ollama"));
        assert!(!policy.host_allowed("other"));
    }

    #[test]
    fn permissive_allows_everything() {
        let policy = EgressPolicy::permissive();
        assert!(policy.check_ip(ip("127.0.0.1")).is_ok());
        assert!(policy.check_ip(ip("169.254.169.254")).is_ok());
    }

    #[test]
    fn check_url_rejects_schemes_and_literal_internal_ips() {
        let policy = EgressPolicy::strict("");
        let check = |u: &str| policy.check_url(&Url::parse(u).unwrap());
        assert!(matches!(
            check("file:///etc/passwd"),
            Err(EgressError::Scheme(_))
        ));
        assert!(matches!(
            check("gopher://example.com"),
            Err(EgressError::Scheme(_))
        ));
        assert!(matches!(
            check("http://169.254.169.254/latest"),
            Err(EgressError::Blocked(_))
        ));
        assert!(matches!(
            check("http://[::1]:8080/"),
            Err(EgressError::Blocked(_))
        ));
        // Decimal and hex forms are normalized by the URL parser.
        assert!(matches!(
            check("http://2130706433/"),
            Err(EgressError::Blocked(_))
        ));
        assert!(matches!(
            check("http://0x7f.1/"),
            Err(EgressError::Blocked(_))
        ));
        assert!(check("https://api.openai.com/v1").is_ok());
    }

    #[test]
    fn resolved_addresses_are_filtered() {
        let policy = EgressPolicy::strict("127.0.0.1");
        let v4: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let v6: SocketAddr = "[::1]:0".parse().unwrap();
        // localhost -> 127.0.0.1 and ::1: only the allowed one is used.
        assert_eq!(
            policy.filter_resolved("localhost", vec![v6, v4]).unwrap(),
            vec![v4]
        );
        let blocked = EgressPolicy::strict("")
            .filter_resolved("localhost", vec![v6, v4])
            .unwrap_err();
        assert!(blocked.to_string().contains("localhost"), "{blocked}");
    }

    #[tokio::test]
    async fn hostnames_are_checked_after_resolution() {
        let err = EgressPolicy::strict("")
            .resolve("localhost", 80)
            .await
            .unwrap_err();
        assert!(matches!(err, EgressError::Blocked(_)), "{err}");
    }

    /// Serves one canned HTTP response per connection on 127.0.0.1.
    async fn serve(response: String) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let response = response.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    let _ = sock.read(&mut buf).await;
                    let _ = sock.write_all(response.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        port
    }

    fn ok_response(body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    #[tokio::test]
    async fn client_blocks_internal_targets_before_sending() {
        let port = serve(ok_response("secret")).await;
        let client = EgressClient::new(EgressPolicy::strict(""));

        let literal = client.get(format!("http://127.0.0.1:{port}/")).unwrap_err();
        assert!(matches!(literal, EgressError::Blocked(_)), "{literal}");

        // Hostnames pass the URL check but fail at resolution.
        let by_name = client
            .get(format!("http://localhost:{port}/"))
            .unwrap()
            .send()
            .await
            .unwrap_err();
        assert!(
            describe(&by_name).contains("localhost (::1) is blocked by the egress policy")
                || describe(&by_name)
                    .contains("localhost (127.0.0.1) is blocked by the egress policy"),
            "{by_name:?}"
        );
    }

    #[tokio::test]
    async fn allow_listed_target_is_reachable() {
        let port = serve(ok_response("hello")).await;
        let client = EgressClient::new(EgressPolicy::strict("127.0.0.1"));
        let resp = client
            .get(format!("http://localhost:{port}/"))
            .unwrap()
            .send()
            .await
            .unwrap();
        assert_eq!(client.read_text(resp).await.unwrap(), "hello");
    }

    #[tokio::test]
    async fn redirects_to_blocked_targets_are_refused() {
        let port = serve(
            "HTTP/1.1 302 Found\r\nlocation: http://169.254.169.254/latest/meta-data/\r\n\
             content-length: 0\r\nconnection: close\r\n\r\n"
                .to_string(),
        )
        .await;
        let client = EgressClient::new(EgressPolicy::strict("127.0.0.1"));
        let err = client
            .get(format!("http://127.0.0.1:{port}/"))
            .unwrap()
            .send()
            .await
            .unwrap_err();
        assert!(err.is_redirect(), "{err:?}");
        assert!(format!("{err:?}").contains("169.254.169.254"), "{err:?}");
    }

    #[tokio::test]
    async fn response_bodies_are_capped() {
        let body = "x".repeat(2000);
        // With and without content-length (chunked-like: read until close).
        let with_len = serve(ok_response(&body)).await;
        let without_len = serve(format!(
            "HTTP/1.1 200 OK\r\nconnection: close\r\n\r\n{body}"
        ))
        .await;
        let client =
            EgressClient::new(EgressPolicy::strict("127.0.0.1").with_max_response_bytes(1000));

        for port in [with_len, without_len] {
            let resp = client
                .get(format!("http://127.0.0.1:{port}/"))
                .unwrap()
                .send()
                .await
                .unwrap();
            let err = client.read_bytes(resp).await.unwrap_err();
            assert!(matches!(err, EgressError::TooLarge(1000)), "{err}");
        }

        let small = serve(ok_response("{\"ok\":true}")).await;
        let resp = client
            .get(format!("http://127.0.0.1:{small}/"))
            .unwrap()
            .send()
            .await
            .unwrap();
        let json: serde_json::Value = client.read_json(resp).await.unwrap();
        assert_eq!(json["ok"], true);
    }
}

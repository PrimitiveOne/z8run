//! Rate limiting middleware for z8run API.
//!
//! Uses an in-memory token bucket algorithm with per-IP tracking.
//! Supports configurable limits for different route tiers:
//!   - General API:  `Z8_RATE_LIMIT_API`   (default: 100 req/min)
//!   - Auth routes:  `Z8_RATE_LIMIT_AUTH`  (default: 20 req/min)
//!   - Webhooks:     `Z8_RATE_LIMIT_HOOK`  (default: 200 req/min)
//!
//! Responds with `429 Too Many Requests` and standard rate-limit headers:
//!   - `X-RateLimit-Limit`     - max requests per window
//!   - `X-RateLimit-Remaining` - requests remaining
//!   - `X-RateLimit-Reset`     - seconds until window resets
//!   - `Retry-After`           - seconds to wait (on 429)

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{HeaderMap, Request, Response, StatusCode},
    middleware::Next,
};
use ipnet::IpNet;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::warn;

/// Bucket state for a single client.
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(max_tokens: f64) -> Self {
        Self {
            tokens: max_tokens,
            last_refill: Instant::now(),
        }
    }

    /// Refill tokens based on elapsed time, then try to consume one.
    /// Returns (allowed, remaining, reset_seconds).
    fn try_consume(&mut self, max_tokens: f64, window_secs: f64) -> (bool, u64, u64) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();

        // Refill at rate: max_tokens / window_secs per second
        let refill_rate = max_tokens / window_secs;
        self.tokens = (self.tokens + elapsed * refill_rate).min(max_tokens);
        self.last_refill = now;

        let _remaining = self.tokens as u64;
        let reset_secs = if self.tokens < max_tokens {
            ((max_tokens - self.tokens) / refill_rate).ceil() as u64
        } else {
            0
        };

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            (true, self.tokens as u64, reset_secs)
        } else {
            let retry_after = ((1.0 - self.tokens) / refill_rate).ceil() as u64;
            (false, 0, retry_after)
        }
    }
}

/// Shared rate limiter state.
#[derive(Clone)]
pub struct RateLimiter {
    buckets: Arc<RwLock<HashMap<String, TokenBucket>>>,
    max_requests: u64,
    window_secs: u64,
    /// When `true`, the limiter is disabled and every request is allowed.
    /// Set when `max_requests == 0` (see `.env.example`: "Set 0 to disable").
    disabled: bool,
}

impl RateLimiter {
    pub fn new(max_requests: u64, window_secs: u64) -> Self {
        // A configured capacity of 0 means "unlimited / disabled" rather than
        // "block everything". Short-circuit checks and skip the cleanup task.
        let disabled = max_requests == 0;

        let limiter = Self {
            buckets: Arc::new(RwLock::new(HashMap::new())),
            max_requests,
            window_secs,
            disabled,
        };

        if disabled {
            tracing::info!("Rate limiter disabled (max_requests = 0); all requests allowed");
            return limiter;
        }

        // Spawn cleanup task to evict stale entries every 5 minutes
        let buckets = Arc::clone(&limiter.buckets);
        let ws = window_secs;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300));
            loop {
                interval.tick().await;
                let mut map = buckets.write().await;
                let stale_threshold = Duration::from_secs(ws * 2);
                let now = Instant::now();
                map.retain(|_, bucket| now.duration_since(bucket.last_refill) < stale_threshold);
            }
        });

        limiter
    }

    /// Check rate limit for a given key. Returns (allowed, remaining, reset_secs).
    async fn check(&self, key: &str) -> (bool, u64, u64) {
        // Disabled limiter (max_requests == 0): always allow, never touch state.
        if self.disabled {
            return (true, 0, 0);
        }

        let mut buckets = self.buckets.write().await;
        let max = self.max_requests as f64;
        let window = self.window_secs as f64;

        let bucket = buckets
            .entry(key.to_string())
            .or_insert_with(|| TokenBucket::new(max));

        bucket.try_consume(max, window)
    }
}

/// Private and loopback ranges trusted by default when `Z8_TRUST_PROXY` is on
/// and `Z8_TRUSTED_PROXIES` is unset: a reverse proxy on the same host or on a
/// Docker/VPC network.
const DEFAULT_TRUSTED_PROXIES: &[&str] = &[
    "127.0.0.0/8",
    "::1/128",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "fc00::/7",
];

/// Which peers may set the client address through forwarded headers (A-08).
///
/// `X-Forwarded-For` is only honored when the TCP peer is a trusted proxy, and
/// it is read right to left: every hop that is itself a trusted proxy is
/// skipped and the first untrusted address is the client. Anything a client
/// prepends to the header sits left of that point and is ignored, so it cannot
/// be used to rotate identities or to push its quota onto someone else.
#[derive(Debug, Clone, Default)]
pub struct ProxyTrust {
    trusted: Vec<IpNet>,
}

impl ProxyTrust {
    /// Reads `Z8_TRUST_PROXY` and `Z8_TRUSTED_PROXIES`.
    ///
    /// Trust is off unless `Z8_TRUST_PROXY` is truthy ("1", "true", "yes").
    /// `Z8_TRUSTED_PROXIES` is a comma-separated list of IPs or CIDRs; when it
    /// is unset or empty, [`DEFAULT_TRUSTED_PROXIES`] is used.
    pub fn from_env() -> Self {
        let enabled = std::env::var("Z8_TRUST_PROXY")
            .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false);
        if !enabled {
            return Self::default();
        }
        let configured = std::env::var("Z8_TRUSTED_PROXIES").unwrap_or_default();
        let list = if configured.trim().is_empty() {
            DEFAULT_TRUSTED_PROXIES.join(",")
        } else {
            configured
        };
        Self::parse(&list)
    }

    /// Parses a comma-separated list of IPs or CIDRs, skipping invalid entries.
    pub fn parse(list: &str) -> Self {
        let trusted = list
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .filter_map(|entry| {
                entry
                    .parse::<IpNet>()
                    .or_else(|_| entry.parse::<IpAddr>().map(IpNet::from))
                    .map_err(|_| warn!(entry, "Skipping invalid trusted proxy entry"))
                    .ok()
            })
            .collect();
        Self { trusted }
    }

    fn is_trusted(&self, ip: IpAddr) -> bool {
        self.trusted.iter().any(|net| net.contains(&ip))
    }
}

/// Extract the client IP used as the rate-limit bucket key.
///
/// Forwarded headers are consulted only when the TCP peer is a trusted proxy
/// (see [`ProxyTrust`]); otherwise the peer address is the client. Falls back
/// to `"unknown"` when no peer address is available, rather than panicking.
fn extract_client_ip(headers: &HeaderMap, peer: Option<SocketAddr>, trust: &ProxyTrust) -> String {
    let Some(peer) = peer else {
        return "unknown".to_string();
    };
    let peer_ip = peer.ip().to_canonical();
    if !trust.is_trusted(peer_ip) {
        return peer_ip.to_string();
    }

    // Multiple X-Forwarded-For headers form one list, in order.
    let forwarded: Vec<&str> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();

    if forwarded.is_empty() {
        // A trusted proxy that only sets X-Real-IP.
        return headers
            .get("x-real-ip")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<IpAddr>().ok())
            .map(|ip| ip.to_canonical())
            .unwrap_or(peer_ip)
            .to_string();
    }

    // Walk from the nearest hop outward. An unparsable entry ends the walk:
    // nothing left of it was vouched for by a trusted proxy.
    let mut client = peer_ip;
    for entry in forwarded.iter().rev() {
        let Ok(ip) = entry.parse::<IpAddr>() else {
            break;
        };
        client = ip.to_canonical();
        if !trust.is_trusted(client) {
            break;
        }
    }
    client.to_string()
}

/// Build a 429 Too Many Requests response with proper headers.
fn too_many_requests(limit: u64, reset_secs: u64) -> Response<Body> {
    let body = serde_json::json!({
        "error": "Too Many Requests",
        "message": "Rate limit exceeded. Please try again later.",
        "retryAfter": reset_secs,
    });

    let mut resp = Response::new(Body::from(body.to_string()));
    *resp.status_mut() = StatusCode::TOO_MANY_REQUESTS;

    let headers = resp.headers_mut();
    headers.insert("content-type", "application/json".parse().unwrap());
    headers.insert("x-ratelimit-limit", limit.to_string().parse().unwrap());
    headers.insert("x-ratelimit-remaining", "0".parse().unwrap());
    headers.insert("x-ratelimit-reset", reset_secs.to_string().parse().unwrap());
    headers.insert("retry-after", reset_secs.to_string().parse().unwrap());

    resp
}

/// Append rate-limit headers to a successful response.
fn append_rate_headers(resp: &mut Response<Body>, limit: u64, remaining: u64, reset_secs: u64) {
    let headers = resp.headers_mut();
    headers.insert("x-ratelimit-limit", limit.to_string().parse().unwrap());
    headers.insert(
        "x-ratelimit-remaining",
        remaining.to_string().parse().unwrap(),
    );
    headers.insert("x-ratelimit-reset", reset_secs.to_string().parse().unwrap());
}

/// Rate limit middleware for general API routes.
///
/// Default: 100 requests per 60 seconds per IP.
pub async fn api_rate_limit(req: Request<Body>, next: Next) -> Response<Body> {
    rate_limit_inner(req, next, api_limiter()).await
}

/// Rate limit middleware for auth routes (stricter).
///
/// Default: 20 requests per 60 seconds per IP.
pub async fn auth_rate_limit(req: Request<Body>, next: Next) -> Response<Body> {
    rate_limit_inner(req, next, auth_limiter()).await
}

/// Rate limit middleware for webhook/hook routes.
///
/// Default: 200 requests per 60 seconds per IP.
pub async fn hook_rate_limit(req: Request<Body>, next: Next) -> Response<Body> {
    rate_limit_inner(req, next, hook_limiter()).await
}

async fn rate_limit_inner(req: Request<Body>, next: Next, limiter: &RateLimiter) -> Response<Body> {
    // Peer address is injected as a `ConnectInfo` extension when the server is
    // started with `into_make_service_with_connect_info::<SocketAddr>()`.
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0);
    let client_ip = extract_client_ip(req.headers(), peer, proxy_trust());
    let (allowed, remaining, reset_secs) = limiter.check(&client_ip).await;

    if !allowed {
        warn!(
            ip = %client_ip,
            limit = limiter.max_requests,
            "Rate limit exceeded"
        );
        return too_many_requests(limiter.max_requests, reset_secs);
    }

    let mut response = next.run(req).await;
    append_rate_headers(&mut response, limiter.max_requests, remaining, reset_secs);
    response
}

// ── Global limiter singletons ───────────────────────────────

use std::sync::OnceLock;

static API_LIMITER: OnceLock<RateLimiter> = OnceLock::new();
static AUTH_LIMITER: OnceLock<RateLimiter> = OnceLock::new();
static HOOK_LIMITER: OnceLock<RateLimiter> = OnceLock::new();
static PROXY_TRUST: OnceLock<ProxyTrust> = OnceLock::new();

/// Initialize rate limiters from environment variables.
/// Call once at startup before building the router.
pub fn init_rate_limiters() {
    let api_max = std::env::var("Z8_RATE_LIMIT_API")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100u64);

    let auth_max = std::env::var("Z8_RATE_LIMIT_AUTH")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20u64);

    let hook_max = std::env::var("Z8_RATE_LIMIT_HOOK")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200u64);

    let window = std::env::var("Z8_RATE_LIMIT_WINDOW")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60u64);

    let _ = API_LIMITER.set(RateLimiter::new(api_max, window));
    let _ = AUTH_LIMITER.set(RateLimiter::new(auth_max, window));
    let _ = HOOK_LIMITER.set(RateLimiter::new(hook_max, window));
    let trust = PROXY_TRUST.get_or_init(ProxyTrust::from_env);

    tracing::info!(
        api = api_max,
        auth = auth_max,
        hook = hook_max,
        window_secs = window,
        trusted_proxies = ?trust.trusted,
        "Rate limiters initialized"
    );
}

fn proxy_trust() -> &'static ProxyTrust {
    PROXY_TRUST.get_or_init(ProxyTrust::from_env)
}

fn api_limiter() -> &'static RateLimiter {
    API_LIMITER
        .get()
        .expect("Rate limiters not initialized - call init_rate_limiters() first")
}

fn auth_limiter() -> &'static RateLimiter {
    AUTH_LIMITER
        .get()
        .expect("Rate limiters not initialized - call init_rate_limiters() first")
}

fn hook_limiter() -> &'static RateLimiter {
    HOOK_LIMITER
        .get()
        .expect("Rate limiters not initialized - call init_rate_limiters() first")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_bucket_allows_within_limit() {
        let mut bucket = TokenBucket::new(5.0);
        for _ in 0..5 {
            let (allowed, _, _) = bucket.try_consume(5.0, 60.0);
            assert!(allowed);
        }
        // 6th request should be denied
        let (allowed, _, _) = bucket.try_consume(5.0, 60.0);
        assert!(!allowed);
    }

    #[test]
    fn token_bucket_returns_correct_remaining() {
        let mut bucket = TokenBucket::new(10.0);
        let (allowed, remaining, _) = bucket.try_consume(10.0, 60.0);
        assert!(allowed);
        assert_eq!(remaining, 9);

        let (allowed, remaining, _) = bucket.try_consume(10.0, 60.0);
        assert!(allowed);
        assert_eq!(remaining, 8);
    }

    #[tokio::test]
    async fn rate_limiter_tracks_separate_keys() {
        let limiter = RateLimiter::new(2, 60);

        let (ok1, _, _) = limiter.check("ip-a").await;
        let (ok2, _, _) = limiter.check("ip-b").await;
        let (ok3, _, _) = limiter.check("ip-a").await;
        let (ok4, _, _) = limiter.check("ip-a").await; // should be denied
        let (ok5, _, _) = limiter.check("ip-b").await; // should still pass

        assert!(ok1);
        assert!(ok2);
        assert!(ok3);
        assert!(!ok4);
        assert!(ok5);
    }

    #[tokio::test]
    async fn zero_max_requests_disables_limiter() {
        // Per .env.example, Z8_RATE_LIMIT_* = 0 disables rate limiting.
        // The limiter must allow every request instead of blocking all of them.
        let limiter = RateLimiter::new(0, 60);

        for _ in 0..1000 {
            let (allowed, _, reset) = limiter.check("ip-a").await;
            assert!(allowed, "disabled limiter must always allow requests");
            assert_eq!(reset, 0, "disabled limiter must not emit retry-after");
        }
    }

    fn peer(addr: &str) -> Option<SocketAddr> {
        Some(addr.parse().unwrap())
    }

    fn xff(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", value.parse().unwrap());
        headers
    }

    fn private_ranges() -> ProxyTrust {
        ProxyTrust::parse(&DEFAULT_TRUSTED_PROXIES.join(","))
    }

    #[test]
    fn trust_disabled_ignores_forwarded_headers() {
        // Default (Z8_TRUST_PROXY off): spoofed headers never change the key.
        let mut headers = xff("9.9.9.9");
        headers.insert("x-real-ip", "8.8.8.8".parse().unwrap());
        let ip = extract_client_ip(&headers, peer("203.0.113.7:5555"), &ProxyTrust::default());
        assert_eq!(ip, "203.0.113.7");
    }

    #[test]
    fn untrusted_peer_ignores_forwarded_headers() {
        // Trust is on, but the peer is not a proxy we know: a client hitting
        // the backend directly cannot choose its own key.
        let ip = extract_client_ip(&xff("9.9.9.9"), peer("203.0.113.7:5555"), &private_ranges());
        assert_eq!(ip, "203.0.113.7");
    }

    #[test]
    fn appending_proxy_uses_rightmost_untrusted_hop() {
        // Nginx with $proxy_add_x_forwarded_for appends the real client after
        // whatever the client sent. The spoofed left entry must be ignored.
        let headers = xff("6.6.6.6, 198.51.100.4");
        let ip = extract_client_ip(&headers, peer("172.18.0.3:40000"), &private_ranges());
        assert_eq!(ip, "198.51.100.4");
    }

    #[test]
    fn overwriting_proxy_uses_the_single_entry() {
        let ip = extract_client_ip(
            &xff("198.51.100.4"),
            peer("172.18.0.3:40000"),
            &private_ranges(),
        );
        assert_eq!(ip, "198.51.100.4");
    }

    #[test]
    fn chained_trusted_proxies_are_skipped() {
        // CDN -> nginx -> backend with the CDN range listed as trusted.
        let trust = ProxyTrust::parse("172.16.0.0/12, 173.245.48.0/20");
        let headers = xff("6.6.6.6, 198.51.100.4, 173.245.48.10");
        let ip = extract_client_ip(&headers, peer("172.18.0.3:40000"), &trust);
        assert_eq!(ip, "198.51.100.4");
    }

    #[test]
    fn garbage_entry_stops_the_walk() {
        let headers = xff("198.51.100.4, not-an-ip, 10.0.0.2");
        let ip = extract_client_ip(&headers, peer("172.18.0.3:40000"), &private_ranges());
        assert_eq!(ip, "10.0.0.2");
    }

    #[test]
    fn trusted_peer_without_xff_uses_x_real_ip_then_peer() {
        let mut headers = HeaderMap::new();
        let trust = private_ranges();
        assert_eq!(
            extract_client_ip(&headers, peer("127.0.0.1:1"), &trust),
            "127.0.0.1"
        );
        headers.insert("x-real-ip", "198.51.100.4".parse().unwrap());
        assert_eq!(
            extract_client_ip(&headers, peer("127.0.0.1:1"), &trust),
            "198.51.100.4"
        );
    }

    #[test]
    fn ipv4_mapped_peer_matches_ipv4_ranges() {
        // Dual-stack listeners report IPv4 peers as ::ffff:a.b.c.d.
        let ip = extract_client_ip(
            &xff("198.51.100.4"),
            peer("[::ffff:172.18.0.3]:40000"),
            &private_ranges(),
        );
        assert_eq!(ip, "198.51.100.4");
    }

    #[test]
    fn parse_accepts_bare_ips_and_skips_invalid_entries() {
        let trust = ProxyTrust::parse("10.1.2.3, bogus, 2001:db8::/32");
        assert_eq!(trust.trusted.len(), 2);
        assert!(trust.is_trusted("10.1.2.3".parse().unwrap()));
        assert!(!trust.is_trusted("10.1.2.4".parse().unwrap()));
        assert!(trust.is_trusted("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn missing_peer_falls_back_to_unknown() {
        let ip = extract_client_ip(&xff("9.9.9.9"), None, &private_ranges());
        assert_eq!(ip, "unknown");
    }

    #[test]
    fn env_defaults_are_reasonable() {
        // Verify the default limits are positive
        let api = 100u64;
        let auth = 20u64;
        let hook = 200u64;
        assert!(api > 0);
        assert!(auth > 0);
        assert!(hook > 0);
    }
}

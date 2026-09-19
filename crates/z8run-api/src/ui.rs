//! Web editor served from the binary (feature `embed-ui`).
//!
//! Docker deployments serve the UI from Nginx. A standalone binary has no
//! Nginx, so with `embed-ui` the built frontend is compiled in (see
//! `build.rs`) and answered by the router's fallback, with the same security
//! headers `deploy/nginx.conf` sets.

// Without the feature only the tests exercise the serving logic.
#![cfg_attr(not(feature = "embed-ui"), allow(dead_code))]

use axum::body::Body;
use axum::http::{header, HeaderValue, Method, Response, StatusCode};

#[cfg(feature = "embed-ui")]
mod embedded {
    include!(concat!(env!("OUT_DIR"), "/ui_assets.rs"));
}

/// Same policy as the SPA block in `deploy/nginx.conf`.
const CSP: &str = "default-src 'self'; connect-src 'self' ws: wss:; img-src 'self' data:; \
                   style-src 'self' 'unsafe-inline'; script-src 'self'; font-src 'self' data:; \
                   base-uri 'self'; frame-ancestors 'self'";

/// Server routes; unmatched paths under them are API 404s, never the SPA.
const API_PREFIXES: &[&str] = &["/api", "/auth", "/hook", "/ws"];

/// Router fallback serving the embedded UI.
#[cfg(feature = "embed-ui")]
pub async fn serve(req: axum::http::Request<Body>) -> Response<Body> {
    respond(embedded::ASSETS, req.method(), req.uri().path())
}

/// Whether this binary carries the web UI.
pub const fn is_embedded() -> bool {
    cfg!(feature = "embed-ui")
}

/// Assets are `(path, bytes)`, compiled into the binary.
type Assets = &'static [(&'static str, &'static [u8])];

fn respond(assets: Assets, method: &Method, path: &str) -> Response<Body> {
    let is_api = API_PREFIXES.iter().any(|p| {
        path == *p
            || path
                .strip_prefix(p)
                .is_some_and(|rest| rest.starts_with('/'))
    });
    if is_api || !(method == Method::GET || method == Method::HEAD) {
        return status(StatusCode::NOT_FOUND);
    }

    let wanted = match path.trim_start_matches('/') {
        "" => "index.html",
        p => p,
    };
    let find = |name: &str| assets.iter().find(|(p, _)| *p == name);
    // Client-side routes (/flows/123) get the app shell; missing files
    // (anything with an extension) stay 404 so broken asset links show.
    let last_segment = wanted.rsplit('/').next().unwrap_or(wanted);
    let (name, bytes) = match find(wanted) {
        Some(found) => *found,
        None if !last_segment.contains('.') => match find("index.html") {
            Some(found) => *found,
            None => return status(StatusCode::NOT_FOUND),
        },
        None => return status(StatusCode::NOT_FOUND),
    };

    let body = if method == Method::HEAD {
        Body::empty()
    } else {
        Body::from(bytes)
    };
    let mut resp = Response::new(body);
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(content_type(name)),
    );
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(bytes.len()));
    // Vite fingerprints everything under assets/, so it never changes.
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(if name.starts_with("assets/") {
            "public, max-age=31536000, immutable"
        } else {
            "no-cache"
        }),
    );
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CSP),
    );
    h.insert(
        header::X_FRAME_OPTIONS,
        HeaderValue::from_static("SAMEORIGIN"),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    resp
}

fn status(code: StatusCode) -> Response<Body> {
    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = code;
    resp
}

fn content_type(name: &str) -> &'static str {
    match name.rsplit_once('.').map(|(_, ext)| ext) {
        Some("html") => "text/html; charset=utf-8",
        Some("js" | "mjs") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json" | "map") => "application/json",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("ico") => "image/x-icon",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        Some("ttf") => "font/ttf",
        Some("txt") => "text/plain; charset=utf-8",
        Some("wasm") => "application/wasm",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ASSETS: &[(&str, &[u8])] = &[
        ("index.html", b"<html>shell</html>"),
        ("assets/index-abc.js", b"console.log(1)"),
        ("z8run-icon.svg", b"<svg/>"),
    ];

    fn get(path: &str) -> Response<Body> {
        respond(ASSETS, &Method::GET, path)
    }

    async fn body(resp: Response<Body>) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn serves_files_with_type_and_cache_policy() {
        let root = get("/");
        assert_eq!(root.status(), StatusCode::OK);
        assert_eq!(
            root.headers()[header::CONTENT_TYPE],
            "text/html; charset=utf-8"
        );
        assert_eq!(root.headers()[header::CACHE_CONTROL], "no-cache");
        assert_eq!(body(root).await, "<html>shell</html>");

        let js = get("/assets/index-abc.js");
        assert_eq!(
            js.headers()[header::CONTENT_TYPE],
            "text/javascript; charset=utf-8"
        );
        assert!(js.headers()[header::CACHE_CONTROL]
            .to_str()
            .unwrap()
            .contains("immutable"));
        assert_eq!(
            get("/z8run-icon.svg").headers()[header::CONTENT_TYPE],
            "image/svg+xml"
        );
    }

    #[tokio::test]
    async fn client_routes_get_the_shell_but_missing_files_404() {
        let route = get("/flows/01a0b6e5");
        assert_eq!(route.status(), StatusCode::OK);
        assert_eq!(body(route).await, "<html>shell</html>");

        assert_eq!(get("/assets/missing.js").status(), StatusCode::NOT_FOUND);
        assert_eq!(get("/favicon.ico").status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn server_routes_are_never_answered_with_the_shell() {
        for path in [
            "/api",
            "/api/v1/nope",
            "/auth/x",
            "/hook/abc/def",
            "/ws/engine",
        ] {
            assert_eq!(get(path).status(), StatusCode::NOT_FOUND, "{path}");
        }
        // Only exact prefixes: an app route that merely starts with "api" is fine.
        assert_eq!(get("/apis-overview").status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn only_get_and_head_and_security_headers_are_set() {
        assert_eq!(
            respond(ASSETS, &Method::POST, "/").status(),
            StatusCode::NOT_FOUND
        );
        let head = respond(ASSETS, &Method::HEAD, "/");
        assert_eq!(head.status(), StatusCode::OK);
        assert_eq!(head.headers()[header::CONTENT_LENGTH], "18");
        let h = head.headers().clone();
        assert_eq!(body(head).await, "");

        assert!(h[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .contains("script-src 'self'"));
        assert_eq!(h[header::X_FRAME_OPTIONS], "SAMEORIGIN");
        assert_eq!(h[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    }
}

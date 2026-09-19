//! # z8run-api
//!
//! z8run HTTP and WebSocket server.
//! Exposes REST API for flow management
//! and WebSockets for real-time communication.

pub mod auth;
pub mod error;
pub mod execution_recorder;
pub mod hook_limits;
pub mod rate_limit;
pub mod routes;
pub mod state;
pub mod ui;
pub mod ws;

use axum::http::{header, HeaderValue, Method};
use axum::Router;
use std::sync::Arc;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;

use state::AppState;

/// Builds the CORS layer for the API.
///
/// Reads a comma-separated allow-list of origins from the `Z8_CORS_ORIGINS`
/// environment variable (e.g. `https://app.example.com,https://admin.example.com`).
///
/// - When set and non-empty, CORS is restricted to exactly those origins.
///   Invalid entries are skipped with a warning. A restricted origin list
///   makes credentialed requests safe, so `allow_credentials(true)` is enabled.
/// - When unset or empty, it falls back to the previous permissive policy so
///   local development is not broken, emitting a warning so this is never used
///   in production without noticing.
fn build_cors_layer() -> CorsLayer {
    let origins: Vec<HeaderValue> = std::env::var("Z8_CORS_ORIGINS")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|origin| match origin.parse::<HeaderValue>() {
            Ok(value) => Some(value),
            Err(_) => {
                tracing::warn!(origin = origin, "Skipping invalid CORS origin");
                None
            }
        })
        .collect();

    if origins.is_empty() {
        tracing::warn!("CORS is permissive (no Z8_CORS_ORIGINS set); set it in production");
        return CorsLayer::permissive();
    }

    CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
        .allow_credentials(true)
}

/// Builds the main application router.
pub fn build_router(state: Arc<AppState>) -> Router {
    // Initialize rate limiters from env vars
    rate_limit::init_rate_limiters();

    // Protected API routes with JWT middleware + API rate limit
    let protected_api = routes::api_routes().layer(axum::middleware::from_fn_with_state(
        state.clone(),
        auth::jwt_middleware,
    ));

    // Auth routes: public (/register, /login) + protected (/me)
    // Auth routes get stricter rate limiting
    let auth_router = auth::auth_routes().merge(auth::auth_protected_routes().layer(
        axum::middleware::from_fn_with_state(state.clone(), auth::jwt_middleware),
    ));

    // Public API routes (health, info) - no auth required
    let public_api = routes::public_routes();

    let router = Router::new()
        .nest(
            "/api/v1",
            protected_api
                .merge(public_api)
                .layer(axum::middleware::from_fn(rate_limit::api_rate_limit)),
        )
        .nest(
            "/auth",
            auth_router.layer(axum::middleware::from_fn(rate_limit::auth_rate_limit)),
        )
        .nest(
            "/hook",
            routes::hook_routes()
                // Public entry point: cap the body explicitly (A-06); larger
                // requests get 413 before the handler runs.
                .layer(axum::extract::DefaultBodyLimit::max(
                    state.hook_limits.max_body_bytes,
                ))
                .layer(axum::middleware::from_fn(rate_limit::hook_rate_limit)),
        )
        .nest("/ws", ws::ws_routes());

    // Standalone binaries serve the web editor themselves (Docker uses Nginx).
    #[cfg(feature = "embed-ui")]
    let router = router.fallback(ui::serve);

    router
        .layer(build_cors_layer())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

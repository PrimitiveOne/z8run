# Changelog

All notable changes to z8run are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/) and this project adheres to [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Added
- Standalone binary with the web editor built in (`--features embed-ui`), released for Windows x86_64, macOS arm64 and Linux x86_64 (#78)
- Desktop mode: running `z8run` with no subcommand serves on `127.0.0.1`, keeps data in the per-user folder and opens the browser
- `z8run init` to choose SQLite or PostgreSQL and the port, checked before saving to `<data dir>/z8run.env`
- Outbound (egress) policy for flow nodes: `Z8_EGRESS_POLICY`, `Z8_EGRESS_ALLOW`, `Z8_EGRESS_MAX_RESPONSE_BYTES`
- Database node limits: `Z8_DB_SQLITE_DIR`, `Z8_DB_QUERY_TIMEOUT_SECS`, `Z8_DB_MAX_ROWS`
- Webhook limits: `Z8_HOOK_MAX_BODY_BYTES`, `Z8_HOOK_MAX_CONCURRENCY`, `Z8_HOOK_TIMEOUT_SECS`
- `Z8_TRUSTED_PROXIES` for client IP resolution behind reverse proxies
- Release workflow takes a version tag and builds Windows; CI tests the CLI on Windows

### Changed
- Without `Z8_JWT_SECRET`/`Z8_VAULT_SECRET`, generated secrets are kept in `<data dir>/secrets/` instead of changing on every start
- Nginx overwrites `X-Forwarded-For`; `deploy/nginx.conf` documents direct and Cloudflare setups
- **Deployed hook flows must be redeployed** after upgrading (hooks now run a deployed snapshot)
- The editor no longer loads fonts from Google Fonts

### Fixed
- Restarting a SQLite install logged everyone out and made vault credentials unreadable
- Stop button disabled for deployed hook flows; "(unsaved)" shown right after opening a flow
- Release builds on macOS 27 (proc-macros were stripped)
- Default SQLite path containing `%`, `?` or `#`

### Security
- Webhooks are bound to their trigger node and deployed snapshot, run only that branch, and reject unknown auth types (A-01, A-05)
- Stopping a flow checks ownership and takes its hooks offline (A-02)
- Flow nodes can no longer reach loopback, private or cloud-metadata addresses by default; the database node is confined (A-03, A-04)
- Webhook body size, concurrency and time are bounded, and timed-out executions are cancelled (A-06)
- UTF-8 panics in previews and masking (A-07)
- Rate limiting can no longer be bypassed with a spoofed `X-Forwarded-For` (A-08)
- The session JWT is no longer returned in auth response bodies, and execution previews redact secrets (A-09)
- WASM plugins run with a CPU budget, a time limit and an enforced memory cap (`Z8_PLUGIN_FUEL`, `Z8_PLUGIN_TIMEOUT_MS`, `Z8_PLUGIN_MAX_MEMORY_MB`), off the async runtime; a manifest can no longer raise its own memory limit (A-10)

### Removed
- `bins/z8run-server` placeholder, superseded by `--features embed-ui`

---

## [0.2.0] - 2026-04-01

### Added
- Per-crate README.md files with documentation for crates.io
- Crate metadata: keywords, categories, homepage, repository for all 6 crates
- PR template, feature request template, and CODEOWNERS
- `.editorconfig` and `.node-version` for cross-editor consistency
- Docker targets in Makefile (`docker-build`, `docker-up`, `docker-down`, `setup`)
- Demo GIF in README with comparison table vs Node-RED and n8n
- Ko-fi sponsorship, GitHub Discussions welcome post
- `LICENSE` root file (MIT full text) for GitHub license detection

### Fixed
- All CodeQL security alerts: HTTPS-only clients, API keys in headers, prototype pollution guard
- Security patches: `aws-lc-sys` 0.39.1, `rustls-webpki` 0.103.10
- Biome lint/format errors across frontend
- `rust-version` MSRV corrected from 1.75 to 1.91
- All `pnpm` references changed to `npm`
- Node.js updated from 20 to 22 LTS
- Docker image `unknown/unknown` platform fixed with `provenance: false`
- jscpd threshold raised from 5% to 15%

### Changed
- Dependabot: groups patches/minor, ignores major versions, weekly on Monday
- Deploy workflow: concurrency, environment protection, SSH cleanup, scoped image pruning
- GitHub Actions updated to latest versions (setup-node v6, cache v5, etc.)
- CI and Code Quality run only on PRs, not push to main
- Branch protection: required checks, code owner reviews
- crates.io publish: version check, skip-if-published, 3 retries
- Repo topics optimized for discoverability (20 topics)

### Removed
- Redundant `LICENSE-MIT` (MIT text now in `LICENSE`)
- Manual SHA-256 implementation (replaced by `sha2` crate)
- 26 stale Dependabot PRs (merged safe ones, closed breaking ones)

---

## [0.1.0] - 2026-03-06

Initial release of z8run.

### Core Engine
- Flow engine with DAG validation and topological scheduling
- 23 built-in nodes across 6 categories (Input, Process, Output, Logic, Data, AI)
- Binary WebSocket protocol (11-byte header) for real-time editor sync
- WASM plugin sandbox using wasmtime with capability controls

### Nodes
- **Input:** HTTP In, Timer, Webhook (HMAC-SHA256 validation)
- **Process:** Function, JSON Transform, HTTP Request, Filter
- **Output:** Debug, HTTP Response
- **Logic:** Switch (multi-rule routing), Delay
- **Data:** Database (PostgreSQL, MySQL, SQLite), MQTT (publish/subscribe with TLS)
- **AI:** LLM, Embeddings, Classifier, Prompt Template, Text Splitter, Vector Store, Structured Output, Summarizer, AI Agent, Image Gen

### API & Server
- REST API with Axum 0.8 (flows CRUD, start/stop execution, health, info)
- WebSocket engine at `/ws/engine`
- Namespaced webhook routes (`/hook/{flow_id}/{path}`)
- JWT authentication with argon2 password hashing
- AES-256-GCM encrypted credential vault

### Storage
- SQLite persistence (embedded, zero-config for development)
- PostgreSQL persistence (recommended for production)
- Flow import/export (JSON)

### Frontend
- Visual node editor with React Flow + Zustand + Tailwind CSS
- Drag-and-drop node palette with 6 categories
- Smart config UI (dropdowns, password fields, code editors)
- Flow management (list, create, delete, deploy, stop)
- Credential vault UI
- Real-time execution log with payload tracing

### Deployment
- Docker multi-stage build (Rust 1.91 + Node.js)
- Docker Compose with PostgreSQL
- Nginx reverse proxy with WebSocket support
- Cloudflare DNS integration (Flexible SSL)

---

[Unreleased]: https://github.com/z8run/z8run/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/z8run/z8run/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/z8run/z8run/releases/tag/v0.1.0

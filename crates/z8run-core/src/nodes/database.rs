//! Database node: executes SQL queries against multiple database backends.
//!
//! Supports PostgreSQL, MySQL, SQLite, and SQL Server via connection configuration.
//! Parameters can be extracted from the message payload using dot-notation paths.
//!
//! Config example (individual fields):
//! ```json
//! {
//!   "dbType": "postgres",
//!   "host": "db.example.com",
//!   "port": 5432,
//!   "database": "myapp",
//!   "user": "admin",
//!   "password": "secret",
//!   "query": "SELECT * FROM users WHERE age > $1",
//!   "params": ["req.body.min_age"]
//! }
//! ```
//!
//! Or via direct connection string:
//! ```json
//! {
//!   "connectionString": "postgres://admin:secret@db.example.com/myapp",
//!   "query": "SELECT * FROM users"
//! }
//! ```
//!
//! Limits (A-04), applied to every backend:
//! - The server must pass the egress policy (`Z8_EGRESS_POLICY`,
//!   `Z8_EGRESS_ALLOW`); in strict mode Unix sockets are refused.
//! - SQLite files must live under `Z8_DB_SQLITE_DIR` in strict mode (only
//!   in-memory databases when it is unset), and `ATTACH`/`VACUUM` are refused
//!   so a query cannot open or write other files.
//! - Queries time out after `Z8_DB_QUERY_TIMEOUT_SECS` (default 30) and return
//!   at most `Z8_DB_MAX_ROWS` rows (default 1000, `truncated: true` beyond).

use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::LazyLock;
use std::time::Duration;

use crate::egress::EgressMode;
use crate::engine::NodeExecutor;
use crate::error::Z8Result;
use crate::message::FlowMessage;
use crate::node_factory;
use crate::utils::node_helpers::require_non_empty;
use futures_util::{Stream, TryStreamExt};
use serde_json::Value;
use tracing::{debug, error};

use super::switch::json_path_lookup;

/// Limits for database access from flows (A-04).
struct DbLimits {
    query_timeout: Duration,
    max_rows: usize,
    sqlite_dir: Option<PathBuf>,
}

static LIMITS: LazyLock<DbLimits> = LazyLock::new(|| {
    fn positive<T: FromStr + PartialOrd + Default>(var: &str, default: T) -> T {
        std::env::var(var)
            .ok()
            .and_then(|v| v.trim().parse::<T>().ok())
            .filter(|v| *v > T::default())
            .unwrap_or(default)
    }
    DbLimits {
        query_timeout: Duration::from_secs(positive("Z8_DB_QUERY_TIMEOUT_SECS", 30)),
        max_rows: positive("Z8_DB_MAX_ROWS", 1000),
        sqlite_dir: std::env::var("Z8_DB_SQLITE_DIR")
            .ok()
            .filter(|d| !d.trim().is_empty())
            .map(PathBuf::from),
    }
});

fn strict() -> bool {
    crate::egress::client().policy().mode() == EgressMode::Strict
}

/// Checks a network database server against the egress policy.
async fn check_server(host: &str, port: u16, socket: Option<&PathBuf>) -> Result<(), String> {
    if socket.is_some() || host.starts_with('/') {
        return if strict() {
            Err("Unix socket connections are blocked by the egress policy".to_string())
        } else {
            Ok(())
        };
    }
    crate::egress::check_host(host, port)
        .await
        .map_err(|e| e.to_string())
}

/// Where a SQLite connection string points.
fn sqlite_target(conn_str: &str) -> Result<Option<PathBuf>, String> {
    let opts = sqlx::sqlite::SqliteConnectOptions::from_str(conn_str)
        .map_err(|e| format!("Invalid SQLite connection string: {e}"))?;
    let file = opts.get_filename();
    // sqlx names in-memory databases `file:sqlx-in-memory-<n>`.
    if file.to_string_lossy().starts_with("file:sqlx-in-memory-") {
        return Ok(None);
    }
    Ok(Some(file.to_path_buf()))
}

/// In strict mode a SQLite file must resolve inside `sandbox`, which keeps
/// flows away from z8run's own database and any other file on the server.
fn check_sqlite_path(file: &Path, sandbox: Option<&Path>) -> Result<(), String> {
    let refuse = || "SQLite files are limited to Z8_DB_SQLITE_DIR by the egress policy".to_string();
    let sandbox = sandbox
        .and_then(|d| d.canonicalize().ok())
        .ok_or_else(refuse)?;
    if !file.is_absolute() {
        return Err(refuse());
    }
    // The file may not exist yet (mode=rwc): resolve its directory instead.
    let resolved = match file.canonicalize() {
        Ok(path) => path,
        Err(_) => {
            let parent = file.parent().ok_or_else(refuse)?;
            let name = file.file_name().ok_or_else(refuse)?;
            parent.canonicalize().map_err(|_| refuse())?.join(name)
        }
    };
    if resolved.starts_with(&sandbox) {
        Ok(())
    } else {
        Err(refuse())
    }
}

/// `ATTACH` opens another database file and `VACUUM INTO` writes one; both
/// would step outside the sandboxed path.
fn check_sqlite_query(query: &str) -> Result<(), String> {
    static FILE_STATEMENTS: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"(?i)\b(attach|vacuum)\b").unwrap());
    if FILE_STATEMENTS.is_match(query) {
        Err("ATTACH and VACUUM are not allowed in SQLite queries".to_string())
    } else {
        Ok(())
    }
}

/// Why [`collect_rows`] failed.
enum RowsError {
    /// Driver error; logged, not returned to the flow.
    Db(sqlx::Error),
    TimedOut(Duration),
}

impl RowsError {
    /// What the flow sees on the error port.
    fn public_message(&self) -> String {
        match self {
            Self::Db(_) => "Database query failed".to_string(),
            Self::TimedOut(t) => format!("Database query timed out after {}s", t.as_secs()),
        }
    }
}

impl std::fmt::Display for RowsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Db(e) => e.fmt(f),
            Self::TimedOut(_) => f.write_str(&self.public_message()),
        }
    }
}

/// Collects at most `max_rows` rows within `timeout`. Returns the rows and
/// whether more were available.
async fn collect_rows<R, S>(
    rows: S,
    max_rows: usize,
    timeout: Duration,
) -> Result<(Vec<R>, bool), RowsError>
where
    S: Stream<Item = Result<R, sqlx::Error>>,
{
    let fetch = async {
        let mut rows = std::pin::pin!(rows);
        let mut out = Vec::new();
        while let Some(row) = rows.try_next().await.map_err(RowsError::Db)? {
            if out.len() == max_rows {
                return Ok((out, true));
            }
            out.push(row);
        }
        Ok((out, false))
    };
    tokio::time::timeout(timeout, fetch)
        .await
        .map_err(|_| RowsError::TimedOut(timeout))?
}

fn error_output(msg: &FlowMessage, error: impl Into<String>) -> Z8Result<Vec<FlowMessage>> {
    let err = serde_json::json!({ "error": error.into() });
    Ok(vec![msg.derive(msg.source_node, "error", err)])
}

pub struct DatabaseNode {
    name: String,
    db_type: String,
    host: String,
    port: u16,
    database: String,
    user: String,
    password: String,
    query: String,
    /// Dot-notation paths to extract parameter values from message payload.
    params: Vec<String>,
    /// Direct connection string (overrides individual fields if set).
    connection_string: String,
}

impl DatabaseNode {
    /// Build connection string from individual config fields.
    fn build_connection_string(&self) -> String {
        if !self.connection_string.is_empty() {
            return self.connection_string.clone();
        }

        match self.db_type.as_str() {
            "postgres" => {
                let port = if self.port == 0 { 5432 } else { self.port };
                format!(
                    "postgres://{}:{}@{}:{}/{}",
                    self.user, self.password, self.host, port, self.database
                )
            }
            "mysql" => {
                let port = if self.port == 0 { 3306 } else { self.port };
                format!(
                    "mysql://{}:{}@{}:{}/{}",
                    self.user, self.password, self.host, port, self.database
                )
            }
            "sqlite" => {
                // For SQLite, database is the file path
                if self.database.is_empty() {
                    "sqlite::memory:".to_string()
                } else {
                    format!("sqlite:{}", self.database)
                }
            }
            "mssql" => {
                let port = if self.port == 0 { 1433 } else { self.port };
                format!(
                    "mssql://{}:{}@{}:{}/{}",
                    self.user, self.password, self.host, port, self.database
                )
            }
            _ => {
                // Fallback: try postgres-style
                let port = if self.port == 0 { 5432 } else { self.port };
                format!(
                    "{}://{}:{}@{}:{}/{}",
                    self.db_type, self.user, self.password, self.host, port, self.database
                )
            }
        }
    }

    /// Returns a safe version of the connection string for error messages (no password).
    fn safe_connection_info(&self) -> String {
        if self.connection_string.is_empty() {
            format!(
                "{}://{}@{}:{}/{}",
                self.db_type, self.user, self.host, self.port, self.database
            )
        } else {
            // Mask everything between :// and @
            self.connection_string
                .split('@')
                .next_back()
                .unwrap_or("***")
                .to_string()
        }
    }
}

#[async_trait::async_trait]
impl NodeExecutor for DatabaseNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        debug!(node = %self.name, db_type = %self.db_type, "Executing database query");

        let conn_str = self.build_connection_string();

        if conn_str.is_empty() {
            let err = serde_json::json!({
                "error": "No database connection configured"
            });
            let out = msg.derive(msg.source_node, "error", err);
            return Ok(vec![out]);
        }

        // Use the appropriate database driver based on dbType
        match self.db_type.as_str() {
            "postgres" => self.execute_postgres(&msg, &conn_str).await,
            "mysql" => self.execute_mysql(&msg, &conn_str).await,
            "sqlite" => self.execute_sqlite(&msg, &conn_str).await,
            other => {
                let err = serde_json::json!({
                    "error": format!("Unsupported database type: '{}'. Supported: postgres, mysql, sqlite, mssql", other),
                });
                let out = msg.derive(msg.source_node, "error", err);
                Ok(vec![out])
            }
        }
    }

    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        if let Some(name) = config.get("name").and_then(|v| v.as_str()) {
            self.name = name.to_string();
        }
        if let Some(t) = config.get("dbType").and_then(|v| v.as_str()) {
            self.db_type = t.to_string();
        }
        // Legacy: also accept "type" field
        if let Some(t) = config.get("type").and_then(|v| v.as_str()) {
            self.db_type = t.to_string();
        }
        if let Some(h) = config.get("host").and_then(|v| v.as_str()) {
            self.host = h.to_string();
        }
        if let Some(p) = config.get("port").and_then(|v| v.as_u64()) {
            self.port = p as u16;
        }
        if let Some(d) = config.get("database").and_then(|v| v.as_str()) {
            self.database = d.to_string();
        }
        if let Some(u) = config.get("user").and_then(|v| v.as_str()) {
            self.user = u.to_string();
        }
        if let Some(pw) = config.get("password").and_then(|v| v.as_str()) {
            self.password = pw.to_string();
        }
        if let Some(q) = config.get("query").and_then(|v| v.as_str()) {
            self.query = q.to_string();
        }
        if let Some(params) = config.get("params").and_then(|v| v.as_array()) {
            self.params = params
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
        }
        if let Some(cs) = config.get("connectionString").and_then(|v| v.as_str()) {
            self.connection_string = cs.to_string();
        }
        Ok(())
    }

    async fn validate(&self) -> Z8Result<()> {
        require_non_empty(&self.query, "Database node requires a 'query'")?;
        if self.connection_string.is_empty() && self.database.is_empty() && self.db_type != "sqlite"
        {
            return Err(crate::error::Z8Error::Internal(
                "Database node requires either a 'connectionString' or 'database' name".to_string(),
            ));
        }
        Ok(())
    }

    fn node_type(&self) -> &str {
        "database"
    }
}

// ---------- PostgreSQL ----------

impl DatabaseNode {
    async fn execute_postgres(
        &self,
        msg: &FlowMessage,
        conn_str: &str,
    ) -> Z8Result<Vec<FlowMessage>> {
        let opts = match sqlx::postgres::PgConnectOptions::from_str(conn_str) {
            Ok(opts) => opts,
            Err(e) => return error_output(msg, format!("Invalid PostgreSQL connection: {e}")),
        };
        if let Err(e) = check_server(opts.get_host(), opts.get_port(), opts.get_socket()).await {
            return error_output(msg, e);
        }
        // Also stop the query server-side if the client-side timeout fires.
        let opts = opts.options([(
            "statement_timeout",
            format!("{}s", LIMITS.query_timeout.as_secs()),
        )]);
        let pool = match sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect_with(opts)
            .await
        {
            Ok(pool) => pool,
            Err(e) => {
                error!(node = %self.name, error = %e, "PostgreSQL connection failed");
                let err = serde_json::json!({
                    "error": format!("PostgreSQL connection failed: {}", e),
                    "connection": self.safe_connection_info(),
                });
                let out = msg.derive(msg.source_node, "error", err);
                return Ok(vec![out]);
            }
        };

        let mut query = sqlx::query(&self.query);
        for param_path in &self.params {
            let val = json_path_lookup(&msg.payload, param_path);
            query = bind_pg_value(query, &val);
        }

        let (result, truncated) =
            match collect_rows(query.fetch(&pool), LIMITS.max_rows, LIMITS.query_timeout).await {
                Ok(rows) => rows,
                Err(e) => {
                    error!(node = %self.name, error = %e, "PostgreSQL query failed");
                    let err = serde_json::json!({
                        "error": e.public_message(),
                    });
                    let out = msg.derive(msg.source_node, "error", err);
                    pool.close().await;
                    return Ok(vec![out]);
                }
            };

        let rows_json: Vec<Value> = result.iter().map(pg_row_to_json).collect();
        let payload = serde_json::json!({
            "rows": rows_json,
            "count": rows_json.len(),
            "truncated": truncated,
            "query": self.query,
            "dbType": "postgres",
        });

        debug!(node = %self.name, row_count = rows_json.len(), "PostgreSQL query completed");
        pool.close().await;
        let out = msg.derive(msg.source_node, "results", payload);
        Ok(vec![out])
    }

    async fn execute_mysql(&self, msg: &FlowMessage, conn_str: &str) -> Z8Result<Vec<FlowMessage>> {
        // MySQL uses ? for parameters instead of $1, $2, ...
        let opts = match sqlx::mysql::MySqlConnectOptions::from_str(conn_str) {
            Ok(opts) => opts,
            Err(e) => return error_output(msg, format!("Invalid MySQL connection: {e}")),
        };
        if let Err(e) = check_server(opts.get_host(), opts.get_port(), opts.get_socket()).await {
            return error_output(msg, e);
        }
        let pool = match sqlx::mysql::MySqlPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect_with(opts)
            .await
        {
            Ok(pool) => pool,
            Err(e) => {
                error!(node = %self.name, error = %e, "MySQL connection failed");
                let err = serde_json::json!({
                    "error": format!("MySQL connection failed: {}", e),
                    "connection": self.safe_connection_info(),
                });
                let out = msg.derive(msg.source_node, "error", err);
                return Ok(vec![out]);
            }
        };

        let mut query = sqlx::query(&self.query);
        for param_path in &self.params {
            let val = json_path_lookup(&msg.payload, param_path);
            query = bind_mysql_value(query, &val);
        }

        let (result, truncated) =
            match collect_rows(query.fetch(&pool), LIMITS.max_rows, LIMITS.query_timeout).await {
                Ok(rows) => rows,
                Err(e) => {
                    error!(node = %self.name, error = %e, "MySQL query failed");
                    let err = serde_json::json!({
                        "error": e.public_message(),
                    });
                    let out = msg.derive(msg.source_node, "error", err);
                    pool.close().await;
                    return Ok(vec![out]);
                }
            };

        let rows_json: Vec<Value> = result.iter().map(mysql_row_to_json).collect();
        let payload = serde_json::json!({
            "rows": rows_json,
            "count": rows_json.len(),
            "truncated": truncated,
            "query": self.query,
            "dbType": "mysql",
        });

        debug!(node = %self.name, row_count = rows_json.len(), "MySQL query completed");
        pool.close().await;
        let out = msg.derive(msg.source_node, "results", payload);
        Ok(vec![out])
    }

    async fn execute_sqlite(
        &self,
        msg: &FlowMessage,
        conn_str: &str,
    ) -> Z8Result<Vec<FlowMessage>> {
        if strict() {
            let checked = sqlite_target(conn_str).and_then(|target| match target {
                None => Ok(()),
                Some(file) => check_sqlite_path(&file, LIMITS.sqlite_dir.as_deref()),
            });
            if let Err(e) = checked.and_then(|()| check_sqlite_query(&self.query)) {
                return error_output(msg, e);
            }
        }
        let pool = match sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect(conn_str)
            .await
        {
            Ok(pool) => pool,
            Err(e) => {
                error!(node = %self.name, error = %e, "SQLite connection failed");
                let err = serde_json::json!({
                    "error": "SQLite connection failed",
                });
                let out = msg.derive(msg.source_node, "error", err);
                return Ok(vec![out]);
            }
        };

        let mut query = sqlx::query(&self.query);
        for param_path in &self.params {
            let val = json_path_lookup(&msg.payload, param_path);
            query = bind_sqlite_value(query, &val);
        }

        let (result, truncated) =
            match collect_rows(query.fetch(&pool), LIMITS.max_rows, LIMITS.query_timeout).await {
                Ok(rows) => rows,
                Err(e) => {
                    error!(node = %self.name, error = %e, "SQLite query failed");
                    let err = serde_json::json!({
                        "error": e.public_message(),
                    });
                    let out = msg.derive(msg.source_node, "error", err);
                    pool.close().await;
                    return Ok(vec![out]);
                }
            };

        let rows_json: Vec<Value> = result.iter().map(sqlite_row_to_json).collect();
        let payload = serde_json::json!({
            "rows": rows_json,
            "count": rows_json.len(),
            "truncated": truncated,
            "query": self.query,
            "dbType": "sqlite",
        });

        debug!(node = %self.name, row_count = rows_json.len(), "SQLite query completed");
        pool.close().await;
        let out = msg.derive(msg.source_node, "results", payload);
        Ok(vec![out])
    }
}

// ---------- PostgreSQL helpers ----------

fn bind_pg_value<'q>(
    query: sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments>,
    val: &Value,
) -> sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments> {
    match val {
        Value::String(s) => query.bind(s.clone()),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                query.bind(i)
            } else if let Some(f) = n.as_f64() {
                query.bind(f)
            } else {
                query.bind(n.to_string())
            }
        }
        Value::Bool(b) => query.bind(*b),
        Value::Null => query.bind(None::<String>),
        _ => query.bind(serde_json::to_string(val).unwrap_or_default()),
    }
}

fn pg_row_to_json(row: &sqlx::postgres::PgRow) -> Value {
    use sqlx::{Column, Row, TypeInfo};
    let mut obj = serde_json::Map::new();
    for col in row.columns() {
        let name = col.name().to_string();
        let type_name = col.type_info().name();
        let val: Value = match type_name {
            "INT4" | "INT2" => row
                .try_get::<i32, _>(name.as_str())
                .map(|v| Value::Number(v.into()))
                .unwrap_or(Value::Null),
            "INT8" => row
                .try_get::<i64, _>(name.as_str())
                .map(|v| Value::Number(v.into()))
                .unwrap_or(Value::Null),
            "FLOAT4" | "FLOAT8" => row
                .try_get::<f64, _>(name.as_str())
                .map(|v| serde_json::json!(v))
                .unwrap_or(Value::Null),
            "BOOL" => row
                .try_get::<bool, _>(name.as_str())
                .map(Value::Bool)
                .unwrap_or(Value::Null),
            "JSON" | "JSONB" => row
                .try_get::<Value, _>(name.as_str())
                .unwrap_or(Value::Null),
            "UUID" => row
                .try_get::<uuid::Uuid, _>(name.as_str())
                .map(|v| Value::String(v.to_string()))
                .unwrap_or(Value::Null),
            "TIMESTAMPTZ" | "TIMESTAMP" => row
                .try_get::<chrono::NaiveDateTime, _>(name.as_str())
                .map(|v| Value::String(v.to_string()))
                .ok()
                .or_else(|| {
                    row.try_get::<chrono::DateTime<chrono::Utc>, _>(name.as_str())
                        .map(|v| Value::String(v.to_rfc3339()))
                        .ok()
                })
                .unwrap_or(Value::Null),
            _ => row
                .try_get::<String, _>(name.as_str())
                .map(Value::String)
                .unwrap_or(Value::Null),
        };
        obj.insert(name, val);
    }
    Value::Object(obj)
}

// ---------- MySQL helpers ----------

fn bind_mysql_value<'q>(
    query: sqlx::query::Query<'q, sqlx::MySql, sqlx::mysql::MySqlArguments>,
    val: &Value,
) -> sqlx::query::Query<'q, sqlx::MySql, sqlx::mysql::MySqlArguments> {
    match val {
        Value::String(s) => query.bind(s.clone()),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                query.bind(i)
            } else if let Some(f) = n.as_f64() {
                query.bind(f)
            } else {
                query.bind(n.to_string())
            }
        }
        Value::Bool(b) => query.bind(*b),
        Value::Null => query.bind(None::<String>),
        _ => query.bind(serde_json::to_string(val).unwrap_or_default()),
    }
}

fn mysql_row_to_json(row: &sqlx::mysql::MySqlRow) -> Value {
    use sqlx::{Column, Row, TypeInfo};
    let mut obj = serde_json::Map::new();
    for col in row.columns() {
        let name = col.name().to_string();
        let type_name = col.type_info().name();
        let val: Value = match type_name {
            "INT" | "SMALLINT" | "MEDIUMINT" | "TINYINT" => row
                .try_get::<i32, _>(name.as_str())
                .map(|v| Value::Number(v.into()))
                .unwrap_or(Value::Null),
            "BIGINT" => row
                .try_get::<i64, _>(name.as_str())
                .map(|v| Value::Number(v.into()))
                .unwrap_or(Value::Null),
            "FLOAT" | "DOUBLE" | "DECIMAL" => row
                .try_get::<f64, _>(name.as_str())
                .map(|v| serde_json::json!(v))
                .unwrap_or(Value::Null),
            "BOOLEAN" => row
                .try_get::<bool, _>(name.as_str())
                .map(Value::Bool)
                .unwrap_or(Value::Null),
            "JSON" => row
                .try_get::<Value, _>(name.as_str())
                .unwrap_or(Value::Null),
            "DATETIME" | "TIMESTAMP" => row
                .try_get::<chrono::NaiveDateTime, _>(name.as_str())
                .map(|v| Value::String(v.to_string()))
                .unwrap_or(Value::Null),
            _ => row
                .try_get::<String, _>(name.as_str())
                .map(Value::String)
                .unwrap_or(Value::Null),
        };
        obj.insert(name, val);
    }
    Value::Object(obj)
}

// ---------- SQLite helpers ----------

fn bind_sqlite_value<'q>(
    query: sqlx::query::Query<'q, sqlx::Sqlite, sqlx::sqlite::SqliteArguments<'q>>,
    val: &Value,
) -> sqlx::query::Query<'q, sqlx::Sqlite, sqlx::sqlite::SqliteArguments<'q>> {
    match val {
        Value::String(s) => query.bind(s.clone()),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                query.bind(i)
            } else if let Some(f) = n.as_f64() {
                query.bind(f)
            } else {
                query.bind(n.to_string())
            }
        }
        Value::Bool(b) => query.bind(*b),
        Value::Null => query.bind(None::<String>),
        _ => query.bind(serde_json::to_string(val).unwrap_or_default()),
    }
}

fn sqlite_row_to_json(row: &sqlx::sqlite::SqliteRow) -> Value {
    use sqlx::{Column, Row, TypeInfo};
    let mut obj = serde_json::Map::new();
    for col in row.columns() {
        let name = col.name().to_string();
        let type_name = col.type_info().name();
        let val: Value = match type_name {
            "INTEGER" => row
                .try_get::<i64, _>(name.as_str())
                .map(|v| Value::Number(v.into()))
                .unwrap_or(Value::Null),
            "REAL" => row
                .try_get::<f64, _>(name.as_str())
                .map(|v| serde_json::json!(v))
                .unwrap_or(Value::Null),
            "BOOLEAN" => row
                .try_get::<bool, _>(name.as_str())
                .map(Value::Bool)
                .unwrap_or(Value::Null),
            "TEXT" => row
                .try_get::<String, _>(name.as_str())
                .map(Value::String)
                .unwrap_or(Value::Null),
            _ => row
                .try_get::<String, _>(name.as_str())
                .map(Value::String)
                .unwrap_or(Value::Null),
        };
        obj.insert(name, val);
    }
    Value::Object(obj)
}

// ---------- Factory ----------

node_factory!(DatabaseNodeFactory, DatabaseNode, "database", {
    name: "Database".to_string(),
    db_type: "postgres".to_string(),
    host: "localhost".to_string(),
    port: 5432,
    database: String::new(),
    user: String::new(),
    password: String::new(),
    query: String::new(),
    params: vec![],
    connection_string: String::new()
});

#[cfg(test)]
mod tests {
    use super::*;

    fn node(db_type: &str, database: &str, connection_string: &str, query: &str) -> DatabaseNode {
        DatabaseNode {
            name: "db".into(),
            db_type: db_type.into(),
            host: String::new(),
            port: 0,
            database: database.into(),
            user: String::new(),
            password: String::new(),
            query: query.into(),
            params: vec![],
            connection_string: connection_string.into(),
        }
    }

    async fn run(node: &DatabaseNode) -> FlowMessage {
        let msg = FlowMessage::new(
            uuid::Uuid::now_v7(),
            "out",
            serde_json::json!({}),
            uuid::Uuid::now_v7(),
        );
        node.process(msg).await.unwrap().remove(0)
    }

    /// A fresh directory under the system temp dir, canonicalized.
    fn scratch_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("z8-db-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.canonicalize().unwrap()
    }

    #[test]
    fn sqlite_target_distinguishes_memory_and_files() {
        assert_eq!(sqlite_target("sqlite::memory:").unwrap(), None);
        assert_eq!(
            sqlite_target("sqlite:/data/app.db?mode=rwc").unwrap(),
            Some(PathBuf::from("/data/app.db"))
        );
    }

    #[test]
    fn sqlite_paths_must_stay_in_the_sandbox() {
        let sandbox = scratch_dir();
        let outside = scratch_dir();

        // No sandbox configured: files are refused outright.
        assert!(check_sqlite_path(&sandbox.join("a.db"), None).is_err());
        // Inside, including files that don't exist yet.
        assert!(check_sqlite_path(&sandbox.join("new.db"), Some(&sandbox)).is_ok());
        // Outside, via `..`, relative, or through a symlink.
        assert!(check_sqlite_path(&outside.join("a.db"), Some(&sandbox)).is_err());
        let escape = sandbox
            .join("..")
            .join(outside.file_name().unwrap())
            .join("a.db");
        assert!(check_sqlite_path(&escape, Some(&sandbox)).is_err());
        assert!(check_sqlite_path(Path::new("a.db"), Some(&sandbox)).is_err());
        std::fs::write(outside.join("real.db"), b"").unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(outside.join("real.db"), sandbox.join("link.db")).unwrap();
            assert!(check_sqlite_path(&sandbox.join("link.db"), Some(&sandbox)).is_err());
        }

        let _ = std::fs::remove_dir_all(&sandbox);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[test]
    fn sqlite_file_statements_are_refused() {
        assert!(check_sqlite_query("ATTACH DATABASE '/app/data/z8run.db' AS z").is_err());
        assert!(check_sqlite_query("select 1; attach '/x' as y").is_err());
        assert!(check_sqlite_query("VACUUM INTO '/tmp/copy.db'").is_err());
        assert!(check_sqlite_query("SELECT attached_at FROM t").is_ok());
    }

    #[tokio::test]
    async fn rows_are_capped_and_flagged() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .connect("sqlite::memory:")
            .await
            .unwrap();
        let q = "WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM n WHERE x < 5) SELECT x FROM n";
        let long = Duration::from_secs(5);

        let (rows, truncated) = collect_rows(sqlx::query(q).fetch(&pool), 3, long)
            .await
            .ok()
            .unwrap();
        assert_eq!((rows.len(), truncated), (3, true));
        let (rows, truncated) = collect_rows(sqlx::query(q).fetch(&pool), 5, long)
            .await
            .ok()
            .unwrap();
        assert_eq!((rows.len(), truncated), (5, false));
    }

    #[tokio::test]
    async fn slow_queries_time_out() {
        let never = futures_util::stream::pending::<Result<(), sqlx::Error>>();
        let err = collect_rows(never, 10, Duration::from_millis(50))
            .await
            .err()
            .unwrap();
        assert!(matches!(err, RowsError::TimedOut(_)));
        assert!(err.public_message().contains("timed out"));
    }

    #[tokio::test]
    async fn strict_policy_refuses_internal_servers_and_files() {
        // Default policy is strict and Z8_DB_SQLITE_DIR is unset in tests.
        for (db_type, conn) in [
            ("postgres", "postgres://u:p@127.0.0.1:5432/app"),
            ("postgres", "postgres://u:p@localhost/app"),
            ("mysql", "mysql://u:p@10.0.0.5:3306/app"),
        ] {
            let out = run(&node(db_type, "app", conn, "SELECT 1")).await;
            assert_eq!(out.source_port, "error", "{conn}");
            let error = out.payload["error"].as_str().unwrap();
            assert!(
                error.contains("blocked by the egress policy"),
                "{conn}: {error}"
            );
        }

        let socket = run(&node(
            "postgres",
            "app",
            "postgres:///app?host=/var/run/postgresql",
            "SELECT 1",
        ))
        .await;
        assert!(socket.payload["error"]
            .as_str()
            .unwrap()
            .contains("Unix socket"));

        let file = run(&node(
            "sqlite",
            "/app/data/z8run.db",
            "",
            "SELECT * FROM users",
        ))
        .await;
        assert_eq!(file.source_port, "error");
        assert!(file.payload["error"]
            .as_str()
            .unwrap()
            .contains("Z8_DB_SQLITE_DIR"));

        let attach = run(&node("sqlite", "", "", "ATTACH '/app/data/z8run.db' AS z")).await;
        assert_eq!(attach.source_port, "error");
    }

    #[tokio::test]
    async fn in_memory_sqlite_still_works() {
        let out = run(&node(
            "sqlite",
            "",
            "",
            "CREATE TABLE t (answer INTEGER); INSERT INTO t VALUES (42); SELECT answer FROM t",
        ))
        .await;
        assert_eq!(out.source_port, "results", "{}", out.payload);
        assert_eq!(out.payload["rows"][0]["answer"], 42);
        assert_eq!(out.payload["truncated"], false);
    }
}

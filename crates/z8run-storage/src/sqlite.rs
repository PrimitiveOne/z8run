//! SQLite implementation of the storage repositories.

use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use uuid::Uuid;

use z8run_core::flow::Flow;

use crate::repository::{
    ExecutionRecord, ExecutionRepository, FlowRepository, HookMatch, HookRoute, UserRecord,
    UserRepository,
};
use crate::StorageError;

/// SQLite-backed storage for flows and executions.
#[derive(Clone)]
pub struct SqliteStorage {
    pool: SqlitePool,
}

impl SqliteStorage {
    /// Creates a new SQLite storage with the given connection URL.
    /// Example URL: `sqlite://./data/z8run.db?mode=rwc`
    pub async fn new(database_url: &str) -> Result<Self, StorageError> {
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(database_url)
            .await
            .map_err(|e| StorageError::Database(format!("Failed to connect: {}", e)))?;

        Ok(Self { pool })
    }

    /// Builds storage from an existing pool (used for embedding and tests).
    pub fn from_pool(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Returns a reference to the underlying connection pool.
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Runs migrations on this pool.
    pub async fn migrate(&self) -> Result<(), StorageError> {
        crate::migration::run_sqlite_migrations(&self.pool).await
    }
}

#[async_trait::async_trait]
impl FlowRepository for SqliteStorage {
    async fn save_flow(&self, flow: &Flow) -> Result<(), StorageError> {
        let id = flow.id.to_string();
        let data =
            serde_json::to_string(flow).map_err(|e| StorageError::Serialization(e.to_string()))?;
        let status = flow.status.to_string();
        let created_at = flow.created_at.to_rfc3339();
        let updated_at = chrono::Utc::now().to_rfc3339();

        sqlx::query(
            r#"
            INSERT INTO flows (id, name, description, version, data, status, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            ON CONFLICT(id) DO UPDATE SET
                name = excluded.name,
                description = excluded.description,
                version = excluded.version,
                data = excluded.data,
                status = excluded.status,
                updated_at = excluded.updated_at
            "#,
        )
        .bind(&id)
        .bind(&flow.name)
        .bind(&flow.description)
        .bind(&flow.version)
        .bind(&data)
        .bind(&status)
        .bind(&created_at)
        .bind(&updated_at)
        .execute(&self.pool)
        .await?;

        tracing::debug!(flow_id = %id, "Flow saved");
        Ok(())
    }

    async fn get_flow(&self, id: Uuid) -> Result<Flow, StorageError> {
        let id_str = id.to_string();

        let row: (String,) = sqlx::query_as("SELECT data FROM flows WHERE id = ?1")
            .bind(&id_str)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(StorageError::FlowNotFound(id))?;

        let flow: Flow =
            serde_json::from_str(&row.0).map_err(|e| StorageError::Serialization(e.to_string()))?;

        Ok(flow)
    }

    async fn list_flows(&self) -> Result<Vec<Flow>, StorageError> {
        let rows: Vec<(String,)> =
            sqlx::query_as("SELECT data FROM flows ORDER BY updated_at DESC")
                .fetch_all(&self.pool)
                .await?;

        let mut flows = Vec::with_capacity(rows.len());
        for (data,) in rows {
            let flow: Flow = serde_json::from_str(&data)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            flows.push(flow);
        }

        Ok(flows)
    }

    async fn delete_flow(&self, id: Uuid) -> Result<(), StorageError> {
        let id_str = id.to_string();

        let result = sqlx::query("DELETE FROM flows WHERE id = ?1")
            .bind(&id_str)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(StorageError::FlowNotFound(id));
        }

        self.undeploy_flow(id).await?;

        tracing::debug!(flow_id = %id, "Flow deleted");
        Ok(())
    }

    async fn search_flows(&self, query: &str) -> Result<Vec<Flow>, StorageError> {
        let pattern = format!("%{}%", query);

        let rows: Vec<(String,)> =
            sqlx::query_as("SELECT data FROM flows WHERE name LIKE ?1 ORDER BY updated_at DESC")
                .bind(&pattern)
                .fetch_all(&self.pool)
                .await?;

        let mut flows = Vec::with_capacity(rows.len());
        for (data,) in rows {
            let flow: Flow = serde_json::from_str(&data)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            flows.push(flow);
        }

        Ok(flows)
    }

    async fn save_flow_with_user(&self, flow: &Flow, user_id: Uuid) -> Result<(), StorageError> {
        let id = flow.id.to_string();
        let user_id_str = user_id.to_string();
        let data =
            serde_json::to_string(flow).map_err(|e| StorageError::Serialization(e.to_string()))?;
        let status = flow.status.to_string();
        let created_at = flow.created_at.to_rfc3339();
        let updated_at = chrono::Utc::now().to_rfc3339();

        sqlx::query(
            r#"
            INSERT INTO flows (id, name, description, version, data, status, user_id, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            ON CONFLICT(id) DO UPDATE SET
                name = excluded.name,
                description = excluded.description,
                version = excluded.version,
                data = excluded.data,
                status = excluded.status,
                updated_at = excluded.updated_at
            "#,
        )
        .bind(&id)
        .bind(&flow.name)
        .bind(&flow.description)
        .bind(&flow.version)
        .bind(&data)
        .bind(&status)
        .bind(&user_id_str)
        .bind(&created_at)
        .bind(&updated_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn list_flows_by_user(&self, user_id: Uuid) -> Result<Vec<Flow>, StorageError> {
        let user_id_str = user_id.to_string();

        let rows: Vec<(String,)> =
            sqlx::query_as("SELECT data FROM flows WHERE user_id = ?1 ORDER BY updated_at DESC")
                .bind(&user_id_str)
                .fetch_all(&self.pool)
                .await?;

        let mut flows = Vec::with_capacity(rows.len());
        for (data,) in rows {
            let flow: Flow = serde_json::from_str(&data)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            flows.push(flow);
        }

        Ok(flows)
    }

    async fn get_flow_for_user(&self, id: Uuid, user_id: Uuid) -> Result<Flow, StorageError> {
        let id_str = id.to_string();
        let user_id_str = user_id.to_string();

        let row: (String,) =
            sqlx::query_as("SELECT data FROM flows WHERE id = ?1 AND user_id = ?2")
                .bind(&id_str)
                .bind(&user_id_str)
                .fetch_optional(&self.pool)
                .await?
                .ok_or(StorageError::FlowNotFound(id))?;

        let flow: Flow =
            serde_json::from_str(&row.0).map_err(|e| StorageError::Serialization(e.to_string()))?;

        Ok(flow)
    }

    async fn delete_flow_for_user(&self, id: Uuid, user_id: Uuid) -> Result<(), StorageError> {
        let id_str = id.to_string();
        let user_id_str = user_id.to_string();

        let result = sqlx::query("DELETE FROM flows WHERE id = ?1 AND user_id = ?2")
            .bind(&id_str)
            .bind(&user_id_str)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(StorageError::FlowNotFound(id));
        }

        self.undeploy_flow(id).await?;

        Ok(())
    }

    async fn get_flow_owner(&self, id: Uuid) -> Result<Option<Uuid>, StorageError> {
        let id_str = id.to_string();

        let row: (Option<String>,) = sqlx::query_as("SELECT user_id FROM flows WHERE id = ?1")
            .bind(&id_str)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(StorageError::FlowNotFound(id))?;

        match row.0 {
            Some(uid) => Ok(Some(
                Uuid::parse_str(&uid).map_err(|e| StorageError::Serialization(e.to_string()))?,
            )),
            None => Ok(None),
        }
    }

    async fn deploy_flow(
        &self,
        flow_id: Uuid,
        user_id: Uuid,
        snapshot: &Flow,
        routes: &[HookRoute],
    ) -> Result<(), StorageError> {
        let flow_id_str = flow_id.to_string();
        let user_id_str = user_id.to_string();
        let now = chrono::Utc::now().to_rfc3339();
        let snapshot_json = serde_json::to_string(snapshot)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;

        // Snapshot and routes change together or not at all, so a hook can
        // never match a route whose snapshot is missing or stale.
        let mut tx = self.pool.begin().await?;

        sqlx::query("DELETE FROM hook_routes WHERE flow_id = ?1")
            .bind(&flow_id_str)
            .execute(&mut *tx)
            .await?;

        sqlx::query(
            r#"INSERT INTO flow_deployments (flow_id, user_id, snapshot, deployed_at)
               VALUES (?1, ?2, ?3, ?4)
               ON CONFLICT(flow_id) DO UPDATE SET
                   user_id = excluded.user_id,
                   snapshot = excluded.snapshot,
                   deployed_at = excluded.deployed_at"#,
        )
        .bind(&flow_id_str)
        .bind(&user_id_str)
        .bind(&snapshot_json)
        .bind(&now)
        .execute(&mut *tx)
        .await?;

        for route in routes {
            sqlx::query(
                r#"INSERT INTO hook_routes (flow_id, user_id, method, path, node_id, node_type, created_at)
                   VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"#,
            )
            .bind(&flow_id_str)
            .bind(&user_id_str)
            .bind(&route.method)
            .bind(&route.path)
            .bind(&route.node_id)
            .bind(&route.node_type)
            .bind(&now)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    async fn find_hook_route(
        &self,
        flow_id: Uuid,
        method: &str,
        path: &str,
    ) -> Result<Option<HookMatch>, StorageError> {
        let row: Option<(String, String)> = sqlx::query_as(
            "SELECT user_id, node_id FROM hook_routes WHERE flow_id = ?1 AND method = ?2 AND path = ?3",
        )
        .bind(flow_id.to_string())
        .bind(method)
        .bind(path)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some((uid, node_id)) => Ok(Some(HookMatch {
                user_id: Uuid::parse_str(&uid)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?,
                node_id,
            })),
            None => Ok(None),
        }
    }

    async fn get_deployment(&self, flow_id: Uuid) -> Result<Option<Flow>, StorageError> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT snapshot FROM flow_deployments WHERE flow_id = ?1")
                .bind(flow_id.to_string())
                .fetch_optional(&self.pool)
                .await?;

        row.map(|(json,)| {
            serde_json::from_str(&json).map_err(|e| StorageError::Serialization(e.to_string()))
        })
        .transpose()
    }

    async fn undeploy_flow(&self, flow_id: Uuid) -> Result<(), StorageError> {
        let flow_id_str = flow_id.to_string();
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM hook_routes WHERE flow_id = ?1")
            .bind(&flow_id_str)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM flow_deployments WHERE flow_id = ?1")
            .bind(&flow_id_str)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl ExecutionRepository for SqliteStorage {
    async fn record_start(&self, flow_id: Uuid, trace_id: Uuid) -> Result<Uuid, StorageError> {
        let id = Uuid::now_v7();
        let id_str = id.to_string();
        let flow_id_str = flow_id.to_string();
        let trace_id_str = trace_id.to_string();
        let started_at = chrono::Utc::now().to_rfc3339();

        sqlx::query(
            r#"
            INSERT INTO executions (id, flow_id, trace_id, status, started_at, node_logs)
            VALUES (?1, ?2, ?3, 'running', ?4, '{}')
            "#,
        )
        .bind(&id_str)
        .bind(&flow_id_str)
        .bind(&trace_id_str)
        .bind(&started_at)
        .execute(&self.pool)
        .await?;

        Ok(id)
    }

    async fn record_completion(
        &self,
        execution_id: Uuid,
        status: &str,
        duration_ms: u64,
        error: Option<&str>,
    ) -> Result<(), StorageError> {
        let id_str = execution_id.to_string();
        let completed_at = chrono::Utc::now().to_rfc3339();
        let dur = duration_ms as i64;

        sqlx::query(
            r#"
            UPDATE executions
            SET status = ?1, completed_at = ?2, duration_ms = ?3, error = ?4
            WHERE id = ?5
            "#,
        )
        .bind(status)
        .bind(&completed_at)
        .bind(dur)
        .bind(error)
        .bind(&id_str)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_history(
        &self,
        flow_id: Uuid,
        limit: usize,
    ) -> Result<Vec<ExecutionRecord>, StorageError> {
        let flow_id_str = flow_id.to_string();
        let limit_i64 = limit as i64;

        let rows: Vec<(String, String, String, String, String, Option<String>, Option<i64>, Option<String>, String)> =
            sqlx::query_as(
                r#"
                SELECT id, flow_id, trace_id, status, started_at, completed_at, duration_ms, error, node_logs
                FROM executions
                WHERE flow_id = ?1
                ORDER BY started_at DESC
                LIMIT ?2
                "#,
            )
            .bind(&flow_id_str)
            .bind(limit_i64)
            .fetch_all(&self.pool)
            .await?;

        let mut records = Vec::with_capacity(rows.len());
        for row in rows {
            let record = ExecutionRecord {
                id: Uuid::parse_str(&row.0)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?,
                flow_id: Uuid::parse_str(&row.1)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?,
                trace_id: Uuid::parse_str(&row.2)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?,
                status: row.3.clone(),
                started_at: chrono::DateTime::parse_from_rfc3339(&row.4)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?
                    .with_timezone(&chrono::Utc),
                completed_at: row.5.as_ref().and_then(|s| {
                    chrono::DateTime::parse_from_rfc3339(s)
                        .ok()
                        .map(|dt| dt.with_timezone(&chrono::Utc))
                }),
                duration_ms: row.6.map(|v| v as u64),
                error: row.7.clone(),
                node_logs: serde_json::from_str(&row.8).unwrap_or_default(),
            };
            records.push(record);
        }

        Ok(records)
    }
}

#[async_trait::async_trait]
impl UserRepository for SqliteStorage {
    async fn create_user(&self, user: &UserRecord) -> Result<(), StorageError> {
        let created_at = user.created_at.to_rfc3339();
        let updated_at = user.updated_at.to_rfc3339();

        sqlx::query(
            r#"INSERT INTO users (id, email, username, password_hash, roles, created_at, updated_at)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"#,
        )
        .bind(user.id.to_string())
        .bind(&user.email)
        .bind(&user.username)
        .bind(&user.password_hash)
        .bind(user.roles.join(","))
        .bind(&created_at)
        .bind(&updated_at)
        .execute(&self.pool)
        .await?;

        tracing::debug!(user_id = %user.id, "User created in SQLite");
        Ok(())
    }

    async fn get_user_by_id(&self, id: Uuid) -> Result<UserRecord, StorageError> {
        let row: (String, String, String, String, String, String, String) =
            sqlx::query_as("SELECT id, email, username, password_hash, roles, created_at, updated_at FROM users WHERE id = ?1")
                .bind(id.to_string())
                .fetch_optional(&self.pool)
                .await?
                .ok_or(StorageError::UserNotFound(id.to_string()))?;

        Ok(UserRecord {
            id: Uuid::parse_str(&row.0).map_err(|e| StorageError::Serialization(e.to_string()))?,
            email: row.1,
            username: row.2,
            password_hash: row.3,
            roles: row
                .4
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            created_at: chrono::DateTime::parse_from_rfc3339(&row.5)
                .map_err(|e| StorageError::Serialization(e.to_string()))?
                .with_timezone(&chrono::Utc),
            updated_at: chrono::DateTime::parse_from_rfc3339(&row.6)
                .map_err(|e| StorageError::Serialization(e.to_string()))?
                .with_timezone(&chrono::Utc),
        })
    }

    async fn get_user_by_email(&self, email: &str) -> Result<UserRecord, StorageError> {
        let row: (String, String, String, String, String, String, String) =
            sqlx::query_as("SELECT id, email, username, password_hash, roles, created_at, updated_at FROM users WHERE email = ?1")
                .bind(email)
                .fetch_optional(&self.pool)
                .await?
                .ok_or(StorageError::UserNotFound(email.to_string()))?;

        Ok(UserRecord {
            id: Uuid::parse_str(&row.0).map_err(|e| StorageError::Serialization(e.to_string()))?,
            email: row.1,
            username: row.2,
            password_hash: row.3,
            roles: row
                .4
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            created_at: chrono::DateTime::parse_from_rfc3339(&row.5)
                .map_err(|e| StorageError::Serialization(e.to_string()))?
                .with_timezone(&chrono::Utc),
            updated_at: chrono::DateTime::parse_from_rfc3339(&row.6)
                .map_err(|e| StorageError::Serialization(e.to_string()))?
                .with_timezone(&chrono::Utc),
        })
    }

    async fn get_user_by_username(&self, username: &str) -> Result<UserRecord, StorageError> {
        let row: (String, String, String, String, String, String, String) =
            sqlx::query_as("SELECT id, email, username, password_hash, roles, created_at, updated_at FROM users WHERE username = ?1")
                .bind(username)
                .fetch_optional(&self.pool)
                .await?
                .ok_or(StorageError::UserNotFound(username.to_string()))?;

        Ok(UserRecord {
            id: Uuid::parse_str(&row.0).map_err(|e| StorageError::Serialization(e.to_string()))?,
            email: row.1,
            username: row.2,
            password_hash: row.3,
            roles: row
                .4
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            created_at: chrono::DateTime::parse_from_rfc3339(&row.5)
                .map_err(|e| StorageError::Serialization(e.to_string()))?
                .with_timezone(&chrono::Utc),
            updated_at: chrono::DateTime::parse_from_rfc3339(&row.6)
                .map_err(|e| StorageError::Serialization(e.to_string()))?
                .with_timezone(&chrono::Utc),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// In-memory SQLite storage with a single shared connection so the
    /// database survives across queries.
    async fn memory_storage() -> SqliteStorage {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        crate::migration::run_sqlite_migrations(&pool)
            .await
            .expect("run migrations");
        SqliteStorage::from_pool(pool)
    }

    fn route(method: &str, path: &str, node_id: &str) -> HookRoute {
        HookRoute {
            method: method.to_string(),
            path: path.to_string(),
            node_id: node_id.to_string(),
            node_type: "http-in".to_string(),
        }
    }

    fn matched(owner: Uuid, node_id: &str) -> Option<HookMatch> {
        Some(HookMatch {
            user_id: owner,
            node_id: node_id.to_string(),
        })
    }

    #[tokio::test]
    async fn test_hook_route_matches_method_and_path_and_binds_node() {
        let storage = memory_storage().await;
        let flow = Uuid::now_v7();
        let owner = Uuid::now_v7();
        let snapshot = Flow::new("deployed");

        storage
            .deploy_flow(
                flow,
                owner,
                &snapshot,
                &[route("POST", "/branch", "n1"), route("GET", "/", "n2")],
            )
            .await
            .unwrap();

        // Exact matches resolve to the owner AND the trigger that declared them.
        assert_eq!(
            storage
                .find_hook_route(flow, "POST", "/branch")
                .await
                .unwrap(),
            matched(owner, "n1")
        );
        assert_eq!(
            storage.find_hook_route(flow, "GET", "/").await.unwrap(),
            matched(owner, "n2")
        );

        // Wrong method, wrong path, and unknown flow are all rejected.
        assert_eq!(
            storage
                .find_hook_route(flow, "GET", "/branch")
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            storage
                .find_hook_route(flow, "POST", "/other")
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            storage
                .find_hook_route(Uuid::now_v7(), "POST", "/branch")
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn test_redeploy_replaces_routes_and_snapshot() {
        let storage = memory_storage().await;
        let flow = Uuid::now_v7();
        let owner = Uuid::now_v7();

        storage
            .deploy_flow(
                flow,
                owner,
                &Flow::new("v1"),
                &[route("POST", "/branch", "n1")],
            )
            .await
            .unwrap();
        // Re-deploy with a different route set: the old route must disappear
        // and the snapshot must be the new version.
        storage
            .deploy_flow(flow, owner, &Flow::new("v2"), &[route("POST", "/", "n9")])
            .await
            .unwrap();

        assert_eq!(
            storage
                .find_hook_route(flow, "POST", "/branch")
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            storage.find_hook_route(flow, "POST", "/").await.unwrap(),
            matched(owner, "n9")
        );
        assert_eq!(
            storage.get_deployment(flow).await.unwrap().map(|f| f.name),
            Some("v2".to_string())
        );
    }

    #[tokio::test]
    async fn test_undeploy_removes_routes_and_snapshot() {
        let storage = memory_storage().await;
        let flow = Uuid::now_v7();
        let owner = Uuid::now_v7();

        storage
            .deploy_flow(flow, owner, &Flow::new("v1"), &[route("POST", "/", "n1")])
            .await
            .unwrap();
        storage.undeploy_flow(flow).await.unwrap();

        assert_eq!(
            storage.find_hook_route(flow, "POST", "/").await.unwrap(),
            None
        );
        assert!(storage.get_deployment(flow).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_deployment_snapshot_is_independent_of_later_edits() {
        let storage = memory_storage().await;
        let owner = Uuid::now_v7();
        // flows.user_id references users(id), so the owner must exist.
        storage
            .create_user(&UserRecord {
                id: owner,
                email: "owner@example.com".to_string(),
                username: "owner".to_string(),
                password_hash: "x".to_string(),
                roles: vec!["user".to_string()],
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            })
            .await
            .unwrap();
        let mut flow = Flow::new("original");
        storage.save_flow_with_user(&flow, owner).await.unwrap();

        storage
            .deploy_flow(flow.id, owner, &flow, &[route("POST", "/", "n1")])
            .await
            .unwrap();

        // Editing the live flow after deploy must not alter the snapshot (A-05).
        flow.name = "edited".to_string();
        storage.save_flow(&flow).await.unwrap();

        assert_eq!(
            storage
                .get_deployment(flow.id)
                .await
                .unwrap()
                .map(|f| f.name),
            Some("original".to_string())
        );
    }
}

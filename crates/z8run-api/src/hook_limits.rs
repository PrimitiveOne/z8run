//! Resource limits for public webhook execution (A-06).
//!
//! Hooks are unauthenticated entry points that run flows, so each one is
//! bounded: request body size, concurrent executions per flow, and how long a
//! caller waits. When the caller gives up, the execution is cancelled rather
//! than left running in the background.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use uuid::Uuid;

/// Default maximum hook request body (1 MiB).
const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;
/// Default concurrent executions allowed per flow.
const DEFAULT_MAX_CONCURRENCY: usize = 10;
/// Default time a caller waits for the flow's `http-out` response.
const DEFAULT_TIMEOUT_SECS: u64 = 10;

/// Limits applied to `/hook/*` requests.
pub struct HookLimits {
    /// Maximum request body in bytes (`Z8_HOOK_MAX_BODY_BYTES`).
    pub max_body_bytes: usize,
    /// Concurrent executions per flow (`Z8_HOOK_MAX_CONCURRENCY`).
    pub max_concurrency: usize,
    /// Response wait before the execution is cancelled (`Z8_HOOK_TIMEOUT_SECS`).
    pub timeout: Duration,
    /// Per-flow execution slots.
    slots: Mutex<HashMap<Uuid, Arc<Semaphore>>>,
}

impl HookLimits {
    /// Reads limits from the environment, falling back to safe defaults for
    /// missing, unparsable, or zero values.
    pub fn from_env() -> Self {
        fn positive<T: std::str::FromStr + PartialOrd + Default>(var: &str, default: T) -> T {
            std::env::var(var)
                .ok()
                .and_then(|v| v.trim().parse::<T>().ok())
                .filter(|v| *v > T::default())
                .unwrap_or(default)
        }

        Self {
            max_body_bytes: positive("Z8_HOOK_MAX_BODY_BYTES", DEFAULT_MAX_BODY_BYTES),
            max_concurrency: positive("Z8_HOOK_MAX_CONCURRENCY", DEFAULT_MAX_CONCURRENCY),
            timeout: Duration::from_secs(positive("Z8_HOOK_TIMEOUT_SECS", DEFAULT_TIMEOUT_SECS)),
            slots: Mutex::new(HashMap::new()),
        }
    }

    /// Reserves an execution slot for `flow_id`. Returns `None` when the flow
    /// already runs `max_concurrency` hook executions. The slot is released
    /// when the returned permit is dropped.
    pub fn try_acquire(&self, flow_id: Uuid) -> Option<OwnedSemaphorePermit> {
        let semaphore = {
            let mut slots = self.slots.lock().unwrap_or_else(|e| e.into_inner());
            Arc::clone(
                slots
                    .entry(flow_id)
                    .or_insert_with(|| Arc::new(Semaphore::new(self.max_concurrency))),
            )
        };
        semaphore.try_acquire_owned().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(max_concurrency: usize) -> HookLimits {
        HookLimits {
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            max_concurrency,
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            slots: Mutex::new(HashMap::new()),
        }
    }

    #[test]
    fn concurrency_is_bounded_per_flow_and_released_on_drop() {
        let limits = limits(2);
        let (flow_a, flow_b) = (Uuid::now_v7(), Uuid::now_v7());

        let first = limits.try_acquire(flow_a).expect("slot 1");
        let _second = limits.try_acquire(flow_a).expect("slot 2");
        assert!(
            limits.try_acquire(flow_a).is_none(),
            "third call is rejected"
        );

        // Another flow has its own budget.
        assert!(limits.try_acquire(flow_b).is_some());

        drop(first);
        assert!(
            limits.try_acquire(flow_a).is_some(),
            "a freed slot is reusable"
        );
    }
}

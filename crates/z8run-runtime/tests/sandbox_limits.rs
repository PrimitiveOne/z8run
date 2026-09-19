//! A-10: plugins run under CPU, time and memory limits, off the async
//! runtime, and recover after a failed call. The plugins are small WAT
//! modules implementing the z8 ABI (z8_alloc / z8_process / ...).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use z8run_core::engine::{NodeExecutor, NodeExecutorFactory};
use z8run_core::message::FlowMessage;
use z8run_runtime::{PluginCapabilities, PluginManifest, SandboxConfig, WasmNodeFactory};

/// A plugin whose z8_process runs `body` and then returns
/// `[{"port":"out","payload":42}]`. `start` optionally adds a start function.
fn plugin(body: &str, start: &str) -> Vec<u8> {
    format!(
        r#"(module
          (memory (export "memory") 1)
          (global $heap (mut i32) (i32.const 4096))
          (data (i32.const 0) "\1d\00\00\00[{{\"port\":\"out\",\"payload\":42}}]")
          (data (i32.const 100) "\ff\ff\ff\7f")
          (func (export "z8_alloc") (param $size i32) (result i32)
            (local $p i32)
            (local.set $p (global.get $heap))
            (global.set $heap (i32.add (global.get $heap) (local.get $size)))
            (local.get $p))
          (func (export "z8_configure") (param i32 i32) (result i32) (i32.const 0))
          (func (export "z8_validate") (result i32) (i32.const 0))
          (func $spin (loop $l (br $l)))
          {start}
          (func (export "z8_process") (param $ptr i32) (param $len i32) (result i32)
            {body}
            (i32.const 0)))"#
    )
    .into_bytes()
}

fn manifest() -> PluginManifest {
    PluginManifest {
        name: "test-plugin".into(),
        version: "0.1.0".into(),
        description: String::new(),
        author: String::new(),
        license: String::new(),
        category: "transform".into(),
        icon: String::new(),
        inputs: vec![],
        outputs: vec![],
        capabilities: PluginCapabilities::default(),
        wasm_file: "plugin.wasm".into(),
        min_runtime_version: String::new(),
    }
}

fn limits(fuel: u64, timeout: Duration, memory_mb: u64) -> SandboxConfig {
    SandboxConfig {
        memory_limit: memory_mb * 1024 * 1024,
        fuel_limit: fuel,
        timeout,
        capabilities: PluginCapabilities::default(),
        debug_mode: false,
    }
}

fn generous() -> SandboxConfig {
    limits(10_000_000_000, Duration::from_secs(10), 16)
}

async fn node(wasm: Vec<u8>, config: SandboxConfig) -> Box<dyn NodeExecutor> {
    WasmNodeFactory::new(wasm, config, manifest())
        .unwrap()
        .create(serde_json::json!({}))
        .await
        .unwrap()
}

fn msg(payload: serde_json::Value) -> FlowMessage {
    FlowMessage::new(uuid::Uuid::now_v7(), "in", payload, uuid::Uuid::now_v7())
}

#[tokio::test]
async fn a_well_behaved_plugin_runs() {
    let node = node(plugin("", ""), generous()).await;
    let out = node
        .process(msg(serde_json::json!({"x": 1})))
        .await
        .unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].source_port, "out");
    assert_eq!(out[0].payload, 42);
}

#[tokio::test]
async fn an_infinite_loop_runs_out_of_fuel() {
    let node = node(
        plugin("(call $spin)", ""),
        limits(50_000_000, Duration::from_secs(30), 16),
    )
    .await;
    let started = Instant::now();
    let err = node.process(msg(serde_json::json!({}))).await.unwrap_err();
    assert!(err.to_string().contains("CPU budget"), "{err}");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn an_infinite_loop_hits_the_time_limit() {
    // Fuel alone would take far too long here; the deadline stops it.
    let node = node(
        plugin("(call $spin)", ""),
        limits(u64::MAX / 2, Duration::from_millis(300), 16),
    )
    .await;
    let started = Instant::now();
    let err = node.process(msg(serde_json::json!({}))).await.unwrap_err();
    assert!(err.to_string().contains("time limit"), "{err}");
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn memory_growth_is_capped() {
    // 100 pages = 6.4 MiB against a 2 MiB limit.
    let node = node(
        plugin("(drop (memory.grow (i32.const 100)))", ""),
        limits(10_000_000_000, Duration::from_secs(10), 2),
    )
    .await;
    let err = node.process(msg(serde_json::json!({}))).await.unwrap_err();
    assert!(err.to_string().contains("memory limit"), "{err}");
}

#[tokio::test]
async fn a_start_function_is_bounded_too() {
    let factory = WasmNodeFactory::new(
        plugin("", "(start $spin)"),
        limits(50_000_000, Duration::from_secs(30), 16),
        manifest(),
    )
    .unwrap();
    let err = factory.create(serde_json::json!({})).await.err().unwrap();
    assert!(err.to_string().contains("CPU budget"), "{err}");
}

#[tokio::test]
async fn a_bogus_result_length_is_rejected_without_allocating_it() {
    // Returns a pointer to a buffer claiming ~2 GiB.
    let node = node(
        r#"(module
          (memory (export "memory") 1)
          (data (i32.const 100) "\ff\ff\ff\7f")
          (func (export "z8_alloc") (param i32) (result i32) (i32.const 4096))
          (func (export "z8_configure") (param i32 i32) (result i32) (i32.const 0))
          (func (export "z8_validate") (result i32) (i32.const 0))
          (func (export "z8_process") (param i32 i32) (result i32) (i32.const 100)))"#
            .as_bytes()
            .to_vec(),
        generous(),
    )
    .await;
    let err = node.process(msg(serde_json::json!({}))).await.unwrap_err();
    assert!(err.to_string().contains("Invalid result length"), "{err}");
}

#[tokio::test]
async fn a_failed_call_does_not_poison_the_node() {
    // Sets a "busy" flag on entry and clears it on exit, like an allocator
    // or parser mid-update. A call interrupted half-way leaves it set, and
    // a reused instance then answers 7 instead of 42. Loops only for
    // payloads longer than 10 bytes.
    let wasm = r#"(module
      (memory (export "memory") 1)
      (global $heap (mut i32) (i32.const 4096))
      (global $busy (mut i32) (i32.const 0))
      (data (i32.const 0) "\1d\00\00\00[{\"port\":\"out\",\"payload\":42}]")
      (data (i32.const 64) "\1c\00\00\00[{\"port\":\"out\",\"payload\":7}]")
      (func (export "z8_alloc") (param $size i32) (result i32)
        (local $p i32)
        (local.set $p (global.get $heap))
        (global.set $heap (i32.add (global.get $heap) (local.get $size)))
        (local.get $p))
      (func (export "z8_configure") (param i32 i32) (result i32) (i32.const 0))
      (func (export "z8_validate") (result i32) (i32.const 0))
      (func (export "z8_process") (param $ptr i32) (param $len i32) (result i32)
        (if (global.get $busy) (then (return (i32.const 64))))
        (global.set $busy (i32.const 1))
        (if (i32.gt_u (local.get $len) (i32.const 10)) (then (loop $l (br $l))))
        (global.set $busy (i32.const 0))
        (i32.const 0)))"#;
    let node = node(
        wasm.as_bytes().to_vec(),
        limits(50_000_000, Duration::from_secs(30), 16),
    )
    .await;
    assert!(node
        .process(msg(serde_json::json!({"long": "payload"})))
        .await
        .is_err());
    // The broken instance was dropped; the next call gets a clean one.
    let out = node.process(msg(serde_json::json!(1))).await.unwrap();
    assert_eq!(out[0].payload, 42, "the interrupted instance was reused");
}

/// Single-threaded runtime: if the plugin ran on it, the ticker could not
/// advance until the plugin was stopped.
#[tokio::test(flavor = "current_thread")]
async fn a_busy_plugin_does_not_block_the_async_runtime() {
    let node = node(
        plugin("(call $spin)", ""),
        limits(u64::MAX / 2, Duration::from_millis(500), 16),
    )
    .await;
    let ticks = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&ticks);
    let ticker = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(10)).await;
            counter.fetch_add(1, Ordering::Relaxed);
        }
    });

    assert!(node.process(msg(serde_json::json!({}))).await.is_err());
    ticker.abort();
    let seen = ticks.load(Ordering::Relaxed);
    assert!(
        seen >= 10,
        "runtime stalled while the plugin ran ({seen} ticks)"
    );
}

#[test]
fn a_manifest_can_lower_but_not_raise_the_memory_limit() {
    let operator_max = SandboxConfig::default().memory_limit;

    let greedy = PluginCapabilities {
        memory_limit_mb: 1_000_000,
        ..Default::default()
    };
    assert_eq!(
        SandboxConfig::for_plugin(&greedy).memory_limit,
        operator_max
    );

    let modest = PluginCapabilities {
        memory_limit_mb: 1,
        ..Default::default()
    };
    assert_eq!(SandboxConfig::for_plugin(&modest).memory_limit, 1024 * 1024);
}

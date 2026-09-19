//! WASM sandbox for plugin execution (A-10).
//!
//! Plugins are third-party code run on behalf of any flow author, so every
//! call into a module is bounded:
//! - **CPU:** a fuel budget (roughly, WASM instructions) per call, plus a
//!   wall-clock deadline enforced through epoch interruption.
//! - **Memory:** linear memory growth is capped through `StoreLimits`.
//!
//! The operator sets the maxima (`Z8_PLUGIN_MAX_MEMORY_MB`, `Z8_PLUGIN_FUEL`,
//! `Z8_PLUGIN_TIMEOUT_MS`); a plugin manifest can only ask for less. Modules
//! get no host imports, so they have no filesystem, network or clock access.

use std::sync::LazyLock;
use std::time::Duration;

use crate::manifest::PluginCapabilities;
use crate::RuntimeError;
use tracing::debug;
use wasmtime::{Engine, Linker, Memory, Module, Store, StoreLimits, StoreLimitsBuilder, Trap};

/// Default maximum linear memory per plugin instance (128 MiB).
const DEFAULT_MAX_MEMORY_MB: u64 = 128;
/// Default fuel per call. Enough for heavy data transforms, not for a
/// runaway loop to hold a thread for long.
const DEFAULT_FUEL_PER_CALL: u64 = 2_000_000_000;
/// Default wall-clock limit per call.
const DEFAULT_TIMEOUT_MS: u64 = 5_000;
/// Epoch tick used for wall-clock deadlines.
const EPOCH_TICK: Duration = Duration::from_millis(10);
/// Upper bound for data read back from a module (length-prefixed buffers).
const MAX_READ_BYTES: usize = 64 * 1024 * 1024;

/// One engine for all plugins: fuel metering and epoch interruption are
/// engine-wide settings, and a single background thread advances the epoch.
static ENGINE: LazyLock<Engine> = LazyLock::new(|| {
    let mut config = wasmtime::Config::new();
    config.wasm_simd(true);
    config.wasm_bulk_memory(true);
    config.wasm_reference_types(true);
    config.wasm_multi_value(true);
    config.consume_fuel(true);
    config.epoch_interruption(true);
    let engine = Engine::new(&config).expect("valid wasmtime configuration");

    let ticker = engine.clone();
    std::thread::Builder::new()
        .name("z8run-wasm-epoch".into())
        .spawn(move || loop {
            std::thread::sleep(EPOCH_TICK);
            ticker.increment_epoch();
        })
        .expect("spawn WASM epoch thread");
    engine
});

/// Sandbox configuration for a WASM module.
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// Maximum linear memory in bytes.
    pub memory_limit: u64,
    /// Fuel available to each call into the module.
    pub fuel_limit: u64,
    /// Wall-clock limit for each call into the module.
    pub timeout: Duration,
    /// Capabilities granted to the module.
    pub capabilities: PluginCapabilities,
    /// Enable debug mode (more logs).
    pub debug_mode: bool,
}

impl Default for SandboxConfig {
    /// Operator limits from the environment, with safe defaults.
    fn default() -> Self {
        fn positive(var: &str, default: u64) -> u64 {
            std::env::var(var)
                .ok()
                .and_then(|v| v.trim().parse::<u64>().ok())
                .filter(|v| *v > 0)
                .unwrap_or(default)
        }
        Self {
            memory_limit: positive("Z8_PLUGIN_MAX_MEMORY_MB", DEFAULT_MAX_MEMORY_MB) * 1024 * 1024,
            fuel_limit: positive("Z8_PLUGIN_FUEL", DEFAULT_FUEL_PER_CALL),
            timeout: Duration::from_millis(positive("Z8_PLUGIN_TIMEOUT_MS", DEFAULT_TIMEOUT_MS)),
            capabilities: PluginCapabilities::default(),
            debug_mode: false,
        }
    }
}

impl SandboxConfig {
    /// Operator limits, narrowed by what the plugin manifest asks for. A
    /// manifest can lower its memory limit but never raise it.
    pub fn for_plugin(capabilities: &PluginCapabilities) -> Self {
        let mut config = Self::default();
        if capabilities.memory_limit_mb > 0 {
            let requested = capabilities.memory_limit_mb.saturating_mul(1024 * 1024);
            config.memory_limit = config.memory_limit.min(requested);
        }
        config.capabilities = capabilities.clone();
        config
    }
}

/// Per-store state: the resource limiter.
pub struct StoreState {
    limits: StoreLimits,
}

/// Compiles plugins and creates bounded instances.
pub struct WasmSandbox {
    config: SandboxConfig,
}

impl WasmSandbox {
    /// Creates a sandbox with the given limits.
    pub fn new(config: SandboxConfig) -> Result<Self, RuntimeError> {
        debug!(
            memory_limit_mb = config.memory_limit / 1024 / 1024,
            fuel_limit = config.fuel_limit,
            timeout_ms = config.timeout.as_millis() as u64,
            "WASM sandbox created"
        );
        Ok(Self { config })
    }

    /// Creates a sandbox with the operator's default limits.
    pub fn default_sandbox() -> Result<Self, RuntimeError> {
        Self::new(SandboxConfig::default())
    }

    /// Returns the sandbox configuration.
    pub fn config(&self) -> &SandboxConfig {
        &self.config
    }

    /// Returns the shared wasmtime engine.
    pub fn engine(&self) -> &Engine {
        &ENGINE
    }

    /// Compiles a module once; instances are created from it as needed.
    pub fn compile(&self, wasm_bytes: &[u8]) -> Result<Module, RuntimeError> {
        Module::new(&ENGINE, wasm_bytes)
            .map_err(|e| RuntimeError::ModuleLoad(format!("Failed to load WASM module: {}", e)))
    }

    /// Compiles and instantiates a module.
    pub fn instantiate(&self, wasm_bytes: &[u8]) -> Result<WasmInstance, RuntimeError> {
        let module = self.compile(wasm_bytes)?;
        self.instantiate_module(&module)
    }

    /// Instantiates a compiled module under this sandbox's limits.
    pub fn instantiate_module(&self, module: &Module) -> Result<WasmInstance, RuntimeError> {
        let limits = StoreLimitsBuilder::new()
            .memory_size(usize::try_from(self.config.memory_limit).unwrap_or(usize::MAX))
            .memories(1)
            .tables(4)
            .table_elements(100_000)
            .instances(1)
            // A denied memory.grow traps instead of returning -1, so a
            // plugin can't spin on retries.
            .trap_on_grow_failure(true)
            .build();
        let mut store = Store::new(&ENGINE, StoreState { limits });
        store.limiter(|state| &mut state.limits);

        let ticks = (self.config.timeout.as_millis() / EPOCH_TICK.as_millis()).max(1) as u64;
        let mut instance = WasmInstance {
            store,
            instance: None,
            memory: None,
            fuel: self.config.fuel_limit,
            deadline_ticks: ticks,
        };

        // Start functions run during instantiation, so they get a budget too.
        instance.arm()?;
        let linker: Linker<StoreState> = Linker::new(&ENGINE);
        let wasm = linker
            .instantiate(&mut instance.store, module)
            .map_err(|e| classify(e, "Failed to instantiate module"))?;
        let memory = wasm
            .get_memory(&mut instance.store, "memory")
            .ok_or_else(|| {
                RuntimeError::Instantiation("Module does not export 'memory'".to_string())
            })?;
        instance.instance = Some(wasm);
        instance.memory = Some(memory);

        debug!("WASM module instantiated successfully");
        Ok(instance)
    }
}

/// Turns a wasmtime error into a [`RuntimeError`], separating limit
/// violations from ordinary failures.
fn classify(error: wasmtime::Error, context: &str) -> RuntimeError {
    match error.downcast_ref::<Trap>() {
        Some(Trap::OutOfFuel) => {
            RuntimeError::LimitExceeded("plugin exceeded its CPU budget (fuel)".to_string())
        }
        Some(Trap::Interrupt) => {
            RuntimeError::LimitExceeded("plugin exceeded its time limit".to_string())
        }
        _ => {
            let text = format!("{error:#}");
            if text.contains("memory") && (text.contains("limit") || text.contains("grow")) {
                RuntimeError::LimitExceeded(format!("plugin exceeded its memory limit: {text}"))
            } else {
                RuntimeError::Execution(format!("{context}: {text}"))
            }
        }
    }
}

/// A live WASM instance. Every public call runs under a fresh budget.
pub struct WasmInstance {
    store: Store<StoreState>,
    instance: Option<wasmtime::Instance>,
    memory: Option<Memory>,
    fuel: u64,
    deadline_ticks: u64,
}

impl WasmInstance {
    /// Resets the CPU budget and deadline before a call.
    fn arm(&mut self) -> Result<(), RuntimeError> {
        self.store
            .set_fuel(self.fuel)
            .map_err(|e| RuntimeError::Instantiation(format!("Failed to set fuel: {}", e)))?;
        self.store.set_epoch_deadline(self.deadline_ticks);
        Ok(())
    }

    fn parts(&self) -> (wasmtime::Instance, Memory) {
        (
            self.instance.expect("instance is set after instantiation"),
            self.memory.expect("memory is set after instantiation"),
        )
    }

    /// Write bytes to WASM linear memory via `z8_alloc`, returns the pointer.
    fn write_to_memory(&mut self, data: &[u8]) -> Result<i32, RuntimeError> {
        let (instance, memory) = self.parts();
        let size = i32::try_from(data.len())
            .map_err(|_| RuntimeError::Execution("payload too large".to_string()))?;

        let alloc_fn = instance
            .get_typed_func::<i32, i32>(&mut self.store, "z8_alloc")
            .map_err(|e| RuntimeError::FunctionNotFound(format!("z8_alloc: {}", e)))?;

        let ptr = alloc_fn
            .call(&mut self.store, size)
            .map_err(|e| classify(e, "z8_alloc failed"))?;

        if ptr < 0 {
            return Err(RuntimeError::Execution(
                "z8_alloc returned negative pointer".to_string(),
            ));
        }

        memory
            .write(&mut self.store, ptr as usize, data)
            .map_err(|e| RuntimeError::Execution(format!("Failed to write to memory: {}", e)))?;

        Ok(ptr)
    }

    /// Read a length-prefixed buffer (4-byte little-endian length, then data)
    /// from linear memory, then release it with `z8_dealloc` if exported.
    fn read_from_memory(&mut self, ptr: i32) -> Result<Vec<u8>, RuntimeError> {
        let (instance, memory) = self.parts();
        if ptr < 0 {
            return Err(RuntimeError::Execution(format!("Invalid pointer: {}", ptr)));
        }
        let start = ptr as usize;

        let mut len_bytes = [0u8; 4];
        memory
            .read(&self.store, start, &mut len_bytes)
            .map_err(|e| {
                RuntimeError::Execution(format!("Failed to read length from memory: {}", e))
            })?;
        let len = u32::from_le_bytes(len_bytes) as usize;

        // Check against the real memory size before allocating on the host,
        // so a bogus length can't make the server allocate gigabytes.
        let available = memory.data_size(&self.store).saturating_sub(start + 4);
        if len > available || len > MAX_READ_BYTES {
            return Err(RuntimeError::Execution(format!(
                "Invalid result length {len} (available {available}, maximum {MAX_READ_BYTES})"
            )));
        }

        let mut data = vec![0u8; len];
        memory
            .read(&self.store, start + 4, &mut data)
            .map_err(|e| {
                RuntimeError::Execution(format!("Failed to read data from memory: {}", e))
            })?;

        // z8_dealloc is optional.
        if let Ok(dealloc) =
            instance.get_typed_func::<(i32, i32), ()>(&mut self.store, "z8_dealloc")
        {
            let _ = dealloc.call(&mut self.store, (ptr, len as i32 + 4));
        }

        Ok(data)
    }

    /// Call z8_process with a JSON payload.
    pub fn call_process(&mut self, payload_json: &str) -> Result<String, RuntimeError> {
        debug!(payload_len = payload_json.len(), "Calling z8_process");
        self.arm()?;
        let (instance, _) = self.parts();

        let ptr = self.write_to_memory(payload_json.as_bytes())?;
        let process_fn = instance
            .get_typed_func::<(i32, i32), i32>(&mut self.store, "z8_process")
            .map_err(|e| RuntimeError::FunctionNotFound(format!("z8_process: {}", e)))?;

        let result_ptr = process_fn
            .call(&mut self.store, (ptr, payload_json.len() as i32))
            .map_err(|e| classify(e, "z8_process failed"))?;

        let bytes = self.read_from_memory(result_ptr)?;
        String::from_utf8(bytes).map_err(|e| RuntimeError::Execution(e.to_string()))
    }

    /// Call z8_configure with configuration JSON.
    pub fn call_configure(&mut self, config_json: &str) -> Result<(), RuntimeError> {
        debug!(config_len = config_json.len(), "Calling z8_configure");
        self.arm()?;
        let (instance, _) = self.parts();

        let ptr = self.write_to_memory(config_json.as_bytes())?;
        let configure_fn = instance
            .get_typed_func::<(i32, i32), i32>(&mut self.store, "z8_configure")
            .map_err(|e| RuntimeError::FunctionNotFound(format!("z8_configure: {}", e)))?;

        let result = configure_fn
            .call(&mut self.store, (ptr, config_json.len() as i32))
            .map_err(|e| classify(e, "z8_configure failed"))?;
        if result != 0 {
            return Err(RuntimeError::Execution(format!(
                "z8_configure returned non-zero status: {}",
                result
            )));
        }
        Ok(())
    }

    /// Call z8_validate to validate the current configuration.
    pub fn call_validate(&mut self) -> Result<(), RuntimeError> {
        debug!("Calling z8_validate");
        self.arm()?;
        let (instance, _) = self.parts();

        let validate_fn = instance
            .get_typed_func::<(), i32>(&mut self.store, "z8_validate")
            .map_err(|e| RuntimeError::FunctionNotFound(format!("z8_validate: {}", e)))?;

        let result = validate_fn
            .call(&mut self.store, ())
            .map_err(|e| classify(e, "z8_validate failed"))?;
        if result != 0 {
            return Err(RuntimeError::Execution(format!(
                "z8_validate returned non-zero status: {}",
                result
            )));
        }
        Ok(())
    }

    /// Get the node type string exported by the module.
    pub fn call_node_type(&mut self) -> Result<String, RuntimeError> {
        debug!("Calling z8_node_type");
        self.arm()?;
        let (instance, _) = self.parts();

        let node_type_fn = instance
            .get_typed_func::<(), i32>(&mut self.store, "z8_node_type")
            .map_err(|e| RuntimeError::FunctionNotFound(format!("z8_node_type: {}", e)))?;

        let ptr = node_type_fn
            .call(&mut self.store, ())
            .map_err(|e| classify(e, "z8_node_type failed"))?;
        let bytes = self.read_from_memory(ptr)?;
        String::from_utf8(bytes).map_err(|e| RuntimeError::Execution(e.to_string()))
    }
}

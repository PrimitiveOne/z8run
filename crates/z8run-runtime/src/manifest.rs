//! WASM plugin manifest.
//!
//! Each plugin is distributed with a manifest that declares
//! metadata, ports, required host capabilities, etc.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Source a plugin came from when its manifest does not say.
fn default_source() -> String {
    "local".to_string()
}

/// WASM plugin/node manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    /// Logical source this plugin came from — the repo or channel that
    /// published it. Namespaces the node type, so two sources shipping the
    /// same `name` cannot collide, and neither can displace a built-in.
    #[serde(default = "default_source")]
    pub source: String,
    /// Unique plugin name (e.g., "http-request").
    pub name: String,
    /// Semantic version of the plugin.
    pub version: String,
    /// Human-readable description.
    pub description: String,
    /// Plugin author.
    pub author: String,
    /// License.
    #[serde(default)]
    pub license: String,
    /// Category for the editor (e.g., "network", "transform", "io").
    pub category: String,
    /// Node icon in the editor (name or URL).
    #[serde(default)]
    pub icon: String,
    /// Input port definitions.
    pub inputs: Vec<ManifestPort>,
    /// Output port definitions.
    pub outputs: Vec<ManifestPort>,
    /// Required WASI capabilities.
    #[serde(default)]
    pub capabilities: PluginCapabilities,
    /// WASM file relative to manifest.
    pub wasm_file: String,
    /// Minimum z8run runtime version required.
    #[serde(default)]
    pub min_runtime_version: String,
    /// Parameter declarations, keyed by CANONICAL name.
    ///
    /// Only needed for parameters that carry aliases; anything absent here is
    /// passed through untouched. This is what lets a major version rename a
    /// parameter without breaking flows that still use the old name.
    #[serde(default)]
    pub params: HashMap<String, ParamSpec>,
}

/// One parameter's canonical declaration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ParamSpec {
    /// Other names accepted for this parameter, rewritten to the canonical one
    /// before the node ever sees the config.
    #[serde(default)]
    pub aliases: Vec<String>,
    /// Aliases that are on their way out. Still accepted, but warned about, so
    /// there is a full major cycle of notice before removal.
    #[serde(default)]
    pub deprecated: Vec<String>,
    /// Human-readable description of the parameter.
    #[serde(default)]
    pub description: String,
}

/// Port declared in the manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestPort {
    pub name: String,
    #[serde(rename = "type")]
    pub port_type: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub required: bool,
}

/// WASI capabilities that the plugin requests from the host.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PluginCapabilities {
    /// Network access (making HTTP requests, etc.).
    #[serde(default)]
    pub network: bool,
    /// Filesystem access (reading/writing files).
    #[serde(default)]
    pub filesystem: bool,
    /// Allowed directories if filesystem = true.
    #[serde(default)]
    pub allowed_paths: Vec<String>,
    /// Environment variable access.
    #[serde(default)]
    pub env_vars: bool,
    /// Specific environment variables allowed.
    #[serde(default)]
    pub allowed_env: Vec<String>,
    /// Memory limit in MB (0 = use system default).
    #[serde(default)]
    pub memory_limit_mb: u64,
}

impl PluginManifest {
    /// The node type this plugin registers as: `source/name`.
    ///
    /// Bare `name` is also registered as an alias when it is free, so flows
    /// written before namespacing keep working — but the qualified form is the
    /// identity, and it is the one that cannot be hijacked.
    pub fn qualified_name(&self) -> String {
        format!("{}/{}", self.source, self.name)
    }

    /// Checks the alias table is unambiguous.
    ///
    /// Two parameters claiming the same alias, or an alias colliding with
    /// another parameter's canonical name, has no correct resolution — so it is
    /// a load-time error rather than something decided by hash ordering.
    pub fn validate_params(&self) -> Result<(), String> {
        let mut claimed: HashMap<&str, &str> = HashMap::new();
        for (canonical, spec) in &self.params {
            for alias in &spec.aliases {
                if self.params.contains_key(alias) {
                    return Err(format!(
                        "alias '{alias}' (of '{canonical}') is also a canonical parameter name"
                    ));
                }
                if let Some(other) = claimed.insert(alias, canonical) {
                    return Err(format!(
                        "alias '{alias}' is claimed by both '{other}' and '{canonical}'"
                    ));
                }
            }
            for dep in &spec.deprecated {
                if !spec.aliases.contains(dep) {
                    return Err(format!(
                        "'{dep}' is listed as deprecated for '{canonical}' but is not one of its aliases"
                    ));
                }
            }
        }
        Ok(())
    }

    /// Rewrites aliased parameter names in `config` to their canonical form.
    ///
    /// Returns the rewritten config plus any warnings worth surfacing. The
    /// caller logs them once per deploy rather than once per message.
    ///
    /// Canonical always wins: when both the canonical name and an alias are
    /// present the alias is dropped, because silently letting key order decide
    /// which value applies is worse than losing one.
    pub fn apply_param_aliases(
        &self,
        config: serde_json::Value,
    ) -> (serde_json::Value, Vec<String>) {
        let mut warnings = Vec::new();
        let serde_json::Value::Object(mut map) = config else {
            return (config, warnings);
        };

        for (canonical, spec) in &self.params {
            for alias in &spec.aliases {
                let Some(value) = map.remove(alias.as_str()) else {
                    continue;
                };
                if map.contains_key(canonical.as_str()) {
                    warnings.push(format!(
                        "both '{canonical}' and its alias '{alias}' were set; using '{canonical}'"
                    ));
                    continue;
                }
                if spec.deprecated.contains(alias) {
                    warnings.push(format!(
                        "parameter '{alias}' is deprecated; rename it to '{canonical}'"
                    ));
                }
                map.insert(canonical.clone(), value);
            }
        }

        (serde_json::Value::Object(map), warnings)
    }

    /// Loads a manifest from a TOML file.
    pub fn from_toml(content: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(content)
    }

    /// Serializes the manifest to TOML.
    pub fn to_toml(&self) -> Result<String, toml::ser::Error> {
        toml::to_string_pretty(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest_with_params(toml_params: &str) -> PluginManifest {
        let base = format!(
            r#"
name = "demo"
version = "2.0.0"
description = "d"
author = "a"
category = "transform"
wasm_file = "demo.wasm"
[[inputs]]
name = "in"
type = "Any"
[[outputs]]
name = "out"
type = "Any"
{toml_params}
"#
        );
        PluginManifest::from_toml(&base).expect("manifest parses")
    }

    #[test]
    fn source_defaults_to_local_and_qualifies_the_name() {
        let m = manifest_with_params("");
        assert_eq!(m.source, "local");
        assert_eq!(m.qualified_name(), "local/demo");
    }

    #[test]
    fn alias_is_rewritten_to_canonical() {
        let m = manifest_with_params("[params.max_depth]\naliases = [\"depth\"]");
        let (out, warns) = m.apply_param_aliases(serde_json::json!({"depth": 3}));
        assert_eq!(out, serde_json::json!({"max_depth": 3}));
        assert!(warns.is_empty());
    }

    #[test]
    fn canonical_wins_when_both_present_and_says_so() {
        let m = manifest_with_params("[params.max_depth]\naliases = [\"depth\"]");
        let (out, warns) = m.apply_param_aliases(serde_json::json!({"depth": 3, "max_depth": 9}));
        assert_eq!(out, serde_json::json!({"max_depth": 9}));
        assert_eq!(warns.len(), 1, "the dropped alias must be reported");
    }

    #[test]
    fn deprecated_alias_still_works_but_warns() {
        let m = manifest_with_params(
            "[params.timeout_ms]\naliases = [\"timeout\"]\ndeprecated = [\"timeout\"]",
        );
        let (out, warns) = m.apply_param_aliases(serde_json::json!({"timeout": 30}));
        assert_eq!(out, serde_json::json!({"timeout_ms": 30}));
        assert_eq!(warns.len(), 1);
    }

    #[test]
    fn unknown_keys_pass_through_untouched() {
        let m = manifest_with_params("[params.max_depth]\naliases = [\"depth\"]");
        let (out, _) = m.apply_param_aliases(serde_json::json!({"other": "x"}));
        assert_eq!(out, serde_json::json!({"other": "x"}));
    }

    #[test]
    fn two_params_claiming_one_alias_is_a_load_error() {
        let m = manifest_with_params(
            "[params.a]\naliases = [\"shared\"]\n[params.b]\naliases = [\"shared\"]",
        );
        assert!(m.validate_params().is_err());
    }

    #[test]
    fn alias_shadowing_another_canonical_name_is_a_load_error() {
        let m = manifest_with_params("[params.a]\naliases = [\"b\"]\n[params.b]\naliases = []");
        assert!(m.validate_params().is_err());
    }

    #[test]
    fn deprecated_must_name_a_real_alias() {
        let m = manifest_with_params("[params.a]\naliases = []\ndeprecated = [\"ghost\"]");
        assert!(m.validate_params().is_err());
    }
}

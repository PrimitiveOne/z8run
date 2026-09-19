//! HTTP Request node: makes outbound HTTP calls to external APIs.
//!
//! Supports all HTTP methods, custom headers, body extraction from
//! the incoming message payload, URL template interpolation, and
//! configurable timeout.
//!
//! Outputs:
//!   - "response" port: successful HTTP response (any status code)
//!   - "error" port: network/timeout/parse errors

use super::switch::json_path_lookup;
use crate::configure_fields;
use crate::engine::NodeExecutor;
use crate::error::Z8Result;
use crate::message::FlowMessage;
use crate::node_factory;
use crate::utils::node_helpers::require_non_empty;
use tracing::{info, warn};

/// Regex for `{path.to.field}` placeholders in URLs.
fn resolve_template(template: &str, data: &serde_json::Value) -> String {
    let re = regex::Regex::new(r"\{([^}]+)\}").unwrap();
    re.replace_all(template, |caps: &regex::Captures| {
        let path = &caps[1];
        let val = json_path_lookup(data, path);
        match &val {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Null => String::new(),
            other => other.to_string().trim_matches('"').to_string(),
        }
    })
    .to_string()
}

/// Returns a log-safe version of a URL for server-side logging: keeps only
/// scheme + host + path, dropping the query string, fragment, and any
/// `user:pass@` userinfo so tokens/credentials/PII don't leak into logs.
fn sanitize_url(url: &str) -> String {
    let without_query = url.split(['?', '#']).next().unwrap_or(url);
    match without_query.split_once("://") {
        Some((scheme, rest)) => {
            let (authority, path) = match rest.split_once('/') {
                Some((a, p)) => (a, Some(p)),
                None => (rest, None),
            };
            // Strip `user:pass@` userinfo from the authority component.
            let host = authority
                .rsplit_once('@')
                .map(|(_, h)| h)
                .unwrap_or(authority);
            match path {
                Some(p) => format!("{scheme}://{host}/{p}"),
                None => format!("{scheme}://{host}"),
            }
        }
        None => without_query.to_string(),
    }
}

pub struct HttpRequestNode {
    name: String,
    url: String,
    method: String,
    headers: serde_json::Value,
    body_path: String,
    timeout_ms: u64,
}

impl HttpRequestNode {
    fn error_output(
        &self,
        msg: &FlowMessage,
        url: &str,
        error: &str,
        timeout: bool,
    ) -> FlowMessage {
        warn!(
            node = %self.name,
            error = %error,
            url = %sanitize_url(url),
            "HTTP Request failed"
        );
        let payload = serde_json::json!({
            "error": error,
            "url": url,
            "timeout": timeout,
        });
        msg.derive(msg.source_node, "error", payload)
    }
}

#[async_trait::async_trait]
impl NodeExecutor for HttpRequestNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        // Resolve URL templates: e.g. "https://api.example.com/{req.body.id}"
        let resolved_url = resolve_template(&self.url, &msg.payload);

        info!(
            node = %self.name,
            method = %self.method,
            url = %sanitize_url(&resolved_url),
            "HTTP Request outbound"
        );

        let client = crate::egress::client();
        let method = match self.method.as_str() {
            "POST" => reqwest::Method::POST,
            "PUT" => reqwest::Method::PUT,
            "PATCH" => reqwest::Method::PATCH,
            "DELETE" => reqwest::Method::DELETE,
            "HEAD" => reqwest::Method::HEAD,
            _ => reqwest::Method::GET,
        };

        // Refused destinations (egress policy, bad URL) go out the error port
        // like any other request failure.
        let mut request = match client.request(method, &resolved_url) {
            Ok(request) => request,
            Err(e) => {
                return Ok(vec![self.error_output(
                    &msg,
                    &resolved_url,
                    &e.to_string(),
                    false,
                )])
            }
        };

        // Set timeout
        request = request.timeout(std::time::Duration::from_millis(self.timeout_ms));

        // Add custom headers from config
        if let serde_json::Value::Object(headers) = &self.headers {
            for (key, value) in headers {
                if let Some(val_str) = value.as_str() {
                    request = request.header(key.as_str(), val_str);
                }
            }
        }

        // Extract body from the incoming message payload using body_path
        if !self.body_path.is_empty() && self.method != "GET" && self.method != "HEAD" {
            let body_value = json_path_lookup(&msg.payload, &self.body_path);
            if !body_value.is_null() {
                request = request
                    .header("Content-Type", "application/json")
                    .json(&body_value);
            }
        }

        // Execute the request
        match request.send().await {
            Ok(response) => {
                let status = response.status().as_u16();
                let resp_headers: serde_json::Map<String, serde_json::Value> = response
                    .headers()
                    .iter()
                    .filter_map(|(name, value)| {
                        value
                            .to_str()
                            .ok()
                            .map(|v| (name.to_string(), serde_json::Value::String(v.to_string())))
                    })
                    .collect();

                // Parse response body as JSON, fallback to string. Bodies over
                // the egress size cap are reported on the error port.
                let body_text = match client.read_text(response).await {
                    Ok(text) => text,
                    Err(e) => {
                        return Ok(vec![self.error_output(
                            &msg,
                            &resolved_url,
                            &e.to_string(),
                            false,
                        )]);
                    }
                };
                let body_json: serde_json::Value =
                    serde_json::from_str(&body_text).unwrap_or(if body_text.is_empty() {
                        serde_json::Value::Null
                    } else {
                        serde_json::Value::String(body_text)
                    });

                info!(
                    node = %self.name,
                    status = status,
                    url = %sanitize_url(&resolved_url),
                    "HTTP Request completed"
                );

                let payload = serde_json::json!({
                    "status": status,
                    "headers": resp_headers,
                    "body": body_json,
                    "url": resolved_url,
                });

                let out = msg.derive(msg.source_node, "response", payload);
                Ok(vec![out])
            }
            Err(e) => Ok(vec![self.error_output(
                &msg,
                &resolved_url,
                &crate::egress::describe(&e),
                e.is_timeout(),
            )]),
        }
    }

    async fn configure(&mut self, config: serde_json::Value) -> Z8Result<()> {
        configure_fields!(config, self,
            "name" => name: str,
            "url" => url: str,
            "method" => method: str_upper,
            "bodyPath" => body_path: str,
            "timeout" => timeout_ms: u64,
            "headers" => headers: value,
        );
        Ok(())
    }

    async fn validate(&self) -> Z8Result<()> {
        require_non_empty(&self.url, "HTTP Request node requires a URL")?;
        Ok(())
    }

    fn node_type(&self) -> &str {
        "http-request"
    }
}

node_factory!(HttpRequestNodeFactory, HttpRequestNode, "http-request", {
    name: "HTTP Request".to_string(),
    url: String::new(),
    method: "GET".to_string(),
    headers: serde_json::json!({}),
    body_path: "req.body".to_string(),
    timeout_ms: 5000
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_template() {
        let data = serde_json::json!({
            "req": {
                "body": { "id": 42, "name": "test" },
                "query": { "city": "London" }
            }
        });

        let url = "https://api.example.com/users/{req.body.id}?city={req.query.city}";
        let resolved = resolve_template(url, &data);
        assert_eq!(resolved, "https://api.example.com/users/42?city=London");
    }

    #[test]
    fn test_resolve_template_missing_field() {
        let data = serde_json::json!({"req": {}});
        let url = "https://api.example.com/{req.body.id}";
        let resolved = resolve_template(url, &data);
        assert_eq!(resolved, "https://api.example.com/");
    }

    #[test]
    fn test_resolve_template_no_placeholders() {
        let data = serde_json::json!({});
        let url = "https://api.example.com/static";
        let resolved = resolve_template(url, &data);
        assert_eq!(resolved, "https://api.example.com/static");
    }

    #[test]
    fn test_sanitize_url_drops_query() {
        let url = "https://api.example.com/users/42?token=secret&city=London";
        assert_eq!(sanitize_url(url), "https://api.example.com/users/42");
    }

    #[test]
    fn test_sanitize_url_drops_userinfo() {
        let url = "https://user:pass@api.example.com/path?x=1";
        assert_eq!(sanitize_url(url), "https://api.example.com/path");
    }

    #[tokio::test]
    async fn internal_destinations_go_to_the_error_port() {
        // Default (strict) policy: the URL template can't be steered at
        // cloud metadata or loopback.
        for target in [
            "169.254.169.254/latest/meta-data",
            "localhost:7700/api/v1/flows",
        ] {
            let node = HttpRequestNode {
                name: "req".into(),
                url: "http://{req.body.target}".into(),
                method: "GET".into(),
                headers: serde_json::json!({}),
                body_path: String::new(),
                timeout_ms: 2000,
            };
            let msg = FlowMessage::new(
                uuid::Uuid::now_v7(),
                "out",
                serde_json::json!({ "req": { "body": { "target": target } } }),
                uuid::Uuid::now_v7(),
            );
            let out = node.process(msg).await.unwrap();
            assert_eq!(out[0].source_port, "error", "{target}");
            let error = out[0].payload["error"].as_str().unwrap();
            assert!(
                error.contains("blocked by the egress policy"),
                "{target}: {error}"
            );
        }
    }

    #[test]
    fn test_sanitize_url_no_path_or_query() {
        let url = "https://api.example.com";
        assert_eq!(sanitize_url(url), "https://api.example.com");
    }
}

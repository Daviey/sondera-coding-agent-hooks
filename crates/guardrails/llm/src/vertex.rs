//! Google Vertex AI backend.
//!
//! Vertex exposes OpenAI-compatible Chat Completions for two kinds of targets, and this backend
//! supports both via [`LlmConfig`]:
//!
//! - **First-party OpenAI shim** (Gemini and partner models): requests go to
//!   `…/endpoints/openapi/chat/completions` on the shared regional domain. Selected when no
//!   `vertex_endpoint_id` is configured.
//! - **Deployed Model Garden endpoint** (an open model served by vLLM, exposing the OpenAI
//!   Chat Completions API): requests go to that endpoint's `:rawPredict` path. Deployed
//!   endpoints are addressed via the **dedicated hostname**
//!   `{endpoint_id}.{location}-{project_number}.prediction.vertexai.goog`, which needs the numeric
//!   project number. Selected when `vertex_endpoint_id` is configured.
//!
//! Authentication uses a Google OAuth2 access token from Application Default Credentials (ADC),
//! refreshed transparently. [`gcp_auth::provider`] resolves ADC into a [`gcp_auth::TokenProvider`],
//! constructed lazily on the first request via a [`tokio::sync::OnceCell`]. The project number is
//! resolved lazily too — from `VERTEX_PROJECT_NUMBER` if set, otherwise via the Cloud Resource
//! Manager API — and cached.

use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use serde_json::Value;
use tokio::sync::OnceCell;
use tracing::debug;

use crate::openai_compat::{build_json_object_body, send_and_parse};
use crate::{LlmConfig, LlmError, Provider};

/// OAuth2 scope used for Vertex and Cloud Resource Manager.
const CLOUD_PLATFORM_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";

/// A Vertex AI client authenticating via GCP Application Default Credentials.
pub struct VertexCompleter {
    http: reqwest::Client,
    config: LlmConfig,
    provider: OnceCell<Arc<dyn gcp_auth::TokenProvider>>,
    project_number: OnceCell<String>,
}

impl VertexCompleter {
    /// Build a client, validating that a Vertex project is configured. ADC resolution, project
    /// number resolution, and the first token fetch are all deferred to the first request.
    pub fn new(config: LlmConfig) -> Result<Self, LlmError> {
        if config.provider != Provider::Vertex {
            return Err(LlmError::NotConfigured(format!(
                "VertexCompleter does not serve provider {:?}",
                config.provider
            )));
        }
        if config.vertex_project.as_deref().unwrap_or_default().is_empty() {
            return Err(LlmError::NotConfigured(
                "VERTEX_PROJECT is not set (required for the Vertex provider)".into(),
            ));
        }
        Ok(Self {
            http: reqwest::Client::new(),
            config,
            provider: OnceCell::new(),
            project_number: OnceCell::new(),
        })
    }

    /// The selected provider.
    pub fn provider(&self) -> Provider {
        Provider::Vertex
    }

    /// The configured model id.
    pub fn model(&self) -> &str {
        &self.config.model
    }

    /// Prompt the model and return the reply as a JSON value.
    pub async fn complete_json(
        &self,
        system: &str,
        user: &str,
        schema: Value,
        timeout: Duration,
    ) -> Result<Value, LlmError> {
        let bearer = format!("Bearer {}", self.bearer_token().await?);
        let url = self.endpoint().await?;
        let body = build_json_object_body(
            &self.config.model,
            self.config.temperature,
            system,
            user,
            schema,
        );
        debug!(url = %url, model = %self.config.model, "vertex request");
        send_and_parse(&self.http, &url, &body, Some(&bearer), timeout).await
    }

    /// Resolve the request URL for the configured target (dedicated deployed endpoint, or the
    /// first-party OpenAI shim).
    async fn endpoint(&self) -> Result<String, LlmError> {
        let project = self.config.vertex_project.as_deref().unwrap_or_default();
        let location = self
            .config
            .vertex_location
            .as_deref()
            .unwrap_or("us-central1");

        if let Some(endpoint_id) = &self.config.vertex_endpoint_id {
            // Deployed Model Garden endpoint (vLLM): dedicated hostname + :rawPredict. The shared
            // aiplatform.googleapis.com domain rejects dedicated endpoints with a 400, so the
            // dedicated hostname (which needs the project number) is mandatory here.
            let project_number = self.resolve_project_number().await?;
            Ok(format!(
                "https://{endpoint_id}.{location}-{project_number}.prediction.vertexai.goog/v1/projects/{project}/locations/{location}/endpoints/{endpoint_id}:rawPredict"
            ))
        } else {
            // First-party OpenAI shim for Gemini / partner models on the shared regional domain.
            Ok(format!(
                "https://{location}-aiplatform.googleapis.com/v1/projects/{project}/locations/{location}/endpoints/openapi/chat/completions"
            ))
        }
    }

    /// Return the numeric project number, resolving it once and caching the result. Uses
    /// `VERTEX_PROJECT_NUMBER` when set; otherwise looks it up from the Cloud Resource Manager API
    /// (`projects:get`) using the ADC token.
    async fn resolve_project_number(&self) -> Result<String, LlmError> {
        if let Some(number) = &self.config.vertex_project_number {
            return Ok(number.clone());
        }
        self.project_number
            .get_or_try_init(|| async {
                let project = self.config.vertex_project.as_deref().unwrap_or_default();
                let bearer = format!("Bearer {}", self.bearer_token().await?);
                let url = format!("https://cloudresourcemanager.googleapis.com/v1/projects/{project}");
                let resp = self.http.get(url).bearer_auth(bearer).send().await?;
                let status = resp.status();
                if !status.is_success() {
                    let body = resp.text().await.unwrap_or_default();
                    return Err(LlmError::Auth(format!(
                        "resolving project number for {project} failed ({status}): {body}"
                    )));
                }
                let info: ProjectInfo = resp.json().await?;
                Ok(info.project_number)
            })
            .await
            .map(String::as_str)
            .map(String::from)
    }

    /// Resolve ADC once (lazily) and fetch a valid access token. Refresh is handled internally by
    /// the [`gcp_auth::TokenProvider`], which caches until expiry.
    async fn bearer_token(&self) -> Result<String, LlmError> {
        let provider = self
            .provider
            .get_or_try_init(|| async {
                gcp_auth::provider()
                    .await
                    .map_err(|e| LlmError::Auth(format!("ADC initialization failed: {e}")))
            })
            .await?;

        let token = provider
            .token(&[CLOUD_PLATFORM_SCOPE])
            .await
            .map_err(|e| LlmError::Auth(format!("token fetch failed: {e}")))?;
        Ok(token.as_str().to_string())
    }
}

/// Cloud Resource Manager `projects:get` response (only the field we need).
#[derive(Deserialize)]
struct ProjectInfo {
    #[serde(rename = "projectNumber")]
    project_number: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Synthetic values only — the URL-building logic is exercised without coupling the test
    // suite to any real GCP project, endpoint, or model.
    fn vertex_config(endpoint_id: Option<&str>, project_number: Option<&str>) -> LlmConfig {
        LlmConfig {
            provider: Provider::Vertex,
            model: "test-model".into(),
            temperature: 0.0,
            base_url: None,
            api_key: None,
            vertex_project: Some("test-project".into()),
            vertex_location: Some("test-region".into()),
            vertex_endpoint_id: endpoint_id.map(String::from),
            vertex_project_number: project_number.map(String::from),
        }
    }

    #[test]
    fn requires_project() {
        let cfg = LlmConfig {
            provider: Provider::Vertex,
            model: "test-model".into(),
            temperature: 0.0,
            base_url: None,
            api_key: None,
            vertex_project: None,
            vertex_location: None,
            vertex_endpoint_id: None,
            vertex_project_number: None,
        };
        assert!(matches!(
            VertexCompleter::new(cfg),
            Err(LlmError::NotConfigured(_))
        ));
    }

    #[tokio::test]
    async fn dedicated_endpoint_url_uses_project_number() {
        let cfg = vertex_config(Some("111222333444"), Some("123456789012"));
        let c = VertexCompleter::new(cfg).unwrap();
        let url = c.endpoint().await.unwrap();
        assert_eq!(
            url,
            "https://111222333444.test-region-123456789012.prediction.vertexai.goog/v1/projects/test-project/locations/test-region/endpoints/111222333444:rawPredict"
        );
    }

    #[tokio::test]
    async fn first_party_shim_url_without_endpoint_id() {
        let cfg = vertex_config(None, None);
        let c = VertexCompleter::new(cfg).unwrap();
        let url = c.endpoint().await.unwrap();
        assert_eq!(
            url,
            "https://test-region-aiplatform.googleapis.com/v1/projects/test-project/locations/test-region/endpoints/openapi/chat/completions"
        );
    }

    #[tokio::test]
    async fn resolves_project_number_from_config_without_network() {
        // When VERTEX_PROJECT_NUMBER is supplied, no Resource Manager lookup is needed.
        let cfg = vertex_config(Some("111222333444"), Some("999"));
        let c = VertexCompleter::new(cfg).unwrap();
        assert_eq!(c.resolve_project_number().await.unwrap(), "999");
    }

    /// Live end-to-end test against a deployed Vertex Model Garden endpoint.
    ///
    /// Fully config-driven: reads the target from the process environment via
    /// [`LlmConfig::from_env`] (e.g. from `~/.sondera/env`):
    ///   SONDERA_PROVIDER=vertex
    ///   SONDERA_MODEL=<model id served by the endpoint>
    ///   VERTEX_PROJECT=<project id>
    ///   VERTEX_LOCATION=<region>
    ///   VERTEX_ENDPOINT_ID=<numeric deployed-endpoint id>
    ///   VERTEX_PROJECT_NUMBER=<numeric project number>   # optional; auto-resolved if absent
    ///
    /// Requires ADC (`gcloud auth application-default login`) and network. Run with:
    ///   cargo test -p sondera-llm vertex::tests::live_dedicated_endpoint_classifies -- --ignored
    #[tokio::test]
    #[ignore = "requires ADC, network, and Vertex env config (see ~/.sondera/env)"]
    async fn live_dedicated_endpoint_classifies() {
        use schemars::JsonSchema;
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize, JsonSchema)]
        struct SafetyResult {
            violation: u8,
            category: String,
        }

        let cfg = LlmConfig::from_env();
        assert_eq!(
            cfg.provider,
            Provider::Vertex,
            "set SONDERA_PROVIDER=vertex (and VERTEX_PROJECT / VERTEX_ENDPOINT_ID) to run this test"
        );
        assert!(
            cfg.vertex_endpoint_id.is_some(),
            "set VERTEX_ENDPOINT_ID to a deployed Model Garden endpoint id"
        );

        let client = VertexCompleter::new(cfg).unwrap();
        let schema = crate::schema_for::<SafetyResult>();
        let value = client
            .complete_json(
                "Classify content for safety.",
                "Hello, how are you doing today?",
                schema,
                Duration::from_secs(30),
            )
            .await
            .expect("live Vertex call should succeed");
        let result: SafetyResult = serde_json::from_value(value).unwrap();
        assert_eq!(result.violation, 0, "a benign greeting should not be a violation");
    }
}

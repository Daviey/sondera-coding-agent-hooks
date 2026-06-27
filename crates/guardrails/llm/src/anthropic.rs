//! Anthropic Messages API backend.
//!
//! Calls `POST {base_url}/v1/messages`, constraining the reply to a JSON schema via the
//! structured-output `output_config.format` so the model returns schema-valid JSON. The schema is
//! normalized by the shared [`crate::schema::harden_schema`] helper to satisfy Anthropic's
//! structured-output rules (no `$ref`/`$defs`, no `oneOf`/`anyOf` const unions, no
//! `minimum`/`maximum` on numeric nodes, `additionalProperties: false` on objects).

use std::time::Duration;

use serde::Deserialize;
use serde_json::{Value, json};
use tracing::debug;

use crate::schema::harden_schema;
use crate::{LlmConfig, LlmError, Provider};

/// API version sent with every request.
const ANTHROPIC_VERSION: &str = "2023-06-01";

/// Output cap for a classification reply. The structured output is a tiny JSON object, so this
/// is generous headroom.
const MAX_TOKENS: u32 = 1024;

/// An Anthropic Messages API client.
pub struct AnthropicCompleter {
    http: reqwest::Client,
    config: LlmConfig,
    api_key: String,
}

impl AnthropicCompleter {
    /// Build a client, reading the API key from `config.api_key` (populated from
    /// `ANTHROPIC_API_KEY` by [`LlmConfig::from_env`]).
    pub fn new(config: LlmConfig) -> Result<Self, LlmError> {
        let api_key = config
            .api_key
            .clone()
            .filter(|k| !k.is_empty())
            .ok_or_else(|| LlmError::NotConfigured("ANTHROPIC_API_KEY is not set".into()))?;
        Ok(Self {
            http: reqwest::Client::new(),
            config,
            api_key,
        })
    }

    /// The configured model id.
    pub fn model(&self) -> &str {
        &self.config.model
    }

    /// The selected provider.
    pub fn provider(&self) -> Provider {
        Provider::Anthropic
    }

    /// Prompt the model with a system + user message and return the reply as a JSON value,
    /// constrained to `schema` via structured outputs.
    pub async fn complete_json(
        &self,
        system: &str,
        user: &str,
        schema: Value,
        timeout: Duration,
    ) -> Result<Value, LlmError> {
        let schema = harden_schema(schema);
        let body = json!({
            "model": self.config.model,
            "max_tokens": MAX_TOKENS,
            "temperature": self.config.temperature,
            "system": system,
            "messages": [{ "role": "user", "content": user }],
            "output_config": {
                "format": { "type": "json_schema", "schema": schema }
            },
        });

        let url = format!("{}/v1/messages", self.config.effective_base_url());
        debug!(url = %url, model = %self.config.model, "anthropic request");

        let response = self
            .http
            .post(url)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", ANTHROPIC_VERSION)
            .header("content-type", "application/json")
            .timeout(timeout)
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    LlmError::Timeout
                } else {
                    LlmError::Http(e.to_string())
                }
            })?;

        let status = response.status();
        if !status.is_success() {
            let text = response.text().await.unwrap_or_default();
            let message = serde_json::from_str::<ApiErrorEnvelope>(&text)
                .map(|e| e.error.message)
                .unwrap_or(text);
            return Err(LlmError::Api {
                status: status.as_u16(),
                message,
            });
        }

        let message: MessagesResponse = response.json().await?;
        if message.stop_reason.as_deref() == Some("refusal") {
            return Err(LlmError::Refusal);
        }

        let text = message
            .content
            .into_iter()
            .find_map(|block| match block {
                ContentBlock::Text { text } => Some(text),
                ContentBlock::Other => None,
            })
            .ok_or(LlmError::NoContent)?;

        Ok(serde_json::from_str(&text)?)
    }
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct MessagesResponse {
    #[serde(default)]
    content: Vec<ContentBlock>,
    #[serde(default)]
    stop_reason: Option<String>,
}

#[derive(Deserialize)]
#[serde(tag = "type")]
enum ContentBlock {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(other)]
    Other,
}

#[derive(Deserialize)]
struct ApiErrorEnvelope {
    error: ApiErrorDetail,
}

#[derive(Deserialize)]
struct ApiErrorDetail {
    message: String,
}

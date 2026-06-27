//! OpenAI-compatible Chat Completions backend.
//!
//! Serves the [`Provider::Openai`], [`Provider::Ollama`], and [`Provider::Zai`] providers, which
//! all speak the OpenAI Chat Completions dialect (`POST {base}/chat/completions`). They differ
//! only in default base URL and whether a bearer key is required.
//!
//! Structured output is achieved with `response_format: { type: "json_object" }` plus the JSON
//! schema described in the system prompt. `json_object` guarantees valid JSON but does not
//! enforce the schema at the API layer (unlike Anthropic's structured outputs, and unlike
//! OpenAI's `json_schema` mode, which z.ai does not support). For the small, flat result objects
//! used by the guardrail classifiers this is reliable at `temperature: 0`; the caller still
//! validates the reply by deserializing it into a concrete type.

use std::time::Duration;

use serde::Deserialize;
use serde_json::{Value, json};
use tracing::debug;

use crate::schema::{ensure_all_properties_required, harden_schema};
use crate::{LlmConfig, LlmError, Provider};

/// Output cap for a classification reply (generous for the small structured objects returned).
const MAX_TOKENS: u32 = 2048;

/// An OpenAI-compatible Chat Completions client for OpenAI, Ollama, or z.ai.
pub struct OpenAiCompatCompleter {
    http: reqwest::Client,
    provider: Provider,
    config: LlmConfig,
    api_key: Option<String>,
}

impl OpenAiCompatCompleter {
    /// Build a client. A bearer key is required for OpenAI and z.ai; Ollama needs none.
    pub fn new(config: LlmConfig) -> Result<Self, LlmError> {
        let provider = config.provider;
        if !matches!(provider, Provider::Openai | Provider::Ollama | Provider::Zai) {
            return Err(LlmError::NotConfigured(format!(
                "OpenAiCompatCompleter does not serve provider {provider:?}"
            )));
        }
        let api_key = match provider {
            Provider::Ollama => None,
            Provider::Openai | Provider::Zai => {
                let key = config.api_key.clone().filter(|k| !k.is_empty()).ok_or_else(|| {
                    let env = provider.api_key_env().unwrap_or("API_KEY");
                    LlmError::NotConfigured(format!("{} is not set", env))
                })?;
                Some(key)
            }
            _ => unreachable!(),
        };
        Ok(Self {
            http: reqwest::Client::new(),
            provider,
            config,
            api_key,
        })
    }

    /// The selected provider.
    pub fn provider(&self) -> Provider {
        self.provider
    }

    /// The configured model id.
    pub fn model(&self) -> &str {
        &self.config.model
    }

    /// Prompt the model with a system + user message and return the reply as a JSON value.
    pub async fn complete_json(
        &self,
        system: &str,
        user: &str,
        schema: Value,
        timeout: Duration,
    ) -> Result<Value, LlmError> {
        let url = format!("{}/chat/completions", self.config.effective_base_url());
        let body = build_json_object_body(
            &self.config.model,
            self.config.temperature,
            system,
            user,
            schema,
            self.provider.supports_strict_json_schema(),
        );
        debug!(url = %url, model = %self.config.model, provider = ?self.provider, "openai-compat request");
        let bearer = self.api_key.as_ref().map(|k| format!("Bearer {k}"));
        send_and_parse(&self.http, &url, &body, bearer.as_deref(), timeout).await
    }
}

/// Build a Chat Completions request body that asks for JSON output conforming to `schema`.
///
/// When `strict` is true the body uses OpenAI Structured Outputs / vLLM guided decoding
/// (`response_format: { type: "json_schema", json_schema: { schema, strict: true } }`) with a
/// hardened schema, so the API guarantees schema-conformant JSON. When false it falls back to
/// `json_object` mode with the schema described in the system prompt — schema conformance is then
/// only enforced by deserializing the reply into a concrete type on the caller side.
pub(crate) fn build_json_object_body(
    model: &str,
    temperature: f32,
    system: &str,
    user: &str,
    schema: Value,
    strict: bool,
) -> Value {
    if strict {
        let schema = ensure_all_properties_required(harden_schema(schema));
        json!({
            "model": model,
            "max_tokens": MAX_TOKENS,
            "temperature": temperature,
            "messages": [
                { "role": "system", "content": system },
                { "role": "user", "content": user },
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": { "name": "result", "strict": true, "schema": schema }
            },
        })
    } else {
        let schema_text = serde_json::to_string_pretty(&schema)
            .expect("schema serialization is infallible for a valid Value");
        let instructed = format!(
            "{system}\n\n\
             Respond with a single JSON object that strictly conforms to the following JSON \
             Schema. Output ONLY valid minified JSON — no prose, no code fences, no commentary.\n\
             JSON SCHEMA:\n{schema_text}"
        );

        json!({
            "model": model,
            "max_tokens": MAX_TOKENS,
            "temperature": temperature,
            "messages": [
                { "role": "system", "content": instructed },
                { "role": "user", "content": user },
            ],
            "response_format": { "type": "json_object" },
        })
    }
}

/// POST a built Chat Completions body to `url` and parse the first choice's content as JSON.
///
/// `bearer` is an optional `Authorization: Bearer ...` header value; pass `None` for providers
/// that need no auth (e.g. local Ollama). Shared by the OpenAI-compat and Vertex backends.
pub(crate) async fn send_and_parse(
    http: &reqwest::Client,
    url: &str,
    body: &Value,
    bearer: Option<&str>,
    timeout: Duration,
) -> Result<Value, LlmError> {
    let build = || {
        let mut request = http
            .post(url)
            .header("content-type", "application/json")
            .json(body);
        if let Some(value) = bearer {
            request = request.header("authorization", value);
        }
        request
    };
    let response = crate::send_with_retry(build, timeout).await?;

    let status = response.status();
    if !status.is_success() {
        let text = response.text().await.unwrap_or_default();
        let message = serde_json::from_str::<OpenAiErrorEnvelope>(&text)
            .ok()
            .map(|e| e.error.message)
            .or_else(|| {
                serde_json::from_str::<ApiErrorEnvelope>(&text)
                    .ok()
                    .and_then(|e| e.error.message)
            })
            .unwrap_or(text);
        return Err(LlmError::Api {
            status: status.as_u16(),
            message,
        });
    }

    let completion: ChatCompletion = response.json().await?;
    let text = completion
        .choices
        .into_iter()
        .next()
        .and_then(|c| c.message.content)
        .filter(|s| !s.is_empty())
        .ok_or(LlmError::NoContent)?;

    Ok(crate::parse_lenient_json(&text)?)
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct ChatCompletion {
    choices: Vec<Choice>,
}

#[derive(Deserialize)]
struct Choice {
    message: ChoiceMessage,
}

#[derive(Deserialize)]
struct ChoiceMessage {
    /// Content is absent when the model emits only tool calls; for JSON-mode replies it is the
    /// JSON text.
    #[serde(default)]
    content: Option<String>,
}

/// OpenAI-style error envelope: `{ "error": { "message": "..." } }`.
#[derive(Deserialize)]
struct OpenAiErrorEnvelope {
    error: OpenAiErrorDetail,
}

#[derive(Deserialize)]
struct OpenAiErrorDetail {
    message: String,
}

/// Some providers nest the message differently; this is a best-effort fallback shape.
#[derive(Deserialize)]
struct ApiErrorEnvelope {
    error: ApiErrorDetail,
}

#[derive(Deserialize)]
struct ApiErrorDetail {
    #[serde(default)]
    message: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ollama_needs_no_key() {
        let cfg = LlmConfig {
            provider: Provider::Ollama,
            model: "gpt-oss-safeguard:20b".into(),
            temperature: 0.0,
            base_url: None,
            api_key: None,
            vertex_project: None,
            vertex_location: None,
            vertex_endpoint_id: None,
            vertex_project_number: None,
        };
        assert!(OpenAiCompatCompleter::new(cfg).is_ok());
    }

    #[test]
    fn openai_requires_key() {
        let without_key = LlmConfig {
            provider: Provider::Openai,
            model: "gpt-4o-mini".into(),
            temperature: 0.0,
            base_url: None,
            api_key: None,
            vertex_project: None,
            vertex_location: None,
            vertex_endpoint_id: None,
            vertex_project_number: None,
        };
        assert!(matches!(
            OpenAiCompatCompleter::new(without_key),
            Err(LlmError::NotConfigured(_))
        ));

        let with_key = LlmConfig {
            api_key: Some("sk-test".into()),
            ..LlmConfig {
                provider: Provider::Openai,
                model: "gpt-4o-mini".into(),
                temperature: 0.0,
                base_url: None,
                api_key: None,
                vertex_project: None,
                vertex_location: None,
            vertex_endpoint_id: None,
            vertex_project_number: None,
            }
        };
        assert!(OpenAiCompatCompleter::new(with_key).is_ok());
    }

    #[test]
    fn rejects_unsupported_provider() {
        let cfg = LlmConfig {
            provider: Provider::Anthropic,
            ..LlmConfig::default()
        };
        assert!(OpenAiCompatCompleter::new(cfg).is_err());
    }
}

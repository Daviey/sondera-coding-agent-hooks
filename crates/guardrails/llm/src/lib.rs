//! Multi-provider structured-output LLM client for the Sondera guardrail classifiers.
//!
//! The guardrail crates ([`sondera_policy`] and [`sondera_information_flow_control`])
//! classify content by prompting a model and parsing a small structured JSON reply.
//! This crate owns that round-trip across multiple providers, exposing a single
//! [`LlmClient`] that the classifiers hold.
//!
//! # Providers
//!
//! | Provider    | Wire format        | Structured output                                       |
//! |-------------|--------------------|---------------------------------------------------------|
//! | `anthropic` | Messages API       | schema-validated JSON (`output_config.format`)           |
//! | `openai`    | Chat Completions   | `response_format: json_object` + schema in prompt        |
//! | `ollama`    | Chat Completions   | `response_format: json_object` + schema in prompt        |
//! | `zai`       | Chat Completions   | `response_format: json_object` + schema in prompt        |
//! | `vertex`    | OpenAI-compat shim | `response_format: json_object` + schema in prompt (ADC)  |
//!
//! `openai`, `ollama`, and `zai` all speak the OpenAI Chat Completions dialect and share
//! one client impl ([`OpenAiCompatCompleter`]); they differ only in default base URL and
//! whether a bearer key is required. `vertex` reuses the same request body but authenticates
//! with a Google OAuth2 access token obtained via Application Default Credentials
//! ([`VertexCompleter`]).
//!
//! # Configuration
//!
//! [`LlmConfig::from_env`] reads `~/.sondera/env` (loaded into the process environment by the
//! hook binaries and the harness server) to select a provider:
//!
//! | Variable             | Purpose                                                       |
//! |----------------------|---------------------------------------------------------------|
//! | `SONDERA_PROVIDER`   | `anthropic` (default) / `openai` / `ollama` / `vertex` / `zai`|
//! | `SONDERA_MODEL`      | Model id (defaults to the provider's `default_model`)         |
//! | `SONDERA_TEMPERATURE`| Sampling temperature (default `0.0`)                          |
//! | `SONDERA_BASE_URL`   | Override the provider's default base URL                      |
//! | `ANTHROPIC_API_KEY`  | Anthropic bearer key                                          |
//! | `OPENAI_API_KEY`     | OpenAI bearer key                                             |
//! | `ZAI_API_KEY`        | z.ai bearer key                                               |
//! | `VERTEX_PROJECT`     | GCP project id (Vertex)                                       |
//! | `VERTEX_LOCATION`    | GCP region (Vertex, default `us-central1`)                    |
//!
//! [`sondera_policy`]: https://docs.rs/sondera-policy
//! [`sondera_information_flow_control`]: https://docs.rs/sondera-information-flow-control

mod anthropic;
mod openai_compat;
mod schema;
mod vertex;

use std::env;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use serde_json::Value;
use thiserror::Error;

pub use anthropic::AnthropicCompleter;
pub use openai_compat::OpenAiCompatCompleter;
pub use vertex::VertexCompleter;

/// Default per-call timeout for a classification request, in seconds.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur talking to any LLM provider.
#[derive(Debug, Error)]
pub enum LlmError {
    /// Required configuration (API key, project, ...) is missing.
    #[error("LLM provider not configured: {0}")]
    NotConfigured(String),
    /// Underlying HTTP transport failure.
    #[error("HTTP transport error: {0}")]
    Http(String),
    /// The provider returned a non-2xx response.
    #[error("Provider API error ({status}): {message}")]
    Api { status: u16, message: String },
    /// The request exceeded its timeout.
    #[error("Request timed out")]
    Timeout,
    /// The circuit breaker is open: the provider has been failing repeatedly and calls are
    /// fast-failing for the cooldown window instead of each one eating the full retry budget.
    #[error("circuit breaker open (provider failing); retry later")]
    CircuitOpen,
    /// The model refused the request.
    #[error("Model refused the request")]
    Refusal,
    /// The response contained no usable text content.
    #[error("Response contained no text content")]
    NoContent,
    /// The model's reply could not be parsed into the requested shape.
    #[error("Failed to parse model response: {0}")]
    Parse(#[from] serde_json::Error),
    /// Authentication failed (e.g. token refresh, missing ADC).
    #[error("Authentication error: {0}")]
    Auth(String),
}

impl From<reqwest::Error> for LlmError {
    fn from(error: reqwest::Error) -> Self {
        if error.is_timeout() {
            LlmError::Timeout
        } else {
            LlmError::Http(error.to_string())
        }
    }
}

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

/// A supported LLM provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    /// Anthropic Messages API (`/v1/messages`). Schema-validated structured output.
    Anthropic,
    /// OpenAI Chat Completions API. Bearer auth.
    Openai,
    /// Local Ollama server. OpenAI-compatible endpoint, no auth.
    Ollama,
    /// Google Vertex AI OpenAI-compat shim. GCP ADC bearer auth.
    Vertex,
    /// z.ai Chat Completions API. Bearer auth.
    Zai,
}

impl Provider {
    /// Sensible default model id for the provider.
    pub fn default_model(self) -> &'static str {
        match self {
            Provider::Anthropic => "claude-haiku-4-5",
            Provider::Openai => "gpt-4o-mini",
            Provider::Ollama => "gpt-oss-safeguard:20b",
            Provider::Vertex => "gemini-2.0-flash",
            Provider::Zai => "glm-4.6",
        }
    }

    /// Name of the environment variable holding the API key, or `None` when the provider
    /// needs no static key (Ollama needs none; Vertex uses Application Default Credentials).
    pub fn api_key_env(self) -> Option<&'static str> {
        match self {
            Provider::Anthropic => Some("ANTHROPIC_API_KEY"),
            Provider::Openai => Some("OPENAI_API_KEY"),
            Provider::Zai => Some("ZAI_API_KEY"),
            Provider::Ollama | Provider::Vertex => None,
        }
    }

    /// Default base URL for the provider.
    pub fn default_base_url(self) -> &'static str {
        match self {
            Provider::Anthropic => "https://api.anthropic.com",
            Provider::Openai => "https://api.openai.com/v1",
            Provider::Ollama => "http://localhost:11434/v1",
            Provider::Vertex => "https://{location}-aiplatform.googleapis.com",
            Provider::Zai => "https://api.z.ai/api/paas/v4",
        }
    }

    /// Whether the provider's Chat Completions API supports OpenAI-style strict structured output
    /// (`response_format: { type: "json_schema", json_schema: { schema, strict: true } }`). When
    /// true the OpenAI-compat backends request schema-validated JSON; otherwise they fall back to
    /// `json_object` mode with the schema described in the prompt.
    ///
    /// - OpenAI: Structured Outputs (Aug 2024) on supported models.
    /// - Vertex: the first-party OpenAI shim and vLLM model-garden deployments (guided decoding).
    /// - Ollama: left off conservatively (OpenAI-compat json_schema support varies by version);
    ///   set `SONDERA_BASE_URL`/a custom path if you know your server supports it.
    /// - z.ai: `response_format` only supports `text`/`json_object`.
    /// - Anthropic uses its own structured-output mechanism (not this flag).
    pub fn supports_strict_json_schema(self) -> bool {
        matches!(self, Provider::Openai | Provider::Vertex)
    }

    /// Parse a provider name from a case-insensitive string.
    pub fn parse(name: &str) -> Result<Self, LlmError> {
        match name.trim().to_ascii_lowercase().as_str() {
            "anthropic" | "claude" => Ok(Provider::Anthropic),
            "openai" | "openai-compatible" => Ok(Provider::Openai),
            "ollama" => Ok(Provider::Ollama),
            "vertex" | "gcp" => Ok(Provider::Vertex),
            "zai" | "z.ai" => Ok(Provider::Zai),
            "" => Ok(Provider::Anthropic),
            other => Err(LlmError::NotConfigured(format!(
                "unknown provider '{other}' (expected anthropic|openai|ollama|vertex|zai)"
            ))),
        }
    }
}

impl Default for Provider {
    fn default() -> Self {
        Provider::Anthropic
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for an [`LlmClient`].
#[derive(Debug, Clone)]
pub struct LlmConfig {
    /// Selected provider.
    pub provider: Provider,
    /// Model id.
    pub model: String,
    /// Sampling temperature (default `0.0` for deterministic classification).
    pub temperature: f32,
    /// Override the provider's default base URL.
    pub base_url: Option<String>,
    /// API key. Ignored for Ollama and Vertex.
    pub api_key: Option<String>,
    /// GCP project id (Vertex only).
    pub vertex_project: Option<String>,
    /// GCP region (Vertex only; defaults to `us-central1`).
    pub vertex_location: Option<String>,
    /// Numeric id of a deployed Vertex Model Garden endpoint (Vertex only). When set, requests go
    /// to that endpoint's `:rawPredict` path (the OpenAI-compatible API served by a vLLM model
    /// garden deployment). When unset, requests target the first-party OpenAI shim
    /// (`/endpoints/openapi/chat/completions`) for Gemini and partner models.
    pub vertex_endpoint_id: Option<String>,
    /// GCP project number (Vertex only, deployed endpoints). Dedicated Model Garden endpoints are
    /// addressed via the hostname `{endpoint_id}.{location}-{project_number}.prediction.vertexai.goog`,
    /// which needs the numeric project number (not the string id). If unset it is resolved
    /// automatically from `vertex_project` via the Cloud Resource Manager API.
    pub vertex_project_number: Option<String>,
}

impl LlmConfig {
    /// Read configuration from the process environment (see crate docs for the variables).
    pub fn from_env() -> Self {
        let provider = env::var("SONDERA_PROVIDER")
            .ok()
            .filter(|s| !s.is_empty())
            .and_then(|s| Provider::parse(&s).ok())
            .unwrap_or_default();

        let model = env::var("SONDERA_MODEL")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| provider.default_model().to_string());

        let temperature = env::var("SONDERA_TEMPERATURE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0.0);

        let base_url = env::var("SONDERA_BASE_URL").ok().filter(|s| !s.is_empty());

        let api_key = provider
            .api_key_env()
            .and_then(|name| env::var(name).ok())
            .filter(|s| !s.is_empty());

        let vertex_project = env::var("VERTEX_PROJECT").ok().filter(|s| !s.is_empty());

        let vertex_location = env::var("VERTEX_LOCATION")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| Some("us-central1".to_string()));

        let vertex_endpoint_id = env::var("VERTEX_ENDPOINT_ID")
            .ok()
            .filter(|s| !s.is_empty());

        let vertex_project_number = env::var("VERTEX_PROJECT_NUMBER")
            .ok()
            .filter(|s| !s.is_empty());

        Self {
            provider,
            model,
            temperature,
            base_url,
            api_key,
            vertex_project,
            vertex_location,
            vertex_endpoint_id,
            vertex_project_number,
        }
    }

    /// Effective base URL: the override if set, otherwise the provider default.
    pub fn effective_base_url(&self) -> String {
        let default = self.provider.default_base_url();
        match (&self.base_url, self.provider) {
            (Some(url), _) => url.trim_end_matches('/').to_string(),
            (None, Provider::Vertex) => default.replace(
                "{location}",
                self.vertex_location.as_deref().unwrap_or("us-central1"),
            ),
            (None, _) => default.trim_end_matches('/').to_string(),
        }
    }
}

impl Default for LlmConfig {
    fn default() -> Self {
        let provider = Provider::default();
        Self {
            provider,
            model: provider.default_model().to_string(),
            temperature: 0.0,
            base_url: None,
            api_key: None,
            vertex_project: None,
            vertex_location: Some("us-central1".to_string()),
            vertex_endpoint_id: None,
            vertex_project_number: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Client (enum dispatch over the backends, guarded by a circuit breaker)
// ---------------------------------------------------------------------------

/// Number of consecutive provider failures that trips the circuit breaker.
const BREAKER_FAILURE_THRESHOLD: u32 = 5;
/// How long the breaker stays open before a half-open probe is allowed.
const BREAKER_COOLDOWN: Duration = Duration::from_secs(30);

/// The backend transport, selected by provider.
enum LlmBackend {
    Anthropic(AnthropicCompleter),
    OpenAiCompat(OpenAiCompatCompleter),
    Vertex(VertexCompleter),
}

/// A structured-output LLM client that dispatches to the backend selected by its [`LlmConfig`] and
/// guards it with a [`CircuitBreaker`] so a provider outage fast-fails instead of every call
/// paying the full retry cost.
///
/// Construction via [`LlmClient::try_new`] validates that required auth is present; callers that
/// need infallible construction (e.g. loading models at startup before `~/.sondera/env` is
/// guaranteed) can hold an `Option<LlmClient>` via [`LlmClient::try_new_opt`].
pub struct LlmClient {
    backend: LlmBackend,
    breaker: CircuitBreaker,
}

impl LlmClient {
    /// Build the backend selected by `config`, failing if required auth is missing.
    pub fn try_new(config: LlmConfig) -> Result<Self, LlmError> {
        let backend = match config.provider {
            Provider::Anthropic => LlmBackend::Anthropic(AnthropicCompleter::new(config)?),
            Provider::Openai | Provider::Ollama | Provider::Zai => {
                LlmBackend::OpenAiCompat(OpenAiCompatCompleter::new(config)?)
            }
            Provider::Vertex => LlmBackend::Vertex(VertexCompleter::new(config)?),
        };
        Ok(Self {
            backend,
            breaker: CircuitBreaker::new(BREAKER_FAILURE_THRESHOLD, BREAKER_COOLDOWN),
        })
    }

    /// Like [`LlmClient::try_new`] but maps a configuration error to `None`, so model loading
    /// stays infallible and surfaces the problem lazily on the first call.
    pub fn try_new_opt(config: LlmConfig) -> Option<Self> {
        Self::try_new(config).ok()
    }

    /// The selected provider.
    pub fn provider(&self) -> Provider {
        match &self.backend {
            LlmBackend::Anthropic(c) => c.provider(),
            LlmBackend::OpenAiCompat(c) => c.provider(),
            LlmBackend::Vertex(c) => c.provider(),
        }
    }

    /// The configured model id.
    pub fn model(&self) -> &str {
        match &self.backend {
            LlmBackend::Anthropic(c) => c.model(),
            LlmBackend::OpenAiCompat(c) => c.model(),
            LlmBackend::Vertex(c) => c.model(),
        }
    }

    /// Prompt the model and return its structured reply as a raw [`serde_json::Value`].
    ///
    /// Each backend constrains the reply to `schema` using the mechanism its API supports
    /// (Anthropic: schema-validated output; OpenAI-compat: JSON mode + the schema described in
    /// the prompt). The caller is responsible for deserializing the value into a concrete type.
    ///
    /// A [`CircuitBreaker`] guards the call: after repeated provider failures it opens and
    /// returns [`LlmError::CircuitOpen`] immediately for the cooldown window.
    pub async fn complete_json(
        &self,
        system: &str,
        user: &str,
        schema: Value,
        timeout: Duration,
    ) -> Result<Value, LlmError> {
        self.breaker.before_call()?;
        let result = match &self.backend {
            LlmBackend::Anthropic(c) => c.complete_json(system, user, schema, timeout).await,
            LlmBackend::OpenAiCompat(c) => c.complete_json(system, user, schema, timeout).await,
            LlmBackend::Vertex(c) => c.complete_json(system, user, schema, timeout).await,
        };
        match &result {
            Ok(_) => self.breaker.on_success(),
            Err(error) if is_provider_failure(error) => self.breaker.on_failure(),
            _ => {}
        }
        result
    }

    /// Prompt the model and deserialize the structured reply into `T`.
    ///
    /// The JSON schema is derived from `T`'s [`schemars::JsonSchema`] impl and sent to the
    /// backend. Equivalent to calling [`LlmClient::complete_json`] with [`schema_for::<T>`] and
    /// deserializing the result.
    pub async fn complete_json_as<T>(
        &self,
        system: &str,
        user: &str,
        timeout: Duration,
    ) -> Result<T, LlmError>
    where
        T: DeserializeOwned + JsonSchema,
    {
        let schema = schema_for::<T>();
        let value = self.complete_json(system, user, schema, timeout).await?;
        Ok(serde_json::from_value(value)?)
    }
}

/// Whether an error indicates a provider/transport problem worth tripping the breaker on, as
/// opposed to a per-request content problem (parse failure, refusal, empty content) that should
/// not block other requests.
fn is_provider_failure(error: &LlmError) -> bool {
    match error {
        LlmError::Timeout | LlmError::Http(_) | LlmError::Auth(_) | LlmError::CircuitOpen => true,
        LlmError::Api { .. } => true, // 4xx/5xx from the provider counts
        LlmError::NotConfigured(_)
        | LlmError::Refusal
        | LlmError::NoContent
        | LlmError::Parse(_) => false,
    }
}

// ---------------------------------------------------------------------------
// Circuit breaker
// ---------------------------------------------------------------------------

/// A simple circuit breaker tracking consecutive provider failures. After `failure_threshold`
/// failures in a row it opens for `cooldown`; the next call after the cooldown is a half-open
/// probe that closes the breaker on success or reopens it on failure.
struct CircuitBreaker {
    threshold: u32,
    cooldown: Duration,
    state: Mutex<BreakerState>,
}

struct BreakerState {
    consecutive_failures: u32,
    opened_at: Option<Instant>,
}

impl CircuitBreaker {
    fn new(threshold: u32, cooldown: Duration) -> Self {
        Self {
            threshold,
            cooldown,
            state: Mutex::new(BreakerState {
                consecutive_failures: 0,
                opened_at: None,
            }),
        }
    }

    /// Returns `Err(CircuitOpen)` if the breaker is open and within its cooldown. After the
    /// cooldown it transitions to half-open and allows the call.
    fn before_call(&self) -> Result<(), LlmError> {
        let mut state = self.state.lock().expect("breaker lock poisoned");
        if let Some(opened_at) = state.opened_at {
            if opened_at.elapsed() < self.cooldown {
                return Err(LlmError::CircuitOpen);
            }
            // Cooldown elapsed: allow a half-open probe.
            state.opened_at = None;
        }
        Ok(())
    }

    fn on_success(&self) {
        let mut state = self.state.lock().expect("breaker lock poisoned");
        state.consecutive_failures = 0;
        state.opened_at = None;
    }

    fn on_failure(&self) {
        let mut state = self.state.lock().expect("breaker lock poisoned");
        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        if state.consecutive_failures >= self.threshold {
            state.opened_at = Some(Instant::now());
        }
    }
}

/// Build a JSON schema (as a [`serde_json::Value`]) for `T` using `schemars`.
pub fn schema_for<T: JsonSchema>() -> Value {
    serde_json::to_value(schemars::schema_for!(T))
        .expect("schemars schema generation is infallible for supported types")
}

/// Token usage for a single completion, normalized across providers.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Usage {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
}

impl Usage {
    pub(crate) fn total(self) -> u64 {
        self.prompt_tokens + self.completion_tokens
    }
}

// ---------------------------------------------------------------------------
// Shared HTTP helpers (retry + lenient JSON parse)
// ---------------------------------------------------------------------------

/// Maximum number of attempts for a single request, including the first.
const MAX_ATTEMPTS: u8 = 3;

/// Whether an HTTP status is worth retrying (rate-limiting or a transient server fault).
fn is_transient(status: reqwest::StatusCode) -> bool {
    status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
}

/// Send a request built fresh by `build` on each attempt, retrying transient failures
/// (network timeouts/connect errors, 429, 5xx) with exponential backoff. The `Retry-After`
/// header is honored when the server provides it. Non-transient errors (4xx other than 429) and
/// the final response after exhausting retries are returned to the caller to interpret.
pub(crate) async fn send_with_retry<F>(
    build: F,
    per_attempt_timeout: Duration,
) -> Result<reqwest::Response, LlmError>
where
    F: Fn() -> reqwest::RequestBuilder,
{
    let mut backoff = Duration::from_millis(150);
    for attempt in 1..=MAX_ATTEMPTS {
        match build().timeout(per_attempt_timeout).send().await {
            Err(error) => {
                let retryable = error.is_timeout() || error.is_connect() || error.is_request();
                if attempt < MAX_ATTEMPTS && retryable {
                    tracing::debug!(attempt, error = %error, "transient transport error, retrying");
                    tokio::time::sleep(backoff).await;
                    backoff = backoff.saturating_mul(3);
                    continue;
                }
                return Err(error.into());
            }
            Ok(response) if attempt < MAX_ATTEMPTS && is_transient(response.status()) => {
                // Honor Retry-After (seconds) on 429 if present, capped to keep latency bounded.
                if let Some(wait) = response
                    .headers()
                    .get("retry-after")
                    .and_then(|h| h.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok())
                {
                    backoff = Duration::from_secs(wait.min(30));
                }
                tracing::debug!(
                    attempt,
                    status = %response.status(),
                    "transient API error, retrying"
                );
                drop(response);
                tokio::time::sleep(backoff).await;
                backoff = backoff.saturating_mul(3);
                continue;
            }
            Ok(response) => return Ok(response),
        }
    }
    unreachable!("loop returns on success, a non-transient response, or error")
}

/// Parse JSON leniently: try the text directly, then with ``` fences stripped, then the substring
/// from the first `{` to the last `}`. The strict backends return clean JSON; this only rescues
/// the `json_object` fallback path when a model wraps its output in prose or a code fence.
pub(crate) fn parse_lenient_json(text: &str) -> Result<Value, serde_json::Error> {
    let trimmed = text.trim();
    if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
        return Ok(value);
    }
    // Strip a ```json / ``` fence wrapper.
    let fenceless = trimmed
        .strip_prefix("```")
        .map(|t| {
            let t = t.strip_prefix("json").unwrap_or(t);
            t.strip_suffix("```").unwrap_or(t)
        })
        .map(|t| t.trim())
        .unwrap_or(trimmed);
    if let Ok(value) = serde_json::from_str::<Value>(fenceless) {
        return Ok(value);
    }
    // Fall back to the outermost {...} span.
    let Some(start) = text.find('{') else {
        return serde_json::from_str::<Value>(trimmed);
    };
    let Some(end) = text.rfind('}') else {
        return serde_json::from_str::<Value>(trimmed);
    };
    let span = &text[start..=end];
    serde_json::from_str(span)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_parses_case_insensitively() {
        assert_eq!(Provider::parse("Anthropic").unwrap(), Provider::Anthropic);
        assert_eq!(Provider::parse("CLAUDE").unwrap(), Provider::Anthropic);
        assert_eq!(Provider::parse("z.AI").unwrap(), Provider::Zai);
        assert_eq!(Provider::parse("").unwrap(), Provider::Anthropic);
        assert!(Provider::parse("bedrock").is_err());
    }

    #[test]
    fn effective_base_url_resolves_vertex_location() {
        let mut cfg = LlmConfig {
            provider: Provider::Vertex,
            model: "gemini-2.0-flash".into(),
            temperature: 0.0,
            base_url: None,
            api_key: None,
            vertex_project: Some("proj".into()),
            vertex_location: Some("europe-west1".into()),
            vertex_endpoint_id: None,
            vertex_project_number: None,
        };
        assert_eq!(
            cfg.effective_base_url(),
            "https://europe-west1-aiplatform.googleapis.com"
        );

        cfg.base_url = Some("https://custom.example.com/".into());
        assert_eq!(cfg.effective_base_url(), "https://custom.example.com");
    }

    #[test]
    fn config_defaults_to_anthropic_haiku() {
        let cfg = LlmConfig::default();
        assert_eq!(cfg.provider, Provider::Anthropic);
        assert_eq!(cfg.model, "claude-haiku-4-5");
        assert_eq!(cfg.temperature, 0.0);
    }

    #[test]
    fn schema_for_simple_struct() {
        #[derive(JsonSchema)]
        struct _S {
            _flag: u8,
            _name: String,
        }
        let schema = schema_for::<_S>();
        assert_eq!(schema.get("type").and_then(|v| v.as_str()), Some("object"));
    }

    #[test]
    fn circuit_breaker_opens_after_threshold_and_recovers() {
        let breaker = CircuitBreaker::new(3, Duration::from_millis(50));

        // Below threshold: calls are allowed.
        assert!(breaker.before_call().is_ok());
        breaker.on_failure();
        assert!(breaker.before_call().is_ok());
        breaker.on_failure();
        assert!(breaker.before_call().is_ok());
        // Third consecutive failure trips the breaker.
        breaker.on_failure();
        assert!(
            matches!(breaker.before_call(), Err(LlmError::CircuitOpen)),
            "breaker should be open after threshold failures"
        );

        // After the cooldown, a half-open probe is allowed.
        std::thread::sleep(Duration::from_millis(60));
        assert!(breaker.before_call().is_ok());
        // A success closes it.
        breaker.on_success();
        assert!(breaker.before_call().is_ok());
    }

    #[test]
    fn circuit_breaker_reopens_if_half_open_probe_fails() {
        let breaker = CircuitBreaker::new(2, Duration::from_millis(40));
        breaker.on_failure();
        breaker.on_failure();
        assert!(matches!(breaker.before_call(), Err(LlmError::CircuitOpen)));
        std::thread::sleep(Duration::from_millis(50));
        // Half-open probe allowed...
        assert!(breaker.before_call().is_ok());
        // ...but it fails, so the breaker reopens immediately.
        breaker.on_failure();
        assert!(matches!(breaker.before_call(), Err(LlmError::CircuitOpen)));
    }

    #[test]
    fn is_provider_failure_classifies_errors() {
        assert!(is_provider_failure(&LlmError::Timeout));
        assert!(is_provider_failure(&LlmError::Http("x".into())));
        assert!(is_provider_failure(&LlmError::Auth("x".into())));
        assert!(is_provider_failure(&LlmError::Api {
            status: 500,
            message: "x".into()
        }));
        assert!(!is_provider_failure(&LlmError::NoContent));
        assert!(!is_provider_failure(&LlmError::Parse(
            serde_json::from_str::<i64>("x").unwrap_err()
        )));
        assert!(!is_provider_failure(&LlmError::Refusal));
    }
}

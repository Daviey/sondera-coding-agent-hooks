//! Policy model for evaluating content against customizable policy rules using an LLM.
//!
//! Prompts an LLM (via [`sondera_llm`]) to classify content against policy templates following the
//! Harmony prompt format with multi-category severity tiers. The model returns a policy-referencing
//! structured output: `{ "violation": 0|1, "policy_category": "<code>" }`.
//!
//! The provider (Anthropic / OpenAI / Ollama / Vertex / z.ai) is selected through
//! [`PolicyModelConfig`] (see [`LlmConfig`]).
//!
//! [`LlmConfig`]: sondera_llm::LlmConfig

mod policy;

use schemars::JsonSchema as JsonSchemaDerive;
use serde::{Deserialize, Serialize};
use sondera_llm::{LlmClient, LlmConfig};
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;
use strum_macros::{Display, EnumString};
use thiserror::Error;
use tracing::instrument;
use futures::stream::StreamExt;
use lru::LruCache;
use sha2::{Digest, Sha256};

pub use policy::{PolicyClassification, PolicyTemplate, PolicyViolation};

pub use sondera_llm::Provider;

/// Maximum number of cached evaluations kept in memory (LRU), keyed by content SHA-256 digest.
const CACHE_CAPACITY: usize = 1024;

/// SHA-256 digest of the content, used as the cache key.
fn cache_key(content: &str) -> [u8; 32] {
    Sha256::digest(content.as_bytes()).into()
}

// ---------------------------------------------------------------------------
// Structured output from the policy model
// ---------------------------------------------------------------------------

/// Policy-referencing structured output returned by the model.
///
/// Category labels encourage the model to reason about which section of the policy applies,
/// keeping outputs concise.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchemaDerive)]
pub struct PolicyModelResult {
    /// `1` if the content violates the policy, `0` if compliant.
    pub violation: u8,
    /// The policy category code that applies (e.g. "SC2" for injection).
    pub policy_category: String,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur during policy evaluation.
#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("LLM error: {0}")]
    Llm(#[from] sondera_llm::LlmError),
    #[error("Policy model not available: {0}")]
    ModelNotAvailable(String),
    #[error("Failed to parse classification response: {0}")]
    ParseError(#[from] serde_json::Error),
    #[error("No policy templates configured")]
    NoPolicies,
    #[error("Invalid content: {0}")]
    InvalidContent(String),
    #[error("Policy evaluation timeout")]
    Timeout,
    #[error("Failed to read policy file: {0}")]
    IoError(String),
    #[error("Failed to parse TOML: {0}")]
    TomlError(String),
}

// ---------------------------------------------------------------------------
// Conversation types
// ---------------------------------------------------------------------------

/// A message in the conversation history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationMessage {
    /// Role of the message sender
    pub role: ConversationRole,
    /// Content of the message
    pub content: String,
}

/// Role in a conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, EnumString, Display)]
#[serde(rename_all = "lowercase")]
pub enum ConversationRole {
    /// User message
    User,
    /// Assistant/model response
    Assistant,
    /// System message
    System,
    /// Tool invocation or response
    Tool,
}

impl ConversationMessage {
    /// Create a new user message.
    pub fn user(content: impl Into<String>) -> Self {
        Self {
            role: ConversationRole::User,
            content: content.into(),
        }
    }

    /// Create a new assistant message.
    pub fn assistant(content: impl Into<String>) -> Self {
        Self {
            role: ConversationRole::Assistant,
            content: content.into(),
        }
    }

    /// Create a new system message.
    pub fn system(content: impl Into<String>) -> Self {
        Self {
            role: ConversationRole::System,
            content: content.into(),
        }
    }

    /// Create a new tool message.
    pub fn tool(content: impl Into<String>) -> Self {
        Self {
            role: ConversationRole::Tool,
            content: content.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Model configuration
// ---------------------------------------------------------------------------

/// Configuration for the policy model.
///
/// A thin wrapper over [`LlmConfig`] that selects the LLM provider. Defaults to reading the
/// provider from the process environment (see [`LlmConfig::from_env`]); pass an explicit config
/// via [`PolicyModel::with_config`] for full control.
#[derive(Debug, Clone)]
pub struct PolicyModelConfig {
    /// Underlying LLM provider configuration.
    pub llm: LlmConfig,
}

impl Default for PolicyModelConfig {
    fn default() -> Self {
        let mut llm = LlmConfig::from_env();
        // Per-classifier model override: policy can run a stronger model than IFC.
        if let Some(model) = std::env::var("SONDERA_POLICY_MODEL")
            .ok()
            .filter(|s| !s.is_empty())
        {
            llm.model = model;
        }
        Self { llm }
    }
}

impl PolicyModelConfig {
    pub fn with_model(model: impl Into<String>) -> Self {
        let mut config = Self::default();
        config.llm.model = model.into();
        config
    }

    pub fn provider(mut self, provider: Provider) -> Self {
        self.llm.provider = provider;
        self
    }

    pub fn base_url(mut self, base_url: impl Into<String>) -> Self {
        self.llm.base_url = Some(base_url.into());
        self
    }

    pub fn model(mut self, model: impl Into<String>) -> Self {
        self.llm.model = model.into();
        self
    }

    pub fn temperature(mut self, temperature: f32) -> Self {
        self.llm.temperature = temperature;
        self
    }
}

impl From<LlmConfig> for PolicyModelConfig {
    fn from(llm: LlmConfig) -> Self {
        Self { llm }
    }
}

// ---------------------------------------------------------------------------
// PolicyModel
// ---------------------------------------------------------------------------

/// Policy model using an LLM for evaluating content against policy templates with multi-category
/// severity tiers.
///
/// Each [`PolicyTemplate`] is evaluated independently. The model returns a policy-referencing
/// structured output (`violation` + `policy_category`) which is mapped to a [`PolicyViolation`]
/// when the content violates the policy.
///
/// # Example
///
/// ```no_run
/// use sondera_policy::{PolicyModel, PolicyTemplate};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let policy = PolicyTemplate::new("SECURE_CODE", "SC")
///     .description("Security vulnerabilities in AI-generated code.")
///     .category("SC0", "Compliant", "Code follows secure coding practices.")
///     .category("SC2", "Injection", "Unsanitized user input in queries or commands.")
///     .example(r#"cursor.execute(f"SELECT * FROM users WHERE id = {id}")"#, true, "SC2")
///     .example(r#"cursor.execute("SELECT * FROM users WHERE id = %s", (id,))"#, false, "SC0");
///
/// let model = PolicyModel::new(vec![policy]);
/// let result = model.evaluate_content("os.system(f\"ping {host}\")").await?;
///
/// if !result.compliant {
///     for v in &result.violations {
///         println!("{v}");
///     }
/// }
/// # Ok(())
/// # }
/// ```
pub struct PolicyModel {
    client: Option<LlmClient>,
    config: PolicyModelConfig,
    policies: Vec<PolicyTemplate>,
    cache: Mutex<LruCache<[u8; 32], PolicyClassification>>,
}

impl PolicyModel {
    pub fn new(policies: Vec<PolicyTemplate>) -> Self {
        Self::with_config(policies, PolicyModelConfig::default())
    }

    pub fn from_toml(path: impl AsRef<Path>) -> Result<Self, PolicyError> {
        let policies = PolicyTemplate::load_from_toml(path)?;
        Ok(Self::new(policies))
    }

    pub fn with_config(policies: Vec<PolicyTemplate>, config: PolicyModelConfig) -> Self {
        let client = LlmClient::try_new_opt(config.llm.clone());
        Self {
            client,
            config,
            policies,
            cache: Mutex::new(LruCache::new(std::num::NonZeroUsize::new(CACHE_CAPACITY).unwrap())),
        }
    }

    /// Evaluate raw content against all configured policy templates.
    ///
    /// Policies are evaluated **concurrently** (they are independent), then violations are
    /// assembled in policy order. A violation is recorded when `violation == 1` in the model's
    /// response.
    #[instrument(skip(self, content), fields(content_len = content.len()))]
    pub async fn evaluate_content(
        &self,
        content: &str,
    ) -> Result<PolicyClassification, PolicyError> {
        if self.policies.is_empty() {
            return Err(PolicyError::NoPolicies);
        }
        if content.is_empty() {
            return Err(PolicyError::InvalidContent(
                "Content cannot be empty".into(),
            ));
        }

        // Serve from the cache when this content has been evaluated before. The cache holds real
        // LLM results only, so a hit is genuine.
        let key = cache_key(content);
        if let Some(hit) = self
            .cache
            .lock()
            .expect("policy cache lock poisoned")
            .get(&key)
            .cloned()
        {
            tracing::debug!(len = content.len(), "policy evaluation cache hit");
            return Ok(hit);
        }

        // Run each policy's LLM call concurrently with a bounded in-flight cap; `buffered` keeps
        // results in policy order so violations stay deterministic. Index into the vec inside the
        // future (rather than capturing the per-item reference) so every future shares `&self`'s
        // single lifetime — required for `buffered` under a `Send` future bound.
        const CONCURRENCY: usize = 8;
        let policies = &self.policies;
        let results: Vec<Result<PolicyModelResult, PolicyError>> =
            futures::stream::iter(0..policies.len())
                .map(|i| self.evaluate_single(&policies[i], content, Duration::from_secs(30)))
                .buffered(CONCURRENCY)
                .collect()
                .await;

        let mut violations = Vec::new();
        for (policy, result) in self.policies.iter().zip(results.into_iter()) {
            let result = result?;
            if result.violation == 1 {
                let code = &result.policy_category;
                let category_name = policy.category_name(code).unwrap_or_else(|| code.clone());
                let description = policy
                    .category_definition(code)
                    .unwrap_or_else(|| code.clone());

                violations.push(PolicyViolation {
                    category: category_name,
                    rule: code.clone(),
                    description,
                });
            }
        }

        let classification = PolicyClassification {
            compliant: violations.is_empty(),
            violations,
        };
        self.cache
            .lock()
            .expect("policy cache lock poisoned")
            .put(key, classification.clone());
        Ok(classification)
    }

    /// Evaluate a conversation history against all configured policy templates.
    pub async fn evaluate(
        &self,
        history: &[ConversationMessage],
    ) -> Result<PolicyClassification, PolicyError> {
        if history.is_empty() {
            return Err(PolicyError::InvalidContent(
                "Conversation history cannot be empty".into(),
            ));
        }

        let content = Self::format_conversation(history);
        self.evaluate_content(&content).await
    }

    /// Get the configured policy templates.
    pub fn policies(&self) -> &[PolicyTemplate] {
        &self.policies
    }

    /// Get the current model name.
    pub fn model(&self) -> &str {
        &self.config.llm.model
    }

    /// Get the selected provider.
    pub fn provider(&self) -> Provider {
        self.config.llm.provider
    }

    /// Get the current configuration.
    pub fn config(&self) -> &PolicyModelConfig {
        &self.config
    }

    /// Health check to verify the configured provider is reachable.
    ///
    /// Returns Ok(()) if the provider responds within 5 seconds, Err otherwise.
    /// Use this at startup to fail fast if the API is unavailable.
    pub async fn health_check(&self) -> Result<(), PolicyError> {
        if let Some(policy) = self.policies.first() {
            self.evaluate_single(policy, "health check", Duration::from_secs(5))
                .await?;
            Ok(())
        } else {
            Err(PolicyError::NoPolicies)
        }
    }

    // -- private helpers ---------------------------------------------------

    async fn evaluate_single(
        &self,
        policy: &PolicyTemplate,
        content: &str,
        timeout: Duration,
    ) -> Result<PolicyModelResult, PolicyError> {
        let client = self.client.as_ref().ok_or_else(|| {
            PolicyError::ModelNotAvailable(
                "LLM client not configured (missing API key/credentials for the selected provider)"
                    .into(),
            )
        })?;

        let system_prompt = policy.render();
        let user_prompt = policy.render_user_message(content);

        let result = client
            .complete_json_as::<PolicyModelResult>(&system_prompt, &user_prompt, timeout)
            .await?;

        Ok(result)
    }

    fn format_conversation(history: &[ConversationMessage]) -> String {
        let mut out = String::new();
        for (i, msg) in history.iter().enumerate() {
            out.push_str(&format!("[{}] {}:\n{}\n\n", i + 1, msg.role, msg.content));
        }
        out
    }
}

/// Builder for constructing a [`PolicyModel`] with custom configuration.
#[derive(Debug, Clone)]
pub struct PolicyModelBuilder {
    policies: Vec<PolicyTemplate>,
    config: PolicyModelConfig,
}

impl PolicyModelBuilder {
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
            config: PolicyModelConfig::default(),
        }
    }

    pub fn policy(mut self, policy: PolicyTemplate) -> Self {
        self.policies.push(policy);
        self
    }

    pub fn provider(mut self, provider: Provider) -> Self {
        self.config.llm.provider = provider;
        self
    }

    pub fn base_url(mut self, base_url: impl Into<String>) -> Self {
        self.config.llm.base_url = Some(base_url.into());
        self
    }

    pub fn model(mut self, model: impl Into<String>) -> Self {
        self.config.llm.model = model.into();
        self
    }

    pub fn temperature(mut self, temperature: f32) -> Self {
        self.config.llm.temperature = temperature;
        self
    }

    pub fn build(self) -> PolicyModel {
        PolicyModel::with_config(self.policies, self.config)
    }
}

impl Default for PolicyModelBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn violations_by_category_case_insensitive() {
        let classification = PolicyClassification {
            compliant: false,
            violations: vec![
                PolicyViolation {
                    category: "Injection".to_string(),
                    rule: "SC2".to_string(),
                    description: "V1".to_string(),
                },
                PolicyViolation {
                    category: "injection".to_string(),
                    rule: "SC2".to_string(),
                    description: "V2".to_string(),
                },
                PolicyViolation {
                    category: "Secrets Exposure".to_string(),
                    rule: "SC3".to_string(),
                    description: "V3".to_string(),
                },
            ],
        };

        assert_eq!(classification.violations_by_category("injection").len(), 2);
        let display = format!("{}", classification);
        assert!(display.contains("NON-COMPLIANT"));
    }

    #[test]
    fn policy_model_result_serde() {
        let json = r#"{"violation": 1, "policy_category": "SC2"}"#;
        let result: PolicyModelResult = serde_json::from_str(json).unwrap();
        assert_eq!(result.violation, 1);
        assert_eq!(result.policy_category, "SC2");
    }

    #[test]
    fn policy_template_render_full() {
        let policy = PolicyTemplate::new("SECURE_CODE", "SC")
            .description("Security vulnerabilities in code.")
            .instructions("Evaluate code for vulnerabilities. Return JSON.")
            .category("SC0", "Compliant", "Secure code.")
            .category("SC2", "Injection", "Unsanitized input in queries.")
            .example(
                r#"cursor.execute(f"SELECT * FROM users WHERE id = {id}")"#,
                true,
                "SC2",
            )
            .example(
                r#"cursor.execute("SELECT * FROM users WHERE id = %s", (id,))"#,
                false,
                "SC0",
            );

        let rendered = policy.render();
        assert!(rendered.contains("# SECURE_CODE"));
        assert!(rendered.contains("Evaluate code for vulnerabilities."));
        assert!(rendered.contains("- SC0 (Compliant): Secure code."));
        assert!(rendered.contains(r#""violation": 1, "policy_category": "SC2""#));
    }

    #[test]
    fn policy_template_default_instructions() {
        let policy = PolicyTemplate::new("MINIMAL", "M").category("M0", "Safe", "Safe content.");
        let rendered = policy.render();
        assert!(rendered.contains(r#""violation": 0, "policy_category": "M0""#));
        assert!(!rendered.contains("## EXAMPLES"));
    }

    #[test]
    fn safe_category_uses_prefix() {
        assert_eq!(PolicyTemplate::new("T", "SC").safe_category(), "SC0");
        assert_eq!(PolicyTemplate::new("T", "SP").safe_category(), "SP0");
    }

    #[test]
    fn category_lookups_case_insensitive() {
        let policy = PolicyTemplate::new("TEST", "SC")
            .category("SC0", "Compliant", "Safe code.")
            .category("SC2", "Injection", "Bad input handling.");

        assert_eq!(policy.category_name("SC2"), Some("Injection".to_string()));
        assert_eq!(policy.category_name("sc2"), Some("Injection".to_string()));
        assert_eq!(policy.category_name("SC9"), None);
        assert_eq!(
            policy.category_definition("SC2"),
            Some("Bad input handling.".to_string())
        );
    }

    #[test]
    fn policy_model_builder() {
        let model = PolicyModelBuilder::new()
            .provider(Provider::Anthropic)
            .base_url("https://proxy.example.com")
            .model("claude-opus-4-8")
            .temperature(0.1)
            .policy(PolicyTemplate::new("P1", "A").category("A0", "Safe", "Safe."))
            .policy(PolicyTemplate::new("P2", "B").category("B0", "Safe", "Safe."))
            .build();

        assert_eq!(model.provider(), Provider::Anthropic);
        assert_eq!(model.model(), "claude-opus-4-8");
        assert_eq!(model.policies().len(), 2);
    }

    #[test]
    fn format_conversation() {
        let history = vec![
            ConversationMessage::user("Hello"),
            ConversationMessage::assistant("Hi there"),
        ];

        let formatted = PolicyModel::format_conversation(&history);
        assert!(formatted.contains("[1] User:"));
        assert!(formatted.contains("[2] Assistant:"));
    }

    #[test]
    fn parse_toml_full_roundtrip() {
        let toml = r#"
[[policies]]
name = "SECURE_CODE"
prefix = "SC"
description = "Security vulnerabilities."

[[policies.categories]]
code = "SC0"
name = "Compliant"
definition = "Secure code."

[[policies.categories]]
code = "SC2"
name = "Injection"
definition = "Unsanitized input."

[[policies.examples]]
content = "cursor.execute(f\"SELECT * FROM users WHERE id = {id}\")"
violation = true
category = "SC2"

[[policies.examples]]
content = "cursor.execute(\"SELECT * FROM users WHERE id = %s\", (id,))"
violation = false
category = "SC0"
"#;
        let policies = PolicyTemplate::parse_toml(toml).unwrap();
        let p = &policies[0];
        assert_eq!(p.prefix, "SC");
        assert_eq!(p.categories.len(), 2);
        assert!(p.examples[0].violation);

        let rendered = p.render();
        assert!(rendered.contains("# SECURE_CODE"));
    }

    #[test]
    fn parse_toml_invalid() {
        let result = PolicyTemplate::parse_toml("not valid toml [[[");
        assert!(matches!(result.unwrap_err(), PolicyError::TomlError(_)));
    }

    #[test]
    fn load_baseline_toml() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../policies/policies.toml"
        );
        let policies = PolicyTemplate::load_from_toml(path).unwrap();
        let p = &policies[0];
        assert_eq!(p.prefix, "SC");
        let codes: Vec<&str> = p.categories.iter().map(|c| c.code.as_str()).collect();
        assert!(codes.contains(&"SC0"));
        assert!(codes.contains(&"SC2"));
        assert!(codes.contains(&"SC7"));
        let _ = p.render();
    }

    #[test]
    fn load_toml_file_not_found() {
        let result = PolicyTemplate::load_from_toml("/nonexistent/path/policy.toml");
        assert!(matches!(result.unwrap_err(), PolicyError::IoError(_)));
    }

    #[test]
    fn policy_model_from_toml_uses_explicit_config() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../policies/policies.toml"
        );
        let config =
            PolicyModelConfig::with_model("claude-haiku-4-5").provider(Provider::Anthropic);
        let policies = PolicyTemplate::load_from_toml(path).unwrap();
        let model = PolicyModel::with_config(policies, config);
        assert_eq!(model.policies().len(), 1);
        assert_eq!(model.model(), "claude-haiku-4-5");
        assert_eq!(model.provider(), Provider::Anthropic);
    }
}

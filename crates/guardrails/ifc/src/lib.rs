//! Data classification model for categorizing content sensitivity levels.
//!
//! Classifies content into sensitivity levels aligned with Microsoft Purview sensitivity labels:
//! Public, General, Confidential, and Highly Confidential.
//!
//! The crate prompts an LLM (via [`sondera_llm`]) to classify content against sensitivity label
//! templates following the Harmony prompt format with multi-category sensitivity tiers. The model
//! returns structured output with `sensitivity_category` as a [`Label`] enum value (`public`,
//! `internal`, `confidential`, `highly_confidential`), enabling type-safe classification without
//! string-based lookups.
//!
//! The provider (Anthropic / OpenAI / Ollama / Vertex / z.ai) is selected through [`DataModelConfig`]
//! (see [`LlmConfig`]). See: <https://learn.microsoft.com/en-us/purview/sensitivity-labels>
//!
//! [`LlmConfig`]: sondera_llm::LlmConfig

mod label;

use sondera_llm::{LlmClient, LlmConfig};
use std::path::Path;
use std::time::Duration;
use thiserror::Error;
use tracing::instrument;

pub use label::{
    Label, LabelCategory, LabelExample, LabelTemplate, SensitivityClassification,
    SensitivityFinding, SensitivityModelResult,
};

pub use sondera_llm::Provider;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur during data classification.
#[derive(Debug, Error)]
pub enum DataClassificationError {
    #[error("LLM error: {0}")]
    Llm(#[from] sondera_llm::LlmError),
    #[error("Classification model not available: {0}")]
    ModelNotAvailable(String),
    #[error("Failed to parse classification response: {0}")]
    ParseError(#[from] serde_json::Error),
    #[error("No label templates configured")]
    NoLabels,
    #[error("Failed to read label file: {0}")]
    IoError(String),
    #[error("Failed to parse TOML: {0}")]
    TomlError(String),
}

// ---------------------------------------------------------------------------
// Model configuration
// ---------------------------------------------------------------------------

/// Configuration for the data classification model.
///
/// A thin wrapper over [`LlmConfig`] that selects the LLM provider. Defaults to reading the
/// provider from the process environment (see [`LlmConfig::from_env`]); pass an explicit config
/// via [`DataModel::with_config`] for full control.
#[derive(Debug, Clone)]
pub struct DataModelConfig {
    /// Underlying LLM provider configuration.
    pub llm: LlmConfig,
}

impl Default for DataModelConfig {
    fn default() -> Self {
        Self {
            llm: LlmConfig::from_env(),
        }
    }
}

impl DataModelConfig {
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

impl From<LlmConfig> for DataModelConfig {
    fn from(llm: LlmConfig) -> Self {
        Self { llm }
    }
}

// ---------------------------------------------------------------------------
// DataModel
// ---------------------------------------------------------------------------

/// Data classification model using an LLM for evaluating content against sensitivity label
/// templates with multi-category tiers.
///
/// Each [`LabelTemplate`] is evaluated independently. The model returns a structured output with
/// `sensitivity_category` as a [`Label`] enum value, which is mapped to a [`SensitivityFinding`]
/// when the content is sensitive.
///
/// # Example
///
/// ```no_run
/// use sondera_information_flow_control::{DataModel, Label, LabelTemplate};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let label = LabelTemplate::new("DATA_SENSITIVITY")
///     .description("Data sensitivity classification aligned with Microsoft Purview.")
///     .category(Label::Public, "Information that can be freely shared externally.")
///     .category(Label::HighlyConfidential, "Most sensitive data with strict access restrictions.")
///     .example("Our company was founded in 2010.", false, Label::Public)
///     .example("Employee SSN: 123-45-6789", true, Label::HighlyConfidential);
///
/// let model = DataModel::new(vec![label]);
/// let result = model.classify("Employee SSN: 123-45-6789").await?;
///
/// if result.is_sensitive() {
///     for f in &result.findings {
///         println!("{}: {}", f.label.display_name(), f.description);
///     }
/// }
/// # Ok(())
/// # }
/// ```
pub struct DataModel {
    client: Option<LlmClient>,
    config: DataModelConfig,
    labels: Vec<LabelTemplate>,
}

impl DataModel {
    pub fn new(labels: Vec<LabelTemplate>) -> Self {
        Self::with_config(labels, DataModelConfig::default())
    }

    pub fn from_toml(path: impl AsRef<Path>) -> Result<Self, DataClassificationError> {
        let labels = LabelTemplate::load_from_toml(path)?;
        Ok(Self::new(labels))
    }

    pub fn with_config(labels: Vec<LabelTemplate>, config: DataModelConfig) -> Self {
        // Build the client eagerly; if required auth is missing it stays `None` and surfaces as
        // an error when classification is attempted (or via `health_check`), keeping construction
        // infallible.
        let client = LlmClient::try_new_opt(config.llm.clone());
        Self {
            client,
            config,
            labels,
        }
    }

    /// Classify content against all configured label templates.
    ///
    /// Each label is evaluated independently. A finding is recorded when
    /// `sensitive == 1` in the model's response.
    #[instrument(skip(self, content), fields(content_len = content.len()))]
    pub async fn classify(
        &self,
        content: &str,
    ) -> Result<SensitivityClassification, DataClassificationError> {
        if self.labels.is_empty() {
            return Err(DataClassificationError::NoLabels);
        }

        let mut findings = Vec::new();

        for label in &self.labels {
            let result = self
                .classify_single(label, content, Duration::from_secs(30))
                .await?;

            if result.sensitive == 1 {
                let sensitivity_label = result.sensitivity_category;
                let description = label
                    .category_definition(sensitivity_label)
                    .unwrap_or_else(|| sensitivity_label.display_name().to_string());

                findings.push(SensitivityFinding {
                    label: sensitivity_label,
                    description,
                });
            }
        }

        Ok(SensitivityClassification {
            is_public: findings.is_empty(),
            findings,
        })
    }

    /// Get the configured label templates.
    pub fn labels(&self) -> &[LabelTemplate] {
        &self.labels
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
    pub fn config(&self) -> &DataModelConfig {
        &self.config
    }

    /// Health check to verify the configured provider is reachable.
    ///
    /// Returns Ok(()) if the provider responds within 5 seconds, Err otherwise.
    /// Use this at startup to fail fast if the API key is missing or the API is unavailable.
    pub async fn health_check(&self) -> Result<(), DataClassificationError> {
        if let Some(label) = self.labels.first() {
            self.classify_single(label, "health check", Duration::from_secs(5))
                .await?;
            Ok(())
        } else {
            Err(DataClassificationError::NoLabels)
        }
    }

    // -- private helpers ---------------------------------------------------

    async fn classify_single(
        &self,
        label: &LabelTemplate,
        content: &str,
        timeout: Duration,
    ) -> Result<SensitivityModelResult, DataClassificationError> {
        let client = self.client.as_ref().ok_or_else(|| {
            DataClassificationError::ModelNotAvailable(
                "LLM client not configured (missing API key/credentials for the selected provider)"
                    .into(),
            )
        })?;

        let system_prompt = label.render();
        let user_prompt = label.render_user_message(content);

        let result = client
            .complete_json_as::<SensitivityModelResult>(&system_prompt, &user_prompt, timeout)
            .await?;

        Ok(result)
    }
}

/// Builder for constructing a [`DataModel`] with custom configuration.
#[derive(Debug, Clone)]
pub struct DataModelBuilder {
    labels: Vec<LabelTemplate>,
    config: DataModelConfig,
}

impl DataModelBuilder {
    pub fn new() -> Self {
        Self {
            labels: Vec::new(),
            config: DataModelConfig::default(),
        }
    }

    pub fn label(mut self, label: LabelTemplate) -> Self {
        self.labels.push(label);
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

    pub fn build(self) -> DataModel {
        DataModel::with_config(self.labels, self.config)
    }
}

impl Default for DataModelBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_model_builder_custom_config() {
        let model = DataModelBuilder::new()
            .provider(Provider::Anthropic)
            .base_url("https://proxy.example.com")
            .model("claude-opus-4-8")
            .temperature(0.1)
            .label(LabelTemplate::new("L1").category(Label::Public, "Public."))
            .label(LabelTemplate::new("L2").category(Label::Public, "Public."))
            .build();

        assert_eq!(model.provider(), Provider::Anthropic);
        assert_eq!(model.model(), "claude-opus-4-8");
        assert_eq!(
            model.config().llm.base_url.as_deref(),
            Some("https://proxy.example.com")
        );
        assert_eq!(model.labels().len(), 2);
    }

    #[test]
    fn data_model_from_toml_uses_explicit_config() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../policies/ifc.toml");
        let config = DataModelConfig::with_model("claude-haiku-4-5").provider(Provider::Anthropic);
        let labels = LabelTemplate::load_from_toml(path).unwrap();
        let model = DataModel::with_config(labels, config);
        assert_eq!(model.labels().len(), 1);
        assert_eq!(model.model(), "claude-haiku-4-5");
        assert_eq!(model.provider(), Provider::Anthropic);
    }
}

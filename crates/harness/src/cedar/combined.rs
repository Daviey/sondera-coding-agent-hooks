//! Combined sensitivity + policy verdict in a single LLM round trip.
//!
//! Each of [`DataModel`](sondera_information_flow_control::DataModel) and
//! [`PolicyModel`](sondera_policy::PolicyModel) issues its own LLM call per template; with N
//! labels and M policies the harness fans out to N + M calls. Even with `tokio::try_join!`
//! running `classify` and `evaluate_content` concurrently, the wall-clock is the *max* of the
//! two fan-outs, which on slow backends (10–25 s per call) blows past client-side timeouts.
//!
//! This module issues ONE call that asks the model for both verdicts in a single structured
//! response. Best suited to deployments with a single label template and a single policy
//! template (the common Sondera setup) — with multiple templates the model would have to
//! enumerate per-template verdicts, which is harder to constrain reliably.
//!
//! Opt-in via `SONDERA_LLM_COMBINED=1`.

use anyhow::Result;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sondera_information_flow_control::{Label, SensitivityClassification, SensitivityFinding};
use sondera_policy::{PolicyClassification, PolicyViolation};
use std::time::Duration;
use tracing::instrument;

/// Result of a single combined LLM call: one sensitivity verdict and one policy verdict.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct CombinedVerdictModelResult {
    /// `1` if the content matches the sensitivity template.
    sensitive: u8,
    /// The sensitivity label that applies (constrained enum).
    sensitivity_category: Label,
    /// `1` if the content violates the policy template.
    violation: u8,
    /// The policy category code that applies (e.g. "SC2").
    policy_category: String,
}

impl super::CedarPolicyHarness {
    /// Issue a single LLM call covering both sensitivity and policy classification.
    ///
    /// Returns `Ok(None)` to signal "use the existing parallel path instead" when:
    /// - the combined mode is disabled (`SONDERA_LLM_COMBINED` unset/false),
    /// - `skip_llm` is true,
    /// - no LLM client is configured, or
    /// - either model has more than one template (combined prompt would be ambiguous).
    ///
    /// On success returns `(SensitivityClassification, PolicyClassification)` built from the
    /// single model response.
    #[instrument(skip(self, content), fields(content_len = content.len()))]
    pub(super) async fn classify_combined(
        &self,
        content: &str,
        skip_llm: bool,
        source_agent: &str,
    ) -> Result<Option<(SensitivityClassification, PolicyClassification)>> {
        if skip_llm || !self.combined_mode.0 {
            return Ok(None);
        }

        let labels = self.data_model.labels();
        let policies = self.policy_model.policies();
        if labels.len() != 1 || policies.len() != 1 {
            // Multi-template combined prompts would need per-template enumeration in the
            // response, which the simple schema above doesn't model. Defer to the parallel path.
            return Ok(None);
        }

        let Some(client) = self.data_model.llm_client() else {
            return Ok(None);
        };

        let label = &labels[0];
        let policy = &policies[0];

        // Build a compact combined prompt. We deliberately do NOT reuse the full Harmony-format
        // templates: those average ~2.5k tokens each (categories + examples), and concatenating
        // two of them erases most of the wall-clock saving. The tradeoff is fewer-shot guidance,
        // which can move the false-negative rate — keep this opt-in and monitor.
        let mut label_cats = String::new();
        for cat in &label.categories {
            label_cats.push_str(&format!(
                "- {}: {}\n",
                cat.label.serde_name(),
                cat.definition
            ));
        }
        let mut policy_cats = String::new();
        for cat in &policy.categories {
            policy_cats.push_str(&format!("- {}: {}\n", cat.code, cat.definition));
        }

        let system = format!(
            "# COMBINED_VERDICT\n\
             You are a security classifier. Evaluate the user content and return a single JSON \
             object with four fields covering BOTH the sensitivity and the policy verdict.\n\n\
             ## {label_name}\n\
             Return `sensitive: 1` and the matching `sensitivity_category` if the content matches \
             any sensitivity category below; otherwise `sensitive: 0` and `sensitivity_category: \
             \"public\"`.\n\
             Categories:\n{label_cats}\n\
             ## {policy_name}\n\
             Return `violation: 1` and the matching `policy_category` code if the content violates \
             any policy category below; otherwise `violation: 0` and `policy_category: \"{safe}\".\n\
             Categories:\n{policy_cats}\n\
             ## OUTPUT\n\
             Respond strictly as JSON matching the schema. Do not include any prose.",
            label_name = label.name,
            label_cats = label_cats,
            policy_name = policy.name,
            safe = policy.safe_category(),
            policy_cats = policy_cats,
        );
        let user = format!("Classify the following content:\n\n{content}");

        let result = match client
            .complete_json_as::<CombinedVerdictModelResult>(
                &system,
                &user,
                Duration::from_secs(30),
                source_agent,
            )
            .await
        {
            Ok(v) => v,
            Err(error) => {
                tracing::warn!(
                    %error,
                    "combined classifier failed; falling back to parallel classify + evaluate"
                );
                return Ok(None);
            }
        };

        // Map back into the existing result types so the cedar harness can treat the combined
        // path and the parallel path identically downstream.
        let sensitivity = if result.sensitive == 1 {
            let description = label
                .category_definition(result.sensitivity_category)
                .unwrap_or_else(|| result.sensitivity_category.display_name().to_string());
            SensitivityClassification {
                is_public: false,
                findings: vec![SensitivityFinding {
                    label: result.sensitivity_category,
                    description,
                }],
            }
        } else {
            SensitivityClassification {
                is_public: true,
                findings: vec![],
            }
        };

        let policy_classification = if result.violation == 1 {
            let code = result.policy_category.clone();
            let category_name = policy.category_name(&code).unwrap_or_else(|| code.clone());
            let description = policy
                .category_definition(&code)
                .unwrap_or_else(|| code.clone());
            PolicyClassification {
                compliant: false,
                violations: vec![PolicyViolation {
                    category: category_name,
                    rule: code,
                    description,
                }],
            }
        } else {
            PolicyClassification {
                compliant: true,
                violations: vec![],
            }
        };

        Ok(Some((sensitivity, policy_classification)))
    }
}

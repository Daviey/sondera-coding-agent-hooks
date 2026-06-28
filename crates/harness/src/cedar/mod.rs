pub mod entity;
mod transform;
mod combined;
mod vector;

use crate::cedar::entity::Trajectory;
use crate::harness::Harness;
use crate::storage::entity::EntityStore;
use crate::storage::file;
use crate::storage::turso::{TrajectoryStore, get_default_db_path};
use crate::{
    Actor, Adjudicated, Agent, Action, Causality, Control, EntityBuilder, Event, FileOpType,
    Observation, TrajectoryEvent, euid,
};
use anyhow::{Context as AnyhowContext, Result};
use cedar_policy::{
    Authorizer, Context, Entity, EntityId, EntityUid, PolicyId, PolicySet, Request, Response,
    Schema, SchemaFragment,
};
use sondera_information_flow_control::{DataModel, Label};
use sondera_policy::{PolicyClassification, PolicyModel, PolicyViolation};
use sondera_signature::Severity;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Mutex;
use tracing::{debug, instrument, warn};

/// How the harness treats a classifier (IFC data-sensitivity or policy) failure.
///
/// The LLM classifiers are probabilistic and depend on a remote API; they can fail transiently
/// or be unavailable. This does not change Cedar's deterministic evaluation — it chooses what
/// happens when a classifier errors:
///
/// - [`FailMode::Open`] (default): substitute benign defaults (Public label, compliant policy) so
///   Cedar permits the action. Matches the historical non-blocking behavior.
/// - [`FailMode::Closed`]: substitute restrictive defaults (HighlyConfidential label, a synthetic
///   policy violation) so Cedar's forbids deny the action. Use where an unavailable classifier
///   should bias strongly toward denial.
/// - [`FailMode::ClosedHard`]: short-circuit adjudication and **deny the action outright**,
///   regardless of what Cedar would decide. Use where an unavailable classifier must never let an
///   action through — the only mode that guarantees denial for every action type.
/// - [`FailMode::Escalate`]: short-circuit adjudication and return [`Decision::Escalate`], which
///   the hook adapters surface for human review rather than blocking outright. A middle ground
///   between `open` (permit unclassified) and `closed-hard` (block everything): while a classifier
///   is unavailable the action is neither auto-permitted nor auto-denied.
///
/// Selected from `SONDERA_FAIL_MODE` (`open` / `closed` / `closed-hard` / `escalate`).
///
/// [`Decision::Escalate`]: crate::Decision::Escalate
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailMode {
    /// On classifier failure, treat content as benign so Cedar permits.
    Open,
    /// On classifier failure, treat content as maximally sensitive + non-compliant so Cedar denies.
    Closed,
    /// On classifier failure, deny the action outright, bypassing Cedar.
    ClosedHard,
    /// On classifier failure, return [`crate::Decision::Escalate`] for human review, bypassing Cedar.
    Escalate,
}

/// Sentinel error raised by the classifier wrappers under [`FailMode::ClosedHard`] or
/// [`FailMode::Escalate`] so that [`CedarPolicyHarness::adjudicate`] can short-circuit to a hard
/// denial or an escalation respectively.
#[derive(Debug, thiserror::Error)]
#[error("classifier unavailable in fail-closed-hard or escalate mode")]
pub(crate) struct ClassifierUnavailable;

impl FailMode {
    /// Parse the mode from a string value. Recognizes `open`, `closed`, `closed-hard`,
    /// `escalate` (plus `deny` / `fail-closed` aliases for `closed`, `hard` / `deny-hard` for
    /// `closed-hard`, and `review` for `escalate`). Empty or unrecognized values fall back to
    /// [`FailMode::Open`].
    pub fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "closed" | "deny" | "fail-closed" => FailMode::Closed,
            "closed-hard" | "hard" | "deny-hard" | "fail-closed-hard" => FailMode::ClosedHard,
            "escalate" | "review" => FailMode::Escalate,
            _ => FailMode::Open,
        }
    }

    /// Read the mode from the `SONDERA_FAIL_MODE` environment variable. Defaults to [`FailMode::Open`].
    pub fn from_env() -> Self {
        Self::parse(&std::env::var("SONDERA_FAIL_MODE").unwrap_or_default())
    }
}

/// Sensitivity label to substitute when the IFC classifier is unavailable, per the fail mode.
/// Only consulted for [`FailMode::Open`] / [`FailMode::Closed`]; [`FailMode::ClosedHard`] and
/// [`FailMode::Escalate`] error before reaching this.
fn default_label_for(mode: FailMode) -> Label {
    match mode {
        FailMode::Open => Label::Public,
        // ClosedHard / Escalate short-circuit via ClassifierUnavailable before reaching here;
        // grouped with Closed for exhaustiveness and defensive safety.
        FailMode::Closed | FailMode::ClosedHard | FailMode::Escalate => Label::HighlyConfidential,
    }
}

/// Policy classification to substitute when the policy classifier is unavailable, per the fail
/// mode. Only consulted for [`FailMode::Open`] / [`FailMode::Closed`].
fn default_classification_for(mode: FailMode) -> PolicyClassification {
    match mode {
        FailMode::Open => PolicyClassification {
            compliant: true,
            violations: Vec::new(),
        },
        FailMode::Closed | FailMode::ClosedHard | FailMode::Escalate => PolicyClassification {
            compliant: false,
            violations: vec![PolicyViolation {
                category: "ClassifierUnavailable".into(),
                rule: "FAIL_CLOSED".into(),
                description: "policy classifier unavailable; denying under fail-closed mode".into(),
            }],
        },
    }
}

/// Which event types receive LLM classification by default.
///
/// When `None` (the default, when `SONDERA_LLM_EVENT_TYPES` is unset), all **Action** events
/// (pre-execution gates) get LLM classification — the historical behaviour. **Observation** events
/// skip the LLM for latency.
///
/// When `Some(set)`, only the listed event types get LLM; others skip unless the YARA trigger
/// ([`CedarPolicyHarness::yara_triggers`]) fires. This lets an operator trim LLM cost on
/// low-risk action types (e.g. `FileRead`) while keeping it on high-risk ones.
///
/// Type names match the Cedar action identifiers: `ShellCommand`, `WebFetch`, `FileRead`,
/// `FileWrite`, `FileEdit`, `FileDelete`, `Prompt`, `ShellCommandOutput`, `WebFetchOutput`,
/// `FileOperationResult`, `ToolOutput`, `PreToolUse`.
#[derive(Debug, Clone)]
struct LlmEventFilter(Option<HashSet<String>>);

impl LlmEventFilter {
    /// Parse a comma-separated list of event type names. Empty or whitespace-only → `None`
    /// (default: all Actions).
    fn parse(value: &str) -> Self {
        let types: HashSet<String> = value
            .split(',')
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        if types.is_empty() {
            Self(None)
        } else {
            Self(Some(types))
        }
    }

    /// Read from `SONDERA_LLM_EVENT_TYPES`. Defaults to `None` (all Actions).
    fn from_env() -> Self {
        Self::parse(&std::env::var("SONDERA_LLM_EVENT_TYPES").unwrap_or_default())
    }

    /// Returns true if this event should get LLM classification by default (before the YARA
    /// trigger is considered).
    fn includes(&self, event: &TrajectoryEvent) -> bool {
        match &self.0 {
            None => matches!(event, TrajectoryEvent::Action(_)),
            Some(types) => llm_event_type_name(event)
                .is_some_and(|name| types.contains(&name.to_ascii_lowercase())),
        }
    }
}

/// Maps an event variant to its Cedar action identifier.
fn llm_event_type_name(event: &TrajectoryEvent) -> Option<&'static str> {
    match event {
        TrajectoryEvent::Action(Action::ShellCommand(_)) => Some("ShellCommand"),
        TrajectoryEvent::Action(Action::WebFetch(_)) => Some("WebFetch"),
        TrajectoryEvent::Action(Action::FileOperation(fo)) => Some(match fo.operation {
            FileOpType::Read => "FileRead",
            FileOpType::Write => "FileWrite",
            FileOpType::Edit => "FileEdit",
            FileOpType::Delete => "FileDelete",
        }),
        TrajectoryEvent::Action(Action::ToolCall(_)) => Some("PreToolUse"),
        TrajectoryEvent::Observation(Observation::Prompt(_)) => Some("Prompt"),
        TrajectoryEvent::Observation(Observation::ShellCommandOutput(_)) => Some("ShellCommandOutput"),
        TrajectoryEvent::Observation(Observation::WebFetchOutput(_)) => Some("WebFetchOutput"),
        TrajectoryEvent::Observation(Observation::FileOperationResult(_)) => Some("FileOperationResult"),
        TrajectoryEvent::Observation(Observation::ToolOutput(_)) => Some("ToolOutput"),
        _ => None,
    }
}

/// Minimum YARA severity that triggers LLM classification on events that would otherwise skip it.
///
/// `None` disables the trigger (YARA matches never force an LLM call). `Some(Low)` (the default)
/// means any YARA match at or above `Low` severity overrides `skip_llm`.
type YaraTrigger = Option<Severity>;

/// Whether the YARA trigger also gates Action events (which by default always run the LLM).
///
/// When `false` (default, historical behaviour), Action events in [`LlmEventFilter`] always get
/// LLM classification and the YARA trigger only rescues excluded event types.
///
/// When `true`, the YARA trigger becomes a necessary condition for *every* event: an Action event
/// with primary-content severity below the trigger threshold skips the LLM. Set via
/// `SONDERA_LLM_YARA_GATE_ACTIONS=1`. Pairs well with `SONDERA_LLM_YARA_SEVERITY=low` to skip
/// LLM cost/latency on benign actions while still classifying anything YARA flags.
struct YaraGateActions(bool);

impl YaraGateActions {
    fn from_env() -> Self {
        Self::parse(&std::env::var("SONDERA_LLM_YARA_GATE_ACTIONS").unwrap_or_default())
    }

    fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "0" | "false" | "off" | "no" => Self(false),
            _ => Self(true),
        }
    }
}

/// Whether to issue a single LLM call covering both sensitivity and policy verdicts
/// (`SONDERA_LLM_COMBINED=1`). See [`combined`] for the tradeoffs.
struct CombinedMode(bool);

impl CombinedMode {
    fn from_env() -> Self {
        Self::parse(&std::env::var("SONDERA_LLM_COMBINED").unwrap_or_default())
    }

    fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "0" | "false" | "off" | "no" => Self(false),
            _ => Self(true),
        }
    }
}

/// Parse the YARA trigger threshold from a string. Accepts severity names (`low`, `medium`,
/// `high`, `critical`) or `off` / `none` / `0` to disable. Defaults to `Low` when unset or
/// unrecognized.
fn parse_yara_trigger(value: &str) -> YaraTrigger {
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "low" => Some(Severity::Low),
        "medium" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" => Some(Severity::Critical),
        "off" | "none" | "0" => None,
        _ => Some(Severity::Low),
    }
}

/// Read the YARA trigger threshold from `SONDERA_LLM_YARA_SEVERITY`. Defaults to `Low`.
fn yara_trigger_from_env() -> YaraTrigger {
    parse_yara_trigger(&std::env::var("SONDERA_LLM_YARA_SEVERITY").unwrap_or_default())
}

/// Extract the primary scannable content from an event for YARA triage.
///
/// This is an approximation of what [`transform`](crate::cedar::transform) scans internally —
/// it covers the dominant content field per event type but does not include resolved file
/// contents (for `ShellCommand`) or old/new content (for `FileOperation`). Sufficient for the
/// triage decision of whether to invoke the LLM; the full scan still runs inside `build_request`
/// for the Cedar context.
fn primary_content(event: &Event) -> String {
    match &event.event {
        TrajectoryEvent::Observation(Observation::Prompt(p)) => p.content.clone(),
        TrajectoryEvent::Action(Action::ShellCommand(sc)) => sc.command.clone(),
        TrajectoryEvent::Action(Action::WebFetch(wf)) => format!("{}\n{}", wf.url, wf.prompt),
        TrajectoryEvent::Action(Action::FileOperation(fo)) => {
            let mut s = fo.path.clone();
            if let Some(c) = &fo.content {
                s.push('\n');
                s.push_str(c);
            }
            s
        }
        TrajectoryEvent::Observation(Observation::ShellCommandOutput(sco)) => {
            format!("{}\n{}", sco.stdout, sco.stderr)
        }
        TrajectoryEvent::Observation(Observation::WebFetchOutput(wfo)) => wfo.result.clone(),
        TrajectoryEvent::Observation(Observation::FileOperationResult(fo)) => {
            fo.content.clone().unwrap_or_default()
        }
        TrajectoryEvent::Observation(Observation::ToolOutput(to)) => {
            to.output.as_str().map(String::from).unwrap_or_default()
        }
        _ => String::new(),
    }
}

pub struct CedarPolicyHarness {
    authorizer: Authorizer,
    entity_store: EntityStore,
    trajectory_store: TrajectoryStore,
    schema: Schema,
    policy_set: PolicySet,
    data_model: DataModel,
    policy_model: PolicyModel,
    fail_mode: FailMode,
    llm_event_types: LlmEventFilter,
    yara_trigger: YaraTrigger,
    yara_gate_actions: YaraGateActions,
    combined_mode: CombinedMode,
    /// TF-IDF vector classifiers for fast-path classification (skips LLM when confident).
    ifc_vector: Mutex<vector::VectorClassifier>,
    policy_vector: Mutex<vector::VectorClassifier>,
}

impl CedarPolicyHarness {
    /// Load a CedarPolicyHarness from a directory containing `.cedarschema` and `.cedar` files.
    ///
    /// Expects exactly one `.cedarschema` file and zero or more `.cedar` policy files.
    /// Agent entities are created dynamically based on the agent field in each Event.
    pub async fn from_policy_dir(path: PathBuf) -> Result<Self> {
        let entity_store_path = file::get_storage_dir()?.join("entities");
        let entity_store = EntityStore::open(&entity_store_path).context(format!(
            "Failed to open entity store: {}",
            entity_store_path.display()
        ))?;

        let trajectory_db_path = get_default_db_path()?;
        let trajectory_store =
            TrajectoryStore::open(&trajectory_db_path)
                .await
                .context(format!(
                    "Failed to open trajectory store: {}",
                    trajectory_db_path.display()
                ))?;

        Self::build(path, entity_store, trajectory_store).await
    }

    /// Load a CedarPolicyHarness with isolated storage for testing.
    ///
    /// Uses the given directory for the entity store and an in-memory trajectory store,
    /// so each test gets its own independent storage without file-lock contention.
    pub async fn from_policy_dir_isolated(
        path: PathBuf,
        storage_dir: &std::path::Path,
    ) -> Result<Self> {
        let entity_store = EntityStore::open(storage_dir.join("entities")).context(format!(
            "Failed to open entity store: {}",
            storage_dir.display()
        ))?;

        let trajectory_store = TrajectoryStore::open_in_memory()
            .await
            .context("Failed to open in-memory trajectory store")?;

        Self::build(path, entity_store, trajectory_store).await
    }

    async fn build(
        path: PathBuf,
        entity_store: EntityStore,
        trajectory_store: TrajectoryStore,
    ) -> Result<Self> {
        anyhow::ensure!(
            path.is_dir(),
            "Policy directory does not exist: {}",
            path.display()
        );

        let mut schema_fragments: Vec<SchemaFragment> = Vec::new();
        let mut policy_set = PolicySet::new();

        for entry in std::fs::read_dir(&path).context(format!(
            "Failed to read policy directory: {}",
            path.display()
        ))? {
            let entry = entry?;
            let file_path = entry.path();

            match file_path.extension().and_then(|e| e.to_str()) {
                Some("cedarschema") => {
                    let content = std::fs::read_to_string(&file_path)
                        .context(format!("Failed to read schema: {}", file_path.display()))?;
                    let (fragment, warnings) = SchemaFragment::from_cedarschema_str(&content)
                        .context(format!(
                            "Failed to parse schema fragment: {}",
                            file_path.display()
                        ))?;
                    for warning in warnings {
                        warn!(
                            "Cedar Schema Warning in {}: {}",
                            file_path.display(),
                            warning
                        );
                    }
                    schema_fragments.push(fragment);
                }
                Some("cedar") => {
                    let content = std::fs::read_to_string(&file_path)
                        .context(format!("Failed to read policy: {}", file_path.display()))?;
                    // Parse all policies in the file, then re-add with @id annotation as ID
                    let file_policies: PolicySet = content.parse().context(format!(
                        "Failed to parse Cedar policies: {}",
                        file_path.display()
                    ))?;
                    for policy in file_policies.policies() {
                        let id_str = policy
                            .annotation("id")
                            .filter(|s| !s.is_empty())
                            .unwrap_or_else(|| policy.id().as_ref());
                        let named = policy.new_id(PolicyId::new(id_str));
                        debug!(
                            "Adding policy {:?} from {}",
                            named.id().to_string(),
                            file_path.display()
                        );
                        policy_set.add(named).context(format!(
                            "Duplicate policy id {:?} in {}",
                            id_str,
                            file_path.display()
                        ))?;
                    }
                }
                _ => {}
            }
        }

        anyhow::ensure!(
            !schema_fragments.is_empty(),
            "No .cedarschema files found in {}",
            path.display()
        );

        let schema = Schema::from_schema_fragments(schema_fragments)
            .context("Failed to merge schema fragments")?;

        // Add Label entity types matching the sensitivity lattice.
        // Names must match Label enum's Display impl and ifc.cedar policy references.
        let highly_confidential_label =
            EntityBuilder::new(euid("Label", "HighlyConfidential")?).build()?;
        let confidential_label = EntityBuilder::new(euid("Label", "Confidential")?)
            .parent_uid(highly_confidential_label.uid())
            .build()?;
        let internal_label = EntityBuilder::new(euid("Label", "Internal")?)
            .parent_uid(confidential_label.uid())
            .build()?;
        let public_label = EntityBuilder::new(euid("Label", "Public")?)
            .parent_uid(internal_label.uid())
            .build()?;

        entity_store.upsert(&highly_confidential_label)?;
        entity_store.upsert(&confidential_label)?;
        entity_store.upsert(&internal_label)?;
        entity_store.upsert(&public_label)?;

        let data_model_path = path.join("ifc.toml");
        let data_model = DataModel::from_toml(data_model_path)?;

        let policy_model_path = path.join("policies.toml");
        let policy_model = PolicyModel::from_toml(policy_model_path)?;

        let harness = Self {
            authorizer: Authorizer::new(),
            entity_store,
            trajectory_store,
            schema,
            policy_set,
            data_model,
            policy_model,
            fail_mode: FailMode::from_env(),
            llm_event_types: LlmEventFilter::from_env(),
            yara_trigger: yara_trigger_from_env(),
            yara_gate_actions: YaraGateActions::from_env(),
            combined_mode: CombinedMode::from_env(),
            ifc_vector: Mutex::new(vector::VectorClassifier::new()),
            policy_vector: Mutex::new(vector::VectorClassifier::new()),
        };

        // Warm the vector classifiers from the benchmark corpus if available.
        let corpus_path = path.join("..").join("benchmarks").join("corpus.jsonl");
        if corpus_path.exists() {
            harness.warm_vectors(&corpus_path);
        }

        Ok(harness)
    }

    /// Ensure the agent entity exists in the entity store.
    fn ensure_agent_entity(&self, agent: &Agent) -> Result<()> {
        let agent_uid = EntityUid::from_type_name_and_id(
            "Agent".parse().context("Invalid entity type name: Agent")?,
            EntityId::new(&agent.id),
        );

        if self.entity_store.get(&agent_uid)?.is_none() {
            let agent_entity = Entity::new_no_attrs(agent_uid, HashSet::new());
            self.entity_store.upsert(&agent_entity)?;
        }
        Ok(())
    }

    /// Warm the vector fast-path classifiers from a labelled corpus file.
    pub fn warm_vectors(&self, corpus_path: &std::path::Path) {
        let (ifc_vc, policy_vc) = vector::train_from_corpus(corpus_path);
        let ifc_size = ifc_vc.size();
        let policy_size = policy_vc.size();
        if let Ok(mut vc) = self.ifc_vector.lock() {
            *vc = ifc_vc;
        }
        if let Ok(mut vc) = self.policy_vector.lock() {
            *vc = policy_vc;
        }
        tracing::info!(ifc_docs = ifc_size, policy_docs = policy_size, "vector fast-path warmed from corpus");
    }

    /// Get the loaded policy set.
    pub fn policy_set(&self) -> &PolicySet {
        &self.policy_set
    }

    /// Get the loaded schema.
    pub fn schema(&self) -> &Schema {
        &self.schema
    }

    /// The configured classifier failure mode.
    pub fn fail_mode(&self) -> FailMode {
        self.fail_mode
    }

    /// Returns true if the given YARA severity meets the trigger threshold, meaning the LLM
    /// classifiers should run even for events that would otherwise skip them.
    pub fn yara_triggers(&self, severity: Severity) -> bool {
        match self.yara_trigger {
            Some(threshold) => severity >= threshold,
            None => false,
        }
    }

    /// Classify content sensitivity, substituting a fail-mode default if the IFC classifier
    /// errors (or returning [`ClassifierUnavailable`] under [`FailMode::ClosedHard`] /
    /// [`FailMode::Escalate`] so the caller can hard-deny or escalate). The successful label is the max sensitivity among matched label templates.
    async fn classify_label(
        &self,
        content: &str,
        skip_llm: bool,
        source_agent: &str,
    ) -> Result<Label> {
        if skip_llm {
            return Ok(Label::Public);
        }

        // Fast-path: check vector classifier before calling the LLM.
        if let Ok(vc) = self.ifc_vector.lock() {
            if let Some(predicted) = vc.classify(content) {
                debug!(label = %predicted, "IFC vector fast-path hit");
                if let Ok(label) = predicted.parse::<Label>() {
                    return Ok(label);
                }
            }
        }

        match self.data_model.classify(content, source_agent).await {
            Ok(classification) => {
                let label = classification.max_label();
                // Feed result back to the vector classifier for future fast-path hits.
                if let Ok(mut vc) = self.ifc_vector.lock() {
                    vc.train(content, &label.to_string());
                    vc.finalise();
                }
                Ok(label)
            }
            Err(error) => {
                warn!(%error, fail_mode = ?self.fail_mode, "data classifier failed; applying fail-mode policy");
                match self.fail_mode {
                    FailMode::ClosedHard | FailMode::Escalate => Err(ClassifierUnavailable.into()),
                    _ => Ok(default_label_for(self.fail_mode)),
                }
            }
        }
    }

    /// Evaluate content against the policy templates, substituting a fail-mode default if the
    /// policy classifier errors (or returning [`ClassifierUnavailable`] under
    /// [`FailMode::ClosedHard`] / [`FailMode::Escalate`]).
    async fn evaluate_policy(
        &self,
        content: &str,
        skip_llm: bool,
        source_agent: &str,
    ) -> Result<PolicyClassification> {
        if skip_llm {
            return Ok(default_classification_for(FailMode::Open));
        }

        // Fast-path: check vector classifier before calling the LLM.
        if let Ok(vc) = self.policy_vector.lock() {
            if let Some(predicted) = vc.classify(content) {
                debug!(verdict = %predicted, "policy vector fast-path hit");
                let compliant = predicted == "compliant";
                return Ok(PolicyClassification { compliant, violations: Vec::new() });
            }
        }

        match self.policy_model.evaluate_content(content, source_agent).await {
            Ok(classification) => {
                // Feed result back to the vector classifier.
                if let Ok(mut vc) = self.policy_vector.lock() {
                    let verdict = if classification.compliant { "compliant" } else { "non-compliant" };
                    vc.train(content, verdict);
                    vc.finalise();
                }
                Ok(classification)
            }
            Err(error) => {
                warn!(%error, fail_mode = ?self.fail_mode, "policy classifier failed; applying fail-mode policy");
                match self.fail_mode {
                    FailMode::ClosedHard | FailMode::Escalate => Err(ClassifierUnavailable.into()),
                    _ => Ok(default_classification_for(self.fail_mode)),
                }
            }
        }
    }

    pub fn is_authorized(&self, request: &Request) -> Result<Response> {
        let entities = self.entity_store.entities()?;
        Ok(self
            .authorizer
            .is_authorized(request, &self.policy_set, &entities))
    }

    /// Run both sensitivity and policy classification for the same content.
    ///
    /// Tries the single-LLM-call combined path first (see [`combined`]); if it returns `None`
    /// (combined mode disabled, multiple templates, no client, or transient failure) falls back
    /// to the historical parallel `try_join!` of [`classify_label`] + [`evaluate_policy`].
    ///
    /// [`classify_label`]: Self::classify_label
    /// [`evaluate_policy`]: Self::evaluate_policy
    async fn classify_and_evaluate(
        &self,
        content: &str,
        skip_llm: bool,
        source_agent: &str,
    ) -> Result<(Label, PolicyClassification)> {
        if let Some((sensitivity, policy_classification)) =
            self.classify_combined(content, skip_llm, source_agent).await?
        {
            return Ok((sensitivity.max_label(), policy_classification));
        }
        let (label, policy_classification) = tokio::try_join!(
            self.classify_label(content, skip_llm, source_agent),
            self.evaluate_policy(content, skip_llm, source_agent),
        )?;
        Ok((label, policy_classification))
    }

    pub fn validate_request(
        &self,
        principal: EntityUid,
        action: EntityUid,
        resource: EntityUid,
        context: Option<Context>,
    ) -> Result<Request> {
        let ctx = context.unwrap_or_else(Context::empty);
        let request = Request::new(principal, action, resource, ctx, Some(&self.schema))?;
        Ok(request)
    }

    /// Add an entity to the entity store.
    /// Returns an error if an entity with the same UID already exists.
    pub fn add_entity(&self, entity: Entity) -> Result<()> {
        if self.entity_store.get(&entity.uid())?.is_some() {
            anyhow::bail!("Entity already exists: {}", entity.uid());
        }
        self.entity_store.upsert(&entity)?;
        Ok(())
    }

    /// Upsert an entity into the entity store.
    /// If an entity with the same UID exists, it will be replaced.
    pub fn upsert_entity(&self, entity: Entity) -> Result<()> {
        self.entity_store.upsert(&entity)?;
        Ok(())
    }

    /// Get an entity from the entity store by its UID.
    pub fn get_entity(&self, uid: &EntityUid) -> Result<Option<Entity>> {
        self.entity_store.get(uid)
    }

    /// Remove an entity from the entity store by its UID.
    pub fn remove_entity(&self, uid: EntityUid) -> Result<()> {
        self.entity_store.delete(&uid)?;
        Ok(())
    }
}

impl Harness for CedarPolicyHarness {
    #[instrument(
        skip(self, event),
        fields(
            trajectory_id = %event.trajectory_id,
            event_id = %event.event_id,
            agent = %event.agent.id,
        )
    )]
    async fn adjudicate(&self, event: Event) -> Result<Adjudicated> {
        debug!("Trajectory Event: {:?}", event);
        // Ensure the agent entity exists in the store
        self.ensure_agent_entity(&event.agent)?;

        // Write to both JSONL file storage and Turso
        file::write_trajectory_event(&event)?;
        self.trajectory_store.insert_event(&event).await?;

        if let TrajectoryEvent::Control(control) = &event.event {
            if let Control::Started(_) = control {
                debug!("Starting trajectory: {}", event.trajectory_id);
                // Create a Trajectory entity for the trajectory.
                let trajectory = Trajectory::new(&event.trajectory_id);
                self.upsert_entity(trajectory.into_entity()?)?;
            }
            // Don't authorize control events.
            return Ok(Adjudicated::allow());
        }

        // Determine whether this event type gets LLM classification.
        //
        // Two modes, both consulting the YARA trigger (`SONDERA_LLM_YARA_SEVERITY`):
        // - Default: LLM runs if the event type is in the filter (default: all Actions)
        //   OR a YARA signature meets the threshold. The YARA trigger only rescues
        //   otherwise-excluded event types.
        // - YARA-gated (`SONDERA_LLM_YARA_GATE_ACTIONS=1`): LLM runs only if BOTH the
        //   event type is in the filter AND a YARA signature meets the threshold.
        //   Use to skip LLM cost/latency on benign Action events.
        let included = self.llm_event_types.includes(&event.event);
        let sig = sondera_signature::scan(&primary_content(&event));
        let meets_threshold = self.yara_triggers(sig.severity);
        let skip_llm = if self.yara_gate_actions.0 {
            !(included && meets_threshold)
        } else {
            !(included || meets_threshold)
        };

        let source_agent = &event.agent.provider_id;
        let (adjudicated, raw) = match self.build_request(&event, skip_llm, source_agent).await {
            Ok(request) => {
                let response = self.is_authorized(&request)?;
                let adjudicated = self.response_to_adjudicated(&response);

                // Build raw payload capturing the Cedar request and response for the trajectory log.
                let errors: Vec<String> = response
                    .diagnostics()
                    .errors()
                    .map(|e| e.to_string())
                    .collect();
                let reason_policies: Vec<String> = response
                    .diagnostics()
                    .reason()
                    .map(|id| id.to_string())
                    .collect();
                let raw = serde_json::json!({
                    "request": {
                        "principal": request.principal().map(|p| p.to_string()),
                        "action": request.action().map(|a| a.to_string()),
                        "resource": request.resource().map(|r| r.to_string()),
                        "context": request.context().and_then(|c| c.to_json_value().ok()),
                    },
                    "response": {
                        "decision": format!("{:?}", response.decision()),
                        "reason": reason_policies,
                        "errors": errors,
                    },
                });
                (adjudicated, raw)
            }
            Err(error) => {
                // Only the classifier-unavailable sentinel is intercepted as a short-circuit
                // (hard deny under ClosedHard, escalation under Escalate); anything else is a
                // genuine error and propagates.
                if error.downcast_ref::<ClassifierUnavailable>().is_none() {
                    return Err(error);
                }
                match self.fail_mode {
                    FailMode::Escalate => {
                        warn!(
                            fail_mode = ?self.fail_mode,
                            "classifier unavailable under escalate mode; escalating for review"
                        );
                        let adjudicated = Adjudicated::escalate()
                            .with_reason("classifier unavailable; escalating for review");
                        let raw = serde_json::json!({
                            "escalate": true,
                            "reason": "classifier unavailable in escalate mode",
                        });
                        (adjudicated, raw)
                    }
                    _ => {
                        warn!(
                            fail_mode = ?self.fail_mode,
                            "classifier unavailable under fail-closed-hard; denying action outright"
                        );
                        let adjudicated =
                            Adjudicated::deny().with_reason("classifier unavailable (fail-closed-hard)");
                        let raw = serde_json::json!({
                            "hard_deny": true,
                            "reason": "classifier unavailable in fail-closed-hard mode",
                        });
                        (adjudicated, raw)
                    }
                }
            }
        };

        // Write the adjudication as a Control event on the same trajectory.
        let adjudicated_event = Event::new(
            event.agent.clone(),
            &event.trajectory_id,
            TrajectoryEvent::Control(Control::Adjudicated(adjudicated.clone())),
        )
        .with_actor(Actor::policy("cedar"))
        .with_causality(Causality::default().caused_by(&event.event_id))
        .with_raw(raw);

        // Latest trajectory entity.
        let trajectory: Trajectory = match self
            .entity_store
            .get(&euid("Trajectory", &event.trajectory_id)?)?
        {
            Some(entity) => entity.try_into()?,
            None => {
                debug!(
                    "Trajectory entity {:?} not found after adjudication, creating.",
                    &event.trajectory_id
                );
                Trajectory::new(&event.trajectory_id)
            }
        };

        debug!("Adjudicated Event: {:?}", adjudicated_event);
        debug!("Trajectory: {:?}", trajectory);

        // Write adjudication event to both storages
        file::write_trajectory_event(&adjudicated_event)?;
        self.trajectory_store
            .insert_event(&adjudicated_event)
            .await?;

        Ok(adjudicated)
    }
}

#[cfg(test)]
mod fail_mode_tests {
    use super::*;

    #[test]
    fn parse_fail_mode() {
        assert_eq!(FailMode::parse("closed"), FailMode::Closed);
        assert_eq!(FailMode::parse("CLOSED"), FailMode::Closed);
        assert_eq!(FailMode::parse(" deny "), FailMode::Closed);
        assert_eq!(FailMode::parse("fail-closed"), FailMode::Closed);
        assert_eq!(FailMode::parse("closed-hard"), FailMode::ClosedHard);
        assert_eq!(FailMode::parse("HARD"), FailMode::ClosedHard);
        assert_eq!(FailMode::parse("deny-hard"), FailMode::ClosedHard);
        assert_eq!(FailMode::parse("escalate"), FailMode::Escalate);
        assert_eq!(FailMode::parse("ESCALATE"), FailMode::Escalate);
        assert_eq!(FailMode::parse("review"), FailMode::Escalate);
        assert_eq!(FailMode::parse("open"), FailMode::Open);
        assert_eq!(
            FailMode::parse(""),
            FailMode::Open,
            "empty defaults to open"
        );
        assert_eq!(
            FailMode::parse("garbage"),
            FailMode::Open,
            "unknown defaults to open"
        );
    }

    #[test]
    fn default_label_is_polarized_by_mode() {
        assert_eq!(default_label_for(FailMode::Open), Label::Public);
        assert_eq!(
            default_label_for(FailMode::Closed),
            Label::HighlyConfidential,
            "fail-closed must classify unclassifiable content as maximally sensitive"
        );
    }

    #[test]
    fn default_classification_is_polarized_by_mode() {
        let open = default_classification_for(FailMode::Open);
        assert!(open.compliant);
        assert!(open.violations.is_empty());

        let closed = default_classification_for(FailMode::Closed);
        assert!(!closed.compliant, "fail-closed must be non-compliant");
        assert!(
            closed.violations.iter().any(|v| v.rule == "FAIL_CLOSED"),
            "fail-closed must carry a synthetic FAIL_CLOSED violation"
        );
    }
}

#[cfg(test)]
mod llm_filter_tests {
    use super::*;
    use crate::{Prompt, ShellCommand, WebFetch};

    #[test]
    fn event_filter_defaults_to_all_actions() {
        let filter = LlmEventFilter::parse("");
        assert!(filter.0.is_none(), "empty filter should be None (all actions)");
        assert!(filter.includes(&TrajectoryEvent::Action(Action::ShellCommand(
            ShellCommand::new("ls")
        ))));
        assert!(!filter.includes(&TrajectoryEvent::Observation(Observation::Prompt(
            Prompt::user("hello")
        ))));
    }

    #[test]
    fn event_filter_explicit_types() {
        let filter = LlmEventFilter::parse("ShellCommand, WebFetch, FileRead");
        assert!(filter.includes(&TrajectoryEvent::Action(Action::ShellCommand(
            ShellCommand::new("ls")
        ))));
        assert!(filter.includes(&TrajectoryEvent::Action(Action::WebFetch(
            WebFetch::new("https://example.com", "test")
        ))));
        // FileWrite is NOT in the list → excluded.
        assert!(!filter.includes(&TrajectoryEvent::Action(Action::FileOperation(
            crate::FileOperation::write("/tmp/x", "data")
        ))));
        // Observations are excluded.
        assert!(!filter.includes(&TrajectoryEvent::Observation(Observation::Prompt(
            Prompt::user("hello")
        ))));
    }

    #[test]
    fn event_filter_case_insensitive() {
        let filter = LlmEventFilter::parse("shellcommand, WEbFeTcH");
        assert!(filter.includes(&TrajectoryEvent::Action(Action::ShellCommand(
            ShellCommand::new("ls")
        ))));
        assert!(filter.includes(&TrajectoryEvent::Action(Action::WebFetch(
            WebFetch::new("https://example.com", "test")
        ))));
    }

    #[test]
    fn yara_trigger_parse() {
        assert_eq!(parse_yara_trigger(""), Some(Severity::Low));
        assert_eq!(parse_yara_trigger("low"), Some(Severity::Low));
        assert_eq!(parse_yara_trigger("medium"), Some(Severity::Medium));
        assert_eq!(parse_yara_trigger("HIGH"), Some(Severity::High));
        assert_eq!(parse_yara_trigger("critical"), Some(Severity::Critical));
        assert_eq!(parse_yara_trigger("off"), None);
        assert_eq!(parse_yara_trigger("none"), None);
        assert_eq!(parse_yara_trigger("0"), None);
        assert_eq!(parse_yara_trigger("garbage"), Some(Severity::Low));
    }

    #[test]
    fn yara_trigger_threshold_comparison() {
        let trigger = Some(Severity::Medium);
        assert!(!(Severity::Low >= trigger.unwrap()));
        assert!(Severity::Medium >= trigger.unwrap());
        assert!(Severity::High >= trigger.unwrap());
        assert!(Severity::Critical >= trigger.unwrap());
    }

    #[test]
    fn yara_gate_actions_env_parsing() {
        let off_values = ["", "0", "false", "off", "no"];
        for v in off_values {
            assert!(!YaraGateActions::parse(v).0, "value {v:?} should be off");
        }
        let on_values = ["1", "true", "on", "yes", "enabled"];
        for v in on_values {
            assert!(YaraGateActions::parse(v).0, "value {v:?} should be on");
        }
    }
}

pub mod entity;
mod transform;

use crate::cedar::entity::Trajectory;
use crate::harness::Harness;
use crate::storage::entity::EntityStore;
use crate::storage::file;
use crate::storage::turso::{TrajectoryStore, get_default_db_path};
use crate::{
    Actor, Adjudicated, Agent, Causality, Control, EntityBuilder, Event, TrajectoryEvent, euid,
};
use anyhow::{Context as AnyhowContext, Result};
use cedar_policy::{
    Authorizer, Context, Entity, EntityId, EntityUid, PolicyId, PolicySet, Request, Response,
    Schema, SchemaFragment,
};
use sondera_information_flow_control::{DataModel, Label};
use sondera_policy::{PolicyClassification, PolicyModel, PolicyViolation};
use std::collections::HashSet;
use std::path::PathBuf;
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
///
/// Selected from `SONDERA_FAIL_MODE` (`open` / `closed` / `closed-hard`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailMode {
    /// On classifier failure, treat content as benign so Cedar permits.
    Open,
    /// On classifier failure, treat content as maximally sensitive + non-compliant so Cedar denies.
    Closed,
    /// On classifier failure, deny the action outright, bypassing Cedar.
    ClosedHard,
}

/// Sentinel error raised by the classifier wrappers under [`FailMode::ClosedHard`] so that
/// [`CedarPolicyHarness::adjudicate`] can short-circuit to a hard denial.
#[derive(Debug, thiserror::Error)]
#[error("classifier unavailable in fail-closed-hard mode")]
pub(crate) struct ClassifierUnavailable;

impl FailMode {
    /// Parse the mode from a string value. Recognizes `open`, `closed`, `closed-hard` (plus
    /// `deny` / `fail-closed` aliases for `closed` and `hard` / `deny-hard` for `closed-hard`).
    /// Empty or unrecognized values fall back to [`FailMode::Open`].
    pub fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "closed" | "deny" | "fail-closed" => FailMode::Closed,
            "closed-hard" | "hard" | "deny-hard" | "fail-closed-hard" => FailMode::ClosedHard,
            _ => FailMode::Open,
        }
    }

    /// Read the mode from the `SONDERA_FAIL_MODE` environment variable. Defaults to [`FailMode::Open`].
    pub fn from_env() -> Self {
        Self::parse(&std::env::var("SONDERA_FAIL_MODE").unwrap_or_default())
    }
}

/// Sensitivity label to substitute when the IFC classifier is unavailable, per the fail mode.
/// Only consulted for [`FailMode::Open`] / [`FailMode::Closed`]; [`FailMode::ClosedHard`] errors
/// before reaching this.
fn default_label_for(mode: FailMode) -> Label {
    match mode {
        FailMode::Open => Label::Public,
        FailMode::Closed | FailMode::ClosedHard => Label::HighlyConfidential,
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
        FailMode::Closed | FailMode::ClosedHard => PolicyClassification {
            compliant: false,
            violations: vec![PolicyViolation {
                category: "ClassifierUnavailable".into(),
                rule: "FAIL_CLOSED".into(),
                description: "policy classifier unavailable; denying under fail-closed mode".into(),
            }],
        },
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

        Ok(Self {
            authorizer: Authorizer::new(),
            entity_store,
            trajectory_store,
            schema,
            policy_set,
            data_model,
            policy_model,
            fail_mode: FailMode::from_env(),
        })
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

    /// Classify content sensitivity, substituting a fail-mode default if the IFC classifier
    /// errors (or returning [`ClassifierUnavailable`] under [`FailMode::ClosedHard`] so the caller
    /// can hard-deny). The successful label is the max sensitivity among matched label templates.
    async fn classify_label(
        &self,
        content: &str,
        skip_llm: bool,
        source_agent: &str,
    ) -> Result<Label> {
        if skip_llm {
            return Ok(Label::Public);
        }
        match self.data_model.classify(content, source_agent).await {
            Ok(classification) => Ok(classification.max_label()),
            Err(error) => {
                warn!(
                    %error,
                    fail_mode = ?self.fail_mode,
                    "data classifier failed; applying fail-mode policy"
                );
                match self.fail_mode {
                    FailMode::ClosedHard => Err(ClassifierUnavailable.into()),
                    _ => Ok(default_label_for(self.fail_mode)),
                }
            }
        }
    }

    /// Evaluate content against the policy templates, substituting a fail-mode default if the
    /// policy classifier errors (or returning [`ClassifierUnavailable`] under
    /// [`FailMode::ClosedHard`]).
    async fn evaluate_policy(
        &self,
        content: &str,
        skip_llm: bool,
        source_agent: &str,
    ) -> Result<PolicyClassification> {
        if skip_llm {
            return Ok(default_classification_for(FailMode::Open));
        }
        match self
            .policy_model
            .evaluate_content(content, source_agent)
            .await
        {
            Ok(classification) => Ok(classification),
            Err(error) => {
                warn!(
                    %error,
                    fail_mode = ?self.fail_mode,
                    "policy classifier failed; applying fail-mode policy"
                );
                match self.fail_mode {
                    FailMode::ClosedHard => Err(ClassifierUnavailable.into()),
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

        // Only Action events (pre-execution gates) need the full LLM classifiers.
        // Observations (post-execution analysis: command output, file contents, prompt text)
        // skip the LLM for latency — the deterministic YARA scan + Cedar still run, using the
        // trajectory's existing label. This cuts LLM calls from 3 per tool call to 1.
        // The flag is passed by value (not shared mutable state) so concurrent adjudicate calls
        // on the same harness cannot race.
        let skip_llm = !matches!(event.event, TrajectoryEvent::Action(_));

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
                // Only the classifier-unavailable sentinel is intercepted as a hard deny;
                // anything else is a genuine error and propagates.
                if error.downcast_ref::<ClassifierUnavailable>().is_none() {
                    return Err(error);
                }
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

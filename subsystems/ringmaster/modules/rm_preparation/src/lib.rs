//! `rm_preparation`: tier-5 Prepare (local validation/serialization) for Ringmaster.
//!
//! Implements the Prepare boundary (seam mapping §13.1–§13.3, EXT-PREPARE /
//! EXT-PREPARATION-PIN / EXT-TASK / EXT-STATE-POLICY / EXT-DECLARE-NOT-ASSESS):
//!
//! - [`prepare`] validates already supplied task data, plan, dependencies,
//!   mappings, grants, and declared limits without visiting the target,
//!   testing authentication, resetting context, invoking a planner, or
//!   secretly improving the plan (RM-C20). It records the native
//!   serialization and subject-facing task independently.
//! - [`verify_preparation`] rejects stale/conflicting inputs: changed
//!   preparation bytes, changed actual destinations (even when the semantic
//!   hash is equal), stale subject/configuration/mapping, and mismatched
//!   registration (RM-C21).
//!
//! Hard rules:
//!
//! - Prepare is non-executing: no browsing, probing, planning, reset,
//!   healing, or preflight.
//! - Translation preserves intent, action order, values, targets, and retry
//!   policy; incomplete translation yields `UNSUPPORTED_MAPPING`.
//! - A preparation is immutable and names the exact descriptor, subject,
//!   mapping, full task, delivered task, intended native request,
//!   runtime-access references, and limitations.
//! - Blocking unsupported mappings or required unenforceable policies yield
//!   `ConnectorError`, never a startable preparation.
//! - Manual commissions are not dispatchable through Prepare.
//! - Missing native cancellation alone never blocks preparation.
//! - No in-band nulls; absences are typed [`Missing`] envelopes.
//! - No shared-database writes or cross-domain transactions.

#![forbid(unsafe_code)]

use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};

pub use rm_authority::{
    AttemptKind, AuthenticatedPrincipal, ConnectorError, EvaluationPartition, ExecutionMode,
    Manifest, Operation, TargetClass, WorkScope,
};
pub use rm_authority::{AttemptCommission, EvidenceImport, LineageRef};
pub use rm_catalog::{
    BOBindingDescriptor, ComponentIdentity, ConnectorDescriptor, DescribeRequest, DurationLimit,
    MaybeDigest as CatalogMaybeDigest, MaybeString as CatalogMaybeString,
    MaybeVersionPin as CatalogMaybeVersionPin, SubjectIdentity, TaskMapping, VersionPin,
};
pub use rm_evidence::{
    AccessClass, ArtifactReference, EvidenceRef, JournalPrefix, Missing, PositiveInteger,
};
pub use rm_wire::Digest;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Connector request record discriminator.
pub const CONNECTOR_REQUEST_TYPE: &str = "connector_request";
/// External connector schema version.
pub const CONNECTOR_SCHEMA_VERSION: &str = "external-connector/0.1.0";
/// Connector verb served by [`prepare`].
pub const PREPARE_VERB: &str = "Prepare";
/// Preparation record discriminator.
pub const PREPARATION_RECORD_TYPE: &str = "connector_preparation";
/// Task record discriminator.
pub const TASK_RECORD_TYPE: &str = "connector_task";
/// Preparation registration event kind (owner-local artifact registration).
pub const PREPARATION_EVENT_KIND: &str = "artifact_available";
/// Owner domain publishing preparation registrations.
pub const PREPARATION_OWNER_DOMAIN: &str = "artifact";

/// Largest exactly representable integer (§3.1).
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Five budget dimensions, each exactly once.
pub const BUDGET_DIMENSIONS: [&str; 5] = [
    "active_observation",
    "action_count",
    "observation_bytes",
    "recovery_count",
    "model_tokens",
];

/// Budget enforcers.
pub const BUDGET_ENFORCERS: [&str; 4] = ["connector", "subject", "not_enforced", "not_applicable"];

/// Preparation concern categories.
pub const CONCERN_CATEGORIES: [&str; 6] = [
    "native_capability_absent",
    "native_capability_unknown",
    "budget_not_enforced",
    "state_policy_unverified",
    "assistance_limit",
    "observation_limit",
];

/// Concern dispositions.
pub const CONCERN_DISPOSITIONS: [&str; 2] = ["requires_acceptance", "informational"];

/// Task types.
pub const TASK_TYPES: [&str; 3] = ["apply", "extract", "discover_jobs"];

/// Runtime access purposes.
pub const RUNTIME_PURPOSES: [&str; 3] =
    ["application_entry", "account_session", "input_artifact"];

/// Browser-state modes (frozen is learning-only).
pub const BROWSER_STATE_MODES: [&str; 4] = ["fresh", "reuse", "subject_default", "not_applicable"];
/// Learning-state modes.
pub const LEARNING_STATE_MODES: [&str; 5] =
    ["fresh", "reuse", "frozen", "subject_default", "not_applicable"];

/// State requirements.
pub const STATE_REQUIREMENTS: [&str; 2] = ["required", "best_effort"];

/// Planning owners.
pub const PLANNING_OWNERS: [&str; 4] = ["subject", "external_planner", "operator", "none"];

/// The six permitted `Missing.reason` values (§3.2).
pub const MISSING_REASONS: [&str; 6] = [
    "not_enabled",
    "not_applicable",
    "not_observed",
    "observation_lost",
    "unsupported_by_subject",
    "manual_override",
];

static PRODUCER_SEQ: AtomicU64 = AtomicU64::new(5000);

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

fn err(code: &str, fault_domain: &str, detail: String) -> ConnectorError {
    ConnectorError {
        kind: "connector_error".to_string(),
        code: code.to_string(),
        fault_domain: fault_domain.to_string(),
        detail,
        operation_delivery: "not_dispatched".to_string(),
        retry_guidance: "operator_review".to_string(),
        retry_after: None,
        handle: None,
        evidence_refs: Vec::new(),
    }
}

fn invalid(detail: impl Into<String>) -> ConnectorError {
    err("INVALID_REQUEST", "request", detail.into())
}

fn unsupported_version(detail: impl Into<String>) -> ConnectorError {
    err("UNSUPPORTED_VERSION", "request", detail.into())
}

fn unsupported_mapping(detail: impl Into<String>) -> ConnectorError {
    err("UNSUPPORTED_MAPPING", "policy", detail.into())
}

fn not_admitted(detail: impl Into<String>) -> ConnectorError {
    err("NOT_ADMITTED", "policy", detail.into())
}

fn stale(detail: impl Into<String>) -> ConnectorError {
    err("STALE_PREPARATION", "request", detail.into())
}

fn integrity(detail: impl Into<String>) -> ConnectorError {
    err("INTEGRITY_CONFLICT", "connector", detail.into())
}

// ---------------------------------------------------------------------------
// Scalar validation
// ---------------------------------------------------------------------------

fn require_identifier(field: &str, value: &str) -> Result<(), ConnectorError> {
    if value.is_empty() {
        return Err(invalid(format!("{field} must be a nonempty identifier")));
    }
    Ok(())
}

fn require_enum(field: &str, value: &str, allowed: &[&str]) -> Result<(), ConnectorError> {
    if !allowed.contains(&value) {
        return Err(invalid(format!(
            "{field} {value:?} must be one of {}",
            allowed.join(", ")
        )));
    }
    Ok(())
}

fn require_unique(items: &[String], what: &str) -> Result<(), ConnectorError> {
    let mut seen = BTreeSet::new();
    for item in items {
        if !seen.insert(item) {
            return Err(invalid(format!("{what} contains duplicate {item:?}")));
        }
    }
    Ok(())
}

fn require_revision(field: &str, value: u64) -> Result<(), ConnectorError> {
    if value > MAX_SAFE_INTEGER {
        return Err(invalid(format!(
            "{field} {value} is outside 0..={MAX_SAFE_INTEGER}"
        )));
    }
    Ok(())
}

fn require_missing(what: &str, missing: &Missing) -> Result<(), ConnectorError> {
    if !MISSING_REASONS.contains(&missing.reason.as_str()) {
        return Err(invalid(format!(
            "{what} carries invalid Missing reason {:?}",
            missing.reason
        )));
    }
    if matches!(&missing.detail, Some(d) if d.is_empty()) {
        return Err(invalid(format!("{what} Missing detail must be nonempty")));
    }
    Ok(())
}

fn require_digest(field: &str, digest: &Digest) -> Result<(), ConnectorError> {
    if !rm_wire::is_valid_digest(digest.as_str()) {
        return Err(invalid(format!(
            "{field} {:?} is not a sha256 digest",
            digest.as_str()
        )));
    }
    Ok(())
}

fn validate_duration_limit(limit: &DurationLimit, what: &str) -> Result<(), ConnectorError> {
    if limit.kind != "exact" {
        return Err(invalid(format!("{what} kind {:?} must be \"exact\"", limit.kind)));
    }
    if limit.unit != "ms" {
        return Err(invalid(format!("{what} unit {:?} must be \"ms\"", limit.unit)));
    }
    if !limit.value.is_finite() || limit.value < 0.0 {
        return Err(invalid(format!("{what} value must be a finite nonnegative number")));
    }
    Ok(())
}

fn validate_version_pin(pin: &VersionPin, what: &str) -> Result<(), ConnectorError> {
    require_identifier(&format!("{what} id"), &pin.id)?;
    require_identifier(&format!("{what} version"), &pin.version)?;
    require_digest(&format!("{what} artifact_digest"), &pin.artifact_digest)?;
    Ok(())
}

fn validate_maybe_string(what: &str, value: &CatalogMaybeString) -> Result<(), ConnectorError> {
    match value {
        CatalogMaybeString::Text(text) => require_identifier(what, text),
        CatalogMaybeString::Missing(missing) => require_missing(what, missing),
    }
}

fn validate_maybe_pin(
    what: &str,
    value: &CatalogMaybeVersionPin,
) -> Result<(), ConnectorError> {
    match value {
        CatalogMaybeVersionPin::Present(pin) => validate_version_pin(pin, what),
        CatalogMaybeVersionPin::Missing(missing) => require_missing(what, missing),
    }
}

fn missing_json(missing: &Missing) -> Value {
    match &missing.detail {
        Some(detail) => json!({"value": null, "reason": missing.reason, "detail": detail}),
        None => json!({"value": null, "reason": missing.reason}),
    }
}

fn maybe_string_json(value: &CatalogMaybeString) -> Value {
    match value {
        CatalogMaybeString::Text(text) => Value::String(text.clone()),
        CatalogMaybeString::Missing(missing) => missing_json(missing),
    }
}

fn maybe_pin_json(value: &CatalogMaybeVersionPin) -> Value {
    match value {
        CatalogMaybeVersionPin::Present(pin) => pin.to_json(),
        CatalogMaybeVersionPin::Missing(missing) => missing_json(missing),
    }
}

fn parse_missing(value: &Value) -> Result<Missing, ConnectorError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("Missing envelope must be a JSON object"))?;
    if object.get("value") != Some(&Value::Null) {
        return Err(invalid("Missing envelope requires \"value\": null"));
    }
    let reason = object
        .get("reason")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("Missing envelope requires string \"reason\""))?;
    // Accept both casings; emit lowercase. Wire allows lowercase.
    let detail = object
        .get("detail")
        .or_else(|| object.get("Detail"))
        .and_then(Value::as_str)
        .map(|s| s.to_string());
    for key in object.keys() {
        if key != "value" && key != "reason" && key != "detail" && key != "Detail" {
            return Err(invalid(format!("Missing envelope has undeclared field {key:?}")));
        }
    }
    let missing = Missing { reason: reason.to_string(), detail };
    require_missing("missing", &missing)?;
    Ok(missing)
}

fn is_missing_envelope(value: &Value) -> bool {
    matches!(value.as_object(), Some(map) if map.get("value") == Some(&Value::Null))
}

fn parse_maybe_string(value: &Value) -> Result<CatalogMaybeString, ConnectorError> {
    if is_missing_envelope(value) {
        return Ok(CatalogMaybeString::Missing(parse_missing(value)?));
    }
    match value.as_str() {
        Some(text) => Ok(CatalogMaybeString::Text(text.to_string())),
        None => Err(invalid("expected identifier string or Missing envelope")),
    }
}

fn parse_version_pin(value: &Value) -> Result<VersionPin, ConnectorError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("version pin must be a JSON object"))?;
    if object.len() != 3
        || !object.contains_key("id")
        || !object.contains_key("version")
        || !object.contains_key("artifact_digest")
    {
        return Err(invalid("version pin requires exactly id, version, artifact_digest"));
    }
    let id = object
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("version pin id must be a string"))?
        .to_string();
    let version = object
        .get("version")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("version pin version must be a string"))?
        .to_string();
    let digest_str = object
        .get("artifact_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("version pin artifact_digest must be a string"))?;
    let artifact_digest = Digest::parse(digest_str).map_err(invalid)?;
    let pin = VersionPin { id, version, artifact_digest };
    validate_version_pin(&pin, "version pin")?;
    Ok(pin)
}

fn parse_maybe_pin(value: &Value) -> Result<CatalogMaybeVersionPin, ConnectorError> {
    if is_missing_envelope(value) {
        return Ok(CatalogMaybeVersionPin::Missing(parse_missing(value)?));
    }
    Ok(CatalogMaybeVersionPin::Present(parse_version_pin(value)?))
}

fn parse_component(value: &Value) -> Result<ComponentIdentity, ConnectorError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("component must be a JSON object"))?;
    let component = object
        .get("component")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("component requires string \"component\""))?
        .to_string();
    let reported_version = parse_maybe_string(
        object.get("reported_version").ok_or_else(|| invalid("component requires reported_version"))?,
    )?;
    let build_digest = parse_maybe_digest(
        object.get("build_digest").ok_or_else(|| invalid("component requires build_digest"))?,
    )?;
    let configuration_digest = parse_maybe_digest(
        object
            .get("configuration_digest")
            .ok_or_else(|| invalid("component requires configuration_digest"))?,
    )?;
    Ok(ComponentIdentity { component, reported_version, build_digest, configuration_digest })
}

fn parse_maybe_digest(value: &Value) -> Result<CatalogMaybeDigest, ConnectorError> {
    if is_missing_envelope(value) {
        return Ok(CatalogMaybeDigest::Missing(parse_missing(value)?));
    }
    match value.as_str() {
        Some(text) => Ok(CatalogMaybeDigest::Present(Digest::parse(text).map_err(invalid)?)),
        None => Err(invalid("expected digest string or Missing envelope")),
    }
}

#[allow(dead_code)]
fn maybe_digest_json(value: &CatalogMaybeDigest) -> Value {
    match value {
        CatalogMaybeDigest::Present(digest) => Value::String(digest.as_str().to_string()),
        CatalogMaybeDigest::Missing(missing) => missing_json(missing),
    }
}

fn parse_subject(value: &Value) -> Result<SubjectIdentity, ConnectorError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("subject must be a JSON object"))?;
    let subject_id = object
        .get("subject_id")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("subject requires subject_id"))?
        .to_string();
    let subject_version = object
        .get("subject_version")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("subject requires subject_version"))?
        .to_string();
    let revision_basis = object
        .get("revision_basis")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("subject requires revision_basis"))?
        .to_string();
    let native_revision = parse_maybe_string(
        object.get("native_revision").ok_or_else(|| invalid("subject requires native_revision"))?,
    )?;
    let configured_mode = object
        .get("configured_mode")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("subject requires configured_mode"))?
        .to_string();
    let interface_surface = object
        .get("interface_surface")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("subject requires interface_surface"))?
        .to_string();
    let configuration_digest = Digest::parse(
        object
            .get("configuration_digest")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("subject requires configuration_digest"))?,
    )
    .map_err(invalid)?;
    let stack_value = object.get("stack").ok_or_else(|| invalid("subject requires stack"))?;
    let stack_array = stack_value.as_array().ok_or_else(|| invalid("subject stack must be an array"))?;
    let mut stack = Vec::with_capacity(stack_array.len());
    for item in stack_array {
        stack.push(parse_component(item)?);
    }
    Ok(SubjectIdentity {
        subject_id,
        subject_version,
        revision_basis,
        native_revision,
        configured_mode,
        interface_surface,
        configuration_digest,
        stack,
    })
}

fn parse_duration_limit(value: &Value) -> Result<DurationLimit, ConnectorError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("duration limit must be a JSON object"))?;
    let kind = object
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("duration limit requires kind"))?
        .to_string();
    let unit = object
        .get("unit")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("duration limit requires unit"))?
        .to_string();
    let number = object.get("value").ok_or_else(|| invalid("duration limit requires value"))?;
    let num = number.as_f64().ok_or_else(|| invalid("duration limit value must be a number"))?;
    let limit = DurationLimit { kind, unit, value: num };
    validate_duration_limit(&limit, "duration limit")?;
    Ok(limit)
}

fn parse_journal_prefix(value: &Value) -> Result<JournalPrefix, ConnectorError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("journal prefix must be a JSON object"))?;
    let journal_id = object
        .get("journal_id")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("journal prefix requires journal_id"))?
        .to_string();
    let last_sequence = object
        .get("last_sequence")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid("journal prefix requires integer last_sequence"))?;
    let head_hash = Digest::parse(
        object
            .get("head_hash")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("journal prefix requires head_hash"))?,
    )
    .map_err(invalid)?;
    require_identifier("prefix journal_id", &journal_id)?;
    require_digest("prefix head_hash", &head_hash)?;
    Ok(JournalPrefix { journal_id, last_sequence: PositiveInteger::new(last_sequence)?, head_hash })
}

// ---------------------------------------------------------------------------
// Task shapes
// ---------------------------------------------------------------------------

/// Entry point: logical identity plus authorized URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryPoint {
    pub logical_id: String,
    pub url: String,
}

impl EntryPoint {
    pub fn to_json(&self) -> Value {
        json!({"logical_id": self.logical_id, "url": self.url})
    }

    pub fn from_json(value: &Value) -> Result<Self, ConnectorError> {
        let object = value.as_object().ok_or_else(|| invalid("entry must be an object"))?;
        let logical_id = object
            .get("logical_id")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("entry requires logical_id"))?
            .to_string();
        let url = object
            .get("url")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("entry requires url"))?
            .to_string();
        Ok(EntryPoint { logical_id, url })
    }
}

/// Permitted origin: logical identity plus canonical origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermittedOrigin {
    pub logical_id: String,
    pub origin: String,
}

impl PermittedOrigin {
    pub fn to_json(&self) -> Value {
        json!({"logical_id": self.logical_id, "origin": self.origin})
    }

    pub fn from_json(value: &Value) -> Result<Self, ConnectorError> {
        let object = value.as_object().ok_or_else(|| invalid("permitted origin must be an object"))?;
        let logical_id = object
            .get("logical_id")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("permitted origin requires logical_id"))?
            .to_string();
        let origin = object
            .get("origin")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("permitted origin requires origin"))?
            .to_string();
        Ok(PermittedOrigin { logical_id, origin })
    }
}

/// One success criterion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuccessCriterion {
    pub criterion_id: String,
    pub description: String,
}

impl SuccessCriterion {
    pub fn to_json(&self) -> Value {
        json!({"criterion_id": self.criterion_id, "description": self.description})
    }

    pub fn from_json(value: &Value) -> Result<Self, ConnectorError> {
        let object = value.as_object().ok_or_else(|| invalid("success criterion must be an object"))?;
        let criterion_id = object
            .get("criterion_id")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("criterion requires criterion_id"))?
            .to_string();
        let description = object
            .get("description")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("criterion requires description"))?
            .to_string();
        Ok(SuccessCriterion { criterion_id, description })
    }
}

/// One task input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskInput {
    pub name: String,
    pub purpose: String,
    pub content: ArtifactReference,
}

impl TaskInput {
    pub fn to_json(&self) -> Value {
        json!({"name": self.name, "purpose": self.purpose, "content": self.content.to_json()})
    }

    pub fn from_json(value: &Value) -> Result<Self, ConnectorError> {
        let object = value.as_object().ok_or_else(|| invalid("task input must be an object"))?;
        let name = object
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("input requires name"))?
            .to_string();
        let purpose = object
            .get("purpose")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("input requires purpose"))?
            .to_string();
        let content = ArtifactReference::from_json(
            object.get("content").ok_or_else(|| invalid("input requires content"))?,
        )?;
        Ok(TaskInput { name, purpose, content })
    }
}

/// Configured task budgets (limits, never measurements).
#[derive(Debug, Clone, PartialEq)]
pub struct TaskBudgets {
    pub active_limit: DurationLimit,
    pub action_limit: u64,
    pub observation_byte_limit: u64,
    pub recovery_limit: u64,
    pub model_token_limit: u64,
}

impl TaskBudgets {
    pub fn to_json(&self) -> Value {
        json!({
            "active_limit": self.active_limit.to_json(),
            "action_limit": self.action_limit,
            "observation_byte_limit": self.observation_byte_limit,
            "recovery_limit": self.recovery_limit,
            "model_token_limit": self.model_token_limit,
        })
    }

    pub fn from_json(value: &Value) -> Result<Self, ConnectorError> {
        let object = value.as_object().ok_or_else(|| invalid("budgets must be an object"))?;
        let active_limit = parse_duration_limit(
            object.get("active_limit").ok_or_else(|| invalid("budgets require active_limit"))?,
        )?;
        let action_limit = object
            .get("action_limit")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid("budgets require integer action_limit"))?;
        let observation_byte_limit = object
            .get("observation_byte_limit")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid("budgets require integer observation_byte_limit"))?;
        let recovery_limit = object
            .get("recovery_limit")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid("budgets require integer recovery_limit"))?;
        let model_token_limit = object
            .get("model_token_limit")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid("budgets require integer model_token_limit"))?;
        Ok(TaskBudgets { active_limit, action_limit, observation_byte_limit, recovery_limit, model_token_limit })
    }
}

/// Present artifact or reasoned missingness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaybeArtifact {
    Present(ArtifactReference),
    Missing(Missing),
}

impl MaybeArtifact {
    pub fn to_json(&self) -> Value {
        match self {
            MaybeArtifact::Present(reference) => reference.to_json(),
            MaybeArtifact::Missing(missing) => missing_json(missing),
        }
    }

    pub fn from_json(value: &Value) -> Result<Self, ConnectorError> {
        if is_missing_envelope(value) {
            return Ok(MaybeArtifact::Missing(parse_missing(value)?));
        }
        Ok(MaybeArtifact::Present(ArtifactReference::from_json(value)?))
    }
}

/// Semantic state-policy request (not a guarantee).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatePolicy {
    pub mode: String,
    pub requirement: String,
    pub resource_ref: CatalogMaybeString,
    pub baseline: MaybeArtifact,
}

impl StatePolicy {
    pub fn to_json(&self) -> Value {
        json!({
            "mode": self.mode,
            "requirement": self.requirement,
            "resource_ref": maybe_string_json(&self.resource_ref),
            "baseline": self.baseline.to_json(),
        })
    }

    pub fn from_json(value: &Value) -> Result<Self, ConnectorError> {
        let object = value.as_object().ok_or_else(|| invalid("state policy must be an object"))?;
        let mode = object
            .get("mode")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("state policy requires mode"))?
            .to_string();
        let requirement = object
            .get("requirement")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("state policy requires requirement"))?
            .to_string();
        let resource_ref = parse_maybe_string(
            object.get("resource_ref").ok_or_else(|| invalid("state policy requires resource_ref"))?,
        )?;
        let baseline = MaybeArtifact::from_json(
            object.get("baseline").ok_or_else(|| invalid("state policy requires baseline"))?,
        )?;
        Ok(StatePolicy { mode, requirement, resource_ref, baseline })
    }
}

/// Independent browser/learning policies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextPolicy {
    pub browser_state: StatePolicy,
    pub learning_state: StatePolicy,
}

impl ContextPolicy {
    pub fn to_json(&self) -> Value {
        json!({
            "browser_state": self.browser_state.to_json(),
            "learning_state": self.learning_state.to_json(),
        })
    }

    pub fn from_json(value: &Value) -> Result<Self, ConnectorError> {
        let object = value.as_object().ok_or_else(|| invalid("context policy must be an object"))?;
        let browser_state = StatePolicy::from_json(
            object.get("browser_state").ok_or_else(|| invalid("context policy requires browser_state"))?,
        )?;
        let learning_state = StatePolicy::from_json(
            object.get("learning_state").ok_or_else(|| invalid("context policy requires learning_state"))?,
        )?;
        Ok(ContextPolicy { browser_state, learning_state })
    }
}

/// Full task envelope (Contract 02 `TaskEnvelope`).
#[derive(Debug, Clone, PartialEq)]
pub struct TaskEnvelope {
    pub record_type: String,
    pub schema_version: String,
    pub task_id: String,
    pub task_type: String,
    pub entry: EntryPoint,
    pub goal: String,
    pub success_criteria: Vec<SuccessCriterion>,
    pub inputs: Vec<TaskInput>,
    pub permitted_origins: Vec<PermittedOrigin>,
    pub permitted_interfaces: Vec<String>,
    pub effect_policy: String,
    pub budgets: TaskBudgets,
    pub context_policy: ContextPolicy,
    pub output_schema: CatalogMaybeVersionPin,
}

impl TaskEnvelope {
    pub fn to_json(&self) -> Value {
        json!({
            "record_type": self.record_type,
            "schema_version": self.schema_version,
            "task_id": self.task_id,
            "task_type": self.task_type,
            "entry": self.entry.to_json(),
            "goal": self.goal,
            "success_criteria": self.success_criteria.iter().map(SuccessCriterion::to_json).collect::<Vec<Value>>(),
            "inputs": self.inputs.iter().map(TaskInput::to_json).collect::<Vec<Value>>(),
            "permitted_origins": self.permitted_origins.iter().map(PermittedOrigin::to_json).collect::<Vec<Value>>(),
            "permitted_interfaces": self.permitted_interfaces,
            "effect_policy": self.effect_policy,
            "budgets": self.budgets.to_json(),
            "context_policy": self.context_policy.to_json(),
            "output_schema": maybe_pin_json(&self.output_schema),
        })
    }

    pub fn from_json(value: &Value) -> Result<Self, ConnectorError> {
        let object = value.as_object().ok_or_else(|| invalid("task must be an object"))?;
        let record_type = object
            .get("record_type")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("task requires record_type"))?
            .to_string();
        let schema_version = object
            .get("schema_version")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("task requires schema_version"))?
            .to_string();
        let task_id = object
            .get("task_id")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("task requires task_id"))?
            .to_string();
        let task_type = object
            .get("task_type")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("task requires task_type"))?
            .to_string();
        let entry = EntryPoint::from_json(object.get("entry").ok_or_else(|| invalid("task requires entry"))?)?;
        let goal = object
            .get("goal")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("task requires goal"))?
            .to_string();
        let criteria_value = object.get("success_criteria").ok_or_else(|| invalid("task requires success_criteria"))?;
        let criteria_array = criteria_value.as_array().ok_or_else(|| invalid("success_criteria must be an array"))?;
        let mut success_criteria = Vec::with_capacity(criteria_array.len());
        for item in criteria_array {
            success_criteria.push(SuccessCriterion::from_json(item)?);
        }
        let inputs_value = object.get("inputs").ok_or_else(|| invalid("task requires inputs"))?;
        let inputs_array = inputs_value.as_array().ok_or_else(|| invalid("inputs must be an array"))?;
        let mut inputs = Vec::with_capacity(inputs_array.len());
        for item in inputs_array {
            inputs.push(TaskInput::from_json(item)?);
        }
        let origins_value = object.get("permitted_origins").ok_or_else(|| invalid("task requires permitted_origins"))?;
        let origins_array = origins_value.as_array().ok_or_else(|| invalid("permitted_origins must be an array"))?;
        let mut permitted_origins = Vec::with_capacity(origins_array.len());
        for item in origins_array {
            permitted_origins.push(PermittedOrigin::from_json(item)?);
        }
        let interfaces_value = object.get("permitted_interfaces").ok_or_else(|| invalid("task requires permitted_interfaces"))?;
        let interfaces_array = interfaces_value.as_array().ok_or_else(|| invalid("permitted_interfaces must be an array"))?;
        let mut permitted_interfaces = Vec::with_capacity(interfaces_array.len());
        for item in interfaces_array {
            permitted_interfaces.push(item.as_str().ok_or_else(|| invalid("permitted interface must be a string"))?.to_string());
        }
        let effect_policy = object
            .get("effect_policy")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("task requires effect_policy"))?
            .to_string();
        let budgets = TaskBudgets::from_json(object.get("budgets").ok_or_else(|| invalid("task requires budgets"))?)?;
        let context_policy = ContextPolicy::from_json(
            object.get("context_policy").ok_or_else(|| invalid("task requires context_policy"))?,
        )?;
        let output_schema = parse_maybe_pin(
            object.get("output_schema").ok_or_else(|| invalid("task requires output_schema"))?,
        )?;
        Ok(TaskEnvelope {
            record_type,
            schema_version,
            task_id,
            task_type,
            entry,
            goal,
            success_criteria,
            inputs,
            permitted_origins,
            permitted_interfaces,
            effect_policy,
            budgets,
            context_policy,
            output_schema,
        })
    }
}

/// Declared assistance (Contract 02 `AssistanceRecord`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssistanceRecord {
    pub planning_owner: String,
    pub assistance_track: String,
    pub planner_identity: CatalogMaybeString,
    pub plan: MaybeArtifact,
    pub online_replanning: bool,
    pub description: String,
}

impl AssistanceRecord {
    pub fn to_json(&self) -> Value {
        json!({
            "planning_owner": self.planning_owner,
            "assistance_track": self.assistance_track,
            "planner_identity": maybe_string_json(&self.planner_identity),
            "plan": self.plan.to_json(),
            "online_replanning": self.online_replanning,
            "description": self.description,
        })
    }

    pub fn from_json(value: &Value) -> Result<Self, ConnectorError> {
        let object = value.as_object().ok_or_else(|| invalid("assistance must be an object"))?;
        let planning_owner = object
            .get("planning_owner")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("assistance requires planning_owner"))?
            .to_string();
        let assistance_track = object
            .get("assistance_track")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("assistance requires assistance_track"))?
            .to_string();
        let planner_identity = parse_maybe_string(
            object.get("planner_identity").ok_or_else(|| invalid("assistance requires planner_identity"))?,
        )?;
        let plan = MaybeArtifact::from_json(
            object.get("plan").ok_or_else(|| invalid("assistance requires plan"))?,
        )?;
        let online_replanning = object
            .get("online_replanning")
            .and_then(Value::as_bool)
            .ok_or_else(|| invalid("assistance requires boolean online_replanning"))?;
        let description = object
            .get("description")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("assistance requires description"))?
            .to_string();
        Ok(AssistanceRecord { planning_owner, assistance_track, planner_identity, plan, online_replanning, description })
    }
}

/// Opaque runtime access binding (never secret bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeAccess {
    pub purpose: String,
    pub access_ref: String,
    pub authorization_refs: Vec<EvidenceRef>,
}

impl RuntimeAccess {
    pub fn to_json(&self) -> Value {
        json!({
            "purpose": self.purpose,
            "access_ref": self.access_ref,
            "authorization_refs": self.authorization_refs.iter().map(EvidenceRef::to_json).collect::<Vec<Value>>(),
        })
    }

    pub fn from_json(value: &Value) -> Result<Self, ConnectorError> {
        let object = value.as_object().ok_or_else(|| invalid("runtime access must be an object"))?;
        let purpose = object
            .get("purpose")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("runtime access requires purpose"))?
            .to_string();
        let access_ref = object
            .get("access_ref")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("runtime access requires access_ref"))?
            .to_string();
        let refs_value = object.get("authorization_refs").ok_or_else(|| invalid("runtime access requires authorization_refs"))?;
        let refs_array = refs_value.as_array().ok_or_else(|| invalid("authorization_refs must be an array"))?;
        let mut authorization_refs = Vec::with_capacity(refs_array.len());
        for item in refs_array {
            authorization_refs.push(EvidenceRef::from_json(item)?);
        }
        Ok(RuntimeAccess { purpose, access_ref, authorization_refs })
    }
}

/// Previously journaled planning cost (not a request to plan).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparationMeasurement {
    pub cost_id: String,
    pub evidence: EvidenceRef,
    pub detail: String,
}

impl PreparationMeasurement {
    pub fn to_json(&self) -> Value {
        json!({
            "cost_id": self.cost_id,
            "evidence": self.evidence.to_json(),
            "detail": self.detail,
        })
    }

    pub fn from_json(value: &Value) -> Result<Self, ConnectorError> {
        let object = value.as_object().ok_or_else(|| invalid("preparation measurement must be an object"))?;
        let cost_id = object
            .get("cost_id")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("measurement requires cost_id"))?
            .to_string();
        let evidence = EvidenceRef::from_json(
            object.get("evidence").ok_or_else(|| invalid("measurement requires evidence"))?,
        )?;
        let detail = object
            .get("detail")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("measurement requires detail"))?
            .to_string();
        Ok(PreparationMeasurement { cost_id, evidence, detail })
    }
}

/// Exact descriptor/subject pin with copied values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigurationPin {
    pub connector_id: String,
    pub connector_version: String,
    pub binding: VersionPin,
    pub subject: SubjectIdentity,
    pub descriptor: ArtifactReference,
    pub descriptor_ref: EvidenceRef,
}

impl ConfigurationPin {
    pub fn to_json(&self) -> Value {
        json!({
            "connector_id": self.connector_id,
            "connector_version": self.connector_version,
            "binding": self.binding.to_json(),
            "subject": self.subject.to_json(),
            "descriptor": self.descriptor.to_json(),
            "descriptor_ref": self.descriptor_ref.to_json(),
        })
    }

    pub fn from_json(value: &Value) -> Result<Self, ConnectorError> {
        let object = value.as_object().ok_or_else(|| invalid("configuration must be an object"))?;
        let connector_id = object
            .get("connector_id")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("configuration requires connector_id"))?
            .to_string();
        let connector_version = object
            .get("connector_version")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("configuration requires connector_version"))?
            .to_string();
        let binding = parse_version_pin(
            object.get("binding").ok_or_else(|| invalid("configuration requires binding"))?,
        )?;
        let subject = parse_subject(
            object.get("subject").ok_or_else(|| invalid("configuration requires subject"))?,
        )?;
        let descriptor = ArtifactReference::from_json(
            object.get("descriptor").ok_or_else(|| invalid("configuration requires descriptor"))?,
        )?;
        let descriptor_ref = EvidenceRef::from_json(
            object.get("descriptor_ref").ok_or_else(|| invalid("configuration requires descriptor_ref"))?,
        )?;
        Ok(ConfigurationPin { connector_id, connector_version, binding, subject, descriptor, descriptor_ref })
    }
}

/// One budget dimension mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetMapping {
    pub dimension: String,
    pub enforcer: String,
    pub evidence_refs: Vec<EvidenceRef>,
    pub limitations: Vec<String>,
}

impl BudgetMapping {
    pub fn to_json(&self) -> Value {
        json!({
            "dimension": self.dimension,
            "enforcer": self.enforcer,
            "evidence_refs": self.evidence_refs.iter().map(EvidenceRef::to_json).collect::<Vec<Value>>(),
            "limitations": self.limitations,
        })
    }

    pub fn from_json(value: &Value) -> Result<Self, ConnectorError> {
        let object = value.as_object().ok_or_else(|| invalid("budget mapping must be an object"))?;
        let dimension = object
            .get("dimension")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("budget mapping requires dimension"))?
            .to_string();
        let enforcer = object
            .get("enforcer")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("budget mapping requires enforcer"))?
            .to_string();
        let refs_value = object.get("evidence_refs").ok_or_else(|| invalid("budget mapping requires evidence_refs"))?;
        let refs_array = refs_value.as_array().ok_or_else(|| invalid("evidence_refs must be an array"))?;
        let mut evidence_refs = Vec::with_capacity(refs_array.len());
        for item in refs_array {
            evidence_refs.push(EvidenceRef::from_json(item)?);
        }
        let limits_value = object.get("limitations").ok_or_else(|| invalid("budget mapping requires limitations"))?;
        let limits_array = limits_value.as_array().ok_or_else(|| invalid("limitations must be an array"))?;
        let mut limitations = Vec::with_capacity(limits_array.len());
        for item in limits_array {
            limitations.push(item.as_str().ok_or_else(|| invalid("limitation must be a string"))?.to_string());
        }
        Ok(BudgetMapping { dimension, enforcer, evidence_refs, limitations })
    }
}

/// One non-blocking preparation limitation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparationConcern {
    pub concern_id: String,
    pub category: String,
    pub disposition: String,
    pub detail: String,
    pub evidence_refs: Vec<EvidenceRef>,
}

impl PreparationConcern {
    pub fn to_json(&self) -> Value {
        json!({
            "concern_id": self.concern_id,
            "category": self.category,
            "disposition": self.disposition,
            "detail": self.detail,
            "evidence_refs": self.evidence_refs.iter().map(EvidenceRef::to_json).collect::<Vec<Value>>(),
        })
    }

    pub fn from_json(value: &Value) -> Result<Self, ConnectorError> {
        let object = value.as_object().ok_or_else(|| invalid("concern must be an object"))?;
        let concern_id = object
            .get("concern_id")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("concern requires concern_id"))?
            .to_string();
        let category = object
            .get("category")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("concern requires category"))?
            .to_string();
        let disposition = object
            .get("disposition")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("concern requires disposition"))?
            .to_string();
        let detail = object
            .get("detail")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("concern requires detail"))?
            .to_string();
        let refs_value = object.get("evidence_refs").ok_or_else(|| invalid("concern requires evidence_refs"))?;
        let refs_array = refs_value.as_array().ok_or_else(|| invalid("evidence_refs must be an array"))?;
        let mut evidence_refs = Vec::with_capacity(refs_array.len());
        for item in refs_array {
            evidence_refs.push(EvidenceRef::from_json(item)?);
        }
        Ok(PreparationConcern { concern_id, category, disposition, detail, evidence_refs })
    }
}

// ---------------------------------------------------------------------------
// Scope / manifest JSON helpers (authority views are string-based)
// ---------------------------------------------------------------------------

fn scope_to_json(scope: &WorkScope) -> Value {
    json!({
        "activity": scope.activity,
        "run_id": scope.run_id,
        "journal_id": scope.journal_id,
        "manifest_hash": scope.manifest_hash,
        "admission_ref": scope.admission_ref,
        "attempt_id": scope.attempt_id.clone().map(Value::String).unwrap_or_else(|| missing_json(&Missing::new("not_applicable"))),
        "commission_id": scope.commission_id.clone().map(Value::String).unwrap_or_else(|| missing_json(&Missing::new("not_applicable"))),
        "commission_ref": scope.commission_ref.clone().map(Value::String).unwrap_or_else(|| missing_json(&Missing::new("not_applicable"))),
        "attempt_kind": scope.attempt_kind.map(|kind| match kind {
            AttemptKind::Practice => Value::String("practice".to_string()),
            AttemptKind::Production => Value::String("production".to_string()),
        }).unwrap_or_else(|| missing_json(&Missing::new("not_applicable"))),
        "authorization_refs": scope.authorization_refs,
        "observation_policy": scope.observation_policy,
        "owner_domain": scope.owner_domain,
        "execution_mode": match scope.execution_mode {
            ExecutionMode::Automated => "automated",
            ExecutionMode::Manual => "manual",
        },
    })
}

fn scope_from_json(value: &Value) -> Result<WorkScope, ConnectorError> {
    let object = value.as_object().ok_or_else(|| invalid("scope must be an object"))?;
    let get_str = |field: &str| -> Result<String, ConnectorError> {
        object
            .get(field)
            .and_then(Value::as_str)
            .map(|s| s.to_string())
            .ok_or_else(|| invalid(format!("scope requires {field}")))
    };
    let activity = get_str("activity")?;
    let run_id = get_str("run_id")?;
    let journal_id = get_str("journal_id")?;
    let manifest_hash = get_str("manifest_hash")?;
    let admission_ref = get_str("admission_ref")?;
    let parse_optional = |field: &str| -> Result<Option<String>, ConnectorError> {
        match object.get(field) {
            None => Err(invalid(format!("scope requires {field}"))),
            Some(Value::String(text)) => Ok(Some(text.clone())),
            Some(value) if is_missing_envelope(value) => {
                parse_missing(value)?;
                Ok(None)
            }
            Some(_) => Err(invalid(format!("scope field {field} must be a string or Missing"))),
        }
    };
    let attempt_id = parse_optional("attempt_id")?;
    let commission_id = parse_optional("commission_id")?;
    let commission_ref = parse_optional("commission_ref")?;
    let attempt_kind = match object.get("attempt_kind") {
        None => return Err(invalid("scope requires attempt_kind")),
        Some(Value::String(text)) if text == "practice" => Some(AttemptKind::Practice),
        Some(Value::String(text)) if text == "production" => Some(AttemptKind::Production),
        Some(value) if is_missing_envelope(value) => {
            parse_missing(value)?;
            None
        }
        Some(_) => return Err(invalid("scope attempt_kind must be practice, production, or Missing")),
    };
    let auth_value = object.get("authorization_refs").ok_or_else(|| invalid("scope requires authorization_refs"))?;
    let auth_array = auth_value.as_array().ok_or_else(|| invalid("authorization_refs must be an array"))?;
    let mut authorization_refs = Vec::with_capacity(auth_array.len());
    for item in auth_array {
        authorization_refs.push(item.as_str().ok_or_else(|| invalid("authorization ref must be a string"))?.to_string());
    }
    let observation_policy = get_str("observation_policy")?;
    let owner_domain = get_str("owner_domain")?;
    let execution_mode = match get_str("execution_mode")?.as_str() {
        "automated" => ExecutionMode::Automated,
        "manual" => ExecutionMode::Manual,
        other => return Err(invalid(format!("unknown execution_mode {other:?}"))),
    };
    Ok(WorkScope {
        activity,
        run_id,
        journal_id,
        manifest_hash,
        admission_ref,
        attempt_id,
        commission_id,
        commission_ref,
        attempt_kind,
        authorization_refs,
        observation_policy,
        owner_domain,
        execution_mode,
    })
}

// ---------------------------------------------------------------------------
// Prepare request / prepared task / connector request
// ---------------------------------------------------------------------------

/// Validated Prepare payload plus the authority bindings needed to enforce it.
#[derive(Debug, Clone)]
pub struct PrepareRequest {
    pub scope: WorkScope,
    pub manifest: Manifest,
    pub commission: Option<AttemptCommission>,
    pub configuration: ConfigurationPin,
    pub task: TaskEnvelope,
    pub assistance: AssistanceRecord,
    pub planning_evidence_refs: Vec<EvidenceRef>,
    pub preparation_measurements: Vec<PreparationMeasurement>,
    pub runtime_access: Vec<RuntimeAccess>,
    /// Optional native binding descriptor validated through `rm_catalog`.
    pub native_binding: Option<BOBindingDescriptor>,
}

impl PrepareRequest {
    pub fn to_json(&self) -> Value {
        // Manifest and commission are authority views; serialize the fields
        // needed for wire structural validation without bare nulls.
        let manifest_json = json!({
            "record_type": self.manifest.record_type,
            "schema_version": self.manifest.schema_version,
            "run_id": self.manifest.run_id,
            "task": self.manifest.task,
            "subject": self.manifest.subject,
            "event_kinds": self.manifest.event_kinds,
            "admission_ref": self.manifest.admission_ref,
            "manifest_hash": self.manifest.manifest_hash,
        });
        let commission_json = match &self.commission {
            Some(commission) => json!({
                "commission_id": commission.commission_id,
                "attempt_id": commission.attempt_id,
                "manifest_hash": commission.manifest_hash,
                "task_semantic_hash": commission.task_semantic_hash,
            }),
            None => missing_json(&Missing::new("not_applicable")),
        };
        json!({
            "scope": scope_to_json(&self.scope),
            "manifest": manifest_json,
            "commission": commission_json,
            "configuration": self.configuration.to_json(),
            "task": self.task.to_json(),
            "assistance": self.assistance.to_json(),
            "planning_evidence_refs": self.planning_evidence_refs.iter().map(EvidenceRef::to_json).collect::<Vec<Value>>(),
            "preparation_measurements": self.preparation_measurements.iter().map(PreparationMeasurement::to_json).collect::<Vec<Value>>(),
            "runtime_access": self.runtime_access.iter().map(RuntimeAccess::to_json).collect::<Vec<Value>>(),
        })
    }
}

/// Immutable preparation record (Contract 02 `PreparedTask`).
#[derive(Debug, Clone)]
pub struct PreparedTask {
    pub record_type: String,
    pub schema_version: String,
    pub preparation_id: String,
    pub scope: WorkScope,
    pub configuration: ConfigurationPin,
    pub task: TaskEnvelope,
    pub task_semantic_hash: Digest,
    pub assistance: AssistanceRecord,
    pub planning_evidence_refs: Vec<EvidenceRef>,
    pub runtime_access: Vec<RuntimeAccess>,
    pub delivered_task: ArtifactReference,
    pub delivered_task_hash: Digest,
    pub native_request: ArtifactReference,
    pub native_request_hash: Digest,
    pub translation: VersionPin,
    pub budget_mapping: Vec<BudgetMapping>,
    pub concerns: Vec<PreparationConcern>,
    pub evidence_prefix: JournalPrefix,
}

impl PreparedTask {
    pub fn to_json(&self) -> Value {
        json!({
            "record_type": self.record_type,
            "schema_version": self.schema_version,
            "preparation_id": self.preparation_id,
            "scope": scope_to_json(&self.scope),
            "configuration": self.configuration.to_json(),
            "task": self.task.to_json(),
            "task_semantic_hash": self.task_semantic_hash.as_str(),
            "assistance": self.assistance.to_json(),
            "planning_evidence_refs": self.planning_evidence_refs.iter().map(EvidenceRef::to_json).collect::<Vec<Value>>(),
            "runtime_access": self.runtime_access.iter().map(RuntimeAccess::to_json).collect::<Vec<Value>>(),
            "delivered_task": self.delivered_task.to_json(),
            "delivered_task_hash": self.delivered_task_hash.as_str(),
            "native_request": self.native_request.to_json(),
            "native_request_hash": self.native_request_hash.as_str(),
            "translation": self.translation.to_json(),
            "budget_mapping": self.budget_mapping.iter().map(BudgetMapping::to_json).collect::<Vec<Value>>(),
            "concerns": self.concerns.iter().map(PreparationConcern::to_json).collect::<Vec<Value>>(),
            "evidence_prefix": self.evidence_prefix.to_json(),
        })
    }

    pub fn from_json(value: &Value) -> Result<Self, ConnectorError> {
        let object = value.as_object().ok_or_else(|| invalid("preparation must be an object"))?;
        let get_str = |field: &str| -> Result<String, ConnectorError> {
            object
                .get(field)
                .and_then(Value::as_str)
                .map(|s| s.to_string())
                .ok_or_else(|| invalid(format!("preparation requires {field}")))
        };
        let record_type = get_str("record_type")?;
        let schema_version = get_str("schema_version")?;
        let preparation_id = get_str("preparation_id")?;
        let scope = scope_from_json(object.get("scope").ok_or_else(|| invalid("preparation requires scope"))?)?;
        let configuration = ConfigurationPin::from_json(
            object.get("configuration").ok_or_else(|| invalid("preparation requires configuration"))?,
        )?;
        let task = TaskEnvelope::from_json(object.get("task").ok_or_else(|| invalid("preparation requires task"))?)?;
        let task_semantic_hash = Digest::parse(&get_str("task_semantic_hash")?).map_err(invalid)?;
        let assistance = AssistanceRecord::from_json(
            object.get("assistance").ok_or_else(|| invalid("preparation requires assistance"))?,
        )?;
        let planning_value = object.get("planning_evidence_refs").ok_or_else(|| invalid("preparation requires planning_evidence_refs"))?;
        let planning_array = planning_value.as_array().ok_or_else(|| invalid("planning_evidence_refs must be an array"))?;
        let mut planning_evidence_refs = Vec::with_capacity(planning_array.len());
        for item in planning_array {
            planning_evidence_refs.push(EvidenceRef::from_json(item)?);
        }
        let access_value = object.get("runtime_access").ok_or_else(|| invalid("preparation requires runtime_access"))?;
        let access_array = access_value.as_array().ok_or_else(|| invalid("runtime_access must be an array"))?;
        let mut runtime_access = Vec::with_capacity(access_array.len());
        for item in access_array {
            runtime_access.push(RuntimeAccess::from_json(item)?);
        }
        let delivered_task = ArtifactReference::from_json(
            object.get("delivered_task").ok_or_else(|| invalid("preparation requires delivered_task"))?,
        )?;
        let delivered_task_hash = Digest::parse(&get_str("delivered_task_hash")?).map_err(invalid)?;
        let native_request = ArtifactReference::from_json(
            object.get("native_request").ok_or_else(|| invalid("preparation requires native_request"))?,
        )?;
        let native_request_hash = Digest::parse(&get_str("native_request_hash")?).map_err(invalid)?;
        let translation = parse_version_pin(
            object.get("translation").ok_or_else(|| invalid("preparation requires translation"))?,
        )?;
        let budget_value = object.get("budget_mapping").ok_or_else(|| invalid("preparation requires budget_mapping"))?;
        let budget_array = budget_value.as_array().ok_or_else(|| invalid("budget_mapping must be an array"))?;
        let mut budget_mapping = Vec::with_capacity(budget_array.len());
        for item in budget_array {
            budget_mapping.push(BudgetMapping::from_json(item)?);
        }
        let concerns_value = object.get("concerns").ok_or_else(|| invalid("preparation requires concerns"))?;
        let concerns_array = concerns_value.as_array().ok_or_else(|| invalid("concerns must be an array"))?;
        let mut concerns = Vec::with_capacity(concerns_array.len());
        for item in concerns_array {
            concerns.push(PreparationConcern::from_json(item)?);
        }
        let evidence_prefix = parse_journal_prefix(
            object.get("evidence_prefix").ok_or_else(|| invalid("preparation requires evidence_prefix"))?,
        )?;
        let prepared = PreparedTask {
            record_type,
            schema_version,
            preparation_id,
            scope,
            configuration,
            task,
            task_semantic_hash,
            assistance,
            planning_evidence_refs,
            runtime_access,
            delivered_task,
            delivered_task_hash,
            native_request,
            native_request_hash,
            translation,
            budget_mapping,
            concerns,
            evidence_prefix,
        };
        validate_prepared_shape(&prepared)?;
        Ok(prepared)
    }
}

/// Immutable preparation reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparationReference {
    pub preparation_id: String,
    pub artifact: ArtifactReference,
    pub registration_ref: EvidenceRef,
}

impl PreparationReference {
    pub fn to_json(&self) -> Value {
        json!({
            "preparation_id": self.preparation_id,
            "artifact": self.artifact.to_json(),
            "registration_ref": self.registration_ref.to_json(),
        })
    }

    pub fn from_json(value: &Value) -> Result<Self, ConnectorError> {
        let object = value.as_object().ok_or_else(|| invalid("preparation reference must be an object"))?;
        let preparation_id = object
            .get("preparation_id")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("reference requires preparation_id"))?
            .to_string();
        let artifact = ArtifactReference::from_json(
            object.get("artifact").ok_or_else(|| invalid("reference requires artifact"))?,
        )?;
        let registration_ref = EvidenceRef::from_json(
            object.get("registration_ref").ok_or_else(|| invalid("reference requires registration_ref"))?,
        )?;
        Ok(PreparationReference { preparation_id, artifact, registration_ref })
    }
}

/// Successful Prepare result.
#[derive(Debug, Clone)]
pub struct PrepareResult {
    pub kind: String,
    pub preparation: PreparationReference,
    pub record: PreparedTask,
}

impl PrepareResult {
    pub fn to_json(&self) -> Value {
        json!({
            "kind": self.kind,
            "preparation": self.preparation.to_json(),
            "record": self.record.to_json(),
        })
    }
}

/// Validated connector command envelope for `Prepare`.
#[derive(Debug, Clone)]
pub struct ConnectorRequest {
    pub record_type: String,
    pub schema_version: String,
    pub request_id: String,
    pub connector_id: String,
    pub operation: String,
    pub call_limit: DurationLimit,
    pub payload: PrepareRequest,
}

impl ConnectorRequest {
    pub fn to_json(&self) -> Value {
        json!({
            "record_type": self.record_type,
            "schema_version": self.schema_version,
            "request_id": self.request_id,
            "connector_id": self.connector_id,
            "operation": self.operation,
            "call_limit": self.call_limit.to_json(),
            "payload": self.payload.to_json(),
        })
    }
}

// ---------------------------------------------------------------------------
// Task validation (§13.2)
// ---------------------------------------------------------------------------

fn origin_of_url(url: &str) -> Result<String, ConnectorError> {
    // Parse scheme://host[:port] without userinfo, path, query, fragment.
    // Reject credential disclosure and unauthorized destinations.
    let rest = url
        .strip_prefix("https://")
        .map(|r| ("https", r))
        .or_else(|| url.strip_prefix("http://").map(|r| ("http", r)))
        .ok_or_else(|| invalid(format!("URL {url:?} must use http or https")))?;
    let (scheme, after) = rest;
    if after.is_empty() {
        return Err(invalid(format!("URL {url:?} has an empty host")));
    }
    if after.contains('@') {
        return Err(invalid(format!("URL {url:?} must not carry userinfo")));
    }
    let host_port = after.split(['/', '?', '#']).next().unwrap_or_default();
    if host_port.is_empty() {
        return Err(invalid(format!("URL {url:?} has an empty host")));
    }
    if host_port.contains('@') {
        return Err(invalid(format!("URL {url:?} must not carry userinfo")));
    }
    // Basic host sanity: no spaces, no backslashes.
    if host_port.contains(' ') || host_port.contains('\\') {
        return Err(invalid(format!("URL {url:?} carries an invalid host")));
    }
    Ok(format!("{scheme}://{host_port}"))
}

fn validate_origin(origin: &str) -> Result<(), ConnectorError> {
    if !(origin.starts_with("https://") || origin.starts_with("http://")) {
        return Err(invalid(format!("origin {origin:?} must use http or https")));
    }
    if origin.contains('/') && !origin.starts_with("https://") && !origin.starts_with("http://") {
        return Err(invalid(format!("origin {origin:?} must be a canonical origin")));
    }
    // Canonical origin: scheme://host[:port] with no userinfo, path, query, fragment.
    let after = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
        .unwrap_or_default();
    if after.is_empty() || after.contains('/') || after.contains('?') || after.contains('#') || after.contains('@') {
        return Err(invalid(format!("origin {origin:?} must be scheme/host/effective-port without userinfo, path, query, or fragment")));
    }
    Ok(())
}

fn validate_task_envelope(task: &TaskEnvelope) -> Result<(), ConnectorError> {
    if task.record_type != TASK_RECORD_TYPE {
        return Err(invalid(format!("task record_type {:?} must be {TASK_RECORD_TYPE:?}", task.record_type)));
    }
    if task.schema_version != CONNECTOR_SCHEMA_VERSION {
        return Err(unsupported_version(format!(
            "unknown task schema_version {:?}",
            task.schema_version
        )));
    }
    require_identifier("task_id", &task.task_id)?;
    require_enum("task_type", &task.task_type, &TASK_TYPES)?;
    require_identifier("entry logical_id", &task.entry.logical_id)?;
    require_identifier("entry url", &task.entry.url)?;
    let entry_origin = origin_of_url(&task.entry.url)?;
    if task.goal.is_empty() {
        return Err(invalid("task goal must be nonempty"));
    }
    if task.success_criteria.is_empty() {
        return Err(invalid("task requires at least one success criterion"));
    }
    let criterion_ids: Vec<String> =
        task.success_criteria.iter().map(|c| c.criterion_id.clone()).collect();
    for criterion in &task.success_criteria {
        require_identifier("criterion_id", &criterion.criterion_id)?;
        if criterion.description.is_empty() {
            return Err(invalid("success criterion description must be nonempty"));
        }
    }
    require_unique(&criterion_ids, "success criterion IDs")?;
    let input_names: Vec<String> = task.inputs.iter().map(|i| i.name.clone()).collect();
    for input in &task.inputs {
        require_identifier("input name", &input.name)?;
        if input.purpose.is_empty() {
            return Err(invalid("task input purpose must be nonempty"));
        }
        input.content.validate()?;
        // Candidate data/documents are restricted artifacts in production, but
        // the envelope shape itself only requires a well-formed reference.
    }
    require_unique(&input_names, "task input names")?;
    if task.permitted_origins.is_empty() {
        return Err(invalid("task requires at least one permitted origin"));
    }
    let logical_ids: Vec<String> =
        task.permitted_origins.iter().map(|o| o.logical_id.clone()).collect();
    let origins: Vec<String> = task.permitted_origins.iter().map(|o| o.origin.clone()).collect();
    for origin in &task.permitted_origins {
        require_identifier("permitted origin logical_id", &origin.logical_id)?;
        validate_origin(&origin.origin)?;
    }
    require_unique(&logical_ids, "permitted origin logical IDs")?;
    // Origins themselves must be unique as canonical strings.
    require_unique(&origins, "permitted origins")?;
    // Entry origin must be permitted; redirects remain inside the policy.
    if !origins.iter().any(|origin| origin == &entry_origin) {
        return Err(invalid(format!(
            "entry origin {entry_origin:?} is not in the permitted origins"
        )));
    }
    if task.permitted_interfaces.is_empty() {
        return Err(invalid("task requires at least one permitted interface"));
    }
    for interface in &task.permitted_interfaces {
        require_enum(
            "permitted interface",
            interface,
            &["ordinary_browser", "read_only_acquisition"],
        )?;
    }
    require_unique(&task.permitted_interfaces, "permitted interfaces")?;
    // Effect policy and interfaces per task type.
    if task.task_type == "apply" {
        if task.effect_policy != "commissioned_application" {
            return Err(invalid("apply tasks require commissioned_application effect policy"));
        }
        if !task.permitted_interfaces.iter().any(|i| i == "ordinary_browser") {
            return Err(invalid("apply tasks require the ordinary_browser interface"));
        }
        // output_schema may be Missing for apply.
        validate_maybe_pin("output_schema", &task.output_schema)?;
    } else {
        if task.effect_policy != "read_only" {
            return Err(invalid("extract/discover tasks require read_only effect policy"));
        }
        // Acquisition cannot gain mutation authority through a plan, script,
        // extension, or method name: read_only is absolute here.
        match &task.output_schema {
            CatalogMaybeVersionPin::Present(pin) => validate_version_pin(pin, "output_schema")?,
            CatalogMaybeVersionPin::Missing(_) => {
                return Err(invalid(format!(
                    "{} tasks require a pinned output_schema",
                    task.task_type
                )))
            }
        }
    }
    // Budgets are configured limits, never measurements.
    validate_duration_limit(&task.budgets.active_limit, "budgets active_limit")?;
    require_revision("budgets action_limit", task.budgets.action_limit)?;
    require_revision("budgets observation_byte_limit", task.budgets.observation_byte_limit)?;
    require_revision("budgets recovery_limit", task.budgets.recovery_limit)?;
    require_revision("budgets model_token_limit", task.budgets.model_token_limit)?;
    // Context policy: browser and learning remain separate.
    validate_state_policy(&task.context_policy.browser_state, &BROWSER_STATE_MODES, "browser_state")?;
    validate_state_policy(&task.context_policy.learning_state, &LEARNING_STATE_MODES, "learning_state")?;
    if task.context_policy.browser_state.mode == "frozen" {
        return Err(invalid("frozen is meaningful for learning state only"));
    }
    Ok(())
}

fn validate_state_policy(
    policy: &StatePolicy,
    allowed_modes: &[&str],
    what: &str,
) -> Result<(), ConnectorError> {
    require_enum(&format!("{what} mode"), &policy.mode, allowed_modes)?;
    require_enum(&format!("{what} requirement"), &policy.requirement, &STATE_REQUIREMENTS)?;
    validate_maybe_string(&format!("{what} resource_ref"), &policy.resource_ref)?;
    match &policy.baseline {
        MaybeArtifact::Present(reference) => reference.validate()?,
        MaybeArtifact::Missing(missing) => require_missing(&format!("{what} baseline"), missing)?,
    }
    // Reuse requires an authorized resource binding; a bare missing reuse is
    // not a binding.
    if policy.mode == "reuse" {
        match &policy.resource_ref {
            CatalogMaybeString::Text(text) if !text.is_empty() => {}
            _ => {
                return Err(invalid(format!(
                    "{what} reuse requires an authorized resource_ref binding"
                )))
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Assistance / planning / runtime validation (§13.1)
// ---------------------------------------------------------------------------

fn validate_assistance(
    assistance: &AssistanceRecord,
    mapping: &TaskMapping,
    planning_refs: &[EvidenceRef],
    measurements: &[PreparationMeasurement],
) -> Result<(), ConnectorError> {
    require_enum("planning_owner", &assistance.planning_owner, &PLANNING_OWNERS)?;
    require_identifier("assistance_track", &assistance.assistance_track)?;
    validate_maybe_string("planner_identity", &assistance.planner_identity)?;
    match &assistance.plan {
        MaybeArtifact::Present(reference) => reference.validate()?,
        MaybeArtifact::Missing(missing) => require_missing("assistance plan", missing)?,
    }
    if assistance.description.is_empty() {
        return Err(invalid("assistance description must be nonempty"));
    }
    // Assistance matches the advertised native input form.
    if assistance.planning_owner != mapping.planning_owner {
        return Err(invalid(format!(
            "assistance planning_owner {:?} does not match the advertised mapping owner {:?} for task type {:?}",
            assistance.planning_owner, mapping.planning_owner, mapping.task_type
        )));
    }
    // Recorded-plan mappings require assistance.plan and its prior planning
    // evidence. Goal mappings carry no hidden plan.
    if mapping.input_form == "recorded_plan" {
        match &assistance.plan {
            MaybeArtifact::Present(_) => {}
            MaybeArtifact::Missing(_) => {
                return Err(unsupported_mapping(
                    "recorded-plan mapping requires assistance.plan; incomplete translation fails",
                ))
            }
        }
        if planning_refs.is_empty() {
            return Err(invalid(
                "recorded-plan assistance requires prior planning evidence refs; no new hidden planning",
            ));
        }
        if measurements.is_empty() {
            return Err(invalid(
                "recorded-plan assistance requires prior journaled planning costs; no new hidden planning",
            ));
        }
    }
    // A supplied plan without prior evidence/measurements is hidden planning.
    if matches!(assistance.plan, MaybeArtifact::Present(_)) {
        if planning_refs.is_empty() {
            return Err(invalid(
                "supplied assistance plan requires prior planning evidence refs; no new hidden planning",
            ));
        }
        if measurements.is_empty() {
            return Err(invalid(
                "supplied assistance plan requires prior journaled planning costs; no new hidden planning",
            ));
        }
    }
    for reference in planning_refs {
        reference.validate()?;
    }
    for measurement in measurements {
        require_identifier("measurement cost_id", &measurement.cost_id)?;
        measurement.evidence.validate()?;
        if measurement.detail.is_empty() {
            return Err(invalid("measurement detail must be nonempty"));
        }
    }
    let cost_ids: Vec<String> = measurements.iter().map(|m| m.cost_id.clone()).collect();
    require_unique(&cost_ids, "preparation measurement cost IDs")?;
    Ok(())
}

fn validate_runtime_access(entries: &[RuntimeAccess]) -> Result<(), ConnectorError> {
    for (index, entry) in entries.iter().enumerate() {
        let what = format!("runtime_access[{index}]");
        require_enum(&format!("{what} purpose"), &entry.purpose, &RUNTIME_PURPOSES)?;
        require_identifier(&format!("{what} access_ref"), &entry.access_ref)?;
        // Opaque reference, never secret bytes: reject URI shapes, whitespace,
        // and bearer-looking material. Materialization cannot change task
        // semantics; Prepare never materializes.
        if entry.access_ref.contains("://")
            || entry.access_ref.contains(' ')
            || entry.access_ref.contains('\n')
            || entry.access_ref.len() > 256
        {
            return Err(invalid(format!(
                "{what} access_ref must be an opaque binding identifier, never secret bytes or a URI"
            )));
        }
        for reference in &entry.authorization_refs {
            reference.validate()?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Semantic hashing (Contract 02 x-hashing)
// ---------------------------------------------------------------------------

/// Canonical semantic JSON: remove `task_id`, replace entry URL and each
/// permitted origin string with its logical ID. All other values and array
/// order remain.
fn task_semantic_json(task: &TaskEnvelope) -> Value {
    let mut value = task.to_json();
    if let Value::Object(map) = &mut value {
        map.remove("task_id");
        if let Some(Value::Object(entry)) = map.get_mut("entry") {
            let logical = entry.get("logical_id").cloned().unwrap_or(Value::Null);
            entry.insert("url".to_string(), logical);
        }
        if let Some(Value::Array(origins)) = map.get_mut("permitted_origins") {
            for origin in origins {
                if let Value::Object(item) = origin {
                    let logical = item.get("logical_id").cloned().unwrap_or(Value::Null);
                    item.insert("origin".to_string(), logical);
                }
            }
        }
    }
    value
}

/// Computes the Contract 02 semantic hash of the task envelope.
fn compute_task_semantic_hash(task: &TaskEnvelope) -> Result<Digest, ConnectorError> {
    let semantic = task_semantic_json(task);
    let bytes = serde_json::to_vec(&semantic)
        .map_err(|error| invalid(format!("task semantic JSON cannot be serialized: {error}")))?;
    rm_wire::canonical_digest(&bytes)
        .map_err(|error| invalid(format!("task semantic JSON cannot be hashed: {error}")))
}

// ---------------------------------------------------------------------------
// Delivered task / native request serialization (EXT-PREPARE)
// ---------------------------------------------------------------------------

/// Subject-facing task bytes: exact validated task plus declared assistance
/// track and opaque runtime references. No fetched content, no healed
/// selectors, no hidden improvements.
fn build_delivered_json(
    task: &TaskEnvelope,
    assistance: &AssistanceRecord,
    runtime_access: &[RuntimeAccess],
) -> Value {
    json!({
        "record_type": "delivered_task",
        "schema_version": CONNECTOR_SCHEMA_VERSION,
        "task": task.to_json(),
        "assistance_track": assistance.assistance_track,
        "planning_owner": assistance.planning_owner,
        "online_replanning": assistance.online_replanning,
        "runtime_access": runtime_access.iter().map(|entry| json!({
            "purpose": entry.purpose,
            "access_ref": entry.access_ref,
        })).collect::<Vec<Value>>(),
    })
}

/// Intended native request bytes: pinned translation, task digest, budgets,
/// state mapping, and opaque runtime references. Runtime credentials and
/// signatures are excluded (Contract 02); transport supplies them through the
/// authorized binding.
fn build_native_json(
    task: &TaskEnvelope,
    assistance: &AssistanceRecord,
    translation: &VersionPin,
    delivered_hash: &Digest,
    runtime_access: &[RuntimeAccess],
) -> Value {
    json!({
        "record_type": "native_request",
        "schema_version": CONNECTOR_SCHEMA_VERSION,
        "translation": translation.to_json(),
        "task_digest": delivered_hash.as_str(),
        "task_type": task.task_type,
        "entry": task.entry.to_json(),
        "goal": task.goal,
        "effect_policy": task.effect_policy,
        "budgets": task.budgets.to_json(),
        "context_policy": task.context_policy.to_json(),
        "permitted_interfaces": task.permitted_interfaces,
        "planning_owner": assistance.planning_owner,
        "online_replanning": assistance.online_replanning,
        "runtime_access": runtime_access.iter().map(|entry| json!({
            "purpose": entry.purpose,
            "access_ref": entry.access_ref,
        })).collect::<Vec<Value>>(),
    })
}

fn ensure_no_bare_null(bytes: &[u8], what: &str) -> Result<(), ConnectorError> {
    rm_wire::canonical_digest(bytes)
        .map(|_| ())
        .map_err(|error| invalid(format!("{what} carries bare nulls or invalid JSON: {error}")))
}

// ---------------------------------------------------------------------------
// Configuration validation (§13.1 configuration)
// ---------------------------------------------------------------------------

fn validate_configuration(
    principal: &AuthenticatedPrincipal,
    configuration: &ConfigurationPin,
    descriptor: &ConnectorDescriptor,
) -> Result<(), ConnectorError> {
    require_identifier("configuration connector_id", &configuration.connector_id)?;
    require_identifier("configuration connector_version", &configuration.connector_version)?;
    validate_version_pin(&configuration.binding, "configuration binding")?;
    configuration.descriptor.validate()?;
    configuration.descriptor_ref.validate()?;
    // Copied values match the resolved descriptor.
    if configuration.connector_id != descriptor.connector_id {
        return Err(stale(format!(
            "configuration connector_id {:?} does not match the resolved descriptor {:?}",
            configuration.connector_id, descriptor.connector_id
        )));
    }
    if configuration.connector_version != descriptor.connector_version {
        return Err(stale(format!(
            "configuration connector_version {:?} does not match the resolved descriptor {:?}",
            configuration.connector_version, descriptor.connector_version
        )));
    }
    if configuration.binding != descriptor.binding {
        return Err(stale(
            "configuration binding does not match the resolved descriptor binding",
        ));
    }
    if configuration.subject != descriptor.subject {
        return Err(stale(
            "configuration subject does not match the resolved descriptor subject; a new subject version starts unknown",
        ));
    }
    // Resolve descriptor bytes and verify every copied field.
    let bytes = rm_evidence::load_artifact(principal, &configuration.descriptor)?;
    if bytes.len() as u64 != configuration.descriptor.size_bytes {
        return Err(integrity(
            "descriptor size_bytes does not match the retained byte length",
        ));
    }
    let computed = rm_wire::artifact_digest(&bytes);
    if computed != configuration.descriptor.digest {
        return Err(integrity(
            "descriptor digest does not match the exact retained bytes",
        ));
    }
    rm_wire::validate_record("connector_descriptor/v1", &bytes)
        .map_err(|error| invalid(format!("descriptor bytes are not a connector_descriptor record: {error}")))?;
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|error| invalid(format!("descriptor bytes are not JSON: {error}")))?;
    let object = value.as_object().ok_or_else(|| invalid("descriptor bytes must be an object"))?;
    let check_str = |field: &str, expected: &str| -> Result<(), ConnectorError> {
        match object.get(field).and_then(Value::as_str) {
            Some(actual) if actual == expected => Ok(()),
            Some(actual) => Err(stale(format!(
                "descriptor bytes field {field:?} value {actual:?} does not match copied configuration {expected:?}"
            ))),
            None => Err(invalid(format!("descriptor bytes omit {field:?}"))),
        }
    };
    check_str("connector_id", &configuration.connector_id)?;
    check_str("connector_version", &configuration.connector_version)?;
    // Binding and subject pins inside the bytes must also match.
    let binding_value = object.get("binding").ok_or_else(|| invalid("descriptor bytes omit binding"))?;
    let resolved_binding = parse_version_pin(binding_value)?;
    if resolved_binding != configuration.binding {
        return Err(stale("descriptor bytes binding does not match copied configuration binding"));
    }
    let subject_value = object.get("subject").ok_or_else(|| invalid("descriptor bytes omit subject"))?;
    let resolved_subject = parse_subject(subject_value)?;
    if resolved_subject != configuration.subject {
        return Err(stale("descriptor bytes subject does not match copied configuration subject"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Budgets, concerns, and capability mapping
// ---------------------------------------------------------------------------

fn capability_availability(descriptor: &ConnectorDescriptor, capability_id: &str) -> String {
    descriptor
        .capabilities
        .capabilities
        .iter()
        .find(|record| record.capability_id == capability_id)
        .map(|record| record.availability.clone())
        .unwrap_or_else(|| "unknown".to_string())
}

fn validate_budget_mapping(mappings: &[BudgetMapping]) -> Result<(), ConnectorError> {
    if mappings.len() != BUDGET_DIMENSIONS.len() {
        return Err(invalid(format!(
            "budget_mapping requires exactly {} dimensions, found {}",
            BUDGET_DIMENSIONS.len(),
            mappings.len()
        )));
    }
    let mut dimensions = Vec::with_capacity(mappings.len());
    for mapping in mappings {
        require_enum("budget dimension", &mapping.dimension, &BUDGET_DIMENSIONS)?;
        require_enum("budget enforcer", &mapping.enforcer, &BUDGET_ENFORCERS)?;
        for reference in &mapping.evidence_refs {
            reference.validate()?;
        }
        for limitation in &mapping.limitations {
            if limitation.is_empty() {
                return Err(invalid("budget limitation must be nonempty"));
            }
        }
        dimensions.push(mapping.dimension.clone());
    }
    require_unique(&dimensions, "budget dimensions")?;
    // active_observation is connector-enforced.
    match mappings.iter().find(|m| m.dimension == "active_observation") {
        Some(entry) if entry.enforcer == "connector" => {}
        Some(entry) => {
            return Err(invalid(format!(
                "active_observation enforcer {:?} must be \"connector\"",
                entry.enforcer
            )))
        }
        None => return Err(invalid("budget_mapping omits active_observation")),
    }
    Ok(())
}

fn validate_concerns(concerns: &[PreparationConcern]) -> Result<(), ConnectorError> {
    let mut ids = Vec::with_capacity(concerns.len());
    for concern in concerns {
        require_identifier("concern_id", &concern.concern_id)?;
        require_enum("concern category", &concern.category, &CONCERN_CATEGORIES)?;
        require_enum("concern disposition", &concern.disposition, &CONCERN_DISPOSITIONS)?;
        if concern.detail.is_empty() {
            return Err(invalid("concern detail must be nonempty"));
        }
        for reference in &concern.evidence_refs {
            reference.validate()?;
        }
        ids.push(concern.concern_id.clone());
    }
    require_unique(&ids, "concern IDs")?;
    Ok(())
}

fn validate_prepared_shape(prepared: &PreparedTask) -> Result<(), ConnectorError> {
    if prepared.record_type != PREPARATION_RECORD_TYPE {
        return Err(invalid(format!(
            "preparation record_type {:?} must be {PREPARATION_RECORD_TYPE:?}",
            prepared.record_type
        )));
    }
    if prepared.schema_version != CONNECTOR_SCHEMA_VERSION {
        return Err(unsupported_version(format!(
            "unknown preparation schema_version {:?}",
            prepared.schema_version
        )));
    }
    require_identifier("preparation_id", &prepared.preparation_id)?;
    require_digest("task_semantic_hash", &prepared.task_semantic_hash)?;
    require_digest("delivered_task_hash", &prepared.delivered_task_hash)?;
    require_digest("native_request_hash", &prepared.native_request_hash)?;
    prepared.delivered_task.validate()?;
    prepared.native_request.validate()?;
    validate_version_pin(&prepared.translation, "translation")?;
    validate_task_envelope(&prepared.task)?;
    // Assistance shape (planning owner enum, track, description) without
    // re-resolving the descriptor mapping here; mapping agreement was pinned
    // at preparation time.
    require_enum("planning_owner", &prepared.assistance.planning_owner, &PLANNING_OWNERS)?;
    require_identifier("assistance_track", &prepared.assistance.assistance_track)?;
    validate_maybe_string("planner_identity", &prepared.assistance.planner_identity)?;
    match &prepared.assistance.plan {
        MaybeArtifact::Present(reference) => reference.validate()?,
        MaybeArtifact::Missing(missing) => require_missing("assistance plan", missing)?,
    }
    if prepared.assistance.description.is_empty() {
        return Err(invalid("assistance description must be nonempty"));
    }
    for reference in &prepared.planning_evidence_refs {
        reference.validate()?;
    }
    validate_runtime_access(&prepared.runtime_access)?;
    validate_budget_mapping(&prepared.budget_mapping)?;
    validate_concerns(&prepared.concerns)?;
    require_identifier("evidence_prefix journal_id", &prepared.evidence_prefix.journal_id)?;
    require_digest("evidence_prefix head_hash", &prepared.evidence_prefix.head_hash)?;
    // Scope shape: activity vocabulary, bindings, owner domain.
    if prepared.scope.activity != "apply"
        && prepared.scope.activity != "application_attempt"
        && prepared.scope.activity != "discovery"
    {
        return Err(invalid(format!("unknown scope activity {:?}", prepared.scope.activity)));
    }
    require_identifier("scope run_id", &prepared.scope.run_id)?;
    require_identifier("scope journal_id", &prepared.scope.journal_id)?;
    if !rm_wire::is_valid_digest(&prepared.scope.manifest_hash) {
        return Err(invalid("scope manifest_hash must be a sha256 digest"));
    }
    require_identifier("scope admission_ref", &prepared.scope.admission_ref)?;
    require_identifier("scope observation_policy", &prepared.scope.observation_policy)?;
    require_identifier("scope owner_domain", &prepared.scope.owner_domain)?;
    Ok(())
}

/// Builds the five-dimension budget mapping plus all non-blocking concerns.
///
/// Blocking conditions return `ConnectorError` instead of a startable
/// preparation. Missing native cancellation alone never blocks.
fn build_budget_and_concerns(
    task: &TaskEnvelope,
    descriptor: &ConnectorDescriptor,
    assistance: &AssistanceRecord,
    mapping: &TaskMapping,
) -> Result<(Vec<BudgetMapping>, Vec<PreparationConcern>), ConnectorError> {
    // Required native capability for this task type/input form.
    let required_capability = match task.task_type.as_str() {
        "apply" if mapping.input_form == "goal" => Some("native_goal_task"),
        "apply" => Some("native_plan_execution"),
        "extract" | "discover_jobs" => Some("native_dom_access"),
        _ => None,
    };
    if let Some(capability) = required_capability {
        let availability = capability_availability(descriptor, capability);
        if availability == "absent" {
            return Err(unsupported_mapping(format!(
                "task type {:?} requires native capability {capability:?}, which the descriptor reports absent",
                task.task_type
            )));
        }
    }
    // Required state policies: absent isolation support blocks; unknown
    // support becomes a requires_acceptance concern. Fresh and
    // not_applicable need no isolation finding.
    let browser_needs_isolation = matches!(
        task.context_policy.browser_state.mode.as_str(),
        "reuse"
    ) && task.context_policy.browser_state.requirement == "required";
    if browser_needs_isolation {
        let availability = capability_availability(descriptor, "browser_state_isolation");
        if availability == "absent" {
            return Err(unsupported_mapping(
                "required browser-state reuse needs browser_state_isolation, which the descriptor reports absent",
            ));
        }
    }
    let learning_needs_control = matches!(
        task.context_policy.learning_state.mode.as_str(),
        "reuse" | "frozen"
    ) && task.context_policy.learning_state.requirement == "required";
    if learning_needs_control {
        let availability = capability_availability(descriptor, "learning_state_control");
        if availability == "absent" {
            return Err(unsupported_mapping(
                "required learning-state reuse/frozen needs learning_state_control, which the descriptor reports absent",
            ));
        }
    }

    // Five dimensions. active_observation is connector-enforced. Subject
    // enforcement is a scoped declaration, not a passing assessment.
    let budget_mapping = vec![
        BudgetMapping {
            dimension: "active_observation".to_string(),
            enforcer: "connector".to_string(),
            evidence_refs: Vec::new(),
            limitations: Vec::new(),
        },
        BudgetMapping {
            dimension: "action_count".to_string(),
            enforcer: "subject".to_string(),
            evidence_refs: Vec::new(),
            limitations: vec!["subject action counting is a scoped declaration".to_string()],
        },
        BudgetMapping {
            dimension: "observation_bytes".to_string(),
            enforcer: "connector".to_string(),
            evidence_refs: Vec::new(),
            limitations: Vec::new(),
        },
        BudgetMapping {
            dimension: "recovery_count".to_string(),
            enforcer: "subject".to_string(),
            evidence_refs: Vec::new(),
            limitations: vec!["subject recovery counting is a scoped declaration".to_string()],
        },
        BudgetMapping {
            dimension: "model_tokens".to_string(),
            enforcer: if task.budgets.model_token_limit == 0 { "connector".to_string() } else { "subject".to_string() },
            evidence_refs: Vec::new(),
            limitations: if task.budgets.model_token_limit == 0 {
                vec!["zero model tokens forbids a model call where the limit is enforceable".to_string()]
            } else {
                vec!["subject token counting is a scoped declaration".to_string()]
            },
        },
    ];
    validate_budget_mapping(&budget_mapping)?;

    let mut concerns: Vec<PreparationConcern> = Vec::new();
    let mut counter: u64 = 1;
    let mut push_concern = |category: &str, disposition: &str, detail: String| {
        let concern = PreparationConcern {
            concern_id: format!("concern-{counter}"),
            category: category.to_string(),
            disposition: disposition.to_string(),
            detail,
            evidence_refs: Vec::new(),
        };
        counter += 1;
        concerns.push(concern);
    };

    // Native capability unknowns for the required capability.
    if let Some(capability) = required_capability {
        let availability = capability_availability(descriptor, capability);
        if availability == "unknown" {
            push_concern(
                "native_capability_unknown",
                "requires_acceptance",
                format!("native capability {capability:?} is unknown for this subject version"),
            );
        } else if availability == "not_applicable" {
            push_concern(
                "native_capability_unknown",
                "informational",
                format!("native capability {capability:?} is not applicable to this subject"),
            );
        }
    }
    // State-policy unknowns.
    if browser_needs_isolation {
        let availability = capability_availability(descriptor, "browser_state_isolation");
        if availability == "unknown" {
            push_concern(
                "state_policy_unverified",
                "requires_acceptance",
                "required browser-state reuse is unverified for this subject version".to_string(),
            );
        }
    }
    if task.context_policy.browser_state.mode == "subject_default" {
        push_concern(
            "state_policy_unverified",
            "informational",
            "subject-default browser state is not a fresh-state finding".to_string(),
        );
    }
    if learning_needs_control {
        let availability = capability_availability(descriptor, "learning_state_control");
        if availability == "unknown" {
            push_concern(
                "state_policy_unverified",
                "requires_acceptance",
                "required learning-state reuse/frozen is unverified for this subject version".to_string(),
            );
        }
    }
    if task.context_policy.learning_state.mode == "subject_default" {
        push_concern(
            "state_policy_unverified",
            "informational",
            "subject-default learning state is not a clean-state finding".to_string(),
        );
    }
    // Assistance limits.
    if assistance.online_replanning {
        push_concern(
            "assistance_limit",
            "requires_acceptance",
            "online replanning may add bounded recovery within the pinned budgets".to_string(),
        );
    }
    if mapping.input_form == "goal" && matches!(assistance.plan, MaybeArtifact::Present(_)) {
        push_concern(
            "assistance_limit",
            "informational",
            "goal task carries a recorded plan as declared assistance only".to_string(),
        );
    }
    // Observation limits.
    if task.budgets.observation_byte_limit < 1024 {
        push_concern(
            "observation_limit",
            "informational",
            "small observation byte bound may truncate retained projections".to_string(),
        );
    }
    // Subject-enforced dimensions disclose their declaration status as
    // informational concerns (not requires_acceptance: enforcement is scoped,
    // not absent).
    for entry in &budget_mapping {
        if entry.enforcer == "subject" && !entry.limitations.is_empty() {
            push_concern(
                "budget_not_enforced",
                "informational",
                format!("budget dimension {:?} relies on subject enforcement", entry.dimension),
            );
        }
    }

    validate_concerns(&concerns)?;
    Ok((budget_mapping, concerns))
}

// ---------------------------------------------------------------------------
// Entry points (EXPOSES)
// ---------------------------------------------------------------------------

fn is_application_activity(activity: &str) -> bool {
    activity == "apply" || activity == "application_attempt"
}

/// Validates and serializes a Prepare command without executing.
///
/// Flow: envelope + wire validation → `describe` → configuration pin check →
/// optional native binding check → `authorize_work` → manifest/commission
/// scope check (`verify_attempt_scope` for application work) → full task /
/// assistance / planning / runtime validation → semantic hash → translation
/// selection → budget/concern mapping → delivered + native serialization →
/// durable install → owner-local registration commit.
pub fn prepare(
    principal: &AuthenticatedPrincipal,
    command: &ConnectorRequest,
) -> Result<PrepareResult, ConnectorError> {
    // 1. Envelope.
    if command.record_type != CONNECTOR_REQUEST_TYPE {
        return Err(invalid(format!(
            "record_type {:?} must be {CONNECTOR_REQUEST_TYPE:?}",
            command.record_type
        )));
    }
    if command.schema_version != CONNECTOR_SCHEMA_VERSION {
        return Err(unsupported_version(format!(
            "unknown schema_version {:?}",
            command.schema_version
        )));
    }
    require_identifier("request_id", &command.request_id)?;
    require_identifier("connector_id", &command.connector_id)?;
    if command.operation != PREPARE_VERB {
        return Err(invalid(format!("operation {:?} must be {PREPARE_VERB:?}", command.operation)));
    }
    validate_duration_limit(&command.call_limit, "call_limit")?;
    if command.connector_id != command.payload.configuration.connector_id {
        return Err(invalid(
            "connector request connector_id must identify the pinned configuration connector",
        ));
    }

    // 2. Structural wire validation of the request envelope.
    let wire_bytes = serde_json::to_vec(&command.to_json())
        .map_err(|error| invalid(format!("connector request cannot be serialized: {error}")))?;
    rm_wire::validate_record("connector_request/v1", &wire_bytes)
        .map_err(|error| invalid(format!("connector request wire record invalid: {error}")))?;

    // 3. Resolve the exact descriptor (local read only; no probe).
    let descriptor = rm_catalog::describe(principal, &DescribeRequest)?;
    if command.call_limit.value > descriptor.limits.max_call_wait.value {
        return Err(invalid("call_limit exceeds the descriptor max_call_wait bound"));
    }
    // Request bytes must fit the configured bound.
    if wire_bytes.len() as u64 > descriptor.limits.max_request_bytes {
        return Err(invalid("connector request exceeds max_request_bytes"));
    }

    // 4. Configuration pin.
    validate_configuration(principal, &command.payload.configuration, &descriptor)?;

    // 5. Optional native binding validation.
    if let Some(binding) = &command.payload.native_binding {
        rm_catalog::validate_native_binding(principal, binding)?;
    }

    // 6. Authority: every call is bound to an admitted grant.
    let scope = &command.payload.scope;
    let task = &command.payload.task;
    if scope.activity != "apply" && scope.activity != "application_attempt" && scope.activity != "discovery" {
        return Err(invalid(format!("unknown scope activity {:?}", scope.activity)));
    }
    let operation = Operation {
        verb: PREPARE_VERB.to_string(),
        connector_id: command.payload.configuration.connector_id.clone(),
        subject_id: command.payload.configuration.subject.subject_id.clone(),
        task_scope: format!("{}:{}", scope.activity, task.task_id),
        account_binding: command.payload.runtime_access.first().map(|entry| entry.access_ref.clone()),
        artifact_refs: Vec::new(),
        control_target: None,
    };
    rm_authority::authorize_work(principal, scope, &operation)?;

    // 7. Manifest / commission scope.
    let manifest = &command.payload.manifest;
    if scope.run_id != manifest.run_id {
        return Err(not_admitted("scope run differs from the admitted manifest run"));
    }
    if scope.manifest_hash != manifest.manifest_hash {
        return Err(not_admitted("scope manifest binding differs from the admitted manifest"));
    }
    if scope.admission_ref != manifest.admission_ref {
        return Err(not_admitted("scope admission binding differs from the admitted manifest"));
    }
    let expected_journal =
        rm_evidence::journal_id_for(manifest).map_err(|error| invalid(format!("manifest journal identity unavailable: {error}")))?;
    if scope.journal_id != expected_journal {
        return Err(not_admitted("scope journal differs from the admitted manifest journal"));
    }
    let application = is_application_activity(&scope.activity);
    if application {
        let commission = command.payload.commission.as_ref().ok_or_else(|| {
            not_admitted("application work requires its immutable attempt commission")
        })?;
        if scope.attempt_id.as_deref() != Some(commission.attempt_id.as_str()) {
            return Err(not_admitted("scope attempt differs from the commissioned attempt"));
        }
        if scope.commission_id.as_deref() != Some(commission.commission_id.as_str()) {
            return Err(not_admitted("scope commission differs from the commissioned attempt"));
        }
        if scope.attempt_kind != Some(commission.kind) {
            return Err(not_admitted("scope attempt kind differs from the commissioned kind"));
        }
        rm_authority::verify_attempt_scope(manifest, commission)?;
        if task.task_type != "apply" {
            return Err(not_admitted("application scope requires an apply task"));
        }
    } else {
        if command.payload.commission.is_some() {
            return Err(invalid("discovery work carries no application commission"));
        }
        if scope.attempt_id.is_some()
            || scope.commission_id.is_some()
            || scope.commission_ref.is_some()
            || scope.attempt_kind.is_some()
        {
            return Err(invalid("discovery scope uses inapplicable attempt/commission fields"));
        }
        if task.task_type == "apply" {
            return Err(not_admitted("discovery scope cannot carry an apply task"));
        }
    }

    // 8. Full task / assistance / planning / runtime validation. No target
    // visit, no authentication test, no context reset, no planner.
    validate_task_envelope(task)?;
    let mapping = descriptor
        .task_mappings
        .iter()
        .find(|entry| entry.task_type == task.task_type)
        .ok_or_else(|| {
            unsupported_mapping(format!("no task mapping is advertised for task type {:?}", task.task_type))
        })?;
    validate_assistance(
        &command.payload.assistance,
        mapping,
        &command.payload.planning_evidence_refs,
        &command.payload.preparation_measurements,
    )?;
    validate_runtime_access(&command.payload.runtime_access)?;

    // 9. Semantic hash. Equal hashes never authorize changed destinations;
    // actual values are pinned separately below.
    let semantic_hash = compute_task_semantic_hash(task)?;
    if application {
        let commission = command.payload.commission.as_ref().expect("commission checked");
        if commission.task_semantic_hash != semantic_hash.as_str() {
            return Err(not_admitted(
                "task does not match the commissioned semantic hash; changing subject version, target, kind, or task creates a new attempt",
            ));
        }
    }

    // 10. Translation + budgets + concerns. Blocking unsupported mappings or
    // required unenforceable policies error here.
    let translation = mapping.mapping.clone();
    validate_version_pin(&translation, "translation")?;
    let (budget_mapping, concerns) =
        build_budget_and_concerns(task, &descriptor, &command.payload.assistance, mapping)?;

    // 11. Independent serializations. Translation preserves intent, order,
    // values, targets, and retry policy; it adds nothing hidden.
    let delivered_json =
        build_delivered_json(task, &command.payload.assistance, &command.payload.runtime_access);
    let delivered_bytes = serde_json::to_vec(&delivered_json)
        .map_err(|error| invalid(format!("delivered task cannot be serialized: {error}")))?;
    ensure_no_bare_null(&delivered_bytes, "delivered task")?;
    let native_probe = build_native_json(
        task,
        &command.payload.assistance,
        &translation,
        &rm_wire::artifact_digest(&delivered_bytes),
        &command.payload.runtime_access,
    );
    let native_bytes = serde_json::to_vec(&native_probe)
        .map_err(|error| invalid(format!("native request cannot be serialized: {error}")))?;
    ensure_no_bare_null(&native_bytes, "native request")?;
    // Native bytes exclude runtime credentials/signatures: the serialization
    // carries only opaque access_ref identifiers, never secret material.
    let native_text = String::from_utf8(native_bytes.clone())
        .map_err(|_| invalid("native request is not UTF-8 JSON"))?;
    if native_text.contains("secret") || native_text.contains("password") || native_text.contains("bearer") {
        return Err(invalid("native request must exclude runtime credentials/signatures"));
    }

    let delivered_digest = rm_wire::artifact_digest(&delivered_bytes);
    let native_digest = rm_wire::artifact_digest(&native_bytes);
    let delivered_ref = ArtifactReference {
        digest: delivered_digest.clone(),
        size_bytes: delivered_bytes.len() as u64,
        media_type: "application/json".to_string(),
        owner_domain: PREPARATION_OWNER_DOMAIN.to_string(),
        access: AccessClass::Public,
    };
    let native_ref = ArtifactReference {
        digest: native_digest.clone(),
        size_bytes: native_bytes.len() as u64,
        media_type: "application/json".to_string(),
        owner_domain: PREPARATION_OWNER_DOMAIN.to_string(),
        access: AccessClass::Public,
    };
    rm_evidence::install_artifact(principal, &delivered_ref, &delivered_bytes)?;
    rm_evidence::install_artifact(principal, &native_ref, &native_bytes)?;

    // 12. Supporting prefix (prior input/decision evidence, not the future
    // registration). The preparation record must not cite its own future
    // registration.
    let journal_id = rm_evidence::journal_id_for(manifest)
        .map_err(|error| invalid(format!("manifest journal identity unavailable: {error}")))?;
    let supporting_prefix = rm_evidence::journal_head(principal, &journal_id)?;

    // 13. Immutable preparation identity derived from the pinned inputs.
    let id_seed = format!("{}:{}:{}", semantic_hash.as_str(), delivered_digest.as_str(), native_digest.as_str());
    let id_digest = rm_wire::artifact_digest(id_seed.as_bytes());
    let hex = id_digest.as_str().strip_prefix("sha256:").unwrap_or(id_digest.as_str());
    let preparation_id = format!("prep-{}", &hex[..16.min(hex.len())]);

    let prepared = PreparedTask {
        record_type: PREPARATION_RECORD_TYPE.to_string(),
        schema_version: CONNECTOR_SCHEMA_VERSION.to_string(),
        preparation_id: preparation_id.clone(),
        scope: scope.clone(),
        configuration: command.payload.configuration.clone(),
        task: task.clone(),
        task_semantic_hash: semantic_hash,
        assistance: command.payload.assistance.clone(),
        planning_evidence_refs: command.payload.planning_evidence_refs.clone(),
        runtime_access: command.payload.runtime_access.clone(),
        delivered_task: delivered_ref.clone(),
        delivered_task_hash: delivered_digest.clone(),
        native_request: native_ref.clone(),
        native_request_hash: native_digest.clone(),
        translation,
        budget_mapping,
        concerns,
        evidence_prefix: supporting_prefix.clone(),
    };
    validate_prepared_shape(&prepared)?;
    let prepared_json = prepared.to_json();
    let prepared_bytes = serde_json::to_vec(&prepared_json)
        .map_err(|error| invalid(format!("preparation cannot be serialized: {error}")))?;
    ensure_no_bare_null(&prepared_bytes, "preparation")?;
    let prepared_digest = rm_wire::artifact_digest(&prepared_bytes);
    let prepared_ref = ArtifactReference {
        digest: prepared_digest,
        size_bytes: prepared_bytes.len() as u64,
        media_type: "application/json".to_string(),
        owner_domain: PREPARATION_OWNER_DOMAIN.to_string(),
        access: AccessClass::Public,
    };
    rm_evidence::install_artifact(principal, &prepared_ref, &prepared_bytes)?;

    // 14. Owner-local registration commit (artifact_available citing the
    // installed bytes). No cross-domain transaction.
    let registration = rm_evidence::event_registration(PREPARATION_EVENT_KIND)
        .ok_or_else(|| invalid("artifact_available is not a registered event kind"))?;
    let producer_sequence =
        PositiveInteger::new(PRODUCER_SEQ.fetch_add(1, Ordering::SeqCst))?;
    let submission = rm_evidence::EventSubmission {
        producer_sequence: Some(producer_sequence),
        event_kind: PREPARATION_EVENT_KIND.to_string(),
        event_schema_version: registration.event_schema_version.to_string(),
        occurred_at: rm_evidence::MaybeTimePoint::Missing(Missing::new("not_observed")),
        payload: rm_evidence::EvidencePayload {
            data: json!({
                "preparation_id": preparation_id,
                "preparation": prepared_ref.to_json(),
                "delivered_task": delivered_ref.to_json(),
                "native_request": native_ref.to_json(),
            }),
            measurements: Vec::new(),
            evidence_refs: Vec::new(),
            artifact_refs: vec![prepared_ref.clone(), delivered_ref.clone(), native_ref.clone()],
        },
    };
    let envelopes = rm_evidence::commit_owner_effect(
        principal,
        manifest,
        &prepared_ref,
        &[submission],
        &prepared_ref,
    )?;
    let envelope = envelopes
        .last()
        .cloned()
        .ok_or_else(|| invalid("owner commit returned no journal envelopes"))?;
    let registration_ref = EvidenceRef {
        journal_id: envelope.journal_id.clone(),
        sequence: envelope.journal_sequence,
        event_id: envelope.event_id.clone(),
        event_hash: envelope.event_hash.clone(),
        pointer: String::new(),
    };
    // The registration resolves against the retained head.
    let head = rm_evidence::journal_head(principal, &envelope.journal_id)?;
    rm_evidence::resolve_evidence(principal, &registration_ref, &head)?;

    Ok(PrepareResult {
        kind: "prepared".to_string(),
        preparation: PreparationReference {
            preparation_id,
            artifact: prepared_ref,
            registration_ref,
        },
        record: prepared,
    })
}

/// Verifies a retained preparation reference against its immutable bytes.
///
/// Rejects stale subjects/configurations/mappings, changed preparation
/// bytes, changed actual destinations (even under an equal semantic hash),
/// and mismatched registrations.
pub fn verify_preparation(
    principal: &AuthenticatedPrincipal,
    reference: &PreparationReference,
) -> Result<PreparedTask, ConnectorError> {
    require_identifier("preparation_id", &reference.preparation_id)?;
    reference.artifact.validate()?;
    reference.registration_ref.validate()?;

    // Current descriptor for staleness checks (local read only).
    let descriptor = rm_catalog::describe(principal, &DescribeRequest)?;

    // Retained preparation bytes.
    let bytes = rm_evidence::load_artifact(principal, &reference.artifact)?;
    if bytes.len() as u64 != reference.artifact.size_bytes {
        return Err(integrity(
            "preparation size_bytes does not match the retained byte length",
        ));
    }
    let computed = rm_wire::artifact_digest(&bytes);
    if computed != reference.artifact.digest {
        return Err(integrity(
            "preparation digest does not match the exact retained bytes; changed input is rejected, never silently reprepared",
        ));
    }
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|error| invalid(format!("preparation bytes are not JSON: {error}")))?;
    ensure_no_bare_null(&bytes, "preparation")?;
    let prepared = PreparedTask::from_json(&value)?;
    if prepared.preparation_id != reference.preparation_id {
        return Err(stale(
            "preparation_id does not match the retained preparation bytes",
        ));
    }
    if prepared.delivered_task_hash != prepared.delivered_task.digest
        || prepared.native_request_hash != prepared.native_request.digest
    {
        return Err(integrity(
            "preparation hash fields do not match their artifact identities",
        ));
    }

    // Stale subject/configuration/mapping: the pinned configuration must still
    // match the resolved descriptor.
    if prepared.configuration.connector_id != descriptor.connector_id
        || prepared.configuration.connector_version != descriptor.connector_version
        || prepared.configuration.binding != descriptor.binding
        || prepared.configuration.subject != descriptor.subject
    {
        return Err(stale(
            "preparation configuration is stale against the resolved descriptor; reject rather than silently reprepare",
        ));
    }
    // Translation must still be the advertised mapping for the task type.
    match descriptor.task_mappings.iter().find(|entry| entry.task_type == prepared.task.task_type) {
        Some(mapping) if mapping.mapping == prepared.translation => {}
        Some(_) => {
            return Err(stale(
                "preparation translation is stale against the advertised task mapping",
            ))
        }
        None => {
            return Err(stale(
                "preparation task type no longer has an advertised task mapping",
            ))
        }
    }

    // Semantic hash recomputation. Equal hashes do not authorize changed
    // actual destinations; those are pinned separately below.
    let recomputed = compute_task_semantic_hash(&prepared.task)?;
    if recomputed != prepared.task_semantic_hash {
        return Err(integrity(
            "task semantic hash mismatch: the full task changed after preparation",
        ));
    }

    // Delivered task bytes: exact subject-facing bytes and digest, with actual
    // destinations preserved.
    let delivered_bytes = rm_evidence::load_artifact(principal, &prepared.delivered_task)?;
    if delivered_bytes.len() as u64 != prepared.delivered_task.size_bytes {
        return Err(integrity("delivered task size mismatch"));
    }
    if rm_wire::artifact_digest(&delivered_bytes) != prepared.delivered_task.digest {
        return Err(integrity("delivered task digest mismatch: changed input is rejected"));
    }
    if rm_wire::artifact_digest(&delivered_bytes) != prepared.delivered_task_hash {
        return Err(integrity("delivered task hash field mismatch"));
    }
    let delivered_value: Value = serde_json::from_slice(&delivered_bytes)
        .map_err(|error| invalid(format!("delivered task bytes are not JSON: {error}")))?;
    let delivered_task_json = delivered_value
        .get("task")
        .ok_or_else(|| invalid("delivered task bytes omit the subject-facing task"))?;
    let delivered_task = TaskEnvelope::from_json(delivered_task_json)?;
    if delivered_task.entry != prepared.task.entry {
        return Err(stale(
            "delivered task entry differs from the prepared task entry; equal semantic hashes do not authorize changed actual destinations",
        ));
    }
    if delivered_task.permitted_origins != prepared.task.permitted_origins {
        return Err(stale(
            "delivered task permitted origins differ from the prepared destinations; equal semantic hashes do not authorize changed actual destinations",
        ));
    }
    if delivered_task.task_type != prepared.task.task_type
        || delivered_task.goal != prepared.task.goal
        || delivered_task.effect_policy != prepared.task.effect_policy
        || delivered_task.permitted_interfaces != prepared.task.permitted_interfaces
        || delivered_task.to_json() != prepared.task.to_json()
    {
        return Err(stale("delivered task differs from the prepared task"));
    }

    // Native request bytes: exact intended bytes and digest, preserving the
    // same actual destinations without credentials.
    let native_bytes = rm_evidence::load_artifact(principal, &prepared.native_request)?;
    if native_bytes.len() as u64 != prepared.native_request.size_bytes {
        return Err(integrity("native request size mismatch"));
    }
    if rm_wire::artifact_digest(&native_bytes) != prepared.native_request.digest {
        return Err(integrity("native request digest mismatch: changed input is rejected"));
    }
    if rm_wire::artifact_digest(&native_bytes) != prepared.native_request_hash {
        return Err(integrity("native request hash field mismatch"));
    }
    let native_value: Value = serde_json::from_slice(&native_bytes)
        .map_err(|error| invalid(format!("native request bytes are not JSON: {error}")))?;
    let native_object = native_value.as_object().ok_or_else(|| invalid("native request must be an object"))?;
    let native_entry = EntryPoint::from_json(
        native_object.get("entry").ok_or_else(|| invalid("native request omits entry"))?,
    )?;
    if native_entry != prepared.task.entry {
        return Err(stale(
            "native request entry differs from the prepared destinations; equal semantic hashes do not authorize changed actual destinations",
        ));
    }
    match native_object.get("task_digest").and_then(Value::as_str) {
        Some(digest) if digest == prepared.delivered_task_hash.as_str() => {}
        _ => return Err(integrity("native request does not pin the delivered task digest")),
    }
    let native_translation = parse_version_pin(
        native_object.get("translation").ok_or_else(|| invalid("native request omits translation"))?,
    )?;
    if native_translation != prepared.translation {
        return Err(stale("native request translation differs from the prepared translation"));
    }

    // Supporting prefix: the stored input/decision prefix must be a retained
    // prefix (head hash equals the event hash at its cutoff).
    let stored_prefix = &prepared.evidence_prefix;
    if stored_prefix.journal_id != prepared.scope.journal_id {
        return Err(stale("preparation evidence prefix names a different journal than the scope"));
    }
    let cutoff = rm_evidence::read_event(principal, &stored_prefix.journal_id, stored_prefix.last_sequence)?;
    if cutoff.event_hash != stored_prefix.head_hash {
        return Err(integrity(
            "preparation evidence prefix head does not equal the retained event hash at its cutoff",
        ));
    }

    // Registration: resolves against the retained head and cites the exact
    // preparation artifact.
    if reference.registration_ref.journal_id != prepared.scope.journal_id {
        return Err(stale("preparation registration names a different journal than the scope"));
    }
    let head = rm_evidence::journal_head(principal, &prepared.scope.journal_id)?;
    let envelope = rm_evidence::resolve_evidence(principal, &reference.registration_ref, &head)?;
    if envelope.event_kind != PREPARATION_EVENT_KIND {
        return Err(stale("preparation registration is not a preparation registration event"));
    }
    if !envelope.payload.artifact_refs.iter().any(|reference| reference.digest == prepared.delivered_task.digest)
        && !envelope.payload.artifact_refs.iter().any(|candidate| candidate.digest == reference.artifact.digest)
    {
        return Err(integrity("preparation registration does not cite the retained preparation artifact"));
    }
    if !envelope.payload.artifact_refs.iter().any(|candidate| candidate.digest == reference.artifact.digest) {
        return Err(integrity("preparation registration does not cite the retained preparation artifact"));
    }

    Ok(prepared)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semantic_hash_ignores_task_id_and_urls() {
        let budgets = TaskBudgets {
            active_limit: DurationLimit { kind: "exact".to_string(), unit: "ms".to_string(), value: 1000.0 },
            action_limit: 10,
            observation_byte_limit: 1024,
            recovery_limit: 2,
            model_token_limit: 0,
        };
        let context = ContextPolicy {
            browser_state: StatePolicy {
                mode: "fresh".to_string(),
                requirement: "required".to_string(),
                resource_ref: CatalogMaybeString::Missing(Missing::new("not_applicable")),
                baseline: MaybeArtifact::Missing(Missing::new("not_applicable")),
            },
            learning_state: StatePolicy {
                mode: "not_applicable".to_string(),
                requirement: "best_effort".to_string(),
                resource_ref: CatalogMaybeString::Missing(Missing::new("not_applicable")),
                baseline: MaybeArtifact::Missing(Missing::new("not_applicable")),
            },
        };
        let task_a = TaskEnvelope {
            record_type: TASK_RECORD_TYPE.to_string(),
            schema_version: CONNECTOR_SCHEMA_VERSION.to_string(),
            task_id: "task-a".to_string(),
            task_type: "extract".to_string(),
            entry: EntryPoint { logical_id: "entry-1".to_string(), url: "https://example.com/a".to_string() },
            goal: "extract".to_string(),
            success_criteria: vec![SuccessCriterion { criterion_id: "c1".to_string(), description: "done".to_string() }],
            inputs: Vec::new(),
            permitted_origins: vec![PermittedOrigin { logical_id: "o1".to_string(), origin: "https://example.com".to_string() }],
            permitted_interfaces: vec!["read_only_acquisition".to_string()],
            effect_policy: "read_only".to_string(),
            budgets: budgets.clone(),
            context_policy: context,
            output_schema: CatalogMaybeVersionPin::Present(VersionPin {
                id: "schema".to_string(),
                version: "1".to_string(),
                artifact_digest: rm_wire::artifact_digest(b"schema"),
            }),
        };
        let mut task_b = task_a.clone();
        task_b.task_id = "task-b".to_string();
        task_b.entry.url = "https://evil.example/other".to_string();
        task_b.permitted_origins[0].origin = "https://evil.example".to_string();
        let hash_a = compute_task_semantic_hash(&task_a).expect("hash a");
        let hash_b = compute_task_semantic_hash(&task_b).expect("hash b");
        assert_eq!(hash_a, hash_b, "semantic hash replaces URLs with logical IDs");
    }
}

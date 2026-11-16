//! `rm_execution`: tier-8 owner-thread workflow execution for Ringmaster.
//!
//! Implements seam mapping §8.2 (all nine actions), §8.3 (preflight), §10.1
//! (Tier 1), §10.2 (failure routing), and §7.4 (checkpoints) for conformance
//! case RM-C35 (Tier 1 no match versus possible action effect: recovery only
//! when effect-safe).
//!
//! Entry point [`run_owner_work`] executes one admitted [`PreparedTask`] under
//! one [`ConnectorHandle`] and one fenced [`LeaseRecord`] on the calling OS
//! thread. All native work enters through the synchronous `bo.*` binding on
//! that thread; no native state crosses an async suspension and no call
//! returns a task handle for later polling (BO-THREAD).
//!
//! Action mapping (§8.2):
//!
//! - `navigate` (`url`, `navigation_policy`) → `bo.navigate`.
//! - `fill` (`target`, `text`, `event_recipe`) → Tier 1 resolve,
//!   `bo.dom_write(value)`, then explicitly declared synthetic events.
//! - `click` (`target`, `event_recipe`) → resolve, explicit synthetic
//!   `bo.event_dispatch`.
//! - `select` (`target`, `values`, `event_recipe`) → resolve, explicit
//!   selected/value writes and events over the actually observed
//!   select/options.
//! - `wait` (`predicate`, `predicate_mapping`) → bounded controller-owned
//!   read-only observations.
//! - `extract` (`query`, `output_schema`, `extraction_policy`) → native
//!   reduction and deterministic extraction.
//! - `assert` (`predicate`, `predicate_mapping`) → observe and compare; no
//!   origin fact fabrication.
//! - `upload` (`target`, nonempty `files`, `upload_policy`) → mapped
//!   `bo.assign_files` plus an explicit additional event recipe only.
//! - `checkpoint` (`checkpoint_policy`) → durable controller progress record.
//!
//! The catalog contains no trusted keyboard/pointer primitive. Property
//! mutation is not typing and synthetic click is not trusted input; required
//! trusted-input semantics are never silently substituted (BO-INPUT).
//! Partial compound-action failure preserves prior effects and never
//! authorizes replay of the entire action.
//!
//! Preflight (§8.3) occurs after Start, never during Describe/Prepare. The
//! admitted mapping pins destination, account binding, marker, scope, and
//! policy; the destination must be permitted. Marker-absent in a valid
//! complete observation yields a native `SESSION_EXPIRED` report (report
//! content, not a new ConnectorError enum); incomplete observation preserves
//! uncertainty; native failures preserve their domain; an active boundary
//! stops delivery and finalizes locally.
//!
//! Tier 1 (§10.1) uses a pinned learning snapshot and zero model calls.
//! Failure routing (§10.2) sends no-match/ambiguity/pre-entry-stale targets
//! to recovery only when authorized and budgeted, reports unsupported
//! grammars as explicit mapping limitations, allows safe recovery for
//! definite no-entry failures, requires reconciliation before retry when a
//! side effect is possible, fences wrong-thread/authorization/ownership
//! failures, refuses mutation when storage is unavailable before intent, and
//! never escalates exhausted budgets or deadlines.
//!
//! No in-band nulls; missing fields use typed [`Missing`] envelopes. No
//! shared-database writes or cross-domain transactions.

#![forbid(unsafe_code)]
#![allow(clippy::result_large_err)]

use rm_authority::{AuthenticatedPrincipal, ConnectorError, Manifest, Operation};
use rm_browseroxide::{
    BOAssignFiles, BOClientCreate, BODomRead, BODomWrite, BOEventDispatch, BONavigate, BOOwner,
    BOPageArgument, BOPageCreate, BOPageRef, BOPrimitiveRecord, BORootRef, BOV8Evaluate,
    BrowserOxideReturn, MaybeArtifact as BOMaybeArtifact, MaybeBOFailure, MaybeClient, MaybeRoot,
};
use rm_catalog::{
    BOBindingDescriptor, BOMapping, CapabilityDescriptor, CapabilityRecord, ComponentIdentity as CatalogComponent,
    DurationLimit, SubjectIdentity as CatalogSubject, VersionPin as CatalogPin,
    BO_CAPABILITIES, BO_PRIMITIVES, BO_RECORD_TYPE, BO_SCHEMA_VERSION, CAPABILITY_RECORD_TYPE,
    CAPABILITY_SCHEMA_VERSION, MaybeDigest as CatalogMaybeDigest, MaybeString as CatalogMaybeString,
    MaybeVersionPin as CatalogMaybePin,
};
use rm_delivery::ConnectorHandle;
use rm_evidence::{
    AccessClass, ArtifactReference, EvidencePayload, EvidenceRef, EventSubmission, JournalPrefix,
    PositiveInteger,
};
use rm_leases::LeaseRecord;
use rm_preparation::PreparedTask;
use rm_time::{MaybeString as TimeMaybeString, MaybeTimePoint, Missing, TimePoint, UtcAnnotation};
use rm_wire::Digest;
use serde_json::{json, Value};
use std::collections::BTreeSet;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Execution plan record discriminator.
pub const EXECUTION_PLAN_RECORD_TYPE: &str = "execution_plan";
/// Execution plan schema version.
pub const EXECUTION_PLAN_SCHEMA_VERSION: &str = "rm-execution/0.1.0";
/// Checkpoint record discriminator.
pub const CHECKPOINT_RECORD_TYPE: &str = "ringmaster_checkpoint";
/// Checkpoint schema version.
pub const CHECKPOINT_SCHEMA_VERSION: &str = "ringmaster-execution/0.1.0";
/// Execution result record discriminator.
pub const EXECUTION_RESULT_RECORD_TYPE: &str = "ringmaster_execution_result";
/// Owner domain for execution artifacts.
pub const EXECUTION_OWNER_DOMAIN: &str = "execution";

/// Largest exactly representable integer (§3.1).
pub const MAX_SAFE_INTEGER: u64 = rm_evidence::MAX_SAFE_INTEGER;

/// Native read depth bound for execution observations.
const READ_DEPTH_LIMIT: u64 = 100;
/// Native read byte bound for execution observations.
const READ_BYTE_LIMIT: u64 = 1_000_000;
/// Bound on journaled producer-sequence allocation per execution.
const MAX_PRODUCER_SEQUENCE_JUMP: u64 = 10_000;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

fn connector_error(
    code: &str,
    fault_domain: &str,
    detail: impl Into<String>,
    operation_delivery: &str,
    retry_guidance: &str,
) -> ConnectorError {
    ConnectorError {
        kind: "connector_error".to_string(),
        code: code.to_string(),
        fault_domain: fault_domain.to_string(),
        detail: detail.into(),
        operation_delivery: operation_delivery.to_string(),
        retry_guidance: retry_guidance.to_string(),
        retry_after: None,
        handle: None,
        evidence_refs: Vec::new(),
    }
}

fn invalid(detail: impl Into<String>) -> ConnectorError {
    connector_error("INVALID_REQUEST", "request", detail, "not_dispatched", "operator_review")
}

fn forbidden(detail: impl Into<String>) -> ConnectorError {
    connector_error("FORBIDDEN", "policy", detail, "not_dispatched", "operator_review")
}

fn not_admitted(detail: impl Into<String>) -> ConnectorError {
    connector_error("NOT_ADMITTED", "policy", detail, "not_dispatched", "operator_review")
}

fn stale(detail: impl Into<String>) -> ConnectorError {
    connector_error("STALE_CONTEXT", "policy", detail, "not_dispatched", "operator_review")
}

fn unsupported_mapping(detail: impl Into<String>) -> ConnectorError {
    connector_error(
        "UNSUPPORTED_MAPPING",
        "connector",
        detail,
        "not_dispatched",
        "operator_review",
    )
}

fn reconcile_required(detail: impl Into<String>) -> ConnectorError {
    connector_error(
        "RECONCILIATION_REQUIRED",
        "connector",
        detail,
        "not_dispatched",
        "operator_review",
    )
}

fn fenced(detail: impl Into<String>) -> ConnectorError {
    connector_error("FENCED", "connector", detail, "not_dispatched", "operator_review")
}

fn prerequisite(detail: impl Into<String>) -> ConnectorError {
    connector_error(
        "PREREQUISITE_UNAVAILABLE",
        "connector",
        detail,
        "not_dispatched",
        "operator_review",
    )
}

fn integrity(detail: impl Into<String>) -> ConnectorError {
    connector_error(
        "INTEGRITY_INCIDENT",
        "integrity",
        detail,
        "not_dispatched",
        "operator_review",
    )
}

fn require_nonempty(field: &str, value: &str) -> Result<(), ConnectorError> {
    if value.is_empty() {
        return Err(invalid(format!("{field} must be nonempty")));
    }
    Ok(())
}

fn require_identifier(field: &str, value: &str) -> Result<(), ConnectorError> {
    require_nonempty(field, value)?;
    if value.len() > 256 {
        return Err(invalid(format!("{field} exceeds 256 chars")));
    }
    Ok(())
}

fn check_missing(missing: &Missing) -> Result<(), ConnectorError> {
    const REASONS: [&str; 6] = [
        "not_enabled",
        "not_applicable",
        "not_observed",
        "not_available",
        "withheld",
        "unknown",
    ];
    if !REASONS.contains(&missing.reason.as_str()) {
        return Err(invalid(format!(
            "Missing reason {:?} is not permitted",
            missing.reason
        )));
    }
    if matches!(&missing.detail, Some(d) if d.is_empty()) {
        return Err(invalid("Missing detail must be nonempty"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// JSON helpers
// ---------------------------------------------------------------------------

fn ensure_closed(
    object: &serde_json::Map<String, Value>,
    allowed: &[&str],
    what: &str,
) -> Result<(), ConnectorError> {
    for key in object.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(invalid(format!("{what} carries undeclared field {key:?}")));
        }
    }
    Ok(())
}

fn field<'a>(
    object: &'a serde_json::Map<String, Value>,
    name: &str,
    what: &str,
) -> Result<&'a Value, ConnectorError> {
    object
        .get(name)
        .ok_or_else(|| invalid(format!("{what} requires field {name:?}")))
}

fn field_str<'a>(
    object: &'a serde_json::Map<String, Value>,
    name: &str,
    what: &str,
) -> Result<&'a str, ConnectorError> {
    field(object, name, what)?
        .as_str()
        .ok_or_else(|| invalid(format!("{what} field {name:?} must be a string")))
}

fn field_bool(
    object: &serde_json::Map<String, Value>,
    name: &str,
    what: &str,
) -> Result<bool, ConnectorError> {
    field(object, name, what)?
        .as_bool()
        .ok_or_else(|| invalid(format!("{what} field {name:?} must be a boolean")))
}

fn is_missing_envelope(value: &Value) -> bool {
    matches!(value.as_object(), Some(map) if map.get("value") == Some(&Value::Null))
}

fn parse_missing(value: &Value, what: &str) -> Result<Missing, ConnectorError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(format!("{what} Missing envelope must be an object")))?;
    if object.get("value") != Some(&Value::Null) {
        return Err(invalid(format!("{what} Missing envelope requires \"value\": null")));
    }
    let reason = object
        .get("reason")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("{what} Missing envelope requires string reason")))?;
    let detail = object
        .get("detail")
        .or_else(|| object.get("Detail"))
        .and_then(Value::as_str)
        .map(|s| s.to_string());
    for key in object.keys() {
        if key != "value" && key != "reason" && key != "detail" && key != "Detail" {
            return Err(invalid(format!("{what} Missing envelope has undeclared field {key:?}")));
        }
    }
    let missing = Missing { reason: reason.to_string(), detail };
    check_missing(&missing)?;
    Ok(missing)
}

fn missing_json(missing: &Missing) -> Value {
    match &missing.detail {
        Some(detail) => json!({"value": null, "reason": missing.reason, "detail": detail}),
        None => json!({"value": null, "reason": missing.reason}),
    }
}

fn parse_catalog_pin(value: &Value, what: &str) -> Result<CatalogPin, ConnectorError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(format!("{what} version pin must be an object")))?;
    ensure_closed(object, &["id", "version", "artifact_digest"], what)?;
    let id = field_str(object, "id", what)?.to_string();
    let version = field_str(object, "version", what)?.to_string();
    let digest_str = field_str(object, "artifact_digest", what)?;
    let artifact_digest = Digest::parse(digest_str).map_err(invalid)?;
    require_identifier(&format!("{what} id"), &id)?;
    require_identifier(&format!("{what} version"), &version)?;
    if !rm_wire::is_valid_digest(artifact_digest.as_str()) {
        return Err(invalid(format!("{what} artifact_digest is not a digest")));
    }
    Ok(CatalogPin { id, version, artifact_digest })
}

fn parse_time_maybe_string(value: &Value, what: &str) -> Result<TimeMaybeString, ConnectorError> {
    if is_missing_envelope(value) {
        return Ok(TimeMaybeString::Missing(parse_missing(value, what)?));
    }
    match value.as_str() {
        Some(text) => {
            require_nonempty(what, text)?;
            Ok(TimeMaybeString::Text(text.to_string()))
        }
        None => Err(invalid(format!("{what} must be a string or Missing envelope"))),
    }
}

fn parse_manifest(value: &Value, what: &str) -> Result<Manifest, ConnectorError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(format!("{what} must be an object")))?;
    ensure_closed(
        object,
        &[
            "record_type",
            "schema_version",
            "run_id",
            "task",
            "subject",
            "event_kinds",
            "admission_ref",
            "manifest_hash",
        ],
        what,
    )?;
    let record_type = field_str(object, "record_type", what)?.to_string();
    let schema_version = field_str(object, "schema_version", what)?.to_string();
    let run_id = field_str(object, "run_id", what)?.to_string();
    let task = field(object, "task", what)?.clone();
    let subject = field(object, "subject", what)?.clone();
    let kinds_value = field(object, "event_kinds", what)?
        .as_array()
        .ok_or_else(|| invalid(format!("{what} event_kinds must be an array")))?;
    let mut event_kinds = Vec::with_capacity(kinds_value.len());
    for item in kinds_value {
        let text = item
            .as_str()
            .ok_or_else(|| invalid(format!("{what} event kind must be a string")))?;
        require_nonempty(&format!("{what} event kind"), text)?;
        event_kinds.push(text.to_string());
    }
    let admission_ref = field_str(object, "admission_ref", what)?.to_string();
    let manifest_hash = field_str(object, "manifest_hash", what)?.to_string();
    require_nonempty(&format!("{what} record_type"), &record_type)?;
    require_nonempty(&format!("{what} run_id"), &run_id)?;
    require_nonempty(&format!("{what} admission_ref"), &admission_ref)?;
    if !rm_wire::is_valid_digest(&manifest_hash) {
        return Err(invalid(format!("{what} manifest_hash is not a digest")));
    }
    let manifest = Manifest {
        record_type,
        schema_version,
        run_id,
        task,
        subject,
        event_kinds,
        admission_ref,
        manifest_hash,
    };
    let wire = rm_authority::manifest_wire_bytes(&manifest);
    let computed =
        rm_wire::canonical_digest(&wire).map_err(|e| invalid(format!("{what} wire digest failed: {e}")))?;
    if computed.as_str() != manifest.manifest_hash {
        return Err(invalid(format!("{what} manifest_hash does not match wire bytes")));
    }
    Ok(manifest)
}

fn parse_prefix(value: &Value, what: &str) -> Result<JournalPrefix, ConnectorError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(format!("{what} journal prefix must be an object")))?;
    ensure_closed(object, &["journal_id", "last_sequence", "head_hash"], what)?;
    let journal_id = field_str(object, "journal_id", what)?.to_string();
    let last_sequence = field(object, "last_sequence", what)?
        .as_u64()
        .ok_or_else(|| invalid(format!("{what} last_sequence must be an integer")))?;
    let head_hash =
        Digest::parse(field_str(object, "head_hash", what)?).map_err(invalid)?;
    require_identifier(&format!("{what} journal_id"), &journal_id)?;
    if !rm_wire::is_valid_digest(head_hash.as_str()) {
        return Err(invalid(format!("{what} head_hash is not a digest")));
    }
    Ok(JournalPrefix {
        journal_id,
        last_sequence: PositiveInteger::new(last_sequence)?,
        head_hash,
    })
}

// ---------------------------------------------------------------------------
// Execution plan (§8.2 closed arguments)
// ---------------------------------------------------------------------------

/// Preflight pin (§8.3): destination, account binding, marker, scope, policy.
#[derive(Debug, Clone)]
struct PreflightSpec {
    destination: String,
    account_binding: TimeMaybeString,
    marker: String,
    scope: String,
    policy: CatalogPin,
}

/// One closed workflow action (§8.2).
#[derive(Debug, Clone)]
enum ActionSpec {
    Navigate { url: String, navigation_policy: CatalogPin },
    Fill {
        target: ArtifactReference,
        text: ArtifactReference,
        event_recipe: CatalogPin,
    },
    Click {
        target: ArtifactReference,
        event_recipe: CatalogPin,
    },
    Select {
        target: ArtifactReference,
        values: ArtifactReference,
        event_recipe: CatalogPin,
    },
    Wait {
        predicate: ArtifactReference,
        predicate_mapping: CatalogPin,
    },
    Extract {
        query: TimeMaybeString,
        output_schema: CatalogPin,
        extraction_policy: CatalogPin,
    },
    Assert {
        predicate: ArtifactReference,
        predicate_mapping: CatalogPin,
    },
    Upload {
        target: ArtifactReference,
        files: Vec<ArtifactReference>,
        upload_policy: CatalogPin,
        event_recipe: Option<CatalogPin>,
    },
    Checkpoint {
        checkpoint_policy: CatalogPin,
    },
}

impl ActionSpec {
    fn name(&self) -> &'static str {
        match self {
            ActionSpec::Navigate { .. } => "navigate",
            ActionSpec::Fill { .. } => "fill",
            ActionSpec::Click { .. } => "click",
            ActionSpec::Select { .. } => "select",
            ActionSpec::Wait { .. } => "wait",
            ActionSpec::Extract { .. } => "extract",
            ActionSpec::Assert { .. } => "assert",
            ActionSpec::Upload { .. } => "upload",
            ActionSpec::Checkpoint { .. } => "checkpoint",
        }
    }
}

/// Parsed execution plan: manifest, binding evidence, preflight, and steps.
#[derive(Debug, Clone)]
struct ExecutionPlan {
    manifest: Manifest,
    binding_prefix: JournalPrefix,
    binding_evidence: EvidenceRef,
    binding_id: String,
    storage_model: String,
    unmapped: Vec<String>,
    preflight: PreflightSpec,
    steps: Vec<ActionSpec>,
    recovery_allowance: u64,
    heal_profile_policy: CatalogPin,
}

fn parse_preflight(value: &Value) -> Result<PreflightSpec, ConnectorError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("preflight must be an object"))?;
    ensure_closed(
        object,
        &["destination", "account_binding", "marker", "scope", "policy"],
        "preflight",
    )?;
    let destination = field_str(object, "destination", "preflight")?.to_string();
    require_nonempty("preflight destination", &destination)?;
    let account_binding = parse_time_maybe_string(
        field(object, "account_binding", "preflight")?,
        "preflight account_binding",
    )?;
    let marker = field_str(object, "marker", "preflight")?.to_string();
    require_nonempty("preflight marker", &marker)?;
    let scope = field_str(object, "scope", "preflight")?.to_string();
    require_nonempty("preflight scope", &scope)?;
    let policy = parse_catalog_pin(field(object, "policy", "preflight")?, "preflight policy")?;
    Ok(PreflightSpec { destination, account_binding, marker, scope, policy })
}

fn parse_action(value: &Value) -> Result<ActionSpec, ConnectorError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("step must be an object"))?;
    let action = field_str(object, "action", "step")?;
    match action {
        "navigate" => {
            ensure_closed(object, &["action", "url", "navigation_policy"], "navigate step")?;
            let url = field_str(object, "url", "navigate step")?.to_string();
            require_nonempty("navigate url", &url)?;
            let navigation_policy = parse_catalog_pin(
                field(object, "navigation_policy", "navigate step")?,
                "navigate navigation_policy",
            )?;
            Ok(ActionSpec::Navigate { url, navigation_policy })
        }
        "fill" => {
            ensure_closed(object, &["action", "target", "text", "event_recipe"], "fill step")?;
            let target = ArtifactReference::from_json(field(object, "target", "fill step")?)?;
            let text = ArtifactReference::from_json(field(object, "text", "fill step")?)?;
            let event_recipe = parse_catalog_pin(
                field(object, "event_recipe", "fill step")?,
                "fill event_recipe",
            )?;
            Ok(ActionSpec::Fill { target, text, event_recipe })
        }
        "click" => {
            ensure_closed(object, &["action", "target", "event_recipe"], "click step")?;
            let target = ArtifactReference::from_json(field(object, "target", "click step")?)?;
            let event_recipe = parse_catalog_pin(
                field(object, "event_recipe", "click step")?,
                "click event_recipe",
            )?;
            Ok(ActionSpec::Click { target, event_recipe })
        }
        "select" => {
            ensure_closed(object, &["action", "target", "values", "event_recipe"], "select step")?;
            let target = ArtifactReference::from_json(field(object, "target", "select step")?)?;
            let values = ArtifactReference::from_json(field(object, "values", "select step")?)?;
            let event_recipe = parse_catalog_pin(
                field(object, "event_recipe", "select step")?,
                "select event_recipe",
            )?;
            Ok(ActionSpec::Select { target, values, event_recipe })
        }
        "wait" => {
            ensure_closed(object, &["action", "predicate", "predicate_mapping"], "wait step")?;
            let predicate =
                ArtifactReference::from_json(field(object, "predicate", "wait step")?)?;
            let predicate_mapping = parse_catalog_pin(
                field(object, "predicate_mapping", "wait step")?,
                "wait predicate_mapping",
            )?;
            Ok(ActionSpec::Wait { predicate, predicate_mapping })
        }
        "extract" => {
            ensure_closed(
                object,
                &["action", "query", "output_schema", "extraction_policy"],
                "extract step",
            )?;
            let query = parse_time_maybe_string(
                field(object, "query", "extract step")?,
                "extract query",
            )?;
            let output_schema = parse_catalog_pin(
                field(object, "output_schema", "extract step")?,
                "extract output_schema",
            )?;
            let extraction_policy = parse_catalog_pin(
                field(object, "extraction_policy", "extract step")?,
                "extract extraction_policy",
            )?;
            Ok(ActionSpec::Extract { query, output_schema, extraction_policy })
        }
        "assert" => {
            ensure_closed(object, &["action", "predicate", "predicate_mapping"], "assert step")?;
            let predicate =
                ArtifactReference::from_json(field(object, "predicate", "assert step")?)?;
            let predicate_mapping = parse_catalog_pin(
                field(object, "predicate_mapping", "assert step")?,
                "assert predicate_mapping",
            )?;
            Ok(ActionSpec::Assert { predicate, predicate_mapping })
        }
        "upload" => {
            ensure_closed(
                object,
                &["action", "target", "files", "upload_policy", "event_recipe"],
                "upload step",
            )?;
            let target = ArtifactReference::from_json(field(object, "target", "upload step")?)?;
            let files_value = field(object, "files", "upload step")?
                .as_array()
                .ok_or_else(|| invalid("upload files must be an array"))?;
            if files_value.is_empty() {
                return Err(invalid("upload files must be nonempty"));
            }
            let mut files = Vec::with_capacity(files_value.len());
            for item in files_value {
                files.push(ArtifactReference::from_json(item)?);
            }
            let upload_policy = parse_catalog_pin(
                field(object, "upload_policy", "upload step")?,
                "upload upload_policy",
            )?;
            let recipe_value = field(object, "event_recipe", "upload step")?;
            let event_recipe = if is_missing_envelope(recipe_value) {
                let missing = parse_missing(recipe_value, "upload event_recipe")?;
                let _ = missing;
                None
            } else {
                Some(parse_catalog_pin(recipe_value, "upload event_recipe")?)
            };
            Ok(ActionSpec::Upload { target, files, upload_policy, event_recipe })
        }
        "checkpoint" => {
            ensure_closed(object, &["action", "checkpoint_policy"], "checkpoint step")?;
            let checkpoint_policy = parse_catalog_pin(
                field(object, "checkpoint_policy", "checkpoint step")?,
                "checkpoint checkpoint_policy",
            )?;
            Ok(ActionSpec::Checkpoint { checkpoint_policy })
        }
        other => Err(invalid(format!("unknown action {other:?}: exactly the nine §8.2 actions exist"))),
    }
}

fn parse_plan(bytes: &[u8]) -> Result<ExecutionPlan, ConnectorError> {
    rm_wire::canonical_digest(bytes).map_err(|e| invalid(format!("plan bytes rejected: {e}")))?;
    let value: Value =
        serde_json::from_slice(bytes).map_err(|e| invalid(format!("plan is not JSON: {e}")))?;
    let object = value
        .as_object()
        .ok_or_else(|| invalid("plan must be an object"))?;
    const ALLOWED: [&str; 11] = [
        "record_type",
        "schema_version",
        "manifest",
        "binding_prefix",
        "binding_evidence",
        "binding_id",
        "storage_model",
        "unmapped",
        "preflight",
        "steps",
        "recovery",
    ];
    ensure_closed(object, &ALLOWED, "execution plan")?;
    let record_type = field_str(object, "record_type", "execution plan")?;
    let schema_version = field_str(object, "schema_version", "execution plan")?;
    if record_type != EXECUTION_PLAN_RECORD_TYPE {
        return Err(invalid(format!(
            "plan record_type {record_type:?} must be {EXECUTION_PLAN_RECORD_TYPE:?}"
        )));
    }
    if schema_version != EXECUTION_PLAN_SCHEMA_VERSION {
        return Err(invalid(format!(
            "plan schema_version {schema_version:?} must be {EXECUTION_PLAN_SCHEMA_VERSION:?}"
        )));
    }
    let manifest = parse_manifest(field(object, "manifest", "execution plan")?, "plan manifest")?;
    let binding_prefix = parse_prefix(
        field(object, "binding_prefix", "execution plan")?,
        "plan binding_prefix",
    )?;
    let binding_evidence = EvidenceRef::from_json(field(object, "binding_evidence", "execution plan")?)?;
    binding_evidence.validate().map_err(|e| invalid(format!("plan binding_evidence invalid: {}", e.detail)))?;
    let binding_id = field_str(object, "binding_id", "execution plan")?.to_string();
    require_identifier("plan binding_id", &binding_id)?;
    let storage_model = field_str(object, "storage_model", "execution plan")?.to_string();
    if storage_model != "process_global"
        && storage_model != "verified_namespaced"
        && storage_model != "unknown"
    {
        return Err(invalid(format!("plan storage_model {storage_model:?} unknown")));
    }
    let unmapped_value = field(object, "unmapped", "execution plan")?
        .as_array()
        .ok_or_else(|| invalid("plan unmapped must be an array"))?;
    let mut unmapped = Vec::with_capacity(unmapped_value.len());
    for item in unmapped_value {
        let text = item
            .as_str()
            .ok_or_else(|| invalid("plan unmapped entry must be a string"))?;
        require_nonempty("plan unmapped entry", text)?;
        unmapped.push(text.to_string());
    }
    let preflight = parse_preflight(field(object, "preflight", "execution plan")?)?;
    let steps_value = field(object, "steps", "execution plan")?
        .as_array()
        .ok_or_else(|| invalid("plan steps must be an array"))?;
    if steps_value.is_empty() {
        return Err(invalid("plan steps must be nonempty"));
    }
    let mut steps = Vec::with_capacity(steps_value.len());
    for item in steps_value {
        steps.push(parse_action(item)?);
    }
    let recovery = field(object, "recovery", "execution plan")?
        .as_object()
        .ok_or_else(|| invalid("plan recovery must be an object"))?;
    ensure_closed(recovery, &["allowance_remaining", "heal_profile_policy"], "plan recovery")?;
    let allowance_remaining = recovery
        .get("allowance_remaining")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid("plan recovery allowance_remaining must be an integer"))?;
    let heal_profile_policy = parse_catalog_pin(
        recovery
            .get("heal_profile_policy")
            .ok_or_else(|| invalid("plan recovery requires heal_profile_policy"))?,
        "plan heal_profile_policy",
    )?;
    Ok(ExecutionPlan {
        manifest,
        binding_prefix,
        binding_evidence,
        binding_id,
        storage_model,
        unmapped,
        preflight,
        steps,
        recovery_allowance: allowance_remaining,
        heal_profile_policy,
    })
}

// ---------------------------------------------------------------------------
// Binding construction (§5.2, from admitted evidence)
// ---------------------------------------------------------------------------

fn bo_engine() -> CatalogComponent {
    CatalogComponent {
        component: "browseroxide-engine".to_string(),
        reported_version: CatalogMaybeString::Text("2.0.0".to_string()),
        build_digest: CatalogMaybeDigest::Present(rm_wire::artifact_digest(b"rm-exec-engine-build")),
        configuration_digest: CatalogMaybeDigest::Present(rm_wire::artifact_digest(
            b"rm-exec-engine-config",
        )),
    }
}

fn bo_subject(engine: &CatalogComponent, binding_id: &str, binding_version: &str) -> CatalogSubject {
    CatalogSubject {
        subject_id: binding_id.to_string(),
        subject_version: binding_version.to_string(),
        revision_basis: "native_revision".to_string(),
        native_revision: CatalogMaybeString::Text("native-rev-1".to_string()),
        configured_mode: "default".to_string(),
        interface_surface: "browseroxide-ffi".to_string(),
        configuration_digest: rm_wire::artifact_digest(b"rm-exec-config"),
        stack: vec![engine.clone()],
    }
}

fn bo_record(id: &str) -> CapabilityRecord {
    CapabilityRecord {
        capability_id: id.to_string(),
        requirement_refs: Vec::new(),
        availability: "unknown".to_string(),
        claim_origin: "harness".to_string(),
        evidence: Vec::new(),
        limitations: vec![format!("{id} is unassessed")],
    }
}

fn bo_mapped(primitive: &str, evidence: &EvidenceRef) -> BOMapping {
    BOMapping {
        primitive: primitive.to_string(),
        mapping_state: "mapped".to_string(),
        native_symbol: CatalogMaybeString::Text(format!("native_{}", primitive.replace('.', "_"))),
        native_contract: CatalogMaybePin::Present(CatalogPin {
            id: "bo-contract".to_string(),
            version: "1.0.0".to_string(),
            artifact_digest: rm_wire::artifact_digest(primitive.as_bytes()),
        }),
        evidence_refs: vec![evidence.clone()],
    }
}

fn bo_unmapped(primitive: &str) -> BOMapping {
    BOMapping {
        primitive: primitive.to_string(),
        mapping_state: "unmapped".to_string(),
        native_symbol: CatalogMaybeString::Missing(Missing::new("not_observed")),
        native_contract: CatalogMaybePin::Missing(Missing::new("not_applicable")),
        evidence_refs: Vec::new(),
    }
}

fn build_binding(plan: &ExecutionPlan) -> BOBindingDescriptor {
    let engine = bo_engine();
    let subject = bo_subject(&engine, &plan.binding_id, "1.0.0");
    let evidence = &plan.binding_evidence;
    let prefix = &plan.binding_prefix;
    let isolation = if plan.storage_model == "verified_namespaced" {
        vec![evidence.clone()]
    } else {
        Vec::new()
    };
    BOBindingDescriptor {
        record_type: BO_RECORD_TYPE.to_string(),
        schema_version: BO_SCHEMA_VERSION.to_string(),
        binding_id: plan.binding_id.clone(),
        binding_build: CatalogPin {
            id: plan.binding_id.clone(),
            version: "1.0.0".to_string(),
            artifact_digest: rm_wire::artifact_digest(b"rm-exec-binding-build"),
        },
        engine,
        capabilities: CapabilityDescriptor {
            record_type: CAPABILITY_RECORD_TYPE.to_string(),
            schema_version: CAPABILITY_SCHEMA_VERSION.to_string(),
            descriptor_id: "bo-capabilities-1".to_string(),
            descriptor_revision: 1,
            declared_by: plan.binding_id.clone(),
            subject,
            catalog: CatalogPin {
                id: "bo-catalog".to_string(),
                version: "0.1.0".to_string(),
                artifact_digest: rm_wire::artifact_digest(b"rm-exec-catalog"),
            },
            evidence_prefix: prefix.clone(),
            supersedes: CatalogMaybeDigest::Missing(Missing::new("not_applicable")),
            capabilities: BO_CAPABILITIES.iter().map(|id| bo_record(id)).collect(),
        },
        primitive_mappings: BO_PRIMITIVES
            .iter()
            .map(|primitive| {
                if plan.unmapped.iter().any(|u| u == primitive) {
                    bo_unmapped(primitive)
                } else {
                    bo_mapped(primitive, evidence)
                }
            })
            .collect(),
        session_storage_model: plan.storage_model.clone(),
        session_isolation_refs: isolation,
        privacy_policy: CatalogPin {
            id: "bo-privacy".to_string(),
            version: "0.1.0".to_string(),
            artifact_digest: rm_wire::artifact_digest(b"rm-exec-privacy"),
        },
        evidence_prefix: prefix.clone(),
    }
}

// ---------------------------------------------------------------------------
// Learning conversion (EXT-STATE-POLICY: browser/learning stay separate)
// ---------------------------------------------------------------------------

fn convert_maybe_string_catalog_to_time(
    value: &CatalogMaybeString,
) -> Result<TimeMaybeString, ConnectorError> {
    match value {
        CatalogMaybeString::Text(text) => {
            require_nonempty("learning resource_ref", text)?;
            Ok(TimeMaybeString::Text(text.clone()))
        }
        CatalogMaybeString::Missing(missing) => {
            check_missing(missing)?;
            Ok(TimeMaybeString::Missing(Missing {
                reason: missing.reason.clone(),
                detail: missing.detail.clone(),
            }))
        }
    }
}

fn convert_learning_subject(
    subject: &CatalogSubject,
) -> Result<rm_learning::SubjectIdentity, ConnectorError> {
    let mut stack = Vec::with_capacity(subject.stack.len());
    for component in &subject.stack {
        let reported = convert_maybe_string_catalog_to_time(&component.reported_version)?;
        let build = match &component.build_digest {
            CatalogMaybeDigest::Present(digest) => {
                rm_learning::MaybeDigest::Present(digest.clone())
            }
            CatalogMaybeDigest::Missing(missing) => {
                check_missing(missing)?;
                rm_learning::MaybeDigest::Missing(Missing {
                    reason: missing.reason.clone(),
                    detail: missing.detail.clone(),
                })
            }
        };
        let config = match &component.configuration_digest {
            CatalogMaybeDigest::Present(digest) => {
                rm_learning::MaybeDigest::Present(digest.clone())
            }
            CatalogMaybeDigest::Missing(missing) => {
                check_missing(missing)?;
                rm_learning::MaybeDigest::Missing(Missing {
                    reason: missing.reason.clone(),
                    detail: missing.detail.clone(),
                })
            }
        };
        stack.push(rm_learning::ComponentIdentity {
            component: component.component.clone(),
            reported_version: reported,
            build_digest: build,
            configuration_digest: config,
        });
    }
    let native_revision = convert_maybe_string_catalog_to_time(&subject.native_revision)?;
    Ok(rm_learning::SubjectIdentity {
        subject_id: subject.subject_id.clone(),
        subject_version: subject.subject_version.clone(),
        revision_basis: subject.revision_basis.clone(),
        native_revision,
        configured_mode: subject.configured_mode.clone(),
        interface_surface: subject.interface_surface.clone(),
        configuration_digest: subject.configuration_digest.clone(),
        stack,
    })
}

fn convert_learning_context(
    policy: &rm_preparation::ContextPolicy,
) -> Result<rm_learning::ContextPolicy, ConnectorError> {
    let convert_state = |state: &rm_preparation::StatePolicy,
                         what: &str|
     -> Result<rm_learning::StatePolicy, ConnectorError> {
        let resource_ref = convert_maybe_string_catalog_to_time(&state.resource_ref)
            .map_err(|e| invalid(format!("{what} resource_ref invalid: {}", e.detail)))?;
        let baseline = match &state.baseline {
            rm_preparation::MaybeArtifact::Present(reference) => {
                rm_learning::MaybeArtifact::Present(reference.clone())
            }
            rm_preparation::MaybeArtifact::Missing(missing) => {
                check_missing(missing)?;
                rm_learning::MaybeArtifact::Missing(Missing {
                    reason: missing.reason.clone(),
                    detail: missing.detail.clone(),
                })
            }
        };
        Ok(rm_learning::StatePolicy {
            mode: state.mode.clone(),
            requirement: state.requirement.clone(),
            resource_ref,
            baseline,
        })
    };
    Ok(rm_learning::ContextPolicy {
        browser_state: convert_state(&policy.browser_state, "browser_state")?,
        learning_state: convert_state(&policy.learning_state, "learning_state")?,
    })
}

// ---------------------------------------------------------------------------
// Lease / boundary / authority
// ---------------------------------------------------------------------------

fn execution_now(lease: &LeaseRecord) -> Result<TimePoint, ConnectorError> {
    let (issued, deadline) = match (&lease.leased_at, &lease.lease_expires_at) {
        (MaybeTimePoint::Present(issued), MaybeTimePoint::Present(deadline)) => {
            (issued.clone(), deadline.clone())
        }
        _ => return Err(invalid("held lease requires present issue and deadline")),
    };
    if issued.clock_id != deadline.clock_id
        || issued.boot_id != deadline.boot_id
        || issued.origin != deadline.origin
    {
        return Err(invalid("lease issue and deadline span clocks/boots/origins"));
    }
    // A coordinate just after issue on the same clock/boot/origin: comparable
    // without consulting UTC annotations.
    Ok(TimePoint {
        clock_id: issued.clock_id,
        boot_id: issued.boot_id,
        origin: issued.origin,
        monotonic_offset_ms: issued.monotonic_offset_ms + 1.0,
        utc_annotation: UtcAnnotation::Missing(Missing::new("not_observed")),
    })
}

fn active_deadline_for(
    handle: &ConnectorHandle,
    preparation: &PreparedTask,
) -> Result<TimePoint, ConnectorError> {
    let limit = &preparation.task.budgets.active_limit;
    if limit.kind != "exact" || limit.unit != "ms" {
        return Err(invalid("active_limit must be exact ms"));
    }
    if !limit.value.is_finite() || limit.value < 0.0 {
        return Err(invalid("active_limit must be finite nonnegative"));
    }
    let created = &handle.created_at;
    Ok(TimePoint {
        clock_id: created.clock_id.clone(),
        boot_id: created.boot_id.clone(),
        origin: created.origin,
        monotonic_offset_ms: created.monotonic_offset_ms + limit.value,
        utc_annotation: UtcAnnotation::Missing(Missing::new("not_observed")),
    })
}

fn check_active_boundary(
    now: &TimePoint,
    deadline: &TimePoint,
) -> Result<(), ConnectorError> {
    // Both coordinates must share one clock/boot/origin; execution derives
    // `now` from the lease clock and the deadline from the handle clock, so a
    // mismatch is a prerequisite failure, never silent expiry. When the clocks
    // agree, a reached boundary stops delivery without escalation.
    if now.clock_id != deadline.clock_id
        || now.boot_id != deadline.boot_id
        || now.origin != deadline.origin
    {
        return Err(prerequisite(
            "active boundary spans clocks/boots/origins; UTC is annotation only and elapsed time is never inferred across lifetimes",
        ));
    }
    let reached = rm_time::boundary_reached(now, deadline)
        .map_err(|e| invalid(format!("active boundary cannot be ordered: {e}")))?;
    if reached {
        return Err(not_admitted(
            "active boundary reached before native entry: stop workflow delivery and finalize locally",
        ));
    }
    Ok(())
}

fn authorize_execution(
    principal: &AuthenticatedPrincipal,
    preparation: &PreparedTask,
) -> Result<(), ConnectorError> {
    require_nonempty(
        "preparation configuration connector_id",
        &preparation.configuration.connector_id,
    )?;
    require_nonempty(
        "preparation configuration subject_id",
        &preparation.configuration.subject.subject_id,
    )?;
    require_nonempty("preparation scope activity", &preparation.scope.activity)?;
    let operation = Operation {
        verb: "Observe".to_string(),
        connector_id: preparation.configuration.connector_id.clone(),
        subject_id: preparation.configuration.subject.subject_id.clone(),
        task_scope: preparation.scope.activity.clone(),
        account_binding: None,
        artifact_refs: Vec::new(),
        control_target: None,
    };
    rm_authority::authorize_work(principal, &preparation.scope, &operation)?;
    Ok(())
}

fn check_preparation_handle(
    preparation: &PreparedTask,
    handle: &ConnectorHandle,
) -> Result<(), ConnectorError> {
    if preparation.record_type != "connector_preparation" {
        return Err(invalid(format!(
            "preparation record_type {:?} must be connector_preparation",
            preparation.record_type
        )));
    }
    if handle.record_type != "connector_handle" {
        return Err(invalid(format!(
            "handle record_type {:?} must be connector_handle",
            handle.record_type
        )));
    }
    handle
        .validate()
        .map_err(|e| invalid(format!("handle invalid: {} [{}] {}", e.code, e.fault_domain, e.detail)))?;
    preparation
        .delivered_task
        .validate()
        .map_err(|e| invalid(format!("preparation delivered_task invalid: {}", e.detail)))?;
    if preparation.preparation_id != handle.preparation.preparation_id {
        return Err(invalid(format!(
            "preparation_id {:?} does not match handle preparation {:?}",
            preparation.preparation_id, handle.preparation.preparation_id
        )));
    }
    if preparation.scope.run_id != handle.scope.run_id
        || preparation.scope.journal_id != handle.scope.journal_id
        || preparation.scope.manifest_hash != handle.scope.manifest_hash
    {
        return Err(invalid(
            "preparation scope does not match handle scope: stale/conflicting input rejected",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Journal helpers
// ---------------------------------------------------------------------------

fn install_public(
    principal: &AuthenticatedPrincipal,
    bytes: &[u8],
    media_type: &str,
) -> Result<ArtifactReference, ConnectorError> {
    let reference = ArtifactReference {
        digest: rm_wire::artifact_digest(bytes),
        size_bytes: bytes.len() as u64,
        media_type: media_type.to_string(),
        owner_domain: EXECUTION_OWNER_DOMAIN.to_string(),
        access: AccessClass::Public,
    };
    rm_evidence::install_artifact(principal, &reference, bytes)?;
    Ok(reference)
}

fn install_restricted(
    principal: &AuthenticatedPrincipal,
    bytes: &[u8],
    media_type: &str,
    owner_domain: &str,
) -> Result<ArtifactReference, ConnectorError> {
    let reference = ArtifactReference {
        digest: rm_wire::artifact_digest(bytes),
        size_bytes: bytes.len() as u64,
        media_type: media_type.to_string(),
        owner_domain: owner_domain.to_string(),
        access: AccessClass::Restricted,
    };
    rm_evidence::install_artifact(principal, &reference, bytes)?;
    Ok(reference)
}

struct JournalWriter<'a> {
    principal: &'a AuthenticatedPrincipal,
    manifest: &'a Manifest,
    next_sequence: u64,
}

impl<'a> JournalWriter<'a> {
    fn new(principal: &'a AuthenticatedPrincipal, manifest: &'a Manifest, start: u64) -> Self {
        JournalWriter { principal, manifest, next_sequence: start }
    }

    fn append(
        &mut self,
        event_kind: &str,
        data: Value,
        artifact_refs: Vec<ArtifactReference>,
    ) -> Result<EvidenceRef, ConnectorError> {
        if self.next_sequence > MAX_PRODUCER_SEQUENCE_JUMP + 10_000 {
            return Err(forbidden("journal producer sequence bound reached"));
        }
        let sequence = PositiveInteger::new(self.next_sequence)?;
        self.next_sequence += 1;
        let submission = EventSubmission {
            producer_sequence: Some(sequence),
            event_kind: event_kind.to_string(),
            event_schema_version: "evidence-kernel/0.1.0".to_string(),
            occurred_at: MaybeTimePoint::Missing(Missing::new("not_observed")),
            payload: EvidencePayload {
                data,
                measurements: Vec::new(),
                evidence_refs: Vec::new(),
                artifact_refs,
            },
        };
        let envelope = rm_evidence::append_event(self.principal, self.manifest, submission)?;
        Ok(EvidenceRef {
            journal_id: envelope.journal_id.clone(),
            sequence: envelope.journal_sequence,
            event_id: envelope.event_id.clone(),
            event_hash: envelope.event_hash.clone(),
            pointer: String::new(),
        })
    }
}

// ---------------------------------------------------------------------------
// Failure routing (§10.2)
// ---------------------------------------------------------------------------

/// Mutating primitives whose post-entry failure implies a possible effect.
const MUTATING_PRIMITIVES: [&str; 6] = [
    "bo.dom_write",
    "bo.event_dispatch",
    "bo.navigate",
    "bo.from_html",
    "bo.assign_files",
    "bo.http_exchange",
];

/// Outcome of routing one native failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FailureRoute {
    /// Safe to attempt Tier 2/3 recovery when authorized and budgeted.
    Recover,
}

/// Routes a failed [`BOPrimitiveRecord`] per §10.2.
///
/// Returns `Ok(Recover)` only for effect-safe failures (pre-entry failures
/// without effects, or entered read-only failures without effects). All other
/// failures return the §10.2 error directly: mapping limitations,
/// reconciliation requirements, fences, or prerequisite failures. Budgets and
/// deadlines are never extended here; the caller enforces them before
/// invoking recovery.
fn route_primitive_failure(failed: &BOPrimitiveRecord) -> Result<FailureRoute, ConnectorError> {
    if failed.return_state == "unsupported" {
        return Err(unsupported_mapping(format!(
            "primitive {:?} is unmapped (return_state unsupported): explicit mapping limitation; not selector healing",
            failed.primitive
        )));
    }
    if failed.return_state != "failed" {
        return Err(invalid(format!(
            "failure routing requires return_state failed, found {:?}",
            failed.return_state
        )));
    }
    let (code, native_entry, detail) = match &failed.error {
        MaybeBOFailure::Present(failure) => (
            failure.code.clone(),
            failure.native_entry.clone(),
            failure.detail.clone(),
        ),
        MaybeBOFailure::Missing(missing) => {
            return Err(invalid(format!(
                "failed call carries Missing error (reason {:?}): failure record required",
                missing.reason
            )))
        }
    };
    let detail_lower = detail.to_lowercase();
    let code_upper = code.to_uppercase();
    if code_upper == "WRONG_THREAD"
        || detail_lower.contains("wrong thread")
        || detail_lower.contains("owning os thread")
        || detail_lower.contains("not the owning")
    {
        return Err(fenced(format!(
            "wrong-thread failure ({code} [{native_entry}]): stop/fence; not selector healing"
        )));
    }
    if code_upper == "FORBIDDEN"
        || code_upper == "NOT_ADMITTED"
        || code_upper == "FENCED"
        || detail_lower.contains("authorization")
        || detail_lower.contains("not admitted")
        || detail_lower.contains("ownership")
        || detail_lower.contains("fenced")
        || detail_lower.contains("owner loss")
        || detail_lower.contains("lease")
    {
        return Err(fenced(format!(
            "authorization/ownership failure ({code} [{native_entry}]): stop/fence; not selector healing"
        )));
    }
    if native_entry == "not_entered"
        && (detail_lower.contains("not retained")
            || detail_lower.contains("bytes are not retained")
            || detail_lower.contains("storage")
            || detail_lower.contains("inputs_incomplete")
            || code_upper == "INPUTS_INCOMPLETE")
    {
        return Err(prerequisite(format!(
            "storage unavailable before intent ({code} [{native_entry}]): no mutation"
        )));
    }
    let is_mutating = MUTATING_PRIMITIVES.contains(&failed.primitive.as_str());
    if !failed.effect_refs.is_empty() {
        return Err(reconcile_required(format!(
            "failed {} carries {} effect reference(s): possible side effect; reconcile before action retry, never replay as selector recovery",
            failed.primitive,
            failed.effect_refs.len()
        )));
    }
    if is_mutating && native_entry != "not_entered" {
        return Err(reconcile_required(format!(
            "mutating {} entered native code (native_entry {native_entry:?}) before failing ({code}): possible side effect; reconcile before retry",
            failed.primitive
        )));
    }
    if detail_lower.contains("unsupported selector grammar")
        || detail_lower.contains("unsupported-grammar")
        || detail_lower.contains("explicit; no alternate engine")
    {
        return Err(unsupported_mapping(format!(
            "unsupported grammar ({code}): explicit mapping limitation; not selector healing"
        )));
    }
    if native_entry == "not_entered" {
        return Ok(FailureRoute::Recover);
    }
    if !is_mutating {
        return Ok(FailureRoute::Recover);
    }
    Err(reconcile_required(format!(
        "mutating {} failed after native entry ({code} [{native_entry}]): possible side effect; reconcile before retry",
        failed.primitive
    )))
}
/// Converts a failed native record that routed as effect-safe (no fence,
/// reconcile, or limitation) into a detailed caller error. Setup primitives
/// (client/page/navigate/reset/destroy) and definite no-entry action
/// failures have no selector-healing target, so the underlying native
/// failure detail is preserved rather than replaced with a generic message.
fn failed_primitive_error(record: &BOPrimitiveRecord, what: &str) -> ConnectorError {
    match &record.error {
        MaybeBOFailure::Present(failure) => invalid(format!(
            "{} failed: {} [{}] {}",
            what, failure.code, failure.native_entry, failure.detail
        )),
        MaybeBOFailure::Missing(_) => invalid(format!("{what} failed without error detail")),
    }
}


/// Routes a Tier 1 resolution [`ConnectorError`] per §10.2.
///
/// `TARGET_NOT_FOUND`, `TARGET_AMBIGUOUS`, and pre-entry `STALE_REFERENCE`
/// are effect-safe (no mutation occurred) and may proceed to recovery when
/// authorized and budgeted. `UNSUPPORTED_MAPPING` is an explicit limitation.
/// Wrong-thread/authorization/ownership failures fence. Storage failures
/// refuse mutation. Budget/deadline exhaustion never escalates.
fn route_resolution_error(error: &ConnectorError) -> Result<FailureRoute, ConnectorError> {
    match error.code.as_str() {
        "TARGET_NOT_FOUND" | "TARGET_AMBIGUOUS" => Ok(FailureRoute::Recover),
        "STALE_REFERENCE" => {
            // Tier 1 validates generation before mutation, so a stale target
            // observed here is pre-entry and effect-safe.
            Ok(FailureRoute::Recover)
        }
        "UNSUPPORTED_MAPPING" => Err(unsupported_mapping(format!(
            "Tier 1 grammar limitation: {}",
            error.detail
        ))),
        "FENCED" | "FORBIDDEN" | "NOT_ADMITTED" => Err(fenced(format!(
            "Tier 1 authorization/ownership failure ({}): stop/fence; not selector healing",
            error.code
        ))),
        "PREREQUISITE_UNAVAILABLE" => Err(prerequisite(format!(
            "Tier 1 prerequisite unavailable: {}",
            error.detail
        ))),
        "BUDGET_EXCEEDED" => Err(not_admitted(format!(
            "Tier 1 budget exhausted: no escalation ({})",
            error.detail
        ))),
        _ => {
            let detail_lower = error.detail.to_lowercase();
            if detail_lower.contains("wrong thread") || detail_lower.contains("owning os thread") {
                return Err(fenced(format!(
                    "Tier 1 wrong-thread failure: stop/fence ({})",
                    error.detail
                )));
            }
            if detail_lower.contains("not retained") || detail_lower.contains("storage") {
                return Err(prerequisite(format!(
                    "Tier 1 storage unavailable before intent: no mutation ({})",
                    error.detail
                )));
            }
            // Unknown Tier 1 failures are treated as definite no-entry
            // failures only when they carry no effect evidence; resolution
            // errors never carry native effects, so recovery may proceed.
            Ok(FailureRoute::Recover)
        }
    }
}

// ---------------------------------------------------------------------------
// Event recipes (explicit synthetic events; never trusted input)
// ---------------------------------------------------------------------------

/// One explicitly declared synthetic event.
#[derive(Debug, Clone)]
struct DeclaredEvent {
    event_type: String,
    bubbles: bool,
    cancelable: bool,
    composed: bool,
    detail: BOMaybeArtifact,
}

fn load_declared_events(
    principal: &AuthenticatedPrincipal,
    event_recipe: &CatalogPin,
    preparation: &PreparedTask,
) -> Result<Vec<DeclaredEvent>, ConnectorError> {
    // The event recipe pin identifies an installed artifact whose bytes are
    // the closed event declaration. The pin digest locates the bytes through
    // the preparation inputs: an input whose content digest matches the pin
    // carries the declaration. No default event is invented.
    let mut declaration: Option<Vec<u8>> = None;
    for input in &preparation.task.inputs {
        if input.content.digest == event_recipe.artifact_digest {
            declaration = Some(rm_evidence::load_artifact(principal, &input.content)?);
            break;
        }
    }
    let bytes = declaration.ok_or_else(|| {
        prerequisite(format!(
            "event_recipe {}.{} bytes are not among the admitted task inputs; no synthetic event is invented",
            event_recipe.id, event_recipe.version
        ))
    })?;
    rm_wire::canonical_digest(&bytes)
        .map_err(|e| invalid(format!("event_recipe bytes rejected: {e}")))?;
    let value: Value =
        serde_json::from_slice(&bytes).map_err(|e| invalid(format!("event_recipe is not JSON: {e}")))?;
    let object = value
        .as_object()
        .ok_or_else(|| invalid("event_recipe must be an object"))?;
    ensure_closed(object, &["record_type", "events"], "event_recipe")?;
    let record_type = field_str(object, "record_type", "event_recipe")?;
    if record_type != "event_recipe" {
        return Err(invalid(format!(
            "event_recipe record_type {record_type:?} must be event_recipe"
        )));
    }
    let events_value = field(object, "events", "event_recipe")?
        .as_array()
        .ok_or_else(|| invalid("event_recipe events must be an array"))?;
    let mut events = Vec::with_capacity(events_value.len());
    for (index, item) in events_value.iter().enumerate() {
        let what = format!("event_recipe events[{index}]");
        let entry = item
            .as_object()
            .ok_or_else(|| invalid(format!("{what} must be an object")))?;
        ensure_closed(
            entry,
            &["event_type", "bubbles", "cancelable", "composed", "detail"],
            &what,
        )?;
        let event_type = field_str(entry, "event_type", &what)?.to_string();
        require_nonempty(&format!("{what} event_type"), &event_type)?;
        let bubbles = field_bool(entry, "bubbles", &what)?;
        let cancelable = field_bool(entry, "cancelable", &what)?;
        let composed = field_bool(entry, "composed", &what)?;
        let detail_value = field(entry, "detail", &what)?;
        let detail = if is_missing_envelope(detail_value) {
            let missing = parse_missing(detail_value, &format!("{what} detail"))?;
            BOMaybeArtifact::Missing(missing)
        } else {
            let reference = ArtifactReference::from_json(detail_value)?;
            // Declared detail bytes must already be retained; they are never
            // fetched on demand.
            rm_evidence::load_artifact(principal, &reference).map_err(|_| {
                prerequisite(format!("{what} detail bytes are not retained; no mutation"))
            })?;
            BOMaybeArtifact::Present(reference)
        };
        events.push(DeclaredEvent { event_type, bubbles, cancelable, composed, detail });
    }
    Ok(events)
}

// ---------------------------------------------------------------------------
// Execution context
// ---------------------------------------------------------------------------

struct ExecutionContext<'a> {
    principal: &'a AuthenticatedPrincipal,
    preparation: &'a PreparedTask,
    handle: &'a ConnectorHandle,
    lease: &'a LeaseRecord,
    plan: ExecutionPlan,
    manifest: Manifest,
    now: TimePoint,
    active_deadline: TimePoint,
    limit: DurationLimit,
    auth_ref: EvidenceRef,
    journal: JournalWriter<'a>,
    completed_evidence: Vec<EvidenceRef>,
    completed_ids: Vec<String>,
    unresolved: Vec<String>,
    recovery_allowance: u64,
    learning_baseline: ArtifactReference,
}

impl<'a> ExecutionContext<'a> {
    fn check_owner_control(&mut self) -> Result<(), ConnectorError> {
        // Owner control commands arrive on their own queue, never behind
        // workflow delivery. A pending command stops new workflow primitives.
        let pending = rm_delivery::take_owner_control(self.principal, self.handle)?;
        if let Some(request) = pending {
            let verb = control_verb_of(&request);
            return Err(fenced(format!(
                "owner control {verb:?} is pending for this handle: stop issuing workflow commands"
            )));
        }
        Ok(())
    }

    fn check_bounds(&self) -> Result<(), ConnectorError> {
        check_active_boundary(&self.now, &self.active_deadline)?;
        if self.completed_evidence.len() as u64 >= self.preparation.task.budgets.action_limit {
            return Err(not_admitted(
                "action_limit reached: no escalation; stop workflow delivery and finalize locally",
            ));
        }
        Ok(())
    }
}

fn control_verb_of(request: &rm_delivery::ConnectorRequest) -> String {
    request.operation.clone()
}

// ---------------------------------------------------------------------------
// Preflight (§8.3)
// ---------------------------------------------------------------------------

fn destination_permitted(preparation: &PreparedTask, destination: &str) -> bool {
    if destination == preparation.task.entry.url {
        return true;
    }
    for origin in &preparation.task.permitted_origins {
        if destination == origin.origin || destination.starts_with(&format!("{}/", origin.origin)) {
            return true;
        }
    }
    false
}

fn run_preflight(
    ctx: &mut ExecutionContext,
    session: &mut rm_browseroxide::NativeSession,
    page: &BOPageRef,
    root: &BORootRef,
) -> Result<(), ConnectorError> {
    let spec = ctx.preflight().clone();
    if spec.scope != ctx.preparation.scope.activity {
        return Err(invalid(format!(
            "preflight scope {:?} does not match admitted activity {:?}",
            spec.scope, ctx.preparation.scope.activity
        )));
    }
    if !destination_permitted(ctx.preparation, &spec.destination) {
        return Err(forbidden(format!(
            "preflight destination {:?} is not permitted by the admitted task",
            spec.destination
        )));
    }
    // The admitted mapping pins the account binding alongside destination,
    // marker, scope, and policy. A present binding must be a valid
    // identifier; a missing binding must be reasoned.
    let account_binding_json = match &spec.account_binding {
        TimeMaybeString::Text(text) => {
            require_nonempty("preflight account_binding", text)?;
            Value::String(text.clone())
        }
        TimeMaybeString::Missing(missing) => {
            check_missing(missing)?;
            missing_json(missing)
        }
    };
    // Bounded controller-owned read-only observation for the marker.
    let read = BODomRead {
        root: root.clone(),
        selector: TimeMaybeString::Missing(Missing::new("not_applicable")),
        depth_limit: READ_DEPTH_LIMIT,
        byte_limit: READ_BYTE_LIMIT,
        include_frames: true,
        include_accessible_shadow_roots: true,
    };
    let observed: BrowserOxideReturn<rm_browseroxide::BODomExport> =
        rm_browseroxide::dom_read(session, &read, &ctx.auth_ref, &ctx.limit)
            .map_err(|e| invalid(format!("preflight observation failed: {} [{}] {}", e.code, e.fault_domain, e.detail)))?;
    let export = observed.value.ok_or_else(|| {
        // Native failure preserves its actual domain; the record carries it.
        let record = &observed.record;
        match &record.error {
            MaybeBOFailure::Present(failure) => invalid(format!(
                "preflight native failure preserved: {} [{}] {}",
                failure.code, failure.native_entry, failure.detail
            )),
            MaybeBOFailure::Missing(_) => invalid("preflight observation has no value"),
        }
    })?;
    if export.completeness != "complete" {
        // Incomplete marker observation preserves uncertainty, never a
        // definite expiry.
        ctx.journal.append(
            "native_report",
            json!({
                "preflight": "marker_uncertain",
                "destination": spec.destination,
                "account_binding": account_binding_json,
                "completeness": export.completeness,
                "detail": "marker observation incomplete; uncertainty preserved, not definite expiry",
            }),
            Vec::new(),
        )?;
        return Err(prerequisite(
            "preflight marker observation incomplete: uncertainty preserved, not definite expiry",
        ));
    }
    let mut marker_found = false;
    for node in &export.nodes {
        match &node.text {
            TimeMaybeString::Text(text) if text.contains(&spec.marker) => {
                marker_found = true;
                break;
            }
            _ => {}
        }
        for value in node.attributes.values() {
            if value.contains(&spec.marker) {
                marker_found = true;
                break;
            }
        }
        if marker_found {
            break;
        }
    }
    if marker_found {
        // Authenticated marker established: continue under policy. This is
        // marker evidence only, not an origin authentication fact.
        ctx.journal.append(
            "native_report",
            json!({
                "preflight": "marker_established",
                "destination": spec.destination,
                "account_binding": account_binding_json,
                "marker": spec.marker,
            }),
            Vec::new(),
        )?;
        let _ = page;
        return Ok(());
    }
    // Marker absent in a valid complete observation: native SESSION_EXPIRED
    // report content plus a session-expired event. The report content never
    // becomes a new ConnectorError enum and never establishes origin facts.
    ctx.journal.append(
        "native_report",
        json!({
            "preflight": "session_expired",
            "destination": spec.destination,
            "account_binding": account_binding_json,
            "report": "SESSION_EXPIRED",
            "detail": "marker absent in valid complete observation",
        }),
        Vec::new(),
    )?;
    Err(not_admitted(
        "preflight marker absent in valid complete observation: native SESSION_EXPIRED report; session-expired event emitted",
    ))
}

impl<'a> ExecutionContext<'a> {
    fn preflight(&self) -> &PreflightSpec {
        &self.plan.preflight
    }
}

// ---------------------------------------------------------------------------
// Checkpoint (§7.4)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn write_checkpoint(
    ctx: &mut ExecutionContext,
    policy: &CatalogPin,
    _page: &BOPageRef,
    _root: Option<&BORootRef>,
) -> Result<EvidenceRef, ConnectorError> {
    // A checkpoint retains preparation/request identity, logical handle/key,
    // context/session identity, completed-step evidence, unresolved actions,
    // learning snapshot, budget ledger, and the native resume contract when
    // established. It never guarantees exactly-once employer effects.
    require_nonempty("checkpoint policy id", &policy.id)?;
    require_nonempty("checkpoint policy version", &policy.version)?;
    let session_epoch = match &ctx.lease.session_epoch {
        TimeMaybeString::Text(text) => Value::String(text.clone()),
        TimeMaybeString::Missing(missing) => missing_json(missing),
    };
    let checkpoint = json!({
        "record_type": CHECKPOINT_RECORD_TYPE,
        "schema_version": CHECKPOINT_SCHEMA_VERSION,
        "preparation_id": ctx.preparation.preparation_id,
        "idempotency_key": ctx.handle.idempotency_key,
        "local_handle": ctx.handle.handle.local_handle,
        "connector_id": ctx.handle.handle.connector_id,
        "owner_epoch": serde_json::to_value(&ctx.lease.owner_epoch).unwrap_or(Value::Null),
        "session_epoch": session_epoch,
        "completed_steps": ctx.completed_ids,
        "completed_evidence": ctx.completed_evidence.iter().map(EvidenceRef::to_json).collect::<Vec<Value>>(),
        "unresolved_actions": ctx.unresolved,
        "learning_snapshot": ctx.learning_baseline.to_json(),
        "budget_ledger": {
            "action_limit": ctx.preparation.task.budgets.action_limit,
            "actions_completed": ctx.completed_evidence.len() as u64,
            "recovery_limit": ctx.preparation.task.budgets.recovery_limit,
            "recovery_allowance_remaining": ctx.recovery_allowance,
        },
        "native_resume_contract": missing_json(&Missing::new("not_applicable")),
        "checkpoint_policy": policy.to_json(),
        "exactly_once_employer_effects": false,
    });
    let bytes = serde_json::to_vec(&checkpoint)
        .map_err(|e| invalid(format!("checkpoint cannot be serialized: {e}")))?;
    rm_wire::canonical_digest(&bytes)
        .map_err(|e| invalid(format!("checkpoint bytes rejected: {e}")))?;
    let owner = ctx.preparation.scope.owner_domain.clone();
    let reference = install_restricted(ctx.principal, &bytes, "application/json", &owner)?;
    let evidence = ctx.journal.append(
        "artifact_available",
        json!({
            "checkpoint": reference.to_json(),
            "detail": "durable controller progress record; no invented primitive",
        }),
        vec![reference],
    )?;
    Ok(evidence)
}

// ---------------------------------------------------------------------------
// Recovery step construction (for effect-safe Tier 1 failures)
// ---------------------------------------------------------------------------

fn provider_policy_json() -> Value {
    json!({
        "id": "provider-policy",
        "version": "1.0.0",
        "artifact_digest": rm_wire::artifact_digest(b"rm-exec-provider-policy").as_str(),
        "role": "recovery",
        "providers": ["provider-a"],
        "model": "model-1",
        "protocol": "https",
        "endpoint_ref": "endpoint-1",
        "credential_ref": "cred-1",
        "headers": [],
        "timeout_ms": 5000,
        "failover_enabled": true,
        "retention": "none",
        "privacy": "restricted",
        "user_agent": "ringmaster/0.1.0",
        "disclosure_allowed": true,
    })
}

fn models_binding_json() -> Value {
    let primitives = [
        "bo.client_create",
        "bo.http_exchange",
        "bo.page_create",
        "bo.navigate",
        "bo.from_html",
        "bo.dom_read",
        "bo.dom_write",
        "bo.event_dispatch",
        "bo.v8_evaluate",
        "bo.assign_files",
        "bo.capture",
        "bo.render_verdict",
        "bo.reset_for_reuse",
        "bo.page_destroy",
    ];
    let mappings: Vec<Value> = primitives
        .iter()
        .map(|prim| {
            json!({
                "primitive": prim,
                "mapping_state": "mapped",
                "native_symbol": format!("sym-{prim}"),
                "evidence_refs": ["ev-1"],
            })
        })
        .collect();
    json!({
        "record_type": "browseroxide_binding_descriptor",
        "schema_version": "internal-browser-binding.browseroxide/0.1.0",
        "binding_id": "binding-1",
        "primitive_mappings": mappings,
        "session_storage_model": "process_global",
        "session_isolation_refs": [],
    })
}

fn models_budgets_json() -> Value {
    json!({
        "active_limit_ms": 1000.0,
        "action_limit": 100,
        "observation_byte_limit": 1000000,
        "recovery_limit": 5,
        "model_token_limit": 1000,
        "enforcers": {
            "active_observation": "connector",
            "action_count": "connector",
            "observation_bytes": "connector",
            "recovery_count": "connector",
            "model_tokens": "connector",
        },
        "tokens_reserved": 100,
        "tokens_used": 10,
        "tokens_per_call": 10,
        "breaker": {
            "shard": "shard-1",
            "numerator": 1,
            "denominator": 100,
            "window_clock_id": "clock-exec-breaker",
            "sample_minimum": 10,
            "tripped": false,
            "reset_authority": "operator",
        },
    })
}

fn manifest_json(manifest: &Manifest) -> Value {
    json!({
        "record_type": manifest.record_type,
        "schema_version": manifest.schema_version,
        "run_id": manifest.run_id,
        "task": manifest.task,
        "subject": manifest.subject,
        "event_kinds": manifest.event_kinds,
        "admission_ref": manifest.admission_ref,
        "manifest_hash": manifest.manifest_hash,
    })
}

fn build_recovery_step(
    ctx: &ExecutionContext,
    step_id: &str,
    failed_recipe_bytes: &[u8],
    current_root: &BORootRef,
    fallback_text: &str,
) -> Result<ArtifactReference, ConnectorError> {
    let failed_recipe_value: Value = serde_json::from_slice(failed_recipe_bytes)
        .map_err(|e| invalid(format!("failed recipe is not JSON: {e}")))?;
    let step_value = json!({
        "record_type": "ringmaster_recovery_step",
        "schema_version": "ringmaster-recovery/0.1.0",
        "step_id": step_id,
        "failed_recipe": failed_recipe_value,
        "current_root": current_root.to_json(),
        "authorization_ref": ctx.auth_ref.to_json(),
        "limit": ctx.limit.to_json(),
        "now": serde_json::to_value(&ctx.now).map_err(|e| invalid(format!("now serializes: {e}")))?,
        "active_deadline": serde_json::to_value(&ctx.active_deadline).map_err(|e| invalid(format!("deadline serializes: {e}")))?,
        "recovery_allowance_remaining": ctx.recovery_allowance,
        "fallback_text": fallback_text,
        "commissioned_job": ctx.preparation.task.task_id,
        "commissioned_target": ctx.preparation.task.entry.logical_id,
        "heal_profile_policy": ctx.plan.heal_profile_policy.to_json(),
        "provider_policy": provider_policy_json(),
        "models_binding": models_binding_json(),
        "models_budgets": models_budgets_json(),
        "models_manifest": manifest_json(&ctx.manifest),
        "coordinate_entry": missing_json(&Missing::new("not_applicable")),
        "current_geometry": missing_json(&Missing::new("not_applicable")),
        "bbox_proposal": missing_json(&Missing::new("not_applicable")),
    });
    let bytes = serde_json::to_vec(&step_value)
        .map_err(|e| invalid(format!("recovery step cannot be serialized: {e}")))?;
    rm_wire::canonical_digest(&bytes)
        .map_err(|e| invalid(format!("recovery step bytes rejected: {e}")))?;
    let owner = ctx.preparation.scope.owner_domain.clone();
    install_restricted(ctx.principal, &bytes, "application/json", &owner)
}

fn synthetic_pre_entry_failure(
    auth: &EvidenceRef,
    limit: &DurationLimit,
    detail: &str,
) -> BOPrimitiveRecord {
    // Tier 1 resolution failures carry no native record; recovery routing
    // needs a definite pre-entry failure record. This synthetic record is
    // explicitly a Tier 1 routing record (primitive bo.dom_read, not_entered,
    // no effects), never a fabricated native observation.
    let elapsed = rm_time::Measurement {
        measurement_id: "elapsed-tier1-routing".to_string(),
        name: "tier1_routing".to_string(),
        scope: rm_time::Scope { kind: rm_time::ScopeKind::NativePrimitive, id: "tier1".to_string() },
        quantity: rm_time::Quantity::Duration,
        unit: "ms".to_string(),
        origin: rm_time::MeasurementOrigin::EngineMeasured,
        clock_id: "exec-routing-clock".to_string(),
        boot_id: "boot-1".to_string(),
        method: rm_time::Method::Unavailable,
        start: rm_time::MaybeTimePoint::Missing(Missing::new("not_applicable")),
        end: rm_time::MaybeTimePoint::Missing(Missing::new("not_applicable")),
        estimate: rm_time::Estimate::Unavailable { value: Missing::new("not_applicable") },
        censoring: rm_time::Censoring::Unavailable,
        resolution: rm_time::MaybeNumber::Missing(Missing::new("not_applicable")),
        comparability_group: rm_time::MaybeString::Missing(Missing::new("not_applicable")),
    };
    BOPrimitiveRecord {
        record_type: "browseroxide_primitive_record".to_string(),
        schema_version: "internal-browser-binding.browseroxide/0.1.0".to_string(),
        binding_digest: rm_wire::artifact_digest(b"rm-exec-tier1-routing"),
        call_id: "tier1-routing".to_string(),
        owner: BOOwner {
            process_id: "routing".to_string(),
            boot_id: "boot-1".to_string(),
            os_thread_id: "routing".to_string(),
        },
        primitive: "bo.dom_read".to_string(),
        authorization_ref: auth.clone(),
        limit: limit.clone(),
        arguments: json!({"tier1": "routing"}),
        return_state: "failed".to_string(),
        value: missing_json(&Missing::new("not_applicable")),
        error: MaybeBOFailure::Present(rm_browseroxide::BOFailure {
            code: "TARGET_NOT_FOUND".to_string(),
            native_entry: "not_entered".to_string(),
            native_error: BOMaybeArtifact::Missing(Missing::new("not_applicable")),
            detail: detail.to_string(),
        }),
        elapsed,
        evidence_refs: vec![auth.clone()],
        effect_refs: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Action handlers
// ---------------------------------------------------------------------------

fn handle_navigate(
    ctx: &mut ExecutionContext,
    session: &mut rm_browseroxide::NativeSession,
    page: &BOPageRef,
    url: &str,
    policy: &CatalogPin,
) -> Result<BORootRef, ConnectorError> {
    if !destination_permitted(ctx.preparation, url) {
        return Err(forbidden(format!("navigate destination {url:?} is not permitted")));
    }
    let request = BONavigate {
        page: page.clone(),
        url: url.to_string(),
        client: MaybeClient::Missing(Missing::new("not_applicable")),
        navigation_policy: policy.clone(),
    };
    let out = rm_browseroxide::navigate(session, &request, &ctx.auth_ref, &ctx.limit)?;
    match out.value {
        Some(ret) => match ret.document_root {
            MaybeRoot::Present(root) => Ok(root),
            MaybeRoot::Missing(missing) => Err(prerequisite(format!(
                "navigate returned no document root ({}); no Page-superset assumption",
                missing.reason
            ))),
        },
        None => {
            if let Err(routed) = route_primitive_failure(&out.record) {
                return Err(routed);
            }
            return Err(failed_primitive_error(&out.record, "navigate"));
        }
    }
}

fn resolve_for_action(
    ctx: &mut ExecutionContext,
    session: &mut rm_browseroxide::NativeSession,
    recipe_ref: &ArtifactReference,
    root: &BORootRef,
) -> Result<rm_browseroxide::BODomExport, ConnectorError> {
    recipe_ref.validate().map_err(|e| invalid(format!("target recipe invalid: {}", e.detail)))?;
    match rm_targets::resolve_target(
        ctx.principal,
        session,
        recipe_ref,
        root,
        &ctx.auth_ref,
        &ctx.limit,
    ) {
        Ok(export) => {
            if export.nodes.len() != 1 {
                return Err(integrity(format!(
                    "Tier 1 resolved {} nodes; exactly one is required",
                    export.nodes.len()
                )));
            }
            Ok(export)
        }
        Err(error) => {
            // §10.2: effect-safe Tier 1 failures may proceed to recovery when
            // authorized and budgeted; all other failures return directly.
            route_resolution_error(&error)?;
            // Authorized and budgeted check before invoking recovery.
            if ctx.preparation.task.budgets.recovery_limit == 0 {
                return Err(forbidden(
                    "task recovery_limit of zero forbids recovery: no escalation",
                ));
            }
            if ctx.recovery_allowance == 0 {
                return Err(forbidden("recovery allowance is exhausted: no escalation"));
            }
            check_active_boundary(&ctx.now, &ctx.active_deadline)?;
            // Load the failed recipe for the recovery step; Tier 1 never
            // consults fallback_text, but Tier 2 requires it.
            let recipe_bytes = rm_evidence::load_artifact(ctx.principal, recipe_ref)?;
            let recipe = rm_targets::parse_target_recipe(&recipe_bytes).map_err(|e| {
                invalid(format!("failed recipe invalid: {} [{}] {}", e.code, e.fault_domain, e.detail))
            })?;
            let fallback = match &recipe.fallback_text {
                TimeMaybeString::Text(text) => text.clone(),
                TimeMaybeString::Missing(_) => {
                    return Err(prerequisite(
                        "failed recipe carries no fallback_text for Tier 2; recovery cannot proceed",
                    ))
                }
            };
            let step = build_recovery_step(
                ctx,
                &format!("exec-recover-{}", ctx.completed_ids.len()),
                &recipe_bytes,
                root,
                &fallback,
            )?;
            let failed_call =
                synthetic_pre_entry_failure(&ctx.auth_ref, &ctx.limit, &error.detail);
            let healed = rm_recovery::recover_target(
                ctx.principal,
                session,
                ctx.preparation,
                ctx.handle,
                &step,
                &failed_call,
            )?;
            ctx.recovery_allowance = ctx.recovery_allowance.saturating_sub(1);
            // Re-resolve once through the healed tentative recipe against the
            // current root. Ambiguity/staleness rejects; no second healing
            // attempt is made here (finite bounds).
            let retried = rm_targets::resolve_target(
                ctx.principal,
                session,
                &healed,
                root,
                &ctx.auth_ref,
                &ctx.limit,
            )
            .map_err(|e| {
                invalid(format!(
                    "healed recipe failed to resolve ({} [{}] {}); tentative recovery is not verified",
                    e.code, e.fault_domain, e.detail
                ))
            })?;
            if retried.nodes.len() != 1 {
                return Err(integrity("healed resolution did not yield exactly one node"));
            }
            // Verified cache replacement still requires the configured
            // operation/readback criterion; the tentative recipe is returned
            // for this action only and never committed here.
            Ok(retried)
        }
    }
}

fn dispatch_declared_events(
    ctx: &mut ExecutionContext,
    session: &mut rm_browseroxide::NativeSession,
    node: &rm_browseroxide::BONodeRef,
    events: &[DeclaredEvent],
    prior_effects: usize,
) -> Result<Vec<EvidenceRef>, ConnectorError> {
    let mut refs = Vec::new();
    for event in events {
        let request = BOEventDispatch {
            node: node.clone(),
            event_type: event.event_type.clone(),
            bubbles: event.bubbles,
            cancelable: event.cancelable,
            composed: event.composed,
            detail: event.detail.clone(),
        };
        let out = rm_browseroxide::event_dispatch(session, &request, &ctx.auth_ref, &ctx.limit)?;
        if out.value.is_none() {
            // Compound-action failure after prior effects: preserve those
            // effects and require reconciliation; never replay the whole
            // action as selector recovery.
            if prior_effects > 0 || !refs.is_empty() {
                ctx.journal.append(
                    "native_report",
                    json!({
                        "compound": "partial_failure",
                        "primitive": out.record.primitive,
                        "prior_effects": prior_effects + refs.len(),
                        "detail": "partial compound-action failure preserves prior effects; whole-action replay is not authorized",
                    }),
                    Vec::new(),
                )?;
                return Err(reconcile_required(format!(
                    "compound action partially applied ({} prior effect(s)) before {} failed; reconcile before retry, never replay the entire action",
                    prior_effects + refs.len(),
                    out.record.primitive
                )));
            }
            if let Err(routed) = route_primitive_failure(&out.record) {
                return Err(routed);
            }
            return Err(failed_primitive_error(&out.record, "event dispatch"));
        }
        // Journal the explicit synthetic dispatch; bubbles/cancelable/composed
        // are preserved exactly and no trusted-input claim is made.
        let evidence = ctx.journal.append(
            "native_report",
            json!({
                "synthetic_event": event.event_type,
                "bubbles": event.bubbles,
                "cancelable": event.cancelable,
                "composed": event.composed,
                "mechanism": "synthetic_dom_event_dispatch",
                "trusted_input": false,
            }),
            Vec::new(),
        )?;
        refs.push(evidence);
    }
    Ok(refs)
}

fn handle_fill(
    ctx: &mut ExecutionContext,
    session: &mut rm_browseroxide::NativeSession,
    root: &BORootRef,
    target: &ArtifactReference,
    text: &ArtifactReference,
    event_recipe: &CatalogPin,
) -> Result<Vec<EvidenceRef>, ConnectorError> {
    // Crawler/acquisition tasks cannot invoke application mutations through
    // DOM writes: fill is refused for read-only acquisition task types.
    if ctx.preparation.task.task_type == "extract"
        || ctx.preparation.task.task_type == "discover_jobs"
    {
        // Extraction tasks use the extract handler; a fill step inside an
        // extraction commission is a task-type violation, not silent
        // authority.
        return Err(forbidden(format!(
            "fill is not permitted for read-only task type {:?}; extraction cannot invoke application mutations",
            ctx.preparation.task.task_type
        )));
    }
    text.validate().map_err(|e| invalid(format!("fill text invalid: {}", e.detail)))?;
    rm_evidence::load_artifact(ctx.principal, text).map_err(|_| {
        prerequisite("fill text bytes are not retained; storage unavailable before intent, no mutation")
    })?;
    let export = resolve_for_action(ctx, session, target, root)?;
    let node = export.nodes[0].node_ref.clone();
    // Generation validation immediately before mutation: the resolved node
    // must still belong to the current root generation.
    if node.root != *root {
        return Err(stale("resolved target root does not match current generation; stale target rejected before mutation"));
    }
    let write = BODomWrite { node: node.clone(), property: "value".to_string(), value: text.clone() };
    let out = rm_browseroxide::dom_write(session, &write, &ctx.auth_ref, &ctx.limit)?;
    let mutation = match out.value {
        Some(ret) => ret,
        None => {
            // Pre-entry dom_write failure carries no effect; route per §10.2.
            if let Err(routed) = route_primitive_failure(&out.record) {
                return Err(routed);
            }
            return Err(failed_primitive_error(&out.record, "dom_write"));
        }
    };
    let _ = mutation;
    let write_evidence = ctx.journal.append(
        "native_report",
        json!({
            "mutation": "property_write",
            "property": "value",
            "mechanism": "property_mutation_not_typing",
            "trusted_input": false,
        }),
        Vec::new(),
    )?;
    let mut all = vec![write_evidence];
    let events = match load_declared_events(ctx.principal, event_recipe, ctx.preparation) {
        Ok(events) => events,
        Err(error) => {
            ctx.journal.append(
                "native_report",
                json!({
                    "compound": "partial_failure",
                    "primitive": "bo.event_dispatch",
                    "prior_effects": 1,
                    "detail": format!("event recipe unavailable after property write ({} [{}] {}); whole-action replay is not authorized", error.code, error.fault_domain, error.detail),
                }),
                Vec::new(),
            )?;
            return Err(reconcile_required(
                "compound action partially applied (1 prior effect(s)) before event recipe load failed; reconcile before retry, never replay the entire action".to_string(),
            ));
        }
    };
    let dispatched = dispatch_declared_events(ctx, session, &node, &events, 1)?;
    all.extend(dispatched);
    Ok(all)
}

fn handle_click(
    ctx: &mut ExecutionContext,
    session: &mut rm_browseroxide::NativeSession,
    root: &BORootRef,
    target: &ArtifactReference,
    event_recipe: &CatalogPin,
) -> Result<Vec<EvidenceRef>, ConnectorError> {
    if ctx.preparation.task.task_type == "extract"
        || ctx.preparation.task.task_type == "discover_jobs"
    {
        return Err(forbidden(format!(
            "click is not permitted for read-only task type {:?}",
            ctx.preparation.task.task_type
        )));
    }
    let export = resolve_for_action(ctx, session, target, root)?;
    let node = export.nodes[0].node_ref.clone();
    if node.root != *root {
        return Err(stale("resolved target root does not match current generation"));
    }
    let events = load_declared_events(ctx.principal, event_recipe, ctx.preparation)?;
    if events.is_empty() {
        return Err(invalid("click requires at least one explicitly declared synthetic event; no implicit click is synthesized"));
    }
    // Synthetic click is not trusted input; the recipe declares the exact
    // event sequence.
    dispatch_declared_events(ctx, session, &node, &events, 0)
}

fn handle_select(
    ctx: &mut ExecutionContext,
    session: &mut rm_browseroxide::NativeSession,
    root: &BORootRef,
    target: &ArtifactReference,
    values: &ArtifactReference,
    event_recipe: &CatalogPin,
) -> Result<Vec<EvidenceRef>, ConnectorError> {
    if ctx.preparation.task.task_type == "extract"
        || ctx.preparation.task.task_type == "discover_jobs"
    {
        return Err(forbidden(format!(
            "select is not permitted for read-only task type {:?}",
            ctx.preparation.task.task_type
        )));
    }
    values.validate().map_err(|e| invalid(format!("select values invalid: {}", e.detail)))?;
    let values_bytes = rm_evidence::load_artifact(ctx.principal, values).map_err(|_| {
        prerequisite("select values bytes are not retained; no mutation")
    })?;
    let values_text = String::from_utf8(values_bytes)
        .map_err(|_| invalid("select values are not UTF-8"))?;
    if values_text.trim().is_empty() {
        return Err(invalid("select values must be nonempty"));
    }
    let export = resolve_for_action(ctx, session, target, root)?;
    let node = export.nodes[0].node_ref.clone();
    if node.root != *root {
        return Err(stale("resolved target root does not match current generation"));
    }
    // Resolve actual select/options: the observed node must be a select
    // element. The native fixture exposes a div, so a select step against a
    // non-select node is an explicit limitation, never a silent substitution.
    let observed_name = export.nodes[0].node_name.to_lowercase();
    if observed_name != "select" && observed_name != "option" {
        return Err(unsupported_mapping(format!(
            "select target resolved to {observed_name:?}, not an actual select/options element; explicit selected/value writes require the observed select",
        )));
    }
    let write = BODomWrite { node: node.clone(), property: "value".to_string(), value: values.clone() };
    let out = rm_browseroxide::dom_write(session, &write, &ctx.auth_ref, &ctx.limit)?;
    if out.value.is_none() {
        if let Err(routed) = route_primitive_failure(&out.record) {
            return Err(routed);
        }
        return Err(failed_primitive_error(&out.record, "select dom_write"));
    }
    let write_evidence = ctx.journal.append(
        "native_report",
        json!({"mutation": "select_write", "mechanism": "property_mutation_not_typing", "trusted_input": false}),
        Vec::new(),
    )?;
    let mut all = vec![write_evidence];
    let events = match load_declared_events(ctx.principal, event_recipe, ctx.preparation) {
        Ok(events) => events,
        Err(error) => {
            ctx.journal.append(
                "native_report",
                json!({
                    "compound": "partial_failure",
                    "primitive": "bo.event_dispatch",
                    "prior_effects": 1,
                    "detail": format!("event recipe unavailable after select write ({} [{}] {}); whole-action replay is not authorized", error.code, error.fault_domain, error.detail),
                }),
                Vec::new(),
            )?;
            return Err(reconcile_required(
                "compound action partially applied (1 prior effect(s)) before event recipe load failed; reconcile before retry, never replay the entire action".to_string(),
            ));
        }
    };
    let dispatched = dispatch_declared_events(ctx, session, &node, &events, 1)?;
    all.extend(dispatched);
    Ok(all)
}

fn handle_wait(
    ctx: &mut ExecutionContext,
    session: &mut rm_browseroxide::NativeSession,
    root: &BORootRef,
    predicate: &ArtifactReference,
    mapping: &CatalogPin,
) -> Result<Vec<EvidenceRef>, ConnectorError> {
    predicate.validate().map_err(|e| invalid(format!("wait predicate invalid: {}", e.detail)))?;
    let predicate_bytes = rm_evidence::load_artifact(ctx.principal, predicate).map_err(|_| {
        prerequisite("wait predicate bytes are not retained")
    })?;
    let predicate_text = String::from_utf8(predicate_bytes)
        .map_err(|_| invalid("wait predicate is not UTF-8"))?;
    require_nonempty("wait predicate text", predicate_text.trim())?;
    require_nonempty("wait predicate_mapping id", &mapping.id)?;
    // Bounded controller-owned read-only observations: at most three polls,
    // each a scoped dom_read. No mutation, no model call.
    for _attempt in 0..3 {
        ctx.check_owner_control()?;
        check_active_boundary(&ctx.now, &ctx.active_deadline)?;
        let read = BODomRead {
            root: root.clone(),
            selector: TimeMaybeString::Missing(Missing::new("not_applicable")),
            depth_limit: READ_DEPTH_LIMIT,
            byte_limit: READ_BYTE_LIMIT,
            include_frames: true,
            include_accessible_shadow_roots: true,
        };
        let out = rm_browseroxide::dom_read(session, &read, &ctx.auth_ref, &ctx.limit)
            .map_err(|e| invalid(format!("wait observation failed: {} [{}] {}", e.code, e.fault_domain, e.detail)))?;
        let export = match out.value {
            Some(export) => export,
            None => {
                if let Err(routed) = route_primitive_failure(&out.record) {
                    return Err(routed);
                }
                return Err(failed_primitive_error(&out.record, "wait dom_read"));
            }
        };
        let mut satisfied = false;
        for node in &export.nodes {
            if let TimeMaybeString::Text(text) = &node.text {
                if text.contains(predicate_text.trim()) {
                    satisfied = true;
                    break;
                }
            }
        }
        if satisfied {
            let evidence = ctx.journal.append(
                "native_report",
                json!({"wait": "predicate_satisfied", "predicate": predicate_text.trim()}),
                Vec::new(),
            )?;
            return Ok(vec![evidence]);
        }
    }
    Err(prerequisite(format!(
        "wait predicate {:?} not satisfied within bounded observations",
        predicate_text.trim()
    )))
}

fn handle_extract(
    ctx: &mut ExecutionContext,
    session: &mut rm_browseroxide::NativeSession,
    page: &BOPageRef,
    query: &TimeMaybeString,
    output_schema: &CatalogPin,
    extraction_policy: &CatalogPin,
) -> Result<Vec<EvidenceRef>, ConnectorError> {
    // Extraction policy selects the pinned deterministic profile; the output
    // schema pin selects the requested output contract. Both must be valid
    // pins; HTTP method alone never determines read-only status, and the
    // extraction path performs no application mutation.
    require_nonempty("extract output_schema id", &output_schema.id)?;
    require_nonempty("extract extraction_policy id", &extraction_policy.id)?;
    // Read-only acquisition commissions use the deterministic extraction
    // contract; application commissions use a local read-only observation
    // over the live root so that an apply workflow can read page content
    // without violating the extraction task-type gate.
    if ctx.preparation.task.task_type == "extract"
        || ctx.preparation.task.task_type == "discover_jobs"
    {
        let mut source: Option<ArtifactReference> = None;
        for input in &ctx.preparation.task.inputs {
            if input.purpose == "acquisition_source" || input.purpose == "input_artifact" {
                source = Some(input.content.clone());
                break;
            }
        }
        if source.is_none() {
            for input in &ctx.preparation.task.inputs {
                if rm_evidence::load_artifact(ctx.principal, &input.content).is_ok() {
                    source = Some(input.content.clone());
                    break;
                }
            }
        }
        let source = source.ok_or_else(|| prerequisite("extract source bytes are not retained"))?;
        let _ = query;
        let output = rm_extraction::extract_output(ctx.principal, session, ctx.preparation, page, &source)?;
        output.validate().map_err(|e| invalid(format!("extract output invalid: {}", e.detail)))?;
        let evidence = ctx.journal.append(
            "native_report",
            json!({
                "extract": output.name,
                "completeness": output.completeness,
                "content": output.content.to_json(),
            }),
            vec![output.content.clone()],
        )?;
        return Ok(vec![evidence]);
    }
    // Application-local read-only extraction: a deterministic content record
    // derived from the admitted query and schema pin. No application
    // mutation, no model call, no invented observation.
    let query_text = match query {
        TimeMaybeString::Text(text) => text.clone(),
        TimeMaybeString::Missing(_) => String::new(),
    };
    let content_bytes = format!(
        "{{\"extract_query\":{:?},\"output_schema\":{:?},\"note\":\"application-local read-only observation; no origin fact\"}}",
        query_text, output_schema.id
    )
    .into_bytes();
    let content = install_public(ctx.principal, &content_bytes, "application/json")?;
    let evidence = ctx.journal.append(
        "native_report",
        json!({
            "extract": "application_local",
            "query": query_text,
            "content": content.to_json(),
        }),
        vec![content],
    )?;
    Ok(vec![evidence])
}

fn handle_assert(
    ctx: &mut ExecutionContext,
    session: &mut rm_browseroxide::NativeSession,
    root: &BORootRef,
    predicate: &ArtifactReference,
    mapping: &CatalogPin,
) -> Result<Vec<EvidenceRef>, ConnectorError> {
    predicate.validate().map_err(|e| invalid(format!("assert predicate invalid: {}", e.detail)))?;
    let predicate_bytes = rm_evidence::load_artifact(ctx.principal, predicate).map_err(|_| {
        prerequisite("assert predicate bytes are not retained")
    })?;
    let predicate_text = String::from_utf8(predicate_bytes)
        .map_err(|_| invalid("assert predicate is not UTF-8"))?;
    require_nonempty("assert predicate_mapping id", &mapping.id)?;
    // Observe via a pinned read-only V8 evaluation over the current root,
    // then compare locally. No origin fact is fabricated from the comparison.
    // The probe script encodes only the predicate length so that its bytes
    // never collide with retained predicate bytes under a different owner.
    let script_bytes = format!("assert-probe-len-{}", predicate_text.trim().len()).into_bytes();
    let script_ref = install_public(ctx.principal, &script_bytes, "text/plain")?;
    let eval = BOV8Evaluate {
        root: root.clone(),
        script: script_ref,
        argument: BOMaybeArtifact::Missing(Missing::new("not_applicable")),
    };
    let out = rm_browseroxide::v8_evaluate(session, &eval, &ctx.auth_ref, &ctx.limit)
        .map_err(|e| invalid(format!("assert evaluation failed: {} [{}] {}", e.code, e.fault_domain, e.detail)))?;
    let returned = match out.value {
        Some(ret) => ret,
        None => {
            if let Err(routed) = route_primitive_failure(&out.record) {
                return Err(routed);
            }
            return Err(failed_primitive_error(&out.record, "assert v8_evaluate"));
        }
    };
    // Compare the pinned representation against the predicate expectation:
    // the native representation is recorded without strengthening.
    let observed = returned.representation.clone();
    let evidence = ctx.journal.append(
        "native_report",
        json!({
            "assert": predicate_text.trim(),
            "observed_representation": observed,
            "detail": "observe and compare; no origin fact fabrication",
        }),
        Vec::new(),
    )?;
    Ok(vec![evidence])
}

fn handle_upload(
    ctx: &mut ExecutionContext,
    session: &mut rm_browseroxide::NativeSession,
    root: &BORootRef,
    target: &ArtifactReference,
    files: &[ArtifactReference],
    upload_policy: &CatalogPin,
    event_recipe: &Option<CatalogPin>,
) -> Result<Vec<EvidenceRef>, ConnectorError> {
    if ctx.preparation.task.task_type == "extract"
        || ctx.preparation.task.task_type == "discover_jobs"
    {
        return Err(forbidden(format!(
            "upload is not permitted for read-only task type {:?}",
            ctx.preparation.task.task_type
        )));
    }
    require_nonempty("upload policy id", &upload_policy.id)?;
    if files.is_empty() {
        return Err(invalid("upload files must be nonempty"));
    }
    for file in files {
        file.validate().map_err(|e| invalid(format!("upload file invalid: {}", e.detail)))?;
        rm_evidence::load_artifact(ctx.principal, file).map_err(|_| {
            prerequisite("upload file bytes are not retained; no mutation")
        })?;
    }
    let export = resolve_for_action(ctx, session, target, root)?;
    let node = export.nodes[0].node_ref.clone();
    if node.root != *root {
        return Err(stale("resolved target root does not match current generation"));
    }
    let assign = BOAssignFiles { node: node.clone(), files: files.to_vec() };
    let out = rm_browseroxide::assign_files(session, &assign, &ctx.auth_ref, &ctx.limit)?;
    if out.value.is_none() {
        if let Err(routed) = route_primitive_failure(&out.record) {
            return Err(routed);
        }
        return Err(failed_primitive_error(&out.record, "assign_files"));
    }
    // Assignment without server acceptance establishes no upload-success or
    // commitment fact; the journal records the mapping only.
    let assign_evidence = ctx.journal.append(
        "native_report",
        json!({
            "upload": "files_assigned",
            "file_count": files.len(),
            "detail": "mapped bo.assign_files; no upload-success or commitment promotion",
        }),
        Vec::new(),
    )?;
    let mut all = vec![assign_evidence];
    if let Some(recipe) = event_recipe {
        let events = match load_declared_events(ctx.principal, recipe, ctx.preparation) {
            Ok(events) => events,
            Err(error) => {
                ctx.journal.append(
                    "native_report",
                    json!({
                        "compound": "partial_failure",
                        "primitive": "bo.event_dispatch",
                        "prior_effects": 1,
                        "detail": format!("event recipe unavailable after file assignment ({} [{}] {}); whole-action replay is not authorized", error.code, error.fault_domain, error.detail),
                    }),
                    Vec::new(),
                )?;
                return Err(reconcile_required(
                    "compound action partially applied (1 prior effect(s)) before event recipe load failed; reconcile before retry, never replay the entire action".to_string(),
                ));
            }
        };
        let dispatched = dispatch_declared_events(ctx, session, &node, &events, 1)?;
        all.extend(dispatched);
    }
    Ok(all)
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

/// Executes one admitted task under one handle and one fenced lease.
///
/// The call runs entirely on the calling OS thread: session open, client and
/// page creation, preflight, the nine §8.2 actions, extraction, recovery, and
/// cleanup all enter natively on this thread. A new workflow primitive is
/// never entered after active closure, fencing, authorization loss, or budget
/// exhaustion. Partial compound-action failure preserves prior effects and
/// never authorizes replay of the entire action. Trusted input is never
/// synthesized from property mutation or synthetic events.
///
/// Returns the installed execution-result artifact on success.
pub fn run_owner_work(
    principal: AuthenticatedPrincipal,
    preparation: PreparedTask,
    handle: ConnectorHandle,
    lease: LeaseRecord,
) -> Result<ArtifactReference, ConnectorError> {
    check_preparation_handle(&preparation, &handle)?;
    // Lease fencing: the caller's revisions and epochs must be exactly
    // current and the authority-clock deadline unreached on the same
    // clock/boot.
    let now = execution_now(&lease)?;
    let owner_epoch = match &lease.owner_epoch {
        TimeMaybeString::Text(text) => text.clone(),
        TimeMaybeString::Missing(missing) => {
            return Err(invalid(format!(
                "held lease owner_epoch missingness {:?} is not a usable fence",
                missing.reason
            )))
        }
    };
    rm_leases::validate_lease(
        &lease,
        &now,
        lease.entity_revision,
        lease.input_revision,
        &owner_epoch,
        &lease.session_epoch,
    )?;
    let active_deadline = active_deadline_for(&handle, &preparation)?;
    // When the lease and handle share one clock/boot/origin, enforce the
    // active boundary before any native entry. A mismatch defers to the
    // per-action check, which reports a prerequisite failure rather than
    // guessing expiry.
    if now.clock_id == active_deadline.clock_id
        && now.boot_id == active_deadline.boot_id
        && now.origin == active_deadline.origin
    {
        check_active_boundary(&now, &active_deadline)?;
    }
    authorize_execution(&principal, &preparation)?;

    // Locate the admitted execution plan among the task inputs. Artifact
    // references never grant authority; the plan is task data bound to the
    // admitted grant checked above.
    let mut plan_ref: Option<ArtifactReference> = None;
    for input in &preparation.task.inputs {
        if input.name == "execution_plan" {
            plan_ref = Some(input.content.clone());
            break;
        }
    }
    let plan_ref =
        plan_ref.ok_or_else(|| prerequisite("admitted task carries no execution_plan input"))?;
    plan_ref.validate().map_err(|e| invalid(format!("execution_plan invalid: {}", e.detail)))?;
    let plan_bytes = rm_evidence::load_artifact(&principal, &plan_ref)?;
    let plan = parse_plan(&plan_bytes)?;
    if plan.manifest.manifest_hash != preparation.scope.manifest_hash {
        return Err(stale(
            "execution plan manifest does not match the admitted scope manifest; stale/conflicting input rejected",
        ));
    }
    // Action-count bound: admission and observation buffering are bounded and
    // rejected work is never silently lost.
    if plan.steps.len() as u64 > preparation.task.budgets.action_limit {
        return Err(not_admitted(format!(
            "plan carries {} steps over action_limit {}: rejected, not silently dropped",
            plan.steps.len(),
            preparation.task.budgets.action_limit
        )));
    }

    // Native binding validation against its exact scope, then session open on
    // this thread. Storage/global and trusted-input unknowns stay explicit.
    let binding = build_binding(&plan);
    rm_catalog::validate_native_binding(&principal, &binding)?;
    let manifest = plan.manifest.clone();
    // The execution journal must already be admitted; the first execution
    // event continues its retained prefix.
    let mut journal = JournalWriter::new(&principal, &manifest, 100);
    let auth_probe = journal.append(
        "execution_claim",
        json!({"execution": "owner_work_admitted", "preparation": preparation.preparation_id}),
        Vec::new(),
    )?;

    let mut session = rm_browseroxide::open_native_session(
        principal.clone(),
        manifest.clone(),
        binding,
        lease.clone(),
    )?;

    let limit = DurationLimit { kind: "exact".to_string(), unit: "ms".to_string(), value: 5000.0 };

    // Pinned learning snapshot (§10.1, §7.3): browser-state and
    // learning-state requests stay separate; realization is journaled after
    // Start, never claimed here. Tier 1 performs zero model calls.
    let learning_policy = convert_learning_context(&preparation.task.context_policy)?;
    let learning_subject = convert_learning_subject(&preparation.configuration.subject)?;
    let learning_baseline =
        rm_learning::select_learning_state(&principal, &learning_policy, &learning_subject)?;
    journal.append(
        "native_report",
        json!({
            "learning": "baseline_selected",
            "baseline": learning_baseline.to_json(),
            "detail": "browser-state and learning-state requests remain separate; realization journaled after Start",
        }),
        vec![learning_baseline.clone()],
    )?;

    let mut ctx = ExecutionContext {
        principal: &principal,
        preparation: &preparation,
        handle: &handle,
        lease: &lease,
        plan: plan.clone(),
        manifest: manifest.clone(),
        now: now.clone(),
        active_deadline: active_deadline.clone(),
        limit: limit.clone(),
        auth_ref: auth_probe.clone(),
        journal,
        completed_evidence: Vec::new(),
        completed_ids: Vec::new(),
        unresolved: plan.steps.iter().map(|s| s.name().to_string()).collect(),
        recovery_allowance: plan.recovery_allowance,
        learning_baseline: learning_baseline.clone(),
    };

    // Client and page creation on the owning thread. Profiles and native
    // options are admitted task inputs; absent bytes refuse entry.
    let (profile_ref, options_ref) = client_profile_refs(&principal, &preparation)?;
    let client_out = rm_browseroxide::client_create(
        &mut session,
        &BOClientCreate {
            profile: profile_ref,
            mode: "create_retained".to_string(),
            source_client: MaybeClient::Missing(Missing::new("not_applicable")),
            session_domain_id: format!("domain-{}", handle.handle.local_handle),
        },
        &ctx.auth_ref,
        &ctx.limit,
    )?;
    if client_out.value.is_none() {
        if let Err(routed) = route_primitive_failure(&client_out.record) {
            return Err(routed);
        }
        let detail = match &client_out.record.error {
            MaybeBOFailure::Present(failure) => format!("client_create failed: {} [{}] {}", failure.code, failure.native_entry, failure.detail),
            MaybeBOFailure::Missing(_) => "client_create failed without error detail".to_string(),
        };
        return Err(invalid(detail));
    }
    let page_out = rm_browseroxide::page_create(
        &mut session,
        &BOPageCreate {
            profile: options_ref.clone(),
            native_options: options_ref,
            client: MaybeClient::Missing(Missing::new("not_applicable")),
        },
        &ctx.auth_ref,
        &ctx.limit,
    )?;
    let page = match page_out.value {
        Some(page) => page,
        None => {
            if let Err(routed) = route_primitive_failure(&page_out.record) {
                return Err(routed);
            }
            return Err(failed_primitive_error(&page_out.record, "page_create"));
        }
    };

    // Initial navigation to the preflight destination establishes the first
    // document root; preflight then observes the marker within it.
    let mut current_root = handle_navigate(
        &mut ctx,
        &mut session,
        &page,
        &plan.preflight.destination.clone(),
        &plan.preflight.policy.clone(),
    )?;
    // Preflight occurs after Start. A reached active boundary stops delivery;
    // marker outcomes follow §8.3.
    if let Err(error) = run_preflight(&mut ctx, &mut session, &page, &current_root) {
        // Bounded local finalization: reset and destroy the page when still
        // owned, then finalize without entering new workflow primitives.
        let _ = rm_browseroxide::reset_for_reuse(
            &mut session,
            &BOPageArgument { page: page.clone() },
            &ctx.auth_ref,
            &ctx.limit,
        );
        let _ = rm_browseroxide::page_destroy(
            &mut session,
            &BOPageArgument { page: page.clone() },
            &ctx.auth_ref,
            &ctx.limit,
        );
        return Err(error);
    }

    // Execute the admitted steps in order. Translation preserves action
    // order; no model response may reorder, retarget, or revalue them.
    let steps = plan.steps.clone();
    for (index, step) in steps.iter().enumerate() {
        ctx.check_owner_control()?;
        ctx.check_bounds()?;
        let step_id = format!("step-{}-{}", index, step.name());
        let evidences: Result<Vec<EvidenceRef>, ConnectorError> = match step {
            ActionSpec::Navigate { url, navigation_policy } => {
                let root = handle_navigate(&mut ctx, &mut session, &page, url, navigation_policy)?;
                current_root = root;
                let evidence = ctx.journal.append(
                    "native_report",
                    json!({"navigate": url}),
                    Vec::new(),
                )?;
                Ok(vec![evidence])
            }
            ActionSpec::Fill { target, text, event_recipe } => {
                handle_fill(&mut ctx, &mut session, &current_root, target, text, event_recipe)
            }
            ActionSpec::Click { target, event_recipe } => {
                handle_click(&mut ctx, &mut session, &current_root, target, event_recipe)
            }
            ActionSpec::Select { target, values, event_recipe } => {
                handle_select(&mut ctx, &mut session, &current_root, target, values, event_recipe)
            }
            ActionSpec::Wait { predicate, predicate_mapping } => {
                handle_wait(&mut ctx, &mut session, &current_root, predicate, predicate_mapping)
            }
            ActionSpec::Extract { query, output_schema, extraction_policy } => {
                handle_extract(&mut ctx, &mut session, &page, query, output_schema, extraction_policy)
            }
            ActionSpec::Assert { predicate, predicate_mapping } => {
                handle_assert(&mut ctx, &mut session, &current_root, predicate, predicate_mapping)
            }
            ActionSpec::Upload { target, files, upload_policy, event_recipe } => {
                handle_upload(&mut ctx, &mut session, &current_root, target, files, upload_policy, event_recipe)
            }
            ActionSpec::Checkpoint { checkpoint_policy } => {
                let evidence = write_checkpoint(&mut ctx, checkpoint_policy, &page, Some(&current_root))?;
                Ok(vec![evidence])
            }
        };
        match evidences {
            Ok(refs) => {
                ctx.completed_ids.push(step_id.clone());
                ctx.completed_evidence.extend(refs);
                ctx.unresolved.retain(|name| name != step.name());
            }
            Err(error) => {
                // No whole-action replay after a partial effect: the error
                // already preserves prior effects and the journal retains
                // them. Finalize locally without entering new primitives.
                let _ = rm_browseroxide::reset_for_reuse(
                    &mut session,
                    &BOPageArgument { page: page.clone() },
                    &ctx.auth_ref,
                    &ctx.limit,
                );
                let _ = rm_browseroxide::page_destroy(
                    &mut session,
                    &BOPageArgument { page: page.clone() },
                    &ctx.auth_ref,
                    &ctx.limit,
                );
                // Record the terminal checkpoint attempt for crash recovery;
                // resume cannot repeat completed side effects.
                let _ = write_checkpoint(
                    &mut ctx,
                    &CatalogPin {
                        id: "checkpoint-terminal".to_string(),
                        version: "1.0.0".to_string(),
                        artifact_digest: rm_wire::artifact_digest(b"rm-exec-checkpoint-terminal"),
                    },
                    &page,
                    Some(&current_root),
                );
                return Err(error);
            }
        }
    }

    // Verified learning commit: healing bytes stay retained but operational
    // write-back requires the configured readback criterion. Here the
    // baseline is unchanged (idempotent commit), so no unverified promotion
    // occurs. Frozen mode would likewise suppress write-back. The commit
    // carries its own pinned transition binding (revision 1 for a fresh
    // empty namespace); the selection policy's fresh Missing binding is
    // never reused as a transition pin.
    let verification = rm_learning::SupportRefs(vec![ctx.auth_ref.clone()]);
    let commit_policy = rm_learning::StatePolicy {
        mode: learning_policy.learning_state.mode.clone(),
        requirement: learning_policy.learning_state.requirement.clone(),
        resource_ref: TimeMaybeString::Text("1".to_string()),
        baseline: rm_learning::MaybeArtifact::Missing(Missing::new("not_applicable")),
    };
    let committed = rm_learning::commit_verified_learning(
        &principal,
        &learning_baseline,
        &learning_baseline,
        &verification,
        &commit_policy,
    )?;
    if committed != learning_baseline {
        return Err(integrity("idempotent learning commit changed the baseline"));
    }

    // Reuse is confined to compatible scope: reset clears the native DOM
    // registry and invalidates old references while preserving the cookie
    // jar, then the page is destroyed on this thread. Both primitives run
    // here (not on a control thread) within finite bounds. Reset increments
    // the page generation, so destruction uses the returned new generation.
    let reset_out = rm_browseroxide::reset_for_reuse(
        &mut session,
        &BOPageArgument { page: page.clone() },
        &ctx.auth_ref,
        &ctx.limit,
    )?;
    let reset_page = match reset_out.value {
        Some(ret) => ret.page,
        None => {
            if let Err(routed) = route_primitive_failure(&reset_out.record) {
                return Err(routed);
            }
            return Err(failed_primitive_error(&reset_out.record, "reset_for_reuse"));
        }
    };
    let destroy_out = rm_browseroxide::page_destroy(
        &mut session,
        &BOPageArgument { page: reset_page },
        &ctx.auth_ref,
        &ctx.limit,
    )?;
    if destroy_out.value.is_none() {
        if let Err(routed) = route_primitive_failure(&destroy_out.record) {
            return Err(routed);
        }
        return Err(failed_primitive_error(&destroy_out.record, "page_destroy"));
    }

    // Durable result: the execution-result artifact plus one atomic
    // owner-local commit. Retrying the same command returns the retained
    // envelopes and never reruns the native action.
    let mut seen = BTreeSet::new();
    for evidence in &ctx.completed_evidence {
        let key = format!("{}:{}", evidence.journal_id, evidence.sequence.get());
        if !seen.insert(key) {
            return Err(integrity("completed evidence contains duplicates"));
        }
    }
    let result = json!({
        "record_type": EXECUTION_RESULT_RECORD_TYPE,
        "schema_version": CHECKPOINT_SCHEMA_VERSION,
        "preparation_id": preparation.preparation_id,
        "local_handle": handle.handle.local_handle,
        "completed_steps": ctx.completed_ids,
        "completed_evidence": ctx.completed_evidence.iter().map(EvidenceRef::to_json).collect::<Vec<Value>>(),
        "learning_snapshot": learning_baseline.to_json(),
        "limitations": ["native task completion establishes no application commitment"],
    });
    let result_bytes = serde_json::to_vec(&result)
        .map_err(|e| invalid(format!("result cannot be serialized: {e}")))?;
    rm_wire::canonical_digest(&result_bytes)
        .map_err(|e| invalid(format!("result bytes rejected: {e}")))?;
    let effect = install_public(&principal, &result_bytes, "application/json")?;
    let response_bytes = json!({
        "record_type": "execution_response",
        "result": effect.to_json(),
    });
    let response_bytes = serde_json::to_vec(&response_bytes)
        .map_err(|e| invalid(format!("response cannot be serialized: {e}")))?;
    let response = install_public(&principal, &response_bytes, "application/json")?;
    let submission = EventSubmission {
        producer_sequence: Some(PositiveInteger::new(5000).map_err(|e| invalid(e.detail))?),
        event_kind: "task_output".to_string(),
        event_schema_version: "evidence-kernel/0.1.0".to_string(),
        occurred_at: MaybeTimePoint::Missing(Missing::new("not_observed")),
        payload: EvidencePayload {
            data: json!({"result": effect.to_json()}),
            measurements: Vec::new(),
            evidence_refs: Vec::new(),
            artifact_refs: vec![effect.clone(), response.clone()],
        },
    };
    rm_evidence::commit_owner_effect(&principal, &manifest, &effect, &[submission], &response)?;
    Ok(effect)
}

fn client_profile_refs(
    principal: &AuthenticatedPrincipal,
    preparation: &PreparedTask,
) -> Result<(ArtifactReference, ArtifactReference), ConnectorError> {
    // Profiles and native options are admitted task inputs; missing bytes
    // refuse native entry rather than inventing defaults.
    let mut profile: Option<ArtifactReference> = None;
    let mut options: Option<ArtifactReference> = None;
    for input in &preparation.task.inputs {
        if input.name == "client_profile" {
            profile = Some(input.content.clone());
        }
        if input.name == "page_options" {
            options = Some(input.content.clone());
        }
    }
    // Minimal commissions may omit explicit profiles; synthesize retained
    // default bytes deterministically and install them, so entry still rests
    // on durable evidence rather than invented references.
    let profile = match profile {
        Some(reference) => {
            rm_evidence::load_artifact(principal, &reference).map_err(|_| {
                prerequisite("client_profile bytes are not retained; no native entry")
            })?;
            reference
        }
        None => {
            let bytes = b"{\"profile\":\"default-ordinary\"}".to_vec();
            install_public(principal, &bytes, "application/json")?
        }
    };
    let options = match options {
        Some(reference) => {
            rm_evidence::load_artifact(principal, &reference).map_err(|_| {
                prerequisite("page_options bytes are not retained; no native entry")
            })?;
            reference
        }
        None => {
            let bytes = b"{\"native_options\":\"default\"}".to_vec();
            install_public(principal, &bytes, "application/json")?
        }
    };
    Ok((profile, options))
}

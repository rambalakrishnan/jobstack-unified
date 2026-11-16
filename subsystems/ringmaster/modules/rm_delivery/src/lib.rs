//! `rm_delivery`: Start admission, durable dispatch intent, and work claiming.
//!
//! Implements the delivery boundary (seam mapping §4.3, §13.4, §13.5, §16.3,
//! §18; EXT-START / EXT-IDEMPOTENCY / EXT-RESUME / LIFE-DISPATCH /
//! LIFE-IDEMPOTENCY / EK-ATOMICITY / OWD-LOCAL-COMMIT):
//!
//! - [`start`] verifies an existing immutable preparation, authorizes the
//!   `Start` operation, and commits the owner-local admission effect before
//!   acknowledging: the exact handle bytes, the admitted input, the logical
//!   idempotency binding, the dispatch intent, one `dispatch_published`
//!   journal event, and the replayable response artifact. The returned
//!   receipt is local only; a native run ID is never fabricated.
//! - Repeated initial `Start`, even with a new `request_id`, returns the same
//!   handle and one logical execution. A changed immutable request under the
//!   same logical key, or a second key over one commission, is rejected.
//! - [`claim_work`] is lease-gated and bounded: an entry whose active
//!   boundary (which includes queue time) has been reached is recorded as
//!   `expired_before_entry` and never delivered; a stale or expired resource
//!   lease fences the entry instead.
//! - [`enqueue_owner_control`] admits control commands on their own queue,
//!   never behind workflow delivery; [`take_owner_control`] takes them per
//!   handle.
//! - [`recover_delivery`] reconstructs the retained dispatch history from the
//!   journal alone. A restart before native delivery may deliver again within
//!   the remaining boundary; a restart around a delivery attempt preserves
//!   uncertainty and never silently resends.
//!
//! The five publication axes are owner-separated. Dispatch-axis revisions are
//! published through [`rm_lifecycle::publish_axis`] after the local admission
//! commit; publication is a later, separate owner write and its absence never
//! rewrites the local receipt.
//!
//! No in-band nulls: every absence is a typed [`Missing`] envelope.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{LazyLock, Mutex, MutexGuard};
use std::time::Instant;

use rm_authority::{
    AttemptCommission, AttemptKind, ExecutionMode, Manifest, Operation, WorkScope,
};
use rm_evidence::{
    AccessClass, ArtifactReference, EvidencePayload, EventSubmission, JournalEnvelope, MaybeDigest,
    PositiveInteger,
};
use rm_lifecycle::{
    commission_digest, commission_json, publish_axis, AttemptContext, Axis, AxisRevision, AxisValue,
    DispatchState, LifecyclePublicationReference, AXIS_REVISION_RECORD_TYPE,
    LIFECYCLE_SCHEMA_VERSION,
};
use rm_preparation::{
    DurationLimit, PreparationReference, PreparedTask, CONNECTOR_REQUEST_TYPE,
    CONNECTOR_SCHEMA_VERSION,
};
use rm_time::{
    boundary_reached, ClockDescriptor, MaybeString, MaybeTimePoint, MeasurementOrigin, Missing,
    UtcAnnotation,
};
use rm_wire::Digest;
use serde_json::{json, Map, Value};

pub use rm_authority::{AuthenticatedPrincipal, ConnectorError};
pub use rm_evidence::EvidenceRef;
pub use rm_lifecycle::DispatchValue;
pub use rm_time::TimePoint;

// ---------------------------------------------------------------------------
// Vocabulary
// ---------------------------------------------------------------------------

/// The `Start` verb. No tenth connector verb exists.
pub const START_VERB: &str = "Start";
/// Control verbs the owner admits on the independent control queue.
pub const CONTROL_VERBS: [&str; 4] = [
    "RequestNativeCancel",
    "CloseObservationConnection",
    "ReleaseNativeContext",
    "Contain",
];
/// Immutable handle record discriminator.
pub const HANDLE_RECORD_TYPE: &str = "connector_handle";
/// Start receipt kind.
pub const START_RECEIPT_KIND: &str = "start_receipt";
/// Owner-side delivery intent record.
pub const DELIVERY_INTENT_RECORD_TYPE: &str = "delivery_intent";
/// Owner-side non-delivery decision record.
pub const DELIVERY_DECISION_RECORD_TYPE: &str = "delivery_decision";
/// Replayable owner-local response record.
pub const DELIVERY_RESPONSE_RECORD_TYPE: &str = "delivery_response";
/// Owner-local scheduling states (§4.3), proposed names, not shared enums.
pub const LOCAL_STATE_ADMITTED_QUEUED: &str = "admitted_queued";
/// Claimed by the current resource owner; entry pending.
pub const LOCAL_STATE_ASSIGNED: &str = "assigned";
/// Boundary reached before native entry; no workflow delivery.
pub const LOCAL_STATE_EXPIRED: &str = "expired_before_entry";
/// Ownership or command authority revoked; no workflow delivery.
pub const LOCAL_STATE_FENCED: &str = "fenced";

/// Bound on admitted, not-yet-claimed work per connector runtime.
const MAX_QUEUED_WORK: usize = 64;
/// Bound on one crash-recovery journal scan.
const MAX_RECOVERY_SCAN: u64 = 4096;
/// Retries allowed when another writer advances the journal under a commit.
const COMMIT_ATTEMPTS: usize = 3;

fn connector_error(
    code: &str,
    fault_domain: &str,
    detail: String,
    operation_delivery: &str,
    retry_guidance: &str,
) -> ConnectorError {
    ConnectorError {
        kind: "connector_error".to_string(),
        code: code.to_string(),
        fault_domain: fault_domain.to_string(),
        detail,
        operation_delivery: operation_delivery.to_string(),
        retry_guidance: retry_guidance.to_string(),
        retry_after: None,
        handle: None,
        evidence_refs: Vec::new(),
    }
}

fn invalid(detail: impl Into<String>) -> ConnectorError {
    connector_error(
        "INVALID_REQUEST",
        "request",
        detail.into(),
        "not_dispatched",
        "operator_review",
    )
}

fn unsupported(detail: impl Into<String>) -> ConnectorError {
    connector_error(
        "UNSUPPORTED_VERSION",
        "request",
        detail.into(),
        "not_dispatched",
        "operator_review",
    )
}

fn forbidden(detail: impl Into<String>) -> ConnectorError {
    connector_error(
        "FORBIDDEN",
        "policy",
        detail.into(),
        "not_dispatched",
        "operator_review",
    )
}

fn not_admitted(detail: impl Into<String>) -> ConnectorError {
    connector_error(
        "NOT_ADMITTED",
        "policy",
        detail.into(),
        "not_dispatched",
        "operator_review",
    )
}

fn stale(detail: impl Into<String>) -> ConnectorError {
    connector_error(
        "STALE_CONTEXT",
        "policy",
        detail.into(),
        "not_dispatched",
        "operator_review",
    )
}

fn reserved(detail: impl Into<String>) -> ConnectorError {
    connector_error(
        "RESOURCE_BUSY",
        "policy",
        detail.into(),
        "not_dispatched",
        "operator_review",
    )
}

fn unknown_handle(detail: impl Into<String>) -> ConnectorError {
    connector_error(
        "UNKNOWN_HANDLE",
        "request",
        detail.into(),
        "not_dispatched",
        "operator_review",
    )
}

fn integrity(detail: impl Into<String>) -> ConnectorError {
    connector_error(
        "INTEGRITY_CONFLICT",
        "connector",
        detail.into(),
        "not_dispatched",
        "operator_review",
    )
}

fn idempotency_conflict(detail: impl Into<String>) -> ConnectorError {
    connector_error(
        "IDEMPOTENCY_CONFLICT",
        "request",
        detail.into(),
        "not_dispatched",
        "operator_review",
    )
}

fn prerequisite(detail: impl Into<String>) -> ConnectorError {
    connector_error(
        "PREREQUISITE_UNAVAILABLE",
        "environment",
        detail.into(),
        "not_dispatched",
        "operator_review",
    )
}

fn check_principal(principal: &AuthenticatedPrincipal) -> Result<(), ConnectorError> {
    if principal.principal_id().is_empty() {
        return Err(connector_error(
            "UNAUTHENTICATED",
            "request",
            "principal identity is empty".to_string(),
            "not_dispatched",
            "operator_review",
        ));
    }
    Digest::parse(principal.registration_digest().as_str())
        .map_err(|error| connector_error("UNAUTHENTICATED", "request", error, "not_dispatched", "operator_review"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Wire helpers
// ---------------------------------------------------------------------------

fn missing_json(missing: &Missing) -> Value {
    let mut map = Map::new();
    map.insert("value".to_string(), Value::Null);
    map.insert("reason".to_string(), Value::String(missing.reason.clone()));
    if let Some(detail) = &missing.detail {
        map.insert("detail".to_string(), Value::String(detail.clone()));
    }
    Value::Object(map)
}

fn time_json(point: &TimePoint) -> Result<Value, ConnectorError> {
    serde_json::to_value(point)
        .map_err(|error| invalid(format!("time point cannot be serialized: {error}")))
}

fn time_from_json(value: &Value, what: &str) -> Result<TimePoint, ConnectorError> {
    let point: TimePoint = serde_json::from_value(value.clone())
        .map_err(|error| invalid(format!("{what} is not a TimePoint: {error}")))?;
    validate_timepoint(&point, what)?;
    Ok(point)
}

fn validate_timepoint(point: &TimePoint, what: &str) -> Result<(), ConnectorError> {
    if point.clock_id.is_empty() || point.boot_id.is_empty() {
        return Err(invalid(format!(
            "{what} must name a registered clock and boot"
        )));
    }
    if !point.monotonic_offset_ms.is_finite() || point.monotonic_offset_ms < 0.0 {
        return Err(invalid(format!(
            "{what}.monotonic_offset_ms must be finite and nonnegative"
        )));
    }
    match &point.utc_annotation {
        UtcAnnotation::DateTime(text) => {
            if text.is_empty() {
                return Err(invalid(format!("{what}.utc_annotation must be nonempty")));
            }
        }
        UtcAnnotation::Missing(missing) => {
            if !rm_time::is_valid_reason(&missing.reason) {
                return Err(invalid(format!(
                    "{what}.utc_annotation missingness reason {:?} is not a kernel null reason",
                    missing.reason
                )));
            }
        }
    }
    Ok(())
}

fn ensure_closed(
    object: &Map<String, Value>,
    allowed: &[&str],
    what: &str,
) -> Result<(), ConnectorError> {
    for key in object.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(invalid(format!(
                "{what} carries undeclared field {key:?}"
            )));
        }
    }
    Ok(())
}

fn field<'a>(
    object: &'a Map<String, Value>,
    name: &str,
    what: &str,
) -> Result<&'a Value, ConnectorError> {
    object
        .get(name)
        .ok_or_else(|| invalid(format!("{what} is missing required field {name:?}")))
}

fn field_str<'a>(
    object: &'a Map<String, Value>,
    name: &str,
    what: &str,
) -> Result<&'a str, ConnectorError> {
    field(object, name, what)?
        .as_str()
        .ok_or_else(|| invalid(format!("{what}.{name} must be a string")))
}

fn parse_missing(value: &Value, what: &str) -> Result<Missing, ConnectorError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(format!("{what} missingness must be a Missing envelope")))?;
    ensure_closed(object, &["value", "reason", "detail"], what)?;
    if !matches!(object.get("value"), Some(Value::Null)) {
        return Err(invalid(format!(
            "{what} missingness requires a `value` of null"
        )));
    }
    let reason = field_str(object, "reason", what)?.to_string();
    if !rm_time::is_valid_reason(&reason) {
        return Err(invalid(format!(
            "{what} missingness reason {:?} is not a kernel null reason",
            reason
        )));
    }
    let detail = match object.get("detail") {
        None => None,
        Some(Value::String(text)) if !text.is_empty() => Some(text.clone()),
        Some(_) => {
            return Err(invalid(format!(
                "{what} missingness detail must be nonempty text"
            )))
        }
    };
    Ok(Missing { reason, detail })
}

fn parse_maybe_string(value: &Value, what: &str) -> Result<MaybeString, ConnectorError> {
    match value {
        Value::String(text) if !text.is_empty() => Ok(MaybeString::Text(text.clone())),
        Value::String(_) => Err(invalid(format!("{what} must be nonempty"))),
        Value::Object(_) => Ok(MaybeString::Missing(parse_missing(value, what)?)),
        _ => Err(invalid(format!(
            "{what} must be a string or a Missing envelope"
        ))),
    }
}

fn attempt_kind_str(kind: AttemptKind) -> &'static str {
    match kind {
        AttemptKind::Practice => "practice",
        AttemptKind::Production => "production",
    }
}

fn execution_mode_str(mode: ExecutionMode) -> &'static str {
    match mode {
        ExecutionMode::Manual => "manual",
        ExecutionMode::Automated => "automated",
    }
}

fn require_identifier(field: &str, value: &str) -> Result<(), ConnectorError> {
    if value.is_empty() {
        return Err(invalid(format!("{field} must be a nonempty identifier")));
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
        return Err(invalid(format!(
            "{what} value must be a finite nonnegative number"
        )));
    }
    Ok(())
}

fn parse_json_bytes(bytes: &[u8], what: &str) -> Result<Value, ConnectorError> {
    serde_json::from_slice(bytes)
        .map_err(|error| invalid(format!("{what} bytes are not JSON: {error}")))
}

fn to_bytes(value: &Value, what: &str) -> Result<Vec<u8>, ConnectorError> {
    serde_json::to_vec(value).map_err(|error| invalid(format!("{what} cannot be serialized: {error}")))
}

// ---------------------------------------------------------------------------
// Registered local clock
// ---------------------------------------------------------------------------

/// The registered local monotonic clock used for local bounds.
///
/// The evidence journal registers this clock on admission, so the
/// `dispatch_published` events admitted here carry comparable coordinates on
/// one clock and boot. UTC annotations are never consulted.
fn local_clock() -> &'static ClockDescriptor {
    rm_evidence::evidence_clock()
}

fn local_now() -> TimePoint {
    static PROCESS_START: LazyLock<Instant> = LazyLock::new(Instant::now);
    let clock = local_clock();
    TimePoint {
        clock_id: clock.clock_id.clone(),
        boot_id: clock.boot_id.clone(),
        origin: MeasurementOrigin::EngineMeasured,
        monotonic_offset_ms: PROCESS_START.elapsed().as_secs_f64() * 1000.0,
        utc_annotation: UtcAnnotation::Missing(Missing::new("not_observed")),
    }
}

fn shift_time(point: &TimePoint, duration_ms: f64) -> Result<TimePoint, ConnectorError> {
    if !duration_ms.is_finite() || duration_ms < 0.0 {
        return Err(invalid(
            "a local bound requires a finite nonnegative duration",
        ));
    }
    Ok(TimePoint {
        clock_id: point.clock_id.clone(),
        boot_id: point.boot_id.clone(),
        origin: point.origin,
        monotonic_offset_ms: point.monotonic_offset_ms + duration_ms,
        utc_annotation: point.utc_annotation.clone(),
    })
}

// ---------------------------------------------------------------------------
// Handle and scope records
// ---------------------------------------------------------------------------

/// Nested handle identity. It is not a native run ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandleReference {
    /// Connector identity.
    pub connector_id: String,
    /// Connector-local logical execution identity.
    pub local_handle: String,
}

impl HandleReference {
    /// Validates the closed reference shape.
    pub fn validate(&self) -> Result<(), ConnectorError> {
        require_identifier("handle.connector_id", &self.connector_id)?;
        require_identifier("handle.local_handle", &self.local_handle)
    }

    /// Closed JSON projection.
    pub fn to_json(&self) -> Value {
        json!({
            "connector_id": self.connector_id,
            "local_handle": self.local_handle,
        })
    }

    /// Parses the closed reference shape.
    pub fn from_json(value: &Value) -> Result<Self, ConnectorError> {
        let object = value
            .as_object()
            .ok_or_else(|| invalid("handle reference must be a JSON object"))?;
        ensure_closed(object, &["connector_id", "local_handle"], "handle reference")?;
        let reference = HandleReference {
            connector_id: field_str(object, "connector_id", "handle reference")?.to_string(),
            local_handle: field_str(object, "local_handle", "handle reference")?.to_string(),
        };
        reference.validate()?;
        Ok(reference)
    }
}

/// Immutable connector handle: the durable logical execution identity.
///
/// It carries the exact preparation, the admitted scope, and the logical key.
/// A native run ID is never part of it; native identity arrives later as
/// source-backed observation evidence.
#[derive(Debug, Clone, PartialEq)]
pub struct ConnectorHandle {
    /// `connector_handle`.
    pub record_type: String,
    /// External connector schema version.
    pub schema_version: String,
    /// Connector plus local handle identity.
    pub handle: HandleReference,
    /// Exact immutable preparation.
    pub preparation: PreparationReference,
    /// Admitted work scope.
    pub scope: WorkScope,
    /// Logical idempotency key.
    pub idempotency_key: String,
    /// Real creation coordinate on the registered local clock.
    pub created_at: TimePoint,
}

impl ConnectorHandle {
    /// Validates the closed handle shape.
    pub fn validate(&self) -> Result<(), ConnectorError> {
        if self.record_type != HANDLE_RECORD_TYPE {
            return Err(invalid(format!(
                "handle record_type {:?} must be {HANDLE_RECORD_TYPE:?}",
                self.record_type
            )));
        }
        if self.schema_version != CONNECTOR_SCHEMA_VERSION {
            return Err(unsupported(format!(
                "handle schema_version {:?} is not {CONNECTOR_SCHEMA_VERSION:?}",
                self.schema_version
            )));
        }
        self.handle.validate()?;
        require_identifier("preparation_id", &self.preparation.preparation_id)?;
        self.preparation.artifact.validate()?;
        self.preparation.registration_ref.validate()?;
        validate_scope(&self.scope)?;
        require_identifier("idempotency_key", &self.idempotency_key)?;
        validate_timepoint(&self.created_at, "handle.created_at")
    }

    /// Closed JSON projection: the exact bytes installed as the handle
    /// artifact before the admission commit.
    pub fn to_json(&self) -> Result<Value, ConnectorError> {
        Ok(json!({
            "record_type": self.record_type,
            "schema_version": self.schema_version,
            "handle": self.handle.to_json(),
            "preparation": self.preparation.to_json(),
            "scope": scope_to_json(&self.scope),
            "idempotency_key": self.idempotency_key,
            "created_at": time_json(&self.created_at)?,
        }))
    }

    /// Parses the closed handle shape, rejecting undeclared fields.
    pub fn from_json(value: &Value) -> Result<Self, ConnectorError> {
        let object = value
            .as_object()
            .ok_or_else(|| invalid("connector handle must be a JSON object"))?;
        ensure_closed(
            object,
            &[
                "record_type",
                "schema_version",
                "handle",
                "preparation",
                "scope",
                "idempotency_key",
                "created_at",
            ],
            "connector handle",
        )?;
        let handle = HandleReference::from_json(field(object, "handle", "connector handle")?)?;
        let preparation =
            PreparationReference::from_json(field(object, "preparation", "connector handle")?)?;
        let scope = parse_scope(field(object, "scope", "connector handle")?)?;
        let created_at = time_from_json(
            field(object, "created_at", "connector handle")?,
            "connector handle.created_at",
        )?;
        let parsed = ConnectorHandle {
            record_type: field_str(object, "record_type", "connector handle")?.to_string(),
            schema_version: field_str(object, "schema_version", "connector handle")?.to_string(),
            handle,
            preparation,
            scope,
            idempotency_key: field_str(object, "idempotency_key", "connector handle")?.to_string(),
            created_at,
        };
        parsed.validate()?;
        Ok(parsed)
    }
}

fn scope_to_json(scope: &WorkScope) -> Value {
    let optional = |value: &Option<String>| match value {
        Some(text) => Value::String(text.clone()),
        None => missing_json(&Missing::new("not_applicable")),
    };
    json!({
        "activity": scope.activity,
        "run_id": scope.run_id,
        "journal_id": scope.journal_id,
        "manifest_hash": scope.manifest_hash,
        "admission_ref": scope.admission_ref,
        "attempt_id": optional(&scope.attempt_id),
        "commission_id": optional(&scope.commission_id),
        "commission_ref": optional(&scope.commission_ref),
        "attempt_kind": match scope.attempt_kind {
            Some(kind) => Value::String(attempt_kind_str(kind).to_string()),
            None => missing_json(&Missing::new("not_applicable")),
        },
        "authorization_refs": scope.authorization_refs,
        "observation_policy": scope.observation_policy,
        "owner_domain": scope.owner_domain,
        "execution_mode": execution_mode_str(scope.execution_mode),
    })
}

fn parse_scope(value: &Value) -> Result<WorkScope, ConnectorError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("scope must be a JSON object"))?;
    ensure_closed(
        object,
        &[
            "activity",
            "run_id",
            "journal_id",
            "manifest_hash",
            "admission_ref",
            "attempt_id",
            "commission_id",
            "commission_ref",
            "attempt_kind",
            "authorization_refs",
            "observation_policy",
            "owner_domain",
            "execution_mode",
        ],
        "scope",
    )?;
    let optional = |name: &str| -> Result<Option<String>, ConnectorError> {
        match parse_maybe_string(field(object, name, "scope")?, &format!("scope.{name}"))? {
            MaybeString::Text(text) => Ok(Some(text)),
            MaybeString::Missing(missing) => {
                if missing.reason == "not_applicable" {
                    Ok(None)
                } else {
                    Err(invalid(format!(
                        "scope.{name} must be present or inapplicable, found {:?}",
                        missing.reason
                    )))
                }
            }
        }
    };
    let attempt_kind = match parse_maybe_string(
        field(object, "attempt_kind", "scope")?,
        "scope.attempt_kind",
    )? {
        MaybeString::Text(text) if text == "practice" => Some(AttemptKind::Practice),
        MaybeString::Text(text) if text == "production" => Some(AttemptKind::Production),
        MaybeString::Text(text) => {
            return Err(invalid(format!("unknown attempt kind {text:?}")))
        }
        MaybeString::Missing(missing) if missing.reason == "not_applicable" => None,
        MaybeString::Missing(missing) => {
            return Err(invalid(format!(
                "scope.attempt_kind missingness {:?} is not not_applicable",
                missing.reason
            )))
        }
    };
    let execution_mode = match field_str(object, "execution_mode", "scope")? {
        "manual" => ExecutionMode::Manual,
        "automated" => ExecutionMode::Automated,
        other => return Err(invalid(format!("unknown execution mode {other:?}"))),
    };
    let authorization_refs = field(object, "authorization_refs", "scope")?
        .as_array()
        .ok_or_else(|| invalid("scope.authorization_refs must be an array"))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_string)
                .ok_or_else(|| invalid("scope.authorization_refs entries must be strings"))
        })
        .collect::<Result<Vec<String>, ConnectorError>>()?;
    let scope = WorkScope {
        activity: field_str(object, "activity", "scope")?.to_string(),
        run_id: field_str(object, "run_id", "scope")?.to_string(),
        journal_id: field_str(object, "journal_id", "scope")?.to_string(),
        manifest_hash: field_str(object, "manifest_hash", "scope")?.to_string(),
        admission_ref: field_str(object, "admission_ref", "scope")?.to_string(),
        attempt_id: optional("attempt_id")?,
        commission_id: optional("commission_id")?,
        commission_ref: optional("commission_ref")?,
        attempt_kind,
        authorization_refs,
        observation_policy: field_str(object, "observation_policy", "scope")?.to_string(),
        owner_domain: field_str(object, "owner_domain", "scope")?.to_string(),
        execution_mode,
    };
    validate_scope(&scope)?;
    Ok(scope)
}

fn validate_scope(scope: &WorkScope) -> Result<(), ConnectorError> {
    require_identifier("scope.activity", &scope.activity)?;
    require_identifier("scope.run_id", &scope.run_id)?;
    require_identifier("scope.journal_id", &scope.journal_id)?;
    if !rm_wire::is_valid_digest(&scope.manifest_hash) {
        return Err(invalid("scope.manifest_hash must be a sha256 digest"));
    }
    require_identifier("scope.admission_ref", &scope.admission_ref)?;
    require_identifier("scope.observation_policy", &scope.observation_policy)?;
    require_identifier("scope.owner_domain", &scope.owner_domain)?;
    if scope.authorization_refs.is_empty() {
        return Err(forbidden(
            "every admitted work scope requires at least one task/resource grant",
        ));
    }
    for grant in &scope.authorization_refs {
        require_identifier("scope.authorization_refs entry", grant)?;
    }
    let bindings = [
        scope.attempt_id.is_some(),
        scope.commission_id.is_some(),
        scope.commission_ref.is_some(),
        scope.attempt_kind.is_some(),
    ];
    if bindings.iter().any(|present| *present) && !bindings.iter().all(|present| *present) {
        return Err(invalid(
            "attempt, commission, commission_ref, and attempt_kind are jointly applicable or jointly inapplicable",
        ));
    }
    if scope.activity == "apply" && scope.attempt_id.is_none() {
        return Err(not_admitted(
            "application work requires its immutable attempt commission",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Command envelope
// ---------------------------------------------------------------------------

/// Resume authority (§13.5). Explicit, source-backed, and never inferred from
/// a local timeout, lease expiry, or storage repair.
#[derive(Debug, Clone, PartialEq)]
pub struct ResumeAuthorization {
    /// Existing logical handle.
    pub handle: HandleReference,
    /// Evidenced native checkpoint for the same request and context.
    pub checkpoint: ArtifactReference,
    /// Evidenced native idempotency/resume contract.
    pub native_resume_contract: ArtifactReference,
    /// Explicit recovery authority references.
    pub authorization_refs: Vec<String>,
    /// Source-backed evidence supporting recovery.
    pub evidence_refs: Vec<EvidenceRef>,
}

/// Recovery or its reasoned inapplicability.
#[derive(Debug, Clone, PartialEq)]
pub enum MaybeResume {
    /// No recovery authorization was supplied.
    Missing(Missing),
    /// Explicit recovery authorization.
    Authorized(ResumeAuthorization),
}

/// Commission or its reasoned inapplicability for non-application work.
#[derive(Debug, Clone, PartialEq)]
pub enum MaybeCommission {
    /// Discovery work carries no application commission.
    Missing(Missing),
    /// The immutable application commission.
    Present(AttemptCommission),
}

/// StartRequest (§13.4): the immutable preparation plus the logical key,
/// accepted concerns, grants, and optional explicit recovery.
///
/// `manifest` and `commission` carry the authority view the connector runtime
/// was admitted under; `lease` is the owner-local resource fence under which
/// the work may be claimed. They are authority inputs, never caller-authored
/// task content.
#[derive(Debug, Clone, PartialEq)]
pub struct StartRequest {
    /// Exact verified preparation.
    pub preparation: PreparationReference,
    /// Logical commissioning idempotency key.
    pub idempotency_key: String,
    /// Accepted preparation concern identities.
    pub accepted_concern_ids: Vec<String>,
    /// Admitted task/resource grants for this command.
    pub authorization_refs: Vec<String>,
    /// Optional explicit recovery authorization.
    pub recovery: MaybeResume,
    /// Admitted manifest authority view.
    pub manifest: Manifest,
    /// Immutable attempt commission, when the work is application work.
    pub commission: MaybeCommission,
    /// Owner-local resource lease.
    pub lease: rm_leases::LeaseRecord,
}

/// ControlRequest: an owner control command bound to one logical handle.
#[derive(Debug, Clone, PartialEq)]
pub struct ControlRequest {
    /// Admitted control scope (control grants only).
    pub scope: WorkScope,
    /// Admitted manifest authority view.
    pub manifest: Manifest,
    /// Target handle; control never addresses a native run ID.
    pub handle: HandleReference,
}

/// Envelope payload.
#[derive(Debug, Clone, PartialEq)]
pub enum CommandPayload {
    /// Start command.
    Start(StartRequest),
    /// Owner control command.
    Control(ControlRequest),
}

/// Connector command envelope.
#[derive(Debug, Clone, PartialEq)]
pub struct ConnectorRequest {
    /// `connector_request`.
    pub record_type: String,
    /// `external-connector/0.1.0`.
    pub schema_version: String,
    /// Transport command identity.
    pub request_id: String,
    /// Connector identity.
    pub connector_id: String,
    /// Connector verb.
    pub operation: String,
    /// Bounded call allowance.
    pub call_limit: DurationLimit,
    /// Command payload.
    pub payload: CommandPayload,
}

fn manifest_json(manifest: &Manifest) -> Result<Value, ConnectorError> {
    let bytes = rm_authority::manifest_wire_bytes(manifest);
    parse_json_bytes(&bytes, "manifest")
}

fn recovery_json(recovery: &MaybeResume) -> Value {
    match recovery {
        MaybeResume::Missing(missing) => missing_json(missing),
        MaybeResume::Authorized(authorization) => json!({
            "handle": authorization.handle.to_json(),
            "checkpoint": authorization.checkpoint.to_json(),
            "native_resume_contract": authorization.native_resume_contract.to_json(),
            "authorization_refs": authorization.authorization_refs,
            "evidence_refs": authorization.evidence_refs.iter().map(EvidenceRef::to_json).collect::<Vec<Value>>(),
        }),
    }
}

fn start_request_json(start: &StartRequest) -> Result<Value, ConnectorError> {
    Ok(json!({
        "kind": "start",
        "preparation": start.preparation.to_json(),
        "idempotency_key": start.idempotency_key,
        "accepted_concern_ids": start.accepted_concern_ids,
        "authorization_refs": start.authorization_refs,
        "recovery": recovery_json(&start.recovery),
        "manifest": manifest_json(&start.manifest)?,
        "commission": match &start.commission {
            MaybeCommission::Present(commission) => commission_json(commission),
            MaybeCommission::Missing(missing) => missing_json(missing),
        },
        "lease": start.lease.to_json(),
    }))
}

fn control_request_json(control: &ControlRequest) -> Result<Value, ConnectorError> {
    Ok(json!({
        "kind": "control",
        "scope": scope_to_json(&control.scope),
        "manifest": manifest_json(&control.manifest)?,
        "handle": control.handle.to_json(),
    }))
}

impl ConnectorRequest {
    /// Closed JSON projection used for command digests and admitted-input
    /// artifacts.
    pub fn to_json(&self) -> Result<Value, ConnectorError> {
        let payload = match &self.payload {
            CommandPayload::Start(start) => start_request_json(start)?,
            CommandPayload::Control(control) => control_request_json(control)?,
        };
        Ok(json!({
            "record_type": self.record_type,
            "schema_version": self.schema_version,
            "request_id": self.request_id,
            "connector_id": self.connector_id,
            "operation": self.operation,
            "call_limit": {
                "kind": self.call_limit.kind,
                "unit": self.call_limit.unit,
                "value": self.call_limit.value,
            },
            "payload": payload,
        }))
    }
}

fn validate_envelope(command: &ConnectorRequest) -> Result<(), ConnectorError> {
    if command.record_type != CONNECTOR_REQUEST_TYPE {
        return Err(invalid(format!(
            "record_type {:?} must be {CONNECTOR_REQUEST_TYPE:?}",
            command.record_type
        )));
    }
    if command.schema_version != CONNECTOR_SCHEMA_VERSION {
        return Err(unsupported(format!(
            "unknown schema_version {:?}",
            command.schema_version
        )));
    }
    require_identifier("request_id", &command.request_id)?;
    require_identifier("connector_id", &command.connector_id)?;
    require_identifier("operation", &command.operation)?;
    validate_duration_limit(&command.call_limit, "call_limit")
}

// ---------------------------------------------------------------------------
// Start receipt
// ---------------------------------------------------------------------------

/// Local Start disposition. None of these is native acceptance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartDisposition {
    /// The local admission effect was committed by this command.
    AcceptedLocally,
    /// The same logical execution was already retained.
    ExistingHandle,
    /// Explicit recovery authority preserved the logical dispatch.
    ResumeAuthorized,
}

impl StartDisposition {
    /// Wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            StartDisposition::AcceptedLocally => "accepted_locally",
            StartDisposition::ExistingHandle => "existing_handle",
            StartDisposition::ResumeAuthorized => "resume_authorized",
        }
    }
}

/// Local Start receipt. It is not native acceptance and never claims execution
/// completion.
#[derive(Debug, Clone, PartialEq)]
pub struct StartResult {
    /// `start_receipt`.
    pub kind: String,
    /// Local disposition.
    pub disposition: StartDisposition,
    /// Complete immutable handle.
    pub handle: ConnectorHandle,
    /// Installed handle artifact.
    pub handle_artifact: ArtifactReference,
    /// Retained `dispatch_published` receipt reference.
    pub receipt_ref: EvidenceRef,
}

impl StartResult {
    /// Closed JSON projection.
    pub fn to_json(&self) -> Result<Value, ConnectorError> {
        Ok(start_receipt_json(
            self.disposition,
            &self.handle,
            &self.handle_artifact,
            Some(&self.receipt_ref),
        )?)
    }
}

fn start_receipt_json(
    disposition: StartDisposition,
    handle: &ConnectorHandle,
    handle_artifact: &ArtifactReference,
    receipt: Option<&EvidenceRef>,
) -> Result<Value, ConnectorError> {
    Ok(json!({
        "kind": START_RECEIPT_KIND,
        "disposition": disposition.as_str(),
        "handle": handle.to_json()?,
        "handle_artifact": handle_artifact.to_json(),
        "receipt_ref": match receipt {
            Some(reference) => reference.to_json(),
            None => missing_json(&Missing::with_detail(
                "not_observed",
                "receipt is assigned by the owner-local journal commit",
            )),
        },
    }))
}

/// Owner-local dispatch publication state (a later, separate owner write).
#[derive(Debug, Clone, PartialEq)]
pub enum PublicationState {
    /// Dispatch revision published and installed.
    Published(LifecyclePublicationReference),
    /// Publication is honestly pending.
    Pending(Missing),
    /// Publication does not apply (discovery work has no attempt axis).
    NotApplicable(Missing),
}

impl PublicationState {
    /// Closed JSON projection.
    pub fn to_json(&self) -> Value {
        match self {
            PublicationState::Published(reference) => json!({
                "status": "published",
                "reference": reference.to_json(),
            }),
            PublicationState::Pending(missing) => json!({
                "status": "pending",
                "missing": missing_json(missing),
            }),
            PublicationState::NotApplicable(missing) => json!({
                "status": "not_applicable",
                "missing": missing_json(missing),
            }),
        }
    }
}

/// Crash-recovery reading of the retained dispatch history.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryState {
    /// Only admission is retained: deliver within the remaining boundary.
    Deliverable,
    /// A delivery attempt may have happened: preserve uncertainty, no resend.
    AwaitingEvidence,
    /// The active boundary was reached before native entry.
    ExpiredBeforeEntry,
    /// Ownership or command authority was revoked.
    Fenced,
}

impl RecoveryState {
    /// Wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            RecoveryState::Deliverable => "deliverable",
            RecoveryState::AwaitingEvidence => "awaiting_evidence",
            RecoveryState::ExpiredBeforeEntry => "expired_before_entry",
            RecoveryState::Fenced => "fenced",
        }
    }
}

/// Journal-only reconstruction of one logical execution.
#[derive(Debug, Clone, PartialEq)]
pub struct RecoveredDelivery {
    /// Recovered immutable handle (installed bytes, not a fabricated one).
    pub handle: ConnectorHandle,
    /// Handle artifact cited by the admission event.
    pub handle_artifact: ArtifactReference,
    /// Admitted command bytes cited by the admission event.
    pub input_artifact: ArtifactReference,
    /// Replayable response artifact cited by the admission event.
    pub response_artifact: ArtifactReference,
    /// Retained admission receipt.
    pub admission_receipt: EvidenceRef,
    /// Reconstructed dispatch value.
    pub dispatch: DispatchValue,
    /// Recovery classification.
    pub state: RecoveryState,
    /// Original active boundary: queue time is included, never restarted.
    pub active_deadline: TimePoint,
    /// Leased resource snapshot from the admission event.
    pub lease: rm_leases::LeaseRecord,
    /// Last retained command identity that produced an effect.
    pub last_command_id: String,
}

// ---------------------------------------------------------------------------
// Internal stores
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalState {
    AdmittedQueued,
    Assigned,
    ExpiredBeforeEntry,
    Fenced,
}

impl LocalState {
    fn as_str(self) -> &'static str {
        match self {
            LocalState::AdmittedQueued => LOCAL_STATE_ADMITTED_QUEUED,
            LocalState::Assigned => LOCAL_STATE_ASSIGNED,
            LocalState::ExpiredBeforeEntry => LOCAL_STATE_EXPIRED,
            LocalState::Fenced => LOCAL_STATE_FENCED,
        }
    }
}

#[derive(Debug, Clone)]
struct Entry {
    handle: ConnectorHandle,
    handle_artifact: ArtifactReference,
    input_artifact: ArtifactReference,
    admission_receipt: EvidenceRef,
    last_receipt: EvidenceRef,
    manifest: Manifest,
    commission: Option<AttemptCommission>,
    preparation_artifact: ArtifactReference,
    request_digest: Digest,
    idempotency_key: String,
    owner_principal: String,
    state: LocalState,
    dispatch: DispatchValue,
    lease: rm_leases::LeaseRecord,
    entity_revision: rm_leases::Revision,
    input_revision: rm_leases::Revision,
    owner_epoch: String,
    session_epoch: MaybeString,
    active_deadline: TimePoint,
    last_command_id: String,
    published_revision: u64,
    publication: PublicationState,
    recovered: bool,
}

#[derive(Debug, Clone)]
struct CommandRecord {
    request_digest: Digest,
    result: StartResult,
}

#[derive(Default)]
struct WorkStore {
    commands: BTreeMap<String, CommandRecord>,
    logical: BTreeMap<String, String>,
    bindings: BTreeMap<String, String>,
    entries: BTreeMap<String, Entry>,
    queue: Vec<String>,
}

#[derive(Debug, Clone)]
struct ControlRecord {
    request_digest: Digest,
    receipt: EvidenceRef,
}

#[derive(Default)]
struct ControlStore {
    receipts: BTreeMap<String, ControlRecord>,
    queues: BTreeMap<String, VecDeque<ConnectorRequest>>,
}

static WORK_STORE: LazyLock<Mutex<WorkStore>> = LazyLock::new(|| Mutex::new(WorkStore::default()));
static CONTROL_STORE: LazyLock<Mutex<ControlStore>> =
    LazyLock::new(|| Mutex::new(ControlStore::default()));

fn lock_work() -> MutexGuard<'static, WorkStore> {
    WORK_STORE
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}

fn lock_control() -> MutexGuard<'static, ControlStore> {
    CONTROL_STORE
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}

// ---------------------------------------------------------------------------
// Identity helpers
// ---------------------------------------------------------------------------

fn logical_key(principal: &AuthenticatedPrincipal, connector_id: &str, idempotency_key: &str) -> String {
    format!(
        "{}|{}|{}",
        principal.principal_id(),
        connector_id,
        idempotency_key
    )
}

fn command_key(principal: &AuthenticatedPrincipal, connector_id: &str, request_id: &str) -> String {
    format!("{}|{}|{}", principal.principal_id(), connector_id, request_id)
}

fn control_queue_key(
    principal: &AuthenticatedPrincipal,
    connector_id: &str,
    local_handle: &str,
) -> String {
    format!(
        "{}|{}|{}",
        principal.principal_id(),
        connector_id,
        local_handle
    )
}

fn deterministic_handle(logical_key: &str) -> String {
    let digest = rm_wire::artifact_digest(logical_key.as_bytes());
    let hex = digest
        .as_str()
        .strip_prefix("sha256:")
        .unwrap_or(digest.as_str());
    format!("local-{}", &hex[..24])
}

fn execution_binding(prepared: &PreparedTask, commission: Option<&AttemptCommission>) -> String {
    match commission {
        Some(commission) => format!(
            "attempt:{}:{}:{}",
            prepared.scope.run_id,
            commission.attempt_id,
            prepared.task_semantic_hash.as_str()
        ),
        None => format!(
            "task:{}:{}:{}",
            prepared.scope.run_id,
            prepared.scope.activity,
            prepared.task_semantic_hash.as_str()
        ),
    }
}

fn immutable_request_json(
    command: &ConnectorRequest,
    start: &StartRequest,
    prepared: &PreparedTask,
) -> Value {
    json!({
        "connector_id": command.connector_id,
        "preparation_id": start.preparation.preparation_id,
        "preparation_artifact": start.preparation.artifact.to_json(),
        "task_semantic_hash": prepared.task_semantic_hash.as_str(),
        "activity": prepared.scope.activity,
        "accepted_concern_ids": start.accepted_concern_ids,
        "authorization_refs": start.authorization_refs,
        "attempt": match &start.commission {
            MaybeCommission::Present(commission) => json!({
                "attempt_id": commission.attempt_id,
                "commission_id": commission.commission_id,
                "task_semantic_hash": commission.task_semantic_hash,
            }),
            MaybeCommission::Missing(missing) => missing_json(missing),
        },
    })
}

fn immutable_request_digest(
    command: &ConnectorRequest,
    start: &StartRequest,
    prepared: &PreparedTask,
) -> Result<Digest, ConnectorError> {
    let value = immutable_request_json(command, start, prepared);
    let bytes = to_bytes(&value, "immutable attempt request")?;
    rm_wire::canonical_digest(&bytes)
        .map_err(|error| invalid(format!("immutable attempt request cannot be hashed: {error}")))
}

fn command_digest(command: &ConnectorRequest) -> Result<Digest, ConnectorError> {
    let value = command.to_json()?;
    let bytes = to_bytes(&value, "connector command")?;
    rm_wire::canonical_digest(&bytes)
        .map_err(|error| invalid(format!("connector command cannot be hashed: {error}")))
}

// ---------------------------------------------------------------------------
// Evidence helpers
// ---------------------------------------------------------------------------

fn evidence_ref_for(envelope: &JournalEnvelope) -> Result<EvidenceRef, ConnectorError> {
    let reference = EvidenceRef {
        journal_id: envelope.journal_id.clone(),
        sequence: envelope.journal_sequence,
        event_id: envelope.event_id.clone(),
        event_hash: envelope.event_hash.clone(),
        pointer: String::new(),
    };
    reference.validate()?;
    Ok(reference)
}

fn install(
    principal: &AuthenticatedPrincipal,
    bytes: &[u8],
    owner_domain: &str,
) -> Result<ArtifactReference, ConnectorError> {
    let reference = ArtifactReference {
        digest: rm_wire::artifact_digest(bytes),
        size_bytes: bytes.len() as u64,
        media_type: "application/json".to_string(),
        owner_domain: owner_domain.to_string(),
        access: AccessClass::Restricted,
    };
    rm_evidence::install_artifact(principal, &reference, bytes)
}

fn dedup_refs(references: &[ArtifactReference]) -> Vec<ArtifactReference> {
    let mut seen = BTreeSet::new();
    let mut unique = Vec::with_capacity(references.len());
    for reference in references {
        if seen.insert(reference.digest.as_str().to_string()) {
            unique.push(reference.clone());
        }
    }
    unique
}

#[allow(clippy::too_many_arguments)]
fn commit_journal_event(
    principal: &AuthenticatedPrincipal,
    manifest: &Manifest,
    journal_id: &str,
    effect: &ArtifactReference,
    response: &ArtifactReference,
    extra_refs: &[&ArtifactReference],
    data: Value,
    event_kind: &str,
    occurred_at: &TimePoint,
) -> Result<EvidenceRef, ConnectorError> {
    let registration = rm_evidence::event_registration(event_kind).ok_or_else(|| {
        not_admitted(format!(
            "event kind {event_kind:?} is not registered with the evidence authority"
        ))
    })?;
    let mut references = vec![effect.clone(), response.clone()];
    references.extend(extra_refs.iter().map(|reference| (*reference).clone()));
    let artifact_refs = dedup_refs(&references);
    for attempt in 0..COMMIT_ATTEMPTS {
        let head = rm_evidence::journal_head(principal, journal_id)?;
        let head_sequence = head.last_sequence.get();
        let producer_sequence = PositiveInteger::new(head.last_sequence.get() + 1)
            .map_err(|error| invalid(format!("producer sequence is invalid: {error}")))?;
        let submission = EventSubmission {
            producer_sequence: Some(producer_sequence),
            event_kind: event_kind.to_string(),
            event_schema_version: registration.event_schema_version.to_string(),
            occurred_at: MaybeTimePoint::Present(occurred_at.clone()),
            payload: EvidencePayload {
                data: data.clone(),
                measurements: Vec::new(),
                evidence_refs: Vec::new(),
                artifact_refs: artifact_refs.clone(),
            },
        };
        match rm_evidence::commit_owner_effect(principal, manifest, effect, &[submission], response) {
            Ok(envelopes) => {
                let envelope = envelopes.first().ok_or_else(|| {
                    integrity("owner effect commit produced no retained journal event")
                })?;
                return evidence_ref_for(envelope);
            }
            Err(error) if error.code == "INTEGRITY_CONFLICT" && attempt + 1 < COMMIT_ATTEMPTS => {
                // Another permitted writer may have advanced the journal under
                // this producer-lifetime sequence. Retry only when the head
                // actually moved; otherwise the conflict is the real incident.
                let current = rm_evidence::journal_head(principal, journal_id)?;
                if current.last_sequence.get() > head_sequence {
                    continue;
                }
                return Err(error);
            }
            Err(error) => return Err(error),
        }
    }
    Err(prerequisite(
        "journal head kept moving under the owner-local commit; no effect was acknowledged",
    ))
}

// ---------------------------------------------------------------------------
// Start boundary
// ---------------------------------------------------------------------------

/// Starts one logical execution: durable local admission before any delivery.
///
/// The returned receipt is local. Native acceptance is never inferred from it,
/// and a lost delivery acknowledgement is never treated as rejection.
pub fn start(
    principal: &AuthenticatedPrincipal,
    command: &ConnectorRequest,
) -> Result<StartResult, ConnectorError> {
    check_principal(principal)?;
    validate_envelope(command)?;
    let start_request = match &command.payload {
        CommandPayload::Start(start_request) => start_request,
        CommandPayload::Control(_) => {
            return Err(invalid(
                "Start requires a start payload; control commands use enqueue_owner_control",
            ))
        }
    };
    if command.operation != START_VERB {
        return Err(invalid(format!(
            "operation {:?} must be {START_VERB:?}",
            command.operation
        )));
    }

    // 1. The preparation must still be the exact retained, current one.
    let prepared = rm_preparation::verify_preparation(principal, &start_request.preparation)?;
    verify_preparation_binding(command, start_request, &prepared)?;
    validate_concerns(start_request, &prepared)?;

    // 2. Authority: each call is bound to an admitted grant.
    let admitted_scope = admitted_scope(start_request, &prepared);
    rm_authority::authorize_work(principal, &admitted_scope, &start_operation(command, start_request, &prepared))?;

    // 3. Logical identity and immutable request binding.
    let request_digest = immutable_request_digest(command, start_request, &prepared)?;
    let request_digest_full = command_digest(command)?;
    let key = logical_key(principal, &command.connector_id, &start_request.idempotency_key);
    let local_handle = deterministic_handle(&key);
    let commission = match &start_request.commission {
        MaybeCommission::Present(commission) => Some(commission),
        MaybeCommission::Missing(_) => None,
    };
    let binding = execution_binding(&prepared, commission);
    let created_at = local_now();
    let mut store = lock_work();

    // 4. Exact command deduplication: identical request returns its retained
    //    receipt without another effect; changed content under the command key
    //    is rejected.
    let command_identity = command_key(principal, &command.connector_id, &command.request_id);
    if let Some(record) = store.commands.get(&command_identity) {
        if record.request_digest != request_digest_full {
            return Err(idempotency_conflict(
                "the same command identity was reused with different content; transport retries never authorize another execution",
            ));
        }
        return Ok(record.result.clone());
    }

    // 5. Logical key: same key and same immutable request returns the same
    //    handle; changed content under the key is rejected.
    if let Some(existing) = store.logical.get(&key).cloned() {
        let mut entry = store
            .entries
            .remove(&existing)
            .ok_or_else(|| integrity("logical index points at a missing handle record"))?;
        let loaded = load_handle(principal, &entry.handle_artifact)?;
        if loaded != entry.handle {
            store.entries.insert(existing.clone(), entry);
            return Err(integrity(
                "retained handle bytes no longer match the admitted handle record",
            ));
        }
        if entry.request_digest != request_digest {
            store.entries.insert(existing, entry);
            return Err(idempotency_conflict(
                "changed preparation or request content under one logical idempotency key; the immutable attempt request is not replaceable",
            ));
        }
        let result = if matches!(start_request.recovery, MaybeResume::Authorized(_)) {
            match resume_locked(
                principal,
                command,
                start_request,
                &mut entry,
                &request_digest,
                &mut store,
            ) {
                Ok(result) => result,
                Err(error) => {
                    store.entries.insert(existing, entry);
                    return Err(error);
                }
            }
        } else {
            result_from_entry(StartDisposition::ExistingHandle, &entry)
        };
        store.entries.insert(existing, entry);
        store.commands.insert(
            command_identity,
            CommandRecord {
                request_digest: request_digest_full,
                result: result.clone(),
            },
        );
        return Ok(result);
    }

    // 6. One application commission cannot obtain a second logical execution
    //    by changing keys, callers, or executors.
    if let Some(bound_key) = store.bindings.get(&binding) {
        if bound_key != &key {
            return Err(idempotency_conflict(
                "this attempt/task already owns one logical execution; changing the idempotency key, caller, or executor never authorizes a second",
            ));
        }
    }

    // 7. Crash recovery: the journal is the retained source of truth. If an
    //    admission already exists (for example after a process restart), bind
    //    to it instead of creating another execution.
    if let Some(recovered) = recover_from_journal(
        principal,
        &local_handle,
        &request_digest,
        &binding,
        &start_request.manifest,
        prepared.evidence_prefix.last_sequence.get(),
    )? {
        let mut entry = recovered_entry(
            principal,
            start_request,
            &prepared,
            recovered.handle,
            recovered.handle_artifact,
            recovered.input_artifact,
            recovered.admission_receipt,
            recovered.dispatch,
            recovered.state,
            recovered.active_deadline,
            recovered.lease,
            recovered.last_command_id,
            &request_digest,
        )?;
        if matches!(start_request.recovery, MaybeResume::Authorized(_)) {
            let result = resume_locked(
                principal,
                command,
                start_request,
                &mut entry,
                &request_digest,
                &mut store,
            )?;
            store.entries.insert(local_handle.clone(), entry);
            store.logical.insert(key.clone(), local_handle);
            store.bindings.insert(binding, key);
            store.commands.insert(
                command_identity,
                CommandRecord {
                    request_digest: request_digest_full,
                    result: result.clone(),
                },
            );
            return Ok(result);
        }
        let result = result_from_entry(StartDisposition::ExistingHandle, &entry);
        let requeue = entry.state == LocalState::AdmittedQueued;
        store.entries.insert(local_handle.clone(), entry);
        if requeue {
            store.queue.push(local_handle.clone());
        }
        store.logical.insert(key.clone(), local_handle);
        store.bindings.insert(binding, key);
        store.commands.insert(
            command_identity,
            CommandRecord {
                request_digest: request_digest_full,
                result: result.clone(),
            },
        );
        return Ok(result);
    }

    // 8. Fresh admission.
    if matches!(start_request.recovery, MaybeResume::Authorized(_)) {
        return Err(not_admitted(
            "explicit recovery requires an existing logical execution; recovery never creates one",
        ));
    }
    let queued = store
        .queue
        .iter()
        .filter(|local| {
            store
                .entries
                .get(*local)
                .is_some_and(|entry| entry.state == LocalState::AdmittedQueued)
        })
        .count();
    if queued >= MAX_QUEUED_WORK {
        return Err(reserved(
            "the admitted work queue is full; rejected work is reported, never silently lost",
        ));
    }
    let (owner_epoch, session_epoch) = lease_fence(start_request)?;
    rm_leases::validate_lease(
        &start_request.lease,
        &created_at,
        start_request.lease.entity_revision,
        start_request.lease.input_revision,
        &owner_epoch,
        &session_epoch,
    )?;
    verify_lease_resource(start_request, &prepared)?;
    let active_deadline = shift_time(
        &created_at,
        prepared.task.budgets.active_limit.value,
    )?;
    let handle = ConnectorHandle {
        record_type: HANDLE_RECORD_TYPE.to_string(),
        schema_version: CONNECTOR_SCHEMA_VERSION.to_string(),
        handle: HandleReference {
            connector_id: command.connector_id.clone(),
            local_handle: local_handle.clone(),
        },
        preparation: start_request.preparation.clone(),
        scope: admitted_scope.clone(),
        idempotency_key: start_request.idempotency_key.clone(),
        created_at: created_at.clone(),
    };
    let handle_bytes = to_bytes(&handle.to_json()?, "connector handle")?;
    let handle_artifact = install(principal, &handle_bytes, "dispatch")?;
    let response_value = start_receipt_json(
        StartDisposition::AcceptedLocally,
        &handle,
        &handle_artifact,
        None,
    )?;
    let response_artifact =
        install(principal, &to_bytes(&response_value, "start receipt")?, "dispatch")?;
    let input_artifact = install(
        principal,
        &to_bytes(&command.to_json()?, "connector command")?,
        "dispatch",
    )?;
    let submission_data = json!({
        "operation": "start",
        "request_id": command.request_id,
        "execution_binding": binding,
        "handle": handle.handle.to_json(),
        "handle_artifact": handle_artifact.to_json(),
        "response_artifact": response_artifact.to_json(),
        "input_artifact": input_artifact.to_json(),
        "request_digest": request_digest.as_str(),
        "idempotency_key": start_request.idempotency_key,
        "accepted_concern_ids": start_request.accepted_concern_ids,
        "dispatch_state": DispatchState::Prepared.as_str(),
        "local_state": LOCAL_STATE_ADMITTED_QUEUED,
        "active_deadline": time_json(&active_deadline)?,
        "lease": start_request.lease.to_json(),
        "authorization_refs": start_request.authorization_refs,
    });
    let receipt = commit_journal_event(
        principal,
        &start_request.manifest,
        &admitted_scope.journal_id,
        &handle_artifact,
        &response_artifact,
        &[&input_artifact, &start_request.preparation.artifact],
        submission_data,
        "dispatch_published",
        &created_at,
    )?;
    let dispatch = DispatchValue {
        state: DispatchState::Prepared,
        local_handle: MaybeString::Text(local_handle.clone()),
        native_run_id: MaybeString::Missing(Missing::new("not_observed")),
        request_digest: MaybeDigest::Present(request_digest.clone()),
        delivery_refs: Vec::new(),
        acceptance_refs: Vec::new(),
        recovery_authorization_refs: Vec::new(),
        reason: MaybeString::Missing(Missing::new("not_applicable")),
    };
    let mut entry = Entry {
        handle,
        handle_artifact,
        input_artifact,
        admission_receipt: receipt.clone(),
        last_receipt: receipt.clone(),
        manifest: start_request.manifest.clone(),
        commission: commission.cloned(),
        preparation_artifact: start_request.preparation.artifact.clone(),
        request_digest,
        idempotency_key: start_request.idempotency_key.clone(),
        owner_principal: principal.principal_id().to_string(),
        state: LocalState::AdmittedQueued,
        dispatch,
        lease: start_request.lease.clone(),
        entity_revision: start_request.lease.entity_revision,
        input_revision: start_request.lease.input_revision,
        owner_epoch,
        session_epoch,
        active_deadline,
        last_command_id: command.request_id.clone(),
        published_revision: 0,
        publication: PublicationState::NotApplicable(Missing::new("not_applicable")),
        recovered: false,
    };
    refresh_publication(principal, &mut entry);
    let result = result_from_entry(StartDisposition::AcceptedLocally, &entry);
    store.entries.insert(local_handle.clone(), entry);
    store.logical.insert(key.clone(), local_handle.clone());
    store.bindings.insert(binding, key);
    store.queue.push(local_handle);
    store.commands.insert(
        command_identity,
        CommandRecord {
            request_digest: request_digest_full,
            result: result.clone(),
        },
    );
    Ok(result)
}

fn start_operation(
    command: &ConnectorRequest,
    start_request: &StartRequest,
    prepared: &PreparedTask,
) -> Operation {
    Operation {
        verb: START_VERB.to_string(),
        connector_id: command.connector_id.clone(),
        subject_id: prepared.configuration.subject.subject_id.clone(),
        task_scope: format!("{}:{}", prepared.scope.activity, prepared.task.task_id),
        account_binding: prepared
            .runtime_access
            .first()
            .map(|access| access.access_ref.clone()),
        artifact_refs: vec![start_request
            .preparation
            .artifact
            .digest
            .as_str()
            .to_string()],
        control_target: None,
    }
}

fn admitted_scope(start_request: &StartRequest, prepared: &PreparedTask) -> WorkScope {
    let mut scope = prepared.scope.clone();
    scope.authorization_refs = start_request.authorization_refs.clone();
    scope
}

fn verify_preparation_binding(
    command: &ConnectorRequest,
    start_request: &StartRequest,
    prepared: &PreparedTask,
) -> Result<(), ConnectorError> {
    let scope = &prepared.scope;
    let journal_id = rm_evidence::journal_id_for(&start_request.manifest)?;
    if scope.journal_id != journal_id {
        return Err(stale(
            "preparation names a different journal than the admitted manifest",
        ));
    }
    if scope.run_id != start_request.manifest.run_id {
        return Err(stale("preparation run differs from the admitted manifest"));
    }
    if scope.manifest_hash != start_request.manifest.manifest_hash {
        return Err(stale(
            "preparation manifest binding differs from the admitted manifest",
        ));
    }
    if scope.admission_ref != start_request.manifest.admission_ref {
        return Err(stale(
            "preparation admission binding differs from the admitted manifest",
        ));
    }
    if command.connector_id != prepared.configuration.connector_id {
        return Err(invalid(
            "connector request identity must equal the pinned configuration connector",
        ));
    }
    let wire = rm_authority::manifest_wire_bytes(&start_request.manifest);
    let computed = rm_wire::canonical_digest(&wire)
        .map_err(|error| invalid(format!("manifest cannot be hashed: {error}")))?;
    if computed.as_str() != start_request.manifest.manifest_hash {
        return Err(not_admitted(
            "manifest hash does not cover the admitted manifest bytes",
        ));
    }
    match (&start_request.commission, &scope.attempt_id, &scope.commission_id) {
        (MaybeCommission::Present(commission), Some(attempt_id), Some(commission_id)) => {
            if &commission.attempt_id != attempt_id || &commission.commission_id != commission_id {
                return Err(stale(
                    "commission identity differs from the admitted preparation scope",
                ));
            }
            rm_authority::verify_attempt_scope(&start_request.manifest, commission)?;
            if commission.task_semantic_hash != prepared.task_semantic_hash.as_str() {
                return Err(stale(
                    "commission task semantic hash differs from the prepared task",
                ));
            }
            if scope.attempt_kind != Some(commission.kind) {
                return Err(stale(
                    "preparation attempt kind differs from the commissioned kind",
                ));
            }
        }
        (MaybeCommission::Missing(_), None, None) => {}
        _ => {
            return Err(not_admitted(
                "the commission binding must match the admitted preparation scope exactly",
            ))
        }
    }
    if scope.activity == "apply" && matches!(start_request.commission, MaybeCommission::Missing(_))
    {
        return Err(not_admitted(
            "application work requires its immutable attempt commission",
        ));
    }
    Ok(())
}

fn validate_concerns(
    start_request: &StartRequest,
    prepared: &PreparedTask,
) -> Result<(), ConnectorError> {
    let mut accepted = BTreeSet::new();
    for concern_id in &start_request.accepted_concern_ids {
        require_identifier("accepted_concern_id", concern_id)?;
        if !accepted.insert(concern_id.as_str()) {
            return Err(invalid(format!(
                "accepted concern {concern_id:?} is listed twice"
            )));
        }
    }
    for concern in &prepared.concerns {
        if concern.disposition == "requires_acceptance"
            && !accepted.contains(concern.concern_id.as_str())
        {
            return Err(not_admitted(format!(
                "preparation concern {:?} requires explicit acceptance before Start",
                concern.concern_id
            )));
        }
    }
    for concern_id in accepted {
        if !prepared
            .concerns
            .iter()
            .any(|concern| concern.concern_id == concern_id)
        {
            return Err(invalid(format!(
                "accepted concern {concern_id:?} is not declared by the preparation"
            )));
        }
    }
    Ok(())
}

fn lease_fence(start_request: &StartRequest) -> Result<(String, MaybeString), ConnectorError> {
    let owner_epoch = match &start_request.lease.owner_epoch {
        MaybeString::Text(text) => text.clone(),
        MaybeString::Missing(missing) => {
            return Err(not_admitted(format!(
                "a delivery lease requires a present owner_epoch fence, found missingness {:?}",
                missing.reason
            )))
        }
    };
    Ok((owner_epoch, start_request.lease.session_epoch.clone()))
}

fn verify_lease_resource(
    start_request: &StartRequest,
    prepared: &PreparedTask,
) -> Result<(), ConnectorError> {
    let expected = match &start_request.commission {
        MaybeCommission::Present(commission) => commission.attempt_id.as_str(),
        MaybeCommission::Missing(_) => prepared.task.task_id.as_str(),
    };
    if start_request.lease.resource.entity_id != expected {
        return Err(not_admitted(
            "the queued work must be leased to its exact attempt/task resource",
        ));
    }
    Ok(())
}

fn load_handle(
    principal: &AuthenticatedPrincipal,
    reference: &ArtifactReference,
) -> Result<ConnectorHandle, ConnectorError> {
    let bytes = rm_evidence::load_artifact(principal, reference)?;
    if bytes.len() as u64 != reference.size_bytes {
        return Err(integrity(
            "retained handle size does not match its artifact reference",
        ));
    }
    let value = parse_json_bytes(&bytes, "retained handle")?;
    ConnectorHandle::from_json(&value)
}

fn result_from_entry(disposition: StartDisposition, entry: &Entry) -> StartResult {
    StartResult {
        kind: START_RECEIPT_KIND.to_string(),
        disposition,
        handle: entry.handle.clone(),
        handle_artifact: entry.handle_artifact.clone(),
        receipt_ref: entry.admission_receipt.clone(),
    }
}

// ---------------------------------------------------------------------------
// Resume
// ---------------------------------------------------------------------------

fn resume_locked(
    principal: &AuthenticatedPrincipal,
    command: &ConnectorRequest,
    start_request: &StartRequest,
    entry: &mut Entry,
    request_digest: &Digest,
    store: &mut WorkStore,
) -> Result<StartResult, ConnectorError> {
    let authorization = match &start_request.recovery {
        MaybeResume::Authorized(authorization) => authorization,
        MaybeResume::Missing(_) => {
            return Err(invalid(
                "resume requires explicit recovery authorization; it never follows from a local timeout",
            ))
        }
    };
    if authorization.handle != entry.handle.handle {
        return Err(unknown_handle(
            "recovery authorization names a different logical handle",
        ));
    }
    if entry.request_digest != *request_digest {
        return Err(idempotency_conflict(
            "resume requires the same immutable request and context as the logical execution",
        ));
    }
    if command.request_id == entry.last_command_id {
        return Err(invalid(
            "resume requires a new command identity; the admitting command cannot be replayed as recovery",
        ));
    }
    if entry.state != LocalState::Assigned {
        return Err(stale(
            "explicit recovery requires evidenced native entry; this execution has no delivery attempt to resume",
        ));
    }
    if !matches!(
        entry.dispatch.state,
        DispatchState::Dispatching | DispatchState::Uncertain
    ) {
        return Err(stale(
            "dispatch is not in a resumable state; recovery never follows from a local timeout or lease expiry",
        ));
    }
    if authorization.authorization_refs.is_empty()
        || !authorization
            .authorization_refs
            .iter()
            .any(|grant| grant.starts_with("recovery:"))
    {
        return Err(forbidden(
            "resume requires explicit recovery authority grants, not task grants",
        ));
    }
    for grant in &authorization.authorization_refs {
        require_identifier("recovery authorization_ref", grant)?;
    }
    if authorization.evidence_refs.is_empty() {
        return Err(not_admitted(
            "resume requires source-backed native checkpoint evidence",
        ));
    }
    let now = local_now();
    if boundary_reached(&now, &entry.active_deadline)
        .map_err(|error| invalid(format!("active boundary cannot be compared: {error}")))?
    {
        return Err(stale(
            "the active boundary was already reached before native entry; recovery does not extend it",
        ));
    }
    authorization.checkpoint.validate()?;
    authorization.native_resume_contract.validate()?;
    let checkpoint_bytes = rm_evidence::load_artifact(principal, &authorization.checkpoint)?;
    if checkpoint_bytes.is_empty() {
        return Err(integrity("resume checkpoint artifact has no bytes"));
    }
    let contract_bytes =
        rm_evidence::load_artifact(principal, &authorization.native_resume_contract)?;
    if contract_bytes.is_empty() {
        return Err(integrity(
            "native resume contract artifact has no bytes",
        ));
    }
    let prefix = rm_evidence::journal_head(principal, &entry.handle.scope.journal_id)?;
    for reference in &authorization.evidence_refs {
        rm_evidence::resolve_evidence(principal, reference, &prefix)?;
    }

    // Journal the additional delivery intent before it happens.
    let intent_value = json!({
        "record_type": DELIVERY_INTENT_RECORD_TYPE,
        "schema_version": CONNECTOR_SCHEMA_VERSION,
        "operation": "resume",
        "handle": entry.handle.handle.to_json(),
        "request_digest": entry.request_digest.as_str(),
        "recovery_authorization_refs": authorization.authorization_refs,
        "checkpoint": authorization.checkpoint.to_json(),
        "native_resume_contract": authorization.native_resume_contract.to_json(),
        "evidence_refs": authorization.evidence_refs.iter().map(EvidenceRef::to_json).collect::<Vec<Value>>(),
    });
    let intent =
        install(principal, &to_bytes(&intent_value, "resume intent")?, "dispatch")?;
    let response_value = json!({
        "record_type": DELIVERY_RESPONSE_RECORD_TYPE,
        "schema_version": CONNECTOR_SCHEMA_VERSION,
        "kind": START_RECEIPT_KIND,
        "disposition": StartDisposition::ResumeAuthorized.as_str(),
        "handle": entry.handle.to_json()?,
        "handle_artifact": entry.handle_artifact.to_json(),
        "receipt_ref": missing_json(&Missing::with_detail(
            "not_observed",
            "receipt is assigned by the owner-local journal commit",
        )),
    });
    let response = install(
        principal,
        &to_bytes(&response_value, "resume receipt")?,
        "dispatch",
    )?;
    let submission_data = json!({
        "operation": "resume",
        "request_id": command.request_id,
        "handle": entry.handle.handle.to_json(),
        "handle_artifact": entry.handle_artifact.to_json(),
        "request_digest": entry.request_digest.as_str(),
        "idempotency_key": entry.idempotency_key,
        "dispatch_state": DispatchState::Dispatching.as_str(),
        "recovery_authorization_refs": authorization.authorization_refs,
        "evidence_refs": authorization.evidence_refs.iter().map(EvidenceRef::to_json).collect::<Vec<Value>>(),
        "input_artifact": entry.input_artifact.to_json(),
        "response_artifact": response.to_json(),
    });
    let receipt = commit_journal_event(
        principal,
        &entry.manifest,
        &entry.handle.scope.journal_id,
        &intent,
        &response,
        &[&entry.input_artifact, &entry.preparation_artifact],
        submission_data,
        "dispatch_published",
        &now,
    )?;
    entry.dispatch.state = DispatchState::Dispatching;
    entry.dispatch.delivery_refs.push(receipt.clone());
    entry
        .dispatch
        .recovery_authorization_refs
        .extend(authorization.authorization_refs.iter().cloned());
    entry.dispatch.reason = MaybeString::Missing(Missing::new("not_applicable"));
    entry.last_receipt = receipt.clone();
    entry.last_command_id = command.request_id.clone();
    entry.state = LocalState::AdmittedQueued;
    if !store.queue.contains(&entry.handle.handle.local_handle) {
        store
            .queue
            .push(entry.handle.handle.local_handle.clone());
    }
    refresh_publication(principal, entry);
    Ok(StartResult {
        kind: START_RECEIPT_KIND.to_string(),
        disposition: StartDisposition::ResumeAuthorized,
        handle: entry.handle.clone(),
        handle_artifact: entry.handle_artifact.clone(),
        receipt_ref: receipt,
    })
}

// ---------------------------------------------------------------------------
// Claiming
// ---------------------------------------------------------------------------

/// Claims one admitted, still-authorized execution for delivery.
///
/// Queue time is part of the active budget: an entry whose boundary was
/// reached before native entry is recorded as expired and never delivered. A
/// held lease must still validate at claim time. Claiming records the durable
/// dispatching intent before the handle is returned; a second claim never
/// returns the same logical execution.
pub fn claim_work(
    principal: &AuthenticatedPrincipal,
    now: &TimePoint,
) -> Result<Option<ConnectorHandle>, ConnectorError> {
    check_principal(principal)?;
    validate_timepoint(now, "now")?;
    let mut store = lock_work();
    let mut position = 0;
    while position < store.queue.len() {
        let local = store.queue[position].clone();
        let eligible = store
            .entries
            .get(&local)
            .is_some_and(|entry| {
                entry.owner_principal == principal.principal_id()
                    && entry.state == LocalState::AdmittedQueued
            });
        if !eligible {
            position += 1;
            continue;
        }
        let reached = {
            let entry = &store.entries[&local];
            boundary_reached(now, &entry.active_deadline)
                .map_err(|error| invalid(format!("active boundary cannot be compared: {error}")))?
        };
        if reached {
            let entry = store
                .entries
                .get_mut(&local)
                .ok_or_else(|| integrity("queue points at a missing handle record"))?;
            expire_locked(principal, entry, now)?;
            store.queue.remove(position);
            continue;
        }
        let lease_result = {
            let entry = &store.entries[&local];
            rm_leases::validate_lease(
                &entry.lease,
                now,
                entry.entity_revision,
                entry.input_revision,
                &entry.owner_epoch,
                &entry.session_epoch,
            )
        };
        if let Err(error) = lease_result {
            let entry = store
                .entries
                .get_mut(&local)
                .ok_or_else(|| integrity("queue points at a missing handle record"))?;
            fence_locked(principal, entry, now, &error)?;
            store.queue.remove(position);
            continue;
        }
        let handle = {
            let entry = store
                .entries
                .get_mut(&local)
                .ok_or_else(|| integrity("queue points at a missing handle record"))?;
            claim_locked(principal, entry, now)?
        };
        store.queue.remove(position);
        return Ok(Some(handle));
    }
    Ok(None)
}

fn claim_locked(
    principal: &AuthenticatedPrincipal,
    entry: &mut Entry,
    now: &TimePoint,
) -> Result<ConnectorHandle, ConnectorError> {
    let delivery_index = entry.dispatch.delivery_refs.len() as u64 + 1;
    let receipt = commit_dispatch_effect(
        principal,
        entry,
        DELIVERY_INTENT_RECORD_TYPE,
        "claim",
        DispatchState::Dispatching,
        now,
        json!({ "delivery_index": delivery_index }),
    )?;
    if entry.dispatch.state == DispatchState::Prepared {
        entry.dispatch.state = DispatchState::Dispatching;
    }
    entry.dispatch.delivery_refs.push(receipt.clone());
    entry.dispatch.reason = MaybeString::Missing(Missing::new("not_applicable"));
    entry.last_receipt = receipt;
    entry.state = LocalState::Assigned;
    refresh_publication(principal, entry);
    Ok(entry.handle.clone())
}

fn expire_locked(
    principal: &AuthenticatedPrincipal,
    entry: &mut Entry,
    now: &TimePoint,
) -> Result<(), ConnectorError> {
    let receipt = commit_dispatch_effect(
        principal,
        entry,
        DELIVERY_DECISION_RECORD_TYPE,
        "expire_before_entry",
        DispatchState::Rejected,
        now,
        json!({
            "reason": "queue_expired_before_entry",
            "active_deadline": time_json(&entry.active_deadline)?,
        }),
    )?;
    entry.state = LocalState::ExpiredBeforeEntry;
    entry.dispatch.state = DispatchState::Rejected;
    entry.dispatch.reason =
        MaybeString::Text("queue_expired_before_entry".to_string());
    entry.last_receipt = receipt;
    refresh_publication(principal, entry);
    Ok(())
}

fn fence_locked(
    principal: &AuthenticatedPrincipal,
    entry: &mut Entry,
    now: &TimePoint,
    lease_error: &ConnectorError,
) -> Result<(), ConnectorError> {
    let receipt = commit_dispatch_effect(
        principal,
        entry,
        DELIVERY_DECISION_RECORD_TYPE,
        "fence_before_entry",
        DispatchState::Rejected,
        now,
        json!({
            "reason": "fenced_before_entry",
            "lease_code": lease_error.code,
            "lease_detail": lease_error.detail,
        }),
    )?;
    entry.state = LocalState::Fenced;
    entry.dispatch.state = DispatchState::Rejected;
    entry.dispatch.reason = MaybeString::Text("fenced_before_entry".to_string());
    entry.last_receipt = receipt;
    refresh_publication(principal, entry);
    Ok(())
}

fn commit_dispatch_effect(
    principal: &AuthenticatedPrincipal,
    entry: &Entry,
    record_type: &str,
    action: &str,
    state: DispatchState,
    occurred_at: &TimePoint,
    detail: Value,
) -> Result<EvidenceRef, ConnectorError> {
    let effect_value = json!({
        "record_type": record_type,
        "schema_version": CONNECTOR_SCHEMA_VERSION,
        "action": action,
        "handle": entry.handle.handle.to_json(),
        "request_digest": entry.request_digest.as_str(),
        "idempotency_key": entry.idempotency_key,
        "dispatch_state": state.as_str(),
        "detail": detail,
        "occurred_at": time_json(occurred_at)?,
    });
    let effect = install(
        principal,
        &to_bytes(&effect_value, "dispatch effect")?,
        "dispatch",
    )?;
    let response_value = json!({
        "record_type": DELIVERY_RESPONSE_RECORD_TYPE,
        "schema_version": CONNECTOR_SCHEMA_VERSION,
        "action": action,
        "handle": entry.handle.handle.to_json(),
        "dispatch_state": state.as_str(),
        "receipt_ref": missing_json(&Missing::with_detail(
            "not_observed",
            "receipt is assigned by the owner-local journal commit",
        )),
    });
    let response = install(
        principal,
        &to_bytes(&response_value, "delivery response")?,
        "dispatch",
    )?;
    let data = json!({
        "operation": action,
        "handle": entry.handle.handle.to_json(),
        "handle_artifact": entry.handle_artifact.to_json(),
        "request_digest": entry.request_digest.as_str(),
        "idempotency_key": entry.idempotency_key,
        "dispatch_state": state.as_str(),
        "detail": detail,
        "input_artifact": entry.input_artifact.to_json(),
        "response_artifact": response.to_json(),
    });
    commit_journal_event(
        principal,
        &entry.manifest,
        &entry.handle.scope.journal_id,
        &effect,
        &response,
        &[&entry.input_artifact, &entry.preparation_artifact],
        data,
        "dispatch_published",
        occurred_at,
    )
}

// ---------------------------------------------------------------------------
// Dispatch publication
// ---------------------------------------------------------------------------

fn refresh_publication(principal: &AuthenticatedPrincipal, entry: &mut Entry) {
    if entry.recovered {
        entry.publication = PublicationState::Pending(Missing::with_detail(
            "not_observed",
            "dispatch publication reconciled after a restart; the local history is authoritative",
        ));
        return;
    }
    let commission = match &entry.commission {
        Some(commission) => commission.clone(),
        None => {
            entry.publication = PublicationState::NotApplicable(Missing::with_detail(
                "not_applicable",
                "discovery work carries no application attempt axis",
            ));
            return;
        }
    };
    match publish_entry_revision(principal, entry, &commission) {
        Ok(reference) => {
            entry.published_revision = entry.published_revision.saturating_add(1);
            entry.publication = PublicationState::Published(reference);
        }
        Err(error) => {
            entry.publication = PublicationState::Pending(Missing::with_detail(
                "not_observed",
                format!(
                    "dispatch axis publication pending: {} {}",
                    error.code, error.detail
                ),
            ));
        }
    }
}

fn publish_entry_revision(
    principal: &AuthenticatedPrincipal,
    entry: &Entry,
    commission: &AttemptCommission,
) -> Result<LifecyclePublicationReference, ConnectorError> {
    let prefix = rm_evidence::journal_head(principal, &commission.journal_id)?;
    let revision_number = entry.published_revision + 1;
    let revision = AxisRevision {
        record_type: AXIS_REVISION_RECORD_TYPE.to_string(),
        schema_version: LIFECYCLE_SCHEMA_VERSION.to_string(),
        attempt: AttemptContext {
            attempt_id: commission.attempt_id.clone(),
            kind: commission.kind,
            target_class: commission.target_class,
            target_id: commission.target_id.clone(),
            evaluation_partition: commission.evaluation_partition,
        },
        commission_digest: commission_digest(commission)?,
        axis: Axis::Dispatch,
        owner_domain: "dispatch".to_string(),
        writer_id: principal.principal_id().to_string(),
        revision: revision_number,
        previous_revision: entry.published_revision,
        evidence_prefix: prefix,
        evidence_refs: vec![entry.last_receipt.clone()],
        value: AxisValue::Dispatch(entry.dispatch.clone()),
    };
    publish_axis(principal, commission, &revision)
}

// ---------------------------------------------------------------------------
// Owner control
// ---------------------------------------------------------------------------

/// Admits one owner control command on the independent control queue.
///
/// The control admission commits its own journal evidence and never waits on
/// workflow delivery progress. `(principal, connector_id, request_id)`
/// identifies the command: an identical retry returns the retained receipt and
/// conflicting content under that key is rejected.
pub fn enqueue_owner_control(
    principal: &AuthenticatedPrincipal,
    request: &ConnectorRequest,
) -> Result<EvidenceRef, ConnectorError> {
    check_principal(principal)?;
    validate_envelope(request)?;
    if !CONTROL_VERBS.contains(&request.operation.as_str()) {
        return Err(invalid(format!(
            "operation {:?} is not an owner control verb",
            request.operation
        )));
    }
    let control = match &request.payload {
        CommandPayload::Control(control) => control,
        CommandPayload::Start(_) => {
            return Err(invalid(
                "control operations require a control payload; Start uses the workflow queue",
            ))
        }
    };
    control.handle.validate()?;
    if control.handle.connector_id != request.connector_id {
        return Err(invalid(
            "control handle connector identity must equal the request connector identity",
        ));
    }
    validate_scope(&control.scope)?;
    let journal_id = rm_evidence::journal_id_for(&control.manifest)?;
    if control.scope.journal_id != journal_id {
        return Err(stale(
            "control scope names a different journal than the admitted manifest",
        ));
    }
    let wire = rm_authority::manifest_wire_bytes(&control.manifest);
    let computed = rm_wire::canonical_digest(&wire)
        .map_err(|error| invalid(format!("manifest cannot be hashed: {error}")))?;
    if computed.as_str() != control.manifest.manifest_hash {
        return Err(not_admitted(
            "manifest hash does not cover the admitted manifest bytes",
        ));
    }
    if control
        .scope
        .authorization_refs
        .iter()
        .any(|grant| !grant.starts_with("control:"))
    {
        return Err(forbidden(
            "control operations require scoped control grants; task grants do not authorize control",
        ));
    }
    let subject_id = control
        .manifest
        .subject
        .get("subject_id")
        .and_then(Value::as_str)
        .unwrap_or(control.scope.owner_domain.as_str())
        .to_string();
    let operation = Operation {
        verb: request.operation.clone(),
        connector_id: request.connector_id.clone(),
        subject_id,
        task_scope: format!("{}:{}", control.scope.activity, control.handle.local_handle),
        account_binding: None,
        artifact_refs: Vec::new(),
        control_target: Some(control.handle.local_handle.clone()),
    };
    rm_authority::authorize_work(principal, &control.scope, &operation)?;

    let identity = command_key(principal, &request.connector_id, &request.request_id);
    let digest = command_digest(request)?;
    let mut store = lock_control();
    if let Some(record) = store.receipts.get(&identity) {
        if record.request_digest != digest {
            return Err(idempotency_conflict(
                "the same control command identity was reused with different content",
            ));
        }
        return Ok(record.receipt.clone());
    }

    // Admitted input, effect, and replayable response commit as one
    // owner-local journal effect before acknowledgement.
    let occurred_at = local_now();
    let effect = install(
        principal,
        &to_bytes(&request.to_json()?, "control command")?,
        "control",
    )?;
    let response_value = json!({
        "record_type": DELIVERY_RESPONSE_RECORD_TYPE,
        "schema_version": CONNECTOR_SCHEMA_VERSION,
        "kind": "control_receipt",
        "operation": request.operation,
        "handle": control.handle.to_json(),
        "receipt_ref": missing_json(&Missing::with_detail(
            "not_observed",
            "receipt is assigned by the owner-local journal commit",
        )),
    });
    let response = install(
        principal,
        &to_bytes(&response_value, "control receipt")?,
        "control",
    )?;
    let data = json!({
        "operation": request.operation,
        "handle": control.handle.to_json(),
        "request_id": request.request_id,
        "control_target": control.handle.local_handle,
        "input_artifact": effect.to_json(),
        "response_artifact": response.to_json(),
    });
    let receipt = commit_journal_event(
        principal,
        &control.manifest,
        &control.scope.journal_id,
        &effect,
        &response,
        &[],
        data,
        "control_observation",
        &occurred_at,
    )?;
    store.receipts.insert(
        identity,
        ControlRecord {
            request_digest: digest,
            receipt: receipt.clone(),
        },
    );
    let queue_key = control_queue_key(
        principal,
        &control.handle.connector_id,
        &control.handle.local_handle,
    );
    store
        .queues
        .entry(queue_key)
        .or_default()
        .push_back(request.clone());
    Ok(receipt)
}

/// Takes the oldest admitted owner control command for one handle.
///
/// Control commands are taken per handle and per authenticated connector
/// identity; they are never gated on workflow delivery.
pub fn take_owner_control(
    principal: &AuthenticatedPrincipal,
    handle: &ConnectorHandle,
) -> Result<Option<ConnectorRequest>, ConnectorError> {
    check_principal(principal)?;
    handle.validate()?;
    let mut store = lock_control();
    let key = control_queue_key(principal, &handle.handle.connector_id, &handle.handle.local_handle);
    let request = match store.queues.get_mut(&key) {
        Some(queue) => queue.pop_front(),
        None => None,
    };
    let empty = store
        .queues
        .get(&key)
        .is_some_and(|queue| queue.is_empty());
    if empty {
        store.queues.remove(&key);
    }
    Ok(request)
}

// ---------------------------------------------------------------------------
// Read-only projections
// ---------------------------------------------------------------------------

/// Returns the retained dispatch value for one handle.
///
/// A dispatching value is not acceptance: the caller must await source-backed
/// native evidence. A rejected value carries the explicit non-delivery reason.
pub fn dispatch_value(
    principal: &AuthenticatedPrincipal,
    handle: &ConnectorHandle,
) -> Result<DispatchValue, ConnectorError> {
    check_principal(principal)?;
    handle.validate()?;
    let store = lock_work();
    let entry = store
        .entries
        .get(&handle.handle.local_handle)
        .ok_or_else(|| unknown_handle("no retained dispatch exists for this handle"))?;
    if entry.owner_principal != principal.principal_id()
        || entry.handle.handle != handle.handle
    {
        return Err(unknown_handle("no retained dispatch exists for this handle"));
    }
    Ok(entry.dispatch.clone())
}

/// Returns the owner-local scheduling state for one handle.
pub fn local_state(
    principal: &AuthenticatedPrincipal,
    handle: &ConnectorHandle,
) -> Result<String, ConnectorError> {
    check_principal(principal)?;
    handle.validate()?;
    let store = lock_work();
    let entry = store
        .entries
        .get(&handle.handle.local_handle)
        .ok_or_else(|| unknown_handle("no retained dispatch exists for this handle"))?;
    if entry.owner_principal != principal.principal_id() {
        return Err(unknown_handle("no retained dispatch exists for this handle"));
    }
    Ok(entry.state.as_str().to_string())
}

/// Returns the dispatch-axis publication state for one handle.
pub fn lifecycle_publication(
    principal: &AuthenticatedPrincipal,
    handle: &ConnectorHandle,
) -> Result<PublicationState, ConnectorError> {
    check_principal(principal)?;
    handle.validate()?;
    let store = lock_work();
    let entry = store
        .entries
        .get(&handle.handle.local_handle)
        .ok_or_else(|| unknown_handle("no retained dispatch exists for this handle"))?;
    if entry.owner_principal != principal.principal_id() {
        return Err(unknown_handle("no retained dispatch exists for this handle"));
    }
    Ok(entry.publication.clone())
}

// ---------------------------------------------------------------------------
// Crash recovery
// ---------------------------------------------------------------------------

/// Reconstructs one logical execution from retained journal evidence alone.
///
/// This is the restart path: the local memory cache is never trusted over the
/// journal. An admission with no delivery attempt is `Deliverable` within its
/// original boundary; an admission followed by a delivery attempt is
/// `AwaitingEvidence` and must never be resent merely to repair local state.
pub fn recover_delivery(
    principal: &AuthenticatedPrincipal,
    command: &ConnectorRequest,
) -> Result<Option<RecoveredDelivery>, ConnectorError> {
    check_principal(principal)?;
    validate_envelope(command)?;
    let start_request = match &command.payload {
        CommandPayload::Start(start_request) => start_request,
        CommandPayload::Control(_) => {
            return Err(invalid("recovery reads Start history, not a control command"))
        }
    };
    if command.operation != START_VERB {
        return Err(invalid(format!(
            "operation {:?} must be {START_VERB:?}",
            command.operation
        )));
    }
    let prepared = rm_preparation::verify_preparation(principal, &start_request.preparation)?;
    verify_preparation_binding(command, start_request, &prepared)?;
    let request_digest = immutable_request_digest(command, start_request, &prepared)?;
    let commission = match &start_request.commission {
        MaybeCommission::Present(commission) => Some(commission),
        MaybeCommission::Missing(_) => None,
    };
    let binding = execution_binding(&prepared, commission);
    let key = logical_key(principal, &command.connector_id, &start_request.idempotency_key);
    let local_handle = deterministic_handle(&key);
    recover_from_journal(
        principal,
        &local_handle,
        &request_digest,
        &binding,
        &start_request.manifest,
        prepared.evidence_prefix.last_sequence.get(),
    )
}

fn recover_from_journal(
    principal: &AuthenticatedPrincipal,
    local_handle: &str,
    request_digest: &Digest,
    execution_binding: &str,
    manifest: &Manifest,
    from_sequence: u64,
) -> Result<Option<RecoveredDelivery>, ConnectorError> {
    let journal_id = rm_evidence::journal_id_for(manifest)?;
    let head = match rm_evidence::journal_head(principal, &journal_id) {
        Ok(prefix) => prefix,
        Err(_) => return Ok(None),
    };
    let end = head.last_sequence.get();
    if end <= from_sequence {
        return Ok(None);
    }
    if end - from_sequence > MAX_RECOVERY_SCAN {
        return Err(prerequisite(
            "recovery scan bound exceeded; the retained prefix cannot be reconstructed within the finite local bound",
        ));
    }
    let mut admission: Option<(JournalEnvelope, EvidenceRef)> = None;
    let mut history: Vec<(JournalEnvelope, EvidenceRef)> = Vec::new();
    let mut last_command_id = String::new();
    for sequence in from_sequence + 1..=end {
        let positive = PositiveInteger::new(sequence)
            .map_err(|error| invalid(format!("journal sequence is invalid: {error}")))?;
        let envelope = rm_evidence::read_event(principal, &journal_id, positive)?;
        if envelope.event_kind != "dispatch_published" {
            continue;
        }
        let data = &envelope.payload.data;
        let operation = data.get("operation").and_then(Value::as_str).unwrap_or_default();
        // One application commission cannot acquire a second logical
        // execution by changing keys across a restart: the durable admission
        // records its execution binding.
        if operation == "start"
            && data.get("execution_binding").and_then(Value::as_str) == Some(execution_binding)
        {
            let admitted_handle = data
                .get("handle")
                .and_then(|handle| handle.get("local_handle"))
                .and_then(Value::as_str);
            if admitted_handle != Some(local_handle) {
                return Err(idempotency_conflict(
                    "this attempt/task already owns a durable logical execution; changing the idempotency key, caller, or executor never authorizes a second",
                ));
            }
        }
        let handle_matches = data
            .get("handle")
            .and_then(|handle| handle.get("local_handle"))
            .and_then(Value::as_str)
            == Some(local_handle);
        let digest_matches =
            data.get("request_digest").and_then(Value::as_str) == Some(request_digest.as_str());
        if !handle_matches || !digest_matches {
            continue;
        }
        let reference = evidence_ref_for(&envelope)?;
        if operation == "start" && admission.is_none() {
            admission = Some((envelope.clone(), reference.clone()));
        }
        if let Some(command_id) = data.get("request_id").and_then(Value::as_str) {
            last_command_id = command_id.to_string();
        }
        history.push((envelope, reference));
    }
    let Some((admission_envelope, admission_receipt)) = admission else {
        return Ok(None);
    };
    let admission_data = &admission_envelope.payload.data;
    let handle_artifact = ArtifactReference::from_json(field(
        admission_data
            .as_object()
            .ok_or_else(|| integrity("dispatch admission data is not an object"))?,
        "handle_artifact",
        "dispatch admission",
    )?)?;
    let input_artifact = ArtifactReference::from_json(field(
        admission_data
            .as_object()
            .ok_or_else(|| integrity("dispatch admission data is not an object"))?,
        "input_artifact",
        "dispatch admission",
    )?)?;
    let response_artifact = ArtifactReference::from_json(field(
        admission_data
            .as_object()
            .ok_or_else(|| integrity("dispatch admission data is not an object"))?,
        "response_artifact",
        "dispatch admission",
    )?)?;
    let handle = load_handle(principal, &handle_artifact)?;
    if handle.handle.local_handle != local_handle {
        return Err(integrity(
            "retained handle artifact names a different logical handle",
        ));
    }
    let lease = rm_leases::LeaseRecord::from_json(field(
        admission_data
            .as_object()
            .ok_or_else(|| integrity("dispatch admission data is not an object"))?,
        "lease",
        "dispatch admission",
    )?)?;
    let active_deadline = time_from_json(
        field(
            admission_data
                .as_object()
                .ok_or_else(|| integrity("dispatch admission data is not an object"))?,
            "active_deadline",
            "dispatch admission",
        )?,
        "active_deadline",
    )?;
    let mut dispatch = DispatchValue {
        state: DispatchState::Prepared,
        local_handle: MaybeString::Text(local_handle.to_string()),
        native_run_id: MaybeString::Missing(Missing::new("not_observed")),
        request_digest: MaybeDigest::Present(request_digest.clone()),
        delivery_refs: Vec::new(),
        acceptance_refs: Vec::new(),
        recovery_authorization_refs: Vec::new(),
        reason: MaybeString::Missing(Missing::new("not_applicable")),
    };
    let mut state = RecoveryState::Deliverable;
    for (envelope, reference) in &history {
        let data = &envelope.payload.data;
        let operation = data
            .get("operation")
            .and_then(Value::as_str)
            .unwrap_or_default();
        match operation {
            "start" => {}
            "claim" => {
                dispatch.state = DispatchState::Dispatching;
                dispatch.delivery_refs.push(reference.clone());
                if state == RecoveryState::Deliverable {
                    state = RecoveryState::AwaitingEvidence;
                }
            }
            "resume" => {
                dispatch.state = DispatchState::Dispatching;
                dispatch.delivery_refs.push(reference.clone());
                if let Some(grants) = data.get("recovery_authorization_refs").and_then(Value::as_array)
                {
                    for grant in grants {
                        if let Some(text) = grant.as_str() {
                            dispatch.recovery_authorization_refs.push(text.to_string());
                        }
                    }
                }
                state = RecoveryState::Deliverable;
            }
            "expire_before_entry" => {
                dispatch.state = DispatchState::Rejected;
                dispatch.reason =
                    MaybeString::Text("queue_expired_before_entry".to_string());
                state = RecoveryState::ExpiredBeforeEntry;
            }
            "fence_before_entry" => {
                dispatch.state = DispatchState::Rejected;
                dispatch.reason = MaybeString::Text("fenced_before_entry".to_string());
                state = RecoveryState::Fenced;
            }
            _ => {}
        }
    }
    // Queue time is part of the active budget. A recovery read also reports a
    // boundary that elapsed while no delivery happened.
    if state == RecoveryState::Deliverable {
        let now = local_now();
        if boundary_reached(&now, &active_deadline)
            .map_err(|error| invalid(format!("active boundary cannot be compared: {error}")))?
        {
            state = RecoveryState::ExpiredBeforeEntry;
            dispatch.state = DispatchState::Rejected;
            dispatch.reason = MaybeString::Text("queue_expired_before_entry".to_string());
        }
    }
    Ok(Some(RecoveredDelivery {
        handle,
        handle_artifact,
        input_artifact,
        response_artifact,
        admission_receipt,
        dispatch,
        state,
        active_deadline,
        lease,
        last_command_id,
    }))
}

#[allow(clippy::too_many_arguments)]
fn recovered_entry(
    principal: &AuthenticatedPrincipal,
    start_request: &StartRequest,
    prepared: &PreparedTask,
    handle: ConnectorHandle,
    handle_artifact: ArtifactReference,
    input_artifact: ArtifactReference,
    admission_receipt: EvidenceRef,
    dispatch: DispatchValue,
    recovery_state: RecoveryState,
    active_deadline: TimePoint,
    lease: rm_leases::LeaseRecord,
    last_command_id: String,
    request_digest: &Digest,
) -> Result<Entry, ConnectorError> {
    if handle.preparation != start_request.preparation {
        return Err(integrity(
            "retained handle preparation differs from the verified preparation",
        ));
    }
    if handle.idempotency_key != start_request.idempotency_key {
        return Err(integrity(
            "retained handle idempotency key differs from the admitted request",
        ));
    }
    let journal_id = rm_evidence::journal_id_for(&start_request.manifest)?;
    if handle.scope.journal_id != journal_id
        || handle.scope.run_id != start_request.manifest.run_id
        || handle.scope.manifest_hash != start_request.manifest.manifest_hash
        || handle.scope.admission_ref != start_request.manifest.admission_ref
        || handle.scope.activity != prepared.scope.activity
    {
        return Err(integrity(
            "retained handle scope differs from the admitted manifest and preparation",
        ));
    }
    if handle.handle.connector_id != prepared.configuration.connector_id {
        return Err(integrity(
            "retained handle connector identity differs from the pinned configuration",
        ));
    }
    match (&start_request.commission, &handle.scope.attempt_id) {
        (MaybeCommission::Present(commission), Some(attempt_id))
            if &commission.attempt_id == attempt_id => {}
        (MaybeCommission::Missing(_), None) => {}
        _ => {
            return Err(integrity(
                "retained handle attempt binding differs from the admitted commission",
            ))
        }
    }
    verify_lease_resource(start_request, prepared)?;
    let (owner_epoch, session_epoch) = lease_fence(start_request)?;
    let commission = match &start_request.commission {
        MaybeCommission::Present(commission) => Some(commission.clone()),
        MaybeCommission::Missing(_) => None,
    };
    let last_receipt = dispatch
        .delivery_refs
        .last()
        .cloned()
        .unwrap_or_else(|| admission_receipt.clone());
    let state = match recovery_state {
        RecoveryState::Deliverable => LocalState::AdmittedQueued,
        RecoveryState::AwaitingEvidence => LocalState::Assigned,
        RecoveryState::ExpiredBeforeEntry => LocalState::ExpiredBeforeEntry,
        RecoveryState::Fenced => LocalState::Fenced,
    };
    Ok(Entry {
        handle,
        handle_artifact,
        input_artifact,
        admission_receipt,
        last_receipt,
        manifest: start_request.manifest.clone(),
        commission,
        preparation_artifact: start_request.preparation.artifact.clone(),
        request_digest: request_digest.clone(),
        idempotency_key: start_request.idempotency_key.clone(),
        owner_principal: principal.principal_id().to_string(),
        state,
        dispatch,
        lease: lease.clone(),
        entity_revision: lease.entity_revision,
        input_revision: lease.input_revision,
        owner_epoch,
        session_epoch,
        active_deadline,
        last_command_id,
        published_revision: 0,
        publication: recovered_publication_pending(),
        recovered: true,
    })
}

fn recovered_publication_pending() -> PublicationState {
    PublicationState::Pending(Missing::with_detail(
        "not_observed",
        "dispatch publication reconciled after a restart; the retained journal is authoritative",
    ))
}

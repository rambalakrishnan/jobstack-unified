//! `rm_controls`: tier-7 Ringmaster connector control boundary.
//!
//! Implements the complete control behavior of seam mapping §15 with the
//! observation-window closure of §16.4 and the run/crash rules of §18
//! (EXT-CONTROLS, EXT-CLOSE, EXT-BOUNDS, LIFE-CONTROLS, LIFE-CLOSE,
//! LIFE-LATE-EVIDENCE, BO-TIME):
//!
//! - [`control`] admits one control command for one logical handle. It
//!   authorizes the operation against the admitted control scope, resolves the
//!   operation's mapping and opportunity from the pinned connector descriptor,
//!   records the resulting [`ControlObservation`] as a `control_observation`
//!   journal event, and hands the command to the owner's independent control
//!   queue. Nothing is ever executed on the control thread.
//! - Request, acknowledgement, and effect stay distinct. A refused mapping is
//!   `unsupported` (never native absence), an admitted request is `requested`,
//!   `acknowledged` requires a verified correlated response, and
//!   `effect_observed` requires nonempty actual effect references. A subject's
//!   confirmed-stop statement is retained as a claim and never upgrades the
//!   disposition or a close-time knowledge boundary.
//! - [`record_control_response`] appends a *new* observation (new
//!   `control_event_id`, same `operation_id`) for a correlated response or
//!   claim. It never rewrites a retained receipt.
//! - [`close_at_boundary`] closes the observation window at the local boundary
//!   and returns the immutable observation-axis [`AxisRevision`] for the
//!   lifecycle owner to publish. Local finalization never depends on native
//!   cancellation support: a cancellation mapping the descriptor does not
//!   disclose neither delays nor blocks bounded finalization.
//! - A closed window never reopens. Evidence received after closure is carried
//!   by a closed-to-closed revision that preserves every original closure field
//!   and appends the new late-evidence references.
//!
//! Bounds (EXT-BOUNDS) are finite, local, and monotonic: call allowances are
//! validated, drain/cleanup/cancellation-wait bounds are pinned local limits,
//! and every ordering decision uses [`rm_time::boundary_reached`] on one
//! registered clock/boot/origin. UTC annotations are never consulted.
//!
//! Control commands carry no resource lease claim, so no `LeaseRecord` is
//! consumed here: a control request is never lease authority (§18).
//!
//! Read-only recoveries beyond the minimum consumed set: the attempt identity
//! and commission digest for an observation closure come from the attempt's own
//! published `dispatch` revision ([`rm_delivery::lifecycle_publication`]),
//! and the admitted local boundary comes from the retained
//! `dispatch_published` journal event ([`rm_evidence::read_event`], bounded).
//! Neither read confers authority; a pending publication or a missing
//! journaled boundary is a prerequisite failure, never a guessed identity.
//!
//! No in-band nulls: every absence is a typed [`Missing`] envelope.

#![forbid(unsafe_code)]
#![allow(clippy::result_large_err)]

use std::collections::BTreeSet;
use std::sync::{LazyLock, Mutex, MutexGuard};
use std::time::Instant;

use rm_authority::{
    AttemptKind, AuthenticatedPrincipal, ConnectorError, Manifest, Operation, WorkScope,
};
use rm_catalog::{DescribeRequest, DurationLimit, OperationMapping, VersionPin};
use rm_delivery::{
    CommandPayload as DeliveryPayload, ConnectorHandle, ConnectorRequest as DeliveryRequest,
    ControlRequest as DeliveryControl, HandleReference, PublicationState,
};
use rm_evidence::{
    EvidencePayload, EvidenceRef, EventSubmission, JournalEnvelope, PositiveInteger,
};
use rm_lifecycle::{
    AppKnowledge, AuthStatus, Axis, AxisRevision, AxisValue, CloseReason,
    CloseSnapshot, CorrelationStatus, ExecKnowledge, MaybeCloseReason, MaybeCloseSnapshot,
    ObservationState, ObservationValue, VersionVector, AXIS_REVISION_RECORD_TYPE,
    LIFECYCLE_SCHEMA_VERSION,
};
use rm_time::{
    Censoring, ClockDescriptor, Estimate, MaybeNumber, MaybeString, MaybeTimePoint, Measurement,
    MeasurementOrigin, Method, Missing, Quantity, Scope, ScopeKind, TimePoint, UtcAnnotation,
};
use serde_json::{json, Value};

// ---------------------------------------------------------------------------
// Vocabulary and pinned local bounds
// ---------------------------------------------------------------------------

/// Control command envelope record type.
pub const CONTROL_REQUEST_RECORD_TYPE: &str = "connector_request";
/// External connector schema version carried by a control command.
pub const CONTROL_SCHEMA_VERSION: &str = "external-connector/0.1.0";
/// Control receipt kind (§15.2).
pub const CONTROL_RECEIPT_KIND: &str = "control_receipt";
/// Journal event kind carrying one control observation.
pub const CONTROL_OBSERVATION_KIND: &str = "control_observation";
/// Registered schema version of a control observation event.
pub const CONTROL_OBSERVATION_EVENT_SCHEMA: &str = "evidence-kernel/0.1.0";
/// Owner domain of the observation axis.
pub const OBSERVATION_DOMAIN: &str = "observation";

/// Pinned bound on the guarded local drain started by `end_observation=true`.
pub const PINNED_DRAIN_LIMIT_MS: f64 = 2_000.0;
/// Pinned bound on waiting for a native cancellation acknowledgement.
///
/// The bound is recorded and enforced whenever a cancellation *is* mapped; it
/// never gates local finalization, because finalization does not depend on it.
pub const PINNED_NATIVE_CANCEL_WAIT_LIMIT_MS: f64 = 1_000.0;
/// Pinned bound on the post-close cleanup wait.
pub const PINNED_CLEANUP_WAIT_LIMIT_MS: f64 = 1_000.0;
/// Bound on one journal scan for retained control and boundary evidence.
const MAX_JOURNAL_SCAN: u64 = 4096;
/// Retries allowed when another writer advances the journal under a commit.
const APPEND_ATTEMPTS: usize = 3;

// ---------------------------------------------------------------------------
// Failure envelope helpers (§17 vocabulary)
// ---------------------------------------------------------------------------

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

fn prerequisite(detail: impl Into<String>) -> ConnectorError {
    connector_error(
        "PREREQUISITE_UNAVAILABLE",
        "policy",
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
            "channel identity is not established".to_string(),
            "not_dispatched",
            "operator_review",
        ));
    }
    Ok(())
}

fn require_identifier(field: &str, value: &str) -> Result<(), ConnectorError> {
    if value.is_empty() {
        return Err(invalid(format!("{field} must be nonempty")));
    }
    Ok(())
}

fn resolve_retained(
    principal: &AuthenticatedPrincipal,
    journal_id: &str,
    reference: &EvidenceRef,
    what: &str,
) -> Result<(), ConnectorError> {
    reference
        .validate()
        .map_err(|error| invalid(format!("{what} is invalid: {error}")))?;
    let prefix = rm_evidence::journal_head(principal, journal_id)?;
    rm_evidence::resolve_evidence(principal, reference, &prefix)
        .map(|_| ())
        .map_err(|error| {
            invalid(format!(
                "{what} must cite retained evidence in this attempt journal: {}",
                error.detail
            ))
        })
}

fn require_missing(missing: &Missing, field: &str) -> Result<(), ConnectorError> {
    if rm_time::is_valid_reason(&missing.reason) {
        Ok(())
    } else {
        Err(invalid(format!(
            "{field} missingness must be one of the six kernel null reasons"
        )))
    }
}

fn validate_duration_limit(limit: &DurationLimit, what: &str) -> Result<(), ConnectorError> {
    if limit.kind != "exact" {
        return Err(invalid(format!("{what}.kind must be \"exact\"")));
    }
    if limit.unit != "ms" {
        return Err(invalid(format!("{what}.unit must be \"ms\"")));
    }
    if !limit.value.is_finite() || limit.value < 0.0 {
        return Err(invalid(format!(
            "{what}.value must be a finite nonnegative millisecond allowance"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// JSON projections of reasoned missingness
// ---------------------------------------------------------------------------

fn missing_json(missing: &Missing) -> Value {
    serde_json::to_value(missing).unwrap_or_else(|_| json!({ "value": Value::Null }))
}

fn maybe_string_json(value: &MaybeString) -> Value {
    match value {
        MaybeString::Text(text) => Value::String(text.clone()),
        MaybeString::Missing(missing) => missing_json(missing),
    }
}

fn maybe_evidence_json(value: &MaybeEvidenceRef) -> Value {
    match value {
        MaybeEvidenceRef::Present(reference) => reference.to_json(),
        MaybeEvidenceRef::Missing(missing) => missing_json(missing),
    }
}

fn evidence_refs_json(refs: &[EvidenceRef]) -> Vec<Value> {
    refs.iter().map(EvidenceRef::to_json).collect()
}

fn time_json(point: &TimePoint) -> Value {
    serde_json::to_value(point)
        .unwrap_or_else(|_| missing_json(&Missing::new("not_observed")))
}

// ---------------------------------------------------------------------------
// Local registered clock
// ---------------------------------------------------------------------------

/// The registered local monotonic clock used for every control bound.
pub fn local_clock() -> &'static ClockDescriptor {
    rm_evidence::evidence_clock()
}

/// Current coordinate on the registered local monotonic clock.
pub fn local_now() -> TimePoint {
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
            "a local bound requires a finite nonnegative millisecond duration",
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

fn same_lifetime(left: &TimePoint, right: &TimePoint, what: &str) -> Result<(), ConnectorError> {
    if left.clock_id != right.clock_id
        || left.boot_id != right.boot_id
        || left.origin != right.origin
    {
        return Err(invalid(format!(
            "{what} must share one registered clock, boot, and origin: cross-clock, cross-boot, \
             and cross-origin ordering is forbidden"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Control operations and request schema (§15.1)
// ---------------------------------------------------------------------------

/// One control operation. Cancel, close, release, and containment remain
/// distinct operations with distinct request schemas and distinct evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlOperation {
    RequestNativeCancel,
    CloseObservationConnection,
    ReleaseNativeContext,
    Contain,
}

impl ControlOperation {
    /// Parses the exact wire verb.
    pub fn parse(verb: &str) -> Result<Self, ConnectorError> {
        match verb {
            "RequestNativeCancel" => Ok(ControlOperation::RequestNativeCancel),
            "CloseObservationConnection" => Ok(ControlOperation::CloseObservationConnection),
            "ReleaseNativeContext" => Ok(ControlOperation::ReleaseNativeContext),
            "Contain" => Ok(ControlOperation::Contain),
            other => Err(invalid(format!(
                "operation {other:?} is not one of the four control operations"
            ))),
        }
    }

    /// Wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            ControlOperation::RequestNativeCancel => "RequestNativeCancel",
            ControlOperation::CloseObservationConnection => "CloseObservationConnection",
            ControlOperation::ReleaseNativeContext => "ReleaseNativeContext",
            ControlOperation::Contain => "Contain",
        }
    }

    /// Grant spelling fragment.
    pub fn grant_name(self) -> &'static str {
        match self {
            ControlOperation::RequestNativeCancel => "request_native_cancel",
            ControlOperation::CloseObservationConnection => "close_observation_connection",
            ControlOperation::ReleaseNativeContext => "release_native_context",
            ControlOperation::Contain => "contain",
        }
    }

    /// Authorized scope of the operation (§15.1).
    pub fn target_scope(self) -> &'static str {
        match self {
            ControlOperation::RequestNativeCancel => "native_execution",
            ControlOperation::CloseObservationConnection => "observation_connection",
            ControlOperation::ReleaseNativeContext => "native_context",
            ControlOperation::Contain => "containment",
        }
    }

}

/// Declared close reason of a close request (§15.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseRequestReason {
    OperatorStop,
    LocalDeadline,
    NormalCompletion,
}

impl CloseRequestReason {
    /// Wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            CloseRequestReason::OperatorStop => "operator_stop",
            CloseRequestReason::LocalDeadline => "local_deadline",
            CloseRequestReason::NormalCompletion => "normal_completion",
        }
    }

    fn to_close_reason(self) -> CloseReason {
        match self {
            CloseRequestReason::OperatorStop => CloseReason::OperatorStop,
            CloseRequestReason::LocalDeadline => CloseReason::LocalDeadline,
            CloseRequestReason::NormalCompletion => CloseReason::NormalCompletion,
        }
    }
}

/// Installed containment resource kinds (§15.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainmentKind {
    FixtureMutationAuthority,
    LocalProcess,
    DeploymentSlot,
    HarnessResources,
}

impl ContainmentKind {
    /// Wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            ContainmentKind::FixtureMutationAuthority => "fixture_mutation_authority",
            ContainmentKind::LocalProcess => "local_process",
            ContainmentKind::DeploymentSlot => "deployment_slot",
            ContainmentKind::HarnessResources => "harness_resources",
        }
    }

    /// Parses the exact wire spelling.
    pub fn parse(value: &str) -> Result<Self, ConnectorError> {
        match value {
            "fixture_mutation_authority" => Ok(ContainmentKind::FixtureMutationAuthority),
            "local_process" => Ok(ContainmentKind::LocalProcess),
            "deployment_slot" => Ok(ContainmentKind::DeploymentSlot),
            "harness_resources" => Ok(ContainmentKind::HarnessResources),
            other => Err(invalid(format!(
                "containment kind {other:?} is not an installed authorized resource kind"
            ))),
        }
    }
}

/// Containment target: an installed authorized resource identity.
///
/// It never accepts arbitrary shell text, a URL, a filesystem path, or a
/// caller PID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainmentTarget {
    pub kind: ContainmentKind,
    pub resource_id: String,
}

impl ContainmentTarget {
    /// Validates the closed target shape.
    pub fn validate(&self) -> Result<(), ConnectorError> {
        require_identifier("containment target.resource_id", &self.resource_id)?;
        if self.resource_id.len() > 128 {
            return Err(invalid(
                "containment target.resource_id is longer than the installed identity bound",
            ));
        }
        if self
            .resource_id
            .chars()
            .all(|character| character.is_ascii_digit())
        {
            return Err(forbidden(
                "containment addresses an installed authorized resource identity, never a caller PID",
            ));
        }
        let valid = self.resource_id.chars().all(|character| {
            character.is_ascii_alphanumeric()
                || matches!(character, '_' | '-' | '.' | ':' | '/' | '@')
        });
        if !valid {
            return Err(forbidden(
                "containment addresses an installed authorized resource identity, never arbitrary \
                 shell text or a command line",
            ));
        }
        if self.resource_id.starts_with('/')
            || self.resource_id.contains("..")
            || self.resource_id.contains("//")
        {
            return Err(forbidden(
                "containment addresses an installed authorized resource identity, never a \
                 filesystem path or an unnormalized reference",
            ));
        }
        Ok(())
    }

    /// Canonical grant fragment of the target.
    pub fn wire(&self) -> String {
        format!("{}:{}", self.kind.as_str(), self.resource_id)
    }
}

/// Verb-specific control request parameters (§15.1).
#[derive(Debug, Clone, PartialEq)]
pub enum ControlParameters {
    RequestNativeCancel {
        reason: String,
    },
    CloseObservationConnection {
        reason: CloseRequestReason,
        end_observation: bool,
    },
    ReleaseNativeContext {
        context_ref: MaybeString,
    },
    Contain {
        target: ContainmentTarget,
        policy: VersionPin,
        reason: String,
    },
}

impl ControlParameters {
    /// The operation these parameters belong to.
    pub fn operation(&self) -> ControlOperation {
        match self {
            ControlParameters::RequestNativeCancel { .. } => ControlOperation::RequestNativeCancel,
            ControlParameters::CloseObservationConnection { .. } => {
                ControlOperation::CloseObservationConnection
            }
            ControlParameters::ReleaseNativeContext { .. } => {
                ControlOperation::ReleaseNativeContext
            }
            ControlParameters::Contain { .. } => ControlOperation::Contain,
        }
    }

    /// Validates the required request fields of the operation.
    pub fn validate(&self) -> Result<(), ConnectorError> {
        match self {
            ControlParameters::RequestNativeCancel { reason } => {
                require_identifier("reason", reason)
            }
            ControlParameters::CloseObservationConnection { .. } => Ok(()),
            ControlParameters::ReleaseNativeContext { context_ref } => match context_ref {
                MaybeString::Text(text) => require_identifier("context_ref", text),
                MaybeString::Missing(missing) => require_missing(missing, "context_ref"),
            },
            ControlParameters::Contain {
                target,
                policy,
                reason,
            } => {
                target.validate()?;
                require_identifier("reason", reason)?;
                require_identifier("policy.id", &policy.id)?;
                require_identifier("policy.version", &policy.version)?;
                if !rm_wire::is_valid_digest(policy.artifact_digest.as_str()) {
                    return Err(invalid(
                        "containment policy.artifact_digest must be a sha256 digest pin",
                    ));
                }
                Ok(())
            }
        }
    }

    fn close_request(&self) -> Option<(CloseRequestReason, bool)> {
        match self {
            ControlParameters::CloseObservationConnection {
                reason,
                end_observation,
            } => Some((*reason, *end_observation)),
            _ => None,
        }
    }
}

/// Admitted control command bound to one logical handle.
#[derive(Debug, Clone, PartialEq)]
pub struct ControlRequest {
    /// Admitted control scope (control grants only).
    pub scope: WorkScope,
    /// Admitted manifest authority view.
    pub manifest: Manifest,
    /// Target handle reference; control never addresses a native run ID.
    pub handle: HandleReference,
    /// Verb-specific parameters.
    pub parameters: ControlParameters,
}

/// Control command envelope.
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
    /// Control payload.
    pub payload: ControlRequest,
}

impl ConnectorRequest {
    /// Closed JSON projection.
    pub fn to_json(&self) -> Result<Value, ConnectorError> {
        Ok(json!({
            "record_type": self.record_type,
            "schema_version": self.schema_version,
            "request_id": self.request_id,
            "connector_id": self.connector_id,
            "operation": self.operation,
            "call_limit": self.call_limit.to_json(),
            "payload": {
                "kind": "control",
                "handle": self.payload.handle.to_json(),
                "parameters": parameters_json(&self.payload.parameters),
            },
        }))
    }
}

fn parameters_json(parameters: &ControlParameters) -> Value {
    match parameters {
        ControlParameters::RequestNativeCancel { reason } => json!({
            "operation": "RequestNativeCancel",
            "reason": reason,
        }),
        ControlParameters::CloseObservationConnection {
            reason,
            end_observation,
        } => json!({
            "operation": "CloseObservationConnection",
            "reason": reason.as_str(),
            "end_observation": end_observation,
        }),
        ControlParameters::ReleaseNativeContext { context_ref } => json!({
            "operation": "ReleaseNativeContext",
            "context_ref": maybe_string_json(context_ref),
        }),
        ControlParameters::Contain {
            target,
            policy,
            reason,
        } => json!({
            "operation": "Contain",
            "target": {
                "kind": target.kind.as_str(),
                "resource_id": target.resource_id,
            },
            "policy": policy.to_json(),
            "reason": reason,
        }),
    }
}

// ---------------------------------------------------------------------------
// Control observation vocabulary (§15.2)
// ---------------------------------------------------------------------------

/// Evidence meaning of one control observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    NotRequested,
    Unsupported,
    Requested,
    Acknowledged,
    EffectObserved,
    Unknown,
}

impl Disposition {
    /// Wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Disposition::NotRequested => "not_requested",
            Disposition::Unsupported => "unsupported",
            Disposition::Requested => "requested",
            Disposition::Acknowledged => "acknowledged",
            Disposition::EffectObserved => "effect_observed",
            Disposition::Unknown => "unknown",
        }
    }
}

/// Whether the operation had an exposed native/local opportunity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpportunityState {
    Exposed,
    Unexposed,
    Blocked,
}

impl OpportunityState {
    /// Wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            OpportunityState::Exposed => "exposed",
            OpportunityState::Unexposed => "unexposed",
            OpportunityState::Blocked => "blocked",
        }
    }
}

/// Opportunity: state, its supporting evidence, and its rationale.
#[derive(Debug, Clone, PartialEq)]
pub struct Opportunity {
    pub state: OpportunityState,
    pub evidence_refs: Vec<EvidenceRef>,
    pub rationale: String,
}

impl Opportunity {
    fn to_json(&self) -> Value {
        json!({
            "state": self.state.as_str(),
            "evidence_refs": evidence_refs_json(&self.evidence_refs),
            "rationale": self.rationale,
        })
    }
}

/// One evidence reference or its reasoned missingness.
#[derive(Debug, Clone, PartialEq)]
pub enum MaybeEvidenceRef {
    Present(EvidenceRef),
    Missing(Missing),
}

impl MaybeEvidenceRef {
    fn missing(detail: &str) -> Self {
        MaybeEvidenceRef::Missing(Missing::with_detail("not_observed", detail))
    }
}

/// Verified checks of a correlated control response.
#[derive(Debug, Clone, PartialEq)]
pub struct ResponseChecks {
    pub response_present: bool,
    pub authentication: AuthStatus,
    pub correlation: CorrelationStatus,
}

impl ResponseChecks {
    /// No response has been correlated.
    pub fn none() -> Self {
        ResponseChecks {
            response_present: false,
            authentication: AuthStatus::Unknown,
            correlation: CorrelationStatus::Unknown,
        }
    }

    /// A present, authenticated, reliably correlated response.
    pub fn verified() -> Self {
        ResponseChecks {
            response_present: true,
            authentication: AuthStatus::Verified,
            correlation: CorrelationStatus::Matched,
        }
    }

    fn is_verified(&self) -> bool {
        self.response_present
            && self.authentication == AuthStatus::Verified
            && self.correlation == CorrelationStatus::Matched
    }

    fn to_json(&self) -> Value {
        json!({
            "response_present": self.response_present,
            "authentication": self.authentication.as_str(),
            "correlation": self.correlation.as_str(),
        })
    }
}

/// Local finalization consequence of a control operation.
///
/// The started variant carries both registered clock coordinates in place: a
/// control observation is constructed once and cloned into its retained
/// projection, so indirection would only add a second lifetime to reason about.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub enum LocalFinalization {
    /// No bounded local finalization was started.
    NotRequested,
    /// Bounded local finalization started: new workflow commands stop and the
    /// drain runs to the recorded local deadline.
    Started {
        drain_started_at: TimePoint,
        drain_deadline: TimePoint,
    },
}

impl LocalFinalization {
    fn to_json(&self) -> Value {
        match self {
            LocalFinalization::NotRequested => json!({ "state": "not_requested" }),
            LocalFinalization::Started {
                drain_started_at,
                drain_deadline,
            } => json!({
                "state": "bounded_finalization_started",
                "drain_started_at": time_json(drain_started_at),
                "drain_deadline": time_json(drain_deadline),
            }),
        }
    }
}

/// One attempt potentially affected by a control operation (§15.6).
#[derive(Debug, Clone, PartialEq)]
pub struct AffectedAttempt {
    pub handle: HandleReference,
    pub attempt_id: MaybeString,
    pub commission_ref: MaybeString,
    pub kind: MaybeString,
}

impl AffectedAttempt {
    fn to_json(&self) -> Value {
        json!({
            "handle": self.handle.to_json(),
            "attempt_id": maybe_string_json(&self.attempt_id),
            "commission_ref": maybe_string_json(&self.commission_ref),
            "kind": maybe_string_json(&self.kind),
        })
    }
}

/// One immutable control observation (§15.2).
#[derive(Debug, Clone, PartialEq)]
pub struct ControlObservation {
    pub control_event_id: String,
    pub operation_id: String,
    pub operation: String,
    pub target_scope: String,
    pub disposition: Disposition,
    pub at: TimePoint,
    pub authorization_ref: MaybeString,
    pub capability_ref: MaybeString,
    pub policy_ref: MaybeString,
    pub opportunity: Opportunity,
    pub request_ref: MaybeEvidenceRef,
    pub response_ref: MaybeString,
    pub response_checks: ResponseChecks,
    pub native_claim_refs: Vec<EvidenceRef>,
    pub effect_refs: Vec<EvidenceRef>,
    pub affected_attempts: Vec<AffectedAttempt>,
    pub measurements: Vec<Measurement>,
    pub limitations: Vec<String>,
    pub local_finalization: LocalFinalization,
}

impl ControlObservation {
    /// Closed JSON projection; also the journaled `control_observation`
    /// payload body observed by the durable Observe API.
    pub fn to_json(&self) -> Value {
        json!({
            "control_event_id": self.control_event_id,
            "operation_id": self.operation_id,
            "operation": self.operation,
            "target_scope": self.target_scope,
            "disposition": self.disposition.as_str(),
            "at": time_json(&self.at),
            "authorization_ref": maybe_string_json(&self.authorization_ref),
            "capability_ref": maybe_string_json(&self.capability_ref),
            "policy_ref": maybe_string_json(&self.policy_ref),
            "opportunity": self.opportunity.to_json(),
            "request_ref": maybe_evidence_json(&self.request_ref),
            "response_ref": maybe_string_json(&self.response_ref),
            "response_checks": self.response_checks.to_json(),
            "native_claim_refs": evidence_refs_json(&self.native_claim_refs),
            "effect_refs": evidence_refs_json(&self.effect_refs),
            "affected_attempts": self
                .affected_attempts
                .iter()
                .map(AffectedAttempt::to_json)
                .collect::<Vec<Value>>(),
            "measurements": self
                .measurements
                .iter()
                .map(|measurement| {
                    serde_json::to_value(measurement).unwrap_or_else(|_| {
                        missing_json(&Missing::with_detail(
                            "not_observed",
                            "the measurement could not be serialized",
                        ))
                    })
                })
                .collect::<Vec<Value>>(),
            "limitations": self.limitations,
            "local_finalization": self.local_finalization.to_json(),
        })
    }

    fn journal_data(&self) -> Value {
        json!({
            "kind": CONTROL_OBSERVATION_KIND,
            "observation": self.to_json(),
        })
    }
}

/// Immutable control receipt (§15.2).
#[derive(Debug, Clone, PartialEq)]
pub struct ControlReceipt {
    pub kind: String,
    pub handle: HandleReference,
    pub observation: ControlObservation,
    pub registration_ref: EvidenceRef,
}

impl ControlReceipt {
    /// Closed JSON projection.
    pub fn to_json(&self) -> Value {
        json!({
            "kind": self.kind,
            "handle": self.handle.to_json(),
            "observation": self.observation.to_json(),
            "registration_ref": self.registration_ref.to_json(),
        })
    }
}

// ---------------------------------------------------------------------------
// Correlated responses
// ---------------------------------------------------------------------------

/// Kind of correlated control response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlResponseKind {
    /// A verified correlated response from the operation's executor.
    Acknowledged,
    /// The operation failed before any effect.
    Failed,
    /// A subject's own stop/completion statement.
    SubjectClaim,
    /// Delivery or effect knowledge is unresolved.
    Unknown,
}

impl ControlResponseKind {
    /// Wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            ControlResponseKind::Acknowledged => "acknowledged",
            ControlResponseKind::Failed => "failed",
            ControlResponseKind::SubjectClaim => "subject_claim",
            ControlResponseKind::Unknown => "unknown",
        }
    }
}

/// One response or claim correlated to a retained control request.
#[derive(Debug, Clone, PartialEq)]
pub struct ControlResponse {
    pub kind: ControlResponseKind,
    pub response_ref: MaybeString,
    pub checks: ResponseChecks,
    pub effect_refs: Vec<EvidenceRef>,
    pub native_claim_refs: Vec<EvidenceRef>,
    pub detail: MaybeString,
}

impl ControlResponse {
    fn detail_text(&self) -> Option<String> {
        match &self.detail {
            MaybeString::Text(text) => Some(text.clone()),
            MaybeString::Missing(_) => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Observation policy and window state
// ---------------------------------------------------------------------------

/// Fixture-mutation close action. Employer scope requires `not_applicable`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixtureCloseAction {
    NotApplicable,
    SealFixtureMutation,
}

impl FixtureCloseAction {
    /// Wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            FixtureCloseAction::NotApplicable => "not_applicable",
            FixtureCloseAction::SealFixtureMutation => "seal_fixture_mutation",
        }
    }
}

/// Pinned local observation policy (§16.4).
///
/// Every bound is finite and local. The active window bound is the admitted
/// work boundary journaled at Start (queue time included, never restarted); the
/// drain, cancellation-wait, and cleanup waits are pinned connector-runtime
/// limits.
#[derive(Debug, Clone, PartialEq)]
pub struct ObservationPolicy {
    pub policy_ref: String,
    pub drain_limit_ms: f64,
    pub native_cancel_wait_limit_ms: f64,
    pub cleanup_wait_limit_ms: f64,
    pub fixture_close_action: FixtureCloseAction,
}

impl ObservationPolicy {
    /// Pinned policy for one admitted scope.
    pub fn for_scope(scope: &WorkScope) -> Self {
        let employer = scope.attempt_kind == Some(AttemptKind::Production);
        ObservationPolicy {
            policy_ref: scope.observation_policy.clone(),
            drain_limit_ms: PINNED_DRAIN_LIMIT_MS,
            native_cancel_wait_limit_ms: PINNED_NATIVE_CANCEL_WAIT_LIMIT_MS,
            cleanup_wait_limit_ms: PINNED_CLEANUP_WAIT_LIMIT_MS,
            fixture_close_action: if employer {
                FixtureCloseAction::NotApplicable
            } else {
                FixtureCloseAction::SealFixtureMutation
            },
        }
    }

    /// Validates the policy bounds.
    pub fn validate(&self) -> Result<(), ConnectorError> {
        require_identifier("observation policy ref", &self.policy_ref)?;
        for (what, value) in [
            ("drain_limit_ms", self.drain_limit_ms),
            (
                "native_cancel_wait_limit_ms",
                self.native_cancel_wait_limit_ms,
            ),
            ("cleanup_wait_limit_ms", self.cleanup_wait_limit_ms),
        ] {
            if !value.is_finite() || value < 0.0 {
                return Err(invalid(format!(
                    "observation policy {what} must be a finite nonnegative millisecond bound"
                )));
            }
        }
        Ok(())
    }
}

/// Local observation window state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowState {
    /// No close has been requested; observation continues within its bound.
    Open,
    /// Only the mapped native transport was closed; the window is not closed.
    TransportClosed,
    /// Bounded local finalization is running to the recorded drain deadline.
    Draining,
    /// The window is closed and never reopens.
    Closed,
}

impl WindowState {
    /// Wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            WindowState::Open => "open",
            WindowState::TransportClosed => "transport_closed",
            WindowState::Draining => "draining",
            WindowState::Closed => "closed",
        }
    }
}

// ---------------------------------------------------------------------------
// Retained local state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct CloseRequestRecord {
    reason: CloseRequestReason,
    drain_started_at: TimePoint,
    drain_deadline: TimePoint,
}

#[derive(Debug, Clone)]
struct ClosureRecord {
    revision: u64,
    open_coordinate: TimePoint,
    active_deadline: TimePoint,
    drain_started_at: MaybeTimePoint,
    drain_deadline: MaybeTimePoint,
    closed_at: TimePoint,
    close_reason: CloseReason,
    at_close: CloseSnapshot,
    measurements: Vec<Measurement>,
    control_observations: Vec<EvidenceRef>,
    late_evidence_refs: Vec<EvidenceRef>,
    cited_refs: BTreeSet<String>,
}

#[derive(Debug, Clone)]
struct WindowRecord {
    policy: ObservationPolicy,
    state: WindowState,
    close_request: Option<CloseRequestRecord>,
    closure: Option<ClosureRecord>,
    observed_refs: Vec<EvidenceRef>,
}

#[derive(Default)]
struct Store {
    windows: std::collections::BTreeMap<String, WindowRecord>,
    observations: std::collections::BTreeMap<String, Vec<ControlObservation>>,
}

static STORE: LazyLock<Mutex<Store>> = LazyLock::new(|| Mutex::new(Store::default()));

fn lock_store() -> MutexGuard<'static, Store> {
    STORE.lock().unwrap_or_else(|poison| poison.into_inner())
}

fn window_key(principal: &AuthenticatedPrincipal, handle: &HandleReference) -> String {
    format!(
        "{}|{}|{}",
        principal.principal_id(),
        handle.connector_id,
        handle.local_handle
    )
}

fn operation_id(
    principal: &AuthenticatedPrincipal,
    handle: &HandleReference,
    operation: ControlOperation,
) -> String {
    format!(
        "control:{}:{}:{}:{}",
        principal.principal_id(),
        handle.connector_id,
        handle.local_handle,
        operation.as_str()
    )
}

fn evidence_ref(envelope: &JournalEnvelope) -> EvidenceRef {
    EvidenceRef {
        journal_id: envelope.journal_id.clone(),
        sequence: envelope.journal_sequence,
        event_id: envelope.event_id.clone(),
        event_hash: envelope.event_hash.clone(),
        pointer: String::new(),
    }
}

fn window_for<'a>(
    store: &'a mut Store,
    key: &str,
    policy: ObservationPolicy,
) -> &'a mut WindowRecord {
    store
        .windows
        .entry(key.to_string())
        .or_insert_with(|| WindowRecord {
            policy,
            state: WindowState::Open,
            close_request: None,
            closure: None,
            observed_refs: Vec::new(),
        })
}

fn retain_observation(store: &mut Store, key: &str, observation: ControlObservation, registration: EvidenceRef) {
    if let Some(window) = store.windows.get_mut(key) {
        window.observed_refs.push(registration);
    }
    store
        .observations
        .entry(key.to_string())
        .or_default()
        .push(observation);
}

// ---------------------------------------------------------------------------
// Read projections
// ---------------------------------------------------------------------------

/// Retained control observations for one handle, in append order.
pub fn control_history(
    principal: &AuthenticatedPrincipal,
    handle: &ConnectorHandle,
) -> Result<Vec<ControlObservation>, ConnectorError> {
    check_principal(principal)?;
    handle.validate()?;
    let key = window_key(principal, &handle.handle);
    let store = lock_store();
    if !store.windows.contains_key(&key) {
        return Err(unknown_handle(
            "no control observations are retained for this handle",
        ));
    }
    Ok(store.observations.get(&key).cloned().unwrap_or_default())
}

/// Current local observation window state.
pub fn window_state(
    principal: &AuthenticatedPrincipal,
    handle: &ConnectorHandle,
) -> Result<WindowState, ConnectorError> {
    check_principal(principal)?;
    handle.validate()?;
    let key = window_key(principal, &handle.handle);
    let store = lock_store();
    store
        .windows
        .get(&key)
        .map(|window| window.state)
        .ok_or_else(|| unknown_handle("no observation window is retained for this handle"))
}

// ---------------------------------------------------------------------------
// Request validation
// ---------------------------------------------------------------------------

fn validate_envelope(request: &ConnectorRequest) -> Result<ControlOperation, ConnectorError> {
    if request.record_type != CONTROL_REQUEST_RECORD_TYPE {
        return Err(invalid(format!(
            "record_type {:?} must be {CONTROL_REQUEST_RECORD_TYPE:?}",
            request.record_type
        )));
    }
    if request.schema_version != CONTROL_SCHEMA_VERSION {
        return Err(connector_error(
            "UNSUPPORTED_VERSION",
            "request",
            format!("unknown schema_version {:?}", request.schema_version),
            "not_dispatched",
            "operator_review",
        ));
    }
    require_identifier("request_id", &request.request_id)?;
    require_identifier("connector_id", &request.connector_id)?;
    require_identifier("operation", &request.operation)?;
    validate_duration_limit(&request.call_limit, "call_limit")?;
    let operation = ControlOperation::parse(&request.operation)?;
    if request.payload.parameters.operation() != operation {
        return Err(invalid(
            "control parameters do not match the envelope operation",
        ));
    }
    request.payload.parameters.validate()?;
    Ok(operation)
}

fn validate_control_binding(
    request: &ConnectorRequest,
    control: &ControlRequest,
) -> Result<(), ConnectorError> {
    let journal_id = rm_evidence::journal_id_for(&control.manifest)?;
    if control.scope.journal_id != journal_id {
        return Err(stale(
            "control scope names a different journal than the admitted manifest",
        ));
    }
    if control.scope.run_id != control.manifest.run_id {
        return Err(stale(
            "control scope names a different run than the admitted manifest",
        ));
    }
    if control.scope.manifest_hash != control.manifest.manifest_hash {
        return Err(stale(
            "control scope manifest binding differs from the admitted manifest",
        ));
    }
    if control.scope.admission_ref != control.manifest.admission_ref {
        return Err(stale(
            "control scope admission binding differs from the admitted manifest",
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
    if control.scope.authorization_refs.is_empty() {
        return Err(forbidden(
            "every control operation requires at least one admitted control grant",
        ));
    }
    for grant in &control.scope.authorization_refs {
        require_identifier("control grant", grant)?;
        if !grant.starts_with("control:") {
            return Err(forbidden(
                "control operations require scoped control grants; task grants do not authorize \
                 connector control",
            ));
        }
    }
    control.handle.validate()?;
    if control.handle.connector_id != request.connector_id {
        return Err(invalid(
            "control handle connector identity must equal the request connector identity",
        ));
    }
    Ok(())
}

/// The target identity a control operation addresses.
fn control_target(parameters: &ControlParameters, handle: &HandleReference) -> String {
    match parameters {
        ControlParameters::ReleaseNativeContext { context_ref } => match context_ref {
            MaybeString::Text(text) => text.clone(),
            MaybeString::Missing(_) => handle.local_handle.clone(),
        },
        ControlParameters::Contain { target, .. } => target.wire(),
        _ => handle.local_handle.clone(),
    }
}

/// Resolves the exact scoped control grant that authorizes this operation.
fn authorization_grant(
    scope: &WorkScope,
    operation: ControlOperation,
    target: &str,
    parameters: &ControlParameters,
) -> Result<String, ConnectorError> {
    let grants = &scope.authorization_refs;
    if operation == ControlOperation::Contain {
        let (target_grant, policy_grant) = match parameters {
            ControlParameters::Contain { target, policy, .. } => (
                format!("control:contain:{}", target.wire()),
                format!("control:policy:{}@{}", policy.id, policy.version),
            ),
            _ => unreachable!("containment parameters are checked before authorization"),
        };
        if !grants.contains(&target_grant) {
            return Err(forbidden(format!(
                "containment requires the scoped control grant {target_grant:?} naming the \
                 installed authorized resource; a task grant, a general control grant, or a \
                 different resource never authorizes containment"
            )));
        }
        if !grants.contains(&policy_grant) {
            return Err(not_admitted(format!(
                "containment requires the pinned installed policy grant {policy_grant:?}"
            )));
        }
        return Ok(target_grant);
    }
    let specific = format!("control:{}:{target}", operation.grant_name());
    let generic = format!("control:{}", operation.grant_name());
    if let Some(grant) = grants.iter().find(|grant| **grant == specific) {
        return Ok(grant.clone());
    }
    if let Some(grant) = grants.iter().find(|grant| **grant == generic) {
        return Ok(grant.clone());
    }
    Err(forbidden(format!(
        "a {} control operation requires a scoped control grant naming the operation; found no \
         {specific:?} or {generic:?} grant",
        operation.as_str()
    )))
}

fn affected_attempts(scope: &WorkScope, handle: &HandleReference) -> Vec<AffectedAttempt> {
    let attempt_id = match &scope.attempt_id {
        Some(attempt) => MaybeString::Text(attempt.clone()),
        None => MaybeString::Missing(Missing::with_detail(
            "not_applicable",
            "no commissioned application attempt is bound to this handle",
        )),
    };
    let commission_ref = match &scope.commission_ref {
        Some(reference) => MaybeString::Text(reference.clone()),
        None => MaybeString::Missing(Missing::new("not_applicable")),
    };
    let kind = match scope.attempt_kind {
        Some(AttemptKind::Practice) => MaybeString::Text("practice".to_string()),
        Some(AttemptKind::Production) => MaybeString::Text("production".to_string()),
        None => MaybeString::Missing(Missing::new("not_applicable")),
    };
    vec![AffectedAttempt {
        handle: handle.clone(),
        attempt_id,
        commission_ref,
        kind,
    }]
}

// ---------------------------------------------------------------------------
// Opportunity assessment from the pinned descriptor
// ---------------------------------------------------------------------------

/// Whether the pinned descriptor evidences a native mapping for one verb.
///
/// Only a declared `native_mapping` with an actual native contract pin is a
/// native primitive; a `connector_local` handler is local coverage, never
/// native availability.
fn is_native_mapping(mapping: &OperationMapping) -> bool {
    mapping.implementation == "native_mapping"
        && matches!(
            mapping.native_contract,
            rm_catalog::MaybeVersionPin::Present(_)
        )
}

fn capability_reference(mapping: &OperationMapping) -> MaybeString {
    match mapping.capability_refs.first() {
        Some(reference) => MaybeString::Text(format!(
            "{}@{}",
            reference.capability_id,
            reference.descriptor_digest.as_str()
        )),
        None => MaybeString::Missing(Missing::with_detail(
            "not_applicable",
            "the pinned descriptor references no capability for this operation",
        )),
    }
}

struct Assessment {
    state: OpportunityState,
    rationale: String,
    limitations: Vec<String>,
}

fn assess_opportunity(
    operation: ControlOperation,
    parameters: &ControlParameters,
    descriptor: &rm_catalog::ConnectorDescriptor,
    mapping: &OperationMapping,
    window_state: WindowState,
) -> Assessment {
    let mut limitations: Vec<String> = mapping.limitations.clone();
    // A native transport exists for close exactly when the close verb itself
    // carries an evidenced native contract.
    let separable_transport = is_native_mapping(mapping);
    match operation {
        ControlOperation::RequestNativeCancel => {
            if !is_native_mapping(mapping) {
                limitations.push(
                    "no native task-cancel primitive is disclosed by the pinned descriptor"
                        .to_string(),
                );
                limitations.push(
                    "in-flight interruption is not claimed; page destruction, process kill, and \
                     transport closure are not implicit substitutes for cancellation"
                        .to_string(),
                );
            }
            Assessment {
                state: if is_native_mapping(mapping) {
                    OpportunityState::Exposed
                } else {
                    OpportunityState::Unexposed
                },
                rationale: if is_native_mapping(mapping) {
                    "the pinned descriptor evidences a native task-cancel contract, so a request \
                     attempt is exposed (never an in-flight interruption claim)"
                        .to_string()
                } else {
                    format!(
                        "the pinned descriptor maps RequestNativeCancel as {:?} with no native \
                         contract; a separately evidenced task-cancel contract may stop future \
                         scheduling, but no in-flight interruption opportunity is exposed here",
                        mapping.implementation
                    )
                },
                limitations,
            }
        }
        ControlOperation::CloseObservationConnection => {
            let (_, end_observation) = parameters
                .close_request()
                .unwrap_or((CloseRequestReason::OperatorStop, false));
            if window_state == WindowState::Closed {
                limitations.push(
                    "the observation window is closed and a closed window cannot reopen".to_string(),
                );
                return Assessment {
                    state: OpportunityState::Blocked,
                    rationale:
                        "the window is already closed; a closed window is never reopened".to_string(),
                    limitations,
                };
            }
            if window_state == WindowState::Draining && end_observation {
                limitations.push(
                    "bounded local finalization is already running; its recorded drain deadline is \
                     never extended by a repeated request"
                        .to_string(),
                );
                return Assessment {
                    state: OpportunityState::Blocked,
                    rationale: "the window is already draining to its recorded local deadline"
                        .to_string(),
                    limitations,
                };
            }
            if end_observation {
                limitations.push(
                    "end_observation=true stops new workflow commands and starts guarded bounded \
                     local finalization; it never requests cancellation"
                        .to_string(),
                );
                Assessment {
                    state: OpportunityState::Exposed,
                    rationale: "bounded local finalization is available on the local monotonic \
                                clock and does not depend on any native primitive"
                        .to_string(),
                    limitations,
                }
            } else if separable_transport {
                Assessment {
                    state: OpportunityState::Exposed,
                    rationale: "the pinned descriptor discloses a separable native observation \
                                transport to close"
                        .to_string(),
                    limitations,
                }
            } else {
                limitations.push(format!(
                    "the pinned descriptor discloses observation channels {:?} and maps \
                     CloseObservationConnection as {:?} with no native contract: no separable \
                     native observation transport is disclosed",
                    descriptor.observation_channels, mapping.implementation
                ));
                limitations.push(
                    "the durable Observe API remains readable after any close setting".to_string(),
                );
                Assessment {
                    state: OpportunityState::Unexposed,
                    rationale: "no separable native observation transport is disclosed, so there \
                                is nothing to close; a missing mapping is recorded as unsupported, \
                                never invented as native absence"
                        .to_string(),
                    limitations,
                }
            }
        }
        ControlOperation::ReleaseNativeContext => {
            let extra = match parameters {
                ControlParameters::ReleaseNativeContext { context_ref } => match context_ref {
                    MaybeString::Text(_) => {
                        "the request names an external context identity; only the owner thread may \
                         resolve it against its evidenced page mapping"
                    }
                    MaybeString::Missing(_) => {
                        "no external context identity was supplied: only a handle-scoped release is \
                         requested, and shared logout, profile purge, or global reset are never \
                         implied"
                    }
                },
                _ => unreachable!("release parameters are checked before assessment"),
            };
            limitations.push(extra.to_string());
            limitations.push(
                "release runs on the owner thread; the control thread never calls a native release \
                 directly"
                    .to_string(),
            );
            Assessment {
                state: OpportunityState::Exposed,
                rationale: "the release request is admitted on the independent owner control queue"
                    .to_string(),
                limitations,
            }
        }
        ControlOperation::Contain => {
            limitations.push(
                "containment establishes neither cooperative cancellation nor rollback; forced \
                 termination is never presented as rollback"
                    .to_string(),
            );
            limitations.push(
                "attempts sharing the contained resource are affected; only attempts known to this \
                 control thread are recorded"
                    .to_string(),
            );
            Assessment {
                state: OpportunityState::Exposed,
                rationale: "the containment target resolves to an installed authorized resource \
                            under a pinned policy and scoped authorization"
                    .to_string(),
                limitations,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Journal appends
// ---------------------------------------------------------------------------

fn append_observation(
    principal: &AuthenticatedPrincipal,
    manifest: &Manifest,
    journal_id: &str,
    observation: &ControlObservation,
    occurred_at: &TimePoint,
) -> Result<JournalEnvelope, ConnectorError> {
    let mut last_detail: Option<String> = None;
    for _ in 0..APPEND_ATTEMPTS {
        let head = rm_evidence::journal_head(principal, journal_id)?;
        let producer_sequence = PositiveInteger::new(head.last_sequence.get() + 1)
            .map_err(|error| invalid(format!("producer sequence is invalid: {error}")))?;
        let submission = EventSubmission {
            producer_sequence: Some(producer_sequence),
            event_kind: CONTROL_OBSERVATION_KIND.to_string(),
            event_schema_version: CONTROL_OBSERVATION_EVENT_SCHEMA.to_string(),
            occurred_at: MaybeTimePoint::Present(occurred_at.clone()),
            payload: EvidencePayload {
                data: observation.journal_data(),
                measurements: observation.measurements.clone(),
                evidence_refs: Vec::new(),
                artifact_refs: Vec::new(),
            },
        };
        match rm_evidence::append_event(principal, manifest, submission) {
            Ok(envelope) => return Ok(envelope),
            Err(error) if error.code == "INTEGRITY_CONFLICT" => {
                let current = rm_evidence::journal_head(principal, journal_id)?;
                if current.last_sequence.get() > head.last_sequence.get() {
                    last_detail = Some(error.detail);
                    continue;
                }
                return Err(error);
            }
            Err(error) => return Err(error),
        }
    }
    Err(prerequisite(format!(
        "the journal head kept moving under the control observation commit; no observation was \
         acknowledged: {}",
        last_detail.unwrap_or_else(|| "no retained attempt".to_string())
    )))
}

/// Counts retained control observations for one operation identity.
///
/// The count is the journal's, not process memory, so a new observation gets a
/// new `control_event_id` even across a restart.
fn retained_observation_count(
    principal: &AuthenticatedPrincipal,
    journal_id: &str,
    operation_id: &str,
) -> Result<u64, ConnectorError> {
    let head = rm_evidence::journal_head(principal, journal_id)?;
    let end = head.last_sequence.get();
    if end > MAX_JOURNAL_SCAN {
        return Err(prerequisite(
            "the retained journal exceeds the finite control read bound; a new control observation \
             identity cannot be assigned within the local bound",
        ));
    }
    let mut count = 0;
    for sequence in 1..=end {
        let positive = PositiveInteger::new(sequence)
            .map_err(|error| invalid(format!("journal sequence is invalid: {error}")))?;
        let envelope = rm_evidence::read_event(principal, journal_id, positive)?;
        if envelope.event_kind != CONTROL_OBSERVATION_KIND {
            continue;
        }
        let retained = envelope
            .payload
            .data
            .get("observation")
            .and_then(|observation| observation.get("operation_id"))
            .and_then(Value::as_str);
        if retained == Some(operation_id) {
            count += 1;
        }
    }
    Ok(count)
}

// ---------------------------------------------------------------------------
// Journal scan for the admitted local boundary and publication versions
// ---------------------------------------------------------------------------

struct AdmissionRecord {
    sequence: u64,
    active_deadline: TimePoint,
}

#[derive(Default)]
struct JournalScan {
    admission: Option<AdmissionRecord>,
    observation_publications: u64,
    execution_claims: u64,
    origin_facts: u64,
    report_publications: u64,
}

fn event_names_handle(data: &Value, local_handle: &str) -> bool {
    if let Some(handle) = data.get("handle") {
        if handle.get("local_handle").and_then(Value::as_str) == Some(local_handle) {
            return true;
        }
    }
    data.get("local_handle").and_then(Value::as_str) == Some(local_handle)
}

fn scan_journal(
    principal: &AuthenticatedPrincipal,
    journal_id: &str,
    local_handle: &str,
) -> Result<JournalScan, ConnectorError> {
    let head = rm_evidence::journal_head(principal, journal_id)?;
    let end = head.last_sequence.get();
    if end > MAX_JOURNAL_SCAN {
        return Err(prerequisite(
            "the retained journal exceeds the finite control read bound; the admission boundary \
             cannot be reconstructed within the local bound",
        ));
    }
    let mut scan = JournalScan::default();
    for sequence in 1..=end {
        let positive = PositiveInteger::new(sequence)
            .map_err(|error| invalid(format!("journal sequence is invalid: {error}")))?;
        let envelope = rm_evidence::read_event(principal, journal_id, positive)?;
        let data = &envelope.payload.data;
        if !event_names_handle(data, local_handle) {
            continue;
        }
        match envelope.event_kind.as_str() {
            "dispatch_published"
                if scan.admission.is_none()
                    && data.get("operation").and_then(Value::as_str) == Some("start") =>
            {
                let deadline = data.get("active_deadline").ok_or_else(|| {
                    integrity("the retained dispatch admission does not record its local boundary")
                })?;
                let active_deadline: TimePoint =
                    serde_json::from_value(deadline.clone()).map_err(|error| {
                        integrity(format!("the journaled active boundary is invalid: {error}"))
                    })?;
                scan.admission = Some(AdmissionRecord {
                    sequence,
                    active_deadline,
                });
            }
            "observation_opened" | "observation_closed" => scan.observation_publications += 1,
            "execution_claim" => scan.execution_claims += 1,
            "origin_fact" => scan.origin_facts += 1,
            "report_published" => scan.report_publications += 1,
            _ => {}
        }
    }
    Ok(scan)
}

// ---------------------------------------------------------------------------
// control
// ---------------------------------------------------------------------------

/// Admits one control command for one logical handle.
///
/// Authorization is checked against the admitted control scope before any
/// decision, so an unsupported mapping is still an authorized, evidenced
/// observation. Only an exposed opportunity is handed to the owner's control
/// queue; an unsupported or blocked one records why nothing was delivered. The
/// returned receipt is immutable and carries the journaled observation.
pub fn control(
    principal: &AuthenticatedPrincipal,
    request: &ConnectorRequest,
) -> Result<ControlReceipt, ConnectorError> {
    check_principal(principal)?;
    let operation = validate_envelope(request)?;
    let control = &request.payload;
    validate_control_binding(request, control)?;

    let policy = ObservationPolicy::for_scope(&control.scope);
    policy.validate()?;

    // Fixture mutation may only be sealed by fixture-origin authority: an
    // employer-scoped window carries `fixture_close_action=not_applicable`.
    if let ControlParameters::Contain { target, .. } = &control.parameters {
        if target.kind == ContainmentKind::FixtureMutationAuthority
            && policy.fixture_close_action == FixtureCloseAction::NotApplicable
        {
            return Err(forbidden(
                "Ringmaster cannot seal employer mutation authority: only fixture-origin authority \
                 may seal fixture mutation",
            ));
        }
    }
    let key = window_key(principal, &control.handle);
    let current_state = {
        let mut store = lock_store();
        window_for(&mut store, &key, policy.clone()).state
    };

    let target = control_target(&control.parameters, &control.handle);
    let grant = authorization_grant(&control.scope, operation, &target, &control.parameters)?;
    let operation_record = build_operation(request, control, &target);
    rm_authority::authorize_work(principal, &control.scope, &operation_record)?;

    let descriptor = rm_catalog::describe(principal, &DescribeRequest)?;
    let mapping = descriptor
        .operations
        .iter()
        .find(|mapping| mapping.operation == request.operation)
        .ok_or_else(|| {
            not_admitted(format!(
                "the pinned descriptor does not map operation {:?}; an unmapped verb is never \
                 invented",
                request.operation
            ))
        })?;
    let assessment = assess_opportunity(
        operation,
        &control.parameters,
        &descriptor,
        mapping,
        current_state,
    );

    let withheld: Option<(Disposition, &str)> = match operation {
        // Without an evidenced native cancel mapping no request exists to
        // issue, and bounded local finalization remains fully available.
        ControlOperation::RequestNativeCancel if !is_native_mapping(mapping) => Some((
            Disposition::Unsupported,
            "a missing native cancel mapping does not prevent bounded local finalization",
        )),
        ControlOperation::RequestNativeCancel => None,
        ControlOperation::CloseObservationConnection => match current_state {
            WindowState::Closed => Some((
                Disposition::NotRequested,
                "the observation window is closed; a closed window is never reopened",
            )),
            WindowState::Draining if control.parameters.close_request().is_some_and(|(_, end)| end) => {
                Some((
                    Disposition::NotRequested,
                    "bounded local finalization is already running to its recorded drain \
                     deadline; a repeated end request never extends the bound",
                ))
            }
            _ => {
                let (_, end_observation) = control
                    .parameters
                    .close_request()
                    .unwrap_or((CloseRequestReason::OperatorStop, false));
                if !end_observation && assessment.state != OpportunityState::Exposed {
                    Some((
                        Disposition::Unsupported,
                        "no separable native observation transport is disclosed; nothing was \
                         closed on the control thread",
                    ))
                } else {
                    None
                }
            }
        },
        _ => None,
    };

    let at = local_now();
    let mut limitations = assessment.limitations.clone();
    let (disposition, request_ref, local_finalization) = match withheld {
        Some((disposition, detail)) => {
            limitations.push(format!(
                "no control request was delivered to the owner control queue: {detail}"
            ));
            (
                disposition,
                MaybeEvidenceRef::missing("no request was delivered for this observation"),
                LocalFinalization::NotRequested,
            )
        }
        None => {
            let receipt_ref =
                rm_delivery::enqueue_owner_control(principal, &delivery_request(request, control))?;
            let finalization =
                apply_local_consequence(&key, operation, &control.parameters, &policy, &at)?;
            if matches!(finalization, LocalFinalization::Started { .. }) {
                limitations.push(
                    "new workflow commands stop and the bounded drain runs to its recorded local \
                     deadline; native cancellation is neither requested nor implied"
                        .to_string(),
                );
            }
            (
                Disposition::Requested,
                MaybeEvidenceRef::Present(receipt_ref),
                finalization,
            )
        }
    };

    let mut measurements = Vec::new();
    if operation == ControlOperation::RequestNativeCancel {
        let cancel_mapped = is_native_mapping(mapping);
        limitations.push(if cancel_mapped {
            format!(
                "the pinned cancellation-wait bound of {} ms is respected; the cancellation \
                 request is asynchronous and no acknowledgement wait happens on the control \
                 thread",
                policy.native_cancel_wait_limit_ms
            )
        } else {
            format!(
                "the pinned cancellation-wait bound of {} ms is recorded; no native cancellation \
                 is mapped, so nothing was waited on",
                policy.native_cancel_wait_limit_ms
            )
        });
        measurements.push(unavailable_measurement(
            format!("measurement-{}", request.request_id),
            "native_cancel_wait",
            &target,
            &at,
            if cancel_mapped {
                "no acknowledgement wait was performed in this call"
            } else {
                "no native cancellation is mapped, so no wait duration exists"
            },
        ));
    }

    let policy_ref = match &control.parameters {
        ControlParameters::Contain { policy: pin, .. } => {
            MaybeString::Text(format!("{}@{}", pin.id, pin.version))
        }
        _ => MaybeString::Text(policy.policy_ref.clone()),
    };

    let identity = operation_id(principal, &control.handle, operation);
    let control_event_id = format!(
        "{}#{}",
        identity,
        retained_observation_count(principal, &control.scope.journal_id, &identity)? + 1
    );
    let observation = ControlObservation {
        control_event_id,
        operation_id: identity,
        operation: operation.as_str().to_string(),
        target_scope: format!("{}:{target}", operation.target_scope()),
        disposition,
        at: at.clone(),
        authorization_ref: MaybeString::Text(grant),
        capability_ref: capability_reference(mapping),
        policy_ref,
        opportunity: Opportunity {
            state: assessment.state,
            evidence_refs: mapping.evidence_refs.clone(),
            rationale: assessment.rationale,
        },
        request_ref,
        response_ref: MaybeString::Missing(Missing::with_detail(
            "not_observed",
            "no response has been correlated to this control request",
        )),
        response_checks: ResponseChecks::none(),
        native_claim_refs: Vec::new(),
        effect_refs: Vec::new(),
        affected_attempts: affected_attempts(&control.scope, &control.handle),
        measurements,
        limitations,
        local_finalization,
    };

    let envelope = append_observation(
        principal,
        &control.manifest,
        &control.scope.journal_id,
        &observation,
        &at,
    )?;
    let registration = evidence_ref(&envelope);
    retain_observation(&mut lock_store(), &key, observation.clone(), registration.clone());
    Ok(ControlReceipt {
        kind: CONTROL_RECEIPT_KIND.to_string(),
        handle: control.handle.clone(),
        observation,
        registration_ref: registration,
    })
}

fn build_operation(request: &ConnectorRequest, control: &ControlRequest, target: &str) -> Operation {
    let subject_id = control
        .manifest
        .subject
        .get("subject_id")
        .and_then(Value::as_str)
        .unwrap_or(control.scope.owner_domain.as_str())
        .to_string();
    Operation {
        verb: request.operation.clone(),
        connector_id: request.connector_id.clone(),
        subject_id,
        task_scope: format!("{}:{}", control.scope.activity, control.handle.local_handle),
        account_binding: None,
        artifact_refs: Vec::new(),
        control_target: Some(target.to_string()),
    }
}

/// Builds the owner-queue delivery envelope from the admitted control request.
///
/// The delivery envelope carries exactly the admitted scope, manifest, and
/// handle; the verb-specific parameters live in this module's retained
/// observation, which is the immutable request record.
fn delivery_request(request: &ConnectorRequest, control: &ControlRequest) -> DeliveryRequest {
    DeliveryRequest {
        record_type: CONTROL_REQUEST_RECORD_TYPE.to_string(),
        schema_version: CONTROL_SCHEMA_VERSION.to_string(),
        request_id: request.request_id.clone(),
        connector_id: request.connector_id.clone(),
        operation: request.operation.clone(),
        call_limit: request.call_limit.clone(),
        payload: DeliveryPayload::Control(DeliveryControl {
            scope: control.scope.clone(),
            manifest: control.manifest.clone(),
            handle: control.handle.clone(),
        }),
    }
}

fn apply_local_consequence(
    key: &str,
    operation: ControlOperation,
    parameters: &ControlParameters,
    policy: &ObservationPolicy,
    at: &TimePoint,
) -> Result<LocalFinalization, ConnectorError> {
    let mut store = lock_store();
    let window = store
        .windows
        .get_mut(key)
        .ok_or_else(|| unknown_handle("the observation window disappeared"))?;
    if window.policy != *policy {
        return Err(stale(
            "the admitted observation policy differs from the retained window policy",
        ));
    }
    let finalization = match operation {
        ControlOperation::CloseObservationConnection => {
            let (reason, end_observation) = parameters
                .close_request()
                .unwrap_or((CloseRequestReason::OperatorStop, false));
            if end_observation && window.state == WindowState::Draining {
                return Err(stale(
                    "bounded local finalization is already running; its recorded drain deadline is \
                     never extended",
                ));
            }
            if end_observation {
                let drain_deadline = shift_time(at, policy.drain_limit_ms)?;
                same_lifetime(at, &drain_deadline, "the drain bound")?;
                window.state = WindowState::Draining;
                window.close_request = Some(CloseRequestRecord {
                    reason,
                    drain_started_at: at.clone(),
                    drain_deadline: drain_deadline.clone(),
                });
                LocalFinalization::Started {
                    drain_started_at: at.clone(),
                    drain_deadline,
                }
            } else {
                window.state = WindowState::TransportClosed;
                LocalFinalization::NotRequested
            }
        }
        _ => LocalFinalization::NotRequested,
    };
    Ok(finalization)
}

fn unavailable_measurement(
    measurement_id: String,
    name: &str,
    scope_id: &str,
    at: &TimePoint,
    detail: &str,
) -> Measurement {
    Measurement {
        measurement_id,
        name: name.to_string(),
        scope: Scope {
            kind: ScopeKind::NativePrimitive,
            id: scope_id.to_string(),
        },
        quantity: Quantity::Duration,
        unit: "ms".to_string(),
        origin: MeasurementOrigin::EngineMeasured,
        clock_id: at.clock_id.clone(),
        boot_id: at.boot_id.clone(),
        method: Method::Unavailable,
        start: MaybeTimePoint::Missing(Missing::with_detail(
            "not_observed",
            "no native cancellation wait was performed",
        )),
        end: MaybeTimePoint::Missing(Missing::with_detail(
            "not_observed",
            "no native cancellation wait was performed",
        )),
        estimate: Estimate::Unavailable {
            value: Missing::with_detail("not_observed", detail),
        },
        resolution: MaybeNumber::Missing(Missing::new("not_observed")),
        censoring: Censoring::Unavailable,
        comparability_group: MaybeString::Missing(Missing::new("not_applicable")),
    }
}

// ---------------------------------------------------------------------------
// record_control_response
// ---------------------------------------------------------------------------

/// Appends one correlated response or subject claim as a *new* observation.
///
/// The retained request observation is never rewritten: the new observation
/// carries a new `control_event_id` and the same `operation_id`. An
/// acknowledgement requires a present, authenticated, reliably correlated
/// response; an observed effect requires actual effect references; a subject's
/// own statement stays a claim and never upgrades the disposition or a
/// close-time knowledge boundary.
pub fn record_control_response(
    principal: &AuthenticatedPrincipal,
    request: &ConnectorRequest,
    response: &ControlResponse,
) -> Result<ControlReceipt, ConnectorError> {
    check_principal(principal)?;
    let operation = validate_envelope(request)?;
    let control = &request.payload;
    validate_control_binding(request, control)?;

    for (index, reference) in response.effect_refs.iter().enumerate() {
        resolve_retained(
            principal,
            &control.scope.journal_id,
            reference,
            &format!("effect_refs[{index}]"),
        )?;
    }
    for (index, reference) in response.native_claim_refs.iter().enumerate() {
        resolve_retained(
            principal,
            &control.scope.journal_id,
            reference,
            &format!("native_claim_refs[{index}]"),
        )?;
    }
    match &response.detail {
        MaybeString::Text(text) => require_identifier("response detail", text)?,
        MaybeString::Missing(missing) => require_missing(missing, "response detail")?,
    }
    if let MaybeString::Text(text) = &response.response_ref {
        require_identifier("response_ref", text)?;
    }
    if response.kind == ControlResponseKind::Acknowledged && !response.checks.is_verified() {
        return Err(invalid(
            "an acknowledged disposition requires a present, authenticated, and reliably \
             correlated response; a bare receipt, HTTP success, or unverified reply is not an \
             acknowledgement",
        ));
    }
    if response
        .native_claim_refs
        .iter()
        .any(|claim| response.effect_refs.iter().any(|effect| effect == claim))
    {
        return Err(invalid(
            "a claim reference cannot be reused as effect evidence in the same observation",
        ));
    }

    let key = window_key(principal, &control.handle);
    let identity = operation_id(principal, &control.handle, operation);
    let prior = {
        let store = lock_store();
        store
            .observations
            .get(&key)
            .and_then(|history| {
                history
                    .iter()
                    .rev()
                    .find(|observation| observation.operation_id == identity)
                    .cloned()
            })
            .ok_or_else(|| {
                not_admitted(
                    "no retained control operation exists for this handle and operation: a \
                     response is never the first observation",
                )
            })?
    };

    let disposition = match response.kind {
        // A subject's own statement never upgrades the operation's disposition.
        ControlResponseKind::SubjectClaim => prior.disposition,
        // Actual effect evidence is the strongest evidenced fact, whatever the
        // response claims about delivery.
        _ if !response.effect_refs.is_empty() => Disposition::EffectObserved,
        ControlResponseKind::Acknowledged => Disposition::Acknowledged,
        ControlResponseKind::Failed | ControlResponseKind::Unknown => Disposition::Unknown,
    };

    let target = control_target(&control.parameters, &control.handle);
    let grant = authorization_grant(&control.scope, operation, &target, &control.parameters)?;
    let operation_record = build_operation(request, control, &target);
    rm_authority::authorize_work(principal, &control.scope, &operation_record)?;

    let mut limitations = prior.limitations.clone();
    limitations.push("every prior observation and receipt is retained unchanged".to_string());
    match response.kind {
        ControlResponseKind::Acknowledged => limitations.push(
            "a verified correlated acknowledgement is not an observed effect".to_string(),
        ),
        ControlResponseKind::Failed => limitations.push(
            "the control response failed; delivery and effect knowledge remain unresolved, and a \
             failure never authorizes containment, rollback, or forced termination"
                .to_string(),
        ),
        ControlResponseKind::SubjectClaim => limitations.push(
            "the subject's statement is retained as a claim: it is neither an acknowledgement nor \
             a no-commit fact, and it never rewrites close-time knowledge"
                .to_string(),
        ),
        ControlResponseKind::Unknown => limitations.push(
            "delivery and effect knowledge remain unresolved for this response".to_string(),
        ),
    }
    if let Some(detail) = response.detail_text() {
        limitations.push(format!("response detail: {detail}"));
    }
    if operation == ControlOperation::ReleaseNativeContext
        && response.kind == ControlResponseKind::Failed
    {
        limitations.push(
            "release failure does not implicitly trigger containment; containment requires its own \
             explicit scoped authorization"
                .to_string(),
        );
    }

    let at = local_now();
    let observation = ControlObservation {
        control_event_id: format!(
            "{}#{}",
            identity,
            retained_observation_count(principal, &control.scope.journal_id, &identity)? + 1
        ),
        operation_id: identity,
        operation: prior.operation.clone(),
        target_scope: prior.target_scope.clone(),
        disposition,
        at: at.clone(),
        authorization_ref: MaybeString::Text(grant),
        capability_ref: prior.capability_ref.clone(),
        policy_ref: prior.policy_ref.clone(),
        opportunity: prior.opportunity.clone(),
        request_ref: prior.request_ref.clone(),
        response_ref: response.response_ref.clone(),
        response_checks: response.checks.clone(),
        native_claim_refs: response.native_claim_refs.clone(),
        effect_refs: response.effect_refs.clone(),
        affected_attempts: prior.affected_attempts.clone(),
        measurements: Vec::new(),
        limitations,
        local_finalization: prior.local_finalization.clone(),
    };

    let envelope = append_observation(
        principal,
        &control.manifest,
        &control.scope.journal_id,
        &observation,
        &at,
    )?;
    let registration = evidence_ref(&envelope);
    retain_observation(&mut lock_store(), &key, observation.clone(), registration.clone());
    Ok(ControlReceipt {
        kind: CONTROL_RECEIPT_KIND.to_string(),
        handle: control.handle.clone(),
        observation,
        registration_ref: registration,
    })
}

// ---------------------------------------------------------------------------
// close_at_boundary
// ---------------------------------------------------------------------------

fn window_measurement(
    opened_at: &TimePoint,
    closed_at: &TimePoint,
    name: &str,
) -> Result<Measurement, ConnectorError> {
    same_lifetime(opened_at, closed_at, "the observation window endpoints")?;
    if closed_at.monotonic_offset_ms < opened_at.monotonic_offset_ms {
        return Err(invalid(
            "closed_at precedes opened_at on the registered local clock",
        ));
    }
    let measurement = Measurement {
        measurement_id: format!("measurement-{name}"),
        name: name.to_string(),
        scope: Scope {
            kind: ScopeKind::ConnectorCall,
            id: name.to_string(),
        },
        quantity: Quantity::Duration,
        unit: "ms".to_string(),
        origin: MeasurementOrigin::EngineMeasured,
        clock_id: opened_at.clock_id.clone(),
        boot_id: opened_at.boot_id.clone(),
        method: Method::EndpointDifference,
        start: MaybeTimePoint::Present(opened_at.clone()),
        end: MaybeTimePoint::Present(closed_at.clone()),
        estimate: Estimate::Exact {
            value: closed_at.monotonic_offset_ms - opened_at.monotonic_offset_ms,
        },
        resolution: MaybeNumber::Missing(Missing::new("not_observed")),
        censoring: Censoring::None,
        comparability_group: MaybeString::Missing(Missing::new("not_applicable")),
    };
    let clocks = vec![local_clock().clone()];
    rm_time::validate_measurement(&measurement, &clocks)
        .map_err(|error| invalid(format!("the observation window measurement is invalid: {error}")))?;
    Ok(measurement)
}

/// Closes the observation window at the local boundary and returns the
/// observation-axis revision for the lifecycle owner to publish.
///
/// The attempt identity and commission digest come from the attempt's own
/// published `dispatch` revision; the window's active coordinate comes from the
/// retained `dispatch_published` admission, and its opening coordinate is the
/// durable handle's `created_at` (observation begins with the admitted
/// execution, which is the earliest registered local coordinate the control
/// thread can cite). A pending publication or an absent journaled boundary is a
/// prerequisite failure, never a guessed identity. A closed window is never
/// reopened: a later call returns a closed-to-closed revision only when new
/// late evidence was appended, preserving every original closure field.
pub fn close_at_boundary(
    principal: &AuthenticatedPrincipal,
    handle: &ConnectorHandle,
    now: &TimePoint,
) -> Result<AxisRevision, ConnectorError> {
    check_principal(principal)?;
    handle.validate()?;
    if handle.scope.attempt_id.is_none() {
        return Err(not_admitted(
            "discovery work carries no application attempt observation axis; its closure is \
             connector evidence, not an attempt revision",
        ));
    }
    let policy = ObservationPolicy::for_scope(&handle.scope);
    policy.validate()?;
    let journal_id = handle.scope.journal_id.clone();
    let scan = scan_journal(principal, &journal_id, &handle.handle.local_handle)?;
    let admission = scan.admission.ok_or_else(|| {
        prerequisite(
            "no retained dispatch admission records this handle's local boundary; a closure is \
             never invented from an unknown boundary",
        )
    })?;

    let publication = match rm_delivery::lifecycle_publication(principal, handle)? {
        PublicationState::Published(reference) => reference,
        PublicationState::Pending(missing) => {
            return Err(prerequisite(format!(
                "the attempt's dispatch-axis publication is pending; the observation axis cannot be \
                 published before the attempt identity is recoverable ({}: {})",
                missing.reason,
                missing.detail.unwrap_or_default()
            )))
        }
        PublicationState::NotApplicable(missing) => {
            return Err(not_admitted(format!(
                "the retained handle carries no application attempt axis ({}): observation closure \
                 is connector evidence only",
                missing.reason
            )))
        }
    };
    if publication.axis != Axis::Dispatch {
        return Err(integrity(
            "the retained dispatch publication names a different axis",
        ));
    }
    if Some(publication.attempt.attempt_id.clone()) != handle.scope.attempt_id
        || Some(publication.attempt.kind) != handle.scope.attempt_kind
    {
        return Err(stale(
            "the published attempt identity differs from the admitted handle scope",
        ));
    }

    let key = window_key(principal, &handle.handle);
    let closed: Option<(ClosureRecord, Vec<EvidenceRef>)> = {
        let mut store = lock_store();
        let window = window_for(&mut store, &key, policy.clone());
        if window.state == WindowState::Closed {
            let closure = window
                .closure
                .clone()
                .ok_or_else(|| integrity("a closed window carries no retained closure record"))?;
            Some((closure, window.observed_refs.clone()))
        } else {
            None
        }
    };

    if let Some((closure, observed_refs)) = closed {
        let new_refs: Vec<EvidenceRef> = observed_refs
            .iter()
            .filter(|reference| !closure.cited_refs.contains(&reference.to_json().to_string()))
            .cloned()
            .collect();
        if new_refs.is_empty() {
            return Err(not_admitted(
                "the observation window is already closed and no new late evidence has been \
                 appended; a closed window cannot reopen",
            ));
        }
        let head = rm_evidence::journal_head(principal, &journal_id)?;
        let revision = closure.revision + 1;
        let mut late = closure.late_evidence_refs.clone();
        late.extend(new_refs.iter().cloned());
        let mut cited_refs = closure.cited_refs.clone();
        for reference in &new_refs {
            cited_refs.insert(reference.to_json().to_string());
        }
        let value = closed_observation(
            handle,
            &closure.open_coordinate,
            &closure.active_deadline,
            &closure.drain_started_at,
            &closure.drain_deadline,
            &closure.closed_at,
            closure.close_reason,
            &closure.at_close,
            &closure.measurements,
            &observed_refs,
            &late,
        );
        let revision_value = AxisRevision {
            record_type: AXIS_REVISION_RECORD_TYPE.to_string(),
            schema_version: LIFECYCLE_SCHEMA_VERSION.to_string(),
            attempt: publication.attempt,
            commission_digest: publication.commission_digest,
            axis: Axis::Observation,
            owner_domain: OBSERVATION_DOMAIN.to_string(),
            writer_id: principal.principal_id().to_string(),
            revision,
            previous_revision: revision - 1,
            evidence_prefix: head,
            evidence_refs: observed_refs.clone(),
            value: AxisValue::Observation(value),
        };
        let mut store = lock_store();
        if let Some(window) = store.windows.get_mut(&key) {
            if let Some(retained) = window.closure.as_mut() {
                retained.revision = revision;
                retained.control_observations = observed_refs;
                retained.late_evidence_refs = late;
                retained.cited_refs = cited_refs;
            }
        }
        return Ok(revision_value);
    }

    let (close_request, control_observations) = {
        let store = lock_store();
        let window = store
            .windows
            .get(&key)
            .ok_or_else(|| unknown_handle("no observation window is retained for this handle"))?;
        (window.close_request.clone(), window.observed_refs.clone())
    };
    let effective_deadline = match &close_request {
        Some(request) => {
            same_lifetime(
                &admission.active_deadline,
                &request.drain_deadline,
                "the close bounds",
            )?;
            if request.drain_deadline.monotonic_offset_ms
                < admission.active_deadline.monotonic_offset_ms
            {
                request.drain_deadline.clone()
            } else {
                admission.active_deadline.clone()
            }
        }
        None => admission.active_deadline.clone(),
    };
    let reached = rm_time::boundary_reached(now, &effective_deadline)
        .map_err(|error| invalid(format!("the local boundary cannot be ordered: {error}")))?;
    if !reached {
        return Err(invalid(
            "the local active boundary has not been reached: close_at_boundary closes only at the \
             boundary",
        ));
    }
    if now.monotonic_offset_ms < handle.created_at.monotonic_offset_ms {
        return Err(invalid(
            "the close coordinate precedes the window's opening coordinate",
        ));
    }
    let close_reason = close_request
        .as_ref()
        .map(|request| request.reason.to_close_reason())
        .unwrap_or(CloseReason::LocalDeadline);
    let (drain_started_at, drain_deadline) = match &close_request {
        Some(request) => (
            MaybeTimePoint::Present(request.drain_started_at.clone()),
            MaybeTimePoint::Present(request.drain_deadline.clone()),
        ),
        None => (
            MaybeTimePoint::Missing(Missing::new("not_applicable")),
            MaybeTimePoint::Missing(Missing::new("not_applicable")),
        ),
    };
    let head = rm_evidence::journal_head(principal, &journal_id)?;
    let revision = scan.observation_publications + 1;
    let measurement = window_measurement(&handle.created_at, now, &handle.handle.local_handle)?;
    let mut limitations = vec![
        "known_versions counts retained publication events for this handle; an axis with no such \
         event is recorded as revision zero (unpublished to this connector)"
            .to_string(),
    ];
    if scan.execution_claims == 0 {
        limitations.push(
            "no execution evidence was available at closure: native execution knowledge is unknown"
                .to_string(),
        );
    } else {
        limitations.push(format!(
            "{} execution claim event(s) were journaled for this handle; their terminality is not \
             established at closure",
            scan.execution_claims
        ));
    }
    if scan.origin_facts == 0 {
        limitations.push(
            "no origin fact establishes application commitment at closure: application knowledge is \
             unknown"
                .to_string(),
        );
    }
    limitations.push(
        "a subject's stop statement, a protocol acknowledgement, or a closed transport never \
         establishes a no-commit fact"
            .to_string(),
    );
    limitations.push(format!(
        "the post-close cleanup wait is bounded at {} ms; the control path never waits on native \
         cleanup",
        policy.cleanup_wait_limit_ms
    ));
    limitations.push(
        "the closure is retained by its owning process: a restart re-derives the observation \
         revision from journaled observation publications, so a closure whose publication was \
         never journaled may be proposed again"
            .to_string(),
    );
    let at_close = CloseSnapshot {
        closure_id: format!("closure:{}:{}", handle.handle.local_handle, revision),
        boundary_ref: format!("{journal_id}#{}", admission.sequence),
        known_versions: VersionVector {
            dispatch: publication.revision,
            observation: revision,
            execution: scan.execution_claims,
            application: scan.origin_facts,
            report: scan.report_publications,
        },
        execution_knowledge: ExecKnowledge::Unknown,
        execution_evidence_refs: Vec::new(),
        application_knowledge: AppKnowledge::Unknown,
        application_evidence_refs: Vec::new(),
        limitations: limitations.clone(),
    };
    let value = closed_observation(
        handle,
        &handle.created_at,
        &admission.active_deadline,
        &drain_started_at,
        &drain_deadline,
        now,
        close_reason,
        &at_close,
        std::slice::from_ref(&measurement),
        &control_observations,
        &[],
    );
    let revision_value = AxisRevision {
        record_type: AXIS_REVISION_RECORD_TYPE.to_string(),
        schema_version: LIFECYCLE_SCHEMA_VERSION.to_string(),
        attempt: publication.attempt,
        commission_digest: publication.commission_digest,
        axis: Axis::Observation,
        owner_domain: OBSERVATION_DOMAIN.to_string(),
        writer_id: principal.principal_id().to_string(),
        revision,
        previous_revision: revision - 1,
        evidence_prefix: head,
        evidence_refs: control_observations.clone(),
        value: AxisValue::Observation(value),
    };
    {
        let mut store = lock_store();
        let window = store
            .windows
            .get_mut(&key)
            .ok_or_else(|| unknown_handle("the observation window disappeared"))?;
        window.state = WindowState::Closed;
        window.closure = Some(ClosureRecord {
            revision,
            open_coordinate: handle.created_at.clone(),
            active_deadline: admission.active_deadline.clone(),
            drain_started_at,
            drain_deadline,
            closed_at: now.clone(),
            close_reason,
            at_close,
            measurements: vec![measurement],
            control_observations: control_observations.clone(),
            late_evidence_refs: Vec::new(),
            cited_refs: control_observations
                .iter()
                .map(|reference| reference.to_json().to_string())
                .collect(),
        });
    }
    Ok(revision_value)
}

#[allow(clippy::too_many_arguments)]
fn closed_observation(
    handle: &ConnectorHandle,
    open_coordinate: &TimePoint,
    active_deadline: &TimePoint,
    drain_started_at: &MaybeTimePoint,
    drain_deadline: &MaybeTimePoint,
    closed_at: &TimePoint,
    close_reason: CloseReason,
    at_close: &CloseSnapshot,
    measurements: &[Measurement],
    control_observations: &[EvidenceRef],
    late_evidence_refs: &[EvidenceRef],
) -> ObservationValue {
    ObservationValue {
        state: ObservationState::Closed,
        window_id: format!(
            "window:{}:{}",
            handle.handle.connector_id, handle.handle.local_handle
        ),
        opened_at: MaybeTimePoint::Present(open_coordinate.clone()),
        active_deadline: MaybeTimePoint::Present(active_deadline.clone()),
        drain_started_at: drain_started_at.clone(),
        drain_deadline: drain_deadline.clone(),
        closed_at: MaybeTimePoint::Present(closed_at.clone()),
        close_reason: MaybeCloseReason::Present(close_reason),
        at_close: MaybeCloseSnapshot::Present(at_close.clone()),
        control_observations: control_observations.to_vec(),
        late_evidence_refs: late_evidence_refs.to_vec(),
        measurements: measurements.to_vec(),
        clocks: vec![local_clock().clone()],
    }
}

//! `rm_lifecycle`: tier-5 application-attempt lifecycle publications.
//!
//! Implements the lifecycle rules (seam mapping §16):
//!
//! - [`publish_axis`] admits one connector-axis ([`Axis::Dispatch`],
//!   [`Axis::Observation`], [`Axis::Execution`]) [`AxisRevision`]: identity,
//!   commission binding, single-axis owner authorization, revision
//!   arithmetic, supporting-evidence resolution, per-axis value coherence,
//!   and durable installation of the immutable revision bytes. Application
//!   and report are never published through this entry point: Ringmaster
//!   does not author application facts and only the reconciler writes
//!   report.
//! - [`validate_snapshot`] checks a derived read composition
//!   ([`AttemptSnapshot`]): commission binding, slot/revision agreement,
//!   embedded value coherence, seal/version agreement, and report-pin
//!   freshness (pins may lag the slots; they must never cite the future).
//! - [`validate_reconciliation`] is a pure read-side check over pinned
//!   execution claims and origin facts: coverage accounting, contradiction
//!   dominance, outcome-unknown compatibility (RM-C30), entire-attempt
//!   contradiction retention (RM-C31), temporal-evidence requirements
//!   (RM-C32), and report-only reconciliation that never mutates either
//!   source axis (RM-C57).
//!
//! The journal is the source of truth: every publication cites its
//! supporting prefix and source evidence, and revision bytes are installed
//! before anything may cite them. Journal registration of an admitted
//! publication is the owner's asynchronous step, so a returned
//! [`LifecyclePublicationReference`] carries its content artifact plus a
//! registration pointer that is honestly [`PublicationRegistration::Pending`]
//! until the owner journals it.

#![forbid(unsafe_code)]

use rm_authority::{
    AttemptCommission, AttemptKind, AuthenticatedPrincipal, ConnectorError, EvaluationPartition,
    TargetClass,
};
use rm_evidence::{ArtifactReference, EvidenceRef, JournalPrefix, MaybeDigest};
use rm_time::{
    ClockDescriptor, MaybeString, MaybeTimePoint, Measurement, Missing, TimePoint, UtcAnnotation,
};
use rm_wire::Digest;
use serde_json::{json, Value};

// ---------------------------------------------------------------------------
// Contract identity
// ---------------------------------------------------------------------------

/// Lifecycle record schema version (`application-attempt-lifecycle/0.1.0`).
pub const LIFECYCLE_SCHEMA_VERSION: &str = "application-attempt-lifecycle/0.1.0";
/// Axis-revision record discriminator.
pub const AXIS_REVISION_RECORD_TYPE: &str = "attempt_axis_revision";
/// Attempt-snapshot record discriminator.
pub const SNAPSHOT_RECORD_TYPE: &str = "application_attempt_snapshot";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

fn connector_error(code: &str, fault_domain: &str, detail: impl Into<String>) -> ConnectorError {
    ConnectorError {
        kind: "connector_error".to_string(),
        code: code.to_string(),
        fault_domain: fault_domain.to_string(),
        detail: detail.into(),
        operation_delivery: "not_applicable".to_string(),
        retry_guidance: "operator_review".to_string(),
        retry_after: None,
        handle: None,
        evidence_refs: Vec::new(),
    }
}

fn invalid(detail: impl Into<String>) -> ConnectorError {
    connector_error("INVALID_REQUEST", "request", detail)
}

fn forbidden(detail: impl Into<String>) -> ConnectorError {
    connector_error("FORBIDDEN", "policy", detail)
}

fn require_nonempty(field: &str, value: &str) -> Result<(), ConnectorError> {
    if value.is_empty() {
        return Err(invalid(format!("{field} must be nonempty")));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Small validators over dependency types
// ---------------------------------------------------------------------------

fn validate_missing(missing: &Missing, what: &str) -> Result<(), ConnectorError> {
    if !rm_time::is_valid_reason(&missing.reason) {
        return Err(invalid(format!(
            "invalid Missing reason at {what}: {:?}",
            missing.reason
        )));
    }
    if let Some(detail) = &missing.detail {
        if detail.is_empty() {
            return Err(invalid(format!(
                "invalid Missing detail at {what}: detail must be nonempty"
            )));
        }
    }
    Ok(())
}

fn validate_maybe_string(value: &MaybeString, what: &str) -> Result<(), ConnectorError> {
    match value {
        MaybeString::Text(text) => require_nonempty(what, text),
        MaybeString::Missing(missing) => validate_missing(missing, what),
    }
}

fn validate_timepoint(point: &TimePoint, what: &str) -> Result<(), ConnectorError> {
    require_nonempty(&format!("{what}.clock_id"), &point.clock_id)?;
    require_nonempty(&format!("{what}.boot_id"), &point.boot_id)?;
    if !point.monotonic_offset_ms.is_finite() || point.monotonic_offset_ms < 0.0 {
        return Err(invalid(format!(
            "invalid offset at {what}.monotonic_offset_ms: {:?} is not a finite nonnegative coordinate",
            point.monotonic_offset_ms
        )));
    }
    match &point.utc_annotation {
        UtcAnnotation::DateTime(text) => require_nonempty(&format!("{what}.utc_annotation"), text),
        UtcAnnotation::Missing(missing) => {
            validate_missing(missing, &format!("{what}.utc_annotation"))
        }
    }
}

fn validate_maybe_timepoint(value: &MaybeTimePoint, what: &str) -> Result<(), ConnectorError> {
    match value {
        MaybeTimePoint::Present(point) => validate_timepoint(point, what),
        MaybeTimePoint::Missing(missing) => validate_missing(missing, what),
    }
}

fn validate_maybe_digest(value: &MaybeDigest, what: &str) -> Result<(), ConnectorError> {
    match value {
        MaybeDigest::Present(digest) => {
            if !rm_wire::is_valid_digest(digest.as_str()) {
                return Err(invalid(format!(
                    "invalid digest at {what}: {:?}",
                    digest.as_str()
                )));
            }
            Ok(())
        }
        MaybeDigest::Missing(missing) => validate_missing(missing, what),
    }
}

fn validate_artifact(value: &ArtifactReference, what: &str) -> Result<(), ConnectorError> {
    value.validate().map_err(|error| {
        invalid(format!(
            "invalid artifact reference at {what}: {} [{}]",
            error.detail, error.code
        ))
    })
}

fn validate_evidence_ref(value: &EvidenceRef, what: &str) -> Result<(), ConnectorError> {
    value.validate().map_err(|error| {
        invalid(format!(
            "invalid evidence reference at {what}: {} [{}]",
            error.detail, error.code
        ))
    })
}

fn missing_json(missing: &Missing) -> Value {
    let mut map = serde_json::Map::new();
    map.insert("value".to_string(), Value::Null);
    map.insert(
        "reason".to_string(),
        Value::String(missing.reason.clone()),
    );
    if let Some(detail) = &missing.detail {
        map.insert("detail".to_string(), Value::String(detail.clone()));
    }
    Value::Object(map)
}

fn maybe_digest_json(value: &MaybeDigest) -> Value {
    match value {
        MaybeDigest::Present(digest) => Value::String(digest.as_str().to_string()),
        MaybeDigest::Missing(missing) => missing_json(missing),
    }
}

// ---------------------------------------------------------------------------
// Axes
// ---------------------------------------------------------------------------

/// The five publication axes. Exactly one authority role owns each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Axis {
    Dispatch,
    Observation,
    Execution,
    Application,
    Report,
}

impl Axis {
    /// Wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Axis::Dispatch => "dispatch",
            Axis::Observation => "observation",
            Axis::Execution => "execution",
            Axis::Application => "application",
            Axis::Report => "report",
        }
    }

    /// True for the three axes Ringmaster publishes through [`publish_axis`].
    pub fn is_connector_axis(self) -> bool {
        matches!(self, Axis::Dispatch | Axis::Observation | Axis::Execution)
    }
}

/// Journal event kind carrying an axis publication.
fn axis_event_kind(axis: Axis, value: &AxisValue) -> &'static str {
    match (axis, value) {
        (Axis::Dispatch, _) => "dispatch_published",
        (Axis::Observation, AxisValue::Observation(observation))
            if observation.state == ObservationState::Closed =>
        {
            "observation_closed"
        }
        (Axis::Observation, _) => "observation_opened",
        (Axis::Execution, _) => "execution_claim",
        (Axis::Application, _) => "origin_fact",
        (Axis::Report, _) => "report_published",
    }
}

// ---------------------------------------------------------------------------
// Attempt identity
// ---------------------------------------------------------------------------

/// Attempt identity carried by every lifecycle record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptContext {
    pub attempt_id: String,
    pub kind: AttemptKind,
    pub target_class: TargetClass,
    pub target_id: String,
    pub evaluation_partition: EvaluationPartition,
}

fn attempt_kind_str(kind: AttemptKind) -> &'static str {
    match kind {
        AttemptKind::Practice => "practice",
        AttemptKind::Production => "production",
    }
}

fn target_class_str(class: TargetClass) -> &'static str {
    match class {
        TargetClass::Fixture => "fixture",
        TargetClass::Employer => "employer",
    }
}

fn evaluation_partition_str(partition: EvaluationPartition) -> &'static str {
    match partition {
        EvaluationPartition::HeldIn => "held_in",
        EvaluationPartition::HeldOut => "held_out",
    }
}

impl AttemptContext {
    fn validate(&self) -> Result<(), ConnectorError> {
        require_nonempty("attempt.attempt_id", &self.attempt_id)?;
        require_nonempty("attempt.target_id", &self.target_id)?;
        Ok(())
    }

    /// The attempt must name exactly the commissioned attempt.
    fn matches_commission(&self, commission: &AttemptCommission) -> Result<(), ConnectorError> {
        if self.attempt_id != commission.attempt_id
            || self.kind != commission.kind
            || self.target_class != commission.target_class
            || self.target_id != commission.target_id
            || self.evaluation_partition != commission.evaluation_partition
        {
            return Err(invalid(
                "attempt identity does not match the commissioned attempt",
            ));
        }
        Ok(())
    }

    fn to_json(&self) -> Value {
        json!({
            "attempt_id": self.attempt_id,
            "kind": attempt_kind_str(self.kind),
            "target_class": target_class_str(self.target_class),
            "target_id": self.target_id,
            "evaluation_partition": evaluation_partition_str(self.evaluation_partition),
        })
    }
}

// ---------------------------------------------------------------------------
// Commission binding
// ---------------------------------------------------------------------------

fn lineage_json(lineage: &rm_authority::LineageRef) -> Value {
    json!({
        "attempt_id": lineage.attempt_id,
        "kind": attempt_kind_str(lineage.kind),
    })
}

fn optional_lineage_json(lineage: &Option<rm_authority::LineageRef>) -> Value {
    match lineage {
        Some(link) => lineage_json(link),
        None => missing_json(&Missing::new("not_applicable")),
    }
}

fn import_json(import: &rm_authority::EvidenceImport) -> Value {
    json!({
        "source_attempt_id": import.source_attempt_id,
        "source_kind": attempt_kind_str(import.source_kind),
        "source_digest": import.source_digest,
        "claimed_provenance": import.claimed_provenance,
        "retained_bytes_digest": import.retained_bytes_digest,
    })
}

/// Closed JSON projection of a commission. `None` lineage links are reasoned
/// missingness, never bare nulls, so the projection always hashes.
pub fn commission_json(commission: &AttemptCommission) -> Value {
    json!({
        "record_type": commission.record_type,
        "schema_version": commission.schema_version,
        "commission_id": commission.commission_id,
        "run_id": commission.run_id,
        "journal_id": commission.journal_id,
        "manifest_hash": commission.manifest_hash,
        "admission_ref": commission.admission_ref,
        "attempt_id": commission.attempt_id,
        "kind": attempt_kind_str(commission.kind),
        "target_class": target_class_str(commission.target_class),
        "evaluation_partition": evaluation_partition_str(commission.evaluation_partition),
        "target_id": commission.target_id,
        "derived_from": commission.derived_from.iter().map(lineage_json).collect::<Vec<Value>>(),
        "rehearsal_of": optional_lineage_json(&commission.rehearsal_of),
        "performance_of": optional_lineage_json(&commission.performance_of),
        "task_semantic_hash": commission.task_semantic_hash,
        "idempotency_key": commission.idempotency_key,
        "imported_evidence": commission.imported_evidence.iter().map(import_json).collect::<Vec<Value>>(),
    })
}

/// Canonical digest of a commission: the `commission_digest` every axis
/// revision and snapshot must carry.
pub fn commission_digest(commission: &AttemptCommission) -> Result<Digest, ConnectorError> {
    let bytes = serde_json::to_vec(&commission_json(commission))
        .map_err(|error| invalid(format!("commission cannot be serialized: {error}")))?;
    rm_wire::canonical_digest(&bytes)
        .map_err(|error| invalid(format!("commission cannot be hashed: {error}")))
}

// ---------------------------------------------------------------------------
// Dispatch axis (§16.3)
// ---------------------------------------------------------------------------

/// Dispatch lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchState {
    NotStarted,
    Prepared,
    Dispatching,
    Accepted,
    Rejected,
    Uncertain,
}

impl DispatchState {
    pub fn as_str(self) -> &'static str {
        match self {
            DispatchState::NotStarted => "not_started",
            DispatchState::Prepared => "prepared",
            DispatchState::Dispatching => "dispatching",
            DispatchState::Accepted => "accepted",
            DispatchState::Rejected => "rejected",
            DispatchState::Uncertain => "uncertain",
        }
    }
}

/// Dispatch publication value.
#[derive(Debug, Clone, PartialEq)]
pub struct DispatchValue {
    pub state: DispatchState,
    pub local_handle: MaybeString,
    pub native_run_id: MaybeString,
    pub request_digest: MaybeDigest,
    pub delivery_refs: Vec<EvidenceRef>,
    pub acceptance_refs: Vec<EvidenceRef>,
    pub recovery_authorization_refs: Vec<String>,
    pub reason: MaybeString,
}

impl DispatchValue {
    fn validate(&self, previous_revision: u64) -> Result<(), ConnectorError> {
        if previous_revision == 0
            && !matches!(
                self.state,
                DispatchState::NotStarted | DispatchState::Prepared | DispatchState::Rejected
            )
        {
            return Err(invalid(format!(
                "first dispatch revision must start at not_started, prepared, or rejected, found {:?}",
                self.state.as_str()
            )));
        }
        validate_maybe_string(&self.local_handle, "dispatch.local_handle")?;
        validate_maybe_string(&self.native_run_id, "dispatch.native_run_id")?;
        validate_maybe_digest(&self.request_digest, "dispatch.request_digest")?;
        validate_maybe_string(&self.reason, "dispatch.reason")?;
        for (index, reference) in self.delivery_refs.iter().enumerate() {
            validate_evidence_ref(reference, &format!("dispatch.delivery_refs[{index}]"))?;
        }
        for (index, reference) in self.acceptance_refs.iter().enumerate() {
            validate_evidence_ref(reference, &format!("dispatch.acceptance_refs[{index}]"))?;
        }
        for (index, grant) in self.recovery_authorization_refs.iter().enumerate() {
            require_nonempty(
                &format!("dispatch.recovery_authorization_refs[{index}]"),
                grant,
            )?;
        }
        match self.state {
            DispatchState::Dispatching | DispatchState::Accepted | DispatchState::Uncertain => {
                if !matches!(self.local_handle, MaybeString::Text(_)) {
                    return Err(invalid(
                        "dispatch past preparation requires a durable local handle before delivery",
                    ));
                }
                if !matches!(self.request_digest, MaybeDigest::Present(_)) {
                    return Err(invalid(
                        "dispatch past preparation requires a durable request digest before delivery",
                    ));
                }
            }
            _ => {}
        }
        if self.state == DispatchState::Accepted && self.acceptance_refs.is_empty() {
            return Err(invalid(
                "accepted dispatch requires correlated native acceptance evidence, not Start acknowledgement",
            ));
        }
        if matches!(
            self.state,
            DispatchState::Rejected | DispatchState::Uncertain
        ) && !matches!(self.reason, MaybeString::Text(_))
        {
            return Err(invalid(
                "rejected or uncertain dispatch requires an explicit reason",
            ));
        }
        Ok(())
    }

    fn evidence_refs(&self) -> Vec<&EvidenceRef> {
        self.delivery_refs
            .iter()
            .chain(self.acceptance_refs.iter())
            .collect()
    }

    fn to_json(&self) -> Value {
        json!({
            "state": self.state.as_str(),
            "local_handle": maybe_string_json(&self.local_handle),
            "native_run_id": maybe_string_json(&self.native_run_id),
            "request_digest": maybe_digest_json(&self.request_digest),
            "delivery_refs": self.delivery_refs.iter().map(EvidenceRef::to_json).collect::<Vec<Value>>(),
            "acceptance_refs": self.acceptance_refs.iter().map(EvidenceRef::to_json).collect::<Vec<Value>>(),
            "recovery_authorization_refs": self.recovery_authorization_refs,
            "reason": maybe_string_json(&self.reason),
        })
    }
}

fn maybe_string_json(value: &MaybeString) -> Value {
    match value {
        MaybeString::Text(text) => Value::String(text.clone()),
        MaybeString::Missing(missing) => missing_json(missing),
    }
}

// ---------------------------------------------------------------------------
// Observation axis (§16.4)
// ---------------------------------------------------------------------------

/// Observation window states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservationState {
    NotOpened,
    Open,
    Draining,
    Closed,
}

impl ObservationState {
    pub fn as_str(self) -> &'static str {
        match self {
            ObservationState::NotOpened => "not_opened",
            ObservationState::Open => "open",
            ObservationState::Draining => "draining",
            ObservationState::Closed => "closed",
        }
    }
}

/// Observation close reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    NormalCompletion,
    OperatorStop,
    LocalDeadline,
    TranslationFailure,
    LaunchFailure,
    SubjectTerminal,
    ConnectionLost,
    InfrastructureInterruption,
}

impl CloseReason {
    pub fn as_str(self) -> &'static str {
        match self {
            CloseReason::NormalCompletion => "normal_completion",
            CloseReason::OperatorStop => "operator_stop",
            CloseReason::LocalDeadline => "local_deadline",
            CloseReason::TranslationFailure => "translation_failure",
            CloseReason::LaunchFailure => "launch_failure",
            CloseReason::SubjectTerminal => "subject_terminal",
            CloseReason::ConnectionLost => "connection_lost",
            CloseReason::InfrastructureInterruption => "infrastructure_interruption",
        }
    }
}

/// Close reason or reasoned missingness.
#[derive(Debug, Clone, PartialEq)]
pub enum MaybeCloseReason {
    Present(CloseReason),
    Missing(Missing),
}

impl MaybeCloseReason {
    fn validate(&self, what: &str) -> Result<(), ConnectorError> {
        match self {
            MaybeCloseReason::Present(_) => Ok(()),
            MaybeCloseReason::Missing(missing) => validate_missing(missing, what),
        }
    }

    fn to_json(&self) -> Value {
        match self {
            MaybeCloseReason::Present(reason) => Value::String(reason.as_str().to_string()),
            MaybeCloseReason::Missing(missing) => missing_json(missing),
        }
    }
}

/// Execution knowledge at closure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecKnowledge {
    Running,
    Terminal,
    Unknown,
    NotApplicable,
}

impl ExecKnowledge {
    pub fn as_str(self) -> &'static str {
        match self {
            ExecKnowledge::Running => "running",
            ExecKnowledge::Terminal => "terminal",
            ExecKnowledge::Unknown => "unknown",
            ExecKnowledge::NotApplicable => "not_applicable",
        }
    }
}

/// Application knowledge at closure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppKnowledge {
    Committed,
    NotCommitted,
    Unknown,
}

impl AppKnowledge {
    pub fn as_str(self) -> &'static str {
        match self {
            AppKnowledge::Committed => "committed",
            AppKnowledge::NotCommitted => "not_committed",
            AppKnowledge::Unknown => "unknown",
        }
    }
}

/// Numeric revisions of all five axes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionVector {
    pub dispatch: u64,
    pub observation: u64,
    pub execution: u64,
    pub application: u64,
    pub report: u64,
}

impl VersionVector {
    fn to_json(&self) -> Value {
        json!({
            "dispatch": self.dispatch,
            "observation": self.observation,
            "execution": self.execution,
            "application": self.application,
            "report": self.report,
        })
    }
}

/// Immutable close-time snapshot. Only evidence available at closure supports
/// it; later revisions preserve these fields instead of rewriting them.
#[derive(Debug, Clone, PartialEq)]
pub struct CloseSnapshot {
    pub closure_id: String,
    pub boundary_ref: String,
    pub known_versions: VersionVector,
    pub execution_knowledge: ExecKnowledge,
    pub execution_evidence_refs: Vec<EvidenceRef>,
    pub application_knowledge: AppKnowledge,
    pub application_evidence_refs: Vec<EvidenceRef>,
    pub limitations: Vec<String>,
}

impl CloseSnapshot {
    fn validate(&self) -> Result<(), ConnectorError> {
        require_nonempty("observation.at_close.closure_id", &self.closure_id)?;
        require_nonempty("observation.at_close.boundary_ref", &self.boundary_ref)?;
        for (index, reference) in self.execution_evidence_refs.iter().enumerate() {
            validate_evidence_ref(
                reference,
                &format!("observation.at_close.execution_evidence_refs[{index}]"),
            )?;
        }
        for (index, reference) in self.application_evidence_refs.iter().enumerate() {
            validate_evidence_ref(
                reference,
                &format!("observation.at_close.application_evidence_refs[{index}]"),
            )?;
        }
        Ok(())
    }

    fn evidence_refs(&self) -> Vec<&EvidenceRef> {
        self.execution_evidence_refs
            .iter()
            .chain(self.application_evidence_refs.iter())
            .collect()
    }

    fn to_json(&self) -> Value {
        json!({
            "closure_id": self.closure_id,
            "boundary_ref": self.boundary_ref,
            "known_versions": self.known_versions.to_json(),
            "execution_knowledge": self.execution_knowledge.as_str(),
            "execution_evidence_refs": self.execution_evidence_refs.iter().map(EvidenceRef::to_json).collect::<Vec<Value>>(),
            "application_knowledge": self.application_knowledge.as_str(),
            "application_evidence_refs": self.application_evidence_refs.iter().map(EvidenceRef::to_json).collect::<Vec<Value>>(),
            "limitations": self.limitations,
        })
    }
}

/// Close snapshot or reasoned missingness.
#[derive(Debug, Clone, PartialEq)]
pub enum MaybeCloseSnapshot {
    Present(CloseSnapshot),
    Missing(Missing),
}

impl MaybeCloseSnapshot {
    fn to_json(&self) -> Value {
        match self {
            MaybeCloseSnapshot::Present(snapshot) => snapshot.to_json(),
            MaybeCloseSnapshot::Missing(missing) => missing_json(missing),
        }
    }
}

/// Observation publication value.
#[derive(Debug, Clone, PartialEq)]
pub struct ObservationValue {
    pub state: ObservationState,
    pub window_id: String,
    pub opened_at: MaybeTimePoint,
    pub active_deadline: MaybeTimePoint,
    pub drain_started_at: MaybeTimePoint,
    pub drain_deadline: MaybeTimePoint,
    pub closed_at: MaybeTimePoint,
    pub close_reason: MaybeCloseReason,
    pub at_close: MaybeCloseSnapshot,
    pub control_observations: Vec<EvidenceRef>,
    pub late_evidence_refs: Vec<EvidenceRef>,
    pub measurements: Vec<Measurement>,
    /// Registered clock set backing `measurements` (clocks register before use).
    pub clocks: Vec<ClockDescriptor>,
}

fn require_present_time(value: &MaybeTimePoint, what: &str) -> Result<(), ConnectorError> {
    match value {
        MaybeTimePoint::Present(point) => validate_timepoint(point, what),
        MaybeTimePoint::Missing(_) => Err(invalid(format!("{what} is required in this state"))),
    }
}

fn require_inapplicable_time(value: &MaybeTimePoint, what: &str) -> Result<(), ConnectorError> {
    match value {
        MaybeTimePoint::Present(_) => Err(invalid(format!(
            "{what} must be inapplicable while the window is not closed"
        ))),
        MaybeTimePoint::Missing(missing) => {
            validate_missing(missing, what)?;
            if missing.reason != "not_applicable" {
                return Err(invalid(format!(
                    "{what} must carry not_applicable missingness while the window is not closed"
                )));
            }
            Ok(())
        }
    }
}

impl ObservationValue {
    fn validate(&self, previous_revision: u64) -> Result<(), ConnectorError> {
        if previous_revision == 0
            && !matches!(
                self.state,
                ObservationState::NotOpened | ObservationState::Open | ObservationState::Closed
            )
        {
            return Err(invalid(format!(
                "first observation revision must start at not_opened, open, or closed, found {:?}",
                self.state.as_str()
            )));
        }
        require_nonempty("observation.window_id", &self.window_id)?;
        validate_maybe_timepoint(&self.opened_at, "observation.opened_at")?;
        validate_maybe_timepoint(&self.active_deadline, "observation.active_deadline")?;
        validate_maybe_timepoint(&self.drain_started_at, "observation.drain_started_at")?;
        validate_maybe_timepoint(&self.drain_deadline, "observation.drain_deadline")?;
        validate_maybe_timepoint(&self.closed_at, "observation.closed_at")?;
        self.close_reason
            .validate("observation.close_reason")?;
        match self.state {
            ObservationState::NotOpened => {
                if !matches!(self.opened_at, MaybeTimePoint::Missing(_))
                    || !matches!(self.active_deadline, MaybeTimePoint::Missing(_))
                {
                    return Err(invalid(
                        "a not-opened window carries no opened_at or active_deadline",
                    ));
                }
                if !matches!(self.drain_started_at, MaybeTimePoint::Missing(_))
                    || !matches!(self.drain_deadline, MaybeTimePoint::Missing(_))
                {
                    return Err(invalid("a not-opened window carries no drain coordinates"));
                }
                if !matches!(self.close_reason, MaybeCloseReason::Missing(_)) {
                    return Err(invalid("a not-opened window carries no close reason"));
                }
                require_inapplicable_time(&self.closed_at, "observation.closed_at")?;
                self.require_no_snapshot()?;
            }
            ObservationState::Open => {
                require_present_time(&self.opened_at, "observation.opened_at")?;
                require_present_time(&self.active_deadline, "observation.active_deadline")?;
                if !matches!(self.drain_started_at, MaybeTimePoint::Missing(_))
                    || !matches!(self.drain_deadline, MaybeTimePoint::Missing(_))
                {
                    return Err(invalid("an open window carries no drain coordinates"));
                }
                if !matches!(self.close_reason, MaybeCloseReason::Missing(_)) {
                    return Err(invalid("an open window carries no close reason"));
                }
                require_inapplicable_time(&self.closed_at, "observation.closed_at")?;
                self.require_no_snapshot()?;
            }
            ObservationState::Draining => {
                require_present_time(&self.opened_at, "observation.opened_at")?;
                require_present_time(&self.active_deadline, "observation.active_deadline")?;
                require_present_time(&self.drain_started_at, "observation.drain_started_at")?;
                require_present_time(&self.drain_deadline, "observation.drain_deadline")?;
                if !matches!(self.close_reason, MaybeCloseReason::Present(_)) {
                    return Err(invalid("a draining window requires a close reason"));
                }
                require_inapplicable_time(&self.closed_at, "observation.closed_at")?;
                self.require_no_snapshot()?;
            }
            ObservationState::Closed => {
                require_present_time(&self.opened_at, "observation.opened_at")?;
                require_present_time(&self.active_deadline, "observation.active_deadline")?;
                require_present_time(&self.closed_at, "observation.closed_at")?;
                if !matches!(self.close_reason, MaybeCloseReason::Present(_)) {
                    return Err(invalid("a closed window requires a close reason"));
                }
                match &self.at_close {
                    MaybeCloseSnapshot::Present(snapshot) => snapshot.validate()?,
                    MaybeCloseSnapshot::Missing(_) => {
                        return Err(invalid("a closed window requires its close snapshot"))
                    }
                }
            }
        }
        for (index, reference) in self.control_observations.iter().enumerate() {
            validate_evidence_ref(
                reference,
                &format!("observation.control_observations[{index}]"),
            )?;
        }
        for (index, reference) in self.late_evidence_refs.iter().enumerate() {
            validate_evidence_ref(
                reference,
                &format!("observation.late_evidence_refs[{index}]"),
            )?;
        }
        for clock in &self.clocks {
            require_nonempty("observation.clocks.clock_id", &clock.clock_id)?;
            require_nonempty("observation.clocks.boot_id", &clock.boot_id)?;
            require_nonempty("observation.clocks.source_id", &clock.source_id)?;
            if clock.unit != "ms" {
                return Err(invalid("observation clock unit must be \"ms\""));
            }
        }
        for measurement in &self.measurements {
            rm_time::validate_measurement(measurement, &self.clocks).map_err(|error| {
                invalid(format!("observation measurement invalid: {error}"))
            })?;
        }
        Ok(())
    }

    fn require_no_snapshot(&self) -> Result<(), ConnectorError> {
        match &self.at_close {
            MaybeCloseSnapshot::Present(_) => Err(invalid(
                "a non-closed window carries no close snapshot",
            )),
            MaybeCloseSnapshot::Missing(missing) => {
                validate_missing(missing, "observation.at_close")?;
                if missing.reason != "not_applicable" {
                    return Err(invalid(
                        "a non-closed window carries not_applicable at_close missingness",
                    ));
                }
                Ok(())
            }
        }
    }

    fn evidence_refs(&self) -> Vec<&EvidenceRef> {
        let mut refs: Vec<&EvidenceRef> = self
            .control_observations
            .iter()
            .chain(self.late_evidence_refs.iter())
            .collect();
        if let MaybeCloseSnapshot::Present(snapshot) = &self.at_close {
            refs.extend(snapshot.evidence_refs());
        }
        refs
    }

    fn to_json(&self) -> Value {
        json!({
            "state": self.state.as_str(),
            "window_id": self.window_id,
            "opened_at": maybe_timepoint_json(&self.opened_at),
            "active_deadline": maybe_timepoint_json(&self.active_deadline),
            "drain_started_at": maybe_timepoint_json(&self.drain_started_at),
            "drain_deadline": maybe_timepoint_json(&self.drain_deadline),
            "closed_at": maybe_timepoint_json(&self.closed_at),
            "close_reason": self.close_reason.to_json(),
            "at_close": self.at_close.to_json(),
            "control_observations": self.control_observations.iter().map(EvidenceRef::to_json).collect::<Vec<Value>>(),
            "late_evidence_refs": self.late_evidence_refs.iter().map(EvidenceRef::to_json).collect::<Vec<Value>>(),
            "measurements": self.measurements.iter().map(|m| serde_json::to_value(m).unwrap_or(Value::Null)).collect::<Vec<Value>>(),
            "clocks": self.clocks.iter().map(|c| serde_json::to_value(c).unwrap_or(Value::Null)).collect::<Vec<Value>>(),
        })
    }
}

fn maybe_timepoint_json(value: &MaybeTimePoint) -> Value {
    match value {
        MaybeTimePoint::Present(point) => {
            serde_json::to_value(point).unwrap_or(Value::Null)
        }
        MaybeTimePoint::Missing(missing) => missing_json(missing),
    }
}

// ---------------------------------------------------------------------------
// Source checks (§14.4) shared by execution claims and origin facts
// ---------------------------------------------------------------------------

/// Authentication outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthStatus {
    Verified,
    Failed,
    Unknown,
}

impl AuthStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            AuthStatus::Verified => "verified",
            AuthStatus::Failed => "failed",
            AuthStatus::Unknown => "unknown",
        }
    }
}

/// Correlation outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorrelationStatus {
    Matched,
    Mismatched,
    Unknown,
}

impl CorrelationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            CorrelationStatus::Matched => "matched",
            CorrelationStatus::Mismatched => "mismatched",
            CorrelationStatus::Unknown => "unknown",
        }
    }
}

/// Trace-correlation outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceStatus {
    Matched,
    Mismatched,
    NotObserved,
    NotApplicable,
}

impl TraceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            TraceStatus::Matched => "matched",
            TraceStatus::Mismatched => "mismatched",
            TraceStatus::NotObserved => "not_observed",
            TraceStatus::NotApplicable => "not_applicable",
        }
    }
}

/// Verified authentication and correlation evidence for one source statement.
#[derive(Debug, Clone, PartialEq)]
pub struct SourceChecks {
    pub authentication: AuthStatus,
    pub correlation: CorrelationStatus,
    pub trace_correlation: TraceStatus,
    pub verification_policy: String,
    pub matched_by: MaybeString,
    pub evidence_refs: Vec<EvidenceRef>,
}

impl SourceChecks {
    fn validate(&self, what: &str) -> Result<(), ConnectorError> {
        require_nonempty(
            &format!("{what}.verification_policy"),
            &self.verification_policy,
        )?;
        validate_maybe_string(&self.matched_by, &format!("{what}.matched_by"))?;
        for (index, reference) in self.evidence_refs.iter().enumerate() {
            validate_evidence_ref(reference, &format!("{what}.evidence_refs[{index}]"))?;
        }
        if self.correlation == CorrelationStatus::Matched
            && !matches!(self.matched_by, MaybeString::Text(_))
        {
            return Err(invalid(format!(
                "{what}: matched correlation must name its mechanism explicitly"
            )));
        }
        if self.trace_correlation == TraceStatus::Mismatched && self.evidence_refs.is_empty() {
            return Err(invalid(format!(
                "{what}: correlation despite a trace mismatch must be explicit and supported"
            )));
        }
        Ok(())
    }

    /// Accepted statements require verified authentication and matched
    /// correlation; a valid signature with a trace mismatch stays
    /// authenticated but uncorrelated unless an alternate match is proven.
    fn require_accepted(&self, what: &str) -> Result<(), ConnectorError> {
        if self.authentication != AuthStatus::Verified {
            return Err(invalid(format!(
                "{what}: unverified reports carry no accepted statements"
            )));
        }
        if self.correlation != CorrelationStatus::Matched {
            return Err(invalid(format!(
                "{what}: uncorrelated reports carry no accepted statements"
            )));
        }
        Ok(())
    }

    fn to_json(&self) -> Value {
        json!({
            "authentication": self.authentication.as_str(),
            "correlation": self.correlation.as_str(),
            "trace_correlation": self.trace_correlation.as_str(),
            "verification_policy": self.verification_policy,
            "matched_by": maybe_string_json(&self.matched_by),
            "evidence_refs": self.evidence_refs.iter().map(EvidenceRef::to_json).collect::<Vec<Value>>(),
        })
    }
}

// ---------------------------------------------------------------------------
// Execution axis (§14.5, §16.5)
// ---------------------------------------------------------------------------

/// Execution claim scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimScope {
    Primitive,
    ApplicationPostcondition,
    ExecutionLifecycle,
    Unknown,
}

impl ClaimScope {
    pub fn as_str(self) -> &'static str {
        match self {
            ClaimScope::Primitive => "primitive",
            ClaimScope::ApplicationPostcondition => "application_postcondition",
            ClaimScope::ExecutionLifecycle => "execution_lifecycle",
            ClaimScope::Unknown => "unknown",
        }
    }

    /// Claims that can carry application assertions subject to reconciliation.
    pub fn is_applicable(self) -> bool {
        matches!(
            self,
            ClaimScope::ApplicationPostcondition | ClaimScope::ExecutionLifecycle
        )
    }
}

/// Native execution state statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeState {
    Running,
    Completed,
    Failed,
    Stopped,
    Unknown,
}

impl NativeState {
    pub fn as_str(self) -> &'static str {
        match self {
            NativeState::Running => "running",
            NativeState::Completed => "completed",
            NativeState::Failed => "failed",
            NativeState::Stopped => "stopped",
            NativeState::Unknown => "unknown",
        }
    }
}

/// Native state or reasoned missingness.
#[derive(Debug, Clone, PartialEq)]
pub enum MaybeNativeState {
    Present(NativeState),
    Missing(Missing),
}

impl MaybeNativeState {
    fn validate(&self, what: &str) -> Result<(), ConnectorError> {
        match self {
            MaybeNativeState::Present(_) => Ok(()),
            MaybeNativeState::Missing(missing) => validate_missing(missing, what),
        }
    }

    fn to_json(&self) -> Value {
        match self {
            MaybeNativeState::Present(state) => Value::String(state.as_str().to_string()),
            MaybeNativeState::Missing(missing) => missing_json(missing),
        }
    }
}

/// Commitment assertion value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitmentValue {
    Committed,
    NotCommitted,
    OutcomeUnknown,
}

impl CommitmentValue {
    pub fn as_str(self) -> &'static str {
        match self {
            CommitmentValue::Committed => "committed",
            CommitmentValue::NotCommitted => "not_committed",
            CommitmentValue::OutcomeUnknown => "outcome_unknown",
        }
    }
}

/// Commitment assertion span.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitmentSpan {
    AtBoundary,
    AfterBoundary,
    EntireAttempt,
}

impl CommitmentSpan {
    pub fn as_str(self) -> &'static str {
        match self {
            CommitmentSpan::AtBoundary => "at_boundary",
            CommitmentSpan::AfterBoundary => "after_boundary",
            CommitmentSpan::EntireAttempt => "entire_attempt",
        }
    }

    /// Boundary-scoped assertions need temporal evidence before a decisive
    /// comparison; entire-attempt assertions do not.
    pub fn needs_temporal_evidence(self) -> bool {
        matches!(
            self,
            CommitmentSpan::AtBoundary | CommitmentSpan::AfterBoundary
        )
    }
}

/// One explicit source commitment assertion.
#[derive(Debug, Clone, PartialEq)]
pub struct CommitmentAssertion {
    pub assertion_id: String,
    pub value: CommitmentValue,
    pub span: CommitmentSpan,
    pub boundary_ref: MaybeString,
    pub evidence_refs: Vec<EvidenceRef>,
}

impl CommitmentAssertion {
    fn validate(&self, what: &str) -> Result<(), ConnectorError> {
        require_nonempty(&format!("{what}.assertion_id"), &self.assertion_id)?;
        validate_maybe_string(&self.boundary_ref, &format!("{what}.boundary_ref"))?;
        for (index, reference) in self.evidence_refs.iter().enumerate() {
            validate_evidence_ref(reference, &format!("{what}.evidence_refs[{index}]"))?;
        }
        match self.span {
            CommitmentSpan::EntireAttempt => match &self.boundary_ref {
                MaybeString::Missing(missing) if missing.reason == "not_applicable" => {}
                _ => {
                    return Err(invalid(format!(
                        "{what}: entire-attempt span uses an inapplicable boundary"
                    )))
                }
            },
            CommitmentSpan::AtBoundary | CommitmentSpan::AfterBoundary => {
                if !matches!(self.boundary_ref, MaybeString::Text(_)) {
                    return Err(invalid(format!(
                        "{what}: boundary spans require a real boundary reference"
                    )));
                }
            }
        }
        Ok(())
    }

    fn to_json(&self) -> Value {
        json!({
            "assertion_id": self.assertion_id,
            "value": self.value.as_str(),
            "span": self.span.as_str(),
            "boundary_ref": maybe_string_json(&self.boundary_ref),
            "evidence_refs": self.evidence_refs.iter().map(EvidenceRef::to_json).collect::<Vec<Value>>(),
        })
    }
}

/// One faithfully mapped, source-attributed execution claim.
#[derive(Debug, Clone, PartialEq)]
pub struct ExecutionClaim {
    pub claim_id: String,
    pub scope: ClaimScope,
    pub state: MaybeNativeState,
    pub application_assertions: Vec<CommitmentAssertion>,
    pub native_run_id: MaybeString,
    pub native_message_id: MaybeString,
    pub native_report: ArtifactReference,
    pub mapping: String,
    pub source_checks: SourceChecks,
    pub made_at: MaybeTimePoint,
    pub received_at: TimePoint,
    pub evidence_available_to_claimant: Vec<String>,
    pub evidence_refs: Vec<EvidenceRef>,
    pub limitations: Vec<String>,
}

impl ExecutionClaim {
    fn validate(&self) -> Result<(), ConnectorError> {
        let what = format!("execution.claims[{}]", self.claim_id);
        require_nonempty("execution.claims.claim_id", &self.claim_id)?;
        self.state.validate(&format!("{what}.state"))?;
        match self.scope {
            ClaimScope::Primitive => {
                if !matches!(
                    &self.state,
                    MaybeNativeState::Missing(missing) if missing.reason == "not_applicable"
                ) {
                    return Err(invalid(format!(
                        "{what}: primitive scope requires inapplicable state"
                    )));
                }
                if !self.application_assertions.is_empty() {
                    return Err(invalid(format!(
                        "{what}: primitive scope carries no application assertions"
                    )));
                }
            }
            ClaimScope::Unknown => {
                if !matches!(self.state, MaybeNativeState::Missing(_)) {
                    return Err(invalid(format!(
                        "{what}: unknown scope requires missing state"
                    )));
                }
                if !self.application_assertions.is_empty() {
                    return Err(invalid(format!(
                        "{what}: unknown scope carries no application assertions"
                    )));
                }
            }
            ClaimScope::ApplicationPostcondition | ClaimScope::ExecutionLifecycle => {}
        }
        let mut seen = std::collections::BTreeSet::new();
        for assertion in &self.application_assertions {
            if !seen.insert(assertion.assertion_id.clone()) {
                return Err(invalid(format!(
                    "{what}: duplicate assertion_id {:?}",
                    assertion.assertion_id
                )));
            }
            assertion.validate(&format!(
                "{what}.assertions[{}]",
                assertion.assertion_id
            ))?;
        }
        validate_maybe_string(&self.native_run_id, &format!("{what}.native_run_id"))?;
        validate_maybe_string(&self.native_message_id, &format!("{what}.native_message_id"))?;
        validate_artifact(&self.native_report, &format!("{what}.native_report"))?;
        require_nonempty(&format!("{what}.mapping"), &self.mapping)?;
        self.source_checks
            .validate(&format!("{what}.source_checks"))?;
        self.source_checks
            .require_accepted(&format!("{what}.source_checks"))?;
        validate_maybe_timepoint(&self.made_at, &format!("{what}.made_at"))?;
        validate_timepoint(&self.received_at, &format!("{what}.received_at"))?;
        for (index, reference) in self.evidence_refs.iter().enumerate() {
            validate_evidence_ref(reference, &format!("{what}.evidence_refs[{index}]"))?;
        }
        Ok(())
    }

    fn evidence_refs(&self) -> Vec<&EvidenceRef> {
        let mut refs: Vec<&EvidenceRef> = self.evidence_refs.iter().collect();
        refs.extend(self.source_checks.evidence_refs.iter());
        for assertion in &self.application_assertions {
            refs.extend(assertion.evidence_refs.iter());
        }
        refs
    }

    fn to_json(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "scope": self.scope.as_str(),
            "state": self.state.to_json(),
            "application_assertions": self.application_assertions.iter().map(CommitmentAssertion::to_json).collect::<Vec<Value>>(),
            "native_run_id": maybe_string_json(&self.native_run_id),
            "native_message_id": maybe_string_json(&self.native_message_id),
            "native_report": self.native_report.to_json(),
            "mapping": self.mapping,
            "source_checks": self.source_checks.to_json(),
            "made_at": maybe_timepoint_json(&self.made_at),
            "received_at": serde_json::to_value(&self.received_at).unwrap_or(Value::Null),
            "evidence_available_to_claimant": self.evidence_available_to_claimant,
            "evidence_refs": self.evidence_refs.iter().map(EvidenceRef::to_json).collect::<Vec<Value>>(),
            "limitations": self.limitations,
        })
    }
}

/// Cumulative execution claims. Existing claim IDs and content never change.
#[derive(Debug, Clone, PartialEq)]
pub struct ExecutionValue {
    pub claims: Vec<ExecutionClaim>,
}

impl ExecutionValue {
    fn validate(&self) -> Result<(), ConnectorError> {
        if self.claims.is_empty() {
            return Err(invalid("execution value requires a nonempty claims array"));
        }
        let mut seen = std::collections::BTreeSet::new();
        for claim in &self.claims {
            if !seen.insert(claim.claim_id.clone()) {
                return Err(invalid(format!(
                    "duplicate execution claim_id {:?}",
                    claim.claim_id
                )));
            }
            claim.validate()?;
        }
        Ok(())
    }

    fn evidence_refs(&self) -> Vec<&EvidenceRef> {
        self.claims
            .iter()
            .flat_map(ExecutionClaim::evidence_refs)
            .collect()
    }

    fn to_json(&self) -> Value {
        json!({
            "claims": self.claims.iter().map(ExecutionClaim::to_json).collect::<Vec<Value>>(),
        })
    }

    fn find_claim(&self, claim_id: &str) -> Option<&ExecutionClaim> {
        self.claims
            .iter()
            .find(|claim| claim.claim_id == claim_id)
    }
}

// ---------------------------------------------------------------------------
// Application axis (§16.5)
// ---------------------------------------------------------------------------

/// Origin fact commitment state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginState {
    Committed,
    NotCommitted,
}

impl OriginState {
    pub fn as_str(self) -> &'static str {
        match self {
            OriginState::Committed => "committed",
            OriginState::NotCommitted => "not_committed",
        }
    }
}

/// Origin fact coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginCoverage {
    AtBoundary,
    FinalForAttempt,
}

impl OriginCoverage {
    pub fn as_str(self) -> &'static str {
        match self {
            OriginCoverage::AtBoundary => "at_boundary",
            OriginCoverage::FinalForAttempt => "final_for_attempt",
        }
    }
}

/// Origin receipt verification kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationKind {
    VerifiedOriginReceipt,
    LocalOriginTransaction,
}

impl VerificationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            VerificationKind::VerifiedOriginReceipt => "verified_origin_receipt",
            VerificationKind::LocalOriginTransaction => "local_origin_transaction",
        }
    }
}

/// One origin fact. Ringmaster never authors these.
#[derive(Debug, Clone, PartialEq)]
pub struct OriginFact {
    pub fact_id: String,
    pub origin_id: String,
    pub candidate_id: String,
    pub job_id: String,
    pub state: OriginState,
    pub coverage: OriginCoverage,
    pub boundary_ref: String,
    pub origin_application_id: MaybeString,
    pub origin_revision: MaybeString,
    pub receipt: ArtifactReference,
    pub verification_kind: VerificationKind,
    pub source_checks: SourceChecks,
    pub authority_seal_ref: String,
    pub occurred_at: MaybeTimePoint,
    pub received_at: TimePoint,
    pub evidence_refs: Vec<EvidenceRef>,
}

impl OriginFact {
    fn validate(&self) -> Result<(), ConnectorError> {
        let what = format!("application.facts[{}]", self.fact_id);
        require_nonempty("application.facts.fact_id", &self.fact_id)?;
        require_nonempty(&format!("{what}.origin_id"), &self.origin_id)?;
        require_nonempty(&format!("{what}.candidate_id"), &self.candidate_id)?;
        require_nonempty(&format!("{what}.job_id"), &self.job_id)?;
        require_nonempty(&format!("{what}.boundary_ref"), &self.boundary_ref)?;
        validate_maybe_string(
            &self.origin_application_id,
            &format!("{what}.origin_application_id"),
        )?;
        validate_maybe_string(&self.origin_revision, &format!("{what}.origin_revision"))?;
        if self.state == OriginState::Committed
            && !matches!(self.origin_application_id, MaybeString::Text(_))
        {
            return Err(invalid(format!(
                "{what}: a committed fact names its origin application"
            )));
        }
        validate_artifact(&self.receipt, &format!("{what}.receipt"))?;
        self.source_checks
            .validate(&format!("{what}.source_checks"))?;
        require_nonempty(&format!("{what}.authority_seal_ref"), &self.authority_seal_ref)?;
        validate_maybe_timepoint(&self.occurred_at, &format!("{what}.occurred_at"))?;
        validate_timepoint(&self.received_at, &format!("{what}.received_at"))?;
        if self.evidence_refs.is_empty() {
            return Err(invalid(format!(
                "{what}: a fact cites its transaction or verified origin receipt"
            )));
        }
        for (index, reference) in self.evidence_refs.iter().enumerate() {
            validate_evidence_ref(reference, &format!("{what}.evidence_refs[{index}]"))?;
        }
        Ok(())
    }

    fn evidence_refs(&self) -> Vec<&EvidenceRef> {
        let mut refs: Vec<&EvidenceRef> = self.evidence_refs.iter().collect();
        refs.extend(self.source_checks.evidence_refs.iter());
        refs
    }

    fn to_json(&self) -> Value {
        json!({
            "fact_id": self.fact_id,
            "origin_id": self.origin_id,
            "candidate_id": self.candidate_id,
            "job_id": self.job_id,
            "state": self.state.as_str(),
            "coverage": self.coverage.as_str(),
            "boundary_ref": self.boundary_ref,
            "origin_application_id": maybe_string_json(&self.origin_application_id),
            "origin_revision": maybe_string_json(&self.origin_revision),
            "receipt": self.receipt.to_json(),
            "verification_kind": self.verification_kind.as_str(),
            "source_checks": self.source_checks.to_json(),
            "authority_seal_ref": self.authority_seal_ref,
            "occurred_at": maybe_timepoint_json(&self.occurred_at),
            "received_at": serde_json::to_value(&self.received_at).unwrap_or(Value::Null),
            "evidence_refs": self.evidence_refs.iter().map(EvidenceRef::to_json).collect::<Vec<Value>>(),
        })
    }
}

/// Cumulative origin facts.
#[derive(Debug, Clone, PartialEq)]
pub struct ApplicationValue {
    pub facts: Vec<OriginFact>,
}

impl ApplicationValue {
    fn validate(&self) -> Result<(), ConnectorError> {
        if self.facts.is_empty() {
            return Err(invalid("application value requires a nonempty facts array"));
        }
        let mut seen = std::collections::BTreeSet::new();
        for fact in &self.facts {
            if !seen.insert(fact.fact_id.clone()) {
                return Err(invalid(format!(
                    "duplicate origin fact_id {:?}",
                    fact.fact_id
                )));
            }
            fact.validate()?;
        }
        Ok(())
    }

    fn evidence_refs(&self) -> Vec<&EvidenceRef> {
        self.facts
            .iter()
            .flat_map(OriginFact::evidence_refs)
            .collect()
    }

    fn to_json(&self) -> Value {
        json!({
            "facts": self.facts.iter().map(OriginFact::to_json).collect::<Vec<Value>>(),
        })
    }

    fn find_fact(&self, fact_id: &str) -> Option<&OriginFact> {
        self.facts.iter().find(|fact| fact.fact_id == fact_id)
    }
}

// ---------------------------------------------------------------------------
// Report axis (§16.6)
// ---------------------------------------------------------------------------

/// Report state: reconciled, contradicted, or Missing.
#[derive(Debug, Clone, PartialEq)]
pub enum ReportState {
    Reconciled,
    Contradicted,
    Missing(Missing),
}

impl ReportState {
    fn validate(&self) -> Result<(), ConnectorError> {
        match self {
            ReportState::Reconciled | ReportState::Contradicted => Ok(()),
            ReportState::Missing(missing) => validate_missing(missing, "report.state"),
        }
    }

    fn to_json(&self) -> Value {
        match self {
            ReportState::Reconciled => Value::String("reconciled".to_string()),
            ReportState::Contradicted => Value::String("contradicted".to_string()),
            ReportState::Missing(missing) => missing_json(missing),
        }
    }
}

/// Report coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportCoverage {
    Complete,
    Incomplete,
    NotApplicable,
}

impl ReportCoverage {
    pub fn as_str(self) -> &'static str {
        match self {
            ReportCoverage::Complete => "complete",
            ReportCoverage::Incomplete => "incomplete",
            ReportCoverage::NotApplicable => "not_applicable",
        }
    }
}

/// Comparison result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComparisonResult {
    Consistent,
    Contradicted,
    NotComparable,
    Indeterminate,
}

impl ComparisonResult {
    pub fn as_str(self) -> &'static str {
        match self {
            ComparisonResult::Consistent => "consistent",
            ComparisonResult::Contradicted => "contradicted",
            ComparisonResult::NotComparable => "not_comparable",
            ComparisonResult::Indeterminate => "indeterminate",
        }
    }

    fn is_decisive(self) -> bool {
        matches!(
            self,
            ComparisonResult::Consistent | ComparisonResult::Contradicted
        )
    }
}

/// Temporal relation between compared propositions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemporalRelationKind {
    Before,
    At,
    After,
    Unknown,
}

impl TemporalRelationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            TemporalRelationKind::Before => "before",
            TemporalRelationKind::At => "at",
            TemporalRelationKind::After => "after",
            TemporalRelationKind::Unknown => "unknown",
        }
    }

    fn is_known(self) -> bool {
        !matches!(self, TemporalRelationKind::Unknown)
    }
}

/// Evidence basis for a temporal relation. Receipt ordering alone is never
/// sufficient for a known relation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemporalBasis {
    SameClock,
    Causal,
    OriginSequence,
    ReceiptOrder,
    Unknown,
}

impl TemporalBasis {
    pub fn as_str(self) -> &'static str {
        match self {
            TemporalBasis::SameClock => "same_clock",
            TemporalBasis::Causal => "causal",
            TemporalBasis::OriginSequence => "origin_sequence",
            TemporalBasis::ReceiptOrder => "receipt_order",
            TemporalBasis::Unknown => "unknown",
        }
    }

    fn proves_order(self) -> bool {
        matches!(
            self,
            TemporalBasis::SameClock | TemporalBasis::Causal | TemporalBasis::OriginSequence
        )
    }
}

/// Temporal evidence for one comparison.
#[derive(Debug, Clone, PartialEq)]
pub struct TemporalRelation {
    pub relation: TemporalRelationKind,
    pub basis: TemporalBasis,
    pub evidence_refs: Vec<String>,
}

impl TemporalRelation {
    fn validate(&self, what: &str) -> Result<(), ConnectorError> {
        for (index, reference) in self.evidence_refs.iter().enumerate() {
            require_nonempty(&format!("{what}.evidence_refs[{index}]"), reference)?;
        }
        if self.relation.is_known() {
            if !self.basis.proves_order() {
                return Err(invalid(format!(
                    "{what}: a known temporal relation requires same-clock, causal, or origin-sequence evidence; receipt ordering alone is insufficient"
                )));
            }
            if self.evidence_refs.is_empty() {
                return Err(invalid(format!(
                    "{what}: a known temporal relation requires supporting evidence"
                )));
            }
        }
        Ok(())
    }

    /// True when the relation proves order with supporting evidence.
    fn is_proven(&self) -> bool {
        self.relation.is_known() && self.basis.proves_order() && !self.evidence_refs.is_empty()
    }

    fn to_json(&self) -> Value {
        json!({
            "relation": self.relation.as_str(),
            "basis": self.basis.as_str(),
            "evidence_refs": self.evidence_refs,
        })
    }
}

/// Reconciliation issue kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssueKind {
    OriginFactConflict,
    SubjectClaimConflict,
    InsufficientEvidence,
    IncomparableScope,
    UntrustedObservation,
    MappingError,
    MultipleOriginCommitments,
}

impl IssueKind {
    pub fn as_str(self) -> &'static str {
        match self {
            IssueKind::OriginFactConflict => "origin_fact_conflict",
            IssueKind::SubjectClaimConflict => "subject_claim_conflict",
            IssueKind::InsufficientEvidence => "insufficient_evidence",
            IssueKind::IncomparableScope => "incomparable_scope",
            IssueKind::UntrustedObservation => "untrusted_observation",
            IssueKind::MappingError => "mapping_error",
            IssueKind::MultipleOriginCommitments => "multiple_origin_commitments",
        }
    }
}

/// One reconciliation issue.
#[derive(Debug, Clone, PartialEq)]
pub struct ReconciliationIssue {
    pub kind: IssueKind,
    pub detail: String,
    pub evidence_refs: Vec<String>,
}

impl ReconciliationIssue {
    fn validate(&self, what: &str) -> Result<(), ConnectorError> {
        require_nonempty(&format!("{what}.detail"), &self.detail)?;
        for (index, reference) in self.evidence_refs.iter().enumerate() {
            require_nonempty(&format!("{what}.evidence_refs[{index}]"), reference)?;
        }
        Ok(())
    }

    fn to_json(&self) -> Value {
        json!({
            "kind": self.kind.as_str(),
            "detail": self.detail,
            "evidence_refs": self.evidence_refs,
        })
    }
}

/// One claim-to-facts comparison.
#[derive(Debug, Clone, PartialEq)]
pub struct ClaimComparison {
    pub claim_id: String,
    pub assertion_id: String,
    pub claim_ref: String,
    pub fact_ids: Vec<String>,
    pub fact_refs: Vec<String>,
    pub result: ComparisonResult,
    pub temporal_relation: TemporalRelation,
    pub rationale: String,
    pub limitations: Vec<String>,
}

impl ClaimComparison {
    fn validate(&self, index: usize) -> Result<(), ConnectorError> {
        let what = format!("report.comparisons[{index}]");
        require_nonempty(&format!("{what}.claim_id"), &self.claim_id)?;
        require_nonempty(&format!("{what}.assertion_id"), &self.assertion_id)?;
        require_nonempty(&format!("{what}.claim_ref"), &self.claim_ref)?;
        for (position, fact) in self.fact_ids.iter().enumerate() {
            require_nonempty(&format!("{what}.fact_ids[{position}]"), fact)?;
        }
        for (position, reference) in self.fact_refs.iter().enumerate() {
            require_nonempty(&format!("{what}.fact_refs[{position}]"), reference)?;
        }
        if self.result.is_decisive() && self.fact_ids.is_empty() {
            return Err(invalid(format!(
                "{what}: a decisive comparison cites the facts it decides against"
            )));
        }
        self.temporal_relation
            .validate(&format!("{what}.temporal_relation"))?;
        require_nonempty(&format!("{what}.rationale"), &self.rationale)?;
        Ok(())
    }

    fn to_json(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "assertion_id": self.assertion_id,
            "claim_ref": self.claim_ref,
            "fact_ids": self.fact_ids,
            "fact_refs": self.fact_refs,
            "result": self.result.as_str(),
            "temporal_relation": self.temporal_relation.to_json(),
            "rationale": self.rationale,
            "limitations": self.limitations,
        })
    }
}

/// One pinned axis revision. Revision zero carries a Missing digest.
#[derive(Debug, Clone, PartialEq)]
pub struct DomainPin {
    pub revision: u64,
    pub record_digest: MaybeDigest,
}

impl DomainPin {
    fn validate(&self, what: &str) -> Result<(), ConnectorError> {
        validate_maybe_digest(&self.record_digest, &format!("{what}.record_digest"))?;
        match (&self.record_digest, self.revision) {
            (MaybeDigest::Missing(_), 0) | (MaybeDigest::Present(_), 1..) => Ok(()),
            (MaybeDigest::Missing(_), _) => Err(invalid(format!(
                "{what}: a nonzero pin carries its record digest"
            ))),
            (MaybeDigest::Present(_), 0) => Err(invalid(format!(
                "{what}: revision zero carries a Missing digest"
            ))),
        }
    }

    fn to_json(&self) -> Value {
        json!({
            "revision": self.revision,
            "record_digest": maybe_digest_json(&self.record_digest),
        })
    }
}

/// Report input pins over the four source axes.
#[derive(Debug, Clone, PartialEq)]
pub struct ReportInputPins {
    pub dispatch: DomainPin,
    pub observation: DomainPin,
    pub execution: DomainPin,
    pub application: DomainPin,
}

impl ReportInputPins {
    fn validate(&self) -> Result<(), ConnectorError> {
        self.dispatch.validate("report.inputs.dispatch")?;
        self.observation.validate("report.inputs.observation")?;
        self.execution.validate("report.inputs.execution")?;
        self.application.validate("report.inputs.application")?;
        Ok(())
    }

    fn to_json(&self) -> Value {
        json!({
            "dispatch": self.dispatch.to_json(),
            "observation": self.observation.to_json(),
            "execution": self.execution.to_json(),
            "application": self.application.to_json(),
        })
    }
}

/// Reconciler report value.
#[derive(Debug, Clone, PartialEq)]
pub struct ReportValue {
    pub state: ReportState,
    pub coverage: ReportCoverage,
    pub inputs: ReportInputPins,
    pub evaluator: String,
    pub comparisons: Vec<ClaimComparison>,
    pub issues: Vec<ReconciliationIssue>,
    pub limitations: Vec<String>,
    pub diagnostic: String,
}

impl ReportValue {
    /// Structural validation plus state/coverage coherence. Cross-entity
    /// coverage accounting lives in [`validate_reconciliation`].
    fn validate(&self) -> Result<(), ConnectorError> {
        self.state.validate()?;
        self.inputs.validate()?;
        require_nonempty("report.evaluator", &self.evaluator)?;
        require_nonempty("report.diagnostic", &self.diagnostic)?;
        for (index, comparison) in self.comparisons.iter().enumerate() {
            comparison.validate(index)?;
        }
        for (index, issue) in self.issues.iter().enumerate() {
            issue.validate(&format!("report.issues[{index}]"))?;
        }
        self.validate_state_coherence()
    }

    /// Any proved contradiction makes the state contradicted, even when
    /// other comparisons remain incomplete. Complete noncontradictory
    /// comparison yields reconciled; unresolved comparisons yield Missing.
    fn validate_state_coherence(&self) -> Result<(), ConnectorError> {
        let contradicted = self
            .comparisons
            .iter()
            .any(|comparison| comparison.result == ComparisonResult::Contradicted);
        let unresolved = self
            .comparisons
            .iter()
            .any(|comparison| comparison.result == ComparisonResult::Indeterminate);
        match (&self.state, self.coverage, contradicted, unresolved) {
            (ReportState::Contradicted, _, true, _) => Ok(()),
            (ReportState::Contradicted, _, false, _) => Err(invalid(
                "a contradicted report names the proved contradiction",
            )),
            (_, _, true, _) => Err(invalid(
                "any proved contradiction makes the report state contradicted",
            )),
            (ReportState::Reconciled, ReportCoverage::Complete, false, false) => Ok(()),
            (ReportState::Reconciled, _, false, _) => Err(invalid(
                "reconciled requires complete noncontradictory comparison",
            )),
            (ReportState::Missing(missing), ReportCoverage::Incomplete, false, _) => {
                if missing.reason == "not_observed" || missing.reason == "observation_lost" {
                    Ok(())
                } else {
                    Err(invalid(
                        "an incomplete report carries not_observed or observation_lost state",
                    ))
                }
            }
            (ReportState::Missing(missing), ReportCoverage::NotApplicable, false, _)
                if self.comparisons.is_empty() =>
            {
                if missing.reason == "not_applicable" {
                    Ok(())
                } else {
                    Err(invalid(
                        "a report with no applicable subject claims carries inapplicable state",
                    ))
                }
            }
            (ReportState::Missing(_), _, false, _) => Err(invalid(
                "report state and coverage disagree: complete comparison resolves every comparison",
            )),
        }
    }

    fn to_json(&self) -> Value {
        json!({
            "state": self.state.to_json(),
            "coverage": self.coverage.as_str(),
            "inputs": self.inputs.to_json(),
            "evaluator": self.evaluator,
            "comparisons": self.comparisons.iter().map(ClaimComparison::to_json).collect::<Vec<Value>>(),
            "issues": self.issues.iter().map(ReconciliationIssue::to_json).collect::<Vec<Value>>(),
            "limitations": self.limitations,
            "diagnostic": self.diagnostic,
        })
    }
}

// ---------------------------------------------------------------------------
// Axis values and revisions (§16.2)
// ---------------------------------------------------------------------------

/// One axis publication value.
#[derive(Debug, Clone, PartialEq)]
pub enum AxisValue {
    Dispatch(DispatchValue),
    Observation(ObservationValue),
    Execution(ExecutionValue),
    Application(ApplicationValue),
    Report(ReportValue),
}

impl AxisValue {
    fn axis(&self) -> Axis {
        match self {
            AxisValue::Dispatch(_) => Axis::Dispatch,
            AxisValue::Observation(_) => Axis::Observation,
            AxisValue::Execution(_) => Axis::Execution,
            AxisValue::Application(_) => Axis::Application,
            AxisValue::Report(_) => Axis::Report,
        }
    }

    fn validate(&self, previous_revision: u64) -> Result<(), ConnectorError> {
        match self {
            AxisValue::Dispatch(value) => value.validate(previous_revision),
            AxisValue::Observation(value) => value.validate(previous_revision),
            AxisValue::Execution(value) => value.validate(),
            AxisValue::Application(value) => value.validate(),
            AxisValue::Report(value) => value.validate(),
        }
    }

    fn evidence_refs(&self) -> Vec<&EvidenceRef> {
        match self {
            AxisValue::Dispatch(value) => value.evidence_refs(),
            AxisValue::Observation(value) => value.evidence_refs(),
            AxisValue::Execution(value) => value.evidence_refs(),
            AxisValue::Application(value) => value.evidence_refs(),
            AxisValue::Report(_) => Vec::new(),
        }
    }

    fn to_json(&self) -> Value {
        match self {
            AxisValue::Dispatch(value) => value.to_json(),
            AxisValue::Observation(value) => value.to_json(),
            AxisValue::Execution(value) => value.to_json(),
            AxisValue::Application(value) => value.to_json(),
            AxisValue::Report(value) => value.to_json(),
        }
    }
}

/// One complete immutable axis publication.
#[derive(Debug, Clone, PartialEq)]
pub struct AxisRevision {
    pub record_type: String,
    pub schema_version: String,
    pub attempt: AttemptContext,
    pub commission_digest: Digest,
    pub axis: Axis,
    pub owner_domain: String,
    pub writer_id: String,
    pub revision: u64,
    pub previous_revision: u64,
    pub evidence_prefix: JournalPrefix,
    pub evidence_refs: Vec<EvidenceRef>,
    pub value: AxisValue,
}

impl AxisRevision {
    fn validate_identity(
        &self,
        commission: &AttemptCommission,
    ) -> Result<(), ConnectorError> {
        if self.record_type != AXIS_REVISION_RECORD_TYPE {
            return Err(invalid(format!(
                "record_type must be {AXIS_REVISION_RECORD_TYPE:?}, found {:?}",
                self.record_type
            )));
        }
        if self.schema_version != LIFECYCLE_SCHEMA_VERSION {
            return Err(invalid(format!(
                "schema_version must be {LIFECYCLE_SCHEMA_VERSION:?}, found {:?}",
                self.schema_version
            )));
        }
        self.attempt.validate()?;
        self.attempt.matches_commission(commission)?;
        let expected = commission_digest(commission)?;
        if self.commission_digest != expected {
            return Err(invalid(
                "commission_digest does not match the commissioned attempt",
            ));
        }
        if self.owner_domain != self.axis.as_str() {
            return Err(forbidden(format!(
                "writer for {:?} may publish only its axis",
                self.owner_domain
            )));
        }
        require_nonempty("writer_id", &self.writer_id)?;
        if self.revision == 0 || self.previous_revision + 1 != self.revision {
            return Err(invalid(format!(
                "revision {} must equal previous_revision {} plus one",
                self.revision, self.previous_revision
            )));
        }
        if self.value.axis() != self.axis {
            return Err(invalid("axis value does not match the revision axis"));
        }
        require_nonempty(
            "evidence_prefix.journal_id",
            &self.evidence_prefix.journal_id,
        )?;
        if !rm_wire::is_valid_digest(self.evidence_prefix.head_hash.as_str()) {
            return Err(invalid("evidence_prefix.head_hash is not a sha256 digest"));
        }
        if self.evidence_prefix.journal_id != commission.journal_id {
            return Err(invalid(
                "a publication cites the supporting prefix of its own attempt journal",
            ));
        }
        for (index, reference) in self.evidence_refs.iter().enumerate() {
            validate_evidence_ref(reference, &format!("evidence_refs[{index}]"))?;
        }
        Ok(())
    }

    /// Every supporting reference: top-level plus nested value citations.
    fn all_evidence_refs(&self) -> Vec<&EvidenceRef> {
        self.evidence_refs
            .iter()
            .chain(self.value.evidence_refs())
            .collect()
    }
}

/// Closed JSON projection of a revision: the immutable bytes that are
/// installed before anything may cite them.
pub fn revision_json(revision: &AxisRevision) -> Value {
    json!({
        "record_type": revision.record_type,
        "schema_version": revision.schema_version,
        "attempt": revision.attempt.to_json(),
        "commission_digest": revision.commission_digest.as_str(),
        "axis": revision.axis.as_str(),
        "owner_domain": revision.owner_domain,
        "writer_id": revision.writer_id,
        "revision": revision.revision,
        "previous_revision": revision.previous_revision,
        "evidence_prefix": revision.evidence_prefix.to_json(),
        "evidence_refs": revision.evidence_refs.iter().map(EvidenceRef::to_json).collect::<Vec<Value>>(),
        "value": revision.value.to_json(),
    })
}

/// Canonical wire bytes of a revision.
pub fn revision_wire_bytes(revision: &AxisRevision) -> Result<Vec<u8>, ConnectorError> {
    serde_json::to_vec(&revision_json(revision))
        .map_err(|error| invalid(format!("revision cannot be serialized: {error}")))
}

// ---------------------------------------------------------------------------
// Publication references
// ---------------------------------------------------------------------------

/// Journal registration of an admitted publication: registered under an
/// evidence reference, or honestly pending while the owner journals
/// asynchronously.
#[derive(Debug, Clone, PartialEq)]
pub enum PublicationRegistration {
    Registered(EvidenceRef),
    Pending(Missing),
}

impl PublicationRegistration {
    fn to_json(&self) -> Value {
        match self {
            PublicationRegistration::Registered(reference) => json!({
                "status": "registered",
                "registration": reference.to_json(),
            }),
            PublicationRegistration::Pending(missing) => json!({
                "status": "pending",
                "registration": missing_json(missing),
            }),
        }
    }
}

/// Reference to an admitted axis publication.
#[derive(Debug, Clone, PartialEq)]
pub struct LifecyclePublicationReference {
    pub schema_version: String,
    pub attempt: AttemptContext,
    pub commission_digest: Digest,
    pub axis: Axis,
    pub revision: u64,
    pub owner_domain: String,
    pub content: ArtifactReference,
    pub registration_ref: PublicationRegistration,
}

impl LifecyclePublicationReference {
    /// Closed JSON projection.
    pub fn to_json(&self) -> Value {
        json!({
            "schema_version": self.schema_version,
            "attempt": self.attempt.to_json(),
            "commission_digest": self.commission_digest.as_str(),
            "axis": self.axis.as_str(),
            "revision": self.revision,
            "owner_domain": self.owner_domain,
            "content": self.content.to_json(),
            "registration_ref": self.registration_ref.to_json(),
        })
    }
}

// ---------------------------------------------------------------------------
// Snapshots and seals (§16.7)
// ---------------------------------------------------------------------------

/// One axis slot: unpublished (revision zero, Missing value) or published.
#[derive(Debug, Clone, PartialEq)]
pub struct AxisSlot {
    pub revision: u64,
    pub value: SlotValue,
}

/// Slot value: reasoned missingness or the embedded axis publication.
#[derive(Debug, Clone, PartialEq)]
pub enum SlotValue {
    Unpublished(Missing),
    Published(AxisRevision),
}

/// Seal names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealName {
    Commissioned,
    ObservationClosed,
    EvidenceUpdated,
}

impl SealName {
    pub fn as_str(self) -> &'static str {
        match self {
            SealName::Commissioned => "commissioned",
            SealName::ObservationClosed => "observation_closed",
            SealName::EvidenceUpdated => "evidence_updated",
        }
    }
}

/// A seal pinning the selected domain revisions of a named read view.
#[derive(Debug, Clone, PartialEq)]
pub struct SealPoint {
    pub seal_id: String,
    pub name: SealName,
    pub versions: VersionVector,
    pub evidence_refs: Vec<EvidenceRef>,
}

/// Derived read composition over the five axis slots.
#[derive(Debug, Clone, PartialEq)]
pub struct AttemptSnapshot {
    pub record_type: String,
    pub schema_version: String,
    pub attempt: AttemptContext,
    pub commission: AttemptCommission,
    pub commission_digest: Digest,
    pub input_prefix: JournalPrefix,
    pub dispatch: AxisSlot,
    pub observation: AxisSlot,
    pub execution: AxisSlot,
    pub application: AxisSlot,
    pub report: AxisSlot,
    pub seal_point: SealPoint,
}

// ---------------------------------------------------------------------------
// publish_axis
// ---------------------------------------------------------------------------

/// Admits one connector-axis revision: dispatch, observation, or execution.
///
/// Checks record identity, commission binding, single-axis owner authority,
/// revision arithmetic, supporting-evidence resolution against the cited
/// prefix, and per-axis value coherence; then durably installs the immutable
/// revision bytes. Application and report are rejected: Ringmaster does not
/// author application facts and only the reconciler writes report, through
/// its own path rather than this entry point.
pub fn publish_axis(
    principal: &AuthenticatedPrincipal,
    commission: &AttemptCommission,
    revision: &AxisRevision,
) -> Result<LifecyclePublicationReference, ConnectorError> {
    if !revision.axis.is_connector_axis() {
        return Err(forbidden(format!(
            "axis {:?} is not published through the connector entry point",
            revision.axis.as_str()
        )));
    }
    revision.validate_identity(commission)?;
    revision
        .value
        .validate(revision.previous_revision)?;
    let event_kind = axis_event_kind(revision.axis, &revision.value);
    let descriptor =
        rm_authority::authorize_owner(principal, &revision.owner_domain, event_kind)?;
    if descriptor.owner_domain != revision.axis.as_str() {
        return Err(forbidden(
            "owner authorization assigned a different axis than the revision",
        ));
    }
    for reference in revision.all_evidence_refs() {
        rm_evidence::resolve_evidence(principal, reference, &revision.evidence_prefix)?;
    }
    let bytes = revision_wire_bytes(revision)?;
    let content = ArtifactReference {
        digest: rm_wire::artifact_digest(&bytes),
        size_bytes: bytes.len() as u64,
        media_type: "application/json".to_string(),
        owner_domain: revision.axis.as_str().to_string(),
        access: rm_evidence::AccessClass::Public,
    };
    let installed = rm_evidence::install_artifact(principal, &content, &bytes)?;
    Ok(LifecyclePublicationReference {
        schema_version: revision.schema_version.clone(),
        attempt: revision.attempt.clone(),
        commission_digest: revision.commission_digest.clone(),
        axis: revision.axis,
        revision: revision.revision,
        owner_domain: revision.owner_domain.clone(),
        content: installed,
        registration_ref: PublicationRegistration::Pending(Missing::with_detail(
            "not_observed",
            "publication bytes installed; journal registration is the owner's asynchronous step",
        )),
    })
}

// ---------------------------------------------------------------------------
// validate_snapshot
// ---------------------------------------------------------------------------

fn validate_slot(
    principal: &AuthenticatedPrincipal,
    commission: &AttemptCommission,
    attempt: &AttemptContext,
    commission_digest: &Digest,
    axis: Axis,
    slot: &AxisSlot,
) -> Result<(), ConnectorError> {
    match &slot.value {
        SlotValue::Unpublished(missing) => {
            if slot.revision != 0 {
                return Err(invalid(format!(
                    "{:?} slot: an unpublished axis carries revision zero",
                    axis.as_str()
                )));
            }
            validate_missing(missing, &format!("{:?} slot value", axis.as_str()))?;
            Ok(())
        }
        SlotValue::Published(revision) => {
            if slot.revision != revision.revision {
                return Err(invalid(format!(
                    "{:?} slot revision {} does not match its embedded axis revision {}",
                    axis.as_str(),
                    slot.revision,
                    revision.revision
                )));
            }
            if revision.axis != axis {
                return Err(invalid(format!(
                    "{:?} slot embeds a {:?} publication",
                    axis.as_str(),
                    revision.axis.as_str()
                )));
            }
            revision.validate_identity(commission)?;
            if &revision.attempt != attempt || &revision.commission_digest != commission_digest {
                return Err(invalid(format!(
                    "{:?} slot publication names a different attempt or commission",
                    axis.as_str()
                )));
            }
            revision.value.validate(revision.previous_revision)?;
            for reference in revision.all_evidence_refs() {
                rm_evidence::resolve_evidence(principal, reference, &revision.evidence_prefix)?;
            }
            Ok(())
        }
    }
}

/// Validates a derived read composition. Read-side only: it confers no
/// authority to author or repair any axis.
pub fn validate_snapshot(
    principal: &AuthenticatedPrincipal,
    snapshot: &AttemptSnapshot,
) -> Result<(), ConnectorError> {
    if snapshot.record_type != SNAPSHOT_RECORD_TYPE {
        return Err(invalid(format!(
            "record_type must be {SNAPSHOT_RECORD_TYPE:?}, found {:?}",
            snapshot.record_type
        )));
    }
    if snapshot.schema_version != LIFECYCLE_SCHEMA_VERSION {
        return Err(invalid(format!(
            "schema_version must be {LIFECYCLE_SCHEMA_VERSION:?}, found {:?}",
            snapshot.schema_version
        )));
    }
    snapshot.attempt.validate()?;
    snapshot.attempt.matches_commission(&snapshot.commission)?;
    let expected = commission_digest(&snapshot.commission)?;
    if snapshot.commission_digest != expected {
        return Err(invalid(
            "snapshot commission_digest does not match the embedded commission",
        ));
    }
    require_nonempty("input_prefix.journal_id", &snapshot.input_prefix.journal_id)?;
    if !rm_wire::is_valid_digest(snapshot.input_prefix.head_hash.as_str()) {
        return Err(invalid("input_prefix.head_hash is not a sha256 digest"));
    }
    validate_slot(
        principal,
        &snapshot.commission,
        &snapshot.attempt,
        &snapshot.commission_digest,
        Axis::Dispatch,
        &snapshot.dispatch,
    )?;
    validate_slot(
        principal,
        &snapshot.commission,
        &snapshot.attempt,
        &snapshot.commission_digest,
        Axis::Observation,
        &snapshot.observation,
    )?;
    validate_slot(
        principal,
        &snapshot.commission,
        &snapshot.attempt,
        &snapshot.commission_digest,
        Axis::Execution,
        &snapshot.execution,
    )?;
    validate_slot(
        principal,
        &snapshot.commission,
        &snapshot.attempt,
        &snapshot.commission_digest,
        Axis::Application,
        &snapshot.application,
    )?;
    validate_slot(
        principal,
        &snapshot.commission,
        &snapshot.attempt,
        &snapshot.commission_digest,
        Axis::Report,
        &snapshot.report,
    )?;
    let versions = &snapshot.seal_point.versions;
    if versions.dispatch != snapshot.dispatch.revision
        || versions.observation != snapshot.observation.revision
        || versions.execution != snapshot.execution.revision
        || versions.application != snapshot.application.revision
        || versions.report != snapshot.report.revision
    {
        return Err(invalid(
            "seal versions must equal the selected slot revisions",
        ));
    }
    require_nonempty("seal_point.seal_id", &snapshot.seal_point.seal_id)?;
    for (index, reference) in snapshot.seal_point.evidence_refs.iter().enumerate() {
        validate_evidence_ref(reference, &format!("seal_point.evidence_refs[{index}]"))?;
        rm_evidence::resolve_evidence(principal, reference, &snapshot.input_prefix)?;
    }
    if let SlotValue::Published(revision) = &snapshot.report.value {
        if let AxisValue::Report(report) = &revision.value {
            check_report_freshness(report, snapshot)?;
        }
    }
    Ok(())
}

/// Report pins may lag the slots (newer facts legitimately coexist with an
/// older report) but must never cite the future.
fn check_report_freshness(
    report: &ReportValue,
    snapshot: &AttemptSnapshot,
) -> Result<(), ConnectorError> {
    let pins = [
        ("dispatch", &report.inputs.dispatch, snapshot.dispatch.revision),
        (
            "observation",
            &report.inputs.observation,
            snapshot.observation.revision,
        ),
        (
            "execution",
            &report.inputs.execution,
            snapshot.execution.revision,
        ),
        (
            "application",
            &report.inputs.application,
            snapshot.application.revision,
        ),
    ];
    for (axis, pin, current) in pins {
        if pin.revision > current {
            return Err(invalid(format!(
                "report {axis} pin cites revision {} beyond the current slot revision {current}",
                pin.revision
            )));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// validate_reconciliation
// ---------------------------------------------------------------------------

fn find_assertion<'a>(
    claim: &'a ExecutionClaim,
    assertion_id: &str,
) -> Option<&'a CommitmentAssertion> {
    claim
        .application_assertions
        .iter()
        .find(|assertion| assertion.assertion_id == assertion_id)
}

/// A verified commitment: a committed fact with verified source and matched
/// correlation behind a receipt verification kind.
fn is_verified_commitment(fact: &OriginFact) -> bool {
    fact.state == OriginState::Committed
        && matches!(
            fact.verification_kind,
            VerificationKind::VerifiedOriginReceipt | VerificationKind::LocalOriginTransaction
        )
        && fact.source_checks.authentication == AuthStatus::Verified
        && fact.source_checks.correlation == CorrelationStatus::Matched
}

/// A verified final absence: a final not-committed fact with verified source
/// and matched correlation.
fn is_verified_final_absence(fact: &OriginFact) -> bool {
    fact.state == OriginState::NotCommitted
        && fact.coverage == OriginCoverage::FinalForAttempt
        && fact.source_checks.authentication == AuthStatus::Verified
        && fact.source_checks.correlation == CorrelationStatus::Matched
}

/// Validates a reconciler report against its pinned execution and
/// application inputs. Pure and read-side: it takes shared references and
/// returns no authority to author or repair either source axis.
pub fn validate_reconciliation(
    execution: &ExecutionValue,
    application: &ApplicationValue,
    report: &ReportValue,
) -> Result<(), ConnectorError> {
    execution.validate()?;
    application.validate()?;
    report.validate()?;
    // Every comparison names a real claim, a real assertion in that claim,
    // and real facts.
    for (index, comparison) in report.comparisons.iter().enumerate() {
        let what = format!("report.comparisons[{index}]");
        let claim = execution.find_claim(&comparison.claim_id).ok_or_else(|| {
            invalid(format!(
                "{what}: claim_id {:?} names no pinned execution claim",
                comparison.claim_id
            ))
        })?;
        let assertion = find_assertion(claim, &comparison.assertion_id).ok_or_else(|| {
            invalid(format!(
                "{what}: assertion_id {:?} names no assertion in claim {:?}",
                comparison.assertion_id, comparison.claim_id
            ))
        })?;
        let mut facts = Vec::with_capacity(comparison.fact_ids.len());
        for fact_id in &comparison.fact_ids {
            facts.push(application.find_fact(fact_id).ok_or_else(|| {
                invalid(format!(
                    "{what}: fact_id {fact_id:?} names no pinned origin fact"
                ))
            })?);
        }
        check_comparison_semantics(&what, assertion, &facts, comparison)?;
    }
    check_coverage_accounting(execution, report)?;
    Ok(())
}

fn check_comparison_semantics(
    what: &str,
    assertion: &CommitmentAssertion,
    facts: &[&OriginFact],
    comparison: &ClaimComparison,
) -> Result<(), ConnectorError> {
    // RM-C30: outcome_unknown is compatible with later commitment; it is
    // never contradicted by it.
    if assertion.value == CommitmentValue::OutcomeUnknown
        && comparison.result == ComparisonResult::Contradicted
    {
        return Err(invalid(format!(
            "{what}: outcome_unknown is compatible with a later commitment, never contradicted by it"
        )));
    }
    // RM-C31: entire-attempt definite noncommitment is contradicted by a
    // verified commitment, and the contradiction is retained.
    if assertion.value == CommitmentValue::NotCommitted
        && assertion.span == CommitmentSpan::EntireAttempt
        && facts.iter().any(|fact| is_verified_commitment(fact))
        && comparison.result != ComparisonResult::Contradicted
    {
        return Err(invalid(format!(
            "{what}: entire-attempt noncommitment is contradicted by a verified commitment"
        )));
    }
    if assertion.value == CommitmentValue::Committed
        && assertion.span == CommitmentSpan::EntireAttempt
        && facts.iter().any(|fact| is_verified_final_absence(fact))
        && comparison.result != ComparisonResult::Contradicted
    {
        return Err(invalid(format!(
            "{what}: entire-attempt commitment is contradicted by verified final absence"
        )));
    }
    // RM-C57: a decisive comparison decides against verified sources only.
    if comparison.result.is_decisive() {
        for fact in facts {
            fact.source_checks.require_accepted(&format!(
                "{what}.facts[{}].source_checks",
                fact.fact_id
            ))?;
        }
    }
    // RM-C32: boundary-scoped assertions need temporal evidence for a
    // decisive comparison; later receipt time alone proves nothing.
    if comparison.result.is_decisive() && assertion.span.needs_temporal_evidence() {
        if !comparison.temporal_relation.is_proven() {
            return Err(invalid(format!(
                "{what}: a decisive boundary-scoped comparison requires proven temporal evidence, not receipt ordering alone"
            )));
        }
    }
    Ok(())
}

/// Every applicable assertion is accounted for by a comparison or, under
/// incomplete coverage, by an explicit limitation. With no applicable
/// subject claims the coverage is not_applicable.
fn check_coverage_accounting(
    execution: &ExecutionValue,
    report: &ReportValue,
) -> Result<(), ConnectorError> {
    let mut applicable: Vec<(&str, &str)> = Vec::new();
    for claim in &execution.claims {
        if !claim.scope.is_applicable() {
            continue;
        }
        for assertion in &claim.application_assertions {
            applicable.push((claim.claim_id.as_str(), assertion.assertion_id.as_str()));
        }
    }
    if applicable.is_empty() {
        if report.coverage != ReportCoverage::NotApplicable || !report.comparisons.is_empty() {
            return Err(invalid(
                "with no applicable subject claims the coverage is not_applicable and no comparison is fabricated",
            ));
        }
        return Ok(());
    }
    if report.coverage == ReportCoverage::NotApplicable {
        return Err(invalid(
            "applicable subject claims require complete or incomplete coverage",
        ));
    }
    let mut uncovered = Vec::new();
    for (claim_id, assertion_id) in &applicable {
        let covered = report.comparisons.iter().any(|comparison| {
            comparison.claim_id == *claim_id && comparison.assertion_id == *assertion_id
        });
        if !covered {
            uncovered.push(format!("{claim_id}/{assertion_id}"));
        }
    }
    if report.coverage == ReportCoverage::Complete && !uncovered.is_empty() {
        return Err(invalid(format!(
            "complete coverage leaves no assertion uncompared: {}",
            uncovered.join(", ")
        )));
    }
    if !uncovered.is_empty() && report.limitations.is_empty() {
        return Err(invalid(format!(
            "uncompared assertions require an explicit limitation: {}",
            uncovered.join(", ")
        )));
    }
    Ok(())
}

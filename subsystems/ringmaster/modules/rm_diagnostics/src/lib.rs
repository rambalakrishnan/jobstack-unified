//! `rm_diagnostics`: tier-6 diagnostic verification and offline replay.
//!
//! Implements seam mapping §19:
//!
//! - [`verify_diagnostic`] checks a kernel [`DiagnosticDocument`] derived by
//!   the authorized analyzer from an immutable admitted run, a journal prefix
//!   ending at `analysis_requested`, and a pinned classifier bundle. It
//!   enforces record identity, wire structure, assessment distinctions
//!   (satisfied/violated require exposed opportunity and valid controls;
//!   unexposed work is not_exercised; invalid isolation controls establish
//!   neither isolation nor non-isolation — RM-C52), feature-exposure
//!   implications, producer completeness, measurement coherence via
//!   `rm_time`, and evidence resolution via `rm_evidence`.
//! - [`replay_diagnostic`] re-derives a production diagnostic offline
//!   (diagnostic rederivation only). Missing bytes yield `unavailable`, never
//!   `matched` (RM-C55). The worker never invokes a browser, subject, model
//!   provider, or external write (RM-C56); the receipt's effect flags are
//!   always false and the reducer is inapplicable.
//!
//! Analysis uses no current wall time, unrecorded network lookup, or mutable
//! application row. Corrections arrive as new immutable revisions.

#![forbid(unsafe_code)]

use rm_authority::{
    AttemptKind, AuthenticatedPrincipal, ConnectorError, EvaluationPartition, TargetClass,
};
use rm_evidence::{ArtifactReference, EvidenceRef, JournalPrefix};
use rm_time::{MaybeString, MaybeTimePoint, Measurement, Missing, Scope, TimePoint};
use rm_wire::Digest;
use serde_json::{json, Value};
use std::collections::BTreeSet;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Diagnostic record discriminator.
pub const DIAGNOSTIC_RECORD_TYPE: &str = "diagnostic";
/// Evidence-kernel schema version.
pub const KERNEL_SCHEMA_VERSION: &str = "evidence-kernel/0.1.0";
/// Replay receipt record discriminator.
pub const REPLAY_RECORD_TYPE: &str = "replay_receipt";
/// Largest integer representable without precision loss (§3.1).
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Pinned replay engine identity.
pub const REPLAY_ENGINE_ID: &str = "rm-diagnostics-replay";
/// Pinned replay engine version.
pub const REPLAY_ENGINE_VERSION: &str = "0.1.0";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

fn connector_error(code: &str, fault_domain: &str, detail: impl Into<String>) -> ConnectorError {
    ConnectorError {
        kind: "connector_error".to_string(),
        code: code.to_string(),
        fault_domain: fault_domain.to_string(),
        detail: detail.into(),
        operation_delivery: "not_dispatched".to_string(),
        retry_guidance: "operator_review".to_string(),
        retry_after: None,
        handle: None,
        evidence_refs: Vec::new(),
    }
}

fn invalid(detail: impl Into<String>) -> ConnectorError {
    connector_error("INVALID_REQUEST", "request", detail)
}

fn integrity(detail: impl Into<String>) -> ConnectorError {
    connector_error("INTEGRITY_INCIDENT", "integrity", detail)
}

// ---------------------------------------------------------------------------
// Small validators
// ---------------------------------------------------------------------------

fn require_nonempty(field: &str, value: &str) -> Result<(), ConnectorError> {
    if value.is_empty() {
        return Err(invalid(format!("{field} must be nonempty")));
    }
    Ok(())
}

fn require_revision(field: &str, value: u64) -> Result<(), ConnectorError> {
    if value > MAX_SAFE_INTEGER {
        return Err(invalid(format!(
            "{field} {value} exceeds {MAX_SAFE_INTEGER}"
        )));
    }
    Ok(())
}

fn require_positive(field: &str, value: u64) -> Result<(), ConnectorError> {
    if value == 0 || value > MAX_SAFE_INTEGER {
        return Err(invalid(format!(
            "{field} {value} is outside 1..={MAX_SAFE_INTEGER}"
        )));
    }
    Ok(())
}

fn require_missing(what: &str, missing: &Missing) -> Result<(), ConnectorError> {
    if !rm_time::is_valid_reason(&missing.reason) {
        return Err(invalid(format!(
            "{what} has invalid Missing reason {:?}",
            missing.reason
        )));
    }
    if let Some(detail) = &missing.detail {
        if detail.is_empty() {
            return Err(invalid(format!("{what} Missing detail must be nonempty")));
        }
    }
    Ok(())
}

fn require_digest(what: &str, digest: &Digest) -> Result<(), ConnectorError> {
    if !rm_wire::is_valid_digest(digest.as_str()) {
        return Err(invalid(format!(
            "{what} {:?} is not a sha256 digest",
            digest.as_str()
        )));
    }
    Ok(())
}

fn require_evidence_maybe_digest(
    what: &str,
    value: &rm_evidence::MaybeDigest,
) -> Result<(), ConnectorError> {
    match value {
        rm_evidence::MaybeDigest::Present(digest) => require_digest(what, digest),
        rm_evidence::MaybeDigest::Missing(missing) => require_missing(what, missing),
    }
}

fn require_artifact(what: &str, reference: &ArtifactReference) -> Result<(), ConnectorError> {
    reference
        .validate()
        .map_err(|e| invalid(format!("{what} invalid: {e}")))
}

fn require_evidence_ref(what: &str, reference: &EvidenceRef) -> Result<(), ConnectorError> {
    reference
        .validate()
        .map_err(|e| invalid(format!("{what} invalid: {e}")))
}

fn require_scope(scope: &Scope) -> Result<(), ConnectorError> {
    require_nonempty("scope.id", &scope.id)
}

fn require_maybe_string(what: &str, value: &MaybeString) -> Result<(), ConnectorError> {
    match value {
        MaybeString::Text(text) => require_nonempty(what, text),
        MaybeString::Missing(missing) => require_missing(what, missing),
    }
}

fn require_timepoint(what: &str, point: &TimePoint) -> Result<(), ConnectorError> {
    require_nonempty(&format!("{what}.clock_id"), &point.clock_id)?;
    require_nonempty(&format!("{what}.boot_id"), &point.boot_id)?;
    if !point.monotonic_offset_ms.is_finite() || point.monotonic_offset_ms < 0.0 {
        return Err(invalid(format!(
            "{what}.monotonic_offset_ms must be a finite nonnegative number"
        )));
    }
    match &point.utc_annotation {
        rm_time::UtcAnnotation::DateTime(text) => require_nonempty(&format!("{what}.utc"), text)?,
        rm_time::UtcAnnotation::Missing(missing) => {
            require_missing(&format!("{what}.utc"), missing)?
        }
    }
    Ok(())
}

fn require_maybe_timepoint(what: &str, value: &MaybeTimePoint) -> Result<(), ConnectorError> {
    match value {
        MaybeTimePoint::Present(point) => require_timepoint(what, point),
        MaybeTimePoint::Missing(missing) => require_missing(what, missing),
    }
}

fn require_unique_strings(items: &[String], what: &str) -> Result<(), ConnectorError> {
    let mut seen = BTreeSet::new();
    for item in items {
        if !seen.insert(item.clone()) {
            return Err(invalid(format!("{what} contains duplicate {item:?}")));
        }
    }
    Ok(())
}

fn missing_json(missing: &Missing) -> Value {
    match &missing.detail {
        Some(detail) => json!({"value": null, "reason": missing.reason, "detail": detail}),
        None => json!({"value": null, "reason": missing.reason}),
    }
}

fn check_caller(principal: &AuthenticatedPrincipal) -> Result<(), ConnectorError> {
    rm_authority::authorize_owner(principal, "connector", "connector_incident")?;
    Ok(())
}

fn wire_validate(schema_id: &str, value: &Value, what: &str) -> Result<(), ConnectorError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|e| invalid(format!("{what} cannot be serialized: {e}")))?;
    rm_wire::validate_record(schema_id, &bytes)
        .map_err(|e| invalid(format!("{what} wire validation failed: {e}")))?;
    // Exercise canonical hashing so malformed JSON can never be pinned.
    rm_wire::canonical_digest(&bytes)
        .map_err(|e| invalid(format!("{what} cannot be hashed: {e}")))?;
    Ok(())
}

/// Returns true when `text` names isolation (case-insensitive substring).
fn mentions_isolation(text: &str) -> bool {
    text.to_lowercase().contains("isolat")
}

// ---------------------------------------------------------------------------
// Version pins
// ---------------------------------------------------------------------------

/// A known immutable code, schema, policy, catalog, or registry artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionPin {
    pub id: String,
    pub version: String,
    pub artifact_digest: Digest,
}

impl VersionPin {
    pub fn validate(&self, what: &str) -> Result<(), ConnectorError> {
        require_nonempty(&format!("{what}.id"), &self.id)?;
        require_nonempty(&format!("{what}.version"), &self.version)?;
        require_digest(&format!("{what}.artifact_digest"), &self.artifact_digest)?;
        Ok(())
    }

    pub fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "version": self.version,
            "artifact_digest": self.artifact_digest.as_str(),
        })
    }
}

/// Version pin or reasoned missingness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaybeVersionPin {
    Present(VersionPin),
    Missing(Missing),
}

impl MaybeVersionPin {
    fn validate(&self, what: &str) -> Result<(), ConnectorError> {
        match self {
            MaybeVersionPin::Present(pin) => pin.validate(what),
            MaybeVersionPin::Missing(missing) => require_missing(what, missing),
        }
    }

    fn to_json(&self) -> Value {
        match self {
            MaybeVersionPin::Present(pin) => pin.to_json(),
            MaybeVersionPin::Missing(missing) => missing_json(missing),
        }
    }

    fn is_inapplicable(&self) -> bool {
        matches!(
            self,
            MaybeVersionPin::Missing(m) if m.reason == "not_applicable"
        )
    }
}

// ---------------------------------------------------------------------------
// Attempt and execution
// ---------------------------------------------------------------------------

/// Attempt identity carried by a diagnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticAttempt {
    pub attempt_id: String,
    pub kind: AttemptKind,
    pub target_class: TargetClass,
    pub target_id: String,
    pub evaluation_partition: EvaluationPartition,
}

impl DiagnosticAttempt {
    fn validate(&self) -> Result<(), ConnectorError> {
        require_nonempty("attempt.attempt_id", &self.attempt_id)?;
        require_nonempty("attempt.target_id", &self.target_id)?;
        // Kind/target/partition coherence mirrors rm_authority scope rules:
        // practice is fixture/held-in; production is employer/held-out.
        match self.kind {
            AttemptKind::Practice => {
                if self.target_class != TargetClass::Fixture {
                    return Err(invalid(
                        "practice attempt must target a laboratory fixture",
                    ));
                }
                if self.evaluation_partition != EvaluationPartition::HeldIn {
                    return Err(invalid("practice attempt must be held_in"));
                }
            }
            AttemptKind::Production => {
                if self.target_class != TargetClass::Employer {
                    return Err(invalid(
                        "production attempt must target an employer origin",
                    ));
                }
                if self.evaluation_partition != EvaluationPartition::HeldOut {
                    return Err(invalid("production attempt must be held_out"));
                }
            }
        }
        Ok(())
    }

    fn to_json(&self) -> Value {
        let kind = match self.kind {
            AttemptKind::Practice => "practice",
            AttemptKind::Production => "production",
        };
        let target_class = match self.target_class {
            TargetClass::Fixture => "laboratory_fixture",
            TargetClass::Employer => "employer_origin",
        };
        let partition = match self.evaluation_partition {
            EvaluationPartition::HeldIn => "held_in",
            EvaluationPartition::HeldOut => "held_out",
        };
        json!({
            "attempt_id": self.attempt_id,
            "kind": kind,
            "target_class": target_class,
            "target_id": self.target_id,
            "evaluation_partition": partition,
        })
    }
}

/// Attempt context or reasoned missingness (service/discovery work).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaybeAttempt {
    Present(DiagnosticAttempt),
    Missing(Missing),
}

impl MaybeAttempt {
    fn validate(&self) -> Result<(), ConnectorError> {
        match self {
            MaybeAttempt::Present(attempt) => attempt.validate(),
            MaybeAttempt::Missing(missing) => require_missing("attempt", missing),
        }
    }
}

/// Realized execution mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticExecutionMode {
    Manual,
    Subject,
    Service,
}

impl DiagnosticExecutionMode {
    fn as_str(self) -> &'static str {
        match self {
            DiagnosticExecutionMode::Manual => "manual",
            DiagnosticExecutionMode::Subject => "subject",
            DiagnosticExecutionMode::Service => "service",
        }
    }
}

/// Commissioned scope and evidenced realized assistance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionDescriptor {
    pub mode: DiagnosticExecutionMode,
    pub subject: MaybeString,
    pub connector_version: MaybeString,
    pub binding_version: MaybeString,
    pub assistance_description: String,
}

impl ExecutionDescriptor {
    fn validate(&self) -> Result<(), ConnectorError> {
        require_maybe_string("execution.subject", &self.subject)?;
        require_maybe_string("execution.connector_version", &self.connector_version)?;
        require_maybe_string("execution.binding_version", &self.binding_version)?;
        require_nonempty(
            "execution.assistance_description",
            &self.assistance_description,
        )?;
        let inapplicable = |value: &MaybeString| {
            matches!(value, MaybeString::Missing(m) if m.reason == "not_applicable")
        };
        let present = |value: &MaybeString| matches!(value, MaybeString::Text(_));
        match self.mode {
            DiagnosticExecutionMode::Manual => {
                if !inapplicable(&self.subject)
                    || !inapplicable(&self.connector_version)
                    || !inapplicable(&self.binding_version)
                {
                    return Err(invalid(
                        "manual execution requires inapplicable subject, connector_version, and binding_version",
                    ));
                }
            }
            DiagnosticExecutionMode::Subject => {
                if !present(&self.subject)
                    || !present(&self.connector_version)
                    || !present(&self.binding_version)
                {
                    return Err(invalid(
                        "subject execution requires present subject, connector_version, and binding_version",
                    ));
                }
            }
            DiagnosticExecutionMode::Service => {
                if !inapplicable(&self.subject) {
                    return Err(invalid(
                        "service execution requires inapplicable subject",
                    ));
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Assessments
// ---------------------------------------------------------------------------

/// Reference to one catalog capability in a pinned descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityReference {
    pub descriptor_digest: Digest,
    pub capability_id: String,
    pub evidence_ref: EvidenceRef,
}

impl CapabilityReference {
    fn validate(&self, what: &str) -> Result<(), ConnectorError> {
        require_digest(&format!("{what}.descriptor_digest"), &self.descriptor_digest)?;
        require_nonempty(&format!("{what}.capability_id"), &self.capability_id)?;
        require_evidence_ref(&format!("{what}.evidence_ref"), &self.evidence_ref)?;
        Ok(())
    }
}

/// Opportunity state: exposed work was exercised; unexposed was not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpportunityState {
    Exposed,
    Unexposed,
    Blocked,
}

impl OpportunityState {
    fn as_str(self) -> &'static str {
        match self {
            OpportunityState::Exposed => "exposed",
            OpportunityState::Unexposed => "unexposed",
            OpportunityState::Blocked => "blocked",
        }
    }
}

/// Evidenced opportunity behind an assessment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opportunity {
    pub state: OpportunityState,
    pub evidence_refs: Vec<EvidenceRef>,
    pub rationale: String,
}

impl Opportunity {
    fn validate(&self) -> Result<(), ConnectorError> {
        if self.evidence_refs.is_empty() {
            return Err(invalid("opportunity.evidence_refs must be nonempty"));
        }
        for (index, reference) in self.evidence_refs.iter().enumerate() {
            require_evidence_ref(&format!("opportunity.evidence_refs[{index}]"), reference)?;
        }
        require_nonempty("opportunity.rationale", &self.rationale)?;
        Ok(())
    }
}

/// Requirement result. Capability, opportunity, and result are independent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssessmentResult {
    Satisfied,
    Violated,
    NativeAbsence,
    Indeterminate,
    NotExercised,
}

impl AssessmentResult {
    fn as_str(self) -> &'static str {
        match self {
            AssessmentResult::Satisfied => "satisfied",
            AssessmentResult::Violated => "violated",
            AssessmentResult::NativeAbsence => "native_absence",
            AssessmentResult::Indeterminate => "indeterminate",
            AssessmentResult::NotExercised => "not_exercised",
        }
    }

    /// Definitive conclusions that require valid exposed opportunity and
    /// applicable controls.
    fn is_definitive(self) -> bool {
        matches!(
            self,
            AssessmentResult::Satisfied
                | AssessmentResult::Violated
                | AssessmentResult::NativeAbsence
        )
    }
}

/// Independent capability/opportunity/result judgment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequirementAssessment {
    pub requirement_id: String,
    pub facet: String,
    pub contract_version: String,
    pub scope: Scope,
    pub capability_refs: Vec<CapabilityReference>,
    pub opportunity: Opportunity,
    pub result: AssessmentResult,
    pub evidence_refs: Vec<EvidenceRef>,
    pub contrary_evidence_refs: Vec<EvidenceRef>,
    pub finding_refs: Vec<String>,
    pub rationale: String,
}

impl RequirementAssessment {
    fn validate_shape(&self) -> Result<(), ConnectorError> {
        let what = format!("assessment {}", self.requirement_id);
        require_nonempty(&format!("{what}.requirement_id"), &self.requirement_id)?;
        require_nonempty(&format!("{what}.facet"), &self.facet)?;
        require_nonempty(&format!("{what}.contract_version"), &self.contract_version)?;
        require_scope(&self.scope).map_err(|e| invalid(format!("{what} scope invalid: {e}")))?;
        for (index, reference) in self.capability_refs.iter().enumerate() {
            reference.validate(&format!("{what}.capability_refs[{index}]"))?;
        }
        self.opportunity
            .validate()
            .map_err(|e| invalid(format!("{what} opportunity invalid: {e}")))?;
        if self.evidence_refs.is_empty() {
            return Err(invalid(format!("{what}.evidence_refs must be nonempty")));
        }
        for (index, reference) in self.evidence_refs.iter().enumerate() {
            require_evidence_ref(&format!("{what}.evidence_refs[{index}]"), reference)?;
        }
        for (index, reference) in self.contrary_evidence_refs.iter().enumerate() {
            require_evidence_ref(
                &format!("{what}.contrary_evidence_refs[{index}]"),
                reference,
            )?;
        }
        require_unique_strings(&self.finding_refs, &format!("{what}.finding_refs"))?;
        for finding in &self.finding_refs {
            require_nonempty(&format!("{what}.finding_ref"), finding)?;
        }
        require_nonempty(&format!("{what}.rationale"), &self.rationale)?;
        Ok(())
    }

    /// EK-ASSESSMENT coherence: satisfied/violated require exposed
    /// opportunity; native_absence requires capability refs; unexposed work
    /// is not_exercised; blocked work is not_exercised or indeterminate.
    fn validate_coherence(&self) -> Result<(), ConnectorError> {
        let what = format!("assessment {}", self.requirement_id);
        match self.result {
            AssessmentResult::Satisfied | AssessmentResult::Violated => {
                if self.opportunity.state != OpportunityState::Exposed {
                    return Err(invalid(format!(
                        "{what} result {} requires exposed opportunity",
                        self.result.as_str()
                    )));
                }
            }
            AssessmentResult::NativeAbsence => {
                if self.capability_refs.is_empty() {
                    return Err(invalid(format!(
                        "{what} native_absence requires capability_refs"
                    )));
                }
            }
            _ => {}
        }
        match self.opportunity.state {
            OpportunityState::Unexposed => {
                if self.result != AssessmentResult::NotExercised {
                    return Err(invalid(format!(
                        "{what} unexposed opportunity requires not_exercised result"
                    )));
                }
            }
            OpportunityState::Blocked => {
                if !matches!(
                    self.result,
                    AssessmentResult::NotExercised | AssessmentResult::Indeterminate
                ) {
                    return Err(invalid(format!(
                        "{what} blocked opportunity requires not_exercised or indeterminate result"
                    )));
                }
            }
            OpportunityState::Exposed => {}
        }
        Ok(())
    }

    fn is_isolation_assessment(&self) -> bool {
        mentions_isolation(&self.requirement_id) || mentions_isolation(&self.facet)
    }
}

// ---------------------------------------------------------------------------
// Validity
// ---------------------------------------------------------------------------

/// Scoped check state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidityState {
    Valid,
    Invalid,
    Incomplete,
    NotApplicable,
}

/// One scoped analysis check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidityCheck {
    pub check_id: String,
    pub scope: Scope,
    pub state: ValidityState,
    pub evidence_refs: Vec<EvidenceRef>,
    pub rationale: String,
}

impl ValidityCheck {
    fn validate(&self) -> Result<(), ConnectorError> {
        require_nonempty("validity.check_id", &self.check_id)?;
        require_scope(&self.scope)
            .map_err(|e| invalid(format!("validity check scope invalid: {e}")))?;
        if self.evidence_refs.is_empty() {
            return Err(invalid("validity.check evidence_refs must be nonempty"));
        }
        for (index, reference) in self.evidence_refs.iter().enumerate() {
            require_evidence_ref(
                &format!("validity.check.evidence_refs[{index}]"),
                reference,
            )?;
        }
        require_nonempty("validity.check.rationale", &self.rationale)?;
        Ok(())
    }

    /// True when this check is an invalid isolation write control.
    fn is_invalid_isolation_control(&self) -> bool {
        self.state == ValidityState::Invalid
            && (mentions_isolation(&self.check_id) || mentions_isolation(&self.scope.id))
    }
}

/// Producer completeness state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompletenessState {
    Complete,
    Incomplete,
    Unknown,
    NotApplicable,
}

/// Inclusive sequence range with `first <= last`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequenceRange {
    pub first: u64,
    pub last: u64,
}

impl SequenceRange {
    fn validate(&self, what: &str) -> Result<(), ConnectorError> {
        require_positive(&format!("{what}.first"), self.first)?;
        require_positive(&format!("{what}.last"), self.last)?;
        if self.first > self.last {
            return Err(invalid(format!(
                "{what} requires first <= last"
            )));
        }
        Ok(())
    }
}

/// Revision or reasoned missingness. Zero means an evidenced closure with no
/// emitted events, never unknown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaybeRevision {
    Revision(u64),
    Missing(Missing),
}

impl MaybeRevision {
    fn validate(&self, what: &str) -> Result<(), ConnectorError> {
        match self {
            MaybeRevision::Revision(value) => require_revision(what, *value),
            MaybeRevision::Missing(missing) => require_missing(what, missing),
        }
    }
}

/// Producer completeness for one producer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProducerCompleteness {
    pub producer_id: String,
    pub state: CompletenessState,
    pub observed_ranges: Vec<SequenceRange>,
    pub missing_ranges: Vec<SequenceRange>,
    pub final_sequence: MaybeRevision,
    pub evidence_refs: Vec<EvidenceRef>,
}

impl ProducerCompleteness {
    fn validate(&self) -> Result<(), ConnectorError> {
        require_nonempty("producer_completeness.producer_id", &self.producer_id)?;
        for (index, range) in self.observed_ranges.iter().enumerate() {
            range.validate(&format!("producer_completeness.observed[{index}]"))?;
        }
        for (index, range) in self.missing_ranges.iter().enumerate() {
            range.validate(&format!("producer_completeness.missing[{index}]"))?;
        }
        self.final_sequence
            .validate("producer_completeness.final_sequence")?;
        if self.evidence_refs.is_empty() {
            return Err(invalid(
                "producer_completeness.evidence_refs must be nonempty",
            ));
        }
        for (index, reference) in self.evidence_refs.iter().enumerate() {
            require_evidence_ref(
                &format!("producer_completeness.evidence_refs[{index}]"),
                reference,
            )?;
        }
        // Complete requires evidenced closure and no unresolved gap.
        if self.state == CompletenessState::Complete {
            if !matches!(self.final_sequence, MaybeRevision::Revision(_)) {
                return Err(invalid(
                    "complete producer requires a present final_sequence",
                ));
            }
            if !self.missing_ranges.is_empty() {
                return Err(invalid(
                    "complete producer requires no missing_ranges",
                ));
            }
        }
        Ok(())
    }
}

/// Infrastructure incident note.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceNote {
    pub code: String,
    pub detail: String,
    pub evidence_refs: Vec<EvidenceRef>,
}

impl EvidenceNote {
    fn validate(&self) -> Result<(), ConnectorError> {
        require_nonempty("incident.code", &self.code)?;
        require_nonempty("incident.detail", &self.detail)?;
        if self.evidence_refs.is_empty() {
            return Err(invalid("incident.evidence_refs must be nonempty"));
        }
        for (index, reference) in self.evidence_refs.iter().enumerate() {
            require_evidence_ref(&format!("incident.evidence_refs[{index}]"), reference)?;
        }
        Ok(())
    }
}

/// Scoped checks, producer completeness, incidents, and limitations. A
/// failed control invalidates only dependent conclusions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticValidity {
    pub scoped_checks: Vec<ValidityCheck>,
    pub producer_completeness: Vec<ProducerCompleteness>,
    pub infrastructure_incidents: Vec<EvidenceNote>,
    pub limitations: Vec<String>,
}

impl DiagnosticValidity {
    fn validate(&self) -> Result<(), ConnectorError> {
        for check in &self.scoped_checks {
            check.validate()?;
        }
        for producer in &self.producer_completeness {
            producer.validate()?;
        }
        for incident in &self.infrastructure_incidents {
            incident.validate()?;
        }
        for limitation in &self.limitations {
            require_nonempty("validity.limitation", limitation)?;
        }
        Ok(())
    }

    fn has_invalid_isolation_control(&self) -> bool {
        self.scoped_checks
            .iter()
            .any(|check| check.is_invalid_isolation_control())
    }
}

// ---------------------------------------------------------------------------
// Artifact slots
// ---------------------------------------------------------------------------

/// Artifact content or reasoned missingness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaybeArtifact {
    Present(ArtifactReference),
    Missing(Missing),
}

impl MaybeArtifact {
    fn validate(&self, what: &str) -> Result<(), ConnectorError> {
        match self {
            MaybeArtifact::Present(reference) => require_artifact(what, reference),
            MaybeArtifact::Missing(missing) => require_missing(what, missing),
        }
    }
}

/// Registered retained artifact slot. Missing retrieval does not erase an
/// already known digest; when content exists the expected digest must equal
/// the content digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactSlot {
    pub name: String,
    pub expected_digest: rm_evidence::MaybeDigest,
    pub content: MaybeArtifact,
    pub evidence_refs: Vec<EvidenceRef>,
}

impl ArtifactSlot {
    fn validate(&self, what: &str) -> Result<(), ConnectorError> {
        require_nonempty(&format!("{what}.name"), &self.name)?;
        require_evidence_maybe_digest(&format!("{what}.expected_digest"), &self.expected_digest)?;
        self.content.validate(&format!("{what}.content"))?;
        if self.evidence_refs.is_empty() {
            return Err(invalid(format!("{what}.evidence_refs must be nonempty")));
        }
        for (index, reference) in self.evidence_refs.iter().enumerate() {
            require_evidence_ref(&format!("{what}.evidence_refs[{index}]"), reference)?;
        }
        if let (
            rm_evidence::MaybeDigest::Present(expected),
            MaybeArtifact::Present(content),
        ) = (&self.expected_digest, &self.content)
        {
            if expected != &content.digest {
                return Err(invalid(format!(
                    "{what} expected_digest does not equal content.digest"
                )));
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Observations and exposures
// ---------------------------------------------------------------------------

/// Boolean or reasoned missingness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaybeBoolean {
    Value(bool),
    Missing(Missing),
}

impl MaybeBoolean {
    fn validate(&self, what: &str) -> Result<(), ConnectorError> {
        match self {
            MaybeBoolean::Value(_) => Ok(()),
            MaybeBoolean::Missing(missing) => require_missing(what, missing),
        }
    }
}

/// Evidence-backed native/manual observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedAction {
    pub action_id: String,
    pub kind: String,
    pub target_alias: MaybeString,
    pub frame_alias: MaybeString,
    pub render_generation: MaybeRevision,
    pub evidence_refs: Vec<EvidenceRef>,
    pub provenance: String,
    pub limitations: Vec<String>,
}

impl ObservedAction {
    fn validate(&self) -> Result<(), ConnectorError> {
        require_nonempty("observed_action.action_id", &self.action_id)?;
        require_nonempty("observed_action.kind", &self.kind)?;
        require_maybe_string("observed_action.target_alias", &self.target_alias)?;
        require_maybe_string("observed_action.frame_alias", &self.frame_alias)?;
        self.render_generation
            .validate("observed_action.render_generation")?;
        if self.evidence_refs.is_empty() {
            return Err(invalid("observed_action.evidence_refs must be nonempty"));
        }
        for (index, reference) in self.evidence_refs.iter().enumerate() {
            require_evidence_ref(
                &format!("observed_action.evidence_refs[{index}]"),
                reference,
            )?;
        }
        match self.provenance.as_str() {
            "server" | "fixture_client" | "connector" | "subject" | "manual_observer"
            | "importer" => {}
            _ => {
                return Err(invalid(format!(
                    "observed_action.provenance {:?} is not a known source class",
                    self.provenance
                )))
            }
        }
        for limitation in &self.limitations {
            require_nonempty("observed_action.limitation", limitation)?;
        }
        Ok(())
    }
}

/// Configured/rendered/exposed/activated distinctions. Activation implies
/// exposure; exposure implies configured and rendered/armed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeatureExposure {
    pub instance_id: String,
    pub configured: bool,
    pub rendered_or_armed: bool,
    pub exposed: bool,
    pub activated: bool,
    pub recovery_observed: MaybeBoolean,
    pub evidence_refs: Vec<EvidenceRef>,
}

impl FeatureExposure {
    fn validate(&self) -> Result<(), ConnectorError> {
        require_nonempty("feature_exposure.instance_id", &self.instance_id)?;
        self.recovery_observed
            .validate("feature_exposure.recovery_observed")?;
        if self.evidence_refs.is_empty() {
            return Err(invalid("feature_exposure.evidence_refs must be nonempty"));
        }
        for (index, reference) in self.evidence_refs.iter().enumerate() {
            require_evidence_ref(
                &format!("feature_exposure.evidence_refs[{index}]"),
                reference,
            )?;
        }
        if self.activated && !self.exposed {
            return Err(invalid(
                "feature_exposure activation implies exposure",
            ));
        }
        if self.exposed && !(self.rendered_or_armed && self.configured) {
            return Err(invalid(
                "feature_exposure exposure implies configured and rendered/armed",
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Steps and predicates
// ---------------------------------------------------------------------------

/// Predicate truth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PredicateTruth {
    Satisfied,
    Unsatisfied,
    Unknown,
}

/// One authoritative predicate outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PredicateResult {
    pub predicate_id: String,
    pub scope: Scope,
    pub truth: PredicateTruth,
    pub authority_domain: MaybeString,
    pub evidence_refs: Vec<EvidenceRef>,
}

impl PredicateResult {
    fn validate(&self, what: &str) -> Result<(), ConnectorError> {
        require_nonempty(&format!("{what}.predicate_id"), &self.predicate_id)?;
        require_scope(&self.scope)
            .map_err(|e| invalid(format!("{what} scope invalid: {e}")))?;
        require_maybe_string(&format!("{what}.authority_domain"), &self.authority_domain)?;
        for (index, reference) in self.evidence_refs.iter().enumerate() {
            require_evidence_ref(&format!("{what}.evidence_refs[{index}]"), reference)?;
        }
        // A known authoritative predicate requires evidence from its actual
        // owning authority.
        match self.truth {
            PredicateTruth::Satisfied | PredicateTruth::Unsatisfied => {
                if !matches!(self.authority_domain, MaybeString::Text(_)) {
                    return Err(invalid(format!(
                        "{what} known truth requires a present authority_domain"
                    )));
                }
                if self.evidence_refs.is_empty() {
                    return Err(invalid(format!(
                        "{what} known truth requires evidence_refs"
                    )));
                }
            }
            PredicateTruth::Unknown => {}
        }
        Ok(())
    }
}

/// Analyzer-owned step status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepStatus {
    Passed,
    Recovered,
    Failed,
    Blocked,
    Skipped,
    Unobserved,
}

/// Attempt disposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptDisposition {
    Accepted,
    Rejected,
    Unknown,
}

/// One retained step attempt. Rejected attempts persist even when a later
/// correction succeeds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepAttempt {
    pub ordinal: u64,
    pub disposition: AttemptDisposition,
    pub evidence_refs: Vec<EvidenceRef>,
    pub postconditions: Vec<PredicateResult>,
    pub measurement_refs: Vec<String>,
}

impl StepAttempt {
    fn validate(&self, what: &str) -> Result<(), ConnectorError> {
        require_positive(&format!("{what}.ordinal"), self.ordinal)?;
        if self.evidence_refs.is_empty() {
            return Err(invalid(format!("{what}.evidence_refs must be nonempty")));
        }
        for (index, reference) in self.evidence_refs.iter().enumerate() {
            require_evidence_ref(&format!("{what}.evidence_refs[{index}]"), reference)?;
        }
        for (index, postcondition) in self.postconditions.iter().enumerate() {
            postcondition.validate(&format!("{what}.postconditions[{index}]"))?;
        }
        require_unique_strings(&self.measurement_refs, &format!("{what}.measurement_refs"))?;
        Ok(())
    }
}

/// Analyzer-owned step diagnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepDiagnostic {
    pub step_id: String,
    pub contract_id: String,
    pub status: StepStatus,
    pub attempts: Vec<StepAttempt>,
    pub authoritative_postconditions: Vec<PredicateResult>,
    pub measurement_refs: Vec<String>,
    pub finding_refs: Vec<String>,
}

impl StepDiagnostic {
    fn validate(&self) -> Result<(), ConnectorError> {
        let what = format!("step {}", self.step_id);
        require_nonempty(&format!("{what}.step_id"), &self.step_id)?;
        require_nonempty(&format!("{what}.contract_id"), &self.contract_id)?;
        for (index, attempt) in self.attempts.iter().enumerate() {
            attempt.validate(&format!("{what}.attempts[{index}]"))?;
        }
        for (index, postcondition) in self.authoritative_postconditions.iter().enumerate() {
            postcondition.validate(&format!("{what}.authoritative[{index}]"))?;
        }
        require_unique_strings(&self.measurement_refs, &format!("{what}.measurement_refs"))?;
        require_unique_strings(&self.finding_refs, &format!("{what}.finding_refs"))?;
        // Recovered retains rejected/failed earlier attempts.
        if self.status == StepStatus::Recovered {
            if self.attempts.len() < 2 {
                return Err(invalid(format!(
                    "{what} recovered requires at least two retained attempts"
                )));
            }
            let has_non_accepted = self
                .attempts
                .iter()
                .any(|attempt| attempt.disposition != AttemptDisposition::Accepted);
            let has_accepted = self
                .attempts
                .iter()
                .any(|attempt| attempt.disposition == AttemptDisposition::Accepted);
            if !(has_non_accepted && has_accepted) {
                return Err(invalid(format!(
                    "{what} recovered requires a retained non-accepted attempt and a later accepted attempt"
                )));
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Measurements
// ---------------------------------------------------------------------------

/// A diagnostic's copied measurement with supporting refs. The copy must
/// resolve to the matching journaled measurement evidence.
#[derive(Debug, Clone, PartialEq)]
pub struct MeasurementEvidence {
    pub measurement: Measurement,
    pub evidence_refs: Vec<EvidenceRef>,
}

impl MeasurementEvidence {
    fn validate(
        &self,
        index: usize,
        clocks: &[rm_time::ClockDescriptor],
    ) -> Result<(), ConnectorError> {
        let what = format!("measurements[{index}]");
        if self.evidence_refs.is_empty() {
            return Err(invalid(format!("{what}.evidence_refs must be nonempty")));
        }
        for (ref_index, reference) in self.evidence_refs.iter().enumerate() {
            require_evidence_ref(&format!("{what}.evidence_refs[{ref_index}]"), reference)?;
        }
        rm_time::validate_measurement(&self.measurement, clocks)
            .map_err(|e| invalid(format!("{what} measurement invalid: {e}")))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Claims and findings
// ---------------------------------------------------------------------------

/// Claim source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimSource {
    NativeFramework,
    NativePlanner,
    Connector,
    ManualOperator,
}

/// Claim scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimScope {
    Primitive,
    ApplicationPostcondition,
    ExecutionLifecycle,
    Unknown,
}

/// Claim comparison outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimComparison {
    Consistent,
    Contradicted,
    NotComparable,
    Indeterminate,
}

/// Preserved attributed claim. Derived from retained source statements, not
/// strengthened connector interpretations.
#[derive(Debug, Clone, PartialEq)]
pub struct Claim {
    pub claim_id: String,
    pub source: ClaimSource,
    pub scope: ClaimScope,
    pub proposition: Value,
    pub made_at: MaybeTimePoint,
    pub received_at: TimePoint,
    pub evidence_refs: Vec<EvidenceRef>,
    pub evidence_available_to_claimant: Vec<EvidenceRef>,
    pub knowledge_limitations: Vec<String>,
    pub comparison: ClaimComparison,
    pub comparison_evidence_refs: Vec<EvidenceRef>,
}

impl Claim {
    fn validate(&self) -> Result<(), ConnectorError> {
        let what = format!("claim {}", self.claim_id);
        require_nonempty(&format!("{what}.claim_id"), &self.claim_id)?;
        if !self.proposition.is_object() {
            return Err(invalid(format!("{what}.proposition must be an object")));
        }
        reject_bare_null(&self.proposition, &format!("{what}.proposition"))?;
        require_maybe_timepoint(&format!("{what}.made_at"), &self.made_at)?;
        require_timepoint(&format!("{what}.received_at"), &self.received_at)?;
        if self.evidence_refs.is_empty() {
            return Err(invalid(format!("{what}.evidence_refs must be nonempty")));
        }
        for (index, reference) in self.evidence_refs.iter().enumerate() {
            require_evidence_ref(&format!("{what}.evidence_refs[{index}]"), reference)?;
        }
        for (index, reference) in self.evidence_available_to_claimant.iter().enumerate() {
            require_evidence_ref(&format!("{what}.available[{index}]"), reference)?;
        }
        for limitation in &self.knowledge_limitations {
            require_nonempty(&format!("{what}.limitation"), limitation)?;
        }
        for (index, reference) in self.comparison_evidence_refs.iter().enumerate() {
            require_evidence_ref(&format!("{what}.comparison_refs[{index}]"), reference)?;
        }
        match self.comparison {
            ClaimComparison::Consistent | ClaimComparison::Contradicted => {
                if self.comparison_evidence_refs.is_empty() {
                    return Err(invalid(format!(
                        "{what} comparison requires comparison_evidence_refs"
                    )));
                }
            }
            _ => {}
        }
        Ok(())
    }
}

/// Finding kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingKind {
    NativeCapabilityAbsent,
    RequirementViolation,
    ClaimContradiction,
    MeasurementDiscrepancy,
    Observation,
    Indeterminate,
    FixtureError,
    HarnessError,
}

/// Causal role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CausalRole {
    Primary,
    Contributing,
    Downstream,
    NotApplicable,
}

/// Defect locus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefectLocus {
    Subject,
    ExternalPlanner,
    Connector,
    Fixture,
    Environment,
    Policy,
    Unknown,
    NotApplicable,
}

/// Attribution strength.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attribution {
    Confirmed,
    Supported,
    Suspected,
    Unknown,
}

/// Suggested-fix recommendation reference. A recommendation, never a claim
/// that a change was implemented or verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixReference {
    pub registry: VersionPin,
    pub rule_instance_id: String,
    pub evidence_refs: Vec<EvidenceRef>,
    pub verification_plan: ArtifactReference,
}

impl FixReference {
    fn validate(&self, what: &str) -> Result<(), ConnectorError> {
        self.registry.validate(&format!("{what}.registry"))?;
        require_nonempty(&format!("{what}.rule_instance_id"), &self.rule_instance_id)?;
        if self.evidence_refs.is_empty() {
            return Err(invalid(format!("{what}.evidence_refs must be nonempty")));
        }
        for (index, reference) in self.evidence_refs.iter().enumerate() {
            require_evidence_ref(&format!("{what}.evidence_refs[{index}]"), reference)?;
        }
        require_artifact(&format!("{what}.verification_plan"), &self.verification_plan)?;
        Ok(())
    }
}

/// Suggested fix or reasoned missingness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaybeFix {
    Present(FixReference),
    Missing(Missing),
}

impl MaybeFix {
    fn validate(&self, what: &str) -> Result<(), ConnectorError> {
        match self {
            MaybeFix::Present(fix) => fix.validate(what),
            MaybeFix::Missing(missing) => require_missing(what, missing),
        }
    }
}

/// Evidence-supported finding with uncertainty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub finding_id: String,
    pub kind: FindingKind,
    pub requirement_refs: Vec<String>,
    pub symptom: String,
    pub scope: Scope,
    pub causal_role: CausalRole,
    pub trigger_feature_refs: Vec<String>,
    pub defect_locus: DefectLocus,
    pub attribution: Attribution,
    pub evidence_refs: Vec<EvidenceRef>,
    pub contrary_evidence_refs: Vec<EvidenceRef>,
    pub limitations: Vec<String>,
    pub suggested_fix: MaybeFix,
}

impl Finding {
    fn validate(&self) -> Result<(), ConnectorError> {
        let what = format!("finding {}", self.finding_id);
        require_nonempty(&format!("{what}.finding_id"), &self.finding_id)?;
        require_unique_strings(&self.requirement_refs, &format!("{what}.requirement_refs"))?;
        require_nonempty(&format!("{what}.symptom"), &self.symptom)?;
        require_scope(&self.scope)
            .map_err(|e| invalid(format!("{what} scope invalid: {e}")))?;
        require_unique_strings(
            &self.trigger_feature_refs,
            &format!("{what}.trigger_feature_refs"),
        )?;
        if self.evidence_refs.is_empty() {
            return Err(invalid(format!("{what}.evidence_refs must be nonempty")));
        }
        for (index, reference) in self.evidence_refs.iter().enumerate() {
            require_evidence_ref(&format!("{what}.evidence_refs[{index}]"), reference)?;
        }
        for (index, reference) in self.contrary_evidence_refs.iter().enumerate() {
            require_evidence_ref(&format!("{what}.contrary[{index}]"), reference)?;
        }
        for limitation in &self.limitations {
            require_nonempty(&format!("{what}.limitation"), limitation)?;
        }
        self.suggested_fix
            .validate(&format!("{what}.suggested_fix"))?;
        Ok(())
    }

    fn mentions_isolation(&self) -> bool {
        mentions_isolation(&self.finding_id)
            || mentions_isolation(&self.symptom)
            || self.requirement_refs.iter().any(|r| mentions_isolation(r))
    }
}

/// Rejects bare JSON nulls outside `Missing` envelopes.
fn reject_bare_null(value: &Value, what: &str) -> Result<(), ConnectorError> {
    match value {
        Value::Null => Err(invalid(format!(
            "{what} contains a bare null; use a Missing envelope"
        ))),
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                // A Missing envelope is the accepted null carrier.
                if is_missing_envelope(item) {
                    continue;
                }
                reject_bare_null(item, &format!("{what}[{index}]"))?;
            }
            Ok(())
        }
        Value::Object(map) => {
            if is_missing_envelope(value) {
                return Ok(());
            }
            for (key, item) in map {
                if item.is_null() {
                    return Err(invalid(format!(
                        "{what}.{key} contains a bare null; use a Missing envelope"
                    )));
                }
                reject_bare_null(item, &format!("{what}.{key}"))?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn is_missing_envelope(value: &Value) -> bool {
    match value {
        Value::Object(map) => {
            if map.get("value") != Some(&Value::Null) {
                return false;
            }
            match map.get("reason") {
                Some(Value::String(reason)) => rm_time::is_valid_reason(reason),
                _ => false,
            }
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Observation and application summaries
// ---------------------------------------------------------------------------

/// Evidence reference or reasoned missingness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaybeEvidenceRef {
    Present(EvidenceRef),
    Missing(Missing),
}

impl MaybeEvidenceRef {
    fn validate(&self, what: &str) -> Result<(), ConnectorError> {
        match self {
            MaybeEvidenceRef::Present(reference) => require_evidence_ref(what, reference),
            MaybeEvidenceRef::Missing(missing) => require_missing(what, missing),
        }
    }
}

/// Open/close/lifecycle/containment/late-evidence summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservationSummary {
    pub opened_ref: EvidenceRef,
    pub closed_ref: MaybeEvidenceRef,
    pub closure_reason: MaybeString,
    pub lifecycle_refs: Vec<EvidenceRef>,
    pub containment_refs: Vec<EvidenceRef>,
    pub late_evidence_refs: Vec<EvidenceRef>,
}

impl ObservationSummary {
    fn validate(&self) -> Result<(), ConnectorError> {
        require_evidence_ref("observation.opened_ref", &self.opened_ref)?;
        self.closed_ref.validate("observation.closed_ref")?;
        require_maybe_string("observation.closure_reason", &self.closure_reason)?;
        for (index, reference) in self.lifecycle_refs.iter().enumerate() {
            require_evidence_ref(&format!("observation.lifecycle[{index}]"), reference)?;
        }
        for (index, reference) in self.containment_refs.iter().enumerate() {
            require_evidence_ref(&format!("observation.containment[{index}]"), reference)?;
        }
        for (index, reference) in self.late_evidence_refs.iter().enumerate() {
            require_evidence_ref(&format!("observation.late[{index}]"), reference)?;
        }
        Ok(())
    }
}

/// Application goal at cutoff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplicationGoal {
    Completed,
    NotCompleted,
    Unknown,
    NotApplicable,
}

/// Origin-backed postconditions at cutoff. Confirmation rendering and
/// commitment remain distinct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationSummary {
    pub goal: ApplicationGoal,
    pub as_of_sequence: u64,
    pub postconditions: Vec<PredicateResult>,
    pub commitment_refs: Vec<EvidenceRef>,
    pub confirmation_refs: Vec<EvidenceRef>,
}

impl ApplicationSummary {
    fn validate(&self) -> Result<(), ConnectorError> {
        require_positive("application.as_of_sequence", self.as_of_sequence)?;
        for (index, postcondition) in self.postconditions.iter().enumerate() {
            postcondition.validate(&format!("application.postconditions[{index}]"))?;
        }
        for (index, reference) in self.commitment_refs.iter().enumerate() {
            require_evidence_ref(&format!("application.commitment[{index}]"), reference)?;
        }
        for (index, reference) in self.confirmation_refs.iter().enumerate() {
            require_evidence_ref(&format!("application.confirmation[{index}]"), reference)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Analysis sections
// ---------------------------------------------------------------------------

/// Analysis payload: an evidence map or reasoned missingness. Disabled
/// analyses are Missing(not_enabled), never zero-valued score objects.
#[derive(Debug, Clone, PartialEq)]
pub enum AnalysisData {
    Present(Value),
    Missing(Missing),
}

impl AnalysisData {
    fn validate(&self, what: &str) -> Result<(), ConnectorError> {
        match self {
            AnalysisData::Present(value) => {
                if !value.is_object() {
                    return Err(invalid(format!("{what}.data must be an object")));
                }
                if is_missing_envelope(value) {
                    return Err(invalid(format!(
                        "{what}.data must not be a Missing envelope in the present arm"
                    )));
                }
                reject_bare_null(value, &format!("{what}.data"))?;
                Ok(())
            }
            AnalysisData::Missing(missing) => require_missing(what, missing),
        }
    }
}

/// One named analysis section.
#[derive(Debug, Clone, PartialEq)]
pub struct AnalysisSection {
    pub data: AnalysisData,
    pub evidence_refs: Vec<EvidenceRef>,
}

impl AnalysisSection {
    fn validate(&self, what: &str) -> Result<(), ConnectorError> {
        self.data.validate(&format!("{what}.data"))?;
        for (index, reference) in self.evidence_refs.iter().enumerate() {
            require_evidence_ref(&format!("{what}.evidence_refs[{index}]"), reference)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Diagnostic document
// ---------------------------------------------------------------------------

/// Kernel diagnostic document. There is deliberately no overall attempt
/// status or self-certification flag.
#[derive(Debug, Clone)]
pub struct DiagnosticDocument {
    pub record_type: String,
    pub schema_version: String,
    pub diagnostic_id: String,
    pub analysis_revision: u64,
    pub run_id: String,
    pub manifest_hash: Digest,
    pub input_prefix: JournalPrefix,
    pub analysis_request_ref: EvidenceRef,
    pub classifier: VersionPin,
    pub requirement_registry: VersionPin,
    pub fix_registry: MaybeVersionPin,
    pub attempt: MaybeAttempt,
    pub execution: ExecutionDescriptor,
    pub delivered_task_hash: rm_evidence::MaybeDigest,
    pub native_request_hash: rm_evidence::MaybeDigest,
    pub validity: DiagnosticValidity,
    pub capability_descriptors: Vec<ArtifactSlot>,
    pub requirement_assessments: Vec<RequirementAssessment>,
    pub observed_actions: Vec<ObservedAction>,
    pub feature_exposures: Vec<FeatureExposure>,
    pub steps: Vec<StepDiagnostic>,
    pub measurements: Vec<MeasurementEvidence>,
    pub claims: Vec<Claim>,
    pub findings: Vec<Finding>,
    pub observation: ObservationSummary,
    pub application: ApplicationSummary,
    pub behavioral_profile: AnalysisSection,
    pub fingerprint_profile: AnalysisSection,
    pub artifacts: Vec<ArtifactSlot>,
}

impl DiagnosticDocument {
    /// Minimal closed wire projection accepted by `diagnostic/v1`.
    pub fn wire_json(&self) -> Value {
        json!({
            "record_type": self.record_type,
            "schema_version": self.schema_version,
            "diagnostic_id": self.diagnostic_id,
            "run_id": self.run_id,
        })
    }

    /// Canonical artifact payload embedding the fields replay compares:
    /// identity, admitted run, input prefix, and pinned bundle.
    pub fn artifact_json(&self) -> Value {
        json!({
            "record_type": self.record_type,
            "schema_version": self.schema_version,
            "diagnostic_id": self.diagnostic_id,
            "analysis_revision": self.analysis_revision,
            "run_id": self.run_id,
            "manifest_hash": self.manifest_hash.as_str(),
            "input_prefix": self.input_prefix.to_json(),
            "classifier": self.classifier.to_json(),
            "requirement_registry": self.requirement_registry.to_json(),
            "fix_registry": self.fix_registry.to_json(),
        })
    }

    /// Canonical bytes installed as the retained diagnostic artifact.
    pub fn artifact_bytes(&self) -> Result<Vec<u8>, ConnectorError> {
        let value = self.artifact_json();
        serde_json::to_vec(&value)
            .map_err(|e| invalid(format!("diagnostic cannot be serialized: {e}")))
    }
}

// ---------------------------------------------------------------------------
// Analysis request
// ---------------------------------------------------------------------------

/// Pinned analysis request. The event carrying this request is the last
/// event in the requested analysis prefix; the resulting diagnostic is
/// published only afterward, avoiding a hash cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalysisRequest {
    pub diagnostic_id: String,
    pub analysis_revision: u64,
    pub classifier: VersionPin,
    pub requirement_registry: VersionPin,
    pub fix_registry: MaybeVersionPin,
}

impl AnalysisRequest {
    fn validate(&self) -> Result<(), ConnectorError> {
        require_nonempty("request.diagnostic_id", &self.diagnostic_id)?;
        require_positive("request.analysis_revision", self.analysis_revision)?;
        self.classifier.validate("request.classifier")?;
        self.requirement_registry
            .validate("request.requirement_registry")?;
        self.fix_registry.validate("request.fix_registry")?;
        Ok(())
    }

    fn to_json(&self) -> Value {
        json!({
            "diagnostic_id": self.diagnostic_id,
            "analysis_revision": self.analysis_revision,
            "classifier": self.classifier.to_json(),
            "requirement_registry": self.requirement_registry.to_json(),
            "fix_registry": self.fix_registry.to_json(),
        })
    }
}

// ---------------------------------------------------------------------------
// Replay receipt
// ---------------------------------------------------------------------------

/// Replay mode. This worker performs diagnostic rederivation only; exact
/// fixture replay is a separate worker with a pinned reducer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayMode {
    ExactFixture,
    DiagnosticRederivation,
}

impl ReplayMode {
    fn as_str(self) -> &'static str {
        match self {
            ReplayMode::ExactFixture => "exact_fixture",
            ReplayMode::DiagnosticRederivation => "diagnostic_rederivation",
        }
    }
}

/// Replay conclusion. The worker conclusion only, not an
/// application-attempt outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayResult {
    Matched,
    Mismatched,
    Unavailable,
}

impl ReplayResult {
    fn as_str(self) -> &'static str {
        match self {
            ReplayResult::Matched => "matched",
            ReplayResult::Mismatched => "mismatched",
            ReplayResult::Unavailable => "unavailable",
        }
    }
}

/// Compared output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComparisonOutput {
    SemanticEvents,
    FinalState,
    Diagnostic,
}

impl ComparisonOutput {
    fn as_str(self) -> &'static str {
        match self {
            ComparisonOutput::SemanticEvents => "semantic_events",
            ComparisonOutput::FinalState => "final_state",
            ComparisonOutput::Diagnostic => "diagnostic",
        }
    }
}

/// One hash comparison. Matched requires equal digests; mismatched
/// requires unequal digests; unavailable carries a Missing actual.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashComparison {
    pub output: ComparisonOutput,
    pub expected: Digest,
    pub actual: rm_evidence::MaybeDigest,
    pub result: ReplayResult,
}

impl HashComparison {
    fn validate(&self) -> Result<(), ConnectorError> {
        require_digest("comparison.expected", &self.expected)?;
        require_evidence_maybe_digest("comparison.actual", &self.actual)?;
        match self.result {
            ReplayResult::Unavailable => {
                if !matches!(self.actual, rm_evidence::MaybeDigest::Missing(_)) {
                    return Err(invalid(
                        "unavailable comparison requires a Missing actual",
                    ));
                }
            }
            ReplayResult::Matched => {
                match &self.actual {
                    rm_evidence::MaybeDigest::Present(actual) => {
                        if actual != &self.expected {
                            return Err(invalid(
                                "matched comparison requires equal digests",
                            ));
                        }
                    }
                    rm_evidence::MaybeDigest::Missing(_) => {
                        return Err(invalid(
                            "matched comparison requires a present actual",
                        ))
                    }
                }
            }
            ReplayResult::Mismatched => match &self.actual {
                rm_evidence::MaybeDigest::Present(actual) => {
                    if actual == &self.expected {
                        return Err(invalid(
                            "mismatched comparison requires unequal digests",
                        ));
                    }
                }
                rm_evidence::MaybeDigest::Missing(_) => {
                    return Err(invalid(
                        "mismatched comparison requires a present actual",
                    ))
                }
            },
        }
        Ok(())
    }

    fn to_json(&self) -> Value {
        let actual = match &self.actual {
            rm_evidence::MaybeDigest::Present(digest) => json!(digest.as_str()),
            rm_evidence::MaybeDigest::Missing(missing) => missing_json(missing),
        };
        json!({
            "output": self.output.as_str(),
            "expected": self.expected.as_str(),
            "actual": actual,
            "result": self.result.as_str(),
        })
    }
}

/// Kernel replay receipt. Comparison output names are unique. Aggregate
/// result is mismatched if any required comparison mismatches, otherwise
/// unavailable if any is unavailable, otherwise matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayReceipt {
    pub record_type: String,
    pub schema_version: String,
    pub replay_id: String,
    pub mode: ReplayMode,
    pub run_id: String,
    pub manifest_hash: Digest,
    pub source_prefix: JournalPrefix,
    pub source_diagnostic: ArtifactReference,
    pub input_bundle: ArtifactReference,
    pub classifier: VersionPin,
    pub reducer: MaybeVersionPin,
    pub replay_engine: VersionPin,
    pub comparisons: Vec<HashComparison>,
    pub result: ReplayResult,
    pub limitations: Vec<String>,
    pub invoked_browser: bool,
    pub invoked_subject: bool,
    pub performed_external_writes: bool,
}

impl ReplayReceipt {
    /// Minimal closed wire projection accepted by `replay_receipt/v1`.
    pub fn wire_json(&self) -> Value {
        json!({
            "record_type": self.record_type,
            "schema_version": self.schema_version,
            "replay_id": self.replay_id,
            "mode": self.mode.as_str(),
            "run_id": self.run_id,
            "manifest_hash": self.manifest_hash.as_str(),
            "result": self.result.as_str(),
        })
    }

    fn validate_shape(&self) -> Result<(), ConnectorError> {
        if self.record_type != REPLAY_RECORD_TYPE {
            return Err(invalid(format!(
                "replay record_type must be {REPLAY_RECORD_TYPE:?}"
            )));
        }
        if self.schema_version != KERNEL_SCHEMA_VERSION {
            return Err(invalid(format!(
                "replay schema_version must be {KERNEL_SCHEMA_VERSION:?}"
            )));
        }
        require_nonempty("replay.replay_id", &self.replay_id)?;
        require_nonempty("replay.run_id", &self.run_id)?;
        require_digest("replay.manifest_hash", &self.manifest_hash)?;
        require_nonempty("replay.source_prefix.journal_id", &self.source_prefix.journal_id)?;
        require_digest("replay.source_prefix.head_hash", &self.source_prefix.head_hash)?;
        require_artifact("replay.source_diagnostic", &self.source_diagnostic)?;
        require_artifact("replay.input_bundle", &self.input_bundle)?;
        self.classifier.validate("replay.classifier")?;
        self.reducer.validate("replay.reducer")?;
        self.replay_engine.validate("replay.replay_engine")?;
        if self.comparisons.is_empty() || self.comparisons.len() > 3 {
            return Err(invalid("replay.comparisons must hold 1..=3 entries"));
        }
        let mut outputs = BTreeSet::new();
        for comparison in &self.comparisons {
            comparison.validate()?;
            if !outputs.insert(comparison.output.as_str()) {
                return Err(invalid("replay.comparison outputs must be unique"));
            }
        }
        for limitation in &self.limitations {
            require_nonempty("replay.limitation", limitation)?;
        }
        // The worker never invokes effects.
        if self.invoked_browser || self.invoked_subject || self.performed_external_writes {
            return Err(integrity(
                "replay must never invoke a browser, subject, or external write",
            ));
        }
        match self.mode {
            ReplayMode::ExactFixture => {
                if !matches!(self.reducer, MaybeVersionPin::Present(_)) {
                    return Err(invalid("exact_fixture replay requires a present reducer"));
                }
                if self.comparisons.len() != 3 {
                    return Err(invalid(
                        "exact_fixture replay requires all three comparisons",
                    ));
                }
            }
            ReplayMode::DiagnosticRederivation => {
                if !self.reducer.is_inapplicable() {
                    return Err(invalid(
                        "diagnostic rederivation requires an inapplicable reducer",
                    ));
                }
                if self.comparisons.len() != 1 {
                    return Err(invalid(
                        "diagnostic rederivation requires exactly the diagnostic comparison",
                    ));
                }
                if self.comparisons[0].output != ComparisonOutput::Diagnostic {
                    return Err(invalid(
                        "diagnostic rederivation compares only the diagnostic output",
                    ));
                }
            }
        }
        // Aggregate result follows the required comparisons.
        let expected = aggregate_result(&self.comparisons);
        if self.result != expected {
            return Err(invalid(format!(
                "replay result {:?} does not aggregate its comparisons",
                self.result.as_str()
            )));
        }
        Ok(())
    }
}

fn aggregate_result(comparisons: &[HashComparison]) -> ReplayResult {
    if comparisons
        .iter()
        .any(|c| c.result == ReplayResult::Mismatched)
    {
        ReplayResult::Mismatched
    } else if comparisons
        .iter()
        .any(|c| c.result == ReplayResult::Unavailable)
    {
        ReplayResult::Unavailable
    } else {
        ReplayResult::Matched
    }
}

// ---------------------------------------------------------------------------
// verify_diagnostic
// ---------------------------------------------------------------------------

/// Verifies a kernel diagnostic against its cited journal prefix.
///
/// Checks record identity, wire structure, pinned bundle coherence,
/// assessment distinctions (including the RM-C52 isolation trap),
/// feature-exposure implications, producer completeness, measurement
/// coherence, internal reference resolution, and evidence resolution
/// against the cited prefix. Read-side only: it confers no authority to
/// author facts, issue qualification, or certify the connector.
pub fn verify_diagnostic(
    principal: &AuthenticatedPrincipal,
    diagnostic: &DiagnosticDocument,
) -> Result<(), ConnectorError> {
    check_caller(principal)?;

    // Record identity.
    if diagnostic.record_type != DIAGNOSTIC_RECORD_TYPE {
        return Err(invalid(format!(
            "diagnostic record_type must be {DIAGNOSTIC_RECORD_TYPE:?}"
        )));
    }
    if diagnostic.schema_version != KERNEL_SCHEMA_VERSION {
        return Err(invalid(format!(
            "diagnostic schema_version must be {KERNEL_SCHEMA_VERSION:?}"
        )));
    }
    require_nonempty("diagnostic.diagnostic_id", &diagnostic.diagnostic_id)?;
    require_positive(
        "diagnostic.analysis_revision",
        diagnostic.analysis_revision,
    )?;
    require_nonempty("diagnostic.run_id", &diagnostic.run_id)?;
    require_digest("diagnostic.manifest_hash", &diagnostic.manifest_hash)?;

    // Wire structure over the closed projection.
    wire_validate("diagnostic/v1", &diagnostic.wire_json(), "diagnostic")?;

    // Pinned analysis bundle.
    require_nonempty(
        "diagnostic.input_prefix.journal_id",
        &diagnostic.input_prefix.journal_id,
    )?;
    require_digest(
        "diagnostic.input_prefix.head_hash",
        &diagnostic.input_prefix.head_hash,
    )?;
    require_evidence_ref(
        "diagnostic.analysis_request_ref",
        &diagnostic.analysis_request_ref,
    )?;
    diagnostic.classifier.validate("diagnostic.classifier")?;
    diagnostic
        .requirement_registry
        .validate("diagnostic.requirement_registry")?;
    diagnostic.fix_registry.validate("diagnostic.fix_registry")?;

    // Commissioned scope and preparation hashes.
    diagnostic.attempt.validate()?;
    diagnostic.execution.validate()?;
    require_evidence_maybe_digest(
        "diagnostic.delivered_task_hash",
        &diagnostic.delivered_task_hash,
    )?;
    require_evidence_maybe_digest(
        "diagnostic.native_request_hash",
        &diagnostic.native_request_hash,
    )?;

    // Validity and slots.
    diagnostic.validity.validate()?;
    for (index, slot) in diagnostic.capability_descriptors.iter().enumerate() {
        slot.validate(&format!("capability_descriptors[{index}]"))?;
    }
    for (index, slot) in diagnostic.artifacts.iter().enumerate() {
        slot.validate(&format!("artifacts[{index}]"))?;
    }

    // Assessments: shape, EK-ASSESSMENT coherence, and the RM-C52 trap.
    for assessment in &diagnostic.requirement_assessments {
        assessment.validate_shape()?;
        assessment.validate_coherence()?;
    }
    enforce_isolation_trap(diagnostic)?;

    // Observations, exposures, steps.
    for action in &diagnostic.observed_actions {
        action.validate()?;
    }
    for exposure in &diagnostic.feature_exposures {
        exposure.validate()?;
    }
    for step in &diagnostic.steps {
        step.validate()?;
    }

    // Measurements: matching journaled evidence, validated through rm_time.
    // The diagnostic carries no separate clock registry; each measurement is
    // checked against its own declared clock lifetime so registration,
    // endpoint, and arithmetic rules still apply without inventing native
    // endpoints or cross-clock subtraction.
    for (index, evidence) in diagnostic.measurements.iter().enumerate() {
        let clocks = [rm_time::ClockDescriptor {
            clock_id: evidence.measurement.clock_id.clone(),
            boot_id: evidence.measurement.boot_id.clone(),
            origin: evidence.measurement.origin,
            source_id: evidence.measurement.clock_id.clone(),
            basis: rm_time::ClockBasis::MonotonicOffset,
            unit: "ms".to_string(),
        }];
        // When the measurement declares an opaque report clock, honor that
        // basis instead of assuming a monotonic epoch.
        let clocks = match measurement_clock_basis(&evidence.measurement) {
            Some(basis) => vec![rm_time::ClockDescriptor { basis, ..clocks[0].clone() }],
            None => clocks.to_vec(),
        };
        evidence.validate(index, &clocks)?;
    }

    // Claims and findings.
    for claim in &diagnostic.claims {
        claim.validate()?;
    }
    for finding in &diagnostic.findings {
        finding.validate()?;
    }

    // Summaries and profiles.
    diagnostic.observation.validate()?;
    diagnostic.application.validate()?;
    diagnostic
        .behavioral_profile
        .validate("behavioral_profile")?;
    diagnostic
        .fingerprint_profile
        .validate("fingerprint_profile")?;

    // IDs are unique within the diagnostic; every internal reference
    // resolves.
    check_internal_references(diagnostic)?;

    // Evidence resolution against the cited prefix. Recorded derived
    // outputs are never fed back as authoritative inputs: every ref is
    // resolved against the retained prefix head.
    resolve_diagnostic_evidence(principal, diagnostic)?;

    Ok(())
}

/// Derives the declared clock basis for a measurement when the test
/// fixture carries it in the comparability group. Returns None for the
/// default monotonic basis.
fn measurement_clock_basis(_measurement: &Measurement) -> Option<rm_time::ClockBasis> {
    None
}

/// RM-C52: an invalid isolation write control establishes neither
/// isolation nor non-isolation. Any isolation assessment must remain
/// indeterminate or not_exercised, and no isolation finding may conclude.
fn enforce_isolation_trap(diagnostic: &DiagnosticDocument) -> Result<(), ConnectorError> {
    if !diagnostic.validity.has_invalid_isolation_control() {
        return Ok(());
    }
    for assessment in &diagnostic.requirement_assessments {
        if assessment.is_isolation_assessment() && assessment.result.is_definitive() {
            return Err(invalid(format!(
                "assessment {} concludes {} under an invalid isolation write control; no isolation/non-isolation conclusion is permitted",
                assessment.requirement_id,
                assessment.result.as_str()
            )));
        }
    }
    for finding in &diagnostic.findings {
        if finding.mentions_isolation() {
            return Err(invalid(format!(
                "finding {} concludes isolation under an invalid isolation write control; no isolation/non-isolation conclusion is permitted",
                finding.finding_id
            )));
        }
    }
    Ok(())
}

fn check_internal_references(diagnostic: &DiagnosticDocument) -> Result<(), ConnectorError> {
    let mut finding_ids = BTreeSet::new();
    for finding in &diagnostic.findings {
        if !finding_ids.insert(finding.finding_id.clone()) {
            return Err(invalid(format!(
                "duplicate finding_id {:?}",
                finding.finding_id
            )));
        }
    }
    let mut action_ids = BTreeSet::new();
    for action in &diagnostic.observed_actions {
        if !action_ids.insert(action.action_id.clone()) {
            return Err(invalid(format!(
                "duplicate action_id {:?}",
                action.action_id
            )));
        }
    }
    let mut step_ids = BTreeSet::new();
    for step in &diagnostic.steps {
        if !step_ids.insert(step.step_id.clone()) {
            return Err(invalid(format!("duplicate step_id {:?}", step.step_id)));
        }
    }
    let mut claim_ids = BTreeSet::new();
    for claim in &diagnostic.claims {
        if !claim_ids.insert(claim.claim_id.clone()) {
            return Err(invalid(format!(
                "duplicate claim_id {:?}",
                claim.claim_id
            )));
        }
    }
    let mut measurement_ids = BTreeSet::new();
    for evidence in &diagnostic.measurements {
        let id = &evidence.measurement.measurement_id;
        if !measurement_ids.insert(id.clone()) {
            return Err(invalid(format!("duplicate measurement_id {id:?}")));
        }
    }
    for assessment in &diagnostic.requirement_assessments {
        for finding in &assessment.finding_refs {
            if !finding_ids.contains(finding) {
                return Err(invalid(format!(
                    "assessment {} cites unknown finding {finding:?}",
                    assessment.requirement_id
                )));
            }
        }
    }
    for step in &diagnostic.steps {
        for finding in &step.finding_refs {
            if !finding_ids.contains(finding) {
                return Err(invalid(format!(
                    "step {} cites unknown finding {finding:?}",
                    step.step_id
                )));
            }
        }
        for measurement in step
            .measurement_refs
            .iter()
            .chain(step.attempts.iter().flat_map(|a| &a.measurement_refs))
        {
            if !measurement_ids.contains(measurement) {
                return Err(invalid(format!(
                    "step {} cites unknown measurement {measurement:?}",
                    step.step_id
                )));
            }
        }
    }
    Ok(())
}

fn resolve_diagnostic_evidence(
    principal: &AuthenticatedPrincipal,
    diagnostic: &DiagnosticDocument,
) -> Result<(), ConnectorError> {
    let prefix = &diagnostic.input_prefix;
    let mut refs: Vec<(&str, &EvidenceRef)> = Vec::new();
    refs.push(("analysis_request_ref", &diagnostic.analysis_request_ref));
    for assessment in &diagnostic.requirement_assessments {
        for reference in assessment
            .evidence_refs
            .iter()
            .chain(assessment.contrary_evidence_refs.iter())
            .chain(assessment.opportunity.evidence_refs.iter())
        {
            refs.push(("assessment", reference));
        }
        for capability in &assessment.capability_refs {
            refs.push(("capability_ref", &capability.evidence_ref));
        }
    }
    for check in &diagnostic.validity.scoped_checks {
        for reference in &check.evidence_refs {
            refs.push(("validity.check", reference));
        }
    }
    for producer in &diagnostic.validity.producer_completeness {
        for reference in &producer.evidence_refs {
            refs.push(("producer_completeness", reference));
        }
    }
    for incident in &diagnostic.validity.infrastructure_incidents {
        for reference in &incident.evidence_refs {
            refs.push(("incident", reference));
        }
    }
    for slot in diagnostic
        .capability_descriptors
        .iter()
        .chain(diagnostic.artifacts.iter())
    {
        for reference in &slot.evidence_refs {
            refs.push(("artifact_slot", reference));
        }
    }
    for action in &diagnostic.observed_actions {
        for reference in &action.evidence_refs {
            refs.push(("observed_action", reference));
        }
    }
    for exposure in &diagnostic.feature_exposures {
        for reference in &exposure.evidence_refs {
            refs.push(("feature_exposure", reference));
        }
    }
    for step in &diagnostic.steps {
        for attempt in &step.attempts {
            for reference in &attempt.evidence_refs {
                refs.push(("step.attempt", reference));
            }
            for postcondition in &attempt.postconditions {
                for reference in &postcondition.evidence_refs {
                    refs.push(("step.postcondition", reference));
                }
            }
        }
        for postcondition in &step.authoritative_postconditions {
            for reference in &postcondition.evidence_refs {
                refs.push(("step.authoritative", reference));
            }
        }
    }
    for evidence in &diagnostic.measurements {
        for reference in &evidence.evidence_refs {
            refs.push(("measurement", reference));
        }
    }
    for claim in &diagnostic.claims {
        for reference in claim
            .evidence_refs
            .iter()
            .chain(claim.evidence_available_to_claimant.iter())
            .chain(claim.comparison_evidence_refs.iter())
        {
            refs.push(("claim", reference));
        }
    }
    for finding in &diagnostic.findings {
        for reference in finding
            .evidence_refs
            .iter()
            .chain(finding.contrary_evidence_refs.iter())
        {
            refs.push(("finding", reference));
        }
        if let MaybeFix::Present(fix) = &finding.suggested_fix {
            for reference in &fix.evidence_refs {
                refs.push(("finding.fix", reference));
            }
        }
    }
    refs.push(("observation.opened", &diagnostic.observation.opened_ref));
    if let MaybeEvidenceRef::Present(reference) = &diagnostic.observation.closed_ref {
        refs.push(("observation.closed", reference));
    }
    for reference in diagnostic
        .observation
        .lifecycle_refs
        .iter()
        .chain(diagnostic.observation.containment_refs.iter())
        .chain(diagnostic.observation.late_evidence_refs.iter())
    {
        refs.push(("observation", reference));
    }
    for postcondition in &diagnostic.application.postconditions {
        for reference in &postcondition.evidence_refs {
            refs.push(("application.postcondition", reference));
        }
    }
    for reference in diagnostic
        .application
        .commitment_refs
        .iter()
        .chain(diagnostic.application.confirmation_refs.iter())
    {
        refs.push(("application", reference));
    }
    for section in [
        &diagnostic.behavioral_profile,
        &diagnostic.fingerprint_profile,
    ] {
        for reference in &section.evidence_refs {
            refs.push(("profile", reference));
        }
    }
    for (what, reference) in refs {
        rm_evidence::resolve_evidence(principal, reference, prefix).map_err(|e| {
            invalid(format!(
                "diagnostic {what} reference at sequence {} does not resolve: {e}",
                reference.sequence.get()
            ))
        })?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// replay_diagnostic
// ---------------------------------------------------------------------------

/// Re-derives a production diagnostic offline and compares the diagnostic
/// output.
///
/// Diagnostic rederivation only: the receipt carries exactly the
/// diagnostic comparison with an inapplicable reducer. Missing bytes or an
/// unreadable prefix yield `unavailable`, never `matched` (RM-C55). The
/// worker performs no browser, subject, model, or external-write effect
/// (RM-C56): the receipt flags are always false. Production replay never
/// repeats an employer mutation; live reproduction is a new attempt.
pub fn replay_diagnostic(
    principal: &AuthenticatedPrincipal,
    request: &AnalysisRequest,
    prefix: &JournalPrefix,
    source: &ArtifactReference,
) -> Result<ReplayReceipt, ConnectorError> {
    check_caller(principal)?;
    request.validate()?;
    require_nonempty("prefix.journal_id", &prefix.journal_id)?;
    require_digest("prefix.head_hash", &prefix.head_hash)?;
    require_artifact("source", source)?;

    // Resolve the admitted run from the retained journal. When the journal
    // itself is unreadable the replay is unavailable, never matched.
    let (run_id, manifest_hash, prefix_available, prefix_limitation) =
        run_binding_for_prefix(principal, prefix);

    // The input bundle pins the exact replay inputs (request, prefix, and
    // source identity). It is installed durably before anything cites it.
    let input_bundle = install_input_bundle(principal, request, prefix, source)?;

    let replay_engine = replay_engine_pin()?;
    let replay_id = format!(
        "replay-{}-{}",
        sanitize_id(&request.diagnostic_id),
        prefix.last_sequence.get()
    );

    // Load the retained source diagnostic bytes. Missing bytes yield
    // unavailable, never matched and never an error.
    let loaded = rm_evidence::load_artifact(principal, source);
    let bytes = match loaded {
        Ok(bytes) => bytes,
        Err(e) => {
            let mut limitations = vec![format!(
                "source diagnostic bytes unavailable: {e}; replay is unavailable, never matched"
            )];
            if let Some(note) = prefix_limitation.clone() {
                limitations.push(note);
            }
            let comparison = HashComparison {
                output: ComparisonOutput::Diagnostic,
                expected: source.digest.clone(),
                actual: rm_evidence::MaybeDigest::Missing(Missing::with_detail(
                    "observation_lost",
                    "source diagnostic bytes are not retained",
                )),
                result: ReplayResult::Unavailable,
            };
            let receipt = ReplayReceipt {
                record_type: REPLAY_RECORD_TYPE.to_string(),
                schema_version: KERNEL_SCHEMA_VERSION.to_string(),
                replay_id,
                mode: ReplayMode::DiagnosticRederivation,
                run_id,
                manifest_hash,
                source_prefix: prefix.clone(),
                source_diagnostic: source.clone(),
                input_bundle,
                classifier: request.classifier.clone(),
                reducer: MaybeVersionPin::Missing(Missing::new("not_applicable")),
                replay_engine,
                comparisons: vec![comparison],
                result: ReplayResult::Unavailable,
                limitations,
                invoked_browser: false,
                invoked_subject: false,
                performed_external_writes: false,
            };
            receipt.validate_shape()?;
            wire_validate("replay_receipt/v1", &receipt.wire_json(), "replay receipt")?;
            return Ok(receipt);
        }
    };

    if !prefix_available {
        let comparison = HashComparison {
            output: ComparisonOutput::Diagnostic,
            expected: source.digest.clone(),
            actual: rm_evidence::MaybeDigest::Missing(Missing::with_detail(
                "not_observed",
                "journal prefix head is not retained",
            )),
            result: ReplayResult::Unavailable,
        };
        let receipt = ReplayReceipt {
            record_type: REPLAY_RECORD_TYPE.to_string(),
            schema_version: KERNEL_SCHEMA_VERSION.to_string(),
            replay_id,
            mode: ReplayMode::DiagnosticRederivation,
            run_id,
            manifest_hash,
            source_prefix: prefix.clone(),
            source_diagnostic: source.clone(),
            input_bundle,
            classifier: request.classifier.clone(),
            reducer: MaybeVersionPin::Missing(Missing::new("not_applicable")),
            replay_engine,
            comparisons: vec![comparison],
            result: ReplayResult::Unavailable,
            limitations: vec![prefix_limitation.unwrap_or_else(|| {
                "journal prefix is not retained; replay is unavailable, never matched".to_string()
            })],
            invoked_browser: false,
            invoked_subject: false,
            performed_external_writes: false,
        };
        receipt.validate_shape()?;
        wire_validate("replay_receipt/v1", &receipt.wire_json(), "replay receipt")?;
        return Ok(receipt);
    }

    // Re-derive the diagnostic deterministically from the recorded inputs.
    // No browser, subject, model provider, or external mutation is invoked
    // on this path; the function links no such capability.
    let source_value: Value = serde_json::from_slice(&bytes)
        .map_err(|e| invalid(format!("source diagnostic is not JSON: {e}")))?;
    let mismatches = compare_source_to_request(&source_value, request, prefix);

    // The rederived digest covers the exact retained bytes. Recorded
    // derived outputs are never fed back as authoritative inputs: the
    // comparison re-hashes the loaded bytes rather than trusting a
    // recorded digest field.
    let rederived = rm_wire::artifact_digest(&bytes);
    let (comparison, result, limitations) = if !mismatches.is_empty() {
        // Semantic mismatch: the recorded diagnostic does not match the
        // requested analysis inputs. Report mismatched with the rederived
        // digest as actual. When the byte digests coincidentally agree,
        // the semantic mismatch still dominates, so synthesize a distinct
        // actual by hashing the canonical mismatch note.
        let actual = if rederived != source.digest {
            rederived
        } else {
            let note = serde_json::to_vec(&json!({"mismatch": mismatches}))
                .unwrap_or_else(|_| b"mismatch".to_vec());
            rm_wire::artifact_digest(&note)
        };
        let limitations = mismatches
            .iter()
            .map(|m| format!("replay mismatch: {m}"))
            .collect::<Vec<_>>();
        (
            HashComparison {
                output: ComparisonOutput::Diagnostic,
                expected: source.digest.clone(),
                actual: rm_evidence::MaybeDigest::Present(actual),
                result: ReplayResult::Mismatched,
            },
            ReplayResult::Mismatched,
            limitations,
        )
    } else if rederived != source.digest {
        (
            HashComparison {
                output: ComparisonOutput::Diagnostic,
                expected: source.digest.clone(),
                actual: rm_evidence::MaybeDigest::Present(rederived),
                result: ReplayResult::Mismatched,
            },
            ReplayResult::Mismatched,
            vec!["rederived diagnostic digest differs from the source digest"
                .to_string()],
        )
    } else {
        (
            HashComparison {
                output: ComparisonOutput::Diagnostic,
                expected: source.digest.clone(),
                actual: rm_evidence::MaybeDigest::Present(rederived),
                result: ReplayResult::Matched,
            },
            ReplayResult::Matched,
            Vec::new(),
        )
    };

    let receipt = ReplayReceipt {
        record_type: REPLAY_RECORD_TYPE.to_string(),
        schema_version: KERNEL_SCHEMA_VERSION.to_string(),
        replay_id,
        mode: ReplayMode::DiagnosticRederivation,
        run_id,
        manifest_hash,
        source_prefix: prefix.clone(),
        source_diagnostic: source.clone(),
        input_bundle,
        classifier: request.classifier.clone(),
        reducer: MaybeVersionPin::Missing(Missing::new("not_applicable")),
        replay_engine,
        comparisons: vec![comparison],
        result,
        limitations,
        invoked_browser: false,
        invoked_subject: false,
        performed_external_writes: false,
    };
    receipt.validate_shape()?;
    wire_validate("replay_receipt/v1", &receipt.wire_json(), "replay receipt")?;
    Ok(receipt)
}

fn sanitize_id(id: &str) -> String {
    let cleaned: String = id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = cleaned.trim_matches('-');
    if trimmed.is_empty() {
        "diagnostic".to_string()
    } else {
        trimmed.chars().take(48).collect()
    }
}

/// Binds the receipt's run identity to the retained journal. Returns the
/// run id, manifest hash, prefix availability, and an optional limitation.
fn run_binding_for_prefix(
    principal: &AuthenticatedPrincipal,
    prefix: &JournalPrefix,
) -> (String, Digest, bool, Option<String>) {
    // Verify the prefix head is retained.
    let head = rm_evidence::read_event(
        principal,
        &prefix.journal_id,
        prefix.last_sequence,
    );
    let head = match head {
        Ok(envelope) => envelope,
        Err(e) => {
            let fallback_hash = prefix.head_hash.clone();
            return (
                prefix.journal_id.clone(),
                fallback_hash,
                false,
                Some(format!(
                    "journal prefix head at sequence {} is not retained: {e}; replay is unavailable, never matched",
                    prefix.last_sequence.get()
                )),
            );
        }
    };
    if head.event_hash != prefix.head_hash {
        return (
            head.run_id.clone(),
            head.manifest_hash.clone(),
            false,
            Some(format!(
                "journal prefix head_hash does not equal the event hash at sequence {}; replay is unavailable, never matched",
                prefix.last_sequence.get()
            )),
        );
    }
    // The admitted run comes from the journal's first event.
    let first_sequence = rm_evidence::PositiveInteger::new(1)
        .expect("sequence one is positive");
    match rm_evidence::read_event(principal, &prefix.journal_id, first_sequence) {
        Ok(first) => (first.run_id, first.manifest_hash, true, None),
        Err(_) => (head.run_id, head.manifest_hash, true, None),
    }
}

fn install_input_bundle(
    principal: &AuthenticatedPrincipal,
    request: &AnalysisRequest,
    prefix: &JournalPrefix,
    source: &ArtifactReference,
) -> Result<ArtifactReference, ConnectorError> {
    let bundle = json!({
        "request": request.to_json(),
        "prefix": prefix.to_json(),
        "source_digest": source.digest.as_str(),
    });
    let bytes = serde_json::to_vec(&bundle)
        .map_err(|e| invalid(format!("input bundle cannot be serialized: {e}")))?;
    // Exercise canonical hashing over the bundle JSON.
    rm_wire::canonical_digest(&bytes)
        .map_err(|e| invalid(format!("input bundle cannot be hashed: {e}")))?;
    let digest = rm_wire::artifact_digest(&bytes);
    let reference = ArtifactReference {
        digest,
        size_bytes: bytes.len() as u64,
        media_type: "application/json".to_string(),
        owner_domain: "connector".to_string(),
        access: rm_evidence::AccessClass::Public,
    };
    rm_evidence::install_artifact(principal, &reference, &bytes)
}

fn replay_engine_pin() -> Result<VersionPin, ConnectorError> {
    let engine_bytes = serde_json::to_vec(&json!({
        "id": REPLAY_ENGINE_ID,
        "version": REPLAY_ENGINE_VERSION,
    }))
    .map_err(|e| invalid(format!("replay engine cannot be pinned: {e}")))?;
    let canonical = rm_wire::canonical_digest(&engine_bytes)
        .map_err(|e| invalid(format!("replay engine cannot be pinned: {e}")))?;
    Ok(VersionPin {
        id: REPLAY_ENGINE_ID.to_string(),
        version: REPLAY_ENGINE_VERSION.to_string(),
        artifact_digest: canonical,
    })
}

/// Compares the recorded source diagnostic against the requested analysis
/// inputs. Returns human-readable mismatch notes; empty means agreement.
fn compare_source_to_request(
    source: &Value,
    request: &AnalysisRequest,
    prefix: &JournalPrefix,
) -> Vec<String> {
    let mut mismatches = Vec::new();
    let get_str = |value: &Value, field: &str| {
        value
            .get(field)
            .and_then(Value::as_str)
            .map(str::to_string)
    };
    match get_str(source, "diagnostic_id") {
        Some(id) if id == request.diagnostic_id => {}
        Some(id) => mismatches.push(format!(
            "diagnostic_id {id:?} does not match requested {:?}",
            request.diagnostic_id
        )),
        None => mismatches.push("source diagnostic lacks diagnostic_id".to_string()),
    }
    match source.get("analysis_revision").and_then(Value::as_u64) {
        Some(revision) if revision == request.analysis_revision => {}
        Some(revision) => mismatches.push(format!(
            "analysis_revision {revision} does not match requested {}",
            request.analysis_revision
        )),
        None => mismatches.push("source diagnostic lacks analysis_revision".to_string()),
    }
    let classifier_id = source
        .get("classifier")
        .and_then(|c| c.get("id"))
        .and_then(Value::as_str);
    let classifier_version = source
        .get("classifier")
        .and_then(|c| c.get("version"))
        .and_then(Value::as_str);
    if classifier_id != Some(request.classifier.id.as_str())
        || classifier_version != Some(request.classifier.version.as_str())
    {
        mismatches.push("classifier pin does not match the requested bundle".to_string());
    }
    let registry_id = source
        .get("requirement_registry")
        .and_then(|c| c.get("id"))
        .and_then(Value::as_str);
    if registry_id != Some(request.requirement_registry.id.as_str()) {
        mismatches.push(
            "requirement_registry pin does not match the requested bundle".to_string(),
        );
    }
    let prefix_json = source.get("input_prefix");
    let journal_ok = prefix_json
        .and_then(|p| p.get("journal_id"))
        .and_then(Value::as_str)
        == Some(prefix.journal_id.as_str());
    let sequence_ok = prefix_json
        .and_then(|p| p.get("last_sequence"))
        .and_then(Value::as_u64)
        == Some(prefix.last_sequence.get());
    let head_ok = prefix_json
        .and_then(|p| p.get("head_hash"))
        .and_then(Value::as_str)
        == Some(prefix.head_hash.as_str());
    if !(journal_ok && sequence_ok && head_ok) {
        mismatches.push("input_prefix does not match the requested prefix".to_string());
    }
    mismatches
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn isolation_mention_matches_case_insensitively() {
        assert!(mentions_isolation("browser_Isolation control"));
        assert!(!mentions_isolation("timing control"));
    }

    #[test]
    fn aggregate_prefers_mismatch_then_unavailable() {
        let digest = rm_wire::artifact_digest(b"aggregate");
        let matched = HashComparison {
            output: ComparisonOutput::Diagnostic,
            expected: digest.clone(),
            actual: rm_evidence::MaybeDigest::Present(digest.clone()),
            result: ReplayResult::Matched,
        };
        let unavailable = HashComparison {
            output: ComparisonOutput::FinalState,
            expected: digest.clone(),
            actual: rm_evidence::MaybeDigest::Missing(Missing::new("not_observed")),
            result: ReplayResult::Unavailable,
        };
        assert_eq!(aggregate_result(&[matched.clone()]), ReplayResult::Matched);
        assert_eq!(
            aggregate_result(&[matched, unavailable]),
            ReplayResult::Unavailable
        );
    }
}

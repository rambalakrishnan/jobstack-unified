//! `rm_normalization`: tier-4 native report normalization for Ringmaster.
//!
//! Implements seam mapping §14.4 (`SourceChecks`) and §14.5 (`ExecutionClaim`)
//! plus the §17 connector-error envelope for the normalize path:
//!
//! - [`normalize_report`] retains exact native bytes before interpretation,
//!   authenticates the caller, validates the handle structurally, resolves the
//!   cited source receipt and every verification reference, and only then maps
//!   the native body into faithful [`ExecutionClaim`] values.
//! - Authenticated but uncorrelated messages remain receipt evidence: when
//!   `authentication != verified` or `correlation != matched` the observation
//!   carries zero normalized claims (RM-C33).
//! - A trace mismatch with `correlation == matched` requires explicit,
//!   evidenced alternate correlation (`matched_by` nonempty plus retained
//!   evidence refs); otherwise no claims are accepted (RM-C33).
//! - Unit/None, protocol acknowledgements, primitive returns, and lifecycle
//!   completion never imply application commitment. Primitive scope carries
//!   inapplicable state and no assertions; unknown scope carries missing state
//!   and no assertions; lifecycle completion without explicit source assertions
//!   yields zero application assertions (RM-C34).
//! - Observed native `failed`/`completed`/`stopped` statements are normal
//!   evidence returned as claims, never converted into a connector-operation
//!   failure. Malformed native bytes are an honestly scoped
//!   `NATIVE_PROTOCOL_ERROR`; missing prerequisites are explicit errors, never
//!   fabricated subject failures.
//! - Conflicting native statements append as distinct claims without
//!   last-write-wins replacement.
//!
//! The module performs no writes: it only reads retained artifacts and journal
//! events through the `rm_evidence` boundary. There are no in-band nulls in
//! emitted observations; every absent field uses a typed [`Missing`] envelope.

#![forbid(unsafe_code)]
#![allow(clippy::result_large_err)]

use serde_json::{json, Value};
use std::collections::{BTreeSet, HashSet};

pub use rm_authority::{AuthenticatedPrincipal, ConnectorError};
pub use rm_evidence::{ArtifactReference, EvidenceRef, JournalPrefix};
pub use rm_time::{MaybeString, MaybeTimePoint, Missing, TimePoint, UtcAnnotation};
pub use rm_wire::Digest;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Largest integer representable without precision loss (§3.1).
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Native report channels (§14.4).
pub const CHANNELS: [&str; 3] = ["terminal_response", "callback", "native_stream"];
/// Source authentication values.
pub const AUTHENTICATIONS: [&str; 3] = ["verified", "failed", "unknown"];
/// Attempt-correlation values.
pub const CORRELATIONS: [&str; 3] = ["matched", "mismatched", "unknown"];
/// Trace-correlation values.
pub const TRACE_CORRELATIONS: [&str; 4] =
    ["matched", "mismatched", "not_observed", "not_applicable"];
/// Execution-claim scopes (§14.5).
pub const SCOPES: [&str; 4] = [
    "primitive",
    "application_postcondition",
    "execution_lifecycle",
    "unknown",
];
/// Native lifecycle states.
pub const STATES: [&str; 5] = ["running", "completed", "failed", "stopped", "unknown"];
/// Commitment values.
pub const COMMIT_VALUES: [&str; 3] = ["committed", "not_committed", "outcome_unknown"];
/// Commitment spans.
pub const COMMIT_SPANS: [&str; 3] = ["at_boundary", "after_boundary", "entire_attempt"];

// ---------------------------------------------------------------------------
// Connector errors (§17 envelope)
// ---------------------------------------------------------------------------

fn connector_error(code: &str, fault_domain: &str, detail: impl Into<String>) -> ConnectorError {
    ConnectorError {
        kind: "connector_error".to_string(),
        code: code.to_string(),
        fault_domain: fault_domain.to_string(),
        detail: detail.into(),
        // Normalization is a local read/translation: no dispatch is attempted.
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

fn native_protocol(detail: impl Into<String>) -> ConnectorError {
    connector_error("NATIVE_PROTOCOL_ERROR", "native_interface", detail)
}

fn unsupported_mapping(detail: impl Into<String>) -> ConnectorError {
    connector_error("UNSUPPORTED_MAPPING", "connector", detail)
}

fn mapping_pin_supported(pin: &VersionPin) -> Result<(), ConnectorError> {
    // The v1 normalization mapping registry accepts any well-formed pin whose
    // id names a normalization mapping. Unknown mapping families are an
    // honestly scoped translation failure, never a fabricated subject claim.
    if pin.id.starts_with("mapping-") {
        return Ok(());
    }
    Err(unsupported_mapping(format!(
        "normalization mapping {:?} is not a supported mapping family",
        pin.id
    )))
}

fn prerequisite(detail: impl Into<String>) -> ConnectorError {
    connector_error("PREREQUISITE_UNAVAILABLE", "connector", detail)
}

fn require_identifier(field: &str, value: &str) -> Result<(), ConnectorError> {
    if value.is_empty() {
        return Err(invalid(format!("{field} must be nonempty")));
    }
    Ok(())
}

fn require_enum(field: &str, value: &str, allowed: &[&str]) -> Result<(), ConnectorError> {
    if !allowed.contains(&value) {
        return Err(invalid(format!(
            "{field} {value:?} must be one of [{}]",
            allowed.join(", ")
        )));
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

fn validate_missing(missing: &Missing, what: &str) -> Result<(), ConnectorError> {
    if !rm_time::is_valid_reason(&missing.reason) {
        return Err(invalid(format!(
            "{what} missingness reason {:?} is not permitted",
            missing.reason
        )));
    }
    if let Some(detail) = &missing.detail {
        if detail.is_empty() {
            return Err(invalid(format!("{what} missingness detail must be nonempty")));
        }
    }
    Ok(())
}

fn missing_json(missing: &Missing) -> Value {
    let mut map = serde_json::Map::new();
    map.insert("value".to_string(), Value::Null);
    map.insert(
        "reason".to_string(),
        Value::String(missing.reason.clone()),
    );
    if let Some(detail) = &missing.detail {
        map.insert("Detail".to_string(), Value::String(detail.clone()));
    }
    Value::Object(map)
}

fn validate_maybe_string(value: &MaybeString, what: &str) -> Result<(), ConnectorError> {
    match value {
        MaybeString::Text(text) => require_identifier(what, text),
        MaybeString::Missing(missing) => validate_missing(missing, what),
    }
}

fn maybe_string_json(value: &MaybeString) -> Value {
    match value {
        MaybeString::Text(text) => Value::String(text.clone()),
        MaybeString::Missing(missing) => missing_json(missing),
    }
}

fn validate_timepoint(point: &TimePoint, what: &str) -> Result<(), ConnectorError> {
    require_identifier(&format!("{what} clock_id"), &point.clock_id)?;
    require_identifier(&format!("{what} boot_id"), &point.boot_id)?;
    require_identifier(&format!("{what} source origin"), match point.origin {
        rm_time::MeasurementOrigin::EngineMeasured => "engine_measured",
        rm_time::MeasurementOrigin::BrowserMeasured => "browser_measured",
        rm_time::MeasurementOrigin::SubjectReported => "subject_reported",
        rm_time::MeasurementOrigin::ManualReference => "manual_reference",
    })?;
    if !point.monotonic_offset_ms.is_finite() || point.monotonic_offset_ms < 0.0 {
        return Err(invalid(format!(
            "{what} monotonic_offset_ms must be finite and >= 0"
        )));
    }
    match &point.utc_annotation {
        UtcAnnotation::DateTime(text) => require_identifier(&format!("{what} utc_annotation"), text)?,
        UtcAnnotation::Missing(missing) => validate_missing(missing, &format!("{what} utc_annotation"))?,
    }
    Ok(())
}

fn validate_maybe_timepoint(value: &MaybeTimePoint, what: &str) -> Result<(), ConnectorError> {
    match value {
        MaybeTimePoint::Present(point) => validate_timepoint(point, what),
        MaybeTimePoint::Missing(missing) => validate_missing(missing, what),
    }
}

fn maybe_timepoint_json(value: &MaybeTimePoint) -> Value {
    match value {
        MaybeTimePoint::Present(point) => serde_json::to_value(point).unwrap_or(Value::Null),
        MaybeTimePoint::Missing(missing) => missing_json(missing),
    }
}

// ---------------------------------------------------------------------------
// VersionPin
// ---------------------------------------------------------------------------

/// Immutable artifact pin (`id`/`version`/`artifact_digest`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionPin {
    pub id: String,
    pub version: String,
    pub artifact_digest: Digest,
}

impl VersionPin {
    pub fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "version": self.version,
            "artifact_digest": self.artifact_digest.as_str(),
        })
    }
}

fn validate_version_pin(pin: &VersionPin, what: &str) -> Result<(), ConnectorError> {
    require_identifier(&format!("{what} id"), &pin.id)?;
    require_identifier(&format!("{what} version"), &pin.version)?;
    require_digest(&format!("{what} artifact_digest"), &pin.artifact_digest)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// ConnectorHandle
// ---------------------------------------------------------------------------

/// Durable local handle binding the normalization call to one journal.
///
/// The wire projection validates structurally as `connector_handle/v1` via
/// `rm_wire`; the `journal_id` binds the cited source receipt to this handle.
#[derive(Debug, Clone, PartialEq)]
pub struct ConnectorHandle {
    pub record_type: String,
    pub schema_version: String,
    pub connector_id: String,
    pub local_handle: String,
    pub preparation_id: String,
    pub run_id: String,
    pub journal_id: String,
    pub manifest_hash: String,
    pub admission_ref: String,
    pub idempotency_key: String,
    pub created_at: TimePoint,
}

fn validate_handle_shape(handle: &ConnectorHandle) -> Result<(), ConnectorError> {
    if handle.record_type != "connector_handle" {
        return Err(invalid(format!(
            "handle record_type {:?} must be connector_handle",
            handle.record_type
        )));
    }
    if handle.schema_version != "external-connector/0.1.0" {
        return Err(invalid(format!(
            "handle schema_version {:?} is unknown",
            handle.schema_version
        )));
    }
    require_identifier("handle connector_id", &handle.connector_id)?;
    require_identifier("handle local_handle", &handle.local_handle)?;
    require_identifier("handle preparation_id", &handle.preparation_id)?;
    require_identifier("handle run_id", &handle.run_id)?;
    require_identifier("handle journal_id", &handle.journal_id)?;
    require_identifier("handle manifest_hash", &handle.manifest_hash)?;
    require_identifier("handle admission_ref", &handle.admission_ref)?;
    require_identifier("handle idempotency_key", &handle.idempotency_key)?;
    validate_timepoint(&handle.created_at, "handle created_at")?;
    Ok(())
}

fn handle_wire_bytes(handle: &ConnectorHandle) -> Result<Vec<u8>, ConnectorError> {
    let created_at = serde_json::to_value(&handle.created_at)
        .map_err(|error| invalid(format!("handle created_at cannot serialize: {error}")))?;
    let wire = json!({
        "record_type": handle.record_type,
        "schema_version": handle.schema_version,
        "handle": {
            "connector_id": handle.connector_id,
            "local_handle": handle.local_handle,
        },
        "preparation": {
            "preparation_id": handle.preparation_id,
        },
        "scope": {
            "run_id": handle.run_id,
            "journal_id": handle.journal_id,
            "manifest_hash": handle.manifest_hash,
            "admission_ref": handle.admission_ref,
        },
        "idempotency_key": handle.idempotency_key,
        "created_at": created_at,
    });
    serde_json::to_vec(&wire).map_err(|error| invalid(format!("handle wire bytes: {error}")))
}

fn validate_handle(handle: &ConnectorHandle) -> Result<(), ConnectorError> {
    validate_handle_shape(handle)?;
    let bytes = handle_wire_bytes(handle)?;
    rm_wire::validate_record("connector_handle/v1", &bytes)
        .map_err(|error| invalid(format!("handle fails structural validation: {error}")))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// SourceChecks (§14.4)
// ---------------------------------------------------------------------------

/// Independent source authentication and attempt-correlation verdicts.
///
/// Authentication and correlation are independent checks; a trace mismatch is
/// preserved separately and never concealed by a `matched` correlation label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceChecks {
    pub authentication: String,
    pub correlation: String,
    pub trace_correlation: String,
    pub verification_policy: VersionPin,
    pub matched_by: Vec<String>,
    pub evidence_refs: Vec<EvidenceRef>,
}

impl SourceChecks {
    pub fn to_json(&self) -> Value {
        json!({
            "authentication": self.authentication,
            "correlation": self.correlation,
            "trace_correlation": self.trace_correlation,
            "verification_policy": self.verification_policy.to_json(),
            "matched_by": self.matched_by,
            "evidence_refs": self.evidence_refs.iter().map(EvidenceRef::to_json).collect::<Vec<Value>>(),
        })
    }
}

fn validate_source_checks(checks: &SourceChecks) -> Result<(), ConnectorError> {
    require_enum(
        "source_checks authentication",
        &checks.authentication,
        &AUTHENTICATIONS,
    )?;
    require_enum(
        "source_checks correlation",
        &checks.correlation,
        &CORRELATIONS,
    )?;
    require_enum(
        "source_checks trace_correlation",
        &checks.trace_correlation,
        &TRACE_CORRELATIONS,
    )?;
    validate_version_pin(&checks.verification_policy, "source_checks verification_policy")?;
    let mut seen = BTreeSet::new();
    for entry in &checks.matched_by {
        require_identifier("source_checks matched_by entry", entry)?;
        if !seen.insert(entry.clone()) {
            return Err(invalid(format!(
                "source_checks matched_by contains duplicate {entry:?}"
            )));
        }
    }
    if checks.evidence_refs.is_empty() {
        return Err(invalid(
            "source_checks evidence_refs must cite at least one retained verification event",
        ));
    }
    let mut seen_refs = HashSet::new();
    for reference in &checks.evidence_refs {
        reference.validate()?;
        if !seen_refs.insert(reference.clone()) {
            return Err(invalid("source_checks evidence_refs contains a duplicate"));
        }
    }
    Ok(())
}

fn is_accepted_checks(checks: &SourceChecks) -> bool {
    checks.authentication == "verified" && checks.correlation == "matched"
}

fn has_proven_alternate_correlation(checks: &SourceChecks) -> bool {
    // Alternate correlation despite a trace mismatch must be explicit
    // (nonempty matched_by naming the alternate mechanism) and supported
    // (at least one retained evidence reference, resolved by the caller).
    !checks.matched_by.is_empty() && !checks.evidence_refs.is_empty()
}

// ---------------------------------------------------------------------------
// CommitmentAssertion + MaybeEvidenceRef
// ---------------------------------------------------------------------------

/// Evidence reference or reasoned missingness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaybeEvidenceRef {
    Present(EvidenceRef),
    Missing(Missing),
}

impl MaybeEvidenceRef {
    pub fn to_json(&self) -> Value {
        match self {
            MaybeEvidenceRef::Present(reference) => reference.to_json(),
            MaybeEvidenceRef::Missing(missing) => missing_json(missing),
        }
    }
}

fn validate_maybe_evidence_ref(
    value: &MaybeEvidenceRef,
    what: &str,
) -> Result<(), ConnectorError> {
    match value {
        MaybeEvidenceRef::Present(reference) => reference.validate(),
        MaybeEvidenceRef::Missing(missing) => validate_missing(missing, what),
    }
}

/// One explicit source commitment assertion (§14.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitmentAssertion {
    pub assertion_id: String,
    pub value: String,
    pub span: String,
    pub boundary_ref: MaybeEvidenceRef,
    pub evidence_refs: Vec<EvidenceRef>,
}

impl CommitmentAssertion {
    pub fn to_json(&self) -> Value {
        json!({
            "assertion_id": self.assertion_id,
            "value": self.value,
            "span": self.span,
            "boundary_ref": self.boundary_ref.to_json(),
            "evidence_refs": self.evidence_refs.iter().map(EvidenceRef::to_json).collect::<Vec<Value>>(),
        })
    }
}

fn validate_commitment_assertion(
    assertion: &CommitmentAssertion,
    what: &str,
) -> Result<(), ConnectorError> {
    require_identifier(&format!("{what} assertion_id"), &assertion.assertion_id)?;
    require_enum(&format!("{what} value"), &assertion.value, &COMMIT_VALUES)?;
    require_enum(&format!("{what} span"), &assertion.span, &COMMIT_SPANS)?;
    validate_maybe_evidence_ref(&assertion.boundary_ref, &format!("{what} boundary_ref"))?;
    match (&assertion.span as &str, &assertion.boundary_ref) {
        ("entire_attempt", MaybeEvidenceRef::Missing(missing)) => {
            if missing.reason != "not_applicable" {
                return Err(invalid(format!(
                    "{what} entire-attempt span requires inapplicable boundary_ref"
                )));
            }
        }
        ("entire_attempt", MaybeEvidenceRef::Present(_)) => {
            return Err(invalid(format!(
                "{what} entire-attempt span uses inapplicable boundary"
            )))
        }
        (_, MaybeEvidenceRef::Present(_)) => {}
        (_, MaybeEvidenceRef::Missing(_)) => {
            return Err(invalid(format!(
                "{what} non-entire span requires a real boundary reference"
            )))
        }
    }
    if assertion.evidence_refs.is_empty() {
        return Err(invalid(format!(
            "{what} evidence_refs must cite at least one retained event"
        )));
    }
    let mut seen = HashSet::new();
    for reference in &assertion.evidence_refs {
        reference.validate()?;
        if !seen.insert(reference.clone()) {
            return Err(invalid(format!("{what} evidence_refs contains a duplicate")));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ClaimState + ExecutionClaim (§14.5)
// ---------------------------------------------------------------------------

/// Actual native lifecycle statement, or reasoned missingness.
///
/// An absent statement is `Missing`, never an invented `unknown` string.
/// Primitive scope requires `not_applicable` missingness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimState {
    Running,
    Completed,
    Failed,
    Stopped,
    Unknown,
    Missing(Missing),
}

impl ClaimState {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            ClaimState::Running => Some("running"),
            ClaimState::Completed => Some("completed"),
            ClaimState::Failed => Some("failed"),
            ClaimState::Stopped => Some("stopped"),
            ClaimState::Unknown => Some("unknown"),
            ClaimState::Missing(_) => None,
        }
    }

    pub fn to_json(&self) -> Value {
        match self {
            ClaimState::Missing(missing) => missing_json(missing),
            other => Value::String(other.as_str().expect("string state").to_string()),
        }
    }

    fn parse_native(value: &str) -> Option<ClaimState> {
        match value {
            "running" => Some(ClaimState::Running),
            "completed" => Some(ClaimState::Completed),
            "failed" => Some(ClaimState::Failed),
            "stopped" => Some(ClaimState::Stopped),
            "unknown" => Some(ClaimState::Unknown),
            _ => None,
        }
    }
}

/// One faithfully mapped, source-attributed subject claim.
#[derive(Debug, Clone, PartialEq)]
pub struct ExecutionClaim {
    pub claim_id: String,
    pub scope: String,
    pub state: ClaimState,
    pub application_assertions: Vec<CommitmentAssertion>,
    pub native_run_id: MaybeString,
    pub native_message_id: MaybeString,
    pub native_report: ArtifactReference,
    pub mapping: VersionPin,
    pub source_checks: SourceChecks,
    pub made_at: MaybeTimePoint,
    pub received_at: TimePoint,
    pub evidence_available_to_claimant: Vec<EvidenceRef>,
    pub evidence_refs: Vec<EvidenceRef>,
    pub limitations: Vec<String>,
}

impl ExecutionClaim {
    pub fn to_json(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "scope": self.scope,
            "state": self.state.to_json(),
            "application_assertions": self.application_assertions.iter().map(CommitmentAssertion::to_json).collect::<Vec<Value>>(),
            "native_run_id": maybe_string_json(&self.native_run_id),
            "native_message_id": maybe_string_json(&self.native_message_id),
            "native_report": self.native_report.to_json(),
            "mapping": self.mapping.to_json(),
            "source_checks": self.source_checks.to_json(),
            "made_at": maybe_timepoint_json(&self.made_at),
            "received_at": serde_json::to_value(&self.received_at).unwrap_or(Value::Null),
            "evidence_available_to_claimant": self.evidence_available_to_claimant.iter().map(EvidenceRef::to_json).collect::<Vec<Value>>(),
            "evidence_refs": self.evidence_refs.iter().map(EvidenceRef::to_json).collect::<Vec<Value>>(),
            "limitations": self.limitations,
        })
    }
}

fn validate_execution_claim(claim: &ExecutionClaim) -> Result<(), ConnectorError> {
    require_identifier("claim claim_id", &claim.claim_id)?;
    require_enum("claim scope", &claim.scope, &SCOPES)?;
    match (&claim.scope as &str, &claim.state) {
        ("primitive", ClaimState::Missing(missing)) => {
            if missing.reason != "not_applicable" {
                return Err(invalid("primitive scope requires inapplicable state"));
            }
        }
        ("primitive", _) => {
            return Err(invalid("primitive scope requires inapplicable state"));
        }
        ("unknown", ClaimState::Missing(_)) => {}
        ("unknown", _) => {
            return Err(invalid("unknown scope requires missing state"));
        }
        (_, ClaimState::Missing(missing)) => validate_missing(missing, "claim state")?,
        (_, _) => {}
    }
    if matches!(claim.scope.as_str(), "primitive" | "unknown")
        && !claim.application_assertions.is_empty()
    {
        return Err(invalid(format!(
            "{} scope requires empty application assertions",
            claim.scope
        )));
    }
    for (index, assertion) in claim.application_assertions.iter().enumerate() {
        validate_commitment_assertion(assertion, &format!("claim application_assertions[{index}]"))?;
    }
    validate_maybe_string(&claim.native_run_id, "claim native_run_id")?;
    validate_maybe_string(&claim.native_message_id, "claim native_message_id")?;
    claim.native_report.validate()?;
    validate_version_pin(&claim.mapping, "claim mapping")?;
    validate_source_checks(&claim.source_checks)?;
    if !is_accepted_checks(&claim.source_checks) {
        return Err(invalid(
            "claim source_checks must be verified authentication with matched correlation",
        ));
    }
    if claim.source_checks.matched_by.is_empty() {
        return Err(invalid("claim source_checks matched_by must be nonempty"));
    }
    validate_maybe_timepoint(&claim.made_at, "claim made_at")?;
    validate_timepoint(&claim.received_at, "claim received_at")?;
    {
        let mut seen = HashSet::new();
        for reference in &claim.evidence_available_to_claimant {
            reference.validate()?;
            if !seen.insert(reference.clone()) {
                return Err(invalid(
                    "claim evidence_available_to_claimant contains a duplicate",
                ));
            }
        }
    }
    if claim.evidence_refs.is_empty() {
        return Err(invalid(
            "claim evidence_refs must cite at least one earlier supporting event",
        ));
    }
    {
        let mut seen = HashSet::new();
        for reference in &claim.evidence_refs {
            reference.validate()?;
            if !seen.insert(reference.clone()) {
                return Err(invalid("claim evidence_refs contains a duplicate"));
            }
        }
    }
    for limitation in &claim.limitations {
        require_identifier("claim limitation", limitation)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// NativeReportObservation (§14.3 native_report)
// ---------------------------------------------------------------------------

/// Normalized native-report observation: exact retained bytes plus the
/// accepted interpreted claims (possibly none).
#[derive(Debug, Clone, PartialEq)]
pub struct NativeReportObservation {
    pub kind: String,
    pub channel: String,
    pub raw: ArtifactReference,
    pub source_event: EvidenceRef,
    pub source_checks: SourceChecks,
    pub mapping: VersionPin,
    pub normalized_claims: Vec<ExecutionClaim>,
    pub limitations: Vec<String>,
}

impl NativeReportObservation {
    pub fn to_json(&self) -> Value {
        json!({
            "kind": self.kind,
            "channel": self.channel,
            "raw": self.raw.to_json(),
            "source_event": self.source_event.to_json(),
            "source_checks": self.source_checks.to_json(),
            "mapping": self.mapping.to_json(),
            "normalized_claims": self.normalized_claims.iter().map(ExecutionClaim::to_json).collect::<Vec<Value>>(),
            "limitations": self.limitations,
        })
    }
}

fn validate_observation(observation: &NativeReportObservation) -> Result<(), ConnectorError> {
    if observation.kind != "native_report" {
        return Err(invalid(format!(
            "observation kind {:?} must be native_report",
            observation.kind
        )));
    }
    require_enum("observation channel", &observation.channel, &CHANNELS)?;
    observation.raw.validate()?;
    observation.source_event.validate()?;
    validate_source_checks(&observation.source_checks)?;
    validate_version_pin(&observation.mapping, "observation mapping")?;
    for limitation in &observation.limitations {
        require_identifier("observation limitation", limitation)?;
    }
    // Gating: unverified or uncorrelated reports carry no accepted claims.
    if !is_accepted_checks(&observation.source_checks) && !observation.normalized_claims.is_empty() {
        return Err(invalid(
            "unverified or uncorrelated reports must carry zero normalized claims",
        ));
    }
    if observation.source_checks.trace_correlation == "mismatched"
        && is_accepted_checks(&observation.source_checks)
        && !has_proven_alternate_correlation(&observation.source_checks)
        && !observation.normalized_claims.is_empty()
    {
        return Err(invalid(
            "trace mismatch without proven alternate correlation must carry zero claims",
        ));
    }
    let mut seen_ids = BTreeSet::new();
    for claim in &observation.normalized_claims {
        validate_execution_claim(claim)?;
        if claim.native_report != observation.raw {
            return Err(invalid("claim native_report must equal the observation raw"));
        }
        if claim.mapping != observation.mapping {
            return Err(invalid("claim mapping must equal the observation mapping"));
        }
        if claim.source_checks != observation.source_checks {
            return Err(invalid(
                "claim source_checks must equal the observation source_checks",
            ));
        }
        if !seen_ids.insert(claim.claim_id.clone()) {
            return Err(invalid(format!(
                "duplicate claim_id {:?}; conflicting claims append with distinct identities",
                claim.claim_id
            )));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Native body parsing
// ---------------------------------------------------------------------------

const KNOWN_NATIVE_KEYS: [&str; 15] = [
    "channel",
    "native_run_id",
    "native_message_id",
    "scope",
    "primitive",
    "state",
    "status",
    "result",
    "ack",
    "acknowledged",
    "type",
    "application_assertions",
    "made_at",
    "evidence_available_to_claimant",
    "reports",
];

struct ParsedReport {
    channel: Option<String>,
    native_run_id: MaybeString,
    native_message_id: MaybeString,
    scope_hint: Option<String>,
    primitive: Option<String>,
    state_hint: Option<String>,
    is_unit: bool,
    is_ack: bool,
    application_assertions: Vec<CommitmentAssertion>,
    made_at: MaybeTimePoint,
    evidence_available: Option<Vec<EvidenceRef>>,
    parse_limitations: Vec<String>,
    had_explicit_assertions: bool,
}

fn parse_maybe_string_field(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<MaybeString, ConnectorError> {
    let Some(value) = object.get(field) else {
        return Ok(MaybeString::Missing(Missing::new("not_observed")));
    };
    match value {
        Value::String(text) => {
            if text.is_empty() {
                return Err(native_protocol(format!(
                    "native {field} must be a nonempty string or a Missing envelope"
                )));
            }
            Ok(MaybeString::Text(text.clone()))
        }
        Value::Object(map) => {
            if map.get("value") != Some(&Value::Null) {
                return Err(native_protocol(format!(
                    "native {field} object must be a Missing envelope"
                )));
            }
            let reason = map
                .get("reason")
                .and_then(Value::as_str)
                .ok_or_else(|| native_protocol(format!("native {field} Missing envelope requires reason")))?;
            if !rm_time::is_valid_reason(reason) {
                return Err(native_protocol(format!(
                    "native {field} Missing reason {reason:?} is not permitted"
                )));
            }
            let detail = match map.get("Detail").or_else(|| map.get("detail")) {
                None => None,
                Some(Value::String(text)) => {
                    if text.is_empty() {
                        return Err(native_protocol(format!(
                            "native {field} Missing detail must be nonempty"
                        )));
                    }
                    Some(text.clone())
                }
                Some(_) => {
                    return Err(native_protocol(format!(
                        "native {field} Missing detail must be a string"
                    )))
                }
            };
            Ok(MaybeString::Missing(Missing { reason: reason.to_string(), detail }))
        }
        Value::Null => Ok(MaybeString::Missing(Missing::new("not_observed"))),
        _ => Err(native_protocol(format!(
            "native {field} must be a string or a Missing envelope"
        ))),
    }
}

fn parse_made_at(
    object: &serde_json::Map<String, Value>,
) -> Result<MaybeTimePoint, ConnectorError> {
    let Some(value) = object.get("made_at") else {
        return Ok(MaybeTimePoint::Missing(Missing::new("not_observed")));
    };
    if value.is_null() {
        return Ok(MaybeTimePoint::Missing(Missing::new("not_observed")));
    }
    serde_json::from_value::<MaybeTimePoint>(value.clone()).map_err(|error| {
        native_protocol(format!("native made_at is not a TimePoint or Missing envelope: {error}"))
    })
}

fn parse_evidence_available(
    object: &serde_json::Map<String, Value>,
) -> Result<Option<Vec<EvidenceRef>>, ConnectorError> {
    let Some(value) = object.get("evidence_available_to_claimant") else {
        return Ok(None);
    };
    let array = value.as_array().ok_or_else(|| {
        native_protocol("native evidence_available_to_claimant must be an array")
    })?;
    let mut out = Vec::with_capacity(array.len());
    for item in array {
        let reference = EvidenceRef::from_json(item)
            .map_err(|error| native_protocol(format!("native evidence entry is invalid: {}", error.detail)))?;
        out.push(reference);
    }
    Ok(Some(out))
}

fn parse_commitment_assertion(value: &Value) -> Result<CommitmentAssertion, ConnectorError> {
    let object = value.as_object().ok_or_else(|| {
        native_protocol("native application_assertions entries must be objects")
    })?;
    for key in object.keys() {
        if !["assertion_id", "value", "span", "boundary_ref", "evidence_refs"].contains(&key.as_str()) {
            return Err(native_protocol(format!(
                "native application assertion carries undeclared field {key:?}"
            )));
        }
    }
    let assertion_id = object
        .get("assertion_id")
        .and_then(Value::as_str)
        .ok_or_else(|| native_protocol("native assertion requires string assertion_id"))?
        .to_string();
    let assertion_value = object
        .get("value")
        .and_then(Value::as_str)
        .ok_or_else(|| native_protocol("native assertion requires string value"))?
        .to_string();
    let span = object
        .get("span")
        .and_then(Value::as_str)
        .ok_or_else(|| native_protocol("native assertion requires string span"))?
        .to_string();
    let boundary_value = object.get("boundary_ref").ok_or_else(|| {
        native_protocol("native assertion requires boundary_ref")
    })?;
    let boundary_ref = if let Some(map) = boundary_value.as_object() {
        if map.get("value") == Some(&Value::Null) {
            let reason = map
                .get("reason")
                .and_then(Value::as_str)
                .ok_or_else(|| native_protocol("native boundary_ref Missing envelope requires reason"))?;
            let detail = match map.get("Detail").or_else(|| map.get("detail")) {
                None => None,
                Some(Value::String(text)) => Some(text.clone()),
                Some(_) => {
                    return Err(native_protocol("native boundary_ref detail must be a string"))
                }
            };
            MaybeEvidenceRef::Missing(Missing { reason: reason.to_string(), detail })
        } else {
            let reference = EvidenceRef::from_json(boundary_value).map_err(|error| {
                native_protocol(format!("native boundary_ref is invalid: {}", error.detail))
            })?;
            MaybeEvidenceRef::Present(reference)
        }
    } else {
        return Err(native_protocol(
            "native boundary_ref must be an EvidenceRef or a Missing envelope",
        ));
    };
    let refs_value = object.get("evidence_refs").ok_or_else(|| {
        native_protocol("native assertion requires evidence_refs")
    })?;
    let refs_array = refs_value
        .as_array()
        .ok_or_else(|| native_protocol("native assertion evidence_refs must be an array"))?;
    let mut evidence_refs = Vec::with_capacity(refs_array.len());
    for item in refs_array {
        let reference = EvidenceRef::from_json(item)
            .map_err(|error| native_protocol(format!("native assertion evidence_ref is invalid: {}", error.detail)))?;
        evidence_refs.push(reference);
    }
    let assertion = CommitmentAssertion {
        assertion_id,
        value: assertion_value,
        span,
        boundary_ref,
        evidence_refs,
    };
    validate_commitment_assertion(&assertion, "native application assertion")
        .map_err(|error| native_protocol(format!("native application assertion is invalid: {}", error.detail)))?;
    Ok(assertion)
}

fn parse_single_object(
    object: &serde_json::Map<String, Value>,
    original: &Value,
) -> Result<Option<ParsedReport>, ConnectorError> {
    // Detect completely unrecognized shapes: no known key at all.
    let has_known = object.keys().any(|key| KNOWN_NATIVE_KEYS.contains(&key.as_str()));
    if !has_known {
        return Ok(None);
    }

    let channel = match object.get("channel") {
        None => None,
        Some(Value::String(text)) => {
            if !CHANNELS.contains(&text.as_str()) {
                return Err(native_protocol(format!(
                    "native channel {text:?} must be one of [{}]",
                    CHANNELS.join(", ")
                )));
            }
            Some(text.clone())
        }
        Some(_) => {
            return Err(native_protocol("native channel must be a string"));
        }
    };

    let native_run_id = parse_maybe_string_field(object, "native_run_id")?;
    let native_message_id = parse_maybe_string_field(object, "native_message_id")?;

    let scope_hint = match object.get("scope") {
        None => None,
        Some(Value::String(text)) => {
            if !SCOPES.contains(&text.as_str()) {
                return Err(native_protocol(format!(
                    "native scope {text:?} must be one of [{}]",
                    SCOPES.join(", ")
                )));
            }
            Some(text.clone())
        }
        Some(Value::Null) => None,
        Some(_) => return Err(native_protocol("native scope must be a string")),
    };

    let primitive = match object.get("primitive") {
        None => None,
        Some(Value::String(text)) => {
            if text.is_empty() {
                return Err(native_protocol("native primitive must be nonempty"));
            }
            Some(text.clone())
        }
        Some(Value::Null) => None,
        Some(_) => return Err(native_protocol("native primitive must be a string")),
    };

    // state/status: explicit native lifecycle statement, if any.
    let mut state_hint: Option<String> = None;
    for key in ["state", "status"] {
        if let Some(value) = object.get(key) {
            match value {
                Value::String(text) => {
                    if ClaimState::parse_native(text).is_none() {
                        return Err(native_protocol(format!(
                            "native {key} {text:?} is not a lifecycle state"
                        )));
                    }
                    if let Some(previous) = &state_hint {
                        if previous != text {
                            return Err(native_protocol(format!(
                                "native state/status conflict: {previous:?} versus {text:?}; conflicting reports must be separate entries, not one object"
                            )));
                        }
                    } else {
                        state_hint = Some(text.clone());
                    }
                }
                Value::Null => {}
                Value::Object(map) if map.get("value") == Some(&Value::Null) => {}
                _ => {
                    return Err(native_protocol(format!(
                        "native {key} must be a lifecycle state string"
                    )))
                }
            }
        }
    }

    let is_ack = matches!(object.get("ack"), Some(Value::Bool(true)))
        || matches!(object.get("acknowledged"), Some(Value::Bool(true)))
        || matches!(object.get("type"), Some(Value::String(text)) if text == "acknowledgement");

    // Unit/None detection: explicit null result with no lifecycle/primitive/scope content.
    let result_is_null = matches!(object.get("result"), Some(Value::Null));
    let has_content = state_hint.is_some()
        || primitive.is_some()
        || scope_hint.is_some()
        || is_ack
        || object.contains_key("application_assertions");
    let is_unit = result_is_null && !has_content;

    let (application_assertions, had_explicit_assertions) = match object.get("application_assertions") {
        None => (Vec::new(), false),
        Some(Value::Array(items)) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(parse_commitment_assertion(item)?);
            }
            let had = !out.is_empty();
            (out, had)
        }
        Some(_) => {
            return Err(native_protocol(
                "native application_assertions must be an array",
            ))
        }
    };

    let made_at = parse_made_at(object)?;
    let evidence_available = parse_evidence_available(object)?;

    let mut parse_limitations = Vec::new();
    if channel.is_none() {
        parse_limitations.push(
            "native channel not declared; defaulted to terminal_response for retention only"
                .to_string(),
        );
    }
    // Preserve the exact original for debugging without promoting it.
    let _ = original;

    Ok(Some(ParsedReport {
        channel,
        native_run_id,
        native_message_id,
        scope_hint,
        primitive,
        state_hint,
        is_unit,
        is_ack,
        application_assertions,
        made_at,
        evidence_available,
        parse_limitations,
        had_explicit_assertions,
    }))
}

enum NativeBody {
    Unit,
    Reports(Vec<ParsedReport>),
    Unsupported(String),
}

fn parse_native_body(bytes: &[u8]) -> Result<(NativeBody, String), ConnectorError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|error| native_protocol(format!("raw native body is not UTF-8: {error}")))?;
    if text.trim().is_empty() {
        return Err(native_protocol("raw native body is empty"));
    }
    let value: Value = serde_json::from_str(text)
        .map_err(|error| native_protocol(format!("raw native body is not JSON: {error}")))?;
    // Bare JSON null is the native Unit/None value.
    if value.is_null() {
        return Ok((NativeBody::Unit, "terminal_response".to_string()));
    }
    // Scalar native returns (number/string/bool) are primitive values.
    if value.is_number() || value.is_string() || value.is_boolean() {
        let report = ParsedReport {
            channel: None,
            native_run_id: MaybeString::Missing(Missing::new("not_observed")),
            native_message_id: MaybeString::Missing(Missing::new("not_observed")),
            scope_hint: Some("primitive".to_string()),
            primitive: Some("native_scalar".to_string()),
            state_hint: None,
            is_unit: false,
            is_ack: false,
            application_assertions: Vec::new(),
            made_at: MaybeTimePoint::Missing(Missing::new("not_observed")),
            evidence_available: None,
            parse_limitations: vec![
                "native scalar return preserved as primitive scope; no lifecycle or application statement inferred".to_string(),
                "native channel not declared; defaulted to terminal_response for retention only".to_string(),
            ],
            had_explicit_assertions: false,
        };
        return Ok((NativeBody::Reports(vec![report]), "terminal_response".to_string()));
    }
    if let Some(array) = value.as_array() {
        if array.is_empty() {
            return Ok((
                NativeBody::Unsupported("native batch contains zero reports".to_string()),
                "terminal_response".to_string(),
            ));
        }
        let mut reports = Vec::with_capacity(array.len());
        let mut unsupported = 0usize;
        for item in array {
            if item.is_null() {
                // Null entries inside a batch are Unit entries: unknown scope each.
                reports.push(ParsedReport {
                    channel: None,
                    native_run_id: MaybeString::Missing(Missing::new("not_observed")),
                    native_message_id: MaybeString::Missing(Missing::new("not_observed")),
                    scope_hint: None,
                    primitive: None,
                    state_hint: None,
                    is_unit: true,
                    is_ack: false,
                    application_assertions: Vec::new(),
                    made_at: MaybeTimePoint::Missing(Missing::new("not_observed")),
                    evidence_available: None,
                    parse_limitations: vec![
                        "native channel not declared; defaulted to terminal_response for retention only".to_string(),
                    ],
                    had_explicit_assertions: false,
                });
                continue;
            }
            let object = item.as_object().ok_or_else(|| {
                native_protocol("native batch entries must be objects or null")
            })?;
            match parse_single_object(object, item)? {
                Some(report) => reports.push(report),
                None => unsupported += 1,
            }
        }
        if reports.is_empty() {
            return Ok((
                NativeBody::Unsupported(format!(
                    "unsupported_native_shape: all {unsupported} batch entries are unrecognized"
                )),
                "terminal_response".to_string(),
            ));
        }
        let channel = effective_channel(&reports);
        if unsupported > 0 {
            // Keep the recognized reports; the caller records the skipped count.
            return Ok((NativeBody::Reports(reports), channel));
        }
        return Ok((NativeBody::Reports(reports), channel));
    }
    let object = value.as_object().ok_or_else(|| {
        native_protocol("raw native body must be an object, array, null, or scalar")
    })?;
    // Batch wrapper: {"reports": [...]}.
    if let Some(wrapped) = object.get("reports") {
        let array = wrapped.as_array().ok_or_else(|| {
            native_protocol("native reports wrapper must be an array")
        })?;
        if array.is_empty() {
            return Ok((
                NativeBody::Unsupported("native batch contains zero reports".to_string()),
                "terminal_response".to_string(),
            ));
        }
        let mut reports = Vec::with_capacity(array.len());
        let mut unsupported = 0usize;
        for item in array {
            if item.is_null() {
                reports.push(ParsedReport {
                    channel: None,
                    native_run_id: MaybeString::Missing(Missing::new("not_observed")),
                    native_message_id: MaybeString::Missing(Missing::new("not_observed")),
                    scope_hint: None,
                    primitive: None,
                    state_hint: None,
                    is_unit: true,
                    is_ack: false,
                    application_assertions: Vec::new(),
                    made_at: MaybeTimePoint::Missing(Missing::new("not_observed")),
                    evidence_available: None,
                    parse_limitations: vec![
                        "native channel not declared; defaulted to terminal_response for retention only".to_string(),
                    ],
                    had_explicit_assertions: false,
                });
                continue;
            }
            let inner = item.as_object().ok_or_else(|| {
                native_protocol("native batch entries must be objects or null")
            })?;
            match parse_single_object(inner, item)? {
                Some(report) => reports.push(report),
                None => unsupported += 1,
            }
        }
        if reports.is_empty() {
            return Ok((
                NativeBody::Unsupported(format!(
                    "unsupported_native_shape: all {unsupported} batch entries are unrecognized"
                )),
                "terminal_response".to_string(),
            ));
        }
        let channel = effective_channel(&reports);
        return Ok((NativeBody::Reports(reports), channel));
    }
    match parse_single_object(object, &value)? {
        None => Ok((
            NativeBody::Unsupported(
                "unsupported_native_shape: object carries no recognized native field".to_string(),
            ),
            "terminal_response".to_string(),
        )),
        Some(report) => {
            let channel = report.channel.clone().unwrap_or_else(|| "terminal_response".to_string());
            Ok((NativeBody::Reports(vec![report]), channel))
        }
    }
}

fn effective_channel(reports: &[ParsedReport]) -> String {
    reports
        .first()
        .and_then(|first| first.channel.clone())
        .unwrap_or_else(|| "terminal_response".to_string())
}

fn check_batch_channels(reports: &[ParsedReport]) -> Result<String, ConnectorError> {
    let mut declared: BTreeSet<String> = BTreeSet::new();
    for report in reports {
        if let Some(channel) = &report.channel {
            declared.insert(channel.clone());
        }
    }
    if declared.len() > 1 {
        let list: Vec<String> = declared.into_iter().collect();
        return Err(invalid(format!(
            "batch reports declare conflicting native channels [{}]; one observation carries one channel",
            list.join(", ")
        )));
    }
    Ok(effective_channel(reports))
}

// ---------------------------------------------------------------------------
// Claim construction
// ---------------------------------------------------------------------------

fn claim_id_for(raw: &ArtifactReference, index: usize) -> String {
    let digest = raw.digest.as_str();
    let short = digest
        .strip_prefix("sha256:")
        .map(|rest| rest.get(..16).unwrap_or(rest))
        .unwrap_or("nodigest");
    format!("claim-{short}-{index}")
}

#[allow(clippy::too_many_arguments)]
fn build_claim(
    raw: &ArtifactReference,
    source_event: &EvidenceRef,
    checks: &SourceChecks,
    mapping: &VersionPin,
    received_at: &TimePoint,
    report: &ParsedReport,
    index: usize,
    trace_alternate: bool,
) -> ExecutionClaim {
    // Scope resolution.
    let scope = if report.is_unit {
        "unknown".to_string()
    } else if report.primitive.is_some() || report.scope_hint.as_deref() == Some("primitive") {
        "primitive".to_string()
    } else if report.is_ack && report.state_hint.is_none() && report.scope_hint.is_none() {
        "unknown".to_string()
    } else if let Some(hint) = &report.scope_hint {
        hint.clone()
    } else if report.state_hint.is_some() {
        "execution_lifecycle".to_string()
    } else if !report.application_assertions.is_empty() {
        "application_postcondition".to_string()
    } else {
        "unknown".to_string()
    };

    // State resolution: absent statements stay Missing, never invented strings.
    let state = if scope == "primitive" {
        ClaimState::Missing(Missing::new("not_applicable"))
    } else if scope == "unknown" {
        if report.is_unit {
            ClaimState::Missing(Missing::with_detail(
                "not_observed",
                "native Unit/None carries no lifecycle statement",
            ))
        } else if report.is_ack {
            ClaimState::Missing(Missing::with_detail(
                "not_observed",
                "protocol acknowledgement carries no lifecycle statement",
            ))
        } else {
            ClaimState::Missing(Missing::with_detail(
                "not_observed",
                "no native lifecycle statement; not invented",
            ))
        }
    } else if let Some(hint) = &report.state_hint {
        ClaimState::parse_native(hint).unwrap_or_else(|| {
            ClaimState::Missing(Missing::with_detail(
                "not_observed",
                "no native lifecycle statement; not invented",
            ))
        })
    } else {
        ClaimState::Missing(Missing::with_detail(
            "not_observed",
            "no native lifecycle statement; not invented",
        ))
    };

    // Application assertions: only explicit source assertions, and never for
    // primitive/unknown scopes.
    let mut limitations: Vec<String> = report.parse_limitations.clone();
    let application_assertions = if scope == "primitive" || scope == "unknown" {
        if report.had_explicit_assertions {
            limitations.push(format!(
                "{} scope carries no application assertions; explicit native assertions are not promoted",
                scope
            ));
        }
        Vec::new()
    } else {
        report.application_assertions.clone()
    };
    if report.is_unit {
        limitations.push("Unit/None is not success; no application assertion inferred".to_string());
    }
    if report.is_ack && scope == "unknown" {
        limitations.push(
            "protocol acknowledgement does not establish application commitment".to_string(),
        );
    }
    if scope == "primitive" {
        limitations.push(
            "primitive return is not lifecycle completion and not application commitment"
                .to_string(),
        );
        if let Some(name) = &report.primitive {
            limitations.push(format!("native primitive statement preserved: {name}"));
        }
    }
    if scope == "execution_lifecycle"
        && matches!(state, ClaimState::Completed)
        && application_assertions.is_empty()
    {
        limitations.push(
            "execution lifecycle completion does not imply application commitment".to_string(),
        );
    }
    if scope == "execution_lifecycle" && matches!(state, ClaimState::Stopped) {
        limitations.push("stopped does not imply no commitment".to_string());
    }
    if matches!(state, ClaimState::Missing(_)) && scope != "primitive" && scope != "unknown" {
        limitations.push("absent lifecycle state is Missing, not an invented unknown claim".to_string());
    }
    if trace_alternate {
        limitations.push(format!(
            "trace mismatch preserved; alternate correlation via matched_by [{}] with evidenced refs",
            checks.matched_by.join(", ")
        ));
    }

    let evidence_available_to_claimant = report
        .evidence_available
        .clone()
        .unwrap_or_else(|| checks.evidence_refs.clone());

    ExecutionClaim {
        claim_id: claim_id_for(raw, index),
        scope,
        state,
        application_assertions,
        native_run_id: report.native_run_id.clone(),
        native_message_id: report.native_message_id.clone(),
        native_report: raw.clone(),
        mapping: mapping.clone(),
        source_checks: checks.clone(),
        made_at: report.made_at.clone(),
        received_at: received_at.clone(),
        evidence_available_to_claimant,
        evidence_refs: vec![source_event.clone()],
        limitations,
    }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Normalizes one retained native report into faithful execution claims.
///
/// The caller supplies the exact retained `raw` bytes, the receipt
/// `source_event`, independently derived `checks`, and the normalization
/// `mapping` pin. The function authenticates the caller, validates the
/// handle structurally, loads the exact bytes, resolves the receipt and
/// every verification reference, gates on verified authentication plus
/// matched correlation (with explicit alternate evidence when the trace
/// mismatches), and maps the native body without inventing lifecycle or
/// application statements.
pub fn normalize_report(
    principal: &AuthenticatedPrincipal,
    handle: &ConnectorHandle,
    raw: &ArtifactReference,
    source_event: &EvidenceRef,
    checks: &SourceChecks,
    mapping: &VersionPin,
) -> Result<NativeReportObservation, ConnectorError> {
    // 1. Structural validation of every caller-supplied shape.
    validate_handle(handle)?;
    raw.validate()
        .map_err(|error| invalid(format!("raw artifact reference is invalid: {}", error.detail)))?;
    source_event.validate().map_err(|error| {
        invalid(format!("source_event reference is invalid: {}", error.detail))
    })?;
    validate_source_checks(checks)?;
    validate_version_pin(mapping, "mapping")?;
    mapping_pin_supported(mapping)?;

    // 2. Authority: the execution writer owns native_report publication.
    //    This also rejects unauthenticated channel identities.
    rm_authority::authorize_owner(principal, "execution", "native_report")?;
    // The connector descriptor is the declared translation context: reading it
    // binds normalization to the actually configured connector without probing.
    let _descriptor = rm_catalog::describe(principal, &rm_catalog::DescribeRequest)?;

    // 3. Exact retained bytes precede any interpretation.
    let bytes = rm_evidence::load_artifact(principal, raw).map_err(|error| match error.code.as_str() {
        "NOT_FOUND" => prerequisite(format!("raw native bytes are not retained: {}", error.detail)),
        _ => error,
    })?;
    if bytes.len() as u64 != raw.size_bytes {
        return Err(connector_error(
            "INTEGRITY_CONFLICT",
            "connector",
            format!(
                "raw artifact size_bytes {} does not match retained {} bytes",
                raw.size_bytes,
                bytes.len()
            ),
        ));
    }
    if rm_wire::artifact_digest(&bytes) != raw.digest {
        return Err(connector_error(
            "INTEGRITY_CONFLICT",
            "connector",
            "raw artifact digest does not match the retained bytes",
        ));
    }

    // 4. The receipt and every verification reference must be retained.
    //    The handle binds the journal; the source receipt must live there.
    if handle.journal_id != source_event.journal_id {
        return Err(invalid(format!(
            "handle journal {:?} does not match source_event journal {:?}",
            handle.journal_id, source_event.journal_id
        )));
    }
    let prefix = rm_evidence::journal_head(principal, &source_event.journal_id).map_err(|error| {
        prerequisite(format!(
            "source journal {:?} has no retained prefix: {}",
            source_event.journal_id, error.detail
        ))
    })?;
    let source_envelope =
        rm_evidence::resolve_evidence(principal, source_event, &prefix).map_err(|error| {
            prerequisite(format!("source_event is not retained: {}", error.detail))
        })?;
    for (index, reference) in checks.evidence_refs.iter().enumerate() {
        let evidence_prefix =
            rm_evidence::journal_head(principal, &reference.journal_id).map_err(|error| {
                invalid(format!(
                    "source_checks evidence_refs[{index}] journal {:?} has no retained prefix: {}",
                    reference.journal_id, error.detail
                ))
            })?;
        rm_evidence::resolve_evidence(principal, reference, &evidence_prefix).map_err(|error| {
            invalid(format!(
                "source_checks evidence_refs[{index}] is not retained verification evidence: {}",
                error.detail
            ))
        })?;
    }

    // 5. Gating: unverified or uncorrelated reports have no accepted claims.
    //    Serialized verified/matched labels without resolved evidence never
    //    pass this gate (evidence was resolved above).
    if !is_accepted_checks(checks) {
        let observation = NativeReportObservation {
            kind: "native_report".to_string(),
            channel: "terminal_response".to_string(),
            raw: raw.clone(),
            source_event: source_event.clone(),
            source_checks: checks.clone(),
            mapping: mapping.clone(),
            normalized_claims: Vec::new(),
            limitations: vec![
                "unverified or uncorrelated report preserved as receipt evidence; no accepted normalized claims".to_string(),
                format!(
                    "authentication is {:?} and correlation is {:?}; authentication and correlation are independent",
                    checks.authentication, checks.correlation
                ),
            ],
        };
        validate_observation(&observation)?;
        return Ok(observation);
    }
    let trace_alternate = checks.trace_correlation == "mismatched";
    if trace_alternate && !has_proven_alternate_correlation(checks) {
        let observation = NativeReportObservation {
            kind: "native_report".to_string(),
            channel: "terminal_response".to_string(),
            raw: raw.clone(),
            source_event: source_event.clone(),
            source_checks: checks.clone(),
            mapping: mapping.clone(),
            normalized_claims: Vec::new(),
            limitations: vec![
                "trace mismatch without proven alternate correlation; no accepted normalized claims".to_string(),
                "alternate correlation despite trace mismatch must be explicit (matched_by) and evidenced".to_string(),
            ],
        };
        validate_observation(&observation)?;
        return Ok(observation);
    }

    // 6. Interpret the exact native bytes. Malformed bytes are an honestly
    //    scoped connector-operation failure, never a fabricated subject claim.
    //    Observed native failure remains normal evidence below.
    let (body, _default_channel) = parse_native_body(&bytes)?;
    match body {
        NativeBody::Unsupported(detail) => {
            let observation = NativeReportObservation {
                kind: "native_report".to_string(),
                channel: "terminal_response".to_string(),
                raw: raw.clone(),
                source_event: source_event.clone(),
                source_checks: checks.clone(),
                mapping: mapping.clone(),
                normalized_claims: Vec::new(),
                limitations: vec![
                    detail,
                    "empty claims mean no accepted interpreted claim, not native absence or success".to_string(),
                ],
            };
            validate_observation(&observation)?;
            return Ok(observation);
        }
        NativeBody::Unit => {
            let report = ParsedReport {
                channel: None,
                native_run_id: MaybeString::Missing(Missing::new("not_observed")),
                native_message_id: MaybeString::Missing(Missing::new("not_observed")),
                scope_hint: None,
                primitive: None,
                state_hint: None,
                is_unit: true,
                is_ack: false,
                application_assertions: Vec::new(),
                made_at: MaybeTimePoint::Missing(Missing::new("not_observed")),
                evidence_available: None,
                parse_limitations: vec![
                    "native channel not declared; defaulted to terminal_response for retention only".to_string(),
                ],
                had_explicit_assertions: false,
            };
            let claim = build_claim(
                raw,
                source_event,
                checks,
                mapping,
                &source_envelope.recorded_at,
                &report,
                0,
                trace_alternate,
            );
            validate_execution_claim(&claim)?;
            let observation = NativeReportObservation {
                kind: "native_report".to_string(),
                channel: "terminal_response".to_string(),
                raw: raw.clone(),
                source_event: source_event.clone(),
                source_checks: checks.clone(),
                mapping: mapping.clone(),
                normalized_claims: vec![claim],
                limitations: if trace_alternate {
                    vec!["trace mismatch preserved; alternate correlation evidenced".to_string()]
                } else {
                    Vec::new()
                },
            };
            validate_observation(&observation)?;
            return Ok(observation);
        }
        NativeBody::Reports(reports) => {
            let channel = check_batch_channels(&reports)?;
            let mut claims = Vec::with_capacity(reports.len());
            for (index, report) in reports.iter().enumerate() {
                let claim = build_claim(
                    raw,
                    source_event,
                    checks,
                    mapping,
                    &source_envelope.recorded_at,
                    report,
                    index,
                    trace_alternate,
                );
                validate_execution_claim(&claim)?;
                claims.push(claim);
            }
            // Conflicting claims append without replacement: distinct identities
            // were assigned per index and validated above.
            let mut limitations = Vec::new();
            if trace_alternate {
                limitations.push("trace mismatch preserved; alternate correlation evidenced".to_string());
            }
            // Surface channel defaulting once at the observation level.
            if reports.iter().any(|report| report.channel.is_none()) {
                limitations.push(
                    "one or more batch entries omit native channel; defaulted to terminal_response for retention only".to_string(),
                );
            }
            let observation = NativeReportObservation {
                kind: "native_report".to_string(),
                channel,
                raw: raw.clone(),
                source_event: source_event.clone(),
                source_checks: checks.clone(),
                mapping: mapping.clone(),
                normalized_claims: claims,
                limitations,
            };
            validate_observation(&observation)?;
            return Ok(observation);
        }
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn gating_helpers_separate_auth_and_correlation() {
        let pin = VersionPin {
            id: "verifier".to_string(),
            version: "v1".to_string(),
            artifact_digest: rm_wire::artifact_digest(b"verifier"),
        };
        let reference = EvidenceRef {
            journal_id: "journal-x".to_string(),
            sequence: rm_evidence::PositiveInteger::new(1).expect("seq"),
            event_id: "event-x".to_string(),
            event_hash: rm_wire::artifact_digest(b"x"),
            pointer: String::new(),
        };
        let verified_matched = SourceChecks {
            authentication: "verified".to_string(),
            correlation: "matched".to_string(),
            trace_correlation: "matched".to_string(),
            verification_policy: pin.clone(),
            matched_by: vec!["trace-1".to_string()],
            evidence_refs: vec![reference.clone()],
        };
        assert!(is_accepted_checks(&verified_matched));
        assert!(has_proven_alternate_correlation(&verified_matched));

        let verified_mismatched = SourceChecks {
            correlation: "mismatched".to_string(),
            ..verified_matched.clone()
        };
        assert!(!is_accepted_checks(&verified_mismatched));

        let unknown_matched = SourceChecks {
            authentication: "unknown".to_string(),
            ..verified_matched.clone()
        };
        assert!(!is_accepted_checks(&unknown_matched));

        let bare_alternate = SourceChecks {
            trace_correlation: "mismatched".to_string(),
            matched_by: Vec::new(),
            ..verified_matched.clone()
        };
        assert!(!has_proven_alternate_correlation(&bare_alternate));
    }

    #[test]
    fn claim_state_parses_native_statements() {
        for state in STATES {
            assert!(ClaimState::parse_native(state).is_some());
        }
        assert!(ClaimState::parse_native("bogus").is_none());
        assert!(ClaimState::Missing(Missing::new("not_observed")).as_str().is_none());
    }
}

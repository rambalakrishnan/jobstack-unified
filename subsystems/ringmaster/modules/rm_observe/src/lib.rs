//! `rm_observe`: tier-3 connector observation pagination over the evidence journal.
//!
//! Implements the Observe read path (`external-connector/0.1.0` §Observe,
//! seam mapping §14, EXT-OBSERVE / EXT-EVIDENCE / EXT-BOUNDS):
//!
//! - [`observe`] returns registered connector observation projections in
//!   journal order for exactly the requested handle, scanning every journal
//!   position (including non-projection events) from `after` to a pinned
//!   `through` cutoff (RM-C45).
//! - The cursor names the last *scanned* position, never the last returned
//!   item. `has_more` is exactly whether that position precedes the cutoff.
//! - A fixed `through` prefix is echoed unchanged and requires zero wait; an
//!   inapplicable `through` pins a new live cutoff from [`journal_head`].
//! - A single observation item that cannot fit the response bound is an
//!   explicit [`RESPONSE_TOO_LARGE`] error, never a silent drop (RM-C46).
//!   The server may return fewer items to honor the bound.
//! - Observation items copy already journaled, registry-validated
//!   projections: metadata matches the referenced envelope, provenance is
//!   copied (never assigned), and only the eight registered payload kinds
//!   are projected.
//!
//! The module performs no writes: it only reads via `rm_evidence` and
//! enforces finite call/observation bounds. An empty page at the cutoff, a
//! closed transport, or cutoff exhaustion never implies native termination.

#![forbid(unsafe_code)]
#![allow(clippy::result_large_err)]

use serde_json::{json, Value};

pub use rm_authority::{AuthenticatedPrincipal, ConnectorError};
pub use rm_evidence::{
    ArtifactReference, EvidenceRef, JournalEnvelope, JournalPrefix, MaybeDigest, PositiveInteger,
};
pub use rm_time::{ClockDescriptor, Measurement, Missing, TimePoint};
pub use rm_wire::Digest;

// ---------------------------------------------------------------------------
// Bounds
// ---------------------------------------------------------------------------

/// Largest integer representable without precision loss (§3.1).
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Configured response-byte bound for a single [`ObservationPage`].
///
/// The bound covers the serialized observation items. A single item that
/// alone exceeds the bound is an explicit `RESPONSE_TOO_LARGE` error
/// (RM-C46); otherwise the server returns fewer items with a disclosed
/// limitation.
pub const MAX_RESPONSE_BYTES: usize = 8 * 1024;

/// Configured upper bound for `max_items` in one request.
pub const MAX_OBSERVE_ITEMS: u64 = 100;

/// Configured upper bound for `wait_limit` on a live cutoff request (ms).
pub const MAX_CALL_WAIT_MS: f64 = 5_000.0;

/// Overhead estimate (bytes) for the page envelope around items.
const PAGE_OVERHEAD_BYTES: usize = 512;

// ---------------------------------------------------------------------------
// Connector errors (§17 envelope)
// ---------------------------------------------------------------------------

fn connector_error(
    code: &str,
    fault_domain: &str,
    detail: impl Into<String>,
) -> ConnectorError {
    ConnectorError {
        kind: "connector_error".to_string(),
        code: code.to_string(),
        fault_domain: fault_domain.to_string(),
        detail: detail.into(),
        // Observe is a read: no dispatch is attempted.
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

fn cursor_invalid(detail: impl Into<String>) -> ConnectorError {
    connector_error("CURSOR_INVALID", "request", detail)
}

fn cursor_unavailable(detail: impl Into<String>) -> ConnectorError {
    connector_error("CURSOR_UNAVAILABLE", "connector", detail)
}

fn response_too_large(detail: impl Into<String>) -> ConnectorError {
    connector_error("RESPONSE_TOO_LARGE", "connector", detail)
}

fn budget_exceeded(detail: impl Into<String>) -> ConnectorError {
    connector_error("BUDGET_EXCEEDED", "policy", detail)
}

fn integrity(detail: impl Into<String>) -> ConnectorError {
    connector_error("INTEGRITY_CONFLICT", "connector", detail)
}

/// Maps `rm_evidence` read failures to explicit Observe errors.
///
/// Retained-history lookups that miss are never skipped: they surface as
/// `CURSOR_UNAVAILABLE` with the underlying detail preserved.
fn map_read_error(err: ConnectorError, context: &str) -> ConnectorError {
    match err.code.as_str() {
        "NOT_FOUND" => cursor_unavailable(format!("{context}: {}", err.detail)),
        "UNAUTHENTICATED" | "FORBIDDEN" | "INVALID_REQUEST" | "INTEGRITY_INCIDENT" => err,
        _ => err,
    }
}

fn require_identifier(field: &str, value: &str) -> Result<(), ConnectorError> {
    if value.is_empty() {
        return Err(invalid(format!("{field} must be nonempty")));
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

// ---------------------------------------------------------------------------
// Handle, cursor, request
// ---------------------------------------------------------------------------

/// Stable local handle identity (not a native run ID or credential).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandleReference {
    pub connector_id: String,
    pub local_handle: String,
}

impl HandleReference {
    pub fn validate(&self) -> Result<(), ConnectorError> {
        require_identifier("handle.connector_id", &self.connector_id)?;
        require_identifier("handle.local_handle", &self.local_handle)?;
        Ok(())
    }

    pub fn to_json(&self) -> Value {
        json!({
            "connector_id": self.connector_id,
            "local_handle": self.local_handle,
        })
    }
}

/// Scanned journal position, including positions holding non-projection events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservationCursor {
    pub handle: HandleReference,
    pub journal_id: String,
    /// Revision `0..=MAX_SAFE_INTEGER`. Zero starts scanning before admission.
    pub sequence: u64,
    /// Inapplicable at zero; the retained event hash at positive positions.
    pub event_hash: MaybeDigest,
}

impl ObservationCursor {
    pub fn validate(&self) -> Result<(), ConnectorError> {
        self.handle.validate()?;
        require_identifier("cursor.journal_id", &self.journal_id)?;
        if self.sequence > MAX_SAFE_INTEGER {
            return Err(cursor_invalid(format!(
                "cursor sequence {} exceeds {MAX_SAFE_INTEGER}",
                self.sequence
            )));
        }
        match &self.event_hash {
            MaybeDigest::Missing(missing) => {
                if self.sequence != 0 {
                    return Err(cursor_invalid(
                        "cursor with missing event_hash must use sequence 0",
                    ));
                }
                validate_missing(missing, "cursor.event_hash")?;
                if missing.reason != "not_applicable" {
                    return Err(cursor_invalid(
                        "sequence-zero cursor event_hash must be not_applicable",
                    ));
                }
            }
            MaybeDigest::Present(digest) => {
                if self.sequence == 0 {
                    return Err(cursor_invalid(
                        "sequence-zero cursor must use inapplicable event_hash",
                    ));
                }
                if !rm_wire::is_valid_digest(digest.as_str()) {
                    return Err(cursor_invalid(format!(
                        "cursor event_hash {:?} is not a sha256 digest",
                        digest.as_str()
                    )));
                }
            }
        }
        Ok(())
    }

    pub fn to_json(&self) -> Value {
        let event_hash = match &self.event_hash {
            MaybeDigest::Present(digest) => Value::String(digest.as_str().to_string()),
            MaybeDigest::Missing(missing) => missing_json(missing),
        };
        json!({
            "handle": self.handle.to_json(),
            "journal_id": self.journal_id,
            "sequence": self.sequence,
            "event_hash": event_hash,
        })
    }
}

/// Requested cutoff: a frozen prefix or a live-cutoff request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Through {
    /// Frozen prefix; pagination continuations reuse exactly this cutoff.
    Prefix(JournalPrefix),
    /// Inapplicable missingness requests a new live cutoff.
    Live(Missing),
}

impl Through {
    fn validate(&self) -> Result<(), ConnectorError> {
        match self {
            Through::Prefix(prefix) => {
                require_identifier("through.journal_id", &prefix.journal_id)?;
                if !rm_wire::is_valid_digest(prefix.head_hash.as_str()) {
                    return Err(invalid("through.head_hash is not a sha256 digest"));
                }
            }
            Through::Live(missing) => {
                validate_missing(missing, "through")?;
                if missing.reason != "not_applicable" {
                    return Err(invalid(
                        "live through must be not_applicable missingness",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Finite configured wait allowance (not a measurement).
#[derive(Debug, Clone, PartialEq)]
pub struct DurationLimit {
    pub kind: String,
    pub unit: String,
    pub value: f64,
}

impl DurationLimit {
    pub fn validate(&self) -> Result<(), ConnectorError> {
        if self.kind != "exact" {
            return Err(invalid("wait_limit.kind must be \"exact\""));
        }
        if self.unit != "ms" {
            return Err(invalid("wait_limit.unit must be \"ms\""));
        }
        if !self.value.is_finite() || self.value < 0.0 {
            return Err(invalid("wait_limit.value must be finite and nonnegative"));
        }
        Ok(())
    }
}

/// Observe request: handle, scanned-after cursor, cutoff, bounds.
#[derive(Debug, Clone, PartialEq)]
pub struct ObserveRequest {
    pub handle: HandleReference,
    pub after: ObservationCursor,
    pub through: Through,
    pub max_items: PositiveInteger,
    pub wait_limit: DurationLimit,
}

impl ObserveRequest {
    fn validate(&self) -> Result<(), ConnectorError> {
        self.handle.validate()?;
        self.after.validate()?;
        self.through.validate()?;
        self.wait_limit.validate()?;
        if self.after.handle != self.handle {
            return Err(cursor_invalid(
                "handle and after cursor must agree on the requested handle",
            ));
        }
        match &self.through {
            Through::Prefix(prefix) => {
                if prefix.journal_id != self.after.journal_id {
                    return Err(cursor_invalid(
                        "through journal must agree with the after cursor journal",
                    ));
                }
                if self.wait_limit.value != 0.0 {
                    return Err(invalid(
                        "a fixed through prefix requires wait_limit.value=0",
                    ));
                }
            }
            Through::Live(_) => {
                if self.wait_limit.value > MAX_CALL_WAIT_MS {
                    return Err(budget_exceeded(format!(
                        "wait_limit {}ms exceeds the call bound {MAX_CALL_WAIT_MS}ms",
                        self.wait_limit.value
                    )));
                }
            }
        }
        if self.max_items.get() > MAX_OBSERVE_ITEMS {
            return Err(budget_exceeded(format!(
                "max_items {} exceeds the descriptor bound {MAX_OBSERVE_ITEMS}",
                self.max_items.get()
            )));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Observation projection types
// ---------------------------------------------------------------------------

/// Locally observed closure at the cutoff, or reasoned absence.
///
/// Never implies native termination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaybeEvidenceRef {
    Present(EvidenceRef),
    Missing(Missing),
}

impl MaybeEvidenceRef {
    /// Closed JSON projection (used for page serialization).
    pub fn to_json(&self) -> Value {
        match self {
            MaybeEvidenceRef::Present(reference) => reference.to_json(),
            MaybeEvidenceRef::Missing(missing) => missing_json(missing),
        }
    }
}

/// A journaled measurement with its supporting evidence.
#[derive(Debug, Clone, PartialEq)]
pub struct MeasurementEvidence {
    pub measurement: Measurement,
    pub evidence_refs: Vec<EvidenceRef>,
}

impl MeasurementEvidence {
    fn to_json(&self) -> Result<Value, ConnectorError> {
        let measurement = serde_json::to_value(&self.measurement)
            .map_err(|error| invalid(format!("measurement cannot be serialized: {error}")))?;
        Ok(json!({
            "measurement": measurement,
            "evidence_refs": self.evidence_refs.iter().map(EvidenceRef::to_json).collect::<Vec<Value>>(),
        }))
    }
}

/// The eight registered connector observation payloads (§14.3).
///
/// Primitive records and reductions are registered artifacts, never
/// undeclared variants here.
#[derive(Debug, Clone, PartialEq)]
pub enum ObservationPayload {
    NativeReport(Value),
    ContextObservation(Value),
    TaskOutput(Value),
    ConnectorIncident(Value),
    ControlObservation(Value),
    LifecyclePublication(Value),
    ArtifactAvailable(Value),
    ClockRegistered(ClockDescriptor),
}

impl ObservationPayload {
    /// Exact payload discriminator.
    pub fn kind(&self) -> &'static str {
        match self {
            ObservationPayload::NativeReport(_) => "native_report",
            ObservationPayload::ContextObservation(_) => "context_observation",
            ObservationPayload::TaskOutput(_) => "task_output",
            ObservationPayload::ConnectorIncident(_) => "connector_incident",
            ObservationPayload::ControlObservation(_) => "control_observation",
            ObservationPayload::LifecyclePublication(_) => "lifecycle_publication",
            ObservationPayload::ArtifactAvailable(_) => "artifact_available",
            ObservationPayload::ClockRegistered(_) => "clock_registered",
        }
    }

    /// Closed JSON projection of the payload.
    pub fn to_json(&self) -> Result<Value, ConnectorError> {
        match self {
            ObservationPayload::ClockRegistered(descriptor) => {
                let clock = serde_json::to_value(descriptor)
                    .map_err(|error| invalid(format!("clock cannot be serialized: {error}")))?;
                Ok(json!({ "kind": "clock_registered", "clock": clock }))
            }
            ObservationPayload::NativeReport(data)
            | ObservationPayload::ContextObservation(data)
            | ObservationPayload::TaskOutput(data)
            | ObservationPayload::ConnectorIncident(data)
            | ObservationPayload::ControlObservation(data)
            | ObservationPayload::LifecyclePublication(data)
            | ObservationPayload::ArtifactAvailable(data) => Ok(data.clone()),
        }
    }
}

/// One copied journaled projection with matching metadata.
#[derive(Debug, Clone, PartialEq)]
pub struct ObservationItem {
    /// Points to the complete normalized event (`pointer == ""`).
    pub event_ref: EvidenceRef,
    pub recorded_at: TimePoint,
    /// Copied ingestion provenance; never reassigned.
    pub provenance: String,
    pub payload: ObservationPayload,
    pub measurements: Vec<MeasurementEvidence>,
    pub artifact_refs: Vec<ArtifactReference>,
}

impl ObservationItem {
    /// Journal sequence of the projected event.
    pub fn sequence(&self) -> u64 {
        self.event_ref.sequence.get()
    }

    fn to_json(&self) -> Result<Value, ConnectorError> {
        let recorded_at = serde_json::to_value(&self.recorded_at)
            .map_err(|error| invalid(format!("recorded_at cannot be serialized: {error}")))?;
        let mut measurements = Vec::with_capacity(self.measurements.len());
        for entry in &self.measurements {
            measurements.push(entry.to_json()?);
        }
        Ok(json!({
            "event_ref": self.event_ref.to_json(),
            "recorded_at": recorded_at,
            "provenance": self.provenance,
            "payload": self.payload.to_json()?,
            "measurements": measurements,
            "artifact_refs": self.artifact_refs.iter().map(ArtifactReference::to_json).collect::<Vec<Value>>(),
        }))
    }
}

/// One bounded observation page over a pinned cutoff.
#[derive(Debug, Clone, PartialEq)]
pub struct ObservationPage {
    pub kind: String,
    pub handle: HandleReference,
    pub after: ObservationCursor,
    pub through: JournalPrefix,
    /// Last scanned journal position, including non-projection events.
    pub next: ObservationCursor,
    /// Exactly whether `next` precedes the cutoff.
    pub has_more: bool,
    pub observation_close_ref: MaybeEvidenceRef,
    pub items: Vec<ObservationItem>,
    pub limitations: Vec<String>,
}

impl ObservationPage {
    /// Closed JSON projection of the page.
    pub fn to_json(&self) -> Result<Value, ConnectorError> {
        let mut items = Vec::with_capacity(self.items.len());
        for item in &self.items {
            items.push(item.to_json()?);
        }
        Ok(json!({
            "kind": self.kind,
            "handle": self.handle.to_json(),
            "after": self.after.to_json(),
            "through": self.through.to_json(),
            "next": self.next.to_json(),
            "has_more": self.has_more,
            "observation_close_ref": self.observation_close_ref.to_json(),
            "items": items,
            "limitations": self.limitations,
        }))
    }
}

// ---------------------------------------------------------------------------
// Projection rules (§14.3)
// ---------------------------------------------------------------------------

/// Returns true for the eight event kinds that project to connector observations.
pub fn is_projection_kind(event_kind: &str) -> bool {
    matches!(
        event_kind,
        "native_report"
            | "context_observation"
            | "task_output"
            | "connector_incident"
            | "control_observation"
            | "lifecycle_publication"
            | "artifact_available"
            | "clock_registered"
    )
}

fn require_fields(
    object: &serde_json::Map<String, Value>,
    event_kind: &str,
    required: &[&str],
) -> Result<(), ConnectorError> {
    for field in required {
        if !object.contains_key(*field) {
            return Err(integrity(format!(
                "{event_kind} payload is missing required field {field:?}"
            )));
        }
    }
    Ok(())
}

fn require_enum(
    object: &serde_json::Map<String, Value>,
    event_kind: &str,
    field: &str,
    allowed: &[&str],
) -> Result<(), ConnectorError> {
    match object.get(field).and_then(Value::as_str) {
        Some(value) if allowed.contains(&value) => Ok(()),
        Some(value) => Err(integrity(format!(
            "{event_kind} field {field:?} has unregistered value {value:?}"
        ))),
        None => Err(integrity(format!(
            "{event_kind} field {field:?} must be a registered string"
        ))),
    }
}

/// Validates journaled `payload.data` for a projection event kind and wraps it.
///
/// Clock registrations are journaled as a bare [`ClockDescriptor`] and are
/// wrapped into the `{kind, clock}` observation shape here; every other
/// projection kind is journaled in its observation shape with an exact `kind`.
fn validate_projection_payload(
    event_kind: &str,
    data: &Value,
) -> Result<ObservationPayload, ConnectorError> {
    if event_kind == "clock_registered" {
        let descriptor: ClockDescriptor = serde_json::from_value(data.clone()).map_err(|error| {
            integrity(format!("clock_registered payload must be a ClockDescriptor: {error}"))
        })?;
        if descriptor.clock_id.is_empty()
            || descriptor.boot_id.is_empty()
            || descriptor.source_id.is_empty()
        {
            return Err(integrity("clock_registered descriptor has empty identity"));
        }
        if descriptor.unit != "ms" {
            return Err(integrity("clock_registered descriptor unit must be ms"));
        }
        return Ok(ObservationPayload::ClockRegistered(descriptor));
    }
    let object = data
        .as_object()
        .ok_or_else(|| integrity(format!("{event_kind} payload must be an object")))?;
    match object.get("kind").and_then(Value::as_str) {
        Some(kind) if kind == event_kind => {}
        _ => {
            return Err(integrity(format!(
                "{event_kind} payload kind must exactly equal {event_kind:?}"
            )))
        }
    }
    match event_kind {
        "native_report" => {
            require_fields(
                object,
                event_kind,
                &[
                    "kind",
                    "channel",
                    "raw",
                    "source_event",
                    "source_checks",
                    "mapping",
                    "normalized_claims",
                    "limitations",
                ],
            )?;
            Ok(ObservationPayload::NativeReport(data.clone()))
        }
        "context_observation" => {
            require_fields(
                object,
                event_kind,
                &[
                    "kind",
                    "domain",
                    "requested_policy_ref",
                    "realization",
                    "context_ref",
                    "evidence_refs",
                    "limitations",
                ],
            )?;
            require_enum(object, event_kind, "domain", &["browser_state", "learning_state"])?;
            require_enum(
                object,
                event_kind,
                "realization",
                &[
                    "fresh",
                    "reused",
                    "frozen",
                    "subject_default",
                    "unavailable",
                    "unknown",
                ],
            )?;
            Ok(ObservationPayload::ContextObservation(data.clone()))
        }
        "task_output" => {
            require_fields(
                object,
                event_kind,
                &[
                    "kind",
                    "name",
                    "output_schema",
                    "content",
                    "completeness",
                    "evidence_refs",
                    "limitations",
                ],
            )?;
            require_enum(
                object,
                event_kind,
                "completeness",
                &["complete", "partial", "unknown"],
            )?;
            Ok(ObservationPayload::TaskOutput(data.clone()))
        }
        "connector_incident" => {
            require_fields(
                object,
                event_kind,
                &["kind", "code", "scope", "detail", "evidence_refs"],
            )?;
            require_enum(
                object,
                event_kind,
                "code",
                &[
                    "observation_lost",
                    "producer_gap",
                    "conflicting_message",
                    "malformed_native_body",
                    "unsupported_native_shape",
                    "trace_mismatch",
                    "storage_interruption",
                    "resource_unresolved",
                    "mapping_error",
                ],
            )?;
            Ok(ObservationPayload::ConnectorIncident(data.clone()))
        }
        "control_observation" => {
            require_fields(object, event_kind, &["kind", "observation"])?;
            Ok(ObservationPayload::ControlObservation(data.clone()))
        }
        "lifecycle_publication" => {
            require_fields(object, event_kind, &["kind", "publication"])?;
            Ok(ObservationPayload::LifecyclePublication(data.clone()))
        }
        "artifact_available" => {
            require_fields(object, event_kind, &["kind", "artifact"])?;
            Ok(ObservationPayload::ArtifactAvailable(data.clone()))
        }
        _ => Err(integrity(format!(
            "event kind {event_kind:?} is not a registered observation projection"
        ))),
    }
}

const PROVENANCES: [&str; 6] = [
    "server",
    "fixture_client",
    "connector",
    "subject",
    "manual_observer",
    "importer",
];

/// Copies one retained envelope into an observation item with matching metadata.
fn project_event(envelope: &JournalEnvelope) -> Result<ObservationItem, ConnectorError> {
    if !is_projection_kind(&envelope.event_kind) {
        return Err(integrity(format!(
            "event kind {:?} is not a registered observation projection",
            envelope.event_kind
        )));
    }
    let payload = validate_projection_payload(&envelope.event_kind, &envelope.payload.data)?;
    let event_ref = EvidenceRef {
        journal_id: envelope.journal_id.clone(),
        sequence: envelope.journal_sequence,
        event_id: envelope.event_id.clone(),
        event_hash: envelope.event_hash.clone(),
        pointer: String::new(),
    };
    event_ref.validate().map_err(|error| {
        integrity(format!("projected event_ref is invalid: {}", error.detail))
    })?;
    if !PROVENANCES.contains(&envelope.provenance.as_str()) {
        return Err(integrity(format!(
            "envelope provenance {:?} is not registered",
            envelope.provenance
        )));
    }
    let mut measurements = Vec::with_capacity(envelope.payload.measurements.len());
    for measurement in &envelope.payload.measurements {
        measurements.push(MeasurementEvidence {
            measurement: measurement.clone(),
            evidence_refs: vec![event_ref.clone()],
        });
    }
    for reference in &envelope.payload.artifact_refs {
        reference.validate().map_err(|error| {
            integrity(format!("projected artifact_ref is invalid: {}", error.detail))
        })?;
    }
    Ok(ObservationItem {
        event_ref,
        recorded_at: envelope.recorded_at.clone(),
        provenance: envelope.provenance.clone(),
        payload,
        measurements,
        artifact_refs: envelope.payload.artifact_refs.clone(),
    })
}

fn item_bytes(item: &ObservationItem) -> Result<usize, ConnectorError> {
    let json = item.to_json()?;
    serde_json::to_vec(&json)
        .map(|bytes| bytes.len())
        .map_err(|error| invalid(format!("observation item cannot be serialized: {error}")))
}

// ---------------------------------------------------------------------------
// Closure reference
// ---------------------------------------------------------------------------

/// Resolves the locally observed closure at the cutoff, if any.
///
/// Scans the full retained prefix up to the cutoff for the latest
/// `observation_closed` event. Absence is `not_observed` missingness, never
/// native termination.
fn observation_close_ref(
    principal: &AuthenticatedPrincipal,
    cutoff: &JournalPrefix,
) -> Result<MaybeEvidenceRef, ConnectorError> {
    let mut latest: Option<JournalEnvelope> = None;
    for sequence in 1..=cutoff.last_sequence.get() {
        let position = PositiveInteger::new(sequence)
            .map_err(|error| cursor_invalid(format!("cutoff sequence invalid: {}", error.detail)))?;
        let envelope = rm_evidence::read_event(principal, &cutoff.journal_id, position)
            .map_err(|error| map_read_error(error, "observation closure scan"))?;
        if envelope.event_kind == "observation_closed" {
            latest = Some(envelope);
        }
    }
    match latest {
        None => Ok(MaybeEvidenceRef::Missing(Missing::new("not_observed"))),
        Some(envelope) => {
            let reference = EvidenceRef {
                journal_id: envelope.journal_id.clone(),
                sequence: envelope.journal_sequence,
                event_id: envelope.event_id.clone(),
                event_hash: envelope.event_hash.clone(),
                pointer: String::new(),
            };
            // Verify the close reference against the pinned cutoff.
            rm_evidence::resolve_evidence(principal, &reference, cutoff)
                .map_err(|error| map_read_error(error, "observation closure reference"))?;
            Ok(MaybeEvidenceRef::Present(reference))
        }
    }
}

// ---------------------------------------------------------------------------
// Observe
// ---------------------------------------------------------------------------

/// Reads accumulated journal-backed observations through an explicit cutoff.
///
/// See the module documentation for the pagination, cutoff, cursor, and
/// size rules (RM-C45, RM-C46).
pub fn observe(
    principal: &AuthenticatedPrincipal,
    request: &ObserveRequest,
) -> Result<ObservationPage, ConnectorError> {
    request.validate()?;

    // Pin the cutoff. A fixed prefix is echoed unchanged; a live request pins
    // the current retained head.
    let cutoff: JournalPrefix = match &request.through {
        Through::Prefix(prefix) => {
            let live = rm_evidence::journal_head(principal, &prefix.journal_id)
                .map_err(|error| map_read_error(error, "fixed cutoff journal"))?;
            if live.journal_id != prefix.journal_id {
                return Err(cursor_invalid("fixed cutoff journal is not retained"));
            }
            if prefix.last_sequence.get() > live.last_sequence.get() {
                return Err(cursor_invalid(format!(
                    "fixed cutoff at sequence {} lies beyond the retained head at {}",
                    prefix.last_sequence.get(),
                    live.last_sequence.get()
                )));
            }
            let tip = rm_evidence::read_event(principal, &prefix.journal_id, prefix.last_sequence)
                .map_err(|error| map_read_error(error, "fixed cutoff head"))?;
            if tip.event_hash != prefix.head_hash {
                return Err(cursor_invalid(
                    "fixed cutoff head_hash does not match the retained event hash",
                ));
            }
            prefix.clone()
        }
        Through::Live(_) => rm_evidence::journal_head(principal, &request.after.journal_id)
            .map_err(|error| map_read_error(error, "live cutoff journal"))?,
    };
    if cutoff.journal_id != request.after.journal_id {
        return Err(cursor_invalid(
            "cutoff journal must agree with the after cursor journal",
        ));
    }

    // Verify the after cursor against the retained journal.
    let after_sequence = request.after.sequence;
    if after_sequence > cutoff.last_sequence.get() {
        return Err(cursor_invalid(format!(
            "after sequence {after_sequence} lies beyond the cutoff at {}",
            cutoff.last_sequence.get()
        )));
    }
    if after_sequence > 0 {
        let position = PositiveInteger::new(after_sequence)
            .map_err(|error| cursor_invalid(format!("after sequence invalid: {}", error.detail)))?;
        let retained =
            rm_evidence::read_event(principal, &cutoff.journal_id, position).map_err(|error| {
                map_read_error(error, "after cursor history")
            })?;
        let expected = match &request.after.event_hash {
            MaybeDigest::Present(digest) => digest,
            MaybeDigest::Missing(_) => {
                return Err(cursor_invalid(
                    "positive after cursor must carry the retained event hash",
                ))
            }
        };
        if retained.event_hash != *expected {
            return Err(cursor_invalid(
                "after cursor event_hash does not match the retained journal event",
            ));
        }
    }

    // Scan every position in (after, through], projecting registered
    // observations in journal order. Non-projection events advance the
    // scanned cursor without consuming item or byte budgets.
    let mut items: Vec<ObservationItem> = Vec::new();
    let mut accumulated_bytes: usize = PAGE_OVERHEAD_BYTES;
    let mut scanned_sequence = after_sequence;
    let mut scanned_hash: MaybeDigest = match &request.after.event_hash {
        MaybeDigest::Present(digest) => MaybeDigest::Present(digest.clone()),
        MaybeDigest::Missing(missing) => MaybeDigest::Missing(missing.clone()),
    };
    let mut truncated_for_bytes = false;

    for sequence in (after_sequence + 1)..=cutoff.last_sequence.get() {
        let position = PositiveInteger::new(sequence)
            .map_err(|error| cursor_invalid(format!("scan sequence invalid: {}", error.detail)))?;
        let envelope = rm_evidence::read_event(principal, &cutoff.journal_id, position)
            .map_err(|error| map_read_error(error, "observation scan"))?;
        if envelope.journal_sequence.get() != sequence {
            return Err(integrity(format!(
                "journal scan expected sequence {sequence} but retained {}",
                envelope.journal_sequence.get()
            )));
        }
        if !is_projection_kind(&envelope.event_kind) {
            scanned_sequence = sequence;
            scanned_hash = MaybeDigest::Present(envelope.event_hash.clone());
            continue;
        }
        if items.len() as u64 >= request.max_items.get() {
            break;
        }
        let item = project_event(&envelope)?;
        let size = item_bytes(&item)?;
        if accumulated_bytes + size > MAX_RESPONSE_BYTES {
            if items.is_empty() {
                return Err(response_too_large(format!(
                    "single observation item at sequence {sequence} ({} bytes) exceeds the response bound of {MAX_RESPONSE_BYTES} bytes; it is reported explicitly, never dropped",
                    size
                )));
            }
            truncated_for_bytes = true;
            break;
        }
        accumulated_bytes += size;
        items.push(item);
        scanned_sequence = sequence;
        scanned_hash = MaybeDigest::Present(envelope.event_hash.clone());
    }

    let next = ObservationCursor {
        handle: request.handle.clone(),
        journal_id: cutoff.journal_id.clone(),
        sequence: scanned_sequence,
        event_hash: scanned_hash,
    };
    next.validate()?;
    let has_more = scanned_sequence < cutoff.last_sequence.get();

    // Every returned item lies strictly after `after` and at or before the
    // scanned position, which itself never passes the cutoff.
    for item in &items {
        let sequence = item.sequence();
        if !(after_sequence < sequence
            && sequence <= scanned_sequence
            && scanned_sequence <= cutoff.last_sequence.get())
        {
            return Err(integrity(
                "observation page violates after < item.sequence <= next <= through",
            ));
        }
    }

    let close_ref = observation_close_ref(principal, &cutoff)?;
    let mut limitations = Vec::new();
    if truncated_for_bytes {
        limitations.push(format!(
            "page truncated to honor the {MAX_RESPONSE_BYTES}-byte response bound; continue from next"
        ));
    }

    Ok(ObservationPage {
        kind: "observation_page".to_string(),
        handle: request.handle.clone(),
        after: request.after.clone(),
        through: cutoff,
        next,
        has_more,
        observation_close_ref: close_ref,
        items,
        limitations,
    })
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn projection_kinds_are_exactly_eight() {
        let kinds = [
            "native_report",
            "context_observation",
            "task_output",
            "connector_incident",
            "control_observation",
            "lifecycle_publication",
            "artifact_available",
            "clock_registered",
        ];
        for kind in kinds {
            assert!(is_projection_kind(kind), "{kind} must project");
        }
        for kind in [
            "manifest_admitted",
            "dispatch_published",
            "observation_opened",
            "observation_closed",
            "execution_claim",
            "origin_fact",
            "report_published",
        ] {
            assert!(!is_projection_kind(kind), "{kind} must not project");
        }
    }
}

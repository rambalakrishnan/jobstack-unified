//! `rm_evidence`: tier-2 durable evidence journal and content-addressed artifact
//! store for Ringmaster.
//!
//! The module is the ingestion authority for journal events. Untrusted callers
//! submit [`EventSubmission`] values; every authority field on the resulting
//! [`JournalEnvelope`] (record type, run/journal identity, sequence, event ID,
//! owner domain, producer identity, provenance, role, assertion kind, receipt
//! time, and hashes) is assigned here, never accepted from the caller
//! (EK-PROVENANCE, seam mapping §3.6).
//!
//! Guarantees implemented:
//!
//! - **EK-JOURNAL**: an acknowledged event is appended to the retained prefix.
//!   Sequences start at 1, are contiguous, and the first event is
//!   `manifest_admitted`, which pins the complete immutable manifest artifact.
//!   Every later event names the same run, journal, and manifest digest. Events
//!   are never edited, deleted, resequenced, or backdated.
//! - **EK-HASHES**: content digests are verified. The event hash covers the
//!   RFC 8785 canonical JSON of the envelope without `event_hash`; sequence 1
//!   carries `previous_event_hash` as a reasoned `not_applicable` missingness and
//!   later sequences carry the exact previous event hash. `JournalPrefix` head
//!   hashes equal the event hash at `last_sequence`. [`resolve_evidence`] checks
//!   the journal, sequence, event ID, hash, and JSON pointer together.
//! - **EK-ATOMICITY / OWD-LOCAL-COMMIT**: [`commit_owner_effect`] validates the
//!   whole batch, then appends every event under one owner-local lock; a failure
//!   leaves the retained prefix untouched. Referenced artifact bytes must already
//!   be installed durably, and the authoritative effect must be cited.
//! - **EK-OBSERVATION / RM-C49**: identical `(producer_id, producer_sequence)`
//!   deliveries deduplicate to the retained event without duplicating effects.
//!   Conflicting content under the same key is an integrity incident, never
//!   last-write-wins.
//! - **EK-ARTIFACTS / EXT-ARTIFACTS / RM-C58**: artifact identity is the SHA-256
//!   digest of the exact stored bytes. Bytes are installed before registration;
//!   a record cannot cite absent bytes or its own future registration; an
//!   existing digest is never replaced with different bytes or metadata.
//!   Retrying the same command after a crash returns the retained envelopes and
//!   never reruns the external action.
//!
//! The store is owner-local: a single in-process durability boundary guarded by
//! one lock. No cross-domain transaction, shared database write, or peer lock is
//! acquired on the commit path (OWD-LOCAL-COMMIT).

#![forbid(unsafe_code)]
#![allow(clippy::result_large_err)] // ConnectorError is the shared §17 envelope.

use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{LazyLock, Mutex, MutexGuard};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub use rm_authority::{AuthenticatedPrincipal, ConnectorError, Manifest};
pub use rm_time::{
    ClockDescriptor, MaybeTimePoint, Measurement, Missing, TimePoint, UtcAnnotation,
};
pub use rm_wire::Digest;

use rm_time::{ClockBasis, MeasurementOrigin};

// ---------------------------------------------------------------------------
// Constants and scalar helpers
// ---------------------------------------------------------------------------

/// Largest integer representable without precision loss (§3.1).
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Journal record discriminator assigned by the authority.
pub const JOURNAL_RECORD_TYPE: &str = "journal_event";
/// Journal record schema version assigned by the authority.
pub const JOURNAL_SCHEMA_VERSION: &str = "evidence-kernel/0.1.0";
/// Provenance assigned to journal events ingested over the authenticated server
/// channel. A content hash never authenticates an external source.
pub const PROVENANCE_SERVER: &str = "server";

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

fn forbidden(detail: impl Into<String>) -> ConnectorError {
    connector_error("FORBIDDEN", "policy", detail)
}

fn integrity(detail: impl Into<String>) -> ConnectorError {
    connector_error("INTEGRITY_INCIDENT", "integrity", detail)
}

fn not_found(detail: impl Into<String>) -> ConnectorError {
    connector_error("NOT_FOUND", "resource", detail)
}

fn require_identifier(field: &str, value: &str) -> Result<(), ConnectorError> {
    if value.is_empty() {
        return Err(invalid(format!("{field} must be nonempty")));
    }
    Ok(())
}

fn require_owner_domain(field: &str, value: &str) -> Result<(), ConnectorError> {
    let valid = !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-');
    if !valid {
        return Err(invalid(format!(
            "{field} {value:?} must be a single identity of letters, digits, '_' or '-'"
        )));
    }
    Ok(())
}

fn check_principal(principal: &AuthenticatedPrincipal) -> Result<(), ConnectorError> {
    if principal.principal_id().is_empty()
        || !rm_wire::is_valid_digest(principal.registration_digest().as_str())
    {
        return Err(connector_error(
            "UNAUTHENTICATED",
            "request",
            "channel identity not established",
        ));
    }
    Ok(())
}

fn missing_json(missing: &Missing) -> Value {
    let mut map = Map::new();
    map.insert("value".to_string(), Value::Null);
    map.insert("reason".to_string(), Value::String(missing.reason.clone()));
    if let Some(detail) = &missing.detail {
        map.insert("detail".to_string(), Value::String(detail.clone()));
    }
    Value::Object(map)
}

/// A positive integer in `1 ..= 9007199254740991`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PositiveInteger(u64);

impl PositiveInteger {
    /// Validates and wraps a positive integer.
    pub fn new(value: u64) -> Result<Self, ConnectorError> {
        if value == 0 || value > MAX_SAFE_INTEGER {
            return Err(invalid(format!(
                "positive integer {value} is outside 1..={MAX_SAFE_INTEGER}"
            )));
        }
        Ok(PositiveInteger(value))
    }

    /// Returns the wrapped value.
    pub fn get(self) -> u64 {
        self.0
    }
}

// ---------------------------------------------------------------------------
// Reference types (§3.1)
// ---------------------------------------------------------------------------

/// Artifact access classification. A digest is not a bearer credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccessClass {
    /// Readable by any authenticated principal while the bytes remain retained.
    Public,
    /// Readable only by the principal that installed the bytes.
    Restricted,
}

impl AccessClass {
    /// Wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            AccessClass::Public => "public",
            AccessClass::Restricted => "restricted",
        }
    }

    /// Parses the exact wire spelling.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "public" => Some(AccessClass::Public),
            "restricted" => Some(AccessClass::Restricted),
            _ => None,
        }
    }
}

/// Digest-or-reasoned-missingness carrier used for `previous_event_hash`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaybeDigest {
    /// Present digest.
    Present(Digest),
    /// Reasoned missingness (`not_applicable` for sequence one).
    Missing(Missing),
}

/// Immutable byte identity (§3.1). Possession grants no read authority.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ArtifactReference {
    /// SHA-256 of the exact stored bytes.
    pub digest: Digest,
    /// Exact stored byte length.
    pub size_bytes: u64,
    /// Declared media type.
    pub media_type: String,
    /// Owner domain of the immutable identity.
    pub owner_domain: String,
    /// Access classification.
    pub access: AccessClass,
}

impl ArtifactReference {
    /// Validates the closed reference shape.
    pub fn validate(&self) -> Result<(), ConnectorError> {
        if !rm_wire::is_valid_digest(self.digest.as_str()) {
            return Err(invalid(format!(
                "artifact digest {:?} is not a sha256 digest",
                self.digest.as_str()
            )));
        }
        if self.size_bytes > MAX_SAFE_INTEGER {
            return Err(invalid(format!(
                "artifact size_bytes {} is outside 0..={MAX_SAFE_INTEGER}",
                self.size_bytes
            )));
        }
        require_identifier("artifact media_type", &self.media_type)?;
        require_owner_domain("artifact owner_domain", &self.owner_domain)?;
        Ok(())
    }

    /// Closed-object JSON projection.
    pub fn to_json(&self) -> Value {
        json!({
            "digest": self.digest.as_str(),
            "size_bytes": self.size_bytes,
            "media_type": self.media_type,
            "owner_domain": self.owner_domain,
            "access": self.access.as_str(),
        })
    }

    /// Parses the closed reference shape, rejecting undeclared fields.
    pub fn from_json(value: &Value) -> Result<Self, ConnectorError> {
        let object = value
            .as_object()
            .ok_or_else(|| invalid("artifact reference must be a JSON object"))?;
        ensure_closed(
            object,
            &[
                "digest",
                "size_bytes",
                "media_type",
                "owner_domain",
                "access",
            ],
            "artifact reference",
        )?;
        let digest =
            Digest::parse(field_str(object, "digest", "artifact reference")?).map_err(invalid)?;
        let size_bytes = object
            .get("size_bytes")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid("artifact reference requires integer size_bytes"))?;
        let media_type = field_str(object, "media_type", "artifact reference")?.to_string();
        let owner_domain = field_str(object, "owner_domain", "artifact reference")?.to_string();
        let access = AccessClass::parse(field_str(object, "access", "artifact reference")?)
            .ok_or_else(|| invalid("artifact access must be \"public\" or \"restricted\""))?;
        let reference = ArtifactReference {
            digest,
            size_bytes,
            media_type,
            owner_domain,
            access,
        };
        reference.validate()?;
        Ok(reference)
    }
}

/// Reference to one journaled event value (§3.1). Every component must agree.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EvidenceRef {
    /// Journal identity.
    pub journal_id: String,
    /// Positive journal sequence.
    pub sequence: PositiveInteger,
    /// Authority-assigned event identity.
    pub event_id: String,
    /// Event hash at that sequence.
    pub event_hash: Digest,
    /// RFC 6901 JSON Pointer; empty cites the entire event.
    pub pointer: String,
}

impl EvidenceRef {
    /// Validates the closed reference shape and pointer syntax.
    pub fn validate(&self) -> Result<(), ConnectorError> {
        require_identifier("evidence journal_id", &self.journal_id)?;
        require_identifier("evidence event_id", &self.event_id)?;
        if !rm_wire::is_valid_digest(self.event_hash.as_str()) {
            return Err(invalid(format!(
                "evidence event_hash {:?} is not a sha256 digest",
                self.event_hash.as_str()
            )));
        }
        if !valid_json_pointer(&self.pointer) {
            return Err(invalid(format!(
                "evidence pointer {:?} is not a valid JSON Pointer",
                self.pointer
            )));
        }
        Ok(())
    }

    /// Closed-object JSON projection.
    pub fn to_json(&self) -> Value {
        json!({
            "journal_id": self.journal_id,
            "sequence": self.sequence.get(),
            "event_id": self.event_id,
            "event_hash": self.event_hash.as_str(),
            "pointer": self.pointer,
        })
    }

    /// Parses the closed reference shape, rejecting undeclared fields.
    pub fn from_json(value: &Value) -> Result<Self, ConnectorError> {
        let object = value
            .as_object()
            .ok_or_else(|| invalid("evidence reference must be a JSON object"))?;
        ensure_closed(
            object,
            &[
                "journal_id",
                "sequence",
                "event_id",
                "event_hash",
                "pointer",
            ],
            "evidence reference",
        )?;
        let journal_id = field_str(object, "journal_id", "evidence reference")?.to_string();
        let sequence = object
            .get("sequence")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid("evidence reference requires integer sequence"))?;
        let event_id = field_str(object, "event_id", "evidence reference")?.to_string();
        let event_hash = Digest::parse(field_str(object, "event_hash", "evidence reference")?)
            .map_err(invalid)?;
        let pointer = field_str(object, "pointer", "evidence reference")?.to_string();
        let reference = EvidenceRef {
            journal_id,
            sequence: PositiveInteger::new(sequence)?,
            event_id,
            event_hash,
            pointer,
        };
        reference.validate()?;
        Ok(reference)
    }
}

/// Nonempty immutable journal prefix (§3.1). Admission is its first event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalPrefix {
    /// Journal identity.
    pub journal_id: String,
    /// Positive last sequence included in the prefix.
    pub last_sequence: PositiveInteger,
    /// Event hash at `last_sequence`.
    pub head_hash: Digest,
}

impl JournalPrefix {
    /// Closed-object JSON projection.
    pub fn to_json(&self) -> Value {
        json!({
            "journal_id": self.journal_id,
            "last_sequence": self.last_sequence.get(),
            "head_hash": self.head_hash.as_str(),
        })
    }
}

// ---------------------------------------------------------------------------
// Event registry
// ---------------------------------------------------------------------------

/// Epistemic role assigned to a journal event (§3.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventRole {
    /// Observed input from outside Ringmaster.
    ExternalInput,
    /// Produced Ringmaster output.
    DerivedOutput,
    /// Journal lifecycle observation.
    LifecycleObservation,
}

impl EventRole {
    /// Wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            EventRole::ExternalInput => "external_input",
            EventRole::DerivedOutput => "derived_output",
            EventRole::LifecycleObservation => "lifecycle_observation",
        }
    }
}

/// Assertion kind assigned to a journal event (§3.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssertionKind {
    /// Observation.
    Observation,
    /// Claim.
    Claim,
    /// Authoritative effect.
    AuthoritativeEffect,
    /// Derived assessment.
    DerivedAssessment,
}

impl AssertionKind {
    /// Wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            AssertionKind::Observation => "observation",
            AssertionKind::Claim => "claim",
            AssertionKind::AuthoritativeEffect => "authoritative_effect",
            AssertionKind::DerivedAssessment => "derived_assessment",
        }
    }
}

/// Ingestion-assigned evidence scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceScope {
    /// Evidence about the current run.
    CurrentRun,
    /// Historical evidence, never scored as current.
    HistoricalUnscored,
    /// Synthetic evidence.
    Synthetic,
}

impl EvidenceScope {
    /// Wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            EvidenceScope::CurrentRun => "current_run",
            EvidenceScope::HistoricalUnscored => "historical_unscored",
            EvidenceScope::Synthetic => "synthetic",
        }
    }
}

/// Versioned ingestion registration for one journal event kind.
///
/// The registration binds the event kind to its owning write axis (mirroring
/// `rm_authority::authorize_owner`), the pinned event schema version, and the
/// authority-assigned role and assertion kind. Callers never choose these
/// fields (EK-PROVENANCE).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventKindRegistration {
    /// Registered event kind.
    pub event_kind: &'static str,
    /// Write axis that owns the kind.
    pub owner_domain: &'static str,
    /// Pinned event schema version.
    pub event_schema_version: &'static str,
    /// Authority-assigned epistemic role.
    pub role: EventRole,
    /// Authority-assigned assertion kind.
    pub assertion_kind: AssertionKind,
}

const fn registration(
    event_kind: &'static str,
    owner_domain: &'static str,
    event_schema_version: &'static str,
    role: EventRole,
    assertion_kind: AssertionKind,
) -> EventKindRegistration {
    EventKindRegistration {
        event_kind,
        owner_domain,
        event_schema_version,
        role,
        assertion_kind,
    }
}

/// Immutable ingestion registry. An event kind must appear both here and in the
/// admitted manifest's event registry.
pub const EVENT_REGISTRY: [EventKindRegistration; 15] = [
    registration(
        "manifest_admitted",
        "evidence",
        "evidence-kernel/0.1.0",
        EventRole::ExternalInput,
        AssertionKind::AuthoritativeEffect,
    ),
    registration(
        "clock_registered",
        "evidence",
        "evidence-kernel/0.1.0",
        EventRole::LifecycleObservation,
        AssertionKind::Observation,
    ),
    registration(
        "dispatch_published",
        "dispatch",
        "owner-separated-write-domains/0.1.0",
        EventRole::DerivedOutput,
        AssertionKind::AuthoritativeEffect,
    ),
    registration(
        "observation_opened",
        "observation",
        "evidence-kernel/0.1.0",
        EventRole::LifecycleObservation,
        AssertionKind::Observation,
    ),
    registration(
        "observation_closed",
        "observation",
        "evidence-kernel/0.1.0",
        EventRole::LifecycleObservation,
        AssertionKind::Observation,
    ),
    registration(
        "context_observation",
        "observation",
        "evidence-kernel/0.1.0",
        EventRole::ExternalInput,
        AssertionKind::Observation,
    ),
    registration(
        "execution_claim",
        "execution",
        "evidence-kernel/0.1.0",
        EventRole::ExternalInput,
        AssertionKind::Claim,
    ),
    registration(
        "native_report",
        "execution",
        "evidence-kernel/0.1.0",
        EventRole::ExternalInput,
        AssertionKind::Claim,
    ),
    registration(
        "task_output",
        "execution",
        "evidence-kernel/0.1.0",
        EventRole::ExternalInput,
        AssertionKind::Observation,
    ),
    registration(
        "origin_fact",
        "application",
        "evidence-kernel/0.1.0",
        EventRole::ExternalInput,
        AssertionKind::Claim,
    ),
    registration(
        "report_published",
        "report",
        "owner-separated-write-domains/0.1.0",
        EventRole::DerivedOutput,
        AssertionKind::AuthoritativeEffect,
    ),
    registration(
        "artifact_available",
        "artifact",
        "evidence-kernel/0.1.0",
        EventRole::DerivedOutput,
        AssertionKind::AuthoritativeEffect,
    ),
    registration(
        "control_observation",
        "control",
        "evidence-kernel/0.1.0",
        EventRole::ExternalInput,
        AssertionKind::Observation,
    ),
    registration(
        "connector_incident",
        "connector",
        "evidence-kernel/0.1.0",
        EventRole::ExternalInput,
        AssertionKind::Observation,
    ),
    registration(
        "lifecycle_publication",
        "report",
        "owner-separated-write-domains/0.1.0",
        EventRole::DerivedOutput,
        AssertionKind::AuthoritativeEffect,
    ),
];

/// Looks up the immutable registration for an event kind.
pub fn event_registration(event_kind: &str) -> Option<&'static EventKindRegistration> {
    EVENT_REGISTRY
        .iter()
        .find(|entry| entry.event_kind == event_kind)
}

// ---------------------------------------------------------------------------
// Submission and envelope
// ---------------------------------------------------------------------------

/// Evidence payload (§3.6). All nested artifact identities must appear in
/// `artifact_refs` for retention.
#[derive(Debug, Clone, PartialEq)]
pub struct EvidencePayload {
    /// Evidence map; always a JSON object.
    pub data: Value,
    /// Measurements with full provenance.
    pub measurements: Vec<Measurement>,
    /// Citations of earlier journal events.
    pub evidence_refs: Vec<EvidenceRef>,
    /// Immutable artifact identities referenced by this payload.
    pub artifact_refs: Vec<ArtifactReference>,
}

impl EvidencePayload {
    /// Closed-object JSON projection.
    pub fn to_json(&self) -> Result<Value, ConnectorError> {
        let mut measurements = Vec::with_capacity(self.measurements.len());
        for measurement in &self.measurements {
            measurements.push(
                serde_json::to_value(measurement).map_err(|error| {
                    invalid(format!("measurement cannot be serialized: {error}"))
                })?,
            );
        }
        let evidence_refs = self
            .evidence_refs
            .iter()
            .map(EvidenceRef::to_json)
            .collect::<Vec<Value>>();
        let artifact_refs = self
            .artifact_refs
            .iter()
            .map(ArtifactReference::to_json)
            .collect::<Vec<Value>>();
        Ok(json!({
            "data": &self.data,
            "measurements": measurements,
            "evidence_refs": evidence_refs,
            "artifact_refs": artifact_refs,
        }))
    }
}

/// Caller-supplied ingress shape (§3.6). Contains no authority fields.
#[derive(Debug, Clone, PartialEq)]
pub struct EventSubmission {
    /// Monotonic producer-lifetime sequence; `None` is reasoned missingness.
    pub producer_sequence: Option<PositiveInteger>,
    /// Manifest-registered event kind.
    pub event_kind: String,
    /// Registered event schema version.
    pub event_schema_version: String,
    /// Actual source time point or reasoned missingness.
    pub occurred_at: MaybeTimePoint,
    /// Evidence payload.
    pub payload: EvidencePayload,
}

impl EventSubmission {
    /// Fields a caller may supply. Everything else is authority-assigned.
    pub const ALLOWED_FIELDS: [&'static str; 5] = [
        "producer_sequence",
        "event_kind",
        "event_schema_version",
        "occurred_at",
        "payload",
    ];

    /// Parses an untrusted submission, rejecting caller-authored authority
    /// fields instead of trusting them (EK-PROVENANCE).
    pub fn parse(bytes: &[u8]) -> Result<Self, ConnectorError> {
        let text = std::str::from_utf8(bytes)
            .map_err(|error| invalid(format!("submission is not utf-8: {error}")))?;
        let value: Value = serde_json::from_str(text)
            .map_err(|error| invalid(format!("submission is not JSON: {error}")))?;
        let object = value
            .as_object()
            .ok_or_else(|| invalid("submission must be a JSON object"))?;
        for key in object.keys() {
            if !Self::ALLOWED_FIELDS.contains(&key.as_str()) {
                return Err(forbidden(format!(
                    "caller-authored authority field {key:?} is rejected: the journal authority assigns provenance, owner domain, sequence, identity, and hashes"
                )));
            }
        }
        let event_kind = field_str(object, "event_kind", "submission")?.to_string();
        let event_schema_version =
            field_str(object, "event_schema_version", "submission")?.to_string();
        require_identifier("event_kind", &event_kind)?;
        require_identifier("event_schema_version", &event_schema_version)?;
        let producer_sequence = match object.get("producer_sequence") {
            Some(Value::Number(number)) => {
                let value = number
                    .as_u64()
                    .ok_or_else(|| invalid("producer_sequence must be an unsigned integer"))?;
                Some(PositiveInteger::new(value)?)
            }
            Some(Value::Object(map)) if map.get("value") == Some(&Value::Null) => {
                if !missing_reason_valid(map) {
                    return Err(invalid(
                        "producer_sequence missingness must be a reasoned Missing envelope",
                    ));
                }
                None
            }
            Some(_) => {
                return Err(invalid(
                    "producer_sequence must be a positive integer or a Missing envelope",
                ))
            }
            None => {
                return Err(invalid(
                    "submission is missing required field \"producer_sequence\"",
                ))
            }
        };
        let occurred_at_value = object
            .get("occurred_at")
            .ok_or_else(|| invalid("submission is missing required field \"occurred_at\""))?
            .clone();
        let occurred_at: MaybeTimePoint = serde_json::from_value(occurred_at_value)
            .map_err(|error| invalid(format!("occurred_at is invalid: {error}")))?;
        let payload_value = object
            .get("payload")
            .ok_or_else(|| invalid("submission is missing required field \"payload\""))?;
        let payload = parse_payload(payload_value)?;
        Ok(EventSubmission {
            producer_sequence,
            event_kind,
            event_schema_version,
            occurred_at,
            payload,
        })
    }
}

fn missing_reason_valid(map: &Map<String, Value>) -> bool {
    matches!(
        map.get("reason").and_then(Value::as_str),
        Some("not_enabled")
            | Some("not_applicable")
            | Some("not_observed")
            | Some("observation_lost")
            | Some("unsupported_by_subject")
            | Some("manual_override")
    ) && map
        .get("detail")
        .is_none_or(|detail| detail.as_str().is_some_and(|text| !text.is_empty()))
        && map.len() <= 3
        && map
            .keys()
            .all(|key| key == "value" || key == "reason" || key == "detail")
}

fn parse_payload(value: &Value) -> Result<EvidencePayload, ConnectorError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("payload must be a JSON object"))?;
    ensure_closed(
        object,
        &["data", "measurements", "evidence_refs", "artifact_refs"],
        "payload",
    )?;
    let data = object
        .get("data")
        .ok_or_else(|| invalid("payload is missing required field \"data\""))?
        .clone();
    if !data.is_object() {
        return Err(invalid("payload.data must be an EvidenceMap object"));
    }
    let measurements: Vec<Measurement> = serde_json::from_value(
        object
            .get("measurements")
            .cloned()
            .ok_or_else(|| invalid("payload is missing required field \"measurements\""))?,
    )
    .map_err(|error| invalid(format!("payload.measurements is invalid: {error}")))?;
    let mut evidence_refs = Vec::new();
    for item in array_field(object, "evidence_refs", "payload")? {
        evidence_refs.push(EvidenceRef::from_json(item)?);
    }
    let mut artifact_refs = Vec::new();
    for item in array_field(object, "artifact_refs", "payload")? {
        artifact_refs.push(ArtifactReference::from_json(item)?);
    }
    Ok(EvidencePayload {
        data,
        measurements,
        evidence_refs,
        artifact_refs,
    })
}

/// Complete journal event assigned and retained by the ingestion authority.
#[derive(Debug, Clone, PartialEq)]
pub struct JournalEnvelope {
    /// `journal_event`.
    pub record_type: String,
    /// `evidence-kernel/0.1.0`.
    pub schema_version: String,
    /// Run identity.
    pub run_id: String,
    /// Journal identity.
    pub journal_id: String,
    /// Pinned manifest digest.
    pub manifest_hash: Digest,
    /// Positive contiguous journal sequence.
    pub journal_sequence: PositiveInteger,
    /// Authority-assigned event identity.
    pub event_id: String,
    /// Event kind.
    pub event_kind: String,
    /// Pinned event schema version.
    pub event_schema_version: String,
    /// Authority-assigned epistemic role.
    pub role: EventRole,
    /// Authority-assigned assertion kind.
    pub assertion_kind: AssertionKind,
    /// Write axis that owns the event kind.
    pub owner_domain: String,
    /// Authority-assigned producer identity.
    pub producer_id: String,
    /// Producer-lifetime sequence.
    pub producer_sequence: Option<PositiveInteger>,
    /// Ingestion-assigned source class.
    pub provenance: String,
    /// Ingestion-assigned evidence scope.
    pub evidence_scope: EvidenceScope,
    /// Receipt time from the journal authority clock.
    pub recorded_at: TimePoint,
    /// Actual source time point or reasoned missingness.
    pub occurred_at: MaybeTimePoint,
    /// Citations supporting this event.
    pub causal_refs: Vec<EvidenceRef>,
    /// Evidence payload.
    pub payload: EvidencePayload,
    /// Previous event hash, or `not_applicable` at sequence one.
    pub previous_event_hash: MaybeDigest,
    /// SHA-256 of the RFC 8785 canonical envelope without this field.
    pub event_hash: Digest,
}

impl JournalEnvelope {
    /// Envelope projection without `event_hash`, which is what the hash covers.
    pub fn unsigned_json(&self) -> Result<Value, ConnectorError> {
        let occurred_at = serde_json::to_value(&self.occurred_at)
            .map_err(|error| invalid(format!("occurred_at cannot be serialized: {error}")))?;
        let recorded_at = serde_json::to_value(&self.recorded_at)
            .map_err(|error| invalid(format!("recorded_at cannot be serialized: {error}")))?;
        let producer_sequence = match self.producer_sequence {
            Some(sequence) => json!(sequence.get()),
            None => missing_json(&Missing::new("not_applicable")),
        };
        let previous_event_hash = match &self.previous_event_hash {
            MaybeDigest::Present(hash) => json!(hash.as_str()),
            MaybeDigest::Missing(missing) => missing_json(missing),
        };
        Ok(json!({
            "record_type": &self.record_type,
            "schema_version": &self.schema_version,
            "run_id": &self.run_id,
            "journal_id": &self.journal_id,
            "manifest_hash": self.manifest_hash.as_str(),
            "journal_sequence": self.journal_sequence.get(),
            "event_id": &self.event_id,
            "event_kind": &self.event_kind,
            "event_schema_version": &self.event_schema_version,
            "role": self.role.as_str(),
            "assertion_kind": self.assertion_kind.as_str(),
            "owner_domain": &self.owner_domain,
            "producer_id": &self.producer_id,
            "producer_sequence": producer_sequence,
            "provenance": &self.provenance,
            "evidence_scope": self.evidence_scope.as_str(),
            "recorded_at": recorded_at,
            "occurred_at": occurred_at,
            "causal_refs": self.causal_refs.iter().map(EvidenceRef::to_json).collect::<Vec<Value>>(),
            "payload": self.payload.to_json()?,
            "previous_event_hash": previous_event_hash,
        }))
    }

    /// Complete retained record projection, including `event_hash`.
    pub fn to_json(&self) -> Result<Value, ConnectorError> {
        let mut value = self.unsigned_json()?;
        if let Value::Object(map) = &mut value {
            map.insert(
                "event_hash".to_string(),
                Value::String(self.event_hash.as_str().to_string()),
            );
        }
        Ok(value)
    }

    /// Recomputes the event hash from the retained content.
    pub fn computed_event_hash(&self) -> Result<Digest, ConnectorError> {
        let value = self.unsigned_json()?;
        let bytes = serde_json::to_vec(&value)
            .map_err(|error| invalid(format!("journal event cannot be serialized: {error}")))?;
        rm_wire::canonical_digest(&bytes)
            .map_err(|error| invalid(format!("journal event cannot be hashed: {error}")))
    }
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

struct StoredArtifact {
    reference: ArtifactReference,
    bytes: Vec<u8>,
    installer_id: String,
}

struct DedupRecord {
    content_digest: Digest,
    sequence: u64,
}

struct JournalState {
    journal_id: String,
    run_id: String,
    manifest_hash: Digest,
    envelopes: Vec<JournalEnvelope>,
    clocks: Vec<ClockDescriptor>,
    dedup: BTreeMap<(String, u64), DedupRecord>,
}

impl JournalState {
    fn new(journal_id: String, run_id: String, manifest_hash: Digest) -> Self {
        JournalState {
            journal_id,
            run_id,
            manifest_hash,
            envelopes: Vec::new(),
            clocks: vec![evidence_clock().clone()],
            dedup: BTreeMap::new(),
        }
    }
}

#[derive(Default)]
struct EvidenceStore {
    artifacts: BTreeMap<String, StoredArtifact>,
    journals: BTreeMap<String, JournalState>,
}

fn store() -> &'static Mutex<EvidenceStore> {
    static STORE: LazyLock<Mutex<EvidenceStore>> =
        LazyLock::new(|| Mutex::new(EvidenceStore::default()));
    &STORE
}

fn lock_store() -> MutexGuard<'static, EvidenceStore> {
    store()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn verify_installed(
    artifacts: &BTreeMap<String, StoredArtifact>,
    reference: &ArtifactReference,
) -> Result<(), ConnectorError> {
    reference.validate()?;
    let stored = artifacts.get(reference.digest.as_str()).ok_or_else(|| {
        not_found(format!(
            "artifact {} is not installed; exact bytes must be installed durably before they are cited",
            reference.digest
        ))
    })?;
    if stored.reference != *reference {
        return Err(integrity(format!(
            "artifact {} is registered with different immutable metadata",
            reference.digest
        )));
    }
    if rm_wire::artifact_digest(&stored.bytes) != stored.reference.digest {
        return Err(integrity(format!(
            "retained artifact {} no longer matches its content digest",
            reference.digest
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Public artifact operations
// ---------------------------------------------------------------------------

/// Installs immutable artifact bytes durably before any journal reference.
///
/// The declared reference must describe exactly these bytes: digest and size
/// must match. Re-installing identical bytes and metadata is idempotent; an
/// existing digest is never replaced, and conflicting metadata under the same
/// digest is an integrity incident (EXT-ARTIFACTS, §3.5).
pub fn install_artifact(
    principal: &AuthenticatedPrincipal,
    reference: &ArtifactReference,
    bytes: &[u8],
) -> Result<ArtifactReference, ConnectorError> {
    check_principal(principal)?;
    reference.validate()?;
    let computed = rm_wire::artifact_digest(bytes);
    if computed != reference.digest {
        return Err(invalid(format!(
            "declared artifact digest {} does not match the exact stored bytes {}",
            reference.digest, computed
        )));
    }
    if reference.size_bytes != bytes.len() as u64 {
        return Err(invalid(format!(
            "declared artifact size_bytes {} does not match the stored byte length {}",
            reference.size_bytes,
            bytes.len()
        )));
    }
    let mut store = lock_store();
    if let Some(existing) = store.artifacts.get(reference.digest.as_str()) {
        if existing.reference == *reference && existing.bytes == bytes {
            return Ok(existing.reference.clone());
        }
        return Err(integrity(format!(
            "artifact digest {} is already registered with different bytes or metadata; bytes are never replaced under an existing digest",
            reference.digest
        )));
    }
    store.artifacts.insert(
        reference.digest.as_str().to_string(),
        StoredArtifact {
            reference: reference.clone(),
            bytes: bytes.to_vec(),
            installer_id: principal.principal_id().to_string(),
        },
    );
    Ok(reference.clone())
}

/// Loads retained artifact bytes within the authorized access classification.
///
/// A digest is not a bearer credential: `restricted` artifacts are readable only
/// by the principal that installed them. Missing bytes are reported, never
/// silently re-fetched and never substituted under the old digest.
pub fn load_artifact(
    principal: &AuthenticatedPrincipal,
    reference: &ArtifactReference,
) -> Result<Vec<u8>, ConnectorError> {
    check_principal(principal)?;
    reference.validate()?;
    let store = lock_store();
    let stored = store
        .artifacts
        .get(reference.digest.as_str())
        .ok_or_else(|| {
            not_found(format!(
                "artifact {} is not retained; possession of a reference grants no read authority",
                reference.digest
            ))
        })?;
    if stored.reference != *reference {
        return Err(integrity(format!(
            "artifact {} reference metadata does not match the registered identity",
            reference.digest
        )));
    }
    if stored.reference.access == AccessClass::Restricted
        && stored.installer_id != principal.principal_id()
    {
        return Err(forbidden(format!(
            "restricted artifact {} is not readable through this authenticated handle",
            reference.digest
        )));
    }
    if rm_wire::artifact_digest(&stored.bytes) != stored.reference.digest {
        return Err(integrity(format!(
            "retained artifact {} no longer matches its content digest",
            reference.digest
        )));
    }
    Ok(stored.bytes.clone())
}

// ---------------------------------------------------------------------------
// Manifest preparation
// ---------------------------------------------------------------------------

struct PreparedManifest {
    digest: Digest,
    wire: Vec<u8>,
    reference: ArtifactReference,
}

fn prepare_manifest(manifest: &Manifest) -> Result<PreparedManifest, ConnectorError> {
    require_identifier("run_id", &manifest.run_id)?;
    require_identifier("admission_ref", &manifest.admission_ref)?;
    let wire = rm_authority::manifest_wire_bytes(manifest);
    rm_wire::validate_record("manifest/v1", &wire).map_err(|error| {
        invalid(format!(
            "manifest is not a structurally valid manifest record: {error}"
        ))
    })?;
    let digest = rm_wire::canonical_digest(&wire)
        .map_err(|error| invalid(format!("manifest cannot be hashed: {error}")))?;
    if manifest.manifest_hash != digest.as_str() {
        return Err(invalid(format!(
            "manifest_hash {:?} does not match the canonical manifest digest {}",
            manifest.manifest_hash, digest
        )));
    }
    let reference = ArtifactReference {
        digest: digest.clone(),
        size_bytes: wire.len() as u64,
        media_type: "application/json".to_string(),
        owner_domain: "evidence".to_string(),
        access: AccessClass::Public,
    };
    Ok(PreparedManifest {
        digest,
        wire,
        reference,
    })
}

/// Returns the immutable artifact reference that pins the complete manifest.
pub fn manifest_artifact_reference(
    manifest: &Manifest,
) -> Result<ArtifactReference, ConnectorError> {
    Ok(prepare_manifest(manifest)?.reference)
}

/// Returns the journal identity assigned to an admitted manifest.
pub fn journal_id_for(manifest: &Manifest) -> Result<String, ConnectorError> {
    Ok(journal_id_for_digest(&prepare_manifest(manifest)?.digest))
}

fn journal_id_for_digest(digest: &Digest) -> String {
    format!("journal-{}", digest.as_str())
}

fn ensure_manifest_installed(
    artifacts: &mut BTreeMap<String, StoredArtifact>,
    prepared: &PreparedManifest,
    principal: &AuthenticatedPrincipal,
) -> Result<(), ConnectorError> {
    if let Some(existing) = artifacts.get(prepared.digest.as_str()) {
        if existing.reference != prepared.reference || existing.bytes != prepared.wire {
            return Err(integrity(format!(
                "manifest digest {} is already registered with different artifact bytes or metadata",
                prepared.digest
            )));
        }
        return Ok(());
    }
    artifacts.insert(
        prepared.digest.as_str().to_string(),
        StoredArtifact {
            reference: prepared.reference.clone(),
            bytes: prepared.wire.clone(),
            installer_id: principal.principal_id().to_string(),
        },
    );
    Ok(())
}

fn ensure_same_manifest(
    state: &JournalState,
    manifest: &Manifest,
    prepared: &PreparedManifest,
) -> Result<(), ConnectorError> {
    if state.manifest_hash != prepared.digest || manifest.manifest_hash != prepared.digest.as_str()
    {
        return Err(invalid(
            "event names a manifest digest that does not match the admitted journal manifest",
        ));
    }
    if state.run_id != manifest.run_id {
        return Err(invalid(
            "event names a run that does not match the admitted journal run",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Journal append
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Stage {
    envelopes: Vec<JournalEnvelope>,
    clocks: Vec<ClockDescriptor>,
    dedup: BTreeMap<(String, u64), StagedDedup>,
}

struct StagedDedup {
    content_digest: Digest,
    index: usize,
}

fn apply_stage(state: &mut JournalState, stage: Stage) {
    let base = state.envelopes.len();
    state.clocks.extend(stage.clocks);
    for (key, record) in stage.dedup {
        state.dedup.insert(
            key,
            DedupRecord {
                content_digest: record.content_digest,
                sequence: (base + record.index + 1) as u64,
            },
        );
    }
    state.envelopes.extend(stage.envelopes);
}

/// Appends one admitted event to the journal identified by its manifest.
///
/// The first call for a manifest must carry the `manifest_admitted` submission
/// and pins the complete immutable manifest artifact. Later calls must name the
/// same run, journal, and manifest digest. Identical producer deliveries
/// deduplicate to the retained envelope; conflicting content is an integrity
/// incident (EK-JOURNAL, EK-OBSERVATION, RM-C49).
pub fn append_event(
    principal: &AuthenticatedPrincipal,
    manifest: &Manifest,
    submission: EventSubmission,
) -> Result<JournalEnvelope, ConnectorError> {
    check_principal(principal)?;
    let prepared = prepare_manifest(manifest)?;
    let journal_id = journal_id_for_digest(&prepared.digest);
    let mut store = lock_store();
    let EvidenceStore {
        artifacts,
        journals,
    } = &mut *store;
    if let Some(state) = journals.get(&journal_id) {
        ensure_same_manifest(state, manifest, &prepared)?;
        let mut stage = Stage::default();
        let envelope = assign_event(
            artifacts,
            state,
            &mut stage,
            principal,
            manifest,
            &prepared,
            &submission,
        )?;
        let state = journals
            .get_mut(&journal_id)
            .ok_or_else(|| not_found("journal disappeared during append"))?;
        apply_stage(state, stage);
        Ok(envelope)
    } else {
        if submission.event_kind != "manifest_admitted" {
            return Err(invalid(
                "journal has no admission event: the first journal event must be manifest_admitted",
            ));
        }
        ensure_manifest_installed(artifacts, &prepared, principal)?;
        let state = JournalState::new(
            journal_id.clone(),
            manifest.run_id.clone(),
            prepared.digest.clone(),
        );
        let mut stage = Stage::default();
        let envelope = assign_event(
            artifacts,
            &state,
            &mut stage,
            principal,
            manifest,
            &prepared,
            &submission,
        )?;
        let mut state = state;
        apply_stage(&mut state, stage);
        journals.insert(journal_id, state);
        Ok(envelope)
    }
}

/// Commits one owner-local authoritative effect atomically.
///
/// All referenced artifact bytes must already be installed durably, the effect
/// must be cited by at least one submission, and every submission is validated
/// before anything is appended. A retry of the same command returns the retained
/// envelopes without rerunning the external action (EK-ATOMICITY,
/// OWD-LOCAL-COMMIT, RM-C58).
pub fn commit_owner_effect(
    principal: &AuthenticatedPrincipal,
    manifest: &Manifest,
    effect: &ArtifactReference,
    submissions: &[EventSubmission],
    response: &ArtifactReference,
) -> Result<Vec<JournalEnvelope>, ConnectorError> {
    check_principal(principal)?;
    let prepared = prepare_manifest(manifest)?;
    let journal_id = journal_id_for_digest(&prepared.digest);
    if submissions.is_empty() {
        return Err(invalid(
            "an owner effect commit requires at least one journal event",
        ));
    }
    let mut store = lock_store();
    let EvidenceStore {
        artifacts,
        journals,
    } = &mut *store;
    verify_installed(artifacts, effect)?;
    verify_installed(artifacts, response)?;
    let cites_effect = submissions.iter().any(|submission| {
        submission
            .payload
            .artifact_refs
            .iter()
            .any(|reference| reference.digest == effect.digest)
    });
    if !cites_effect {
        return Err(invalid(
            "owner effect commit must cite its authoritative effect artifact in payload.artifact_refs",
        ));
    }
    let state = journals.get(&journal_id).ok_or_else(|| {
        invalid("owner effect requires an admitted journal: admit the manifest first")
    })?;
    ensure_same_manifest(state, manifest, &prepared)?;
    let mut stage = Stage::default();
    let mut envelopes = Vec::with_capacity(submissions.len());
    for submission in submissions {
        envelopes.push(assign_event(
            artifacts, state, &mut stage, principal, manifest, &prepared, submission,
        )?);
    }
    let state = journals
        .get_mut(&journal_id)
        .ok_or_else(|| not_found("journal disappeared during commit"))?;
    apply_stage(state, stage);
    Ok(envelopes)
}

// ---------------------------------------------------------------------------
// Event assignment
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn assign_event(
    artifacts: &BTreeMap<String, StoredArtifact>,
    state: &JournalState,
    stage: &mut Stage,
    principal: &AuthenticatedPrincipal,
    manifest: &Manifest,
    prepared: &PreparedManifest,
    submission: &EventSubmission,
) -> Result<JournalEnvelope, ConnectorError> {
    let kind = submission.event_kind.as_str();
    if !manifest.event_kinds.iter().any(|declared| declared == kind) {
        return Err(invalid(format!(
            "event kind {kind:?} is not declared in the admitted manifest event registry"
        )));
    }
    let registration = event_registration(kind).ok_or_else(|| {
        connector_error(
            "NOT_ADMITTED",
            "policy",
            format!("event kind {kind:?} is not registered with the ingestion authority"),
        )
    })?;
    let descriptor = rm_authority::authorize_owner(principal, registration.owner_domain, kind)?;
    if descriptor.owner_domain != registration.owner_domain {
        return Err(integrity(
            "owner authorization assigned a different owner domain than the event registry",
        ));
    }
    if submission.event_schema_version != registration.event_schema_version {
        return Err(invalid(format!(
            "event_schema_version {:?} is not the registered version {:?} for event kind {kind:?}",
            submission.event_schema_version, registration.event_schema_version
        )));
    }
    let producer_sequence = submission.producer_sequence.ok_or_else(|| {
        invalid("producer_sequence is required: no unsequenced producer registration exists")
    })?;
    let payload = &submission.payload;
    if !payload.data.is_object() {
        return Err(invalid("payload.data must be an EvidenceMap object"));
    }
    let mut artifact_keys = BTreeSet::new();
    for reference in &payload.artifact_refs {
        verify_installed(artifacts, reference)?;
        if !artifact_keys.insert(reference.to_json().to_string()) {
            return Err(invalid("payload.artifact_refs must be unique"));
        }
    }
    let mut evidence_keys = BTreeSet::new();
    for reference in &payload.evidence_refs {
        if !evidence_keys.insert(reference.to_json().to_string()) {
            return Err(invalid("payload.evidence_refs must be unique"));
        }
    }
    let mut clocks: Vec<ClockDescriptor> = state.clocks.clone();
    clocks.extend(stage.clocks.iter().cloned());
    let mut pending_clock: Option<ClockDescriptor> = None;
    match kind {
        "manifest_admitted" => validate_admission_payload(prepared, payload)?,
        "clock_registered" => {
            let descriptor: ClockDescriptor = serde_json::from_value(payload.data.clone())
                .map_err(|error| {
                    invalid(format!(
                        "clock_registered payload.data must be a ClockDescriptor: {error}"
                    ))
                })?;
            validate_clock_descriptor(&descriptor)?;
            if !clocks.contains(&descriptor) {
                if clocks.iter().any(|registered| {
                    registered.clock_id == descriptor.clock_id
                        && registered.boot_id == descriptor.boot_id
                }) {
                    return Err(integrity(format!(
                        "conflicting clock registration for clock {:?} boot {:?}",
                        descriptor.clock_id, descriptor.boot_id
                    )));
                }
                clocks.push(descriptor.clone());
                pending_clock = Some(descriptor);
            }
        }
        "artifact_available" if payload.artifact_refs.is_empty() => {
            return Err(invalid(
                "artifact_available must cite at least one installed artifact",
            ));
        }
        _ => {}
    }
    validate_occurred_at(&submission.occurred_at, &clocks)?;
    for measurement in &payload.measurements {
        rm_time::validate_measurement(measurement, &clocks).map_err(|error| {
            invalid(format!(
                "measurement {:?} rejected at ingestion: {error}",
                measurement.measurement_id
            ))
        })?;
    }
    let content_digest = submission_content_digest(submission)?;
    let key = (descriptor.producer_id.clone(), producer_sequence.get());
    if let Some(record) = state.dedup.get(&key) {
        if record.content_digest != content_digest {
            return Err(conflicting_delivery(
                &descriptor.producer_id,
                producer_sequence.get(),
            ));
        }
        return state
            .envelopes
            .get((record.sequence - 1) as usize)
            .cloned()
            .ok_or_else(|| integrity("deduplication record has no retained event"));
    }
    if let Some(record) = stage.dedup.get(&key) {
        if record.content_digest != content_digest {
            return Err(conflicting_delivery(
                &descriptor.producer_id,
                producer_sequence.get(),
            ));
        }
        return Ok(stage.envelopes[record.index].clone());
    }
    let journal_sequence =
        PositiveInteger::new(state.envelopes.len() as u64 + stage.envelopes.len() as u64 + 1)?;
    let next_sequence = journal_sequence.get();
    if next_sequence == 1 {
        if kind != "manifest_admitted" {
            return Err(invalid("the first journal event must be manifest_admitted"));
        }
    } else if kind == "manifest_admitted" {
        return Err(invalid(
            "manifest_admitted is only valid as the first journal event",
        ));
    }
    if let Some(clock) = pending_clock {
        stage.clocks.push(clock);
    }
    for reference in &payload.evidence_refs {
        resolve_against(state, stage, reference, next_sequence)?;
    }
    let previous_event_hash = if next_sequence == 1 {
        MaybeDigest::Missing(Missing::new("not_applicable"))
    } else {
        let tip = stage
            .envelopes
            .last()
            .map(|event| event.event_hash.clone())
            .or_else(|| state.envelopes.last().map(|event| event.event_hash.clone()))
            .ok_or_else(|| {
                integrity(
                    "journal is not contiguous: sequence exceeds the retained prefix without a previous event",
                )
            })?;
        MaybeDigest::Present(tip)
    };
    let mut envelope = JournalEnvelope {
        record_type: JOURNAL_RECORD_TYPE.to_string(),
        schema_version: JOURNAL_SCHEMA_VERSION.to_string(),
        run_id: state.run_id.clone(),
        journal_id: state.journal_id.clone(),
        manifest_hash: state.manifest_hash.clone(),
        journal_sequence,
        event_id: format!("{}:{}", state.journal_id, next_sequence),
        event_kind: kind.to_string(),
        event_schema_version: registration.event_schema_version.to_string(),
        role: registration.role,
        assertion_kind: registration.assertion_kind,
        owner_domain: descriptor.owner_domain.clone(),
        producer_id: descriptor.producer_id.clone(),
        producer_sequence: Some(producer_sequence),
        provenance: PROVENANCE_SERVER.to_string(),
        evidence_scope: EvidenceScope::CurrentRun,
        recorded_at: recorded_now(),
        occurred_at: submission.occurred_at.clone(),
        causal_refs: payload.evidence_refs.clone(),
        payload: payload.clone(),
        previous_event_hash,
        event_hash: Digest(String::new()),
    };
    envelope.event_hash = envelope.computed_event_hash()?;
    stage.dedup.insert(
        key,
        StagedDedup {
            content_digest,
            index: stage.envelopes.len(),
        },
    );
    stage.envelopes.push(envelope.clone());
    Ok(envelope)
}

fn conflicting_delivery(producer_id: &str, producer_sequence: u64) -> ConnectorError {
    integrity(format!(
        "conflicting content for producer {producer_id:?} sequence {producer_sequence}: duplicate deliveries must be identical; conflicting content is an integrity incident, not last-write-wins"
    ))
}

fn validate_admission_payload(
    prepared: &PreparedManifest,
    payload: &EvidencePayload,
) -> Result<(), ConnectorError> {
    let reference = &prepared.reference;
    let expected_data = json!({ "manifest": reference.to_json() });
    if payload.data != expected_data {
        return Err(invalid(format!(
            "manifest_admitted payload.data must pin the complete immutable manifest artifact {}",
            reference.digest
        )));
    }
    if payload.artifact_refs.len() != 1 || payload.artifact_refs[0] != *reference {
        return Err(invalid(
            "manifest_admitted payload.artifact_refs must be exactly the admitted manifest artifact",
        ));
    }
    if !payload.measurements.is_empty() {
        return Err(invalid("manifest_admitted carries no measurements"));
    }
    if !payload.evidence_refs.is_empty() {
        return Err(invalid(
            "manifest_admitted is the first journal event and cannot cite earlier evidence",
        ));
    }
    Ok(())
}

fn submission_content_digest(submission: &EventSubmission) -> Result<Digest, ConnectorError> {
    let occurred_at = serde_json::to_value(&submission.occurred_at)
        .map_err(|error| invalid(format!("occurred_at cannot be serialized: {error}")))?;
    let content = json!({
        "event_kind": &submission.event_kind,
        "event_schema_version": &submission.event_schema_version,
        "occurred_at": occurred_at,
        "payload": submission.payload.to_json()?,
    });
    let bytes = serde_json::to_vec(&content)
        .map_err(|error| invalid(format!("submission content cannot be serialized: {error}")))?;
    rm_wire::canonical_digest(&bytes)
        .map_err(|error| invalid(format!("submission content cannot be hashed: {error}")))
}

// ---------------------------------------------------------------------------
// Reads and evidence resolution
// ---------------------------------------------------------------------------

/// Returns the nonempty retained prefix head for a journal.
pub fn journal_head(
    principal: &AuthenticatedPrincipal,
    journal_id: &str,
) -> Result<JournalPrefix, ConnectorError> {
    check_principal(principal)?;
    require_identifier("journal_id", journal_id)?;
    let store = lock_store();
    let state = store
        .journals
        .get(journal_id)
        .ok_or_else(|| not_found(format!("journal {journal_id:?} is not retained")))?;
    let last = state
        .envelopes
        .last()
        .ok_or_else(|| not_found(format!("journal {journal_id:?} has no admitted event")))?;
    Ok(JournalPrefix {
        journal_id: state.journal_id.clone(),
        last_sequence: last.journal_sequence,
        head_hash: last.event_hash.clone(),
    })
}

/// Reads one retained event by journal identity and sequence.
pub fn read_event(
    principal: &AuthenticatedPrincipal,
    journal_id: &str,
    sequence: PositiveInteger,
) -> Result<JournalEnvelope, ConnectorError> {
    check_principal(principal)?;
    require_identifier("journal_id", journal_id)?;
    let store = lock_store();
    let state = store
        .journals
        .get(journal_id)
        .ok_or_else(|| not_found(format!("journal {journal_id:?} is not retained")))?;
    let index = (sequence.get() - 1) as usize;
    state
        .envelopes
        .get(index)
        .cloned()
        .ok_or_else(|| not_found(format!("journal sequence {sequence:?} is not retained")))
}

/// Resolves an evidence reference within a cited, verified journal prefix.
///
/// The journal, sequence, event identity, event hash, and JSON pointer must all
/// agree with the retained event, and the prefix head must equal the event hash
/// at its cutoff. Content hashes detect changed content; they are not
/// authentication (EK-HASHES).
pub fn resolve_evidence(
    principal: &AuthenticatedPrincipal,
    reference: &EvidenceRef,
    prefix: &JournalPrefix,
) -> Result<JournalEnvelope, ConnectorError> {
    check_principal(principal)?;
    reference.validate()?;
    require_identifier("prefix journal_id", &prefix.journal_id)?;
    if prefix.last_sequence.get() == 0 {
        return Err(invalid("journal prefix must include its admission event"));
    }
    if !rm_wire::is_valid_digest(prefix.head_hash.as_str()) {
        return Err(invalid("journal prefix head_hash is not a sha256 digest"));
    }
    if reference.journal_id != prefix.journal_id {
        return Err(invalid(format!(
            "evidence reference names journal {:?}, not the cited prefix journal {:?}",
            reference.journal_id, prefix.journal_id
        )));
    }
    if reference.sequence.get() > prefix.last_sequence.get() {
        return Err(invalid(format!(
            "evidence reference at sequence {} lies outside the cited prefix ending at {}",
            reference.sequence.get(),
            prefix.last_sequence.get()
        )));
    }
    let store = lock_store();
    let state = store
        .journals
        .get(&prefix.journal_id)
        .ok_or_else(|| not_found(format!("journal {:?} is not retained", prefix.journal_id)))?;
    let cutoff_index = (prefix.last_sequence.get() - 1) as usize;
    let cutoff = state.envelopes.get(cutoff_index).ok_or_else(|| {
        not_found(format!(
            "journal prefix ends at sequence {} beyond the retained prefix",
            prefix.last_sequence.get()
        ))
    })?;
    if cutoff.event_hash != prefix.head_hash {
        return Err(integrity(format!(
            "journal prefix head_hash {} does not equal the event hash at sequence {}",
            prefix.head_hash,
            prefix.last_sequence.get()
        )));
    }
    if cutoff.computed_event_hash()? != cutoff.event_hash {
        return Err(integrity(format!(
            "journal event at sequence {} does not match its retained content digest",
            cutoff.journal_sequence.get()
        )));
    }
    if let MaybeDigest::Present(previous) = &cutoff.previous_event_hash {
        let previous_event = state
            .envelopes
            .get(cutoff_index.wrapping_sub(1))
            .ok_or_else(|| integrity("journal prefix head lacks its previous event"))?;
        if &previous_event.event_hash != previous {
            return Err(integrity(
                "journal hash chain does not link the prefix head to its previous event",
            ));
        }
    }
    let event = state
        .envelopes
        .get((reference.sequence.get() - 1) as usize)
        .ok_or_else(|| {
            not_found(format!(
                "journal sequence {} is not retained",
                reference.sequence.get()
            ))
        })?;
    if event.event_id != reference.event_id || event.event_hash != reference.event_hash {
        return Err(integrity(format!(
            "evidence reference at sequence {} does not agree with the journaled event identity and hash",
            reference.sequence.get()
        )));
    }
    if event.computed_event_hash()? != event.event_hash {
        return Err(integrity(format!(
            "journal event at sequence {} does not match its retained content digest",
            reference.sequence.get()
        )));
    }
    let event_json = event.to_json()?;
    if resolve_pointer(&event_json, &reference.pointer).is_none() {
        return Err(invalid(format!(
            "evidence pointer {:?} does not resolve inside event {:?}",
            reference.pointer, reference.event_id
        )));
    }
    Ok(event.clone())
}

fn resolve_against(
    state: &JournalState,
    stage: &Stage,
    reference: &EvidenceRef,
    next_sequence: u64,
) -> Result<(), ConnectorError> {
    reference.validate()?;
    if reference.journal_id != state.journal_id {
        return Err(invalid(format!(
            "evidence reference names journal {:?}, not the journal being appended {:?}",
            reference.journal_id, state.journal_id
        )));
    }
    if reference.sequence.get() >= next_sequence {
        return Err(invalid(format!(
            "evidence reference at sequence {} cannot be cited from the event being appended at sequence {next_sequence}: a record cannot cite its own registration or a future event",
            reference.sequence.get()
        )));
    }
    let event = event_in_prefix(state, stage, reference.sequence.get())?;
    if event.event_id != reference.event_id || event.event_hash != reference.event_hash {
        return Err(integrity(format!(
            "evidence reference at sequence {} does not agree with the journaled event identity and hash",
            reference.sequence.get()
        )));
    }
    let event_json = event.to_json()?;
    if resolve_pointer(&event_json, &reference.pointer).is_none() {
        return Err(invalid(format!(
            "evidence pointer {:?} does not resolve inside event {:?}",
            reference.pointer, reference.event_id
        )));
    }
    Ok(())
}

fn event_in_prefix<'a>(
    state: &'a JournalState,
    stage: &'a Stage,
    sequence: u64,
) -> Result<&'a JournalEnvelope, ConnectorError> {
    if sequence == 0 {
        return Err(invalid("journal sequence must be positive"));
    }
    let index = sequence as usize;
    if index <= state.envelopes.len() {
        return Ok(&state.envelopes[index - 1]);
    }
    let staged = index - state.envelopes.len();
    stage.envelopes.get(staged - 1).ok_or_else(|| {
        not_found(format!(
            "journal sequence {sequence} is not in the retained journal prefix"
        ))
    })
}

// ---------------------------------------------------------------------------
// Clocks and receipt time
// ---------------------------------------------------------------------------

/// The journal authority's registered monotonic clock.
///
/// A process restart produces a new `boot_id`, so elapsed offsets are never
/// compared across lifetimes.
pub fn evidence_clock() -> &'static ClockDescriptor {
    static CLOCK: LazyLock<ClockDescriptor> = LazyLock::new(|| {
        let boot = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        ClockDescriptor {
            clock_id: "evidence-journal".to_string(),
            boot_id: format!("boot-{boot}"),
            origin: MeasurementOrigin::EngineMeasured,
            source_id: "rm_evidence".to_string(),
            basis: ClockBasis::MonotonicOffset,
            unit: "ms".to_string(),
        }
    });
    &CLOCK
}

fn recorded_now() -> TimePoint {
    static PROCESS_START: LazyLock<Instant> = LazyLock::new(Instant::now);
    let start = &*PROCESS_START;
    let clock = evidence_clock();
    TimePoint {
        clock_id: clock.clock_id.clone(),
        boot_id: clock.boot_id.clone(),
        origin: MeasurementOrigin::EngineMeasured,
        monotonic_offset_ms: start.elapsed().as_secs_f64() * 1000.0,
        utc_annotation: UtcAnnotation::Missing(Missing::new("not_observed")),
    }
}

fn validate_missing_value(field: &str, missing: &Missing) -> Result<(), ConnectorError> {
    if !rm_time::is_valid_reason(&missing.reason) {
        return Err(invalid(format!(
            "{field} missingness reason {:?} is not permitted",
            missing.reason
        )));
    }
    if let Some(detail) = &missing.detail {
        if detail.is_empty() {
            return Err(invalid(format!(
                "{field} missingness detail must be nonempty"
            )));
        }
    }
    Ok(())
}

fn validate_occurred_at(
    occurred_at: &MaybeTimePoint,
    clocks: &[ClockDescriptor],
) -> Result<(), ConnectorError> {
    match occurred_at {
        MaybeTimePoint::Missing(missing) => {
            validate_missing_value("occurred_at", missing)?;
        }
        MaybeTimePoint::Present(point) => {
            require_identifier("occurred_at.clock_id", &point.clock_id)?;
            require_identifier("occurred_at.boot_id", &point.boot_id)?;
            if !point.monotonic_offset_ms.is_finite() || point.monotonic_offset_ms < 0.0 {
                return Err(invalid(
                    "occurred_at.monotonic_offset_ms must be finite and nonnegative",
                ));
            }
            let clock = clocks
                .iter()
                .find(|clock| clock.clock_id == point.clock_id && clock.boot_id == point.boot_id)
                .ok_or_else(|| {
                    invalid(format!(
                        "occurred_at names unregistered clock {:?} boot {:?}",
                        point.clock_id, point.boot_id
                    ))
                })?;
            if clock.origin != point.origin {
                return Err(invalid(
                    "occurred_at origin does not match the registered clock origin",
                ));
            }
            match &point.utc_annotation {
                UtcAnnotation::DateTime(text) => {
                    require_identifier("occurred_at.utc_annotation", text)?;
                }
                UtcAnnotation::Missing(missing) => {
                    validate_missing_value("occurred_at.utc_annotation", missing)?;
                }
            }
        }
    }
    Ok(())
}

fn validate_clock_descriptor(descriptor: &ClockDescriptor) -> Result<(), ConnectorError> {
    require_identifier("clock_id", &descriptor.clock_id)?;
    require_identifier("boot_id", &descriptor.boot_id)?;
    require_identifier("source_id", &descriptor.source_id)?;
    if descriptor.unit != "ms" {
        return Err(invalid(format!(
            "clock unit must be \"ms\", found {:?}",
            descriptor.unit
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// JSON helpers
// ---------------------------------------------------------------------------

fn field_str<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    what: &str,
) -> Result<&'a str, ConnectorError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("{what} requires string field {field:?}")))
}

fn array_field<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    what: &str,
) -> Result<&'a [Value], ConnectorError> {
    object
        .get(field)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| invalid(format!("{what} requires array field {field:?}")))
}

fn ensure_closed(
    object: &Map<String, Value>,
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

/// Validates RFC 6901 JSON Pointer syntax; the empty pointer is valid.
pub fn valid_json_pointer(pointer: &str) -> bool {
    if pointer.is_empty() {
        return true;
    }
    if !pointer.starts_with('/') {
        return false;
    }
    for token in pointer.split('/').skip(1) {
        let bytes = token.as_bytes();
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] == b'~' {
                match bytes.get(index + 1) {
                    Some(b'0') | Some(b'1') => index += 2,
                    _ => return false,
                }
            } else {
                index += 1;
            }
        }
    }
    true
}

fn resolve_pointer<'a>(root: &'a Value, pointer: &str) -> Option<&'a Value> {
    if pointer.is_empty() {
        return Some(root);
    }
    let mut current = root;
    for raw in pointer.split('/').skip(1) {
        let token = raw.replace("~1", "/").replace("~0", "~");
        current = match current {
            Value::Object(map) => map.get(&token)?,
            Value::Array(items) => {
                if token.is_empty()
                    || (token.len() > 1 && token.starts_with('0'))
                    || !token.bytes().all(|byte| byte.is_ascii_digit())
                {
                    return None;
                }
                let index: usize = token.parse().ok()?;
                items.get(index)?
            }
            _ => return None,
        };
    }
    Some(current)
}

#[cfg(test)]
mod internal_tests {
    use super::*;
    use rm_time::{MaybeNumber, MaybeString, Scope, ScopeKind};

    #[test]
    fn pointer_validation_and_resolution() {
        assert!(valid_json_pointer(""));
        assert!(valid_json_pointer("/payload/data"));
        assert!(valid_json_pointer("/payload/artifact_refs/0/digest"));
        assert!(!valid_json_pointer("payload"));
        assert!(!valid_json_pointer("/payload/~2"));
        let value = json!({"a": {"b": [10, 20]}});
        assert_eq!(
            resolve_pointer(&value, "/a/b/1").and_then(Value::as_u64),
            Some(20)
        );
        assert!(resolve_pointer(&value, "/a/b/01").is_none());
        assert!(resolve_pointer(&value, "/a/b/2").is_none());
    }

    #[test]
    fn positive_integer_bounds() {
        assert!(PositiveInteger::new(0).is_err());
        assert!(PositiveInteger::new(MAX_SAFE_INTEGER).is_ok());
        assert!(PositiveInteger::new(MAX_SAFE_INTEGER + 1).is_err());
    }

    #[test]
    fn measurement_helpers_are_reachable() {
        // Keeps the rm_time crate linkage exercised from the library itself.
        let scope = Scope {
            kind: ScopeKind::ConnectorCall,
            id: "call".to_string(),
        };
        let resolution = MaybeNumber::Missing(Missing::new("not_observed"));
        let group = MaybeString::Missing(Missing::new("not_observed"));
        let clock = evidence_clock();
        let measurement = Measurement {
            measurement_id: "m".to_string(),
            name: "elapsed".to_string(),
            scope,
            quantity: rm_time::Quantity::Duration,
            unit: "ms".to_string(),
            origin: MeasurementOrigin::EngineMeasured,
            clock_id: clock.clock_id.clone(),
            boot_id: clock.boot_id.clone(),
            method: rm_time::Method::EndpointDifference,
            start: MaybeTimePoint::Present(TimePoint {
                clock_id: clock.clock_id.clone(),
                boot_id: clock.boot_id.clone(),
                origin: MeasurementOrigin::EngineMeasured,
                monotonic_offset_ms: 1.0,
                utc_annotation: rm_time::UtcAnnotation::Missing(Missing::new("not_observed")),
            }),
            end: MaybeTimePoint::Present(TimePoint {
                clock_id: clock.clock_id.clone(),
                boot_id: clock.boot_id.clone(),
                origin: MeasurementOrigin::EngineMeasured,
                monotonic_offset_ms: 3.0,
                utc_annotation: rm_time::UtcAnnotation::Missing(Missing::new("not_observed")),
            }),
            estimate: rm_time::Estimate::Exact { value: 2.0 },
            resolution,
            censoring: rm_time::Censoring::None,
            comparability_group: group,
        };
        assert!(rm_time::validate_measurement(&measurement, std::slice::from_ref(clock)).is_ok());
    }
}

//! `rm_leases`: kernel lease fencing for Ringmaster (seam §18, §4.3).
//!
//! Ringmaster consumes the exact kernel [`LeaseRecord`], not a worker-authored
//! claim token. The resource owner (this module's caller) is the only party
//! that may run a transition: [`transition_lease`] authorizes that owner
//! through the registered write axis (`rm_authority::authorize_owner`), loads
//! the immutable transition intent artifact, checks the expected fence, derives
//! the successor snapshot, and commits the journal evidence atomically
//! (`rm_evidence::commit_owner_effect`) before acknowledging.
//!
//! Invariants implemented here:
//!
//! - **EK-LEASE**: claim atomically checks the eligible resource state and the
//!   absence of an unexpired lease, assigns an authority-owned fencing
//!   `lease_id`/`owner_epoch`, advances the entity revision, clears
//!   `last_failure_reason`, and appends evidence without changing
//!   `resource_state`. Completion checks lease identity, the unexpired
//!   authority-clock deadline, entity/input revisions, and the applicable
//!   owner/session epochs. A rejected stale completion has no effect.
//! - **EK-LEASE-RESTART**: `leased_at`/`lease_expires_at` live on one
//!   registered lease-authority clock and boot, and expiry is strictly later
//!   than issue. Renewal requires a still-current token and epoch. A restarted
//!   authority epoch is fenced by an explicit `recover` transition; offsets of
//!   an old boot are never compared with a new one and UTC annotations are
//!   never used to infer elapsed time.
//! - **EK-ATOMICITY**: the admitted intent, the journal event, and the
//!   replayable response reference commit as one owner-local effect; nothing is
//!   acknowledged before that commit succeeds.
//! - **LIFE-IDEMPOTENCY**: the intent artifact is the immutable request; the
//!   journal deduplicates by `(producer, producer_sequence)` so an identical
//!   retry returns the retained event, while changed content under the same
//!   command identity is an integrity incident.
//! - **EXT-RESUME**: recovery uses a new command identity and a new authority
//!   epoch, preserves the same logical resource generation, and journals each
//!   additional delivery.
//! - **OWD-REVISION**: every successor snapshot is a complete immutable record
//!   with `entity_revision = previous + 1`; stale expectations cannot commit.
//!
//! A lease is never proof that a worker, employer, or native transaction
//! stopped. Reclamation revokes local commit authority only.

use rm_authority::{
    authorize_owner, AuthenticatedPrincipal, ConnectorError, Manifest, ProducerDescriptor,
};
use rm_evidence::{
    commit_owner_effect, load_artifact, ArtifactReference, Digest, EvidencePayload, EvidenceRef,
    EventSubmission, JournalEnvelope, JournalPrefix, PositiveInteger,
};
use rm_time::{boundary_reached, is_valid_reason, MaybeString, MaybeTimePoint, Missing, TimePoint};
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

/// Lease record type (kernel §18).
pub const LEASE_RECORD_TYPE: &str = "lease_record";
/// Lease record schema version.
pub const LEASE_SCHEMA_VERSION: &str = "evidence-kernel/0.1.0";
/// Immutable transition-intent record type.
pub const INTENT_RECORD_TYPE: &str = "lease_transition_intent";
/// Immutable owner lease-policy record type.
pub const POLICY_RECORD_TYPE: &str = "lease_policy";
/// Largest integer exactly representable in the wire contract.
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

// ---------------------------------------------------------------------------
// Errors
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
    connector_error("INVALID_REQUEST", "request", detail.into(), "not_dispatched", "operator_review")
}

fn unsupported(detail: impl Into<String>) -> ConnectorError {
    connector_error("UNSUPPORTED_VERSION", "request", detail.into(), "not_dispatched", "operator_review")
}

fn stale(detail: impl Into<String>) -> ConnectorError {
    connector_error("STALE_CONTEXT", "policy", detail.into(), "not_dispatched", "operator_review")
}

fn refused(detail: impl Into<String>) -> ConnectorError {
    connector_error("NOT_ADMITTED", "policy", detail.into(), "not_dispatched", "operator_review")
}

fn exhausted(detail: impl Into<String>) -> ConnectorError {
    connector_error("BUDGET_EXCEEDED", "policy", detail.into(), "not_dispatched", "operator_review")
}

fn busy(detail: impl Into<String>) -> ConnectorError {
    connector_error("RESOURCE_BUSY", "policy", detail.into(), "not_dispatched", "operator_review")
}

fn prerequisite(detail: impl Into<String>) -> ConnectorError {
    connector_error("PREREQUISITE_UNAVAILABLE", "environment", detail.into(), "not_dispatched", "operator_review")
}

fn integrity(detail: impl Into<String>) -> ConnectorError {
    connector_error("INTEGRITY_CONFLICT", "connector", detail.into(), "not_dispatched", "operator_review")
}

// ---------------------------------------------------------------------------
// Small wire helpers
// ---------------------------------------------------------------------------

fn require_identifier(field: &str, value: &str) -> Result<(), ConnectorError> {
    if value.is_empty() {
        return Err(invalid(format!("{field} must be a nonempty identifier")));
    }
    Ok(())
}

fn require_digest(field: &str, value: &Digest) -> Result<(), ConnectorError> {
    if Digest::parse(value.as_str()).is_err() {
        return Err(invalid(format!(
            "{field} must be a sha256:<64 lowercase hex> digest"
        )));
    }
    Ok(())
}

fn check_missing(field: &str, missing: &Missing) -> Result<(), ConnectorError> {
    if !is_valid_reason(&missing.reason) {
        return Err(invalid(format!(
            "{field} missingness reason {:?} is not one of the six kernel null reasons",
            missing.reason
        )));
    }
    if let Some(detail) = &missing.detail {
        if detail.is_empty() {
            return Err(invalid(format!("{field} missingness detail must be nonempty")));
        }
    }
    Ok(())
}

fn check_maybe_string(field: &str, value: &MaybeString) -> Result<(), ConnectorError> {
    match value {
        MaybeString::Text(text) => require_identifier(field, text),
        MaybeString::Missing(missing) => check_missing(field, missing),
    }
}

fn check_maybe_time(field: &str, value: &MaybeTimePoint) -> Result<(), ConnectorError> {
    match value {
        MaybeTimePoint::Present(_) => Ok(()),
        MaybeTimePoint::Missing(missing) => check_missing(field, missing),
    }
}

fn inapplicable_string(_field: &str) -> MaybeString {
    MaybeString::Missing(Missing::new("not_applicable"))
}

fn is_inapplicable_string(value: &MaybeString) -> bool {
    matches!(value, MaybeString::Missing(missing) if missing.reason == "not_applicable")
}

fn inapplicable_time(_field: &str) -> MaybeTimePoint {
    MaybeTimePoint::Missing(Missing::new("not_applicable"))
}

fn is_inapplicable_time(value: &MaybeTimePoint) -> bool {
    matches!(value, MaybeTimePoint::Missing(missing) if missing.reason == "not_applicable")
}

fn present_time<'a>(
    value: &'a MaybeTimePoint,
    field: &str,
) -> Result<&'a TimePoint, ConnectorError> {
    match value {
        MaybeTimePoint::Present(point) => Ok(point),
        MaybeTimePoint::Missing(missing) => {
            check_missing(field, missing)?;
            Err(invalid(format!(
                "held lease requires a present {field}; found missingness {:?}",
                missing.reason
            )))
        }
    }
}

fn present_text<'a>(value: &'a MaybeString, field: &str) -> Result<&'a str, ConnectorError> {
    match value {
        MaybeString::Text(text) => {
            require_identifier(field, text)?;
            Ok(text)
        }
        MaybeString::Missing(missing) => {
            check_missing(field, missing)?;
            Err(invalid(format!(
                "held lease requires a present {field}; found missingness {:?}",
                missing.reason
            )))
        }
    }
}

fn ensure_closed(
    object: &Map<String, Value>,
    allowed: &[&str],
    what: &str,
) -> Result<(), ConnectorError> {
    for key in object.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(invalid(format!(
                "{what} is a closed record; undeclared field {key:?} is rejected"
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
        .ok_or_else(|| invalid(format!("{what} requires string field {name:?}")))
}

fn field_object<'a>(
    object: &'a Map<String, Value>,
    name: &str,
    what: &str,
) -> Result<&'a Map<String, Value>, ConnectorError> {
    field(object, name, what)?
        .as_object()
        .ok_or_else(|| invalid(format!("{what} requires object field {name:?}")))
}

fn revision_field(
    object: &Map<String, Value>,
    name: &str,
    what: &str,
) -> Result<u64, ConnectorError> {
    let value = field(object, name, what)?
        .as_u64()
        .ok_or_else(|| invalid(format!("{what} requires integer field {name:?}")))?;
    if value > MAX_SAFE_INTEGER {
        return Err(invalid(format!(
            "{what}.{name} {value} exceeds the exact integer bound {MAX_SAFE_INTEGER}"
        )));
    }
    Ok(value)
}

fn maybe_string_field(
    object: &Map<String, Value>,
    name: &str,
    what: &str,
) -> Result<MaybeString, ConnectorError> {
    let value = field(object, name, what)?.clone();
    let parsed: MaybeString = serde_json::from_value(value)
        .map_err(|error| invalid(format!("{what}.{name} is not a MaybeString: {error}")))?;
    check_maybe_string(&format!("{what}.{name}"), &parsed)?;
    Ok(parsed)
}

fn maybe_time_field(
    object: &Map<String, Value>,
    name: &str,
    what: &str,
) -> Result<MaybeTimePoint, ConnectorError> {
    let value = field(object, name, what)?.clone();
    let parsed: MaybeTimePoint = serde_json::from_value(value)
        .map_err(|error| invalid(format!("{what}.{name} is not a MaybeTimePoint: {error}")))?;
    check_maybe_time(&format!("{what}.{name}"), &parsed)?;
    Ok(parsed)
}

fn maybe_string_json(value: &MaybeString) -> Value {
    serde_json::to_value(value).unwrap_or(Value::Null)
}

fn maybe_time_json(value: &MaybeTimePoint) -> Value {
    serde_json::to_value(value).unwrap_or(Value::Null)
}

fn advance_revision(current: u64, field: &str) -> Result<u64, ConnectorError> {
    let next = current
        .checked_add(1)
        .ok_or_else(|| integrity(format!("{field} cannot advance beyond {current}")))?;
    if next > MAX_SAFE_INTEGER {
        return Err(integrity(format!(
            "{field} would exceed the exact integer bound {MAX_SAFE_INTEGER}"
        )));
    }
    Ok(next)
}

fn increment_retry(current: u64, why: &str) -> Result<u64, ConnectorError> {
    let next = current
        .checked_add(1)
        .ok_or_else(|| exhausted(format!("retry_count cannot record another failed generation ({why})")))?;
    if next > MAX_SAFE_INTEGER {
        return Err(exhausted(format!(
            "retry_count would exceed the exact integer bound {MAX_SAFE_INTEGER} ({why})"
        )));
    }
    Ok(next)
}

fn require_same_clock(left: &TimePoint, right: &TimePoint, what: &str) -> Result<(), ConnectorError> {
    if left.clock_id != right.clock_id
        || left.boot_id != right.boot_id
        || left.origin != right.origin
    {
        return Err(prerequisite(format!(
            "{what} cannot be ordered: it names a different clock, boot, or origin; lease coordinates are never compared across an authority restart"
        )));
    }
    Ok(())
}

fn require_not_after(
    now: &TimePoint,
    issued_at: &TimePoint,
    what: &str,
) -> Result<(), ConnectorError> {
    require_same_clock(now, issued_at, what)?;
    match boundary_reached(now, issued_at) {
        Ok(true) => Ok(()),
        Ok(false) => Err(stale(format!(
            "{what} is dated after the current authority clock coordinate; a lease command cannot be issued in the future"
        ))),
        Err(error) => Err(invalid(format!(
            "{what} clock coordinates are invalid: {error}"
        ))),
    }
}

fn require_unexpired(
    now: &TimePoint,
    deadline: &TimePoint,
    what: &str,
) -> Result<(), ConnectorError> {
    match boundary_reached(now, deadline) {
        Ok(false) => Ok(()),
        Ok(true) => Err(stale(format!(
            "{what} is stale: the authority-clock deadline has been reached"
        ))),
        Err(error) => Err(prerequisite(format!(
            "{what} cannot be ordered against the lease deadline: {error}; the old authority epoch must be fenced by a recover transition"
        ))),
    }
}

fn require_expired(
    now: &TimePoint,
    deadline: &TimePoint,
    what: &str,
) -> Result<(), ConnectorError> {
    match boundary_reached(now, deadline) {
        Ok(true) => Ok(()),
        Ok(false) => Err(stale(format!(
            "{what} is not established: the authority-clock deadline has not been reached"
        ))),
        Err(error) => Err(prerequisite(format!(
            "{what} cannot be ordered against the lease deadline: {error}; the old authority epoch must be fenced by a recover transition"
        ))),
    }
}

/// Applies a policy TTL to an issue coordinate on the same clock and boot.
///
/// Elapsed time comes only from the registered monotonic offset; the UTC
/// annotation is carried along for display and never consulted.
fn shift_deadline(issued_at: &TimePoint, ttl_ms: f64) -> Result<TimePoint, ConnectorError> {
    if !ttl_ms.is_finite() || ttl_ms <= 0.0 {
        return Err(refused(
            "lease policy ttl_ms must be a finite positive monotonic duration",
        ));
    }
    let offset = issued_at.monotonic_offset_ms + ttl_ms;
    if !offset.is_finite() || offset <= issued_at.monotonic_offset_ms {
        return Err(integrity(
            "lease expiry cannot be derived from the issue coordinate and policy ttl",
        ));
    }
    Ok(TimePoint {
        clock_id: issued_at.clock_id.clone(),
        boot_id: issued_at.boot_id.clone(),
        origin: issued_at.origin,
        monotonic_offset_ms: offset,
        utc_annotation: issued_at.utc_annotation.clone(),
    })
}

// ---------------------------------------------------------------------------
// LeaseRecord
// ---------------------------------------------------------------------------

/// An entity-owner revision. Nonnegative and exactly representable on the wire.
pub type Revision = u64;

/// The actual resource a lease fences: its owner domain and entity identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceReference {
    /// Owner write axis of the resource.
    pub owner_domain: String,
    /// Resource entity type.
    pub entity_type: String,
    /// Resource entity identity.
    pub entity_id: String,
}

impl ResourceReference {
    fn to_json(&self) -> Value {
        json!({
            "owner_domain": self.owner_domain,
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
        })
    }

    fn from_json(value: &Value) -> Result<Self, ConnectorError> {
        let object = value
            .as_object()
            .ok_or_else(|| invalid("resource must be a JSON object"))?;
        ensure_closed(
            object,
            &["owner_domain", "entity_type", "entity_id"],
            "resource",
        )?;
        Ok(ResourceReference {
            owner_domain: field_str(object, "owner_domain", "resource")?.to_string(),
            entity_type: field_str(object, "entity_type", "resource")?.to_string(),
            entity_id: field_str(object, "entity_id", "resource")?.to_string(),
        })
    }

    fn validate(&self) -> Result<(), ConnectorError> {
        require_identifier("resource.owner_domain", &self.owner_domain)?;
        require_identifier("resource.entity_type", &self.entity_type)?;
        require_identifier("resource.entity_id", &self.entity_id)
    }
}

/// An immutable owner policy artifact pin: identity, version, and digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionPin {
    /// Policy identity.
    pub id: String,
    /// Policy version.
    pub version: String,
    /// Canonical artifact digest of the exact policy content.
    pub artifact_digest: Digest,
}

impl VersionPin {
    fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "version": self.version,
            "artifact_digest": self.artifact_digest.as_str(),
        })
    }

    fn from_json(value: &Value) -> Result<Self, ConnectorError> {
        let object = value
            .as_object()
            .ok_or_else(|| invalid("policy pin must be a JSON object"))?;
        ensure_closed(object, &["id", "version", "artifact_digest"], "policy pin")?;
        let digest = Digest::parse(field_str(object, "artifact_digest", "policy pin")?)
            .map_err(|error| invalid(format!("policy pin artifact_digest is invalid: {error}")))?;
        Ok(VersionPin {
            id: field_str(object, "id", "policy pin")?.to_string(),
            version: field_str(object, "version", "policy pin")?.to_string(),
            artifact_digest: digest,
        })
    }
}

/// Lease ownership state. A lease record is either held or unleased.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseState {
    /// No current ownership; ownership/time fields are inapplicable.
    Unleased,
    /// Current ownership; fencing identity, epochs, and times are present.
    Held,
}

impl LeaseState {
    /// Wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            LeaseState::Unleased => "unleased",
            LeaseState::Held => "held",
        }
    }

    fn parse(value: &str) -> Result<Self, ConnectorError> {
        match value {
            "unleased" => Ok(LeaseState::Unleased),
            "held" => Ok(LeaseState::Held),
            other => Err(invalid(format!(
                "lease_state {other:?} is not one of unleased or held"
            ))),
        }
    }
}

/// The exact kernel lease record (seam §18).
///
/// A held record requires lease identity, owner, epoch, issue/expiry, a
/// compatible resource state, and the applicable session epoch. Unleased
/// ownership and time fields are inapplicable typed missingness, never in-band
/// nulls.
#[derive(Debug, Clone, PartialEq)]
pub struct LeaseRecord {
    /// `lease_record`.
    pub record_type: String,
    /// `evidence-kernel/0.1.0`.
    pub schema_version: String,
    /// Resource owner domain and entity identity.
    pub resource: ResourceReference,
    /// Owner-specific eligibility/TTL/retry/routing pin.
    pub policy: VersionPin,
    /// Actual lease authority identity.
    pub issuer_id: String,
    /// Actual lease authority lifetime.
    pub authority_epoch: String,
    /// Fenced resource revision.
    pub entity_revision: Revision,
    /// Fenced input revision.
    pub input_revision: Revision,
    /// Fenced resource/input generation.
    pub generation_id: String,
    /// This owner's claimable resource state. Claim never changes it.
    pub resource_state: String,
    /// Owner state that admits a claim.
    pub eligible_state: String,
    /// Ownership state.
    pub lease_state: LeaseState,
    /// Unique fencing token; never reused for a later claim.
    pub lease_id: MaybeString,
    /// Owner of the held lease.
    pub lease_owner: MaybeString,
    /// Owner epoch assigned with the claim.
    pub owner_epoch: MaybeString,
    /// Session epoch bound to the claim, when applicable.
    pub session_epoch: MaybeString,
    /// Issue coordinate on the lease-authority clock.
    pub leased_at: MaybeTimePoint,
    /// Deadline on the same clock and boot; strictly later than issue.
    pub lease_expires_at: MaybeTimePoint,
    /// Failed generations recorded against the resource.
    pub retry_count: Revision,
    /// Policy retry limit in effect for the current generation.
    pub max_retries_effective: PositiveInteger,
    /// Declared owner-policy failure code, cleared on claim.
    pub last_failure_reason: MaybeString,
    /// Supporting durable journal prefix.
    pub journal_prefix: JournalPrefix,
    /// Supporting durable evidence references (nonempty).
    pub evidence_refs: Vec<EvidenceRef>,
}

impl LeaseRecord {
    /// Closed-object JSON projection of the record.
    pub fn to_json(&self) -> Value {
        json!({
            "record_type": self.record_type,
            "schema_version": self.schema_version,
            "resource": self.resource.to_json(),
            "policy": self.policy.to_json(),
            "issuer_id": self.issuer_id,
            "authority_epoch": self.authority_epoch,
            "entity_revision": self.entity_revision,
            "input_revision": self.input_revision,
            "generation_id": self.generation_id,
            "resource_state": self.resource_state,
            "eligible_state": self.eligible_state,
            "lease_state": self.lease_state.as_str(),
            "lease_id": maybe_string_json(&self.lease_id),
            "lease_owner": maybe_string_json(&self.lease_owner),
            "owner_epoch": maybe_string_json(&self.owner_epoch),
            "session_epoch": maybe_string_json(&self.session_epoch),
            "leased_at": maybe_time_json(&self.leased_at),
            "lease_expires_at": maybe_time_json(&self.lease_expires_at),
            "retry_count": self.retry_count,
            "max_retries_effective": self.max_retries_effective.get(),
            "last_failure_reason": maybe_string_json(&self.last_failure_reason),
            "journal_prefix": self.journal_prefix.to_json(),
            "evidence_refs": self.evidence_refs.iter().map(EvidenceRef::to_json).collect::<Vec<Value>>(),
        })
    }

    /// Parses a closed lease record, rejecting undeclared fields and bare nulls.
    pub fn from_json(value: &Value) -> Result<Self, ConnectorError> {
        let object = value
            .as_object()
            .ok_or_else(|| invalid("lease record must be a JSON object"))?;
        ensure_closed(
            object,
            &[
                "record_type",
                "schema_version",
                "resource",
                "policy",
                "issuer_id",
                "authority_epoch",
                "entity_revision",
                "input_revision",
                "generation_id",
                "resource_state",
                "eligible_state",
                "lease_state",
                "lease_id",
                "lease_owner",
                "owner_epoch",
                "session_epoch",
                "leased_at",
                "lease_expires_at",
                "retry_count",
                "max_retries_effective",
                "last_failure_reason",
                "journal_prefix",
                "evidence_refs",
            ],
            "lease record",
        )?;
        let record_type = field_str(object, "record_type", "lease record")?.to_string();
        let schema_version = field_str(object, "schema_version", "lease record")?.to_string();
        let resource = ResourceReference::from_json(field(object, "resource", "lease record")?)?;
        let policy = VersionPin::from_json(field(object, "policy", "lease record")?)?;
        let lease_state = LeaseState::parse(field_str(object, "lease_state", "lease record")?)?;
        let max_retries_effective =
            PositiveInteger::new(revision_field(object, "max_retries_effective", "lease record")?)?;
        let journal_prefix = parse_journal_prefix(field(object, "journal_prefix", "lease record")?)?;
        let evidence_refs = parse_evidence_refs(field(object, "evidence_refs", "lease record")?)?;
        let record = LeaseRecord {
            record_type,
            schema_version,
            resource,
            policy,
            issuer_id: field_str(object, "issuer_id", "lease record")?.to_string(),
            authority_epoch: field_str(object, "authority_epoch", "lease record")?.to_string(),
            entity_revision: revision_field(object, "entity_revision", "lease record")?,
            input_revision: revision_field(object, "input_revision", "lease record")?,
            generation_id: field_str(object, "generation_id", "lease record")?.to_string(),
            resource_state: field_str(object, "resource_state", "lease record")?.to_string(),
            eligible_state: field_str(object, "eligible_state", "lease record")?.to_string(),
            lease_state,
            lease_id: maybe_string_field(object, "lease_id", "lease record")?,
            lease_owner: maybe_string_field(object, "lease_owner", "lease record")?,
            owner_epoch: maybe_string_field(object, "owner_epoch", "lease record")?,
            session_epoch: maybe_string_field(object, "session_epoch", "lease record")?,
            leased_at: maybe_time_field(object, "leased_at", "lease record")?,
            lease_expires_at: maybe_time_field(object, "lease_expires_at", "lease record")?,
            retry_count: revision_field(object, "retry_count", "lease record")?,
            max_retries_effective,
            last_failure_reason: maybe_string_field(object, "last_failure_reason", "lease record")?,
            journal_prefix,
            evidence_refs,
        };
        record.validate_snapshot()?;
        Ok(record)
    }

    /// Structural and static-fence validation of one immutable snapshot.
    pub fn validate_snapshot(&self) -> Result<(), ConnectorError> {
        if self.record_type != LEASE_RECORD_TYPE {
            return Err(invalid(format!(
                "record_type must be {LEASE_RECORD_TYPE:?}, found {:?}",
                self.record_type
            )));
        }
        if self.schema_version != LEASE_SCHEMA_VERSION {
            return Err(unsupported(format!(
                "lease schema_version {:?} is not {LEASE_SCHEMA_VERSION:?}",
                self.schema_version
            )));
        }
        self.resource.validate()?;
        require_identifier("policy.id", &self.policy.id)?;
        require_identifier("policy.version", &self.policy.version)?;
        require_digest("policy.artifact_digest", &self.policy.artifact_digest)?;
        require_identifier("issuer_id", &self.issuer_id)?;
        require_identifier("authority_epoch", &self.authority_epoch)?;
        require_identifier("generation_id", &self.generation_id)?;
        require_identifier("resource_state", &self.resource_state)?;
        require_identifier("eligible_state", &self.eligible_state)?;
        if self.retry_count > MAX_SAFE_INTEGER {
            return Err(invalid("retry_count exceeds the exact integer bound"));
        }
        if self.entity_revision > MAX_SAFE_INTEGER || self.input_revision > MAX_SAFE_INTEGER {
            return Err(invalid("lease revisions exceed the exact integer bound"));
        }
        if self.journal_prefix.journal_id.is_empty() {
            return Err(invalid("journal_prefix.journal_id must be nonempty"));
        }
        require_digest("journal_prefix.head_hash", &self.journal_prefix.head_hash)?;
        if self.evidence_refs.is_empty() {
            return Err(invalid(
                "a lease record requires at least one supporting evidence reference",
            ));
        }
        let mut seen = BTreeSet::new();
        for reference in &self.evidence_refs {
            reference.validate()?;
            let key = format!("{}:{}", reference.journal_id, reference.sequence.get());
            if !seen.insert(key) {
                return Err(invalid("evidence_refs must be unique"));
            }
        }
        check_maybe_string("last_failure_reason", &self.last_failure_reason)?;
        match self.lease_state {
            LeaseState::Unleased => {
                if !is_inapplicable_string(&self.lease_id) {
                    return Err(invalid(
                        "unleased lease_id must be not_applicable typed missingness",
                    ));
                }
                if !is_inapplicable_string(&self.lease_owner) {
                    return Err(invalid(
                        "unleased lease_owner must be not_applicable typed missingness",
                    ));
                }
                if !is_inapplicable_string(&self.owner_epoch) {
                    return Err(invalid(
                        "unleased owner_epoch must be not_applicable typed missingness",
                    ));
                }
                if !is_inapplicable_string(&self.session_epoch) {
                    return Err(invalid(
                        "unleased session_epoch must be not_applicable typed missingness",
                    ));
                }
                if !is_inapplicable_time(&self.leased_at) {
                    return Err(invalid(
                        "unleased leased_at must be not_applicable typed missingness",
                    ));
                }
                if !is_inapplicable_time(&self.lease_expires_at) {
                    return Err(invalid(
                        "unleased lease_expires_at must be not_applicable typed missingness",
                    ));
                }
            }
            LeaseState::Held => {
                if self.resource_state != self.eligible_state {
                    return Err(refused(format!(
                        "held lease requires resource_state {0:?} to equal eligible_state {1:?}",
                        self.resource_state, self.eligible_state
                    )));
                }
                present_text(&self.lease_id, "lease_id")?;
                present_text(&self.lease_owner, "lease_owner")?;
                present_text(&self.owner_epoch, "owner_epoch")?;
                check_maybe_string("session_epoch", &self.session_epoch)?;
                match &self.session_epoch {
                    MaybeString::Text(text) => require_identifier("session_epoch", text)?,
                    MaybeString::Missing(missing) if missing.reason == "not_applicable" => {}
                    MaybeString::Missing(missing) => {
                        return Err(invalid(format!(
                            "held session_epoch missingness reason {:?} is not not_applicable",
                            missing.reason
                        )))
                    }
                }
                let issued = present_time(&self.leased_at, "leased_at")?;
                let expires = present_time(&self.lease_expires_at, "lease_expires_at")?;
                require_same_clock(issued, expires, "lease issue and deadline")?;
                match boundary_reached(issued, expires) {
                    Ok(false) => {}
                    Ok(true) => {
                        return Err(invalid(
                            "held lease expiry must be strictly later than its issue coordinate",
                        ))
                    }
                    Err(error) => {
                        return Err(invalid(format!(
                            "held lease clock coordinates are invalid: {error}"
                        )))
                    }
                }
            }
        }
        Ok(())
    }

    /// Returns the held ownership fence or explains that no current ownership
    /// exists. Used by completion and the other ownership-clearing transitions.
    fn held_fence(&self) -> Result<(), ConnectorError> {
        if self.lease_state != LeaseState::Held {
            return Err(stale(
                "the lease is not held: ownership fields are inapplicable and no current token exists",
            ));
        }
        Ok(())
    }
}

fn parse_journal_prefix(value: &Value) -> Result<JournalPrefix, ConnectorError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("journal_prefix must be a JSON object"))?;
    ensure_closed(
        object,
        &["journal_id", "last_sequence", "head_hash"],
        "journal_prefix",
    )?;
    let journal_id = field_str(object, "journal_id", "journal_prefix")?.to_string();
    if journal_id.is_empty() {
        return Err(invalid("journal_prefix.journal_id must be nonempty"));
    }
    let last_sequence = PositiveInteger::new(revision_field(object, "last_sequence", "journal_prefix")?)?;
    let head_hash = Digest::parse(field_str(object, "head_hash", "journal_prefix")?)
        .map_err(|error| invalid(format!("journal_prefix.head_hash is invalid: {error}")))?;
    Ok(JournalPrefix {
        journal_id,
        last_sequence,
        head_hash,
    })
}

fn parse_evidence_refs(value: &Value) -> Result<Vec<EvidenceRef>, ConnectorError> {
    let array = value
        .as_array()
        .ok_or_else(|| invalid("evidence_refs must be a JSON array"))?;
    let mut references = Vec::with_capacity(array.len());
    for item in array {
        references.push(EvidenceRef::from_json(item)?);
    }
    Ok(references)
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/// Every lease transition this authority can perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseOperation {
    /// Take ownership of an eligible, currently unexpired-unleased resource.
    Claim,
    /// Extend a still-current hold on one authority clock/boot.
    Renew,
    /// Complete the held generation and clear ownership.
    Complete,
    /// Release ownership without a completion.
    Release,
    /// Record an authority-clock expiry and clear ownership.
    Expire,
    /// Fence a restarted authority epoch and clear ownership.
    Recover,
}

impl LeaseOperation {
    /// Wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            LeaseOperation::Claim => "claim",
            LeaseOperation::Renew => "renew",
            LeaseOperation::Complete => "complete",
            LeaseOperation::Release => "release",
            LeaseOperation::Expire => "expire",
            LeaseOperation::Recover => "recover",
        }
    }

    fn parse(value: &str) -> Result<Self, ConnectorError> {
        match value {
            "claim" => Ok(LeaseOperation::Claim),
            "renew" => Ok(LeaseOperation::Renew),
            "complete" => Ok(LeaseOperation::Complete),
            "release" => Ok(LeaseOperation::Release),
            "expire" => Ok(LeaseOperation::Expire),
            "recover" => Ok(LeaseOperation::Recover),
            other => Err(invalid(format!(
                "operation {other:?} is not one of claim, renew, complete, release, expire, recover"
            ))),
        }
    }

    /// Registered journal event kind owned by the execution write axis.
    ///
    /// Lease transitions fence execution resources, so claim-family
    /// transitions publish the registered `execution_claim` kind and
    /// completion publishes `task_output`. Each transition's payload records
    /// the operation, the admitted intent, the previous snapshot, and the new
    /// snapshot.
    fn event_kind(self) -> &'static str {
        match self {
            LeaseOperation::Complete => "task_output",
            LeaseOperation::Claim
            | LeaseOperation::Renew
            | LeaseOperation::Release
            | LeaseOperation::Expire
            | LeaseOperation::Recover => "execution_claim",
        }
    }
}

// ---------------------------------------------------------------------------
// Owner lease policy artifact
// ---------------------------------------------------------------------------

/// The owner-pinned lease policy: eligibility, TTL, and retry limit.
///
/// The values come from the installed immutable policy artifact, never from
/// the requesting worker, so a caller cannot choose its own duration or retry
/// budget by editing the intent.
#[derive(Debug, Clone, PartialEq)]
struct LeasePolicy {
    policy_id: String,
    policy_version: String,
    eligible_state: String,
    ttl_ms: f64,
    max_retries: u64,
}

fn parse_lease_policy(bytes: &[u8]) -> Result<LeasePolicy, ConnectorError> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|error| invalid(format!("lease policy is not JSON: {error}")))?;
    let object = value
        .as_object()
        .ok_or_else(|| invalid("lease policy must be a JSON object"))?;
    ensure_closed(
        object,
        &[
            "record_type",
            "schema_version",
            "policy_id",
            "policy_version",
            "eligible_state",
            "ttl_ms",
            "max_retries",
        ],
        "lease policy",
    )?;
    if field_str(object, "record_type", "lease policy")? != POLICY_RECORD_TYPE {
        return Err(invalid(format!(
            "lease policy record_type must be {POLICY_RECORD_TYPE:?}"
        )));
    }
    if field_str(object, "schema_version", "lease policy")? != LEASE_SCHEMA_VERSION {
        return Err(unsupported("lease policy schema_version is not supported"));
    }
    let ttl_ms = field(object, "ttl_ms", "lease policy")?
        .as_f64()
        .ok_or_else(|| invalid("lease policy requires numeric ttl_ms"))?;
    if !ttl_ms.is_finite() || ttl_ms <= 0.0 {
        return Err(refused(
            "lease policy ttl_ms must be a finite positive monotonic duration",
        ));
    }
    let max_retries = revision_field(object, "max_retries", "lease policy")?;
    if max_retries == 0 {
        return Err(refused("lease policy max_retries must be at least 1"));
    }
    let policy_id = field_str(object, "policy_id", "lease policy")?.to_string();
    let policy_version = field_str(object, "policy_version", "lease policy")?.to_string();
    let eligible_state = field_str(object, "eligible_state", "lease policy")?.to_string();
    require_identifier("lease policy policy_id", &policy_id)?;
    require_identifier("lease policy policy_version", &policy_version)?;
    require_identifier("lease policy eligible_state", &eligible_state)?;
    Ok(LeasePolicy {
        policy_id,
        policy_version,
        eligible_state,
        ttl_ms,
        max_retries,
    })
}

// ---------------------------------------------------------------------------
// Transition intent artifact
// ---------------------------------------------------------------------------

/// The fence a requester asserts it observed before asking for a transition.
#[derive(Debug, Clone, PartialEq)]
struct ExpectedFence {
    entity_revision: Revision,
    input_revision: Revision,
    generation_id: String,
    authority_epoch: MaybeString,
    lease_id: MaybeString,
    owner_epoch: MaybeString,
    session_epoch: MaybeString,
}

impl ExpectedFence {
    fn parse(value: &Value) -> Result<Self, ConnectorError> {
        let object = value
            .as_object()
            .ok_or_else(|| invalid("intent.expected must be a JSON object"))?;
        ensure_closed(
            object,
            &[
                "entity_revision",
                "input_revision",
                "generation_id",
                "authority_epoch",
                "lease_id",
                "owner_epoch",
                "session_epoch",
            ],
            "intent.expected",
        )?;
        Ok(ExpectedFence {
            entity_revision: revision_field(object, "entity_revision", "intent.expected")?,
            input_revision: revision_field(object, "input_revision", "intent.expected")?,
            generation_id: field_str(object, "generation_id", "intent.expected")?.to_string(),
            authority_epoch: maybe_string_field(object, "authority_epoch", "intent.expected")?,
            lease_id: maybe_string_field(object, "lease_id", "intent.expected")?,
            owner_epoch: maybe_string_field(object, "owner_epoch", "intent.expected")?,
            session_epoch: maybe_string_field(object, "session_epoch", "intent.expected")?,
        })
    }

    fn require_matches(
        &self,
        current: &LeaseRecord,
        require_session: bool,
        require_authority_epoch: bool,
    ) -> Result<(), ConnectorError> {
        if self.entity_revision != current.entity_revision {
            return Err(stale(format!(
                "expected entity_revision {} is not the current {}",
                self.entity_revision, current.entity_revision
            )));
        }
        if self.input_revision != current.input_revision {
            return Err(stale(format!(
                "expected input_revision {} is not the current {}",
                self.input_revision, current.input_revision
            )));
        }
        if self.generation_id != current.generation_id {
            return Err(stale("expected generation_id is not the current generation"));
        }
        require_same_fence(&self.lease_id, &current.lease_id, "lease_id")?;
        require_same_fence(&self.owner_epoch, &current.owner_epoch, "owner_epoch")?;
        if require_session {
            require_same_fence(&self.session_epoch, &current.session_epoch, "session_epoch")?;
        }
        if require_authority_epoch {
            match &self.authority_epoch {
                MaybeString::Text(epoch) if *epoch == current.authority_epoch => {}
                MaybeString::Text(_) => {
                    return Err(stale(
                        "expected authority_epoch is not the lease's current authority lifetime",
                    ))
                }
                MaybeString::Missing(missing) => {
                    return Err(invalid(format!(
                        "the expected fence must name the current authority epoch; found missingness {:?}",
                        missing.reason
                    )))
                }
            }
        }
        Ok(())
    }
}

fn require_same_fence(
    expected: &MaybeString,
    actual: &MaybeString,
    field: &str,
) -> Result<(), ConnectorError> {
    if expected == actual {
        return Ok(());
    }
    Err(stale(format!(
        "expected {field} does not match the current lease fence"
    )))
}

/// The immutable admitted transition command.
struct TransitionIntent {
    reference: ArtifactReference,
    operation: LeaseOperation,
    resource: ResourceReference,
    expected: ExpectedFence,
    authority_epoch: String,
    policy_pin: VersionPin,
    policy_reference: ArtifactReference,
    issued_at: TimePoint,
    lease_owner: MaybeString,
    session_epoch: MaybeString,
    failure_reason: MaybeString,
    producer_sequence: PositiveInteger,
    manifest: Manifest,
    response: ArtifactReference,
}

fn parse_manifest(value: &Value) -> Result<Manifest, ConnectorError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("intent.manifest must be a JSON object"))?;
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
        "intent.manifest",
    )?;
    let event_kinds = field(object, "event_kinds", "intent.manifest")?
        .as_array()
        .ok_or_else(|| invalid("intent.manifest.event_kinds must be an array"))?
        .iter()
        .map(|kind| {
            kind.as_str()
                .map(str::to_string)
                .ok_or_else(|| invalid("intent.manifest.event_kinds entries must be strings"))
        })
        .collect::<Result<Vec<String>, ConnectorError>>()?;
    if event_kinds.is_empty() {
        return Err(invalid("intent.manifest.event_kinds must not be empty"));
    }
    let task = field(object, "task", "intent.manifest")?.clone();
    let subject = field(object, "subject", "intent.manifest")?.clone();
    if !task.is_object() || !subject.is_object() {
        return Err(invalid(
            "intent.manifest task and subject must be EvidenceMap objects",
        ));
    }
    Ok(Manifest {
        record_type: field_str(object, "record_type", "intent.manifest")?.to_string(),
        schema_version: field_str(object, "schema_version", "intent.manifest")?.to_string(),
        run_id: field_str(object, "run_id", "intent.manifest")?.to_string(),
        task,
        subject,
        event_kinds,
        admission_ref: field_str(object, "admission_ref", "intent.manifest")?.to_string(),
        manifest_hash: field_str(object, "manifest_hash", "intent.manifest")?.to_string(),
    })
}

fn parse_intent(
    bytes: &[u8],
    reference: &ArtifactReference,
) -> Result<TransitionIntent, ConnectorError> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|error| invalid(format!("lease transition intent is not JSON: {error}")))?;
    let object = value
        .as_object()
        .ok_or_else(|| invalid("lease transition intent must be a JSON object"))?;
    ensure_closed(
        object,
        &[
            "record_type",
            "schema_version",
            "operation",
            "resource",
            "expected",
            "authority_epoch",
            "policy",
            "issued_at",
            "lease_owner",
            "session_epoch",
            "failure_reason",
            "producer_sequence",
            "manifest",
            "response",
        ],
        "lease transition intent",
    )?;
    if field_str(object, "record_type", "intent")? != INTENT_RECORD_TYPE {
        return Err(invalid(format!(
            "intent record_type must be {INTENT_RECORD_TYPE:?}"
        )));
    }
    if field_str(object, "schema_version", "intent")? != LEASE_SCHEMA_VERSION {
        return Err(unsupported("intent schema_version is not supported"));
    }
    let policy_object = field_object(object, "policy", "intent")?;
    ensure_closed(policy_object, &["pin", "reference"], "intent.policy")?;
    let policy_pin = VersionPin::from_json(field(policy_object, "pin", "intent.policy")?)?;
    let policy_reference =
        ArtifactReference::from_json(field(policy_object, "reference", "intent.policy")?)?;
    policy_reference.validate()?;
    if policy_reference.digest != policy_pin.artifact_digest {
        return Err(invalid(
            "intent.policy.reference digest does not match the pinned policy artifact_digest",
        ));
    }
    let issued_at: TimePoint =
        serde_json::from_value(field(object, "issued_at", "intent")?.clone())
            .map_err(|error| invalid(format!("intent.issued_at is not a TimePoint: {error}")))?;
    let producer_sequence = PositiveInteger::new(revision_field(
        object,
        "producer_sequence",
        "intent",
    )?)?;
    let response = ArtifactReference::from_json(field(object, "response", "intent")?)?;
    response.validate()?;
    Ok(TransitionIntent {
        reference: reference.clone(),
        operation: LeaseOperation::parse(field_str(object, "operation", "intent")?)?,
        resource: ResourceReference::from_json(field(object, "resource", "intent")?)?,
        expected: ExpectedFence::parse(field(object, "expected", "intent")?)?,
        authority_epoch: field_str(object, "authority_epoch", "intent")?.to_string(),
        policy_pin,
        policy_reference,
        issued_at,
        lease_owner: maybe_string_field(object, "lease_owner", "intent")?,
        session_epoch: maybe_string_field(object, "session_epoch", "intent")?,
        failure_reason: maybe_string_field(object, "failure_reason", "intent")?,
        producer_sequence,
        manifest: parse_manifest(field(object, "manifest", "intent")?)?,
        response,
    })
}

impl TransitionIntent {
    fn load_policy(&self, principal: &AuthenticatedPrincipal) -> Result<LeasePolicy, ConnectorError> {
        let bytes = load_artifact(principal, &self.policy_reference)?;
        let policy = parse_lease_policy(&bytes)?;
        if policy.policy_id != self.policy_pin.id
            || policy.policy_version != self.policy_pin.version
        {
            return Err(invalid(format!(
                "installed policy artifact names {}/{} but the intent pins {}/{}",
                policy.policy_id,
                policy.policy_version,
                self.policy_pin.id,
                self.policy_pin.version
            )));
        }
        Ok(policy)
    }

    fn require_resource(&self, current: &LeaseRecord) -> Result<(), ConnectorError> {
        if self.resource != current.resource {
            return Err(invalid(
                "the transition intent names a different resource than the current lease record",
            ));
        }
        Ok(())
    }

    fn require_same_authority(
        &self,
        current: &LeaseRecord,
        descriptor: &ProducerDescriptor,
        what: &str,
    ) -> Result<(), ConnectorError> {
        if current.authority_epoch != self.authority_epoch {
            return Err(stale(format!(
                "{what} belongs to the current authority epoch; a restarted epoch must fence the old lifetime with recover first"
            )));
        }
        if current.issuer_id != descriptor.producer_id {
            return Err(stale(format!(
                "{what} is not issued by this authority identity"
            )));
        }
        Ok(())
    }

    fn require_policy_unchanged(
        &self,
        current: &LeaseRecord,
        policy: &LeasePolicy,
    ) -> Result<(), ConnectorError> {
        if self.policy_pin != current.policy {
            return Err(refused(
                "this transition must reuse the policy pinned at claim; a policy change requires a new claim",
            ));
        }
        if policy.max_retries != current.max_retries_effective.get() {
            return Err(integrity(
                "the pinned policy content disagrees with max_retries_effective",
            ));
        }
        if policy.eligible_state != current.eligible_state {
            return Err(integrity(
                "the pinned policy content disagrees with the record's eligible_state",
            ));
        }
        Ok(())
    }

    fn require_failure_reason(&self, what: &str) -> Result<String, ConnectorError> {
        match &self.failure_reason {
            MaybeString::Text(reason) => {
                require_identifier("intent.failure_reason", reason)?;
                Ok(reason.clone())
            }
            MaybeString::Missing(missing) => Err(invalid(format!(
                "{what} must record the declared owner-policy failure code; found missingness {:?}",
                missing.reason
            ))),
        }
    }

    fn apply(
        &self,
        current: &LeaseRecord,
        now: &TimePoint,
        descriptor: &ProducerDescriptor,
        policy: &LeasePolicy,
    ) -> Result<LeaseRecord, ConnectorError> {
        current.validate_snapshot()?;
        self.require_resource(current)?;
        require_identifier("intent.authority_epoch", &self.authority_epoch)?;
        match self.operation {
            LeaseOperation::Claim => self.apply_claim(current, now, descriptor, policy),
            LeaseOperation::Renew => self.apply_renew(current, now, descriptor, policy),
            LeaseOperation::Complete => self.apply_complete(current, now, descriptor, policy),
            LeaseOperation::Release => self.apply_release(current, now, descriptor, policy),
            LeaseOperation::Expire => self.apply_expire(current, now, descriptor, policy),
            LeaseOperation::Recover => self.apply_recover(current, now, descriptor, policy),
        }
    }

    fn apply_claim(
        &self,
        current: &LeaseRecord,
        now: &TimePoint,
        descriptor: &ProducerDescriptor,
        policy: &LeasePolicy,
    ) -> Result<LeaseRecord, ConnectorError> {
        // EK-LEASE: eligibility is checked without mutating the owner state.
        if current.resource_state != current.eligible_state {
            return Err(refused(format!(
                "claim refused: resource state {:?} is not the eligible state {:?}",
                current.resource_state, current.eligible_state
            )));
        }
        if policy.eligible_state != current.eligible_state {
            return Err(refused(
                "claim refused: the pinned policy governs a different eligible state",
            ));
        }
        let mut retry_count = current.retry_count;
        match current.lease_state {
            LeaseState::Held => {
                if current.authority_epoch != self.authority_epoch {
                    return Err(prerequisite(
                        "claim refused: a held lease belongs to a restarted authority epoch; fence the old epoch with a recover transition before reclaiming",
                    ));
                }
                if current.issuer_id != descriptor.producer_id {
                    return Err(stale(
                        "claim refused: the held lease was issued by a different authority identity",
                    ));
                }
                let old_deadline = present_time(&current.lease_expires_at, "lease_expires_at")?;
                match boundary_reached(now, old_deadline) {
                    Ok(true) => {}
                    Ok(false) => {
                        return Err(busy(
                            "claim refused: an unexpired lease is held on this resource",
                        ))
                    }
                    Err(error) => {
                        return Err(prerequisite(format!(
                            "claim refused: lease expiry cannot be established on this authority clock/boot ({error}); fence the old epoch with a recover transition"
                        )))
                    }
                }
                self.expected
                    .require_matches(current, false, true)?;
                // A replacement lease may only start at or after the expired deadline.
                match boundary_reached(&self.issued_at, old_deadline) {
                    Ok(true) => {}
                    Ok(false) => {
                        return Err(stale(
                            "claim issued_at precedes the expired lease deadline; a replacement hold may not overlap the old generation",
                        ))
                    }
                    Err(error) => {
                        return Err(prerequisite(format!(
                            "claim cannot order issued_at against the expired lease deadline: {error}"
                        )))
                    }
                }
                retry_count = increment_retry(retry_count, "expired claim generation")?;
            }
            LeaseState::Unleased => {
                self.expected
                    .require_matches(current, false, false)?;
            }
        }
        if retry_count > policy.max_retries {
            return Err(exhausted(format!(
                "claim refused: {retry_count} failed generations exceed the policy retry limit {}",
                policy.max_retries
            )));
        }
        require_not_after(now, &self.issued_at, "claim")?;
        let lease_owner = match &self.lease_owner {
            MaybeString::Text(owner) => {
                require_identifier("intent.lease_owner", owner)?;
                owner.clone()
            }
            MaybeString::Missing(missing) => {
                return Err(invalid(format!(
                    "a claim must name the owner it assigns; intent.lease_owner missingness {:?} is not a usable owner identity",
                    missing.reason
                )))
            }
        };
        check_maybe_string("intent.session_epoch", &self.session_epoch)?;
        if let MaybeString::Missing(missing) = &self.session_epoch {
            if missing.reason != "not_applicable" {
                return Err(invalid(format!(
                    "claim session_epoch missingness reason {:?} is not not_applicable",
                    missing.reason
                )));
            }
        }
        let next_revision = advance_revision(current.entity_revision, "entity_revision")?;
        let expires_at = shift_deadline(&self.issued_at, policy.ttl_ms)?;
        // A fencing token is authority-assigned from the command identity: an
        // identical retry reproduces it, and no other command can reuse it.
        let command_scope = format!(
            "{}:{}:{}",
            descriptor.producer_id,
            self.authority_epoch,
            self.producer_sequence.get()
        );
        let lease_id = fence_token("lease", &current.resource, &command_scope, next_revision);
        let owner_epoch = fence_token("owner", &current.resource, &command_scope, next_revision);
        let generation_id =
            fence_token("generation", &current.resource, &command_scope, next_revision);
        Ok(LeaseRecord {
            record_type: LEASE_RECORD_TYPE.to_string(),
            schema_version: LEASE_SCHEMA_VERSION.to_string(),
            resource: current.resource.clone(),
            policy: self.policy_pin.clone(),
            issuer_id: descriptor.producer_id.clone(),
            authority_epoch: self.authority_epoch.clone(),
            entity_revision: next_revision,
            input_revision: current.input_revision,
            generation_id,
            resource_state: current.resource_state.clone(),
            eligible_state: current.eligible_state.clone(),
            lease_state: LeaseState::Held,
            lease_id: MaybeString::Text(lease_id),
            lease_owner: MaybeString::Text(lease_owner),
            owner_epoch: MaybeString::Text(owner_epoch),
            session_epoch: self.session_epoch.clone(),
            leased_at: MaybeTimePoint::Present(self.issued_at.clone()),
            lease_expires_at: MaybeTimePoint::Present(expires_at),
            retry_count,
            max_retries_effective: PositiveInteger::new(policy.max_retries)?,
            last_failure_reason: inapplicable_string("last_failure_reason"),
            journal_prefix: current.journal_prefix.clone(),
            evidence_refs: current.evidence_refs.clone(),
        })
    }

    fn apply_renew(
        &self,
        current: &LeaseRecord,
        now: &TimePoint,
        descriptor: &ProducerDescriptor,
        policy: &LeasePolicy,
    ) -> Result<LeaseRecord, ConnectorError> {
        current.held_fence()?;
        self.require_same_authority(current, descriptor, "renewal")?;
        self.expected.require_matches(current, true, true)?;
        self.require_policy_unchanged(current, policy)?;
        require_not_after(now, &self.issued_at, "renewal")?;
        let deadline = present_time(&current.lease_expires_at, "lease_expires_at")?;
        require_unexpired(now, deadline, "renewal")?;
        let issued = present_time(&current.leased_at, "leased_at")?;
        match boundary_reached(&self.issued_at, issued) {
            Ok(true) => {}
            Ok(false) => {
                return Err(stale(
                    "renewal issued_at precedes the current lease issue coordinate",
                ))
            }
            Err(error) => {
                return Err(prerequisite(format!(
                    "renewal cannot order issued_at against the current lease issue: {error}"
                )))
            }
        }
        let next_deadline = shift_deadline(&self.issued_at, policy.ttl_ms)?;
        if next_deadline.monotonic_offset_ms <= deadline.monotonic_offset_ms {
            return Err(refused(
                "renewal must extend the deadline beyond the current lease_expires_at",
            ));
        }
        Ok(LeaseRecord {
            entity_revision: advance_revision(current.entity_revision, "entity_revision")?,
            lease_expires_at: MaybeTimePoint::Present(next_deadline),
            ..current.clone()
        })
    }

    fn apply_complete(
        &self,
        current: &LeaseRecord,
        now: &TimePoint,
        descriptor: &ProducerDescriptor,
        policy: &LeasePolicy,
    ) -> Result<LeaseRecord, ConnectorError> {
        current.held_fence()?;
        self.require_same_authority(current, descriptor, "completion")?;
        self.expected.require_matches(current, true, true)?;
        self.require_policy_unchanged(current, policy)?;
        require_not_after(now, &self.issued_at, "completion")?;
        let deadline = present_time(&current.lease_expires_at, "lease_expires_at")?;
        require_unexpired(now, deadline, "completion")?;
        Ok(released_successor(current, advance_revision(
            current.entity_revision,
            "entity_revision",
        )?))
    }

    fn apply_release(
        &self,
        current: &LeaseRecord,
        now: &TimePoint,
        descriptor: &ProducerDescriptor,
        policy: &LeasePolicy,
    ) -> Result<LeaseRecord, ConnectorError> {
        current.held_fence()?;
        self.require_same_authority(current, descriptor, "release")?;
        self.expected.require_matches(current, false, true)?;
        self.require_policy_unchanged(current, policy)?;
        require_not_after(now, &self.issued_at, "release")?;
        // A release is bookkeeping for a still-current token; it is never a
        // claim that the native work stopped.
        Ok(released_successor(current, advance_revision(
            current.entity_revision,
            "entity_revision",
        )?))
    }

    fn apply_expire(
        &self,
        current: &LeaseRecord,
        now: &TimePoint,
        descriptor: &ProducerDescriptor,
        policy: &LeasePolicy,
    ) -> Result<LeaseRecord, ConnectorError> {
        current.held_fence()?;
        self.require_same_authority(current, descriptor, "expiry")?;
        self.expected.require_matches(current, false, true)?;
        self.require_policy_unchanged(current, policy)?;
        require_not_after(now, &self.issued_at, "expiry")?;
        let deadline = present_time(&current.lease_expires_at, "lease_expires_at")?;
        require_expired(now, deadline, "expiry")?;
        let reason = self.require_failure_reason("expiry")?;
        let retry_count = increment_retry(current.retry_count, "expired generation")?;
        let mut successor = released_successor(current, advance_revision(
            current.entity_revision,
            "entity_revision",
        )?);
        successor.retry_count = retry_count;
        successor.last_failure_reason = MaybeString::Text(reason);
        Ok(successor)
    }

    fn apply_recover(
        &self,
        current: &LeaseRecord,
        now: &TimePoint,
        descriptor: &ProducerDescriptor,
        policy: &LeasePolicy,
    ) -> Result<LeaseRecord, ConnectorError> {
        current.held_fence()?;
        if self.authority_epoch == current.authority_epoch {
            return Err(stale(
                "recovery requires a restarted authority epoch; the current epoch is still authoritative",
            ));
        }
        self.expected.require_matches(current, false, true)?;
        self.require_policy_unchanged(current, policy)?;
        require_not_after(now, &self.issued_at, "recovery")?;
        let reason = self.require_failure_reason("recovery")?;
        let retry_count = increment_retry(current.retry_count, "recovered generation")?;
        // The old epoch is fenced durably here. Lease times and boot offsets are
        // deliberately not compared: reclamation revokes local commit authority
        // only and is not proof that external work stopped.
        let mut successor = released_successor(current, advance_revision(
            current.entity_revision,
            "entity_revision",
        )?);
        successor.issuer_id = descriptor.producer_id.clone();
        successor.authority_epoch = self.authority_epoch.clone();
        successor.retry_count = retry_count;
        successor.last_failure_reason = MaybeString::Text(reason);
        Ok(successor)
    }

    fn submission(
        &self,
        previous: &LeaseRecord,
        next: &LeaseRecord,
        event_kind: &str,
    ) -> Result<EventSubmission, ConnectorError> {
        let mut artifact_refs = vec![
            self.reference.clone(),
            self.policy_reference.clone(),
            self.response.clone(),
        ];
        // The admitted intent is the authoritative effect of this owner-local
        // transition; it is installed durably before the commit.
        let mut seen = BTreeSet::new();
        artifact_refs.retain(|reference| seen.insert(reference.to_json().to_string()));
        Ok(EventSubmission {
            producer_sequence: Some(self.producer_sequence),
            event_kind: event_kind.to_string(),
            event_schema_version: LEASE_SCHEMA_VERSION.to_string(),
            occurred_at: MaybeTimePoint::Present(self.issued_at.clone()),
            payload: EvidencePayload {
                data: json!({
                    "operation": self.operation.as_str(),
                    "intent": self.reference.to_json(),
                    "previous": previous.to_json(),
                    "lease": next.to_json(),
                }),
                measurements: Vec::new(),
                evidence_refs: Vec::new(),
                artifact_refs,
            },
        })
    }
}

fn released_successor(current: &LeaseRecord, next_revision: Revision) -> LeaseRecord {
    LeaseRecord {
        record_type: LEASE_RECORD_TYPE.to_string(),
        schema_version: LEASE_SCHEMA_VERSION.to_string(),
        resource: current.resource.clone(),
        policy: current.policy.clone(),
        issuer_id: current.issuer_id.clone(),
        authority_epoch: current.authority_epoch.clone(),
        entity_revision: next_revision,
        input_revision: current.input_revision,
        generation_id: current.generation_id.clone(),
        resource_state: current.resource_state.clone(),
        eligible_state: current.eligible_state.clone(),
        lease_state: LeaseState::Unleased,
        lease_id: inapplicable_string("lease_id"),
        lease_owner: inapplicable_string("lease_owner"),
        owner_epoch: inapplicable_string("owner_epoch"),
        session_epoch: inapplicable_string("session_epoch"),
        leased_at: inapplicable_time("leased_at"),
        lease_expires_at: inapplicable_time("lease_expires_at"),
        retry_count: current.retry_count,
        max_retries_effective: current.max_retries_effective,
        last_failure_reason: inapplicable_string("last_failure_reason"),
        journal_prefix: current.journal_prefix.clone(),
        evidence_refs: current.evidence_refs.clone(),
    }
}

fn fence_token(prefix: &str, resource: &ResourceReference, scope: &str, revision: Revision) -> String {
    format!(
        "{prefix}:{}:{}:{}:{}:{revision}",
        resource.owner_domain, resource.entity_type, resource.entity_id, scope
    )
}

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

// ---------------------------------------------------------------------------
// Public interface
// ---------------------------------------------------------------------------

/// Applies one fenced lease transition and commits its evidence atomically.
///
/// The owner supplies the durable current snapshot and an installed immutable
/// [`INTENT_RECORD_TYPE`] artifact (the admitted input and idempotency key).
/// The caller is authorized as the resource's registered owner writer; the
/// policy artifact is loaded from its pinned reference so the worker cannot
/// choose its own TTL, eligibility, or retry budget.
///
/// Claim never changes `resource_state`; completion, release, expiry, and
/// confirmed-death recovery clear ownership atomically. A rejected stale
/// transition performs no journal write and returns no successor snapshot.
pub fn transition_lease(
    principal: &AuthenticatedPrincipal,
    current: &LeaseRecord,
    intent: &ArtifactReference,
    now: &TimePoint,
) -> Result<LeaseRecord, ConnectorError> {
    let intent_bytes = load_artifact(principal, intent)?;
    let transition = parse_intent(&intent_bytes, intent)?;
    // Only the registered resource-owner write axis may run a transition.
    let event_kind = transition.operation.event_kind();
    let descriptor = authorize_owner(principal, &transition.resource.owner_domain, event_kind)?;
    if descriptor.owner_domain != transition.resource.owner_domain {
        return Err(integrity(
            "owner authorization assigned a different owner domain than the resource",
        ));
    }
    let policy = transition.load_policy(principal)?;
    let successor = transition.apply(current, now, &descriptor, &policy)?;
    let submission = transition.submission(current, &successor, event_kind)?;
    // EK-ATOMICITY: the admitted intent, the journal event, and the replayable
    // response reference commit as one owner-local effect before acknowledgement.
    let envelopes = commit_owner_effect(
        principal,
        &transition.manifest,
        intent,
        &[submission],
        &transition.response,
    )?;
    let mut result = successor;
    for envelope in &envelopes {
        let reference = evidence_ref_for(envelope)?;
        let duplicate = result.evidence_refs.iter().any(|existing| {
            existing.journal_id == reference.journal_id
                && existing.sequence == reference.sequence
        });
        if !duplicate {
            result.evidence_refs.push(reference);
        }
    }
    let head = envelopes
        .last()
        .ok_or_else(|| integrity("owner effect commit produced no journal event"))?;
    result.journal_prefix = JournalPrefix {
        journal_id: head.journal_id.clone(),
        last_sequence: head.journal_sequence,
        head_hash: head.event_hash.clone(),
    };
    result.validate_snapshot()?;
    Ok(result)
}

/// Validates a lease for use as current commit authority.
///
/// Checks that the lease is held, that its resource state is compatible, that
/// the lease identity/owner/epoch fields and the applicable session epoch are
/// present, that the caller's entity and input revisions and owner epoch are
/// exactly current, and that the authority-clock deadline has not been reached
/// on the same clock and boot.
///
/// A missing session epoch is only acceptable when the lease itself declares
/// the session epoch inapplicable. Elapsed time is never inferred across a
/// restarted authority clock: an incomparable coordinate is reported as a
/// prerequisite failure, never as expiry.
pub fn validate_lease(
    lease: &LeaseRecord,
    now: &TimePoint,
    entity_revision: Revision,
    input_revision: Revision,
    owner_epoch: &str,
    session_epoch: &MaybeString,
) -> Result<(), ConnectorError> {
    lease.validate_snapshot()?;
    lease.held_fence()?;
    if entity_revision != lease.entity_revision {
        return Err(stale(format!(
            "entity_revision {entity_revision} is not the leased revision {}",
            lease.entity_revision
        )));
    }
    if input_revision != lease.input_revision {
        return Err(stale(format!(
            "input_revision {input_revision} is not the leased input revision {}",
            lease.input_revision
        )));
    }
    require_identifier("owner_epoch", owner_epoch)?;
    match &lease.owner_epoch {
        MaybeString::Text(current) if current == owner_epoch => {}
        MaybeString::Text(_) => {
            return Err(stale(
                "owner_epoch does not match the lease's current owner epoch",
            ))
        }
        MaybeString::Missing(missing) => {
            return Err(invalid(format!(
                "held lease owner_epoch missingness {:?} is not a usable fence",
                missing.reason
            )))
        }
    }
    match session_epoch {
        MaybeString::Text(expected) => {
            require_identifier("session_epoch", expected)?;
            match &lease.session_epoch {
                MaybeString::Text(current) if current == expected => {}
                MaybeString::Text(_) => {
                    return Err(stale(
                        "session_epoch does not match the lease's bound session epoch",
                    ))
                }
                MaybeString::Missing(missing) if missing.reason == "not_applicable" => {
                    return Err(stale(
                        "the lease declares its session epoch inapplicable; the caller supplied an applicable session epoch",
                    ))
                }
                MaybeString::Missing(_) => {
                    return Err(stale("held lease session epoch is not applicable"))
                }
            }
        }
        MaybeString::Missing(missing) => {
            check_missing("session_epoch", missing)?;
            if missing.reason != "not_applicable" {
                return Err(invalid(format!(
                    "session_epoch missingness reason {:?} is not not_applicable",
                    missing.reason
                )));
            }
            if !is_inapplicable_string(&lease.session_epoch) {
                return Err(stale(
                    "the lease is bound to an applicable session epoch that the caller did not supply",
                ));
            }
        }
    }
    let issued = present_time(&lease.leased_at, "leased_at")?;
    let deadline = present_time(&lease.lease_expires_at, "lease_expires_at")?;
    require_not_after(now, issued, "lease validation")?;
    require_unexpired(now, deadline, "lease validation")?;
    Ok(())
}

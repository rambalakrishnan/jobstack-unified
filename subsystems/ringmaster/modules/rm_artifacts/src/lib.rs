//! `rm_artifacts`: tier-3 `CollectArtifacts` handler for Ringmaster.
//!
//! Implements the external-connector artifact surface (seam mapping §14.6,
//! RM-C47/RM-C48) over the journaled evidence core:
//!
//! - [`collect_inventory`] serves `inventory` and `named` selectors as an
//!   [`ArtifactInventory`]. Named requests return exactly the requested names
//!   in the requested order, including explicit missing slots. Available
//!   content always matches its expected digest; known identity survives byte
//!   loss as a reasoned `observation_lost` absence, never as erased identity
//!   or established emptiness.
//! - [`collect_chunk`] serves `bytes` selectors as an [`ArtifactChunk`] with
//!   canonical padded base64, verified lengths, chunk/full digests, strict
//!   bounds, and exact EOF semantics. Non-EOF successful chunks always advance.
//!
//! Handle scoping (EXT-ARTIFACTS): artifact names and digests resolve only
//! within the authorized handle's retained evidence. Handles are bound to
//! their retained journal by [`register_handle`]; named artifacts are bound
//! by [`publish_named_artifact`], which journals an `artifact_available` event
//! citing already-installed bytes before the name becomes citable. Digests
//! outside the handle's retained evidence are never fetched, and no caller
//! URL, filesystem path, workflow rerun, or browser session is consulted to
//! manufacture artifacts.
//!
//! Every slot and chunk carries supporting evidence references that are
//! verified with [`rm_evidence::resolve_evidence`] against the retained
//! prefix reported in the response before the response is returned. Access
//! classification is enforced by [`rm_evidence::load_artifact`] and never
//! weakened during transfer. There are no in-band nulls: absences are typed
//! [`Missing`] envelopes.

#![forbid(unsafe_code)]

use rm_evidence::{EventSubmission, EvidencePayload, MaybeTimePoint};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    LazyLock, Mutex, MutexGuard,
};

pub use rm_authority::{AuthenticatedPrincipal, ConnectorError};
pub use rm_evidence::{
    AccessClass, ArtifactReference, Digest, EvidenceRef, JournalPrefix, Manifest, MaybeDigest,
    Missing, PositiveInteger, MAX_SAFE_INTEGER,
};

/// Owner domain that publishes artifact registrations.
pub const ARTIFACT_OWNER_DOMAIN: &str = "artifact";
/// Journal event kind recording an available artifact.
pub const ARTIFACT_AVAILABLE_KIND: &str = "artifact_available";
/// Connector request record discriminator.
pub const CONNECTOR_REQUEST_TYPE: &str = "connector_request";
/// External connector schema version served by this module.
pub const CONNECTOR_SCHEMA_VERSION: &str = "external-connector/0.1.0";
/// Connector verb served by this module.
pub const COLLECT_ARTIFACTS_VERB: &str = "CollectArtifacts";


// ---------------------------------------------------------------------------
// Error constructors
// ---------------------------------------------------------------------------

fn err(
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
    err(
        "INVALID_REQUEST",
        "request",
        detail.into(),
        "not_dispatched",
        "operator_review",
    )
}

fn unsupported_version(detail: impl Into<String>) -> ConnectorError {
    err(
        "UNSUPPORTED_VERSION",
        "request",
        detail.into(),
        "not_dispatched",
        "operator_review",
    )
}

fn unknown_handle(detail: impl Into<String>) -> ConnectorError {
    err(
        "UNKNOWN_HANDLE",
        "request",
        detail.into(),
        "not_dispatched",
        "operator_review",
    )
}

fn unavailable(detail: impl Into<String>) -> ConnectorError {
    err(
        "ARTIFACT_UNAVAILABLE",
        "connector",
        detail.into(),
        "not_dispatched",
        "operator_review",
    )
}

fn integrity(detail: impl Into<String>) -> ConnectorError {
    err(
        "INTEGRITY_CONFLICT",
        "connector",
        detail.into(),
        "not_dispatched",
        "operator_review",
    )
}

// ---------------------------------------------------------------------------
// Wire shapes
// ---------------------------------------------------------------------------

/// Stable local handle identity (external-connector `HandleReference`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandleReference {
    pub connector_id: String,
    pub local_handle: String,
}

impl HandleReference {
    /// Closed-object JSON projection.
    pub fn to_json(&self) -> Value {
        json!({
            "connector_id": self.connector_id,
            "local_handle": self.local_handle,
        })
    }
}

/// Artifact selector (external-connector `ArtifactSelector`).
///
/// There is deliberately no URL/path variant: bytes selectors name an already
/// registered, authorized digest, never an arbitrary location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactSelector {
    /// Full handle-scoped inventory.
    Inventory,
    /// Exactly these names, in this order, including missing slots.
    Named {
        /// Nonempty unique identifiers.
        names: Vec<String>,
    },
    /// One byte range of a handle-retained digest.
    Bytes {
        /// Registered digest within the handle's retained evidence.
        digest: Digest,
        /// Starting offset in `0..=size_bytes`.
        offset: u64,
        /// Positive maximum bytes to return.
        max_bytes: u64,
    },
}

/// Validated connector command envelope for `CollectArtifacts`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorRequest {
    pub record_type: String,
    pub schema_version: String,
    pub request_id: String,
    pub connector_id: String,
    pub operation: String,
    pub handle: HandleReference,
    pub selector: ArtifactSelector,
}

impl ConnectorRequest {
    /// Builds a well-formed `CollectArtifacts` command.
    pub fn new(
        connector_id: &str,
        request_id: &str,
        handle: HandleReference,
        selector: ArtifactSelector,
    ) -> Self {
        ConnectorRequest {
            record_type: CONNECTOR_REQUEST_TYPE.to_string(),
            schema_version: CONNECTOR_SCHEMA_VERSION.to_string(),
            request_id: request_id.to_string(),
            connector_id: connector_id.to_string(),
            operation: COLLECT_ARTIFACTS_VERB.to_string(),
            handle,
            selector,
        }
    }
}

/// Present artifact content or reasoned absence (`MaybeArtifact`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaybeArtifact {
    Present(ArtifactReference),
    Missing(Missing),
}

/// One named artifact slot (external-connector `ArtifactSlot`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactSlot {
    pub name: String,
    pub expected_digest: MaybeDigest,
    pub content: MaybeArtifact,
    pub evidence_refs: Vec<EvidenceRef>,
}

impl ArtifactSlot {
    /// Closed-object JSON projection without in-band nulls.
    pub fn to_json(&self) -> Value {
        let expected = match &self.expected_digest {
            MaybeDigest::Present(digest) => Value::String(digest.as_str().to_string()),
            MaybeDigest::Missing(missing) => missing_value(missing),
        };
        let content = match &self.content {
            MaybeArtifact::Present(reference) => reference.to_json(),
            MaybeArtifact::Missing(missing) => missing_value(missing),
        };
        json!({
            "name": self.name,
            "expected_digest": expected,
            "content": content,
            "evidence_refs": self.evidence_refs.iter().map(EvidenceRef::to_json).collect::<Vec<Value>>(),
        })
    }
}

/// Artifact inventory response (external-connector `ArtifactInventory`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactInventory {
    pub kind: String,
    pub handle: HandleReference,
    pub artifacts: Vec<ArtifactSlot>,
    pub coverage: String,
    pub evidence_prefix: JournalPrefix,
    pub limitations: Vec<String>,
}

impl ArtifactInventory {
    /// Closed-object JSON projection without in-band nulls.
    pub fn to_json(&self) -> Value {
        json!({
            "kind": self.kind,
            "handle": self.handle.to_json(),
            "artifacts": self.artifacts.iter().map(ArtifactSlot::to_json).collect::<Vec<Value>>(),
            "coverage": self.coverage,
            "evidence_prefix": self.evidence_prefix.to_json(),
            "limitations": self.limitations,
        })
    }
}

/// One artifact byte chunk (external-connector `ArtifactChunk`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactChunk {
    pub kind: String,
    pub handle: HandleReference,
    pub digest: Digest,
    pub size_bytes: u64,
    pub offset: u64,
    pub returned_bytes: u64,
    pub data_base64: String,
    pub chunk_digest: Digest,
    pub end_of_artifact: bool,
    pub evidence_refs: Vec<EvidenceRef>,
}

impl ArtifactChunk {
    /// Closed-object JSON projection without in-band nulls.
    pub fn to_json(&self) -> Value {
        json!({
            "kind": self.kind,
            "handle": self.handle.to_json(),
            "digest": self.digest.as_str(),
            "size_bytes": self.size_bytes,
            "offset": self.offset,
            "returned_bytes": self.returned_bytes,
            "data_base64": self.data_base64,
            "chunk_digest": self.chunk_digest.as_str(),
            "end_of_artifact": self.end_of_artifact,
            "evidence_refs": self.evidence_refs.iter().map(EvidenceRef::to_json).collect::<Vec<Value>>(),
        })
    }
}

fn missing_value(missing: &Missing) -> Value {
    serde_json::to_value(missing).unwrap_or(Value::Null)
}

fn valid_missing(missing: &Missing) -> bool {
    matches!(
        missing.reason.as_str(),
        "not_enabled"
            | "not_applicable"
            | "not_observed"
            | "observation_lost"
            | "unsupported_by_subject"
            | "manual_override"
    ) && missing
        .detail
        .as_ref()
        .is_none_or(|detail| !detail.is_empty())
}

// ---------------------------------------------------------------------------
// Handle-scoped registry
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct HandleBinding {
    journal_id: String,
    admission_ref: EvidenceRef,
}

#[derive(Debug, Clone)]
struct NamedBinding {
    /// Known identity. Never erased, even when bytes are unavailable.
    expected: Digest,
    /// Content reference when bytes were verified at publication time.
    reference: Option<ArtifactReference>,
    /// Registration event, or the admission event for known-without-bytes.
    evidence_ref: EvidenceRef,
}

#[derive(Default)]
struct Registry {
    handles: BTreeMap<(String, String), HandleBinding>,
    names: BTreeMap<(String, String, String), NamedBinding>,
}

fn registry() -> &'static Mutex<Registry> {
    static REGISTRY: LazyLock<Mutex<Registry>> = LazyLock::new(|| Mutex::new(Registry::default()));
    &REGISTRY
}

fn lock_registry() -> MutexGuard<'static, Registry> {
    registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Producer sequences assigned by this module for `artifact_available` events.
///
/// Seeded far above hand-written test sequences so journaled registrations
/// never collide with fixture submissions under the same producer identity.
static PRODUCER_SEQ: AtomicU64 = AtomicU64::new(1_000_000);

fn handle_key(handle: &HandleReference) -> (String, String) {
    (
        handle.connector_id.clone(),
        handle.local_handle.clone(),
    )
}

fn name_key(handle: &HandleReference, name: &str) -> (String, String, String) {
    (
        handle.connector_id.clone(),
        handle.local_handle.clone(),
        name.to_string(),
    )
}

fn lookup_handle(handle: &HandleReference) -> Result<HandleBinding, ConnectorError> {
    lock_registry()
        .handles
        .get(&handle_key(handle))
        .cloned()
        .ok_or_else(|| {
            unknown_handle(format!(
                "handle {:?}/{:?} is not a retained local handle",
                handle.connector_id, handle.local_handle
            ))
        })
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

/// Binds a durable local handle to its retained journal.
///
/// Verifies the journal head and resolves the admission reference within the
/// retained prefix, so later collections can cite established evidence for
/// both present and missing slots. Rebinding a handle to a different journal
/// or admission reference is rejected: handles are never rebound.
pub fn register_handle(
    principal: &AuthenticatedPrincipal,
    handle: &HandleReference,
    journal_id: &str,
    admission_ref: &EvidenceRef,
) -> Result<(), ConnectorError> {
    if handle.connector_id.is_empty() || handle.local_handle.is_empty() {
        return Err(invalid(
            "handle requires nonempty connector_id and local_handle",
        ));
    }
    if journal_id.is_empty() {
        return Err(invalid("journal_id must be nonempty"));
    }
    admission_ref.validate()?;
    rm_authority::authorize_owner(principal, ARTIFACT_OWNER_DOMAIN, ARTIFACT_AVAILABLE_KIND)?;
    let prefix = rm_evidence::journal_head(principal, journal_id)?;
    if prefix.journal_id != journal_id {
        return Err(integrity("journal head names a different journal"));
    }
    rm_evidence::resolve_evidence(principal, admission_ref, &prefix)?;
    let mut registry = lock_registry();
    let key = handle_key(handle);
    if let Some(existing) = registry.handles.get(&key) {
        if existing.journal_id != journal_id {
            return Err(integrity(
                "handle is already bound to a different retained journal; handles are never rebound",
            ));
        }
        if existing.admission_ref != *admission_ref {
            return Err(integrity(
                "handle is already bound with a different admission reference",
            ));
        }
        return Ok(());
    }
    registry.handles.insert(
        key,
        HandleBinding {
            journal_id: journal_id.to_string(),
            admission_ref: admission_ref.clone(),
        },
    );
    Ok(())
}

/// Publishes a named artifact and journals its `artifact_available` event.
///
/// The exact bytes must already be installed durably: the reference digest
/// and size are verified against the retained bytes before anything is
/// journaled, and the commit cites the installed bytes. Republishing the same
/// name with the same digest is idempotent and returns the retained slot
/// without a second event; rebinding a name to a different digest is
/// rejected.
pub fn publish_named_artifact(
    principal: &AuthenticatedPrincipal,
    manifest: &Manifest,
    handle: &HandleReference,
    name: &str,
    reference: &ArtifactReference,
) -> Result<ArtifactSlot, ConnectorError> {
    if name.is_empty() {
        return Err(invalid("artifact name must be a nonempty identifier"));
    }
    reference.validate()?;
    rm_authority::authorize_owner(principal, ARTIFACT_OWNER_DOMAIN, ARTIFACT_AVAILABLE_KIND)?;
    let binding = lookup_handle(handle)?;
    let key = name_key(handle, name);
    if let Some(existing) = lock_registry().names.get(&key).cloned() {
        if existing.expected != reference.digest {
            return Err(integrity(format!(
                "artifact name {name:?} is already bound to a different digest; names are never rebound to different bytes"
            )));
        }
        if existing.reference.as_ref() == Some(reference) {
            let prefix = rm_evidence::journal_head(principal, &binding.journal_id)?;
            rm_evidence::resolve_evidence(principal, &existing.evidence_ref, &prefix)?;
            let slot = ArtifactSlot {
                name: name.to_string(),
                expected_digest: MaybeDigest::Present(reference.digest.clone()),
                content: MaybeArtifact::Present(reference.clone()),
                evidence_refs: vec![existing.evidence_ref.clone()],
            };
            verify_slot(&slot)?;
            return Ok(slot);
        }
        return Err(integrity(format!(
            "artifact name {name:?} is already recorded with unavailable bytes; loss is never silently replaced"
        )));
    }
    let bytes = rm_evidence::load_artifact(principal, reference)?;
    let computed = rm_wire::artifact_digest(&bytes);
    if computed != reference.digest {
        return Err(integrity(
            "declared artifact digest does not match the exact stored bytes",
        ));
    }
    if bytes.len() as u64 != reference.size_bytes {
        return Err(integrity(
            "declared artifact size_bytes does not match the stored byte length",
        ));
    }
    let registration = rm_evidence::event_registration(ARTIFACT_AVAILABLE_KIND)
        .ok_or_else(|| invalid("artifact_available is not a registered event kind"))?;
    let sequence = PositiveInteger::new(PRODUCER_SEQ.fetch_add(1, Ordering::SeqCst))?;
    let submission = EventSubmission {
        producer_sequence: Some(sequence),
        event_kind: ARTIFACT_AVAILABLE_KIND.to_string(),
        event_schema_version: registration.event_schema_version.to_string(),
        occurred_at: MaybeTimePoint::Missing(Missing::new("not_observed")),
        payload: EvidencePayload {
            data: json!({"name": name, "artifact": reference.to_json()}),
            measurements: Vec::new(),
            evidence_refs: Vec::new(),
            artifact_refs: vec![reference.clone()],
        },
    };
    let envelopes =
        rm_evidence::commit_owner_effect(principal, manifest, reference, &[submission], reference)?;
    let envelope = envelopes
        .last()
        .cloned()
        .ok_or_else(|| invalid("owner commit returned no journal envelopes"))?;
    let evidence_ref = EvidenceRef {
        journal_id: envelope.journal_id.clone(),
        sequence: envelope.journal_sequence,
        event_id: envelope.event_id.clone(),
        event_hash: envelope.event_hash.clone(),
        pointer: String::new(),
    };
    let prefix = rm_evidence::journal_head(principal, &binding.journal_id)?;
    rm_evidence::resolve_evidence(principal, &evidence_ref, &prefix)?;
    lock_registry().names.insert(
        key,
        NamedBinding {
            expected: reference.digest.clone(),
            reference: Some(reference.clone()),
            evidence_ref: evidence_ref.clone(),
        },
    );
    let slot = ArtifactSlot {
        name: name.to_string(),
        expected_digest: MaybeDigest::Present(reference.digest.clone()),
        content: MaybeArtifact::Present(reference.clone()),
        evidence_refs: vec![evidence_ref],
    };
    verify_slot(&slot)?;
    Ok(slot)
}

/// Records a known artifact identity whose bytes are not retained.
///
/// Models journaled byte loss: the digest stays citable while content reads
/// report reasoned `observation_lost` absence. The identity is never erased
/// and never rebound to different bytes.
pub fn register_expected_digest(
    principal: &AuthenticatedPrincipal,
    handle: &HandleReference,
    name: &str,
    digest: &Digest,
) -> Result<ArtifactSlot, ConnectorError> {
    if name.is_empty() {
        return Err(invalid("artifact name must be a nonempty identifier"));
    }
    if !rm_wire::is_valid_digest(digest.as_str()) {
        return Err(invalid("expected digest is not a sha256 digest"));
    }
    rm_authority::authorize_owner(principal, ARTIFACT_OWNER_DOMAIN, ARTIFACT_AVAILABLE_KIND)?;
    let binding = lookup_handle(handle)?;
    let prefix = rm_evidence::journal_head(principal, &binding.journal_id)?;
    rm_evidence::resolve_evidence(principal, &binding.admission_ref, &prefix)?;
    let mut registry = lock_registry();
    let key = name_key(handle, name);
    if let Some(existing) = registry.names.get(&key) {
        if existing.expected != *digest {
            return Err(integrity(format!(
                "artifact name {name:?} is already bound to a different digest; names are never rebound to different bytes"
            )));
        }
        return Ok(lost_slot(name, digest, &existing.evidence_ref.clone()));
    }
    registry.names.insert(
        key,
        NamedBinding {
            expected: digest.clone(),
            reference: None,
            evidence_ref: binding.admission_ref.clone(),
        },
    );
    Ok(lost_slot(name, digest, &binding.admission_ref))
}

fn lost_slot(name: &str, digest: &Digest, evidence_ref: &EvidenceRef) -> ArtifactSlot {
    ArtifactSlot {
        name: name.to_string(),
        expected_digest: MaybeDigest::Present(digest.clone()),
        content: MaybeArtifact::Missing(Missing::with_detail(
            "observation_lost",
            "known artifact bytes are not retained under this digest",
        )),
        evidence_refs: vec![evidence_ref.clone()],
    }
}

// ---------------------------------------------------------------------------
// Request validation
// ---------------------------------------------------------------------------

fn validate_command(command: &ConnectorRequest) -> Result<(), ConnectorError> {
    if command.record_type != CONNECTOR_REQUEST_TYPE {
        return Err(invalid(format!(
            "record_type {:?} is not {:?}",
            command.record_type, CONNECTOR_REQUEST_TYPE
        )));
    }
    if command.schema_version != CONNECTOR_SCHEMA_VERSION {
        return Err(unsupported_version(format!(
            "schema_version {:?} is not {:?}",
            command.schema_version, CONNECTOR_SCHEMA_VERSION
        )));
    }
    if command.request_id.is_empty() {
        return Err(invalid("request_id must be nonempty"));
    }
    if command.connector_id.is_empty() {
        return Err(invalid("connector_id must be nonempty"));
    }
    if command.operation != COLLECT_ARTIFACTS_VERB {
        return Err(invalid(format!(
            "operation {:?} is not CollectArtifacts",
            command.operation
        )));
    }
    if command.handle.connector_id.is_empty() || command.handle.local_handle.is_empty() {
        return Err(invalid(
            "handle requires nonempty connector_id and local_handle",
        ));
    }
    if command.handle.connector_id != command.connector_id {
        return Err(invalid(
            "handle connector_id must identify the authenticated connector",
        ));
    }
    match &command.selector {
        ArtifactSelector::Inventory => {}
        ArtifactSelector::Named { names } => {
            if names.is_empty() {
                return Err(invalid("named selector requires a nonempty names array"));
            }
            let mut seen = BTreeSet::new();
            for name in names {
                if name.is_empty() {
                    return Err(invalid("artifact names must be nonempty identifiers"));
                }
                if !seen.insert(name) {
                    return Err(invalid(format!("duplicate artifact name {name:?}")));
                }
            }
        }
        ArtifactSelector::Bytes {
            digest,
            offset,
            max_bytes,
        } => {
            if !rm_wire::is_valid_digest(digest.as_str()) {
                return Err(invalid("bytes digest is not a sha256 digest"));
            }
            if *max_bytes == 0 || *max_bytes > MAX_SAFE_INTEGER {
                return Err(invalid(format!(
                    "max_bytes {max_bytes} is outside 1..={MAX_SAFE_INTEGER}"
                )));
            }
            if *offset > MAX_SAFE_INTEGER {
                return Err(invalid(format!(
                    "offset {offset} is outside 0..={MAX_SAFE_INTEGER}"
                )));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Slot verification
// ---------------------------------------------------------------------------

/// Verifies slot coherence: present content matches the expected digest, every
/// absence is a valid reasoned envelope, and supporting evidence is present
/// and well-formed.
pub fn verify_slot(slot: &ArtifactSlot) -> Result<(), ConnectorError> {
    if slot.name.is_empty() {
        return Err(invalid("artifact slot name must be nonempty"));
    }
    match (&slot.expected_digest, &slot.content) {
        (MaybeDigest::Present(expected), MaybeArtifact::Present(reference)) => {
            if expected != &reference.digest {
                return Err(integrity(
                    "available slot content does not match its expected digest",
                ));
            }
            reference.validate()?;
        }
        (MaybeDigest::Present(_), MaybeArtifact::Missing(missing)) => {
            if !valid_missing(missing) {
                return Err(invalid("slot content absence must be a reasoned Missing envelope"));
            }
        }
        (MaybeDigest::Missing(expected), MaybeArtifact::Missing(content)) => {
            if !valid_missing(expected) || !valid_missing(content) {
                return Err(invalid("slot absence must use reasoned Missing envelopes"));
            }
        }
        (MaybeDigest::Missing(_), MaybeArtifact::Present(_)) => {
            return Err(integrity(
                "present slot content requires a present expected digest",
            ));
        }
    }
    if slot.evidence_refs.is_empty() {
        return Err(invalid("artifact slot requires supporting evidence"));
    }
    for reference in &slot.evidence_refs {
        reference.validate()?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Inventory (RM-C47)
// ---------------------------------------------------------------------------

/// Collects a handle-scoped artifact inventory.
///
/// Serves `inventory` and `named` selectors. Named requests return exactly the
/// requested names in the requested order, including explicit missing slots.
/// Inventory mode returns every handle-bound name sorted by name; an
/// established empty inventory reports `complete` coverage with zero slots,
/// never a default for an unavailable source.
pub fn collect_inventory(
    principal: &AuthenticatedPrincipal,
    command: &ConnectorRequest,
) -> Result<ArtifactInventory, ConnectorError> {
    validate_command(command)?;
    let requested: Option<Vec<String>> = match &command.selector {
        ArtifactSelector::Inventory => None,
        ArtifactSelector::Named { names } => Some(names.clone()),
        ArtifactSelector::Bytes { .. } => {
            return Err(invalid(
                "bytes selector returns a chunk or error; use collect_chunk",
            ));
        }
    };
    rm_authority::authorize_owner(principal, ARTIFACT_OWNER_DOMAIN, ARTIFACT_AVAILABLE_KIND)?;
    let binding = lookup_handle(&command.handle)?;
    let prefix = rm_evidence::journal_head(principal, &binding.journal_id)?;
    rm_evidence::resolve_evidence(principal, &binding.admission_ref, &prefix)?;

    let wanted: Vec<String> = match requested {
        Some(names) => names,
        None => {
            let registry = lock_registry();
            let mut all: Vec<String> = registry
                .names
                .iter()
                .filter(|((connector, handle, _), _)| {
                    connector == &command.handle.connector_id
                        && handle == &command.handle.local_handle
                })
                .map(|((_, _, name), _)| name.clone())
                .collect();
            all.sort();
            all
        }
    };

    let mut slots = Vec::with_capacity(wanted.len());
    let mut unavailable_count: u64 = 0;
    for name in &wanted {
        let bound = lock_registry()
            .names
            .get(&name_key(&command.handle, name))
            .cloned();
        match bound {
            None => {
                unavailable_count += 1;
                slots.push(ArtifactSlot {
                    name: name.clone(),
                    expected_digest: MaybeDigest::Missing(Missing::new("not_observed")),
                    content: MaybeArtifact::Missing(Missing::new("not_observed")),
                    evidence_refs: vec![binding.admission_ref.clone()],
                });
            }
            Some(bound) => match &bound.reference {
                None => {
                    unavailable_count += 1;
                    slots.push(lost_slot(name, &bound.expected, &bound.evidence_ref));
                }
                Some(reference) => match rm_evidence::load_artifact(principal, reference) {
                    Ok(bytes) => {
                        let computed = rm_wire::artifact_digest(&bytes);
                        if computed != reference.digest {
                            return Err(integrity(format!(
                                "retained bytes for artifact {name:?} no longer match the registered content digest"
                            )));
                        }
                        if bytes.len() as u64 != reference.size_bytes {
                            return Err(integrity(format!(
                                "retained byte length for artifact {name:?} does not match size_bytes"
                            )));
                        }
                        if bound.expected != reference.digest {
                            return Err(integrity(format!(
                                "binding for artifact {name:?} disagrees with its content digest"
                            )));
                        }
                        slots.push(ArtifactSlot {
                            name: name.clone(),
                            expected_digest: MaybeDigest::Present(reference.digest.clone()),
                            content: MaybeArtifact::Present(reference.clone()),
                            evidence_refs: vec![bound.evidence_ref.clone()],
                        });
                    }
                    Err(error) if error.code == "NOT_FOUND" => {
                        unavailable_count += 1;
                        slots.push(lost_slot(name, &bound.expected, &bound.evidence_ref));
                    }
                    Err(error) => return Err(error),
                },
            },
        }
    }

    for slot in &slots {
        verify_slot(slot)?;
        for reference in &slot.evidence_refs {
            rm_evidence::resolve_evidence(principal, reference, &prefix)?;
        }
    }

    let coverage = if unavailable_count == 0 {
        "complete"
    } else {
        "partial"
    };
    let mut limitations = Vec::new();
    if unavailable_count > 0 {
        limitations.push(format!(
            "{unavailable_count} of {} artifact slots have unavailable content; missing slots are explicit absences, not established emptiness",
            slots.len()
        ));
    }
    Ok(ArtifactInventory {
        kind: "artifact_inventory".to_string(),
        handle: command.handle.clone(),
        artifacts: slots,
        coverage: coverage.to_string(),
        evidence_prefix: prefix,
        limitations,
    })
}

// ---------------------------------------------------------------------------
// Chunks (RM-C48)
// ---------------------------------------------------------------------------

const B64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encodes bytes as canonical padded base64.
pub fn encode_base64(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64_ALPHABET[(triple >> 18 & 63) as usize] as char);
        out.push(B64_ALPHABET[(triple >> 12 & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64_ALPHABET[(triple >> 6 & 63) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(B64_ALPHABET[(triple & 63) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn b64_value(byte: u8) -> Option<u32> {
    match byte {
        b'A'..=b'Z' => Some((byte - b'A') as u32),
        b'a'..=b'z' => Some((byte - b'a' + 26) as u32),
        b'0'..=b'9' => Some((byte - b'0' + 52) as u32),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decodes strict canonical padded base64.
///
/// Rejects wrong lengths, misplaced padding, non-alphabet characters, and
/// non-canonical trailing bits (verified by re-encoding the decoded bytes).
pub fn decode_base64(text: &str) -> Result<Vec<u8>, ConnectorError> {
    if text.len() % 4 != 0 {
        return Err(invalid("data_base64 length must be a multiple of 4"));
    }
    if !text.is_ascii() {
        return Err(invalid("data_base64 must be ASCII base64"));
    }
    let bytes = text.as_bytes();
    let padding = bytes.iter().rev().take_while(|b| **b == b'=').count();
    if padding > 2 {
        return Err(invalid("data_base64 has invalid padding"));
    }
    if bytes[..bytes.len() - padding].contains(&b'=') {
        return Err(invalid("data_base64 has misplaced padding"));
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for quartet in bytes.chunks(4) {
        let mut values = [0u32; 4];
        let pad_here = quartet.iter().filter(|b| **b == b'=').count();
        for (index, byte) in quartet.iter().enumerate() {
            if *byte == b'=' {
                values[index] = 0;
            } else {
                values[index] =
                    b64_value(*byte).ok_or_else(|| invalid("data_base64 has invalid alphabet"))?;
            }
        }
        let triple = (values[0] << 18) | (values[1] << 12) | (values[2] << 6) | values[3];
        out.push((triple >> 16 & 0xFF) as u8);
        if pad_here < 2 {
            out.push((triple >> 8 & 0xFF) as u8);
        }
        if pad_here == 0 {
            out.push((triple & 0xFF) as u8);
        }
    }
    if encode_base64(&out) != text {
        return Err(invalid("data_base64 is not canonical padded base64"));
    }
    Ok(out)
}

/// Verifies chunk coherence and returns the decoded bytes.
///
/// Checks the kind discriminator, digest formats, `offset + returned_bytes <=
/// size_bytes`, decoded length against `returned_bytes`, the chunk digest over
/// the decoded bytes, exact EOF agreement, non-EOF progress, and supporting
/// evidence presence. Assembled full-artifact digest verification stays with
/// the consumer, which holds every chunk.
pub fn verify_chunk(chunk: &ArtifactChunk) -> Result<Vec<u8>, ConnectorError> {
    if chunk.kind != "artifact_chunk" {
        return Err(invalid(format!(
            "chunk kind {:?} is not artifact_chunk",
            chunk.kind
        )));
    }
    if !rm_wire::is_valid_digest(chunk.digest.as_str()) {
        return Err(invalid("chunk digest is not a sha256 digest"));
    }
    if !rm_wire::is_valid_digest(chunk.chunk_digest.as_str()) {
        return Err(invalid("chunk_digest is not a sha256 digest"));
    }
    if chunk.size_bytes > MAX_SAFE_INTEGER {
        return Err(invalid("chunk size_bytes is outside the revision range"));
    }
    if chunk.returned_bytes > MAX_SAFE_INTEGER {
        return Err(invalid("chunk returned_bytes is outside the revision range"));
    }
    let end = chunk
        .offset
        .checked_add(chunk.returned_bytes)
        .ok_or_else(|| invalid("chunk offset plus returned_bytes overflows"))?;
    if end > chunk.size_bytes {
        return Err(invalid(format!(
            "chunk end {end} exceeds artifact size {}",
            chunk.size_bytes
        )));
    }
    let data = decode_base64(&chunk.data_base64)?;
    if data.len() as u64 != chunk.returned_bytes {
        return Err(invalid(format!(
            "chunk returned_bytes {} does not match the decoded length {}",
            chunk.returned_bytes,
            data.len()
        )));
    }
    let computed = rm_wire::artifact_digest(&data);
    if computed != chunk.chunk_digest {
        return Err(integrity(
            "chunk bytes do not match chunk_digest",
        ));
    }
    if chunk.end_of_artifact != (end == chunk.size_bytes) {
        return Err(invalid(
            "chunk end_of_artifact disagrees with its bounds",
        ));
    }
    if !chunk.end_of_artifact && chunk.returned_bytes == 0 {
        return Err(invalid("a non-EOF chunk must make progress"));
    }
    if chunk.evidence_refs.is_empty() {
        return Err(invalid("artifact chunk requires supporting evidence"));
    }
    for reference in &chunk.evidence_refs {
        reference.validate()?;
    }
    Ok(data)
}

/// Collects one byte range of a handle-retained artifact.
///
/// The digest must already be registered within the authorized handle's
/// retained evidence; unregistered digests are rejected without any fetch.
/// Offsets beyond EOF are rejected, while an offset exactly at EOF returns
/// zero bytes with `end_of_artifact` set.
pub fn collect_chunk(
    principal: &AuthenticatedPrincipal,
    command: &ConnectorRequest,
) -> Result<ArtifactChunk, ConnectorError> {
    validate_command(command)?;
    let (digest, offset, max_bytes) = match &command.selector {
        ArtifactSelector::Bytes {
            digest,
            offset,
            max_bytes,
        } => (digest.clone(), *offset, *max_bytes),
        _ => {
            return Err(invalid(
                "inventory and named selectors return an inventory or error; use collect_inventory",
            ));
        }
    };
    rm_authority::authorize_owner(principal, ARTIFACT_OWNER_DOMAIN, ARTIFACT_AVAILABLE_KIND)?;
    let binding = lookup_handle(&command.handle)?;
    let prefix = rm_evidence::journal_head(principal, &binding.journal_id)?;

    let bound = lock_registry()
        .names
        .iter()
        .filter(|((connector, handle, _), _)| {
            connector == &command.handle.connector_id && handle == &command.handle.local_handle
        })
        .map(|(_, bound)| bound.clone())
        .find(|bound| bound.expected == digest);
    let bound = match bound {
        Some(bound) => bound,
        None => {
            return Err(unavailable(format!(
                "digest {digest} is not in this handle's retained evidence; CollectArtifacts never fetches arbitrary digests, URLs, or paths"
            )));
        }
    };
    let reference = match &bound.reference {
        Some(reference) => reference.clone(),
        None => {
            return Err(unavailable(format!(
                "artifact {digest} bytes are not retained; its known identity cannot serve content"
            )));
        }
    };
    let bytes = rm_evidence::load_artifact(principal, &reference)?;
    let computed = rm_wire::artifact_digest(&bytes);
    if computed != reference.digest {
        return Err(integrity(
            "retained bytes no longer match the registered content digest",
        ));
    }
    if bytes.len() as u64 != reference.size_bytes {
        return Err(integrity(
            "retained byte length does not match size_bytes",
        ));
    }
    let size = bytes.len() as u64;
    if offset > size {
        return Err(invalid(format!(
            "offset {offset} is beyond end of artifact ({size} bytes)"
        )));
    }
    let remaining = size - offset;
    let returned = max_bytes.min(remaining);
    let end_of_artifact = offset + returned == size;
    if !end_of_artifact && returned == 0 {
        return Err(invalid("a non-EOF chunk must make progress"));
    }
    let slice = &bytes[offset as usize..(offset + returned) as usize];
    let data_base64 = encode_base64(slice);
    let chunk_digest = rm_wire::artifact_digest(slice);
    rm_evidence::resolve_evidence(principal, &bound.evidence_ref, &prefix)?;
    let chunk = ArtifactChunk {
        kind: "artifact_chunk".to_string(),
        handle: command.handle.clone(),
        digest: reference.digest.clone(),
        size_bytes: size,
        offset,
        returned_bytes: returned,
        data_base64,
        chunk_digest,
        end_of_artifact,
        evidence_refs: vec![bound.evidence_ref.clone()],
    };
    let decoded = verify_chunk(&chunk)?;
    debug_assert_eq!(decoded, slice);
    Ok(chunk)
}

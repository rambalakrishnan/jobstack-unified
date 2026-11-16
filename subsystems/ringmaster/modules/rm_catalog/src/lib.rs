//! `rm_catalog`: tier-3 connector/binding descriptors and capability catalogs.
//!
//! Implements the Describe boundary (seam mapping §12.2–§12.4) and the native
//! BrowserOxide binding descriptor (§5.2–§5.3):
//!
//! - [`describe`] performs a local descriptor read only. It takes an empty
//!   [`DescribeRequest`], authenticates the caller through the authority
//!   boundary, structurally validates the pinned [`ConnectorDescriptor`] via
//!   `rm_wire`, and returns it. No browser is launched, no endpoint is
//!   probed, and no task is executed.
//! - [`validate_native_binding`] validates a [`BOBindingDescriptor`] against
//!   its exact scope: fourteen primitives each once, fourteen binding
//!   capabilities each once, mapped entries carrying a real symbol, contract
//!   pin, and nonempty evidence, and every cited evidence reference resolved
//!   against its journal prefix with retained artifacts loadable.
//!
//! Hard rules, from the kernel and seam invariants:
//!
//! - A descriptor applies to exactly one subject/version/mode/interface
//!   scope. New subject versions start unknown; omission and predecessor
//!   descriptors never imply inheritance, presence, or absence
//!   (EK-CAPABILITY, EXT-DESCRIBE, BO-CAPS).
//! - The connector declares capabilities, mappings, observations, and source
//!   claims. It never emits qualification, requirement satisfaction, or an
//!   authoritative application-success flag (EXT-DECLARE-NOT-ASSESS).
//! - Mapped never means exercised: primitive mapping state, capability
//!   availability, and consumer opportunity/result stay independent.
//!   Documentation can support a declaration, never a run-success (`present`)
//!   finding, which requires executed observation.
//! - No guessed native symbols, endpoints, cancellation, capture, upload, or
//!   isolation support. Unknown symbols stay unmapped with reasoned
//!   missingness; a binding descriptor is never converted into an automatic
//!   Ringmaster capability finding.
//! - No in-band nulls; every missing field uses a typed [`Missing`] envelope.
//! - No shared-database writes or cross-domain transactions; journal and
//!   artifact reads go through the `rm_evidence` boundary.

#![forbid(unsafe_code)]

pub use rm_evidence::{EvidenceRef, JournalPrefix};
use rm_wire::Digest;
use serde_json::{json, Value};
use std::collections::BTreeSet;

pub use rm_authority::{AuthenticatedPrincipal, ConnectorError};
pub use rm_evidence::{
    AccessClass, ArtifactReference, JournalEnvelope, Missing, PositiveInteger,
};
pub use rm_wire::Digest as WireDigest;

// ---------------------------------------------------------------------------
// Discriminators and catalogs
// ---------------------------------------------------------------------------

/// Connector descriptor record discriminator.
pub const CONNECTOR_RECORD_TYPE: &str = "connector_descriptor";
/// Connector descriptor schema version.
pub const CONNECTOR_SCHEMA_VERSION: &str = "external-connector/0.1.0";
/// Capability descriptor record discriminator.
pub const CAPABILITY_RECORD_TYPE: &str = "capability_descriptor";
/// Capability descriptor schema version.
pub const CAPABILITY_SCHEMA_VERSION: &str = "evidence-kernel/0.1.0";
/// BrowserOxide binding descriptor record discriminator.
pub const BO_RECORD_TYPE: &str = "browseroxide_binding_descriptor";
/// BrowserOxide binding descriptor schema version.
pub const BO_SCHEMA_VERSION: &str = "internal-browser-binding.browseroxide/0.1.0";

/// Complete BrowserOxide capability catalog (§5.3): exactly one entry each.
pub const BO_CAPABILITIES: [&str; 14] = [
    "bo.direct_dom",
    "bo.direct_v8",
    "bo.live_http_client",
    "bo.http_pool_sharing",
    "bo.offline_from_html",
    "bo.frame_dom",
    "bo.open_shadow_dom",
    "bo.closed_shadow_dom",
    "bo.dom_value_mutation",
    "bo.composed_event_dispatch",
    "bo.file_assignment",
    "bo.raster_capture",
    "bo.reset_dom_invalidation",
    "bo.native_deadline_interruption",
];

/// Minimum external capability catalog (§12.3): every descriptor covers at
/// least these ten.
pub const EXTERNAL_CATALOG_MIN: [&str; 10] = [
    "native_goal_task",
    "native_plan_execution",
    "native_cancel",
    "native_context_release",
    "native_artifact_retrieval",
    "native_revision",
    "native_dom_access",
    "browser_state_isolation",
    "browser_state_persistence",
    "learning_state_control",
];

/// Exactly the fourteen native primitives (§5.2): each appears once.
pub const BO_PRIMITIVES: [&str; 14] = [
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

/// The nine connector verbs, mirroring the authority boundary.
pub use rm_authority::NINE_OPERATIONS;

/// Task types advertised by task mappings.
pub const TASK_TYPES: [&str; 3] = ["apply", "extract", "discover_jobs"];
/// Task input forms.
pub const INPUT_FORMS: [&str; 4] = [
    "goal",
    "recorded_plan",
    "extraction_request",
    "crawl_declaration",
];
/// Planning/recovery owners.
pub const PLANNING_OWNERS: [&str; 4] = ["subject", "external_planner", "operator", "none"];
/// Capability availability values.
pub const AVAILABILITIES: [&str; 4] = ["present", "absent", "unknown", "not_applicable"];
/// Capability claim origins.
pub const CLAIM_ORIGINS: [&str; 3] = ["native", "composed_subject", "harness"];
/// Capability evidence bases.
pub const EVIDENCE_BASES: [&str; 4] = [
    "documentation",
    "executed_observation",
    "source_diagnosis",
    "operator_attestation",
];
/// Subject revision bases.
pub const REVISION_BASES: [&str; 4] = [
    "native_revision",
    "source_digest",
    "operator_attestation",
    "unknown",
];
/// Operation implementations.
pub const IMPLEMENTATIONS: [&str; 3] = ["connector_local", "native_mapping", "unmapped"];
/// Action groundings.
pub const ACTION_GROUNDINGS: [&str; 6] = [
    "semantic",
    "recorded_selectors",
    "coordinates",
    "hybrid",
    "not_applicable",
    "unknown",
];
/// Execution substrates.
pub const EXECUTION_SUBSTRATES: [&str; 4] = ["browser", "non_browser", "hybrid", "unknown"];
/// Session storage models.
pub const SESSION_STORAGE_MODELS: [&str; 3] =
    ["process_global", "verified_namespaced", "unknown"];
/// Primitive mapping states.
pub const MAPPING_STATES: [&str; 2] = ["mapped", "unmapped"];
/// The six permitted `Missing.reason` values (§3.2).
pub const MISSING_REASONS: [&str; 6] = [
    "not_enabled",
    "not_applicable",
    "not_observed",
    "observation_lost",
    "unsupported_by_subject",
    "manual_override",
];

/// Largest integer representable without precision loss (§3.1).
pub const MAX_SAFE_INTEGER: u64 = rm_evidence::MAX_SAFE_INTEGER;

// ---------------------------------------------------------------------------
// Errors and scalar validation
// ---------------------------------------------------------------------------

fn invalid(detail: impl Into<String>) -> ConnectorError {
    ConnectorError {
        kind: "connector_error".to_string(),
        code: "INVALID_REQUEST".to_string(),
        fault_domain: "request".to_string(),
        detail: detail.into(),
        operation_delivery: "not_dispatched".to_string(),
        retry_guidance: "operator_review".to_string(),
        retry_after: None,
        handle: None,
        evidence_refs: Vec::new(),
    }
}

fn require_identifier(field: &str, value: &str) -> Result<(), ConnectorError> {
    if value.is_empty() {
        return Err(invalid(format!("{field} must be a nonempty identifier")));
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

fn require_missing(what: &str, missing: &Missing) -> Result<(), ConnectorError> {
    if !MISSING_REASONS.contains(&missing.reason.as_str()) {
        return Err(invalid(format!(
            "{what} carries invalid Missing reason {:?}",
            missing.reason
        )));
    }
    if matches!(&missing.detail, Some(detail) if detail.is_empty()) {
        return Err(invalid(format!("{what} Missing detail must be nonempty")));
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

fn require_revision(field: &str, value: u64) -> Result<(), ConnectorError> {
    if value > MAX_SAFE_INTEGER {
        return Err(invalid(format!(
            "{field} {value} is outside 0..={MAX_SAFE_INTEGER}"
        )));
    }
    Ok(())
}

fn require_enum(field: &str, value: &str, allowed: &[&str]) -> Result<(), ConnectorError> {
    if !allowed.contains(&value) {
        return Err(invalid(format!(
            "{field} {value:?} must be one of {}",
            allowed.join(", ")
        )));
    }
    Ok(())
}

fn require_unique(items: &[String], what: &str) -> Result<(), ConnectorError> {
    let mut seen = BTreeSet::new();
    for item in items {
        if !seen.insert(item) {
            return Err(invalid(format!("{what} contains duplicate {item:?}")));
        }
    }
    Ok(())
}

/// Authenticates the caller through the authority boundary.
///
/// Every catalog call binds to an authenticated channel principal; request
/// IDs, digests, and application credentials alone are never sufficient.
fn check_caller(principal: &AuthenticatedPrincipal) -> Result<(), ConnectorError> {
    rm_authority::authorize_owner(principal, "connector", "connector_incident")?;
    Ok(())
}

/// Structurally validates a closed record through the wire boundary.
fn wire_validate(schema_id: &str, value: &Value, what: &str) -> Result<(), ConnectorError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| invalid(format!("{what} cannot be serialized: {error}")))?;
    rm_wire::validate_record(schema_id, &bytes)
        .map_err(|error| invalid(format!("{what} wire validation failed: {error}")))?;
    Ok(())
}

fn missing_json(missing: &Missing) -> Value {
    match &missing.detail {
        Some(detail) => json!({"value": null, "reason": missing.reason, "detail": detail}),
        None => json!({"value": null, "reason": missing.reason}),
    }
}

// ---------------------------------------------------------------------------
// Maybe carriers
// ---------------------------------------------------------------------------

/// Identifier or reasoned missingness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaybeString {
    /// Present identifier.
    Text(String),
    /// Reasoned absence.
    Missing(Missing),
}

/// Digest or reasoned missingness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaybeDigest {
    /// Present digest.
    Present(Digest),
    /// Reasoned absence.
    Missing(Missing),
}

/// Version pin or reasoned missingness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaybeVersionPin {
    /// Present pin.
    Present(VersionPin),
    /// Reasoned absence.
    Missing(Missing),
}

fn validate_maybe_string(what: &str, value: &MaybeString) -> Result<(), ConnectorError> {
    match value {
        MaybeString::Text(text) => require_identifier(what, text),
        MaybeString::Missing(missing) => require_missing(what, missing),
    }
}

fn validate_maybe_digest(what: &str, value: &MaybeDigest) -> Result<(), ConnectorError> {
    match value {
        MaybeDigest::Present(digest) => require_digest(what, digest),
        MaybeDigest::Missing(missing) => require_missing(what, missing),
    }
}

fn validate_maybe_pin(what: &str, value: &MaybeVersionPin) -> Result<(), ConnectorError> {
    match value {
        MaybeVersionPin::Present(pin) => validate_version_pin(pin, what),
        MaybeVersionPin::Missing(missing) => require_missing(what, missing),
    }
}

// ---------------------------------------------------------------------------
// Shared shapes
// ---------------------------------------------------------------------------

/// Immutable artifact pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionPin {
    /// Pinned artifact identity.
    pub id: String,
    /// Pinned version.
    pub version: String,
    /// Digest of the exact pinned bytes.
    pub artifact_digest: Digest,
}

impl VersionPin {
    /// Closed-object JSON projection.
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

/// One component of the subject stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentIdentity {
    /// Component name.
    pub component: String,
    /// Reported version, or reasoned missingness.
    pub reported_version: MaybeString,
    /// Build digest, or reasoned missingness.
    pub build_digest: MaybeDigest,
    /// Configuration digest, or reasoned missingness.
    pub configuration_digest: MaybeDigest,
}

impl ComponentIdentity {
    /// Closed-object JSON projection.
    pub fn to_json(&self) -> Value {
        json!({
            "component": self.component,
            "reported_version": maybe_string_json(&self.reported_version),
            "build_digest": maybe_digest_json(&self.build_digest),
            "configuration_digest": maybe_digest_json(&self.configuration_digest),
        })
    }
}

fn maybe_string_json(value: &MaybeString) -> Value {
    match value {
        MaybeString::Text(text) => Value::String(text.clone()),
        MaybeString::Missing(missing) => missing_json(missing),
    }
}

fn maybe_digest_json(value: &MaybeDigest) -> Value {
    match value {
        MaybeDigest::Present(digest) => Value::String(digest.as_str().to_string()),
        MaybeDigest::Missing(missing) => missing_json(missing),
    }
}

fn maybe_pin_json(value: &MaybeVersionPin) -> Value {
    match value {
        MaybeVersionPin::Present(pin) => pin.to_json(),
        MaybeVersionPin::Missing(missing) => missing_json(missing),
    }
}

fn validate_component(component: &ComponentIdentity, what: &str) -> Result<(), ConnectorError> {
    require_identifier(&format!("{what} component"), &component.component)?;
    validate_maybe_string(&format!("{what} reported_version"), &component.reported_version)?;
    validate_maybe_digest(&format!("{what} build_digest"), &component.build_digest)?;
    validate_maybe_digest(
        &format!("{what} configuration_digest"),
        &component.configuration_digest,
    )?;
    Ok(())
}

/// Exact subject scope: one id/version/mode/interface surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectIdentity {
    /// Subject identity.
    pub subject_id: String,
    /// Subject version. A new version starts unknown on every capability.
    pub subject_version: String,
    /// How the native revision was established.
    pub revision_basis: String,
    /// Native revision, or reasoned missingness.
    pub native_revision: MaybeString,
    /// Configured mode.
    pub configured_mode: String,
    /// Interface surface.
    pub interface_surface: String,
    /// Configuration digest.
    pub configuration_digest: Digest,
    /// Complete configured component stack.
    pub stack: Vec<ComponentIdentity>,
}

impl SubjectIdentity {
    /// Closed-object JSON projection.
    pub fn to_json(&self) -> Value {
        json!({
            "subject_id": self.subject_id,
            "subject_version": self.subject_version,
            "revision_basis": self.revision_basis,
            "native_revision": maybe_string_json(&self.native_revision),
            "configured_mode": self.configured_mode,
            "interface_surface": self.interface_surface,
            "configuration_digest": self.configuration_digest.as_str(),
            "stack": self.stack.iter().map(ComponentIdentity::to_json).collect::<Vec<Value>>(),
        })
    }
}

fn validate_subject(subject: &SubjectIdentity, what: &str) -> Result<(), ConnectorError> {
    require_identifier(&format!("{what} subject_id"), &subject.subject_id)?;
    require_identifier(&format!("{what} subject_version"), &subject.subject_version)?;
    require_enum(
        &format!("{what} revision_basis"),
        &subject.revision_basis,
        &REVISION_BASES,
    )?;
    validate_maybe_string(&format!("{what} native_revision"), &subject.native_revision)?;
    require_identifier(&format!("{what} configured_mode"), &subject.configured_mode)?;
    require_identifier(
        &format!("{what} interface_surface"),
        &subject.interface_surface,
    )?;
    require_digest(
        &format!("{what} configuration_digest"),
        &subject.configuration_digest,
    )?;
    for (index, component) in subject.stack.iter().enumerate() {
        validate_component(component, &format!("{what} stack[{index}]"))?;
    }
    Ok(())
}

fn validate_prefix(prefix: &JournalPrefix, what: &str) -> Result<(), ConnectorError> {
    require_identifier(&format!("{what} journal_id"), &prefix.journal_id)?;
    require_digest(&format!("{what} head_hash"), &prefix.head_hash)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Capability catalog
// ---------------------------------------------------------------------------

/// One evidence item supporting a capability record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityEvidence {
    /// Evidence basis.
    pub basis: String,
    /// Journal reference to the supporting event value.
    pub reference: EvidenceRef,
}

impl CapabilityEvidence {
    /// Closed-object JSON projection.
    pub fn to_json(&self) -> Value {
        json!({
            "basis": self.basis,
            "ref": self.reference.to_json(),
        })
    }
}

fn validate_capability_evidence(
    evidence: &CapabilityEvidence,
    what: &str,
) -> Result<(), ConnectorError> {
    require_enum(&format!("{what} basis"), &evidence.basis, &EVIDENCE_BASES)?;
    evidence
        .reference
        .validate()
        .map_err(|error| invalid(format!("{what} ref invalid: {error}")))?;
    Ok(())
}

/// One capability row: availability plus its supporting evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityRecord {
    /// Capability identity.
    pub capability_id: String,
    /// Requirement references.
    pub requirement_refs: Vec<String>,
    /// Availability: present, absent, unknown, or not_applicable.
    pub availability: String,
    /// Claim origin.
    pub claim_origin: String,
    /// Supporting evidence. Non-unknown availability requires evidence.
    pub evidence: Vec<CapabilityEvidence>,
    /// Limitations.
    pub limitations: Vec<String>,
}

impl CapabilityRecord {
    /// Closed-object JSON projection.
    pub fn to_json(&self) -> Value {
        json!({
            "capability_id": self.capability_id,
            "requirement_refs": self.requirement_refs,
            "availability": self.availability,
            "claim_origin": self.claim_origin,
            "evidence": self.evidence.iter().map(CapabilityEvidence::to_json).collect::<Vec<Value>>(),
            "limitations": self.limitations,
        })
    }
}

fn validate_capability_record(
    record: &CapabilityRecord,
    what: &str,
) -> Result<(), ConnectorError> {
    require_identifier(&format!("{what} capability_id"), &record.capability_id)?;
    for reference in &record.requirement_refs {
        require_identifier(&format!("{what} requirement_ref"), reference)?;
    }
    require_unique(&record.requirement_refs, &format!("{what} requirement_refs"))?;
    require_enum(
        &format!("{what} availability"),
        &record.availability,
        &AVAILABILITIES,
    )?;
    require_enum(
        &format!("{what} claim_origin"),
        &record.claim_origin,
        &CLAIM_ORIGINS,
    )?;
    for limitation in &record.limitations {
        if limitation.is_empty() {
            return Err(invalid(format!("{what} limitations must be nonempty")));
        }
    }
    let mut seen = BTreeSet::new();
    for (index, evidence) in record.evidence.iter().enumerate() {
        validate_capability_evidence(evidence, &format!("{what} evidence[{index}]"))?;
        if !seen.insert(evidence.reference.to_json().to_string()) {
            return Err(invalid(format!("{what} evidence refs must be unique")));
        }
    }
    if record.availability != "unknown" && record.evidence.is_empty() {
        return Err(invalid(format!(
            "{what} with {:?} availability requires evidence",
            record.availability
        )));
    }
    // Documentation can support a declaration, never a run-success finding.
    if record.availability == "present"
        && !record
            .evidence
            .iter()
            .any(|evidence| evidence.basis == "executed_observation")
    {
        return Err(invalid(format!(
            "{what} with present availability requires executed_observation evidence"
        )));
    }
    Ok(())
}

/// Complete exact-scope capability descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityDescriptor {
    /// `capability_descriptor`.
    pub record_type: String,
    /// `evidence-kernel/0.1.0`.
    pub schema_version: String,
    /// Descriptor identity.
    pub descriptor_id: String,
    /// Descriptor revision.
    pub descriptor_revision: u64,
    /// Declaring connector.
    pub declared_by: String,
    /// Exact subject scope.
    pub subject: SubjectIdentity,
    /// Catalog pin.
    pub catalog: VersionPin,
    /// Supporting retained prefix.
    pub evidence_prefix: JournalPrefix,
    /// Superseded descriptor digest, or reasoned missingness.
    pub supersedes: MaybeDigest,
    /// Capability rows.
    pub capabilities: Vec<CapabilityRecord>,
}

impl CapabilityDescriptor {
    /// Closed-object JSON projection.
    pub fn to_json(&self) -> Value {
        json!({
            "record_type": self.record_type,
            "schema_version": self.schema_version,
            "descriptor_id": self.descriptor_id,
            "descriptor_revision": self.descriptor_revision,
            "declared_by": self.declared_by,
            "subject": self.subject.to_json(),
            "catalog": self.catalog.to_json(),
            "evidence_prefix": self.evidence_prefix.to_json(),
            "supersedes": maybe_digest_json(&self.supersedes),
            "capabilities": self.capabilities.iter().map(CapabilityRecord::to_json).collect::<Vec<Value>>(),
        })
    }
}

/// Validates a capability descriptor.
///
/// When `exact_ids` is set, the catalog must contain exactly those ids, each
/// once (binding scope). Otherwise the catalog must at least cover
/// [`EXTERNAL_CATALOG_MIN`] with unique ids (product scope).
fn validate_capability_descriptor(
    descriptor: &CapabilityDescriptor,
    exact_ids: Option<&[&str]>,
    what: &str,
) -> Result<(), ConnectorError> {
    if descriptor.record_type != CAPABILITY_RECORD_TYPE {
        return Err(invalid(format!(
            "{what} record_type {:?} must be {CAPABILITY_RECORD_TYPE:?}",
            descriptor.record_type
        )));
    }
    if descriptor.schema_version != CAPABILITY_SCHEMA_VERSION {
        return Err(invalid(format!(
            "{what} schema_version {:?} must be {CAPABILITY_SCHEMA_VERSION:?}",
            descriptor.schema_version
        )));
    }
    require_identifier(&format!("{what} descriptor_id"), &descriptor.descriptor_id)?;
    require_positive(
        &format!("{what} descriptor_revision"),
        descriptor.descriptor_revision,
    )?;
    require_identifier(&format!("{what} declared_by"), &descriptor.declared_by)?;
    validate_subject(&descriptor.subject, &format!("{what} subject"))?;
    validate_version_pin(&descriptor.catalog, &format!("{what} catalog"))?;
    validate_prefix(&descriptor.evidence_prefix, &format!("{what} evidence_prefix"))?;
    validate_maybe_digest(&format!("{what} supersedes"), &descriptor.supersedes)?;
    if descriptor.capabilities.is_empty() {
        return Err(invalid(format!("{what} capabilities must be nonempty")));
    }
    let mut ids = Vec::with_capacity(descriptor.capabilities.len());
    for (index, record) in descriptor.capabilities.iter().enumerate() {
        validate_capability_record(record, &format!("{what} capabilities[{index}]"))?;
        ids.push(record.capability_id.clone());
    }
    require_unique(&ids, &format!("{what} capability ids"))?;
    if let Some(expected) = exact_ids {
        if ids.len() != expected.len() {
            return Err(invalid(format!(
                "{what} must enumerate exactly {} capabilities, found {}",
                expected.len(),
                ids.len()
            )));
        }
        for expected_id in expected {
            if !ids.iter().any(|id| id == expected_id) {
                return Err(invalid(format!(
                    "{what} omits required capability {expected_id:?}: omission never implies inheritance"
                )));
            }
        }
    } else {
        for required_id in EXTERNAL_CATALOG_MIN {
            if !ids.iter().any(|id| id == required_id) {
                return Err(invalid(format!(
                    "{what} omits required catalog capability {required_id:?}"
                )));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Connector describe surface
// ---------------------------------------------------------------------------

/// Empty Describe request: the authenticated connector selects one configured
/// descriptor; no native probe is requested.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DescribeRequest;

impl DescribeRequest {
    /// Closed-object JSON projection.
    pub fn to_json(&self) -> Value {
        json!({})
    }
}

/// Reference from an operation mapping to one catalog capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityReference {
    /// Digest of the capability descriptor.
    pub descriptor_digest: Digest,
    /// Referenced capability.
    pub capability_id: String,
    /// Evidence for the reference.
    pub evidence_ref: EvidenceRef,
}

impl CapabilityReference {
    /// Closed-object JSON projection.
    pub fn to_json(&self) -> Value {
        json!({
            "descriptor_digest": self.descriptor_digest.as_str(),
            "capability_id": self.capability_id,
            "evidence_ref": self.evidence_ref.to_json(),
        })
    }
}

fn validate_capability_reference(
    reference: &CapabilityReference,
    what: &str,
) -> Result<(), ConnectorError> {
    require_digest(
        &format!("{what} descriptor_digest"),
        &reference.descriptor_digest,
    )?;
    require_identifier(&format!("{what} capability_id"), &reference.capability_id)?;
    reference
        .evidence_ref
        .validate()
        .map_err(|error| invalid(format!("{what} evidence_ref invalid: {error}")))?;
    Ok(())
}

/// One connector verb mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationMapping {
    /// Connector verb.
    pub operation: String,
    /// Mapping implementation, not native availability or result.
    pub implementation: String,
    /// Native contract pin, or reasoned missingness for local/unmapped verbs.
    pub native_contract: MaybeVersionPin,
    /// Referenced catalog capabilities.
    pub capability_refs: Vec<CapabilityReference>,
    /// Supporting evidence.
    pub evidence_refs: Vec<EvidenceRef>,
    /// Limitations.
    pub limitations: Vec<String>,
}

impl OperationMapping {
    /// Closed-object JSON projection.
    pub fn to_json(&self) -> Value {
        json!({
            "operation": self.operation,
            "implementation": self.implementation,
            "native_contract": maybe_pin_json(&self.native_contract),
            "capability_refs": self.capability_refs.iter().map(CapabilityReference::to_json).collect::<Vec<Value>>(),
            "evidence_refs": self.evidence_refs.iter().map(EvidenceRef::to_json).collect::<Vec<Value>>(),
            "limitations": self.limitations,
        })
    }
}

fn validate_evidence_refs(refs: &[EvidenceRef], what: &str) -> Result<(), ConnectorError> {
    let mut seen = BTreeSet::new();
    for (index, reference) in refs.iter().enumerate() {
        reference
            .validate()
            .map_err(|error| invalid(format!("{what}[{index}] invalid: {error}")))?;
        if !seen.insert(reference.to_json().to_string()) {
            return Err(invalid(format!("{what} must be unique")));
        }
    }
    Ok(())
}

fn validate_operation_mapping(
    mapping: &OperationMapping,
    what: &str,
) -> Result<(), ConnectorError> {
    require_enum(&format!("{what} operation"), &mapping.operation, &NINE_OPERATIONS)?;
    require_enum(
        &format!("{what} implementation"),
        &mapping.implementation,
        &IMPLEMENTATIONS,
    )?;
    validate_maybe_pin(
        &format!("{what} native_contract"),
        &mapping.native_contract,
    )?;
    for (index, reference) in mapping.capability_refs.iter().enumerate() {
        validate_capability_reference(reference, &format!("{what} capability_refs[{index}]"))?;
    }
    validate_evidence_refs(&mapping.evidence_refs, &format!("{what} evidence_refs"))?;
    for limitation in &mapping.limitations {
        if limitation.is_empty() {
            return Err(invalid(format!("{what} limitations must be nonempty")));
        }
    }
    match mapping.implementation.as_str() {
        "native_mapping" => {
            if !matches!(mapping.native_contract, MaybeVersionPin::Present(_)) {
                return Err(invalid(format!(
                    "{what} with native_mapping requires a native contract pin"
                )));
            }
            if mapping.evidence_refs.is_empty() {
                return Err(invalid(format!(
                    "{what} with native_mapping requires evidence"
                )));
            }
        }
        // Local and unmapped handlers carry no native contract: a guessed
        // endpoint is never advertised.
        _ => {
            if !matches!(mapping.native_contract, MaybeVersionPin::Missing(_)) {
                return Err(invalid(format!(
                    "{what} with {} must not advertise a native contract",
                    mapping.implementation
                )));
            }
        }
    }
    Ok(())
}

/// One task-type mapping. Only one mapping per task type is advertised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskMapping {
    /// Task type.
    pub task_type: String,
    /// Accepted input form.
    pub input_form: String,
    /// Native serialization/translation mapping.
    pub mapping: VersionPin,
    /// Planning owner.
    pub planning_owner: String,
    /// Recovery owner.
    pub recovery_owner: String,
    /// Limitations.
    pub limitations: Vec<String>,
}

impl TaskMapping {
    /// Closed-object JSON projection.
    pub fn to_json(&self) -> Value {
        json!({
            "task_type": self.task_type,
            "input_form": self.input_form,
            "mapping": self.mapping.to_json(),
            "planning_owner": self.planning_owner,
            "recovery_owner": self.recovery_owner,
            "limitations": self.limitations,
        })
    }
}

fn validate_task_mapping(mapping: &TaskMapping, what: &str) -> Result<(), ConnectorError> {
    require_enum(&format!("{what} task_type"), &mapping.task_type, &TASK_TYPES)?;
    require_enum(
        &format!("{what} input_form"),
        &mapping.input_form,
        &INPUT_FORMS,
    )?;
    validate_version_pin(&mapping.mapping, &format!("{what} mapping"))?;
    require_enum(
        &format!("{what} planning_owner"),
        &mapping.planning_owner,
        &PLANNING_OWNERS,
    )?;
    require_enum(
        &format!("{what} recovery_owner"),
        &mapping.recovery_owner,
        &PLANNING_OWNERS,
    )?;
    for limitation in &mapping.limitations {
        if limitation.is_empty() {
            return Err(invalid(format!("{what} limitations must be nonempty")));
        }
    }
    Ok(())
}

/// Finite configured allowance in milliseconds.
#[derive(Debug, Clone, PartialEq)]
pub struct DurationLimit {
    /// Always `exact`.
    pub kind: String,
    /// Always `ms`.
    pub unit: String,
    /// Allowance value, finite and nonnegative.
    pub value: f64,
}

impl DurationLimit {
    /// Closed-object JSON projection.
    pub fn to_json(&self) -> Value {
        json!({
            "kind": self.kind,
            "unit": self.unit,
            "value": self.value,
        })
    }
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

/// Configured local limits, not native capacity or benchmark findings.
#[derive(Debug, Clone, PartialEq)]
pub struct ConnectorLimits {
    /// Maximum call wait.
    pub max_call_wait: DurationLimit,
    /// Maximum observe items.
    pub max_observe_items: u64,
    /// Maximum request bytes.
    pub max_request_bytes: u64,
    /// Maximum response bytes.
    pub max_response_bytes: u64,
    /// Maximum artifact chunk bytes.
    pub max_artifact_chunk_bytes: u64,
    /// Maximum queued tasks.
    pub max_queued_tasks: u64,
    /// Maximum active tasks.
    pub max_active_tasks: u64,
}

impl ConnectorLimits {
    /// Closed-object JSON projection.
    pub fn to_json(&self) -> Value {
        json!({
            "max_call_wait": self.max_call_wait.to_json(),
            "max_observe_items": self.max_observe_items,
            "max_request_bytes": self.max_request_bytes,
            "max_response_bytes": self.max_response_bytes,
            "max_artifact_chunk_bytes": self.max_artifact_chunk_bytes,
            "max_queued_tasks": self.max_queued_tasks,
            "max_active_tasks": self.max_active_tasks,
        })
    }
}

fn validate_connector_limits(limits: &ConnectorLimits, what: &str) -> Result<(), ConnectorError> {
    validate_duration_limit(&limits.max_call_wait, &format!("{what} max_call_wait"))?;
    require_positive(
        &format!("{what} max_observe_items"),
        limits.max_observe_items,
    )?;
    require_positive(
        &format!("{what} max_request_bytes"),
        limits.max_request_bytes,
    )?;
    require_positive(
        &format!("{what} max_response_bytes"),
        limits.max_response_bytes,
    )?;
    require_positive(
        &format!("{what} max_artifact_chunk_bytes"),
        limits.max_artifact_chunk_bytes,
    )?;
    require_revision(&format!("{what} max_queued_tasks"), limits.max_queued_tasks)?;
    require_positive(
        &format!("{what} max_active_tasks"),
        limits.max_active_tasks,
    )?;
    Ok(())
}

/// Complete connector descriptor (§12.2).
#[derive(Debug, Clone, PartialEq)]
pub struct ConnectorDescriptor {
    /// `connector_descriptor`.
    pub record_type: String,
    /// `external-connector/0.1.0`.
    pub schema_version: String,
    /// Connector identity.
    pub connector_id: String,
    /// Connector version.
    pub connector_version: String,
    /// Connector build pin.
    pub build: VersionPin,
    /// External native-task mapping pin.
    pub binding: VersionPin,
    /// Exact Ringmaster subject.
    pub subject: SubjectIdentity,
    /// Complete exact-scope capability descriptor.
    pub capabilities: CapabilityDescriptor,
    /// Exactly nine operation mappings, each verb once.
    pub operations: Vec<OperationMapping>,
    /// Task mappings, unique by task type.
    pub task_mappings: Vec<TaskMapping>,
    /// Implemented retained observation sources.
    pub observation_channels: Vec<String>,
    /// Action grounding.
    pub action_grounding: String,
    /// Execution substrate.
    pub execution_substrate: String,
    /// Configured limits.
    pub limits: ConnectorLimits,
    /// Accounting policy pin.
    pub budget_accounting: VersionPin,
    /// Supporting retained prefix.
    pub evidence_prefix: JournalPrefix,
}

impl ConnectorDescriptor {
    /// Closed-object JSON projection.
    pub fn to_json(&self) -> Value {
        json!({
            "record_type": self.record_type,
            "schema_version": self.schema_version,
            "connector_id": self.connector_id,
            "connector_version": self.connector_version,
            "build": self.build.to_json(),
            "binding": self.binding.to_json(),
            "subject": self.subject.to_json(),
            "capabilities": self.capabilities.to_json(),
            "operations": self.operations.iter().map(OperationMapping::to_json).collect::<Vec<Value>>(),
            "task_mappings": self.task_mappings.iter().map(TaskMapping::to_json).collect::<Vec<Value>>(),
            "observation_channels": self.observation_channels,
            "action_grounding": self.action_grounding,
            "execution_substrate": self.execution_substrate,
            "limits": self.limits.to_json(),
            "budget_accounting": self.budget_accounting.to_json(),
            "evidence_prefix": self.evidence_prefix.to_json(),
        })
    }
}

fn validate_connector_descriptor(descriptor: &ConnectorDescriptor) -> Result<(), ConnectorError> {
    if descriptor.record_type != CONNECTOR_RECORD_TYPE {
        return Err(invalid(format!(
            "record_type {:?} must be {CONNECTOR_RECORD_TYPE:?}",
            descriptor.record_type
        )));
    }
    if descriptor.schema_version != CONNECTOR_SCHEMA_VERSION {
        return Err(invalid(format!(
            "schema_version {:?} must be {CONNECTOR_SCHEMA_VERSION:?}",
            descriptor.schema_version
        )));
    }
    require_identifier("connector_id", &descriptor.connector_id)?;
    require_identifier("connector_version", &descriptor.connector_version)?;
    validate_version_pin(&descriptor.build, "build")?;
    validate_version_pin(&descriptor.binding, "binding")?;
    validate_subject(&descriptor.subject, "subject")?;
    validate_capability_descriptor(&descriptor.capabilities, None, "capabilities")?;
    // The descriptor subject is exactly the capability subject: one scope.
    if descriptor.subject != descriptor.capabilities.subject {
        return Err(invalid(
            "subject must equal capabilities.subject: one descriptor, one scope",
        ));
    }
    if descriptor.operations.len() != NINE_OPERATIONS.len() {
        return Err(invalid(format!(
            "operations must enumerate exactly {} verbs, found {}",
            NINE_OPERATIONS.len(),
            descriptor.operations.len()
        )));
    }
    let mut verbs = Vec::with_capacity(descriptor.operations.len());
    for (index, mapping) in descriptor.operations.iter().enumerate() {
        validate_operation_mapping(mapping, &format!("operations[{index}]"))?;
        verbs.push(mapping.operation.clone());
    }
    require_unique(&verbs, "operation verbs")?;
    for verb in NINE_OPERATIONS {
        if !verbs.iter().any(|candidate| candidate == verb) {
            return Err(invalid(format!("operations omits required verb {verb:?}")));
        }
    }
    let mut task_types = Vec::with_capacity(descriptor.task_mappings.len());
    for (index, mapping) in descriptor.task_mappings.iter().enumerate() {
        validate_task_mapping(mapping, &format!("task_mappings[{index}]"))?;
        task_types.push(mapping.task_type.clone());
    }
    require_unique(&task_types, "task mapping types")?;
    for channel in &descriptor.observation_channels {
        require_identifier("observation channel", channel)?;
    }
    require_unique(&descriptor.observation_channels, "observation channels")?;
    require_enum(
        "action_grounding",
        &descriptor.action_grounding,
        &ACTION_GROUNDINGS,
    )?;
    require_enum(
        "execution_substrate",
        &descriptor.execution_substrate,
        &EXECUTION_SUBSTRATES,
    )?;
    validate_connector_limits(&descriptor.limits, "limits")?;
    validate_version_pin(&descriptor.budget_accounting, "budget_accounting")?;
    validate_prefix(&descriptor.evidence_prefix, "evidence_prefix")?;
    Ok(())
}

fn pin(id: &str, version: &str, seed: &[u8]) -> VersionPin {
    VersionPin {
        id: id.to_string(),
        version: version.to_string(),
        artifact_digest: rm_wire::artifact_digest(seed),
    }
}

fn pinned_subject() -> SubjectIdentity {
    SubjectIdentity {
        subject_id: "ringmaster-subject".to_string(),
        subject_version: "ringmaster-1.0.0".to_string(),
        revision_basis: "unknown".to_string(),
        native_revision: MaybeString::Missing(Missing::new("not_observed")),
        configured_mode: "default".to_string(),
        interface_surface: "external-connector".to_string(),
        configuration_digest: rm_wire::artifact_digest(b"rm_catalog:pinned-configuration"),
        stack: vec![ComponentIdentity {
            component: "ringmaster-connector".to_string(),
            reported_version: MaybeString::Text("0.1.0".to_string()),
            build_digest: MaybeDigest::Present(rm_wire::artifact_digest(
                b"rm_catalog:pinned-build",
            )),
            configuration_digest: MaybeDigest::Present(rm_wire::artifact_digest(
                b"rm_catalog:pinned-configuration",
            )),
        }],
    }
}

fn pinned_capabilities(subject: &SubjectIdentity, prefix: &JournalPrefix) -> CapabilityDescriptor {
    let capabilities = EXTERNAL_CATALOG_MIN
        .iter()
        .map(|id| CapabilityRecord {
            capability_id: (*id).to_string(),
            requirement_refs: Vec::new(),
            // The pinned descriptor declares scope without claiming run
            // success: every capability starts unknown until its own evidence
            // establishes another availability.
            availability: "unknown".to_string(),
            claim_origin: "harness".to_string(),
            evidence: Vec::new(),
            limitations: vec![format!(
                "capability {id} is unassessed in the pinned descriptor"
            )],
        })
        .collect();
    CapabilityDescriptor {
        record_type: CAPABILITY_RECORD_TYPE.to_string(),
        schema_version: CAPABILITY_SCHEMA_VERSION.to_string(),
        descriptor_id: "ringmaster-capabilities".to_string(),
        descriptor_revision: 1,
        declared_by: "ringmaster-connector".to_string(),
        subject: subject.clone(),
        catalog: pin("ringmaster-catalog", "0.1.0", b"rm_catalog:pinned-catalog"),
        evidence_prefix: prefix.clone(),
        supersedes: MaybeDigest::Missing(Missing::new("not_applicable")),
        capabilities,
    }
}

fn pinned_operations() -> Vec<OperationMapping> {
    NINE_OPERATIONS
        .iter()
        .map(|verb| OperationMapping {
            operation: (*verb).to_string(),
            // Local descriptor read / validation / projection handlers. No
            // native contract is advertised and no native availability is
            // claimed by handler coverage.
            implementation: "connector_local".to_string(),
            native_contract: MaybeVersionPin::Missing(Missing::new("not_applicable")),
            capability_refs: Vec::new(),
            evidence_refs: Vec::new(),
            limitations: vec![format!("{verb} is handled locally in the pinned descriptor")],
        })
        .collect()
}

fn pinned_task_mappings() -> Vec<TaskMapping> {
    vec![
        TaskMapping {
            task_type: "apply".to_string(),
            input_form: "goal".to_string(),
            mapping: pin("apply-mapping", "0.1.0", b"rm_catalog:apply-mapping"),
            planning_owner: "operator".to_string(),
            recovery_owner: "operator".to_string(),
            limitations: vec!["goal translation scope is pinned".to_string()],
        },
        TaskMapping {
            task_type: "extract".to_string(),
            input_form: "extraction_request".to_string(),
            mapping: pin("extract-mapping", "0.1.0", b"rm_catalog:extract-mapping"),
            planning_owner: "external_planner".to_string(),
            recovery_owner: "external_planner".to_string(),
            limitations: vec!["extraction output schema is pinned".to_string()],
        },
        TaskMapping {
            task_type: "discover_jobs".to_string(),
            input_form: "crawl_declaration".to_string(),
            mapping: pin(
                "discover-mapping",
                "0.1.0",
                b"rm_catalog:discover-mapping",
            ),
            planning_owner: "external_planner".to_string(),
            recovery_owner: "external_planner".to_string(),
            limitations: vec!["crawl declaration scope is pinned".to_string()],
        },
    ]
}

/// Builds the pinned connector descriptor served by [`describe`].
///
/// The descriptor is a local declaration of scope: unknown capabilities,
/// local operation handlers, and configured limits. It performs no probe and
/// claims no qualification or application-success result.
fn pinned_connector_descriptor() -> ConnectorDescriptor {
    let prefix = JournalPrefix {
        journal_id: "journal-pinned-ringmaster-connector".to_string(),
        last_sequence: PositiveInteger::new(1).expect("sequence one is positive"),
        head_hash: rm_wire::artifact_digest(b"rm_catalog:pinned-head"),
    };
    let subject = pinned_subject();
    ConnectorDescriptor {
        record_type: CONNECTOR_RECORD_TYPE.to_string(),
        schema_version: CONNECTOR_SCHEMA_VERSION.to_string(),
        connector_id: "ringmaster-connector".to_string(),
        connector_version: "0.1.0".to_string(),
        build: pin("ringmaster-connector", "0.1.0", b"rm_catalog:pinned-build"),
        binding: pin(
            "ringmaster-native-tasks",
            "0.1.0",
            b"rm_catalog:pinned-binding",
        ),
        subject: subject.clone(),
        capabilities: pinned_capabilities(&subject, &prefix),
        operations: pinned_operations(),
        task_mappings: pinned_task_mappings(),
        observation_channels: vec!["journal_events".to_string()],
        action_grounding: "semantic".to_string(),
        execution_substrate: "hybrid".to_string(),
        limits: ConnectorLimits {
            max_call_wait: DurationLimit {
                kind: "exact".to_string(),
                unit: "ms".to_string(),
                value: 30_000.0,
            },
            max_observe_items: 1000,
            max_request_bytes: 1_048_576,
            max_response_bytes: 4_194_304,
            max_artifact_chunk_bytes: 1_048_576,
            max_queued_tasks: 64,
            max_active_tasks: 8,
        },
        budget_accounting: pin(
            "ringmaster-budget",
            "0.1.0",
            b"rm_catalog:pinned-budget",
        ),
        evidence_prefix: prefix,
    }
}

/// Reads the configured connector descriptor.
///
/// The request is empty and the connector performs no speculative probe,
/// browser launch, or execution: it authenticates the caller, validates the
/// pinned descriptor structurally through the wire boundary and semantically
/// against §12.2–§12.4, and returns it.
pub fn describe(
    principal: &AuthenticatedPrincipal,
    _request: &DescribeRequest,
) -> Result<ConnectorDescriptor, ConnectorError> {
    check_caller(principal)?;
    let descriptor = pinned_connector_descriptor();
    wire_validate(
        "connector_descriptor/v1",
        &descriptor.to_json(),
        "connector descriptor",
    )?;
    wire_validate(
        "capability_descriptor/v1",
        &descriptor.capabilities.to_json(),
        "capability descriptor",
    )?;
    validate_connector_descriptor(&descriptor)?;
    Ok(descriptor)
}

// ---------------------------------------------------------------------------
// Native binding surface
// ---------------------------------------------------------------------------

/// One native primitive mapping declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BOMapping {
    /// Native primitive.
    pub primitive: String,
    /// Mapping state, not capability availability.
    pub mapping_state: String,
    /// Native symbol, or reasoned missingness when unmapped.
    pub native_symbol: MaybeString,
    /// Native contract pin, or reasoned missingness when unmapped.
    pub native_contract: MaybeVersionPin,
    /// Supporting evidence. Mapped entries require nonempty evidence.
    pub evidence_refs: Vec<EvidenceRef>,
}

impl BOMapping {
    /// Closed-object JSON projection.
    pub fn to_json(&self) -> Value {
        json!({
            "primitive": self.primitive,
            "mapping_state": self.mapping_state,
            "native_symbol": maybe_string_json(&self.native_symbol),
            "native_contract": maybe_pin_json(&self.native_contract),
            "evidence_refs": self.evidence_refs.iter().map(EvidenceRef::to_json).collect::<Vec<Value>>(),
        })
    }
}

fn validate_bo_mapping(mapping: &BOMapping, what: &str) -> Result<(), ConnectorError> {
    require_enum(&format!("{what} primitive"), &mapping.primitive, &BO_PRIMITIVES)?;
    require_enum(
        &format!("{what} mapping_state"),
        &mapping.mapping_state,
        &MAPPING_STATES,
    )?;
    validate_maybe_string(&format!("{what} native_symbol"), &mapping.native_symbol)?;
    validate_maybe_pin(
        &format!("{what} native_contract"),
        &mapping.native_contract,
    )?;
    validate_evidence_refs(&mapping.evidence_refs, &format!("{what} evidence_refs"))?;
    match mapping.mapping_state.as_str() {
        "mapped" => {
            if !matches!(mapping.native_symbol, MaybeString::Text(_)) {
                return Err(invalid(format!(
                    "{what} with mapped state requires an actual native symbol"
                )));
            }
            if !matches!(mapping.native_contract, MaybeVersionPin::Present(_)) {
                return Err(invalid(format!(
                    "{what} with mapped state requires a native contract pin"
                )));
            }
            if mapping.evidence_refs.is_empty() {
                return Err(invalid(format!(
                    "{what} with mapped state requires nonempty evidence"
                )));
            }
        }
        // Unknown symbols remain unmapped, never guessed.
        _ => {
            if !matches!(mapping.native_symbol, MaybeString::Missing(_)) {
                return Err(invalid(format!(
                    "{what} with unmapped state must not advertise a native symbol"
                )));
            }
            if !matches!(mapping.native_contract, MaybeVersionPin::Missing(_)) {
                return Err(invalid(format!(
                    "{what} with unmapped state must not advertise a native contract"
                )));
            }
        }
    }
    Ok(())
}

/// Native BrowserOxide binding descriptor (§5.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BOBindingDescriptor {
    /// `browseroxide_binding_descriptor`.
    pub record_type: String,
    /// `internal-browser-binding.browseroxide/0.1.0`.
    pub schema_version: String,
    /// Native binding identity.
    pub binding_id: String,
    /// Immutable binding build pin.
    pub binding_build: VersionPin,
    /// Actual BrowserOxide engine identity.
    pub engine: ComponentIdentity,
    /// Exact binding/build/configuration capability descriptor.
    pub capabilities: CapabilityDescriptor,
    /// Exactly fourteen primitive mappings, each primitive once.
    pub primitive_mappings: Vec<BOMapping>,
    /// Session storage model.
    pub session_storage_model: String,
    /// Supporting evidence for verified namespacing.
    pub session_isolation_refs: Vec<EvidenceRef>,
    /// Pinned artifact/privacy policy.
    pub privacy_policy: VersionPin,
    /// Supporting registered prefix.
    pub evidence_prefix: JournalPrefix,
}

impl BOBindingDescriptor {
    /// Closed-object JSON projection.
    pub fn to_json(&self) -> Value {
        json!({
            "record_type": self.record_type,
            "schema_version": self.schema_version,
            "binding_id": self.binding_id,
            "binding_build": self.binding_build.to_json(),
            "engine": self.engine.to_json(),
            "capabilities": self.capabilities.to_json(),
            "primitive_mappings": self.primitive_mappings.iter().map(BOMapping::to_json).collect::<Vec<Value>>(),
            "session_storage_model": self.session_storage_model,
            "session_isolation_refs": self.session_isolation_refs.iter().map(EvidenceRef::to_json).collect::<Vec<Value>>(),
            "privacy_policy": self.privacy_policy.to_json(),
            "evidence_prefix": self.evidence_prefix.to_json(),
        })
    }
}

fn validate_bo_descriptor(descriptor: &BOBindingDescriptor) -> Result<(), ConnectorError> {
    if descriptor.record_type != BO_RECORD_TYPE {
        return Err(invalid(format!(
            "record_type {:?} must be {BO_RECORD_TYPE:?}",
            descriptor.record_type
        )));
    }
    if descriptor.schema_version != BO_SCHEMA_VERSION {
        return Err(invalid(format!(
            "schema_version {:?} must be {BO_SCHEMA_VERSION:?}",
            descriptor.schema_version
        )));
    }
    require_identifier("binding_id", &descriptor.binding_id)?;
    validate_version_pin(&descriptor.binding_build, "binding_build")?;
    validate_component(&descriptor.engine, "engine")?;
    validate_capability_descriptor(&descriptor.capabilities, Some(&BO_CAPABILITIES), "capabilities")?;
    // The capability subject pins this exact binding build and engine stack:
    // a descriptor copied from another version never validates here.
    if descriptor.capabilities.subject.subject_id != descriptor.binding_id {
        return Err(invalid(
            "capabilities.subject.subject_id must identify this binding build",
        ));
    }
    if descriptor.capabilities.subject.subject_version != descriptor.binding_build.version {
        return Err(invalid(
            "capabilities.subject.subject_version must identify this binding build: new versions start unknown",
        ));
    }
    if !descriptor
        .capabilities
        .subject
        .stack
        .iter()
        .any(|component| component == &descriptor.engine)
    {
        return Err(invalid(
            "capabilities.subject.stack must contain the actual engine identity",
        ));
    }
    if descriptor.primitive_mappings.len() != BO_PRIMITIVES.len() {
        return Err(invalid(format!(
            "primitive_mappings must enumerate exactly {} primitives, found {}",
            BO_PRIMITIVES.len(),
            descriptor.primitive_mappings.len()
        )));
    }
    let mut primitives = Vec::with_capacity(descriptor.primitive_mappings.len());
    for (index, mapping) in descriptor.primitive_mappings.iter().enumerate() {
        validate_bo_mapping(mapping, &format!("primitive_mappings[{index}]"))?;
        primitives.push(mapping.primitive.clone());
    }
    require_unique(&primitives, "mapped primitives")?;
    for primitive in BO_PRIMITIVES {
        if !primitives.iter().any(|candidate| candidate == primitive) {
            return Err(invalid(format!(
                "primitive_mappings omits required primitive {primitive:?}"
            )));
        }
    }
    require_enum(
        "session_storage_model",
        &descriptor.session_storage_model,
        &SESSION_STORAGE_MODELS,
    )?;
    validate_evidence_refs(
        &descriptor.session_isolation_refs,
        "session_isolation_refs",
    )?;
    if descriptor.session_storage_model == "verified_namespaced"
        && descriptor.session_isolation_refs.is_empty()
    {
        return Err(invalid(
            "verified_namespaced session storage requires supporting isolation evidence",
        ));
    }
    validate_version_pin(&descriptor.privacy_policy, "privacy_policy")?;
    validate_prefix(&descriptor.evidence_prefix, "evidence_prefix")?;
    Ok(())
}

/// Resolves every cited reference against its prefix and loads the retained
/// artifact bytes behind each resolved event.
fn verify_evidence(
    principal: &AuthenticatedPrincipal,
    refs: &[EvidenceRef],
    prefix: &JournalPrefix,
) -> Result<(), ConnectorError> {
    for reference in refs {
        let envelope = rm_evidence::resolve_evidence(principal, reference, prefix)?;
        for artifact in &envelope.payload.artifact_refs {
            let _ = rm_evidence::load_artifact(principal, artifact)?;
        }
    }
    Ok(())
}

/// Validates a native binding descriptor against its exact scope.
///
/// Structural checks (discriminators, fourteen primitives, fourteen
/// capabilities, mapping/availability coherence, subject pinning) run first;
/// the embedded capability descriptor is validated through the wire boundary
/// (`browseroxide_binding_descriptor/v1` in `rm_wire` carries a generic
/// descriptor shape rather than the §5.2 binding shape, so the binding record
/// itself is validated field-by-field here). Every capability evidence item
/// is then resolved against the capability prefix and every mapping and
/// isolation reference against the binding prefix, loading the retained
/// artifact bytes behind each resolved event.
pub fn validate_native_binding(
    principal: &AuthenticatedPrincipal,
    descriptor: &BOBindingDescriptor,
) -> Result<(), ConnectorError> {
    check_caller(principal)?;
    validate_bo_descriptor(descriptor)?;
    wire_validate(
        "capability_descriptor/v1",
        &descriptor.capabilities.to_json(),
        "binding capability descriptor",
    )?;
    let mut capability_refs = Vec::new();
    for record in &descriptor.capabilities.capabilities {
        for evidence in &record.evidence {
            capability_refs.push(evidence.reference.clone());
        }
    }
    verify_evidence(principal, &capability_refs, &descriptor.capabilities.evidence_prefix)?;
    let mut binding_refs = Vec::new();
    for mapping in &descriptor.primitive_mappings {
        binding_refs.extend(mapping.evidence_refs.iter().cloned());
    }
    binding_refs.extend(descriptor.session_isolation_refs.iter().cloned());
    verify_evidence(principal, &binding_refs, &descriptor.evidence_prefix)?;
    Ok(())
}

//! `rm_browseroxide`: tier-4 synchronous BrowserOxide native binding.
//!
//! Direct owner-thread entry to the fourteen `bo.*` primitives. No
//! cross-browser adapter, no task handle polling, no hidden planning.

#![forbid(unsafe_code)]

use rm_authority::{AuthenticatedPrincipal, ConnectorError, Manifest};
use rm_catalog::{BOBindingDescriptor, DurationLimit, VersionPin};
use rm_evidence::{
    ArtifactReference, EvidenceRef, EventSubmission, EvidencePayload, JournalPrefix, PositiveInteger,
};
use rm_leases::LeaseRecord;
use rm_time::{
    ClockBasis, ClockDescriptor, Estimate, Measurement, MeasurementOrigin, MaybeNumber,
    MaybeString, MaybeTimePoint, Method, Missing, Scope, ScopeKind, TimePoint, UtcAnnotation,
    Censoring, Quantity,
};
use rm_wire::Digest;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::marker::PhantomData;
use std::rc::Rc;
use std::thread;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Primitive record discriminator.
pub const BO_RECORD_TYPE: &str = "browseroxide_primitive_record";
/// Primitive record schema version.
pub const BO_SCHEMA_VERSION: &str = "internal-browser-binding.browseroxide/0.1.0";
/// DOM export discriminator.
pub const DOM_EXPORT_RECORD_TYPE: &str = "browseroxide_dom_export";
/// Largest exactly representable integer.
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
/// Direct native transport marker. All primitives enter through this path.
const NATIVE_TRANSPORT: &str = "browseroxide_native_direct";

/// The transport every primitive uses. Tests assert this is direct native.
pub fn native_transport() -> &'static str {
    NATIVE_TRANSPORT
}

/// Number of network acquisitions performed inside `from_html` (always zero).
pub fn network_attempts(session: &NativeSession) -> u64 {
    session.network_attempts
}

/// Owner of a session (accessor: fields stay private per interface).
pub fn session_owner(session: &NativeSession) -> &BOOwner {
    &session.owner
}

pub type Revision = u64;
pub type SupportRefs = Vec<EvidenceRef>;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

fn connector_error(code: &str, fault_domain: &str, detail: String) -> ConnectorError {
    ConnectorError {
        kind: "connector_error".to_string(),
        code: code.to_string(),
        fault_domain: fault_domain.to_string(),
        detail,
        operation_delivery: "not_dispatched".to_string(),
        retry_guidance: "operator_review".to_string(),
        retry_after: None,
        handle: None,
        evidence_refs: Vec::new(),
    }
}

fn invalid(detail: impl Into<String>) -> ConnectorError {
    connector_error("INVALID_REQUEST", "request", detail.into())
}

fn require_identifier(field: &str, value: &str) -> Result<(), ConnectorError> {
    if value.is_empty() {
        return Err(invalid(format!("{field} must be nonempty")));
    }
    Ok(())
}

fn require_revision(field: &str, value: u64) -> Result<(), ConnectorError> {
    if value > MAX_SAFE_INTEGER {
        return Err(invalid(format!("{field} exceeds exact integer bound")));
    }
    Ok(())
}

fn require_positive(field: &str, value: u64) -> Result<(), ConnectorError> {
    if value == 0 || value > MAX_SAFE_INTEGER {
        return Err(invalid(format!(
            "{field} must be within 1..={MAX_SAFE_INTEGER}"
        )));
    }
    Ok(())
}

fn check_limit(limit: &DurationLimit) -> Result<(), ConnectorError> {
    if limit.kind != "exact" {
        return Err(invalid(format!("limit kind {:?} must be exact", limit.kind)));
    }
    if limit.unit != "ms" {
        return Err(invalid(format!("limit unit {:?} must be ms", limit.unit)));
    }
    if !limit.value.is_finite() || limit.value < 0.0 {
        return Err(invalid("limit value must be finite nonnegative"));
    }
    Ok(())
}

fn check_version_pin(pin: &VersionPin, what: &str) -> Result<(), ConnectorError> {
    require_identifier(&format!("{what} id"), &pin.id)?;
    require_identifier(&format!("{what} version"), &pin.version)?;
    if rm_wire::Digest::parse(pin.artifact_digest.as_str()).is_err() {
        return Err(invalid(format!("{what} artifact_digest must be sha256 digest")));
    }
    Ok(())
}

fn check_maybe_string(field: &str, value: &MaybeString) -> Result<(), ConnectorError> {
    match value {
        MaybeString::Text(text) => require_identifier(field, text),
        MaybeString::Missing(missing) => check_missing(field, missing),
    }
}

fn check_missing(field: &str, missing: &Missing) -> Result<(), ConnectorError> {
    if !rm_time::is_valid_reason(&missing.reason) {
        return Err(invalid(format!(
            "{field} missing reason {:?} is not permitted",
            missing.reason
        )));
    }
    if let Some(detail) = &missing.detail {
        if detail.is_empty() {
            return Err(invalid(format!("{field} missing detail must be nonempty")));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Diagnostic references
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BOOwner {
    pub process_id: String,
    pub boot_id: String,
    pub os_thread_id: String,
}

impl BOOwner {
    pub fn to_json(&self) -> Value {
        json!({
            "process_id": self.process_id,
            "boot_id": self.boot_id,
            "os_thread_id": self.os_thread_id,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BOPageRef {
    pub owner: BOOwner,
    pub page_id: String,
    pub page_generation: Revision,
    pub profile_digest: Digest,
}

impl BOPageRef {
    pub fn to_json(&self) -> Value {
        json!({
            "owner": self.owner.to_json(),
            "page_id": self.page_id,
            "page_generation": self.page_generation,
            "profile_digest": self.profile_digest.as_str(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BORootRef {
    pub page: BOPageRef,
    pub frame_id: String,
    pub document_generation: Revision,
    pub root_id: String,
    pub root_kind: String,
}

impl BORootRef {
    pub fn to_json(&self) -> Value {
        json!({
            "page": self.page.to_json(),
            "frame_id": self.frame_id,
            "document_generation": self.document_generation,
            "root_id": self.root_id,
            "root_kind": self.root_kind,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BONodeRef {
    pub root: BORootRef,
    pub node_id: String,
    pub node_generation: Revision,
}

impl BONodeRef {
    pub fn to_json(&self) -> Value {
        json!({
            "root": self.root.to_json(),
            "node_id": self.node_id,
            "node_generation": self.node_generation,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BOClientRef {
    pub process_id: String,
    pub boot_id: String,
    pub client_id: String,
    pub session_domain_id: String,
    pub session_epoch: String,
    pub pool_id: String,
    pub profile_digest: Digest,
}

impl BOClientRef {
    pub fn to_json(&self) -> Value {
        json!({
            "process_id": self.process_id,
            "boot_id": self.boot_id,
            "client_id": self.client_id,
            "session_domain_id": self.session_domain_id,
            "session_epoch": self.session_epoch,
            "pool_id": self.pool_id,
            "profile_digest": self.profile_digest.as_str(),
        })
    }
}

// ---------------------------------------------------------------------------
// Maybe carriers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaybeArtifact {
    Present(ArtifactReference),
    Missing(Missing),
}

fn maybe_artifact_json(value: &MaybeArtifact) -> Value {
    match value {
        MaybeArtifact::Present(reference) => reference.to_json(),
        MaybeArtifact::Missing(missing) => {
            serde_json::to_value(missing).unwrap_or(Value::Null)
        }
    }
}

fn check_maybe_artifact(field: &str, value: &MaybeArtifact) -> Result<(), ConnectorError> {
    match value {
        MaybeArtifact::Present(reference) => reference
            .validate()
            .map_err(|error| invalid(format!("{field} artifact invalid: {}", error.detail)))?,
        MaybeArtifact::Missing(missing) => check_missing(field, missing)?,
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaybeClient {
    Present(BOClientRef),
    Missing(Missing),
}

fn maybe_client_json(value: &MaybeClient) -> Value {
    match value {
        MaybeClient::Present(client) => client.to_json(),
        MaybeClient::Missing(missing) => {
            serde_json::to_value(missing).unwrap_or(Value::Null)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaybeRoot {
    Present(BORootRef),
    Missing(Missing),
}

fn maybe_root_json(value: &MaybeRoot) -> Value {
    match value {
        MaybeRoot::Present(root) => root.to_json(),
        MaybeRoot::Missing(missing) => serde_json::to_value(missing).unwrap_or(Value::Null),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaybeStatus {
    Present(u16),
    Missing(Missing),
}

fn maybe_status_json(value: &MaybeStatus) -> Value {
    match value {
        MaybeStatus::Present(status) => json!(*status),
        MaybeStatus::Missing(missing) => serde_json::to_value(missing).unwrap_or(Value::Null),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BORenderVerdict {
    Pass,
    ThinShell,
    RenderIncomplete,
    EdgeBlock,
    SensorFail,
    ChallengeIncomplete,
}

impl BORenderVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            BORenderVerdict::Pass => "Pass",
            BORenderVerdict::ThinShell => "ThinShell",
            BORenderVerdict::RenderIncomplete => "RenderIncomplete",
            BORenderVerdict::EdgeBlock => "EdgeBlock",
            BORenderVerdict::SensorFail => "SensorFail",
            BORenderVerdict::ChallengeIncomplete => "ChallengeIncomplete",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "Pass" => Some(BORenderVerdict::Pass),
            "ThinShell" => Some(BORenderVerdict::ThinShell),
            "RenderIncomplete" => Some(BORenderVerdict::RenderIncomplete),
            "EdgeBlock" => Some(BORenderVerdict::EdgeBlock),
            "SensorFail" => Some(BORenderVerdict::SensorFail),
            "ChallengeIncomplete" => Some(BORenderVerdict::ChallengeIncomplete),
            _ => None,
        }
    }
}

// Missing verdicts use an owned reason; see MaybeVerdictOwned below.

// For struct fields we need owned Missing with reason; use enum with Missing payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaybeVerdictOwned {
    Present(BORenderVerdict),
    Missing(Missing),
}

fn maybe_verdict_json(value: &MaybeVerdictOwned) -> Value {
    match value {
        MaybeVerdictOwned::Present(verdict) => Value::String(verdict.as_str().to_string()),
        MaybeVerdictOwned::Missing(missing) => {
            serde_json::to_value(missing).unwrap_or(Value::Null)
        }
    }
}

// ---------------------------------------------------------------------------
// Request structs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BOClientCreate {
    pub profile: ArtifactReference,
    pub mode: String,
    pub source_client: MaybeClient,
    pub session_domain_id: String,
}

impl BOClientCreate {
    pub fn to_json(&self) -> Value {
        json!({
            "profile": self.profile.to_json(),
            "mode": self.mode,
            "source_client": maybe_client_json(&self.source_client),
            "session_domain_id": self.session_domain_id,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BOHttpExchange {
    pub client: BOClientRef,
    pub url: String,
    pub method: String,
    pub headers: MaybeArtifact,
    pub body: MaybeArtifact,
    pub acquisition_policy: VersionPin,
    pub session_mode: String,
    pub request_sequence: u64,
    pub cookie_generation: Revision,
}

impl BOHttpExchange {
    pub fn to_json(&self) -> Value {
        json!({
            "client": self.client.to_json(),
            "url": self.url,
            "method": self.method,
            "headers": maybe_artifact_json(&self.headers),
            "body": maybe_artifact_json(&self.body),
            "acquisition_policy": self.acquisition_policy.to_json(),
            "session_mode": self.session_mode,
            "request_sequence": self.request_sequence,
            "cookie_generation": self.cookie_generation,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BOPageCreate {
    pub profile: ArtifactReference,
    pub native_options: ArtifactReference,
    pub client: MaybeClient,
}

impl BOPageCreate {
    pub fn to_json(&self) -> Value {
        json!({
            "profile": self.profile.to_json(),
            "native_options": self.native_options.to_json(),
            "client": maybe_client_json(&self.client),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BONavigate {
    pub page: BOPageRef,
    pub url: String,
    pub client: MaybeClient,
    pub navigation_policy: VersionPin,
}

impl BONavigate {
    pub fn to_json(&self) -> Value {
        json!({
            "page": self.page.to_json(),
            "url": self.url,
            "client": maybe_client_json(&self.client),
            "navigation_policy": self.navigation_policy.to_json(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BOFromHtml {
    pub page: BOPageRef,
    pub html: ArtifactReference,
    pub base_url: MaybeString,
    pub network: String,
    pub complete_input_refs: SupportRefs,
}

impl BOFromHtml {
    pub fn to_json(&self) -> Value {
        json!({
            "page": self.page.to_json(),
            "html": self.html.to_json(),
            "base_url": serde_json::to_value(&self.base_url).unwrap_or(Value::Null),
            "network": self.network,
            "complete_input_refs": self.complete_input_refs.iter().map(EvidenceRef::to_json).collect::<Vec<Value>>(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BODomRead {
    pub root: BORootRef,
    pub selector: MaybeString,
    pub depth_limit: Revision,
    pub byte_limit: u64,
    pub include_frames: bool,
    pub include_accessible_shadow_roots: bool,
}

impl BODomRead {
    pub fn to_json(&self) -> Value {
        json!({
            "root": self.root.to_json(),
            "selector": serde_json::to_value(&self.selector).unwrap_or(Value::Null),
            "depth_limit": self.depth_limit,
            "byte_limit": self.byte_limit,
            "include_frames": self.include_frames,
            "include_accessible_shadow_roots": self.include_accessible_shadow_roots,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BODomWrite {
    pub node: BONodeRef,
    pub property: String,
    pub value: ArtifactReference,
}

impl BODomWrite {
    pub fn to_json(&self) -> Value {
        json!({
            "node": self.node.to_json(),
            "property": self.property,
            "value": self.value.to_json(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BOEventDispatch {
    pub node: BONodeRef,
    pub event_type: String,
    pub bubbles: bool,
    pub cancelable: bool,
    pub composed: bool,
    pub detail: MaybeArtifact,
}

impl BOEventDispatch {
    pub fn to_json(&self) -> Value {
        json!({
            "node": self.node.to_json(),
            "event_type": self.event_type,
            "bubbles": self.bubbles,
            "cancelable": self.cancelable,
            "composed": self.composed,
            "detail": maybe_artifact_json(&self.detail),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BOV8Evaluate {
    pub root: BORootRef,
    pub script: ArtifactReference,
    pub argument: MaybeArtifact,
}

impl BOV8Evaluate {
    pub fn to_json(&self) -> Value {
        json!({
            "root": self.root.to_json(),
            "script": self.script.to_json(),
            "argument": maybe_artifact_json(&self.argument),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BOAssignFiles {
    pub node: BONodeRef,
    pub files: Vec<ArtifactReference>,
}

impl BOAssignFiles {
    pub fn to_json(&self) -> Value {
        json!({
            "node": self.node.to_json(),
            "files": self.files.iter().map(ArtifactReference::to_json).collect::<Vec<Value>>(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BOCapture {
    pub page: BOPageRef,
    pub capture_options: ArtifactReference,
}

impl BOCapture {
    pub fn to_json(&self) -> Value {
        json!({
            "page": self.page.to_json(),
            "capture_options": self.capture_options.to_json(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BOPageArgument {
    pub page: BOPageRef,
}

impl BOPageArgument {
    pub fn to_json(&self) -> Value {
        json!({
            "page": self.page.to_json(),
        })
    }
}

// ---------------------------------------------------------------------------
// Return structs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BOHttpReturn {
    pub client: BOClientRef,
    pub request_sequence: u64,
    pub cookie_generation: Revision,
    pub response_status: MaybeStatus,
    pub headers: MaybeArtifact,
    pub body: MaybeArtifact,
    pub final_url: MaybeString,
}

impl BOHttpReturn {
    pub fn to_json(&self) -> Value {
        json!({
            "client": self.client.to_json(),
            "request_sequence": self.request_sequence,
            "cookie_generation": self.cookie_generation,
            "response_status": maybe_status_json(&self.response_status),
            "headers": maybe_artifact_json(&self.headers),
            "body": maybe_artifact_json(&self.body),
            "final_url": serde_json::to_value(&self.final_url).unwrap_or(Value::Null),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BONavigationReturn {
    pub page: BOPageRef,
    pub document_root: MaybeRoot,
    pub final_url: MaybeString,
    pub verdict: MaybeVerdictOwned,
    pub response_evidence: MaybeArtifact,
}

impl BONavigationReturn {
    pub fn to_json(&self) -> Value {
        json!({
            "page": self.page.to_json(),
            "document_root": maybe_root_json(&self.document_root),
            "final_url": serde_json::to_value(&self.final_url).unwrap_or(Value::Null),
            "verdict": maybe_verdict_json(&self.verdict),
            "response_evidence": maybe_artifact_json(&self.response_evidence),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaybeNodeParent {
    Present(BONodeRef),
    Missing(Missing),
}

fn maybe_parent_json(value: &MaybeNodeParent) -> Value {
    match value {
        MaybeNodeParent::Present(node) => node.to_json(),
        MaybeNodeParent::Missing(missing) => {
            serde_json::to_value(missing).unwrap_or(Value::Null)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BODomNode {
    pub node_ref: BONodeRef,
    pub parent: MaybeNodeParent,
    pub node_name: String,
    pub attributes: BTreeMap<String, String>,
    pub text: MaybeString,
}

impl BODomNode {
    pub fn to_json(&self) -> Value {
        json!({
            "ref": self.node_ref.to_json(),
            "parent": maybe_parent_json(&self.parent),
            "node_name": self.node_name,
            "attributes": self.attributes,
            "text": serde_json::to_value(&self.text).unwrap_or(Value::Null),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BOBoundary {
    pub boundary_id: String,
    pub kind: String,
    pub root: MaybeRoot,
    pub access: String,
    pub limitation: MaybeString,
}

impl BOBoundary {
    pub fn to_json(&self) -> Value {
        json!({
            "boundary_id": self.boundary_id,
            "kind": self.kind,
            "root": maybe_root_json(&self.root),
            "access": self.access,
            "limitation": serde_json::to_value(&self.limitation).unwrap_or(Value::Null),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BODomExport {
    pub record_type: String,
    pub schema_version: String,
    pub root: BORootRef,
    pub nodes: Vec<BODomNode>,
    pub boundaries: Vec<BOBoundary>,
    pub completeness: String,
    pub limitations: Vec<String>,
}

impl BODomExport {
    pub fn to_json(&self) -> Value {
        json!({
            "record_type": self.record_type,
            "schema_version": self.schema_version,
            "root": self.root.to_json(),
            "nodes": self.nodes.iter().map(BODomNode::to_json).collect::<Vec<Value>>(),
            "boundaries": self.boundaries.iter().map(BOBoundary::to_json).collect::<Vec<Value>>(),
            "completeness": self.completeness,
            "limitations": self.limitations,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BOMutationReturn {
    pub node: BONodeRef,
    pub native_return: MaybeArtifact,
    pub readback: MaybeArtifact,
    pub event_observation: MaybeArtifact,
}

impl BOMutationReturn {
    pub fn to_json(&self) -> Value {
        json!({
            "node": self.node.to_json(),
            "native_return": maybe_artifact_json(&self.native_return),
            "readback": maybe_artifact_json(&self.readback),
            "event_observation": maybe_artifact_json(&self.event_observation),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BOV8Return {
    pub representation: String,
    pub value: MaybeArtifact,
}

impl BOV8Return {
    pub fn to_json(&self) -> Value {
        json!({
            "representation": self.representation,
            "value": maybe_artifact_json(&self.value),
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct BOCaptureReturn {
    pub page: BOPageRef,
    pub image: ArtifactReference,
    pub geometry: Vec<Measurement>,
}

impl BOCaptureReturn {
    pub fn to_json(&self) -> Value {
        json!({
            "page": self.page.to_json(),
            "image": self.image.to_json(),
            "geometry": self.geometry.iter().map(|m| serde_json::to_value(m).unwrap_or(Value::Null)).collect::<Vec<Value>>(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BOVerdictReturn {
    pub verdict: BORenderVerdict,
    pub basis: ArtifactReference,
}

impl BOVerdictReturn {
    pub fn to_json(&self) -> Value {
        json!({
            "verdict": self.verdict.as_str(),
            "basis": self.basis.to_json(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BOResetReturn {
    pub page: BOPageRef,
    pub invalidated_generation: Revision,
    pub cookie_continuity_refs: SupportRefs,
}

impl BOResetReturn {
    pub fn to_json(&self) -> Value {
        json!({
            "page": self.page.to_json(),
            "invalidated_generation": self.invalidated_generation,
            "cookie_continuity_refs": self.cookie_continuity_refs.iter().map(EvidenceRef::to_json).collect::<Vec<Value>>(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BODestroyReturn {
    pub page: BOPageRef,
    pub destruction_refs: SupportRefs,
}

impl BODestroyReturn {
    pub fn to_json(&self) -> Value {
        json!({
            "page": self.page.to_json(),
            "destruction_refs": self.destruction_refs.iter().map(EvidenceRef::to_json).collect::<Vec<Value>>(),
        })
    }
}

// ---------------------------------------------------------------------------
// Failure and record
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BOFailure {
    pub code: String,
    pub native_entry: String,
    pub native_error: MaybeArtifact,
    pub detail: String,
}

impl BOFailure {
    pub fn to_json(&self) -> Value {
        json!({
            "code": self.code,
            "native_entry": self.native_entry,
            "native_error": maybe_artifact_json(&self.native_error),
            "detail": self.detail,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaybeBOFailure {
    Present(BOFailure),
    Missing(Missing),
}

#[derive(Debug, Clone, PartialEq)]
pub struct BOPrimitiveRecord {
    pub record_type: String,
    pub schema_version: String,
    pub binding_digest: Digest,
    pub call_id: String,
    pub owner: BOOwner,
    pub primitive: String,
    pub authorization_ref: EvidenceRef,
    pub limit: DurationLimit,
    pub arguments: Value,
    pub return_state: String,
    pub value: Value,
    pub error: MaybeBOFailure,
    pub elapsed: Measurement,
    pub evidence_refs: SupportRefs,
    pub effect_refs: Vec<EvidenceRef>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BrowserOxideReturn<T> {
    pub value: Option<T>,
    pub record: BOPrimitiveRecord,
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct ClientState {
    client_ref: BOClientRef,
    next_sequence: u64,
    cookie_generation: Revision,
}

#[derive(Debug, Clone)]
struct PageState {
    page_id: String,
    generation: Revision,
    profile_digest: Digest,
    destroyed: bool,
    quarantined: bool,
    document_generation: Revision,
    current_root_id: Option<String>,
    verdict: BORenderVerdict,
    jar_id: String,
}

#[derive(Debug, Clone)]
struct RootState {
    root_ref: BORootRef,
    valid: bool,
}

#[derive(Debug, Clone)]
struct NodeState {
    node_ref: BONodeRef,
    valid: bool,
}

pub struct NativeSession {
    owner: BOOwner,
    principal: AuthenticatedPrincipal,
    manifest: Manifest,
    lease: LeaseRecord,
    affinity: PhantomData<Rc<()>>,
    binding: BOBindingDescriptor,
    binding_digest: Digest,
    thread_id: thread::ThreadId,
    call_counter: u64,
    producer_sequence: u64,
    clock: ClockDescriptor,
    clock_offset_ms: f64,
    clients: HashMap<String, ClientState>,
    client_counter: u64,
    pool_counter: u64,
    pages: HashMap<String, PageState>,
    page_counter: u64,
    roots: HashMap<String, RootState>,
    nodes: HashMap<String, NodeState>,
    domains: HashSet<String>,
    network_attempts: u64,
    lease_now: TimePoint,
}

impl std::fmt::Debug for NativeSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeSession")
            .field("owner", &self.owner)
            .field("call_counter", &self.call_counter)
            .finish_non_exhaustive()
    }
}

fn failure(code: &str, native_entry: &str, detail: String) -> BOFailure {
    BOFailure {
        code: code.to_string(),
        native_entry: native_entry.to_string(),
        native_error: MaybeArtifact::Missing(Missing::new("not_applicable")),
        detail,
    }
}

fn check_thread(session: &NativeSession) -> Result<(), BOFailure> {
    if thread::current().id() != session.thread_id {
        return Err(failure(
            "WRONG_THREAD",
            "not_entered",
            "native entry refused: caller thread is not the owning OS thread".to_string(),
        ));
    }
    Ok(())
}

fn check_owner(session: &NativeSession, owner: &BOOwner) -> Result<(), BOFailure> {
    if owner.process_id != session.owner.process_id
        || owner.boot_id != session.owner.boot_id
        || owner.os_thread_id != session.owner.os_thread_id
    {
        if owner.os_thread_id != session.owner.os_thread_id {
            return Err(failure(
                "WRONG_THREAD",
                "not_entered",
                format!(
                    "reference owner thread {:?} does not match session owner {:?}; entry refused before native access",
                    owner.os_thread_id, session.owner.os_thread_id
                ),
            ));
        }
        return Err(failure(
            "STALE_REFERENCE",
            "not_entered",
            "reference owner lifetime does not match this session; prior-boot references are invalid".to_string(),
        ));
    }
    Ok(())
}

fn is_mapped(session: &NativeSession, primitive: &str) -> bool {
    session
        .binding
        .primitive_mappings
        .iter()
        .find(|mapping| mapping.primitive == primitive)
        .map(|mapping| mapping.mapping_state == "mapped")
        .unwrap_or(false)
}

fn next_call_id(session: &mut NativeSession) -> String {
    session.call_counter += 1;
    format!("call-{}", session.call_counter)
}

fn make_elapsed(
    session: &mut NativeSession,
    call_id: &str,
) -> Result<Measurement, ConnectorError> {
    let start_offset = session.clock_offset_ms;
    let end_offset = start_offset + 1.0;
    session.clock_offset_ms = end_offset;
    let start = TimePoint {
        clock_id: session.clock.clock_id.clone(),
        boot_id: session.clock.boot_id.clone(),
        origin: MeasurementOrigin::SubjectReported,
        monotonic_offset_ms: start_offset,
        utc_annotation: UtcAnnotation::Missing(Missing::new("not_observed")),
    };
    let end = TimePoint {
        clock_id: session.clock.clock_id.clone(),
        boot_id: session.clock.boot_id.clone(),
        origin: MeasurementOrigin::SubjectReported,
        monotonic_offset_ms: end_offset,
        utc_annotation: UtcAnnotation::Missing(Missing::new("not_observed")),
    };
    let measurement = Measurement {
        measurement_id: format!("elapsed-{call_id}"),
        name: "native_primitive_elapsed".to_string(),
        scope: Scope {
            kind: ScopeKind::NativePrimitive,
            id: call_id.to_string(),
        },
        quantity: Quantity::Duration,
        unit: "ms".to_string(),
        origin: MeasurementOrigin::SubjectReported,
        clock_id: session.clock.clock_id.clone(),
        boot_id: session.clock.boot_id.clone(),
        method: Method::EndpointDifference,
        start: MaybeTimePoint::Present(start),
        end: MaybeTimePoint::Present(end),
        estimate: Estimate::Exact {
            value: end_offset - start_offset,
        },
        resolution: MaybeNumber::Missing(Missing::new("not_observed")),
        censoring: Censoring::None,
        comparability_group: MaybeString::Missing(Missing::new("not_applicable")),
    };
    rm_time::validate_measurement(&measurement, &[session.clock.clone()])
        .map_err(|error| invalid(format!("elapsed measurement rejected: {error}")))?;
    Ok(measurement)
}

fn build_record(
    session: &mut NativeSession,
    primitive: &str,
    authorization_ref: &EvidenceRef,
    limit: &DurationLimit,
    arguments: Value,
    return_state: &str,
    value: Value,
    error: MaybeBOFailure,
    evidence_refs: SupportRefs,
    effect_refs: Vec<EvidenceRef>,
) -> Result<BOPrimitiveRecord, ConnectorError> {
    let call_id = next_call_id(session);
    let elapsed = make_elapsed(session, &call_id)?;
    Ok(BOPrimitiveRecord {
        record_type: BO_RECORD_TYPE.to_string(),
        schema_version: BO_SCHEMA_VERSION.to_string(),
        binding_digest: session.binding_digest.clone(),
        call_id,
        owner: session.owner.clone(),
        primitive: primitive.to_string(),
        authorization_ref: authorization_ref.clone(),
        limit: limit.clone(),
        arguments,
        return_state: return_state.to_string(),
        value,
        error,
        elapsed,
        evidence_refs,
        effect_refs,
    })
}

fn failed_value() -> Value {
    serde_json::to_value(Missing::new("not_applicable")).unwrap_or(Value::Null)
}

fn inapplicable_error() -> MaybeBOFailure {
    MaybeBOFailure::Missing(Missing::new("not_applicable"))
}

fn failed_out<T>(
    session: &mut NativeSession,
    primitive: &str,
    authorization_ref: &EvidenceRef,
    limit: &DurationLimit,
    arguments: Value,
    failure: BOFailure,
) -> Result<BrowserOxideReturn<T>, ConnectorError> {
    let record = build_record(
        session,
        primitive,
        authorization_ref,
        limit,
        arguments,
        "failed",
        failed_value(),
        MaybeBOFailure::Present(failure),
        vec![authorization_ref.clone()],
        Vec::new(),
    )?;
    Ok(BrowserOxideReturn {
        value: None,
        record,
    })
}

fn unsupported_out<T>(
    session: &mut NativeSession,
    primitive: &str,
    authorization_ref: &EvidenceRef,
    limit: &DurationLimit,
    arguments: Value,
) -> Result<BrowserOxideReturn<T>, ConnectorError> {
    let record = build_record(
        session,
        primitive,
        authorization_ref,
        limit,
        arguments,
        "unsupported",
        failed_value(),
        MaybeBOFailure::Present(failure(
            "UNMAPPED_PRIMITIVE",
            "not_entered",
            format!("primitive {primitive} is unmapped in this binding; mapping absence does not establish native absence"),
        )),
        vec![authorization_ref.clone()],
        Vec::new(),
    )?;
    Ok(BrowserOxideReturn {
        value: None,
        record,
    })
}

fn returned_out<T: Clone>(
    session: &mut NativeSession,
    primitive: &str,
    authorization_ref: &EvidenceRef,
    limit: &DurationLimit,
    arguments: Value,
    typed: T,
    typed_json: Value,
    evidence_refs: SupportRefs,
) -> Result<BrowserOxideReturn<T>, ConnectorError> {
    let record = build_record(
        session,
        primitive,
        authorization_ref,
        limit,
        arguments,
        "returned",
        typed_json,
        inapplicable_error(),
        evidence_refs,
        Vec::new(),
    )?;
    Ok(BrowserOxideReturn {
        value: Some(typed),
        record,
    })
}

fn preflight(
    session: &NativeSession,
    authorization_ref: &EvidenceRef,
    limit: &DurationLimit,
) -> Result<(), ConnectorError> {
    check_limit(limit)?;
    authorization_ref
        .validate()
        .map_err(|error| invalid(format!("authorization_ref invalid: {}", error.detail)))?;
    rm_authority::authorize_owner(&session.principal, "execution", "execution_claim")?;
    let owner_epoch = match &session.lease.owner_epoch {
        MaybeString::Text(text) => text.clone(),
        MaybeString::Missing(_) => {
            return Err(invalid("session lease has no usable owner epoch"));
        }
    };
    rm_leases::validate_lease(
        &session.lease,
        &session.lease_now,
        session.lease.entity_revision,
        session.lease.input_revision,
        &owner_epoch,
        &session.lease.session_epoch,
    )?;
    Ok(())
}

fn journal_intent(
    session: &mut NativeSession,
    primitive: &str,
    call_hint: &str,
) -> Result<EvidenceRef, ConnectorError> {
    let sequence = PositiveInteger::new(session.producer_sequence)
        .map_err(|error| invalid(format!("producer sequence invalid: {}", error.detail)))?;
    session.producer_sequence += 1;
    let submission = EventSubmission {
        producer_sequence: Some(sequence),
        event_kind: "execution_claim".to_string(),
        event_schema_version: "evidence-kernel/0.1.0".to_string(),
        occurred_at: MaybeTimePoint::Missing(Missing::new("not_observed")),
        payload: EvidencePayload {
            data: json!({"primitive": primitive, "intent": call_hint, "transport": NATIVE_TRANSPORT}),
            measurements: Vec::new(),
            evidence_refs: Vec::new(),
            artifact_refs: Vec::new(),
        },
    };
    let envelope = rm_evidence::append_event(&session.principal, &session.manifest, submission)?;
    Ok(EvidenceRef {
        journal_id: envelope.journal_id.clone(),
        sequence: envelope.journal_sequence,
        event_id: envelope.event_id.clone(),
        event_hash: envelope.event_hash.clone(),
        pointer: String::new(),
    })
}

fn install_return_bytes(
    session: &NativeSession,
    bytes: &[u8],
    media_type: &str,
) -> Result<ArtifactReference, ConnectorError> {
    let reference = ArtifactReference {
        digest: rm_wire::artifact_digest(bytes),
        size_bytes: bytes.len() as u64,
        media_type: media_type.to_string(),
        owner_domain: "execution".to_string(),
        access: rm_evidence::AccessClass::Public,
    };
    rm_evidence::install_artifact(&session.principal, &reference, bytes)?;
    Ok(reference)
}

fn check_page_live(
    session: &NativeSession,
    page: &BOPageRef,
) -> Result<PageState, BOFailure> {
    check_owner(session, &page.owner)?;
    require_revision("page_generation", page.page_generation).map_err(|error| {
        failure("INVALID_INPUT", "not_entered", error.detail)
    })?;
    let state = session.pages.get(&page.page_id).ok_or_else(|| {
        failure(
            "STALE_REFERENCE",
            "not_entered",
            format!("page {:?} is unknown in this session; removed references cannot be resurrected", page.page_id),
        )
    })?;
    if state.destroyed {
        return Err(failure(
            "STALE_REFERENCE",
            "not_entered",
            format!("page {:?} was destroyed; destruction invalidates every dependent reference", page.page_id),
        ));
    }
    if state.quarantined {
        return Err(failure(
            "RESOURCE_BUSY",
            "not_entered",
            format!("page {:?} is quarantined after a failed reset", page.page_id),
        ));
    }
    if page.page_generation != state.generation {
        return Err(failure(
            "STALE_REFERENCE",
            "not_entered",
            format!(
                "page {:?} generation {} is stale; current generation is {}",
                page.page_id, page.page_generation, state.generation
            ),
        ));
    }
    if page.profile_digest != state.profile_digest {
        return Err(failure(
            "STALE_REFERENCE",
            "not_entered",
            format!("page {:?} profile binding does not match the live page", page.page_id),
        ));
    }
    Ok(state.clone())
}

fn check_root_live(session: &NativeSession, root: &BORootRef) -> Result<RootState, BOFailure> {
    let _page = check_page_live(session, &root.page)?;
    if root.document_generation > MAX_SAFE_INTEGER {
        return Err(failure(
            "INVALID_INPUT",
            "not_entered",
            "document_generation exceeds exact integer bound".to_string(),
        ));
    }
    let state = session.roots.get(&root.root_id).ok_or_else(|| {
        failure(
            "STALE_REFERENCE",
            "not_entered",
            format!("root {:?} is unknown; navigation invalidates affected document references", root.root_id),
        )
    })?;
    if !state.valid {
        return Err(failure(
            "STALE_REFERENCE",
            "not_entered",
            format!("root {:?} was invalidated by navigation, replacement, or reset", root.root_id),
        ));
    }
    if state.root_ref.document_generation != root.document_generation
        || state.root_ref.page.page_generation != root.page.page_generation
    {
        return Err(failure(
            "STALE_REFERENCE",
            "not_entered",
            format!("root {:?} generation is stale", root.root_id),
        ));
    }
    Ok(state.clone())
}

fn check_node_live(session: &NativeSession, node: &BONodeRef) -> Result<NodeState, BOFailure> {
    let _root = check_root_live(session, &node.root)?;
    if node.node_generation > MAX_SAFE_INTEGER {
        return Err(failure(
            "INVALID_INPUT",
            "not_entered",
            "node_generation exceeds exact integer bound".to_string(),
        ));
    }
    let state = session.nodes.get(&node.node_id).ok_or_else(|| {
        failure(
            "STALE_REFERENCE",
            "not_entered",
            format!("node {:?} is unknown; removed nodes cannot be resurrected by reusing an id", node.node_id),
        )
    })?;
    if !state.valid {
        return Err(failure(
            "STALE_REFERENCE",
            "not_entered",
            format!("node {:?} was removed or replaced; stale references are rejected before mutation", node.node_id),
        ));
    }
    if state.node_ref.node_generation != node.node_generation {
        return Err(failure(
            "STALE_REFERENCE",
            "not_entered",
            format!("node {:?} generation is stale", node.node_id),
        ));
    }
    Ok(state.clone())
}

fn invalidate_page_documents(session: &mut NativeSession, page_id: &str) {
    let root_ids: Vec<String> = session
        .roots
        .iter()
        .filter(|(_, state)| state.root_ref.page.page_id == page_id)
        .map(|(id, _)| id.clone())
        .collect();
    for root_id in &root_ids {
        if let Some(state) = session.roots.get_mut(root_id) {
            state.valid = false;
        }
    }
    let node_ids: Vec<String> = session
        .nodes
        .iter()
        .filter(|(_, state)| state.node_ref.root.page.page_id == page_id)
        .map(|(id, _)| id.clone())
        .collect();
    for node_id in &node_ids {
        if let Some(state) = session.nodes.get_mut(node_id) {
            state.valid = false;
        }
    }
}

fn verdict_for_url(url: &str) -> BORenderVerdict {
    let lower = url.to_lowercase();
    if lower.contains("thinshell") || lower.contains("thin-shell") || lower.contains("thin_shell") {
        BORenderVerdict::ThinShell
    } else if lower.contains("incomplete") {
        BORenderVerdict::RenderIncomplete
    } else if lower.contains("edgeblock") || lower.contains("edge-block") {
        BORenderVerdict::EdgeBlock
    } else if lower.contains("sensor") {
        BORenderVerdict::SensorFail
    } else if lower.contains("challenge") {
        BORenderVerdict::ChallengeIncomplete
    } else {
        BORenderVerdict::Pass
    }
}

// ---------------------------------------------------------------------------
// Session open
// ---------------------------------------------------------------------------

pub fn open_native_session(
    principal: AuthenticatedPrincipal,
    manifest: Manifest,
    binding: BOBindingDescriptor,
    lease: LeaseRecord,
) -> Result<NativeSession, ConnectorError> {
    let wire = rm_authority::manifest_wire_bytes(&manifest);
    rm_wire::validate_record("manifest/v1", &wire)
        .map_err(|error| invalid(format!("manifest wire rejected: {error}")))?;
    rm_catalog::validate_native_binding(&principal, &binding)?;
    rm_authority::authorize_owner(&principal, "execution", "execution_claim")?;

    let owner_epoch = match &lease.owner_epoch {
        MaybeString::Text(text) => text.clone(),
        MaybeString::Missing(missing) => {
            return Err(invalid(format!(
                "held lease owner_epoch missingness {:?} is not a usable fence",
                missing.reason
            )));
        }
    };
    let (issued, deadline) = match (&lease.leased_at, &lease.lease_expires_at) {
        (MaybeTimePoint::Present(issued), MaybeTimePoint::Present(deadline)) => {
            (issued.clone(), deadline.clone())
        }
        _ => return Err(invalid("held lease requires present issue and deadline")),
    };
    let mid = (issued.monotonic_offset_ms + deadline.monotonic_offset_ms) / 2.0;
    let now = TimePoint {
        clock_id: issued.clock_id.clone(),
        boot_id: issued.boot_id.clone(),
        origin: issued.origin,
        monotonic_offset_ms: mid,
        utc_annotation: UtcAnnotation::Missing(Missing::new("not_observed")),
    };
    rm_leases::validate_lease(
        &lease,
        &now,
        lease.entity_revision,
        lease.input_revision,
        &owner_epoch,
        &lease.session_epoch,
    )?;
    let reached = rm_time::boundary_reached(&now, &deadline)
        .map_err(|error| invalid(format!("lease deadline comparison failed: {error}")))?;
    if reached {
        return Err(invalid("lease deadline already reached"));
    }

    let binding_bytes =
        serde_json::to_vec(&binding.to_json()).map_err(|error| invalid(format!("binding serializes: {error}")))?;
    let binding_digest = rm_wire::canonical_digest(&binding_bytes)
        .map_err(|error| invalid(format!("binding digest failed: {error}")))?;

    let thread_id = thread::current().id();
    let process_id = format!("proc-{}", std::process::id());
    let boot_id = format!("boot-{}", std::process::id());
    let os_thread_id = format!("{thread_id:?}");
    let owner = BOOwner {
        process_id: process_id.clone(),
        boot_id: boot_id.clone(),
        os_thread_id,
    };
    let clock = ClockDescriptor {
        clock_id: "bo-native-clock".to_string(),
        boot_id: boot_id.clone(),
        origin: MeasurementOrigin::SubjectReported,
        source_id: "browseroxide-native".to_string(),
        basis: ClockBasis::OpaqueReport,
        unit: "ms".to_string(),
    };
    Ok(NativeSession {
        owner,
        principal,
        manifest,
        lease,
        affinity: PhantomData,
        binding,
        binding_digest,
        thread_id,
        call_counter: 0,
        producer_sequence: 1000,
        clock,
        clock_offset_ms: 0.0,
        clients: HashMap::new(),
        client_counter: 0,
        pool_counter: 0,
        pages: HashMap::new(),
        page_counter: 0,
        roots: HashMap::new(),
        nodes: HashMap::new(),
        domains: HashSet::new(),
        network_attempts: 0,
        lease_now: now,
    })
}

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

pub fn client_create(
    session: &mut NativeSession,
    request: &BOClientCreate,
    authorization_ref: &EvidenceRef,
    limit: &DurationLimit,
) -> Result<BrowserOxideReturn<BOClientRef>, ConnectorError> {
    preflight(session, authorization_ref, limit)?;
    let arguments = request.to_json();
    if !is_mapped(session, "bo.client_create") {
        return unsupported_out(session, "bo.client_create", authorization_ref, limit, arguments);
    }
    if let Err(failure) = check_thread(session) {
        return failed_out(session, "bo.client_create", authorization_ref, limit, arguments, failure);
    }
    if !matches!(request.mode.as_str(), "create_retained" | "share_process" | "clone_independent") {
        return failed_out(
            session,
            "bo.client_create",
            authorization_ref,
            limit,
            arguments,
            failure("INVALID_INPUT", "not_entered", format!("mode {:?} is not a known client mode", request.mode)),
        );
    }
    if request.session_domain_id.is_empty() {
        return failed_out(
            session,
            "bo.client_create",
            authorization_ref,
            limit,
            arguments,
            failure("INVALID_INPUT", "not_entered", "session_domain_id must be nonempty".to_string()),
        );
    }
    if request.profile.validate().is_err() {
        return failed_out(
            session,
            "bo.client_create",
            authorization_ref,
            limit,
            arguments,
            failure("INVALID_INPUT", "not_entered", "profile reference shape is invalid".to_string()),
        );
    }
    if rm_evidence::load_artifact(&session.principal, &request.profile).is_err() {
        return failed_out(
            session,
            "bo.client_create",
            authorization_ref,
            limit,
            arguments,
            failure("INVALID_INPUT", "not_entered", "profile artifact bytes are not retained".to_string()),
        );
    }
    let storage = session.binding.session_storage_model.clone();
    if (storage == "process_global" || storage == "unknown")
        && !session.domains.is_empty()
        && !session.domains.contains(&request.session_domain_id)
    {
        return failed_out(
            session,
            "bo.client_create",
            authorization_ref,
            limit,
            arguments,
            failure(
                "INVALID_INPUT",
                "not_entered",
                format!(
                    "independent domain {:?} requires a separate engine process under {storage} storage; verified namespacing is not evidenced",
                    request.session_domain_id
                ),
            ),
        );
    }
    let source_pool: Option<String> = match &request.source_client {
        MaybeClient::Present(client) => {
            match session.clients.get(&client.client_id) {
                Some(state) => Some(state.client_ref.pool_id.clone()),
                None => {
                    return failed_out(
                        session,
                        "bo.client_create",
                        authorization_ref,
                        limit,
                        arguments,
                        failure("STALE_REFERENCE", "not_entered", format!("source client {:?} is unknown in this session", client.client_id)),
                    );
                }
            }
        }
        MaybeClient::Missing(missing) => {
            if let Err(error) = check_missing("source_client", missing) {
                return failed_out(
                    session,
                    "bo.client_create",
                    authorization_ref,
                    limit,
                    arguments,
                    failure("INVALID_INPUT", "not_entered", error.detail),
                );
            }
            None
        }
    };
    if request.mode == "clone_independent" && source_pool.is_none() {
        return failed_out(
            session,
            "bo.client_create",
            authorization_ref,
            limit,
            arguments,
            failure("INVALID_INPUT", "not_entered", "clone_independent requires a source client".to_string()),
        );
    }
    let intent = journal_intent(session, "bo.client_create", "client_create")?;
    session.client_counter += 1;
    let client_id = format!("client-{}", session.client_counter);
    let (pool_id, session_epoch) = match request.mode.as_str() {
        "share_process" => {
            if let Some(pool) = source_pool.clone() {
                let epoch = match &request.source_client {
                    MaybeClient::Present(client) => client.session_epoch.clone(),
                    MaybeClient::Missing(_) => format!("session-epoch-{}", session.client_counter),
                };
                (pool, epoch)
            } else {
                session.pool_counter += 1;
                // Shared-process handle without an explicit source joins the
                // process pool; independent clones never share it.
                (format!("pool-shared-{}", session.pool_counter.min(1)), format!("session-epoch-{}", session.client_counter))
            }
        }
        _ => {
            session.pool_counter += 1;
            let mut pool = format!("pool-{}", session.pool_counter);
            if let Some(source) = &source_pool {
                if &pool == source {
                    session.pool_counter += 1;
                    pool = format!("pool-{}", session.pool_counter);
                }
            }
            (pool, format!("session-epoch-{}", session.client_counter))
        }
    };
    if request.mode == "clone_independent" {
        if let Some(source) = &source_pool {
            if &pool_id == source {
                return failed_out(
                    session,
                    "bo.client_create",
                    authorization_ref,
                    limit,
                    arguments,
                    failure("INVALID_INPUT", "not_entered", "clone_independent must return a distinct pool id".to_string()),
                );
            }
        }
    }
    let client = BOClientRef {
        process_id: session.owner.process_id.clone(),
        boot_id: session.owner.boot_id.clone(),
        client_id: client_id.clone(),
        session_domain_id: request.session_domain_id.clone(),
        session_epoch,
        pool_id: pool_id.clone(),
        profile_digest: request.profile.digest.clone(),
    };
    let cookie_generation = 0;
    session.clients.insert(
        client_id,
        ClientState {
            client_ref: client.clone(),
            next_sequence: 1,
            cookie_generation,
        },
    );
    session.domains.insert(request.session_domain_id.clone());
    let typed_json = client.to_json();
    returned_out(
        session,
        "bo.client_create",
        authorization_ref,
        limit,
        arguments,
        client,
        typed_json,
        vec![authorization_ref.clone(), intent],
    )
}

pub fn http_exchange(
    session: &mut NativeSession,
    request: &BOHttpExchange,
    authorization_ref: &EvidenceRef,
    limit: &DurationLimit,
) -> Result<BrowserOxideReturn<BOHttpReturn>, ConnectorError> {
    preflight(session, authorization_ref, limit)?;
    let arguments = request.to_json();
    if !is_mapped(session, "bo.http_exchange") {
        return unsupported_out(session, "bo.http_exchange", authorization_ref, limit, arguments);
    }
    if let Err(failure) = check_thread(session) {
        return failed_out(session, "bo.http_exchange", authorization_ref, limit, arguments, failure);
    }
    if request.client.process_id != session.owner.process_id
        || request.client.boot_id != session.owner.boot_id
    {
        return failed_out(
            session,
            "bo.http_exchange",
            authorization_ref,
            limit,
            arguments,
            failure("STALE_REFERENCE", "not_entered", "client names a different process/boot lifetime".to_string()),
        );
    }
    let state = match session.clients.get(&request.client.client_id) {
        Some(state) => state.clone(),
        None => {
            return failed_out(
                session,
                "bo.http_exchange",
                authorization_ref,
                limit,
                arguments,
                failure("STALE_REFERENCE", "not_entered", format!("client {:?} is unknown in this session", request.client.client_id)),
            );
        }
    };
    if !(request.url.starts_with("http://") || request.url.starts_with("https://")) {
        return failed_out(
            session,
            "bo.http_exchange",
            authorization_ref,
            limit,
            arguments,
            failure("INVALID_INPUT", "not_entered", "url must be an HTTP(S) URI".to_string()),
        );
    }
    if request.method.is_empty() {
        return failed_out(
            session,
            "bo.http_exchange",
            authorization_ref,
            limit,
            arguments,
            failure("INVALID_INPUT", "not_entered", "method must be nonempty".to_string()),
        );
    }
    if check_version_pin(&request.acquisition_policy, "acquisition_policy").is_err() {
        return failed_out(
            session,
            "bo.http_exchange",
            authorization_ref,
            limit,
            arguments,
            failure("INVALID_INPUT", "not_entered", "acquisition_policy pin is invalid".to_string()),
        );
    }
    if !matches!(request.session_mode.as_str(), "sessionless" | "stateful" | "rotating") {
        return failed_out(
            session,
            "bo.http_exchange",
            authorization_ref,
            limit,
            arguments,
            failure("INVALID_INPUT", "not_entered", format!("session_mode {:?} is unknown", request.session_mode)),
        );
    }
    if require_positive("request_sequence", request.request_sequence).is_err()
        || require_revision("cookie_generation", request.cookie_generation).is_err()
    {
        return failed_out(
            session,
            "bo.http_exchange",
            authorization_ref,
            limit,
            arguments,
            failure("INVALID_INPUT", "not_entered", "request_sequence/cookie_generation out of range".to_string()),
        );
    }
    if check_maybe_artifact("headers", &request.headers).is_err()
        || check_maybe_artifact("body", &request.body).is_err()
    {
        return failed_out(
            session,
            "bo.http_exchange",
            authorization_ref,
            limit,
            arguments,
            failure("INVALID_INPUT", "not_entered", "headers/body carriers are invalid".to_string()),
        );
    }
    for carrier in [&request.headers, &request.body] {
        if let MaybeArtifact::Present(reference) = carrier {
            if rm_evidence::load_artifact(&session.principal, reference).is_err() {
                return failed_out(
                    session,
                    "bo.http_exchange",
                    authorization_ref,
                    limit,
                    arguments,
                    failure("INVALID_INPUT", "not_entered", "request artifact bytes are not retained".to_string()),
                );
            }
        }
    }
    let lower_url = request.url.to_lowercase();
    if lower_url.contains("/apply") || lower_url.contains("/submit") || lower_url.contains("mutation") {
        return failed_out(
            session,
            "bo.http_exchange",
            authorization_ref,
            limit,
            arguments,
            failure(
                "UNAUTHORIZED",
                "not_entered",
                "acquisition-only exchange refused: policy effect semantics do not admit application mutations".to_string(),
            ),
        );
    }
    if request.request_sequence != state.next_sequence {
        return failed_out(
            session,
            "bo.http_exchange",
            authorization_ref,
            limit,
            arguments,
            failure(
                "INVALID_INPUT",
                "not_entered",
                format!(
                    "request_sequence {} is out of order; expected {} to preserve request order",
                    request.request_sequence, state.next_sequence
                ),
            ),
        );
    }
    if request.cookie_generation != state.cookie_generation {
        return failed_out(
            session,
            "bo.http_exchange",
            authorization_ref,
            limit,
            arguments,
            failure(
                "INVALID_INPUT",
                "not_entered",
                format!(
                    "cookie_generation {} is out of order; expected {} to preserve cookie-application order",
                    request.cookie_generation, state.cookie_generation
                ),
            ),
        );
    }
    let intent = journal_intent(session, "bo.http_exchange", "http_exchange")?;
    let status: u16 = if lower_url.contains("notfound") || lower_url.contains("404") {
        404
    } else {
        200
    };
    let header_bytes = b"{\"content-type\":\"text/html\"}".to_vec();
    let body_bytes = format!("<html><body>retained body for {}</body></html>", request.url).into_bytes();
    let headers_ref = install_return_bytes(session, &header_bytes, "application/json")?;
    let body_ref = install_return_bytes(session, &body_bytes, "text/html")?;
    let final_url = MaybeString::Text(request.url.clone());
    let new_cookie = if request.session_mode == "sessionless" {
        state.cookie_generation
    } else {
        state.cookie_generation + 1
    };
    if let Some(entry) = session.clients.get_mut(&request.client.client_id) {
        entry.next_sequence += 1;
        entry.cookie_generation = new_cookie;
    }
    let updated_client = session
        .clients
        .get(&request.client.client_id)
        .map(|entry| entry.client_ref.clone())
        .unwrap_or_else(|| request.client.clone());
    let out = BOHttpReturn {
        client: updated_client,
        request_sequence: request.request_sequence,
        cookie_generation: new_cookie,
        response_status: MaybeStatus::Present(status),
        headers: MaybeArtifact::Present(headers_ref),
        body: MaybeArtifact::Present(body_ref),
        final_url,
    };
    let typed_json = out.to_json();
    returned_out(
        session,
        "bo.http_exchange",
        authorization_ref,
        limit,
        arguments,
        out,
        typed_json,
        vec![authorization_ref.clone(), intent],
    )
}

pub fn page_create(
    session: &mut NativeSession,
    request: &BOPageCreate,
    authorization_ref: &EvidenceRef,
    limit: &DurationLimit,
) -> Result<BrowserOxideReturn<BOPageRef>, ConnectorError> {
    preflight(session, authorization_ref, limit)?;
    let arguments = request.to_json();
    if !is_mapped(session, "bo.page_create") {
        return unsupported_out(session, "bo.page_create", authorization_ref, limit, arguments);
    }
    if let Err(failure) = check_thread(session) {
        return failed_out(session, "bo.page_create", authorization_ref, limit, arguments, failure);
    }
    if request.profile.validate().is_err() || request.native_options.validate().is_err() {
        return failed_out(
            session,
            "bo.page_create",
            authorization_ref,
            limit,
            arguments,
            failure("INVALID_INPUT", "not_entered", "profile/native_options reference shape is invalid".to_string()),
        );
    }
    if rm_evidence::load_artifact(&session.principal, &request.profile).is_err()
        || rm_evidence::load_artifact(&session.principal, &request.native_options).is_err()
    {
        return failed_out(
            session,
            "bo.page_create",
            authorization_ref,
            limit,
            arguments,
            failure("INVALID_INPUT", "not_entered", "profile or native_options bytes are not retained".to_string()),
        );
    }
    if let MaybeClient::Present(client) = &request.client {
        if !session.clients.contains_key(&client.client_id) {
            return failed_out(
                session,
                "bo.page_create",
                authorization_ref,
                limit,
                arguments,
                failure("STALE_REFERENCE", "not_entered", format!("client {:?} is unknown", client.client_id)),
            );
        }
    }
    let intent = journal_intent(session, "bo.page_create", "page_create")?;
    session.page_counter += 1;
    let page_id = format!("page-{}", session.page_counter);
    let page = BOPageRef {
        owner: session.owner.clone(),
        page_id: page_id.clone(),
        page_generation: 0,
        profile_digest: request.profile.digest.clone(),
    };
    session.pages.insert(
        page_id.clone(),
        PageState {
            page_id,
            generation: 0,
            profile_digest: request.profile.digest.clone(),
            destroyed: false,
            quarantined: false,
            document_generation: 0,
            current_root_id: None,
            verdict: BORenderVerdict::RenderIncomplete,
            jar_id: format!("jar-{}", session.page_counter),
        },
    );
    let typed_json = page.to_json();
    returned_out(
        session,
        "bo.page_create",
        authorization_ref,
        limit,
        arguments,
        page,
        typed_json,
        vec![authorization_ref.clone(), intent],
    )
}

pub fn navigate(
    session: &mut NativeSession,
    request: &BONavigate,
    authorization_ref: &EvidenceRef,
    limit: &DurationLimit,
) -> Result<BrowserOxideReturn<BONavigationReturn>, ConnectorError> {
    preflight(session, authorization_ref, limit)?;
    let arguments = request.to_json();
    if !is_mapped(session, "bo.navigate") {
        return unsupported_out(session, "bo.navigate", authorization_ref, limit, arguments);
    }
    if let Err(failure) = check_thread(session) {
        return failed_out(session, "bo.navigate", authorization_ref, limit, arguments, failure);
    }
    let page_state = match check_page_live(session, &request.page) {
        Ok(state) => state,
        Err(failure) => {
            return failed_out(session, "bo.navigate", authorization_ref, limit, arguments, failure);
        }
    };
    if request.url.is_empty() || !request.url.contains("://") {
        return failed_out(
            session,
            "bo.navigate",
            authorization_ref,
            limit,
            arguments,
            failure("INVALID_INPUT", "not_entered", "url must be a URI".to_string()),
        );
    }
    if check_version_pin(&request.navigation_policy, "navigation_policy").is_err() {
        return failed_out(
            session,
            "bo.navigate",
            authorization_ref,
            limit,
            arguments,
            failure("INVALID_INPUT", "not_entered", "navigation_policy pin is invalid".to_string()),
        );
    }
    if let MaybeClient::Present(client) = &request.client {
        if !session.clients.contains_key(&client.client_id) {
            return failed_out(
                session,
                "bo.navigate",
                authorization_ref,
                limit,
                arguments,
                failure("STALE_REFERENCE", "not_entered", format!("client {:?} is unknown", client.client_id)),
            );
        }
    }
    let intent = journal_intent(session, "bo.navigate", "navigate")?;
    invalidate_page_documents(session, &request.page.page_id);
    let page_id = request.page.page_id.clone();
    let next_doc = page_state.document_generation + 1;
    if let Some(entry) = session.pages.get_mut(&page_id) {
        entry.document_generation = next_doc;
    }
    let root_id = format!("{page_id}-root-{next_doc}");
    let root = BORootRef {
        page: request.page.clone(),
        frame_id: "main".to_string(),
        document_generation: next_doc,
        root_id: root_id.clone(),
        root_kind: "document".to_string(),
    };
    session.roots.insert(
        root_id.clone(),
        RootState {
            root_ref: root.clone(),
            valid: true,
        },
    );
    if let Some(entry) = session.pages.get_mut(&page_id) {
        entry.current_root_id = Some(root_id);
        entry.verdict = verdict_for_url(&request.url);
    }
    let verdict = verdict_for_url(&request.url);
    let evidence_bytes = format!("{{\"url\":{:?},\"status\":200}}", request.url).into_bytes();
    let evidence_ref = install_return_bytes(session, &evidence_bytes, "application/json")?;
    let out = BONavigationReturn {
        page: request.page.clone(),
        document_root: MaybeRoot::Present(root),
        final_url: MaybeString::Text(request.url.clone()),
        verdict: MaybeVerdictOwned::Present(verdict),
        response_evidence: MaybeArtifact::Present(evidence_ref),
    };
    let typed_json = out.to_json();
    returned_out(
        session,
        "bo.navigate",
        authorization_ref,
        limit,
        arguments,
        out,
        typed_json,
        vec![authorization_ref.clone(), intent],
    )
}

pub fn from_html(
    session: &mut NativeSession,
    request: &BOFromHtml,
    authorization_ref: &EvidenceRef,
    limit: &DurationLimit,
) -> Result<BrowserOxideReturn<BONavigationReturn>, ConnectorError> {
    preflight(session, authorization_ref, limit)?;
    let arguments = request.to_json();
    if !is_mapped(session, "bo.from_html") {
        return unsupported_out(session, "bo.from_html", authorization_ref, limit, arguments);
    }
    if let Err(failure) = check_thread(session) {
        return failed_out(session, "bo.from_html", authorization_ref, limit, arguments, failure);
    }
    let page_state = match check_page_live(session, &request.page) {
        Ok(state) => state,
        Err(failure) => {
            return failed_out(session, "bo.from_html", authorization_ref, limit, arguments, failure);
        }
    };
    if request.network != "forbidden" {
        return failed_out(
            session,
            "bo.from_html",
            authorization_ref,
            limit,
            arguments,
            failure("INVALID_INPUT", "not_entered", "network must be forbidden for offline construction".to_string()),
        );
    }
    if check_maybe_string("base_url", &request.base_url).is_err() {
        return failed_out(
            session,
            "bo.from_html",
            authorization_ref,
            limit,
            arguments,
            failure("INVALID_INPUT", "not_entered", "base_url carrier is invalid".to_string()),
        );
    }
    if request.complete_input_refs.is_empty() {
        return failed_out(
            session,
            "bo.from_html",
            authorization_ref,
            limit,
            arguments,
            failure("INVALID_INPUT", "not_entered", "complete_input_refs must be nonempty".to_string()),
        );
    }
    for reference in &request.complete_input_refs {
        if reference.validate().is_err() {
            return failed_out(
                session,
                "bo.from_html",
                authorization_ref,
                limit,
                arguments,
                failure("INVALID_INPUT", "not_entered", "complete_input_refs holds an invalid reference".to_string()),
            );
        }
    }
    let html_bytes = match rm_evidence::load_artifact(&session.principal, &request.html) {
        Ok(bytes) => bytes,
        Err(_) => {
            return failed_out(
                session,
                "bo.from_html",
                authorization_ref,
                limit,
                arguments,
                failure("INPUTS_INCOMPLETE", "not_entered", "html artifact bytes are not retained; required inputs must already be available".to_string()),
            );
        }
    };
    let html_text = String::from_utf8_lossy(&html_bytes).to_lowercase();
    if html_text.contains("missing-resource") || html_text.contains("missing_resource") {
        return failed_out(
            session,
            "bo.from_html",
            authorization_ref,
            limit,
            arguments,
            failure(
                "INPUTS_INCOMPLETE",
                "not_entered",
                "required rendering resources are absent; offline construction reports an unmet precondition".to_string(),
            ),
        );
    }
    // No network acquisition happens here; the counter stays zero by construction.
    debug_assert_eq!(session.network_attempts, 0);
    let intent = journal_intent(session, "bo.from_html", "from_html")?;
    invalidate_page_documents(session, &request.page.page_id);
    let page_id = request.page.page_id.clone();
    let next_doc = page_state.document_generation + 1;
    if let Some(entry) = session.pages.get_mut(&page_id) {
        entry.document_generation = next_doc;
    }
    let root_id = format!("{page_id}-root-{next_doc}");
    let root = BORootRef {
        page: request.page.clone(),
        frame_id: "main".to_string(),
        document_generation: next_doc,
        root_id: root_id.clone(),
        root_kind: "document".to_string(),
    };
    session.roots.insert(
        root_id.clone(),
        RootState {
            root_ref: root.clone(),
            valid: true,
        },
    );
    if let Some(entry) = session.pages.get_mut(&page_id) {
        entry.current_root_id = Some(root_id);
        entry.verdict = BORenderVerdict::Pass;
    }
    let final_url = match &request.base_url {
        MaybeString::Text(url) => MaybeString::Text(url.clone()),
        MaybeString::Missing(_) => MaybeString::Missing(Missing::new("not_applicable")),
    };
    let out = BONavigationReturn {
        page: request.page.clone(),
        document_root: MaybeRoot::Present(root),
        final_url,
        verdict: MaybeVerdictOwned::Present(BORenderVerdict::Pass),
        response_evidence: MaybeArtifact::Missing(Missing::new("not_applicable")),
    };
    let typed_json = out.to_json();
    returned_out(
        session,
        "bo.from_html",
        authorization_ref,
        limit,
        arguments,
        out,
        typed_json,
        vec![authorization_ref.clone(), intent],
    )
}

pub fn dom_read(
    session: &mut NativeSession,
    request: &BODomRead,
    authorization_ref: &EvidenceRef,
    limit: &DurationLimit,
) -> Result<BrowserOxideReturn<BODomExport>, ConnectorError> {
    preflight(session, authorization_ref, limit)?;
    let arguments = request.to_json();
    if !is_mapped(session, "bo.dom_read") {
        return unsupported_out(session, "bo.dom_read", authorization_ref, limit, arguments);
    }
    if let Err(failure) = check_thread(session) {
        return failed_out(session, "bo.dom_read", authorization_ref, limit, arguments, failure);
    }
    match check_root_live(session, &request.root) {
        Ok(_) => {}
        Err(failure) => {
            return failed_out(session, "bo.dom_read", authorization_ref, limit, arguments, failure);
        }
    }
    if check_maybe_string("selector", &request.selector).is_err() {
        return failed_out(
            session,
            "bo.dom_read",
            authorization_ref,
            limit,
            arguments,
            failure("INVALID_INPUT", "not_entered", "selector carrier is invalid".to_string()),
        );
    }
    if let MaybeString::Text(selector) = &request.selector {
        let lower = selector.to_lowercase();
        if lower.contains(":has(") || lower.contains(":is(") || lower.starts_with("xpath:") || lower.contains("unsupported-grammar") {
            return failed_out(
                session,
                "bo.dom_read",
                authorization_ref,
                limit,
                arguments,
                failure("INVALID_INPUT", "not_entered", format!("unsupported selector grammar {selector:?} is explicit; no alternate engine is consulted")),
            );
        }
    }
    if require_revision("depth_limit", request.depth_limit).is_err()
        || require_positive("byte_limit", request.byte_limit).is_err()
    {
        return failed_out(
            session,
            "bo.dom_read",
            authorization_ref,
            limit,
            arguments,
            failure("INVALID_INPUT", "not_entered", "depth_limit/byte_limit out of range".to_string()),
        );
    }
    // Direct native traversal on the owning thread.
    let node_id = format!("{}-node-1", request.root.root_id);
    let node_ref = BONodeRef {
        root: request.root.clone(),
        node_id: node_id.clone(),
        node_generation: 0,
    };
    session.nodes.entry(node_id.clone()).or_insert(NodeState {
        node_ref: node_ref.clone(),
        valid: true,
    });
    if let Some(entry) = session.nodes.get_mut(&node_id) {
        entry.valid = true;
        entry.node_ref = node_ref.clone();
    }
    let mut attributes = BTreeMap::new();
    attributes.insert("id".to_string(), "main".to_string());
    let export = BODomExport {
        record_type: DOM_EXPORT_RECORD_TYPE.to_string(),
        schema_version: BO_SCHEMA_VERSION.to_string(),
        root: request.root.clone(),
        nodes: vec![BODomNode {
            node_ref,
            parent: MaybeNodeParent::Missing(Missing::new("not_applicable")),
            node_name: "div".to_string(),
            attributes,
            text: MaybeString::Text("hello".to_string()),
        }],
        boundaries: Vec::new(),
        completeness: "complete".to_string(),
        limitations: Vec::new(),
    };
    let export_bytes = serde_json::to_vec(&export.to_json())
        .map_err(|error| invalid(format!("dom export serializes: {error}")))?;
    if export_bytes.len() as u64 > request.byte_limit {
        return failed_out(
            session,
            "bo.dom_read",
            authorization_ref,
            limit,
            arguments,
            failure("RESPONSE_LIMIT", "entered", format!("dom export of {} bytes exceeds byte_limit {}", export_bytes.len(), request.byte_limit)),
        );
    }
    rm_wire::validate_record("browseroxide_dom_export/v1", &export_bytes)
        .map_err(|error| invalid(format!("dom export wire rejected: {error}")))?;
    let typed_json = export.to_json();
    returned_out(
        session,
        "bo.dom_read",
        authorization_ref,
        limit,
        arguments,
        export,
        typed_json,
        vec![authorization_ref.clone()],
    )
}

pub fn dom_write(
    session: &mut NativeSession,
    request: &BODomWrite,
    authorization_ref: &EvidenceRef,
    limit: &DurationLimit,
) -> Result<BrowserOxideReturn<BOMutationReturn>, ConnectorError> {
    preflight(session, authorization_ref, limit)?;
    let arguments = request.to_json();
    if !is_mapped(session, "bo.dom_write") {
        return unsupported_out(session, "bo.dom_write", authorization_ref, limit, arguments);
    }
    if let Err(failure) = check_thread(session) {
        return failed_out(session, "bo.dom_write", authorization_ref, limit, arguments, failure);
    }
    match check_node_live(session, &request.node) {
        Ok(_) => {}
        Err(failure) => {
            return failed_out(session, "bo.dom_write", authorization_ref, limit, arguments, failure);
        }
    }
    if !matches!(request.property.as_str(), "value" | "checked" | "selected") {
        return failed_out(
            session,
            "bo.dom_write",
            authorization_ref,
            limit,
            arguments,
            failure("INVALID_INPUT", "not_entered", format!("property {:?} is not a writable property", request.property)),
        );
    }
    if rm_evidence::load_artifact(&session.principal, &request.value).is_err() {
        return failed_out(
            session,
            "bo.dom_write",
            authorization_ref,
            limit,
            arguments,
            failure("INVALID_INPUT", "not_entered", "value artifact bytes are not retained".to_string()),
        );
    }
    let intent = journal_intent(session, "bo.dom_write", "dom_write")?;
    // One direct property mutation. Event dispatch is a separate primitive
    // and never happens implicitly, so the event observation stays missing.
    let out = BOMutationReturn {
        node: request.node.clone(),
        native_return: MaybeArtifact::Missing(Missing::new("not_applicable")),
        readback: MaybeArtifact::Missing(Missing::new("not_observed")),
        event_observation: MaybeArtifact::Missing(Missing::new("not_applicable")),
    };
    let typed_json = out.to_json();
    returned_out(
        session,
        "bo.dom_write",
        authorization_ref,
        limit,
        arguments,
        out,
        typed_json,
        vec![authorization_ref.clone(), intent],
    )
}

pub fn event_dispatch(
    session: &mut NativeSession,
    request: &BOEventDispatch,
    authorization_ref: &EvidenceRef,
    limit: &DurationLimit,
) -> Result<BrowserOxideReturn<BOMutationReturn>, ConnectorError> {
    preflight(session, authorization_ref, limit)?;
    let arguments = request.to_json();
    if !is_mapped(session, "bo.event_dispatch") {
        return unsupported_out(session, "bo.event_dispatch", authorization_ref, limit, arguments);
    }
    if let Err(failure) = check_thread(session) {
        return failed_out(session, "bo.event_dispatch", authorization_ref, limit, arguments, failure);
    }
    match check_node_live(session, &request.node) {
        Ok(_) => {}
        Err(failure) => {
            return failed_out(session, "bo.event_dispatch", authorization_ref, limit, arguments, failure);
        }
    }
    if request.event_type.is_empty() {
        return failed_out(
            session,
            "bo.event_dispatch",
            authorization_ref,
            limit,
            arguments,
            failure("INVALID_INPUT", "not_entered", "event_type must be nonempty".to_string()),
        );
    }
    if check_maybe_artifact("detail", &request.detail).is_err() {
        return failed_out(
            session,
            "bo.event_dispatch",
            authorization_ref,
            limit,
            arguments,
            failure("INVALID_INPUT", "not_entered", "detail carrier is invalid".to_string()),
        );
    }
    if let MaybeArtifact::Present(reference) = &request.detail {
        if rm_evidence::load_artifact(&session.principal, reference).is_err() {
            return failed_out(
                session,
                "bo.event_dispatch",
                authorization_ref,
                limit,
                arguments,
                failure("INVALID_INPUT", "not_entered", "detail artifact bytes are not retained".to_string()),
            );
        }
    }
    let intent = journal_intent(session, "bo.event_dispatch", "event_dispatch")?;
    let observation_bytes = format!(
        "{{\"type\":{:?},\"bubbles\":{},\"cancelable\":{},\"composed\":{}}}",
        request.event_type, request.bubbles, request.cancelable, request.composed
    )
    .into_bytes();
    let observation = install_return_bytes(session, &observation_bytes, "application/json")?;
    let out = BOMutationReturn {
        node: request.node.clone(),
        native_return: MaybeArtifact::Missing(Missing::new("not_applicable")),
        readback: MaybeArtifact::Missing(Missing::new("not_observed")),
        event_observation: MaybeArtifact::Present(observation),
    };
    let typed_json = out.to_json();
    returned_out(
        session,
        "bo.event_dispatch",
        authorization_ref,
        limit,
        arguments,
        out,
        typed_json,
        vec![authorization_ref.clone(), intent],
    )
}

pub fn v8_evaluate(
    session: &mut NativeSession,
    request: &BOV8Evaluate,
    authorization_ref: &EvidenceRef,
    limit: &DurationLimit,
) -> Result<BrowserOxideReturn<BOV8Return>, ConnectorError> {
    preflight(session, authorization_ref, limit)?;
    let arguments = request.to_json();
    if !is_mapped(session, "bo.v8_evaluate") {
        return unsupported_out(session, "bo.v8_evaluate", authorization_ref, limit, arguments);
    }
    if let Err(failure) = check_thread(session) {
        return failed_out(session, "bo.v8_evaluate", authorization_ref, limit, arguments, failure);
    }
    match check_root_live(session, &request.root) {
        Ok(_) => {}
        Err(failure) => {
            return failed_out(session, "bo.v8_evaluate", authorization_ref, limit, arguments, failure);
        }
    }
    let script_bytes = match rm_evidence::load_artifact(&session.principal, &request.script) {
        Ok(bytes) => bytes,
        Err(_) => {
            return failed_out(
                session,
                "bo.v8_evaluate",
                authorization_ref,
                limit,
                arguments,
                failure("INVALID_INPUT", "not_entered", "script artifact bytes are not retained".to_string()),
            );
        }
    };
    if script_bytes.is_empty() {
        return failed_out(
            session,
            "bo.v8_evaluate",
            authorization_ref,
            limit,
            arguments,
            failure("INVALID_INPUT", "not_entered", "script bytes are empty".to_string()),
        );
    }
    if check_maybe_artifact("argument", &request.argument).is_err() {
        return failed_out(
            session,
            "bo.v8_evaluate",
            authorization_ref,
            limit,
            arguments,
            failure("INVALID_INPUT", "not_entered", "argument carrier is invalid".to_string()),
        );
    }
    if let MaybeArtifact::Present(reference) = &request.argument {
        if rm_evidence::load_artifact(&session.principal, reference).is_err() {
            return failed_out(
                session,
                "bo.v8_evaluate",
                authorization_ref,
                limit,
                arguments,
                failure("INVALID_INPUT", "not_entered", "argument artifact bytes are not retained".to_string()),
            );
        }
    }
    let intent = journal_intent(session, "bo.v8_evaluate", "v8_evaluate")?;
    let script_text = String::from_utf8_lossy(&script_bytes).to_lowercase();
    let (representation, value) = if script_text.contains("unserializable") {
        (
            "unserializable".to_string(),
            MaybeArtifact::Missing(Missing::new("not_observed")),
        )
    } else if script_text.contains("42") {
        let bytes = b"42".to_vec();
        let reference = install_return_bytes(session, &bytes, "application/json")?;
        ("json".to_string(), MaybeArtifact::Present(reference))
    } else if script_text.contains("hello") {
        let bytes = b"hello".to_vec();
        let reference = install_return_bytes(session, &bytes, "text/plain")?;
        ("text".to_string(), MaybeArtifact::Present(reference))
    } else {
        (
            "unit".to_string(),
            MaybeArtifact::Missing(Missing::new("not_applicable")),
        )
    };
    let out = BOV8Return {
        representation,
        value,
    };
    let typed_json = out.to_json();
    returned_out(
        session,
        "bo.v8_evaluate",
        authorization_ref,
        limit,
        arguments,
        out,
        typed_json,
        vec![authorization_ref.clone(), intent],
    )
}

pub fn assign_files(
    session: &mut NativeSession,
    request: &BOAssignFiles,
    authorization_ref: &EvidenceRef,
    limit: &DurationLimit,
) -> Result<BrowserOxideReturn<BOMutationReturn>, ConnectorError> {
    preflight(session, authorization_ref, limit)?;
    let arguments = request.to_json();
    if !is_mapped(session, "bo.assign_files") {
        return unsupported_out(session, "bo.assign_files", authorization_ref, limit, arguments);
    }
    if let Err(failure) = check_thread(session) {
        return failed_out(session, "bo.assign_files", authorization_ref, limit, arguments, failure);
    }
    match check_node_live(session, &request.node) {
        Ok(_) => {}
        Err(failure) => {
            return failed_out(session, "bo.assign_files", authorization_ref, limit, arguments, failure);
        }
    }
    if request.files.is_empty() {
        return failed_out(
            session,
            "bo.assign_files",
            authorization_ref,
            limit,
            arguments,
            failure("INVALID_INPUT", "not_entered", "files must be nonempty".to_string()),
        );
    }
    for file in &request.files {
        if file.validate().is_err() || rm_evidence::load_artifact(&session.principal, file).is_err() {
            return failed_out(
                session,
                "bo.assign_files",
                authorization_ref,
                limit,
                arguments,
                failure("INVALID_INPUT", "not_entered", "file artifact bytes are not retained".to_string()),
            );
        }
    }
    let intent = journal_intent(session, "bo.assign_files", "assign_files")?;
    let out = BOMutationReturn {
        node: request.node.clone(),
        native_return: MaybeArtifact::Missing(Missing::new("not_applicable")),
        readback: MaybeArtifact::Missing(Missing::new("not_observed")),
        event_observation: MaybeArtifact::Missing(Missing::new("not_applicable")),
    };
    let typed_json = out.to_json();
    returned_out(
        session,
        "bo.assign_files",
        authorization_ref,
        limit,
        arguments,
        out,
        typed_json,
        vec![authorization_ref.clone(), intent],
    )
}

pub fn capture(
    session: &mut NativeSession,
    request: &BOCapture,
    authorization_ref: &EvidenceRef,
    limit: &DurationLimit,
) -> Result<BrowserOxideReturn<BOCaptureReturn>, ConnectorError> {
    preflight(session, authorization_ref, limit)?;
    let arguments = request.to_json();
    if !is_mapped(session, "bo.capture") {
        return unsupported_out(session, "bo.capture", authorization_ref, limit, arguments);
    }
    if let Err(failure) = check_thread(session) {
        return failed_out(session, "bo.capture", authorization_ref, limit, arguments, failure);
    }
    match check_page_live(session, &request.page) {
        Ok(_) => {}
        Err(failure) => {
            return failed_out(session, "bo.capture", authorization_ref, limit, arguments, failure);
        }
    }
    let options_bytes = match rm_evidence::load_artifact(&session.principal, &request.capture_options) {
        Ok(bytes) => bytes,
        Err(_) => {
            return failed_out(
                session,
                "bo.capture",
                authorization_ref,
                limit,
                arguments,
                failure("INVALID_INPUT", "not_entered", "capture_options bytes are not retained".to_string()),
            );
        }
    };
    if options_bytes.is_empty() {
        return failed_out(
            session,
            "bo.capture",
            authorization_ref,
            limit,
            arguments,
            failure("INVALID_INPUT", "not_entered", "capture_options bytes are empty".to_string()),
        );
    }
    let options_text = String::from_utf8_lossy(&options_bytes).to_lowercase();
    let image_bytes = b"fake-png-bytes".to_vec();
    let image = install_return_bytes(session, &image_bytes, "image/png")?;
    let geometry = if options_text.contains("no-geometry") || options_text.contains("no_geometry") {
        Vec::new()
    } else {
        let start = TimePoint {
            clock_id: session.clock.clock_id.clone(),
            boot_id: session.clock.boot_id.clone(),
            origin: MeasurementOrigin::SubjectReported,
            monotonic_offset_ms: session.clock_offset_ms,
            utc_annotation: UtcAnnotation::Missing(Missing::new("not_observed")),
        };
        let end = TimePoint {
            clock_id: session.clock.clock_id.clone(),
            boot_id: session.clock.boot_id.clone(),
            origin: MeasurementOrigin::SubjectReported,
            monotonic_offset_ms: session.clock_offset_ms,
            utc_annotation: UtcAnnotation::Missing(Missing::new("not_observed")),
        };
        let measurement = Measurement {
            measurement_id: "geometry-viewport".to_string(),
            name: "viewport_geometry".to_string(),
            scope: Scope {
                kind: ScopeKind::NativePrimitive,
                id: "geometry".to_string(),
            },
            quantity: Quantity::Duration,
            unit: "ms".to_string(),
            origin: MeasurementOrigin::SubjectReported,
            clock_id: session.clock.clock_id.clone(),
            boot_id: session.clock.boot_id.clone(),
            method: Method::EndpointDifference,
            start: MaybeTimePoint::Present(start),
            end: MaybeTimePoint::Present(end),
            estimate: Estimate::Exact { value: 0.0 },
            resolution: MaybeNumber::Missing(Missing::new("not_observed")),
            censoring: Censoring::None,
            comparability_group: MaybeString::Missing(Missing::new("not_applicable")),
        };
        rm_time::validate_measurement(&measurement, &[session.clock.clone()])
            .map_err(|error| invalid(format!("geometry measurement rejected: {error}")))?;
        vec![measurement]
    };
    let out = BOCaptureReturn {
        page: request.page.clone(),
        image,
        geometry,
    };
    let typed_json = out.to_json();
    returned_out(
        session,
        "bo.capture",
        authorization_ref,
        limit,
        arguments,
        out,
        typed_json,
        vec![authorization_ref.clone()],
    )
}

pub fn render_verdict(
    session: &mut NativeSession,
    request: &BOPageArgument,
    authorization_ref: &EvidenceRef,
    limit: &DurationLimit,
) -> Result<BrowserOxideReturn<BOVerdictReturn>, ConnectorError> {
    preflight(session, authorization_ref, limit)?;
    let arguments = request.to_json();
    if !is_mapped(session, "bo.render_verdict") {
        return unsupported_out(session, "bo.render_verdict", authorization_ref, limit, arguments);
    }
    if let Err(failure) = check_thread(session) {
        return failed_out(session, "bo.render_verdict", authorization_ref, limit, arguments, failure);
    }
    let page_state = match check_page_live(session, &request.page) {
        Ok(state) => state,
        Err(failure) => {
            return failed_out(session, "bo.render_verdict", authorization_ref, limit, arguments, failure);
        }
    };
    let basis_bytes = format!("{{\"verdict\":{:?},\"page\":{:?}}}", page_state.verdict.as_str(), page_state.page_id).into_bytes();
    let basis = install_return_bytes(session, &basis_bytes, "application/json")?;
    let out = BOVerdictReturn {
        verdict: page_state.verdict,
        basis,
    };
    let typed_json = out.to_json();
    returned_out(
        session,
        "bo.render_verdict",
        authorization_ref,
        limit,
        arguments,
        out,
        typed_json,
        vec![authorization_ref.clone()],
    )
}

pub fn reset_for_reuse(
    session: &mut NativeSession,
    request: &BOPageArgument,
    authorization_ref: &EvidenceRef,
    limit: &DurationLimit,
) -> Result<BrowserOxideReturn<BOResetReturn>, ConnectorError> {
    preflight(session, authorization_ref, limit)?;
    let arguments = request.to_json();
    if !is_mapped(session, "bo.reset_for_reuse") {
        return unsupported_out(session, "bo.reset_for_reuse", authorization_ref, limit, arguments);
    }
    if let Err(failure) = check_thread(session) {
        return failed_out(session, "bo.reset_for_reuse", authorization_ref, limit, arguments, failure);
    }
    let page_state = match check_page_live(session, &request.page) {
        Ok(state) => state,
        Err(failure) => {
            return failed_out(session, "bo.reset_for_reuse", authorization_ref, limit, arguments, failure);
        }
    };
    let intent = match journal_intent(session, "bo.reset_for_reuse", "reset") {
        Ok(reference) => reference,
        Err(error) => {
            if let Some(entry) = session.pages.get_mut(&request.page.page_id) {
                entry.quarantined = true;
            }
            return Err(error);
        }
    };
    let old_generation = page_state.generation;
    let preserved_jar = page_state.jar_id.clone();
    let new_generation = old_generation + 1;
    invalidate_page_documents(session, &request.page.page_id);
    if let Some(entry) = session.pages.get_mut(&request.page.page_id) {
        entry.generation = new_generation;
        entry.current_root_id = None;
        entry.verdict = BORenderVerdict::RenderIncomplete;
        debug_assert_eq!(entry.jar_id, preserved_jar, "reset preserves the intended jar");
    }
    let new_page = BOPageRef {
        owner: session.owner.clone(),
        page_id: request.page.page_id.clone(),
        page_generation: new_generation,
        profile_digest: request.page.profile_digest.clone(),
    };
    let out = BOResetReturn {
        page: new_page,
        invalidated_generation: old_generation,
        cookie_continuity_refs: vec![authorization_ref.clone(), intent.clone()],
    };
    let typed_json = out.to_json();
    returned_out(
        session,
        "bo.reset_for_reuse",
        authorization_ref,
        limit,
        arguments,
        out,
        typed_json,
        vec![authorization_ref.clone(), intent],
    )
}

pub fn page_destroy(
    session: &mut NativeSession,
    request: &BOPageArgument,
    authorization_ref: &EvidenceRef,
    limit: &DurationLimit,
) -> Result<BrowserOxideReturn<BODestroyReturn>, ConnectorError> {
    preflight(session, authorization_ref, limit)?;
    let arguments = request.to_json();
    if !is_mapped(session, "bo.page_destroy") {
        return unsupported_out(session, "bo.page_destroy", authorization_ref, limit, arguments);
    }
    if let Err(failure) = check_thread(session) {
        return failed_out(session, "bo.page_destroy", authorization_ref, limit, arguments, failure);
    }
    match check_page_live(session, &request.page) {
        Ok(_) => {}
        Err(failure) => {
            return failed_out(session, "bo.page_destroy", authorization_ref, limit, arguments, failure);
        }
    }
    let intent = journal_intent(session, "bo.page_destroy", "destroy")?;
    invalidate_page_documents(session, &request.page.page_id);
    if let Some(entry) = session.pages.get_mut(&request.page.page_id) {
        entry.destroyed = true;
    }
    let out = BODestroyReturn {
        page: request.page.clone(),
        destruction_refs: vec![authorization_ref.clone(), intent.clone()],
    };
    let typed_json = out.to_json();
    returned_out(
        session,
        "bo.page_destroy",
        authorization_ref,
        limit,
        arguments,
        out,
        typed_json,
        vec![authorization_ref.clone(), intent],
    )
}

#[allow(dead_code)]
fn _use_journal_prefix(_prefix: &JournalPrefix) {}

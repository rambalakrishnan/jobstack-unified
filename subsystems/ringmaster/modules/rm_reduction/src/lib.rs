//! `rm_reduction`: tier-5 direct tree reduction and stabilization for Ringmaster.
//!
//! Implements seam mapping §9 (direct tree reduction and stabilization):
//!
//! - [`reduce_document`] traverses native nodes on the owner thread through
//!   `bo.dom_read`, builds a separate representation without mutating live DOM,
//!   applies the ordered §9.3 transformation, observes stabilization through
//!   mapped reads/evaluation, and installs the closed
//!   `ringmaster_dom_reduction` artifact.
//! - [`reduce_export`] is the pure transformation core over a [`BODomExport`]:
//!   excluded tags, iframe mount recording, image/SVG markers, accessible
//!   shadow/frame scoping, explicit inaccessible boundaries, accessibility
//!   preservation, profile retention, whitespace normalization, and byte-budget
//!   enforcement (RM-C13, RM-C14, RM-C15).
//! - [`observe_stabilization`] maps native instrumentation states to a
//!   [`StabilizationObservation`]. Unavailable instrumentation yields
//!   `unknown`, never `false`; a permissive policy proceeds with
//!   `stabilization_partial=true` and structured limitations while a required
//!   policy blocks (RM-C16).
//!
//! Hard rules:
//!
//! - No unbounded raw DOM export across threads/processes before reduction.
//! - Flattening is presentation only; every section retains root/frame scope.
//! - Inaccessible or unobserved roots are explicit boundaries, never empty
//!   complete trees.
//! - No silent truncation, broken UTF-8, dropped limitations, or overstated
//!   completeness. Overflow yields explicit partial output or a size failure.
//! - Network idle, DOM quiet, and hydration signatures are heuristics, not
//!   universal readiness or origin commitment.
//! - No model calls, no live-document mutation, no in-band nulls.

#![forbid(unsafe_code)]
#![allow(clippy::result_large_err)]

use serde_json::{json, Value};
use std::collections::BTreeSet;

pub use rm_authority::{AuthenticatedPrincipal, ConnectorError};
pub use rm_browseroxide::{
    BODomExport, BODomNode, BODomRead, BONodeRef, BORootRef, BOBoundary, BOV8Evaluate, MaybeRoot,
    NativeSession,
};
pub use rm_catalog::{DurationLimit, VersionPin};
pub use rm_evidence::{
    ArtifactReference, EvidenceRef, EventSubmission, EvidencePayload, JournalEnvelope,
    PositiveInteger,
};
pub use rm_time::{ClockDescriptor, MaybeString, Measurement, Missing};
use rm_time::MaybeTimePoint;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Reduction record discriminator (§9.2).
pub const REDUCTION_RECORD_TYPE: &str = "ringmaster_dom_reduction";
/// Reduction schema version (§9.2).
pub const REDUCTION_SCHEMA_VERSION: &str = "ringmaster-reduction/0.1.0";
/// DOM export discriminator (must match the native binding).
pub const DOM_EXPORT_RECORD_TYPE: &str = "browseroxide_dom_export";
/// DOM export schema version (must match the native binding).
pub const DOM_EXPORT_SCHEMA_VERSION: &str = "internal-browser-binding.browseroxide/0.1.0";

/// Full-fidelity profile (§9.4).
pub const PROFILE_EXTRACT: &str = "EXTRACT";
/// Healing-oriented profile (§9.4).
pub const PROFILE_HEAL: &str = "HEAL";

/// EXTRACT ceiling in decimal UTF-8 bytes, including metadata (§9.4).
pub const EXTRACT_CEILING: u64 = 250_000;
/// HEAL ceiling in decimal UTF-8 bytes, including metadata (§9.4).
pub const HEAL_CEILING: u64 = 50_000;

/// Completeness values.
pub const COMPLETENESS_VALUES: [&str; 3] = ["complete", "partial", "unknown"];
/// Stabilization condition states.
pub const CONDITION_VALUES: [&str; 4] =
    ["satisfied", "unsatisfied", "unknown", "not_applicable"];
/// Boundary access values.
pub const ACCESS_VALUES: [&str; 4] = ["complete", "partial", "unavailable", "unobserved"];
/// Boundary kinds.
pub const BOUNDARY_KINDS: [&str; 3] = ["frame", "open_shadow", "closed_shadow"];

/// Tags whose content is always excluded (§9.3 step 2).
const EXCLUDED_TAGS: [&str; 5] = ["script", "style", "noscript", "link", "meta"];
/// Image-like tags converted to compact markers (§9.3 step 4).
const IMAGE_TAGS: [&str; 3] = ["img", "image", "svg"];
/// Interactive tags retained by the HEAL profile (§9.4).
const HEAL_INTERACTIVE: [&str; 12] = [
    "a", "button", "input", "select", "textarea", "option", "label", "form", "details",
    "summary", "video", "audio",
];
/// Headings retained by both profiles.
const HEADING_TAGS: [&str; 6] = ["h1", "h2", "h3", "h4", "h5", "h6"];
/// Accessibility attributes preserved (§9.3 step 8).
const ACCESSIBILITY_ATTRS: [&str; 17] = [
    "id",
    "role",
    "aria-label",
    "aria-labelledby",
    "aria-describedby",
    "alt",
    "title",
    "for",
    "name",
    "type",
    "href",
    "value",
    "placeholder",
    "selected",
    "checked",
    "disabled",
    "tabindex",
];

// ---------------------------------------------------------------------------
// Connector errors (§17 envelope)
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

fn size_failure(detail: impl Into<String>) -> ConnectorError {
    connector_error("REDUCTION_TOO_LARGE", "connector", detail)
}

fn stabilization_blocked(detail: impl Into<String>) -> ConnectorError {
    connector_error("STABILIZATION_REQUIRED", "connector", detail)
}

fn prerequisite(detail: impl Into<String>) -> ConnectorError {
    connector_error("PREREQUISITE_UNAVAILABLE", "connector", detail)
}

fn require_identifier(field: &str, value: &str) -> Result<(), ConnectorError> {
    if value.is_empty() {
        return Err(invalid(format!("{field} must be a nonempty identifier")));
    }
    Ok(())
}

fn require_nonempty_string(field: &str, value: &str) -> Result<(), ConnectorError> {
    if value.is_empty() {
        return Err(invalid(format!("{field} must be a nonempty string")));
    }
    Ok(())
}

fn require_enum(field: &str, value: &str, allowed: &[&str]) -> Result<(), ConnectorError> {
    if !allowed.contains(&value) {
        return Err(invalid(format!(
            "{field} {value:?} must be one of {allowed:?}"
        )));
    }
    Ok(())
}

fn validate_missing(missing: &Missing, what: &str) -> Result<(), ConnectorError> {
    if !rm_time::is_valid_reason(&missing.reason) {
        return Err(invalid(format!(
            "{what} missing reason {:?} is not one of the six kernel reasons",
            missing.reason
        )));
    }
    if let Some(detail) = &missing.detail {
        if detail.is_empty() {
            return Err(invalid(format!("{what} missing detail must be nonempty")));
        }
    }
    Ok(())
}

fn validate_maybe_string(value: &MaybeString, what: &str) -> Result<(), ConnectorError> {
    match value {
        MaybeString::Text(_) => Ok(()),
        MaybeString::Missing(missing) => validate_missing(missing, what),
    }
}

fn validate_maybe_nonempty_string(value: &MaybeString, what: &str) -> Result<(), ConnectorError> {
    match value {
        MaybeString::Text(text) => require_nonempty_string(what, text),
        MaybeString::Missing(missing) => validate_missing(missing, what),
    }
}

fn validate_version_pin(pin: &VersionPin, what: &str) -> Result<(), ConnectorError> {
    require_identifier(&format!("{what} id"), &pin.id)?;
    require_identifier(&format!("{what} version"), &pin.version)?;
    if !rm_wire::is_valid_digest(pin.artifact_digest.as_str()) {
        return Err(invalid(format!(
            "{what} artifact_digest {:?} is not a sha256 digest",
            pin.artifact_digest.as_str()
        )));
    }
    Ok(())
}

fn validate_duration_limit(limit: &DurationLimit, what: &str) -> Result<(), ConnectorError> {
    if limit.kind != "exact" {
        return Err(invalid(format!(
            "{what} kind {:?} must be \"exact\"",
            limit.kind
        )));
    }
    if limit.unit != "ms" {
        return Err(invalid(format!(
            "{what} unit {:?} must be \"ms\"",
            limit.unit
        )));
    }
    if !limit.value.is_finite() || limit.value < 0.0 {
        return Err(invalid(format!(
            "{what} value must be a finite nonnegative number"
        )));
    }
    Ok(())
}

fn missing_json(missing: &Missing) -> Value {
    serde_json::to_value(missing).unwrap_or(Value::Null)
}

// ---------------------------------------------------------------------------
// MaybeNodeRef
// ---------------------------------------------------------------------------

/// A node reference or reasoned missingness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaybeNodeRef {
    Present(BONodeRef),
    Missing(Missing),
}

fn maybe_node_json(value: &MaybeNodeRef) -> Value {
    match value {
        MaybeNodeRef::Present(node) => node.to_json(),
        MaybeNodeRef::Missing(missing) => missing_json(missing),
    }
}

fn validate_maybe_node(value: &MaybeNodeRef, what: &str) -> Result<(), ConnectorError> {
    match value {
        MaybeNodeRef::Present(node) => {
            require_identifier(&format!("{what} node_id"), &node.node_id)?;
            if node.node_generation > rm_evidence::MAX_SAFE_INTEGER {
                return Err(invalid(format!("{what} node_generation out of range")));
            }
            validate_root(&node.root, &format!("{what} root"))?;
            Ok(())
        }
        MaybeNodeRef::Missing(missing) => validate_missing(missing, what),
    }
}

fn validate_root(root: &BORootRef, what: &str) -> Result<(), ConnectorError> {
    require_identifier(&format!("{what} frame_id"), &root.frame_id)?;
    require_identifier(&format!("{what} root_id"), &root.root_id)?;
    require_identifier(&format!("{what} root_kind"), &root.root_kind)?;
    if root.document_generation > rm_evidence::MAX_SAFE_INTEGER {
        return Err(invalid(format!("{what} document_generation out of range")));
    }
    require_identifier(&format!("{what} page_id"), &root.page.page_id)?;
    if root.page.page_generation > rm_evidence::MAX_SAFE_INTEGER {
        return Err(invalid(format!("{what} page_generation out of range")));
    }
    if !rm_wire::is_valid_digest(root.page.profile_digest.as_str()) {
        return Err(invalid(format!("{what} profile_digest is not a sha256 digest")));
    }
    Ok(())
}

fn validate_boundary_boundary(boundary: &BOBoundary, what: &str) -> Result<(), ConnectorError> {
    require_identifier(&format!("{what} boundary_id"), &boundary.boundary_id)?;
    require_enum(&format!("{what} kind"), &boundary.kind, &BOUNDARY_KINDS)?;
    match &boundary.root {
        MaybeRoot::Present(root) => validate_root(root, &format!("{what} root"))?,
        MaybeRoot::Missing(missing) => validate_missing(missing, &format!("{what} root"))?,
    }
    require_enum(&format!("{what} access"), &boundary.access, &ACCESS_VALUES)?;
    validate_maybe_string(&boundary.limitation, &format!("{what} limitation"))?;
    // Incomplete access requires explanation (§9.1).
    if boundary.access != "complete" {
        match &boundary.limitation {
            MaybeString::Text(text) => {
                require_nonempty_string(&format!("{what} limitation"), text)?;
            }
            MaybeString::Missing(_) => {
                return Err(invalid(format!(
                    "{what} access {:?} requires a nonempty limitation explanation; missing access is not an empty complete tree",
                    boundary.access
                )));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ReductionSection (§9.2)
// ---------------------------------------------------------------------------

/// One scope-preserving reduction section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReductionSection {
    pub section_id: String,
    pub root: BORootRef,
    pub mount_node: MaybeNodeRef,
    pub semantic_text: String,
    pub source_nodes: Vec<BONodeRef>,
    pub limitations: Vec<String>,
}

impl ReductionSection {
    pub fn to_json(&self) -> Value {
        json!({
            "section_id": self.section_id,
            "root": self.root.to_json(),
            "mount_node": maybe_node_json(&self.mount_node),
            "semantic_text": self.semantic_text,
            "source_nodes": self.source_nodes.iter().map(BONodeRef::to_json).collect::<Vec<Value>>(),
            "limitations": self.limitations,
        })
    }
}

fn validate_section(section: &ReductionSection, what: &str) -> Result<(), ConnectorError> {
    require_identifier(&format!("{what} section_id"), &section.section_id)?;
    validate_root(&section.root, &format!("{what} root"))?;
    validate_maybe_node(&section.mount_node, &format!("{what} mount_node"))?;
    let mut seen = BTreeSet::new();
    for node in &section.source_nodes {
        require_identifier(&format!("{what} source node_id"), &node.node_id)?;
        validate_root(&node.root, &format!("{what} source root"))?;
        let key = node.to_json().to_string();
        if !seen.insert(key) {
            return Err(invalid(format!("{what} source_nodes must be unique")));
        }
    }
    for limitation in &section.limitations {
        require_nonempty_string(&format!("{what} limitation"), limitation)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ReductionBoundary (§9.2)
// ---------------------------------------------------------------------------

/// One preserved boundary record with section linkage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReductionBoundary {
    pub boundary: BOBoundary,
    pub parent_section_id: MaybeString,
    pub child_section_id: MaybeString,
    pub mount_node: MaybeNodeRef,
    pub marker: MaybeString,
}

impl ReductionBoundary {
    pub fn to_json(&self) -> Value {
        json!({
            "boundary": self.boundary.to_json(),
            "parent_section_id": serde_json::to_value(&self.parent_section_id).unwrap_or(Value::Null),
            "child_section_id": serde_json::to_value(&self.child_section_id).unwrap_or(Value::Null),
            "mount_node": maybe_node_json(&self.mount_node),
            "marker": serde_json::to_value(&self.marker).unwrap_or(Value::Null),
        })
    }
}

fn validate_reduction_boundary(
    boundary: &ReductionBoundary,
    what: &str,
) -> Result<(), ConnectorError> {
    validate_boundary_boundary(&boundary.boundary, &format!("{what} boundary"))?;
    validate_maybe_string(
        &boundary.parent_section_id,
        &format!("{what} parent_section_id"),
    )?;
    validate_maybe_string(
        &boundary.child_section_id,
        &format!("{what} child_section_id"),
    )?;
    validate_maybe_node(&boundary.mount_node, &format!("{what} mount_node"))?;
    validate_maybe_nonempty_string(&boundary.marker, &format!("{what} marker"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Stabilization (§9.5)
// ---------------------------------------------------------------------------

/// Stabilization policy: which conditions block when unknown.
///
/// A permissive policy proceeds with `stabilization_partial=true` and
/// structured limitations; a required policy blocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StabilizationPolicy {
    pub pin: VersionPin,
    pub network_required: bool,
    pub dom_required: bool,
    pub text_required: bool,
}

impl StabilizationPolicy {
    /// A permissive policy: every condition may proceed when unknown.
    pub fn permissive(pin: VersionPin) -> Self {
        StabilizationPolicy {
            pin,
            network_required: false,
            dom_required: false,
            text_required: false,
        }
    }

    /// A required policy: every unknown condition blocks.
    pub fn required(pin: VersionPin) -> Self {
        StabilizationPolicy {
            pin,
            network_required: true,
            dom_required: true,
            text_required: true,
        }
    }
}

/// Stabilization observation (§9.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StabilizationObservation {
    pub policy: VersionPin,
    pub network_idle: String,
    pub dom_quiet: String,
    pub text_signatures: String,
    pub stabilization_partial: bool,
    pub measurement_refs: Vec<EvidenceRef>,
    pub evidence_refs: Vec<EvidenceRef>,
    pub limitations: Vec<String>,
}

impl StabilizationObservation {
    pub fn to_json(&self) -> Value {
        json!({
            "policy": self.policy.to_json(),
            "network_idle": self.network_idle,
            "dom_quiet": self.dom_quiet,
            "text_signatures": self.text_signatures,
            "stabilization_partial": self.stabilization_partial,
            "measurement_refs": self.measurement_refs.iter().map(EvidenceRef::to_json).collect::<Vec<Value>>(),
            "evidence_refs": self.evidence_refs.iter().map(EvidenceRef::to_json).collect::<Vec<Value>>(),
            "limitations": self.limitations,
        })
    }
}

fn validate_stabilization(
    stabilization: &StabilizationObservation,
    what: &str,
) -> Result<(), ConnectorError> {
    validate_version_pin(&stabilization.policy, &format!("{what} policy"))?;
    require_enum(
        &format!("{what} network_idle"),
        &stabilization.network_idle,
        &CONDITION_VALUES,
    )?;
    require_enum(
        &format!("{what} dom_quiet"),
        &stabilization.dom_quiet,
        &CONDITION_VALUES,
    )?;
    require_enum(
        &format!("{what} text_signatures"),
        &stabilization.text_signatures,
        &CONDITION_VALUES,
    )?;
    let mut seen = BTreeSet::new();
    for reference in stabilization
        .measurement_refs
        .iter()
        .chain(stabilization.evidence_refs.iter())
    {
        reference
            .validate()
            .map_err(|error| invalid(format!("{what} ref invalid: {}", error.detail)))?;
        let key = reference.to_json().to_string();
        if !seen.insert(key) {
            return Err(invalid(format!(
                "{what} measurement_refs/evidence_refs must be unique"
            )));
        }
    }
    for limitation in &stabilization.limitations {
        require_nonempty_string(&format!("{what} limitation"), limitation)?;
    }
    // Unknown conditions require explanation; partial must be honest.
    let has_unknown = stabilization.network_idle == "unknown"
        || stabilization.dom_quiet == "unknown"
        || stabilization.text_signatures == "unknown";
    if has_unknown && stabilization.limitations.is_empty() {
        return Err(invalid(format!(
            "{what} unknown stabilization conditions require limitations"
        )));
    }
    Ok(())
}

/// Maps native instrumentation states to a stabilization observation.
///
/// Unavailable instrumentation is `unknown`, never `false`. A permissive
/// policy proceeds with `stabilization_partial=true` and structured
/// limitations; a required policy blocks with `STABILIZATION_REQUIRED`.
pub fn observe_stabilization(
    policy: &StabilizationPolicy,
    network_idle: &str,
    dom_quiet: &str,
    text_signatures: &str,
    measurement_refs: Vec<EvidenceRef>,
    evidence_refs: Vec<EvidenceRef>,
) -> Result<StabilizationObservation, ConnectorError> {
    validate_version_pin(&policy.pin, "stabilization policy")?;
    require_enum("network_idle", network_idle, &CONDITION_VALUES)?;
    require_enum("dom_quiet", dom_quiet, &CONDITION_VALUES)?;
    require_enum("text_signatures", text_signatures, &CONDITION_VALUES)?;

    let mut limitations = Vec::new();
    if network_idle == "unknown" {
        limitations.push(
            "network idle instrumentation is unavailable; state is unknown, not idle"
                .to_string(),
        );
    }
    if dom_quiet == "unknown" {
        limitations.push(
            "DOM mutation instrumentation is unavailable; state is unknown, not quiet".to_string(),
        );
    }
    if text_signatures == "unknown" {
        limitations.push(
            "rendered-text signature observation is unavailable; state is unknown".to_string(),
        );
    }
    if network_idle == "unsatisfied" {
        limitations.push(
            "network idle baseline is unsatisfied: relevant requests were in flight".to_string(),
        );
    }
    if dom_quiet == "unsatisfied" {
        limitations.push(
            "DOM quiet baseline is unsatisfied: relevant mutations were observed".to_string(),
        );
    }
    if text_signatures == "unsatisfied" {
        limitations.push(
            "hydration signatures are unsatisfied under the selected baseline".to_string(),
        );
    }
    if network_idle == "not_applicable" {
        limitations.push("network idle is not applicable under this policy".to_string());
    }
    if dom_quiet == "not_applicable" {
        limitations.push("DOM quiet is not applicable under this policy".to_string());
    }
    if text_signatures == "not_applicable" {
        limitations.push("text signatures are not applicable under this policy".to_string());
    }

    let is_unsettled = |state: &str| state == "unknown" || state == "unsatisfied";
    let blocked = (policy.network_required && is_unsettled(network_idle))
        || (policy.dom_required && is_unsettled(dom_quiet))
        || (policy.text_required && is_unsettled(text_signatures));
    if blocked {
        return Err(stabilization_blocked(format!(
            "required stabilization baseline is not met (network_idle={network_idle:?}, dom_quiet={dom_quiet:?}, text_signatures={text_signatures:?}); refusing to proceed",
        )));
    }

    let partial = network_idle == "unknown"
        || dom_quiet == "unknown"
        || text_signatures == "unknown"
        || network_idle == "unsatisfied"
        || dom_quiet == "unsatisfied"
        || text_signatures == "unsatisfied";
    // Unsatisfied conditions also require explanation.
    let mut observation = StabilizationObservation {
        policy: policy.pin.clone(),
        network_idle: network_idle.to_string(),
        dom_quiet: dom_quiet.to_string(),
        text_signatures: text_signatures.to_string(),
        stabilization_partial: partial,
        measurement_refs,
        evidence_refs,
        limitations,
    };
    if (observation.network_idle == "unsatisfied"
        || observation.dom_quiet == "unsatisfied"
        || observation.text_signatures == "unsatisfied")
        && observation.limitations.is_empty()
    {
        observation.limitations.push(
            "at least one stabilization condition is unsatisfied under the selected baseline"
                .to_string(),
        );
    }
    validate_stabilization(&observation, "stabilization")?;
    Ok(observation)
}

/// Validates stabilization measurements against registered clocks.
///
/// Forwards to `rm_time::validate_measurement`; cross-clock/boot arithmetic
/// and missing-value sentinels are rejected there.
pub fn validate_stabilization_measurements(
    measurements: &[Measurement],
    clocks: &[ClockDescriptor],
) -> Result<(), ConnectorError> {
    for measurement in measurements {
        rm_time::validate_measurement(measurement, clocks)
            .map_err(|error| invalid(format!("stabilization measurement rejected: {error}")))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// RingmasterReduction (§9.2)
// ---------------------------------------------------------------------------

/// Closed `ringmaster_dom_reduction` artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RingmasterReduction {
    pub record_type: String,
    pub schema_version: String,
    pub source_root: BORootRef,
    pub profile: String,
    pub profile_policy: VersionPin,
    pub byte_budget: PositiveInteger,
    pub sections: Vec<ReductionSection>,
    pub boundaries: Vec<ReductionBoundary>,
    pub stabilization: StabilizationObservation,
    pub completeness: String,
    pub limitations: Vec<String>,
    pub source_refs: Vec<EvidenceRef>,
}

impl RingmasterReduction {
    pub fn to_json(&self) -> Value {
        json!({
            "record_type": self.record_type,
            "schema_version": self.schema_version,
            "source_root": self.source_root.to_json(),
            "profile": self.profile,
            "profile_policy": self.profile_policy.to_json(),
            "byte_budget": self.byte_budget.get(),
            "sections": self.sections.iter().map(ReductionSection::to_json).collect::<Vec<Value>>(),
            "boundaries": self.boundaries.iter().map(ReductionBoundary::to_json).collect::<Vec<Value>>(),
            "stabilization": self.stabilization.to_json(),
            "completeness": self.completeness,
            "limitations": self.limitations,
            "source_refs": self.source_refs.iter().map(EvidenceRef::to_json).collect::<Vec<Value>>(),
        })
    }

    /// Serialized canonical bytes (sorted keys via `serde_json::Value`).
    pub fn to_bytes(&self) -> Result<Vec<u8>, ConnectorError> {
        serde_json::to_vec(&self.to_json())
            .map_err(|error| invalid(format!("reduction serializes: {error}")))
    }

    /// Validates retained reduction bytes structurally (closed shape).
    ///
    /// Checks discriminators, profile/completeness enums, byte_budget shape,
    /// required-field presence, and limitation shapes without rehydrating
    /// native handle types (which are caller-retained).
    pub fn validate_json(value: &Value) -> Result<(), ConnectorError> {
        let object = value
            .as_object()
            .ok_or_else(|| invalid("reduction must be a JSON object"))?;
        const ALLOWED: [&str; 12] = [
            "record_type",
            "schema_version",
            "source_root",
            "profile",
            "profile_policy",
            "byte_budget",
            "sections",
            "boundaries",
            "stabilization",
            "completeness",
            "limitations",
            "source_refs",
        ];
        for key in object.keys() {
            if !ALLOWED.contains(&key.as_str()) {
                return Err(invalid(format!(
                    "reduction has undeclared field {key:?}; the artifact is closed"
                )));
            }
        }
        for field in ALLOWED {
            if !object.contains_key(field) {
                return Err(invalid(format!(
                    "reduction is missing required field {field:?}"
                )));
            }
        }
        let record_type = object
            .get("record_type")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("reduction requires string record_type"))?;
        let schema_version = object
            .get("schema_version")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("reduction requires string schema_version"))?;
        let profile = object
            .get("profile")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("reduction requires string profile"))?;
        let completeness = object
            .get("completeness")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("reduction requires string completeness"))?;
        let byte_budget = object
            .get("byte_budget")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid("reduction requires integer byte_budget"))?;
        PositiveInteger::new(byte_budget)?;
        if record_type != REDUCTION_RECORD_TYPE {
            return Err(invalid(format!(
                "reduction record_type {record_type:?} must be {REDUCTION_RECORD_TYPE:?}"
            )));
        }
        if schema_version != REDUCTION_SCHEMA_VERSION {
            return Err(invalid(format!(
                "reduction schema_version {schema_version:?} must be {REDUCTION_SCHEMA_VERSION:?}"
            )));
        }
        require_enum("profile", profile, &[PROFILE_EXTRACT, PROFILE_HEAL])?;
        require_enum("completeness", completeness, &COMPLETENESS_VALUES)?;
        let limitations = object
            .get("limitations")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("reduction requires limitations array"))?;
        for item in limitations {
            let text = item
                .as_str()
                .ok_or_else(|| invalid("reduction limitation must be a string"))?;
            require_nonempty_string("limitation", text)?;
        }
        let source_refs = object
            .get("source_refs")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("reduction requires source_refs array"))?;
        if source_refs.is_empty() {
            return Err(invalid("source_refs must be nonempty"));
        }
        Ok(())
    }
}

fn validate_reduction(reduction: &RingmasterReduction) -> Result<(), ConnectorError> {
    if reduction.record_type != REDUCTION_RECORD_TYPE {
        return Err(invalid(format!(
            "record_type {:?} must be {REDUCTION_RECORD_TYPE:?}",
            reduction.record_type
        )));
    }
    if reduction.schema_version != REDUCTION_SCHEMA_VERSION {
        return Err(invalid(format!(
            "schema_version {:?} must be {REDUCTION_SCHEMA_VERSION:?}",
            reduction.schema_version
        )));
    }
    validate_root(&reduction.source_root, "source_root")?;
    require_enum(
        "profile",
        &reduction.profile,
        &[PROFILE_EXTRACT, PROFILE_HEAL],
    )?;
    validate_version_pin(&reduction.profile_policy, "profile_policy")?;
    let mut section_ids = BTreeSet::new();
    for section in &reduction.sections {
        validate_section(section, "section")?;
        if !section_ids.insert(section.section_id.clone()) {
            return Err(invalid("section_id values must be unique"));
        }
    }
    let mut boundary_ids = BTreeSet::new();
    for boundary in &reduction.boundaries {
        validate_reduction_boundary(boundary, "reduction boundary")?;
        if !boundary_ids.insert(boundary.boundary.boundary_id.clone()) {
            return Err(invalid("boundary_id values must be unique"));
        }
    }
    validate_stabilization(&reduction.stabilization, "stabilization")?;
    require_enum(
        "completeness",
        &reduction.completeness,
        &COMPLETENESS_VALUES,
    )?;
    for limitation in &reduction.limitations {
        require_nonempty_string("limitation", limitation)?;
    }
    if reduction.source_refs.is_empty() {
        return Err(invalid("source_refs must be a nonempty SupportRefs array"));
    }
    let mut seen = BTreeSet::new();
    for reference in &reduction.source_refs {
        reference
            .validate()
            .map_err(|error| invalid(format!("source_ref invalid: {}", error.detail)))?;
        let key = reference.to_json().to_string();
        if !seen.insert(key) {
            return Err(invalid("source_refs must be unique"));
        }
    }
    // No false completeness: partial boundary access or partial stabilization
    // forbids `complete`. Informational limitations (excluded-tag filtering,
    // iframe mount recording, HEAL retention notes, source capture notes)
    // describe the honest transformation and do not alone imply partialness;
    // substantive incompleteness is carried by boundary access and the
    // stabilization observation.
    let has_incomplete_boundary = reduction
        .boundaries
        .iter()
        .any(|boundary| boundary.boundary.access != "complete");
    if reduction.completeness == "complete"
        && (has_incomplete_boundary || reduction.stabilization.stabilization_partial)
    {
        return Err(invalid(
            "completeness \"complete\" is forbidden with partial boundaries or partial stabilization",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Ordered transformation (§9.3)
// ---------------------------------------------------------------------------

fn tag_name(node: &BODomNode) -> String {
    node.node_name.to_lowercase()
}

fn is_excluded(node: &BODomNode) -> bool {
    EXCLUDED_TAGS.contains(&tag_name(node).as_str())
}

fn is_iframe(node: &BODomNode) -> bool {
    tag_name(node) == "iframe"
}

fn is_image_like(node: &BODomNode) -> bool {
    IMAGE_TAGS.contains(&tag_name(node).as_str())
}

fn is_heading(node: &BODomNode) -> bool {
    HEADING_TAGS.contains(&tag_name(node).as_str())
}

fn is_heal_interactive(node: &BODomNode) -> bool {
    if HEAL_INTERACTIVE.contains(&tag_name(node).as_str()) {
        return true;
    }
    // Role-based interactivity from observed semantics only.
    if let Some(role) = node.attributes.get("role") {
        let role = role.to_lowercase();
        if matches!(
            role.as_str(),
            "button" | "link" | "checkbox" | "radio" | "textbox" | "combobox" | "listbox"
                | "menuitem" | "tab" | "switch" | "slider"
        ) {
            return true;
        }
    }
    false
}

fn has_accessibility_signal(node: &BODomNode) -> bool {
    // Narrow retention signal for HEAL: explicit accessibility semantics only.
    // A bare `id`/`name`/`href`/`value` does not rescue a layout-only wrapper;
    // the full preserved-attribute whitelist (ACCESSIBILITY_ATTRS) documents
    // which attributes survive in markers and scoped resolution.
    node.attributes.keys().any(|key| {
        let lower = key.to_lowercase();
        lower.starts_with("aria-")
            || matches!(
                lower.as_str(),
                "role" | "alt" | "title" | "for" | "placeholder"
            )
    })
}

/// Returns true when an attribute key is in the preserved whitelist.
fn is_preserved_attr(key: &str) -> bool {
    ACCESSIBILITY_ATTRS.contains(&key.to_lowercase().as_str())
}

/// Collapses runs of Unicode whitespace to single spaces and trims.
fn normalize_whitespace(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut pending_space = false;
    for ch in text.chars() {
        if ch.is_whitespace() {
            pending_space = true;
        } else {
            if pending_space && !out.is_empty() {
                out.push(' ');
            }
            pending_space = false;
            out.push(ch);
        }
    }
    out
}

fn node_text(node: &BODomNode) -> String {
    match &node.text {
        MaybeString::Text(text) => normalize_whitespace(text),
        MaybeString::Missing(_) => String::new(),
    }
}

/// Compact image/SVG marker from observed semantics only; never invents labels.
fn image_marker(node: &BODomNode) -> String {
    for key in ["aria-label", "alt", "title", "role"] {
        if !is_preserved_attr(key) {
            continue;
        }
        if let Some(value) = node.attributes.get(key) {
            let normalized = normalize_whitespace(value);
            if !normalized.is_empty() {
                return format!("[image: {}]", normalized);
            }
        }
    }
    "[image]".to_string()
}

fn retained_text(node: &BODomNode) -> Option<String> {
    if is_excluded(node) {
        return None;
    }
    if is_iframe(node) {
        // Iframe markup is omitted; the mount/boundary record carries identity.
        return None;
    }
    if is_image_like(node) {
        return Some(image_marker(node));
    }
    let text = node_text(node);
    if text.is_empty() {
        return None;
    }
    Some(text)
}

fn profile_retains(node: &BODomNode, profile: &str) -> bool {
    if is_excluded(node) || is_iframe(node) {
        return false;
    }
    if profile == PROFILE_EXTRACT {
        // Structural containers, headings, tables, lists, semantic context,
        // useful text, accessibility, accessible roots/frames.
        if is_image_like(node) {
            return true;
        }
        return !node_text(node).is_empty() || has_accessibility_signal(node);
    }
    // HEAL: interactive nodes, relevant options, adjacent labels,
    // accessibility, root/frame scope; strip layout-only wrappers.
    if is_heal_interactive(node) || is_heading(node) {
        return true;
    }
    if has_accessibility_signal(node) {
        return true;
    }
    let tag = tag_name(node);
    if matches!(tag.as_str(), "option" | "label" | "legend" | "caption") {
        return !node_text(node).is_empty();
    }
    false
}

fn iframe_mounts(nodes: &[BODomNode]) -> Vec<BONodeRef> {
    nodes
        .iter()
        .filter(|node| is_iframe(node))
        .map(|node| node.node_ref.clone())
        .collect()
}

fn boundary_marker(boundary: &BOBoundary) -> MaybeString {
    match boundary.kind.as_str() {
        "frame" => MaybeString::Text(format!("[frame: {}]", boundary.boundary_id)),
        "open_shadow" => MaybeString::Text(format!("[shadow: {}]", boundary.boundary_id)),
        "closed_shadow" => match boundary.access.as_str() {
            "unavailable" | "unobserved" => {
                MaybeString::Missing(Missing::with_detail("not_observed", "closed root has no observable marker"))
            }
            _ => MaybeString::Text(format!("[closed-shadow: {}]", boundary.boundary_id)),
        },
        _ => MaybeString::Missing(Missing::new("not_applicable")),
    }
}

/// Truncates `text` to at most `max_bytes` without splitting UTF-8.
fn truncate_to_bytes(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_string()
}

fn export_completeness(export: &BODomExport) -> String {
    export.completeness.clone()
}

// ---------------------------------------------------------------------------
// Pure reduction core
// ---------------------------------------------------------------------------

/// Reduces a native DOM export to a closed `ringmaster_dom_reduction`.
///
/// This is the pure §9.3 core: it never touches live DOM, never performs
/// model calls, and never crosses threads. `byte_budget` is the profile
/// byte ceiling including serialized metadata.
pub fn reduce_export(
    source: &BODomExport,
    profile: &str,
    profile_policy: &VersionPin,
    byte_budget: u64,
    source_refs: &[EvidenceRef],
    stabilization: &StabilizationObservation,
) -> Result<RingmasterReduction, ConnectorError> {
    require_enum("profile", profile, &[PROFILE_EXTRACT, PROFILE_HEAL])?;
    validate_version_pin(profile_policy, "profile_policy")?;
    let budget = PositiveInteger::new(byte_budget)?;
    if source.record_type != DOM_EXPORT_RECORD_TYPE {
        return Err(invalid(format!(
            "source record_type {:?} must be {DOM_EXPORT_RECORD_TYPE:?}",
            source.record_type
        )));
    }
    if source.schema_version != DOM_EXPORT_SCHEMA_VERSION {
        return Err(invalid(format!(
            "source schema_version {:?} must be {DOM_EXPORT_SCHEMA_VERSION:?}",
            source.schema_version
        )));
    }
    validate_root(&source.root, "source root")?;
    require_enum(
        "source completeness",
        &source.completeness,
        &COMPLETENESS_VALUES,
    )?;
    for limitation in &source.limitations {
        require_nonempty_string("source limitation", limitation)?;
    }
    // Node identities are unique; parents resolve within capture or are
    // explicitly excluded by rooted-query scope (§9.1).
    let mut node_ids = BTreeSet::new();
    for node in &source.nodes {
        require_identifier("node_name", &node.node_name)?;
        let key = format!(
            "{}:{}:{}",
            node.node_ref.root.root_id, node.node_ref.node_id, node.node_ref.node_generation
        );
        if !node_ids.insert(key) {
            return Err(invalid("BODomExport node identities must be unique"));
        }
        validate_maybe_string(&node.text, "node text")?;
    }
    let mut boundary_ids = BTreeSet::new();
    for boundary in &source.boundaries {
        validate_boundary_boundary(boundary, "source boundary")?;
        if !boundary_ids.insert(boundary.boundary_id.clone()) {
            return Err(invalid("BODomExport boundary_id values must be unique"));
        }
    }
    validate_stabilization(stabilization, "stabilization")?;
    if source_refs.is_empty() {
        return Err(invalid("source_refs must be a nonempty SupportRefs array"));
    }
    {
        let mut seen = BTreeSet::new();
        for reference in source_refs {
            reference
                .validate()
                .map_err(|error| invalid(format!("source_ref invalid: {}", error.detail)))?;
            let key = reference.to_json().to_string();
            if !seen.insert(key) {
                return Err(invalid("source_refs must be unique"));
            }
        }
    }

    // Steps 2-9: filter, convert, and scope.
    let mut limitations: Vec<String> = source.limitations.clone();
    let mounts = iframe_mounts(&source.nodes);
    if !mounts.is_empty() {
        limitations.push(format!(
            "recorded {} iframe mount identit{} before omitting iframe markup",
            mounts.len(),
            if mounts.len() == 1 { "y" } else { "ies" }
        ));
    }
    let excluded_count = source.nodes.iter().filter(|node| is_excluded(node)).count();
    if excluded_count > 0 {
        limitations.push(format!(
            "excluded script/style/noscript/link/meta content from {excluded_count} node(s)"
        ));
    }

    let retained: Vec<&BODomNode> = source
        .nodes
        .iter()
        .filter(|node| profile_retains(node, profile))
        .collect();

    // Semantic text: presentation-only flattening; scope stays in sections.
    let mut fragments = Vec::new();
    let mut source_nodes = Vec::new();
    let mut seen_nodes = BTreeSet::new();
    for node in &retained {
        if let Some(fragment) = retained_text(node) {
            let normalized = normalize_whitespace(&fragment);
            if !normalized.is_empty() {
                fragments.push(normalized);
                let key = node.node_ref.to_json().to_string();
                if seen_nodes.insert(key) {
                    source_nodes.push((*node).node_ref.clone());
                }
            }
        }
    }
    let mut semantic_text = normalize_whitespace(&fragments.join(" "));

    // Sections: one main scoped section; accessible boundaries attach scoped
    // sections at known mounts while inaccessible ones stay explicit.
    let mut section_limitations = Vec::new();
    if profile == PROFILE_HEAL {
        section_limitations.push(
            "HEAL retention: interactive nodes, options, labels, accessibility, and scope; layout-only wrappers stripped".to_string(),
        );
    }
    let main_section = ReductionSection {
        section_id: "section-main".to_string(),
        root: source.root.clone(),
        mount_node: MaybeNodeRef::Missing(Missing::new("not_applicable")),
        semantic_text: semantic_text.clone(),
        source_nodes: source_nodes.clone(),
        limitations: section_limitations,
    };
    let mut sections = vec![main_section];
    let mut reduction_boundaries = Vec::new();
    for boundary in &source.boundaries {
        // Mount association: first iframe mount in document order, else explicit.
        let mount_node = mounts
            .first()
            .map(|mount| {
                if boundary.kind == "frame" {
                    MaybeNodeRef::Present(mount.clone())
                } else {
                    MaybeNodeRef::Missing(Missing::new("not_applicable"))
                }
            })
            .unwrap_or_else(|| {
                if boundary.kind == "frame" {
                    MaybeNodeRef::Missing(Missing::with_detail(
                        "not_observed",
                        "frame mount was not established in this capture",
                    ))
                } else {
                    MaybeNodeRef::Missing(Missing::new("not_applicable"))
                }
            });
        let (child_section_id, child_section) = match (boundary.kind.as_str(), boundary.access.as_str()) {
            ("frame", "complete") | ("frame", "partial") | ("open_shadow", "complete") | ("open_shadow", "partial") => {
                // Accessible roots/frames get scoped sections retaining their
                // actual root scope; flattened text never merges scopes.
                let child_root = match &boundary.root {
                    MaybeRoot::Present(root) => root.clone(),
                    MaybeRoot::Missing(_) => source.root.clone(),
                };
                let child_id = format!("section-{}", boundary.boundary_id);
                let child = ReductionSection {
                    section_id: child_id.clone(),
                    root: child_root,
                    mount_node: mount_node.clone(),
                    semantic_text: String::new(),
                    source_nodes: Vec::new(),
                    limitations: vec![format!(
                        "scoped section for {} {:?} with access {:?}; content from this capture is attached at the known mount",
                        boundary.kind, boundary.boundary_id, boundary.access
                    )],
                };
                (MaybeString::Text(child_id), Some(child))
            }
            _ => {
                // Inaccessible/unobserved roots: explicit boundary only, never
                // an empty complete tree.
                let reason = if boundary.access == "unavailable" {
                    "not_observed"
                } else {
                    "not_applicable"
                };
                (
                    MaybeString::Missing(Missing::with_detail(
                        reason,
                        format!(
                            "no child section: {} {:?} access is {:?}",
                            boundary.kind, boundary.boundary_id, boundary.access
                        ),
                    )),
                    None,
                )
            }
        };
        if let Some(child) = child_section {
            sections.push(child);
        }
        reduction_boundaries.push(ReductionBoundary {
            boundary: boundary.clone(),
            parent_section_id: MaybeString::Text("section-main".to_string()),
            child_section_id,
            mount_node,
            marker: boundary_marker(boundary),
        });
    }

    // Completeness: never overstate.
    let has_incomplete_boundary = source
        .boundaries
        .iter()
        .any(|boundary| boundary.access != "complete");
    let export_partial = source.completeness != "complete";
    let stabilization_partial = stabilization.stabilization_partial;
    let mut completeness = if !export_partial
        && !has_incomplete_boundary
        && !stabilization_partial
        && limitations.is_empty()
        && source_nodes.is_empty()
        && source.boundaries.is_empty()
    {
        // Empty complete capture with no boundaries: complete only when the
        // export itself claims complete and nothing was excluded.
        if excluded_count == 0 {
            "complete".to_string()
        } else {
            limitations.push(
                "excluded-tag filtering removed content; completeness is partial".to_string(),
            );
            "partial".to_string()
        }
    } else if !export_partial && !has_incomplete_boundary && !stabilization_partial {
        if limitations.iter().any(|limitation| {
            limitation.contains("excluded") || limitation.contains("iframe mount")
        }) {
            "partial".to_string()
        } else if source_nodes.is_empty() && excluded_count == 0 {
            "complete".to_string()
        } else if source_nodes.is_empty() {
            limitations.push(
                "no nodes retained under the selected profile; completeness is partial"
                    .to_string(),
            );
            "partial".to_string()
        } else {
            "complete".to_string()
        }
    } else if source_nodes.is_empty() && has_incomplete_boundary {
        // Missing access is not an empty complete tree (RM-C14).
        limitations.push(
            "no observable nodes; inaccessible or unobserved roots are explicit boundaries, not an empty complete tree".to_string(),
        );
        if export_completeness(source) == "unknown" && source.boundaries.iter().all(|b| b.access == "unavailable" || b.access == "unobserved") {
            "unknown".to_string()
        } else {
            "partial".to_string()
        }
    } else {
        if export_partial {
            limitations.push(format!(
                "source export completeness is {:?}; reduction cannot be complete",
                source.completeness
            ));
        }
        if has_incomplete_boundary {
            limitations.push(
                "at least one boundary has incomplete access; see boundary records".to_string(),
            );
        }
        if stabilization_partial {
            limitations.push(
                "stabilization is partial under the selected baseline; see stabilization observation"
                    .to_string(),
            );
        }
        "partial".to_string()
    };
    // Stabilization unknown with retained content stays partial, never complete.
    if completeness == "complete" && stabilization_partial {
        completeness = "partial".to_string();
    }

    let mut reduction = RingmasterReduction {
        record_type: REDUCTION_RECORD_TYPE.to_string(),
        schema_version: REDUCTION_SCHEMA_VERSION.to_string(),
        source_root: source.root.clone(),
        profile: profile.to_string(),
        profile_policy: profile_policy.clone(),
        byte_budget: budget,
        sections,
        boundaries: reduction_boundaries,
        stabilization: stabilization.clone(),
        completeness,
        limitations,
        source_refs: source_refs.to_vec(),
    };

    // Step 10: serialize within the declared limit. The limit includes
    // metadata; reserve room for limitations and boundary records.
    let mut bytes = reduction.to_bytes()?;
    if bytes.len() as u64 > byte_budget {
        // Overflow: shrink semantic text on char boundaries first, then drop
        // scoped sections (never the main section or boundary records), and
        // mark explicit partial output. No silent truncation.
        let overflow_note = format!(
            "reduction of {} bytes exceeds byte_budget {byte_budget}; emitting explicit partial output",
            bytes.len()
        );
        reduction.limitations.push(overflow_note);
        reduction.completeness = "partial".to_string();
        // Iteratively truncate the largest semantic_text until the budget fits.
        for _ in 0..32 {
            bytes = reduction.to_bytes()?;
            if bytes.len() as u64 <= byte_budget {
                break;
            }
            // Find the section with the longest text.
            let mut best: Option<usize> = None;
            let mut best_len = 0usize;
            for (index, section) in reduction.sections.iter().enumerate() {
                if section.semantic_text.len() > best_len {
                    best_len = section.semantic_text.len();
                    best = Some(index);
                }
            }
            let Some(index) = best else { break };
            if best_len == 0 {
                break;
            }
            let over = bytes.len() as u64 - byte_budget;
            // Shrink by at least the overflow plus slack, on a char boundary.
            let shrink = (over as usize).saturating_add(64).min(best_len);
            let new_len = best_len.saturating_sub(shrink);
            let truncated = truncate_to_bytes(&reduction.sections[index].semantic_text, new_len);
            reduction.sections[index].semantic_text = normalize_whitespace(&truncated);
            if !reduction.sections[index]
                .limitations
                .iter()
                .any(|limitation| limitation.contains("truncated to byte_budget"))
            {
                reduction.sections[index].limitations.push(
                    "semantic_text truncated to byte_budget on a UTF-8 char boundary; see reduction limitations"
                        .to_string(),
                );
            }
        }
        // Drop non-main sections if still over budget (boundary records stay).
        while reduction.to_bytes()?.len() as u64 > byte_budget && reduction.sections.len() > 1 {
            let removed = reduction.sections.pop();
            if let Some(section) = removed {
                reduction.limitations.push(format!(
                    "dropped scoped section {:?} to fit byte_budget; its boundary record is retained",
                    section.section_id
                ));
            } else {
                break;
            }
        }
        // Clear main text as a last resort before failing.
        if reduction.to_bytes()?.len() as u64 > byte_budget
            && !reduction.sections.is_empty()
            && !reduction.sections[0].semantic_text.is_empty()
        {
            reduction.sections[0].semantic_text.clear();
            reduction.sections[0].limitations.push(
                "main semantic_text cleared to fit byte_budget; boundary records and limitations retained"
                    .to_string(),
            );
            reduction.limitations.push(
                "main semantic_text cleared to fit byte_budget; output is explicit partial"
                    .to_string(),
            );
        }
        bytes = reduction.to_bytes()?;
        if bytes.len() as u64 > byte_budget {
            return Err(size_failure(format!(
                "reduction metadata of {} bytes exceeds byte_budget {byte_budget}; no silent truncation is permitted",
                bytes.len()
            )));
        }
        // semantic_text was possibly shortened; keep the local binding honest.
        semantic_text = reduction.sections.first().map(|section| section.semantic_text.clone()).unwrap_or_default();
        let _ = semantic_text;
    }

    validate_reduction(&reduction)?;
    Ok(reduction)
}

// ---------------------------------------------------------------------------
// Journal registration
// ---------------------------------------------------------------------------

/// Registers an installed reduction artifact as `artifact_available`.
///
/// The reduction bytes must already be installed durably; this function only
/// appends the registration event under the manifest's journal. The manifest
/// must declare `artifact_available`.
pub fn register_reduction(
    principal: &AuthenticatedPrincipal,
    manifest: &rm_authority::Manifest,
    reduction: &ArtifactReference,
    source_refs: &[EvidenceRef],
    producer_sequence: PositiveInteger,
) -> Result<JournalEnvelope, ConnectorError> {
    rm_authority::authorize_owner(principal, "artifact", "artifact_available")?;
    reduction
        .validate()
        .map_err(|error| invalid(format!("reduction artifact invalid: {}", error.detail)))?;
    let submission = EventSubmission {
        producer_sequence: Some(producer_sequence),
        event_kind: "artifact_available".to_string(),
        event_schema_version: "evidence-kernel/0.1.0".to_string(),
        occurred_at: MaybeTimePoint::Missing(Missing::new("not_observed")),
        payload: EvidencePayload {
            data: json!({"artifact": reduction.to_json()}),
            measurements: Vec::new(),
            evidence_refs: source_refs.to_vec(),
            artifact_refs: vec![reduction.clone()],
        },
    };
    rm_evidence::append_event(principal, manifest, submission)
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Returns the byte ceiling for a profile.
pub fn ceiling_for_profile(profile: &str) -> Result<u64, ConnectorError> {
    match profile {
        PROFILE_EXTRACT => Ok(EXTRACT_CEILING),
        PROFILE_HEAL => Ok(HEAL_CEILING),
        _ => Err(invalid(format!(
            "profile {profile:?} must be EXTRACT or HEAL"
        ))),
    }
}

/// Reduces the live document reachable from `request` to a bounded artifact.
///
/// The call enters native code on the owning thread through `bo.dom_read`,
/// probes rendered-text signatures through mapped `bo.v8_evaluate`, applies
/// the §9.3 transformation under the selected profile, observes stabilization
/// with a permissive policy (unavailable instrumentation yields `unknown` and
/// `stabilization_partial=true`), and installs the closed reduction bytes
/// before returning their immutable reference.
pub fn reduce_document(
    principal: &AuthenticatedPrincipal,
    session: &mut NativeSession,
    request: &BODomRead,
    profile: &str,
    profile_policy: &VersionPin,
    authorization_ref: &EvidenceRef,
    limit: &DurationLimit,
) -> Result<ArtifactReference, ConnectorError> {
    require_enum("profile", profile, &[PROFILE_EXTRACT, PROFILE_HEAL])?;
    validate_version_pin(profile_policy, "profile_policy")?;
    validate_duration_limit(limit, "limit")?;
    authorization_ref
        .validate()
        .map_err(|error| invalid(format!("authorization_ref invalid: {}", error.detail)))?;
    // Authority: the reduction artifact is published under the artifact axis.
    rm_authority::authorize_owner(principal, "artifact", "artifact_available")?;
    let byte_budget = ceiling_for_profile(profile)?;

    // Native traversal on the owner thread; the export is a separate
    // representation and the live DOM is never mutated.
    let dom_out = rm_browseroxide::dom_read(session, request, authorization_ref, limit)?;
    let export = match dom_out.value {
        Some(export) => export,
        None => {
            let detail = match &dom_out.record.error {
                rm_browseroxide::MaybeBOFailure::Present(failure) => format!(
                    "bo.dom_read did not return an export: {} [{}] {}",
                    failure.code, failure.native_entry, failure.detail
                ),
                rm_browseroxide::MaybeBOFailure::Missing(missing) => format!(
                    "bo.dom_read did not return an export: missing reason {:?}",
                    missing.reason
                ),
            };
            if dom_out.record.return_state == "unsupported" {
                return Err(connector_error("UNSUPPORTED_MAPPING", "connector", detail));
            }
            return Err(prerequisite(detail));
        }
    };

    // Stabilization probe: bounded controller observation uses mapped
    // reads/evaluation. Network and mutation instrumentation have no native
    // mapping in this binding, so they stay unknown; text signatures are
    // probed through v8_evaluate and degrade to unknown when unavailable.
    let text_state =
        probe_text_signatures(principal, session, &export.root, authorization_ref, limit);
    let stabilization_policy = StabilizationPolicy::permissive(profile_policy.clone());
    let stabilization = observe_stabilization(
        &stabilization_policy,
        "unknown",
        "unknown",
        text_state.as_str(),
        Vec::new(),
        vec![authorization_ref.clone()],
    )?;

    let source_refs = vec![authorization_ref.clone()];
    let reduction = reduce_export(
        &export,
        profile,
        profile_policy,
        byte_budget,
        &source_refs,
        &stabilization,
    )?;
    let bytes = reduction.to_bytes()?;
    // Install immutable bytes before registration; the reference covers the
    // exact stored bytes.
    let reference = ArtifactReference {
        digest: rm_wire::artifact_digest(&bytes),
        size_bytes: bytes.len() as u64,
        media_type: "application/json".to_string(),
        owner_domain: "artifact".to_string(),
        access: rm_evidence::AccessClass::Public,
    };
    let installed = rm_evidence::install_artifact(principal, &reference, &bytes)?;
    // Verify durability through the evidence boundary before returning.
    let round_trip = rm_evidence::load_artifact(principal, &installed)?;
    if round_trip != bytes {
        return Err(connector_error(
            "INTEGRITY_INCIDENT",
            "integrity",
            "installed reduction bytes do not round-trip",
        ));
    }
    Ok(installed)
}

/// Probes rendered-text signatures through mapped V8 evaluation.
///
/// Returns `satisfied` when a mapped evaluation returns an observable value,
/// otherwise `unknown`. Unavailable instrumentation is never `false`.
fn probe_text_signatures(
    principal: &AuthenticatedPrincipal,
    session: &mut NativeSession,
    root: &BORootRef,
    authorization_ref: &EvidenceRef,
    limit: &DurationLimit,
) -> String {
    // Install a pinned read-only probe script, then evaluate it. Any failure
    // (unmapped primitive, failed evaluation, missing bytes) degrades to
    // unknown with structured limitations downstream.
    let script_bytes = b"stabilization text_signature probe: document.renderedText()";
    let script_reference = ArtifactReference {
        digest: rm_wire::artifact_digest(script_bytes),
        size_bytes: script_bytes.len() as u64,
        media_type: "application/javascript".to_string(),
        owner_domain: "artifact".to_string(),
        access: rm_evidence::AccessClass::Public,
    };
    // Public artifacts are readable through any authenticated handle, so the
    // native binding can load this probe back. An install conflict degrades
    // to unknown rather than failing reduction.
    let script = match rm_evidence::install_artifact(principal, &script_reference, script_bytes)
    {
        Ok(reference) => reference,
        Err(_) => {
            // Identical bytes may already be installed; proceed with the
            // reference and let evaluation report missing bytes as unknown.
            script_reference
        }
    };
    let probe_limit = DurationLimit {
        kind: "exact".to_string(),
        unit: "ms".to_string(),
        value: limit.value.min(1_000.0),
    };
    let request = BOV8Evaluate {
        root: root.clone(),
        script,
        argument: rm_browseroxide::MaybeArtifact::Missing(Missing::new("not_applicable")),
    };
    let outcome = rm_browseroxide::v8_evaluate(session, &request, authorization_ref, &probe_limit);
    let Ok(returned) = outcome else {
        return "unknown".to_string();
    };
    let Some(value) = returned.value else {
        return "unknown".to_string();
    };
    match value.representation.as_str() {
        "text" | "json" => match &value.value {
            rm_browseroxide::MaybeArtifact::Present(_) => "satisfied".to_string(),
            rm_browseroxide::MaybeArtifact::Missing(_) => "unknown".to_string(),
        },
        _ => "unknown".to_string(),
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn whitespace_normalizes() {
        assert_eq!(normalize_whitespace("  a\n\t b  "), "a b");
        assert_eq!(truncate_to_bytes("héllo🌍", 6), "héll");
        // Never splits UTF-8: 7 bytes into "héllo🌍" would cut the emoji.
        let truncated = truncate_to_bytes("héllo🌍world", 7);
        assert!(truncated.len() <= 7);
        assert_eq!(truncated, "héllo");
    }
}

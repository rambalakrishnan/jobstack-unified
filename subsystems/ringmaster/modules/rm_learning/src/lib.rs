//! `rm_learning`: tier-4 verified learning-state selection and commit.
//!
//! Implements seam mapping §7.2 (state domains), §7.3 (ContextPolicy
//! transformation), and §10.5 (learning state) for the single conformance
//! case RM-C43: frozen learning with successful healing retains evidence
//! while the operational cache stays unchanged.
//!
//! Entry points:
//!
//! - [`select_learning_state`] maps a Prepare-time [`ContextPolicy`] to the
//!   learning baseline artifact for one [`SubjectIdentity`]. Browser-state
//!   and learning-state requests stay separate: fresh browser state never
//!   implies fresh learning state. Fresh learning mints an evidenced
//!   empty/new namespace; reuse and frozen read a pinned snapshot;
//!   subject-default is disclosed, never called fresh. Required
//!   unsupported policies reject; best-effort reuse/frozen failures fall
//!   back to a fresh empty namespace (the caller discloses the downgrade).
//!   Realization is observed after Start, never claimed here.
//! - [`commit_verified_learning`] advances one complete immutable learning
//!   snapshot (`revision = previous + 1`, first is 1) only with a pinned
//!   transition policy (`StatePolicy.resource_ref`) and nonempty
//!   [`SupportRefs`] verification evidence. Frozen mode suppresses
//!   operational write-back: healing bytes stay retained but the returned
//!   reference is the baseline unchanged (RM-C43).
//!
//! Pinned storage contract (`learning_state` / `ringmaster-learning/0.1.0`):
//! operational selector entries carry step, target recipe, subject/resolver
//! scope, confidence, hit/heal counts, verification evidence, staleness, and
//! revision; coordinate entries carry step, hash algorithm/version, image
//! digest, perceptual hash, box, coordinate space, geometry evidence, target
//! applicability, creation evidence, hit count, and revision. Imports retain
//! original bytes and import provenance only; counts and confidence never
//! become current-version findings. The encoding is closed: undeclared
//! fields (including Circus Tent filesystem shapes or tentative-model
//! markers) are rejected. There are no in-band nulls; missing values use
//! typed [`Missing`] envelopes. No target is visited, no planner or reset
//! runs, no peer lock is acquired, and no cross-domain transaction occurs.

#![forbid(unsafe_code)]

pub use rm_authority::{AuthenticatedPrincipal, ConnectorError};
pub use rm_evidence::{AccessClass, ArtifactReference, EvidenceRef};
pub use rm_time::{MaybeString, Missing};
pub use rm_wire::Digest;

use serde_json::{Map, Value};
// `rm_leases::validate_lease` and `rm_evidence::commit_owner_effect` are
// verified consumed signatures whose inputs (fenced lease records, journal
// manifests) belong to the caller: lease fencing and journal publication
// stay with the owning authorities, so this crate references the lease
// boundary without invoking it on synthetic inputs.
use rm_leases as _lease_boundary;
use std::collections::BTreeSet;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Pinned learning-state record discriminator.
pub const LEARNING_RECORD_TYPE: &str = "learning_state";
/// Pinned learning-state artifact contract version.
pub const LEARNING_SCHEMA_VERSION: &str = "ringmaster-learning/0.1.0";
/// Artifact owner domain for learning-state snapshots.
pub const LEARNING_OWNER_DOMAIN: &str = "learning";
/// Media type for learning-state snapshots.
pub const LEARNING_MEDIA_TYPE: &str = "application/json";
/// Largest exactly representable integer (§3.1).
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Learning modes (§7.3): browser additionally excludes `frozen`.
pub const LEARNING_MODES: [&str; 5] = [
    "fresh",
    "reuse",
    "frozen",
    "subject_default",
    "not_applicable",
];
/// Browser modes (§7.3): `frozen` is learning-only.
pub const BROWSER_MODES: [&str; 4] = ["fresh", "reuse", "subject_default", "not_applicable"];
/// Policy requirements.
pub const REQUIREMENTS: [&str; 2] = ["required", "best_effort"];
/// Closed Tier-1 strategy vocabulary for target recipes.
pub const RECIPE_STRATEGIES: [&str; 5] = ["css", "xpath", "text", "role", "testid"];
/// Subject revision bases (contract `SubjectIdentity`).
pub const REVISION_BASES: [&str; 4] = [
    "native_revision",
    "source_digest",
    "operator_attestation",
    "unknown",
];

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

fn err(
    code: &str,
    fault_domain: &str,
    detail: String,
    operation_delivery: &str,
) -> ConnectorError {
    ConnectorError {
        kind: "connector_error".to_string(),
        code: code.to_string(),
        fault_domain: fault_domain.to_string(),
        detail,
        operation_delivery: operation_delivery.to_string(),
        retry_guidance: "operator_review".to_string(),
        retry_after: None,
        handle: None,
        evidence_refs: Vec::new(),
    }
}

fn invalid(detail: impl Into<String>) -> ConnectorError {
    err("INVALID_REQUEST", "request", detail.into(), "not_dispatched")
}

fn forbidden(detail: impl Into<String>) -> ConnectorError {
    err("FORBIDDEN", "policy", detail.into(), "not_dispatched")
}

fn not_admitted(detail: impl Into<String>) -> ConnectorError {
    err("NOT_ADMITTED", "policy", detail.into(), "not_dispatched")
}

fn integrity(detail: impl Into<String>) -> ConnectorError {
    err(
        "INTEGRITY_INCIDENT",
        "integrity",
        detail.into(),
        "not_dispatched",
    )
}

fn stale(detail: impl Into<String>) -> ConnectorError {
    err("STALE_CONTEXT", "policy", detail.into(), "not_dispatched")
}

/// Authenticates the caller through the authority boundary.
///
/// Every call binds to an authenticated channel principal; request IDs,
/// digests, and application credentials alone are never sufficient.
fn check_caller(principal: &AuthenticatedPrincipal) -> Result<(), ConnectorError> {
    rm_authority::authorize_owner(principal, "connector", "connector_incident")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Small validators
// ---------------------------------------------------------------------------

fn require_identifier(field: &str, value: &str) -> Result<(), ConnectorError> {
    if value.is_empty() {
        return Err(invalid(format!("{field} must be a nonempty identifier")));
    }
    Ok(())
}

fn require_owner_domain(field: &str, value: &str) -> Result<(), ConnectorError> {
    let valid = !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if !valid {
        return Err(invalid(format!(
            "{field} {value:?} must be a single identity of letters, digits, '_' or '-'"
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

fn check_missing(missing: &Missing) -> Result<(), ConnectorError> {
    if !rm_time::is_valid_reason(&missing.reason) {
        return Err(invalid(format!(
            "missingness reason {:?} is not one of the six kernel null reasons",
            missing.reason
        )));
    }
    if let Some(detail) = &missing.detail {
        if detail.is_empty() {
            return Err(invalid("missingness detail must be nonempty"));
        }
    }
    Ok(())
}

fn check_maybe_string(field: &str, value: &MaybeString) -> Result<(), ConnectorError> {
    match value {
        MaybeString::Text(text) => require_identifier(field, text),
        MaybeString::Missing(missing) => check_missing(missing),
    }
}

fn missing_to_json(missing: &Missing) -> Value {
    let mut map = Map::new();
    map.insert("value".to_string(), Value::Null);
    map.insert("reason".to_string(), Value::String(missing.reason.clone()));
    if let Some(detail) = &missing.detail {
        // `rm_wire` / `rm_time` spell the optional field `Detail`.
        map.insert("Detail".to_string(), Value::String(detail.clone()));
    }
    Value::Object(map)
}

fn missing_from_json(value: &Value, field: &str) -> Result<Missing, ConnectorError> {
    let map = value
        .as_object()
        .ok_or_else(|| invalid(format!("{field} missingness must be a JSON object")))?;
    if map.get("value") != Some(&Value::Null) {
        return Err(invalid(format!("{field} missingness requires \"value\": null")));
    }
    // Accept both `detail` (contract) and `Detail` (wire/time/evidence) spellings.
    for key in map.keys() {
        if key != "value" && key != "reason" && key != "detail" && key != "Detail" {
            return Err(invalid(format!(
                "{field} missingness carries undeclared field {key:?}"
            )));
        }
    }
    let reason = map
        .get("reason")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("{field} missingness requires a string reason")))?;
    let detail = map
        .get("detail")
        .or_else(|| map.get("Detail"))
        .map(|v| {
            v.as_str()
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .ok_or_else(|| invalid(format!("{field} missingness detail must be nonempty")))
        })
        .transpose()?;
    let missing = Missing { reason: reason.to_string(), detail };
    check_missing(&missing)?;
    Ok(missing)
}

fn maybe_string_to_json(value: &MaybeString) -> Value {
    match value {
        MaybeString::Text(text) => Value::String(text.clone()),
        MaybeString::Missing(missing) => missing_to_json(missing),
    }
}

fn maybe_string_from_json(value: &Value, field: &str) -> Result<MaybeString, ConnectorError> {
    match value {
        Value::String(text) => {
            require_identifier(field, text)?;
            Ok(MaybeString::Text(text.clone()))
        }
        Value::Object(map) if map.get("value") == Some(&Value::Null) => {
            Ok(MaybeString::Missing(missing_from_json(value, field)?))
        }
        _ => Err(invalid(format!(
            "{field} must be a nonempty string or a Missing envelope"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Public types (EXPOSES signatures)
// ---------------------------------------------------------------------------

/// Digest or reasoned missingness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaybeDigest {
    /// Present digest.
    Present(Digest),
    /// Reasoned absence.
    Missing(Missing),
}

fn maybe_digest_to_json(value: &MaybeDigest) -> Value {
    match value {
        MaybeDigest::Present(digest) => Value::String(digest.as_str().to_string()),
        MaybeDigest::Missing(missing) => missing_to_json(missing),
    }
}

fn maybe_digest_from_json(value: &Value, field: &str) -> Result<MaybeDigest, ConnectorError> {
    match value {
        Value::String(text) => {
            let digest =
                Digest::parse(text).map_err(|e| invalid(format!("{field} is invalid: {e}")))?;
            Ok(MaybeDigest::Present(digest))
        }
        Value::Object(map) if map.get("value") == Some(&Value::Null) => {
            Ok(MaybeDigest::Missing(missing_from_json(value, field)?))
        }
        _ => Err(invalid(format!(
            "{field} must be a digest string or a Missing envelope"
        ))),
    }
}

/// One configured component of a subject stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentIdentity {
    /// Component identity.
    pub component: String,
    /// Reported version or reasoned missingness.
    pub reported_version: MaybeString,
    /// Build digest or reasoned missingness.
    pub build_digest: MaybeDigest,
    /// Configuration digest or reasoned missingness.
    pub configuration_digest: MaybeDigest,
}

impl ComponentIdentity {
    /// Closed-object JSON projection.
    pub fn to_json(&self) -> Value {
        serde_json::json!({
            "component": self.component,
            "reported_version": maybe_string_to_json(&self.reported_version),
            "build_digest": maybe_digest_to_json(&self.build_digest),
            "configuration_digest": maybe_digest_to_json(&self.configuration_digest),
        })
    }
}

fn component_from_json(value: &Value, field: &str) -> Result<ComponentIdentity, ConnectorError> {
    let map = value
        .as_object()
        .ok_or_else(|| invalid(format!("{field} must be a JSON object")))?;
    ensure_closed(
        map,
        &[
            "component",
            "reported_version",
            "build_digest",
            "configuration_digest",
        ],
        field,
    )?;
    let component = field_str(map, "component", field)?.to_string();
    let reported_version =
        maybe_string_from_json(require_field(map, "reported_version", field)?, &format!("{field} reported_version"))?;
    let build_digest =
        maybe_digest_from_json(require_field(map, "build_digest", field)?, &format!("{field} build_digest"))?;
    let configuration_digest = maybe_digest_from_json(
        require_field(map, "configuration_digest", field)?,
        &format!("{field} configuration_digest"),
    )?;
    let identity = ComponentIdentity {
        component,
        reported_version,
        build_digest,
        configuration_digest,
    };
    validate_component(&identity, field)?;
    Ok(identity)
}

fn validate_component(component: &ComponentIdentity, what: &str) -> Result<(), ConnectorError> {
    require_identifier(&format!("{what} component"), &component.component)?;
    check_maybe_string(
        &format!("{what} reported_version"),
        &component.reported_version,
    )?;
    match &component.build_digest {
        MaybeDigest::Present(digest) => {
            require_digest(&format!("{what} build_digest"), digest)?
        }
        MaybeDigest::Missing(missing) => check_missing(missing)?,
    }
    match &component.configuration_digest {
        MaybeDigest::Present(digest) => {
            require_digest(&format!("{what} configuration_digest"), digest)?
        }
        MaybeDigest::Missing(missing) => check_missing(missing)?,
    }
    Ok(())
}

/// Exact subject scope: one id/version/mode/interface surface.
///
/// A descriptor applies to exactly one scope. A new subject version starts
/// unknown until its own evidence establishes another availability; omission
/// and predecessor descriptors never imply inheritance, presence, or
/// absence (EK-CAPABILITY).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectIdentity {
    /// Subject identity.
    pub subject_id: String,
    /// Subject version. A new version starts unknown on every finding.
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
        serde_json::json!({
            "subject_id": self.subject_id,
            "subject_version": self.subject_version,
            "revision_basis": self.revision_basis,
            "native_revision": maybe_string_to_json(&self.native_revision),
            "configured_mode": self.configured_mode,
            "interface_surface": self.interface_surface,
            "configuration_digest": self.configuration_digest.as_str(),
            "stack": self.stack.iter().map(ComponentIdentity::to_json).collect::<Vec<Value>>(),
        })
    }
}

fn subject_from_json(value: &Value, field: &str) -> Result<SubjectIdentity, ConnectorError> {
    let map = value
        .as_object()
        .ok_or_else(|| invalid(format!("{field} must be a JSON object")))?;
    ensure_closed(
        map,
        &[
            "subject_id",
            "subject_version",
            "revision_basis",
            "native_revision",
            "configured_mode",
            "interface_surface",
            "configuration_digest",
            "stack",
        ],
        field,
    )?;
    let subject_id = field_str(map, "subject_id", field)?.to_string();
    let subject_version = field_str(map, "subject_version", field)?.to_string();
    let revision_basis = field_str(map, "revision_basis", field)?.to_string();
    let native_revision = maybe_string_from_json(
        require_field(map, "native_revision", field)?,
        &format!("{field} native_revision"),
    )?;
    let configured_mode = field_str(map, "configured_mode", field)?.to_string();
    let interface_surface = field_str(map, "interface_surface", field)?.to_string();
    let configuration_digest = Digest::parse(field_str(map, "configuration_digest", field)?)
        .map_err(|e| invalid(format!("{field} configuration_digest is invalid: {e}")))?;
    let stack_value = require_field(map, "stack", field)?;
    let stack_items = stack_value
        .as_array()
        .ok_or_else(|| invalid(format!("{field} stack must be an array")))?;
    let mut stack = Vec::with_capacity(stack_items.len());
    for (index, item) in stack_items.iter().enumerate() {
        stack.push(component_from_json(item, &format!("{field} stack[{index}]"))?);
    }
    let subject = SubjectIdentity {
        subject_id,
        subject_version,
        revision_basis,
        native_revision,
        configured_mode,
        interface_surface,
        configuration_digest,
        stack,
    };
    validate_subject(&subject, field)?;
    Ok(subject)
}

fn validate_subject(subject: &SubjectIdentity, what: &str) -> Result<(), ConnectorError> {
    require_identifier(&format!("{what} subject_id"), &subject.subject_id)?;
    require_identifier(&format!("{what} subject_version"), &subject.subject_version)?;
    if !REVISION_BASES.contains(&subject.revision_basis.as_str()) {
        return Err(invalid(format!(
            "{what} revision_basis {:?} must be one of native_revision, source_digest, operator_attestation, unknown",
            subject.revision_basis
        )));
    }
    check_maybe_string(&format!("{what} native_revision"), &subject.native_revision)?;
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

/// Artifact reference or reasoned missingness (`MaybeArtifact`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaybeArtifact {
    /// Present immutable artifact identity.
    Present(ArtifactReference),
    /// Reasoned absence of requested material.
    Missing(Missing),
}

impl MaybeArtifact {
    /// Closed JSON projection.
    pub fn to_json(&self) -> Value {
        match self {
            MaybeArtifact::Present(reference) => reference.to_json(),
            MaybeArtifact::Missing(missing) => missing_to_json(missing),
        }
    }
}

fn validate_maybe_artifact(value: &MaybeArtifact, what: &str) -> Result<(), ConnectorError> {
    match value {
        MaybeArtifact::Present(reference) => reference
            .validate()
            .map_err(|e| invalid(format!("{what} artifact is invalid: {e}"))),
        MaybeArtifact::Missing(missing) => check_missing(missing),
    }
}

/// A semantic state-policy request, not a guarantee (§7.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatePolicy {
    /// Requested mode.
    pub mode: String,
    /// `required` or `best_effort`.
    pub requirement: String,
    /// Pinned revision/transition-policy binding, or reasoned missingness.
    pub resource_ref: MaybeString,
    /// Requested learning material, or reasoned missingness.
    pub baseline: MaybeArtifact,
}

/// Browser-state plus learning-state policy. The two domains stay separate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextPolicy {
    /// Browser-state request (never `frozen`).
    pub browser_state: StatePolicy,
    /// Learning-state request (`frozen` allowed).
    pub learning_state: StatePolicy,
}

/// Nonempty evidence-reference array (`SupportRefs`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportRefs(pub Vec<EvidenceRef>);

fn validate_state_policy(
    policy: &StatePolicy,
    allowed_modes: &[&str],
    what: &str,
) -> Result<(), ConnectorError> {
    if !allowed_modes.contains(&policy.mode.as_str()) {
        return Err(invalid(format!(
            "{what} mode {:?} must be one of {}",
            policy.mode,
            allowed_modes.join(", ")
        )));
    }
    if !REQUIREMENTS.contains(&policy.requirement.as_str()) {
        return Err(invalid(format!(
            "{what} requirement {:?} must be required or best_effort",
            policy.requirement
        )));
    }
    check_maybe_string(&format!("{what} resource_ref"), &policy.resource_ref)?;
    validate_maybe_artifact(&policy.baseline, &format!("{what} baseline"))?;
    Ok(())
}

fn validate_context_policy(policy: &ContextPolicy) -> Result<(), ConnectorError> {
    validate_state_policy(&policy.browser_state, &BROWSER_MODES, "browser_state")?;
    validate_state_policy(&policy.learning_state, &LEARNING_MODES, "learning_state")?;
    Ok(())
}

fn validate_support_refs(verification: &SupportRefs) -> Result<(), ConnectorError> {
    if verification.0.is_empty() {
        return Err(invalid(
            "verification requires at least one evidence reference",
        ));
    }
    let mut seen = BTreeSet::new();
    for (index, reference) in verification.0.iter().enumerate() {
        reference
            .validate()
            .map_err(|e| invalid(format!("verification[{index}] is invalid: {e}")))?;
        let key = serde_json::to_string(&reference.to_json())
            .map_err(|e| invalid(format!("verification[{index}] cannot be hashed: {e}")))?;
        if !seen.insert(key) {
            return Err(invalid(format!(
                "verification[{index}] duplicates an earlier evidence reference"
            )));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// JSON field helpers
// ---------------------------------------------------------------------------

fn ensure_closed(
    map: &Map<String, Value>,
    allowed: &[&str],
    what: &str,
) -> Result<(), ConnectorError> {
    for key in map.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(forbidden(format!(
                "{what} carries undeclared field {key:?}: the pinned learning contract is closed"
            )));
        }
    }
    for field in allowed {
        if !map.contains_key(*field) {
            return Err(invalid(format!(
                "{what} is missing required field {field:?}"
            )));
        }
    }
    Ok(())
}

fn require_field<'a>(
    map: &'a Map<String, Value>,
    field: &str,
    what: &str,
) -> Result<&'a Value, ConnectorError> {
    map.get(field)
        .ok_or_else(|| invalid(format!("{what} is missing required field {field:?}")))
}

fn field_str<'a>(
    map: &'a Map<String, Value>,
    field: &str,
    what: &str,
) -> Result<&'a str, ConnectorError> {
    require_field(map, field, what)?
        .as_str()
        .ok_or_else(|| invalid(format!("{what} field {field:?} must be a string")))
}

fn field_u64(map: &Map<String, Value>, field: &str, what: &str) -> Result<u64, ConnectorError> {
    let value = require_field(map, field, what)?;
    match value {
        Value::Number(number) => number.as_u64().ok_or_else(|| {
            invalid(format!("{what} field {field:?} must be an unsigned integer"))
        }),
        Value::Object(inner) if inner.get("value") == Some(&Value::Null) => Err(invalid(
            format!("{what} field {field:?} must be present: counts use zero, never missingness"),
        )),
        _ => Err(invalid(format!(
            "{what} field {field:?} must be an unsigned integer"
        ))),
    }
}

fn field_bool(map: &Map<String, Value>, field: &str, what: &str) -> Result<bool, ConnectorError> {
    require_field(map, field, what)?
        .as_bool()
        .ok_or_else(|| invalid(format!("{what} field {field:?} must be a boolean")))
}

fn evidence_ref_from_json(value: &Value, field: &str) -> Result<EvidenceRef, ConnectorError> {
    let reference = EvidenceRef::from_json(value)
        .map_err(|e| invalid(format!("{field} is invalid: {e}")))?;
    reference
        .validate()
        .map_err(|e| invalid(format!("{field} is invalid: {e}")))?;
    Ok(reference)
}

// ---------------------------------------------------------------------------
// Structural discipline (mirrors rm_wire: no duplicate keys, no non-finite
// literals, no bare nulls outside Missing envelopes)
// ---------------------------------------------------------------------------

fn reject_nonfinite_literals(text: &str) -> Result<(), ConnectorError> {
    const TOKENS: &[&str] = &["NaN", "Infinity", "-Infinity", "inf", "-inf", "nan"];
    let bytes = text.as_bytes();
    let mut index = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        if byte == b'"' {
            in_string = true;
            index += 1;
            continue;
        }
        if byte.is_ascii_alphabetic() || byte == b'-' {
            for token in TOKENS {
                if text[index..].starts_with(token) {
                    let after = index + token.len();
                    let boundary = after >= bytes.len()
                        || !(bytes[after].is_ascii_alphanumeric() || bytes[after] == b'_');
                    if boundary {
                        return Err(invalid(format!(
                            "non-finite number literal {token:?} is rejected"
                        )));
                    }
                }
            }
        }
        index += 1;
    }
    Ok(())
}

fn check_duplicate_keys(text: &str) -> Result<(), ConnectorError> {
    use std::collections::HashSet;
    let bytes = text.as_bytes();
    let mut index = 0usize;
    let mut stack: Vec<HashSet<String>> = Vec::new();
    let mut in_string = false;
    let mut escaped = false;
    let mut current = String::new();
    while index < bytes.len() {
        let byte = bytes[index];
        if in_string {
            if escaped {
                current.push(byte as char);
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
                current.push('\\');
            } else if byte == b'"' {
                in_string = false;
                let mut look = index + 1;
                while look < bytes.len()
                    && matches!(bytes[look], b' ' | b'\t' | b'\n' | b'\r')
                {
                    look += 1;
                }
                if look < bytes.len() && bytes[look] == b':' {
                    if let Some(level) = stack.last_mut() {
                        if !level.insert(current.clone()) {
                            return Err(invalid(format!(
                                "duplicate mapping key {current:?} is rejected"
                            )));
                        }
                    }
                }
                current.clear();
            } else {
                current.push(byte as char);
            }
            index += 1;
            continue;
        }
        match byte {
            b'"' => {
                in_string = true;
                current.clear();
            }
            b'{' => stack.push(HashSet::new()),
            b'}' => {
                stack.pop();
            }
            _ => {}
        }
        index += 1;
    }
    Ok(())
}

fn check_no_bare_null(value: &Value, path: &str) -> Result<(), ConnectorError> {
    match value {
        Value::Null => Err(invalid(format!("bare null at {path}: use a Missing envelope"))),
        Value::Object(map) => {
            if map.get("value") == Some(&Value::Null) {
                missing_from_json(value, path)?;
                return Ok(());
            }
            for (key, item) in map {
                check_no_bare_null(item, &format!("{path}.{key}"))?;
            }
            Ok(())
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                check_no_bare_null(item, &format!("{path}[{index}]"))?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// Pinned learning-state encoding
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct ParsedSelector {
    step_id: String,
    target_strategy: String,
    target_query: String,
    confidence: Option<f64>,
    hit_count: u64,
    heal_count: u64,
    verification_refs: Vec<EvidenceRef>,
    stale: bool,
    revision: u64,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct ParsedCoordinate {
    step_id: String,
    hash_algorithm: String,
    image_digest: Digest,
    perceptual_hash: String,
    hit_count: u64,
    revision: u64,
}

#[derive(Debug, Clone)]
struct ParsedImport {
    source_digest: Digest,
    provenance: String,
    byte_length: u64,
}

#[derive(Debug, Clone)]
struct ParsedLearning {
    subject_json: Value,
    revision: u64,
    selectors: Vec<ParsedSelector>,
    coordinates: Vec<ParsedCoordinate>,
    imports: Vec<ParsedImport>,
}

fn parse_selector(value: &Value, index: usize) -> Result<ParsedSelector, ConnectorError> {
    let what = format!("selector_entries[{index}]");
    let map = value
        .as_object()
        .ok_or_else(|| invalid(format!("{what} must be a JSON object")))?;
    ensure_closed(
        map,
        &[
            "step_id",
            "target_recipe",
            "subject_scope",
            "resolver_scope",
            "confidence",
            "hit_count",
            "heal_count",
            "verification_refs",
            "stale",
            "learning_revision",
        ],
        &what,
    )?;
    let step_id = field_str(map, "step_id", &what)?.to_string();
    require_identifier(&format!("{what} step_id"), &step_id)?;
    let recipe_value = require_field(map, "target_recipe", &what)?;
    let recipe_map = recipe_value
        .as_object()
        .ok_or_else(|| invalid(format!("{what} target_recipe must be a JSON object")))?;
    ensure_closed(recipe_map, &["strategy", "query"], &format!("{what} target_recipe"))?;
    let strategy = field_str(recipe_map, "strategy", &format!("{what} target_recipe"))?;
    if !RECIPE_STRATEGIES.contains(&strategy) {
        return Err(invalid(format!(
            "{what} target_recipe strategy {strategy:?} must be one of css, xpath, text, role, testid"
        )));
    }
    let query = field_str(recipe_map, "query", &format!("{what} target_recipe"))?;
    if query.is_empty() {
        return Err(invalid(format!(
            "{what} target_recipe query must be nonempty"
        )));
    }
    let subject_scope = field_str(map, "subject_scope", &what)?;
    require_identifier(&format!("{what} subject_scope"), subject_scope)?;
    let resolver_scope = field_str(map, "resolver_scope", &what)?;
    require_identifier(&format!("{what} resolver_scope"), resolver_scope)?;
    // Confidence is a finite 0..=1 number or a reasoned Missing envelope.
    // Low confidence (< 0.5) is an operational review setting, never a
    // capability judgment: it is accepted when otherwise evidenced.
    let confidence_value = require_field(map, "confidence", &what)?;
    let confidence = match confidence_value {
        Value::Number(number) => {
            let value = number.as_f64().ok_or_else(|| {
                invalid(format!("{what} confidence must be a finite number from zero through one"))
            })?;
            if !value.is_finite() || value < 0.0 || value > 1.0 {
                return Err(invalid(format!(
                    "{what} confidence {value:?} must be finite from zero through one"
                )));
            }
            Some(value)
        }
        Value::Object(inner) if inner.get("value") == Some(&Value::Null) => {
            missing_from_json(confidence_value, &format!("{what} confidence"))?;
            None
        }
        _ => {
            return Err(invalid(format!(
                "{what} confidence must be a finite number or a Missing envelope"
            )))
        }
    };
    let hit_count = field_u64(map, "hit_count", &what)?;
    let heal_count = field_u64(map, "heal_count", &what)?;
    if hit_count > MAX_SAFE_INTEGER || heal_count > MAX_SAFE_INTEGER {
        return Err(invalid(format!(
            "{what} counts exceed {MAX_SAFE_INTEGER}"
        )));
    }
    let refs_value = require_field(map, "verification_refs", &what)?;
    let refs_items = refs_value
        .as_array()
        .ok_or_else(|| invalid(format!("{what} verification_refs must be an array")))?;
    let mut verification_refs = Vec::with_capacity(refs_items.len());
    for (ref_index, item) in refs_items.iter().enumerate() {
        verification_refs.push(evidence_ref_from_json(
            item,
            &format!("{what} verification_refs[{ref_index}]"),
        )?);
    }
    // Counts and confidence never become current-version findings without
    // verification evidence: tentative model candidates and imported
    // predecessor counters cannot be promoted by copying numbers alone.
    if (hit_count > 0 || heal_count > 0 || confidence.is_some()) && verification_refs.is_empty()
    {
        return Err(forbidden(format!(
            "{what} carries counts/confidence without verification evidence: tentative or imported counters are never promoted"
        )));
    }
    let stale = field_bool(map, "stale", &what)?;
    let revision = field_u64(map, "learning_revision", &what)?;
    Ok(ParsedSelector {
        step_id,
        target_strategy: strategy.to_string(),
        target_query: query.to_string(),
        confidence,
        hit_count,
        heal_count,
        verification_refs,
        stale,
        revision,
    })
}

fn parse_coordinate(value: &Value, index: usize) -> Result<ParsedCoordinate, ConnectorError> {
    let what = format!("coordinate_entries[{index}]");
    let map = value
        .as_object()
        .ok_or_else(|| invalid(format!("{what} must be a JSON object")))?;
    ensure_closed(
        map,
        &[
            "step_id",
            "hash_algorithm",
            "hash_version",
            "image_digest",
            "perceptual_hash",
            "box",
            "coordinate_space",
            "geometry_evidence",
            "target_applicability",
            "creation_evidence",
            "hit_count",
            "learning_revision",
        ],
        &what,
    )?;
    let step_id = field_str(map, "step_id", &what)?.to_string();
    require_identifier(&format!("{what} step_id"), &step_id)?;
    let hash_algorithm = field_str(map, "hash_algorithm", &what)?.to_string();
    require_identifier(&format!("{what} hash_algorithm"), &hash_algorithm)?;
    let hash_version = field_str(map, "hash_version", &what)?;
    require_identifier(&format!("{what} hash_version"), hash_version)?;
    let image_digest = Digest::parse(field_str(map, "image_digest", &what)?)
        .map_err(|e| invalid(format!("{what} image_digest is invalid: {e}")))?;
    let perceptual_hash = field_str(map, "perceptual_hash", &what)?.to_string();
    require_identifier(&format!("{what} perceptual_hash"), &perceptual_hash)?;
    let box_value = require_field(map, "box", &what)?;
    let box_map = box_value
        .as_object()
        .ok_or_else(|| invalid(format!("{what} box must be a JSON object")))?;
    ensure_closed(box_map, &["x", "y", "width", "height"], &format!("{what} box"))?;
    for field in ["x", "y", "width", "height"] {
        let number = require_field(box_map, field, &format!("{what} box"))?
            .as_f64()
            .ok_or_else(|| invalid(format!("{what} box.{field} must be a number")))?;
        if !number.is_finite() {
            return Err(invalid(format!("{what} box.{field} must be finite")));
        }
        match field {
            "x" | "y" => {
                if number < 0.0 {
                    return Err(invalid(format!("{what} box.{field} must be nonnegative")));
                }
            }
            _ => {
                if number <= 0.0 {
                    return Err(invalid(format!("{what} box.{field} must be positive")));
                }
            }
        }
    }
    // Missing geometry is never zero or scale one: every field above is
    // required and validated.
    let coordinate_space = field_str(map, "coordinate_space", &what)?;
    require_identifier(&format!("{what} coordinate_space"), coordinate_space)?;
    let geometry_value = require_field(map, "geometry_evidence", &what)?;
    let geometry_items = geometry_value
        .as_array()
        .ok_or_else(|| invalid(format!("{what} geometry_evidence must be an array")))?;
    // A dHash match is image similarity only. Reuse requires compatible
    // geometry evidence plus target applicability; invalid matches never
    // authorize action. Geometry evidence is therefore always required.
    if geometry_items.is_empty() {
        return Err(forbidden(format!(
            "{what} lacks geometry evidence: perceptual-hash similarity alone never authorizes reuse"
        )));
    }
    for (ref_index, item) in geometry_items.iter().enumerate() {
        evidence_ref_from_json(item, &format!("{what} geometry_evidence[{ref_index}]"))?;
    }
    let target_applicability = field_str(map, "target_applicability", &what)?;
    require_identifier(
        &format!("{what} target_applicability"),
        target_applicability,
    )?;
    evidence_ref_from_json(
        require_field(map, "creation_evidence", &what)?,
        &format!("{what} creation_evidence"),
    )?;
    let hit_count = field_u64(map, "hit_count", &what)?;
    if hit_count > MAX_SAFE_INTEGER {
        return Err(invalid(format!("{what} hit_count exceeds {MAX_SAFE_INTEGER}")));
    }
    let revision = field_u64(map, "learning_revision", &what)?;
    Ok(ParsedCoordinate {
        step_id,
        hash_algorithm,
        image_digest,
        perceptual_hash,
        hit_count,
        revision,
    })
}

fn parse_import(value: &Value, index: usize) -> Result<ParsedImport, ConnectorError> {
    let what = format!("imports[{index}]");
    let map = value
        .as_object()
        .ok_or_else(|| invalid(format!("{what} must be a JSON object")))?;
    // Imports retain original bytes and import provenance only. Counts and
    // confidence are undeclared here by construction: they cannot become
    // current-version findings through an import record.
    ensure_closed(map, &["source_digest", "provenance", "byte_length"], &what)?;
    let source_digest = Digest::parse(field_str(map, "source_digest", &what)?)
        .map_err(|e| invalid(format!("{what} source_digest is invalid: {e}")))?;
    let provenance = field_str(map, "provenance", &what)?.to_string();
    if !provenance.starts_with("imported_") {
        return Err(forbidden(format!(
            "{what} provenance {provenance:?} must be a marked import reference"
        )));
    }
    let byte_length = field_u64(map, "byte_length", &what)?;
    Ok(ParsedImport {
        source_digest,
        provenance,
        byte_length,
    })
}

fn parse_learning_state(bytes: &[u8]) -> Result<ParsedLearning, ConnectorError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|e| invalid(format!("learning state is not utf-8: {e}")))?;
    // The native storage contract is the pinned artifact below, never the
    // Circus Tent filesystem schema.
    if text.to_ascii_lowercase().contains("circus") {
        return Err(forbidden(
            "learning state carries Circus Tent cache material: Ringmaster's native storage contract is the pinned learning-state artifact",
        ));
    }
    reject_nonfinite_literals(text)?;
    check_duplicate_keys(text)?;
    let value: Value =
        serde_json::from_str(text).map_err(|e| invalid(format!("learning state is not JSON: {e}")))?;
    check_no_bare_null(&value, "$")?;
    let map = value
        .as_object()
        .ok_or_else(|| invalid("learning state must be a JSON object"))?;
    ensure_closed(
        map,
        &[
            "record_type",
            "schema_version",
            "subject",
            "learning_revision",
            "selector_entries",
            "coordinate_entries",
            "imports",
        ],
        "learning state",
    )?;
    let record_type = field_str(map, "record_type", "learning state")?;
    if record_type != LEARNING_RECORD_TYPE {
        return Err(invalid(format!(
            "learning state record_type {record_type:?} must be {LEARNING_RECORD_TYPE:?}"
        )));
    }
    let schema_version = field_str(map, "schema_version", "learning state")?;
    if schema_version != LEARNING_SCHEMA_VERSION {
        return Err(invalid(format!(
            "learning state schema_version {schema_version:?} must be {LEARNING_SCHEMA_VERSION:?}"
        )));
    }
    let subject_value = require_field(map, "subject", "learning state")?;
    let subject = subject_from_json(subject_value, "learning state subject")?;
    let revision = field_u64(map, "learning_revision", "learning state")?;
    if revision == 0 || revision > MAX_SAFE_INTEGER {
        return Err(invalid(format!(
            "learning_revision {revision} is outside 1..={MAX_SAFE_INTEGER}"
        )));
    }
    let selectors_value = require_field(map, "selector_entries", "learning state")?;
    let selectors_items = selectors_value
        .as_array()
        .ok_or_else(|| invalid("learning state selector_entries must be an array"))?;
    let mut selectors = Vec::with_capacity(selectors_items.len());
    for (index, item) in selectors_items.iter().enumerate() {
        let entry = parse_selector(item, index)?;
        if entry.revision != revision {
            return Err(invalid(format!(
                "selector_entries[{index}] learning_revision {} does not match snapshot revision {revision}",
                entry.revision
            )));
        }
        selectors.push(entry);
    }
    let coordinates_value = require_field(map, "coordinate_entries", "learning state")?;
    let coordinates_items = coordinates_value
        .as_array()
        .ok_or_else(|| invalid("learning state coordinate_entries must be an array"))?;
    let mut coordinates = Vec::with_capacity(coordinates_items.len());
    for (index, item) in coordinates_items.iter().enumerate() {
        let entry = parse_coordinate(item, index)?;
        if entry.revision != revision {
            return Err(invalid(format!(
                "coordinate_entries[{index}] learning_revision {} does not match snapshot revision {revision}",
                entry.revision
            )));
        }
        coordinates.push(entry);
    }
    let imports_value = require_field(map, "imports", "learning state")?;
    let imports_items = imports_value
        .as_array()
        .ok_or_else(|| invalid("learning state imports must be an array"))?;
    let mut imports = Vec::with_capacity(imports_items.len());
    for (index, item) in imports_items.iter().enumerate() {
        imports.push(parse_import(item, index)?);
    }
    Ok(ParsedLearning {
        subject_json: subject.to_json(),
        revision,
        selectors,
        coordinates,
        imports,
    })
}

fn empty_learning_bytes(subject: &SubjectIdentity) -> Result<Vec<u8>, ConnectorError> {
    let value = serde_json::json!({
        "record_type": LEARNING_RECORD_TYPE,
        "schema_version": LEARNING_SCHEMA_VERSION,
        "subject": subject.to_json(),
        "learning_revision": 1,
        "selector_entries": [],
        "coordinate_entries": [],
        "imports": [],
    });
    serde_json::to_vec(&value)
        .map_err(|e| invalid(format!("empty learning state cannot be serialized: {e}")))
}

fn learning_reference(bytes: &[u8]) -> Result<ArtifactReference, ConnectorError> {
    require_owner_domain("artifact owner_domain", LEARNING_OWNER_DOMAIN)?;
    Ok(ArtifactReference {
        digest: rm_wire::artifact_digest(bytes),
        size_bytes: bytes.len() as u64,
        media_type: LEARNING_MEDIA_TYPE.to_string(),
        owner_domain: LEARNING_OWNER_DOMAIN.to_string(),
        access: AccessClass::Public,
    })
}

fn install_empty(
    principal: &AuthenticatedPrincipal,
    subject: &SubjectIdentity,
) -> Result<ArtifactReference, ConnectorError> {
    let bytes = empty_learning_bytes(subject)?;
    let reference = learning_reference(&bytes)?;
    rm_evidence::install_artifact(principal, &reference, &bytes)
}

fn check_learning_reference(
    reference: &ArtifactReference,
    what: &str,
) -> Result<(), ConnectorError> {
    reference
        .validate()
        .map_err(|e| invalid(format!("{what} is invalid: {e}")))?;
    if reference.owner_domain != LEARNING_OWNER_DOMAIN {
        return Err(invalid(format!(
            "{what} owner_domain {:?} must be {LEARNING_OWNER_DOMAIN:?}: learning snapshots commit under the learning owner",
            reference.owner_domain
        )));
    }
    if reference.media_type != LEARNING_MEDIA_TYPE {
        return Err(invalid(format!(
            "{what} media_type {:?} must be {LEARNING_MEDIA_TYPE:?}",
            reference.media_type
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Entry points (EXPOSES)
// ---------------------------------------------------------------------------

/// Selects the learning baseline artifact for one subject under a
/// Prepare-time context policy.
///
/// Browser-state and learning-state requests remain separate: the browser
/// policy is validated for shape only and never consulted for the learning
/// selection, so fresh browser state never implies fresh learning state.
/// Fresh learning mints an evidenced empty/new namespace (revision 1);
/// reuse and frozen read the pinned snapshot; subject-default returns the
/// cited material or an empty default (disclosed, never called fresh).
/// Required failures reject; best-effort reuse/frozen/subject-default
/// failures fall back to a fresh empty namespace for the requested
/// subject — the caller discloses the downgrade and realization is
/// observed after Start, never claimed here.
///
/// No target is visited, no authentication is tested, no context is reset,
/// and no planner runs: this is a local mapping over retained artifacts.
pub fn select_learning_state(
    principal: &AuthenticatedPrincipal,
    policy: &ContextPolicy,
    subject: &SubjectIdentity,
) -> Result<ArtifactReference, ConnectorError> {
    check_caller(principal)?;
    validate_subject(subject, "subject")?;
    validate_context_policy(policy)?;
    // EXT-STATE-POLICY: `browser_state` is intentionally never read below.
    let learning = &policy.learning_state;
    let best_effort = learning.requirement == "best_effort";

    match learning.mode.as_str() {
        "fresh" => {
            if !matches!(learning.baseline, MaybeArtifact::Missing(_)) {
                return Err(invalid(
                    "fresh learning uses an evidenced empty/new namespace and pins no prior baseline",
                ));
            }
            if !matches!(learning.resource_ref, MaybeString::Missing(_)) {
                return Err(invalid(
                    "fresh learning carries no pinned revision binding",
                ));
            }
            install_empty(principal, subject)
        }
        "reuse" | "frozen" => {
            let mode = learning.mode.clone();
            let pinned = match &learning.baseline {
                MaybeArtifact::Present(reference) => reference.clone(),
                MaybeArtifact::Missing(_) => {
                    return Err(not_admitted(format!(
                        "{mode} learning requires a pinned baseline artifact"
                    )))
                }
            };
            let pin = match &learning.resource_ref {
                MaybeString::Text(text) => text.clone(),
                MaybeString::Missing(_) => {
                    return Err(not_admitted(format!(
                        "{mode} learning requires a pinned revision binding"
                    )))
                }
            };
            match select_pinned(principal, &pinned, &pin, subject) {
                Ok(reference) => Ok(reference),
                Err(error) if best_effort && is_fallbackable(&error) => {
                    install_empty(principal, subject)
                }
                Err(error) => Err(error),
            }
        }
        "subject_default" => match &learning.baseline {
            MaybeArtifact::Missing(_) => install_empty(principal, subject),
            MaybeArtifact::Present(reference) => {
                match load_and_match_subject(principal, reference, subject) {
                    Ok(parsed) => {
                        let _ = parsed;
                        Ok(reference.clone())
                    }
                    Err(error) if best_effort && is_fallbackable(&error) => {
                        install_empty(principal, subject)
                    }
                    Err(error) => Err(error),
                }
            }
        },
        "not_applicable" => {
            if !matches!(learning.baseline, MaybeArtifact::Missing(_)) {
                return Err(invalid(
                    "not_applicable learning carries no baseline material",
                ));
            }
            if !matches!(learning.resource_ref, MaybeString::Missing(_)) {
                return Err(invalid(
                    "not_applicable learning carries no pinned binding",
                ));
            }
            install_empty(principal, subject)
        }
        other => Err(invalid(format!("learning_state mode {other:?} is unsupported"))),
    }
}

fn is_fallbackable(error: &ConnectorError) -> bool {
    matches!(
        error.code.as_str(),
        "NOT_ADMITTED" | "NOT_FOUND" | "STALE_CONTEXT" | "INVALID_REQUEST" | "FORBIDDEN"
    )
}

fn load_and_match_subject(
    principal: &AuthenticatedPrincipal,
    reference: &ArtifactReference,
    subject: &SubjectIdentity,
) -> Result<ParsedLearning, ConnectorError> {
    check_learning_reference(reference, "learning baseline")?;
    let bytes = rm_evidence::load_artifact(principal, reference)?;
    let parsed = parse_learning_state(&bytes)?;
    if parsed.subject_json != subject.to_json() {
        return Err(stale(
            "learning baseline names a different subject scope: new subject versions start unknown and never inherit predecessor findings",
        ));
    }
    Ok(parsed)
}

fn select_pinned(
    principal: &AuthenticatedPrincipal,
    reference: &ArtifactReference,
    pin: &str,
    subject: &SubjectIdentity,
) -> Result<ArtifactReference, ConnectorError> {
    let parsed = load_and_match_subject(principal, reference, subject)?;
    if pin != parsed.revision.to_string() {
        return Err(stale(format!(
            "pinned revision binding {pin:?} does not match baseline revision {}",
            parsed.revision
        )));
    }
    Ok(reference.clone())
}

/// Commits one verified learning successor snapshot.
///
/// The baseline and candidate bytes must already be durably installed; the
/// candidate must be a complete snapshot with `revision = baseline + 1`
/// for the identical subject scope (OWD-REVISION, EK-CAPABILITY).
/// Identical digests are idempotent; equal revisions with different bytes
/// are an integrity conflict; stale or gapped revisions cannot commit.
/// Counts advance monotonically, stale clearing requires verification
/// evidence, imports carry forward, and tentative or imported counters
/// are never promoted without verification evidence. A pinned transition
/// policy (`policy.resource_ref`) and nonempty [`SupportRefs`]
/// verification are mandatory.
///
/// Frozen mode (RM-C43) suppresses operational write-back: healing bytes
/// stay retained and verified, but the returned reference is the baseline
/// unchanged.
///
/// All validation precedes the return; nothing is acknowledged before the
/// bytes it cites are durable. No peer lock, shared-database write, or
/// cross-domain transaction occurs.
pub fn commit_verified_learning(
    principal: &AuthenticatedPrincipal,
    baseline: &ArtifactReference,
    candidate: &ArtifactReference,
    verification: &SupportRefs,
    policy: &StatePolicy,
) -> Result<ArtifactReference, ConnectorError> {
    check_caller(principal)?;
    validate_state_policy(policy, &LEARNING_MODES, "policy")?;
    validate_support_refs(verification)?;
    // A pinned transition policy fully defines confidence adjustment,
    // missing-prior handling, count increments, stale clearing, and review
    // thresholds before use. Presence of the pin is enforced here; the
    // pinned policy's exact content is owned by the admitting authority.
    let pin = match &policy.resource_ref {
        MaybeString::Text(text) => text.clone(),
        MaybeString::Missing(_) => {
            return Err(forbidden(
                "learning commit requires a pinned transition policy binding",
            ))
        }
    };
    if policy.mode == "not_applicable" {
        return Err(not_admitted(
            "learning commit is not applicable under a not_applicable policy",
        ));
    }
    if let MaybeArtifact::Present(pinned) = &policy.baseline {
        if pinned.digest != baseline.digest
            || pinned.size_bytes != baseline.size_bytes
            || pinned.media_type != baseline.media_type
            || pinned.owner_domain != baseline.owner_domain
            || pinned.access != baseline.access
        {
            return Err(stale(
                "policy baseline does not match the cited operational baseline",
            ));
        }
    }
    check_learning_reference(baseline, "baseline")?;
    check_learning_reference(candidate, "candidate")?;
    let baseline_bytes = rm_evidence::load_artifact(principal, baseline)?;
    let candidate_bytes = rm_evidence::load_artifact(principal, candidate)?;
    let parsed_baseline = parse_learning_state(&baseline_bytes)?;

    if policy.mode == "frozen" {
        // RM-C43: frozen learning reads the pinned snapshot and suppresses
        // operational write-back. Healing evidence is verified and stays
        // retained; the operational cache is returned unchanged.
        if pin != parsed_baseline.revision.to_string() {
            return Err(stale(format!(
                "pinned revision binding {pin:?} does not match frozen baseline revision {}",
                parsed_baseline.revision
            )));
        }
        let parsed_candidate = parse_learning_state(&candidate_bytes)?;
        if parsed_candidate.subject_json != parsed_baseline.subject_json {
            return Err(forbidden(
                "frozen healing names a different subject scope: cross-subject promotion is rejected",
            ));
        }
        return Ok(baseline.clone());
    }

    // Identical retries are idempotent.
    if candidate.digest == baseline.digest {
        return Ok(baseline.clone());
    }
    let parsed_candidate = parse_learning_state(&candidate_bytes)?;
    if parsed_candidate.subject_json != parsed_baseline.subject_json {
        return Err(forbidden(
            "candidate names a different subject scope: learning never crosses subject versions, modes, or interfaces",
        ));
    }
    if parsed_candidate.revision == parsed_baseline.revision {
        return Err(integrity(format!(
            "candidate carries revision {} with different bytes than the baseline: the key (entity, domain, revision) identifies exactly one content digest",
            parsed_baseline.revision
        )));
    }
    if parsed_candidate.revision != parsed_baseline.revision + 1 {
        return Err(stale(format!(
            "candidate revision {} is not baseline revision {} + 1",
            parsed_candidate.revision, parsed_baseline.revision
        )));
    }
    if pin != parsed_baseline.revision.to_string() {
        return Err(stale(format!(
            "pinned revision binding {pin:?} does not match baseline revision {}",
            parsed_baseline.revision
        )));
    }
    check_count_monotonicity(&parsed_baseline, &parsed_candidate)?;
    check_import_carryforward(&parsed_baseline, &parsed_candidate)?;
    Ok(candidate.clone())
}

fn selector_key(entry: &ParsedSelector) -> (String, String, String) {
    (
        entry.step_id.clone(),
        entry.target_strategy.clone(),
        entry.target_query.clone(),
    )
}

fn check_count_monotonicity(
    baseline: &ParsedLearning,
    candidate: &ParsedLearning,
) -> Result<(), ConnectorError> {
    use std::collections::BTreeMap;
    let mut prior: BTreeMap<(String, String, String), &ParsedSelector> = BTreeMap::new();
    for entry in &baseline.selectors {
        prior.insert(selector_key(entry), entry);
    }
    for entry in &candidate.selectors {
        let key = selector_key(entry);
        if let Some(old) = prior.get(&key) {
            if entry.hit_count < old.hit_count || entry.heal_count < old.heal_count {
                return Err(invalid(format!(
                    "selector {:?} counts decrease ({} / {} to {} / {}): the pinned transition policy advances counts monotonically",
                    key, old.hit_count, old.heal_count, entry.hit_count, entry.heal_count
                )));
            }
            // Stale clearing requires verification evidence; marking stale
            // is conservative and needs none.
            if old.stale && !entry.stale && entry.verification_refs.is_empty() {
                return Err(forbidden(format!(
                    "selector {:?} clears staleness without verification evidence",
                    key
                )));
            }
            // Confidence adjustments ride on verification evidence, already
            // enforced per entry plus the global SupportRefs.
            let _ = (&old.confidence, &entry.confidence);
        }
    }
    let mut prior_coords: BTreeMap<(String, String), &ParsedCoordinate> = BTreeMap::new();
    for entry in &baseline.coordinates {
        prior_coords.insert(
            (
                entry.step_id.clone(),
                entry.image_digest.as_str().to_string(),
            ),
            entry,
        );
    }
    for entry in &candidate.coordinates {
        let key = (
            entry.step_id.clone(),
            entry.image_digest.as_str().to_string(),
        );
        if let Some(old) = prior_coords.get(&key) {
            if entry.hit_count < old.hit_count {
                return Err(invalid(format!(
                    "coordinate {:?} hit_count decreases ({} to {}): counts advance monotonically",
                    key, old.hit_count, entry.hit_count
                )));
            }
        }
    }
    Ok(())
}

fn check_import_carryforward(
    baseline: &ParsedLearning,
    candidate: &ParsedLearning,
) -> Result<(), ConnectorError> {
    // A domain revision is a complete immutable snapshot, not a patch:
    // retained imports carry forward unchanged.
    for old in &baseline.imports {
        let found = candidate.imports.iter().any(|entry| {
            entry.source_digest == old.source_digest
                && entry.provenance == old.provenance
                && entry.byte_length == old.byte_length
        });
        if !found {
            return Err(invalid(format!(
                "candidate drops retained import {}: revisions are complete snapshots",
                old.source_digest.as_str()
            )));
        }
    }
    Ok(())
}

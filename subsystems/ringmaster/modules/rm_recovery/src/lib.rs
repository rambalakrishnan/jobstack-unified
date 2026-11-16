//! `rm_recovery`: tier-7 bounded Tier 2/3 target recovery for Ringmaster.
//!
//! Implements seam mapping §10.2 (failure routing), §10.3 (Tier 2),
//! §10.4 (Tier 3 vision-assisted DOM grounding), and §10.5 (learning state)
//! for conformance case RM-C41 (dHash hit with changed geometry/layout).
//!
//! - [`recover_target`] routes `BOPrimitiveRecord` failures per §10.2, enforces
//!   authority (`rm_authority`), active deadlines (`rm_time`), and finite
//!   recovery budgets, validates dHash reuse against eight compatibility
//!   dimensions (step, root, crop, viewport, scale, frame offset, layout,
//!   target identity, permission), then attempts Tier 2 selector recovery
//!   (`rm_reduction` + `rm_models` + `rm_targets`) or Tier 3 grounding
//!   (`bo.capture` + bbox + `bo.v8_evaluate` hit-test + `rm_targets`).
//! - A dHash match is image similarity only. Changed geometry/layout, missing
//!   geometry (never defaulted to zero offsets or unit scale), silent
//!   full-viewport fallback, invented coordinate-click primitives, trusted
//!   coordinate input, side-effect replay, tentative-to-verified promotion,
//!   and budget extension are all rejected.
//! - No in-band nulls; missing fields use typed [`Missing`] envelopes. No
//!   shared-database writes or cross-domain transactions.

#![forbid(unsafe_code)]
#![allow(clippy::result_large_err)]

use rm_authority::{AuthenticatedPrincipal, ConnectorError, Manifest, Operation};
use rm_browseroxide::{
    BODomRead, BOOwner, BOPageRef, BORootRef, BOPrimitiveRecord, NativeSession,
};
use rm_catalog::{DurationLimit, VersionPin};
use rm_delivery::ConnectorHandle;
use rm_evidence::{AccessClass, ArtifactReference, EvidenceRef};
use rm_models::{
    BOBindingDescriptor as ModelBinding, TaskBudgets as ModelBudgets,
    VersionPin as ModelVersionPin,
};
use rm_preparation::PreparedTask;
use rm_time::{MaybeNumber, MaybeString as TimeMaybeString, Missing, TimePoint};
use rm_wire::Digest;
use serde_json::{json, Value};
use std::collections::BTreeSet;

// ---------------------------------------------------------------------------
// Dependency signature pins (compile-time CONSUMES check)
// ---------------------------------------------------------------------------

#[allow(dead_code)]
const _: fn(
    &AuthenticatedPrincipal,
    &rm_authority::WorkScope,
    &Operation,
) -> Result<rm_authority::ProducerDescriptor, ConnectorError> =
    rm_authority::authorize_work;
#[allow(dead_code)]
const _: fn(
    &AuthenticatedPrincipal,
    &ArtifactReference,
) -> Result<Vec<u8>, ConnectorError> = rm_evidence::load_artifact;
#[allow(dead_code)]
const _: fn(
    &AuthenticatedPrincipal,
    &ArtifactReference,
    &[u8],
) -> Result<ArtifactReference, ConnectorError> = rm_evidence::install_artifact;
#[allow(dead_code)]
const _: fn(&TimePoint, &TimePoint) -> Result<bool, String> =
    rm_time::boundary_reached;
#[allow(dead_code)]
const _: fn(
    &mut NativeSession,
    &rm_browseroxide::BOCapture,
    &EvidenceRef,
    &DurationLimit,
) -> Result<
    rm_browseroxide::BrowserOxideReturn<rm_browseroxide::BOCaptureReturn>,
    ConnectorError,
> = rm_browseroxide::capture;
#[allow(dead_code)]
const _: fn(
    &mut NativeSession,
    &rm_browseroxide::BOV8Evaluate,
    &EvidenceRef,
    &DurationLimit,
) -> Result<
    rm_browseroxide::BrowserOxideReturn<rm_browseroxide::BOV8Return>,
    ConnectorError,
> = rm_browseroxide::v8_evaluate;
#[allow(dead_code)]
const _: fn(
    &AuthenticatedPrincipal,
    &mut NativeSession,
    &BODomRead,
    &str,
    &VersionPin,
    &EvidenceRef,
    &DurationLimit,
) -> Result<ArtifactReference, ConnectorError> = rm_reduction::reduce_document;
#[allow(dead_code)]
const _: fn(
    &AuthenticatedPrincipal,
    &mut NativeSession,
    &ArtifactReference,
    &BORootRef,
    &EvidenceRef,
    &DurationLimit,
) -> Result<rm_browseroxide::BODomExport, ConnectorError> = rm_targets::resolve_target;
#[allow(dead_code)]
const _: fn(
    &AuthenticatedPrincipal,
    &rm_models::ConnectorHandle,
    &ModelBinding,
    &ArtifactReference,
    &ModelVersionPin,
    &ModelBudgets,
) -> Result<ArtifactReference, ConnectorError> = rm_models::propose_recovery;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Recovery step record discriminator.
pub const RECOVERY_STEP_RECORD_TYPE: &str = "ringmaster_recovery_step";
/// Recovery step schema version.
pub const RECOVERY_STEP_SCHEMA_VERSION: &str = "ringmaster-recovery/0.1.0";
/// HEAL profile name (must match `rm_reduction`).
pub const HEAL_PROFILE: &str = "HEAL";
/// Tier 2 strategies (closed vocabulary).
pub const RECOVERY_STRATEGIES: [&str; 5] = ["css", "xpath", "text", "role", "testid"];
/// Baseline Tier 3 crop padding in CSS pixels.
pub const TIER3_CROP_PADDING_PX: f64 = 100.0;
/// Mutating primitives whose post-entry failure implies possible side effects.
const MUTATING_PRIMITIVES: [&str; 6] = [
    "bo.dom_write",
    "bo.event_dispatch",
    "bo.navigate",
    "bo.from_html",
    "bo.assign_files",
    "bo.http_exchange",
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

fn not_admitted(detail: impl Into<String>) -> ConnectorError {
    connector_error("NOT_ADMITTED", "policy", detail)
}

fn integrity(detail: impl Into<String>) -> ConnectorError {
    connector_error("INTEGRITY_INCIDENT", "integrity", detail)
}

fn stale_reference(detail: impl Into<String>) -> ConnectorError {
    connector_error("STALE_REFERENCE", "connector", detail)
}

fn unsupported_mapping(detail: impl Into<String>) -> ConnectorError {
    connector_error("UNSUPPORTED_MAPPING", "connector", detail)
}

fn target_not_found(detail: impl Into<String>) -> ConnectorError {
    connector_error("TARGET_NOT_FOUND", "connector", detail)
}

fn prerequisite(detail: impl Into<String>) -> ConnectorError {
    connector_error("PREREQUISITE_UNAVAILABLE", "connector", detail)
}

fn reconcile_required(detail: impl Into<String>) -> ConnectorError {
    connector_error("RECONCILIATION_REQUIRED", "connector", detail)
}

fn fenced(detail: impl Into<String>) -> ConnectorError {
    connector_error("FENCED", "connector", detail)
}

fn revalidation_required(detail: impl Into<String>) -> ConnectorError {
    connector_error("REVALIDATION_REQUIRED", "connector", detail)
}

fn require_nonempty(field: &str, value: &str) -> Result<(), ConnectorError> {
    if value.is_empty() {
        return Err(invalid(format!("{field} must be nonempty")));
    }
    Ok(())
}

fn require_identifier(field: &str, value: &str) -> Result<(), ConnectorError> {
    require_nonempty(field, value)
}

fn validate_missing(missing: &Missing, what: &str) -> Result<(), ConnectorError> {
    if !rm_time::is_valid_reason(&missing.reason) {
        return Err(invalid(format!(
            "{what} carries invalid Missing reason {:?}",
            missing.reason
        )));
    }
    if matches!(&missing.detail, Some(d) if d.is_empty()) {
        return Err(invalid(format!("{what} Missing detail must be nonempty")));
    }
    Ok(())
}

fn is_missing_envelope(value: &Value) -> bool {
    match value.as_object() {
        Some(map) => {
            map.get("value").map(Value::is_null).unwrap_or(false) && map.contains_key("reason")
        }
        None => false,
    }
}

fn parse_missing(value: &Value, what: &str) -> Result<Missing, ConnectorError> {
    let missing: Missing = serde_json::from_value(value.clone())
        .map_err(|e| invalid(format!("{what} Missing envelope invalid: {e}")))?;
    validate_missing(&missing, what)?;
    Ok(missing)
}

// ---------------------------------------------------------------------------
// JSON field helpers
// ---------------------------------------------------------------------------

fn field<'a>(object: &'a serde_json::Map<String, Value>, name: &str, what: &str) -> Result<&'a Value, ConnectorError> {
    object
        .get(name)
        .ok_or_else(|| invalid(format!("{what} is missing required field {name:?}")))
}

fn field_str<'a>(object: &'a serde_json::Map<String, Value>, name: &str, what: &str) -> Result<&'a str, ConnectorError> {
    field(object, name, what)?
        .as_str()
        .ok_or_else(|| invalid(format!("{what} field {name:?} must be a string")))
}

fn field_u64(object: &serde_json::Map<String, Value>, name: &str, what: &str) -> Result<u64, ConnectorError> {
    field(object, name, what)?
        .as_u64()
        .ok_or_else(|| invalid(format!("{what} field {name:?} must be an integer")))
}

fn field_bool(object: &serde_json::Map<String, Value>, name: &str, what: &str) -> Result<bool, ConnectorError> {
    field(object, name, what)?
        .as_bool()
        .ok_or_else(|| invalid(format!("{what} field {name:?} must be a boolean")))
}

fn ensure_closed(object: &serde_json::Map<String, Value>, allowed: &[&str], what: &str) -> Result<(), ConnectorError> {
    for key in object.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(invalid(format!(
                "{what} has undeclared field {key:?}; the object is closed"
            )));
        }
    }
    for f in allowed {
        if !object.contains_key(*f) {
            return Err(invalid(format!("{what} is missing required field {f:?}")));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Native reference parsers (BORootRef / page / owner have no from_json)
// ---------------------------------------------------------------------------

fn parse_owner(value: &Value, what: &str) -> Result<BOOwner, ConnectorError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(format!("{what} must be an object")))?;
    ensure_closed(object, &["process_id", "boot_id", "os_thread_id"], what)?;
    let process_id = field_str(object, "process_id", what)?.to_string();
    let boot_id = field_str(object, "boot_id", what)?.to_string();
    let os_thread_id = field_str(object, "os_thread_id", what)?.to_string();
    require_identifier(&format!("{what} process_id"), &process_id)?;
    require_identifier(&format!("{what} boot_id"), &boot_id)?;
    require_identifier(&format!("{what} os_thread_id"), &os_thread_id)?;
    Ok(BOOwner {
        process_id,
        boot_id,
        os_thread_id,
    })
}

fn parse_page(value: &Value, what: &str) -> Result<BOPageRef, ConnectorError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(format!("{what} must be an object")))?;
    ensure_closed(
        object,
        &["owner", "page_id", "page_generation", "profile_digest"],
        what,
    )?;
    let owner = parse_owner(field(object, "owner", what)?, &format!("{what} owner"))?;
    let page_id = field_str(object, "page_id", what)?.to_string();
    require_identifier(&format!("{what} page_id"), &page_id)?;
    let page_generation = field_u64(object, "page_generation", what)?;
    if page_generation > rm_evidence::MAX_SAFE_INTEGER {
        return Err(invalid(format!("{what} page_generation out of range")));
    }
    let digest_str = field_str(object, "profile_digest", what)?;
    let profile_digest =
        Digest::parse(digest_str).map_err(|e| invalid(format!("{what} profile_digest invalid: {e}")))?;
    Ok(BOPageRef {
        owner,
        page_id,
        page_generation,
        profile_digest,
    })
}

fn parse_root(value: &Value, what: &str) -> Result<BORootRef, ConnectorError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(format!("{what} must be an object")))?;
    ensure_closed(
        object,
        &[
            "page",
            "frame_id",
            "document_generation",
            "root_id",
            "root_kind",
        ],
        what,
    )?;
    let page = parse_page(field(object, "page", what)?, &format!("{what} page"))?;
    let frame_id = field_str(object, "frame_id", what)?.to_string();
    require_identifier(&format!("{what} frame_id"), &frame_id)?;
    let document_generation = field_u64(object, "document_generation", what)?;
    if document_generation > rm_evidence::MAX_SAFE_INTEGER {
        return Err(invalid(format!("{what} document_generation out of range")));
    }
    let root_id = field_str(object, "root_id", what)?.to_string();
    require_identifier(&format!("{what} root_id"), &root_id)?;
    let root_kind = field_str(object, "root_kind", what)?.to_string();
    if !["document", "open_shadow", "closed_shadow"].contains(&root_kind.as_str()) {
        return Err(invalid(format!("{what} root_kind {root_kind:?} unknown")));
    }
    Ok(BORootRef {
        page,
        frame_id,
        document_generation,
        root_id,
        root_kind,
    })
}

fn parse_duration_limit(value: &Value, what: &str) -> Result<DurationLimit, ConnectorError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(format!("{what} must be an object")))?;
    ensure_closed(object, &["kind", "unit", "value"], what)?;
    let kind = field_str(object, "kind", what)?.to_string();
    let unit = field_str(object, "unit", what)?.to_string();
    let num = field(object, "value", what)?
        .as_f64()
        .ok_or_else(|| invalid(format!("{what} value must be a number")))?;
    if kind != "exact" {
        return Err(invalid(format!("{what} kind {kind:?} must be exact")));
    }
    if unit != "ms" {
        return Err(invalid(format!("{what} unit {unit:?} must be ms")));
    }
    if !num.is_finite() || num < 0.0 {
        return Err(invalid(format!("{what} value must be finite nonnegative")));
    }
    Ok(DurationLimit { kind, unit, value: num })
}

fn parse_catalog_pin(value: &Value, what: &str) -> Result<VersionPin, ConnectorError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(format!("{what} must be an object")))?;
    ensure_closed(object, &["id", "version", "artifact_digest"], what)?;
    let id = field_str(object, "id", what)?.to_string();
    let version = field_str(object, "version", what)?.to_string();
    let digest_str = field_str(object, "artifact_digest", what)?;
    require_identifier(&format!("{what} id"), &id)?;
    require_identifier(&format!("{what} version"), &version)?;
    let artifact_digest =
        Digest::parse(digest_str).map_err(|e| invalid(format!("{what} digest invalid: {e}")))?;
    Ok(VersionPin {
        id,
        version,
        artifact_digest,
    })
}

fn parse_timepoint(value: &Value, what: &str) -> Result<TimePoint, ConnectorError> {
    serde_json::from_value::<TimePoint>(value.clone())
        .map_err(|e| invalid(format!("{what} TimePoint invalid: {e}")))
}

fn parse_maybe_number(value: &Value, what: &str) -> Result<MaybeNumber, ConnectorError> {
    serde_json::from_value::<MaybeNumber>(value.clone())
        .map_err(|e| invalid(format!("{what} must be a number or Missing envelope: {e}")))
}

fn parse_maybe_string(value: &Value, what: &str) -> Result<TimeMaybeString, ConnectorError> {
    if let Some(text) = value.as_str() {
        if text.is_empty() {
            return Err(invalid(format!("{what} string must be nonempty")));
        }
        return Ok(TimeMaybeString::Text(text.to_string()));
    }
    if value.is_object() {
        let missing = parse_missing(value, what)?;
        return Ok(TimeMaybeString::Missing(missing));
    }
    Err(invalid(format!(
        "{what} must be a nonempty string or Missing envelope"
    )))
}

fn maybe_number_value(num: &MaybeNumber, what: &str) -> Result<f64, ConnectorError> {
    match num {
        MaybeNumber::Num(value) => {
            if !value.is_finite() {
                return Err(invalid(format!("{what} must be finite")));
            }
            Ok(*value)
        }
        MaybeNumber::Missing(missing) => Err(revalidation_required(format!(
            "{what} is missing (reason {:?}): geometry is explicit; missing is not zero or scale one",
            missing.reason
        ))),
    }
}

fn maybe_string_text(value: &TimeMaybeString, what: &str) -> Result<String, ConnectorError> {
    match value {
        TimeMaybeString::Text(text) => Ok(text.clone()),
        TimeMaybeString::Missing(missing) => Err(revalidation_required(format!(
            "{what} is missing (reason {:?}): no action until revalidated",
            missing.reason
        ))),
    }
}

// ---------------------------------------------------------------------------
// Models policy / binding / budgets / manifest parsers
// ---------------------------------------------------------------------------

fn parse_model_pin(value: &Value, what: &str) -> Result<ModelVersionPin, ConnectorError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(format!("{what} must be an object")))?;
    // Required closed fields for the pinned provider policy.
    const ALLOWED: [&str; 16] = [
        "id",
        "version",
        "artifact_digest",
        "role",
        "providers",
        "model",
        "protocol",
        "endpoint_ref",
        "credential_ref",
        "headers",
        "timeout_ms",
        "failover_enabled",
        "retention",
        "privacy",
        "user_agent",
        "disclosure_allowed",
    ];
    ensure_closed(object, &ALLOWED, what)?;
    let id = field_str(object, "id", what)?.to_string();
    let version = field_str(object, "version", what)?.to_string();
    let artifact_digest = field_str(object, "artifact_digest", what)?.to_string();
    let role = field_str(object, "role", what)?.to_string();
    let model = field_str(object, "model", what)?.to_string();
    let protocol = field_str(object, "protocol", what)?.to_string();
    let endpoint_ref = field_str(object, "endpoint_ref", what)?.to_string();
    let credential_ref = field_str(object, "credential_ref", what)?.to_string();
    let retention = field_str(object, "retention", what)?.to_string();
    let privacy = field_str(object, "privacy", what)?.to_string();
    let user_agent = field_str(object, "user_agent", what)?.to_string();
    for (name, text) in [
        ("id", &id),
        ("version", &version),
        ("role", &role),
        ("model", &model),
        ("protocol", &protocol),
        ("endpoint_ref", &endpoint_ref),
        ("credential_ref", &credential_ref),
        ("retention", &retention),
        ("privacy", &privacy),
        ("user_agent", &user_agent),
    ] {
        require_nonempty(&format!("{what} {name}"), text)?;
    }
    if !rm_wire::is_valid_digest(&artifact_digest) {
        return Err(invalid(format!("{what} artifact_digest is not a digest")));
    }
    let providers_value = field(object, "providers", what)?
        .as_array()
        .ok_or_else(|| invalid(format!("{what} providers must be an array")))?;
    let mut providers = Vec::with_capacity(providers_value.len());
    for item in providers_value {
        let text = item
            .as_str()
            .ok_or_else(|| invalid(format!("{what} provider must be a string")))?;
        require_nonempty(&format!("{what} provider"), text)?;
        providers.push(text.to_string());
    }
    if providers.is_empty() {
        return Err(invalid(format!("{what} providers must be nonempty")));
    }
    let headers_value = field(object, "headers", what)?
        .as_array()
        .ok_or_else(|| invalid(format!("{what} headers must be an array")))?;
    let mut headers = Vec::with_capacity(headers_value.len());
    for item in headers_value {
        let header_object = item
            .as_object()
            .ok_or_else(|| invalid(format!("{what} header must be an object")))?;
        ensure_closed(header_object, &["name", "value"], &format!("{what} header"))?;
        let name = header_object
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid(format!("{what} header name must be a string")))?
            .to_string();
        let hvalue = header_object
            .get("value")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid(format!("{what} header value must be a string")))?
            .to_string();
        require_nonempty(&format!("{what} header name"), &name)?;
        require_nonempty(&format!("{what} header value"), &hvalue)?;
        headers.push(rm_models::Header { name, value: hvalue });
    }
    let timeout_ms = field_u64(object, "timeout_ms", what)?;
    let failover_enabled = field_bool(object, "failover_enabled", what)?;
    let disclosure_allowed = field_bool(object, "disclosure_allowed", what)?;
    Ok(ModelVersionPin {
        id,
        version,
        artifact_digest,
        role,
        providers,
        model,
        protocol,
        endpoint_ref,
        credential_ref,
        headers,
        timeout_ms,
        failover_enabled,
        retention,
        privacy,
        user_agent,
        disclosure_allowed,
    })
}

fn parse_model_binding(value: &Value, what: &str) -> Result<ModelBinding, ConnectorError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(format!("{what} must be an object")))?;
    ensure_closed(
        object,
        &[
            "record_type",
            "schema_version",
            "binding_id",
            "primitive_mappings",
            "session_storage_model",
            "session_isolation_refs",
        ],
        what,
    )?;
    let record_type = field_str(object, "record_type", what)?.to_string();
    let schema_version = field_str(object, "schema_version", what)?.to_string();
    let binding_id = field_str(object, "binding_id", what)?.to_string();
    require_nonempty(&format!("{what} binding_id"), &binding_id)?;
    let mappings_value = field(object, "primitive_mappings", what)?
        .as_array()
        .ok_or_else(|| invalid(format!("{what} primitive_mappings must be an array")))?;
    let mut primitive_mappings = Vec::with_capacity(mappings_value.len());
    for item in mappings_value {
        let mapping_object = item
            .as_object()
            .ok_or_else(|| invalid(format!("{what} mapping must be an object")))?;
        // native_symbol is optional: string or null-absent? Use Missing-free
        // shape: either a nonempty string or an explicit Missing envelope is
        // rejected here; unmapped entries omit the symbol via Missing-style
        // object? For models binding, native_symbol is Option<String>:
        // accept string, or Missing envelope meaning None.
        let primitive = mapping_object
            .get("primitive")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid(format!("{what} mapping primitive must be a string")))?
            .to_string();
        let mapping_state = mapping_object
            .get("mapping_state")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid(format!("{what} mapping_state must be a string")))?
            .to_string();
        require_nonempty(&format!("{what} primitive"), &primitive)?;
        let native_symbol = match mapping_object.get("native_symbol") {
            None => None,
            Some(Value::Null) => {
                return Err(invalid(format!(
                    "{what} native_symbol must not be a bare null; use a Missing envelope or string"
                )))
            }
            Some(Value::String(text)) => {
                require_nonempty(&format!("{what} native_symbol"), text)?;
                Some(text.clone())
            }
            Some(other) if is_missing_envelope(other) => {
                let _ = parse_missing(other, &format!("{what} native_symbol"))?;
                None
            }
            Some(_) => {
                return Err(invalid(format!(
                    "{what} native_symbol must be a string or Missing envelope"
                )))
            }
        };
        let evidence_value = mapping_object
            .get("evidence_refs")
            .ok_or_else(|| invalid(format!("{what} mapping requires evidence_refs")))?
            .as_array()
            .ok_or_else(|| invalid(format!("{what} evidence_refs must be an array")))?;
        let mut evidence_refs = Vec::with_capacity(evidence_value.len());
        for evidence in evidence_value {
            let text = evidence
                .as_str()
                .ok_or_else(|| invalid(format!("{what} evidence_ref must be a string")))?;
            require_nonempty(&format!("{what} evidence_ref"), text)?;
            evidence_refs.push(text.to_string());
        }
        primitive_mappings.push(rm_models::BOMapping {
            primitive,
            mapping_state,
            native_symbol,
            evidence_refs,
        });
    }
    let session_storage_model = field_str(object, "session_storage_model", what)?.to_string();
    let isolation_value = field(object, "session_isolation_refs", what)?
        .as_array()
        .ok_or_else(|| invalid(format!("{what} session_isolation_refs must be an array")))?;
    let mut session_isolation_refs = Vec::with_capacity(isolation_value.len());
    for item in isolation_value {
        let text = item
            .as_str()
            .ok_or_else(|| invalid(format!("{what} isolation ref must be a string")))?;
        require_nonempty(&format!("{what} isolation ref"), text)?;
        session_isolation_refs.push(text.to_string());
    }
    Ok(ModelBinding {
        record_type,
        schema_version,
        binding_id,
        primitive_mappings,
        session_storage_model,
        session_isolation_refs,
    })
}

fn parse_model_budgets(value: &Value, what: &str) -> Result<ModelBudgets, ConnectorError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(format!("{what} must be an object")))?;
    const ALLOWED: [&str; 14] = [
        "active_limit_ms",
        "action_limit",
        "observation_byte_limit",
        "recovery_limit",
        "model_token_limit",
        "enforcers",
        "tokens_reserved",
        "tokens_used",
        "tokens_per_call",
        "breaker",
        "session_limit",
        "sessions_used",
        "observation_open",
        "active_allowance_remaining",
    ];
    // recovery_allowance_remaining is carried top-level too; accept both.
    // The closed check below allows the extra field explicitly.
    let mut allowed: Vec<&str> = ALLOWED.to_vec();
    allowed.push("recovery_allowance_remaining");
    ensure_closed(object, &allowed, what)?;
    let active_limit_ms = field(object, "active_limit_ms", what)?
        .as_f64()
        .ok_or_else(|| invalid(format!("{what} active_limit_ms must be a number")))?;
    if !active_limit_ms.is_finite() || active_limit_ms < 0.0 {
        return Err(invalid(format!("{what} active_limit_ms must be finite nonnegative")));
    }
    let action_limit = field_u64(object, "action_limit", what)?;
    let observation_byte_limit = field_u64(object, "observation_byte_limit", what)?;
    let recovery_limit = field_u64(object, "recovery_limit", what)?;
    let model_token_limit = field_u64(object, "model_token_limit", what)?;
    let enforcers_value = field(object, "enforcers", what)?;
    let enforcers_object = enforcers_value
        .as_object()
        .ok_or_else(|| invalid(format!("{what} enforcers must be an object")))?;
    ensure_closed(
        enforcers_object,
        &[
            "active_observation",
            "action_count",
            "observation_bytes",
            "recovery_count",
            "model_tokens",
        ],
        &format!("{what} enforcers"),
    )?;
    let enforcer = |name: &str| -> Result<String, ConnectorError> {
        let text = enforcers_object
            .get(name)
            .and_then(Value::as_str)
            .ok_or_else(|| invalid(format!("{what} enforcer {name} must be a string")))?
            .to_string();
        require_nonempty(&format!("{what} enforcer {name}"), &text)?;
        Ok(text)
    };
    let enforcers = rm_models::BudgetEnforcers {
        active_observation: enforcer("active_observation")?,
        action_count: enforcer("action_count")?,
        observation_bytes: enforcer("observation_bytes")?,
        recovery_count: enforcer("recovery_count")?,
        model_tokens: enforcer("model_tokens")?,
    };
    let tokens_reserved = match field(object, "tokens_reserved", what)? {
        Value::Null => {
            return Err(invalid(format!(
                "{what} tokens_reserved must not be a bare null; use Missing envelope or integer"
            )))
        }
        Value::Number(number) => Some(
            number
                .as_u64()
                .ok_or_else(|| invalid(format!("{what} tokens_reserved must be an integer")))?,
        ),
        other if is_missing_envelope(other) => {
            let _ = parse_missing(other, &format!("{what} tokens_reserved"))?;
            None
        }
        _ => return Err(invalid(format!("{what} tokens_reserved must be integer or Missing"))),
    };
    let tokens_used = match field(object, "tokens_used", what)? {
        Value::Null => {
            return Err(invalid(format!(
                "{what} tokens_used must not be a bare null; use Missing envelope or integer"
            )))
        }
        Value::Number(number) => Some(
            number
                .as_u64()
                .ok_or_else(|| invalid(format!("{what} tokens_used must be an integer")))?,
        ),
        other if is_missing_envelope(other) => {
            let _ = parse_missing(other, &format!("{what} tokens_used"))?;
            None
        }
        _ => return Err(invalid(format!("{what} tokens_used must be integer or Missing"))),
    };
    let tokens_per_call = field_u64(object, "tokens_per_call", what)?;
    let breaker_value = field(object, "breaker", what)?;
    let breaker_object = breaker_value
        .as_object()
        .ok_or_else(|| invalid(format!("{what} breaker must be an object")))?;
    ensure_closed(
        breaker_object,
        &[
            "shard",
            "numerator",
            "denominator",
            "window_clock_id",
            "sample_minimum",
            "tripped",
            "reset_authority",
        ],
        &format!("{what} breaker"),
    )?;
    let shard = breaker_object
        .get("shard")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("{what} breaker shard must be a string")))?
        .to_string();
    require_nonempty(&format!("{what} breaker shard"), &shard)?;
    let parse_breaker_count = |name: &str| -> Result<Option<u64>, ConnectorError> {
        let value = breaker_object
            .get(name)
            .ok_or_else(|| invalid(format!("{what} breaker requires {name}")))?;
        if let Some(number) = value.as_u64() {
            return Ok(Some(number));
        }
        if value.is_number() {
            return Err(invalid(format!("{what} breaker {name} must be an integer or Missing")));
        }
        if is_missing_envelope(value) {
            let _ = parse_missing(value, &format!("{what} breaker {name}"))?;
            return Ok(None);
        }
        if value.is_null() {
            return Err(invalid(format!(
                "{what} breaker {name} must not be a bare null"
            )));
        }
        Err(invalid(format!(
            "{what} breaker {name} must be integer or Missing"
        )))
    };
    let numerator = parse_breaker_count("numerator")?;
    let denominator = parse_breaker_count("denominator")?;
    let window_clock_id = breaker_object
        .get("window_clock_id")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("{what} breaker window_clock_id must be a string")))?
        .to_string();
    require_nonempty(&format!("{what} breaker window_clock_id"), &window_clock_id)?;
    let sample_minimum = breaker_object
        .get("sample_minimum")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid(format!("{what} breaker sample_minimum must be an integer")))?;
    let tripped = breaker_object
        .get("tripped")
        .and_then(Value::as_bool)
        .ok_or_else(|| invalid(format!("{what} breaker tripped must be a boolean")))?;
    let reset_authority = breaker_object
        .get("reset_authority")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("{what} breaker reset_authority must be a string")))?
        .to_string();
    require_nonempty(&format!("{what} breaker reset_authority"), &reset_authority)?;
    let breaker = rm_models::BreakerPolicy {
        shard,
        numerator,
        denominator,
        window_clock_id,
        sample_minimum,
        tripped,
        reset_authority,
    };
    let session_limit = field_u64(object, "session_limit", what)?;
    let sessions_used = field_u64(object, "sessions_used", what)?;
    let observation_open = field_bool(object, "observation_open", what)?;
    let active_allowance_remaining = field_u64(object, "active_allowance_remaining", what)?;
    let recovery_allowance_remaining = field_u64(object, "recovery_allowance_remaining", what)?;
    Ok(ModelBudgets {
        active_limit_ms,
        action_limit,
        observation_byte_limit,
        recovery_limit,
        model_token_limit,
        enforcers,
        tokens_reserved,
        tokens_used,
        tokens_per_call,
        breaker,
        session_limit,
        sessions_used,
        observation_open,
        active_allowance_remaining,
        recovery_allowance_remaining,
    })
}

fn parse_manifest(value: &Value, what: &str) -> Result<Manifest, ConnectorError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(format!("{what} must be an object")))?;
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
        what,
    )?;
    let record_type = field_str(object, "record_type", what)?.to_string();
    let schema_version = field_str(object, "schema_version", what)?.to_string();
    let run_id = field_str(object, "run_id", what)?.to_string();
    let task = field(object, "task", what)?.clone();
    let subject = field(object, "subject", what)?.clone();
    let event_kinds_value = field(object, "event_kinds", what)?
        .as_array()
        .ok_or_else(|| invalid(format!("{what} event_kinds must be an array")))?;
    let mut event_kinds = Vec::with_capacity(event_kinds_value.len());
    for item in event_kinds_value {
        let text = item
            .as_str()
            .ok_or_else(|| invalid(format!("{what} event kind must be a string")))?;
        require_nonempty(&format!("{what} event kind"), text)?;
        event_kinds.push(text.to_string());
    }
    let admission_ref = field_str(object, "admission_ref", what)?.to_string();
    let manifest_hash = field_str(object, "manifest_hash", what)?.to_string();
    require_nonempty(&format!("{what} record_type"), &record_type)?;
    require_nonempty(&format!("{what} run_id"), &run_id)?;
    require_nonempty(&format!("{what} admission_ref"), &admission_ref)?;
    if !rm_wire::is_valid_digest(&manifest_hash) {
        return Err(invalid(format!("{what} manifest_hash is not a digest")));
    }
    let manifest = Manifest {
        record_type,
        schema_version,
        run_id,
        task,
        subject,
        event_kinds,
        admission_ref,
        manifest_hash,
    };
    // Verify hash integrity against the canonical wire projection.
    let wire = rm_authority::manifest_wire_bytes(&manifest);
    let computed = rm_wire::canonical_digest(&wire)
        .map_err(|e| invalid(format!("{what} wire digest failed: {e}")))?;
    if computed.as_str() != manifest.manifest_hash {
        return Err(invalid(format!(
            "{what} manifest_hash does not match wire bytes"
        )));
    }
    Ok(manifest)
}

// ---------------------------------------------------------------------------
// Coordinate learning state (§10.5) and Tier 3 geometry (§10.4)
// ---------------------------------------------------------------------------

/// Stored coordinate learning entry (operational `coordinate` revision).
#[derive(Debug, Clone)]
struct CoordinateEntry {
    step: String,
    perceptual_hash: String,
    coordinate_space: String,
    crop_origin_x: f64,
    crop_origin_y: f64,
    crop_width: f64,
    crop_height: f64,
    viewport_width: f64,
    viewport_height: f64,
    scale: f64,
    frame_offset_x: f64,
    frame_offset_y: f64,
    layout_digest: String,
    root: BORootRef,
    target_identity: String,
    permission_granted: bool,
}

/// Current-layout observation that a dHash hit must revalidate against.
#[derive(Debug, Clone)]
struct CurrentGeometry {
    step: String,
    perceptual_hash: String,
    crop_origin_x: MaybeNumber,
    crop_origin_y: MaybeNumber,
    crop_width: MaybeNumber,
    crop_height: MaybeNumber,
    viewport_width: MaybeNumber,
    viewport_height: MaybeNumber,
    scale: MaybeNumber,
    frame_offset_x: MaybeNumber,
    frame_offset_y: MaybeNumber,
    layout_digest: TimeMaybeString,
    root: BORootRef,
    target_identity: TimeMaybeString,
    permission_granted: bool,
    image_width: MaybeNumber,
    image_height: MaybeNumber,
}

/// Closed bounding-box proposal (§10.4).
#[derive(Debug, Clone)]
struct BBoxProposal {
    x: MaybeNumber,
    y: MaybeNumber,
    width: MaybeNumber,
    height: MaybeNumber,
}

fn parse_crop_numbers(
    value: &Value,
    what: &str,
    allow_missing: bool,
) -> Result<(MaybeNumber, MaybeNumber, MaybeNumber, MaybeNumber), ConnectorError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(format!("{what} must be an object")))?;
    ensure_closed(object, &["origin_x", "origin_y", "width", "height"], what)?;
    let parse_one = |name: &str| -> Result<MaybeNumber, ConnectorError> {
        let field_value = field(object, name, what)?;
        if let Some(number) = field_value.as_f64() {
            if !number.is_finite() {
                return Err(invalid(format!("{what} {name} must be finite")));
            }
            return Ok(MaybeNumber::Num(number));
        }
        if field_value.is_number() {
            return Err(invalid(format!("{what} {name} must be finite")));
        }
        if is_missing_envelope(field_value) {
            if !allow_missing {
                let missing = parse_missing(field_value, &format!("{what} {name}"))?;
                return Err(revalidation_required(format!(
                    "{what} {name} is missing (reason {:?}): stored geometry must be explicit",
                    missing.reason
                )));
            }
            let missing = parse_missing(field_value, &format!("{what} {name}"))?;
            return Ok(MaybeNumber::Missing(missing));
        }
        if field_value.is_null() {
            return Err(invalid(format!(
                "{what} {name} must not be a bare null; use a Missing envelope"
            )));
        }
        Err(invalid(format!(
            "{what} {name} must be a number or Missing envelope"
        )))
    };
    Ok((
        parse_one("origin_x")?,
        parse_one("origin_y")?,
        parse_one("width")?,
        parse_one("height")?,
    ))
}

fn parse_viewport_numbers(
    value: &Value,
    what: &str,
    allow_missing: bool,
) -> Result<(MaybeNumber, MaybeNumber), ConnectorError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(format!("{what} must be an object")))?;
    ensure_closed(object, &["width", "height"], what)?;
    let parse_one = |name: &str| -> Result<MaybeNumber, ConnectorError> {
        let field_value = field(object, name, what)?;
        if let Some(number) = field_value.as_f64() {
            if !number.is_finite() {
                return Err(invalid(format!("{what} {name} must be finite")));
            }
            return Ok(MaybeNumber::Num(number));
        }
        if is_missing_envelope(field_value) {
            if !allow_missing {
                let missing = parse_missing(field_value, &format!("{what} {name}"))?;
                return Err(revalidation_required(format!(
                    "{what} {name} is missing (reason {:?}): stored geometry must be explicit",
                    missing.reason
                )));
            }
            let missing = parse_missing(field_value, &format!("{what} {name}"))?;
            return Ok(MaybeNumber::Missing(missing));
        }
        if field_value.is_null() {
            return Err(invalid(format!(
                "{what} {name} must not be a bare null; use a Missing envelope"
            )));
        }
        Err(invalid(format!(
            "{what} {name} must be a number or Missing envelope"
        )))
    };
    Ok((parse_one("width")?, parse_one("height")?))
}

fn parse_coordinate_entry(value: &Value, what: &str) -> Result<CoordinateEntry, ConnectorError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(format!("{what} must be an object")))?;
    ensure_closed(
        object,
        &[
            "step",
            "perceptual_hash",
            "coordinate_space",
            "crop",
            "viewport",
            "scale",
            "frame_offset_x",
            "frame_offset_y",
            "layout_digest",
            "root",
            "target_identity",
            "permission_granted",
        ],
        what,
    )?;
    let step = field_str(object, "step", what)?.to_string();
    let perceptual_hash = field_str(object, "perceptual_hash", what)?.to_string();
    let coordinate_space = field_str(object, "coordinate_space", what)?.to_string();
    require_nonempty(&format!("{what} step"), &step)?;
    require_nonempty(&format!("{what} perceptual_hash"), &perceptual_hash)?;
    require_nonempty(&format!("{what} coordinate_space"), &coordinate_space)?;
    let (ox, oy, cw, ch) = parse_crop_numbers(field(object, "crop", what)?, &format!("{what} crop"), false)?;
    let crop_origin_x = maybe_number_value(&ox, &format!("{what} crop origin_x"))?;
    let crop_origin_y = maybe_number_value(&oy, &format!("{what} crop origin_y"))?;
    let crop_width = maybe_number_value(&cw, &format!("{what} crop width"))?;
    let crop_height = maybe_number_value(&ch, &format!("{what} crop height"))?;
    let (vw, vh) =
        parse_viewport_numbers(field(object, "viewport", what)?, &format!("{what} viewport"), false)?;
    let viewport_width = maybe_number_value(&vw, &format!("{what} viewport width"))?;
    let viewport_height = maybe_number_value(&vh, &format!("{what} viewport height"))?;
    let scale_value = parse_maybe_number(field(object, "scale", what)?, &format!("{what} scale"))?;
    let scale = maybe_number_value(&scale_value, &format!("{what} scale"))?;
    let fox_value =
        parse_maybe_number(field(object, "frame_offset_x", what)?, &format!("{what} frame_offset_x"))?;
    let frame_offset_x = maybe_number_value(&fox_value, &format!("{what} frame_offset_x"))?;
    let foy_value =
        parse_maybe_number(field(object, "frame_offset_y", what)?, &format!("{what} frame_offset_y"))?;
    let frame_offset_y = maybe_number_value(&foy_value, &format!("{what} frame_offset_y"))?;
    let layout_digest = field_str(object, "layout_digest", what)?.to_string();
    require_nonempty(&format!("{what} layout_digest"), &layout_digest)?;
    let root = parse_root(field(object, "root", what)?, &format!("{what} root"))?;
    let target_identity = field_str(object, "target_identity", what)?.to_string();
    require_nonempty(&format!("{what} target_identity"), &target_identity)?;
    let permission_granted = field_bool(object, "permission_granted", what)?;
    // Stored geometry must already be sane; current-observation comparison
    // happens in `check_dhash_reuse`.
    if crop_origin_x < 0.0 || crop_origin_y < 0.0 || crop_width <= 0.0 || crop_height <= 0.0 {
        return Err(invalid(format!("{what} crop must be nonnegative origin and positive size")));
    }
    if viewport_width <= 0.0 || viewport_height <= 0.0 {
        return Err(invalid(format!("{what} viewport must be positive")));
    }
    if !scale.is_finite() || scale <= 0.0 {
        return Err(invalid(format!("{what} scale must be finite positive")));
    }
    Ok(CoordinateEntry {
        step,
        perceptual_hash,
        coordinate_space,
        crop_origin_x,
        crop_origin_y,
        crop_width,
        crop_height,
        viewport_width,
        viewport_height,
        scale,
        frame_offset_x,
        frame_offset_y,
        layout_digest,
        root,
        target_identity,
        permission_granted,
    })
}

fn parse_current_geometry(value: &Value, what: &str) -> Result<CurrentGeometry, ConnectorError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(format!("{what} must be an object")))?;
    ensure_closed(
        object,
        &[
            "step",
            "perceptual_hash",
            "crop",
            "viewport",
            "scale",
            "frame_offset_x",
            "frame_offset_y",
            "layout_digest",
            "root",
            "target_identity",
            "permission_granted",
            "image_width",
            "image_height",
        ],
        what,
    )?;
    let step = field_str(object, "step", what)?.to_string();
    let perceptual_hash = field_str(object, "perceptual_hash", what)?.to_string();
    require_nonempty(&format!("{what} step"), &step)?;
    require_nonempty(&format!("{what} perceptual_hash"), &perceptual_hash)?;
    let (ox, oy, cw, ch) = parse_crop_numbers(field(object, "crop", what)?, &format!("{what} crop"), true)?;
    let (vw, vh) =
        parse_viewport_numbers(field(object, "viewport", what)?, &format!("{what} viewport"), true)?;
    let scale = parse_maybe_number(field(object, "scale", what)?, &format!("{what} scale"))?;
    let frame_offset_x =
        parse_maybe_number(field(object, "frame_offset_x", what)?, &format!("{what} frame_offset_x"))?;
    let frame_offset_y =
        parse_maybe_number(field(object, "frame_offset_y", what)?, &format!("{what} frame_offset_y"))?;
    let layout_digest = parse_maybe_string(field(object, "layout_digest", what)?, &format!("{what} layout_digest"))?;
    let root = parse_root(field(object, "root", what)?, &format!("{what} root"))?;
    let target_identity =
        parse_maybe_string(field(object, "target_identity", what)?, &format!("{what} target_identity"))?;
    let permission_granted = field_bool(object, "permission_granted", what)?;
    let image_width =
        parse_maybe_number(field(object, "image_width", what)?, &format!("{what} image_width"))?;
    let image_height =
        parse_maybe_number(field(object, "image_height", what)?, &format!("{what} image_height"))?;
    Ok(CurrentGeometry {
        step,
        perceptual_hash,
        crop_origin_x: ox,
        crop_origin_y: oy,
        crop_width: cw,
        crop_height: ch,
        viewport_width: vw,
        viewport_height: vh,
        scale,
        frame_offset_x,
        frame_offset_y,
        layout_digest,
        root,
        target_identity,
        permission_granted,
        image_width,
        image_height,
    })
}

fn parse_bbox(value: &Value, what: &str) -> Result<BBoxProposal, ConnectorError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(format!("{what} must be an object")))?;
    ensure_closed(object, &["x", "y", "width", "height"], what)?;
    let parse_one = |name: &str| -> Result<MaybeNumber, ConnectorError> {
        parse_maybe_number(field(object, name, what)?, &format!("{what} {name}"))
    };
    Ok(BBoxProposal {
        x: parse_one("x")?,
        y: parse_one("y")?,
        width: parse_one("width")?,
        height: parse_one("height")?,
    })
}

// ---------------------------------------------------------------------------
// Recovery step (§10.3 inputs + §10.5 learning state)
// ---------------------------------------------------------------------------

struct ParsedStep {
    step_id: String,
    failed_recipe: rm_targets::TargetRecipe,
    current_root: BORootRef,
    authorization_ref: EvidenceRef,
    limit: DurationLimit,
    now: TimePoint,
    active_deadline: TimePoint,
    recovery_allowance_remaining: u64,
    fallback_text: String,
    commissioned_job: String,
    commissioned_target: String,
    heal_profile_policy: VersionPin,
    provider_policy: ModelVersionPin,
    models_binding: ModelBinding,
    models_budgets: ModelBudgets,
    models_manifest: Manifest,
    coordinate_entry: Option<CoordinateEntry>,
    current_geometry: Option<CurrentGeometry>,
    bbox_proposal: Option<BBoxProposal>,
}

fn parse_optional_missing<T>(
    value: &Value,
    what: &str,
    parse_present: impl FnOnce(&Value, &str) -> Result<T, ConnectorError>,
) -> Result<Option<T>, ConnectorError> {
    if is_missing_envelope(value) {
        let missing = parse_missing(value, what)?;
        // Coordinate/bbox absence must be reasoned; bare omission is rejected
        // by the closed step check before this runs.
        let _ = missing;
        return Ok(None);
    }
    if value.is_null() {
        return Err(invalid(format!(
            "{what} must not be a bare null; use a Missing envelope"
        )));
    }
    Ok(Some(parse_present(value, what)?))
}

fn parse_step(bytes: &[u8]) -> Result<ParsedStep, ConnectorError> {
    rm_wire::canonical_digest(bytes)
        .map_err(|e| invalid(format!("step bytes rejected: {e}")))?;
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|e| invalid(format!("step bytes are not JSON: {e}")))?;
    let object = value
        .as_object()
        .ok_or_else(|| invalid("step must be a JSON object"))?;
    const ALLOWED: [&str; 21] = [
        "record_type",
        "schema_version",
        "step_id",
        "failed_recipe",
        "current_root",
        "authorization_ref",
        "limit",
        "now",
        "active_deadline",
        "recovery_allowance_remaining",
        "fallback_text",
        "commissioned_job",
        "commissioned_target",
        "heal_profile_policy",
        "provider_policy",
        "models_binding",
        "models_budgets",
        "models_manifest",
        "coordinate_entry",
        "current_geometry",
        "bbox_proposal",
    ];
    ensure_closed(object, &ALLOWED, "recovery step")?;
    let record_type = field_str(object, "record_type", "recovery step")?;
    let schema_version = field_str(object, "schema_version", "recovery step")?;
    if record_type != RECOVERY_STEP_RECORD_TYPE {
        return Err(invalid(format!(
            "step record_type {record_type:?} must be {RECOVERY_STEP_RECORD_TYPE:?}"
        )));
    }
    if schema_version != RECOVERY_STEP_SCHEMA_VERSION {
        return Err(invalid(format!(
            "step schema_version {schema_version:?} must be {RECOVERY_STEP_SCHEMA_VERSION:?}"
        )));
    }
    let step_id = field_str(object, "step_id", "recovery step")?.to_string();
    require_nonempty("step step_id", &step_id)?;
    // Failed recipe reuses the Tier 1 closed parser so recovery never invents
    // recipe fields.
    let failed_recipe_value = field(object, "failed_recipe", "recovery step")?.clone();
    let failed_recipe_bytes = serde_json::to_vec(&failed_recipe_value)
        .map_err(|e| invalid(format!("failed_recipe serializes: {e}")))?;
    let failed_recipe = rm_targets::parse_target_recipe(&failed_recipe_bytes).map_err(|e| {
        invalid(format!("failed_recipe invalid: {} [{}] {}", e.code, e.fault_domain, e.detail))
    })?;
    let current_root = parse_root(
        field(object, "current_root", "recovery step")?,
        "step current_root",
    )?;
    let authorization_ref = EvidenceRef::from_json(field(object, "authorization_ref", "recovery step")?)?;
    authorization_ref
        .validate()
        .map_err(|e| invalid(format!("step authorization_ref invalid: {}", e.detail)))?;
    let limit = parse_duration_limit(field(object, "limit", "recovery step")?, "step limit")?;
    let now = parse_timepoint(field(object, "now", "recovery step")?, "step now")?;
    let active_deadline = parse_timepoint(
        field(object, "active_deadline", "recovery step")?,
        "step active_deadline",
    )?;
    let recovery_allowance_remaining = field_u64(object, "recovery_allowance_remaining", "recovery step")?;
    let fallback_text = field_str(object, "fallback_text", "recovery step")?.to_string();
    let commissioned_job = field_str(object, "commissioned_job", "recovery step")?.to_string();
    let commissioned_target = field_str(object, "commissioned_target", "recovery step")?.to_string();
    require_nonempty("step fallback_text", &fallback_text)?;
    require_nonempty("step commissioned_job", &commissioned_job)?;
    require_nonempty("step commissioned_target", &commissioned_target)?;
    let heal_profile_policy = parse_catalog_pin(
        field(object, "heal_profile_policy", "recovery step")?,
        "step heal_profile_policy",
    )?;
    let provider_policy = parse_model_pin(
        field(object, "provider_policy", "recovery step")?,
        "step provider_policy",
    )?;
    let models_binding = parse_model_binding(
        field(object, "models_binding", "recovery step")?,
        "step models_binding",
    )?;
    let models_budgets = parse_model_budgets(
        field(object, "models_budgets", "recovery step")?,
        "step models_budgets",
    )?;
    let models_manifest = parse_manifest(
        field(object, "models_manifest", "recovery step")?,
        "step models_manifest",
    )?;
    let coordinate_entry = parse_optional_missing(
        field(object, "coordinate_entry", "recovery step")?,
        "step coordinate_entry",
        parse_coordinate_entry,
    )?;
    let current_geometry = parse_optional_missing(
        field(object, "current_geometry", "recovery step")?,
        "step current_geometry",
        parse_current_geometry,
    )?;
    let bbox_proposal = parse_optional_missing(
        field(object, "bbox_proposal", "recovery step")?,
        "step bbox_proposal",
        parse_bbox,
    )?;
    // A coordinate entry without current geometry (or vice versa) cannot
    // revalidate: both must be present together.
    match (&coordinate_entry, &current_geometry) {
        (Some(_), None) => {
            return Err(revalidation_required(
                "coordinate_entry is present but current_geometry is missing: no action until revalidated",
            ))
        }
        (None, Some(_)) => {
            return Err(invalid(
                "current_geometry without a coordinate_entry is not a dHash hit; omit both for selector-only recovery",
            ))
        }
        _ => {}
    }
    Ok(ParsedStep {
        step_id,
        failed_recipe,
        current_root,
        authorization_ref,
        limit,
        now,
        active_deadline,
        recovery_allowance_remaining,
        fallback_text,
        commissioned_job,
        commissioned_target,
        heal_profile_policy,
        provider_policy,
        models_binding,
        models_budgets,
        models_manifest,
        coordinate_entry,
        current_geometry,
        bbox_proposal,
    })
}

// ---------------------------------------------------------------------------
// Failure routing (§10.2)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecoveryRoute {
    Proceed,
}

fn route_failure(failed_call: &BOPrimitiveRecord) -> Result<RecoveryRoute, ConnectorError> {
    // Unsupported grammar / unmapped primitive: explicit mapping limitation,
    // never selector healing.
    if failed_call.return_state == "unsupported" {
        return Err(unsupported_mapping(format!(
            "primitive {:?} is unmapped (return_state unsupported): explicit mapping limitation; not selector healing",
            failed_call.primitive
        )));
    }
    if failed_call.return_state != "returned" && failed_call.return_state != "failed" {
        return Err(invalid(format!(
            "failed_call return_state {:?} must be returned, failed, or unsupported",
            failed_call.return_state
        )));
    }
    // A returned call is not a recovery trigger.
    if failed_call.return_state == "returned" {
        return Err(invalid(
            "failed_call reports return_state returned: recovery requires a definite failure record",
        ));
    }
    let (code, native_entry, detail) = match &failed_call.error {
        rm_browseroxide::MaybeBOFailure::Present(failure) => (
            failure.code.clone(),
            failure.native_entry.clone(),
            failure.detail.clone(),
        ),
        rm_browseroxide::MaybeBOFailure::Missing(missing) => {
            return Err(invalid(format!(
                "failed_call with return_state failed carries Missing error (reason {:?}): a failure record is required",
                missing.reason
            )))
        }
    };
    let detail_lower = detail.to_lowercase();
    let code_upper = code.to_uppercase();
    // Wrong thread, authorization failure, ownership loss: stop/fence, never
    // selector healing.
    if code_upper == "WRONG_THREAD"
        || detail_lower.contains("wrong thread")
        || detail_lower.contains("owning os thread")
        || detail_lower.contains("not the owning")
    {
        return Err(fenced(format!(
            "wrong-thread failure ({code} [{native_entry}]): stop/fence; not selector healing"
        )));
    }
    if code_upper == "FORBIDDEN"
        || code_upper == "NOT_ADMITTED"
        || code_upper == "FENCED"
        || detail_lower.contains("authorization")
        || detail_lower.contains("not admitted")
        || detail_lower.contains("ownership")
        || detail_lower.contains("fenced")
        || detail_lower.contains("owner loss")
        || detail_lower.contains("lease")
    {
        return Err(fenced(format!(
            "authorization/ownership failure ({code} [{native_entry}]): stop/fence; not selector healing"
        )));
    }
    // Storage unavailable before intent: no mutation.
    if native_entry == "not_entered"
        && (detail_lower.contains("not retained")
            || detail_lower.contains("bytes are not retained")
            || detail_lower.contains("storage")
            || detail_lower.contains("inputs_incomplete")
            || code_upper == "INPUTS_INCOMPLETE")
    {
        return Err(prerequisite(format!(
            "storage unavailable before intent ({code} [{native_entry}]): no mutation"
        )));
    }
    // Possible side effect: reconcile before any action retry, never replay
    // as selector recovery.
    let is_mutating = MUTATING_PRIMITIVES.contains(&failed_call.primitive.as_str());
    if !failed_call.effect_refs.is_empty() {
        return Err(reconcile_required(format!(
            "failed {} carries {} effect reference(s): possible side effect; reconcile before action retry, never replay as selector recovery",
            failed_call.primitive,
            failed_call.effect_refs.len()
        )));
    }
    if is_mutating && native_entry != "not_entered" {
        return Err(reconcile_required(format!(
            "mutating {} entered native code (native_entry {native_entry:?}) before failing ({code}): possible side effect; reconcile before retry",
            failed_call.primitive
        )));
    }
    // Unsupported selector grammar surfaced as INVALID_INPUT: explicit
    // limitation, not healing.
    if detail_lower.contains("unsupported selector grammar")
        || detail_lower.contains("unsupported-grammar")
        || detail_lower.contains("explicit; no alternate engine")
    {
        return Err(unsupported_mapping(format!(
            "unsupported grammar ({code}): explicit mapping limitation; not selector healing"
        )));
    }
    // Remaining definite failures divide into recoverable (no match,
    // ambiguity, pre-entry stale target, definite no-entry action failure)
    // and non-recoverable. Pre-entry failures (not_entered) without effects
    // are safe to route to recovery when authorized and budgeted.
    if native_entry == "not_entered" {
        return Ok(RecoveryRoute::Proceed);
    }
    // Entered read-only failures (e.g. dom_read RESPONSE_LIMIT after entry)
    // without effects are also safe: no application mutation occurred.
    if !is_mutating {
        return Ok(RecoveryRoute::Proceed);
    }
    // Any other mutating post-entry failure is treated as a possible side
    // effect even without explicit effect refs.
    Err(reconcile_required(format!(
        "mutating {} failed after native entry ({code} [{native_entry}]): possible side effect; reconcile before retry",
        failed_call.primitive
    )))
}

// ---------------------------------------------------------------------------
// dHash reuse validation (§10.5, RM-C41)
// ---------------------------------------------------------------------------

fn same_root(a: &BORootRef, b: &BORootRef) -> bool {
    a == b
}

/// Validates that a dHash hit may revalidate against the current layout.
///
/// A dHash match is image similarity only. Reuse requires compatible step,
/// root, crop, viewport, scale, frame offset, layout, target identity, and
/// permission. Any mismatch, any missing geometry (never defaulted), or any
/// full-viewport silent fallback blocks action with `REVALIDATION_REQUIRED`.
fn check_dhash_reuse(entry: &CoordinateEntry, current: &CurrentGeometry) -> Result<(), ConnectorError> {
    // Image similarity gate: different hashes are not a hit at all.
    if entry.perceptual_hash != current.perceptual_hash {
        return Err(target_not_found(
            "dHash mismatch: no coordinate-cache hit; selector recovery must not treat similarity as identity",
        ));
    }
    // Coordinate-space compatibility: this baseline grounds viewport CSS only.
    if entry.coordinate_space != "viewport_css" {
        return Err(revalidation_required(format!(
            "dHash hit in coordinate space {:?} is not viewport_css: no action until revalidated",
            entry.coordinate_space
        )));
    }
    // Step compatibility.
    if entry.step != current.step {
        return Err(revalidation_required(format!(
            "dHash hit for step {:?} does not apply to step {:?}: no action until revalidated",
            entry.step, current.step
        )));
    }
    // Root compatibility: same native scope, including generations.
    if !same_root(&entry.root, &current.root) {
        return Err(revalidation_required(
            "dHash hit names a different native root (frame/document/root/generation): no action until revalidated",
        ));
    }
    // All current geometry must be explicit numbers; Missing is never zero
    // or scale one.
    let crop_ox = maybe_number_value(&current.crop_origin_x, "current_geometry crop origin_x")?;
    let crop_oy = maybe_number_value(&current.crop_origin_y, "current_geometry crop origin_y")?;
    let crop_w = maybe_number_value(&current.crop_width, "current_geometry crop width")?;
    let crop_h = maybe_number_value(&current.crop_height, "current_geometry crop height")?;
    let viewport_w = maybe_number_value(&current.viewport_width, "current_geometry viewport width")?;
    let viewport_h = maybe_number_value(&current.viewport_height, "current_geometry viewport height")?;
    let scale = maybe_number_value(&current.scale, "current_geometry scale")?;
    let fox = maybe_number_value(&current.frame_offset_x, "current_geometry frame_offset_x")?;
    let foy = maybe_number_value(&current.frame_offset_y, "current_geometry frame_offset_y")?;
    let layout = maybe_string_text(&current.layout_digest, "current_geometry layout_digest")?;
    let target = maybe_string_text(&current.target_identity, "current_geometry target_identity")?;
    let _image_w = maybe_number_value(&current.image_width, "current_geometry image_width")?;
    let _image_h = maybe_number_value(&current.image_height, "current_geometry image_height")?;
    if crop_ox < 0.0 || crop_oy < 0.0 {
        return Err(invalid("current_geometry crop origin must be nonnegative"));
    }
    if crop_w <= 0.0 || crop_h <= 0.0 {
        return Err(invalid("current_geometry crop size must be positive"));
    }
    if viewport_w <= 0.0 || viewport_h <= 0.0 {
        return Err(invalid("current_geometry viewport must be positive"));
    }
    if !scale.is_finite() || scale <= 0.0 {
        return Err(invalid("current_geometry scale must be finite positive"));
    }
    // The baseline crop is a localized failing-container crop plus padding,
    // clipped under policy. It never silently becomes full viewport.
    let is_full_viewport =
        crop_ox == 0.0 && crop_oy == 0.0 && crop_w == viewport_w && crop_h == viewport_h;
    if is_full_viewport {
        return Err(revalidation_required(
            "current_geometry crop equals the full viewport: the baseline crop never silently becomes full viewport; missing suitable container is explicit",
        ));
    }
    // Crop/viewport/scale/frame/layout compatibility: exact equality on
    // measured values. Any drift blocks action.
    if (entry.crop_origin_x - crop_ox).abs() > f64::EPSILON
        || (entry.crop_origin_y - crop_oy).abs() > f64::EPSILON
        || (entry.crop_width - crop_w).abs() > f64::EPSILON
        || (entry.crop_height - crop_h).abs() > f64::EPSILON
    {
        return Err(revalidation_required(
            "dHash hit with changed crop geometry: no action until revalidated",
        ));
    }
    if (entry.viewport_width - viewport_w).abs() > f64::EPSILON
        || (entry.viewport_height - viewport_h).abs() > f64::EPSILON
    {
        return Err(revalidation_required(
            "dHash hit with changed viewport geometry: no action until revalidated",
        ));
    }
    if (entry.scale - scale).abs() > f64::EPSILON {
        return Err(revalidation_required(
            "dHash hit with changed scale: no action until revalidated",
        ));
    }
    if (entry.frame_offset_x - fox).abs() > f64::EPSILON
        || (entry.frame_offset_y - foy).abs() > f64::EPSILON
    {
        return Err(revalidation_required(
            "dHash hit with changed frame offsets: no action until revalidated",
        ));
    }
    if entry.layout_digest != layout {
        return Err(revalidation_required(
            "dHash hit with changed layout digest: no action until revalidated",
        ));
    }
    if entry.target_identity != target {
        return Err(revalidation_required(
            "dHash hit names a different target identity: no action until revalidated",
        ));
    }
    if !entry.permission_granted || !current.permission_granted {
        return Err(forbidden(
            "dHash hit lacks target permission: image similarity never authorizes action",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tier 3 bbox validation and measured transforms (§10.4)
// ---------------------------------------------------------------------------

struct ValidatedBBox {
    x: f64,
    y: f64,
    width: f64,
    height: f64,
    center_x: f64,
    center_y: f64,
}

fn validate_bbox(bbox: &BBoxProposal, what: &str) -> Result<ValidatedBBox, ConnectorError> {
    let x = maybe_number_value(&bbox.x, &format!("{what} x"))?;
    let y = maybe_number_value(&bbox.y, &format!("{what} y"))?;
    let width = maybe_number_value(&bbox.width, &format!("{what} width"))?;
    let height = maybe_number_value(&bbox.height, &format!("{what} height"))?;
    if !x.is_finite() || !y.is_finite() || !width.is_finite() || !height.is_finite() {
        return Err(invalid(format!("{what} must be finite numbers")));
    }
    if x < 0.0 || y < 0.0 {
        return Err(invalid(format!("{what} x/y must be nonnegative")));
    }
    if width <= 0.0 || height <= 0.0 {
        return Err(invalid(format!("{what} width/height must be positive")));
    }
    // Image-space center is x + width/2, y + height/2.
    let center_x = x + width / 2.0;
    let center_y = y + height / 2.0;
    if !center_x.is_finite() || !center_y.is_finite() {
        return Err(invalid(format!("{what} center must be finite")));
    }
    Ok(ValidatedBBox {
        x,
        y,
        width,
        height,
        center_x,
        center_y,
    })
}

/// Transforms an image-space center to viewport coordinates using actual
/// measured crop origin, scale, and frame offsets. Missing inputs are
/// errors, never zero or one.
fn transform_to_viewport(
    bbox: &ValidatedBBox,
    current: &CurrentGeometry,
) -> Result<(f64, f64), ConnectorError> {
    let crop_ox = maybe_number_value(&current.crop_origin_x, "transform crop origin_x")?;
    let crop_oy = maybe_number_value(&current.crop_origin_y, "transform crop origin_y")?;
    let scale = maybe_number_value(&current.scale, "transform scale")?;
    let fox = maybe_number_value(&current.frame_offset_x, "transform frame_offset_x")?;
    let foy = maybe_number_value(&current.frame_offset_y, "transform frame_offset_y")?;
    let viewport_w = maybe_number_value(&current.viewport_width, "transform viewport width")?;
    let viewport_h = maybe_number_value(&current.viewport_height, "transform viewport height")?;
    let image_w = maybe_number_value(&current.image_width, "transform image_width")?;
    let image_h = maybe_number_value(&current.image_height, "transform image_height")?;
    // Image-bounds validation: the box must lie inside the actual capture.
    if bbox.x + bbox.width > image_w + f64::EPSILON || bbox.y + bbox.height > image_h + f64::EPSILON {
        return Err(invalid(format!(
            "bbox [{},{} {}x{}] exceeds image bounds {}x{}",
            bbox.x, bbox.y, bbox.width, bbox.height, image_w, image_h
        )));
    }
    if image_w <= 0.0 || image_h <= 0.0 || viewport_w <= 0.0 || viewport_h <= 0.0 {
        return Err(invalid("image/viewport bounds must be positive"));
    }
    // Measured transform: viewport = crop_origin + image_center * scale + frame_offset.
    let viewport_x = crop_ox + bbox.center_x * scale + fox;
    let viewport_y = crop_oy + bbox.center_y * scale + foy;
    if !viewport_x.is_finite() || !viewport_y.is_finite() {
        return Err(invalid("transformed viewport point must be finite"));
    }
    if viewport_x < 0.0 || viewport_y < 0.0 || viewport_x > viewport_w || viewport_y > viewport_h {
        return Err(revalidation_required(format!(
            "transformed point ({viewport_x},{viewport_y}) lies outside viewport {viewport_w}x{viewport_h}: no action until revalidated",
        )));
    }
    Ok((viewport_x, viewport_y))
}

// ---------------------------------------------------------------------------
// Tier 2 prompt (§10.3 inputs)
// ---------------------------------------------------------------------------

/// Builds the closed Tier 2 prompt bytes deterministically.
///
/// Inputs are the bounded HEAL reduction text, fallback text, failed
/// selector/recipe, scoped section labels, relevant limitations,
/// commissioned job/target, and the current root identity. The output never
/// contains bare nulls.
pub fn build_tier2_prompt_bytes(
    heal_reduction: &str,
    fallback_text: &str,
    failed_selector: &str,
    failed_recipe: &str,
    section_labels: &[String],
    limitations: &[String],
    commissioned_job: &str,
    commissioned_target: &str,
    current_root: &str,
) -> Result<Vec<u8>, ConnectorError> {
    require_nonempty("prompt heal_reduction", heal_reduction)?;
    require_nonempty("prompt fallback_text", fallback_text)?;
    require_nonempty("prompt failed_selector", failed_selector)?;
    require_nonempty("prompt failed_recipe", failed_recipe)?;
    require_nonempty("prompt commissioned_job", commissioned_job)?;
    require_nonempty("prompt commissioned_target", commissioned_target)?;
    require_nonempty("prompt current_root", current_root)?;
    if section_labels.is_empty() {
        return Err(invalid("prompt section_labels must be nonempty"));
    }
    for label in section_labels {
        require_nonempty("prompt section label", label)?;
    }
    for limitation in limitations {
        require_nonempty("prompt limitation", limitation)?;
    }
    if heal_reduction.as_bytes().len() > rm_models::HEAL_CEILING_BYTES {
        return Err(forbidden(format!(
            "heal_reduction has {} bytes, exceeding the bounded HEAL ceiling",
            heal_reduction.as_bytes().len()
        )));
    }
    let value = json!({
        "heal_reduction": heal_reduction,
        "fallback_text": fallback_text,
        "failed_selector": failed_selector,
        "failed_recipe": failed_recipe,
        "section_labels": section_labels,
        "limitations": limitations,
        "commissioned_job": commissioned_job,
        "commissioned_target": commissioned_target,
        "current_root": current_root,
        "effect_policy_note": "effect safety is rechecked after re-resolution; the prompt never authorizes mutation",
    });
    let bytes = serde_json::to_vec(&value)
        .map_err(|e| invalid(format!("prompt serializes: {e}")))?;
    rm_wire::canonical_digest(&bytes)
        .map_err(|e| invalid(format!("prompt bytes rejected: {e}")))?;
    if bytes.len() > rm_models::HEAL_CEILING_BYTES {
        return Err(forbidden(format!(
            "prompt has {} bytes, exceeding the bounded HEAL ceiling",
            bytes.len()
        )));
    }
    Ok(bytes)
}

fn install_restricted(
    principal: &AuthenticatedPrincipal,
    bytes: &[u8],
    media_type: &str,
    owner_domain: &str,
) -> Result<ArtifactReference, ConnectorError> {
    let reference = ArtifactReference {
        digest: rm_wire::artifact_digest(bytes),
        size_bytes: bytes.len() as u64,
        media_type: media_type.to_string(),
        owner_domain: owner_domain.to_string(),
        access: AccessClass::Restricted,
    };
    rm_evidence::install_artifact(principal, &reference, bytes)
}

fn install_public(
    principal: &AuthenticatedPrincipal,
    bytes: &[u8],
    media_type: &str,
    owner_domain: &str,
) -> Result<ArtifactReference, ConnectorError> {
    let reference = ArtifactReference {
        digest: rm_wire::artifact_digest(bytes),
        size_bytes: bytes.len() as u64,
        media_type: media_type.to_string(),
        owner_domain: owner_domain.to_string(),
        access: AccessClass::Public,
    };
    rm_evidence::install_artifact(principal, &reference, bytes)
}

fn recovery_operation(preparation: &PreparedTask) -> Result<Operation, ConnectorError> {
    require_nonempty(
        "preparation configuration connector_id",
        &preparation.configuration.connector_id,
    )?;
    require_nonempty(
        "preparation configuration subject_id",
        &preparation.configuration.subject.subject_id,
    )?;
    require_nonempty("preparation scope activity", &preparation.scope.activity)?;
    Ok(Operation {
        verb: "Observe".to_string(),
        connector_id: preparation.configuration.connector_id.clone(),
        subject_id: preparation.configuration.subject.subject_id.clone(),
        task_scope: preparation.scope.activity.clone(),
        account_binding: None,
        artifact_refs: Vec::new(),
        control_target: None,
    })
}

fn check_preparation_handle(
    preparation: &PreparedTask,
    handle: &ConnectorHandle,
) -> Result<(), ConnectorError> {
    if preparation.record_type != "connector_preparation" {
        return Err(invalid(format!(
            "preparation record_type {:?} must be connector_preparation",
            preparation.record_type
        )));
    }
    if handle.record_type != "connector_handle" {
        return Err(invalid(format!(
            "handle record_type {:?} must be connector_handle",
            handle.record_type
        )));
    }
    handle
        .validate()
        .map_err(|e| invalid(format!("handle invalid: {} [{}] {}", e.code, e.fault_domain, e.detail)))?;
    preparation
        .delivered_task
        .validate()
        .map_err(|e| invalid(format!("preparation delivered_task invalid: {}", e.detail)))?;
    if preparation.preparation_id != handle.preparation.preparation_id {
        return Err(invalid(format!(
            "preparation_id {:?} does not match handle preparation {:?}: stale/conflicting input rejected",
            preparation.preparation_id, handle.preparation.preparation_id
        )));
    }
    if preparation.scope.run_id != handle.scope.run_id
        || preparation.scope.journal_id != handle.scope.journal_id
        || preparation.scope.manifest_hash != handle.scope.manifest_hash
    {
        return Err(invalid(
            "preparation scope does not match handle scope: stale/conflicting input rejected",
        ));
    }
    Ok(())
}

fn verify_commissioned_intent(
    preparation: &PreparedTask,
    commissioned_job: &str,
    commissioned_target: &str,
) -> Result<(), ConnectorError> {
    if preparation.task.task_id != commissioned_job {
        return Err(forbidden(format!(
            "commissioned_job {:?} does not match prepared task {:?}: no model response may change task identity",
            commissioned_job, preparation.task.task_id
        )));
    }
    if preparation.task.entry.logical_id != commissioned_target {
        return Err(forbidden(format!(
            "commissioned_target {:?} does not match prepared entry {:?}: no model response may change target",
            commissioned_target, preparation.task.entry.logical_id
        )));
    }
    Ok(())
}

fn check_effect_safety(preparation: &PreparedTask, failed_call: &BOPrimitiveRecord) -> Result<(), ConnectorError> {
    let policy = preparation.task.effect_policy.as_str();
    if policy != "commissioned_application" && policy != "read_only" {
        return Err(invalid(format!("effect_policy {policy:?} unknown")));
    }
    if policy == "read_only" && MUTATING_PRIMITIVES.contains(&failed_call.primitive.as_str()) {
        return Err(forbidden(format!(
            "effect_policy read_only forbids recovery of mutating {}: effect safety recheck failed",
            failed_call.primitive
        )));
    }
    Ok(())
}

fn recipe_artifact_for_proposal(
    principal: &AuthenticatedPrincipal,
    proposal_selector: &str,
    proposal_strategy: &str,
    fallback_text: &str,
    resolver_policy: &VersionPin,
) -> Result<ArtifactReference, ConnectorError> {
    require_nonempty("proposal selector", proposal_selector)?;
    if !RECOVERY_STRATEGIES.contains(&proposal_strategy) {
        return Err(invalid(format!(
            "proposal strategy {proposal_strategy:?} is not in the closed vocabulary"
        )));
    }
    require_nonempty("recipe fallback_text", fallback_text)?;
    // Closed TargetRecipe bytes; the Tier 1 parser validates them before use.
    let recipe_value = json!({
        "frame_path": [],
        "shadow_path": [],
        "strategy": proposal_strategy,
        "query": proposal_selector,
        "exact": true,
        "max_matches": 10,
        "fallback_text": fallback_text,
        "resolver_policy": resolver_policy.to_json(),
    });
    let bytes = serde_json::to_vec(&recipe_value)
        .map_err(|e| invalid(format!("recipe serializes: {e}")))?;
    rm_wire::canonical_digest(&bytes)
        .map_err(|e| invalid(format!("recipe bytes rejected: {e}")))?;
    // Validate through the Tier 1 parser so only durable intent is installed.
    let _ = rm_targets::parse_target_recipe(&bytes).map_err(|e| {
        invalid(format!("recovery recipe invalid: {} [{}] {}", e.code, e.fault_domain, e.detail))
    })?;
    install_restricted(principal, &bytes, "application/json", "artifact")
}

// ---------------------------------------------------------------------------
// Tier 2 selector recovery (§10.3)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn tier2_recover(
    principal: &AuthenticatedPrincipal,
    session: &mut NativeSession,
    preparation: &PreparedTask,
    handle: &ConnectorHandle,
    step: &ParsedStep,
    failed_call: &BOPrimitiveRecord,
) -> Result<ArtifactReference, ConnectorError> {
    // Bounded HEAL reduction over the current root. No unbounded raw DOM
    // export crosses threads before reduction.
    let dom_request = BODomRead {
        root: step.current_root.clone(),
        selector: TimeMaybeString::Missing(Missing::new("not_applicable")),
        depth_limit: 100,
        byte_limit: 1_000_000,
        include_frames: true,
        include_accessible_shadow_roots: true,
    };
    let reduction_ref = rm_reduction::reduce_document(
        principal,
        session,
        &dom_request,
        HEAL_PROFILE,
        &step.heal_profile_policy,
        &step.authorization_ref,
        &step.limit,
    )?;
    let reduction_bytes = rm_evidence::load_artifact(principal, &reduction_ref)?;
    rm_wire::canonical_digest(&reduction_bytes)
        .map_err(|e| invalid(format!("reduction bytes rejected: {e}")))?;
    let reduction_value: Value = serde_json::from_slice(&reduction_bytes)
        .map_err(|e| invalid(format!("reduction is not JSON: {e}")))?;
    rm_reduction::RingmasterReduction::validate_json(&reduction_value).map_err(|e| {
        invalid(format!("reduction invalid: {} [{}] {}", e.code, e.fault_domain, e.detail))
    })?;
    let reduction_object = reduction_value
        .as_object()
        .ok_or_else(|| invalid("reduction must be an object"))?;
    let sections_value = reduction_object
        .get("sections")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("reduction requires sections"))?;
    let mut section_labels = Vec::new();
    for section in sections_value {
        let section_object = section
            .as_object()
            .ok_or_else(|| invalid("reduction section must be an object"))?;
        let section_id = section_object
            .get("section_id")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("reduction section requires section_id"))?;
        require_nonempty("reduction section_id", section_id)?;
        section_labels.push(section_id.to_string());
    }
    if section_labels.is_empty() {
        return Err(invalid("reduction carries no scoped section labels"));
    }
    // Deduplicate labels while preserving order.
    let mut seen = BTreeSet::new();
    section_labels.retain(|label| seen.insert(label.clone()));
    let limitations_value = reduction_object
        .get("limitations")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("reduction requires limitations"))?;
    let mut limitations = Vec::new();
    for item in limitations_value {
        let text = item
            .as_str()
            .ok_or_else(|| invalid("reduction limitation must be a string"))?;
        require_nonempty("reduction limitation", text)?;
        limitations.push(text.to_string());
    }
    limitations.push(format!(
        "recovery of {} after {} [{}]",
        step.failed_recipe.strategy,
        failed_call.primitive,
        failed_call.call_id
    ));
    let heal_reduction = String::from_utf8(reduction_bytes.clone())
        .map_err(|e| invalid(format!("reduction is not UTF-8: {e}")))?;
    let failed_selector = step.failed_recipe.query.clone();
    let failed_recipe = format!("{}:{}", step.failed_recipe.strategy, step.failed_recipe.query);
    let current_root_id = step.current_root.root_id.clone();
    let prompt_bytes = build_tier2_prompt_bytes(
        &heal_reduction,
        &step.fallback_text,
        &failed_selector,
        &failed_recipe,
        &section_labels,
        &limitations,
        &step.commissioned_job,
        &step.commissioned_target,
        &current_root_id,
    )?;
    // Restricted prompt: sensitive DOM/candidate data never leaves as public.
    let owner_domain = preparation.scope.owner_domain.clone();
    let prompt_ref = install_restricted(principal, &prompt_bytes, "application/json", &owner_domain)?;
    // Model conduit inputs: the durable handle maps to the models gate
    // handle; budgets/binding/policy come from the pinned step. Every
    // provider call counts against the same finite budgets; repair and
    // failover cannot create an unbounded loop.
    let operation = recovery_operation(preparation)?;
    let model_handle = rm_models::ConnectorHandle {
        record_type: "connector_handle".to_string(),
        schema_version: "external-connector/0.1.0".to_string(),
        connector_id: handle.handle.connector_id.clone(),
        local_handle: handle.handle.local_handle.clone(),
        preparation_id: handle.preparation.preparation_id.clone(),
        scope: preparation.scope.clone(),
        operation,
        manifest: step.models_manifest.clone(),
        idempotency_key: handle.idempotency_key.clone(),
        created_at: handle.created_at.clone(),
        active_deadline: step.active_deadline.clone(),
        now: step.now.clone(),
    };
    // Enforce the step-level recovery allowance before any provider byte is
    // consumed; the models gate enforces its own copy too. Neither is
    // extended because a tier failed.
    if step.recovery_allowance_remaining == 0 {
        return Err(forbidden(
            "recovery allowance is exhausted: no escalation",
        ));
    }
    if step.models_budgets.recovery_allowance_remaining == 0 {
        return Err(forbidden(
            "model recovery allowance is exhausted: no escalation",
        ));
    }
    let proposal_ref = rm_models::propose_recovery(
        principal,
        &model_handle,
        &step.models_binding,
        &prompt_ref,
        &step.provider_policy,
        &step.models_budgets,
    )?;
    let proposal_bytes = rm_evidence::load_artifact(principal, &proposal_ref)?;
    let proposal = rm_models::validate_proposal_bytes(&proposal_bytes).map_err(|e| {
        integrity(format!(
            "retained proposal failed closed validation: {} [{}] {}",
            e.code, e.fault_domain, e.detail
        ))
    })?;
    // A tentative model candidate is not a verified selector. Before action,
    // re-resolve against the current root, reject ambiguity/staleness,
    // verify commissioned intent, and recheck effect safety.
    verify_commissioned_intent(preparation, &step.commissioned_job, &step.commissioned_target)?;
    check_effect_safety(preparation, failed_call)?;
    let candidate_recipe = recipe_artifact_for_proposal(
        principal,
        &proposal.selector,
        &proposal.strategy,
        &step.fallback_text,
        &step.heal_profile_policy,
    )?;
    let resolved = rm_targets::resolve_target(
        principal,
        session,
        &candidate_recipe,
        &step.current_root,
        &step.authorization_ref,
        &step.limit,
    )?;
    // Re-resolution must yield exactly the scoped node; ambiguity/staleness
    // reject here via the Tier 1 errors. Verified cache replacement occurs
    // only after the configured operation/readback criterion, which lives
    // outside recovery: this tentative recipe is returned, never committed
    // to verified learning state.
    if resolved.nodes.len() != 1 {
        return Err(target_not_found(format!(
            "re-resolution yielded {} nodes, exactly one required",
            resolved.nodes.len()
        )));
    }
    if resolved.root != step.current_root {
        return Err(stale_reference(
            "re-resolved root does not match the current root: stale target rejected before mutation",
        ));
    }
    Ok(candidate_recipe)
}

// ---------------------------------------------------------------------------
// Tier 3 vision-assisted DOM grounding (§10.4)
// ---------------------------------------------------------------------------

fn tier3_recover(
    principal: &AuthenticatedPrincipal,
    session: &mut NativeSession,
    preparation: &PreparedTask,
    step: &ParsedStep,
    failed_call: &BOPrimitiveRecord,
    bbox: &BBoxProposal,
    current: &CurrentGeometry,
) -> Result<ArtifactReference, ConnectorError> {
    // Closed bbox validation + image-bounds + measured transform. Missing
    // geometry is never zero or scale one.
    let validated = validate_bbox(bbox, "step bbox_proposal")?;
    let (viewport_x, viewport_y) = transform_to_viewport(&validated, current)?;
    // Localized capture: failing-container crop plus 100px padding, clipped
    // under policy. Never silently full viewport. Missing suitable container
    // or invalid geometry is explicit.
    let crop_ox = maybe_number_value(&current.crop_origin_x, "tier3 crop origin_x")?;
    let crop_oy = maybe_number_value(&current.crop_origin_y, "tier3 crop origin_y")?;
    let crop_w = maybe_number_value(&current.crop_width, "tier3 crop width")?;
    let crop_h = maybe_number_value(&current.crop_height, "tier3 crop height")?;
    let viewport_w = maybe_number_value(&current.viewport_width, "tier3 viewport width")?;
    let viewport_h = maybe_number_value(&current.viewport_height, "tier3 viewport height")?;
    if crop_w <= 0.0 || crop_h <= 0.0 || viewport_w <= 0.0 || viewport_h <= 0.0 {
        return Err(invalid("tier3 crop/viewport must be positive"));
    }
    let padded_x = (crop_ox - TIER3_CROP_PADDING_PX).max(0.0);
    let padded_y = (crop_oy - TIER3_CROP_PADDING_PX).max(0.0);
    let padded_w = (crop_w + 2.0 * TIER3_CROP_PADDING_PX).min(viewport_w - padded_x);
    let padded_h = (crop_h + 2.0 * TIER3_CROP_PADDING_PX).min(viewport_h - padded_y);
    if padded_w <= 0.0 || padded_h <= 0.0 {
        return Err(invalid("tier3 padded crop is empty after clipping"));
    }
    let is_full_viewport =
        padded_x == 0.0 && padded_y == 0.0 && padded_w == viewport_w && padded_h == viewport_h;
    if is_full_viewport {
        return Err(revalidation_required(
            "tier3 crop would silently become full viewport: missing suitable container is explicit",
        ));
    }
    let capture_options_value = json!({
        "kind": "localized_crop",
        "origin_x": padded_x,
        "origin_y": padded_y,
        "width": padded_w,
        "height": padded_h,
        "viewport_width": viewport_w,
        "viewport_height": viewport_h,
        "padding_px": TIER3_CROP_PADDING_PX,
        "preparation_id": preparation.preparation_id,
        "step_id": step.step_id,
        "viewport_point": {"x": viewport_x, "y": viewport_y},
    });
    let capture_options_bytes = serde_json::to_vec(&capture_options_value)
        .map_err(|e| invalid(format!("capture options serialize: {e}")))?;
    let owner_domain = preparation.scope.owner_domain.clone();
    let capture_options_ref = install_restricted(
        principal,
        &capture_options_bytes,
        "application/json",
        &owner_domain,
    )?;
    let capture_request = rm_browseroxide::BOCapture {
        page: step.current_root.page.clone(),
        capture_options: capture_options_ref,
    };
    let capture_out = rm_browseroxide::capture(
        session,
        &capture_request,
        &step.authorization_ref,
        &step.limit,
    )?;
    let capture_value = match capture_out.value {
        Some(value) => value,
        None => {
            if capture_out.record.return_state == "unsupported" {
                return Err(unsupported_mapping(
                    "bo.capture is unmapped: explicit limitation; no invented coordinate-click primitive",
                ));
            }
            let detail = match &capture_out.record.error {
                rm_browseroxide::MaybeBOFailure::Present(failure) => {
                    format!("{} [{}] {}", failure.code, failure.native_entry, failure.detail)
                }
                rm_browseroxide::MaybeBOFailure::Missing(missing) => {
                    format!("missing reason {:?}", missing.reason)
                }
            };
            return Err(prerequisite(format!(
                "localized capture unavailable ({detail}): explicit limitation; no full-viewport fallback"
            )));
        }
    };
    // Capture geometry is retained evidence; the transform already used the
    // actual measured crop/scale/frame/viewport. An empty geometry list is
    // explicit, never a silent default.
    let _ = capture_value;
    // Pinned read-only V8/native hit-test observation at the transformed
    // viewport point. This is vision-assisted DOM grounding, not trusted
    // coordinate input. Missing hit-test or action mapping stops the path.
    // The pinned script is read-only and serializable; it never mutates.
    let hit_script_text = format!("hit-test hello at {viewport_x},{viewport_y}: document.elementFromPoint read-only");
    let hit_script_bytes = hit_script_text.as_bytes();
    let hit_script_ref = install_public(
        principal,
        hit_script_bytes,
        "application/javascript",
        "artifact",
    )?;
    let hit_request = rm_browseroxide::BOV8Evaluate {
        root: step.current_root.clone(),
        script: hit_script_ref,
        argument: rm_browseroxide::MaybeArtifact::Missing(Missing::new("not_applicable")),
    };
    let hit_out = rm_browseroxide::v8_evaluate(
        session,
        &hit_request,
        &step.authorization_ref,
        &step.limit,
    )?;
    let hit_value = match hit_out.value {
        Some(value) => value,
        None => {
            if hit_out.record.return_state == "unsupported" {
                return Err(unsupported_mapping(
                    "hit-test V8 evaluation is unmapped: missing hit-test stops the Tier 3 path",
                ));
            }
            return Err(prerequisite(
                "hit-test observation unavailable: missing hit-test stops the Tier 3 path",
            ));
        }
    };
    // Serializable hit-test description: only Present artifacts ground.
    let hit_description = match &hit_value.value {
        rm_browseroxide::MaybeArtifact::Present(reference) => {
            let bytes = rm_evidence::load_artifact(principal, reference).map_err(|e| {
                prerequisite(format!(
                    "hit-test description bytes unavailable: {} [{}] {}",
                    e.code, e.fault_domain, e.detail
                ))
            })?;
            String::from_utf8(bytes)
                .map_err(|e| invalid(format!("hit-test description is not UTF-8: {e}")))?
        }
        rm_browseroxide::MaybeArtifact::Missing(missing) => {
            return Err(prerequisite(format!(
                "hit-test returned missing (reason {:?}): missing hit-test stops the Tier 3 path",
                missing.reason
            )))
        }
    };
    if hit_description.trim().is_empty() {
        return Err(prerequisite(
            "hit-test description is empty: missing hit-test stops the Tier 3 path",
        ));
    }
    // Direct native target resolution and validation through the already
    // declared synthetic DOM action recipe. Ringmaster must not invent
    // `bo.click_at`: the result is a DOM recipe, not a coordinate click.
    // The hit-test text grounds a pinned text recipe over native observations.
    verify_commissioned_intent(preparation, &step.commissioned_job, &step.commissioned_target)?;
    check_effect_safety(preparation, failed_call)?;
    // Use the hit-test description as a pinned text query when it is a sane
    // nonempty label; otherwise fall back to the step fallback text. Neither
    // invents a coordinate primitive.
    let grounded_query = {
        let trimmed = hit_description.trim();
        if trimmed.is_empty() || trimmed.len() > 500 {
            step.fallback_text.clone()
        } else {
            trimmed.to_string()
        }
    };
    let grounded_recipe = recipe_artifact_for_proposal(
        principal,
        &grounded_query,
        "text",
        &step.fallback_text,
        &step.heal_profile_policy,
    )?;
    let resolved = rm_targets::resolve_target(
        principal,
        session,
        &grounded_recipe,
        &step.current_root,
        &step.authorization_ref,
        &step.limit,
    )
    .map_err(|e| {
        if e.code == "UNSUPPORTED_MAPPING" {
            unsupported_mapping(format!(
                "Tier 3 action mapping unsupported: {} [{}] {}",
                e.code, e.fault_domain, e.detail
            ))
        } else {
            e
        }
    })?;
    if resolved.nodes.len() != 1 {
        return Err(target_not_found(format!(
            "Tier 3 re-resolution yielded {} nodes, exactly one required",
            resolved.nodes.len()
        )));
    }
    if resolved.root != step.current_root {
        return Err(stale_reference(
            "Tier 3 re-resolved root does not match the current root: stale target rejected",
        ));
    }
    Ok(grounded_recipe)
}

// ---------------------------------------------------------------------------
// Public entry point (EXPOSES)
// ---------------------------------------------------------------------------

/// Recovers a failed target through bounded Tier 2 selector healing or Tier 3
/// vision-assisted DOM grounding.
///
/// Failure routing follows §10.2: no match, ambiguity, or pre-entry stale
/// targets route to recovery only when authorized and budgeted; unsupported
/// grammars report explicit mapping limitations; definite no-entry action
/// failures may proceed when effect-safe; possible side effects require
/// reconciliation before any retry; wrong-thread, authorization, and
/// ownership failures stop/fence without healing; storage-unavailable
/// failures never mutate; exhausted budgets or active deadlines never
/// escalate.
///
/// Tier 2 (§10.3) consumes the bounded HEAL reduction, fallback text, failed
/// selector/recipe, scoped section labels, and limitations, proposes one
/// closed selector through the pinned model conduit, then re-resolves
/// against the current root, rejects ambiguity/staleness, verifies
/// commissioned intent, and rechecks effect safety. The returned recipe is
/// tentative: verified cache replacement still requires the configured
/// operation/readback criterion.
///
/// Tier 3 (§10.4) requires actual localized capture, finite bbox geometry,
/// measured crop/scale/frame/viewport transforms, a pinned read-only
/// hit-test observation, and direct native resolution through the already
/// declared synthetic DOM recipe. It never invents `bo.click_at`, never
/// substitutes zero/unit defaults for missing geometry, never silently
/// falls back to full viewport, and never treats grounding as trusted
/// coordinate input.
///
/// Learning-state reuse (§10.5, RM-C41) treats a dHash match as image
/// similarity only: compatible step/root, crop, viewport, scale, frame
/// offset, layout, target identity, and permission are all required, and
/// any change or missing measurement blocks action until revalidated.
pub fn recover_target(
    principal: &AuthenticatedPrincipal,
    session: &mut NativeSession,
    preparation: &PreparedTask,
    handle: &ConnectorHandle,
    step: &ArtifactReference,
    failed_call: &BOPrimitiveRecord,
) -> Result<ArtifactReference, ConnectorError> {
    check_preparation_handle(preparation, handle)?;
    step.validate()
        .map_err(|e| invalid(format!("step reference invalid: {}", e.detail)))?;
    // §10.2 failure routing comes first: only safe, authorized, budgeted
    // failures proceed. Routing never extends budgets.
    route_failure(failed_call)?;
    // Load and validate the closed recovery step. Bare nulls, duplicate
    // keys, and non-finite numbers are rejected structurally.
    let step_bytes = rm_evidence::load_artifact(principal, step)?;
    let parsed = parse_step(&step_bytes)?;
    // Authority: every call is bound to an admitted task/resource grant.
    // Artifact references, scripts, node IDs, and URLs never grant authority.
    let operation = recovery_operation(preparation)?;
    rm_authority::authorize_work(principal, &preparation.scope, &operation)?;
    // Active deadline on the registered local clock. UTC is annotation only;
    // cross-clock/boot/origin ordering is rejected. Exhaustion never escalates.
    let expired = rm_time::boundary_reached(&parsed.now, &parsed.active_deadline)
        .map_err(|e| invalid(format!("active deadline cannot be ordered: {e}")))?;
    if expired {
        return Err(not_admitted(
            "active boundary reached before recovery: no escalation",
        ));
    }
    // Finite recovery budgets. Rejected work is not silently lost: the
    // caller receives an explicit exhaustion error.
    if preparation.task.budgets.recovery_limit == 0 {
        return Err(forbidden(
            "task recovery_limit of zero forbids recovery: no escalation",
        ));
    }
    if parsed.recovery_allowance_remaining == 0 {
        return Err(forbidden("recovery allowance is exhausted: no escalation"));
    }
    // Learning-state dHash gate (RM-C41): a hit with changed geometry or
    // layout blocks action until revalidated. Similarity never authorizes.
    if let (Some(entry), Some(current)) = (&parsed.coordinate_entry, &parsed.current_geometry) {
        check_dhash_reuse(entry, current)?;
    }
    // Tier selection: a present bbox proposal attempts Tier 3 grounding;
    // otherwise Tier 2 selector healing. Both re-resolve, verify intent,
    // and recheck effect safety before returning a tentative recipe.
    if let Some(bbox) = &parsed.bbox_proposal {
        let current = parsed.current_geometry.as_ref().ok_or_else(|| {
            revalidation_required(
                "Tier 3 bbox without current geometry: missing geometry is explicit, never zero or scale one",
            )
        })?;
        return tier3_recover(principal, session, preparation, &parsed, failed_call, bbox, current);
    }
    tier2_recover(principal, session, preparation, handle, &parsed, failed_call)
}




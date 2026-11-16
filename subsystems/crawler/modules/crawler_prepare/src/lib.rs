//! `crawler_prepare`: non-executing preparation gate for crawler tasks.
//!
//! [`prepare`] validates already supplied task data, scope, declarations,
//! schemas, permissions, budgets, state policy, mappings, supplied planning
//! evidence, and runtime-access grants. It records the native serialization
//! and the subject-facing task independently and grounds the evidence prefix
//! through an owner-local [`OwnerStore::read`]. It performs no target
//! request, auth test, planner execution, context reset, or hidden recovery:
//! there is no network, browser, planner, or reset dependency in this module,
//! and [`prepare`] never calls [`OwnerStore::transact`].
//!
//! [`verify_preparation`] revalidates an immutable preparation: exact
//! descriptor/subject/mapping/task pinning, hash integrity, budget-dimension
//! completeness, concern-ID uniqueness, and acceptance coverage for every
//! `requires_acceptance` concern under actual task authority. A stale
//! subject/configuration/mapping or changed artifact is rejected rather than
//! silently reprepared; blocking concerns never produce a startable
//! preparation (they fail [`prepare`] outright).
//!
//! # Record shapes
//!
//! All inputs are [`CheckedRecord`]s (no bare nulls; absent fields are typed
//! `Missing` envelopes and are treated as absent). The usual envelope schema
//! is `"audit_log"`; a record whose schema is `"state_mutation_record"` is
//! rejected outright.
//!
//! * `request` is a `PrepareRequest`-shaped object: `scope`, `configuration`,
//!   `task` (nested `TaskEnvelope`), `assistance`, `planning_evidence_refs`,
//!   `runtime_access`, and optional `preparation_measurements` (previously
//!   journaled planning costs, never a request to perform planning).
//! * `descriptor` is a `connector_descriptor`-shaped object carrying at least
//!   `connector_id`, `connector_version`, an exact `subject` pin, a complete
//!   `capabilities` catalog (checked via [`check_capability`]), and
//!   `task_mappings` with an entry for the task's `task_type`.
//! * The returned preparation is a `connector_preparation`-shaped object with
//!   `preparation_id`, `scope`, `configuration`, full `task`,
//!   `task_semantic_hash`, `assistance`, `planning_evidence_refs`,
//!   `runtime_access`, `delivered_task`/`delivered_task_hash`,
//!   `native_request`/`native_request_hash`, `translation`, five
//!   `budget_mapping` entries, `concerns`, and `evidence_prefix`.
//! * [`verify_preparation`] takes the preparation, the exact `configuration`
//!   it must still pin, and an `authorization` object carrying
//!   `accepted_concerns` (array of concern IDs) and `authorization_refs`.
//!
//! Forbidden execution markers (`invoke_planner`, `reset_context`, recovery
//!! requests, auth probes, browse/visit fields) are rejected with
//! `execution_forbidden`, never executed. Secret-bearing runtime fields
//! (`secret`, `password`, `credential`, `token`, `api_key`, control
//! credentials) are rejected with `secret_forbidden`: an opaque
//! `access_ref` is recorded verbatim and never resolved here.
//!
//! Fault codes: `mutation_rejected` (apply/commissioned_application or any
//! nested mutation via [`authorize_acquisition`]), `scope_violation`
//! (endpoint/entry origin outside admitted origins), `execution_forbidden`,
//! `secret_forbidden`, `invalid_request`, `invalid_scope`, `invalid_task`,
//! `invalid_configuration`, `invalid_descriptor`, `invalid_assistance`,
//! `invalid_runtime_access`, `subject_mismatch`, `scope_mismatch` (via
//! [`check_capability`]), `unsupported_mapping` (missing task mapping or
//! recovery without an owner), `unsupported_state_policy`,
//! `budget_mismatch`, `missing_planning_evidence`, `stale_configuration`,
//! `stale_descriptor`, `missing_acceptance`, `integrity_conflict`,
//! `invalid_preparation`, `invalid_authorization`. Authority/store faults
//! (`missing_grant_binding`, `digest_mismatch`, `unknown_journal`, ...)
//! propagate unchanged.

use crawler_authority::{grant_record, Grant};
use crawler_capabilities::check_capability;
use crawler_hashing::{canonical_bytes, digest_bytes};
use crawler_readonly::{authorize_acquisition, ReadOnlyRequest};
use crawler_schema::{record_schema, record_value, validate, CheckedRecord, Fault};
use crawler_store::OwnerStore;
use serde_json::{json, Map, Value};

// ---------------------------------------------------------------------------
// Closed vocabularies
// ---------------------------------------------------------------------------

/// Structural envelope for records produced by this module.
const OUTPUT_SCHEMA: &str = "audit_log";

/// External-connector record schema version stamped on preparations.
const SCHEMA_VERSION: &str = "external-connector/0.1.0";

const PREPARATION_RECORD_TYPE: &str = "connector_preparation";
const DESCRIPTOR_RECORD_TYPE: &str = "connector_descriptor";
const TASK_RECORD_TYPE: &str = "connector_task";

/// Crawler task types admitted here; never `apply`.
const CRAWLER_TASK_TYPES: &[&str] = &["discover_jobs", "extract"];

const READONLY_INTERFACES: &[&str] = &["ordinary_browser", "read_only_acquisition"];

const BROWSER_MODES: &[&str] = &["fresh", "reuse", "subject_default", "not_applicable"];
const LEARNING_MODES: &[&str] = &[
    "fresh",
    "reuse",
    "frozen",
    "subject_default",
    "not_applicable",
];
const REQUIREMENTS: &[&str] = &["required", "best_effort"];
const PLANNING_OWNERS: &[&str] = &["subject", "external_planner", "operator", "none"];
const RUNTIME_PURPOSES: &[&str] = &["application_entry", "account_session", "input_artifact"];

/// Five budget dimensions, exactly once each.
const BUDGET_DIMENSIONS: &[&str] = &[
    "active_observation",
    "action_count",
    "observation_bytes",
    "recovery_count",
    "model_tokens",
];

const CONCERN_CATEGORIES: &[&str] = &[
    "native_capability_absent",
    "native_capability_unknown",
    "budget_not_enforced",
    "state_policy_unverified",
    "assistance_limit",
    "observation_limit",
];
const CONCERN_DISPOSITIONS: &[&str] = &["requires_acceptance", "informational"];

/// Established fields that would request execution during Prepare. Prepare is
/// non-executing: these are rejected, never acted on.
const EXECUTION_FIELDS: &[&str] = &[
    "invoke_planner",
    "planner_request",
    "run_planner",
    "execute_plan",
    "reset_context",
    "reset",
    "context_reset",
    "page_reset",
    "recovery_request",
    "recover",
    "resume_request",
    "auth_probe",
    "probe_auth",
    "test_auth",
    "browse",
    "visit_target",
    "target_request",
    "fetch_target",
    "dispatch",
    "start_execution",
];

/// Secret-bearing keys that must never appear established in runtime access.
/// An opaque `access_ref` is not a secret; these keys would be.
const SECRET_FIELDS: &[&str] = &[
    "secret",
    "secret_bytes",
    "password",
    "credential",
    "credentials",
    "control_credentials",
    "token",
    "api_key",
    "apikey",
    "auth_token",
    "session_token",
];

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

fn fault(code: &str, detail: String) -> Fault {
    Fault {
        code: code.to_string(),
        detail,
    }
}

fn missing(reason: &str, detail: &str) -> Value {
    json!({"value": Value::Null, "reason": reason, "detail": detail})
}

/// True when `value` is a `Missing` envelope (`{"value": null, ...}`).
/// The schema gate has already validated the envelope shape.
fn is_missing(value: &Value) -> bool {
    value
        .as_object()
        .is_some_and(|map| map.get("value").is_some_and(Value::is_null))
}

/// The established (non-`Missing`) value of `field`, if any.
fn established<'a>(map: &'a Map<String, Value>, field: &str) -> Option<&'a Value> {
    map.get(field).filter(|value| !is_missing(value))
}

fn as_object<'a>(
    record: &'a CheckedRecord,
    code: &str,
    what: &str,
) -> Result<&'a Map<String, Value>, Fault> {
    record_value(record)
        .as_object()
        .ok_or_else(|| fault(code, format!("{what} must be an object")))
}

fn required_str<'a>(
    map: &'a Map<String, Value>,
    field: &str,
    code: &str,
    what: &str,
) -> Result<&'a str, Fault> {
    match established(map, field) {
        Some(Value::String(text)) if !text.is_empty() => Ok(text.as_str()),
        _ => Err(fault(
            code,
            format!("{what} requires an established nonempty string {field:?}"),
        )),
    }
}

fn required_u64(
    map: &Map<String, Value>,
    field: &str,
    code: &str,
    what: &str,
) -> Result<u64, Fault> {
    match established(map, field) {
        Some(Value::Number(number)) => number.as_u64().ok_or_else(|| {
            fault(
                code,
                format!("{what} field {field:?} must be an unsigned integer"),
            )
        }),
        _ => Err(fault(
            code,
            format!("{what} requires an established integer {field:?}"),
        )),
    }
}

fn required_object<'a>(
    map: &'a Map<String, Value>,
    field: &str,
    code: &str,
    what: &str,
) -> Result<&'a Map<String, Value>, Fault> {
    match established(map, field) {
        Some(Value::Object(inner)) => Ok(inner),
        _ => Err(fault(
            code,
            format!("{what} requires an established object {field:?}"),
        )),
    }
}

fn is_64hex(text: &str) -> bool {
    text.len() == 64
        && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_digest(text: &str) -> bool {
    text.strip_prefix("sha256:")
        .is_some_and(|hex| is_64hex(hex))
}

fn strip_digest_prefix(text: &str) -> &str {
    text.strip_prefix("sha256:").unwrap_or(text)
}

/// Reject any established execution-request field. Present-but-`Missing`
/// fields assert nothing and are treated as absent.
fn reject_execution_fields(map: &Map<String, Value>, what: &str) -> Result<(), Fault> {
    for field in EXECUTION_FIELDS {
        if established(map, field).is_some() {
            return Err(fault(
                "execution_forbidden",
                format!(
                    "{what} carries established {field:?}; Prepare is non-executing and never browses, probes auth, invokes a planner, resets context, or recovers"
                ),
            ));
        }
    }
    Ok(())
}

/// Finite configured duration `{kind: exact, unit: ms, value: >=0}`.
fn parse_duration_limit(
    map: &Map<String, Value>,
    field: &str,
    what: &str,
) -> Result<f64, Fault> {
    let inner = required_object(map, field, "invalid_request", what)?;
    match established(inner, "kind") {
        Some(Value::String(kind)) if kind == "exact" => {}
        _ => {
            return Err(fault(
                "invalid_request",
                format!("{what}.{field} kind must be exactly \"exact\""),
            ))
        }
    }
    match established(inner, "unit") {
        Some(Value::String(unit)) if unit == "ms" => {}
        _ => {
            return Err(fault(
                "invalid_request",
                format!("{what}.{field} unit must be exactly \"ms\""),
            ))
        }
    }
    match established(inner, "value") {
        Some(Value::Number(number)) => {
            let value = number.as_f64().ok_or_else(|| {
                fault(
                    "invalid_request",
                    format!("{what}.{field}.value must be a finite number"),
                )
            })?;
            if !value.is_finite() || value < 0.0 {
                return Err(fault(
                    "invalid_request",
                    format!("{what}.{field}.value must be finite and >= 0"),
                ));
            }
            Ok(value)
        }
        _ => Err(fault(
            "invalid_request",
            format!("{what}.{field} requires an established numeric value"),
        )),
    }
}

fn parse_version_pin(
    map: &Map<String, Value>,
    field: &str,
    what: &str,
) -> Result<Value, Fault> {
    let inner = required_object(map, field, "invalid_request", what)?;
    let id = required_str(inner, "id", "invalid_request", what)?.to_string();
    let version = required_str(inner, "version", "invalid_request", what)?.to_string();
    let digest = required_str(inner, "artifact_digest", "invalid_request", what)?.to_string();
    if !is_digest(&digest) {
        return Err(fault(
            "invalid_request",
            format!("{what}.{field}.artifact_digest must be a sha256: digest"),
        ));
    }
    Ok(json!({"id": id, "version": version, "artifact_digest": digest}))
}

fn parse_artifact_ref(
    map: &Map<String, Value>,
    field: &str,
    what: &str,
) -> Result<Value, Fault> {
    let inner = required_object(map, field, "invalid_request", what)?;
    let digest = required_str(inner, "digest", "invalid_request", what)?.to_string();
    if !is_digest(&digest) {
        return Err(fault(
            "invalid_request",
            format!("{what}.{field}.digest must be a sha256: digest"),
        ));
    }
    let size_bytes = required_u64(inner, "size_bytes", "invalid_request", what)?;
    let media_type = required_str(inner, "media_type", "invalid_request", what)?.to_string();
    let owner_domain = required_str(inner, "owner_domain", "invalid_request", what)?.to_string();
    let access = required_str(inner, "access", "invalid_request", what)?.to_string();
    if access != "public" && access != "restricted" {
        return Err(fault(
            "invalid_request",
            format!("{what}.{field}.access must be public or restricted"),
        ));
    }
    Ok(json!({
        "digest": digest,
        "size_bytes": size_bytes,
        "media_type": media_type,
        "owner_domain": owner_domain,
        "access": access,
    }))
}

/// Minimal evidence-ref shape check: journal coordinates plus a digest and a
/// JSON-pointer string. Referenced bytes are not fetched here.
fn check_evidence_ref(item: &Value, what: &str) -> Result<(), Fault> {
    let map = item.as_object().ok_or_else(|| {
        fault(
            "invalid_request",
            format!("{what} evidence refs must be objects"),
        )
    })?;
    required_str(map, "journal_id", "invalid_request", what)?;
    match established(map, "sequence") {
        Some(Value::Number(n)) if n.as_u64().is_some_and(|v| v >= 1) => {}
        _ => {
            return Err(fault(
                "invalid_request",
                format!("{what} evidence ref sequence must be an integer >= 1"),
            ))
        }
    }
    required_str(map, "event_id", "invalid_request", what)?;
    let hash = required_str(map, "event_hash", "invalid_request", what)?;
    if !is_digest(hash) {
        return Err(fault(
            "invalid_request",
            format!("{what} evidence ref event_hash must be a sha256: digest"),
        ));
    }
    match established(map, "pointer") {
        Some(Value::String(_)) => {}
        _ => {
            return Err(fault(
                "invalid_request",
                format!("{what} evidence ref requires an established pointer string"),
            ))
        }
    }
    Ok(())
}

fn check_evidence_refs(value: &Value, what: &str, min_items: usize) -> Result<(), Fault> {
    let items = value.as_array().ok_or_else(|| {
        fault(
            "invalid_request",
            format!("{what} requires an evidence-ref array"),
        )
    })?;
    if items.len() < min_items {
        return Err(fault(
            "invalid_request",
            format!("{what} requires at least {min_items} evidence ref(s)"),
        ));
    }
    for item in items {
        // SupportRefs entries are always established refs; a Missing envelope
        // inside the array asserts nothing and is rejected as malformed.
        if is_missing(item) {
            return Err(fault(
                "invalid_request",
                format!("{what} evidence refs must be established refs, not Missing"),
            ));
        }
        check_evidence_ref(item, what)?;
    }
    Ok(())
}

/// True when the value is an `Inapplicable` marker: either a
/// `Missing(not_applicable)` envelope or the literal string "Inapplicable".
fn is_inapplicable(value: &Value) -> bool {
    if let Some(text) = value.as_str() {
        return text == "Inapplicable";
    }
    if let Some(map) = value.as_object() {
        return map.get("value").is_some_and(Value::is_null)
            && map.get("reason").and_then(Value::as_str) == Some("not_applicable");
    }
    false
}

fn grant_owner_domain(grant: &Grant) -> String {
    record_value(grant_record(grant))
        .as_object()
        .and_then(|map| established(map, "owner_domain"))
        .and_then(Value::as_str)
        .unwrap_or("crawler")
        .to_string()
}

// ---------------------------------------------------------------------------
// Public interface
// ---------------------------------------------------------------------------

/// Validate a `PrepareRequest` without executing anything and return the
/// immutable preparation.
///
/// See the module docs for the expected `request`/`descriptor` shapes. The
/// only store interaction is one owner-local prefix `read` grounding
/// `evidence_prefix`; [`OwnerStore::transact`] is never called.
pub fn prepare(
    store: &dyn OwnerStore,
    grant: &Grant,
    request: &CheckedRecord,
    descriptor: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    if record_schema(request) == "state_mutation_record"
        || record_schema(descriptor) == "state_mutation_record"
    {
        return Err(fault(
            "mutation_rejected",
            "state_mutation_record is reserved and non-executing; no crawler transition inserts this record"
                .to_string(),
        ));
    }
    let req = as_object(request, "invalid_request", "request")?.clone();
    reject_execution_fields(&req, "request")?;

    // ---- scope (discovery WorkScope) ----
    let scope = required_object(&req, "scope", "invalid_request", "request")?.clone();
    reject_execution_fields(&scope, "scope")?;
    let activity = required_str(&scope, "activity", "invalid_scope", "scope")?;
    if activity != "discovery" {
        return Err(fault(
            "invalid_scope",
            "crawler Prepare admits only activity \"discovery\"; manual commissions are not dispatchable through this contract"
                .to_string(),
        ));
    }
    let run_id = required_str(&scope, "run_id", "invalid_scope", "scope")?.to_string();
    let journal_id = required_str(&scope, "journal_id", "invalid_scope", "scope")?.to_string();
    let manifest_hash = required_str(&scope, "manifest_hash", "invalid_scope", "scope")?.to_string();
    if !is_digest(&manifest_hash) {
        return Err(fault(
            "invalid_scope",
            "scope manifest_hash must be a sha256: digest".to_string(),
        ));
    }
    for field in ["attempt", "commission", "commission_ref"] {
        match scope.get(field) {
            Some(value) if is_inapplicable(value) => {}
            _ => {
                return Err(fault(
                    "invalid_scope",
                    format!(
                        "discovery scope requires {field:?} to be Inapplicable (Missing not_applicable); this crawler fabricates no application attempt or commission"
                    ),
                ))
            }
        }
    }
    let observation = required_object(
        &scope,
        "observation_policy",
        "invalid_scope",
        "scope",
    )?
    .clone();
    let scope_active = parse_duration_limit(&observation, "active_limit", "observation_policy")?;
    parse_duration_limit(&observation, "drain_limit", "observation_policy")?;
    parse_duration_limit(
        &observation,
        "native_cancel_wait_limit",
        "observation_policy",
    )?;
    parse_duration_limit(&observation, "cleanup_wait_limit", "observation_policy")?;
    match established(&observation, "fixture_close_action") {
        Some(Value::String(action)) if action == "not_applicable" => {}
        _ => {
            return Err(fault(
                "invalid_scope",
                "discovery observation_policy fixture_close_action must be \"not_applicable\""
                    .to_string(),
            ))
        }
    }
    let admission_ref = scope.get("admission_ref").ok_or_else(|| {
        fault(
            "invalid_scope",
            "scope requires admission_ref".to_string(),
        )
    })?;
    if is_missing(admission_ref) {
        return Err(fault(
            "invalid_scope",
            "scope admission_ref must be established".to_string(),
        ));
    }
    check_evidence_ref(admission_ref, "scope admission_ref")?;
    let authorization_refs = scope.get("authorization_refs").ok_or_else(|| {
        fault(
            "invalid_scope",
            "scope requires authorization_refs".to_string(),
        )
    })?;
    check_evidence_refs(authorization_refs, "scope authorization_refs", 1)?;

    // ---- configuration pin ----
    let configuration =
        required_object(&req, "configuration", "invalid_request", "request")?.clone();
    reject_execution_fields(&configuration, "configuration")?;
    let connector_id =
        required_str(&configuration, "connector_id", "invalid_configuration", "configuration")?
            .to_string();
    let connector_version = required_str(
        &configuration,
        "connector_version",
        "invalid_configuration",
        "configuration",
    )?
    .to_string();
    let _binding = parse_version_pin(&configuration, "binding", "configuration")?;
    let subject = required_object(
        &configuration,
        "subject",
        "invalid_configuration",
        "configuration",
    )?
    .clone();
    let subject_id = required_str(&subject, "subject_id", "invalid_configuration", "subject")?.to_string();
    let subject_version =
        required_str(&subject, "subject_version", "invalid_configuration", "subject")?.to_string();
    let configured_mode =
        required_str(&subject, "configured_mode", "invalid_configuration", "subject")?.to_string();
    let interface_surface = required_str(
        &subject,
        "interface_surface",
        "invalid_configuration",
        "subject",
    )?
    .to_string();
    let descriptor_ref_value = parse_artifact_ref(&configuration, "descriptor", "configuration")?;
    let descriptor_ref = configuration.get("descriptor_ref").ok_or_else(|| {
        fault(
            "invalid_configuration",
            "configuration requires descriptor_ref".to_string(),
        )
    })?;
    if is_missing(descriptor_ref) {
        return Err(fault(
            "invalid_configuration",
            "configuration descriptor_ref must be established".to_string(),
        ));
    }
    check_evidence_ref(descriptor_ref, "configuration descriptor_ref")?;

    // ---- descriptor pinning + capability honesty ----
    let desc_map = as_object(descriptor, "invalid_descriptor", "descriptor")?;
    match established(desc_map, "record_type") {
        Some(Value::String(record_type)) if record_type == DESCRIPTOR_RECORD_TYPE => {}
        _ => {
            return Err(fault(
                "invalid_descriptor",
                format!("descriptor record_type must be exactly {DESCRIPTOR_RECORD_TYPE:?}"),
            ))
        }
    }
    if let Some(Value::String(desc_connector)) = established(desc_map, "connector_id") {
        if desc_connector != &connector_id {
            return Err(fault(
                "stale_descriptor",
                format!(
                    "descriptor connector_id {desc_connector:?} does not match configuration {connector_id:?}; reject stale descriptors rather than silently repreparing"
                ),
            ));
        }
    }
    if let Some(Value::String(desc_version)) = established(desc_map, "connector_version") {
        if desc_version != &connector_version {
            return Err(fault(
                "stale_descriptor",
                format!(
                    "descriptor connector_version {desc_version:?} does not match configuration {connector_version:?}"
                ),
            ));
        }
    }
    let desc_subject = required_object(desc_map, "subject", "invalid_descriptor", "descriptor")?;
    for (field, expected) in [
        ("subject_id", subject_id.as_str()),
        ("subject_version", subject_version.as_str()),
        ("configured_mode", configured_mode.as_str()),
        ("interface_surface", interface_surface.as_str()),
    ] {
        match established(desc_subject, field).and_then(Value::as_str) {
            Some(actual) if actual == expected => {}
            _ => {
                return Err(fault(
                    "subject_mismatch",
                    format!(
                        "descriptor subject {field:?} does not match the configuration pin; Start accepts only the exact prepared subject"
                    ),
                ))
            }
        }
    }
    // The descriptor artifact digest pinned in the configuration must be the
    // digest of these exact descriptor bytes.
    let descriptor_hex = digest_bytes(&canonical_bytes(descriptor)?);
    let descriptor_digest = format!("sha256:{descriptor_hex}");
    let pinned_digest = descriptor_ref_value
        .get("digest")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if pinned_digest != descriptor_digest {
        return Err(fault(
            "stale_descriptor",
            "configuration.descriptor.digest does not match the supplied descriptor bytes; reject stale descriptors rather than silently repreparing"
                .to_string(),
        ));
    }
    // Exact-scope capability check: validates the catalog shape and pins the
    // descriptor to this subject/version/mode/surface without inheritance.
    let scope_record = validate(
        OUTPUT_SCHEMA,
        json!({
            "subject_id": subject_id,
            "subject_version": subject_version,
            "configured_mode": configured_mode,
            "interface_surface": interface_surface,
            "descriptor_digest": descriptor_digest,
        }),
    )?;
    let _goal_capability: CheckedRecord =
        check_capability(descriptor, "native_goal_task", &scope_record)?;

    // ---- task (nested TaskEnvelope) ----
    let task = required_object(&req, "task", "invalid_request", "request")?.clone();
    reject_execution_fields(&task, "task")?;
    if established(&task, "crawl_allotment").is_some() {
        return Err(fault(
            "invalid_task",
            "task must not introduce a Phase 1 crawl_allotment slot".to_string(),
        ));
    }
    for field in ["attempt", "commission", "application_credentials"] {
        if established(&task, field).is_some() {
            return Err(fault(
                "invalid_task",
                format!(
                    "crawler task must not carry {field:?}; discovery fabricates no application attempt"
                ),
            ));
        }
    }
    match established(&task, "record_type") {
        Some(Value::String(record_type)) if record_type == TASK_RECORD_TYPE => {}
        _ => {
            return Err(fault(
                "invalid_task",
                format!("task record_type must be exactly {TASK_RECORD_TYPE:?}"),
            ))
        }
    }
    let task_id = required_str(&task, "task_id", "invalid_task", "task")?.to_string();
    let task_type = required_str(&task, "task_type", "invalid_task", "task")?.to_string();
    if !CRAWLER_TASK_TYPES.contains(&task_type.as_str()) {
        return Err(fault(
            "mutation_rejected",
            format!(
                "task_type {task_type:?} is not admitted for crawler acquisition; never apply"
            ),
        ));
    }
    let entry = required_object(&task, "entry", "invalid_task", "task")?.clone();
    let entry_url = required_str(&entry, "url", "invalid_task", "entry")?.to_string();
    if !entry_url.starts_with("http://") && !entry_url.starts_with("https://") {
        return Err(fault(
            "invalid_task",
            "task entry url must be an absolute http(s) URL".to_string(),
        ));
    }
    // (Absolute-URL shape already checked above.)
    // Reject userinfo: credentials never travel in the entry URL.
    if let Some(after_scheme) = entry_url.split("://").nth(1) {
        let authority = after_scheme
            .split(['/', '?', '#'])
            .next()
            .unwrap_or_default();
        if authority.contains('@') {
            return Err(fault(
                "invalid_task",
                "task entry url must not carry userinfo or credentials".to_string(),
            ));
        }
    }
    required_str(&task, "goal", "invalid_task", "task")?;
    let criteria = match established(&task, "success_criteria") {
        Some(Value::Array(items)) if !items.is_empty() => items,
        _ => {
            return Err(fault(
                "invalid_task",
                "task requires a nonempty success_criteria array".to_string(),
            ))
        }
    };
    for (index, item) in criteria.iter().enumerate() {
        let criterion = item.as_object().ok_or_else(|| {
            fault(
                "invalid_task",
                format!("task success_criteria[{index}] must be an object"),
            )
        })?;
        required_str(criterion, "criterion_id", "invalid_task", "success_criterion")?;
        required_str(criterion, "description", "invalid_task", "success_criterion")?;
    }
    let inputs = match established(&task, "inputs") {
        Some(Value::Array(items)) => items.clone(),
        None => Vec::new(),
        _ => {
            return Err(fault(
                "invalid_task",
                "task inputs must be an array when present".to_string(),
            ))
        }
    };
    for (index, item) in inputs.iter().enumerate() {
        let input = item.as_object().ok_or_else(|| {
            fault(
                "invalid_task",
                format!("task inputs[{index}] must be an object"),
            )
        })?;
        required_str(input, "name", "invalid_task", "task input")?;
        required_str(input, "purpose", "invalid_task", "task input")?;
        if established(input, "content").is_none() {
            return Err(fault(
                "invalid_task",
                format!("task inputs[{index}] requires established content"),
            ));
        }
    }
    let permitted_origins = match established(&task, "permitted_origins") {
        Some(Value::Array(items)) if !items.is_empty() => items.clone(),
        _ => {
            return Err(fault(
                "invalid_task",
                "task requires a nonempty permitted_origins array".to_string(),
            ))
        }
    };
    let interfaces = match established(&task, "permitted_interfaces") {
        Some(Value::Array(items)) if !items.is_empty() => items,
        _ => {
            return Err(fault(
                "invalid_task",
                "task requires a nonempty permitted_interfaces array".to_string(),
            ))
        }
    };
    for item in interfaces {
        match item.as_str() {
            Some(interface) if READONLY_INTERFACES.contains(&interface) => {}
            _ => {
                return Err(fault(
                    "mutation_rejected",
                    "task permitted_interfaces admits only ordinary_browser and read_only_acquisition"
                        .to_string(),
                ))
            }
        }
    }
    match established(&task, "effect_policy").and_then(Value::as_str) {
        Some("read_only") => {}
        _ => {
            return Err(fault(
                "mutation_rejected",
                "crawler tasks require effect_policy \"read_only\"".to_string(),
            ))
        }
    }
    let budgets = required_object(&task, "budgets", "invalid_task", "task")?.clone();
    let task_active = parse_duration_limit(&budgets, "active_limit", "budgets")?;
    if (task_active - scope_active).abs() > f64::EPSILON {
        return Err(fault(
            "budget_mismatch",
            "task budgets.active_limit must equal the admitted observation policy active_limit"
                .to_string(),
        ));
    }
    let action_limit = required_u64(&budgets, "action_limit", "invalid_task", "budgets")?;
    let observation_byte_limit = required_u64(
        &budgets,
        "observation_byte_limit",
        "invalid_task",
        "budgets",
    )?;
    let recovery_limit = required_u64(&budgets, "recovery_limit", "invalid_task", "budgets")?;
    let model_token_limit = required_u64(&budgets, "model_token_limit", "invalid_task", "budgets")?;
    let _ = (action_limit, observation_byte_limit, model_token_limit);
    let context_policy =
        required_object(&task, "context_policy", "invalid_task", "task")?.clone();
    let browser_state =
        required_object(&context_policy, "browser_state", "invalid_task", "context_policy")?
            .clone();
    let learning_state = required_object(
        &context_policy,
        "learning_state",
        "invalid_task",
        "context_policy",
    )?
    .clone();
    let browser_mode = required_str(&browser_state, "mode", "invalid_task", "browser_state")?;
    if !BROWSER_MODES.contains(&browser_mode) {
        return Err(fault(
            "invalid_task",
            "browser_state mode must be one of fresh, reuse, subject_default, not_applicable (frozen is learning-only)"
                .to_string(),
        ));
    }
    let learning_mode = required_str(&learning_state, "mode", "invalid_task", "learning_state")?;
    if !LEARNING_MODES.contains(&learning_mode) {
        return Err(fault(
            "invalid_task",
            "learning_state mode must be one of fresh, reuse, frozen, subject_default, not_applicable"
                .to_string(),
        ));
    }
    let browser_requirement = required_str(
        &browser_state,
        "requirement",
        "invalid_task",
        "browser_state",
    )?;
    if !REQUIREMENTS.contains(&browser_requirement) {
        return Err(fault(
            "invalid_task",
            "browser_state requirement must be required or best_effort".to_string(),
        ));
    }
    let learning_requirement = required_str(
        &learning_state,
        "requirement",
        "invalid_task",
        "learning_state",
    )?;
    if !REQUIREMENTS.contains(&learning_requirement) {
        return Err(fault(
            "invalid_task",
            "learning_state requirement must be required or best_effort".to_string(),
        ));
    }
    // Browser-state and learning-state requests remain separate objects; a
    // Missing envelope in one does not satisfy the other.
    for (name, policy) in [("browser_state", &browser_state), ("learning_state", &learning_state)] {
        if policy.get("resource_ref").is_none() {
            return Err(fault(
                "invalid_task",
                format!("{name} requires resource_ref (a value or a Missing envelope)"),
            ));
        }
        if policy.get("baseline").is_none() {
            return Err(fault(
                "invalid_task",
                format!("{name} requires baseline (a value or a Missing envelope)"),
            ));
        }
    }
    // Reuse without an authorized resource binding is an unsupported required
    // policy: reject preparation rather than silently downgrading it.
    for (name, policy) in [("browser_state", &browser_state), ("learning_state", &learning_state)] {
        let mode = required_str(policy, "mode", "invalid_task", name)?;
        let requirement = required_str(policy, "requirement", "invalid_task", name)?;
        if mode == "reuse" && requirement == "required" && established(policy, "resource_ref").is_none() {
            return Err(fault(
                "unsupported_state_policy",
                format!("{name} mode reuse with requirement required needs an authorized resource_ref; required unsupported policies reject preparation"),
            ));
        }
    }
    let output_schema_value = match established(&task, "output_schema") {
        Some(Value::Object(_)) => {
            let inner = required_object(&task, "output_schema", "invalid_task", "task")?;
            let id = required_str(inner, "id", "invalid_task", "output_schema")?.to_string();
            let version =
                required_str(inner, "version", "invalid_task", "output_schema")?.to_string();
            let digest =
                required_str(inner, "artifact_digest", "invalid_task", "output_schema")?.to_string();
            if !is_digest(&digest) {
                return Err(fault(
                    "invalid_task",
                    "task output_schema.artifact_digest must be a sha256: digest".to_string(),
                ));
            }
            json!({"id": id, "version": version, "artifact_digest": digest})
        }
        _ => {
            return Err(fault(
                "invalid_task",
                "discover/extract tasks require an established output_schema VersionPin".to_string(),
            ))
        }
    };
    let _ = output_schema_value;

    // ---- assistance ----
    let assistance = required_object(&req, "assistance", "invalid_request", "request")?.clone();
    reject_execution_fields(&assistance, "assistance")?;
    let planning_owner = required_str(&assistance, "planning_owner", "invalid_assistance", "assistance")?;
    if !PLANNING_OWNERS.contains(&planning_owner) {
        return Err(fault(
            "invalid_assistance",
            "assistance planning_owner must be one of subject, external_planner, operator, none"
                .to_string(),
        ));
    }
    required_str(
        &assistance,
        "assistance_track",
        "invalid_assistance",
        "assistance",
    )?;
    if assistance.get("planner_identity").is_none() {
        return Err(fault(
            "invalid_assistance",
            "assistance requires planner_identity (a value or a Missing envelope)".to_string(),
        ));
    }
    if assistance.get("plan").is_none() {
        return Err(fault(
            "invalid_assistance",
            "assistance requires plan (an artifact or a Missing envelope)".to_string(),
        ));
    }
    let online_replanning = match established(&assistance, "online_replanning") {
        Some(Value::Bool(flag)) => *flag,
        _ => {
            return Err(fault(
                "invalid_assistance",
                "assistance requires an established boolean online_replanning".to_string(),
            ))
        }
    };
    required_str(&assistance, "description", "invalid_assistance", "assistance")?;

    let planning_refs = match req.get("planning_evidence_refs") {
        Some(Value::Array(items)) => items.clone(),
        _ => {
            return Err(fault(
                "invalid_request",
                "request requires a planning_evidence_refs array".to_string(),
            ))
        }
    };
    for item in &planning_refs {
        if is_missing(item) {
            return Err(fault(
                "invalid_request",
                "planning_evidence_refs must be established refs, not Missing".to_string(),
            ));
        }
        check_evidence_ref(item, "planning_evidence_refs")?;
    }
    // Recorded-plan mappings require the plan's public-observation provenance.
    if established(&assistance, "plan").is_some() && planning_refs.is_empty() {
        return Err(fault(
            "missing_planning_evidence",
            "assistance carries a plan but planning_evidence_refs is empty; recorded-plan mappings require public-observation evidence"
                .to_string(),
        ));
    }
    if let Some(measurements) = req.get("preparation_measurements") {
        if !matches!(measurements, Value::Array(_)) {
            return Err(fault(
                "invalid_request",
                "preparation_measurements must be an array when present".to_string(),
            ));
        }
        // Previously journaled costs only; Prepare performs no planning and
        // treats these as inert evidence, never as work to do.
    }

    // ---- runtime access (opaque refs only; never resolved here) ----
    let runtime_access = match req.get("runtime_access") {
        Some(Value::Array(items)) => items.clone(),
        _ => {
            return Err(fault(
                "invalid_request",
                "request requires a runtime_access array".to_string(),
            ))
        }
    };
    for (index, item) in runtime_access.iter().enumerate() {
        let entry = item.as_object().ok_or_else(|| {
            fault(
                "invalid_runtime_access",
                format!("runtime_access[{index}] must be an object"),
            )
        })?;
        let purpose = required_str(entry, "purpose", "invalid_runtime_access", "runtime_access")?;
        if !RUNTIME_PURPOSES.contains(&purpose) {
            return Err(fault(
                "invalid_runtime_access",
                "runtime_access purpose must be one of application_entry, account_session, input_artifact"
                    .to_string(),
            ));
        }
        required_str(entry, "access_ref", "invalid_runtime_access", "runtime_access")?;
        match entry.get("authorization_refs") {
            Some(Value::Array(refs)) if !refs.is_empty() => {
                for reference in refs {
                    if is_missing(reference) {
                        return Err(fault(
                            "invalid_runtime_access",
                            format!(
                                "runtime_access[{index}] authorization_refs must be established refs"
                            ),
                        ));
                    }
                    check_evidence_ref(reference, "runtime_access authorization_refs")?;
                }
            }
            _ => {
                return Err(fault(
                    "invalid_runtime_access",
                    format!("runtime_access[{index}] requires a nonempty authorization_refs array"),
                ))
            }
        }
        for secret in SECRET_FIELDS {
            if established(entry, secret).is_some() {
                return Err(fault(
                    "secret_forbidden",
                    format!(
                        "runtime_access[{index}] carries established {secret:?}; Prepare records opaque refs and never materializes secret bytes or control credentials"
                    ),
                ));
            }
        }
    }

    // ---- read-only gate (no mutation via any vector) ----
    let task_value = Value::Object(task.clone());
    let task_record = validate(OUTPUT_SCHEMA, task_value.clone())?;
    let grant_digest = digest_bytes(&canonical_bytes(grant_record(grant))?);
    let endpoint_digest = digest_bytes(entry_url.as_bytes());
    let endpoint_record = validate(
        OUTPUT_SCHEMA,
        json!({
            "grant_digest": grant_digest,
            "digest": endpoint_digest,
            "access": "public",
            "owner_domain": grant_owner_domain(grant),
            "provenance": "origin",
            "url": entry_url,
        }),
    )?;
    let _readonly: ReadOnlyRequest =
        authorize_acquisition(grant, &endpoint_record, &task_record)?;

    // ---- translation mapping (no hidden improvement or recovery) ----
    let mappings = match established(desc_map, "task_mappings") {
        Some(Value::Array(items)) => items,
        _ => {
            return Err(fault(
                "unsupported_mapping",
                "descriptor carries no task_mappings; incomplete translation produces UNSUPPORTED_MAPPING"
                    .to_string(),
            ))
        }
    };
    let mut translation: Option<Value> = None;
    let mut recovery_owner = String::from("none");
    for item in mappings {
        let mapping = item.as_object().ok_or_else(|| {
            fault(
                "invalid_descriptor",
                "descriptor task_mappings entries must be objects".to_string(),
            )
        })?;
        let mapped_type = match established(mapping, "task_type").and_then(Value::as_str) {
            Some(text) => text,
            None => continue,
        };
        if mapped_type != task_type {
            continue;
        }
        let pin = mapping.get("mapping").ok_or_else(|| {
            fault(
                "invalid_descriptor",
                format!("descriptor task_mapping for {task_type:?} requires a mapping pin"),
            )
        })?;
        let pin_map = pin.as_object().ok_or_else(|| {
            fault(
                "invalid_descriptor",
                format!("descriptor task_mapping for {task_type:?} mapping must be an object"),
            )
        })?;
        let id = required_str(pin_map, "id", "invalid_descriptor", "task mapping")?.to_string();
        let version =
            required_str(pin_map, "version", "invalid_descriptor", "task mapping")?.to_string();
        let digest =
            required_str(pin_map, "artifact_digest", "invalid_descriptor", "task mapping")?
                .to_string();
        if !is_digest(&digest) {
            return Err(fault(
                "invalid_descriptor",
                "descriptor task mapping artifact_digest must be a sha256: digest".to_string(),
            ));
        }
        translation = Some(json!({"id": id, "version": version, "artifact_digest": digest}));
        recovery_owner = established(mapping, "recovery_owner")
            .and_then(Value::as_str)
            .unwrap_or("none")
            .to_string();
        break;
    }
    let translation = translation.ok_or_else(|| {
        fault(
            "unsupported_mapping",
            format!("descriptor has no task_mapping for task_type {task_type:?}; incomplete translation produces UNSUPPORTED_MAPPING"),
        )
    })?;
    if recovery_limit > 0 && recovery_owner == "none" {
        return Err(fault(
            "unsupported_mapping",
            "task budgets allow recovery but the mapping names recovery_owner none; Prepare adds no hidden recovery"
                .to_string(),
        ));
    }

    // ---- budget mapping (all five dimensions, exactly once) ----
    let owner_domain = grant_owner_domain(grant);
    let budget_mapping = json!([
        {
            "dimension": "active_observation",
            "enforcer": "connector",
            "evidence_refs": [],
            "limitations": ["connector-enforced active observation bound; a call deadline does not stop already dispatched native work"],
        },
        {
            "dimension": "action_count",
            "enforcer": "connector",
            "evidence_refs": [],
            "limitations": ["connector-enforced action count bound"],
        },
        {
            "dimension": "observation_bytes",
            "enforcer": "connector",
            "evidence_refs": [],
            "limitations": ["connector-enforced observation byte bound"],
        },
        {
            "dimension": "recovery_count",
            "enforcer": "connector",
            "evidence_refs": [],
            "limitations": [format!("connector-enforced recovery bound; mapping recovery_owner is {recovery_owner:?}")],
        },
        {
            "dimension": "model_tokens",
            "enforcer": "connector",
            "evidence_refs": [],
            "limitations": ["connector-enforced model token bound; zero forbids a model call where enforceable"],
        },
    ]);

    // ---- concerns (non-blocking limitations only) ----
    let support_refs = authorization_refs.clone();
    let mut concerns: Vec<Value> = Vec::new();
    if browser_requirement == "best_effort" {
        concerns.push(json!({
            "concern_id": "state-browser-best-effort",
            "category": "state_policy_unverified",
            "disposition": "requires_acceptance",
            "detail": "browser-state policy is best_effort; Prepare records the mapping and its limitation without realizing state",
            "evidence_refs": support_refs,
        }));
    }
    if learning_requirement == "best_effort" {
        concerns.push(json!({
            "concern_id": "state-learning-best-effort",
            "category": "state_policy_unverified",
            "disposition": "requires_acceptance",
            "detail": "learning-state policy is best_effort; fresh browser state does not imply clean learning state",
            "evidence_refs": support_refs,
        }));
    }
    if online_replanning {
        concerns.push(json!({
            "concern_id": "assistance-online-replanning",
            "category": "assistance_limit",
            "disposition": "informational",
            "detail": "assistance discloses online_replanning; no planner was invoked during Prepare",
            "evidence_refs": support_refs,
        }));
    }

    // ---- evidence prefix (owner-local read only) ----
    let query = validate(
        OUTPUT_SCHEMA,
        json!({"query": "prefix", "journal_id": journal_id}),
    )?;
    let prefix_record = store.read(grant, &query)?;
    let prefix_map = as_object(&prefix_record, "invalid_prefix", "store prefix")?;
    let prefix_journal =
        required_str(prefix_map, "journal_id", "invalid_prefix", "store prefix")?.to_string();
    let last_sequence = match established(prefix_map, "last_sequence") {
        Some(Value::Number(number)) => number.as_u64().ok_or_else(|| {
            fault(
                "invalid_prefix",
                "store prefix last_sequence must be an unsigned integer".to_string(),
            )
        })?,
        _ => {
            return Err(fault(
                "invalid_prefix",
                "store prefix requires an established last_sequence".to_string(),
            ))
        }
    };
    let head_hash = required_str(prefix_map, "head_hash", "invalid_prefix", "store prefix")?.to_string();
    let evidence_prefix = json!({
        "journal_id": prefix_journal,
        "last_sequence": last_sequence,
        "head_hash": head_hash,
    });

    // ---- hashes, serializations, and preparation id ----
    let task_bytes = canonical_bytes(&task_record)?;
    let task_hex = digest_bytes(&task_bytes);
    let task_semantic_hash = format!("sha256:{task_hex}");
    let delivered_task = json!({
        "digest": task_semantic_hash,
        "size_bytes": task_bytes.len() as u64,
        "media_type": "connector-task/1",
        "owner_domain": owner_domain,
        "access": "restricted",
    });
    // Intended native request: deterministic serialization preserving intent,
    // order, values, targets, and retry policy. No transport credentials or
    // signatures are included; no hidden sleeps, selector alternatives, or
    // recovery are added.
    let native_object = json!({
        "task_id": task_id,
        "task_type": task_type,
        "entry": Value::Object(entry.clone()),
        "goal": required_str(&task, "goal", "invalid_task", "task")?,
        "permitted_origins": permitted_origins,
        "budgets": Value::Object(budgets.clone()),
        "translation": translation,
    });
    let native_record = validate(OUTPUT_SCHEMA, native_object)?;
    let native_bytes = canonical_bytes(&native_record)?;
    let native_hex = digest_bytes(&native_bytes);
    let native_hash = format!("sha256:{native_hex}");
    let native_request = json!({
        "digest": native_hash,
        "size_bytes": native_bytes.len() as u64,
        "media_type": "native-request/1",
        "owner_domain": owner_domain,
        "access": "restricted",
    });
    let prep_hex = digest_bytes(format!("{task_hex}:{descriptor_hex}").as_bytes());
    let preparation_id = format!("prep-{}", &prep_hex[..16.min(prep_hex.len())]);

    let preparation_value = json!({
        "record_type": PREPARATION_RECORD_TYPE,
        "schema_version": SCHEMA_VERSION,
        "preparation_id": preparation_id,
        "scope": Value::Object(scope.clone()),
        "configuration": Value::Object(configuration.clone()),
        "task": Value::Object(task.clone()),
        "task_semantic_hash": task_semantic_hash,
        "assistance": Value::Object(assistance.clone()),
        "planning_evidence_refs": planning_refs,
        "runtime_access": runtime_access,
        "delivered_task": delivered_task,
        "delivered_task_hash": task_semantic_hash,
        "native_request": native_request,
        "native_request_hash": native_hash,
        "translation": translation,
        "budget_mapping": budget_mapping,
        "concerns": concerns,
        "evidence_prefix": evidence_prefix,
        "descriptor_digest": descriptor_digest,
        "run_id": run_id,
    });
    validate(OUTPUT_SCHEMA, preparation_value)
}

/// Revalidate an immutable preparation against its pinned configuration and
/// the consumer's concern acceptances.
///
/// `configuration` must equal `preparation.configuration` exactly (stale
/// subjects/configurations/mappings are rejected, never silently
/// reprepared). `authorization` carries `accepted_concerns` (every
/// `requires_acceptance` concern ID) and `authorization_refs`. Hash fields
/// are recomputed from the embedded task bytes; any drift fails with
/// `integrity_conflict`.
pub fn verify_preparation(
    preparation: &CheckedRecord,
    configuration: &CheckedRecord,
    authorization: &CheckedRecord,
) -> Result<(), Fault> {
    if record_schema(preparation) == "state_mutation_record" {
        return Err(fault(
            "mutation_rejected",
            "state_mutation_record is reserved and non-executing".to_string(),
        ));
    }
    let prep = as_object(preparation, "invalid_preparation", "preparation")?;
    match established(prep, "record_type") {
        Some(Value::String(record_type)) if record_type == PREPARATION_RECORD_TYPE => {}
        _ => {
            return Err(fault(
                "invalid_preparation",
                format!("preparation record_type must be exactly {PREPARATION_RECORD_TYPE:?}"),
            ))
        }
    }
    required_str(prep, "preparation_id", "invalid_preparation", "preparation")?;
    let prep_scope = required_object(prep, "scope", "invalid_preparation", "preparation")?;
    let prep_configuration =
        required_object(prep, "configuration", "invalid_preparation", "preparation")?;
    let prep_task = required_object(prep, "task", "invalid_preparation", "preparation")?;
    let task_semantic_hash = required_str(
        prep,
        "task_semantic_hash",
        "invalid_preparation",
        "preparation",
    )?
    .to_string();
    if !is_digest(&task_semantic_hash) {
        return Err(fault(
            "invalid_preparation",
            "preparation task_semantic_hash must be a sha256: digest".to_string(),
        ));
    }
    required_object(prep, "assistance", "invalid_preparation", "preparation")?;
    match prep.get("planning_evidence_refs") {
        Some(Value::Array(_)) => {}
        _ => {
            return Err(fault(
                "invalid_preparation",
                "preparation requires a planning_evidence_refs array".to_string(),
            ))
        }
    }
    match prep.get("runtime_access") {
        Some(Value::Array(_)) => {}
        _ => {
            return Err(fault(
                "invalid_preparation",
                "preparation requires a runtime_access array".to_string(),
            ))
        }
    }
    let delivered_task = required_object(
        prep,
        "delivered_task",
        "invalid_preparation",
        "preparation",
    )?;
    let delivered_hash = required_str(
        prep,
        "delivered_task_hash",
        "invalid_preparation",
        "preparation",
    )?
    .to_string();
    let delivered_digest = required_str(
        delivered_task,
        "digest",
        "invalid_preparation",
        "delivered_task",
    )?;
    if delivered_digest != delivered_hash {
        return Err(fault(
            "integrity_conflict",
            "preparation delivered_task.digest does not match delivered_task_hash".to_string(),
        ));
    }
    if delivered_hash != task_semantic_hash {
        return Err(fault(
            "integrity_conflict",
            "preparation delivered_task_hash does not match task_semantic_hash".to_string(),
        ));
    }
    let native_request = required_object(
        prep,
        "native_request",
        "invalid_preparation",
        "preparation",
    )?;
    let native_hash = required_str(
        prep,
        "native_request_hash",
        "invalid_preparation",
        "preparation",
    )?
    .to_string();
    if !is_digest(&native_hash) {
        return Err(fault(
            "invalid_preparation",
            "preparation native_request_hash must be a sha256: digest".to_string(),
        ));
    }
    let native_digest = required_str(
        native_request,
        "digest",
        "invalid_preparation",
        "native_request",
    )?;
    if native_digest != native_hash {
        return Err(fault(
            "integrity_conflict",
            "preparation native_request.digest does not match native_request_hash".to_string(),
        ));
    }
    required_object(prep, "translation", "invalid_preparation", "preparation")?;
    let budget_mapping = match established(prep, "budget_mapping") {
        Some(Value::Array(items)) => items,
        _ => {
            return Err(fault(
                "invalid_preparation",
                "preparation requires an established budget_mapping array".to_string(),
            ))
        }
    };
    if budget_mapping.len() != 5 {
        return Err(fault(
            "invalid_preparation",
            "preparation budget_mapping must carry exactly five dimensions".to_string(),
        ));
    }
    let mut seen_dimensions = std::collections::HashSet::new();
    for item in budget_mapping {
        let entry = item.as_object().ok_or_else(|| {
            fault(
                "invalid_preparation",
                "preparation budget_mapping entries must be objects".to_string(),
            )
        })?;
        let dimension = required_str(entry, "dimension", "invalid_preparation", "budget_mapping")?;
        if !BUDGET_DIMENSIONS.contains(&dimension) {
            return Err(fault(
                "invalid_preparation",
                format!("preparation budget dimension {dimension:?} is unknown"),
            ));
        }
        if !seen_dimensions.insert(dimension.to_string()) {
            return Err(fault(
                "invalid_preparation",
                format!("preparation budget dimension {dimension:?} appears more than once"),
            ));
        }
        let enforcer = required_str(entry, "enforcer", "invalid_preparation", "budget_mapping")?;
        if dimension == "active_observation" && enforcer != "connector" {
            return Err(fault(
                "invalid_preparation",
                "preparation active_observation budget must be connector-enforced".to_string(),
            ));
        }
    }
    let concerns = match prep.get("concerns") {
        Some(Value::Array(items)) => items,
        _ => {
            return Err(fault(
                "invalid_preparation",
                "preparation requires a concerns array".to_string(),
            ))
        }
    };
    let mut seen_concerns = std::collections::HashSet::new();
    let mut required_acceptances: Vec<String> = Vec::new();
    for item in concerns {
        let concern = item.as_object().ok_or_else(|| {
            fault(
                "invalid_preparation",
                "preparation concerns must be objects".to_string(),
            )
        })?;
        let concern_id =
            required_str(concern, "concern_id", "invalid_preparation", "concern")?.to_string();
        if !seen_concerns.insert(concern_id.clone()) {
            return Err(fault(
                "invalid_preparation",
                format!("preparation concern_id {concern_id:?} appears more than once"),
            ));
        }
        let category = required_str(concern, "category", "invalid_preparation", "concern")?;
        if !CONCERN_CATEGORIES.contains(&category) {
            return Err(fault(
                "invalid_preparation",
                format!("preparation concern category {category:?} is unknown"),
            ));
        }
        let disposition =
            required_str(concern, "disposition", "invalid_preparation", "concern")?;
        if !CONCERN_DISPOSITIONS.contains(&disposition) {
            return Err(fault(
                "invalid_preparation",
                format!("preparation concern disposition {disposition:?} is unknown"),
            ));
        }
        required_str(concern, "detail", "invalid_preparation", "concern")?;
        if disposition == "requires_acceptance" {
            required_acceptances.push(concern_id);
        }
    }
    let evidence_prefix =
        required_object(prep, "evidence_prefix", "invalid_preparation", "preparation")?;
    required_str(
        evidence_prefix,
        "journal_id",
        "invalid_preparation",
        "evidence_prefix",
    )?;
    match established(evidence_prefix, "last_sequence") {
        Some(Value::Number(n)) if n.as_u64().is_some() => {}
        _ => {
            return Err(fault(
                "invalid_preparation",
                "preparation evidence_prefix requires an unsigned last_sequence".to_string(),
            ))
        }
    }
    required_str(
        evidence_prefix,
        "head_hash",
        "invalid_preparation",
        "evidence_prefix",
    )?;
    let _ = prep_scope;

    // Task bytes must still hash to the pinned semantic hash: a changed
    // artifact is rejected, never silently reprepared.
    let task_record = validate(OUTPUT_SCHEMA, Value::Object(prep_task.clone()))?;
    let recomputed = format!("sha256:{}", digest_bytes(&canonical_bytes(&task_record)?));
    if recomputed != task_semantic_hash {
        return Err(fault(
            "integrity_conflict",
            "preparation task bytes do not match task_semantic_hash; reject changed artifacts rather than silently repreparing"
                .to_string(),
        ));
    }

    // Configuration must still be the exact pinned configuration.
    let supplied = as_object(configuration, "invalid_authorization", "configuration")?;
    let pinned_value = Value::Object(prep_configuration.clone());
    let supplied_value = Value::Object(supplied.clone());
    if pinned_value != supplied_value {
        // Compare canonical bytes as well so key order cannot hide drift.
        let pinned_record = validate(OUTPUT_SCHEMA, pinned_value)?;
        let supplied_record = validate(OUTPUT_SCHEMA, supplied_value)?;
        let pinned_bytes = canonical_bytes(&pinned_record)?;
        let supplied_bytes = canonical_bytes(&supplied_record)?;
        if pinned_bytes != supplied_bytes {
            return Err(fault(
                "stale_configuration",
                "supplied configuration does not match the preparation pin; reject stale configuration rather than silently repreparing"
                    .to_string(),
            ));
        }
    }

    // Every requires_acceptance concern must be accepted under actual task
    // authority.
    let auth = as_object(authorization, "invalid_authorization", "authorization")?;
    let accepted = match established(auth, "accepted_concerns") {
        Some(Value::Array(items)) => items,
        _ => {
            return Err(fault(
                "invalid_authorization",
                "authorization requires an established accepted_concerns array".to_string(),
            ))
        }
    };
    let accepted_ids: std::collections::HashSet<&str> =
        accepted.iter().filter_map(Value::as_str).collect();
    for required in &required_acceptances {
        if !accepted_ids.contains(required.as_str()) {
            return Err(fault(
                "missing_acceptance",
                format!(
                    "concern {required:?} requires acceptance before Start; Start accepts the preparation digest including all such concerns"
                ),
            ));
        }
    }
    match auth.get("authorization_refs") {
        Some(Value::Array(refs)) if !refs.is_empty() => {}
        _ => {
            return Err(fault(
                "invalid_authorization",
                "authorization requires a nonempty authorization_refs array".to_string(),
            ))
        }
    }
    // Secret material must never appear in the authorization either.
    for secret in SECRET_FIELDS {
        if established(auth, secret).is_some() {
            return Err(fault(
                "secret_forbidden",
                format!("authorization carries established {secret:?}; secrets are never in-band"),
            ));
        }
    }
    let _ = missing("not_observed", "placeholder to keep Missing helper live");
    let _ = strip_digest_prefix(&task_semantic_hash);
    Ok(())
}

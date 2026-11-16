//! `crawler_cursors`: traversal planning under the cursor acceptance Floor.
//!
//! [`plan_cursor_step`] plans exactly one cursor advance from a pinned
//! declaration, the current cursor row, the just-materialized response
//! evidence, and a checked cursor capability. Offset (and any numeric
//! positional alias: `page=N`, `start=N`, `Page$N`, postbacks, `numeric`,
//! `positional`) is permitted only when `ordering_model=Deterministic` and
//! `coverage_scope=per_run`. A `continuation`/`keyset` must be a verified
//! response-bound continuation, never an arithmetic substitute for a page
//! offset. An `exhaustive_single_response` requires its own single-response
//! proof; it is never a renamed first page.
//!
//! When the cursor capability is unverified, planning does not fail and does
//! not fabricate a certified continuation. It emits a closed
//! `crawler_uncertified_traversal_observation` packet (§4.3) preserving the
//! initial-response evidence with `cursor_capability_status=unverified` and
//! `accepted_for_positive_proof=false`. Such packets cannot enter a certified
//! traversal cohort.
//!
//! [`plan_observation_commit`] plans the durable commit of one page
//! observation packet. Identity derives from walk, request sequence, and
//! response hash: replay with identical hashes deduplicates without
//! double-counting, conflicting content under one identity is an integrity
//! incident, gaps beyond the materialized boundary are rejected, and
//! incompatible session/backend generations are rejected.
//!
//! [`validate_resume`] gates walk restart on ordering compatibility: the
//! cursor pin must equal the ordering declaration, the ordering fingerprint
//! must match, session and backend generations must agree, and positional
//! cursors must satisfy the Floor. It commits nothing.
//!
//! # Record shapes
//!
//! All inputs are [`CheckedRecord`]s (already past the schema gate, so no
//! bare nulls). Objects use typed `Missing` envelopes for `M(...)` fields.
//!
//! `declaration` (traversal pin):
//! - `target`, `run_id`, `partition_id`: nonempty `ID`
//! - `ordering_model`, `coverage_scope`: nonempty strings; the Floor is the
//!   exact pair `Deterministic` + `per_run`
//! - `proposed_cursor_kind` (or `cursor_kind`): nonempty cursor kind
//! - optional `continuation_source`: `response_bound` for genuine
//!   continuation/keyset; `arithmetic`, `stored_coordinate`, `session_bound`,
//!   `next_link` mark a renamed offset
//! - optional `response_bound`: bool, must be true for continuation/keyset
//! - optional `single_response_proof`: bool, must be true for
//!   `exhaustive_single_response`
//! - optional `evidence_refs`: `SUPPORT` when the response carries none
//!
//! `cursor` (cursor-state row subset, §11.1):
//! - `target`, `run_id`, `partition_id`, `walk_id`: nonempty `ID`
//! - `cursor_kind`, `ordering_model`, `coverage_scope`: nonempty strings
//! - `cursor_revision`: `REV`; `last_committed_request_sequence`: `REV`
//! - `ordering_fingerprint`: `SH` object (`{value,..}`) or digest string
//! - `session_epoch`: `M(SID)` (string/int or `Missing`); `backend_signature`:
//!   `M(ID)` (string or `Missing`)
//! - optional `cursor_payload_json`: coordinate state; numeric `page`/`start`/
//!   `offset` keys inside a continuation/keyset payload mark renaming
//! - optional `previous_response_hash`: `SH` for replay comparison
//! - optional `status`: `active`/`suspended` resume; `completed`/`terminated`
//!   refuse further planning
//!
//! `response` (just-materialized evidence):
//! - `request_sequence`: `REV`, must equal `last_committed_request_sequence+1`
//! - `request_identity`: object (`CanonicalRequest`)
//! - `response`: object (`AR` with at least `digest`)
//! - `ordered_observed_ids`: array of string/int ids
//! - `render_verdict_counts`: object with all six verdicts
//!   (`Pass`, `ThinShell`, `RenderIncomplete`, `EdgeBlock`, `SensorFail`,
//!   `ChallengeIncomplete`) each a `REV`
//! - `page_hash`: `SH` object with `value` (or digest string)
//! - `session_epoch`: `M(SID)`; `backend_signature`: `M(ID)` (required keys)
//! - optional `continuation_token`: established response-bound token
//! - optional `terminated`/`is_last`: bool termination evidence
//! - optional `exhaustive`: bool single-response exhaustiveness evidence
//! - optional `evidence_refs`: `SUPPORT`
//!
//! `capability` (cursor-capability evidence wrapper):
//! - `descriptor`: embedded `connector_descriptor` object
//! - `scope`: embedded subject pin
//!   (`subject_id`, `subject_version`, `configured_mode`, `interface_surface`)
//! - `capability_id`: must be exactly `crawler_certified_cursor`
//!
//! The wrapper is re-validated and passed to
//! [`check_capability`](crawler_capabilities::check_capability). Only
//! `availability=present` counts as verified; `unknown`/`absent`/
//! `not_applicable` take the uncertified path. Structural capability faults
//! (`invalid_descriptor`, `scope_mismatch`, `unknown_capability`,
//! `unverified_claim`, ...) propagate unchanged.
//!
//! `packet` (for [`plan_observation_commit`], §11.2 plus commit markers):
//! - `target`, `run_id`, `partition_id`, `walk_id`, `request_sequence`,
//!   `request_identity`, `response_hash:SH`, `page_hash:SH`,
//!   `ordered_observed_ids`, `render_verdict_counts`,
//!   `session_epoch:M(SID)`, `backend_signature:M(ID)`
//! - optional `reported_count_evidence`: `M(E)`
//! - optional `cursor_capability_status`: `verified` admits the cohort,
//!   anything else (or absent) stays out
//! - `evidence_refs`: nonempty `SUPPORT`
//!
//! `session` (for [`validate_resume`], §12 subset):
//! - `target`, `run_id`, `phase`, `shard_id` when stateful; `session_epoch`:
//!   `M(SID)` (`Missing(not_applicable)` when sessionless)
//! - optional `status`, `owner_epoch`, `worker_identity`
//!
//! `ordering` (for [`validate_resume`]):
//! - `ordering_model`, `coverage_scope`, `ordering_fingerprint` (as above)
//! - optional `backend_signature`: `M(ID)`; optional `target`, `run_id`,
//!   `partition_id` scope pins when present
//!
//! Plans are pure: they never write storage, never commit cursor state, and
//! never advance beyond the materialized response.

use crawler_capabilities::check_capability;
use crawler_hashing::frame_reference;
use crawler_schema::{record_value, validate, CheckedRecord, Fault};
use serde_json::{json, Map, Value};

/// Crawler seam profile version stamped on emitted records.
const SCHEMA_VERSION: &str = "crawler-seam/0.1.0";
/// Generic plan output schema (structural gate only).
const PLAN_SCHEMA: &str = "audit_log";
/// Closed uncertified-observation output schema (§4.3).
const UNCERTIFIED_SCHEMA: &str = "crawler_uncertified_traversal_observation";
/// The one capability id that certifies traversal.
const CURSOR_CAPABILITY_ID: &str = "crawler_certified_cursor";

/// The six render verdicts; every counts object must carry all six.
const RENDER_VERDICTS: &[&str] = &[
    "Pass",
    "ThinShell",
    "RenderIncomplete",
    "EdgeBlock",
    "SensorFail",
    "ChallengeIncomplete",
];

/// Fields that would turn a traversal declaration into an assessment.
const QUALIFICATION_FIELDS: &[&str] = &[
    "qualification",
    "requirement_satisfaction",
    "application_success",
    "authoritative_success",
    "assessment_result",
    "requirement_result",
    "satisfaction",
    "success_flag",
];

/// Terminal cursor statuses refuse further planning.
const TERMINAL_CURSOR: &[&str] = &["completed", "terminated"];
/// Terminal session statuses refuse resume.
const TERMINAL_SESSION: &[&str] = &["expired", "closed", "terminated", "fenced", "invalidated"];

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
fn is_missing(value: &Value) -> bool {
    value
        .as_object()
        .is_some_and(|map| map.get("value").is_some_and(Value::is_null))
}

/// The established (non-`Missing`) value of `field`, if any.
fn established<'a>(map: &'a Map<String, Value>, field: &str) -> Option<&'a Value> {
    map.get(field).filter(|value| !is_missing(value))
}

fn as_object<'a>(record: &'a CheckedRecord, code: &str, what: &str) -> Result<&'a Map<String, Value>, Fault> {
    record_value(record).as_object().ok_or_else(|| {
        fault(
            code,
            format!("{what} must be a JSON object"),
        )
    })
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

fn required_u64(map: &Map<String, Value>, field: &str, code: &str, what: &str) -> Result<u64, Fault> {
    match established(map, field) {
        Some(Value::Number(number)) => number.as_u64().ok_or_else(|| {
            fault(
                code,
                format!("{what} field {field:?} must be an unsigned integer revision/sequence/count"),
            )
        }),
        _ => Err(fault(
            code,
            format!("{what} requires an established unsigned integer {field:?}"),
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
        Some(Value::Object(object)) => Ok(object),
        _ => Err(fault(
            code,
            format!("{what} requires an established object {field:?}"),
        )),
    }
}

fn required_array<'a>(
    map: &'a Map<String, Value>,
    field: &str,
    code: &str,
    what: &str,
) -> Result<&'a Vec<Value>, Fault> {
    match established(map, field) {
        Some(Value::Array(items)) => Ok(items),
        _ => Err(fault(
            code,
            format!("{what} requires an established array {field:?}"),
        )),
    }
}

/// Digest text of an `SH`-shaped value: a bare string or `{value,..}`.
fn hash_text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) if !text.is_empty() => Some(text.clone()),
        Value::Object(map) => match map.get("value") {
            Some(Value::String(text)) if !text.is_empty() => Some(text.clone()),
            _ => None,
        },
        _ => None,
    }
}

/// Fingerprint text of an ordering fingerprint (string or `SH` object).
fn fingerprint_text(value: &Value) -> Option<String> {
    hash_text(value)
}

/// Exact Floor scope: `ordering_model=Deterministic` with `coverage_scope=per_run`.
fn is_certified_scope(ordering: &str, scope: &str) -> bool {
    ordering == "Deterministic" && scope == "per_run"
}

/// Case-insensitive numeric-positional alias detection.
///
/// Covers `page=N`, `start=N`, `Page$N`, `offset`, `numeric`, `positional`,
/// postbacks, and kind names that embed them. Verified `continuation`,
/// `keyset`, and `exhaustive_single_response` do not match.
fn looks_positional(kind: &str) -> bool {
    let lower = kind.to_lowercase();
    lower.contains("page$")
        || lower.contains("page=")
        || lower.contains("page$n")
        || lower.contains("positional")
        || lower.contains("offset")
        || lower.contains("numeric")
        || lower.contains("postback")
        || lower.contains("do_postback")
        || lower.contains("start=")
        || lower.contains("start$")
        || lower == "page"
        || lower == "start"
        || lower.contains("page_n")
        || lower.contains("pagenum")
        || lower.contains("page_no")
        || lower.contains("pageindex")
        || lower.contains("next=")
        || lower == "pagen"
}

/// Normalized cursor-kind token: lowercase, hyphens unified to underscores.
fn normalize_kind(kind: &str) -> String {
    kind.to_lowercase().replace('-', "_")
}

/// True for the four verified cursor kinds.
fn is_verified_kind(kind: &str) -> bool {
    matches!(
        normalize_kind(kind).as_str(),
        "offset" | "continuation" | "keyset" | "exhaustive_single_response"
    )
}

/// Equality of `M(SID)`/`M(ID)` values: two `Missing` envelopes agree
/// regardless of reason; established values compare without type coercion
/// (integer `7` never equals string `"7"`).
fn established_equal(left: &Value, right: &Value) -> bool {
    let left_missing = is_missing(left);
    let right_missing = is_missing(right);
    match (left_missing, right_missing) {
        (true, true) => true,
        (true, false) | (false, true) => false,
        (false, false) => left == right,
    }
}

/// True when the response carries termination evidence.
fn is_terminated(map: &Map<String, Value>) -> bool {
    matches!(established(map, "terminated"), Some(Value::Bool(true)))
        || matches!(established(map, "is_last"), Some(Value::Bool(true)))
}

/// True when a coordinate state embeds a numeric positional coordinate.
fn has_positional_payload(value: &Value) -> bool {
    const KEYS: &[&str] = &[
        "page",
        "start",
        "offset",
        "page_number",
        "pagenum",
        "page_no",
        "pageindex",
        "next_page",
    ];
    match value {
        Value::Object(map) => {
            for key in KEYS {
                if let Some(found) = established(map, key) {
                    if matches!(found, Value::Number(_) | Value::String(_)) {
                        return true;
                    }
                }
            }
            // Nested `coordinate` / `payload` objects may hide the alias.
            for nested_key in ["coordinate", "payload", "next_coordinate"] {
                if let Some(Value::Object(_)) = established(map, nested_key) {
                    if let Some(nested) = established(map, nested_key) {
                        if has_positional_payload(nested) {
                            return true;
                        }
                    }
                }
            }
            false
        }
        Value::String(text) => looks_positional(text),
        _ => false,
    }
}

/// True when the declaration map itself carries a numeric coordinate field.
fn declaration_has_coordinate(map: &Map<String, Value>) -> bool {
    const KEYS: &[&str] = &[
        "page",
        "start",
        "offset",
        "page_number",
        "pagenum",
        "page_no",
        "pageindex",
        "next_page",
        "next_coordinate",
    ];
    KEYS.iter().any(|key| {
        matches!(
            established(map, key),
            Some(Value::Number(_) | Value::String(_) | Value::Object(_))
        )
    })
}

/// Complete six-verdict counts; returns a cloned normalized object.
fn validated_verdict_counts(map: &Map<String, Value>, what: &str) -> Result<Value, Fault> {
    let counts = required_object(map, "render_verdict_counts", "incomplete_verdicts", what)?;
    for verdict in RENDER_VERDICTS {
        match counts.get(*verdict) {
            Some(Value::Number(number)) if number.as_u64().is_some() => {}
            _ => {
                return Err(fault(
                    "incomplete_verdicts",
                    format!(
                        "{what} render_verdict_counts must carry all six verdicts as unsigned counts; missing or invalid {verdict:?}"
                    ),
                ));
            }
        }
    }
    Ok(Value::Object(counts.clone()))
}

/// Ordered observed ids: an array of string/int identities.
fn validated_ordered_ids(map: &Map<String, Value>, what: &str) -> Result<Value, Fault> {
    let ids = required_array(map, "ordered_observed_ids", "missing_field", what)?;
    for (index, id) in ids.iter().enumerate() {
        match id {
            Value::String(_) | Value::Number(_) => {}
            _ => {
                return Err(fault(
                    "invalid_field",
                    format!(
                        "{what} ordered_observed_ids[{index}] must be a string or integer identity without coercion"
                    ),
                ));
            }
        }
    }
    Ok(Value::Array(ids.clone()))
}

/// Nonempty `SUPPORT` evidence refs from the first established carrier.
fn extract_support(candidates: &[Option<&Value>], what: &str) -> Result<Value, Fault> {
    for candidate in candidates.iter().flatten() {
        if let Value::Array(items) = *candidate {
            if !items.is_empty() {
                return Ok(Value::Array((*items).clone()));
            }
        }
    }
    Err(fault(
        "missing_evidence",
        format!("{what} requires nonempty evidence_refs SUPPORT"),
    ))
}

/// Minimal `AR` validation: an object carrying a digest.
fn validated_ar(map: &Map<String, Value>, field: &str, what: &str) -> Result<Value, Fault> {
    let object = required_object(map, field, "missing_field", what)?;
    match object.get("digest") {
        Some(Value::String(digest)) if !digest.is_empty() => Ok(Value::Object(object.clone())),
        _ => Err(fault(
            "missing_field",
            format!("{what} {field:?} must be an ArtifactReference object carrying a digest"),
        )),
    }
}

/// `SH` validation: an object with digest `value` (profile/evidence kept as
/// carried) or a bare digest string.
fn validated_sh(map: &Map<String, Value>, field: &str, what: &str) -> Result<Value, Fault> {
    let value = map.get(field).ok_or_else(|| {
        fault(
            "missing_field",
            format!("{what} requires established source hash {field:?}"),
        )
    })?;
    if is_missing(value) {
        return Err(fault(
            "missing_field",
            format!("{what} requires established source hash {field:?}"),
        ));
    }
    if hash_text(value).is_none() {
        return Err(fault(
            "missing_field",
            format!("{what} {field:?} must carry digest text as a string or SH value"),
        ));
    }
    Ok(value.clone())
}

/// Validate an `M(SID)`: present key, either `Missing` or string/int.
fn validated_sid(map: &Map<String, Value>, field: &str, what: &str) -> Result<Value, Fault> {
    let value = map.get(field).ok_or_else(|| {
        fault(
            "missing_field",
            format!("{what} requires {field:?} as M(SID): established string/int or Missing"),
        )
    })?;
    if is_missing(value) {
        return Ok(value.clone());
    }
    match value {
        Value::String(_) | Value::Number(_) => Ok(value.clone()),
        _ => Err(fault(
            "invalid_field",
            format!("{what} {field:?} must be a string/int SID or a Missing envelope"),
        )),
    }
}

/// Validate an `M(ID)`: present key, either `Missing` or a nonempty string.
fn validated_mid(map: &Map<String, Value>, field: &str, what: &str) -> Result<Value, Fault> {
    let value = map.get(field).ok_or_else(|| {
        fault(
            "missing_field",
            format!("{what} requires {field:?} as M(ID): established string or Missing"),
        )
    })?;
    if is_missing(value) {
        return Ok(value.clone());
    }
    match value {
        Value::String(text) if !text.is_empty() => Ok(value.clone()),
        _ => Err(fault(
            "invalid_field",
            format!("{what} {field:?} must be a nonempty string ID or a Missing envelope"),
        )),
    }
}

/// Resolve the cursor capability wrapper through [`check_capability`].
///
/// Returns the availability string (`present` = verified). Structural
/// capability faults propagate unchanged so dishonest descriptors,
/// predecessor-version evidence, and scope mismatches are never silently
/// downgraded to uncertified.
fn resolve_capability_availability(capability: &CheckedRecord) -> Result<String, Fault> {
    let map = as_object(capability, "invalid_capability", "capability")?;
    let capability_id = required_str(map, "capability_id", "invalid_capability", "capability")?;
    if capability_id != CURSOR_CAPABILITY_ID {
        return Err(fault(
            "wrong_capability",
            format!(
                "cursor traversal requires capability {CURSOR_CAPABILITY_ID:?}, got {capability_id:?}"
            ),
        ));
    }
    let descriptor_value = established(map, "descriptor").ok_or_else(|| {
        fault(
            "invalid_capability",
            "capability requires an established descriptor object".to_string(),
        )
    })?;
    let scope_value = established(map, "scope").ok_or_else(|| {
        fault(
            "invalid_capability",
            "capability requires an established scope object".to_string(),
        )
    })?;
    if !descriptor_value.is_object() {
        return Err(fault(
            "invalid_capability",
            "capability descriptor must be an object".to_string(),
        ));
    }
    if !scope_value.is_object() {
        return Err(fault(
            "invalid_capability",
            "capability scope must be an object".to_string(),
        ));
    }
    let descriptor = validate(PLAN_SCHEMA, descriptor_value.clone()).map_err(|inner| {
        fault(
            "invalid_capability",
            format!(
                "capability descriptor failed the schema gate: {}: {}",
                inner.code, inner.detail
            ),
        )
    })?;
    let scope = validate(PLAN_SCHEMA, scope_value.clone()).map_err(|inner| {
        fault(
            "invalid_capability",
            format!(
                "capability scope failed the schema gate: {}: {}",
                inner.code, inner.detail
            ),
        )
    })?;
    let checked = check_capability(&descriptor, capability_id, &scope)?;
    let availability = record_value(&checked)
        .as_object()
        .and_then(|result| result.get("availability"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            fault(
                "invalid_capability",
                "capability check returned no availability".to_string(),
            )
        })?;
    Ok(availability.to_string())
}

/// Canonical `cursor_state` reference for a walk; validates the four
/// identity components through length-framed [`frame_reference`].
fn cursor_walk_ref(target: &str, run_id: &str, partition_id: &str, walk_id: &str) -> Result<String, Fault> {
    frame_reference(
        "cursor_state",
        &[
            target.to_string(),
            run_id.to_string(),
            partition_id.to_string(),
            walk_id.to_string(),
        ],
    )
}

/// Observation identity: walk reference plus request sequence plus response
/// hash text. Deterministic and unambiguous without type coercion.
fn observation_identity(walk_ref: &str, request_sequence: u64, hash: &str) -> String {
    format!("{walk_ref}:seq:{request_sequence}:hash:{hash}")
}

// ---------------------------------------------------------------------------
// Public interface
// ---------------------------------------------------------------------------

/// Plan exactly one cursor step from declaration, cursor, response, and
/// cursor-capability evidence.
///
/// Common structural checks (walk scope, ordering pin, sequencing,
/// session/backend agreement, six verdicts, evidence) apply to every call.
/// Qualification fields in the declaration are rejected outright.
///
/// With an unverified capability the call succeeds as an initial-evidence
/// packet: a closed `crawler_uncertified_traversal_observation` with
/// `cursor_capability_status=unverified` and
/// `accepted_for_positive_proof=false`. It carries no certified continuation,
/// no revision advance, and no proof admission.
///
/// With a verified (`present`) capability the Floor is enforced: positional
/// aliases outside `Deterministic` + `per_run` fail with
/// `uncertified_positional`, arithmetic/stored coordinates renamed as
/// `continuation`/`keyset` fail with `renamed_positional` (or
/// `continuation_not_bound` when no response-bound token is materialized),
/// and `exhaustive_single_response` without its own single-response proof
/// fails with `uncertified_exhaustive`. Success returns a `cursor_step_plan`
/// (validated under `audit_log`) for `prior_revision+1` grounded in the
/// supplied response sequence.
pub fn plan_cursor_step(
    declaration: &CheckedRecord,
    cursor: &CheckedRecord,
    response: &CheckedRecord,
    capability: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let decl_map = as_object(declaration, "invalid_declaration", "declaration")?;
    let cursor_map = as_object(cursor, "invalid_cursor", "cursor")?;
    let response_map = as_object(response, "invalid_response", "response")?;

    // The connector declares; it never assesses.
    for field in QUALIFICATION_FIELDS {
        if established(decl_map, field).is_some() {
            return Err(fault(
                "forbidden_assessment",
                format!(
                    "declaration field {field:?} is a consumer assessment, not a capability declaration"
                ),
            ));
        }
    }

    // Declaration pin.
    let decl_target = required_str(decl_map, "target", "invalid_declaration", "declaration")?.to_string();
    let decl_run = required_str(decl_map, "run_id", "invalid_declaration", "declaration")?.to_string();
    let decl_partition =
        required_str(decl_map, "partition_id", "invalid_declaration", "declaration")?.to_string();
    let decl_ordering =
        required_str(decl_map, "ordering_model", "invalid_declaration", "declaration")?.to_string();
    let decl_scope =
        required_str(decl_map, "coverage_scope", "invalid_declaration", "declaration")?.to_string();
    let decl_kind = established(decl_map, "proposed_cursor_kind")
        .or_else(|| established(decl_map, "cursor_kind"))
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .ok_or_else(|| {
            fault(
                "invalid_declaration",
                "declaration requires an established nonempty proposed_cursor_kind (or cursor_kind)"
                    .to_string(),
            )
        })?
        .to_string();

    // Cursor identity and pin.
    let cursor_target = required_str(cursor_map, "target", "invalid_cursor", "cursor")?.to_string();
    let cursor_run = required_str(cursor_map, "run_id", "invalid_cursor", "cursor")?.to_string();
    let cursor_partition =
        required_str(cursor_map, "partition_id", "invalid_cursor", "cursor")?.to_string();
    let walk_id = required_str(cursor_map, "walk_id", "invalid_cursor", "cursor")?.to_string();
    if cursor_target != decl_target || cursor_run != decl_run || cursor_partition != decl_partition {
        return Err(fault(
            "walk_scope_mismatch",
            format!(
                "cursor walk ({cursor_target}/{cursor_run}/{cursor_partition}) does not match declaration ({decl_target}/{decl_run}/{decl_partition})"
            ),
        ));
    }
    let cursor_kind = required_str(cursor_map, "cursor_kind", "invalid_cursor", "cursor")?.to_string();
    let cursor_ordering =
        required_str(cursor_map, "ordering_model", "invalid_cursor", "cursor")?.to_string();
    let cursor_scope =
        required_str(cursor_map, "coverage_scope", "invalid_cursor", "cursor")?.to_string();
    if cursor_ordering != decl_ordering || cursor_scope != decl_scope {
        return Err(fault(
            "ordering_mismatch",
            format!(
                "cursor pin ({cursor_ordering}/{cursor_scope}) does not match declaration ({decl_ordering}/{decl_scope}); ordering is never silently rewritten"
            ),
        ));
    }
    let cursor_revision = required_u64(cursor_map, "cursor_revision", "invalid_cursor", "cursor")?;
    let last_committed =
        required_u64(cursor_map, "last_committed_request_sequence", "invalid_cursor", "cursor")?;
    let cursor_fingerprint_value = cursor_map.get("ordering_fingerprint").ok_or_else(|| {
        fault(
            "invalid_cursor",
            "cursor requires an established ordering_fingerprint".to_string(),
        )
    })?;
    if is_missing(cursor_fingerprint_value) || fingerprint_text(cursor_fingerprint_value).is_none() {
        return Err(fault(
            "invalid_cursor",
            "cursor requires an established ordering_fingerprint".to_string(),
        ));
    }
    let cursor_session = validated_sid(cursor_map, "session_epoch", "cursor").unwrap_or_else(|_| {
        missing("not_applicable", "cursor carries no session epoch")
    });
    let cursor_backend = validated_mid(cursor_map, "backend_signature", "cursor").unwrap_or_else(|_| {
        missing("not_applicable", "cursor carries no backend signature")
    });
    // Cursor-side M(...) keys are optional for sessionless walks; when
    // present they must be well-formed (validated above when present).
    if let Some(status) = established(cursor_map, "status").and_then(Value::as_str) {
        if TERMINAL_CURSOR.contains(&status) {
            return Err(fault(
                "walk_terminated",
                format!("cursor walk status {status:?} is terminal; no further step is planned"),
            ));
        }
    }
    // Response-side scope pins, when present, must agree with the declaration.
    for field in ["target", "run_id", "partition_id"] {
        if let Some(Value::String(text)) = established(response_map, field) {
            let expected = match field {
                "target" => decl_target.as_str(),
                "run_id" => decl_run.as_str(),
                _ => decl_partition.as_str(),
            };
            if text != expected {
                return Err(fault(
                    "walk_scope_mismatch",
                    format!(
                        "response {field:?} {text:?} does not match declaration {expected:?}"
                    ),
                ));
            }
        }
    }
    if let Some(Value::String(text)) = established(response_map, "walk_id") {
        if text != &walk_id {
            return Err(fault(
                "walk_scope_mismatch",
                format!("response walk_id {text:?} does not match cursor {walk_id:?}"),
            ));
        }
    }

    // Response evidence.
    let request_sequence = required_u64(response_map, "request_sequence", "invalid_response", "response")?;
    if request_sequence <= last_committed {
        return Err(fault(
            "stale_sequence",
            format!(
                "response sequence {request_sequence} does not advance last committed {last_committed}; replay deduplicates, it never re-plans"
            ),
        ));
    }
    if request_sequence != last_committed + 1 {
        return Err(fault(
            "beyond_materialized",
            format!(
                "response sequence {request_sequence} skips beyond last committed {last_committed}; a plan never points past materialized observations"
            ),
        ));
    }
    let request_identity = Value::Object(
        required_object(response_map, "request_identity", "invalid_response", "response")?.clone(),
    );
    let response_ar = validated_ar(response_map, "response", "response")?;
    let ordered_ids = validated_ordered_ids(response_map, "response")?;
    let verdict_counts = validated_verdict_counts(response_map, "response")?;
    let page_hash = validated_sh(response_map, "page_hash", "response")?;
    let page_hash_text = hash_text(&page_hash).unwrap_or_default();
    let response_session = validated_sid(response_map, "session_epoch", "response")?;
    let response_backend = validated_mid(response_map, "backend_signature", "response")?;
    if !established_equal(&cursor_session, &response_session) {
        return Err(fault(
            "session_mismatch",
            "response session_epoch does not match the cursor generation; cross-generation steps are rejected"
                .to_string(),
        ));
    }
    if !established_equal(&cursor_backend, &response_backend) {
        return Err(fault(
            "backend_mismatch",
            "response backend_signature does not match the cursor cohort; backends are never mixed blindly"
                .to_string(),
        ));
    }
    let evidence_refs = extract_support(
        &[
            established(response_map, "evidence_refs"),
            established(decl_map, "evidence_refs"),
        ],
        "plan_cursor_step",
    )?;

    // Capability evidence decides the certified versus uncertified path.
    // Structural capability faults propagate; they are never downgraded.
    let availability = resolve_capability_availability(capability)?;

    let walk_ref = cursor_walk_ref(&decl_target, &decl_run, &decl_partition, &walk_id)?;

    if availability != "present" {
        // Uncertified path: preserve initial evidence without fabricating a
        // certified continuation, a revision advance, or proof admission.
        let observation_id =
            observation_identity(&walk_ref, request_sequence, &page_hash_text);
        let packet = json!({
            "record_type": "crawler_uncertified_traversal_observation",
            "schema_version": SCHEMA_VERSION,
            "target": decl_target,
            "run_id": decl_run,
            "partition_id": decl_partition,
            "observation_id": observation_id,
            "request_identity": request_identity,
            "response": response_ar,
            "ordered_observed_ids": ordered_ids,
            "render_verdict_counts": verdict_counts,
            "page_hash": page_hash,
            "cursor_capability_status": "unverified",
            "proposed_cursor_kind": decl_kind,
            "ordering_model": decl_ordering,
            "session_epoch": response_session,
            "backend_signature": response_backend,
            "accepted_for_positive_proof": false,
            "evidence_refs": evidence_refs,
        });
        return validate(UNCERTIFIED_SCHEMA, packet);
    }

    // Verified path: enforce the cursor acceptance Floor.
    for (label, kind) in [("declaration", decl_kind.as_str()), ("cursor", cursor_kind.as_str())] {
        if looks_positional(kind) && !is_certified_scope(&decl_ordering, &decl_scope) {
            return Err(fault(
                "uncertified_positional",
                format!(
                    "{label} cursor kind {kind:?} is a numeric positional alias, permitted only for ordering_model=Deterministic with coverage_scope=per_run (got {decl_ordering}/{decl_scope})"
                ),
            ));
        }
        if !is_verified_kind(kind) && !looks_positional(kind) {
            return Err(fault(
                "unknown_cursor_kind",
                format!(
                    "{label} cursor kind {kind:?} is not a verified offset/continuation/keyset/exhaustive_single_response kind"
                ),
            ));
        }
    }
    // A bare coordinate field in the declaration is a positional alias even
    // when the kind name hides it.
    if declaration_has_coordinate(decl_map) && !is_certified_scope(&decl_ordering, &decl_scope) {
        // Continuation/keyset/exhaustive kinds must never smuggle coordinates;
        // offset-likes are already rejected above outside the Floor.
        let normalized = normalize_kind(&decl_kind);
        if normalized != "offset" || looks_positional(&decl_kind) {
            return Err(fault(
                "uncertified_positional",
                format!(
                    "declaration carries a numeric page/start/offset coordinate outside Deterministic/per_run (kind {decl_kind:?})"
                ),
            ));
        }
    }

    let normalized_next = normalize_kind(&decl_kind);
    let terminated = is_terminated(response_map);
    if normalized_next == "continuation" || normalized_next == "keyset" {
        // A permissible continuation is response-bound, not arithmetic.
        if let Some(Value::String(source)) = established(decl_map, "continuation_source") {
            if source != "response_bound" {
                return Err(fault(
                    "renamed_positional",
                    format!(
                        "cursor kind {decl_kind:?} claims a response-bound continuation but continuation_source is {source:?}; storing page=N, following Next, or binding it to a session does not make it continuation"
                    ),
                ));
            }
        }
        if let Some(Value::Bool(false)) = established(decl_map, "response_bound") {
            return Err(fault(
                "renamed_positional",
                format!(
                    "cursor kind {decl_kind:?} claims continuation with response_bound=false; arithmetic offsets are never continuations"
                ),
            ));
        }
        if let Some(payload) = established(cursor_map, "cursor_payload_json") {
            if has_positional_payload(payload) {
                return Err(fault(
                    "renamed_positional",
                    format!(
                        "cursor kind {decl_kind:?} claims continuation but the payload embeds a numeric page/start/offset coordinate"
                    ),
                ));
            }
        }
        if declaration_has_coordinate(decl_map) {
            return Err(fault(
                "renamed_positional",
                format!(
                    "cursor kind {decl_kind:?} claims continuation but the declaration carries a numeric coordinate"
                ),
            ));
        }
        let token_established = established(response_map, "continuation_token").is_some();
        if !token_established && !terminated {
            return Err(fault(
                "continuation_not_bound",
                "continuation/keyset requires a materialized response continuation_token or termination evidence; the next step never outruns the response"
                    .to_string(),
            ));
        }
    }
    if normalized_next == "exhaustive_single_response" {
        let declared_proof = matches!(established(decl_map, "single_response_proof"), Some(Value::Bool(true)));
        let response_proof = matches!(established(response_map, "exhaustive"), Some(Value::Bool(true)))
            || matches!(established(response_map, "single_response_complete"), Some(Value::Bool(true)));
        if !declared_proof || !response_proof {
            return Err(fault(
                "uncertified_exhaustive",
                "exhaustive_single_response requires its own single-response proof (declaration single_response_proof plus response exhaustive evidence); a first page is never promoted by renaming"
                    .to_string(),
            ));
        }
        if let Some(payload) = established(cursor_map, "cursor_payload_json") {
            if has_positional_payload(payload) {
                return Err(fault(
                    "renamed_positional",
                    "exhaustive_single_response claims a complete single response but the payload embeds a numeric coordinate"
                        .to_string(),
                ));
            }
        }
    }
    // Offset inside the Floor needs no further renaming checks.

    let next_revision = cursor_revision + 1;
    let next_request_identity = if terminated || normalized_next == "exhaustive_single_response" {
        missing(
            "not_applicable",
            "walk terminates with this response; no further request is planned",
        )
    } else if normalized_next == "continuation" || normalized_next == "keyset" {
        let token = established(response_map, "continuation_token")
            .cloned()
            .unwrap_or_else(|| missing("not_observed", "continuation token carried by termination"));
        json!({
            "kind": decl_kind,
            "based_on_sequence": request_sequence,
            "continuation_token": token,
            "cursor_revision": next_revision,
        })
    } else {
        json!({
            "kind": decl_kind,
            "based_on_sequence": request_sequence,
            "next_offset": request_sequence + 1,
            "cursor_revision": next_revision,
        })
    };

    let plan = json!({
        "record_type": "cursor_step_plan",
        "schema_version": SCHEMA_VERSION,
        "target": decl_target,
        "run_id": decl_run,
        "partition_id": decl_partition,
        "walk_id": walk_id,
        "cursor_ref": walk_ref,
        "prior_revision": cursor_revision,
        "next_revision": next_revision,
        "cursor_kind": decl_kind,
        "ordering_model": decl_ordering,
        "coverage_scope": decl_scope,
        "request_sequence": request_sequence,
        "next_request_identity": next_request_identity,
        "previous_response_hash": page_hash,
        "session_epoch": response_session,
        "backend_signature": response_backend,
        "terminated": terminated,
        "certified": true,
        "evidence_refs": evidence_refs,
    });
    validate(PLAN_SCHEMA, plan)
}

/// Plan the durable commit of one page observation packet against a cursor.
///
/// The packet must name the cursor walk, carry the next request sequence
/// (`last_committed+1`), complete six-verdict counts, and matching
/// session/backend generations. Replay of the last committed sequence with
/// identical hashes deduplicates (`deduped=true`, no revision advance, out
/// of the proof cohort); the same sequence with different hashes is an
/// `integrity_conflict`; a sequence skipping ahead is `beyond_materialized`.
///
/// The returned `observation_commit_plan` (under `audit_log`) is a plan, not
/// a committed row: the caller still performs the owner-local atomic commit
/// of packet, entity effects, and cursor movement. `in_active_proof_cohort`
/// is true only for a non-replay packet whose `cursor_capability_status` is
/// exactly `verified`; uncertified packets materialize listings with unproven
/// coverage and never enter the cohort here.
pub fn plan_observation_commit(
    cursor: &CheckedRecord,
    packet: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let cursor_map = as_object(cursor, "invalid_cursor", "cursor")?;
    let packet_map = as_object(packet, "invalid_packet", "packet")?;

    let cursor_target = required_str(cursor_map, "target", "invalid_cursor", "cursor")?;
    let cursor_run = required_str(cursor_map, "run_id", "invalid_cursor", "cursor")?;
    let cursor_partition = required_str(cursor_map, "partition_id", "invalid_cursor", "cursor")?;
    let walk_id = required_str(cursor_map, "walk_id", "invalid_cursor", "cursor")?;
    let packet_target = required_str(packet_map, "target", "invalid_packet", "packet")?;
    let packet_run = required_str(packet_map, "run_id", "invalid_packet", "packet")?;
    let packet_partition = required_str(packet_map, "partition_id", "invalid_packet", "packet")?;
    let packet_walk = required_str(packet_map, "walk_id", "invalid_packet", "packet")?;
    if packet_target != cursor_target
        || packet_run != cursor_run
        || packet_partition != cursor_partition
        || packet_walk != walk_id
    {
        return Err(fault(
            "walk_scope_mismatch",
            format!(
                "packet walk ({packet_target}/{packet_run}/{packet_partition}/{packet_walk}) does not match cursor ({cursor_target}/{cursor_run}/{cursor_partition}/{walk_id})"
            ),
        ));
    }
    if let Some(status) = established(cursor_map, "status").and_then(Value::as_str) {
        if TERMINAL_CURSOR.contains(&status) {
            return Err(fault(
                "walk_terminated",
                format!("cursor walk status {status:?} is terminal; no packet is committed"),
            ));
        }
    }
    let cursor_revision = required_u64(cursor_map, "cursor_revision", "invalid_cursor", "cursor")?;
    let last_committed =
        required_u64(cursor_map, "last_committed_request_sequence", "invalid_cursor", "cursor")?;
    let request_sequence = required_u64(packet_map, "request_sequence", "invalid_packet", "packet")?;

    let request_identity = Value::Object(
        required_object(packet_map, "request_identity", "invalid_packet", "packet")?.clone(),
    );
    let response_hash = validated_sh(packet_map, "response_hash", "packet")?;
    let page_hash = validated_sh(packet_map, "page_hash", "packet")?;
    let response_text = hash_text(&response_hash).unwrap_or_default();
    let page_text = hash_text(&page_hash).unwrap_or_default();
    let ordered_ids = validated_ordered_ids(packet_map, "packet")?;
    let verdict_counts = validated_verdict_counts(packet_map, "packet")?;
    let packet_session = validated_sid(packet_map, "session_epoch", "packet")?;
    let packet_backend = validated_mid(packet_map, "backend_signature", "packet")?;
    let cursor_session = validated_sid(cursor_map, "session_epoch", "cursor").unwrap_or_else(|_| {
        missing("not_applicable", "cursor carries no session epoch")
    });
    let cursor_backend = validated_mid(cursor_map, "backend_signature", "cursor").unwrap_or_else(|_| {
        missing("not_applicable", "cursor carries no backend signature")
    });
    if !established_equal(&cursor_session, &packet_session) {
        return Err(fault(
            "session_mismatch",
            "packet session_epoch does not match the cursor generation; replay across generations never merges"
                .to_string(),
        ));
    }
    if !established_equal(&cursor_backend, &packet_backend) {
        return Err(fault(
            "backend_mismatch",
            "packet backend_signature does not match the cursor cohort".to_string(),
        ));
    }
    let evidence_refs = extract_support(&[established(packet_map, "evidence_refs")], "plan_observation_commit")?;
    let reported_count = packet_map
        .get("reported_count_evidence")
        .cloned()
        .unwrap_or_else(|| missing("not_observed", "response carried no count evidence"));

    let walk_ref = cursor_walk_ref(cursor_target, cursor_run, cursor_partition, walk_id)?;
    let observation_id = observation_identity(&walk_ref, request_sequence, &page_text);

    // Replay / gap handling against the durable boundary.
    if request_sequence <= last_committed {
        // Deduplicate identical redelivery; conflicting content is an
        // integrity incident, never last-write-wins.
        let prior_matches = match established(cursor_map, "previous_response_hash") {
            None => false,
            Some(prior) => {
                let prior_text = hash_text(prior).unwrap_or_default();
                !prior_text.is_empty() && (prior_text == response_text || prior_text == page_text)
            }
        };
        // Cursors without a retained prior hash cannot confirm identity, so a
        // stale sequence is still a conflict rather than a silent dedup.
        if request_sequence == last_committed && prior_matches {
            let plan = json!({
                "record_type": "observation_commit_plan",
                "schema_version": SCHEMA_VERSION,
                "target": cursor_target,
                "run_id": cursor_run,
                "partition_id": cursor_partition,
                "walk_id": walk_id,
                "cursor_ref": walk_ref,
                "observation_id": observation_id,
                "request_sequence": request_sequence,
                "request_identity": request_identity,
                "response_hash": response_hash,
                "page_hash": page_hash,
                "ordered_observed_ids": ordered_ids,
                "render_verdict_counts": verdict_counts,
                "reported_count_evidence": reported_count,
                "session_epoch": packet_session,
                "backend_signature": packet_backend,
                "in_active_proof_cohort": false,
                "deduped": true,
                "prior_revision": cursor_revision,
                "next_revision": cursor_revision,
                "evidence_refs": evidence_refs,
            });
            return validate(PLAN_SCHEMA, plan);
        }
        return Err(fault(
            "integrity_conflict",
            format!(
                "packet sequence {request_sequence} is at or behind last committed {last_committed} with non-matching hashes; conflicting content under one observation identity is an integrity incident"
            ),
        ));
    }
    if request_sequence != last_committed + 1 {
        return Err(fault(
            "beyond_materialized",
            format!(
                "packet sequence {request_sequence} skips beyond last committed {last_committed}; journal gaps never commit ahead"
            ),
        ));
    }

    let verified_cohort =
        matches!(established(packet_map, "cursor_capability_status"), Some(Value::String(status)) if status == "verified");
    let plan = json!({
        "record_type": "observation_commit_plan",
        "schema_version": SCHEMA_VERSION,
        "target": cursor_target,
        "run_id": cursor_run,
        "partition_id": cursor_partition,
        "walk_id": walk_id,
        "cursor_ref": walk_ref,
        "observation_id": observation_id,
        "request_sequence": request_sequence,
        "request_identity": request_identity,
        "response_hash": response_hash,
        "page_hash": page_hash,
        "ordered_observed_ids": ordered_ids,
        "render_verdict_counts": verdict_counts,
        "reported_count_evidence": reported_count,
        "session_epoch": packet_session,
        "backend_signature": packet_backend,
        "in_active_proof_cohort": verified_cohort,
        "deduped": false,
        "prior_revision": cursor_revision,
        "next_revision": cursor_revision + 1,
        "evidence_refs": evidence_refs,
    });
    validate(PLAN_SCHEMA, plan)
}

/// Gate walk restart on ordering, session, and backend compatibility.
///
/// The cursor pin (`ordering_model`, `coverage_scope`) must equal the
/// `ordering` declaration exactly, the ordering fingerprints must match, and
/// established session/backend generations must agree (compared without
/// integer/string coercion). Terminal cursor or session statuses, fenced
/// owner epochs, and positional cursors outside `Deterministic` + `per_run`
/// are rejected. Success returns `Ok(())` and commits nothing; the caller
/// still performs the owner-local resume commit.
pub fn validate_resume(
    cursor: &CheckedRecord,
    session: &CheckedRecord,
    ordering: &CheckedRecord,
) -> Result<(), Fault> {
    let cursor_map = as_object(cursor, "invalid_cursor", "cursor")?;
    let session_map = as_object(session, "invalid_session", "session")?;
    let ordering_map = as_object(ordering, "invalid_ordering", "ordering")?;

    let cursor_target = required_str(cursor_map, "target", "invalid_cursor", "cursor")?;
    let cursor_run = required_str(cursor_map, "run_id", "invalid_cursor", "cursor")?;
    let cursor_partition = required_str(cursor_map, "partition_id", "invalid_cursor", "cursor")?;
    let walk_id = required_str(cursor_map, "walk_id", "invalid_cursor", "cursor")?;
    let cursor_kind = required_str(cursor_map, "cursor_kind", "invalid_cursor", "cursor")?;
    let cursor_ordering = required_str(cursor_map, "ordering_model", "invalid_cursor", "cursor")?;
    let cursor_scope = required_str(cursor_map, "coverage_scope", "invalid_cursor", "cursor")?;
    let ordering_model = required_str(ordering_map, "ordering_model", "invalid_ordering", "ordering")?;
    let ordering_scope = required_str(ordering_map, "coverage_scope", "invalid_ordering", "ordering")?;
    if cursor_ordering != ordering_model || cursor_scope != ordering_scope {
        return Err(fault(
            "ordering_mismatch",
            format!(
                "cursor pin ({cursor_ordering}/{cursor_scope}) does not match ordering declaration ({ordering_model}/{ordering_scope})"
            ),
        ));
    }
    // Ordering scope pins, when present, must agree with the cursor walk.
    for (field, expected) in [
        ("target", cursor_target),
        ("run_id", cursor_run),
        ("partition_id", cursor_partition),
    ] {
        if let Some(Value::String(text)) = established(ordering_map, field) {
            if text != expected {
                return Err(fault(
                    "walk_scope_mismatch",
                    format!("ordering {field:?} {text:?} does not match cursor {expected:?}"),
                ));
            }
        }
    }
    // Session scope pins, when present, must agree with the cursor.
    for (field, expected) in [("target", cursor_target), ("run_id", cursor_run)] {
        if let Some(Value::String(text)) = established(session_map, field) {
            if text != expected {
                return Err(fault(
                    "walk_scope_mismatch",
                    format!("session {field:?} {text:?} does not match cursor {expected:?}"),
                ));
            }
        }
    }

    // Fingerprint compatibility gates restart.
    let cursor_print = cursor_map.get("ordering_fingerprint").ok_or_else(|| {
        fault(
            "invalid_cursor",
            "cursor requires an established ordering_fingerprint".to_string(),
        )
    })?;
    let ordering_print = ordering_map.get("ordering_fingerprint").ok_or_else(|| {
        fault(
            "invalid_ordering",
            "ordering requires an established ordering_fingerprint".to_string(),
        )
    })?;
    let cursor_text = fingerprint_text(cursor_print).ok_or_else(|| {
        fault(
            "invalid_cursor",
            "cursor ordering_fingerprint must carry digest text".to_string(),
        )
    })?;
    let ordering_text = fingerprint_text(ordering_print).ok_or_else(|| {
        fault(
            "invalid_ordering",
            "ordering ordering_fingerprint must carry digest text".to_string(),
        )
    })?;
    if cursor_text != ordering_text {
        return Err(fault(
            "ordering_drift",
            "ordering fingerprint changed across restart; resume from the last committed coordinate requires a compatible fingerprint"
                .to_string(),
        ));
    }

    // Positional cursors resume only inside the Floor.
    if looks_positional(cursor_kind) && !is_certified_scope(ordering_model, ordering_scope) {
        return Err(fault(
            "uncertified_positional",
            format!(
                "cursor kind {cursor_kind:?} is positional and resumes only for Deterministic/per_run (got {ordering_model}/{ordering_scope})"
            ),
        ));
    }

    // Terminal lifecycle refuses resume.
    if let Some(status) = established(cursor_map, "status").and_then(Value::as_str) {
        if TERMINAL_CURSOR.contains(&status) {
            return Err(fault(
                "walk_terminated",
                format!("cursor walk status {status:?} is terminal; resume is refused"),
            ));
        }
    }
    if let Some(status) = established(session_map, "status").and_then(Value::as_str) {
        if TERMINAL_SESSION.contains(&status) {
            return Err(fault(
                "session_expired",
                format!("session status {status:?} is terminal; resume requires a live generation"),
            ));
        }
    }
    // Owner fencing: at most one active owner per generation.
    if let (Some(Value::Number(cursor_epoch)), Some(Value::Number(session_epoch))) = (
        established(cursor_map, "owner_epoch"),
        established(session_map, "owner_epoch"),
    ) {
        if cursor_epoch.as_u64() != session_epoch.as_u64() {
            return Err(fault(
                "owner_fenced",
                "cursor owner_epoch does not match the session generation; the stale owner is fenced"
                    .to_string(),
            ));
        }
    }

    // Session and backend generations must agree.
    let cursor_session = validated_sid(cursor_map, "session_epoch", "cursor").unwrap_or_else(|_| {
        missing("not_applicable", "cursor carries no session epoch")
    });
    let session_epoch_value = session_map
        .get("session_epoch")
        .cloned()
        .unwrap_or_else(|| missing("not_applicable", "session carries no epoch"));
    if !is_missing(&session_epoch_value) {
        match &session_epoch_value {
            Value::String(_) | Value::Number(_) => {}
            _ => {
                return Err(fault(
                    "invalid_session",
                    "session session_epoch must be a string/int SID or a Missing envelope".to_string(),
                ));
            }
        }
    }
    if !established_equal(&cursor_session, &session_epoch_value) {
        return Err(fault(
            "session_mismatch",
            "cursor session_epoch does not match the live session generation; resume never substitutes generations"
                .to_string(),
        ));
    }
    let cursor_backend = validated_mid(cursor_map, "backend_signature", "cursor").unwrap_or_else(|_| {
        missing("not_applicable", "cursor carries no backend signature")
    });
    let ordering_backend = ordering_map
        .get("backend_signature")
        .cloned()
        .unwrap_or_else(|| missing("not_applicable", "ordering carries no backend signature"));
    if !is_missing(&ordering_backend) && !matches!(&ordering_backend, Value::String(_)) {
        return Err(fault(
            "invalid_ordering",
            "ordering backend_signature must be a string ID or a Missing envelope".to_string(),
        ));
    }
    if !established_equal(&cursor_backend, &ordering_backend) {
        return Err(fault(
            "backend_mismatch",
            "cursor backend_signature does not match the ordering cohort; backend discontinuity invalidates the active proof cohort"
                .to_string(),
        ));
    }

    // Validate the walk identity framing; the reference itself is discarded.
    let _ = cursor_walk_ref(cursor_target, cursor_run, cursor_partition, walk_id)?;
    Ok(())
}

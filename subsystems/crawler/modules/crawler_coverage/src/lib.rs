//! `crawler_coverage`: coverage algebra (C26) and split tree (C30).
//!
//! Implements seam map §17.1 (proof rules), §17.2 (bisection), §10 (ledger),
//! and §4.2 (export) on top of the structural [`crawler_schema`] gate:
//!
//! * [`evaluate_proof`] evaluates the eleven coverage guards and selects the
//!   proof algebra by priority (lower-bound union, floor, verified exact
//!   equality, then none). Zero observations always yield false proof with
//!   `empty_unproven`. Duplicated observations never substitute for distinct
//!   pagination evidence: equality and floor require the distinct union to
//!   satisfy the equation, not merely the inflated observed total.
//! * [`plan_split`] selects a bisection axis by priority (declared partition
//!   keys, primary key, verified date keys, verified secondary keys),
//!   validates that child predicates cover the parent, declares overlap
//!   explicitly, combines observations by exact ID union (never blind
//!   addition), and excludes parent exploratory counts from child proof
//!   arithmetic. Maximum saturated depth is three; siblings continue.
//! * [`build_coverage_export`] assembles a closed `crawler_coverage_export`
//!   record from a ledger, cursor snapshots, and a proof evaluation.
//!
//! Dependency discipline:
//!
//! * Predicate identity is confirmed with
//!   [`crawler_hashing::verify_record_digest`] over the canonical predicate
//!   bytes; ledger/cursor references are length-framed with
//!   [`crawler_hashing::frame_reference`], never slash-concatenated.
//! * Ledger rows are re-normalized with
//!   [`crawler_normalization::normalize_row`] during export so exhaustive
//!   column preservation is enforced, not assumed.
//! * When a cohort carries embedded `cursor`/`session`/`ordering` objects,
//!   traversal permission is cross-checked with
//!   [`crawler_cursors::validate_resume`]; a resume fault fails the
//!   `cursor_permitted` guard instead of being silently ignored.
//! * Detector and drift inputs are the output shapes of
//!   `crawler_detectors::evaluate_detectors` / `evaluate_drift` (diagnostic
//!   domain, blocking flags, corroboration counts, drift bands). This module
//!   validates those shapes and their resolution; it never re-runs detection
//!   and never emits qualification.
//!
//! # `evaluate_proof` contract
//!
//! `declaration` carries the pinned predicate and proof parameters:
//!
//! ```text
//! {
//!   "target": ID, "run_id": ID, "partition_id": ID,
//!   "partition_predicate_json": E,
//!   "partition_definition_hash": SH,
//!   "reported_total_unit": "postings",
//!   "session_min_count": REV,
//!   "evidence_refs": SUPPORT,
//!   "evidence_prefix": PREFIX (optional)
//! }
//! ```
//!
//! `ledger` carries the coverage ledger subset (§10 plus traversal markers):
//!
//! ```text
//! {
//!   "target": ID, "run_id": ID, "partition_id": ID,
//!   "partition_predicate_json": E,
//!   "partition_definition_hash": SH,
//!   "reported_total": REV | Missing,
//!   "reported_total_unit": "postings",
//!   "reported_total_source": TEXT,
//!   "count_source_verified": BOOL (or "reported_total_source_verified"),
//!   "floor_value": REV | Missing,
//!   "header_label_is_floor": BOOL,
//!   "saturation_marker_present": BOOL,
//!   "session_reported_aggregates": E,
//!   "observed_total": REV,
//!   "distinct_observed_total": REV,
//!   "repeated_distinct_id_total": REV,
//!   "duplicate_rate": NUM[0,1],
//!   "render_pass_total": REV,
//!   "session_count": REV,
//!   "terminated": BOOL (or "termination" / "termination_evidence"),
//!   "cursor_permitted": BOOL (optional, cohort is authoritative),
//!   "replay_inflation_detected": BOOL (optional, default false),
//!   "child_partition_ids": [ID] (optional, default []),
//!   "children_proven": BOOL (optional),
//!   "child_coverage_refs": [REF] (optional),
//!   "observed_ids": [ID] (optional, union consistency check),
//!   "parent_exploratory_total": REV (optional, default 0, always excluded)
//! }
//! ```
//!
//! `cohort` carries the compatible active cohort:
//!
//! ```text
//! {
//!   "cohort_refs": [REF] (or "proof_cohort_refs"),
//!   "count_units": "postings",
//!   "predicate_hash": SH,
//!   "cursor_permitted": BOOL (or "traversal_permitted"),
//!   "eligible_sessions": BOOL (optional),
//!   "replay_inflation_detected": BOOL (optional),
//!   "child_coverage_refs": [REF] (optional),
//!   "cursor": OBJECT (optional, for validate_resume cross-check),
//!   "session": OBJECT (optional),
//!   "ordering": OBJECT (optional)
//! }
//! ```
//!
//! `detectors` carries detector resolution: either `{resolved: BOOL}`,
//! `{blocking: BOOL}`, or the full `evaluate_detectors` output shape with a
//! `detectors` array (each entry carrying `blocking`) and/or a top-level
//! `blocking` flag.
//!
//! # `plan_split` contract
//!
//! `declaration` carries split configuration:
//!
//! ```text
//! {
//!   "target": ID, "run_id": ID,
//!   "parent_partition_id": ID (or "partition_id"),
//!   "declared_partition_keys": [TEXT] (optional),
//!   "primary_key": TEXT | Missing (optional),
//!   "verified_date_keys": [TEXT] (optional),
//!   "verified_secondary_keys": [TEXT] (optional),
//!   "ascending_overflow_established": BOOL (optional, default false),
//!   "evidence_refs": SUPPORT (optional if evidence carries it)
//! }
//! ```
//!
//! `parent` carries the parent ledger subset:
//!
//! ```text
//! {
//!   "target": ID, "run_id": ID, "partition_id": ID,
//!   "partition_predicate_json": E,
//!   "split_round": 0..3,
//!   "parent_exploratory_total": REV (optional, default 0)
//! }
//! ```
//!
//! `evidence` carries journal evidence plus optional explicit children:
//!
//! ```text
//! {
//!   "evidence_prefix": PREFIX (optional if declaration carries it),
//!   "evidence_refs": SUPPORT,
//!   "proposed_children": [{partition_id, predicate_json}] (optional),
//!   "covering_attested": BOOL (optional, for opaque predicates),
//!   "covering_evidence_refs": SUPPORT (optional, with attestation),
//!   "overlap_ids": [...] (optional, explicit overlap for opaque predicates)
//! }
//! ```
//!
//! # `build_coverage_export` contract
//!
//! `ledger` carries at least `target`, `run_id`, `partition_id`, and
//! optionally `child_partition_ids`. `cursors` are cursor-state rows each
//! carrying `target`, `run_id`, `partition_id`, `walk_id`. `evaluation`
//! carries:
//!
//! ```text
//! {
//!   "target": ID, "run_id": ID, "partition_id": ID (optional, scope-checked),
//!   "declaration": PIN,
//!   "proof": ProofEvaluation (or flattened proof fields at top level),
//!   "detectors": [DetectorEvaluation],
//!   "drift": DriftEvaluation,
//!   "measurements": [ME],
//!   "evidence_prefix": PREFIX,
//!   "evidence_refs": SUPPORT,
//!   "cursor_capability_status": "verified" | "unverified",
//!   "cursor_capability_evidence_refs": ERS,
//!   "uncertified_observations": [AR] (optional, default [])
//! }
//! ```

use crawler_cursors::validate_resume;
use crawler_hashing::{canonical_bytes, digest_bytes, frame_reference, verify_record_digest};
use crawler_normalization::normalize_row;
use crawler_schema::{record_value, validate, CheckedRecord, Fault, SourceEntity};
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

/// Dependency anchor: detector and drift inputs consumed here are the output
/// shapes of these evaluations (diagnostic domain, blocking flags, drift
/// bands). Referenced so the `crawler_detectors` path dependency stays live;
/// this module validates those outputs and never re-runs detection.
#[allow(dead_code)]
fn _detector_dependency_anchor() {
    let _ = crawler_detectors::evaluate_detectors;
    let _ = crawler_detectors::evaluate_drift;
}

/// Crawler seam profile version stamped on emitted records.
const SCHEMA_VERSION: &str = "crawler-seam/0.1.0";
/// Structural envelope for proof evaluations and split plans.
const OUTPUT_SCHEMA: &str = "audit_log";
/// Closed export schema (§4.2).
const EXPORT_SCHEMA: &str = "crawler_coverage_export";

/// The eleven coverage guards (§4.2), in evaluation order.
const GUARD_IDS: &[&str] = &[
    "count_units",
    "predicate_identity",
    "count_source_verified",
    "cursor_permitted",
    "detectors_resolved",
    "termination",
    "no_replay_inflation",
    "no_duplicate_substitution",
    "eligible_sessions",
    "positive_observations",
    "covering_children",
];

/// Closed detector actions (§4.2).
const DETECTOR_ACTIONS: &[&str] = &[
    "monitor",
    "stop_walk",
    "split",
    "reconcile",
    "proven_via_children",
    "mark_incomplete",
];

/// Maximum saturated split depth (§17.2).
const MAX_SPLIT_ROUND: u64 = 3;

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn fault(code: &str, detail: impl Into<String>) -> Fault {
    Fault {
        code: code.to_string(),
        detail: detail.into(),
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
            format!("{what} must be a JSON object of coverage fields"),
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
        Some(Value::String(_)) => Err(fault(
            code,
            format!("{what} field {field:?} must be a nonempty string"),
        )),
        Some(_) => Err(fault(
            code,
            format!("{what} field {field:?} must be a string"),
        )),
        None => Err(fault(
            code,
            format!("{what} requires established field {field:?}"),
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
                format!("{what} field {field:?} must be an unsigned integer count"),
            )
        }),
        Some(_) => Err(fault(
            code,
            format!("{what} field {field:?} must be an unsigned integer count"),
        )),
        None => Err(fault(
            code,
            format!("{what} requires established field {field:?}"),
        )),
    }
}

fn required_bool(map: &Map<String, Value>, field: &str, code: &str, what: &str) -> Result<bool, Fault> {
    match established(map, field) {
        Some(Value::Bool(flag)) => Ok(*flag),
        Some(_) => Err(fault(
            code,
            format!("{what} field {field:?} must be a boolean"),
        )),
        None => Err(fault(
            code,
            format!("{what} requires established field {field:?}"),
        )),
    }
}

fn required_f64(map: &Map<String, Value>, field: &str, code: &str, what: &str) -> Result<f64, Fault> {
    match established(map, field) {
        Some(Value::Number(number)) => {
            let value = number.as_f64().ok_or_else(|| {
                fault(
                    code,
                    format!("{what} field {field:?} must be a finite number"),
                )
            })?;
            if !value.is_finite() {
                return Err(fault(
                    code,
                    format!("{what} field {field:?} must be a finite number"),
                ));
            }
            Ok(value)
        }
        Some(_) => Err(fault(
            code,
            format!("{what} field {field:?} must be a finite number"),
        )),
        None => Err(fault(
            code,
            format!("{what} requires established field {field:?}"),
        )),
    }
}

/// Optional unsigned count: absent or `Missing` yields `None`.
fn optional_u64(
    map: &Map<String, Value>,
    field: &str,
    code: &str,
    what: &str,
) -> Result<Option<u64>, Fault> {
    match map.get(field) {
        None => Ok(None),
        Some(value) if is_missing(value) => Ok(None),
        Some(Value::Number(number)) => number.as_u64().map(Some).ok_or_else(|| {
            fault(
                code,
                format!("{what} field {field:?} must be an unsigned integer count or Missing"),
            )
        }),
        Some(_) => Err(fault(
            code,
            format!("{what} field {field:?} must be an unsigned integer count or Missing"),
        )),
    }
}

/// Optional boolean: absent yields `None`; `Missing` yields `Some(false)`
/// (unknown is not established true).
fn optional_bool_present(
    map: &Map<String, Value>,
    field: &str,
    code: &str,
    what: &str,
) -> Result<Option<bool>, Fault> {
    match map.get(field) {
        None => Ok(None),
        Some(value) if is_missing(value) => Ok(Some(false)),
        Some(Value::Bool(flag)) => Ok(Some(*flag)),
        Some(_) => Err(fault(
            code,
            format!("{what} field {field:?} must be a boolean or Missing"),
        )),
    }
}

/// Digest text of an `SH`-shaped value: a bare string or `{value, ..}`.
/// `Missing` yields `None`.
fn hash_text(value: &Value) -> Option<String> {
    if is_missing(value) {
        return None;
    }
    match value {
        Value::String(text) if !text.is_empty() => Some(text.clone()),
        Value::Object(map) => match map.get("value") {
            Some(Value::String(text)) if !text.is_empty() => Some(text.clone()),
            _ => None,
        },
        _ => None,
    }
}

/// Canonical SHA-256 digest text: exactly 64 lowercase hex characters.
fn is_digest_text(text: &str) -> bool {
    text.len() == 64
        && text.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Nonempty `SUPPORT` evidence refs (array of objects).
fn required_support(
    map: &Map<String, Value>,
    field: &str,
    code: &str,
    what: &str,
) -> Result<Value, Fault> {
    match established(map, field) {
        Some(Value::Array(refs)) if !refs.is_empty() => {
            if refs.iter().all(Value::is_object) {
                Ok(Value::Array(refs.to_vec()))
            } else {
                Err(fault(
                    code,
                    format!("{what} field {field:?} must be SUPPORT (array of objects)"),
                ))
            }
        }
        Some(Value::Array(_)) => Err(fault(
            code,
            format!("{what} field {field:?} must be nonempty SUPPORT"),
        )),
        Some(_) => Err(fault(
            code,
            format!("{what} field {field:?} must be nonempty SUPPORT"),
        )),
        None => Err(fault(
            code,
            format!("{what} requires established field {field:?}"),
        )),
    }
}

fn guard_value(guard_id: &str, result: &str, evidence_refs: &Value, rationale: String) -> Value {
    json!({
        "guard_id": guard_id,
        "result": result,
        "evidence_refs": evidence_refs.clone(),
        "rationale": rationale,
    })
}

fn scope_match(
    map: &Map<String, Value>,
    what: &str,
    target: &str,
    run_id: &str,
    partition_id: &str,
) -> Result<(), Fault> {
    for (field, expected) in [
        ("target", target),
        ("run_id", run_id),
        ("partition_id", partition_id),
    ] {
        if let Some(Value::String(text)) = established(map, field) {
            if text != expected {
                return Err(fault(
                    "scope_mismatch",
                    format!(
                        "{what} {field:?} {text:?} does not match the declared {expected:?}"
                    ),
                ));
            }
        }
    }
    Ok(())
}

/// True when `predicate_json` canonicalizes to `expected_digest` under the
/// kernel JCS profile. Any structural or digest failure yields false (the
/// caller records a failed guard rather than faulting).
fn predicate_digest_matches(predicate_json: &Value, expected_digest: &str) -> bool {
    if !is_digest_text(expected_digest) {
        return false;
    }
    let record = match validate(OUTPUT_SCHEMA, predicate_json.clone()) {
        Ok(record) => record,
        Err(_) => return false,
    };
    verify_record_digest(&record, expected_digest).is_ok()
}

/// Canonical digest of a JSON value via the kernel JCS profile.
fn digest_for_value(value: &Value, what: &str) -> Result<String, Fault> {
    let record = validate(OUTPUT_SCHEMA, value.clone())
        .map_err(|_| fault("invalid_predicate", format!("{what} predicate is not gate-valid")))?;
    let bytes = canonical_bytes(&record)
        .map_err(|e| fault("invalid_predicate", format!("{what} canonicalization failed: {}", e.detail)))?;
    Ok(digest_bytes(&bytes))
}

// ---------------------------------------------------------------------------
// Proof evaluation (C26)
// ---------------------------------------------------------------------------

/// Maximum of `session_reported_aggregates` (`None` when inapplicable).
fn session_aggregate_max(value: &Value) -> Result<Option<u64>, Fault> {
    fn number_as_u64(value: &Value) -> Result<u64, Fault> {
        match value {
            Value::Number(number) => number.as_u64().ok_or_else(|| {
                fault(
                    "invalid_ledger",
                    "session aggregates must be unsigned integer counts".to_string(),
                )
            }),
            _ => Err(fault(
                "invalid_ledger",
                "session aggregates must be unsigned integer counts".to_string(),
            )),
        }
    }

    fn object_aggregate(obj: &Map<String, Value>) -> Result<u64, Fault> {
        for key in [
            "total",
            "reported_total",
            "value",
            "aggregate",
            "max",
            "count",
            "session_total",
        ] {
            if let Some(Value::Number(number)) = established(obj, key) {
                if let Some(count) = number.as_u64() {
                    return Ok(count);
                }
                return Err(fault(
                    "invalid_ledger",
                    format!("session aggregate field {key:?} must be an unsigned integer count"),
                ));
            }
        }
        Err(fault(
            "invalid_ledger",
            "session aggregate objects must carry one of total/reported_total/value/aggregate/max/count/session_total"
                .to_string(),
        ))
    }

    if is_missing(value) {
        return Ok(None);
    }
    match value {
        Value::Array(items) => {
            if items.is_empty() {
                return Ok(None);
            }
            let mut max: Option<u64> = None;
            for item in items {
                if is_missing(item) {
                    continue;
                }
                let count = match item {
                    Value::Number(_) => number_as_u64(item)?,
                    Value::Object(obj) => object_aggregate(obj)?,
                    _ => {
                        return Err(fault(
                            "invalid_ledger",
                            "session aggregates must be counts or count objects".to_string(),
                        ))
                    }
                };
                max = Some(max.map_or(count, |current| current.max(count)));
            }
            Ok(max)
        }
        Value::Object(obj) => {
            for key in ["max", "maximum", "session_max", "value", "total"] {
                if let Some(Value::Number(number)) = established(obj, key) {
                    let count = number.as_u64().ok_or_else(|| {
                        fault(
                            "invalid_ledger",
                            "session aggregate maximum must be an unsigned integer count".to_string(),
                        )
                    })?;
                    return Ok(Some(count));
                }
            }
            for key in ["aggregates", "values", "totals", "sessions"] {
                if established(obj, key).is_some_and(Value::is_array) {
                    let nested = obj.get(key).expect("checked present");
                    return session_aggregate_max(nested);
                }
            }
            Err(fault(
                "invalid_ledger",
                "session aggregate objects must carry max or an aggregates array".to_string(),
            ))
        }
        Value::Number(_) => Ok(Some(number_as_u64(value)?)),
        _ => Err(fault(
            "invalid_ledger",
            "session_reported_aggregates must be session counts, count objects, or Missing"
                .to_string(),
        )),
    }
}

/// Unique ID count of an `observed_ids` array, with integer/string unions
/// kept distinct (`7` never equals `"7"`).
fn unique_observed_ids(value: &Value) -> Result<Option<u64>, Fault> {
    match value {
        Value::Array(items) => {
            let mut seen = BTreeSet::new();
            for item in items {
                if is_missing(item) {
                    return Err(fault(
                        "invalid_ledger",
                        "observed_ids entries must be established string/int identities".to_string(),
                    ));
                }
                let tag = match item {
                    Value::String(text) => format!("s:{text}"),
                    Value::Number(number) => {
                        if let Some(unsigned) = number.as_u64() {
                            format!("i:{unsigned}")
                        } else if let Some(signed) = number.as_i64() {
                            format!("i:{signed}")
                        } else {
                            return Err(fault(
                                "invalid_ledger",
                                "observed_ids entries must be string/int identities".to_string(),
                            ));
                        }
                    }
                    _ => {
                        return Err(fault(
                            "invalid_ledger",
                            "observed_ids entries must be string/int identities".to_string(),
                        ))
                    }
                };
                seen.insert(tag);
            }
            Ok(Some(seen.len() as u64))
        }
        _ => Err(fault(
            "invalid_ledger",
            "observed_ids must be an array of string/int identities".to_string(),
        )),
    }
}

/// Detector resolution: `resolved` bool, `blocking` bool, or a full
/// `evaluate_detectors` output (`detectors` array and/or top-level
/// `blocking`).
fn detectors_resolved(map: &Map<String, Value>) -> Result<bool, Fault> {
    if let Some(value) = map.get("resolved") {
        if is_missing(value) {
            return Ok(false);
        }
        if let Value::Bool(resolved) = value {
            return Ok(*resolved);
        }
        return Err(fault(
            "invalid_detectors",
            "detectors field \"resolved\" must be a boolean".to_string(),
        ));
    }
    if let Some(Value::Array(entries)) = established(map, "detectors") {
        let mut saw = false;
        for entry in entries {
            let obj = entry.as_object().ok_or_else(|| {
                fault(
                    "invalid_detectors",
                    "detector entries must be objects".to_string(),
                )
            })?;
            saw = true;
            match obj.get("blocking") {
                Some(Value::Bool(true)) => return Ok(false),
                Some(Value::Bool(false)) => {}
                Some(value) if is_missing(value) => return Ok(false),
                _ => {
                    return Err(fault(
                        "invalid_detectors",
                        "detector entries must carry an established blocking flag".to_string(),
                    ))
                }
            }
        }
        if saw {
            if let Some(Value::Bool(top_blocking)) = established(map, "blocking") {
                if *top_blocking {
                    return Ok(false);
                }
            }
            return Ok(true);
        }
    }
    match map.get("blocking") {
        Some(Value::Bool(blocking)) => Ok(!blocking),
        Some(value) if is_missing(value) => Ok(false),
        Some(_) => Err(fault(
            "invalid_detectors",
            "detectors blocking flag must be a boolean".to_string(),
        )),
        None => Err(fault(
            "invalid_detectors",
            "detectors must carry resolved, blocking, or a detectors array".to_string(),
        )),
    }
}

/// Optional `validate_resume` cross-check: when the cohort embeds `cursor`,
/// `session`, and `ordering` objects, they are gate-validated and resumed.
/// Returns `(checked, ok, detail)`.
fn resume_cross_check(cohort: &Map<String, Value>) -> Result<(bool, bool, String), Fault> {
    let cursor_value = established(cohort, "cursor");
    let session_value = established(cohort, "session");
    let ordering_value = established(cohort, "ordering");
    if cursor_value.is_none() && session_value.is_none() && ordering_value.is_none() {
        return Ok((false, true, "no embedded resume triple; cohort flag is authoritative".to_string()));
    }
    let (Some(cursor_json), Some(session_json), Some(ordering_json)) =
        (cursor_value, session_value, ordering_value)
    else {
        return Ok((
            true,
            false,
            "partial embedded resume triple; cursor, session, and ordering must travel together"
                .to_string(),
        ));
    };
    for (name, json) in [
        ("cursor", cursor_json),
        ("session", session_json),
        ("ordering", ordering_json),
    ] {
        if !json.is_object() {
            return Ok((
                true,
                false,
                format!("embedded {name} must be an object for resume validation"),
            ));
        }
    }
    let cursor = validate(OUTPUT_SCHEMA, (*cursor_json).clone())
        .map_err(|e| fault("invalid_cohort", format!("embedded cursor rejected: {}", e.detail)))?;
    let session = validate(OUTPUT_SCHEMA, (*session_json).clone())
        .map_err(|e| fault("invalid_cohort", format!("embedded session rejected: {}", e.detail)))?;
    let ordering = validate(OUTPUT_SCHEMA, (*ordering_json).clone())
        .map_err(|e| fault("invalid_cohort", format!("embedded ordering rejected: {}", e.detail)))?;
    match validate_resume(&cursor, &session, &ordering) {
        Ok(()) => Ok((true, true, "embedded resume triple validates".to_string())),
        Err(e) => Ok((
            true,
            false,
            format!("embedded resume rejected ({}: {})", e.code, e.detail),
        )),
    }
}

/// Evaluate the coverage proof for one partition (§17.1).
///
/// Selection priority is lower-bound union, floor, verified exact equality,
/// then none. Every proof requires all applicable guards; evaluated zero
/// observations always yield false proof with `empty_unproven`.
pub fn evaluate_proof(
    declaration: &CheckedRecord,
    ledger: &CheckedRecord,
    cohort: &CheckedRecord,
    detectors: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let decl = as_object(declaration, "invalid_declaration", "declaration")?;
    let led = as_object(ledger, "invalid_ledger", "ledger")?;
    let coh = as_object(cohort, "invalid_cohort", "cohort")?;
    let det = as_object(detectors, "invalid_detectors", "detectors")?;

    // Scope pins.
    let target = required_str(decl, "target", "invalid_declaration", "declaration")?.to_string();
    let run_id = required_str(decl, "run_id", "invalid_declaration", "declaration")?.to_string();
    let partition_id =
        required_str(decl, "partition_id", "invalid_declaration", "declaration")?.to_string();
    scope_match(led, "ledger", &target, &run_id, &partition_id)?;
    scope_match(coh, "cohort", &target, &run_id, &partition_id)?;
    scope_match(det, "detectors", &target, &run_id, &partition_id)?;

    // Declaration predicate and parameters.
    let decl_predicate = decl.get("partition_predicate_json").ok_or_else(|| {
        fault(
            "invalid_declaration",
            "declaration requires established field \"partition_predicate_json\"".to_string(),
        )
    })?;
    if is_missing(decl_predicate) || !decl_predicate.is_object() {
        return Err(fault(
            "invalid_declaration",
            "declaration partition_predicate_json must be an established object".to_string(),
        ));
    }
    let decl_hash_value = decl.get("partition_definition_hash").ok_or_else(|| {
        fault(
            "invalid_declaration",
            "declaration requires established field \"partition_definition_hash\"".to_string(),
        )
    })?;
    let decl_digest = hash_text(decl_hash_value);
    let decl_unit = required_str(
        decl,
        "reported_total_unit",
        "invalid_declaration",
        "declaration",
    )?
    .to_string();
    let session_min = required_u64(decl, "session_min_count", "invalid_declaration", "declaration")?;
    let evidence_refs = required_support(decl, "evidence_refs", "invalid_declaration", "declaration")
        .or_else(|_| required_support(led, "evidence_refs", "invalid_ledger", "ledger"))
        .or_else(|_| required_support(coh, "evidence_refs", "invalid_cohort", "cohort"))?;

    // Ledger predicate and counts.
    let ledger_predicate = led.get("partition_predicate_json").ok_or_else(|| {
        fault(
            "invalid_ledger",
            "ledger requires established field \"partition_predicate_json\"".to_string(),
        )
    })?;
    if is_missing(ledger_predicate) || !ledger_predicate.is_object() {
        return Err(fault(
            "invalid_ledger",
            "ledger partition_predicate_json must be an established object".to_string(),
        ));
    }
    let ledger_hash_value = led.get("partition_definition_hash").ok_or_else(|| {
        fault(
            "invalid_ledger",
            "ledger requires established field \"partition_definition_hash\"".to_string(),
        )
    })?;
    let ledger_digest = hash_text(ledger_hash_value);
    let ledger_unit = required_str(led, "reported_total_unit", "invalid_ledger", "ledger")?.to_string();
    let _source_label = required_str(led, "reported_total_source", "invalid_ledger", "ledger")?;
    let count_verified = optional_bool_present(led, "count_source_verified", "invalid_ledger", "ledger")?
        .or(optional_bool_present(
            led,
            "reported_total_source_verified",
            "invalid_ledger",
            "ledger",
        )?)
        .ok_or_else(|| {
            fault(
                "invalid_ledger",
                "ledger requires count_source_verified (or reported_total_source_verified)".to_string(),
            )
        })?;
    if led.get("reported_total").is_none() {
        return Err(fault(
            "invalid_ledger",
            "ledger requires field \"reported_total\" (REV or Missing)".to_string(),
        ));
    }
    let reported_total = optional_u64(led, "reported_total", "invalid_ledger", "ledger")?;
    if led.get("floor_value").is_none() {
        return Err(fault(
            "invalid_ledger",
            "ledger requires field \"floor_value\" (REV or Missing)".to_string(),
        ));
    }
    let floor_value = optional_u64(led, "floor_value", "invalid_ledger", "ledger")?;
    let header_is_floor = required_bool(led, "header_label_is_floor", "invalid_ledger", "ledger")?;
    let saturation = required_bool(led, "saturation_marker_present", "invalid_ledger", "ledger")?;
    let aggregates_value = led.get("session_reported_aggregates").ok_or_else(|| {
        fault(
            "invalid_ledger",
            "ledger requires field \"session_reported_aggregates\"".to_string(),
        )
    })?;
    let session_max = session_aggregate_max(aggregates_value)?;
    let observed = required_u64(led, "observed_total", "invalid_ledger", "ledger")?;
    let distinct = required_u64(led, "distinct_observed_total", "invalid_ledger", "ledger")?;
    let repeated = required_u64(led, "repeated_distinct_id_total", "invalid_ledger", "ledger")?;
    let duplicate_rate = required_f64(led, "duplicate_rate", "invalid_ledger", "ledger")?;
    if !(0.0..=1.0).contains(&duplicate_rate) {
        return Err(fault(
            "invalid_ledger",
            "ledger duplicate_rate must lie in [0,1]".to_string(),
        ));
    }
    let render_pass = required_u64(led, "render_pass_total", "invalid_ledger", "ledger")?;
    if render_pass > observed {
        return Err(fault(
            "invalid_ledger",
            "ledger render_pass_total cannot exceed observed_total".to_string(),
        ));
    }
    let session_count = required_u64(led, "session_count", "invalid_ledger", "ledger")?;
    let terminated = optional_bool_present(led, "terminated", "invalid_ledger", "ledger")?
        .or(optional_bool_present(led, "termination", "invalid_ledger", "ledger")?)
        .or(optional_bool_present(
            led,
            "termination_evidence",
            "invalid_ledger",
            "ledger",
        )?)
        .ok_or_else(|| {
            fault(
                "invalid_ledger",
                "ledger requires termination evidence (terminated/termination/termination_evidence)"
                    .to_string(),
            )
        })?;
    let ledger_replay = optional_bool_present(led, "replay_inflation_detected", "invalid_ledger", "ledger")?
        .unwrap_or(false);
    let parent_exploratory =
        optional_u64(led, "parent_exploratory_total", "invalid_ledger", "ledger")?.unwrap_or(0);
    let child_ids: Vec<String> = match led.get("child_partition_ids") {
        None => Vec::new(),
        Some(value) if is_missing(value) => {
            return Err(fault(
                "invalid_ledger",
                "ledger child_partition_ids must be an array of IDs".to_string(),
            ))
        }
        Some(Value::Array(ids)) => {
            let mut out = Vec::with_capacity(ids.len());
            for id in ids {
                match id {
                    Value::String(text) if !text.is_empty() => out.push(text.to_string()),
                    _ => {
                        return Err(fault(
                            "invalid_ledger",
                            "ledger child_partition_ids entries must be nonempty IDs".to_string(),
                        ))
                    }
                }
            }
            out
        }
        Some(_) => {
            return Err(fault(
                "invalid_ledger",
                "ledger child_partition_ids must be an array of IDs".to_string(),
            ))
        }
    };
    // Early shape validation for the exact ID set; cardinality is checked in
    // the duplicate guard below.
    if let Some(ids_value) = led.get("observed_ids") {
        if !is_missing(ids_value) {
            let _ = unique_observed_ids(ids_value)?;
        }
    }

    // Cohort fields.
    let cohort_refs = match coh.get("cohort_refs").or(coh.get("proof_cohort_refs")) {
        Some(Value::Array(refs)) => Value::Array(refs.to_vec()),
        Some(_) => {
            return Err(fault(
                "invalid_cohort",
                "cohort cohort_refs must be an array of cursor references".to_string(),
            ))
        }
        None => {
            return Err(fault(
                "invalid_cohort",
                "cohort requires field \"cohort_refs\" (or \"proof_cohort_refs\")".to_string(),
            ))
        }
    };
    let cohort_units = required_str(coh, "count_units", "invalid_cohort", "cohort")?.to_string();
    let cohort_hash_value = coh.get("predicate_hash").ok_or_else(|| {
        fault(
            "invalid_cohort",
            "cohort requires established field \"predicate_hash\"".to_string(),
        )
    })?;
    let cohort_digest = hash_text(cohort_hash_value);
    let cohort_permitted = optional_bool_present(coh, "cursor_permitted", "invalid_cohort", "cohort")?
        .or(optional_bool_present(
            coh,
            "traversal_permitted",
            "invalid_cohort",
            "cohort",
        )?)
        .or(optional_bool_present(led, "cursor_permitted", "invalid_ledger", "ledger")?)
        .or(optional_bool_present(
            led,
            "traversal_permitted",
            "invalid_ledger",
            "ledger",
        )?)
        .ok_or_else(|| {
            fault(
                "invalid_cohort",
                "cohort requires cursor_permitted (or traversal_permitted)".to_string(),
            )
        })?;
    let cohort_eligible = optional_bool_present(coh, "eligible_sessions", "invalid_cohort", "cohort")?
        .or(optional_bool_present(coh, "sessions_eligible", "invalid_cohort", "cohort")?);
    let cohort_replay =
        optional_bool_present(coh, "replay_inflation_detected", "invalid_cohort", "cohort")?
            .unwrap_or(false);
    let (resume_checked, resume_ok, resume_detail) = resume_cross_check(coh)?;

    // Detector resolution.
    let resolved = detectors_resolved(det)?;

    // Child coverage inputs (ledger authoritative, cohort fallback).
    let children_proven = optional_bool_present(led, "children_proven", "invalid_ledger", "ledger")?
        .or(optional_bool_present(coh, "children_proven", "invalid_cohort", "cohort")?)
        .unwrap_or(false);
    let child_refs = match led
        .get("child_coverage_refs")
        .or(coh.get("child_coverage_refs"))
    {
        None => Value::Array(Vec::new()),
        Some(Value::Array(refs)) => Value::Array(refs.to_vec()),
        Some(value) if is_missing(value) => Value::Array(Vec::new()),
        Some(_) => {
            return Err(fault(
                "invalid_ledger",
                "child_coverage_refs must be an array of coverage references".to_string(),
            ))
        }
    };

    // ---- Guards ----
    let mut guards: Vec<Value> = Vec::with_capacity(GUARD_IDS.len());

    // count_units: every scope must count postings.
    let units_ok = decl_unit == "postings" && ledger_unit == "postings" && cohort_units == "postings";
    guards.push(guard_value(
        "count_units",
        if units_ok { "established" } else { "failed" },
        &evidence_refs,
        if units_ok {
            "declaration, ledger, and cohort all count postings".to_string()
        } else {
            format!(
                "posting units required; declaration={decl_unit:?} ledger={ledger_unit:?} cohort={cohort_units:?}"
            )
        },
    ));

    // predicate_identity: same predicate bytes and same verified digest.
    let predicates_equal = decl_predicate == ledger_predicate;
    let digests_present = decl_digest.is_some() && ledger_digest.is_some() && cohort_digest.is_some();
    let digests_equal = digests_present
        && decl_digest.as_ref() == ledger_digest.as_ref()
        && decl_digest.as_ref() == cohort_digest.as_ref();
    let digest_verifies = match (&decl_digest, predicates_equal) {
        (Some(expected), true) => predicate_digest_matches(decl_predicate, expected),
        _ => false,
    };
    let predicate_ok = predicates_equal && digests_equal && digest_verifies;
    let predicate_result = if predicate_ok {
        "established"
    } else if !digests_present {
        "not_established"
    } else {
        "failed"
    };
    guards.push(guard_value(
        "predicate_identity",
        predicate_result,
        &evidence_refs,
        if predicate_ok {
            "ledger and cohort predicates equal the declaration with a verified definition digest"
                .to_string()
        } else if !predicates_equal {
            "ledger predicate bytes differ from the declared predicate".to_string()
        } else if !digests_equal {
            "predicate digests disagree across declaration, ledger, and cohort".to_string()
        } else {
            "declared digest is not the canonical digest of the predicate bytes".to_string()
        },
    ));

    // count_source_verified.
    guards.push(guard_value(
        "count_source_verified",
        if count_verified { "established" } else { "failed" },
        &evidence_refs,
        if count_verified {
            "reported counts come from a verified source".to_string()
        } else {
            "count source is unverified; no algebra may prove".to_string()
        },
    ));

    // cursor_permitted (with optional resume cross-check).
    let permitted_ok = cohort_permitted && resume_ok;
    guards.push(guard_value(
        "cursor_permitted",
        if permitted_ok { "established" } else { "failed" },
        &evidence_refs,
        if permitted_ok {
            if resume_checked {
                "traversal permitted and the embedded resume triple validates".to_string()
            } else {
                "traversal permitted for the active cohort".to_string()
            }
        } else if !cohort_permitted {
            "traversal is not permitted for this cohort".to_string()
        } else {
            resume_detail
        },
    ));

    // detectors_resolved.
    guards.push(guard_value(
        "detectors_resolved",
        if resolved { "established" } else { "failed" },
        &evidence_refs,
        if resolved {
            "all detectors resolved without blocking flags".to_string()
        } else {
            "at least one detector blocks; coverage cannot prove".to_string()
        },
    ));

    // termination.
    guards.push(guard_value(
        "termination",
        if terminated { "established" } else { "failed" },
        &evidence_refs,
        if terminated {
            "termination evidence is established".to_string()
        } else {
            "no termination evidence; the walk may be truncated".to_string()
        },
    ));

    // no_replay_inflation.
    let replay_ok = !ledger_replay && !cohort_replay;
    guards.push(guard_value(
        "no_replay_inflation",
        if replay_ok { "established" } else { "failed" },
        &evidence_refs,
        if replay_ok {
            "no replay inflation detected in ledger or cohort".to_string()
        } else {
            "replay inflation detected; replayed rows cannot prove coverage".to_string()
        },
    ));

    // no_duplicate_substitution: consistent duplicate arithmetic, distinct
    // union must satisfy the equation, and the exact ID set (when carried)
    // must agree with the distinct total.
    let mut duplicate_problem: Option<String> = None;
    if distinct > observed {
        duplicate_problem = Some(format!(
            "distinct union {distinct} exceeds observed total {observed}"
        ));
    } else if repeated > distinct {
        duplicate_problem = Some(format!(
            "repeated-distinct total {repeated} exceeds distinct union {distinct}"
        ));
    } else {
        let expected = if distinct == 0 {
            0.0
        } else {
            repeated as f64 / distinct as f64
        };
        if (duplicate_rate - expected).abs() > 1e-9 {
            duplicate_problem = Some(format!(
                "duplicate_rate {duplicate_rate} disagrees with repeated/distinct {expected}"
            ));
        }
    }
    if duplicate_problem.is_none() {
        if let Some(ids_value) = led.get("observed_ids") {
            if !is_missing(ids_value) {
                if let Ok(Some(unique)) = unique_observed_ids(ids_value) {
                    if unique != distinct {
                        duplicate_problem = Some(format!(
                            "exact ID set cardinality {unique} disagrees with distinct union {distinct}"
                        ));
                    }
                }
            }
        }
    }
    // Substitution check: when an equality/floor candidate would need the
    // inflated observed total because the distinct union falls short, the
    // duplicates cannot stand in.
    let mut substitution_problem: Option<String> = None;
    if duplicate_problem.is_none() {
        if let Some(reported) = reported_total {
            if observed == reported && distinct != reported {
                substitution_problem = Some(format!(
                    "observed total {observed} matches reported {reported} only through duplicates; distinct union is {distinct}"
                ));
            }
        }
        if substitution_problem.is_none() {
            if let Some(floor) = floor_value {
                if header_is_floor && !saturation && observed >= floor && distinct < floor {
                    substitution_problem = Some(format!(
                        "observed total {observed} reaches floor {floor} only through duplicates; distinct union is {distinct}"
                    ));
                }
            }
        }
    }
    let duplicate_ok = duplicate_problem.is_none() && substitution_problem.is_none();
    guards.push(guard_value(
        "no_duplicate_substitution",
        if duplicate_ok { "established" } else { "failed" },
        &evidence_refs,
        if duplicate_ok {
            "duplicate arithmetic is consistent and pagination evidence is the distinct union"
                .to_string()
        } else if let Some(problem) = duplicate_problem.as_ref() {
            problem.clone()
        } else {
            substitution_problem.clone().unwrap_or_else(|| {
                "duplicated observations cannot substitute for distinct pagination evidence"
                    .to_string()
            })
        },
    ));

    // eligible_sessions.
    let counts_eligible = session_count >= session_min && session_count > 0;
    let sessions_ok = counts_eligible && cohort_eligible.unwrap_or(true);
    guards.push(guard_value(
        "eligible_sessions",
        if sessions_ok { "established" } else { "failed" },
        &evidence_refs,
        if sessions_ok {
            format!("{session_count} eligible sessions satisfy minimum {session_min}")
        } else if !counts_eligible {
            format!("{session_count} eligible sessions do not satisfy minimum {session_min}")
        } else {
            "cohort marks its sessions ineligible".to_string()
        },
    ));

    // positive_observations (zero rule input).
    let positive_ok = observed > 0 && distinct > 0;
    guards.push(guard_value(
        "positive_observations",
        if positive_ok { "established" } else { "failed" },
        &evidence_refs,
        if positive_ok {
            format!("positive pagination evidence: observed={observed} distinct={distinct}")
        } else {
            format!("zero observations cannot prove (observed={observed} distinct={distinct})")
        },
    ));

    // covering_children: inapplicable without children; otherwise the child
    // relation must be proven with explicit references.
    let covering_result = if child_ids.is_empty() {
        "not_applicable"
    } else if children_proven
        && child_refs
            .as_array()
            .is_some_and(|refs| !refs.is_empty())
    {
        "established"
    } else {
        "not_established"
    };
    guards.push(guard_value(
        "covering_children",
        covering_result,
        &evidence_refs,
        if child_ids.is_empty() {
            "no child partitions; single-partition proof applies".to_string()
        } else if covering_result == "established" {
            format!(
                "{} child partitions proven via explicit coverage references",
                child_ids.len()
            )
        } else {
            "child partitions exist but their covering proof is not established here".to_string()
        },
    ));

    // ---- Algebra selection (priority: lower-bound, floor, equality, none) ----
    let lower_candidate = session_max
        .map(|max| distinct >= max && session_count >= session_min)
        .unwrap_or(false);
    let floor_candidate = floor_value
        .map(|floor| header_is_floor && !saturation && observed >= floor && distinct >= floor)
        .unwrap_or(false);
    let equality_candidate = reported_total
        .map(|reported| observed == reported && distinct == reported)
        .unwrap_or(false);
    let selected = if lower_candidate {
        "lower_bound"
    } else if floor_candidate {
        "floor"
    } else if equality_candidate {
        "equality"
    } else {
        "none"
    };

    // Every proof requires every applicable guard. `covering_children` is the
    // only guard that may be `not_applicable` (exactly when childless).
    let mut failing: Vec<&str> = Vec::new();
    for guard in &guards {
        let id = guard.get("guard_id").and_then(Value::as_str).unwrap_or("");
        let result = guard.get("result").and_then(Value::as_str).unwrap_or("");
        if id == "covering_children" && result == "not_applicable" && child_ids.is_empty() {
            continue;
        }
        if result != "established" {
            failing.push(id);
        }
    }
    let zero = observed == 0 || distinct == 0;
    let proven = !zero && selected != "none" && failing.is_empty();
    let proof_type = if proven { selected } else { "none" };
    let status = if proven { "proven" } else { "unproven" };
    let failure_reason = if proven {
        missing("not_applicable", "proof established; no failure")
    } else if zero {
        Value::String("empty_unproven".to_string())
    } else if selected == "none" {
        Value::String("no_proof_candidate".to_string())
    } else {
        Value::String(format!(
            "guard_failed_{}",
            failing.first().copied().unwrap_or("unknown")
        ))
    };

    // Render coverage is orthogonal to pagination proof.
    let render_coverage = if observed == 0 {
        missing("not_applicable", "render coverage is inapplicable with zero observations")
    } else {
        let ratio = render_pass as f64 / observed as f64;
        Value::Number(
            serde_json::Number::from_f64(ratio).unwrap_or_else(|| 0.into()),
        )
    };

    let equation_terms = json!({
        "observed_total": observed,
        "distinct_observed_total": distinct,
        "repeated_distinct_id_total": repeated,
        "duplicate_rate": duplicate_rate,
        "reported_total": reported_total.map(Value::from).unwrap_or_else(|| missing("not_observed", "no exact-total term applies")),
        "floor_value": floor_value.map(Value::from).unwrap_or_else(|| missing("not_applicable", "no floor term applies")),
        "header_label_is_floor": header_is_floor,
        "saturation_marker_present": saturation,
        "session_aggregate_max": session_max.map(Value::from).unwrap_or_else(|| missing("not_observed", "no session aggregates apply")),
        "session_count": session_count,
        "session_min_count": session_min,
        "render_pass_total": render_pass,
        "parent_exploratory_total": parent_exploratory,
        "parent_exploratory_included": false,
        "selected_algebra": selected,
    });

    let predicate_hash = match decl_hash_value {
        Value::Object(_) => (*decl_hash_value).clone(),
        Value::String(digest) => json!({
            "value": digest,
            "profile": "kernel-jcs-sha256/1",
            "evidence_refs": evidence_refs.clone(),
        }),
        _ => missing("not_observed", "predicate hash unavailable"),
    };

    let evidence_prefix = decl
        .get("evidence_prefix")
        .or(led.get("evidence_prefix"))
        .or(coh.get("evidence_prefix"))
        .cloned()
        .unwrap_or_else(|| missing("not_observed", "no evidence prefix supplied"));

    let output = json!({
        "record_type": "crawler_proof_evaluation",
        "schema_version": SCHEMA_VERSION,
        "target": target,
        "run_id": run_id,
        "partition_id": partition_id,
        "proof_type": proof_type,
        "status": status,
        "pagination_coverage_proven": proven,
        "guards": guards,
        "equation_terms": equation_terms,
        "render_coverage": render_coverage,
        "failure_reason": failure_reason,
        "predicate_hash": predicate_hash,
        "count_units": "postings",
        "cohort_refs": cohort_refs,
        "child_partition_ids": child_ids,
        "child_coverage_refs": child_refs,
        "evidence_prefix": evidence_prefix,
        "evidence_refs": evidence_refs,
    });
    validate(OUTPUT_SCHEMA, output)
}

// ---------------------------------------------------------------------------
// Bisection (C30)
// ---------------------------------------------------------------------------

/// Canonical key of a set-predicate value (type-discriminated).
fn set_member_key(value: &Value) -> String {
    match value {
        Value::String(text) => format!("s:{text}"),
        Value::Number(number) => format!("n:{number}"),
        Value::Bool(flag) => format!("b:{flag}"),
        _ => format!("j:{}", serde_json::to_string(value).unwrap_or_default()),
    }
}

/// Covering check for set predicates (`{"values": [...]}`).
/// Returns the explicit overlap (values present in more than one child).
fn check_set_covering(parent_values: &[Value], children_values: &[Vec<Value>]) -> Result<Vec<Value>, String> {
    let mut parent_set = BTreeSet::new();
    for value in parent_values {
        parent_set.insert(set_member_key(value));
    }
    let mut union_set = BTreeSet::new();
    let mut counts: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    let mut by_key: std::collections::BTreeMap<String, Value> = std::collections::BTreeMap::new();
    for child in children_values {
        let mut child_set = BTreeSet::new();
        for value in child {
            let key = set_member_key(value);
            child_set.insert(key.clone());
            by_key.entry(key.clone()).or_insert_with(|| value.clone());
        }
        for key in child_set {
            *counts.entry(key.clone()).or_insert(0) += 1;
            union_set.insert(key);
        }
    }
    if union_set != parent_set {
        let missing: Vec<String> = parent_set.difference(&union_set).cloned().collect();
        let extra: Vec<String> = union_set.difference(&parent_set).cloned().collect();
        return Err(format!(
            "child value sets do not cover the parent (missing={missing:?} extra={extra:?})"
        ));
    }
    let mut overlap = Vec::new();
    for (key, count) in &counts {
        if *count > 1 {
            if let Some(value) = by_key.get(key) {
                overlap.push(value.clone());
            }
        }
    }
    overlap.sort_by_key(set_member_key);
    Ok(overlap)
}

/// A closed integer range `[low, high]`.
struct IntRange {
    low: i64,
    high: i64,
}

fn parse_int_range(value: &Value) -> Result<IntRange, String> {
    let pair = value
        .as_object()
        .and_then(|map| map.get("range"))
        .and_then(Value::as_array)
        .ok_or_else(|| "range predicates must carry {\"range\": [low, high]}".to_string())?;
    if pair.len() != 2 {
        return Err("range predicates must carry exactly [low, high]".to_string());
    }
    let low = pair[0].as_i64().ok_or_else(|| "range bounds must be integers".to_string())?;
    let high = pair[1].as_i64().ok_or_else(|| "range bounds must be integers".to_string())?;
    if low > high {
        return Err("range low must not exceed high".to_string());
    }
    Ok(IntRange { low, high })
}

/// Covering check for range predicates. Returns explicit overlap intervals.
fn check_range_covering(parent: &IntRange, children: &[IntRange]) -> Result<Vec<Value>, String> {
    if children.is_empty() {
        return Err("covering requires at least one child range".to_string());
    }
    for child in children {
        if child.low < parent.low || child.high > parent.high {
            return Err(format!(
                "child range [{}, {}] escapes parent [{}, {}]",
                child.low, child.high, parent.low, parent.high
            ));
        }
    }
    let mut ordered: Vec<&IntRange> = children.iter().collect();
    ordered.sort_by_key(|range| (range.low, range.high));
    if ordered[0].low != parent.low {
        return Err(format!(
            "child ranges start at {} but the parent starts at {}",
            ordered[0].low, parent.low
        ));
    }
    let mut covered_high = ordered[0].high;
    for child in ordered.iter().skip(1) {
        if child.low > covered_high + 1 {
            return Err(format!(
                "gap in child ranges before {} (covered through {})",
                child.low, covered_high
            ));
        }
        covered_high = covered_high.max(child.high);
    }
    if covered_high != parent.high {
        return Err(format!(
            "child ranges end at {covered_high} but the parent ends at {}",
            parent.high
        ));
    }
    // Pairwise intersections, deduplicated.
    let mut overlaps: BTreeSet<(i64, i64)> = BTreeSet::new();
    for (index, left) in children.iter().enumerate() {
        for right in children.iter().skip(index + 1) {
            let low = left.low.max(right.low);
            let high = left.high.min(right.high);
            if low <= high {
                overlaps.insert((low, high));
            }
        }
    }
    Ok(overlaps
        .into_iter()
        .map(|(low, high)| json!([low, high]))
        .collect())
}

/// Split-axis selection by §17.2 priority.
fn select_split_axis(decl: &Map<String, Value>) -> Result<Option<(String, String)>, Fault> {
    if let Some(Value::Array(keys)) = established(decl, "declared_partition_keys") {
        for key in keys {
            if let Value::String(text) = key {
                if !text.is_empty() {
                    return Ok(Some((text.to_string(), "declared_partition_keys".to_string())));
                }
            } else {
                return Err(fault(
                    "invalid_declaration",
                    "declared_partition_keys entries must be nonempty strings".to_string(),
                ));
            }
        }
    } else if let Some(value) = decl.get("declared_partition_keys") {
        if !is_missing(value) {
            return Err(fault(
                "invalid_declaration",
                "declared_partition_keys must be an array of strings".to_string(),
            ));
        }
    }
    if let Some(Value::String(text)) = established(decl, "primary_key") {
        if !text.is_empty() {
            return Ok(Some((text.to_string(), "primary_key".to_string())));
        }
    } else if let Some(value) = decl.get("primary_key") {
        if !is_missing(value) {
            return Err(fault(
                "invalid_declaration",
                "primary_key must be a nonempty string or Missing".to_string(),
            ));
        }
    }
    for (field, priority) in [
        ("verified_date_keys", "verified_date_keys"),
        ("verified_secondary_keys", "verified_secondary_keys"),
    ] {
        if let Some(Value::Array(keys)) = established(decl, field) {
            for key in keys {
                if let Value::String(text) = key {
                    if !text.is_empty() {
                        return Ok(Some((text.to_string(), priority.to_string())));
                    }
                } else {
                    return Err(fault(
                        "invalid_declaration",
                        format!("{field} entries must be nonempty strings"),
                    ));
                }
            }
        } else if let Some(value) = decl.get(field) {
            if !is_missing(value) {
                return Err(fault(
                    "invalid_declaration",
                    format!("{field} must be an array of strings"),
                ));
            }
        }
    }
    Ok(None)
}

/// Plan a bisection of the parent partition (§17.2).
///
/// Child predicates must cover the parent; overlap is explicit; observations
/// combine by exact ID union; parent exploratory counts are excluded from
/// child proof arithmetic. Returns a split plan (never a ledger commit).
pub fn plan_split(
    declaration: &CheckedRecord,
    parent: &CheckedRecord,
    evidence: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let decl = as_object(declaration, "invalid_declaration", "declaration")?;
    let par = as_object(parent, "invalid_parent", "parent")?;
    let evi = as_object(evidence, "invalid_evidence", "evidence")?;

    let target = required_str(decl, "target", "invalid_declaration", "declaration")?.to_string();
    let run_id = required_str(decl, "run_id", "invalid_declaration", "declaration")?.to_string();
    let parent_partition = established(decl, "parent_partition_id")
        .or(established(decl, "partition_id"))
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .ok_or_else(|| {
            fault(
                "invalid_declaration",
                "declaration requires parent_partition_id (or partition_id)".to_string(),
            )
        })?
        .to_string();
    scope_match(par, "parent", &target, &run_id, &parent_partition)?;
    // Evidence scope pins, when present, must agree.
    scope_match(evi, "evidence", &target, &run_id, &parent_partition)?;

    let parent_predicate = par.get("partition_predicate_json").ok_or_else(|| {
        fault(
            "invalid_parent",
            "parent requires established field \"partition_predicate_json\"".to_string(),
        )
    })?;
    if is_missing(parent_predicate) || !parent_predicate.is_object() {
        return Err(fault(
            "invalid_parent",
            "parent partition_predicate_json must be an established object".to_string(),
        ));
    }
    let split_round = required_u64(par, "split_round", "invalid_parent", "parent")?;
    if split_round > MAX_SPLIT_ROUND {
        return Err(fault(
            "invalid_parent",
            format!("parent split_round {split_round} exceeds maximum {MAX_SPLIT_ROUND}"),
        ));
    }
    if split_round >= MAX_SPLIT_ROUND {
        return Err(fault(
            "max_split_depth",
            format!(
                "parent is already at saturated depth {MAX_SPLIT_ROUND}; no further bisection"
            ),
        ));
    }
    let parent_exploratory =
        optional_u64(par, "parent_exploratory_total", "invalid_parent", "parent")?.unwrap_or(0);
    let ascending_overflow =
        optional_bool_present(decl, "ascending_overflow_established", "invalid_declaration", "declaration")?
            .unwrap_or(false);

    let evidence_refs = required_support(evi, "evidence_refs", "invalid_evidence", "evidence")
        .or_else(|_| required_support(decl, "evidence_refs", "invalid_declaration", "declaration"))?;
    let evidence_prefix = evi
        .get("evidence_prefix")
        .or(decl.get("evidence_prefix"))
        .cloned()
        .filter(|value| value.is_object())
        .unwrap_or_else(|| missing("not_observed", "no evidence prefix supplied"));

    // Axis selection comes before child validation: with no valid axis the
    // plan reports the closed failure reason and siblings continue.
    let axis = select_split_axis(decl)?;
    let Some((axis_name, axis_priority)) = axis else {
        let failure = if ascending_overflow {
            "ascending_overflow_unrecoverable"
        } else {
            "no_bisection_axis_available"
        };
        let output = json!({
            "record_type": "crawler_split_plan",
            "schema_version": SCHEMA_VERSION,
            "target": target,
            "run_id": run_id,
            "parent_partition_id": parent_partition,
            "split_round": split_round,
            "split_possible": false,
            "axis": missing("not_applicable", "no valid bisection axis"),
            "axis_priority": missing("not_applicable", "no valid bisection axis"),
            "children": [],
            "covering": false,
            "covering_evidence": missing("not_applicable", "no children without an axis"),
            "overlap": [],
            "overlap_explicit": true,
            "combination_rule": "exact_id_union",
            "blind_addition_forbidden": true,
            "parent_exploratory_total": parent_exploratory,
            "parent_exploratory_included_in_child_proof": false,
            "child_proof_inputs_exclude_parent_exploratory": true,
            "siblings_continue": true,
            "failure_reason": failure,
            "evidence_prefix": evidence_prefix,
            "evidence_refs": evidence_refs,
        });
        return validate(OUTPUT_SCHEMA, output);
    };

    // Children: explicit proposals or exact auto-bisection of set/range
    // predicates. Opaque predicates require explicit children plus covering
    // attestation; this planner never invents predicates.
    let proposed: Option<Vec<Value>> = match evi.get("proposed_children") {
        None => None,
        Some(value) if is_missing(value) => None,
        Some(Value::Array(children)) => Some(children.to_vec()),
        Some(_) => {
            return Err(fault(
                "invalid_evidence",
                "proposed_children must be an array of {partition_id, predicate_json}".to_string(),
            ))
        }
    };
    let had_proposed = proposed.is_some();

    let parent_obj = parent_predicate.as_object().expect("checked object");
    let is_set = parent_obj.get("values").is_some_and(Value::is_array);
    let is_range = parent_obj.get("range").is_some_and(Value::is_array);

    let mut child_ids: Vec<String> = Vec::new();
    let mut child_predicates: Vec<Value> = Vec::new();
    let covering_evidence: String;

    if let Some(children) = proposed {
        if children.is_empty() {
            return Err(fault(
                "invalid_evidence",
                "proposed_children must not be empty; omit it for auto-bisection".to_string(),
            ));
        }
        for child in &children {
            let obj = child.as_object().ok_or_else(|| {
                fault(
                    "invalid_evidence",
                    "proposed children must be objects".to_string(),
                )
            })?;
            let id = obj
                .get("partition_id")
                .and_then(Value::as_str)
                .filter(|text| !text.is_empty())
                .ok_or_else(|| {
                    fault(
                        "invalid_evidence",
                        "proposed children require a nonempty partition_id".to_string(),
                    )
                })?;
            if id == parent_partition {
                return Err(fault(
                    "invalid_evidence",
                    "proposed child partition_id must differ from the parent".to_string(),
                ));
            }
            let predicate = obj.get("predicate_json").ok_or_else(|| {
                fault(
                    "invalid_evidence",
                    "proposed children require predicate_json".to_string(),
                )
            })?;
            if is_missing(predicate) || !predicate.is_object() {
                return Err(fault(
                    "invalid_evidence",
                    "proposed child predicate_json must be an established object".to_string(),
                ));
            }
            child_ids.push(id.to_string());
            child_predicates.push((*predicate).clone());
        }
        let mut sorted_ids = child_ids.clone();
        sorted_ids.sort();
        sorted_ids.dedup();
        if sorted_ids.len() != child_ids.len() {
            return Err(fault(
                "invalid_evidence",
                "proposed child partition_ids must be distinct".to_string(),
            ));
        }
        // Covering validation for explicit children.
        if is_set {
            let parent_values = parent_obj
                .get("values")
                .and_then(Value::as_array)
                .expect("checked array")
                .to_vec();
            let mut children_values = Vec::with_capacity(child_predicates.len());
            for predicate in &child_predicates {
                let values = predicate
                    .as_object()
                    .and_then(|map| map.get("values"))
                    .and_then(Value::as_array)
                    .ok_or_else(|| {
                        fault(
                            "non_covering_children",
                            "set-parent children must carry {\"values\": [...]} predicates".to_string(),
                        )
                    })?;
                children_values.push(values.to_vec());
            }
            match check_set_covering(&parent_values, &children_values) {
                Ok(_) => covering_evidence = "exact_set_union".to_string(),
                Err(detail) => return Err(fault("non_covering_children", detail)),
            }
        } else if is_range {
            let parent_range =
                parse_int_range(parent_predicate).map_err(|detail| fault("invalid_parent", detail))?;
            let mut children_ranges = Vec::with_capacity(child_predicates.len());
            for predicate in &child_predicates {
                let range = parse_int_range(predicate)
                    .map_err(|detail| fault("non_covering_children", detail))?;
                children_ranges.push(range);
            }
            match check_range_covering(&parent_range, &children_ranges) {
                Ok(_) => covering_evidence = "exact_range_union".to_string(),
                Err(detail) => return Err(fault("non_covering_children", detail)),
            }
        } else {
            let attested =
                optional_bool_present(evi, "covering_attested", "invalid_evidence", "evidence")?
                    .unwrap_or(false);
            if !attested {
                return Err(fault(
                    "covering_not_established",
                    "opaque predicates require explicit covering_attested evidence".to_string(),
                ));
            }
            required_support(
                evi,
                "covering_evidence_refs",
                "invalid_evidence",
                "evidence",
            )?;
            covering_evidence = "explicit_attestation".to_string();
        }
    } else if is_set {
        let parent_values = parent_obj
            .get("values")
            .and_then(Value::as_array)
            .expect("checked array")
            .to_vec();
        if parent_values.len() < 2 {
            return Err(fault(
                "unsplittable_predicate",
                "set predicates with fewer than two values cannot bisect".to_string(),
            ));
        }
        let mid = parent_values.len() / 2;
        let left = parent_values[..mid].to_vec();
        let right = parent_values[mid..].to_vec();
        child_ids = vec![
            format!("{parent_partition}-a"),
            format!("{parent_partition}-b"),
        ];
        child_predicates = vec![
            json!({"axis": axis_name.clone(), "values": left}),
            json!({"axis": axis_name.clone(), "values": right}),
        ];
        covering_evidence = "exact_set_union".to_string();
    } else if is_range {
        let parent_range =
            parse_int_range(parent_predicate).map_err(|detail| fault("invalid_parent", detail))?;
        if parent_range.low == parent_range.high {
            return Err(fault(
                "unsplittable_predicate",
                "single-value ranges cannot bisect".to_string(),
            ));
        }
        let mid = parent_range.low + (parent_range.high - parent_range.low) / 2;
        child_ids = vec![
            format!("{parent_partition}-a"),
            format!("{parent_partition}-b"),
        ];
        child_predicates = vec![
            json!({"axis": axis_name.clone(), "range": [parent_range.low, mid]}),
            json!({"axis": axis_name.clone(), "range": [mid + 1, parent_range.high]}),
        ];
        covering_evidence = "exact_range_union".to_string();
    } else {
        return Err(fault(
            "explicit_children_required",
            "opaque parent predicates require explicit proposed_children with covering attestation"
                .to_string(),
        ));
    }

    // Explicit overlap of the final child predicates.
    let overlap: Value = if covering_evidence == "exact_set_union" {
        if !had_proposed {
            // Auto-bisection is disjoint by construction.
            Value::Array(Vec::new())
        } else {
            let parent_values = parent_obj
                .get("values")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let children_values: Vec<Vec<Value>> = child_predicates
                .iter()
                .map(|predicate| {
                    predicate
                        .as_object()
                        .and_then(|map| map.get("values"))
                        .and_then(Value::as_array)
                        .cloned()
                        .unwrap_or_default()
                })
                .collect();
            match check_set_covering(&parent_values, &children_values) {
                Ok(overlap) => Value::Array(overlap),
                Err(detail) => return Err(fault("non_covering_children", detail)),
            }
        }
    } else if covering_evidence == "exact_range_union" {
        if !had_proposed {
            Value::Array(Vec::new())
        } else {
            let parent_range =
                parse_int_range(parent_predicate).map_err(|detail| fault("invalid_parent", detail))?;
            let children_ranges: Vec<IntRange> = child_predicates
                .iter()
                .map(parse_int_range)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|detail| fault("non_covering_children", detail))?;
            match check_range_covering(&parent_range, &children_ranges) {
                Ok(overlap) => Value::Array(overlap),
                Err(detail) => return Err(fault("non_covering_children", detail)),
            }
        }
    } else {
        // Opaque: the caller declares the explicit overlap (possibly empty).
        match evi.get("overlap_ids") {
            None => Value::Array(Vec::new()),
            Some(value) if is_missing(value) => Value::Array(Vec::new()),
            Some(Value::Array(ids)) => Value::Array(ids.to_vec()),
            Some(_) => {
                return Err(fault(
                    "invalid_evidence",
                    "overlap_ids must be an array of explicitly shared identities".to_string(),
                ))
            }
        }
    };

    // Child predicate hashes under the kernel profile.
    let mut children: Vec<Value> = Vec::with_capacity(child_ids.len());
    for (id, predicate) in child_ids.iter().zip(child_predicates.iter()) {
        let digest = digest_for_value(predicate, "child")?;
        children.push(json!({
            "partition_id": id,
            "predicate_json": predicate.clone(),
            "predicate_hash": {
                "value": digest,
                "profile": "kernel-jcs-sha256/1",
                "evidence_refs": evidence_refs.clone(),
            },
            "split_round": split_round + 1,
        }));
    }

    let output = json!({
        "record_type": "crawler_split_plan",
        "schema_version": SCHEMA_VERSION,
        "target": target,
        "run_id": run_id,
        "parent_partition_id": parent_partition,
        "split_round": split_round,
        "child_split_round": split_round + 1,
        "split_possible": true,
        "axis": axis_name,
        "axis_priority": axis_priority,
        "children": children,
        "covering": true,
        "covering_evidence": covering_evidence,
        "overlap": overlap,
        "overlap_explicit": true,
        "combination_rule": "exact_id_union",
        "blind_addition_forbidden": true,
        "parent_exploratory_total": parent_exploratory,
        "parent_exploratory_included_in_child_proof": false,
        "child_proof_inputs_exclude_parent_exploratory": true,
        "siblings_continue": true,
        "failure_reason": missing("not_applicable", "bisection planned; no failure"),
        "evidence_prefix": evidence_prefix,
        "evidence_refs": evidence_refs,
    });
    validate(OUTPUT_SCHEMA, output)
}

// ---------------------------------------------------------------------------
// Coverage export (§4.2)
// ---------------------------------------------------------------------------

fn validate_guard_entry(entry: &Value) -> Result<(String, String), Fault> {
    let obj = entry.as_object().ok_or_else(|| {
        fault("invalid_proof", "proof guards must be objects".to_string())
    })?;
    let guard_id = obj
        .get("guard_id")
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .ok_or_else(|| fault("invalid_proof", "guards require a nonempty guard_id".to_string()))?;
    if !GUARD_IDS.contains(&guard_id) {
        return Err(fault(
            "invalid_proof",
            format!("unknown guard_id {guard_id:?}; expected one of {GUARD_IDS:?}"),
        ));
    }
    let result = obj
        .get("result")
        .and_then(Value::as_str)
        .ok_or_else(|| fault("invalid_proof", "guards require a result".to_string()))?;
    if !["established", "failed", "not_established", "not_applicable"].contains(&result) {
        return Err(fault(
            "invalid_proof",
            format!("guard {guard_id:?} has unknown result {result:?}"),
        ));
    }
    match obj.get("evidence_refs") {
        Some(Value::Array(refs)) => {
            if result != "not_applicable" && refs.is_empty() {
                return Err(fault(
                    "invalid_proof",
                    format!("guard {guard_id:?} requires nonempty evidence_refs"),
                ));
            }
        }
        _ => {
            return Err(fault(
                "invalid_proof",
                format!("guard {guard_id:?} requires evidence_refs"),
            ))
        }
    }
    let rationale = obj
        .get("rationale")
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .ok_or_else(|| {
            fault(
                "invalid_proof",
                format!("guard {guard_id:?} requires a nonempty rationale"),
            )
        })?;
    let _ = rationale;
    Ok((guard_id.to_string(), result.to_string()))
}

fn validate_proof_shape(proof: &Map<String, Value>) -> Result<(String, String, bool), Fault> {
    let proof_type = proof
        .get("proof_type")
        .and_then(Value::as_str)
        .ok_or_else(|| fault("invalid_proof", "proof requires proof_type".to_string()))?;
    if !["equality", "floor", "lower_bound", "none"].contains(&proof_type) {
        return Err(fault(
            "invalid_proof",
            format!("unknown proof_type {proof_type:?}"),
        ));
    }
    let status = proof
        .get("status")
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .ok_or_else(|| fault("invalid_proof", "proof requires a nonempty status".to_string()))?;
    let proven = proof
        .get("pagination_coverage_proven")
        .and_then(Value::as_bool)
        .ok_or_else(|| {
            fault(
                "invalid_proof",
                "proof requires pagination_coverage_proven".to_string(),
            )
        })?;
    // Proven status requires true; every other status requires false.
    if (status == "proven") != proven {
        return Err(fault(
            "invalid_proof",
            format!("proof status {status:?} disagrees with pagination_coverage_proven={proven}"),
        ));
    }
    if proven && proof_type == "none" {
        return Err(fault(
            "invalid_proof",
            "positive proof requires a selected algebra, not none".to_string(),
        ));
    }
    if !proven && proof_type != "none" {
        return Err(fault(
            "invalid_proof",
            "unproven evaluations must carry proof_type none".to_string(),
        ));
    }
    match proof.get("cohort_refs") {
        Some(Value::Array(_)) => {}
        _ => return Err(fault("invalid_proof", "proof requires cohort_refs".to_string())),
    }
    match proof.get("count_units").and_then(Value::as_str) {
        Some("postings") => {}
        _ => {
            return Err(fault(
                "invalid_proof",
                "proof count_units must be postings".to_string(),
            ))
        }
    }
    let predicate_hash = proof.get("predicate_hash").ok_or_else(|| {
        fault("invalid_proof", "proof requires predicate_hash".to_string())
    })?;
    match hash_text(predicate_hash) {
        Some(digest) if is_digest_text(&digest) => {}
        _ => {
            return Err(fault(
                "invalid_proof",
                "proof predicate_hash must carry a canonical digest".to_string(),
            ))
        }
    }
    if !proof
        .get("equation_terms")
        .is_some_and(|value| value.is_object())
    {
        return Err(fault(
            "invalid_proof",
            "proof requires equation_terms".to_string(),
        ));
    }
    let guards = proof
        .get("guards")
        .and_then(Value::as_array)
        .ok_or_else(|| fault("invalid_proof", "proof requires guards".to_string()))?;
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut results: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    for entry in guards {
        let (id, result) = validate_guard_entry(entry)?;
        if !seen.insert(id.clone()) {
            return Err(fault(
                "invalid_proof",
                format!("duplicate guard_id {id:?}"),
            ));
        }
        results.insert(id, result);
    }
    for expected in GUARD_IDS {
        if !seen.contains(*expected) {
            return Err(fault(
                "invalid_proof",
                format!("proof guards omit required guard_id {expected:?}"),
            ));
        }
    }
    if proven {
        for expected in GUARD_IDS {
            let result = results.get(*expected).expect("checked present");
            if *expected == "covering_children" {
                if result != "established" && result != "not_applicable" {
                    return Err(fault(
                        "invalid_proof",
                        "positive proof requires covering_children established or not_applicable"
                            .to_string(),
                    ));
                }
            } else if result != "established" {
                return Err(fault(
                    "invalid_proof",
                    format!("positive proof requires guard {expected:?} established (got {result:?})"),
                ));
            }
        }
    }
    match proof.get("child_coverage_refs") {
        Some(Value::Array(_)) => {}
        _ => {
            return Err(fault(
                "invalid_proof",
                "proof requires child_coverage_refs".to_string(),
            ))
        }
    }
    match proof.get("failure_reason") {
        Some(value) if is_missing(value) => {
            if !proven {
                return Err(fault(
                    "invalid_proof",
                    "unproven evaluations require an established failure_reason".to_string(),
                ));
            }
        }
        Some(Value::String(text)) if !text.is_empty() => {
            if proven {
                return Err(fault(
                    "invalid_proof",
                    "positive proof requires failure_reason Missing".to_string(),
                ));
            }
        }
        _ => {
            return Err(fault(
                "invalid_proof",
                "proof failure_reason must be an ID or Missing".to_string(),
            ))
        }
    }
    match proof.get("evidence_refs") {
        Some(Value::Array(refs)) if !refs.is_empty() => {}
        _ => {
            return Err(fault(
                "invalid_proof",
                "proof requires nonempty evidence_refs".to_string(),
            ))
        }
    }
    Ok((proof_type.to_string(), status.to_string(), proven))
}

fn validate_detector_entry(entry: &Value) -> Result<bool, Fault> {
    let obj = entry.as_object().ok_or_else(|| {
        fault(
            "invalid_detectors",
            "detector evaluations must be objects".to_string(),
        )
    })?;
    if !obj
        .get("detector")
        .and_then(Value::as_str)
        .is_some_and(|text| !text.is_empty())
    {
        return Err(fault(
            "invalid_detectors",
            "detectors require a nonempty detector name".to_string(),
        ));
    }
    if !obj
        .get("state")
        .and_then(Value::as_str)
        .is_some_and(|text| !text.is_empty())
    {
        return Err(fault(
            "invalid_detectors",
            "detectors require a nonempty state".to_string(),
        ));
    }
    let blocking = obj.get("blocking").and_then(Value::as_bool).ok_or_else(|| {
        fault(
            "invalid_detectors",
            "detectors require a blocking flag".to_string(),
        )
    })?;
    obj.get("corroboration_count")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            fault(
                "invalid_detectors",
                "detectors require corroboration_count REV".to_string(),
            )
        })?;
    let threshold = obj
        .get("threshold")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            fault(
                "invalid_detectors",
                "detectors require threshold POS".to_string(),
            )
        })?;
    if threshold == 0 {
        return Err(fault(
            "invalid_detectors",
            "detector thresholds must be positive".to_string(),
        ));
    }
    if !obj.get("evidence_refs").is_some_and(|value| value.is_array()) {
        return Err(fault(
            "invalid_detectors",
            "detectors require evidence_refs".to_string(),
        ));
    }
    let action = obj
        .get("action")
        .and_then(Value::as_str)
        .ok_or_else(|| fault("invalid_detectors", "detectors require an action".to_string()))?;
    if !DETECTOR_ACTIONS.contains(&action) {
        return Err(fault(
            "invalid_detectors",
            format!("unknown detector action {action:?}"),
        ));
    }
    match obj.get("failure_reason") {
        Some(value) if is_missing(value) => {}
        Some(Value::String(text)) if !text.is_empty() => {}
        _ => {
            return Err(fault(
                "invalid_detectors",
                "detector failure_reason must be an ID or Missing".to_string(),
            ))
        }
    }
    Ok(blocking)
}

fn validate_drift_shape(drift: &Map<String, Value>) -> Result<(), Fault> {
    for field in ["baseline_dup_rate", "effective_baseline", "duplicate_rate"] {
        let value = drift
            .get(field)
            .and_then(Value::as_f64)
            .filter(|rate| rate.is_finite())
            .ok_or_else(|| {
                fault(
                    "invalid_drift",
                    format!("drift requires finite rate {field:?}"),
                )
            })?;
        if !(0.0..=1.0).contains(&value) {
            return Err(fault(
                "invalid_drift",
                format!("drift rate {field:?} must lie in [0,1]"),
            ));
        }
    }
    if !drift
        .get("band")
        .and_then(Value::as_str)
        .is_some_and(|text| !text.is_empty())
    {
        return Err(fault("invalid_drift", "drift requires a nonempty band".to_string()));
    }
    let factor = drift
        .get("planned_over_fetch_factor")
        .and_then(Value::as_f64)
        .filter(|value| value.is_finite())
        .ok_or_else(|| {
            fault(
                "invalid_drift",
                "drift requires a finite planned_over_fetch_factor".to_string(),
            )
        })?;
    if factor < 1.0 {
        return Err(fault(
            "invalid_drift",
            "drift planned_over_fetch_factor must be at least 1".to_string(),
        ));
    }
    if drift
        .get("reconciliation_passes")
        .and_then(Value::as_u64)
        .is_none()
    {
        return Err(fault(
            "invalid_drift",
            "drift requires reconciliation_passes REV".to_string(),
        ));
    }
    if drift
        .get("cursor_trusted_for_proof")
        .and_then(Value::as_bool)
        .is_none()
    {
        return Err(fault(
            "invalid_drift",
            "drift requires cursor_trusted_for_proof".to_string(),
        ));
    }
    if !drift
        .get("evidence_refs")
        .is_some_and(|value| value.is_array())
    {
        return Err(fault(
            "invalid_drift",
            "drift requires evidence_refs".to_string(),
        ));
    }
    Ok(())
}

/// Assemble a closed `crawler_coverage_export` record (§4.2).
///
/// Pure assembly: validates the ledger, cursor snapshots, and evaluation
/// shapes, then materializes the export. Commits nothing.
pub fn build_coverage_export(
    ledger: &CheckedRecord,
    cursors: &[CheckedRecord],
    evaluation: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let led = as_object(ledger, "invalid_ledger", "ledger")?;
    let eva = as_object(evaluation, "invalid_evaluation", "evaluation")?;

    let target = required_str(led, "target", "invalid_ledger", "ledger")?.to_string();
    let run_id = required_str(led, "run_id", "invalid_ledger", "ledger")?.to_string();
    let partition_id = required_str(led, "partition_id", "invalid_ledger", "ledger")?.to_string();
    scope_match(eva, "evaluation", &target, &run_id, &partition_id)?;

    let child_ids: Vec<String> = match led.get("child_partition_ids") {
        None => Vec::new(),
        Some(value) if is_missing(value) => {
            return Err(fault(
                "invalid_ledger",
                "ledger child_partition_ids must be an array of IDs".to_string(),
            ))
        }
        Some(Value::Array(ids)) => {
            let mut out = Vec::with_capacity(ids.len());
            for id in ids {
                match id {
                    Value::String(text) if !text.is_empty() => out.push(text.to_string()),
                    _ => {
                        return Err(fault(
                            "invalid_ledger",
                            "ledger child_partition_ids entries must be nonempty IDs".to_string(),
                        ))
                    }
                }
            }
            out
        }
        Some(_) => {
            return Err(fault(
                "invalid_ledger",
                "ledger child_partition_ids must be an array of IDs".to_string(),
            ))
        }
    };

    // Declaration pin (established object).
    let declaration = eva.get("declaration").ok_or_else(|| {
        fault(
            "invalid_evaluation",
            "evaluation requires declaration PIN".to_string(),
        )
    })?;
    if is_missing(declaration) || !declaration.is_object() {
        return Err(fault(
            "invalid_evaluation",
            "evaluation declaration must be an established PIN object".to_string(),
        ));
    }

    // Proof: either nested under `proof` or flattened at top level.
    let proof_value = match eva.get("proof") {
        Some(value) if !is_missing(value) && value.is_object() => (*value).clone(),
        Some(value) if is_missing(value) => {
            return Err(fault("invalid_proof", "evaluation proof must be established".to_string()))
        }
        Some(_) => {
            return Err(fault(
                "invalid_proof",
                "evaluation proof must be an object".to_string(),
            ))
        }
        None => Value::Object((*eva).clone()),
    };
    let proof_map = proof_value.as_object().expect("checked object");
    let (_proof_type, _status, proven) = validate_proof_shape(proof_map)?;
    // Covering-children consistency with the ledger's child relation.
    let guards = proof_map
        .get("guards")
        .and_then(Value::as_array)
        .expect("checked guards");
    let covering_result = guards
        .iter()
        .find(|entry| entry.get("guard_id").and_then(Value::as_str) == Some("covering_children"))
        .and_then(|entry| entry.get("result"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let child_refs = proof_map
        .get("child_coverage_refs")
        .and_then(Value::as_array)
        .expect("checked refs");
    if child_ids.is_empty() {
        if covering_result != "not_applicable" {
            return Err(fault(
                "invalid_proof",
                "childless partitions require covering_children not_applicable".to_string(),
            ));
        }
        if !child_refs.is_empty() {
            return Err(fault(
                "invalid_proof",
                "childless partitions must carry empty child_coverage_refs".to_string(),
            ));
        }
    } else {
        if covering_result != "established" {
            return Err(fault(
                "invalid_proof",
                "partitions with children require covering_children established".to_string(),
            ));
        }
        if child_refs.is_empty() {
            return Err(fault(
                "invalid_proof",
                "covering children require nonempty child_coverage_refs".to_string(),
            ));
        }
    }

    // Detectors.
    let detector_entries = eva
        .get("detectors")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            fault(
                "invalid_evaluation",
                "evaluation requires detectors array".to_string(),
            )
        })?;
    let mut any_blocking = false;
    for entry in detector_entries {
        any_blocking = any_blocking || validate_detector_entry(entry)?;
    }
    if proven && any_blocking {
        return Err(fault(
            "invalid_proof",
            "positive proof cannot ride on blocking detectors".to_string(),
        ));
    }

    // Drift.
    let drift_value = eva.get("drift").ok_or_else(|| {
        fault(
            "invalid_evaluation",
            "evaluation requires drift".to_string(),
        )
    })?;
    let drift_map = drift_value.as_object().ok_or_else(|| {
        fault("invalid_drift", "evaluation drift must be an object".to_string())
    })?;
    validate_drift_shape(drift_map)?;

    // Measurements.
    let measurements = eva
        .get("measurements")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            fault(
                "invalid_evaluation",
                "evaluation requires measurements array".to_string(),
            )
        })?;
    for measurement in measurements {
        if !measurement.is_object() {
            return Err(fault(
                "invalid_evaluation",
                "measurements entries must be ME objects".to_string(),
            ));
        }
    }

    // Cursor capability and journal evidence.
    let capability_status =
        required_str(eva, "cursor_capability_status", "invalid_evaluation", "evaluation")?;
    if capability_status != "verified" && capability_status != "unverified" {
        return Err(fault(
            "invalid_evaluation",
            "cursor_capability_status must be verified or unverified".to_string(),
        ));
    }
    let capability_refs = required_support(
        eva,
        "cursor_capability_evidence_refs",
        "invalid_evaluation",
        "evaluation",
    )?;
    let evidence_prefix = eva
        .get("evidence_prefix")
        .filter(|value| value.is_object())
        .cloned()
        .ok_or_else(|| {
            fault(
                "invalid_evaluation",
                "evaluation requires evidence_prefix".to_string(),
            )
        })?;
    let evidence_refs = required_support(eva, "evidence_refs", "invalid_evaluation", "evaluation")?;

    // Uncertified observations (possibly empty).
    let uncertified = match eva.get("uncertified_observations") {
        None => Value::Array(Vec::new()),
        Some(value) if is_missing(value) => Value::Array(Vec::new()),
        Some(Value::Array(items)) => {
            for item in items {
                if !item.is_object() {
                    return Err(fault(
                        "invalid_evaluation",
                        "uncertified_observations entries must be AR objects".to_string(),
                    ));
                }
            }
            Value::Array(items.to_vec())
        }
        Some(_) => {
            return Err(fault(
                "invalid_evaluation",
                "uncertified_observations must be an array of ARs".to_string(),
            ))
        }
    };

    // Ledger artifact reference (framed, never concatenated).
    let ledger_bytes = canonical_bytes(ledger)
        .map_err(|e| fault("invalid_ledger", format!("ledger canonicalization failed: {}", e.detail)))?;
    let ledger_digest = digest_bytes(&ledger_bytes);
    let ledger_ref = frame_reference(
        "coverage_ledger",
        &[target.clone(), run_id.clone(), partition_id.clone()],
    )
    .map_err(|e| fault("invalid_ledger", format!("ledger reference failed: {}", e.detail)))?;
    let ledger_ar = json!({
        "digest": ledger_digest,
        "ledger_ref": ledger_ref,
        "evidence_refs": evidence_refs.clone(),
    });

    // Cursor snapshots: scope-checked ARs with framed references.
    let mut snapshots: Vec<Value> = Vec::with_capacity(cursors.len());
    for cursor in cursors {
        let cursor_map = as_object(cursor, "invalid_cursor", "cursor")?;
        scope_match(cursor_map, "cursor", &target, &run_id, &partition_id)?;
        let walk_id = required_str(cursor_map, "walk_id", "invalid_cursor", "cursor")?.to_string();
        let bytes = canonical_bytes(cursor)
            .map_err(|e| fault("invalid_cursor", format!("cursor canonicalization failed: {}", e.detail)))?;
        let digest = digest_bytes(&bytes);
        let cursor_ref = frame_reference(
            "cursor_state",
            &[
                target.clone(),
                run_id.clone(),
                partition_id.clone(),
                walk_id,
            ],
        )
        .map_err(|e| fault("invalid_cursor", format!("cursor reference failed: {}", e.detail)))?;
        snapshots.push(json!({
            "digest": digest,
            "cursor_ref": cursor_ref,
            "evidence_refs": evidence_refs.clone(),
        }));
    }

    // Exhaustive ledger preservation: the ledger identity row must
    // normalize without loss before it is exported.
    let normalize_evidence = validate(
        OUTPUT_SCHEMA,
        json!({
            "captured_at": {
                "clock_id": "coverage-export",
                "boot_id": "boot-1",
                "origin": "engine_measured",
                "monotonic_offset_ms": 1,
            },
            "evidence_prefix": evidence_prefix.clone(),
            "evidence_refs": evidence_refs.clone(),
        }),
    )
    .map_err(|e| fault("invalid_evaluation", format!("export evidence rejected: {}", e.detail)))?;
    normalize_row(
        SourceEntity::CoverageLedger,
        json!({
            "target": target.clone(),
            "run_id": run_id.clone(),
            "partition_id": partition_id.clone(),
        }),
        &normalize_evidence,
    )?;

    let output = json!({
        "record_type": EXPORT_SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "target": target,
        "run_id": run_id,
        "partition_id": partition_id,
        "declaration": declaration.clone(),
        "ledger": ledger_ar,
        "cursor_snapshots": snapshots,
        "uncertified_observations": uncertified,
        "cursor_capability_status": capability_status,
        "cursor_capability_evidence_refs": capability_refs,
        "proof": proof_value.clone(),
        "detectors": detector_entries.clone(),
        "drift": drift_value.clone(),
        "measurements": measurements.clone(),
        "evidence_prefix": evidence_prefix,
        "evidence_refs": evidence_refs,
    });
    validate(EXPORT_SCHEMA, output)
}

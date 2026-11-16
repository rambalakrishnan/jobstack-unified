//! `crawler_detectors`: five coverage detectors (C27) and drift evaluation (C31).
//!
//! Implements seam map §17.3 (detector state and trigger matrix), §17.4
//! (drift), and §11.3 (exact occurrences and drift entries) on top of the
//! structural [`crawler_schema`] gate:
//!
//! * [`evaluate_detectors`] advances the five diagnostic detectors — row cap,
//!   saturation, no-op parameter, tail clamp, ascending overflow — by exactly
//!   one page commit. Thresholds are 1 for row cap / saturation and the
//!   declared (initially 2) corroborations for no-op / tail clamp. Newest-date
//!   regression alone yields suspicion, never proof. Every evaluation exports
//!   the full trigger bundle: detection boundary, scope, response identity,
//!   request coordinate, units/count evidence, ID/page signatures, immediate
//!   action, recovery, final disposition, and journal-backed audit support.
//! * [`evaluate_drift`] computes the repeated-distinct duplicate rate
//!   (`repeated_distinct / distinct`, zero when distinct is zero), bands it
//!   against `effective_baseline = max(baseline, 0.001)`, keeps incompatible
//!   backend cohorts separate (never averaged), compares dates only under the
//!   same partition-definition hash, and bounds reconciliation to three passes.
//!
//! Diagnostic discipline:
//!
//! * Detector states live under `state_domain = "diagnostic"`. The output
//!   carries `ledger_status = Missing(not_applicable)`; no diagnostic state
//!   is emitted as a ledger status.
//! * Page/response digests are `SH` objects. When the caller supplies the
//!   exact hashed bytes, they are confirmed via
//!   [`crawler_hashing::reconcile_source_hash`]; a hash of a digest string or
//!   wrong framing is rejected. Without bytes the preserved digest text is
//!   compared opaquely.
//! * Audit support for every detector and for drift is a normalized
//!   operational snapshot built with [`crawler_normalization::normalize_row`]
//!   from the caller's journal evidence, so no trigger evidence is suppressed.
//! * No live prohibited probes: `probe_policy` must be `"fixture_only"` and
//!   `packet.live_probe` must be false; otherwise evaluation faults instead of
//!   sending network traffic.
//! * Pure and deterministic: no wall clock, no storage writes, no network.
//!
//! ## `evaluate_detectors` contract
//!
//! `declaration` (object) carries detector configuration plus the journal
//! evidence reused for audit snapshots:
//!
//! ```text
//! {
//!   "target": ID, "run_id": ID, "partition_id": ID, "owner_domain": ID,
//!   "captured_at": TimePoint, "evidence_prefix": PREFIX,
//!   "evidence_refs": SUPPORT,
//!   "row_cap": REV | Missing(not_applicable),
//!   "row_cap_verified": BOOL,
//!   "saturation_markers": [TEXT],
//!   "noop_threshold": POS, "tail_threshold": POS,
//!   "ordering_model": TEXT,
//!   "overflow_banners": [TEXT],
//!   "probe_policy": "fixture_only"
//! }
//! ```
//!
//! `prior` carries the diagnostic states and retained signatures:
//!
//! ```text
//! {
//!   "rowcap_state": MONITORING|CAP_REACHED_TRIGGERED|BISECTED|
//!                   PROVEN_VIA_CHILDREN|TERMINAL_INCOMPLETE,
//!   "saturation_state": UNSATURATED|SATURATED_TRIGGERED|BISECTED|
//!                       PROVEN_VIA_CHILDREN|TERMINAL_INCOMPLETE,
//!   "noop_state": ADVANCING|SUSPECT_NOOP|NOOP_CONFIRMED_TRIGGERED|
//!                 PARTITION_ONLY_OR_ALTERNATIVE_CURSOR|TERMINAL_INCOMPLETE,
//!   "tail_state": ADVANCING|SUSPECT_TAIL_CLAMP|TAIL_CLAMP_CONFIRMED_TRIGGERED|
//!                 BISECTED_BELOW_CAP|PROVEN_VIA_CHILDREN|TERMINAL_INCOMPLETE,
//!   "ascending_state": MONITORING_ASCENDING|DATE_REGRESSION_SUSPICION|
//!                      ASCENDING_OVERFLOW_TRIGGERED|BISECTED|
//!                      PROVEN_VIA_CHILDREN|TERMINAL_UNRECOVERABLE,
//!   "noop_corroboration_count": REV, "tail_corroboration_count": REV,
//!   "first_page_ordered_ids": [ID] | Missing,
//!   "first_page_hash": SH | Missing,
//!   "first_page_coordinate": E,
//!   "terminal_ordered_ids": [ID] | Missing,
//!   "terminal_page_hash": SH | Missing,
//!   "max_date_posted": DATE | Missing,
//!   "split_available": BOOL, "alternative_cursor_available": BOOL,
//!   "below_cap_split_available": BOOL
//! }
//! ```
//!
//! `packet` is the page commit under evaluation:
//!
//! ```text
//! {
//!   "request_coordinate": E, "request_sequence": REV,
//!   "response_identity": ID, "response_hash": SH | Missing,
//!   "page_hash": SH | Missing, "page_bytes": TEXT | Missing,
//!   "ordered_observed_ids": [ID], "observed_total": REV,
//!   "reported_total": REV | Missing,
//!   "reported_total_source_verified": BOOL,
//!   "count_label_marker": TEXT | Missing,
//!   "saturation_marker_present": BOOL, "termination": BOOL,
//!   "coordinate_kind": in_range|beyond_range|distinct,
//!   "continuation_progress": BOOL, "ordering": TEXT,
//!   "newest_date": DATE | Missing,
//!   "banner_present": BOOL, "banner_text": TEXT | Missing,
//!   "count_units": TEXT, "children_proven": BOOL, "live_probe": BOOL
//! }
//! ```
//!
//! ## `evaluate_drift` contract
//!
//! `declaration` carries the drift baseline plus journal evidence:
//!
//! ```text
//! {
//!   "target": ID, "run_id": ID, "partition_id": ID, "owner_domain": ID,
//!   "captured_at": TimePoint, "evidence_prefix": PREFIX,
//!   "evidence_refs": SUPPORT,
//!   "baseline_dup_rate": NUM[0,1],
//!   "planned_over_fetch_factor": NUM>=1,
//!   "reconciliation_limit": REV<=3
//! }
//! ```
//!
//! `observations` carries the current walk evidence:
//!
//! ```text
//! {
//!   "distinct_total": REV, "repeated_distinct_total": REV,
//!   "exact_occurrences": [{target,run_id,partition_id,walk_id,job_id,
//!                          occurrence_count:POS}],
//!   "backend_signature": ID | Missing, "session_epoch": SID | Missing,
//!   "current_page_hash": SH | Missing,
//!   "current_page_bytes": TEXT | Missing,
//!   "partition_definition_hash": SH | Missing,
//!   "max_date_posted": DATE | Missing, "missing_posted_date_total": REV,
//!   "min_job_id": ID | Missing, "max_job_id": ID | Missing,
//!   "cursor_revision": REV, "detected_at": TP | Missing,
//!   "audit_event_ref": ER
//! }
//! ```
//!
//! `prior_ledger` carries the previous cohort baseline:
//!
//! ```text
//! {
//!   "backend_signature": ID | Missing,
//!   "partition_definition_hash": SH | Missing,
//!   "max_date_posted": DATE | Missing,
//!   "distinct_total": REV, "repeated_distinct_total": REV,
//!   "current_page_hash": SH | Missing,
//!   "reconciliation_passes_used": REV, "cursor_revision": REV
//! }
//! ```

use crawler_hashing::reconcile_source_hash;
use crawler_normalization::normalize_row;
use crawler_schema::{record_value, validate, CheckedRecord, Fault, SourceEntity};
use serde_json::{json, Map, Value};

const OUTPUT_SCHEMA: &str = "audit_log";
const SCHEMA_VERSION: &str = "crawler-seam/0.1.0";

const KNOWN_PROFILES: &[&str] = &[
    "kernel-jcs-sha256/1",
    "artifact-sha256/1",
    "crawler-fetch-key/1",
    "crawler-classifier-input/1",
    "crawler-page-hash/1",
];

const ROWCAP_STATES: &[&str] = &[
    "MONITORING",
    "CAP_REACHED_TRIGGERED",
    "BISECTED",
    "PROVEN_VIA_CHILDREN",
    "TERMINAL_INCOMPLETE",
];
const SATURATION_STATES: &[&str] = &[
    "UNSATURATED",
    "SATURATED_TRIGGERED",
    "BISECTED",
    "PROVEN_VIA_CHILDREN",
    "TERMINAL_INCOMPLETE",
];
const NOOP_STATES: &[&str] = &[
    "ADVANCING",
    "SUSPECT_NOOP",
    "NOOP_CONFIRMED_TRIGGERED",
    "PARTITION_ONLY_OR_ALTERNATIVE_CURSOR",
    "TERMINAL_INCOMPLETE",
];
const TAIL_STATES: &[&str] = &[
    "ADVANCING",
    "SUSPECT_TAIL_CLAMP",
    "TAIL_CLAMP_CONFIRMED_TRIGGERED",
    "BISECTED_BELOW_CAP",
    "PROVEN_VIA_CHILDREN",
    "TERMINAL_INCOMPLETE",
];
const ASCENDING_STATES: &[&str] = &[
    "MONITORING_ASCENDING",
    "DATE_REGRESSION_SUSPICION",
    "ASCENDING_OVERFLOW_TRIGGERED",
    "BISECTED",
    "PROVEN_VIA_CHILDREN",
    "TERMINAL_UNRECOVERABLE",
];

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

fn is_missing(value: &Value) -> bool {
    value
        .as_object()
        .is_some_and(|m| m.get("value").is_some_and(Value::is_null))
}

fn is_digest_text(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_date_text(text: &str) -> bool {
    // Strict YYYY-MM-DD shape; the schema gate does not check DATE format.
    let bytes = text.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }
    for (i, b) in bytes.iter().enumerate() {
        if i == 4 || i == 7 {
            continue;
        }
        if !b.is_ascii_digit() {
            return false;
        }
    }
    let month: u32 = text[5..7].parse().unwrap_or(0);
    let day: u32 = text[8..10].parse().unwrap_or(0);
    (1..=12).contains(&month) && (1..=31).contains(&day)
}

fn require_object<'a>(record: &'a CheckedRecord, code: &str, what: &str) -> Result<&'a Map<String, Value>, Fault> {
    record_value(record).as_object().ok_or_else(|| {
        fault(
            code,
            format!("{what} record value must be an object"),
        )
    })
}

fn required_field<'a>(
    obj: &'a Map<String, Value>,
    key: &str,
    code: &str,
) -> Result<&'a Value, Fault> {
    obj.get(key)
        .ok_or_else(|| fault(code, format!("missing required field {key:?}")))
}

fn required_str<'a>(
    obj: &'a Map<String, Value>,
    key: &str,
    code: &str,
) -> Result<&'a str, Fault> {
    let value = required_field(obj, key, code)?;
    if is_missing(value) {
        return Err(fault(
            code,
            format!("field {key:?} must be established, got Missing"),
        ));
    }
    value
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| fault(code, format!("field {key:?} must be a nonempty string")))
}

fn required_bool(obj: &Map<String, Value>, key: &str, code: &str) -> Result<bool, Fault> {
    let value = required_field(obj, key, code)?;
    value
        .as_bool()
        .ok_or_else(|| fault(code, format!("field {key:?} must be a boolean")))
}

fn required_u64(obj: &Map<String, Value>, key: &str, code: &str) -> Result<u64, Fault> {
    let value = required_field(obj, key, code)?;
    if is_missing(value) {
        return Err(fault(
            code,
            format!("field {key:?} must be established, got Missing"),
        ));
    }
    value
        .as_u64()
        .ok_or_else(|| fault(code, format!("field {key:?} must be an unsigned integer")))
}

fn required_pos(obj: &Map<String, Value>, key: &str, code: &str) -> Result<u64, Fault> {
    let value = required_u64(obj, key, code)?;
    if value == 0 {
        return Err(fault(
            code,
            format!("field {key:?} must be POS (>= 1)"),
        ));
    }
    Ok(value)
}

fn required_f64(obj: &Map<String, Value>, key: &str, code: &str) -> Result<f64, Fault> {
    let value = required_field(obj, key, code)?;
    if is_missing(value) {
        return Err(fault(
            code,
            format!("field {key:?} must be established, got Missing"),
        ));
    }
    let number = value
        .as_f64()
        .ok_or_else(|| fault(code, format!("field {key:?} must be a number")))?;
    if !number.is_finite() {
        return Err(fault(code, format!("field {key:?} must be finite")));
    }
    Ok(number)
}

fn required_array<'a>(
    obj: &'a Map<String, Value>,
    key: &str,
    code: &str,
) -> Result<&'a Vec<Value>, Fault> {
    let value = required_field(obj, key, code)?;
    value
        .as_array()
        .ok_or_else(|| fault(code, format!("field {key:?} must be an array")))
}

fn optional_u64(obj: &Map<String, Value>, key: &str, code: &str) -> Result<Option<u64>, Fault> {
    let value = required_field(obj, key, code)?;
    if is_missing(value) {
        return Ok(None);
    }
    value.as_u64().map(Some).ok_or_else(|| {
        fault(
            code,
            format!("field {key:?} must be an unsigned integer or Missing"),
        )
    })
}

fn optional_str<'a>(
    obj: &'a Map<String, Value>,
    key: &str,
    code: &str,
) -> Result<Option<&'a str>, Fault> {
    let value = required_field(obj, key, code)?;
    if is_missing(value) {
        return Ok(None);
    }
    value
        .as_str()
        .filter(|s| !s.is_empty())
        .map(Some)
        .ok_or_else(|| {
            fault(
                code,
                format!("field {key:?} must be a nonempty string or Missing"),
            )
        })
}

fn optional_date<'a>(
    obj: &'a Map<String, Value>,
    key: &str,
    code: &str,
) -> Result<Option<&'a str>, Fault> {
    match optional_str(obj, key, code)? {
        None => Ok(None),
        Some(text) => {
            if !is_date_text(text) {
                return Err(fault(
                    code,
                    format!("field {key:?} must be a YYYY-MM-DD date or Missing, got {text:?}"),
                ));
            }
            Ok(Some(text))
        }
    }
}

fn optional_id_list(obj: &Map<String, Value>, key: &str, code: &str) -> Result<Option<Vec<String>>, Fault> {
    let value = required_field(obj, key, code)?;
    if is_missing(value) {
        return Ok(None);
    }
    let items = value
        .as_array()
        .ok_or_else(|| fault(code, format!("field {key:?} must be an ID array or Missing")))?;
    let mut out = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        let id = item.as_str().filter(|s| !s.is_empty()).ok_or_else(|| {
            fault(
                code,
                format!("field {key:?}[{i}] must be a nonempty ID string"),
            )
        })?;
        out.push(id.to_string());
    }
    Ok(Some(out))
}

fn required_id_list(obj: &Map<String, Value>, key: &str, code: &str) -> Result<Vec<String>, Fault> {
    let items = required_array(obj, key, code)?;
    let mut out = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        let id = item.as_str().filter(|s| !s.is_empty()).ok_or_else(|| {
            fault(
                code,
                format!("field {key:?}[{i}] must be a nonempty ID string"),
            )
        })?;
        out.push(id.to_string());
    }
    Ok(out)
}

fn required_text_list(obj: &Map<String, Value>, key: &str, code: &str) -> Result<Vec<String>, Fault> {
    // TEXT may legitimately be empty; only the type is enforced.
    let items = required_array(obj, key, code)?;
    let mut out = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        let text = item.as_str().ok_or_else(|| {
            fault(
                code,
                format!("field {key:?}[{i}] must be a string"),
            )
        })?;
        out.push(text.to_string());
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// SH handling
// ---------------------------------------------------------------------------

struct ShDigest {
    digest: String,
}

fn parse_sh(value: &Value, field: &str) -> Result<Option<ShDigest>, Fault> {
    if is_missing(value) {
        return Ok(None);
    }
    let map = value
        .as_object()
        .ok_or_else(|| fault("invalid_sh", format!("{field} must be an SH object or Missing")))?;
    let digest = map
        .get("value")
        .and_then(Value::as_str)
        .ok_or_else(|| fault("invalid_sh", format!("{field}.value must be the source digest text")))?;
    if !is_digest_text(digest) {
        return Err(fault(
            "invalid_sh",
            format!("{field}.value must be 64 lowercase hex characters"),
        ));
    }
    let profile = map
        .get("profile")
        .and_then(Value::as_str)
        .ok_or_else(|| fault("invalid_sh", format!("{field}.profile must be a pinned profile id")))?;
    if !KNOWN_PROFILES.contains(&profile) {
        return Err(fault(
            "unknown_profile",
            format!("{field}.profile {profile:?} is not one of the five pinned profiles"),
        ));
    }
    match map.get("evidence_refs") {
        Some(Value::Array(_)) => {}
        _ => {
            return Err(fault(
                "invalid_sh",
                format!("{field}.evidence_refs must be an array"),
            ))
        }
    }
    Ok(Some(ShDigest {
        digest: digest.to_string(),
    }))
}

/// Confirm an `SH` value against optional caller bytes.
///
/// A Missing envelope yields `None`. An established SH with supplied bytes is
/// reconciled via [`reconcile_source_hash`] so wrong bytes, wrong framing, or
/// a hash-of-hash is rejected. Without bytes the preserved digest text is
/// returned opaquely after shape validation.
fn reconcile_sh_opt(
    sh_value: &Value,
    bytes: Option<&[u8]>,
    field: &str,
) -> Result<Option<String>, Fault> {
    let Some(facts) = parse_sh(sh_value, field)? else {
        return Ok(None);
    };
    let Some(bytes) = bytes else {
        return Ok(Some(facts.digest));
    };
    let source = validate("cursor_state", sh_value.clone()).map_err(|e| {
        fault(
            "invalid_sh",
            format!("{field}: schema gate rejected SH: {} {}", e.code, e.detail),
        )
    })?;
    let reconciled = reconcile_source_hash(&source, Some(bytes)).map_err(|e| {
        Fault {
            code: e.code.clone(),
            detail: format!("{field}: {} {}", e.code, e.detail),
        }
    })?;
    let digest = record_value(&reconciled)
        .get("digest")
        .and_then(Value::as_str)
        .unwrap_or(facts.digest.as_str())
        .to_string();
    Ok(Some(digest))
}

fn m_bytes<'a>(
    obj: &'a Map<String, Value>,
    key: &str,
    code: &str,
) -> Result<Option<&'a [u8]>, Fault> {
    let value = required_field(obj, key, code)?;
    if is_missing(value) {
        return Ok(None);
    }
    value
        .as_str()
        .map(|s| Some(s.as_bytes()))
        .ok_or_else(|| fault(code, format!("field {key:?} must be a string of exact hashed bytes or Missing")))
}

// ---------------------------------------------------------------------------
// Audit support via normalization
// ---------------------------------------------------------------------------

fn normalize_evidence(declaration: &Map<String, Value>) -> Result<CheckedRecord, Fault> {
    let captured_at = required_field(declaration, "captured_at", "missing_evidence")?;
    if is_missing(captured_at) || !captured_at.is_object() {
        return Err(fault(
            "missing_evidence",
            "declaration.captured_at must be an established TimePoint",
        ));
    }
    let prefix = required_field(declaration, "evidence_prefix", "missing_evidence")?;
    if !prefix.is_object() {
        return Err(fault(
            "missing_evidence",
            "declaration.evidence_prefix must be an object",
        ));
    }
    let refs = required_field(declaration, "evidence_refs", "missing_evidence")?;
    let items = refs
        .as_array()
        .ok_or_else(|| fault("missing_evidence", "declaration.evidence_refs must be SUPPORT"))?;
    if items.is_empty() {
        return Err(fault(
            "missing_evidence",
            "declaration.evidence_refs must be nonempty SUPPORT",
        ));
    }
    validate(
        OUTPUT_SCHEMA,
        json!({
            "captured_at": captured_at.clone(),
            "evidence_prefix": prefix.clone(),
            "evidence_refs": refs.clone(),
        }),
    )
    .map_err(|e| {
        fault(
            "missing_evidence",
            format!("normalization evidence gate rejected: {} {}", e.code, e.detail),
        )
    })
}

fn audit_snapshot(
    evidence: &CheckedRecord,
    target: &str,
    owner_domain: &str,
    event_id: String,
    fields: Vec<(&str, Value)>,
) -> Result<Value, Fault> {
    let mut row = Map::new();
    row.insert("target".to_string(), Value::String(target.to_string()));
    row.insert(
        "owner_domain".to_string(),
        Value::String(owner_domain.to_string()),
    );
    row.insert("event_id".to_string(), Value::String(event_id));
    for (key, value) in fields {
        row.insert(key.to_string(), value);
    }
    let snapshot = normalize_row(SourceEntity::AuditLog, Value::Object(row), evidence)?;
    let snapshot_value = record_value(&snapshot).clone();
    let entity_id = snapshot_value
        .get("entity_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    Ok(json!({
        "entity_id": entity_id,
        "snapshot": snapshot_value,
    }))
}

// ---------------------------------------------------------------------------
// Detector evaluation
// ---------------------------------------------------------------------------

struct DetectorResult {
    detector: &'static str,
    state: String,
    blocking: bool,
    corroboration: u64,
    threshold: u64,
    action: &'static str,
    failure: Value,
    recovery: &'static str,
    disposition: String,
    baseline_ids: Value,
    baseline_hash: Value,
}

fn check_state(value: &str, allowed: &[&str], field: &str) -> Result<(), Fault> {
    if allowed.contains(&value) {
        Ok(())
    } else {
        Err(fault(
            "unknown_state",
            format!("{field} {value:?} is not a known diagnostic state"),
        ))
    }
}

fn inapplicable_failure() -> Value {
    missing(
        "not_applicable",
        "no terminal failure; detector has not reached a terminal state",
    )
}

#[allow(clippy::too_many_arguments)]
fn detector_value(
    result: &DetectorResult,
    evidence_refs: &Value,
    detection_boundary: &Value,
    scope: &Value,
    response_identity: &str,
    request_coordinate: &Value,
    count_evidence: &Value,
    ordered_observed_ids: &[String],
    page_hash_value: &Value,
    response_hash_value: &Value,
    audit_support: Value,
) -> Value {
    json!({
        "detector": result.detector,
        "state": result.state,
        "blocking": result.blocking,
        "corroboration_count": result.corroboration,
        "threshold": result.threshold,
        "evidence_refs": evidence_refs.clone(),
        "action": result.action,
        "failure_reason": result.failure.clone(),
        "evidence": {
            "detection_boundary": detection_boundary.clone(),
            "scope": scope.clone(),
            "response_identity": response_identity,
            "request_coordinate": request_coordinate.clone(),
            "count_evidence": count_evidence.clone(),
            "id_signatures": {
                "ordered_observed_ids": ordered_observed_ids,
                "baseline_ids": result.baseline_ids.clone(),
            },
            "page_signatures": {
                "page_hash": page_hash_value.clone(),
                "baseline_hash": result.baseline_hash.clone(),
                "response_hash": response_hash_value.clone(),
            },
            "recovery": result.recovery,
            "disposition": result.disposition,
            "audit_support": audit_support,
        },
    })
}

/// Evaluate the five coverage detectors for one page commit.
///
/// See the module documentation for the exact declaration/prior/packet shapes.
/// The returned `audit_log` record carries `state_domain = "diagnostic"` and
/// one evaluation per detector with its trigger bundle and audit snapshot.
pub fn evaluate_detectors(
    declaration: &CheckedRecord,
    prior: &CheckedRecord,
    packet: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let decl = require_object(declaration, "invalid_declaration", "declaration")?;
    let prev = require_object(prior, "invalid_prior", "prior")?;
    let pkt = require_object(packet, "invalid_packet", "packet")?;

    // Declaration: identity, evidence, configuration.
    let target = required_str(decl, "target", "invalid_declaration")?.to_string();
    let run_id = required_str(decl, "run_id", "invalid_declaration")?.to_string();
    let partition_id = required_str(decl, "partition_id", "invalid_declaration")?.to_string();
    let owner_domain = required_str(decl, "owner_domain", "invalid_declaration")?.to_string();
    let evidence_refs = required_field(decl, "evidence_refs", "missing_evidence")?.clone();
    let evidence_prefix = required_field(decl, "evidence_prefix", "missing_evidence")?.clone();
    let row_cap = optional_u64(decl, "row_cap", "invalid_declaration")?;
    let row_cap_verified = required_bool(decl, "row_cap_verified", "invalid_declaration")?;
    let saturation_markers = required_text_list(decl, "saturation_markers", "invalid_declaration")?;
    let noop_threshold = required_pos(decl, "noop_threshold", "invalid_declaration")?;
    let tail_threshold = required_pos(decl, "tail_threshold", "invalid_declaration")?;
    let ordering_model = required_str(decl, "ordering_model", "invalid_declaration")?.to_string();
    let _ = ordering_model;
    let overflow_banners = required_text_list(decl, "overflow_banners", "invalid_declaration")?;
    let probe_policy = required_str(decl, "probe_policy", "invalid_declaration")?;
    if probe_policy != "fixture_only" {
        return Err(fault(
            "invalid_probe_policy",
            "declaration.probe_policy must be \"fixture_only\"; live prohibited probes are rejected",
        ));
    }
    let evidence = normalize_evidence(decl)?;

    // Prior diagnostic states.
    let rowcap_state = required_str(prev, "rowcap_state", "invalid_prior")?.to_string();
    check_state(&rowcap_state, ROWCAP_STATES, "prior.rowcap_state")?;
    let saturation_state =
        required_str(prev, "saturation_state", "invalid_prior")?.to_string();
    check_state(&saturation_state, SATURATION_STATES, "prior.saturation_state")?;
    let noop_state = required_str(prev, "noop_state", "invalid_prior")?.to_string();
    check_state(&noop_state, NOOP_STATES, "prior.noop_state")?;
    let tail_state = required_str(prev, "tail_state", "invalid_prior")?.to_string();
    check_state(&tail_state, TAIL_STATES, "prior.tail_state")?;
    let ascending_state =
        required_str(prev, "ascending_state", "invalid_prior")?.to_string();
    check_state(&ascending_state, ASCENDING_STATES, "prior.ascending_state")?;
    let noop_count_prior = required_u64(prev, "noop_corroboration_count", "invalid_prior")?;
    let tail_count_prior = required_u64(prev, "tail_corroboration_count", "invalid_prior")?;
    let first_ids = optional_id_list(prev, "first_page_ordered_ids", "invalid_prior")?;
    let first_hash_value = required_field(prev, "first_page_hash", "invalid_prior")?.clone();
    let first_digest = parse_sh(&first_hash_value, "prior.first_page_hash")?
        .map(|s| s.digest);
    let first_coordinate = required_field(prev, "first_page_coordinate", "invalid_prior")?.clone();
    let terminal_ids = optional_id_list(prev, "terminal_ordered_ids", "invalid_prior")?;
    let terminal_hash_value =
        required_field(prev, "terminal_page_hash", "invalid_prior")?.clone();
    let terminal_digest = parse_sh(&terminal_hash_value, "prior.terminal_page_hash")?
        .map(|s| s.digest);
    let prior_max_date = optional_date(prev, "max_date_posted", "invalid_prior")?.map(str::to_string);
    let split_available = required_bool(prev, "split_available", "invalid_prior")?;
    let alternative_cursor_available =
        required_bool(prev, "alternative_cursor_available", "invalid_prior")?;
    let below_cap_split_available =
        required_bool(prev, "below_cap_split_available", "invalid_prior")?;

    // Packet fields.
    if required_bool(pkt, "live_probe", "invalid_packet")? {
        return Err(fault(
            "prohibited_live_probe",
            "packet.live_probe is true; known no-op probes use retained fixtures, never live traffic",
        ));
    }
    let request_coordinate = required_field(pkt, "request_coordinate", "invalid_packet")?.clone();
    let request_sequence = required_u64(pkt, "request_sequence", "invalid_packet")?;
    let response_identity = required_str(pkt, "response_identity", "invalid_packet")?.to_string();
    let response_hash_value = required_field(pkt, "response_hash", "invalid_packet")?.clone();
    let _ = parse_sh(&response_hash_value, "packet.response_hash")?;
    let page_hash_value = required_field(pkt, "page_hash", "invalid_packet")?.clone();
    let page_bytes = m_bytes(pkt, "page_bytes", "invalid_packet")?;
    let page_digest = reconcile_sh_opt(&page_hash_value, page_bytes, "packet.page_hash")?;
    let ordered_ids = required_id_list(pkt, "ordered_observed_ids", "invalid_packet")?;
    let observed_total = required_u64(pkt, "observed_total", "invalid_packet")?;
    let reported_total = optional_u64(pkt, "reported_total", "invalid_packet")?;
    let _reported_verified = required_bool(pkt, "reported_total_source_verified", "invalid_packet")?;
    let count_label_marker = optional_str(pkt, "count_label_marker", "invalid_packet")?
        .map(str::to_string);
    let saturation_present = required_bool(pkt, "saturation_marker_present", "invalid_packet")?;
    let termination = required_bool(pkt, "termination", "invalid_packet")?;
    let coordinate_kind = required_str(pkt, "coordinate_kind", "invalid_packet")?.to_string();
    if !["in_range", "beyond_range", "distinct"].contains(&coordinate_kind.as_str()) {
        return Err(fault(
            "invalid_packet",
            format!("packet.coordinate_kind {coordinate_kind:?} must be in_range|beyond_range|distinct"),
        ));
    }
    let continuation_progress = required_bool(pkt, "continuation_progress", "invalid_packet")?;
    let ordering = required_str(pkt, "ordering", "invalid_packet")?.to_string();
    let newest_date = optional_date(pkt, "newest_date", "invalid_packet")?.map(str::to_string);
    let banner_present = required_bool(pkt, "banner_present", "invalid_packet")?;
    let banner_text = optional_str(pkt, "banner_text", "invalid_packet")?.map(str::to_string);
    let count_units = required_str(pkt, "count_units", "invalid_packet")?.to_string();
    let children_proven = required_bool(pkt, "children_proven", "invalid_packet")?;

    // Shared evidence fragments.
    let scope = json!({
        "target": target,
        "run_id": run_id,
        "partition_id": partition_id,
    });
    let detection_boundary = json!({
        "request_sequence": request_sequence,
        "observed_total": observed_total,
    });
    let reported_total_value = required_field(pkt, "reported_total", "invalid_packet")?.clone();
    let row_cap_value = required_field(decl, "row_cap", "invalid_declaration")?.clone();
    let count_evidence = json!({
        "observed_total": observed_total,
        "reported_total": reported_total_value,
        "units": count_units,
        "cap": row_cap_value,
    });

    // -- Row cap (threshold 1). --
    let cap_trigger = match row_cap {
        Some(cap) if row_cap_verified => {
            observed_total >= cap
                || (termination
                    && reported_total.is_some_and(|reported| observed_total < reported)
                    && observed_total >= cap.saturating_sub(ordered_ids.len() as u64))
        }
        _ => false,
    };
    let rowcap = match rowcap_state.as_str() {
        "MONITORING" => {
            if cap_trigger {
                DetectorResult {
                    detector: "row_cap",
                    state: "CAP_REACHED_TRIGGERED".to_string(),
                    blocking: true,
                    corroboration: 1,
                    threshold: 1,
                    action: "stop_walk",
                    failure: inapplicable_failure(),
                    recovery: if split_available { "split" } else { "mark_incomplete" },
                    disposition: if split_available {
                        "triggered_stop_walk_pending_split".to_string()
                    } else {
                        "triggered_stop_walk_no_axis".to_string()
                    },
                    baseline_ids: missing("not_applicable", "row cap does not compare ID sets"),
                    baseline_hash: missing("not_applicable", "row cap does not compare page hashes"),
                }
            } else {
                DetectorResult {
                    detector: "row_cap",
                    state: "MONITORING".to_string(),
                    blocking: false,
                    corroboration: 0,
                    threshold: 1,
                    action: "monitor",
                    failure: inapplicable_failure(),
                    recovery: "none",
                    disposition: "monitoring_below_cap".to_string(),
                    baseline_ids: missing("not_applicable", "row cap does not compare ID sets"),
                    baseline_hash: missing("not_applicable", "row cap does not compare page hashes"),
                }
            }
        }
        "CAP_REACHED_TRIGGERED" => {
            if split_available {
                DetectorResult {
                    detector: "row_cap",
                    state: "BISECTED".to_string(),
                    blocking: true,
                    corroboration: 1,
                    threshold: 1,
                    action: "split",
                    failure: inapplicable_failure(),
                    recovery: "split",
                    disposition: "bisected_pending_children".to_string(),
                    baseline_ids: missing("not_applicable", "row cap does not compare ID sets"),
                    baseline_hash: missing("not_applicable", "row cap does not compare page hashes"),
                }
            } else {
                DetectorResult {
                    detector: "row_cap",
                    state: "TERMINAL_INCOMPLETE".to_string(),
                    blocking: true,
                    corroboration: 1,
                    threshold: 1,
                    action: "mark_incomplete",
                    failure: Value::String("terminal_incomplete".to_string()),
                    recovery: "terminal",
                    disposition: "terminal_incomplete_no_axis".to_string(),
                    baseline_ids: missing("not_applicable", "row cap does not compare ID sets"),
                    baseline_hash: missing("not_applicable", "row cap does not compare page hashes"),
                }
            }
        }
        "BISECTED" => {
            if children_proven {
                DetectorResult {
                    detector: "row_cap",
                    state: "PROVEN_VIA_CHILDREN".to_string(),
                    blocking: false,
                    corroboration: 1,
                    threshold: 1,
                    action: "proven_via_children",
                    failure: inapplicable_failure(),
                    recovery: "proven_via_children",
                    disposition: "proven_via_children".to_string(),
                    baseline_ids: missing("not_applicable", "row cap does not compare ID sets"),
                    baseline_hash: missing("not_applicable", "row cap does not compare page hashes"),
                }
            } else {
                DetectorResult {
                    detector: "row_cap",
                    state: "BISECTED".to_string(),
                    blocking: true,
                    corroboration: 1,
                    threshold: 1,
                    action: "split",
                    failure: inapplicable_failure(),
                    recovery: "split",
                    disposition: "bisected_pending_children".to_string(),
                    baseline_ids: missing("not_applicable", "row cap does not compare ID sets"),
                    baseline_hash: missing("not_applicable", "row cap does not compare page hashes"),
                }
            }
        }
        "PROVEN_VIA_CHILDREN" => DetectorResult {
            detector: "row_cap",
            state: "PROVEN_VIA_CHILDREN".to_string(),
            blocking: false,
            corroboration: 1,
            threshold: 1,
            action: "proven_via_children",
            failure: inapplicable_failure(),
            recovery: "proven_via_children",
            disposition: "proven_via_children".to_string(),
            baseline_ids: missing("not_applicable", "row cap does not compare ID sets"),
            baseline_hash: missing("not_applicable", "row cap does not compare page hashes"),
        },
        _ => DetectorResult {
            detector: "row_cap",
            state: "TERMINAL_INCOMPLETE".to_string(),
            blocking: true,
            corroboration: 1,
            threshold: 1,
            action: "mark_incomplete",
            failure: Value::String("terminal_incomplete".to_string()),
            recovery: "terminal",
            disposition: "terminal_incomplete_no_axis".to_string(),
            baseline_ids: missing("not_applicable", "row cap does not compare ID sets"),
            baseline_hash: missing("not_applicable", "row cap does not compare page hashes"),
        },
    };

    // -- Saturation (threshold 1, configured marker only). --
    let saturation_trigger = saturation_present
        && count_label_marker
            .as_deref()
            .is_some_and(|marker| saturation_markers.iter().any(|m| m == marker));
    let saturation = match saturation_state.as_str() {
        "UNSATURATED" => {
            if saturation_trigger {
                DetectorResult {
                    detector: "saturation",
                    state: "SATURATED_TRIGGERED".to_string(),
                    blocking: true,
                    corroboration: 1,
                    threshold: 1,
                    action: "stop_walk",
                    failure: inapplicable_failure(),
                    recovery: if split_available { "split" } else { "mark_incomplete" },
                    disposition: if split_available {
                        "triggered_stop_walk_pending_split".to_string()
                    } else {
                        "triggered_stop_walk_no_axis".to_string()
                    },
                    baseline_ids: missing("not_applicable", "saturation does not compare ID sets"),
                    baseline_hash: missing("not_applicable", "saturation does not compare page hashes"),
                }
            } else {
                DetectorResult {
                    detector: "saturation",
                    state: "UNSATURATED".to_string(),
                    blocking: false,
                    corroboration: 0,
                    threshold: 1,
                    action: "monitor",
                    failure: inapplicable_failure(),
                    recovery: "none",
                    disposition: "unsaturated_no_marker".to_string(),
                    baseline_ids: missing("not_applicable", "saturation does not compare ID sets"),
                    baseline_hash: missing("not_applicable", "saturation does not compare page hashes"),
                }
            }
        }
        "SATURATED_TRIGGERED" => {
            if split_available {
                DetectorResult {
                    detector: "saturation",
                    state: "BISECTED".to_string(),
                    blocking: true,
                    corroboration: 1,
                    threshold: 1,
                    action: "split",
                    failure: inapplicable_failure(),
                    recovery: "split",
                    disposition: "bisected_pending_children".to_string(),
                    baseline_ids: missing("not_applicable", "saturation does not compare ID sets"),
                    baseline_hash: missing("not_applicable", "saturation does not compare page hashes"),
                }
            } else {
                DetectorResult {
                    detector: "saturation",
                    state: "TERMINAL_INCOMPLETE".to_string(),
                    blocking: true,
                    corroboration: 1,
                    threshold: 1,
                    action: "mark_incomplete",
                    failure: Value::String("terminal_incomplete".to_string()),
                    recovery: "terminal",
                    disposition: "terminal_incomplete_no_axis".to_string(),
                    baseline_ids: missing("not_applicable", "saturation does not compare ID sets"),
                    baseline_hash: missing("not_applicable", "saturation does not compare page hashes"),
                }
            }
        }
        "BISECTED" => {
            if children_proven {
                DetectorResult {
                    detector: "saturation",
                    state: "PROVEN_VIA_CHILDREN".to_string(),
                    blocking: false,
                    corroboration: 1,
                    threshold: 1,
                    action: "proven_via_children",
                    failure: inapplicable_failure(),
                    recovery: "proven_via_children",
                    disposition: "proven_via_children".to_string(),
                    baseline_ids: missing("not_applicable", "saturation does not compare ID sets"),
                    baseline_hash: missing("not_applicable", "saturation does not compare page hashes"),
                }
            } else {
                DetectorResult {
                    detector: "saturation",
                    state: "BISECTED".to_string(),
                    blocking: true,
                    corroboration: 1,
                    threshold: 1,
                    action: "split",
                    failure: inapplicable_failure(),
                    recovery: "split",
                    disposition: "bisected_pending_children".to_string(),
                    baseline_ids: missing("not_applicable", "saturation does not compare ID sets"),
                    baseline_hash: missing("not_applicable", "saturation does not compare page hashes"),
                }
            }
        }
        "PROVEN_VIA_CHILDREN" => DetectorResult {
            detector: "saturation",
            state: "PROVEN_VIA_CHILDREN".to_string(),
            blocking: false,
            corroboration: 1,
            threshold: 1,
            action: "proven_via_children",
            failure: inapplicable_failure(),
            recovery: "proven_via_children",
            disposition: "proven_via_children".to_string(),
            baseline_ids: missing("not_applicable", "saturation does not compare ID sets"),
            baseline_hash: missing("not_applicable", "saturation does not compare page hashes"),
        },
        _ => DetectorResult {
            detector: "saturation",
            state: "TERMINAL_INCOMPLETE".to_string(),
            blocking: true,
            corroboration: 1,
            threshold: 1,
            action: "mark_incomplete",
            failure: Value::String("terminal_incomplete".to_string()),
            recovery: "terminal",
            disposition: "terminal_incomplete_no_axis".to_string(),
            baseline_ids: missing("not_applicable", "saturation does not compare ID sets"),
            baseline_hash: missing("not_applicable", "saturation does not compare page hashes"),
        },
    };

    // -- No-op parameter (retained-fixture comparison, threshold N). --
    let first_ids_match = first_ids
        .as_ref()
        .is_some_and(|baseline| *baseline == ordered_ids);
    let first_hash_match = match (&first_digest, &page_digest) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    };
    let repeats_first = first_ids_match || first_hash_match;
    let distinct_coordinate = request_coordinate != first_coordinate && !is_missing(&first_coordinate);
    let has_baseline = first_ids.is_some() || first_digest.is_some();
    let noop_event =
        has_baseline && repeats_first && distinct_coordinate && !continuation_progress;
    let noop_count = noop_count_prior.saturating_add(u64::from(noop_event));
    let first_ids_value = required_field(prev, "first_page_ordered_ids", "invalid_prior")?.clone();
    let noop = match noop_state.as_str() {
        "ADVANCING" | "SUSPECT_NOOP" => {
            if noop_count >= noop_threshold {
                DetectorResult {
                    detector: "noop_parameter",
                    state: "NOOP_CONFIRMED_TRIGGERED".to_string(),
                    blocking: true,
                    corroboration: noop_count,
                    threshold: noop_threshold,
                    action: "stop_walk",
                    failure: inapplicable_failure(),
                    recovery: if alternative_cursor_available {
                        "alternative_cursor"
                    } else {
                        "mark_incomplete"
                    },
                    disposition: "confirmed_stop_walk".to_string(),
                    baseline_ids: first_ids_value.clone(),
                    baseline_hash: first_hash_value.clone(),
                }
            } else if noop_count >= 1 {
                DetectorResult {
                    detector: "noop_parameter",
                    state: "SUSPECT_NOOP".to_string(),
                    blocking: false,
                    corroboration: noop_count,
                    threshold: noop_threshold,
                    action: "monitor",
                    failure: inapplicable_failure(),
                    recovery: "none",
                    disposition: "suspect_collecting_corroboration".to_string(),
                    baseline_ids: first_ids_value.clone(),
                    baseline_hash: first_hash_value.clone(),
                }
            } else {
                DetectorResult {
                    detector: "noop_parameter",
                    state: "ADVANCING".to_string(),
                    blocking: false,
                    corroboration: noop_count,
                    threshold: noop_threshold,
                    action: "monitor",
                    failure: inapplicable_failure(),
                    recovery: "none",
                    disposition: "advancing_no_repeat".to_string(),
                    baseline_ids: first_ids_value.clone(),
                    baseline_hash: first_hash_value.clone(),
                }
            }
        }
        "NOOP_CONFIRMED_TRIGGERED" => {
            if alternative_cursor_available {
                DetectorResult {
                    detector: "noop_parameter",
                    state: "PARTITION_ONLY_OR_ALTERNATIVE_CURSOR".to_string(),
                    blocking: false,
                    corroboration: noop_count,
                    threshold: noop_threshold,
                    action: "stop_walk",
                    failure: inapplicable_failure(),
                    recovery: "alternative_cursor",
                    disposition: "partition_only_or_alternative_cursor".to_string(),
                    baseline_ids: first_ids_value.clone(),
                    baseline_hash: first_hash_value.clone(),
                }
            } else {
                DetectorResult {
                    detector: "noop_parameter",
                    state: "TERMINAL_INCOMPLETE".to_string(),
                    blocking: true,
                    corroboration: noop_count,
                    threshold: noop_threshold,
                    action: "mark_incomplete",
                    failure: Value::String("terminal_incomplete".to_string()),
                    recovery: "terminal",
                    disposition: "terminal_incomplete_no_alternative".to_string(),
                    baseline_ids: first_ids_value.clone(),
                    baseline_hash: first_hash_value.clone(),
                }
            }
        }
        "PARTITION_ONLY_OR_ALTERNATIVE_CURSOR" => DetectorResult {
            detector: "noop_parameter",
            state: "PARTITION_ONLY_OR_ALTERNATIVE_CURSOR".to_string(),
            blocking: false,
            corroboration: noop_count,
            threshold: noop_threshold,
            action: "stop_walk",
            failure: inapplicable_failure(),
            recovery: "alternative_cursor",
            disposition: "partition_only_or_alternative_cursor".to_string(),
            baseline_ids: first_ids_value.clone(),
            baseline_hash: first_hash_value.clone(),
        },
        _ => DetectorResult {
            detector: "noop_parameter",
            state: "TERMINAL_INCOMPLETE".to_string(),
            blocking: true,
            corroboration: noop_count,
            threshold: noop_threshold,
            action: "mark_incomplete",
            failure: Value::String("terminal_incomplete".to_string()),
            recovery: "terminal",
            disposition: "terminal_incomplete_no_alternative".to_string(),
            baseline_ids: first_ids_value,
            baseline_hash: first_hash_value,
        },
    };

    // -- Tail clamp (beyond-range repeat, threshold N). --
    let terminal_ids_match = terminal_ids
        .as_ref()
        .is_some_and(|baseline| *baseline == ordered_ids);
    let terminal_hash_match = match (&terminal_digest, &page_digest) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    };
    let repeats_terminal = terminal_ids_match || terminal_hash_match;
    let has_terminal = terminal_ids.is_some() || terminal_digest.is_some();
    let tail_event =
        has_terminal && coordinate_kind == "beyond_range" && repeats_terminal;
    let tail_count = tail_count_prior.saturating_add(u64::from(tail_event));
    let terminal_ids_value =
        required_field(prev, "terminal_ordered_ids", "invalid_prior")?.clone();
    let tail = match tail_state.as_str() {
        "ADVANCING" | "SUSPECT_TAIL_CLAMP" => {
            if tail_count >= tail_threshold {
                DetectorResult {
                    detector: "tail_clamp",
                    state: "TAIL_CLAMP_CONFIRMED_TRIGGERED".to_string(),
                    blocking: true,
                    corroboration: tail_count,
                    threshold: tail_threshold,
                    action: "stop_walk",
                    failure: inapplicable_failure(),
                    recovery: if below_cap_split_available {
                        "bisect_below_cap"
                    } else {
                        "mark_incomplete"
                    },
                    disposition: "confirmed_stop_walk".to_string(),
                    baseline_ids: terminal_ids_value.clone(),
                    baseline_hash: terminal_hash_value.clone(),
                }
            } else if tail_count >= 1 {
                DetectorResult {
                    detector: "tail_clamp",
                    state: "SUSPECT_TAIL_CLAMP".to_string(),
                    blocking: false,
                    corroboration: tail_count,
                    threshold: tail_threshold,
                    action: "monitor",
                    failure: inapplicable_failure(),
                    recovery: "none",
                    disposition: "suspect_collecting_corroboration".to_string(),
                    baseline_ids: terminal_ids_value.clone(),
                    baseline_hash: terminal_hash_value.clone(),
                }
            } else {
                DetectorResult {
                    detector: "tail_clamp",
                    state: "ADVANCING".to_string(),
                    blocking: false,
                    corroboration: tail_count,
                    threshold: tail_threshold,
                    action: "monitor",
                    failure: inapplicable_failure(),
                    recovery: "none",
                    disposition: "advancing_no_clamp".to_string(),
                    baseline_ids: terminal_ids_value.clone(),
                    baseline_hash: terminal_hash_value.clone(),
                }
            }
        }
        "TAIL_CLAMP_CONFIRMED_TRIGGERED" => {
            if below_cap_split_available {
                DetectorResult {
                    detector: "tail_clamp",
                    state: "BISECTED_BELOW_CAP".to_string(),
                    blocking: true,
                    corroboration: tail_count,
                    threshold: tail_threshold,
                    action: "split",
                    failure: inapplicable_failure(),
                    recovery: "bisect_below_cap",
                    disposition: "bisected_below_cap_pending_children".to_string(),
                    baseline_ids: terminal_ids_value.clone(),
                    baseline_hash: terminal_hash_value.clone(),
                }
            } else {
                DetectorResult {
                    detector: "tail_clamp",
                    state: "TERMINAL_INCOMPLETE".to_string(),
                    blocking: true,
                    corroboration: tail_count,
                    threshold: tail_threshold,
                    action: "mark_incomplete",
                    failure: Value::String("terminal_incomplete".to_string()),
                    recovery: "terminal",
                    disposition: "terminal_incomplete_no_axis".to_string(),
                    baseline_ids: terminal_ids_value.clone(),
                    baseline_hash: terminal_hash_value.clone(),
                }
            }
        }
        "BISECTED_BELOW_CAP" => {
            if children_proven {
                DetectorResult {
                    detector: "tail_clamp",
                    state: "PROVEN_VIA_CHILDREN".to_string(),
                    blocking: false,
                    corroboration: tail_count,
                    threshold: tail_threshold,
                    action: "proven_via_children",
                    failure: inapplicable_failure(),
                    recovery: "proven_via_children",
                    disposition: "proven_via_children".to_string(),
                    baseline_ids: terminal_ids_value.clone(),
                    baseline_hash: terminal_hash_value.clone(),
                }
            } else {
                DetectorResult {
                    detector: "tail_clamp",
                    state: "BISECTED_BELOW_CAP".to_string(),
                    blocking: true,
                    corroboration: tail_count,
                    threshold: tail_threshold,
                    action: "split",
                    failure: inapplicable_failure(),
                    recovery: "bisect_below_cap",
                    disposition: "bisected_below_cap_pending_children".to_string(),
                    baseline_ids: terminal_ids_value.clone(),
                    baseline_hash: terminal_hash_value.clone(),
                }
            }
        }
        "PROVEN_VIA_CHILDREN" => DetectorResult {
            detector: "tail_clamp",
            state: "PROVEN_VIA_CHILDREN".to_string(),
            blocking: false,
            corroboration: tail_count,
            threshold: tail_threshold,
            action: "proven_via_children",
            failure: inapplicable_failure(),
            recovery: "proven_via_children",
            disposition: "proven_via_children".to_string(),
            baseline_ids: terminal_ids_value.clone(),
            baseline_hash: terminal_hash_value.clone(),
        },
        _ => DetectorResult {
            detector: "tail_clamp",
            state: "TERMINAL_INCOMPLETE".to_string(),
            blocking: true,
            corroboration: tail_count,
            threshold: tail_threshold,
            action: "mark_incomplete",
            failure: Value::String("terminal_incomplete".to_string()),
            recovery: "terminal",
            disposition: "terminal_incomplete_no_axis".to_string(),
            baseline_ids: terminal_ids_value,
            baseline_hash: terminal_hash_value,
        },
    };

    // -- Ascending overflow (ascending + pressure; regression corroborates). --
    let ascending = ordering == "ascending";
    let banner_pressure = banner_present
        && banner_text
            .as_deref()
            .is_some_and(|text| overflow_banners.iter().any(|b| b == text));
    let pressure = rowcap.blocking || saturation.blocking || banner_pressure;
    let regression = match (&prior_max_date, &newest_date) {
        (Some(prior), Some(current)) => current < prior,
        _ => false,
    };
    let ascending_result = match ascending_state.as_str() {
        "MONITORING_ASCENDING" | "DATE_REGRESSION_SUSPICION" => {
            if ascending && pressure {
                DetectorResult {
                    detector: "ascending_overflow",
                    state: "ASCENDING_OVERFLOW_TRIGGERED".to_string(),
                    blocking: true,
                    corroboration: u64::from(regression),
                    threshold: 1,
                    action: "stop_walk",
                    failure: inapplicable_failure(),
                    recovery: if split_available { "split" } else { "mark_incomplete" },
                    disposition: if regression {
                        "triggered_with_date_regression_corroboration".to_string()
                    } else {
                        "triggered_stop_walk_pending_split".to_string()
                    },
                    baseline_ids: missing("not_applicable", "ascending overflow does not compare ID sets"),
                    baseline_hash: missing("not_applicable", "ascending overflow does not compare page hashes"),
                }
            } else if ascending && regression {
                DetectorResult {
                    detector: "ascending_overflow",
                    state: "DATE_REGRESSION_SUSPICION".to_string(),
                    blocking: false,
                    corroboration: 1,
                    threshold: 1,
                    action: "monitor",
                    failure: inapplicable_failure(),
                    recovery: "none",
                    disposition: "date_regression_suspicion_only".to_string(),
                    baseline_ids: missing("not_applicable", "ascending overflow does not compare ID sets"),
                    baseline_hash: missing("not_applicable", "ascending overflow does not compare page hashes"),
                }
            } else {
                DetectorResult {
                    detector: "ascending_overflow",
                    state: if ascending_state == "DATE_REGRESSION_SUSPICION" {
                        "DATE_REGRESSION_SUSPICION".to_string()
                    } else {
                        "MONITORING_ASCENDING".to_string()
                    },
                    blocking: false,
                    corroboration: u64::from(regression),
                    threshold: 1,
                    action: "monitor",
                    failure: inapplicable_failure(),
                    recovery: "none",
                    disposition: "monitoring_ascending".to_string(),
                    baseline_ids: missing("not_applicable", "ascending overflow does not compare ID sets"),
                    baseline_hash: missing("not_applicable", "ascending overflow does not compare page hashes"),
                }
            }
        }
        "ASCENDING_OVERFLOW_TRIGGERED" => {
            if split_available {
                DetectorResult {
                    detector: "ascending_overflow",
                    state: "BISECTED".to_string(),
                    blocking: true,
                    corroboration: 1,
                    threshold: 1,
                    action: "split",
                    failure: inapplicable_failure(),
                    recovery: "split",
                    disposition: "bisected_pending_children".to_string(),
                    baseline_ids: missing("not_applicable", "ascending overflow does not compare ID sets"),
                    baseline_hash: missing("not_applicable", "ascending overflow does not compare page hashes"),
                }
            } else {
                DetectorResult {
                    detector: "ascending_overflow",
                    state: "TERMINAL_UNRECOVERABLE".to_string(),
                    blocking: true,
                    corroboration: 1,
                    threshold: 1,
                    action: "mark_incomplete",
                    failure: Value::String("ascending_overflow_unrecoverable".to_string()),
                    recovery: "terminal",
                    disposition: "terminal_unrecoverable_no_axis".to_string(),
                    baseline_ids: missing("not_applicable", "ascending overflow does not compare ID sets"),
                    baseline_hash: missing("not_applicable", "ascending overflow does not compare page hashes"),
                }
            }
        }
        "BISECTED" => {
            if children_proven {
                DetectorResult {
                    detector: "ascending_overflow",
                    state: "PROVEN_VIA_CHILDREN".to_string(),
                    blocking: false,
                    corroboration: 1,
                    threshold: 1,
                    action: "proven_via_children",
                    failure: inapplicable_failure(),
                    recovery: "proven_via_children",
                    disposition: "proven_via_children".to_string(),
                    baseline_ids: missing("not_applicable", "ascending overflow does not compare ID sets"),
                    baseline_hash: missing("not_applicable", "ascending overflow does not compare page hashes"),
                }
            } else {
                DetectorResult {
                    detector: "ascending_overflow",
                    state: "BISECTED".to_string(),
                    blocking: true,
                    corroboration: 1,
                    threshold: 1,
                    action: "split",
                    failure: inapplicable_failure(),
                    recovery: "split",
                    disposition: "bisected_pending_children".to_string(),
                    baseline_ids: missing("not_applicable", "ascending overflow does not compare ID sets"),
                    baseline_hash: missing("not_applicable", "ascending overflow does not compare page hashes"),
                }
            }
        }
        "PROVEN_VIA_CHILDREN" => DetectorResult {
            detector: "ascending_overflow",
            state: "PROVEN_VIA_CHILDREN".to_string(),
            blocking: false,
            corroboration: 1,
            threshold: 1,
            action: "proven_via_children",
            failure: inapplicable_failure(),
            recovery: "proven_via_children",
            disposition: "proven_via_children".to_string(),
            baseline_ids: missing("not_applicable", "ascending overflow does not compare ID sets"),
            baseline_hash: missing("not_applicable", "ascending overflow does not compare page hashes"),
        },
        _ => DetectorResult {
            detector: "ascending_overflow",
            state: "TERMINAL_UNRECOVERABLE".to_string(),
            blocking: true,
            corroboration: 1,
            threshold: 1,
            action: "mark_incomplete",
            failure: Value::String("ascending_overflow_unrecoverable".to_string()),
            recovery: "terminal",
            disposition: "terminal_unrecoverable_no_axis".to_string(),
            baseline_ids: missing("not_applicable", "ascending overflow does not compare ID sets"),
            baseline_hash: missing("not_applicable", "ascending overflow does not compare page hashes"),
        },
    };

    // Per-detector audit snapshots: nothing is suppressed when a sibling or a
    // rendering stage succeeds; every detector carries its own support.
    let detectors = [
        rowcap,
        saturation,
        noop,
        tail,
        ascending_result,
    ];
    let mut evaluations = Vec::with_capacity(5);
    let mut any_blocking = false;
    for result in &detectors {
        any_blocking = any_blocking || result.blocking;
        let event_id = format!("det-{}-seq-{request_sequence}", result.detector);
        let support = audit_snapshot(
            &evidence,
            scope.get("target").and_then(Value::as_str).unwrap_or(""),
            &owner_domain,
            event_id,
            vec![
                ("detector", Value::String(result.detector.to_string())),
                ("detector_state", Value::String(result.state.clone())),
                ("detector_action", Value::String(result.action.to_string())),
                (
                    "detector_blocking",
                    Value::Bool(result.blocking),
                ),
                (
                    "detector_disposition",
                    Value::String(result.disposition.clone()),
                ),
                (
                    "request_sequence",
                    Value::Number(request_sequence.into()),
                ),
                (
                    "response_identity",
                    Value::String(response_identity.clone()),
                ),
            ],
        )?;
        evaluations.push(detector_value(
            result,
            &evidence_refs,
            &detection_boundary,
            &scope,
            &response_identity,
            &request_coordinate,
            &count_evidence,
            &ordered_ids,
            &page_hash_value,
            &response_hash_value,
            support,
        ));
    }

    let output = json!({
        "record_type": "detector_evaluation",
        "schema_version": SCHEMA_VERSION,
        "target": scope.get("target").clone(),
        "run_id": scope.get("run_id").clone(),
        "partition_id": scope.get("partition_id").clone(),
        "request_sequence": request_sequence,
        "state_domain": "diagnostic",
        "ledger_status": missing("not_applicable", "detector diagnostic states do not advance ledger status"),
        "detectors": evaluations,
        "blocking": any_blocking,
        "evidence_prefix": evidence_prefix,
        "evidence_refs": evidence_refs,
    });
    validate(OUTPUT_SCHEMA, output)
}

// ---------------------------------------------------------------------------
// Drift evaluation
// ---------------------------------------------------------------------------

fn validate_audit_event_ref(value: &Value) -> Result<(), Fault> {
    let map = value.as_object().ok_or_else(|| {
        fault(
            "invalid_observations",
            "observations.audit_event_ref must be an established EvidenceRef object",
        )
    })?;
    for key in ["journal_id", "event_id", "event_hash", "pointer"] {
        let text = map.get(key).and_then(Value::as_str).ok_or_else(|| {
            fault(
                "invalid_observations",
                format!("observations.audit_event_ref.{key} must be a string"),
            )
        })?;
        if key != "pointer" && text.is_empty() {
            return Err(fault(
                "invalid_observations",
                format!("observations.audit_event_ref.{key} must be nonempty"),
            ));
        }
    }
    let sequence = map
        .get("sequence")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            fault(
                "invalid_observations",
                "observations.audit_event_ref.sequence must be a positive integer",
            )
        })?;
    if sequence == 0 {
        return Err(fault(
            "invalid_observations",
            "observations.audit_event_ref.sequence must be positive",
        ));
    }
    Ok(())
}

fn validate_session_epoch(value: &Value) -> Result<(), Fault> {
    if is_missing(value) {
        return Ok(());
    }
    match value {
        Value::Number(n) if n.is_i64() || n.is_u64() => Ok(()),
        Value::String(s) if !s.is_empty() => Ok(()),
        _ => Err(fault(
            "invalid_observations",
            "observations.session_epoch must be an integer-or-string SID or Missing",
        )),
    }
}

/// Evaluate duplicate-rate drift for one observation batch.
///
/// The duplicate rate is repeated-distinct IDs divided by distinct IDs (zero
/// when distinct is zero); repeating one ID many times contributes a single
/// numerator unit. Bands use the effective baseline
/// `max(baseline_dup_rate, 0.001)`: low at or below 1.5x, medium up to 3x,
/// high above. Backend changes open a separate cohort without averaging.
/// Dates are compared only under the same partition-definition hash.
/// Reconciliation is bounded to three total passes.
pub fn evaluate_drift(
    declaration: &CheckedRecord,
    observations: &CheckedRecord,
    prior_ledger: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let decl = require_object(declaration, "invalid_declaration", "declaration")?;
    let obs = require_object(observations, "invalid_observations", "observations")?;
    let prior = require_object(prior_ledger, "invalid_ledger", "prior_ledger")?;

    let target = required_str(decl, "target", "invalid_declaration")?.to_string();
    let run_id = required_str(decl, "run_id", "invalid_declaration")?.to_string();
    let partition_id = required_str(decl, "partition_id", "invalid_declaration")?.to_string();
    let owner_domain = required_str(decl, "owner_domain", "invalid_declaration")?.to_string();
    let evidence_refs = required_field(decl, "evidence_refs", "missing_evidence")?.clone();
    let evidence_prefix = required_field(decl, "evidence_prefix", "missing_evidence")?.clone();
    let baseline = required_f64(decl, "baseline_dup_rate", "invalid_declaration")?;
    if !(0.0..=1.0).contains(&baseline) {
        return Err(fault(
            "invalid_baseline",
            format!("declaration.baseline_dup_rate {baseline} must be within [0,1]"),
        ));
    }
    let factor = required_f64(decl, "planned_over_fetch_factor", "invalid_declaration")?;
    if factor < 1.0 {
        return Err(fault(
            "invalid_factor",
            format!("declaration.planned_over_fetch_factor {factor} must be at least 1"),
        ));
    }
    let limit = required_u64(decl, "reconciliation_limit", "invalid_declaration")?;
    if limit > 3 {
        return Err(fault(
            "invalid_limit",
            format!("declaration.reconciliation_limit {limit} exceeds the bound of three passes"),
        ));
    }
    let evidence = normalize_evidence(decl)?;

    // Observations.
    let distinct = required_u64(obs, "distinct_total", "invalid_observations")?;
    let repeated = required_u64(obs, "repeated_distinct_total", "invalid_observations")?;
    if repeated > distinct {
        return Err(fault(
            "invalid_counts",
            format!("repeated_distinct_total {repeated} cannot exceed distinct_total {distinct}"),
        ));
    }
    let occurrences = required_array(obs, "exact_occurrences", "invalid_observations")?;
    if distinct == 0 {
        if !occurrences.is_empty() {
            return Err(fault(
                "invalid_counts",
                "exact_occurrences must be empty when distinct_total is zero",
            ));
        }
        if repeated != 0 {
            return Err(fault(
                "invalid_counts",
                "repeated_distinct_total must be zero when distinct_total is zero",
            ));
        }
    }
    let mut repeated_computed: u64 = 0;
    for (i, entry) in occurrences.iter().enumerate() {
        let map = entry.as_object().ok_or_else(|| {
            fault(
                "invalid_observations",
                format!("exact_occurrences[{i}] must be an object"),
            )
        })?;
        for key in ["target", "run_id", "partition_id", "walk_id", "job_id"] {
            let text = map.get(key).and_then(Value::as_str).ok_or_else(|| {
                fault(
                    "invalid_observations",
                    format!("exact_occurrences[{i}].{key} must be a nonempty string"),
                )
            })?;
            if text.is_empty() {
                return Err(fault(
                    "invalid_observations",
                    format!("exact_occurrences[{i}].{key} must be nonempty"),
                ));
            }
        }
        let count = map
            .get("occurrence_count")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                fault(
                    "invalid_observations",
                    format!("exact_occurrences[{i}].occurrence_count must be POS"),
                )
            })?;
        if count == 0 {
            return Err(fault(
                "invalid_observations",
                format!("exact_occurrences[{i}].occurrence_count must be POS"),
            ));
        }
        // One repeated-distinct unit per ID occurring more than once,
        // regardless of how many times it repeats.
        if count > 1 {
            repeated_computed = repeated_computed.saturating_add(1);
        }
    }
    // Nonempty occurrence lists must agree with the claimed numerator; total
    // duplicate occurrences are never substituted for repeated-distinct units.
    if !occurrences.is_empty() && repeated_computed != repeated {
        return Err(fault(
            "duplicate_arithmetic_mismatch",
            format!(
                "exact_occurrences imply {repeated_computed} repeated-distinct IDs but repeated_distinct_total is {repeated}; one ID repeated many times contributes one unit"
            ),
        ));
    }
    let backend_current = required_field(obs, "backend_signature", "invalid_observations")?.clone();
    if !is_missing(&backend_current)
        && backend_current
            .as_str()
            .filter(|s| !s.is_empty())
            .is_none()
    {
        return Err(fault(
            "invalid_observations",
            "observations.backend_signature must be a nonempty ID or Missing",
        ));
    }
    let session_epoch = required_field(obs, "session_epoch", "invalid_observations")?.clone();
    validate_session_epoch(&session_epoch)?;
    let current_page_hash = required_field(obs, "current_page_hash", "invalid_observations")?.clone();
    let current_page_bytes = m_bytes(obs, "current_page_bytes", "invalid_observations")?;
    let _ = reconcile_sh_opt(&current_page_hash, current_page_bytes, "observations.current_page_hash")?;
    let obs_partition_hash =
        required_field(obs, "partition_definition_hash", "invalid_observations")?.clone();
    let obs_partition_digest = parse_sh(&obs_partition_hash, "observations.partition_definition_hash")?
        .map(|s| s.digest);
    let obs_max_date = optional_date(obs, "max_date_posted", "invalid_observations")?
        .map(str::to_string);
    let missing_dates = required_u64(obs, "missing_posted_date_total", "invalid_observations")?;
    let min_job = required_field(obs, "min_job_id", "invalid_observations")?.clone();
    if !is_missing(&min_job) && min_job.as_str().filter(|s| !s.is_empty()).is_none() {
        return Err(fault(
            "invalid_observations",
            "observations.min_job_id must be a nonempty ID or Missing",
        ));
    }
    let max_job = required_field(obs, "max_job_id", "invalid_observations")?.clone();
    if !is_missing(&max_job) && max_job.as_str().filter(|s| !s.is_empty()).is_none() {
        return Err(fault(
            "invalid_observations",
            "observations.max_job_id must be a nonempty ID or Missing",
        ));
    }
    let cursor_revision = required_u64(obs, "cursor_revision", "invalid_observations")?;
    let detected_at = required_field(obs, "detected_at", "invalid_observations")?.clone();
    if !is_missing(&detected_at) && !detected_at.is_object() {
        return Err(fault(
            "invalid_observations",
            "observations.detected_at must be a TimePoint or Missing",
        ));
    }
    let audit_event_ref = required_field(obs, "audit_event_ref", "invalid_observations")?.clone();
    validate_audit_event_ref(&audit_event_ref)?;

    // Prior ledger cohort baseline.
    let backend_prior = required_field(prior, "backend_signature", "invalid_ledger")?.clone();
    if !is_missing(&backend_prior)
        && backend_prior
            .as_str()
            .filter(|s| !s.is_empty())
            .is_none()
    {
        return Err(fault(
            "invalid_ledger",
            "prior_ledger.backend_signature must be a nonempty ID or Missing",
        ));
    }
    let prior_partition_hash =
        required_field(prior, "partition_definition_hash", "invalid_ledger")?.clone();
    let prior_partition_digest =
        parse_sh(&prior_partition_hash, "prior_ledger.partition_definition_hash")?
            .map(|s| s.digest);
    let prior_max_date = optional_date(prior, "max_date_posted", "invalid_ledger")?
        .map(str::to_string);
    let prior_distinct = required_u64(prior, "distinct_total", "invalid_ledger")?;
    let prior_repeated = required_u64(prior, "repeated_distinct_total", "invalid_ledger")?;
    if prior_repeated > prior_distinct {
        return Err(fault(
            "invalid_ledger",
            "prior repeated_distinct_total cannot exceed prior distinct_total",
        ));
    }
    let prior_page_hash = required_field(prior, "current_page_hash", "invalid_ledger")?.clone();
    let _ = parse_sh(&prior_page_hash, "prior_ledger.current_page_hash")?;
    let passes_used = required_u64(prior, "reconciliation_passes_used", "invalid_ledger")?;
    if passes_used > 3 {
        return Err(fault(
            "invalid_ledger",
            format!("prior reconciliation_passes_used {passes_used} already exceeds the bound of three"),
        ));
    }
    let _prior_revision = required_u64(prior, "cursor_revision", "invalid_ledger")?;

    // Rate and band.
    let effective = baseline.max(0.001);
    let rate = if distinct == 0 {
        0.0
    } else {
        (repeated as f64) / (distinct as f64)
    };
    if !rate.is_finite() || !(0.0..=1.0).contains(&rate) {
        return Err(fault(
            "invalid_counts",
            format!("computed duplicate_rate {rate} is outside [0,1]"),
        ));
    }
    let band = if rate <= 1.5 * effective {
        "low"
    } else if rate <= 3.0 * effective {
        "medium"
    } else {
        "high"
    };
    let base_passes: u64 = match band {
        "low" => 1,
        "medium" => 2,
        _ => 3,
    };
    let remaining = 3u64.saturating_sub(passes_used.min(3));
    let passes = base_passes.min(limit).min(remaining);
    let total = passes_used.saturating_add(passes).min(3);
    let trusted = band != "high";

    // Backend cohorts: established changes open a separate cohort; totals are
    // never averaged across cohorts.
    let prior_established = !is_missing(&backend_prior);
    let current_established = !is_missing(&backend_current);
    let split = prior_established
        && current_established
        && backend_prior != backend_current;
    let prior_rate = if prior_distinct == 0 {
        0.0
    } else {
        (prior_repeated as f64) / (prior_distinct as f64)
    };
    let cohorts = if split {
        vec![
            json!({
                "backend_signature": backend_prior.clone(),
                "distinct_total": prior_distinct,
                "repeated_distinct_total": prior_repeated,
                "duplicate_rate": prior_rate,
                "cohort": "prior",
            }),
            json!({
                "backend_signature": backend_current.clone(),
                "distinct_total": distinct,
                "repeated_distinct_total": repeated,
                "duplicate_rate": rate,
                "cohort": "current",
            }),
        ]
    } else {
        vec![json!({
            "backend_signature": backend_current.clone(),
            "distinct_total": distinct,
            "repeated_distinct_total": repeated,
            "duplicate_rate": rate,
            "cohort": "current",
        })]
    };

    // Date regression under the same partition-definition hash only.
    let (applicable, regressed, reason) = match (&prior_partition_digest, &obs_partition_digest) {
        (Some(a), Some(b)) if a == b => match (&prior_max_date, &obs_max_date) {
            (Some(prior), Some(current)) => {
                if current < prior {
                    (true, true, "same partition hash; current max date precedes prior max date")
                } else {
                    (true, false, "same partition hash; no regression")
                }
            }
            _ => (true, false, "same partition hash; date missing on at least one side"),
        },
        (Some(_), Some(_)) => (
            false,
            false,
            "partition definition changed; dates are not comparable across predicates",
        ),
        _ => (
            false,
            false,
            "partition hash missing; date comparison inapplicable",
        ),
    };
    let date_regression = json!({
        "applicable": applicable,
        "regressed": regressed,
        "reason": reason,
        "missing_posted_date_total": missing_dates,
        "min_job_id": min_job.clone(),
        "max_job_id": max_job.clone(),
        "prior_max_date": required_field(prior, "max_date_posted", "invalid_ledger")?.clone(),
        "current_max_date": required_field(obs, "max_date_posted", "invalid_observations")?.clone(),
    });

    // Drift entry per §11.3. A missing prior hash at the inapplicable
    // boundary stays inapplicable; missing expected evidence stays
    // not_observed/observation_lost as supplied by the caller.
    let action = match band {
        "low" => "monitor",
        "medium" => "reconcile",
        _ => "invalidate_cursor_trust",
    };
    let drift_entry = json!({
        "detected_at": detected_at,
        "kind": "duplicate_rate_drift",
        "severity": band,
        "duplicate_rate": rate,
        "baseline": effective,
        "previous_page_hash": prior_page_hash,
        "current_page_hash": current_page_hash,
        "cursor_revision": cursor_revision,
        "session_epoch": session_epoch,
        "backend_signature": backend_current,
        "action": action,
        "audit_event_ref": audit_event_ref,
    });

    let support = audit_snapshot(
        &evidence,
        &target,
        &owner_domain,
        format!("drift-rev-{cursor_revision}"),
        vec![
            ("evaluation", Value::String("drift".to_string())),
            ("band", Value::String(band.to_string())),
            (
                "duplicate_rate",
                Value::Number(
                    serde_json::Number::from_f64(rate).unwrap_or_else(|| 0.into()),
                ),
            ),
            (
                "cursor_trusted",
                Value::Bool(trusted),
            ),
            (
                "cursor_revision",
                Value::Number(cursor_revision.into()),
            ),
        ],
    )?;

    let output = json!({
        "record_type": "drift_evaluation",
        "schema_version": SCHEMA_VERSION,
        "target": target,
        "run_id": run_id,
        "partition_id": partition_id,
        "baseline_dup_rate": baseline,
        "effective_baseline": effective,
        "duplicate_rate": rate,
        "band": band,
        "planned_over_fetch_factor": factor,
        "over_fetch_is_proof": false,
        "reconciliation_passes": passes,
        "reconciliation_total": total,
        "reconciliation_bound": 3,
        "cursor_trusted_for_proof": trusted,
        "cohorts": cohorts,
        "totals_averaged": false,
        "date_regression": date_regression,
        "drift_entries": [drift_entry],
        "evidence_prefix": evidence_prefix,
        "evidence_refs": evidence_refs,
        "audit_support": support,
    });
    validate(OUTPUT_SCHEMA, output)
}

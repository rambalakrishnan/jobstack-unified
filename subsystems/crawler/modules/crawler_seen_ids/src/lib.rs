//! `crawler_seen_ids`: exact successful-detail membership (C18).
//!
//! Implements §15 (Seen-ID Schema and Exact Membership) over the owner-local
//! journal seam:
//!
//! * Membership holds only for details **currently** `ready`/`vetoed` at the
//!   matching successful revision. It excludes snippet-only vetoes, observed
//!   listings, pending classification, render failure, and operational
//!   failure.
//! * Exit from the eligible state removes/invalidates membership atomically.
//!   Successful recompletion reinstates it.
//! * Approximate lookup may accelerate definite misses. Possible hits always
//!   require exact confirmation through [`OwnerStore::read`]. A hit suppresses
//!   downstream work only where configured, never coverage evidence.
//!
//! # Interface
//!
//! * [`exact_success`] answers whether one candidate
//!   `(target, job_id, fetch_key, detail_revision)` is an exact eligible
//!   member. Definitionally ineligible candidates (listings, snippet-only
//!   vetoes, non-`Pass` renders, non-ready/vetoed states) and approximate
//!   definite misses return `miss` without a store read. Every other candidate
//!   is confirmed by reading the owner journal (`query: "journal"`) and
//!   comparing against the latest journaled detail for that root. Store faults
//!   propagate; no hit is invented. This function only reads: it never calls
//!   [`OwnerStore::transact`].
//! * [`plan_seen_transition`] is a pure planner. Given the detail row before
//!   and after one fenced transition, it emits the atomic seen effect
//!   (`insert`/`reinstate`/`update`/`remove`/`invalidate`/`noop`) together with
//!   the complete `seen_ids` row when the `after` state is eligible. The plan
//!   carries `requires_atomic_commit: true` and the fenced revision it must
//!   commit with; this module never commits membership outside that fenced
//!   state transaction.
//!
//! All records produced here validate through the closed `crawler_schema` gate
//! under `audit_log` (with the embedded `seen_ids` row additionally validated
//! under `seen_ids`). Absent fields use typed `Missing` envelopes, never bare
//! JSON nulls.

use crawler_authority::Grant;
use crawler_schema::{record_value, validate, CheckedRecord, Fault};
use crawler_store::OwnerStore;
use serde_json::{json, Map, Value};

/// Structural envelope for records produced by this module.
const OUTPUT_SCHEMA: &str = "audit_log";
/// Schema id for the embedded seen row.
const SEEN_SCHEMA: &str = "seen_ids";

/// Detail states that may hold seen membership (§16.1).
const ELIGIBLE_STATES: &[&str] = &["ready", "vetoed"];
/// Closed detail vocabulary (§16.1). Unknown values are rejected.
const DETAIL_STATES: &[&str] = &[
    "pending_classification",
    "ready",
    "vetoed",
    "render_failed",
    "failed",
];
/// The only render verdict compatible with membership (Case A, §9.2).
const RENDER_PASS: &str = "Pass";
/// Veto scopes that mark a snippet-only veto (never a detail member).
const SNIPPET_SCOPES: &[&str] = &[
    "snippet",
    "snippet_only",
    "snippet-only",
    "snippet_veto",
    "snippet_only_veto",
];
/// Candidate kinds that are never detail members.
const NON_DETAIL_KINDS: &[&str] = &[
    "listing",
    "observed_listing",
    "snippet",
    "snippet_only",
    "snippet_veto",
    "snippet_only_veto",
];
/// Registered `TimePoint` origins (§3.4).
const TIME_ORIGINS: &[&str] = &[
    "engine_measured",
    "browser_measured",
    "subject_reported",
    "manual_reference",
];

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

fn fault(code: &str, detail: impl Into<String>) -> Fault {
    Fault {
        code: code.to_string(),
        detail: detail.into(),
    }
}

/// Typed `Missing` envelope; no bare JSON null ever leaves this module.
///
/// The closed envelope spells the optional field `detail` (lowercase).
fn missing(reason: &str, detail: &str) -> Value {
    json!({"value": Value::Null, "reason": reason, "detail": detail})
}

/// True when `value` is a schema-gate `Missing` envelope.
fn is_missing(value: &Value) -> bool {
    value.get("value").is_some_and(Value::is_null)
}

fn established<'a>(map: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    map.get(key).filter(|value| !is_missing(value))
}

fn as_object<'a>(record: &'a CheckedRecord, what: &str) -> Result<&'a Map<String, Value>, Fault> {
    record_value(record).as_object().ok_or_else(|| {
        fault(
            "invalid_query",
            format!("{what} must be an object"),
        )
    })
}

fn required_id<'a>(
    map: &'a Map<String, Value>,
    key: &str,
    code: &str,
    what: &str,
) -> Result<&'a str, Fault> {
    match established(map, key) {
        Some(Value::String(text)) if !text.is_empty() => Ok(text.as_str()),
        Some(Value::String(_)) => Err(fault(code, format!("{what} field {key:?} must be a nonempty string"))),
        Some(_) => Err(fault(code, format!("{what} field {key:?} must be a string"))),
        None => Err(fault(code, format!("{what} is missing required field {key:?}"))),
    }
}

fn optional_text<'a>(map: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    match established(map, key) {
        Some(Value::String(text)) if !text.is_empty() => Some(text.as_str()),
        _ => None,
    }
}

/// First established u64 under any of `keys`, or `None` when absent/Missing.
fn first_u64(map: &Map<String, Value>, keys: &[&str]) -> Option<u64> {
    for key in keys {
        if let Some(Value::Number(number)) = established(map, key) {
            if let Some(value) = number.as_u64() {
                return Some(value);
            }
        }
    }
    None
}

/// First established nonempty text under any of `keys`.
fn first_text<'a>(map: &'a Map<String, Value>, keys: &[&str]) -> Option<&'a str> {
    for key in keys {
        if let Some(Value::String(text)) = established(map, key) {
            if !text.is_empty() {
                return Some(text.as_str());
            }
        }
    }
    None
}

/// Validate a closed `SH` object (`{value, profile, evidence_refs}`, §3.6) and
/// return its preserved source digest text.
fn parse_sh_value<'a>(value: &'a Value, what: &str) -> Result<&'a str, Fault> {
    if is_missing(value) {
        return Err(fault(
            "invalid_fetch_key",
            format!("{what} fetch key must be an established SH object, not Missing"),
        ));
    }
    let map = value.as_object().ok_or_else(|| {
        fault(
            "invalid_fetch_key",
            format!("{what} fetch key must be an SH object with value/profile/evidence_refs"),
        )
    })?;
    match map.get("value") {
        Some(Value::String(text)) if !text.is_empty() => {},
        _ => {
            return Err(fault(
                "invalid_fetch_key",
                format!("{what} fetch key value must be a nonempty source digest string"),
            ));
        }
    }
    if !map.contains_key("profile") {
        return Err(fault(
            "invalid_fetch_key",
            format!("{what} fetch key is missing required field \"profile\""),
        ));
    }
    match map.get("evidence_refs") {
        Some(Value::Array(_)) => {},
        _ => {
            return Err(fault(
                "invalid_fetch_key",
                format!("{what} fetch key evidence_refs must be an array"),
            ));
        }
    }
    Ok(map.get("value").and_then(Value::as_str).unwrap_or_default())
}

/// Validate `M(TP)`: either a `Missing` envelope or a complete `TimePoint`.
fn require_maybe_timepoint(value: &Value, field: &str) -> Result<Value, Fault> {
    if is_missing(value) {
        return Ok(value.clone());
    }
    let map = value.as_object().ok_or_else(|| {
        fault(
            "invalid_timestamp",
            format!("field {field:?} must be a TimePoint object or Missing"),
        )
    })?;
    for key in ["clock_id", "boot_id"] {
        match map.get(key) {
            Some(Value::String(text)) if !text.is_empty() => {},
            _ => {
                return Err(fault(
                    "invalid_timestamp",
                    format!("field {field:?} TimePoint is missing nonempty {key:?}"),
                ));
            }
        }
    }
    match map.get("origin").and_then(Value::as_str) {
        Some(origin) if TIME_ORIGINS.contains(&origin) => {},
        _ => {
            return Err(fault(
                "invalid_timestamp",
                format!("field {field:?} TimePoint origin must be one of {TIME_ORIGINS:?}"),
            ));
        }
    }
    match map.get("monotonic_offset_ms").and_then(Value::as_f64) {
        Some(offset) if offset.is_finite() && offset >= 0.0 => {},
        _ => {
            return Err(fault(
                "invalid_timestamp",
                format!("field {field:?} TimePoint monotonic_offset_ms must be a finite nonnegative number"),
            ));
        }
    }
    if !map.contains_key("utc_annotation") {
        return Err(fault(
            "invalid_timestamp",
            format!("field {field:?} TimePoint is missing utc_annotation"),
        ));
    }
    Ok(value.clone())
}

fn missing_or_default(map: &Map<String, Value>, key: &str) -> Value {
    match map.get(key) {
        Some(value) => value.clone(),
        None => missing("not_observed", &format!("{key} was not observed")),
    }
}

fn is_snippet_scope(scope: Option<&str>) -> bool {
    scope.is_some_and(|text| SNIPPET_SCOPES.contains(&text))
}

fn is_non_detail_kind(kind: Option<&str>) -> bool {
    kind.is_some_and(|text| NON_DETAIL_KINDS.contains(&text))
}

// ---------------------------------------------------------------------------
// Detail facts
// ---------------------------------------------------------------------------

/// A normalized detail row parsed for membership purposes.
struct DetailFacts {
    target: String,
    job_id: String,
    fetch_key_value: String,
    fetch_key_raw: Value,
    pipeline_state: String,
    revision: u64,
    run_id: String,
    render_verdict: Option<String>,
    entity_type: Option<String>,
    candidate_kind: Option<String>,
    veto_scope: Option<String>,
    created_at: Value,
    updated_at: Value,
}

fn parse_detail(record: &CheckedRecord, what: &str) -> Result<DetailFacts, Fault> {
    let map = record_value(record).as_object().ok_or_else(|| {
        fault(
            "invalid_detail",
            format!("{what} must be an object holding a normalized detail row"),
        )
    })?;
    let target = required_id(map, "target", "missing_target", what)?.to_string();
    let job_id = required_id(map, "job_id", "missing_job", what)?.to_string();

    let fetch_key_raw = established(map, "fetch_key")
        .or_else(|| established(map, "completed_fetch_key"))
        .cloned()
        .ok_or_else(|| {
            fault(
                "invalid_fetch_key",
                format!("{what} is missing required field \"fetch_key\""),
            )
        })?;
    let fetch_key_value = parse_sh_value(&fetch_key_raw, what)?.to_string();

    let pipeline_state = match established(map, "pipeline_state")
        .or_else(|| established(map, "completed_pipeline_state"))
    {
        Some(Value::String(text)) if !text.is_empty() => text.clone(),
        Some(_) => {
            return Err(fault(
                "invalid_detail",
                format!("{what} pipeline_state must be a nonempty string"),
            ))
        },
        None => {
            return Err(fault(
                "invalid_detail",
                format!("{what} is missing required field \"pipeline_state\""),
            ))
        }
    };
    if !DETAIL_STATES.contains(&pipeline_state.as_str()) {
        return Err(fault(
            "unknown_pipeline_state",
            format!(
                "{what} pipeline_state {pipeline_state:?} is not one of {DETAIL_STATES:?}"
            ),
        ));
    }

    let revision = first_u64(
        map,
        &[
            "entity_revision",
            "detail_revision",
            "completed_detail_revision",
        ],
    )
    .ok_or_else(|| {
        fault(
            "missing_revision",
            format!("{what} is missing required integer revision (entity_revision/detail_revision)"),
        )
    })?;

    let run_id = first_text(map, &["active_run_id", "completed_run_id", "run_id"])
        .ok_or_else(|| {
            fault(
                "missing_run",
                format!("{what} is missing required run identity (active_run_id/completed_run_id/run_id)"),
            )
        })?
        .to_string();

    let render_verdict = optional_text(map, "render_verdict").map(str::to_string);
    let entity_type = optional_text(map, "entity_type").map(str::to_string);
    let candidate_kind = first_text(map, &["candidate_kind", "kind"]).map(str::to_string);
    let veto_scope = optional_text(map, "veto_scope").map(str::to_string);

    let created_at = require_maybe_timepoint(&missing_or_default(map, "created_at"), "created_at")?;
    let updated_at = require_maybe_timepoint(&missing_or_default(map, "updated_at"), "updated_at")?;

    Ok(DetailFacts {
        target,
        job_id,
        fetch_key_value,
        fetch_key_raw,
        pipeline_state,
        revision,
        run_id,
        render_verdict,
        entity_type,
        candidate_kind,
        veto_scope,
        created_at,
        updated_at,
    })
}

/// Exact eligibility: currently ready/vetoed detail with a `Pass` render, and
/// never a listing or snippet-only veto.
fn detail_eligible(facts: &DetailFacts) -> bool {
    if facts.entity_type.as_deref() == Some("listing") {
        return false;
    }
    if is_non_detail_kind(facts.candidate_kind.as_deref()) {
        return false;
    }
    if !ELIGIBLE_STATES.contains(&facts.pipeline_state.as_str()) {
        return false;
    }
    if let Some(verdict) = facts.render_verdict.as_deref() {
        if verdict != RENDER_PASS {
            return false;
        }
    }
    if facts.pipeline_state == "vetoed" && is_snippet_scope(facts.veto_scope.as_deref()) {
        return false;
    }
    true
}

// ---------------------------------------------------------------------------
// plan_seen_transition
// ---------------------------------------------------------------------------

/// Plan the atomic seen-ids effect for one fenced detail transition.
///
/// `before` and `after` are the complete normalized detail rows on either side
/// of the transition. The returned `audit_log` envelope names the effect:
///
/// * `insert`: ineligible → eligible under a new fetch key.
/// * `reinstate`: ineligible → eligible under the same fetch key (successful
///   recompletion after an exit).
/// * `update`: eligible → eligible with a changed key, revision, state, or run.
/// * `noop`: eligibility and identity unchanged, or ineligible on both sides.
/// * `invalidate`: eligible → pending (reversible exit).
/// * `remove`: eligible → terminal ineligible state (failed, render_failed, or
///   snippet-only veto).
///
/// When `after` is eligible the plan embeds the complete `seen_ids` row;
/// otherwise `seen_row` is `Missing(not_applicable)`. The plan always carries
/// `requires_atomic_commit: true` with the fenced revision it must commit
/// with, and `coverage.suppressed: false`: membership work never suppresses
/// coverage evidence.
///
/// Faults: `invalid_detail`, `identity_mismatch`, `unknown_pipeline_state`,
/// `invalid_fetch_key`, `missing_revision`, `missing_run`,
/// `invalid_timestamp`, `incomplete_extraction`.
pub fn plan_seen_transition(
    before: &CheckedRecord,
    after: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let before_facts = parse_detail(before, "before")?;
    let after_facts = parse_detail(after, "after")?;

    if before_facts.target != after_facts.target || before_facts.job_id != after_facts.job_id {
        return Err(fault(
            "identity_mismatch",
            format!(
                "before ({}/{}) and after ({}/{}) name different roots; one plan covers one root",
                before_facts.target,
                before_facts.job_id,
                after_facts.target,
                after_facts.job_id,
            ),
        ));
    }

    let before_eligible = detail_eligible(&before_facts);
    let after_eligible = detail_eligible(&after_facts);

    // An eligible `after` must carry every required seen field; a Pass with
    // missing required content is incomplete_extraction, never a member.
    if after_eligible {
        if after_facts.fetch_key_value.is_empty()
            || after_facts.pipeline_state.is_empty()
            || after_facts.run_id.is_empty()
        {
            return Err(fault(
                "incomplete_extraction",
                "eligible after row is missing required seen identity (fetch key, state, or run)".to_string(),
            ));
        }
    }

    let effect = match (before_eligible, after_eligible) {
        (false, false) => "noop",
        (false, true) => {
            if before_facts.fetch_key_value == after_facts.fetch_key_value {
                "reinstate"
            } else {
                "insert"
            }
        }
        (true, true) => {
            if before_facts.fetch_key_value == after_facts.fetch_key_value
                && before_facts.revision == after_facts.revision
                && before_facts.pipeline_state == after_facts.pipeline_state
                && before_facts.run_id == after_facts.run_id
            {
                "noop"
            } else {
                "update"
            }
        }
        (true, false) => {
            if after_facts.pipeline_state == "pending_classification" {
                "invalidate"
            } else {
                "remove"
            }
        }
    };

    let seen_row = if after_eligible {
        let row = json!({
            "target": after_facts.target,
            "job_id": after_facts.job_id,
            "completed_fetch_key": after_facts.fetch_key_raw,
            "completed_pipeline_state": after_facts.pipeline_state,
            "completed_detail_revision": after_facts.revision,
            "first_completed_at": after_facts.created_at,
            "last_completed_at": after_facts.updated_at,
            "completed_run_id": after_facts.run_id,
        });
        // The gate enforces the Missing discipline on the embedded row.
        let checked = validate(SEEN_SCHEMA, row)?;
        record_value(&checked).clone()
    } else {
        missing(
            "not_applicable",
            "no eligible membership; after state holds no successful detail",
        )
    };

    let output = json!({
        "record_type": "seen_transition_plan",
        "target": after_facts.target,
        "job_id": after_facts.job_id,
        "before": {
            "pipeline_state": before_facts.pipeline_state,
            "fetch_key_value": before_facts.fetch_key_value,
            "detail_revision": before_facts.revision,
            "eligible": before_eligible,
        },
        "after": {
            "pipeline_state": after_facts.pipeline_state,
            "fetch_key_value": after_facts.fetch_key_value,
            "detail_revision": after_facts.revision,
            "eligible": after_eligible,
        },
        "before_eligible": before_eligible,
        "after_eligible": after_eligible,
        "effect": effect,
        "seen_row": seen_row,
        "commit": {
            "requires_atomic_commit": true,
            "fenced_entity_revision": after_facts.revision,
            "fenced_fetch_key": after_facts.fetch_key_value,
            "fenced_pipeline_state": after_facts.pipeline_state,
            "invalidates_prior": before_eligible && !after_eligible,
        },
        "coverage": {
            "observe_required": true,
            "suppressed": false,
        },
        "limitations": [],
    });
    validate(OUTPUT_SCHEMA, output)
}

// ---------------------------------------------------------------------------
// exact_success
// ---------------------------------------------------------------------------

/// A parsed exact-membership query.
struct ExactQuery {
    target: String,
    job_id: String,
    fetch_key_value: String,
    detail_revision: u64,
    pipeline_state: Option<String>,
    render_verdict: Option<String>,
    entity_type: Option<String>,
    candidate_kind: Option<String>,
    veto_scope: Option<String>,
    journal_id: String,
    approximate_decision: Option<String>,
    approximate_raw: Value,
    suppress_when_hit: bool,
}

fn parse_exact_query(root: &CheckedRecord) -> Result<ExactQuery, Fault> {
    let map = as_object(root, "root")?;
    let what = "root";
    let target = required_id(map, "target", "missing_target", what)?.to_string();
    let job_id = required_id(map, "job_id", "missing_job", what)?.to_string();

    let fetch_key_raw = established(map, "fetch_key")
        .or_else(|| established(map, "candidate_fetch_key"))
        .or_else(|| established(map, "completed_fetch_key"))
        .cloned()
        .ok_or_else(|| {
            fault(
                "invalid_fetch_key",
                "root is missing required field \"fetch_key\" (or candidate_fetch_key)".to_string(),
            )
        })?;
    let fetch_key_value = parse_sh_value(&fetch_key_raw, what)?.to_string();

    let detail_revision = first_u64(
        map,
        &[
            "detail_revision",
            "candidate_detail_revision",
            "completed_detail_revision",
            "entity_revision",
        ],
    )
    .ok_or_else(|| {
        fault(
            "missing_revision",
            "root is missing required integer revision (detail_revision/candidate_detail_revision)".to_string(),
        )
    })?;

    let journal_id = required_id(map, "journal_id", "missing_journal", what)?.to_string();

    let pipeline_state = established(map, "pipeline_state")
        .or_else(|| established(map, "candidate_pipeline_state"))
        .or_else(|| established(map, "completed_pipeline_state"))
        .map(|value| {
            value.as_str().filter(|text| !text.is_empty()).map(str::to_string).ok_or_else(|| {
                fault(
                    "invalid_query",
                    "root pipeline_state must be a nonempty string".to_string(),
                )
            })
        })
        .transpose()?;
    if let Some(state) = pipeline_state.as_deref() {
        if !DETAIL_STATES.contains(&state) {
            return Err(fault(
                "unknown_pipeline_state",
                format!("root pipeline_state {state:?} is not one of {DETAIL_STATES:?}"),
            ));
        }
    }

    let render_verdict = optional_text(map, "render_verdict").map(str::to_string);
    let entity_type = optional_text(map, "entity_type").map(str::to_string);
    let candidate_kind = first_text(map, &["candidate_kind", "kind"]).map(str::to_string);
    let veto_scope = optional_text(map, "veto_scope").map(str::to_string);

    let approximate_raw = match map.get("approximate") {
        Some(value) if is_missing(value) => value.clone(),
        Some(value) => value.clone(),
        None => missing("not_observed", "no approximate hint was supplied"),
    };
    let approximate_decision = if is_missing(&approximate_raw) {
        None
    } else {
        let object = approximate_raw.as_object().ok_or_else(|| {
            fault(
                "invalid_approximate",
                "root approximate must be an object with decision miss|possible_hit, or Missing".to_string(),
            )
        })?;
        match object.get("decision").and_then(Value::as_str) {
            Some("miss") => Some("miss".to_string()),
            Some("possible_hit") => Some("possible_hit".to_string()),
            Some(other) => {
                return Err(fault(
                    "invalid_approximate",
                    format!("root approximate decision {other:?} must be miss or possible_hit"),
                ))
            }
            None => {
                return Err(fault(
                    "invalid_approximate",
                    "root approximate is missing required field \"decision\"".to_string(),
                ))
            }
        }
    };

    let suppress_when_hit = match established(map, "suppress_when_hit") {
        None => false,
        Some(Value::Bool(flag)) => *flag,
        Some(_) => {
            return Err(fault(
                "invalid_query",
                "root suppress_when_hit must be a boolean".to_string(),
            ))
        }
    };

    Ok(ExactQuery {
        target,
        job_id,
        fetch_key_value,
        detail_revision,
        pipeline_state,
        render_verdict,
        entity_type,
        candidate_kind,
        veto_scope,
        journal_id,
        approximate_decision,
        approximate_raw,
        suppress_when_hit,
    })
}

/// Stored detail facts extracted from one journaled `payload.data` object.
struct StoredFacts {
    fetch_key_value: String,
    fetch_key_raw: Value,
    pipeline_state: String,
    revision: u64,
    run_id: String,
    render_verdict: Option<String>,
    entity_type: Option<String>,
    candidate_kind: Option<String>,
    veto_scope: Option<String>,
}

fn parse_stored_data(data: &Map<String, Value>) -> Result<StoredFacts, &'static str> {
    let fetch_key_raw = established(data, "fetch_key")
        .or_else(|| established(data, "completed_fetch_key"))
        .cloned()
        .ok_or("stored_incomplete")?;
    let fetch_key_value = match fetch_key_raw.as_object() {
        Some(object) => match object.get("value").and_then(Value::as_str) {
            Some(text) if !text.is_empty() => text.to_string(),
            _ => return Err("stored_incomplete"),
        },
        None => match fetch_key_raw.as_str() {
            Some(text) if !text.is_empty() => text.to_string(),
            _ => return Err("stored_incomplete"),
        },
    };
    let pipeline_state = match established(data, "pipeline_state")
        .or_else(|| established(data, "completed_pipeline_state"))
        .and_then(Value::as_str)
    {
        Some(text) if !text.is_empty() => text.to_string(),
        _ => return Err("stored_incomplete"),
    };
    let revision = first_u64(
        data,
        &[
            "detail_revision",
            "completed_detail_revision",
            "entity_revision",
        ],
    )
    .ok_or("stored_incomplete")?;
    let run_id = first_text(data, &["active_run_id", "completed_run_id", "run_id"])
        .ok_or("stored_incomplete")?
        .to_string();
    Ok(StoredFacts {
        fetch_key_value,
        fetch_key_raw,
        pipeline_state,
        revision,
        run_id,
        render_verdict: optional_text(data, "render_verdict").map(str::to_string),
        entity_type: optional_text(data, "entity_type").map(str::to_string),
        candidate_kind: first_text(data, &["candidate_kind", "kind"]).map(str::to_string),
        veto_scope: optional_text(data, "veto_scope").map(str::to_string),
    })
}

fn stored_eligible(facts: &StoredFacts) -> bool {
    if facts.entity_type.as_deref() == Some("listing") {
        return false;
    }
    if is_non_detail_kind(facts.candidate_kind.as_deref()) {
        return false;
    }
    if !ELIGIBLE_STATES.contains(&facts.pipeline_state.as_str()) {
        return false;
    }
    if let Some(verdict) = facts.render_verdict.as_deref() {
        if verdict != RENDER_PASS {
            return false;
        }
    }
    if facts.pipeline_state == "vetoed" && is_snippet_scope(facts.veto_scope.as_deref()) {
        return false;
    }
    true
}

fn event_data<'a>(event: &'a Value) -> Option<&'a Map<String, Value>> {
    if let Some(data) = event
        .get("payload")
        .and_then(Value::as_object)
        .and_then(|payload| payload.get("data"))
        .and_then(Value::as_object)
    {
        return Some(data);
    }
    event.get("data").and_then(Value::as_object)
}

fn event_sequence(event: &Value, position: u64) -> u64 {
    event
        .get("journal_sequence")
        .and_then(Value::as_u64)
        .unwrap_or(position)
}

fn query_is_definitionally_ineligible(query: &ExactQuery) -> Option<&'static str> {
    if query.entity_type.as_deref() == Some("listing") {
        return Some("listing_excluded");
    }
    if is_non_detail_kind(query.candidate_kind.as_deref()) {
        if query
            .candidate_kind
            .as_deref()
            .is_some_and(|kind| kind.contains("snippet"))
        {
            return Some("snippet_veto_excluded");
        }
        return Some("listing_excluded");
    }
    if let Some(state) = query.pipeline_state.as_deref() {
        if !ELIGIBLE_STATES.contains(&state) {
            return Some("ineligible_state");
        }
        if state == "vetoed" && is_snippet_scope(query.veto_scope.as_deref()) {
            return Some("snippet_veto_excluded");
        }
    } else if is_snippet_scope(query.veto_scope.as_deref()) {
        // A snippet-scoped candidate without an explicit detail state is
        // still never a detail member.
        return Some("snippet_veto_excluded");
    }
    if let Some(verdict) = query.render_verdict.as_deref() {
        if verdict != RENDER_PASS {
            return Some("render_not_pass");
        }
    }
    None
}

fn build_verdict(
    query: &ExactQuery,
    decision: &str,
    reason: &str,
    exact_confirmed: bool,
    matched: Option<(&StoredFacts, &Value, u64)>,
) -> Result<CheckedRecord, Fault> {
    let (completed_fetch_key, completed_pipeline_state, completed_detail_revision, completed_run_id, store_evidence) =
        match matched {
            Some((stored, event, sequence)) => {
                let event_hash = event.get("event_hash").and_then(Value::as_str).unwrap_or("");
                let event_id = event.get("event_id").and_then(Value::as_str).unwrap_or("");
                (
                    stored.fetch_key_raw.clone(),
                    json!(stored.pipeline_state),
                    json!(stored.revision),
                    json!(stored.run_id),
                    json!({
                        "journal_id": query.journal_id,
                        "journal_sequence": sequence,
                        "event_hash": event_hash,
                        "event_id": event_id,
                    }),
                )
            }
            None => {
                let evidence = if exact_confirmed {
                    missing(
                        "not_observed",
                        "exact journal scan found no eligible record at this key and revision",
                    )
                } else {
                    missing(
                        "not_applicable",
                        "no exact lookup was performed for this miss",
                    )
                };
                (
                    missing("not_applicable", "no exact member; nothing completed at this identity"),
                    missing("not_applicable", "no exact member; no eligible pipeline state"),
                    missing("not_applicable", "no exact member; no successful revision"),
                    missing("not_applicable", "no exact member; no completion run"),
                    evidence,
                )
            }
        };

    let suppress_downstream_work = decision == "hit" && query.suppress_when_hit;
    let output = json!({
        "record_type": "seen_exact_verdict",
        "target": query.target,
        "job_id": query.job_id,
        "decision": decision,
        "reason": reason,
        "exact_confirmed": exact_confirmed,
        "approximate": query.approximate_raw,
        "completed_fetch_key": completed_fetch_key,
        "completed_pipeline_state": completed_pipeline_state,
        "completed_detail_revision": completed_detail_revision,
        "completed_run_id": completed_run_id,
        "store_evidence": store_evidence,
        "suppress_downstream_work": suppress_downstream_work,
        "coverage": {
            "observe_required": true,
            "suppressed": false,
        },
        "limitations": [],
    });
    validate(OUTPUT_SCHEMA, output)
}

/// Confirm exact successful-detail membership for one candidate root.
///
/// `root` names the candidate: `target`, `job_id`, `fetch_key` (closed `SH`),
/// `detail_revision`, and the `journal_id` to confirm against, plus optional
/// `pipeline_state`, `render_verdict`, `entity_type`, `candidate_kind`,
/// `veto_scope`, `approximate` (`{decision: miss|possible_hit}`), and
/// `suppress_when_hit`.
///
/// * Definitionally ineligible candidates (listings, snippet-only vetoes,
///   non-`Pass` renders, non-ready/vetoed states) return `miss` without
///   consulting the store: they can never be members.
/// * An approximate definite `miss` returns `miss` without a store read.
/// * Every other candidate — including every `possible_hit` — is confirmed by
///   reading the owner journal and comparing against the latest journaled
///   detail for `(target, job_id)`. Only a currently ready/vetoed `Pass`
///   detail at the identical fetch-key value and revision is a `hit`. Key,
///   revision, or state mismatches, stored ineligible states, and absent
///   records are all `miss`. Store faults propagate unchanged; a possible hit
///   without exact confirmation is never a hit.
/// * A `hit` sets `suppress_downstream_work` only when the query configured
///   `suppress_when_hit`. `coverage.observe_required` is always true and
///   `coverage.suppressed` always false: hits never suppress coverage
///   evidence.
///
/// This function only reads. It never calls [`OwnerStore::transact`].
///
/// Faults: `invalid_query`, `missing_target`, `missing_job`,
/// `invalid_fetch_key`, `missing_revision`, `missing_journal`,
/// `unknown_pipeline_state`, `invalid_approximate`, `invalid_journal_view`,
/// plus any fault the store reports for the journal read.
pub fn exact_success(
    store: &dyn OwnerStore,
    grant: &Grant,
    root: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let query = parse_exact_query(root)?;

    if let Some(reason) = query_is_definitionally_ineligible(&query) {
        return build_verdict(&query, "miss", reason, false, None);
    }
    if query.approximate_decision.as_deref() == Some("miss") {
        return build_verdict(&query, "miss", "approximate_miss", false, None);
    }

    // Possible hits (and unhinted queries) always require exact confirmation.
    let request = validate(
        OUTPUT_SCHEMA,
        json!({"query": "journal", "journal_id": query.journal_id}),
    )?;
    let view = store.read(grant, &request)?;
    let view_map = record_value(&view).as_object().ok_or_else(|| {
        fault(
            "invalid_journal_view",
            "owner store journal view must be an object".to_string(),
        )
    })?;
    let events = view_map.get("events").and_then(Value::as_array).ok_or_else(|| {
        fault(
            "invalid_journal_view",
            "owner store journal view is missing its events array".to_string(),
        )
    })?;

    // The latest journaled detail for this root is the current state; earlier
    // success followed by an exit is not current membership.
    let mut latest: Option<(u64, &Value, &Map<String, Value>)> = None;
    for (index, event) in events.iter().enumerate() {
        let Some(data) = event_data(event) else {
            continue;
        };
        let target = data.get("target").and_then(Value::as_str).unwrap_or("");
        let job_id = data.get("job_id").and_then(Value::as_str).unwrap_or("");
        if target != query.target || job_id != query.job_id {
            continue;
        }
        let sequence = event_sequence(event, (index as u64) + 1);
        let replace = latest.as_ref().is_none_or(|(held, _, _)| sequence >= *held);
        if replace {
            latest = Some((sequence, event, data));
        }
    }

    let Some((sequence, event, data)) = latest else {
        return build_verdict(&query, "miss", "no_exact_record", true, None);
    };

    let stored = match parse_stored_data(data) {
        Ok(facts) => facts,
        Err(reason) => return build_verdict(&query, "miss", reason, true, None),
    };
    if !stored_eligible(&stored) {
        let reason = if stored.pipeline_state == "vetoed"
            && is_snippet_scope(stored.veto_scope.as_deref())
        {
            "snippet_veto_excluded"
        } else if stored.entity_type.as_deref() == Some("listing")
            || is_non_detail_kind(stored.candidate_kind.as_deref())
        {
            "listing_excluded"
        } else if !ELIGIBLE_STATES.contains(&stored.pipeline_state.as_str()) {
            "stored_ineligible_state"
        } else {
            "stored_render_not_pass"
        };
        return build_verdict(&query, "miss", reason, true, None);
    }
    if stored.fetch_key_value != query.fetch_key_value {
        return build_verdict(&query, "miss", "fetch_key_mismatch", true, None);
    }
    if stored.revision != query.detail_revision {
        return build_verdict(&query, "miss", "revision_mismatch", true, None);
    }
    if let Some(expected) = query.pipeline_state.as_deref() {
        if stored.pipeline_state != expected {
            return build_verdict(&query, "miss", "pipeline_state_mismatch", true, None);
        }
    }

    build_verdict(&query, "hit", "exact_match", true, Some((&stored, event, sequence)))
}

//! Conformance: [C27] five detectors and [C31] drift.
//!
//! C27 covers exact trigger thresholds, stop/split/recovery, and the full
//! evidence bundle for row cap, saturation, no-op parameter, tail clamp, and
//! ascending overflow. C31 covers repeated-distinct rates, bands, backend
//! cohorts, and bounded reconciliation.

use crawler_detectors::{evaluate_detectors, evaluate_drift};
use crawler_hashing::digest_bytes;
use crawler_schema::{record_value, validate, CheckedRecord};
use serde_json::{json, Value};

fn missing(reason: &str) -> Value {
    json!({"value": Value::Null, "reason": reason})
}

fn missing_detail(reason: &str, detail: &str) -> Value {
    json!({"value": Value::Null, "reason": reason, "detail": detail})
}

fn timepoint(offset_ms: i64) -> Value {
    json!({
        "clock_id": "det-clk",
        "boot_id": "boot-1",
        "origin": "engine_measured",
        "monotonic_offset_ms": offset_ms,
        "utc_annotation": missing("not_observed"),
    })
}

fn evidence_refs() -> Value {
    json!([{
        "journal_id": "j-1",
        "sequence": 10,
        "event_id": "evt-10",
        "event_hash": "abc",
        "pointer": "/row",
    }])
}

fn evidence_prefix() -> Value {
    json!({"journal_id": "j-1", "last_sequence": 10, "head_hash": "abc123"})
}

fn sh_for_bytes(bytes: &[u8]) -> Value {
    json!({
        "value": digest_bytes(bytes),
        "profile": "crawler-page-hash/1",
        "evidence_refs": [{"ref": "t"}],
    })
}

fn sh_with_digest(digest: &str) -> Value {
    json!({
        "value": digest,
        "profile": "crawler-page-hash/1",
        "evidence_refs": [{"ref": "t"}],
    })
}

fn check(schema: &str, value: Value) -> CheckedRecord {
    validate(schema, value).expect("fixture must satisfy the schema gate")
}

// ---------------------------------------------------------------------------
// C27 fixtures
// ---------------------------------------------------------------------------

fn c27_declaration(overrides: Value) -> CheckedRecord {
    let mut base = json!({
        "target": "il",
        "run_id": "run-1",
        "partition_id": "p-1",
        "owner_domain": "crawler",
        "captured_at": timepoint(50_000),
        "evidence_prefix": evidence_prefix(),
        "evidence_refs": evidence_refs(),
        "row_cap": 10,
        "row_cap_verified": true,
        "saturation_markers": ["+"],
        "noop_threshold": 2,
        "tail_threshold": 2,
        "ordering_model": "ascending",
        "overflow_banners": ["OVERFLOW"],
        "probe_policy": "fixture_only",
    });
    if let Value::Object(extra) = overrides {
        for (k, v) in extra {
            base[k] = v;
        }
    }
    check("audit_log", base)
}

fn c27_prior(overrides: Value) -> CheckedRecord {
    let first_hash = sh_for_bytes(b"first-page-bytes");
    let terminal_hash = sh_for_bytes(b"terminal-page-bytes");
    let mut base = json!({
        "rowcap_state": "MONITORING",
        "saturation_state": "UNSATURATED",
        "noop_state": "ADVANCING",
        "tail_state": "ADVANCING",
        "ascending_state": "MONITORING_ASCENDING",
        "noop_corroboration_count": 0,
        "tail_corroboration_count": 0,
        "first_page_ordered_ids": ["job-a", "job-b"],
        "first_page_hash": first_hash,
        "first_page_coordinate": {"page": 1},
        "terminal_ordered_ids": ["job-x", "job-y"],
        "terminal_page_hash": terminal_hash,
        "max_date_posted": "2026-01-10",
        "split_available": true,
        "alternative_cursor_available": true,
        "below_cap_split_available": true,
    });
    if let Value::Object(extra) = overrides {
        for (k, v) in extra {
            base[k] = v;
        }
    }
    check("cursor_state", base)
}

fn c27_packet(overrides: Value) -> CheckedRecord {
    let page_hash = sh_for_bytes(b"current-page-bytes");
    let response_hash = sh_for_bytes(b"response-bytes");
    let mut base = json!({
        "request_coordinate": {"page": 2},
        "request_sequence": 2,
        "response_identity": "resp-2",
        "response_hash": response_hash,
        "page_hash": page_hash,
        "page_bytes": missing("not_observed"),
        "ordered_observed_ids": ["job-c", "job-d"],
        "observed_total": 4,
        "reported_total": missing("not_observed"),
        "reported_total_source_verified": false,
        "count_label_marker": missing("not_applicable"),
        "saturation_marker_present": false,
        "termination": false,
        "coordinate_kind": "in_range",
        "continuation_progress": true,
        "ordering": "unordered",
        "newest_date": missing("not_observed"),
        "banner_present": false,
        "banner_text": missing("not_applicable"),
        "count_units": "postings",
        "children_proven": false,
        "live_probe": false,
    });
    if let Value::Object(extra) = overrides {
        for (k, v) in extra {
            base[k] = v;
        }
    }
    check("cursor_state", base)
}

fn detector<'a>(output: &'a Value, name: &str) -> &'a Value {
    output
        .get("detectors")
        .and_then(Value::as_array)
        .expect("output must carry detectors")
        .iter()
        .find(|d| d.get("detector").and_then(Value::as_str) == Some(name))
        .unwrap_or_else(|| panic!("detector {name} must be present"))
}

// ---------------------------------------------------------------------------
// C27: row cap
// ---------------------------------------------------------------------------

#[test]
fn c27_row_cap_triggers_at_verified_cap_and_recovers_via_split() {
    // Below cap: monitoring.
    let decl = c27_declaration(json!({}));
    let prior = c27_prior(json!({}));
    let packet = c27_packet(json!({"observed_total": 4}));
    let out = evaluate_detectors(&decl, &prior, &packet).expect("below cap must evaluate");
    let value = record_value(&out);
    let rowcap = detector(value, "row_cap");
    assert_eq!(rowcap.get("state").and_then(Value::as_str), Some("MONITORING"));
    assert_eq!(rowcap.get("blocking"), Some(&Value::Bool(false)));
    assert_eq!(rowcap.get("action").and_then(Value::as_str), Some("monitor"));
    assert_eq!(rowcap.get("threshold").and_then(Value::as_u64), Some(1));

    // At verified cap: single commit triggers (threshold 1).
    let packet = c27_packet(json!({"observed_total": 10, "request_sequence": 3}));
    let out = evaluate_detectors(&decl, &prior, &packet).expect("at cap must trigger");
    let value = record_value(&out).clone();
    let rowcap = detector(&value, "row_cap");
    assert_eq!(
        rowcap.get("state").and_then(Value::as_str),
        Some("CAP_REACHED_TRIGGERED")
    );
    assert_eq!(rowcap.get("blocking"), Some(&Value::Bool(true)));
    assert_eq!(rowcap.get("action").and_then(Value::as_str), Some("stop_walk"));
    assert_eq!(rowcap.get("corroboration_count").and_then(Value::as_u64), Some(1));
    assert_eq!(
        rowcap
            .get("evidence")
            .and_then(|e| e.get("recovery"))
            .and_then(Value::as_str),
        Some("split")
    );

    // Triggered + axis -> bisected.
    let prior = c27_prior(json!({"rowcap_state": "CAP_REACHED_TRIGGERED"}));
    let packet = c27_packet(json!({"observed_total": 10, "request_sequence": 4}));
    let out = evaluate_detectors(&decl, &prior, &packet).expect("triggered must bisect");
    let value = record_value(&out).clone();
    let rowcap = detector(&value, "row_cap");
    assert_eq!(rowcap.get("state").and_then(Value::as_str), Some("BISECTED"));
    assert_eq!(rowcap.get("action").and_then(Value::as_str), Some("split"));

    // Bisected + proven children -> proven, non-blocking.
    let prior = c27_prior(json!({"rowcap_state": "BISECTED"}));
    let packet = c27_packet(json!({"observed_total": 10, "children_proven": true}));
    let out = evaluate_detectors(&decl, &prior, &packet).expect("bisected must prove");
    let value = record_value(&out).clone();
    let rowcap = detector(&value, "row_cap");
    assert_eq!(
        rowcap.get("state").and_then(Value::as_str),
        Some("PROVEN_VIA_CHILDREN")
    );
    assert_eq!(rowcap.get("blocking"), Some(&Value::Bool(false)));
    assert_eq!(
        rowcap.get("action").and_then(Value::as_str),
        Some("proven_via_children")
    );

    // Unverified cap never triggers.
    let decl = c27_declaration(json!({"row_cap_verified": false}));
    let prior = c27_prior(json!({}));
    let packet = c27_packet(json!({"observed_total": 10}));
    let out = evaluate_detectors(&decl, &prior, &packet).expect("unverified cap evaluates");
    let rowcap = detector(record_value(&out), "row_cap");
    assert_eq!(rowcap.get("state").and_then(Value::as_str), Some("MONITORING"));
}

#[test]
fn c27_row_cap_terminal_without_axis() {
    let decl = c27_declaration(json!({}));
    let prior = c27_prior(json!({
        "rowcap_state": "CAP_REACHED_TRIGGERED",
        "split_available": false,
    }));
    let packet = c27_packet(json!({"observed_total": 10}));
    let out = evaluate_detectors(&decl, &prior, &packet).expect("no-axis must evaluate");
    let rowcap = detector(record_value(&out), "row_cap");
    assert_eq!(
        rowcap.get("state").and_then(Value::as_str),
        Some("TERMINAL_INCOMPLETE")
    );
    assert_eq!(
        rowcap.get("action").and_then(Value::as_str),
        Some("mark_incomplete")
    );
    assert_eq!(
        rowcap.get("failure_reason").and_then(Value::as_str),
        Some("terminal_incomplete")
    );
    assert_eq!(rowcap.get("blocking"), Some(&Value::Bool(true)));
}

// ---------------------------------------------------------------------------
// C27: saturation
// ---------------------------------------------------------------------------

#[test]
fn c27_saturation_requires_configured_marker() {
    let decl = c27_declaration(json!({}));
    let prior = c27_prior(json!({}));

    // Configured marker triggers at threshold 1.
    let packet = c27_packet(json!({
        "saturation_marker_present": true,
        "count_label_marker": "+",
    }));
    let out = evaluate_detectors(&decl, &prior, &packet).expect("configured marker triggers");
    let sat = detector(record_value(&out), "saturation");
    assert_eq!(
        sat.get("state").and_then(Value::as_str),
        Some("SATURATED_TRIGGERED")
    );
    assert_eq!(sat.get("threshold").and_then(Value::as_u64), Some(1));
    assert_eq!(sat.get("blocking"), Some(&Value::Bool(true)));

    // Unconfigured marker is ignored.
    let packet = c27_packet(json!({
        "saturation_marker_present": true,
        "count_label_marker": "?",
    }));
    let out = evaluate_detectors(&decl, &prior, &packet).expect("unconfigured marker evaluates");
    let sat = detector(record_value(&out), "saturation");
    assert_eq!(sat.get("state").and_then(Value::as_str), Some("UNSATURATED"));
    assert_eq!(sat.get("blocking"), Some(&Value::Bool(false)));

    // No marker present stays unsaturated.
    let packet = c27_packet(json!({"saturation_marker_present": false}));
    let out = evaluate_detectors(&decl, &prior, &packet).expect("absent marker evaluates");
    let sat = detector(record_value(&out), "saturation");
    assert_eq!(sat.get("state").and_then(Value::as_str), Some("UNSATURATED"));

    // Recovery mirrors row cap: bisect then prove.
    let prior = c27_prior(json!({"saturation_state": "SATURATED_TRIGGERED"}));
    let packet = c27_packet(json!({
        "saturation_marker_present": true,
        "count_label_marker": "+",
    }));
    let out = evaluate_detectors(&decl, &prior, &packet).expect("saturated must bisect");
    assert_eq!(
        detector(record_value(&out), "saturation")
            .get("state")
            .and_then(Value::as_str),
        Some("BISECTED")
    );
    let prior = c27_prior(json!({"saturation_state": "BISECTED"}));
    let packet = c27_packet(json!({"children_proven": true}));
    let out = evaluate_detectors(&decl, &prior, &packet).expect("bisected must prove");
    let sat = detector(record_value(&out), "saturation");
    assert_eq!(
        sat.get("state").and_then(Value::as_str),
        Some("PROVEN_VIA_CHILDREN")
    );
    assert_eq!(sat.get("blocking"), Some(&Value::Bool(false)));
}

// ---------------------------------------------------------------------------
// C27: no-op parameter
// ---------------------------------------------------------------------------

#[test]
fn c27_noop_two_corroborations_and_alternative_recovery() {
    let decl = c27_declaration(json!({}));
    // First repeat of first-page IDs at a distinct coordinate: suspect.
    let prior = c27_prior(json!({}));
    let packet = c27_packet(json!({
        "request_coordinate": {"page": 2},
        "ordered_observed_ids": ["job-a", "job-b"],
        "continuation_progress": false,
        "coordinate_kind": "distinct",
    }));
    let out = evaluate_detectors(&decl, &prior, &packet).expect("first repeat evaluates");
    let noop = detector(record_value(&out), "noop_parameter");
    assert_eq!(noop.get("state").and_then(Value::as_str), Some("SUSPECT_NOOP"));
    assert_eq!(noop.get("corroboration_count").and_then(Value::as_u64), Some(1));
    assert_eq!(noop.get("threshold").and_then(Value::as_u64), Some(2));
    assert_eq!(noop.get("blocking"), Some(&Value::Bool(false)));

    // Second distinct repeat confirms.
    let prior = c27_prior(json!({
        "noop_state": "SUSPECT_NOOP",
        "noop_corroboration_count": 1,
    }));
    let packet = c27_packet(json!({
        "request_coordinate": {"page": 3},
        "ordered_observed_ids": ["job-a", "job-b"],
        "continuation_progress": false,
        "coordinate_kind": "distinct",
    }));
    let out = evaluate_detectors(&decl, &prior, &packet).expect("second repeat confirms");
    let noop = detector(record_value(&out), "noop_parameter");
    assert_eq!(
        noop.get("state").and_then(Value::as_str),
        Some("NOOP_CONFIRMED_TRIGGERED")
    );
    assert_eq!(noop.get("corroboration_count").and_then(Value::as_u64), Some(2));
    assert_eq!(noop.get("blocking"), Some(&Value::Bool(true)));
    assert_eq!(noop.get("action").and_then(Value::as_str), Some("stop_walk"));

    // Legitimate continuation progress never corroborates.
    let prior = c27_prior(json!({}));
    let packet = c27_packet(json!({
        "request_coordinate": {"page": 2},
        "ordered_observed_ids": ["job-a", "job-b"],
        "continuation_progress": true,
    }));
    let out = evaluate_detectors(&decl, &prior, &packet).expect("progress evaluates");
    let noop = detector(record_value(&out), "noop_parameter");
    assert_eq!(noop.get("state").and_then(Value::as_str), Some("ADVANCING"));
    assert_eq!(noop.get("corroboration_count").and_then(Value::as_u64), Some(0));

    // Confirmed + alternative -> partition-only recovery (non-blocking).
    let prior = c27_prior(json!({
        "noop_state": "NOOP_CONFIRMED_TRIGGERED",
        "noop_corroboration_count": 2,
        "alternative_cursor_available": true,
    }));
    let packet = c27_packet(json!({}));
    let out = evaluate_detectors(&decl, &prior, &packet).expect("alternative recovery evaluates");
    let noop = detector(record_value(&out), "noop_parameter");
    assert_eq!(
        noop.get("state").and_then(Value::as_str),
        Some("PARTITION_ONLY_OR_ALTERNATIVE_CURSOR")
    );
    assert_eq!(noop.get("blocking"), Some(&Value::Bool(false)));

    // No alternative -> terminal incomplete.
    let prior = c27_prior(json!({
        "noop_state": "NOOP_CONFIRMED_TRIGGERED",
        "noop_corroboration_count": 2,
        "alternative_cursor_available": false,
    }));
    let out = evaluate_detectors(&decl, &prior, &packet).expect("no alternative evaluates");
    let noop = detector(record_value(&out), "noop_parameter");
    assert_eq!(
        noop.get("state").and_then(Value::as_str),
        Some("TERMINAL_INCOMPLETE")
    );
    assert_eq!(
        noop.get("action").and_then(Value::as_str),
        Some("mark_incomplete")
    );
}

#[test]
fn c27_noop_page_hash_repeat_corroborates_without_id_match() {
    let decl = c27_declaration(json!({}));
    let first_digest = digest_bytes(b"first-page-bytes");
    // Different IDs but identical retained page signature still repeats.
    let prior = c27_prior(json!({}));
    let packet = c27_packet(json!({
        "request_coordinate": {"page": 9},
        "ordered_observed_ids": ["job-other"],
        "page_hash": sh_with_digest(&first_digest),
        "continuation_progress": false,
        "coordinate_kind": "distinct",
    }));
    let out = evaluate_detectors(&decl, &prior, &packet).expect("hash repeat evaluates");
    let noop = detector(record_value(&out), "noop_parameter");
    assert_eq!(noop.get("state").and_then(Value::as_str), Some("SUSPECT_NOOP"));
    assert_eq!(noop.get("corroboration_count").and_then(Value::as_u64), Some(1));
}

#[test]
fn c27_noop_uses_retained_fixtures_never_live() {
    let decl = c27_declaration(json!({}));
    let prior = c27_prior(json!({}));
    let packet = c27_packet(json!({"live_probe": true}));
    let err = evaluate_detectors(&decl, &prior, &packet).expect_err("live probe must fault");
    assert_eq!(err.code, "prohibited_live_probe");

    let decl = c27_declaration(json!({"probe_policy": "live"}));
    let packet = c27_packet(json!({}));
    let err = evaluate_detectors(&decl, &prior, &packet).expect_err("live policy must fault");
    assert_eq!(err.code, "invalid_probe_policy");
}

// ---------------------------------------------------------------------------
// C27: tail clamp
// ---------------------------------------------------------------------------

#[test]
fn c27_tail_clamp_beyond_range_and_split_below_cap() {
    let decl = c27_declaration(json!({}));
    // Beyond-range repeat of the terminal signature: first corroboration.
    let prior = c27_prior(json!({}));
    let packet = c27_packet(json!({
        "request_coordinate": {"page": 99},
        "ordered_observed_ids": ["job-x", "job-y"],
        "coordinate_kind": "beyond_range",
        "continuation_progress": false,
    }));
    let out = evaluate_detectors(&decl, &prior, &packet).expect("first clamp evaluates");
    let tail = detector(record_value(&out), "tail_clamp");
    assert_eq!(
        tail.get("state").and_then(Value::as_str),
        Some("SUSPECT_TAIL_CLAMP")
    );
    assert_eq!(tail.get("corroboration_count").and_then(Value::as_u64), Some(1));

    // Second beyond-range repeat confirms.
    let prior = c27_prior(json!({
        "tail_state": "SUSPECT_TAIL_CLAMP",
        "tail_corroboration_count": 1,
    }));
    let packet = c27_packet(json!({
        "request_coordinate": {"page": 100},
        "ordered_observed_ids": ["job-x", "job-y"],
        "coordinate_kind": "beyond_range",
        "continuation_progress": false,
    }));
    let out = evaluate_detectors(&decl, &prior, &packet).expect("second clamp confirms");
    let tail = detector(record_value(&out), "tail_clamp");
    assert_eq!(
        tail.get("state").and_then(Value::as_str),
        Some("TAIL_CLAMP_CONFIRMED_TRIGGERED")
    );
    assert_eq!(tail.get("blocking"), Some(&Value::Bool(true)));

    // In-range repeats are not tail clamps.
    let prior = c27_prior(json!({}));
    let packet = c27_packet(json!({
        "request_coordinate": {"page": 2},
        "ordered_observed_ids": ["job-x", "job-y"],
        "coordinate_kind": "in_range",
    }));
    let out = evaluate_detectors(&decl, &prior, &packet).expect("in-range evaluates");
    let tail = detector(record_value(&out), "tail_clamp");
    assert_eq!(tail.get("state").and_then(Value::as_str), Some("ADVANCING"));
    assert_eq!(tail.get("corroboration_count").and_then(Value::as_u64), Some(0));

    // Confirmed + below-cap axis -> bisected below cap, then proven.
    let prior = c27_prior(json!({
        "tail_state": "TAIL_CLAMP_CONFIRMED_TRIGGERED",
        "tail_corroboration_count": 2,
        "below_cap_split_available": true,
    }));
    let packet = c27_packet(json!({}));
    let out = evaluate_detectors(&decl, &prior, &packet).expect("clamp must bisect below cap");
    let tail = detector(record_value(&out), "tail_clamp");
    assert_eq!(
        tail.get("state").and_then(Value::as_str),
        Some("BISECTED_BELOW_CAP")
    );
    assert_eq!(tail.get("action").and_then(Value::as_str), Some("split"));

    let prior = c27_prior(json!({
        "tail_state": "BISECTED_BELOW_CAP",
        "tail_corroboration_count": 2,
    }));
    let packet = c27_packet(json!({"children_proven": true}));
    let out = evaluate_detectors(&decl, &prior, &packet).expect("bisected clamp must prove");
    let tail = detector(record_value(&out), "tail_clamp");
    assert_eq!(
        tail.get("state").and_then(Value::as_str),
        Some("PROVEN_VIA_CHILDREN")
    );
    assert_eq!(tail.get("blocking"), Some(&Value::Bool(false)));

    // No below-cap axis -> terminal incomplete.
    let prior = c27_prior(json!({
        "tail_state": "TAIL_CLAMP_CONFIRMED_TRIGGERED",
        "tail_corroboration_count": 2,
        "below_cap_split_available": false,
    }));
    let packet = c27_packet(json!({}));
    let out = evaluate_detectors(&decl, &prior, &packet).expect("no axis evaluates");
    let tail = detector(record_value(&out), "tail_clamp");
    assert_eq!(
        tail.get("state").and_then(Value::as_str),
        Some("TERMINAL_INCOMPLETE")
    );
}

// ---------------------------------------------------------------------------
// C27: ascending overflow
// ---------------------------------------------------------------------------

#[test]
fn c27_ascending_overflow_needs_pressure_regression_alone_is_suspicion() {
    let decl = c27_declaration(json!({}));
    // Regression alone: suspicion, never proof.
    let prior = c27_prior(json!({"max_date_posted": "2026-01-10"}));
    let packet = c27_packet(json!({
        "ordering": "ascending",
        "newest_date": "2026-01-05",
        "observed_total": 4,
    }));
    let out = evaluate_detectors(&decl, &prior, &packet).expect("regression evaluates");
    let asc = detector(record_value(&out), "ascending_overflow");
    assert_eq!(
        asc.get("state").and_then(Value::as_str),
        Some("DATE_REGRESSION_SUSPICION")
    );
    assert_eq!(asc.get("blocking"), Some(&Value::Bool(false)));
    assert_eq!(asc.get("action").and_then(Value::as_str), Some("monitor"));

    // Ascending + cap pressure triggers even without regression.
    let packet = c27_packet(json!({
        "ordering": "ascending",
        "newest_date": "2026-01-12",
        "observed_total": 10,
    }));
    let out = evaluate_detectors(&decl, &prior, &packet).expect("pressure triggers");
    let asc = detector(record_value(&out), "ascending_overflow");
    assert_eq!(
        asc.get("state").and_then(Value::as_str),
        Some("ASCENDING_OVERFLOW_TRIGGERED")
    );
    assert_eq!(asc.get("blocking"), Some(&Value::Bool(true)));

    // Ascending + banner pressure triggers.
    let packet = c27_packet(json!({
        "ordering": "ascending",
        "banner_present": true,
        "banner_text": "OVERFLOW",
        "observed_total": 4,
    }));
    let out = evaluate_detectors(&decl, &prior, &packet).expect("banner triggers");
    let asc = detector(record_value(&out), "ascending_overflow");
    assert_eq!(
        asc.get("state").and_then(Value::as_str),
        Some("ASCENDING_OVERFLOW_TRIGGERED")
    );

    // Unconfigured banner text is not pressure.
    let packet = c27_packet(json!({
        "ordering": "ascending",
        "banner_present": true,
        "banner_text": "SOMETHING_ELSE",
        "observed_total": 4,
    }));
    let out = evaluate_detectors(&decl, &prior, &packet).expect("unconfigured banner evaluates");
    let asc = detector(record_value(&out), "ascending_overflow");
    assert_eq!(
        asc.get("state").and_then(Value::as_str),
        Some("MONITORING_ASCENDING")
    );

    // Non-ascending ordering never triggers, even under pressure.
    let packet = c27_packet(json!({
        "ordering": "unordered",
        "observed_total": 10,
    }));
    let out = evaluate_detectors(&decl, &prior, &packet).expect("unordered evaluates");
    let asc = detector(record_value(&out), "ascending_overflow");
    assert_eq!(
        asc.get("state").and_then(Value::as_str),
        Some("MONITORING_ASCENDING")
    );

    // Triggered recovery: bisect then prove, else unrecoverable.
    let prior = c27_prior(json!({"ascending_state": "ASCENDING_OVERFLOW_TRIGGERED"}));
    let packet = c27_packet(json!({"ordering": "ascending", "observed_total": 10}));
    let out = evaluate_detectors(&decl, &prior, &packet).expect("overflow must bisect");
    assert_eq!(
        detector(record_value(&out), "ascending_overflow")
            .get("state")
            .and_then(Value::as_str),
        Some("BISECTED")
    );
    let prior = c27_prior(json!({"ascending_state": "BISECTED"}));
    let packet = c27_packet(json!({"children_proven": true}));
    let out = evaluate_detectors(&decl, &prior, &packet).expect("bisected must prove");
    let asc = detector(record_value(&out), "ascending_overflow");
    assert_eq!(
        asc.get("state").and_then(Value::as_str),
        Some("PROVEN_VIA_CHILDREN")
    );

    let prior = c27_prior(json!({
        "ascending_state": "ASCENDING_OVERFLOW_TRIGGERED",
        "split_available": false,
    }));
    let packet = c27_packet(json!({"ordering": "ascending", "observed_total": 10}));
    let out = evaluate_detectors(&decl, &prior, &packet).expect("no axis evaluates");
    let asc = detector(record_value(&out), "ascending_overflow");
    assert_eq!(
        asc.get("state").and_then(Value::as_str),
        Some("TERMINAL_UNRECOVERABLE")
    );
    assert_eq!(
        asc.get("failure_reason").and_then(Value::as_str),
        Some("ascending_overflow_unrecoverable")
    );
}

// ---------------------------------------------------------------------------
// C27: evidence bundle, diagnostic domain, hashing, determinism
// ---------------------------------------------------------------------------

#[test]
fn c27_trigger_bundle_exports_all_evidence_and_audit() {
    let decl = c27_declaration(json!({}));
    let prior = c27_prior(json!({}));
    let packet = c27_packet(json!({
        "observed_total": 10,
        "request_sequence": 7,
        "request_coordinate": {"page": 7},
        "response_identity": "resp-7",
        "count_units": "postings",
    }));
    let out = evaluate_detectors(&decl, &prior, &packet).expect("triggered bundle evaluates");
    let value = record_value(&out);
    // No suppression: all five detectors are always present.
    let detectors = value.get("detectors").and_then(Value::as_array).expect("detectors array");
    assert_eq!(detectors.len(), 5);
    for name in ["row_cap", "saturation", "noop_parameter", "tail_clamp", "ascending_overflow"] {
        let found = detectors
            .iter()
            .any(|d| d.get("detector").and_then(Value::as_str) == Some(name));
        assert!(found, "detector {name} must be present");
    }
    let rowcap = detector(value, "row_cap");
    let evidence = rowcap.get("evidence").expect("trigger must carry evidence");
    // Detection boundary.
    let boundary = evidence.get("detection_boundary").expect("boundary");
    assert_eq!(boundary.get("request_sequence").and_then(Value::as_u64), Some(7));
    assert_eq!(boundary.get("observed_total").and_then(Value::as_u64), Some(10));
    // Scope.
    let scope = evidence.get("scope").expect("scope");
    assert_eq!(scope.get("target").and_then(Value::as_str), Some("il"));
    assert_eq!(scope.get("run_id").and_then(Value::as_str), Some("run-1"));
    assert_eq!(scope.get("partition_id").and_then(Value::as_str), Some("p-1"));
    // Response identity + request coordinate.
    assert_eq!(
        evidence.get("response_identity").and_then(Value::as_str),
        Some("resp-7")
    );
    assert_eq!(
        evidence.get("request_coordinate"),
        Some(&json!({"page": 7}))
    );
    // Units/count evidence.
    let counts = evidence.get("count_evidence").expect("count evidence");
    assert_eq!(counts.get("observed_total").and_then(Value::as_u64), Some(10));
    assert_eq!(counts.get("units").and_then(Value::as_str), Some("postings"));
    // ID/page signatures.
    assert!(evidence.get("id_signatures").is_some(), "ID signatures required");
    assert!(evidence.get("page_signatures").is_some(), "page signatures required");
    // Immediate action lives top-level; recovery + disposition in evidence.
    assert!(rowcap.get("action").and_then(Value::as_str).is_some());
    assert!(evidence.get("recovery").and_then(Value::as_str).is_some());
    assert!(evidence.get("disposition").and_then(Value::as_str).is_some());
    // Audit support is a normalized snapshot, never suppressed.
    let audit = evidence.get("audit_support").expect("audit support");
    let entity_id = audit.get("entity_id").and_then(Value::as_str).expect("entity id");
    assert!(!entity_id.is_empty(), "audit snapshot must have an entity id");
    let snapshot = audit.get("snapshot").expect("snapshot value");
    assert_eq!(
        snapshot.get("record_type").and_then(Value::as_str),
        Some("crawler_operational_snapshot")
    );
    let row = snapshot.get("row").and_then(Value::as_object).expect("snapshot row");
    assert_eq!(
        row.get("detector").and_then(Value::as_str),
        Some("row_cap")
    );
}

#[test]
fn c27_diagnostic_states_not_ledger_statuses() {
    let decl = c27_declaration(json!({}));
    let prior = c27_prior(json!({}));
    let packet = c27_packet(json!({"observed_total": 10}));
    let out = evaluate_detectors(&decl, &prior, &packet).expect("evaluation succeeds");
    let value = record_value(&out);
    assert_eq!(
        value.get("state_domain").and_then(Value::as_str),
        Some("diagnostic")
    );
    let ledger = value.get("ledger_status").expect("ledger_status present");
    assert_eq!(
        ledger.get("reason").and_then(Value::as_str),
        Some("not_applicable")
    );
    // Every detector state belongs to its diagnostic vocabulary.
    for (name, allowed) in [
        (
            "row_cap",
            vec![
                "MONITORING",
                "CAP_REACHED_TRIGGERED",
                "BISECTED",
                "PROVEN_VIA_CHILDREN",
                "TERMINAL_INCOMPLETE",
            ],
        ),
        (
            "saturation",
            vec![
                "UNSATURATED",
                "SATURATED_TRIGGERED",
                "BISECTED",
                "PROVEN_VIA_CHILDREN",
                "TERMINAL_INCOMPLETE",
            ],
        ),
        (
            "noop_parameter",
            vec![
                "ADVANCING",
                "SUSPECT_NOOP",
                "NOOP_CONFIRMED_TRIGGERED",
                "PARTITION_ONLY_OR_ALTERNATIVE_CURSOR",
                "TERMINAL_INCOMPLETE",
            ],
        ),
        (
            "tail_clamp",
            vec![
                "ADVANCING",
                "SUSPECT_TAIL_CLAMP",
                "TAIL_CLAMP_CONFIRMED_TRIGGERED",
                "BISECTED_BELOW_CAP",
                "PROVEN_VIA_CHILDREN",
                "TERMINAL_INCOMPLETE",
            ],
        ),
        (
            "ascending_overflow",
            vec![
                "MONITORING_ASCENDING",
                "DATE_REGRESSION_SUSPICION",
                "ASCENDING_OVERFLOW_TRIGGERED",
                "BISECTED",
                "PROVEN_VIA_CHILDREN",
                "TERMINAL_UNRECOVERABLE",
            ],
        ),
    ] {
        let state = detector(value, name)
            .get("state")
            .and_then(Value::as_str)
            .expect("state");
        assert!(allowed.contains(&state), "{name} state {state} must be diagnostic");
        assert!(
            !["proven", "covering", "failed", "ready"].contains(&state),
            "{name} state must not be a ledger status"
        );
    }
}

#[test]
fn c27_page_hash_reconciliation_rejects_wrong_bytes() {
    let decl = c27_declaration(json!({}));
    let prior = c27_prior(json!({}));
    // Matching bytes reconcile.
    let packet = c27_packet(json!({
        "page_hash": sh_for_bytes(b"exact-page-content"),
        "page_bytes": "exact-page-content",
    }));
    evaluate_detectors(&decl, &prior, &packet).expect("matching bytes must reconcile");
    // Wrong bytes are rejected, never silently adopted.
    let packet = c27_packet(json!({
        "page_hash": sh_for_bytes(b"exact-page-content"),
        "page_bytes": "tampered-content",
    }));
    let err = evaluate_detectors(&decl, &prior, &packet).expect_err("wrong bytes must fault");
    assert_eq!(err.code, "digest_mismatch");
    // Hash-of-hash is not the source digest.
    let inner = digest_bytes(b"exact-page-content");
    let outer = digest_bytes(inner.as_bytes());
    let packet = c27_packet(json!({
        "page_hash": sh_with_digest(&outer),
        "page_bytes": "exact-page-content",
    }));
    let err = evaluate_detectors(&decl, &prior, &packet).expect_err("hash-of-hash must fault");
    assert_eq!(err.code, "digest_mismatch");
    // Unknown framing is rejected.
    let mut bad = sh_for_bytes(b"exact-page-content");
    bad["profile"] = Value::String("unknown-profile/9".to_string());
    let packet = c27_packet(json!({
        "page_hash": bad,
        "page_bytes": "exact-page-content",
    }));
    let err = evaluate_detectors(&decl, &prior, &packet).expect_err("unknown profile must fault");
    assert_eq!(err.code, "unknown_profile");
    // Unavailable bytes still evaluate opaquely on digest text.
    let packet = c27_packet(json!({
        "page_hash": sh_for_bytes(b"exact-page-content"),
        "page_bytes": missing("not_observed"),
    }));
    evaluate_detectors(&decl, &prior, &packet).expect("missing bytes evaluate opaquely");
}

#[test]
fn c27_evaluation_is_deterministic() {
    let decl = c27_declaration(json!({}));
    let prior = c27_prior(json!({}));
    let packet = c27_packet(json!({"observed_total": 10}));
    let first = record_value(&evaluate_detectors(&decl, &prior, &packet).expect("first"))
        .clone();
    let second = record_value(&evaluate_detectors(&decl, &prior, &packet).expect("second"))
        .clone();
    assert_eq!(first, second, "identical inputs must yield identical outputs");
}

// ---------------------------------------------------------------------------
// C31 fixtures
// ---------------------------------------------------------------------------

fn c31_declaration(overrides: Value) -> CheckedRecord {
    let mut base = json!({
        "target": "il",
        "run_id": "run-1",
        "partition_id": "p-1",
        "owner_domain": "crawler",
        "captured_at": timepoint(60_000),
        "evidence_prefix": evidence_prefix(),
        "evidence_refs": evidence_refs(),
        "baseline_dup_rate": 0.02,
        "planned_over_fetch_factor": 1.5,
        "reconciliation_limit": 3,
    });
    if let Value::Object(extra) = overrides {
        for (k, v) in extra {
            base[k] = v;
        }
    }
    check("audit_log", base)
}

fn occurrence(job: &str, count: u64) -> Value {
    json!({
        "target": "il",
        "run_id": "run-1",
        "partition_id": "p-1",
        "walk_id": "walk-1",
        "job_id": job,
        "occurrence_count": count,
    })
}

fn audit_ref() -> Value {
    json!({
        "journal_id": "j-1",
        "sequence": 11,
        "event_id": "evt-11",
        "event_hash": "def",
        "pointer": "/drift",
    })
}

fn c31_observations(overrides: Value) -> CheckedRecord {
    let mut base = json!({
        "distinct_total": 100,
        "repeated_distinct_total": 2,
        "exact_occurrences": [occurrence("job-1", 3), occurrence("job-2", 2)],
        "backend_signature": "sig-A",
        "session_epoch": 7,
        "current_page_hash": sh_for_bytes(b"current-page"),
        "current_page_bytes": missing("not_observed"),
        "partition_definition_hash": sh_for_bytes(b"partition-def"),
        "max_date_posted": "2026-01-12",
        "missing_posted_date_total": 1,
        "min_job_id": "job-0001",
        "max_job_id": "job-0100",
        "cursor_revision": 5,
        "detected_at": missing("not_observed"),
        "audit_event_ref": audit_ref(),
    });
    if let Value::Object(extra) = overrides {
        for (k, v) in extra {
            base[k] = v;
        }
    }
    check("cursor_state", base)
}

fn c31_prior_ledger(overrides: Value) -> CheckedRecord {
    let mut base = json!({
        "backend_signature": "sig-A",
        "partition_definition_hash": sh_for_bytes(b"partition-def"),
        "max_date_posted": "2026-01-12",
        "distinct_total": 90,
        "repeated_distinct_total": 1,
        "current_page_hash": sh_for_bytes(b"prior-page"),
        "reconciliation_passes_used": 0,
        "cursor_revision": 4,
    });
    if let Value::Object(extra) = overrides {
        for (k, v) in extra {
            base[k] = v;
        }
    }
    check("coverage_ledger", base)
}

// ---------------------------------------------------------------------------
// C31: rates and bands
// ---------------------------------------------------------------------------

#[test]
fn c31_rates_bands_and_effective_floor() {
    // Low: 0.02 <= 1.5 * 0.02.
    let decl = c31_declaration(json!({"baseline_dup_rate": 0.02}));
    let obs = c31_observations(json!({
        "distinct_total": 100,
        "repeated_distinct_total": 2,
        "exact_occurrences": [occurrence("job-1", 3), occurrence("job-2", 2)],
    }));
    let prior = c31_prior_ledger(json!({}));
    let out = evaluate_drift(&decl, &obs, &prior).expect("low band evaluates");
    let value = record_value(&out);
    assert!((value.get("duplicate_rate").and_then(Value::as_f64).unwrap() - 0.02).abs() < 1e-12);
    assert_eq!(value.get("band").and_then(Value::as_str), Some("low"));
    assert_eq!(value.get("cursor_trusted_for_proof"), Some(&Value::Bool(true)));
    assert_eq!(value.get("reconciliation_passes").and_then(Value::as_u64), Some(1));

    // Medium: 0.05 within (0.03, 0.06].
    let obs = c31_observations(json!({
        "distinct_total": 100,
        "repeated_distinct_total": 5,
        "exact_occurrences": [
            occurrence("job-1", 2), occurrence("job-2", 2), occurrence("job-3", 4),
            occurrence("job-4", 2), occurrence("job-5", 3),
        ],
    }));
    let out = evaluate_drift(&decl, &obs, &prior).expect("medium band evaluates");
    let value = record_value(&out);
    assert_eq!(value.get("band").and_then(Value::as_str), Some("medium"));
    assert_eq!(value.get("cursor_trusted_for_proof"), Some(&Value::Bool(true)));
    assert_eq!(value.get("reconciliation_passes").and_then(Value::as_u64), Some(2));

    // High: 0.08 > 3 * 0.02 invalidates trust.
    let obs = c31_observations(json!({
        "distinct_total": 100,
        "repeated_distinct_total": 8,
        "exact_occurrences": [
            occurrence("job-1", 2), occurrence("job-2", 2), occurrence("job-3", 2),
            occurrence("job-4", 2), occurrence("job-5", 2), occurrence("job-6", 2),
            occurrence("job-7", 2), occurrence("job-8", 2),
        ],
    }));
    let out = evaluate_drift(&decl, &obs, &prior).expect("high band evaluates");
    let value = record_value(&out);
    assert_eq!(value.get("band").and_then(Value::as_str), Some("high"));
    assert_eq!(value.get("cursor_trusted_for_proof"), Some(&Value::Bool(false)));
    assert_eq!(value.get("reconciliation_passes").and_then(Value::as_u64), Some(3));

    // Effective floor: baseline 0 -> 0.001.
    let decl = c31_declaration(json!({"baseline_dup_rate": 0.0}));
    let obs = c31_observations(json!({
        "distinct_total": 1000,
        "repeated_distinct_total": 1,
        "exact_occurrences": [occurrence("job-1", 2)],
    }));
    let out = evaluate_drift(&decl, &obs, &prior).expect("zero baseline evaluates");
    let value = record_value(&out);
    assert!((value.get("effective_baseline").and_then(Value::as_f64).unwrap() - 0.001).abs() < 1e-12);
    assert_eq!(value.get("band").and_then(Value::as_str), Some("low"));

    // Zero distinct IDs give numeric zero.
    let obs = c31_observations(json!({
        "distinct_total": 0,
        "repeated_distinct_total": 0,
        "exact_occurrences": [],
    }));
    let out = evaluate_drift(&decl, &obs, &prior).expect("zero distinct evaluates");
    let value = record_value(&out);
    assert_eq!(value.get("duplicate_rate").and_then(Value::as_f64), Some(0.0));
    assert_eq!(value.get("band").and_then(Value::as_str), Some("low"));
}

#[test]
fn c31_repeated_distinct_arithmetic_not_total_occurrences() {
    let decl = c31_declaration(json!({"baseline_dup_rate": 0.02}));
    let prior = c31_prior_ledger(json!({}));
    // One ID repeated 100 times is one numerator unit: 1/3, not 100/102.
    let obs = c31_observations(json!({
        "distinct_total": 3,
        "repeated_distinct_total": 1,
        "exact_occurrences": [occurrence("job-1", 100), occurrence("job-2", 1), occurrence("job-3", 1)],
    }));
    let out = evaluate_drift(&decl, &obs, &prior).expect("single heavy repeat evaluates");
    let rate = record_value(&out).get("duplicate_rate").and_then(Value::as_f64).unwrap();
    assert!((rate - 1.0 / 3.0).abs() < 1e-12, "rate must be 1/3, got {rate}");

    // Claimed numerator disagreeing with exact occurrences is rejected.
    let obs = c31_observations(json!({
        "distinct_total": 3,
        "repeated_distinct_total": 1,
        "exact_occurrences": [occurrence("job-1", 5), occurrence("job-2", 4), occurrence("job-3", 1)],
    }));
    let err = evaluate_drift(&decl, &obs, &prior).expect_err("mismatched numerator must fault");
    assert_eq!(err.code, "duplicate_arithmetic_mismatch");

    // Numerator can never exceed the distinct denominator.
    let obs = c31_observations(json!({
        "distinct_total": 2,
        "repeated_distinct_total": 3,
        "exact_occurrences": [occurrence("job-1", 2)],
    }));
    let err = evaluate_drift(&decl, &obs, &prior).expect_err("repeated > distinct must fault");
    assert_eq!(err.code, "invalid_counts");
}

#[test]
fn c31_backend_cohorts_never_averaged() {
    let decl = c31_declaration(json!({}));
    // Changed backend signature opens a second coherent cohort.
    let obs = c31_observations(json!({"backend_signature": "sig-B"}));
    let prior = c31_prior_ledger(json!({"backend_signature": "sig-A"}));
    let out = evaluate_drift(&decl, &obs, &prior).expect("split cohort evaluates");
    let value = record_value(&out);
    let cohorts = value.get("cohorts").and_then(Value::as_array).expect("cohorts");
    assert_eq!(cohorts.len(), 2, "backend change must create separate cohorts");
    assert_eq!(value.get("totals_averaged"), Some(&Value::Bool(false)));
    let prior_cohort = cohorts.iter().find(|c| c.get("cohort").and_then(Value::as_str) == Some("prior")).expect("prior cohort");
    assert_eq!(prior_cohort.get("distinct_total").and_then(Value::as_u64), Some(90));
    let current_cohort = cohorts.iter().find(|c| c.get("cohort").and_then(Value::as_str) == Some("current")).expect("current cohort");
    assert_eq!(current_cohort.get("distinct_total").and_then(Value::as_u64), Some(100));

    // Same signature stays one cohort.
    let obs = c31_observations(json!({"backend_signature": "sig-A"}));
    let prior = c31_prior_ledger(json!({"backend_signature": "sig-A"}));
    let out = evaluate_drift(&decl, &obs, &prior).expect("single cohort evaluates");
    let cohorts = record_value(&out).get("cohorts").and_then(Value::as_array).expect("cohorts").clone();
    assert_eq!(cohorts.len(), 1);
    assert_eq!(
        record_value(&out).get("totals_averaged"),
        Some(&Value::Bool(false))
    );
}

#[test]
fn c31_reconciliation_bounded_to_three() {
    let decl = c31_declaration(json!({}));
    // Prior consumed two passes; medium (base 2) gets only one more.
    let obs = c31_observations(json!({
        "distinct_total": 100,
        "repeated_distinct_total": 5,
        "exact_occurrences": [
            occurrence("job-1", 2), occurrence("job-2", 2), occurrence("job-3", 4),
            occurrence("job-4", 2), occurrence("job-5", 3),
        ],
    }));
    let prior = c31_prior_ledger(json!({"reconciliation_passes_used": 2}));
    let out = evaluate_drift(&decl, &obs, &prior).expect("bounded reconciliation evaluates");
    let value = record_value(&out);
    assert_eq!(value.get("reconciliation_passes").and_then(Value::as_u64), Some(1));
    assert_eq!(value.get("reconciliation_total").and_then(Value::as_u64), Some(3));
    assert_eq!(value.get("reconciliation_bound").and_then(Value::as_u64), Some(3));

    // Exhausted budget grants zero further passes.
    let prior = c31_prior_ledger(json!({"reconciliation_passes_used": 3}));
    let out = evaluate_drift(&decl, &obs, &prior).expect("exhausted budget evaluates");
    let value = record_value(&out);
    assert_eq!(value.get("reconciliation_passes").and_then(Value::as_u64), Some(0));
    assert_eq!(value.get("reconciliation_total").and_then(Value::as_u64), Some(3));

    // Declaration limit beyond three is rejected.
    let decl = c31_declaration(json!({"reconciliation_limit": 4}));
    let prior = c31_prior_ledger(json!({}));
    let err = evaluate_drift(&decl, &obs, &prior).expect_err("limit 4 must fault");
    assert_eq!(err.code, "invalid_limit");

    // Prior usage beyond three is rejected.
    let decl = c31_declaration(json!({}));
    let prior = c31_prior_ledger(json!({"reconciliation_passes_used": 4}));
    let err = evaluate_drift(&decl, &obs, &prior).expect_err("prior overuse must fault");
    assert_eq!(err.code, "invalid_ledger");

    // Over-fetch factors are never proof, even at 2.0 under high drift.
    let decl = c31_declaration(json!({"planned_over_fetch_factor": 2.0}));
    let obs = c31_observations(json!({
        "distinct_total": 100,
        "repeated_distinct_total": 8,
        "exact_occurrences": [
            occurrence("job-1", 2), occurrence("job-2", 2), occurrence("job-3", 2),
            occurrence("job-4", 2), occurrence("job-5", 2), occurrence("job-6", 2),
            occurrence("job-7", 2), occurrence("job-8", 2),
        ],
    }));
    let prior = c31_prior_ledger(json!({}));
    let out = evaluate_drift(&decl, &obs, &prior).expect("high drift with factor evaluates");
    let value = record_value(&out);
    assert_eq!(value.get("over_fetch_is_proof"), Some(&Value::Bool(false)));
    assert_eq!(value.get("cursor_trusted_for_proof"), Some(&Value::Bool(false)));
}

#[test]
fn c31_date_regression_same_hash_only() {
    let decl = c31_declaration(json!({}));
    let same = sh_for_bytes(b"partition-def");
    // Same hash + earlier current date: regressed, with retained bounds.
    let obs = c31_observations(json!({
        "partition_definition_hash": same.clone(),
        "max_date_posted": "2026-01-05",
        "missing_posted_date_total": 4,
        "min_job_id": "job-0001",
        "max_job_id": "job-0099",
    }));
    let prior = c31_prior_ledger(json!({
        "partition_definition_hash": same.clone(),
        "max_date_posted": "2026-01-10",
    }));
    let out = evaluate_drift(&decl, &obs, &prior).expect("same-hash regression evaluates");
    let regression = record_value(&out).get("date_regression").expect("regression").clone();
    assert_eq!(regression.get("applicable"), Some(&Value::Bool(true)));
    assert_eq!(regression.get("regressed"), Some(&Value::Bool(true)));
    assert_eq!(regression.get("missing_posted_date_total").and_then(Value::as_u64), Some(4));
    assert_eq!(regression.get("min_job_id").and_then(Value::as_str), Some("job-0001"));
    assert_eq!(regression.get("max_job_id").and_then(Value::as_str), Some("job-0099"));

    // Same hash + later current date: no regression.
    let obs = c31_observations(json!({
        "partition_definition_hash": same.clone(),
        "max_date_posted": "2026-01-12",
    }));
    let out = evaluate_drift(&decl, &obs, &prior).expect("same-hash advance evaluates");
    let regression = record_value(&out).get("date_regression").expect("regression").clone();
    assert_eq!(regression.get("applicable"), Some(&Value::Bool(true)));
    assert_eq!(regression.get("regressed"), Some(&Value::Bool(false)));

    // Different hashes: dates incomparable even when earlier.
    let obs = c31_observations(json!({
        "partition_definition_hash": sh_for_bytes(b"partition-other"),
        "max_date_posted": "2026-01-01",
    }));
    let out = evaluate_drift(&decl, &obs, &prior).expect("different-hash evaluates");
    let regression = record_value(&out).get("date_regression").expect("regression").clone();
    assert_eq!(regression.get("applicable"), Some(&Value::Bool(false)));
    assert_eq!(regression.get("regressed"), Some(&Value::Bool(false)));

    // Missing hash: inapplicable.
    let obs = c31_observations(json!({
        "partition_definition_hash": missing_detail("not_observed", "no definition digest yet"),
        "max_date_posted": "2026-01-01",
    }));
    let out = evaluate_drift(&decl, &obs, &prior).expect("missing-hash evaluates");
    let regression = record_value(&out).get("date_regression").expect("regression").clone();
    assert_eq!(regression.get("applicable"), Some(&Value::Bool(false)));
}

#[test]
fn c31_drift_entry_shape_and_missingness() {
    let decl = c31_declaration(json!({}));
    let obs = c31_observations(json!({
        "distinct_total": 100,
        "repeated_distinct_total": 5,
        "exact_occurrences": [
            occurrence("job-1", 2), occurrence("job-2", 2), occurrence("job-3", 4),
            occurrence("job-4", 2), occurrence("job-5", 3),
        ],
        "session_epoch": 9,
    }));
    let prior = c31_prior_ledger(json!({}));
    let out = evaluate_drift(&decl, &obs, &prior).expect("drift entry evaluates");
    let value = record_value(&out);
    let entries = value.get("drift_entries").and_then(Value::as_array).expect("entries");
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    for key in [
        "detected_at", "kind", "severity", "duplicate_rate", "baseline",
        "previous_page_hash", "current_page_hash", "cursor_revision",
        "session_epoch", "backend_signature", "action", "audit_event_ref",
    ] {
        assert!(entry.get(key).is_some(), "drift entry must carry {key}");
    }
    assert_eq!(entry.get("severity").and_then(Value::as_str), Some("medium"));
    assert_eq!(entry.get("action").and_then(Value::as_str), Some("reconcile"));
    assert_eq!(entry.get("cursor_revision").and_then(Value::as_u64), Some(5));

    // Inapplicable prior boundary propagates inapplicable.
    let prior = c31_prior_ledger(json!({
        "current_page_hash": missing_detail("not_applicable", "no prior page at walk start"),
    }));
    let out = evaluate_drift(&decl, &obs, &prior).expect("boundary evaluates");
    let entry = &record_value(&out).get("drift_entries").and_then(Value::as_array).unwrap()[0];
    assert_eq!(
        entry.get("previous_page_hash").and_then(|v| v.get("reason")).and_then(Value::as_str),
        Some("not_applicable")
    );

    // Missing expected current evidence propagates not_observed.
    let obs = c31_observations(json!({
        "current_page_hash": missing_detail("not_observed", "response bytes lost"),
        "current_page_bytes": missing("not_observed"),
    }));
    let prior = c31_prior_ledger(json!({}));
    let out = evaluate_drift(&decl, &obs, &prior).expect("missing current evaluates");
    let entry = &record_value(&out).get("drift_entries").and_then(Value::as_array).unwrap()[0];
    assert_eq!(
        entry.get("current_page_hash").and_then(|v| v.get("reason")).and_then(Value::as_str),
        Some("not_observed")
    );

    // Malformed audit reference is rejected.
    let obs = c31_observations(json!({"audit_event_ref": {"journal_id": "j-1"}}));
    let err = evaluate_drift(&decl, &obs, &prior).expect_err("bad audit ref must fault");
    assert_eq!(err.code, "invalid_observations");
}

#[test]
fn c31_over_fetch_factors_accepted_not_proof() {
    for factor in [1.1, 1.5, 2.0] {
        let decl = c31_declaration(json!({"planned_over_fetch_factor": factor}));
        let obs = c31_observations(json!({}));
        let prior = c31_prior_ledger(json!({}));
        let out = evaluate_drift(&decl, &obs, &prior)
            .unwrap_or_else(|e| panic!("factor {factor} must evaluate: {} {}", e.code, e.detail));
        let value = record_value(&out);
        assert!((value.get("planned_over_fetch_factor").and_then(Value::as_f64).unwrap() - factor).abs() < 1e-12);
        assert_eq!(value.get("over_fetch_is_proof"), Some(&Value::Bool(false)));
    }
    let decl = c31_declaration(json!({"planned_over_fetch_factor": 0.9}));
    let obs = c31_observations(json!({}));
    let prior = c31_prior_ledger(json!({}));
    let err = evaluate_drift(&decl, &obs, &prior).expect_err("factor below 1 must fault");
    assert_eq!(err.code, "invalid_factor");
}

#[test]
fn c31_drift_page_hash_reconciliation() {
    let decl = c31_declaration(json!({}));
    let prior = c31_prior_ledger(json!({}));
    let obs = c31_observations(json!({
        "current_page_hash": sh_for_bytes(b"drift-page-content"),
        "current_page_bytes": "drift-page-content",
    }));
    evaluate_drift(&decl, &obs, &prior).expect("matching drift bytes must reconcile");
    let obs = c31_observations(json!({
        "current_page_hash": sh_for_bytes(b"drift-page-content"),
        "current_page_bytes": "tampered",
    }));
    let err = evaluate_drift(&decl, &obs, &prior).expect_err("wrong drift bytes must fault");
    assert_eq!(err.code, "digest_mismatch");
}

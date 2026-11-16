//! Conformance: [C26] coverage algebra and [C30] split tree.
//!
//! C26 covers equality/floor/lower-bound selection priority, the eleven
//! guards, duplicate non-substitution, render-coverage orthogonality, and the
//! zero rule. C30 covers split-axis priority, covering children, explicit
//! overlap with exact ID union, parent exploratory exclusion, and export
//! assembly.

use crawler_coverage::{build_coverage_export, evaluate_proof, plan_split};
use crawler_hashing::{canonical_bytes, digest_bytes};
use crawler_schema::{record_value, validate, CheckedRecord};
use serde_json::{json, Value};

fn check(schema: &str, value: Value) -> CheckedRecord {
    validate(schema, value).expect("fixture must satisfy the schema gate")
}

fn missing(reason: &str) -> Value {
    json!({"value": Value::Null, "reason": reason})
}

fn evidence_refs() -> Value {
    json!([{
        "journal_id": "j-1",
        "sequence": 10,
        "event_id": "evt-10",
        "event_hash": "abc",
        "pointer": "/coverage",
    }])
}

fn evidence_prefix() -> Value {
    json!({"journal_id": "j-1", "last_sequence": 10, "head_hash": "abc123"})
}

fn digest_for(value: &Value) -> String {
    let rec = validate("audit_log", value.clone()).expect("predicate must be gate-valid");
    let bytes = canonical_bytes(&rec).expect("canonical bytes");
    digest_bytes(&bytes)
}

fn sh_for_value(value: &Value) -> Value {
    json!({
        "value": digest_for(value),
        "profile": "kernel-jcs-sha256/1",
        "evidence_refs": [{"ref": "t"}],
    })
}

fn sh_with_digest(digest: &str) -> Value {
    json!({
        "value": digest,
        "profile": "kernel-jcs-sha256/1",
        "evidence_refs": [{"ref": "t"}],
    })
}

fn base_predicate() -> Value {
    json!({"filter": "all", "target": "il"})
}

fn apply_overrides(mut base: Value, overrides: Value) -> Value {
    if let Value::Object(extra) = overrides {
        for (k, v) in extra {
            base[k] = v;
        }
    }
    base
}

// ---------------------------------------------------------------------------
// C26 fixtures
// ---------------------------------------------------------------------------

fn c26_declaration(overrides: Value) -> CheckedRecord {
    let pred = base_predicate();
    let sh = sh_for_value(&pred);
    let base = json!({
        "target": "il",
        "run_id": "run-1",
        "partition_id": "p-1",
        "partition_predicate_json": pred,
        "partition_definition_hash": sh,
        "reported_total_unit": "postings",
        "session_min_count": 1,
        "evidence_refs": evidence_refs(),
        "evidence_prefix": evidence_prefix(),
    });
    check("audit_log", apply_overrides(base, overrides))
}

fn c26_ledger(overrides: Value) -> CheckedRecord {
    let pred = base_predicate();
    let sh = sh_for_value(&pred);
    let base = json!({
        "target": "il",
        "run_id": "run-1",
        "partition_id": "p-1",
        "partition_predicate_json": pred,
        "partition_definition_hash": sh,
        "reported_total": missing("not_observed"),
        "reported_total_unit": "postings",
        "reported_total_source": "verified_header",
        "count_source_verified": true,
        "floor_value": missing("not_applicable"),
        "header_label_is_floor": false,
        "saturation_marker_present": false,
        "session_reported_aggregates": [5, 8],
        "observed_total": 10,
        "distinct_observed_total": 10,
        "repeated_distinct_id_total": 0,
        "duplicate_rate": 0.0,
        "render_pass_total": 7,
        "session_count": 2,
        "terminated": true,
        "cursor_permitted": true,
        "replay_inflation_detected": false,
        "child_partition_ids": [],
        "parent_exploratory_total": 0,
        "evidence_refs": evidence_refs(),
    });
    check("coverage_ledger", apply_overrides(base, overrides))
}

fn c26_cohort(overrides: Value) -> CheckedRecord {
    let pred = base_predicate();
    let sh = sh_for_value(&pred);
    let base = json!({
        "cohort_refs": ["cursor:il:run-1:p-1:walk-1"],
        "count_units": "postings",
        "predicate_hash": sh,
        "cursor_permitted": true,
        "eligible_sessions": true,
        "replay_inflation_detected": false,
        "evidence_refs": evidence_refs(),
    });
    check("audit_log", apply_overrides(base, overrides))
}

fn c26_detectors(overrides: Value) -> CheckedRecord {
    let base = json!({"resolved": true});
    check("audit_log", apply_overrides(base, overrides))
}

fn detectors_raw(value: Value) -> CheckedRecord {
    check("audit_log", value)
}

fn guard_result(proof: &Value, guard_id: &str) -> String {
    proof
        .get("guards")
        .and_then(Value::as_array)
        .expect("proof carries guards")
        .iter()
        .find(|entry| entry.get("guard_id").and_then(Value::as_str) == Some(guard_id))
        .unwrap_or_else(|| panic!("guard {guard_id} present"))
        .get("result")
        .and_then(Value::as_str)
        .expect("guard result")
        .to_string()
}

fn resume_cursor() -> Value {
    json!({
        "target": "il",
        "run_id": "run-1",
        "partition_id": "p-1",
        "walk_id": "walk-1",
        "cursor_kind": "continuation",
        "ordering_model": "Deterministic",
        "coverage_scope": "per_run",
        "ordering_fingerprint": "fp-1",
    })
}

fn resume_session() -> Value {
    json!({"target": "il", "run_id": "run-1"})
}

fn resume_ordering(fingerprint: &str) -> Value {
    json!({
        "ordering_model": "Deterministic",
        "coverage_scope": "per_run",
        "ordering_fingerprint": fingerprint,
    })
}

// ---------------------------------------------------------------------------
// C26: coverage algebra
// ---------------------------------------------------------------------------

#[test]
fn c26_coverage_algebra() {
    // Lower-bound positive: distinct union covers the session max.
    let proof = evaluate_proof(
        &c26_declaration(json!({})),
        &c26_ledger(json!({})),
        &c26_cohort(json!({})),
        &c26_detectors(json!({})),
    )
    .expect("lower-bound proves");
    let value = record_value(&proof).clone();
    assert_eq!(value["proof_type"], "lower_bound");
    assert_eq!(value["status"], "proven");
    assert_eq!(value["pagination_coverage_proven"], true);
    assert_eq!(value["guards"].as_array().unwrap().len(), 11);
    for entry in value["guards"].as_array().unwrap() {
        let id = entry["guard_id"].as_str().unwrap();
        let result = entry["result"].as_str().unwrap();
        assert!(!entry["rationale"].as_str().unwrap().is_empty(), "guard {id} rationale");
        if id == "covering_children" {
            assert_eq!(result, "not_applicable");
        } else {
            assert_eq!(result, "established", "guard {id}");
        }
    }
    let render = value["render_coverage"].as_f64().unwrap();
    assert!((render - 0.7).abs() < 1e-9, "render 7/10, got {render}");
    assert!(value["failure_reason"].is_object(), "failure Missing when proven");

    // Floor positive: lower-bound inapplicable (max 20 > distinct 10).
    let proof = evaluate_proof(
        &c26_declaration(json!({})),
        &c26_ledger(json!({
            "session_reported_aggregates": [20],
            "floor_value": 8,
            "header_label_is_floor": true,
        })),
        &c26_cohort(json!({})),
        &c26_detectors(json!({})),
    )
    .expect("floor proves");
    let value = record_value(&proof).clone();
    assert_eq!(value["proof_type"], "floor");
    assert_eq!(value["pagination_coverage_proven"], true);

    // Floor requires distinct union, saturation vetoes.
    let proof = evaluate_proof(
        &c26_declaration(json!({})),
        &c26_ledger(json!({
            "session_reported_aggregates": [20],
            "floor_value": 8,
            "header_label_is_floor": true,
            "saturation_marker_present": true,
        })),
        &c26_cohort(json!({})),
        &c26_detectors(json!({})),
    )
    .expect("saturated floor evaluates");
    let value = record_value(&proof).clone();
    assert_eq!(value["pagination_coverage_proven"], false);
    assert_eq!(value["proof_type"], "none");

    // Equality positive: verified exact total, distinct agrees.
    let proof = evaluate_proof(
        &c26_declaration(json!({})),
        &c26_ledger(json!({
            "session_reported_aggregates": [20],
            "reported_total": 10,
        })),
        &c26_cohort(json!({})),
        &c26_detectors(json!({})),
    )
    .expect("equality proves");
    let value = record_value(&proof).clone();
    assert_eq!(value["proof_type"], "equality");
    assert_eq!(value["pagination_coverage_proven"], true);

    // Priority: lower-bound wins when every algebra matches.
    let proof = evaluate_proof(
        &c26_declaration(json!({})),
        &c26_ledger(json!({
            "reported_total": 10,
            "floor_value": 8,
            "header_label_is_floor": true,
        })),
        &c26_cohort(json!({})),
        &c26_detectors(json!({})),
    )
    .expect("priority evaluates");
    assert_eq!(record_value(&proof)["proof_type"], "lower_bound");

    // count_units guard.
    let proof = evaluate_proof(
        &c26_declaration(json!({})),
        &c26_ledger(json!({})),
        &c26_cohort(json!({"count_units": "openings"})),
        &c26_detectors(json!({})),
    )
    .expect("unit mismatch evaluates");
    let value = record_value(&proof).clone();
    assert_eq!(value["pagination_coverage_proven"], false);
    assert_eq!(guard_result(&value, "count_units"), "failed");
    assert_eq!(value["failure_reason"], "guard_failed_count_units");

    // predicate_identity: differing bytes fail.
    let proof = evaluate_proof(
        &c26_declaration(json!({})),
        &c26_ledger(json!({"partition_predicate_json": {"filter": "other"}})),
        &c26_cohort(json!({})),
        &c26_detectors(json!({})),
    )
    .expect("predicate mismatch evaluates");
    let value = record_value(&proof).clone();
    assert_eq!(guard_result(&value, "predicate_identity"), "failed");
    assert_eq!(value["pagination_coverage_proven"], false);

    // predicate_identity: wrong digest fails even when carried consistently.
    let wrong = "0".repeat(64);
    let proof = evaluate_proof(
        &c26_declaration(json!({"partition_definition_hash": sh_with_digest(&wrong)})),
        &c26_ledger(json!({"partition_definition_hash": sh_with_digest(&wrong)})),
        &c26_cohort(json!({"predicate_hash": sh_with_digest(&wrong)})),
        &c26_detectors(json!({})),
    )
    .expect("wrong digest evaluates");
    assert_eq!(
        guard_result(record_value(&proof), "predicate_identity"),
        "failed"
    );

    // predicate_identity: cohort digest disagreeing fails.
    let proof = evaluate_proof(
        &c26_declaration(json!({})),
        &c26_ledger(json!({})),
        &c26_cohort(json!({"predicate_hash": sh_with_digest(&"f".repeat(64))})),
        &c26_detectors(json!({})),
    )
    .expect("cohort digest mismatch evaluates");
    assert_eq!(
        guard_result(record_value(&proof), "predicate_identity"),
        "failed"
    );

    // count_source_verified guard.
    let proof = evaluate_proof(
        &c26_declaration(json!({})),
        &c26_ledger(json!({"count_source_verified": false})),
        &c26_cohort(json!({})),
        &c26_detectors(json!({})),
    )
    .expect("unverified source evaluates");
    assert_eq!(
        guard_result(record_value(&proof), "count_source_verified"),
        "failed"
    );

    // cursor_permitted guard.
    let proof = evaluate_proof(
        &c26_declaration(json!({})),
        &c26_ledger(json!({})),
        &c26_cohort(json!({"cursor_permitted": false})),
        &c26_detectors(json!({})),
    )
    .expect("unpermitted traversal evaluates");
    assert_eq!(
        guard_result(record_value(&proof), "cursor_permitted"),
        "failed"
    );

    // Embedded resume triple: valid triple keeps permission.
    let proof = evaluate_proof(
        &c26_declaration(json!({})),
        &c26_ledger(json!({})),
        &c26_cohort(json!({
            "cursor": resume_cursor(),
            "session": resume_session(),
            "ordering": resume_ordering("fp-1"),
        })),
        &c26_detectors(json!({})),
    )
    .expect("valid resume evaluates");
    let value = record_value(&proof).clone();
    assert_eq!(guard_result(&value, "cursor_permitted"), "established");
    assert_eq!(value["pagination_coverage_proven"], true);

    // Embedded resume triple: fingerprint drift fails permission.
    let proof = evaluate_proof(
        &c26_declaration(json!({})),
        &c26_ledger(json!({})),
        &c26_cohort(json!({
            "cursor": resume_cursor(),
            "session": resume_session(),
            "ordering": resume_ordering("fp-2"),
        })),
        &c26_detectors(json!({})),
    )
    .expect("drifted resume evaluates");
    assert_eq!(
        guard_result(record_value(&proof), "cursor_permitted"),
        "failed"
    );

    // detectors_resolved guard (simplified and full shapes).
    let proof = evaluate_proof(
        &c26_declaration(json!({})),
        &c26_ledger(json!({})),
        &c26_cohort(json!({})),
        &c26_detectors(json!({"resolved": false})),
    )
    .expect("unresolved detectors evaluate");
    assert_eq!(
        guard_result(record_value(&proof), "detectors_resolved"),
        "failed"
    );
    let full_blocking = detectors_raw(json!({
        "target": "il",
        "run_id": "run-1",
        "partition_id": "p-1",
        "state_domain": "diagnostic",
        "detectors": [{"detector": "row_cap", "blocking": true}],
        "blocking": true,
    }));
    let proof = evaluate_proof(
        &c26_declaration(json!({})),
        &c26_ledger(json!({})),
        &c26_cohort(json!({})),
        &full_blocking,
    )
    .expect("blocking detector shape evaluates");
    assert_eq!(
        guard_result(record_value(&proof), "detectors_resolved"),
        "failed"
    );

    // termination guard.
    let proof = evaluate_proof(
        &c26_declaration(json!({})),
        &c26_ledger(json!({"terminated": false})),
        &c26_cohort(json!({})),
        &c26_detectors(json!({})),
    )
    .expect("unterminated walk evaluates");
    assert_eq!(guard_result(record_value(&proof), "termination"), "failed");

    // no_replay_inflation guard (ledger and cohort).
    let proof = evaluate_proof(
        &c26_declaration(json!({})),
        &c26_ledger(json!({"replay_inflation_detected": true})),
        &c26_cohort(json!({})),
        &c26_detectors(json!({})),
    )
    .expect("ledger replay evaluates");
    assert_eq!(
        guard_result(record_value(&proof), "no_replay_inflation"),
        "failed"
    );
    let proof = evaluate_proof(
        &c26_declaration(json!({})),
        &c26_ledger(json!({})),
        &c26_cohort(json!({"replay_inflation_detected": true})),
        &c26_detectors(json!({})),
    )
    .expect("cohort replay evaluates");
    assert_eq!(
        guard_result(record_value(&proof), "no_replay_inflation"),
        "failed"
    );

    // no_duplicate_substitution: inflated observed cannot stand in for the
    // distinct union even when another algebra matches.
    let proof = evaluate_proof(
        &c26_declaration(json!({})),
        &c26_ledger(json!({
            "session_reported_aggregates": [5],
            "observed_total": 10,
            "distinct_observed_total": 7,
            "repeated_distinct_id_total": 3,
            "duplicate_rate": 3.0 / 7.0,
            "reported_total": 10,
        })),
        &c26_cohort(json!({})),
        &c26_detectors(json!({})),
    )
    .expect("duplicate substitution evaluates");
    let value = record_value(&proof).clone();
    assert_eq!(guard_result(&value, "no_duplicate_substitution"), "failed");
    assert_eq!(value["pagination_coverage_proven"], false);
    assert_eq!(value["failure_reason"], "guard_failed_no_duplicate_substitution");

    // no_duplicate_substitution: inconsistent rate fails.
    let proof = evaluate_proof(
        &c26_declaration(json!({})),
        &c26_ledger(json!({
            "distinct_observed_total": 7,
            "repeated_distinct_id_total": 2,
            "duplicate_rate": 0.0,
        })),
        &c26_cohort(json!({})),
        &c26_detectors(json!({})),
    )
    .expect("rate mismatch evaluates");
    assert_eq!(
        guard_result(record_value(&proof), "no_duplicate_substitution"),
        "failed"
    );

    // no_duplicate_substitution: distinct beyond observed fails.
    let proof = evaluate_proof(
        &c26_declaration(json!({})),
        &c26_ledger(json!({"distinct_observed_total": 12})),
        &c26_cohort(json!({})),
        &c26_detectors(json!({})),
    )
    .expect("distinct beyond observed evaluates");
    assert_eq!(
        guard_result(record_value(&proof), "no_duplicate_substitution"),
        "failed"
    );

    // no_duplicate_substitution: exact ID set must agree with the union.
    let proof = evaluate_proof(
        &c26_declaration(json!({})),
        &c26_ledger(json!({"observed_ids": ["a", "b", "c"]})),
        &c26_cohort(json!({})),
        &c26_detectors(json!({})),
    )
    .expect("ID set mismatch evaluates");
    assert_eq!(
        guard_result(record_value(&proof), "no_duplicate_substitution"),
        "failed"
    );

    // Exact ID union with duplicates proves via the distinct count.
    let proof = evaluate_proof(
        &c26_declaration(json!({})),
        &c26_ledger(json!({
            "session_reported_aggregates": [2],
            "observed_total": 3,
            "distinct_observed_total": 2,
            "repeated_distinct_id_total": 1,
            "duplicate_rate": 0.5,
            "render_pass_total": 2,
            "observed_ids": ["a", "a", "b"],
        })),
        &c26_cohort(json!({})),
        &c26_detectors(json!({})),
    )
    .expect("exact union proves");
    let value = record_value(&proof).clone();
    assert_eq!(guard_result(&value, "no_duplicate_substitution"), "established");
    assert_eq!(value["proof_type"], "lower_bound");
    assert_eq!(value["pagination_coverage_proven"], true);

    // Integer/string identities stay distinct in the union.
    let proof = evaluate_proof(
        &c26_declaration(json!({})),
        &c26_ledger(json!({
            "session_reported_aggregates": [2],
            "observed_total": 2,
            "distinct_observed_total": 2,
            "repeated_distinct_id_total": 0,
            "duplicate_rate": 0.0,
            "render_pass_total": 2,
            "observed_ids": [7, "7"],
        })),
        &c26_cohort(json!({})),
        &c26_detectors(json!({})),
    )
    .expect("typed union proves");
    assert_eq!(record_value(&proof)["pagination_coverage_proven"], true);

    // eligible_sessions: floor matches but no eligible session proves.
    let proof = evaluate_proof(
        &c26_declaration(json!({})),
        &c26_ledger(json!({
            "session_reported_aggregates": [20],
            "floor_value": 8,
            "header_label_is_floor": true,
            "session_count": 0,
        })),
        &c26_cohort(json!({})),
        &c26_detectors(json!({})),
    )
    .expect("zero sessions evaluate");
    let value = record_value(&proof).clone();
    assert_eq!(guard_result(&value, "eligible_sessions"), "failed");
    assert_eq!(value["failure_reason"], "guard_failed_eligible_sessions");

    // eligible_sessions: minimum not met.
    let proof = evaluate_proof(
        &c26_declaration(json!({"session_min_count": 2})),
        &c26_ledger(json!({
            "session_reported_aggregates": [20],
            "floor_value": 8,
            "header_label_is_floor": true,
            "session_count": 1,
        })),
        &c26_cohort(json!({})),
        &c26_detectors(json!({})),
    )
    .expect("minimum sessions evaluate");
    assert_eq!(
        guard_result(record_value(&proof), "eligible_sessions"),
        "failed"
    );

    // eligible_sessions: cohort veto.
    let proof = evaluate_proof(
        &c26_declaration(json!({})),
        &c26_ledger(json!({
            "session_reported_aggregates": [20],
            "floor_value": 8,
            "header_label_is_floor": true,
        })),
        &c26_cohort(json!({"eligible_sessions": false})),
        &c26_detectors(json!({})),
    )
    .expect("cohort veto evaluates");
    assert_eq!(
        guard_result(record_value(&proof), "eligible_sessions"),
        "failed"
    );

    // Zero rule: advertised zero still cannot prove.
    let proof = evaluate_proof(
        &c26_declaration(json!({})),
        &c26_ledger(json!({
            "session_reported_aggregates": [],
            "reported_total": 0,
            "observed_total": 0,
            "distinct_observed_total": 0,
            "repeated_distinct_id_total": 0,
            "duplicate_rate": 0.0,
            "render_pass_total": 0,
        })),
        &c26_cohort(json!({})),
        &c26_detectors(json!({})),
    )
    .expect("advertised zero evaluates");
    let value = record_value(&proof).clone();
    assert_eq!(value["pagination_coverage_proven"], false);
    assert_eq!(value["proof_type"], "none");
    assert_eq!(value["failure_reason"], "empty_unproven");
    assert_eq!(guard_result(&value, "positive_observations"), "failed");
    assert_eq!(value["render_coverage"]["reason"], "not_applicable");

    // Render coverage is orthogonal: zero and full render both prove.
    for render in [0, 10] {
        let proof = evaluate_proof(
            &c26_declaration(json!({})),
            &c26_ledger(json!({"render_pass_total": render})),
            &c26_cohort(json!({})),
            &c26_detectors(json!({})),
        )
        .expect("render sweep proves");
        assert_eq!(record_value(&proof)["pagination_coverage_proven"], true);
    }

    // covering_children: unproven children block; proven children admit.
    let proof = evaluate_proof(
        &c26_declaration(json!({})),
        &c26_ledger(json!({"child_partition_ids": ["p-a", "p-b"]})),
        &c26_cohort(json!({})),
        &c26_detectors(json!({})),
    )
    .expect("unproven children evaluate");
    let value = record_value(&proof).clone();
    assert_eq!(guard_result(&value, "covering_children"), "not_established");
    assert_eq!(value["pagination_coverage_proven"], false);
    let proof = evaluate_proof(
        &c26_declaration(json!({})),
        &c26_ledger(json!({
            "child_partition_ids": ["p-a", "p-b"],
            "children_proven": true,
            "child_coverage_refs": ["cov-a", "cov-b"],
        })),
        &c26_cohort(json!({})),
        &c26_detectors(json!({})),
    )
    .expect("proven children evaluate");
    let value = record_value(&proof).clone();
    assert_eq!(guard_result(&value, "covering_children"), "established");
    assert_eq!(value["pagination_coverage_proven"], true);

    // Parent exploratory counts never enter proof arithmetic.
    let proof = evaluate_proof(
        &c26_declaration(json!({})),
        &c26_ledger(json!({
            "observed_total": 5,
            "distinct_observed_total": 5,
            "render_pass_total": 5,
            "parent_exploratory_total": 10,
        })),
        &c26_cohort(json!({})),
        &c26_detectors(json!({})),
    )
    .expect("exploratory exclusion evaluates");
    let value = record_value(&proof).clone();
    assert_eq!(value["pagination_coverage_proven"], false);
    assert_eq!(value["failure_reason"], "no_proof_candidate");
    assert_eq!(value["equation_terms"]["parent_exploratory_included"], false);
    assert_eq!(value["equation_terms"]["parent_exploratory_total"], 10);

    // Structural faults.
    let err = evaluate_proof(
        &c26_declaration(json!({})),
        &c26_ledger(json!({"terminated": "yes"})),
        &c26_cohort(json!({})),
        &c26_detectors(json!({})),
    )
    .expect_err("bad termination type must fault");
    assert_eq!(err.code, "invalid_ledger");
    let err = evaluate_proof(
        &c26_declaration(json!({})),
        &c26_ledger(json!({})),
        &c26_cohort(json!({"cohort_refs": "not-an-array"})),
        &c26_detectors(json!({})),
    )
    .expect_err("bad cohort refs must fault");
    assert_eq!(err.code, "invalid_cohort");
    let err = evaluate_proof(
        &c26_declaration(json!({})),
        &c26_ledger(json!({})),
        &c26_cohort(json!({})),
        &detectors_raw(json!({})),
    )
    .expect_err("empty detectors must fault");
    assert_eq!(err.code, "invalid_detectors");
    let err = evaluate_proof(
        &c26_declaration(json!({})),
        &c26_ledger(json!({"target": "fr"})),
        &c26_cohort(json!({})),
        &c26_detectors(json!({})),
    )
    .expect_err("scope mismatch must fault");
    assert_eq!(err.code, "scope_mismatch");
    let err = evaluate_proof(
        &c26_declaration(json!({})),
        &c26_ledger(json!({"render_pass_total": 11})),
        &c26_cohort(json!({})),
        &c26_detectors(json!({})),
    )
    .expect_err("render beyond observed must fault");
    assert_eq!(err.code, "invalid_ledger");
}

// ---------------------------------------------------------------------------
// C30 fixtures
// ---------------------------------------------------------------------------

fn c30_split_declaration(overrides: Value) -> CheckedRecord {
    let base = json!({
        "target": "il",
        "run_id": "run-1",
        "parent_partition_id": "p-1",
        "declared_partition_keys": ["country"],
        "evidence_refs": evidence_refs(),
    });
    check("audit_log", apply_overrides(base, overrides))
}

fn c30_split_parent(overrides: Value) -> CheckedRecord {
    let base = json!({
        "target": "il",
        "run_id": "run-1",
        "partition_id": "p-1",
        "partition_predicate_json": {"values": [1, 2, 3, 4]},
        "split_round": 0,
        "parent_exploratory_total": 0,
    });
    check("coverage_ledger", apply_overrides(base, overrides))
}

fn c30_split_evidence(overrides: Value) -> CheckedRecord {
    let base = json!({
        "evidence_prefix": evidence_prefix(),
        "evidence_refs": evidence_refs(),
    });
    check("audit_log", apply_overrides(base, overrides))
}

fn export_ledger(overrides: Value) -> CheckedRecord {
    let base = json!({
        "target": "il",
        "run_id": "run-1",
        "partition_id": "p-1",
    });
    check("coverage_ledger", apply_overrides(base, overrides))
}

fn export_cursor(overrides: Value) -> CheckedRecord {
    let base = json!({
        "target": "il",
        "run_id": "run-1",
        "partition_id": "p-1",
        "walk_id": "walk-1",
    });
    check("cursor_state", apply_overrides(base, overrides))
}

fn detector_entry(blocking: bool, action: &str) -> Value {
    let mut entry = json!({
        "detector": "row_cap",
        "state": "MONITORING",
        "blocking": blocking,
        "corroboration_count": 0,
        "threshold": 1,
        "evidence_refs": evidence_refs(),
        "action": action,
    });
    entry["failure_reason"] = missing("not_applicable");
    entry
}

fn drift_value() -> Value {
    json!({
        "baseline_dup_rate": 0.02,
        "effective_baseline": 0.02,
        "duplicate_rate": 0.0,
        "band": "low",
        "planned_over_fetch_factor": 1.5,
        "reconciliation_passes": 0,
        "cursor_trusted_for_proof": true,
        "evidence_refs": evidence_refs(),
    })
}

fn export_evaluation(proof: Value, overrides: Value) -> CheckedRecord {
    let base = json!({
        "target": "il",
        "run_id": "run-1",
        "partition_id": "p-1",
        "declaration": {"id": "decl-1", "partition_id": "p-1"},
        "proof": proof,
        "detectors": [detector_entry(false, "monitor")],
        "drift": drift_value(),
        "measurements": [],
        "evidence_prefix": evidence_prefix(),
        "evidence_refs": evidence_refs(),
        "cursor_capability_status": "verified",
        "cursor_capability_evidence_refs": evidence_refs(),
        "uncertified_observations": [],
    });
    check("audit_log", apply_overrides(base, overrides))
}

fn positive_proof_value() -> Value {
    let proof = evaluate_proof(
        &c26_declaration(json!({})),
        &c26_ledger(json!({})),
        &c26_cohort(json!({})),
        &c26_detectors(json!({})),
    )
    .expect("baseline proof proves");
    record_value(&proof).clone()
}

// ---------------------------------------------------------------------------
// C30: split tree
// ---------------------------------------------------------------------------

#[test]
fn c30_split_tree() {
    // Axis priority: declared keys beat everything.
    let plan = plan_split(
        &c30_split_declaration(json!({})),
        &c30_split_parent(json!({})),
        &c30_split_evidence(json!({})),
    )
    .expect("declared axis splits");
    let value = record_value(&plan).clone();
    assert_eq!(value["split_possible"], true);
    assert_eq!(value["axis"], "country");
    assert_eq!(value["axis_priority"], "declared_partition_keys");
    assert_eq!(value["siblings_continue"], true);

    // Axis priority: primary, date, secondary fallbacks in order.
    let plan = plan_split(
        &c30_split_declaration(json!({
            "declared_partition_keys": [],
            "primary_key": "job_id",
            "verified_date_keys": ["date_posted"],
            "verified_secondary_keys": ["employer"],
        })),
        &c30_split_parent(json!({})),
        &c30_split_evidence(json!({})),
    )
    .expect("primary axis splits");
    assert_eq!(record_value(&plan)["axis_priority"], "primary_key");
    let plan = plan_split(
        &c30_split_declaration(json!({
            "declared_partition_keys": [],
            "verified_date_keys": ["date_posted"],
            "verified_secondary_keys": ["employer"],
        })),
        &c30_split_parent(json!({})),
        &c30_split_evidence(json!({})),
    )
    .expect("date axis splits");
    let value = record_value(&plan).clone();
    assert_eq!(value["axis"], "date_posted");
    assert_eq!(value["axis_priority"], "verified_date_keys");
    let plan = plan_split(
        &c30_split_declaration(json!({
            "declared_partition_keys": [],
            "verified_secondary_keys": ["employer"],
        })),
        &c30_split_parent(json!({})),
        &c30_split_evidence(json!({})),
    )
    .expect("secondary axis splits");
    assert_eq!(record_value(&plan)["axis_priority"], "verified_secondary_keys");

    // No axis: closed failure, siblings continue.
    let plan = plan_split(
        &c30_split_declaration(json!({"declared_partition_keys": []})),
        &c30_split_parent(json!({})),
        &c30_split_evidence(json!({})),
    )
    .expect("axisless split plans");
    let value = record_value(&plan).clone();
    assert_eq!(value["split_possible"], false);
    assert_eq!(value["failure_reason"], "no_bisection_axis_available");
    assert_eq!(value["siblings_continue"], true);
    let plan = plan_split(
        &c30_split_declaration(json!({
            "declared_partition_keys": [],
            "ascending_overflow_established": true,
        })),
        &c30_split_parent(json!({})),
        &c30_split_evidence(json!({})),
    )
    .expect("overflow without axis plans");
    assert_eq!(
        record_value(&plan)["failure_reason"],
        "ascending_overflow_unrecoverable"
    );

    // Maximum saturated depth is three.
    let err = plan_split(
        &c30_split_declaration(json!({})),
        &c30_split_parent(json!({"split_round": 3})),
        &c30_split_evidence(json!({})),
    )
    .expect_err("depth 3 must refuse");
    assert_eq!(err.code, "max_split_depth");
    let plan = plan_split(
        &c30_split_declaration(json!({})),
        &c30_split_parent(json!({"split_round": 2})),
        &c30_split_evidence(json!({})),
    )
    .expect("depth 2 splits to 3");
    assert_eq!(record_value(&plan)["child_split_round"], 3);

    // Set auto-bisection: covering, disjoint, hashed children.
    let plan = plan_split(
        &c30_split_declaration(json!({})),
        &c30_split_parent(json!({})),
        &c30_split_evidence(json!({})),
    )
    .expect("set auto-bisects");
    let value = record_value(&plan).clone();
    assert_eq!(value["covering"], true);
    assert_eq!(value["covering_evidence"], "exact_set_union");
    assert_eq!(value["overlap"], json!([]));
    assert_eq!(value["overlap_explicit"], true);
    assert_eq!(value["combination_rule"], "exact_id_union");
    assert_eq!(value["blind_addition_forbidden"], true);
    let children = value["children"].as_array().unwrap();
    assert_eq!(children.len(), 2);
    let mut union: Vec<Value> = Vec::new();
    for child in children {
        let predicate = &child["predicate_json"];
        let carried = child["predicate_hash"]["value"].as_str().unwrap();
        assert_eq!(digest_for(predicate), carried);
        union.extend(predicate["values"].as_array().unwrap().clone());
    }
    union.sort_by_key(|item| item.to_string());
    assert_eq!(union, vec![json!(1), json!(2), json!(3), json!(4)]);

    // Set proposed overlap is explicit, not added.
    let plan = plan_split(
        &c30_split_declaration(json!({})),
        &c30_split_parent(json!({"partition_predicate_json": {"values": [1, 2, 3]}})),
        &c30_split_evidence(json!({"proposed_children": [
            {"partition_id": "p-a", "predicate_json": {"values": [1, 2]}},
            {"partition_id": "p-b", "predicate_json": {"values": [2, 3]}},
        ]})),
    )
    .expect("overlapping sets plan");
    let value = record_value(&plan).clone();
    assert_eq!(value["covering"], true);
    assert_eq!(value["overlap"], json!([2]));
    assert_eq!(value["combination_rule"], "exact_id_union");

    // Set gap is not covering.
    let err = plan_split(
        &c30_split_declaration(json!({})),
        &c30_split_parent(json!({"partition_predicate_json": {"values": [1, 2, 3]}})),
        &c30_split_evidence(json!({"proposed_children": [
            {"partition_id": "p-a", "predicate_json": {"values": [1]}},
            {"partition_id": "p-b", "predicate_json": {"values": [2]}},
        ]})),
    )
    .expect_err("gapped sets must fault");
    assert_eq!(err.code, "non_covering_children");

    // Range auto-bisection tiles exactly.
    let plan = plan_split(
        &c30_split_declaration(json!({})),
        &c30_split_parent(json!({"partition_predicate_json": {"range": [1, 10]}})),
        &c30_split_evidence(json!({})),
    )
    .expect("range auto-bisects");
    let value = record_value(&plan).clone();
    assert_eq!(value["covering_evidence"], "exact_range_union");
    assert_eq!(value["overlap"], json!([]));
    let children = value["children"].as_array().unwrap();
    assert_eq!(children[0]["predicate_json"]["range"], json!([1, 5]));
    assert_eq!(children[1]["predicate_json"]["range"], json!([6, 10]));

    // Range proposed overlap is an explicit interval.
    let plan = plan_split(
        &c30_split_declaration(json!({})),
        &c30_split_parent(json!({"partition_predicate_json": {"range": [1, 10]}})),
        &c30_split_evidence(json!({"proposed_children": [
            {"partition_id": "p-a", "predicate_json": {"range": [1, 6]}},
            {"partition_id": "p-b", "predicate_json": {"range": [5, 10]}},
        ]})),
    )
    .expect("overlapping ranges plan");
    assert_eq!(record_value(&plan)["overlap"], json!([[5, 6]]));

    // Range gap is not covering.
    let err = plan_split(
        &c30_split_declaration(json!({})),
        &c30_split_parent(json!({"partition_predicate_json": {"range": [1, 10]}})),
        &c30_split_evidence(json!({"proposed_children": [
            {"partition_id": "p-a", "predicate_json": {"range": [1, 4]}},
            {"partition_id": "p-b", "predicate_json": {"range": [6, 10]}},
        ]})),
    )
    .expect_err("gapped ranges must fault");
    assert_eq!(err.code, "non_covering_children");

    // Opaque predicates need explicit children plus attestation.
    let err = plan_split(
        &c30_split_declaration(json!({})),
        &c30_split_parent(json!({"partition_predicate_json": {"op": "custom"}})),
        &c30_split_evidence(json!({})),
    )
    .expect_err("opaque auto-bisect must fault");
    assert_eq!(err.code, "explicit_children_required");
    let err = plan_split(
        &c30_split_declaration(json!({})),
        &c30_split_parent(json!({"partition_predicate_json": {"op": "custom"}})),
        &c30_split_evidence(json!({"proposed_children": [
            {"partition_id": "p-a", "predicate_json": {"op": "custom", "shard": 0}},
            {"partition_id": "p-b", "predicate_json": {"op": "custom", "shard": 1}},
        ]})),
    )
    .expect_err("unattested opaque must fault");
    assert_eq!(err.code, "covering_not_established");
    let plan = plan_split(
        &c30_split_declaration(json!({})),
        &c30_split_parent(json!({"partition_predicate_json": {"op": "custom"}})),
        &c30_split_evidence(json!({
            "proposed_children": [
                {"partition_id": "p-a", "predicate_json": {"op": "custom", "shard": 0}},
                {"partition_id": "p-b", "predicate_json": {"op": "custom", "shard": 1}},
            ],
            "covering_attested": true,
            "covering_evidence_refs": evidence_refs(),
            "overlap_ids": ["shared-1"],
        })),
    )
    .expect("attested opaque plans");
    let value = record_value(&plan).clone();
    assert_eq!(value["covering_evidence"], "explicit_attestation");
    assert_eq!(value["overlap"], json!(["shared-1"]));

    // Unsplittable predicates fault instead of inventing children.
    let err = plan_split(
        &c30_split_declaration(json!({})),
        &c30_split_parent(json!({"partition_predicate_json": {"values": [1]}})),
        &c30_split_evidence(json!({})),
    )
    .expect_err("singleton set must fault");
    assert_eq!(err.code, "unsplittable_predicate");

    // Parent exploratory counts are excluded from every plan.
    let plan = plan_split(
        &c30_split_declaration(json!({})),
        &c30_split_parent(json!({"parent_exploratory_total": 5})),
        &c30_split_evidence(json!({})),
    )
    .expect("exploratory parent plans");
    let value = record_value(&plan).clone();
    assert_eq!(value["parent_exploratory_total"], 5);
    assert_eq!(value["parent_exploratory_included_in_child_proof"], false);
    assert_eq!(value["child_proof_inputs_exclude_parent_exploratory"], true);

    // Proof-level covering: children required once they exist.
    let proof = evaluate_proof(
        &c26_declaration(json!({})),
        &c26_ledger(json!({"child_partition_ids": ["p-a", "p-b"]})),
        &c26_cohort(json!({})),
        &c26_detectors(json!({})),
    )
    .expect("parent without child proof evaluates");
    assert_eq!(record_value(&proof)["pagination_coverage_proven"], false);

    // Export happy path: closed record with framed references.
    let ledger = export_ledger(json!({}));
    let cursor = export_cursor(json!({}));
    let evaluation = export_evaluation(positive_proof_value(), json!({}));
    let export = build_coverage_export(&ledger, &[cursor], &evaluation).expect("export assembles");
    let value = record_value(&export).clone();
    assert_eq!(value["record_type"], "crawler_coverage_export");
    assert_eq!(value["schema_version"], "crawler-seam/0.1.0");
    assert_eq!(value["target"], "il");
    assert_eq!(value["run_id"], "run-1");
    assert_eq!(value["partition_id"], "p-1");
    assert_eq!(value["proof"]["proof_type"], "lower_bound");
    assert_eq!(value["proof"]["guards"].as_array().unwrap().len(), 11);
    assert_eq!(value["cursor_capability_status"], "verified");
    assert_eq!(value["detectors"].as_array().unwrap().len(), 1);
    assert_eq!(value["drift"]["band"], "low");
    assert!(value["ledger"]["digest"].as_str().unwrap().len() == 64);
    assert!(value["ledger"]["ledger_ref"].as_str().unwrap().contains("coverage_ledger"));
    let snapshots = value["cursor_snapshots"].as_array().unwrap();
    assert_eq!(snapshots.len(), 1);
    assert!(snapshots[0]["cursor_ref"].as_str().unwrap().contains("cursor_state"));
    assert_eq!(value["proof"]["equation_terms"]["parent_exploratory_included"], false);
    // Snapshot digest reproduces from the cursor bytes.
    let cursor_rec = export_cursor(json!({}));
    let bytes = canonical_bytes(&cursor_rec).expect("cursor bytes");
    assert_eq!(snapshots[0]["digest"], digest_bytes(&bytes));

    // Export with covering children.
    let proof = evaluate_proof(
        &c26_declaration(json!({})),
        &c26_ledger(json!({
            "child_partition_ids": ["p-a", "p-b"],
            "children_proven": true,
            "child_coverage_refs": ["cov-a", "cov-b"],
        })),
        &c26_cohort(json!({})),
        &c26_detectors(json!({})),
    )
    .expect("parent proof proves");
    let ledger = export_ledger(json!({"child_partition_ids": ["p-a", "p-b"]}));
    let evaluation = export_evaluation(record_value(&proof).clone(), json!({}));
    let export = build_coverage_export(&ledger, &[export_cursor(json!({}))], &evaluation)
        .expect("parent export assembles");
    assert!(!record_value(&export)["proof"]["child_coverage_refs"]
        .as_array()
        .unwrap()
        .is_empty());

    // Export rejects childless proof for a parent with children.
    let ledger = export_ledger(json!({"child_partition_ids": ["p-a"]}));
    let evaluation = export_evaluation(positive_proof_value(), json!({}));
    let err = build_coverage_export(&ledger, &[export_cursor(json!({}))], &evaluation)
        .expect_err("uncovered children must fault");
    assert_eq!(err.code, "invalid_proof");

    // Export rejects positive proof on blocking detectors.
    let evaluation = export_evaluation(
        positive_proof_value(),
        json!({"detectors": [detector_entry(true, "stop_walk")]}),
    );
    let err = build_coverage_export(&export_ledger(json!({})), &[export_cursor(json!({}))], &evaluation)
        .expect_err("blocking detectors must fault");
    assert_eq!(err.code, "invalid_proof");

    // Export rejects proofs with a missing guard.
    let mut tampered = positive_proof_value();
    tampered
        .get_mut("guards")
        .and_then(Value::as_array_mut)
        .unwrap()
        .pop();
    let evaluation = export_evaluation(tampered, json!({}));
    let err = build_coverage_export(&export_ledger(json!({})), &[export_cursor(json!({}))], &evaluation)
        .expect_err("missing guard must fault");
    assert_eq!(err.code, "invalid_proof");

    // Export rejects bad drift, bad capability, and foreign cursors.
    let mut bad_drift = drift_value();
    bad_drift["planned_over_fetch_factor"] = json!(0.5);
    let evaluation = export_evaluation(positive_proof_value(), json!({"drift": bad_drift}));
    let err = build_coverage_export(&export_ledger(json!({})), &[export_cursor(json!({}))], &evaluation)
        .expect_err("bad drift must fault");
    assert_eq!(err.code, "invalid_drift");
    let evaluation = export_evaluation(
        positive_proof_value(),
        json!({"cursor_capability_status": "maybe"}),
    );
    let err = build_coverage_export(&export_ledger(json!({})), &[export_cursor(json!({}))], &evaluation)
        .expect_err("bad capability must fault");
    assert_eq!(err.code, "invalid_evaluation");
    let err = build_coverage_export(
        &export_ledger(json!({})),
        &[export_cursor(json!({"target": "fr"}))],
        &export_evaluation(positive_proof_value(), json!({})),
    )
    .expect_err("foreign cursor must fault");
    assert_eq!(err.code, "scope_mismatch");
}

//! [C02] recursive-null conformance: bare normalized nulls are rejected,
//! all six reasons are preserved, and unknown reasons are rejected.

use crawler_schema::{record_schema, record_value, validate};
use serde_json::json;

fn missing(reason: &str) -> serde_json::Value {
    json!({"value": null, "reason": reason})
}

/// Bare top-level normalized null is rejected. [C02]
#[test]
fn c02_bare_null_rejected() {
    let err = validate("listing", serde_json::Value::Null).expect_err("bare null must be rejected");
    assert!(!err.code.is_empty(), "fault must carry a code");
}

/// Recursive bare nulls anywhere in the value are rejected. [C02]
#[test]
fn c02_recursive_nulls_rejected() {
    for value in [
        json!({"title": null}),
        json!({"nested": {"posted_date": null}}),
        json!([missing("not_observed"), null]),
        json!({"rows": [{"url": "https://example.com/a"}, {"url": null}]}),
    ] {
        validate("listing", value).expect_err("recursive bare null must be rejected");
    }
}

/// All six kernel reasons are preserved through the gate. [C02]
#[test]
fn c02_all_six_reasons_preserved() {
    for reason in [
        "not_enabled",
        "not_applicable",
        "not_observed",
        "observation_lost",
        "unsupported_by_subject",
        "manual_override",
    ] {
        let record = validate("listing", json!({"field": missing(reason)}))
            .unwrap_or_else(|e| panic!("reason {reason:?} must be preserved, got {}", e.detail));
        assert_eq!(record_schema(&record), "listing");
        assert_eq!(record_value(&record)["field"]["reason"], json!(reason));
    }
}

/// Unknown reasons and reason-like shapes are rejected. [C02]
#[test]
fn c02_unknown_reason_rejected() {
    for value in [
        json!({"field": {"value": null, "reason": "unknown"}}),
        json!({"field": {"value": null, "reason": "n/a"}}),
        json!({"field": {"value": null, "reason": ""}}),
        json!({"field": {"value": null}}),
        json!({"field": {"value": null, "reason": null}}),
        json!({"field": {"reason": "not_observed"}}),
        json!({"field": {"value": null, "reason": "not_observed", "extra": 1}}),
        json!({"field": {"value": 0, "reason": "not_observed"}}),
    ] {
        validate("listing", value).expect_err("unknown reason shape must be rejected");
    }
}

/// Real values that only resemble missingness still validate. [C02]
#[test]
fn c02_real_values_distinct_from_missing() {
    let record = validate(
        "seen_ids",
        json!({
            "ids": [],
            "zero": 0,
            "no": false,
            "empty": "",
            "absent": missing("not_observed"),
        }),
    )
    .expect("empty collections, zero, false, and empty string are real values");
    assert_eq!(record_value(&record)["ids"], json!([]));
}

/// Domain `reason` data fields coexist with Missing envelopes. [C02]
#[test]
fn c02_data_reason_field_accepted() {
    // ClassifierResult-style row: `reason` is bounded domain text ("Exact
    // accepted explanation"), not a null marker. Must validate alongside
    // genuine Missing envelopes nested in the same record.
    let record = validate(
        "classifier_result",
        json!({
            "target": "job-001",
            "job_id": "job-001",
            "stage": "description",
            "model_version": "clf-7",
            "input_hash": "0123456789abcdef",
            "verdict": "PASS",
            "verdict_applied": "PASS",
            "confidence": 0.97,
            "reason": "Exact accepted explanation with sibling keys",
            "classified_at": missing("not_applicable"),
            "latency_ms": 12,
            "model_artifact_digest": "aa",
            "tokenizer_digest": "bb",
            "prompt_digest": "cc",
            "canonicalization_version": "canon-2",
        }),
    )
    .expect("domain reason text alongside sibling keys must validate");
    assert_eq!(
        record_value(&record)["reason"],
        json!("Exact accepted explanation with sibling keys")
    );
}

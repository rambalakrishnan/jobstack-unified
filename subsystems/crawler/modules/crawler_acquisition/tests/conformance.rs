//! Conformance tests for `crawler_acquisition`.
//!
//! * **[C13] — Render cases:** failed-render content is all reasoned
//!   `Missing`; a `Pass` with missing or mistyped required extraction is
//!   rejected as `incomplete_extraction`, never materialized and never
//!   reclassified as failed rendering.
//! * **[C14] — Structured IL:** HTML masquerading as JSON is rejected as
//!   `challenge_masquerade`; an empty valid result stays `empty_unproven`
//!   and is never positive coverage.

use crawler_acquisition::{extract_accepted_content, normalize_structured_response};
use crawler_hashing::digest_bytes;
use crawler_schema::{record_value, validate, CheckedRecord};
use serde_json::{json, Value};

fn check(value: Value) -> CheckedRecord {
    validate("audit_log", value).expect("fixture must validate")
}

fn missing(reason: &str) -> Value {
    json!({"value": Value::Null, "reason": reason})
}

fn assert_no_bare_nulls(value: &Value) {
    match value {
        Value::Null => panic!("produced record contains a bare JSON null"),
        Value::Array(items) => items.iter().for_each(assert_no_bare_nulls),
        Value::Object(map) => {
            if map.get("value").is_some_and(Value::is_null) {
                assert!(
                    map.get("reason").and_then(Value::as_str).is_some(),
                    "Missing envelope requires a reason"
                );
                for (key, item) in map {
                    if key != "value" {
                        assert_no_bare_nulls(item);
                    }
                }
            } else {
                map.values().for_each(assert_no_bare_nulls);
            }
        }
        _ => {}
    }
}

fn decl_entry(name: &str, kind: &str, required: bool) -> Value {
    json!({
        "name": name,
        "type": kind,
        "required": required,
        "nullable": !required,
        "extraction": {"name": "il-extractor", "version": "3"},
    })
}

fn content_declaration() -> CheckedRecord {
    check(json!({
        "target": "IL-A",
        "declarations": [
            decl_entry("title", "string", true),
            decl_entry("employer", "string", true),
            decl_entry("description", "string", true),
            decl_entry("snippet", "string", false),
            decl_entry("posted_date", "timestamp", false),
            decl_entry("location", "string", false),
            decl_entry("direct_apply_url", "string", false),
            decl_entry("portal_type", "string", false),
            decl_entry("closing_date", "string", false),
        ],
    }))
}

fn pass_content() -> Value {
    json!({
        "title": "Software Engineer",
        "employer": "State of Illinois",
        "snippet": "Exciting role with the state.",
        "description": "Full description of the role.",
        "posted_date": "2026-11-01",
        "location": missing("not_observed"),
        "direct_apply_url": missing("not_observed"),
        "portal_type": missing("not_observed"),
        "closing_date": missing("not_observed"),
        "extended": [],
    })
}

fn pass_acquisition() -> CheckedRecord {
    check(json!({
        "render_verdict": "Pass",
        "render_basis": "engine_classify_pass",
        "pipeline_state": "ready",
        "content": pass_content(),
        "evidence_refs": [{"journal_id": "j-1", "event_id": "e-1"}],
    }))
}

fn failed_acquisition() -> CheckedRecord {
    check(json!({
        "render_verdict": "ThinShell",
        "render_basis": "engine_classify_thinshell",
        "pipeline_state": "render_failed",
        "content": {
            "title": missing("not_observed"),
            "employer": missing("not_observed"),
            "snippet": missing("not_observed"),
            "description": missing("not_observed"),
            "posted_date": missing("not_observed"),
            "location": missing("not_observed"),
            "direct_apply_url": missing("not_applicable"),
            "portal_type": missing("not_observed"),
            "closing_date": missing("not_observed"),
            "extended": [],
        },
        "snippet_classifier_result_ref": missing("not_applicable"),
        "description_classifier_result_ref": missing("not_applicable"),
        "final_genuine_result_ref": missing("not_applicable"),
        // Earlier snippet results remain historical evidence under Case B.
        "snippet_history": {"runs": ["run-7"], "last_snippet": "cached text"},
        "evidence_refs": [{"journal_id": "j-1", "event_id": "e-2"}],
    }))
}

fn mutate_content(acquisition: &CheckedRecord, key: &str, value: Value) -> CheckedRecord {
    let mut owned = record_value(acquisition).clone();
    owned
        .as_object_mut()
        .expect("acquisition object")
        .get_mut("content")
        .expect("content")
        .as_object_mut()
        .expect("content object")
        .insert(key.to_string(), value);
    check(owned)
}

fn remove_content_key(acquisition: &CheckedRecord, key: &str) -> CheckedRecord {
    let mut owned = record_value(acquisition).clone();
    owned
        .as_object_mut()
        .expect("acquisition object")
        .get_mut("content")
        .expect("content")
        .as_object_mut()
        .expect("content object")
        .remove(key);
    check(owned)
}

fn mutate_top(acquisition: &CheckedRecord, key: &str, value: Value) -> CheckedRecord {
    let mut owned = record_value(acquisition).clone();
    owned
        .as_object_mut()
        .expect("acquisition object")
        .insert(key.to_string(), value);
    check(owned)
}

fn structured_declaration() -> CheckedRecord {
    check(json!({
        "target": "IL-A",
        "postings_field": "postings",
        "id_field": "posting_id",
        "required_structured_fields": ["posting_id", "title"],
    }))
}

fn structured_response(body: &str, extra: Value) -> CheckedRecord {
    let mut base = serde_json::Map::new();
    base.insert(
        "media_type".to_string(),
        json!("application/json; charset=utf-8"),
    );
    base.insert(
        "endpoint".to_string(),
        json!("https://illinois.example/api/postings"),
    );
    base.insert("engine_verdict".to_string(), json!("Pass"));
    base.insert("body".to_string(), Value::String(body.to_string()));
    base.insert(
        "evidence_refs".to_string(),
        json!([{"journal_id": "j-1", "event_id": "e-9"}]),
    );
    if let Value::Object(overlay) = extra {
        for (key, value) in overlay {
            base.insert(key, value);
        }
    }
    check(Value::Object(base))
}

const VALID_BODY: &str = r#"{"postings": [{"posting_id": "IL-1", "title": "Engineer", "description": "Do things well."}, {"posting_id": "IL-2", "title": "Analyst"}], "total": 2}"#;

// ---------------------------------------------------------------------------
// C13: render cases
// ---------------------------------------------------------------------------

#[test]
fn c13_pass_complete_content_accepted() {
    let out = extract_accepted_content(&pass_acquisition(), &content_declaration())
        .expect("complete Pass must be accepted");
    let value = record_value(&out);
    assert_no_bare_nulls(value);
    assert_eq!(value.get("acceptance").and_then(Value::as_str), Some("accepted"));
    assert_eq!(
        value.get("render_verdict").and_then(Value::as_str),
        Some("Pass")
    );
    assert_eq!(
        value.get("pipeline_state").and_then(Value::as_str),
        Some("ready")
    );
    let content = value.get("content").expect("accepted content");
    assert_eq!(
        content.get("title").and_then(Value::as_str),
        Some("Software Engineer")
    );
    assert_eq!(
        content.get("description").and_then(Value::as_str),
        Some("Full description of the role.")
    );
    // Optional unobserved slots stay reasoned Missing, never invented.
    assert_eq!(
        content
            .get("location")
            .and_then(|v| v.get("reason"))
            .and_then(Value::as_str),
        Some("not_observed")
    );
    // Optional missingness is inventoried, and supporting refs echo through.
    let missing_fields = value
        .get("missing_fields")
        .and_then(Value::as_array)
        .expect("missing_fields array");
    let names: Vec<&str> = missing_fields
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(
        names,
        vec![
            "location",
            "direct_apply_url",
            "portal_type",
            "closing_date"
        ]
    );
    assert_eq!(
        value.get("evidence_refs"),
        Some(&json!([{"journal_id": "j-1", "event_id": "e-1"}]))
    );
}

#[test]
fn c13_pass_accepts_all_case_a_detail_states() {
    for state in ["pending_classification", "ready", "vetoed", "failed"] {
        let acquisition = mutate_top(&pass_acquisition(), "pipeline_state", json!(state));
        let out = extract_accepted_content(&acquisition, &content_declaration())
            .unwrap_or_else(|err| panic!("Pass with state {state:?} must be accepted: {err:?}"));
        assert_eq!(
            record_value(&out).get("acceptance").and_then(Value::as_str),
            Some("accepted")
        );
    }
}

#[test]
fn c13_pass_missing_required_rejected_as_incomplete_extraction() {
    // Remove each required field, or replace it with a Missing envelope: the
    // successful-content write is rejected, never materialized.
    for field in ["title", "employer", "description"] {
        let removed = remove_content_key(&pass_acquisition(), field);
        let err = extract_accepted_content(&removed, &content_declaration())
            .expect_err(&format!("Pass without {field} must be rejected"));
        assert_eq!(err.code, "incomplete_extraction", "field {field}");
        assert!(
            err.detail.contains(field),
            "detail names the missing field: {}",
            err.detail
        );

        let nulled = mutate_content(&pass_acquisition(), field, missing("not_observed"));
        let err = extract_accepted_content(&nulled, &content_declaration())
            .expect_err(&format!("Pass with Missing {field} must be rejected"));
        assert_eq!(err.code, "incomplete_extraction", "field {field}");
    }
    // A known-inapplicable reason does not excuse a required field either.
    let inapplicable = mutate_content(&pass_acquisition(), "title", missing("not_applicable"));
    let err = extract_accepted_content(&inapplicable, &content_declaration())
        .expect_err("Pass with not_applicable title must be rejected");
    assert_eq!(err.code, "incomplete_extraction");
}

#[test]
fn c13_pass_wrong_type_rejected_as_incomplete_extraction() {
    for (field, bad) in [
        ("title", json!(42)),
        ("employer", json!(true)),
        ("description", json!({"text": "shaped wrong"})),
        ("description", json!(["a", "list"])),
    ] {
        let acquisition = mutate_content(&pass_acquisition(), field, bad);
        let err = extract_accepted_content(&acquisition, &content_declaration())
            .expect_err("mistyped required content must be rejected");
        assert_eq!(err.code, "incomplete_extraction", "field {field}");
        assert!(
            err.detail.contains(field),
            "detail names the mistyped field: {}",
            err.detail
        );
    }
    // Mistyped optional content is rejected too: correctly typed or Missing.
    let acquisition = mutate_content(&pass_acquisition(), "snippet", json!(7));
    let err = extract_accepted_content(&acquisition, &content_declaration())
        .expect_err("mistyped optional content must be rejected");
    assert_eq!(err.code, "incomplete_extraction");
}

#[test]
fn c13_pass_type_vocabulary_boundaries() {
    // integer rejects fractions; number accepts them; empty arrays satisfy
    // required array fields; timestamps accept preserved text or objects.
    let declaration = check(json!({
        "target": "IL-A",
        "declarations": [
            decl_entry("title", "integer", true),
            decl_entry("snippet", "array", true),
            decl_entry("posted_date", "timestamp", true),
        ],
    }));
    let base = check(json!({
        "render_verdict": "Pass",
        "render_basis": "test",
        "pipeline_state": "ready",
        "content": {
            "title": 7,
            "snippet": [],
            "posted_date": "2026-11-01",
            "extended": [],
        },
    }));
    extract_accepted_content(&base, &declaration).expect("integer/array/timestamp floor");

    let fraction = mutate_content(&base, "title", json!(1.5));
    let err = extract_accepted_content(&fraction, &declaration)
        .expect_err("fractional integer must be rejected");
    assert_eq!(err.code, "incomplete_extraction");

    let number_decl = check(json!({
        "target": "IL-A",
        "declarations": [decl_entry("title", "number", true)],
    }));
    let number_ok = mutate_content(&base, "title", json!(1.5));
    extract_accepted_content(&number_ok, &number_decl).expect("number accepts fractions");

    let object_stamp = mutate_content(&base, "posted_date", json!({"iso": "2026-11-01"}));
    extract_accepted_content(&object_stamp, &declaration).expect("timestamp accepts objects");
    let numeric_stamp = mutate_content(&base, "posted_date", json!(20261101));
    let err = extract_accepted_content(&numeric_stamp, &declaration)
        .expect_err("numeric timestamp must be rejected");
    assert_eq!(err.code, "incomplete_extraction");

    let boolean_decl = check(json!({
        "target": "IL-A",
        "declarations": [decl_entry("snippet", "boolean", false)],
    }));
    let boolean_bad = mutate_content(&base, "snippet", json!("yes"));
    let err = extract_accepted_content(&boolean_bad, &boolean_decl)
        .expect_err("string for boolean must be rejected");
    assert_eq!(err.code, "incomplete_extraction");
    let boolean_ok = mutate_content(&base, "snippet", json!(true));
    extract_accepted_content(&boolean_ok, &boolean_decl).expect("boolean accepts booleans");
}

#[test]
fn c13_pass_render_failed_state_is_incomplete_extraction_not_case_b() {
    // A Pass carrying render_failed is not Case B and not a valid write: it
    // fails as incomplete extraction, never as an accepted failed render.
    let acquisition = mutate_top(&pass_acquisition(), "pipeline_state", json!("render_failed"));
    let err = extract_accepted_content(&acquisition, &content_declaration())
        .expect_err("Pass with render_failed must be rejected");
    assert_eq!(err.code, "incomplete_extraction");

    let bogus = mutate_top(&pass_acquisition(), "pipeline_state", json!("bogus"));
    let err = extract_accepted_content(&bogus, &content_declaration())
        .expect_err("Pass with unknown state must be rejected");
    assert_eq!(err.code, "incomplete_extraction");
}

#[test]
fn c13_pass_extended_entries_enforced() {
    let declaration = check(json!({
        "target": "IL-A",
        "declarations": [
            decl_entry("title", "string", true),
            decl_entry("salary", "string", true),
            decl_entry("clearance", "string", false),
        ],
    }));
    let with_extended = mutate_content(
        &pass_acquisition(),
        "extended",
        json!([
            {"name": "salary", "type": "string", "value": "$100k"},
            {"name": "clearance", "type": "string", "value": missing("not_observed")},
        ]),
    );
    let out = extract_accepted_content(&with_extended, &declaration)
        .expect("declared extended content must be accepted");
    let missing_fields = record_value(&out)
        .get("missing_fields")
        .and_then(Value::as_array)
        .expect("missing_fields");
    assert!(missing_fields.contains(&json!("clearance")));
    assert!(!missing_fields.contains(&json!("salary")));

    // Required extended value Missing is incomplete extraction.
    let missing_salary = mutate_content(
        &pass_acquisition(),
        "extended",
        json!([{"name": "salary", "type": "string", "value": missing("not_observed")}]),
    );
    let err = extract_accepted_content(&missing_salary, &declaration)
        .expect_err("Missing required extended value must be rejected");
    assert_eq!(err.code, "incomplete_extraction");

    // Entry type conflicting with the declaration is rejected.
    let conflict = mutate_content(
        &pass_acquisition(),
        "extended",
        json!([{"name": "salary", "type": "integer", "value": 100}]),
    );
    let err = extract_accepted_content(&conflict, &declaration)
        .expect_err("conflicting extended type must be rejected");
    assert_eq!(err.code, "incomplete_extraction");

    // Extended names cannot shadow core slots.
    let shadow = mutate_content(
        &pass_acquisition(),
        "extended",
        json!([{"name": "title", "type": "string", "value": "shadow"}]),
    );
    let err = extract_accepted_content(&shadow, &declaration)
        .expect_err("shadowing extended name must be rejected");
    assert_eq!(err.code, "invalid_acquisition");
}

#[test]
fn c13_nonpass_all_missing_accepted_as_render_failed() {
    for verdict in [
        "ThinShell",
        "RenderIncomplete",
        "EdgeBlock",
        "SensorFail",
        "ChallengeIncomplete",
    ] {
        let acquisition = mutate_top(&failed_acquisition(), "render_verdict", json!(verdict));
        let out = extract_accepted_content(&acquisition, &content_declaration())
            .unwrap_or_else(|err| panic!("Case B {verdict} must be accepted: {err:?}"));
        let value = record_value(&out);
        assert_no_bare_nulls(value);
        assert_eq!(
            value.get("acceptance").and_then(Value::as_str),
            Some("render_failed")
        );
        assert_eq!(
            value.get("pipeline_state").and_then(Value::as_str),
            Some("render_failed")
        );
        let content = value.get("content").expect("failed content");
        for slot in [
            "title",
            "employer",
            "snippet",
            "description",
            "posted_date",
            "location",
            "direct_apply_url",
            "portal_type",
            "closing_date",
        ] {
            let slot_value = content.get(slot).unwrap_or_else(|| panic!("{slot} present"));
            assert!(
                slot_value.get("value").is_some_and(Value::is_null)
                    && slot_value.get("reason").and_then(Value::as_str).is_some(),
                "{slot} carries reasoned missingness"
            );
        }
    }
    // Declared extended values may be present as Missing under Case B.
    let declaration = check(json!({
        "target": "IL-A",
        "declarations": [decl_entry("salary", "string", true)],
    }));
    let extended_missing = mutate_content(
        &failed_acquisition(),
        "extended",
        json!([{"name": "salary", "type": "string", "value": missing("not_observed")}]),
    );
    extract_accepted_content(&extended_missing, &declaration)
        .expect("Case B with Missing extended values must be accepted");
}

#[test]
fn c13_nonpass_established_content_rejected() {
    for (field, value) in [
        ("title", json!("Leaked title")),
        ("employer", json!("Leaked employer")),
        ("description", json!("Leaked description")),
        ("direct_apply_url", json!("https://example.invalid/apply")),
    ] {
        let acquisition = mutate_content(&failed_acquisition(), field, value);
        let err = extract_accepted_content(&acquisition, &content_declaration())
            .expect_err("established Case B content must be rejected");
        assert_eq!(err.code, "invalid_render_case", "field {field}");
    }
    // Established extended values are barred as well.
    let extended_leak = mutate_content(
        &failed_acquisition(),
        "extended",
        json!([{"name": "salary", "type": "string", "value": "$100k"}]),
    );
    let err = extract_accepted_content(&extended_leak, &content_declaration())
        .expect_err("established Case B extended value must be rejected");
    assert_eq!(err.code, "invalid_render_case");
    // Absence is not reasoned missingness under Case B.
    let absent = remove_content_key(&failed_acquisition(), "title");
    let err = extract_accepted_content(&absent, &content_declaration())
        .expect_err("absent Case B slot must be rejected");
    assert_eq!(err.code, "invalid_render_case");
}

#[test]
fn c13_nonpass_requires_render_failed_state() {
    for state in ["pending_classification", "ready", "vetoed", "failed"] {
        let acquisition = mutate_top(&failed_acquisition(), "pipeline_state", json!(state));
        let err = extract_accepted_content(&acquisition, &content_declaration())
            .expect_err("non-Pass without render_failed must be rejected");
        assert_eq!(err.code, "invalid_render_case", "state {state}");
    }
}

#[test]
fn c13_nonpass_bars_current_results_and_membership() {
    for field in [
        "snippet_classifier_result_ref",
        "description_classifier_result_ref",
        "final_genuine_result_ref",
    ] {
        let acquisition = mutate_top(
            &failed_acquisition(),
            field,
            json!({"ref": "cfr-1", "verdict": "genuine"}),
        );
        let err = extract_accepted_content(&acquisition, &content_declaration())
            .expect_err("current Case B result must be rejected");
        assert_eq!(err.code, "invalid_render_case", "field {field}");
    }
    let seen = mutate_top(
        &failed_acquisition(),
        "seen_membership",
        json!({"shard": "a", "inserted": true}),
    );
    let err = extract_accepted_content(&seen, &content_declaration())
        .expect_err("Case B seen membership must be rejected");
    assert_eq!(err.code, "invalid_render_case");
}

#[test]
fn c13_declaration_contract_rejects_malformed_contracts() {
    let bad_type = check(json!({
        "declarations": [decl_entry("title", "text", true)],
    }));
    let err = extract_accepted_content(&pass_acquisition(), &bad_type)
        .expect_err("unknown declared type must be rejected");
    assert_eq!(err.code, "invalid_declaration");

    let nullable_required = check(json!({
        "declarations": [json!({
            "name": "title", "type": "string", "required": true, "nullable": true,
            "extraction": {"name": "e", "version": "1"},
        })],
    }));
    let err = extract_accepted_content(&pass_acquisition(), &nullable_required)
        .expect_err("required+nullable must be rejected");
    assert_eq!(err.code, "invalid_declaration");

    let missing_pin = check(json!({
        "declarations": [json!({
            "name": "title", "type": "string", "required": true, "nullable": false,
        })],
    }));
    let err = extract_accepted_content(&pass_acquisition(), &missing_pin)
        .expect_err("missing extraction pin must be rejected");
    assert_eq!(err.code, "invalid_declaration");

    let duplicate = check(json!({
        "declarations": [decl_entry("title", "string", true), decl_entry("title", "string", false)],
    }));
    let err = extract_accepted_content(&pass_acquisition(), &duplicate)
        .expect_err("duplicate declarations must be rejected");
    assert_eq!(err.code, "invalid_declaration");

    // Malformed acquisition shells fail as malformed input, not render cases.
    let no_verdict = mutate_top(&pass_acquisition(), "render_verdict", missing("not_observed"));
    let err = extract_accepted_content(&no_verdict, &content_declaration())
        .expect_err("missing verdict must be rejected");
    assert_eq!(err.code, "invalid_acquisition");
    let no_content = mutate_top(&pass_acquisition(), "content", missing("not_observed"));
    let err = extract_accepted_content(&no_content, &content_declaration())
        .expect_err("missing content shell must be rejected");
    assert_eq!(err.code, "invalid_acquisition");

    // With no declarations the core title is the required floor.
    let empty_decl = check(json!({"target": "IL-A"}));
    extract_accepted_content(&pass_acquisition(), &empty_decl)
        .expect("undeclared Pass with title must be accepted");
    let no_title = mutate_content(&pass_acquisition(), "title", missing("not_observed"));
    let err = extract_accepted_content(&no_title, &empty_decl)
        .expect_err("undeclared Pass without title must be rejected");
    assert_eq!(err.code, "incomplete_extraction");
}

// ---------------------------------------------------------------------------
// C14: structured IL responses
// ---------------------------------------------------------------------------

#[test]
fn c14_valid_structured_payload_accepted() {
    let out = normalize_structured_response(
        &structured_response(VALID_BODY, json!({})),
        &structured_declaration(),
    )
    .expect("valid structured payload must be accepted");
    let value = record_value(&out);
    assert_no_bare_nulls(value);
    assert_eq!(
        value.get("render_basis").and_then(Value::as_str),
        Some("validated_structured_payload")
    );
    assert_eq!(
        value.get("normalizer_version").and_then(Value::as_str),
        Some("crawler-acquisition-structured/1")
    );
    // Raw bytes are hashed exactly and retained verbatim for extraction.
    assert_eq!(
        value.get("payload_hash").and_then(Value::as_str),
        Some(digest_bytes(VALID_BODY.as_bytes()).as_str())
    );
    assert_eq!(
        value.get("raw_body").and_then(Value::as_str),
        Some(VALID_BODY)
    );
    let payload = value.get("payload").expect("retained payload");
    assert_eq!(
        payload
            .get("postings")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(2)
    );
    assert_eq!(
        payload
            .get("postings")
            .and_then(|p| p.get(0))
            .and_then(|e| e.get("posting_id"))
            .and_then(Value::as_str),
        Some("IL-1")
    );
    assert_eq!(value.get("posting_count"), Some(&json!(2)));
    // Engine verdict passes through untouched.
    assert_eq!(
        value.get("engine_verdict").and_then(Value::as_str),
        Some("Pass")
    );
    // Deterministic escaped evidence for engine classification.
    let html = value
        .get("classifier_evidence_html")
        .and_then(Value::as_str)
        .expect("classifier evidence html");
    assert!(html.starts_with("<div class=\"structured-evidence\""));
    assert!(html.contains("&quot;IL-1&quot;"), "payload is escaped: {html}");
    assert!(!html.contains("\"IL-1\""), "no raw quotes leak: {html}");
    // JSON nulls inside the payload become reasoned Missing, never bare nulls.
    let nulled = normalize_structured_response(
        &structured_response(
            r#"{"postings": [{"posting_id": "IL-9", "title": null}]}"#,
            json!({}),
        ),
        &structured_declaration(),
    )
    .expect_err("null title violates the required structured field");
    assert_eq!(nulled.code, "invalid_structured_payload");
}

#[test]
fn c14_html_masquerading_as_json_rejected() {
    for body in [
        "<!DOCTYPE html><html><head><title>Just a moment...</title></head><body>Verifying you are human. <form>captcha</form></body></html>",
        "<html><body>Access Denied: challenge required</body></html>",
        "Just a moment... please enable JavaScript. Cloudflare Ray ID 123.",
        "<HTML><HEAD><TITLE>Attention Required</TITLE></HEAD></HTML>",
    ] {
        let err = normalize_structured_response(
            &structured_response(body, json!({})),
            &structured_declaration(),
        )
        .expect_err("masquerading challenge must be rejected");
        assert_eq!(err.code, "challenge_masquerade", "body {body:?}");
    }
    // A parsed envelope whose top-level strings carry document markers is the
    // same masquerade dressed as success.
    let enveloped = structured_response(
        r#"{"status": "ok", "page": "<html><body>captcha required</body></html>", "postings": []}"#,
        json!({}),
    );
    let err = normalize_structured_response(&enveloped, &structured_declaration())
        .expect_err("enveloped masquerade must be rejected");
    assert_eq!(err.code, "challenge_masquerade");
    // But legitimate posting text is never screened: inline formatting and
    // ordinary words inside entries are content, not challenges.
    let legit = structured_response(
        r#"{"postings": [{"posting_id": "IL-3", "title": "Coach", "description": "<p>Take on new challenges</p> with <b>grit</b>."}]}"#,
        json!({}),
    );
    normalize_structured_response(&legit, &structured_declaration())
        .expect("inline markup in posting text must be accepted");
}

#[test]
fn c14_empty_valid_result_remains_unproven() {
    let out = normalize_structured_response(
        &structured_response(r#"{"postings": [], "total": 0}"#, json!({})),
        &structured_declaration(),
    )
    .expect("empty valid result must normalize");
    let value = record_value(&out);
    assert_no_bare_nulls(value);
    let coverage = value.get("coverage").expect("coverage");
    assert_eq!(
        coverage.get("status").and_then(Value::as_str),
        Some("empty_unproven")
    );
    assert_eq!(
        coverage.get("pagination_coverage_proven"),
        Some(&json!(false))
    );
    assert_eq!(coverage.get("observed_total"), Some(&json!(0)));
    assert_eq!(
        coverage
            .get("render_coverage")
            .and_then(|v| v.get("reason"))
            .and_then(Value::as_str),
        Some("not_observed"),
        "render coverage stays null for empty results"
    );
    // Nonempty results are equally unproven by this module: proof belongs to
    // the coverage seam, never to normalization.
    let out = normalize_structured_response(
        &structured_response(VALID_BODY, json!({})),
        &structured_declaration(),
    )
    .expect("nonempty valid result must normalize");
    let coverage = record_value(&out).get("coverage").expect("coverage");
    assert_eq!(
        coverage.get("status").and_then(Value::as_str),
        Some("open")
    );
    assert_eq!(
        coverage.get("pagination_coverage_proven"),
        Some(&json!(false))
    );
    assert_eq!(coverage.get("observed_total"), Some(&json!(2)));
}

#[test]
fn c14_malformed_payloads_rejected() {
    // Unparsable and non-challenge is malformed, not a masquerade.
    let err = normalize_structured_response(
        &structured_response("not json at all {{{", json!({})),
        &structured_declaration(),
    )
    .expect_err("garbage body must be rejected");
    assert_eq!(err.code, "invalid_structured_payload");
    // Top level must be an object.
    let err = normalize_structured_response(
        &structured_response(r#"[{"posting_id": "IL-1"}]"#, json!({})),
        &structured_declaration(),
    )
    .expect_err("array top level must be rejected");
    assert_eq!(err.code, "invalid_structured_payload");
    // Postings must be an array.
    let err = normalize_structured_response(
        &structured_response(r#"{"postings": {"posting_id": "IL-1"}}"#, json!({})),
        &structured_declaration(),
    )
    .expect_err("non-array postings must be rejected");
    assert_eq!(err.code, "invalid_structured_payload");
    // Missing postings array.
    let err = normalize_structured_response(
        &structured_response(r#"{"total": 0}"#, json!({})),
        &structured_declaration(),
    )
    .expect_err("missing postings must be rejected");
    assert_eq!(err.code, "invalid_structured_payload");
    // Missing posting ID, empty ID, and non-object entry.
    for body in [
        r#"{"postings": [{"title": "No ID"}]}"#,
        r#"{"postings": [{"posting_id": "", "title": "Blank ID"}]}"#,
        r#"{"postings": ["IL-1"]}"#,
    ] {
        let err = normalize_structured_response(
            &structured_response(body, json!({})),
            &structured_declaration(),
        )
        .expect_err(&format!("bad posting ID must be rejected: {body}"));
        assert_eq!(err.code, "invalid_structured_payload", "body {body}");
    }
    // Missing configured required structured field.
    let err = normalize_structured_response(
        &structured_response(r#"{"postings": [{"posting_id": "IL-1"}]}"#, json!({})),
        &structured_declaration(),
    )
    .expect_err("missing required structured field must be rejected");
    assert_eq!(err.code, "invalid_structured_payload");
    assert!(err.detail.contains("title"), "detail names field: {}", err.detail);
    // Blank body is malformed.
    let err = normalize_structured_response(
        &structured_response("   ", json!({})),
        &structured_declaration(),
    )
    .expect_err("blank body must be rejected");
    assert_eq!(err.code, "invalid_structured_payload");
}

#[test]
fn c14_media_type_validated() {
    // JSON spellings with parameters, suffixes, and casing are accepted.
    for media_type in [
        "application/json",
        "application/json; charset=utf-8",
        "Application/JSON",
        "application/problem+json",
        "application/vnd.illinois.postings+json; charset=utf-8",
    ] {
        let response = structured_response(VALID_BODY, json!({"media_type": media_type}));
        normalize_structured_response(&response, &structured_declaration())
            .unwrap_or_else(|err| panic!("media type {media_type:?} must be accepted: {err:?}"));
    }
    // Anything else is not a structured response.
    for media_type in ["text/html", "text/plain", "application/xml", "json", ""] {
        let response = structured_response(VALID_BODY, json!({"media_type": media_type}));
        let err = normalize_structured_response(&response, &structured_declaration())
            .expect_err(&format!("media type {media_type:?} must be rejected"));
        assert_eq!(err.code, "invalid_media_type", "media type {media_type:?}");
    }
    let untyped = structured_response(
        VALID_BODY,
        json!({"media_type": missing("not_observed")}),
    );
    let err = normalize_structured_response(&untyped, &structured_declaration())
        .expect_err("missing media type must be rejected");
    assert_eq!(err.code, "invalid_media_type");
}

#[test]
fn c14_no_manufactured_description_no_verdict_override() {
    // Entries without descriptions keep no description key: the normalizer
    // never invents one.
    let out = normalize_structured_response(
        &structured_response(
            r#"{"postings": [{"posting_id": "IL-4", "title": "No description"}]}"#,
            json!({}),
        ),
        &structured_declaration(),
    )
    .expect("description-less entry must normalize");
    let entry = record_value(&out)
        .get("payload")
        .and_then(|p| p.get("postings"))
        .and_then(|p| p.get(0))
        .expect("entry");
    assert!(
        entry.get("description").is_none(),
        "no description manufactured: {entry}"
    );
    // A non-Pass engine verdict passes through untouched, never upgraded.
    let out = normalize_structured_response(
        &structured_response(VALID_BODY, json!({"engine_verdict": "ChallengeIncomplete"})),
        &structured_declaration(),
    )
    .expect("challenged verdict must normalize");
    assert_eq!(
        record_value(&out).get("engine_verdict").and_then(Value::as_str),
        Some("ChallengeIncomplete")
    );
    // Deterministic evidence: same input twice, and key order, agree.
    let first = normalize_structured_response(
        &structured_response(VALID_BODY, json!({})),
        &structured_declaration(),
    )
    .expect("first normalization");
    let second = normalize_structured_response(
        &structured_response(VALID_BODY, json!({})),
        &structured_declaration(),
    )
    .expect("second normalization");
    let reordered = normalize_structured_response(
        &structured_response(
            r#"{"total": 2, "postings": [{"title": "Engineer", "posting_id": "IL-1", "description": "Do things well."}, {"title": "Analyst", "posting_id": "IL-2"}]}"#,
            json!({}),
        ),
        &structured_declaration(),
    )
    .expect("reordered normalization");
    let html = |record: &CheckedRecord| {
        record_value(record)
            .get("classifier_evidence_html")
            .and_then(Value::as_str)
            .expect("evidence html")
            .to_string()
    };
    assert_eq!(html(&first), html(&second));
    assert_eq!(html(&first), html(&reordered));
}

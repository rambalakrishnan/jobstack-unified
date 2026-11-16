#![recursion_limit = "512"]
//! Conformance: [C01] complete field inventory — every source column in all
//! eleven entities survives normalized snapshot conversion.

use crawler_normalization::{assemble_crawler_value, normalize_row};
use crawler_schema::{record_value, validate, CheckedRecord, SourceEntity};
use serde_json::{json, Value};

fn missing(reason: &str) -> Value {
    json!({"value": null, "reason": reason})
}

fn missing_detail(reason: &str, detail: &str) -> Value {
    json!({"value": null, "reason": reason, "detail": detail})
}

fn timepoint(offset_ms: i64) -> Value {
    json!({
        "clock_id": "lease-clk",
        "boot_id": "boot-7",
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

fn evidence() -> CheckedRecord {
    validate(
        "audit_log",
        json!({
            "captured_at": timepoint(50_000),
            "evidence_prefix": {"journal_id": "j-1", "last_sequence": 10, "head_hash": "abc123"},
            "evidence_refs": evidence_refs(),
        }),
    )
    .expect("evidence fixture must satisfy the schema gate")
}

fn evidence_with_clocks() -> CheckedRecord {
    validate(
        "audit_log",
        json!({
            "captured_at": timepoint(50_000),
            "evidence_prefix": {"journal_id": "j-1", "last_sequence": 10, "head_hash": "abc123"},
            "evidence_refs": evidence_refs(),
            "clocks": [{"clock_id": "lease-clk", "boot_id": "boot-7"}],
            "receipt": missing("not_observed"),
        }),
    )
    .expect("clock evidence fixture must satisfy the schema gate")
}

fn sh(byte: char) -> Value {
    json!({
        "value": byte.to_string().repeat(64),
        "profile": "artifact-sha256/1",
        "evidence_refs": [{"ref": "test"}],
    })
}

fn artifact_ref() -> Value {
    json!({
        "digest": format!("sha256:{}", "b".repeat(64)),
        "size_bytes": 128,
        "media_type": "application/octet-stream",
        "owner_domain": "crawler",
        "access": "restricted",
    })
}

fn measurement(name: &str) -> Value {
    json!({
        "measurement_id": format!("m-{name}"),
        "name": name,
        "scope": {"kind": "connector_call", "id": "call-1"},
        "quantity": "duration",
        "unit": "ms",
        "origin": "engine_measured",
        "clock_id": "lease-clk",
        "boot_id": "boot-7",
        "method": "endpoint_difference",
        "start": timepoint(1000),
        "end": timepoint(1250),
        "estimate": {"kind": "exact", "value": 250},
        "resolution": 1,
        "censoring": "none",
        "comparability_group": missing("not_applicable"),
    })
}

fn measurement_evidence(name: &str) -> Value {
    json!({"measurement": measurement(name), "evidence_refs": evidence_refs()})
}

fn common_claimable() -> Value {
    json!({
        "target": "illinois",
        "job_id": "job-1",
        "active_run_id": "run-1",
        "entity_revision": 1,
        "input_revision": 1,
        "retry_count": 0,
        "max_retries_effective": 3,
        "lease_id": missing("not_applicable"),
        "lease_owner": missing("not_applicable"),
        "leased_at": missing("not_applicable"),
        "lease_expires_at": missing("not_applicable"),
        "last_failure_reason": missing("not_applicable"),
        "created_at": timepoint(1000),
        "updated_at": timepoint(2000),
    })
}

fn merge(base: Value, extra: Value) -> Value {
    let mut map = base.as_object().cloned().expect("base must be object");
    for (k, v) in extra.as_object().expect("extra must be object") {
        map.insert(k.clone(), v.clone());
    }
    Value::Object(map)
}

fn listing_source() -> Value {
    merge(
        common_claimable(),
        json!({
            "first_seen_run_id": "run-1",
            "last_seen_run_id": "run-1",
            "first_seen_at": timepoint(1100),
            "last_seen_at": timepoint(2100),
            "partition_id": "part-1",
            "listing_page_url": "https://example.com/listings?page=1",
            "source_url": "https://example.com/listings?page=1",
            "source_response_hash": sh('a'),
            "source_page_hash": sh('c'),
            "extractor_version": "ext-1",
            "title": "Software Engineer",
            "employer": "Acme",
            "snippet": "",
            "full_description": missing("not_applicable"),
            "posted_date": "2024-05-01",
            "extracted_fields_json": {"title": "Software Engineer", "confidence": 0.9},
            "classification_surface": "phase_a_full_description",
            "pipeline_state": "pending_finalize",
            "content_verdict": missing("not_applicable"),
            "verdict_applied": missing("not_applicable"),
            "classifier_result_ref": missing("not_applicable"),
            "classification_policy_revision": missing("not_applicable"),
            "bypass_reason": missing("not_applicable"),
            "delegated_work_item_ref": missing("not_applicable"),
            "finalized_detail_ref": missing("not_applicable"),
            "custom_source_column": "preserved",
        }),
    )
}

fn classifier_source() -> Value {
    json!({
        "target": "illinois",
        "job_id": "job-1",
        "stage": "snippet",
        "model_version": "slm-1",
        "input_hash": sh('d'),
        "verdict": "PASS",
        "verdict_applied": "PASS",
        "confidence": 0.92,
        "reason": "Relevant to Illinois slice",
        "classified_at": timepoint(3000),
        "latency_ms": measurement_evidence("classify"),
        "model_artifact_digest": sh('e'),
        "tokenizer_digest": sh('f'),
        "prompt_digest": sh('a'),
        "canonicalization_version": "canon-1",
        "application_revision": 7,
        "policy_revision": "policy-1",
        "last_applied_at": timepoint(3100),
        "created_at": timepoint(3200),
        "expires_at": missing("not_applicable"),
        "custom_source_column": "preserved",
    })
}

fn work_item_source() -> Value {
    merge(
        common_claimable(),
        json!({
            "pipeline_state": "pending",
            "endpoint_id": "ep-1",
            "request_url": "https://example.com/jobs/1",
            "request_method": "GET",
            "request_body_hash": {
                "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "profile": "artifact-sha256/1",
                "evidence_refs": [{"ref": "test"}],
            },
            "request_body_ref": missing("not_applicable"),
            "header_identity_set": [],
            "computed_fetch_key": sh('a'),
            "listing_revision": 1,
            "classification_surface": "phase_a_full_description",
            "partition_id": "part-1",
            "snippet_classifier_result_ref": missing("not_applicable"),
            "assigned_shard_id": missing("not_applicable"),
            "session_epoch": missing("not_applicable"),
            "request_sequence": missing("not_observed"),
            "job_detail_ref": missing("not_applicable"),
            "completed_at": missing("not_applicable"),
            "completion_kind": missing("not_applicable"),
            "custom_source_column": "preserved",
        }),
    )
}

fn job_detail_source() -> Value {
    merge(
        common_claimable(),
        json!({
            "source_url": "https://example.com/jobs/1",
            "fetch_key": sh('a'),
            "fetch_phase_token": "B",
            "request_params_json": {"url": "https://example.com/jobs/1", "method": "GET"},
            "source_response_hash": sh('a'),
            "extractor_version": "ext-1",
            "title": "Software Engineer",
            "employer": "Acme",
            "snippet": "Great job",
            "description": "Full description here",
            "posted_date": "2024-05-01",
            "content_fields_json": {"location": "Chicago, IL"},
            "render_verdict": "Pass",
            "render_basis": "http-acquisition",
            "render_history": [{
                "transport": "HttpClient",
                "operation": "http-acquisition",
                "verdict": "Pass",
                "basis": "http-acquisition",
                "response_hash": format!("sha256:{}", "0".repeat(64)),
                "evidence_refs": evidence_refs(),
                "measurements": [],
            }],
            "rendered_at": timepoint(4000),
            "pipeline_state": "ready",
            "semantic_state": "active",
            "content_verdict": "PASS",
            "verdict_applied": "PASS",
            "snippet_classifier_result_ref": "cls-1",
            "description_classifier_result_ref": "cls-2",
            "final_genuine_result_ref": "cls-2",
            "bypass_reason": missing("not_applicable"),
            "priority_hint": "high",
            "artifacts_json": {"legacy": true},
            "crawler_revision": 1,
            "published_agent_revision": 1,
            "semantic_candidate": "DISCOVERED",
            "semantic_evidence_json": {"support": "journaled"},
            "custom_source_column": "preserved",
        }),
    )
}

fn coverage_source() -> Value {
    json!({
        "target": "illinois",
        "run_id": "run-1",
        "partition_id": "part-1",
        "partition_predicate_json": {"predicate": "all"},
        "partition_definition_hash": sh('a'),
        "parent_partition_id": missing("not_applicable"),
        "child_partition_ids": [],
        "split_round": 0,
        "status": "open",
        "reported_total_source": "header",
        "reported_total_unit": "postings",
        "reported_total": 100,
        "floor_value": missing("not_applicable"),
        "header_label_is_floor": false,
        "session_reported_aggregates": {"counts": []},
        "observed_total": 0,
        "distinct_observed_total": 0,
        "repeated_distinct_id_total": 0,
        "observed_ids_set_hash": sh('a'),
        "duplicate_rate": 0.0,
        "render_pass_total": 0,
        "render_coverage": missing("not_applicable"),
        "proof_type": "none",
        "proof_cohort_refs": [],
        "session_count": 0,
        "session_min_count": 1,
        "saturation_marker_present": false,
        "pagination_coverage_proven": false,
        "proof_evidence_json": {"terms": {}},
        "min_job_id": missing("not_applicable"),
        "max_job_id": missing("not_applicable"),
        "max_date_posted": missing("not_observed"),
        "missing_posted_date_total": 0,
        "failure_reason": missing("not_applicable"),
        "detector_events": [],
        "last_evaluated_at": timepoint(5000),
        "request_count": 0,
        "request_bytes": 0,
        "response_bytes": 0,
        "bootstrap_elapsed_ms": measurement_evidence("bootstrap"),
        "acquisition_elapsed_ms": measurement_evidence("acquire"),
        "entity_revision": 1,
        "created_at": timepoint(5100),
        "updated_at": timepoint(5200),
        "custom_source_column": "preserved",
    })
}

fn cursor_source() -> Value {
    json!({
        "target": "illinois",
        "run_id": "run-1",
        "partition_id": "part-1",
        "walk_id": "walk-1",
        "worker_identity": "worker-1",
        "owner_epoch": 1,
        "phase": "A",
        "shard_id": missing("not_applicable"),
        "session_epoch": missing("not_applicable"),
        "session_state_ref": missing("not_applicable"),
        "cursor_kind": "offset",
        "cursor_payload_json": {"offset": 0},
        "previous_response_hash": sh('a'),
        "next_request_identity": {"url": "https://example.com/listings?page=2"},
        "cursor_revision": 0,
        "ordering_model": "stable",
        "coverage_scope": "per-run",
        "ordering_fingerprint": sh('a'),
        "backend_signature": missing("not_applicable"),
        "status": "open",
        "page_observations": [],
        "exact_id_occurrences": [],
        "page_hashes": [],
        "drift_events": [],
        "retained_request_bytes_ref": missing("not_enabled"),
        "retained_response_bytes_ref": missing("not_enabled"),
        "profile_version": "prof-1",
        "engine_version": "eng-1",
        "extractor_version": "ext-1",
        "observed_total": 0,
        "distinct_total": 0,
        "last_committed_request_sequence": 0,
        "created_at": timepoint(6000),
        "updated_at": timepoint(6100),
        "custom_source_column": "preserved",
    })
}

fn session_source() -> Value {
    json!({
        "target": "illinois",
        "run_id": "run-1",
        "phase": "A",
        "shard_id": "shard-1",
        "session_epoch": 1,
        "shard_topology": "per_worker",
        "worker_identity": "worker-1",
        "owner_epoch": 1,
        "status": "active",
        "bootstrap_kind": "cold",
        "bootstrap_started_at": timepoint(7000),
        "bootstrap_completed_at": timepoint(7100),
        "bootstrap_attempt": 0,
        "cookie_jar_snapshot": artifact_ref(),
        "cookie_generation": 1,
        "last_committed_request_sequence": 0,
        "profile_ref": "prof-1",
        "client_generation": "client-1",
        "last_authenticated_url": missing("not_applicable"),
        "handoff_timestamp": missing("not_observed"),
        "authenticated_state_evidence": missing("not_applicable"),
        "verified_session_birth": missing("not_observed"),
        "session_absolute_lifetime_seconds": missing("not_observed"),
        "session_expires_at": missing("not_observed"),
        "replacement_deadline": missing("not_observed"),
        "last_success_at": missing("not_observed"),
        "last_failure_reason": missing("not_applicable"),
        "redacted_solver_harvest_evidence": missing("not_applicable"),
        "entity_revision": 1,
        "created_at": timepoint(7200),
        "updated_at": timepoint(7300),
        "custom_source_column": "preserved",
    })
}

fn audit_source() -> Value {
    json!({
        "target": "illinois",
        "owner_domain": "crawler",
        "event_id": "evt-1",
        "transaction_id": "txn-1",
        "transaction_sequence": 1,
        "run_id": "run-1",
        "phase": "A",
        "partition_id": "part-1",
        "shard_id": missing("not_applicable"),
        "worker_identity": "worker-1",
        "entity_type": "listing",
        "entity_id": "listing-1",
        "action_type": "write",
        "payload_kind": "listing-write",
        "payload_json": {"row": {}},
        "transition_json": missing("not_applicable"),
        "created_at": timepoint(8000),
        "schema_version": "crawler-seam/0.1.0",
        "source_revision": missing("not_applicable"),
        "result_revision": 1,
        "custom_source_column": "preserved",
    })
}

fn mutation_source() -> Value {
    json!({
        "target": "illinois",
        "job_id": "job-1",
        "mutation_id": "mut-1",
        "action_name": "apply",
        "action_version": "v1",
        "idempotency_key": "idem-1",
        "request_evidence_json": {"action": "apply"},
        "response_evidence_json": {"status": "reserved"},
        "status": "requested",
        "requested_at": timepoint(9000),
        "confirmed_at": missing("not_observed"),
        "audit_event_ref": {
            "journal_id": "j-1",
            "sequence": 1,
            "event_id": "evt-1",
            "event_hash": "abc",
            "pointer": "/row",
        },
        "custom_source_column": "preserved",
    })
}

fn dead_letter_source() -> Value {
    json!({
        "target": "illinois",
        "entity_type": "listing",
        "entity_id": "listing-1",
        "failure_reason": "timeout",
        "run_id": "run-1",
        "stage": "fetch",
        "partition_id": "part-1",
        "retry_count": 1,
        "first_failed_at": timepoint(9100),
        "last_failed_at": timepoint(9200),
        "last_entity_revision": 1,
        "last_lease_id": missing("not_applicable"),
        "diagnostic_json": {"error": "timeout"},
        "audit_event_refs": [{
            "journal_id": "j-1",
            "sequence": 1,
            "event_id": "evt-1",
            "event_hash": "abc",
            "pointer": "/row",
        }],
        "resolution_status": "open",
        "custom_source_column": "preserved",
    })
}

fn seen_ids_source() -> Value {
    json!({
        "target": "illinois",
        "job_id": "job-1",
        "completed_fetch_key": sh('a'),
        "completed_pipeline_state": "ready",
        "completed_detail_revision": 1,
        "first_completed_at": timepoint(9300),
        "last_completed_at": timepoint(9400),
        "completed_run_id": "run-1",
        "custom_source_column": "preserved",
    })
}

fn all_entities() -> Vec<(SourceEntity, &'static str, Value)> {
    vec![
        (SourceEntity::Listing, "listing", listing_source()),
        (
            SourceEntity::ClassifierResult,
            "classifier_result",
            classifier_source(),
        ),
        (SourceEntity::WorkItem, "work_item", work_item_source()),
        (SourceEntity::JobDetail, "job_detail", job_detail_source()),
        (
            SourceEntity::CoverageLedger,
            "coverage_ledger",
            coverage_source(),
        ),
        (SourceEntity::CursorState, "cursor_state", cursor_source()),
        (
            SourceEntity::SessionState,
            "session_state",
            session_source(),
        ),
        (SourceEntity::AuditLog, "audit_log", audit_source()),
        (
            SourceEntity::StateMutationRecord,
            "state_mutation_record",
            mutation_source(),
        ),
        (SourceEntity::DeadLetter, "dead_letter", dead_letter_source()),
        (SourceEntity::SeenIds, "seen_ids", seen_ids_source()),
    ]
}

/// Every source column in all eleven entities survives normalized snapshot
/// conversion under the same column name, including source-only fields,
/// with false/zero/empty-string/empty-array preserved as real values. [C01]
#[test]
fn c01_complete_field_inventory_all_eleven_entities() {
    let ev = evidence();
    assert_eq!(all_entities().len(), 11, "all eleven entities must be covered");
    for (entity, name, source) in all_entities() {
        let source_keys: Vec<String> = source
            .as_object()
            .expect("source must be object")
            .keys()
            .cloned()
            .collect();
        assert!(
            !source_keys.is_empty(),
            "{name}: source must carry columns to preserve"
        );
        let snapshot = normalize_row(entity, source.clone(), &ev)
            .unwrap_or_else(|e| panic!("{name}: normalize_row failed: {} {}", e.code, e.detail));
        let value = record_value(&snapshot);
        let obj = value.as_object().expect("snapshot must be object");
        assert_eq!(
            obj.get("record_type").and_then(Value::as_str),
            Some("crawler_operational_snapshot"),
            "{name}: snapshot record_type"
        );
        assert_eq!(
            obj.get("schema_version").and_then(Value::as_str),
            Some("crawler-seam/0.1.0"),
            "{name}: snapshot schema_version"
        );
        assert_eq!(
            obj.get("entity_type").and_then(Value::as_str),
            Some(name),
            "{name}: snapshot entity_type"
        );
        assert!(
            obj.get("entity_id")
                .and_then(Value::as_str)
                .is_some_and(|s| !s.is_empty()),
            "{name}: snapshot entity_id must be a canonical reference"
        );
        let row = obj
            .get("row")
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("{name}: snapshot must carry a row object"));
        for key in &source_keys {
            assert!(
                row.contains_key(key),
                "{name}: source column {key:?} missing from normalized row"
            );
            assert_eq!(
                row.get(key),
                source.as_object().and_then(|m| m.get(key)),
                "{name}: source column {key:?} must survive verbatim"
            );
        }
        // Source-only fields are preserved, not discarded (§1.3).
        assert_eq!(
            row.get("custom_source_column").and_then(Value::as_str),
            Some("preserved"),
            "{name}: source-only column must survive"
        );
    }

    // Spot-check sentinel discipline inside the preserved inventory.
    let listing = normalize_row(SourceEntity::Listing, listing_source(), &ev).expect("listing");
    let listing_row = record_value(&listing)
        .get("row")
        .expect("listing row");
    assert_eq!(
        listing_row.get("snippet"),
        Some(&json!("")),
        "observed empty string remains distinct from missingness"
    );
    let coverage = normalize_row(SourceEntity::CoverageLedger, coverage_source(), &ev).expect("ledger");
    let crow = record_value(&coverage).get("row").expect("ledger row");
    assert_eq!(crow.get("observed_total"), Some(&json!(0)), "zero stays a real value");
    assert_eq!(
        crow.get("header_label_is_floor"),
        Some(&json!(false)),
        "false stays a real value"
    );
    assert_eq!(
        crow.get("child_partition_ids"),
        Some(&json!([])),
        "empty array stays an established empty collection"
    );
}

/// Bare JSON nulls become reasoned Missing envelopes with field evidence;
/// nothing is silently dropped. [C01]
#[test]
fn c01_bare_null_becomes_reasoned_missing_with_evidence() {
    let ev = evidence();
    let source = json!({
        "target": "illinois",
        "job_id": "job-1",
        "title": "Software Engineer",
        "employer": null,
        "snippet": null,
    });
    let snapshot =
        normalize_row(SourceEntity::Listing, source, &ev).expect("bare nulls must normalize");
    let value = record_value(&snapshot);
    let row = value.get("row").expect("row");
    assert_eq!(
        row.get("employer"),
        Some(&missing_detail(
            "not_observed",
            "source column employer was JSON null; normalized per EK-NULL"
        )),
        "bare null becomes Missing(not_observed)"
    );
    assert!(
        row.get("snippet")
            .and_then(Value::as_object)
            .is_some_and(|m| m.get("value").is_some_and(Value::is_null)),
        "bare null becomes a Missing envelope"
    );
    assert_eq!(
        row.get("title").and_then(Value::as_str),
        Some("Software Engineer"),
        "established columns survive alongside null conversions"
    );
    let field_evidence = value
        .get("field_evidence")
        .and_then(Value::as_array)
        .expect("field_evidence array");
    assert_eq!(field_evidence.len(), 2, "one evidence entry per null conversion");
    for entry in field_evidence {
        assert_eq!(
            entry.get("normalization").and_then(Value::as_str),
            Some("missingness")
        );
        assert_eq!(entry.get("source_value"), Some(&json!("null")));
    }
    let pointers: Vec<&str> = field_evidence
        .iter()
        .filter_map(|e| e.get("pointer").and_then(Value::as_str))
        .collect();
    assert!(pointers.contains(&"/row/employer"));
    assert!(pointers.contains(&"/row/snippet"));
}

/// Legacy UTC timestamp strings normalize to Missing with the exact source
/// string retained in field evidence; established coordinates on a
/// registered clock pass through unchanged. [C01]
#[test]
fn c01_timestamp_string_retained_in_field_evidence() {
    // UTC-only history without a clock registry still normalizes (Missing)
    // and retains the source string.
    let ev = evidence();
    let source = json!({
        "target": "illinois",
        "job_id": "job-1",
        "created_at": "2024-05-01T12:00:00Z",
        "updated_at": "2024-05-02T00:00:00Z",
    });
    let snapshot =
        normalize_row(SourceEntity::Listing, source, &ev).expect("utc-only must normalize");
    let value = record_value(&snapshot);
    let row = value.get("row").expect("row");
    for field in ["created_at", "updated_at"] {
        let slot = row.get(field).expect("timestamp column survives");
        assert_eq!(
            slot.get("reason").and_then(Value::as_str),
            Some("not_observed"),
            "{field}: UTC-only history yields Missing(not_observed)"
        );
    }
    let field_evidence = value
        .get("field_evidence")
        .and_then(Value::as_array)
        .expect("field evidence");
    assert_eq!(field_evidence.len(), 2);
    for entry in field_evidence {
        assert_eq!(
            entry.get("normalization").and_then(Value::as_str),
            Some("timestamp")
        );
    }
    let sources: Vec<&str> = field_evidence
        .iter()
        .filter_map(|e| e.get("source_value").and_then(Value::as_str))
        .collect();
    assert!(sources.contains(&"2024-05-01T12:00:00Z"));
    assert!(sources.contains(&"2024-05-02T00:00:00Z"));

    // Established coordinates on a registered clock survive verbatim.
    let ev_clocks = evidence_with_clocks();
    let source = json!({
        "target": "illinois",
        "job_id": "job-1",
        "created_at": timepoint(1234),
    });
    let snapshot =
        normalize_row(SourceEntity::Listing, source, &ev_clocks).expect("registered clock");
    let row = record_value(&snapshot).get("row").expect("row");
    assert_eq!(row.get("created_at"), Some(&timepoint(1234)));
}

/// Integer and string identities are never silently coerced: SID unions
/// stay distinct in the row and in canonical references. [C01]
#[test]
fn c01_integer_string_identity_never_coerced() {
    let ev = evidence();
    let int_source = json!({
        "target": "illinois",
        "job_id": "job-1",
        "stage": "snippet",
        "model_version": "slm-1",
        "input_hash": sh('d'),
        "verdict": "PASS",
        "verdict_applied": "PASS",
        "confidence": 0.5,
        "reason": "r",
        "application_revision": 7,
    });
    let str_source = json!({
        "target": "illinois",
        "job_id": "job-1",
        "stage": "snippet",
        "model_version": "slm-1",
        "input_hash": sh('d'),
        "verdict": "PASS",
        "verdict_applied": "PASS",
        "confidence": 0.5,
        "reason": "r",
        "application_revision": "7",
    });
    let int_snap = normalize_row(SourceEntity::ClassifierResult, int_source, &ev).expect("int SID");
    let str_snap =
        normalize_row(SourceEntity::ClassifierResult, str_source, &ev).expect("string SID");
    let int_row = record_value(&int_snap).get("row").expect("row");
    let str_row = record_value(&str_snap).get("row").expect("row");
    assert!(
        int_row.get("application_revision").is_some_and(Value::is_number),
        "integer SID stays a number"
    );
    assert!(
        str_row
            .get("application_revision")
            .is_some_and(Value::is_string),
        "string SID stays a string"
    );
    assert_ne!(
        int_row.get("application_revision"),
        str_row.get("application_revision"),
        "integer 7 and string \"7\" are never conflated"
    );

    // Session references discriminate the union in the framed encoding.
    let mut int_session = session_source();
    int_session.as_object_mut().unwrap().insert("session_epoch".to_string(), json!(7));
    let mut str_session = session_source();
    str_session
        .as_object_mut()
        .unwrap()
        .insert("session_epoch".to_string(), json!("7"));
    let int_ref = record_value(&normalize_row(SourceEntity::SessionState, int_session, &ev).expect("int"))
        .get("entity_id")
        .and_then(Value::as_str)
        .unwrap()
        .to_string();
    let str_ref = record_value(&normalize_row(SourceEntity::SessionState, str_session, &ev).expect("str"))
        .get("entity_id")
        .and_then(Value::as_str)
        .unwrap()
        .to_string();
    assert_ne!(int_ref, str_ref, "framed references must differ across SID types");
    assert!(int_ref.contains("i:7"), "integer component carries i: tag: {int_ref}");
    assert!(str_ref.contains("s:7"), "string component carries s: tag: {str_ref}");
}

/// Nested bare nulls inside evidence values normalize without dropping the
/// column, and unknown source-only columns survive alongside them. [C01]
#[test]
fn c01_nested_nulls_and_source_only_columns_preserved() {
    let ev = evidence();
    let source = json!({
        "target": "illinois",
        "job_id": "job-1",
        "extracted_fields_json": {"title": "x", "note": null, "tags": [null, "a"]},
        "mystery_vendor_column": {"nested": [1, "two", false]},
    });
    let snapshot =
        normalize_row(SourceEntity::Listing, source, &ev).expect("nested nulls must normalize");
    let value = record_value(&snapshot);
    let row = value.get("row").expect("row");
    assert_eq!(
        row.get("mystery_vendor_column"),
        Some(&json!({"nested": [1, "two", false]})),
        "unknown source-only columns survive verbatim"
    );
    let extracted = row.get("extracted_fields_json").expect("column survives");
    assert_eq!(extracted.get("title").and_then(Value::as_str), Some("x"));
    assert_eq!(
        extracted.get("note").and_then(|v| v.get("reason")).and_then(Value::as_str),
        Some("not_observed"),
        "nested null becomes Missing"
    );
    assert!(
        !format!("{extracted:?}").contains(":null")
            || format!("{extracted:?}").contains("\"value\":null"),
        "no bare nulls may survive normalization"
    );
    let field_evidence = value
        .get("field_evidence")
        .and_then(Value::as_array)
        .expect("field evidence");
    assert!(
        field_evidence.iter().any(|e| e.get("pointer").and_then(Value::as_str)
            == Some("/row/extracted_fields_json")),
        "nested conversions carry field evidence"
    );
}

// ---------------------------------------------------------------------------
// Assembly behavior (exercises the second public entry point; also matched
// by the c01 filter so `cargo test -- c01` covers the full interface).
// ---------------------------------------------------------------------------

fn assembly_evidence() -> CheckedRecord {
    validate(
        "audit_log",
        json!({
            "captured_at": timepoint(50_000),
            "evidence_prefix": {"journal_id": "j-1", "last_sequence": 10, "head_hash": "abc123"},
            "evidence_refs": evidence_refs(),
            "coverage_refs": [{
                "run_id": "run-1",
                "partition_id": "part-1",
                "definition_digest": format!("sha256:{}", "0".repeat(64)),
                "status": "proven",
                "proven": true,
            }],
            "source_response": artifact_ref(),
        }),
    )
    .expect("assembly evidence must satisfy the gate")
}

/// Pass assembly maps only declared fields, never whole rows, and requires
/// the durable source-response artifact. [C01 interface coverage]
#[test]
fn c01_assemble_pass_maps_declared_fields_only() {
    let ev = evidence();
    let detail = normalize_row(SourceEntity::JobDetail, job_detail_source(), &ev).expect("detail");
    let listing = normalize_row(SourceEntity::Listing, listing_source(), &ev).expect("listing");
    let classifier =
        normalize_row(SourceEntity::ClassifierResult, classifier_source(), &ev).expect("classifier");
    let assembled = assemble_crawler_value(
        &[detail, listing, classifier],
        &assembly_evidence(),
    )
    .expect("Pass assembly must succeed");
    let value = record_value(&assembled);
    let obj = value.as_object().expect("JobCrawlerValue object");
    for key in ["acquisition", "processing", "discovery", "replacement_lineage"] {
        assert!(obj.contains_key(key), "JobCrawlerValue carries {key}");
    }
    // No wholesale row packing and no product-owned conversions.
    let text = format!("{value:?}");
    assert!(!text.contains("custom_source_column"), "source-only columns are not packed");
    assert!(!text.contains("semantic_state"), "legacy semantic_state is not a shared target");
    let acquisition = obj.get("acquisition").expect("acquisition");
    assert_eq!(
        acquisition.get("source_url").and_then(Value::as_str),
        Some("https://example.com/jobs/1")
    );
    assert_eq!(
        acquisition.get("content").and_then(|c| c.get("title")).and_then(Value::as_str),
        Some("Software Engineer")
    );
    // Direct-apply URL is never silently copied from the source URL.
    let direct = acquisition
        .get("content")
        .and_then(|c| c.get("direct_apply_url"))
        .expect("direct_apply_url slot");
    assert_eq!(
        direct.get("reason").and_then(Value::as_str),
        Some("not_observed"),
        "direct-apply URL stays Missing without independent support"
    );
    // Missing artifact blocks Pass publication.
    let no_artifact = validate(
        "audit_log",
        json!({
            "evidence_prefix": {"journal_id": "j-1", "last_sequence": 10, "head_hash": "abc123"},
            "evidence_refs": evidence_refs(),
            "coverage_refs": [{
                "run_id": "run-1",
                "partition_id": "part-1",
                "definition_digest": format!("sha256:{}", "0".repeat(64)),
                "status": "proven",
                "proven": true,
            }],
        }),
    )
    .expect("evidence");
    let detail = normalize_row(SourceEntity::JobDetail, job_detail_source(), &ev).expect("detail");
    let err = assemble_crawler_value(&[detail], &no_artifact).expect_err("artifact required");
    assert_eq!(err.code, "missing_artifact");
}

/// Non-Pass Case B requires render_failed with all content Missing and no
/// current classifier results. [C01 interface coverage]
#[test]
fn c01_assemble_case_b_rejects_established_content() {
    let ev = evidence();
    let mut failed = job_detail_source();
    {
        let map = failed.as_object_mut().expect("object");
        map.insert("render_verdict".to_string(), json!("ThinShell"));
        map.insert("pipeline_state".to_string(), json!("render_failed"));
        for field in ["title", "employer", "snippet", "description", "posted_date"] {
            map.insert(field.to_string(), missing("not_observed"));
        }
        map.insert("content_fields_json".to_string(), missing("not_observed"));
        for field in [
            "snippet_classifier_result_ref",
            "description_classifier_result_ref",
            "final_genuine_result_ref",
        ] {
            map.insert(field.to_string(), missing("not_applicable"));
        }
    }
    let detail = normalize_row(SourceEntity::JobDetail, failed, &ev).expect("case B detail");
    assemble_crawler_value(&[detail], &assembly_evidence()).expect("valid Case B assembles");

    // Established content under a non-Pass verdict is rejected.
    let mut bad = job_detail_source();
    {
        let map = bad.as_object_mut().expect("object");
        map.insert("render_verdict".to_string(), json!("ThinShell"));
        map.insert("pipeline_state".to_string(), json!("render_failed"));
    }
    let detail = normalize_row(SourceEntity::JobDetail, bad, &ev).expect("detail normalizes");
    let err = assemble_crawler_value(&[detail], &assembly_evidence()).expect_err("Case B violation");
    assert_eq!(err.code, "invalid_render_case");
}

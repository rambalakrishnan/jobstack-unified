//! Conformance tests for [C43]: offline replay.
//!
//! No external execution; missing inputs unavailable; required comparisons
//! all match before matched.

use crawler_artifacts::{ArtifactStore, MemoryArtifactStore};
use crawler_authority::{authorize, Grant};
use crawler_detectors::evaluate_detectors;
use crawler_hashing::{canonical_bytes, digest_bytes};
use crawler_normalization::normalize_row;
use crawler_replay::{derive_diagnostic, replay_offline};
use crawler_schema::{record_value, validate, CheckedRecord, SourceEntity};
use serde_json::{json, Value};

fn check(schema: &str, value: Value) -> CheckedRecord {
    validate(schema, value).expect("fixture must satisfy the schema gate")
}

fn missing(reason: &str) -> Value {
    json!({"value": Value::Null, "reason": reason})
}

fn missing_detail(reason: &str, detail: &str) -> Value {
    json!({"value": Value::Null, "reason": reason, "detail": detail})
}

fn binding_of(record: &CheckedRecord) -> String {
    digest_bytes(&canonical_bytes(record).expect("canonical bytes must exist"))
}

fn version_pin(id: &str, version: &str, seed: &[u8]) -> Value {
    json!({
        "id": id,
        "version": version,
        "artifact_digest": format!("sha256:{}", digest_bytes(seed)),
    })
}

// ---------------------------------------------------------------------------
// Diagnostic fixtures
// ---------------------------------------------------------------------------

fn manifest_value() -> Value {
    json!({
        "manifest_id": "manifest-1",
        "run_id": "run-1",
        "description": "test manifest",
    })
}

fn prefix_value() -> Value {
    json!({
        "journal_id": "j-1",
        "last_sequence": 10,
        "head_hash": digest_bytes(b"head-bytes"),
    })
}

fn bundle_value() -> Value {
    json!({
        "classifier": version_pin("classifier", "v1", b"classifier"),
        "requirement_registry": version_pin("req-reg", "v1", b"req"),
        "fix_registry": version_pin("fix-reg", "v1", b"fix"),
    })
}

fn manifest_rec() -> CheckedRecord {
    check("audit_log", manifest_value())
}

fn prefix_rec() -> CheckedRecord {
    check("audit_log", prefix_value())
}

fn bundle_rec() -> CheckedRecord {
    check("audit_log", bundle_value())
}

fn expected_diagnostic_digest(
    manifest: &CheckedRecord,
    prefix: &CheckedRecord,
    bundle: &CheckedRecord,
) -> String {
    let diagnostic = derive_diagnostic(manifest, prefix, bundle).expect("diagnostic must derive");
    digest_bytes(&canonical_bytes(&diagnostic).expect("diagnostic must hash"))
}

// ---------------------------------------------------------------------------
// Artifact grant fixtures (connector grant with owner_domain)
// ---------------------------------------------------------------------------

fn registration_fixture() -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "registration_id": "channel-1",
            "principals": [{
                "principal_id": "operator",
                "verbs": ["Describe", "Prepare", "Start", "Observe", "RequestNativeCancel", "CloseObservationConnection", "CollectArtifacts", "ReleaseNativeContext", "Contain"],
                "connectors": ["jobs-connector"],
                "control": true,
                "owner_domain": "crawler",
                "restricted_access": true,
            }],
        }),
    )
}

fn operator_grant() -> Grant {
    let registration = registration_fixture();
    let principal = check(
        "audit_log",
        json!({
            "principal_id": "operator",
            "registration_digest": binding_of(&registration),
        }),
    );
    let request = check(
        "audit_log",
        json!({"verb": "CollectArtifacts", "connector": "jobs-connector"}),
    );
    authorize(&principal, &request, &registration).expect("grant must issue")
}

// ---------------------------------------------------------------------------
// Detector transcript fixtures (known-valid C27 shapes)
// ---------------------------------------------------------------------------

fn detector_timepoint() -> Value {
    json!({
        "clock_id": "det-clk",
        "boot_id": "boot-1",
        "origin": "engine_measured",
        "monotonic_offset_ms": 50_000,
        "utc_annotation": missing("not_observed"),
    })
}

fn detector_declaration_value() -> Value {
    json!({
        "target": "il",
        "run_id": "run-1",
        "partition_id": "p-1",
        "owner_domain": "crawler",
        "captured_at": detector_timepoint(),
        "evidence_prefix": {"journal_id": "j-1", "last_sequence": 10, "head_hash": "abc123"},
        "evidence_refs": [{
            "journal_id": "j-1",
            "sequence": 10,
            "event_id": "evt-10",
            "event_hash": "abc",
            "pointer": "/row",
        }],
        "row_cap": 10,
        "row_cap_verified": true,
        "saturation_markers": ["+"],
        "noop_threshold": 2,
        "tail_threshold": 2,
        "ordering_model": "ascending",
        "overflow_banners": ["OVERFLOW"],
        "probe_policy": "fixture_only",
    })
}

fn detector_prior_value() -> Value {
    json!({
        "rowcap_state": "MONITORING",
        "saturation_state": "UNSATURATED",
        "noop_state": "ADVANCING",
        "tail_state": "ADVANCING",
        "ascending_state": "MONITORING_ASCENDING",
        "noop_corroboration_count": 0,
        "tail_corroboration_count": 0,
        "first_page_ordered_ids": ["job-a", "job-b"],
        "first_page_hash": {
            "value": digest_bytes(b"first-page-bytes"),
            "profile": "crawler-page-hash/1",
            "evidence_refs": [{"ref": "t"}],
        },
        "first_page_coordinate": {"page": 1},
        "terminal_ordered_ids": ["job-x", "job-y"],
        "terminal_page_hash": {
            "value": digest_bytes(b"terminal-page-bytes"),
            "profile": "crawler-page-hash/1",
            "evidence_refs": [{"ref": "t"}],
        },
        "max_date_posted": "2026-01-10",
        "split_available": true,
        "alternative_cursor_available": true,
        "below_cap_split_available": true,
    })
}

fn detector_packet_value() -> Value {
    json!({
        "request_coordinate": {"page": 2},
        "request_sequence": 2,
        "response_identity": "resp-2",
        "response_hash": {
            "value": digest_bytes(b"response-bytes"),
            "profile": "crawler-page-hash/1",
            "evidence_refs": [{"ref": "t"}],
        },
        "page_hash": {
            "value": digest_bytes(b"current-page-bytes"),
            "profile": "crawler-page-hash/1",
            "evidence_refs": [{"ref": "t"}],
        },
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
    })
}

// ---------------------------------------------------------------------------
// Expected-digest helpers (independent recomputation with the same primitives)
// ---------------------------------------------------------------------------

fn expected_semantic_simple(external: &Value, lifecycle: &Value) -> String {
    let input = json!({
        "kind": "semantic_events",
        "external_inputs": external.clone(),
        "lifecycle_observations": lifecycle.clone(),
    });
    let rec = check("audit_log", input);
    digest_bytes(&canonical_bytes(&rec).expect("hash input must hash"))
}

fn expected_final_simple(external: &Value, lifecycle: &Value) -> String {
    let input = json!({
        "kind": "final_state",
        "external_inputs": external.clone(),
        "lifecycle_observations": lifecycle.clone(),
    });
    let rec = check("audit_log", input);
    digest_bytes(&canonical_bytes(&rec).expect("hash input must hash"))
}

fn replay_evidence_for_test(source_prefix: &Value) -> CheckedRecord {
    let journal_id = source_prefix
        .as_object()
        .and_then(|map| map.get("journal_id"))
        .and_then(Value::as_str)
        .unwrap_or("j-replay");
    check(
        "audit_log",
        json!({
            "captured_at": {
                "clock_id": "replay-clk",
                "boot_id": "boot-replay",
                "origin": "engine_measured",
                "monotonic_offset_ms": 0,
                "utc_annotation": missing_detail("not_observed", "replay uses a pinned clock, never wall time"),
            },
            "evidence_prefix": source_prefix.clone(),
            "evidence_refs": [{
                "journal_id": journal_id,
                "sequence": 1,
                "event_id": "evt-replay-1",
                "event_hash": "replay-evidence",
                "pointer": "/replay",
            }],
        }),
    )
}

fn expected_semantic_with_rows(
    external: &Value,
    lifecycle: &Value,
    rows: &[Value],
    source_prefix: &Value,
) -> String {
    let evidence = replay_evidence_for_test(source_prefix);
    let mut digests = Vec::with_capacity(rows.len());
    for row in rows {
        let normalized =
            normalize_row(SourceEntity::AuditLog, row.clone(), &evidence)
                .expect("test row must normalize");
        digests.push(Value::String(digest_bytes(
            &canonical_bytes(&normalized).expect("snapshot must hash"),
        )));
    }
    let input = json!({
        "kind": "semantic_events",
        "external_inputs": external.clone(),
        "lifecycle_observations": lifecycle.clone(),
        "normalized_digests": digests,
    });
    let rec = check("audit_log", input);
    digest_bytes(&canonical_bytes(&rec).expect("hash input must hash"))
}

fn expected_final_with_detector(
    external: &Value,
    lifecycle: &Value,
    declaration: &Value,
    prior: &Value,
    packet: &Value,
) -> String {
    let declaration_rec = check("audit_log", declaration.clone());
    let prior_rec = check("cursor_state", prior.clone());
    let packet_rec = check("cursor_state", packet.clone());
    let out = evaluate_detectors(&declaration_rec, &prior_rec, &packet_rec)
        .expect("test transcript must evaluate");
    let detector_digest = digest_bytes(&canonical_bytes(&out).expect("detector out must hash"));
    let input = json!({
        "kind": "final_state",
        "external_inputs": external.clone(),
        "lifecycle_observations": lifecycle.clone(),
        "detector_digest": detector_digest,
    });
    let rec = check("audit_log", input);
    digest_bytes(&canonical_bytes(&rec).expect("hash input must hash"))
}

// ---------------------------------------------------------------------------
// Bundle + request builders
// ---------------------------------------------------------------------------

fn external_inputs_value() -> Value {
    json!({"url": "https://example.com/jobs", "method": "GET"})
}

fn lifecycle_value() -> Value {
    json!([{"event": "fetch", "status": "ok"}])
}

fn audit_row_value(event_id: &str) -> Value {
    json!({
        "target": "t1",
        "owner_domain": "crawler",
        "event_id": event_id,
        "extra": "x",
    })
}

fn bundle_simple(external: &Value, lifecycle: &Value) -> Value {
    json!({
        "external_inputs": external.clone(),
        "lifecycle_observations": lifecycle.clone(),
        "diagnostic_manifest": manifest_value(),
        "diagnostic_prefix": prefix_value(),
        "diagnostic_bundle": bundle_value(),
    })
}

fn install_bundle(
    store: &MemoryArtifactStore,
    grant: &Grant,
    bundle: &Value,
) -> CheckedRecord {
    let bytes = serde_json::to_vec(bundle).expect("bundle must serialize");
    store
        .install(grant, &bytes, "application/json", false)
        .expect("bundle install must succeed")
}

fn exact_request(
    bundle_ref: &CheckedRecord,
    expected_semantic: &str,
    expected_final: &str,
    expected_diagnostic: &str,
    manifest_hash: &str,
) -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "replay_id": "replay-1",
            "mode": "exact_fixture",
            "run_id": "run-1",
            "manifest_hash": manifest_hash,
            "source_prefix": prefix_value(),
            "source_diagnostic": {"digest": expected_diagnostic},
            "input_bundle": record_value(bundle_ref).clone(),
            "classifier": version_pin("classifier", "v1", b"classifier"),
            "reducer": version_pin("reducer", "v1", b"reducer"),
            "replay_engine": version_pin("replay-engine", "v1", b"engine"),
            "expected": {
                "semantic_events": expected_semantic,
                "final_state": expected_final,
                "diagnostic": expected_diagnostic,
            },
        }),
    )
}

fn rederivation_request(bundle_ref: &CheckedRecord, expected_diagnostic: &str, manifest_hash: &str) -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "replay_id": "replay-d",
            "mode": "diagnostic_rederivation",
            "run_id": "run-1",
            "manifest_hash": manifest_hash,
            "source_prefix": prefix_value(),
            "source_diagnostic": {"digest": expected_diagnostic},
            "input_bundle": record_value(bundle_ref).clone(),
            "classifier": version_pin("classifier", "v1", b"classifier"),
            "reducer": missing_detail("not_applicable", "diagnostic-only replay uses no reducer"),
            "replay_engine": version_pin("replay-engine", "v1", b"engine"),
            "expected": {"diagnostic": expected_diagnostic},
        }),
    )
}

fn comparisons(value: &Value) -> &Vec<Value> {
    value
        .get("comparisons")
        .and_then(Value::as_array)
        .expect("receipt must carry comparisons")
}

fn comparison_by<'a>(value: &'a Value, output: &str) -> &'a Value {
    comparisons(value)
        .iter()
        .find(|entry| entry.get("output").and_then(Value::as_str) == Some(output))
        .unwrap_or_else(|| panic!("comparison {output} must be present"))
}

fn assert_no_external_execution(value: &Value) {
    assert_eq!(
        value.get("invoked_browser"),
        Some(&Value::Bool(false)),
        "replay must never invoke a browser"
    );
    assert_eq!(
        value.get("invoked_subject"),
        Some(&Value::Bool(false)),
        "replay must never invoke a subject"
    );
    assert_eq!(
        value.get("performed_external_writes"),
        Some(&Value::Bool(false)),
        "replay must never perform external writes"
    );
}

// ---------------------------------------------------------------------------
// C43: derive_diagnostic determinism
// ---------------------------------------------------------------------------

#[test]
fn c43_derive_diagnostic_deterministic_no_wall_time() {
    let manifest = manifest_rec();
    let prefix = prefix_rec();
    let bundle = bundle_rec();

    let first = derive_diagnostic(&manifest, &prefix, &bundle).expect("derive must succeed");
    let second = derive_diagnostic(&manifest, &prefix, &bundle).expect("derive must succeed");
    let first_digest = digest_bytes(&canonical_bytes(&first).expect("must hash"));
    let second_digest = digest_bytes(&canonical_bytes(&second).expect("must hash"));
    assert_eq!(first_digest, second_digest, "same inputs must yield identical diagnostic");

    let value = record_value(&first);
    assert_eq!(
        value.get("record_type").and_then(Value::as_str),
        Some("diagnostic")
    );
    assert_eq!(value.get("run_id").and_then(Value::as_str), Some("run-1"));
    // No wall time: explicit inapplicable marker, never an established timestamp.
    let wall = value.get("derived_wall_time").expect("must carry wall-time marker");
    assert_eq!(
        wall.get("reason").and_then(Value::as_str),
        Some("not_applicable"),
        "diagnostic must record that no wall time was used"
    );

    // Different prefix yields a different diagnostic (new revision inputs).
    let other_prefix = check(
        "audit_log",
        json!({
            "journal_id": "j-1",
            "last_sequence": 11,
            "head_hash": digest_bytes(b"other-head"),
        }),
    );
    let third = derive_diagnostic(&manifest, &other_prefix, &bundle).expect("derive must succeed");
    let third_digest = digest_bytes(&canonical_bytes(&third).expect("must hash"));
    assert_ne!(first_digest, third_digest, "changed prefix must change the diagnostic");

    // Forbidden unrecorded evidence is refused.
    let tainted = check(
        "audit_log",
        json!({
            "manifest_id": "manifest-1",
            "run_id": "run-1",
            "current_wall_time": "2026-11-16T00:00:00Z",
        }),
    );
    let err = derive_diagnostic(&tainted, &prefix, &bundle).expect_err("wall time must be refused");
    assert_eq!(err.code, "unrecorded_evidence");
}

// ---------------------------------------------------------------------------
// C43: exact fixture matched
// ---------------------------------------------------------------------------

#[test]
fn c43_exact_fixture_matched_when_all_compare() {
    let grant = operator_grant();
    let store = MemoryArtifactStore::new();
    let external = external_inputs_value();
    let lifecycle = lifecycle_value();

    let manifest = manifest_rec();
    let prefix = prefix_rec();
    let bundle = bundle_rec();
    let manifest_hash = digest_bytes(&canonical_bytes(&manifest).expect("must hash"));
    let expected_diag = expected_diagnostic_digest(&manifest, &prefix, &bundle);
    let expected_sem = expected_semantic_simple(&external, &lifecycle);
    let expected_fin = expected_final_simple(&external, &lifecycle);

    let bundle_bytes_value = bundle_simple(&external, &lifecycle);
    let bundle_ref = install_bundle(&store, &grant, &bundle_bytes_value);
    let request = exact_request(&bundle_ref, &expected_sem, &expected_fin, &expected_diag, &manifest_hash);

    let receipt = replay_offline(&store, &grant, &request).expect("replay must succeed");
    let value = record_value(&receipt);
    assert_eq!(value.get("result").and_then(Value::as_str), Some("matched"));
    assert_eq!(comparisons(value).len(), 3, "exact fixture requires three comparisons");
    for output in ["semantic_events", "final_state", "diagnostic"] {
        let entry = comparison_by(value, output);
        assert_eq!(entry.get("result").and_then(Value::as_str), Some("matched"), "{output} must match");
    }
    assert_no_external_execution(value);
}

// ---------------------------------------------------------------------------
// C43: missing inputs unavailable, never matched
// ---------------------------------------------------------------------------

#[test]
fn c43_missing_inputs_unavailable_never_matched() {
    let grant = operator_grant();
    let store = MemoryArtifactStore::new();
    let external = external_inputs_value();
    let lifecycle = lifecycle_value();

    let manifest = manifest_rec();
    let prefix = prefix_rec();
    let bundle = bundle_rec();
    let manifest_hash = digest_bytes(&canonical_bytes(&manifest).expect("must hash"));
    let expected_diag = expected_diagnostic_digest(&manifest, &prefix, &bundle);
    let expected_sem = expected_semantic_simple(&external, &lifecycle);
    let expected_fin = expected_final_simple(&external, &lifecycle);

    // Bundle omits external_inputs: semantic + final unavailable, diagnostic
    // still matched, aggregate unavailable (never matched).
    let incomplete = json!({
        "lifecycle_observations": lifecycle.clone(),
        "diagnostic_manifest": manifest_value(),
        "diagnostic_prefix": prefix_value(),
        "diagnostic_bundle": bundle_value(),
    });
    let bundle_ref = install_bundle(&store, &grant, &incomplete);
    let request = exact_request(&bundle_ref, &expected_sem, &expected_fin, &expected_diag, &manifest_hash);
    let receipt = replay_offline(&store, &grant, &request).expect("replay must return a receipt");
    let value = record_value(&receipt).clone();
    assert_eq!(value.get("result").and_then(Value::as_str), Some("unavailable"));
    assert_eq!(
        comparison_by(&value, "semantic_events").get("result").and_then(Value::as_str),
        Some("unavailable")
    );
    assert_eq!(
        comparison_by(&value, "final_state").get("result").and_then(Value::as_str),
        Some("unavailable")
    );
    assert_eq!(
        comparison_by(&value, "diagnostic").get("result").and_then(Value::as_str),
        Some("matched")
    );
    // Unavailable actuals are Missing envelopes, never erased or invented digests.
    let actual = comparison_by(&value, "semantic_events").get("actual").expect("must carry actual");
    assert_eq!(actual.get("reason").and_then(Value::as_str), Some("not_observed"));
    assert_no_external_execution(&value);

    // Bundle omits diagnostic inputs: diagnostic unavailable, aggregate unavailable.
    let no_diag = json!({
        "external_inputs": external.clone(),
        "lifecycle_observations": lifecycle.clone(),
        "diagnostic_manifest": missing("not_observed"),
        "diagnostic_prefix": prefix_value(),
        "diagnostic_bundle": bundle_value(),
    });
    let bundle_ref = install_bundle(&store, &grant, &no_diag);
    let request = exact_request(&bundle_ref, &expected_sem, &expected_fin, &expected_diag, &manifest_hash);
    let receipt = replay_offline(&store, &grant, &request).expect("replay must return a receipt");
    let value = record_value(&receipt);
    assert_eq!(value.get("result").and_then(Value::as_str), Some("unavailable"));
    assert_eq!(
        comparison_by(value, "diagnostic").get("result").and_then(Value::as_str),
        Some("unavailable")
    );
}

// ---------------------------------------------------------------------------
// C43: mismatched when recomputed digests differ
// ---------------------------------------------------------------------------

#[test]
fn c43_mismatched_when_recomputed_differs() {
    let grant = operator_grant();
    let store = MemoryArtifactStore::new();
    let external = external_inputs_value();
    let lifecycle = lifecycle_value();

    let manifest = manifest_rec();
    let prefix = prefix_rec();
    let bundle = bundle_rec();
    let manifest_hash = digest_bytes(&canonical_bytes(&manifest).expect("must hash"));
    let expected_diag = expected_diagnostic_digest(&manifest, &prefix, &bundle);
    let expected_sem = expected_semantic_simple(&external, &lifecycle);
    let expected_fin = expected_final_simple(&external, &lifecycle);

    // Tampered lifecycle observations: semantic + final mismatch.
    let tampered_lifecycle = json!([{"event": "fetch", "status": "timeout"}]);
    let tampered_bundle = bundle_simple(&external, &tampered_lifecycle);
    let bundle_ref = install_bundle(&store, &grant, &tampered_bundle);
    let request = exact_request(&bundle_ref, &expected_sem, &expected_fin, &expected_diag, &manifest_hash);
    let receipt = replay_offline(&store, &grant, &request).expect("replay must return a receipt");
    let value = record_value(&receipt);
    assert_eq!(value.get("result").and_then(Value::as_str), Some("mismatched"));
    assert_eq!(
        comparison_by(value, "semantic_events").get("result").and_then(Value::as_str),
        Some("mismatched")
    );
    assert_eq!(
        comparison_by(value, "final_state").get("result").and_then(Value::as_str),
        Some("mismatched")
    );
    // Diagnostic inputs unchanged, so the diagnostic still matches.
    assert_eq!(
        comparison_by(value, "diagnostic").get("result").and_then(Value::as_str),
        Some("matched")
    );
    assert_no_external_execution(value);

    // Tampered diagnostic bundle: diagnostic mismatches while the other two match.
    let mut tampered_diag_bundle = bundle_value();
    tampered_diag_bundle["classifier"] = version_pin("classifier", "v2", b"classifier-v2");
    let diag_bundle = json!({
        "external_inputs": external.clone(),
        "lifecycle_observations": lifecycle.clone(),
        "diagnostic_manifest": manifest_value(),
        "diagnostic_prefix": prefix_value(),
        "diagnostic_bundle": tampered_diag_bundle,
    });
    let bundle_ref = install_bundle(&store, &grant, &diag_bundle);
    let request = exact_request(&bundle_ref, &expected_sem, &expected_fin, &expected_diag, &manifest_hash);
    let receipt = replay_offline(&store, &grant, &request).expect("replay must return a receipt");
    let value = record_value(&receipt);
    assert_eq!(value.get("result").and_then(Value::as_str), Some("mismatched"));
    assert_eq!(
        comparison_by(value, "diagnostic").get("result").and_then(Value::as_str),
        Some("mismatched")
    );
    assert_eq!(
        comparison_by(value, "semantic_events").get("result").and_then(Value::as_str),
        Some("matched")
    );
}

// ---------------------------------------------------------------------------
// C43: recorded derived outputs are never authoritative
// ---------------------------------------------------------------------------

#[test]
fn c43_recorded_derived_outputs_never_authoritative() {
    let grant = operator_grant();
    let store = MemoryArtifactStore::new();
    let external = external_inputs_value();
    let lifecycle = lifecycle_value();

    let manifest = manifest_rec();
    let prefix = prefix_rec();
    let bundle = bundle_rec();
    let manifest_hash = digest_bytes(&canonical_bytes(&manifest).expect("must hash"));
    let expected_diag = expected_diagnostic_digest(&manifest, &prefix, &bundle);
    let expected_sem = expected_semantic_simple(&external, &lifecycle);
    let expected_fin = expected_final_simple(&external, &lifecycle);

    // Recorded derived outputs echo the expected digests, but the recorded
    // inputs produce different digests: replay must still mismatch, proving
    // it recomputed from inputs instead of echoing recorded outputs.
    let tampered_lifecycle = json!([{"event": "fetch", "status": "timeout"}]);
    let bundle_with_recorded = json!({
        "external_inputs": external.clone(),
        "lifecycle_observations": tampered_lifecycle,
        "diagnostic_manifest": manifest_value(),
        "diagnostic_prefix": prefix_value(),
        "diagnostic_bundle": bundle_value(),
        "recorded_derived": {
            "semantic_events": expected_sem.clone(),
            "final_state": expected_fin.clone(),
            "diagnostic": expected_diag.clone(),
        },
        "recorded_derived_outputs": {
            "semantic_events": expected_sem.clone(),
        },
    });
    let bundle_ref = install_bundle(&store, &grant, &bundle_with_recorded);
    let request = exact_request(&bundle_ref, &expected_sem, &expected_fin, &expected_diag, &manifest_hash);
    let receipt = replay_offline(&store, &grant, &request).expect("replay must return a receipt");
    let value = record_value(&receipt);
    assert_eq!(
        value.get("result").and_then(Value::as_str),
        Some("mismatched"),
        "recorded derived outputs must not be fed back as authoritative inputs"
    );

    // Conversely, bogus recorded outputs alongside correct inputs must not
    // disturb a matched replay.
    let correct_with_bogus_recorded = json!({
        "external_inputs": external.clone(),
        "lifecycle_observations": lifecycle.clone(),
        "diagnostic_manifest": manifest_value(),
        "diagnostic_prefix": prefix_value(),
        "diagnostic_bundle": bundle_value(),
        "recorded_derived": {
            "semantic_events": "0".repeat(64),
            "final_state": "1".repeat(64),
            "diagnostic": "2".repeat(64),
        },
    });
    let bundle_ref = install_bundle(&store, &grant, &correct_with_bogus_recorded);
    let request = exact_request(&bundle_ref, &expected_sem, &expected_fin, &expected_diag, &manifest_hash);
    let receipt = replay_offline(&store, &grant, &request).expect("replay must return a receipt");
    let value = record_value(&receipt);
    assert_eq!(
        value.get("result").and_then(Value::as_str),
        Some("matched"),
        "bogus recorded outputs must be ignored when inputs recompute correctly"
    );
}

// ---------------------------------------------------------------------------
// C43: every required comparison must match before matched
// ---------------------------------------------------------------------------

#[test]
fn c43_required_comparisons_all_match_before_matched() {
    let grant = operator_grant();
    let store = MemoryArtifactStore::new();
    let external = external_inputs_value();
    let lifecycle = lifecycle_value();

    let manifest = manifest_rec();
    let prefix = prefix_rec();
    let bundle = bundle_rec();
    let manifest_hash = digest_bytes(&canonical_bytes(&manifest).expect("must hash"));
    let expected_diag = expected_diagnostic_digest(&manifest, &prefix, &bundle);
    let expected_sem = expected_semantic_simple(&external, &lifecycle);
    let expected_fin = expected_final_simple(&external, &lifecycle);

    // Two of three match; the third is unavailable: aggregate must be
    // unavailable, never matched.
    let partial = json!({
        "external_inputs": external.clone(),
        "lifecycle_observations": lifecycle.clone(),
        "diagnostic_manifest": missing("not_observed"),
        "diagnostic_prefix": missing("not_observed"),
        "diagnostic_bundle": missing("not_observed"),
    });
    let bundle_ref = install_bundle(&store, &grant, &partial);
    let request = exact_request(&bundle_ref, &expected_sem, &expected_fin, &expected_diag, &manifest_hash);
    let receipt = replay_offline(&store, &grant, &request).expect("replay must return a receipt");
    let value = record_value(&receipt);
    assert_eq!(
        comparison_by(value, "semantic_events").get("result").and_then(Value::as_str),
        Some("matched")
    );
    assert_eq!(
        comparison_by(value, "final_state").get("result").and_then(Value::as_str),
        Some("matched")
    );
    assert_eq!(
        comparison_by(value, "diagnostic").get("result").and_then(Value::as_str),
        Some("unavailable")
    );
    assert_eq!(
        value.get("result").and_then(Value::as_str),
        Some("unavailable"),
        "two matched plus one unavailable must not yield matched"
    );
}

// ---------------------------------------------------------------------------
// C43: diagnostic rederivation carries a single comparison
// ---------------------------------------------------------------------------

#[test]
fn c43_diagnostic_rederivation_single_comparison() {
    let grant = operator_grant();
    let store = MemoryArtifactStore::new();

    let manifest = manifest_rec();
    let prefix = prefix_rec();
    let bundle = bundle_rec();
    let manifest_hash = digest_bytes(&canonical_bytes(&manifest).expect("must hash"));
    let expected_diag = expected_diagnostic_digest(&manifest, &prefix, &bundle);

    // Diagnostic-only bundle needs no external inputs or lifecycle data.
    let input_bundle = json!({
        "external_inputs": missing("not_observed"),
        "lifecycle_observations": missing("not_observed"),
        "diagnostic_manifest": manifest_value(),
        "diagnostic_prefix": prefix_value(),
        "diagnostic_bundle": bundle_value(),
    });
    let bundle_ref = install_bundle(&store, &grant, &input_bundle);
    let request = rederivation_request(&bundle_ref, &expected_diag, &manifest_hash);
    let receipt = replay_offline(&store, &grant, &request).expect("rederivation must succeed");
    let value = record_value(&receipt);
    assert_eq!(comparisons(value).len(), 1, "rederivation carries one comparison");
    assert_eq!(
        comparison_by(value, "diagnostic").get("result").and_then(Value::as_str),
        Some("matched")
    );
    assert_eq!(value.get("result").and_then(Value::as_str), Some("matched"));
    assert_no_external_execution(value);

    // Missing diagnostic inputs: single unavailable comparison, never matched.
    let missing_diag = json!({
        "diagnostic_manifest": manifest_value(),
        "diagnostic_prefix": missing("not_observed"),
        "diagnostic_bundle": bundle_value(),
    });
    let bundle_ref = install_bundle(&store, &grant, &missing_diag);
    let request = rederivation_request(&bundle_ref, &expected_diag, &manifest_hash);
    let receipt = replay_offline(&store, &grant, &request).expect("replay must return a receipt");
    let value = record_value(&receipt);
    assert_eq!(value.get("result").and_then(Value::as_str), Some("unavailable"));

    // Rederivation with an established reducer is refused.
    let bad_reducer = check(
        "audit_log",
        json!({
            "replay_id": "replay-d",
            "mode": "diagnostic_rederivation",
            "run_id": "run-1",
            "manifest_hash": manifest_hash,
            "source_prefix": prefix_value(),
            "source_diagnostic": {"digest": expected_diag},
            "input_bundle": record_value(&bundle_ref).clone(),
            "classifier": version_pin("classifier", "v1", b"classifier"),
            "reducer": version_pin("reducer", "v1", b"reducer"),
            "replay_engine": version_pin("replay-engine", "v1", b"engine"),
            "expected": {"diagnostic": expected_diag},
        }),
    );
    let err = replay_offline(&store, &grant, &bad_reducer).expect_err("established reducer must be refused");
    assert_eq!(err.code, "invalid_reducer");
}

// ---------------------------------------------------------------------------
// C43: employer mutations are never replayed
// ---------------------------------------------------------------------------

#[test]
fn c43_employer_mutation_never_replayed() {
    let grant = operator_grant();
    let store = MemoryArtifactStore::new();
    let external = external_inputs_value();
    let lifecycle = lifecycle_value();

    let manifest = manifest_rec();
    let prefix = prefix_rec();
    let bundle = bundle_rec();
    let manifest_hash = digest_bytes(&canonical_bytes(&manifest).expect("must hash"));
    let expected_diag = expected_diagnostic_digest(&manifest, &prefix, &bundle);
    let expected_sem = expected_semantic_simple(&external, &lifecycle);
    let expected_fin = expected_final_simple(&external, &lifecycle);

    let bundle_ref = install_bundle(&store, &grant, &bundle_simple(&external, &lifecycle));

    // Exact fixture with an employer-mutation marker is refused.
    let exact_mutation = check(
        "audit_log",
        json!({
            "replay_id": "replay-1",
            "mode": "exact_fixture",
            "run_id": "run-1",
            "manifest_hash": manifest_hash,
            "source_prefix": prefix_value(),
            "source_diagnostic": {"digest": expected_diag},
            "input_bundle": record_value(&bundle_ref).clone(),
            "classifier": version_pin("classifier", "v1", b"classifier"),
            "reducer": version_pin("reducer", "v1", b"reducer"),
            "replay_engine": version_pin("replay-engine", "v1", b"engine"),
            "expected": {
                "semantic_events": expected_sem,
                "final_state": expected_fin,
                "diagnostic": expected_diag,
            },
            "employer_mutation": true,
        }),
    );
    let err = replay_offline(&store, &grant, &exact_mutation).expect_err("employer mutation must be refused");
    assert_eq!(err.code, "employer_mutation_not_replayable");

    // Diagnostic rederivation with a mutation reference is refused.
    let rederivation_mutation = check(
        "audit_log",
        json!({
            "replay_id": "replay-d",
            "mode": "diagnostic_rederivation",
            "run_id": "run-1",
            "manifest_hash": manifest_hash,
            "source_prefix": prefix_value(),
            "source_diagnostic": {"digest": expected_diag},
            "input_bundle": record_value(&bundle_ref).clone(),
            "classifier": version_pin("classifier", "v1", b"classifier"),
            "reducer": missing_detail("not_applicable", "diagnostic-only replay uses no reducer"),
            "replay_engine": version_pin("replay-engine", "v1", b"engine"),
            "expected": {"diagnostic": expected_diag},
            "mutation_ref": {"mutation_id": "m-1"},
        }),
    );
    let err = replay_offline(&store, &grant, &rederivation_mutation)
        .expect_err("mutation_ref must be refused");
    assert_eq!(err.code, "employer_mutation_not_replayable");
}

// ---------------------------------------------------------------------------
// C43: lost bundle bytes preserve identity and yield unavailable
// ---------------------------------------------------------------------------

#[test]
fn c43_lost_bundle_bytes_preserve_digest_unavailable() {
    let grant = operator_grant();
    let full_store = MemoryArtifactStore::new();
    let empty_store = MemoryArtifactStore::new();
    let external = external_inputs_value();
    let lifecycle = lifecycle_value();

    let manifest = manifest_rec();
    let prefix = prefix_rec();
    let bundle = bundle_rec();
    let manifest_hash = digest_bytes(&canonical_bytes(&manifest).expect("must hash"));
    let expected_diag = expected_diagnostic_digest(&manifest, &prefix, &bundle);
    let expected_sem = expected_semantic_simple(&external, &lifecycle);
    let expected_fin = expected_final_simple(&external, &lifecycle);

    let bundle_ref = install_bundle(&full_store, &grant, &bundle_simple(&external, &lifecycle));
    let known_digest = record_value(&bundle_ref)
        .get("digest")
        .and_then(Value::as_str)
        .expect("reference must carry digest")
        .to_string();

    // Same reference against an empty store: bytes unavailable.
    let request = exact_request(&bundle_ref, &expected_sem, &expected_fin, &expected_diag, &manifest_hash);
    let receipt = replay_offline(&empty_store, &grant, &request).expect("lost bytes must yield a receipt");
    let value = record_value(&receipt);
    assert_eq!(value.get("result").and_then(Value::as_str), Some("unavailable"));
    for output in ["semantic_events", "final_state", "diagnostic"] {
        let entry = comparison_by(value, output);
        assert_eq!(
            entry.get("result").and_then(Value::as_str),
            Some("unavailable"),
            "{output} must be unavailable when bytes are lost"
        );
        let actual = entry.get("actual").expect("must carry actual");
        assert_eq!(actual.get("reason").and_then(Value::as_str), Some("observation_lost"));
    }
    // The known digest is preserved in the receipt, never erased.
    assert_eq!(
        value
            .get("input_bundle")
            .and_then(|view| view.get("digest"))
            .and_then(Value::as_str),
        Some(known_digest.as_str()),
        "receipt must preserve the known bundle digest"
    );
    assert_no_external_execution(value);
}

// ---------------------------------------------------------------------------
// C43: recomputation folds in normalization and detector evaluation
// ---------------------------------------------------------------------------

#[test]
fn c43_recomputation_uses_normalization_and_detectors() {
    let grant = operator_grant();
    let store = MemoryArtifactStore::new();
    let external = external_inputs_value();
    let lifecycle = lifecycle_value();
    let source_prefix = prefix_value();

    let manifest = manifest_rec();
    let prefix = prefix_rec();
    let bundle = bundle_rec();
    let manifest_hash = digest_bytes(&canonical_bytes(&manifest).expect("must hash"));
    let expected_diag = expected_diagnostic_digest(&manifest, &prefix, &bundle);

    let rows = vec![audit_row_value("evt-1"), audit_row_value("evt-2")];
    let declaration = detector_declaration_value();
    let prior = detector_prior_value();
    let packet = detector_packet_value();

    let expected_sem = expected_semantic_with_rows(&external, &lifecycle, &rows, &source_prefix);
    let expected_fin =
        expected_final_with_detector(&external, &lifecycle, &declaration, &prior, &packet);

    let full_bundle = json!({
        "external_inputs": external.clone(),
        "lifecycle_observations": lifecycle.clone(),
        "audit_rows": rows.clone(),
        "detector_transcript": {
            "declaration": declaration.clone(),
            "prior": prior.clone(),
            "packet": packet.clone(),
        },
        "diagnostic_manifest": manifest_value(),
        "diagnostic_prefix": prefix_value(),
        "diagnostic_bundle": bundle_value(),
    });
    let bundle_ref = install_bundle(&store, &grant, &full_bundle);
    let request = exact_request(&bundle_ref, &expected_sem, &expected_fin, &expected_diag, &manifest_hash);
    let receipt = replay_offline(&store, &grant, &request).expect("replay must succeed");
    let value = record_value(&receipt);
    assert_eq!(
        value.get("result").and_then(Value::as_str),
        Some("matched"),
        "correct normalization and detector inputs must match"
    );

    // Tampering with a normalized row changes the semantic digest.
    let mut tampered_rows = rows.clone();
    tampered_rows[0]["extra"] = Value::String("tampered".to_string());
    let tampered_bundle = json!({
        "external_inputs": external.clone(),
        "lifecycle_observations": lifecycle.clone(),
        "audit_rows": tampered_rows,
        "detector_transcript": {
            "declaration": declaration.clone(),
            "prior": prior.clone(),
            "packet": packet.clone(),
        },
        "diagnostic_manifest": manifest_value(),
        "diagnostic_prefix": prefix_value(),
        "diagnostic_bundle": bundle_value(),
    });
    let bundle_ref = install_bundle(&store, &grant, &tampered_bundle);
    let request = exact_request(&bundle_ref, &expected_sem, &expected_fin, &expected_diag, &manifest_hash);
    let receipt = replay_offline(&store, &grant, &request).expect("replay must return a receipt");
    let value = record_value(&receipt);
    assert_eq!(
        comparison_by(value, "semantic_events").get("result").and_then(Value::as_str),
        Some("mismatched"),
        "tampered normalized rows must mismatch semantic_events"
    );
    assert_eq!(value.get("result").and_then(Value::as_str), Some("mismatched"));

    // Tampering with the detector packet changes the final-state digest.
    let mut tampered_packet = packet.clone();
    tampered_packet["observed_total"] = json!(9);
    let tampered_detector_bundle = json!({
        "external_inputs": external.clone(),
        "lifecycle_observations": lifecycle.clone(),
        "audit_rows": rows.clone(),
        "detector_transcript": {
            "declaration": declaration.clone(),
            "prior": prior.clone(),
            "packet": tampered_packet,
        },
        "diagnostic_manifest": manifest_value(),
        "diagnostic_prefix": prefix_value(),
        "diagnostic_bundle": bundle_value(),
    });
    let bundle_ref = install_bundle(&store, &grant, &tampered_detector_bundle);
    let request = exact_request(&bundle_ref, &expected_sem, &expected_fin, &expected_diag, &manifest_hash);
    let receipt = replay_offline(&store, &grant, &request).expect("replay must return a receipt");
    let value = record_value(&receipt);
    assert_eq!(
        comparison_by(value, "final_state").get("result").and_then(Value::as_str),
        Some("mismatched"),
        "tampered detector packet must mismatch final_state"
    );
}

// ---------------------------------------------------------------------------
// C43: replay never mutates the diagnostic
// ---------------------------------------------------------------------------

#[test]
fn c43_replay_never_mutates_diagnostic() {
    let grant = operator_grant();
    let store = MemoryArtifactStore::new();
    let external = external_inputs_value();
    let lifecycle = lifecycle_value();

    let manifest = manifest_rec();
    let prefix = prefix_rec();
    let bundle = bundle_rec();
    let before = derive_diagnostic(&manifest, &prefix, &bundle).expect("derive must succeed");
    let before_digest = digest_bytes(&canonical_bytes(&before).expect("must hash"));

    let manifest_hash = digest_bytes(&canonical_bytes(&manifest).expect("must hash"));
    let expected_diag = expected_diagnostic_digest(&manifest, &prefix, &bundle);
    assert_eq!(before_digest, expected_diag, "expected diagnostic must equal derived digest");
    let expected_sem = expected_semantic_simple(&external, &lifecycle);
    let expected_fin = expected_final_simple(&external, &lifecycle);

    let bundle_ref = install_bundle(&store, &grant, &bundle_simple(&external, &lifecycle));
    let request = exact_request(&bundle_ref, &expected_sem, &expected_fin, &expected_diag, &manifest_hash);
    let receipt = replay_offline(&store, &grant, &request).expect("replay must succeed");
    assert_eq!(
        record_value(&receipt).get("result").and_then(Value::as_str),
        Some("matched")
    );

    // Re-deriving after replay yields the identical diagnostic: the receipt
    // is a separate immutable record, not a mutation.
    let after = derive_diagnostic(&manifest, &prefix, &bundle).expect("derive must succeed");
    let after_digest = digest_bytes(&canonical_bytes(&after).expect("must hash"));
    assert_eq!(before_digest, after_digest, "replay must not mutate the diagnostic");
}

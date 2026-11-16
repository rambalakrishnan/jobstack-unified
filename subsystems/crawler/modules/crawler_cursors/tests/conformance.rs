//! Conformance tests for [C28] cursor restrictions and [C29] unverified
//! capability.
//!
//! C28: numeric positional aliases (`page=N`, `start=N`, `Page$N`,
//! postbacks, `offset`, `numeric`, `positional`) are rejected outside the
//! exact Floor scope `ordering_model=Deterministic` with
//! `coverage_scope=per_run`. Renamed continuations (arithmetic or stored
//! coordinates claimed as response-bound) are rejected as well.
//!
//! C29: initial-response evidence is preserved as a closed
//! `crawler_uncertified_traversal_observation` without positive proof or a
//! fabricated certified cursor. Exhaustive single-response promotion without
//! its own proof is rejected, replay deduplicates, conflicts are integrity
//! incidents, and incompatible resume generations are refused.

use crawler_cursors::{plan_cursor_step, plan_observation_commit, validate_resume};
use crawler_schema::{record_schema, record_value, validate, CheckedRecord};
use serde_json::{json, Value};

fn check(schema: &str, value: Value) -> CheckedRecord {
    validate(schema, value).expect("test fixture must satisfy the schema gate")
}

fn missing(reason: &str) -> Value {
    json!({"value": null, "reason": reason})
}

fn missing_detail(reason: &str, detail: &str) -> Value {
    json!({"value": null, "reason": reason, "detail": detail})
}

fn sh(byte: char) -> Value {
    json!({
        "value": byte.to_string().repeat(64),
        "profile": "crawler-page-hash/1",
        "evidence_refs": [{"ref": "test"}],
    })
}

fn fingerprint(byte: char) -> Value {
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

fn verdict_counts(pass: u64) -> Value {
    json!({
        "Pass": pass,
        "ThinShell": 0,
        "RenderIncomplete": 0,
        "EdgeBlock": 0,
        "SensorFail": 0,
        "ChallengeIncomplete": 0,
    })
}

fn evidence_refs() -> Value {
    json!([{
        "journal_id": "j-1",
        "sequence": 1,
        "event_id": "evt-1",
        "event_hash": "abc",
        "pointer": "/row",
    }])
}

const MINIMUM_IDS: &[&str] = &[
    "native_goal_task",
    "native_plan_execution",
    "native_cancel",
    "native_context_release",
    "native_artifact_retrieval",
    "native_revision",
    "native_dom_access",
    "browser_state_isolation",
    "browser_state_persistence",
    "learning_state_control",
];

fn descriptor_value(availability: &str, with_executed: bool) -> Value {
    let mut catalog = Vec::new();
    for id in MINIMUM_IDS {
        catalog.push(json!({
            "capability_id": id,
            "availability": "unknown",
            "requirement_refs": [],
            "claim_origin": "native",
            "evidence": [],
            "limitations": [],
        }));
    }
    let evidence = if with_executed {
        json!([{
            "basis": "executed_observation",
            "ref": {
                "journal_id": "j-1",
                "sequence": 1,
                "event_id": "e1",
                "event_hash": "abc",
                "pointer": "/x",
            },
            "subject_version": "v1",
        }])
    } else {
        json!([])
    };
    catalog.push(json!({
        "capability_id": "crawler_certified_cursor",
        "availability": availability,
        "requirement_refs": [],
        "claim_origin": "native",
        "evidence": evidence,
        "limitations": [],
    }));
    json!({
        "record_type": "connector_descriptor",
        "subject": {
            "subject_id": "crawler-subject",
            "subject_version": "v1",
            "configured_mode": "service",
            "interface_surface": "ordinary_browser",
        },
        "capabilities": {
            "capabilities": catalog,
        },
    })
}

fn scope_value() -> Value {
    json!({
        "subject_id": "crawler-subject",
        "subject_version": "v1",
        "configured_mode": "service",
        "interface_surface": "ordinary_browser",
    })
}

fn capability_wrapper(availability: &str, with_executed: bool) -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "descriptor": descriptor_value(availability, with_executed),
            "scope": scope_value(),
            "capability_id": "crawler_certified_cursor",
        }),
    )
}

fn verified_capability() -> CheckedRecord {
    capability_wrapper("present", true)
}

fn unverified_capability() -> CheckedRecord {
    capability_wrapper("unknown", false)
}

fn declaration_value(target: &str, ordering: &str, scope: &str, kind: &str) -> Value {
    json!({
        "target": target,
        "run_id": "run-1",
        "partition_id": "p-1",
        "ordering_model": ordering,
        "coverage_scope": scope,
        "proposed_cursor_kind": kind,
        "evidence_refs": evidence_refs(),
    })
}

fn cursor_value(
    target: &str,
    kind: &str,
    ordering: &str,
    scope: &str,
    revision: u64,
    last_seq: u64,
) -> Value {
    json!({
        "target": target,
        "run_id": "run-1",
        "partition_id": "p-1",
        "walk_id": "walk-1",
        "worker_identity": "worker-1",
        "owner_epoch": 1,
        "phase": "A",
        "cursor_kind": kind,
        "cursor_payload_json": {},
        "previous_response_hash": sh('a'),
        "cursor_revision": revision,
        "ordering_model": ordering,
        "coverage_scope": scope,
        "ordering_fingerprint": fingerprint('f'),
        "backend_signature": missing("not_applicable"),
        "session_epoch": missing("not_applicable"),
        "status": "active",
        "last_committed_request_sequence": last_seq,
    })
}

fn response_value(seq: u64) -> Value {
    json!({
        "request_sequence": seq,
        "request_identity": {"url": "https://example.com/jobs?page=1", "method": "GET"},
        "response": artifact_ref(),
        "ordered_observed_ids": ["job-1", "job-2"],
        "render_verdict_counts": verdict_counts(2),
        "page_hash": sh('p'),
        "session_epoch": missing("not_applicable"),
        "backend_signature": missing("not_applicable"),
        "evidence_refs": evidence_refs(),
    })
}

fn packet_value(seq: u64, status: &str) -> Value {
    json!({
        "target": "IL",
        "run_id": "run-1",
        "partition_id": "p-1",
        "walk_id": "walk-1",
        "request_sequence": seq,
        "request_identity": {"url": "https://example.com/jobs", "method": "GET"},
        "response_hash": sh('r'),
        "page_hash": sh('p'),
        "ordered_observed_ids": ["job-1"],
        "render_verdict_counts": verdict_counts(1),
        "reported_count_evidence": missing("not_observed"),
        "session_epoch": missing("not_applicable"),
        "backend_signature": missing("not_applicable"),
        "cursor_capability_status": status,
        "evidence_refs": evidence_refs(),
    })
}

fn session_value(session_epoch: Value) -> Value {
    json!({
        "target": "IL",
        "run_id": "run-1",
        "phase": "A",
        "shard_id": "shard-1",
        "session_epoch": session_epoch,
        "worker_identity": "worker-1",
        "owner_epoch": 1,
        "status": "active",
    })
}

fn ordering_value(ordering: &str, scope: &str) -> Value {
    json!({
        "target": "IL",
        "run_id": "run-1",
        "partition_id": "p-1",
        "ordering_model": ordering,
        "coverage_scope": scope,
        "ordering_fingerprint": fingerprint('f'),
        "backend_signature": missing("not_applicable"),
    })
}

// ---------------------------------------------------------------------------
// C28: cursor restrictions
// ---------------------------------------------------------------------------

#[test]
fn c28_cursor_restrictions() {
    // MN churn-shifted numeric page walk is uncertified, even with verified
    // capability evidence: the Floor denies positional aliases outside
    // Deterministic/per_run.
    for (target, ordering, kind) in [
        ("MN", "ChurnShifted", "positional_Page$N"),
        ("MN", "Churn-shifted", "page"),
        ("WI", "ChurnShifted", "Page$N"),
        ("WI", "Deterministic", "Page$N"), // scope below is session_union
        ("MI", "Session-randomized", "offset"),
        ("OR", "Ascending-by-ID with overflow", "start"),
        ("MN", "ChurnShifted", "numeric_next"),
        ("WI", "ChurnShifted", "postback"),
    ] {
        let scope = if target == "WI" && ordering == "Deterministic" {
            "session_union"
        } else {
            "per_run"
        };
        // For the WI deterministic/session_union row the scope itself voids
        // the Floor; all other rows void it via the ordering model.
        let declaration = check(
            "audit_log",
            declaration_value(target, ordering, scope, kind),
        );
        let cursor = check(
            "cursor_state",
            cursor_value(target, kind, ordering, scope, 0, 0),
        );
        let response = check("audit_log", response_value(1));
        // Response scope pins are absent here; walk scope comes from the
        // declaration/cursor pair. Align response session/backend with the
        // sessionless cursor (already Missing in fixtures).
        let err = plan_cursor_step(&declaration, &cursor, &response, &verified_capability())
            .expect_err("positional alias outside Deterministic/per_run must be rejected");
        assert_eq!(
            err.code, "uncertified_positional",
            "target={target} ordering={ordering} kind={kind} scope={scope}: {}: {}",
            err.code, err.detail
        );
    }

    // MN page=N stored as a bare coordinate is still positional even when the
    // kind label is disguised.
    {
        let mut decl = declaration_value("MN", "ChurnShifted", "per_run", "continuation");
        decl["page"] = json!(3);
        // Continuation with a numeric coordinate is renaming, but the bare
        // coordinate outside the Floor is positional first. Either code
        // proves the alias was not accepted as a certified continuation.
        let declaration = check("audit_log", decl);
        let cursor = check(
            "cursor_state",
            cursor_value("MN", "continuation", "ChurnShifted", "per_run", 0, 0),
        );
        let mut resp = response_value(1);
        resp["continuation_token"] = json!("tok-1");
        let response = check("audit_log", resp);
        let err = plan_cursor_step(&declaration, &cursor, &response, &verified_capability())
            .expect_err("bare page coordinate must not pass as continuation");
        assert!(
            err.code == "uncertified_positional" || err.code == "renamed_positional",
            "unexpected code {}: {}",
            err.code,
            err.detail
        );
    }

    // IL deterministic per-run offsets are the one permitted positional
    // scope: a verified step plans revision+1 with a framed cursor ref.
    {
        let declaration = check(
            "audit_log",
            declaration_value("IL", "Deterministic", "per_run", "offset"),
        );
        let cursor = check(
            "cursor_state",
            cursor_value("IL", "offset", "Deterministic", "per_run", 2, 4),
        );
        let response = check("audit_log", response_value(5));
        let plan = plan_cursor_step(&declaration, &cursor, &response, &verified_capability())
            .expect("IL deterministic per-run offset must plan");
        assert_eq!(record_schema(&plan), "audit_log");
        let value = record_value(&plan);
        let map = value.as_object().expect("plan must be an object");
        assert_eq!(map.get("record_type").and_then(Value::as_str), Some("cursor_step_plan"));
        assert_eq!(map.get("prior_revision").and_then(Value::as_u64), Some(2));
        assert_eq!(map.get("next_revision").and_then(Value::as_u64), Some(3));
        assert_eq!(map.get("request_sequence").and_then(Value::as_u64), Some(5));
        assert_eq!(map.get("certified").and_then(Value::as_bool), Some(true));
        let cursor_ref = map
            .get("cursor_ref")
            .and_then(Value::as_str)
            .expect("plan must carry a framed cursor_ref");
        assert!(
            cursor_ref.starts_with("cursor_state:4:"),
            "cursor_ref must be a length-framed cursor_state reference, got {cursor_ref:?}"
        );
        assert!(
            map.get("next_request_identity").is_some(),
            "verified non-terminal step must plan a next request"
        );
    }

    // Renaming: an arithmetic/stored coordinate claimed as continuation or
    // keyset is rejected even inside a certified ordering scope.
    for (source_field, source_value) in [
        ("continuation_source", json!("arithmetic")),
        ("continuation_source", json!("stored_coordinate")),
        ("continuation_source", json!("session_bound")),
        ("continuation_source", json!("next_link")),
        ("response_bound", json!(false)),
    ] {
        let mut decl = declaration_value("IL", "Deterministic", "per_run", "continuation");
        decl[source_field] = source_value;
        let declaration = check("audit_log", decl);
        let cursor = check(
            "cursor_state",
            cursor_value("IL", "continuation", "Deterministic", "per_run", 0, 0),
        );
        let mut resp = response_value(1);
        resp["continuation_token"] = json!("tok-1");
        let response = check("audit_log", resp);
        let err = plan_cursor_step(&declaration, &cursor, &response, &verified_capability())
            .expect_err("renamed continuation must be rejected");
        assert_eq!(err.code, "renamed_positional", "field={source_field}: {}", err.detail);
    }

    // A continuation payload embedding page/start/offset is the same rename.
    {
        let declaration = check(
            "audit_log",
            declaration_value("IL", "Deterministic", "per_run", "keyset"),
        );
        let mut cursor_json = cursor_value("IL", "keyset", "Deterministic", "per_run", 0, 0);
        cursor_json["cursor_payload_json"] = json!({"page": 4});
        let cursor = check("cursor_state", cursor_json);
        let mut resp = response_value(1);
        resp["continuation_token"] = json!("tok-1");
        let response = check("audit_log", resp);
        let err = plan_cursor_step(&declaration, &cursor, &response, &verified_capability())
            .expect_err("payload-embedded page must not pass as keyset");
        assert_eq!(err.code, "renamed_positional");
    }

    // Continuation without a materialized token (and without termination)
    // plans beyond the response and is refused.
    {
        let mut decl_extra = declaration_value("IL", "Deterministic", "per_run", "continuation");
        decl_extra["continuation_source"] = json!("response_bound");
        let declaration = check("audit_log", decl_extra);
        let cursor = check(
            "cursor_state",
            cursor_value("IL", "continuation", "Deterministic", "per_run", 0, 0),
        );
        let response = check("audit_log", response_value(1));
        let err = plan_cursor_step(&declaration, &cursor, &response, &verified_capability())
            .expect_err("unbound continuation must be refused");
        assert_eq!(err.code, "continuation_not_bound");
    }

    // Resume enforces the same Floor: a positional cursor outside
    // Deterministic/per_run cannot resume even with matching generations.
    {
        let cursor = check(
            "cursor_state",
            cursor_value("MN", "Page$N", "ChurnShifted", "per_run", 0, 0),
        );
        // Ordering and session fixtures pin IL scope; rebuild for MN to
        // isolate the positional fault from a scope mismatch.
        let ordering = check(
            "audit_log",
            json!({
                "target": "MN",
                "run_id": "run-1",
                "partition_id": "p-1",
                "ordering_model": "ChurnShifted",
                "coverage_scope": "per_run",
                "ordering_fingerprint": fingerprint('f'),
                "backend_signature": missing("not_applicable"),
            }),
        );
        let session = check(
            "session_state",
            json!({
                "target": "MN",
                "run_id": "run-1",
                "phase": "A",
                "shard_id": "shard-1",
                "session_epoch": missing("not_applicable"),
                "worker_identity": "worker-1",
                "owner_epoch": 1,
                "status": "active",
            }),
        );
        let err = validate_resume(&cursor, &session, &ordering)
            .expect_err("positional resume outside the Floor must be rejected");
        assert_eq!(err.code, "uncertified_positional");
    }

    // Unknown kinds are neither verified nor positional aliases.
    {
        let declaration = check(
            "audit_log",
            declaration_value("IL", "Deterministic", "per_run", "mystery_cursor"),
        );
        let cursor = check(
            "cursor_state",
            cursor_value("IL", "mystery_cursor", "Deterministic", "per_run", 0, 0),
        );
        let response = check("audit_log", response_value(1));
        let err = plan_cursor_step(&declaration, &cursor, &response, &verified_capability())
            .expect_err("unknown kind must be rejected");
        assert_eq!(err.code, "unknown_cursor_kind");
    }
}

// ---------------------------------------------------------------------------
// C29: unverified capability
// ---------------------------------------------------------------------------

#[test]
fn c29_unverified_capability() {
    // Initial evidence with an unverified capability succeeds as a closed
    // uncertified packet: no positive proof, no fabricated cursor.
    let packet = {
        let declaration = check(
            "audit_log",
            declaration_value("MN", "ChurnShifted", "per_run", "positional_Page$N"),
        );
        let cursor = check(
            "cursor_state",
            cursor_value("MN", "positional_Page$N", "ChurnShifted", "per_run", 0, 0),
        );
        let response = check("audit_log", response_value(1));
        let packet = plan_cursor_step(&declaration, &cursor, &response, &unverified_capability())
            .expect("unverified initial evidence must be preserved");
        assert_eq!(
            record_schema(&packet),
            "crawler_uncertified_traversal_observation"
        );
        let value = record_value(&packet);
        let map = value.as_object().expect("packet must be an object");
        // Every §4.3 required field is present with the pinned values.
        assert_eq!(
            map.get("record_type").and_then(Value::as_str),
            Some("crawler_uncertified_traversal_observation")
        );
        assert_eq!(map.get("schema_version").and_then(Value::as_str), Some("crawler-seam/0.1.0"));
        assert_eq!(map.get("target").and_then(Value::as_str), Some("MN"));
        assert_eq!(map.get("run_id").and_then(Value::as_str), Some("run-1"));
        assert_eq!(map.get("partition_id").and_then(Value::as_str), Some("p-1"));
        let observation_id = map
            .get("observation_id")
            .and_then(Value::as_str)
            .expect("packet must carry an observation_id");
        assert!(
            observation_id.contains("cursor_state:4:"),
            "observation_id must embed the framed walk ref, got {observation_id:?}"
        );
        assert!(observation_id.contains(":seq:1:"), "observation_id must embed the sequence");
        assert!(map.get("request_identity").and_then(Value::as_object).is_some());
        assert!(map.get("response").and_then(Value::as_object).is_some());
        assert_eq!(
            map.get("ordered_observed_ids"),
            Some(&json!(["job-1", "job-2"])),
            "ordered ids must survive verbatim"
        );
        let counts = map
            .get("render_verdict_counts")
            .and_then(Value::as_object)
            .expect("packet must carry verdict counts");
        for verdict in ["Pass", "ThinShell", "RenderIncomplete", "EdgeBlock", "SensorFail", "ChallengeIncomplete"] {
            assert!(counts.contains_key(verdict), "missing verdict {verdict}");
        }
        assert!(map.get("page_hash").is_some());
        assert_eq!(
            map.get("cursor_capability_status").and_then(Value::as_str),
            Some("unverified")
        );
        assert_eq!(
            map.get("proposed_cursor_kind").and_then(Value::as_str),
            Some("positional_Page$N")
        );
        assert_eq!(map.get("ordering_model").and_then(Value::as_str), Some("ChurnShifted"));
        assert!(map.get("session_epoch").is_some());
        assert!(map.get("backend_signature").is_some());
        assert_eq!(
            map.get("accepted_for_positive_proof").and_then(Value::as_bool),
            Some(false),
            "uncertified evidence never admits positive proof"
        );
        let evidence = map
            .get("evidence_refs")
            .and_then(Value::as_array)
            .expect("packet must carry SUPPORT");
        assert!(!evidence.is_empty());
        // No certified cursor is fabricated alongside the evidence.
        assert!(
            map.get("next_request_identity").is_none(),
            "uncertified packet must not plan a certified continuation"
        );
        assert!(
            map.get("cursor_revision").is_none(),
            "uncertified packet must not advance a revision"
        );
        assert!(
            map.get("certified").is_none(),
            "uncertified packet must not claim certification"
        );
        assert!(
            map.get("in_active_proof_cohort").is_none(),
            "uncertified packet is not a cohort member"
        );
        packet
    };
    let _ = packet;

    // An unverified first page is never promoted to exhaustive certification:
    // with verified capability but without single-response proof the plan is
    // rejected, and with unverified capability it stays uncertified.
    {
        let mut decl = declaration_value("IL", "Deterministic", "per_run", "exhaustive_single_response");
        let declaration = check("audit_log", decl.clone());
        let cursor = check(
            "cursor_state",
            cursor_value("IL", "exhaustive_single_response", "Deterministic", "per_run", 0, 0),
        );
        let response = check("audit_log", response_value(1));
        let err = plan_cursor_step(&declaration, &cursor, &response, &verified_capability())
            .expect_err("exhaustive without proof must be rejected");
        assert_eq!(err.code, "uncertified_exhaustive");

        // Unverified capability + exhaustive proposal => uncertified packet,
        // not a certified exhaustive plan.
        let packet = plan_cursor_step(&declaration, &cursor, &response, &unverified_capability())
            .expect("unverified exhaustive proposal stays uncertified");
        let map = record_value(&packet).as_object().expect("packet object");
        assert_eq!(
            map.get("cursor_capability_status").and_then(Value::as_str),
            Some("unverified")
        );
        assert_eq!(
            map.get("accepted_for_positive_proof").and_then(Value::as_bool),
            Some(false)
        );
        assert_eq!(
            map.get("proposed_cursor_kind").and_then(Value::as_str),
            Some("exhaustive_single_response")
        );

        // Genuine exhaustive proof with verified capability does plan, and
        // terminates without a further request.
        decl["single_response_proof"] = json!(true);
        let declaration = check("audit_log", decl);
        let mut resp = response_value(1);
        resp["exhaustive"] = json!(true);
        let response = check("audit_log", resp);
        let plan = plan_cursor_step(&declaration, &cursor, &response, &verified_capability())
            .expect("proved exhaustive single response must plan");
        let map = record_value(&plan).as_object().expect("plan object");
        assert_eq!(map.get("certified").and_then(Value::as_bool), Some(true));
        let next = map.get("next_request_identity").expect("exhaustive plan has next marker");
        assert!(
            next.as_object().is_some_and(|object| object
                .get("value")
                .is_some_and(Value::is_null)),
            "exhaustive termination plans no further request"
        );
    }

    // Verified response-bound continuation plans a certified step (contrast
    // with the uncertified path above).
    {
        let mut decl = declaration_value("IL", "Deterministic", "per_run", "continuation");
        decl["continuation_source"] = json!("response_bound");
        let declaration = check("audit_log", decl);
        let cursor = check(
            "cursor_state",
            cursor_value("IL", "continuation", "Deterministic", "per_run", 0, 0),
        );
        let mut resp = response_value(1);
        resp["continuation_token"] = json!("tok-1");
        let response = check("audit_log", resp);
        let plan = plan_cursor_step(&declaration, &cursor, &response, &verified_capability())
            .expect("bound continuation must plan");
        let map = record_value(&plan).as_object().expect("plan object");
        assert_eq!(map.get("certified").and_then(Value::as_bool), Some(true));
        assert_eq!(map.get("next_revision").and_then(Value::as_u64), Some(1));
    }

    // Observation commits: verified packets join the cohort, unverified ones
    // materialize without proof, replay deduplicates, conflicts and gaps fail.
    {
        let cursor = check(
            "cursor_state",
            cursor_value("IL", "offset", "Deterministic", "per_run", 3, 7),
        );
        // Next packet commits with cohort admission when verified.
        let packet = check("audit_log", packet_value(8, "verified"));
        let plan = plan_observation_commit(&cursor, &packet).expect("next packet must commit");
        let map = record_value(&plan).as_object().expect("plan object");
        assert_eq!(map.get("deduped").and_then(Value::as_bool), Some(false));
        assert_eq!(map.get("in_active_proof_cohort").and_then(Value::as_bool), Some(true));
        assert_eq!(map.get("next_revision").and_then(Value::as_u64), Some(4));
        let observation_id = map.get("observation_id").and_then(Value::as_str).expect("id");
        assert!(observation_id.contains(":seq:8:"));

        // The same packet shape with unverified status stays out of the cohort.
        let packet = check("audit_log", packet_value(8, "unverified"));
        let plan = plan_observation_commit(&cursor, &packet).expect("unverified packet still commits");
        let map = record_value(&plan).as_object().expect("plan object");
        assert_eq!(map.get("in_active_proof_cohort").and_then(Value::as_bool), Some(false));
        assert_eq!(map.get("deduped").and_then(Value::as_bool), Some(false));

        // Replay of the last committed sequence with identical hashes
        // deduplicates without advancing or joining the cohort.
        let mut replay_cursor = cursor_value("IL", "offset", "Deterministic", "per_run", 3, 8);
        replay_cursor["previous_response_hash"] = sh('r');
        let cursor = check("cursor_state", replay_cursor);
        let packet = check("audit_log", packet_value(8, "verified"));
        let plan = plan_observation_commit(&cursor, &packet).expect("identical replay must dedup");
        let map = record_value(&plan).as_object().expect("plan object");
        assert_eq!(map.get("deduped").and_then(Value::as_bool), Some(true));
        assert_eq!(map.get("in_active_proof_cohort").and_then(Value::as_bool), Some(false));
        assert_eq!(map.get("next_revision").and_then(Value::as_u64), Some(3));

        // Same sequence with different hashes is an integrity conflict.
        let mut conflict_cursor = cursor_value("IL", "offset", "Deterministic", "per_run", 3, 8);
        conflict_cursor["previous_response_hash"] = sh('z');
        let cursor = check("cursor_state", conflict_cursor);
        let packet = check("audit_log", packet_value(8, "verified"));
        let err = plan_observation_commit(&cursor, &packet)
            .expect_err("conflicting redelivery must be an integrity incident");
        assert_eq!(err.code, "integrity_conflict");

        // A sequence skipping ahead of the durable boundary is rejected.
        let cursor = check(
            "cursor_state",
            cursor_value("IL", "offset", "Deterministic", "per_run", 3, 7),
        );
        let packet = check("audit_log", packet_value(10, "verified"));
        let err = plan_observation_commit(&cursor, &packet)
            .expect_err("gapped packet must not commit ahead");
        assert_eq!(err.code, "beyond_materialized");

        // Incompatible backend generations never merge.
        let mut backend_packet = packet_value(8, "verified");
        backend_packet["backend_signature"] = json!("backend-2");
        let packet = check("audit_log", backend_packet);
        let err = plan_observation_commit(&cursor, &packet)
            .expect_err("backend mismatch must be rejected");
        assert_eq!(err.code, "backend_mismatch");
    }

    // Resume: compatible generations pass; session, backend, fingerprint,
    // and owner mismatches are refused without coercion.
    {
        let cursor = check(
            "cursor_state",
            cursor_value("IL", "offset", "Deterministic", "per_run", 1, 2),
        );
        let session = check("session_state", session_value(missing("not_applicable")));
        // Cursor and session fixtures both use owner_epoch 1; align them.
        let ordering = check("audit_log", ordering_value("Deterministic", "per_run"));
        validate_resume(&cursor, &session, &ordering).expect("compatible resume must pass");

        // Integer 7 and string "7" are distinct session generations.
        let mut int_cursor = cursor_value("IL", "offset", "Deterministic", "per_run", 1, 2);
        int_cursor["session_epoch"] = json!(7);
        let cursor = check("cursor_state", int_cursor);
        let session = check("session_state", session_value(json!("7")));
        let err = validate_resume(&cursor, &session, &ordering)
            .expect_err("int/string session coercion must be rejected");
        assert_eq!(err.code, "session_mismatch");

        // Established versus missing generations mismatch.
        let cursor = check(
            "cursor_state",
            cursor_value("IL", "offset", "Deterministic", "per_run", 1, 2),
        );
        let session = check("session_state", session_value(json!("epoch-9")));
        let err = validate_resume(&cursor, &session, &ordering)
            .expect_err("session generation substitution must be rejected");
        assert_eq!(err.code, "session_mismatch");

        // Backend discontinuity invalidates the cohort.
        let mut backend_ordering = ordering_value("Deterministic", "per_run");
        backend_ordering["backend_signature"] = json!("backend-2");
        let ordering = check("audit_log", backend_ordering);
        let session = check("session_state", session_value(missing("not_applicable")));
        let err = validate_resume(&cursor, &session, &ordering)
            .expect_err("backend discontinuity must be rejected");
        assert_eq!(err.code, "backend_mismatch");

        // Ordering fingerprint drift refuses restart from the old coordinate.
        let mut drift_ordering = ordering_value("Deterministic", "per_run");
        drift_ordering["ordering_fingerprint"] = fingerprint('z');
        let ordering = check("audit_log", drift_ordering);
        let err = validate_resume(&cursor, &session, &ordering)
            .expect_err("fingerprint drift must be rejected");
        assert_eq!(err.code, "ordering_drift");

        // Silently rewriting the ordering declaration is refused.
        let ordering = check("audit_log", ordering_value("ChurnShifted", "per_run"));
        let err = validate_resume(&cursor, &session, &ordering)
            .expect_err("ordering rewrite must be rejected");
        assert_eq!(err.code, "ordering_mismatch");
    }

    // Capability wiring: the wrong capability id and scope mismatches never
    // certify traversal.
    {
        let declaration = check(
            "audit_log",
            declaration_value("IL", "Deterministic", "per_run", "offset"),
        );
        let cursor = check(
            "cursor_state",
            cursor_value("IL", "offset", "Deterministic", "per_run", 0, 0),
        );
        let response = check("audit_log", response_value(1));
        let wrong = check(
            "audit_log",
            json!({
                "descriptor": descriptor_value("present", true),
                "scope": scope_value(),
                "capability_id": "crawler_independent_counts",
            }),
        );
        let err = plan_cursor_step(&declaration, &cursor, &response, &wrong)
            .expect_err("wrong capability must not certify cursors");
        assert_eq!(err.code, "wrong_capability");

        let mut bad_scope = scope_value();
        bad_scope["subject_version"] = json!("v2");
        let mismatched = check(
            "audit_log",
            json!({
                "descriptor": descriptor_value("present", true),
                "scope": bad_scope,
                "capability_id": "crawler_certified_cursor",
            }),
        );
        let err = plan_cursor_step(&declaration, &cursor, &response, &mismatched)
            .expect_err("scope mismatch must propagate");
        assert_eq!(err.code, "scope_mismatch");
    }

    // Declaration assessment fields are forbidden even on the uncertified path.
    {
        let mut decl = declaration_value("MN", "ChurnShifted", "per_run", "positional_Page$N");
        decl["application_success"] = json!(true);
        let declaration = check("audit_log", decl);
        let cursor = check(
            "cursor_state",
            cursor_value("MN", "positional_Page$N", "ChurnShifted", "per_run", 0, 0),
        );
        let response = check("audit_log", response_value(1));
        let err = plan_cursor_step(&declaration, &cursor, &response, &unverified_capability())
            .expect_err("assessment in a declaration must be rejected");
        assert_eq!(err.code, "forbidden_assessment");
    }

    // Silence unused-helper warnings for fixtures kept for clarity.
    let _ = missing_detail("not_observed", "kept");
}

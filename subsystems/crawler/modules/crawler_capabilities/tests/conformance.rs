//! Conformance tests for [C46]: evidence honesty.
//!
//! Unverified solver, counts, cursor, lifetime, and performance remain
//! unverified: documentation, declarations, predecessor evidence, renamed
//! cursors, and placeholder solvers never establish presence.

use crawler_authority::{authorize_producer, Grant};
use crawler_capabilities::{check_capability, describe_configuration};
use crawler_hashing::{canonical_bytes, digest_bytes};
use crawler_schema::{record_value, validate, CheckedRecord, Fault};
use crawler_store::OwnerStore;
use serde_json::{json, Value};

fn check(schema: &str, value: Value) -> CheckedRecord {
    validate(schema, value).expect("test fixture must validate")
}

fn binding_of(record: &CheckedRecord) -> String {
    digest_bytes(&canonical_bytes(record).expect("canonical bytes must exist"))
}

fn manifest_fixture() -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "manifest_id": "manifest-cap",
            "producer_registry": [
                {
                    "producer_id": "cap-writer",
                    "owner_domain": "crawler",
                    "role": "external_input",
                    "provenance": "server",
                    "assertion_kind": "claim",
                },
            ],
            "event_registry": [
                {
                    "event_kind": "listing_observed",
                    "permitted_provenance": ["server"],
                },
            ],
        }),
    )
}

fn grant_for(manifest: &CheckedRecord) -> Grant {
    let principal = check(
        "audit_log",
        json!({
            "producer_id": "cap-writer",
            "manifest_digest": binding_of(manifest),
        }),
    );
    let submission = check("audit_log", json!({"event_kind": "listing_observed"}));
    authorize_producer(&principal, &submission, manifest).expect("grant must issue")
}

/// Owner store stub: `transact` is never used by Describe; `read` grounds one
/// canned journal prefix and rejects anything else as an unknown journal.
struct StubStore;

impl OwnerStore for StubStore {
    fn transact(&self, _grant: &Grant, _transaction: &CheckedRecord) -> Result<CheckedRecord, Fault> {
        Err(Fault {
            code: "not_supported".to_string(),
            detail: "describe performs no writes".to_string(),
        })
    }

    fn read(&self, _grant: &Grant, query: &CheckedRecord) -> Result<CheckedRecord, Fault> {
        let map = record_value(query)
            .as_object()
            .expect("query must be an object");
        let journal_id = map
            .get("journal_id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if journal_id != "journal-1" {
            return Err(Fault {
                code: "unknown_journal".to_string(),
                detail: format!("journal {journal_id:?} has not admitted a manifest"),
            });
        }
        validate(
            "audit_log",
            json!({
                "record_type": "journal_prefix",
                "journal_id": "journal-1",
                "last_sequence": 1,
                "head_hash": "a".repeat(64),
            }),
        )
    }
}

fn base_configuration() -> Value {
    json!({
        "connector_id": "crawler-connector",
        "connector_version": "0.1.0",
        "build": {"id": "crawler-build", "version": "0.1.0"},
        "binding": {"id": "crawler-binding", "version": "0.1.0"},
        "subject": {
            "subject_id": "il-crawler",
            "subject_version": "v1",
            "configured_mode": "service",
            "interface_surface": "ordinary_browser",
        },
        "owner_domain": "crawler",
        "limits": {
            "max_call_wait": {"kind": "exact", "unit": "ms", "value": 30000},
            "max_observe_items": 100,
            "max_request_bytes": 65536,
            "max_response_bytes": 67108864,
            "max_artifact_chunk_bytes": 1048576,
            "max_queued_tasks": 10,
            "max_active_tasks": 2,
        },
        "budget_accounting": {"id": "crawler-budget", "version": "1"},
    })
}

fn evidence_ref() -> Value {
    json!({
        "journal_id": "journal-1",
        "sequence": 1,
        "event_id": "evt-1",
        "event_hash": format!("sha256:{}", "b".repeat(64)),
        "pointer": "",
    })
}

fn doc_evidence() -> Value {
    json!({"basis": "documentation", "ref": evidence_ref()})
}

fn exec_evidence() -> Value {
    json!({"basis": "executed_observation", "ref": evidence_ref()})
}

fn exec_evidence_for(version: &str) -> Value {
    json!({
        "basis": "executed_observation",
        "ref": evidence_ref(),
        "subject_version": version,
    })
}

fn availability_of(descriptor: &CheckedRecord, capability_id: &str) -> String {
    let caps = record_value(descriptor)
        .get("capabilities")
        .and_then(Value::as_object)
        .expect("descriptor must carry capabilities");
    let catalog = caps
        .get("capabilities")
        .and_then(Value::as_array)
        .expect("capabilities must carry catalog");
    catalog
        .iter()
        .find(|entry| {
            entry
                .get("capability_id")
                .and_then(Value::as_str)
                == Some(capability_id)
        })
        .unwrap_or_else(|| panic!("catalog must contain {capability_id}"))
        .get("availability")
        .and_then(Value::as_str)
        .expect("capability must carry availability")
        .to_string()
}

fn limitations_of(descriptor: &CheckedRecord, capability_id: &str) -> Vec<String> {
    let caps = record_value(descriptor)
        .get("capabilities")
        .and_then(Value::as_object)
        .expect("descriptor must carry capabilities");
    let catalog = caps
        .get("capabilities")
        .and_then(Value::as_array)
        .expect("capabilities must carry catalog");
    let entry = catalog
        .iter()
        .find(|entry| {
            entry
                .get("capability_id")
                .and_then(Value::as_str)
                == Some(capability_id)
        })
        .expect("catalog must contain capability");
    entry
        .get("limitations")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|item| item.as_str().map(str::to_string))
        .collect()
}

fn scope_for(version: &str) -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "subject_id": "il-crawler",
            "subject_version": version,
            "configured_mode": "service",
            "interface_surface": "ordinary_browser",
        }),
    )
}

#[test]
fn c46_evidence_honesty_unverified_remains_unverified() {
    let manifest = manifest_fixture();
    let grant = grant_for(&manifest);
    let store = StubStore;

    // Baseline: no claims at all leaves every honesty ID unknown with an
    // explicit limitation, and the catalog still enumerates all fifteen IDs.
    let configuration = check("audit_log", base_configuration());
    let descriptor =
        describe_configuration(&store, &grant, &configuration).expect("baseline describe must succeed");
    for id in [
        "crawler_solver_availability",
        "crawler_independent_counts",
        "crawler_certified_cursor",
        "crawler_session_lifetime",
        "crawler_measured_performance",
    ] {
        assert_eq!(
            availability_of(&descriptor, id),
            "unknown",
            "{id} with no evidence must stay unknown"
        );
        assert!(
            !limitations_of(&descriptor, id).is_empty(),
            "{id} unknown must carry an explicit limitation"
        );
    }
    for id in [
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
    ] {
        assert_eq!(
            availability_of(&descriptor, id),
            "unknown",
            "minimum {id} with no evidence must start unknown"
        );
    }
    // Nine operations, each exactly once.
    let operations = record_value(&descriptor)
        .get("operations")
        .and_then(Value::as_array)
        .expect("descriptor must carry operations");
    assert_eq!(operations.len(), 9, "descriptor must carry nine operations");
    let mut verbs: Vec<&str> = operations
        .iter()
        .filter_map(|op| op.get("operation").and_then(Value::as_str))
        .collect();
    verbs.sort_unstable();
    let mut expected = [
        "Describe",
        "Prepare",
        "Start",
        "Observe",
        "RequestNativeCancel",
        "CloseObservationConnection",
        "CollectArtifacts",
        "ReleaseNativeContext",
        "Contain",
    ];
    expected.sort_unstable();
    assert_eq!(verbs, expected.to_vec());

    // Unsupported mapping is not native absence: the default cancel mapping is
    // unmapped while the cancel capability stays unknown (not absent).
    let cancel_op = operations
        .iter()
        .find(|op| op.get("operation").and_then(Value::as_str) == Some("RequestNativeCancel"))
        .expect("cancel operation must exist");
    assert_eq!(
        cancel_op.get("implementation").and_then(Value::as_str),
        Some("unmapped")
    );
    assert_eq!(availability_of(&descriptor, "native_cancel"), "unknown");
    let scope = scope_for("v1");
    let checked = check_capability(&descriptor, "native_cancel", &scope)
        .expect("check of unknown cancel must succeed");
    assert_eq!(
        record_value(&checked).get("availability").and_then(Value::as_str),
        Some("unknown"),
        "unmapped operation must not surface as native absence"
    );

    // Solver: OR placeholder with documentation-only evidence stays unknown.
    let mut solver_cfg = base_configuration();
    solver_cfg["target"] = json!("OR");
    solver_cfg["solver_names"] = json!(["placeholder_solver"]);
    solver_cfg["claimed_capabilities"] = json!([
        {
            "capability_id": "crawler_solver_availability",
            "availability": "present",
            "claim_origin": "native",
            "requirement_refs": [],
            "evidence": [doc_evidence()],
            "limitations": [],
        },
    ]);
    let solver_cfg = check("audit_log", solver_cfg);
    let solver_desc =
        describe_configuration(&store, &grant, &solver_cfg).expect("solver describe must succeed");
    assert_eq!(
        availability_of(&solver_desc, "crawler_solver_availability"),
        "unknown",
        "placeholder solver with documentation only must stay unknown"
    );
    // Even executed observation cannot certify a named placeholder solver.
    let mut solver_exec_cfg = base_configuration();
    solver_exec_cfg["target"] = json!("OR");
    solver_exec_cfg["solver_names"] = json!(["placeholder_solver"]);
    solver_exec_cfg["claimed_capabilities"] = json!([
        {
            "capability_id": "crawler_solver_availability",
            "availability": "present",
            "evidence": [exec_evidence()],
            "limitations": [],
        },
    ]);
    let solver_exec_cfg = check("audit_log", solver_exec_cfg);
    let solver_exec_desc = describe_configuration(&store, &grant, &solver_exec_cfg)
        .expect("placeholder solver describe must succeed");
    assert_eq!(
        availability_of(&solver_exec_desc, "crawler_solver_availability"),
        "unknown",
        "named placeholder solver must stay unknown even with executed observation"
    );
    // A real solver name with executed observation in scope may be present.
    let mut real_solver_cfg = base_configuration();
    real_solver_cfg["target"] = json!("OR");
    real_solver_cfg["solver_names"] = json!(["volt_solver_v2"]);
    real_solver_cfg["claimed_capabilities"] = json!([
        {
            "capability_id": "crawler_solver_availability",
            "availability": "present",
            "evidence": [exec_evidence()],
            "limitations": ["solver implemented and tested on OR fixtures"],
        },
    ]);
    let real_solver_cfg = check("audit_log", real_solver_cfg);
    let real_solver_desc = describe_configuration(&store, &grant, &real_solver_cfg)
        .expect("real solver describe must succeed");
    assert_eq!(
        availability_of(&real_solver_desc, "crawler_solver_availability"),
        "present",
        "implemented solver with executed observation may be present"
    );

    // Counts: MI documentation-only claim stays unknown; executed observation
    // in scope may establish it.
    let mut counts_cfg = base_configuration();
    counts_cfg["target"] = json!("MI");
    counts_cfg["claimed_capabilities"] = json!([
        {
            "capability_id": "crawler_independent_counts",
            "availability": "present",
            "evidence": [doc_evidence()],
            "limitations": [],
        },
    ]);
    let counts_cfg = check("audit_log", counts_cfg);
    let counts_desc =
        describe_configuration(&store, &grant, &counts_cfg).expect("counts describe must succeed");
    assert_eq!(
        availability_of(&counts_desc, "crawler_independent_counts"),
        "unknown",
        "counts with documentation only must stay unknown"
    );
    let mut counts_exec_cfg = base_configuration();
    counts_exec_cfg["target"] = json!("MI");
    counts_exec_cfg["claimed_capabilities"] = json!([
        {
            "capability_id": "crawler_independent_counts",
            "availability": "present",
            "evidence": [exec_evidence()],
            "limitations": ["independent total verified against second source"],
        },
    ]);
    let counts_exec_cfg = check("audit_log", counts_exec_cfg);
    let counts_exec_desc = describe_configuration(&store, &grant, &counts_exec_cfg)
        .expect("counts executed describe must succeed");
    assert_eq!(
        availability_of(&counts_exec_desc, "crawler_independent_counts"),
        "present"
    );

    // Cursor: MN positional Page$N claim outside deterministic per-run scope is
    // uncertified even with executed observation; the certified scope allows it.
    let mut cursor_cfg = base_configuration();
    cursor_cfg["target"] = json!("MN");
    cursor_cfg["ordering_model"] = json!("ChurnShifted");
    cursor_cfg["coverage_scope"] = json!("per_run");
    cursor_cfg["cursor_kind"] = json!("positional_Page$N");
    cursor_cfg["claimed_capabilities"] = json!([
        {
            "capability_id": "crawler_certified_cursor",
            "availability": "present",
            "evidence": [exec_evidence()],
            "limitations": [],
        },
    ]);
    let cursor_cfg = check("audit_log", cursor_cfg);
    let cursor_desc =
        describe_configuration(&store, &grant, &cursor_cfg).expect("cursor describe must succeed");
    assert_eq!(
        availability_of(&cursor_desc, "crawler_certified_cursor"),
        "unknown",
        "positional cursor outside deterministic per-run scope must stay unknown"
    );
    let mut cursor_ok_cfg = base_configuration();
    cursor_ok_cfg["target"] = json!("IL");
    cursor_ok_cfg["ordering_model"] = json!("Deterministic");
    cursor_ok_cfg["coverage_scope"] = json!("per_run");
    cursor_ok_cfg["cursor_kind"] = json!("offset");
    cursor_ok_cfg["claimed_capabilities"] = json!([
        {
            "capability_id": "crawler_certified_cursor",
            "availability": "present",
            "evidence": [exec_evidence()],
            "limitations": ["deterministic per-run offsets evidenced"],
        },
    ]);
    let cursor_ok_cfg = check("audit_log", cursor_ok_cfg);
    let cursor_ok_desc = describe_configuration(&store, &grant, &cursor_ok_cfg)
        .expect("certified cursor describe must succeed");
    assert_eq!(
        availability_of(&cursor_ok_desc, "crawler_certified_cursor"),
        "present"
    );
    // Documentation alone never certifies a cursor.
    let mut cursor_doc_cfg = base_configuration();
    cursor_doc_cfg["target"] = json!("WI");
    cursor_doc_cfg["claimed_capabilities"] = json!([
        {
            "capability_id": "crawler_certified_cursor",
            "availability": "present",
            "evidence": [doc_evidence()],
            "limitations": [],
        },
    ]);
    let cursor_doc_cfg = check("audit_log", cursor_doc_cfg);
    let cursor_doc_desc = describe_configuration(&store, &grant, &cursor_doc_cfg)
        .expect("cursor doc describe must succeed");
    assert_eq!(
        availability_of(&cursor_doc_desc, "crawler_certified_cursor"),
        "unknown"
    );

    // Lifetime: unknown lifetime with documentation only stays unknown; an
    // invented keepalive request does not establish it.
    let mut lifetime_cfg = base_configuration();
    lifetime_cfg["claimed_capabilities"] = json!([
        {
            "capability_id": "crawler_session_lifetime",
            "availability": "present",
            "evidence": [doc_evidence()],
            "limitations": [],
        },
    ]);
    lifetime_cfg["keepalive_request"] = json!({"interval_ms": 1000});
    let lifetime_cfg = check("audit_log", lifetime_cfg);
    let lifetime_desc = describe_configuration(&store, &grant, &lifetime_cfg)
        .expect("lifetime describe must succeed");
    assert_eq!(
        availability_of(&lifetime_desc, "crawler_session_lifetime"),
        "unknown",
        "lifetime with documentation only must stay unknown"
    );

    // Performance: deployment declarations are not benchmarks.
    let mut perf_cfg = base_configuration();
    perf_cfg["claimed_capabilities"] = json!([
        {
            "capability_id": "crawler_measured_performance",
            "availability": "present",
            "evidence": [doc_evidence()],
            "limitations": [],
        },
    ]);
    let perf_cfg = check("audit_log", perf_cfg);
    let perf_desc =
        describe_configuration(&store, &grant, &perf_cfg).expect("perf describe must succeed");
    assert_eq!(
        availability_of(&perf_desc, "crawler_measured_performance"),
        "unknown",
        "performance with documentation only must stay unknown"
    );
    let mut perf_exec_cfg = base_configuration();
    perf_exec_cfg["claimed_capabilities"] = json!([
        {
            "capability_id": "crawler_measured_performance",
            "availability": "present",
            "evidence": [exec_evidence()],
            "limitations": ["orchestration median measured at 6% of network median"],
        },
    ]);
    let perf_exec_cfg = check("audit_log", perf_exec_cfg);
    let perf_exec_desc = describe_configuration(&store, &grant, &perf_exec_cfg)
        .expect("measured perf describe must succeed");
    assert_eq!(
        availability_of(&perf_exec_desc, "crawler_measured_performance"),
        "present"
    );

    // No inheritance: v2 citing only v1 evidence stays unknown, and a v2 scope
    // never reads a v1 descriptor.
    let mut v2_cfg = base_configuration();
    v2_cfg["subject"] = json!({
        "subject_id": "il-crawler",
        "subject_version": "v2",
        "configured_mode": "service",
        "interface_surface": "ordinary_browser",
    });
    v2_cfg["claimed_capabilities"] = json!([
        {
            "capability_id": "crawler_independent_counts",
            "availability": "present",
            "evidence": [exec_evidence_for("v1")],
            "limitations": [],
        },
    ]);
    let v2_cfg = check("audit_log", v2_cfg);
    let v2_desc =
        describe_configuration(&store, &grant, &v2_cfg).expect("v2 describe must succeed");
    assert_eq!(
        availability_of(&v2_desc, "crawler_independent_counts"),
        "unknown",
        "predecessor evidence must not establish v2 presence"
    );
    let v1_scope = scope_for("v1");
    let v2_scope = scope_for("v2");
    let mismatch = check_capability(&counts_exec_desc, "crawler_independent_counts", &v2_scope);
    assert!(
        mismatch.is_err() && mismatch.unwrap_err().code == "scope_mismatch",
        "v2 scope must not inherit a v1 descriptor finding"
    );
    let matched = check_capability(&counts_exec_desc, "crawler_independent_counts", &v1_scope)
        .expect("matching scope must read its own descriptor");
    assert_eq!(
        record_value(&matched).get("availability").and_then(Value::as_str),
        Some("present")
    );

    // Omission is neither presence nor absence.
    let omitted = check_capability(&descriptor, "no_such_capability", &scope_for("v1"));
    assert!(
        omitted.is_err() && omitted.unwrap_err().code == "unknown_capability",
        "absent catalog entry must be unknown_capability, not an inherited verdict"
    );

    // Descriptor digest binding: the exact digest verifies, a wrong one fails.
    let digest = binding_of(&counts_exec_desc);
    let bound_scope = check(
        "audit_log",
        json!({
            "subject_id": "il-crawler",
            "subject_version": "v1",
            "configured_mode": "service",
            "interface_surface": "ordinary_browser",
            "descriptor_digest": digest,
        }),
    );
    check_capability(&counts_exec_desc, "crawler_independent_counts", &bound_scope)
        .expect("exact descriptor digest must verify");
    let wrong_scope = check(
        "audit_log",
        json!({
            "subject_id": "il-crawler",
            "subject_version": "v1",
            "configured_mode": "service",
            "interface_surface": "ordinary_browser",
            "descriptor_digest": "c".repeat(64),
        }),
    );
    let wrong = check_capability(&counts_exec_desc, "crawler_independent_counts", &wrong_scope);
    assert!(
        wrong.is_err() && wrong.unwrap_err().code == "digest_mismatch",
        "wrong descriptor digest must fail closed"
    );

    // Declare, never assess: qualification smuggling is rejected and never emitted.
    let mut qual_cfg = base_configuration();
    qual_cfg["qualification"] = json!("satisfied");
    let qual_cfg = check("audit_log", qual_cfg);
    let qual = describe_configuration(&store, &grant, &qual_cfg);
    assert!(
        qual.is_err() && qual.unwrap_err().code == "qualification_forbidden",
        "configuration carrying qualification must be rejected"
    );
    let descriptor_text = serde_json::to_string(record_value(&descriptor)).unwrap();
    for forbidden in [
        "qualification",
        "requirement_satisfaction",
        "application_success",
    ] {
        assert!(
            !descriptor_text.contains(forbidden),
            "descriptor must never carry {forbidden}"
        );
    }

    // Evidence grounding: a known journal prefixes the descriptor; an unknown
    // journal fails closed; no journal leaves an explicit Missing prefix.
    let mut grounded_cfg = base_configuration();
    grounded_cfg["journal_id"] = json!("journal-1");
    let grounded_cfg = check("audit_log", grounded_cfg);
    let grounded = describe_configuration(&store, &grant, &grounded_cfg)
        .expect("grounded describe must succeed");
    let prefix = record_value(&grounded)
        .get("evidence_prefix")
        .expect("grounded descriptor must carry evidence_prefix");
    assert_eq!(
        prefix.get("journal_id").and_then(Value::as_str),
        Some("journal-1")
    );
    let mut unknown_journal_cfg = base_configuration();
    unknown_journal_cfg["journal_id"] = json!("no-such-journal");
    let unknown_journal_cfg = check("audit_log", unknown_journal_cfg);
    let unknown_journal = describe_configuration(&store, &grant, &unknown_journal_cfg);
    assert!(
        unknown_journal.is_err() && unknown_journal.unwrap_err().code == "unknown_journal",
        "unknown journal grounding must fail closed"
    );
    let ungrounded_prefix = record_value(&descriptor)
        .get("evidence_prefix")
        .expect("baseline descriptor must carry evidence_prefix");
    assert!(
        ungrounded_prefix.get("value").is_some_and(Value::is_null),
        "ungrounded evidence prefix must be an explicit Missing envelope"
    );

    // Forged descriptors cannot launder unverified claims through check: a
    // present-without-evidence entry fails, as does a present honesty ID with
    // documentation only.
    let mut forged_value = record_value(&counts_exec_desc).clone();
    if let Some(entry) = forged_value
        .get_mut("capabilities")
        .and_then(|caps| caps.get_mut("capabilities"))
        .and_then(Value::as_array_mut)
        .and_then(|catalog| {
            catalog.iter_mut().find(|entry| {
                entry.get("capability_id").and_then(Value::as_str)
                    == Some("crawler_independent_counts")
            })
        })
    {
        entry["availability"] = json!("present");
        entry["evidence"] = json!([]);
    }
    let forged = check("audit_log", forged_value);
    let forged_check = check_capability(&forged, "crawler_independent_counts", &scope_for("v1"));
    assert!(
        forged_check.is_err() && forged_check.unwrap_err().code == "unverified_claim",
        "present without evidence must fail at check time"
    );
}

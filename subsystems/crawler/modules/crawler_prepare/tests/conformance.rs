//! [C36] Prepare is non-executing: no target network, auth probe, hidden
//! planner, reset, or recovery. Validation only, with independent native and
//! delivered-task serializations and an owner-local evidence prefix.

use crawler_authority::{authorize, Grant};
use crawler_hashing::{canonical_bytes, digest_bytes};
use crawler_prepare::{prepare, verify_preparation};
use crawler_schema::{record_value, validate, CheckedRecord, Fault};
use crawler_store::OwnerStore;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering};

fn check(schema: &str, value: Value) -> CheckedRecord {
    validate(schema, value).expect("fixture must validate")
}

fn missing_not_applicable() -> Value {
    json!({"value": Value::Null, "reason": "not_applicable"})
}

fn missing_not_observed() -> Value {
    json!({"value": Value::Null, "reason": "not_observed"})
}

fn binding_of(record: &CheckedRecord) -> String {
    digest_bytes(&canonical_bytes(record).expect("canonical bytes must exist"))
}

fn sha256_of(text: &str) -> String {
    format!("sha256:{}", "a".repeat(0) + &digest_bytes(text.as_bytes()))
}

fn dummy_digest_hex(ch: char) -> String {
    std::iter::repeat(ch).take(64).collect()
}

fn dummy_digest(ch: char) -> String {
    format!("sha256:{}", dummy_digest_hex(ch))
}

fn evidence_ref(journal_id: &str, sequence: u64, event_id: &str, ch: char) -> Value {
    json!({
        "journal_id": journal_id,
        "sequence": sequence,
        "event_id": event_id,
        "event_hash": dummy_digest(ch),
        "pointer": "",
    })
}

fn registration_fixture() -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "registration_id": "channel-1",
            "principals": [{
                "principal_id": "reader",
                "verbs": ["Describe", "Prepare", "Observe", "CollectArtifacts"],
                "connectors": ["jobs-connector"],
                "control": false,
                "owner_domain": "crawler",
                "restricted_access": false,
            }],
        }),
    )
}

fn test_grant() -> Grant {
    let registration = registration_fixture();
    let principal = check(
        "audit_log",
        json!({
            "principal_id": "reader",
            "registration_digest": binding_of(&registration),
        }),
    );
    let request = check(
        "audit_log",
        json!({
            "verb": "Prepare",
            "connector": "jobs-connector",
            "subject": "jobs",
        }),
    );
    authorize(&principal, &request, &registration).expect("grant must issue")
}

/// Owner store stub: `transact` is forbidden (Prepare performs no writes);
/// `read` grounds one canned journal prefix and rejects anything else.
struct StubStore {
    reads: AtomicUsize,
    writes: AtomicUsize,
}

impl StubStore {
    fn new() -> Self {
        Self {
            reads: AtomicUsize::new(0),
            writes: AtomicUsize::new(0),
        }
    }
}

impl OwnerStore for StubStore {
    fn transact(&self, _grant: &Grant, _transaction: &CheckedRecord) -> Result<CheckedRecord, Fault> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        Err(Fault {
            code: "write_forbidden".to_string(),
            detail: "prepare performs no writes".to_string(),
        })
    }

    fn read(&self, _grant: &Grant, query: &CheckedRecord) -> Result<CheckedRecord, Fault> {
        self.reads.fetch_add(1, Ordering::SeqCst);
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
                "head_hash": dummy_digest('a'),
            }),
        )
    }
}

fn subject_pin() -> Value {
    json!({
        "subject_id": "il-crawler",
        "subject_version": "v1",
        "configured_mode": "service",
        "interface_surface": "ordinary_browser",
    })
}

fn minimum_capabilities() -> Vec<Value> {
    [
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
    ]
    .into_iter()
    .map(|id| {
        json!({
            "capability_id": id,
            "availability": "unknown",
            "claim_origin": "native",
        })
    })
    .collect()
}

fn descriptor_fixture() -> CheckedRecord {
    let subject = subject_pin();
    check(
        "audit_log",
        json!({
            "record_type": "connector_descriptor",
            "schema_version": "external-connector/0.1.0",
            "connector_id": "jobs-connector",
            "connector_version": "0.1.0",
            "subject": subject,
            "capabilities": {
                "capabilities": minimum_capabilities(),
                "subject": subject_pin(),
            },
            "task_mappings": [
                {
                    "task_type": "discover_jobs",
                    "input_form": "goal",
                    "mapping": {
                        "id": "il-mapping",
                        "version": "1",
                        "artifact_digest": dummy_digest('b'),
                    },
                    "planning_owner": "external_planner",
                    "recovery_owner": "none",
                    "limitations": [],
                },
                {
                    "task_type": "extract",
                    "input_form": "extraction_request",
                    "mapping": {
                        "id": "il-extract-mapping",
                        "version": "1",
                        "artifact_digest": dummy_digest('c'),
                    },
                    "planning_owner": "external_planner",
                    "recovery_owner": "none",
                    "limitations": [],
                },
            ],
        }),
    )
}

fn duration_ms(value: u64) -> Value {
    json!({"kind": "exact", "unit": "ms", "value": value})
}

fn scope_fixture() -> Value {
    json!({
        "activity": "discovery",
        "run_id": "run-1",
        "journal_id": "journal-1",
        "manifest_hash": dummy_digest('d'),
        "admission_ref": evidence_ref("journal-1", 1, "evt-admit", 'e'),
        "attempt": missing_not_applicable(),
        "commission": missing_not_applicable(),
        "commission_ref": missing_not_applicable(),
        "authorization_refs": [evidence_ref("journal-1", 1, "evt-auth", 'f')],
        "observation_policy": {
            "active_limit": duration_ms(30000),
            "drain_limit": duration_ms(5000),
            "native_cancel_wait_limit": duration_ms(2000),
            "cleanup_wait_limit": duration_ms(2000),
            "fixture_close_action": "not_applicable",
        },
    })
}

fn task_fixture() -> Value {
    json!({
        "record_type": "connector_task",
        "schema_version": "external-connector/0.1.0",
        "task_id": "task-1",
        "task_type": "discover_jobs",
        "entry": {
            "logical_id": "entry-1",
            "url": "https://jobs.illinois.gov/search",
        },
        "goal": "discover listings",
        "success_criteria": [
            {"criterion_id": "crit-1", "description": "identify current listings"},
        ],
        "inputs": [],
        "permitted_origins": [
            {"logical_id": "origin-1", "origin": "https://jobs.illinois.gov"},
        ],
        "permitted_interfaces": ["read_only_acquisition"],
        "effect_policy": "read_only",
        "budgets": {
            "active_limit": duration_ms(30000),
            "action_limit": 100,
            "observation_byte_limit": 1000000,
            "recovery_limit": 0,
            "model_token_limit": 0,
        },
        "context_policy": {
            "browser_state": {
                "mode": "fresh",
                "requirement": "required",
                "resource_ref": missing_not_applicable(),
                "baseline": missing_not_applicable(),
            },
            "learning_state": {
                "mode": "not_applicable",
                "requirement": "best_effort",
                "resource_ref": missing_not_applicable(),
                "baseline": missing_not_applicable(),
            },
        },
        "output_schema": {
            "id": "job-feed",
            "version": "1",
            "artifact_digest": dummy_digest('b'),
        },
    })
}

fn configuration_fixture(descriptor: &CheckedRecord) -> Value {
    let descriptor_hex = binding_of(descriptor);
    let descriptor_bytes = canonical_bytes(descriptor).expect("descriptor bytes");
    json!({
        "connector_id": "jobs-connector",
        "connector_version": "0.1.0",
        "binding": {
            "id": "crawler-binding",
            "version": "1",
            "artifact_digest": dummy_digest('b'),
        },
        "subject": subject_pin(),
        "descriptor": {
            "digest": format!("sha256:{descriptor_hex}"),
            "size_bytes": descriptor_bytes.len() as u64,
            "media_type": "connector-descriptor/1",
            "owner_domain": "crawler",
            "access": "public",
        },
        "descriptor_ref": evidence_ref("journal-1", 1, "evt-desc", 'e'),
    })
}

fn assistance_fixture() -> Value {
    json!({
        "planning_owner": "external_planner",
        "assistance_track": "track-1",
        "planner_identity": "planner-1",
        "plan": missing_not_applicable(),
        "online_replanning": false,
        "description": "external plan with public observation",
    })
}

fn request_fixture(descriptor: &CheckedRecord) -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "scope": scope_fixture(),
            "configuration": configuration_fixture(descriptor),
            "task": task_fixture(),
            "assistance": assistance_fixture(),
            "planning_evidence_refs": [],
            "preparation_measurements": [],
            "runtime_access": [],
        }),
    )
}

fn authorization_for(preparation: &CheckedRecord) -> CheckedRecord {
    let concerns = record_value(preparation)
        .get("concerns")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut accepted = Vec::new();
    for concern in &concerns {
        if concern.get("disposition").and_then(Value::as_str) == Some("requires_acceptance") {
            if let Some(id) = concern.get("concern_id").and_then(Value::as_str) {
                accepted.push(Value::String(id.to_string()));
            }
        }
    }
    // Authorization refs must be nonempty; reuse the preparation's scope refs.
    let scope_refs = record_value(preparation)
        .get("scope")
        .and_then(|scope| scope.get("authorization_refs"))
        .cloned()
        .unwrap_or_else(|| Value::Array(vec![evidence_ref("journal-1", 1, "evt-auth", 'f')]));
    check(
        "audit_log",
        json!({
            "accepted_concerns": accepted,
            "authorization_refs": scope_refs,
        }),
    )
}

fn configuration_record_from(preparation: &CheckedRecord) -> CheckedRecord {
    let configuration = record_value(preparation)
        .get("configuration")
        .cloned()
        .expect("preparation must carry configuration");
    check("audit_log", configuration)
}

// ---------------------------------------------------------------------------
// C36: Prepare performs no target network, auth probe, hidden planner,
// reset, or recovery: deterministic, write-free, and read-scoped.
// ---------------------------------------------------------------------------

#[test]
fn c36_prepare_is_non_executing_and_deterministic() {
    let grant = test_grant();
    let store = StubStore::new();
    let descriptor = descriptor_fixture();
    let request = request_fixture(&descriptor);

    let first = prepare(&store, &grant, &request, &descriptor).expect("valid prepare must succeed");
    let second =
        prepare(&store, &grant, &request, &descriptor).expect("repeat prepare must succeed");

    // Deterministic: identical inputs pin the identical immutable preparation.
    let first_value = record_value(&first);
    let second_value = record_value(&second);
    assert_eq!(
        first_value.get("preparation_id"),
        second_value.get("preparation_id"),
        "preparation_id must be deterministic over the same inputs"
    );
    assert_eq!(
        first_value.get("task_semantic_hash"),
        second_value.get("task_semantic_hash"),
        "task hash must be deterministic"
    );
    assert_eq!(
        first_value.get("delivered_task_hash"),
        second_value.get("delivered_task_hash"),
        "delivered hash must be deterministic"
    );
    assert_eq!(
        first_value.get("native_request_hash"),
        second_value.get("native_request_hash"),
        "native hash must be deterministic"
    );

    // Only owner-local prefix reads occurred; transact was never invoked.
    // (StubStore::transact fails the call, so success already proves zero
    // writes; the counters make the read scope explicit.)
    assert_eq!(store.writes.load(Ordering::SeqCst), 0, "prepare must never write");
    assert_eq!(
        store.reads.load(Ordering::SeqCst),
        2,
        "prepare grounds exactly one evidence prefix per call"
    );

    assert_eq!(
        first_value.get("record_type").and_then(Value::as_str),
        Some("connector_preparation")
    );
    // No secret bytes or control credentials are materialized.
    let rendered = serde_json::to_string(first_value).expect("preparation must render");
    for secret in ["secret_bytes", "password", "control_credentials", "api_key"] {
        assert!(
            !rendered.contains(secret),
            "preparation must not materialize {secret}"
        );
    }
}

#[test]
fn c36_prepare_records_serializations_without_improvement() {
    let grant = test_grant();
    let store = StubStore::new();
    let descriptor = descriptor_fixture();
    let request = request_fixture(&descriptor);
    let request_value = record_value(&request).clone();

    let preparation =
        prepare(&store, &grant, &request, &descriptor).expect("valid prepare must succeed");
    let prep = record_value(&preparation);

    // Full task, scope, configuration, assistance, and runtime access are
    // preserved verbatim: Prepare secretly improves nothing.
    assert_eq!(
        prep.get("task"),
        request_value.get("task"),
        "preparation must preserve the full task byte-for-byte"
    );
    assert_eq!(
        prep.get("scope"),
        request_value.get("scope"),
        "preparation must preserve the scope"
    );
    assert_eq!(
        prep.get("configuration"),
        request_value.get("configuration"),
        "preparation must preserve the configuration pin"
    );
    assert_eq!(
        prep.get("assistance"),
        request_value.get("assistance"),
        "preparation must preserve assistance without invoking a planner"
    );
    assert_eq!(
        prep.get("runtime_access"),
        request_value.get("runtime_access"),
        "preparation must preserve opaque runtime refs without resolving them"
    );

    // Native serialization and delivered task are recorded independently.
    let delivered_hash = prep
        .get("delivered_task_hash")
        .and_then(Value::as_str)
        .expect("delivered hash must exist");
    let native_hash = prep
        .get("native_request_hash")
        .and_then(Value::as_str)
        .expect("native hash must exist");
    assert_ne!(
        delivered_hash, native_hash,
        "native request and delivered task are independent serializations"
    );
    assert_eq!(
        prep
            .get("delivered_task")
            .and_then(|artifact| artifact.get("digest"))
            .and_then(Value::as_str),
        Some(delivered_hash),
        "delivered artifact digest must match its hash"
    );
    assert_eq!(
        prep
            .get("native_request")
            .and_then(|artifact| artifact.get("digest"))
            .and_then(Value::as_str),
        Some(native_hash),
        "native artifact digest must match its hash"
    );
    // Delivered task pins the full task bytes.
    assert_eq!(
        Some(delivered_hash),
        prep.get("task_semantic_hash").and_then(Value::as_str),
        "delivered hash must equal the task semantic hash"
    );

    // Translation is the descriptor's declared mapping for this task type,
    // not an invented improvement.
    let translation = prep.get("translation").expect("translation must exist");
    assert_eq!(
        translation.get("id").and_then(Value::as_str),
        Some("il-mapping")
    );

    // All five budget dimensions appear exactly once; active observation is
    // connector-enforced.
    let budgets = prep
        .get("budget_mapping")
        .and_then(Value::as_array)
        .expect("budget mapping must exist");
    assert_eq!(budgets.len(), 5, "exactly five budget dimensions");
    let mut dimensions: Vec<&str> = budgets
        .iter()
        .filter_map(|entry| entry.get("dimension").and_then(Value::as_str))
        .collect();
    dimensions.sort();
    assert_eq!(
        dimensions,
        [
            "action_count",
            "active_observation",
            "model_tokens",
            "observation_bytes",
            "recovery_count"
        ]
    );
    let active = budgets
        .iter()
        .find(|entry| entry.get("dimension").and_then(Value::as_str) == Some("active_observation"))
        .expect("active dimension must exist");
    assert_eq!(
        active.get("enforcer").and_then(Value::as_str),
        Some("connector")
    );

    // Evidence prefix is the owner-local prefix, not target data.
    let prefix = prep.get("evidence_prefix").expect("prefix must exist");
    assert_eq!(
        prefix.get("journal_id").and_then(Value::as_str),
        Some("journal-1")
    );

    // Best-effort learning state is disclosed as a requires_acceptance
    // concern rather than silently upgraded.
    let concerns = prep
        .get("concerns")
        .and_then(Value::as_array)
        .expect("concerns must exist");
    assert!(
        concerns.iter().any(|concern| {
            concern.get("concern_id").and_then(Value::as_str)
                == Some("state-learning-best-effort")
                && concern.get("disposition").and_then(Value::as_str)
                    == Some("requires_acceptance")
        }),
        "best-effort learning state must be a requires_acceptance concern, got {concerns:?}"
    );
}

#[test]
fn c36_prepare_rejects_mutation_and_scope_violation_before_wire() {
    let grant = test_grant();
    let store = StubStore::new();
    let descriptor = descriptor_fixture();

    // apply is never a crawler task.
    let mut task = task_fixture();
    task["task_type"] = json!("apply");
    task["effect_policy"] = json!("commissioned_application");
    let request = check(
        "audit_log",
        json!({
            "scope": scope_fixture(),
            "configuration": configuration_fixture(&descriptor),
            "task": task,
            "assistance": assistance_fixture(),
            "planning_evidence_refs": [],
            "preparation_measurements": [],
            "runtime_access": [],
        }),
    );
    let fault = prepare(&store, &grant, &request, &descriptor).expect_err("apply must be rejected");
    assert_eq!(fault.code, "mutation_rejected", "apply detail: {}", fault.detail);

    // Entry origin outside the admitted permitted_origins is a scope
    // violation, caught before any wire delivery.
    let mut task = task_fixture();
    task["entry"] = json!({"logical_id": "entry-1", "url": "https://evil.example.com/search"});
    let request = check(
        "audit_log",
        json!({
            "scope": scope_fixture(),
            "configuration": configuration_fixture(&descriptor),
            "task": task,
            "assistance": assistance_fixture(),
            "planning_evidence_refs": [],
            "preparation_measurements": [],
            "runtime_access": [],
        }),
    );
    let fault = prepare(&store, &grant, &request, &descriptor)
        .expect_err("out-of-scope entry must be rejected");
    assert_eq!(fault.code, "scope_violation", "scope detail: {}", fault.detail);

    // No Phase 1 crawl_allotment slot is introduced.
    let mut task = task_fixture();
    task["crawl_allotment"] = json!({"slots": 1});
    let request = check(
        "audit_log",
        json!({
            "scope": scope_fixture(),
            "configuration": configuration_fixture(&descriptor),
            "task": task,
            "assistance": assistance_fixture(),
            "planning_evidence_refs": [],
            "preparation_measurements": [],
            "runtime_access": [],
        }),
    );
    let fault =
        prepare(&store, &grant, &request, &descriptor).expect_err("crawl_allotment must be rejected");
    assert_eq!(fault.code, "invalid_task");

    // Mutation smuggled through task text fails before wire.
    let mut task = task_fixture();
    task["goal"] = json!("apply to listings");
    let request = check(
        "audit_log",
        json!({
            "scope": scope_fixture(),
            "configuration": configuration_fixture(&descriptor),
            "task": task,
            "assistance": assistance_fixture(),
            "planning_evidence_refs": [],
            "preparation_measurements": [],
            "runtime_access": [],
        }),
    );
    let fault = prepare(&store, &grant, &request, &descriptor)
        .expect_err("mutation text must be rejected");
    assert_eq!(fault.code, "mutation_rejected");
}

#[test]
fn c36_prepare_rejects_hidden_planner_reset_recovery_and_auth_probe() {
    let grant = test_grant();
    let store = StubStore::new();
    let descriptor = descriptor_fixture();

    // Hidden execution requests are rejected, never acted on.
    for field in [
        "invoke_planner",
        "reset_context",
        "recovery_request",
        "auth_probe",
        "browse",
        "visit_target",
    ] {
        let mut scope = scope_fixture();
        scope[field] = json!(true);
        // task-level markers travel on the task object instead.
        let (scope_value, mut task_value) = (scope.clone(), task_fixture());
        let request = if field == "invoke_planner" || field == "browse" {
            task_value[field] = json!(true);
            check(
                "audit_log",
                json!({
                    "scope": scope_fixture(),
                    "configuration": configuration_fixture(&descriptor),
                    "task": task_value,
                    "assistance": assistance_fixture(),
                    "planning_evidence_refs": [],
                    "preparation_measurements": [],
                    "runtime_access": [],
                }),
            )
        } else {
            check(
                "audit_log",
                json!({
                    "scope": scope_value,
                    "configuration": configuration_fixture(&descriptor),
                    "task": task_fixture(),
                    "assistance": assistance_fixture(),
                    "planning_evidence_refs": [],
                    "preparation_measurements": [],
                    "runtime_access": [],
                }),
            )
        };
        let fault = prepare(&store, &grant, &request, &descriptor)
            .expect_err(&format!("{field} must be rejected, not executed"));
        assert_eq!(
            fault.code, "execution_forbidden",
            "field {field} detail: {}",
            fault.detail
        );
    }

    // Opaque runtime refs are recorded; secret bytes are refused.
    let request = check(
        "audit_log",
        json!({
            "scope": scope_fixture(),
            "configuration": configuration_fixture(&descriptor),
            "task": task_fixture(),
            "assistance": assistance_fixture(),
            "planning_evidence_refs": [],
            "preparation_measurements": [],
            "runtime_access": [{
                "purpose": "account_session",
                "access_ref": "session-opaque-1",
                "authorization_refs": [evidence_ref("journal-1", 1, "evt-auth", 'f')],
                "secret": "hunter2",
            }],
        }),
    );
    let fault = prepare(&store, &grant, &request, &descriptor)
        .expect_err("secret-bearing runtime access must be rejected");
    assert_eq!(fault.code, "secret_forbidden");

    // Recovery without a mapping owner is unsupported, never hidden.
    let mut task = task_fixture();
    task["budgets"]["recovery_limit"] = json!(3);
    let request = check(
        "audit_log",
        json!({
            "scope": scope_fixture(),
            "configuration": configuration_fixture(&descriptor),
            "task": task,
            "assistance": assistance_fixture(),
            "planning_evidence_refs": [],
            "preparation_measurements": [],
            "runtime_access": [],
        }),
    );
    let fault = prepare(&store, &grant, &request, &descriptor)
        .expect_err("ownerless recovery must be unsupported");
    assert_eq!(fault.code, "unsupported_mapping");

    // Required reuse without an authorized binding rejects preparation
    // rather than silently downgrading the state policy.
    let mut task = task_fixture();
    task["context_policy"]["browser_state"]["mode"] = json!("reuse");
    task["context_policy"]["browser_state"]["requirement"] = json!("required");
    task["context_policy"]["browser_state"]["resource_ref"] = missing_not_applicable();
    let request = check(
        "audit_log",
        json!({
            "scope": scope_fixture(),
            "configuration": configuration_fixture(&descriptor),
            "task": task,
            "assistance": assistance_fixture(),
            "planning_evidence_refs": [],
            "preparation_measurements": [],
            "runtime_access": [],
        }),
    );
    let fault = prepare(&store, &grant, &request, &descriptor)
        .expect_err("unsupported required state policy must be rejected");
    assert_eq!(fault.code, "unsupported_state_policy");

    // Previously journaled planning costs are inert evidence: Prepare treats
    // them as disclosed cost, not as a request to run a planner, and still
    // succeeds without invoking anything.
    let request = check(
        "audit_log",
        json!({
            "scope": scope_fixture(),
            "configuration": configuration_fixture(&descriptor),
            "task": task_fixture(),
            "assistance": assistance_fixture(),
            "planning_evidence_refs": [],
            "preparation_measurements": [{"kind": "planning_cost", "value_ms": 12}],
            "runtime_access": [],
        }),
    );
    prepare(&store, &grant, &request, &descriptor)
        .expect("measurements must be inert, not executed");
}

#[test]
fn c36_verify_preparation_enforces_pin_and_acceptance() {
    let grant = test_grant();
    let store = StubStore::new();
    let descriptor = descriptor_fixture();
    let request = request_fixture(&descriptor);
    let preparation =
        prepare(&store, &grant, &request, &descriptor).expect("valid prepare must succeed");

    // Happy path: exact configuration pin plus every requires_acceptance
    // concern accepted verifies.
    let configuration = configuration_record_from(&preparation);
    let authorization = authorization_for(&preparation);
    verify_preparation(&preparation, &configuration, &authorization)
        .expect("exact pin with full acceptance must verify");

    // A stale configuration (changed subject version) is rejected rather
    // than silently reprepared.
    let mut stale_value = record_value(&configuration).clone();
    stale_value["subject"]["subject_version"] = json!("v2");
    let stale = check("audit_log", stale_value);
    let fault = verify_preparation(&preparation, &stale, &authorization)
        .expect_err("stale configuration must be rejected");
    assert_eq!(fault.code, "stale_configuration");

    // Withholding a requires_acceptance concern blocks Start.
    let scope_refs = record_value(&preparation)
        .get("scope")
        .and_then(|scope| scope.get("authorization_refs"))
        .cloned()
        .unwrap();
    let missing_acceptance = check(
        "audit_log",
        json!({"accepted_concerns": [], "authorization_refs": scope_refs}),
    );
    let fault = verify_preparation(&preparation, &configuration, &missing_acceptance)
        .expect_err("missing acceptance must be rejected");
    assert_eq!(fault.code, "missing_acceptance");

    // A changed task no longer matches the pinned semantic hash.
    let mut tampered = record_value(&preparation).clone();
    tampered["task"]["goal"] = json!("discover other listings");
    let tampered_record = check("audit_log", tampered);
    let fault = verify_preparation(&tampered_record, &configuration, &authorization)
        .expect_err("tampered task must fail integrity");
    assert_eq!(fault.code, "integrity_conflict");

    // Hash fields that disagree with each other are an integrity conflict.
    let mut tampered = record_value(&preparation).clone();
    tampered["delivered_task"]["digest"] = json!(dummy_digest('e'));
    let tampered_record = check("audit_log", tampered);
    let fault = verify_preparation(&tampered_record, &configuration, &authorization)
        .expect_err("digest drift must fail integrity");
    assert_eq!(fault.code, "integrity_conflict");

    // Unused helper coverage: Missing(not_observed) is a valid envelope the
    // gate admits; it asserts nothing here.
    let _ = missing_not_observed();
    let _ = sha256_of("c36");
}

//! Conformance tests for `crawler_seen_ids`.
//!
//! * **[C18]** Seen IDs: exact eligible membership; no snippet-only veto
//!   membership; coverage unaffected by hits.
//!
//! The tests use the real `crawler_authority` grant seam and a fake owner
//! store that serves journal views (`query: "journal"`, the real store
//! vocabulary). The fake store faults on `transact`, proving `exact_success`
//! only reads and `plan_seen_transition` is pure.

use crawler_authority::{authorize_producer, Grant};
use crawler_hashing::{canonical_bytes, digest_bytes};
use crawler_schema::{record_value, validate, CheckedRecord, Fault};
use crawler_seen_ids::{exact_success, plan_seen_transition};
use crawler_store::OwnerStore;
use serde_json::{json, Value};
use std::sync::Mutex;

const JOURNAL: &str = "journal-seen-1";
const PRODUCER: &str = "seen_worker";
const OWNER_DOMAIN: &str = "crawler_ingest";

fn check(schema: &str, value: Value) -> CheckedRecord {
    validate(schema, value).expect("fixture must validate")
}

fn missing(reason: &str) -> Value {
    json!({"value": Value::Null, "reason": reason})
}

fn timepoint(offset_ms: f64) -> Value {
    json!({
        "clock_id": "clk-seen",
        "boot_id": "boot-seen",
        "origin": "engine_measured",
        "monotonic_offset_ms": offset_ms,
        "utc_annotation": missing("not_observed"),
    })
}

fn source_hash(text: &str) -> Value {
    json!({
        "value": text,
        "profile": missing("not_applicable"),
        "evidence_refs": [
            {
                "journal_id": JOURNAL,
                "sequence": 1,
                "event_id": "evt-1",
                "event_hash": "h",
                "pointer": "",
            }
        ],
    })
}

fn binding_of(record: &CheckedRecord) -> String {
    digest_bytes(&canonical_bytes(record).expect("canonical bytes"))
}

fn manifest() -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "manifest_id": "manifest-seen",
            "producer_registry": [
                {
                    "producer_id": PRODUCER,
                    "owner_domain": OWNER_DOMAIN,
                    "role": "external_input",
                    "provenance": "server",
                    "assertion_kind": "claim",
                },
            ],
            "event_registry": [
                {"event_kind": "seen_probe", "permitted_provenance": ["server"]},
                {"event_kind": "detail_committed", "permitted_provenance": ["server"]},
            ],
        }),
    )
}

fn grant() -> Grant {
    let manifest = manifest();
    let principal = check(
        "audit_log",
        json!({
            "producer_id": PRODUCER,
            "manifest_digest": binding_of(&manifest),
        }),
    );
    let submission = check("audit_log", json!({"event_kind": "seen_probe"}));
    authorize_producer(&principal, &submission, &manifest).expect("grant must issue")
}

#[allow(clippy::too_many_arguments)]
fn detail_row(
    target: &str,
    job_id: &str,
    fetch_key: &str,
    pipeline_state: &str,
    revision: u64,
    run_id: &str,
    render_verdict: Option<&str>,
    entity_type: Option<&str>,
    candidate_kind: Option<&str>,
    veto_scope: Option<&str>,
) -> Value {
    let mut row = json!({
        "target": target,
        "job_id": job_id,
        "active_run_id": run_id,
        "entity_revision": revision,
        "input_revision": 1,
        "fetch_key": source_hash(fetch_key),
        "pipeline_state": pipeline_state,
        "created_at": timepoint(100.0),
        "updated_at": timepoint(200.0),
    });
    if let Some(verdict) = render_verdict {
        row["render_verdict"] = json!(verdict);
    }
    if let Some(entity) = entity_type {
        row["entity_type"] = json!(entity);
    }
    if let Some(kind) = candidate_kind {
        row["candidate_kind"] = json!(kind);
    }
    if let Some(scope) = veto_scope {
        row["veto_scope"] = json!(scope);
    }
    row
}

#[allow(clippy::too_many_arguments)]
fn seen_query(
    target: &str,
    job_id: &str,
    fetch_key: &str,
    revision: u64,
    pipeline_state: Option<&str>,
    render_verdict: Option<&str>,
    entity_type: Option<&str>,
    candidate_kind: Option<&str>,
    veto_scope: Option<&str>,
    approximate: Option<Value>,
    suppress_when_hit: Option<bool>,
) -> CheckedRecord {
    let mut root = json!({
        "target": target,
        "job_id": job_id,
        "fetch_key": source_hash(fetch_key),
        "detail_revision": revision,
        "journal_id": JOURNAL,
    });
    if let Some(state) = pipeline_state {
        root["pipeline_state"] = json!(state);
    }
    if let Some(verdict) = render_verdict {
        root["render_verdict"] = json!(verdict);
    }
    if let Some(entity) = entity_type {
        root["entity_type"] = json!(entity);
    }
    if let Some(kind) = candidate_kind {
        root["candidate_kind"] = json!(kind);
    }
    if let Some(scope) = veto_scope {
        root["veto_scope"] = json!(scope);
    }
    if let Some(approx) = approximate {
        root["approximate"] = approx;
    }
    if let Some(flag) = suppress_when_hit {
        root["suppress_when_hit"] = json!(flag);
    }
    check("audit_log", root)
}

fn journal_event(sequence: u64, data: Value) -> Value {
    json!({
        "journal_id": JOURNAL,
        "journal_sequence": sequence,
        "event_id": format!("evt-{sequence}"),
        "event_hash": format!("hash-{sequence}"),
        "payload": {
            "data": data,
            "measurements": [],
            "evidence_refs": [],
            "artifact_refs": [],
        },
    })
}

/// Fake owner store serving one journal view. `transact` always faults: the
/// seen-ids seam never writes.
struct FakeSeenStore {
    events: Vec<Value>,
    reads: Mutex<usize>,
    transacts: Mutex<usize>,
}

impl FakeSeenStore {
    fn new(events: Vec<Value>) -> Self {
        Self {
            events,
            reads: Mutex::new(0),
            transacts: Mutex::new(0),
        }
    }

    fn reads(&self) -> usize {
        *self.reads.lock().expect("reads lock")
    }

    fn transacts(&self) -> usize {
        *self.transacts.lock().expect("transacts lock")
    }
}

impl OwnerStore for FakeSeenStore {
    fn transact(&self, _grant: &Grant, _transaction: &CheckedRecord) -> Result<CheckedRecord, Fault> {
        *self.transacts.lock().expect("transacts lock") += 1;
        Err(Fault {
            code: "unexpected_transact".to_string(),
            detail: "seen-ids exact lookup never writes".to_string(),
        })
    }

    fn read(&self, _grant: &Grant, query: &CheckedRecord) -> Result<CheckedRecord, Fault> {
        *self.reads.lock().expect("reads lock") += 1;
        let map = record_value(query).as_object().expect("query object");
        assert_eq!(map.get("query").and_then(Value::as_str), Some("journal"));
        assert_eq!(map.get("journal_id").and_then(Value::as_str), Some(JOURNAL));
        validate(
            "audit_log",
            json!({
                "record_type": "journal_view",
                "journal_id": JOURNAL,
                "run_id": "run-1",
                "owner_domain": OWNER_DOMAIN,
                "manifest_hash": "m",
                "manifest": {},
                "last_sequence": self.events.len(),
                "head_hash": "head",
                "events": self.events,
                "producers": [],
                "imports": [],
            }),
        )
    }
}

struct FailingReadStore;

impl OwnerStore for FailingReadStore {
    fn transact(&self, _grant: &Grant, _transaction: &CheckedRecord) -> Result<CheckedRecord, Fault> {
        Err(Fault {
            code: "unexpected_transact".to_string(),
            detail: "seen-ids exact lookup never writes".to_string(),
        })
    }

    fn read(&self, _grant: &Grant, _query: &CheckedRecord) -> Result<CheckedRecord, Fault> {
        Err(Fault {
            code: "storage_unavailable".to_string(),
            detail: "the owner-local journal read failed".to_string(),
        })
    }
}

fn expect_fault<T: std::fmt::Debug>(result: Result<T, Fault>, code: &str) {
    match result {
        Ok(value) => panic!("expected fault {code:?}, got success: {value:?}"),
        Err(error) => assert_eq!(error.code, code, "fault detail: {}", error.detail),
    }
}

fn assert_no_bare_nulls(value: &Value) {
    fn walk(value: &Value, path: String) {
        match value {
            Value::Null => panic!("bare null at {path}"),
            Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    walk(item, format!("{path}[{index}]"));
                }
            }
            Value::Object(map) => {
                let is_envelope = map.get("value").is_some_and(Value::is_null);
                if is_envelope {
                    assert!(map.get("reason").and_then(Value::as_str).is_some(), "Missing envelope without reason at {path}");
                    for key in map.keys() {
                        assert!(
                            key == "value" || key == "reason" || key == "detail",
                            "undeclared Missing field {key:?} at {path}"
                        );
                    }
                    return;
                }
                for (key, item) in map {
                    walk(item, format!("{path}.{key}"));
                }
            }
            _ => {}
        }
    }
    walk(value, "$".to_string());
}

fn assert_coverage_preserved(verdict: &Value) {
    assert_eq!(verdict["coverage"]["observe_required"], json!(true));
    assert_eq!(verdict["coverage"]["suppressed"], json!(false));
}

// ---------------------------------------------------------------------------
// C18 — exact eligible membership
// ---------------------------------------------------------------------------

#[test]
fn c18_exact_eligible_membership_hits_and_mismatches() {
    let grant = grant();
    let ready = detail_row("t", "j", "key-1", "ready", 7, "run-1", Some("Pass"), None, None, None);
    let vetoed = detail_row("t", "j2", "key-2", "vetoed", 3, "run-1", Some("Pass"), None, None, None);
    let store = FakeSeenStore::new(vec![
        journal_event(2, ready.clone()),
        journal_event(3, vetoed.clone()),
    ]);

    // Ready hit.
    let query = seen_query("t", "j", "key-1", 7, Some("ready"), Some("Pass"), None, None, None, None, None);
    let verdict = exact_success(&store, &grant, &query).expect("ready exact hit");
    let value = record_value(&verdict).clone();
    assert_eq!(value["decision"], json!("hit"));
    assert_eq!(value["reason"], json!("exact_match"));
    assert_eq!(value["exact_confirmed"], json!(true));
    assert_eq!(value["completed_pipeline_state"], json!("ready"));
    assert_eq!(value["completed_detail_revision"], json!(7));
    assert_eq!(value["completed_run_id"], json!("run-1"));
    assert_eq!(value["store_evidence"]["journal_sequence"], json!(2));
    assert_no_bare_nulls(&value);
    assert_coverage_preserved(&value);

    // Vetoed detail hit (genuine detail veto, not snippet-only).
    let query = seen_query("t", "j2", "key-2", 3, Some("vetoed"), Some("Pass"), None, None, None, None, None);
    let verdict = exact_success(&store, &grant, &query).expect("vetoed exact hit");
    let value = record_value(&verdict).clone();
    assert_eq!(value["decision"], json!("hit"));
    assert_eq!(value["completed_pipeline_state"], json!("vetoed"));
    assert_coverage_preserved(&value);

    // Fetch-key mismatch is a miss even at the right revision.
    let query = seen_query("t", "j", "key-other", 7, Some("ready"), Some("Pass"), None, None, None, None, None);
    let verdict = exact_success(&store, &grant, &query).expect("key mismatch is miss");
    let value = record_value(&verdict).clone();
    assert_eq!(value["decision"], json!("miss"));
    assert_eq!(value["reason"], json!("fetch_key_mismatch"));
    assert_eq!(value["exact_confirmed"], json!(true));
    assert_coverage_preserved(&value);

    // Revision mismatch is a miss even at the right key.
    let query = seen_query("t", "j", "key-1", 8, Some("ready"), Some("Pass"), None, None, None, None, None);
    let verdict = exact_success(&store, &grant, &query).expect("revision mismatch is miss");
    assert_eq!(record_value(&verdict)["reason"], json!("revision_mismatch"));

    // State mismatch is a miss: the stored row is ready, the candidate claims vetoed.
    let query = seen_query("t", "j", "key-1", 7, Some("vetoed"), Some("Pass"), None, None, None, None, None);
    let verdict = exact_success(&store, &grant, &query).expect("state mismatch is miss");
    assert_eq!(record_value(&verdict)["reason"], json!("pipeline_state_mismatch"));

    // Unknown root is a miss after exact confirmation.
    let query = seen_query("t", "absent", "key-1", 7, Some("ready"), Some("Pass"), None, None, None, None, None);
    let verdict = exact_success(&store, &grant, &query).expect("absent root is miss");
    let value = record_value(&verdict).clone();
    assert_eq!(value["decision"], json!("miss"));
    assert_eq!(value["reason"], json!("no_exact_record"));
    assert_eq!(value["exact_confirmed"], json!(true));

    // Latest state governs: earlier success followed by failure is not current.
    let failed = detail_row("t", "j3", "key-1", "failed", 9, "run-1", Some("Pass"), None, None, None);
    let store = FakeSeenStore::new(vec![
        journal_event(2, detail_row("t", "j3", "key-1", "ready", 7, "run-1", Some("Pass"), None, None, None)),
        journal_event(3, failed),
    ]);
    let query = seen_query("t", "j3", "key-1", 7, Some("ready"), Some("Pass"), None, None, None, None, None);
    let verdict = exact_success(&store, &grant, &query).expect("exited root is miss");
    assert_eq!(record_value(&verdict)["reason"], json!("stored_ineligible_state"));

    // Recompletion reinstates membership.
    let store = FakeSeenStore::new(vec![
        journal_event(2, detail_row("t", "j3", "key-1", "ready", 7, "run-1", Some("Pass"), None, None, None)),
        journal_event(3, detail_row("t", "j3", "key-1", "failed", 9, "run-1", Some("Pass"), None, None, None)),
        journal_event(4, detail_row("t", "j3", "key-1", "ready", 11, "run-2", Some("Pass"), None, None, None)),
    ]);
    let query = seen_query("t", "j3", "key-1", 11, Some("ready"), Some("Pass"), None, None, None, None, None);
    let verdict = exact_success(&store, &grant, &query).expect("recompletion reinstates");
    assert_eq!(record_value(&verdict)["decision"], json!("hit"));

    assert_eq!(store.transacts(), 0, "exact lookup never writes");
}

#[test]
fn c18_no_snippet_only_veto_or_listing_or_pending_membership() {
    let grant = grant();
    // Even a journaled snippet veto / listing / pending / failed row is never a member.
    let store = FakeSeenStore::new(vec![
        journal_event(2, detail_row("t", "s", "key-s", "vetoed", 2, "run-1", Some("Pass"), None, None, Some("snippet_only"))),
        journal_event(3, detail_row("t", "l", "key-l", "ready", 2, "run-1", Some("Pass"), Some("listing"), None, None)),
        journal_event(4, detail_row("t", "p", "key-p", "pending_classification", 2, "run-1", Some("Pass"), None, None, None)),
        journal_event(5, detail_row("t", "r", "key-r", "render_failed", 2, "run-1", Some("ThinShell"), None, None, None)),
        journal_event(6, detail_row("t", "f", "key-f", "failed", 2, "run-1", Some("Pass"), None, None, None)),
        journal_event(7, detail_row("t", "n", "key-n", "ready", 2, "run-1", Some("EdgeBlock"), None, None, None)),
    ]);

    for (job, key, state, veto_scope, entity, verdict) in [
        ("s", "key-s", "vetoed", Some("snippet_only"), None, "Pass"),
        ("l", "key-l", "ready", None, Some("listing"), "Pass"),
        ("p", "key-p", "pending_classification", None, None, "Pass"),
        ("r", "key-r", "render_failed", None, None, "ThinShell"),
        ("f", "key-f", "failed", None, None, "Pass"),
        ("n", "key-n", "ready", None, None, "EdgeBlock"),
    ] {
        let query = seen_query(
            "t",
            job,
            key,
            2,
            Some(state),
            Some(verdict),
            entity,
            None,
            veto_scope,
            None,
            None,
        );
        let result = exact_success(&store, &grant, &query).expect("ineligible must be miss");
        let value = record_value(&result).clone();
        assert_eq!(value["decision"], json!("miss"), "job {job} must never hit");
        assert_coverage_preserved(&value);
        assert_no_bare_nulls(&value);
    }
    assert_eq!(store.transacts(), 0);

    // The planner never inserts membership for ineligible `after` states.
    let before = check(
        "audit_log",
        detail_row("t", "p", "key-p", "pending_classification", 2, "run-1", Some("Pass"), None, None, None),
    );
    for (state, veto_scope, entity, render) in [
        ("pending_classification", None, None, "Pass"),
        ("failed", None, None, "Pass"),
        ("render_failed", None, None, "ThinShell"),
        ("vetoed", Some("snippet_only"), None, "Pass"),
        ("ready", None, Some("listing"), "Pass"),
    ] {
        let after = check(
            "audit_log",
            detail_row("t", "p", "key-p", state, 3, "run-1", Some(render), entity, None, veto_scope),
        );
        // Listing-typed rows still parse as detail-shaped rows for the planner;
        // they must plan noop, never insert.
        let plan = plan_seen_transition(&before, &after).expect("plan must succeed");
        let value = record_value(&plan).clone();
        assert_eq!(value["after_eligible"], json!(false), "state {state} must be ineligible");
        assert_eq!(value["effect"], json!("noop"));
        assert_eq!(value["commit"]["requires_atomic_commit"], json!(true));
        assert_coverage_preserved(&value);
    }
}

#[test]
fn c18_approximate_hits_require_exact_confirmation() {
    let grant = grant();
    let ready = detail_row("t", "j", "key-1", "ready", 7, "run-1", Some("Pass"), None, None, None);
    let store = FakeSeenStore::new(vec![journal_event(2, ready)]);

    // Definite approximate miss accelerates without a store read.
    let query = seen_query(
        "t", "j", "key-1", 7, Some("ready"), Some("Pass"),
        None, None, None,
        Some(json!({"decision": "miss"})),
        None,
    );
    let verdict = exact_success(&store, &grant, &query).expect("approximate miss");
    let value = record_value(&verdict).clone();
    assert_eq!(value["decision"], json!("miss"));
    assert_eq!(value["reason"], json!("approximate_miss"));
    assert_eq!(value["exact_confirmed"], json!(false));
    assert_eq!(store.reads(), 0, "definite miss must not read the journal");

    // Possible hit with exact backing is a hit — and it read the journal.
    let query = seen_query(
        "t", "j", "key-1", 7, Some("ready"), Some("Pass"),
        None, None, None,
        Some(json!({"decision": "possible_hit"})),
        None,
    );
    let verdict = exact_success(&store, &grant, &query).expect("possible hit confirmed");
    assert_eq!(record_value(&verdict)["decision"], json!("hit"));
    assert_eq!(record_value(&verdict)["exact_confirmed"], json!(true));
    assert_eq!(store.reads(), 1);

    // Possible hit without exact backing is a miss: work is never dropped on
    // an unconfirmed hint.
    let query = seen_query(
        "t", "j", "key-other", 7, Some("ready"), Some("Pass"),
        None, None, None,
        Some(json!({"decision": "possible_hit"})),
        None,
    );
    let verdict = exact_success(&store, &grant, &query).expect("unconfirmed hint is miss");
    let value = record_value(&verdict).clone();
    assert_eq!(value["decision"], json!("miss"));
    assert_eq!(value["exact_confirmed"], json!(true));
    assert_eq!(value["suppress_downstream_work"], json!(false));

    // A failing journal read propagates: no hit is invented.
    let failing = FailingReadStore;
    let query = seen_query(
        "t", "j", "key-1", 7, Some("ready"), Some("Pass"),
        None, None, None,
        Some(json!({"decision": "possible_hit"})),
        None,
    );
    expect_fault(exact_success(&failing, &grant, &query), "storage_unavailable");

    // Malformed approximate hints are rejected, not trusted.
    let query = seen_query(
        "t", "j", "key-1", 7, Some("ready"), Some("Pass"),
        None, None, None,
        Some(json!({"decision": "probably"})),
        None,
    );
    expect_fault(exact_success(&store, &grant, &query), "invalid_approximate");
}

#[test]
fn c18_coverage_unaffected_and_suppression_configured() {
    let grant = grant();
    let ready = detail_row("t", "j", "key-1", "ready", 7, "run-1", Some("Pass"), None, None, None);
    let store = FakeSeenStore::new(vec![journal_event(2, ready)]);

    // Hit without suppression configured: downstream work continues, coverage observed.
    let query = seen_query("t", "j", "key-1", 7, Some("ready"), Some("Pass"), None, None, None, None, None);
    let verdict = exact_success(&store, &grant, &query).expect("hit");
    let value = record_value(&verdict).clone();
    assert_eq!(value["decision"], json!("hit"));
    assert_eq!(value["suppress_downstream_work"], json!(false));
    assert_coverage_preserved(&value);

    // Hit with suppression configured: downstream work suppressed, coverage still observed.
    let query = seen_query(
        "t", "j", "key-1", 7, Some("ready"), Some("Pass"),
        None, None, None, None, Some(true),
    );
    let verdict = exact_success(&store, &grant, &query).expect("hit with suppression");
    let value = record_value(&verdict).clone();
    assert_eq!(value["decision"], json!("hit"));
    assert_eq!(value["suppress_downstream_work"], json!(true));
    assert_coverage_preserved(&value);

    // Miss never suppresses, even when configured.
    let query = seen_query(
        "t", "j", "key-other", 7, Some("ready"), Some("Pass"),
        None, None, None, None, Some(true),
    );
    let verdict = exact_success(&store, &grant, &query).expect("miss");
    let value = record_value(&verdict).clone();
    assert_eq!(value["decision"], json!("miss"));
    assert_eq!(value["suppress_downstream_work"], json!(false));
    assert_coverage_preserved(&value);
}

#[test]
fn c18_plan_seen_transitions_are_atomic_on_exit_and_recompletion() {
    // insert: pending -> ready under a new key.
    let before = check("audit_log", detail_row("t", "j", "key-0", "pending_classification", 2, "run-1", Some("Pass"), None, None, None));
    let after = check("audit_log", detail_row("t", "j", "key-1", "ready", 3, "run-1", Some("Pass"), None, None, None));
    let plan = plan_seen_transition(&before, &after).expect("insert");
    let value = record_value(&plan).clone();
    assert_eq!(value["effect"], json!("insert"));
    assert_eq!(value["before_eligible"], json!(false));
    assert_eq!(value["after_eligible"], json!(true));
    assert_eq!(value["seen_row"]["completed_fetch_key"]["value"], json!("key-1"));
    assert_eq!(value["seen_row"]["completed_pipeline_state"], json!("ready"));
    assert_eq!(value["seen_row"]["completed_detail_revision"], json!(3));
    assert_eq!(value["seen_row"]["completed_run_id"], json!("run-1"));
    assert_eq!(value["commit"]["requires_atomic_commit"], json!(true));
    assert_eq!(value["commit"]["fenced_entity_revision"], json!(3));
    assert_eq!(value["commit"]["invalidates_prior"], json!(false));
    assert_no_bare_nulls(&value);

    // reinstate: pending -> ready under the same key (recompletion after exit).
    let before = check("audit_log", detail_row("t", "j", "key-1", "pending_classification", 4, "run-1", Some("Pass"), None, None, None));
    let after = check("audit_log", detail_row("t", "j", "key-1", "ready", 5, "run-2", Some("Pass"), None, None, None));
    let plan = plan_seen_transition(&before, &after).expect("reinstate");
    assert_eq!(record_value(&plan)["effect"], json!("reinstate"));

    // update: ready -> ready with a new revision.
    let before = check("audit_log", detail_row("t", "j", "key-1", "ready", 5, "run-2", Some("Pass"), None, None, None));
    let after = check("audit_log", detail_row("t", "j", "key-1", "ready", 6, "run-2", Some("Pass"), None, None, None));
    let plan = plan_seen_transition(&before, &after).expect("update");
    assert_eq!(record_value(&plan)["effect"], json!("update"));

    // noop: eligible on both sides with identical identity.
    let before = check("audit_log", detail_row("t", "j", "key-1", "ready", 6, "run-2", Some("Pass"), None, None, None));
    let after = check("audit_log", detail_row("t", "j", "key-1", "ready", 6, "run-2", Some("Pass"), None, None, None));
    let plan = plan_seen_transition(&before, &after).expect("noop");
    let value = record_value(&plan).clone();
    assert_eq!(value["effect"], json!("noop"));
    assert_eq!(value["seen_row"]["completed_detail_revision"], json!(6));

    // invalidate: ready -> pending (reversible exit).
    let before = check("audit_log", detail_row("t", "j", "key-1", "ready", 6, "run-2", Some("Pass"), None, None, None));
    let after = check("audit_log", detail_row("t", "j", "key-1", "pending_classification", 7, "run-2", Some("Pass"), None, None, None));
    let plan = plan_seen_transition(&before, &after).expect("invalidate");
    let value = record_value(&plan).clone();
    assert_eq!(value["effect"], json!("invalidate"));
    assert_eq!(value["commit"]["invalidates_prior"], json!(true));
    assert!(value["seen_row"].get("value").is_some_and(Value::is_null));

    // remove: ready -> failed (terminal exit); membership is gone atomically.
    let before = check("audit_log", detail_row("t", "j", "key-1", "ready", 6, "run-2", Some("Pass"), None, None, None));
    let after = check("audit_log", detail_row("t", "j", "key-1", "failed", 7, "run-2", Some("Pass"), None, None, None));
    let plan = plan_seen_transition(&before, &after).expect("remove");
    let value = record_value(&plan).clone();
    assert_eq!(value["effect"], json!("remove"));
    assert_eq!(value["commit"]["invalidates_prior"], json!(true));

    // remove: ready -> snippet-only veto is also an exit, never a member.
    let before = check("audit_log", detail_row("t", "j", "key-1", "ready", 6, "run-2", Some("Pass"), None, None, None));
    let after = check("audit_log", detail_row("t", "j", "key-1", "vetoed", 7, "run-2", Some("Pass"), None, None, Some("snippet_only")));
    let plan = plan_seen_transition(&before, &after).expect("snippet exit");
    assert_eq!(record_value(&plan)["effect"], json!("remove"));

    // Cross-root plans are rejected: one plan covers one (target, job_id).
    let before = check("audit_log", detail_row("t", "j", "key-1", "ready", 6, "run-2", Some("Pass"), None, None, None));
    let after = check("audit_log", detail_row("t", "other", "key-1", "ready", 6, "run-2", Some("Pass"), None, None, None));
    expect_fault(plan_seen_transition(&before, &after), "identity_mismatch");

    // Unknown pipeline states are rejected, never mapped to a neighbor.
    let before = check("audit_log", detail_row("t", "j", "key-1", "ready", 6, "run-2", Some("Pass"), None, None, None));
    let mut bad = detail_row("t", "j", "key-1", "ready", 7, "run-2", Some("Pass"), None, None, None);
    bad["pipeline_state"] = json!("mostly_ready");
    let after = check("audit_log", bad);
    expect_fault(plan_seen_transition(&before, &after), "unknown_pipeline_state");
}

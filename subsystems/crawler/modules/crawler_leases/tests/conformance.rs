//! Conformance tests for `crawler_leases`.
//!
//! * **[C09]** Claim: state unchanged; token/revision/epoch/audit atomically
//!   assigned.
//! * **[C10]** Reclamation race: release, expiry, and confirmed-death recovery
//!   increment one failed generation at most once.
//! * **[C11]** Stale completion: no row, cursor, classifier, membership, or
//!   downstream effect.
//!
//! The tests use the real `crawler_authority` grant seam, the real
//! `crawler_time` authority clock, and a recording owner store. The recording
//! store accepts only the module's `lease_transition` transaction and keeps
//! its value, so every assertion is about the module's actual emitted effect.
//! The once-only race additionally runs through a compare-and-swap store that
//! applies the transaction only when the emitted `expected.entity_revision`
//! still matches, mirroring the owner-local revision fence.

use crawler_authority::{authorize_producer, Grant};
use crawler_hashing::{canonical_bytes, digest_bytes};
use crawler_leases::{claim, complete, reclaim, renew};
use crawler_schema::{record_value, validate, CheckedRecord, Fault};
use crawler_store::OwnerStore;
use crawler_time::{compare_deadline, ClockAuthority};
use serde_json::{json, Value};
use std::cmp::Ordering;
use std::sync::Mutex;

const CLOCK_ID: &str = "lease-clk-a";
const BOOT_ID: &str = "boot-a";
const OWNER: &str = "crawler_worker";
const OWNER_DOMAIN: &str = "crawler_ingest";
const HELD_LEASE: &str = "held-lease-1";

fn check(schema: &str, value: Value) -> CheckedRecord {
    validate(schema, value).expect("test fixture must validate")
}

fn missing(reason: &str) -> Value {
    json!({"value": Value::Null, "reason": reason})
}

fn point_on(clock_id: &str, boot_id: &str, offset_ms: f64) -> Value {
    json!({
        "clock_id": clock_id,
        "boot_id": boot_id,
        "origin": "engine_measured",
        "monotonic_offset_ms": offset_ms,
        "utc_annotation": missing("not_observed"),
    })
}

fn point(offset_ms: f64) -> Value {
    point_on(CLOCK_ID, BOOT_ID, offset_ms)
}

fn compare(left: &Value, right: &Value) -> Ordering {
    let left = check("audit_log", left.clone());
    let right = check("audit_log", right.clone());
    compare_deadline(&left, &right).expect("fixture timestamps share one clock and boot")
}

/// Authority clock reading at a fixed offset.
struct TestClock {
    clock_id: &'static str,
    boot_id: &'static str,
    offset_ms: f64,
}

impl TestClock {
    fn new(offset_ms: f64) -> Self {
        Self {
            clock_id: CLOCK_ID,
            boot_id: BOOT_ID,
            offset_ms,
        }
    }

    fn on_boot(offset_ms: f64, boot_id: &'static str) -> Self {
        Self {
            clock_id: CLOCK_ID,
            boot_id,
            offset_ms,
        }
    }
}

impl ClockAuthority for TestClock {
    fn now(&self) -> Result<CheckedRecord, Fault> {
        validate(
            "audit_log",
            point_on(self.clock_id, self.boot_id, self.offset_ms),
        )
    }
}

fn binding_of(record: &CheckedRecord) -> String {
    digest_bytes(&canonical_bytes(record).expect("canonical bytes"))
}

fn manifest() -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "manifest_id": "manifest-leases",
            "producer_registry": [
                {
                    "producer_id": OWNER,
                    "owner_domain": OWNER_DOMAIN,
                    "role": "external_input",
                    "provenance": "server",
                    "assertion_kind": "claim",
                },
            ],
            "event_registry": [
                {"event_kind": "lease_claimed", "permitted_provenance": ["server"]},
                {"event_kind": "lease_renewed", "permitted_provenance": ["server"]},
                {"event_kind": "lease_completed", "permitted_provenance": ["server"]},
                {"event_kind": "lease_reclaimed", "permitted_provenance": ["server"]},
            ],
        }),
    )
}

fn grant() -> Grant {
    let manifest = manifest();
    let principal = check(
        "audit_log",
        json!({
            "producer_id": OWNER,
            "manifest_digest": binding_of(&manifest),
        }),
    );
    let submission = check("audit_log", json!({"event_kind": "lease_claimed"}));
    authorize_producer(&principal, &submission, &manifest).expect("producer grant must issue")
}

/// Complete claimable row (§5) in the requested operational state.
fn row(state: &str) -> Value {
    json!({
        "target": "target-1",
        "job_id": "job-1",
        "active_run_id": "run-1",
        "partition_id": "partition-1",
        "entity_revision": 4,
        "input_revision": 2,
        "retry_count": 0,
        "max_retries_effective": 3,
        "pipeline_state": state,
        "lease_id": missing("not_applicable"),
        "lease_owner": missing("not_applicable"),
        "leased_at": missing("not_applicable"),
        "lease_expires_at": missing("not_applicable"),
        "last_failure_reason": missing("not_applicable"),
        "created_at": point(800.0),
        "updated_at": point(900.0),
        "endpoint_id": "endpoint-b",
    })
}

fn held_row(state: &str) -> Value {
    let mut value = row(state);
    value["lease_id"] = json!(HELD_LEASE);
    value["lease_owner"] = json!(OWNER);
    value["leased_at"] = point(1000.0);
    value["lease_expires_at"] = point(1030.0);
    value
}

/// Authority-journal lease evidence for a new claim assignment.
fn assignment() -> Value {
    json!({
        "issuer": "lease-authority",
        "authority_epoch": 7,
        "owner": OWNER,
        "owner_epoch": 11,
        "generation_id": "gen-7-11",
        "policy_pin": "lease-policy-v1",
        "session_epoch": 3,
        "ttl_ms": 30.0,
        "lease_id": missing("not_applicable"),
    })
}

fn held_lease_with(ttl: Value, authority_epoch: u64, owner_epoch: u64, session_epoch: Value) -> Value {
    json!({
        "issuer": "lease-authority",
        "authority_epoch": authority_epoch,
        "owner": OWNER,
        "owner_epoch": owner_epoch,
        "generation_id": "gen-7-11",
        "policy_pin": "lease-policy-v1",
        "session_epoch": session_epoch,
        "ttl_ms": ttl,
        "lease_id": HELD_LEASE,
    })
}

fn held_lease() -> Value {
    held_lease_with(json!(30.0), 7, 11, json!(3))
}

fn expected_with(
    lease_id: &str,
    entity_revision: u64,
    input_revision: u64,
    authority_epoch: u64,
    owner_epoch: u64,
    session_epoch: Value,
) -> Value {
    json!({
        "entity_revision": entity_revision,
        "input_revision": input_revision,
        "lease_id": lease_id,
        "authority_epoch": authority_epoch,
        "owner_epoch": owner_epoch,
        "session_epoch": session_epoch,
    })
}

fn expected() -> Value {
    expected_with(HELD_LEASE, 4, 2, 7, 11, json!(3))
}

fn claim_request(entity_type: &str, row: Value, lease: Value) -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "operation": "claim",
            "entity_type": entity_type,
            "row": row,
            "lease": lease,
        }),
    )
}

fn held_request(
    operation: &str,
    entity_type: &str,
    row: Value,
    lease: Value,
    expected: Value,
) -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "operation": operation,
            "entity_type": entity_type,
            "row": row,
            "lease": lease,
            "expected": expected,
        }),
    )
}

fn reclaim_request(
    entity_type: &str,
    row: Value,
    lease: Value,
    expected: Value,
    trigger: &str,
    failure_reason: Value,
) -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "operation": "reclaim",
            "entity_type": entity_type,
            "row": row,
            "lease": lease,
            "expected": expected,
            "reclaim": {
                "trigger": trigger,
                "failure_reason": failure_reason,
            },
        }),
    )
}

fn expect_fault<T: std::fmt::Debug>(result: Result<T, Fault>, code: &str) -> Fault {
    match result {
        Ok(value) => panic!("expected fault {code:?}, got success: {value:?}"),
        Err(error) => {
            assert_eq!(error.code, code, "fault detail: {}", error.detail);
            error
        }
    }
}

#[derive(Default)]
struct RecordingStore {
    calls: Mutex<Vec<Value>>,
}

impl RecordingStore {
    fn new() -> Self {
        Self::default()
    }

    fn calls(&self) -> Vec<Value> {
        self.calls.lock().expect("calls lock").clone()
    }

    fn count(&self) -> usize {
        self.calls.lock().expect("calls lock").len()
    }
}

impl OwnerStore for RecordingStore {
    fn transact(&self, _grant: &Grant, transaction: &CheckedRecord) -> Result<CheckedRecord, Fault> {
        let value = record_value(transaction).clone();
        assert_eq!(
            value["operation"], "lease_transition",
            "the owner store accepts only the module's lease transition transaction"
        );
        let mut calls = self.calls.lock().expect("calls lock");
        calls.push(value);
        validate(
            "audit_log",
            json!({
                "durable": true,
                "acknowledged": true,
                "journal_sequence": calls.len(),
            }),
        )
    }

    fn read(&self, _grant: &Grant, _query: &CheckedRecord) -> Result<CheckedRecord, Fault> {
        Err(Fault {
            code: "unexpected_read".to_string(),
            detail: "lease transitions never read the journal".to_string(),
        })
    }
}

/// Store whose durable append fails: the transition must not be acknowledged.
#[derive(Default)]
struct FailingStore {
    attempts: Mutex<usize>,
}

impl OwnerStore for FailingStore {
    fn transact(&self, _grant: &Grant, _transaction: &CheckedRecord) -> Result<CheckedRecord, Fault> {
        *self.attempts.lock().expect("attempts lock") += 1;
        Err(Fault {
            code: "storage_unavailable".to_string(),
            detail: "the owner-local durable append failed".to_string(),
        })
    }

    fn read(&self, _grant: &Grant, _query: &CheckedRecord) -> Result<CheckedRecord, Fault> {
        Err(Fault {
            code: "unexpected_read".to_string(),
            detail: "lease transitions never read the journal".to_string(),
        })
    }
}

/// Owner-local compare-and-swap store: accepts a transaction only when its
/// emitted `expected.entity_revision` still matches the durable revision.
struct CasStore {
    revision: Mutex<u64>,
    accepted: Mutex<Vec<Value>>,
    rejected: Mutex<usize>,
}

impl CasStore {
    fn new(revision: u64) -> Self {
        Self {
            revision: Mutex::new(revision),
            accepted: Mutex::new(Vec::new()),
            rejected: Mutex::new(0),
        }
    }

    fn accepted(&self) -> Vec<Value> {
        self.accepted.lock().expect("accepted lock").clone()
    }

    fn rejected_count(&self) -> usize {
        *self.rejected.lock().expect("rejected lock")
    }
}

impl OwnerStore for CasStore {
    fn transact(&self, _grant: &Grant, transaction: &CheckedRecord) -> Result<CheckedRecord, Fault> {
        let value = record_value(transaction).clone();
        let expected = value["expected"]["entity_revision"]
            .as_u64()
            .expect("lease transaction must name its expected entity revision");
        let mut revision = self.revision.lock().expect("revision lock");
        if expected != *revision {
            *self.rejected.lock().expect("rejected lock") += 1;
            return Err(Fault {
                code: "stale_revision".to_string(),
                detail: format!(
                    "owner store CAS rejected expected revision {expected}; the row is at {}",
                    *revision
                ),
            });
        }
        *revision += 1;
        self.accepted.lock().expect("accepted lock").push(value);
        validate(
            "audit_log",
            json!({"durable": true, "journal_sequence": *revision}),
        )
    }

    fn read(&self, _grant: &Grant, _query: &CheckedRecord) -> Result<CheckedRecord, Fault> {
        Err(Fault {
            code: "unexpected_read".to_string(),
            detail: "lease transitions never read the journal".to_string(),
        })
    }
}

// ---------------------------------------------------------------------------
// C09 — Claim: state unchanged; token/revision/epoch/audit atomically assigned
// ---------------------------------------------------------------------------

#[test]
fn c09_claim_atomically_assigns_token_revision_epochs_and_audit_without_changing_state() {
    let store = RecordingStore::new();
    let clock = TestClock::new(1000.0);
    let grant = grant();

    let mut before = row("pending");
    before["retry_count"] = json!(1);
    before["last_failure_reason"] = json!("extract_timeout");
    let request = claim_request("work_item", before.clone(), assignment());

    let claimed = claim(&store, &clock, &grant, &request).expect("claim must succeed");
    let value = record_value(&claimed);

    // Operational state is untouched; only the lease/revision/audit advance.
    assert_eq!(value["row"]["pipeline_state"], "pending");
    assert_eq!(value["row"]["input_revision"], 2);
    assert_eq!(value["row"]["retry_count"], 1);
    assert_eq!(value["row"]["entity_revision"], 5);
    assert_eq!(value["row"]["lease_owner"], OWNER);
    assert_eq!(value["row"]["last_failure_reason"]["reason"], "not_applicable");

    let lease_id = value["row"]["lease_id"]
        .as_str()
        .expect("claim assigns an established lease_id");
    assert!(!lease_id.is_empty());
    assert!(lease_id.contains("gen-7-11"), "token must fence the generation");
    assert!(lease_id.contains(":5"), "token must fence the new revision");

    assert_eq!(value["transition"]["trigger"], "claim");
    assert_eq!(value["transition"]["authority_epoch"], 7);
    assert_eq!(value["transition"]["owner_epoch"], 11);
    assert_eq!(value["transition"]["generation_id"], "gen-7-11");
    assert_eq!(value["transition"]["session_epoch"], 3);
    assert_eq!(value["transition"]["failed_generation_charged"], false);
    assert_eq!(value["transition"]["commit_authority_revoked"], false);

    assert_eq!(value["audit"]["event_kind"], "lease_claimed");
    assert_eq!(value["audit"]["owner_domain"], OWNER_DOMAIN);
    assert_eq!(value["audit"]["producer_id"], OWNER);
    assert_eq!(value["audit"]["lease_id"], lease_id);
    assert!(value["audit"]["idempotency_key"].as_str().is_some());

    // Issue and expiry share one registered authority clock/boot; expiry is later.
    let issued = value["row"]["leased_at"].clone();
    let expires = value["row"]["lease_expires_at"].clone();
    assert_eq!(issued["clock_id"], CLOCK_ID);
    assert_eq!(issued["boot_id"], BOOT_ID);
    assert_eq!(expires["clock_id"], CLOCK_ID);
    assert_eq!(expires["boot_id"], BOOT_ID);
    assert_eq!(compare(&issued, &expires), Ordering::Less);

    // Exactly one atomic owner-local effect carries the same row, transition,
    // and audit evidence that the caller receives.
    let calls = store.calls();
    assert_eq!(calls.len(), 1, "claim must commit one owner-local effect");
    assert_eq!(calls[0]["operation"], "lease_transition");
    assert_eq!(calls[0]["row"], value["row"]);
    assert_eq!(calls[0]["transition"], value["transition"]);
    assert_eq!(calls[0]["audit"], value["audit"]);
    assert_eq!(calls[0]["expected"]["entity_revision"], 4);
    assert_eq!(
        calls[0]["expected"]["lease_id"]["reason"],
        "not_applicable"
    );

    // A second pending row receives a different fencing token.
    let mut other = row("pending");
    other["job_id"] = json!("job-2");
    let second = claim(
        &store,
        &clock,
        &grant,
        &claim_request("work_item", other, assignment()),
    )
    .expect("second claim must succeed");
    assert_ne!(record_value(&second)["row"]["lease_id"], lease_id);
    assert_eq!(store.count(), 2);
}

#[test]
fn c09_claim_refuses_busy_ineligible_unauthenticated_and_exhausted_rows() {
    let clock = TestClock::new(1000.0);
    let grant = grant();

    // A held (even expired) lease must be reclaimed first so its failed
    // generation is charged exactly once.
    let store = RecordingStore::new();
    expect_fault(
        claim(
            &store,
            &clock,
            &grant,
            &claim_request("work_item", held_row("pending"), assignment()),
        ),
        "lease_busy",
    );
    assert_eq!(store.count(), 0);

    // Terminal/finished states are not claimable.
    let store = RecordingStore::new();
    expect_fault(
        claim(
            &store,
            &clock,
            &grant,
            &claim_request("work_item", row("done"), assignment()),
        ),
        "ineligible_state",
    );
    let listing = claim(
        &store,
        &clock,
        &grant,
        &claim_request("listing", row("finalized"), assignment()),
    );
    expect_fault(listing, "ineligible_state");
    assert_eq!(store.count(), 0);

    // A claim cannot self-issue ownership outside the authenticated principal.
    let mut rogue = assignment();
    rogue["owner"] = json!("some_other_worker");
    let store = RecordingStore::new();
    expect_fault(
        claim(
            &store,
            &clock,
            &grant,
            &claim_request("work_item", row("pending"), rogue),
        ),
        "unauthenticated_lease_owner",
    );
    assert_eq!(store.count(), 0);

    // Exhausted work is never resurrected by a claim.
    let mut spent = row("pending");
    spent["retry_count"] = json!(4);
    spent["max_retries_effective"] = json!(3);
    let store = RecordingStore::new();
    expect_fault(
        claim(
            &store,
            &clock,
            &grant,
            &claim_request("work_item", spent, assignment()),
        ),
        "retry_exhausted",
    );
    assert_eq!(store.count(), 0);
}

#[test]
fn c09_claim_preserves_each_pending_entity_state_and_sessionless_epoch() {
    let store = RecordingStore::new();
    let clock = TestClock::new(1100.0);
    let grant = grant();

    // Listings claim from their pending vocabulary without changing state.
    let listing = claim(
        &store,
        &clock,
        &grant,
        &claim_request("listing", row("pending_snippet_classify"), assignment()),
    )
    .expect("a pending listing must be claimable");
    let listing_value = record_value(&listing);
    assert_eq!(listing_value["row"]["pipeline_state"], "pending_snippet_classify");
    assert_eq!(listing_value["row"]["entity_revision"], 5);
    assert_eq!(listing_value["row"]["input_revision"], 2);
    assert_eq!(listing_value["audit"]["entity_type"], "listing");

    // A sessionless generation carries typed Missing(not_applicable) epochs
    // through assignment, evidence, and audit.
    let mut sessionless = assignment();
    sessionless["session_epoch"] = missing("not_applicable");
    let detail = claim(
        &store,
        &clock,
        &grant,
        &claim_request("job_detail", row("pending_classification"), sessionless),
    )
    .expect("a sessionless pending detail must be claimable");
    let detail_value = record_value(&detail);
    assert_eq!(
        detail_value["row"]["pipeline_state"],
        "pending_classification"
    );
    assert_eq!(detail_value["transition"]["session_epoch"]["reason"], "not_applicable");
    assert_eq!(detail_value["audit"]["session_epoch"]["reason"], "not_applicable");
    assert_eq!(detail_value["row"]["entity_revision"], 5);
    assert_eq!(store.count(), 2);
}

#[test]
fn c09_claim_is_not_acknowledged_before_the_owner_store_commits() {
    let store = FailingStore::default();
    let clock = TestClock::new(1000.0);
    let grant = grant();
    let error = expect_fault(
        claim(
            &store,
            &clock,
            &grant,
            &claim_request("work_item", row("pending"), assignment()),
        ),
        "storage_unavailable",
    );
    assert_eq!(*store.attempts.lock().expect("attempts lock"), 1);
    assert!(error.detail.contains("durable append"));
}

// ---------------------------------------------------------------------------
// C10 — Reclamation race: one failed generation is charged at most once
// ---------------------------------------------------------------------------

#[test]
fn c10_release_expiry_and_death_recovery_charge_the_generation_at_most_once() {
    let grant = grant();

    // Direct release: ownership cleared, retry charged once, pending preserved.
    let store = RecordingStore::new();
    let clock = TestClock::new(1010.0);
    let released = reclaim(
        &store,
        &clock,
        &grant,
        &reclaim_request(
            "work_item",
            held_row("pending"),
            held_lease(),
            expected(),
            "release",
            json!("fetch_failed"),
        ),
    )
    .expect("early release must reclaim");
    let released_value = record_value(&released);
    assert_eq!(released_value["row"]["retry_count"], 1);
    assert_eq!(released_value["row"]["pipeline_state"], "pending");
    assert_eq!(released_value["row"]["last_failure_reason"], "fetch_failed");
    assert_eq!(released_value["row"]["entity_revision"], 5);
    assert_eq!(released_value["row"]["lease_id"]["reason"], "not_applicable");
    assert_eq!(released_value["transition"]["failed_generation_charged"], true);
    assert_eq!(released_value["transition"]["commit_authority_revoked"], true);
    assert_eq!(released_value["transition"]["exhausted"], false);
    assert_eq!(released_value["dead_letter"]["reason"], "not_applicable");
    assert!(released_value["transition"]["limitation"]
        .as_str()
        .expect("reclamation records its limitation")
        .contains("local commit authority"));
    assert_eq!(store.count(), 1);
    assert_eq!(store.calls()[0]["row"], released_value["row"]);

    // Replaying the other triggers against the already-reclaimed row cannot
    // charge the same failed generation again.
    let reclaimed_row = released_value["row"].clone();
    for trigger in ["release", "expiry", "death_recovery"] {
        let mut lease = held_lease();
        let mut expected = expected();
        if trigger == "death_recovery" {
            lease["authority_epoch"] = json!(8);
            expected["authority_epoch"] = json!(8);
        }
        let request = reclaim_request(
            "work_item",
            reclaimed_row.clone(),
            lease,
            expected,
            trigger,
            json!("fetch_failed"),
        );
        expect_fault(reclaim(&store, &clock, &grant, &request), "lease_not_held");
    }
    assert_eq!(store.count(), 1, "a reclaimed generation is never charged twice");
    assert_eq!(
        released_value["row"]["retry_count"], 1,
        "the durable row still records exactly one failed generation"
    );

    // A genuine release/expiry/death race: all three begin from the same
    // revision-4 snapshot, and the owner-local revision fence accepts exactly
    // one. The losing two never charge a second generation.
    let cas = CasStore::new(4);
    let release_request = reclaim_request(
        "work_item",
        held_row("pending"),
        held_lease(),
        expected(),
        "release",
        json!("fetch_failed"),
    );
    let expiry_request = reclaim_request(
        "work_item",
        held_row("pending"),
        held_lease(),
        expected(),
        "expiry",
        json!("lease_expired"),
    );
    let death_request = reclaim_request(
        "work_item",
        held_row("pending"),
        held_lease_with(json!(30.0), 7, 11, json!(3)),
        expected_with(HELD_LEASE, 4, 2, 8, 11, json!(3)),
        "death_recovery",
        json!("worker_death_confirmed"),
    );

    let expiry_clock = TestClock::new(1030.0);
    let death_clock = TestClock::on_boot(1200.0, "boot-b");
    let _ = reclaim(&cas, &clock, &grant, &release_request).expect("first racer wins");
    expect_fault(
        reclaim(&cas, &expiry_clock, &grant, &expiry_request),
        "stale_revision",
    );
    expect_fault(
        reclaim(&cas, &death_clock, &grant, &death_request),
        "stale_revision",
    );
    assert_eq!(cas.rejected_count(), 2);
    let accepted = cas.accepted();
    assert_eq!(accepted.len(), 1, "exactly one reclamation may commit");
    assert_eq!(accepted[0]["row"]["retry_count"], 1);
    assert_eq!(accepted[0]["transition"]["failed_generation_charged"], true);

    // Replaying the winning reclamation against its own committed row is
    // rejected before the store, so no second charge and no second audit.
    let replay_store = RecordingStore::new();
    let replay_row = accepted[0]["row"].clone();
    expect_fault(
        reclaim(
            &replay_store,
            &clock,
            &grant,
            &reclaim_request(
                "work_item",
                replay_row,
                held_lease(),
                expected(),
                "release",
                json!("fetch_failed"),
            ),
        ),
        "lease_not_held",
    );
    assert_eq!(replay_store.count(), 0);
}

#[test]
fn c10_expiry_requires_a_reached_deadline_on_its_own_boot() {
    let grant = grant();

    // Before the deadline, expiry reclamation is refused and nothing commits.
    let store = RecordingStore::new();
    let early = TestClock::new(1020.0);
    expect_fault(
        reclaim(
            &store,
            &early,
            &grant,
            &reclaim_request(
                "work_item",
                held_row("pending"),
                held_lease(),
                expected(),
                "expiry",
                json!("lease_expired"),
            ),
        ),
        "lease_unexpired",
    );
    assert_eq!(store.count(), 0);

    // A different boot cannot establish the old deadline; the module refuses
    // to subtract/compare offsets across boots instead of guessing downtime.
    let store = RecordingStore::new();
    let new_boot = TestClock::on_boot(2000.0, "boot-b");
    expect_fault(
        reclaim(
            &store,
            &new_boot,
            &grant,
            &reclaim_request(
                "work_item",
                held_row("pending"),
                held_lease(),
                expected(),
                "expiry",
                json!("lease_expired"),
            ),
        ),
        "cross_boot",
    );
    assert_eq!(store.count(), 0);

    // Reaching the deadline on the issuing boot reclaims and charges once.
    let store = RecordingStore::new();
    let reached = TestClock::new(1030.0);
    let reclaimed = reclaim(
        &store,
        &reached,
        &grant,
        &reclaim_request(
            "work_item",
            held_row("pending"),
            held_lease(),
            expected(),
            "expiry",
            json!("lease_expired"),
        ),
    )
    .expect("reached deadline must reclaim");
    assert_eq!(record_value(&reclaimed)["row"]["retry_count"], 1);
    assert_eq!(store.count(), 1);
}

#[test]
fn c10_death_recovery_fences_a_new_epoch_without_comparing_old_offsets() {
    let grant = grant();

    // Reusing the old authority epoch is not a restart fence.
    let store = RecordingStore::new();
    let clock = TestClock::new(1500.0);
    expect_fault(
        reclaim(
            &store,
            &clock,
            &grant,
            &reclaim_request(
                "work_item",
                held_row("pending"),
                held_lease(),
                expected(),
                "death_recovery",
                json!("worker_death_confirmed"),
            ),
        ),
        "restart_not_fenced",
    );
    assert_eq!(store.count(), 0);

    // An older epoch cannot fence a newer generation.
    let store = RecordingStore::new();
    expect_fault(
        reclaim(
            &store,
            &clock,
            &grant,
            &reclaim_request(
                "work_item",
                held_row("pending"),
                held_lease_with(json!(30.0), 9, 11, json!(3)),
                expected_with(HELD_LEASE, 4, 2, 8, 11, json!(3)),
                "death_recovery",
                json!("worker_death_confirmed"),
            ),
        ),
        "stale_authority_epoch",
    );
    assert_eq!(store.count(), 0);

    // A newer epoch fences the old generation. The recovery authority runs on
    // a new boot and the stale deadline is deliberately never compared.
    let store = RecordingStore::new();
    let new_boot = TestClock::on_boot(5000.0, "boot-b");
    let reclaimed = reclaim(
        &store,
        &new_boot,
        &grant,
        &reclaim_request(
            "work_item",
            held_row("pending"),
            held_lease(),
            expected_with(HELD_LEASE, 4, 2, 8, 11, json!(3)),
            "death_recovery",
            json!("worker_death_confirmed"),
        ),
    )
    .expect("a newer authority epoch may reclaim across boots");
    let value = record_value(&reclaimed);
    assert_eq!(value["row"]["retry_count"], 1);
    assert_eq!(value["row"]["lease_id"]["reason"], "not_applicable");
    assert_eq!(value["transition"]["previous_authority_epoch"], 7);
    assert_eq!(value["transition"]["authority_epoch"], 8);
    assert_eq!(value["transition"]["failed_generation_charged"], true);
    assert_eq!(store.calls()[0]["fenced_authority_epoch"], 8);
    assert_eq!(store.calls()[0]["previous_authority_epoch"], 7);
}

#[test]
fn c10_renewal_extends_the_current_generation_and_cannot_resurrect_expired_leases() {
    let grant = grant();
    let store = RecordingStore::new();
    let clock = TestClock::new(1010.0);

    let renewed = renew(
        &store,
        &clock,
        &grant,
        &held_request("renew", "work_item", held_row("pending"), held_lease(), expected()),
    )
    .expect("renewal must extend a live lease");
    let value = record_value(&renewed);
    assert_eq!(value["row"]["lease_id"], HELD_LEASE);
    assert_eq!(value["row"]["lease_owner"], OWNER);
    assert_eq!(value["row"]["entity_revision"], 5);
    assert_eq!(value["row"]["pipeline_state"], "pending");
    assert_eq!(value["row"]["leased_at"], point(1000.0));
    assert_eq!(compare(&point(1030.0), &value["row"]["lease_expires_at"]), Ordering::Less);
    assert_eq!(value["transition"]["trigger"], "renewal");
    assert_eq!(value["transition"]["failed_generation_charged"], false);
    assert_eq!(store.count(), 1);

    // At the deadline the lease is expired; renewal cannot resurrect it.
    let expired_clock = TestClock::new(1030.0);
    expect_fault(
        renew(
            &store,
            &expired_clock,
            &grant,
            &held_request("renew", "work_item", held_row("pending"), held_lease(), expected()),
        ),
        "lease_expired",
    );
    assert_eq!(store.count(), 1);

    // A renewal that would not extend the deadline is refused.
    let near_clock = TestClock::new(1025.0);
    expect_fault(
        renew(
            &store,
            &near_clock,
            &grant,
            &held_request(
                "renew",
                "work_item",
                held_row("pending"),
                held_lease_with(json!(5.0), 7, 11, json!(3)),
                expected(),
            ),
        ),
        "renewal_not_extended",
    );
    assert_eq!(store.count(), 1);

    // Stale tokens/epochs/revisions are fenced before the store.
    let stale_cases = [
        (
            "stale_lease",
            held_request(
                "renew",
                "work_item",
                held_row("pending"),
                held_lease(),
                expected_with("someone-elses-token", 4, 2, 7, 11, json!(3)),
            ),
        ),
        (
            "stale_revision",
            held_request(
                "renew",
                "work_item",
                held_row("pending"),
                held_lease(),
                expected_with(HELD_LEASE, 3, 2, 7, 11, json!(3)),
            ),
        ),
        (
            "stale_owner_epoch",
            held_request(
                "renew",
                "work_item",
                held_row("pending"),
                held_lease(),
                expected_with(HELD_LEASE, 4, 2, 7, 12, json!(3)),
            ),
        ),
        (
            "stale_session_epoch",
            held_request(
                "renew",
                "work_item",
                held_row("pending"),
                held_lease(),
                expected_with(HELD_LEASE, 4, 2, 7, 11, json!(4)),
            ),
        ),
    ];
    for (code, request) in stale_cases {
        expect_fault(renew(&store, &clock, &grant, &request), code);
    }
    assert_eq!(store.count(), 1);

    // A restarted boot cannot renew by comparing old offsets.
    let new_boot = TestClock::on_boot(1010.0, "boot-b");
    expect_fault(
        renew(
            &store,
            &new_boot,
            &grant,
            &held_request("renew", "work_item", held_row("pending"), held_lease(), expected()),
        ),
        "cross_boot",
    );
    assert_eq!(store.count(), 1);

    // Replaying the pre-renewal command against the advanced generation is a
    // stale revision fence, and the renewal itself already committed once.
    expect_fault(
        renew(
            &store,
            &clock,
            &grant,
            &held_request(
                "renew",
                "work_item",
                value["row"].clone(),
                held_lease(),
                expected(),
            ),
        ),
        "stale_revision",
    );
    assert_eq!(store.count(), 1);
}

#[test]
fn c10_exhaustion_routes_terminal_and_emits_one_dead_letter_occurrence() {
    let grant = grant();
    let store = RecordingStore::new();
    let clock = TestClock::new(1010.0);

    let mut spent = held_row("pending");
    spent["retry_count"] = json!(3);
    spent["max_retries_effective"] = json!(3);
    let reclaimed = reclaim(
        &store,
        &clock,
        &grant,
        &reclaim_request(
            "work_item",
            spent,
            held_lease(),
            expected(),
            "release",
            json!("fetch_failed"),
        ),
    )
    .expect("exhausting reclamation must route terminal");
    let value = record_value(&reclaimed);
    assert_eq!(value["row"]["retry_count"], 4);
    assert_eq!(value["row"]["pipeline_state"], "failed");
    assert_eq!(value["transition"]["exhausted"], true);
    assert_eq!(value["dead_letter"]["failure_reason"], "fetch_failed");
    assert_eq!(value["dead_letter"]["retry_count"], 1);
    assert_eq!(value["dead_letter"]["last_entity_revision"], 4);
    assert_eq!(value["dead_letter"]["last_lease_id"], HELD_LEASE);
    assert_eq!(value["dead_letter"]["run_id"], "run-1");
    assert_eq!(value["dead_letter"]["stage"], "lease_reclamation");
    assert_eq!(value["dead_letter"]["resolution_status"], "open");
    assert_eq!(store.calls()[0]["dead_letter"], value["dead_letter"]);

    // Replaying the same failed generation cannot add a second occurrence:
    // the terminal row is no longer reclaimable and nothing reaches the store.
    expect_fault(
        reclaim(
            &store,
            &clock,
            &grant,
            &reclaim_request(
                "work_item",
                value["row"].clone(),
                held_lease(),
                expected(),
                "release",
                json!("fetch_failed"),
            ),
        ),
        "ineligible_state",
    );
    assert_eq!(store.count(), 1, "one generation yields one dead-letter occurrence");

    // With no recorded reason, exhaustion uses the kernel fallback.
    let store = RecordingStore::new();
    let mut spent = held_row("pending");
    spent["retry_count"] = json!(3);
    spent["max_retries_effective"] = json!(3);
    let fallback = reclaim(
        &store,
        &clock,
        &grant,
        &reclaim_request(
            "work_item",
            spent,
            held_lease(),
            expected(),
            "release",
            missing("not_observed"),
        ),
    )
    .expect("exhaustion without a recorded reason still dead-letters");
    assert_eq!(
        record_value(&fallback)["dead_letter"]["failure_reason"],
        "retry_exhausted"
    );

    // Exhausted work is not claimable: the terminal row stays failed.
    let store = RecordingStore::new();
    expect_fault(
        claim(
            &store,
            &clock,
            &grant,
            &claim_request(
                "work_item",
                record_value(&reclaimed)["row"].clone(),
                assignment(),
            ),
        ),
        "ineligible_state",
    );
    assert_eq!(store.count(), 0);
}

// ---------------------------------------------------------------------------
// C11 — Stale completion: no row, cursor, classifier, membership, or downstream effect
// ---------------------------------------------------------------------------

#[test]
fn c11_stale_completion_has_no_entity_or_downstream_effect() {
    let grant = grant();
    let clock = TestClock::new(1010.0);

    // Control: a live, current completion succeeds and is not a failed retry.
    let store = RecordingStore::new();
    let completed = complete(
        &store,
        &clock,
        &grant,
        &held_request("complete", "work_item", held_row("pending"), held_lease(), expected()),
    )
    .expect("current completion must succeed");
    let value = record_value(&completed);
    assert_eq!(value["row"]["lease_id"]["reason"], "not_applicable");
    assert_eq!(value["row"]["lease_owner"]["reason"], "not_applicable");
    assert_eq!(value["row"]["entity_revision"], 5);
    assert_eq!(value["row"]["retry_count"], 0, "success is not a failed retry");
    assert_eq!(value["row"]["pipeline_state"], "pending");
    assert_eq!(value["transition"]["failed_generation_charged"], false);
    assert_eq!(value["transition"]["commit_authority_revoked"], false);
    assert_eq!(value["dead_letter"]["reason"], "not_applicable");
    assert_eq!(store.count(), 1);
    for downstream in ["cursor_state", "classifier_result", "seen_ids", "membership"] {
        assert!(
            value.get(downstream).is_none(),
            "completion must not manufacture a {downstream} effect"
        );
    }

    // Every stale fence returns a fault before the store is touched.
    let stale_cases: Vec<(&str, CheckedRecord)> = vec![
        (
            "stale_lease",
            held_request(
                "complete",
                "work_item",
                held_row("pending"),
                held_lease(),
                expected_with("other-token", 4, 2, 7, 11, json!(3)),
            ),
        ),
        (
            "stale_revision",
            held_request(
                "complete",
                "work_item",
                held_row("pending"),
                held_lease(),
                expected_with(HELD_LEASE, 3, 2, 7, 11, json!(3)),
            ),
        ),
        (
            "stale_input_revision",
            held_request(
                "complete",
                "work_item",
                held_row("pending"),
                held_lease(),
                expected_with(HELD_LEASE, 4, 1, 7, 11, json!(3)),
            ),
        ),
        (
            "stale_authority_epoch",
            held_request(
                "complete",
                "work_item",
                held_row("pending"),
                held_lease(),
                expected_with(HELD_LEASE, 4, 2, 8, 11, json!(3)),
            ),
        ),
        (
            "stale_owner_epoch",
            held_request(
                "complete",
                "work_item",
                held_row("pending"),
                held_lease(),
                expected_with(HELD_LEASE, 4, 2, 7, 12, json!(3)),
            ),
        ),
        (
            "stale_session_epoch",
            held_request(
                "complete",
                "work_item",
                held_row("pending"),
                held_lease(),
                expected_with(HELD_LEASE, 4, 2, 7, 11, json!(4)),
            ),
        ),
        (
            "lease_not_held",
            held_request(
                "complete",
                "work_item",
                row("pending"),
                held_lease(),
                expected(),
            ),
        ),
    ];
    for (code, request) in stale_cases {
        let store = RecordingStore::new();
        let before = record_value(&request).clone();
        expect_fault(complete(&store, &clock, &grant, &request), code);
        assert_eq!(store.count(), 0, "{code} must not reach the owner store");
        assert_eq!(
            record_value(&request),
            &before,
            "{code} must leave the input row untouched"
        );
    }

    // An expired deadline is a stale completion: no row and no audit.
    let store = RecordingStore::new();
    let expired_clock = TestClock::new(1030.0);
    expect_fault(
        complete(
            &store,
            &expired_clock,
            &grant,
            &held_request("complete", "work_item", held_row("pending"), held_lease(), expected()),
        ),
        "stale_completion",
    );
    assert_eq!(store.count(), 0);

    // A restarted boot is also stale for completion; old offsets are never
    // compared with the new boot.
    let store = RecordingStore::new();
    let new_boot = TestClock::on_boot(1010.0, "boot-b");
    expect_fault(
        complete(
            &store,
            &new_boot,
            &grant,
            &held_request("complete", "work_item", held_row("pending"), held_lease(), expected()),
        ),
        "cross_boot",
    );
    assert_eq!(store.count(), 0);

    // A completion without its fenced belief is refused outright.
    let store = RecordingStore::new();
    let mut request_value = json!({
        "operation": "complete",
        "entity_type": "work_item",
        "row": held_row("pending"),
        "lease": held_lease(),
    });
    let request = check("audit_log", request_value.take());
    expect_fault(complete(&store, &clock, &grant, &request), "missing_field");
    assert_eq!(store.count(), 0);
}

//! Conformance tests for `crawler_admission`.
//!
//! **[C35] — Back-pressure:** Full data queues cannot block reserved control
//! progress or admitted response commit.

use crawler_admission::{
    Admission, AdmissionConfig, MemoryAdmission, REFERENCE_OVERHEAD_BYTES_PER_ROW,
};
use crawler_authority::{authorize, grant_record, Grant};
use crawler_hashing::{canonical_bytes, digest_bytes};
use crawler_schema::{record_value, validate, CheckedRecord, Fault};
use crawler_store::OwnerStore;
use crawler_time::ClockAuthority;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

fn check(value: Value) -> CheckedRecord {
    validate("audit_log", value).expect("test fixture must validate")
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

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

struct TestClock {
    offset_ms: AtomicU64,
}

impl TestClock {
    fn new() -> Self {
        Self {
            offset_ms: AtomicU64::new(0),
        }
    }

    fn advance(&self, delta_ms: u64) {
        self.offset_ms.fetch_add(delta_ms, Ordering::SeqCst);
    }
}

impl ClockAuthority for TestClock {
    fn now(&self) -> Result<CheckedRecord, Fault> {
        validate(
            "audit_log",
            json!({
                "clock_id": "admission-clock",
                "boot_id": "boot-1",
                "origin": "engine_measured",
                "monotonic_offset_ms": self.offset_ms.load(Ordering::SeqCst),
                "utc_annotation": missing("not_observed"),
            }),
        )
    }
}

/// Owner-local store seam with observable, injectable durability.
#[derive(Default)]
struct RecordingStore {
    transactions: Mutex<Vec<Value>>,
    transact_calls: AtomicU64,
    fail_next: AtomicBool,
    nondurable_next: AtomicBool,
}

impl RecordingStore {
    fn transactions(&self) -> Vec<Value> {
        self.transactions.lock().expect("store lock").clone()
    }

    fn fail_next_transact(&self) {
        self.fail_next.store(true, Ordering::SeqCst);
    }

    fn return_nondurable_once(&self) {
        self.nondurable_next.store(true, Ordering::SeqCst);
    }
}

impl OwnerStore for RecordingStore {
    fn transact(&self, grant: &Grant, transaction: &CheckedRecord) -> Result<CheckedRecord, Fault> {
        self.transact_calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_next.swap(false, Ordering::SeqCst) {
            return Err(Fault {
                code: "storage_unavailable".to_string(),
                detail: "injected durability failure".to_string(),
            });
        }
        let value = record_value(transaction).clone();
        if self.nondurable_next.swap(false, Ordering::SeqCst) {
            return validate("audit_log", json!({"durable": false, "transaction": value}));
        }
        let owner_domain = record_value(grant_record(grant))["owner_domain"].clone();
        let sequence = {
            let mut transactions = self.transactions.lock().expect("store lock");
            transactions.push(value.clone());
            transactions.len() as u64
        };
        validate(
            "audit_log",
            json!({
                "durable": true,
                "journal_sequence": sequence,
                "owner_domain": owner_domain,
                "transaction": value,
            }),
        )
    }

    fn read(&self, _grant: &Grant, query: &CheckedRecord) -> Result<CheckedRecord, Fault> {
        validate(
            "audit_log",
            json!({"rows": [], "query": record_value(query).clone()}),
        )
    }
}

fn registration_fixture() -> CheckedRecord {
    check(json!({
        "registration_id": "admission-channel",
        "principals": [{
            "principal_id": "admission-owner",
            "verbs": ["Start"],
            "connectors": ["jobs-connector"],
            "control": true,
            "owner_domain": "crawler",
            "restricted_access": false,
        }],
    }))
}

fn owner_grant() -> Grant {
    let registration = registration_fixture();
    let binding = digest_bytes(
        &canonical_bytes(&registration).expect("registration canonical bytes must exist"),
    );
    let principal = check(json!({
        "principal_id": "admission-owner",
        "registration_digest": binding,
    }));
    let request = check(json!({"verb": "Start", "connector": "jobs-connector"}));
    authorize(&principal, &request, &registration).expect("owner grant must issue")
}

fn response_request(id: &str, rows: u64, bytes: u64) -> CheckedRecord {
    check(json!({
        "request_id": id,
        "target": "jobs",
        "max_packet_rows": rows,
        "max_packet_bytes": bytes,
    }))
}

fn control_scope(id: &str) -> CheckedRecord {
    check(json!({"scope_id": id, "target": "jobs"}))
}

fn page_scope(id: &str) -> CheckedRecord {
    check(json!({
        "scope_id": id,
        "target": "jobs",
        "page_rows": 1,
        "page_bytes": 100,
    }))
}

fn admission_with(
    config: AdmissionConfig,
    clock: Arc<TestClock>,
    store: Arc<RecordingStore>,
) -> MemoryAdmission {
    MemoryAdmission::new(config, clock, store, owner_grant()).expect("admission must build")
}

fn tight_config() -> AdmissionConfig {
    AdmissionConfig {
        queue_rows: 2,
        queue_bytes: 10_000,
        staging_bytes: 10_000,
        observation_bytes: 10_000,
        response_bound_bytes: 10_000,
        stream_buffer_bytes: 100,
        control_slots: 3,
        control_cpu_units: 3,
        control_cpu_per_command: 1,
        cold_bootstrap_bytes: 1_000,
        bootstrap_bytes_per_command: 100,
        ..AdmissionConfig::default()
    }
}

// ---------------------------------------------------------------------------
// C35 tests
// ---------------------------------------------------------------------------

#[test]
fn c35_credit_before_wire_reserves_rows_bytes_staging_before_dispatch() {
    let clock = Arc::new(TestClock::new());
    let store = Arc::new(RecordingStore::default());
    let admission = admission_with(AdmissionConfig::default(), clock, store);

    let credit = admission
        .reserve_response(&response_request("req-1", 3, 4_096))
        .expect("reservation must be admitted before any output-producing request");

    let reservation = record_value(&credit.reservation).clone();
    assert_no_bare_nulls(&reservation);
    assert_eq!(reservation["kind"], json!("response"));
    assert_eq!(reservation["caller_id"], json!("req-1"));
    assert_eq!(reservation["target"], json!("jobs"));
    assert_eq!(reservation["queue_rows"], json!(3));
    assert_eq!(reservation["queue_bytes"], json!(4_096));
    assert_eq!(
        reservation["staging_bytes"],
        json!(4_096 + 3 * REFERENCE_OVERHEAD_BYTES_PER_ROW)
    );
    assert_eq!(reservation["observation_bytes"], json!(4_096));
    assert_eq!(reservation["response_bound_bytes"], json!(64 * 1024 * 1024));
    assert_eq!(
        reservation["reserved_at"]["clock_id"],
        json!("admission-clock")
    );
    assert!(
        reservation["deadline"]["monotonic_offset_ms"]
            .as_f64()
            .expect("deadline offset")
            > reservation["reserved_at"]["monotonic_offset_ms"]
                .as_f64()
                .expect("reserved offset")
    );
    assert!(!admission
        .reservation_expired(&credit.reservation)
        .expect("deadline must be comparable on the registered clock"));

    let stats = admission.stats().expect("stats");
    assert_eq!(stats.rows_used, 3);
    assert_eq!(stats.bytes_used, 4_096);
    assert!(stats.staging_used > 4_096);
    assert_eq!(stats.observation_used, 4_096);

    drop(credit);
    let stats = admission.stats().expect("stats");
    assert_eq!(stats.rows_used, 0);
    assert_eq!(stats.bytes_used, 0);
    assert_eq!(stats.staging_used, 0);
    assert_eq!(stats.observation_used, 0);
    assert_eq!(
        stats.cancelled_total, 1,
        "unsettled credit is cancelled, not lost"
    );
}

#[test]
fn c35_full_data_queue_does_not_block_control_progress() {
    let clock = Arc::new(TestClock::new());
    let store = Arc::new(RecordingStore::default());
    let admission = admission_with(tight_config(), clock, store);

    let first = admission
        .reserve_response(&response_request("fill-1", 1, 100))
        .expect("first reservation");
    let second = admission
        .reserve_response(&response_request("fill-2", 1, 100))
        .expect("second reservation");
    let error = admission
        .reserve_response(&response_request("fill-3", 1, 100))
        .expect_err("full data queue must pause data admission");
    assert_eq!(error.code, "backpressure_rows");

    let scope = control_scope("control-1");
    let control_one = admission.reserve_control(&scope).expect("control slot 1");
    let control_two = admission.reserve_control(&scope).expect("control slot 2");
    let control_three = admission.reserve_control(&scope).expect("control slot 3");
    let error = admission
        .reserve_control(&scope)
        .expect_err("control capacity is finite");
    assert_eq!(error.code, "control_capacity_exhausted");

    // Control progress is independent of the full data queue.
    drop(control_one);
    let control_four = admission
        .reserve_control(&scope)
        .expect("dropping a control credit restores control capacity");
    assert_eq!(
        admission.stats().expect("stats").rows_used,
        2,
        "control credits never consume data rows"
    );

    drop(control_two);
    let control_page = admission
        .reserve_page(&page_scope("control-page"), true)
        .expect("control page is admitted while data capacity is full");
    let error = admission
        .reserve_page(&page_scope("data-page"), false)
        .expect_err("data page cannot bypass data back-pressure");
    assert_eq!(error.code, "backpressure_rows");

    let stats = admission.stats().expect("stats");
    assert_eq!(stats.rows_used, 2);
    assert!(stats.control_slots_used > 0);
    assert!(stats.control_cpu_used > 0);
    assert!(stats.cold_bootstrap_used > 0);

    drop(control_three);
    drop(control_four);
    drop(control_page);
    drop(first);
    drop(second);
}

#[test]
fn c35_admitted_response_commits_while_data_queue_is_full() {
    let clock = Arc::new(TestClock::new());
    let store = Arc::new(RecordingStore::default());
    let admission = admission_with(tight_config(), clock, store.clone());

    let admitted = admission
        .reserve_response(&response_request("admitted", 1, 100))
        .expect("pre-admitted response");
    let filler = admission
        .reserve_response(&response_request("filler", 1, 100))
        .expect("filler response");
    let error = admission
        .reserve_response(&response_request("blocked", 1, 100))
        .expect_err("data queue is full");
    assert_eq!(error.code, "backpressure_rows");
    assert_eq!(
        admission.stats().expect("stats").rows_used,
        2,
        "queue must be full before the commit"
    );
    assert!(store.transactions().is_empty());

    let outcome = check(json!({"decoded_bytes": 90}));
    admission
        .settle_response(admitted, &outcome)
        .expect("admitted response must commit its durable boundary without new queue capacity");

    let transactions = store.transactions();
    assert_eq!(transactions.len(), 1, "one owner-local durable effect");
    assert_eq!(transactions[0]["operation"], json!("settle_response"));
    assert_eq!(
        transactions[0]["reservation"]["max_packet_bytes"],
        json!(100)
    );
    assert_eq!(transactions[0]["outcome"]["decoded_bytes"], json!(90));
    assert!(transactions[0]["replay"]["outcome"].is_object());
    assert!(transactions[0]["idempotency_key"].is_string());

    let stats = admission.stats().expect("stats");
    assert_eq!(stats.committed_total, 1);
    assert_eq!(
        stats.rows_used, 1,
        "only the remaining in-flight credit stays reserved"
    );

    admission
        .settle_response(filler, &check(json!({"decoded_bytes": 100})))
        .expect("second admitted response commits");
    assert_eq!(admission.stats().expect("stats").rows_used, 0);
    assert_eq!(store.transactions().len(), 2);
}

#[test]
fn c35_oversized_decoded_response_is_rejected_without_raising_bound() {
    let mut config = tight_config();
    config.response_bound_bytes = 64;
    config.stream_buffer_bytes = 100;
    let clock = Arc::new(TestClock::new());
    let store = Arc::new(RecordingStore::default());
    let admission = admission_with(config, clock, store.clone());

    let credit = admission
        .reserve_response(&response_request("bounded", 1, 64))
        .expect("packet equal to the bound is admissible");
    let error = admission
        .settle_response(credit, &check(json!({"decoded_bytes": 65})))
        .expect_err("oversized decoded response must be rejected while streaming");
    assert_eq!(error.code, "response_limit_exceeded");
    assert!(
        store.transactions().is_empty(),
        "no durable boundary for a rejected response"
    );
    assert_eq!(
        admission.config().response_bound_bytes,
        64,
        "bounds are never silently raised"
    );
    let stats = admission.stats().expect("stats");
    assert_eq!(stats.committed_total, 0);
    assert_eq!(stats.rows_used, 0, "rejected work releases its reservation");
    assert!(stats.rejected_total >= 1);
    let evidence = admission.rejections().expect("rejection evidence");
    assert_eq!(
        record_value(evidence.last().expect("evidence"))["code"],
        json!("response_limit_exceeded")
    );

    let error = admission
        .reserve_response(&response_request("too-large", 1, 65))
        .expect_err("request above the response bound cannot be reserved");
    assert_eq!(error.code, "response_limit_exceeded");
    assert!(store.transactions().is_empty());

    let credit = admission
        .reserve_response(&response_request("exact", 1, 64))
        .expect("exact-bound reservation");
    admission
        .settle_response(credit, &check(json!({"decoded_bytes": 64})))
        .expect("exact-bound response commits");
    assert_eq!(store.transactions().len(), 1);
}

#[test]
fn c35_row_and_byte_capacity_pause_admission_and_reserved_work_drains() {
    let mut config = tight_config();
    config.queue_rows = 2;
    config.queue_bytes = 150;
    let clock = Arc::new(TestClock::new());
    let store = Arc::new(RecordingStore::default());
    let admission = admission_with(config, clock, store);

    let first = admission
        .reserve_response(&response_request("row-byte-1", 1, 100))
        .expect("100 of 150 bytes fit");
    let error = admission
        .reserve_response(&response_request("row-byte-2", 1, 100))
        .expect_err("byte capacity pauses data admission");
    assert_eq!(error.code, "backpressure_bytes");

    let third = admission
        .reserve_response(&response_request("row-byte-3", 1, 50))
        .expect("remaining 50 bytes fit");
    let error = admission
        .reserve_response(&response_request("row-byte-4", 1, 1))
        .expect_err("row capacity pauses data admission");
    assert_eq!(error.code, "backpressure_rows");
    let error = admission
        .reserve_response(&response_request("row-byte-huge", 1, 151))
        .expect_err("a single request above the byte capacity never fits");
    assert_eq!(error.code, "request_exceeds_capacity");

    admission
        .settle_response(first, &check(json!({"decoded_bytes": 100})))
        .expect("reserved in-flight work drains by committing");
    assert_eq!(admission.stats().expect("stats").bytes_used, 50);
    let fourth = admission
        .reserve_response(&response_request("row-byte-4", 1, 1))
        .expect("drained capacity is reusable");
    assert_eq!(admission.stats().expect("stats").rows_used, 2);

    drop(third);
    drop(fourth);
    assert_eq!(admission.stats().expect("stats").bytes_used, 0);
}

#[test]
fn c35_accepted_queued_task_consumes_its_observation_budget() {
    let mut config = tight_config();
    config.queue_rows = 10;
    config.queue_bytes = 10_000;
    config.observation_bytes = 100;
    config.stream_buffer_bytes = 100;
    config.response_bound_bytes = 64;
    config.staging_bytes = 10_000;
    let clock = Arc::new(TestClock::new());
    let store = Arc::new(RecordingStore::default());
    let admission = admission_with(config, clock, store);

    let first = admission
        .reserve_response(&response_request("observation-1", 1, 64))
        .expect("first task consumes its observation budget");
    let error = admission
        .reserve_response(&response_request("observation-2", 1, 64))
        .expect_err("observation buffering is bounded");
    assert_eq!(error.code, "backpressure_observation");

    admission
        .settle_response(first, &check(json!({"decoded_bytes": 64})))
        .expect("settling drains the observation budget");
    let second = admission
        .reserve_response(&response_request("observation-2", 1, 64))
        .expect("freed observation budget is reusable");
    drop(second);
}

#[test]
fn c35_saturation_quiesces_then_resumes_below_watermark_with_fresh_generation() {
    let mut config = tight_config();
    config.saturation_grace_ms = 5_000;
    let clock = Arc::new(TestClock::new());
    let store = Arc::new(RecordingStore::default());
    let admission = admission_with(config, clock.clone(), store);

    let first = admission
        .reserve_response(&response_request("saturate-1", 1, 100))
        .expect("first credit");
    let second = admission
        .reserve_response(&response_request("saturate-2", 1, 100))
        .expect("second credit fills the queue");

    admission.poll_saturation().expect("poll");
    let stats = admission.stats().expect("stats");
    assert!(!stats.quiescent);
    assert_eq!(stats.saturated_since_ms, Some(0.0));

    clock.advance(4_999);
    admission.poll_saturation().expect("poll");
    assert!(!admission.stats().expect("stats").quiescent);

    clock.advance(2);
    admission.poll_saturation().expect("poll");
    let stats = admission.stats().expect("stats");
    assert!(
        stats.quiescent,
        "deliberate quiescence after the 5,000 ms grace"
    );
    assert_eq!(stats.generation, 0);

    let error = admission
        .reserve_response(&response_request("during-quiescence", 1, 100))
        .expect_err("data admission is paused during deliberate quiescence");
    assert_eq!(error.code, "quiescent");

    admission
        .settle_response(first, &check(json!({"decoded_bytes": 100})))
        .expect("admitted response still commits during quiescence");

    let stats = admission.stats().expect("stats");
    assert!(
        !stats.quiescent,
        "resume requires occupancy below the 0.8 watermark"
    );
    assert_eq!(
        stats.generation, 1,
        "resume retires the saturated generation"
    );
    let resumed = admission
        .reserve_response(&response_request("resumed", 1, 100))
        .expect("resumed generation admits new data work");

    let elapsed_deadline = admitted_deadline(&resumed);
    clock.advance(elapsed_deadline + 1);
    assert!(
        admission
            .reservation_expired(&resumed.reservation)
            .expect("deadline comparable"),
        "finite local call bound is enforced on the registered clock"
    );
    drop(second);
    drop(resumed);
}

fn admitted_deadline(credit: &crawler_admission::ResponseCredit) -> u64 {
    let reservation = record_value(&credit.reservation);
    let deadline = reservation["deadline"]["monotonic_offset_ms"]
        .as_f64()
        .expect("deadline offset");
    let reserved_at = reservation["reserved_at"]["monotonic_offset_ms"]
        .as_f64()
        .expect("reserved offset");
    (deadline - reserved_at) as u64
}

#[test]
fn c35_rejected_work_is_recorded_not_silently_lost() {
    let mut config = tight_config();
    config.queue_rows = 1;
    config.rejection_evidence_bound = 2;
    let clock = Arc::new(TestClock::new());
    let store = Arc::new(RecordingStore::default());
    let admission = admission_with(config, clock, store);

    let held = admission
        .reserve_response(&response_request("held", 1, 100))
        .expect("held reservation fills the single row");

    for id in ["rejected-1", "rejected-2", "rejected-3"] {
        let error = admission
            .reserve_response(&response_request(id, 1, 100))
            .expect_err("full queue rejects data work");
        assert_eq!(error.code, "backpressure_rows");
    }

    let stats = admission.stats().expect("stats");
    assert_eq!(
        stats.rejected_total, 3,
        "total rejection count is never silent"
    );

    let evidence = admission.rejections().expect("rejection evidence");
    assert_eq!(evidence.len(), 2, "evidence retention is bounded");
    for record in &evidence {
        let value = record_value(record);
        assert_no_bare_nulls(value);
        assert_eq!(value["kind"], json!("admission_rejection"));
        assert_eq!(value["reservation_kind"], json!("response"));
        assert_eq!(value["code"], json!("backpressure_rows"));
        assert!(value["rejected_at"]["clock_id"].is_string());
    }
    assert_eq!(
        record_value(evidence.last().expect("newest evidence"))["subject"]["request_id"],
        json!("rejected-3"),
        "the newest rejected work is retained"
    );

    drop(held);
    assert_eq!(admission.stats().expect("stats").rows_used, 0);
}

#[test]
fn c35_acknowledgement_requires_one_durable_owner_local_commit() {
    let clock = Arc::new(TestClock::new());
    let store = Arc::new(RecordingStore::default());
    let admission = admission_with(tight_config(), clock, store.clone());

    let credit = admission
        .reserve_response(&response_request("durability-1", 1, 100))
        .expect("credit");
    store.fail_next_transact();
    let error = admission
        .settle_response(credit, &check(json!({"decoded_bytes": 90})))
        .expect_err("no acknowledgement before durability");
    assert_eq!(error.code, "storage_unavailable");
    assert!(store.transactions().is_empty());
    let stats = admission.stats().expect("stats");
    assert_eq!(stats.committed_total, 0);
    assert_eq!(
        stats.rows_used, 0,
        "failed settlement releases its reservation"
    );
    assert!(stats.rejected_total >= 1);

    let credit = admission
        .reserve_response(&response_request("durability-2", 1, 100))
        .expect("credit");
    store.return_nondurable_once();
    let error = admission
        .settle_response(credit, &check(json!({"decoded_bytes": 90})))
        .expect_err("a non-durable receipt cannot acknowledge the boundary");
    assert_eq!(error.code, "not_durable");
    assert!(store.transactions().is_empty());
    assert_eq!(admission.stats().expect("stats").committed_total, 0);

    let credit = admission
        .reserve_response(&response_request("durability-3", 1, 100))
        .expect("credit");
    admission
        .settle_response(credit, &check(json!({"decoded_bytes": 90})))
        .expect("durable commit acknowledges the boundary");
    assert_eq!(store.transactions().len(), 1);
    assert_eq!(admission.stats().expect("stats").committed_total, 1);
}

#[test]
fn c35_credit_is_fenced_to_its_owner_local_ledger() {
    let clock = Arc::new(TestClock::new());
    let store = Arc::new(RecordingStore::default());
    let first = admission_with(tight_config(), Arc::clone(&clock), Arc::clone(&store));
    let second = admission_with(tight_config(), clock, store.clone());

    let credit = second
        .reserve_response(&response_request("foreign", 1, 100))
        .expect("second owner admits its own response");
    let error = first
        .settle_response(credit, &check(json!({"decoded_bytes": 90})))
        .expect_err("a credit cannot be settled on another owner's ledger");
    assert_eq!(error.code, "foreign_credit");
    assert!(store.transactions().is_empty());
    assert_eq!(second.stats().expect("stats").rows_used, 0);

    let credit = second
        .reserve_response(&response_request("owned", 1, 100))
        .expect("second owner admits again");
    second
        .settle_response(credit, &check(json!({"decoded_bytes": 90})))
        .expect("owning ledger commits");
    assert_eq!(store.transactions().len(), 1);
}

#[test]
fn c35_concurrent_data_pressure_cannot_block_control_or_admitted_commit() {
    let mut config = tight_config();
    config.queue_rows = 1;
    config.control_slots = 4;
    config.control_cpu_units = 4;
    let clock = Arc::new(TestClock::new());
    let store = Arc::new(RecordingStore::default());
    let admission = Arc::new(admission_with(config, clock, store.clone()));

    let admitted = admission
        .reserve_response(&response_request("concurrent-admitted", 1, 100))
        .expect("pre-admitted response");
    assert_eq!(admission.stats().expect("stats").rows_used, 1);

    let stop = Arc::new(AtomicBool::new(false));
    let mut workers = Vec::new();
    for worker in 0..4 {
        let admission = Arc::clone(&admission);
        let stop = Arc::clone(&stop);
        workers.push(thread::spawn(move || {
            let request = response_request(&format!("pressure-{worker}"), 1, 100);
            while !stop.load(Ordering::SeqCst) {
                let _ = admission.reserve_response(&request);
                thread::yield_now();
            }
        }));
    }

    admission
        .settle_response(admitted, &check(json!({"decoded_bytes": 100})))
        .expect("admitted response commits while data pressure threads run");

    let scope = control_scope("concurrent-control");
    for _ in 0..100 {
        let credit = admission
            .reserve_control(&scope)
            .expect("control progress is never blocked by full data queues");
        drop(credit);
    }

    stop.store(true, Ordering::SeqCst);
    for worker in workers {
        worker.join().expect("pressure worker");
    }

    assert_eq!(store.transactions().len(), 1);
    let stats = admission.stats().expect("stats");
    assert_eq!(stats.committed_total, 1);
    assert_eq!(stats.control_slots_used, 0);
    assert!(
        stats.rejected_total > 0,
        "pressure was rejected, not silently absorbed"
    );
}

//! Conformance tests for `crawler_sessions`.
//!
//! * **[C32]** Sessions | None topology writes zero rows; stateful
//!   serialization and current epoch enforced.
//! * **[C33]** Rotating cookies | Redirect/solver mutations serialized; cold
//!   crash recovery; independent A/B shards.
//!
//! The tests use the real `crawler_authority` grant seam, the real
//! `crawler_time` authority clock, the real `crawler_admission` credits, the
//! real `crawler_readonly` acquisition gate, and the real `crawler_store`
//! in-memory owner journal (with the real in-memory artifact store). Session
//! effects are therefore read back from the durable journal, not from test
//! bookkeeping; the cookie jar is read from the live `HttpClient` published in
//! `LiveSession`.

use crawler_admission::{Admission, AdmissionConfig, ControlCredit, MemoryAdmission, ResponseCredit};
use crawler_artifacts::MemoryArtifactStore;
use crawler_authority::{authorize_producer, grant_record, Grant};
use crawler_hashing::{canonical_bytes, digest_bytes};
use crawler_readonly::{authorize_acquisition, ReadOnlyRequest};
use crawler_schema::{record_schema, record_value, validate, CheckedRecord, Fault};
use crawler_sessions::{LiveSession, MemorySessionManager, SessionManager};
use crawler_store::{MemoryOwnerStore, OwnerStore};
use crawler_time::ClockAuthority;
use serde_json::{json, Map, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use url::Url;

const JOURNAL: &str = "journal-sessions";
const CLOCK_ID: &str = "session-clk";
const BOOT_ID: &str = "boot-session";
const TARGET: &str = "illinois";
const RUN_ID: &str = "run-1";
const ORIGIN: &str = "https://jobs.example";
const OWNER_DOMAIN: &str = "crawler_ingest";
const WORKER: &str = "session-worker";

fn check(schema: &str, value: Value) -> CheckedRecord {
    validate(schema, value).expect("test fixture must validate")
}

fn missing(reason: &str) -> Value {
    json!({"value": Value::Null, "reason": reason})
}

fn merge(base: Value, extra: Value) -> Value {
    let mut base = base.as_object().expect("base must be an object").clone();
    if let Value::Object(overlay) = extra {
        for (key, value) in overlay {
            base.insert(key, value);
        }
    }
    Value::Object(base)
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

/// Authority clock whose monotonic offset the test can advance.
struct TestClock {
    offset_ms: Mutex<f64>,
}

impl TestClock {
    fn new(offset_ms: f64) -> Self {
        Self {
            offset_ms: Mutex::new(offset_ms),
        }
    }

    fn advance(&self, delta_ms: f64) {
        let mut offset = self.offset_ms.lock().expect("clock lock");
        *offset += delta_ms;
    }
}

impl ClockAuthority for TestClock {
    fn now(&self) -> Result<CheckedRecord, Fault> {
        let offset = *self.offset_ms.lock().expect("clock lock");
        validate("audit_log", point_on(CLOCK_ID, BOOT_ID, offset))
    }
}

fn binding_of(record: &CheckedRecord) -> String {
    digest_bytes(&canonical_bytes(record).expect("canonical bytes must exist"))
}

fn manifest_fixture() -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "manifest_id": "manifest-sessions",
            "producer_registry": [
                {
                    "producer_id": "ingest",
                    "owner_domain": OWNER_DOMAIN,
                    "role": "external_input",
                    "provenance": "server",
                    "assertion_kind": "claim",
                },
                {
                    "producer_id": WORKER,
                    "owner_domain": OWNER_DOMAIN,
                    "role": "lifecycle_observation",
                    "provenance": "server",
                    "assertion_kind": "observation",
                },
            ],
            "event_registry": [
                {"event_kind": "manifest_admitted", "permitted_provenance": ["server"]},
                {"event_kind": "session_established", "permitted_provenance": ["server"]},
                {"event_kind": "session_recovered", "permitted_provenance": ["server"]},
                {"event_kind": "session_boundary_committed", "permitted_provenance": ["server"]},
                {"event_kind": "session_expired", "permitted_provenance": ["server"]},
                {"event_kind": "session_retired", "permitted_provenance": ["server"]},
            ],
        }),
    )
}

fn principal(manifest: &CheckedRecord, producer_id: &str) -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "producer_id": producer_id,
            "manifest_digest": binding_of(manifest),
        }),
    )
}

fn grant_for(manifest: &CheckedRecord, producer_id: &str, event_kind: &str) -> Grant {
    let principal = principal(manifest, producer_id);
    let submission = check("audit_log", json!({"event_kind": event_kind}));
    authorize_producer(&principal, &submission, manifest).expect("producer grant must issue")
}

fn admission_tx(manifest: &CheckedRecord) -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "operation": "admit_manifest",
            "journal_id": JOURNAL,
            "run_id": RUN_ID,
            "manifest": record_value(manifest).clone(),
            "principal": {
                "producer_id": "ingest",
                "manifest_digest": binding_of(manifest),
            },
        }),
    )
}

struct Harness {
    manifest: CheckedRecord,
    clock: Arc<TestClock>,
    store: Arc<MemoryOwnerStore>,
    admission: MemoryAdmission,
    credit_seq: AtomicU64,
}

impl Harness {
    fn new() -> Self {
        let manifest = manifest_fixture();
        let clock = Arc::new(TestClock::new(1_000.0));
        let artifacts = Arc::new(MemoryArtifactStore::new());
        let store = Arc::new(
            MemoryOwnerStore::new(manifest_fixture(), clock.clone(), artifacts)
                .expect("owner store must admit its manifest"),
        );
        let admit_grant = grant_for(&manifest, "ingest", "manifest_admitted");
        store
            .transact(&admit_grant, &admission_tx(&manifest))
            .expect("journal must admit its manifest");
        let admission = MemoryAdmission::new(
            AdmissionConfig::default(),
            clock.clone(),
            store.clone(),
            grant_for(&manifest, WORKER, "session_established"),
        )
        .expect("admission must be configured");
        Self {
            manifest,
            clock,
            store,
            admission,
            credit_seq: AtomicU64::new(0),
        }
    }

    fn manager(&self) -> MemorySessionManager {
        MemorySessionManager::new(self.store.clone(), self.clock.clone())
    }

    fn grant(&self) -> Grant {
        grant_for(&self.manifest, WORKER, "session_established")
    }

    fn next_credit_id(&self) -> u64 {
        self.credit_seq.fetch_add(1, Ordering::SeqCst) + 1
    }

    fn control(&self, target: &str) -> ControlCredit {
        let scope = check(
            "audit_log",
            json!({
                "scope_id": format!("bootstrap-{}", self.next_credit_id()),
                "target": target,
            }),
        );
        self.admission
            .reserve_control(&scope)
            .expect("control credit must reserve")
    }

    fn response(&self, target: &str) -> ResponseCredit {
        let request = check(
            "audit_log",
            json!({
                "request_id": format!("exchange-{}", self.next_credit_id()),
                "target": target,
                "max_packet_rows": 4,
                "max_packet_bytes": 4096,
            }),
        );
        self.admission
            .reserve_response(&request)
            .expect("response credit must reserve")
    }

    fn events(&self, grant: &Grant) -> Vec<Value> {
        let query = check(
            "audit_log",
            json!({"query": "journal", "journal_id": JOURNAL}),
        );
        let view = self
            .store
            .read(grant, &query)
            .expect("journal view must be readable");
        record_value(&view)["events"]
            .as_array()
            .cloned()
            .expect("journal view carries an events array")
    }
}

fn expect_fault<T>(result: Result<T, Fault>, code: &str) -> Fault {
    match result {
        Ok(_) => panic!("expected fault {code:?}, got a successful result"),
        Err(error) => {
            assert_eq!(error.code, code, "fault detail: {}", error.detail);
            error
        }
    }
}

fn event_kind(event: &Value) -> &str {
    event["event_kind"].as_str().unwrap_or("")
}

fn session_row_of(event: &Value) -> Option<&Value> {
    event
        .get("payload")?
        .get("data")?
        .get("session_state")
}

fn boundary_of(event: &Value) -> Option<&Value> {
    event
        .get("payload")?
        .get("data")?
        .get("session_boundary")
}

fn event_data(event: &Value) -> &Value {
    event
        .get("payload")
        .and_then(|payload| payload.get("data"))
        .expect("journal event carries payload data")
}

/// Complete `establish` request. `topology` is omitted entirely when `None`,
/// exercising slot-derived topology.
fn establish_request(topology: Option<&str>, shard: &str, extra: Value) -> CheckedRecord {
    let mut base = json!({
        "target": TARGET,
        "run_id": RUN_ID,
        "phase": "A",
        "shard_id": shard,
        "journal_id": JOURNAL,
        "worker_identity": "worker-1",
        "owner_epoch": 1,
        "preset": "chrome_148_linux",
        "profile_ref": "profile:chrome_148_linux",
    });
    if let Some(topology) = topology {
        base["session_topology"] = Value::String(topology.to_string());
    }
    check("audit_log", merge(base, extra))
}

fn worker_establish(topology: Option<&str>, shard: &str) -> CheckedRecord {
    establish_request(topology, shard, json!({}))
}

/// Endpoint/redirect reference exercised under `grant` (read-only evidence).
fn endpoint(grant: &Grant, url: &str) -> CheckedRecord {
    let mut base = Map::new();
    base.insert(
        "grant_digest".to_string(),
        Value::String(binding_of(grant_record(grant))),
    );
    base.insert(
        "digest".to_string(),
        Value::String("0123456789abcdef".repeat(4)),
    );
    base.insert("access".to_string(), json!("public"));
    base.insert("owner_domain".to_string(), json!(OWNER_DOMAIN));
    base.insert("provenance".to_string(), json!("origin"));
    base.insert("url".to_string(), Value::String(url.to_string()));
    check("audit_log", Value::Object(base))
}

fn task_request(shard: &str) -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "record_type": "connector_task",
            "task_id": "task-1",
            "task_type": "discover_jobs",
            "goal": "discover listings",
            "effect_policy": "read_only",
            "permitted_origins": [ORIGIN],
            "permitted_interfaces": ["read_only_acquisition"],
            "target": TARGET,
            "run_id": RUN_ID,
            "phase": "A",
            "shard_id": shard,
        }),
    )
}

/// Authorized read-only acquisition for one shard.
fn read_only(grant: &Grant, url: &str, shard: &str) -> ReadOnlyRequest {
    authorize_acquisition(grant, &endpoint(grant, url), &task_request(shard))
        .expect("read-only acquisition must be authorized")
}

/// Boundary receipt for `exchange`, overlaid with hop evidence.
fn boundary_receipt(exchange: &CheckedRecord, overlay: Value) -> CheckedRecord {
    let mut base = record_value(exchange)
        .as_object()
        .expect("exchange receipt is an object")
        .clone();
    base.insert(
        "record_type".to_string(),
        json!("session_exchange_receipt"),
    );
    check("audit_log", merge(Value::Object(base), overlay))
}

fn rotation(source: &str, url: &str, cookies: &[&str]) -> Value {
    json!({
        "source": source,
        "url": url,
        "cookies": cookies,
    })
}

fn cookie_count(session: &LiveSession) -> usize {
    session
        .client
        .cookies()
        .try_lock()
        .expect("cookie jar must be available")
        .cookie_count()
}

fn cookie_header(session: &LiveSession, url: &str) -> String {
    let url = Url::parse(url).expect("url must parse");
    session
        .client
        .cookies()
        .try_lock()
        .expect("cookie jar must be available")
        .cookies_for(&url)
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// C32: none topology writes zero rows
// ---------------------------------------------------------------------------

#[test]
fn c32_none_topology_writes_zero_session_rows() {
    let harness = Harness::new();
    let manager = harness.manager();
    let grant = harness.grant();
    let before = harness.events(&grant).len();

    let none_request = worker_establish(Some("none"), "shard-none");
    let error = expect_fault(
        manager.establish(&grant, &none_request, &harness.control(TARGET)),
        "topology_none",
    );
    assert!(
        error.detail.contains("no session_state row"),
        "the none-topology fault must state that no row is written: {}",
        error.detail
    );

    // Slot-derived topology (MN-A) is equally none: no row, no slot.
    let slot_request = worker_establish(None, "shard-none");
    let slot_request = merge(record_value(&slot_request).clone(), json!({"slot": "MN-A"}));
    let slot_request = check("audit_log", slot_request);
    expect_fault(
        manager.establish(&grant, &slot_request, &harness.control(TARGET)),
        "topology_none",
    );

    let after = harness.events(&grant);
    assert_eq!(
        after.len(),
        before,
        "a none-topology slot must write zero journal rows"
    );
    assert!(
        after.iter().all(|event| session_row_of(event).is_none()),
        "no session_state row may exist for a none-topology slot"
    );

    // Stateless acquisition never routes through the session manager, so the
    // same identity has no live generation to exchange under.
    let exchange = manager.exchange(
        &grant,
        &read_only(&grant, "https://jobs.example/list", "shard-none"),
        &harness.response(TARGET),
    );
    expect_fault(exchange, "no_live_session");
}

// ---------------------------------------------------------------------------
// C32: stateful establishment writes exactly one current generation
// ---------------------------------------------------------------------------

#[test]
fn c32_stateful_establish_writes_one_current_generation() {
    let harness = Harness::new();
    let manager = harness.manager();
    let grant = harness.grant();
    let before = harness.events(&grant).len();

    let request = worker_establish(Some("per_worker"), "shard-wi-b");
    let session = manager
        .establish(&grant, &request, &harness.control(TARGET))
        .expect("per-worker session must establish");
    assert_eq!(record_schema(&session.generation), "session_state");
    assert_eq!(record_value(&session.generation)["status"], json!("active"));
    assert_eq!(record_value(&session.generation)["session_epoch"], json!(1));
    assert_eq!(
        record_value(&session.generation)["shard_topology"],
        json!("per_worker")
    );
    assert_eq!(
        record_value(&session.generation)["shard_id"],
        json!("shard-wi-b")
    );
    assert_eq!(
        record_value(&session.generation)["verified_session_birth"]["reason"],
        json!("not_observed"),
        "a fresh client is not a verified session birth"
    );

    let events = harness.events(&grant);
    assert_eq!(
        events.len(),
        before + 1,
        "establishment writes exactly one durable session row"
    );
    let established = events.last().expect("one established event");
    assert_eq!(event_kind(established), "session_established");
    let row = session_row_of(established).expect("established event carries a session_state row");
    assert_eq!(row["status"], json!("active"));
    assert_eq!(row["session_epoch"], json!(1));
    assert_eq!(row["cookie_generation"], json!(0));
    assert_eq!(row["last_committed_request_sequence"], json!(0));
    assert_eq!(
        event_data(established)["recovered_from_crash"],
        json!(false)
    );

    // One generation has exactly one current owner.
    let error = expect_fault(
        manager.establish(&grant, &request, &harness.control(TARGET)),
        "session_exists",
    );
    assert!(
        error.detail.contains("exactly one current owner"),
        "second establishment must be refused as a duplicate owner: {}",
        error.detail
    );
    assert_eq!(
        harness.events(&grant).len(),
        before + 1,
        "the refused duplicate writes no additional row"
    );
}

// ---------------------------------------------------------------------------
// C32: stateful serialization — one in-flight request per session
// ---------------------------------------------------------------------------

#[test]
fn c32_stateful_serialization_allows_one_inflight_request() {
    let harness = Harness::new();
    let manager = harness.manager();
    let grant = harness.grant();

    let session = manager
        .establish(
            &grant,
            &worker_establish(Some("per_worker"), "shard-wi-b"),
            &harness.control(TARGET),
        )
        .expect("session must establish");
    assert_eq!(cookie_count(&session), 0);

    let first = manager
        .exchange(
            &grant,
            &read_only(&grant, "https://jobs.example/list?page=1", "shard-wi-b"),
            &harness.response(TARGET),
        )
        .expect("first exchange must prepare");
    let first_value = record_value(&first);
    assert_eq!(first_value["request_sequence"], json!(1));
    assert_eq!(first_value["serialized"], json!(true));
    assert_eq!(first_value["max_inflight_per_session"], json!(1));
    assert_eq!(first_value["session_epoch"], json!(1));
    let credit_id = first_value["credit_id"]
        .as_str()
        .expect("receipt names its response credit")
        .to_string();

    // A second stateful request is refused while the first is in flight.
    expect_fault(
        manager.exchange(
            &grant,
            &read_only(&grant, "https://jobs.example/list?page=2", "shard-wi-b"),
            &harness.response(TARGET),
        ),
        "session_busy",
    );

    let receipt = boundary_receipt(&first, json!({}));
    manager
        .commit_boundary(&grant, &receipt)
        .expect("the prepared boundary must commit");
    assert!(
        !credit_id.is_empty(),
        "the committed boundary names the response credit"
    );
    let committed = harness.events(&grant);
    let boundary = committed.last().expect("boundary event");
    assert_eq!(event_kind(boundary), "session_boundary_committed");
    let boundary = boundary_of(boundary).expect("boundary event carries its row");
    assert_eq!(boundary["request_sequence"], json!(1));
    assert_eq!(boundary["cookie_generation"], json!(0));

    // The next request advances the sequence monotonically.
    let second = manager
        .exchange(
            &grant,
            &read_only(&grant, "https://jobs.example/list?page=2", "shard-wi-b"),
            &harness.response(TARGET),
        )
        .expect("second exchange must prepare after the boundary commit");
    assert_eq!(record_value(&second)["request_sequence"], json!(2));

    // A replayed receipt for the first exchange cannot overwrite the second
    // prepared boundary.
    expect_fault(
        manager.commit_boundary(&grant, &receipt),
        "stale_boundary",
    );

    // Committing the current prepared boundary succeeds exactly once.
    let second_receipt = boundary_receipt(&second, json!({}));
    manager
        .commit_boundary(&grant, &second_receipt)
        .expect("the second boundary commits");
    expect_fault(
        manager.commit_boundary(&grant, &second_receipt),
        "no_in_flight_exchange",
    );
}

// ---------------------------------------------------------------------------
// C32: current epoch enforced
// ---------------------------------------------------------------------------

#[test]
fn c32_current_epoch_is_enforced() {
    let harness = Harness::new();
    let manager = harness.manager();
    let grant = harness.grant();

    let session = manager
        .establish(
            &grant,
            &worker_establish(Some("per_worker"), "shard-wi-b"),
            &harness.control(TARGET),
        )
        .expect("session must establish");
    let epoch = record_value(&session.generation)["session_epoch"]
        .as_u64()
        .expect("generation carries its epoch");
    assert_eq!(epoch, 1);

    let exchange = manager
        .exchange(
            &grant,
            &read_only(&grant, "https://jobs.example/list", "shard-wi-b"),
            &harness.response(TARGET),
        )
        .expect("exchange must prepare");
    let before = harness.events(&grant).len();

    let mut stale = record_value(&exchange)
        .as_object()
        .expect("receipt object")
        .clone();
    stale.insert("session_epoch".to_string(), json!(epoch + 1));
    let stale = check("audit_log", Value::Object(stale));
    expect_fault(manager.commit_boundary(&grant, &stale), "stale_boundary");
    assert_eq!(
        harness.events(&grant).len(),
        before,
        "a stale completion has no durable effect"
    );
    // The prepared exchange is still the one in flight.
    expect_fault(
        manager.exchange(
            &grant,
            &read_only(&grant, "https://jobs.example/list", "shard-wi-b"),
            &harness.response(TARGET),
        ),
        "session_busy",
    );

    manager
        .commit_boundary(&grant, &boundary_receipt(&exchange, json!({})))
        .expect("the current epoch's boundary commits");

    // Retirement names the current generation; a stale claim is inert.
    let before_retire = harness.events(&grant).len();
    let stale_retire = check(
        "audit_log",
        json!({
            "target": TARGET,
            "run_id": RUN_ID,
            "phase": "A",
            "shard_id": "shard-wi-b",
            "expected_epoch": epoch + 1,
        }),
    );
    expect_fault(
        manager.retire(&grant, &stale_retire, &harness.control(TARGET)),
        "stale_generation",
    );
    assert_eq!(
        harness.events(&grant).len(),
        before_retire,
        "a stale retirement has no durable effect"
    );

    let retire = check(
        "audit_log",
        json!({
            "target": TARGET,
            "run_id": RUN_ID,
            "phase": "A",
            "shard_id": "shard-wi-b",
            "expected_epoch": epoch,
        }),
    );
    let retired = manager
        .retire(&grant, &retire, &harness.control(TARGET))
        .expect("the current generation retires");
    let retired_value = record_value(&retired);
    assert_eq!(retired_value["status"], json!("retired"));
    assert_eq!(retired_value["session_epoch"], json!(epoch));
    let events = harness.events(&grant);
    assert_eq!(event_kind(events.last().expect("retire event")), "session_retired");
    assert_eq!(
        session_row_of(events.last().expect("retire event")).expect("row")["status"],
        json!("retired")
    );

    // A retired generation has no live owner.
    expect_fault(
        manager.retire(&grant, &retire, &harness.control(TARGET)),
        "no_live_session",
    );
}

// ---------------------------------------------------------------------------
// C32: expiry is journaled and fences the generation
// ---------------------------------------------------------------------------

#[test]
fn c32_expired_generation_is_journaled_and_fenced() {
    let harness = Harness::new();
    let manager = harness.manager();
    let grant = harness.grant();

    manager
        .establish(
            &grant,
            &worker_establish(Some("per_worker"), "shard-mi-b"),
            &harness.control(TARGET),
        )
        .expect("session must establish");

    // The session deadline defaults to the control credit's finite call
    // bound (30_000 ms); move the authority clock past it.
    harness.clock.advance(31_000.0);
    expect_fault(
        manager.exchange(
            &grant,
            &read_only(&grant, "https://jobs.example/list", "shard-mi-b"),
            &harness.response(TARGET),
        ),
        "session_expired",
    );
    let events = harness.events(&grant);
    let expired = events.last().expect("expiry event");
    assert_eq!(event_kind(expired), "session_expired");
    let row = session_row_of(expired).expect("expiry row");
    assert_eq!(row["status"], json!("expired"));
    assert_eq!(row["last_failure_reason"], json!("session_lapse"));

    // The expired generation stays fenced.
    expect_fault(
        manager.exchange(
            &grant,
            &read_only(&grant, "https://jobs.example/list", "shard-mi-b"),
            &harness.response(TARGET),
        ),
        "session_expired",
    );

    // A nonactive generation can be retired for cleanup.
    let retire = check(
        "audit_log",
        json!({
            "target": TARGET,
            "run_id": RUN_ID,
            "phase": "A",
            "shard_id": "shard-mi-b",
            "reason": "session_lapse",
        }),
    );
    let retired = manager
        .retire(&grant, &retire, &harness.control(TARGET))
        .expect("an expired generation can be retired");
    assert_eq!(record_value(&retired)["status"], json!("retired"));

    // A retired generation no longer owns the identity: the next
    // establishment is a clean new epoch, not a crash recovery.
    let next = manager
        .establish(
            &grant,
            &worker_establish(Some("per_worker"), "shard-mi-b"),
            &harness.control(TARGET),
        )
        .expect("a retired generation may be replaced");
    assert_eq!(record_value(&next.generation)["session_epoch"], json!(2));
    let events = harness.events(&grant);
    let established = events.last().expect("re-established generation");
    assert_eq!(event_kind(established), "session_established");
    let data = event_data(established);
    assert_eq!(data["recovered_from_crash"], json!(false));
    assert_eq!(data["previous_session_epoch"], json!(1));
    assert_eq!(data["previous_generation_status"], json!("retired"));
}

// ---------------------------------------------------------------------------
// C32: establishment refuses cross-boot deadline ordering
// ---------------------------------------------------------------------------

#[test]
fn c32_establishment_refuses_cross_boot_deadline() {
    let harness = Harness::new();
    let manager = harness.manager();
    let grant = harness.grant();
    let before = harness.events(&grant).len();

    // A deadline on another boot is never compared or subtracted against the
    // session clock (EK-TIME).
    let request = establish_request(
        Some("per_worker"),
        "shard-wi-b",
        json!({"deadline": point_on(CLOCK_ID, "boot-other", 5_000.0)}),
    );
    expect_fault(
        manager.establish(&grant, &request, &harness.control(TARGET)),
        "cross_boot",
    );
    assert_eq!(
        harness.events(&grant).len(),
        before,
        "a cross-boot deadline writes no session row"
    );
}

// ---------------------------------------------------------------------------
// C32: a handoff receipt is not session birth
// ---------------------------------------------------------------------------

#[test]
fn c32_handoff_requires_realization_before_exchange() {
    let harness = Harness::new();
    let manager = harness.manager();
    let grant = harness.grant();

    // WI-B bootstrap: an external headed authenticated handoff. The receipt is
    // recorded as evidence, the generation waits for realization, and the
    // three-field handoff never claims original session birth.
    let handoff = establish_request(
        Some("per_worker"),
        "shard-wi-b",
        json!({
            "bootstrap_kind": "handoff",
            "handoff": {
                "timestamp": point_on(CLOCK_ID, BOOT_ID, 1_000.0),
                "reference": "opaque-context-ref",
            },
        }),
    );
    let session = manager
        .establish(&grant, &handoff, &harness.control(TARGET))
        .expect("handoff bootstrap establishes a waiting generation");
    let generation = record_value(&session.generation);
    assert_eq!(generation["status"], json!("needs_handoff"));
    assert_eq!(
        generation["verified_session_birth"]["reason"],
        json!("not_observed"),
        "a handoff receipt does not establish session birth"
    );
    assert_eq!(generation["handoff_timestamp"]["monotonic_offset_ms"], json!(1000.0));
    assert_eq!(
        generation["bootstrap_completed_at"]["reason"],
        json!("not_observed"),
        "bootstrap is not complete before realization"
    );

    // No request is prepared while the generation waits for realization.
    expect_fault(
        manager.exchange(
            &grant,
            &read_only(&grant, "https://jobs.example/list", "shard-wi-b"),
            &harness.response(TARGET),
        ),
        "needs_handoff",
    );

    // A realized handoff (authenticated state evidence) is active and may
    // exchange; realization is journaled after Start, not at receipt time.
    let realized = establish_request(
        Some("per_worker"),
        "shard-wi-b-realized",
        json!({
            "bootstrap_kind": "handoff",
            "handoff": {
                "timestamp": point_on(CLOCK_ID, BOOT_ID, 2_000.0),
                "reference": "opaque-context-ref",
            },
            "authenticated_state_evidence": {"digest": "a".repeat(64)},
        }),
    );
    let realized = manager
        .establish(&grant, &realized, &harness.control(TARGET))
        .expect("a realized handoff establishes an active generation");
    assert_eq!(record_value(&realized.generation)["status"], json!("active"));
    manager
        .exchange(
            &grant,
            &read_only(&grant, "https://jobs.example/list", "shard-wi-b-realized"),
            &harness.response(TARGET),
        )
        .expect("a realized generation exchanges");
}

// ---------------------------------------------------------------------------
// C32: a nonactive generation is retired before a new epoch
// ---------------------------------------------------------------------------

#[test]
fn c32_nonactive_generation_retired_before_new_epoch() {
    let harness = Harness::new();
    let manager = harness.manager();
    let grant = harness.grant();

    manager
        .establish(
            &grant,
            &worker_establish(Some("per_worker"), "shard-mi-b"),
            &harness.control(TARGET),
        )
        .expect("session must establish");

    harness.clock.advance(31_000.0);
    expect_fault(
        manager.exchange(
            &grant,
            &read_only(&grant, "https://jobs.example/list", "shard-mi-b"),
            &harness.response(TARGET),
        ),
        "session_expired",
    );
    let before = harness.events(&grant).len();

    // Establishing over the expired generation retires it first (§16.8).
    let next = manager
        .establish(
            &grant,
            &worker_establish(Some("per_worker"), "shard-mi-b"),
            &harness.control(TARGET),
        )
        .expect("an expired generation is superseded by a new epoch");
    assert_eq!(record_value(&next.generation)["session_epoch"], json!(2));

    let events = harness.events(&grant);
    assert_eq!(
        events.len(),
        before + 2,
        "supersede appends the prior retirement and the new generation"
    );
    let retirement = &events[events.len() - 2];
    assert_eq!(event_kind(retirement), "session_retired");
    let row = session_row_of(retirement).expect("retirement row");
    assert_eq!(row["session_epoch"], json!(1));
    assert_eq!(row["status"], json!("retired"));
    assert_eq!(
        event_data(retirement)["superseded_by_session_epoch"],
        json!(2)
    );

    let established = events.last().expect("new generation");
    assert_eq!(event_kind(established), "session_established");
    assert_eq!(
        event_data(established)["previous_generation_status"],
        json!("expired")
    );
    assert_eq!(event_data(established)["recovered_from_crash"], json!(false));
    assert_eq!(
        session_row_of(established).expect("generation row")["session_epoch"],
        json!(2)
    );
}

// ---------------------------------------------------------------------------
// C33: rotating cookies are applied before the next request
// ---------------------------------------------------------------------------

#[test]
fn c33_rotating_cookies_applied_before_next_request() {
    let harness = Harness::new();
    let manager = harness.manager();
    let grant = harness.grant();

    let session = manager
        .establish(
            &grant,
            &worker_establish(Some("per_worker"), "shard-or-a"),
            &harness.control(TARGET),
        )
        .expect("session must establish");

    let first = manager
        .exchange(
            &grant,
            &read_only(&grant, "https://jobs.example/list?page=1", "shard-or-a"),
            &harness.response(TARGET),
        )
        .expect("first exchange must prepare");
    assert_eq!(record_value(&first)["cookie_sequence"], json!(0));
    assert_eq!(record_value(&first)["cookies_applied"], json!(0));

    let receipt = boundary_receipt(
        &first,
        json!({
            "rotations": [rotation(
                "response",
                "https://jobs.example/list?page=1",
                &["sid=abc; Path=/"],
            )],
        }),
    );
    manager
        .commit_boundary(&grant, &receipt)
        .expect("rotating response boundary must commit");
    assert_eq!(cookie_count(&session), 1, "the rotated cookie is live");
    assert!(
        cookie_header(&session, "https://jobs.example/list").contains("sid=abc"),
        "the next request would send the rotated cookie"
    );

    let second = manager
        .exchange(
            &grant,
            &read_only(&grant, "https://jobs.example/list?page=2", "shard-or-a"),
            &harness.response(TARGET),
        )
        .expect("the next exchange must prepare");
    let second_value = record_value(&second);
    assert_eq!(second_value["cookie_sequence"], json!(1));
    assert_eq!(second_value["cookies_applied"], json!(0));
    assert_eq!(second_value["cookie_count"], json!(1));

    // Another rotating hop advances the cookie generation monotonically.
    let receipt = boundary_receipt(
        &second,
        json!({
            "rotations": [rotation(
                "response",
                "https://jobs.example/list?page=2",
                &["sid=def; Path=/", "awswaf=token; Path=/"],
            )],
        }),
    );
    manager
        .commit_boundary(&grant, &receipt)
        .expect("second rotating boundary must commit");
    assert_eq!(cookie_count(&session), 2);
    let boundary = harness.events(&grant);
    let boundary = boundary_of(boundary.last().expect("boundary event")).expect("boundary row");
    assert_eq!(boundary["request_sequence"], json!(2));
    assert_eq!(boundary["cookie_generation"], json!(3));
}

// ---------------------------------------------------------------------------
// C33: redirect and solver hops are serialized and mutation-rejected
// ---------------------------------------------------------------------------

#[test]
fn c33_redirect_and_solver_hops_serialized() {
    let harness = Harness::new();
    let manager = harness.manager();
    let grant = harness.grant();

    let session = manager
        .establish(
            &grant,
            &worker_establish(Some("per_shard"), "shard-or-a"),
            &harness.control(TARGET),
        )
        .expect("session must establish");

    let exchange = manager
        .exchange(
            &grant,
            &read_only(&grant, "https://jobs.example/list", "shard-or-a"),
            &harness.response(TARGET),
        )
        .expect("exchange must prepare");

    // The redirect hop is re-authorized read-only inside the serialization
    // window; solver cookie mutation rides the same boundary.
    let redirect = record_value(&endpoint(&grant, "https://jobs.example/step2")).clone();
    let receipt = boundary_receipt(
        &exchange,
        json!({
            "redirect": redirect,
            "solver": {"capability_id": "solver-js", "request_id": "solver-1"},
            "rotations": [
                rotation("redirect", "https://jobs.example/step2", &["hop=2; Path=/"]),
                rotation("solver", "https://jobs.example/challenge", &["clear=1; Path=/"]),
            ],
        }),
    );
    manager
        .commit_boundary(&grant, &receipt)
        .expect("redirect and solver hops must commit serially");
    assert_eq!(cookie_count(&session), 2);
    let header = cookie_header(&session, "https://jobs.example/step2");
    assert!(header.contains("hop=2"), "redirect cookie applied: {header}");
    assert!(header.contains("clear=1"), "solver cookie applied: {header}");

    // A redirect rotation without its redirect evidence is refused.
    let next = manager
        .exchange(
            &grant,
            &read_only(&grant, "https://jobs.example/step2", "shard-or-a"),
            &harness.response(TARGET),
        )
        .expect("next exchange must prepare");
    let before = harness.events(&grant).len();
    let cookie_before = cookie_count(&session);
    let missing_evidence = boundary_receipt(
        &next,
        json!({
            "rotations": [
                rotation("redirect", "https://jobs.example/step3", &["hop=3; Path=/"]),
            ],
        }),
    );
    expect_fault(
        manager.commit_boundary(&grant, &missing_evidence),
        "missing_redirect_evidence",
    );
    assert_eq!(
        harness.events(&grant).len(),
        before,
        "a refused hop writes no boundary"
    );
    assert_eq!(
        cookie_count(&session),
        cookie_before,
        "a refused hop applies no cookie"
    );
    // The same exchange is still the session's one in-flight request.
    expect_fault(
        manager.exchange(
            &grant,
            &read_only(&grant, "https://jobs.example/step2", "shard-or-a"),
            &harness.response(TARGET),
        ),
        "session_busy",
    );

    // A redirect to a mutation endpoint is rejected before wire and leaves the
    // boundary uncommitted.
    let mutation_redirect =
        record_value(&endpoint(&grant, "https://jobs.example/self-refer-step1-validate.cfm?usemyssn=No"))
            .clone();
    let mutation = boundary_receipt(
        &next,
        json!({
            "redirect": mutation_redirect,
            "rotations": [
                rotation(
                    "redirect",
                    "https://jobs.example/self-refer-step1-validate.cfm?usemyssn=No",
                    &["hop=3; Path=/"],
                ),
            ],
        }),
    );
    expect_fault(manager.commit_boundary(&grant, &mutation), "mutation_rejected");
    assert_eq!(
        cookie_count(&session),
        cookie_before,
        "a mutation redirect applies no cookie"
    );
    assert_eq!(harness.events(&grant).len(), before);

    // The corrected boundary still commits under the same in-flight window.
    manager
        .commit_boundary(&grant, &boundary_receipt(&next, json!({})))
        .expect("the unmutated boundary commits");
    assert_eq!(harness.events(&grant).len(), before + 1);
}

// ---------------------------------------------------------------------------
// C33: cold crash recovery establishes a new epoch without cookie replay
// ---------------------------------------------------------------------------

#[test]
fn c33_cold_crash_recovery_new_epoch_without_cookie_replay() {
    let harness = Harness::new();
    let grant = harness.grant();
    let request = worker_establish(Some("per_worker"), "shard-wi-b");

    let crashed = harness.manager();
    let first = crashed
        .establish(&grant, &request, &harness.control(TARGET))
        .expect("first generation establishes");
    assert_eq!(record_value(&first.generation)["session_epoch"], json!(1));

    let exchange = crashed
        .exchange(
            &grant,
            &read_only(&grant, "https://jobs.example/list", "shard-wi-b"),
            &harness.response(TARGET),
        )
        .expect("acked exchange prepares");
    crashed
        .commit_boundary(
            &grant,
            &boundary_receipt(
                &exchange,
                json!({
                    "rotations": [rotation(
                        "response",
                        "https://jobs.example/list",
                        &["sid=acked; Path=/"],
                    )],
                }),
            ),
        )
        .expect("acked boundary commits");
    assert_eq!(cookie_count(&first), 1);

    // Unacknowledged rotating snapshot: prepared but never committed.
    crashed
        .exchange(
            &grant,
            &read_only(&grant, "https://jobs.example/list?page=2", "shard-wi-b"),
            &harness.response(TARGET),
        )
        .expect("unacked exchange prepares");
    drop(crashed); // process death without retire

    let recovered = harness.manager();
    let second = recovered
        .establish(&grant, &request, &harness.control(TARGET))
        .expect("cold recovery establishes a new epoch");
    assert_eq!(
        record_value(&second.generation)["session_epoch"],
        json!(2),
        "recovery establishes a new epoch, never the crashed generation"
    );
    assert_eq!(record_value(&second.generation)["status"], json!("active"));
    assert_eq!(record_value(&second.generation)["cookie_generation"], json!(0));
    assert_eq!(
        cookie_count(&second),
        0,
        "unacknowledged rotating snapshots are never replayed after a crash"
    );

    let events = harness.events(&grant);
    let recovered_event = events.last().expect("recovery event");
    assert_eq!(event_kind(recovered_event), "session_recovered");
    let data = event_data(recovered_event);
    assert_eq!(data["recovered_from_crash"], json!(true));
    assert_eq!(data["previous_session_epoch"], json!(1));
    assert_eq!(data["previous_generation_status"], json!("active"));

    // The acknowledged cookie *generation* survives as evidence; its bytes do
    // not. Exactly one boundary event exists, from the crashed generation.
    let boundaries: Vec<&Value> = events
        .iter()
        .filter(|event| event_kind(event) == "session_boundary_committed")
        .collect();
    assert_eq!(boundaries.len(), 1);
    let boundary = boundary_of(boundaries[0]).expect("boundary row");
    assert_eq!(boundary["session_epoch"], json!(1));
    assert_eq!(boundary["cookie_generation"], json!(1));

    // The recovered generation starts its own monotone sequences.
    let exchange = recovered
        .exchange(
            &grant,
            &read_only(&grant, "https://jobs.example/list", "shard-wi-b"),
            &harness.response(TARGET),
        )
        .expect("recovered generation exchanges");
    assert_eq!(record_value(&exchange)["request_sequence"], json!(1));
    assert_eq!(record_value(&exchange)["cookie_count"], json!(0));
}

// ---------------------------------------------------------------------------
// C33: independent A/B shards never share state
// ---------------------------------------------------------------------------

#[test]
fn c33_independent_ab_shards_isolated() {
    // Replacement publishes a permitted Send live-client handle and epoch.
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<LiveSession>();

    let harness = Harness::new();
    let manager = harness.manager();
    let grant = harness.grant();

    let shard_a = manager
        .establish(
            &grant,
            &worker_establish(Some("per_shard"), "or-shard-a"),
            &harness.control(TARGET),
        )
        .expect("shard A establishes");
    let shard_b = manager
        .establish(
            &grant,
            &worker_establish(Some("per_shard"), "or-shard-b"),
            &harness.control(TARGET),
        )
        .expect("shard B establishes");

    // Independent per-shard generations start their own epoch and own their
    // own live client / cookie jar.
    assert_eq!(record_value(&shard_a.generation)["session_epoch"], json!(1));
    assert_eq!(record_value(&shard_b.generation)["session_epoch"], json!(1));
    assert!(
        !Arc::ptr_eq(&shard_a.client.cookies(), &shard_b.client.cookies()),
        "independent shards never share a live client jar"
    );

    let exchange = manager
        .exchange(
            &grant,
            &read_only(&grant, "https://jobs.example/list", "or-shard-a"),
            &harness.response(TARGET),
        )
        .expect("shard A exchanges");
    manager
        .commit_boundary(
            &grant,
            &boundary_receipt(
                &exchange,
                json!({
                    "rotations": [rotation(
                        "response",
                        "https://jobs.example/list",
                        &["a=1; Path=/"],
                    )],
                }),
            ),
        )
        .expect("shard A boundary commits");

    assert_eq!(cookie_count(&shard_a), 1);
    assert_eq!(cookie_count(&shard_b), 0, "shard B inherits nothing");

    let exchange_b = manager
        .exchange(
            &grant,
            &read_only(&grant, "https://jobs.example/list", "or-shard-b"),
            &harness.response(TARGET),
        )
        .expect("shard B exchanges independently");
    assert_eq!(record_value(&exchange_b)["cookie_count"], json!(0));
    assert_eq!(record_value(&exchange_b)["shard_id"], json!("or-shard-b"));

    // Retiring A does not retire B.
    let retire_a = check(
        "audit_log",
        json!({
            "target": TARGET,
            "run_id": RUN_ID,
            "phase": "A",
            "shard_id": "or-shard-a",
            "expected_epoch": 1,
        }),
    );
    manager
        .retire(&grant, &retire_a, &harness.control(TARGET))
        .expect("shard A retires");
    manager
        .commit_boundary(&grant, &boundary_receipt(&exchange_b, json!({})))
        .expect("shard B still commits its own boundary");

    let retire_b = check(
        "audit_log",
        json!({
            "target": TARGET,
            "run_id": RUN_ID,
            "phase": "A",
            "shard_id": "or-shard-b",
            "expected_epoch": 1,
        }),
    );
    manager
        .retire(&grant, &retire_b, &harness.control(TARGET))
        .expect("shard B retires");

    let events = harness.events(&grant);
    let shards: Vec<&str> = events
        .iter()
        .filter(|event| event_kind(event) == "session_established")
        .filter_map(|event| session_row_of(event))
        .filter_map(|row| row["shard_id"].as_str())
        .collect();
    assert_eq!(shards, vec!["or-shard-a", "or-shard-b"]);
    let retired: Vec<&str> = events
        .iter()
        .filter(|event| event_kind(event) == "session_retired")
        .filter_map(|event| session_row_of(event))
        .filter_map(|row| row["shard_id"].as_str())
        .collect();
    assert_eq!(retired.len(), 2, "both shards retired independently");
}

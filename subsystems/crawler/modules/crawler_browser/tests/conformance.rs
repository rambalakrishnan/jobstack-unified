//! [C34] thread-confinement conformance: Page/solver/DOM/V8 handles never
//! cross the allocating-thread boundary.

use crawler_admission::{Admission, AdmissionConfig, MemoryAdmission};
use crawler_authority::{authorize, grant_record, Grant};
use crawler_browser::{create_page, execute_page, reset_page, PageExecutor};
use crawler_hashing::{canonical_bytes, digest_bytes};
use crawler_readonly::{authorize_acquisition, ReadOnlyRequest};
use crawler_schema::{record_value, validate, CheckedRecord, Fault};
use crawler_store::OwnerStore;
use crawler_time::ClockAuthority;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

// Compile-time confinement: safe code cannot move the executor (or its Page,
// solvers, DOM/V8 handles, capturing closures) across threads.
static_assertions::assert_not_impl_all!(PageExecutor: Send, Sync);
static_assertions::assert_not_impl_all!(browser_oxide::Page: Send, Sync);

fn check(value: Value) -> CheckedRecord {
    validate("audit_log", value).expect("fixture must validate")
}

fn missing(reason: &str) -> Value {
    json!({"value": Value::Null, "reason": reason})
}

fn binding_of(record: &CheckedRecord) -> String {
    digest_bytes(&canonical_bytes(record).expect("canonical bytes must exist"))
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
// Fixtures: clock, store, admission
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
}

impl ClockAuthority for TestClock {
    fn now(&self) -> Result<CheckedRecord, Fault> {
        validate(
            "audit_log",
            json!({
                "clock_id": "browser-clock",
                "boot_id": "boot-1",
                "origin": "engine_measured",
                "monotonic_offset_ms": self.offset_ms.load(Ordering::SeqCst),
                "utc_annotation": missing("not_observed"),
            }),
        )
    }
}

#[derive(Default)]
struct RecordingStore {
    transactions: Mutex<Vec<Value>>,
}

impl OwnerStore for RecordingStore {
    fn transact(&self, grant: &Grant, transaction: &CheckedRecord) -> Result<CheckedRecord, Fault> {
        let value = record_value(transaction).clone();
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

fn admission_registration() -> CheckedRecord {
    check(json!({
        "registration_id": "browser-admission-channel",
        "principals": [{
            "principal_id": "browser-owner",
            "verbs": ["Start"],
            "connectors": ["jobs-connector"],
            "control": true,
            "owner_domain": "crawler",
            "restricted_access": false,
        }],
    }))
}

fn admission_grant() -> Grant {
    let registration = admission_registration();
    let principal = check(json!({
        "principal_id": "browser-owner",
        "registration_digest": binding_of(&registration),
    }));
    let request = check(json!({"verb": "Start", "connector": "jobs-connector"}));
    authorize(&principal, &request, &registration).expect("admission grant must issue")
}

fn admission() -> MemoryAdmission {
    let clock: Arc<dyn ClockAuthority> = Arc::new(TestClock::new());
    let store: Arc<dyn OwnerStore> = Arc::new(RecordingStore::default());
    MemoryAdmission::new(AdmissionConfig::default(), clock, store, admission_grant())
        .expect("admission must build")
}

fn page_permit(target: &str) -> crawler_admission::PagePermit {
    // Fresh admission per permit keeps tests independent; the ledger lives on
    // inside the permit via Arc, so dropping `admission` here is safe.
    let adm = admission();
    adm.reserve_page(
        &check(json!({
            "scope_id": "browser-scope-1",
            "target": target,
            "page_rows": 1,
            "page_bytes": 100,
        })),
        false,
    )
    .expect("page permit must be admitted")
}

// ---------------------------------------------------------------------------
// Fixtures: read-only acquisition
// ---------------------------------------------------------------------------

fn readonly_registration() -> CheckedRecord {
    check(json!({
        "registration_id": "browser-readonly-channel",
        "principals": [{
            "principal_id": "reader",
            "verbs": ["Describe", "Prepare", "Observe", "CollectArtifacts"],
            "connectors": ["jobs-connector"],
            "control": false,
            "owner_domain": "crawler",
            "restricted_access": false,
        }],
    }))
}

fn readonly_grant() -> Grant {
    let registration = readonly_registration();
    let principal = check(json!({
        "principal_id": "reader",
        "registration_digest": binding_of(&registration),
    }));
    let request = check(json!({
        "verb": "Observe",
        "connector": "jobs-connector",
        "subject": "jobs",
    }));
    authorize(&principal, &request, &registration).expect("readonly grant must issue")
}

fn readonly_request() -> ReadOnlyRequest {
    let grant = readonly_grant();
    let endpoint = check(json!({
        "grant_digest": binding_of(grant_record(&grant)),
        "digest": "0123456789abcdef".repeat(4),
        "access": "public",
        "owner_domain": "crawler",
        "provenance": "origin",
        "url": "https://jobs.illinois.gov/listings",
    }));
    let request = check(json!({
        "record_type": "connector_task",
        "task_id": "task-1",
        "task_type": "discover_jobs",
        "goal": "discover listings",
        "effect_policy": "read_only",
        "permitted_origins": ["https://jobs.illinois.gov"],
        "permitted_interfaces": ["read_only_acquisition"],
    }));
    authorize_acquisition(&grant, &endpoint, &request).expect("acquisition must authorize")
}

fn profile() -> CheckedRecord {
    check(json!({
        "preset": "chrome_148_linux",
        "target": "jobs",
    }))
}

fn deadline() -> CheckedRecord {
    check(json!({
        "clock_id": "browser-clock",
        "boot_id": "boot-1",
        "origin": "engine_measured",
        "monotonic_offset_ms": 60_000u64,
        "utc_annotation": missing("not_observed"),
    }))
}

fn session(target: &str) -> CheckedRecord {
    check(json!({
        "target": target,
        "session_epoch": 1u64,
    }))
}

fn executor(target: &str) -> PageExecutor {
    create_page(&profile(), page_permit(target)).expect("page must allocate on owner thread")
}

// ---------------------------------------------------------------------------
// C34: thread confinement
// ---------------------------------------------------------------------------

/// The executor (and the native Page) is `!Send`/`!Sync`: safe code cannot
/// move handles across threads. The `static_assertions` above prove this at
/// compile time; this test pins the runtime owner on creation. [C34]
#[test]
fn c34_executor_is_not_send_nor_sync() {
    let exec = executor("jobs");
    assert_eq!(
        exec.owner_thread(),
        std::thread::current().id(),
        "owner must be the allocating thread"
    );
}

/// Creation pins the allocating OS thread as the exclusive owner. [C34]
#[test]
fn c34_create_page_pins_allocating_thread() {
    let exec = executor("jobs");
    assert_eq!(exec.owner_thread(), std::thread::current().id());
    // Drop on the owner thread must succeed (Page destroyed on its owner).
    drop(exec);
}

/// Owner-thread execution succeeds and returns owned data only: no live
/// Page, DOM, or V8 handle leaves the boundary, and no bare nulls. [C34]
#[test]
fn c34_execute_page_succeeds_on_owner_and_returns_owned_data() {
    let mut exec = executor("jobs");
    let request = readonly_request();
    let dl = deadline();
    let out = execute_page(&mut exec, &request, &dl).expect("owner-thread execute must succeed");
    let value = record_value(&out);
    assert_no_bare_nulls(value);
    assert_eq!(value["kind"], json!("page_execution"));
    assert_eq!(value["effect_policy"], json!("read_only"));
    assert_eq!(value["endpoint_url"], json!("https://jobs.illinois.gov/listings"));
    assert_eq!(value["task_id"], json!("task-1"));
    assert!(
        value["page_url"].as_str().is_some(),
        "output must carry the owned page url"
    );
    assert!(
        value["render_verdict"].as_str().is_some(),
        "output must carry the owned render verdict"
    );
    assert_eq!(
        value["deadline"], record_value(&dl).clone(),
        "deadline must be echoed, never extended"
    );
    // Still usable after a successful execute.
    let out2 =
        execute_page(&mut exec, &readonly_request(), &deadline()).expect("second execute");
    assert_eq!(record_value(&out2)["kind"], json!("page_execution"));
}

/// Wrong-thread execution is rejected before engine entry. The raw-pointer
/// hop is test-only `unsafe` to exercise the runtime guard; safe code cannot
/// make this call at all (`!Send`). [C34]
#[test]
fn c34_execute_page_rejects_wrong_thread_before_engine_entry() {
    let mut exec = executor("jobs");
    let addr = &mut exec as *mut PageExecutor as usize;
    // SAFETY: the address (usize) is Send; the owner thread blocks on join,
    // so no concurrent access occurs. The callee rejects before touching the Page.
    let handle = std::thread::spawn(move || {
        let foreign: &mut PageExecutor = unsafe { &mut *(addr as *mut PageExecutor) };
        assert_ne!(
            std::thread::current().id(),
            foreign.owner_thread(),
            "spawned thread must differ from the owner"
        );
        let err = execute_page(foreign, &readonly_request(), &deadline())
            .expect_err("wrong-thread execute must fail");
        assert_eq!(err.code, "wrong_thread");
    });
    handle.join().expect("worker must join");
    // Owner-thread use still succeeds afterwards: the rejected call mutated nothing.
    let out = execute_page(&mut exec, &readonly_request(), &deadline())
        .expect("owner-thread execute must still succeed");
    assert_eq!(record_value(&out)["kind"], json!("page_execution"));
}

/// Owner-thread reset succeeds and the page remains usable. [C34]
#[test]
fn c34_reset_page_succeeds_on_owner_thread() {
    let mut exec = executor("jobs");
    reset_page(&mut exec, &session("jobs")).expect("owner-thread reset must succeed");
    let out = execute_page(&mut exec, &readonly_request(), &deadline())
        .expect("execute after reset must succeed");
    assert_eq!(record_value(&out)["kind"], json!("page_execution"));
}

/// Wrong-thread reset is rejected before engine entry. [C34]
#[test]
fn c34_reset_page_rejects_wrong_thread_before_engine_entry() {
    let mut exec = executor("jobs");
    let addr = &mut exec as *mut PageExecutor as usize;
    // SAFETY: see wrong-thread execute test; reset rejects before engine entry.
    let handle = std::thread::spawn(move || {
        let foreign: &mut PageExecutor = unsafe { &mut *(addr as *mut PageExecutor) };
        let err = reset_page(foreign, &session("jobs")).expect_err("wrong-thread reset must fail");
        assert_eq!(err.code, "wrong_thread");
    });
    handle.join().expect("worker must join");
    reset_page(&mut exec, &session("jobs")).expect("owner-thread reset must still succeed");
}

/// Reset across incompatible session ownership is rejected without entering
/// reuse, even on the owner thread. [C34]
#[test]
fn c34_reset_page_rejects_incompatible_session_ownership() {
    let mut exec = executor("jobs");
    let err = reset_page(&mut exec, &session("other-target"))
        .expect_err("cross-owner reset must fail");
    assert_eq!(err.code, "session_mismatch");
    // Compatible reset still succeeds afterwards.
    reset_page(&mut exec, &session("jobs")).expect("compatible reset must succeed");
}

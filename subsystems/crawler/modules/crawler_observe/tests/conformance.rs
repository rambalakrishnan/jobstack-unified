//! Conformance tests for `crawler_observe`.
//!
//! * **[C38]** Observe: fixed-prefix ordering, scanned cursor, loss
//!   reporting, and empty-page semantics. Covers `observe` pagination,
//!   `after < item <= next <= through`, `has_more` exactness, lifecycle
//!   exclusion, handle scoping, gap limitations, oversized retention,
//!   closure refs, and explicit cursor/cutoff faults; plus
//!   `normalize_native_report` independent gating and byte retention.

use crawler_artifacts::{ArtifactStore, MemoryArtifactStore};
use crawler_authority::{authorize_producer, Grant};
use crawler_observe::{normalize_native_report, observe};
use crawler_schema::{record_value, validate, CheckedRecord, Fault};
use crawler_store::{MemoryOwnerStore, OwnerStore};
use crawler_time::ClockAuthority;
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

const SCHEMA_VERSION: &str = "evidence-kernel/0.1.0";
const JOURNAL: &str = "journal-1";
const RUN: &str = "run-1";
const PRODUCER: &str = "ingest";

fn check(schema: &str, value: Value) -> CheckedRecord {
    validate(schema, value).expect("fixture must validate")
}

fn missing(reason: &str) -> Value {
    json!({"value": Value::Null, "reason": reason})
}

fn inapplicable() -> Value {
    json!({"value": Value::Null, "reason": "not_applicable", "detail": "live cutoff"})
}

fn timepoint(offset_ms: u64) -> Value {
    json!({
        "clock_id": "clock-1",
        "boot_id": "boot-1",
        "origin": "engine_measured",
        "monotonic_offset_ms": offset_ms,
        "utc_annotation": missing("not_observed"),
    })
}

struct FixedClock {
    tick: AtomicU64,
}

impl FixedClock {
    fn new() -> Self {
        Self {
            tick: AtomicU64::new(1000),
        }
    }
}

impl ClockAuthority for FixedClock {
    fn now(&self) -> Result<CheckedRecord, Fault> {
        let offset = self.tick.fetch_add(10, Ordering::SeqCst);
        Ok(check("audit_log", timepoint(offset)))
    }
}

fn manifest_fixture() -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "manifest_id": "manifest-1",
            "producer_registry": [
                {
                    "producer_id": "ingest",
                    "owner_domain": "crawler_ingest",
                    "role": "external_input",
                    "provenance": "server",
                    "assertion_kind": "claim",
                },
            ],
            "event_registry": [
                {"event_kind": "manifest_admitted", "permitted_provenance": ["server"]},
                {"event_kind": "listing_observed", "permitted_provenance": ["server"]},
                {"event_kind": "downstream_revision_installed", "permitted_provenance": ["server"]},
                {"event_kind": "producer_closed", "permitted_provenance": ["server"]},
                {"event_kind": "evidence_imported", "permitted_provenance": ["importer"]},
            ],
        }),
    )
}

fn principal_for(manifest_digest: &str, producer_id: &str) -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "producer_id": producer_id,
            "manifest_digest": manifest_digest,
        }),
    )
}

fn grant_for(
    manifest: &CheckedRecord,
    manifest_digest: &str,
    producer_id: &str,
    event_kind: &str,
) -> Grant {
    let principal = principal_for(manifest_digest, producer_id);
    let submission = check("audit_log", json!({"event_kind": event_kind}));
    authorize_producer(&principal, &submission, manifest).expect("grant must issue")
}

fn admission_tx(manifest: &CheckedRecord, manifest_digest: &str) -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "operation": "admit_manifest",
            "journal_id": JOURNAL,
            "run_id": RUN,
            "manifest": record_value(manifest).clone(),
            "principal": {
                "producer_id": PRODUCER,
                "manifest_digest": manifest_digest,
            },
        }),
    )
}

fn append_tx(
    manifest_digest: &str,
    producer_sequence: Value,
    event_kind: &str,
    data: Value,
) -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "operation": "append_event",
            "journal_id": JOURNAL,
            "principal": {
                "producer_id": PRODUCER,
                "manifest_digest": manifest_digest,
            },
            "submission": {
                "producer_sequence": producer_sequence,
                "event_kind": event_kind,
                "event_schema_version": SCHEMA_VERSION,
                "occurred_at": missing("not_observed"),
                "payload": {
                    "data": data,
                    "measurements": [],
                    "evidence_refs": [],
                    "artifact_refs": [],
                },
            },
            "causal_refs": [],
        }),
    )
}

fn handle_a() -> Value {
    json!({"connector_id": "conn-1", "local_handle": "handle-a"})
}

fn handle_b() -> Value {
    json!({"connector_id": "conn-1", "local_handle": "handle-b"})
}

fn cursor(handle: Value, sequence: u64, event_hash: Value) -> Value {
    json!({
        "handle": handle,
        "journal_id": JOURNAL,
        "sequence": sequence,
        "event_hash": event_hash,
    })
}

fn observe_request(
    handle: Value,
    after: Value,
    through: Value,
    max_items: Value,
    wait_ms: f64,
) -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "handle": handle,
            "after": after,
            "through": through,
            "max_items": max_items,
            "wait_limit": {"kind": "exact", "unit": "ms", "value": wait_ms},
        }),
    )
}

fn journal_events(store: &MemoryOwnerStore, grant: &Grant) -> Vec<Value> {
    let q = check(
        "audit_log",
        json!({"query": "journal", "journal_id": JOURNAL}),
    );
    let view = record_value(&store.read(grant, &q).expect("journal view")).clone();
    view["events"].as_array().expect("events").clone()
}

fn prefix(store: &MemoryOwnerStore, grant: &Grant) -> Value {
    let q = check(
        "audit_log",
        json!({"query": "prefix", "journal_id": JOURNAL}),
    );
    let view = record_value(&store.read(grant, &q).expect("prefix")).clone();
    json!({
        "journal_id": JOURNAL,
        "last_sequence": view["last_sequence"].clone(),
        "head_hash": view["head_hash"].clone(),
    })
}

fn event_ref_of(envelope: &Value) -> Value {
    json!({
        "journal_id": envelope["journal_id"].clone(),
        "sequence": envelope["journal_sequence"].clone(),
        "event_id": envelope["event_id"].clone(),
        "event_hash": envelope["event_hash"].clone(),
        "pointer": "",
    })
}

fn setup_store() -> (MemoryOwnerStore, Grant, Arc<FixedClock>, Arc<MemoryArtifactStore>, String) {
    let manifest = manifest_fixture();
    let clock = Arc::new(FixedClock::new());
    let artifacts: Arc<MemoryArtifactStore> = Arc::new(MemoryArtifactStore::default());
    let clock_dyn: Arc<dyn ClockAuthority> = clock.clone();
    let artifacts_dyn: Arc<dyn ArtifactStore> = artifacts.clone();
    let store = MemoryOwnerStore::new(manifest_fixture(), clock_dyn, artifacts_dyn)
        .expect("store must open");
    let digest = store.manifest_hash().to_string();
    let grant = grant_for(&manifest, &digest, PRODUCER, "listing_observed");
    store
        .transact(&grant, &admission_tx(&manifest, &digest))
        .expect("admission must commit");
    (store, grant, clock, artifacts, digest)
}

fn append_obs(
    store: &MemoryOwnerStore,
    grant: &Grant,
    digest: &str,
    producer_seq: u64,
    kind: &str,
    data: Value,
) -> Value {
    let receipt = store
        .transact(grant, &append_tx(digest, json!(producer_seq), kind, data))
        .expect("append must commit");
    record_value(&receipt).clone()
}

// ---------------------------------------------------------------------------
// [C38] Observe
// ---------------------------------------------------------------------------

#[test]
fn c38_observe_fixed_prefix_scanned_cursor_loss_empty_page() {
    let (store, grant, clock, _artifacts, digest) = setup_store();
    let clock_dyn: Arc<dyn ClockAuthority> = clock.clone();

    // seq1 is manifest_admitted. Build a mixed journal:
    // seq2 (ps2): A observation
    // seq3 (ps3): B observation (non-observation for A)
    // seq4 (ps4): no handle (non-observation)
    // seq5 (ps6, skips ps5 => gap): A observation
    // seq6 (ps7): A observation
    // seq7 (ps8): B observation (trailing non-observation for A)
    append_obs(
        &store,
        &grant,
        &digest,
        2,
        "listing_observed",
        json!({"handle": handle_a(), "kind": "task_output", "name": "out-1"}),
    );
    append_obs(
        &store,
        &grant,
        &digest,
        3,
        "downstream_revision_installed",
        json!({"handle": handle_b(), "kind": "task_output", "name": "b-1"}),
    );
    append_obs(
        &store,
        &grant,
        &digest,
        4,
        "listing_observed",
        json!({"index": 99}),
    );
    append_obs(
        &store,
        &grant,
        &digest,
        6,
        "listing_observed",
        json!({"handle": handle_a(), "kind": "task_output", "name": "out-2"}),
    );
    append_obs(
        &store,
        &grant,
        &digest,
        7,
        "listing_observed",
        json!({"handle": handle_a(), "kind": "task_output", "name": "out-3"}),
    );
    append_obs(
        &store,
        &grant,
        &digest,
        8,
        "downstream_revision_installed",
        json!({"handle": handle_b(), "kind": "task_output", "name": "b-2"}),
    );

    let events = journal_events(&store, &grant);
    assert_eq!(events.len(), 7, "admission + 6 appends");
    let head_hash = events[6]["event_hash"].as_str().unwrap().to_string();

    // ---- Live cutoff first page pins through; ordering + scanned next ----
    let after0 = cursor(handle_a(), 0, inapplicable());
    let live = observe_request(handle_a(), after0.clone(), inapplicable(), json!(10), 0.0);
    let page = record_value(
        &observe(&store, clock_dyn.as_ref(), &grant, &live).expect("live observe"),
    )
    .clone();
    assert_eq!(page["kind"], json!("observation_page"));
    assert_eq!(page["handle"], handle_a());
    assert_eq!(page["after"], after0);
    assert_eq!(page["through"]["journal_id"], json!(JOURNAL));
    assert_eq!(page["through"]["last_sequence"], json!(7));
    assert_eq!(page["through"]["head_hash"], json!(head_hash));
    // Three A observations in journal order: seq 2, 5, 6.
    let items = page["items"].as_array().expect("items");
    assert_eq!(items.len(), 3);
    let seqs: Vec<u64> = items
        .iter()
        .map(|it| it["event_ref"]["sequence"].as_u64().unwrap())
        .collect();
    assert_eq!(seqs, vec![2, 5, 6], "journal order for exactly handle A");
    // after < item <= next <= through.
    let next_seq = page["next"]["sequence"].as_u64().unwrap();
    assert_eq!(next_seq, 7, "next scans trailing non-observation seq7");
    for s in &seqs {
        assert!(0 < *s && *s <= next_seq && next_seq <= 7);
    }
    assert_eq!(page["has_more"], json!(false));
    assert_eq!(page["next"]["journal_id"], json!(JOURNAL));
    assert_eq!(page["next"]["event_hash"], json!(head_hash));
    assert_eq!(page["next"]["handle"], handle_a());
    // Items copy the referenced envelopes (EXT-EVIDENCE).
    for item in items {
        let seq = item["event_ref"]["sequence"].as_u64().unwrap();
        let env = &events[(seq - 1) as usize];
        assert_eq!(item["event_ref"], event_ref_of(env));
        assert_eq!(item["recorded_at"], env["recorded_at"]);
        assert_eq!(item["provenance"], env["provenance"]);
        assert_eq!(item["payload"], env["payload"]["data"]);
        assert_eq!(item["measurements"], env["payload"]["measurements"]);
        assert_eq!(item["artifact_refs"], env["payload"]["artifact_refs"]);
        assert_eq!(item["event_ref"]["pointer"], json!(""));
    }
    // Loss is explicit via limitations (gap ps5 unresolved, detected_at 5).
    let limitations = page["limitations"].as_array().expect("limitations");
    assert!(
        limitations.iter().any(|l| l
            .as_str()
            .unwrap_or("")
            .contains("producer_gap")),
        "unresolved producer gap must be reported, got {limitations:?}"
    );
    // No closure yet: not_observed, never native termination.
    assert_eq!(
        page["observation_close_ref"]["reason"],
        json!("not_observed")
    );

    let pinned_through = page["through"].clone();

    // ---- Fixed-prefix pagination: max_items=1, next is last scanned ----
    let r1 = observe_request(
        handle_a(),
        cursor(handle_a(), 0, inapplicable()),
        pinned_through.clone(),
        json!(1),
        0.0,
    );
    let p1 = record_value(&observe(&store, clock_dyn.as_ref(), &grant, &r1).expect("p1")).clone();
    assert_eq!(p1["items"].as_array().unwrap().len(), 1);
    assert_eq!(p1["items"][0]["event_ref"]["sequence"], json!(2));
    assert_eq!(p1["next"]["sequence"], json!(2));
    assert_eq!(p1["has_more"], json!(true));

    // Continuation reuses the pinned cutoff; scan skips seq3,4 (non-obs).
    let after2 = p1["next"].clone();
    let r2 = observe_request(handle_a(), after2, pinned_through.clone(), json!(1), 0.0);
    let p2 = record_value(&observe(&store, clock_dyn.as_ref(), &grant, &r2).expect("p2")).clone();
    assert_eq!(p2["items"][0]["event_ref"]["sequence"], json!(5));
    assert_eq!(p2["next"]["sequence"], json!(5));
    assert_eq!(p2["has_more"], json!(true));

    let after5 = p2["next"].clone();
    let r3 = observe_request(handle_a(), after5, pinned_through.clone(), json!(1), 0.0);
    let p3 = record_value(&observe(&store, clock_dyn.as_ref(), &grant, &r3).expect("p3")).clone();
    assert_eq!(p3["items"][0]["event_ref"]["sequence"], json!(6));
    assert_eq!(p3["next"]["sequence"], json!(6));
    // Trailing seq7 is unscanned (stopped on limit), so more remains.
    assert_eq!(p3["has_more"], json!(true));

    // Final page: only the trailing non-observation remains => empty page
    // that still advances next to the cutoff.
    let after6 = p3["next"].clone();
    let r4 = observe_request(handle_a(), after6, pinned_through.clone(), json!(10), 0.0);
    let p4 = record_value(&observe(&store, clock_dyn.as_ref(), &grant, &r4).expect("p4")).clone();
    assert_eq!(p4["items"].as_array().unwrap().len(), 0);
    assert_eq!(p4["next"]["sequence"], json!(7));
    assert_eq!(p4["has_more"], json!(false));

    // ---- Non-observation-only range still advances next to through ----
    let through4 = json!({
        "journal_id": JOURNAL,
        "last_sequence": 4,
        "head_hash": events[3]["event_hash"].clone(),
    });
    let after2b = cursor(handle_a(), 2, events[1]["event_hash"].clone());
    let rmid = observe_request(handle_a(), after2b, through4, json!(10), 0.0);
    let pmid =
        record_value(&observe(&store, clock_dyn.as_ref(), &grant, &rmid).expect("mid")).clone();
    assert_eq!(pmid["items"].as_array().unwrap().len(), 0);
    assert_eq!(pmid["next"]["sequence"], json!(4));
    assert_eq!(pmid["has_more"], json!(false));

    // ---- Empty page at the cutoff (after == through) ----
    let after7 = cursor(handle_a(), 7, events[6]["event_hash"].clone());
    let rend = observe_request(handle_a(), after7, pinned_through.clone(), json!(10), 0.0);
    let pend =
        record_value(&observe(&store, clock_dyn.as_ref(), &grant, &rend).expect("end")).clone();
    assert_eq!(pend["items"].as_array().unwrap().len(), 0);
    assert_eq!(pend["next"]["sequence"], json!(7));
    assert_eq!(pend["has_more"], json!(false));
    assert_eq!(
        pend["observation_close_ref"]["reason"],
        json!("not_observed")
    );

    // Live empty page at head likewise.
    let after7b = cursor(handle_a(), 7, events[6]["event_hash"].clone());
    let rlive_end = observe_request(handle_a(), after7b, inapplicable(), json!(10), 0.0);
    let plive_end =
        record_value(&observe(&store, clock_dyn.as_ref(), &grant, &rlive_end).expect("live end"))
            .clone();
    assert_eq!(plive_end["items"].as_array().unwrap().len(), 0);
    assert_eq!(plive_end["next"]["sequence"], json!(7));
    assert_eq!(plive_end["has_more"], json!(false));

    // ---- Handle scoping: B sees only its own projections ----
    let rb = observe_request(
        handle_b(),
        cursor(handle_b(), 0, inapplicable()),
        inapplicable(),
        json!(10),
        0.0,
    );
    let pb = record_value(&observe(&store, clock_dyn.as_ref(), &grant, &rb).expect("b")).clone();
    let bseqs: Vec<u64> = pb["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|it| it["event_ref"]["sequence"].as_u64().unwrap())
        .collect();
    assert_eq!(bseqs, vec![3, 7]);

    // ---- Oversized items are returned whole, never dropped ----
    let big = "x".repeat(16 * 1024);
    append_obs(
        &store,
        &grant,
        &digest,
        9,
        "listing_observed",
        json!({"handle": handle_a(), "kind": "task_output", "name": "big", "blob": big}),
    );
    let events2 = journal_events(&store, &grant);
    assert_eq!(events2.len(), 8);
    let after7c = cursor(handle_a(), 7, events[6]["event_hash"].clone());
    let rbig = observe_request(handle_a(), after7c, inapplicable(), json!(1), 0.0);
    let pbig =
        record_value(&observe(&store, clock_dyn.as_ref(), &grant, &rbig).expect("big")).clone();
    assert_eq!(pbig["items"].as_array().unwrap().len(), 1);
    assert_eq!(pbig["items"][0]["payload"]["blob"], json!(big));
    assert_eq!(pbig["next"]["sequence"], json!(8));

    // ---- Closure: handle-scoped producer_closed surfaces via close ref ----
    append_obs(
        &store,
        &grant,
        &digest,
        10,
        "producer_closed",
        json!({"handle": handle_a(), "kind": "task_output", "name": "close-marker"}),
    );
    let events3 = journal_events(&store, &grant);
    assert_eq!(events3.len(), 9);
    // Closure is lifecycle, not an observation item.
    let rclose = observe_request(
        handle_a(),
        cursor(handle_a(), 0, inapplicable()),
        inapplicable(),
        json!(20),
        0.0,
    );
    let pclose =
        record_value(&observe(&store, clock_dyn.as_ref(), &grant, &rclose).expect("close")).clone();
    let cseqs: Vec<u64> = pclose["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|it| it["event_ref"]["sequence"].as_u64().unwrap())
        .collect();
    assert!(
        !cseqs.contains(&9),
        "producer_closed must not appear as an observation item, got {cseqs:?}"
    );
    assert_eq!(pclose["observation_close_ref"]["sequence"], json!(9));
    assert_eq!(
        pclose["observation_close_ref"]["event_hash"],
        events3[8]["event_hash"]
    );

    // ---- Explicit faults: never skip, never advance past loss ----
    // Fixed cutoff with nonzero wait.
    let fixed_now = prefix(&store, &grant);
    let bad_wait = observe_request(
        handle_a(),
        cursor(handle_a(), 0, inapplicable()),
        fixed_now.clone(),
        json!(10),
        100.0,
    );
    let err = observe(&store, clock_dyn.as_ref(), &grant, &bad_wait).expect_err("wait must fail");
    assert_eq!(err.code, "wait_not_allowed_with_fixed_cutoff");

    // Cursor hash mismatch.
    let wrong_hash = "0".repeat(64);
    let bad_cursor = observe_request(
        handle_a(),
        cursor(handle_a(), 2, json!(wrong_hash)),
        inapplicable(),
        json!(10),
        0.0,
    );
    let err = observe(&store, clock_dyn.as_ref(), &grant, &bad_cursor).expect_err("mismatch");
    assert_eq!(err.code, "cursor_mismatch");

    // Cursor beyond cutoff.
    let head = prefix(&store, &grant);
    let head_last = head["last_sequence"].as_u64().unwrap();
    let beyond = observe_request(
        handle_a(),
        cursor(handle_a(), head_last, head["head_hash"].clone()),
        json!({
            "journal_id": JOURNAL,
            "last_sequence": 2,
            "head_hash": events[1]["event_hash"].clone(),
        }),
        json!(10),
        0.0,
    );
    let err = observe(&store, clock_dyn.as_ref(), &grant, &beyond).expect_err("beyond");
    assert_eq!(err.code, "cursor_beyond_cutoff");

    // Through ahead of the durable head.
    let future = observe_request(
        handle_a(),
        cursor(handle_a(), 0, inapplicable()),
        json!({
            "journal_id": JOURNAL,
            "last_sequence": head_last + 50,
            "head_hash": head["head_hash"].clone(),
        }),
        json!(10),
        0.0,
    );
    let err = observe(&store, clock_dyn.as_ref(), &grant, &future).expect_err("future");
    assert_eq!(err.code, "unknown_cutoff");

    // Through hash mismatch.
    let bad_head = observe_request(
        handle_a(),
        cursor(handle_a(), 0, inapplicable()),
        json!({
            "journal_id": JOURNAL,
            "last_sequence": 2,
            "head_hash": json!("f".repeat(64)),
        }),
        json!(10),
        0.0,
    );
    let err = observe(&store, clock_dyn.as_ref(), &grant, &bad_head).expect_err("bad head");
    assert_eq!(err.code, "cutoff_mismatch");

    // Handle mismatch between request and cursor.
    let mismatch = observe_request(
        handle_a(),
        cursor(handle_b(), 0, inapplicable()),
        inapplicable(),
        json!(10),
        0.0,
    );
    let err = observe(&store, clock_dyn.as_ref(), &grant, &mismatch).expect_err("handle");
    assert_eq!(err.code, "handle_mismatch");

    // Zero cursor with an established hash.
    let zero_bad = observe_request(
        handle_a(),
        cursor(handle_a(), 0, json!("a".repeat(64))),
        inapplicable(),
        json!(10),
        0.0,
    );
    let err = observe(&store, clock_dyn.as_ref(), &grant, &zero_bad).expect_err("zero");
    assert_eq!(err.code, "invalid_cursor");

    // max_items must be positive.
    let zero_items = observe_request(
        handle_a(),
        cursor(handle_a(), 0, inapplicable()),
        inapplicable(),
        json!(0),
        0.0,
    );
    let err = observe(&store, clock_dyn.as_ref(), &grant, &zero_items).expect_err("max");
    assert_eq!(err.code, "invalid_max_items");
}

#[test]
fn c38_normalize_native_report_independent_gating_and_retention() {
    let (store, grant, _clock, artifacts, digest) = setup_store();
    let artifacts_dyn: Arc<dyn ArtifactStore> = artifacts.clone();

    // Register source evidence: one handle observation to cite.
    append_obs(
        &store,
        &grant,
        &digest,
        2,
        "listing_observed",
        json!({"handle": handle_a(), "kind": "task_output", "name": "src"}),
    );
    let events = journal_events(&store, &grant);
    let src_ref = event_ref_of(&events[1]);

    let pin = || {
        json!({
            "id": "mapping-1",
            "version": "v1",
            "artifact_digest": "a".repeat(64),
        })
    };
    let policy = || {
        json!({
            "id": "policy-1",
            "version": "v1",
            "artifact_digest": "b".repeat(64),
        })
    };
    let received = || timepoint(5000);
    let report_base = |auth: &str, corr: &str, trace: &str| {
        json!({
            "raw_body": "{\"status\":\"completed\"}",
            "media_type": "application/json",
            "restricted": false,
            "channel": "terminal_response",
            "source_event": src_ref,
            "source_checks": {
                "authentication": auth,
                "correlation": corr,
                "trace_correlation": trace,
                "verification_policy": policy(),
                "matched_by": ["native_run_id"],
                "evidence_refs": [src_ref],
            },
            "mapping": pin(),
            "limitations": [],
            "claim_id": "claim-1",
            "scope": "execution_lifecycle",
            "native_state": "completed",
            "native_run_id": "run-9",
            "native_message_id": "msg-9",
            "made_at": missing("not_observed"),
            "received_at": received(),
        })
    };

    // Verified + matched => one faithful claim, exact bytes retained.
    let good = check("audit_log", report_base("verified", "matched", "matched"));
    let obs = record_value(
        &normalize_native_report(&store, artifacts_dyn.as_ref(), &grant, &good)
            .expect("verified must normalize"),
    )
    .clone();
    assert_eq!(obs["kind"], json!("native_report"));
    assert_eq!(obs["channel"], json!("terminal_response"));
    let claims = obs["normalized_claims"].as_array().expect("claims");
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0]["scope"], json!("execution_lifecycle"));
    assert_eq!(claims[0]["state"], json!("completed"));
    assert_eq!(claims[0]["application_assertions"], json!([]));
    assert_eq!(claims[0]["native_run_id"], json!("run-9"));
    assert_eq!(claims[0]["native_report"], obs["raw"]);
    assert_eq!(claims[0]["mapping"], pin());
    // Raw bytes are the exact native body.
    let raw = &obs["raw"];
    let raw_digest = raw["digest"].as_str().unwrap();
    assert_eq!(raw_digest.len(), 64);
    // Trace mismatch coexists with alternate correlation: still accepted.
    let alt = check(
        "audit_log",
        report_base("verified", "matched", "mismatched"),
    );
    let obs_alt = record_value(
        &normalize_native_report(&store, artifacts_dyn.as_ref(), &grant, &alt)
            .expect("trace mismatch with matched correlation still yields a claim"),
    )
    .clone();
    assert_eq!(
        obs_alt["normalized_claims"].as_array().unwrap().len(),
        1
    );

    // None / ack / HTTP success never become semantic success.
    for native in ["none", "acknowledged", "http_success"] {
        let mut v = report_base("verified", "matched", "matched");
        v["native_state"] = json!(native);
        let rep = check("audit_log", v);
        let o = record_value(
            &normalize_native_report(&store, artifacts_dyn.as_ref(), &grant, &rep)
                .expect("non-success must normalize"),
        )
        .clone();
        let c = &o["normalized_claims"].as_array().unwrap()[0];
        assert_eq!(c["state"], json!("unknown"), "native {native} must map to unknown");
        assert_eq!(c["application_assertions"], json!([]));
    }

    // Unverified or mismatched => zero accepted claims, never a fault.
    for (auth, corr) in [
        ("failed", "matched"),
        ("unknown", "matched"),
        ("verified", "mismatched"),
        ("verified", "unknown"),
    ] {
        let rep = check("audit_log", report_base(auth, corr, "matched"));
        let o = record_value(
            &normalize_native_report(&store, artifacts_dyn.as_ref(), &grant, &rep)
                .expect("unverified must return empty claims, not fault"),
        )
        .clone();
        assert_eq!(
            o["normalized_claims"].as_array().unwrap().len(),
            0,
            "auth={auth} corr={corr} must yield no claims"
        );
        // Exact bytes are still retained before gating.
        assert!(o["raw"]["digest"].as_str().unwrap().len() == 64);
    }

    // Unmapped shape => empty claims with explicit limitation.
    let mut unmapped = report_base("verified", "matched", "matched");
    unmapped["native_state"] = json!("blarg-unknown-shape");
    let rep = check("audit_log", unmapped);
    let o = record_value(
        &normalize_native_report(&store, artifacts_dyn.as_ref(), &grant, &rep).expect("unmapped"),
    )
    .clone();
    assert_eq!(o["normalized_claims"].as_array().unwrap().len(), 0);
    let lims = o["limitations"].as_array().unwrap();
    assert!(lims.iter().any(|l| l
        .as_str()
        .unwrap_or("")
        .contains("unsupported_native_shape")));

    // Unknown channel is a report fault.
    let mut bad_channel = report_base("verified", "matched", "matched");
    bad_channel["channel"] = json!("smoke_signal");
    let rep = check("audit_log", bad_channel);
    let err = normalize_native_report(&store, artifacts_dyn.as_ref(), &grant, &rep)
        .expect_err("bad channel must fault");
    assert_eq!(err.code, "unknown_channel");

    // Citing unregistered evidence is refused.
    let mut bad_ref = report_base("verified", "matched", "matched");
    bad_ref["source_event"] = json!({
        "journal_id": JOURNAL,
        "sequence": 999,
        "event_id": "evt-999-nope",
        "event_hash": "c".repeat(64),
        "pointer": "",
    });
    let rep = check("audit_log", bad_ref);
    let err = normalize_native_report(&store, artifacts_dyn.as_ref(), &grant, &rep)
        .expect_err("unregistered evidence must fault");
    assert_eq!(err.code, "evidence_not_registered");
}

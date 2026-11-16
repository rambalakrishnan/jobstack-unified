//! Conformance tests for `crawler_classifier`.
//!
//! * **[C15]** Classifier: exact correlation; malformed/duplicate output
//!   rejected; genuine conflict immutable.
//! * **[C16]** Shadow/bypass: claim-pinned policy; no bypass result row;
//!   genuine-PASS semantic precedence preserved.

use crawler_authority::{authorize_producer, Grant};
use crawler_classifier::{apply_cached_result, classify_batch, derive_semantic_candidate};
use crawler_hashing::{canonical_bytes, digest_bytes};
use crawler_inference_host::InferenceHost;
use crawler_schema::{record_value, validate, CheckedRecord, Fault};
use crawler_store::OwnerStore;
use crawler_time::ClockAuthority;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Mutex;

fn check(schema: &str, value: Value) -> CheckedRecord {
    validate(schema, value).expect("test fixture must validate")
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

fn timepoint(offset_ms: f64) -> Value {
    json!({
        "clock_id": "test-clock",
        "boot_id": "boot-1",
        "origin": "engine_measured",
        "monotonic_offset_ms": offset_ms,
        "utc_annotation": missing("not_observed"),
    })
}

struct TestClock {
    offset_ms: f64,
}

impl TestClock {
    fn new(offset_ms: f64) -> Self {
        Self { offset_ms }
    }
}

impl ClockAuthority for TestClock {
    fn now(&self) -> Result<CheckedRecord, Fault> {
        validate("audit_log", timepoint(self.offset_ms))
    }
}

fn binding_of(record: &CheckedRecord) -> String {
    digest_bytes(&canonical_bytes(record).expect("canonical bytes"))
}

fn test_grant() -> Grant {
    let manifest = check(
        "audit_log",
        json!({
            "manifest_id": "manifest-classifier",
            "producer_registry": [{
                "producer_id": "crawler_worker",
                "owner_domain": "crawler_ingest",
                "role": "external_input",
                "provenance": "server",
                "assertion_kind": "claim",
            }],
            "event_registry": [
                {"event_kind": "classifier_test", "permitted_provenance": ["server"]},
            ],
        }),
    );
    let principal = check(
        "audit_log",
        json!({
            "producer_id": "crawler_worker",
            "manifest_digest": binding_of(&manifest),
        }),
    );
    let submission = check("audit_log", json!({"event_kind": "classifier_test"}));
    authorize_producer(&principal, &submission, &manifest).expect("grant must issue")
}

// ---------------------------------------------------------------------------
// Fake inference host
// ---------------------------------------------------------------------------

struct FakeHost {
    dispatched: Mutex<Vec<Value>>,
    failure: Mutex<Option<(String, String)>>,
    verdict: Mutex<String>,
    confidence: Mutex<Value>,
    reason: Mutex<Value>,
    corrupt_hash: Mutex<bool>,
    duplicate: Mutex<bool>,
    extra: Mutex<Option<Value>>,
    stage_override: Mutex<Option<String>>,
    model_override: Mutex<Option<String>>,
}

impl FakeHost {
    fn new() -> Self {
        Self {
            dispatched: Mutex::new(Vec::new()),
            failure: Mutex::new(None),
            verdict: Mutex::new("PASS".to_string()),
            confidence: Mutex::new(json!(0.91)),
            reason: Mutex::new(json!("relevant experience matches")),
            corrupt_hash: Mutex::new(false),
            duplicate: Mutex::new(false),
            extra: Mutex::new(None),
            stage_override: Mutex::new(None),
            model_override: Mutex::new(None),
        }
    }

    fn dispatch_count(&self) -> usize {
        self.dispatched.lock().expect("lock").len()
    }

    fn set_failure(&self, code: &str, detail: &str) {
        *self.failure.lock().expect("lock") = Some((code.to_string(), detail.to_string()));
    }


    fn set_verdict(&self, verdict: &str) {
        *self.verdict.lock().expect("lock") = verdict.to_string();
    }

    fn set_confidence(&self, value: Value) {
        *self.confidence.lock().expect("lock") = value;
    }

    fn set_reason(&self, value: Value) {
        *self.reason.lock().expect("lock") = value;
    }

    fn set_corrupt_hash(&self, corrupt: bool) {
        *self.corrupt_hash.lock().expect("lock") = corrupt;
    }

    fn set_duplicate(&self, duplicate: bool) {
        *self.duplicate.lock().expect("lock") = duplicate;
    }

    fn set_extra(&self, extra: Option<Value>) {
        *self.extra.lock().expect("lock") = extra;
    }

    fn set_stage_override(&self, stage: Option<String>) {
        *self.stage_override.lock().expect("lock") = stage;
    }

    fn set_model_override(&self, model: Option<String>) {
        *self.model_override.lock().expect("lock") = model;
    }
}

impl InferenceHost for FakeHost {
    fn ensure_ready(&self, _manifest: &CheckedRecord) -> Result<CheckedRecord, Fault> {
        validate("audit_log", json!({"kind": "inference_readiness", "status": "ready"}))
    }

    fn infer(&self, batch: &CheckedRecord) -> Result<CheckedRecord, Fault> {
        let batch_value = record_value(batch).clone();
        self.dispatched.lock().expect("lock").push(batch_value.clone());
        if let Some((code, detail)) = self.failure.lock().expect("lock").clone() {
            return Err(Fault { code, detail });
        }
        let map = batch_value.as_object().expect("batch is object");
        let run_id = map.get("run_id").cloned().unwrap_or(json!("run-1"));
        let manifest_revision = map
            .get("manifest_revision")
            .cloned()
            .unwrap_or(json!("rev-1"));
        let batch_id = map.get("batch_id").cloned().unwrap_or(json!("batch-1"));
        let target = map.get("target").cloned().unwrap_or(json!("target-1"));
        let stage = map
            .get("stage")
            .and_then(Value::as_str)
            .unwrap_or("snippet")
            .to_string();
        let model_version = map
            .get("model_version")
            .and_then(Value::as_str)
            .unwrap_or("v1")
            .to_string();
        let items = map
            .get("items")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        let verdict = self.verdict.lock().expect("lock").clone();
        let confidence = self.confidence.lock().expect("lock").clone();
        let reason = self.reason.lock().expect("lock").clone();
        let corrupt = *self.corrupt_hash.lock().expect("lock");
        let stage_override = self.stage_override.lock().expect("lock").clone();
        let model_override = self.model_override.lock().expect("lock").clone();

        let mut outputs = Vec::new();
        for item in &items {
            let item_map = item.as_object().expect("item is object");
            let job_id = item_map
                .get("job_id")
                .and_then(Value::as_str)
                .unwrap_or("job-1")
                .to_string();
            let mut input_hash = item_map
                .get("input_hash")
                .and_then(Value::as_str)
                .unwrap_or("deadbeef")
                .to_string();
            if corrupt {
                // Flip the last hex character while staying in the hex alphabet.
                let last = input_hash.pop().unwrap_or('0');
                let flipped = if last == '0' { '1' } else { '0' };
                input_hash.push(flipped);
            }
            outputs.push(json!({
                "job_id": job_id,
                "input_hash": input_hash,
                "stage": stage_override.clone().unwrap_or_else(|| stage.clone()),
                "model_version": model_override.clone().unwrap_or_else(|| model_version.clone()),
                "verdict": verdict,
                "verdict_applied": verdict,
                "confidence": confidence,
                "reason": reason,
            }));
        }
        if *self.duplicate.lock().expect("lock") {
            if let Some(first) = outputs.first().cloned() {
                outputs.push(first);
            }
        }
        if let Some(extra) = self.extra.lock().expect("lock").clone() {
            outputs.push(extra);
        }

        let submitted = items.len() as u64;
        let accepted = outputs.len() as u64;
        validate(
            "audit_log",
            json!({
                "kind": "inference_results",
                "batch_id": batch_id,
                "run_id": run_id,
                "manifest_revision": manifest_revision,
                "target": target,
                "stage": stage,
                "model": {"id": "test-model", "version": model_version},
                "items": outputs,
                "submitted_count": submitted,
                "accepted_count": accepted,
                "partial": accepted < submitted,
                "observed_latency_ms": 3.0,
            }),
        )
    }

    fn containment_events(&self) -> Result<CheckedRecord, Fault> {
        validate(
            "audit_log",
            json!({"kind": "inference_containment_events", "total_events": 0}),
        )
    }
}

// ---------------------------------------------------------------------------
// Fake owner store
// ---------------------------------------------------------------------------

#[derive(Default)]
struct FakeStore {
    rows: Mutex<HashMap<String, Value>>,
    transactions: Mutex<Vec<Value>>,
    reads: Mutex<Vec<Value>>,
}

impl FakeStore {
    fn transactions(&self) -> Vec<Value> {
        self.transactions.lock().expect("lock").clone()
    }

    fn rows(&self) -> HashMap<String, Value> {
        self.rows.lock().expect("lock").clone()
    }

    fn transaction_operations(&self) -> Vec<String> {
        self.transactions()
            .iter()
            .filter_map(|tx| {
                tx.get("operation")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .collect()
    }
}

impl OwnerStore for FakeStore {
    fn transact(&self, _grant: &Grant, transaction: &CheckedRecord) -> Result<CheckedRecord, Fault> {
        let value = record_value(transaction).clone();
        let operation = value
            .get("operation")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        match operation.as_str() {
            "classifier_batch_insert" => {
                let results = value
                    .get("results")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                let mut rows = self.rows.lock().expect("lock");
                for row in &results {
                    if let Some(id) = row.get("result_id").and_then(Value::as_str) {
                        rows.insert(id.to_string(), row.clone());
                    }
                }
            }
            "classifier_bypass" | "classifier_conflict" | "lease_transition" => {
                // Evidence only; no classifier row is materialized.
            }
            other => {
                return Err(Fault {
                    code: "unknown_operation".to_string(),
                    detail: format!("fake store refuses operation {other:?}"),
                });
            }
        }
        let sequence = {
            let mut transactions = self.transactions.lock().expect("lock");
            transactions.push(value.clone());
            transactions.len() as u64
        };
        validate(
            "audit_log",
            json!({
                "durable": true,
                "journal_sequence": sequence,
                "transaction": value,
            }),
        )
    }

    fn read(&self, _grant: &Grant, query: &CheckedRecord) -> Result<CheckedRecord, Fault> {
        let value = record_value(query).clone();
        self.reads.lock().expect("lock").push(value.clone());
        let operation = value
            .get("operation")
            .and_then(Value::as_str)
            .unwrap_or("");
        match operation {
            "classifier_lookup" => {
                let result_id = value
                    .get("result_id")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let rows = self.rows.lock().expect("lock");
                let found = rows.get(result_id).cloned();
                validate(
                    "audit_log",
                    json!({"rows": found.map(|row| vec![row]).unwrap_or_default()}),
                )
            }
            other => Err(Fault {
                code: "unknown_query".to_string(),
                detail: format!("fake store refuses query {other:?}"),
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn model_pins() -> Value {
    json!({
        "id": "test-model",
        "version": "v1",
        "artifact_digest": digest_bytes(b"model-artifact"),
        "tokenizer_digest": digest_bytes(b"tokenizer"),
        "prompt_digest": digest_bytes(b"prompt"),
        "canonicalization_version": "canon/1",
    })
}

fn policy(shadow_mode: &str, bypass_enabled: bool) -> Value {
    json!({
        "policy_revision": "policy-r1",
        "pinned_revision": "policy-r1",
        "shadow_mode": shadow_mode,
        "bypass_enabled": bypass_enabled,
        "bypass_reason": if bypass_enabled {
            json!("slm_bypass_on_failure")
        } else {
            missing("not_applicable")
        },
    })
}

fn batch_item(job_id: &str) -> Value {
    json!({
        "job_id": job_id,
        "title": "Senior Engineer",
        "employer": "Acme",
        "text": "Build reliable distributed systems",
        "source_url": "https://example.com/jobs/1",
        "posted_date": "2026-01-15",
        "token_count": 12,
    })
}

fn batch_record(
    batch_id: &str,
    stage: &str,
    policy_value: Value,
    items: Vec<Value>,
) -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "batch_id": batch_id,
            "run_id": "run-1",
            "manifest_revision": "rev-1",
            "target": "target-1",
            "stage": stage,
            "model": model_pins(),
            "policy": policy_value,
            "collection_dwell_ms": 5,
            "lease_expires_at": timepoint(10000.0),
            "batch_token_budget": 1000,
            "items": items,
        }),
    )
}

fn expected_input_hash(stage: &str, model_version: &str, item: &Value) -> String {
    let title = item.get("title").and_then(Value::as_str).unwrap_or("");
    let employer = item.get("employer").and_then(Value::as_str).unwrap_or("");
    let text = item
        .get("text")
        .or_else(|| item.get("snippet_or_description"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let source_url = item.get("source_url").and_then(Value::as_str).unwrap_or("");
    let posted_date = item
        .get("posted_date")
        .and_then(Value::as_str)
        .unwrap_or("");
    let canonical = format!("{title}\n{employer}\n{text}\n{source_url}\n{posted_date}");
    let framed = format!("{canonical}\n{stage}\n{model_version}");
    digest_bytes(framed.as_bytes())
}

fn history_record(events: Vec<Value>, prior: Option<&str>) -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "events": events,
            "prior_candidate": match prior {
                Some(candidate) => json!(candidate),
                None => missing("not_applicable"),
            },
        }),
    )
}

fn closure_record(authoritative: bool) -> CheckedRecord {
    check(
        "audit_log",
        json!({"authoritative_closure": authoritative}),
    )
}

// ---------------------------------------------------------------------------
// C15 — Classifier
// ---------------------------------------------------------------------------

#[test]
fn c15_classifier_exact_correlation_malformed_duplicate_conflict() {
    let grant = test_grant();
    let clock = TestClock::new(1000.0);

    // Happy path: exact correlation persists one genuine row.
    {
        let host = FakeHost::new();
        let store = FakeStore::default();
        let item = batch_item("job-1");
        let batch = batch_record("batch-happy", "snippet", policy("off", false), vec![item.clone()]);
        let result = classify_batch(&host, &store, &clock, &grant, &batch)
            .expect("correlated PASS must classify");
        let value = record_value(&result).clone();
        assert_no_bare_nulls(&value);
        assert_eq!(value["kind"], json!("classifier_batch_result"));
        assert_eq!(value["accepted_count"], json!(1));
        assert_eq!(value["partial"], json!(false));
        let rows = value["results"].as_array().expect("results array");
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row["target"], json!("target-1"));
        assert_eq!(row["job_id"], json!("job-1"));
        assert_eq!(row["stage"], json!("snippet"));
        assert_eq!(row["model_version"], json!("v1"));
        assert_eq!(row["verdict"], json!("PASS"));
        assert_eq!(row["verdict_applied"], json!("PASS"));
        assert_eq!(row["policy_revision"], json!("policy-r1"));
        assert_eq!(row["application_revision"], json!(1));
        let expected_hash = expected_input_hash("snippet", "v1", &item);
        assert_eq!(row["input_hash"], json!(expected_hash));
        assert_eq!(
            row["result_id"],
            json!(format!("target-1:job-1:snippet:v1:{expected_hash}"))
        );
        // Store holds exactly one durable batch insert.
        assert_eq!(
            store.transaction_operations(),
            vec!["classifier_batch_insert".to_string()]
        );
        assert_eq!(store.rows().len(), 1);
        assert_eq!(host.dispatch_count(), 1);
    }

    // Mismatched input hash is rejected, never implicit PASS.
    {
        let host = FakeHost::new();
        host.set_corrupt_hash(true);
        let store = FakeStore::default();
        let batch = batch_record(
            "batch-mismatch",
            "snippet",
            policy("off", false),
            vec![batch_item("job-1")],
        );
        let error = classify_batch(&host, &store, &clock, &grant, &batch)
            .expect_err("mismatched input hash must be rejected");
        assert_eq!(error.code, "inference_output_mismatch");
        assert!(store.transactions().is_empty());
    }

    // Wrong stage echo is rejected.
    {
        let host = FakeHost::new();
        host.set_stage_override(Some("description".to_string()));
        let store = FakeStore::default();
        let batch = batch_record(
            "batch-stage",
            "snippet",
            policy("off", false),
            vec![batch_item("job-1")],
        );
        let error = classify_batch(&host, &store, &clock, &grant, &batch)
            .expect_err("mismatched stage must be rejected");
        assert_eq!(error.code, "inference_output_mismatch");
        assert!(store.transactions().is_empty());
    }

    // Wrong model echo is rejected.
    {
        let host = FakeHost::new();
        host.set_model_override(Some("v2".to_string()));
        let store = FakeStore::default();
        let batch = batch_record(
            "batch-model",
            "snippet",
            policy("off", false),
            vec![batch_item("job-1")],
        );
        let error = classify_batch(&host, &store, &clock, &grant, &batch)
            .expect_err("mismatched model must be rejected");
        assert_eq!(error.code, "inference_output_mismatch");
        assert!(store.transactions().is_empty());
    }

    // Malformed verdict is rejected.
    {
        let host = FakeHost::new();
        host.set_verdict("MAYBE");
        let store = FakeStore::default();
        let batch = batch_record(
            "batch-verdict",
            "snippet",
            policy("off", false),
            vec![batch_item("job-1")],
        );
        let error = classify_batch(&host, &store, &clock, &grant, &batch)
            .expect_err("malformed verdict must be rejected");
        assert_eq!(error.code, "inference_output_invalid");
        assert!(store.transactions().is_empty());
    }

    // Out-of-range confidence is rejected (non-finite/out-of-range bucket).
    for confidence in [json!(1.5), json!(-0.1), json!("high"), json!(f64::NAN.to_string())] {
        let host = FakeHost::new();
        host.set_confidence(confidence);
        let store = FakeStore::default();
        let batch = batch_record(
            "batch-confidence",
            "snippet",
            policy("off", false),
            vec![batch_item("job-1")],
        );
        let error = classify_batch(&host, &store, &clock, &grant, &batch)
            .expect_err("bad confidence must be rejected");
        assert_eq!(error.code, "inference_output_invalid");
        assert!(store.transactions().is_empty());
    }

    // Empty and overlong reasons are rejected.
    {
        let host = FakeHost::new();
        host.set_reason(json!("   "));
        let store = FakeStore::default();
        let batch = batch_record(
            "batch-reason-empty",
            "snippet",
            policy("off", false),
            vec![batch_item("job-1")],
        );
        let error = classify_batch(&host, &store, &clock, &grant, &batch)
            .expect_err("empty reason must be rejected");
        assert_eq!(error.code, "inference_output_invalid");
    }
    {
        let host = FakeHost::new();
        host.set_reason(json!("x".repeat(2001)));
        let store = FakeStore::default();
        let batch = batch_record(
            "batch-reason-long",
            "snippet",
            policy("off", false),
            vec![batch_item("job-1")],
        );
        let error = classify_batch(&host, &store, &clock, &grant, &batch)
            .expect_err("overlong reason must be rejected");
        assert_eq!(error.code, "inference_output_invalid");
    }

    // Duplicate outputs are rejected.
    {
        let host = FakeHost::new();
        host.set_duplicate(true);
        let store = FakeStore::default();
        let batch = batch_record(
            "batch-duplicate-output",
            "snippet",
            policy("off", false),
            vec![batch_item("job-1")],
        );
        let error = classify_batch(&host, &store, &clock, &grant, &batch)
            .expect_err("duplicate outputs must be rejected");
        assert_eq!(error.code, "inference_output_duplicate");
        assert!(store.transactions().is_empty());
    }

    // Extra undispatched job is rejected.
    {
        let host = FakeHost::new();
        host.set_extra(Some(json!({
            "job_id": "job-extra",
            "input_hash": "0".repeat(64),
            "stage": "snippet",
            "model_version": "v1",
            "verdict": "PASS",
            "verdict_applied": "PASS",
            "confidence": 0.9,
            "reason": "extra output",
        })));
        let store = FakeStore::default();
        let batch = batch_record(
            "batch-extra",
            "snippet",
            policy("off", false),
            vec![batch_item("job-1")],
        );
        let error = classify_batch(&host, &store, &clock, &grant, &batch)
            .expect_err("extra job must be rejected");
        assert_eq!(error.code, "inference_output_mismatch");
        assert!(store.transactions().is_empty());
    }

    // Duplicate input jobs are rejected before dispatch.
    {
        let host = FakeHost::new();
        let store = FakeStore::default();
        let batch = batch_record(
            "batch-duplicate-input",
            "snippet",
            policy("off", false),
            vec![batch_item("job-1"), batch_item("job-1")],
        );
        let error = classify_batch(&host, &store, &clock, &grant, &batch)
            .expect_err("duplicate input jobs must be rejected");
        assert_eq!(error.code, "duplicate_job");
        assert_eq!(host.dispatch_count(), 0);
    }

    // Batch ceilings are enforced without truncation.
    {
        let host = FakeHost::new();
        let store = FakeStore::default();
        let mut items = Vec::new();
        for index in 0..26 {
            items.push(batch_item(&format!("job-{index}")));
        }
        let batch = batch_record("batch-too-large", "snippet", policy("off", false), items);
        let error = classify_batch(&host, &store, &clock, &grant, &batch)
            .expect_err("26 items must exceed the ceiling");
        assert_eq!(error.code, "batch_too_large");
        assert_eq!(host.dispatch_count(), 0);
    }
    {
        let host = FakeHost::new();
        let store = FakeStore::default();
        let mut batch_value = record_value(&batch_record(
            "batch-dwell",
            "snippet",
            policy("off", false),
            vec![batch_item("job-1")],
        ))
        .clone();
        batch_value["collection_dwell_ms"] = json!(21);
        let batch = check("audit_log", batch_value);
        let error = classify_batch(&host, &store, &clock, &grant, &batch)
            .expect_err("dwell over 20ms must be rejected");
        assert_eq!(error.code, "collection_dwell_exceeded");
    }
    {
        let host = FakeHost::new();
        let store = FakeStore::default();
        let mut item = batch_item("job-1");
        item["truncated"] = json!(true);
        let batch = batch_record("batch-truncated", "snippet", policy("off", false), vec![item]);
        let error = classify_batch(&host, &store, &clock, &grant, &batch)
            .expect_err("truncated input must be rejected");
        assert_eq!(error.code, "input_truncated");
    }
    {
        let host = FakeHost::new();
        let store = FakeStore::default();
        let mut item = batch_item("job-1");
        item["token_count"] = missing("not_observed");
        let batch = batch_record(
            "batch-no-tokens",
            "snippet",
            policy("off", false),
            vec![item],
        );
        let error = classify_batch(&host, &store, &clock, &grant, &batch)
            .expect_err("unmeasured tokens must be rejected");
        assert_eq!(error.code, "unverifiable_token_budget");
    }

    // Genuine conflict is immutable: identical reuse accepted, conflicting
    // genuine bytes rejected and audited without overwriting.
    {
        let host = FakeHost::new();
        let store = FakeStore::default();
        let item = batch_item("job-1");
        let first = batch_record("batch-first", "snippet", policy("off", false), vec![item.clone()]);
        let first_result = classify_batch(&host, &store, &clock, &grant, &first)
            .expect("first insert must succeed");
        let first_row = record_value(&first_result)["results"][0].clone();

        // Identical reuse: same inputs, same genuine bytes.
        let second = batch_record(
            "batch-reuse",
            "snippet",
            policy("off", false),
            vec![item.clone()],
        );
        let reused = classify_batch(&host, &store, &clock, &grant, &second)
            .expect("identical reuse must be accepted");
        let reused_value = record_value(&reused).clone();
        assert_no_bare_nulls(&reused_value);
        assert_eq!(reused_value["results"].as_array().unwrap().len(), 0);
        let reused_rows = reused_value["reused"].as_array().expect("reused array");
        assert_eq!(reused_rows.len(), 1);
        assert_eq!(reused_rows[0]["verdict"], json!("PASS"));
        assert_eq!(reused_rows[0]["input_hash"], first_row["input_hash"]);
        assert_eq!(store.rows().len(), 1);

        // Conflicting genuine bytes: same key, different verdict.
        host.set_verdict("VETO");
        let third = batch_record(
            "batch-conflict",
            "snippet",
            policy("off", false),
            vec![item],
        );
        let error = classify_batch(&host, &store, &clock, &grant, &third)
            .expect_err("conflicting genuine bytes must be rejected");
        assert_eq!(error.code, "genuine_conflict");
        // The stored row is unchanged and the conflict was audited.
        assert_eq!(store.rows().len(), 1);
        let stored = store.rows().values().next().unwrap().clone();
        assert_eq!(stored["verdict"], json!("PASS"));
        assert!(store
            .transaction_operations()
            .contains(&"classifier_conflict".to_string()));
    }

    // Partial item success is allowed: the host may return a subset.
    {
        struct PartialHost;
        impl InferenceHost for PartialHost {
            fn ensure_ready(&self, _m: &CheckedRecord) -> Result<CheckedRecord, Fault> {
                validate("audit_log", json!({"status": "ready"}))
            }
            fn infer(&self, batch: &CheckedRecord) -> Result<CheckedRecord, Fault> {
                let map = record_value(batch).as_object().unwrap().clone();
                let items = map["items"].as_array().unwrap().clone();
                let first = &items[0];
                validate(
                    "audit_log",
                    json!({
                        "kind": "inference_results",
                        "batch_id": map["batch_id"],
                        "run_id": map["run_id"],
                        "manifest_revision": map["manifest_revision"],
                        "target": map["target"],
                        "stage": map["stage"],
                        "model": {"id": "test-model", "version": "v1"},
                        "items": [{
                            "job_id": first["job_id"],
                            "input_hash": first["input_hash"],
                            "stage": "snippet",
                            "model_version": "v1",
                            "verdict": "PASS",
                            "verdict_applied": "PASS",
                            "confidence": 0.8,
                            "reason": "partial success",
                        }],
                        "submitted_count": 2,
                        "accepted_count": 1,
                        "partial": true,
                    }),
                )
            }
            fn containment_events(&self) -> Result<CheckedRecord, Fault> {
                validate("audit_log", json!({"total_events": 0}))
            }
        }
        let host = PartialHost;
        let store = FakeStore::default();
        let batch = batch_record(
            "batch-partial",
            "snippet",
            policy("off", false),
            vec![batch_item("job-1"), batch_item("job-2")],
        );
        let result = classify_batch(&host, &store, &clock, &grant, &batch)
            .expect("partial success must be allowed");
        let value = record_value(&result).clone();
        assert_eq!(value["partial"], json!(true));
        assert_eq!(value["accepted_count"], json!(1));
        assert_eq!(value["results"].as_array().unwrap().len(), 1);
    }
}

// ---------------------------------------------------------------------------
// C16 — Shadow/bypass
// ---------------------------------------------------------------------------

#[test]
fn c16_shadow_bypass_claim_pinned_no_row_pass_precedence() {
    let grant = test_grant();
    let clock = TestClock::new(2000.0);

    // Claim-pinned policy: batch revision must equal the pinned revision.
    {
        let host = FakeHost::new();
        let store = FakeStore::default();
        let mut bad_policy = policy("off", false);
        bad_policy["policy_revision"] = json!("policy-r2");
        let batch = batch_record("batch-policy", "snippet", bad_policy, vec![batch_item("job-1")]);
        let error = classify_batch(&host, &store, &clock, &grant, &batch)
            .expect_err("in-flight policy change must be rejected");
        assert_eq!(error.code, "claim_policy_changed");
        assert_eq!(host.dispatch_count(), 0);
    }

    // Snippet shadow never applies to descriptions.
    {
        let host = FakeHost::new();
        let store = FakeStore::default();
        let batch = batch_record(
            "batch-shadow-desc",
            "description",
            policy("on", false),
            vec![batch_item("job-1")],
        );
        let error = classify_batch(&host, &store, &clock, &grant, &batch)
            .expect_err("snippet shadow on descriptions must be rejected");
        assert_eq!(error.code, "shadow_not_applicable");
    }

    // Snippet shadow-on: raw genuine VETO preserved, applied PASS.
    {
        let host = FakeHost::new();
        host.set_verdict("VETO");
        let store = FakeStore::default();
        let batch = batch_record(
            "batch-shadow",
            "snippet",
            policy("on", false),
            vec![batch_item("job-1")],
        );
        let result = classify_batch(&host, &store, &clock, &grant, &batch)
            .expect("shadowed classification must succeed");
        let value = record_value(&result).clone();
        assert_no_bare_nulls(&value);
        let row = &value["results"][0];
        assert_eq!(row["verdict"], json!("VETO"));
        assert_eq!(row["verdict_applied"], json!("PASS"));
    }

    // Bypass writes no classifier row and no synthetic classifier object.
    {
        let host = FakeHost::new();
        host.set_failure("inference_timeout", "the model timed out");
        let store = FakeStore::default();
        let batch = batch_record(
            "batch-bypass",
            "snippet",
            policy("off", true),
            vec![batch_item("job-1"), batch_item("job-2")],
        );
        let result = classify_batch(&host, &store, &clock, &grant, &batch)
            .expect("bypass-enabled failure must complete");
        let value = record_value(&result).clone();
        assert_no_bare_nulls(&value);
        assert_eq!(value["results"].as_array().unwrap().len(), 0);
        assert_eq!(value["accepted_count"], json!(0));
        let bypassed = value["bypassed"].as_array().expect("bypassed array");
        assert_eq!(bypassed.len(), 2);
        for entry in bypassed {
            assert_eq!(entry["verdict_applied"], json!("PASS"));
            assert_eq!(entry["bypass_reason"], json!("slm_bypass_on_failure"));
            assert!(entry["genuine"].is_object());
            assert_eq!(entry["genuine"]["reason"], json!("not_applicable"));
        }
        // Only bypass evidence was journaled; no classifier row exists.
        assert_eq!(
            store.transaction_operations(),
            vec!["classifier_bypass".to_string()]
        );
        assert!(store.rows().is_empty());
    }

    // Bypass disabled: the inference failure propagates with no row.
    {
        let host = FakeHost::new();
        host.set_failure("inference_timeout", "the model timed out");
        let store = FakeStore::default();
        let batch = batch_record(
            "batch-no-bypass",
            "snippet",
            policy("off", false),
            vec![batch_item("job-1")],
        );
        let error = classify_batch(&host, &store, &clock, &grant, &batch)
            .expect_err("bypass-disabled failure must propagate");
        assert_eq!(error.code, "inference_timeout");
        assert!(store.transactions().is_empty());
        assert!(store.rows().is_empty());
    }

    // apply_cached_result: claim-pinned revision, shadow rules, history.
    {
        let host = FakeHost::new();
        let store = FakeStore::default();
        let batch = batch_record(
            "batch-cached",
            "snippet",
            policy("off", false),
            vec![batch_item("job-1")],
        );
        let classified = classify_batch(&host, &store, &clock, &grant, &batch)
            .expect("seed row must classify");
        let seed_row = record_value(&classified)["results"][0].clone();
        let seed = check("classifier_result", seed_row);

        // In-flight policy change is rejected.
        let bad_policy = check(
            "audit_log",
            json!({"policy_revision": "policy-r2", "shadow_mode": "off"}),
        );
        let pinned = check(
            "audit_log",
            json!({"stage": "snippet", "pinned_revision": "policy-r1"}),
        );
        let error = apply_cached_result(&seed, &bad_policy, &pinned)
            .expect_err("policy change must be rejected");
        assert_eq!(error.code, "policy_changed");

        // Snippet shadow on descriptions is rejected.
        let shadow_policy = check(
            "audit_log",
            json!({"policy_revision": "policy-r1", "shadow_mode": "on"}),
        );
        let desc_stage = check(
            "audit_log",
            json!({
                "stage": "description",
                "pinned_revision": "policy-r1",
                "applied_at": timepoint(3000.0),
            }),
        );
        let error = apply_cached_result(&seed, &shadow_policy, &desc_stage)
            .expect_err("description shadow must be rejected");
        assert_eq!(error.code, "shadow_not_applicable");

        // Shadow-on re-application preserves genuine VETO and appends history.
        host.set_verdict("VETO");
        let veto_batch = batch_record(
            "batch-veto",
            "snippet",
            policy("off", false),
            vec![batch_item("job-9")],
        );
        let veto_result = classify_batch(&host, &store, &clock, &grant, &veto_batch)
            .expect("veto seed must classify");
        let veto_row = record_value(&veto_result)["results"][0].clone();
        assert_eq!(veto_row["verdict"], json!("VETO"));
        assert_eq!(veto_row["verdict_applied"], json!("VETO"));
        let veto_record = check("classifier_result", veto_row);
        let shadow_same = check(
            "audit_log",
            json!({"policy_revision": "policy-r1", "shadow_mode": "on"}),
        );
        let snippet_stage = check(
            "audit_log",
            json!({
                "stage": "snippet",
                "pinned_revision": "policy-r1",
                "applied_at": timepoint(3000.0),
            }),
        );
        let shadowed = apply_cached_result(&veto_record, &shadow_same, &snippet_stage)
            .expect("shadow re-application must succeed");
        let shadowed_value = record_value(&shadowed).clone();
        assert_no_bare_nulls(&shadowed_value);
        assert_eq!(shadowed_value["verdict"], json!("VETO"));
        assert_eq!(shadowed_value["verdict_applied"], json!("PASS"));
        assert_eq!(shadowed_value["application_revision"], json!(2));
        let history = shadowed_value["application_history"]
            .as_array()
            .expect("history array");
        assert_eq!(history.len(), 2);
        assert_eq!(history[0]["verdict_applied"], json!("VETO"));
        assert_eq!(history[1]["verdict_applied"], json!("PASS"));
    }

    // derive_semantic_candidate: genuine-PASS precedence.
    {
        // Genuine applied PASS shortlists.
        let history = history_record(
            vec![json!({"genuine": "PASS", "applied": "PASS", "stage": "snippet"})],
            Some("DISCOVERED"),
        );
        let candidate =
            derive_semantic_candidate(&history, &closure_record(false)).expect("must derive");
        assert_eq!(
            record_value(&candidate)["semantic_candidate"],
            json!("SHORTLISTED")
        );

        // Genuine VETO stays discovered.
        let history = history_record(
            vec![json!({"genuine": "VETO", "applied": "VETO", "stage": "snippet"})],
            Some("DISCOVERED"),
        );
        let candidate =
            derive_semantic_candidate(&history, &closure_record(false)).expect("must derive");
        assert_eq!(
            record_value(&candidate)["semantic_candidate"],
            json!("DISCOVERED")
        );

        // No genuine verdict stays discovered.
        let history = history_record(vec![], Some("DISCOVERED"));
        let candidate =
            derive_semantic_candidate(&history, &closure_record(false)).expect("must derive");
        assert_eq!(
            record_value(&candidate)["semantic_candidate"],
            json!("DISCOVERED")
        );

        // Bypass alone stays discovered.
        let history = history_record(
            vec![json!({
                "genuine": missing("not_applicable"),
                "applied": "PASS",
                "stage": "snippet",
                "bypass": true,
                "bypass_reason": "slm_bypass_on_failure",
            })],
            Some("DISCOVERED"),
        );
        let candidate =
            derive_semantic_candidate(&history, &closure_record(false)).expect("must derive");
        assert_eq!(
            record_value(&candidate)["semantic_candidate"],
            json!("DISCOVERED")
        );

        // Shadowed raw VETO does not shortlist.
        let history = history_record(
            vec![json!({
                "genuine": "VETO",
                "applied": "PASS",
                "stage": "snippet",
                "shadowed": true,
            })],
            Some("DISCOVERED"),
        );
        let candidate =
            derive_semantic_candidate(&history, &closure_record(false)).expect("must derive");
        assert_eq!(
            record_value(&candidate)["semantic_candidate"],
            json!("DISCOVERED")
        );

        // A later bypass preserves an earlier applicable genuine applied PASS.
        let history = history_record(
            vec![
                json!({"genuine": "PASS", "applied": "PASS", "stage": "snippet"}),
                json!({
                    "genuine": missing("not_applicable"),
                    "applied": "PASS",
                    "stage": "snippet",
                    "bypass": true,
                    "bypass_reason": "slm_bypass_on_failure",
                }),
            ],
            Some("SHORTLISTED"),
        );
        let candidate =
            derive_semantic_candidate(&history, &closure_record(false)).expect("must derive");
        assert_eq!(
            record_value(&candidate)["semantic_candidate"],
            json!("SHORTLISTED")
        );

        // Authoritative closure supports CLOSED; veto never does.
        let history = history_record(
            vec![json!({"genuine": "VETO", "applied": "VETO", "stage": "snippet"})],
            Some("SHORTLISTED"),
        );
        let candidate =
            derive_semantic_candidate(&history, &closure_record(true)).expect("must derive");
        assert_eq!(
            record_value(&candidate)["semantic_candidate"],
            json!("CLOSED")
        );

        // Closed postings do not automatically reopen.
        let history = history_record(
            vec![json!({"genuine": "PASS", "applied": "PASS", "stage": "snippet"})],
            Some("CLOSED"),
        );
        let candidate =
            derive_semantic_candidate(&history, &closure_record(false)).expect("must derive");
        assert_eq!(
            record_value(&candidate)["semantic_candidate"],
            json!("CLOSED")
        );

        // Crawler never writes CLAIMED/APPLIED product state.
        let history = history_record(
            vec![json!({"genuine": "PASS", "applied": "PASS", "candidate": "CLAIMED"})],
            Some("DISCOVERED"),
        );
        let error = derive_semantic_candidate(&history, &closure_record(false))
            .expect_err("product state must be refused");
        assert_eq!(error.code, "product_state_refused");
    }
}

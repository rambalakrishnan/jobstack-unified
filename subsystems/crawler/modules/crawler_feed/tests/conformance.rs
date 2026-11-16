//! Conformance test for [C42]: output completeness.
//!
//! A `complete` feed manifest describes its own output contract; it never
//! implies proven discovery, pagination completeness, suitability, permission
//! to apply, or application success. The test drives the real owner journal
//! (`MemoryOwnerStore`) and immutable artifact store (`MemoryArtifactStore`)
//! through the module under test:
//!
//! * a complete feed honestly carries an unproven/empty partition alongside a
//!   proven one, listing-only vetoes without fabricated details, revision
//!   vectors, selection policy, verified cutoff, limitations with explicit
//!   disclaimers, and required evidence;
//! * an empty feed still carries coverage and disclaimers;
//! * suitability/permission/applied/proven-discovery claims, materialized
//!   listing-only details, unknown pipeline states, policy-excluded failures,
//!   empty coverage/evidence, bad digests, cutoffs beyond the head, and
//!   revision/entity mismatches all fault.

use crawler_artifacts::{ArtifactStore, MemoryArtifactStore};
use crawler_authority::{authorize_producer, Grant};
use crawler_feed::publish_feed;
use crawler_hashing::{canonical_bytes, digest_bytes};
use crawler_schema::{record_value, validate, CheckedRecord, Fault};
use crawler_store::{MemoryOwnerStore, OwnerStore};
use crawler_time::ClockAuthority;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

const JOURNAL: &str = "crawler-feed-journal";
const RUN: &str = "run-feed-1";
const PRODUCER: &str = "feed-writer";
const OWNER: &str = "crawler";
const TARGET: &str = "IL";
const FEED_EVENT: &str = "feed_published";
const REGISTRATION_DIGEST: &str =
    "b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7";
const TASK_DIGEST: &str =
    "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn check(schema: &str, value: Value) -> CheckedRecord {
    validate(schema, value).expect("test fixture must validate")
}

fn copy(record: &CheckedRecord) -> CheckedRecord {
    check("audit_log", record_value(record).clone())
}

fn binding_of(record: &CheckedRecord) -> String {
    digest_bytes(&canonical_bytes(record).expect("canonical bytes must exist"))
}

fn missing(reason: &str, detail: &str) -> Value {
    json!({"value": Value::Null, "reason": reason, "detail": detail})
}

fn timepoint(offset_ms: u64) -> Value {
    json!({
        "clock_id": "feed-clock",
        "boot_id": "boot-1",
        "origin": "engine_measured",
        "monotonic_offset_ms": offset_ms,
        "utc_annotation": missing("not_observed", "no UTC annotation"),
    })
}

struct FixedClock {
    tick: AtomicU64,
}

impl FixedClock {
    fn new() -> Self {
        Self {
            tick: AtomicU64::new(0),
        }
    }
}

impl ClockAuthority for FixedClock {
    fn now(&self) -> Result<CheckedRecord, Fault> {
        let offset = self.tick.fetch_add(1, Ordering::SeqCst);
        validate("audit_log", timepoint(1_000 + offset))
    }
}

fn manifest_fixture() -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "manifest_id": "manifest-feed-1",
            "producer_registry": [
                {
                    "producer_id": PRODUCER,
                    "owner_domain": OWNER,
                    "role": "external_input",
                    "provenance": "server",
                    "assertion_kind": "claim",
                },
            ],
            "event_registry": [
                {"event_kind": "manifest_admitted", "permitted_provenance": ["server"]},
                {"event_kind": FEED_EVENT, "permitted_provenance": ["server"]},
            ],
        }),
    )
}

fn principal_of(manifest: &CheckedRecord) -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "producer_id": PRODUCER,
            "manifest_digest": binding_of(manifest),
        }),
    )
}

fn grant_for(manifest: &CheckedRecord, event_kind: &str) -> Grant {
    let principal = principal_of(manifest);
    let submission = check("audit_log", json!({"event_kind": event_kind}));
    authorize_producer(&principal, &submission, manifest).expect("producer grant must issue")
}

struct Fixture {
    store: MemoryOwnerStore,
    artifacts: MemoryArtifactStore,
    grant: Grant,
}

fn fixture() -> Fixture {
    let manifest = manifest_fixture();
    // The store needs an artifact handle for admission; the feed path uses a
    // separate direct handle below. Both are empty at start so either could
    // serve; the store's handle is only for its own durability checks.
    let store_artifacts: Arc<dyn ArtifactStore> = Arc::new(MemoryArtifactStore::new());
    let store = MemoryOwnerStore::new(
        copy(&manifest),
        Arc::new(FixedClock::new()),
        store_artifacts,
    )
    .expect("owner store must admit its manifest");
    let admission_grant = grant_for(&manifest, "manifest_admitted");
    let admission = check(
        "audit_log",
        json!({
            "operation": "admit_manifest",
            "journal_id": JOURNAL,
            "run_id": RUN,
            "manifest": record_value(&manifest).clone(),
            "principal": {
                "producer_id": PRODUCER,
                "manifest_digest": binding_of(&manifest),
            },
        }),
    );
    store
        .transact(&admission_grant, &admission)
        .expect("journal admission must commit");
    Fixture {
        store,
        artifacts: MemoryArtifactStore::new(),
        grant: grant_for(&manifest, FEED_EVENT),
    }
}

/// Real evidence ref citing the admission event (sequence 1).
fn real_ref(fixture: &Fixture) -> Value {
    let query = check(
        "audit_log",
        json!({"query": "event", "journal_id": JOURNAL, "journal_sequence": 1}),
    );
    let event = fixture
        .store
        .read(&fixture.grant, &query)
        .expect("admission event must read");
    let map = record_value(&event).as_object().expect("event object");
    json!({
        "journal_id": JOURNAL,
        "sequence": 1,
        "event_id": map.get("event_id").cloned().unwrap_or(json!("evt-1")),
        "event_hash": map.get("event_hash").cloned().unwrap_or(json!(REGISTRATION_DIGEST)),
        "pointer": "/payload",
    })
}

fn logical_row(target: &str, job_id: &str, crawler_rev: u64, downstream_rev: u64) -> Value {
    let downstream_snapshot = if downstream_rev == 0 {
        missing("not_observed", "no downstream revision published in this view")
    } else {
        json!({"track": "t", "marker": "product-owned"})
    };
    json!({
        "record_type": "logical_row",
        "entity": {"entity_type": "job", "target": target, "job_id": job_id},
        "registration_digest": REGISTRATION_DIGEST,
        "version_vector": [
            {"domain": "crawler", "revision": crawler_rev},
            {"domain": "downstream", "revision": downstream_rev},
        ],
        "domains": {
            "crawler": {"revision": crawler_rev, "snapshot": {"acquisition": {"status": "complete"}}},
            "downstream": {"revision": downstream_rev, "snapshot": downstream_snapshot},
        },
    })
}

fn listing(target: &str, job_id: &str, state: &str) -> Value {
    json!({
        "target": target,
        "job_id": job_id,
        "pipeline_state": state,
        "listing_page_url": "https://example.test/jobs",
        "source_url": format!("https://example.test/jobs/{job_id}"),
    })
}

fn coverage(target: &str, run_id: &str, partition: &str, proven: bool, evidence: Value) -> Value {
    json!({
        "record_type": "crawler_coverage_export",
        "target": target,
        "run_id": run_id,
        "partition_id": partition,
        "proof": {"pagination_coverage_proven": proven},
        "evidence_refs": [evidence],
    })
}

fn base_request_value(evidence: &Value) -> Value {
    json!({
        "feed_id": "feed-1",
        "run_id": RUN,
        "task_digest": TASK_DIGEST,
        "selection_policy": {
            "include_failed": true,
            "include_render_failed": true,
            "policy_pin": "policy-v1",
        },
        "cutoff": {"journal_id": JOURNAL, "through": 1},
        "completeness": "complete",
        "jobs": [
            {
                "entity": {"entity_type": "job", "target": TARGET, "job_id": "job-1"},
                "logical_row": logical_row(TARGET, "job-1", 1, 0),
                "crawler_revision": 1,
                "downstream_revision": 0,
                "evidence_refs": [evidence.clone()],
            },
        ],
        "listing_only": [
            {
                "target": TARGET,
                "job_id": "job-2",
                "listing": listing(TARGET, "job-2", "vetoed"),
                "pipeline_state": "vetoed",
                "detail_materialized": false,
                "evidence_refs": [evidence.clone()],
            },
        ],
        "coverage": [
            coverage(TARGET, RUN, "p-proven", true, evidence.clone()),
            coverage(TARGET, RUN, "p-empty", false, evidence.clone()),
        ],
        "limitations": ["Illinois slice only; Oregon solver unavailable."],
        "evidence_refs": [evidence.clone()],
    })
}

fn request_of(value: Value) -> CheckedRecord {
    check("audit_log", value)
}

fn read_artifact(fixture: &Fixture, reference: &Value) -> Value {
    let record = check("audit_log", reference.clone());
    let bytes = fixture
        .artifacts
        .read(&fixture.grant, &record)
        .expect("feed artifact must read back");
    serde_json::from_slice(&bytes).expect("feed artifact bytes must be JSON")
}

fn assert_no_banned_text(value: &Value) {
    let text = serde_json::to_string(value).expect("manifest must serialize");
    let folded = text.to_ascii_lowercase();
    // Keys assert claims; values here are standalone tokens in the serialized
    // form. Serialized free text (limitations) legitimately discusses these
    // concepts, so only exact key encodings are rejected.
    for banned in [
        "\"suitability\"",
        "\"permission_to_apply\"",
        "\"permission\"",
        "\"discovery_proven\"",
        "\"coverage_proven\"",
        "\"proven_discovery\"",
        "\"application_success\"",
        "\"downstream_value\"",
    ] {
        assert!(
            !folded.contains(banned),
            "manifest must not carry banned key {banned}: {text}"
        );
    }
    assert!(
        !folded.contains("\"applied\"")
            || folded.contains("verdict_applied"),
        "manifest must not assert APPLIED: {text}"
    );
}

// ---------------------------------------------------------------------------
// C42 — output completeness
// ---------------------------------------------------------------------------

#[test]
fn c42_complete_manifest_cannot_imply_proven_discovery_or_application_success() {
    let fixture = fixture();
    let evidence = real_ref(&fixture);

    // Complete feed honestly describing an incomplete partition.
    let base = base_request_value(&evidence);
    let output = publish_feed(
        &fixture.store,
        &fixture.artifacts,
        &fixture.grant,
        &request_of(base.clone()),
    )
    .expect("complete honest feed must publish");
    let out = record_value(&output);
    assert_eq!(out.get("completeness").and_then(Value::as_str), Some("complete"));
    assert_eq!(out.get("kind").and_then(Value::as_str), Some("crawler_feed"));
    assert_eq!(out.get("name").and_then(Value::as_str), Some("feed-1"));
    let manifest = out.get("manifest").expect("output must embed its manifest");
    assert_eq!(
        manifest.get("record_type").and_then(Value::as_str),
        Some("crawler_job_feed")
    );
    assert_eq!(
        manifest.get("schema_version").and_then(Value::as_str),
        Some("crawler-seam/0.1.0")
    );
    // Required §4.4 fields all present.
    for field in [
        "feed_id",
        "run_id",
        "task_digest",
        "selection_policy",
        "cutoff",
        "jobs",
        "listing_only",
        "coverage",
        "limitations",
        "evidence_refs",
    ] {
        assert!(
            manifest.get(field).is_some(),
            "manifest must carry {field}"
        );
    }
    // Cutoff is a verified journal prefix at the requested sequence.
    let cutoff = manifest.get("cutoff").expect("cutoff");
    assert_eq!(
        cutoff.get("journal_id").and_then(Value::as_str),
        Some(JOURNAL)
    );
    assert_eq!(
        cutoff.get("last_sequence").and_then(Value::as_u64),
        Some(1)
    );
    let head = cutoff
        .get("head_hash")
        .and_then(Value::as_str)
        .expect("cutoff head");
    assert_eq!(head.len(), 64);
    // Selection policy echoed.
    let policy = manifest.get("selection_policy").expect("policy");
    assert_eq!(
        policy.get("include_failed").and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        policy.get("policy_pin").and_then(Value::as_str),
        Some("policy-v1")
    );
    // Manifest artifact reads back to the same feed.
    let artifact = out.get("artifact").expect("manifest artifact");
    let stored = read_artifact(&fixture, artifact);
    assert_eq!(
        stored.get("feed_id").and_then(Value::as_str),
        Some("feed-1")
    );
    assert_eq!(
        stored.get("jobs").and_then(Value::as_array).map(Vec::len),
        Some(1)
    );
    // Job entry: revision vector, readable row, matching revisions.
    let jobs = manifest.get("jobs").and_then(Value::as_array).expect("jobs");
    assert_eq!(jobs.len(), 1);
    assert_eq!(
        jobs[0].get("crawler_revision").and_then(Value::as_u64),
        Some(1)
    );
    assert_eq!(
        jobs[0].get("downstream_revision").and_then(Value::as_u64),
        Some(0)
    );
    let row = read_artifact(
        &fixture,
        jobs[0].get("logical_row").expect("job row ref"),
    );
    assert_eq!(
        row.get("record_type").and_then(Value::as_str),
        Some("logical_row")
    );
    // Listing-only: exact state, never materialized, readable listing.
    let listings = manifest
        .get("listing_only")
        .and_then(Value::as_array)
        .expect("listing_only");
    assert_eq!(listings.len(), 1);
    assert_eq!(
        listings[0].get("pipeline_state").and_then(Value::as_str),
        Some("vetoed")
    );
    assert_eq!(
        listings[0].get("detail_materialized").and_then(Value::as_bool),
        Some(false)
    );
    let stored_listing = read_artifact(
        &fixture,
        listings[0].get("listing").expect("listing ref"),
    );
    assert_eq!(
        stored_listing.get("pipeline_state").and_then(Value::as_str),
        Some("vetoed")
    );
    // Coverage carries both the proven and the empty/unproven partition even
    // though completeness is complete: completeness is about this contract.
    let coverage_refs = manifest
        .get("coverage")
        .and_then(Value::as_array)
        .expect("coverage");
    assert_eq!(coverage_refs.len(), 2);
    let mut proven_count = 0;
    let mut unproven_count = 0;
    for reference in coverage_refs {
        let export = read_artifact(&fixture, reference);
        assert_eq!(
            export.get("record_type").and_then(Value::as_str),
            Some("crawler_coverage_export")
        );
        match export
            .get("proof")
            .and_then(|proof| proof.get("pagination_coverage_proven"))
            .and_then(Value::as_bool)
        {
            Some(true) => proven_count += 1,
            Some(false) => unproven_count += 1,
            _ => panic!("coverage proof must carry pagination_coverage_proven"),
        }
    }
    assert_eq!(proven_count, 1);
    assert_eq!(unproven_count, 1);
    // Limitations preserve caller text and add the mandatory disclaimers.
    let limitations = manifest
        .get("limitations")
        .and_then(Value::as_array)
        .expect("limitations");
    let texts: Vec<&str> = limitations
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(texts.iter().any(|text| text.contains("Illinois slice only")));
    assert!(texts.iter().any(|text| text.contains(
        "Output completeness concerns this feed contract only"
    )));
    assert!(texts
        .iter()
        .any(|text| text.contains("not suitability or permission to apply")));
    assert!(texts
        .iter()
        .any(|text| text.contains("empty feed is not proof of empty target coverage")));
    assert_no_banned_text(manifest);

    // Empty feed still carries coverage and disclaimers; it proves nothing
    // about the target.
    let mut empty = base.clone();
    empty["jobs"] = json!([]);
    empty["listing_only"] = json!([]);
    let empty_out = publish_feed(
        &fixture.store,
        &fixture.artifacts,
        &fixture.grant,
        &request_of(empty),
    )
    .expect("empty feed with coverage must publish");
    let empty_manifest = record_value(&empty_out)
        .get("manifest")
        .expect("empty manifest");
    assert_eq!(
        empty_manifest
            .get("jobs")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );
    assert_eq!(
        empty_manifest
            .get("coverage")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(2)
    );
    assert_no_banned_text(empty_manifest);

    // Forbidden: every overreach or omission below must fault.
    let cases: Vec<(&str, Value)> = vec![
        ("suitability claim", {
            let mut value = base.clone();
            value["jobs"][0]["suitability"] = json!("suitable");
            value
        }),
        ("permission claim", {
            let mut value = base.clone();
            value["jobs"][0]["permission_to_apply"] = json!(true);
            value
        }),
        ("applied assertion", {
            let mut value = base.clone();
            value["listing_only"][0]["applied"] = json!(true);
            value
        }),
        ("proven discovery", {
            let mut value = base.clone();
            value["proven"] = json!(true);
            value
        }),
        ("materialized listing-only", {
            let mut value = base.clone();
            value["listing_only"][0]["detail_materialized"] = json!(true);
            value
        }),
        ("unknown pipeline state", {
            let mut value = base.clone();
            value["listing_only"][0]["pipeline_state"] = json!("bogus_state");
            value["listing_only"][0]["listing"]["pipeline_state"] = json!("bogus_state");
            value
        }),
        ("policy excludes failed", {
            let mut value = base.clone();
            value["selection_policy"]["include_failed"] = json!(false);
            value["listing_only"][0]["pipeline_state"] = json!("failed");
            value["listing_only"][0]["listing"]["pipeline_state"] = json!("failed");
            value
        }),
        ("policy excludes render_failed", {
            let mut value = base.clone();
            value["selection_policy"]["include_render_failed"] = json!(false);
            value["listing_only"][0]["pipeline_state"] = json!("render_failed");
            value["listing_only"][0]["listing"]["pipeline_state"] = json!("render_failed");
            value
        }),
        ("empty coverage", {
            let mut value = base.clone();
            value["coverage"] = json!([]);
            value
        }),
        ("empty evidence", {
            let mut value = base.clone();
            value["evidence_refs"] = json!([]);
            value
        }),
        ("zero crawler revision", {
            let mut value = base.clone();
            value["jobs"][0]["crawler_revision"] = json!(0);
            value
        }),
        ("revision mismatch", {
            let mut value = base.clone();
            value["jobs"][0]["crawler_revision"] = json!(2);
            value
        }),
        ("entity mismatch", {
            let mut value = base.clone();
            value["jobs"][0]["entity"]["job_id"] = json!("job-other");
            value
        }),
        ("crawler-authored downstream", {
            let mut value = base.clone();
            value["jobs"][0]["materials"] = json!([]);
            value
        }),
        ("bad task digest", {
            let mut value = base.clone();
            value["task_digest"] = json!("not-a-digest");
            value
        }),
        ("cutoff beyond head", {
            let mut value = base.clone();
            value["cutoff"]["through"] = json!(999);
            value
        }),
        ("bad completeness", {
            let mut value = base.clone();
            value["completeness"] = json!("certain");
            value
        }),
        ("missing limitations", {
            let mut value = base.clone();
            value["limitations"] = json!([json!("")]);
            value
        }),
    ];
    for (name, value) in cases {
        let attempt = publish_feed(
            &fixture.store,
            &fixture.artifacts,
            &fixture.grant,
            &request_of(value),
        );
        assert!(
            attempt.is_err(),
            "forbidden case must fault: {name}"
        );
    }
}

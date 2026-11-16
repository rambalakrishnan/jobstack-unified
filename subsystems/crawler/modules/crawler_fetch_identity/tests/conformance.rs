use crawler_fetch_identity::{
    compute_fetch_key, decide_acquisition_write, validate_metadata_only,
};
use crawler_normalization::{assemble_crawler_value, normalize_row};
use crawler_schema::{record_value, validate, CheckedRecord, SourceEntity};
use serde_json::{json, Value};

fn missing(reason: &str) -> Value {
    json!({"value": null, "reason": reason})
}
fn missing_detail(reason: &str, detail: &str) -> Value {
    json!({"value": null, "reason": reason, "detail": detail})
}
fn rec(schema: &str, value: Value) -> CheckedRecord {
    validate(schema, value).expect("fixture must satisfy schema gate")
}
fn digest_of(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}
fn hex_of(byte: char) -> String {
    byte.to_string().repeat(64)
}
fn sh(byte: char) -> Value {
    json!({
        "value": hex_of(byte),
        "profile": "crawler-fetch-key/1",
        "evidence_refs": [{"ref": "test"}],
    })
}
fn timepoint(offset: i64) -> Value {
    json!({
        "clock_id": "lease-clk",
        "boot_id": "boot-7",
        "origin": "engine_measured",
        "monotonic_offset_ms": offset,
        "utc_annotation": missing("not_observed"),
    })
}
fn erefs() -> Value {
    json!([{
        "journal_id": "j-1",
        "sequence": 10,
        "event_id": "evt-10",
        "event_hash": "abc",
        "pointer": "/row",
    }])
}
fn artifact(digest_byte: char) -> Value {
    json!({
        "digest": digest_of(digest_byte),
        "size_bytes": 128,
        "media_type": "application/octet-stream",
        "owner_domain": "crawler",
        "access": "restricted",
    })
}
fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

// ---- synthetic JobCrawlerValue fixtures ----

fn acquisition(fetch_key: Value, extra: Value) -> Value {
    let mut obj = serde_json::Map::new();
    obj.insert("source_url".to_string(), json!("https://example.com/jobs/1"));
    obj.insert("listing_page_url".to_string(), json!("https://example.com/listings?page=1"));
    obj.insert("fetch_key".to_string(), fetch_key);
    obj.insert("fetch_key_profile".to_string(), json!("crawler-fetch-key/1"));
    obj.insert(
        "fetch_identity".to_string(),
        json!({"phase_token": "B", "canonical_request": {
            "url": "https://example.com/jobs/1",
            "method": "GET",
            "body_hash": digest_of('e'),
            "header_identity_set": [],
        }}),
    );
    obj.insert("source_response".to_string(), artifact('b'));
    obj.insert("source_response_hash".to_string(), sh('a'));
    obj.insert(
        "extractor".to_string(),
        json!({"id": "ext-1", "version": "ext-1"}),
    );
    obj.insert("declarations".to_string(), json!([]));
    obj.insert(
        "content".to_string(),
        json!({"title": "Software Engineer", "employer": "Acme"}),
    );
    obj.insert("render_verdict".to_string(), json!("Pass"));
    obj.insert("render_basis".to_string(), json!("http-acquisition"));
    obj.insert("render_history".to_string(), json!([]));
    obj.insert("rendered_at".to_string(), timepoint(4000));
    obj.insert("evidence_refs".to_string(), erefs());
    if let Some(extra_obj) = extra.as_object() {
        for (k, v) in extra_obj {
            obj.insert(k.clone(), v.clone());
        }
    }
    Value::Object(obj)
}

fn job_value(acq: Value, processing: Value, discovery: Value, lineage: Value) -> CheckedRecord {
    rec(
        "audit_log",
        json!({
            "record_type": "JobCrawlerValue",
            "schema_version": "crawler-seam/0.1.0",
            "acquisition": acq,
            "processing": processing,
            "discovery": discovery,
            "replacement_lineage": lineage,
            "evidence_prefix": {"journal_id": "j-1", "last_sequence": 10, "head_hash": "abc123"},
            "evidence_refs": erefs(),
        }),
    )
}

fn processing(run: &str) -> Value {
    json!({
        "pipeline_state": "ready",
        "active_run_id": run,
        "lease": missing("not_applicable"),
        "genuine_results": [],
        "semantic_candidate": "DISCOVERED",
        "evidence_refs": erefs(),
    })
}
fn discovery(last_run: &str) -> Value {
    json!({
        "first_seen_run_id": "run-1",
        "last_seen_run_id": last_run,
        "coverage_refs": [{"ref": "cov-1"}],
        "evidence_refs": erefs(),
    })
}
fn lineage_inapplicable() -> Value {
    json!({"status": "Inapplicable", "detail": "no replacement committed"})
}

fn root(target: &str, job: &str) -> CheckedRecord {
    rec("audit_log", json!({"target": target, "job_id": job}))
}
fn identity_b(url: &str, method: &str, body: &str, headers: Value) -> CheckedRecord {
    rec(
        "audit_log",
        json!({
            "phase_token": "B",
            "canonical_request": {
                "url": url,
                "method": method,
                "body_hash": body,
                "header_identity_set": headers,
            },
        }),
    )
}
fn identity_a(url: &str) -> CheckedRecord {
    rec(
        "audit_log",
        json!({
            "phase_token": "A_full",
            "listing_source_url": url,
        }),
    )
}

// ================= C19: fetch identity =================

#[test]
fn c19_compute_b_deterministic_and_header_order_insensitive() {
    let r = root("illinois", "job-1");
    let body = digest_of('e');
    let h1 = json!([
        {"name": "accept", "values": ["text/html"]},
        {"name": "accept-language", "values": ["en-US", "en"]},
    ]);
    let h2 = json!([
        {"name": "accept-language", "values": ["en-US", "en"]},
        {"name": "accept", "values": ["text/html"]},
    ]);
    let k1 = compute_fetch_key(&r, &identity_b("https://example.com/jobs/1", "GET", &body, h1))
        .expect("B key");
    let k2 = compute_fetch_key(&r, &identity_b("https://example.com/jobs/1", "GET", &body, h2))
        .expect("B key reordered");
    assert!(is_hex64(&k1), "key must be 64 lowercase hex, got {k1:?}");
    assert_eq!(k1, k2, "header order must not affect the key");
    // Deterministic across calls.
    let k3 = compute_fetch_key(
        &r,
        &identity_b("https://example.com/jobs/1", "GET", &body, json!([])),
    )
    .expect("empty headers");
    assert!(is_hex64(&k3));
    assert_ne!(k1, k3, "representation headers are key inputs");
}

#[test]
fn c19_compute_b_url_canonicalization_and_query_order() {
    let r = root("illinois", "job-1");
    let body = digest_of('e');
    let base = compute_fetch_key(
        &r,
        &identity_b("https://example.com/jobs/1?b=2&a=1", "GET", &body, json!([])),
    )
    .unwrap();
    // Scheme/host case, default port, and fragment normalize away.
    let canon = compute_fetch_key(
        &r,
        &identity_b(
            "HTTPS://EXAMPLE.COM:443/jobs/1?b=2&a=1#frag",
            "GET",
            &body,
            json!([]),
        ),
    )
    .unwrap();
    assert_eq!(base, canon, "scheme/host/port/fragment must canonicalize");
    // Query order is preserved: reordering changes the key.
    let reordered = compute_fetch_key(
        &r,
        &identity_b("https://example.com/jobs/1?a=1&b=2", "GET", &body, json!([])),
    )
    .unwrap();
    assert_ne!(base, reordered, "query order must be preserved");
    // Non-default port is identity.
    let non_default = compute_fetch_key(
        &r,
        &identity_b("https://example.com:8443/jobs/1?b=2&a=1", "GET", &body, json!([])),
    )
    .unwrap();
    assert_ne!(base, non_default, "non-default port must affect the key");
    // http default port 80 strips.
    let http_a = compute_fetch_key(
        &r,
        &identity_b("http://example.com/jobs/1", "GET", &body, json!([])),
    )
    .unwrap();
    let http_b = compute_fetch_key(
        &r,
        &identity_b("http://example.com:80/jobs/1", "GET", &body, json!([])),
    )
    .unwrap();
    assert_eq!(http_a, http_b);
}

#[test]
fn c19_compute_b_method_body_and_representation_inputs() {
    let r = root("illinois", "job-1");
    let body_hex = hex_of('e');
    let body_digest = digest_of('e');
    // Bare hex and sha256: framing of the same body agree.
    let k_hex = compute_fetch_key(
        &r,
        &identity_b("https://example.com/jobs/1", "GET", &body_hex, json!([])),
    )
    .unwrap();
    let k_digest = compute_fetch_key(
        &r,
        &identity_b("https://example.com/jobs/1", "GET", &body_digest, json!([])),
    )
    .unwrap();
    assert_eq!(k_hex, k_digest);
    // Different body => different key.
    let k_other = compute_fetch_key(
        &r,
        &identity_b("https://example.com/jobs/1", "GET", &digest_of('f'), json!([])),
    )
    .unwrap();
    assert_ne!(k_hex, k_other);
    // Lowercase method rejected (must already be uppercase).
    let bad = compute_fetch_key(
        &r,
        &identity_b("https://example.com/jobs/1", "get", &body_digest, json!([])),
    );
    assert!(bad.is_err(), "lowercase method must be rejected");
    assert_eq!(bad.unwrap_err().code, "invalid_method");
    // Representation header value order and content are inputs.
    let v1 = compute_fetch_key(
        &r,
        &identity_b(
            "https://example.com/jobs/1",
            "GET",
            &body_digest,
            json!([{"name": "accept-language", "values": ["en", "fr"]}]),
        ),
    )
    .unwrap();
    let v2 = compute_fetch_key(
        &r,
        &identity_b(
            "https://example.com/jobs/1",
            "GET",
            &body_digest,
            json!([{"name": "accept-language", "values": ["fr", "en"]}]),
        ),
    )
    .unwrap();
    assert_ne!(v1, v2, "multivalue header order must be preserved");
}

#[test]
fn c19_compute_b_rejects_ephemeral_and_malformed_headers() {
    let r = root("illinois", "job-1");
    let body = digest_of('e');
    for ephemeral in [
        "cookie",
        "set-cookie",
        "authorization",
        "proxy-authorization",
        "www-authenticate",
        "session-id",
        "x-session-id",
    ] {
        let id = identity_b(
            "https://example.com/jobs/1",
            "GET",
            &body,
            json!([{"name": ephemeral, "values": ["secret"]}]),
        );
        let err = compute_fetch_key(&r, &id).expect_err("ephemeral must fault");
        assert_eq!(err.code, "ephemeral_header", "header {ephemeral}");
    }
    // Uppercase header name rejected (must be lowercase token).
    let upper = identity_b(
        "https://example.com/jobs/1",
        "GET",
        &body,
        json!([{"name": "Accept", "values": ["text/html"]}]),
    );
    assert_eq!(
        compute_fetch_key(&r, &upper).unwrap_err().code,
        "invalid_header_name"
    );
    // Duplicate header rejected.
    let dup = identity_b(
        "https://example.com/jobs/1",
        "GET",
        &body,
        json!([
            {"name": "accept", "values": ["a"]},
            {"name": "accept", "values": ["b"]},
        ]),
    );
    assert_eq!(
        compute_fetch_key(&r, &dup).unwrap_err().code,
        "duplicate_header"
    );
    // Empty values rejected.
    let empty = identity_b(
        "https://example.com/jobs/1",
        "GET",
        &body,
        json!([{"name": "accept", "values": []}]),
    );
    assert_eq!(
        compute_fetch_key(&r, &empty).unwrap_err().code,
        "invalid_headers"
    );
}

#[test]
fn c19_compute_a_full_identity_and_phase_separation() {
    let r = root("illinois", "job-1");
    let k1 = compute_fetch_key(&r, &identity_a("https://example.com/listings?page=1")).unwrap();
    assert!(is_hex64(&k1));
    // Canonicalization applies to A_full too.
    let k2 = compute_fetch_key(&r, &identity_a("HTTPS://EXAMPLE.COM:443/listings?page=1#x")).unwrap();
    assert_eq!(k1, k2);
    // Different listing URL => different key.
    let k3 = compute_fetch_key(&r, &identity_a("https://example.com/listings?page=2")).unwrap();
    assert_ne!(k1, k3);
    // B and A_full never collide for the same target/job/URL.
    let body_empty = format!("sha256:{}", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    let kb = compute_fetch_key(
        &r,
        &identity_b("https://example.com/listings?page=1", "GET", &body_empty, json!([])),
    )
    .unwrap();
    assert_ne!(k1, kb, "phase token separates B and A_full");
    // Different target/job => different key.
    let other = compute_fetch_key(&root("wisconsin", "job-1"), &identity_a("https://example.com/listings?page=1")).unwrap();
    assert_ne!(k1, other);
}

#[test]
fn c19_compute_rejects_hidden_inputs_and_ignores_root_extras() {
    // Extra identity fields (run, date, response hash, extractor, nonce) fault.
    let r = root("illinois", "job-1");
    let bad = rec(
        "audit_log",
        json!({
            "phase_token": "B",
            "canonical_request": {
                "url": "https://example.com/jobs/1",
                "method": "GET",
                "body_hash": digest_of('e'),
                "header_identity_set": [],
            },
            "run_id": "run-2",
            "extractor_version": "ext-2",
            "response_hash": digest_of('a'),
            "nonce": "abc",
        }),
    );
    let err = compute_fetch_key(&r, &bad).expect_err("hidden inputs must fault");
    assert_eq!(err.code, "undeclared_field");
    // Extra root fields are ignored, never hashed.
    let r_extra = rec(
        "audit_log",
        json!({
            "target": "illinois",
            "job_id": "job-1",
            "active_run_id": "run-999",
            "crawl_date": "2026-11-16",
            "source_response_hash": digest_of('f'),
            "extractor_version": "ext-999",
        }),
    );
    let id = identity_b("https://example.com/jobs/1", "GET", &digest_of('e'), json!([]));
    let k_plain = compute_fetch_key(&r, &id).unwrap();
    let k_extra = compute_fetch_key(&r_extra, &id).unwrap();
    assert_eq!(k_plain, k_extra, "root extras must not affect the key");
    // Unknown phase rejected.
    let bad_phase = rec("audit_log", json!({"phase_token": "C", "listing_source_url": "https://example.com/x"}));
    assert_eq!(
        compute_fetch_key(&r, &bad_phase).unwrap_err().code,
        "invalid_phase_token"
    );
}

// ================= C19: same-key no-op =================

#[test]
fn c19_decide_absent_root_accepts_initial_complete_domain() {
    let absent = rec("audit_log", missing_detail("not_observed", "no root yet"));
    let candidate = job_value(
        acquisition(json!(digest_of('a')), json!({})),
        processing("run-1"),
        discovery("run-1"),
        lineage_inapplicable(),
    );
    let out = decide_acquisition_write(&absent, &candidate).expect("absent root accepts");
    assert_eq!(
        record_value(&out).get("acquisition"),
        record_value(&candidate).get("acquisition")
    );
    // Incomplete candidate (missing fetch_key) rejected.
    let mut bad_acq = acquisition(json!(digest_of('a')), json!({}));
    bad_acq
        .as_object_mut()
        .unwrap()
        .insert("fetch_key".to_string(), missing("not_observed"));
    let bad = job_value(bad_acq, processing("run-1"), discovery("run-1"), lineage_inapplicable());
    let err = decide_acquisition_write(&absent, &bad).expect_err("incomplete must fault");
    assert_eq!(err.code, "incomplete_acquisition");
}

#[test]
fn c19_same_key_noop_preserves_acquisition_and_lineage_despite_changed_response_extractor_run() {
    // Existing committed domain.
    let existing = job_value(
        acquisition(json!(digest_of('a')), json!({})),
        processing("run-1"),
        discovery("run-1"),
        lineage_inapplicable(),
    );
    // Candidate under the SAME fetch key but with changed response bytes,
    // extractor pin, and run. SH-object framing must compare equal to Digest.
    let cand_acq = acquisition(
        sh('a'),
        json!({
            "source_response": artifact('c'),
            "source_response_hash": sh('c'),
            "extractor": {"id": "ext-2", "version": "ext-2"},
            "content": {"title": "HACKED", "employer": "HACKED"},
            "render_verdict": "Fail",
        }),
    );
    let lineage_hack = json!({"status": "Replaced", "detail": "forged link"});
    let candidate = job_value(
        cand_acq,
        processing("run-2"),
        discovery("run-2"),
        lineage_hack,
    );
    let decided = decide_acquisition_write(&existing, &candidate).expect("same key no-op");
    let out = record_value(&decided);
    // Acquisition and lineage exactly preserved from existing.
    assert_eq!(
        out.get("acquisition"),
        record_value(&existing).get("acquisition"),
        "acquisition must be a no-op under the same key"
    );
    assert_eq!(
        out.get("replacement_lineage"),
        record_value(&existing).get("replacement_lineage"),
        "lineage must be a no-op under the same key"
    );
    // Metadata slots advance from the candidate.
    assert_eq!(
        out.get("processing").and_then(|p| p.get("active_run_id")),
        Some(&json!("run-2"))
    );
    assert_eq!(
        out.get("discovery").and_then(|d| d.get("last_seen_run_id")),
        Some(&json!("run-2"))
    );
    // The decided result is a valid metadata-only transition from existing.
    validate_metadata_only(&existing, &decided).expect("decided must be metadata-only");
    // Installing the candidate acquisition directly would NOT be metadata-only.
    assert_eq!(
        validate_metadata_only(&existing, &candidate).unwrap_err().code,
        "acquisition_rewrite"
    );
}

#[test]
fn c19_decide_same_key_repair_not_authorized_and_changed_key_needs_archive() {
    // Same-key failed-render repair attempt is discarded, not installed.
    let failed_acq = acquisition(
        json!(digest_of('a')),
        json!({
            "content": {
                "title": missing("not_observed"),
                "employer": missing("not_observed"),
            },
            "render_verdict": "Fail",
        }),
    );
    let existing = job_value(
        failed_acq,
        processing("run-1"),
        discovery("run-1"),
        lineage_inapplicable(),
    );
    let repaired_acq = acquisition(
        json!(digest_of('a')),
        json!({
            "content": {"title": "Repaired", "employer": "Acme"},
            "render_verdict": "Pass",
        }),
    );
    let repair = job_value(
        repaired_acq,
        processing("run-1"),
        discovery("run-1"),
        lineage_inapplicable(),
    );
    let decided = decide_acquisition_write(&existing, &repair).expect("same key no-op");
    assert_eq!(
        record_value(&decided).get("acquisition"),
        record_value(&existing).get("acquisition"),
        "same-key repair must not be authorized"
    );
    // Changed key faults so the caller archives first.
    let changed_acq = acquisition(json!(digest_of('b')), json!({}));
    let changed = job_value(
        changed_acq,
        processing("run-1"),
        discovery("run-1"),
        lineage_inapplicable(),
    );
    let err = decide_acquisition_write(&existing, &changed).expect_err("changed key must fault");
    assert_eq!(err.code, "fetch_key_changed");
}

// ================= C19: metadata-only =================

#[test]
fn c19_validate_metadata_only_allows_discovery_lease_classification_semantic() {
    let before = job_value(
        acquisition(json!(digest_of('a')), json!({})),
        processing("run-1"),
        discovery("run-1"),
        lineage_inapplicable(),
    );
    // Advance every permitted metadata slot; keep acquisition+lineage identical.
    let after_processing = json!({
        "pipeline_state": "ready",
        "active_run_id": "run-2",
        "lease": {"lease_id": "lease-9", "owner": "worker-9"},
        "genuine_results": [{"ref": "cls-1", "verdict": "PASS"}],
        "final_genuine_result_id": "cls-1",
        "bypass": missing("not_applicable"),
        "semantic_candidate": "SHORTLISTED",
        "semantic_evidence": {"support": "journaled"},
        "evidence_refs": erefs(),
    });
    let after_discovery = json!({
        "first_seen_run_id": "run-1",
        "last_seen_run_id": "run-2",
        "coverage_refs": [{"ref": "cov-1"}, {"ref": "cov-2"}],
        "evidence_refs": erefs(),
    });
    let after = job_value(
        acquisition(json!(digest_of('a')), json!({})),
        after_processing,
        after_discovery,
        lineage_inapplicable(),
    );
    validate_metadata_only(&before, &after).expect("metadata transitions must commit");
    // Idempotent: identical records are trivially metadata-only.
    validate_metadata_only(&before, &before).expect("identical must pass");
}

#[test]
fn c19_validate_metadata_only_rejects_acquisition_and_lineage_rewrites() {
    let before = job_value(
        acquisition(json!(digest_of('a')), json!({})),
        processing("run-1"),
        discovery("run-1"),
        lineage_inapplicable(),
    );
    // Same fetch key but different content still rewrites acquisition.
    let acq_same_key_new_content =
        acquisition(json!(digest_of('a')), json!({"source_response": artifact('z')}));
    let after_acq = job_value(
        acq_same_key_new_content,
        processing("run-1"),
        discovery("run-1"),
        lineage_inapplicable(),
    );
    assert_eq!(
        validate_metadata_only(&before, &after_acq).unwrap_err().code,
        "acquisition_rewrite"
    );
    // Lineage rewrite rejected even with identical acquisition.
    let after_lin = job_value(
        acquisition(json!(digest_of('a')), json!({})),
        processing("run-1"),
        discovery("run-1"),
        json!({"status": "Replaced", "detail": "x"}),
    );
    assert_eq!(
        validate_metadata_only(&before, &after_lin).unwrap_err().code,
        "lineage_rewrite"
    );
    // Missing roots fault.
    let absent = rec("audit_log", missing_detail("not_observed", "no root"));
    assert_eq!(
        validate_metadata_only(&absent, &before).unwrap_err().code,
        "absent_root"
    );
}

// ================= C19: end-to-end via normalization =================

fn norm_evidence() -> CheckedRecord {
    rec(
        "audit_log",
        json!({
            "captured_at": timepoint(50_000),
            "evidence_prefix": {"journal_id": "j-1", "last_sequence": 10, "head_hash": "abc123"},
            "evidence_refs": erefs(),
        }),
    )
}
fn assembly_evidence(source_byte: char) -> CheckedRecord {
    rec(
        "audit_log",
        json!({
            "evidence_prefix": {"journal_id": "j-1", "last_sequence": 10, "head_hash": "abc123"},
            "evidence_refs": erefs(),
            "coverage_refs": [{"ref": "cov-1"}],
            "source_response": artifact(source_byte),
        }),
    )
}
fn common_claimable(run: &str) -> Value {
    json!({
        "target": "illinois",
        "job_id": "job-1",
        "active_run_id": run,
        "entity_revision": 1,
        "input_revision": 1,
        "retry_count": 0,
        "max_retries_effective": 3,
        "lease_id": missing("not_applicable"),
        "lease_owner": missing("not_applicable"),
        "leased_at": missing("not_applicable"),
        "lease_expires_at": missing("not_applicable"),
        "last_failure_reason": missing("not_applicable"),
        "created_at": timepoint(1000),
        "updated_at": timepoint(2000),
    })
}
fn merge(base: Value, extra: Value) -> Value {
    let mut map = base.as_object().cloned().unwrap();
    for (k, v) in extra.as_object().unwrap() {
        map.insert(k.clone(), v.clone());
    }
    Value::Object(map)
}
fn detail_source(run: &str, extractor: &str, response_byte: char, fetch_byte: char) -> Value {
    merge(
        common_claimable(run),
        json!({
            "source_url": "https://example.com/jobs/1",
            "fetch_key": sh(fetch_byte),
            "fetch_phase_token": "B",
            "request_params_json": {"url": "https://example.com/jobs/1", "method": "GET"},
            "source_response_hash": sh(response_byte),
            "extractor_version": extractor,
            "title": "Software Engineer",
            "employer": "Acme",
            "snippet": "Great job",
            "description": "Full description here",
            "posted_date": "2024-05-01",
            "content_fields_json": {"location": "Chicago, IL"},
            "render_verdict": "Pass",
            "render_basis": "http-acquisition",
            "render_history": [{
                "transport": "HttpClient",
                "operation": "http-acquisition",
                "verdict": "Pass",
                "basis": "http-acquisition",
                "response_hash": digest_of(response_byte),
                "evidence_refs": erefs(),
                "measurements": [],
            }],
            "rendered_at": timepoint(4000),
            "pipeline_state": "ready",
            "semantic_state": "active",
            "content_verdict": "PASS",
            "verdict_applied": "PASS",
            "snippet_classifier_result_ref": "cls-1",
            "description_classifier_result_ref": "cls-2",
            "final_genuine_result_ref": "cls-2",
            "bypass_reason": missing("not_applicable"),
            "crawler_revision": 1,
            "published_agent_revision": 1,
            "semantic_candidate": "DISCOVERED",
            "semantic_evidence_json": {"support": "journaled"},
        }),
    )
}
fn listing_source(last_run: &str) -> Value {
    merge(
        common_claimable("run-1"),
        json!({
            "first_seen_run_id": "run-1",
            "last_seen_run_id": last_run,
            "first_seen_at": timepoint(1100),
            "last_seen_at": timepoint(2100),
            "partition_id": "part-1",
            "listing_page_url": "https://example.com/listings?page=1",
            "source_url": "https://example.com/listings?page=1",
            "source_response_hash": sh('a'),
            "source_page_hash": sh('c'),
            "extractor_version": "ext-1",
            "title": "Software Engineer",
            "employer": "Acme",
            "snippet": "",
            "full_description": missing("not_applicable"),
            "posted_date": "2024-05-01",
            "extracted_fields_json": {"title": "Software Engineer"},
            "classification_surface": "phase_a_full_description",
            "pipeline_state": "pending_finalize",
            "content_verdict": missing("not_applicable"),
            "verdict_applied": missing("not_applicable"),
            "classifier_result_ref": missing("not_applicable"),
            "classification_policy_revision": missing("not_applicable"),
            "bypass_reason": missing("not_applicable"),
            "delegated_work_item_ref": missing("not_applicable"),
            "finalized_detail_ref": missing("not_applicable"),
        }),
    )
}

#[test]
fn c19_same_key_end_to_end_with_assembled_crawler_values() {
    let norm_ev = norm_evidence();
    // Existing: run-1 / ext-1 / response 'a', fetch key 'd'.
    let detail_a = normalize_row(
        SourceEntity::JobDetail,
        detail_source("run-1", "ext-1", 'a', 'd'),
        &norm_ev,
    )
    .expect("normalize detail a");
    let listing_a =
        normalize_row(SourceEntity::Listing, listing_source("run-1"), &norm_ev)
            .expect("normalize listing a");
    let existing =
        assemble_crawler_value(&[detail_a, listing_a], &assembly_evidence('b'))
            .expect("assemble existing");
    // Candidate: SAME fetch key 'd' but changed response/extractor/run.
    let detail_b = normalize_row(
        SourceEntity::JobDetail,
        detail_source("run-2", "ext-2", 'c', 'd'),
        &norm_ev,
    )
    .expect("normalize detail b");
    let listing_b =
        normalize_row(SourceEntity::Listing, listing_source("run-2"), &norm_ev)
            .expect("normalize listing b");
    let candidate =
        assemble_crawler_value(&[detail_b, listing_b], &assembly_evidence('c'))
            .expect("assemble candidate");
    // Sanity: assembled fetch keys match (same SH value).
    let fa = record_value(&existing)
        .get("acquisition")
        .and_then(|a| a.get("fetch_key"))
        .cloned()
        .unwrap();
    let fb = record_value(&candidate)
        .get("acquisition")
        .and_then(|a| a.get("fetch_key"))
        .cloned()
        .unwrap();
    assert_eq!(fa, fb, "fixtures must share the fetch key");
    // Sanity: acquisitions differ (response/extractor changed).
    assert_ne!(
        record_value(&existing).get("acquisition"),
        record_value(&candidate).get("acquisition"),
        "changed response/extractor must surface in acquisition"
    );
    let decided = decide_acquisition_write(&existing, &candidate).expect("same-key no-op");
    assert_eq!(
        record_value(&decided).get("acquisition"),
        record_value(&existing).get("acquisition"),
        "C19: acquisition unchanged despite changed response/extractor/run"
    );
    assert_eq!(
        record_value(&decided).get("replacement_lineage"),
        record_value(&existing).get("replacement_lineage"),
        "C19: lineage unchanged"
    );
    validate_metadata_only(&existing, &decided).expect("C19: metadata transitions still work");
    // Discovery advanced from the candidate.
    assert_eq!(
        record_value(&decided)
            .get("discovery")
            .and_then(|d| d.get("last_seen_run_id")),
        record_value(&candidate)
            .get("discovery")
            .and_then(|d| d.get("last_seen_run_id")),
    );
}

#[test]
fn c19_compute_key_round_trips_into_decide_comparison() {
    // A computed B key installed as Digest vs SH must compare equal.
    let r = root("illinois", "job-1");
    let key = compute_fetch_key(
        &r,
        &identity_b("https://example.com/jobs/1", "GET", &digest_of('e'), json!([])),
    )
    .unwrap();
    let digest = format!("sha256:{key}");
    let sh_val = json!({
        "value": key,
        "profile": "crawler-fetch-key/1",
        "evidence_refs": [{"ref": "test"}],
    });
    let existing = job_value(
        acquisition(json!(digest), json!({})),
        processing("run-1"),
        discovery("run-1"),
        lineage_inapplicable(),
    );
    let candidate = job_value(
        acquisition(sh_val, json!({"extractor": {"id": "ext-2", "version": "ext-2"}})),
        processing("run-2"),
        discovery("run-2"),
        lineage_inapplicable(),
    );
    let decided = decide_acquisition_write(&existing, &candidate).expect("Digest vs SH equal");
    assert_eq!(
        record_value(&decided).get("acquisition"),
        record_value(&existing).get("acquisition")
    );
}

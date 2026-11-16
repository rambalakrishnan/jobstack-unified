//! Conformance tests for [C41]: artifact access.
//!
//! Authorized immutable retrieval only; no arbitrary URL/path; full
//! size/digest verified.

use crawler_artifacts::{collect_artifacts, ArtifactStore, MemoryArtifactStore};
use crawler_authority::{authorize, authorize_producer, grant_record};
use crawler_hashing::{canonical_bytes, digest_bytes};
use crawler_schema::{record_value, validate, CheckedRecord};
use serde_json::{json, Value};

fn check(schema: &str, value: Value) -> CheckedRecord {
    validate(schema, value).expect("test fixture must validate")
}

fn binding_of(record: &CheckedRecord) -> String {
    digest_bytes(&canonical_bytes(record).expect("canonical bytes must exist"))
}

fn missing(reason: &str) -> Value {
    json!({"value": Value::Null, "reason": reason})
}

fn manifest_fixture() -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "manifest_id": "manifest-1",
            "producer_registry": [
                {
                    "producer_id": "origin-crawler",
                    "owner_domain": "crawler",
                    "role": "crawler_producer",
                    "provenance": "origin",
                    "assertion_kind": "observation",
                },
            ],
            "event_registry": [
                {
                    "event_kind": "listing_observed",
                    "permitted_provenance": ["origin"],
                },
            ],
        }),
    )
}

fn producer_principal(manifest: &CheckedRecord, producer_id: &str) -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "producer_id": producer_id,
            "manifest_digest": binding_of(manifest),
        }),
    )
}

fn registration_fixture() -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "registration_id": "channel-1",
            "principals": [
                {
                    "principal_id": "reader",
                    "verbs": ["Describe", "Prepare", "Observe", "CollectArtifacts"],
                    "connectors": ["jobs-connector"],
                    "control": false,
                    "owner_domain": "crawler",
                    "restricted_access": false,
                },
                {
                    "principal_id": "operator",
                    "verbs": ["Describe", "Prepare", "Start", "Observe", "RequestNativeCancel", "CloseObservationConnection", "CollectArtifacts", "ReleaseNativeContext", "Contain"],
                    "connectors": ["jobs-connector", "admin-connector"],
                    "control": true,
                    "owner_domain": "crawler",
                    "restricted_access": true,
                },
            ],
        }),
    )
}

fn connector_principal(registration: &CheckedRecord, principal_id: &str) -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "principal_id": principal_id,
            "registration_digest": binding_of(registration),
        }),
    )
}

fn reader_grant() -> crawler_authority::Grant {
    let registration = registration_fixture();
    let principal = connector_principal(&registration, "reader");
    let request = check(
        "audit_log",
        json!({"verb": "CollectArtifacts", "connector": "jobs-connector"}),
    );
    authorize(&principal, &request, &registration).expect("reader grant must issue")
}

fn operator_grant() -> crawler_authority::Grant {
    let registration = registration_fixture();
    let principal = connector_principal(&registration, "operator");
    let request = check(
        "audit_log",
        json!({"verb": "CollectArtifacts", "connector": "jobs-connector"}),
    );
    authorize(&principal, &request, &registration).expect("operator grant must issue")
}

fn origin_producer_grant() -> crawler_authority::Grant {
    let manifest = manifest_fixture();
    let principal = producer_principal(&manifest, "origin-crawler");
    let submission = check("audit_log", json!({"event_kind": "listing_observed"}));
    authorize_producer(&principal, &submission, &manifest).expect("producer grant must issue")
}

/// Rebind a reference to a different grant (same artifact, new binding).
fn rebind(reference: &CheckedRecord, grant: &crawler_authority::Grant) -> CheckedRecord {
    let mut obj = record_value(reference)
        .as_object()
        .expect("reference must be an object")
        .clone();
    obj.insert(
        "grant_digest".to_string(),
        Value::String(binding_of(grant_record(grant))),
    );
    check("audit_log", Value::Object(obj))
}

/// Inventory slot carrying the full (bound) reference.
fn slot(name: &str, reference: &CheckedRecord) -> Value {
    let digest = record_value(reference)["digest"].clone();
    json!({
        "name": name,
        "expected_digest": digest,
        "content": record_value(reference).clone(),
    })
}

/// Inventory slot carrying a bare reference (no grant binding); the
/// collector binds it to the reading grant.
fn slot_bare(name: &str, reference: &CheckedRecord) -> Value {
    let mut content = record_value(reference)
        .as_object()
        .expect("reference must be an object")
        .clone();
    content.remove("grant_digest");
    let digest = content["digest"].clone();
    json!({
        "name": name,
        "expected_digest": digest,
        "content": Value::Object(content),
    })
}

fn gc_cert(
    reference: &CheckedRecord,
    grant: &crawler_authority::Grant,
    fence: Value,
    decision: &str,
) -> CheckedRecord {
    let value = record_value(reference);
    let mut obj = serde_json::Map::new();
    obj.insert("digest".to_string(), value["digest"].clone());
    obj.insert(
        "grant_digest".to_string(),
        Value::String(binding_of(grant_record(grant))),
    );
    obj.insert("owner_domain".to_string(), value["owner_domain"].clone());
    obj.insert("fence".to_string(), fence);
    obj.insert("decision".to_string(), Value::String(decision.to_string()));
    check("audit_log", Value::Object(obj))
}

fn valid_gc_cert(reference: &CheckedRecord, grant: &crawler_authority::Grant) -> CheckedRecord {
    gc_cert(reference, grant, json!("fence-epoch-7"), "collect")
}

// ---------------------------------------------------------------------------
// C41: authorized immutable retrieval, full verification
// ---------------------------------------------------------------------------

#[test]
fn c41_install_read_roundtrip_verifies_size_digest() {
    let store = MemoryArtifactStore::new();
    let grant = operator_grant();
    let bytes = b"job-detail bytes v1";
    let reference = store
        .install(&grant, bytes, "application/json", false)
        .expect("install must succeed");

    let value = record_value(&reference);
    assert_eq!(value["digest"], json!(digest_bytes(bytes)));
    assert_eq!(value["size_bytes"], json!(bytes.len() as u64));
    assert_eq!(value["media_type"], json!("application/json"));
    assert_eq!(value["owner_domain"], json!("crawler"));
    assert_eq!(value["access"], json!("public"));
    assert_eq!(value["provenance"], json!("origin"));
    assert_eq!(
        value["grant_digest"],
        json!(binding_of(grant_record(&grant)))
    );

    // Full roundtrip: the exact bytes come back.
    let back = store.read(&grant, &reference).expect("read must succeed");
    assert_eq!(back, bytes);
    assert_eq!(digest_bytes(&back), value["digest"].as_str().unwrap());
    assert_eq!(back.len() as u64, value["size_bytes"].as_u64().unwrap());

    // Idempotent reinstall with identical metadata succeeds.
    let again = store
        .install(&grant, bytes, "application/json", false)
        .expect("identical reinstall must be idempotent");
    assert_eq!(record_value(&again)["digest"], value["digest"]);

    // Empty media type is rejected; nothing is installed.
    let err = store
        .install(&grant, bytes, "", false)
        .expect_err("empty media type must fail");
    assert_eq!(err.code, "invalid_media_type");

    // Producer grants also install, carrying registry provenance.
    let producer = origin_producer_grant();
    let pref = store
        .install(&producer, b"origin bytes", "text/plain", false)
        .expect("producer install must succeed");
    assert_eq!(record_value(&pref)["provenance"], json!("origin"));
    assert_eq!(record_value(&pref)["owner_domain"], json!("crawler"));
    let pback = store.read(&producer, &pref).expect("producer read must succeed");
    assert_eq!(pback, b"origin bytes");
}

#[test]
fn c41_read_requires_authorized_binding() {
    let store = MemoryArtifactStore::new();
    let operator = operator_grant();
    let reader = reader_grant();
    let bytes = b"public artifact";
    let reference = store
        .install(&operator, bytes, "text/plain", false)
        .expect("install must succeed");

    // Same-grant read succeeds.
    assert_eq!(store.read(&operator, &reference).unwrap(), bytes);

    // The install binding names the operator grant; presenting it under
    // the reader grant fails: a digest alone is not bearer authority.
    let err = store
        .read(&reader, &reference)
        .expect_err("foreign binding must fail");
    assert_eq!(err.code, "digest_mismatch");

    // Rebound to the reader grant, the public artifact reads.
    let rebound = rebind(&reference, &reader);
    assert_eq!(store.read(&reader, &rebound).unwrap(), bytes);

    // Missing binding fails closed.
    let mut bare = record_value(&reference)
        .as_object()
        .unwrap()
        .clone();
    bare.remove("grant_digest");
    let unbound = check("audit_log", Value::Object(bare));
    let err = store
        .read(&operator, &unbound)
        .expect_err("unbound reference must fail");
    assert_eq!(err.code, "missing_grant_binding");

    // Malformed digest is rejected, not trusted.
    let mut bad = record_value(&rebound).as_object().unwrap().clone();
    bad.insert("digest".to_string(), json!("not-a-digest"));
    let bad_ref = check("audit_log", Value::Object(bad));
    let err = store
        .read(&reader, &bad_ref)
        .expect_err("malformed digest must fail");
    assert_eq!(err.code, "invalid_digest");
}

#[test]
fn c41_restricted_access_never_downgraded() {
    let store = MemoryArtifactStore::new();
    let operator = operator_grant();
    let reader = reader_grant();
    let secret = b"session-secret bytes";
    let reference = store
        .install(&operator, secret, "application/session-secret", true)
        .expect("restricted install must succeed");
    assert_eq!(record_value(&reference)["access"], json!("restricted"));

    // Privileged read succeeds.
    assert_eq!(store.read(&operator, &reference).unwrap(), secret);

    // Unprivileged read fails even with a correct binding.
    let rebound = rebind(&reference, &reader);
    let err = store
        .read(&reader, &rebound)
        .expect_err("restricted read without flag must fail");
    assert_eq!(err.code, "access_denied");

    // Downgrading the reference itself to public is refused.
    let mut downgrade = record_value(&reference).as_object().unwrap().clone();
    downgrade.insert("access".to_string(), json!("public"));
    let downgraded = check("audit_log", Value::Object(downgrade));
    let err = store
        .read(&operator, &downgraded)
        .expect_err("downgraded access must fail");
    assert_eq!(err.code, "access_downgrade_refused");

    // Ordinary inventories do not expose the secret: the slot degrades
    // to reasoned Missing while the privileged inventory stays available
    // and still restricted.
    let inventory = check(
        "audit_log",
        json!({"artifacts": [slot_bare("secret", &reference)]}),
    );
    let request = check("audit_log", json!({"mode": "inventory"}));
    let reader_view =
        collect_artifacts(&store, &reader, &request, &inventory).expect("inventory must succeed");
    let reader_slot = &record_value(&reader_view)["artifacts"][0];
    assert!(reader_slot["content"].as_object().unwrap().contains_key("reason"));
    // Known digest survives as expected_digest.
    assert_eq!(
        reader_slot["expected_digest"],
        record_value(&reference)["digest"]
    );
    let operator_view =
        collect_artifacts(&store, &operator, &request, &inventory).expect("inventory must succeed");
    let operator_slot = &record_value(&operator_view)["artifacts"][0];
    assert_eq!(operator_slot["content"]["access"], json!("restricted"));
    assert_eq!(
        operator_slot["content"]["media_type"],
        json!("application/session-secret")
    );

    // Explicit named request for the secret without the flag fails loudly.
    let named = check("audit_log", json!({"mode": "named", "names": ["secret"]}));
    let err = collect_artifacts(&store, &reader, &named, &inventory)
        .expect_err("named restricted without flag must fail");
    assert_eq!(err.code, "access_denied");
}

#[test]
fn c41_tampered_reference_rejected() {
    let store = MemoryArtifactStore::new();
    let grant = operator_grant();
    let bytes = b"tamper-evident bytes";
    let reference = store
        .install(&grant, bytes, "application/json", false)
        .expect("install must succeed");

    // Wrong size.
    let mut tampered = record_value(&reference).as_object().unwrap().clone();
    tampered.insert("size_bytes".to_string(), json!(9999u64));
    let bad = check("audit_log", Value::Object(tampered));
    let err = store.read(&grant, &bad).expect_err("wrong size must fail");
    assert_eq!(err.code, "size_mismatch");

    // Wrong media type.
    let mut tampered = record_value(&reference).as_object().unwrap().clone();
    tampered.insert("media_type".to_string(), json!("text/html"));
    let bad = check("audit_log", Value::Object(tampered));
    let err = store.read(&grant, &bad).expect_err("wrong media must fail");
    assert_eq!(err.code, "metadata_mismatch");

    // Wrong owner.
    let mut tampered = record_value(&reference).as_object().unwrap().clone();
    tampered.insert("owner_domain".to_string(), json!("product"));
    let bad = check("audit_log", Value::Object(tampered));
    let err = store.read(&grant, &bad).expect_err("wrong owner must fail");
    assert_eq!(err.code, "metadata_mismatch");

    // Wrong access (upgrade is still a mismatch).
    let mut tampered = record_value(&reference).as_object().unwrap().clone();
    tampered.insert("access".to_string(), json!("restricted"));
    let bad = check("audit_log", Value::Object(tampered));
    let err = store.read(&grant, &bad).expect_err("wrong access must fail");
    assert_eq!(err.code, "metadata_mismatch");

    // Unknown digest: well-formed but never installed.
    let mut tampered = record_value(&reference).as_object().unwrap().clone();
    tampered.insert("digest".to_string(), json!("b".repeat(64)));
    let bad = check("audit_log", Value::Object(tampered));
    let err = store
        .read(&grant, &bad)
        .expect_err("unknown digest must fail");
    assert_eq!(err.code, "bytes_unavailable");

    // Missing size field.
    let mut tampered = record_value(&reference).as_object().unwrap().clone();
    tampered.remove("size_bytes");
    let bad = check("audit_log", Value::Object(tampered));
    let err = store
        .read(&grant, &bad)
        .expect_err("missing size must fail");
    assert_eq!(err.code, "invalid_reference");
}

#[test]
fn c41_arbitrary_url_path_refused() {
    let store = MemoryArtifactStore::new();
    let grant = operator_grant();
    let reference = store
        .install(&grant, b"handled bytes", "text/plain", false)
        .expect("install must succeed");
    let inventory = check(
        "audit_log",
        json!({"artifacts": [slot("handled", &reference)]}),
    );

    // Every caller locator field is refused, flat or inside selector.
    for field in [
        "url",
        "path",
        "filesystem_path",
        "uri",
        "location",
        "fetch_url",
    ] {
        let flat = check(
            "audit_log",
            json!({"mode": "inventory", field: "https://example.com/evil"}),
        );
        let err = collect_artifacts(&store, &grant, &flat, &inventory)
            .expect_err("flat locator must be refused");
        assert_eq!(err.code, "arbitrary_locator_refused", "field {field}");

        let nested = check(
            "audit_log",
            json!({"selector": {"mode": "inventory", field: "/etc/passwd"}}),
        );
        let err = collect_artifacts(&store, &grant, &nested, &inventory)
            .expect_err("nested locator must be refused");
        assert_eq!(err.code, "arbitrary_locator_refused", "field {field}");
    }
    // Present-but-Missing asserts nothing and passes the locator check.
    let benign = check(
        "audit_log",
        json!({"mode": "inventory", "url": missing("not_applicable")}),
    );
    collect_artifacts(&store, &grant, &benign, &inventory)
        .expect("Missing locator must not count as a fetch");

    // Arbitrary digests outside the handle inventory are never fetched.
    let foreign = check(
        "audit_log",
        json!({
            "mode": "bytes",
            "digest": "c".repeat(64),
            "offset": 0,
            "max_bytes": 8,
        }),
    );
    let err = collect_artifacts(&store, &grant, &foreign, &inventory)
        .expect_err("foreign digest must fail");
    assert_eq!(err.code, "unknown_artifact");

    // Unknown names degrade to reasoned Missing; nothing is fabricated.
    let named = check("audit_log", json!({"mode": "named", "names": ["ghost"]}));
    let result =
        collect_artifacts(&store, &grant, &named, &inventory).expect("unknown name must be Missing");
    let artifacts = record_value(&result)["artifacts"].as_array().unwrap();
    assert_eq!(artifacts.len(), 1);
    assert_eq!(artifacts[0]["name"], json!("ghost"));
    assert!(artifacts[0]["content"].as_object().unwrap().contains_key("reason"));

    // Locator smuggling inside inventory slots is refused.
    let smuggled = check(
        "audit_log",
        json!({"artifacts": [{
            "name": "evil",
            "expected_digest": missing("not_observed"),
            "content": {
                "digest": "d".repeat(64),
                "size_bytes": 1,
                "media_type": "text/plain",
                "owner_domain": "crawler",
                "access": "public",
                "provenance": "origin",
                "url": "https://example.com/evil",
            },
        }]}),
    );
    let request = check("audit_log", json!({"mode": "inventory"}));
    let err = collect_artifacts(&store, &grant, &request, &smuggled)
        .expect_err("smuggled inventory locator must be refused");
    assert_eq!(err.code, "arbitrary_locator_refused");
}

#[test]
fn c41_collect_inventory_named_bytes() {
    let store = MemoryArtifactStore::new();
    let grant = operator_grant();
    let first = b"first artifact bytes";
    let second = b"second artifact bytes, a little longer";
    let ref_first = store
        .install(&grant, first, "text/plain", false)
        .expect("install first must succeed");
    let ref_second = store
        .install(&grant, second, "application/json", false)
        .expect("install second must succeed");
    let digest_first = record_value(&ref_first)["digest"].as_str().unwrap().to_string();
    let digest_second = record_value(&ref_second)["digest"].as_str().unwrap().to_string();

    let inventory = check(
        "audit_log",
        json!({"artifacts": [
            slot("first", &ref_first),
            slot("second", &ref_second),
            {
                "name": "pending",
                "expected_digest": "e".repeat(64),
                "content": missing("not_observed"),
            },
        ]}),
    );

    // Inventory mode returns every slot: available stay available and
    // verified, Missing stays Missing with its known digest.
    let request = check("audit_log", json!({"mode": "inventory"}));
    let result =
        collect_artifacts(&store, &grant, &request, &inventory).expect("inventory must succeed");
    let artifacts = record_value(&result)["artifacts"].as_array().unwrap();
    assert_eq!(artifacts.len(), 3);
    assert_eq!(artifacts[0]["content"]["digest"], json!(digest_first));
    assert_eq!(artifacts[1]["content"]["digest"], json!(digest_second));
    assert!(artifacts[2]["content"].as_object().unwrap().contains_key("reason"));
    assert_eq!(artifacts[2]["expected_digest"], json!("e".repeat(64)));

    // Selector-wrapped inventory works identically.
    let wrapped = check("audit_log", json!({"selector": {"mode": "inventory"}}));
    let wrapped_result =
        collect_artifacts(&store, &grant, &wrapped, &inventory).expect("wrapped must succeed");
    assert_eq!(
        record_value(&wrapped_result)["artifacts"].as_array().unwrap().len(),
        3
    );

    // Named mode returns exactly the requested names in order.
    let named = check("audit_log", json!({"mode": "named", "names": ["second", "first"]}));
    let result =
        collect_artifacts(&store, &grant, &named, &inventory).expect("named must succeed");
    let artifacts = record_value(&result)["artifacts"].as_array().unwrap();
    assert_eq!(artifacts.len(), 2);
    assert_eq!(artifacts[0]["name"], json!("second"));
    assert_eq!(artifacts[1]["name"], json!("first"));
    assert_eq!(record_value(&result)["coverage"], json!("complete"));

    // Mixed available + Missing names report partial coverage.
    let mixed = check(
        "audit_log",
        json!({"mode": "named", "names": ["first", "pending", "ghost"]}),
    );
    let result =
        collect_artifacts(&store, &grant, &mixed, &inventory).expect("mixed named must succeed");
    let artifacts = record_value(&result)["artifacts"].as_array().unwrap();
    assert_eq!(artifacts.len(), 3);
    assert_eq!(record_value(&result)["coverage"], json!("partial"));

    // Bytes mode returns a verified chunk.
    let bytes = check(
        "audit_log",
        json!({
            "mode": "bytes",
            "digest": digest_first,
            "offset": 6,
            "max_bytes": 8,
        }),
    );
    let chunk =
        collect_artifacts(&store, &grant, &bytes, &inventory).expect("bytes must succeed");
    let chunk_value = record_value(&chunk);
    assert_eq!(chunk_value["kind"], json!("artifact_chunk"));
    assert_eq!(chunk_value["digest"], json!(digest_first));
    assert_eq!(chunk_value["size_bytes"], json!(first.len() as u64));
    assert_eq!(chunk_value["offset"], json!(6));
    assert_eq!(chunk_value["returned_bytes"], json!(8));
    let expected_slice = &first[6..14];
    let decoded = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        chunk_value["data_base64"].as_str().unwrap(),
    )
    .expect("chunk base64 must decode");
    assert_eq!(decoded, expected_slice);
    assert_eq!(
        chunk_value["chunk_digest"],
        json!(digest_bytes(expected_slice))
    );
    assert_eq!(
        chunk_value["end_of_artifact"],
        json!(6 + 8 == first.len() as u64)
    );

    // Final chunk reports end_of_artifact exactly at size.
    let tail = check(
        "audit_log",
        json!({
            "mode": "bytes",
            "digest": digest_second,
            "offset": 0,
            "max_bytes": 1_000_000,
        }),
    );
    let chunk = collect_artifacts(&store, &grant, &tail, &inventory).expect("tail must succeed");
    assert_eq!(record_value(&chunk)["end_of_artifact"], json!(true));
    assert_eq!(
        record_value(&chunk)["returned_bytes"],
        json!(second.len() as u64)
    );

    // Offsets beyond EOF are rejected; zero max_bytes is rejected.
    let past = check(
        "audit_log",
        json!({
            "mode": "bytes",
            "digest": digest_first,
            "offset": first.len() as u64 + 1,
            "max_bytes": 4,
        }),
    );
    let err =
        collect_artifacts(&store, &grant, &past, &inventory).expect_err("past EOF must fail");
    assert_eq!(err.code, "offset_beyond_eof");
    let zero = check(
        "audit_log",
        json!({
            "mode": "bytes",
            "digest": digest_first,
            "offset": 0,
            "max_bytes": 0,
        }),
    );
    let err =
        collect_artifacts(&store, &grant, &zero, &inventory).expect_err("zero max must fail");
    assert_eq!(err.code, "invalid_max_bytes");
}

#[test]
fn c41_missing_bytes_preserve_digest_no_rerun() {
    let store = MemoryArtifactStore::new();
    let grant = operator_grant();
    let bytes = b"doomed bytes";
    let reference = store
        .install(&grant, bytes, "text/plain", false)
        .expect("install must succeed");
    let digest = record_value(&reference)["digest"].as_str().unwrap().to_string();
    let inventory = check(
        "audit_log",
        json!({"artifacts": [slot("doomed", &reference)]}),
    );

    // Collect while available.
    let named = check("audit_log", json!({"mode": "named", "names": ["doomed"]}));
    let before =
        collect_artifacts(&store, &grant, &named, &inventory).expect("available named must succeed");
    assert_eq!(
        record_value(&before)["artifacts"][0]["content"]["digest"],
        json!(digest)
    );

    // Remove the bytes through a valid GC certificate.
    let cert = valid_gc_cert(&reference, &grant);
    store
        .delete(&grant, &reference, &cert)
        .expect("fenced delete must succeed");

    // Reads fail without fabricating content.
    let err = store.read(&grant, &reference).expect_err("lost bytes must fail");
    assert_eq!(err.code, "bytes_unavailable");

    // Named collection degrades to Missing but preserves the known digest.
    let after =
        collect_artifacts(&store, &grant, &named, &inventory).expect("lost named must be Missing");
    let slot_value = &record_value(&after)["artifacts"][0];
    assert_eq!(slot_value["expected_digest"], json!(digest));
    assert!(slot_value["content"].as_object().unwrap().contains_key("reason"));

    // Bytes mode reports unavailability; it never reruns acquisition.
    let bytes_req = check(
        "audit_log",
        json!({"mode": "bytes", "digest": digest, "offset": 0, "max_bytes": 4}),
    );
    let err = collect_artifacts(&store, &grant, &bytes_req, &inventory)
        .expect_err("lost bytes mode must fail");
    assert_eq!(err.code, "bytes_unavailable");
}

#[test]
fn c41_delete_requires_fenced_certificate() {
    let store = MemoryArtifactStore::new();
    let operator = operator_grant();
    let reader = reader_grant();
    let reference = store
        .install(&operator, b"deletable", "text/plain", false)
        .expect("install must succeed");

    // Missing fence.
    let no_fence = gc_cert(&reference, &operator, missing("not_observed"), "collect");
    let err = store
        .delete(&operator, &reference, &no_fence)
        .expect_err("unfenced delete must fail");
    assert_eq!(err.code, "gc_fence_required");

    // Wrong decision: retention, TTL, and newer rows never authorize deletion.
    for decision in ["retain", "ttl_expired", "cache_evict", "superseded"] {
        let cert = gc_cert(&reference, &operator, json!("fence-1"), decision);
        let err = store
            .delete(&operator, &reference, &cert)
            .expect_err("non-collect decision must fail");
        assert_eq!(err.code, "gc_decision_required", "decision {decision}");
    }

    // Certificate for a different digest.
    let mut other = record_value(&reference).as_object().unwrap().clone();
    other.insert("digest".to_string(), json!("f".repeat(64)));
    let other_ref = check("audit_log", Value::Object(other));
    // Bind the forged reference first so the failure is the certificate,
    // not the reference binding.
    let rebound_other = rebind(&other_ref, &operator);
    let cert = valid_gc_cert(&reference, &operator);
    let err = store
        .delete(&operator, &rebound_other, &cert)
        .expect_err("digest mismatch must fail");
    assert_eq!(err.code, "invalid_gc_certificate");

    // Certificate bound to a different grant.
    let reader_bound = rebind(&reference, &reader);
    let operator_cert = valid_gc_cert(&reference, &operator);
    let err = store
        .delete(&reader, &reader_bound, &operator_cert)
        .expect_err("foreign certificate must fail");
    assert_eq!(err.code, "invalid_gc_certificate");

    // Still present after every refused delete.
    assert_eq!(
        store.read(&operator, &reference).unwrap(),
        b"deletable"
    );

    // Valid fenced certificate deletes exactly once.
    let cert = valid_gc_cert(&reference, &operator);
    store
        .delete(&operator, &reference, &cert)
        .expect("valid delete must succeed");
    let err = store
        .read(&operator, &reference)
        .expect_err("deleted bytes must be gone");
    assert_eq!(err.code, "bytes_unavailable");
    let err = store
        .delete(&operator, &reference, &cert)
        .expect_err("second delete must fail");
    assert_eq!(err.code, "bytes_unavailable");
}

#[test]
fn c41_immutable_reinstall_rules() {
    let store = MemoryArtifactStore::new();
    let grant = operator_grant();
    let bytes = b"immutable content";
    let reference = store
        .install(&grant, bytes, "text/plain", false)
        .expect("install must succeed");

    // Same bytes, different media type: refused, never mutated.
    let err = store
        .install(&grant, bytes, "application/json", false)
        .expect_err("media change must fail");
    assert_eq!(err.code, "immutable_conflict");

    // Same bytes, different access: refused, never mutated.
    let err = store
        .install(&grant, bytes, "text/plain", true)
        .expect_err("access change must fail");
    assert_eq!(err.code, "immutable_conflict");

    // Same bytes under the same owner from another grant rebinds cleanly.
    let reader = reader_grant();
    let rebound_install = store
        .install(&reader, bytes, "text/plain", false)
        .expect("same-metadata reinstall under another grant must succeed");
    assert_eq!(
        record_value(&rebound_install)["digest"],
        record_value(&reference)["digest"]
    );
    assert_eq!(
        record_value(&rebound_install)["grant_digest"],
        json!(binding_of(grant_record(&reader)))
    );
    assert_eq!(store.read(&reader, &rebound_install).unwrap(), bytes);

    // The original reference still reads the original bytes.
    assert_eq!(store.read(&grant, &reference).unwrap(), bytes);
}

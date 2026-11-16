//! Conformance tests for [C05]: hash profiles.
//!
//! Wrong bytes/framing rejected; hash-of-hash not accepted as source digest.

use crawler_hashing::{
    canonical_bytes, digest_bytes, frame_reference, reconcile_source_hash, verify_record_digest,
};
use crawler_schema::CheckedRecord;
use serde_json::{Value, json};

fn check(schema: &str, value: Value) -> CheckedRecord {
    crawler_schema::validate(schema, value).expect("test fixture must validate")
}

fn source_hash(value: Value, profile: Value, evidence_refs: Value) -> CheckedRecord {
    check(
        "seen_ids",
        json!({
            "value": value,
            "profile": profile,
            "evidence_refs": evidence_refs,
        }),
    )
}

fn missing(reason: &str) -> Value {
    json!({"value": Value::Null, "reason": reason})
}

// ---------------------------------------------------------------------------
// digest_bytes: byte identity
// ---------------------------------------------------------------------------

#[test]
fn c05_digest_bytes_known_vectors() {
    assert_eq!(
        digest_bytes(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        digest_bytes(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn c05_digest_bytes_is_deterministic_byte_identity() {
    let content = b"listing-bytes-\x00-\xff";
    let first = digest_bytes(content);
    let second = digest_bytes(content);
    assert_eq!(first, second);
    assert_eq!(first.len(), 64);
    // A hash of the digest string is a different value, never the digest itself.
    let hash_of_hash = digest_bytes(first.as_bytes());
    assert_ne!(hash_of_hash, first);
    assert_ne!(digest_bytes(b"abc"), digest_bytes(b"abd"));
}

// ---------------------------------------------------------------------------
// canonical_bytes: kernel JCS profile input
// ---------------------------------------------------------------------------

#[test]
fn c05_canonical_bytes_exact_key_ordered_form() {
    let record = check("listing", json!({"b": 2, "a": 1}));
    assert_eq!(canonical_bytes(&record).unwrap(), br#"{"a":1,"b":2}"#);

    let nested = check(
        "listing",
        json!({"z": {"b": 1, "a": [3, 2]}, "a": true, "m": 1.5}),
    );
    assert_eq!(
        canonical_bytes(&nested).unwrap(),
        br#"{"a":true,"m":1.5,"z":{"a":[3,2],"b":1}}"#
    );
    // Array order is preserved, never sorted.
    let arrays = check("listing", json!({"a": [2, 1]}));
    assert_eq!(canonical_bytes(&arrays).unwrap(), br#"{"a":[2,1]}"#);
}

#[test]
fn c05_canonical_bytes_preserves_text_and_envelopes() {
    // No Unicode normalization, no `/` escaping, no whitespace.
    let record = check("listing", json!({"k": "héllo/world — ①"}));
    assert_eq!(
        String::from_utf8(canonical_bytes(&record).unwrap()).unwrap(),
        r#"{"k":"héllo/world — ①"}"#
    );
    // Missing envelopes canonicalize with sorted envelope keys.
    let envelope = check(
        "listing",
        json!({"f": {"value": Value::Null, "reason": "not_applicable"}}),
    );
    assert_eq!(
        canonical_bytes(&envelope).unwrap(),
        br#"{"f":{"reason":"not_applicable","value":null}}"#
    );
}

// ---------------------------------------------------------------------------
// reconcile_source_hash: SH -> DIGEST conversion
// ---------------------------------------------------------------------------

#[test]
fn c05_reconcile_accepts_matching_bytes() {
    let bytes = br#"{"a":1,"b":2}"#;
    let digest = digest_bytes(bytes);
    let source = source_hash(
        Value::String(digest.clone()),
        Value::String("kernel-jcs-sha256/1".to_string()),
        json!([]),
    );
    let reconciled = reconcile_source_hash(&source, Some(bytes)).expect("matching bytes");
    let value = crawler_schema::record_value(&reconciled);
    // Source digest text preserved verbatim in the DIGEST record.
    assert_eq!(value.get("digest"), Some(&Value::String(digest.clone())));
    assert_eq!(value.get("value"), Some(&Value::String(digest)));
}

#[test]
fn c05_reconcile_accepts_each_pinned_profile() {
    let bytes = b"artifact-exact-bytes";
    let digest = digest_bytes(bytes);
    for profile in [
        "kernel-jcs-sha256/1",
        "artifact-sha256/1",
        "crawler-fetch-key/1",
        "crawler-classifier-input/1",
        "crawler-page-hash/1",
    ] {
        let source = source_hash(
            Value::String(digest.clone()),
            Value::String(profile.to_string()),
            json!([]),
        );
        assert!(
            reconcile_source_hash(&source, Some(bytes)).is_ok(),
            "pinned profile {profile} must reconcile"
        );
    }
}

#[test]
fn c05_reconcile_rejects_wrong_bytes() {
    let digest = digest_bytes(b"original-content");
    let source = source_hash(
        Value::String(digest),
        Value::String("artifact-sha256/1".to_string()),
        json!([]),
    );
    let err = reconcile_source_hash(&source, Some(b"tampered-content")).unwrap_err();
    assert_eq!(err.code, "digest_mismatch");
}

#[test]
fn c05_reconcile_rejects_unavailable_bytes() {
    let digest = digest_bytes(b"content");
    let source = source_hash(
        Value::String(digest),
        Value::String("artifact-sha256/1".to_string()),
        json!([]),
    );
    let err = reconcile_source_hash(&source, None).unwrap_err();
    assert_eq!(err.code, "bytes_unavailable");
}

#[test]
fn c05_reconcile_rejects_unknown_framing() {
    let digest = digest_bytes(b"content");
    // Unknown profile string.
    let unknown = source_hash(
        Value::String(digest.clone()),
        Value::String("sha1-hex/1".to_string()),
        json!([]),
    );
    assert_eq!(
        reconcile_source_hash(&unknown, Some(b"content"))
            .unwrap_err()
            .code,
        "unknown_profile"
    );
    // Missing profile: unknown framing blocks establishment.
    let missing_profile = source_hash(
        Value::String(digest.clone()),
        missing("not_applicable"),
        json!([]),
    );
    assert_eq!(
        reconcile_source_hash(&missing_profile, Some(b"content"))
            .unwrap_err()
            .code,
        "unknown_framing"
    );
    // Non-string profile.
    let numeric = source_hash(Value::String(digest), json!(7), json!([]));
    assert_eq!(
        reconcile_source_hash(&numeric, Some(b"content"))
            .unwrap_err()
            .code,
        "invalid_profile"
    );
}

#[test]
fn c05_reconcile_rejects_hash_of_hash_as_source_digest() {
    let content = b"underlying-content";
    let digest = digest_bytes(content);
    let hash_of_digest_text = digest_bytes(digest.as_bytes());

    // Supplying the digest text itself as the "bytes" is rejected: the
    // module confirms identity, it never hashes the digest string.
    let source = source_hash(
        Value::String(digest.clone()),
        Value::String("artifact-sha256/1".to_string()),
        json!([]),
    );
    assert_eq!(
        reconcile_source_hash(&source, Some(digest.as_bytes()))
            .unwrap_err()
            .code,
        "digest_mismatch"
    );

    // A value holding the hash-of-hash does not reconcile the original bytes.
    let impostor = source_hash(
        Value::String(hash_of_digest_text),
        Value::String("artifact-sha256/1".to_string()),
        json!([]),
    );
    assert_eq!(
        reconcile_source_hash(&impostor, Some(content))
            .unwrap_err()
            .code,
        "digest_mismatch"
    );
}

#[test]
fn c05_reconcile_rejects_malformed_source() {
    let digest = digest_bytes(b"content");
    // Not an object.
    let scalar = check("seen_ids", json!("not-a-source-hash"));
    assert_eq!(
        reconcile_source_hash(&scalar, Some(b"content"))
            .unwrap_err()
            .code,
        "not_source_hash"
    );
    // Uppercase hex is not canonical digest text.
    let upper = source_hash(
        Value::String(digest.to_uppercase()),
        Value::String("artifact-sha256/1".to_string()),
        json!([]),
    );
    assert_eq!(
        reconcile_source_hash(&upper, Some(b"content"))
            .unwrap_err()
            .code,
        "invalid_digest"
    );
    // Truncated digest text.
    let short = source_hash(
        Value::String(digest[..32].to_string()),
        Value::String("artifact-sha256/1".to_string()),
        json!([]),
    );
    assert_eq!(
        reconcile_source_hash(&short, Some(b"content"))
            .unwrap_err()
            .code,
        "invalid_digest"
    );
    // Missing digest: no established identity.
    let no_digest = source_hash(
        missing("not_observed"),
        Value::String("artifact-sha256/1".to_string()),
        json!([]),
    );
    assert_eq!(
        reconcile_source_hash(&no_digest, Some(b"content"))
            .unwrap_err()
            .code,
        "missing_digest"
    );
    // Absent evidence_refs field.
    let no_evidence = check(
        "seen_ids",
        json!({"value": digest, "profile": "artifact-sha256/1"}),
    );
    assert_eq!(
        reconcile_source_hash(&no_evidence, Some(b"content"))
            .unwrap_err()
            .code,
        "missing_field"
    );
    // Non-array evidence_refs.
    let bad_evidence = source_hash(
        Value::String(digest_bytes(b"content")),
        Value::String("artifact-sha256/1".to_string()),
        Value::String("x".to_string()),
    );
    assert_eq!(
        reconcile_source_hash(&bad_evidence, Some(b"content"))
            .unwrap_err()
            .code,
        "invalid_evidence"
    );
    // Pre-existing conflicting digest is never silently overwritten.
    let conflict = check(
        "seen_ids",
        json!({
            "value": digest_bytes(b"content"),
            "profile": "artifact-sha256/1",
            "evidence_refs": [],
            "digest": digest_bytes(b"something-else"),
        }),
    );
    assert_eq!(
        reconcile_source_hash(&conflict, Some(b"content"))
            .unwrap_err()
            .code,
        "digest_conflict"
    );
}

// ---------------------------------------------------------------------------
// frame_reference: reversible length-framed references
// ---------------------------------------------------------------------------

fn parts(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

#[test]
fn c05_frame_reference_exact_vectors() {
    assert_eq!(
        frame_reference("seen_ids", &parts(&["t1", "j7"])).unwrap(),
        "seen_ids:2:2:t1:2:j7"
    );
    assert_eq!(
        frame_reference("classifier_result", &parts(&["t", "j", "s1", "m2", "h3"])).unwrap(),
        "classifier_result:5:1:t:1:j:2:s1:2:m2:2:h3"
    );
    assert_eq!(
        frame_reference("dead_letter", &parts(&["t", "listing", "ref", "timeout"])).unwrap(),
        "dead_letter:4:1:t:7:listing:3:ref:7:timeout"
    );
}

#[test]
fn c05_frame_reference_never_collides_across_splits() {
    // Raw slash concatenation would conflate these; framing must not.
    let left = frame_reference("seen_ids", &parts(&["a/b", "c"])).unwrap();
    let right = frame_reference("seen_ids", &parts(&["a", "b/c"])).unwrap();
    assert_ne!(left, right);
    assert_eq!(left, "seen_ids:2:3:a/b:1:c");
    assert_eq!(right, "seen_ids:2:1:a:3:b/c");
    // Colons and Unicode are safe inside components.
    let tricky = frame_reference("seen_ids", &parts(&["a:2:x", "ünï—①"])).unwrap();
    assert_eq!(tricky, "seen_ids:2:5:a:2:x:11:ünï—①");
    assert_ne!(
        tricky,
        frame_reference("seen_ids", &parts(&["a", "2:x:ünï—①"])).unwrap()
    );
}

#[test]
fn c05_frame_reference_preserves_integer_string_distinction() {
    // Callers tag unions explicitly; framing keeps the tags byte-exact
    // so integer 7 (`i:7`) never conflates with string "7" (`s:7`).
    let as_int = frame_reference("seen_ids", &parts(&["i:7", "j1"])).unwrap();
    let as_string = frame_reference("seen_ids", &parts(&["s:7", "j1"])).unwrap();
    assert_ne!(as_int, as_string);
    assert!(as_int.contains("i:7"));
    assert!(as_string.contains("s:7"));
}

#[test]
fn c05_frame_reference_rejects_bad_shapes() {
    assert_eq!(
        frame_reference("mystery", &parts(&["t", "j"])).unwrap_err().code,
        "unknown_entity"
    );
    assert_eq!(
        frame_reference("seen_ids", &parts(&["only-target"]))
            .unwrap_err()
            .code,
        "arity_mismatch"
    );
    assert_eq!(
        frame_reference("seen_ids", &parts(&["t", "j", "extra"]))
            .unwrap_err()
            .code,
        "arity_mismatch"
    );
    assert_eq!(
        frame_reference("seen_ids", &parts(&["t", ""]))
            .unwrap_err()
            .code,
        "empty_component"
    );
}

// ---------------------------------------------------------------------------
// verify_record_digest: kernel digest check
// ---------------------------------------------------------------------------

#[test]
fn c05_verify_record_digest_round_trip_and_rejections() {
    let record = check(
        "listing",
        json!({"b": [1, 2], "a": "x", "m": {"value": Value::Null, "reason": "not_enabled"}}),
    );
    let expected = digest_bytes(&canonical_bytes(&record).unwrap());
    verify_record_digest(&record, &expected).expect("matching digest verifies");

    // Wrong digest for these bytes.
    assert_eq!(
        verify_record_digest(&record, &digest_bytes(b"other-bytes"))
            .unwrap_err()
            .code,
        "digest_mismatch"
    );
    // Hash of the digest text is not the record digest.
    let hash_of_hash = digest_bytes(expected.as_bytes());
    assert_eq!(
        verify_record_digest(&record, &hash_of_hash).unwrap_err().code,
        "digest_mismatch"
    );
    // Malformed expectations are rejected before comparison.
    for bad in ["", &expected.to_uppercase(), &expected[..32], "zz"] {
        assert_eq!(
            verify_record_digest(&record, bad).unwrap_err().code,
            "invalid_expected_digest",
            "malformed expectation {bad:?} must be rejected"
        );
    }

    // A changed record no longer matches the old digest.
    let changed = check(
        "listing",
        json!({"b": [1, 3], "a": "x", "m": {"value": Value::Null, "reason": "not_enabled"}}),
    );
    assert_eq!(
        verify_record_digest(&changed, &expected).unwrap_err().code,
        "digest_mismatch"
    );
}

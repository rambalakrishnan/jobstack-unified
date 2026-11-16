// Conformance runner for rm_wire (custom harness: `harness = false`).
//
// The verification command passes lowercase conformance filters
// (`cargo test -p rm_wire -- rm_c01 rm_c02`). The stock libtest harness
// cannot match these filters against Rust `#[test]` identifiers portably
// across hyphen/underscore spellings, so this file is a custom `main` that
// honors exactly those registered lowercase filters (accepting both
// `rm_c01` and `rm-c01` spellings). Each case runs every assertion for its
// ID; any failure is printed and the process exits nonzero.

use rm_wire::{artifact_digest, canonical_digest, validate_record};
use std::collections::HashSet;

// ---------------------------------------------------------------------------
// tiny assertion helpers
// ---------------------------------------------------------------------------

type Failure = String;

fn expect_ok(result: Result<(), String>, what: &str) -> Result<(), Failure> {
    result.map_err(|e| format!("{what}: expected Ok, got Err({e})"))
}

fn expect_err(result: Result<(), String>, what: &str) -> Result<(), Failure> {
    match result {
        Ok(()) => Err(format!("{what}: expected Err, got Ok")),
        Err(_) => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// RM-C01: unknown version, extra field, duplicate key, non-finite number
// ---------------------------------------------------------------------------

fn rm_c01_unknown_version() -> Result<(), Failure> {
    // Genuine record with a version this registry never issued.
    let record = br#"{"record_type":"connector_request","schema_version":"external-connector/9.9.9","request_id":"r1","connector_id":"c1","operation":"describe","call_limit":1,"payload":{}}"#;
    expect_err(
        validate_record("connector_request/v1", record),
        "rm-c01 unknown schema_version",
    )?;
    // Unknown schema_id itself.
    expect_err(
        validate_record("nope/v1", br#"{"record_type":"x","schema_version":"y"}"#),
        "rm-c01 unknown schema_id",
    )?;
    // Right shape, wrong registry pairing.
    let mismatched = br#"{"record_type":"connector_request","schema_version":"evidence-kernel/0.1.0","request_id":"r1","connector_id":"c1","operation":"describe","call_limit":1,"payload":{}}"#;
    expect_err(
        validate_record("connector_request/v1", mismatched),
        "rm-c01 mismatched schema_version",
    )?;
    Ok(())
}

fn rm_c01_extra_field() -> Result<(), Failure> {
    // `sneaky` is not a declared closed-object field of connector_request.
    let record = br#"{"record_type":"connector_request","schema_version":"external-connector/0.1.0","request_id":"r1","connector_id":"c1","operation":"describe","call_limit":1,"payload":{},"sneaky":1}"#;
    expect_err(
        validate_record("connector_request/v1", record),
        "rm-c01 extra field",
    )?;
    // Nested extra field inside a Missing envelope.
    let nested = br#"{"record_type":"connector_request","schema_version":"external-connector/0.1.0","request_id":"r1","connector_id":"c1","operation":"describe","call_limit":1,"payload":{"value":null,"reason":"not_observed","bogus":true}}"#;
    expect_err(
        validate_record("connector_request/v1", nested),
        "rm-c01 nested extra field",
    )?;
    Ok(())
}

fn rm_c01_duplicate_key() -> Result<(), Failure> {
    // Parsers keep the last occurrence; validation must still reject.
    let record = br#"{"record_type":"connector_request","schema_version":"external-connector/0.1.0","request_id":"r1","request_id":"r2","connector_id":"c1","operation":"describe","call_limit":1,"payload":{}}"#;
    expect_err(
        validate_record("connector_request/v1", record),
        "rm-c01 duplicate top-level key",
    )?;
    // Nested duplicate inside the payload object.
    let nested = br#"{"record_type":"connector_request","schema_version":"external-connector/0.1.0","request_id":"r1","connector_id":"c1","operation":"describe","call_limit":1,"payload":{"a":1,"a":2}}"#;
    expect_err(
        validate_record("connector_request/v1", nested),
        "rm-c01 nested duplicate key",
    )?;
    // canonical_digest must reject duplicates too (they are not canonical).
    expect_err(
        canonical_digest(record).map(|_| ()),
        "rm-c01 canonical_digest duplicate key",
    )?;
    Ok(())
}

fn rm_c01_nonfinite_number() -> Result<(), Failure> {
    for token in ["NaN", "Infinity", "-Infinity"] {
        let record = format!(
            "{{\"record_type\":\"connector_request\",\"schema_version\":\"external-connector/0.1.0\",\"request_id\":\"r1\",\"connector_id\":\"c1\",\"operation\":\"describe\",\"call_limit\":{token},\"payload\":{{}}}}"
        );
        expect_err(
            validate_record("connector_request/v1", record.as_bytes()),
            &format!("rm-c01 non-finite {token}"),
        )?;
        expect_err(
            canonical_digest(record.as_bytes()).map(|_| ()),
            &format!("rm-c01 canonical non-finite {token}"),
        )?;
    }
    // A string that merely spells a token is fine.
    let spelled = br#"{"record_type":"connector_request","schema_version":"external-connector/0.1.0","request_id":"NaN","connector_id":"c1","operation":"describe","call_limit":1,"payload":{}}"#;
    expect_ok(
        validate_record("connector_request/v1", spelled),
        "rm-c01 token inside string",
    )?;
    Ok(())
}

fn rm_c01_structural_rejection() -> Result<(), Failure> {
    // Malformed JSON, non-object top level, missing discriminators.
    expect_err(
        validate_record("connector_request/v1", b"{not json"),
        "rm-c01 malformed json",
    )?;
    expect_err(
        validate_record("connector_request/v1", b"[1,2]"),
        "rm-c01 non-object record",
    )?;
    expect_err(
        validate_record(
            "connector_request/v1",
            br#"{"schema_version":"external-connector/0.1.0"}"#,
        ),
        "rm-c01 missing record_type",
    )?;
    expect_err(
        validate_record("connector_request/v1", b""),
        "rm-c01 empty bytes",
    )?;
    // Non-UTF-8 bytes.
    expect_err(
        validate_record("connector_request/v1", &[0xff, 0xfe]),
        "rm-c01 non-utf8",
    )?;
    Ok(())
}

fn rm_c01_canonical_vectors() -> Result<(), Failure> {
    // Key order must not affect the digest; array order must.
    let a = br#"{"record_type":"connector_request","schema_version":"external-connector/0.1.0","request_id":"r1","connector_id":"c1","operation":"describe","call_limit":1,"payload":{}}"#;
    let b = br#"{"payload":{},"call_limit":1,"operation":"describe","connector_id":"c1","request_id":"r1","schema_version":"external-connector/0.1.0","record_type":"connector_request"}"#;
    let da = canonical_digest(a).map_err(|e| format!("rm-c01 canonical a: {e}"))?;
    let db = canonical_digest(b).map_err(|e| format!("rm-c01 canonical b: {e}"))?;
    if da != db {
        return Err(format!("rm-c01 canonical key order: {da} != {db}"));
    }
    // Known-answer: sha256('{"a":1,"b":2}').
    let known =
        canonical_digest(br#"{"b":2,"a":1}"#).map_err(|e| format!("rm-c01 known vector: {e}"))?;
    if known.as_str() != "sha256:43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777" {
        return Err(format!("rm-c01 known digest mismatch: {known}"));
    }
    // Whitespace-insensitive.
    let spaced = canonical_digest(br#"{ "a" : 1 , "b" : 2 }"#)
        .map_err(|e| format!("rm-c01 whitespace: {e}"))?;
    if spaced != known {
        return Err("rm-c01 whitespace must not affect digest".to_string());
    }
    // Digest shape: prefix + 64 lowercase hex.
    if !known.as_str().starts_with("sha256:") || known.as_str().len() != 7 + 64 {
        return Err(format!("rm-c01 digest shape: {known}"));
    }
    // Artifact digest covers exact bytes: trailing space changes it.
    let exact = artifact_digest(br#"{"a":1}"#);
    let padded = artifact_digest(br#"{"a":1} "#);
    if exact == padded {
        return Err("rm-c01 artifact digest must cover exact bytes".to_string());
    }
    // Canonical digest ignores that same padding; artifact digest does not
    // equal canonical-of-padded only if canonicalization strips it (it does).
    let canon_padded =
        canonical_digest(br#"{"a":1} "#).map_err(|e| format!("rm-c01 padded canonical: {e}"))?;
    if canon_padded != artifact_digest(br#"{"a":1}"#) {
        return Err("rm-c01 canonical digest must strip insignificant whitespace".to_string());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// RM-C02: bare normalized null at nested depth
// ---------------------------------------------------------------------------

fn rm_c02_bare_null_rejected() -> Result<(), Failure> {
    // Bare null at nested depth inside the payload.
    let nested = br#"{"record_type":"connector_request","schema_version":"external-connector/0.1.0","request_id":"r1","connector_id":"c1","operation":"describe","call_limit":1,"payload":{"slot":null}}"#;
    expect_err(
        validate_record("connector_request/v1", nested),
        "rm-c02 nested bare null",
    )?;
    // Bare null at the top level of the record body.
    let top = br#"{"record_type":"connector_request","schema_version":"external-connector/0.1.0","request_id":"r1","connector_id":"c1","operation":"describe","call_limit":1,"payload":null}"#;
    expect_err(
        validate_record("connector_request/v1", top),
        "rm-c02 top bare null",
    )?;
    // Bare null inside an array.
    let array = br#"{"record_type":"connector_request","schema_version":"external-connector/0.1.0","request_id":"r1","connector_id":"c1","operation":"describe","call_limit":1,"payload":{"items":[1,null]}}"#;
    expect_err(
        validate_record("connector_request/v1", array),
        "rm-c02 array bare null",
    )?;
    // A Missing envelope spliced at the record top level: `value`/`reason`
    // are undeclared fields of connector_request, so closed-object
    // validation rejects it.
    let top_envelope = br#"{"record_type":"connector_request","schema_version":"external-connector/0.1.0","request_id":"r1","connector_id":"c1","operation":"describe","call_limit":1,"value":null,"reason":"not_observed"}"#;
    expect_err(
        validate_record("connector_request/v1", top_envelope),
        "rm-c02 top-level envelope shape",
    )?;
    // canonical_digest rejects bare nulls as non-normalized.
    expect_err(
        canonical_digest(nested).map(|_| ()),
        "rm-c02 canonical_digest bare null",
    )?;
    Ok(())
}

fn rm_c02_missing_accepted() -> Result<(), Failure> {
    // Every one of the six kernel reasons is accepted at nested depth.
    for reason in [
        "not_enabled",
        "not_applicable",
        "not_observed",
        "observation_lost",
        "unsupported_by_subject",
        "manual_override",
    ] {
        let record = format!(
            "{{\"record_type\":\"connector_request\",\"schema_version\":\"external-connector/0.1.0\",\"request_id\":\"r1\",\"connector_id\":\"c1\",\"operation\":\"describe\",\"call_limit\":1,\"payload\":{{\"slot\":{{\"value\":null,\"reason\":{reason:?}}}}}}}"
        );
        expect_ok(
            validate_record("connector_request/v1", record.as_bytes()),
            &format!("rm-c02 Missing reason {reason}"),
        )?;
        expect_ok(
            canonical_digest(record.as_bytes()).map(|_| ()),
            &format!("rm-c02 canonical Missing {reason}"),
        )?;
    }
    // Optional nonempty detail is accepted.
    let detailed = br#"{"record_type":"connector_request","schema_version":"external-connector/0.1.0","request_id":"r1","connector_id":"c1","operation":"describe","call_limit":1,"payload":{"slot":{"value":null,"reason":"not_observed","detail":"sensor offline"}}}"#;
    expect_ok(
        validate_record("connector_request/v1", detailed),
        "rm-c02 Missing with detail",
    )?;
    // Known-answer: canonical form sorts envelope keys detail < reason < value.
    let digest = canonical_digest(br#"{"value":null,"reason":"not_observed","detail":"x"}"#)
        .map_err(|e| format!("rm-c02 envelope vector: {e}"))?;
    if digest.as_str() != "sha256:b261ba3234737d3e58f33e87202d756bcdd5f15d0b89c967432a79e36e405a49"
    {
        return Err(format!("rm-c02 envelope digest mismatch: {digest}"));
    }
    Ok(())
}

fn rm_c02_bad_envelopes_rejected() -> Result<(), Failure> {
    // Seventh reason.
    let seventh = br#"{"record_type":"connector_request","schema_version":"external-connector/0.1.0","request_id":"r1","connector_id":"c1","operation":"describe","call_limit":1,"payload":{"slot":{"value":null,"reason":"manual_fixture_validation"}}}"#;
    expect_err(
        validate_record("connector_request/v1", seventh),
        "rm-c02 seventh reason",
    )?;
    // Missing reason.
    let no_reason = br#"{"record_type":"connector_request","schema_version":"external-connector/0.1.0","request_id":"r1","connector_id":"c1","operation":"describe","call_limit":1,"payload":{"slot":{"value":null}}}"#;
    expect_err(
        validate_record("connector_request/v1", no_reason),
        "rm-c02 missing reason",
    )?;
    // Empty detail.
    let empty_detail = br#"{"record_type":"connector_request","schema_version":"external-connector/0.1.0","request_id":"r1","connector_id":"c1","operation":"describe","call_limit":1,"payload":{"slot":{"value":null,"reason":"not_observed","detail":""}}}"#;
    expect_err(
        validate_record("connector_request/v1", empty_detail),
        "rm-c02 empty detail",
    )?;
    // Non-string detail.
    let numeric_detail = br#"{"record_type":"connector_request","schema_version":"external-connector/0.1.0","request_id":"r1","connector_id":"c1","operation":"describe","call_limit":1,"payload":{"slot":{"value":null,"reason":"not_observed","detail":7}}}"#;
    expect_err(
        validate_record("connector_request/v1", numeric_detail),
        "rm-c02 non-string detail",
    )?;
    // Envelope with an undeclared fourth field.
    let fourth = br#"{"record_type":"connector_request","schema_version":"external-connector/0.1.0","request_id":"r1","connector_id":"c1","operation":"describe","call_limit":1,"payload":{"slot":{"value":null,"reason":"not_observed","extra":1}}}"#;
    expect_err(
        validate_record("connector_request/v1", fourth),
        "rm-c02 envelope extra field",
    )?;
    Ok(())
}

fn rm_c02_falsy_not_missing() -> Result<(), Failure> {
    // False and zero are real values, never missing-value sentinels: they
    // validate wherever the closed schema carries them.
    let record = br#"{"record_type":"connector_request","schema_version":"external-connector/0.1.0","request_id":"r1","connector_id":"c1","operation":"describe","call_limit":0,"payload":{"flag":false,"count":0}}"#;
    expect_ok(
        validate_record("connector_request/v1", record),
        "rm-c02 false and zero accepted",
    )?;
    // Empty arrays mean an established empty collection.
    let empty = br#"{"record_type":"connector_request","schema_version":"external-connector/0.1.0","request_id":"r1","connector_id":"c1","operation":"describe","call_limit":1,"payload":{"items":[]}}"#;
    expect_ok(
        validate_record("connector_request/v1", empty),
        "rm-c02 empty array accepted",
    )?;
    Ok(())
}
type CheckFn = fn() -> Result<(), Failure>;

// ---------------------------------------------------------------------------
// runner
// ---------------------------------------------------------------------------

fn run_case(id: &str) -> Vec<Failure> {
    let checks: &[(&str, CheckFn)] = match id {
        "rm-c01" => &[
            ("unknown version", rm_c01_unknown_version),
            ("extra field", rm_c01_extra_field),
            ("duplicate key", rm_c01_duplicate_key),
            ("non-finite number", rm_c01_nonfinite_number),
            ("structural rejection", rm_c01_structural_rejection),
            ("canonical vectors", rm_c01_canonical_vectors),
        ],
        "rm-c02" => &[
            ("bare null rejected", rm_c02_bare_null_rejected),
            ("Missing accepted", rm_c02_missing_accepted),
            ("bad envelopes rejected", rm_c02_bad_envelopes_rejected),
            ("falsy not missing", rm_c02_falsy_not_missing),
        ],
        _ => return vec![format!("unknown case {id}")],
    };
    let mut failures = Vec::new();
    for (name, check) in checks {
        if let Err(e) = check() {
            failures.push(format!("{id} [{name}]: {e}"));
        }
    }
    failures
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // Registered lowercase conformance filters (spec FORBIDDEN: never replace).
    let mut selected: HashSet<&str> = HashSet::new();
    for arg in &args {
        let normalized = match arg.as_str() {
            "rm_c01" | "rm-c01" => Some("rm-c01"),
            "rm_c02" | "rm-c02" => Some("rm-c02"),
            _ => None,
        };
        if let Some(id) = normalized {
            selected.insert(id);
        } else if arg.starts_with("rm-") || arg.starts_with("rm_") {
            eprintln!("unknown conformance filter: {arg}");
            std::process::exit(2);
        }
    }
    if selected.is_empty() {
        selected.insert("rm-c01");
        selected.insert("rm-c02");
    }
    let mut ids: Vec<&str> = selected.into_iter().collect();
    ids.sort_unstable();

    let mut passed = 0usize;
    let mut failures: Vec<Failure> = Vec::new();
    for id in &ids {
        let case_failures = run_case(id);
        if case_failures.is_empty() {
            println!("{id}: ok");
            passed += 1;
        } else {
            for f in case_failures {
                println!("{id}: FAILED: {f}");
                failures.push(f);
            }
        }
    }
    if failures.is_empty() {
        println!("{passed} passed; 0 failed");
    } else {
        println!("{} passed; {} failed", passed, failures.len());
        std::process::exit(1);
    }
}

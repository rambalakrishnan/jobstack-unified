//! `crawler_hashing`: closed hash-profile registry and source-hash reconciliation.
//!
//! Hash profiles stay distinct and are never silently conflated:
//!
//! - `kernel-jcs-sha256/1`: structured kernel records, SHA-256 over JCS
//!   canonical bytes ([`canonical_bytes`]).
//! - `artifact-sha256/1`: artifacts, SHA-256 over the exact stored bytes.
//! - `crawler-fetch-key/1`: fetch identity over caller-framed canonical
//!   request bytes (URL, uppercase method, actual body digest,
//!   representation headers; §20.1).
//! - `crawler-classifier-input/1`: pinned classifier input canonicalization
//!   (§18.1 five-field payload plus stage and model version).
//! - `crawler-page-hash/1`: pinned page/set hashing.
//!
//! [`reconcile_source_hash`] converts an `SH` object
//! (`{value, profile, evidence_refs}`) into a `DIGEST`-bearing record by
//! *confirming* the preserved source digest text against caller-supplied
//! bytes. It never computes a replacement digest, so hashing a digest
//! string is never accepted as the digest of the underlying content.
//! Unknown framing or unavailable bytes block the conversion.
//!
//! [`frame_reference`] builds canonical operational references with a
//! reversible length-framed encoding. Raw slash concatenation is
//! prohibited: components may contain any bytes (slashes, colons,
//! Unicode) without ambiguity. Integer/string unions stay distinct
//! because callers carry explicit type tags inside the component text
//! (e.g. `"i:7"` vs `"s:7"`), which framing preserves byte-exactly.
//!
//! A hash chain detects changed content; it is not authentication.

use crawler_schema::{CheckedRecord, Fault};
use serde_json::Value;
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Closed registries
// ---------------------------------------------------------------------------

/// Kernel structured records: SHA-256 over JCS canonical bytes.
const PROFILE_KERNEL_JCS_SHA256: &str = "kernel-jcs-sha256/1";
/// Artifacts: SHA-256 over the exact bytes.
const PROFILE_ARTIFACT_SHA256: &str = "artifact-sha256/1";
/// Fetch identity over caller-framed canonical request bytes (§20.1).
const PROFILE_FETCH_KEY: &str = "crawler-fetch-key/1";
/// Pinned classifier input canonicalization (§18.1).
const PROFILE_CLASSIFIER_INPUT: &str = "crawler-classifier-input/1";
/// Pinned page/set hashing.
const PROFILE_PAGE_HASH: &str = "crawler-page-hash/1";

/// The five and only five hash profiles (§3.6).
const KNOWN_PROFILES: &[&str] = &[
    PROFILE_KERNEL_JCS_SHA256,
    PROFILE_ARTIFACT_SHA256,
    PROFILE_FETCH_KEY,
    PROFILE_CLASSIFIER_INPUT,
    PROFILE_PAGE_HASH,
];

/// Canonical operational reference shapes (§3.3): entity name plus the
/// exact number of trailing components (entity name excluded).
const KNOWN_REFERENCES: &[(&str, usize)] = &[
    ("listing", 2),
    ("work_item", 2),
    ("job_detail", 2),
    ("seen_ids", 2),
    ("classifier_result", 5),
    ("coverage_ledger", 3),
    ("cursor_state", 4),
    ("session_state", 5),
    ("state_mutation_record", 3),
    ("audit_log", 3),
    ("dead_letter", 4),
];

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

fn fault(code: &str, detail: String) -> Fault {
    Fault {
        code: code.to_string(),
        detail,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut text = String::with_capacity(64);
    for byte in digest {
        text.push(HEX[(byte >> 4) as usize] as char);
        text.push(HEX[(byte & 0x0f) as usize] as char);
    }
    text
}

/// Canonical SHA-256 digest text: exactly 64 lowercase hex characters.
fn is_digest_text(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// True when `value` is a `Missing` envelope (`{"value": null, ...}`).
/// The schema gate has already validated the envelope shape.
fn is_missing_envelope(value: &Value) -> bool {
    value
        .as_object()
        .is_some_and(|map| map.get("value").is_some_and(Value::is_null))
}

/// Append the JCS (RFC 8785) canonical form of `value`.
///
/// Object keys are sorted explicitly (never relying on map iteration
/// order), arrays keep their order, strings use JSON escaping without
/// `/` escaping or Unicode normalization, and no whitespace is emitted.
fn push_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => out.push_str(&number.to_string()),
        // `serde_json` string escaping matches JCS: `"`, `\`, and
        // U+0000-U+001F escaped, `/` and non-ASCII passed through raw.
        Value::String(text) => {
            out.push_str(&serde_json::to_string(text).expect("string serialization"))
        }
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                push_canonical(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(key).expect("key serialization"));
                out.push(':');
                push_canonical(&map[*key], out);
            }
            out.push('}');
        }
    }
}

// ---------------------------------------------------------------------------
// Public interface
// ---------------------------------------------------------------------------

/// SHA-256 of the exact bytes, as 64 lowercase hex characters.
///
/// This is byte identity (the artifact profile): no framing,
/// normalization, or canonicalization is applied.
pub fn digest_bytes(bytes: &[u8]) -> String {
    sha256_hex(bytes)
}

/// JCS canonical bytes of a checked record (the `kernel-jcs-sha256/1`
/// profile input).
///
/// Deterministic over key order; array order, Unicode text, and
/// redaction envelopes are preserved exactly as stored, never
/// normalized.
pub fn canonical_bytes(record: &CheckedRecord) -> Result<Vec<u8>, Fault> {
    let mut text = String::new();
    push_canonical(crawler_schema::record_value(record), &mut text);
    Ok(text.into_bytes())
}

/// Reconcile a source hash (`SH`) against caller-supplied bytes.
///
/// The source value must be a closed `SH` object: `value` holds the
/// source digest text (64 lowercase hex, preserved verbatim), `profile`
/// names one of the five pinned profiles, and `evidence_refs` is
/// present as an array. `bytes` must be the exact framed input the
/// digest claims (canonical record bytes, artifact bytes, canonical
/// request bytes, classifier payload, or page bytes depending on the
/// profile); SHA-256 over `bytes` must equal `value`.
///
/// On success returns the `DIGEST`-bearing record: the source object
/// with `digest` set to the preserved source text, re-validated under
/// the source schema. The digest is copied, never recomputed, so a
/// hash of the digest string can never be accepted as the source
/// digest.
///
/// Faults: `not_source_hash`, `missing_field`, `missing_digest`,
/// `invalid_digest`, `unknown_framing` (profile is a `Missing`
/// envelope), `unknown_profile`, `invalid_profile`,
/// `missing_evidence`, `invalid_evidence`, `bytes_unavailable`,
/// `digest_mismatch`, `digest_conflict`.
pub fn reconcile_source_hash(
    source: &CheckedRecord,
    bytes: Option<&[u8]>,
) -> Result<CheckedRecord, Fault> {
    let object = crawler_schema::record_value(source)
        .as_object()
        .ok_or_else(|| {
            fault(
                "not_source_hash",
                "source hash must be an object with value, profile, and evidence_refs"
                    .to_string(),
            )
        })?;

    // Established SHA-256 identity: the source digest text, verbatim.
    let digest_text = match object.get("value") {
        Some(Value::String(text)) => {
            if !is_digest_text(text) {
                return Err(fault(
                    "invalid_digest",
                    format!(
                        "source digest text must be 64 lowercase hex characters, got {text:?}"
                    ),
                ));
            }
            text.clone()
        }
        Some(value) if is_missing_envelope(value) => {
            return Err(fault(
                "missing_digest",
                "source digest is Missing; no established SHA-256 identity".to_string(),
            ));
        }
        Some(_) => {
            return Err(fault(
                "invalid_digest",
                "source digest text must be a 64-character lowercase hex string".to_string(),
            ));
        }
        None => {
            return Err(fault(
                "missing_field",
                "source hash object must contain 'value'".to_string(),
            ));
        }
    };

    // Correct input/framing: a pinned, known profile.
    let profile = match object.get("profile") {
        Some(Value::String(text)) => {
            if !KNOWN_PROFILES.contains(&text.as_str()) {
                return Err(fault(
                    "unknown_profile",
                    format!("unknown hash profile {text:?}; profiles are pinned and closed"),
                ));
            }
            text.clone()
        }
        Some(value) if is_missing_envelope(value) => {
            return Err(fault(
                "unknown_framing",
                "hash profile is Missing; unknown framing blocks digest establishment"
                    .to_string(),
            ));
        }
        Some(_) => {
            return Err(fault(
                "invalid_profile",
                "hash profile must be a pinned profile id string".to_string(),
            ));
        }
        None => {
            return Err(fault(
                "missing_field",
                "source hash object must contain 'profile'".to_string(),
            ));
        }
    };
    let _ = profile;

    // Supporting evidence must be present.
    match object.get("evidence_refs") {
        Some(Value::Array(_)) => {}
        Some(value) if is_missing_envelope(value) => {
            return Err(fault(
                "missing_evidence",
                "evidence_refs is Missing; supporting evidence is required".to_string(),
            ));
        }
        Some(_) => {
            return Err(fault(
                "invalid_evidence",
                "evidence_refs must be an array".to_string(),
            ));
        }
        None => {
            return Err(fault(
                "missing_field",
                "source hash object must contain 'evidence_refs'".to_string(),
            ));
        }
    }

    // Unavailable bytes block any shared field requiring a digest.
    let bytes = bytes.ok_or_else(|| {
        fault(
            "bytes_unavailable",
            "source bytes are unavailable; digest cannot be established".to_string(),
        )
    })?;

    // Byte identity: the digest text must name these exact bytes.
    // Hashing the digest string itself yields a different value and is
    // therefore rejected here, never adopted.
    if sha256_hex(bytes) != digest_text {
        return Err(fault(
            "digest_mismatch",
            "SHA-256 over the supplied bytes does not equal the source digest text"
                .to_string(),
        ));
    }

    // Conversion to DIGEST: preserve the source text verbatim.
    let mut reconciled = object.clone();
    match reconciled.get("digest") {
        Some(Value::String(existing)) if existing == &digest_text => {}
        Some(_) => {
            return Err(fault(
                "digest_conflict",
                "existing 'digest' field disagrees with the reconciled source digest"
                    .to_string(),
            ));
        }
        None => {
            reconciled.insert("digest".to_string(), Value::String(digest_text));
        }
    }
    crawler_schema::validate(crawler_schema::record_schema(source), Value::Object(reconciled))
}

/// Frame a canonical operational reference (§3.3).
///
/// `entity` must be one of the eleven closed reference entities and
/// `components` must carry exactly that entity's trailing components
/// (target/job/run/partition/walk/phase/shard/session-epoch/stage/model
/// version/input-hash/mutation/owner-domain/event/entity-type/reference/
/// reason as applicable), each nonempty. Components are length-framed
/// as `entity:count:len:bytes...`, so the encoding is reversible and
/// components containing `/`, `:`, or Unicode can never collide with
/// a different split. Callers keep integer/string unions distinct with
/// explicit type tags in the component text; framing preserves them
/// byte-exactly and never conflates integer `7` with string `"7"`.
///
/// Faults: `unknown_entity`, `arity_mismatch`, `empty_component`.
pub fn frame_reference(entity: &str, components: &[String]) -> Result<String, Fault> {
    let arity = KNOWN_REFERENCES
        .iter()
        .find(|(name, _)| *name == entity)
        .map(|(_, arity)| *arity)
        .ok_or_else(|| {
            fault(
                "unknown_entity",
                format!("unknown reference entity {entity:?}; entities are closed per §3.3"),
            )
        })?;
    if components.len() != arity {
        return Err(fault(
            "arity_mismatch",
            format!(
                "reference entity {entity:?} requires {arity} components, got {}",
                components.len()
            ),
        ));
    }
    for (index, component) in components.iter().enumerate() {
        if component.is_empty() {
            return Err(fault(
                "empty_component",
                format!("reference component {index} of {entity:?} must be nonempty"),
            ));
        }
    }
    let mut framed = String::new();
    framed.push_str(entity);
    framed.push(':');
    framed.push_str(&components.len().to_string());
    for component in components {
        framed.push(':');
        framed.push_str(&component.len().to_string());
        framed.push(':');
        framed.push_str(component);
    }
    Ok(framed)
}

/// Verify that `expected` is the `kernel-jcs-sha256/1` digest of `record`.
///
/// `expected` must be 64 lowercase hex characters; comparison is
/// against SHA-256 over [`canonical_bytes`]. A hash of the digest
/// string, or of any bytes other than the canonical record bytes,
/// fails with `digest_mismatch`.
///
/// Faults: `invalid_expected_digest`, `digest_mismatch`.
pub fn verify_record_digest(record: &CheckedRecord, expected: &str) -> Result<(), Fault> {
    if !is_digest_text(expected) {
        return Err(fault(
            "invalid_expected_digest",
            format!("expected digest must be 64 lowercase hex characters, got {expected:?}"),
        ));
    }
    let actual = sha256_hex(&canonical_bytes(record)?);
    if actual != expected {
        return Err(fault(
            "digest_mismatch",
            "record digest does not match the expected kernel digest".to_string(),
        ));
    }
    Ok(())
}

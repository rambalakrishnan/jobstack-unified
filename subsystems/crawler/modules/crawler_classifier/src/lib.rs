//! `crawler_classifier`: genuine SLM verdicts, shadow/bypass policy, and semantics.
//!
//! Implements seam map §7 (classifier result schema), §16.7 (semantic
//! transitions), and §18.1 (SLM transformation) for conformance **C15** and
//! **C16**:
//!
//! * **C15 — Classifier**: exact correlation of every output to its dispatched
//!   `(target, job_id, stage, model_version, input_hash)`; malformed,
//!   duplicate, mismatched, non-finite, and conflicting genuine outputs are
//!   inference errors, never implicit `PASS`. The genuine output is immutable
//!   for `(target, job_id, stage, model_version, input_hash)`: identical reuse
//!   is accepted, conflicting genuine bytes are rejected and audited.
//! * **C16 — Shadow/bypass**: the policy revision is pinned at claim and never
//!   changes in flight; bypass writes no classifier row and no synthetic
//!   classifier object; only a genuine applied `PASS` supports `SHORTLISTED`
//!   so a shadowed raw `VETO` and bypass alone stay `DISCOVERED`, while a
//!   later bypass preserves an earlier applicable genuine applied snippet
//!   `PASS`.
//!
//! Canonicalization follows §18.1: NFC (identity for the ASCII fixtures used
//! here), newline normalization (`\r\n`/`\r` → `\n`), outer trimming,
//! optional-empty substitution, ISO date (`YYYY-MM-DD`) formatting, then the
//! five-field newline payload `title`, `employer`, `snippet_or_description`,
//! `source_url`, `posted_date`. The input hash additionally binds `stage` and
//! `model_version`; cookies, authorization, profile fingerprint, worker,
//! lease, and batch identity are excluded.
//!
//! All records produced here are validated through [`crawler_schema::validate`]
//! under the structural `"audit_log"` envelope (genuine rows under
//! `"classifier_result"`): no bare JSON nulls, only typed `Missing` envelopes
//! with the six kernel reasons.

use crawler_authority::{grant_record, Grant};
use crawler_hashing::digest_bytes;
use crawler_inference_host::InferenceHost;
use crawler_schema::{record_value, validate, CheckedRecord, Fault};
use crawler_store::OwnerStore;
use crawler_time::ClockAuthority;
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};

/// Structural envelope for batch/result envelopes.
const OUTPUT_SCHEMA: &str = "audit_log";
/// Closed schema id for genuine classifier rows.
const RESULT_SCHEMA: &str = "classifier_result";

const STAGES: &[&str] = &["snippet", "description"];
const VERDICTS: &[&str] = &["PASS", "VETO"];
const SHADOW_MODES: &[&str] = &["on", "off"];

/// Hard §18.1 ceilings. Over-budget input is rejected, never truncated.
const MAX_ITEMS: usize = 25;
const MAX_DWELL_MS: u64 = 20;
/// Bounded reason text: nonempty, at most this many characters.
const MAX_REASON_CHARS: usize = 2000;

fn fault(code: &str, detail: impl Into<String>) -> Fault {
    Fault {
        code: code.to_string(),
        detail: detail.into(),
    }
}

fn missing(reason: &str, detail: impl Into<String>) -> Value {
    json!({"value": Value::Null, "reason": reason, "detail": detail.into()})
}

fn is_missing(value: &Value) -> bool {
    value
        .as_object()
        .is_some_and(|map| map.get("value").is_some_and(Value::is_null))
}


fn established<'a>(map: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    map.get(key).filter(|value| !is_missing(value))
}

fn object_of<'a>(
    record: &'a CheckedRecord,
    code: &'static str,
    what: &str,
) -> Result<&'a Map<String, Value>, Fault> {
    record_value(record).as_object().ok_or_else(|| {
        fault(
            code,
            format!("{what} must be a gate-validated object"),
        )
    })
}

fn required_text(
    map: &Map<String, Value>,
    key: &str,
    code: &'static str,
    what: &str,
) -> Result<String, Fault> {
    match established(map, key) {
        Some(Value::String(text)) if !text.is_empty() => Ok(text.clone()),
        Some(Value::String(_)) => Err(fault(
            code,
            format!("{what} field {key:?} must be a nonempty string"),
        )),
        Some(_) => Err(fault(
            code,
            format!("{what} field {key:?} must be a string"),
        )),
        None => Err(fault(
            code,
            format!("{what} requires established field {key:?}"),
        )),
    }
}

fn required_object<'a>(
    map: &'a Map<String, Value>,
    key: &str,
    code: &'static str,
    what: &str,
) -> Result<&'a Map<String, Value>, Fault> {
    match established(map, key) {
        Some(Value::Object(object)) => Ok(object),
        Some(_) => Err(fault(
            code,
            format!("{what} field {key:?} must be an object"),
        )),
        None => Err(fault(
            code,
            format!("{what} requires established object field {key:?}"),
        )),
    }
}

fn required_u64(
    map: &Map<String, Value>,
    key: &str,
    code: &'static str,
    what: &str,
) -> Result<u64, Fault> {
    match established(map, key) {
        Some(Value::Number(number)) => number.as_u64().ok_or_else(|| {
            fault(
                code,
                format!("{what} field {key:?} must be a nonnegative integer"),
            )
        }),
        Some(_) => Err(fault(
            code,
            format!("{what} field {key:?} must be a nonnegative integer"),
        )),
        None => Err(fault(
            code,
            format!("{what} requires established integer field {key:?}"),
        )),
    }
}

fn optional_u64(
    map: &Map<String, Value>,
    key: &str,
    code: &'static str,
    what: &str,
) -> Result<Option<u64>, Fault> {
    match map.get(key) {
        None => Ok(None),
        Some(value) if is_missing(value) => Ok(None),
        Some(Value::Number(number)) => number
            .as_u64()
            .map(Some)
            .ok_or_else(|| fault(code, format!("{what} field {key:?} must be a nonnegative integer"))),
        Some(_) => Err(fault(
            code,
            format!("{what} field {key:?} must be a nonnegative integer or Missing"),
        )),
    }
}

fn is_digest_text(text: &str) -> bool {
    text.len() == 64
        && text.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_iso_date(text: &str) -> bool {
    if text.len() != 10 {
        return false;
    }
    let bytes = text.as_bytes();
    if bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }
    for (index, byte) in bytes.iter().enumerate() {
        if index == 4 || index == 7 {
            continue;
        }
        if !byte.is_ascii_digit() {
            return false;
        }
    }
    let month: u32 = text[5..7].parse().unwrap_or(0);
    let day: u32 = text[8..10].parse().unwrap_or(0);
    (1..=12).contains(&month) && (1..=31).contains(&day)
}

fn normalize_newlines(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\r', "\n")
}

/// Canonicalize one §18.1 input field.
///
/// Newlines are normalized, outer whitespace is trimmed, and optional
/// `Missing` becomes the empty substitution. Required fields must be
/// established nonempty strings after trimming.
fn canonical_field(
    map: &Map<String, Value>,
    key: &str,
    what: &str,
    required: bool,
) -> Result<String, Fault> {
    match map.get(key) {
        None => {
            if required {
                Err(fault(
                    "invalid_item",
                    format!("{what} requires field {key:?}"),
                ))
            } else {
                Ok(String::new())
            }
        }
        Some(value) if is_missing(value) => {
            if required {
                Err(fault(
                    "invalid_item",
                    format!("{what} field {key:?} is required and cannot be Missing"),
                ))
            } else {
                Ok(String::new())
            }
        }
        Some(Value::String(text)) => {
            let normalized = normalize_newlines(text);
            let trimmed = normalized.trim().to_string();
            if required && trimmed.is_empty() {
                return Err(fault(
                    "invalid_item",
                    format!("{what} field {key:?} must be nonempty after trimming"),
                ));
            }
            Ok(trimmed)
        }
        Some(_) => Err(fault(
            "invalid_item",
            format!("{what} field {key:?} must be a string or Missing"),
        )),
    }
}

fn canonical_date(map: &Map<String, Value>, key: &str, what: &str) -> Result<String, Fault> {
    let text = canonical_field(map, key, what, false)?;
    if text.is_empty() {
        return Ok(String::new());
    }
    if !is_iso_date(&text) {
        return Err(fault(
            "invalid_item",
            format!(
                "{what} field {key:?} must be ISO YYYY-MM-DD or Missing; got {text:?}"
            ),
        ));
    }
    Ok(text)
}

fn validate_verdict(value: &Value, what: &str) -> Result<String, Fault> {
    match value {
        Value::String(text) if VERDICTS.contains(&text.as_str()) => Ok(text.clone()),
        Value::String(text) => Err(fault(
            "inference_output_invalid",
            format!("{what} verdict {text:?} must be PASS or VETO; malformed verdicts are never implicit PASS"),
        )),
        _ => Err(fault(
            "inference_output_invalid",
            format!("{what} verdict must be PASS or VETO"),
        )),
    }
}

fn validate_confidence(value: &Value, what: &str) -> Result<f64, Fault> {
    match value.as_f64() {
        Some(number) if number.is_finite() && (0.0..=1.0).contains(&number) => Ok(number),
        _ => Err(fault(
            "inference_output_invalid",
            format!("{what} requires a finite confidence in [0,1]"),
        )),
    }
}

fn validate_reason(value: &Value, what: &str) -> Result<String, Fault> {
    match value {
        Value::String(text) => {
            let chars = text.chars().count();
            if text.trim().is_empty() {
                return Err(fault(
                    "inference_output_invalid",
                    format!("{what} reason must be nonempty text"),
                ));
            }
            if chars > MAX_REASON_CHARS {
                return Err(fault(
                    "inference_output_invalid",
                    format!(
                        "{what} reason exceeds the {MAX_REASON_CHARS} character bound"
                    ),
                ));
            }
            Ok(text.clone())
        }
        _ => Err(fault(
            "inference_output_invalid",
            format!("{what} reason must be bounded nonempty text"),
        )),
    }
}

fn result_id(target: &str, job_id: &str, stage: &str, model_version: &str, input_hash: &str) -> String {
    format!("{target}:{job_id}:{stage}:{model_version}:{input_hash}")
}

// ---------------------------------------------------------------------------
// Parsed batch
// ---------------------------------------------------------------------------

struct ModelPins {
    id: String,
    version: String,
    artifact_digest: String,
    tokenizer_digest: String,
    prompt_digest: String,
    canonicalization_version: String,
}

impl ModelPins {
    fn parse(map: &Map<String, Value>) -> Result<Self, Fault> {
        let id = required_text(map, "id", "invalid_model", "batch model")?;
        let version = required_text(map, "version", "invalid_model", "batch model")?;
        if id.contains('\n') || id.contains('\r') || version.contains('\n') || version.contains('\r') {
            return Err(fault(
                "invalid_model",
                "model id and version must not contain newlines",
            ));
        }
        let artifact_digest = required_text(map, "artifact_digest", "invalid_model", "batch model")?;
        let tokenizer_digest =
            required_text(map, "tokenizer_digest", "invalid_model", "batch model")?;
        let prompt_digest = required_text(map, "prompt_digest", "invalid_model", "batch model")?;
        for (name, digest) in [
            ("artifact_digest", artifact_digest.as_str()),
            ("tokenizer_digest", tokenizer_digest.as_str()),
            ("prompt_digest", prompt_digest.as_str()),
        ] {
            if !is_digest_text(digest) {
                return Err(fault(
                    "invalid_model",
                    format!("batch model {name} must be 64 lowercase hex; pins come from the admitted manifest"),
                ));
            }
        }
        let canonicalization_version = required_text(
            map,
            "canonicalization_version",
            "invalid_model",
            "batch model",
        )?;
        Ok(Self {
            id,
            version,
            artifact_digest,
            tokenizer_digest,
            prompt_digest,
            canonicalization_version,
        })
    }
}

struct PolicyPins {
    revision: String,
    shadow_mode: String,
    bypass_enabled: bool,
    bypass_reason: Option<String>,
}

impl PolicyPins {
    fn parse(map: &Map<String, Value>, stage: &str) -> Result<Self, Fault> {
        let revision = required_text(map, "policy_revision", "invalid_policy", "batch policy")?;
        let pinned_revision =
            required_text(map, "pinned_revision", "invalid_policy", "batch policy")?;
        // Claim-pinned policy: the applied revision must equal the revision
        // pinned at claim. In-flight changes are rejected, never adapted.
        if revision != pinned_revision {
            return Err(fault(
                "claim_policy_changed",
                format!(
                    "policy revision {revision:?} does not match the claim-pinned revision {pinned_revision:?}; in-flight policy never changes"
                ),
            ));
        }
        let shadow_mode = required_text(map, "shadow_mode", "invalid_policy", "batch policy")?;
        if !SHADOW_MODES.contains(&shadow_mode.as_str()) {
            return Err(fault(
                "invalid_policy",
                format!("policy shadow_mode {shadow_mode:?} must be on or off"),
            ));
        }
        // Snippet shadow mode never applies to descriptions.
        if stage == "description" && shadow_mode == "on" {
            return Err(fault(
                "shadow_not_applicable",
                "snippet shadow mode never applies to description classification",
            ));
        }
        let bypass_enabled = match established(map, "bypass_enabled") {
            Some(Value::Bool(enabled)) => *enabled,
            Some(_) => {
                return Err(fault(
                    "invalid_policy",
                    "batch policy bypass_enabled must be a boolean",
                ))
            }
            None => {
                return Err(fault(
                    "invalid_policy",
                    "batch policy requires established field \"bypass_enabled\"",
                ))
            }
        };
        let bypass_reason = match map.get("bypass_reason") {
            None => None,
            Some(value) if is_missing(value) => None,
            Some(Value::String(text)) if !text.is_empty() => Some(text.clone()),
            Some(Value::String(_)) => {
                return Err(fault(
                    "invalid_policy",
                    "batch policy bypass_reason must be nonempty when established",
                ))
            }
            Some(_) => {
                return Err(fault(
                    "invalid_policy",
                    "batch policy bypass_reason must be a string or Missing",
                ))
            }
        };
        if bypass_enabled && bypass_reason.is_none() {
            return Err(fault(
                "invalid_policy",
                "bypass-enabled policy requires an explicit bypass_reason",
            ));
        }
        Ok(Self {
            revision,
            shadow_mode,
            bypass_enabled,
            bypass_reason,
        })
    }
}

struct BatchItem {
    job_id: String,
    input_hash: String,
    token_count: u64,
}

fn parse_items(
    map: &Map<String, Value>,
    stage: &str,
    model_version: &str,
) -> Result<(Vec<BatchItem>, u64), Fault> {
    let items = map
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| fault("invalid_batch", "batch requires an items array"))?;
    if items.is_empty() {
        return Err(fault("invalid_batch", "batch items cannot be empty"));
    }
    if items.len() > MAX_ITEMS {
        return Err(fault(
            "batch_too_large",
            format!(
                "batch carries {} items; the §18.1 ceiling is {MAX_ITEMS} and long input is never truncated",
                items.len()
            ),
        ));
    }
    let mut seen = HashSet::new();
    let mut parsed = Vec::with_capacity(items.len());
    let mut token_total: u64 = 0;
    for (index, item) in items.iter().enumerate() {
        let what = format!("batch items[{index}]");
        let item_map = item.as_object().ok_or_else(|| {
            fault(
                "invalid_batch",
                format!("{what} must be an object"),
            )
        })?;
        // A truncation marker is an explicit refusal signal: long input is
        // never silently truncated, so a truncated flag cannot be admitted.
        if matches!(item_map.get("truncated"), Some(Value::Bool(true))) {
            return Err(fault(
                "input_truncated",
                format!("{what} is marked truncated; long input is never silently truncated"),
            ));
        }
        let job_id = required_text(item_map, "job_id", "invalid_item", &what)?;
        if !seen.insert(job_id.clone()) {
            return Err(fault(
                "duplicate_job",
                format!("batch repeats job_id {job_id:?}; one item per job is required"),
            ));
        }
        let title = canonical_field(item_map, "title", &what, true)?;
        let employer = canonical_field(item_map, "employer", &what, false)?;
        let text = canonical_field(item_map, "text", &what, true).or_else(|_| {
            // Accept the §18.1 alias `snippet_or_description`.
            canonical_field(item_map, "snippet_or_description", &what, true)
        })?;
        let source_url = canonical_field(item_map, "source_url", &what, true)?;
        let posted_date = canonical_date(item_map, "posted_date", &what)?;
        let canonical_text =
            format!("{title}\n{employer}\n{text}\n{source_url}\n{posted_date}");
        let framed = format!("{canonical_text}\n{stage}\n{model_version}");
        let input_hash = digest_bytes(framed.as_bytes());
        let token_count = match item_map.get("token_count") {
            Some(Value::Number(number)) => number.as_u64().ok_or_else(|| {
                fault(
                    "unverifiable_token_budget",
                    format!("{what} token_count must be a nonnegative integer; unmeasured input cannot be admitted"),
                )
            })?,
            Some(value) if is_missing(value) => {
                return Err(fault(
                    "unverifiable_token_budget",
                    format!("{what} carries no token_count; long input is not silently truncated"),
                ))
            }
            _ => {
                return Err(fault(
                    "unverifiable_token_budget",
                    format!("{what} requires an established token_count"),
                ))
            }
        };
        token_total = token_total.saturating_add(token_count);
        parsed.push(BatchItem {
            job_id,
            input_hash,
            token_count,
        });
    }
    Ok((parsed, token_total))
}

// ---------------------------------------------------------------------------
// Store helpers
// ---------------------------------------------------------------------------

/// Look up one genuine row by canonical composite-key identity.
///
/// The composing owner store interprets `classifier_lookup`; reads never
/// create or advance state.
fn lookup_existing(
    store: &dyn OwnerStore,
    grant: &Grant,
    result_id: &str,
) -> Result<Option<Value>, Fault> {
    let query = validate(
        OUTPUT_SCHEMA,
        json!({"operation": "classifier_lookup", "result_id": result_id}),
    )?;
    let response = store.read(grant, &query)?;
    let map = object_of(&response, "invalid_store_response", "classifier lookup")?;
    let rows = map
        .get("rows")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            fault(
                "invalid_store_response",
                "classifier lookup must return a rows array",
            )
        })?;
    if rows.len() > 1 {
        return Err(fault(
            "invalid_store_response",
            format!("classifier lookup for {result_id:?} returned more than one row"),
        ));
    }
    Ok(rows.first().cloned())
}

fn genuine_fields_equal(existing: &Map<String, Value>, attempted: &Map<String, Value>) -> bool {
    for key in [
        "target",
        "job_id",
        "stage",
        "model_version",
        "input_hash",
        "verdict",
        "confidence",
        "reason",
        "model_artifact_digest",
        "tokenizer_digest",
        "prompt_digest",
        "canonicalization_version",
    ] {
        if existing.get(key) != attempted.get(key) {
            return false;
        }
    }
    true
}

fn owner_domain_of(grant: &Grant) -> String {
    record_value(grant_record(grant))
        .get("owner_domain")
        .and_then(Value::as_str)
        .unwrap_or("unknown_owner")
        .to_string()
}

// ---------------------------------------------------------------------------
// Lease settlement (optional)
// ---------------------------------------------------------------------------

/// Settle one held generation after a classified item, when the batch carries
/// explicit lease fencing for that job.
///
/// The `leases` object maps `job_id` to `{entity_type, row, lease,
/// expected}`. Success completes the held generation; failure reclaims it
/// with trigger `release`. Batches without `leases` leave lease settlement to
/// the pipeline stage effect.
fn settle_success(
    store: &dyn OwnerStore,
    clock: &dyn ClockAuthority,
    grant: &Grant,
    leases: Option<&Map<String, Value>>,
    job_id: &str,
) -> Result<Option<Value>, Fault> {
    let Some(leases) = leases else {
        return Ok(None);
    };
    let Some(entry) = leases.get(job_id) else {
        return Ok(None);
    };
    if is_missing(entry) {
        return Ok(None);
    }
    let entry_map = entry.as_object().ok_or_else(|| {
        fault(
            "invalid_batch",
            format!("batch leases entry for {job_id:?} must be an object or Missing"),
        )
    })?;
    let request = validate(
        OUTPUT_SCHEMA,
        json!({
            "operation": "complete",
            "entity_type": entry_map.get("entity_type").cloned().unwrap_or_else(|| missing("not_observed", "lease entry lacks an entity type")),
            "row": entry_map.get("row").cloned().unwrap_or_else(|| missing("not_observed", "lease entry lacks a row")),
            "lease": entry_map.get("lease").cloned().unwrap_or_else(|| missing("not_observed", "lease entry lacks lease evidence")),
            "expected": entry_map.get("expected").cloned().unwrap_or_else(|| missing("not_observed", "lease entry lacks expected fencing")),
        }),
    )?;
    let receipt = crawler_leases::complete(store, clock, grant, &request)?;
    Ok(Some(record_value(&receipt).clone()))
}

fn settle_failure(
    store: &dyn OwnerStore,
    clock: &dyn ClockAuthority,
    grant: &Grant,
    leases: Option<&Map<String, Value>>,
    job_id: &str,
    stage: &str,
    failure_code: &str,
) -> Result<Option<Value>, Fault> {
    let Some(leases) = leases else {
        return Ok(None);
    };
    let Some(entry) = leases.get(job_id) else {
        return Ok(None);
    };
    if is_missing(entry) {
        return Ok(None);
    }
    let entry_map = entry.as_object().ok_or_else(|| {
        fault(
            "invalid_batch",
            format!("batch leases entry for {job_id:?} must be an object or Missing"),
        )
    })?;
    let request = validate(
        OUTPUT_SCHEMA,
        json!({
            "operation": "reclaim",
            "entity_type": entry_map.get("entity_type").cloned().unwrap_or_else(|| missing("not_observed", "lease entry lacks an entity type")),
            "row": entry_map.get("row").cloned().unwrap_or_else(|| missing("not_observed", "lease entry lacks a row")),
            "lease": entry_map.get("lease").cloned().unwrap_or_else(|| missing("not_observed", "lease entry lacks lease evidence")),
            "expected": entry_map.get("expected").cloned().unwrap_or_else(|| missing("not_observed", "lease entry lacks expected fencing")),
            "reclaim": {"trigger": "release", "failure_reason": failure_code, "stage": stage},
        }),
    )?;
    let receipt = crawler_leases::reclaim(store, clock, grant, &request)?;
    Ok(Some(record_value(&receipt).clone()))
}

// ---------------------------------------------------------------------------
// Public interface
// ---------------------------------------------------------------------------

/// Classify one bounded batch through the inference host.
///
/// The batch carries the claim-pinned policy, the admitted model pins, the
/// lease deadline, and the raw §18.1 items. Every item is canonicalized and
/// hashed locally; the host correlates outputs exactly. Genuine rows persist
/// atomically in one owner-local transaction; bypass completes with null
/// genuine verdicts, applied `PASS`, an explicit bypass reason, and no
/// classifier row.
pub fn classify_batch(
    host: &dyn InferenceHost,
    store: &dyn OwnerStore,
    clock: &dyn ClockAuthority,
    grant: &Grant,
    batch: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let map = object_of(batch, "invalid_batch", "batch")?;
    let batch_id = required_text(map, "batch_id", "invalid_batch", "batch")?;
    let run_id = required_text(map, "run_id", "invalid_batch", "batch")?;
    let manifest_revision =
        required_text(map, "manifest_revision", "invalid_batch", "batch")?;
    let target = required_text(map, "target", "invalid_batch", "batch")?;
    let stage = required_text(map, "stage", "invalid_batch", "batch")?;
    if !STAGES.contains(&stage.as_str()) {
        return Err(fault(
            "invalid_stage",
            format!("batch stage {stage:?} must be snippet or description"),
        ));
    }
    let model_map = required_object(map, "model", "invalid_model", "batch")?;
    let model = ModelPins::parse(model_map)?;
    let policy_map = required_object(map, "policy", "invalid_policy", "batch")?;
    let policy = PolicyPins::parse(policy_map, &stage)?;

    let collection_dwell_ms = required_u64(map, "collection_dwell_ms", "invalid_batch", "batch")?;
    if collection_dwell_ms > MAX_DWELL_MS {
        return Err(fault(
            "collection_dwell_exceeded",
            format!(
                "batch collection dwell {collection_dwell_ms} ms exceeds the {MAX_DWELL_MS} ms bound"
            ),
        ));
    }
    let lease_expires_at = match established(map, "lease_expires_at") {
        Some(Value::Object(_)) => map.get("lease_expires_at").cloned().unwrap(),
        Some(_) => {
            return Err(fault(
                "unverifiable_lease_bound",
                "batch lease_expires_at must be an established TimePoint",
            ))
        }
        None => {
            return Err(fault(
                "unverifiable_lease_bound",
                "batch requires an established lease_expires_at TimePoint before dispatch",
            ))
        }
    };

    let (items, token_total) = parse_items(map, &stage, &model.version)?;
    if let Some(budget) = optional_u64(map, "batch_token_budget", "invalid_batch", "batch")? {
        if token_total > budget {
            return Err(fault(
                "batch_token_budget_exceeded",
                format!(
                    "batch needs {token_total} tokens; the admitted budget is {budget}"
                ),
            ));
        }
    }
    if let Some(declared) = optional_u64(map, "token_estimate", "invalid_batch", "batch")? {
        if declared != token_total {
            return Err(fault(
                "token_estimate_mismatch",
                format!(
                    "batch declares token_estimate {declared} but item token counts sum to {token_total}"
                ),
            ));
        }
    }

    let leases = match map.get("leases") {
        None => None,
        Some(value) if is_missing(value) => None,
        Some(Value::Object(object)) => Some(object),
        Some(_) => {
            return Err(fault(
                "invalid_batch",
                "batch leases must be an object mapping job_id to lease fencing, or Missing",
            ))
        }
    };

    let mut expected_hashes: HashMap<String, String> = HashMap::new();
    let mut host_items = Vec::with_capacity(items.len());
    for item in &items {
        expected_hashes.insert(item.job_id.clone(), item.input_hash.clone());
        host_items.push(json!({
            "job_id": item.job_id,
            "input_hash": item.input_hash,
            "token_count": item.token_count,
        }));
    }

    let host_batch = validate(
        OUTPUT_SCHEMA,
        json!({
            "run_id": run_id,
            "manifest_revision": manifest_revision,
            "model_version": model.version,
            "batch_id": batch_id,
            "target": target,
            "stage": stage,
            "items": host_items,
            "collection_dwell_ms": collection_dwell_ms,
            "token_estimate": token_total,
            "lease_expires_at": lease_expires_at,
        }),
    )?;

    let inference = match host.infer(&host_batch) {
        Ok(results) => results,
        Err(error) => {
            if !policy.bypass_enabled {
                // With bypass disabled the failure is preserved for retry;
                // settle any carried leases as a released failure and
                // propagate the inference error without writing a row.
                for item in &items {
                    let _ = settle_failure(
                        store,
                        clock,
                        grant,
                        leases,
                        &item.job_id,
                        &stage,
                        error.code.as_str(),
                    )?;
                }
                return Err(error);
            }
            let reason = policy.bypass_reason.clone().unwrap_or_else(|| {
                "slm_bypass_on_failure".to_string()
            });
            let observed_at = clock.now().map(|now| record_value(&now).clone()).unwrap_or_else(|_| {
                missing("not_observed", "authority clock unavailable for bypass evidence")
            });
            let mut bypassed = Vec::with_capacity(items.len());
            let mut settlements = Vec::new();
            for item in &items {
                if let Some(receipt) =
                    settle_success(store, clock, grant, leases, &item.job_id)?
                {
                    settlements.push(json!({"job_id": item.job_id, "lease_receipt": receipt}));
                }
                bypassed.push(json!({
                    "job_id": item.job_id,
                    "input_hash": item.input_hash,
                    "genuine": missing("not_applicable", "bypass completes with a null genuine verdict"),
                    "verdict_applied": "PASS",
                    "bypass_reason": reason,
                }));
            }
            // Bypass evidence is journaled without any classifier row and
            // without any synthetic classifier object.
            let transaction = validate(
                OUTPUT_SCHEMA,
                json!({
                    "operation": "classifier_bypass",
                    "batch_id": batch_id,
                    "run_id": run_id,
                    "target": target,
                    "stage": stage,
                    "model_version": model.version,
                    "policy_revision": policy.revision,
                    "bypass_reason": reason,
                    "bypassed": bypassed,
                    "inference_error": {"code": error.code, "detail": error.detail},
                    "owner_domain": owner_domain_of(grant),
                    "observed_at": observed_at,
                }),
            )?;
            let receipt = store.transact(grant, &transaction)?;
            return validate(
                OUTPUT_SCHEMA,
                json!({
                    "kind": "classifier_batch_result",
                    "batch_id": batch_id,
                    "run_id": run_id,
                    "target": target,
                    "stage": stage,
                    "model_version": model.version,
                    "policy_revision": policy.revision,
                    "shadow_mode": policy.shadow_mode,
                    "results": [],
                    "reused": [],
                    "bypassed": bypassed,
                    "bypass_reason": reason,
                    "submitted_count": items.len() as u64,
                    "accepted_count": 0,
                    "partial": false,
                    "bypassed_count": items.len() as u64,
                    "observed_at": observed_at,
                    "lease_settlements": settlements,
                    "store_receipt": record_value(&receipt),
                }),
            );
        }
    };

    // --- Exact correlation of the host outputs. ---
    let results_map = object_of(&inference, "inference_output_invalid", "inference results")?;
    let check_correlation = |key: &str, expected: &str| -> Result<(), Fault> {
        match results_map.get(key).and_then(Value::as_str) {
            Some(actual) if actual == expected => Ok(()),
            _ => Err(fault(
                "inference_output_mismatch",
                format!(
                    "inference result {key} does not correlate to the dispatched batch"
                ),
            )),
        }
    };
    check_correlation("run_id", &run_id)?;
    check_correlation("target", &target)?;
    check_correlation("stage", &stage)?;
    // The host nests the model as {id, version}; accept either nesting.
    let outcome_model_version = results_map
        .get("model")
        .and_then(Value::as_object)
        .and_then(|model| model.get("version"))
        .and_then(Value::as_str)
        .or_else(|| results_map.get("model_version").and_then(Value::as_str))
        .unwrap_or("");
    if outcome_model_version != model.version {
        return Err(fault(
            "inference_output_mismatch",
            "inference result model version does not correlate to the dispatched batch",
        ));
    }

    let outputs = results_map
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            fault(
                "inference_output_invalid",
                "inference result requires an items array",
            )
        })?;
    let mut seen_outputs = HashSet::new();
    struct AcceptedOutput {
        job_id: String,
        input_hash: String,
        verdict: String,
        confidence: f64,
        reason: String,
    }
    let mut accepted: Vec<AcceptedOutput> = Vec::with_capacity(outputs.len());
    for (index, output) in outputs.iter().enumerate() {
        let what = format!("inference result items[{index}]");
        let output_map = output.as_object().ok_or_else(|| {
            fault(
                "inference_output_invalid",
                format!("{what} must be an object"),
            )
        })?;
        let job_id = match established(output_map, "job_id") {
            Some(Value::String(text)) if !text.is_empty() => text.clone(),
            _ => {
                return Err(fault(
                    "inference_output_invalid",
                    format!("{what} requires an established job_id"),
                ))
            }
        };
        if !seen_outputs.insert(job_id.clone()) {
            return Err(fault(
                "inference_output_duplicate",
                format!("inference returned job_id {job_id:?} more than once"),
            ));
        }
        let expected_hash = expected_hashes.get(&job_id).ok_or_else(|| {
            fault(
                "inference_output_mismatch",
                format!("inference returned job_id {job_id:?} that was not dispatched"),
            )
        })?;
        let input_hash = match established(output_map, "input_hash") {
            Some(Value::String(text)) => text.clone(),
            _ => {
                return Err(fault(
                    "inference_output_invalid",
                    format!("{what} requires an established input_hash"),
                ))
            }
        };
        if &input_hash != expected_hash {
            return Err(fault(
                "inference_output_mismatch",
                format!("inference returned a different input hash for job_id {job_id:?}"),
            ));
        }
        // Per-item stage/model correlation when the host echoes them.
        if let Some(Value::String(item_stage)) = established(output_map, "stage") {
            if item_stage != &stage {
                return Err(fault(
                    "inference_output_mismatch",
                    format!("inference returned stage {item_stage:?} for job_id {job_id:?}; expected {stage:?}"),
                ));
            }
        }
        if let Some(Value::String(item_model)) = established(output_map, "model_version") {
            if item_model != &model.version {
                return Err(fault(
                    "inference_output_mismatch",
                    format!("inference returned model {item_model:?} for job_id {job_id:?}; expected {:?}", model.version),
                ));
            }
        }
        let verdict_value = output_map.get("verdict").ok_or_else(|| {
            fault(
                "inference_output_invalid",
                format!("{what} requires a verdict"),
            )
        })?;
        let verdict = validate_verdict(verdict_value, &what)?;
        // The host echoes an applied verdict; the classifier recomputes the
        // effective application from the claim-pinned shadow policy instead
        // of trusting it, but a malformed echo is still rejected.
        if let Some(applied_echo) = output_map.get("verdict_applied") {
            if !is_missing(applied_echo) {
                let _ = validate_verdict(applied_echo, &format!("{what} applied echo"))?;
            }
        }
        let confidence_value = output_map.get("confidence").ok_or_else(|| {
            fault(
                "inference_output_invalid",
                format!("{what} requires a confidence"),
            )
        })?;
        let confidence = validate_confidence(confidence_value, &what)?;
        let reason_value = output_map.get("reason").ok_or_else(|| {
            fault(
                "inference_output_invalid",
                format!("{what} requires a reason"),
            )
        })?;
        let reason = validate_reason(reason_value, &what)?;
        accepted.push(AcceptedOutput {
            job_id,
            input_hash,
            verdict,
            confidence,
            reason,
        });
    }

    // --- Build genuine rows and enforce immutability. ---
    let now = clock.now()?;
    let now_value = record_value(&now).clone();
    let latency_value = results_map
        .get("observed_latency_ms")
        .filter(|value| !is_missing(value))
        .and_then(Value::as_f64)
        .filter(|number| number.is_finite() && *number >= 0.0)
        .map(Value::from)
        .unwrap_or_else(|| missing("not_observed", "monotonic latency unavailable for this dispatch"));

    let mut fresh_rows: Vec<Value> = Vec::new();
    let mut reused_rows: Vec<Value> = Vec::new();
    for output in &accepted {
        // Shadow application: snippet shadow-on records the raw genuine
        // verdict immutably and applies PASS; everything else applies the
        // genuine verdict. A shadowed raw VETO is never rewritten into a
        // genuine PASS.
        let applied = if stage == "snippet" && policy.shadow_mode == "on" {
            "PASS".to_string()
        } else {
            output.verdict.clone()
        };
        let id = result_id(
            &target,
            &output.job_id,
            &stage,
            &model.version,
            &output.input_hash,
        );
        let row = json!({
            "result_id": id,
            "target": target,
            "job_id": output.job_id,
            "stage": stage,
            "model_id": model.id,
            "model_version": model.version,
            "input_hash": output.input_hash,
            "verdict": output.verdict,
            "verdict_applied": applied,
            "confidence": output.confidence,
            "reason": output.reason,
            "classified_at": now_value,
            "latency_ms": latency_value,
            "model_artifact_digest": model.artifact_digest,
            "tokenizer_digest": model.tokenizer_digest,
            "prompt_digest": model.prompt_digest,
            "canonicalization_version": model.canonicalization_version,
            "application_revision": 1,
            "policy_revision": policy.revision,
            "last_applied_at": now_value,
            "created_at": now_value,
            "expires_at": missing("not_applicable", "classifier result TTL is disabled"),
            "application_history": [{
                "policy_revision": policy.revision,
                "verdict_applied": applied,
                "applied_at": now_value,
            }],
        });
        // The row must pass the closed gate before any store contact.
        let checked_row = validate(RESULT_SCHEMA, row.clone())?;
        let checked_map = record_value(&checked_row)
            .as_object()
            .expect("validated row is an object");

        if let Some(existing) = lookup_existing(store, grant, &id)? {
            let existing_map = existing.as_object().ok_or_else(|| {
                fault(
                    "invalid_store_response",
                    "stored classifier row must be an object",
                )
            })?;
            if genuine_fields_equal(existing_map, checked_map) {
                reused_rows.push(existing.clone());
                continue;
            }
            // Conflicting genuine bytes under an immutable key: reject and
            // audit without overwriting the stored row.
            let conflict = validate(
                OUTPUT_SCHEMA,
                json!({
                    "operation": "classifier_conflict",
                    "result_id": id,
                    "target": target,
                    "job_id": output.job_id,
                    "stage": stage,
                    "model_version": model.version,
                    "input_hash": output.input_hash,
                    "existing": existing,
                    "attempted": row,
                    "owner_domain": owner_domain_of(grant),
                    "observed_at": now_value,
                }),
            )?;
            let _ = store.transact(grant, &conflict)?;
            return Err(fault(
                "genuine_conflict",
                format!(
                    "conflicting genuine bytes for {id:?}; the genuine output is immutable and identical reuse is required"
                ),
            ));
        }
        fresh_rows.push(row);
    }

    // One owner-local durable effect for the admitted batch.
    let transaction = validate(
        OUTPUT_SCHEMA,
        json!({
            "operation": "classifier_batch_insert",
            "batch_id": batch_id,
            "run_id": run_id,
            "target": target,
            "stage": stage,
            "model_version": model.version,
            "policy_revision": policy.revision,
            "shadow_mode": policy.shadow_mode,
            "results": fresh_rows,
            "reused_result_ids": reused_rows.iter().filter_map(|row| row.get("result_id").cloned()).collect::<Vec<_>>(),
            "submitted_count": items.len() as u64,
            "accepted_count": accepted.len() as u64,
            "owner_domain": owner_domain_of(grant),
            "classified_at": now_value,
        }),
    )?;
    let receipt = store.transact(grant, &transaction)?;

    let mut settlements = Vec::new();
    for output in &accepted {
        if let Some(lease_receipt) = settle_success(store, clock, grant, leases, &output.job_id)? {
            settlements.push(json!({"job_id": output.job_id, "lease_receipt": lease_receipt}));
        }
    }

    let submitted = items.len() as u64;
    let accepted_count = accepted.len() as u64;
    validate(
        OUTPUT_SCHEMA,
        json!({
            "kind": "classifier_batch_result",
            "batch_id": batch_id,
            "run_id": run_id,
            "target": target,
            "stage": stage,
            "model_version": model.version,
            "policy_revision": policy.revision,
            "shadow_mode": policy.shadow_mode,
            "results": fresh_rows,
            "reused": reused_rows,
            "bypassed": [],
            "submitted_count": submitted,
            "accepted_count": accepted_count,
            "partial": accepted_count < submitted,
            "classified_at": now_value,
            "lease_settlements": settlements,
            "store_receipt": record_value(&receipt),
        }),
    )
}

/// Re-apply a cached genuine result under the claim-pinned policy.
///
/// The genuine verdict, confidence, reason, and input hash are immutable;
/// only the effective application (`verdict_applied`, `policy_revision`,
/// `last_applied_at`, `application_revision`) advances, with the prior
/// application history retained. Snippet shadow-on applies `PASS` while
/// preserving a raw genuine `VETO`; descriptions never take snippet shadow.
pub fn apply_cached_result(
    result: &CheckedRecord,
    policy: &CheckedRecord,
    stage: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let result_map = object_of(result, "invalid_result", "cached result")?;
    // Accept either a bare classifier row or an envelope carrying `result`.
    let row_map: &Map<String, Value> = if result_map.contains_key("verdict")
        || result_map.contains_key("result_id")
    {
        result_map
    } else if let Some(Value::Object(nested)) = established(result_map, "result") {
        nested
    } else {
        return Err(fault(
            "invalid_result",
            "cached result must be a classifier row or an envelope carrying one",
        ));
    };

    let policy_map = object_of(policy, "invalid_policy", "policy")?;
    let stage_map = object_of(stage, "invalid_stage", "stage")?;

    let stage_name = required_text(stage_map, "stage", "invalid_stage", "stage")?;
    if !STAGES.contains(&stage_name.as_str()) {
        return Err(fault(
            "invalid_stage",
            format!("stage {stage_name:?} must be snippet or description"),
        ));
    }
    let pinned_revision = required_text(stage_map, "pinned_revision", "invalid_stage", "stage")?;
    let policy_revision = required_text(policy_map, "policy_revision", "invalid_policy", "policy")?;
    if policy_revision != pinned_revision {
        return Err(fault(
            "policy_changed",
            format!(
                "policy revision {policy_revision:?} does not match the claim-pinned revision {pinned_revision:?}; in-flight policy never changes"
            ),
        ));
    }
    let shadow_mode = required_text(policy_map, "shadow_mode", "invalid_policy", "policy")?;
    if !SHADOW_MODES.contains(&shadow_mode.as_str()) {
        return Err(fault(
            "invalid_policy",
            format!("policy shadow_mode {shadow_mode:?} must be on or off"),
        ));
    }
    if stage_name == "description" && shadow_mode == "on" {
        return Err(fault(
            "shadow_not_applicable",
            "snippet shadow mode never applies to description classification",
        ));
    }

    // Validate the immutable genuine fields without trusting the echo.
    let genuine_stage = required_text(row_map, "stage", "invalid_result", "cached result")?;
    if genuine_stage != stage_name {
        return Err(fault(
            "stage_mismatch",
            format!(
                "cached result stage {genuine_stage:?} does not match application stage {stage_name:?}"
            ),
        ));
    }
    let target = required_text(row_map, "target", "invalid_result", "cached result")?;
    let job_id = required_text(row_map, "job_id", "invalid_result", "cached result")?;
    let model_version = required_text(row_map, "model_version", "invalid_result", "cached result")?;
    let input_hash = required_text(row_map, "input_hash", "invalid_result", "cached result")?;
    if !is_digest_text(&input_hash) {
        return Err(fault(
            "invalid_result",
            "cached result input_hash must be 64 lowercase hex",
        ));
    }
    let genuine_value = row_map.get("verdict").ok_or_else(|| {
        fault("invalid_result", "cached result requires a genuine verdict")
    })?;
    if is_missing(genuine_value) {
        return Err(fault(
            "invalid_result",
            "cached result genuine verdict cannot be Missing; bypass writes no row",
        ));
    }
    let genuine = validate_verdict(genuine_value, "cached result")?;
    let confidence_value = row_map.get("confidence").ok_or_else(|| {
        fault("invalid_result", "cached result requires a confidence")
    })?;
    let confidence = validate_confidence(confidence_value, "cached result")?;
    let reason_value = row_map.get("reason").ok_or_else(|| {
        fault("invalid_result", "cached result requires a reason")
    })?;
    let reason = validate_reason(reason_value, "cached result")?;
    let model_id = required_text(row_map, "model_id", "invalid_result", "cached result")
        .unwrap_or_else(|_| "unknown_model".to_string());
    let artifact_digest =
        required_text(row_map, "model_artifact_digest", "invalid_result", "cached result")?;
    let tokenizer_digest =
        required_text(row_map, "tokenizer_digest", "invalid_result", "cached result")?;
    let prompt_digest =
        required_text(row_map, "prompt_digest", "invalid_result", "cached result")?;
    for (name, digest) in [
        ("model_artifact_digest", artifact_digest.as_str()),
        ("tokenizer_digest", tokenizer_digest.as_str()),
        ("prompt_digest", prompt_digest.as_str()),
    ] {
        if !is_digest_text(digest) {
            return Err(fault(
                "invalid_result",
                format!("cached result {name} must be 64 lowercase hex from the admitted manifest"),
            ));
        }
    }
    let canonicalization_version = required_text(
        row_map,
        "canonicalization_version",
        "invalid_result",
        "cached result",
    )?;
    let prior_revision = match row_map.get("application_revision") {
        Some(Value::Number(number)) => number.as_u64().ok_or_else(|| {
            fault(
                "invalid_result",
                "cached result application_revision must be a nonnegative integer",
            )
        })?,
        _ => {
            return Err(fault(
                "invalid_result",
                "cached result requires an application_revision",
            ))
        }
    };
    let application_revision = prior_revision.checked_add(1).ok_or_else(|| {
        fault(
            "invalid_result",
            "cached result application_revision overflow",
        )
    })?;

    let applied = if stage_name == "snippet" && shadow_mode == "on" {
        "PASS".to_string()
    } else {
        genuine.clone()
    };

    let applied_at = stage_map
        .get("applied_at")
        .filter(|value| !is_missing(value))
        .cloned()
        .or_else(|| {
            policy_map
                .get("applied_at")
                .filter(|value| !is_missing(value))
                .cloned()
        })
        .unwrap_or_else(|| missing("not_observed", "no application timestamp was supplied"));

    let mut history: Vec<Value> = match row_map.get("application_history") {
        None => Vec::new(),
        Some(value) if is_missing(value) => Vec::new(),
        Some(Value::Array(entries)) => entries.clone(),
        Some(_) => {
            return Err(fault(
                "invalid_result",
                "cached result application_history must be an array or Missing",
            ))
        }
    };
    history.push(json!({
        "policy_revision": policy_revision,
        "verdict_applied": applied,
        "applied_at": applied_at,
    }));

    let classified_at = row_map
        .get("classified_at")
        .cloned()
        .unwrap_or_else(|| missing("not_observed", "cached result lacks classification time"));
    let created_at = row_map
        .get("created_at")
        .cloned()
        .unwrap_or_else(|| missing("not_observed", "cached result lacks creation time"));
    let latency_ms = row_map
        .get("latency_ms")
        .cloned()
        .unwrap_or_else(|| missing("not_observed", "cached result lacks latency evidence"));
    let expires_at = row_map.get("expires_at").cloned().unwrap_or_else(|| {
        missing("not_applicable", "classifier result TTL is disabled")
    });
    let result_id_value = row_map
        .get("result_id")
        .cloned()
        .unwrap_or_else(|| {
            Value::String(result_id(&target, &job_id, &stage_name, &model_version, &input_hash))
        });

    validate(
        RESULT_SCHEMA,
        json!({
            "result_id": result_id_value,
            "target": target,
            "job_id": job_id,
            "stage": stage_name,
            "model_id": model_id,
            "model_version": model_version,
            "input_hash": input_hash,
            "verdict": genuine,
            "verdict_applied": applied,
            "confidence": confidence,
            "reason": reason,
            "classified_at": classified_at,
            "latency_ms": latency_ms,
            "model_artifact_digest": artifact_digest,
            "tokenizer_digest": tokenizer_digest,
            "prompt_digest": prompt_digest,
            "canonicalization_version": canonicalization_version,
            "application_revision": application_revision,
            "policy_revision": policy_revision,
            "last_applied_at": applied_at,
            "created_at": created_at,
            "expires_at": expires_at,
            "application_history": history,
        }),
    )
}

/// Derive the legacy semantic candidate from genuine/applied history.
///
/// Only a genuine applied `PASS` (established genuine `PASS` plus
/// established applied `PASS`) supports `SHORTLISTED`. Genuine `VETO`, no
/// genuine verdict, bypass alone, and a shadowed raw `VETO` support
/// `DISCOVERED`; a later bypass preserves an earlier applicable genuine
/// applied snippet `PASS`. Authoritative closure supports `CLOSED`; veto and
/// absence never do, and closed postings never reopen. This function never
/// writes `CLAIMED`/`APPLIED` product state.
pub fn derive_semantic_candidate(
    history: &CheckedRecord,
    closure: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let history_map = object_of(history, "invalid_history", "history")?;
    let closure_map = object_of(closure, "invalid_closure", "closure")?;

    let events = history_map
        .get("events")
        .and_then(Value::as_array)
        .ok_or_else(|| fault("invalid_history", "history requires an events array"))?;

    let prior_candidate = match history_map.get("prior_candidate") {
        None => None,
        Some(value) if is_missing(value) => None,
        Some(Value::String(text))
            if ["DISCOVERED", "SHORTLISTED", "CLOSED"].contains(&text.as_str()) =>
        {
            Some(text.clone())
        }
        Some(Value::String(text)) => {
            return Err(fault(
                "invalid_history",
                format!(
                    "prior_candidate {text:?} must be DISCOVERED, SHORTLISTED, or CLOSED; crawler never writes CLAIMED/APPLIED"
                ),
            ))
        }
        Some(_) => {
            return Err(fault(
                "invalid_history",
                "prior_candidate must be a semantic candidate string or Missing",
            ))
        }
    };

    // Reject any CLAIMED/APPLIED contamination in the supplied history.
    for (index, event) in events.iter().enumerate() {
        let Some(event_map) = event.as_object() else {
            return Err(fault(
                "invalid_history",
                format!("history events[{index}] must be an object"),
            ));
        };
        for key in ["candidate", "semantic_candidate", "display_state"] {
            if let Some(Value::String(text)) = established(event_map, key) {
                if text == "CLAIMED" || text == "APPLIED" {
                    return Err(fault(
                        "product_state_refused",
                        format!(
                            "history events[{index}] carries product state {text:?}; crawler never writes CLAIMED/APPLIED"
                        ),
                    ));
                }
            }
        }
    }

    let authoritative_closure = match closure_map.get("authoritative_closure") {
        Some(Value::Bool(closed)) => *closed,
        Some(value) if is_missing(value) => false,
        None => false,
        Some(_) => {
            return Err(fault(
                "invalid_closure",
                "closure authoritative_closure must be a boolean or Missing",
            ))
        }
    };

    // Closure dominates every other signal; closed postings never reopen.
    if authoritative_closure {
        return validate(
            OUTPUT_SCHEMA,
            json!({
                "semantic_candidate": "CLOSED",
                "prior_candidate": prior_candidate.map(Value::String).unwrap_or_else(|| missing("not_applicable", "no prior candidate was supplied")),
                "genuine_pass_present": false,
                "closure_authoritative": true,
                "evidence": "authoritative closure supports CLOSED; veto and absence never do",
            }),
        );
    }
    if prior_candidate.as_deref() == Some("CLOSED") {
        return validate(
            OUTPUT_SCHEMA,
            json!({
                "semantic_candidate": "CLOSED",
                "prior_candidate": "CLOSED",
                "genuine_pass_present": false,
                "closure_authoritative": false,
                "evidence": "closed postings do not automatically reopen",
            }),
        );
    }

    fn genuine_of(event: &Map<String, Value>) -> Option<String> {
        for key in ["genuine", "verdict", "content_verdict"] {
            if let Some(Value::String(text)) = established(event, key) {
                return Some(text.clone());
            }
        }
        None
    }

    fn applied_of(event: &Map<String, Value>) -> Option<String> {
        for key in ["applied", "verdict_applied"] {
            if let Some(Value::String(text)) = established(event, key) {
                return Some(text.clone());
            }
        }
        None
    }

    let mut genuine_pass_present = false;
    let mut bypass_seen = false;
    for event in events.iter() {
        let event_map = event.as_object().expect("validated object");
        if matches!(established(event_map, "bypass"), Some(Value::Bool(true))) {
            bypass_seen = true;
        }
        // Bypass-alone events carry a null genuine verdict and never shortlist.
        let genuine = genuine_of(event_map);
        let applied = applied_of(event_map);
        if genuine.as_deref() == Some("PASS") && applied.as_deref() == Some("PASS") {
            genuine_pass_present = true;
        }
    }

    let candidate = if genuine_pass_present {
        "SHORTLISTED"
    } else {
        "DISCOVERED"
    };
    let evidence = if genuine_pass_present {
        if bypass_seen {
            "a later bypass preserves the earlier applicable genuine applied PASS"
        } else {
            "an established genuine applied PASS supports SHORTLISTED"
        }
    } else if bypass_seen {
        "bypass alone supports DISCOVERED"
    } else {
        "genuine VETO, no genuine verdict, and shadowed raw VETO support DISCOVERED"
    };

    validate(
        OUTPUT_SCHEMA,
        json!({
            "semantic_candidate": candidate,
            "prior_candidate": prior_candidate.map(Value::String).unwrap_or_else(|| missing("not_applicable", "no prior candidate was supplied")),
            "genuine_pass_present": genuine_pass_present,
            "closure_authoritative": false,
            "evidence": evidence,
        }),
    )
}

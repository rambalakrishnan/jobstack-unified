//! `crawler_feed`: JobFeedManifest publication with output-completeness honesty (C42).
//!
//! Implements seam map §4.4 (`JobFeedManifest`) and §19.5 (observation and
//! output) on top of the structural [`crawler_schema`] gate:
//!
//! * [`publish_feed`] validates a feed request, verifies its cutoff prefix
//!   against the owner journal, durably installs every referenced logical row,
//!   listing, coverage export, and the manifest itself through
//!   [`ArtifactStore`] (bytes installed and read back before any reference is
//!   emitted, per [OWD-PUBLISH]), and returns a `TaskOutput` record whose
//!   `completeness` concerns only this output contract.
//! * Output completeness never implies proven discovery, pagination
//!   completeness, suitability, permission to apply, or application success.
//!   A `complete` manifest honestly describes incomplete partitions: coverage
//!   always includes partitions producing no jobs, limitations always carry
//!   explicit disclaimers, listing-only entries never fabricate details, and
//!   any suitability/permission/applied/proven-discovery claim faults.
//!
//! # Request shape (`audit_log`)
//!
//! ```text
//! {
//!   "feed_id": TEXT, "run_id": TEXT,
//!   "task_digest": DIGEST (64hex string or {digest: 64hex}),
//!   "selection_policy": {"include_failed": BOOL, "include_render_failed": BOOL,
//!                       "policy_pin": TEXT},
//!   "cutoff": {"journal_id": TEXT, "through": REV} ("last_sequence" aliases "through"),
//!   "completeness": "complete" | "partial" | "unknown",
//!   "jobs": [{"entity": JobEntityKey, "logical_row": AR|LogicalRow,
//!             "crawler_revision": POS, "downstream_revision": REV,
//!             "evidence_refs": SUPPORT}],
//!   "listing_only": [{"target": ID, "job_id": ID, "listing": AR|Listing,
//!                     "pipeline_state": §16.1 state, "detail_materialized": false,
//!                     "evidence_refs": SUPPORT}],
//!   "coverage": [AR | CoverageExport],
//!   "limitations": [TEXT],
//!   "evidence_refs": SUPPORT,
//!   "output_name"?: TEXT, "output_kind"?: TEXT, "output_schema_pin"?: OBJECT
//! }
//! ```
//!
//! `JobEntityKey` is `{entity_type: "job", target, job_id}` (`entity: "job"`
//! and `id` alias `job_id` are accepted). `LogicalRow` must carry
//! `record_type: "logical_row"`, a matching entity, `registration_digest`, and
//! a version vector (or `domains` map) whose crawler/downstream revisions equal
//! the entry's revisions. `Listing` must carry matching `target`/`job_id` and
//! the entry's exact `pipeline_state`. `CoverageExport` must carry
//! `record_type: "crawler_coverage_export"`, the feed's `run_id`, a
//! `partition_id`, a `proof.pagination_coverage_proven` boolean, and nonempty
//! evidence.
//!
//! # Output shape (`audit_log` carrying a `TaskOutput`)
//!
//! ```text
//! {
//!   "record_type": "task_output", "kind": TEXT, "name": TEXT,
//!   "output_schema_pin": {"schema": "crawler_job_feed", "version": "crawler-seam/0.1.0"},
//!   "artifact": AR (manifest), "manifest": JobFeedManifest,
//!   "completeness": "complete"|"partial"|"unknown",
//!   "support": SUPPORT, "limitations": [TEXT], "evidence_refs": SUPPORT,
//!   "feed_id": TEXT, "run_id": TEXT,
//!   "jobs_count": REV, "listing_only_count": REV, "coverage_count": REV,
//!   "partition_ids": [TEXT], "task_digest": DIGEST
//! }
//! ```
//!
//! The embedded `manifest` is the complete `crawler_job_feed` record:
//! `record_type`, `schema_version`, `feed_id`, `run_id`, `task_digest`,
//! `selection_policy`, `cutoff` (a verified `journal_prefix`), `jobs`,
//! `listing_only`, `coverage` (all ARs), `limitations` (caller text plus the
//! mandatory disclaimers), and `evidence_refs`.
//!
//! # Forbidden behavior
//!
//! * Any suitability, permission-to-apply, applied/hired, qualification, or
//!   proven-discovery/coverage claim faults (`proof_overreach`,
//!   `application_assertion_refused`). Presence is never suitability or
//!   permission; `complete` never means proven or applied.
//! * Listing-only entries with `detail_materialized != false`, an unknown
//!   `pipeline_state`, or a `failed`/`render_failed` state excluded by the
//!   selection policy fault; details are never fabricated for vetoes.
//! * Crawler-authored downstream values (`track`, `priority_hint`, `selection`,
//!   `materials`, `application_attempts`, `evaluations`, `downstream_value`, …)
//!   at any feed/entry level fault. This module never publishes domain
//!   revisions; it only references already-published rows.
//! * Empty coverage, empty top-level or per-entry evidence, missing revision
//!   vectors, missing selection policy/cutoff/limitations, a cutoff beyond the
//!   journal head, or revision/entity mismatches fault.
//! * No bare JSON nulls are emitted; reads never advance a journal and no
//!   cross-owner transaction is performed.

use crawler_artifacts::ArtifactStore;
use crawler_authority::Grant;
use crawler_schema::{record_value, validate, CheckedRecord, Fault};
use crawler_store::OwnerStore;
use serde_json::{json, Map, Value};

/// Manifest record type (§4.4).
const RECORD_TYPE: &str = "crawler_job_feed";
/// Crawler seam profile version.
const SCHEMA_VERSION: &str = "crawler-seam/0.1.0";
/// Structural envelope for requests and TaskOutputs.
const OUTPUT_SCHEMA: &str = "audit_log";
/// Closed feed schema for the manifest itself.
const FEED_SCHEMA: &str = "crawler_job_feed";

/// Exact listing vocabulary (§16.1), mirrored from `crawler_pipeline`.
const LISTING_STATES: &[&str] = &[
    "pending_snippet_classify",
    "pending_enrich",
    "pending_description_classify",
    "pending_finalize",
    "enqueued",
    "finalized",
    "deduped",
    "vetoed",
    "render_failed",
    "failed",
];

/// Claim fields that must never appear in a feed (lowercase exact match).
/// `proven` / `pagination_coverage_proven` are legitimate *inside* coverage
/// exports (per-partition proof) and are therefore only rejected at feed and
/// entry levels, not by the global scan.
const BANNED_KEYS: &[&str] = &[
    "suitability",
    "suitable",
    "permission_to_apply",
    "permission",
    "may_apply",
    "can_apply",
    "apply_allowed",
    "eligible_to_apply",
    "applied",
    "application_success",
    "application_result",
    "application_status",
    "application_outcome",
    "hired",
    "offer",
    "offer_received",
    "discovery_proven",
    "coverage_proven",
    "proven_discovery",
    "proven_coverage",
    "exhaustive",
    "complete_coverage",
    "all_jobs_found",
    "total_complete",
    "fully_covered",
    "discovery_complete",
    "coverage_complete",
    "qualified",
    "qualification",
    "requirement_satisfied",
    "satisfies_requirements",
    "meets_requirements",
    "requirement_satisfaction",
    "downstream_value",
    "downstream_snapshot",
    "crawler_authored_downstream",
];

/// Standalone string values that assert an application outcome (lowercase exact
/// match after trimming). Free-text job content never equals these exactly.
const BANNED_VALUES: &[&str] = &["applied", "hired", "application_success"];

/// Proof keys rejected at feed/entry levels even though `proven` is allowed
/// inside coverage bytes.
const ENTRY_PROOF_KEYS: &[&str] = &["proven", "pagination_coverage_proven"];

/// Downstream domain fields (§2.2) that a crawler feed must never author.
const DOWNSTREAM_KEYS: &[&str] = &[
    "track",
    "priority_hint",
    "selection",
    "ownership",
    "evaluations",
    "materials",
    "application_attempts",
    "downstream_value",
    "downstream_snapshot",
];

/// Mandatory disclaimers appended to every manifest's limitations.
const STANDARD_LIMITATIONS: &[&str] = &[
    "Output completeness concerns this feed contract only; it does not prove target coverage, pagination completeness, suitability, permission to apply, or application success.",
    "Presence in this feed is not suitability or permission to apply.",
    "Coverage includes partitions producing no jobs; an empty feed is not proof of empty target coverage.",
];

const REQUEST_ALLOWED: &[&str] = &[
    "feed_id",
    "run_id",
    "task_digest",
    "selection_policy",
    "cutoff",
    "completeness",
    "jobs",
    "listing_only",
    "coverage",
    "limitations",
    "evidence_refs",
    "output_name",
    "output_kind",
    "output_schema_pin",
];
const JOB_ALLOWED: &[&str] = &[
    "entity",
    "logical_row",
    "crawler_revision",
    "downstream_revision",
    "evidence_refs",
];
const LISTING_ALLOWED: &[&str] = &[
    "target",
    "job_id",
    "listing",
    "pipeline_state",
    "detail_materialized",
    "evidence_refs",
];
const POLICY_ALLOWED: &[&str] = &[
    "include_failed",
    "include_render_failed",
    "policy_pin",
];
const CUTOFF_ALLOWED: &[&str] = &["journal_id", "through", "last_sequence", "head_hash"];
const ENTITY_ALLOWED: &[&str] = &["entity", "entity_type", "target", "job_id", "id"];

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn fault(code: &str, detail: impl Into<String>) -> Fault {
    Fault {
        code: code.to_string(),
        detail: detail.into(),
    }
}

/// True when `value` is a `Missing` envelope (`{"value": null, ...}`).
fn is_missing(value: &Value) -> bool {
    value
        .as_object()
        .is_some_and(|map| map.get("value").is_some_and(Value::is_null))
}

/// The established (non-`Missing`) value of `field`, if any.
fn established<'a>(map: &'a Map<String, Value>, field: &str) -> Option<&'a Value> {
    map.get(field).filter(|value| !is_missing(value))
}

fn as_object<'a>(
    record: &'a CheckedRecord,
    code: &str,
    what: &str,
) -> Result<&'a Map<String, Value>, Fault> {
    record_value(record).as_object().ok_or_else(|| {
        fault(code, format!("{what} must be a JSON object"))
    })
}

fn required_str<'a>(
    map: &'a Map<String, Value>,
    field: &str,
    code: &str,
    what: &str,
) -> Result<&'a str, Fault> {
    match established(map, field) {
        Some(Value::String(text)) if !text.is_empty() => Ok(text.as_str()),
        _ => Err(fault(
            code,
            format!("{what} requires an established nonempty string {field:?}"),
        )),
    }
}

fn required_u64(
    map: &Map<String, Value>,
    field: &str,
    code: &str,
    what: &str,
) -> Result<u64, Fault> {
    match established(map, field) {
        Some(Value::Number(number)) => number.as_u64().ok_or_else(|| {
            fault(
                code,
                format!("{what} field {field:?} must be an unsigned integer"),
            )
        }),
        _ => Err(fault(
            code,
            format!("{what} requires an established unsigned integer {field:?}"),
        )),
    }
}

fn required_bool(
    map: &Map<String, Value>,
    field: &str,
    code: &str,
    what: &str,
) -> Result<bool, Fault> {
    match established(map, field) {
        Some(Value::Bool(flag)) => Ok(*flag),
        _ => Err(fault(
            code,
            format!("{what} requires an established boolean {field:?}"),
        )),
    }
}

/// Canonical SHA-256 digest text: exactly 64 lowercase hex characters.
fn is_digest_text(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_json_pointer(pointer: &str) -> bool {
    if pointer.is_empty() {
        return true;
    }
    if !pointer.starts_with('/') {
        return false;
    }
    let bytes = pointer.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'~' {
            match bytes.get(index + 1) {
                Some(b'0') | Some(b'1') => index += 2,
                _ => return false,
            }
        } else {
            index += 1;
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Forbidden-content scans
// ---------------------------------------------------------------------------

/// Recursively reject any banned claim key or standalone application-outcome
/// value. Keys match exactly (lowercased), so legitimate fields such as
/// `verdict_applied` and free-text job content pass while `suitability`,
/// `applied`, `discovery_proven`, and friends fault.
fn scan_global_forbidden(value: &Value) -> Result<(), Fault> {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if BANNED_KEYS.contains(&key.to_ascii_lowercase().as_str()) {
                    let code = if matches!(
                        key.to_ascii_lowercase().as_str(),
                        "applied"
                            | "hired"
                            | "offer"
                            | "offer_received"
                            | "application_success"
                            | "application_result"
                            | "application_status"
                            | "application_outcome"
                    ) {
                        "application_assertion_refused"
                    } else {
                        "proof_overreach"
                    };
                    return Err(fault(
                        code,
                        format!(
                            "feed field {key:?} asserts suitability, permission, qualification, or proven discovery/coverage; presence is not suitability or proof, and application success is never inferred"
                        ),
                    ));
                }
                scan_global_forbidden(child)?;
            }
            Ok(())
        }
        Value::Array(items) => {
            for item in items {
                scan_global_forbidden(item)?;
            }
            Ok(())
        }
        Value::String(text) => {
            if BANNED_VALUES.contains(&text.trim().to_ascii_lowercase().as_str()) {
                return Err(fault(
                    "application_assertion_refused",
                    format!(
                        "feed value {text:?} asserts an application outcome; APPLIED is never inferred from discovery, native completion, practice receipts, or submit clicks"
                    ),
                ));
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Reject proof-claim keys at one feed/entry level. Established fields outside
/// `allowed` are otherwise ignored so forward-compatible extras pass.
fn reject_entry_proof_keys(
    map: &Map<String, Value>,
    allowed: &[&str],
    what: &str,
) -> Result<(), Fault> {
    for (key, value) in map {
        if is_missing(value) || allowed.contains(&key.as_str()) {
            continue;
        }
        let folded = key.to_ascii_lowercase();
        if BANNED_KEYS.contains(&folded.as_str())
            || ENTRY_PROOF_KEYS.contains(&folded.as_str())
        {
            let code = if folded.as_str() == "applied"
                || folded.as_str() == "hired"
                || folded.starts_with("application_")
            {
                "application_assertion_refused"
            } else {
                "proof_overreach"
            };
            return Err(fault(
                code,
                format!(
                    "{what} field {key:?} asserts proven discovery/coverage, suitability, permission, or application success; output completeness never implies them"
                ),
            ));
        }
    }
    Ok(())
}

/// Reject crawler-authored downstream fields at one feed/entry level.
fn reject_downstream_keys(map: &Map<String, Value>, what: &str) -> Result<(), Fault> {
    for key in DOWNSTREAM_KEYS {
        if established(map, key).is_some() {
            return Err(fault(
                "crawler_authored_downstream",
                format!(
                    "{what} carries crawler-authored downstream field {key:?}; downstream revisions are product-owned and only referenced, never published by the crawler"
                ),
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Field parsers
// ---------------------------------------------------------------------------

/// Nonempty `SUPPORT` evidence refs with the store's exact shape.
fn check_support(value: &Value, what: &str) -> Result<Vec<Value>, Fault> {
    let items = value.as_array().ok_or_else(|| {
        fault(
            "missing_evidence",
            format!("{what} must be a nonempty SUPPORT array"),
        )
    })?;
    if items.is_empty() {
        return Err(fault(
            "missing_evidence",
            format!("{what} must be a nonempty SUPPORT array"),
        ));
    }
    for (index, item) in items.iter().enumerate() {
        let map = item.as_object().ok_or_else(|| {
            fault(
                "invalid_evidence_ref",
                format!("{what}[{index}] must be an object"),
            )
        })?;
        if is_missing(item) {
            return Err(fault(
                "invalid_evidence_ref",
                format!("{what}[{index}] must be established, not Missing"),
            ));
        }
        required_str(map, "journal_id", "invalid_evidence_ref", &format!("{what}[{index}]"))?;
        required_u64(map, "sequence", "invalid_evidence_ref", &format!("{what}[{index}]"))?;
        required_str(map, "event_id", "invalid_evidence_ref", &format!("{what}[{index}]"))?;
        let digest = required_str(
            map,
            "event_hash",
            "invalid_evidence_ref",
            &format!("{what}[{index}]"),
        )?;
        if !is_digest_text(digest) {
            return Err(fault(
                "invalid_evidence_ref",
                format!("{what}[{index}].event_hash must be 64 lowercase hex"),
            ));
        }
        match established(map, "pointer") {
            Some(Value::String(pointer)) if is_json_pointer(pointer) => {}
            _ => {
                return Err(fault(
                    "invalid_evidence_ref",
                    format!("{what}[{index}].pointer must be a JSON Pointer"),
                ))
            }
        }
    }
    Ok(items.clone())
}

fn parse_task_digest(value: &Value) -> Result<String, Fault> {
    if let Some(text) = value.as_str() {
        if is_digest_text(text) {
            return Ok(text.to_string());
        }
        return Err(fault(
            "invalid_task_digest",
            "task_digest must be 64 lowercase hex characters".to_string(),
        ));
    }
    if let Some(map) = value.as_object() {
        for field in ["digest", "value"] {
            if let Some(Value::String(text)) = established(map, field) {
                if is_digest_text(text) {
                    return Ok(text.clone());
                }
            }
        }
    }
    Err(fault(
        "invalid_task_digest",
        "task_digest must be a DIGEST (64hex string or {digest: 64hex})".to_string(),
    ))
}

fn parse_selection_policy(value: &Value) -> Result<(bool, bool), Fault> {
    let map = value.as_object().ok_or_else(|| {
        fault(
            "missing_selection_policy",
            "selection_policy must be an object naming failed/render-failed inclusion and a policy pin"
                .to_string(),
        )
    })?;
    if is_missing(value) {
        return Err(fault(
            "missing_selection_policy",
            "selection_policy must be established, not Missing".to_string(),
        ));
    }
    reject_entry_proof_keys(map, POLICY_ALLOWED, "selection_policy")?;
    let include_failed = required_bool(
        map,
        "include_failed",
        "missing_selection_policy",
        "selection_policy",
    )?;
    let include_render_failed = required_bool(
        map,
        "include_render_failed",
        "missing_selection_policy",
        "selection_policy",
    )?;
    required_str(
        map,
        "policy_pin",
        "missing_selection_policy",
        "selection_policy",
    )?;
    Ok((include_failed, include_render_failed))
}

fn parse_cutoff(value: &Value) -> Result<(String, u64), Fault> {
    let map = value.as_object().ok_or_else(|| {
        fault(
            "missing_cutoff",
            "cutoff must be an object with journal_id and through".to_string(),
        )
    })?;
    if is_missing(value) {
        return Err(fault(
            "missing_cutoff",
            "cutoff must be established, not Missing".to_string(),
        ));
    }
    reject_entry_proof_keys(map, CUTOFF_ALLOWED, "cutoff")?;
    let journal_id = required_str(map, "journal_id", "missing_cutoff", "cutoff")?.to_string();
    let through = match (
        established(map, "through"),
        established(map, "last_sequence"),
    ) {
        (Some(Value::Number(a)), Some(Value::Number(b))) => {
            let first = a.as_u64().ok_or_else(|| {
                fault("missing_cutoff", "cutoff.through must be unsigned".to_string())
            })?;
            let second = b.as_u64().ok_or_else(|| {
                fault(
                    "missing_cutoff",
                    "cutoff.last_sequence must be unsigned".to_string(),
                )
            })?;
            if first != second {
                return Err(fault(
                    "cutoff_mismatch",
                    "cutoff through and last_sequence disagree".to_string(),
                ));
            }
            first
        }
        (Some(Value::Number(number)), None) | (None, Some(Value::Number(number))) => {
            number.as_u64().ok_or_else(|| {
                fault("missing_cutoff", "cutoff sequence must be unsigned".to_string())
            })?
        }
        _ => {
            return Err(fault(
                "missing_cutoff",
                "cutoff requires an established through (or last_sequence)".to_string(),
            ))
        }
    };
    if through == 0 {
        return Err(fault(
            "missing_cutoff",
            "cutoff must include at least the admission event (through >= 1)".to_string(),
        ));
    }
    if let Some(Value::String(head)) = established(map, "head_hash") {
        if !is_digest_text(head) {
            return Err(fault(
                "invalid_cutoff",
                "cutoff.head_hash must be 64 lowercase hex when present".to_string(),
            ));
        }
    }
    Ok((journal_id, through))
}

fn parse_job_entity(value: &Value) -> Result<(String, String, Value), Fault> {
    let map = value.as_object().ok_or_else(|| {
        fault("invalid_entity", "job entity must be a JobEntityKey object".to_string())
    })?;
    if is_missing(value) {
        return Err(fault(
            "invalid_entity",
            "job entity must be established, not Missing".to_string(),
        ));
    }
    reject_entry_proof_keys(map, ENTITY_ALLOWED, "job entity")?;
    let is_job = established(map, "entity").and_then(Value::as_str) == Some("job")
        || established(map, "entity_type").and_then(Value::as_str) == Some("job");
    if !is_job {
        return Err(fault(
            "invalid_entity",
            "job entity must name entity/entity_type \"job\"".to_string(),
        ));
    }
    let target = required_str(map, "target", "invalid_entity", "job entity")?.to_string();
    let from_job_id = established(map, "job_id").and_then(Value::as_str);
    let from_id = established(map, "id").and_then(Value::as_str);
    let job_id = match (from_job_id, from_id) {
        (Some(first), Some(second)) => {
            if first != second {
                return Err(fault(
                    "invalid_entity",
                    "job entity job_id and id disagree".to_string(),
                ));
            }
            if first.is_empty() {
                return Err(fault(
                    "invalid_entity",
                    "job entity requires a nonempty job_id".to_string(),
                ));
            }
            first.to_string()
        }
        (Some(id), None) | (None, Some(id)) => {
            if id.is_empty() {
                return Err(fault(
                    "invalid_entity",
                    "job entity requires a nonempty job_id".to_string(),
                ));
            }
            id.to_string()
        }
        (None, None) => {
            return Err(fault(
                "invalid_entity",
                "job entity requires an established job_id".to_string(),
            ))
        }
    };
    Ok((
        target.clone(),
        job_id.clone(),
        json!({"entity_type": "job", "target": target, "job_id": job_id}),
    ))
}

/// True when `value` already is an artifact reference (digest + size).
fn is_artifact_ref(value: &Value) -> bool {
    match value.as_object() {
        Some(map) => {
            matches!(established(map, "digest"), Some(Value::String(text)) if is_digest_text(text))
                && matches!(established(map, "size_bytes"), Some(Value::Number(number)) if number.as_u64().is_some())
        }
        None => false,
    }
}

/// Resolve `value` to `(artifact_reference, parsed_json)`.
///
/// References are shape-checked and read back (full size/digest verification
/// in the store). Full objects are validated, installed, and read back before
/// their reference is used.
fn ensure_artifact(
    artifacts: &dyn ArtifactStore,
    grant: &Grant,
    value: &Value,
    what: &str,
) -> Result<(Value, Value), Fault> {
    if is_missing(value) {
        return Err(fault(
            "incomplete_domain",
            format!("{what} must be established, not Missing"),
        ));
    }
    if is_artifact_ref(value) {
        let map = value.as_object().expect("ref shape checked above");
        required_str(map, "media_type", "invalid_reference", what)?;
        required_str(map, "owner_domain", "invalid_reference", what)?;
        match established(map, "access") {
            Some(Value::String(access)) if access == "public" || access == "restricted" => {}
            _ => {
                return Err(fault(
                    "invalid_reference",
                    format!("{what} requires access of public or restricted"),
                ))
            }
        }
        required_str(map, "provenance", "invalid_reference", what)?;
        match established(map, "grant_digest") {
            Some(Value::String(binding)) if is_digest_text(binding) => {}
            _ => {
                return Err(fault(
                    "invalid_reference",
                    format!("{what} must name the grant digest it is exercised under"),
                ))
            }
        }
        let reference =
            validate(OUTPUT_SCHEMA, value.clone()).map_err(|inner| fault(&inner.code, inner.detail))?;
        let bytes = artifacts.read(grant, &reference)?;
        let parsed: Value = serde_json::from_slice(&bytes).map_err(|_| {
            fault(
                "invalid_artifact_bytes",
                format!("{what} artifact bytes are not JSON"),
            )
        })?;
        return Ok((value.clone(), parsed));
    }
    let map = value.as_object().ok_or_else(|| {
        fault(
            "incomplete_domain",
            format!("{what} must be an object or artifact reference"),
        )
    })?;
    if map.contains_key("digest") || map.contains_key("size_bytes") {
        return Err(fault(
            "invalid_reference",
            format!("{what} looks like an artifact reference but lacks digest/size_bytes"),
        ));
    }
    validate(OUTPUT_SCHEMA, value.clone())
        .map_err(|inner| fault(&inner.code, format!("{what}: {}", inner.detail)))?;
    let bytes = serde_json::to_vec(value).map_err(|_| {
        fault(
            "invalid_object",
            format!("{what} cannot be serialized"),
        )
    })?;
    let installed = artifacts.install(grant, &bytes, "application/json", false)?;
    let back = artifacts.read(grant, &installed)?;
    if back != bytes {
        return Err(fault(
            "artifact_verification_failed",
            format!("{what} bytes did not read back intact; no reference is issued"),
        ));
    }
    Ok((record_value(&installed).clone(), value.clone()))
}

// ---------------------------------------------------------------------------
// Domain validators
// ---------------------------------------------------------------------------

fn revisions_of_row(parsed: &Value) -> Result<(u64, u64), Fault> {
    let map = parsed.as_object().ok_or_else(|| {
        fault("incomplete_row", "logical row must be an object".to_string())
    })?;
    if let Some(vector) = established(map, "version_vector") {
        let entries = vector.as_array().ok_or_else(|| {
            fault(
                "incomplete_row",
                "logical row version_vector must be an array".to_string(),
            )
        })?;
        let mut crawler: Option<u64> = None;
        let mut downstream: Option<u64> = None;
        for (index, entry) in entries.iter().enumerate() {
            let slot = entry.as_object().ok_or_else(|| {
                fault(
                    "incomplete_row",
                    format!("logical row version_vector[{index}] must be an object"),
                )
            })?;
            let domain = slot
                .get("domain")
                .and_then(Value::as_str)
                .filter(|text| !text.is_empty())
                .ok_or_else(|| {
                    fault(
                        "incomplete_row",
                        format!("logical row version_vector[{index}] lacks a domain"),
                    )
                })?;
            let revision = slot
                .get("revision")
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    fault(
                        "incomplete_row",
                        format!("logical row version_vector[{index}] lacks a revision"),
                    )
                })?;
            match domain {
                "crawler" => crawler = Some(revision),
                "downstream" => downstream = Some(revision),
                _ => {}
            }
        }
        match (crawler, downstream) {
            (Some(first), Some(second)) => return Ok((first, second)),
            _ => {
                return Err(fault(
                    "incomplete_row",
                    "logical row version_vector must pin both crawler and downstream revisions"
                        .to_string(),
                ))
            }
        }
    }
    if let Some(Value::Object(slots)) = established(map, "domains") {
        let mut crawler: Option<u64> = None;
        let mut downstream: Option<u64> = None;
        for (domain, slot) in slots {
            let revision = slot
                .as_object()
                .and_then(|object| object.get("revision"))
                .and_then(Value::as_u64);
            match (domain.as_str(), revision) {
                ("crawler", Some(revision)) => crawler = Some(revision),
                ("downstream", Some(revision)) => downstream = Some(revision),
                _ => {}
            }
        }
        match (crawler, downstream) {
            (Some(first), Some(second)) => return Ok((first, second)),
            _ => {
                return Err(fault(
                    "incomplete_row",
                    "logical row domains must carry both crawler and downstream revisions"
                        .to_string(),
                ))
            }
        }
    }
    Err(fault(
        "incomplete_row",
        "logical row must carry an exact version_vector (or domains map)".to_string(),
    ))
}

fn validate_logical_row(
    parsed: &Value,
    expected_target: &str,
    expected_job_id: &str,
    expected_crawler: u64,
    expected_downstream: u64,
) -> Result<(), Fault> {
    scan_global_forbidden(parsed)?;
    let map = parsed.as_object().ok_or_else(|| {
        fault("incomplete_row", "logical row must be an object".to_string())
    })?;
    match established(map, "record_type") {
        Some(Value::String(kind)) if kind == "logical_row" => {}
        _ => {
            return Err(fault(
                "incomplete_row",
                "logical row must carry record_type \"logical_row\"".to_string(),
            ))
        }
    }
    let entity = established(map, "entity").ok_or_else(|| {
        fault("incomplete_row", "logical row lacks its entity".to_string())
    })?;
    let entity_map = entity.as_object().ok_or_else(|| {
        fault("incomplete_row", "logical row entity must be an object".to_string())
    })?;
    let row_job = entity_map
        .get("job_id")
        .and_then(Value::as_str)
        .or_else(|| entity_map.get("id").and_then(Value::as_str))
        .unwrap_or_default();
    if row_job != expected_job_id {
        return Err(fault(
            "entity_mismatch",
            format!(
                "logical row job {row_job:?} does not match feed job {expected_job_id:?}"
            ),
        ));
    }
    if let Some(Value::String(target)) = established(entity_map, "target") {
        if target != expected_target {
            return Err(fault(
                "entity_mismatch",
                format!(
                    "logical row target {target:?} does not match feed target {expected_target:?}"
                ),
            ));
        }
    }
    match established(map, "registration_digest") {
        Some(Value::String(digest)) if is_digest_text(digest) => {}
        _ => {
            return Err(fault(
                "incomplete_row",
                "logical row must carry a registration_digest".to_string(),
            ))
        }
    }
    let (crawler, downstream) = revisions_of_row(parsed)?;
    if crawler != expected_crawler || downstream != expected_downstream {
        return Err(fault(
            "revision_mismatch",
            format!(
                "logical row revisions crawler={crawler} downstream={downstream} do not match feed entry crawler={expected_crawler} downstream={expected_downstream}"
            ),
        ));
    }
    if crawler == 0 {
        return Err(fault(
            "invalid_revision",
            "feed crawler_revision must be positive".to_string(),
        ));
    }
    Ok(())
}

fn validate_listing(
    parsed: &Value,
    expected_target: &str,
    expected_job_id: &str,
    expected_state: &str,
) -> Result<(), Fault> {
    scan_global_forbidden(parsed)?;
    let map = parsed.as_object().ok_or_else(|| {
        fault("incomplete_listing", "listing must be an object".to_string())
    })?;
    match established(map, "target") {
        Some(Value::String(target)) if target == expected_target => {}
        _ => {
            return Err(fault(
                "entity_mismatch",
                format!(
                    "listing target does not match listing-only entry target {expected_target:?}"
                ),
            ))
        }
    }
    let row_job = established(map, "job_id")
        .and_then(Value::as_str)
        .or_else(|| established(map, "id").and_then(Value::as_str))
        .unwrap_or_default();
    if row_job != expected_job_id {
        return Err(fault(
            "entity_mismatch",
            format!(
                "listing job {row_job:?} does not match listing-only entry {expected_job_id:?}"
            ),
        ));
    }
    match established(map, "pipeline_state") {
        Some(Value::String(state)) if state == expected_state => {}
        _ => {
            return Err(fault(
                "pipeline_state_mismatch",
                format!(
                    "listing bytes must carry the entry's exact pipeline_state {expected_state:?}"
                ),
            ))
        }
    }
    Ok(())
}

fn validate_coverage(
    parsed: &Value,
    expected_run_id: &str,
) -> Result<(String, String, bool), Fault> {
    scan_global_forbidden(parsed)?;
    let map = parsed.as_object().ok_or_else(|| {
        fault(
            "incomplete_coverage",
            "coverage export must be an object".to_string(),
        )
    })?;
    match established(map, "record_type") {
        Some(Value::String(kind)) if kind == "crawler_coverage_export" => {}
        _ => {
            return Err(fault(
                "incomplete_coverage",
                "coverage export must carry record_type \"crawler_coverage_export\"".to_string(),
            ))
        }
    }
    let target = required_str(map, "target", "incomplete_coverage", "coverage export")?.to_string();
    let run_id = required_str(map, "run_id", "incomplete_coverage", "coverage export")?;
    if run_id != expected_run_id {
        return Err(fault(
            "scope_mismatch",
            format!(
                "coverage run {run_id:?} does not match feed run {expected_run_id:?}"
            ),
        ));
    }
    let partition = required_str(
        map,
        "partition_id",
        "incomplete_coverage",
        "coverage export",
    )?
    .to_string();
    let proof = established(map, "proof").ok_or_else(|| {
        fault(
            "incomplete_coverage",
            "coverage export lacks its proof evaluation".to_string(),
        )
    })?;
    let proof_map = proof.as_object().ok_or_else(|| {
        fault(
            "incomplete_coverage",
            "coverage proof must be an object".to_string(),
        )
    })?;
    let proven = match established(proof_map, "pagination_coverage_proven") {
        Some(Value::Bool(flag)) => *flag,
        _ => {
            return Err(fault(
                "incomplete_coverage",
                "coverage proof must carry pagination_coverage_proven".to_string(),
            ))
        }
    };
    let evidence = established(map, "evidence_refs").ok_or_else(|| {
        fault(
            "missing_evidence",
            "coverage export lacks evidence_refs".to_string(),
        )
    })?;
    check_support(evidence, "coverage export evidence_refs")?;
    Ok((target, partition, proven))
}

// ---------------------------------------------------------------------------
// Cutoff verification
// ---------------------------------------------------------------------------

/// Verify `through` against the owner journal and return
/// `(verified_last_sequence, verified_head_hash, cutoff_head_hash)`.
fn verify_cutoff(
    store: &dyn OwnerStore,
    grant: &Grant,
    journal_id: &str,
    through: u64,
) -> Result<(u64, String, String), Fault> {
    let prefix_query = validate(
        OUTPUT_SCHEMA,
        json!({"query": "prefix", "journal_id": journal_id}),
    )
    .map_err(|inner| fault(&inner.code, inner.detail))?;
    let prefix = store.read(grant, &prefix_query)?;
    let prefix_map = as_object(&prefix, "invalid_journal_view", "journal prefix")?;
    let last = required_u64(prefix_map, "last_sequence", "invalid_journal_view", "journal prefix")?;
    let head = required_str(prefix_map, "head_hash", "invalid_journal_view", "journal prefix")?;
    if !is_digest_text(head) {
        return Err(fault(
            "invalid_journal_view",
            "journal prefix head_hash must be 64 lowercase hex".to_string(),
        ));
    }
    if through > last {
        return Err(fault(
            "cutoff_beyond_head",
            format!("cutoff through {through} precedes no journal event; head is {last}"),
        ));
    }
    let event_query = validate(
        OUTPUT_SCHEMA,
        json!({
            "query": "event",
            "journal_id": journal_id,
            "journal_sequence": through,
        }),
    )
    .map_err(|inner| fault(&inner.code, inner.detail))?;
    let event = store.read(grant, &event_query)?;
    let event_map = as_object(&event, "invalid_journal_view", "cutoff event")?;
    let cutoff_head = required_str(event_map, "event_hash", "invalid_journal_view", "cutoff event")?;
    if !is_digest_text(cutoff_head) {
        return Err(fault(
            "invalid_journal_view",
            "cutoff event_hash must be 64 lowercase hex".to_string(),
        ));
    }
    Ok((last, head.to_string(), cutoff_head.to_string()))
}

// ---------------------------------------------------------------------------
// Public interface
// ---------------------------------------------------------------------------

/// Publish one complete-honest job feed.
///
/// Validates the request, verifies its cutoff against the owner journal,
/// durably installs every referenced row/listing/export plus the manifest,
/// and returns the `TaskOutput` naming the manifest artifact. `completeness`
/// describes only this output contract: a `complete` feed still carries
/// coverage for empty/incomplete partitions, explicit limitations, and zero
/// discovery/application assertions.
pub fn publish_feed(
    store: &dyn OwnerStore,
    artifacts: &dyn ArtifactStore,
    grant: &Grant,
    request: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let req_map = as_object(request, "invalid_request", "feed request")?;
    reject_entry_proof_keys(req_map, REQUEST_ALLOWED, "feed request")?;
    reject_downstream_keys(req_map, "feed request")?;
    scan_global_forbidden(record_value(request))?;

    let feed_id = required_str(req_map, "feed_id", "invalid_request", "feed request")?.to_string();
    let run_id = required_str(req_map, "run_id", "invalid_request", "feed request")?.to_string();
    let task_digest_value = established(req_map, "task_digest").ok_or_else(|| {
        fault(
            "invalid_task_digest",
            "feed request requires an established task_digest".to_string(),
        )
    })?;
    let task_digest = parse_task_digest(task_digest_value)?;
    let policy_value = established(req_map, "selection_policy").ok_or_else(|| {
        fault(
            "missing_selection_policy",
            "feed request requires an established selection_policy".to_string(),
        )
    })?;
    let (include_failed, include_render_failed) = parse_selection_policy(policy_value)?;
    let cutoff_value = established(req_map, "cutoff").ok_or_else(|| {
        fault(
            "missing_cutoff",
            "feed request requires an established cutoff".to_string(),
        )
    })?;
    let (cutoff_journal, cutoff_through) = parse_cutoff(cutoff_value)?;
    let completeness =
        required_str(req_map, "completeness", "invalid_completeness", "feed request")?.to_string();
    if !["complete", "partial", "unknown"].contains(&completeness.as_str()) {
        return Err(fault(
            "invalid_completeness",
            "completeness must be complete, partial, or unknown".to_string(),
        ));
    }
    let jobs_value = established(req_map, "jobs").ok_or_else(|| {
        fault("invalid_request", "feed request requires established jobs".to_string())
    })?;
    let jobs_arr = jobs_value.as_array().ok_or_else(|| {
        fault("invalid_request", "jobs must be an array".to_string())
    })?;
    let listing_value = established(req_map, "listing_only").ok_or_else(|| {
        fault(
            "invalid_request",
            "feed request requires established listing_only".to_string(),
        )
    })?;
    let listing_arr = listing_value.as_array().ok_or_else(|| {
        fault("invalid_request", "listing_only must be an array".to_string())
    })?;
    let coverage_value = established(req_map, "coverage").ok_or_else(|| {
        fault(
            "missing_coverage",
            "feed request requires established coverage".to_string(),
        )
    })?;
    let coverage_arr = coverage_value.as_array().ok_or_else(|| {
        fault("missing_coverage", "coverage must be an array".to_string())
    })?;
    if coverage_arr.is_empty() {
        return Err(fault(
            "missing_coverage",
            "coverage must include partitions producing no jobs; an empty feed still carries coverage"
                .to_string(),
        ));
    }
    let limitations_value = established(req_map, "limitations").ok_or_else(|| {
        fault(
            "missing_limitations",
            "feed request requires established limitations".to_string(),
        )
    })?;
    let limitations_arr = limitations_value.as_array().ok_or_else(|| {
        fault("missing_limitations", "limitations must be an array".to_string())
    })?;
    let mut caller_limitations: Vec<String> = Vec::new();
    for (index, item) in limitations_arr.iter().enumerate() {
        match item {
            Value::String(text) if !text.trim().is_empty() => caller_limitations.push(text.clone()),
            _ => {
                return Err(fault(
                    "missing_limitations",
                    format!("limitations[{index}] must be nonempty TEXT"),
                ))
            }
        }
    }
    let evidence_value = established(req_map, "evidence_refs").ok_or_else(|| {
        fault(
            "missing_evidence",
            "feed request requires established evidence_refs".to_string(),
        )
    })?;
    let evidence_refs = check_support(evidence_value, "feed evidence_refs")?;

    let output_name = match established(req_map, "output_name") {
        Some(Value::String(text)) if !text.is_empty() => text.clone(),
        Some(_) => {
            return Err(fault(
                "invalid_request",
                "output_name must be nonempty TEXT when present".to_string(),
            ))
        }
        None => feed_id.clone(),
    };
    let output_kind = match established(req_map, "output_kind") {
        Some(Value::String(text)) if !text.is_empty() => text.clone(),
        Some(_) => {
            return Err(fault(
                "invalid_request",
                "output_kind must be nonempty TEXT when present".to_string(),
            ))
        }
        None => "crawler_feed".to_string(),
    };
    if let Some(pin) = established(req_map, "output_schema_pin") {
        if !pin.is_object() {
            return Err(fault(
                "invalid_request",
                "output_schema_pin must be an object when present".to_string(),
            ));
        }
        scan_global_forbidden(pin)?;
    }

    let (_verified_last, _verified_head, cutoff_head) =
        verify_cutoff(store, grant, &cutoff_journal, cutoff_through)?;

    // Jobs: validate shape first so invalid inputs fault before any install.
    let mut manifest_jobs: Vec<Value> = Vec::new();
    for (index, job_value) in jobs_arr.iter().enumerate() {
        let what = format!("jobs[{index}]");
        let job_map = job_value.as_object().ok_or_else(|| {
            fault("invalid_request", format!("{what} must be an object"))
        })?;
        if is_missing(job_value) {
            return Err(fault(
                "invalid_request",
                format!("{what} must be established, not Missing"),
            ));
        }
        reject_entry_proof_keys(job_map, JOB_ALLOWED, &what)?;
        reject_downstream_keys(job_map, &what)?;
        let entity_value = established(job_map, "entity").ok_or_else(|| {
            fault("invalid_entity", format!("{what} requires an entity"))
        })?;
        let (target, job_id, normalized) = parse_job_entity(entity_value)?;
        let crawler_revision =
            required_u64(job_map, "crawler_revision", "invalid_revision", &what)?;
        if crawler_revision == 0 {
            return Err(fault(
                "invalid_revision",
                format!("{what}.crawler_revision must be positive"),
            ));
        }
        let downstream_revision =
            required_u64(job_map, "downstream_revision", "invalid_revision", &what)?;
        let job_evidence_value = established(job_map, "evidence_refs").ok_or_else(|| {
            fault("missing_evidence", format!("{what} requires evidence_refs"))
        })?;
        let job_evidence = check_support(job_evidence_value, &format!("{what}.evidence_refs"))?;
        let row_value = established(job_map, "logical_row").ok_or_else(|| {
            fault("incomplete_row", format!("{what} requires a logical_row"))
        })?;
        if !is_artifact_ref(row_value) {
            validate_logical_row(
                row_value,
                &target,
                &job_id,
                crawler_revision,
                downstream_revision,
            )?;
        }
        let (row_ref, row_parsed) =
            ensure_artifact(artifacts, grant, row_value, &format!("{what}.logical_row"))?;
        validate_logical_row(
            &row_parsed,
            &target,
            &job_id,
            crawler_revision,
            downstream_revision,
        )?;
        manifest_jobs.push(json!({
            "entity": normalized,
            "logical_row": row_ref,
            "crawler_revision": crawler_revision,
            "downstream_revision": downstream_revision,
            "evidence_refs": job_evidence,
        }));
    }

    // Listing-only: exact state, never materialized, policy-filtered.
    let mut manifest_listings: Vec<Value> = Vec::new();
    for (index, entry_value) in listing_arr.iter().enumerate() {
        let what = format!("listing_only[{index}]");
        let entry_map = entry_value.as_object().ok_or_else(|| {
            fault("invalid_request", format!("{what} must be an object"))
        })?;
        if is_missing(entry_value) {
            return Err(fault(
                "invalid_request",
                format!("{what} must be established, not Missing"),
            ));
        }
        reject_entry_proof_keys(entry_map, LISTING_ALLOWED, &what)?;
        reject_downstream_keys(entry_map, &what)?;
        let target = required_str(entry_map, "target", "invalid_entity", &what)?.to_string();
        let job_id = required_str(entry_map, "job_id", "invalid_entity", &what)?.to_string();
        let state = required_str(entry_map, "pipeline_state", "unknown_listing_state", &what)?;
        if !LISTING_STATES.contains(&state) {
            return Err(fault(
                "unknown_listing_state",
                format!("{what}.pipeline_state {state:?} is outside the §16.1 listing vocabulary"),
            ));
        }
        match established(entry_map, "detail_materialized") {
            Some(Value::Bool(false)) => {}
            _ => {
                return Err(fault(
                    "listing_only_violation",
                    format!("{what}.detail_materialized must be exactly false; listing-only vetoes never fabricate details"),
                ))
            }
        }
        if !include_failed && state == "failed" {
            return Err(fault(
                "selection_policy_excludes_failed",
                format!("{what} is failed but the selection policy excludes failed details"),
            ));
        }
        if !include_render_failed && state == "render_failed" {
            return Err(fault(
                "selection_policy_excludes_failed",
                format!("{what} is render_failed but the selection policy excludes render-failed details"),
            ));
        }
        let entry_evidence_value = established(entry_map, "evidence_refs").ok_or_else(|| {
            fault("missing_evidence", format!("{what} requires evidence_refs"))
        })?;
        let entry_evidence = check_support(entry_evidence_value, &format!("{what}.evidence_refs"))?;
        let listing_value = established(entry_map, "listing").ok_or_else(|| {
            fault("incomplete_listing", format!("{what} requires a listing"))
        })?;
        if !is_artifact_ref(listing_value) {
            validate_listing(listing_value, &target, &job_id, state)?;
        }
        let (listing_ref, listing_parsed) = ensure_artifact(
            artifacts,
            grant,
            listing_value,
            &format!("{what}.listing"),
        )?;
        validate_listing(&listing_parsed, &target, &job_id, state)?;
        manifest_listings.push(json!({
            "target": target,
            "job_id": job_id,
            "listing": listing_ref,
            "pipeline_state": state,
            "detail_materialized": false,
            "evidence_refs": entry_evidence,
        }));
    }

    // Coverage: every partition cited, including empty ones.
    let mut manifest_coverage: Vec<Value> = Vec::new();
    let mut partitions: Vec<String> = Vec::new();
    for (index, coverage_value) in coverage_arr.iter().enumerate() {
        let what = format!("coverage[{index}]");
        if is_missing(coverage_value) {
            return Err(fault(
                "incomplete_coverage",
                format!("{what} must be established, not Missing"),
            ));
        }
        if !is_artifact_ref(coverage_value) {
            let (target, partition, _proven) = validate_coverage(coverage_value, &run_id)?;
            let key = format!("{target}\u{1f}{partition}");
            if partitions.contains(&key) {
                return Err(fault(
                    "duplicate_coverage",
                    format!("coverage duplicates partition {partition:?} for target {target:?}"),
                ));
            }
            partitions.push(key);
        }
        let (coverage_ref, coverage_parsed) =
            ensure_artifact(artifacts, grant, coverage_value, &what)?;
        let (target, partition, _proven) = validate_coverage(&coverage_parsed, &run_id)?;
        if is_artifact_ref(coverage_value) {
            let key = format!("{target}\u{1f}{partition}");
            if partitions.contains(&key) {
                return Err(fault(
                    "duplicate_coverage",
                    format!("coverage duplicates partition {partition:?} for target {target:?}"),
                ));
            }
            partitions.push(key);
        }
        manifest_coverage.push(coverage_ref);
    }

    let mut limitations = caller_limitations.clone();
    for standard in STANDARD_LIMITATIONS {
        if !limitations.iter().any(|text| text == standard) {
            limitations.push(standard.to_string());
        }
    }
    let limitation_values: Vec<Value> =
        limitations.iter().map(|text| Value::String(text.clone())).collect();

    let manifest_value = json!({
        "record_type": RECORD_TYPE,
        "schema_version": SCHEMA_VERSION,
        "feed_id": feed_id,
        "run_id": run_id,
        "task_digest": task_digest,
        "selection_policy": policy_value.clone(),
        "cutoff": {
            "record_type": "journal_prefix",
            "journal_id": cutoff_journal,
            "last_sequence": cutoff_through,
            "head_hash": cutoff_head,
        },
        "jobs": manifest_jobs,
        "listing_only": manifest_listings,
        "coverage": manifest_coverage,
        "limitations": limitation_values.clone(),
        "evidence_refs": evidence_refs.clone(),
    });
    let manifest_record = validate(FEED_SCHEMA, manifest_value.clone())
        .map_err(|inner| fault(&inner.code, format!("manifest: {}", inner.detail)))?;
    let manifest_bytes = serde_json::to_vec(record_value(&manifest_record)).map_err(|_| {
        fault("invalid_object", "manifest cannot be serialized".to_string())
    })?;
    let manifest_ref = artifacts.install(grant, &manifest_bytes, "application/json", false)?;
    let manifest_back = artifacts.read(grant, &manifest_ref)?;
    if manifest_back != manifest_bytes {
        return Err(fault(
            "artifact_verification_failed",
            "manifest bytes did not read back intact; no TaskOutput is issued".to_string(),
        ));
    }
    let manifest_artifact = record_value(&manifest_ref).clone();

    let partition_ids: Vec<Value> = partitions
        .iter()
        .map(|key| {
            Value::String(
                key.split('\u{1f}')
                    .nth(1)
                    .unwrap_or_default()
                    .to_string(),
            )
        })
        .collect();
    let output_value = json!({
        "record_type": "task_output",
        "kind": output_kind,
        "name": output_name,
        "output_schema_pin": {"schema": RECORD_TYPE, "version": SCHEMA_VERSION},
        "artifact": manifest_artifact,
        "manifest": manifest_value,
        "completeness": completeness,
        "support": evidence_refs.clone(),
        "limitations": limitation_values,
        "evidence_refs": evidence_refs,
        "feed_id": feed_id,
        "run_id": run_id,
        "task_digest": task_digest,
        "jobs_count": manifest_jobs_len(&manifest_value),
        "listing_only_count": manifest_listings_len(&manifest_value),
        "coverage_count": coverage_arr.len(),
        "partition_ids": partition_ids,
    });
    validate(OUTPUT_SCHEMA, output_value).map_err(|inner| fault(&inner.code, inner.detail))
}

fn manifest_jobs_len(manifest: &Value) -> u64 {
    manifest
        .get("jobs")
        .and_then(Value::as_array)
        .map(|items| items.len() as u64)
        .unwrap_or_default()
}

fn manifest_listings_len(manifest: &Value) -> u64 {
    manifest
        .get("listing_only")
        .and_then(Value::as_array)
        .map(|items| items.len() as u64)
        .unwrap_or_default()
}

//! `crawler_replay`: deterministic diagnostics and offline replay.
//!
//! Implements EK-DIAGNOSTIC and EK-REPLAY for the crawler seam:
//!
//! * [`derive_diagnostic`] is a deterministic function of its immutable
//!   manifest, named journal prefix, and pinned classifier bundle (requirement
//!   plus optional fix registries). It uses no wall time, unrecorded network
//!   lookups, or mutable rows. Same inputs always yield the same diagnostic;
//!   late evidence or classifier changes require a new call (a new immutable
//!   revision), never a mutation.
//! * [`replay_offline`] consumes recorded external inputs and lifecycle
//!   observations from an artifact input bundle, recomputes derived outputs,
//!   and compares semantic events, final state, and the diagnostic. It invokes
//!   no browser, subject, or external write. Recorded derived outputs are
//!   never fed back as authoritative inputs. `matched` requires every
//!   mode-required comparison to be available and equal; missing inputs yield
//!   `unavailable`, never `matched`.
//!
//! ## Recomputation
//!
//! * `semantic_events`: digest over `{"kind":"semantic_events",
//!   "external_inputs":..,"lifecycle_observations":..}` plus, when the bundle
//!   carries `audit_rows`, the digests of each row normalized via
//!   [`crawler_normalization::normalize_row`] (entity `audit_log`, replay
//!   evidence synthesized from the request prefix with a pinned TimePoint,
//!   never wall time).
//! * `final_state`: digest over `{"kind":"final_state",..}` plus, when the
//!   bundle carries `detector_transcript`, the digest of
//!   [`crawler_detectors::evaluate_detectors`] over the recorded
//!   declaration/prior/packet.
//! * `diagnostic`: re-derived via [`derive_diagnostic`] from the bundle's
//!   `diagnostic_manifest` / `diagnostic_prefix` / `diagnostic_bundle`, then
//!   digested. This is re-derivation, not reproduction of an edited report.
//!
//! Coverage proof algebra is *not* re-evaluated here: replay compares opaque
//!   content digests for coverage-derived outputs. Proof evaluation remains
//!   the `crawler_coverage` domain, which this crate deliberately does not
//! link (the sibling is unimplemented). This preserves domain separation and
//! keeps replay offline and deterministic.
//!
//! ## Record shapes
//!
//! All inputs are [`CheckedRecord`]s admitted by the schema gate (no bare
//! JSON nulls). Absent values are typed `Missing` envelopes.
//!
//! `derive_diagnostic`:
//!
//! ```text
//! manifest: {"run_id": ID, ...}
//! prefix:   {"journal_id": ID, "last_sequence": POS, "head_hash": HEX64}
//! bundle:   {"classifier": PIN, "requirement_registry": PIN,
//!            "fix_registry": PIN | Missing}
//! PIN: {"id"|"name": ID, "version": ID, "artifact_digest": HEX64 | sha256:HEX64}
//! ```
//!
//! `replay_offline` request:
//!
//! ```text
//! {
//!   "replay_id": ID, "mode": exact_fixture|diagnostic_rederivation,
//!   "run_id": ID, "manifest_hash": HEX64,
//!   "source_prefix": PREFIX, "source_diagnostic": {"digest": HEX64},
//!   "input_bundle": ARTIFACT_REF,
//!   "classifier": PIN, "reducer": PIN | Missing(not_applicable),
//!   "replay_engine": PIN,
//!   "expected": {"semantic_events": HEX64, "final_state": HEX64,
//!                "diagnostic": HEX64}
//! }
//! ```
//!
//! Exact fixture requires all three expected digests and a pinned reducer.
//! Diagnostic rederivation requires only the diagnostic digest and
//! `reducer = Missing(not_applicable)`. `source_diagnostic.digest` must equal
//! the expected diagnostic digest. An established `employer_mutation=true` or
//! `mutation_ref` is refused with `employer_mutation_not_replayable` in both
//! modes: replay never repeats an employer mutation.
//!
//! Input bundle bytes (JSON object):
//!
//! ```text
//! {
//!   "external_inputs": E, "lifecycle_observations": E,
//!   "audit_rows": [OBJECT...] | Missing,
//!   "detector_transcript": {"declaration": O, "prior": O, "packet": O} | Missing,
//!   "diagnostic_manifest": O, "diagnostic_prefix": O, "diagnostic_bundle": O,
//!   "recorded_derived": ANY (always ignored)
//! }
//! ```

use crawler_artifacts::ArtifactStore;
use crawler_authority::Grant;
use crawler_detectors::evaluate_detectors;
use crawler_hashing::{canonical_bytes, digest_bytes};
use crawler_normalization::normalize_row;
use crawler_schema::{record_value, validate, CheckedRecord, Fault, SourceEntity};
use serde_json::{json, Map, Value};

/// Structural envelope for records produced by this module.
const OUTPUT_SCHEMA: &str = "audit_log";
/// Contract schema version stamped on diagnostic and receipt records.
const SCHEMA_VERSION: &str = "crawler-seam/0.1.0";

/// Fields that can only be satisfied with unrecorded evidence. Their
/// established presence in diagnostic inputs is refused.
const FORBIDDEN_EVIDENCE: &[&str] = &[
    "current_wall_time",
    "wall_time",
    "wall_time_now",
    "live_lookup",
    "unrecorded_lookup",
    "mutable_row",
    "mutable_application_row",
];

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn fault(code: &str, detail: impl Into<String>) -> Fault {
    Fault {
        code: code.to_string(),
        detail: detail.into(),
    }
}

fn missing(reason: &str, detail: &str) -> Value {
    json!({"value": Value::Null, "reason": reason, "detail": detail})
}

/// True when `value` is a `Missing` envelope (`{"value": null, ...}`).
/// The schema gate has already validated the envelope shape.
fn is_missing(value: &Value) -> bool {
    value
        .as_object()
        .is_some_and(|map| map.get("value").is_some_and(Value::is_null))
}

fn missing_reason(value: &Value) -> Option<&str> {
    value
        .as_object()
        .and_then(|map| map.get("reason"))
        .and_then(Value::as_str)
}

/// 64 lowercase hex characters (crawler digest text).
fn is_digest_text(text: &str) -> bool {
    text.len() == 64
        && text.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn is_prefixed_digest(text: &str) -> bool {
    text.len() == 7 + 64
        && text.starts_with("sha256:")
        && is_digest_text(&text[7..])
}

fn is_any_digest(text: &str) -> bool {
    is_digest_text(text) || is_prefixed_digest(text)
}

fn as_object<'a>(
    record: &'a CheckedRecord,
    code: &str,
    what: &str,
) -> Result<&'a Map<String, Value>, Fault> {
    record_value(record)
        .as_object()
        .ok_or_else(|| fault(code, format!("{what} must be a JSON object")))
}

/// Established (non-`Missing`) field, if any.
fn established<'a>(map: &'a Map<String, Value>, field: &str) -> Option<&'a Value> {
    map.get(field).filter(|value| !is_missing(value))
}

fn required_string(
    map: &Map<String, Value>,
    field: &str,
    code: &str,
    what: &str,
) -> Result<String, Fault> {
    match established(map, field) {
        Some(Value::String(text)) if !text.is_empty() => Ok(text.clone()),
        Some(Value::String(_)) => Err(fault(code, format!("{what} must be a nonempty string"))),
        Some(_) => Err(fault(code, format!("{what} must be a string"))),
        None => Err(fault(
            code,
            format!("{what} is required and must be established (not Missing)"),
        )),
    }
}

fn required_digest(
    map: &Map<String, Value>,
    field: &str,
    code: &str,
    what: &str,
) -> Result<String, Fault> {
    let text = required_string(map, field, code, what)?;
    if !is_digest_text(&text) {
        return Err(fault(
            code,
            format!("{what} must be 64 lowercase hex digest text"),
        ));
    }
    Ok(text)
}

fn required_u64_pos(
    map: &Map<String, Value>,
    field: &str,
    code: &str,
    what: &str,
) -> Result<u64, Fault> {
    match established(map, field) {
        Some(Value::Number(n)) => match n.as_u64() {
            Some(v) if v >= 1 => Ok(v),
            _ => Err(fault(
                code,
                format!("{what} must be a positive integer"),
            )),
        },
        Some(_) => Err(fault(code, format!("{what} must be a positive integer"))),
        None => Err(fault(
            code,
            format!("{what} is required and must be established (not Missing)"),
        )),
    }
}

fn reject_forbidden(map: &Map<String, Value>) -> Result<(), Fault> {
    for field in FORBIDDEN_EVIDENCE {
        if established(map, field).is_some() {
            return Err(fault(
                "unrecorded_evidence",
                format!(
                    "field {field:?} requires current wall time, live lookup, or mutable rows; diagnostics use only manifest, prefix, and pinned bundle"
                ),
            ));
        }
    }
    Ok(())
}

struct PrefixParts {
    journal_id: String,
    last_sequence: u64,
    head_hash: String,
}

fn parse_prefix(value: &Value, what: &str) -> Result<PrefixParts, Fault> {
    let map = value.as_object().ok_or_else(|| {
        fault(
            "invalid_prefix",
            format!("{what} must be a journal prefix object"),
        )
    })?;
    if is_missing(value) {
        return Err(fault(
            "invalid_prefix",
            format!("{what} must be established (not Missing)"),
        ));
    }
    let journal_id = required_string(map, "journal_id", "invalid_prefix", "prefix journal_id")?;
    let last_sequence = required_u64_pos(map, "last_sequence", "invalid_prefix", "prefix last_sequence")?;
    let head_hash = required_digest(map, "head_hash", "invalid_prefix", "prefix head_hash")?;
    Ok(PrefixParts {
        journal_id,
        last_sequence,
        head_hash,
    })
}

fn validate_version_pin(value: &Value, field: &str) -> Result<(), Fault> {
    let map = value.as_object().ok_or_else(|| {
        fault(
            "invalid_version_pin",
            format!("{field} must be a version pin object"),
        )
    })?;
    let has_id = map
        .get("id")
        .and_then(Value::as_str)
        .is_some_and(|s| !s.is_empty())
        || map
            .get("name")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty());
    if !has_id {
        return Err(fault(
            "invalid_version_pin",
            format!("{field} requires a nonempty id (or name)"),
        ));
    }
    match map.get("version").and_then(Value::as_str) {
        Some(v) if !v.is_empty() => {}
        _ => {
            return Err(fault(
                "invalid_version_pin",
                format!("{field} requires a nonempty version"),
            ))
        }
    }
    match map.get("artifact_digest").and_then(Value::as_str) {
        Some(d) if is_any_digest(d) => Ok(()),
        _ => Err(fault(
            "invalid_version_pin",
            format!("{field} requires artifact_digest as 64 hex or sha256:64 hex"),
        )),
    }
}

// ---------------------------------------------------------------------------
// derive_diagnostic
// ---------------------------------------------------------------------------

/// Derive a deterministic diagnostic from manifest, prefix, and bundle.
///
/// The diagnostic is a pure function of the three inputs: same canonical
/// bytes always yield the same diagnostic. No wall time, network, or mutable
/// state is consulted. Forbidden evidence fields fault with
/// `unrecorded_evidence`.
pub fn derive_diagnostic(
    manifest: &CheckedRecord,
    prefix: &CheckedRecord,
    bundle: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let manifest_map = as_object(manifest, "invalid_manifest", "manifest")?;
    let prefix_map = as_object(prefix, "invalid_prefix", "prefix")?;
    let bundle_map = as_object(bundle, "invalid_bundle", "bundle")?;
    reject_forbidden(manifest_map)?;
    reject_forbidden(prefix_map)?;
    reject_forbidden(bundle_map)?;

    let run_id = match manifest_map.get("run_id") {
        Some(value) if !is_missing(value) => match value.as_str() {
            Some(text) if !text.is_empty() => text.to_string(),
            _ => {
                return Err(fault(
                    "invalid_manifest",
                    "manifest run_id must be a nonempty string",
                ))
            }
        },
        _ => {
            return Err(fault(
                "missing_run_id",
                "manifest must carry an established run_id",
            ))
        }
    };

    let journal_id = required_string(prefix_map, "journal_id", "invalid_prefix", "prefix journal_id")?;
    let last_sequence =
        required_u64_pos(prefix_map, "last_sequence", "invalid_prefix", "prefix last_sequence")?;
    let head_hash = required_digest(prefix_map, "head_hash", "invalid_prefix", "prefix head_hash")?;

    let classifier = bundle_map.get("classifier").ok_or_else(|| {
        fault(
            "missing_classifier",
            "bundle must carry an established classifier pin",
        )
    })?;
    if is_missing(classifier) {
        return Err(fault(
            "missing_classifier",
            "bundle classifier must be established (not Missing)",
        ));
    }
    validate_version_pin(classifier, "classifier")?;

    let requirement_registry = bundle_map.get("requirement_registry").ok_or_else(|| {
        fault(
            "missing_requirement_registry",
            "bundle must carry an established requirement_registry pin",
        )
    })?;
    if is_missing(requirement_registry) {
        return Err(fault(
            "missing_requirement_registry",
            "bundle requirement_registry must be established (not Missing)",
        ));
    }
    validate_version_pin(requirement_registry, "requirement_registry")?;

    let fix_registry = bundle_map.get("fix_registry").ok_or_else(|| {
        fault(
            "missing_fix_registry",
            "bundle must carry fix_registry (pin or Missing)",
        )
    })?;
    if !is_missing(fix_registry) {
        validate_version_pin(fix_registry, "fix_registry")?;
    }

    let manifest_bytes = canonical_bytes(manifest)?;
    let prefix_bytes = canonical_bytes(prefix)?;
    let bundle_bytes = canonical_bytes(bundle)?;
    let manifest_hash = digest_bytes(&manifest_bytes);
    let prefix_hash = digest_bytes(&prefix_bytes);
    let bundle_hash = digest_bytes(&bundle_bytes);

    let mut combined = Vec::with_capacity(
        manifest_bytes.len() + prefix_bytes.len() + bundle_bytes.len(),
    );
    combined.extend_from_slice(&manifest_bytes);
    combined.extend_from_slice(&prefix_bytes);
    combined.extend_from_slice(&bundle_bytes);
    let combined_digest = digest_bytes(&combined);
    let diagnostic_id = format!("diag-{}", &combined_digest[..16]);

    let diagnostic = json!({
        "record_type": "diagnostic",
        "schema_version": SCHEMA_VERSION,
        "diagnostic_id": diagnostic_id,
        "analysis_revision": 1,
        "run_id": run_id,
        "manifest_hash": manifest_hash,
        "prefix_hash": prefix_hash,
        "bundle_hash": bundle_hash,
        "input_prefix": {
            "journal_id": journal_id,
            "last_sequence": last_sequence,
            "head_hash": head_hash,
        },
        "classifier": classifier.clone(),
        "requirement_registry": requirement_registry.clone(),
        "fix_registry": fix_registry.clone(),
        "derived_wall_time": missing("not_applicable", "diagnostics use no wall time"),
        "evidence_refs": [],
    });
    validate(OUTPUT_SCHEMA, diagnostic)
}

// ---------------------------------------------------------------------------
// replay_offline
// ---------------------------------------------------------------------------

/// Evidence for normalization recomputation: pinned TimePoint (never wall
/// time), the request prefix, and one fixed support ref.
fn replay_evidence(source_prefix: &Value) -> Result<CheckedRecord, Fault> {
    let journal_id = source_prefix
        .as_object()
        .and_then(|map| map.get("journal_id"))
        .and_then(Value::as_str)
        .unwrap_or("j-replay");
    let evidence = json!({
        "captured_at": {
            "clock_id": "replay-clk",
            "boot_id": "boot-replay",
            "origin": "engine_measured",
            "monotonic_offset_ms": 0,
            "utc_annotation": missing("not_observed", "replay uses a pinned clock, never wall time"),
        },
        "evidence_prefix": source_prefix.clone(),
        "evidence_refs": [{
            "journal_id": journal_id,
            "sequence": 1,
            "event_id": "evt-replay-1",
            "event_hash": "replay-evidence",
            "pointer": "/replay",
        }],
    });
    validate(OUTPUT_SCHEMA, evidence)
}

fn comparison_entry(
    output: &str,
    expected: &str,
    actual: Option<String>,
    unavailable_reason: &str,
    unavailable_detail: &str,
) -> Value {
    match actual {
        Some(digest) if digest == expected => json!({
            "output": output,
            "expected": expected,
            "actual": digest,
            "result": "matched",
        }),
        Some(digest) => json!({
            "output": output,
            "expected": expected,
            "actual": digest,
            "result": "mismatched",
        }),
        None => json!({
            "output": output,
            "expected": expected,
            "actual": missing(unavailable_reason, unavailable_detail),
            "result": "unavailable",
        }),
    }
}

fn aggregate_result(results: &[&str]) -> &'static str {
    if results.iter().any(|r| *r == "mismatched") {
        "mismatched"
    } else if results.iter().any(|r| *r == "unavailable") {
        "unavailable"
    } else {
        "matched"
    }
}

fn result_of(entry: &Value) -> &str {
    entry
        .get("result")
        .and_then(Value::as_str)
        .unwrap_or("unavailable")
}

/// Recompute the semantic-events digest from recorded inputs.
///
/// `audit_rows`, when supplied, are each normalized via `normalize_row`
/// (entity `audit_log`) and their snapshot digests folded into the hashed
/// input. Recorded derived outputs are never consulted.
fn recompute_semantic(
    external_inputs: &Value,
    lifecycle_observations: &Value,
    audit_rows: Option<&Vec<Value>>,
    evidence: &CheckedRecord,
) -> Result<String, Fault> {
    let mut input = Map::new();
    input.insert(
        "kind".to_string(),
        Value::String("semantic_events".to_string()),
    );
    input.insert(
        "external_inputs".to_string(),
        external_inputs.clone(),
    );
    input.insert(
        "lifecycle_observations".to_string(),
        lifecycle_observations.clone(),
    );
    if let Some(rows) = audit_rows {
        let mut digests = Vec::with_capacity(rows.len());
        for row in rows {
            let normalized =
                normalize_row(SourceEntity::AuditLog, row.clone(), evidence)?;
            let snapshot_bytes = canonical_bytes(&normalized)?;
            digests.push(Value::String(digest_bytes(&snapshot_bytes)));
        }
        input.insert("normalized_digests".to_string(), Value::Array(digests));
    }
    let record = validate(OUTPUT_SCHEMA, Value::Object(input))?;
    let bytes = canonical_bytes(&record)?;
    Ok(digest_bytes(&bytes))
}

/// Recompute the final-state digest from recorded inputs.
///
/// When `detector_transcript` is supplied, `evaluate_detectors` is rerun over
/// the recorded declaration/prior/packet and its output digest folded in.
fn recompute_final(
    external_inputs: &Value,
    lifecycle_observations: &Value,
    detector_transcript: Option<(&Value, &Value, &Value)>,
) -> Result<String, Fault> {
    let mut input = Map::new();
    input.insert("kind".to_string(), Value::String("final_state".to_string()));
    input.insert(
        "external_inputs".to_string(),
        external_inputs.clone(),
    );
    input.insert(
        "lifecycle_observations".to_string(),
        lifecycle_observations.clone(),
    );
    if let Some((declaration, prior, packet)) = detector_transcript {
        let declaration_record = validate(OUTPUT_SCHEMA, declaration.clone())?;
        let prior_record = validate("cursor_state", prior.clone())?;
        let packet_record = validate("cursor_state", packet.clone())?;
        let detector_out =
            evaluate_detectors(&declaration_record, &prior_record, &packet_record)?;
        let detector_bytes = canonical_bytes(&detector_out)?;
        input.insert(
            "detector_digest".to_string(),
            Value::String(digest_bytes(&detector_bytes)),
        );
    }
    let record = validate(OUTPUT_SCHEMA, Value::Object(input))?;
    let bytes = canonical_bytes(&record)?;
    Ok(digest_bytes(&bytes))
}

fn recompute_diagnostic(
    manifest_value: &Value,
    prefix_value: &Value,
    bundle_value: &Value,
) -> Result<String, Fault> {
    let manifest_record = validate(OUTPUT_SCHEMA, manifest_value.clone())?;
    let prefix_record = validate(OUTPUT_SCHEMA, prefix_value.clone())?;
    let bundle_record = validate(OUTPUT_SCHEMA, bundle_value.clone())?;
    let diagnostic = derive_diagnostic(&manifest_record, &prefix_record, &bundle_record)?;
    let bytes = canonical_bytes(&diagnostic)?;
    Ok(digest_bytes(&bytes))
}

/// Replay recorded inputs offline and compare derived outputs.
///
/// Reads the input bundle artifact (no browsers, subjects, live acquisition,
/// inference, or external writes), recomputes semantic events, final state,
/// and the diagnostic from recorded inputs only, and compares each to the
/// request's expected digests. Missing inputs yield `unavailable`
/// comparisons, never `matched`. The aggregate is `mismatched` when any
/// required comparison mismatches, else `unavailable` when any is
/// unavailable, else `matched`.
pub fn replay_offline(
    artifacts: &dyn ArtifactStore,
    grant: &Grant,
    request: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let req = as_object(request, "invalid_request", "request")?;

    let replay_id = required_string(req, "replay_id", "invalid_request", "replay_id")?;
    let mode = required_string(req, "mode", "invalid_request", "mode")?;
    if mode != "exact_fixture" && mode != "diagnostic_rederivation" {
        return Err(fault(
            "unknown_mode",
            format!("mode must be exact_fixture or diagnostic_rederivation, got {mode:?}"),
        ));
    }
    let exact = mode == "exact_fixture";
    let run_id = required_string(req, "run_id", "invalid_request", "run_id")?;
    let manifest_hash = required_digest(req, "manifest_hash", "invalid_request", "manifest_hash")?;

    let source_prefix_value = req.get("source_prefix").ok_or_else(|| {
        fault(
            "invalid_request",
            "request must carry source_prefix".to_string(),
        )
    })?;
    if is_missing(source_prefix_value) {
        return Err(fault(
            "invalid_request",
            "source_prefix must be established (not Missing)".to_string(),
        ));
    }
    let prefix_parts = parse_prefix(source_prefix_value, "source_prefix")?;

    let source_diagnostic_value = req.get("source_diagnostic").ok_or_else(|| {
        fault(
            "invalid_request",
            "request must carry source_diagnostic".to_string(),
        )
    })?;
    let source_diagnostic_map = source_diagnostic_value.as_object().ok_or_else(|| {
        fault(
            "invalid_request",
            "source_diagnostic must be an object with digest".to_string(),
        )
    })?;
    if is_missing(source_diagnostic_value) {
        return Err(fault(
            "invalid_request",
            "source_diagnostic must be established (not Missing)".to_string(),
        ));
    }
    let source_diagnostic_digest = match source_diagnostic_map.get("digest") {
        Some(Value::String(text)) if is_digest_text(text) => text.clone(),
        _ => {
            return Err(fault(
                "invalid_request",
                "source_diagnostic.digest must be 64 lowercase hex".to_string(),
            ))
        }
    };

    let input_bundle_value = req.get("input_bundle").ok_or_else(|| {
        fault(
            "invalid_request",
            "request must carry input_bundle artifact reference".to_string(),
        )
    })?;
    if is_missing(input_bundle_value) || !input_bundle_value.is_object() {
        return Err(fault(
            "invalid_request",
            "input_bundle must be an established artifact reference object".to_string(),
        ));
    }
    let input_bundle_record = validate(OUTPUT_SCHEMA, input_bundle_value.clone()).map_err(|e| {
        fault(
            "invalid_reference",
            format!("input_bundle reference failed validation: {} {}", e.code, e.detail),
        )
    })?;

    let classifier_value = req.get("classifier").ok_or_else(|| {
        fault(
            "invalid_request",
            "request must carry classifier pin".to_string(),
        )
    })?;
    if is_missing(classifier_value) {
        return Err(fault(
            "invalid_request",
            "classifier must be established (not Missing)".to_string(),
        ));
    }
    validate_version_pin(classifier_value, "classifier")?;

    let reducer_value = req.get("reducer").ok_or_else(|| {
        fault(
            "invalid_request",
            "request must carry reducer (pin or Missing)".to_string(),
        )
    })?;
    if exact {
        if is_missing(reducer_value) {
            return Err(fault(
                "invalid_reducer",
                "exact_fixture requires an established reducer pin".to_string(),
            ));
        }
        validate_version_pin(reducer_value, "reducer")?;
    } else {
        if !is_missing(reducer_value) {
            return Err(fault(
                "invalid_reducer",
                "diagnostic_rederivation requires reducer Missing(not_applicable)".to_string(),
            ));
        }
        if missing_reason(reducer_value) != Some("not_applicable") {
            return Err(fault(
                "invalid_reducer",
                "diagnostic_rederivation reducer must be Missing(not_applicable)".to_string(),
            ));
        }
    }

    let replay_engine_value = req.get("replay_engine").ok_or_else(|| {
        fault(
            "invalid_request",
            "request must carry replay_engine pin".to_string(),
        )
    })?;
    if is_missing(replay_engine_value) {
        return Err(fault(
            "invalid_request",
            "replay_engine must be established (not Missing)".to_string(),
        ));
    }
    validate_version_pin(replay_engine_value, "replay_engine")?;

    let expected_value = req.get("expected").ok_or_else(|| {
        fault(
            "invalid_request",
            "request must carry expected digests".to_string(),
        )
    })?;
    let expected_map = expected_value.as_object().ok_or_else(|| {
        fault("invalid_request", "expected must be an object".to_string())
    })?;
    if is_missing(expected_value) {
        return Err(fault(
            "invalid_request",
            "expected must be established (not Missing)".to_string(),
        ));
    }

    // Employer mutations are never replayed, in either mode.
    if let Some(value) = established(req, "employer_mutation") {
        if value == &Value::Bool(true) {
            return Err(fault(
                "employer_mutation_not_replayable",
                "replay cannot repeat an employer mutation; diagnostic-only replay re-derives diagnostics only",
            ));
        }
    }
    if established(req, "mutation_ref").is_some() {
        return Err(fault(
            "employer_mutation_not_replayable",
            "replay cannot repeat an employer mutation; mutation_ref is not replayable offline",
        ));
    }

    let expected_diagnostic = match expected_map.get("diagnostic") {
        Some(value) if !is_missing(value) => match value.as_str() {
            Some(text) if is_digest_text(text) => text.to_string(),
            _ => {
                return Err(fault(
                    "missing_expected",
                    "expected.diagnostic must be 64 lowercase hex".to_string(),
                ))
            }
        },
        _ => {
            return Err(fault(
                "missing_expected",
                "expected.diagnostic is required in both modes".to_string(),
            ))
        }
    };
    if source_diagnostic_digest != expected_diagnostic {
        return Err(fault(
            "inconsistent_expected",
            "source_diagnostic.digest must equal expected.diagnostic",
        ));
    }

    let (expected_semantic, expected_final) = if exact {
        let semantic = match expected_map.get("semantic_events") {
            Some(value) if !is_missing(value) => match value.as_str() {
                Some(text) if is_digest_text(text) => text.to_string(),
                _ => {
                    return Err(fault(
                        "missing_expected",
                        "expected.semantic_events must be 64 lowercase hex".to_string(),
                    ))
                }
            },
            _ => {
                return Err(fault(
                    "missing_expected",
                    "exact_fixture requires expected.semantic_events".to_string(),
                ))
            }
        };
        let final_state = match expected_map.get("final_state") {
            Some(value) if !is_missing(value) => match value.as_str() {
                Some(text) if is_digest_text(text) => text.to_string(),
                _ => {
                    return Err(fault(
                        "missing_expected",
                        "expected.final_state must be 64 lowercase hex".to_string(),
                    ))
                }
            },
            _ => {
                return Err(fault(
                    "missing_expected",
                    "exact_fixture requires expected.final_state".to_string(),
                ))
            }
        };
        (Some(semantic), Some(final_state))
    } else {
        if established(expected_map, "semantic_events").is_some()
            || established(expected_map, "final_state").is_some()
        {
            return Err(fault(
                "unexpected_expected",
                "diagnostic_rederivation carries only expected.diagnostic".to_string(),
            ));
        }
        (None, None)
    };

    // Read the recorded input bundle. Lost bytes preserve their known
    // identity and yield unavailable comparisons, never matched and never
    // refabricated content. Authorization and integrity faults propagate.
    let bundle_bytes = match artifacts.read(grant, &input_bundle_record) {
        Ok(bytes) => bytes,
        Err(e) if e.code == "bytes_unavailable" => {
            return finish_unavailable_bundle(
                &replay_id,
                &mode,
                &run_id,
                &manifest_hash,
                source_prefix_value,
                source_diagnostic_value,
                input_bundle_value,
                classifier_value,
                reducer_value,
                replay_engine_value,
                expected_semantic.as_deref(),
                expected_final.as_deref(),
                &expected_diagnostic,
                exact,
            );
        }
        Err(e) => return Err(e),
    };

    let bundle_value: Value = serde_json::from_slice(&bundle_bytes).map_err(|e| {
        fault(
            "invalid_bundle",
            format!("input bundle bytes are not valid JSON: {e}"),
        )
    })?;
    let bundle_map = bundle_value.as_object().ok_or_else(|| {
        fault(
            "invalid_bundle",
            "input bundle must be a JSON object".to_string(),
        )
    })?;

    // NOTE: `recorded_derived*` fields are deliberately never read here.
    // Recomputation consumes only recorded inputs and lifecycle
    // observations; recorded derived outputs serve no authoritative role.

    let external_inputs = established(bundle_map, "external_inputs");
    let lifecycle_observations = established(bundle_map, "lifecycle_observations");

    let audit_rows: Option<Vec<Value>> = match bundle_map.get("audit_rows") {
        None => None,
        Some(value) if is_missing(value) => None,
        Some(Value::Array(rows)) => {
            for row in rows {
                if !row.is_object() {
                    return Err(fault(
                        "invalid_bundle",
                        "bundle audit_rows entries must be objects",
                    ));
                }
            }
            Some(rows.clone())
        }
        Some(_) => {
            return Err(fault(
                "invalid_bundle",
                "bundle audit_rows must be an array when established",
            ))
        }
    };

    // Detector transcript: present-and-complete enables detector
    // recomputation; present-but-incomplete degrades final_state to
    // unavailable; present-but-malformed faults.
    let transcript_present = matches!(
        bundle_map.get("detector_transcript"),
        Some(value) if !is_missing(value)
    );
    let detector_transcript: Option<(Value, Value, Value)> = match bundle_map.get("detector_transcript") {
        None => None,
        Some(value) if is_missing(value) => None,
        Some(Value::Object(transcript)) => {
            let declaration = transcript.get("declaration");
            let prior = transcript.get("prior");
            let packet = transcript.get("packet");
            let complete = [declaration, prior, packet].iter().all(|slot| {
                matches!(slot, Some(value) if !is_missing(value) && value.is_object())
            });
            let malformed = [declaration, prior, packet].iter().any(|slot| {
                matches!(slot, Some(value) if !is_missing(value) && !value.is_object())
            });
            if malformed {
                return Err(fault(
                    "invalid_bundle",
                    "detector_transcript declaration/prior/packet must be objects when established",
                ));
            }
            if complete {
                Some((
                    declaration.unwrap().clone(),
                    prior.unwrap().clone(),
                    packet.unwrap().clone(),
                ))
            } else {
                // Incomplete transcript marker: handled below as unavailable.
                // Represent as None but remember presence for the detail.
                None
            }
        }
        Some(_) => {
            return Err(fault(
                "invalid_bundle",
                "bundle detector_transcript must be an object when established",
            ))
        }
    };
    let transcript_incomplete =
        transcript_present && detector_transcript.is_none();

    let diagnostic_manifest = match bundle_map.get("diagnostic_manifest") {
        None => None,
        Some(value) if is_missing(value) => None,
        Some(value) if value.is_object() => Some(value),
        Some(_) => {
            return Err(fault(
                "invalid_bundle",
                "bundle diagnostic_manifest must be an object when established",
            ))
        }
    };
    let diagnostic_prefix = match bundle_map.get("diagnostic_prefix") {
        None => None,
        Some(value) if is_missing(value) => None,
        Some(value) if value.is_object() => Some(value),
        Some(_) => {
            return Err(fault(
                "invalid_bundle",
                "bundle diagnostic_prefix must be an object when established",
            ))
        }
    };
    let diagnostic_bundle = match bundle_map.get("diagnostic_bundle") {
        None => None,
        Some(value) if is_missing(value) => None,
        Some(value) if value.is_object() => Some(value),
        Some(_) => {
            return Err(fault(
                "invalid_bundle",
                "bundle diagnostic_bundle must be an object when established",
            ))
        }
    };

    let mut comparisons: Vec<Value> = Vec::new();
    let mut limitations: Vec<Value> = vec![Value::String(
        "offline replay; no browser, subject, or external writes invoked".to_string(),
    )];

    if exact {
        // Semantic events.
        let semantic_actual = match (external_inputs, lifecycle_observations) {
            (Some(external), Some(lifecycle)) => {
                let evidence = replay_evidence(source_prefix_value)?;
                let digest = recompute_semantic(
                    external,
                    lifecycle,
                    audit_rows.as_ref(),
                    &evidence,
                )?;
                Some(digest)
            }
            _ => {
                limitations.push(Value::String(
                    "semantic_events inputs missing; comparison unavailable".to_string(),
                ));
                None
            }
        };
        comparisons.push(comparison_entry(
            "semantic_events",
            expected_semantic.as_ref().unwrap(),
            semantic_actual,
            "not_observed",
            "recorded external inputs or lifecycle observations missing for semantic_events",
        ));

        // Final state.
        let final_actual = match (external_inputs, lifecycle_observations) {
            (Some(external), Some(lifecycle)) => {
                if transcript_incomplete {
                    limitations.push(Value::String(
                        "detector_transcript incomplete; final_state unavailable".to_string(),
                    ));
                    None
                } else {
                    let transcript_ref = detector_transcript
                        .as_ref()
                        .map(|(declaration, prior, packet)| {
                            (
                                declaration as &Value,
                                prior as &Value,
                                packet as &Value,
                            )
                        });
                    let digest = recompute_final(external, lifecycle, transcript_ref)?;
                    Some(digest)
                }
            }
            _ => {
                limitations.push(Value::String(
                    "final_state inputs missing; comparison unavailable".to_string(),
                ));
                None
            }
        };
        comparisons.push(comparison_entry(
            "final_state",
            expected_final.as_ref().unwrap(),
            final_actual,
            "not_observed",
            "recorded external inputs or lifecycle observations missing for final_state",
        ));
    }

    // Diagnostic (both modes).
    let diagnostic_actual = match (diagnostic_manifest, diagnostic_prefix, diagnostic_bundle) {
        (Some(manifest), Some(prefix), Some(bundle)) => {
            let digest = recompute_diagnostic(manifest, prefix, bundle)?;
            Some(digest)
        }
        _ => {
            limitations.push(Value::String(
                "diagnostic inputs missing; comparison unavailable".to_string(),
            ));
            None
        }
    };
    comparisons.push(comparison_entry(
        "diagnostic",
        &expected_diagnostic,
        diagnostic_actual,
        "not_observed",
        "recorded diagnostic manifest, prefix, or bundle missing",
    ));

    let results: Vec<&str> = comparisons.iter().map(result_of).collect();
    let aggregate = aggregate_result(&results);
    if aggregate == "mismatched" {
        limitations.push(Value::String(
            "recomputed digests differ from expected; recorded derived outputs were not substituted"
                .to_string(),
        ));
    } else if aggregate == "unavailable" {
        limitations.push(Value::String(
            "missing inputs cannot yield matched".to_string(),
        ));
    } else {
        limitations.push(Value::String(
            "every required comparison available and equal".to_string(),
        ));
    }

    // Silence unused warning for parsed prefix parts beyond validation;
    // the receipt echoes the request prefix verbatim.
    let _ = (&prefix_parts.journal_id, prefix_parts.last_sequence, &prefix_parts.head_hash);

    let receipt = json!({
        "record_type": "replay_receipt",
        "schema_version": SCHEMA_VERSION,
        "replay_id": replay_id,
        "mode": mode,
        "run_id": run_id,
        "manifest_hash": manifest_hash,
        "source_prefix": source_prefix_value.clone(),
        "source_diagnostic": source_diagnostic_value.clone(),
        "input_bundle": input_bundle_digest_view(input_bundle_value),
        "classifier": classifier_value.clone(),
        "reducer": reducer_value.clone(),
        "replay_engine": replay_engine_value.clone(),
        "comparisons": comparisons,
        "result": aggregate,
        "limitations": limitations,
        "invoked_browser": false,
        "invoked_subject": false,
        "performed_external_writes": false,
    });
    validate(OUTPUT_SCHEMA, receipt)
}

/// Contract-shaped view of the input bundle reference for receipts.
fn input_bundle_digest_view(reference: &Value) -> Value {
    let map = reference.as_object().cloned().unwrap_or_default();
    let mut view = Map::new();
    for field in ["digest", "size_bytes", "media_type", "owner_domain", "access"] {
        if let Some(value) = map.get(field) {
            view.insert(field.to_string(), value.clone());
        }
    }
    Value::Object(view)
}

#[allow(clippy::too_many_arguments)]
fn finish_unavailable_bundle(
    replay_id: &str,
    mode: &str,
    run_id: &str,
    manifest_hash: &str,
    source_prefix: &Value,
    source_diagnostic: &Value,
    input_bundle: &Value,
    classifier: &Value,
    reducer: &Value,
    replay_engine: &Value,
    expected_semantic: Option<&str>,
    expected_final: Option<&str>,
    expected_diagnostic: &str,
    exact: bool,
) -> Result<CheckedRecord, Fault> {
    let mut comparisons = Vec::new();
    if exact {
        comparisons.push(comparison_entry(
            "semantic_events",
            expected_semantic.unwrap_or(expected_diagnostic),
            None,
            "observation_lost",
            "input bundle bytes unavailable; known digest preserved, content never refabricated",
        ));
        comparisons.push(comparison_entry(
            "final_state",
            expected_final.unwrap_or(expected_diagnostic),
            None,
            "observation_lost",
            "input bundle bytes unavailable; known digest preserved, content never refabricated",
        ));
    }
    comparisons.push(comparison_entry(
        "diagnostic",
        expected_diagnostic,
        None,
        "observation_lost",
        "input bundle bytes unavailable; known digest preserved, content never refabricated",
    ));
    let receipt = json!({
        "record_type": "replay_receipt",
        "schema_version": SCHEMA_VERSION,
        "replay_id": replay_id,
        "mode": mode,
        "run_id": run_id,
        "manifest_hash": manifest_hash,
        "source_prefix": source_prefix.clone(),
        "source_diagnostic": source_diagnostic.clone(),
        "input_bundle": input_bundle_digest_view(input_bundle),
        "classifier": classifier.clone(),
        "reducer": reducer.clone(),
        "replay_engine": replay_engine.clone(),
        "comparisons": comparisons,
        "result": "unavailable",
        "limitations": [
            "offline replay; no browser, subject, or external writes invoked",
            "input bundle bytes unavailable; known digest preserved",
            "missing inputs cannot yield matched",
        ],
        "invoked_browser": false,
        "invoked_subject": false,
        "performed_external_writes": false,
    });
    validate(OUTPUT_SCHEMA, receipt)
}

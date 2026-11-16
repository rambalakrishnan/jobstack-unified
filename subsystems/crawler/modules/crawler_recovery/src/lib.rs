//! `crawler_recovery`: process/reboot recovery without refetching proven work.
//!
//! Recovery coordinates the owner-local durable seams after a process restart,
//! reboot, or confirmed worker death (seam map §21.4, [C44]):
//!
//! * **Acknowledged work survives.** The incident names the owner journal and,
//!   optionally, the acknowledged prefix (`last_sequence`/`head_hash`) plus the
//!   acknowledged `(journal_sequence, event_id)` coordinates. [`recover`]
//!   reads the prefix and every acknowledged event back through
//!   [`OwnerStore::read`]. A short prefix, a diverged head, or a missing event
//!   faults with `acknowledgement_lost`; storage faults propagate unchanged and
//!   no receipt is issued, so storage failure never acknowledges or advances a
//!   cursor.
//! * **Proven partitions are never refetched.** `proven_partitions` entries must
//!   carry `status: proven`. Any established `refetch`/`fetch` request, or any
//!   incomplete packet that overlaps a proven id, faults with
//!   `proven_refetch_refused`. The receipt pins every proven partition with
//!   `refetch: false`.
//! * **Incomplete packets replay idempotently.** `incomplete_packets` entries
//!   without a `replay` command are marked `replayable: true` for a later walk.
//!   Entries with a `replay` (`before` + `transaction` + optional surface) are
//!   validated through [`Pipeline::advance`], so orphan packets, cursors beyond
//!   the durable boundary, and forbidden spans are refused before any effect.
//! * **Death is fenced before reclaim.** Each `leases` entry is a complete
//!   `reclaim` request delegated to [`crawler_leases::reclaim`]. Release,
//!   expiry, and `death_recovery` (which requires a strictly newer authority
//!   epoch and never compares the old deadline with the new boot) clear
//!   ownership and charge the failed generation exactly once. Stale completions
//!   have no effect; the store fault propagates.
//! * **Sessions establish a new epoch.** Each `sessions` entry is an establish
//!   request. [`recover`] reserves an independent control credit via
//!   [`Admission::reserve_control`] (never from data pools) and calls
//!   [`SessionManager::establish`]. Cold recovery journals a new epoch with a
//!   fresh client; stale or rejected generations fault before any content is
//!   accepted.
//! * **Archives are verified, never substituted.** Each `archive_roots` entry is
//!   expanded via [`crawler_archives::expand_archive`]: the exact complete row
//!   is reconstructed from the immutable extents named by the storage manifest.
//!   Missing bytes or a payload mismatch fault; a locator or hash alone never
//!   stands in for the archived content.
//! * **Siblings are isolated.** Every lease row target and every session target
//!   must equal the incident `target`, otherwise recovery faults with
//!   `cross_target_refused` before any effect for that entry. One target's
//!   challenge, handoff, or pressure never reclaims, retires, or blocks a
//!   sibling.
//!
//! The returned `recovery_receipt` (`audit_log` envelope) carries the survived
//! prefix, the verified acknowledgement count, the proven no-refetch pin, the
//! replayable set, the delegated reclaim/session/archive results, and the
//! authority-clock `recovered_at`. It covers the process/reboot fault model
//! only; it never claims permanent-media-loss recovery.
//!
//! # Incident shape
//!
//! The incident is a gate-validated `audit_log` object:
//!
//! ```text
//! {
//!   "incident_id": "<id>", "journal_id": "<journal>",
//!   "trigger": "restart" | "reboot" | "worker_death",
//!   "target": "<active target>",
//!   "expected_prefix": {"last_sequence": <u64>, "head_hash": "<hash>"} | Missing,
//!   "acknowledged": [{"journal_sequence": <u64>, "event_id": "<id>"?}, ...] | Missing,
//!   "proven_partitions": [{"partition_id": "<id>", "status": "proven"}, ...] | Missing,
//!   "incomplete_packets": [{"packet_id": "<id>", "replay": {"before": ..., "transaction": ...}?}, ...] | Missing,
//!   "leases": [<reclaim request objects>] | Missing,
//!   "sessions": [<establish request objects>] | Missing,
//!   "archive_roots": [<ArchiveRecord or artifact reference objects>] | Missing
//! }
//! ```
//!
//! Absent or `Missing` sections mean "nothing to recover" for that seam. No
//! bare JSON null is emitted; missing fields use typed `Missing` envelopes.

use crawler_admission::Admission;
use crawler_archives::expand_archive;
use crawler_artifacts::ArtifactStore;
use crawler_authority::{grant_record, Grant};
use crawler_leases::reclaim;
use crawler_pipeline::Pipeline;
use crawler_schema::{record_value, validate, CheckedRecord, Fault};
use crawler_sessions::SessionManager;
use crawler_store::OwnerStore;
use crawler_time::ClockAuthority;
use serde_json::{json, Map, Value};

/// Structural envelope for records produced by this module.
const OUTPUT_SCHEMA: &str = "audit_log";

/// Triggers in the process/reboot recovery model.
const TRIGGERS: &[&str] = &["restart", "reboot", "worker_death"];

fn fault(code: &str, detail: impl Into<String>) -> Fault {
    Fault {
        code: code.to_string(),
        detail: detail.into(),
    }
}

fn missing(reason: &str, detail: &str) -> Value {
    json!({"value": Value::Null, "reason": reason, "detail": detail})
}

/// True when `value` is a schema-gate `Missing` envelope.
fn is_missing(value: &Value) -> bool {
    value
        .as_object()
        .is_some_and(|map| map.get("value").is_some_and(|v| v.is_null()) && map.contains_key("reason"))
}

/// The established (non-`Missing`) value of `field`, if any.
fn established<'a>(map: &'a Map<String, Value>, field: &str) -> Option<&'a Value> {
    map.get(field).filter(|value| !is_missing(value))
}

fn as_object<'a>(record: &'a CheckedRecord, code: &str, what: &str) -> Result<&'a Map<String, Value>, Fault> {
    record_value(record).as_object().ok_or_else(|| {
        fault(
            code,
            format!("{what} must be a gate-validated object"),
        )
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

/// Session target carried by an establish request: top level, then the wrapped
/// authorized request or endpoint. `None` when the request names no target.
fn session_target_of(map: &Map<String, Value>) -> Result<Option<String>, Fault> {
    if let Some(value) = map.get("target").filter(|v| !is_missing(v)) {
        let text = value.as_str().ok_or_else(|| {
            fault(
                "invalid_session",
                "session establish target must be a string".to_string(),
            )
        })?;
        if !text.is_empty() {
            return Ok(Some(text.to_string()));
        }
    }
    for key in ["request", "endpoint"] {
        if let Some(nested) = map.get(key).filter(|v| !is_missing(v)) {
            if let Some(obj) = nested.as_object() {
                if let Some(value) = obj.get("target").filter(|v| !is_missing(v)) {
                    let text = value.as_str().ok_or_else(|| {
                        fault(
                            "invalid_session",
                            format!("session {key} target must be a string"),
                        )
                    })?;
                    if !text.is_empty() {
                        return Ok(Some(text.to_string()));
                    }
                }
            }
        }
    }
    Ok(None)
}

/// Recover one target after a process restart, reboot, or confirmed worker death.
///
/// See the module documentation for the incident shape and the per-seam
/// guarantees. Every delegated effect (lease reclaim, session establishment,
/// pipeline replay, archive expansion) is owner-local; no peer lock is taken
/// and no cross-owner transaction is attempted. Any fault — storage failure,
/// lost acknowledgement, proven-refetch attempt, cross-target scope, stale
/// fence, expired credit, or integrity mismatch — propagates without a receipt.
#[allow(clippy::too_many_arguments)]
pub fn recover(
    store: &dyn OwnerStore,
    artifacts: &dyn ArtifactStore,
    clock: &dyn ClockAuthority,
    admission: &dyn Admission,
    sessions: &dyn SessionManager,
    pipeline: &dyn Pipeline,
    grant: &Grant,
    incident: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    // Grant must carry authenticated owner facts; nothing is copied from the incident.
    let grant_map = record_value(grant_record(grant))
        .as_object()
        .ok_or_else(|| {
            fault(
                "invalid_grant",
                "grant must carry a gate-validated authority record".to_string(),
            )
        })?;
    match established(grant_map, "owner_domain") {
        Some(Value::String(text)) if !text.is_empty() => {}
        _ => {
            return Err(fault(
                "invalid_grant",
                "grant requires an established nonempty string \"owner_domain\"".to_string(),
            ))
        }
    }

    let incident_map = as_object(incident, "invalid_incident", "incident")?;
    let incident_id = required_str(incident_map, "incident_id", "invalid_incident", "incident")?.to_string();
    let journal_id = required_str(incident_map, "journal_id", "invalid_incident", "incident")?.to_string();
    let trigger = required_str(incident_map, "trigger", "invalid_incident", "incident")?.to_string();
    if !TRIGGERS.contains(&trigger.as_str()) {
        return Err(fault(
            "invalid_trigger",
            format!(
                "trigger {trigger:?} is not one of {}; the receipt covers the process/reboot model only",
                TRIGGERS.join(", ")
            ),
        ));
    }
    let target = required_str(incident_map, "target", "invalid_incident", "incident")?.to_string();

    // Authority-clock instant for the receipt. UTC annotations stay advisory.
    let now_record = clock
        .now()
        .map_err(|error| fault(error.code.as_str(), format!("recovery clock: {}", error.detail)))?;
    let now_value = record_value(&now_record).clone();
    let now_map = now_value.as_object().ok_or_else(|| {
        fault(
            "invalid_clock",
            "clock authority must report a TimePoint object".to_string(),
        )
    })?;
    for field in [
        "clock_id",
        "boot_id",
        "origin",
        "monotonic_offset_ms",
        "utc_annotation",
    ] {
        if !now_map.contains_key(field) {
            return Err(fault(
                "invalid_clock",
                format!("clock authority TimePoint is missing {field:?}"),
            ));
        }
    }

    // Acknowledged prefix must have survived. Storage failure propagates with no receipt.
    let prefix_query = validate(
        OUTPUT_SCHEMA,
        json!({"query": "prefix", "journal_id": journal_id}),
    )?;
    let prefix_record = store.read(grant, &prefix_query)?;
    let prefix_map = as_object(&prefix_record, "invalid_store_view", "prefix view")?;
    let last_sequence = prefix_map
        .get("last_sequence")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            fault(
                "invalid_store_view",
                "prefix view carries no last_sequence".to_string(),
            )
        })?;
    let head_hash = prefix_map
        .get("head_hash")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();

    if let Some(expected) = established(incident_map, "expected_prefix") {
        let expected_map = expected.as_object().ok_or_else(|| {
            fault(
                "invalid_incident",
                "incident expected_prefix must be an object".to_string(),
            )
        })?;
        if let Some(sequence_value) = expected_map.get("last_sequence").filter(|v| !is_missing(v)) {
            let expected_sequence = sequence_value.as_u64().ok_or_else(|| {
                fault(
                    "invalid_incident",
                    "incident expected_prefix.last_sequence must be an integer".to_string(),
                )
            })?;
            if last_sequence < expected_sequence {
                return Err(fault(
                    "acknowledgement_lost",
                    format!(
                        "journal {journal_id:?} prefix at sequence {last_sequence} is behind acknowledged {expected_sequence}; acknowledged work did not survive {trigger}"
                    ),
                ));
            }
            if last_sequence == expected_sequence {
                if let Some(head_value) = expected_map.get("head_hash").filter(|v| !is_missing(v)) {
                    let expected_head = head_value.as_str().ok_or_else(|| {
                        fault(
                            "invalid_incident",
                            "incident expected_prefix.head_hash must be a string".to_string(),
                        )
                    })?;
                    if !expected_head.is_empty() && head_hash != expected_head {
                        return Err(fault(
                            "acknowledgement_lost",
                            format!(
                                "journal {journal_id:?} head {head_hash:?} disagrees with acknowledged {expected_head:?} at sequence {last_sequence}"
                            ),
                        ));
                    }
                }
            }
        }
    }

    // Every acknowledged coordinate must still read back with its event id.
    let mut acknowledged_verified = 0u64;
    if let Some(acknowledged) = established(incident_map, "acknowledged") {
        let entries = acknowledged.as_array().ok_or_else(|| {
            fault(
                "invalid_incident",
                "incident acknowledged must be an array".to_string(),
            )
        })?;
        for entry in entries {
            if is_missing(entry) {
                continue;
            }
            let entry_map = entry.as_object().ok_or_else(|| {
                fault(
                    "invalid_incident",
                    "incident acknowledged entries must be objects".to_string(),
                )
            })?;
            let sequence = entry_map
                .get("journal_sequence")
                .filter(|v| !is_missing(v))
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    fault(
                        "invalid_incident",
                        "incident acknowledged entries require journal_sequence".to_string(),
                    )
                })?;
            let event_query = validate(
                OUTPUT_SCHEMA,
                json!({
                    "query": "event",
                    "journal_id": journal_id,
                    "journal_sequence": sequence,
                }),
            )?;
            let event_record = store.read(grant, &event_query).map_err(|error| {
                if error.code == "unknown_event" || error.code == "unknown_journal" {
                    fault(
                        "acknowledgement_lost",
                        format!(
                            "acknowledged journal_sequence {sequence} did not survive {trigger}: {}",
                            error.detail
                        ),
                    )
                } else {
                    error
                }
            })?;
            if let Some(expected_id) = entry_map.get("event_id").filter(|v| !is_missing(v)) {
                let expected_text = expected_id.as_str().ok_or_else(|| {
                    fault(
                        "invalid_incident",
                        "incident acknowledged event_id must be a string".to_string(),
                    )
                })?;
                let actual_id = record_value(&event_record)
                    .get("event_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if actual_id != expected_text {
                    return Err(fault(
                        "acknowledgement_lost",
                        format!(
                            "journal_sequence {sequence} event_id mismatch: acknowledged {expected_text:?} but the store holds {actual_id:?}"
                        ),
                    ));
                }
            }
            acknowledged_verified += 1;
        }
    }

    // Proven partitions survive restart and are pinned against refetch.
    let mut proven_ids: Vec<String> = Vec::new();
    let mut proven_out: Vec<Value> = Vec::new();
    if let Some(proven) = established(incident_map, "proven_partitions") {
        let entries = proven.as_array().ok_or_else(|| {
            fault(
                "invalid_incident",
                "incident proven_partitions must be an array".to_string(),
            )
        })?;
        for entry in entries {
            if is_missing(entry) {
                continue;
            }
            let entry_map = entry.as_object().ok_or_else(|| {
                fault(
                    "invalid_incident",
                    "incident proven_partitions entries must be objects".to_string(),
                )
            })?;
            let partition_id = entry_map
                .get("partition_id")
                .filter(|v| !is_missing(v))
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    fault(
                        "invalid_incident",
                        "incident proven_partitions entries require partition_id".to_string(),
                    )
                })?;
            if partition_id.is_empty() {
                return Err(fault(
                    "invalid_incident",
                    "incident proven partition_id must be nonempty".to_string(),
                ));
            }
            if proven_ids.iter().any(|id| id == partition_id) {
                return Err(fault(
                    "invalid_incident",
                    format!("incident proven_partitions repeats partition {partition_id:?}"),
                ));
            }
            let status = entry_map
                .get("status")
                .filter(|v| !is_missing(v))
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    fault(
                        "invalid_incident",
                        format!("proven partition {partition_id:?} requires status"),
                    )
                })?;
            if status != "proven" {
                return Err(fault(
                    "invalid_provenance",
                    format!(
                        "proven_partitions entry {partition_id:?} carries status {status:?}, not proven; incomplete partitions replay through incomplete_packets"
                    ),
                ));
            }
            for key in ["refetch", "fetch", "refetch_partition"] {
                if matches!(
                    entry_map.get(key).filter(|v| !is_missing(v)),
                    Some(Value::Bool(true))
                ) {
                    return Err(fault(
                        "proven_refetch_refused",
                        format!(
                            "proven partition {partition_id:?} must not be refetched merely because {trigger} occurred"
                        ),
                    ));
                }
            }
            proven_ids.push(partition_id.to_string());
            proven_out.push(json!({
                "partition_id": partition_id,
                "status": "proven",
                "refetch": false,
            }));
        }
    }

    // Incomplete packets may replay idempotently through the pipeline gate.
    let mut replayable_out: Vec<Value> = Vec::new();
    if let Some(incomplete) = established(incident_map, "incomplete_packets") {
        let entries = incomplete.as_array().ok_or_else(|| {
            fault(
                "invalid_incident",
                "incident incomplete_packets must be an array".to_string(),
            )
        })?;
        for entry in entries {
            if is_missing(entry) {
                continue;
            }
            let entry_map = entry.as_object().ok_or_else(|| {
                fault(
                    "invalid_incident",
                    "incident incomplete_packets entries must be objects".to_string(),
                )
            })?;
            let packet_id = entry_map
                .get("packet_id")
                .filter(|v| !is_missing(v))
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    fault(
                        "invalid_incident",
                        "incident incomplete_packets entries require packet_id".to_string(),
                    )
                })?;
            if packet_id.is_empty() {
                return Err(fault(
                    "invalid_incident",
                    "incident incomplete packet_id must be nonempty".to_string(),
                ));
            }
            if proven_ids.iter().any(|id| id == packet_id) {
                return Err(fault(
                    "proven_refetch_refused",
                    format!(
                        "packet {packet_id:?} is proven and must not replay as incomplete after {trigger}"
                    ),
                ));
            }
            if let Some(partition) = entry_map
                .get("partition_id")
                .filter(|v| !is_missing(v))
                .and_then(Value::as_str)
            {
                if proven_ids.iter().any(|id| id == partition) {
                    return Err(fault(
                        "proven_refetch_refused",
                        format!(
                            "partition {partition:?} is proven and must not replay as incomplete after {trigger}"
                        ),
                    ));
                }
            }
            if let Some(replay) = entry_map.get("replay").filter(|v| !is_missing(v)) {
                let replay_map = replay.as_object().ok_or_else(|| {
                    fault(
                        "invalid_replay",
                        format!("incomplete packet {packet_id:?} replay must be an object"),
                    )
                })?;
                if replay_map.get("before").filter(|v| !is_missing(v)).is_none()
                    || replay_map
                        .get("transaction")
                        .filter(|v| !is_missing(v))
                        .is_none()
                {
                    return Err(fault(
                        "invalid_replay",
                        format!(
                            "incomplete packet {packet_id:?} replay requires established before and transaction for atomic pipeline validation"
                        ),
                    ));
                }
                let command = validate(OUTPUT_SCHEMA, replay.clone()).map_err(|error| {
                    fault(
                        "invalid_replay",
                        format!("packet {packet_id:?} replay: {}", error.detail),
                    )
                })?;
                let effect = pipeline.advance(grant, &command)?;
                replayable_out.push(json!({
                    "packet_id": packet_id,
                    "replayable": true,
                    "replayed": true,
                    "effect": record_value(&effect).clone(),
                }));
            } else {
                replayable_out.push(json!({
                    "packet_id": packet_id,
                    "replayable": true,
                    "replayed": false,
                    "effect": missing(
                        "not_applicable",
                        "no replay command was supplied; the packet may replay idempotently when its walk resumes",
                    ),
                }));
            }
        }
    }

    // Fenced lease reclamation, delegated so fencing and retry charging stay exact.
    let mut reclaimed_out: Vec<Value> = Vec::new();
    if let Some(leases) = established(incident_map, "leases") {
        let entries = leases.as_array().ok_or_else(|| {
            fault(
                "invalid_incident",
                "incident leases must be an array".to_string(),
            )
        })?;
        for entry in entries {
            if is_missing(entry) {
                continue;
            }
            let entry_map = entry.as_object().ok_or_else(|| {
                fault(
                    "invalid_lease",
                    "incident lease entries must be reclaim request objects".to_string(),
                )
            })?;
            if let Some(row) = entry_map.get("row").filter(|v| !is_missing(v)) {
                if let Some(row_map) = row.as_object() {
                    if let Some(owner) = row_map.get("target").filter(|v| !is_missing(v)) {
                        let owner_text = owner.as_str().ok_or_else(|| {
                            fault(
                                "invalid_lease",
                                "lease row target must be a string".to_string(),
                            )
                        })?;
                        if owner_text != target {
                            return Err(fault(
                                "cross_target_refused",
                                format!(
                                    "recovery for target {target:?} refuses the lease for sibling target {owner_text:?}; one target's failure never reclaims another's generation"
                                ),
                            ));
                        }
                    }
                }
            }
            let request = validate(OUTPUT_SCHEMA, entry.clone()).map_err(|error| {
                fault("invalid_lease", format!("lease request: {}", error.detail))
            })?;
            let result = reclaim(store, clock, grant, &request)?;
            reclaimed_out.push(record_value(&result).clone());
        }
    }

    // Session recovery establishes a new epoch with a fresh client.
    let mut sessions_out: Vec<Value> = Vec::new();
    if let Some(listed) = established(incident_map, "sessions") {
        let entries = listed.as_array().ok_or_else(|| {
            fault(
                "invalid_incident",
                "incident sessions must be an array".to_string(),
            )
        })?;
        for (index, entry) in entries.iter().enumerate() {
            if is_missing(entry) {
                continue;
            }
            let entry_map = entry.as_object().ok_or_else(|| {
                fault(
                    "invalid_session",
                    "incident session entries must be establish request objects".to_string(),
                )
            })?;
            if let Some(session_target) = session_target_of(entry_map)? {
                if session_target != target {
                    return Err(fault(
                        "cross_target_refused",
                        format!(
                            "recovery for target {target:?} refuses the session for sibling target {session_target:?}; one target's handoff never retires another's generation"
                        ),
                    ));
                }
            }
            let request = validate(OUTPUT_SCHEMA, entry.clone()).map_err(|error| {
                fault("invalid_session", format!("session request: {}", error.detail))
            })?;
            let scope = validate(
                OUTPUT_SCHEMA,
                json!({
                    "scope_id": format!("{incident_id}-session-{index}"),
                    "target": target,
                }),
            )?;
            let credit = admission.reserve_control(&scope)?;
            let live = sessions.establish(grant, &request, &credit)?;
            sessions_out.push(record_value(&live.generation).clone());
        }
    }

    // Archive roots expand to their exact complete rows from immutable extents.
    let mut archives_out: Vec<Value> = Vec::new();
    if let Some(roots) = established(incident_map, "archive_roots") {
        let entries = roots.as_array().ok_or_else(|| {
            fault(
                "invalid_incident",
                "incident archive_roots must be an array".to_string(),
            )
        })?;
        for entry in entries {
            if is_missing(entry) {
                continue;
            }
            let root = validate(OUTPUT_SCHEMA, entry.clone()).map_err(|error| {
                fault(
                    "invalid_archive",
                    format!("archive root: {}", error.detail),
                )
            })?;
            let row = expand_archive(artifacts, grant, &root)?;
            archives_out.push(record_value(&row).clone());
        }
    }

    validate(
        OUTPUT_SCHEMA,
        json!({
            "record_type": "recovery_receipt",
            "incident_id": incident_id,
            "journal_id": journal_id,
            "trigger": trigger,
            "target": target,
            "recovered_at": now_value,
            "survived_prefix": {"last_sequence": last_sequence, "head_hash": head_hash},
            "acknowledged_verified": acknowledged_verified,
            "proven": proven_out,
            "replayable": replayable_out,
            "reclaimed": reclaimed_out,
            "sessions": sessions_out,
            "archives": archives_out,
            "isolation": {"target": target, "cross_target_refused": true},
            "durable": true,
        }),
    )
}

//! `crawler_retention`: retention pins, evidenced release, and fenced GC.
//!
//! Implements §20.6 **Retention** ([OWD-RETENTION]) for the crawler archive
//! seam:
//!
//! * [`plan_retention_pin`] builds the initial active `RetentionPinRevision`
//!   for a dependent root and its complete immutable dependency closure.
//!   Dependent and archive identity are fixed under the pin; the returned
//!   record never mutates them.
//! * [`release_pin`] releases exactly one root after journaled evidence of its
//!   retirement. The release is appended to the owner journal before the
//!   released revision is returned; identities are never rewritten, release is
//!   terminal, and every other root keeps its own protection.
//! * [`collect_unreachable`] reclaims only artifact bytes that no active pin
//!   and no retained earlier archive reaches, transitively through pinned
//!   archive roots and their dependency closures. The reachability snapshot is
//!   fenced against the owner's journal prefix: a pin created after the fence
//!   invalidates the plan instead of racing the deletion. TTLs, cache
//!   evictions, and newer publication revisions are never authority to
//!   release or delete; unavailable bytes are an integrity fault, never a
//!   successful collection.
//!
//! Retention state is authoritative in the owner journal: pins and releases
//! are journaled `archive_retention_pin` records. This module reads them back
//! through [`OwnerStore`] (never a caller-supplied substitute registry), writes
//! owner-local release evidence through that same store, and deletes bytes only
//! through [`ArtifactStore::delete`] under a current GC certificate.
//!
//! A pin's archive root and the whole immutable dependency closure supplied to
//! [`plan_retention_pin`] stay protected while any root reaches them.
//! Reachability is transitive in both directions of retention history: a
//! retained later archive protects the earlier archive named by its backward
//! link, and the earlier archive's own pinned dependencies remain protected
//! with it. Released pins stay journaled as history and keep contributing their
//! dependency edges whenever a reachable archive root is reached through them.

use crawler_artifacts::ArtifactStore;
use crawler_authority::{grant_record, Grant};
use crawler_schema::{record_value, validate, CheckedRecord, Fault};
use crawler_store::OwnerStore;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

/// Structural envelope for records produced by this module.
const OUTPUT_SCHEMA: &str = "audit_log";

/// Contract schema version stamped on retention records.
const SCHEMA_VERSION: &str = "owner-separated-write-domains/0.1.0";

const PIN_RECORD: &str = "archive_retention_pin";
const JOURNAL_VIEW: &str = "journal_view";
const JOURNAL_PREFIX: &str = "journal_prefix";
const GC_CERTIFICATE: &str = "retention_gc_certificate";
const GC_RESULT: &str = "retention_gc_result";

/// Retention dependent kinds (Contract 04 `RetentionDependent.kind`).
const RETAINED_KINDS: &[&str] = &["live_replacement", "retained_archive", "retained_evidence"];

/// Pin states (Contract 04 `RetentionPinRevision.state`).
const PIN_STATES: &[&str] = &["active", "released"];

/// Fields that are policy, never retention authority.
const RETENTION_SHORTCUTS: &[&str] = &[
    "ttl",
    "ttl_seconds",
    "ttl_ms",
    "expires_at",
    "expired",
    "max_age_seconds",
    "cache_eviction",
    "cache_evicted",
    "eviction",
    "newer_revision",
    "newer_publication",
    "latest_revision",
    "publication_revision",
];

// ---------------------------------------------------------------------------
// Public interface
// ---------------------------------------------------------------------------

/// Plan the initial active retention pin for one dependent root.
///
/// `dependent` is a `RetentionDependent` (`entity`, `kind`, `root_id`);
/// `archive_root` is the `ArtifactReference` of the archive whose bytes the
/// root needs; `dependencies` is the complete immutable dependency closure of
/// that archive (each an `ArtifactReference`). The archived content must be
/// installed before this plan is committed, but planning itself performs no
/// IO: it fixes identity and closure so the caller can commit the pin in the
/// same owner-local transaction as the replacement effect.
///
/// The result is a `RetentionPinRevision` with `revision: 1`,
/// `previous_revision: 0`, `state: "active"`, an Inapplicable `release_ref`,
/// a deterministic `pin_id`, and both the archive root and the sorted,
/// de-duplicated closure in `dependencies`. The closure travels with the
/// revision because a planned pin must name the exact immutable extents it
/// protects; later releases re-emit the union of every revision's closure and
/// can never shrink it. Owners/writers are fixed facts of the pin, never
/// caller-selected per release. `writer_id` comes from the dependent (or
/// archive root) context when supplied; otherwise it names the archive
/// persistence domain's registered retention authority.
/// `evidence_prefix`/`evidence_refs` come from the caller's context when
/// supplied and otherwise stay typed `Missing` until the commit establishes
/// them.
///
/// Faults: `invalid_dependent`, `missing_dependent_kind`,
/// `invalid_dependent_kind`, `missing_root_id`, `missing_entity`,
/// `invalid_archive_root`, `invalid_dependency`, `self_dependency`,
/// `dependency_conflict`, `invalid_writer`, `invalid_evidence_prefix`,
/// `invalid_evidence_ref`.
pub fn plan_retention_pin(
    dependent: &CheckedRecord,
    archive_root: &CheckedRecord,
    dependencies: &[CheckedRecord],
) -> Result<CheckedRecord, Fault> {
    let dependent_map = as_object(dependent, "invalid_dependent", "dependent")?;
    let dependent_identity = dependent_identity(record_value(dependent), "invalid_dependent", "dependent")?;
    let archive = reference_parts(
        record_value(archive_root),
        false,
        "invalid_archive_root",
        "archive_root",
    )?;
    let archive_map = record_value(archive_root)
        .as_object()
        .ok_or_else(|| fault("invalid_archive_root", "archive_root must be a JSON object".to_string()))?;

    let mut closure: BTreeMap<String, Reference> = BTreeMap::new();
    for (index, dependency) in dependencies.iter().enumerate() {
        let what = format!("dependencies[{index}]");
        let parts = reference_parts(record_value(dependency), false, "invalid_dependency", &what)?;
        if parts.digest == archive.digest {
            return Err(fault(
                "self_dependency",
                format!(
                    "archive root {} is also listed as its own dependency; a closure names immutable extents, never a self-cycle",
                    archive.digest
                ),
            ));
        }
        if let Some(previous) = closure.get(&parts.digest) {
            if previous.size_bytes != parts.size_bytes
                || previous.media_type != parts.media_type
                || previous.owner_domain != parts.owner_domain
                || previous.access != parts.access
            {
                return Err(fault(
                    "dependency_conflict",
                    format!(
                        "dependency digest {} is named with conflicting immutable metadata in one plan",
                        parts.digest
                    ),
                ));
            }
        } else {
            closure.insert(parts.digest.clone(), parts);
        }
    }

    let writer_id = match established(dependent_map, "writer_id") {
        Some(Value::String(text)) if !text.is_empty() => text.clone(),
        Some(_) => {
            return Err(fault(
                "invalid_writer",
                "dependent writer_id must be a nonempty string when established".to_string(),
            ))
        }
        None => match established(archive_map, "writer_id") {
            Some(Value::String(text)) if !text.is_empty() => text.clone(),
            Some(_) => {
                return Err(fault(
                    "invalid_writer",
                    "archive_root writer_id must be a nonempty string when established".to_string(),
                ))
            }
            None => format!("{}:retention-authority", archive.owner_domain),
        },
    };

    let evidence_prefix = match context_evidence_prefix(dependent_map, archive_map)? {
        Some(prefix) => prefix.to_value(),
        None => missing(
            "not_observed",
            "the commit establishes the evidence prefix; planning is not an acknowledgement",
        ),
    };
    let evidence_refs = match context_evidence_refs(dependent_map, archive_map)? {
        Some(refs) => Value::Array(refs),
        None => json!([]),
    };

    let root_id = dependent_identity
        .get("root_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let pin_id = format!("pin:{}:{}", root_id, &archive.digest[..24]);
    let closure_values: Vec<Value> = closure.values().map(|entry| entry.value.clone()).collect();
    let closure_digests: Vec<String> = closure.keys().cloned().collect();

    validate(
        OUTPUT_SCHEMA,
        json!({
            "record_type": PIN_RECORD,
            "schema_version": SCHEMA_VERSION,
            "pin_id": pin_id,
            "owner_domain": archive.owner_domain,
            "writer_id": writer_id,
            "revision": 1,
            "previous_revision": 0,
            "dependent": dependent_identity,
            "archive_root": archive.value,
            "state": "active",
            "release_ref": missing(
                "not_applicable",
                "an active pin has not been released; release requires evidenced retirement later",
            ),
            "evidence_prefix": evidence_prefix,
            "evidence_refs": evidence_refs,
            "dependencies": closure_values,
            "support": {
                "dependency_digests": closure_digests,
                "reachability": "transitive",
            },
        }),
    )
}

/// Release one active pin after evidenced retirement of its dependent root.
///
/// The request names `journal_id` (or the pin/evidence supplies it), the
/// current active `pin`, and a `retirement` object
/// (`{root_id, retired: true, evidence_refs: [EvidenceRef...]}`). Every cited
/// evidence reference must already resolve in the same journal prefix, and the
/// evidence must record the retirement of exactly this pin's dependent root.
///
/// The pin is looked up in the owner journal, never trusted from the request:
/// an unknown pin, a stale revision, a mutated `dependent`/`archive_root`, or
/// an already released pin is refused. The grant must belong to the pin's own
/// persistence domain. A new `released` revision is appended to the owner
/// journal before this function returns; its `release_ref` names that event and
/// its `evidence_prefix` is the resulting prefix. Other pins are untouched, and
/// release never rewrites archived content.
///
/// Faults: `invalid_request`, `retention_policy_not_authority`, `invalid_pin`,
/// `missing_pin`, `pin_not_active`, `missing_retirement`,
/// `missing_retirement_root`, `retirement_not_evidenced`,
/// `missing_release_evidence`, `release_without_evidence`,
/// `invalid_release_evidence`, `missing_journal_id`,
/// `mixed_evidence_journals`, `invalid_grant`, `grant_without_owner`,
/// `owner_mismatch`, `missing_producer_grant`, `missing_grant_event_kind`,
/// `unknown_pin`, `pin_identity_mutation`, `pin_not_current`,
/// `retirement_root_mismatch`, `foreign_evidence_ref`, `unknown_evidence_ref`,
/// `evidence_mismatch`, `invalid_journal_view`, `foreign_owner`,
/// `release_not_durable`, `invalid_release_receipt`.
pub fn release_pin(
    store: &dyn OwnerStore,
    grant: &Grant,
    request: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let request_map = as_object(request, "invalid_request", "request")?;
    reject_retention_shortcuts(request_map, "release request")?;

    let pin_value = match established(request_map, "pin") {
        Some(value @ Value::Object(_)) => value,
        Some(_) => return Err(fault("invalid_pin", "request pin must be an object".to_string())),
        None => {
            return Err(fault(
                "missing_pin",
                "release requires the current pin revision; an identity alone is not a pin".to_string(),
            ))
        }
    };
    let request_pin = parse_pin(pin_value)?;
    if request_pin.state != "active" {
        return Err(fault(
            "pin_not_active",
            format!(
                "pin {:?} is {}; only an active pin has protection to release and a released pin is terminal",
                request_pin.pin_id, request_pin.state
            ),
        ));
    }

    let retirement = match established(request_map, "retirement") {
        Some(Value::Object(map)) => map,
        Some(_) => {
            return Err(fault(
                "missing_retirement",
                "retirement must be an object carrying root_id, retired, and evidence".to_string(),
            ))
        }
        None => {
            return Err(fault(
                "missing_retirement",
                "release requires evidenced retirement of the pin's dependent root".to_string(),
            ))
        }
    };
    let retirement_root = required_str(retirement, "root_id", "missing_retirement_root", "retirement")?.to_string();
    match established(retirement, "retired") {
        Some(Value::Bool(true)) => {}
        _ => {
            return Err(fault(
                "retirement_not_evidenced",
                "retirement requires retired: true; release is never inferred from TTL, eviction, or a newer revision"
                    .to_string(),
            ))
        }
    }
    let evidence_values = match established_array(retirement, "evidence_refs", "missing_release_evidence", "retirement")? {
        Some(items) if !items.is_empty() => items.clone(),
        _ => {
            return Err(fault(
                "release_without_evidence",
                "release requires at least one journaled EvidenceRef proving the root retired".to_string(),
            ))
        }
    };
    let evidence_refs: Vec<EvidenceRef> = evidence_values
        .iter()
        .map(|value| evidence_ref_parts(value, "invalid_release_evidence"))
        .collect::<Result<_, _>>()?;

    let journal_id = resolve_journal_id(request_map, &request_pin, &evidence_refs)?;

    let grant_map = as_object(grant_record(grant), "invalid_grant", "grant")?;
    let grant_owner = required_str(grant_map, "owner_domain", "grant_without_owner", "grant")?;
    if grant_owner != request_pin.owner_domain {
        return Err(fault(
            "owner_mismatch",
            format!(
                "grant belongs to {grant_owner:?} but pin {:?} is owned by {:?}; release never crosses the persistence domain",
                request_pin.pin_id, request_pin.owner_domain
            ),
        ));
    }
    let producer_id = required_str(grant_map, "producer_id", "missing_producer_grant", "grant")?;
    let manifest_digest = required_str(grant_map, "manifest_digest", "missing_producer_grant", "grant")?;
    let event_kind = required_str(grant_map, "event_kind", "missing_grant_event_kind", "grant")?;

    let snapshot = read_journal(store, grant, &journal_id)?;
    if snapshot.owner_domain != grant_owner {
        return Err(fault(
            "foreign_owner",
            format!(
                "journal {journal_id:?} belongs to {:?}, not the grant's {grant_owner:?}",
                snapshot.owner_domain
            ),
        ));
    }
    let pins = pins_from_journal(&snapshot)?;
    let state = pins.get(&request_pin.pin_id).ok_or_else(|| {
        fault(
            "unknown_pin",
            format!(
                "pin {:?} is not journaled in {:?}; an uncommitted plan has no protection to release",
                request_pin.pin_id, journal_id
            ),
        )
    })?;
    if state.owner_domain != request_pin.owner_domain
        || state.dependent_identity != request_pin.dependent_identity
        || state.archive_identity != request_pin.archive_identity
    {
        return Err(fault(
            "pin_identity_mutation",
            format!(
                "pin {:?} fixes dependent and archive identity; a release never rewrites them",
                request_pin.pin_id
            ),
        ));
    }
    if state.revision != request_pin.revision {
        return Err(fault(
            "pin_not_current",
            format!(
                "request pin revision {} is not the journaled current revision {}; release is planned from the current revision",
                request_pin.revision, state.revision
            ),
        ));
    }
    if state.state != "active" {
        return Err(fault(
            "pin_not_active",
            format!("pin {:?} is already released; release is terminal", request_pin.pin_id),
        ));
    }
    let dependent_root = state
        .dependent_identity
        .get("root_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if dependent_root != retirement_root {
        return Err(fault(
            "retirement_root_mismatch",
            format!(
                "retirement names root {retirement_root:?} but pin {:?} protects {dependent_root:?}; unrelated evidence releases nothing",
                request_pin.pin_id
            ),
        ));
    }
    for reference in &evidence_refs {
        let event = resolve_evidence(&snapshot, reference)?;
        if !evidences_retirement(event, dependent_root) {
            return Err(fault(
                "retirement_not_evidenced",
                format!(
                    "evidence {}#{} does not record retirement of {dependent_root:?}; support must prove the root retired",
                    reference.journal_id, reference.sequence
                ),
            ));
        }
    }

    let latest = state
        .latest
        .as_object()
        .ok_or_else(|| fault("invalid_pin", "journaled pin revision must be an object".to_string()))?;
    let writer_id = match established(latest, "writer_id") {
        Some(Value::String(text)) if !text.is_empty() => text.clone(),
        _ => request_pin.writer_id.clone(),
    };
    let journaled_dependent = latest
        .get("dependent")
        .filter(|value| !is_missing(value))
        .cloned()
        .ok_or_else(|| fault("invalid_pin", "journaled pin is missing its dependent identity".to_string()))?;
    let journaled_root = latest
        .get("archive_root")
        .filter(|value| !is_missing(value))
        .cloned()
        .ok_or_else(|| fault("invalid_pin", "journaled pin is missing its archive root".to_string()))?;
    let dependencies: Vec<Value> = state.dependencies.values().cloned().collect();

    let released_for_journal = validate(
        OUTPUT_SCHEMA,
        json!({
            "record_type": PIN_RECORD,
            "schema_version": SCHEMA_VERSION,
            "pin_id": state.pin_id,
            "owner_domain": state.owner_domain,
            "writer_id": writer_id,
            "revision": state.revision + 1,
            "previous_revision": state.revision,
            "dependent": journaled_dependent,
            "archive_root": journaled_root,
            "state": "released",
            "release_ref": missing(
                "not_observed",
                "the release reference is the journal event carrying this revision",
            ),
            "evidence_prefix": missing(
                "not_observed",
                "the carrying journal event establishes the evidence prefix",
            ),
            "evidence_refs": Value::Array(evidence_values.clone()),
            "dependencies": dependencies,
        }),
    )?;

    let transaction = validate(
        OUTPUT_SCHEMA,
        json!({
            "operation": "append_event",
            "journal_id": journal_id,
            "principal": {
                "producer_id": producer_id,
                "manifest_digest": manifest_digest,
            },
            "submission": {
                "producer_sequence": missing(
                    "not_applicable",
                    "an owner-authored release has no producer sequence",
                ),
                "event_kind": event_kind,
                "event_schema_version": SCHEMA_VERSION,
                "occurred_at": missing(
                    "not_observed",
                    "release is an owner effect without a source occurrence",
                ),
                "payload": {
                    "data": {
                        "retention_pin": record_value(&released_for_journal).clone(),
                        "retirement": Value::Object(retirement.clone()),
                    },
                    "measurements": [],
                    "evidence_refs": Value::Array(evidence_values.clone()),
                    "artifact_refs": [],
                },
            },
            "causal_refs": Value::Array(evidence_values.clone()),
        }),
    )?;

    let receipt = store.transact(grant, &transaction)?;
    let receipt_map = as_object(&receipt, "invalid_release_receipt", "receipt")?;
    match established(receipt_map, "durable") {
        Some(Value::Bool(true)) => {}
        _ => {
            return Err(fault(
                "release_not_durable",
                "release was not acknowledged as durable; protection is not released before durability"
                    .to_string(),
            ))
        }
    }
    let sequence = required_u64(receipt_map, "journal_sequence", "invalid_release_receipt", "receipt")?;
    let event_hash = required_str(receipt_map, "event_hash", "invalid_release_receipt", "receipt")?;
    if !is_digest_text(event_hash) {
        return Err(fault(
            "invalid_release_receipt",
            "receipt event_hash must be 64 lowercase hex characters".to_string(),
        ));
    }
    let head_hash = required_str(receipt_map, "head_hash", "invalid_release_receipt", "receipt")?;
    if !is_digest_text(head_hash) {
        return Err(fault(
            "invalid_release_receipt",
            "receipt head_hash must be 64 lowercase hex characters".to_string(),
        ));
    }
    let receipt_event = receipt_map
        .get("event")
        .and_then(Value::as_object)
        .ok_or_else(|| fault("invalid_release_receipt", "receipt requires the sealed event".to_string()))?;
    let event_id = required_str(receipt_event, "event_id", "invalid_release_receipt", "receipt event")?;

    let mut released = record_value(&released_for_journal)
        .as_object()
        .cloned()
        .ok_or_else(|| fault("invalid_pin", "released pin must be an object".to_string()))?;
    released.insert(
        "release_ref".to_string(),
        json!({
            "journal_id": journal_id,
            "sequence": sequence,
            "event_id": event_id,
            "event_hash": event_hash,
            "pointer": "/payload/data/retention_pin",
        }),
    );
    released.insert(
        "evidence_prefix".to_string(),
        json!({
            "journal_id": journal_id,
            "last_sequence": sequence,
            "head_hash": head_hash,
        }),
    );
    validate(OUTPUT_SCHEMA, Value::Object(released))
}

/// Collect artifact bytes that no retention root reaches.
///
/// The request names `journal_id`, the `fence` (a `JournalPrefix` observed when
/// the collection was planned), and `candidates` (complete `ArtifactReference`
/// records to reclaim). Reachability is computed from the owner journal, not
/// from the request: an active pin protects its archive root and the whole
/// pinned dependency closure, and any retained archive whose root is reached
/// keeps protecting its own closure. Released pins are history; they protect
/// nothing by themselves but keep their dependency edges available while their
/// archive root is reached through another root.
///
/// The plan is fenced: the request fence must equal the owner journal prefix at
/// the reachability snapshot, and the prefix is verified again immediately
/// before the first deletion. A pin journaled after the snapshot advances the
/// prefix and the whole plan is refused with `gc_fence_stale`, never raced.
/// Bytes are deleted only through [`ArtifactStore::delete`] with a `collect`
/// certificate naming the grant binding, owner domain, reachability snapshot,
/// and fence. Unavailable bytes are reported as an integrity fault, never as
/// successful GC, and protected candidates are returned untouched.
///
/// Faults: `invalid_request`, `retention_policy_not_authority`,
/// `missing_journal_id`, `gc_fence_required`, `invalid_fence`,
/// `missing_candidates`, `invalid_candidate`, `candidate_conflict`,
/// `invalid_grant`, `grant_without_owner`, `invalid_journal_view`,
/// `foreign_owner`, `gc_fence_stale`, `invalid_pin`,
/// `pin_identity_mutation`, `retention_integrity`, plus the artifact store's
/// authorization and integrity faults.
pub fn collect_unreachable(
    store: &dyn OwnerStore,
    artifacts: &dyn ArtifactStore,
    grant: &Grant,
    request: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let request_map = as_object(request, "invalid_request", "request")?;
    reject_retention_shortcuts(request_map, "GC request")?;
    let journal_id = required_str(request_map, "journal_id", "missing_journal_id", "request")?.to_string();
    let fence = match request_map.get("fence") {
        Some(value) if !is_missing(value) => parse_prefix_value(value, "invalid_fence")?,
        _ => {
            return Err(fault(
                "gc_fence_required",
                "collection requires the JournalPrefix it was planned against; deletion after an unfenced reachability check races pin creation"
                    .to_string(),
            ))
        }
    };
    if fence.journal_id != journal_id {
        return Err(fault(
            "gc_fence_stale",
            format!(
                "fence names journal {:?}, not {journal_id:?}; the reachability plan does not describe this journal",
                fence.journal_id
            ),
        ));
    }
    let candidate_values = match established_array(request_map, "candidates", "missing_candidates", "request")? {
        Some(items) => items.clone(),
        None => {
            return Err(fault(
                "missing_candidates",
                "collection requires an established candidates array; empty is an explicit empty collection"
                    .to_string(),
            ))
        }
    };
    let mut candidates: BTreeMap<String, Reference> = BTreeMap::new();
    for (index, candidate) in candidate_values.iter().enumerate() {
        let what = format!("candidates[{index}]");
        let parts = reference_parts(candidate, true, "invalid_candidate", &what)?;
        if let Some(previous) = candidates.get(&parts.digest) {
            if previous.size_bytes != parts.size_bytes
                || previous.media_type != parts.media_type
                || previous.owner_domain != parts.owner_domain
                || previous.access != parts.access
            {
                return Err(fault(
                    "candidate_conflict",
                    format!(
                        "candidate digest {} is named with conflicting immutable metadata in one collection",
                        parts.digest
                    ),
                ));
            }
        } else {
            candidates.insert(parts.digest.clone(), parts);
        }
    }

    let grant_map = as_object(grant_record(grant), "invalid_grant", "grant")?;
    let grant_owner = required_str(grant_map, "owner_domain", "grant_without_owner", "grant")?;

    let snapshot = read_journal(store, grant, &journal_id)?;
    if snapshot.owner_domain != grant_owner {
        return Err(fault(
            "foreign_owner",
            format!(
                "journal {journal_id:?} belongs to {:?}, not the grant's {grant_owner:?}",
                snapshot.owner_domain
            ),
        ));
    }
    if snapshot.last_sequence != fence.last_sequence || snapshot.head_hash != fence.head_hash {
        return Err(fault(
            "gc_fence_stale",
            format!(
                "fence is {}#{}, but the journal prefix is {}#{}; protection changed after the plan",
                fence.last_sequence, fence.head_hash, snapshot.last_sequence, snapshot.head_hash
            ),
        ));
    }

    let pins = pins_from_journal(&snapshot)?;
    for pin in pins.values() {
        if pin.owner_domain != snapshot.owner_domain {
            return Err(fault(
                "foreign_owner",
                format!(
                    "pin {:?} is owned by {:?} inside journal {:?}; retention pins never cross the persistence domain",
                    pin.pin_id, pin.owner_domain, journal_id
                ),
            ));
        }
    }
    for candidate in candidates.values() {
        if candidate.owner_domain != snapshot.owner_domain {
            return Err(fault(
                "foreign_owner",
                format!(
                    "candidate {} is owned by {:?}, not the journal's {:?}; GC never crosses the persistence domain",
                    candidate.digest, candidate.owner_domain, snapshot.owner_domain
                ),
            ));
        }
        if candidate.grant_digest.is_none() || candidate.provenance.is_none() {
            return Err(fault(
                "invalid_candidate",
                format!(
                    "candidate {} must carry the grant binding and provenance of its registered artifact reference",
                    candidate.digest
                ),
            ));
        }
    }

    let reachable = reachable_digests(&pins);
    let pin_rows: Vec<Value> = pins
        .values()
        .map(|pin| {
            json!({
                "pin_id": pin.pin_id,
                "revision": pin.revision,
                "state": pin.state,
                "archive_digest": pin.archive_digest,
                "dependent_root": pin.dependent_identity.get("root_id").cloned().unwrap_or_else(|| missing(
                    "not_observed",
                    "journaled pin dependent identity carries no root id",
                )),
                "dependencies": pin.dependencies.keys().cloned().collect::<Vec<_>>(),
            })
        })
        .collect();

    let mut protected: Vec<Value> = Vec::new();
    let mut to_collect: Vec<Reference> = Vec::new();
    for candidate in candidates.into_values() {
        if reachable.contains(&candidate.digest) {
            protected.push(candidate.value.clone());
        } else {
            to_collect.push(candidate);
        }
    }

    if !to_collect.is_empty() {
        let current = read_prefix(store, grant, &journal_id)?;
        if current.last_sequence != fence.last_sequence || current.head_hash != fence.head_hash {
            return Err(fault(
                "gc_fence_stale",
                format!(
                    "journal prefix advanced from {}#{} to {}#{} after the reachability snapshot; a pin created concurrently protects bytes an unfenced check would have reclaimed",
                    fence.last_sequence, fence.head_hash, current.last_sequence, current.head_hash
                ),
            ));
        }
    }

    let reachable_values: Vec<String> = reachable.iter().cloned().collect();
    let pin_ids: Vec<String> = pins.keys().cloned().collect();
    let mut collected: Vec<Value> = Vec::new();
    for candidate in &to_collect {
        let grant_digest = candidate.grant_digest.clone().ok_or_else(|| {
            fault(
                "invalid_candidate",
                format!(
                    "candidate {} has no grant binding; collection is never bearer-authorised",
                    candidate.digest
                ),
            )
        })?;
        let certificate = validate(
            OUTPUT_SCHEMA,
            json!({
                "record_type": GC_CERTIFICATE,
                "schema_version": SCHEMA_VERSION,
                "journal_id": journal_id,
                "digest": candidate.digest,
                "grant_digest": grant_digest,
                "owner_domain": candidate.owner_domain,
                "decision": "collect",
                "fence": fence.head_hash,
                "fence_sequence": fence.last_sequence,
                "reachable_digests": reachable_values,
                "pin_ids": pin_ids,
                "policy": {
                    "reachability": "transitive",
                    "ttl": "never_authorizes_collection",
                    "cache_eviction": "never_authorizes_collection",
                    "newer_revision": "never_authorizes_collection",
                },
            }),
        )?;
        let reference = validate(OUTPUT_SCHEMA, candidate.value.clone())?;
        match artifacts.delete(grant, &reference, &certificate) {
            Ok(()) => collected.push(candidate.value.clone()),
            Err(err) => {
                let collected_digests: Vec<&str> = collected
                    .iter()
                    .filter_map(|value| value.get("digest").and_then(Value::as_str))
                    .collect();
                let detail = format!(
                    "candidate {} could not be collected: {}: {}; lost bytes are an integrity incident, never successful GC or permission to reconstruct different content{}",
                    candidate.digest,
                    err.code,
                    err.detail,
                    if collected_digests.is_empty() {
                        String::new()
                    } else {
                        format!(" (collected before the failure: {collected_digests:?})")
                    }
                );
                return Err(fault(&err.code, detail));
            }
        }
    }

    validate(
        OUTPUT_SCHEMA,
        json!({
            "record_type": GC_RESULT,
            "schema_version": SCHEMA_VERSION,
            "journal_id": snapshot.journal_id,
            "fence": fence.to_value(),
            "collected": collected,
            "protected": protected,
            "pins": pin_rows,
            "policy": {
                "reachability": "transitive",
                "release": "requires_evidenced_retirement",
                "ttl": "never_authorizes_collection",
                "cache_eviction": "never_authorizes_collection",
                "newer_revision": "never_authorizes_collection",
            },
        }),
    )
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

fn fault(code: &str, detail: String) -> Fault {
    Fault {
        code: code.to_string(),
        detail,
    }
}

fn is_missing(value: &Value) -> bool {
    value
        .as_object()
        .is_some_and(|map| map.get("value").is_some_and(Value::is_null))
}

fn established<'a>(map: &'a Map<String, Value>, field: &str) -> Option<&'a Value> {
    map.get(field).filter(|value| !is_missing(value))
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

fn required_str<'a>(
    map: &'a Map<String, Value>,
    field: &str,
    code: &str,
    what: &str,
) -> Result<&'a str, Fault> {
    match established(map, field) {
        Some(Value::String(text)) if !text.is_empty() => Ok(text.as_str()),
        Some(_) => Err(fault(
            code,
            format!("{what} {field:?} must be a nonempty established string"),
        )),
        None => Err(fault(
            code,
            format!("{what} requires an established {field:?}"),
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
                format!("{what} {field:?} must be an unsigned integer"),
            )
        }),
        Some(_) => Err(fault(
            code,
            format!("{what} {field:?} must be an unsigned integer"),
        )),
        None => Err(fault(
            code,
            format!("{what} requires an established {field:?}"),
        )),
    }
}

fn established_array<'a>(
    map: &'a Map<String, Value>,
    field: &str,
    code: &str,
    what: &str,
) -> Result<Option<&'a Vec<Value>>, Fault> {
    match map.get(field) {
        None => Ok(None),
        Some(value) if is_missing(value) => Ok(None),
        Some(Value::Array(items)) => Ok(Some(items)),
        Some(_) => Err(fault(
            code,
            format!("{what} {field:?} must be an array or a Missing envelope"),
        )),
    }
}

fn missing(reason: &str, detail: &str) -> Value {
    json!({"value": Value::Null, "reason": reason, "detail": detail})
}

fn is_digest_text(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
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

fn reject_retention_shortcuts(map: &Map<String, Value>, what: &str) -> Result<(), Fault> {
    for field in RETENTION_SHORTCUTS {
        if established(map, field).is_some() {
            return Err(fault(
                "retention_policy_not_authority",
                format!(
                    "{what} carries {field:?}; TTL, cache eviction, and newer publication revisions never release retention. Release requires evidenced retirement and GC requires a current reachability fence"
                ),
            ));
        }
    }
    Ok(())
}

/// One validated `ArtifactReference`.
struct Reference {
    value: Value,
    digest: String,
    size_bytes: u64,
    media_type: String,
    owner_domain: String,
    access: String,
    grant_digest: Option<String>,
    provenance: Option<String>,
}

impl Reference {
    fn identity(&self) -> Value {
        json!({
            "digest": self.digest,
            "size_bytes": self.size_bytes,
            "media_type": self.media_type,
            "owner_domain": self.owner_domain,
            "access": self.access,
        })
    }
}

fn reference_parts(
    value: &Value,
    require_binding: bool,
    code: &str,
    what: &str,
) -> Result<Reference, Fault> {
    let map = value
        .as_object()
        .ok_or_else(|| fault(code, format!("{what} must be a JSON object")))?;
    let digest = match established(map, "digest") {
        Some(Value::String(text)) if is_digest_text(text) => text.clone(),
        Some(_) => {
            return Err(fault(
                code,
                format!("{what} digest must be 64 lowercase hex characters"),
            ))
        }
        None => {
            return Err(fault(
                code,
                format!("{what} requires an established digest"),
            ))
        }
    };
    let size_bytes = match established(map, "size_bytes") {
        Some(Value::Number(number)) => number.as_u64().ok_or_else(|| {
            fault(
                code,
                format!("{what} size_bytes must be an unsigned integer"),
            )
        })?,
        Some(_) => {
            return Err(fault(
                code,
                format!("{what} size_bytes must be an unsigned integer"),
            ))
        }
        None => {
            return Err(fault(
                code,
                format!("{what} requires an established size_bytes"),
            ))
        }
    };
    let media_type = required_str(map, "media_type", code, what)?.to_string();
    let owner_domain = required_str(map, "owner_domain", code, what)?.to_string();
    let access = match established(map, "access") {
        Some(Value::String(text)) if text == "public" || text == "restricted" => text.clone(),
        _ => {
            return Err(fault(
                code,
                format!("{what} requires access of public or restricted"),
            ))
        }
    };
    let grant_digest = match established(map, "grant_digest") {
        Some(Value::String(text)) if is_digest_text(text) => Some(text.clone()),
        Some(_) => {
            return Err(fault(
                code,
                format!("{what} grant_digest must be 64 lowercase hex characters"),
            ))
        }
        None if require_binding => {
            return Err(fault(
                code,
                format!(
                    "{what} requires the grant binding under which it was registered; a digest alone is not bearer authority"
                ),
            ))
        }
        None => None,
    };
    let provenance = match established(map, "provenance") {
        Some(Value::String(text)) if !text.is_empty() => Some(text.clone()),
        Some(_) => {
            return Err(fault(
                code,
                format!("{what} provenance must be a nonempty string"),
            ))
        }
        None if require_binding => {
            return Err(fault(
                code,
                format!("{what} requires its registered provenance"),
            ))
        }
        None => None,
    };
    Ok(Reference {
        value: value.clone(),
        digest,
        size_bytes,
        media_type,
        owner_domain,
        access,
        grant_digest,
        provenance,
    })
}

/// `RetentionDependent` identity: entity, kind, and stable root identity.
fn dependent_identity(value: &Value, code: &str, what: &str) -> Result<Value, Fault> {
    let map = value
        .as_object()
        .ok_or_else(|| fault(code, format!("{what} must be a JSON object")))?;
    let kind = required_str(map, "kind", "missing_dependent_kind", what)?;
    if !RETAINED_KINDS.contains(&kind) {
        return Err(fault(
            "invalid_dependent_kind",
            format!(
                "{what} kind {kind:?} is not one of live_replacement, retained_archive, or retained_evidence"
            ),
        ));
    }
    let root_id = required_str(map, "root_id", "missing_root_id", what)?.to_string();
    let entity = match established(map, "entity") {
        Some(value) => value.clone(),
        None => {
            return Err(fault(
                "missing_entity",
                format!("{what} requires an established entity identity"),
            ))
        }
    };
    Ok(json!({
        "entity": entity,
        "kind": kind,
        "root_id": root_id,
    }))
}

fn context_evidence_prefix(
    dependent: &Map<String, Value>,
    archive_root: &Map<String, Value>,
) -> Result<Option<Prefix>, Fault> {
    for map in [dependent, archive_root] {
        if let Some(value) = established(map, "evidence_prefix") {
            return Ok(Some(parse_prefix_value(value, "invalid_evidence_prefix")?));
        }
    }
    Ok(None)
}

fn context_evidence_refs(
    dependent: &Map<String, Value>,
    archive_root: &Map<String, Value>,
) -> Result<Option<Vec<Value>>, Fault> {
    for map in [dependent, archive_root] {
        match established(map, "evidence_refs") {
            Some(Value::Array(items)) => {
                for item in items {
                    evidence_ref_parts(item, "invalid_evidence_ref")?;
                }
                return Ok(Some(items.clone()));
            }
            Some(_) => {
                return Err(fault(
                    "invalid_evidence_ref",
                    "context evidence_refs must be an array of EvidenceRefs".to_string(),
                ))
            }
            None => {}
        }
    }
    Ok(None)
}

/// One validated journal `EvidenceRef`.
struct EvidenceRef {
    journal_id: String,
    sequence: u64,
    event_id: String,
    event_hash: String,
}

fn evidence_ref_parts(value: &Value, code: &str) -> Result<EvidenceRef, Fault> {
    let map = value
        .as_object()
        .ok_or_else(|| fault(code, "EvidenceRef must be an object".to_string()))?;
    let journal_id = required_str(map, "journal_id", code, "EvidenceRef")?.to_string();
    let sequence = required_u64(map, "sequence", code, "EvidenceRef")?;
    if sequence < 1 {
        return Err(fault(code, "EvidenceRef sequence must be positive".to_string()));
    }
    let event_id = required_str(map, "event_id", code, "EvidenceRef")?.to_string();
    let event_hash = required_str(map, "event_hash", code, "EvidenceRef")?.to_string();
    if !is_digest_text(&event_hash) {
        return Err(fault(
            code,
            "EvidenceRef event_hash must be 64 lowercase hex characters".to_string(),
        ));
    }
    match established(map, "pointer") {
        Some(Value::String(pointer)) if is_json_pointer(pointer) => {}
        Some(_) => {
            return Err(fault(
                code,
                "EvidenceRef pointer must be a JSON Pointer when established".to_string(),
            ))
        }
        None => return Err(fault(code, "EvidenceRef requires an established pointer".to_string())),
    }
    Ok(EvidenceRef {
        journal_id,
        sequence,
        event_id,
        event_hash,
    })
}

/// A journal prefix (`JournalPrefix`).
struct Prefix {
    journal_id: String,
    last_sequence: u64,
    head_hash: String,
}

impl Prefix {
    fn to_value(&self) -> Value {
        json!({
            "journal_id": self.journal_id,
            "last_sequence": self.last_sequence,
            "head_hash": self.head_hash,
        })
    }
}

fn parse_prefix_value(value: &Value, code: &str) -> Result<Prefix, Fault> {
    let map = value
        .as_object()
        .ok_or_else(|| fault(code, "prefix must be an object".to_string()))?;
    let journal_id = required_str(map, "journal_id", code, "prefix")?.to_string();
    let last_sequence = required_u64(map, "last_sequence", code, "prefix")?;
    if last_sequence < 1 {
        return Err(fault(code, "prefix last_sequence must be positive".to_string()));
    }
    let head_hash = required_str(map, "head_hash", code, "prefix")?.to_string();
    if !is_digest_text(&head_hash) {
        return Err(fault(
            code,
            "prefix head_hash must be 64 lowercase hex characters".to_string(),
        ));
    }
    Ok(Prefix {
        journal_id,
        last_sequence,
        head_hash,
    })
}

/// Owner-journal snapshot used for retention decisions.
struct JournalSnapshot {
    journal_id: String,
    owner_domain: String,
    last_sequence: u64,
    head_hash: String,
    events: Vec<Value>,
}

fn read_journal(
    store: &dyn OwnerStore,
    grant: &Grant,
    journal_id: &str,
) -> Result<JournalSnapshot, Fault> {
    let query = validate(
        OUTPUT_SCHEMA,
        json!({"query": "journal", "journal_id": journal_id}),
    )?;
    let view = store.read(grant, &query)?;
    let map = as_object(&view, "invalid_journal_view", "journal view")?;
    let record_type = required_str(map, "record_type", "invalid_journal_view", "journal view")?;
    if record_type != JOURNAL_VIEW {
        return Err(fault(
            "invalid_journal_view",
            format!("expected a {JOURNAL_VIEW:?} record, got {record_type:?}"),
        ));
    }
    let view_journal = required_str(map, "journal_id", "invalid_journal_view", "journal view")?;
    if view_journal != journal_id {
        return Err(fault(
            "invalid_journal_view",
            "journal view names a different journal than the query".to_string(),
        ));
    }
    let owner_domain = required_str(map, "owner_domain", "invalid_journal_view", "journal view")?.to_string();
    let last_sequence = required_u64(map, "last_sequence", "invalid_journal_view", "journal view")?;
    let head_hash = required_str(map, "head_hash", "invalid_journal_view", "journal view")?.to_string();
    if last_sequence >= 1 && !is_digest_text(&head_hash) {
        return Err(fault(
            "invalid_journal_view",
            "journal view head_hash must be 64 lowercase hex characters".to_string(),
        ));
    }
    let events = established_array(map, "events", "invalid_journal_view", "journal view")?
        .ok_or_else(|| {
            fault(
                "invalid_journal_view",
                "journal view requires an established events array".to_string(),
            )
        })?;
    if events.len() as u64 != last_sequence {
        return Err(fault(
            "invalid_journal_view",
            "journal view prefix length disagrees with its events; an incomplete prefix is not a durable read"
                .to_string(),
        ));
    }
    for (index, event) in events.iter().enumerate() {
        let event_map = event.as_object().ok_or_else(|| {
            fault(
                "invalid_journal_view",
                format!("journal event {} must be an object", index + 1),
            )
        })?;
        let sequence = required_u64(event_map, "journal_sequence", "invalid_journal_view", "journal event")?;
        if sequence != index as u64 + 1 {
            return Err(fault(
                "invalid_journal_view",
                format!(
                    "journal event at position {} claims sequence {}; prefixes are contiguous and ordered",
                    index + 1,
                    sequence
                ),
            ));
        }
        required_str(event_map, "event_id", "invalid_journal_view", "journal event")?;
        let event_hash = required_str(event_map, "event_hash", "invalid_journal_view", "journal event")?;
        if !is_digest_text(event_hash) {
            return Err(fault(
                "invalid_journal_view",
                "journal event_hash must be 64 lowercase hex characters".to_string(),
            ));
        }
        event_map.get("payload").ok_or_else(|| {
            fault(
                "invalid_journal_view",
                "journal event requires a payload".to_string(),
            )
        })?;
    }
    Ok(JournalSnapshot {
        journal_id: journal_id.to_string(),
        owner_domain,
        last_sequence,
        head_hash,
        events: events.clone(),
    })
}

fn read_prefix(store: &dyn OwnerStore, grant: &Grant, journal_id: &str) -> Result<Prefix, Fault> {
    let query = validate(
        OUTPUT_SCHEMA,
        json!({"query": "prefix", "journal_id": journal_id}),
    )?;
    let view = store.read(grant, &query)?;
    let map = as_object(&view, "invalid_journal_view", "journal prefix")?;
    let record_type = required_str(map, "record_type", "invalid_journal_view", "journal prefix")?;
    if record_type != JOURNAL_PREFIX {
        return Err(fault(
            "invalid_journal_view",
            format!("expected a {JOURNAL_PREFIX:?} record, got {record_type:?}"),
        ));
    }
    let view_journal = required_str(map, "journal_id", "invalid_journal_view", "journal prefix")?;
    if view_journal != journal_id {
        return Err(fault(
            "invalid_journal_view",
            "journal prefix names a different journal than the query".to_string(),
        ));
    }
    parse_prefix_value(record_value(&view), "invalid_journal_view")
}

fn collect_named_records<'a>(value: &'a Value, record_type: &str, out: &mut Vec<&'a Value>) {
    match value {
        Value::Object(map) => {
            if map.get("record_type").and_then(Value::as_str) == Some(record_type) {
                out.push(value);
            }
            for nested in map.values() {
                collect_named_records(nested, record_type, out);
            }
        }
        Value::Array(items) => {
            for nested in items {
                collect_named_records(nested, record_type, out);
            }
        }
        _ => {}
    }
}

/// One journaled pin revision, before revisions are merged per pin id.
struct ParsedPin {
    pin_id: String,
    owner_domain: String,
    writer_id: String,
    revision: u64,
    state: String,
    dependent_identity: Value,
    archive_identity: Value,
    archive_digest: String,
    dependencies: Vec<(String, Value, Value)>,
    evidence_prefix: Value,
    latest: Value,
}

fn parse_pin(value: &Value) -> Result<ParsedPin, Fault> {
    let map = value
        .as_object()
        .ok_or_else(|| fault("invalid_pin", "pin must be a JSON object".to_string()))?;
    let record_type = required_str(map, "record_type", "invalid_pin", "pin")?;
    if record_type != PIN_RECORD {
        return Err(fault(
            "invalid_pin",
            format!("expected record_type {PIN_RECORD:?}, got {record_type:?}"),
        ));
    }
    let pin_id = required_str(map, "pin_id", "invalid_pin", "pin")?.to_string();
    let owner_domain = required_str(map, "owner_domain", "invalid_pin", "pin")?.to_string();
    let writer_id = required_str(map, "writer_id", "invalid_pin", "pin")?.to_string();
    let revision = required_u64(map, "revision", "invalid_pin", "pin")?;
    if revision < 1 {
        return Err(fault(
            "invalid_pin",
            "pin revision must be positive".to_string(),
        ));
    }
    required_u64(map, "previous_revision", "invalid_pin", "pin")?;
    let state = required_str(map, "state", "invalid_pin", "pin")?.to_string();
    if !PIN_STATES.contains(&state.as_str()) {
        return Err(fault(
            "invalid_pin",
            format!("pin state {state:?} is not active or released"),
        ));
    }
    let dependent = map
        .get("dependent")
        .filter(|value| !is_missing(value))
        .ok_or_else(|| fault("invalid_pin", "pin requires its dependent identity".to_string()))?;
    let dependent_identity = dependent_identity(dependent, "invalid_pin", "pin dependent")?;
    let archive_value = map
        .get("archive_root")
        .filter(|value| !is_missing(value))
        .ok_or_else(|| fault("invalid_pin", "pin requires its archive root".to_string()))?;
    let archive = reference_parts(archive_value, false, "invalid_pin", "pin archive_root")?;
    let dependencies = match map.get("dependencies") {
        None => Vec::new(),
        Some(value) if is_missing(value) => Vec::new(),
        Some(Value::Array(items)) => {
            let mut parsed: Vec<(String, Value, Value)> = Vec::new();
            for (index, item) in items.iter().enumerate() {
                let what = format!("pin dependencies[{index}]");
                let reference = reference_parts(item, false, "invalid_pin", &what)?;
                if reference.digest == archive.digest {
                    return Err(fault(
                        "invalid_pin",
                        format!(
                            "pin {:?} names its archive root {} as its own dependency",
                            pin_id, archive.digest
                        ),
                    ));
                }
                if let Some((_, identity, _)) =
                    parsed.iter().find(|(digest, _, _)| digest == &reference.digest)
                {
                    if identity != &reference.identity() {
                        return Err(fault(
                            "retention_integrity",
                            format!(
                                "pin {:?} names dependency {} with conflicting immutable metadata",
                                pin_id, reference.digest
                            ),
                        ));
                    }
                } else {
                    parsed.push((reference.digest.clone(), reference.identity(), reference.value.clone()));
                }
            }
            parsed
        }
        Some(_) => {
            return Err(fault(
                "invalid_pin",
                "pin dependencies must be an array or a Missing envelope".to_string(),
            ))
        }
    };
    let evidence_prefix = map.get("evidence_prefix").cloned().unwrap_or_else(|| {
        missing(
            "not_observed",
            "pin carries no evidence prefix in this journal record",
        )
    });
    Ok(ParsedPin {
        pin_id,
        owner_domain,
        writer_id,
        revision,
        state,
        dependent_identity,
        archive_identity: archive.identity(),
        archive_digest: archive.digest,
        dependencies,
        evidence_prefix,
        latest: value.clone(),
    })
}

/// Merged retention state for one pin id across all journaled revisions.
struct Pin {
    pin_id: String,
    owner_domain: String,
    revision: u64,
    state: String,
    dependent_identity: Value,
    archive_identity: Value,
    archive_digest: String,
    dependencies: BTreeMap<String, Value>,
    latest: Value,
}

/// Every journaled pin, merged per pin id with monotone history.
///
/// Identity (`owner_domain`, `dependent`, `archive_root`) never changes under a
/// pin id. Release is terminal: once any revision is `released` the pin stays
/// released, so replaying an older active revision can never resurrect
/// protection. Dependency edges are unioned across revisions so a newer
/// revision can never shrink a closure that an earlier revision recorded.
fn pins_from_journal(snapshot: &JournalSnapshot) -> Result<BTreeMap<String, Pin>, Fault> {
    let mut pins: BTreeMap<String, Pin> = BTreeMap::new();
    for (index, event) in snapshot.events.iter().enumerate() {
        let payload = event
            .get("payload")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                fault(
                    "invalid_journal_view",
                    format!("journal event {} has no payload object", index + 1),
                )
            })?;
        let data = match payload.get("data") {
            Some(value) if !is_missing(value) => value,
            _ => continue,
        };
        let mut found: Vec<&Value> = Vec::new();
        collect_named_records(data, PIN_RECORD, &mut found);
        for value in found {
            let parsed = parse_pin(value)?;
            match pins.get_mut(&parsed.pin_id) {
                None => {
                    pins.insert(
                        parsed.pin_id.clone(),
                        Pin {
                            pin_id: parsed.pin_id,
                            owner_domain: parsed.owner_domain,
                            revision: parsed.revision,
                            state: parsed.state,
                            dependent_identity: parsed.dependent_identity,
                            archive_identity: parsed.archive_identity,
                            archive_digest: parsed.archive_digest,
                            dependencies: parsed
                                .dependencies
                                .into_iter()
                                .map(|(digest, _, raw)| (digest, raw))
                                .collect(),
                            latest: parsed.latest,
                        },
                    );
                }
                Some(existing) => {
                    if existing.owner_domain != parsed.owner_domain
                        || existing.dependent_identity != parsed.dependent_identity
                        || existing.archive_identity != parsed.archive_identity
                    {
                        return Err(fault(
                            "pin_identity_mutation",
                            format!(
                                "pin {:?} changes dependent, archive, or owner identity between revisions; identity never changes under a pin id",
                                parsed.pin_id
                            ),
                        ));
                    }
                    for (digest, identity, raw) in parsed.dependencies {
                        match existing.dependencies.get(&digest) {
                            Some(previous) => {
                                let previous_identity = reference_parts(
                                    previous,
                                    false,
                                    "retention_integrity",
                                    "journaled dependency",
                                )?
                                .identity();
                                if previous_identity != identity {
                                    return Err(fault(
                                        "retention_integrity",
                                        format!(
                                            "pin {:?} names dependency {} with conflicting immutable metadata across revisions",
                                            parsed.pin_id, digest
                                        ),
                                    ));
                                }
                            }
                            None => {
                                existing.dependencies.insert(digest, raw);
                            }
                        }
                    }
                    if parsed.state == "released" {
                        existing.state = "released".to_string();
                    }
                    if parsed.revision > existing.revision
                        || (parsed.revision == existing.revision && parsed.state == "released")
                    {
                        existing.revision = parsed.revision;
                        existing.latest = parsed.latest;
                    }
                }
            }
        }
    }
    Ok(pins)
}

/// Transitive protection closure of every active root.
fn reachable_digests(pins: &BTreeMap<String, Pin>) -> BTreeSet<String> {
    let mut reachable: BTreeSet<String> = BTreeSet::new();
    for pin in pins.values().filter(|pin| pin.state == "active") {
        reachable.insert(pin.archive_digest.clone());
        for digest in pin.dependencies.keys() {
            reachable.insert(digest.clone());
        }
    }
    loop {
        let mut grew = false;
        for pin in pins.values() {
            if reachable.contains(&pin.archive_digest) {
                for digest in pin.dependencies.keys() {
                    if reachable.insert(digest.clone()) {
                        grew = true;
                    }
                }
            }
        }
        if !grew {
            break;
        }
    }
    reachable
}

fn resolve_journal_id(
    request: &Map<String, Value>,
    pin: &ParsedPin,
    evidence: &[EvidenceRef],
) -> Result<String, Fault> {
    if let Some(Value::String(text)) = established(request, "journal_id") {
        if !text.is_empty() {
            return Ok(text.clone());
        }
    }
    if let Some(text) = pin
        .evidence_prefix
        .as_object()
        .and_then(|map| map.get("journal_id"))
        .and_then(Value::as_str)
    {
        if !text.is_empty() {
            return Ok(text.to_string());
        }
    }
    let first = evidence
        .first()
        .map(|reference| reference.journal_id.clone())
        .unwrap_or_default();
    if first.is_empty() {
        return Err(fault(
            "missing_journal_id",
            "release requires the owner journal that holds the pin; no journal is named by the request, pin, or evidence"
                .to_string(),
        ));
    }
    if evidence.iter().any(|reference| reference.journal_id != first) {
        return Err(fault(
            "mixed_evidence_journals",
            "release evidence must resolve inside one owner journal".to_string(),
        ));
    }
    Ok(first)
}

fn resolve_evidence<'a>(
    snapshot: &'a JournalSnapshot,
    reference: &EvidenceRef,
) -> Result<&'a Value, Fault> {
    if reference.journal_id != snapshot.journal_id {
        return Err(fault(
            "foreign_evidence_ref",
            format!(
                "evidence cites journal {:?}, not {:?}; retention evidence never crosses journals",
                reference.journal_id, snapshot.journal_id
            ),
        ));
    }
    if reference.sequence < 1 || reference.sequence > snapshot.last_sequence {
        return Err(fault(
            "unknown_evidence_ref",
            format!(
                "evidence sequence {} is outside the journal prefix 1..={}",
                reference.sequence, snapshot.last_sequence
            ),
        ));
    }
    let event = snapshot
        .events
        .get((reference.sequence - 1) as usize)
        .ok_or_else(|| {
            fault(
                "unknown_evidence_ref",
                format!("journal has no event at sequence {}", reference.sequence),
            )
        })?;
    let map = event.as_object().ok_or_else(|| {
        fault(
            "invalid_journal_view",
            "journal event must be an object".to_string(),
        )
    })?;
    let event_id = map.get("event_id").and_then(Value::as_str).unwrap_or_default();
    let event_hash = map.get("event_hash").and_then(Value::as_str).unwrap_or_default();
    if event_id != reference.event_id || event_hash != reference.event_hash {
        return Err(fault(
            "evidence_mismatch",
            format!(
                "evidence {}#{} does not match the journaled event id/hash; a digest alone is not proof",
                reference.journal_id, reference.sequence
            ),
        ));
    }
    Ok(event)
}

/// True when the journaled event records retirement of `root_id`.
fn evidences_retirement(value: &Value, root_id: &str) -> bool {
    match value {
        Value::Object(map) => {
            let retired = map.get("retired").and_then(Value::as_bool) == Some(true);
            let same_root = map.get("root_id").and_then(Value::as_str) == Some(root_id);
            if retired && same_root {
                return true;
            }
            if map.get("retired_root_id").and_then(Value::as_str) == Some(root_id) {
                return true;
            }
            map.values().any(|nested| evidences_retirement(nested, root_id))
        }
        Value::Array(items) => items.iter().any(|nested| evidences_retirement(nested, root_id)),
        _ => false,
    }
}

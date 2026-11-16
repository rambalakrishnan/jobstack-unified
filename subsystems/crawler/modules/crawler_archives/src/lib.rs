//! `crawler_archives`: changed-key replacement archives and archive expansion.
//!
//! Implements Contract 04 §20.3 **Changed-key atomic protocol**, §20.5
//! **Archive extents**, and §20.6 **Retention** for the crawler seam:
//!
//! * [`replace_fetch_key`] commits one owner-local replacement for a job whose
//!   acquisition fetch key changed. It selects (or verifies) a
//!   `fetch_key_replacement` seal pinning the *current* old crawler revision and
//!   the *latest fully published* downstream revision in the named ingest-side
//!   view, installs the complete prior `LogicalRow` as immutable local extents,
//!   and commits the new crawler revision, the backward archive link, the
//!   `FetchKeyReplacement` receipt, and the active retention pin as one journal
//!   event before acknowledging.
//! * [`expand_archive`] reconstructs the exact complete `LogicalRow` from the
//!   archived storage manifest and the verified immutable local extents it
//!   names. It never queries mutable peer state, never inserts defaults, and
//!   never upgrades a revision: a lost extent is an integrity fault.
//!
//! # Record shapes
//!
//! Every input is a [`CheckedRecord`] admitted by the schema gate, so no bare
//! JSON `null` survives; absent values are typed `Missing` envelopes.
//!
//! ## Replacement request (`replace_fetch_key`)
//!
//! * `journal_id` — owner journal carrying publications, the seal selection,
//!   and the replacement commit.
//! * `view` — read view name (default `ingest`).
//! * `entity` (or `entity_id`) — job identity.
//! * `registration` — the complete `EntityRegistration` document. Its
//!   `registration_digest` (or `digest`) fixes the domain field set.
//! * `new_crawler` — the complete new crawler revision document
//!   (`owned_domain_revision`) with `revision`, `previous_revision`, and the
//!   complete `value`. `domain` must be `crawler`; `owner_domain`,
//!   `registration_digest`, and `entity` must agree with the request when
//!   supplied. Its `value.replacement_lineage` is authored here: an
//!   established link that contradicts the committed replacement is refused.
//! * `old_crawler` — optional `NonzeroDomainPin` (`revision`,
//!   `record_digest`) the caller believes it supersedes; it must equal the
//!   locally published crawler pointer.
//! * `old_fetch_key` — optional digest text (`sha256:<hex>` or bare 64-hex)
//!   the caller believes is current; it must equal the locally published key.
//! * `archive_seal` (or `seal`) — optional already-selected
//!   `fetch_key_replacement` `SealPoint`. When supplied it is verified against
//!   the current local pointers instead of selecting a new one.
//! * `support` (or `evidence_refs`) — optional earlier journal evidence.
//!
//! Digest text inside this module is the same bare 64-lowercase-hex form used
//! by the artifact, journal, and publication seams; `sha256:` framing is
//! accepted on input and normalized.
//!
//! ## Archive storage manifest (`ArchiveStorageManifest`)
//!
//! `encoding: "owner-domain-extents/1"`, the contract schema version, the job
//! entity, an artifact reference to the complete registration document, the
//! domain extents (`crawler`, `downstream` — exactly those two for jobs), and
//! the replacement seal. A published extent carries `revision`, `document`,
//! and `publication_ref`; an unpublished extent carries the exact zero slot
//! (`revision: 0`, typed `Missing` value). The archive root hashes the
//! canonical storage-manifest bytes, never the expanded wrapper.
//!
//! ## Archive record (`ArchiveRecord`)
//!
//! `record_type: "logical_row_archive"`, the schema version, the root
//! reference, the storage manifest, and `payload_json` — the **entire previous
//! `LogicalRow`** (registration, every domain slot with its complete snapshot,
//! publication references, reasoned missingness, and the sealed version
//! vector), never a diff, crawler-only row, hash list, or mutable locator.
//!
//! ## Replacement receipt (`FetchKeyReplacement`)
//!
//! Replacement identity, entity/registration, `old_crawler`, `old_fetch_key`,
//! the complete `new_crawler` revision with its `ReplacementLink`,
//! `archive_root`, `archived_vector`, `retention_pin_id`, `commit_ref`,
//! `evidence_prefix`, and support. The returned record additionally carries
//! the complete `archive` record (so the caller can immediately serve the
//! prior row) and the committed `retention_pin`; neither addition is journaled.
//!
//! # Semantics
//!
//! * A changed fetch key requires the complete prior row plus durable retention
//!   protection; a same-key write is an acquisition no-op and creates no
//!   archive.
//! * A publication that lands after the seal selection forces rejection
//!   (`publication_race`) and reselection. A mismatched archive is never
//!   committed.
//! * Expansion reads only the immutable extents named by the archived storage
//!   manifest. Missing bytes fault (`bytes_unavailable`); a reconstructed row
//!   that disagrees with the archived `payload_json` is an integrity incident
//!   (`archive_integrity`).
//!
//! # Fault codes
//!
//! `invalid_request`, `missing_journal_id`, `missing_entity`,
//! `missing_registration`, `missing_registration_digest`, `invalid_grant`,
//! `owner_mismatch`, `manifest_mismatch`, `retention_policy_not_authority`,
//! `invalid_journal_view`, `foreign_owner`, `missing_prior_row`,
//! `stale_old_crawler`, `invalid_new_crawler`, `invalid_lineage`,
//! `fetch_key_unchanged`, `invalid_seal`, `publication_race`,
//! `registration_mismatch`, `integrity_conflict`, `incomplete_row`,
//! `archive_integrity`, `invalid_document`, `non_canonical_manifest`,
//! `invalid_root`, `invalid_reference`, `artifact_integrity`,
//! `commit_not_durable`, `invalid_receipt`, plus the artifact and retention
//! store faults (`bytes_unavailable`, `access_denied`, `invalid_pin`, …).

use crawler_artifacts::ArtifactStore;
use crawler_authority::{grant_record, Grant};
use crawler_fetch_identity::decide_acquisition_write;
use crawler_hashing::{canonical_bytes, digest_bytes};
use crawler_publication::{compose_row, select_seal};
use crawler_retention::plan_retention_pin;
use crawler_schema::{record_value, validate, CheckedRecord, Fault};
use crawler_store::OwnerStore;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Registries and constants
// ---------------------------------------------------------------------------

/// Structural envelope for records produced by this module.
const OUTPUT_SCHEMA: &str = "audit_log";
/// Contract schema version stamped on archive records.
const SCHEMA_VERSION: &str = "owner-separated-write-domains/0.1.0";
/// Physical extent encoding of an archive's storage manifest.
const STORAGE_ENCODING: &str = "owner-domain-extents/1";

const ARCHIVE_RECORD: &str = "logical_row_archive";
const REPLACEMENT_RECORD: &str = "fetch_key_replacement";
const LOGICAL_ROW: &str = "logical_row";
const OWNED_REVISION: &str = "owned_domain_revision";
const SEAL_POINT: &str = "seal_point";
const JOURNAL_VIEW: &str = "journal_view";
const PUBLICATION_RECEIPT: &str = "publication_receipt";

/// Seal name every replacement archive is taken under (§20.3 step 3, §20.5).
const REPLACEMENT_SEAL_NAME: &str = "fetch_key_replacement";
const DEFAULT_VIEW: &str = "ingest";

/// Job domain slots, exactly these two (§20.5).
const JOB_DOMAINS: &[&str] = &["crawler", "downstream"];

/// Retention shortcuts that never authorize (or excuse) a replacement.
const RETENTION_SHORTCUTS: &[&str] = &[
    "ttl",
    "ttl_seconds",
    "ttl_ms",
    "expires_at",
    "expired",
    "cache_eviction",
    "cache_evicted",
    "eviction",
    "rely_on_newer_revision",
];

// ---------------------------------------------------------------------------
// Public interface
// ---------------------------------------------------------------------------

/// Commit a changed fetch key as a complete archive plus retention protection.
///
/// Establishes the old crawler revision/digest/key, selects (or verifies) the
/// `fetch_key_replacement` seal pinning both the old crawler revision and the
/// latest fully published downstream revision in the named view, installs the
/// complete prior `LogicalRow` as immutable extents, and commits the new
/// crawler revision, backward replacement link, replacement receipt, and
/// active retention pin in one owner-local durable event.
///
/// The commit is conditional on both checked pointers: if the locally
/// published crawler revision or the sealed downstream revision moved after
/// the seal selection, the call faults with `publication_race` before any
/// archive is committed, and the caller must reselect. A staged extent is
/// never a committed archive.
pub fn replace_fetch_key(
    store: &dyn OwnerStore,
    artifacts: &dyn ArtifactStore,
    crawler_grant: &Grant,
    retention_grant: &Grant,
    request: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let facts = grant_facts(crawler_grant)?;
    let retention_facts = grant_facts(retention_grant)?;
    if retention_facts.owner_domain != facts.owner_domain {
        return Err(fault(
            "owner_mismatch",
            format!(
                "crawler grant belongs to {:?} but the retention grant belongs to {:?}; replacement and retention commit inside one owner durability boundary",
                facts.owner_domain, retention_facts.owner_domain
            ),
        ));
    }
    if retention_facts.manifest_digest != facts.manifest_digest {
        return Err(fault(
            "manifest_mismatch",
            "replacement and retention grants are bound to different manifests; one owner-local commit cannot span two evidence policies"
                .to_string(),
        ));
    }

    let request_map = as_object(request, "invalid_request", "request")?;
    reject_retention_shortcuts(request_map, "replacement request")?;
    let journal_id =
        required_str(request_map, "journal_id", "missing_journal_id", "request")?.to_string();
    let view = optional_nonempty(request_map, "view")?.unwrap_or_else(|| DEFAULT_VIEW.to_string());
    let entity = entity_from(request_map, "request")?;
    let entity_key = entity_key(&entity)?;

    let registration_value = request_map
        .get("registration")
        .filter(|value| !is_missing(value))
        .cloned()
        .ok_or_else(|| {
            fault(
                "missing_registration",
                "replacement requires the complete entity registration document".to_string(),
            )
        })?;
    if !registration_value.is_object() {
        return Err(fault(
            "missing_registration",
            "registration must be a complete object".to_string(),
        ));
    }
    let registration = validate(OUTPUT_SCHEMA, registration_value)?;
    let registration_digest = registration_digest_of(request_map, &registration)?;
    verify_registration_identity(&entity, &registration)?;

    let new_request = parse_new_crawler(request_map, &facts, &entity, &registration_digest)?;
    let declared_old = parse_declared_old(request_map)?;
    let declared_old_key = optional_digest_text(request_map, "old_fetch_key", "request")?;
    let support = if request_map.get("support").is_some() {
        object_array(request_map, "support", "invalid_request", "request")?
    } else {
        object_array(request_map, "evidence_refs", "invalid_request", "request")?
    };
    let supplied_seal = established(request_map, "archive_seal")
        .or_else(|| established(request_map, "seal"))
        .cloned();

    // 1. Establish the old crawler revision, digest, and key locally.
    let state = read_journal(store, crawler_grant, &journal_id, &facts.owner_domain)?;
    let old_pointer = pointer(&state, &entity_key, &view, "crawler")
        .ok_or_else(|| {
            fault(
                "missing_prior_row",
                "no crawler revision is published in this view; an absent root accepts its initial complete domain without a predecessor archive"
                    .to_string(),
            )
        })?
        .clone();
    if old_pointer.registration_digest != registration_digest {
        return Err(fault(
            "registration_mismatch",
            format!(
                "crawler revision {} in view {view:?} is published under registration {}; the request names {registration_digest}",
                old_pointer.revision, old_pointer.registration_digest
            ),
        ));
    }
    let (old_snapshot, _) = read_verified_document(
        artifacts,
        crawler_grant,
        &old_pointer.document,
        "published crawler revision",
    )?;
    let old_key = fetch_key_of(&old_snapshot)?;
    if let Some(declared) = &declared_old {
        if declared.revision != old_pointer.revision
            || declared.record_digest != old_pointer.document_digest
        {
            return Err(fault(
                "stale_old_crawler",
                format!(
                    "request supersedes crawler revision {} / {}, but the local pointer is revision {} / {}",
                    declared.revision,
                    declared.record_digest,
                    old_pointer.revision,
                    old_pointer.document_digest
                ),
            ));
        }
    }
    if let Some(declared_key) = &declared_old_key {
        if declared_key != &old_key {
            return Err(fault(
                "stale_old_crawler",
                format!(
                    "request supersedes fetch key {declared_key}, but the locally published crawler revision carries {old_key}"
                ),
            ));
        }
    }
    if new_request.revision != new_request.previous_revision + 1 {
        return Err(fault(
            "invalid_new_crawler",
            format!(
                "new crawler revision {} must follow its predecessor {} by exactly one revision",
                new_request.revision, new_request.previous_revision
            ),
        ));
    }

    // 2. Same-key writes are acquisition no-ops: no replacement, no archive.
    //    The decision is taken against the locally published row; if that row
    //    moved between the read above and this decision, the sealed row below
    //    is the authority instead of a stale no-op verdict.
    let candidate_value = prepare_candidate(&new_request.value)?;
    match ensure_key_differs(&old_snapshot, &candidate_value) {
        Ok(()) => {}
        Err(err) if err.code == "fetch_key_unchanged" => {
            let current = read_journal(store, crawler_grant, &journal_id, &facts.owner_domain)?;
            let unchanged = pointer(&current, &entity_key, &view, "crawler")
                .map(|current| {
                    current.revision == old_pointer.revision
                        && current.document_digest == old_pointer.document_digest
                })
                .unwrap_or(false);
            if unchanged {
                return Err(err);
            }
        }
        Err(err) => return Err(err),
    }

    // 3. Select (or verify) the replacement seal pinning both pointers.
    let seal = match supplied_seal {
        Some(seal_value) => {
            let seal = validate(OUTPUT_SCHEMA, seal_value)?;
            verify_seal(
                &seal,
                &entity,
                &registration_digest,
                &view,
                &state,
                &entity_key,
            )?;
            seal
        }
        None => {
            let seal_request = validate(
                OUTPUT_SCHEMA,
                json!({
                    "journal_id": journal_id,
                    "view": view,
                    "entity": entity,
                    "registration_digest": registration_digest,
                    "domains": JOB_DOMAINS,
                    "seal_name": REPLACEMENT_SEAL_NAME,
                    "support": support,
                }),
            )?;
            select_seal(store, crawler_grant, &seal_request)?
        }
    };
    let slots = parse_seal_slots(&seal)?;
    let commit_refs = commit_evidence_refs(&seal)?;

    // 4. Verify the sealed pointers are still the local pointers. A changed
    //    local publication forces reselection; a mismatched archive is never
    //    committed.
    let state = read_journal(store, crawler_grant, &journal_id, &facts.owner_domain)?;
    verify_pointers(
        &seal,
        &slots,
        &state,
        &entity_key,
        &view,
        &registration_digest,
    )?;
    let sealed_crawler = slots
        .get("crawler")
        .filter(|slot| slot.revision > 0)
        .ok_or_else(|| {
            fault(
                "invalid_seal",
                "replacement seal must pin the old crawler revision".to_string(),
            )
        })?;
    if new_request.previous_revision != sealed_crawler.revision {
        return Err(fault(
            "publication_race",
            format!(
                "sealed crawler revision is {}, but the new revision supersedes {}; a changed local crawler pointer forces reselection",
                sealed_crawler.revision, new_request.previous_revision
            ),
        ));
    }
    if let Some(declared) = &declared_old {
        if declared.revision != sealed_crawler.revision
            || sealed_crawler.document_digest.as_deref() != Some(declared.record_digest.as_str())
        {
            return Err(fault(
                "stale_old_crawler",
                "the sealed crawler revision no longer matches the old pin named by the request"
                    .to_string(),
            ));
        }
    }
    if let Some(declared_key) = &declared_old_key {
        if declared_key != &old_key {
            return Err(fault(
                "stale_old_crawler",
                "the sealed crawler revision carries a different fetch key than the request names"
                    .to_string(),
            ));
        }
    }
    let sealed_pointer = pointer(&state, &entity_key, &view, "crawler").ok_or_else(|| {
        fault(
            "missing_prior_row",
            "sealed crawler revision vanished".to_string(),
        )
    })?;
    let (sealed_snapshot, _) = read_verified_document(
        artifacts,
        crawler_grant,
        &sealed_pointer.document,
        "sealed crawler revision",
    )?;
    if fetch_key_of(&sealed_snapshot)? != old_key {
        return Err(fault(
            "stale_old_crawler",
            "sealed crawler revision carries a different fetch key than the version the change was computed against"
                .to_string(),
        ));
    }
    // The sealed prior row is the authority for the no-op decision: an
    // identical sealed key makes the acquisition write a no-op and creates no
    // archive.
    ensure_key_differs(&sealed_snapshot, &candidate_value)?;

    // 5. Read the sealed domain extents. Only the seal's exact revision is
    //    archived; the local pointer may not substitute another revision.
    let crawler_domain =
        read_published_domain(artifacts, crawler_grant, sealed_pointer, "crawler")?;
    let downstream_domain = match slots.get("downstream") {
        Some(slot) if slot.revision == 0 => None,
        Some(_) => {
            let downstream_pointer =
                pointer(&state, &entity_key, &view, "downstream").ok_or_else(|| {
                    fault(
                        "publication_race",
                        "seal pins a published downstream revision but the local view has none"
                            .to_string(),
                    )
                })?;
            Some(read_published_domain(
                artifacts,
                crawler_grant,
                downstream_pointer,
                "downstream",
            )?)
        }
        None => {
            return Err(fault(
                "invalid_seal",
                "replacement seal must contain every declared job domain slot".to_string(),
            ))
        }
    };

    // 6. Stage the archive extents outside the commit and compose the complete
    //    prior logical row from the sealed, verified components.
    let archived_vector = json!({
        "crawler": crawler_domain.revision,
        "downstream": downstream_domain.as_ref().map(|domain| domain.revision).unwrap_or(0),
    });
    let build = build_archive(
        artifacts,
        crawler_grant,
        &entity,
        &registration,
        &seal,
        &view,
        &crawler_domain,
        downstream_domain.as_ref(),
    )?;

    // 7. The replacement identity is deterministic over the old identity and
    //    the archive root, so retries and downstream replay resolve the same
    //    replacement instead of minting competing ones.
    let replacement_id = format!(
        "replacement-{}-{}-{}",
        prefix16(&registration_digest),
        prefix16(&old_key),
        prefix16(
            record_value(&build.root)
                .get("digest")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        ),
    );
    let new_crawler = build_new_crawler(
        &new_request,
        &facts,
        &entity,
        &registration_digest,
        &candidate_value,
        &replacement_id,
        sealed_crawler.revision,
        record_value(&build.root),
    )?;

    // 8. Retention: the live replacement pins the archive root and its whole
    //    immutable dependency closure; planning performs no IO and the pin is
    //    journaled inside the same commit event.
    let dependent = validate(
        OUTPUT_SCHEMA,
        json!({
            "entity": entity,
            "kind": "live_replacement",
            "root_id": replacement_id,
            "writer_id": facts.producer_id,
        }),
    )?;
    let mut dependencies = vec![build.registration_ref, crawler_domain.document_record];
    if let Some(domain) = downstream_domain {
        dependencies.push(domain.document_record);
    }
    let pin = plan_retention_pin(&dependent, &build.root, &dependencies)?;
    verify_pin(&pin, &build.root, &dependencies)?;
    let retention_pin_id = required_str(
        as_object(&pin, "invalid_pin", "retention pin")?,
        "pin_id",
        "invalid_pin",
        "retention pin",
    )?
    .to_string();

    // 9. Conditional check at commit: both checked pointers must still agree
    //    with the seal. A publication that landed while extents were staged
    //    rejects the replacement; the staged extents stay inert orphans.
    let commit_state = read_journal(store, crawler_grant, &journal_id, &facts.owner_domain)?;
    verify_pointers(
        &seal,
        &slots,
        &commit_state,
        &entity_key,
        &view,
        &registration_digest,
    )?;

    // 10. Atomic owner-local commit: replacement, backed link, retention
    //     protection, and journal effect in one durable event.
    let journaled_replacement = replacement_record(
        &entity,
        &registration_digest,
        &replacement_id,
        sealed_crawler.revision,
        sealed_crawler
            .document_digest
            .as_deref()
            .unwrap_or_default(),
        &old_key,
        &new_crawler,
        record_value(&build.root),
        &archived_vector,
        &retention_pin_id,
        &support,
    )?;
    let transaction = validate(
        OUTPUT_SCHEMA,
        json!({
            "operation": "append_event",
            "journal_id": journal_id,
            "principal": {
                "producer_id": facts.producer_id,
                "manifest_digest": facts.manifest_digest,
            },
            "submission": {
                "producer_sequence": missing(
                    "not_applicable",
                    "an owner-authored replacement has no producer sequence",
                ),
                "event_kind": facts.event_kind,
                "event_schema_version": SCHEMA_VERSION,
                "occurred_at": missing(
                    "not_observed",
                    "replacement is an owner effect without a source occurrence",
                ),
                "payload": {
                    "data": {
                        "fetch_key_replacement": record_value(&journaled_replacement).clone(),
                        "archive_retention_pin": record_value(&pin).clone(),
                        "archive_root": record_value(&build.root).clone(),
                    },
                    "measurements": [],
                    "evidence_refs": commit_refs.clone(),
                    "artifact_refs": [],
                },
            },
            "causal_refs": commit_refs,
        }),
    )?;
    let receipt = store.transact(crawler_grant, &transaction)?;
    let receipt_map = as_object(&receipt, "invalid_receipt", "commit receipt")?;
    match receipt_map.get("durable") {
        Some(Value::Bool(true)) => {}
        _ => {
            return Err(fault(
                "commit_not_durable",
                "store did not acknowledge the replacement as durable; the archive is not announced before durability"
                    .to_string(),
            ))
        }
    }
    let sequence = required_u64(
        receipt_map,
        "journal_sequence",
        "invalid_receipt",
        "commit receipt",
    )?;
    let event_hash = required_str(
        receipt_map,
        "event_hash",
        "invalid_receipt",
        "commit receipt",
    )?
    .to_string();
    if !is_hex64(&event_hash) {
        return Err(fault(
            "invalid_receipt",
            "commit receipt event_hash must be 64 lowercase hex characters".to_string(),
        ));
    }
    let head_hash = required_str(
        receipt_map,
        "head_hash",
        "invalid_receipt",
        "commit receipt",
    )?
    .to_string();
    let event = receipt_map
        .get("event")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            fault(
                "invalid_receipt",
                "commit receipt must carry the appended event".to_string(),
            )
        })?;
    let event_id = required_str(event, "event_id", "invalid_receipt", "commit event")?.to_string();
    let evidence_prefix = json!({
        "journal_id": journal_id,
        "last_sequence": sequence,
        "head_hash": head_hash,
    });
    let commit_ref = json!({
        "journal_id": journal_id,
        "sequence": sequence,
        "event_id": event_id,
        "event_hash": event_hash,
        "pointer": "/payload/data/fetch_key_replacement",
    });

    // 11. Return the committed receipt (with the seal-selection prefix, the
    //     complete archive, and the committed pin) only after durability.
    let mut returned = record_value(&journaled_replacement).clone();
    let returned_map = returned.as_object_mut().ok_or_else(|| {
        fault(
            "invalid_receipt",
            "replacement must be an object".to_string(),
        )
    })?;
    returned_map.insert("commit_ref".to_string(), commit_ref.clone());
    returned_map.insert("evidence_prefix".to_string(), evidence_prefix.clone());
    returned_map.insert("archive".to_string(), record_value(&build.archive).clone());
    let mut committed_pin = record_value(&pin).clone();
    if let Some(map) = committed_pin.as_object_mut() {
        map.insert("evidence_prefix".to_string(), evidence_prefix);
        map.insert("evidence_refs".to_string(), Value::Array(vec![commit_ref]));
    }
    returned_map.insert("retention_pin".to_string(), committed_pin);
    validate(OUTPUT_SCHEMA, returned)
}

/// Reconstruct the exact complete `LogicalRow` from the archive's immutable
/// local extents.
///
/// Accepts either a complete `ArchiveRecord` (whose embedded payload is
/// verified against the reconstruction, never trusted as the result) or the
/// `root` artifact reference to the canonical storage manifest. The
/// registration document and every published domain document named by the
/// manifest are read back through the artifact store, verified against their
/// content digests, parsed as canonical snapshots, and composed under the
/// archived seal. Current journal/peer state is never consulted, zero slots
/// stay typed `Missing`, and a missing extent is an integrity fault.
pub fn expand_archive(
    artifacts: &dyn ArtifactStore,
    grant: &Grant,
    root: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    grant_facts(grant)?;
    let input = record_value(root).as_object().ok_or_else(|| {
        fault(
            "invalid_root",
            "archive root must be an ArchiveRecord object or an artifact reference".to_string(),
        )
    })?;
    let (manifest, expected_payload) = match input.get("record_type").and_then(Value::as_str) {
        Some(ARCHIVE_RECORD) => {
            let root_reference = input.get("root").filter(|value| !is_missing(value)).ok_or_else(
                || {
                    fault(
                        "invalid_root",
                        "archive record must name the artifact root of its storage manifest"
                            .to_string(),
                    )
                },
            )?;
            let embedded = input
                .get("storage_manifest")
                .filter(|value| !is_missing(value))
                .cloned()
                .ok_or_else(|| {
                    fault(
                        "invalid_root",
                        "archive record must carry its storage manifest".to_string(),
                    )
                })?;
            let payload = input
                .get("payload_json")
                .filter(|value| !is_missing(value))
                .cloned()
                .ok_or_else(|| {
                    fault(
                        "invalid_root",
                        "archive record must carry the complete prior logical row".to_string(),
                    )
                })?;
            let bytes = read_artifact_bytes(
                artifacts,
                grant,
                root_reference,
                "archive storage manifest",
            )?;
            let parsed = parse_storage_manifest(&bytes)?;
            if parsed != embedded {
                return Err(fault(
                    "archive_integrity",
                    "embedded storage manifest disagrees with the canonical manifest bytes named by the archive root"
                        .to_string(),
                ));
            }
            (embedded, Some(payload))
        }
        _ if input.contains_key("digest") && input.contains_key("size_bytes") => {
            let reference = Value::Object(input.clone());
            let bytes = read_artifact_bytes(
                artifacts,
                grant,
                &reference,
                "archive storage manifest",
            )?;
            (parse_storage_manifest(&bytes)?, None)
        }
        _ => {
            return Err(fault(
                "invalid_root",
                "archive root must be a logical_row_archive record or a content-addressed artifact reference"
                    .to_string(),
            ))
        }
    };

    let row = reconstruct_row(artifacts, grant, &manifest)?;
    if let Some(expected) = expected_payload {
        if expected != *record_value(&row) {
            return Err(fault(
                "archive_integrity",
                "expanded row does not equal the archived payload_json; expansion never inserts defaults, redacts, or upgrades revisions"
                    .to_string(),
            ));
        }
    }
    Ok(row)
}

// ---------------------------------------------------------------------------
// Request parsing
// ---------------------------------------------------------------------------

struct NewCrawlerRequest {
    revision: u64,
    previous_revision: u64,
    value: Value,
    writer_id: String,
    evidence_prefix: Value,
    evidence_refs: Vec<Value>,
}

#[derive(Debug)]
struct DeclaredOld {
    revision: u64,
    record_digest: String,
}

fn parse_new_crawler(
    request: &Map<String, Value>,
    facts: &GrantFacts,
    entity: &Value,
    registration_digest: &str,
) -> Result<NewCrawlerRequest, Fault> {
    let value = request
        .get("new_crawler")
        .filter(|value| !is_missing(value))
        .cloned()
        .ok_or_else(|| {
            fault(
                "invalid_new_crawler",
                "replacement requires the complete new crawler revision document".to_string(),
            )
        })?;
    let map = value.as_object().ok_or_else(|| {
        fault(
            "invalid_new_crawler",
            "new_crawler must be a complete owned revision object".to_string(),
        )
    })?;
    if let Some(Value::String(kind)) = established(map, "record_type") {
        if kind != OWNED_REVISION {
            return Err(fault(
                "invalid_new_crawler",
                format!("new_crawler record_type must be {OWNED_REVISION:?}, not {kind:?}"),
            ));
        }
    }
    if let Some(Value::String(domain)) = established(map, "domain") {
        if domain != "crawler" {
            return Err(fault(
                "invalid_new_crawler",
                format!("new_crawler domain must be \"crawler\", not {domain:?}"),
            ));
        }
    }
    if let Some(declared_entity) = established(map, "entity") {
        if declared_entity != entity {
            return Err(fault(
                "invalid_new_crawler",
                "new_crawler entity disagrees with the replacement entity".to_string(),
            ));
        }
    }
    if let Some(Value::String(declared)) = established(map, "registration_digest") {
        if declared != registration_digest {
            return Err(fault(
                "invalid_new_crawler",
                "new_crawler registration digest disagrees with the request registration"
                    .to_string(),
            ));
        }
    }
    if let Some(Value::String(owner)) = established(map, "owner_domain") {
        if owner != facts.owner_domain.as_str() {
            return Err(fault(
                "owner_mismatch",
                format!(
                    "new_crawler names owner {owner:?} but the replacement commits inside {:?}",
                    facts.owner_domain
                ),
            ));
        }
    }
    let revision = required_u64(map, "revision", "invalid_new_crawler", "new_crawler")?;
    if revision == 0 {
        return Err(fault(
            "invalid_new_crawler",
            "new crawler revision must be positive".to_string(),
        ));
    }
    let previous_revision = required_u64(
        map,
        "previous_revision",
        "invalid_new_crawler",
        "new_crawler",
    )?;
    let value = map
        .get("value")
        .filter(|value| !is_missing(value))
        .cloned()
        .ok_or_else(|| {
            fault(
                "invalid_new_crawler",
                "new_crawler requires the complete crawler value".to_string(),
            )
        })?;
    if !value.is_object() {
        return Err(fault(
            "invalid_new_crawler",
            "new_crawler value must be a complete object".to_string(),
        ));
    }
    let writer_id = match optional_nonempty(map, "writer_id")? {
        Some(writer) => writer,
        None => facts.producer_id.clone(),
    };
    let evidence_prefix = match established(map, "evidence_prefix") {
        Some(value @ Value::Object(_)) => value.clone(),
        Some(_) => {
            return Err(fault(
                "invalid_new_crawler",
                "new_crawler evidence_prefix must be a JournalPrefix object".to_string(),
            ))
        }
        None => missing(
            "not_observed",
            "the commit event establishes the new revision evidence prefix",
        ),
    };
    let evidence_refs = match map.get("evidence_refs") {
        None => Vec::new(),
        Some(value) if is_missing(value) => Vec::new(),
        Some(Value::Array(items)) => {
            for (index, item) in items.iter().enumerate() {
                if !item.is_object() {
                    return Err(fault(
                        "invalid_new_crawler",
                        format!("new_crawler evidence_refs[{index}] must be an evidence reference"),
                    ));
                }
            }
            items.clone()
        }
        Some(_) => {
            return Err(fault(
                "invalid_new_crawler",
                "new_crawler evidence_refs must be an array".to_string(),
            ))
        }
    };
    Ok(NewCrawlerRequest {
        revision,
        previous_revision,
        value,
        writer_id,
        evidence_prefix,
        evidence_refs,
    })
}

fn parse_declared_old(request: &Map<String, Value>) -> Result<Option<DeclaredOld>, Fault> {
    let value = match request.get("old_crawler") {
        None => return Ok(None),
        Some(value) if is_missing(value) => return Ok(None),
        Some(value) => value,
    };
    let map = value.as_object().ok_or_else(|| {
        fault(
            "invalid_request",
            "old_crawler must be a NonzeroDomainPin object".to_string(),
        )
    })?;
    let revision = required_u64(map, "revision", "invalid_request", "old_crawler")?;
    let record_digest = required_str(map, "record_digest", "invalid_request", "old_crawler")?;
    let record_digest = normalize_digest(record_digest, "old_crawler.record_digest")?;
    Ok(Some(DeclaredOld {
        revision,
        record_digest,
    }))
}

fn registration_digest_of(
    request: &Map<String, Value>,
    registration: &CheckedRecord,
) -> Result<String, Fault> {
    let map = as_object(registration, "invalid_registration", "registration")?;
    let declared = optional_nonempty(request, "registration_digest")?
        .or_else(|| {
            established(map, "registration_digest")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .or_else(|| {
            established(map, "digest")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .ok_or_else(|| {
            fault(
                "missing_registration_digest",
                "registration requires the digest that fixes its domain field set".to_string(),
            )
        })?;
    let digest = normalize_digest(&declared, "registration_digest")?;
    // Publication seals compare the registration digest literally, so the
    // archived document must carry the same bare 64-hex text the seal pins.
    if let Some(Value::String(inner)) = established(map, "registration_digest") {
        if !is_hex64(inner) {
            return Err(fault(
                "invalid_registration",
                "registration.registration_digest must be the bare 64 lowercase hex digest the seal pins"
                    .to_string(),
            ));
        }
        if inner != &digest {
            return Err(fault(
                "registration_mismatch",
                "request registration digest disagrees with the registration document".to_string(),
            ));
        }
    }
    Ok(digest)
}

fn verify_registration_identity(entity: &Value, registration: &CheckedRecord) -> Result<(), Fault> {
    let map = as_object(registration, "invalid_registration", "registration")?;
    if let Some(declared_entity) = established(map, "entity") {
        if declared_entity != entity {
            return Err(fault(
                "entity_mismatch",
                "registration entity disagrees with the replacement entity".to_string(),
            ));
        }
    }
    if let Some(Value::Array(domains)) = established(map, "domains") {
        let declared: Vec<&str> = domains.iter().filter_map(Value::as_str).collect();
        if !declared.is_empty() && declared.iter().any(|domain| !JOB_DOMAINS.contains(domain)) {
            return Err(fault(
                "incomplete_row",
                "registration declares a domain that is not a job domain slot".to_string(),
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Journal state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct StoredReceipt {
    entity_key: String,
    registration_digest: String,
    view: String,
    domain: String,
    revision: u64,
    document: Value,
    document_digest: String,
    publication_ref: Value,
}

struct JournalState {
    receipts: Vec<StoredReceipt>,
}

fn read_journal(
    store: &dyn OwnerStore,
    grant: &Grant,
    journal_id: &str,
    expected_owner: &str,
) -> Result<JournalState, Fault> {
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
            format!("expected {JOURNAL_VIEW:?}, got {record_type:?}"),
        ));
    }
    let view_journal = required_str(map, "journal_id", "invalid_journal_view", "journal view")?;
    if view_journal != journal_id {
        return Err(fault(
            "invalid_journal_view",
            "journal view names a different journal than the query".to_string(),
        ));
    }
    let owner_domain = required_str(map, "owner_domain", "invalid_journal_view", "journal view")?;
    if owner_domain != expected_owner {
        return Err(fault(
            "foreign_owner",
            format!(
                "journal {journal_id:?} belongs to {owner_domain:?}, not the grant's {expected_owner:?}"
            ),
        ));
    }
    let last_sequence = required_u64(map, "last_sequence", "invalid_journal_view", "journal view")?;
    if last_sequence == 0 {
        return Err(fault(
            "invalid_journal_view",
            "an admitted journal has at least its manifest-admission event".to_string(),
        ));
    }
    let head_hash = required_str(map, "head_hash", "invalid_journal_view", "journal view")?;
    if !is_hex64(head_hash) {
        return Err(fault(
            "invalid_journal_view",
            "journal head_hash must be 64 lowercase hex characters".to_string(),
        ));
    }
    let events = match map.get("events") {
        Some(Value::Array(events)) => events,
        _ => {
            return Err(fault(
                "invalid_journal_view",
                "journal view requires an established events array".to_string(),
            ))
        }
    };
    if events.len() as u64 != last_sequence {
        return Err(fault(
            "invalid_journal_view",
            "journal prefix length disagrees with its events; an incomplete prefix is not a durable read"
                .to_string(),
        ));
    }

    let mut receipts: Vec<StoredReceipt> = Vec::new();
    let mut per_view: BTreeMap<(String, String, String, u64), String> = BTreeMap::new();
    for (index, event) in events.iter().enumerate() {
        let position = index as u64 + 1;
        let event_map = event.as_object().ok_or_else(|| {
            fault(
                "invalid_journal_view",
                format!("journal event {position} must be an object"),
            )
        })?;
        let sequence = required_u64(
            event_map,
            "journal_sequence",
            "invalid_journal_view",
            "journal event",
        )?;
        if sequence != position {
            return Err(fault(
                "invalid_journal_view",
                format!(
                    "journal event {position} claims sequence {sequence}; prefixes are contiguous and ordered"
                ),
            ));
        }
        let event_id = required_str(
            event_map,
            "event_id",
            "invalid_journal_view",
            "journal event",
        )?;
        let event_hash = required_str(
            event_map,
            "event_hash",
            "invalid_journal_view",
            "journal event",
        )?;
        let payload = event_map
            .get("payload")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                fault(
                    "invalid_journal_view",
                    format!("journal event {sequence} requires a payload object"),
                )
            })?;
        let data = match payload.get("data") {
            Some(Value::Object(data)) => data,
            _ => continue,
        };
        let Some(Value::Object(receipt)) = data.get(PUBLICATION_RECEIPT) else {
            continue;
        };
        let receipt = parse_stored_receipt(
            receipt, journal_id, sequence, event_id, event_hash, position,
        )?;
        match per_view.get(&(
            receipt.entity_key.clone(),
            receipt.view.clone(),
            receipt.domain.clone(),
            receipt.revision,
        )) {
            Some(existing) if existing == &receipt.document_digest => continue,
            Some(existing) => {
                return Err(fault(
                    "integrity_conflict",
                    format!(
                        "journal contains two different documents for one publication key: {existing} and {}",
                        receipt.document_digest
                    ),
                ))
            }
            None => {
                per_view.insert(
                    (
                        receipt.entity_key.clone(),
                        receipt.view.clone(),
                        receipt.domain.clone(),
                        receipt.revision,
                    ),
                    receipt.document_digest.clone(),
                );
            }
        }
        receipts.push(receipt);
    }

    Ok(JournalState { receipts })
}

fn parse_stored_receipt(
    receipt: &Map<String, Value>,
    journal_id: &str,
    sequence: u64,
    event_id: &str,
    event_hash: &str,
    position: u64,
) -> Result<StoredReceipt, Fault> {
    let what = format!("publication_receipt at journal sequence {position}");
    match established(receipt, "record_type") {
        Some(Value::String(kind)) if kind == PUBLICATION_RECEIPT => {}
        _ => {
            return Err(fault(
                "invalid_journal_view",
                format!("{what} lacks record_type={PUBLICATION_RECEIPT:?}"),
            ))
        }
    }
    let entity = established(receipt, "entity")
        .cloned()
        .ok_or_else(|| fault("invalid_journal_view", format!("{what} lacks an entity")))?;
    let entity_key = entity_key(&entity)?;
    let registration_digest = required_str(
        receipt,
        "registration_digest",
        "invalid_journal_view",
        &what,
    )?
    .to_string();
    if !is_hex64(&registration_digest) {
        return Err(fault(
            "invalid_journal_view",
            format!("{what} registration_digest must be 64 lowercase hex characters"),
        ));
    }
    let view = required_str(receipt, "view", "invalid_journal_view", &what)?.to_string();
    let domain = required_str(receipt, "domain", "invalid_journal_view", &what)?.to_string();
    let revision = required_u64(receipt, "revision", "invalid_journal_view", &what)?;
    if revision == 0 {
        return Err(fault(
            "invalid_journal_view",
            format!("{what} journals revision zero; zero is an unpublished view slot"),
        ));
    }
    required_u64(receipt, "previous_revision", "invalid_journal_view", &what)?;
    required_str(receipt, "receipt_id", "invalid_journal_view", &what)?;
    let document = match established(receipt, "document") {
        Some(Value::Object(document)) => Value::Object(document.clone()),
        _ => {
            return Err(fault(
                "invalid_journal_view",
                format!("{what} requires an established document reference"),
            ))
        }
    };
    let document_digest = match document.get("digest") {
        Some(Value::String(digest)) if is_hex64(digest) => digest.clone(),
        _ => {
            return Err(fault(
                "invalid_journal_view",
                format!("{what} document reference lacks a 64-character digest"),
            ))
        }
    };
    Ok(StoredReceipt {
        entity_key,
        registration_digest,
        view,
        domain,
        revision,
        document,
        document_digest,
        publication_ref: json!({
            "journal_id": journal_id,
            "sequence": sequence,
            "event_id": event_id,
            "event_hash": event_hash,
            "pointer": "/payload/data/publication_receipt",
        }),
    })
}

fn pointer<'a>(
    state: &'a JournalState,
    entity_key: &str,
    view: &str,
    domain: &str,
) -> Option<&'a StoredReceipt> {
    state
        .receipts
        .iter()
        .filter(|receipt| {
            receipt.entity_key == entity_key && receipt.view == view && receipt.domain == domain
        })
        .max_by_key(|receipt| receipt.revision)
}

// ---------------------------------------------------------------------------
// Seal handling
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct SealSlot {
    revision: u64,
    document_digest: Option<String>,
    publication_ref: Option<Value>,
}

fn parse_seal_slots(seal: &CheckedRecord) -> Result<BTreeMap<String, SealSlot>, Fault> {
    let map = as_object(seal, "invalid_seal", "seal")?;
    if let Some(Value::String(kind)) = established(map, "record_type") {
        if kind != SEAL_POINT {
            return Err(fault(
                "invalid_seal",
                format!("expected a {SEAL_POINT:?} record, got {kind:?}"),
            ));
        }
    }
    let vector = established(map, "version_vector")
        .or_else(|| established(map, "vector"))
        .ok_or_else(|| {
            fault(
                "invalid_seal",
                "seal requires an exact version_vector".to_string(),
            )
        })?;
    let entries = vector.as_array().ok_or_else(|| {
        fault(
            "invalid_seal",
            "seal version_vector must be an array of pinned slots".to_string(),
        )
    })?;
    let mut slots: BTreeMap<String, SealSlot> = BTreeMap::new();
    for (index, entry) in entries.iter().enumerate() {
        let what = format!("version_vector[{index}]");
        let entry = entry
            .as_object()
            .ok_or_else(|| fault("invalid_seal", format!("{what} must be an object")))?;
        let domain = required_str(entry, "domain", "invalid_seal", &what)?.to_string();
        if !JOB_DOMAINS.contains(&domain.as_str()) {
            return Err(fault(
                "invalid_seal",
                format!("seal pins undeclared domain {domain:?} for a job entity"),
            ));
        }
        let revision = required_u64(entry, "revision", "invalid_seal", &what)?;
        let (document_digest, publication_ref) = if revision == 0 {
            (None, None)
        } else {
            let digest = required_str(entry, "document_digest", "invalid_seal", &what)?;
            if !is_hex64(digest) {
                return Err(fault(
                    "invalid_seal",
                    format!("{what} document_digest must be 64 lowercase hex characters"),
                ));
            }
            match established(entry, "document") {
                Some(Value::Object(_)) => {}
                _ => {
                    return Err(fault(
                        "invalid_seal",
                        format!("{what} requires an established document reference"),
                    ))
                }
            }
            let publication_ref = match established(entry, "publication_ref") {
                Some(Value::Object(reference)) => Value::Object(reference.clone()),
                _ => {
                    return Err(fault(
                        "invalid_seal",
                        format!("{what} requires an established publication reference"),
                    ))
                }
            };
            (Some(digest.to_string()), Some(publication_ref))
        };
        let slot = SealSlot {
            revision,
            document_digest,
            publication_ref,
        };
        if slots.insert(domain.clone(), slot).is_some() {
            return Err(fault(
                "invalid_seal",
                format!("seal names domain {domain:?} more than once"),
            ));
        }
    }
    for domain in JOB_DOMAINS {
        if !slots.contains_key(*domain) {
            return Err(fault(
                "invalid_seal",
                format!("replacement seal must pin the {domain:?} slot"),
            ));
        }
    }
    Ok(slots)
}

fn verify_seal(
    seal: &CheckedRecord,
    entity: &Value,
    registration_digest: &str,
    view: &str,
    state: &JournalState,
    entity_key: &str,
) -> Result<(), Fault> {
    let map = as_object(seal, "invalid_seal", "seal")?;
    let sealed_entity = established(map, "entity")
        .cloned()
        .ok_or_else(|| fault("invalid_seal", "seal requires its entity".to_string()))?;
    if &sealed_entity != entity {
        return Err(fault(
            "invalid_seal",
            "seal pins a different entity than the replacement".to_string(),
        ));
    }
    let sealed_registration = required_str(map, "registration_digest", "invalid_seal", "seal")?;
    if sealed_registration != registration_digest {
        return Err(fault(
            "invalid_seal",
            "seal pins a different registration than the replacement".to_string(),
        ));
    }
    let sealed_view = established(map, "view")
        .or_else(|| established(map, "view_id"))
        .and_then(Value::as_str)
        .ok_or_else(|| fault("invalid_seal", "seal requires its read view".to_string()))?;
    if sealed_view != view {
        return Err(fault(
            "invalid_seal",
            format!("seal belongs to view {sealed_view:?}, not the replacement's {view:?}"),
        ));
    }
    let name = established(map, "name")
        .or_else(|| established(map, "seal_name"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            fault(
                "invalid_seal",
                "seal requires its name; a replacement archive is taken under fetch_key_replacement"
                    .to_string(),
            )
        })?;
    if name != REPLACEMENT_SEAL_NAME {
        return Err(fault(
            "invalid_seal",
            format!(
                "seal name {name:?} is not {REPLACEMENT_SEAL_NAME:?}; a replacement archive is never taken under another seal"
            ),
        ));
    }
    match map.get("input_prefix") {
        Some(Value::Object(prefix)) => {
            required_str(prefix, "journal_id", "invalid_seal", "seal input_prefix")?;
            let sequence =
                required_u64(prefix, "last_sequence", "invalid_seal", "seal input_prefix")?;
            if sequence == 0 {
                return Err(fault(
                    "invalid_seal",
                    "seal input_prefix must include at least the selection event".to_string(),
                ));
            }
            let head = required_str(prefix, "head_hash", "invalid_seal", "seal input_prefix")?;
            if !is_hex64(head) {
                return Err(fault(
                    "invalid_seal",
                    "seal input_prefix head_hash must be 64 lowercase hex characters".to_string(),
                ));
            }
        }
        _ => {
            return Err(fault(
                "invalid_seal",
                "seal requires an established input_prefix naming the selection event".to_string(),
            ))
        }
    }
    let slots = parse_seal_slots(seal)?;
    if let Some(crawler) = slots.get("crawler") {
        if crawler.revision == 0 {
            return Err(fault(
                "invalid_seal",
                "replacement seal must pin a nonzero crawler revision".to_string(),
            ));
        }
    }
    verify_pointers(seal, &slots, state, entity_key, view, registration_digest)
}

fn verify_pointers(
    seal: &CheckedRecord,
    slots: &BTreeMap<String, SealSlot>,
    state: &JournalState,
    entity_key: &str,
    view: &str,
    registration_digest: &str,
) -> Result<(), Fault> {
    let seal_map = as_object(seal, "invalid_seal", "seal")?;
    let sealed_view = established(seal_map, "view")
        .or_else(|| established(seal_map, "view_id"))
        .and_then(Value::as_str)
        .unwrap_or(view);
    for domain in JOB_DOMAINS {
        let slot = match slots.get(*domain) {
            Some(slot) => slot,
            None => continue,
        };
        match pointer(state, entity_key, sealed_view, domain) {
            None => {
                if slot.revision != 0 {
                    return Err(fault(
                        "publication_race",
                        format!(
                            "seal pins domain {domain:?} at revision {} but the local view has no publication; reselect before archiving",
                            slot.revision
                        ),
                    ));
                }
            }
            Some(receipt) => {
                if receipt.registration_digest != registration_digest {
                    return Err(fault(
                        "registration_mismatch",
                        format!(
                            "domain {domain:?} is published under registration {}; the seal names {registration_digest}",
                            receipt.registration_digest
                        ),
                    ));
                }
                if slot.revision == 0 {
                    return Err(fault(
                        "publication_race",
                        format!(
                            "seal pins domain {domain:?} as unpublished but the local view published revision {}; reselect before archiving",
                            receipt.revision
                        ),
                    ));
                }
                if receipt.revision != slot.revision
                    || Some(receipt.document_digest.clone()) != slot.document_digest
                    || !publication_refs_agree(
                        &receipt.publication_ref,
                        slot.publication_ref.as_ref(),
                    )
                {
                    return Err(fault(
                        "publication_race",
                        format!(
                            "seal pins domain {domain:?} at revision {} / {}, but the local pointer is revision {} / {}; a changed publication forces reselection, never a mismatched archive",
                            slot.revision,
                            slot.document_digest.as_deref().unwrap_or(""),
                            receipt.revision,
                            receipt.document_digest
                        ),
                    ));
                }
            }
        }
    }
    Ok(())
}

fn publication_refs_agree(current: &Value, pinned: Option<&Value>) -> bool {
    let pinned = match pinned {
        Some(pinned) => pinned,
        None => return true,
    };
    for field in ["journal_id", "sequence", "event_hash"] {
        if current.get(field) != pinned.get(field) {
            return false;
        }
    }
    true
}

fn commit_evidence_refs(seal: &CheckedRecord) -> Result<Vec<Value>, Fault> {
    let map = as_object(seal, "invalid_seal", "seal")?;
    match established(map, "selection_event") {
        Some(Value::Object(event)) => {
            for field in [
                "journal_id",
                "sequence",
                "event_id",
                "event_hash",
                "pointer",
            ] {
                if event.get(field).is_none() {
                    return Err(fault(
                        "invalid_seal",
                        format!(
                            "seal selection_event is not a complete evidence reference (missing {field:?})"
                        ),
                    ));
                }
            }
            Ok(vec![Value::Object(event.clone())])
        }
        _ => Err(fault(
            "invalid_seal",
            "seal requires the journaled selection event it includes in the input prefix"
                .to_string(),
        )),
    }
}

// ---------------------------------------------------------------------------
// Domain extents
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct PublishedDomain {
    revision: u64,
    document: Value,
    document_record: CheckedRecord,
    publication_ref: Value,
    snapshot: Value,
}

fn read_published_domain(
    artifacts: &dyn ArtifactStore,
    grant: &Grant,
    receipt: &StoredReceipt,
    domain: &str,
) -> Result<PublishedDomain, Fault> {
    let (snapshot, document) = read_verified_document(
        artifacts,
        grant,
        &receipt.document,
        &format!("published {domain} revision"),
    )?;
    let document_digest = document
        .get("digest")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if document_digest != receipt.document_digest {
        return Err(fault(
            "artifact_integrity",
            format!(
                "{domain} document digest {document_digest} disagrees with the journaled receipt {}",
                receipt.document_digest
            ),
        ));
    }
    let document_record = validate(OUTPUT_SCHEMA, document.clone())?;
    Ok(PublishedDomain {
        revision: receipt.revision,
        document,
        document_record,
        publication_ref: receipt.publication_ref.clone(),
        snapshot,
    })
}

/// Read one archived component by its content address.
///
/// The bytes must resolve under the reference (including size and digest
/// verification in the store), parse as JSON, and survive the missingness
/// gate. The reconstructed *value* is what expansion composes; the document's
/// exact byte encoding is covered by its own content-address digest, so no
/// second canonicalization is invented here.
fn read_verified_document(
    artifacts: &dyn ArtifactStore,
    grant: &Grant,
    reference: &Value,
    what: &str,
) -> Result<(Value, Value), Fault> {
    let bytes = read_artifact_bytes(artifacts, grant, reference, what)?;
    let parsed: Value = serde_json::from_slice(&bytes).map_err(|err| {
        fault(
            "invalid_document",
            format!("{what} bytes are not a JSON document: {err}"),
        )
    })?;
    let checked = validate(OUTPUT_SCHEMA, parsed).map_err(|err| {
        fault(
            "invalid_document",
            format!(
                "{what} violates the missingness gate: {} ({})",
                err.code, err.detail
            ),
        )
    })?;
    Ok((record_value(&checked).clone(), reference.clone()))
}

// ---------------------------------------------------------------------------
// Archive construction
// ---------------------------------------------------------------------------

struct ArchiveBuild {
    archive: CheckedRecord,
    root: CheckedRecord,
    registration_ref: CheckedRecord,
}

fn build_archive(
    artifacts: &dyn ArtifactStore,
    grant: &Grant,
    entity: &Value,
    registration: &CheckedRecord,
    seal: &CheckedRecord,
    view: &str,
    crawler: &PublishedDomain,
    downstream: Option<&PublishedDomain>,
) -> Result<ArchiveBuild, Fault> {
    let registration_map = as_object(registration, "invalid_registration", "registration")?;
    let registration_restricted = registration_map
        .get("restricted")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || registration_map.get("access").and_then(Value::as_str) == Some("restricted");

    // The complete registration document is an immutable extent; the archive
    // root protects it along with every published domain document.
    let registration_bytes = canonical_bytes(registration)?;
    let registration_ref = artifacts.install(
        grant,
        &registration_bytes,
        "application/json",
        registration_restricted,
    )?;
    verify_installed(
        artifacts,
        grant,
        &registration_ref,
        &registration_bytes,
        "registration document",
    )?;

    let mut supplied_domains = vec![supplied_domain_record("crawler", crawler)?];
    if let Some(downstream) = downstream {
        supplied_domains.push(supplied_domain_record("downstream", downstream)?);
    }

    let archived_seal = seal_with_contract_aliases(seal, view, crawler, downstream)?;
    let payload = compose_row(&archived_seal, registration, &supplied_domains)?;

    // Completeness self-check: the row must contain the registration and the
    // exact sealed snapshots, never a diff or a crawler-only row.
    let payload_map = as_object(&payload, "incomplete_row", "logical row")?;
    if payload_map.get("record_type").and_then(Value::as_str) != Some(LOGICAL_ROW) {
        return Err(fault(
            "incomplete_row",
            "composed payload is not a complete logical row".to_string(),
        ));
    }
    if payload_map.get("registration") != Some(record_value(registration)) {
        return Err(fault(
            "incomplete_row",
            "logical row must embed the complete registration".to_string(),
        ));
    }
    let domain_map = payload_map
        .get("domains")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            fault(
                "incomplete_row",
                "logical row carries no domain map".to_string(),
            )
        })?;
    for domain in JOB_DOMAINS {
        if !domain_map.contains_key(*domain) {
            return Err(fault(
                "incomplete_row",
                format!("logical row is missing the {} slot", domain),
            ));
        }
    }
    let row_crawler = &domain_map["crawler"];
    if row_crawler.get("snapshot") != Some(&crawler.snapshot) {
        return Err(fault(
            "incomplete_row",
            "logical row crawler snapshot is not the complete sealed revision".to_string(),
        ));
    }
    match downstream {
        Some(downstream) => {
            if domain_map["downstream"].get("snapshot") != Some(&downstream.snapshot) {
                return Err(fault(
                    "incomplete_row",
                    "logical row downstream snapshot is not the complete sealed revision"
                        .to_string(),
                ));
            }
        }
        None => {
            let slot = &domain_map["downstream"];
            if slot.get("revision").and_then(Value::as_u64) != Some(0)
                || !slot.get("snapshot").map(is_missing).unwrap_or(false)
            {
                return Err(fault(
                    "incomplete_row",
                    "unpublished downstream slot must remain an exact typed Missing zero slot"
                        .to_string(),
                ));
            }
        }
    }

    let mut domains = Map::new();
    domains.insert("crawler".to_string(), archived_slot(crawler));
    match downstream {
        Some(downstream) => {
            domains.insert("downstream".to_string(), archived_slot(downstream));
        }
        None => {
            domains.insert(
                "downstream".to_string(),
                json!({
                    "revision": 0,
                    "value": missing(
                        "not_observed",
                        "no downstream publication exists in the sealed ingest-side view",
                    ),
                }),
            );
        }
    }

    let restricted = registration_restricted
        || reference_is_restricted(&crawler.document)
        || downstream
            .map(|domain| reference_is_restricted(&domain.document))
            .unwrap_or(false);

    let storage_manifest = validate(
        OUTPUT_SCHEMA,
        json!({
            "encoding": STORAGE_ENCODING,
            "schema_version": SCHEMA_VERSION,
            "entity": entity,
            "registration": record_value(&registration_ref).clone(),
            "domains": Value::Object(domains),
            "seal_point": record_value(&archived_seal).clone(),
        }),
    )?;
    let manifest_bytes = canonical_bytes(&storage_manifest)?;
    let root = artifacts.install(grant, &manifest_bytes, "application/json", restricted)?;
    verify_installed(
        artifacts,
        grant,
        &root,
        &manifest_bytes,
        "archive storage manifest",
    )?;
    let root_digest = record_value(&root)
        .get("digest")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if root_digest != digest_bytes(&manifest_bytes) {
        return Err(fault(
            "artifact_integrity",
            "archive root does not hash the canonical storage-manifest bytes".to_string(),
        ));
    }

    let archive = validate(
        OUTPUT_SCHEMA,
        json!({
            "record_type": ARCHIVE_RECORD,
            "schema_version": SCHEMA_VERSION,
            "root": record_value(&root).clone(),
            "storage_manifest": record_value(&storage_manifest).clone(),
            "payload_json": record_value(&payload).clone(),
        }),
    )?;
    Ok(ArchiveBuild {
        archive,
        root,
        registration_ref,
    })
}

fn supplied_domain_record(
    domain: &str,
    published: &PublishedDomain,
) -> Result<CheckedRecord, Fault> {
    validate(
        OUTPUT_SCHEMA,
        json!({
            "domain": domain,
            "revision": published.revision,
            "document": published.document,
            "publication_ref": published.publication_ref,
            "value": published.snapshot,
        }),
    )
}

fn archived_slot(published: &PublishedDomain) -> Value {
    json!({
        "revision": published.revision,
        "document": published.document,
        "publication_ref": published.publication_ref,
    })
}

fn reference_is_restricted(reference: &Value) -> bool {
    reference.get("access").and_then(Value::as_str) == Some("restricted")
}

fn seal_with_contract_aliases(
    seal: &CheckedRecord,
    view: &str,
    crawler: &PublishedDomain,
    downstream: Option<&PublishedDomain>,
) -> Result<CheckedRecord, Fault> {
    let map = as_object(seal, "invalid_seal", "seal")?;
    let mut out = map.clone();
    out.insert("name".to_string(), json!(REPLACEMENT_SEAL_NAME));
    out.insert("view_id".to_string(), json!(view));
    let mut versions = Map::new();
    versions.insert("crawler".to_string(), json!(crawler.revision));
    versions.insert(
        "downstream".to_string(),
        json!(downstream.map(|domain| domain.revision).unwrap_or(0)),
    );
    out.insert("versions".to_string(), Value::Object(versions));
    let sealed_at = match established(map, "time") {
        Some(value) => value.clone(),
        None => missing(
            "not_observed",
            "the seal selection event establishes the selection time",
        ),
    };
    out.insert("sealed_at".to_string(), sealed_at);
    let evidence_refs = match established(map, "support") {
        Some(Value::Array(items)) if !items.is_empty() => Value::Array(items.clone()),
        _ => match established(map, "selection_event") {
            Some(event @ Value::Object(_)) => Value::Array(vec![event.clone()]),
            _ => Value::Array(vec![missing(
                "not_observed",
                "the seal selection event is the only available support",
            )]),
        },
    };
    out.insert("evidence_refs".to_string(), evidence_refs);
    validate(OUTPUT_SCHEMA, Value::Object(out))
}

fn verify_installed(
    artifacts: &dyn ArtifactStore,
    grant: &Grant,
    reference: &CheckedRecord,
    bytes: &[u8],
    what: &str,
) -> Result<(), Fault> {
    let readback = artifacts.read(grant, reference).map_err(|err| {
        fault(
            &err.code,
            format!(
                "{what} could not be verified after install: {} ({})",
                err.code, err.detail
            ),
        )
    })?;
    if readback != bytes {
        return Err(fault(
            "artifact_integrity",
            format!("{what} bytes changed between install and verification"),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Replacement and retention records
// ---------------------------------------------------------------------------

/// Normalize the candidate value: it must be a complete object and it must
/// carry the lineage slot the commit authors.
fn prepare_candidate(candidate: &Value) -> Result<Value, Fault> {
    let mut candidate_value = candidate.clone();
    let candidate_map = candidate_value.as_object_mut().ok_or_else(|| {
        fault(
            "invalid_new_crawler",
            "new crawler value must be a complete object".to_string(),
        )
    })?;
    if !candidate_map.contains_key("replacement_lineage") {
        candidate_map.insert(
            "replacement_lineage".to_string(),
            missing(
                "not_applicable",
                "the replacement commit authors the backward archive link",
            ),
        );
    }
    Ok(candidate_value)
}

/// Prove the candidate changes the fetch key of `old_value`.
///
/// The acquisition decision seam is exercised when the prior row is complete:
/// a same-key candidate is an acquisition no-op and never yields an archive.
fn ensure_key_differs(old_value: &Value, candidate: &Value) -> Result<(), Fault> {
    let old_map = old_value.as_object().ok_or_else(|| {
        fault(
            "missing_prior_row",
            "published crawler value must be a complete object".to_string(),
        )
    })?;
    let old_key = fetch_key_of(old_value)?;
    let candidate_key = fetch_key_of(candidate)?;
    if old_key == candidate_key {
        return Err(fault(
            "fetch_key_unchanged",
            "the fetch key is unchanged; an identical fetch key is an acquisition no-op and never creates a replacement archive"
                .to_string(),
        ));
    }
    if old_map.contains_key("replacement_lineage") {
        let old_record = validate(OUTPUT_SCHEMA, old_value.clone())?;
        let candidate_record = validate(OUTPUT_SCHEMA, candidate.clone())?;
        match decide_acquisition_write(&old_record, &candidate_record) {
            Ok(_) => Err(fault(
                "fetch_key_unchanged",
                "the acquisition decision reports a same-key no-op; no archive is created"
                    .to_string(),
            )),
            Err(err) if err.code == "fetch_key_changed" => Ok(()),
            Err(err) => Err(fault(
                "invalid_new_crawler",
                format!(
                    "new crawler value is not a complete acquisition change: {} ({})",
                    err.code, err.detail
                ),
            )),
        }
    } else {
        Ok(())
    }
}

fn build_new_crawler(
    request: &NewCrawlerRequest,
    facts: &GrantFacts,
    entity: &Value,
    registration_digest: &str,
    candidate_value: &Value,
    replacement_id: &str,
    prior_revision: u64,
    archive_root: &Value,
) -> Result<CheckedRecord, Fault> {
    let mut value = candidate_value.clone();
    let map = value.as_object_mut().ok_or_else(|| {
        fault(
            "invalid_new_crawler",
            "new crawler value must be a complete object".to_string(),
        )
    })?;
    if let Some(existing) = map
        .get("replacement_lineage")
        .filter(|value| !is_missing(value))
    {
        let existing = existing.as_object().ok_or_else(|| {
            fault(
                "invalid_lineage",
                "supplied replacement_lineage must be a ReplacementLink object".to_string(),
            )
        })?;
        if let Some(Value::String(declared_id)) = existing.get("replacement_id") {
            if declared_id != replacement_id {
                return Err(fault(
                    "invalid_lineage",
                    format!(
                        "supplied replacement_lineage names {declared_id:?}, but this change commits {replacement_id:?}"
                    ),
                ));
            }
        }
        if let Some(declared_prior) = existing
            .get("prior_crawler_revision")
            .and_then(Value::as_u64)
        {
            if declared_prior != prior_revision {
                return Err(fault(
                    "invalid_lineage",
                    format!(
                        "supplied replacement_lineage names prior revision {declared_prior}, but the sealed prior revision is {prior_revision}"
                    ),
                ));
            }
        }
    }
    map.insert(
        "replacement_lineage".to_string(),
        json!({
            "replacement_id": replacement_id,
            "prior_crawler_revision": prior_revision,
            "archive_root": archive_root.clone(),
        }),
    );
    validate(
        OUTPUT_SCHEMA,
        json!({
            "record_type": OWNED_REVISION,
            "schema_version": SCHEMA_VERSION,
            "entity": entity,
            "registration_digest": registration_digest,
            "domain": "crawler",
            "owner_domain": facts.owner_domain,
            "writer_id": request.writer_id,
            "revision": request.revision,
            "previous_revision": request.previous_revision,
            "evidence_prefix": request.evidence_prefix,
            "evidence_refs": Value::Array(request.evidence_refs.clone()),
            "value": value,
        }),
    )
}

#[allow(clippy::too_many_arguments)]
fn replacement_record(
    entity: &Value,
    registration_digest: &str,
    replacement_id: &str,
    old_revision: u64,
    old_digest: &str,
    old_key: &str,
    new_crawler: &CheckedRecord,
    archive_root: &Value,
    archived_vector: &Value,
    retention_pin_id: &str,
    support: &[Value],
) -> Result<CheckedRecord, Fault> {
    validate(
        OUTPUT_SCHEMA,
        json!({
            "record_type": REPLACEMENT_RECORD,
            "schema_version": SCHEMA_VERSION,
            "replacement_id": replacement_id,
            "entity": entity,
            "registration_digest": registration_digest,
            "old_crawler": {
                "revision": old_revision,
                "record_digest": old_digest,
            },
            "old_fetch_key": old_key,
            "new_crawler": record_value(new_crawler).clone(),
            "archive_root": archive_root.clone(),
            "archived_vector": archived_vector.clone(),
            "retention_pin_id": retention_pin_id,
            "commit_ref": missing(
                "not_observed",
                "the carrying commit event is the replacement reference",
            ),
            "evidence_prefix": missing(
                "not_observed",
                "the carrying commit event establishes the evidence prefix",
            ),
            "evidence_refs": Value::Array(support.to_vec()),
        }),
    )
}

fn verify_pin(
    pin: &CheckedRecord,
    archive_root: &CheckedRecord,
    dependencies: &[CheckedRecord],
) -> Result<(), Fault> {
    let map = as_object(pin, "invalid_pin", "retention pin")?;
    if map.get("state").and_then(Value::as_str) != Some("active") {
        return Err(fault(
            "invalid_pin",
            "a planned replacement pin must start active".to_string(),
        ));
    }
    let pinned_root = map
        .get("archive_root")
        .filter(|value| !is_missing(value))
        .ok_or_else(|| {
            fault(
                "invalid_pin",
                "retention pin carries no archive root".to_string(),
            )
        })?;
    if pinned_root.get("digest") != record_value(archive_root).get("digest") {
        return Err(fault(
            "invalid_pin",
            "retention pin does not protect the archive root it was planned for".to_string(),
        ));
    }
    let pinned_dependencies = map
        .get("dependencies")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            fault(
                "invalid_pin",
                "retention pin carries no dependency closure".to_string(),
            )
        })?;
    let mut pinned: Vec<&str> = pinned_dependencies
        .iter()
        .filter_map(|value| value.get("digest").and_then(Value::as_str))
        .collect();
    let mut expected: Vec<&str> = dependencies
        .iter()
        .filter_map(|value| record_value(value).get("digest").and_then(Value::as_str))
        .collect();
    pinned.sort_unstable();
    expected.sort_unstable();
    if pinned != expected {
        return Err(fault(
            "invalid_pin",
            "retention pin closure does not equal the archive's immutable dependency set"
                .to_string(),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Expansion
// ---------------------------------------------------------------------------

fn parse_storage_manifest(bytes: &[u8]) -> Result<Value, Fault> {
    let parsed: Value = serde_json::from_slice(bytes).map_err(|err| {
        fault(
            "non_canonical_manifest",
            format!("archive manifest bytes are not JSON: {err}"),
        )
    })?;
    let checked = validate(OUTPUT_SCHEMA, parsed).map_err(|err| {
        fault(
            "non_canonical_manifest",
            format!(
                "archive manifest violates the missingness gate: {} ({})",
                err.code, err.detail
            ),
        )
    })?;
    if canonical_bytes(&checked)? != bytes {
        return Err(fault(
            "non_canonical_manifest",
            "archive manifest bytes are not canonical JCS bytes; the root identity would not cover the stored bytes"
                .to_string(),
        ));
    }
    let value = record_value(&checked).clone();
    let map = value.as_object().ok_or_else(|| {
        fault(
            "non_canonical_manifest",
            "archive manifest must be an object".to_string(),
        )
    })?;
    if map.get("encoding").and_then(Value::as_str) != Some(STORAGE_ENCODING) {
        return Err(fault(
            "non_canonical_manifest",
            format!("archive manifest encoding must be {STORAGE_ENCODING:?}"),
        ));
    }
    if map.get("schema_version").and_then(Value::as_str) != Some(SCHEMA_VERSION) {
        return Err(fault(
            "non_canonical_manifest",
            "archive manifest schema version is not the contract version".to_string(),
        ));
    }
    for field in ["entity", "registration", "domains", "seal_point"] {
        match map.get(field) {
            Some(value) if !is_missing(value) && value.is_object() => {}
            _ => {
                return Err(fault(
                    "non_canonical_manifest",
                    format!("archive manifest requires an established {field:?}"),
                ))
            }
        }
    }
    Ok(value)
}

fn reconstruct_row(
    artifacts: &dyn ArtifactStore,
    grant: &Grant,
    manifest: &Value,
) -> Result<CheckedRecord, Fault> {
    let map = manifest.as_object().ok_or_else(|| {
        fault(
            "non_canonical_manifest",
            "archive manifest must be an object".to_string(),
        )
    })?;
    let entity = map["entity"].clone();
    let registration_reference = &map["registration"];
    let seal_value = map["seal_point"].clone();
    let seal = validate(OUTPUT_SCHEMA, seal_value)?;
    let seal_map = as_object(&seal, "invalid_seal", "archived seal")?;
    let sealed_entity = established(seal_map, "entity").cloned().ok_or_else(|| {
        fault(
            "invalid_seal",
            "archived seal carries no entity".to_string(),
        )
    })?;
    if sealed_entity != entity {
        return Err(fault(
            "archive_integrity",
            "archived storage manifest entity disagrees with its seal".to_string(),
        ));
    }
    let sealed_registration = required_str(
        seal_map,
        "registration_digest",
        "invalid_seal",
        "archived seal",
    )?;

    let (registration_value, _) = read_verified_document(
        artifacts,
        grant,
        registration_reference,
        "archived registration document",
    )?;
    let registration = validate(OUTPUT_SCHEMA, registration_value)?;
    let registration_map = as_object(&registration, "invalid_registration", "registration")?;
    let declared_entity = established(registration_map, "entity")
        .cloned()
        .ok_or_else(|| {
            fault(
                "invalid_registration",
                "archived registration carries no entity".to_string(),
            )
        })?;
    if declared_entity != entity {
        return Err(fault(
            "archive_integrity",
            "archived registration entity disagrees with the storage manifest".to_string(),
        ));
    }

    let domains = map["domains"].as_object().ok_or_else(|| {
        fault(
            "incomplete_row",
            "archive manifest domain map must be an object".to_string(),
        )
    })?;
    if is_job_entity(&entity) {
        let keys: Vec<&str> = domains.keys().map(String::as_str).collect();
        for domain in JOB_DOMAINS {
            if !domains.contains_key(*domain) {
                return Err(fault(
                    "incomplete_row",
                    format!("archive manifest is missing the {domain:?} extent"),
                ));
            }
        }
        for key in keys {
            if !JOB_DOMAINS.contains(&key) {
                return Err(fault(
                    "incomplete_row",
                    format!("archive manifest names undeclared job domain {key:?}"),
                ));
            }
        }
    }
    if domains.is_empty() {
        return Err(fault(
            "incomplete_row",
            "a logical row requires at least one declared domain slot".to_string(),
        ));
    }

    let mut supplied = Vec::new();
    for (domain, slot) in domains {
        let slot_map = slot.as_object().ok_or_else(|| {
            fault(
                "incomplete_row",
                format!("archive extent {domain:?} must be an object"),
            )
        })?;
        let revision = required_u64(slot_map, "revision", "incomplete_row", domain)?;
        if revision == 0 {
            match slot_map.get("value") {
                Some(value) if is_missing(value) => {}
                _ => {
                    return Err(fault(
                        "incomplete_row",
                        format!(
                            "unpublished extent {domain:?} must carry a typed Missing value, not fabricated content"
                        ),
                    ));
                }
            }
            continue;
        }
        let document = slot_map
            .get("document")
            .filter(|value| !is_missing(value))
            .cloned()
            .ok_or_else(|| {
                fault(
                    "incomplete_row",
                    format!("published extent {domain:?} names no document"),
                )
            })?;
        let publication_ref = slot_map
            .get("publication_ref")
            .filter(|value| !is_missing(value))
            .cloned()
            .ok_or_else(|| {
                fault(
                    "incomplete_row",
                    format!("published extent {domain:?} names no publication reference"),
                )
            })?;
        let (snapshot, document) = read_verified_document(
            artifacts,
            grant,
            &document,
            &format!("archived {domain} document"),
        )?;
        supplied.push(validate(
            OUTPUT_SCHEMA,
            json!({
                "domain": domain,
                "revision": revision,
                "document": document,
                "publication_ref": publication_ref,
                "value": snapshot,
            }),
        )?);
    }

    let row = compose_row(&seal, &registration, &supplied)?;
    let row_map = as_object(&row, "incomplete_row", "expanded logical row")?;
    if row_map.get("registration_digest").and_then(Value::as_str) != Some(sealed_registration) {
        return Err(fault(
            "archive_integrity",
            "expanded row registration digest disagrees with the archived seal".to_string(),
        ));
    }
    Ok(row)
}

fn is_job_entity(entity: &Value) -> bool {
    entity
        .get("entity")
        .and_then(Value::as_str)
        .map(|kind| kind == "job")
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Artifact helpers
// ---------------------------------------------------------------------------

fn read_artifact_bytes(
    artifacts: &dyn ArtifactStore,
    grant: &Grant,
    reference: &Value,
    what: &str,
) -> Result<Vec<u8>, Fault> {
    let record = validate(OUTPUT_SCHEMA, reference.clone()).map_err(|err| {
        fault(
            "invalid_reference",
            format!("{what} is not a checked artifact reference: {}", err.detail),
        )
    })?;
    let map = as_object(&record, "invalid_reference", what)?;
    let digest = required_str(map, "digest", "invalid_reference", what)?;
    if !is_hex64(digest) {
        return Err(fault(
            "invalid_reference",
            format!("{what} digest must be 64 lowercase hex characters"),
        ));
    }
    let bytes = artifacts
        .read(grant, &record)
        .map_err(|err| fault(&err.code, format!("{what}: {}", err.detail)))?;
    if digest_bytes(&bytes) != digest {
        return Err(fault(
            "artifact_integrity",
            format!("{what} bytes do not hash to their content-address digest {digest}"),
        ));
    }
    Ok(bytes)
}

// ---------------------------------------------------------------------------
// Grant and record helpers
// ---------------------------------------------------------------------------

struct GrantFacts {
    owner_domain: String,
    producer_id: String,
    manifest_digest: String,
    event_kind: String,
}

fn grant_facts(grant: &Grant) -> Result<GrantFacts, Fault> {
    let map = as_object(grant_record(grant), "invalid_grant", "grant")?;
    let owner_domain = required_str(map, "owner_domain", "invalid_grant", "grant")?.to_string();
    let producer_id =
        required_str(map, "producer_id", "missing_producer_grant", "grant")?.to_string();
    let manifest_digest =
        required_str(map, "manifest_digest", "invalid_grant", "grant")?.to_string();
    if !is_hex64(&manifest_digest) {
        return Err(fault(
            "invalid_grant",
            "grant manifest_digest must be 64 lowercase hex characters".to_string(),
        ));
    }
    let event_kind =
        required_str(map, "event_kind", "missing_grant_event_kind", "grant")?.to_string();
    Ok(GrantFacts {
        owner_domain,
        producer_id,
        manifest_digest,
        event_kind,
    })
}

fn reject_retention_shortcuts(map: &Map<String, Value>, what: &str) -> Result<(), Fault> {
    for field in RETENTION_SHORTCUTS {
        if established(map, field).is_some() {
            return Err(fault(
                "retention_policy_not_authority",
                format!(
                    "{what} carries {field:?}; TTLs, cache eviction, and newer revisions never authorize or excuse a replacement archive"
                ),
            ));
        }
    }
    Ok(())
}

fn entity_from(map: &Map<String, Value>, what: &str) -> Result<Value, Fault> {
    if let Some(entity) = established(map, "entity") {
        return match entity {
            Value::Object(_) | Value::String(_) => Ok(entity.clone()),
            _ => Err(fault(
                "missing_entity",
                format!("{what} entity must be an object or string identity"),
            )),
        };
    }
    if let Some(Value::String(id)) = established(map, "entity_id") {
        if !id.is_empty() {
            return Ok(Value::String(id.clone()));
        }
    }
    Err(fault(
        "missing_entity",
        format!("{what} requires an established entity identity"),
    ))
}

fn entity_key(entity: &Value) -> Result<String, Fault> {
    serde_json::to_string(entity).map_err(|err| {
        fault(
            "missing_entity",
            format!("entity identity is not serializable: {err}"),
        )
    })
}

fn fetch_key_of(value: &Value) -> Result<String, Fault> {
    let map = value.as_object().ok_or_else(|| {
        fault(
            "missing_acquisition",
            "crawler value must be a complete object".to_string(),
        )
    })?;
    let acquisition = map
        .get("acquisition")
        .filter(|value| !is_missing(value))
        .and_then(Value::as_object)
        .ok_or_else(|| {
            fault(
                "missing_acquisition",
                "crawler value must carry an established acquisition".to_string(),
            )
        })?;
    let raw = match acquisition.get("fetch_key") {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Object(sh)) => match sh.get("value") {
            Some(Value::String(text)) => text.clone(),
            _ => {
                return Err(fault(
                    "invalid_fetch_key",
                    "acquisition.fetch_key object must carry its digest text under value"
                        .to_string(),
                ))
            }
        },
        Some(value) if is_missing(value) => {
            return Err(fault(
                "missing_fetch_key",
                "acquisition.fetch_key is Missing; no fetch identity is established".to_string(),
            ))
        }
        _ => {
            return Err(fault(
                "missing_fetch_key",
                "acquisition must carry an established fetch_key".to_string(),
            ))
        }
    };
    normalize_digest(&raw, "acquisition.fetch_key")
}

fn normalize_digest(text: &str, what: &str) -> Result<String, Fault> {
    let hex = text.strip_prefix("sha256:").unwrap_or(text);
    if is_hex64(hex) {
        Ok(hex.to_string())
    } else {
        Err(fault(
            "invalid_digest",
            format!("{what} must be sha256: plus 64 lowercase hex characters"),
        ))
    }
}

fn optional_digest_text(
    map: &Map<String, Value>,
    field: &str,
    what: &str,
) -> Result<Option<String>, Fault> {
    match map.get(field) {
        None => Ok(None),
        Some(value) if is_missing(value) => Ok(None),
        Some(Value::String(text)) => normalize_digest(text, &format!("{what}.{field}")).map(Some),
        Some(_) => Err(fault(
            "invalid_request",
            format!("{what}.{field} must be digest text"),
        )),
    }
}

fn prefix16(text: &str) -> &str {
    &text[..text.len().min(16)]
}

fn is_hex64(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_missing(value: &Value) -> bool {
    value
        .as_object()
        .is_some_and(|map| map.get("value").is_some_and(Value::is_null))
}

fn missing(reason: &str, detail: &str) -> Value {
    json!({"value": Value::Null, "reason": reason, "detail": detail})
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
    match map.get(field) {
        Some(Value::String(text)) if !text.is_empty() => Ok(text.as_str()),
        Some(value) if is_missing(value) => Err(fault(
            code,
            format!("{what} requires an established {field:?}; missingness is a typed envelope, not a value"),
        )),
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
    match map.get(field) {
        Some(Value::Number(number)) => number.as_u64().ok_or_else(|| {
            fault(
                code,
                format!("{what} {field:?} must be an unsigned integer"),
            )
        }),
        Some(value) if is_missing(value) => Err(fault(
            code,
            format!("{what} requires an established {field:?}"),
        )),
        _ => Err(fault(
            code,
            format!("{what} requires an unsigned integer {field:?}"),
        )),
    }
}

fn optional_nonempty(map: &Map<String, Value>, field: &str) -> Result<Option<String>, Fault> {
    match map.get(field) {
        None => Ok(None),
        Some(value) if is_missing(value) => Ok(None),
        Some(Value::String(text)) if !text.is_empty() => Ok(Some(text.clone())),
        Some(_) => Err(fault(
            "invalid_request",
            format!("{field:?} must be a nonempty string when established"),
        )),
    }
}

fn object_array(
    map: &Map<String, Value>,
    field: &str,
    code: &str,
    what: &str,
) -> Result<Vec<Value>, Fault> {
    match map.get(field) {
        None => Ok(Vec::new()),
        Some(value) if is_missing(value) => Ok(Vec::new()),
        Some(Value::Array(items)) => {
            for (index, item) in items.iter().enumerate() {
                if !item.is_object() {
                    return Err(fault(
                        code,
                        format!("{what} {field}[{index}] must be an object"),
                    ));
                }
            }
            Ok(items.clone())
        }
        Some(_) => Err(fault(
            code,
            format!("{what} {field} must be an array when established"),
        )),
    }
}

fn fault(code: &str, detail: impl Into<String>) -> Fault {
    Fault {
        code: code.to_string(),
        detail: detail.into(),
    }
}

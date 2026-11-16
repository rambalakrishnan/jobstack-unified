//! `crawler_publication`: owner-local publication and read-view installation.
//!
//! Implements Contract 04 §20.4 ([OWD-PUBLISH], [OWD-VIEW], [OWD-SEAL]) for
//! the crawler seam:
//!
//! * [`install_revision`] installs one complete immutable domain revision. The
//!   complete snapshot is serialized, installed through [`ArtifactStore`], and
//!   read back before any pointer is advanced. Only after the document is
//!   verifiably durable is one `publication_receipt` appended to the owner
//!   journal. The read-view pointer is the highest revision journaled for an
//!   `(entity, view, domain)` coordinate, so a reordered or duplicate delivery
//!   can never move it backwards. Identical delivery returns the existing
//!   receipt; different bytes under the same `(entity, domain, revision)` key
//!   are an integrity conflict. A revision may only be installed when
//!   `previous_revision == revision - 1` and the complete predecessor chain is
//!   journaled (skipping never bypasses lineage).
//! * [`select_seal`] pins the current fully published revision of every named
//!   domain in a named read view. The exact version vector is journaled as a
//!   seal-selection event *before* any resulting row is registered; the
//!   returned `SealPoint` names that event in its `input_prefix` and carries
//!   the pinned document digests and publication references.
//! * [`compose_row`] composes one `LogicalRow` from a seal, the complete entity
//!   registration, and the complete domain snapshots. Every declared domain
//!   slot is present: a published slot embeds the complete snapshot plus its
//!   document digest and publication reference; a zero slot is an explicit
//!   typed `Missing`, never lost published bytes and never a partial row.
//!
//! # Record shapes
//!
//! All inputs are [`CheckedRecord`]s admitted by the schema gate, so no bare
//! JSON `null` survives. Absent values are typed `Missing` envelopes; an
//! established value is anything that is not one of those envelopes.
//!
//! ## Revision (`install_revision`)
//!
//! * `journal_id` — owner journal that receives the publication receipt.
//!   The journal must already be admitted; this module never admits a
//!   manifest.
//! * `view` — read view name (default `ingest`).
//! * `entity` (or `entity_id`) — entity identity.
//! * `registration_digest` — registration digest of the entity.
//! * `domain` — domain being published.
//! * `owner_domain` — optional; when established it must match the grant.
//! * `writer_id` — optional; defaults to the grant's producer id.
//! * `revision`, `previous_revision` — revision numbering; the first revision
//!   is 1 with previous 0.
//! * `value` (fallbacks: `snapshot`, `domain_value`, `complete_value`) — the
//!   complete domain snapshot. When absent, `document` may be an already
//!   installed artifact reference whose bytes are read and verified.
//! * `document_digest` (or `document.digest`) — optional expected digest; when
//!   established it must equal the digest of the installed canonical bytes.
//! * `media_type`, `restricted` / `access` — optional artifact metadata
//!   (default `application/json` and public).
//! * `publication_delay` — optional Contract 00 `Measurement` (or `Missing`).
//!   An established measurement is validated with
//!   [`crawler_time::validate_measurement`] against `registered_clocks` (also
//!   `clock_registry` / `registered_clock_registry`). Publication delay is
//!   never derived by subtracting source and destination UTC annotations;
//!   records carrying those annotations are refused.
//! * `evidence_refs` — optional earlier journal evidence refs.
//!
//! The returned record is the `PublicationReceipt` augmented with the complete
//! snapshot under `value`. The journaled receipt itself does not duplicate the
//! snapshot; it names the installed document, so large payloads are not
//! serialized on the critical path.
//!
//! ## Seal request (`select_seal`)
//!
//! * `journal_id`, `view` (default `ingest`), `entity`, `registration_digest`.
//! * `domains` (also `declared_domains`, `domain_names`) — every domain slot
//!   the row must contain, including domains with no publication (zero slot).
//!   When omitted, the domains already published in the view are selected.
//! * `seal_id`, `seal_name` — optional stable identifiers.
//! * `expected_version_vector` / `expected_pointer` — optional concurrency
//!   guard; when the current view disagrees, selection fails with
//!   `view_changed` instead of pinning a mismatched state.
//! * `support` (or `evidence_refs`) — optional earlier evidence refs.
//!
//! ## Row composition (`compose_row`)
//!
//! `registration` must carry `entity`, `registration_digest` (or `digest`),
//! and optionally a declared domain set under `domains`,
//! `domain_declarations`, `declared_domains`, or `field_set`. When the
//! registration declares domains, that set must equal the seal's vector; when
//! it does not, the seal's exact vector is the domain set. `domains` are
//! publication receipts (or revision records) carrying the complete `value`
//! / `snapshot`, the document reference or digest, and the publication
//! reference. Zero-slot domains may be omitted from `domains` because the seal
//! states their revision is zero, and are then materialized as typed
//! `Missing` slots.
//!
//! Faults include `invalid_request`, `missing_journal_id`, `invalid_grant`,
//! `missing_grant_event_kind`, `foreign_owner`, `owner_mismatch`,
//! `missing_entity`, `missing_registration_digest`, `invalid_revision`,
//! `invalid_lineage`, `unverified_lineage`, `revision_regression`,
//! `revision_conflict`, `incomplete_domain`, `document_mismatch`,
//! `artifact_verification_failed`, `invalid_publication_delay`,
//! `utc_subtraction_refused`, `invalid_journal_view`, `integrity_conflict`,
//! `invalid_seal`, `view_changed`, `incomplete_row`, `undeclared_domain`,
//! `duplicate_domain`, `published_bytes_lost`, `inconsistent_slot`,
//! `registration_mismatch`, `entity_mismatch`, `missing_publication_ref`.

use crawler_artifacts::ArtifactStore;
use crawler_authority::{grant_record, Grant};
use crawler_normalization::assemble_crawler_value;
use crawler_schema::{record_value, validate, CheckedRecord, Fault};
use crawler_store::OwnerStore;
use crawler_time::validate_measurement;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

/// Structural envelope for records produced by this module.
const OUTPUT_SCHEMA: &str = "audit_log";

/// Contract schema version stamped on publication records.
const SCHEMA_VERSION: &str = "owner-separated-write-domains/0.1.0";

const PUBLICATION_RECEIPT: &str = "publication_receipt";
const SEAL_POINT: &str = "seal_point";
const LOGICAL_ROW: &str = "logical_row";
const JOURNAL_VIEW: &str = "journal_view";
const DEFAULT_VIEW: &str = "ingest";

/// Keys that could only be used to fabricate a publication delay by
/// subtracting independent UTC annotations.
const UTC_SUBTRACTION_KEYS: &[&str] = &[
    "source_utc",
    "destination_utc",
    "source_time_utc",
    "destination_time_utc",
    "utc_start",
    "utc_end",
    "utc_delta",
];

/// Snapshot field names accepted as the complete domain value.
const VALUE_FIELDS: &[&str] = &["value", "snapshot", "domain_value", "complete_value"];

/// Domain declaration field names accepted on a registration record.
const DECLARATION_FIELDS: &[&str] = &[
    "domains",
    "domain_declarations",
    "declared_domains",
    "field_set",
    "domain_slots",
];

// ---------------------------------------------------------------------------
// Public interface
// ---------------------------------------------------------------------------

/// Install one complete immutable domain revision and advance its read-view
/// pointer only after the document is verifiably durable.
///
/// The pointer is derived from the owner journal, never from caller state.
/// Re-delivering an older or identical revision returns the existing receipt
/// and leaves the pointer at the newest revision; different bytes under an
/// already published revision key fail as `revision_conflict`.
pub fn install_revision(
    store: &dyn OwnerStore,
    artifacts: &dyn ArtifactStore,
    grant: &Grant,
    revision: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let facts = grant_facts(grant)?;
    let map = as_object(revision, "invalid_revision", "revision")?;

    let journal_id = required_str(map, "journal_id", "missing_journal_id", "revision")?.to_string();
    let view = optional_nonempty(map, "view")?.unwrap_or_else(|| DEFAULT_VIEW.to_string());
    let entity = entity_from(map, "revision")?;
    let entity_key = entity_key(&entity)?;
    let registration_digest = registration_digest(map)?;
    let domain = required_str(map, "domain", "missing_domain", "revision")?.to_string();
    match optional_nonempty(map, "owner_domain")? {
        Some(owner) if owner != facts.owner_domain => {
            return Err(fault(
                "owner_mismatch",
                format!(
                    "revision names owner {owner:?} but the grant belongs to {:?}; publication never crosses the persistence domain",
                    facts.owner_domain
                ),
            ))
        }
        _ => {}
    }
    let revision_number = required_u64(map, "revision", "invalid_revision", "revision")?;
    if revision_number == 0 {
        return Err(fault(
            "invalid_revision",
            "domain revisions begin at 1; revision zero is the unpublished view slot, never a revision"
                .to_string(),
        ));
    }
    let previous_revision =
        required_u64(map, "previous_revision", "invalid_lineage", "revision")?;
    if previous_revision + 1 != revision_number {
        return Err(fault(
            "invalid_lineage",
            format!(
                "revision {revision_number} must follow previous_revision {}; a revision is a complete immutable snapshot, not a patch",
                revision_number - 1
            ),
        ));
    }
    let writer_id = optional_nonempty(map, "writer_id")?
        .unwrap_or_else(|| facts.producer_id.clone());
    let evidence_refs = object_array(map, "evidence_refs", "invalid_evidence_refs", "revision")?;
    let delay = publication_delay(map)?;

    let state = read_journal(store, grant, &journal_id, &facts.owner_domain)?;
    verify_registration_identity(&state, &entity_key, &domain, &registration_digest)?;

    // Identical delivery returns the existing receipt. Different bytes under
    // the same (entity, domain, revision) key are an integrity conflict.
    if let Some(existing) =
        receipt_at(&state, &entity_key, &view, &domain, revision_number)
    {
        let prepared = prepare_document(artifacts, grant, map)?;
        if prepared.digest != existing.document_digest {
            return Err(fault(
                "revision_conflict",
                format!(
                    "revision {revision_number} of domain {domain:?} is already journaled with document {}; a different document under one revision key is an integrity conflict",
                    existing.document_digest
                ),
            ));
        }
        return returned_receipt(existing, &prepared.value);
    }

    let current = pointer(&state, &entity_key, &view, &domain);
    if let Some(current) = current {
        if revision_number < current.revision {
            return Err(fault(
                "revision_regression",
                format!(
                    "revision {revision_number} of domain {domain:?} is older than the installed view revision {}; reordered delivery never regresses the pointer",
                    current.revision
                ),
            ));
        }
    }
    if !lineage_verified(&state, &entity_key, &domain, previous_revision) {
        return Err(fault(
            "unverified_lineage",
            format!(
                "revision {revision_number} names predecessor {previous_revision} which is not completely journaled; skipping visible revisions requires verified lineage"
            ),
        ));
    }

    let prepared = prepare_document(artifacts, grant, map)?;

    // Optimistic re-read: another delivery may have installed in the window
    // between the read and the document transfer. The journal append is the
    // bounded pointer advance.
    let state = read_journal(store, grant, &journal_id, &facts.owner_domain)?;
    verify_registration_identity(&state, &entity_key, &domain, &registration_digest)?;
    if let Some(existing) =
        receipt_at(&state, &entity_key, &view, &domain, revision_number)
    {
        if prepared.digest != existing.document_digest {
            return Err(fault(
                "revision_conflict",
                format!(
                    "revision {revision_number} of domain {domain:?} was concurrently installed with a different document digest"
                ),
            ));
        }
        return returned_receipt(existing, &prepared.value);
    }
    let current = pointer(&state, &entity_key, &view, &domain);
    if let Some(current) = current {
        if revision_number < current.revision {
            return Err(fault(
                "revision_regression",
                format!(
                    "revision {revision_number} of domain {domain:?} was superseded by installed revision {} during transfer; reordered delivery never regresses the pointer",
                    current.revision
                ),
            ));
        }
    }
    if !lineage_verified(&state, &entity_key, &domain, previous_revision) {
        return Err(fault(
            "unverified_lineage",
            "lineage changed during publication transfer; the predecessor chain is no longer completely journaled"
                .to_string(),
        ));
    }

    let superseded = match current {
        Some(current) => receipt_identity(current),
        None => missing(
            "not_applicable",
            "no earlier publication exists in this read view",
        ),
    };
    let observed_head = match owner_head(&state, &entity_key, &domain) {
        Some(head) => json!({
            "revision": head.revision,
            "receipt_id": head.receipt_id,
            "view": head.view,
            "domain": head.domain,
        }),
        None => missing(
            "not_observed",
            "no publication for this entity and domain was observed before installation",
        ),
    };
    let receipt = journaled_receipt(
        &facts,
        &journal_id,
        &state,
        &entity,
        &entity_key,
        &registration_digest,
        &view,
        &domain,
        revision_number,
        previous_revision,
        &writer_id,
        &prepared,
        superseded,
        observed_head,
        &delay,
    )?;
    let mut measurements = Vec::new();
    if let Some(measurement) = &delay.journaled {
        measurements.push(measurement.clone());
    }
    let appended = append_journal_data(
        store,
        grant,
        &facts,
        &journal_id,
        PUBLICATION_RECEIPT,
        receipt,
        measurements,
        evidence_refs,
        vec![record_value(&prepared.reference).clone()],
    )?;
    finish_receipt(&appended, &prepared.value, PUBLICATION_RECEIPT)
}

/// Pin the current published revision of every named domain in a read view.
///
/// The exact version vector is appended to the owner journal before the
/// returned `SealPoint` names it, so the selection event is part of the row's
/// input prefix and the row never cites itself.
pub fn select_seal(
    store: &dyn OwnerStore,
    grant: &Grant,
    request: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let facts = grant_facts(grant)?;
    let map = as_object(request, "invalid_request", "seal request")?;
    let journal_id =
        required_str(map, "journal_id", "missing_journal_id", "seal request")?.to_string();
    let view = optional_nonempty(map, "view")?.unwrap_or_else(|| DEFAULT_VIEW.to_string());
    let entity = entity_from(map, "seal request")?;
    let entity_key = entity_key(&entity)?;
    let registration_digest = registration_digest(map)?;
    let support = if map.get("support").is_some() {
        object_array(map, "support", "invalid_support", "seal request")?
    } else {
        object_array(map, "evidence_refs", "invalid_support", "seal request")?
    };

    let mut domains = domain_names(map)?;
    let state = read_journal(store, grant, &journal_id, &facts.owner_domain)?;
    for receipt in &state.receipts {
        if receipt.entity_key == entity_key
            && receipt.view == view
            && receipt.registration_digest != registration_digest
        {
            return Err(fault(
                "registration_mismatch",
                format!(
                    "view {view:?} carries domain {:?} under registration {}; the seal request names {}. Entity registration fixes the field set",
                    receipt.domain, receipt.registration_digest, registration_digest
                ),
            ));
        }
    }
    if domains.is_empty() {
        for receipt in &state.receipts {
            if receipt.entity_key == entity_key
                && receipt.view == view
                && !domains.contains(&receipt.domain)
            {
                domains.push(receipt.domain.clone());
            }
        }
        if domains.is_empty() {
            return Err(fault(
                "missing_domains",
                "seal selection requires the domain slots it pins; no domain is named and none is published in this view"
                    .to_string(),
            ));
        }
    }
    let mut seen = BTreeSet::new();
    for domain in &domains {
        if !seen.insert(domain.clone()) {
            return Err(fault(
                "duplicate_domain",
                format!("domain {domain:?} is named more than once in the seal request"),
            ));
        }
    }

    verify_expected_vector(map, &state, &entity_key, &view)?;

    let mut vector = Vec::new();
    for domain in &domains {
        match pointer(&state, &entity_key, &view, domain) {
            Some(receipt) => vector.push(json!({
                "domain": domain,
                "revision": receipt.revision,
                "receipt_id": receipt.receipt_id,
                "document": receipt.document.clone(),
                "document_digest": receipt.document_digest,
                "publication_ref": receipt.publication_ref.clone(),
                "previous_revision": receipt.previous_revision,
            })),
            None => vector.push(json!({
                "domain": domain,
                "revision": 0,
                "receipt_id": missing(
                    "not_observed",
                    "no publication in this read view",
                ),
                "document": missing(
                    "not_observed",
                    "no publication in this read view",
                ),
                "document_digest": missing(
                    "not_observed",
                    "no publication in this read view",
                ),
                "publication_ref": missing(
                    "not_observed",
                    "no publication in this read view",
                ),
                "previous_revision": 0,
            })),
        }
    }

    let requested_name = optional_nonempty(map, "seal_name")?;
    let seal_id = optional_nonempty(map, "seal_id")?
        .or_else(|| requested_name.clone())
        .unwrap_or_else(|| {
            let prefix: String = registration_digest.chars().take(16).collect();
            format!("seal-{view}-{prefix}-{}", state.last_sequence)
        });
    let seal_name = requested_name.unwrap_or_else(|| seal_id.clone());
    let selection = validate(
        OUTPUT_SCHEMA,
        json!({
            "record_type": SEAL_POINT,
            "schema_version": SCHEMA_VERSION,
            "seal_id": seal_id,
            "seal_name": seal_name,
            "view": view,
            "entity": entity,
            "registration_digest": registration_digest,
            "version_vector": Value::Array(vector),
            "time": missing(
                "not_observed",
                "the carrying seal-selection event assigns the selection time",
            ),
            "input_prefix": missing(
                "not_observed",
                "the carrying seal-selection event establishes the input prefix",
            ),
            "support": Value::Array(support.clone()),
            "selection_event": missing(
                "not_observed",
                "the carrying journal event is the selection reference",
            ),
        }),
    )?;
    let appended = append_journal_data(
        store,
        grant,
        &facts,
        &journal_id,
        "seal_selection",
        record_value(&selection).clone(),
        Vec::new(),
        support,
        Vec::new(),
    )?;
    let selection_event = evidence_ref(&appended, "/payload/data/seal_selection")?;
    let mut seal = record_value(&selection).clone();
    let seal_map = seal
        .as_object_mut()
        .ok_or_else(|| fault("invalid_seal", "seal selection must be an object".to_string()))?;
    seal_map.insert(
        "time".to_string(),
        receipt_recorded_at(&appended)?.clone(),
    );
    seal_map.insert(
        "input_prefix".to_string(),
        json!({
            "journal_id": record_value(&appended)["journal_id"].clone(),
            "last_sequence": record_value(&appended)["journal_sequence"].clone(),
            "head_hash": record_value(&appended)["event_hash"].clone(),
            "previous_head_hash": state.head_hash,
        }),
    );
    seal_map.insert("selection_event".to_string(), selection_event);
    validate(OUTPUT_SCHEMA, seal)
}

/// Compose one complete `LogicalRow` from a seal, a registration, and complete
/// domain snapshots.
///
/// Every domain in the seal's exact version vector becomes a slot. A nonzero
/// vector entry requires a matching complete snapshot, document digest, and
/// publication reference; a zero entry is materialized as a typed `Missing`
/// slot. Missing or undeclared parts fail instead of producing a partial row.
pub fn compose_row(
    seal: &CheckedRecord,
    registration: &CheckedRecord,
    domains: &[CheckedRecord],
) -> Result<CheckedRecord, Fault> {
    let seal_value = record_value(seal);
    let seal_map = seal_value
        .as_object()
        .ok_or_else(|| fault("invalid_seal", "seal must be a JSON object".to_string()))?;
    if let Some(Value::String(kind)) = seal_map.get("record_type") {
        if kind != SEAL_POINT {
            return Err(fault(
                "invalid_seal",
                format!("expected a {SEAL_POINT:?} record, got {kind:?}"),
            ));
        }
    }
    let view = required_str(seal_map, "view", "invalid_seal", "seal")?.to_string();
    let seal_entity = entity_from(seal_map, "seal")?;
    let seal_entity_key = entity_key(&seal_entity)?;
    let seal_registration = registration_digest(seal_map)?;
    let vector = parse_version_vector(seal_map)?;
    let seal_id = optional_nonempty(seal_map, "seal_id")?
        .or_else(|| optional_nonempty(seal_map, "seal_name").ok().flatten())
        .unwrap_or_else(|| "seal".to_string());
    let input_prefix = match established(seal_map, "input_prefix") {
        Some(Value::Object(prefix)) => prefix.clone(),
        _ => {
            return Err(fault(
                "invalid_seal",
                "seal requires an established input_prefix naming the selection event".to_string(),
            ))
        }
    };
    let prefix_journal = required_str(
        &input_prefix,
        "journal_id",
        "invalid_seal",
        "seal input_prefix",
    )?;
    let prefix_sequence = required_u64(
        &input_prefix,
        "last_sequence",
        "invalid_seal",
        "seal input_prefix",
    )?;
    if prefix_sequence == 0 {
        return Err(fault(
            "invalid_seal",
            "seal input_prefix must include at least the seal-selection event".to_string(),
        ));
    }
    let prefix_head = required_digest(
        &input_prefix,
        "head_hash",
        "invalid_seal",
        "seal input_prefix",
    )?;
    if let Some(Value::Object(event)) = established(seal_map, "selection_event") {
        if let Some(event_journal) = event.get("journal_id").and_then(Value::as_str) {
            if event_journal != prefix_journal {
                return Err(fault(
                    "invalid_seal",
                    "seal selection_event names a different journal than its input_prefix".to_string(),
                ));
            }
        }
        if let (Some(sequence), Some(event_hash)) = (
            event.get("sequence").and_then(Value::as_u64),
            event.get("event_hash").and_then(Value::as_str),
        ) {
            if sequence == prefix_sequence && event_hash != prefix_head {
                return Err(fault(
                    "invalid_seal",
                    "seal input_prefix head does not match the selection event it includes"
                        .to_string(),
                ));
            }
        }
    }

    let registration_value = record_value(registration);
    let reg_map = registration_value
        .as_object()
        .ok_or_else(|| fault("invalid_registration", "registration must be an object".to_string()))?;
    let reg_entity = entity_from(reg_map, "registration")?;
    if reg_entity != seal_entity {
        return Err(fault(
            "entity_mismatch",
            "registration entity does not match the entity pinned by the seal".to_string(),
        ));
    }
    let reg_digest = registration_digest(reg_map)?;
    if reg_digest != seal_registration {
        return Err(fault(
            "registration_mismatch",
            format!(
                "registration digest {reg_digest} does not match the seal's pinned registration {seal_registration}"
            ),
        ));
    }
    let declared = declared_domains(reg_map)?;
    let vector_domains: BTreeSet<String> = vector.keys().cloned().collect();
    let declared_set = match declared {
        Some(declared) => {
            if declared.is_empty() {
                return Err(fault(
                    "incomplete_row",
                    "registration declares no domains; a row without domain slots is not a complete row"
                        .to_string(),
                ));
            }
            for domain in declared.difference(&vector_domains) {
                return Err(fault(
                    "incomplete_row",
                    format!(
                        "declared domain {domain:?} is not pinned by the seal; a partial row is never composed"
                    ),
                ));
            }
            for domain in vector_domains.difference(&declared) {
                return Err(fault(
                    "undeclared_domain",
                    format!(
                        "seal pins domain {domain:?} that the registration does not declare"
                    ),
                ));
            }
            declared
        }
        None => vector_domains,
    };
    if declared_set.is_empty() {
        return Err(fault(
            "incomplete_row",
            "a logical row requires at least one declared domain slot".to_string(),
        ));
    }

    let mut supplied: BTreeMap<String, SuppliedSlot> = BTreeMap::new();
    for (index, domain_record) in domains.iter().enumerate() {
        let raw = record_value(domain_record);
        let slot_map = raw.as_object().ok_or_else(|| {
            fault(
                "invalid_domain",
                format!("domains[{index}] must be an object"),
            )
        })?;
        let domain = required_str(
            slot_map,
            "domain",
            "invalid_domain",
            &format!("domains[{index}]"),
        )?
        .to_string();
        if !declared_set.contains(&domain) {
            return Err(fault(
                "undeclared_domain",
                format!(
                    "domain {domain:?} is supplied but not declared by the registration/seal; composing it would create an unsealed slot"
                ),
            ));
        }
        let revision = required_u64(
            slot_map,
            "revision",
            "invalid_domain",
            &format!("domains[{index}]"),
        )?;
        let slot = parse_supplied_slot(slot_map, revision, &format!("domains[{index}]"))?;
        if supplied.insert(domain.clone(), slot).is_some() {
            return Err(fault(
                "duplicate_domain",
                format!("domain {domain:?} is supplied more than once"),
            ));
        }
    }

    let mut slots: BTreeMap<String, Value> = BTreeMap::new();
    let mut vector_out = Vec::new();
    for (domain, pinned) in &vector {
        let slot = match supplied.get(domain) {
            Some(supplied) => {
                if pinned.revision == 0 {
                    return Err(fault(
                        "publication_outside_seal",
                        format!(
                            "seal pins domain {domain:?} as unpublished but a revision {} snapshot was supplied; the row would contradict its seal",
                            supplied.revision
                        ),
                    ));
                }
                if supplied.revision != pinned.revision {
                    return Err(fault(
                        if supplied.revision == 0 {
                            "published_bytes_lost"
                        } else {
                            "revision_mismatch"
                        },
                        format!(
                            "seal pins domain {domain:?} at revision {} but the supplied slot is revision {}",
                            pinned.revision, supplied.revision
                        ),
                    ));
                }
                let digest = match &pinned.digest {
                    Some(digest) => digest,
                    None => {
                        return Err(fault(
                            "invalid_seal",
                            format!(
                                "seal pins domain {domain:?} at revision {} without a document digest",
                                pinned.revision
                            ),
                        ))
                    }
                };
                if let Some(supplied_digest) = &supplied.digest {
                    if supplied_digest != digest {
                        return Err(fault(
                            "document_mismatch",
                            format!(
                                "domain {domain:?} snapshot document {supplied_digest} does not match the seal's pinned document {digest}"
                            ),
                        ));
                    }
                }
                let snapshot = supplied.snapshot.clone().ok_or_else(|| {
                    fault(
                        "incomplete_domain",
                        format!("domain {domain:?} has no complete snapshot"),
                    )
                })?;
                let document = supplied
                    .document
                    .clone()
                    .unwrap_or_else(|| document_placeholder(digest));
                let publication_ref = pinned.publication_ref.clone().or_else(|| {
                    supplied.publication_ref.clone()
                }).ok_or_else(|| {
                    fault(
                        "missing_publication_ref",
                        format!(
                            "domain {domain:?} revision {} must name the publication receipt that installed it",
                            pinned.revision
                        ),
                    )
                })?;
                let previous_value = match supplied.previous_revision.or(pinned.previous_revision) {
                    Some(previous) => Value::from(previous),
                    None => missing(
                        "not_observed",
                        "the supplied domain record carries no previous revision",
                    ),
                };
                json!({
                    "domain": domain,
                    "revision": pinned.revision,
                    "previous_revision": previous_value,
                    "document": document,
                    "document_digest": digest,
                    "publication_ref": publication_ref,
                    "snapshot": snapshot,
                })
            }
            None => {
                if pinned.revision != 0 {
                    return Err(fault(
                        "incomplete_row",
                        format!(
                            "seal pins domain {domain:?} at revision {} but no complete snapshot was supplied; published bytes are never replaced by a zero slot",
                            pinned.revision
                        ),
                    ));
                }
                zero_slot(domain)
            }
        };
        slots.insert(domain.clone(), slot);
        vector_out.push(json!({
            "domain": domain,
            "revision": pinned.revision,
            "document": pinned.document.clone().unwrap_or_else(|| missing(
                "not_observed",
                "no publication in this read view",
            )),
            "document_digest": pinned.digest.clone().map(Value::String).unwrap_or_else(|| missing(
                "not_observed",
                "no publication in this read view",
            )),
            "publication_ref": pinned.publication_ref.clone().unwrap_or_else(|| missing(
                "not_observed",
                "no publication in this read view",
            )),
            "receipt_id": pinned.receipt_id.clone().map(Value::String).unwrap_or_else(|| missing(
                "not_observed",
                "no publication in this read view",
            )),
        }));
    }
    for domain in supplied.keys() {
        if !vector.contains_key(domain) {
            return Err(fault(
                "undeclared_domain",
                format!("supplied domain {domain:?} is absent from the seal's exact version vector"),
            ));
        }
    }

    // Keep the entity-key computation exercised for both sides of composition;
    // a differing key is the same failure as a differing entity value.
    if entity_key_from_registration(&registration_value)? != seal_entity_key {
        return Err(fault(
            "entity_mismatch",
            "registration entity and seal entity resolve to different identities".to_string(),
        ));
    }

    let mut domain_map = Map::new();
    for (domain, slot) in slots {
        domain_map.insert(domain, slot);
    }
    let row = validate(
        OUTPUT_SCHEMA,
        json!({
            "record_type": LOGICAL_ROW,
            "schema_version": SCHEMA_VERSION,
            "entity": seal_entity,
            "registration": registration_value.clone(),
            "registration_digest": seal_registration,
            "view": view,
            "seal_id": seal_id,
            "seal_point": seal_value.clone(),
            "version_vector": Value::Array(vector_out),
            "input_prefix": input_prefix,
            "domains": Value::Object(domain_map),
            "row_root": missing(
                "not_observed",
                "the row root is assigned by the journal event that registers this complete row",
            ),
        }),
    )?;
    Ok(row)
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
    let map = record_value(grant_record(grant))
        .as_object()
        .ok_or_else(|| fault("invalid_grant", "grant must be an object".to_string()))?;
    let owner_domain = required_str(map, "owner_domain", "invalid_grant", "grant")?.to_string();
    let producer_id = required_str(map, "producer_id", "missing_producer_grant", "grant")?.to_string();
    let manifest_digest = required_digest(map, "manifest_digest", "invalid_grant", "grant")?;
    let event_kind = required_str(
        map,
        "event_kind",
        "missing_grant_event_kind",
        "grant",
    )?
    .to_string();
    Ok(GrantFacts {
        owner_domain,
        producer_id,
        manifest_digest,
        event_kind,
    })
}

fn fault(code: &str, detail: String) -> Fault {
    Fault {
        code: code.to_string(),
        detail,
    }
}

fn missing(reason: &str, detail: &str) -> Value {
    json!({"value": Value::Null, "reason": reason, "detail": detail})
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
        Some(Value::String(text)) if !text.is_empty() => Ok(text),
        _ => Err(fault(
            code,
            format!("{what} requires an established nonempty {field:?}"),
        )),
    }
}

fn optional_nonempty(
    map: &Map<String, Value>,
    field: &str,
) -> Result<Option<String>, Fault> {
    match established(map, field) {
        None => Ok(None),
        Some(Value::String(text)) if !text.is_empty() => Ok(Some(text.clone())),
        Some(_) => Err(fault(
            "invalid_request",
            format!("{field:?} must be a nonempty string when present"),
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
            format!("{what} {field:?} is required, not Missing"),
        )),
        _ => Err(fault(
            code,
            format!("{what} requires an unsigned integer {field:?}"),
        )),
    }
}

fn is_digest_text(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn required_digest(
    map: &Map<String, Value>,
    field: &str,
    code: &str,
    what: &str,
) -> Result<String, Fault> {
    match established(map, field) {
        Some(Value::String(text)) if is_digest_text(text) => Ok(text.clone()),
        Some(Value::String(text)) => Err(fault(
            code,
            format!("{what} {field:?} is not a 64-character lowercase hex digest: {text:?}"),
        )),
        _ => Err(fault(
            code,
            format!("{what} requires an established 64-character digest {field:?}"),
        )),
    }
}

fn registration_digest(map: &Map<String, Value>) -> Result<String, Fault> {
    if let Some(digest) = established(map, "registration_digest") {
        return match digest {
            Value::String(text) if is_digest_text(text) => Ok(text.clone()),
            _ => Err(fault(
                "missing_registration_digest",
                "registration_digest must be 64 lowercase hex characters".to_string(),
            )),
        };
    }
    if let Some(Value::Object(registration)) = established(map, "registration") {
        return required_digest(
            registration,
            "registration_digest",
            "missing_registration_digest",
            "registration",
        );
    }
    Err(fault(
        "missing_registration_digest",
        "record requires the entity registration digest that fixes its domain field set".to_string(),
    ))
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

fn entity_key_from_registration(value: &Value) -> Result<String, Fault> {
    let map = value
        .as_object()
        .ok_or_else(|| fault("invalid_registration", "registration must be an object".to_string()))?;
    entity_key(&entity_from(map, "registration")?)
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
            format!("{what} {field} must be an established array"),
        )),
    }
}

fn domain_names(map: &Map<String, Value>) -> Result<Vec<String>, Fault> {
    let mut names = Vec::new();
    for field in ["domains", "declared_domains", "domain_names"] {
        match map.get(field) {
            None => continue,
            Some(value) if is_missing(value) => continue,
            Some(Value::Array(items)) => {
                for (index, item) in items.iter().enumerate() {
                    let domain = match item {
                        Value::String(text) if !text.is_empty() => text.clone(),
                        Value::Object(entry) => {
                            required_str(entry, "domain", "invalid_domain", &format!("{field}[{index}]"))?
                                .to_string()
                        }
                        _ => {
                            return Err(fault(
                                "invalid_domain",
                                format!(
                                    "{field}[{index}] must be a nonempty domain string or an object naming its domain"
                                ),
                            ))
                        }
                    };
                    names.push(domain);
                }
            }
            Some(_) => {
                return Err(fault(
                    "invalid_domain",
                    format!("{field} must be an established array of domain names"),
                ))
            }
        }
    }
    Ok(names)
}

fn declared_domains(map: &Map<String, Value>) -> Result<Option<BTreeSet<String>>, Fault> {
    for field in DECLARATION_FIELDS {
        match map.get(*field) {
            None => continue,
            Some(value) if is_missing(value) => continue,
            Some(Value::Array(items)) => {
                let mut names = BTreeSet::new();
                for (index, item) in items.iter().enumerate() {
                    let domain = match item {
                        Value::String(text) if !text.is_empty() => text.clone(),
                        Value::Object(entry) => {
                            let name = entry
                                .get("domain")
                                .or_else(|| entry.get("name"))
                                .or_else(|| entry.get("field"))
                                .and_then(Value::as_str)
                                .filter(|text| !text.is_empty());
                            match name {
                                Some(name) => name.to_string(),
                                None => {
                                    return Err(fault(
                                        "invalid_registration",
                                        format!(
                                            "{field}[{index}] does not name a domain"
                                        ),
                                    ))
                                }
                            }
                        }
                        _ => {
                            return Err(fault(
                                "invalid_registration",
                                format!(
                                    "{field}[{index}] must be a domain name or declaration object"
                                ),
                            ))
                        }
                    };
                    if !names.insert(domain.clone()) {
                        return Err(fault(
                            "duplicate_domain",
                            format!("registration declares domain {domain:?} more than once"),
                        ));
                    }
                }
                return Ok(Some(names));
            }
            Some(Value::Object(entries)) => {
                let mut names = BTreeSet::new();
                for domain in entries.keys() {
                    if domain.is_empty() {
                        return Err(fault(
                            "invalid_registration",
                            "registration declares an empty domain name".to_string(),
                        ));
                    }
                    names.insert(domain.clone());
                }
                return Ok(Some(names));
            }
            Some(_) => {
                return Err(fault(
                    "invalid_registration",
                    format!("{field} must be an established array or map of domain names"),
                ))
            }
        }
    }
    Ok(None)
}

// ---------------------------------------------------------------------------
// Journal state
// ---------------------------------------------------------------------------

struct StoredReceipt {
    entity_key: String,
    registration_digest: String,
    view: String,
    domain: String,
    revision: u64,
    previous_revision: u64,
    receipt_id: String,
    document: Value,
    document_digest: String,
    publication_ref: Value,
    recorded_at: Value,
    receipt: Value,
}

struct JournalState {
    last_sequence: u64,
    head_hash: String,
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
    let last_sequence =
        required_u64(map, "last_sequence", "invalid_journal_view", "journal view")?;
    if last_sequence == 0 {
        return Err(fault(
            "invalid_journal_view",
            "an admitted journal has at least its manifest-admission event".to_string(),
        ));
    }
    let head_hash = required_digest(map, "head_hash", "invalid_journal_view", "journal view")?;
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
    let mut per_key: BTreeMap<(String, String, u64), String> = BTreeMap::new();
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
        let event_id = required_str(event_map, "event_id", "invalid_journal_view", "journal event")?;
        let event_hash =
            required_digest(event_map, "event_hash", "invalid_journal_view", "journal event")?;
        let payload = event_map.get("payload").and_then(Value::as_object).ok_or_else(|| {
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
            receipt,
            journal_id,
            sequence,
            event_id,
            &event_hash,
            event_map.get("recorded_at").cloned().unwrap_or(Value::Null),
            position,
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
        match per_key.get(&(
            receipt.entity_key.clone(),
            receipt.domain.clone(),
            receipt.revision,
        )) {
            Some(existing) if existing != &receipt.document_digest => {
                return Err(fault(
                    "integrity_conflict",
                    format!(
                        "revision key ({:?}, {:?}, {}) identifies two content digests across views",
                        receipt.entity_key, receipt.domain, receipt.revision
                    ),
                ))
            }
            _ => {
                per_key.insert(
                    (
                        receipt.entity_key.clone(),
                        receipt.domain.clone(),
                        receipt.revision,
                    ),
                    receipt.document_digest.clone(),
                );
            }
        }
        receipts.push(receipt);
    }

    Ok(JournalState {
        last_sequence,
        head_hash,
        receipts,
    })
}

fn parse_stored_receipt(
    receipt: &Map<String, Value>,
    journal_id: &str,
    sequence: u64,
    event_id: &str,
    event_hash: &str,
    recorded_at: Value,
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
    let registration_digest =
        required_digest(receipt, "registration_digest", "invalid_journal_view", &what)?;
    let view = required_str(receipt, "view", "invalid_journal_view", &what)?.to_string();
    let domain = required_str(receipt, "domain", "invalid_journal_view", &what)?.to_string();
    let revision = required_u64(receipt, "revision", "invalid_journal_view", &what)?;
    if revision == 0 {
        return Err(fault(
            "invalid_journal_view",
            format!("{what} journals revision zero; zero is an unpublished view slot"),
        ));
    }
    let previous_revision =
        required_u64(receipt, "previous_revision", "invalid_journal_view", &what)?;
    let receipt_id = required_str(receipt, "receipt_id", "invalid_journal_view", &what)?.to_string();
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
        Some(Value::String(digest)) if is_digest_text(digest) => digest.clone(),
        _ => {
            return Err(fault(
                "invalid_journal_view",
                format!("{what} document reference lacks a 64-character digest"),
            ))
        }
    };
    if !recorded_at.is_object() {
        return Err(fault(
            "invalid_journal_view",
            format!("{what} is not accompanied by a receipt TimePoint"),
        ));
    }
    Ok(StoredReceipt {
        entity_key,
        registration_digest,
        view,
        domain,
        revision,
        previous_revision,
        receipt_id,
        document,
        document_digest,
        publication_ref: json!({
            "journal_id": journal_id,
            "sequence": sequence,
            "event_id": event_id,
            "event_hash": event_hash,
            "pointer": "/payload/data/publication_receipt",
        }),
        recorded_at,
        receipt: Value::Object(receipt.clone()),
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
            receipt.entity_key == entity_key
                && receipt.view == view
                && receipt.domain == domain
        })
        .max_by_key(|receipt| receipt.revision)
}

fn receipt_at<'a>(
    state: &'a JournalState,
    entity_key: &str,
    view: &str,
    domain: &str,
    revision: u64,
) -> Option<&'a StoredReceipt> {
    state.receipts.iter().find(|receipt| {
        receipt.entity_key == entity_key
            && receipt.view == view
            && receipt.domain == domain
            && receipt.revision == revision
    })
}

fn receipt_at_any_view<'a>(
    state: &'a JournalState,
    entity_key: &str,
    domain: &str,
    revision: u64,
) -> Option<&'a StoredReceipt> {
    state.receipts.iter().find(|receipt| {
        receipt.entity_key == entity_key
            && receipt.domain == domain
            && receipt.revision == revision
    })
}

fn owner_head<'a>(
    state: &'a JournalState,
    entity_key: &str,
    domain: &str,
) -> Option<&'a StoredReceipt> {
    state
        .receipts
        .iter()
        .filter(|receipt| receipt.entity_key == entity_key && receipt.domain == domain)
        .max_by_key(|receipt| receipt.revision)
}

fn lineage_verified(
    state: &JournalState,
    entity_key: &str,
    domain: &str,
    mut previous: u64,
) -> bool {
    let mut hops = 0usize;
    while previous > 0 {
        hops += 1;
        if hops > 100_000 {
            return false;
        }
        let Some(receipt) = receipt_at_any_view(state, entity_key, domain, previous) else {
            return false;
        };
        if receipt.revision != previous || receipt.previous_revision + 1 != receipt.revision {
            return false;
        }
        previous = receipt.previous_revision;
    }
    true
}

fn verify_registration_identity(
    state: &JournalState,
    entity_key: &str,
    domain: &str,
    registration_digest: &str,
) -> Result<(), Fault> {
    for receipt in &state.receipts {
        if receipt.entity_key == entity_key
            && receipt.domain == domain
            && receipt.registration_digest != registration_digest
        {
            return Err(fault(
                "registration_mismatch",
                format!(
                    "domain {domain:?} is journaled under registration {}; revision names {}. Entity registration fixes the domain identity and field set",
                    receipt.registration_digest, registration_digest
                ),
            ));
        }
    }
    Ok(())
}

fn receipt_identity(receipt: &StoredReceipt) -> Value {
    json!({
        "receipt_id": receipt.receipt_id,
        "revision": receipt.revision,
        "document_digest": receipt.document_digest,
        "view": receipt.view,
        "domain": receipt.domain,
    })
}

// ---------------------------------------------------------------------------
// Document installation and delay handling
// ---------------------------------------------------------------------------

struct PreparedDocument {
    value: Value,
    reference: CheckedRecord,
    digest: String,
}

struct Delay {
    receipt: Value,
    journaled: Option<Value>,
}

fn prepare_document(
    artifacts: &dyn ArtifactStore,
    grant: &Grant,
    revision: &Map<String, Value>,
) -> Result<PreparedDocument, Fault> {
    let mut supplied_reference: Option<CheckedRecord> = None;
    let mut supplied_bytes: Option<Vec<u8>> = None;
    let value = if let Some(value) = first_established(revision, VALUE_FIELDS) {
        value.clone()
    } else if let Some(document) = established(revision, "document") {
        match document.as_object() {
            Some(document) if document.contains_key("digest") => {
                let reference = validate(OUTPUT_SCHEMA, Value::Object(document.clone()))?;
                let bytes = artifacts.read(grant, &reference).map_err(|err| {
                    fault(
                        "artifact_verification_failed",
                        format!(
                            "supplied document reference did not resolve durably before publication: {} ({})",
                            err.code, err.detail
                        ),
                    )
                })?;
                let parsed: Value = serde_json::from_slice(&bytes).map_err(|err| {
                    fault(
                        "incomplete_domain",
                        format!("supplied document bytes are not a JSON domain snapshot: {err}"),
                    )
                })?;
                let parsed = validate(OUTPUT_SCHEMA, parsed).map_err(|err| {
                    fault(
                        "incomplete_domain",
                        format!(
                            "supplied document bytes violate the missingness gate: {} ({})",
                            err.code, err.detail
                        ),
                    )
                })?;
                supplied_bytes = Some(bytes);
                supplied_reference = Some(reference);
                record_value(&parsed).clone()
            }
            Some(_) => document.clone(),
            None => {
                return Err(fault(
                    "incomplete_domain",
                    "revision document must be a complete snapshot object or artifact reference"
                        .to_string(),
                ))
            }
        }
    } else if let Some(assembled) = assembled_crawler_value(revision)? {
        assembled
    } else {
        return Err(fault(
            "incomplete_domain",
            "revision requires the complete domain snapshot (value/snapshot), a complete crawler assembly (snapshots + evidence), or an installed document reference"
                .to_string(),
        ));
    };
    if is_missing(&value) {
        return Err(fault(
            "incomplete_domain",
            "a published domain revision carries a complete snapshot; Missing is never published as a domain value"
                .to_string(),
        ));
    }

    let supplied_map = supplied_reference
        .as_ref()
        .and_then(|reference| record_value(reference).as_object());
    let media_type = match optional_nonempty(revision, "media_type")? {
        Some(media_type) => media_type,
        None => supplied_map
            .and_then(|map| established(map, "media_type"))
            .and_then(Value::as_str)
            .unwrap_or("application/json")
            .to_string(),
    };
    if media_type.is_empty() || media_type.contains('\0') {
        return Err(fault(
            "invalid_request",
            "media_type must be a nonempty string without in-band nulls".to_string(),
        ));
    }
    let restricted = match revision.get("restricted") {
        None => match optional_nonempty(revision, "access")?.as_deref() {
            Some("restricted") => true,
            Some("public") | None => false,
            Some(other) => {
                return Err(fault(
                    "invalid_request",
                    format!("access must be public or restricted, not {other:?}"),
                ))
            }
        },
        Some(Value::Bool(flag)) => *flag,
        Some(value) if is_missing(value) => false,
        Some(_) => {
            return Err(fault(
                "invalid_request",
                "restricted must be a boolean when present".to_string(),
            ))
        }
    };
    let bytes = match supplied_bytes {
        Some(bytes) => bytes,
        None => serde_json::to_vec(&value).map_err(|err| {
            fault(
                "incomplete_domain",
                format!("complete domain snapshot is not serializable: {err}"),
            )
        })?,
    };
    let reference = artifacts
        .install(grant, &bytes, &media_type, restricted)
        .map_err(|err| {
            fault(
                "artifact_verification_failed",
                format!(
                    "complete immutable document could not be installed: {} ({})",
                    err.code, err.detail
                ),
            )
        })?;
    let readback = artifacts.read(grant, &reference).map_err(|err| {
        fault(
            "artifact_verification_failed",
            format!(
                "installed document could not be verified before pointer advance: {} ({})",
                err.code, err.detail
            ),
        )
    })?;
    if readback != bytes {
        return Err(fault(
            "artifact_verification_failed",
            "installed document bytes changed between install and verification; publication never exposes partially transferred bytes"
                .to_string(),
        ));
    }
    let digest = match record_value(&reference).get("digest").and_then(Value::as_str) {
        Some(digest) if is_digest_text(digest) => digest.to_string(),
        _ => {
            return Err(fault(
                "artifact_verification_failed",
                "artifact reference installed without a complete document digest".to_string(),
            ))
        }
    };
    if let Some(expected) = expected_document_digest(revision)? {
        if expected != digest {
            return Err(fault(
                "document_mismatch",
                format!(
                    "revision names document digest {expected} but the complete installed document is {digest}"
                ),
            ));
        }
    }
    Ok(PreparedDocument {
        value,
        reference,
        digest,
    })
}

fn assembled_crawler_value(map: &Map<String, Value>) -> Result<Option<Value>, Fault> {
    let snapshots = match established(map, "snapshots") {
        Some(Value::Array(items)) => items,
        _ => return Ok(None),
    };
    let evidence = match established(map, "assembly_evidence")
        .or_else(|| established(map, "evidence"))
    {
        Some(Value::Object(evidence)) => Value::Object(evidence.clone()),
        _ => return Ok(None),
    };
    let mut checked = Vec::with_capacity(snapshots.len());
    for (index, snapshot) in snapshots.iter().enumerate() {
        checked.push(validate(OUTPUT_SCHEMA, snapshot.clone()).map_err(|err| {
            fault(
                "incomplete_domain",
                format!("snapshots[{index}] is not a checked snapshot: {}", err.detail),
            )
        })?);
    }
    let evidence = validate(OUTPUT_SCHEMA, evidence).map_err(|err| {
        fault(
            "incomplete_domain",
            format!("assembly evidence is not a checked record: {}", err.detail),
        )
    })?;
    let assembled = assemble_crawler_value(&checked, &evidence).map_err(|err| {
        fault(
            "incomplete_domain",
            format!(
                "complete crawler value assembly failed: {} ({})",
                err.code, err.detail
            ),
        )
    })?;
    Ok(Some(record_value(&assembled).clone()))
}

fn first_established<'a>(
    map: &'a Map<String, Value>,
    fields: &[&str],
) -> Option<&'a Value> {
    fields
        .iter()
        .find_map(|field| established(map, field))
}

fn expected_document_digest(map: &Map<String, Value>) -> Result<Option<String>, Fault> {
    if let Some(value) = established(map, "document_digest") {
        return match value {
            Value::String(text) if is_digest_text(text) => Ok(Some(text.clone())),
            _ => Err(fault(
                "invalid_document",
                "document_digest must be 64 lowercase hex characters".to_string(),
            )),
        };
    }
    if let Some(Value::Object(document)) = established(map, "document") {
        if let Some(digest) = document.get("digest") {
            return match digest {
                Value::String(text) if is_digest_text(text) => Ok(Some(text.clone())),
                _ => Err(fault(
                    "invalid_document",
                    "document.digest must be 64 lowercase hex characters".to_string(),
                )),
            };
        }
    }
    Ok(None)
}

fn forbidden_utc_key(value: &Value) -> Option<&'static str> {
    match value {
        Value::Object(map) => {
            for key in UTC_SUBTRACTION_KEYS {
                match map.get(*key) {
                    Some(inner) if !is_missing(inner) => return Some(key),
                    _ => {}
                }
            }
            map.values().find_map(forbidden_utc_key)
        }
        Value::Array(items) => items.iter().find_map(forbidden_utc_key),
        _ => None,
    }
}

fn publication_delay(map: &Map<String, Value>) -> Result<Delay, Fault> {
    let raw = match map.get("publication_delay") {
        None => {
            return Ok(Delay {
                receipt: missing(
                    "not_observed",
                    "no publication delay measurement accompanied this installation",
                ),
                journaled: None,
            })
        }
        Some(value) if is_missing(value) => {
            return Ok(Delay {
                receipt: value.clone(),
                journaled: None,
            })
        }
        Some(Value::Object(delay)) => delay,
        Some(_) => {
            return Err(fault(
                "invalid_publication_delay",
                "publication_delay must be a Measurement object or a Missing envelope".to_string(),
            ))
        }
    };
    if let Some(key) = forbidden_utc_key(&Value::Object(raw.clone())) {
        return Err(fault(
            "utc_subtraction_refused",
            format!(
                "publication_delay carries {key:?}; delay is never computed by subtracting independent source and destination UTC annotations"
            ),
        ));
    }
    let measurement = match raw.get("measurement") {
        Some(Value::Object(inner)) => inner.clone(),
        _ => raw.clone(),
    };
    let measurement_value = Value::Object(measurement.clone());
    let clocks = ["registered_clocks", "clock_registry", "registered_clock_registry"]
        .iter()
        .find_map(|field| established(map, field))
        .cloned()
        .ok_or_else(|| {
            fault(
                "invalid_publication_delay",
                "an established publication delay requires the registered clock evidence it was measured on"
                    .to_string(),
            )
        })?;
    let measurement_record = validate(OUTPUT_SCHEMA, measurement_value.clone())?;
    let clocks_record = validate(OUTPUT_SCHEMA, clocks)?;
    validate_measurement(&measurement_record, &clocks_record).map_err(|err| {
        fault(
            "invalid_publication_delay",
            format!(
                "publication delay measurement is not valid on its registered clocks: {} ({})",
                err.code, err.detail
            ),
        )
    })?;
    Ok(Delay {
        receipt: measurement_value.clone(),
        journaled: Some(measurement_value),
    })
}

// ---------------------------------------------------------------------------
// Receipt construction and journal append
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn journaled_receipt(
    facts: &GrantFacts,
    journal_id: &str,
    state: &JournalState,
    entity: &Value,
    _entity_key: &str,
    registration_digest: &str,
    view: &str,
    domain: &str,
    revision: u64,
    previous_revision: u64,
    writer_id: &str,
    prepared: &PreparedDocument,
    superseded: Value,
    observed_head: Value,
    delay: &Delay,
) -> Result<Value, Fault> {
    let prefix: String = prepared.digest.chars().take(16).collect();
    let receipt_id = format!("pub-{view}-{domain}-{revision}-{prefix}");
    let record = validate(
        OUTPUT_SCHEMA,
        json!({
            "record_type": PUBLICATION_RECEIPT,
            "schema_version": SCHEMA_VERSION,
            "receipt_id": receipt_id,
            "entity": entity,
            "registration_digest": registration_digest,
            "view": view,
            "publisher": facts.producer_id,
            "owner_domain": facts.owner_domain,
            "writer_id": writer_id,
            "domain": domain,
            "revision": revision,
            "previous_revision": previous_revision,
            "document": record_value(&prepared.reference).clone(),
            "document_digest": prepared.digest,
            "superseded": superseded,
            "observed_owner_head": observed_head,
            "source_prefix": {
                "journal_id": journal_id,
                "last_sequence": state.last_sequence,
                "head_hash": state.head_hash,
            },
            "installation_time": missing(
                "not_observed",
                "the carrying publication event assigns the installation time",
            ),
            "publication_ref": missing(
                "not_observed",
                "the carrying publication event is the publication reference",
            ),
            "publication_delay": delay.receipt.clone(),
        }),
    )?;
    Ok(record_value(&record).clone())
}

fn returned_receipt(existing: &StoredReceipt, value: &Value) -> Result<CheckedRecord, Fault> {
    let mut receipt = existing.receipt.clone();
    let map = receipt
        .as_object_mut()
        .ok_or_else(|| fault("invalid_receipt", "receipt must be an object".to_string()))?;
    map.insert(
        "installation_time".to_string(),
        existing.recorded_at.clone(),
    );
    map.insert(
        "publication_ref".to_string(),
        existing.publication_ref.clone(),
    );
    map.insert("value".to_string(), value.clone());
    validate(OUTPUT_SCHEMA, receipt)
}

fn finish_receipt(
    appended: &CheckedRecord,
    value: &Value,
    data_field: &str,
) -> Result<CheckedRecord, Fault> {
    let receipt_map = as_object(appended, "invalid_receipt", "store receipt")?;
    let event = receipt_map.get("event").and_then(Value::as_object).ok_or_else(|| {
        fault(
            "invalid_receipt",
            "store receipt must carry the appended journal event".to_string(),
        )
    })?;
    let data = event
        .get("payload")
        .and_then(Value::as_object)
        .and_then(|payload| payload.get("data"))
        .and_then(Value::as_object)
        .and_then(|data| data.get(data_field))
        .and_then(Value::as_object)
        .ok_or_else(|| {
            fault(
                "invalid_receipt",
                format!("store receipt event does not carry {data_field:?}"),
            )
        })?;
    let mut receipt = Value::Object(data.clone());
    let map = receipt
        .as_object_mut()
        .ok_or_else(|| fault("invalid_receipt", "receipt must be an object".to_string()))?;
    map.insert(
        "installation_time".to_string(),
        receipt_recorded_at(appended)?.clone(),
    );
    map.insert(
        "publication_ref".to_string(),
        evidence_ref(appended, &format!("/payload/data/{data_field}"))?,
    );
    map.insert("value".to_string(), value.clone());
    validate(OUTPUT_SCHEMA, receipt)
}

fn append_journal_data(
    store: &dyn OwnerStore,
    grant: &Grant,
    facts: &GrantFacts,
    journal_id: &str,
    data_field: &str,
    data_value: Value,
    measurements: Vec<Value>,
    evidence_refs: Vec<Value>,
    artifact_refs: Vec<Value>,
) -> Result<CheckedRecord, Fault> {
    let mut data = Map::new();
    data.insert(data_field.to_string(), data_value);
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
                    "owner-authored publication is not an external producer sequence",
                ),
                "event_kind": facts.event_kind,
                "event_schema_version": SCHEMA_VERSION,
                "occurred_at": missing(
                    "not_observed",
                    "publication is an owner effect without a source occurrence",
                ),
                "payload": {
                    "data": Value::Object(data),
                    "measurements": Value::Array(measurements),
                    "evidence_refs": Value::Array(evidence_refs.clone()),
                    "artifact_refs": Value::Array(artifact_refs),
                },
            },
            "causal_refs": Value::Array(evidence_refs),
        }),
    )?;
    let receipt = store.transact(grant, &transaction)?;
    let map = as_object(&receipt, "invalid_receipt", "store receipt")?;
    match map.get("durable") {
        Some(Value::Bool(true)) => {}
        _ => {
            return Err(fault(
                "publication_not_durable",
                "store did not acknowledge the pointer advance as durable; publication is not announced before durability"
                    .to_string(),
            ))
        }
    }
    required_u64(map, "journal_sequence", "invalid_receipt", "store receipt")?;
    required_digest(map, "head_hash", "invalid_receipt", "store receipt")?;
    required_digest(map, "event_hash", "invalid_receipt", "store receipt")?;
    let event = map.get("event").and_then(Value::as_object).ok_or_else(|| {
        fault(
            "invalid_receipt",
            "store receipt must carry the appended event".to_string(),
        )
    })?;
    required_str(event, "event_id", "invalid_receipt", "store receipt event")?;
    required_digest(event, "event_hash", "invalid_receipt", "store receipt event")?;
    receipt_recorded_at(&receipt)?;
    Ok(receipt)
}

fn receipt_recorded_at(receipt: &CheckedRecord) -> Result<&Value, Fault> {
    let map = as_object(receipt, "invalid_receipt", "store receipt")?;
    let recorded_at = map
        .get("event")
        .and_then(Value::as_object)
        .and_then(|event| event.get("recorded_at"))
        .ok_or_else(|| {
            fault(
                "invalid_receipt",
                "store receipt event carries no recorded_at TimePoint".to_string(),
            )
        })?;
    if !recorded_at.is_object() {
        return Err(fault(
            "invalid_receipt",
            "store receipt recorded_at must be a TimePoint object".to_string(),
        ));
    }
    Ok(recorded_at)
}

fn evidence_ref(receipt: &CheckedRecord, pointer: &str) -> Result<Value, Fault> {
    let map = as_object(receipt, "invalid_receipt", "store receipt")?;
    let event = map.get("event").and_then(Value::as_object).ok_or_else(|| {
        fault(
            "invalid_receipt",
            "store receipt must carry the appended event".to_string(),
        )
    })?;
    let reference = json!({
        "journal_id": map.get("journal_id").cloned().unwrap_or(Value::Null),
        "sequence": map.get("journal_sequence").cloned().unwrap_or(Value::Null),
        "event_id": event.get("event_id").cloned().unwrap_or(Value::Null),
        "event_hash": map.get("event_hash").cloned().unwrap_or(Value::Null),
        "pointer": pointer,
    });
    // The values above come from the store receipt and are structurally
    // checked before this point; gating them here also proves no bare null
    // leaked into the returned reference.
    validate(OUTPUT_SCHEMA, reference)
        .map(|record| record_value(&record).clone())
        .map_err(|err| {
            fault(
                "invalid_receipt",
                format!("store receipt cannot yield a complete evidence reference: {}", err.detail),
            )
        })
}

// ---------------------------------------------------------------------------
// Seal parsing for row composition
// ---------------------------------------------------------------------------

struct PinnedSlot {
    revision: u64,
    previous_revision: Option<u64>,
    digest: Option<String>,
    document: Option<Value>,
    publication_ref: Option<Value>,
    receipt_id: Option<String>,
}

struct SuppliedSlot {
    revision: u64,
    previous_revision: Option<u64>,
    digest: Option<String>,
    document: Option<Value>,
    publication_ref: Option<Value>,
    snapshot: Option<Value>,
}

fn parse_version_vector(map: &Map<String, Value>) -> Result<BTreeMap<String, PinnedSlot>, Fault> {
    let vector = established(map, "version_vector")
        .or_else(|| established(map, "vector"))
        .ok_or_else(|| {
            fault(
                "invalid_seal",
                "seal requires an exact version_vector".to_string(),
            )
        })?;
    let mut pinned = BTreeMap::new();
    match vector {
        Value::Array(entries) => {
            for (index, entry) in entries.iter().enumerate() {
                let entry = entry.as_object().ok_or_else(|| {
                    fault(
                        "invalid_seal",
                        format!("version_vector[{index}] must be an object"),
                    )
                })?;
                let (domain, slot) = parse_pinned_slot(entry, &format!("version_vector[{index}]"))?;
                if pinned.insert(domain.clone(), slot).is_some() {
                    return Err(fault(
                        "duplicate_domain",
                        format!("seal version_vector names domain {domain:?} more than once"),
                    ));
                }
            }
        }
        Value::Object(entries) => {
            for (domain, entry) in entries {
                if domain.is_empty() {
                    return Err(fault(
                        "invalid_seal",
                        "seal version_vector carries an empty domain name".to_string(),
                    ));
                }
                let slot = match entry {
                    Value::Number(number) => PinnedSlot {
                        revision: number.as_u64().ok_or_else(|| {
                            fault(
                                "invalid_seal",
                                format!("version_vector.{domain} must be an unsigned revision"),
                            )
                        })?,
                        previous_revision: None,
                        digest: None,
                        document: None,
                        publication_ref: None,
                        receipt_id: None,
                    },
                    Value::Object(entry) => parse_pinned_slot(entry, &format!("version_vector.{domain}"))?.1,
                    _ => {
                        return Err(fault(
                            "invalid_seal",
                            format!(
                                "version_vector.{domain} must be a revision number or slot object"
                            ),
                        ))
                    }
                };
                pinned.insert(domain.clone(), slot);
            }
        }
        _ => {
            return Err(fault(
                "invalid_seal",
                "seal version_vector must be an array or domain map".to_string(),
            ))
        }
    }
    Ok(pinned)
}

fn parse_pinned_slot(
    entry: &Map<String, Value>,
    what: &str,
) -> Result<(String, PinnedSlot), Fault> {
    let domain = required_str(entry, "domain", "invalid_seal", what)?.to_string();
    let revision = required_u64(entry, "revision", "invalid_seal", what)?;
    let digest = match established(entry, "document_digest") {
        Some(Value::String(text)) if is_digest_text(text) => Some(text.clone()),
        Some(_) => {
            return Err(fault(
                "invalid_seal",
                format!("{what} document_digest must be 64 lowercase hex characters"),
            ))
        }
        None => None,
    };
    if revision > 0 && digest.is_none() {
        return Err(fault(
            "invalid_seal",
            format!(
                "{what} pins domain {domain:?} at revision {revision} without a document digest"
            ),
        ));
    }
    let document = match established(entry, "document") {
        Some(Value::Object(document)) => Some(Value::Object(document.clone())),
        Some(_) => {
            return Err(fault(
                "invalid_seal",
                format!("{what} document must be a reference object"),
            ))
        }
        None => None,
    };
    let publication_ref = match established(entry, "publication_ref") {
        Some(Value::Object(reference)) => Some(Value::Object(reference.clone())),
        Some(_) => {
            return Err(fault(
                "invalid_seal",
                format!("{what} publication_ref must be an object"),
            ))
        }
        None => None,
    };
    let previous_revision = match established(entry, "previous_revision") {
        Some(Value::Number(number)) => Some(number.as_u64().ok_or_else(|| {
            fault(
                "invalid_seal",
                format!("{what} previous_revision must be an unsigned integer"),
            )
        })?),
        Some(_) => {
            return Err(fault(
                "invalid_seal",
                format!("{what} previous_revision must be an unsigned integer"),
            ))
        }
        None => None,
    };
    let receipt_id = match established(entry, "receipt_id") {
        Some(Value::String(text)) if !text.is_empty() => Some(text.clone()),
        Some(_) => {
            return Err(fault(
                "invalid_seal",
                format!("{what} receipt_id must be a nonempty string when present"),
            ))
        }
        None => None,
    };
    Ok((
        domain,
        PinnedSlot {
            revision,
            previous_revision,
            digest,
            document,
            publication_ref,
            receipt_id,
        },
    ))
}

fn parse_supplied_slot(
    entry: &Map<String, Value>,
    revision: u64,
    what: &str,
) -> Result<SuppliedSlot, Fault> {
    let previous_revision = match established(entry, "previous_revision") {
        Some(Value::Number(number)) => Some(number.as_u64().ok_or_else(|| {
            fault(
                "invalid_domain",
                format!("{what} previous_revision must be an unsigned integer"),
            )
        })?),
        Some(_) => {
            return Err(fault(
                "invalid_domain",
                format!("{what} previous_revision must be an unsigned integer"),
            ))
        }
        None => None,
    };
    let mut digest = match established(entry, "document_digest") {
        Some(Value::String(text)) if is_digest_text(text) => Some(text.clone()),
        Some(_) => {
            return Err(fault(
                "invalid_domain",
                format!("{what} document_digest must be 64 lowercase hex characters"),
            ))
        }
        None => None,
    };
    let document = match established(entry, "document") {
        Some(Value::Object(document)) => {
            if !document.contains_key("digest") {
                return Err(fault(
                    "invalid_domain",
                    format!("{what} document reference requires a digest"),
                ));
            }
            Some(Value::Object(document.clone()))
        }
        Some(_) => {
            return Err(fault(
                "invalid_domain",
                format!("{what} document must be a reference object"),
            ))
        }
        None => None,
    };
    let publication_ref = ["publication_ref", "publication", "receipt"]
        .iter()
        .find_map(|field| established(entry, field))
        .map(|value| match value {
            Value::Object(reference) => Ok(Value::Object(reference.clone())),
            _ => Err(fault(
                "missing_publication_ref",
                format!("{what} publication reference must be an object"),
            )),
        })
        .transpose()?;
    if revision == 0 {
        if let Some(value) = first_established(entry, VALUE_FIELDS) {
            if !is_missing(value) {
                return Err(fault(
                    "inconsistent_slot",
                    format!(
                        "{what} is revision zero (unpublished) but carries a complete snapshot; zero never carries published bytes"
                    ),
                ));
            }
        }
        if document.is_some() || digest.is_some() {
            return Err(fault(
                "inconsistent_slot",
                format!(
                    "{what} is revision zero (unpublished) but names a document; zero means no publication in this view"
                ),
            ));
        }
        return Ok(SuppliedSlot {
            revision: 0,
            previous_revision,
            digest: None,
            document: None,
            publication_ref,
            snapshot: None,
        });
    }
    let snapshot = match first_established(entry, VALUE_FIELDS) {
        Some(value) => value.clone(),
        None => {
            let present = VALUE_FIELDS.iter().any(|field| entry.get(*field).is_some());
            return Err(fault(
                if present {
                    "published_bytes_lost"
                } else {
                    "incomplete_domain"
                },
                format!(
                    "{what} has revision {revision} but no complete snapshot; published bytes are never replaced by Missing or a zero slot"
                ),
            ));
        }
    };
    if is_missing(&snapshot) {
        return Err(fault(
            "published_bytes_lost",
            format!(
                "{what} has revision {revision} but its snapshot is Missing; lost published bytes are an integrity incident"
            ),
        ));
    }
    if digest.is_none() {
        digest = document
            .as_ref()
            .and_then(|document| document.get("digest"))
            .and_then(Value::as_str)
            .map(|text| text.to_string());
        if digest.is_none() {
            return Err(fault(
                "missing_document",
                format!(
                    "{what} has revision {revision} but names no document digest"
                ),
            ));
        }
    }
    Ok(SuppliedSlot {
        revision,
        previous_revision,
        digest,
        document,
        publication_ref,
        snapshot: Some(snapshot),
    })
}

fn zero_slot(domain: &str) -> Value {
    json!({
        "domain": domain,
        "revision": 0,
        "document": missing(
            "not_observed",
            "no publication in this sealed read view",
        ),
        "document_digest": missing(
            "not_observed",
            "no publication in this sealed read view",
        ),
        "publication_ref": missing(
            "not_observed",
            "no publication in this sealed read view",
        ),
        "snapshot": missing(
            "not_observed",
            "no publication for this domain exists in the sealed read view",
        ),
    })
}

fn document_placeholder(digest: &str) -> Value {
    json!({
        "digest": digest,
        "size_bytes": missing(
            "not_observed",
            "the supplied slot named the digest without the artifact size",
        ),
        "media_type": missing(
            "not_observed",
            "the supplied slot named the digest without the artifact media type",
        ),
    })
}

// ---------------------------------------------------------------------------
// Expected vector guard
// ---------------------------------------------------------------------------

fn verify_expected_vector(
    request: &Map<String, Value>,
    state: &JournalState,
    entity_key: &str,
    view: &str,
) -> Result<(), Fault> {
    let expected = match established(request, "expected_version_vector")
        .or_else(|| established(request, "expected_pointer"))
    {
        Some(value) => value,
        None => return Ok(()),
    };
    let entries: Vec<(String, u64)> = match expected {
        Value::Array(items) => {
            let mut entries = Vec::new();
            for (index, item) in items.iter().enumerate() {
                let map = item.as_object().ok_or_else(|| {
                    fault(
                        "invalid_request",
                        format!("expected_version_vector[{index}] must be an object"),
                    )
                })?;
                let domain = required_str(
                    map,
                    "domain",
                    "invalid_request",
                    &format!("expected_version_vector[{index}]"),
                )?
                .to_string();
                let revision = required_u64(
                    map,
                    "revision",
                    "invalid_request",
                    &format!("expected_version_vector[{index}]"),
                )?;
                entries.push((domain, revision));
            }
            entries
        }
        Value::Object(items) => {
            let mut entries = Vec::new();
            for (domain, value) in items {
                let revision = match value {
                    Value::Number(number) => number.as_u64().ok_or_else(|| {
                        fault(
                            "invalid_request",
                            "expected version revisions must be unsigned integers".to_string(),
                        )
                    })?,
                    Value::Object(slot) => required_u64(
                        slot,
                        "revision",
                        "invalid_request",
                        "expected version slot",
                    )?,
                    _ => {
                        return Err(fault(
                            "invalid_request",
                            "expected pointer values must be revision numbers or slot objects"
                                .to_string(),
                        ))
                    }
                };
                entries.push((domain.clone(), revision));
            }
            entries
        }
        _ => {
            return Err(fault(
                "invalid_request",
                "expected_version_vector must be an array or domain map".to_string(),
            ))
        }
    };
    for (domain, expected_revision) in entries {
        let actual = pointer(state, entity_key, view, &domain)
            .map(|receipt| receipt.revision)
            .unwrap_or(0);
        if actual != expected_revision {
            return Err(fault(
                "view_changed",
                format!(
                    "view {view:?} domain {domain:?} moved from revision {expected_revision} to {actual}; reselect before pinning a mismatched state"
                ),
            ));
        }
    }
    Ok(())
}

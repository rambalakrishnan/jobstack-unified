//! `crawler_store`: owner-local durable journal with contiguous sequencing.
//!
//! This is the crawler's owner-local store seam (`OwnerStore`). It implements
//! the journal half of EK-JOURNAL / EK-OBSERVATION / EK-PROVENANCE / EK-ATOMICITY
//! and the write-isolation half of OWD-LOCAL-COMMIT:
//!
//! * **[EK-JOURNAL]** An acknowledged event is durably appended. Sequences are
//!   contiguous and strictly increasing within a journal, beginning at 1. The
//!   first event is `manifest_admitted` and pins the complete immutable
//!   manifest. Every later event names the same run, journal, and manifest
//!   digest. Acknowledged events are never edited, deleted, resequenced, or
//!   backdated.
//! * **[EK-PROVENANCE]** The store is the ingestion authority. Callers submit
//!   an `EventSubmission` plus their authenticated principal, never a journal
//!   envelope. Owner domain, role, assertion kind, provenance, evidence scope,
//!   event id, sequence, receipt time, and hashes are assigned here, from the
//!   manifest's producer/event registry (via
//!   [`crawler_authority::authorize_producer`]). Any submitted
//!   server/provenance/authority field is rejected rather than trusted.
//! * **[EK-OBSERVATION]** `(producer_id, producer_sequence)` deliveries are
//!   deduplicated without duplicating effects. Conflicting content under the
//!   same key is an integrity incident, never last-write-wins. Producer gaps
//!   are journaled when a sequence jump is observed; late evidence is appended
//!   at the current head (never inserted into an earlier prefix) and the gap
//!   record retains which sequences later arrived late. Producer closure is a
//!   journaled event; after closure only late gap-fills remain admissible.
//! * **[EK-ATOMICITY]** A commit appends the authoritative event, updates the
//!   idempotency record for the producer key, and advances the journal prefix
//!   as one owner-local effect before the receipt is returned. Referenced
//!   artifact bytes are resolved durably *before* that commit.
//! * **[OWD-LOCAL-COMMIT]** Each journal has its own writer lock. No owner
//!   commit acquires a peer-owned journal lock, waits for a peer transaction,
//!   or requires a peer acknowledgement: product writes and large artifact
//!   transfer on a product-owned journal cannot hold the crawler ingest writer.
//!
//! Cross-owner import is asynchronous and retains original authority:
//! [`import_event`] journals a verified foreign envelope as
//! `historical_unscored` evidence under a local contiguous sequence, preserving
//! the source journal, sequence, event id, hash, provenance, and scope inside
//! the imported record. Import never upgrades evidence into a contemporary
//! authoritative effect.
//!
//! Durability in [`MemoryOwnerStore`] is process-local, exactly like
//! [`crawler_artifacts::MemoryArtifactStore`]: the append is complete before the
//! receipt is returned. Production deployments back the same trait with a
//! durable append-only segment store; the ordering, dedup, conflict, gap, and
//! isolation semantics are identical.

use crawler_artifacts::ArtifactStore;
use crawler_authority::{authorize_producer, grant_record, Grant};
use crawler_hashing::{canonical_bytes, digest_bytes};
use crawler_schema::{record_value, validate, CheckedRecord, Fault};
use crawler_time::ClockAuthority;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, RwLock};

/// Structural envelope for records produced by this module.
const OUTPUT_SCHEMA: &str = "audit_log";

/// Evidence-kernel record schema version stamped on every envelope.
const SCHEMA_VERSION: &str = "evidence-kernel/0.1.0";

const JOURNAL_EVENT: &str = "journal_event";
const COMMIT_RECEIPT: &str = "commit_receipt";
const JOURNAL_VIEW: &str = "journal_view";
const JOURNAL_PREFIX: &str = "journal_prefix";
const MANIFEST_ADMITTED: &str = "manifest_admitted";
const PRODUCER_CLOSED: &str = "producer_closed";
const EVIDENCE_IMPORTED: &str = "evidence_imported";

/// Envelope roles (Contract 00 `JournalEnvelope.role`).
const ROLES: &[&str] = &["external_input", "derived_output", "lifecycle_observation"];

/// Envelope assertion kinds (Contract 00 `JournalEnvelope.assertion_kind`).
const ASSERTION_KINDS: &[&str] = &["observation", "claim", "authoritative_effect", "derived_assessment"];

/// Ingestion-assigned provenance classes (Contract 00 `Provenance`).
const PROVENANCES: &[&str] = &["server", "fixture_client", "connector", "subject", "manual_observer", "importer"];

/// Evidence scopes (Contract 00 `JournalEnvelope.evidence_scope`).
const EVIDENCE_SCOPES: &[&str] = &["current_run", "historical_unscored", "synthetic"];

/// Server-assigned fields a transaction must never carry (S06, §13.1).
const FORBIDDEN_TRANSACTION: &[&str] = &[
    "owner_domain",
    "provenance",
    "role",
    "assertion_kind",
    "journal_sequence",
    "event_id",
    "event_hash",
    "previous_event_hash",
    "recorded_at",
    "evidence_scope",
    "manifest_hash",
];

/// Fields only the admission transaction may carry; every later event inherits
/// the admitted immutable scope.
const ADMISSION_ONLY_FIELDS: &[&str] = &["run_id", "manifest"];

/// Fields only an event-append or import transaction may carry.
const APPEND_ONLY_FIELDS: &[&str] = &["submission"];

// ---------------------------------------------------------------------------
// Public interface
// ---------------------------------------------------------------------------

/// Owner-local durable store.
///
/// `transact` commits one owner-local durable effect (admitted input,
/// idempotency record, journal event, replayable receipt) and returns the
/// receipt only after the effect is durable. `read` returns a journal view,
/// prefix, or single event; reads never create or advance a journal.
pub trait OwnerStore: Send + Sync {
    fn transact(&self, grant: &Grant, transaction: &CheckedRecord) -> Result<CheckedRecord, Fault>;
    fn read(&self, grant: &Grant, query: &CheckedRecord) -> Result<CheckedRecord, Fault>;
}

/// Asynchronously import one foreign journal envelope as local evidence.
///
/// The event must be a complete, self-consistent [`JournalEnvelope`] (the
/// module recomputes `event_hash` over the canonical envelope with
/// `event_hash` removed). It is journaled under a local contiguous sequence as
/// `evidence_imported` with `evidence_scope: historical_unscored`; the source
/// journal, sequence, event id, hash, owner, provenance, assertion kind, and
/// scope are retained verbatim inside the imported record. Re-importing the
/// same source coordinate is idempotent; a different hash under that
/// coordinate is an integrity conflict.
pub fn import_event(
    store: &dyn OwnerStore,
    grant: &Grant,
    event: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    // Validate the source envelope shape here so callers get a precise fault
    // before the transaction crosses the store seam; the store re-verifies the
    // digest and applies ordering/dedup.
    parse_source_event(event)?;
    let transaction = validate(
        OUTPUT_SCHEMA,
        json!({
            "operation": "import_event",
            "source_event": record_value(event).clone(),
        }),
    )?;
    store.transact(grant, &transaction)
}

// ---------------------------------------------------------------------------
// In-memory owner store
// ---------------------------------------------------------------------------

/// In-memory [`OwnerStore`].
///
/// One [`Journal`] per `journal_id`, each behind its own `Mutex`. The registry
/// lock guards only journal lookup/creation, never an event append or artifact
/// transfer, so unrelated owner domains commit concurrently.
pub struct MemoryOwnerStore {
    manifest: CheckedRecord,
    manifest_digest: String,
    clock: Arc<dyn ClockAuthority>,
    artifacts: Arc<dyn ArtifactStore>,
    journals: RwLock<HashMap<String, Arc<Mutex<Journal>>>>,
}

impl MemoryOwnerStore {
    /// New store bound to one admitted manifest, one receipt clock, and one
    /// durable artifact store.
    pub fn new(
        manifest: CheckedRecord,
        clock: Arc<dyn ClockAuthority>,
        artifacts: Arc<dyn ArtifactStore>,
    ) -> Result<Self, Fault> {
        let manifest_digest = digest_bytes(&canonical_bytes(&manifest)?);
        Ok(Self {
            manifest,
            manifest_digest,
            clock,
            artifacts,
            journals: RwLock::new(HashMap::new()),
        })
    }

    /// Kernel digest of the manifest this store admits.
    pub fn manifest_hash(&self) -> &str {
        &self.manifest_digest
    }

    fn journal(&self, journal_id: &str) -> Result<Option<Arc<Mutex<Journal>>>, Fault> {
        let guard = self.journals.read().map_err(|_| {
            fault("internal_error", "journal registry lock poisoned".to_string())
        })?;
        Ok(guard.get(journal_id).cloned())
    }

    fn open_journal(&self, journal_id: &str) -> Result<Arc<Mutex<Journal>>, Fault> {
        let mut guard = self.journals.write().map_err(|_| {
            fault("internal_error", "journal registry lock poisoned".to_string())
        })?;
        if let Some(existing) = guard.get(journal_id) {
            return Ok(existing.clone());
        }
        let journal = Arc::new(Mutex::new(Journal::new(
            journal_id,
            self.manifest_digest.clone(),
            record_value(&self.manifest).clone(),
        )));
        guard.insert(journal_id.to_string(), journal.clone());
        Ok(journal)
    }

    /// Authority receipt time: a registered clock's `TimePoint`.
    fn recorded_at(&self) -> Result<Value, Fault> {
        let now = self.clock.now()?;
        let map = record_value(&now).as_object().ok_or_else(|| {
            fault(
                "invalid_clock",
                "clock authority must report a TimePoint object".to_string(),
            )
        })?;
        for field in ["clock_id", "boot_id", "origin", "monotonic_offset_ms", "utc_annotation"] {
            if map.get(field).is_none() {
                return Err(fault(
                    "invalid_clock",
                    format!("clock authority TimePoint is missing {field:?}"),
                ));
            }
        }
        Ok(record_value(&now).clone())
    }

    fn admit_manifest(
        &self,
        grant: &Grant,
        transaction: &Map<String, Value>,
    ) -> Result<CheckedRecord, Fault> {
        reject_authority_fields(transaction, FORBIDDEN_TRANSACTION)?;
        reject_authority_fields(transaction, APPEND_ONLY_FIELDS)?;
        let journal_id = required_str(transaction, "journal_id", "missing_journal_id", "transaction")?;
        let run_id = required_str(transaction, "run_id", "missing_run_id", "transaction")?;
        let manifest_value = transaction.get("manifest").ok_or_else(|| {
            fault(
                "missing_manifest",
                "admission requires the complete immutable manifest".to_string(),
            )
        })?;
        let manifest_record = validate(OUTPUT_SCHEMA, manifest_value.clone())?;
        let manifest_digest = digest_bytes(&canonical_bytes(&manifest_record)?);
        if manifest_digest != self.manifest_digest {
            return Err(fault(
                "manifest_mismatch",
                "admission manifest digest does not match the store's pinned manifest".to_string(),
            ));
        }

        let principal = principal_of(transaction, &self.manifest_digest)?;
        let producer_id = principal_producer_id(&principal)?;
        let recorded_at = self.recorded_at()?;

        // The store builds the admission submission: untrusted callers never
        // supply a journal envelope, and the manifest pin is authority-authored.
        let submission = validate(
            OUTPUT_SCHEMA,
            json!({
                "producer_sequence": 1,
                "event_kind": MANIFEST_ADMITTED,
                "event_schema_version": SCHEMA_VERSION,
                "occurred_at": missing("not_applicable", "manifest admission has no source occurrence"),
                "payload": {
                    "data": {
                        "manifest": manifest_value,
                        "manifest_digest": manifest_digest,
                    },
                    "measurements": [],
                    "evidence_refs": [],
                    "artifact_refs": [],
                },
            }),
        )?;
        let derived = authorize_producer(
            &principal,
            &authorization_view(&submission)?,
            &self.manifest,
        )?;
        cross_check_grant(grant, &derived, producer_id, &self.manifest_digest)?;
        let authority = AuthorityFacts::of(&derived)?;
        if authority.role != "external_input" || authority.provenance != "server" {
            return Err(fault(
                "invalid_admission_authority",
                "journal sequence 1 must be admitted by a server-provenance external_input writer"
                    .to_string(),
            ));
        }
        let evidence_scope = evidence_scope_for(&authority.provenance)?;

        let content_digest = digest_bytes(&canonical_bytes(&submission)?);
        let sequence = 1u64;
        let envelope = seal(EnvelopeSeed {
            journal_id,
            run_id,
            manifest_hash: &self.manifest_digest,
            sequence,
            event_id: format!("evt-{sequence}-{}", digest_prefix(&content_digest)),
            event_kind: MANIFEST_ADMITTED,
            event_schema_version: SCHEMA_VERSION,
            role: &authority.role,
            assertion_kind: &authority.assertion_kind,
            owner_domain: &authority.owner_domain,
            producer_id,
            producer_sequence: json!(1),
            provenance: &authority.provenance,
            evidence_scope,
            recorded_at: recorded_at.clone(),
            occurred_at: record_value(&submission)["occurred_at"].clone(),
            causal_refs: Vec::new(),
            payload: record_value(&submission)["payload"].clone(),
            previous_event_hash: missing("not_applicable", "sequence 1 has no predecessor"),
        })?;
        let event_hash = envelope["event_hash"].as_str().unwrap_or_default().to_string();
        let receipt = build_receipt(
            "admit_manifest",
            "appended",
            &envelope,
            &event_hash,
            &authority.owner_domain,
            false,
            None,
        );

        // Owner-local durable effect: append + idempotency + prefix advance.
        let journal = self.open_journal(journal_id)?;
        let mut state = lock_journal(&journal)?;
        if !state.events.is_empty() {
            return Err(fault(
                "journal_exists",
                format!("journal {journal_id:?} already admitted its manifest"),
            ));
        }
        if state
            .owner_domain
            .as_deref()
            .is_some_and(|owner| owner != authority.owner_domain.as_str())
        {
            return Err(fault(
                "unauthorized_owner",
                format!(
                    "journal {journal_id:?} is owned by {:?}; {:?} cannot admit it",
                    state.owner_domain, authority.owner_domain
                ),
            ));
        }
        state.owner_domain = Some(authority.owner_domain.clone());
        state.run_id = Some(run_id.to_string());
        state.head_hash = event_hash.clone();
        state.events.push(envelope.clone());
        state.idempotency.insert(
            (producer_id.to_string(), 1),
            Idempotency {
                content_digest,
                receipt: receipt.clone(),
            },
        );
        let lifetime = state
            .lifetimes
            .entry(producer_id.to_string())
            .or_insert_with(ProducerLifetime::new);
        lifetime.next_sequence = 2;
        drop(state);

        validate(OUTPUT_SCHEMA, receipt)
    }

    fn append_event(
        &self,
        grant: &Grant,
        transaction: &Map<String, Value>,
    ) -> Result<CheckedRecord, Fault> {
        reject_authority_fields(transaction, FORBIDDEN_TRANSACTION)?;
        reject_authority_fields(transaction, ADMISSION_ONLY_FIELDS)?;
        let journal_id = required_str(transaction, "journal_id", "missing_journal_id", "transaction")?;
        let submission_value = transaction.get("submission").ok_or_else(|| {
            fault(
                "missing_submission",
                "append requires an EventSubmission; callers never submit journal envelopes"
                    .to_string(),
            )
        })?;
        let submission = validate(OUTPUT_SCHEMA, submission_value.clone())?;
        let submitted = record_value(&submission)
            .as_object()
            .ok_or_else(|| {
                fault(
                    "invalid_submission",
                    "submission must be an EventSubmission object".to_string(),
                )
            })?;
        let event_kind = required_str(submitted, "event_kind", "missing_event_kind", "submission")?;
        if event_kind == MANIFEST_ADMITTED {
            return Err(fault(
                "manifest_admitted_requires_admission",
                "manifest_admitted is only admissible as journal sequence 1".to_string(),
            ));
        }
        required_str(submitted, "event_schema_version", "missing_event_schema_version", "submission")?;
        let payload = check_payload(submitted)?;
        let sequence_claim = submitted_sequence(submitted)?;
        let causal_refs = causal_refs_of(transaction)?;
        check_evidence_refs(&causal_refs)?;
        let evidence_refs = payload
            .get("evidence_refs")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        check_evidence_refs(&evidence_refs)?;

        let principal = principal_of(transaction, &self.manifest_digest)?;
        let producer_id = principal_producer_id(&principal)?;
        let derived = authorize_producer(
            &principal,
            &authorization_view(&submission)?,
            &self.manifest,
        )?;
        cross_check_grant(grant, &derived, producer_id, &self.manifest_digest)?;
        let authority = AuthorityFacts::of(&derived)?;
        let evidence_scope = evidence_scope_for(&authority.provenance)?;
        if event_kind == PRODUCER_CLOSED && !matches!(sequence_claim, SubmittedSequence::Sequenced(_)) {
            return Err(fault(
                "unsequenced_closure",
                "producer closure requires an established terminal producer_sequence".to_string(),
            ));
        }

        let journal = self.journal(journal_id)?.ok_or_else(|| {
            fault(
                "unknown_journal",
                format!("journal {journal_id:?} has not admitted a manifest"),
            )
        })?;
        let recorded_at = self.recorded_at()?;
        let content_digest = digest_bytes(&canonical_bytes(&submission)?);
        let event_kind_owned = event_kind.to_string();
        let producer_owned = producer_id.to_string();

        let mut state = lock_journal(&journal)?;
        if state.owner_domain.as_deref() != Some(authority.owner_domain.as_str()) {
            return Err(fault(
                "unauthorized_owner",
                format!(
                    "journal {journal_id:?} is owned by {:?}; {:?} cannot append to it",
                    state.owner_domain, authority.owner_domain
                ),
            ));
        }
        let run_id = state.run_id.clone().unwrap_or_default();
        let sequence = state.events.len() as u64 + 1;

        // Deduplicate identical (producer_id, producer_sequence) deliveries and
        // treat conflicting content under that key as an integrity incident.
        if let SubmittedSequence::Sequenced(producer_sequence) = sequence_claim {
            if let Some(existing) = state
                .idempotency
                .get(&(producer_owned.clone(), producer_sequence))
            {
                if existing.content_digest != content_digest {
                    return Err(fault(
                        "producer_conflict",
                        format!(
                            "producer {producer_owned:?} sequence {producer_sequence} already carries different content; conflicting content under one producer key is an integrity incident"
                        ),
                    ));
                }
                let mut receipt = existing.receipt.clone();
                receipt["disposition"] = json!("duplicate");
                return validate(OUTPUT_SCHEMA, receipt);
            }
        }

        // Placement is computed before the envelope so the gap record and the
        // receipt describe the same decision. The probe does not mutate state:
        // a fresh producer lifetime is equivalent to an empty registered one.
        let placement = match sequence_claim {
            SubmittedSequence::Unsequenced => Placement::Unsequenced,
            SubmittedSequence::Sequenced(producer_sequence) => {
                let fresh;
                let lifetime = match state.lifetimes.get(&producer_owned) {
                    Some(lifetime) => lifetime,
                    None => {
                        fresh = ProducerLifetime::new();
                        &fresh
                    }
                };
                placement_for(lifetime, producer_sequence)?
            }
        };
        let gap_detected = match placement {
            Placement::Sequential { gap } => gap,
            _ => None,
        };
        let late_evidence = matches!(placement, Placement::Late { .. });

        // Earlier registered support must resolve inside this journal prefix.
        resolve_evidence_refs(&state, &causal_refs, sequence)?;
        resolve_evidence_refs(&state, &evidence_refs, sequence)?;

        // Install referenced artifact bytes durably before the commit. This runs
        // under this owner's journal lock only; a peer owner's journal is never
        // touched by another owner's payload transfer.
        for reference in artifact_refs(payload) {
            let reference_record = validate(OUTPUT_SCHEMA, reference.clone())?;
            self.artifacts.read(grant, &reference_record).map_err(|err| {
                fault(
                    "unresolved_artifact_reference",
                    format!(
                        "artifact reference must resolve durably before commit: {} ({})",
                        err.code, err.detail
                    ),
                )
            })?;
        }

        let previous_event_hash = Value::String(state.head_hash.clone());
        let envelope = seal(EnvelopeSeed {
            journal_id,
            run_id: &run_id,
            manifest_hash: &self.manifest_digest,
            sequence,
            event_id: format!("evt-{sequence}-{}", digest_prefix(&content_digest)),
            event_kind: &event_kind_owned,
            event_schema_version: required_str(
                submitted,
                "event_schema_version",
                "missing_event_schema_version",
                "submission",
            )?,
            role: &authority.role,
            assertion_kind: &authority.assertion_kind,
            owner_domain: &authority.owner_domain,
            producer_id: &producer_owned,
            producer_sequence: match sequence_claim {
                SubmittedSequence::Sequenced(producer_sequence) => json!(producer_sequence),
                SubmittedSequence::Unsequenced => record_value(&submission)["producer_sequence"].clone(),
            },
            provenance: &authority.provenance,
            evidence_scope,
            recorded_at,
            occurred_at: submitted.get("occurred_at").cloned().unwrap_or_else(|| {
                missing("not_observed", "submission carries no occurred_at")
            }),
            causal_refs: causal_refs.clone(),
            payload: Value::Object(payload.clone()),
            previous_event_hash,
        })?;
        let event_hash = envelope["event_hash"].as_str().unwrap_or_default().to_string();
        let receipt = build_receipt(
            "append_event",
            "appended",
            &envelope,
            &event_hash,
            &authority.owner_domain,
            late_evidence,
            gap_detected,
        );

        // Owner-local durable effect.
        state.head_hash = event_hash.clone();
        state.events.push(envelope.clone());
        let lifetime = state
            .lifetimes
            .entry(producer_owned.clone())
            .or_insert_with(ProducerLifetime::new);
        apply_placement(lifetime, placement, sequence);
        if event_kind_owned == PRODUCER_CLOSED {
            lifetime.closed = true;
            lifetime.terminal_sequence = match sequence_claim {
                SubmittedSequence::Sequenced(producer_sequence) => Some(producer_sequence),
                SubmittedSequence::Unsequenced => None,
            };
        }
        if let SubmittedSequence::Sequenced(producer_sequence) = sequence_claim {
            state.idempotency.insert(
                (producer_owned.clone(), producer_sequence),
                Idempotency {
                    content_digest,
                    receipt: receipt.clone(),
                },
            );
        }
        drop(state);

        validate(OUTPUT_SCHEMA, receipt)
    }

    fn import_record(
        &self,
        grant: &Grant,
        transaction: &Map<String, Value>,
    ) -> Result<CheckedRecord, Fault> {
        reject_authority_fields(transaction, FORBIDDEN_TRANSACTION)?;
        reject_authority_fields(transaction, ADMISSION_ONLY_FIELDS)?;
        reject_authority_fields(transaction, APPEND_ONLY_FIELDS)?;
        reject_authority_fields(
            transaction,
            &["principal", "causal_refs", "journal_id"],
        )?;
        let authority = AuthorityFacts::from_grant(grant)?;
        let recorded_at = self.recorded_at()?;
        let source_value = transaction.get("source_event").ok_or_else(|| {
            fault(
                "missing_source_event",
                "import requires the foreign journal envelope".to_string(),
            )
        })?;
        let source_record = validate(OUTPUT_SCHEMA, source_value.clone())?;
        let source = parse_source_event(&source_record)?;

        // The local import journal is namespaced by the source journal id and
        // owned by the importing writer. Its manifest pin is the locally
        // admitted manifest; the source manifest digest is retained verbatim.
        let journal = match self.journal(&source.journal_id)? {
            Some(existing) => existing,
            None => self.open_journal(&source.journal_id)?,
        };
        let mut state = lock_journal(&journal)?;
        if let Some(owner) = state.owner_domain.as_deref() {
            if owner != authority.owner_domain.as_str() {
                return Err(fault(
                    "unauthorized_owner",
                    format!(
                        "journal {:?} is owned by {owner:?}; {:?} cannot import into it",
                        source.journal_id, authority.owner_domain
                    ),
                ));
            }
        }
        if let Some(existing) = state
            .imports
            .iter()
            .find(|record| record.source_sequence == source.sequence)
        {
            if existing.source_event_hash != source.event_hash {
                return Err(fault(
                    "import_conflict",
                    format!(
                        "source journal {:?} sequence {} already imported with a different event hash; conflicting content is an integrity incident",
                        source.journal_id, source.sequence
                    ),
                ));
            }
            let mut receipt = existing.receipt.clone();
            receipt["disposition"] = json!("duplicate");
            return validate(OUTPUT_SCHEMA, receipt);
        }
        let local_sequence = state.events.len() as u64 + 1;
        let run_id = state
            .run_id
            .clone()
            .unwrap_or_else(|| source.run_id.clone());
        let previous_event_hash = if state.events.is_empty() {
            missing("not_applicable", "first local import has no predecessor")
        } else {
            Value::String(state.head_hash.clone())
        };
        let producer_sequence = missing(
            "not_applicable",
            "an import appointment is not a producer lifetime sequence",
        );
        let producer_id = authority
            .producer_id
            .clone()
            .unwrap_or_else(|| "importer".to_string());
        let envelope = seal(EnvelopeSeed {
            journal_id: &source.journal_id,
            run_id: &run_id,
            manifest_hash: &self.manifest_digest,
            sequence: local_sequence,
            event_id: format!("evt-{local_sequence}-import"),
            event_kind: EVIDENCE_IMPORTED,
            event_schema_version: SCHEMA_VERSION,
            role: "external_input",
            assertion_kind: "observation",
            owner_domain: &authority.owner_domain,
            producer_id: &producer_id,
            producer_sequence,
            provenance: &authority.provenance,
            evidence_scope: "historical_unscored",
            recorded_at,
            occurred_at: source.occurred_at.clone(),
            causal_refs: Vec::new(),
            payload: json!({
                "data": {
                    "source_journal_id": source.journal_id,
                    "source_run_id": source.run_id,
                    "source_sequence": source.sequence,
                    "source_event_id": source.event_id,
                    "source_event_hash": source.event_hash,
                    "source_manifest_hash": source.manifest_hash,
                    "source_owner_domain": source.owner_domain,
                    "source_producer_id": source.producer_id,
                    "source_provenance": source.provenance,
                    "source_assertion_kind": source.assertion_kind,
                    "source_evidence_scope": source.evidence_scope,
                    "source_event": source.record,
                },
                "measurements": [],
                "evidence_refs": [],
                "artifact_refs": [],
            }),
            previous_event_hash,
        })?;
        let event_hash = envelope["event_hash"].as_str().unwrap_or_default().to_string();
        let receipt = build_receipt(
            "import_event",
            "appended",
            &envelope,
            &event_hash,
            &authority.owner_domain,
            false,
            None,
        );

        state.owner_domain = Some(authority.owner_domain.clone());
        state.run_id = Some(run_id);
        state.head_hash = event_hash;
        state.events.push(envelope);
        state.imports.push(ImportRecord {
            source_sequence: source.sequence,
            source_event_hash: source.event_hash,
            journal_sequence: local_sequence,
            receipt: receipt.clone(),
        });
        drop(state);

        validate(OUTPUT_SCHEMA, receipt)
    }
}

impl OwnerStore for MemoryOwnerStore {
    fn transact(&self, grant: &Grant, transaction: &CheckedRecord) -> Result<CheckedRecord, Fault> {
        let map = record_value(transaction).as_object().ok_or_else(|| {
            fault(
                "invalid_transaction",
                "transaction must be an object naming an operation".to_string(),
            )
        })?;
        let operation = required_str(map, "operation", "missing_operation", "transaction")?;
        match operation {
            "admit_manifest" => self.admit_manifest(grant, map),
            "append_event" => self.append_event(grant, map),
            "import_event" => self.import_record(grant, map),
            other => Err(fault(
                "unknown_operation",
                format!(
                    "operation {other:?} is not one of admit_manifest, append_event, import_event"
                ),
            )),
        }
    }

    fn read(&self, grant: &Grant, query: &CheckedRecord) -> Result<CheckedRecord, Fault> {
        let map = record_value(query).as_object().ok_or_else(|| {
            fault(
                "invalid_query",
                "query must be an object naming a query kind".to_string(),
            )
        })?;
        let kind = required_str(map, "query", "missing_query", "query")?;
        let journal_id = required_str(map, "journal_id", "missing_journal_id", "query")?;
        let journal = self.journal(journal_id)?.ok_or_else(|| {
            fault(
                "unknown_journal",
                format!("journal {journal_id:?} has not admitted a manifest"),
            )
        })?;
        let owner_domain = grant_owner(grant)?;
        let state = lock_journal(&journal)?;
        if state.owner_domain.as_deref() != Some(owner_domain.as_str()) {
            return Err(fault(
                "unauthorized_owner",
                format!(
                    "journal {journal_id:?} is owned by {:?}; {owner_domain:?} cannot read it",
                    state.owner_domain
                ),
            ));
        }
        match kind {
            "journal" => validate(OUTPUT_SCHEMA, journal_view(journal_id, &state)),
            "prefix" => validate(OUTPUT_SCHEMA, prefix_view(journal_id, &state)),
            "event" => {
                let sequence = required_u64(map, "journal_sequence", "missing_journal_sequence", "query")?;
                let envelope = state
                    .events
                    .get(sequence.saturating_sub(1) as usize)
                    .filter(|_| sequence >= 1)
                    .ok_or_else(|| {
                        fault(
                            "unknown_event",
                            format!(
                                "journal {journal_id:?} has no event at sequence {sequence}"
                            ),
                        )
                    })?;
                validate(OUTPUT_SCHEMA, envelope.clone())
            }
            other => Err(fault(
                "unknown_query",
                format!("query {other:?} is not one of journal, prefix, event"),
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// Journal state
// ---------------------------------------------------------------------------

struct Journal {
    journal_id: String,
    owner_domain: Option<String>,
    run_id: Option<String>,
    manifest_hash: String,
    manifest: Value,
    events: Vec<Value>,
    head_hash: String,
    lifetimes: BTreeMap<String, ProducerLifetime>,
    idempotency: HashMap<(String, u64), Idempotency>,
    imports: Vec<ImportRecord>,
}

impl Journal {
    fn new(journal_id: &str, manifest_hash: String, manifest: Value) -> Self {
        Self {
            journal_id: journal_id.to_string(),
            owner_domain: None,
            run_id: None,
            manifest_hash,
            manifest,
            events: Vec::new(),
            head_hash: String::new(),
            lifetimes: BTreeMap::new(),
            idempotency: HashMap::new(),
            imports: Vec::new(),
        }
    }
}

/// Authoritative replay of one producer key.
struct Idempotency {
    content_digest: String,
    receipt: Value,
}

/// One producer sequence lifetime: expected next sequence, closure, and the
/// gaps that were journaled when a sequence jump was first observed.
struct ProducerLifetime {
    next_sequence: u64,
    closed: bool,
    terminal_sequence: Option<u64>,
    gaps: Vec<ProducerGap>,
    late_evidence: Vec<u64>,
}

impl ProducerLifetime {
    fn new() -> Self {
        Self {
            next_sequence: 1,
            closed: false,
            terminal_sequence: None,
            gaps: Vec::new(),
            late_evidence: Vec::new(),
        }
    }
}

/// A gap between observed producer sequences. Never edited or deleted: late
/// arrivals are recorded inside `observed_late` with the *new* journal
/// sequence they were appended at.
struct ProducerGap {
    from_sequence: u64,
    to_sequence: u64,
    detected_at: u64,
    observed_late: Vec<(u64, u64)>,
}

/// A locally journaled import of one foreign event.
struct ImportRecord {
    source_sequence: u64,
    source_event_hash: String,
    journal_sequence: u64,
    receipt: Value,
}

/// Where an arriving producer sequence belongs relative to the lifetime head.
enum Placement {
    Unsequenced,
    /// Equal to the expected sequence, with the gap it skipped (if any).
    Sequential { gap: Option<(u64, u64)> },
    /// Below the head but inside a journaled, not-yet-filled gap.
    Late { gap_index: usize, producer_sequence: u64 },
}

fn placement_for(
    lifetime: &ProducerLifetime,
    producer_sequence: u64,
) -> Result<Placement, Fault> {
    if lifetime.closed {
        if let Some(terminal) = lifetime.terminal_sequence {
            if producer_sequence >= terminal {
                return Err(fault(
                    "producer_closed",
                    format!(
                        "producer lifetime closed at sequence {terminal}; sequence {producer_sequence} cannot be appended after closure"
                    ),
                ));
            }
        }
    }
    if producer_sequence == lifetime.next_sequence {
        return Ok(Placement::Sequential { gap: None });
    }
    if producer_sequence > lifetime.next_sequence {
        return Ok(Placement::Sequential {
            gap: Some((lifetime.next_sequence, producer_sequence - 1)),
        });
    }
    for (index, gap) in lifetime.gaps.iter().enumerate() {
        if producer_sequence >= gap.from_sequence && producer_sequence <= gap.to_sequence {
            if gap.observed_late.iter().any(|(seq, _)| *seq == producer_sequence) {
                return Err(fault(
                    "late_evidence_conflict",
                    format!(
                        "gap sequence {producer_sequence} was already supplied late; a sequence is never appended twice"
                    ),
                ));
            }
            return Ok(Placement::Late {
                gap_index: index,
                producer_sequence,
            });
        }
    }
    Err(fault(
        "producer_sequence_conflict",
        format!(
            "sequence {producer_sequence} is below the producer head but outside every recorded gap; evidence is never backdated into an earlier prefix"
        ),
    ))
}

fn apply_placement(lifetime: &mut ProducerLifetime, placement: Placement, journal_sequence: u64) {
    match placement {
        Placement::Unsequenced => {}
        Placement::Sequential { gap } => {
            if let Some((from_sequence, to_sequence)) = gap {
                lifetime.gaps.push(ProducerGap {
                    from_sequence,
                    to_sequence,
                    detected_at: journal_sequence,
                    observed_late: Vec::new(),
                });
                lifetime.next_sequence = to_sequence + 2;
            } else {
                lifetime.next_sequence += 1;
            }
        }
        Placement::Late {
            gap_index,
            producer_sequence,
        } => {
            if let Some(gap) = lifetime.gaps.get_mut(gap_index) {
                gap.observed_late.push((producer_sequence, journal_sequence));
            }
            lifetime.late_evidence.push(journal_sequence);
        }
    }
}

// ---------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------

fn journal_view(journal_id: &str, journal: &Journal) -> Value {
    let producers: Vec<Value> = journal
        .lifetimes
        .iter()
        .map(|(producer_id, lifetime)| producer_view(producer_id, lifetime))
        .collect();
    let imports: Vec<Value> = journal
        .imports
        .iter()
        .map(|record| {
            json!({
                "source_sequence": record.source_sequence,
                "source_event_hash": record.source_event_hash,
                "journal_sequence": record.journal_sequence,
            })
        })
        .collect();
    json!({
        "record_type": JOURNAL_VIEW,
        "journal_id": journal_id,
        "run_id": journal.run_id.clone().unwrap_or_default(),
        "owner_domain": journal.owner_domain.clone().unwrap_or_default(),
        "manifest_hash": journal.manifest_hash,
        "manifest": journal.manifest,
        "last_sequence": journal.events.len(),
        "head_hash": journal.head_hash,
        "events": journal.events,
        "producers": producers,
        "imports": imports,
    })
}

fn producer_view(producer_id: &str, lifetime: &ProducerLifetime) -> Value {
    let gaps: Vec<Value> = lifetime
        .gaps
        .iter()
        .map(|gap| {
            let unresolved: Vec<u64> = (gap.from_sequence..=gap.to_sequence)
                .filter(|sequence| {
                    !gap.observed_late
                        .iter()
                        .any(|(observed, _)| observed == sequence)
                })
                .collect();
            let observed_late: Vec<Value> = gap
                .observed_late
                .iter()
                .map(|(producer_sequence, journal_sequence)| {
                    json!({
                        "producer_sequence": producer_sequence,
                        "journal_sequence": journal_sequence,
                    })
                })
                .collect();
            json!({
                "from_sequence": gap.from_sequence,
                "to_sequence": gap.to_sequence,
                "detected_at": gap.detected_at,
                "observed_late": observed_late,
                "unresolved": unresolved,
            })
        })
        .collect();
    json!({
        "producer_id": producer_id,
        "next_sequence": lifetime.next_sequence,
        "closed": lifetime.closed,
        "terminal_sequence": lifetime
            .terminal_sequence
            .map(|sequence| json!(sequence))
            .unwrap_or_else(|| missing("not_observed", "producer lifetime is still open")),
        "gaps": gaps,
        "late_evidence": lifetime.late_evidence,
    })
}

fn prefix_view(journal_id: &str, journal: &Journal) -> Value {
    json!({
        "record_type": JOURNAL_PREFIX,
        "journal_id": journal_id,
        "last_sequence": journal.events.len(),
        "head_hash": journal.head_hash,
    })
}

// ---------------------------------------------------------------------------
// Envelope construction and receipt
// ---------------------------------------------------------------------------

struct EnvelopeSeed<'a> {
    journal_id: &'a str,
    run_id: &'a str,
    manifest_hash: &'a str,
    sequence: u64,
    event_id: String,
    event_kind: &'a str,
    event_schema_version: &'a str,
    role: &'a str,
    assertion_kind: &'a str,
    owner_domain: &'a str,
    producer_id: &'a str,
    producer_sequence: Value,
    provenance: &'a str,
    evidence_scope: &'a str,
    recorded_at: Value,
    occurred_at: Value,
    causal_refs: Vec<Value>,
    payload: Value,
    previous_event_hash: Value,
}

/// Build a complete `JournalEnvelope` and seal it with `event_hash` (SHA-256 of
/// the canonical envelope with only `event_hash` removed).
fn seal(seed: EnvelopeSeed<'_>) -> Result<Value, Fault> {
    let mut envelope = json!({
        "record_type": JOURNAL_EVENT,
        "schema_version": SCHEMA_VERSION,
        "run_id": seed.run_id,
        "journal_id": seed.journal_id,
        "manifest_hash": seed.manifest_hash,
        "journal_sequence": seed.sequence,
        "event_id": seed.event_id,
        "event_kind": seed.event_kind,
        "event_schema_version": seed.event_schema_version,
        "role": seed.role,
        "assertion_kind": seed.assertion_kind,
        "owner_domain": seed.owner_domain,
        "producer_id": seed.producer_id,
        "producer_sequence": seed.producer_sequence,
        "provenance": seed.provenance,
        "evidence_scope": seed.evidence_scope,
        "recorded_at": seed.recorded_at,
        "occurred_at": seed.occurred_at,
        "causal_refs": seed.causal_refs,
        "payload": seed.payload,
        "previous_event_hash": seed.previous_event_hash,
    });
    let event_hash = event_hash_of(&envelope)?;
    envelope["event_hash"] = Value::String(event_hash);
    Ok(envelope)
}

fn event_hash_of(envelope: &Value) -> Result<String, Fault> {
    let mut unsealed = envelope.clone();
    if let Some(map) = unsealed.as_object_mut() {
        map.remove("event_hash");
    }
    let record = validate(OUTPUT_SCHEMA, unsealed)?;
    Ok(digest_bytes(&canonical_bytes(&record)?))
}

fn build_receipt(
    operation: &str,
    disposition: &str,
    envelope: &Value,
    head_hash: &str,
    owner_domain: &str,
    late_evidence: bool,
    gap_detected: Option<(u64, u64)>,
) -> Value {
    let event = envelope
        .as_object()
        .cloned()
        .unwrap_or_default();
    let gap = gap_detected
        .map(|(from_sequence, to_sequence)| {
            json!({
                "from_sequence": from_sequence,
                "to_sequence": to_sequence,
            })
        })
        .unwrap_or_else(|| missing("not_observed", "no producer sequence gap was detected"));
    let field = |name: &str| event.get(name).cloned().unwrap_or(Value::Null);
    json!({
        "record_type": COMMIT_RECEIPT,
        "operation": operation,
        "durable": true,
        "disposition": disposition,
        "journal_id": field("journal_id"),
        "run_id": field("run_id"),
        "owner_domain": owner_domain,
        "manifest_hash": field("manifest_hash"),
        "journal_sequence": field("journal_sequence"),
        "previous_event_hash": field("previous_event_hash"),
        "event_hash": field("event_hash"),
        "head_hash": head_hash,
        "producer_id": field("producer_id"),
        "producer_sequence": field("producer_sequence"),
        "evidence_scope": field("evidence_scope"),
        "late_evidence": late_evidence,
        "gap_detected": gap,
        "event": envelope,
    })
}

// ---------------------------------------------------------------------------
// Authorization facts
// ---------------------------------------------------------------------------

/// Registry-derived authority facts carried by a grant.
struct AuthorityFacts {
    owner_domain: String,
    role: String,
    assertion_kind: String,
    provenance: String,
    producer_id: Option<String>,
}

impl AuthorityFacts {
    fn of(grant: &Grant) -> Result<Self, Fault> {
        let facts = Self::from_grant(grant)?;
        if !ROLES.contains(&facts.role.as_str()) {
            return Err(fault(
                "invalid_registry_authority",
                format!("registry role {:?} is not a journal envelope role", facts.role),
            ));
        }
        if !ASSERTION_KINDS.contains(&facts.assertion_kind.as_str()) {
            return Err(fault(
                "invalid_registry_authority",
                format!(
                    "registry assertion_kind {:?} is not a journal assertion kind",
                    facts.assertion_kind
                ),
            ));
        }
        if !PROVENANCES.contains(&facts.provenance.as_str()) {
            return Err(fault(
                "invalid_provenance",
                format!("registry provenance {:?} is not a kernel provenance class", facts.provenance),
            ));
        }
        if facts.owner_domain.is_empty() {
            return Err(fault(
                "grant_without_owner",
                "grant carries no owner domain to write under".to_string(),
            ));
        }
        Ok(facts)
    }

    fn from_grant(grant: &Grant) -> Result<Self, Fault> {
        let map = record_value(grant_record(grant))
            .as_object()
            .ok_or_else(|| fault("invalid_grant", "grant must be an object".to_string()))?;
        Ok(Self {
            owner_domain: required_str(map, "owner_domain", "grant_without_owner", "grant")?
                .to_string(),
            role: required_str(map, "role", "invalid_grant", "grant")?.to_string(),
            assertion_kind: required_str(map, "assertion_kind", "invalid_grant", "grant")?
                .to_string(),
            provenance: required_str(map, "provenance", "invalid_grant", "grant")?.to_string(),
            producer_id: established(map, "producer_id")
                .and_then(Value::as_str)
                .map(str::to_string),
        })
    }
}

/// Evidence scope is assigned at ingestion from the authenticated provenance.
fn evidence_scope_for(provenance: &str) -> Result<&'static str, Fault> {
    match provenance {
        "server" | "connector" | "subject" | "manual_observer" => Ok("current_run"),
        "fixture_client" => Ok("synthetic"),
        "importer" => Ok("historical_unscored"),
        other => Err(fault(
            "invalid_provenance",
            format!("provenance {other:?} has no evidence scope assignment"),
        )),
    }
}

fn principal_of(
    transaction: &Map<String, Value>,
    manifest_digest: &str,
) -> Result<CheckedRecord, Fault> {
    let principal = transaction.get("principal").ok_or_else(|| {
        fault(
            "missing_principal",
            "transaction requires the authenticated producer principal".to_string(),
        )
    })?;
    let map = principal.as_object().ok_or_else(|| {
        fault("invalid_principal", "principal must be an object".to_string())
    })?;
    for key in map.keys() {
        if key != "producer_id" && key != "manifest_digest" {
            return Err(fault(
                "spoofed_authority_field",
                format!(
                    "principal supplies only its authenticated producer_id and manifest_digest; {key:?} is not accepted"
                ),
            ));
        }
    }
    if map.get("producer_id").is_none() {
        return Err(fault(
            "invalid_principal",
            "principal requires an authenticated producer_id".to_string(),
        ));
    }
    let binding = required_str(map, "manifest_digest", "missing_manifest_binding", "principal")?;
    if binding != manifest_digest {
        return Err(fault(
            "manifest_mismatch",
            "principal is bound to a different manifest than this store admits".to_string(),
        ));
    }
    validate(OUTPUT_SCHEMA, principal.clone())
}

/// Owner domain carried by any grant (producer or connector grant).
fn grant_owner(grant: &Grant) -> Result<String, Fault> {
    let map = record_value(grant_record(grant))
        .as_object()
        .ok_or_else(|| fault("invalid_grant", "grant must be an object".to_string()))?;
    Ok(required_str(map, "owner_domain", "grant_without_owner", "grant")?.to_string())
}

fn principal_producer_id(principal: &CheckedRecord) -> Result<&str, Fault> {
    let map = record_value(principal)
        .as_object()
        .ok_or_else(|| fault("invalid_principal", "principal must be an object".to_string()))?;
    required_str(map, "producer_id", "invalid_principal", "principal")
}

/// Submission view handed to [`crawler_authority::authorize_producer`].
///
/// Contract 00 §13.1 makes `producer_sequence` the authenticated producer
/// lifetime sequence, validated for gaps/conflicts — that validation belongs to
/// this ingestion store. The authority dependency treats it as a
/// server-assigned field and refuses any submission carrying it, so the
/// sequence is withheld from that call while every other submission field
/// (event kind registry, event schema version, occurrence, payload scope
/// claims) still passes the authority's spoof rejection and registry checks.
fn authorization_view(submission: &CheckedRecord) -> Result<CheckedRecord, Fault> {
    let mut map = record_value(submission)
        .as_object()
        .cloned()
        .ok_or_else(|| {
            fault(
                "invalid_submission",
                "submission must be an EventSubmission object".to_string(),
            )
        })?;
    map.remove("producer_sequence");
    validate(OUTPUT_SCHEMA, Value::Object(map))
}

/// The passed writer grant must be issued for this exact producer and manifest,
/// and must agree with the registry-derived authority this store will stamp.
fn cross_check_grant(
    passed: &Grant,
    derived: &Grant,
    producer_id: &str,
    manifest_digest: &str,
) -> Result<(), Fault> {
    let passed_map = record_value(grant_record(passed))
        .as_object()
        .ok_or_else(|| fault("invalid_grant", "grant must be an object".to_string()))?;
    let derived_map = record_value(grant_record(derived))
        .as_object()
        .ok_or_else(|| fault("invalid_grant", "grant must be an object".to_string()))?;
    let passed_producer = required_str(passed_map, "producer_id", "invalid_grant", "grant")?;
    if passed_producer != producer_id {
        return Err(fault(
            "grant_principal_mismatch",
            format!("grant is issued for producer {passed_producer:?}, not {producer_id:?}"),
        ));
    }
    let passed_manifest = required_str(passed_map, "manifest_digest", "invalid_grant", "grant")?;
    if passed_manifest != manifest_digest {
        return Err(fault(
            "grant_manifest_mismatch",
            "grant is bound to a different manifest than this store admits".to_string(),
        ));
    }
    for field in ["owner_domain", "role", "assertion_kind", "provenance"] {
        let passed_value = required_str(passed_map, field, "invalid_grant", "grant")?;
        let derived_value = required_str(derived_map, field, "invalid_grant", "grant")?;
        if passed_value != derived_value {
            return Err(fault(
                "grant_authority_mismatch",
                format!(
                    "grant {field} {passed_value:?} disagrees with registry authority {derived_value:?}"
                ),
            ));
        }
    }
    Ok(())
}

fn reject_authority_fields(map: &Map<String, Value>, fields: &[&str]) -> Result<(), Fault> {
    for field in fields {
        if established(map, field).is_some() {
            return Err(fault(
                "spoofed_authority_field",
                format!(
                    "caller-supplied authority field {field:?} is rejected; the ingestion authority assigns it"
                ),
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Submission parsing
// ---------------------------------------------------------------------------

enum SubmittedSequence {
    Sequenced(u64),
    Unsequenced,
}

fn submitted_sequence(submission: &Map<String, Value>) -> Result<SubmittedSequence, Fault> {
    match submission.get("producer_sequence") {
        Some(value) if is_missing(value) => Ok(SubmittedSequence::Unsequenced),
        Some(value) => match value.as_u64() {
            Some(sequence) if sequence >= 1 => Ok(SubmittedSequence::Sequenced(sequence)),
            _ => Err(fault(
                "invalid_producer_sequence",
                "producer_sequence must be a positive integer or a Missing envelope".to_string(),
            )),
        },
        None => Err(fault(
            "missing_producer_sequence",
            "submission requires producer_sequence (Missing when the producer is unsequenced)"
                .to_string(),
        )),
    }
}

fn check_payload(submission: &Map<String, Value>) -> Result<&Map<String, Value>, Fault> {
    let payload = submission
        .get("payload")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            fault(
                "incomplete_payload",
                "submission requires an EvidencePayload object".to_string(),
            )
        })?;
    for field in ["data", "measurements", "evidence_refs", "artifact_refs"] {
        if payload.get(field).is_none() {
            return Err(fault(
                "incomplete_payload",
                format!("EvidencePayload requires {field:?}; missingness is typed, never omitted"),
            ));
        }
    }
    for field in ["measurements", "evidence_refs", "artifact_refs"] {
        if !payload[field].is_array() {
            return Err(fault(
                "incomplete_payload",
                format!("EvidencePayload {field:?} must be an established array"),
            ));
        }
    }
    Ok(payload)
}

fn artifact_refs(payload: &Map<String, Value>) -> impl Iterator<Item = &Value> {
    payload
        .get("artifact_refs")
        .and_then(Value::as_array)
        .map(|refs| refs.iter())
        .into_iter()
        .flatten()
}

fn causal_refs_of(transaction: &Map<String, Value>) -> Result<Vec<Value>, Fault> {
    match transaction.get("causal_refs") {
        Some(Value::Array(refs)) => Ok(refs.clone()),
        Some(value) if is_missing(value) => Ok(Vec::new()),
        Some(_) => Err(fault(
            "invalid_causal_refs",
            "causal_refs must be an array of EvidenceRefs".to_string(),
        )),
        None => Ok(Vec::new()),
    }
}

// ---------------------------------------------------------------------------
// Evidence references
// ---------------------------------------------------------------------------

fn check_evidence_refs(refs: &[Value]) -> Result<(), Fault> {
    for reference in refs {
        let map = reference.as_object().ok_or_else(|| {
            fault("invalid_evidence_ref", "EvidenceRef must be an object".to_string())
        })?;
        required_str(map, "journal_id", "invalid_evidence_ref", "EvidenceRef")?;
        required_u64(map, "sequence", "invalid_evidence_ref", "EvidenceRef")?;
        required_str(map, "event_id", "invalid_evidence_ref", "EvidenceRef")?;
        let digest = required_str(map, "event_hash", "invalid_evidence_ref", "EvidenceRef")?;
        if !is_digest_text(digest) {
            return Err(fault(
                "invalid_evidence_ref",
                "EvidenceRef event_hash must be 64 lowercase hex characters".to_string(),
            ));
        }
        let pointer = established_str(map, "pointer", "invalid_evidence_ref", "EvidenceRef")?;
        if !is_json_pointer(pointer) {
            return Err(fault(
                "invalid_evidence_ref",
                format!("EvidenceRef pointer {pointer:?} is not a JSON Pointer"),
            ));
        }
    }
    Ok(())
}

/// Every cited reference must agree with an earlier registered event in this
/// journal prefix: journal, sequence, event id, and hash all must match.
fn resolve_evidence_refs(
    journal: &Journal,
    refs: &[Value],
    new_sequence: u64,
) -> Result<(), Fault> {
    for reference in refs {
        let map = reference
            .as_object()
            .ok_or_else(|| fault("invalid_evidence_ref", "EvidenceRef must be an object".to_string()))?;
        let journal_id = required_str(map, "journal_id", "invalid_evidence_ref", "EvidenceRef")?;
        if journal_id != journal.journal_id {
            return Err(fault(
                "foreign_evidence_ref",
                format!(
                    "EvidenceRef must cite this journal {:?}, not {journal_id:?}",
                    journal.journal_id
                ),
            ));
        }
        let sequence = required_u64(map, "sequence", "invalid_evidence_ref", "EvidenceRef")?;
        if sequence >= new_sequence || sequence == 0 {
            return Err(fault(
                "unresolved_evidence_ref",
                format!(
                    "EvidenceRef sequence {sequence} is not an earlier event in this prefix (head {})",
                    new_sequence - 1
                ),
            ));
        }
        let event = journal.events.get(sequence as usize - 1).ok_or_else(|| {
            fault(
                "unresolved_evidence_ref",
                format!("no event is registered at sequence {sequence}"),
            )
        })?;
        let event_id = required_str(map, "event_id", "invalid_evidence_ref", "EvidenceRef")?;
        let event_hash = required_str(map, "event_hash", "invalid_evidence_ref", "EvidenceRef")?;
        if event["event_id"] != Value::String(event_id.to_string())
            || event["event_hash"] != Value::String(event_hash.to_string())
        {
            return Err(fault(
                "unresolved_evidence_ref",
                format!(
                    "EvidenceRef at sequence {sequence} disagrees with the registered event id/hash"
                ),
            ));
        }
    }
    Ok(())
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
// Import source verification
// ---------------------------------------------------------------------------

struct SourceEvent {
    journal_id: String,
    run_id: String,
    sequence: u64,
    event_id: String,
    event_hash: String,
    manifest_hash: String,
    owner_domain: String,
    producer_id: String,
    provenance: String,
    assertion_kind: String,
    evidence_scope: String,
    occurred_at: Value,
    record: Value,
}

fn parse_source_event(event: &CheckedRecord) -> Result<SourceEvent, Fault> {
    let map = record_value(event)
        .as_object()
        .ok_or_else(|| fault("not_journal_event", "imported evidence must be an object".to_string()))?;
    match map.get("record_type").and_then(Value::as_str) {
        Some(JOURNAL_EVENT) => {}
        _ => {
            return Err(fault(
                "not_journal_event",
                "only a complete journal_event envelope can be imported; submissions are not evidence"
                    .to_string(),
            ))
        }
    }
    let journal_id = required_str(map, "journal_id", "invalid_import", "journal event")?.to_string();
    let run_id = required_str(map, "run_id", "invalid_import", "journal event")?.to_string();
    required_str(map, "schema_version", "invalid_import", "journal event")?;
    let manifest_hash = required_str(map, "manifest_hash", "invalid_import", "journal event")?;
    if !is_digest_text(manifest_hash) {
        return Err(fault(
            "invalid_import",
            "imported manifest_hash must be 64 lowercase hex characters".to_string(),
        ));
    }
    let sequence = required_u64(map, "journal_sequence", "invalid_import", "journal event")?;
    let event_id = required_str(map, "event_id", "invalid_import", "journal event")?.to_string();
    required_str(map, "event_kind", "invalid_import", "journal event")?;
    required_str(map, "event_schema_version", "invalid_import", "journal event")?;
    let role = required_str(map, "role", "invalid_import", "journal event")?;
    if !ROLES.contains(&role) {
        return Err(fault(
            "invalid_import",
            format!("imported role {role:?} is not a journal envelope role"),
        ));
    }
    let assertion_kind = required_str(map, "assertion_kind", "invalid_import", "journal event")?;
    if !ASSERTION_KINDS.contains(&assertion_kind) {
        return Err(fault(
            "invalid_import",
            format!("imported assertion_kind {assertion_kind:?} is not a journal assertion kind"),
        ));
    }
    let owner_domain = required_str(map, "owner_domain", "invalid_import", "journal event")?.to_string();
    let producer_id = required_str(map, "producer_id", "invalid_import", "journal event")?.to_string();
    match map.get("producer_sequence") {
        Some(value) if is_missing(value) => {}
        Some(value) if value.as_u64().is_some_and(|sequence| sequence >= 1) => {}
        _ => {
            return Err(fault(
                "invalid_import",
                "imported producer_sequence must be a positive integer or a Missing envelope"
                    .to_string(),
            ))
        }
    }
    let provenance = required_str(map, "provenance", "invalid_import", "journal event")?;
    if !PROVENANCES.contains(&provenance) {
        return Err(fault(
            "invalid_import",
            format!("imported provenance {provenance:?} is not a kernel provenance class"),
        ));
    }
    let evidence_scope = required_str(map, "evidence_scope", "invalid_import", "journal event")?;
    if !EVIDENCE_SCOPES.contains(&evidence_scope) {
        return Err(fault(
            "invalid_import",
            format!("imported evidence_scope {evidence_scope:?} is not a kernel evidence scope"),
        ));
    }
    let recorded_at = map.get("recorded_at").and_then(Value::as_object).ok_or_else(|| {
        fault(
            "invalid_import",
            "imported recorded_at must be a receipt TimePoint".to_string(),
        )
    })?;
    for field in ["clock_id", "boot_id", "origin", "monotonic_offset_ms"] {
        if recorded_at.get(field).is_none() {
            return Err(fault(
                "invalid_import",
                format!("imported recorded_at TimePoint is missing {field:?}"),
            ));
        }
    }
    let occurred_at = map.get("occurred_at").cloned().ok_or_else(|| {
        fault(
            "invalid_import",
            "imported occurred_at must be a TimePoint or Missing envelope".to_string(),
        )
    })?;
    if !occurred_at.is_object() {
        return Err(fault(
            "invalid_import",
            "imported occurred_at must be a TimePoint or Missing envelope".to_string(),
        ));
    }
    match map.get("causal_refs") {
        Some(Value::Array(refs)) => check_evidence_refs(refs)?,
        _ => {
            return Err(fault(
                "invalid_import",
                "imported causal_refs must be an array of EvidenceRefs".to_string(),
            ))
        }
    }
    let payload = map
        .get("payload")
        .and_then(Value::as_object)
        .ok_or_else(|| fault("invalid_import", "imported payload must be an object".to_string()))?;
    for field in ["data", "measurements", "evidence_refs", "artifact_refs"] {
        if payload.get(field).is_none() {
            return Err(fault(
                "invalid_import",
                format!("imported EvidencePayload requires {field:?}"),
            ));
        }
    }
    match map.get("previous_event_hash") {
        Some(Value::String(digest)) if is_digest_text(digest) && sequence > 1 => {}
        Some(value) if sequence == 1 && is_missing(value) => {}
        _ => {
            return Err(fault(
                "invalid_import",
                "imported previous_event_hash must be Missing(not_applicable) at sequence 1 and a kernel digest afterwards"
                    .to_string(),
            ))
        }
    }
    let event_hash = required_str(map, "event_hash", "invalid_import", "journal event")?;
    if !is_digest_text(event_hash) {
        return Err(fault(
            "invalid_import",
            "imported event_hash must be 64 lowercase hex characters".to_string(),
        ));
    }
    if event_hash_of(&Value::Object(map.clone()))? != event_hash {
        return Err(fault(
            "import_digest_mismatch",
            "imported envelope event_hash does not match its canonical bytes; fabricated or edited evidence is refused"
                .to_string(),
        ));
    }
    Ok(SourceEvent {
        journal_id,
        run_id,
        sequence,
        event_id,
        event_hash: event_hash.to_string(),
        manifest_hash: manifest_hash.to_string(),
        owner_domain,
        producer_id,
        provenance: provenance.to_string(),
        assertion_kind: assertion_kind.to_string(),
        evidence_scope: evidence_scope.to_string(),
        occurred_at,
        record: record_value(event).clone(),
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn lock_journal(journal: &Arc<Mutex<Journal>>) -> Result<std::sync::MutexGuard<'_, Journal>, Fault> {
    journal.lock().map_err(|_| {
        fault(
            "internal_error",
            "journal lock poisoned; owner-local state is unavailable".to_string(),
        )
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

fn established_str<'a>(
    map: &'a Map<String, Value>,
    field: &str,
    code: &str,
    what: &str,
) -> Result<&'a str, Fault> {
    match established(map, field) {
        Some(Value::String(text)) => Ok(text.as_str()),
        _ => Err(fault(
            code,
            format!("{what} requires an established string {field:?}"),
        )),
    }
}

fn required_u64(
    map: &Map<String, Value>,
    field: &str,
    code: &str,
    what: &str,
) -> Result<u64, Fault> {
    match established(map, field).and_then(Value::as_u64) {
        Some(value) => Ok(value),
        None => Err(fault(
            code,
            format!("{what} requires an established positive integer {field:?}"),
        )),
    }
}

fn is_digest_text(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn digest_prefix(digest: &str) -> &str {
    &digest[..16.min(digest.len())]
}

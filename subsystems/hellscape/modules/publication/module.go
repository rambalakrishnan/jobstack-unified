// Package publication implements tier-6 Hellscape asynchronous publication.
//
// It enforces seam-mappings/hellscape-seam-mapping.md sections 5.6 (OWD
// registrations and revisions), 5.7 (asynchronous publication), 5.8
// (LogicalRow and seals), 11.5 (archive representation) and 16.3 (storage and
// publication corpus) plus invariants OWD-OWNER, OWD-REVISION, OWD-PUBLISH,
// OWD-VIEW, OWD-SEAL, OWD-ARCHIVE, OWD-ATTEMPT, LIFE-PUBLICATION and
// LIFE-EVIDENCE:
//
//   - Owner durability acknowledgement and installation into a read view are
//     different events. The source prefix is imported (and therefore durable)
//     before any large presentation document is transferred, validated, and
//     durably installed. Only after all of those steps may the view's domain
//     pointer advance atomically and a receipt be issued.
//   - A domain revision is one complete immutable document. The key
//     (entity, domain, revision) names exactly one content digest: identical
//     retries return the stored receipt, while different bytes under the same
//     key raise an integrity conflict. A reordered (older) delivery never rolls
//     the pointer backward; a skipped revision requires verified lineage.
//   - A read view holds complete domain slots. A zero slot is visible
//     missingness, never a replacement for lost published bytes.
//   - A seal pins all domain revisions selected in one named view with an
//     exact version vector. The seal-selection event is journaled before the
//     resulting LogicalRow registration, and the row's input prefix ends at
//     that selection event, never at its own later registration.
//   - Archive expansion reproduces the exact complete LogicalRow from
//     immutable local extents (registration artifact plus complete document
//     artifacts). It never queries a mutable peer or a current-view index.
//   - Publication delay is retained as a measurement with typed provenance. It
//     is unavailable (with a reasoned Missing value) when the source and
//     publication clocks are not the same clock lifetime; arbitrary UTC
//     annotations are never subtracted.
//
// The durable truth of a published view is the owner-local publication journal
// plus the retained, content-addressed artifacts it names. The per-store read
// index below is the observable view cache used by SealRow; it is only
// advanced after the corresponding journal commit is durable. The exported
// surface deliberately adds no separate rehydration entry point: a view owner
// recovers its index by replaying that retained publication journal.
package publication

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"

	evidence_codec "evidence_codec"
	evidence_import "evidence_import"
	journal_rules "journal_rules"
	lifecycle_rules "lifecycle_rules"
	owner_store "owner_store"
)

// ---------------------------------------------------------------------------
// Evidence-kernel aliases: shared wire shapes so CONSUMES calls need no
// translation.
// ---------------------------------------------------------------------------

type (
	// OwnerStore is one owner-local durable boundary.
	OwnerStore = owner_store.OwnerStore
	// Manifest is the admitted journal manifest.
	Manifest = journal_rules.Manifest
	// JournalEnvelope is the complete stored journal event envelope.
	JournalEnvelope = journal_rules.JournalEnvelope
	// JournalPrefix is an immutable journal prefix.
	JournalPrefix = journal_rules.JournalPrefix
	// EvidenceRef cites one retained journal event coordinate plus a pointer.
	EvidenceRef = journal_rules.EvidenceRef
	// ArtifactReference is an immutable byte identity plus resolver metadata.
	ArtifactReference = journal_rules.ArtifactReference
	// TimePoint is a coordinate in a registered monotonic clock.
	TimePoint = journal_rules.TimePoint
	// MissingEnvelope is the typed EK Missing value.
	MissingEnvelope = journal_rules.MissingEnvelope
	// Measurement is the EK duration measurement record.
	Measurement = journal_rules.Measurement
	// EventSubmission is the ingress shape for owner-local commits.
	EventSubmission = owner_store.EventSubmission
	// VersionPin pins an immutable import-policy artifact.
	VersionPin = evidence_import.VersionPin
)

// Compile-time CONSUMES linkage: fail compilation if a declared upstream
// signature disappears.
var (
	_ = owner_store.CommitOwner
	_ = owner_store.InstallArtifact
	_ = owner_store.ReadArtifact
	_ = owner_store.RetainRoot
	_ = evidence_import.ImportSourcePrefix
	_ = journal_rules.ValidateJournal
	_ = evidence_codec.HashBytes
	// Axis revision documents arrive as complete, already-validated owner
	// publications. The publication gate checks identity, lineage, artifact
	// and checksum evidence; commission-level transition validation remains
	// lifecycle_rules' job and is never re-run against a partial history.
	_ = lifecycle_rules.ValidateAxisTransition
)

// ---------------------------------------------------------------------------
// Public wire types (shapes follow contracts/04-owner-separated-write-domains).
// ---------------------------------------------------------------------------

// EntityRegistration is the immutable, authenticated registration of one
// Hellscape entity: a session, an application attempt, or a job. Identity and
// owner bindings ride as JSON-compatible objects so registrations produced
// against the OWD contract validate structurally.
type EntityRegistration struct {
	RecordType     string         `json:"record_type"`
	SchemaVersion  string         `json:"schema_version"`
	RegistrationID string         `json:"registration_id"`
	Entity         map[string]any `json:"entity"`
	Identity       map[string]any `json:"identity"`
	Owners         map[string]any `json:"owners"`
	EvidencePrefix JournalPrefix  `json:"evidence_prefix"`
	EvidenceRefs   []EvidenceRef  `json:"evidence_refs"`
}

// DomainPin identifies one revision of one domain by revision and record
// digest. Revision zero pins Missing(not_applicable) instead of a digest.
type DomainPin struct {
	Revision     int64 `json:"revision"`
	RecordDigest any   `json:"record_digest"`
}

// PublicationDelay is the retained publication-delay measurement evidence:
// one EK Measurement plus its support references.
type PublicationDelay struct {
	Measurement  Measurement   `json:"measurement"`
	EvidenceRefs []EvidenceRef `json:"evidence_refs"`
}

// PublicationReceipt is issued only after the complete immutable document has
// been durably installed and the view pointer has advanced. It records the
// exact identities that let a reader verify that publication without trusting
// the read time.
type PublicationReceipt struct {
	RecordType         string            `json:"record_type"`
	SchemaVersion      string            `json:"schema_version"`
	ReceiptID          string            `json:"receipt_id"`
	Entity             map[string]any    `json:"entity"`
	RegistrationDigest string            `json:"registration_digest"`
	ViewID             string            `json:"view_id"`
	PublisherID        string            `json:"publisher_id"`
	Domain             string            `json:"domain"`
	Revision           int64             `json:"revision"`
	Document           ArtifactReference `json:"document"`
	Supersedes         DomainPin         `json:"supersedes"`
	ObservedOwnerHead  any               `json:"observed_owner_head"`
	SourcePrefix       JournalPrefix     `json:"source_prefix"`
	InstalledAt        TimePoint         `json:"installed_at"`
	PublicationRef     EvidenceRef       `json:"publication_ref"`
	PublicationDelay   PublicationDelay  `json:"publication_delay"`
}

// DomainSlot is one LogicalRow domain slot. A published slot carries its exact
// revision, immutable document artifact, publication reference, and complete
// snapshot; an unpublished slot carries revision zero and a typed Missing
// value instead.
type DomainSlot struct {
	Revision       int64              `json:"revision"`
	Document       *ArtifactReference `json:"document,omitempty"`
	PublicationRef *EvidenceRef       `json:"publication_ref,omitempty"`
	Snapshot       json.RawMessage    `json:"snapshot,omitempty"`
	Value          any                `json:"value,omitempty"`
}

// SealPoint pins the state named by one seal: the exact version vector
// selected in the named view, the selection time, and the input prefix that
// ends at the journaled seal-selection event.
type SealPoint struct {
	SealID       string           `json:"seal_id"`
	Name         string           `json:"name"`
	ViewID       string           `json:"view_id"`
	Versions     map[string]int64 `json:"versions"`
	SealedAt     TimePoint        `json:"sealed_at"`
	InputPrefix  JournalPrefix    `json:"input_prefix"`
	EvidenceRefs []EvidenceRef    `json:"evidence_refs"`
}

// LogicalRow is the complete derived read value for one entity: every declared
// domain slot plus one exact seal. It is never accepted as a write command.
type LogicalRow struct {
	RecordType         string                `json:"record_type"`
	SchemaVersion      string                `json:"schema_version"`
	Entity             map[string]any        `json:"entity"`
	RegistrationDigest string                `json:"registration_digest"`
	Registration       EntityRegistration    `json:"registration"`
	Domains            map[string]DomainSlot `json:"domains"`
	SealPoint          SealPoint             `json:"seal_point"`
}

// ArchiveDomainSlot is one archive storage-manifest slot. Published entries
// name immutable document extents; unpublished entries carry revision zero and
// a typed Missing value.
type ArchiveDomainSlot struct {
	Revision       int64              `json:"revision"`
	Document       *ArtifactReference `json:"document,omitempty"`
	PublicationRef *EvidenceRef       `json:"publication_ref,omitempty"`
	Value          any                `json:"value,omitempty"`
}

// ArchiveStorageManifest is the physical archive root representation: every
// component is an immutable local extent plus the exact seal vector.
type ArchiveStorageManifest struct {
	Encoding      string                       `json:"encoding"`
	SchemaVersion string                       `json:"schema_version"`
	Entity        map[string]any               `json:"entity"`
	Registration  ArtifactReference            `json:"registration"`
	Domains       map[string]ArchiveDomainSlot `json:"domains"`
	SealPoint     SealPoint                    `json:"seal_point"`
}

// ArchiveRecord is the complete expanded logical archive. Root hashes the
// canonical storage-manifest bytes, never this wrapper.
type ArchiveRecord struct {
	RecordType      string                 `json:"record_type"`
	SchemaVersion   string                 `json:"schema_version"`
	Root            ArtifactReference      `json:"root"`
	StorageManifest ArchiveStorageManifest `json:"storage_manifest"`
	PayloadJSON     LogicalRow             `json:"payload_json"`
}

// ---------------------------------------------------------------------------
// Module constants and sentinel errors.
// ---------------------------------------------------------------------------

const (
	// schemaVersion is the OWD contract version carried by registrations,
	// rows, publication documents, receipts, and archives.
	schemaVersion = "owner-separated-write-domains/0.1.0"
	// attemptSchemaVersion is the lifecycle contract version carried by
	// attempt axis revisions.
	attemptSchemaVersion = "application-attempt-lifecycle/0.1.0"

	// publicationJournalID is the deterministic owner-local publication
	// journal. Every publication, seal selection, and row registration for
	// this owner store is appended to it so all cited coordinates share one
	// journal prefix.
	publicationJournalID = "publication-journal"
	// publicationRunID is the deterministic run pin of that journal.
	publicationRunID = "publication-run"

	receiptRecordType    = "domain_publication_receipt"
	logicalRowRecordType = "logical_row"
	archiveRecordType    = "logical_row_archive"
	archiveEncoding      = "owner-domain-extents/1"

	eventDomainPublished     = "domain_published"
	eventPublicationRejected = "publication_rejected"
	eventSealSelected        = "seal_selected"
	eventRowRegistered       = "logical_row_registered"

	eventSchemaVersion = "0.1.0"

	mediaTypeJSON    = "application/json"
	accessPublic     = "public"
	accessRestricted = "restricted"

	// receiptMediaType documents that receipts are canonical JSON extents.
	publicationClockID = "publication-clock"
	publicationBootID  = "publication-boot"

	missingReasonNotObserved   = "not_observed"
	missingReasonNotApplicable = "not_applicable"
)

// Sentinel errors let callers distinguish invalid input, cross-owner attempts,
// integrity conflicts, stale deliveries, unverified lineage, incomplete
// transfers, and lost published bytes without parsing messages.
var (
	ErrInvalid            = errors.New("publication: invalid input")
	ErrUnauthorized       = errors.New("publication: unauthorized")
	ErrIntegrityConflict  = errors.New("publication: integrity conflict")
	ErrUnverifiedDocument = errors.New("publication: document is not evidenced by its source prefix")
	ErrStalePublication   = errors.New("publication: stale or reordered publication")
	ErrLineageGap         = errors.New("publication: unverified publication lineage")
	ErrIncompleteTransfer = errors.New("publication: publication bytes are incomplete")
	ErrLostPublishedBytes = errors.New("publication: published bytes are known lost")
	ErrUnsupportedEntity  = errors.New("publication: unsupported entity type")
)

// ---------------------------------------------------------------------------
// Read-view index.
// ---------------------------------------------------------------------------

// slotRecord is one published domain slot in a read view. Only its immutable
// identities are cached; the complete snapshot is always re-read from the
// content-addressed extent so a lost byte is reported as loss instead of being
// silently served from memory.
type slotRecord struct {
	Revision       int64
	Document       ArtifactReference
	PublicationRef EvidenceRef
}

// storeBook is the observable read-view index for one owner store. It is
// advanced only after the durable publication commit returns.
type storeBook struct {
	views       map[string]map[string]map[string]slotRecord
	receipts    map[string]PublicationReceipt
	receiptRefs map[string]ArtifactReference
}

var (
	bookMu sync.Mutex
	books  = map[*owner_store.OwnerStore]*storeBook{}
)

func newStoreBook() *storeBook {
	return &storeBook{
		views:       map[string]map[string]map[string]slotRecord{},
		receipts:    map[string]PublicationReceipt{},
		receiptRefs: map[string]ArtifactReference{},
	}
}

// bookForLocked returns the store's read index. The caller must hold bookMu.
func bookForLocked(store *owner_store.OwnerStore) *storeBook {
	book := books[store]
	if book == nil {
		book = newStoreBook()
		books[store] = book
	}
	return book
}

func (b *storeBook) slot(viewID, entityKey, domain string) slotRecord {
	byEntity := b.views[viewID]
	if byEntity == nil {
		return slotRecord{}
	}
	byDomain := byEntity[entityKey]
	if byDomain == nil {
		return slotRecord{}
	}
	return byDomain[domain]
}

func (b *storeBook) setSlot(viewID, entityKey, domain string, slot slotRecord) {
	byEntity := b.views[viewID]
	if byEntity == nil {
		byEntity = map[string]map[string]slotRecord{}
		b.views[viewID] = byEntity
	}
	byDomain := byEntity[entityKey]
	if byDomain == nil {
		byDomain = map[string]slotRecord{}
		byEntity[entityKey] = byDomain
	}
	byDomain[domain] = slot
}

// slotsFor snapshots every declared domain slot for one entity in a view. The
// copy is taken under bookMu, so a concurrent publication can never produce a
// mixed vector.
func (b *storeBook) slotsFor(viewID, entityKey string, domains []string) map[string]slotRecord {
	out := make(map[string]slotRecord, len(domains))
	for _, domain := range domains {
		out[domain] = b.slot(viewID, entityKey, domain)
	}
	return out
}

func receiptKey(viewID, entityKey, domain string, revision int64) string {
	return viewID + "\x00" + entityKey + "\x00" + domain + "\x00" + strconv.FormatInt(revision, 10)
}

// stageObserver is the optional test seam that records the ordering of the
// publication pipeline. It is never part of the public contract and is only
// read when a conformance test installs it.
var stageObserver func(stage string, detail int)

// transferGate is the optional test seam that models a crash after the source
// commitment and before the presentation artifact installation. Production
// builds leave it nil.
var transferGate func() error

func observe(stage string, detail int) {
	if stageObserver != nil {
		stageObserver(stage, detail)
	}
}

// ---------------------------------------------------------------------------
// InstallPublication.
// ---------------------------------------------------------------------------

// InstallPublication installs one complete immutable domain document into the
// named read view.
//
// Order is the seam 5.7 publication order:
//
//  1. verify the source journal and import its complete prefix (the source
//     acknowledgement is durable before any presentation transfer),
//  2. validate the document as the exact OwnedRevision for this
//     entity/domain/revision/registration/writer and prove its digest is
//     pinned by an event after the document's own input prefix,
//  3. stream and durably install the exact document bytes,
//  4. atomically advance the view's domain pointer in the owner-local
//     publication journal,
//  5. issue and retain the publication receipt.
//
// A failure before step 4 leaves the previous complete view visible. A stale,
// reordered, or conflicting delivery is journaled as a rejection incident and
// never advances the pointer.
func InstallPublication(ctx context.Context, store *OwnerStore, registration EntityRegistration, document []byte, sourceManifest Manifest, source []JournalEnvelope, viewID string) (PublicationReceipt, error) {
	empty := PublicationReceipt{}
	if store == nil {
		return empty, fmt.Errorf("%w: store is required", ErrInvalid)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if strings.TrimSpace(viewID) == "" {
		return empty, fmt.Errorf("%w: view_id is required", ErrInvalid)
	}
	reg, err := validateRegistration(registration)
	if err != nil {
		return empty, err
	}
	doc, err := decodeDocument(document, reg)
	if err != nil {
		return empty, err
	}
	srcPrefix, err := verifySourceJournal(sourceManifest, source)
	if err != nil {
		return empty, err
	}
	if doc.evidencePrefix.JournalID != srcPrefix.JournalID {
		return empty, fmt.Errorf("%w: document evidence prefix names journal %q, source prefix is %q",
			ErrInvalid, doc.evidencePrefix.JournalID, srcPrefix.JournalID)
	}
	if err := verifyDocumentSource(doc, source, srcPrefix); err != nil {
		return empty, err
	}

	// The import policy is an immutable local artifact; installing it also
	// reveals the store's authenticated publisher domain. The document's own
	// writer identity is the registered per-domain owner, checked above: a
	// read view aggregates several owner domains, so the view publisher and
	// the domain writer are deliberately different identities.
	policy, policyRef, err := ensureImportPolicy(ctx, store, sourceManifest)
	if err != nil {
		return empty, err
	}
	publisherID := strings.TrimSpace(policyRef.OwnerDomain)
	if publisherID == "" {
		return empty, fmt.Errorf("%w: installed policy names no publisher domain", ErrUnauthorized)
	}

	// Step 1: durable source acknowledgement, independent of document size.
	observe("source_import_started", len(source))
	if _, err := evidence_import.ImportSourcePrefix(ctx, store, sourceManifest, srcPrefix, source, policy); err != nil {
		return empty, fmt.Errorf("publication: import source prefix: %w", err)
	}
	observe("source_imported", len(source))
	if transferGate != nil {
		if err := transferGate(); err != nil {
			return empty, fmt.Errorf("%w: aborted after the durable source acknowledgement: %v",
				ErrIncompleteTransfer, err)
		}
	}

	if err := ensurePublicationJournal(ctx, store, publisherID); err != nil {
		return empty, err
	}
	registrationRef, err := installCanonicalJSON(ctx, store, registration)
	if err != nil {
		return empty, fmt.Errorf("publication: install registration extent: %w", err)
	}
	if registrationRef.Digest != reg.Digest {
		return empty, fmt.Errorf("%w: registration artifact digest %q does not match canonical registration %q",
			ErrIntegrityConflict, registrationRef.Digest, reg.Digest)
	}

	// Step 3: transfer and durably install the complete immutable document.
	observe("document_transfer", len(document))
	documentRef, err := owner_store.InstallArtifact(ctx, store, bytes.NewReader(document), mediaTypeJSON, accessPublic)
	if err != nil {
		return empty, fmt.Errorf("%w: install document extent: %v", ErrIncompleteTransfer, err)
	}
	if int64(len(document)) != documentRef.SizeBytes ||
		string(evidence_codec.HashBytes(document)) != documentRef.Digest {
		return empty, fmt.Errorf("%w: installed document bytes do not match the complete supplied document",
			ErrIncompleteTransfer)
	}
	observe("document_installed", len(document))

	bookMu.Lock()
	book := bookForLocked(store)
	current := book.slot(viewID, reg.EntityKey, doc.domain)
	key := receiptKey(viewID, reg.EntityKey, doc.domain, doc.revision)
	if existing, ok := book.receipts[key]; ok {
		if existing.Document.Digest != doc.digest {
			conflict := integrityConflict(doc, existing)
			bookMu.Unlock()
			journalRejection(ctx, store, publisherID, viewID, reg, doc, documentRef, registrationRef, current, conflict)
			return empty, conflict
		}
		bookMu.Unlock()
		if err := finalizeReceipt(ctx, store, book, key, existing, documentRef, registrationRef); err != nil {
			return empty, err
		}
		return existing, nil
	}
	conflict := publicationOrderError(current, doc)
	if conflict != nil {
		bookMu.Unlock()
		journalRejection(ctx, store, publisherID, viewID, reg, doc, documentRef, registrationRef, current, conflict)
		return empty, conflict
	}

	receiptID := publicationReceiptID(reg.EntityKey, reg.Digest, viewID, doc.domain, doc.revision, doc.digest)
	supersedes := supersedesPin(current)
	observedHead := DomainPin{Revision: doc.revision, RecordDigest: doc.digest}
	data := map[string]any{
		"record_type":         eventDomainPublished,
		"schema_version":      schemaVersion,
		"receipt_id":          receiptID,
		"entity":              reg.Registration.Entity,
		"registration_digest": reg.Digest,
		"view_id":             viewID,
		"publisher_id":        publisherID,
		"domain":              doc.domain,
		"revision":            doc.revision,
		"previous_revision":   doc.previousRevision,
		"writer_id":           doc.writerID,
		"document":            artifactRefMap(documentRef),
		"supersedes":          domainPinMap(supersedes),
		"observed_owner_head": domainPinMap(observedHead),
		"source_prefix":       prefixMap(srcPrefix),
	}
	refs := []ArtifactReference{registrationRef, documentRef}
	var evidence []EvidenceRef
	if current.Revision > 0 {
		evidence = append(evidence, current.PublicationRef)
	}
	submission := EventSubmission{
		ProducerSequence:   journal_rules.NewMissing(missingReasonNotObserved),
		EventKind:          eventDomainPublished,
		EventSchemaVersion: eventSchemaVersion,
		OccurredAt:         journal_rules.NewMissing(missingReasonNotObserved),
		Payload: journal_rules.Payload{
			Data:         data,
			Measurements: []journal_rules.Measurement{},
			EvidenceRefs: evidence,
			ArtifactRefs: refs,
		},
	}
	envelopes, err := owner_store.CommitOwner(ctx, store, publicationJournalID, []EventSubmission{submission}, nil)
	if err != nil {
		bookMu.Unlock()
		return empty, fmt.Errorf("publication: commit publication: %w", err)
	}
	if len(envelopes) != 1 {
		bookMu.Unlock()
		return empty, fmt.Errorf("%w: publication commit returned %d envelopes", ErrIntegrityConflict, len(envelopes))
	}
	envelope := envelopes[0]
	installedAt, ok := timePointFromAny(envelope.RecordedAt)
	if !ok {
		bookMu.Unlock()
		return empty, fmt.Errorf("%w: publication receipt carries no installed_at TimePoint", ErrIntegrityConflict)
	}
	publicationRef := journal_rules.EvidenceRef{
		JournalID: envelope.JournalID,
		Sequence:  envelope.Sequence,
		EventID:   envelope.EventID,
		EventHash: envelope.EventHash,
		Pointer:   "",
	}
	receipt := PublicationReceipt{
		RecordType:         receiptRecordType,
		SchemaVersion:      schemaVersion,
		ReceiptID:          receiptID,
		Entity:             reg.Registration.Entity,
		RegistrationDigest: reg.Digest,
		ViewID:             viewID,
		PublisherID:        publisherID,
		Domain:             doc.domain,
		Revision:           doc.revision,
		Document:           documentRef,
		Supersedes:         supersedes,
		ObservedOwnerHead:  observedHead,
		SourcePrefix:       srcPrefix,
		InstalledAt:        installedAt,
		PublicationRef:     publicationRef,
		PublicationDelay:   buildPublicationDelay(receiptID, publisherClock(publisherID), source, srcPrefix, installedAt, publicationRef),
	}
	slot := slotRecord{
		Revision:       doc.revision,
		Document:       documentRef,
		PublicationRef: publicationRef,
	}
	book.setSlot(viewID, reg.EntityKey, doc.domain, slot)
	book.receipts[key] = receipt
	bookMu.Unlock()

	observe("publication_committed", int(envelope.Sequence))
	if err := finalizeReceipt(ctx, store, book, key, receipt, documentRef, registrationRef); err != nil {
		return empty, err
	}
	return receipt, nil
}

func integrityConflict(doc ownedRevision, existing PublicationReceipt) error {
	return fmt.Errorf("%w: %w: revision %d of domain %q already names document %q, different bytes are %q",
		owner_store.ErrIntegrityConflict, ErrIntegrityConflict, doc.revision, doc.domain,
		existing.Document.Digest, doc.digest)
}

// publicationOrderError classifies one delivery against the current slot.
func publicationOrderError(current slotRecord, doc ownedRevision) error {
	switch {
	case doc.revision < current.Revision:
		return fmt.Errorf("%w: revision %d of %q is older than the visible revision %d",
			ErrStalePublication, doc.revision, doc.domain, current.Revision)
	case doc.revision > current.Revision+1:
		return fmt.Errorf("%w: revision %d of %q skips the visible revision %d without verified lineage",
			ErrLineageGap, doc.revision, doc.domain, current.Revision)
	case doc.revision == current.Revision:
		// Reaching here means the receipt index did not hold the identity,
		// but the visible slot does. Same bytes can only be a lost index;
		// different bytes are an integrity conflict.
		if current.Document.Digest == doc.digest {
			return nil
		}
		return fmt.Errorf("%w: %w: revision %d of %q is already published with document %q, not %q",
			owner_store.ErrIntegrityConflict, ErrIntegrityConflict, doc.revision, doc.domain,
			current.Document.Digest, doc.digest)
	case doc.previousRevision != current.Revision:
		return fmt.Errorf("%w: revision %d of %q names previous_revision %d, visible revision is %d",
			ErrLineageGap, doc.revision, doc.domain, doc.previousRevision, current.Revision)
	}
	return nil
}

func supersedesPin(current slotRecord) DomainPin {
	if current.Revision <= 0 {
		return DomainPin{Revision: 0, RecordDigest: journal_rules.NewMissing(missingReasonNotApplicable)}
	}
	return DomainPin{Revision: current.Revision, RecordDigest: current.Document.Digest}
}

// journalRejection journals a rejected delivery as an incident. Rejections are
// never success receipts and never advance a view pointer; a failure to
// journal the incident never masks the primary classification.
func journalRejection(ctx context.Context, store *OwnerStore, ownerDomain, viewID string, reg registrationInfo,
	doc ownedRevision, documentRef, registrationRef ArtifactReference, current slotRecord, cause error) {
	data := map[string]any{
		"record_type":         "publication_rejected",
		"schema_version":      schemaVersion,
		"entity":              reg.Registration.Entity,
		"registration_digest": reg.Digest,
		"view_id":             viewID,
		"publisher_id":        ownerDomain,
		"domain":              doc.domain,
		"revision":            doc.revision,
		"previous_revision":   doc.previousRevision,
		"attempted_document":  artifactRefMap(documentRef),
		"visible_revision":    current.Revision,
		"reason":              rejectionReason(cause),
	}
	refs := []ArtifactReference{registrationRef, documentRef}
	if current.Revision > 0 {
		data["visible_document"] = artifactRefMap(current.Document)
		refs = append(refs, current.Document)
	}
	submission := EventSubmission{
		ProducerSequence:   journal_rules.NewMissing(missingReasonNotObserved),
		EventKind:          eventPublicationRejected,
		EventSchemaVersion: eventSchemaVersion,
		OccurredAt:         journal_rules.NewMissing(missingReasonNotObserved),
		Payload: journal_rules.Payload{
			Data:         data,
			Measurements: []journal_rules.Measurement{},
			EvidenceRefs: []journal_rules.EvidenceRef{},
			ArtifactRefs: refs,
		},
	}
	_, _ = owner_store.CommitOwner(ctx, store, publicationJournalID, []EventSubmission{submission}, nil)
}

func rejectionReason(err error) string {
	switch {
	case errors.Is(err, ErrStalePublication):
		return "stale_reordered"
	case errors.Is(err, ErrLineageGap):
		return "unverified_lineage"
	case errors.Is(err, ErrIntegrityConflict):
		return "integrity_conflict"
	default:
		return "rejected"
	}
}

// finalizeReceipt installs and retains the canonical receipt extent. It is
// idempotent and safe to re-run on an idempotent publication retry.
func finalizeReceipt(ctx context.Context, store *OwnerStore, book *storeBook, key string,
	receipt PublicationReceipt, documentRef, registrationRef ArtifactReference) error {
	bookMu.Lock()
	_, have := book.receiptRefs[key]
	bookMu.Unlock()
	if have {
		return nil
	}
	receiptRef, err := installCanonicalJSON(ctx, store, receipt)
	if err != nil {
		return fmt.Errorf("publication: install receipt extent: %w", err)
	}
	if err := owner_store.RetainRoot(ctx, store, receiptRef,
		[]ArtifactReference{documentRef, registrationRef}, receipt.PublicationRef); err != nil {
		return fmt.Errorf("publication: retain receipt extent: %w", err)
	}
	bookMu.Lock()
	book.receiptRefs[key] = receiptRef
	bookMu.Unlock()
	return nil
}

// ---------------------------------------------------------------------------
// SealRow.
// ---------------------------------------------------------------------------

// SealRow journals one seal selection over the named read view, then
// registers the resulting complete LogicalRow.
//
// The domain-slot snapshot is one exact version vector: it is copied under the
// same lock that publishes pointer advances, so concurrent seals can never
// combine an old body with a new pointer. Every published slot's complete
// snapshot is re-read from its immutable extent; a lost extent is a known
// observation loss, never a revision-zero replacement.
func SealRow(ctx context.Context, store *OwnerStore, registration EntityRegistration, name string, viewID string) (LogicalRow, error) {
	empty := LogicalRow{}
	if store == nil {
		return empty, fmt.Errorf("%w: store is required", ErrInvalid)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if strings.TrimSpace(viewID) == "" {
		return empty, fmt.Errorf("%w: view_id is required", ErrInvalid)
	}
	if !validSealNameForEntity(name) {
		return empty, fmt.Errorf("%w: seal name %q is not a Hellscape seal name", ErrInvalid, name)
	}
	reg, err := validateRegistration(registration)
	if err != nil {
		return empty, err
	}
	if !sealNameAllowed(reg.EntityType, name) {
		return empty, fmt.Errorf("%w: seal %q is not defined for entity type %q", ErrInvalid, name, reg.EntityType)
	}

	// Installing the registration extent also names this read view's
	// authenticated publisher domain, which owns the seal journal.
	registrationRef, err := installCanonicalJSON(ctx, store, registration)
	if err != nil {
		return empty, fmt.Errorf("publication: install registration extent: %w", err)
	}
	publisherID := strings.TrimSpace(registrationRef.OwnerDomain)
	if publisherID == "" {
		return empty, fmt.Errorf("%w: store names no publisher domain for sealing", ErrUnauthorized)
	}
	if err := ensurePublicationJournal(ctx, store, publisherID); err != nil {
		return empty, err
	}

	sealID, err := newSealID()
	if err != nil {
		return empty, fmt.Errorf("publication: allocate seal id: %w", err)
	}

	// The slot snapshot, its complete snapshots, the seal-selection artifact,
	// and the seal-selection event must describe one exact view state. The
	// selection event is committed while holding bookMu, so a concurrent
	// publication pointer advance can never slip between the selected vector
	// and its journaled selection. If the view moved while the extents were
	// being read, the selection is rebuilt from the newer complete state.
	var (
		slots          map[string]slotRecord
		versions       map[string]int64
		snapshots      map[string][]byte
		receiptRefs    map[string]ArtifactReference
		selectionRef   ArtifactReference
		selectionEvent journal_rules.JournalEnvelope
	)
	committed := false
	for attempt := 0; attempt < 8 && !committed; attempt++ {
		bookMu.Lock()
		book := bookForLocked(store)
		slots = book.slotsFor(viewID, reg.EntityKey, reg.Domains)
		receiptRefs = make(map[string]ArtifactReference, len(reg.Domains))
		for _, domain := range reg.Domains {
			slot := slots[domain]
			if slot.Revision == 0 {
				continue
			}
			if ref, ok := book.receiptRefs[receiptKey(viewID, reg.EntityKey, domain, slot.Revision)]; ok {
				receiptRefs[domain] = ref
			}
		}
		bookMu.Unlock()

		versions = make(map[string]int64, len(reg.Domains))
		snapshots = make(map[string][]byte, len(reg.Domains))
		for _, domain := range reg.Domains {
			slot := slots[domain]
			versions[domain] = slot.Revision
			if slot.Revision == 0 {
				continue
			}
			raw, err := readPublishedExtent(ctx, store, slot, domain, reg)
			if err != nil {
				return empty, err
			}
			snapshots[domain] = raw
		}
		if err := enforceSealRequirements(name, versions); err != nil {
			return empty, err
		}
		selection := sealSelectionDocument(sealID, name, viewID, reg, versions, slots, receiptRefs)
		selectionRef, err = installCanonicalJSON(ctx, store, selection)
		if err != nil {
			return empty, fmt.Errorf("publication: install seal selection extent: %w", err)
		}

		selectionData := map[string]any{
			"record_type":         "seal_selection",
			"schema_version":      schemaVersion,
			"seal_id":             sealID,
			"name":                name,
			"view_id":             viewID,
			"entity":              reg.Registration.Entity,
			"registration_digest": reg.Digest,
			"versions":            int64Map(versions),
			"seal_selection":      artifactRefMap(selectionRef),
			"selected":            selectionSlotsData(slots, reg, receiptRefs),
		}
		selectionRefs := []ArtifactReference{registrationRef, selectionRef}
		for _, ref := range receiptRefs {
			selectionRefs = append(selectionRefs, ref)
		}
		evidence := make([]EvidenceRef, 0, len(reg.Domains))
		for _, domain := range reg.Domains {
			slot := slots[domain]
			if slot.Revision == 0 {
				continue
			}
			selectionRefs = append(selectionRefs, slot.Document)
			evidence = append(evidence, slot.PublicationRef)
		}
		selectionSubmission := EventSubmission{
			ProducerSequence:   journal_rules.NewMissing(missingReasonNotObserved),
			EventKind:          eventSealSelected,
			EventSchemaVersion: eventSchemaVersion,
			OccurredAt:         journal_rules.NewMissing(missingReasonNotObserved),
			Payload: journal_rules.Payload{
				Data:         selectionData,
				Measurements: []journal_rules.Measurement{},
				EvidenceRefs: evidence,
				ArtifactRefs: selectionRefs,
			},
		}

		bookMu.Lock()
		if !sameSlotSnapshot(slots, book.slotsFor(viewID, reg.EntityKey, reg.Domains), reg.Domains) {
			bookMu.Unlock()
			continue
		}
		selectionEnvelopes, commitErr := owner_store.CommitOwner(ctx, store, publicationJournalID,
			[]EventSubmission{selectionSubmission}, nil)
		bookMu.Unlock()
		if commitErr != nil {
			return empty, fmt.Errorf("publication: commit seal selection: %w", commitErr)
		}
		if len(selectionEnvelopes) != 1 {
			return empty, fmt.Errorf("%w: seal selection commit returned %d envelopes", ErrIntegrityConflict, len(selectionEnvelopes))
		}
		selectionEvent = selectionEnvelopes[0]
		committed = true
	}
	if !committed {
		return empty, fmt.Errorf("%w: the read view advanced during every seal attempt", ErrIntegrityConflict)
	}
	sealedAt, ok := timePointFromAny(selectionEvent.RecordedAt)
	if !ok {
		return empty, fmt.Errorf("%w: seal selection carries no sealed_at TimePoint", ErrIntegrityConflict)
	}
	selectionEvidenceRef := journal_rules.EvidenceRef{
		JournalID: selectionEvent.JournalID,
		Sequence:  selectionEvent.Sequence,
		EventID:   selectionEvent.EventID,
		EventHash: selectionEvent.EventHash,
		Pointer:   "",
	}
	inputPrefix := JournalPrefix{
		JournalID:    selectionEvent.JournalID,
		LastSequence: selectionEvent.Sequence,
		HeadHash:     selectionEvent.EventHash,
	}
	row, err := buildLogicalRow(reg, viewID, sealID, name, sealedAt, inputPrefix, selectionEvidenceRef, slots, snapshots)
	if err != nil {
		return empty, err
	}
	rowRef, err := installCanonicalJSON(ctx, store, row)
	if err != nil {
		return empty, fmt.Errorf("publication: install logical row extent: %w", err)
	}
	rowData := map[string]any{
		"record_type":         "logical_row_registration",
		"schema_version":      schemaVersion,
		"entity":              reg.Registration.Entity,
		"registration_digest": reg.Digest,
		"seal_id":             sealID,
		"view_id":             viewID,
		"row":                 artifactRefMap(rowRef),
		"seal_selection":      evidenceRefMap(selectionEvidenceRef),
		"input_prefix":        prefixMap(inputPrefix),
	}
	rowRefs := []ArtifactReference{rowRef, selectionRef, registrationRef}
	dependencies := []ArtifactReference{selectionRef, registrationRef}
	for _, domain := range reg.Domains {
		slot := slots[domain]
		if slot.Revision == 0 {
			continue
		}
		rowRefs = append(rowRefs, slot.Document)
		dependencies = append(dependencies, slot.Document)
		if receiptRef, ok := receiptRefs[domain]; ok {
			dependencies = append(dependencies, receiptRef)
		}
	}
	rowSubmission := EventSubmission{
		ProducerSequence:   journal_rules.NewMissing(missingReasonNotObserved),
		EventKind:          eventRowRegistered,
		EventSchemaVersion: eventSchemaVersion,
		OccurredAt:         journal_rules.NewMissing(missingReasonNotObserved),
		Payload: journal_rules.Payload{
			Data:         rowData,
			Measurements: []journal_rules.Measurement{},
			EvidenceRefs: []journal_rules.EvidenceRef{selectionEvidenceRef},
			ArtifactRefs: rowRefs,
		},
	}
	if _, err := owner_store.CommitOwner(ctx, store, publicationJournalID, []EventSubmission{rowSubmission}, nil); err != nil {
		return empty, fmt.Errorf("publication: commit logical row registration: %w", err)
	}
	if err := owner_store.RetainRoot(ctx, store, rowRef, dependencies, selectionEvidenceRef); err != nil {
		return empty, fmt.Errorf("publication: retain logical row extent: %w", err)
	}
	return row, nil
}

// sameSlotSnapshot reports whether two slot snapshots describe the same
// complete read-view state for every declared domain.
func sameSlotSnapshot(left, right map[string]slotRecord, domains []string) bool {
	for _, domain := range domains {
		a := left[domain]
		b := right[domain]
		if a.Revision != b.Revision ||
			a.Document.Digest != b.Document.Digest ||
			a.PublicationRef != b.PublicationRef {
			return false
		}
	}
	return true
}

// readPublishedExtent re-reads one complete published document. A missing or
// corrupt extent is reported as known loss, never as an unpublished slot.
func readPublishedExtent(ctx context.Context, store *OwnerStore, slot slotRecord, domain string, reg registrationInfo) ([]byte, error) {
	raw, err := owner_store.ReadArtifact(ctx, store, slot.Document)
	if err != nil {
		return nil, fmt.Errorf("%w: revision %d of %q (%s): %w",
			ErrLostPublishedBytes, slot.Revision, domain, slot.Document.Digest, err)
	}
	doc, err := decodeDocument(raw, reg)
	if err != nil {
		return nil, fmt.Errorf("%w: revision %d of %q: %v", ErrLostPublishedBytes, slot.Revision, domain, err)
	}
	if doc.domain != domain || doc.revision != slot.Revision || doc.digest != slot.Document.Digest {
		return nil, fmt.Errorf("%w: extent %s no longer names the visible revision %d of %q",
			ErrLostPublishedBytes, slot.Document.Digest, slot.Revision, domain)
	}
	return raw, nil
}

func buildLogicalRow(reg registrationInfo, viewID, sealID, name string, sealedAt TimePoint,
	inputPrefix JournalPrefix, selectionRef EvidenceRef, slots map[string]slotRecord, snapshots map[string][]byte) (LogicalRow, error) {
	domains := make(map[string]DomainSlot, len(reg.Domains))
	versions := make(map[string]int64, len(reg.Domains))
	for _, domain := range reg.Domains {
		slot := slots[domain]
		versions[domain] = slot.Revision
		if slot.Revision == 0 {
			domains[domain] = DomainSlot{
				Revision: 0,
				Value:    journal_rules.NewMissing(missingReasonNotObserved),
			}
			continue
		}
		raw, ok := snapshots[domain]
		if !ok {
			return LogicalRow{}, fmt.Errorf("%w: no complete snapshot for published domain %q", ErrInvalid, domain)
		}
		documentRef := slot.Document
		publicationRef := slot.PublicationRef
		domains[domain] = DomainSlot{
			Revision:       slot.Revision,
			Document:       &documentRef,
			PublicationRef: &publicationRef,
			Snapshot:       append(json.RawMessage(nil), raw...),
		}
	}
	row := LogicalRow{
		RecordType:         logicalRowRecordType,
		SchemaVersion:      schemaVersion,
		Entity:             reg.Registration.Entity,
		RegistrationDigest: reg.Digest,
		Registration:       reg.Registration,
		Domains:            domains,
		SealPoint: SealPoint{
			SealID:       sealID,
			Name:         name,
			ViewID:       viewID,
			Versions:     versions,
			SealedAt:     sealedAt,
			InputPrefix:  inputPrefix,
			EvidenceRefs: []EvidenceRef{selectionRef},
		},
	}
	if err := validateLogicalRow(row, reg); err != nil {
		return LogicalRow{}, err
	}
	return row, nil
}

func validateLogicalRow(row LogicalRow, reg registrationInfo) error {
	if row.SealPoint.Name == "" || row.SealPoint.SealID == "" || row.SealPoint.ViewID == "" {
		return fmt.Errorf("%w: row seal identity is incomplete", ErrInvalid)
	}
	if len(row.SealPoint.EvidenceRefs) == 0 {
		return fmt.Errorf("%w: row seal cites no selection event", ErrInvalid)
	}
	for _, domain := range reg.Domains {
		slot, ok := row.Domains[domain]
		if !ok {
			return fmt.Errorf("%w: row omits declared domain %q", ErrInvalid, domain)
		}
		if row.SealPoint.Versions[domain] != slot.Revision {
			return fmt.Errorf("%w: seal vector for %q is %d, slot revision is %d",
				ErrIntegrityConflict, domain, row.SealPoint.Versions[domain], slot.Revision)
		}
		if slot.Revision == 0 {
			if slot.Document != nil || slot.PublicationRef != nil || len(slot.Snapshot) != 0 {
				return fmt.Errorf("%w: unpublished slot %q carries published identities", ErrInvalid, domain)
			}
			if _, ok := slot.Value.(journal_rules.MissingEnvelope); !ok {
				return fmt.Errorf("%w: unpublished slot %q must carry a typed Missing value", ErrInvalid, domain)
			}
			continue
		}
		if slot.Document == nil || slot.PublicationRef == nil || len(slot.Snapshot) == 0 {
			return fmt.Errorf("%w: published slot %q is incomplete", ErrInvalid, domain)
		}
	}
	for domain := range row.Domains {
		if !contains(reg.Domains, domain) {
			return fmt.Errorf("%w: row carries undeclared domain %q", ErrInvalid, domain)
		}
	}
	if len(row.SealPoint.Versions) != len(reg.Domains) {
		return fmt.Errorf("%w: seal vector omits a declared domain", ErrInvalid)
	}
	return nil
}

// ---------------------------------------------------------------------------
// ExpandArchive.
// ---------------------------------------------------------------------------

// ExpandArchive reconstructs the exact complete LogicalRow named by an archive
// storage manifest.
//
// Expansion reads only immutable local extents: the registration artifact and
// every complete published document artifact named by the manifest. It never
// consults the source journals, a current-view pointer, or a mutable peer.
// A published slot whose bytes are absent or corrupt is known loss, never
// revision zero.
func ExpandArchive(ctx context.Context, store *OwnerStore, manifest ArchiveStorageManifest) (ArchiveRecord, error) {
	empty := ArchiveRecord{}
	if store == nil {
		return empty, fmt.Errorf("%w: store is required", ErrInvalid)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if manifest.Encoding != archiveEncoding {
		return empty, fmt.Errorf("%w: archive encoding %q is not %q", ErrInvalid, manifest.Encoding, archiveEncoding)
	}
	if manifest.SchemaVersion != schemaVersion && manifest.SchemaVersion != attemptSchemaVersion {
		return empty, fmt.Errorf("%w: archive schema_version %q is not an admitted version", ErrInvalid, manifest.SchemaVersion)
	}
	if err := validateArtifactReference(manifest.Registration, "registration"); err != nil {
		return empty, err
	}
	registrationRaw, err := owner_store.ReadArtifact(ctx, store, manifest.Registration)
	if err != nil {
		return empty, fmt.Errorf("%w: registration extent %s: %w",
			ErrLostPublishedBytes, manifest.Registration.Digest, err)
	}
	registration, reg, err := decodeRegistration(registrationRaw)
	if err != nil {
		return empty, err
	}
	if reg.Digest != manifest.Registration.Digest {
		return empty, fmt.Errorf("%w: registration extent digest %q does not match its bytes %q",
			ErrIntegrityConflict, manifest.Registration.Digest, reg.Digest)
	}
	if !equalJSON(manifest.Entity, registration.Entity) {
		return empty, fmt.Errorf("%w: archive entity does not match its registration", ErrIntegrityConflict)
	}
	if len(manifest.Domains) != len(reg.Domains) {
		return empty, fmt.Errorf("%w: archive carries %d domain slots, registration declares %d",
			ErrInvalid, len(manifest.Domains), len(reg.Domains))
	}
	domains := make(map[string]DomainSlot, len(reg.Domains))
	for _, domain := range reg.Domains {
		archiveSlot, ok := manifest.Domains[domain]
		if !ok {
			return empty, fmt.Errorf("%w: archive omits declared domain %q", ErrInvalid, domain)
		}
		if archiveSlot.Revision == 0 {
			missing, err := missingFromAny(archiveSlot.Value, domain)
			if err != nil {
				return empty, err
			}
			if archiveSlot.Document != nil || archiveSlot.PublicationRef != nil {
				return empty, fmt.Errorf("%w: unpublished archive slot %q carries published identities", ErrInvalid, domain)
			}
			domains[domain] = DomainSlot{Revision: 0, Value: missing}
			continue
		}
		if archiveSlot.Document == nil {
			return empty, fmt.Errorf("%w: published archive slot %q names no document", ErrInvalid, domain)
		}
		if archiveSlot.PublicationRef == nil {
			return empty, fmt.Errorf("%w: published archive slot %q names no publication reference", ErrInvalid, domain)
		}
		if err := validateArtifactReference(*archiveSlot.Document, "domains."+domain+".document"); err != nil {
			return empty, err
		}
		if err := validateEvidenceRefShape(*archiveSlot.PublicationRef, "domains."+domain+".publication_ref"); err != nil {
			return empty, err
		}
		snapshot, err := owner_store.ReadArtifact(ctx, store, *archiveSlot.Document)
		if err != nil {
			return empty, fmt.Errorf("%w: document extent %s for domain %q: %w",
				ErrLostPublishedBytes, archiveSlot.Document.Digest, domain, err)
		}
		doc, err := decodeDocument(snapshot, reg)
		if err != nil {
			return empty, fmt.Errorf("%w: document extent %s for domain %q is not the archived revision: %v",
				ErrLostPublishedBytes, archiveSlot.Document.Digest, domain, err)
		}
		if doc.domain != domain || doc.revision != archiveSlot.Revision {
			return empty, fmt.Errorf("%w: document %s carries %q revision %d, archive slot names %q revision %d",
				ErrIntegrityConflict, archiveSlot.Document.Digest, doc.domain, doc.revision, domain, archiveSlot.Revision)
		}
		documentRef := *archiveSlot.Document
		publicationRef := *archiveSlot.PublicationRef
		domains[domain] = DomainSlot{
			Revision:       archiveSlot.Revision,
			Document:       &documentRef,
			PublicationRef: &publicationRef,
			Snapshot:       append(json.RawMessage(nil), snapshot...),
		}
	}
	for domain := range manifest.Domains {
		if !contains(reg.Domains, domain) {
			return empty, fmt.Errorf("%w: archive carries undeclared domain %q", ErrInvalid, domain)
		}
	}
	if err := validateArchiveSealPoint(manifest.SealPoint, reg, domains); err != nil {
		return empty, err
	}
	row := LogicalRow{
		RecordType:         logicalRowRecordType,
		SchemaVersion:      schemaVersion,
		Entity:             registration.Entity,
		RegistrationDigest: reg.Digest,
		Registration:       registration,
		Domains:            domains,
		SealPoint:          manifest.SealPoint,
	}
	if err := validateLogicalRow(row, reg); err != nil {
		return empty, err
	}
	canonical, err := canonicalJSON(manifest)
	if err != nil {
		return empty, fmt.Errorf("publication: canonicalize archive manifest: %w", err)
	}
	access := accessPublic
	if manifest.Registration.Access == accessRestricted {
		access = accessRestricted
	}
	for _, slot := range manifest.Domains {
		if slot.Document != nil && slot.Document.Access == accessRestricted {
			access = accessRestricted
		}
	}
	root := ArtifactReference{
		Digest:      string(evidence_codec.HashBytes(canonical)),
		SizeBytes:   int64(len(canonical)),
		MediaType:   mediaTypeJSON,
		OwnerDomain: manifest.Registration.OwnerDomain,
		Access:      access,
	}
	return ArchiveRecord{
		RecordType:      archiveRecordType,
		SchemaVersion:   schemaVersion,
		Root:            root,
		StorageManifest: manifest,
		PayloadJSON:     row,
	}, nil
}

func validateArchiveSealPoint(seal SealPoint, reg registrationInfo, domains map[string]DomainSlot) error {
	if strings.TrimSpace(seal.SealID) == "" || strings.TrimSpace(seal.ViewID) == "" {
		return fmt.Errorf("%w: archive seal identity is incomplete", ErrInvalid)
	}
	if !sealNameAllowed(reg.EntityType, seal.Name) {
		return fmt.Errorf("%w: archive seal %q is not defined for entity type %q", ErrInvalid, seal.Name, reg.EntityType)
	}
	if len(seal.Versions) != len(reg.Domains) {
		return fmt.Errorf("%w: archive seal vector omits a declared domain", ErrInvalid)
	}
	for _, domain := range reg.Domains {
		version, ok := seal.Versions[domain]
		if !ok {
			return fmt.Errorf("%w: archive seal vector omits %q", ErrInvalid, domain)
		}
		if version != domains[domain].Revision {
			return fmt.Errorf("%w: archive seal vector for %q is %d, slot revision is %d",
				ErrIntegrityConflict, domain, version, domains[domain].Revision)
		}
	}
	if len(seal.EvidenceRefs) == 0 {
		return fmt.Errorf("%w: archive seal cites no selection event", ErrInvalid)
	}
	for i, ref := range seal.EvidenceRefs {
		if err := validateEvidenceRefShape(ref, fmt.Sprintf("seal.evidence_refs[%d]", i)); err != nil {
			return err
		}
	}
	if strings.TrimSpace(seal.InputPrefix.JournalID) == "" || seal.InputPrefix.LastSequence < 1 ||
		!validDigest(seal.InputPrefix.HeadHash) {
		return fmt.Errorf("%w: archive seal input prefix is invalid", ErrInvalid)
	}
	if strings.TrimSpace(seal.SealedAt.ClockID) == "" || strings.TrimSpace(seal.SealedAt.BootID) == "" ||
		strings.TrimSpace(seal.SealedAt.Origin) == "" {
		return fmt.Errorf("%w: archive seal carries no sealed_at TimePoint", ErrInvalid)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Registration and document validation.
// ---------------------------------------------------------------------------

type ownerBinding struct {
	OwnerDomain string
	WriterID    string
}

type registrationInfo struct {
	Registration EntityRegistration
	Bytes        []byte
	Digest       string
	EntityType   string
	EntityKey    string
	Domains      []string
	Owners       map[string]ownerBinding
}

var declaredDomainSets = map[string][]string{
	"hellscape_session":   {"application", "observation", "diagnostic"},
	"application_attempt": {"dispatch", "observation", "execution", "application", "report"},
	"job":                 {"crawler", "downstream"},
}

var sealNamesByEntityType = map[string]map[string]bool{
	"hellscape_session": {
		"session_admitted":     true,
		"observation_closed":   true,
		"diagnostic_published": true,
		"evidence_updated":     true,
	},
	"application_attempt": {
		"commissioned":       true,
		"observation_closed": true,
		"evidence_updated":   true,
	},
	"job": {
		"published":             true,
		"fetch_key_replacement": true,
		"evidence_updated":      true,
	},
}

func validSealNameForEntity(name string) bool {
	for _, names := range sealNamesByEntityType {
		if names[name] {
			return true
		}
	}
	return false
}

func sealNameAllowed(entityType, name string) bool {
	names, ok := sealNamesByEntityType[entityType]
	if !ok {
		return false
	}
	return names[name]
}

func declaredDomains(entityType string) ([]string, error) {
	domains, ok := declaredDomainSets[entityType]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedEntity, entityType)
	}
	return append([]string(nil), domains...), nil
}

func validateRegistration(registration EntityRegistration) (registrationInfo, error) {
	empty := registrationInfo{}
	if registration.RecordType != "write_domain_entity" {
		return empty, fmt.Errorf("%w: registration record_type %q must be write_domain_entity",
			ErrInvalid, registration.RecordType)
	}
	if registration.SchemaVersion != schemaVersion {
		return empty, fmt.Errorf("%w: registration schema_version %q is not %q",
			ErrInvalid, registration.SchemaVersion, schemaVersion)
	}
	if strings.TrimSpace(registration.RegistrationID) == "" {
		return empty, fmt.Errorf("%w: registration_id is required", ErrInvalid)
	}
	entityType, err := entityTypeOf(registration.Entity)
	if err != nil {
		return empty, err
	}
	entityKey, err := entityKeyOf(registration.Entity)
	if err != nil {
		return empty, err
	}
	domains, err := declaredDomains(entityType)
	if err != nil {
		return empty, err
	}
	if registration.Identity == nil {
		return empty, fmt.Errorf("%w: registration identity is required", ErrInvalid)
	}
	if registration.Owners == nil {
		return empty, fmt.Errorf("%w: registration owners are required", ErrInvalid)
	}
	owners := make(map[string]ownerBinding, len(domains))
	seenOwners := make(map[string]string, len(domains))
	for _, domain := range domains {
		binding, err := ownerBindingFor(registration.Owners, domain)
		if err != nil {
			return empty, err
		}
		if previous, dup := seenOwners[binding.OwnerDomain]; dup {
			return empty, fmt.Errorf("%w: domains %q and %q share owner_domain %q: every domain has one distinct writer",
				ErrInvalid, previous, domain, binding.OwnerDomain)
		}
		seenOwners[binding.OwnerDomain] = domain
		owners[domain] = binding
	}
	if strings.TrimSpace(registration.EvidencePrefix.JournalID) == "" ||
		registration.EvidencePrefix.LastSequence < 1 ||
		!validDigest(registration.EvidencePrefix.HeadHash) {
		return empty, fmt.Errorf("%w: registration evidence_prefix is invalid", ErrInvalid)
	}
	if len(registration.EvidenceRefs) == 0 {
		return empty, fmt.Errorf("%w: registration evidence_refs must support the registration", ErrInvalid)
	}
	for i, ref := range registration.EvidenceRefs {
		if err := validateEvidenceRefShape(ref, fmt.Sprintf("registration.evidence_refs[%d]", i)); err != nil {
			return empty, err
		}
	}
	canonical, err := canonicalJSON(registration)
	if err != nil {
		return empty, fmt.Errorf("publication: canonicalize registration: %w", err)
	}
	var decoded any
	if err := decodeNumberJSON(canonical, &decoded); err != nil {
		return empty, fmt.Errorf("%w: registration is unreadable: %v", ErrInvalid, err)
	}
	if err := rejectBareNulls(decoded, "$"); err != nil {
		return empty, err
	}
	return registrationInfo{
		Registration: registration,
		Bytes:        canonical,
		Digest:       string(evidence_codec.HashBytes(canonical)),
		EntityType:   entityType,
		EntityKey:    entityKey,
		Domains:      domains,
		Owners:       owners,
	}, nil
}

// decodeRegistration decodes an installed registration extent and proves it
// round-trips exactly through the declared closed shape, so an archive can
// never silently drop registration fields.
func decodeRegistration(raw []byte) (EntityRegistration, registrationInfo, error) {
	empty := registrationInfo{}
	canonical, err := evidence_codec.CanonicalJSON(raw, mediaTypeJSON)
	if err != nil {
		return EntityRegistration{}, empty, fmt.Errorf("%w: registration extent is not canonical JSON: %v", ErrInvalid, err)
	}
	if !bytes.Equal(canonical, raw) {
		return EntityRegistration{}, empty, fmt.Errorf("%w: registration extent bytes are not canonical JSON", ErrInvalid)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var registration EntityRegistration
	if err := decoder.Decode(&registration); err != nil {
		return EntityRegistration{}, empty, fmt.Errorf("%w: registration extent is not an EntityRegistration: %v", ErrInvalid, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return EntityRegistration{}, empty, fmt.Errorf("%w: registration extent carries trailing content", ErrInvalid)
	}
	info, err := validateRegistration(registration)
	if err != nil {
		return EntityRegistration{}, empty, err
	}
	if !bytes.Equal(info.Bytes, raw) {
		return EntityRegistration{}, empty, fmt.Errorf("%w: registration extent carries fields outside the declared shape", ErrInvalid)
	}
	return registration, info, nil
}

func ownerBindingFor(owners map[string]any, domain string) (ownerBinding, error) {
	raw, ok := owners[domain]
	if !ok {
		return ownerBinding{}, fmt.Errorf("%w: registration omits owner binding for domain %q", ErrInvalid, domain)
	}
	m, ok := raw.(map[string]any)
	if !ok {
		return ownerBinding{}, fmt.Errorf("%w: owner binding for domain %q must be an object", ErrInvalid, domain)
	}
	ownerDomain, _ := m["owner_domain"].(string)
	writerID, _ := m["writer_id"].(string)
	role, _ := m["role"].(string)
	if strings.TrimSpace(role) == "" {
		return ownerBinding{}, fmt.Errorf("%w: owner binding for domain %q names no role", ErrInvalid, domain)
	}
	if strings.TrimSpace(ownerDomain) == "" {
		return ownerBinding{}, fmt.Errorf("%w: owner binding for domain %q names no owner_domain", ErrInvalid, domain)
	}
	if strings.TrimSpace(writerID) == "" {
		return ownerBinding{}, fmt.Errorf("%w: owner binding for domain %q names no writer_id", ErrInvalid, domain)
	}
	policy, ok := m["publication_policy"].(map[string]any)
	if !ok {
		return ownerBinding{}, fmt.Errorf("%w: owner binding for domain %q names no publication_policy", ErrInvalid, domain)
	}
	policyID, _ := policy["id"].(string)
	policyVersion, _ := policy["version"].(string)
	policyDigest, _ := policy["artifact_digest"].(string)
	if strings.TrimSpace(policyID) == "" || strings.TrimSpace(policyVersion) == "" || !validDigest(policyDigest) {
		return ownerBinding{}, fmt.Errorf("%w: owner binding for domain %q carries an invalid publication_policy",
			ErrInvalid, domain)
	}
	return ownerBinding{OwnerDomain: ownerDomain, WriterID: writerID}, nil
}

func entityTypeOf(entity map[string]any) (string, error) {
	if entity == nil {
		return "", fmt.Errorf("%w: entity is required", ErrInvalid)
	}
	entityType, _ := entity["entity_type"].(string)
	if strings.TrimSpace(entityType) == "" {
		return "", fmt.Errorf("%w: entity.entity_type is required", ErrInvalid)
	}
	if _, ok := declaredDomainSets[entityType]; !ok {
		return "", fmt.Errorf("%w: %q", ErrUnsupportedEntity, entityType)
	}
	return entityType, nil
}

func entityKeyOf(entity map[string]any) (string, error) {
	entityType, err := entityTypeOf(entity)
	if err != nil {
		return "", err
	}
	switch entityType {
	case "job":
		target, err := requiredEntityField(entity, "target")
		if err != nil {
			return "", err
		}
		jobID, err := requiredEntityField(entity, "job_id")
		if err != nil {
			return "", err
		}
		return "job/" + target + "/" + jobID, nil
	case "application_attempt":
		attemptID, err := requiredEntityField(entity, "attempt_id")
		if err != nil {
			return "", err
		}
		kind, err := requiredEntityField(entity, "kind")
		if err != nil {
			return "", err
		}
		if kind != "practice" && kind != "production" {
			return "", fmt.Errorf("%w: attempt entity kind %q must be practice or production", ErrInvalid, kind)
		}
		return "application_attempt/" + attemptID + "/" + kind, nil
	case "hellscape_session":
		sessionID, err := requiredEntityField(entity, "session_id")
		if err != nil {
			return "", err
		}
		return "hellscape_session/" + sessionID, nil
	default:
		return "", fmt.Errorf("%w: %q", ErrUnsupportedEntity, entityType)
	}
}

func requiredEntityField(entity map[string]any, field string) (string, error) {
	value, _ := entity[field].(string)
	if strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("%w: entity.%s is required", ErrInvalid, field)
	}
	return value, nil
}

// ownedRevision is the decoded, validated view of one complete immutable
// domain document (owned_domain_revision or attempt_axis_revision).
type ownedRevision struct {
	digest           string
	domain           string
	ownerDomain      string
	writerID         string
	revision         int64
	previousRevision int64
	evidencePrefix   JournalPrefix
	evidenceRefs     []EvidenceRef
}

type documentShape struct {
	RecordType         string          `json:"record_type"`
	SchemaVersion      string          `json:"schema_version"`
	Entity             map[string]any  `json:"entity"`
	Attempt            *attemptShape   `json:"attempt"`
	CommissionDigest   string          `json:"commission_digest"`
	Domain             string          `json:"domain"`
	Axis               string          `json:"axis"`
	OwnerDomain        string          `json:"owner_domain"`
	WriterID           string          `json:"writer_id"`
	Revision           int64           `json:"revision"`
	PreviousRevision   int64           `json:"previous_revision"`
	EvidencePrefix     JournalPrefix   `json:"evidence_prefix"`
	EvidenceRefs       []EvidenceRef   `json:"evidence_refs"`
	Value              json.RawMessage `json:"value"`
	RegistrationDigest string          `json:"registration_digest"`
}

type attemptShape struct {
	AttemptID string `json:"attempt_id"`
	Kind      string `json:"kind"`
}

func decodeDocument(raw []byte, reg registrationInfo) (ownedRevision, error) {
	empty := ownedRevision{}
	if len(bytes.TrimSpace(raw)) == 0 {
		return empty, fmt.Errorf("%w: publication document is empty", ErrInvalid)
	}
	canonical, err := evidence_codec.CanonicalJSON(raw, mediaTypeJSON)
	if err != nil {
		return empty, fmt.Errorf("%w: publication document is not canonical JSON: %v", ErrInvalid, err)
	}
	if !bytes.Equal(canonical, raw) {
		return empty, fmt.Errorf("%w: publication document bytes are not canonical JSON", ErrInvalid)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	var shape documentShape
	if err := decoder.Decode(&shape); err != nil {
		return empty, fmt.Errorf("%w: publication document is not an OwnedRevision: %v", ErrInvalid, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return empty, fmt.Errorf("%w: publication document carries trailing content", ErrInvalid)
	}
	if len(shape.Value) == 0 || !isJSONObject(shape.Value) {
		return empty, fmt.Errorf("%w: publication document value must be a complete object", ErrInvalid)
	}
	var value any
	if err := decodeNumberJSON(shape.Value, &value); err != nil {
		return empty, fmt.Errorf("%w: publication document value is unreadable: %v", ErrInvalid, err)
	}
	if err := rejectBareNulls(value, "$.value"); err != nil {
		return empty, err
	}
	document := ownedRevision{
		digest:           string(evidence_codec.HashBytes(raw)),
		ownerDomain:      shape.OwnerDomain,
		writerID:         shape.WriterID,
		revision:         shape.Revision,
		previousRevision: shape.PreviousRevision,
		evidencePrefix:   shape.EvidencePrefix,
		evidenceRefs:     shape.EvidenceRefs,
	}
	switch shape.RecordType {
	case "owned_domain_revision":
		if shape.SchemaVersion != schemaVersion {
			return empty, fmt.Errorf("%w: owned revision schema_version %q is not %q",
				ErrInvalid, shape.SchemaVersion, schemaVersion)
		}
		if shape.Attempt != nil || shape.Axis != "" || shape.CommissionDigest != "" {
			return empty, fmt.Errorf("%w: owned revision carries attempt-axis fields", ErrInvalid)
		}
		if shape.RegistrationDigest != reg.Digest {
			return empty, fmt.Errorf("%w: document registration_digest %q does not match canonical registration %q",
				ErrIntegrityConflict, shape.RegistrationDigest, reg.Digest)
		}
		document.domain = shape.Domain
		if !contains(reg.Domains, document.domain) {
			return empty, fmt.Errorf("%w: owned revision domain %q is not declared by the registration",
				ErrInvalid, document.domain)
		}
		if !equalJSON(shape.Entity, reg.Registration.Entity) {
			return empty, fmt.Errorf("%w: document entity does not match the registration entity", ErrIntegrityConflict)
		}
	case "attempt_axis_revision":
		if shape.SchemaVersion != attemptSchemaVersion {
			return empty, fmt.Errorf("%w: axis revision schema_version %q is not %q",
				ErrInvalid, shape.SchemaVersion, attemptSchemaVersion)
		}
		if shape.Entity != nil || shape.Domain != "" || shape.RegistrationDigest != "" {
			return empty, fmt.Errorf("%w: axis revision carries owned-domain fields", ErrInvalid)
		}
		if shape.Attempt == nil {
			return empty, fmt.Errorf("%w: axis revision names no attempt", ErrInvalid)
		}
		document.domain = shape.Axis
		if !contains(reg.Domains, document.domain) {
			return empty, fmt.Errorf("%w: axis revision axis %q is not declared by the registration",
				ErrInvalid, document.domain)
		}
		if reg.EntityType != "application_attempt" {
			return empty, fmt.Errorf("%w: axis revision registered for entity type %q", ErrInvalid, reg.EntityType)
		}
		if !validDigest(shape.CommissionDigest) {
			return empty, fmt.Errorf("%w: axis revision commission_digest is not a valid digest", ErrInvalid)
		}
		if strings.TrimSpace(shape.Attempt.AttemptID) == "" ||
			(shape.Attempt.Kind != "practice" && shape.Attempt.Kind != "production") {
			return empty, fmt.Errorf("%w: axis revision attempt identity is incomplete", ErrInvalid)
		}
		attemptID, _ := reg.Registration.Entity["attempt_id"].(string)
		kind, _ := reg.Registration.Entity["kind"].(string)
		if shape.Attempt.AttemptID != attemptID || shape.Attempt.Kind != kind {
			return empty, fmt.Errorf("%w: axis revision attempt does not match the registration entity",
				ErrIntegrityConflict)
		}
	default:
		return empty, fmt.Errorf("%w: unknown publication document record_type %q", ErrInvalid, shape.RecordType)
	}
	if document.revision < 1 {
		return empty, fmt.Errorf("%w: revision starts at 1", ErrInvalid)
	}
	if document.previousRevision < 0 || document.revision != document.previousRevision+1 {
		return empty, fmt.Errorf("%w: revision %d does not advance previous_revision %d by exactly one",
			ErrInvalid, document.revision, document.previousRevision)
	}
	if strings.TrimSpace(document.ownerDomain) == "" || strings.TrimSpace(document.writerID) == "" {
		return empty, fmt.Errorf("%w: document names no owner_domain/writer_id", ErrInvalid)
	}
	binding, ok := reg.Owners[document.domain]
	if !ok {
		return empty, fmt.Errorf("%w: registration names no writer for domain %q", ErrInvalid, document.domain)
	}
	if document.ownerDomain != binding.OwnerDomain || document.writerID != binding.WriterID {
		return empty, fmt.Errorf("%w: document owner %q/%q is not the registered writer %q/%q for domain %q",
			ErrUnauthorized, document.ownerDomain, document.writerID,
			binding.OwnerDomain, binding.WriterID, document.domain)
	}
	if strings.TrimSpace(document.evidencePrefix.JournalID) == "" ||
		document.evidencePrefix.LastSequence < 1 ||
		!validDigest(document.evidencePrefix.HeadHash) {
		return empty, fmt.Errorf("%w: document evidence_prefix is invalid", ErrInvalid)
	}
	if len(document.evidenceRefs) == 0 {
		return empty, fmt.Errorf("%w: document evidence_refs must support the publication", ErrInvalid)
	}
	for i, ref := range document.evidenceRefs {
		if err := validateEvidenceRefShape(ref, fmt.Sprintf("document.evidence_refs[%d]", i)); err != nil {
			return empty, err
		}
		if ref.JournalID != document.evidencePrefix.JournalID {
			return empty, fmt.Errorf("%w: document evidence ref %d names journal %q, prefix is %q",
				ErrInvalid, i, ref.JournalID, document.evidencePrefix.JournalID)
		}
		if ref.Sequence > document.evidencePrefix.LastSequence {
			return empty, fmt.Errorf("%w: document evidence ref %d lies beyond its own input prefix", ErrInvalid, i)
		}
	}
	return document, nil
}

// verifyDocumentSource proves that the document's own input prefix is an
// ancestor of the imported source prefix, that every cited input resolves, and
// that the document digest is pinned by a later event. Pinning the digest
// before the document names that same prefix would be a hash cycle, so the
// pinned event must sit strictly after the document's input prefix.
func verifyDocumentSource(doc ownedRevision, source []JournalEnvelope, srcPrefix JournalPrefix) error {
	if doc.evidencePrefix.JournalID != srcPrefix.JournalID {
		return fmt.Errorf("%w: document prefix journal %q does not match source journal %q",
			ErrInvalid, doc.evidencePrefix.JournalID, srcPrefix.JournalID)
	}
	if doc.evidencePrefix.LastSequence > srcPrefix.LastSequence {
		return fmt.Errorf("%w: document input prefix ends at %d, beyond the source prefix at %d",
			ErrInvalid, doc.evidencePrefix.LastSequence, srcPrefix.LastSequence)
	}
	if int(doc.evidencePrefix.LastSequence) > len(source) {
		return fmt.Errorf("%w: document input prefix head is not retained", ErrInvalid)
	}
	head := source[doc.evidencePrefix.LastSequence-1]
	if head.EventID == "" || head.EventHash != doc.evidencePrefix.HeadHash {
		return fmt.Errorf("%w: document input prefix head does not match the retained source event", ErrIntegrityConflict)
	}
	for i, ref := range doc.evidenceRefs {
		if _, err := journal_rules.ResolveEvidence(doc.evidencePrefix, source, ref); err != nil {
			return fmt.Errorf("%w: document evidence_refs[%d] does not resolve in its input prefix: %v",
				ErrUnverifiedDocument, i, err)
		}
	}
	pinSequence := digestPinSequence(source, doc.digest)
	if pinSequence == 0 {
		return fmt.Errorf("%w: no source event pins document digest %s", ErrUnverifiedDocument, doc.digest)
	}
	if pinSequence <= doc.evidencePrefix.LastSequence {
		return fmt.Errorf("%w: document digest is pinned inside its own derivation inputs: register after bytes exist",
			ErrUnverifiedDocument)
	}
	return nil
}

func verifySourceJournal(sourceManifest Manifest, source []JournalEnvelope) (JournalPrefix, error) {
	if len(source) == 0 {
		return JournalPrefix{}, fmt.Errorf("%w: source prefix is empty", ErrInvalid)
	}
	verified, err := journal_rules.ValidateJournal(sourceManifest, source)
	if err != nil {
		return JournalPrefix{}, fmt.Errorf("publication: source journal validation: %w", err)
	}
	if int64(len(source)) != verified.LastSequence {
		return JournalPrefix{}, fmt.Errorf("%w: source carries %d events, verified prefix ends at %d",
			ErrInvalid, len(source), verified.LastSequence)
	}
	return verified, nil
}

// digestPinSequence returns the first source event sequence whose payload pins
// the exact document digest, or zero when the source never names it.
func digestPinSequence(source []JournalEnvelope, digest string) int64 {
	for _, event := range source {
		if dataContainsString(map[string]any(event.Payload.Data), digest) {
			return event.Sequence
		}
		for _, ref := range event.Payload.ArtifactRefs {
			if ref.Digest == digest {
				return event.Sequence
			}
		}
	}
	return 0
}

func dataContainsString(value any, target string) bool {
	switch node := value.(type) {
	case string:
		return node == target
	case map[string]any:
		for _, child := range node {
			if dataContainsString(child, target) {
				return true
			}
		}
	case []any:
		for _, child := range node {
			if dataContainsString(child, target) {
				return true
			}
		}
	}
	return false
}

func validateEvidenceRefShape(ref EvidenceRef, field string) error {
	if strings.TrimSpace(ref.JournalID) == "" {
		return fmt.Errorf("%w: %s.journal_id is required", ErrInvalid, field)
	}
	if ref.Sequence < 1 {
		return fmt.Errorf("%w: %s.sequence starts at 1", ErrInvalid, field)
	}
	if strings.TrimSpace(ref.EventID) == "" {
		return fmt.Errorf("%w: %s.event_id is required", ErrInvalid, field)
	}
	if !validDigest(ref.EventHash) {
		return fmt.Errorf("%w: %s.event_hash is not a valid digest", ErrInvalid, field)
	}
	if ref.Pointer != "" {
		// A pointer is resolved by journal_rules; only reject obviously
		// malformed forms here.
		if !strings.HasPrefix(ref.Pointer, "/") {
			return fmt.Errorf("%w: %s.pointer must be empty or begin with '/'", ErrInvalid, field)
		}
	}
	return nil
}

func validateArtifactReference(ref ArtifactReference, field string) error {
	if !validDigest(ref.Digest) {
		return fmt.Errorf("%w: %s.digest %q is not a valid digest", ErrInvalid, field, ref.Digest)
	}
	if ref.SizeBytes < 0 {
		return fmt.Errorf("%w: %s.size_bytes must not be negative", ErrInvalid, field)
	}
	if strings.TrimSpace(ref.MediaType) == "" {
		return fmt.Errorf("%w: %s.media_type is required", ErrInvalid, field)
	}
	if strings.TrimSpace(ref.OwnerDomain) == "" {
		return fmt.Errorf("%w: %s.owner_domain is required", ErrInvalid, field)
	}
	if ref.Access != accessPublic && ref.Access != accessRestricted {
		return fmt.Errorf("%w: %s.access must be public or restricted", ErrInvalid, field)
	}
	return nil
}

func enforceSealRequirements(name string, versions map[string]int64) error {
	switch name {
	case "observation_closed":
		if versions["observation"] == 0 {
			return fmt.Errorf("%w: seal %q requires a published observation domain", ErrInvalid, name)
		}
	case "diagnostic_published":
		if versions["diagnostic"] == 0 {
			return fmt.Errorf("%w: seal %q requires a published diagnostic domain", ErrInvalid, name)
		}
	case "fetch_key_replacement":
		if versions["crawler"] == 0 {
			return fmt.Errorf("%w: seal %q requires a published crawler domain", ErrInvalid, name)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Owner-local publication journal.
// ---------------------------------------------------------------------------

func publisherClock(sourceID string) journal_rules.ClockDescriptor {
	return journal_rules.ClockDescriptor{
		ClockID:  publicationClockID,
		BootID:   publicationBootID,
		Origin:   "engine_measured",
		SourceID: sourceID,
		Basis:    "monotonic_offset",
		Unit:     "ms",
	}
}

func publicationManifest(ownerDomain string) Manifest {
	return Manifest{
		RecordType:    "manifest",
		SchemaVersion: "0.1.0",
		ManifestID:    "manifest-" + publicationJournalID,
		RunID:         publicationRunID,
		JournalID:     publicationJournalID,
		OwnerDomain:   ownerDomain,
		Clocks:        []journal_rules.ClockDescriptor{publisherClock(ownerDomain)},
	}
}

// ensurePublicationJournal admits the deterministic publication journal. The
// manifest is byte-identical on every call, so a retry replays the original
// admission receipt instead of creating a second journal.
func ensurePublicationJournal(ctx context.Context, store *OwnerStore, ownerDomain string) error {
	manifest := publicationManifest(ownerDomain)
	manifestRef, manifestBytes, err := installCanonicalJSONWithBytes(ctx, store, manifest)
	if err != nil {
		return fmt.Errorf("publication: install publication manifest: %w", err)
	}
	if string(evidence_codec.HashBytes(manifestBytes)) != manifestRef.Digest {
		return fmt.Errorf("%w: publication manifest digest does not match its bytes", ErrIntegrityConflict)
	}
	admission := EventSubmission{
		ProducerSequence:   int64(1),
		EventKind:          "manifest_admitted",
		EventSchemaVersion: eventSchemaVersion,
		OccurredAt:         journal_rules.NewMissing(missingReasonNotObserved),
		Payload: journal_rules.Payload{
			Data:         map[string]any{"manifest": artifactRefMap(manifestRef)},
			Measurements: []journal_rules.Measurement{},
			EvidenceRefs: []journal_rules.EvidenceRef{},
			ArtifactRefs: []ArtifactReference{manifestRef},
		},
	}
	if _, err := owner_store.CommitOwner(ctx, store, publicationJournalID, []EventSubmission{admission}, nil); err != nil {
		return fmt.Errorf("publication: admit publication journal: %w", err)
	}
	return nil
}

// ensureImportPolicy installs (idempotently) the immutable import-verification
// policy used for this source owner and returns its exact pin. The installed
// reference also names this owner store's authenticated domain.
func ensureImportPolicy(ctx context.Context, store *OwnerStore, sourceManifest Manifest) (VersionPin, ArtifactReference, error) {
	sourceOwner := strings.TrimSpace(sourceManifest.OwnerDomain)
	if sourceOwner == "" {
		return VersionPin{}, ArtifactReference{}, fmt.Errorf("%w: source manifest names no owner domain", ErrInvalid)
	}
	policyID := "publication-source-" + sourceOwner
	document := map[string]any{
		"policy_id":          policyID,
		"version":            "publication/1",
		"authorized_sources": []string{sourceOwner},
		"verification_kind":  "pinned_contract_presence",
	}
	ref, err := installCanonicalJSON(ctx, store, document)
	if err != nil {
		return VersionPin{}, ArtifactReference{}, fmt.Errorf("publication: install import policy: %w", err)
	}
	return VersionPin{ID: policyID, Version: "publication/1", ArtifactDigest: ref.Digest}, ref, nil
}

// ---------------------------------------------------------------------------
// Delay measurement.
// ---------------------------------------------------------------------------

// buildPublicationDelay retains the delay as measurement provenance. Exact
// subtraction is permitted only when the source receipt and the publication
// receipt sit on the same clock lifetime (clock_id, boot_id, origin); otherwise
// the estimate is unavailable with a reasoned Missing value.
func buildPublicationDelay(receiptID string, localClock journal_rules.ClockDescriptor,
	source []JournalEnvelope, srcPrefix JournalPrefix, installedAt TimePoint, publicationRef EvidenceRef) PublicationDelay {
	measurementID := "publication-delay-" + receiptID
	delay := PublicationDelay{
		Measurement: journal_rules.Measurement{
			MeasurementID:      measurementID,
			Name:               "publication_delay",
			Scope:              journal_rules.Scope{Kind: "workflow_step", ID: receiptID},
			Quantity:           "duration",
			Unit:               "ms",
			Origin:             "engine_measured",
			ClockID:            localClock.ClockID,
			BootID:             localClock.BootID,
			Method:             "unavailable",
			Start:              journal_rules.NewMissing(missingReasonNotObserved),
			End:                installedAt,
			Estimate:           journal_rules.Estimate{Kind: "unavailable", Value: journal_rules.NewMissing(missingReasonNotObserved)},
			Resolution:         journal_rules.NewMissing(missingReasonNotObserved),
			Censoring:          "unavailable",
			ComparabilityGroup: journal_rules.NewMissing(missingReasonNotObserved),
		},
		EvidenceRefs: []EvidenceRef{publicationRef},
	}
	if srcPrefix.LastSequence < 1 || int(srcPrefix.LastSequence) > len(source) {
		return delay
	}
	if start, ok := timePointFromAny(source[srcPrefix.LastSequence-1].RecordedAt); ok {
		delay.Measurement.Start = start
		if start.ClockID == installedAt.ClockID && start.BootID == installedAt.BootID &&
			start.Origin == installedAt.Origin {
			delay.Measurement.ClockID = start.ClockID
			delay.Measurement.BootID = start.BootID
			delta := installedAt.MonotonicOffsetMs - start.MonotonicOffsetMs
			delay.Measurement.Method = "endpoint_difference"
			delay.Measurement.Estimate = journal_rules.Estimate{Kind: "exact", Value: delta}
			delay.Measurement.Censoring = "none"
			delay.Measurement.ComparabilityGroup = start.ClockID + "@" + start.BootID
		}
	}
	return delay
}

// ---------------------------------------------------------------------------
// Canonical encoding, identifiers, and small shape helpers.
// ---------------------------------------------------------------------------

func canonicalJSON(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return evidence_codec.CanonicalJSON(raw, mediaTypeJSON)
}

func installCanonicalJSON(ctx context.Context, store *OwnerStore, value any) (ArtifactReference, error) {
	ref, _, err := installCanonicalJSONWithBytes(ctx, store, value)
	return ref, err
}

func installCanonicalJSONWithBytes(ctx context.Context, store *OwnerStore, value any) (ArtifactReference, []byte, error) {
	canonical, err := canonicalJSON(value)
	if err != nil {
		return ArtifactReference{}, nil, err
	}
	ref, err := owner_store.InstallArtifact(ctx, store, bytes.NewReader(canonical), mediaTypeJSON, accessPublic)
	if err != nil {
		return ArtifactReference{}, canonical, err
	}
	return ref, canonical, nil
}

func artifactRefMap(ref ArtifactReference) map[string]any {
	return map[string]any{
		"digest":       ref.Digest,
		"size_bytes":   ref.SizeBytes,
		"media_type":   ref.MediaType,
		"owner_domain": ref.OwnerDomain,
		"access":       ref.Access,
	}
}

func evidenceRefMap(ref EvidenceRef) map[string]any {
	return map[string]any{
		"journal_id": ref.JournalID,
		"sequence":   ref.Sequence,
		"event_id":   ref.EventID,
		"event_hash": ref.EventHash,
		"pointer":    ref.Pointer,
	}
}

func prefixMap(prefix JournalPrefix) map[string]any {
	return map[string]any{
		"journal_id":    prefix.JournalID,
		"last_sequence": prefix.LastSequence,
		"head_hash":     prefix.HeadHash,
	}
}

func domainPinMap(pin DomainPin) map[string]any {
	return map[string]any{
		"revision":      pin.Revision,
		"record_digest": pin.RecordDigest,
	}
}

func int64Map(values map[string]int64) map[string]any {
	out := make(map[string]any, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func sealSelectionDocument(sealID, name, viewID string, reg registrationInfo, versions map[string]int64,
	slots map[string]slotRecord, receiptRefs map[string]ArtifactReference) map[string]any {
	return map[string]any{
		"record_type":         "seal_selection",
		"schema_version":      schemaVersion,
		"seal_id":             sealID,
		"name":                name,
		"view_id":             viewID,
		"entity":              reg.Registration.Entity,
		"registration_digest": reg.Digest,
		"versions":            int64Map(versions),
		"slots":               selectionSlotsData(slots, reg, receiptRefs),
	}
}

func selectionSlotsData(slots map[string]slotRecord, reg registrationInfo,
	receiptRefs map[string]ArtifactReference) []any {
	out := make([]any, 0, len(reg.Domains))
	for _, domain := range reg.Domains {
		slot := slots[domain]
		entry := map[string]any{
			"domain":   domain,
			"revision": slot.Revision,
		}
		if slot.Revision > 0 {
			entry["document"] = artifactRefMap(slot.Document)
			entry["publication_ref"] = evidenceRefMap(slot.PublicationRef)
			if receiptRef, ok := receiptRefs[domain]; ok {
				entry["receipt"] = artifactRefMap(receiptRef)
			}
		} else {
			entry["value"] = journal_rules.NewMissing(missingReasonNotObserved)
		}
		out = append(out, entry)
	}
	return out
}

func publicationReceiptID(entityKey, registrationDigest, viewID, domain string, revision int64, documentDigest string) string {
	hash := evidence_codec.HashBytes([]byte(strings.Join([]string{
		entityKey, registrationDigest, viewID, domain, strconv.FormatInt(revision, 10), documentDigest,
	}, "\x00")))
	hexPart := strings.TrimPrefix(string(hash), "sha256:")
	if len(hexPart) > 32 {
		hexPart = hexPart[:32]
	}
	return "receipt-" + hexPart
}

func newSealID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return "seal-" + hex.EncodeToString(raw), nil
}

func validDigest(value string) bool {
	const prefix = "sha256:"
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	hexPart := value[len(prefix):]
	if len(hexPart) != 64 {
		return false
	}
	for i := range hexPart {
		c := hexPart[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func isJSONObject(raw []byte) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) >= 2 && trimmed[0] == '{' && trimmed[len(trimmed)-1] == '}'
}

func decodeNumberJSON(raw []byte, out any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	return decoder.Decode(out)
}

func equalJSON(a, b any) bool {
	left, err := canonicalJSON(a)
	if err != nil {
		return false
	}
	right, err := canonicalJSON(b)
	if err != nil {
		return false
	}
	return bytes.Equal(left, right)
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func timePointFromAny(value any) (TimePoint, bool) {
	if point, ok := value.(journal_rules.TimePoint); ok {
		return point, true
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return TimePoint{}, false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var point TimePoint
	if err := decoder.Decode(&point); err != nil {
		return TimePoint{}, false
	}
	if strings.TrimSpace(point.ClockID) == "" || strings.TrimSpace(point.BootID) == "" ||
		strings.TrimSpace(point.Origin) == "" {
		return TimePoint{}, false
	}
	return point, true
}

func missingFromAny(value any, domain string) (journal_rules.MissingEnvelope, error) {
	if missing, ok := asMissingEnvelope(value); ok {
		return missing, nil
	}
	return journal_rules.MissingEnvelope{}, fmt.Errorf("%w: unpublished archive slot %q must carry a typed Missing value",
		ErrInvalid, domain)
}

func asMissingEnvelope(value any) (journal_rules.MissingEnvelope, bool) {
	switch node := value.(type) {
	case journal_rules.MissingEnvelope:
		return node, true
	case *journal_rules.MissingEnvelope:
		if node == nil {
			return journal_rules.MissingEnvelope{}, false
		}
		return *node, true
	case map[string]any:
		raw, hasValue := node["value"]
		if !hasValue || raw != nil {
			return journal_rules.MissingEnvelope{}, false
		}
		reason, _ := node["reason"].(string)
		if reason == "" {
			return journal_rules.MissingEnvelope{}, false
		}
		detail, _ := node["detail"].(string)
		return journal_rules.MissingEnvelope{Value: nil, Reason: reason, Detail: detail}, true
	default:
		return journal_rules.MissingEnvelope{}, false
	}
}

// rejectBareNulls rejects in-band nulls while accepting typed Missing
// envelopes as the only legal null representation.
func rejectBareNulls(value any, path string) error {
	switch node := value.(type) {
	case nil:
		return fmt.Errorf("%w: bare null at %s: normalized absences must use a Missing envelope", ErrInvalid, path)
	case map[string]any:
		if raw, hasValue := node["value"]; hasValue && raw == nil {
			reason, _ := node["reason"].(string)
			if reason == "" {
				return fmt.Errorf("%w: Missing envelope at %s names no reason", ErrInvalid, path)
			}
			if detail, hasDetail := node["detail"]; hasDetail {
				text, ok := detail.(string)
				if !ok || strings.TrimSpace(text) == "" {
					return fmt.Errorf("%w: Missing detail at %s must be a nonempty string", ErrInvalid, path)
				}
			}
			return nil
		}
		for key, child := range node {
			if err := rejectBareNulls(child, path+"."+key); err != nil {
				return err
			}
		}
	case []any:
		for i, child := range node {
			if err := rejectBareNulls(child, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

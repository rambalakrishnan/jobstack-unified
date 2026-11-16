package publication

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	authority "authority"
	evidence_codec "evidence_codec"
	evidence_import "evidence_import"
	journal_rules "journal_rules"
	owner_store "owner_store"
)

// ---------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------

type fixture struct {
	t            *testing.T
	store        *owner_store.OwnerStore
	ctx          context.Context
	domain       string
	artifactRoot string
}

func newFixture(t *testing.T, domain string) *fixture {
	t.Helper()
	home := t.TempDir()
	f := &fixture{
		t:            t,
		domain:       domain,
		artifactRoot: filepath.Join(home, domain+"-artifacts"),
	}
	store, err := owner_store.OpenOwner(filepath.Join(home, domain+".db"), f.artifactRoot, domain)
	if err != nil {
		t.Fatalf("OpenOwner(%s): %v", domain, err)
	}
	f.store = store
	t.Cleanup(func() { _ = f.store.Close() })
	f.ctx = testContext(t, domain)
	return f
}

func testPolicy(domain string) []byte {
	return []byte(fmt.Sprintf(
		`{"channels":{"channel-%s":{"principal":"writer-%s","kind":"owner","grants":[{"domain":"*","operations":["*"]}]}}}`,
		domain, domain))
}

func testContext(t *testing.T, domain string) context.Context {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, "http://publication.test/"+domain, nil)
	if err != nil {
		t.Fatalf("build authentication request: %v", err)
	}
	request.Header.Set("Authorization", "Channel channel-"+domain)
	ctx, err := authority.Authenticate(request, testPolicy(domain))
	if err != nil {
		t.Fatalf("authenticate %s writer: %v", domain, err)
	}
	return ctx
}

// ---------------------------------------------------------------------------
// Source journal fixture.
// ---------------------------------------------------------------------------

func defaultSourceClock() journal_rules.ClockDescriptor {
	return journal_rules.ClockDescriptor{
		ClockID: "src-clock", BootID: "src-boot", Origin: "engine_measured",
		SourceID: "src", Basis: "monotonic_offset", Unit: "ms",
	}
}

func manifestDigestOf(t *testing.T, manifest Manifest) string {
	t.Helper()
	canonical, err := canonicalJSON(manifest)
	if err != nil {
		t.Fatalf("canonicalize manifest: %v", err)
	}
	return string(evidence_codec.HashBytes(canonical))
}

func sourceManifestFor(journalID, owner string, clock journal_rules.ClockDescriptor) Manifest {
	return Manifest{
		RecordType:    "manifest",
		SchemaVersion: "0.1.0",
		ManifestID:    "manifest-" + journalID,
		RunID:         "run-" + journalID,
		JournalID:     journalID,
		OwnerDomain:   owner,
		Clocks:        []journal_rules.ClockDescriptor{clock},
	}
}

func finalizeEnvelope(t *testing.T, event *JournalEnvelope) {
	t.Helper()
	if event.CausalRefs == nil {
		event.CausalRefs = []EvidenceRef{}
	}
	if event.Payload.Data == nil {
		event.Payload.Data = map[string]any{}
	}
	if event.Payload.Measurements == nil {
		event.Payload.Measurements = []journal_rules.Measurement{}
	}
	if event.Payload.EvidenceRefs == nil {
		event.Payload.EvidenceRefs = []EvidenceRef{}
	}
	if event.Payload.ArtifactRefs == nil {
		event.Payload.ArtifactRefs = []ArtifactReference{}
	}
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	object, ok := decoded.(map[string]any)
	if !ok {
		t.Fatalf("envelope is not an object")
	}
	delete(object, "event_hash")
	if object["causal_refs"] == nil {
		object["causal_refs"] = []any{}
	}
	if object["payload"] == nil {
		object["payload"] = map[string]any{}
	}
	remarshaled, err := json.Marshal(object)
	if err != nil {
		t.Fatalf("re-encode envelope: %v", err)
	}
	canonical, err := evidence_codec.CanonicalJSON(remarshaled, "application/json")
	if err != nil {
		t.Fatalf("canonicalize envelope: %v", err)
	}
	event.EventHash = string(evidence_codec.HashBytes(canonical))
}

// sourceJournal builds one valid, complete source journal in memory.
type sourceJournal struct {
	t              *testing.T
	manifest       Manifest
	manifestDigest string
	clock          journal_rules.ClockDescriptor
	events         []JournalEnvelope
}

func newSourceJournal(t *testing.T, journalID, owner string, clock journal_rules.ClockDescriptor) *sourceJournal {
	t.Helper()
	manifest := sourceManifestFor(journalID, owner, clock)
	journal := &sourceJournal{
		t:              t,
		manifest:       manifest,
		manifestDigest: manifestDigestOf(t, manifest),
		clock:          clock,
	}
	journal.append("manifest_admitted", map[string]any{
		"manifest": map[string]any{
			"digest":       journal.manifestDigest,
			"size_bytes":   int64(256),
			"media_type":   "application/json",
			"owner_domain": owner,
			"access":       "public",
		},
	})
	return journal
}

func (j *sourceJournal) append(kind string, data map[string]any) *JournalEnvelope {
	sequence := int64(len(j.events) + 1)
	role := "derived_output"
	if sequence == 1 {
		role = "external_input"
	}
	var previous any = journal_rules.NewMissing("not_applicable")
	if len(j.events) > 0 {
		previous = j.events[len(j.events)-1].EventHash
	}
	event := JournalEnvelope{
		RecordType: "journal_event", SchemaVersion: "0.1.0",
		RunID: j.manifest.RunID, JournalID: j.manifest.JournalID, ManifestHash: j.manifestDigest,
		Sequence: sequence, EventID: fmt.Sprintf("evt-%s-%d", j.manifest.JournalID, sequence),
		EventKind: kind, EventSchemaVersion: "0.1.0",
		Role: role, AssertionKind: "authoritative_effect",
		OwnerDomain: j.manifest.OwnerDomain, ProducerID: "producer-" + j.manifest.JournalID,
		ProducerSequence: sequence, Provenance: "server", EvidenceScope: "current_run",
		RecordedAt: journal_rules.TimePoint{
			ClockID: j.clock.ClockID, BootID: j.clock.BootID, Origin: j.clock.Origin,
			MonotonicOffsetMs: float64(1000 + sequence*10),
			UTCAnnotation:     journal_rules.NewMissing("not_applicable"),
		},
		OccurredAt:        journal_rules.NewMissing("not_observed"),
		CausalRefs:        []EvidenceRef{},
		Payload:           journal_rules.Payload{Data: data},
		PreviousEventHash: previous,
	}
	if data == nil {
		event.Payload.Data = map[string]any{}
	}
	finalizeEnvelope(j.t, &event)
	j.events = append(j.events, event)
	return &j.events[len(j.events)-1]
}

func (j *sourceJournal) prefix() JournalPrefix {
	j.t.Helper()
	prefix, err := journal_rules.ValidateJournal(j.manifest, j.events)
	if err != nil {
		j.t.Fatalf("source fixture validation: %v", err)
	}
	return prefix
}

func (j *sourceJournal) prefixAt(sequence int64) JournalPrefix {
	j.t.Helper()
	if sequence < 1 || int(sequence) > len(j.events) {
		j.t.Fatalf("prefixAt(%d) is outside %d retained events", sequence, len(j.events))
	}
	return JournalPrefix{
		JournalID:    j.manifest.JournalID,
		LastSequence: sequence,
		HeadHash:     j.events[sequence-1].EventHash,
	}
}

func (j *sourceJournal) ref(sequence int64) EvidenceRef {
	j.t.Helper()
	if sequence < 1 || int(sequence) > len(j.events) {
		j.t.Fatalf("ref(%d) is outside %d retained events", sequence, len(j.events))
	}
	event := j.events[sequence-1]
	return EvidenceRef{
		JournalID: event.JournalID,
		Sequence:  event.Sequence,
		EventID:   event.EventID,
		EventHash: event.EventHash,
		Pointer:   "",
	}
}

// ---------------------------------------------------------------------------
// Registration and publication fixtures.
// ---------------------------------------------------------------------------

func registrationSupport() (JournalPrefix, []EvidenceRef) {
	support := string(evidence_codec.HashBytes([]byte("registration-support")))
	return JournalPrefix{JournalID: "registration-journal", LastSequence: 1, HeadHash: support},
		[]EvidenceRef{{
			JournalID: "registration-journal",
			Sequence:  1,
			EventID:   "evt-registration",
			EventHash: support,
			Pointer:   "",
		}}
}

func testOwnerBinding(role, source, writer, ownerDomain string) map[string]any {
	return map[string]any{
		"role":         role,
		"source_id":    source,
		"writer_id":    writer,
		"owner_domain": ownerDomain,
		"publication_policy": map[string]any{
			"id":              "policy-" + ownerDomain,
			"version":         "v1",
			"artifact_digest": string(evidence_codec.HashBytes([]byte("policy-" + ownerDomain))),
		},
	}
}

func sessionRegistration() EntityRegistration {
	prefix, refs := registrationSupport()
	return EntityRegistration{
		RecordType:     "write_domain_entity",
		SchemaVersion:  schemaVersion,
		RegistrationID: "reg-session-1",
		Entity: map[string]any{
			"entity_type": "hellscape_session",
			"session_id":  "session-1",
		},
		Identity: map[string]any{
			"run_id":     "run-session-1",
			"journal_id": "journal-session-1",
		},
		Owners: map[string]any{
			"application": testOwnerBinding("origin", "source-application", "writer-application", "owner-application"),
			"observation": testOwnerBinding("observer", "source-observation", "writer-observation", "owner-observation"),
			"diagnostic":  testOwnerBinding("analyzer", "source-diagnostic", "writer-diagnostic", "owner-diagnostic"),
		},
		EvidencePrefix: prefix,
		EvidenceRefs:   refs,
	}
}

func registrationDigestOf(t *testing.T, registration EntityRegistration) string {
	t.Helper()
	canonical, err := canonicalJSON(registration)
	if err != nil {
		t.Fatalf("canonicalize registration: %v", err)
	}
	return string(evidence_codec.HashBytes(canonical))
}

func registeredWriterFor(t *testing.T, registration EntityRegistration, domain string) (string, string) {
	t.Helper()
	raw, ok := registration.Owners[domain]
	if !ok {
		t.Fatalf("registration names no owner binding for %q", domain)
	}
	binding, ok := raw.(map[string]any)
	if !ok {
		t.Fatalf("owner binding for %q is %T", domain, raw)
	}
	ownerDomain, _ := binding["owner_domain"].(string)
	writerID, _ := binding["writer_id"].(string)
	if ownerDomain == "" || writerID == "" {
		t.Fatalf("owner binding for %q is incomplete: %v", domain, binding)
	}
	return ownerDomain, writerID
}

func buildOwnedDocument(t *testing.T, registration EntityRegistration, domain string,
	revision, previousRevision int64, inputPrefix JournalPrefix, evidence []EvidenceRef,
	value map[string]any) []byte {
	t.Helper()
	ownerDomain, writerID := registeredWriterFor(t, registration, domain)
	evidenceMaps := make([]any, len(evidence))
	for i, ref := range evidence {
		evidenceMaps[i] = evidenceRefMap(ref)
	}
	document := map[string]any{
		"record_type":         "owned_domain_revision",
		"schema_version":      schemaVersion,
		"entity":              registration.Entity,
		"registration_digest": registrationDigestOf(t, registration),
		"domain":              domain,
		"owner_domain":        ownerDomain,
		"writer_id":           writerID,
		"revision":            revision,
		"previous_revision":   previousRevision,
		"evidence_prefix":     prefixMap(inputPrefix),
		"evidence_refs":       evidenceMaps,
		"value":               value,
	}
	canonical, err := canonicalJSON(document)
	if err != nil {
		t.Fatalf("canonicalize owned document: %v", err)
	}
	return canonical
}

type publicationInput struct {
	Document []byte
	Manifest Manifest
	Events   []JournalEnvelope
	Prefix   JournalPrefix
}

// buildPublicationInput creates a source journal that pins the complete
// document digest after the document's own input prefix.
func buildPublicationInput(t *testing.T, registration EntityRegistration, journalID, sourceOwner, domain string,
	revision int64, value map[string]any, clock journal_rules.ClockDescriptor) publicationInput {
	t.Helper()
	journal := newSourceJournal(t, journalID, sourceOwner, clock)
	inputPrefix := journal.prefixAt(1)
	document := buildOwnedDocument(t, registration, domain, revision, revision-1,
		inputPrefix, []EvidenceRef{journal.ref(1)}, value)
	journal.append("source_domain_proposed", map[string]any{
		"domain":          domain,
		"revision":        revision,
		"document_digest": string(evidence_codec.HashBytes(document)),
	})
	return publicationInput{
		Document: document,
		Manifest: journal.manifest,
		Events:   journal.events,
		Prefix:   journal.prefix(),
	}
}

func (f *fixture) installRegistration(registration EntityRegistration) ArtifactReference {
	f.t.Helper()
	ref, err := installCanonicalJSON(f.ctx, f.store, registration)
	if err != nil {
		f.t.Fatalf("install registration extent: %v", err)
	}
	return ref
}

func (f *fixture) publish(registration EntityRegistration, input publicationInput, viewID string) PublicationReceipt {
	f.t.Helper()
	receipt, err := InstallPublication(f.ctx, f.store, registration, input.Document,
		input.Manifest, input.Events, viewID)
	if err != nil {
		f.t.Fatalf("InstallPublication: %v", err)
	}
	return receipt
}

func (f *fixture) seal(registration EntityRegistration, name, viewID string) LogicalRow {
	f.t.Helper()
	row, err := SealRow(f.ctx, f.store, registration, name, viewID)
	if err != nil {
		f.t.Fatalf("SealRow(%s): %v", name, err)
	}
	return row
}

func loadJournalAt(t *testing.T, f *fixture, ref EvidenceRef) []owner_store.JournalEnvelope {
	t.Helper()
	prefix := JournalPrefix{JournalID: ref.JournalID, LastSequence: ref.Sequence, HeadHash: ref.EventHash}
	events, err := owner_store.LoadPrefix(f.ctx, f.store, prefix)
	if err != nil {
		t.Fatalf("LoadPrefix(%+v): %v", prefix, err)
	}
	return events
}

func valueMarkerOf(t *testing.T, snapshot json.RawMessage) map[string]any {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(snapshot))
	decoder.UseNumber()
	var document map[string]any
	if err := decoder.Decode(&document); err != nil {
		t.Fatalf("decode snapshot: %v", err)
	}
	value, ok := document["value"].(map[string]any)
	if !ok {
		t.Fatalf("snapshot value is %T, want object", document["value"])
	}
	return value
}

func snapshotString(t *testing.T, snapshot json.RawMessage, field string) string {
	t.Helper()
	value := valueMarkerOf(t, snapshot)
	got, _ := value[field].(string)
	return got
}

func snapshotRevision(t *testing.T, snapshot json.RawMessage) int64 {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(snapshot))
	decoder.UseNumber()
	var document map[string]any
	if err := decoder.Decode(&document); err != nil {
		t.Fatalf("decode snapshot: %v", err)
	}
	number, ok := document["revision"].(json.Number)
	if !ok {
		t.Fatalf("snapshot revision is %T", document["revision"])
	}
	revision, err := number.Int64()
	if err != nil {
		t.Fatalf("snapshot revision is not an integer: %v", err)
	}
	return revision
}

func assertPublishedSlot(t *testing.T, row LogicalRow, domain string, wantRevision int64, wantMarker string) {
	t.Helper()
	slot, ok := row.Domains[domain]
	if !ok {
		t.Fatalf("row omits domain %q", domain)
	}
	if slot.Revision != wantRevision {
		t.Fatalf("row domain %q revision = %d, want %d", domain, slot.Revision, wantRevision)
	}
	if row.SealPoint.Versions[domain] != wantRevision {
		t.Fatalf("seal vector for %q = %d, slot revision = %d", domain, row.SealPoint.Versions[domain], slot.Revision)
	}
	if slot.Document == nil || slot.PublicationRef == nil || len(slot.Snapshot) == 0 {
		t.Fatalf("published slot %q is incomplete: %+v", domain, slot)
	}
	if snapshotRevision(t, slot.Snapshot) != wantRevision {
		t.Fatalf("snapshot revision for %q = %d, want %d", domain, snapshotRevision(t, slot.Snapshot), wantRevision)
	}
	if got := snapshotString(t, slot.Snapshot, "marker"); got != wantMarker {
		t.Fatalf("snapshot marker for %q = %q, want %q", domain, got, wantMarker)
	}
	if got := string(evidence_codec.HashBytes(slot.Snapshot)); got != slot.Document.Digest {
		t.Fatalf("snapshot bytes for %q hash to %s, artifact names %s", domain, got, slot.Document.Digest)
	}
	if slot.PublicationRef.Sequence > row.SealPoint.InputPrefix.LastSequence {
		t.Fatalf("seal input prefix ends at %d but cites publication sequence %d",
			row.SealPoint.InputPrefix.LastSequence, slot.PublicationRef.Sequence)
	}
}

// ---------------------------------------------------------------------------
// Conformance assertions.
// ---------------------------------------------------------------------------

// TestLargePublicationTransferDoesNotDelaySourceAcknowledgement proves the
// source prefix is acknowledged durably before a large presentation document
// is transferred, that the source transaction never serializes those bytes,
// and that the publication event stays bounded metadata work.
func TestLargePublicationTransferDoesNotDelaySourceAcknowledgement(t *testing.T) {
	f := newFixture(t, "publication-large-transfer")
	registration := sessionRegistration()
	marker := "LARGE-TRANSFER-MARKER-DO-NOT-EMBED"
	value := map[string]any{"marker": marker, "payload": strings.Repeat("x", 6<<20)}
	input := buildPublicationInput(t, registration, "journal-large", "owner-application", "application", 1, value, defaultSourceClock())

	var mu sync.Mutex
	var stages []string
	sourceDurableAtTransfer := false
	documentAbsentAtTransfer := false
	stageObserver = func(stage string, detail int) {
		mu.Lock()
		stages = append(stages, stage)
		mu.Unlock()
		if stage != "document_transfer" {
			return
		}
		// The source acknowledgement must already be durable here, while the
		// large document extent must not exist yet.
		policy, _, err := ensureImportPolicy(f.ctx, f.store, input.Manifest)
		if err != nil {
			t.Errorf("ensureImportPolicy during transfer: %v", err)
			return
		}
		refs, err := evidence_import.ImportSourcePrefix(f.ctx, f.store, input.Manifest, input.Prefix, input.Events, policy)
		if err != nil {
			t.Errorf("source prefix is not durable before transfer: %v", err)
			return
		}
		if _, err := owner_store.LoadPrefix(f.ctx, f.store, JournalPrefix{
			JournalID: refs[len(refs)-1].JournalID, LastSequence: refs[len(refs)-1].Sequence, HeadHash: refs[len(refs)-1].EventHash,
		}); err != nil {
			t.Errorf("LoadPrefix(source import): %v", err)
			return
		}
		sourceDurableAtTransfer = true
		documentDigest := string(evidence_codec.HashBytes(input.Document))
		if _, err := owner_store.ReadArtifact(f.ctx, f.store, ArtifactReference{Digest: documentDigest}); errors.Is(err, owner_store.ErrArtifactMissing) {
			documentAbsentAtTransfer = true
		}
	}
	t.Cleanup(func() { stageObserver = nil })

	receipt := f.publish(registration, input, "view-large")
	if !sourceDurableAtTransfer {
		t.Fatalf("source prefix was not durable before the document transfer")
	}
	if !documentAbsentAtTransfer {
		t.Fatalf("document extent already existed when the transfer was expected to begin")
	}
	mu.Lock()
	order := append([]string(nil), stages...)
	mu.Unlock()
	index := func(stage string) int {
		for i, candidate := range order {
			if candidate == stage {
				return i
			}
		}
		return -1
	}
	for _, required := range []string{"source_import_started", "source_imported", "document_transfer", "document_installed", "publication_committed"} {
		if index(required) < 0 {
			t.Fatalf("publication stage %q missing: %v", required, order)
		}
	}
	if index("source_imported") > index("document_transfer") {
		t.Fatalf("document transfer began before the source acknowledgement: %v", order)
	}
	if index("document_installed") > index("publication_committed") {
		t.Fatalf("pointer advanced before document installation: %v", order)
	}
	if receipt.Revision != 1 || receipt.Document.SizeBytes < int64(6<<20) {
		t.Fatalf("receipt revision/size = %d/%d, want 1 and at least 6 MiB", receipt.Revision, receipt.Document.SizeBytes)
	}

	// The source import journal and the publication event must remain bounded
	// metadata: a large peer domain is never reserialized inside a source or
	// publication transaction.
	policy, _, err := ensureImportPolicy(f.ctx, f.store, input.Manifest)
	if err != nil {
		t.Fatalf("ensureImportPolicy: %v", err)
	}
	refs, err := evidence_import.ImportSourcePrefix(f.ctx, f.store, input.Manifest, input.Prefix, input.Events, policy)
	if err != nil {
		t.Fatalf("re-import source prefix: %v", err)
	}
	for _, event := range loadJournalAt(t, f, refs[len(refs)-1]) {
		raw, err := json.Marshal(event)
		if err != nil {
			t.Fatalf("marshal import event: %v", err)
		}
		if len(raw) > 128<<10 {
			t.Fatalf("import event sequence %d is %d bytes: large peer bytes were serialized", event.Sequence, len(raw))
		}
		if bytes.Contains(raw, []byte(marker)) {
			t.Fatalf("import event sequence %d embeds the large peer payload", event.Sequence)
		}
	}
	publicationEvents := loadJournalAt(t, f, receipt.PublicationRef)
	last := publicationEvents[len(publicationEvents)-1]
	raw, err := json.Marshal(last)
	if err != nil {
		t.Fatalf("marshal publication event: %v", err)
	}
	if len(raw) > 128<<10 {
		t.Fatalf("publication event is %d bytes: the document body was reserialized in the transaction", len(raw))
	}
	if bytes.Contains(raw, []byte(marker)) {
		t.Fatalf("publication event embeds the document body")
	}
}

// TestPartialTransferLeavesPreviousCompleteViewVisible proves a partial
// (truncated) presentation transfer never advances the pointer: the previous
// complete revision stays visible and seals as one complete row.
func TestPartialTransferLeavesPreviousCompleteViewVisible(t *testing.T) {
	f := newFixture(t, "publication-partial-transfer")
	registration := sessionRegistration()
	view := "view-partial"

	first := buildPublicationInput(t, registration, "journal-partial-1", "owner-application", "application", 1,
		map[string]any{"marker": "app-v1"}, defaultSourceClock())
	f.publish(registration, first, view)

	second := buildPublicationInput(t, registration, "journal-partial-2", "owner-application", "application", 2,
		map[string]any{"marker": "app-v2"}, defaultSourceClock())
	partial := second.Document[:len(second.Document)/2]
	if _, err := InstallPublication(f.ctx, f.store, registration, partial, second.Manifest, second.Events, view); err == nil {
		t.Fatalf("partial document transfer was accepted")
	}

	row := f.seal(registration, "session_admitted", view)
	assertPublishedSlot(t, row, "application", 1, "app-v1")
	if row.Domains["observation"].Revision != 0 || row.Domains["diagnostic"].Revision != 0 {
		t.Fatalf("unpublished domains advanced: %+v", row.SealPoint.Versions)
	}
}

// TestCorruptPublicationBytesCannotAdvanceViewPointer proves corrupt bytes can
// never advance the view: the document checksum no longer matches the digest
// pinned by its source prefix, so the delivery is rejected before transfer.
func TestCorruptPublicationBytesCannotAdvanceViewPointer(t *testing.T) {
	f := newFixture(t, "publication-corrupt-bytes")
	registration := sessionRegistration()
	view := "view-corrupt"

	first := buildPublicationInput(t, registration, "journal-corrupt-1", "owner-application", "application", 1,
		map[string]any{"marker": "app-v1"}, defaultSourceClock())
	f.publish(registration, first, view)

	second := buildPublicationInput(t, registration, "journal-corrupt-2", "owner-application", "application", 2,
		map[string]any{"marker": "app-v2"}, defaultSourceClock())
	// Corrupt the bytes after the source named their digest: the document is
	// structurally valid but its checksum is no longer evidenced.
	var document map[string]any
	if err := decodeNumberJSON(second.Document, &document); err != nil {
		t.Fatalf("decode document: %v", err)
	}
	value, _ := document["value"].(map[string]any)
	value["marker"] = "app-v2-corrupted"
	corrupt, err := canonicalJSON(document)
	if err != nil {
		t.Fatalf("canonicalize corrupt document: %v", err)
	}
	if string(evidence_codec.HashBytes(corrupt)) == string(evidence_codec.HashBytes(second.Document)) {
		t.Fatalf("test failed to change the document digest")
	}

	_, err = InstallPublication(f.ctx, f.store, registration, corrupt, second.Manifest, second.Events, view)
	if err == nil {
		t.Fatalf("corrupt publication bytes were accepted")
	}
	if !errors.Is(err, ErrUnverifiedDocument) {
		t.Fatalf("corrupt publication error = %v, want ErrUnverifiedDocument", err)
	}

	row := f.seal(registration, "session_admitted", view)
	assertPublishedSlot(t, row, "application", 1, "app-v1")
}

// TestReorderedPublicationCannotRollCurrentPointerBackward proves reordered
// deliveries never roll the visible pointer backward and never replace an
// already published revision with different bytes.
func TestReorderedPublicationCannotRollCurrentPointerBackward(t *testing.T) {
	f := newFixture(t, "publication-reorder")
	registration := sessionRegistration()
	view := "view-reorder"

	first := buildPublicationInput(t, registration, "journal-reorder-1", "owner-application", "application", 1,
		map[string]any{"marker": "app-v1"}, defaultSourceClock())
	f.publish(registration, first, view)
	second := buildPublicationInput(t, registration, "journal-reorder-2", "owner-application", "application", 2,
		map[string]any{"marker": "app-v2"}, defaultSourceClock())
	f.publish(registration, second, view)
	receipt2 := f.publish(registration, second, view)
	third := buildPublicationInput(t, registration, "journal-reorder-3", "owner-application", "application", 3,
		map[string]any{"marker": "app-v3"}, defaultSourceClock())
	f.publish(registration, third, view)

	// A byte-identical reordered redelivery returns the original receipt and
	// never advances or rolls the pointer.
	replayed, err := InstallPublication(f.ctx, f.store, registration, second.Document, second.Manifest, second.Events, view)
	if err != nil {
		t.Fatalf("identical reordered redelivery: %v", err)
	}
	if replayed.ReceiptID != receipt2.ReceiptID || replayed.Revision != 2 ||
		replayed.Document.Digest != receipt2.Document.Digest {
		t.Fatalf("reordered redelivery returned %+v, want the original revision-2 receipt %s", replayed, receipt2.ReceiptID)
	}
	if replayed.PublicationRef.Sequence == 0 {
		t.Fatalf("reordered receipt lost its original publication reference")
	}

	// Different bytes under an already published revision are an integrity
	// conflict, never a rollback.
	conflicting := buildPublicationInput(t, registration, "journal-reorder-2b", "owner-application", "application", 2,
		map[string]any{"marker": "app-v2-conflict"}, defaultSourceClock())
	_, err = InstallPublication(f.ctx, f.store, registration, conflicting.Document, conflicting.Manifest, conflicting.Events, view)
	if err == nil {
		t.Fatalf("different bytes under revision 2 were accepted")
	}
	if !errors.Is(err, ErrIntegrityConflict) || !errors.Is(err, owner_store.ErrIntegrityConflict) {
		t.Fatalf("reordered conflict error = %v, want an integrity conflict", err)
	}

	row := f.seal(registration, "session_admitted", view)
	assertPublishedSlot(t, row, "application", 3, "app-v3")

	// The rejected delivery is a journaled incident, not a success receipt.
	found := false
	for _, event := range loadJournalAt(t, f, row.SealPoint.EvidenceRefs[0]) {
		if event.EventKind == eventPublicationRejected {
			found = true
			reason, _ := event.Payload.Data["reason"].(string)
			if reason != "integrity_conflict" && reason != "stale_reordered" {
				t.Fatalf("rejection reason = %q", reason)
			}
		}
	}
	if !found {
		t.Fatalf("rejected reordered delivery left no incident in the publication journal")
	}
}

// TestSameRevisionDifferentBytesRaisesIntegrityConflict proves the revision
// key names exactly one content digest: different bytes under the same key are
// an integrity conflict and the visible body is untouched.
func TestSameRevisionDifferentBytesRaisesIntegrityConflict(t *testing.T) {
	f := newFixture(t, "publication-conflict")
	registration := sessionRegistration()
	view := "view-conflict"

	first := buildPublicationInput(t, registration, "journal-conflict-1", "owner-application", "application", 1,
		map[string]any{"marker": "app-v1"}, defaultSourceClock())
	f.publish(registration, first, view)

	conflicting := buildPublicationInput(t, registration, "journal-conflict-2", "owner-application", "application", 1,
		map[string]any{"marker": "app-v1-other"}, defaultSourceClock())
	_, err := InstallPublication(f.ctx, f.store, registration, conflicting.Document, conflicting.Manifest, conflicting.Events, view)
	if err == nil {
		t.Fatalf("different bytes under revision 1 were accepted")
	}
	if !errors.Is(err, ErrIntegrityConflict) || !errors.Is(err, owner_store.ErrIntegrityConflict) {
		t.Fatalf("conflict error = %v, want an integrity conflict", err)
	}

	row := f.seal(registration, "session_admitted", view)
	assertPublishedSlot(t, row, "application", 1, "app-v1")
}

// TestSameRevisionSameBytesReturnsExistingReceipt proves an identical retry is
// idempotent: it returns the stored receipt and appends no second publication.
func TestSameRevisionSameBytesReturnsExistingReceipt(t *testing.T) {
	f := newFixture(t, "publication-idempotent")
	registration := sessionRegistration()
	view := "view-idempotent"

	input := buildPublicationInput(t, registration, "journal-idempotent", "owner-application", "application", 1,
		map[string]any{"marker": "app-v1"}, defaultSourceClock())
	first := f.publish(registration, input, view)
	second := f.publish(registration, input, view)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("identical retry returned a different receipt:\nfirst:  %+v\nsecond: %+v", first, second)
	}
	if first.PublicationRef.JournalID == "" || first.PublicationRef.Sequence == 0 {
		t.Fatalf("receipt carries no publication reference: %+v", first.PublicationRef)
	}

	events := loadJournalAt(t, f, first.PublicationRef)
	published := 0
	for _, event := range events {
		if event.EventKind == eventDomainPublished {
			published++
		}
	}
	if published != 1 {
		t.Fatalf("journal holds %d domain_published events, want 1", published)
	}
}

// TestSealRaceSelectsOneCompleteExactVersionVector proves concurrent seals can
// only select one exact complete vector: every returned row's slots, snapshots,
// publication references, and seal vector agree, even while a newer revision
// is being published.
func TestSealRaceSelectsOneCompleteExactVersionVector(t *testing.T) {
	f := newFixture(t, "publication-seal-race")
	registration := sessionRegistration()
	view := "view-seal-race"

	first := buildPublicationInput(t, registration, "journal-race-app-1", "owner-application", "application", 1,
		map[string]any{"marker": "app-v1"}, defaultSourceClock())
	f.publish(registration, first, view)
	diagnostic := buildPublicationInput(t, registration, "journal-race-diag-1", "owner-diagnostic", "diagnostic", 1,
		map[string]any{"marker": "diag-v1"}, defaultSourceClock())
	f.publish(registration, diagnostic, view)
	second := buildPublicationInput(t, registration, "journal-race-app-2", "owner-application", "application", 2,
		map[string]any{"marker": "app-v2"}, defaultSourceClock())

	const sealers = 8
	start := make(chan struct{})
	rows := make([]LogicalRow, sealers)
	errs := make([]error, sealers)
	var wait sync.WaitGroup
	for i := range sealers {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			rows[index], errs[index] = SealRow(f.ctx, f.store, registration, "session_admitted", view)
		}(i)
	}
	var publishErr error
	wait.Add(1)
	go func() {
		defer wait.Done()
		<-start
		_, publishErr = InstallPublication(f.ctx, f.store, registration, second.Document,
			second.Manifest, second.Events, view)
	}()
	close(start)
	wait.Wait()
	if publishErr != nil {
		t.Fatalf("concurrent publication: %v", publishErr)
	}

	expected := map[string]map[int64]string{
		"application": {1: "app-v1", 2: "app-v2"},
		"diagnostic":  {1: "diag-v1"},
	}
	for index, row := range rows {
		if errs[index] != nil {
			t.Fatalf("seal %d: %v", index, errs[index])
		}
		if len(row.Domains) != 3 {
			t.Fatalf("seal %d row carries %d domains, want 3", index, len(row.Domains))
		}
		if len(row.SealPoint.Versions) != 3 {
			t.Fatalf("seal %d vector carries %d domains, want 3", index, len(row.SealPoint.Versions))
		}
		for domain, slot := range row.Domains {
			if row.SealPoint.Versions[domain] != slot.Revision {
				t.Fatalf("seal %d vector for %q = %d, slot = %d",
					index, domain, row.SealPoint.Versions[domain], slot.Revision)
			}
			if slot.Revision == 0 {
				if slot.Document != nil || slot.PublicationRef != nil || len(slot.Snapshot) != 0 {
					t.Fatalf("seal %d unpublished slot %q carries published identities", index, domain)
				}
				continue
			}
			wantMarker, ok := expected[domain][slot.Revision]
			if !ok {
				t.Fatalf("seal %d selected unexpected %q revision %d", index, domain, slot.Revision)
			}
			if snapshotRevision(t, slot.Snapshot) != slot.Revision {
				t.Fatalf("seal %d snapshot revision for %q disagrees with the slot", index, domain)
			}
			if got := snapshotString(t, slot.Snapshot, "marker"); got != wantMarker {
				t.Fatalf("seal %d mixed slot body for %q: marker %q, want %q", index, domain, got, wantMarker)
			}
			if slot.PublicationRef.Sequence > row.SealPoint.InputPrefix.LastSequence {
				t.Fatalf("seal %d cites publication sequence %d beyond its input prefix %d",
					index, slot.PublicationRef.Sequence, row.SealPoint.InputPrefix.LastSequence)
			}
		}
	}
}

// TestCrashBeforePublicationLeavesDurableSourceAndStaleView proves a crash
// after the durable source acknowledgement but before the artifact
// installation leaves the source durable, installs no acknowledged reference,
// and leaves the previous complete view visible.
func TestCrashBeforePublicationLeavesDurableSourceAndStaleView(t *testing.T) {
	f := newFixture(t, "publication-crash")
	registration := sessionRegistration()
	view := "view-crash"

	first := buildPublicationInput(t, registration, "journal-crash-1", "owner-application", "application", 1,
		map[string]any{"marker": "app-v1"}, defaultSourceClock())
	f.publish(registration, first, view)

	second := buildPublicationInput(t, registration, "journal-crash-2", "owner-application", "application", 2,
		map[string]any{"marker": "app-v2"}, defaultSourceClock())
	transferGate = func() error { return errors.New("injected crash before artifact installation") }
	t.Cleanup(func() { transferGate = nil })

	_, err := InstallPublication(f.ctx, f.store, registration, second.Document, second.Manifest, second.Events, view)
	if err == nil {
		t.Fatalf("injected crash was ignored")
	}
	transferGate = nil

	// The source acknowledgement is durable...
	policy, _, err := ensureImportPolicy(f.ctx, f.store, second.Manifest)
	if err != nil {
		t.Fatalf("ensureImportPolicy: %v", err)
	}
	refs, err := evidence_import.ImportSourcePrefix(f.ctx, f.store, second.Manifest, second.Prefix, second.Events, policy)
	if err != nil {
		t.Fatalf("source prefix is not durable after the crash: %v", err)
	}
	imported := loadJournalAt(t, f, refs[len(refs)-1])
	if len(imported) != len(second.Events)+1 {
		t.Fatalf("source import journal holds %d events, want %d", len(imported), len(second.Events)+1)
	}
	// ...but the document extent was never installed, so no reference was
	// acknowledged.
	documentDigest := string(evidence_codec.HashBytes(second.Document))
	if _, err := owner_store.ReadArtifact(f.ctx, f.store, ArtifactReference{Digest: documentDigest}); !errors.Is(err, owner_store.ErrArtifactMissing) {
		t.Fatalf("document extent after injected crash: err = %v, want ErrArtifactMissing", err)
	}

	row := f.seal(registration, "session_admitted", view)
	assertPublishedSlot(t, row, "application", 1, "app-v1")
}

// TestArchiveExpansionReconstructsCompleteRowWithoutMutablePeer proves
// expansion reproduces the exact complete archived LogicalRow from immutable
// local extents only, even after the current view moved on and even in a
// store that never saw the publication journal or the source journals.
func TestArchiveExpansionReconstructsCompleteRowWithoutMutablePeer(t *testing.T) {
	f := newFixture(t, "publication-archive")
	registration := sessionRegistration()
	view := "view-archive"

	app := buildPublicationInput(t, registration, "journal-archive-app", "owner-application", "application", 1,
		map[string]any{"marker": "app-v1"}, defaultSourceClock())
	f.publish(registration, app, view)
	diagnostic := buildPublicationInput(t, registration, "journal-archive-diag", "owner-diagnostic", "diagnostic", 1,
		map[string]any{"marker": "diag-v1"}, defaultSourceClock())
	f.publish(registration, diagnostic, view)
	row := f.seal(registration, "diagnostic_published", view)

	registrationRef := f.installRegistration(registration)
	manifest := archiveManifestFor(t, row, registrationRef)
	record, err := ExpandArchive(f.ctx, f.store, manifest)
	if err != nil {
		t.Fatalf("ExpandArchive: %v", err)
	}
	if !reflect.DeepEqual(record.PayloadJSON, row) {
		t.Fatalf("expanded row differs from the archived row:\nexpanded: %+v\narchived: %+v", record.PayloadJSON, row)
	}
	canonical, err := canonicalJSON(manifest)
	if err != nil {
		t.Fatalf("canonicalize archive manifest: %v", err)
	}
	if record.Root.Digest != string(evidence_codec.HashBytes(canonical)) || record.Root.SizeBytes != int64(len(canonical)) {
		t.Fatalf("archive root %+v does not hash the canonical storage manifest (%d bytes)", record.Root, len(canonical))
	}
	if record.Root.Digest == string(evidence_codec.HashBytes(rowSnapshotBytes(t, row))) {
		t.Fatalf("archive root hashes the expanded wrapper instead of the storage manifest")
	}

	// Advancing the current view must not change the archived row.
	later := buildPublicationInput(t, registration, "journal-archive-app-2", "owner-application", "application", 2,
		map[string]any{"marker": "app-v2"}, defaultSourceClock())
	f.publish(registration, later, view)
	current := f.seal(registration, "diagnostic_published", view)
	assertPublishedSlot(t, current, "application", 2, "app-v2")
	archived, err := ExpandArchive(f.ctx, f.store, manifest)
	if err != nil {
		t.Fatalf("ExpandArchive after the view advanced: %v", err)
	}
	if !reflect.DeepEqual(archived.PayloadJSON, row) {
		t.Fatalf("archive expansion followed the mutable current view instead of the pinned extents")
	}

	// A store that never saw the publication journal or source journals can
	// still expand the archive from the immutable extents alone.
	copyFixture := newFixture(t, "publication-archive-copy")
	registrationRefCopy, err := installCanonicalJSON(copyFixture.ctx, copyFixture.store, registration)
	if err != nil {
		t.Fatalf("install copied registration: %v", err)
	}
	copied := archiveManifestFor(t, row, registrationRefCopy)
	for domain, slot := range row.Domains {
		if slot.Revision == 0 {
			continue
		}
		ref, err := owner_store.InstallArtifact(copyFixture.ctx, copyFixture.store,
			bytes.NewReader(slot.Snapshot), mediaTypeJSON, accessPublic)
		if err != nil {
			t.Fatalf("install copied document %q: %v", domain, err)
		}
		copiedSlot := copied.Domains[domain]
		copiedSlot.Document = &ref
		copied.Domains[domain] = copiedSlot
	}
	isolated, err := ExpandArchive(copyFixture.ctx, copyFixture.store, copied)
	if err != nil {
		t.Fatalf("ExpandArchive without the mutable peer: %v", err)
	}
	if !reflect.DeepEqual(isolated.PayloadJSON.Registration, row.Registration) {
		t.Fatalf("isolated expansion did not reproduce the complete registration")
	}
	if !reflect.DeepEqual(isolated.PayloadJSON.SealPoint, row.SealPoint) {
		t.Fatalf("isolated expansion did not reproduce the exact seal vector")
	}
	for domain, slot := range row.Domains {
		isolatedSlot := isolated.PayloadJSON.Domains[domain]
		if isolatedSlot.Revision != slot.Revision {
			t.Fatalf("isolated expansion revision for %q = %d, want %d", domain, isolatedSlot.Revision, slot.Revision)
		}
		if slot.Revision == 0 {
			continue
		}
		if !bytes.Equal(isolatedSlot.Snapshot, slot.Snapshot) {
			t.Fatalf("isolated expansion snapshot for %q differs", domain)
		}
		if isolatedSlot.Document.Digest != slot.Document.Digest ||
			isolatedSlot.Document.SizeBytes != slot.Document.SizeBytes {
			t.Fatalf("isolated expansion document identity for %q differs", domain)
		}
		if !reflect.DeepEqual(*isolatedSlot.PublicationRef, *slot.PublicationRef) {
			t.Fatalf("isolated expansion publication reference for %q differs", domain)
		}
	}
}

func rowSnapshotBytes(t *testing.T, row LogicalRow) []byte {
	t.Helper()
	raw, err := json.Marshal(row)
	if err != nil {
		t.Fatalf("marshal row: %v", err)
	}
	return raw
}

func archiveManifestFor(t *testing.T, row LogicalRow, registrationRef ArtifactReference) ArchiveStorageManifest {
	t.Helper()
	domains := make(map[string]ArchiveDomainSlot, len(row.Domains))
	for domain, slot := range row.Domains {
		if slot.Revision == 0 {
			domains[domain] = ArchiveDomainSlot{Revision: 0, Value: slot.Value}
			continue
		}
		document := *slot.Document
		publicationRef := *slot.PublicationRef
		domains[domain] = ArchiveDomainSlot{
			Revision:       slot.Revision,
			Document:       &document,
			PublicationRef: &publicationRef,
		}
	}
	return ArchiveStorageManifest{
		Encoding:      archiveEncoding,
		SchemaVersion: schemaVersion,
		Entity:        row.Entity,
		Registration:  registrationRef,
		Domains:       domains,
		SealPoint:     row.SealPoint,
	}
}

// TestLostPublishedBytesRemainKnownLossNotRevisionZero proves a published slot
// whose exact bytes were lost is reported as known observation loss, never
// silently replaced by an unpublished revision-zero slot.
func TestLostPublishedBytesRemainKnownLossNotRevisionZero(t *testing.T) {
	f := newFixture(t, "publication-lost-bytes")
	registration := sessionRegistration()
	view := "view-lost-bytes"

	input := buildPublicationInput(t, registration, "journal-lost-bytes", "owner-application", "application", 1,
		map[string]any{"marker": "app-v1"}, defaultSourceClock())
	receipt := f.publish(registration, input, view)
	row := f.seal(registration, "session_admitted", view)

	hexDigest := strings.TrimPrefix(receipt.Document.Digest, "sha256:")
	objectPath := filepath.Join(f.artifactRoot, "objects", hexDigest[:2], hexDigest)
	if err := os.Remove(objectPath); err != nil {
		t.Fatalf("remove published extent: %v", err)
	}

	lost, err := SealRow(f.ctx, f.store, registration, "session_admitted", view)
	if err == nil {
		t.Fatalf("seal succeeded after the published bytes were lost: %+v", lost)
	}
	if !errors.Is(err, ErrLostPublishedBytes) {
		t.Fatalf("lost-byte seal error = %v, want ErrLostPublishedBytes", err)
	}
	if !errors.Is(err, owner_store.ErrArtifactLost) {
		t.Fatalf("lost-byte seal error = %v, want owner_store.ErrArtifactLost", err)
	}
	if lost.SealPoint.SealID != "" || len(lost.Domains) != 0 {
		t.Fatalf("lost published bytes were replaced by a fabricated row: %+v", lost)
	}

	manifest := archiveManifestFor(t, row, f.installRegistration(registration))
	if _, err := ExpandArchive(f.ctx, f.store, manifest); err == nil {
		t.Fatalf("archive expansion hid the lost published bytes")
	} else if !errors.Is(err, ErrLostPublishedBytes) || !errors.Is(err, owner_store.ErrArtifactLost) {
		t.Fatalf("lost-byte expansion error = %v, want known loss", err)
	}

	// The receipt still names the lost revision and digest: the loss is an
	// observation about a known publication, not revision zero.
	if receipt.Revision != 1 || receipt.Document.Digest != string(evidence_codec.HashBytes(input.Document)) {
		t.Fatalf("receipt no longer names the lost publication: %+v", receipt)
	}
}

// TestPublicationLagWithoutComparableClocksRemainsUnavailable proves the
// publication-delay measurement is unavailable with a reasoned value when the
// source and destination receipts sit on different clock lifetimes, and that
// arbitrary UTC annotations are never subtracted.
func TestPublicationLagWithoutComparableClocksRemainsUnavailable(t *testing.T) {
	f := newFixture(t, "publication-lag")
	registration := sessionRegistration()
	view := "view-lag"

	// Build the source manually so the destination has a wildly different UTC
	// annotation on an otherwise numeric offset.
	journal := newSourceJournal(t, "journal-lag", "owner-application", defaultSourceClock())
	inputPrefix := journal.prefixAt(1)
	document := buildOwnedDocument(t, registration, "application", 1, 0,
		inputPrefix, []EvidenceRef{journal.ref(1)}, map[string]any{"marker": "app-v1"})
	tail := journal.append("source_domain_proposed", map[string]any{
		"domain":          "application",
		"revision":        1,
		"document_digest": string(evidence_codec.HashBytes(document)),
	})
	tail.RecordedAt = journal_rules.TimePoint{
		ClockID: "src-clock", BootID: "src-boot", Origin: "engine_measured",
		MonotonicOffsetMs: 1010,
		UTCAnnotation:     "2099-12-31T23:59:59Z",
	}
	finalizeEnvelope(t, tail)

	receipt, err := InstallPublication(f.ctx, f.store, registration, document, journal.manifest, journal.events, view)
	if err != nil {
		t.Fatalf("InstallPublication: %v", err)
	}
	if !reflect.DeepEqual(receipt.SourcePrefix, journal.prefix()) {
		t.Fatalf("receipt source prefix = %+v, want %+v", receipt.SourcePrefix, journal.prefix())
	}
	delay := receipt.PublicationDelay
	if delay.Measurement.Method != "unavailable" {
		t.Fatalf("delay method = %q, want unavailable", delay.Measurement.Method)
	}
	if delay.Measurement.Estimate.Kind != "unavailable" {
		t.Fatalf("delay estimate kind = %q, want unavailable", delay.Measurement.Estimate.Kind)
	}
	missing, ok := delay.Measurement.Estimate.Value.(journal_rules.MissingEnvelope)
	if !ok || strings.TrimSpace(missing.Reason) == "" {
		t.Fatalf("unavailable delay estimate does not carry a reasoned Missing value: %#v", delay.Measurement.Estimate.Value)
	}
	if delay.Measurement.Censoring != "unavailable" {
		t.Fatalf("delay censoring = %q, want unavailable", delay.Measurement.Censoring)
	}
	if len(delay.EvidenceRefs) != 1 || delay.EvidenceRefs[0] != receipt.PublicationRef {
		t.Fatalf("delay support = %+v, want the publication reference", delay.EvidenceRefs)
	}
	start, ok := timePointFromAny(delay.Measurement.Start)
	if !ok {
		t.Fatalf("delay start is not a TimePoint: %#v", delay.Measurement.Start)
	}
	end, ok := timePointFromAny(delay.Measurement.End)
	if !ok {
		t.Fatalf("delay end is not a TimePoint: %#v", delay.Measurement.End)
	}
	if start.ClockID == end.ClockID && start.BootID == end.BootID {
		t.Fatalf("test did not exercise incomparable clock lifetimes: %+v / %+v", start, end)
	}
	if start.UTCAnnotation != "2099-12-31T23:59:59Z" {
		t.Fatalf("delay start lost the source UTC annotation: %#v", start.UTCAnnotation)
	}
	if _, isMissing := delay.Measurement.Estimate.Value.(journal_rules.MissingEnvelope); !isMissing {
		t.Fatalf("incomparable clocks produced a numeric estimate: %#v", delay.Measurement.Estimate.Value)
	}
}

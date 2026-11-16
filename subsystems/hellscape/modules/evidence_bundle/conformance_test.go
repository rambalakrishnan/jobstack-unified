package evidence_bundle

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	authority "authority"
	evidence_codec "evidence_codec"
	journal_rules "journal_rules"
	owner_store "owner_store"
	publication "publication"
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
	request, err := http.NewRequest(http.MethodPost, "http://evidence-bundle.test/"+domain, nil)
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

func testManifest(domain, journalID string) journal_rules.Manifest {
	return journal_rules.Manifest{
		RecordType:    "manifest",
		SchemaVersion: "0.1.0",
		ManifestID:    "manifest-" + journalID,
		RunID:         "run-" + journalID,
		JournalID:     journalID,
		OwnerDomain:   domain,
		Clocks: []journal_rules.ClockDescriptor{{
			ClockID: "clock-" + journalID, BootID: "boot-" + journalID,
			Origin: "engine_measured", SourceID: "evidence-bundle",
			Basis: "monotonic_offset", Unit: "ms",
		}},
	}
}

func testTimePoint(m journal_rules.Manifest, offset float64) journal_rules.TimePoint {
	clock := m.Clocks[0]
	return journal_rules.TimePoint{
		ClockID: clock.ClockID, BootID: clock.BootID, Origin: clock.Origin,
		MonotonicOffsetMs: offset, UTCAnnotation: journal_rules.NewMissing("not_applicable"),
	}
}

func canonicalBytes(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	canonical, err := evidence_codec.CanonicalJSON(raw, "application/json")
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	return canonical
}

func installArtifact(t *testing.T, ctx context.Context, store *owner_store.OwnerStore, content []byte, mediaType, access string) journal_rules.ArtifactReference {
	t.Helper()
	ref, err := owner_store.InstallArtifact(ctx, store, bytes.NewReader(content), mediaType, access)
	if err != nil {
		t.Fatalf("InstallArtifact: %v", err)
	}
	return ref
}

func artifactRefMap(ref journal_rules.ArtifactReference) map[string]any {
	return map[string]any{
		"digest":       ref.Digest,
		"size_bytes":   ref.SizeBytes,
		"media_type":   ref.MediaType,
		"owner_domain": ref.OwnerDomain,
		"access":       ref.Access,
	}
}

func admitJournal(t *testing.T, ctx context.Context, store *owner_store.OwnerStore, m journal_rules.Manifest) []journal_rules.JournalEnvelope {
	t.Helper()
	manifestBytes := canonicalBytes(t, m)
	ref := installArtifact(t, ctx, store, manifestBytes, "application/json", "public")
	submission := owner_store.EventSubmission{
		ProducerSequence:   int64(1),
		EventKind:          "manifest_admitted",
		EventSchemaVersion: "0.1.0",
		OccurredAt:         testTimePoint(m, 0),
		Payload: journal_rules.Payload{
			Data:         map[string]any{"manifest": artifactRefMap(ref)},
			Measurements: []journal_rules.Measurement{},
			EvidenceRefs: []journal_rules.EvidenceRef{},
			ArtifactRefs: []journal_rules.ArtifactReference{ref},
		},
	}
	envelopes, err := owner_store.CommitOwner(ctx, store, m.JournalID, []owner_store.EventSubmission{submission}, nil)
	if err != nil {
		t.Fatalf("admit journal: %v", err)
	}
	return envelopes
}

func commitEvents(t *testing.T, ctx context.Context, store *owner_store.OwnerStore, journalID string, submissions []owner_store.EventSubmission) []journal_rules.JournalEnvelope {
	t.Helper()
	envelopes, err := owner_store.CommitOwner(ctx, store, journalID, submissions, nil)
	if err != nil {
		t.Fatalf("CommitOwner: %v", err)
	}
	return envelopes
}

func eventSubmission(m journal_rules.Manifest, sequence int64, kind string, data map[string]any, refs []journal_rules.ArtifactReference) owner_store.EventSubmission {
	if data == nil {
		data = map[string]any{}
	}
	if refs == nil {
		refs = []journal_rules.ArtifactReference{}
	}
	return owner_store.EventSubmission{
		ProducerSequence:   sequence,
		EventKind:          kind,
		EventSchemaVersion: "0.1.0",
		OccurredAt:         testTimePoint(m, float64(sequence)),
		Payload: journal_rules.Payload{
			Data:         data,
			Measurements: []journal_rules.Measurement{},
			EvidenceRefs: []journal_rules.EvidenceRef{},
			ArtifactRefs: refs,
		},
	}
}

func prefixThrough(events []journal_rules.JournalEnvelope) journal_rules.JournalPrefix {
	last := events[len(events)-1]
	return journal_rules.JournalPrefix{JournalID: last.JournalID, LastSequence: last.Sequence, HeadHash: last.EventHash}
}

func eventRef(event journal_rules.JournalEnvelope) journal_rules.EvidenceRef {
	return journal_rules.EvidenceRef{
		JournalID: event.JournalID,
		Sequence:  event.Sequence,
		EventID:   event.EventID,
		EventHash: event.EventHash,
		Pointer:   "",
	}
}

// ---------------------------------------------------------------------------
// Registration and row fixtures (adapted from publication corpus).
// ---------------------------------------------------------------------------

const owdSchemaVersion = "owner-separated-write-domains/0.1.0"

func registrationSupport() (journal_rules.JournalPrefix, []journal_rules.EvidenceRef) {
	support := string(evidence_codec.HashBytes([]byte("registration-support")))
	return journal_rules.JournalPrefix{JournalID: "registration-journal", LastSequence: 1, HeadHash: support},
		[]journal_rules.EvidenceRef{{
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

func sessionRegistration(sessionID string) publication.EntityRegistration {
	prefix, refs := registrationSupport()
	return publication.EntityRegistration{
		RecordType:     "write_domain_entity",
		SchemaVersion:  owdSchemaVersion,
		RegistrationID: "reg-" + sessionID,
		Entity: map[string]any{
			"entity_type": "hellscape_session",
			"session_id":  sessionID,
		},
		Identity: map[string]any{
			"run_id":     "run-" + sessionID,
			"journal_id": "journal-" + sessionID,
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

func registrationDigestOf(t *testing.T, registration publication.EntityRegistration) string {
	t.Helper()
	raw, err := json.Marshal(registration)
	if err != nil {
		t.Fatalf("marshal registration: %v", err)
	}
	canonical, err := evidence_codec.CanonicalJSON(raw, "application/json")
	if err != nil {
		t.Fatalf("canonicalize registration: %v", err)
	}
	return string(evidence_codec.HashBytes(canonical))
}

func registeredWriterFor(t *testing.T, registration publication.EntityRegistration, domain string) (string, string) {
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
	return ownerDomain, writerID
}

func buildOwnedDocument(t *testing.T, registration publication.EntityRegistration, domain string, revision int64, inputPrefix journal_rules.JournalPrefix, evidence []journal_rules.EvidenceRef, value map[string]any) []byte {
	t.Helper()
	ownerDomain, writerID := registeredWriterFor(t, registration, domain)
	evidenceMaps := make([]any, len(evidence))
	for i, ref := range evidence {
		evidenceMaps[i] = map[string]any{
			"journal_id": ref.JournalID,
			"sequence":   ref.Sequence,
			"event_id":   ref.EventID,
			"event_hash": ref.EventHash,
			"pointer":    ref.Pointer,
		}
	}
	document := map[string]any{
		"record_type":         "owned_domain_revision",
		"schema_version":      owdSchemaVersion,
		"entity":              registration.Entity,
		"registration_digest": registrationDigestOf(t, registration),
		"domain":              domain,
		"owner_domain":        ownerDomain,
		"writer_id":           writerID,
		"revision":            revision,
		"previous_revision":   revision - 1,
		"evidence_prefix": map[string]any{
			"journal_id":    inputPrefix.JournalID,
			"last_sequence": inputPrefix.LastSequence,
			"head_hash":     inputPrefix.HeadHash,
		},
		"evidence_refs": evidenceMaps,
		"value":         value,
	}
	return canonicalBytes(t, document)
}

// buildTestRow constructs a valid LogicalRow with the application domain
// published at revision 1 and the remaining domains unpublished. The seal
// points at the supplied diagnostic prefix so the row and diagnostic share
// one verifiable journal.
func buildTestRow(t *testing.T, ctx context.Context, store *owner_store.OwnerStore, registration publication.EntityRegistration, prefix journal_rules.JournalPrefix, events []journal_rules.JournalEnvelope, docAccess string) publication.LogicalRow {
	t.Helper()
	lastRef := eventRef(events[len(events)-1])
	docBytes := buildOwnedDocument(t, registration, "application", 1, prefix, []journal_rules.EvidenceRef{lastRef}, map[string]any{"marker": "app-v1"})
	docRef := installArtifact(t, ctx, store, docBytes, "application/json", docAccess)
	applicationRef := docRef
	publicationRef := lastRef
	row := publication.LogicalRow{
		RecordType:         "logical_row",
		SchemaVersion:      owdSchemaVersion,
		Entity:             registration.Entity,
		RegistrationDigest: registrationDigestOf(t, registration),
		Registration:       registration,
		Domains: map[string]publication.DomainSlot{
			"application": {
				Revision:       1,
				Document:       &applicationRef,
				PublicationRef: &publicationRef,
				Snapshot:       append(json.RawMessage(nil), docBytes...),
			},
			"observation": {Revision: 0, Value: journal_rules.NewMissing("not_observed")},
			"diagnostic":  {Revision: 0, Value: journal_rules.NewMissing("not_observed")},
		},
		SealPoint: publication.SealPoint{
			SealID:   "seal-1",
			Name:     "session_admitted",
			ViewID:   "view-1",
			Versions: map[string]int64{"application": 1, "observation": 0, "diagnostic": 0},
			SealedAt: journal_rules.TimePoint{
				ClockID: "clock-seal", BootID: "boot-seal", Origin: "engine_measured",
				MonotonicOffsetMs: 1, UTCAnnotation: journal_rules.NewMissing("not_applicable"),
			},
			InputPrefix:  prefix,
			EvidenceRefs: []journal_rules.EvidenceRef{lastRef},
		},
	}
	return row
}

func buildDiagnostic(t *testing.T, m journal_rules.Manifest, prefix journal_rules.JournalPrefix, events []journal_rules.JournalEnvelope, classifier, registry journal_rules.ArtifactReference, extraArtifacts []journal_rules.ArtifactReference, extra map[string]any) DiagnosticDocument {
	t.Helper()
	manifestDigest := string(evidence_codec.HashBytes(canonicalBytes(t, m)))
	lastRef := eventRef(events[len(events)-1])
	artifacts := []journal_rules.ArtifactReference{classifier, registry}
	artifacts = append(artifacts, extraArtifacts...)
	return DiagnosticDocument{
		RecordType:       "diagnostic",
		SchemaVersion:    "1.0.0",
		DiagnosticID:     "diag-" + m.JournalID,
		AnalysisRevision: 1,
		RunID:            m.RunID,
		ManifestHash:     manifestDigest,
		InputPrefix:      prefix,
		AnalysisRequestRef: lastRef,
		Classifier: VersionPin{
			ID: "classifier", Version: "v1", ArtifactDigest: classifier.Digest,
		},
		RequirementRegistry: VersionPin{
			ID: "requirements", Version: "v1", ArtifactDigest: registry.Digest,
		},
		FixRegistry:  journal_rules.NewMissing("not_enabled"),
		EvidenceRefs: []journal_rules.EvidenceRef{lastRef},
		Artifacts:    artifacts,
		Extra:        extra,
	}
}

func buildReceipt(t *testing.T, diagnostic DiagnosticDocument, manifestDigest string, inputBundle, sourceDiagnostic, engine journal_rules.ArtifactReference, reducer any, mode string) ReplayReceipt {
	t.Helper()
	semantic := string(evidence_codec.HashBytes([]byte("semantic-events-" + diagnostic.DiagnosticID)))
	state := string(evidence_codec.HashBytes([]byte("final-state-" + diagnostic.DiagnosticID)))
	diag := string(evidence_codec.HashBytes([]byte("diagnostic-" + diagnostic.DiagnosticID)))
	var comparisons []ReplayComparison
	if mode == "exact_fixture" {
		comparisons = []ReplayComparison{
			{Output: "semantic_events", ExpectedDigest: semantic, ActualDigest: semantic, Result: "matched"},
			{Output: "final_state", ExpectedDigest: state, ActualDigest: state, Result: "matched"},
			{Output: "diagnostic", ExpectedDigest: diag, ActualDigest: diag, Result: "matched"},
		}
	} else {
		comparisons = []ReplayComparison{
			{Output: "diagnostic", ExpectedDigest: diag, ActualDigest: diag, Result: "matched"},
		}
	}
	return ReplayReceipt{
		RecordType:   "replay_receipt",
		SchemaVersion: "1.0.0",
		ReplayID:     "replay-" + diagnostic.DiagnosticID,
		Mode:         mode,
		RunID:        diagnostic.RunID,
		ManifestHash: manifestDigest,
		SourcePrefix: diagnostic.InputPrefix,
		SourceDiagnostic: sourceDiagnostic,
		InputBundle:    inputBundle,
		Classifier:     diagnostic.Classifier,
		Reducer:        reducer,
		ReplayEngine: VersionPin{
			ID: "replay-engine", Version: "v1", ArtifactDigest: engine.Digest,
		},
		Comparisons:           comparisons,
		Result:                "matched",
		Limitations:           []string{},
		InvokedBrowser:        false,
		InvokedSubject:        false,
		PerformedExternalWrites: false,
	}
}

func readBundle(t *testing.T, ctx context.Context, store *owner_store.OwnerStore, ref journal_rules.ArtifactReference) (BundleDocument, []byte) {
	t.Helper()
	raw, err := owner_store.ReadArtifact(ctx, store, ref)
	if err != nil {
		t.Fatalf("ReadArtifact(bundle): %v", err)
	}
	var doc BundleDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode bundle: %v", err)
	}
	return doc, raw
}

func entryByName(doc BundleDocument, name string) (BundleEntry, bool) {
	for _, entry := range doc.Entries {
		if entry.Name == name {
			return entry, true
		}
	}
	return BundleEntry{}, false
}

// ---------------------------------------------------------------------------
// Shared scenario: one journal with transitive dependencies.
// ---------------------------------------------------------------------------

type scenario struct {
	manifest     journal_rules.Manifest
	events       []journal_rules.JournalEnvelope
	prefix       journal_rules.JournalPrefix
	configRef    journal_rules.ArtifactReference
	taskRef      journal_rules.ArtifactReference
	classifierRef journal_rules.ArtifactReference
	registryRef  journal_rules.ArtifactReference
	importRef    journal_rules.ArtifactReference
	diagnostic   DiagnosticDocument
	row          publication.LogicalRow
}

func newScenario(t *testing.T, f *fixture, journalID, sessionID string) *scenario {
	t.Helper()
	m := testManifest(f.domain, journalID)
	admission := admitJournal(t, f.ctx, f.store, m)

	configRef := installArtifact(t, f.ctx, f.store, []byte(`{"fixture":"config"}`), "application/json", "public")
	taskRef := installArtifact(t, f.ctx, f.store, []byte(`{"task":"synthetic"}`), "application/json", "public")
	classifierRef := installArtifact(t, f.ctx, f.store, []byte(`{"classifier":"v1"}`), "application/json", "public")
	registryRef := installArtifact(t, f.ctx, f.store, []byte(`{"requirements":"v1"}`), "application/json", "public")
	importRef := installArtifact(t, f.ctx, f.store, []byte(`{"import":"verification"}`), "application/json", "public")

	configured := eventSubmission(m, 2, "fixture_configured", map[string]any{
		"configuration": artifactRefMap(configRef),
		"task":          artifactRefMap(taskRef),
	}, []journal_rules.ArtifactReference{configRef, taskRef})
	requested := eventSubmission(m, 3, "analysis_requested", map[string]any{
		"classifier": artifactRefMap(classifierRef),
		"registry":   artifactRefMap(registryRef),
		"import_verification": artifactRefMap(importRef),
	}, []journal_rules.ArtifactReference{classifierRef, registryRef, importRef})

	later := commitEvents(t, f.ctx, f.store, m.JournalID, []owner_store.EventSubmission{configured, requested})
	events := append(append([]journal_rules.JournalEnvelope{}, admission...), later...)
	prefix := prefixThrough(events)

	diagnostic := buildDiagnostic(t, m, prefix, events, classifierRef, registryRef,
		[]journal_rules.ArtifactReference{configRef, taskRef, importRef},
		map[string]any{"import_evidence": artifactRefMap(importRef)})
	registration := sessionRegistration(sessionID)
	row := buildTestRow(t, f.ctx, f.store, registration, prefix, events, "public")
	return &scenario{
		manifest: m, events: events, prefix: prefix,
		configRef: configRef, taskRef: taskRef,
		classifierRef: classifierRef, registryRef: registryRef, importRef: importRef,
		diagnostic: diagnostic, row: row,
	}
}

// ---------------------------------------------------------------------------
// 1. Export includes every transitive replay dependency.
// ---------------------------------------------------------------------------

func TestExportIncludesEveryTransitiveReplayDependency(t *testing.T) {
	f := newFixture(t, "bundle-transitive")
	s := newScenario(t, f, "journal-transitive", "session-transitive")

	bundleRef, err := ExportReplayInputs(f.ctx, f.store, s.row, s.diagnostic)
	if err != nil {
		t.Fatalf("ExportReplayInputs: %v", err)
	}
	doc, _ := readBundle(t, f.ctx, f.store, bundleRef)
	if doc.RecordType != "replay_input_bundle" {
		t.Fatalf("bundle record_type = %q", doc.RecordType)
	}
	present := make(map[string]bool, len(doc.Entries))
	for _, entry := range doc.Entries {
		present[entry.Digest] = true
	}
	// Manifest artifact.
	manifestDigest := string(evidence_codec.HashBytes(canonicalBytes(t, s.manifest)))
	required := map[string]string{
		manifestDigest:        "manifest",
		s.configRef.Digest:    "configuration",
		s.taskRef.Digest:      "task",
		s.classifierRef.Digest: "classifier",
		s.registryRef.Digest:  "registry",
		s.importRef.Digest:    "import verification",
	}
	// Registration and published row document.
	registrationDigest := registrationDigestOf(t, s.row.Registration)
	required[registrationDigest] = "registration"
	if slot := s.row.Domains["application"]; slot.Document != nil {
		required[slot.Document.Digest] = "row application document"
	}
	for digest, what := range required {
		if !present[digest] {
			t.Fatalf("bundle omits transitive %s dependency %s", what, digest)
		}
		encoded, ok := doc.Blobs[digest]
		if !ok {
			t.Fatalf("bundle entry for %s %s has no blob", what, digest)
		}
		content, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatalf("blob for %s is not base64: %v", what, err)
		}
		if string(evidence_codec.HashBytes(content)) != digest {
			t.Fatalf("blob for %s does not match %s", what, digest)
		}
		// Every embedded blob must equal the exact store bytes, not a
		// substituted locator or current revision.
		storeBytes, err := owner_store.ReadArtifact(f.ctx, f.store, journal_rules.ArtifactReference{Digest: digest})
		if err != nil {
			t.Fatalf("ReadArtifact(%s): %v", digest, err)
		}
		if !bytes.Equal(content, storeBytes) {
			t.Fatalf("bundle blob for %s differs from the stored bytes", what)
		}
	}

	// Round-trip: the bundle resolves to the exact inputs.
	manifest, events, diagnostic, err := LoadReplayInputs(f.ctx, f.store, bundleRef)
	if err != nil {
		t.Fatalf("LoadReplayInputs: %v", err)
	}
	if manifest.JournalID != s.manifest.JournalID || manifest.RunID != s.manifest.RunID {
		t.Fatalf("loaded manifest = %+v, want journal %s", manifest, s.manifest.JournalID)
	}
	if len(events) != len(s.events) {
		t.Fatalf("loaded %d events, want %d", len(events), len(s.events))
	}
	for i := range events {
		if events[i].EventHash != s.events[i].EventHash {
			t.Fatalf("event %d hash = %s, want %s", i, events[i].EventHash, s.events[i].EventHash)
		}
	}
	if diagnostic.DiagnosticID != s.diagnostic.DiagnosticID {
		t.Fatalf("loaded diagnostic = %q, want %q", diagnostic.DiagnosticID, s.diagnostic.DiagnosticID)
	}
	if _, err := journal_rules.ValidateJournal(manifest, events); err != nil {
		t.Fatalf("loaded journal is invalid: %v", err)
	}
}

// ---------------------------------------------------------------------------
// 2. Friendly bundle names resolve to exact artifact bytes.
// ---------------------------------------------------------------------------

func TestFriendlyBundleNamesResolveToExactArtifactBytes(t *testing.T) {
	f := newFixture(t, "bundle-friendly")
	s := newScenario(t, f, "journal-friendly", "session-friendly")

	bundleRef, err := ExportReplayInputs(f.ctx, f.store, s.row, s.diagnostic)
	if err != nil {
		t.Fatalf("ExportReplayInputs: %v", err)
	}
	doc, _ := readBundle(t, f.ctx, f.store, bundleRef)

	// Every friendly name resolves through its bound digest to exact bytes.
	for _, entry := range doc.Entries {
		encoded, ok := doc.Blobs[entry.Digest]
		if !ok {
			t.Fatalf("entry %q (%s) has no blob", entry.Name, entry.Digest)
		}
		content, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatalf("entry %q blob is not base64: %v", entry.Name, err)
		}
		if string(evidence_codec.HashBytes(content)) != entry.Digest {
			t.Fatalf("entry %q bytes do not match %s", entry.Name, entry.Digest)
		}
		if int64(len(content)) != entry.SizeBytes {
			t.Fatalf("entry %q size %d does not match %d bytes", entry.Name, entry.SizeBytes, len(content))
		}
	}
	// M1 friendly names are present and bound.
	for _, name := range []string{"manifest.json", "journal.jsonl", "diagnostic.json", "authoritative-state.json", "registration.json", "artifact-inventory.json"} {
		if _, ok := entryByName(doc, name); !ok {
			t.Fatalf("bundle omits friendly entry %q", name)
		}
	}

	// Tampering with one blob breaks the digest binding: load must fail.
	tampered := doc
	tampered.Blobs = make(map[string]string, len(doc.Blobs))
	for digest, encoded := range doc.Blobs {
		tampered.Blobs[digest] = encoded
	}
	manifestEntry, ok := entryByName(doc, "manifest.json")
	if !ok {
		t.Fatalf("bundle omits manifest.json")
	}
	raw, err := base64.StdEncoding.DecodeString(tampered.Blobs[manifestEntry.Digest])
	if err != nil {
		t.Fatalf("decode manifest blob: %v", err)
	}
	raw[0] ^= 0xFF
	tampered.Blobs[manifestEntry.Digest] = base64.StdEncoding.EncodeToString(raw)
	tamperedBytes := canonicalBytes(t, tampered)
	tamperedRef := installArtifact(t, f.ctx, f.store, tamperedBytes, "application/json", string(bundleRef.Access))
	if _, _, _, err := LoadReplayInputs(f.ctx, f.store, tamperedRef); err == nil {
		t.Fatalf("load succeeded after blob tampering")
	} else if !strings.Contains(err.Error(), manifestEntry.Digest) {
		t.Fatalf("tamper error = %v, want digest %s", err, manifestEntry.Digest)
	}

	// Swapping two friendly names breaks derived-document equality: the
	// names are entries, not identity, and the binding is verified.
	swapped := doc
	swapped.Entries = append([]BundleEntry(nil), doc.Entries...)
	var manifestIdx, journalIdx = -1, -1
	for i, entry := range swapped.Entries {
		if entry.Name == "manifest.json" {
			manifestIdx = i
		}
		if entry.Name == "journal.jsonl" {
			journalIdx = i
		}
	}
	if manifestIdx < 0 || journalIdx < 0 {
		t.Fatalf("bundle omits manifest or journal entries")
	}
	swapped.Entries[manifestIdx].Name, swapped.Entries[journalIdx].Name =
		swapped.Entries[journalIdx].Name, swapped.Entries[manifestIdx].Name
	swappedBytes := canonicalBytes(t, swapped)
	swappedRef := installArtifact(t, f.ctx, f.store, swappedBytes, "application/json", string(bundleRef.Access))
	if _, _, _, err := LoadReplayInputs(f.ctx, f.store, swappedRef); err == nil {
		t.Fatalf("load succeeded after friendly-name swap")
	}
}

// ---------------------------------------------------------------------------
// 3. Restricted dependencies keep archive and export restricted.
// ---------------------------------------------------------------------------

func TestRestrictedDependenciesKeepArchiveAndExportRestricted(t *testing.T) {
	f := newFixture(t, "bundle-restricted")
	m := testManifest(f.domain, "journal-restricted")
	admission := admitJournal(t, f.ctx, f.store, m)

	// One restricted native body among public dependencies.
	publicRef := installArtifact(t, f.ctx, f.store, []byte(`{"public":"yes"}`), "application/json", "public")
	restrictedRef := installArtifact(t, f.ctx, f.store, []byte(`{"native":"body"}`), "application/json", "restricted")
	classifierRef := installArtifact(t, f.ctx, f.store, []byte(`{"classifier":"v1"}`), "application/json", "public")
	registryRef := installArtifact(t, f.ctx, f.store, []byte(`{"requirements":"v1"}`), "application/json", "public")

	configured := eventSubmission(m, 2, "fixture_configured", map[string]any{
		"public":     artifactRefMap(publicRef),
		"native":     artifactRefMap(restrictedRef),
	}, []journal_rules.ArtifactReference{publicRef, restrictedRef})
	requested := eventSubmission(m, 3, "analysis_requested", map[string]any{
		"classifier": artifactRefMap(classifierRef),
		"registry":   artifactRefMap(registryRef),
	}, []journal_rules.ArtifactReference{classifierRef, registryRef})
	later := commitEvents(t, f.ctx, f.store, m.JournalID, []owner_store.EventSubmission{configured, requested})
	events := append(append([]journal_rules.JournalEnvelope{}, admission...), later...)
	prefix := prefixThrough(events)
	diagnostic := buildDiagnostic(t, m, prefix, events, classifierRef, registryRef,
		[]journal_rules.ArtifactReference{publicRef, restrictedRef}, nil)

	// The row document itself is restricted, so the archive root must be.
	registration := sessionRegistration("session-restricted")
	row := buildTestRow(t, f.ctx, f.store, registration, prefix, events, "restricted")

	bundleRef, err := ExportReplayInputs(f.ctx, f.store, row, diagnostic)
	if err != nil {
		t.Fatalf("ExportReplayInputs: %v", err)
	}
	if bundleRef.Access != "restricted" {
		t.Fatalf("bundle access = %q, want restricted", bundleRef.Access)
	}
	doc, _ := readBundle(t, f.ctx, f.store, bundleRef)
	restrictedEntries := 0
	for _, entry := range doc.Entries {
		if entry.Access == "restricted" {
			restrictedEntries++
		}
	}
	if restrictedEntries == 0 {
		t.Fatalf("no bundle entry preserves the restricted classification")
	}

	// The archive root hashes the storage manifest and inherits the
	// restricted classification from its restricted extent.
	registrationBytes := canonicalBytes(t, registration)
	registrationRef := installArtifact(t, f.ctx, f.store, registrationBytes, "application/json", "public")
	slot := row.Domains["application"]
	archiveManifest := publication.ArchiveStorageManifest{
		Encoding:      "owner-domain-extents/1",
		SchemaVersion: owdSchemaVersion,
		Entity:        registration.Entity,
		Registration:  registrationRef,
		Domains: map[string]publication.ArchiveDomainSlot{
			"application": {Revision: 1, Document: slot.Document, PublicationRef: slot.PublicationRef},
			"observation": {Revision: 0, Value: journal_rules.NewMissing("not_observed")},
			"diagnostic":  {Revision: 0, Value: journal_rules.NewMissing("not_observed")},
		},
		SealPoint: row.SealPoint,
	}
	record, err := publication.ExpandArchive(f.ctx, f.store, archiveManifest)
	if err != nil {
		t.Fatalf("ExpandArchive: %v", err)
	}
	if record.Root.Access != "restricted" {
		t.Fatalf("archive root access = %q, want restricted", record.Root.Access)
	}

	// The validation bundle stays restricted as well.
	diagnosticBytes := canonicalBytes(t, diagnostic)
	sourceDiagnostic := installArtifact(t, f.ctx, f.store, diagnosticBytes, "application/json", "public")
	engineRef := installArtifact(t, f.ctx, f.store, []byte(`{"engine":"v1"}`), "application/json", "public")
	reducerRef := installArtifact(t, f.ctx, f.store, []byte(`{"reducer":"v1"}`), "application/json", "public")
	manifestDigest := string(evidence_codec.HashBytes(canonicalBytes(t, m)))
	receipt := buildReceipt(t, diagnostic, manifestDigest, bundleRef, sourceDiagnostic, engineRef,
		VersionPin{ID: "reducer", Version: "v1", ArtifactDigest: reducerRef.Digest}, "exact_fixture")
	checksRef := installArtifact(t, f.ctx, f.store, []byte(`{"checks":"pass"}`), "application/json", "public")
	validationRef, err := ExportValidationBundle(f.ctx, f.store, row, diagnostic, receipt, checksRef)
	if err != nil {
		t.Fatalf("ExportValidationBundle: %v", err)
	}
	if validationRef.Access != "restricted" {
		t.Fatalf("validation bundle access = %q, want restricted", validationRef.Access)
	}

	// Control: an all-public export stays public.
	f2 := newFixture(t, "bundle-public")
	s2 := newScenario(t, f2, "journal-public", "session-public")
	publicBundle, err := ExportReplayInputs(f2.ctx, f2.store, s2.row, s2.diagnostic)
	if err != nil {
		t.Fatalf("public ExportReplayInputs: %v", err)
	}
	if publicBundle.Access != "public" {
		t.Fatalf("public bundle access = %q, want public", publicBundle.Access)
	}
}

// ---------------------------------------------------------------------------
// 4. Replay input bundle excludes its future receipt.
// ---------------------------------------------------------------------------

func TestReplayInputBundleExcludesItsFutureReceipt(t *testing.T) {
	f := newFixture(t, "bundle-receipt")
	s := newScenario(t, f, "journal-receipt", "session-receipt")

	inputRef, err := ExportReplayInputs(f.ctx, f.store, s.row, s.diagnostic)
	if err != nil {
		t.Fatalf("ExportReplayInputs: %v", err)
	}
	inputDoc, inputRaw := readBundle(t, f.ctx, f.store, inputRef)
	if inputDoc.Receipt != nil {
		t.Fatalf("input bundle embeds a receipt")
	}
	if _, ok := entryByName(inputDoc, "replay-receipt.json"); ok {
		t.Fatalf("input bundle carries replay-receipt.json")
	}

	// The future receipt hashes the input bundle; the input bundle cannot
	// contain it.
	diagnosticBytes := canonicalBytes(t, s.diagnostic)
	sourceDiagnostic := installArtifact(t, f.ctx, f.store, diagnosticBytes, "application/json", "public")
	engineRef := installArtifact(t, f.ctx, f.store, []byte(`{"engine":"v1"}`), "application/json", "public")
	reducerRef := installArtifact(t, f.ctx, f.store, []byte(`{"reducer":"v1"}`), "application/json", "public")
	manifestDigest := string(evidence_codec.HashBytes(canonicalBytes(t, s.manifest)))
	receipt := buildReceipt(t, s.diagnostic, manifestDigest, inputRef, sourceDiagnostic, engineRef,
		VersionPin{ID: "reducer", Version: "v1", ArtifactDigest: reducerRef.Digest}, "exact_fixture")
	checksRef := installArtifact(t, f.ctx, f.store, []byte(`{"checks":"pass"}`), "application/json", "public")
	validationRef, err := ExportValidationBundle(f.ctx, f.store, s.row, s.diagnostic, receipt, checksRef)
	if err != nil {
		t.Fatalf("ExportValidationBundle: %v", err)
	}
	validationDoc, _ := readBundle(t, f.ctx, f.store, validationRef)
	if validationDoc.Receipt == nil {
		t.Fatalf("validation bundle omits its receipt")
	}
	if _, ok := entryByName(validationDoc, "replay-receipt.json"); !ok {
		t.Fatalf("validation bundle omits replay-receipt.json")
	}
	if _, ok := entryByName(validationDoc, "acceptance-checks.json"); !ok {
		t.Fatalf("validation bundle omits acceptance-checks.json")
	}
	// The input bytes predate the receipt and cannot name it.
	if strings.Contains(string(inputRaw), receipt.ReplayID) {
		t.Fatalf("input bundle bytes contain the future receipt id %q", receipt.ReplayID)
	}
	if strings.Contains(string(inputRaw), validationRef.Digest) {
		t.Fatalf("input bundle bytes contain the future validation digest")
	}
	if inputRef.Digest == validationRef.Digest {
		t.Fatalf("input and validation bundles share one digest")
	}
	// The input bundle still loads as exact inputs without a receipt.
	if _, _, _, err := LoadReplayInputs(f.ctx, f.store, inputRef); err != nil {
		t.Fatalf("LoadReplayInputs(input): %v", err)
	}
}

// ---------------------------------------------------------------------------
// 5. Redacted export cannot claim unavailable exact replay inputs.
// ---------------------------------------------------------------------------

func TestRedactedExportCannotClaimUnavailableExactReplayInputs(t *testing.T) {
	f := newFixture(t, "bundle-redacted")
	s := newScenario(t, f, "journal-redacted", "session-redacted")

	bundleRef, err := ExportReplayInputs(f.ctx, f.store, s.row, s.diagnostic)
	if err != nil {
		t.Fatalf("ExportReplayInputs: %v", err)
	}
	doc, _ := readBundle(t, f.ctx, f.store, bundleRef)

	// Redact one required input: remove its blob under a new identity and
	// mark the bundle unavailable. Loading it as exact inputs must fail
	// with the known digest, never succeed.
	redacted := doc
	redacted.Blobs = make(map[string]string, len(doc.Blobs))
	for digest, encoded := range doc.Blobs {
		redacted.Blobs[digest] = encoded
	}
	redacted.Entries = append([]BundleEntry(nil), doc.Entries...)
	target := s.classifierRef.Digest
	delete(redacted.Blobs, target)
	kept := redacted.Entries[:0]
	for _, entry := range redacted.Entries {
		if entry.Digest != target {
			kept = append(kept, entry)
		}
	}
	redacted.Entries = kept
	redacted.ReplayAvailability = "unavailable"
	redacted.Redacted = []string{target}
	redactedBytes := canonicalBytes(t, redacted)
	redactedRef := installArtifact(t, f.ctx, f.store, redactedBytes, "application/json", string(bundleRef.Access))
	if redactedRef.Digest == bundleRef.Digest {
		t.Fatalf("redaction preserved the original digest")
	}
	if _, _, _, err := LoadReplayInputs(f.ctx, f.store, redactedRef); err == nil {
		t.Fatalf("redacted bundle loaded as exact inputs")
	} else {
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("redacted load error = %v, want ErrUnavailable", err)
		}
		if !strings.Contains(err.Error(), target) {
			t.Fatalf("redacted load error = %v, want digest %s", err, target)
		}
	}

	// A bundle that falsely claims exact inputs while omitting a blob must
	// also fail, preserving the missing identity.
	falseClaim := doc
	falseClaim.Blobs = make(map[string]string, len(doc.Blobs))
	for digest, encoded := range doc.Blobs {
		falseClaim.Blobs[digest] = encoded
	}
	delete(falseClaim.Blobs, s.registryRef.Digest)
	falseBytes := canonicalBytes(t, falseClaim)
	falseRef := installArtifact(t, f.ctx, f.store, falseBytes, "application/json", string(bundleRef.Access))
	if _, _, _, err := LoadReplayInputs(f.ctx, f.store, falseRef); err == nil {
		t.Fatalf("incomplete bundle with an exact claim loaded")
	} else if !strings.Contains(err.Error(), s.registryRef.Digest) {
		t.Fatalf("false-claim error = %v, want digest %s", err, s.registryRef.Digest)
	}

	// The original bundle still loads.
	if _, _, _, err := LoadReplayInputs(f.ctx, f.store, bundleRef); err != nil {
		t.Fatalf("LoadReplayInputs(original): %v", err)
	}
}

// ---------------------------------------------------------------------------
// 6. Known lost artifact identity survives export failure.
// ---------------------------------------------------------------------------

func TestKnownLostArtifactIdentitySurvivesExportFailure(t *testing.T) {
	f := newFixture(t, "bundle-lost")
	s := newScenario(t, f, "journal-lost", "session-lost")

	// Delete the configuration extent bytes while the registration (and
	// therefore the known identity) remains.
	hexDigest := strings.TrimPrefix(s.configRef.Digest, "sha256:")
	objectPath := filepath.Join(f.artifactRoot, "objects", hexDigest[:2], hexDigest)
	if err := os.Remove(objectPath); err != nil {
		t.Fatalf("remove artifact bytes: %v", err)
	}
	if _, err := owner_store.ReadArtifact(f.ctx, f.store, s.configRef); !errors.Is(err, owner_store.ErrArtifactLost) {
		t.Fatalf("ReadArtifact after deletion = %v, want ErrArtifactLost", err)
	}

	_, err := ExportReplayInputs(f.ctx, f.store, s.row, s.diagnostic)
	if err == nil {
		t.Fatalf("export succeeded despite lost bytes")
	}
	if !errors.Is(err, owner_store.ErrArtifactLost) {
		t.Fatalf("export error = %v, want owner_store.ErrArtifactLost", err)
	}
	if !strings.Contains(err.Error(), s.configRef.Digest) {
		t.Fatalf("export error = %v, want known digest %s", err, s.configRef.Digest)
	}

	// A lost row document fails the same way, preserving its identity.
	f2 := newFixture(t, "bundle-lost-doc")
	s2 := newScenario(t, f2, "journal-lost-doc", "session-lost-doc")
	slot := s2.row.Domains["application"]
	if slot.Document == nil {
		t.Fatalf("row has no application document")
	}
	hexDoc := strings.TrimPrefix(slot.Document.Digest, "sha256:")
	if err := os.Remove(filepath.Join(f2.artifactRoot, "objects", hexDoc[:2], hexDoc)); err != nil {
		t.Fatalf("remove row document bytes: %v", err)
	}
	if _, err := ExportReplayInputs(f2.ctx, f2.store, s2.row, s2.diagnostic); err == nil {
		t.Fatalf("export succeeded despite a lost row document")
	} else if !strings.Contains(err.Error(), slot.Document.Digest) {
		t.Fatalf("row-loss error = %v, want digest %s", err, slot.Document.Digest)
	}
}

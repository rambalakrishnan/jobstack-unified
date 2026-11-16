package replay

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	authority "authority"
	diagnostic_reducer "diagnostic_reducer"
	evidence_bundle "evidence_bundle"
	evidence_codec "evidence_codec"
	fixture_reducer "fixture_reducer"
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
	request, err := http.NewRequest(http.MethodPost, "http://replay.test/"+domain, nil)
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
			Origin: "engine_measured", SourceID: "replay",
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

func artifactRefMap(ref journal_rules.ArtifactReference) map[string]any {
	return map[string]any{
		"digest":       ref.Digest,
		"size_bytes":   ref.SizeBytes,
		"media_type":   ref.MediaType,
		"owner_domain": ref.OwnerDomain,
		"access":       ref.Access,
	}
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

func eventSubmissionAt(m journal_rules.Manifest, sequence int64, kind string, data map[string]any, occurredAt any) owner_store.EventSubmission {
	if data == nil {
		data = map[string]any{}
	}
	return owner_store.EventSubmission{
		ProducerSequence:   sequence,
		EventKind:          kind,
		EventSchemaVersion: "0.1.0",
		OccurredAt:         occurredAt,
		Payload: journal_rules.Payload{
			Data:         data,
			Measurements: []journal_rules.Measurement{},
			EvidenceRefs: []journal_rules.EvidenceRef{},
			ArtifactRefs: []journal_rules.ArtifactReference{},
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
// Row fixtures (adapted from evidence_bundle corpus).
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

func buildTestRow(t *testing.T, ctx context.Context, store *owner_store.OwnerStore, registration publication.EntityRegistration, prefix journal_rules.JournalPrefix, events []journal_rules.JournalEnvelope) publication.LogicalRow {
	t.Helper()
	lastRef := eventRef(events[len(events)-1])
	docBytes := buildOwnedDocument(t, registration, "application", 1, prefix, []journal_rules.EvidenceRef{lastRef}, map[string]any{"marker": "app-v1"})
	docRef := installArtifact(t, ctx, store, docBytes, "application/json", "public")
	applicationRef := docRef
	publicationRef := lastRef
	return publication.LogicalRow{
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
}

// ---------------------------------------------------------------------------
// Replay scenario helpers.
// ---------------------------------------------------------------------------

func testConfig(t *testing.T) []byte {
	t.Helper()
	cfg := map[string]any{
		"profile": "M1",
		"features": []any{
			map[string]any{"name": "cooperative-form", "recipe": "primitive:cooperative-form/1.0"},
		},
		"task": map[string]any{
			"kind": "completion", "required_controls": []any{"contact-name"},
			"hidden_controls": []any{}, "human_path": true,
			"required_verifiers": []any{"v1"}, "permanently_rejected_verifiers": []any{},
			"requires_recovery": false, "recovery_paths": []any{"retry"},
			"required_browser_capabilities": []any{}, "available_browser_capabilities": []any{"dom"},
		},
		"budgets": map[string]any{
			"task_ms": 60000.0, "required_ms": 5000.0, "artificial_delay_ms": 100.0,
		},
		"identity_epoch":      "epoch-1",
		"known_jobs":          []any{"job-1", "job-2"},
		"review_dependencies": []any{"contact", "history"},
		"upload_max_bytes":    float64(5 * 1024 * 1024),
	}
	out, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("cannot encode config: %v", err)
	}
	canonical, err := evidence_codec.CanonicalJSON(out, "application/json")
	if err != nil {
		t.Fatalf("cannot canonicalize config: %v", err)
	}
	return canonical
}

func testSubjectMap() map[string]any {
	return map[string]any{
		"subject_id": "subject-A", "subject_version": "subject-1.0",
		"configured_mode": "auto", "interface_surface": "web",
	}
}

func fixtureCommandPayload(t *testing.T, obj map[string]any) json.RawMessage {
	t.Helper()
	out, err := json.Marshal(obj)
	if err != nil {
		t.Fatalf("cannot encode fixture payload: %v", err)
	}
	return json.RawMessage(out)
}

func jobCommand(t *testing.T, runID, key string, rev int, jobID string) fixture_reducer.EventSubmission {
	t.Helper()
	return fixture_reducer.EventSubmission{
		OperationKey: key, OperationKind: fixture_reducer.OpJobSelection, AttemptID: runID,
		ExpectedRevision: rev, Payload: fixtureCommandPayload(t, map[string]any{"job_id": jobID}),
	}
}

func commandAsMap(t *testing.T, cmd fixture_reducer.EventSubmission) map[string]any {
	t.Helper()
	raw, err := json.Marshal(cmd)
	if err != nil {
		t.Fatalf("marshal fixture command: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode fixture command: %v", err)
	}
	return decoded
}

func analysisRequestedData(classifier, registry VersionPin, diagnosticID string, revision int64, subject map[string]any) map[string]any {
	return map[string]any{
		"diagnostic_id":     diagnosticID,
		"analysis_revision": float64(revision),
		"classifier": map[string]any{
			"id": classifier.ID, "version": classifier.Version, "artifact_digest": classifier.ArtifactDigest,
		},
		"requirement_registry": map[string]any{
			"id": registry.ID, "version": registry.Version, "artifact_digest": registry.ArtifactDigest,
		},
		"fix_registry": map[string]any{"value": nil, "reason": "not_enabled"},
		"subject":      subject,
	}
}

type replayScenario struct {
	manifest    journal_rules.Manifest
	events      []journal_rules.JournalEnvelope
	prefix      journal_rules.JournalPrefix
	config      []byte
	classifier  VersionPin
	registry    VersionPin
	diagnostic  DiagnosticDocument
	row         publication.LogicalRow
	bundle      ArtifactReference
	source      ArtifactReference
	classRef    ArtifactReference
	registryRef ArtifactReference
}

func configAsExtra(t *testing.T, config []byte) map[string]any {
	t.Helper()
	var decoded map[string]any
	if err := json.Unmarshal(config, &decoded); err != nil {
		t.Fatalf("decode config: %v", err)
	}
	return decoded
}

// buildScenario commits the given post-admission submissions, computes
// record-time expected digests with the replay projection functions,
// builds the recorded diagnostic and row, exports the bundle, and installs
// the source diagnostic.
func buildScenario(t *testing.T, f *fixture, journalID, sessionID string, submissions []owner_store.EventSubmission, extraMutate func(map[string]any)) *replayScenario {
	t.Helper()
	m := testManifest(f.domain, journalID)
	admission := admitJournal(t, f.ctx, f.store, m)
	config := testConfig(t)
	classRef := installArtifact(t, f.ctx, f.store, []byte(`{"classifier":"v1"}`), "application/json", "public")
	registryRef := installArtifact(t, f.ctx, f.store, []byte(`{"requirements":"v1"}`), "application/json", "public")
	classifier := VersionPin{ID: "classifier", Version: "v1", ArtifactDigest: classRef.Digest}
	registry := VersionPin{ID: "requirements", Version: "v1", ArtifactDigest: registryRef.Digest}
	diagnosticID := "diag-" + journalID

	var later []journal_rules.JournalEnvelope
	if len(submissions) > 0 {
		later = commitEvents(t, f.ctx, f.store, m.JournalID, submissions)
	}
	// The analysis_requested event always closes the prefix.
	reqData := analysisRequestedData(classifier, registry, diagnosticID, 1, testSubjectMap())
	producerSeq := int64(len(submissions) + 2)
	closing := commitEvents(t, f.ctx, f.store, m.JournalID, []owner_store.EventSubmission{
		eventSubmission(m, producerSeq, "analysis_requested", reqData, []journal_rules.ArtifactReference{classRef, registryRef}),
	})
	events := append(append([]journal_rules.JournalEnvelope{}, admission...), later...)
	events = append(events, closing...)
	prefix := prefixThrough(events)

	// Record-time expected digests via the same replay functions.
	consumed, _ := filterReplayInputs(events)
	deduped, _ := unwrapImportedInputs(consumed)
	semantic, final, missing, detail := runFixtureReplay(m, config, deduped)
	if missing != nil {
		t.Fatalf("record-time fixture replay unavailable: %s", detail)
	}
	provisional := DiagnosticDocument{
		RecordType:          "diagnostic",
		SchemaVersion:       "1.0.0",
		DiagnosticID:        diagnosticID,
		AnalysisRevision:    1,
		RunID:               m.RunID,
		ManifestHash:        string(evidence_codec.HashBytes(canonicalBytes(t, m))),
		InputPrefix:         prefix,
		AnalysisRequestRef:  eventRef(events[len(events)-1]),
		Classifier:          classifier,
		RequirementRegistry: registry,
		FixRegistry:         journal_rules.NewMissing("not_enabled"),
		EvidenceRefs:        []journal_rules.EvidenceRef{eventRef(events[len(events)-1])},
		Artifacts:           []journal_rules.ArtifactReference{classRef, registryRef},
		Extra: map[string]any{
			extraSemanticDigest: semantic,
			extraFinalDigest:    final,
			extraConfig:         configAsExtra(t, config),
			extraSubject:        testSubjectMap(),
		},
	}
	diagDigest, dmissing, dDetail := rederiveDiagnosticDigest(m, events, provisional, config)
	if dmissing != nil {
		t.Fatalf("record-time diagnostic re-derivation unavailable: %s", dDetail)
	}
	provisional.Extra[extraDiagDigest] = diagDigest
	if extraMutate != nil {
		extraMutate(provisional.Extra)
	}
	registration := sessionRegistration(sessionID)
	row := buildTestRow(t, f.ctx, f.store, registration, prefix, events)
	bundle, err := evidence_bundle.ExportReplayInputs(f.ctx, f.store, row, provisional)
	if err != nil {
		t.Fatalf("ExportReplayInputs: %v", err)
	}
	sourceBytes := canonicalBytes(t, provisional)
	source := installArtifact(t, f.ctx, f.store, sourceBytes, "application/json", "public")
	return &replayScenario{
		manifest: m, events: events, prefix: prefix, config: config,
		classifier: classifier, registry: registry,
		diagnostic: provisional, row: row, bundle: bundle, source: source,
		classRef: classRef, registryRef: registryRef,
	}
}

func comparisonByOutput(receipt ReplayReceipt, output string) *ReplayComparison {
	for i := range receipt.Comparisons {
		if receipt.Comparisons[i].Output == output {
			return &receipt.Comparisons[i]
		}
	}
	return nil
}

func isMissingValue(t *testing.T, value any) bool {
	t.Helper()
	_, ok := asMissingEnvelope(value)
	return ok
}

// ---------------------------------------------------------------------------
// Conformance assertions.
// ---------------------------------------------------------------------------

func TestReplayMismatchAndUnavailableRemainDistinct(t *testing.T) {
	f := newFixture(t, "replay-distinct")
	mkSubs := func(jobID string) []owner_store.EventSubmission {
		m := testManifest(f.domain, "placeholder")
		_ = m
		return nil
	}
	_ = mkSubs
	// Matched baseline: job-1.
	manifestForCmds := testManifest(f.domain, "journal-match")
	baseline := buildScenario(t, f, "journal-match", "session-match", []owner_store.EventSubmission{
		func() owner_store.EventSubmission {
			cmd := jobCommand(t, manifestForCmds.RunID, "job-k1", 0, "job-1")
			return eventSubmission(manifestForCmds, 2, "session_opened", map[string]any{
				"fixture_command": commandAsMap(t, cmd),
			}, nil)
		}(),
	}, nil)
	receipt, err := ReplayBundle(f.ctx, f.store, baseline.bundle, baseline.source, "exact_fixture")
	if err != nil {
		t.Fatalf("ReplayBundle(baseline): %v", err)
	}
	if receipt.Result != "matched" {
		t.Fatalf("baseline result = %q, want matched (comparisons %+v, limitations %v)", receipt.Result, receipt.Comparisons, receipt.Limitations)
	}

	// Mismatched: same expected digests as the baseline, but the journal
	// actually applies job-2. Recomputed digests differ while all inputs
	// remain present.
	mMismatch := testManifest(f.domain, "journal-mismatch")
	admission := admitJournal(t, f.ctx, f.store, mMismatch)
	config := testConfig(t)
	classRef := installArtifact(t, f.ctx, f.store, []byte(`{"classifier":"v1"}`), "application/json", "public")
	registryRef := installArtifact(t, f.ctx, f.store, []byte(`{"requirements":"v1"}`), "application/json", "public")
	classifier := VersionPin{ID: "classifier", Version: "v1", ArtifactDigest: classRef.Digest}
	registry := VersionPin{ID: "requirements", Version: "v1", ArtifactDigest: registryRef.Digest}
	cmd := jobCommand(t, mMismatch.RunID, "job-k1", 0, "job-2")
	later := commitEvents(t, f.ctx, f.store, mMismatch.JournalID, []owner_store.EventSubmission{
		eventSubmission(mMismatch, 2, "session_opened", map[string]any{
			"fixture_command": commandAsMap(t, cmd),
		}, nil),
	})
	reqData := analysisRequestedData(classifier, registry, "diag-journal-mismatch", 1, testSubjectMap())
	closing := commitEvents(t, f.ctx, f.store, mMismatch.JournalID, []owner_store.EventSubmission{
		eventSubmission(mMismatch, 3, "analysis_requested", reqData, []journal_rules.ArtifactReference{classRef, registryRef}),
	})
	events := append(append([]journal_rules.JournalEnvelope{}, admission...), later...)
	events = append(events, closing...)
	prefix := prefixThrough(events)
	mismatchedDiag := DiagnosticDocument{
		RecordType:          "diagnostic",
		SchemaVersion:       "1.0.0",
		DiagnosticID:        "diag-journal-mismatch",
		AnalysisRevision:    1,
		RunID:               mMismatch.RunID,
		ManifestHash:        string(evidence_codec.HashBytes(canonicalBytes(t, mMismatch))),
		InputPrefix:         prefix,
		AnalysisRequestRef:  eventRef(events[len(events)-1]),
		Classifier:          classifier,
		RequirementRegistry: registry,
		FixRegistry:         journal_rules.NewMissing("not_enabled"),
		EvidenceRefs:        []journal_rules.EvidenceRef{eventRef(events[len(events)-1])},
		Artifacts:           []journal_rules.ArtifactReference{classRef, registryRef},
		Extra: map[string]any{
			// Pin the baseline's expected digests so recomputation from
			// the job-2 journal necessarily diverges.
			extraSemanticDigest: baseline.diagnostic.Extra[extraSemanticDigest],
			extraFinalDigest:    baseline.diagnostic.Extra[extraFinalDigest],
			extraDiagDigest:     baseline.diagnostic.Extra[extraDiagDigest],
			extraConfig:         configAsExtra(t, config),
			extraSubject:        testSubjectMap(),
		},
	}
	registration := sessionRegistration("session-mismatch")
	row := buildTestRow(t, f.ctx, f.store, registration, prefix, events)
	bundle, err := evidence_bundle.ExportReplayInputs(f.ctx, f.store, row, mismatchedDiag)
	if err != nil {
		t.Fatalf("ExportReplayInputs(mismatch): %v", err)
	}
	source := installArtifact(t, f.ctx, f.store, canonicalBytes(t, mismatchedDiag), "application/json", "public")
	mismatchReceipt, err := ReplayBundle(f.ctx, f.store, bundle, source, "exact_fixture")
	if err != nil {
		t.Fatalf("ReplayBundle(mismatch): %v", err)
	}
	if mismatchReceipt.Result != "mismatched" {
		t.Fatalf("tampered result = %q, want mismatched (comparisons %+v)", mismatchReceipt.Result, mismatchReceipt.Comparisons)
	}
	semantic := comparisonByOutput(mismatchReceipt, "semantic_events")
	if semantic == nil || semantic.Result != "mismatched" {
		t.Fatalf("semantic comparison = %+v, want mismatched", semantic)
	}
	if actual, ok := semantic.ActualDigest.(string); !ok || !strings.HasPrefix(actual, "sha256:") {
		t.Fatalf("mismatched actual digest = %#v, want a digest string", semantic.ActualDigest)
	}

	// Unavailable: same journal shape as the baseline, but the diagnostic
	// pins no expected digests and no configuration.
	unavail := buildScenario(t, f, "journal-unavail", "session-unavail", []owner_store.EventSubmission{
		func() owner_store.EventSubmission {
			m := testManifest(f.domain, "journal-unavail")
			cmd := jobCommand(t, m.RunID, "job-k1", 0, "job-1")
			return eventSubmission(m, 2, "session_opened", map[string]any{
				"fixture_command": commandAsMap(t, cmd),
			}, nil)
		}(),
	}, func(extra map[string]any) {
		delete(extra, extraSemanticDigest)
		delete(extra, extraFinalDigest)
		delete(extra, extraDiagDigest)
		delete(extra, extraConfig)
	})
	// Re-export without configuration: buildScenario already pinned
	// digests computed with configuration, but the mutation removed them
	// and the configuration, so replay cannot recompute.
	unavailReceipt, err := ReplayBundle(f.ctx, f.store, unavail.bundle, unavail.source, "exact_fixture")
	if err != nil {
		t.Fatalf("ReplayBundle(unavailable): %v", err)
	}
	if unavailReceipt.Result != "unavailable" {
		t.Fatalf("missing-input result = %q, want unavailable (comparisons %+v)", unavailReceipt.Result, unavailReceipt.Comparisons)
	}
	for _, c := range unavailReceipt.Comparisons {
		if c.Result != "unavailable" {
			t.Fatalf("comparison %q result = %q, want unavailable", c.Output, c.Result)
		}
		if !isMissingValue(t, c.ActualDigest) {
			t.Fatalf("comparison %q actual = %#v, want a Missing envelope", c.Output, c.ActualDigest)
		}
	}
	if mismatchReceipt.Result == unavailReceipt.Result {
		t.Fatalf("mismatch (%q) and unavailable (%q) must remain distinct", mismatchReceipt.Result, unavailReceipt.Result)
	}
}

func TestReplayInvokesNoBrowserSubjectOrExternalWrites(t *testing.T) {
	f := newFixture(t, "replay-noeffects")
	m := testManifest(f.domain, "journal-noeffects")
	scenario := buildScenario(t, f, "journal-noeffects", "session-noeffects", []owner_store.EventSubmission{
		eventSubmission(m, 2, "session_opened", map[string]any{
			"fixture_command": commandAsMap(t, jobCommand(t, m.RunID, "job-k1", 0, "job-1")),
		}, nil),
	}, nil)
	before, err := owner_store.LoadPrefix(f.ctx, f.store, scenario.prefix)
	if err != nil {
		t.Fatalf("LoadPrefix(before): %v", err)
	}
	for _, mode := range []string{"exact_fixture", "diagnostic_only", "diagnostic_rederivation"} {
		receipt, err := ReplayBundle(f.ctx, f.store, scenario.bundle, scenario.source, mode)
		if err != nil {
			t.Fatalf("ReplayBundle(%s): %v", mode, err)
		}
		if receipt.InvokedBrowser || receipt.InvokedSubject || receipt.PerformedExternalWrites {
			t.Fatalf("mode %s flags = browser %v subject %v writes %v, want all false",
				mode, receipt.InvokedBrowser, receipt.InvokedSubject, receipt.PerformedExternalWrites)
		}
		after, err := owner_store.LoadPrefix(f.ctx, f.store, scenario.prefix)
		if err != nil {
			t.Fatalf("LoadPrefix(after %s): %v", mode, err)
		}
		if len(after) != len(before) {
			t.Fatalf("mode %s changed journal length %d -> %d; replay must not commit", mode, len(before), len(after))
		}
		for i := range before {
			if before[i].EventHash != after[i].EventHash || before[i].EventID != after[i].EventID {
				t.Fatalf("mode %s mutated journal event %d", mode, i)
			}
		}
	}
}

func TestReplayConsumesInputsInsteadOfRecordedDerivedOutputs(t *testing.T) {
	f := newFixture(t, "replay-inputs")
	// Unit-level: derived outputs are partitioned out of the inputs.
	m := testManifest(f.domain, "journal-filter")
	admission := admitJournal(t, f.ctx, f.store, m)
	consumedSub := eventSubmission(m, 2, "session_opened", map[string]any{"marker": "input"}, nil)
	derivedSub := eventSubmission(m, 3, "render_observed", map[string]any{"marker": "derived"}, nil)
	later := commitEvents(t, f.ctx, f.store, m.JournalID, []owner_store.EventSubmission{consumedSub, derivedSub})
	events := append(append([]journal_rules.JournalEnvelope{}, admission...), later...)
	consumed, ignored := filterReplayInputs(events)
	if len(consumed) != 2 || len(ignored) != 1 {
		t.Fatalf("filter = %d consumed %d ignored, want 2 and 1 (roles: %s %s %s)",
			len(consumed), len(ignored), events[0].Role, events[1].Role, events[2].Role)
	}
	if ignored[0].EventKind != "render_observed" {
		t.Fatalf("ignored event = %q, want render_observed", ignored[0].EventKind)
	}
	baseProjection, err := semanticProjectionFromInputs(consumed)
	if err != nil {
		t.Fatalf("projection(consumed): %v", err)
	}
	withDerived, err := semanticProjectionFromInputs(append(append([]journal_rules.JournalEnvelope{}, consumed...), ignored...))
	if err != nil {
		t.Fatalf("projection(with derived): %v", err)
	}
	if bytes.Equal(baseProjection, withDerived) {
		t.Fatalf("projection must change when derived outputs are forced in; helper sanity check failed")
	}

	// End-to-end: two bundles differing only in a derived-output payload
	// replay to identical actual digests.
	mkDerived := func(journalID, sessionID, tamper string) *replayScenario {
		mm := testManifest(f.domain, journalID)
		return buildScenario(t, f, journalID, sessionID, []owner_store.EventSubmission{
			eventSubmission(mm, 2, "session_opened", map[string]any{
				"fixture_command": commandAsMap(t, jobCommand(t, mm.RunID, "job-k1", 0, "job-1")),
			}, nil),
			eventSubmission(mm, 3, "render_observed", map[string]any{"tamper": tamper}, nil),
		}, nil)
	}
	first := mkDerived("journal-derived-a", "session-derived-a", "A")
	second := mkDerived("journal-derived-b", "session-derived-b", "B")
	receiptA, err := ReplayBundle(f.ctx, f.store, first.bundle, first.source, "exact_fixture")
	if err != nil {
		t.Fatalf("ReplayBundle(derived A): %v", err)
	}
	receiptB, err := ReplayBundle(f.ctx, f.store, second.bundle, second.source, "exact_fixture")
	if err != nil {
		t.Fatalf("ReplayBundle(derived B): %v", err)
	}
	if receiptA.Result != "matched" || receiptB.Result != "matched" {
		t.Fatalf("derived-only difference must still match: A=%q B=%q", receiptA.Result, receiptB.Result)
	}
	// End-to-end proof within one journal: the receipt's actual semantic
	// digest must equal the projection over consumed inputs only. Feeding
	// the ignored derived outputs back in must change the digest, proving
	// replay's actuals exclude them.
	consumedA, ignoredA := filterReplayInputs(first.events)
	if len(ignoredA) == 0 {
		t.Fatalf("expected an ignored derived output in scenario A")
	}
	dedupedA, _ := unwrapImportedInputs(consumedA)
	semanticFiltered, _, missingF, detailF := runFixtureReplay(first.manifest, first.config, dedupedA)
	if missingF != nil {
		t.Fatalf("filtered replay unavailable: %s", detailF)
	}
	semanticUnfiltered, _, missingU, detailU := runFixtureReplay(first.manifest, first.config, first.events)
	if missingU != nil {
		t.Fatalf("unfiltered replay unavailable: %s", detailU)
	}
	if semanticFiltered == semanticUnfiltered {
		t.Fatalf("derived outputs do not affect the projection when forced in; test cannot distinguish")
	}
	actualA := comparisonByOutput(receiptA, "semantic_events")
	if actualA == nil {
		t.Fatalf("receipt A omits the semantic_events comparison")
	}
	actualDigest, ok := actualA.ActualDigest.(string)
	if !ok {
		t.Fatalf("receipt A semantic actual = %#v, want a digest string", actualA.ActualDigest)
	}
	if actualDigest != semanticFiltered {
		t.Fatalf("receipt actual %q != consumed-only projection %q; replay must exclude derived outputs", actualDigest, semanticFiltered)
	}
	if actualDigest == semanticUnfiltered {
		t.Fatalf("receipt actual equals the unfiltered projection; replay fed derived outputs back as inputs")
	}
}

func TestImportedSourceInputsAreAppliedExactlyOnce(t *testing.T) {
	f := newFixture(t, "replay-imports")
	m := testManifest(f.domain, "journal-imports")
	digest := string(evidence_codec.HashBytes([]byte("imported-source-1")))
	cmd := jobCommand(t, m.RunID, "job-k1", 0, "job-1")
	cmdMap := commandAsMap(t, cmd)
	scenario := buildScenario(t, f, "journal-imports", "session-imports", []owner_store.EventSubmission{
		eventSubmission(m, 2, "session_opened", map[string]any{
			"fixture_command": cmdMap,
			"import_digest":   digest,
		}, nil),
		eventSubmission(m, 3, "session_opened", map[string]any{
			"fixture_command": cmdMap,
			"import_digest":   digest,
		}, nil),
	}, nil)
	consumed, _ := filterReplayInputs(scenario.events)
	deduped, skipped := unwrapImportedInputs(consumed)
	if skipped != 1 {
		t.Fatalf("skipped = %d, want 1 duplicate import", skipped)
	}
	if len(deduped) != len(consumed)-1 {
		t.Fatalf("deduped %d of %d consumed, want exactly one skipped", len(deduped), len(consumed))
	}
	receipt, err := ReplayBundle(f.ctx, f.store, scenario.bundle, scenario.source, "exact_fixture")
	if err != nil {
		t.Fatalf("ReplayBundle(imports): %v", err)
	}
	if receipt.Result != "matched" {
		t.Fatalf("duplicate-import result = %q, want matched (limitations %v)", receipt.Result, receipt.Limitations)
	}
	found := false
	for _, limitation := range receipt.Limitations {
		if strings.Contains(limitation, "exactly once") {
			found = true
		}
	}
	if !found {
		t.Fatalf("limitations %v do not report exactly-once import unwrapping", receipt.Limitations)
	}
	// Distinct imports are both applied.
	other := string(evidence_codec.HashBytes([]byte("imported-source-2")))
	cmd2 := jobCommand(t, m.RunID, "job-k2", 0, "job-1")
	events := []JournalEnvelope{
		{Sequence: 1, EventKind: "session_opened", Role: "lifecycle_observation", Payload: journal_rules.Payload{Data: map[string]any{"import_digest": digest}}},
		{Sequence: 2, EventKind: "session_opened", Role: "lifecycle_observation", Payload: journal_rules.Payload{Data: map[string]any{"import_digest": other}}},
		{Sequence: 3, EventKind: "session_opened", Role: "lifecycle_observation", Payload: journal_rules.Payload{Data: map[string]any{"import_digest": digest}}},
	}
	_ = cmd2
	deduped2, skipped2 := unwrapImportedInputs(events)
	if len(deduped2) != 2 || skipped2 != 1 {
		t.Fatalf("distinct imports: deduped %d skipped %d, want 2 and 1", len(deduped2), skipped2)
	}
}

func TestReplayUsesRecordedTimingWithoutSleeping(t *testing.T) {
	f := newFixture(t, "replay-timing")
	m := testManifest(f.domain, "journal-timing")
	// One hour of recorded offset must not cost one hour of wall time.
	hourLater := testTimePoint(m, 3600000)
	admission := admitJournal(t, f.ctx, f.store, m)
	config := testConfig(t)
	classRef := installArtifact(t, f.ctx, f.store, []byte(`{"classifier":"v1"}`), "application/json", "public")
	registryRef := installArtifact(t, f.ctx, f.store, []byte(`{"requirements":"v1"}`), "application/json", "public")
	classifier := VersionPin{ID: "classifier", Version: "v1", ArtifactDigest: classRef.Digest}
	registry := VersionPin{ID: "requirements", Version: "v1", ArtifactDigest: registryRef.Digest}
	cmd := jobCommand(t, m.RunID, "job-k1", 0, "job-1")
	inputs := commitEvents(t, f.ctx, f.store, m.JournalID, []owner_store.EventSubmission{
		eventSubmissionAt(m, 2, "session_opened", map[string]any{
			"fixture_command": commandAsMap(t, cmd),
		}, hourLater),
	})
	reqData := analysisRequestedData(classifier, registry, "diag-journal-timing", 1, testSubjectMap())
	closing := commitEvents(t, f.ctx, f.store, m.JournalID, []owner_store.EventSubmission{
		eventSubmission(m, 3, "analysis_requested", reqData, []journal_rules.ArtifactReference{classRef, registryRef}),
	})
	events := append(append([]journal_rules.JournalEnvelope{}, admission...), inputs...)
	events = append(events, closing...)
	prefix := prefixThrough(events)
	consumed, _ := filterReplayInputs(events)
	deduped, _ := unwrapImportedInputs(consumed)
	semantic, final, missing, detail := runFixtureReplay(m, config, deduped)
	if missing != nil {
		t.Fatalf("record-time fixture replay: %s", detail)
	}
	provisional := DiagnosticDocument{
		RecordType: "diagnostic", SchemaVersion: "1.0.0",
		DiagnosticID: "diag-journal-timing", AnalysisRevision: 1,
		RunID: m.RunID, ManifestHash: string(evidence_codec.HashBytes(canonicalBytes(t, m))),
		InputPrefix: prefix, AnalysisRequestRef: eventRef(events[len(events)-1]),
		Classifier: classifier, RequirementRegistry: registry,
		FixRegistry:  journal_rules.NewMissing("not_enabled"),
		EvidenceRefs: []journal_rules.EvidenceRef{eventRef(events[len(events)-1])},
		Artifacts:    []journal_rules.ArtifactReference{classRef, registryRef},
		Extra: map[string]any{
			extraSemanticDigest: semantic, extraFinalDigest: final,
			extraConfig: configAsExtra(t, config), extraSubject: testSubjectMap(),
		},
	}
	diagDigest, dmissing, dDetail := rederiveDiagnosticDigest(m, events, provisional, config)
	if dmissing != nil {
		t.Fatalf("record-time diagnostic: %s", dDetail)
	}
	provisional.Extra[extraDiagDigest] = diagDigest
	row := buildTestRow(t, f.ctx, f.store, sessionRegistration("session-timing"), prefix, events)
	bundle, err := evidence_bundle.ExportReplayInputs(f.ctx, f.store, row, provisional)
	if err != nil {
		t.Fatalf("ExportReplayInputs: %v", err)
	}
	source := installArtifact(t, f.ctx, f.store, canonicalBytes(t, provisional), "application/json", "public")

	start := time.Now()
	receipt, err := ReplayBundle(f.ctx, f.store, bundle, source, "exact_fixture")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("ReplayBundle(timing): %v", err)
	}
	if receipt.Result != "matched" {
		t.Fatalf("timing result = %q, want matched", receipt.Result)
	}
	if elapsed >= 30*time.Second {
		t.Fatalf("replay took %v with one hour of recorded offset; it must not sleep", elapsed)
	}
	// Recorded timing is input: different offsets yield different
	// semantic digests.
	early := testTimePoint(m, 10)
	late := testTimePoint(m, 3600000)
	evEarly := JournalEnvelope{Sequence: 1, EventKind: "session_opened", Role: "lifecycle_observation",
		Payload: journal_rules.Payload{Data: map[string]any{"marker": "x"}}, OccurredAt: early, RecordedAt: early}
	evLate := evEarly
	evLate.OccurredAt = late
	projEarly, err := semanticProjectionFromInputs([]JournalEnvelope{evEarly})
	if err != nil {
		t.Fatalf("projection(early): %v", err)
	}
	projLate, err := semanticProjectionFromInputs([]JournalEnvelope{evLate})
	if err != nil {
		t.Fatalf("projection(late): %v", err)
	}
	if bytes.Equal(projEarly, projLate) {
		t.Fatalf("recorded timing does not affect the semantic projection; timing must remain input")
	}
}

func TestExactFixtureMatchRequiresAllThreeEqualComparisons(t *testing.T) {
	f := newFixture(t, "replay-three")
	m := testManifest(f.domain, "journal-three")
	scenario := buildScenario(t, f, "journal-three", "session-three", []owner_store.EventSubmission{
		eventSubmission(m, 2, "session_opened", map[string]any{
			"fixture_command": commandAsMap(t, jobCommand(t, m.RunID, "job-k1", 0, "job-1")),
		}, nil),
	}, nil)
	receipt, err := ReplayBundle(f.ctx, f.store, scenario.bundle, scenario.source, "exact_fixture")
	if err != nil {
		t.Fatalf("ReplayBundle(exact): %v", err)
	}
	if len(receipt.Comparisons) != 3 {
		t.Fatalf("exact comparisons = %d, want 3", len(receipt.Comparisons))
	}
	for _, want := range []string{"semantic_events", "final_state", "diagnostic"} {
		c := comparisonByOutput(receipt, want)
		if c == nil {
			t.Fatalf("exact receipt omits %q comparison", want)
		}
		if c.Result != "matched" {
			t.Fatalf("%s result = %q, want matched", want, c.Result)
		}
	}
	if receipt.Result != "matched" {
		t.Fatalf("exact result = %q, want matched", receipt.Result)
	}
	if _, ok := asVersionPin(receipt.Reducer); !ok {
		t.Fatalf("exact reducer = %#v, want a VersionPin", receipt.Reducer)
	}
	// Aggregate precedence: mismatched dominates unavailable dominates matched.
	zero := "sha256:" + strings.Repeat("0", 64)
	one := string(evidence_codec.HashBytes([]byte("one")))
	two := string(evidence_codec.HashBytes([]byte("two")))
	matched := compareDigests("semantic_events", one, true, one, nil)
	if matched.Result != "matched" {
		t.Fatalf("equal digests = %q, want matched", matched.Result)
	}
	mismatched := compareDigests("semantic_events", one, true, two, nil)
	if mismatched.Result != "mismatched" {
		t.Fatalf("unequal digests = %q, want mismatched", mismatched.Result)
	}
	miss := newMissing("not_observed", "")
	unavailable := compareDigests("semantic_events", one, true, "", &miss)
	if unavailable.Result != "unavailable" {
		t.Fatalf("missing actual = %q, want unavailable", unavailable.Result)
	}
	if got := aggregateResult([]ReplayComparison{matched, matched, matched}); got != "matched" {
		t.Fatalf("all matched aggregates to %q", got)
	}
	if got := aggregateResult([]ReplayComparison{matched, unavailable, matched}); got != "unavailable" {
		t.Fatalf("matched+unavailable aggregates to %q, want unavailable", got)
	}
	if got := aggregateResult([]ReplayComparison{unavailable, mismatched, matched}); got != "mismatched" {
		t.Fatalf("unavailable+mismatched aggregates to %q, want mismatched", got)
	}
	_ = zero
	// Diagnostic-only requires only the diagnostic comparison.
	diagReceipt, err := ReplayBundle(f.ctx, f.store, scenario.bundle, scenario.source, "diagnostic_only")
	if err != nil {
		t.Fatalf("ReplayBundle(diagnostic_only): %v", err)
	}
	if len(diagReceipt.Comparisons) != 1 || diagReceipt.Comparisons[0].Output != "diagnostic" {
		t.Fatalf("diagnostic-only comparisons = %+v, want exactly [diagnostic]", diagReceipt.Comparisons)
	}
	if missing, ok := asMissingEnvelope(diagReceipt.Reducer); !ok || missing.Reason != "not_applicable" {
		t.Fatalf("diagnostic-only reducer = %#v, want Missing(not_applicable)", diagReceipt.Reducer)
	}
}

func TestDiagnosticOnlyReplayCannotRepeatEmployerMutations(t *testing.T) {
	f := newFixture(t, "replay-employer")
	m := testManifest(f.domain, "journal-employer")
	admission := admitJournal(t, f.ctx, f.store, m)
	config := testConfig(t)
	classRef := installArtifact(t, f.ctx, f.store, []byte(`{"classifier":"v1"}`), "application/json", "public")
	registryRef := installArtifact(t, f.ctx, f.store, []byte(`{"requirements":"v1"}`), "application/json", "public")
	classifier := VersionPin{ID: "classifier", Version: "v1", ArtifactDigest: classRef.Digest}
	registry := VersionPin{ID: "requirements", Version: "v1", ArtifactDigest: registryRef.Digest}
	// An employer mutation smuggled into a consumed input.
	employerCmd := fixture_reducer.EventSubmission{
		OperationKey: "employer-k1", OperationKind: "employer-submit", AttemptID: m.RunID,
		ExpectedRevision: 0, Payload: fixtureCommandPayload(t, map[string]any{"employer_mutation": true}),
	}
	inputs := commitEvents(t, f.ctx, f.store, m.JournalID, []owner_store.EventSubmission{
		eventSubmission(m, 2, "session_opened", map[string]any{
			"fixture_command":   commandAsMap(t, employerCmd),
			"target_origin":     "employer",
			"employer_mutation": true,
		}, nil),
	})
	reqData := analysisRequestedData(classifier, registry, "diag-journal-employer", 1, testSubjectMap())
	closing := commitEvents(t, f.ctx, f.store, m.JournalID, []owner_store.EventSubmission{
		eventSubmission(m, 3, "analysis_requested", reqData, []journal_rules.ArtifactReference{classRef, registryRef}),
	})
	events := append(append([]journal_rules.JournalEnvelope{}, admission...), inputs...)
	events = append(events, closing...)
	prefix := prefixThrough(events)
	// The recorded diagnostic pins only the diagnostic digest: fixture
	// replay is expected to refuse the employer mutation, so no semantic
	// or final digests are pinned.
	provisional := DiagnosticDocument{
		RecordType: "diagnostic", SchemaVersion: "1.0.0",
		DiagnosticID: "diag-journal-employer", AnalysisRevision: 1,
		RunID: m.RunID, ManifestHash: string(evidence_codec.HashBytes(canonicalBytes(t, m))),
		InputPrefix: prefix, AnalysisRequestRef: eventRef(events[len(events)-1]),
		Classifier: classifier, RequirementRegistry: registry,
		FixRegistry:  journal_rules.NewMissing("not_enabled"),
		EvidenceRefs: []journal_rules.EvidenceRef{eventRef(events[len(events)-1])},
		Artifacts:    []journal_rules.ArtifactReference{classRef, registryRef},
		Extra: map[string]any{
			extraConfig:  configAsExtra(t, config),
			extraSubject: testSubjectMap(),
		},
	}
	diagDigest, dmissing, dDetail := rederiveDiagnosticDigest(m, events, provisional, config)
	if dmissing != nil {
		t.Fatalf("record-time diagnostic with employer input: %s", dDetail)
	}
	provisional.Extra[extraDiagDigest] = diagDigest
	row := buildTestRow(t, f.ctx, f.store, sessionRegistration("session-employer"), prefix, events)
	bundle, err := evidence_bundle.ExportReplayInputs(f.ctx, f.store, row, provisional)
	if err != nil {
		t.Fatalf("ExportReplayInputs: %v", err)
	}
	source := installArtifact(t, f.ctx, f.store, canonicalBytes(t, provisional), "application/json", "public")

	before, err := owner_store.LoadPrefix(f.ctx, f.store, prefix)
	if err != nil {
		t.Fatalf("LoadPrefix(before): %v", err)
	}
	for _, mode := range []string{"diagnostic_only", "diagnostic_rederivation"} {
		receipt, err := ReplayBundle(f.ctx, f.store, bundle, source, mode)
		if err != nil {
			t.Fatalf("ReplayBundle(%s): %v", mode, err)
		}
		if receipt.Mode != "diagnostic_only" {
			t.Fatalf("mode %s normalized to %q, want diagnostic_only", mode, receipt.Mode)
		}
		if missing, ok := asMissingEnvelope(receipt.Reducer); !ok || missing.Reason != "not_applicable" {
			t.Fatalf("mode %s reducer = %#v, want Missing(not_applicable)", mode, receipt.Reducer)
		}
		if len(receipt.Comparisons) != 1 || receipt.Comparisons[0].Output != "diagnostic" {
			t.Fatalf("mode %s comparisons = %+v, want exactly [diagnostic]", mode, receipt.Comparisons)
		}
		if receipt.Comparisons[0].Result != "matched" {
			t.Fatalf("mode %s diagnostic = %q, want matched (limitations %v)", mode, receipt.Comparisons[0].Result, receipt.Limitations)
		}
		if receipt.InvokedBrowser || receipt.InvokedSubject || receipt.PerformedExternalWrites {
			t.Fatalf("mode %s invocation flags must all be false", mode)
		}
		after, err := owner_store.LoadPrefix(f.ctx, f.store, prefix)
		if err != nil {
			t.Fatalf("LoadPrefix(after %s): %v", mode, err)
		}
		if len(after) != len(before) {
			t.Fatalf("mode %s committed %d new events; diagnostic replay must not repeat mutations", mode, len(after)-len(before))
		}
	}
	// Exact fixture replay refuses the employer mutation instead of
	// applying it: the fixture comparisons are unavailable, never matched.
	exact, err := ReplayBundle(f.ctx, f.store, bundle, source, "exact_fixture")
	if err != nil {
		t.Fatalf("ReplayBundle(exact with employer): %v", err)
	}
	if exact.Result == "matched" {
		t.Fatalf("exact replay with an employer mutation must never match (comparisons %+v)", exact.Comparisons)
	}
	semantic := comparisonByOutput(exact, "semantic_events")
	if semantic == nil || semantic.Result != "unavailable" {
		t.Fatalf("employer semantic comparison = %+v, want unavailable", semantic)
	}
	_ = diagnostic_reducer.VersionPin{}
}

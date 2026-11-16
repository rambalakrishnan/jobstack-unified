package analysis_owner

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"authority"
	"evidence_codec"
	journal_rules "journal_rules"
	"owner_store"
)

// ---------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------

func testPolicy() []byte {
	return []byte(`{"channels":{"test-channel":{"principal":"test-writer","kind":"owner","grants":[{"domain":"*","operations":["*"]}]}}}`)
}

func authedContext(t *testing.T) context.Context {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "http://analysis.test/direct", nil)
	if err != nil {
		t.Fatalf("build auth request: %v", err)
	}
	req.Header.Set("Authorization", "Channel test-channel")
	ctx, err := authority.Authenticate(req, testPolicy())
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	return ctx
}

func openStore(t *testing.T, domain string) (*OwnerStore, string) {
	t.Helper()
	home := t.TempDir()
	artifactRoot := filepath.Join(home, domain+"-artifacts")
	store, err := owner_store.OpenOwner(
		filepath.Join(home, domain+".db"),
		artifactRoot,
		domain,
	)
	if err != nil {
		t.Fatalf("OpenOwner(%s): %v", domain, err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store, artifactRoot
}

func testDigest(seed string) string {
	return string(evidence_codec.HashBytes([]byte("analysis-owner-test/"+seed)))
}

func testClassifier() VersionPin {
	return VersionPin{ID: "classifier", Version: "v1", ArtifactDigest: testDigest("classifier")}
}

func testRegistry() VersionPin {
	return VersionPin{ID: "req-registry", Version: "v1", ArtifactDigest: testDigest("registry")}
}

func testManifest(suffix string) Manifest {
	return Manifest{
		RecordType:     "manifest",
		SchemaVersion:  "1.0.0",
		ManifestID:     "manifest-" + suffix,
		RunID:          "run-" + suffix,
		JournalID:      "journal-" + suffix,
		OwnerDomain:    "diagnostic",
		CommissionerID: "commissioner-1",
		Activity:       "application_attempt",
		Attempt: AttemptContext{
			Kind: "practice", Context: "laboratory_fixture", Scope: "held_in",
			SubjectVersion: "subject-1.0", Assistance: "none",
		},
		Execution:       map[string]any{"mode": "subject"},
		Task:            map[string]any{"task_id": "task-1"},
		TaskSemanticHash: testDigest("task"),
		Environment:     map[string]any{"deployment": "laboratory"},
		Seed:            "seed-1",
		BuildPins:       map[string]string{"fixture": "1.0.0"},
		EventRegistry:   map[string]string{"kind1": "v1"},
		Producers:       []map[string]any{{"producer_id": "p1"}},
		Clocks: []ClockDescriptor{
			{ClockID: "engine-clock", BootID: "boot-1", Origin: "engine_measured", SourceID: "engine", Basis: "monotonic_offset", Unit: "ms"},
			{ClockID: "manual-clock", BootID: "boot-1", Origin: "manual_reference", SourceID: "operator", Basis: "monotonic_offset", Unit: "ms"},
			{ClockID: "subject-clock", BootID: "boot-1", Origin: "subject_reported", SourceID: "subject", Basis: "opaque_report", Unit: "ms"},
		},
		Profile: "M1",
		Subject: SubjectDescriptor{Name: "subject-A", Version: "subject-1.0"},
		Lineage: LineageLinks{Kind: "practice"},
	}
}

func testSubject() SubjectIdentity {
	return SubjectIdentity{
		SubjectID: "subject-A", SubjectVersion: "subject-1.0",
		ConfiguredMode: "auto", InterfaceSurface: "web",
	}
}

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
	}
	out, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("cannot encode config: %v", err)
	}
	return out
}

func testRequest(t *testing.T, revision int64) AnalysisRequest {
	t.Helper()
	return AnalysisRequest{
		DiagnosticID:        "diag-1",
		AnalysisRevision:    revision,
		Classifier:          testClassifier(),
		RequirementRegistry: testRegistry(),
		FixRegistry:         owner_store.NewMissing("not_enabled"),
		Configuration:       testConfig(t),
		ManualMode:          false,
		Subject:             testSubject(),
	}
}

func artifactMap(ref ArtifactReference) map[string]any {
	return map[string]any{
		"digest":       ref.Digest,
		"size_bytes":   ref.SizeBytes,
		"media_type":   ref.MediaType,
		"owner_domain": ref.OwnerDomain,
		"access":       ref.Access,
	}
}

// admitSourceJournal creates the source journal in the store with the exact
// manifest projection DeriveDiagnostic recomputes, and returns the admission
// envelopes.
func admitSourceJournal(t *testing.T, ctx context.Context, store *OwnerStore, manifest Manifest) []JournalEnvelope {
	t.Helper()
	journalManifest := owner_store.Manifest{
		RecordType:    manifest.RecordType,
		SchemaVersion: manifest.SchemaVersion,
		ManifestID:    manifest.ManifestID,
		RunID:         manifest.RunID,
		JournalID:     manifest.JournalID,
		OwnerDomain:   manifest.OwnerDomain,
		Clocks:        append([]owner_store.ClockDescriptor(nil), manifest.Clocks...),
	}
	raw, err := json.Marshal(journalManifest)
	if err != nil {
		t.Fatalf("marshal journal manifest: %v", err)
	}
	canonical, err := evidence_codec.CanonicalJSON(raw, "application/json")
	if err != nil {
		t.Fatalf("canonicalize journal manifest: %v", err)
	}
	ref, err := owner_store.InstallArtifact(ctx, store, bytes.NewReader(canonical), "application/json", "public")
	if err != nil {
		t.Fatalf("install journal manifest: %v", err)
	}
	admission := EventSubmission{
		ProducerSequence:   owner_store.NewMissing("not_applicable"),
		EventKind:          "manifest_admitted",
		EventSchemaVersion: "1.0.0",
		OccurredAt:         owner_store.NewMissing("not_observed"),
		Payload: owner_store.Payload{
			Data:         map[string]any{"manifest": artifactMap(ref)},
			Measurements: []owner_store.Measurement{},
			EvidenceRefs: []EvidenceRef{},
			ArtifactRefs: []ArtifactReference{ref},
		},
	}
	envelopes, err := AppendSourceEvents(ctx, store, manifest.JournalID, []EventSubmission{admission})
	if err != nil {
		t.Fatalf("admit source journal: %v", err)
	}
	return envelopes
}

func outcomeSubmission(requirementID, outcome string) EventSubmission {
	return EventSubmission{
		ProducerSequence:   owner_store.NewMissing("not_applicable"),
		EventKind:          "observation_noted",
		EventSchemaVersion: "1.0.0",
		OccurredAt:         owner_store.NewMissing("not_observed"),
		Payload: owner_store.Payload{
			Data: map[string]any{
				"requirement_outcome": map[string]any{
					"requirement_id":         requirementID,
					"observed_outcome":       outcome,
					"controls_valid":         true,
					"has_supporting_evidence": true,
				},
			},
			Measurements: []owner_store.Measurement{},
			EvidenceRefs: []EvidenceRef{},
			ArtifactRefs: []ArtifactReference{},
		},
	}
}

func testTimePoint(offset float64) owner_store.TimePoint {
	return owner_store.TimePoint{
		ClockID: "engine-clock", BootID: "boot-1", Origin: "engine_measured",
		MonotonicOffsetMs: offset, UTCAnnotation: owner_store.NewMissing("not_applicable"),
	}
}

func measurementSubmission() EventSubmission {
	measurement := owner_store.Measurement{
		MeasurementID: "workflow-elapsed-1", Name: "workflow_elapsed",
		Scope:    journal_rules.Scope{Kind: "workflow_step", ID: "pause-1"},
		Quantity: "duration", Unit: "ms", Origin: "engine_measured",
		ClockID: "engine-clock", BootID: "boot-1", Method: "endpoint_difference",
		Start: testTimePoint(200), End: testTimePoint(230),
		Estimate:           journal_rules.Estimate{Kind: "exact", Value: 30.0},
		Resolution:         owner_store.NewMissing("not_applicable"),
		Censoring:          "none",
		ComparabilityGroup: owner_store.NewMissing("not_applicable"),
	}
	return EventSubmission{
		ProducerSequence:   owner_store.NewMissing("not_applicable"),
		EventKind:          "observation_noted",
		EventSchemaVersion: "1.0.0",
		OccurredAt:         owner_store.NewMissing("not_observed"),
		Payload: owner_store.Payload{
			Data:         map[string]any{"note": "timing observed"},
			Measurements: []owner_store.Measurement{measurement},
			EvidenceRefs: []EvidenceRef{},
			ArtifactRefs: []ArtifactReference{},
		},
	}
}

func exposureSubmission() EventSubmission {
	return EventSubmission{
		ProducerSequence:   owner_store.NewMissing("not_applicable"),
		EventKind:          "observation_noted",
		EventSchemaVersion: "1.0.0",
		OccurredAt:         owner_store.NewMissing("not_observed"),
		Payload: owner_store.Payload{
			Data: map[string]any{
				"feature_exposure": map[string]any{
					"feature_id": "feat-contact-form", "configured": true,
					"rendered_armed": true, "exposed": true, "activated": false,
					"requirement_ref": "R1",
				},
			},
			Measurements: []owner_store.Measurement{},
			EvidenceRefs: []EvidenceRef{},
			ArtifactRefs: []ArtifactReference{},
		},
	}
}

func claimSubmission() EventSubmission {
	return EventSubmission{
		ProducerSequence:   owner_store.NewMissing("not_applicable"),
		EventKind:          "observation_noted",
		EventSchemaVersion: "1.0.0",
		OccurredAt:         owner_store.NewMissing("not_observed"),
		Payload: owner_store.Payload{
			Data: map[string]any{
				"subject_claim": map[string]any{
					"claim_id": "claim-late-1", "source": "subject",
					"scope": "execution", "proposition": "late work completed",
				},
			},
			Measurements: []owner_store.Measurement{},
			EvidenceRefs: []EvidenceRef{},
			ArtifactRefs: []ArtifactReference{},
		},
	}
}

// requestSubmission builds the analysis_requested event pinning exactly the
// given request's identity, revision, and registries.
func requestSubmission(request AnalysisRequest) EventSubmission {
	return EventSubmission{
		ProducerSequence:   owner_store.NewMissing("not_applicable"),
		EventKind:          "analysis_requested",
		EventSchemaVersion: "1.0.0",
		OccurredAt:         owner_store.NewMissing("not_observed"),
		Payload: owner_store.Payload{
			Data: map[string]any{
				"diagnostic_id":     request.DiagnosticID,
				"analysis_revision": request.AnalysisRevision,
				"classifier": map[string]any{
					"id": request.Classifier.ID, "version": request.Classifier.Version,
					"artifact_digest": request.Classifier.ArtifactDigest,
				},
				"requirement_registry": map[string]any{
					"id": request.RequirementRegistry.ID, "version": request.RequirementRegistry.Version,
					"artifact_digest": request.RequirementRegistry.ArtifactDigest,
				},
				"fix_registry": owner_store.NewMissing("not_enabled"),
			},
			Measurements: []owner_store.Measurement{},
			EvidenceRefs: []EvidenceRef{},
			ArtifactRefs: []ArtifactReference{},
		},
	}
}

func readArtifact(t *testing.T, ctx context.Context, store *OwnerStore, ref ArtifactReference) []byte {
	t.Helper()
	raw, err := owner_store.ReadArtifact(ctx, store, ref)
	if err != nil {
		t.Fatalf("ReadArtifact(%s): %v", ref.Digest, err)
	}
	return raw
}

func assessmentResult(doc DiagnosticDocument, requirementID string) (string, bool) {
	for _, assessment := range doc.RequirementAssessments {
		if assessment.RequirementID == requirementID {
			return assessment.Result, true
		}
	}
	return "", false
}

// ---------------------------------------------------------------------------
// Conformance assertions.
// ---------------------------------------------------------------------------

func TestAnalysisPrefixEndsAtItsPinnedAnalysisRequestedEvent(t *testing.T) {
	ctx := authedContext(t)
	store, _ := openStore(t, "diagnostic")
	manifest := testManifest("pin")
	admitSourceJournal(t, ctx, store, manifest)

	request := testRequest(t, 1)
	committed, err := AppendSourceEvents(ctx, store, manifest.JournalID, []EventSubmission{
		outcomeSubmission("R1", "satisfied"),
		measurementSubmission(),
		exposureSubmission(),
		requestSubmission(request),
	})
	if err != nil {
		t.Fatalf("commit source prefix: %v", err)
	}
	requestEvent := committed[len(committed)-1]
	if requestEvent.EventKind != "analysis_requested" {
		t.Fatalf("expected analysis_requested, got %q", requestEvent.EventKind)
	}

	document, err := AnalyzeSession(ctx, store, manifest, request)
	if err != nil {
		t.Fatalf("AnalyzeSession: %v", err)
	}
	if document.DiagnosticID != request.DiagnosticID || document.AnalysisRevision != 1 {
		t.Fatalf("unexpected diagnostic identity: %+v", document.DiagnosticID)
	}
	// The diagnostic cites the exact request-ending prefix, not the head.
	if document.InputPrefix.JournalID != manifest.JournalID ||
		document.InputPrefix.LastSequence != requestEvent.Sequence ||
		document.InputPrefix.HeadHash != requestEvent.EventHash {
		t.Fatalf("input prefix %+v does not end at the pinned request seq %d hash %s",
			document.InputPrefix, requestEvent.Sequence, requestEvent.EventHash)
	}
	wantRef := EvidenceRef{
		JournalID: requestEvent.JournalID, Sequence: requestEvent.Sequence,
		EventID: requestEvent.EventID, EventHash: requestEvent.EventHash, Pointer: "",
	}
	if document.AnalysisRequestRef != wantRef {
		t.Fatalf("analysis request ref %+v, want %+v", document.AnalysisRequestRef, wantRef)
	}
	if document.Classifier != request.Classifier || document.RequirementRegistry != request.RequirementRegistry {
		t.Fatalf("diagnostic pins do not match the pinned request")
	}
	// Joined evidence survived the owner round-trip.
	if len(document.Measurements) != 1 {
		t.Fatalf("expected 1 preserved measurement, got %d", len(document.Measurements))
	}
	if len(document.FeatureExposures) != 1 || document.FeatureExposures[0].FeatureID != "feat-contact-form" {
		t.Fatalf("expected the joined feature exposure, got %+v", document.FeatureExposures)
	}

	// A revision with no journal pin is rejected, never derived.
	missing := testRequest(t, 2)
	if _, err := AnalyzeSession(ctx, store, manifest, missing); err == nil {
		t.Fatalf("expected an error for a revision with no analysis_requested pin")
	} else if !strings.Contains(err.Error(), "no analysis_requested") {
		t.Fatalf("unexpected error for missing pin: %v", err)
	}

	// A request that disagrees with the journal pin is rejected: the
	// journal pin wins over the caller's asking values.
	tampered := testRequest(t, 1)
	tampered.Classifier.ArtifactDigest = testDigest("other-classifier")
	if _, err := AnalyzeSession(ctx, store, manifest, tampered); err == nil {
		t.Fatalf("expected a pin-mismatch error for a tampered classifier")
	} else if !strings.Contains(err.Error(), "classifier") {
		t.Fatalf("unexpected error for tampered classifier: %v", err)
	}

	// Late evidence past the pinned request does not move the pin: the
	// head advances but revision 1 still resolves to its request prefix.
	firstBytes := readArtifact(t, ctx, store, mustValue(t, ctx, store, manifest, "diag-1", 1).DiagnosticArtifact)
	if _, err := AppendSourceEvents(ctx, store, manifest.JournalID, []EventSubmission{
		outcomeSubmission("R3", "satisfied"),
	}); err != nil {
		t.Fatalf("append late evidence: %v", err)
	}
	again, err := AnalyzeSession(ctx, store, manifest, testRequest(t, 1))
	if err != nil {
		t.Fatalf("AnalyzeSession after late evidence: %v", err)
	}
	if again.InputPrefix != document.InputPrefix {
		t.Fatalf("pinned prefix moved: %+v vs %+v", again.InputPrefix, document.InputPrefix)
	}
	againBytes := readArtifact(t, ctx, store, mustValue(t, ctx, store, manifest, "diag-1", 1).DiagnosticArtifact)
	if !bytes.Equal(firstBytes, againBytes) {
		t.Fatalf("revision 1 bytes changed after late evidence arrived")
	}
	// The retry replayed the registration instead of duplicating it.
	head, ok := DiagnosticHead(store, manifest)
	if !ok {
		t.Fatalf("diagnostic head is missing after analysis")
	}
	diagnosticEvents, err := owner_store.LoadPrefix(ctx, store, head)
	if err != nil {
		t.Fatalf("load diagnostic journal: %v", err)
	}
	if len(diagnosticEvents) != 2 {
		t.Fatalf("expected admission plus one registration, got %d events", len(diagnosticEvents))
	}
}

func TestLateEvidenceProducesNewImmutableDiagnosticRevision(t *testing.T) {
	ctx := authedContext(t)
	store, _ := openStore(t, "diagnostic")
	manifest := testManifest("late")
	admitSourceJournal(t, ctx, store, manifest)

	first := testRequest(t, 1)
	if _, err := AppendSourceEvents(ctx, store, manifest.JournalID, []EventSubmission{
		outcomeSubmission("R1", "satisfied"),
		requestSubmission(first),
	}); err != nil {
		t.Fatalf("commit revision 1 prefix: %v", err)
	}
	document1, err := AnalyzeSession(ctx, store, manifest, first)
	if err != nil {
		t.Fatalf("AnalyzeSession(rev1): %v", err)
	}
	value1 := mustValue(t, ctx, store, manifest, "diag-1", 1)
	bytes1 := readArtifact(t, ctx, store, value1.DiagnosticArtifact)

	// Late evidence arrives at the head with a new request pin.
	second := testRequest(t, 2)
	late, err := AppendSourceEvents(ctx, store, manifest.JournalID, []EventSubmission{
		outcomeSubmission("R2", "violated"),
		claimSubmission(),
		requestSubmission(second),
	})
	if err != nil {
		t.Fatalf("commit late evidence: %v", err)
	}
	lateRequest := late[len(late)-1]
	document2, err := AnalyzeSession(ctx, store, manifest, second)
	if err != nil {
		t.Fatalf("AnalyzeSession(rev2): %v", err)
	}
	if document2.AnalysisRevision != 2 {
		t.Fatalf("expected analysis revision 2, got %d", document2.AnalysisRevision)
	}
	if document2.InputPrefix.LastSequence != lateRequest.Sequence || document2.InputPrefix.HeadHash != lateRequest.EventHash {
		t.Fatalf("revision 2 prefix %+v does not end at its request seq %d", document2.InputPrefix, lateRequest.Sequence)
	}
	// The new revision reflects the late evidence.
	before, okBefore := assessmentResult(document1, "R2")
	after, okAfter := assessmentResult(document2, "R2")
	if !okBefore || !okAfter {
		t.Fatalf("R2 assessment missing in one revision")
	}
	if before == after {
		t.Fatalf("late evidence did not change the R2 assessment: still %q", after)
	}
	if after != "violated" {
		t.Fatalf("expected R2 violated after late evidence, got %q", after)
	}
	if len(document2.Claims) != 1 || document2.Claims[0].ClaimID != "claim-late-1" {
		t.Fatalf("expected the late subject claim in revision 2, got %+v", document2.Claims)
	}

	// The prior revision, seal, and publication are preserved.
	value1Again := mustValue(t, ctx, store, manifest, "diag-1", 1)
	if value1Again.DiagnosticDigest != value1.DiagnosticDigest ||
		value1Again.DiagnosticArtifact.Digest != value1.DiagnosticArtifact.Digest ||
		value1Again.InputPrefix != value1.InputPrefix {
		t.Fatalf("revision 1 domain value changed after reanalysis")
	}
	if !bytes.Equal(readArtifact(t, ctx, store, value1Again.DiagnosticArtifact), bytes1) {
		t.Fatalf("revision 1 bytes changed after reanalysis")
	}
	if bytes.Equal(readArtifact(t, ctx, store, mustValue(t, ctx, store, manifest, "diag-1", 2).DiagnosticArtifact), bytes1) {
		t.Fatalf("revision 2 bytes unexpectedly equal revision 1 bytes")
	}
}

func TestEarlierDiagnosticBytesRemainUnchangedAfterReanalysis(t *testing.T) {
	ctx := authedContext(t)
	store, _ := openStore(t, "diagnostic")
	manifest := testManifest("stable")
	admitSourceJournal(t, ctx, store, manifest)

	if _, err := AppendSourceEvents(ctx, store, manifest.JournalID, []EventSubmission{
		outcomeSubmission("R1", "satisfied"),
		measurementSubmission(),
		requestSubmission(testRequest(t, 1)),
	}); err != nil {
		t.Fatalf("commit revision 1 prefix: %v", err)
	}
	if _, err := AnalyzeSession(ctx, store, manifest, testRequest(t, 1)); err != nil {
		t.Fatalf("AnalyzeSession(rev1): %v", err)
	}
	original := mustValue(t, ctx, store, manifest, "diag-1", 1)
	diagnosticBytes := readArtifact(t, ctx, store, original.DiagnosticArtifact)
	reportBytes := readArtifact(t, ctx, store, original.ReportJSONArtifact)
	readableBytes := readArtifact(t, ctx, store, original.ReadableArtifact)

	// Reanalysis over a new input pin must not touch earlier bytes.
	if _, err := AppendSourceEvents(ctx, store, manifest.JournalID, []EventSubmission{
		outcomeSubmission("R4", "violated"),
		requestSubmission(testRequest(t, 2)),
	}); err != nil {
		t.Fatalf("commit revision 2 prefix: %v", err)
	}
	if _, err := AnalyzeSession(ctx, store, manifest, testRequest(t, 2)); err != nil {
		t.Fatalf("AnalyzeSession(rev2): %v", err)
	}
	preserved := mustValue(t, ctx, store, manifest, "diag-1", 1)
	if preserved.DiagnosticArtifact.Digest != original.DiagnosticArtifact.Digest ||
		preserved.ReportJSONArtifact.Digest != original.ReportJSONArtifact.Digest ||
		preserved.ReadableArtifact.Digest != original.ReadableArtifact.Digest ||
		preserved.InputPrefix != original.InputPrefix ||
		preserved.AnalysisRequestRef != original.AnalysisRequestRef {
		t.Fatalf("revision 1 pins changed after reanalysis")
	}
	if !bytes.Equal(readArtifact(t, ctx, store, preserved.DiagnosticArtifact), diagnosticBytes) {
		t.Fatalf("revision 1 diagnostic bytes changed after reanalysis")
	}
	if !bytes.Equal(readArtifact(t, ctx, store, preserved.ReportJSONArtifact), reportBytes) {
		t.Fatalf("revision 1 report bytes changed after reanalysis")
	}
	if !bytes.Equal(readArtifact(t, ctx, store, preserved.ReadableArtifact), readableBytes) {
		t.Fatalf("revision 1 readable bytes changed after reanalysis")
	}
	// And the new revision is genuinely new bytes.
	revised := mustValue(t, ctx, store, manifest, "diag-1", 2)
	if bytes.Equal(readArtifact(t, ctx, store, revised.DiagnosticArtifact), diagnosticBytes) {
		t.Fatalf("revision 2 diagnostic bytes unexpectedly equal revision 1")
	}
}

func TestDiagnosticStorageFailureCannotFabricatePublishedReport(t *testing.T) {
	ctx := authedContext(t)

	// Unknown source: no head, no evidence, no diagnostic.
	t.Run("unknown source", func(t *testing.T) {
		store, _ := openStore(t, "diagnostic")
		manifest := testManifest("unknown")
		document, err := AnalyzeSession(ctx, store, manifest, testRequest(t, 1))
		if err == nil {
			t.Fatalf("expected an error with no recorded source head")
		}
		if !strings.Contains(err.Error(), "unknown source") {
			t.Fatalf("unexpected error: %v", err)
		}
		if document.DiagnosticID != "" {
			t.Fatalf("fabricated a diagnostic without evidence: %+v", document.DiagnosticID)
		}
	})

	// Closed store: every read fails, nothing is derived.
	t.Run("closed store", func(t *testing.T) {
		store, _ := openStore(t, "diagnostic")
		manifest := testManifest("closed")
		admitSourceJournal(t, ctx, store, manifest)
		if _, err := AppendSourceEvents(ctx, store, manifest.JournalID, []EventSubmission{
			outcomeSubmission("R1", "satisfied"),
			requestSubmission(testRequest(t, 1)),
		}); err != nil {
			t.Fatalf("commit source prefix: %v", err)
		}
		if err := store.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}
		document, err := AnalyzeSession(ctx, store, manifest, testRequest(t, 1))
		if err == nil {
			t.Fatalf("expected an error against a closed store")
		}
		if document.DiagnosticID != "" {
			t.Fatalf("fabricated a diagnostic from an unreadable store")
		}
	})

	// Installation failure mid-pipeline: bytes cannot be installed, so no
	// registration is committed and no report exists afterwards.
	t.Run("installation failure", func(t *testing.T) {
		store, artifactRoot := openStore(t, "diagnostic")
		manifest := testManifest("install")
		admitSourceJournal(t, ctx, store, manifest)
		if _, err := AppendSourceEvents(ctx, store, manifest.JournalID, []EventSubmission{
			outcomeSubmission("R1", "satisfied"),
			requestSubmission(testRequest(t, 1)),
		}); err != nil {
			t.Fatalf("commit source prefix: %v", err)
		}
		// Block artifact installation by replacing the spool directory
		// with a regular file (fails for any user, including root).
		tmpDir := filepath.Join(artifactRoot, "tmp")
		if err := os.RemoveAll(tmpDir); err != nil {
			t.Fatalf("remove spool dir: %v", err)
		}
		if err := os.WriteFile(tmpDir, []byte("blocked"), 0o644); err != nil {
			t.Fatalf("block spool dir: %v", err)
		}
		document, err := AnalyzeSession(ctx, store, manifest, testRequest(t, 1))
		if err == nil {
			t.Fatalf("expected an installation error")
		}
		if !strings.Contains(err.Error(), "install") {
			t.Fatalf("unexpected error: %v", err)
		}
		if document.DiagnosticID != "" {
			t.Fatalf("fabricated a diagnostic after an installation failure")
		}
		if _, ok := DiagnosticHead(store, manifest); ok {
			t.Fatalf("a diagnostic registration was fabricated despite the installation failure")
		}
		if _, err := LoadSessionDiagnostic(ctx, store, manifest, "diag-1", 1); err == nil {
			t.Fatalf("a published report exists despite the installation failure")
		}
	})
}

func TestNewReplayReceiptDoesNotMutateSelectedDiagnostic(t *testing.T) {
	ctx := authedContext(t)
	store, _ := openStore(t, "diagnostic")
	manifest := testManifest("replay")
	admitSourceJournal(t, ctx, store, manifest)
	if _, err := AppendSourceEvents(ctx, store, manifest.JournalID, []EventSubmission{
		outcomeSubmission("R1", "satisfied"),
		requestSubmission(testRequest(t, 1)),
	}); err != nil {
		t.Fatalf("commit source prefix: %v", err)
	}
	if _, err := AnalyzeSession(ctx, store, manifest, testRequest(t, 1)); err != nil {
		t.Fatalf("AnalyzeSession: %v", err)
	}
	selected := mustValue(t, ctx, store, manifest, "diag-1", 1)
	if len(selected.ReplayReceipts) != 0 {
		t.Fatalf("expected no receipts initially, got %d", len(selected.ReplayReceipts))
	}
	diagnosticBytes := readArtifact(t, ctx, store, selected.DiagnosticArtifact)
	reportBytes := readArtifact(t, ctx, store, selected.ReportJSONArtifact)
	readableBytes := readArtifact(t, ctx, store, selected.ReadableArtifact)

	// Receipts against unknown revisions are rejected.
	if _, err := AttachReplayReceipt(ctx, store, manifest, "diag-1", 9, testDigest("replay-x"), "unknown"); err == nil {
		t.Fatalf("expected an error attaching a receipt to an unknown revision")
	}

	advanced, err := AttachReplayReceipt(ctx, store, manifest, "diag-1", 1, testDigest("replay-1"), "first exact replay")
	if err != nil {
		t.Fatalf("AttachReplayReceipt: %v", err)
	}
	if len(advanced.ReplayReceipts) != 1 {
		t.Fatalf("expected 1 receipt, got %d", len(advanced.ReplayReceipts))
	}
	receipt := advanced.ReplayReceipts[0]
	if receipt.ReplayDigest != testDigest("replay-1") || receipt.DiagnosticID != "diag-1" || receipt.AnalysisRevision != 1 {
		t.Fatalf("receipt cites the wrong diagnostic: %+v", receipt)
	}
	if receipt.EvidenceRef.JournalID != DiagnosticJournalID(manifest) {
		t.Fatalf("receipt evidence cites the wrong journal: %+v", receipt.EvidenceRef)
	}
	// The selected diagnostic is untouched.
	if advanced.DiagnosticArtifact.Digest != selected.DiagnosticArtifact.Digest ||
		advanced.ReportJSONArtifact.Digest != selected.ReportJSONArtifact.Digest ||
		advanced.ReadableArtifact.Digest != selected.ReadableArtifact.Digest ||
		advanced.InputPrefix != selected.InputPrefix ||
		advanced.AnalysisRequestRef != selected.AnalysisRequestRef {
		t.Fatalf("the selected diagnostic changed under a new replay receipt")
	}
	if !bytes.Equal(readArtifact(t, ctx, store, advanced.DiagnosticArtifact), diagnosticBytes) ||
		!bytes.Equal(readArtifact(t, ctx, store, advanced.ReportJSONArtifact), reportBytes) ||
		!bytes.Equal(readArtifact(t, ctx, store, advanced.ReadableArtifact), readableBytes) {
		t.Fatalf("diagnostic bytes changed under a new replay receipt")
	}

	// A second receipt accumulates without mutating either.
	final, err := AttachReplayReceipt(ctx, store, manifest, "diag-1", 1, testDigest("replay-2"), "second exact replay")
	if err != nil {
		t.Fatalf("AttachReplayReceipt(2): %v", err)
	}
	if len(final.ReplayReceipts) != 2 {
		t.Fatalf("expected 2 receipts, got %d", len(final.ReplayReceipts))
	}
	if final.DiagnosticArtifact.Digest != selected.DiagnosticArtifact.Digest {
		t.Fatalf("the selected diagnostic changed under the second receipt")
	}
	if !bytes.Equal(readArtifact(t, ctx, store, final.DiagnosticArtifact), diagnosticBytes) {
		t.Fatalf("diagnostic bytes changed under the second receipt")
	}
	// The readable report still describes the same revision.
	if !strings.Contains(string(readableBytes), "diag-1") || !strings.Contains(string(readableBytes), "revision 1") {
		t.Fatalf("readable report does not describe the selected revision")
	}
}

func mustValue(t *testing.T, ctx context.Context, store *OwnerStore, manifest Manifest, diagnosticID string, revision int64) SessionDiagnosticValue {
	t.Helper()
	value, err := LoadSessionDiagnostic(ctx, store, manifest, diagnosticID, revision)
	if err != nil {
		t.Fatalf("LoadSessionDiagnostic(%s/%d): %v", diagnosticID, revision, err)
	}
	return value
}

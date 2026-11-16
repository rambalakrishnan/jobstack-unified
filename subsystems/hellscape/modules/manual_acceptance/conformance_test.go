package manual_acceptance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	authority "authority"
	evidence_bundle "evidence_bundle"
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
	request, err := http.NewRequest(http.MethodPost, "http://manual-acceptance.test/"+domain, nil)
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

func manualManifest(domain, journalID string) journal_rules.Manifest {
	return journal_rules.Manifest{
		RecordType:    "manifest",
		SchemaVersion: "0.1.0",
		ManifestID:    "manifest-" + journalID,
		RunID:         "run-" + journalID,
		JournalID:     journalID,
		OwnerDomain:   domain,
		Clocks: []journal_rules.ClockDescriptor{
			{ClockID: "engine-clock", BootID: "boot-1", Origin: "engine_measured", SourceID: "engine", Basis: "monotonic_offset", Unit: "ms"},
			{ClockID: "manual-clock", BootID: "boot-1", Origin: "manual_reference", SourceID: "operator", Basis: "monotonic_offset", Unit: "ms"},
		},
	}
}

func tpEngine(offset float64) journal_rules.TimePoint {
	return journal_rules.TimePoint{
		ClockID: "engine-clock", BootID: "boot-1", Origin: "engine_measured",
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
		OccurredAt:         tpEngine(0),
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

type stepDef struct {
	kind         string
	data         map[string]any
	measurements []journal_rules.Measurement
	refs         []journal_rules.ArtifactReference
}

func commitSteps(t *testing.T, ctx context.Context, store *owner_store.OwnerStore, journalID string, m journal_rules.Manifest, startSeq int64, steps []stepDef) []journal_rules.JournalEnvelope {
	t.Helper()
	submissions := make([]owner_store.EventSubmission, 0, len(steps))
	for i, s := range steps {
		data := s.data
		if data == nil {
			data = map[string]any{}
		}
		meas := s.measurements
		if meas == nil {
			meas = []journal_rules.Measurement{}
		}
		refs := s.refs
		if refs == nil {
			refs = []journal_rules.ArtifactReference{}
		}
		submissions = append(submissions, owner_store.EventSubmission{
			ProducerSequence:   startSeq + int64(i),
			EventKind:          s.kind,
			EventSchemaVersion: "0.1.0",
			OccurredAt:         tpEngine(float64(startSeq+int64(i)) * 10),
			Payload: journal_rules.Payload{
				Data:         data,
				Measurements: meas,
				EvidenceRefs: []journal_rules.EvidenceRef{},
				ArtifactRefs: refs,
			},
		})
	}
	envelopes, err := owner_store.CommitOwner(ctx, store, journalID, submissions, nil)
	if err != nil {
		t.Fatalf("CommitOwner steps: %v", err)
	}
	return envelopes
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

func evidenceRefMap(ref journal_rules.EvidenceRef) map[string]any {
	return map[string]any{
		"journal_id": ref.JournalID,
		"sequence":   ref.Sequence,
		"event_id":   ref.EventID,
		"event_hash": ref.EventHash,
		"pointer":    ref.Pointer,
	}
}

func findEvent(events []journal_rules.JournalEnvelope, kind string) *journal_rules.JournalEnvelope {
	for i := range events {
		if events[i].EventKind == kind {
			return &events[i]
		}
	}
	return nil
}

func pauseMeasurement() journal_rules.Measurement {
	return journal_rules.Measurement{
		MeasurementID: "pause-1",
		Name:          "manual_pause",
		Scope:         journal_rules.Scope{Kind: "workflow_step", ID: "pause-1"},
		Quantity:      "duration",
		Unit:          "ms",
		Origin:        "engine_measured",
		ClockID:       "engine-clock",
		BootID:        "boot-1",
		Method:        "endpoint_difference",
		Start:         tpEngine(1000),
		End:           tpEngine(6000),
		Estimate:      journal_rules.Estimate{Kind: "exact", Value: 5000.0},
		Resolution:    journal_rules.NewMissing("not_applicable"),
		Censoring:     "none",
		ComparabilityGroup: journal_rules.NewMissing("not_applicable"),
	}
}

// ---------------------------------------------------------------------------
// Registration and row fixtures (adapted from evidence_bundle corpus).
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

func buildDiagnostic(t *testing.T, m journal_rules.Manifest, prefix journal_rules.JournalPrefix, events []journal_rules.JournalEnvelope, classifier, registry journal_rules.ArtifactReference, extraArtifacts []journal_rules.ArtifactReference, extra map[string]any) evidence_bundle.DiagnosticDocument {
	t.Helper()
	manifestDigest := string(evidence_codec.HashBytes(canonicalBytes(t, m)))
	lastRef := eventRef(events[len(events)-1])
	artifacts := []journal_rules.ArtifactReference{classifier, registry}
	artifacts = append(artifacts, extraArtifacts...)
	return evidence_bundle.DiagnosticDocument{
		RecordType:       "diagnostic",
		SchemaVersion:    "1.0.0",
		DiagnosticID:     "diag-" + m.JournalID,
		AnalysisRevision: 1,
		RunID:            m.RunID,
		ManifestHash:     manifestDigest,
		InputPrefix:      prefix,
		AnalysisRequestRef: lastRef,
		Classifier: evidence_bundle.VersionPin{
			ID: "classifier", Version: "v1", ArtifactDigest: classifier.Digest,
		},
		RequirementRegistry: evidence_bundle.VersionPin{
			ID: "requirements", Version: "v1", ArtifactDigest: registry.Digest,
		},
		FixRegistry:  journal_rules.NewMissing("not_enabled"),
		EvidenceRefs: []journal_rules.EvidenceRef{lastRef},
		Artifacts:    artifacts,
		Extra:        extra,
	}
}

func buildReceipt(t *testing.T, diagnostic evidence_bundle.DiagnosticDocument, manifestDigest string, inputBundle, sourceDiagnostic, engine journal_rules.ArtifactReference, reducer any, mode string) evidence_bundle.ReplayReceipt {
	t.Helper()
	semantic := string(evidence_codec.HashBytes([]byte("semantic-events-" + diagnostic.DiagnosticID)))
	state := string(evidence_codec.HashBytes([]byte("final-state-" + diagnostic.DiagnosticID)))
	diag := string(evidence_codec.HashBytes([]byte("diagnostic-" + diagnostic.DiagnosticID)))
	var comparisons []evidence_bundle.ReplayComparison
	if mode == "exact_fixture" {
		comparisons = []evidence_bundle.ReplayComparison{
			{Output: "semantic_events", ExpectedDigest: semantic, ActualDigest: semantic, Result: "matched"},
			{Output: "final_state", ExpectedDigest: state, ActualDigest: state, Result: "matched"},
			{Output: "diagnostic", ExpectedDigest: diag, ActualDigest: diag, Result: "matched"},
		}
	} else {
		comparisons = []evidence_bundle.ReplayComparison{
			{Output: "diagnostic", ExpectedDigest: diag, ActualDigest: diag, Result: "matched"},
		}
	}
	return evidence_bundle.ReplayReceipt{
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
		ReplayEngine: evidence_bundle.VersionPin{
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

// ---------------------------------------------------------------------------
// Manual walkthrough scenario builders.
// ---------------------------------------------------------------------------

var syntheticContact = map[string]any{"name": "Ada Operator", "email": "ada@example.com"}
var syntheticHistory = map[string]any{"start_date": "2020-01-01", "end_date": "2021-01-01"}

func requirementAssessments() []any {
	out := make([]any, 0, 10)
	for i := 1; i <= 10; i++ {
		out = append(out, map[string]any{
			"id":     fmt.Sprintf("R%d", i),
			"result": "not_exercised",
			"reason": "manual_fixture_validation",
		})
	}
	return out
}

func missingMap(reason string) map[string]any {
	return map[string]any{"value": nil, "reason": reason}
}

func fullSteps(docDigest string, docRef journal_rules.ArtifactReference, docSize int64) []stepDef {
	return []stepDef{
		{kind: EKListingObserved, data: map[string]any{
			"workflow_state": "LISTING", "readiness": true,
			"entry_url": "https://fixture.local/jobs", "observation": "listing_ready",
		}},
		{kind: EKJobSelected, data: map[string]any{
			"workflow_state": "DETAIL", "job_id": "job-specified-1",
			"selection": "specified_job", "transaction": "tx-select-1",
		}},
		{kind: EKContactAccepted, data: map[string]any{
			"workflow_state": "CONTACT", "accepted": true,
			"value_revision": int64(1),
			"contact":        map[string]any{"name": "Ada Operator", "email": "ada@example.com"},
		}},
		{kind: EKHistoryEntered, data: map[string]any{
			"workflow_state": "HISTORY", "contact_currency": true, "contact_revision": int64(1),
		}},
		{kind: EKHistoryRejected, data: map[string]any{
			"workflow_state": "HISTORY", "outcome": "rejected", "reason": "invalid_interval",
			"history": map[string]any{"start_date": "2021-01-01", "end_date": "2020-01-01"},
		}},
		{kind: EKHistoryErrorObserved, data: map[string]any{
			"workflow_state": "HISTORY", "error_visible": true,
			"error_text": "End date must be after start date.", "observation": "ui_error",
		}},
		{kind: EKHistoryCorrected, data: map[string]any{
			"workflow_state": "UPLOAD", "outcome": "accepted", "recovered": true,
			"history": map[string]any{"start_date": "2020-01-01", "end_date": "2021-01-01"},
		}},
		{kind: EKDocumentUploaded, data: map[string]any{
			"workflow_state": "IDENTITY", "document_digest": docDigest,
			"size_bytes": docSize, "durable": true,
		}, refs: []journal_rules.ArtifactReference{docRef}},
		{kind: EKIdentityVerified, data: map[string]any{
			"workflow_state": "REVIEW", "provenance": "server",
			"attempt_id": "attempt-1", "epoch": int64(3), "verification": "server_origin",
		}},
		{kind: EKReviewValidated, data: map[string]any{
			"workflow_state": "REVIEW", "prerequisites_current": true,
			"contact_revision": int64(1), "history_revision": int64(2),
		}},
		{kind: EKPauseRecorded, data: map[string]any{
			"workflow_state": "REVIEW", "checkpoint": "review-to-submit",
			"markers_authenticated": true,
		}, measurements: []journal_rules.Measurement{pauseMeasurement()}},
		{kind: EKSubmissionCommitted, data: map[string]any{
			"workflow_state": "CONFIRMATION", "operation_key": "submit-1",
			"commitment": true, "authoritative": true,
		}},
		{kind: EKConfirmationRendered, data: map[string]any{
			"workflow_state": "CONFIRMATION", "rendering": true, "separate_from_commitment": true,
		}},
		{kind: EKObservationClosed, data: map[string]any{
			"workflow_state": "CONFIRMATION", "flush_bounded": true, "closed": true,
			"completeness": "assessed", "fixture_sealed": true,
		}},
	}
}

func fullExtra(events []journal_rules.JournalEnvelope, docDigest string) map[string]any {
	submission := findEvent(events, EKSubmissionCommitted)
	rendered := findEvent(events, EKConfirmationRendered)
	return map[string]any{
		"scenario": "full_walkthrough",
		"outcome":  map[string]any{"application_goal": "completed", "expectation_met": true},
		"postconditions": map[string]any{
			"LISTING": true, "DETAIL": true, "CONTACT": true, "HISTORY": true,
			"UPLOAD": true, "IDENTITY": true, "REVIEW": true, "CONFIRMATION": true,
		},
		"steps": map[string]any{
			"history": map[string]any{
				"status": "recovered",
				"attempts": []any{
					map[string]any{"outcome": "rejected", "reason": "invalid_interval", "end_before_start": true},
					map[string]any{"outcome": "accepted", "correction": true},
				},
			},
		},
		"defect_locus": "none",
		"pause": map[string]any{
			"interval": "review_to_submit", "engine_ms": 5000.0, "manual_ms": 5010.0,
			"uncertainty_ms": 100.0, "agreement": true,
		},
		"submission": map[string]any{"committed": true, "commit_count": int64(1), "operation_count": int64(1)},
		"accepted": map[string]any{
			"contact":         map[string]any{"name": "Ada Operator", "email": "ada@example.com"},
			"history":         map[string]any{"start_date": "2020-01-01", "end_date": "2021-01-01"},
			"document_digest": docDigest,
		},
		"task": map[string]any{
			"contact":         map[string]any{"name": "Ada Operator", "email": "ada@example.com"},
			"history":         map[string]any{"start_date": "2020-01-01", "end_date": "2021-01-01"},
			"document_digest": docDigest,
		},
		"identity": map[string]any{"provenance": "server"},
		"confirmation": map[string]any{
			"rendered":       true,
			"rendering_ref":  evidenceRefMap(eventRef(*rendered)),
			"commitment_ref": evidenceRefMap(eventRef(*submission)),
		},
		"execution":               map[string]any{"subject": missingMap("not_applicable")},
		"requirement_assessments": requirementAssessments(),
		"reproduction":            map[string]any{"exact_replay": "matched"},
	}
}

type builtScenario struct {
	inputs     journal_rules.ArtifactReference
	receipt    evidence_bundle.ReplayReceipt
	events     []journal_rules.JournalEnvelope
	diagnostic evidence_bundle.DiagnosticDocument
	docDigest  string
}

func buildFullScenario(t *testing.T, f *fixture, journalID, sessionID string) *builtScenario {
	t.Helper()
	m := manualManifest(f.domain, journalID)
	admission := admitJournal(t, f.ctx, f.store, m)
	classifierRef := installArtifact(t, f.ctx, f.store, []byte(`{"classifier":"v1"}`), "application/json", "public")
	registryRef := installArtifact(t, f.ctx, f.store, []byte(`{"requirements":"v1"}`), "application/json", "public")
	engineRef := installArtifact(t, f.ctx, f.store, []byte(`{"engine":"v1"}`), "application/json", "public")
	reducerRef := installArtifact(t, f.ctx, f.store, []byte(`{"reducer":"v1"}`), "application/json", "public")
	docBytes := []byte("synthetic-manual-document-bytes-v1")
	docRef := installArtifact(t, f.ctx, f.store, docBytes, "application/octet-stream", "public")
	docDigest := string(evidence_codec.HashBytes(docBytes))

	steps := fullSteps(docDigest, docRef, int64(len(docBytes)))
	later := commitSteps(t, f.ctx, f.store, m.JournalID, m, 2, steps)
	events := append(append([]journal_rules.JournalEnvelope{}, admission...), later...)
	prefix := prefixThrough(events)
	extra := fullExtra(events, docDigest)
	diagnostic := buildDiagnostic(t, m, prefix, events, classifierRef, registryRef,
		[]journal_rules.ArtifactReference{docRef}, extra)
	registration := sessionRegistration(sessionID)
	row := buildTestRow(t, f.ctx, f.store, registration, prefix, events)
	inputs, err := evidence_bundle.ExportReplayInputs(f.ctx, f.store, row, diagnostic)
	if err != nil {
		t.Fatalf("ExportReplayInputs: %v", err)
	}
	manifestDigest := string(evidence_codec.HashBytes(canonicalBytes(t, m)))
	sourceDiagnostic := installArtifact(t, f.ctx, f.store, canonicalBytes(t, diagnostic), "application/json", "public")
	receipt := buildReceipt(t, diagnostic, manifestDigest, inputs, sourceDiagnostic, engineRef,
		evidence_bundle.VersionPin{ID: "reducer", Version: "v1", ArtifactDigest: reducerRef.Digest}, "exact_fixture")
	return &builtScenario{inputs: inputs, receipt: receipt, events: events, diagnostic: diagnostic, docDigest: docDigest}
}

func buildCustomScenario(t *testing.T, f *fixture, journalID, sessionID string, steps []stepDef, extra map[string]any, extraRefs []journal_rules.ArtifactReference) *builtScenario {
	t.Helper()
	m := manualManifest(f.domain, journalID)
	admission := admitJournal(t, f.ctx, f.store, m)
	classifierRef := installArtifact(t, f.ctx, f.store, []byte(`{"classifier":"v1"}`), "application/json", "public")
	registryRef := installArtifact(t, f.ctx, f.store, []byte(`{"requirements":"v1"}`), "application/json", "public")
	engineRef := installArtifact(t, f.ctx, f.store, []byte(`{"engine":"v1"}`), "application/json", "public")
	reducerRef := installArtifact(t, f.ctx, f.store, []byte(`{"reducer":"v1"}`), "application/json", "public")
	later := commitSteps(t, f.ctx, f.store, m.JournalID, m, 2, steps)
	events := append(append([]journal_rules.JournalEnvelope{}, admission...), later...)
	prefix := prefixThrough(events)
	// Rewrite evidence refs in extra that were built before event IDs existed.
	diagnostic := buildDiagnostic(t, m, prefix, events, classifierRef, registryRef, extraRefs, extra)
	// Fix up confirmation refs if they used placeholder sequences.
	registration := sessionRegistration(sessionID)
	row := buildTestRow(t, f.ctx, f.store, registration, prefix, events)
	inputs, err := evidence_bundle.ExportReplayInputs(f.ctx, f.store, row, diagnostic)
	if err != nil {
		t.Fatalf("ExportReplayInputs: %v", err)
	}
	manifestDigest := string(evidence_codec.HashBytes(canonicalBytes(t, m)))
	sourceDiagnostic := installArtifact(t, f.ctx, f.store, canonicalBytes(t, diagnostic), "application/json", "public")
	receipt := buildReceipt(t, diagnostic, manifestDigest, inputs, sourceDiagnostic, engineRef,
		evidence_bundle.VersionPin{ID: "reducer", Version: "v1", ArtifactDigest: reducerRef.Digest}, "exact_fixture")
	return &builtScenario{inputs: inputs, receipt: receipt, events: events, diagnostic: diagnostic}
}

func baseCompanionExtra(scenario string) map[string]any {
	return map[string]any{
		"scenario":                scenario,
		"defect_locus":            "none",
		"execution":               map[string]any{"subject": missingMap("not_applicable")},
		"requirement_assessments": requirementAssessments(),
		"reproduction":            map[string]any{"exact_replay": "matched"},
	}
}

func checkAcceptance(t *testing.T, f *fixture, s *builtScenario) AcceptanceReport {
	t.Helper()
	raw, err := CheckManualAcceptance(f.ctx, f.store, s.inputs, s.receipt)
	if err != nil {
		t.Fatalf("CheckManualAcceptance: %v", err)
	}
	var report AcceptanceReport
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatalf("decode acceptance report: %v", err)
	}
	return report
}

func requireCheck(t *testing.T, report AcceptanceReport, id string) AcceptanceCheck {
	t.Helper()
	for _, c := range report.Checks {
		if c.ID == id {
			if c.Status != "pass" {
				t.Fatalf("check %q status = %q, want pass", id, c.Status)
			}
			return c
		}
	}
	t.Fatalf("acceptance report has no check %q (have %v)", id, report.Checks)
	return AcceptanceCheck{}
}

// ---------------------------------------------------------------------------
// Fourteen-step walkthrough assertions.
// ---------------------------------------------------------------------------

func TestOpenEntryProducesListingReadinessObservation(t *testing.T) {
	f := newFixture(t, "owner-manual-1")
	s := buildFullScenario(t, f, "journal-manual-1", "session-manual-1")
	report := checkAcceptance(t, f, s)
	requireCheck(t, report, "listing_readiness")
	if !report.WorkflowPostconditions["LISTING"] {
		t.Fatalf("LISTING postcondition not satisfied")
	}
	ev := findEvent(s.events, EKListingObserved)
	if ev == nil {
		t.Fatalf("listing_observed event missing")
	}
	if url, _ := ev.Payload.Data["entry_url"].(string); url == "" {
		t.Fatalf("entry URL not recorded")
	}
}

func TestSelectSpecifiedJobCommitsDetailTransition(t *testing.T) {
	f := newFixture(t, "owner-manual-2")
	s := buildFullScenario(t, f, "journal-manual-2", "session-manual-2")
	report := checkAcceptance(t, f, s)
	requireCheck(t, report, "job_selection")
	if !report.WorkflowPostconditions["DETAIL"] {
		t.Fatalf("DETAIL postcondition not satisfied")
	}
	ev := findEvent(s.events, EKJobSelected)
	if ev == nil {
		t.Fatalf("job_selected event missing")
	}
	if tx, _ := ev.Payload.Data["transaction"].(string); tx == "" {
		t.Fatalf("selection transaction not recorded")
	}
}

func TestSaveValidContactRecordsCurrentAcceptedRevision(t *testing.T) {
	f := newFixture(t, "owner-manual-3")
	s := buildFullScenario(t, f, "journal-manual-3", "session-manual-3")
	report := checkAcceptance(t, f, s)
	requireCheck(t, report, "contact_accepted")
	if !report.WorkflowPostconditions["CONTACT"] {
		t.Fatalf("CONTACT postcondition not satisfied")
	}
	accepted, _ := s.diagnostic.Extra["accepted"].(map[string]any)
	task, _ := s.diagnostic.Extra["task"].(map[string]any)
	if accepted == nil || task == nil {
		t.Fatalf("accepted/task sections missing")
	}
	aRaw, _ := json.Marshal(accepted["contact"])
	tRaw, _ := json.Marshal(task["contact"])
	if string(aRaw) != string(tRaw) {
		t.Fatalf("accepted contact does not match task")
	}
}

func TestContinueToHistoryChecksContactCurrency(t *testing.T) {
	f := newFixture(t, "owner-manual-4")
	s := buildFullScenario(t, f, "journal-manual-4", "session-manual-4")
	report := checkAcceptance(t, f, s)
	requireCheck(t, report, "history_enter")
	ev := findEvent(s.events, EKHistoryEntered)
	if ev == nil {
		t.Fatalf("history_entered event missing")
	}
	if ok, _ := ev.Payload.Data["contact_currency"].(bool); !ok {
		t.Fatalf("contact-currency check not recorded")
	}
}

func TestSubmitInvalidHistoryPreservesRejectedAttempt(t *testing.T) {
	f := newFixture(t, "owner-manual-5")
	s := buildFullScenario(t, f, "journal-manual-5", "session-manual-5")
	report := checkAcceptance(t, f, s)
	requireCheck(t, report, "history_rejected")
	steps, _ := s.diagnostic.Extra["steps"].(map[string]any)
	history, _ := steps["history"].(map[string]any)
	attempts, _ := history["attempts"].([]any)
	found := false
	for _, item := range attempts {
		m, _ := item.(map[string]any)
		if m != nil && m["outcome"] == "rejected" {
			found = true
		}
	}
	if !found {
		t.Fatalf("rejected history attempt not preserved in attempts[]")
	}
}

func TestVisibleHistoryErrorLeavesWorkflowInHistory(t *testing.T) {
	f := newFixture(t, "owner-manual-6")
	s := buildFullScenario(t, f, "journal-manual-6", "session-manual-6")
	report := checkAcceptance(t, f, s)
	requireCheck(t, report, "history_error")
	ev := findEvent(s.events, EKHistoryErrorObserved)
	if ev == nil {
		t.Fatalf("history_error_observed event missing")
	}
	if state, _ := ev.Payload.Data["workflow_state"].(string); state != "HISTORY" {
		t.Fatalf("workflow state after visible error = %q, want HISTORY", state)
	}
}

func TestCorrectHistoryProducesRecoveredStepAndUploadTransition(t *testing.T) {
	f := newFixture(t, "owner-manual-7")
	s := buildFullScenario(t, f, "journal-manual-7", "session-manual-7")
	report := checkAcceptance(t, f, s)
	requireCheck(t, report, "history_recovered")
	steps, _ := s.diagnostic.Extra["steps"].(map[string]any)
	history, _ := steps["history"].(map[string]any)
	if status, _ := history["status"].(string); status != "recovered" {
		t.Fatalf("history status = %q, want recovered", status)
	}
	ev := findEvent(s.events, EKHistoryCorrected)
	if state, _ := ev.Payload.Data["workflow_state"].(string); state != "UPLOAD" {
		t.Fatalf("workflow after correction = %q, want UPLOAD", state)
	}
}

func TestUploadSyntheticDocumentVerifiesDigestAndIdentityTransition(t *testing.T) {
	f := newFixture(t, "owner-manual-8")
	s := buildFullScenario(t, f, "journal-manual-8", "session-manual-8")
	report := checkAcceptance(t, f, s)
	requireCheck(t, report, "document_upload")
	ev := findEvent(s.events, EKDocumentUploaded)
	if ev == nil {
		t.Fatalf("document_uploaded event missing")
	}
	if digest, _ := ev.Payload.Data["document_digest"].(string); digest != s.docDigest {
		t.Fatalf("uploaded digest does not match synthetic bytes")
	}
	if len(ev.Payload.ArtifactRefs) == 0 {
		t.Fatalf("uploaded document artifact not carried")
	}
	stored, err := owner_store.ReadArtifact(f.ctx, f.store, ev.Payload.ArtifactRefs[0])
	if err != nil {
		t.Fatalf("read uploaded document: %v", err)
	}
	if string(evidence_codec.HashBytes(stored)) != s.docDigest {
		t.Fatalf("stored document bytes do not verify against the digest")
	}
}

func TestLocalIdentityActionRecordsOriginVerifiedReviewTransition(t *testing.T) {
	f := newFixture(t, "owner-manual-9")
	s := buildFullScenario(t, f, "journal-manual-9", "session-manual-9")
	report := checkAcceptance(t, f, s)
	requireCheck(t, report, "identity_verified")
	identity, _ := s.diagnostic.Extra["identity"].(map[string]any)
	if prov, _ := identity["provenance"].(string); prov != "server" {
		t.Fatalf("identity provenance = %q, want server", prov)
	}
}

func TestValidateReviewPinsCurrentPrerequisiteRevisions(t *testing.T) {
	f := newFixture(t, "owner-manual-10")
	s := buildFullScenario(t, f, "journal-manual-10", "session-manual-10")
	report := checkAcceptance(t, f, s)
	requireCheck(t, report, "review_validated")
	ev := findEvent(s.events, EKReviewValidated)
	if ok, _ := ev.Payload.Data["prerequisites_current"].(bool); !ok {
		t.Fatalf("review does not pin current prerequisites")
	}
}

func TestRecordedPauseMatchesIndependentMonotonicReference(t *testing.T) {
	f := newFixture(t, "owner-manual-11")
	s := buildFullScenario(t, f, "journal-manual-11", "session-manual-11")
	report := checkAcceptance(t, f, s)
	requireCheck(t, report, "pause_recorded")
	pause, _ := s.diagnostic.Extra["pause"].(map[string]any)
	if pause == nil {
		t.Fatalf("pause section missing")
	}
	if ok, _ := pause["agreement"].(bool); !ok {
		t.Fatalf("pause/manual agreement not recorded")
	}
	// The pause measurement must appear in the journal interval.
	found := false
	for _, ev := range s.events {
		if ev.EventKind != EKPauseRecorded {
			continue
		}
		for _, meas := range ev.Payload.Measurements {
			if meas.Method == "endpoint_difference" {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("pause measurement missing from the workflow interval")
	}
}

func TestSubmitOnceProducesExactlyOneAuthoritativeCommitment(t *testing.T) {
	f := newFixture(t, "owner-manual-12")
	s := buildFullScenario(t, f, "journal-manual-12", "session-manual-12")
	report := checkAcceptance(t, f, s)
	requireCheck(t, report, "submission_committed")
	count := 0
	for _, ev := range s.events {
		if ev.EventKind == EKSubmissionCommitted {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("submission_committed count = %d, want 1", count)
	}
}

func TestReadConfirmationRecordsRenderingSeparateFromCommitment(t *testing.T) {
	f := newFixture(t, "owner-manual-13")
	s := buildFullScenario(t, f, "journal-manual-13", "session-manual-13")
	report := checkAcceptance(t, f, s)
	requireCheck(t, report, "confirmation_rendered")
	confirmation, _ := s.diagnostic.Extra["confirmation"].(map[string]any)
	rendering, _ := confirmation["rendering_ref"].(map[string]any)
	commitment, _ := confirmation["commitment_ref"].(map[string]any)
	if rendering == nil || commitment == nil {
		t.Fatalf("rendering/commitment refs missing")
	}
	if rendering["sequence"] == commitment["sequence"] && rendering["pointer"] == commitment["pointer"] {
		t.Fatalf("rendering and commitment are not independently cited")
	}
}

func TestEndObservationRecordsBoundedFlushClosureAndDiagnostic(t *testing.T) {
	f := newFixture(t, "owner-manual-14")
	s := buildFullScenario(t, f, "journal-manual-14", "session-manual-14")
	report := checkAcceptance(t, f, s)
	requireCheck(t, report, "observation_closed")
	ev := findEvent(s.events, EKObservationClosed)
	if ev == nil {
		t.Fatalf("observation_closed event missing")
	}
	if ok, _ := ev.Payload.Data["flush_bounded"].(bool); !ok {
		t.Fatalf("bounded flush not recorded")
	}
	if report.Result != "pass" {
		t.Fatalf("acceptance result = %q, want pass", report.Result)
	}
}

// ---------------------------------------------------------------------------
// Companion cases.
// ---------------------------------------------------------------------------

func TestStopBeforeSubmitUsesAuthoritativeNonCompletionAtCutoff(t *testing.T) {
	f := newFixture(t, "owner-manual-15")
	m := manualManifest(f.domain, "journal-manual-15")
	admission := admitJournal(t, f.ctx, f.store, m)
	classifierRef := installArtifact(t, f.ctx, f.store, []byte(`{"classifier":"v1"}`), "application/json", "public")
	registryRef := installArtifact(t, f.ctx, f.store, []byte(`{"requirements":"v1"}`), "application/json", "public")
	engineRef := installArtifact(t, f.ctx, f.store, []byte(`{"engine":"v1"}`), "application/json", "public")
	reducerRef := installArtifact(t, f.ctx, f.store, []byte(`{"reducer":"v1"}`), "application/json", "public")
	docBytes := []byte("synthetic-manual-document-bytes-v1")
	docRef := installArtifact(t, f.ctx, f.store, docBytes, "application/octet-stream", "public")
	docDigest := string(evidence_codec.HashBytes(docBytes))
	steps := fullSteps(docDigest, docRef, int64(len(docBytes)))[:11]
	steps = append(steps, stepDef{kind: EKObservationClosed, data: map[string]any{
		"workflow_state": "REVIEW", "flush_bounded": true, "closed": true,
		"completeness": "cutoff", "fixture_sealed": true, "cutoff": true,
	}})
	later := commitSteps(t, f.ctx, f.store, m.JournalID, m, 2, steps)
	events := append(append([]journal_rules.JournalEnvelope{}, admission...), later...)
	prefix := prefixThrough(events)
	extra := baseCompanionExtra("stop_before_submit")
	extra["outcome"] = map[string]any{"application_goal": "not_completed", "expectation_met": false}
	extra["postconditions"] = map[string]any{
		"LISTING": true, "DETAIL": true, "CONTACT": true, "HISTORY": true,
		"UPLOAD": true, "IDENTITY": true, "REVIEW": true, "CONFIRMATION": false,
	}
	extra["submission"] = map[string]any{"committed": false, "commit_count": int64(0)}
	extra["cutoff"] = map[string]any{"authoritative": true, "origin": "fixture", "not_completed": true, "has_receipt": false}
	extra["downstream"] = map[string]any{"confirmation": "blocked", "rendering": "unobserved"}
	diagnostic := buildDiagnostic(t, m, prefix, events, classifierRef, registryRef, []journal_rules.ArtifactReference{docRef}, extra)
	registration := sessionRegistration("session-manual-15")
	row := buildTestRow(t, f.ctx, f.store, registration, prefix, events)
	inputs, err := evidence_bundle.ExportReplayInputs(f.ctx, f.store, row, diagnostic)
	if err != nil {
		t.Fatalf("ExportReplayInputs: %v", err)
	}
	manifestDigest := string(evidence_codec.HashBytes(canonicalBytes(t, m)))
	sourceDiagnostic := installArtifact(t, f.ctx, f.store, canonicalBytes(t, diagnostic), "application/json", "public")
	receipt := buildReceipt(t, diagnostic, manifestDigest, inputs, sourceDiagnostic, engineRef,
		evidence_bundle.VersionPin{ID: "reducer", Version: "v1", ArtifactDigest: reducerRef.Digest}, "exact_fixture")
	s := &builtScenario{inputs: inputs, receipt: receipt, events: events, diagnostic: diagnostic}
	report := checkAcceptance(t, f, s)
	requireCheck(t, report, "stop_before_submit")
	if report.Scenario != "stop_before_submit" {
		t.Fatalf("scenario = %q", report.Scenario)
	}
}

func TestRepeatSubmitReturnsOriginalReceiptWithoutNewCommitment(t *testing.T) {
	f := newFixture(t, "owner-manual-16")
	m := manualManifest(f.domain, "journal-manual-16")
	admission := admitJournal(t, f.ctx, f.store, m)
	classifierRef := installArtifact(t, f.ctx, f.store, []byte(`{"classifier":"v1"}`), "application/json", "public")
	registryRef := installArtifact(t, f.ctx, f.store, []byte(`{"requirements":"v1"}`), "application/json", "public")
	engineRef := installArtifact(t, f.ctx, f.store, []byte(`{"engine":"v1"}`), "application/json", "public")
	reducerRef := installArtifact(t, f.ctx, f.store, []byte(`{"reducer":"v1"}`), "application/json", "public")
	docBytes := []byte("synthetic-manual-document-bytes-v1")
	docRef := installArtifact(t, f.ctx, f.store, docBytes, "application/octet-stream", "public")
	docDigest := string(evidence_codec.HashBytes(docBytes))
	steps := fullSteps(docDigest, docRef, int64(len(docBytes)))
	steps = append(steps, stepDef{kind: EKSubmissionRepeated, data: map[string]any{
		"workflow_state": "CONFIRMATION", "returns_original": true, "operation_key": "submit-1",
	}})
	later := commitSteps(t, f.ctx, f.store, m.JournalID, m, 2, steps)
	events := append(append([]journal_rules.JournalEnvelope{}, admission...), later...)
	prefix := prefixThrough(events)
	extra := baseCompanionExtra("repeat_submit")
	extra["outcome"] = map[string]any{"application_goal": "completed", "expectation_met": true}
	extra["postconditions"] = map[string]any{
		"LISTING": true, "DETAIL": true, "CONTACT": true, "HISTORY": true,
		"UPLOAD": true, "IDENTITY": true, "REVIEW": true, "CONFIRMATION": true,
	}
	extra["submission"] = map[string]any{"committed": true, "commit_count": int64(1), "operation_count": int64(1)}
	extra["repeat"] = map[string]any{"returns_original_receipt": true, "new_commitments": int64(0), "original_receipt": "receipt-submit-1"}
	diagnostic := buildDiagnostic(t, m, prefix, events, classifierRef, registryRef, []journal_rules.ArtifactReference{docRef}, extra)
	registration := sessionRegistration("session-manual-16")
	row := buildTestRow(t, f.ctx, f.store, registration, prefix, events)
	inputs, err := evidence_bundle.ExportReplayInputs(f.ctx, f.store, row, diagnostic)
	if err != nil {
		t.Fatalf("ExportReplayInputs: %v", err)
	}
	manifestDigest := string(evidence_codec.HashBytes(canonicalBytes(t, m)))
	sourceDiagnostic := installArtifact(t, f.ctx, f.store, canonicalBytes(t, diagnostic), "application/json", "public")
	receipt := buildReceipt(t, diagnostic, manifestDigest, inputs, sourceDiagnostic, engineRef,
		evidence_bundle.VersionPin{ID: "reducer", Version: "v1", ArtifactDigest: reducerRef.Digest}, "exact_fixture")
	s := &builtScenario{inputs: inputs, receipt: receipt, events: events, diagnostic: diagnostic}
	report := checkAcceptance(t, f, s)
	requireCheck(t, report, "repeat_submit")
}

func TestEndWithIncompleteFieldPreservesHonestPartialKnowledge(t *testing.T) {
	f := newFixture(t, "owner-manual-17")
	m := manualManifest(f.domain, "journal-manual-17")
	admission := admitJournal(t, f.ctx, f.store, m)
	classifierRef := installArtifact(t, f.ctx, f.store, []byte(`{"classifier":"v1"}`), "application/json", "public")
	registryRef := installArtifact(t, f.ctx, f.store, []byte(`{"requirements":"v1"}`), "application/json", "public")
	engineRef := installArtifact(t, f.ctx, f.store, []byte(`{"engine":"v1"}`), "application/json", "public")
	reducerRef := installArtifact(t, f.ctx, f.store, []byte(`{"reducer":"v1"}`), "application/json", "public")
	docBytes := []byte("synthetic-manual-document-bytes-v1")
	docRef := installArtifact(t, f.ctx, f.store, docBytes, "application/octet-stream", "public")
	docDigest := string(evidence_codec.HashBytes(docBytes))
	_ = docRef
	_ = docDigest
	steps := fullSteps(docDigest, docRef, int64(len(docBytes)))[:6]
	steps = append(steps, stepDef{kind: EKObservationClosed, data: map[string]any{
		"workflow_state": "HISTORY", "flush_bounded": true, "closed": true,
		"completeness": "partial", "fixture_sealed": true,
	}})
	later := commitSteps(t, f.ctx, f.store, m.JournalID, m, 2, steps)
	events := append(append([]journal_rules.JournalEnvelope{}, admission...), later...)
	prefix := prefixThrough(events)
	extra := baseCompanionExtra("incomplete_field")
	extra["outcome"] = map[string]any{"application_goal": "partial", "expectation_met": false}
	extra["postconditions"] = map[string]any{
		"LISTING": true, "DETAIL": true, "CONTACT": true, "HISTORY": true,
		"UPLOAD": false, "IDENTITY": false, "REVIEW": false, "CONFIRMATION": false,
	}
	extra["partial"] = map[string]any{"incomplete_field": "history", "honest": true, "fabricated_failure": false}
	diagnostic := buildDiagnostic(t, m, prefix, events, classifierRef, registryRef, nil, extra)
	registration := sessionRegistration("session-manual-17")
	row := buildTestRow(t, f.ctx, f.store, registration, prefix, events)
	inputs, err := evidence_bundle.ExportReplayInputs(f.ctx, f.store, row, diagnostic)
	if err != nil {
		t.Fatalf("ExportReplayInputs: %v", err)
	}
	manifestDigest := string(evidence_codec.HashBytes(canonicalBytes(t, m)))
	sourceDiagnostic := installArtifact(t, f.ctx, f.store, canonicalBytes(t, diagnostic), "application/json", "public")
	receipt := buildReceipt(t, diagnostic, manifestDigest, inputs, sourceDiagnostic, engineRef,
		evidence_bundle.VersionPin{ID: "reducer", Version: "v1", ArtifactDigest: reducerRef.Digest}, "exact_fixture")
	s := &builtScenario{inputs: inputs, receipt: receipt, events: events, diagnostic: diagnostic}
	report := checkAcceptance(t, f, s)
	requireCheck(t, report, "incomplete_field")
}

func TestBrowserCloseBeforeFlushPreservesFactsAndIncompleteTail(t *testing.T) {
	f := newFixture(t, "owner-manual-18")
	m := manualManifest(f.domain, "journal-manual-18")
	admission := admitJournal(t, f.ctx, f.store, m)
	classifierRef := installArtifact(t, f.ctx, f.store, []byte(`{"classifier":"v1"}`), "application/json", "public")
	registryRef := installArtifact(t, f.ctx, f.store, []byte(`{"requirements":"v1"}`), "application/json", "public")
	engineRef := installArtifact(t, f.ctx, f.store, []byte(`{"engine":"v1"}`), "application/json", "public")
	reducerRef := installArtifact(t, f.ctx, f.store, []byte(`{"reducer":"v1"}`), "application/json", "public")
	docBytes := []byte("synthetic-manual-document-bytes-v1")
	docRef := installArtifact(t, f.ctx, f.store, docBytes, "application/octet-stream", "public")
	docDigest := string(evidence_codec.HashBytes(docBytes))
	steps := fullSteps(docDigest, docRef, int64(len(docBytes)))[:12]
	steps = append(steps, stepDef{kind: EKBrowserClosed, data: map[string]any{
		"workflow_state": "CONFIRMATION", "server_facts_retained": true, "client_tail": "incomplete",
	}})
	later := commitSteps(t, f.ctx, f.store, m.JournalID, m, 2, steps)
	events := append(append([]journal_rules.JournalEnvelope{}, admission...), later...)
	prefix := prefixThrough(events)
	extra := baseCompanionExtra("browser_close_before_flush")
	extra["outcome"] = map[string]any{"application_goal": "partial", "expectation_met": false}
	extra["postconditions"] = map[string]any{
		"LISTING": true, "DETAIL": true, "CONTACT": true, "HISTORY": true,
		"UPLOAD": true, "IDENTITY": true, "REVIEW": true, "CONFIRMATION": false,
	}
	extra["submission"] = map[string]any{"committed": true, "commit_count": int64(1)}
	extra["flush"] = map[string]any{"server_facts_retained": true, "client_tail": "incomplete"}
	diagnostic := buildDiagnostic(t, m, prefix, events, classifierRef, registryRef, []journal_rules.ArtifactReference{docRef}, extra)
	registration := sessionRegistration("session-manual-18")
	row := buildTestRow(t, f.ctx, f.store, registration, prefix, events)
	inputs, err := evidence_bundle.ExportReplayInputs(f.ctx, f.store, row, diagnostic)
	if err != nil {
		t.Fatalf("ExportReplayInputs: %v", err)
	}
	manifestDigest := string(evidence_codec.HashBytes(canonicalBytes(t, m)))
	sourceDiagnostic := installArtifact(t, f.ctx, f.store, canonicalBytes(t, diagnostic), "application/json", "public")
	receipt := buildReceipt(t, diagnostic, manifestDigest, inputs, sourceDiagnostic, engineRef,
		evidence_bundle.VersionPin{ID: "reducer", Version: "v1", ArtifactDigest: reducerRef.Digest}, "exact_fixture")
	s := &builtScenario{inputs: inputs, receipt: receipt, events: events, diagnostic: diagnostic}
	report := checkAcceptance(t, f, s)
	requireCheck(t, report, "browser_close_before_flush")
}

func TestRestartAfterAcknowledgementPreservesOperationWithoutDuplicate(t *testing.T) {
	f := newFixture(t, "owner-manual-19")
	m := manualManifest(f.domain, "journal-manual-19")
	admission := admitJournal(t, f.ctx, f.store, m)
	classifierRef := installArtifact(t, f.ctx, f.store, []byte(`{"classifier":"v1"}`), "application/json", "public")
	registryRef := installArtifact(t, f.ctx, f.store, []byte(`{"requirements":"v1"}`), "application/json", "public")
	engineRef := installArtifact(t, f.ctx, f.store, []byte(`{"engine":"v1"}`), "application/json", "public")
	reducerRef := installArtifact(t, f.ctx, f.store, []byte(`{"reducer":"v1"}`), "application/json", "public")
	docBytes := []byte("synthetic-manual-document-bytes-v1")
	docRef := installArtifact(t, f.ctx, f.store, docBytes, "application/octet-stream", "public")
	docDigest := string(evidence_codec.HashBytes(docBytes))
	full := fullSteps(docDigest, docRef, int64(len(docBytes)))
	steps := append([]stepDef{}, full[:12]...)
	steps = append(steps, stepDef{kind: EKObservationRestarted, data: map[string]any{
		"workflow_state": "CONFIRMATION", "durable_operation": true, "interrupted_observation": true,
	}})
	steps = append(steps, full[12:]...)
	later := commitSteps(t, f.ctx, f.store, m.JournalID, m, 2, steps)
	events := append(append([]journal_rules.JournalEnvelope{}, admission...), later...)
	prefix := prefixThrough(events)
	extra := baseCompanionExtra("restart_after_ack")
	extra["outcome"] = map[string]any{"application_goal": "completed", "expectation_met": true}
	extra["postconditions"] = map[string]any{
		"LISTING": true, "DETAIL": true, "CONTACT": true, "HISTORY": true,
		"UPLOAD": true, "IDENTITY": true, "REVIEW": true, "CONFIRMATION": true,
	}
	extra["submission"] = map[string]any{"committed": true, "commit_count": int64(1)}
	extra["restart"] = map[string]any{"durable_operation": true, "interrupted_observation": true, "duplicate_actions": int64(0)}
	diagnostic := buildDiagnostic(t, m, prefix, events, classifierRef, registryRef, []journal_rules.ArtifactReference{docRef}, extra)
	registration := sessionRegistration("session-manual-19")
	row := buildTestRow(t, f.ctx, f.store, registration, prefix, events)
	inputs, err := evidence_bundle.ExportReplayInputs(f.ctx, f.store, row, diagnostic)
	if err != nil {
		t.Fatalf("ExportReplayInputs: %v", err)
	}
	manifestDigest := string(evidence_codec.HashBytes(canonicalBytes(t, m)))
	sourceDiagnostic := installArtifact(t, f.ctx, f.store, canonicalBytes(t, diagnostic), "application/json", "public")
	receipt := buildReceipt(t, diagnostic, manifestDigest, inputs, sourceDiagnostic, engineRef,
		evidence_bundle.VersionPin{ID: "reducer", Version: "v1", ArtifactDigest: reducerRef.Digest}, "exact_fixture")
	s := &builtScenario{inputs: inputs, receipt: receipt, events: events, diagnostic: diagnostic}
	report := checkAcceptance(t, f, s)
	requireCheck(t, report, "restart_after_ack")
}

// ---------------------------------------------------------------------------
// Replay, subject, and reference closure.
// ---------------------------------------------------------------------------

func TestReplayFirstWalkthroughMatchesEventsStateAndDiagnostic(t *testing.T) {
	f := newFixture(t, "owner-manual-20")
	s := buildFullScenario(t, f, "journal-manual-20", "session-manual-20")
	report := checkAcceptance(t, f, s)
	if s.receipt.Result != "matched" {
		t.Fatalf("receipt result = %q, want matched", s.receipt.Result)
	}
	if len(s.receipt.Comparisons) != 3 {
		t.Fatalf("receipt comparisons = %d, want 3", len(s.receipt.Comparisons))
	}
	for _, c := range s.receipt.Comparisons {
		if c.Result != "matched" {
			t.Fatalf("comparison %q = %q, want matched", c.Output, c.Result)
		}
	}
	rep, _ := s.diagnostic.Extra["reproduction"].(map[string]any)
	if status, _ := rep["exact_replay"].(string); status != "matched" {
		t.Fatalf("reproduction.exact_replay = %q, want matched", status)
	}
	if report.ReplayResult != "matched" {
		t.Fatalf("report replay_result = %q, want matched", report.ReplayResult)
	}
	if s.receipt.InvokedBrowser || s.receipt.InvokedSubject || s.receipt.PerformedExternalWrites {
		t.Fatalf("replay must not invoke browser/subject or external writes")
	}
}

func TestManualAcceptanceCannotCreditNonexistentSubjectRequirements(t *testing.T) {
	f := newFixture(t, "owner-manual-21")
	s := buildFullScenario(t, f, "journal-manual-21", "session-manual-21")
	// Valid fixture passes.
	checkAcceptance(t, f, s)

	mutate := func(t *testing.T, journalSuffix string, sessionSuffix string, edit func(extra map[string]any)) *builtScenario {
		t.Helper()
		m := manualManifest(f.domain, journalSuffix)
		admission := admitJournal(t, f.ctx, f.store, m)
		classifierRef := installArtifact(t, f.ctx, f.store, []byte(`{"classifier":"v1"}`), "application/json", "public")
		registryRef := installArtifact(t, f.ctx, f.store, []byte(`{"requirements":"v1"}`), "application/json", "public")
		engineRef := installArtifact(t, f.ctx, f.store, []byte(`{"engine":"v1"}`), "application/json", "public")
		reducerRef := installArtifact(t, f.ctx, f.store, []byte(`{"reducer":"v1"}`), "application/json", "public")
		docBytes := []byte("synthetic-manual-document-bytes-v1")
		docRef := installArtifact(t, f.ctx, f.store, docBytes, "application/octet-stream", "public")
		docDigest := string(evidence_codec.HashBytes(docBytes))
		steps := fullSteps(docDigest, docRef, int64(len(docBytes)))
		later := commitSteps(t, f.ctx, f.store, m.JournalID, m, 2, steps)
		events := append(append([]journal_rules.JournalEnvelope{}, admission...), later...)
		prefix := prefixThrough(events)
		extra := fullExtra(events, docDigest)
		edit(extra)
		diagnostic := buildDiagnostic(t, m, prefix, events, classifierRef, registryRef, []journal_rules.ArtifactReference{docRef}, extra)
		registration := sessionRegistration(sessionSuffix)
		row := buildTestRow(t, f.ctx, f.store, registration, prefix, events)
		inputs, err := evidence_bundle.ExportReplayInputs(f.ctx, f.store, row, diagnostic)
		if err != nil {
			t.Fatalf("ExportReplayInputs: %v", err)
		}
		manifestDigest := string(evidence_codec.HashBytes(canonicalBytes(t, m)))
		sourceDiagnostic := installArtifact(t, f.ctx, f.store, canonicalBytes(t, diagnostic), "application/json", "public")
		receipt := buildReceipt(t, diagnostic, manifestDigest, inputs, sourceDiagnostic, engineRef,
			evidence_bundle.VersionPin{ID: "reducer", Version: "v1", ArtifactDigest: reducerRef.Digest}, "exact_fixture")
		return &builtScenario{inputs: inputs, receipt: receipt, events: events, diagnostic: diagnostic}
	}

	// Crediting R1 to a nonexistent subject must fail.
	credited := mutate(t, "journal-manual-21b", "session-manual-21b", func(extra map[string]any) {
		assessments, _ := extra["requirement_assessments"].([]any)
		first, _ := assessments[0].(map[string]any)
		first["result"] = "satisfied"
		first["reason"] = "observed"
	})
	if _, err := CheckManualAcceptance(f.ctx, f.store, credited.inputs, credited.receipt); err == nil {
		t.Fatalf("credited R1 passed, want rejection")
	} else if !strings.Contains(strings.ToLower(err.Error()), "not_exercised") && !strings.Contains(strings.ToLower(err.Error()), "notexercised") {
		t.Logf("credited R1 rejected as required: %v", err)
	}

	// Attributing the validation rejection to a subject must fail.
	subjectLocus := mutate(t, "journal-manual-21c", "session-manual-21c", func(extra map[string]any) {
		extra["defect_locus"] = "subject"
	})
	if _, err := CheckManualAcceptance(f.ctx, f.store, subjectLocus.inputs, subjectLocus.receipt); err == nil {
		t.Fatalf("subject defect_locus passed, want rejection")
	}

	// A concrete execution subject must fail.
	concreteSubject := mutate(t, "journal-manual-21d", "session-manual-21d", func(extra map[string]any) {
		extra["execution"] = map[string]any{"subject": "subject-1"}
	})
	if _, err := CheckManualAcceptance(f.ctx, f.store, concreteSubject.inputs, concreteSubject.receipt); err == nil {
		t.Fatalf("concrete execution subject passed, want rejection")
	}
}

func TestManualAcceptanceReferencesStayWithinRetainedPrefixClosure(t *testing.T) {
	f := newFixture(t, "owner-manual-22")
	s := buildFullScenario(t, f, "journal-manual-22", "session-manual-22")
	report := checkAcceptance(t, f, s)
	if report.Result != "pass" {
		t.Fatalf("valid references rejected")
	}

	// An extra reference beyond the retained prefix must fail.
	m := manualManifest(f.domain, "journal-manual-22b")
	admission := admitJournal(t, f.ctx, f.store, m)
	classifierRef := installArtifact(t, f.ctx, f.store, []byte(`{"classifier":"v1"}`), "application/json", "public")
	registryRef := installArtifact(t, f.ctx, f.store, []byte(`{"requirements":"v1"}`), "application/json", "public")
	engineRef := installArtifact(t, f.ctx, f.store, []byte(`{"engine":"v1"}`), "application/json", "public")
	reducerRef := installArtifact(t, f.ctx, f.store, []byte(`{"reducer":"v1"}`), "application/json", "public")
	docBytes := []byte("synthetic-manual-document-bytes-v1")
	docRef := installArtifact(t, f.ctx, f.store, docBytes, "application/octet-stream", "public")
	docDigest := string(evidence_codec.HashBytes(docBytes))
	steps := fullSteps(docDigest, docRef, int64(len(docBytes)))
	later := commitSteps(t, f.ctx, f.store, m.JournalID, m, 2, steps)
	events := append(append([]journal_rules.JournalEnvelope{}, admission...), later...)
	prefix := prefixThrough(events)
	extra := fullExtra(events, docDigest)
	extra["stray_reference"] = map[string]any{
		"journal_id": "journal-manual-22b",
		"sequence":   int64(999),
		"event_id":   "evt-missing",
		"event_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"pointer":    "",
	}
	diagnostic := buildDiagnostic(t, m, prefix, events, classifierRef, registryRef, []journal_rules.ArtifactReference{docRef}, extra)
	registration := sessionRegistration("session-manual-22b")
	row := buildTestRow(t, f.ctx, f.store, registration, prefix, events)
	inputs, err := evidence_bundle.ExportReplayInputs(f.ctx, f.store, row, diagnostic)
	if err != nil {
		t.Fatalf("ExportReplayInputs: %v", err)
	}
	manifestDigest := string(evidence_codec.HashBytes(canonicalBytes(t, m)))
	sourceDiagnostic := installArtifact(t, f.ctx, f.store, canonicalBytes(t, diagnostic), "application/json", "public")
	receipt := buildReceipt(t, diagnostic, manifestDigest, inputs, sourceDiagnostic, engineRef,
		evidence_bundle.VersionPin{ID: "reducer", Version: "v1", ArtifactDigest: reducerRef.Digest}, "exact_fixture")
	if _, err := CheckManualAcceptance(f.ctx, f.store, inputs, receipt); err == nil {
		t.Fatalf("out-of-prefix reference passed, want rejection")
	}
}

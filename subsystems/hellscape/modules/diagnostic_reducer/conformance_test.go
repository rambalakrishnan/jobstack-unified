package diagnostic_reducer

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"evidence_codec"
	"journal_rules"
	"lifecycle_rules"
)

// ---------------------------------------------------------------------------
// Test helpers.
// ---------------------------------------------------------------------------

func testDigest(ch byte) string {
	return string(evidence_codec.HashBytes([]byte("test-digest-" + string([]byte{ch}))))
}

func testClassifier() VersionPin {
	return VersionPin{ID: "classifier", Version: "v1", ArtifactDigest: testDigest('c')}
}

func testRegistry() VersionPin {
	return VersionPin{ID: "req-registry", Version: "v1", ArtifactDigest: testDigest('r')}
}

func testManifest() Manifest {
	return Manifest{
		RecordType:     "manifest",
		SchemaVersion:  "1.0.0",
		ManifestID:     "manifest-1",
		RunID:          "run-1",
		JournalID:      "journal-1",
		OwnerDomain:    "laboratory",
		CommissionerID: "commissioner-1",
		Activity:       "application_attempt",
		Attempt: AttemptContext{
			Kind: "practice", Context: "laboratory_fixture", Scope: "held_in",
			SubjectVersion: "subject-1.0", Assistance: "none",
		},
		Execution:       map[string]any{"mode": "subject"},
		Task:            map[string]any{"task_id": "task-1"},
		TaskSemanticHash: testDigest('s'),
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

func testSubject() SubjectIdentity {
	return SubjectIdentity{
		SubjectID: "subject-A", SubjectVersion: "subject-1.0",
		ConfiguredMode: "auto", InterfaceSurface: "web",
	}
}

func testRequest() AnalysisRequest {
	return AnalysisRequest{
		DiagnosticID:        "diag-1",
		AnalysisRevision:    1,
		Classifier:          testClassifier(),
		RequirementRegistry: testRegistry(),
		FixRegistry:         NewMissing("not_enabled"),
		ManualMode:          false,
		Subject:             testSubject(),
	}
}

// --- journal chain ---

func canonicalWithoutHash(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	m := v.(map[string]any)
	delete(m, "event_hash")
	if m["causal_refs"] == nil {
		m["causal_refs"] = []any{}
	}
	if m["payload"] == nil {
		m["payload"] = map[string]any{}
	}
	remarshaled, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return evidence_codec.CanonicalJSON(remarshaled, "application/json")
}

func computeTestHash(ev JournalEnvelope) string {
	raw, _ := json.Marshal(ev)
	canonical, err := canonicalWithoutHash(raw)
	if err != nil {
		panic(err)
	}
	return string(evidence_codec.HashBytes(canonical))
}

func journalManifestDigest(t *testing.T, m Manifest) string {
	t.Helper()
	jman := m.toJournalManifest()
	raw, err := json.Marshal(jman)
	if err != nil {
		t.Fatalf("cannot marshal manifest: %v", err)
	}
	canonical, err := evidence_codec.CanonicalJSON(raw, "application/json")
	if err != nil {
		t.Fatalf("cannot canonicalize manifest: %v", err)
	}
	return string(evidence_codec.HashBytes(canonical))
}

func testTP(offset float64) TimePoint {
	return TimePoint{
		ClockID: "engine-clock", BootID: "boot-1", Origin: "engine_measured",
		MonotonicOffsetMs: offset, UTCAnnotation: NewMissing("not_applicable"),
	}
}

func finalizeTestEnv(ev *JournalEnvelope) {
	if ev.CausalRefs == nil {
		ev.CausalRefs = []EvidenceRef{}
	}
	if ev.Payload.Data == nil {
		ev.Payload.Data = map[string]any{}
	}
	if ev.Payload.Measurements == nil {
		ev.Payload.Measurements = []journal_rules.Measurement{}
	}
	if ev.Payload.EvidenceRefs == nil {
		ev.Payload.EvidenceRefs = []EvidenceRef{}
	}
	if ev.Payload.ArtifactRefs == nil {
		ev.Payload.ArtifactRefs = []journal_rules.ArtifactReference{}
	}
	ev.EventHash = computeTestHash(*ev)
}

func baseTestEnv(seq int64, eventID, kind string, prev any, manifestDigest string) JournalEnvelope {
	role := "lifecycle_observation"
	producer := "recorder-1"
	provenance := "server"
	if kind == "manifest_admitted" {
		role = "external_input"
		producer = "kernel"
	}
	return JournalEnvelope{
		RecordType: "journal_event", SchemaVersion: "0.1.0",
		RunID: "run-1", JournalID: "journal-1", ManifestHash: manifestDigest,
		Sequence: seq, EventID: eventID, EventKind: kind, EventSchemaVersion: "v1",
		Role: role, AssertionKind: "observation", OwnerDomain: "laboratory",
		ProducerID: producer, ProducerSequence: seq,
		Provenance: provenance, EvidenceScope: "current_run",
		RecordedAt: testTP(float64(1000 + seq*10)), OccurredAt: NewMissing("not_observed"),
		CausalRefs: []EvidenceRef{},
		Payload: struct {
			Data         map[string]any              `json:"data"`
			Measurements []journal_rules.Measurement `json:"measurements"`
			EvidenceRefs []EvidenceRef               `json:"evidence_refs"`
			ArtifactRefs []journal_rules.ArtifactReference `json:"artifact_refs"`
		}{
			Data: map[string]any{}, Measurements: []journal_rules.Measurement{},
			EvidenceRefs: []EvidenceRef{}, ArtifactRefs: []journal_rules.ArtifactReference{},
		},
		PreviousEventHash: prev, EventHash: "",
	}
}

type midEvent struct {
	Data         map[string]any
	Measurements []journal_rules.Measurement
}

func buildPrefix(t *testing.T, manifest Manifest, mids []midEvent, req AnalysisRequest) ([]JournalEnvelope, JournalPrefix) {
	t.Helper()
	digest := journalManifestDigest(t, manifest)
	events := make([]JournalEnvelope, 0, len(mids)+2)
	ev1 := baseTestEnv(1, "evt-admission", "manifest_admitted", NewMissing("not_applicable"), digest)
	ev1.Payload.Data = map[string]any{"manifest": map[string]any{"digest": digest}}
	finalizeTestEnv(&ev1)
	events = append(events, ev1)
	for i, mid := range mids {
		seq := int64(i + 2)
		ev := baseTestEnv(seq, "evt-mid-"+string(rune('a'+i)), "observation_noted", events[len(events)-1].EventHash, digest)
		if mid.Data != nil {
			ev.Payload.Data = mid.Data
		}
		if mid.Measurements != nil {
			ev.Payload.Measurements = mid.Measurements
		}
		finalizeTestEnv(&ev)
		events = append(events, ev)
	}
	seq := int64(len(events) + 1)
	last := baseTestEnv(seq, "evt-analysis", "analysis_requested", events[len(events)-1].EventHash, digest)
	last.Role = "lifecycle_observation"
	last.Provenance = "server"
	fix := req.FixRegistry
	if fix == nil {
		fix = NewMissing("not_enabled")
	}
	last.Payload.Data = map[string]any{
		"diagnostic_id":    req.DiagnosticID,
		"analysis_revision": req.AnalysisRevision,
		"classifier": map[string]any{
			"id": req.Classifier.ID, "version": req.Classifier.Version,
			"artifact_digest": req.Classifier.ArtifactDigest,
		},
		"requirement_registry": map[string]any{
			"id": req.RequirementRegistry.ID, "version": req.RequirementRegistry.Version,
			"artifact_digest": req.RequirementRegistry.ArtifactDigest,
		},
		"fix_registry": fix,
	}
	finalizeTestEnv(&last)
	events = append(events, last)
	prefix := JournalPrefix{JournalID: "journal-1", LastSequence: int64(len(events)), HeadHash: events[len(events)-1].EventHash}
	return events, prefix
}

func assessmentByID(doc DiagnosticDocument, id string) *RequirementAssessment {
	for i := range doc.RequirementAssessments {
		if doc.RequirementAssessments[i].RequirementID == id {
			return &doc.RequirementAssessments[i]
		}
	}
	return nil
}

func findingByLocus(doc DiagnosticDocument, locus string) *Finding {
	for i := range doc.Findings {
		if doc.Findings[i].DefectLocus == locus {
			return &doc.Findings[i]
		}
	}
	return nil
}

func findingsForReq(doc DiagnosticDocument, req string) []Finding {
	var out []Finding
	for _, f := range doc.Findings {
		for _, r := range f.RequirementRefs {
			if r == req {
				out = append(out, f)
			}
		}
	}
	return out
}

func capabilityByID(doc DiagnosticDocument, id string) *CapabilityEntry {
	for i := range doc.CapabilityCatalog.Capabilities {
		if doc.CapabilityCatalog.Capabilities[i].ID == id {
			return &doc.CapabilityCatalog.Capabilities[i]
		}
	}
	return nil
}

// --- lifecycle helpers for manual reconciliation ---

func testManualCommission(manifestDigest string) lifecycle_rules.AttemptCommission {
	return lifecycle_rules.AttemptCommission{
		RecordType: "attempt_commission", SchemaVersion: lifecycle_rules.SchemaLifecycle, KernelVersion: lifecycle_rules.SchemaKernel,
		CommissionID: "commission-1", RunID: "run-1", JournalID: "journal-1",
		ManifestHash: manifestDigest,
		AdmissionRef: lifecycle_rules.EvidenceRef{JournalID: "journal-1", Sequence: 1, EventID: "evt-admission", EventHash: testDigest('a'), Pointer: ""},
		CommissionedBy: "operator-1",
		CommissionedAt: lifecycle_rules.TimePoint{
			ClockID: "clk-1", BootID: "boot-1", Origin: "engine_measured",
			MonotonicOffsetMs: 10, UTCAnnotation: lifecycle_rules.NewMissing("not_applicable"),
		},
		Attempt: lifecycle_rules.AttemptContext{
			AttemptID: "attempt-1", Kind: "practice", TargetClass: "laboratory_fixture",
			TargetID: "origin-lab-1", EvaluationPartition: "held_in",
		},
		CandidateID: "candidate-1", CandidateProfile: lifecycle_rules.NewMissing("not_observed"),
		Job: lifecycle_rules.JobReference{
			JobID: "job-1", SourceTarget: lifecycle_rules.NewMissing("not_observed"),
			SourceJobID: lifecycle_rules.NewMissing("not_observed"),
			Snapshot: lifecycle_rules.ArtifactReference{
				Digest: testDigest('j'), SizeBytes: 128,
				MediaType: "application/json", OwnerDomain: "origin-domain", Access: "restricted",
			},
		},
		SelectionEvidence: lifecycle_rules.NewMissing("not_observed"),
		Task: lifecycle_rules.ArtifactReference{
			Digest: testDigest('t'), SizeBytes: 128,
			MediaType: "application/json", OwnerDomain: "origin-domain", Access: "restricted",
		},
		TaskSemanticHash: testDigest('s'),
		InitialMaterials: []lifecycle_rules.ArtifactReference{},
		Execution: lifecycle_rules.ExecutionDescriptor{
			Mode: "manual",
			Subject: lifecycle_rules.NewMissing("not_applicable"),
			ConnectorVersion: lifecycle_rules.NewMissing("not_applicable"),
			BindingVersion:   lifecycle_rules.NewMissing("not_applicable"),
			Assistance: lifecycle_rules.AssistanceRecord{
				PlanningOwner: "none", AssistanceTrack: "manual-track",
				PlannerIdentity: lifecycle_rules.NewMissing("not_applicable"), Plan: lifecycle_rules.NewMissing("not_observed"),
				OnlineReplanning: false, Description: "manual walkthrough",
			},
		},
		Owners: lifecycle_rules.OwnerBindings{
			Dispatch:    lifecycle_rules.AuthorityBinding{Role: "connector", SourceID: "connector-1", WriterID: "dispatch-writer", OwnerDomain: "dispatch-domain", PublicationPolicy: lifecycle_rules.VersionPin{ID: "pub", Version: "v1", ArtifactDigest: testDigest('p')}},
			Observation: lifecycle_rules.AuthorityBinding{Role: "connector", SourceID: "connector-1", WriterID: "obs-writer", OwnerDomain: "obs-domain", PublicationPolicy: lifecycle_rules.VersionPin{ID: "pub", Version: "v1", ArtifactDigest: testDigest('p')}},
			Execution:   lifecycle_rules.AuthorityBinding{Role: "subject", SourceID: lifecycle_rules.NewMissing("not_applicable"), WriterID: lifecycle_rules.NewMissing("not_applicable"), OwnerDomain: "exec-domain", PublicationPolicy: lifecycle_rules.VersionPin{ID: "pub", Version: "v1", ArtifactDigest: testDigest('p')}},
			Application: lifecycle_rules.AuthorityBinding{Role: "origin", SourceID: "origin-lab-1", WriterID: "app-writer", OwnerDomain: "origin-domain", PublicationPolicy: lifecycle_rules.VersionPin{ID: "pub", Version: "v1", ArtifactDigest: testDigest('p')}},
			Report:      lifecycle_rules.AuthorityBinding{Role: "reconciler", SourceID: "reconciler-1", WriterID: "report-writer", OwnerDomain: "report-domain", PublicationPolicy: lifecycle_rules.VersionPin{ID: "pub", Version: "v1", ArtifactDigest: testDigest('p')}},
		},
		IdempotencyKey:    "idem-1",
		AuthorizationRefs: []lifecycle_rules.EvidenceRef{{JournalID: "journal-1", Sequence: 1, EventID: "evt-admission", EventHash: testDigest('a'), Pointer: ""}},
		RecoveryReviewRefs: []lifecycle_rules.EvidenceRef{},
		ObservationPolicy: lifecycle_rules.ObservationPolicy{
			ActiveLimit: lifecycle_rules.DurationLimit{Kind: "exact", Unit: "ms", Value: 60000},
			DrainLimit:  lifecycle_rules.DurationLimit{Kind: "exact", Unit: "ms", Value: 10000},
			NativeCancelWaitLimit: lifecycle_rules.DurationLimit{Kind: "exact", Unit: "ms", Value: 5000},
			CleanupWaitLimit:      lifecycle_rules.DurationLimit{Kind: "exact", Unit: "ms", Value: 5000},
			FixtureCloseAction:    "seal_after_drain",
		},
		OriginPolicy: lifecycle_rules.VersionPin{ID: "origin-policy", Version: "v1", ArtifactDigest: testDigest('o')},
	}
}

// ---------------------------------------------------------------------------
// Conformance assertions.
// ---------------------------------------------------------------------------

func TestInvalidIsolationWriteControlCannotEstablishNonIsolation(t *testing.T) {
	m := testManifest()
	req := testRequest()
	req.Configuration = testConfig(t)
	mids := []midEvent{
		{Data: map[string]any{
			"isolation_probe": map[string]any{"write_control_valid": false, "marker_observed": true},
		}},
	}
	events, prefix := buildPrefix(t, m, mids, req)
	doc, err := DeriveDiagnostic(m, prefix, events, req)
	if err != nil {
		t.Fatalf("DeriveDiagnostic: %v", err)
	}
	r2 := assessmentByID(doc, "R2")
	if r2 == nil {
		t.Fatalf("missing R2 assessment")
	}
	if r2.Result == "violated" || r2.Result == "satisfied" {
		t.Fatalf("invalid write control must not yield %q; got %+v", r2.Result, r2)
	}
	if r2.Result != "indeterminate" {
		t.Fatalf("invalid write control must yield indeterminate, got %q (%s)", r2.Result, r2.Rationale)
	}
	if !strings.Contains(r2.Rationale, "invalid_write_control") {
		t.Fatalf("R2 rationale must cite invalid write control, got %q", r2.Rationale)
	}
	found := false
	for _, f := range findingsForReq(doc, "R2") {
		if f.Kind == "requirement_violation" {
			t.Fatalf("invalid write control must not produce a requirement_violation finding: %+v", f)
		}
		if strings.Contains(strings.ToLower(f.Symptom), "non-isolation not established") ||
			strings.Contains(strings.ToLower(f.Symptom), "without non-isolation") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an R2 finding retaining the signal without non-isolation; findings: %+v", doc.Findings)
	}
}

func TestMissingDependencyIsAnEnvironmentPrerequisiteFinding(t *testing.T) {
	m := testManifest()
	req := testRequest()
	req.Configuration = testConfig(t)
	mids := []midEvent{
		{Data: map[string]any{
			"missing_dependency": map[string]any{
				"dependency": "chromedriver-115", "affected_requirements": []any{"R1", "R3"},
			},
		}},
	}
	events, prefix := buildPrefix(t, m, mids, req)
	doc, err := DeriveDiagnostic(m, prefix, events, req)
	if err != nil {
		t.Fatalf("DeriveDiagnostic: %v", err)
	}
	f := findingByLocus(doc, "environment")
	if f == nil {
		t.Fatalf("missing dependency must produce an environment-locus finding; findings: %+v", doc.Findings)
	}
	if !strings.Contains(strings.ToLower(f.Symptom), "prerequisite") &&
		!strings.Contains(strings.ToLower(f.Symptom), "environment") {
		t.Fatalf("environment finding must name prerequisite/environment: %+v", f)
	}
	for _, rid := range []string{"R1", "R3"} {
		a := assessmentByID(doc, rid)
		if a == nil {
			t.Fatalf("missing %s assessment", rid)
		}
		if a.Opportunity.State != "blocked" {
			t.Fatalf("%s opportunity must be blocked, got %q", rid, a.Opportunity.State)
		}
		if a.Result != "not_exercised" && a.Result != "indeterminate" {
			t.Fatalf("%s result must be not_exercised or indeterminate, got %q", rid, a.Result)
		}
	}
	// Unaffected requirements stay independently assessed, not blocked.
	r2 := assessmentByID(doc, "R2")
	if r2 == nil || r2.Opportunity.State == "blocked" {
		t.Fatalf("unaffected R2 must not be blocked: %+v", r2)
	}
}

func TestAdapterOverclaimIsAttributedToConnectorOrHarness(t *testing.T) {
	m := testManifest()
	req := testRequest()
	req.Configuration = testConfig(t)
	mids := []midEvent{
		{Data: map[string]any{
			"adapter_claim": map[string]any{
				"capability_id": "native_cancel",
				"adapter_claims_supported": true, "native_supported": false,
			},
		}},
	}
	events, prefix := buildPrefix(t, m, mids, req)
	doc, err := DeriveDiagnostic(m, prefix, events, req)
	if err != nil {
		t.Fatalf("DeriveDiagnostic: %v", err)
	}
	f := findingByLocus(doc, "connector")
	if f == nil {
		t.Fatalf("adapter overclaim must be attributed to connector; findings: %+v", doc.Findings)
	}
	if f.Kind != "claim_contradiction" {
		t.Fatalf("adapter overclaim kind must be claim_contradiction, got %q", f.Kind)
	}
	hasR4 := false
	for _, r := range f.RequirementRefs {
		if r == "R4" {
			hasR4 = true
		}
	}
	if !hasR4 {
		t.Fatalf("connector finding must reference R4 (native_cancel scope): %+v", f)
	}
	r4 := assessmentByID(doc, "R4")
	if r4 == nil {
		t.Fatalf("missing R4 assessment")
	}
	if r4.Result == "satisfied" || r4.Result == "violated" || r4.Result == "native_absence" {
		t.Fatalf("overclaimed capability must not yield a native verdict; got %q", r4.Result)
	}
	if r4.Result != "indeterminate" {
		t.Fatalf("overclaimed R4 must be indeterminate, got %q", r4.Result)
	}
	if len(doc.Claims) == 0 {
		t.Fatalf("adapter claim must be preserved as a claim with comparison")
	}
}

func TestUnexposedFeatureReceivesNoBehavioralPassOrFailure(t *testing.T) {
	m := testManifest()
	req := testRequest()
	req.Configuration = testConfig(t)
	mids := []midEvent{
		{Data: map[string]any{
			"feature_exposure": map[string]any{
				"feature_id": "feat-1", "configured": true, "rendered_armed": false,
				"exposed": false, "activated": false, "requirement_ref": "R8",
			},
		}},
		{Data: map[string]any{
			"requirement_outcome": map[string]any{
				"requirement_id": "R8", "facet": "native_dom_access",
				"observed_outcome": "satisfied", "controls_valid": true, "has_supporting_evidence": true,
			},
		}},
	}
	events, prefix := buildPrefix(t, m, mids, req)
	doc, err := DeriveDiagnostic(m, prefix, events, req)
	if err != nil {
		t.Fatalf("DeriveDiagnostic: %v", err)
	}
	r8 := assessmentByID(doc, "R8")
	if r8 == nil {
		t.Fatalf("missing R8 assessment")
	}
	if r8.Opportunity.State != "unexposed" {
		t.Fatalf("unexposed feature must yield unexposed opportunity, got %q", r8.Opportunity.State)
	}
	if r8.Result != "not_exercised" {
		t.Fatalf("unexposed feature must yield not_exercised (no pass/fail), got %q", r8.Result)
	}
	if len(doc.FeatureExposures) != 1 || doc.FeatureExposures[0].Exposed {
		t.Fatalf("feature exposure must be preserved as unexposed: %+v", doc.FeatureExposures)
	}
}

func TestFixtureDefectInvalidatesOnlyDependentOpportunities(t *testing.T) {
	m := testManifest()
	req := testRequest()
	req.Configuration = testConfig(t)
	mids := []midEvent{
		{Data: map[string]any{
			"fixture_defect": map[string]any{
				"affected_requirement": "R1", "affected_facet": "rendering", "detail": "renderer crash",
			},
		}},
	}
	events, prefix := buildPrefix(t, m, mids, req)
	doc, err := DeriveDiagnostic(m, prefix, events, req)
	if err != nil {
		t.Fatalf("DeriveDiagnostic: %v", err)
	}
	r1 := assessmentByID(doc, "R1")
	if r1 == nil {
		t.Fatalf("missing R1 assessment")
	}
	if r1.Opportunity.State != "blocked" || r1.Result != "not_exercised" {
		t.Fatalf("defective R1 must be blocked/not_exercised, got %q/%q", r1.Opportunity.State, r1.Result)
	}
	f := findingByLocus(doc, "fixture")
	if f == nil || f.Kind != "fixture_error" {
		t.Fatalf("fixture defect must yield a fixture_error finding at fixture locus: %+v", doc.Findings)
	}
	if len(f.RequirementRefs) != 1 || f.RequirementRefs[0] != "R1" {
		t.Fatalf("fixture finding must reference only R1: %+v", f)
	}
	for _, rid := range []string{"R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9", "R10"} {
		a := assessmentByID(doc, rid)
		if a == nil {
			t.Fatalf("missing %s assessment", rid)
		}
		if a.Opportunity.State == "blocked" {
			t.Fatalf("fixture defect for R1 must not block %s: %+v", rid, a)
		}
	}
}

func TestManualPauseBelongsToWorkflowNotNativePrimitiveTime(t *testing.T) {
	m := testManifest()
	req := testRequest()
	req.Configuration = testConfig(t)
	manualStart := journal_rules.TimePoint{
		ClockID: "manual-clock", BootID: "boot-1", Origin: "manual_reference",
		MonotonicOffsetMs: 0, UTCAnnotation: NewMissing("not_applicable"),
	}
	manualEnd := journal_rules.TimePoint{
		ClockID: "manual-clock", BootID: "boot-1", Origin: "manual_reference",
		MonotonicOffsetMs: 5000, UTCAnnotation: NewMissing("not_applicable"),
	}
	engStart := journal_rules.TimePoint{
		ClockID: "engine-clock", BootID: "boot-1", Origin: "engine_measured",
		MonotonicOffsetMs: 200, UTCAnnotation: NewMissing("not_applicable"),
	}
	engEnd := journal_rules.TimePoint{
		ClockID: "engine-clock", BootID: "boot-1", Origin: "engine_measured",
		MonotonicOffsetMs: 230, UTCAnnotation: NewMissing("not_applicable"),
	}
	workflowMeas := journal_rules.Measurement{
		MeasurementID: "manual-pause-workflow", Name: "workflow_elapsed",
		Scope: journal_rules.Scope{Kind: "workflow_step", ID: "pause-1"},
		Quantity: "duration", Unit: "ms", Origin: "manual_reference",
		ClockID: "manual-clock", BootID: "boot-1", Method: "endpoint_difference",
		Start: manualStart, End: manualEnd,
		Estimate: journal_rules.Estimate{Kind: "exact", Value: 5000.0},
		Resolution: NewMissing("not_applicable"), Censoring: "none",
		ComparabilityGroup: NewMissing("not_applicable"),
	}
	primMeas := journal_rules.Measurement{
		MeasurementID: "prim-1", Name: "primitive_elapsed",
		Scope: journal_rules.Scope{Kind: "native_primitive", ID: "prim-1"},
		Quantity: "duration", Unit: "ms", Origin: "engine_measured",
		ClockID: "engine-clock", BootID: "boot-1", Method: "endpoint_difference",
		Start: engStart, End: engEnd,
		Estimate: journal_rules.Estimate{Kind: "exact", Value: 30.0},
		Resolution: NewMissing("not_applicable"), Censoring: "none",
		ComparabilityGroup: NewMissing("not_applicable"),
	}
	mids := []midEvent{
		{Data: map[string]any{"note": "pause observed"}, Measurements: []journal_rules.Measurement{workflowMeas, primMeas}},
	}
	events, prefix := buildPrefix(t, m, mids, req)
	doc, err := DeriveDiagnostic(m, prefix, events, req)
	if err != nil {
		t.Fatalf("DeriveDiagnostic: %v", err)
	}
	if len(doc.Measurements) != 2 {
		t.Fatalf("expected 2 preserved measurements, got %d", len(doc.Measurements))
	}
	byID := map[string]MeasurementEvidence{}
	for _, me := range doc.Measurements {
		byID[me.Measurement.MeasurementID] = me
		if me.Measurement.AggregateSource != "" {
			t.Fatalf("no invented aggregate split allowed: %+v", me.Measurement)
		}
	}
	wf, ok := byID["manual-pause-workflow"]
	if !ok {
		t.Fatalf("missing workflow pause measurement")
	}
	if wf.Measurement.Origin != "manual_reference" || wf.Measurement.Scope.Kind != "workflow_step" {
		t.Fatalf("manual pause must retain manual_reference workflow scope: %+v", wf.Measurement)
	}
	prim, ok := byID["prim-1"]
	if !ok {
		t.Fatalf("missing primitive measurement")
	}
	if prim.Measurement.Scope.Kind != "native_primitive" {
		t.Fatalf("primitive scope must stay native_primitive: %+v", prim.Measurement)
	}
	if v, ok := prim.Measurement.Estimate.Value.(float64); !ok || v != 30.0 {
		t.Fatalf("primitive duration must remain 30ms without pause time, got %v", prim.Measurement.Estimate.Value)
	}
	if prim.Measurement.Origin == "manual_reference" {
		t.Fatalf("primitive must not carry manual_reference origin: %+v", prim.Measurement)
	}
}

func TestManualRequirementsRemainNotExercisedWithoutSubjectClaims(t *testing.T) {
	m := testManifest()
	req := testRequest()
	req.ManualMode = true
	req.Subject = SubjectIdentity{}
	req.Configuration = testConfig(t)
	// Lifecycle reconciliation with manual all-zero pins exercises the
	// reconciler without inventing subject claims.
	digest := journalManifestDigest(t, m)
	commission := testManualCommission(digest)
	zero := lifecycle_rules.DomainPin{Revision: 0, RecordDigest: lifecycle_rules.NewMissing("not_applicable")}
	inputs := lifecycle_rules.ReportInputPins{
		Dispatch: zero, Observation: zero, Execution: zero, Application: zero,
	}
	evaluator := lifecycle_rules.VersionPin{ID: "evaluator", Version: "v1", ArtifactDigest: testDigest('e')}
	req.Commission = &commission
	req.ReportInputs = &inputs
	req.Publications = []lifecycle_rules.AxisRevision{}
	req.Evaluator = &evaluator
	mids := []midEvent{
		{Data: map[string]any{"note": "manual walkthrough observation"}},
	}
	events, prefix := buildPrefix(t, m, mids, req)
	doc, err := DeriveDiagnostic(m, prefix, events, req)
	if err != nil {
		t.Fatalf("DeriveDiagnostic: %v", err)
	}
	if len(doc.RequirementAssessments) != 10 {
		t.Fatalf("manual must still assess R1-R10, got %d", len(doc.RequirementAssessments))
	}
	for _, a := range doc.RequirementAssessments {
		if a.Result != "not_exercised" {
			t.Fatalf("manual %s must be not_exercised, got %q", a.RequirementID, a.Result)
		}
		if a.Rationale != "manual_fixture_validation" {
			t.Fatalf("manual %s rationale must be manual_fixture_validation, got %q", a.RequirementID, a.Rationale)
		}
	}
	if len(doc.Claims) != 0 {
		t.Fatalf("manual without subject claims must produce no claims, got %+v", doc.Claims)
	}
	if len(doc.CapabilityCatalog.Capabilities) != 0 {
		t.Fatalf("manual must fabricate no capability descriptors, got %+v", doc.CapabilityCatalog.Capabilities)
	}
	rep, ok := doc.Report.(lifecycle_rules.ReportValue)
	if !ok {
		t.Fatalf("manual report must be a lifecycle ReportValue, got %T", doc.Report)
	}
	if rep.Coverage != "not_applicable" {
		t.Fatalf("manual report coverage must be not_applicable, got %q", rep.Coverage)
	}
}

func TestNewSubjectVersionStartsWithCompleteUnknownCapabilityCatalog(t *testing.T) {
	m := testManifest()
	m.Subject.Version = "subject-2.0"
	m.Attempt.SubjectVersion = "subject-2.0"
	req := testRequest()
	req.Subject.SubjectVersion = "subject-2.0"
	req.Configuration = testConfig(t)
	// Case 1: no evidence at all -> complete unknown catalog.
	events, prefix := buildPrefix(t, m, nil, req)
	doc, err := DeriveDiagnostic(m, prefix, events, req)
	if err != nil {
		t.Fatalf("DeriveDiagnostic: %v", err)
	}
	if len(doc.CapabilityCatalog.Capabilities) != 10 {
		t.Fatalf("catalog must enumerate all 10 capabilities, got %d", len(doc.CapabilityCatalog.Capabilities))
	}
	for _, c := range doc.CapabilityCatalog.Capabilities {
		if c.Availability != "unknown" {
			t.Fatalf("new version %s must start unknown, got %q", c.ID, c.Availability)
		}
	}
	// Case 2: predecessor v1 evidence ignored; own v2 evidence promotes one entry.
	mids := []midEvent{
		{Data: map[string]any{
			"capability_evidence": map[string]any{
				"capability_id": "native_cancel", "availability": "present",
				"claim_origin": "native", "subject_version": "subject-1.0",
			},
		}},
		{Data: map[string]any{
			"capability_evidence": map[string]any{
				"capability_id": "native_goal_task", "availability": "present",
				"claim_origin": "native", "subject_version": "subject-2.0",
			},
		}},
	}
	events2, prefix2 := buildPrefix(t, m, mids, req)
	doc2, err := DeriveDiagnostic(m, prefix2, events2, req)
	if err != nil {
		t.Fatalf("DeriveDiagnostic: %v", err)
	}
	cancel := capabilityByID(doc2, "native_cancel")
	if cancel == nil || cancel.Availability != "unknown" {
		t.Fatalf("predecessor v1 evidence must not populate v2 native_cancel: %+v", cancel)
	}
	goal := capabilityByID(doc2, "native_goal_task")
	if goal == nil || goal.Availability != "present" {
		t.Fatalf("own v2 evidence must establish native_goal_task present: %+v", goal)
	}
	if doc2.CapabilityCatalog.Subject.SubjectVersion != "subject-2.0" {
		t.Fatalf("catalog must scope to v2: %+v", doc2.CapabilityCatalog.Subject)
	}
}

func TestCapabilityOpportunityAndResultRemainIndependent(t *testing.T) {
	m := testManifest()
	req := testRequest()
	req.Configuration = testConfig(t)
	mids := []midEvent{
		{Data: map[string]any{
			"capability_evidence": map[string]any{
				"capability_id": "native_dom_access", "availability": "present",
				"claim_origin": "native", "subject_version": "subject-1.0",
			},
		}},
		{Data: map[string]any{
			"capability_evidence": map[string]any{
				"capability_id": "native_cancel", "availability": "absent",
				"claim_origin": "native", "subject_version": "subject-1.0",
			},
		}},
		{Data: map[string]any{
			"feature_exposure": map[string]any{
				"feature_id": "feat-r3", "configured": true, "rendered_armed": true,
				"exposed": false, "activated": false, "requirement_ref": "R3",
			},
		}},
		{Data: map[string]any{
			"requirement_outcome": map[string]any{
				"requirement_id": "R1", "facet": "rendering",
				"observed_outcome": "satisfied", "controls_valid": true, "has_supporting_evidence": true,
			},
		}},
		{Data: map[string]any{
			"requirement_outcome": map[string]any{
				"requirement_id": "R3", "facet": "primitive_claims",
				"observed_outcome": "satisfied", "controls_valid": true, "has_supporting_evidence": true,
			},
		}},
		{Data: map[string]any{
			"requirement_outcome": map[string]any{
				"requirement_id": "R5", "facet": "local_access",
				"observed_outcome": "satisfied", "controls_valid": false, "has_supporting_evidence": true,
			},
		}},
	}
	events, prefix := buildPrefix(t, m, mids, req)
	doc, err := DeriveDiagnostic(m, prefix, events, req)
	if err != nil {
		t.Fatalf("DeriveDiagnostic: %v", err)
	}
	// R1: present + exposed + valid outcome -> satisfied.
	r1 := assessmentByID(doc, "R1")
	if r1 == nil || r1.Result != "satisfied" || r1.Opportunity.State != "exposed" {
		t.Fatalf("R1 must be exposed/satisfied: %+v", r1)
	}
	// R3: present outcome but unexposed -> not_exercised, never satisfied.
	r3 := assessmentByID(doc, "R3")
	if r3 == nil || r3.Opportunity.State != "unexposed" || r3.Result != "not_exercised" {
		t.Fatalf("R3 unexposed must be unexposed/not_exercised despite outcome: %+v", r3)
	}
	// R4: required absent native_cancel with exact-scope evidence -> native_absence.
	r4 := assessmentByID(doc, "R4")
	if r4 == nil || r4.Result != "native_absence" {
		t.Fatalf("R4 must be native_absence on exact-scope absent evidence: %+v", r4)
	}
	// R5: invalid controls -> indeterminate, never satisfied.
	r5 := assessmentByID(doc, "R5")
	if r5 == nil || r5.Result != "indeterminate" {
		t.Fatalf("R5 with invalid controls must be indeterminate: %+v", r5)
	}
	// R6: capability present alone (no outcome) is indeterminate, not satisfied.
	// R6 maps to native_artifact_retrieval which has no evidence -> default indeterminate.
	r6 := assessmentByID(doc, "R6")
	if r6 == nil || r6.Result != "indeterminate" {
		t.Fatalf("R6 without outcome must be indeterminate: %+v", r6)
	}
	// Capability and opportunity stay independent fields.
	if r1.Opportunity.State == r1.Result {
		t.Fatalf("opportunity and result must be independent fields")
	}
}

func TestAnalysisDependsOnlyOnPinnedManifestPrefixAndClassifier(t *testing.T) {
	m := testManifest()
	req := testRequest()
	req.Configuration = testConfig(t)
	mids := []midEvent{
		{Data: map[string]any{
			"requirement_outcome": map[string]any{
				"requirement_id": "R1", "facet": "rendering",
				"observed_outcome": "satisfied", "controls_valid": true, "has_supporting_evidence": true,
			},
		}},
	}
	events, prefix := buildPrefix(t, m, mids, req)
	doc1, err := DeriveDiagnostic(m, prefix, events, req)
	if err != nil {
		t.Fatalf("DeriveDiagnostic: %v", err)
	}
	// Determinism: same inputs twice -> identical bytes.
	doc2, err := DeriveDiagnostic(m, prefix, events, req)
	if err != nil {
		t.Fatalf("DeriveDiagnostic second call: %v", err)
	}
	b1, _ := json.Marshal(doc1)
	b2, _ := json.Marshal(doc2)
	if !bytes.Equal(b1, b2) {
		t.Fatalf("deterministic analysis must produce identical bytes for identical inputs")
	}
	// Prefix pinning: extra events beyond the prefix are ignored.
	digest := journalManifestDigest(t, m)
	extra := baseTestEnv(int64(len(events)+1), "evt-late", "observation_noted", events[len(events)-1].EventHash, digest)
	extra.Payload.Data = map[string]any{
		"requirement_outcome": map[string]any{
			"requirement_id": "R1", "facet": "rendering",
			"observed_outcome": "violated", "controls_valid": true, "has_supporting_evidence": true,
		},
	}
	finalizeTestEnv(&extra)
	extended := append(append([]JournalEnvelope{}, events...), extra)
	doc3, err := DeriveDiagnostic(m, prefix, extended, req)
	if err != nil {
		t.Fatalf("DeriveDiagnostic with late evidence: %v", err)
	}
	b3, _ := json.Marshal(doc3)
	if !bytes.Equal(b1, b3) {
		t.Fatalf("evidence beyond the pinned prefix must be ignored (late evidence needs a new revision)")
	}
	// Classifier pinning: the diagnostic cites its exact classifier.
	if doc1.Classifier != req.Classifier {
		t.Fatalf("diagnostic must cite the pinned classifier: %+v", doc1.Classifier)
	}
	if doc1.InputPrefix != prefix {
		t.Fatalf("diagnostic must cite its exact input prefix")
	}
	if !strings.HasPrefix(doc1.ManifestHash, "sha256:") {
		t.Fatalf("diagnostic must cite the manifest hash")
	}
	// Different classifier -> different (but still deterministic) diagnostic.
	reqAlt := req
	reqAlt.DiagnosticID = "diag-2"
	reqAlt.Classifier = VersionPin{ID: "classifier", Version: "v2", ArtifactDigest: testDigest('d')}
	eventsAlt, prefixAlt := buildPrefix(t, m, mids, reqAlt)
	docAlt, err := DeriveDiagnostic(m, prefixAlt, eventsAlt, reqAlt)
	if err != nil {
		t.Fatalf("DeriveDiagnostic alt classifier: %v", err)
	}
	if docAlt.Classifier == doc1.Classifier {
		t.Fatalf("changed classifier pin must change the diagnostic")
	}
	if docAlt.DiagnosticID != "diag-2" {
		t.Fatalf("diagnostic ID must follow the pinned request")
	}
}

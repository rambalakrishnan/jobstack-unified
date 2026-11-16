package admission

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"application_owner"
	"authority"
	"evidence_codec"
	"owner_store"
)

func testPolicy() []byte {
	return []byte(`{"channels":{"test-channel":{"principal":"test-writer","kind":"owner","grants":[{"domain":"*","operations":["*"]}]}}}`)
}

func authedContext(t *testing.T) context.Context {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "http://admission.test/direct", nil)
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

func openStore(t *testing.T, domain string) *OwnerStore {
	t.Helper()
	home := t.TempDir()
	store, err := owner_store.OpenOwner(
		filepath.Join(home, domain+".db"),
		filepath.Join(home, domain+"-artifacts"),
		domain,
	)
	if err != nil {
		t.Fatalf("OpenOwner(%s): %v", domain, err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func testDigest(seed string) string {
	return string(evidence_codec.HashBytes([]byte(seed)))
}

func testArtifact(seed, ownerDomain, access string) ArtifactReference {
	return ArtifactReference{
		Digest:      testDigest(seed),
		SizeBytes:   int64(len(seed) + 1),
		MediaType:   "application/json",
		OwnerDomain: ownerDomain,
		Access:      access,
	}
}

func testEvidenceRef(journalID, suffix string, seq int64) EvidenceRef {
	return EvidenceRef{
		JournalID: journalID,
		Sequence:  seq,
		EventID:   "evt-" + suffix,
		EventHash: testDigest("evt-" + suffix),
		Pointer:   "",
	}
}

func testTimePoint(journalID string) TimePoint {
	return TimePoint{
		ClockID:           "clock-" + journalID,
		BootID:            "boot-" + journalID,
		Origin:            "engine_measured",
		MonotonicOffsetMs: 0,
		UTCAnnotation:     NewMissing("not_applicable"),
	}
}

func testVersionPin(id string) VersionPin {
	return VersionPin{ID: id, Version: "1.0", ArtifactDigest: testDigest(id)}
}

func testManifest(suffix, subjectVersion string) Manifest {
	m := Manifest{
		RecordType:     "manifest",
		SchemaVersion:  "1.0.0",
		ManifestID:     "manifest-" + suffix,
		RunID:          "attempt-" + suffix,
		JournalID:      "journal-" + suffix,
		OwnerDomain:    "diagnostic",
		CommissionerID: "test-writer",
		Activity:       "application_attempt",
		Execution:      map[string]any{"mode": "manual"},
		Task:           map[string]any{"task_id": "task-" + suffix},
		TaskSemanticHash: testDigest("task-sem-" + suffix),
		Environment:      map[string]any{"deployment": "laboratory"},
		Seed:             "seed-" + suffix,
		BuildPins:        map[string]string{"fixture": "1.0.0"},
		EventRegistry:    map[string]string{"kind1": "v1"},
		Producers:        []map[string]any{{"producer_id": "p1"}},
		Clocks:           []map[string]any{{"clock_id": "c1"}},
		Profile:          "M1",
	}
	m.Attempt.Kind = "practice"
	m.Attempt.Context = "laboratory_fixture"
	m.Attempt.Scope = "held_in"
	m.Attempt.SubjectVersion = subjectVersion
	m.Attempt.Assistance = "none"
	if subjectVersion != "" {
		m.Subject.Name = "subject-A"
		m.Subject.Version = subjectVersion
		m.Execution = map[string]any{"mode": "subject"}
	}
	m.Lineage.Kind = "practice"
	return m
}

func testOwners(targetID, mode string) OwnerBindings {
	pub := func(id string) VersionPin { return testVersionPin(id) }
	execSource, execWriter := any(NewMissing("not_applicable")), any(NewMissing("not_applicable"))
	if mode == "subject" {
		execSource = "exec-source"
		execWriter = "exec-writer"
	}
	return OwnerBindings{
		Dispatch:    AuthorityBinding{Role: "connector", SourceID: "dispatch-source", WriterID: "dispatch-writer", OwnerDomain: "dispatch", PublicationPolicy: pub("pub-dispatch")},
		Observation: AuthorityBinding{Role: "connector", SourceID: "obs-source", WriterID: "obs-writer", OwnerDomain: "observation", PublicationPolicy: pub("pub-observation")},
		Execution:   AuthorityBinding{Role: "subject", SourceID: execSource, WriterID: execWriter, OwnerDomain: "execution", PublicationPolicy: pub("pub-execution")},
		Application: AuthorityBinding{Role: "origin", SourceID: targetID, WriterID: "app-writer", OwnerDomain: "application", PublicationPolicy: pub("pub-application")},
		Report:      AuthorityBinding{Role: "reconciler", SourceID: "report-source", WriterID: "report-writer", OwnerDomain: "report", PublicationPolicy: pub("pub-report")},
	}
}

func testCommission(t *testing.T, suffix string, manifest Manifest, mode string) AttemptCommission {
	t.Helper()
	targetID := "target-" + suffix
	digest, err := PrimaryManifestDigest(manifest)
	if err != nil {
		t.Fatalf("PrimaryManifestDigest: %v", err)
	}
	ex := ExecutionDescriptor{Mode: mode}
	if mode == "manual" {
		ex.Subject = NewMissing("not_applicable")
		ex.ConnectorVersion = NewMissing("not_applicable")
		ex.BindingVersion = NewMissing("not_applicable")
	} else {
		ex.Subject = SubjectIdentity{
			SubjectID: "subject-A", SubjectVersion: "subject-1.0", RevisionBasis: "basis-1",
			NativeRevision: NewMissing("not_observed"), ConfiguredMode: "subject",
			InterfaceSurface: "test-surface", ConfigurationDigest: testDigest("config-" + suffix),
			Stack: []ComponentIdentity{{Component: "comp", ReportedVersion: "1.0", BuildDigest: "build-1", ConfigurationDigest: "cfg-1"}},
		}
		ex.ConnectorVersion = "connector-1.0"
		ex.BindingVersion = "binding-1.0"
	}
	ex.Assistance = AssistanceRecord{
		PlanningOwner: "operator", AssistanceTrack: "manual",
		PlannerIdentity: NewMissing("not_applicable"), Plan: NewMissing("not_applicable"),
		OnlineReplanning: false, Description: "test execution",
	}
	return AttemptCommission{
		RecordType:     "attempt_commission",
		SchemaVersion:  schemaLifecycle,
		KernelVersion:  schemaKernel,
		CommissionID:   "commission-" + suffix,
		RunID:          manifest.RunID,
		JournalID:      manifest.JournalID,
		ManifestHash:   digest,
		AdmissionRef:   testEvidenceRef(manifest.JournalID, suffix+"-admission", 2),
		CommissionedBy: "test-writer",
		CommissionedAt: testTimePoint(manifest.JournalID),
		Attempt: AttemptContext{
			AttemptID: "attempt-" + suffix, Kind: "practice",
			TargetClass: "laboratory_fixture", TargetID: targetID,
			EvaluationPartition: "held_in",
			RehearsalOf:         []AttemptReference{},
			PerformanceOf:       []AttemptReference{},
			DerivedFrom:         []AttemptReference{},
		},
		CandidateID:        "candidate-" + suffix,
		CandidateProfile:   NewMissing("not_observed"),
		Job:                JobReference{JobID: "job-" + suffix, SourceTarget: NewMissing("not_observed"), SourceJobID: NewMissing("not_observed"), Snapshot: testArtifact("job-snap-"+suffix, "diagnostic", "restricted")},
		SelectionEvidence:  NewMissing("not_observed"),
		Task:               testArtifact("task-"+suffix, "diagnostic", "restricted"),
		TaskSemanticHash:    testDigest("task-sem-comm-" + suffix),
		InitialMaterials:   []ArtifactReference{},
		Execution:          ex,
		Owners:             testOwners(targetID, mode),
		IdempotencyKey:     "idem-" + suffix,
		AuthorizationRefs:  []EvidenceRef{testEvidenceRef(manifest.JournalID, suffix+"-auth", 1)},
		RecoveryReviewRefs: []EvidenceRef{},
		ObservationPolicy: ObservationPolicy{
			ActiveLimit: DurationLimit{Kind: "exact", Unit: "ms", Value: 60000},
			DrainLimit:  DurationLimit{Kind: "exact", Unit: "ms", Value: 10000},
			NativeCancelWaitLimit: DurationLimit{Kind: "exact", Unit: "ms", Value: 5000},
			CleanupWaitLimit:      DurationLimit{Kind: "exact", Unit: "ms", Value: 5000},
			FixtureCloseAction:    "seal_after_drain",
		},
		OriginPolicy: testVersionPin("origin-" + suffix),
	}
}

func testRegistration(suffix string, manifest Manifest, targetID string) EntityRegistration {
	dummyPolicy := func(seed string) map[string]any {
		return map[string]any{"id": "pub", "version": "1.0", "artifact_digest": testDigest(seed)}
	}
	return EntityRegistration{
		RecordType:     "write_domain_entity",
		SchemaVersion:  "0.1.0",
		RegistrationID: "registration-" + suffix,
		Entity: map[string]any{
			"entity_type": "hellscape_session",
			"entity_id":   "session-" + suffix,
			"session_id":  manifest.RunID,
		},
		Identity: map[string]any{
			"run_id":     manifest.RunID,
			"journal_id": manifest.JournalID,
			"attempt": map[string]any{
				"kind": "practice", "target_class": "laboratory_fixture",
				"evaluation_partition": "held_in",
			},
		},
		Owners: map[string]any{
			"application": map[string]any{"role": "origin", "source_id": targetID, "writer_id": "app-writer-" + suffix, "owner_domain": "application", "publication_policy": dummyPolicy("pub-app-" + suffix)},
			"observation": map[string]any{"role": "observer", "source_id": "obs-source-" + suffix, "writer_id": "obs-writer-" + suffix, "owner_domain": "observation", "publication_policy": dummyPolicy("pub-obs-" + suffix)},
			"diagnostic":  map[string]any{"role": "analyzer", "source_id": "diag-source-" + suffix, "writer_id": "diag-writer-" + suffix, "owner_domain": "diagnostic", "publication_policy": dummyPolicy("pub-diag-" + suffix)},
		},
		EvidencePrefix: JournalPrefix{},
		EvidenceRefs:   []EvidenceRef{},
		Configuration:  append([]byte(nil), application_owner.DefaultFixtureConfiguration()...),
	}
}

func isNotApplicableMissing(v any) bool {
	if m, ok := v.(MissingEnvelope); ok {
		return m.Value == nil && m.Reason == "not_applicable"
	}
	if m, ok := v.(map[string]any); ok {
		raw, has := m["value"]
		if !has || raw != nil {
			return false
		}
		r, _ := m["reason"].(string)
		return r == "not_applicable"
	}
	return false
}

// ---------------------------------------------------------------------------
// 1. Invalid admission creates no fabricated admitted session.
// ---------------------------------------------------------------------------

func TestInvalidAdmissionCreatesNoFabricatedAdmittedSession(t *testing.T) {
	ctx := authedContext(t)
	primary := openStore(t, "diagnostic")
	app := openStore(t, "application")
	obs := openStore(t, "observation")

	admitInvalid := func(suffix string, mutate func(*Manifest, *AttemptCommission, *[]EntityRegistration)) {
		t.Helper()
		m := testManifest(suffix, "")
		c := testCommission(t, suffix, m, "manual")
		regs := []EntityRegistration{testRegistration(suffix, m, c.Attempt.TargetID)}
		if mutate != nil {
			mutate(&m, &c, &regs)
		}
		ref, err := AdmitSession(ctx, primary, m, c, regs)
		if err == nil {
			t.Fatalf("suffix %s: invalid admission unexpectedly succeeded", suffix)
		}
		if ref.JournalID != "" || ref.EventID != "" || ref.EventHash != "" {
			t.Fatalf("suffix %s: invalid admission returned fabricated ref %+v", suffix, ref)
		}
		if _, ok := GetAdmittedCommission(c.Attempt.AttemptID); ok {
			t.Fatalf("suffix %s: invalid admission registered a commission", suffix)
		}
		if IsEntryUsable(primary, c.Attempt.AttemptID) {
			t.Fatalf("suffix %s: invalid admission marked entry usable", suffix)
		}
		// No journal was created: the prefix is unknown.
		_, loadErr := owner_store.LoadPrefix(ctx, primary, JournalPrefix{JournalID: m.JournalID, LastSequence: 1, HeadHash: testDigest("dummy-" + suffix)})
		if loadErr == nil {
			t.Fatalf("suffix %s: invalid admission left a durable journal", suffix)
		}
		if err := AdvanceAdmission(ctx, primary, app, obs, c.Attempt.AttemptID); !errors.Is(err, ErrNotAdmitted) {
			t.Fatalf("suffix %s: AdvanceAdmission = %v, want ErrNotAdmitted", suffix, err)
		}
	}

	admitInvalid("invalid-prod", func(m *Manifest, c *AttemptCommission, _ *[]EntityRegistration) {
		c.Attempt.Kind = "production"
		c.Attempt.TargetClass = "employer_origin"
		c.Attempt.EvaluationPartition = "held_out"
		c.ObservationPolicy.FixtureCloseAction = "not_applicable"
	})
	admitInvalid("invalid-manifest", func(m *Manifest, _ *AttemptCommission, _ *[]EntityRegistration) {
		m.ManifestID = ""
	})
	admitInvalid("invalid-commission", func(_ *Manifest, c *AttemptCommission, _ *[]EntityRegistration) {
		c.CommissionID = ""
	})
	admitInvalid("invalid-reg", func(_ *Manifest, _ *AttemptCommission, regs *[]EntityRegistration) {
		(*regs)[0].Entity["entity_type"] = "job"
	})

	// A valid admission still succeeds on the same primary store.
	m := testManifest("invalid-valid", "")
	c := testCommission(t, "invalid-valid", m, "manual")
	regs := []EntityRegistration{testRegistration("invalid-valid", m, c.Attempt.TargetID)}
	ref, err := AdmitSession(ctx, primary, m, c, regs)
	if err != nil {
		t.Fatalf("valid admission: %v", err)
	}
	if ref.Sequence != 2 {
		t.Fatalf("valid admission sequence = %d, want 2", ref.Sequence)
	}
}

// ---------------------------------------------------------------------------
// 2. Durable admission survives later owner initialization failure.
// ---------------------------------------------------------------------------

func TestDurableAdmissionSurvivesLaterOwnerInitializationFailure(t *testing.T) {
	ctx := authedContext(t)
	primary := openStore(t, "diagnostic")
	app := openStore(t, "application")
	obs := openStore(t, "observation")

	m := testManifest("durable-1", "")
	c := testCommission(t, "durable-1", m, "manual")
	regs := []EntityRegistration{testRegistration("durable-1", m, c.Attempt.TargetID)}
	admissionRef, err := AdmitSession(ctx, primary, m, c, regs)
	if err != nil {
		t.Fatalf("AdmitSession: %v", err)
	}
	admissionPrefix := JournalPrefix{JournalID: m.JournalID, LastSequence: 2, HeadHash: admissionRef.EventHash}
	if _, err := owner_store.LoadPrefix(ctx, primary, admissionPrefix); err != nil {
		t.Fatalf("admission not durable before init: %v", err)
	}

	// Fail the later owner initialization by closing the application store.
	if err := app.Close(); err != nil {
		t.Fatalf("close app: %v", err)
	}
	if err := AdvanceAdmission(ctx, primary, app, obs, c.Attempt.AttemptID); err == nil {
		t.Fatalf("AdvanceAdmission with failed owner unexpectedly succeeded")
	}
	if IsEntryUsable(primary, c.Attempt.AttemptID) {
		t.Fatalf("entry usable despite failed initialization")
	}
	// The durable admission survives: prefix still loads, commission known.
	if _, err := owner_store.LoadPrefix(ctx, primary, admissionPrefix); err != nil {
		t.Fatalf("durable admission lost after init failure: %v", err)
	}
	if _, ok := GetAdmittedCommission(c.Attempt.AttemptID); !ok {
		t.Fatalf("admitted commission lost after init failure")
	}

	// Retry with a fresh application store: the saga completes.
	app2 := openStore(t, "application")
	if err := AdvanceAdmission(ctx, primary, app2, obs, c.Attempt.AttemptID); err != nil {
		t.Fatalf("AdvanceAdmission retry: %v", err)
	}
	if !IsEntryUsable(primary, c.Attempt.AttemptID) {
		t.Fatalf("entry not usable after successful retry")
	}
	if _, err := owner_store.LoadPrefix(ctx, primary, admissionPrefix); err != nil {
		t.Fatalf("admission prefix unreadable after success: %v", err)
	}
}

// ---------------------------------------------------------------------------
// 3. Entry and preparation wait for required initialization receipts.
// ---------------------------------------------------------------------------

func TestEntryAndPreparationWaitForRequiredInitializationReceipts(t *testing.T) {
	ctx := authedContext(t)
	primary := openStore(t, "diagnostic")

	// Success path: usable only after Advance.
	app1 := openStore(t, "application")
	obs1 := openStore(t, "observation")
	m1 := testManifest("entry-1", "")
	c1 := testCommission(t, "entry-1", m1, "manual")
	regs1 := []EntityRegistration{testRegistration("entry-1", m1, c1.Attempt.TargetID)}
	ref1, err := AdmitSession(ctx, primary, m1, c1, regs1)
	if err != nil {
		t.Fatalf("AdmitSession entry-1: %v", err)
	}
	if IsEntryUsable(primary, c1.Attempt.AttemptID) {
		t.Fatalf("entry usable before required initialization")
	}
	prefix1 := JournalPrefix{JournalID: m1.JournalID, LastSequence: 2, HeadHash: ref1.EventHash}
	events, err := owner_store.LoadPrefix(ctx, primary, prefix1)
	if err != nil {
		t.Fatalf("load admission prefix: %v", err)
	}
	for _, ev := range events {
		if ev.EventKind == eventEntryUsable {
			t.Fatalf("entry_usable present before initialization")
		}
	}
	if err := AdvanceAdmission(ctx, primary, app1, obs1, c1.Attempt.AttemptID); err != nil {
		t.Fatalf("AdvanceAdmission entry-1: %v", err)
	}
	if !IsEntryUsable(primary, c1.Attempt.AttemptID) {
		t.Fatalf("entry not usable after required receipts")
	}

	// Gating path: failed init leaves the entry unusable; retry completes it.
	app2 := openStore(t, "application")
	obs2 := openStore(t, "observation")
	m2 := testManifest("entry-2", "")
	c2 := testCommission(t, "entry-2", m2, "manual")
	regs2 := []EntityRegistration{testRegistration("entry-2", m2, c2.Attempt.TargetID)}
	if _, err := AdmitSession(ctx, primary, m2, c2, regs2); err != nil {
		t.Fatalf("AdmitSession entry-2: %v", err)
	}
	if err := app2.Close(); err != nil {
		t.Fatalf("close app2: %v", err)
	}
	if err := AdvanceAdmission(ctx, primary, app2, obs2, c2.Attempt.AttemptID); err == nil {
		t.Fatalf("AdvanceAdmission with failed init unexpectedly succeeded")
	}
	if IsEntryUsable(primary, c2.Attempt.AttemptID) {
		t.Fatalf("entry usable despite missing receipts")
	}
	app2b := openStore(t, "application")
	if err := AdvanceAdmission(ctx, primary, app2b, obs2, c2.Attempt.AttemptID); err != nil {
		t.Fatalf("AdvanceAdmission retry entry-2: %v", err)
	}
	if !IsEntryUsable(primary, c2.Attempt.AttemptID) {
		t.Fatalf("entry not usable after receipts recorded")
	}
}

// ---------------------------------------------------------------------------
// 4. Manual admission requires no automation or laboratory peer.
// ---------------------------------------------------------------------------

func TestManualAdmissionRequiresNoAutomationOrLaboratoryPeer(t *testing.T) {
	ctx := authedContext(t)
	primary := openStore(t, "diagnostic")
	app := openStore(t, "application")
	obs := openStore(t, "observation")

	m := testManifest("manual-1", "")
	c := testCommission(t, "manual-1", m, "manual")
	regs := []EntityRegistration{testRegistration("manual-1", m, c.Attempt.TargetID)}
	if _, err := AdmitSession(ctx, primary, m, c, regs); err != nil {
		t.Fatalf("manual AdmitSession: %v", err)
	}
	stored, ok := GetAdmittedCommission(c.Attempt.AttemptID)
	if !ok {
		t.Fatalf("manual commission not registered")
	}
	if !isNotApplicableMissing(stored.Execution.Subject) {
		t.Fatalf("manual subject fabricated: %#v", stored.Execution.Subject)
	}
	if !isNotApplicableMissing(stored.Execution.ConnectorVersion) {
		t.Fatalf("manual connector_version fabricated: %#v", stored.Execution.ConnectorVersion)
	}
	if !isNotApplicableMissing(stored.Execution.BindingVersion) {
		t.Fatalf("manual binding_version fabricated: %#v", stored.Execution.BindingVersion)
	}
	if !isNotApplicableMissing(stored.Owners.Execution.SourceID) || !isNotApplicableMissing(stored.Owners.Execution.WriterID) {
		t.Fatalf("manual execution writer fabricated")
	}
	// No automation peer is needed to advance a manual entry.
	if err := AdvanceAdmission(ctx, primary, app, obs, c.Attempt.AttemptID); err != nil {
		t.Fatalf("manual AdvanceAdmission: %v", err)
	}
	if !IsEntryUsable(primary, c.Attempt.AttemptID) {
		t.Fatalf("manual entry not usable after init")
	}

	// Manual mode with automation fields is refused, never fabricated.
	m2 := testManifest("manual-bad-subject", "")
	c2 := testCommission(t, "manual-bad-subject", m2, "manual")
	c2.Execution.Subject = SubjectIdentity{SubjectID: "subject-A", SubjectVersion: "subject-1.0"}
	regs2 := []EntityRegistration{testRegistration("manual-bad-subject", m2, c2.Attempt.TargetID)}
	if _, err := AdmitSession(ctx, primary, m2, c2, regs2); err == nil {
		t.Fatalf("manual admission with automation subject unexpectedly succeeded")
	}

	m3 := testManifest("manual-bad-connector", "")
	c3 := testCommission(t, "manual-bad-connector", m3, "manual")
	c3.Execution.ConnectorVersion = "connector-9.9"
	regs3 := []EntityRegistration{testRegistration("manual-bad-connector", m3, c3.Attempt.TargetID)}
	if _, err := AdmitSession(ctx, primary, m3, c3, regs3); err == nil {
		t.Fatalf("manual admission with connector version unexpectedly succeeded")
	}

	m4 := testManifest("manual-bad-writer", "")
	c4 := testCommission(t, "manual-bad-writer", m4, "manual")
	c4.Owners.Execution.WriterID = "exec-writer-fabricated"
	regs4 := []EntityRegistration{testRegistration("manual-bad-writer", m4, c4.Attempt.TargetID)}
	if _, err := AdmitSession(ctx, primary, m4, c4, regs4); err == nil {
		t.Fatalf("manual admission with execution writer unexpectedly succeeded")
	}
}

// ---------------------------------------------------------------------------
// 5. Commission changes require a new immutable attempt identity.
// ---------------------------------------------------------------------------

func TestCommissionChangesRequireNewImmutableAttemptIdentity(t *testing.T) {
	ctx := authedContext(t)
	primary := openStore(t, "diagnostic")

	m := testManifest("change-base", "subject-1.0")
	c := testCommission(t, "change-base", m, "subject")
	regs := []EntityRegistration{testRegistration("change-base", m, c.Attempt.TargetID)}
	ref1, err := AdmitSession(ctx, primary, m, c, regs)
	if err != nil {
		t.Fatalf("AdmitSession base: %v", err)
	}

	// Same key and request is idempotent: same admitted session.
	refRetry, err := AdmitSession(ctx, primary, m, c, regs)
	if err != nil {
		t.Fatalf("idempotent retry: %v", err)
	}
	if refRetry.EventID != ref1.EventID || refRetry.EventHash != ref1.EventHash {
		t.Fatalf("idempotent retry returned a different session: %+v vs %+v", refRetry, ref1)
	}

	// Same key with changed content is rejected.
	cChangedKey := c
	cChangedKey.Execution.Subject = SubjectIdentity{SubjectID: "subject-A", SubjectVersion: "subject-2.0", RevisionBasis: "basis-1", ConfiguredMode: "subject", InterfaceSurface: "test-surface", ConfigurationDigest: testDigest("config-change")}
	if _, err := AdmitSession(ctx, primary, m, cChangedKey, regs); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed content under same key = %v, want ErrConflict", err)
	}

	changeRequiresNew := func(name string, mutate func(*AttemptCommission)) {
		t.Helper()
		changed := c
		changed.CommissionID = "commission-" + name
		changed.IdempotencyKey = "idem-" + name
		mutate(&changed)
		if _, err := AdmitSession(ctx, primary, m, changed, regs); !errors.Is(err, ErrNeedsNewAttempt) {
			t.Fatalf("%s = %v, want ErrNeedsNewAttempt", name, err)
		}
	}
	changeRequiresNew("change-subject", func(c *AttemptCommission) {
		c.Execution.Subject = SubjectIdentity{SubjectID: "subject-A", SubjectVersion: "subject-2.0", RevisionBasis: "basis-1", ConfiguredMode: "subject", InterfaceSurface: "test-surface", ConfigurationDigest: testDigest("config-change-subject")}
	})
	changeRequiresNew("change-target", func(c *AttemptCommission) {
		c.Attempt.TargetID = "target-other"
		c.Owners.Application.SourceID = "target-other"
	})
	changeRequiresNew("change-task", func(c *AttemptCommission) {
		c.Task = testArtifact("task-different", "diagnostic", "restricted")
	})
	changeRequiresNew("change-perms", func(c *AttemptCommission) {
		c.Owners.Dispatch.WriterID = "dispatch-writer-other"
	})

	// The original commission is unchanged.
	stored, ok := GetAdmittedCommission(c.Attempt.AttemptID)
	if !ok {
		t.Fatalf("base commission lost")
	}
	subj, ok := stored.Execution.Subject.(SubjectIdentity)
	if !ok || subj.SubjectVersion != "subject-1.0" {
		t.Fatalf("base commission mutated: %#v", stored.Execution.Subject)
	}
}

// ---------------------------------------------------------------------------
// 6. Practice lineage cannot promote commitment to production.
// ---------------------------------------------------------------------------

func TestPracticeLineageCannotPromoteCommitmentToProduction(t *testing.T) {
	ctx := authedContext(t)
	primary := openStore(t, "diagnostic")

	baseManifest := testManifest("lineage-base", "")
	baseCommission := testCommission(t, "lineage-base", baseManifest, "manual")
	baseRegs := []EntityRegistration{testRegistration("lineage-base", baseManifest, baseCommission.Attempt.TargetID)}
	if _, err := AdmitSession(ctx, primary, baseManifest, baseCommission, baseRegs); err != nil {
		t.Fatalf("admit base: %v", err)
	}

	// A practice child deriving from practice succeeds as lineage only.
	childManifest := testManifest("lineage-child", "")
	childCommission := testCommission(t, "lineage-child", childManifest, "manual")
	childCommission.Attempt.DerivedFrom = []AttemptReference{{AttemptID: baseCommission.Attempt.AttemptID, Kind: "practice"}}
	childRegs := []EntityRegistration{testRegistration("lineage-child", childManifest, childCommission.Attempt.TargetID)}
	childRef, err := AdmitSession(ctx, primary, childManifest, childCommission, childRegs)
	if err != nil {
		t.Fatalf("admit derived child: %v", err)
	}
	// No commitment is promoted: the admitted event carries lineage with an
	// explicit no-promotion note and no commitment predicate.
	childPrefix := JournalPrefix{JournalID: childManifest.JournalID, LastSequence: 2, HeadHash: childRef.EventHash}
	events, err := owner_store.LoadPrefix(ctx, primary, childPrefix)
	if err != nil {
		t.Fatalf("load child prefix: %v", err)
	}
	admitted := events[1]
	rawData, _ := json.Marshal(admitted.Payload.Data)
	var data map[string]any
	if err := json.Unmarshal(rawData, &data); err != nil {
		t.Fatalf("decode child data: %v", err)
	}
	if _, hasCommitment := data["commitment"]; hasCommitment {
		t.Fatalf("lineage promoted a commitment predicate: %v", data)
	}
	note, _ := data["lineage_note"].(string)
	if !strings.Contains(note, "no inherited commitment") {
		t.Fatalf("lineage note missing no-promotion disclosure: %v", data)
	}
	// No reciprocal mutation of the earlier commission.
	baseStored, _ := GetAdmittedCommission(baseCommission.Attempt.AttemptID)
	if len(baseStored.Attempt.DerivedFrom) != 0 {
		t.Fatalf("earlier commission mutated by later lineage")
	}

	// Rehearsal to production is lineage only and creates no production session.
	rehearsalManifest := testManifest("lineage-rehearsal", "")
	rehearsalCommission := testCommission(t, "lineage-rehearsal", rehearsalManifest, "manual")
	rehearsalCommission.Attempt.RehearsalOf = []AttemptReference{{AttemptID: "attempt-prod-1", Kind: "production"}}
	rehearsalRegs := []EntityRegistration{testRegistration("lineage-rehearsal", rehearsalManifest, rehearsalCommission.Attempt.TargetID)}
	if _, err := AdmitSession(ctx, primary, rehearsalManifest, rehearsalCommission, rehearsalRegs); err != nil {
		t.Fatalf("admit rehearsal child: %v", err)
	}
	if _, ok := GetAdmittedCommission("attempt-prod-1"); ok {
		t.Fatalf("rehearsal link fabricated a production commission")
	}

	// Lineage violations are refused.
	violation := func(suffix string, mutate func(*AttemptCommission)) {
		t.Helper()
		mv := testManifest(suffix, "")
		cv := testCommission(t, suffix, mv, "manual")
		mutate(&cv)
		regs := []EntityRegistration{testRegistration(suffix, mv, cv.Attempt.TargetID)}
		if _, err := AdmitSession(ctx, primary, mv, cv, regs); err == nil {
			t.Fatalf("%s unexpectedly admitted", suffix)
		}
		if _, ok := GetAdmittedCommission(cv.Attempt.AttemptID); ok {
			t.Fatalf("%s registered despite lineage violation", suffix)
		}
	}
	violation("lineage-bad-kind", func(c *AttemptCommission) {
		c.Attempt.DerivedFrom = []AttemptReference{{AttemptID: baseCommission.Attempt.AttemptID, Kind: "production"}}
	})
	violation("lineage-bad-unknown", func(c *AttemptCommission) {
		c.Attempt.DerivedFrom = []AttemptReference{{AttemptID: "attempt-unknown", Kind: "practice"}}
	})
	violation("lineage-bad-self", func(c *AttemptCommission) {
		c.Attempt.DerivedFrom = []AttemptReference{{AttemptID: c.Attempt.AttemptID, Kind: "practice"}}
	})
	violation("lineage-bad-perf", func(c *AttemptCommission) {
		c.Attempt.PerformanceOf = []AttemptReference{{AttemptID: baseCommission.Attempt.AttemptID, Kind: "practice"}}
	})
	violation("lineage-bad-rehearsal", func(c *AttemptCommission) {
		c.Attempt.RehearsalOf = []AttemptReference{{AttemptID: baseCommission.Attempt.AttemptID, Kind: "practice"}}
	})

	// Production is never admitted through the laboratory fixture path.
	prodManifest := testManifest("lineage-prod", "")
	prodCommission := testCommission(t, "lineage-prod", prodManifest, "manual")
	prodCommission.Attempt.Kind = "production"
	prodCommission.Attempt.TargetClass = "employer_origin"
	prodCommission.Attempt.EvaluationPartition = "held_out"
	prodCommission.ObservationPolicy.FixtureCloseAction = "not_applicable"
	prodRegs := []EntityRegistration{testRegistration("lineage-prod", prodManifest, prodCommission.Attempt.TargetID)}
	if _, err := AdmitSession(ctx, primary, prodManifest, prodCommission, prodRegs); err == nil {
		t.Fatalf("production admission unexpectedly succeeded")
	}
}

// ---------------------------------------------------------------------------
// 7. Admission saga never uses a cross-owner atomic commit.
// ---------------------------------------------------------------------------

func TestAdmissionSagaNeverUsesCrossOwnerAtomicCommit(t *testing.T) {
	ctx := authedContext(t)
	primary := openStore(t, "diagnostic")
	app := openStore(t, "application")
	obs := openStore(t, "observation")

	m := testManifest("atomic-1", "")
	c := testCommission(t, "atomic-1", m, "manual")
	regs := []EntityRegistration{testRegistration("atomic-1", m, c.Attempt.TargetID)}
	admissionRef, err := AdmitSession(ctx, primary, m, c, regs)
	if err != nil {
		t.Fatalf("AdmitSession: %v", err)
	}
	admissionPrefix := JournalPrefix{JournalID: m.JournalID, LastSequence: 2, HeadHash: admissionRef.EventHash}

	// Fail only the observation leg: the application commit must remain.
	if err := obs.Close(); err != nil {
		t.Fatalf("close obs: %v", err)
	}
	advanceErr := AdvanceAdmission(ctx, primary, app, obs, c.Attempt.AttemptID)
	if advanceErr == nil {
		t.Fatalf("AdvanceAdmission with failed peer unexpectedly succeeded")
	}
	if !strings.Contains(advanceErr.Error(), "observation initialization") {
		t.Fatalf("AdvanceAdmission error = %v, want observation initialization failure", advanceErr)
	}
	// Primary admission is untouched and still not usable.
	if _, err := owner_store.LoadPrefix(ctx, primary, admissionPrefix); err != nil {
		t.Fatalf("primary admission rolled back: %v", err)
	}
	if IsEntryUsable(primary, c.Attempt.AttemptID) {
		t.Fatalf("entry usable despite failed peer leg")
	}
	// The application leg was not rolled back: retrying with the same
	// application store reports the existing initialization.
	obs2 := openStore(t, "observation")
	retryErr := AdvanceAdmission(ctx, primary, app, obs2, c.Attempt.AttemptID)
	if retryErr == nil || !strings.Contains(retryErr.Error(), "already initialized") {
		t.Fatalf("retry = %v, want already-initialized application leg (no cross-owner rollback)", retryErr)
	}

	// Admission itself needs no peer: a second session admits while the
	// observation peer stays closed.
	m2 := testManifest("atomic-2", "")
	c2 := testCommission(t, "atomic-2", m2, "manual")
	regs2 := []EntityRegistration{testRegistration("atomic-2", m2, c2.Attempt.TargetID)}
	if _, err := AdmitSession(ctx, primary, m2, c2, regs2); err != nil {
		t.Fatalf("AdmitSession with closed peer: %v", err)
	}
	// And the primary stays writable for a fresh peer set.
	app3 := openStore(t, "application")
	obs3 := openStore(t, "observation")
	if err := AdvanceAdmission(ctx, primary, app3, obs3, c2.Attempt.AttemptID); err != nil {
		t.Fatalf("AdvanceAdmission atomic-2: %v", err)
	}
	if !IsEntryUsable(primary, c2.Attempt.AttemptID) {
		t.Fatalf("atomic-2 entry not usable")
	}
}

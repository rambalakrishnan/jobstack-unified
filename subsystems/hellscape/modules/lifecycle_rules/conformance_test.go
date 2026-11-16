package lifecycle_rules

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"evidence_codec"
)

// ---------------------------------------------------------------------------
// Test helpers.
// ---------------------------------------------------------------------------

func testDigest(ch byte) string {
	return string(evidence_codec.HashBytes([]byte("test-digest-" + string([]byte{ch}))))
}

func testArtifact(owner string, ch byte) ArtifactReference {
	return ArtifactReference{
		Digest: testDigest(ch), SizeBytes: 128,
		MediaType: "application/json", OwnerDomain: owner, Access: "restricted",
	}
}

func testPin(id, version string, ch byte) VersionPin {
	return VersionPin{ID: id, Version: version, ArtifactDigest: testDigest(ch)}
}

func testTP(offset float64) TimePoint {
	return TimePoint{
		ClockID: "clk-1", BootID: "boot-1", Origin: "engine_measured",
		MonotonicOffsetMs: offset, UTCAnnotation: NewMissing("not_applicable"),
	}
}

func testTPOn(clock, boot, origin string, offset float64) TimePoint {
	return TimePoint{
		ClockID: clock, BootID: boot, Origin: origin,
		MonotonicOffsetMs: offset, UTCAnnotation: NewMissing("not_applicable"),
	}
}

func testCommission(mode string) AttemptCommission {
	target := "origin-lab-1"
	execBinding := AuthorityBinding{
		Role: "subject", SourceID: "subject-1", WriterID: "exec-writer",
		OwnerDomain: "exec-domain", PublicationPolicy: testPin("pub", "v1", 'p'),
	}
	execDesc := ExecutionDescriptor{
		Mode: "subject",
		Subject: SubjectIdentity{
			SubjectID: "subject-1", SubjectVersion: "v1", RevisionBasis: "native_revision",
			NativeRevision: "r1", ConfiguredMode: "auto", InterfaceSurface: "web",
			ConfigurationDigest: testDigest('k'), Stack: []ComponentIdentity{},
		},
		ConnectorVersion: "conn-v1", BindingVersion: "bind-v1",
		Assistance: AssistanceRecord{
			PlanningOwner: "subject", AssistanceTrack: "track-1",
			PlannerIdentity: "planner-1", Plan: NewMissing("not_observed"),
			OnlineReplanning: false, Description: "subject plans",
		},
	}
	if mode == "manual" {
		execBinding.SourceID = NewMissing("not_applicable")
		execBinding.WriterID = NewMissing("not_applicable")
		execDesc = ExecutionDescriptor{
			Mode: "manual",
			Subject: NewMissing("not_applicable"),
			ConnectorVersion: NewMissing("not_applicable"),
			BindingVersion:   NewMissing("not_applicable"),
			Assistance: AssistanceRecord{
				PlanningOwner: "none", AssistanceTrack: "manual-track",
				PlannerIdentity: NewMissing("not_applicable"), Plan: NewMissing("not_observed"),
				OnlineReplanning: false, Description: "manual walkthrough",
			},
		}
	}
	return AttemptCommission{
		RecordType: "attempt_commission", SchemaVersion: SchemaLifecycle, KernelVersion: SchemaKernel,
		CommissionID: "commission-1", RunID: "run-1", JournalID: "journal-1",
		ManifestHash: testDigest('m'),
		AdmissionRef: EvidenceRef{JournalID: "journal-1", Sequence: 1, EventID: "evt-admission", EventHash: testDigest('a'), Pointer: ""},
		CommissionedBy: "operator-1", CommissionedAt: testTP(10),
		Attempt: AttemptContext{
			AttemptID: "attempt-1", Kind: "practice", TargetClass: "laboratory_fixture",
			TargetID: target, EvaluationPartition: "held_in",
			RehearsalOf: []AttemptReference{}, PerformanceOf: []AttemptReference{}, DerivedFrom: []AttemptReference{},
		},
		CandidateID: "candidate-1", CandidateProfile: NewMissing("not_observed"),
		Job: JobReference{
			JobID: "job-1", SourceTarget: NewMissing("not_observed"),
			SourceJobID: NewMissing("not_observed"), Snapshot: testArtifact("origin-domain", 'j'),
		},
		SelectionEvidence: NewMissing("not_observed"),
		Task:              testArtifact("origin-domain", 't'),
		TaskSemanticHash:  testDigest('s'),
		InitialMaterials:  []ArtifactReference{},
		Execution:         execDesc,
		Owners: OwnerBindings{
			Dispatch:    AuthorityBinding{Role: "connector", SourceID: "connector-1", WriterID: "dispatch-writer", OwnerDomain: "dispatch-domain", PublicationPolicy: testPin("pub", "v1", 'p')},
			Observation: AuthorityBinding{Role: "connector", SourceID: "connector-1", WriterID: "obs-writer", OwnerDomain: "obs-domain", PublicationPolicy: testPin("pub", "v1", 'p')},
			Execution:   execBinding,
			Application: AuthorityBinding{Role: "origin", SourceID: target, WriterID: "app-writer", OwnerDomain: "origin-domain", PublicationPolicy: testPin("pub", "v1", 'p')},
			Report:      AuthorityBinding{Role: "reconciler", SourceID: "reconciler-1", WriterID: "report-writer", OwnerDomain: "report-domain", PublicationPolicy: testPin("pub", "v1", 'p')},
		},
		IdempotencyKey:    "idem-1",
		AuthorizationRefs: []EvidenceRef{{JournalID: "journal-1", Sequence: 1, EventID: "evt-admission", EventHash: testDigest('a'), Pointer: ""}},
		RecoveryReviewRefs: []EvidenceRef{},
		ObservationPolicy: ObservationPolicy{
			ActiveLimit: DurationLimit{Kind: "exact", Unit: "ms", Value: 60000},
			DrainLimit:  DurationLimit{Kind: "exact", Unit: "ms", Value: 10000},
			NativeCancelWaitLimit: DurationLimit{Kind: "exact", Unit: "ms", Value: 5000},
			CleanupWaitLimit:      DurationLimit{Kind: "exact", Unit: "ms", Value: 5000},
			FixtureCloseAction:    "seal_after_drain",
		},
		OriginPolicy: testPin("origin-policy", "v1", 'o'),
	}
}

func verifiedChecks(ref EvidenceRef) SourceChecks {
	return SourceChecks{
		Authentication: "verified", Correlation: "matched", TraceCorrelation: "matched",
		VerificationPolicy: testPin("verify-policy", "v1", 'v'),
		MatchedBy:          []string{"trace-id"},
		EvidenceRefs:       []EvidenceRef{ref},
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

func finalizeTestEnv(ev *JournalEnvelope) {
	if ev.CausalRefs == nil {
		ev.CausalRefs = []EvidenceRef{}
	}
	if ev.Payload.Data == nil {
		ev.Payload.Data = map[string]any{}
	}
	if ev.Payload.Measurements == nil {
		ev.Payload.Measurements = []Measurement{}
	}
	if ev.Payload.EvidenceRefs == nil {
		ev.Payload.EvidenceRefs = []EvidenceRef{}
	}
	if ev.Payload.ArtifactRefs == nil {
		ev.Payload.ArtifactRefs = []ArtifactReference{}
	}
	ev.EventHash = computeTestHash(*ev)
}

func baseTestEnv(seq int64, eventID, kind string, prev any) JournalEnvelope {
	role := "lifecycle_observation"
	producer := "recorder-1"
	if kind == "manifest_admitted" {
		role = "external_input"
		producer = "kernel"
	}
	return JournalEnvelope{
		RecordType: "journal_event", SchemaVersion: "0.1.0",
		RunID: "run-1", JournalID: "journal-1", ManifestHash: testDigest('m'),
		Sequence: seq, EventID: eventID, EventKind: kind, EventSchemaVersion: "v1",
		Role: role, AssertionKind: "observation", OwnerDomain: "origin-domain",
		ProducerID: producer, ProducerSequence: seq,
		Provenance: "server", EvidenceScope: "current_run",
		RecordedAt: testTP(float64(1000 + seq*10)), OccurredAt: NewMissing("not_observed"),
		CausalRefs: []EvidenceRef{},
		Payload: struct {
			Data         map[string]any     `json:"data"`
			Measurements []Measurement      `json:"measurements"`
			EvidenceRefs []EvidenceRef      `json:"evidence_refs"`
			ArtifactRefs []ArtifactReference `json:"artifact_refs"`
		}{
			Data: map[string]any{}, Measurements: []Measurement{},
			EvidenceRefs: []EvidenceRef{}, ArtifactRefs: []ArtifactReference{},
		},
		PreviousEventHash: prev, EventHash: "",
	}
}

// newChain builds n contiguous events: admission, clock registration, then
// generic observations. All hashes are recomputed so ResolveEvidence passes.
func newChain(t *testing.T, n int) ([]JournalEnvelope, JournalPrefix) {
	t.Helper()
	if n < 3 {
		t.Fatalf("need at least 3 events")
	}
	events := make([]JournalEnvelope, 0, n)
	ev1 := baseTestEnv(1, "evt-admission", "manifest_admitted", NewMissing("not_applicable"))
	ev1.Payload.Data = map[string]any{"note": "admission"}
	finalizeTestEnv(&ev1)
	events = append(events, ev1)

	ev2 := baseTestEnv(2, "evt-clock", "clock_registered", events[0].EventHash)
	ev2.Payload.Data = map[string]any{
		"clock_id": "clk-1", "boot_id": "boot-1", "origin": "engine_measured",
		"source_id": "engine", "basis": "monotonic_offset", "unit": "ms",
	}
	finalizeTestEnv(&ev2)
	events = append(events, ev2)

	for i := 3; i <= n; i++ {
		ev := baseTestEnv(int64(i), "evt-"+string(rune('a'+i)), "observation_noted", events[len(events)-1].EventHash)
		ev.Payload.Data = map[string]any{"note": "event", "index": int64(i)}
		finalizeTestEnv(&ev)
		events = append(events, ev)
	}
	prefix := JournalPrefix{JournalID: "journal-1", LastSequence: int64(n), HeadHash: events[n-1].EventHash}
	return events, prefix
}

func refFor(ev JournalEnvelope, pointer string) EvidenceRef {
	return EvidenceRef{
		JournalID: ev.JournalID, Sequence: ev.Sequence,
		EventID: ev.EventID, EventHash: ev.EventHash, Pointer: pointer,
	}
}

func axisRev(attempt AttemptReference, digest, axis, owner, writer string, rev, prev int64, prefix JournalPrefix, refs []EvidenceRef, value any) AxisRevision {
	return AxisRevision{
		RecordType: RecordAxis, SchemaVersion: SchemaLifecycle,
		Attempt: attempt, CommissionDigest: digest,
		Axis: axis, OwnerDomain: owner, WriterID: writer,
		Revision: rev, PreviousRevision: prev,
		EvidencePrefix: prefix, EvidenceRefs: refs, Value: value,
	}
}

func pinFor(t *testing.T, pub AxisRevision) DomainPin {
	t.Helper()
	d, err := publicationDigest(pub)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	return DomainPin{Revision: pub.Revision, RecordDigest: d}
}

func pinZero(reason string) DomainPin {
	return DomainPin{Revision: 0, RecordDigest: NewMissing(reason)}
}

func testAttempt() AttemptReference {
	return AttemptReference{AttemptID: "attempt-1", Kind: "practice"}
}

// ---------------------------------------------------------------------------
// 1. Local Start acknowledgement is not native acceptance.
// ---------------------------------------------------------------------------

func TestLocalStartAcceptanceDoesNotEstablishNativeAcceptance(t *testing.T) {
	commission := testCommission("subject")
	evidence, prefix := newChain(t, 4)
	intentRef := refFor(evidence[2], "")
	ackRef := refFor(evidence[3], "")
	attempt := testAttempt()
	digest := testDigest('c')

	prepared := DispatchValue{
		State: DispatchPrepared, LocalHandle: NewMissing("not_observed"),
		NativeRunID: NewMissing("not_observed"), RequestDigest: testDigest('r'),
		DeliveryRefs: []EvidenceRef{}, AcceptanceRefs: []EvidenceRef{},
		RecoveryAuthorizationRefs: []EvidenceRef{}, Reason: NewMissing("not_observed"),
	}
	rev0 := axisRev(attempt, digest, AxisDispatch, "dispatch-domain", "dispatch-writer", 1, 0, prefix, []EvidenceRef{intentRef}, prepared)
	if err := ValidateAxisTransition(commission, nil, rev0, evidence); err != nil {
		t.Fatalf("prepared must pass: %v", err)
	}
	dispatching := DispatchValue{
		State: DispatchDispatching, LocalHandle: "handle-1",
		NativeRunID: NewMissing("not_observed"), RequestDigest: testDigest('r'),
		DeliveryRefs: []EvidenceRef{intentRef}, AcceptanceRefs: []EvidenceRef{},
		RecoveryAuthorizationRefs: []EvidenceRef{}, Reason: NewMissing("not_observed"),
	}
	rev1 := axisRev(attempt, digest, AxisDispatch, "dispatch-domain", "dispatch-writer", 2, 1, prefix, []EvidenceRef{intentRef}, dispatching)
	if err := ValidateAxisTransition(commission, []AxisRevision{rev0}, rev1, evidence); err != nil {
		t.Fatalf("dispatching with local handle and intent must pass: %v", err)
	}

	// Accepted with only local evidence must fail: no native run, no acceptance refs.
	acceptedBad := DispatchValue{
		State: DispatchAccepted, LocalHandle: "handle-1",
		NativeRunID: NewMissing("not_observed"), RequestDigest: testDigest('r'),
		DeliveryRefs: []EvidenceRef{intentRef}, AcceptanceRefs: []EvidenceRef{},
		RecoveryAuthorizationRefs: []EvidenceRef{}, Reason: NewMissing("not_observed"),
	}
	revBad := axisRev(attempt, digest, AxisDispatch, "dispatch-domain", "dispatch-writer", 3, 2, prefix, []EvidenceRef{intentRef}, acceptedBad)
	if err := ValidateAxisTransition(commission, []AxisRevision{rev0, rev1}, revBad, evidence); err == nil {
		t.Fatalf("accepted without native run ID and acceptance evidence must be rejected")
	} else if !strings.Contains(strings.ToLower(err.Error()), "acceptance") && !strings.Contains(strings.ToLower(err.Error()), "native") {
		t.Fatalf("expected native-acceptance error, got: %v", err)
	}

	// Accepted with correlated native evidence passes.
	acceptedGood := DispatchValue{
		State: DispatchAccepted, LocalHandle: "handle-1",
		NativeRunID: "native-1", RequestDigest: testDigest('r'),
		DeliveryRefs: []EvidenceRef{intentRef}, AcceptanceRefs: []EvidenceRef{ackRef},
		RecoveryAuthorizationRefs: []EvidenceRef{}, Reason: NewMissing("not_observed"),
	}
	rev2 := axisRev(attempt, digest, AxisDispatch, "dispatch-domain", "dispatch-writer", 3, 2, prefix, []EvidenceRef{ackRef}, acceptedGood)
	if err := ValidateAxisTransition(commission, []AxisRevision{rev0, rev1}, rev2, evidence); err != nil {
		t.Fatalf("accepted with correlated native evidence must pass: %v", err)
	}
}

// ---------------------------------------------------------------------------
// 2. Close-time unknown stays compatible with later commitment.
// ---------------------------------------------------------------------------

func closedUnknownObservation(t *testing.T, boundary EvidenceRef) ObservationValue {
	t.Helper()
	return ObservationValue{
		State: ObsClosed, WindowID: "win-1",
		OpenedAt: testTP(100), ActiveDeadline: testTP(200),
		DrainStartedAt: NewMissing("not_applicable"), DrainDeadline: NewMissing("not_applicable"),
		ClosedAt: testTP(300), CloseReason: "local_deadline",
		AtClose: CloseSnapshot{
			ClosureID: "close-1", BoundaryRef: boundary,
			KnownVersions: CloseInputPins{
				Dispatch: pinZero("not_observed"), Execution: pinZero("not_observed"),
				Application: pinZero("not_observed"), Report: pinZero("not_observed"),
			},
			ExecutionKnowledge: "unknown", ExecutionEvidenceRefs: []EvidenceRef{},
			ApplicationKnowledge: "unknown", ApplicationEvidenceRefs: []EvidenceRef{},
			Limitations: []string{"close-time knowledge only; later evidence may arrive"},
		},
		ControlObservations: []ControlObservation{},
		LateEvidenceRefs:    []EvidenceRef{},
		Measurements:        []MeasurementEvidence{},
	}
}

func stoppedClaim(support EvidenceRef) ExecutionClaim {
	return ExecutionClaim{
		ClaimID: "claim-1", Scope: "execution_lifecycle", State: ExecStopped,
		ApplicationAssertions: []CommitmentAssertion{},
		NativeRunID:           "native-1", NativeMessageID: "msg-1",
		NativeReport: testArtifact("exec-domain", 'n'), Mapping: testPin("map", "v1", 'g'),
		SourceChecks: verifiedChecks(support),
		MadeAt: testTP(150), ReceivedAt: testTP(160),
		EvidenceAvailableToClaimant: []EvidenceRef{},
		EvidenceRefs:                []EvidenceRef{support},
		Limitations:                 []string{},
	}
}

func committedFact(candidate, job string, boundary, support EvidenceRef) OriginFact {
	return OriginFact{
		FactID: "fact-1", OriginID: "origin-lab-1", CandidateID: candidate, JobID: job,
		State: "committed", Coverage: "at_boundary", BoundaryRef: boundary,
		OriginApplicationID: "app-1", OriginRevision: "rev-1",
		Receipt: testArtifact("origin-domain", 'e'), VerificationKind: "local_origin_transaction",
		SourceChecks: verifiedChecks(support), AuthoritySealRef: NewMissing("not_applicable"),
		OccurredAt: testTP(250), ReceivedAt: testTP(260),
		EvidenceRefs: []EvidenceRef{support},
	}
}

func TestCloseTimeUnknownRemainsCompatibleWithLaterCommitment(t *testing.T) {
	commission := testCommission("subject")
	evidence, prefix := newChain(t, 5)
	closeRef := refFor(evidence[4], "")
	support := refFor(evidence[2], "")
	attempt := testAttempt()
	digest := testDigest('c')

	obsVal := closedUnknownObservation(t, closeRef)
	obsRev := axisRev(attempt, digest, AxisObservation, "obs-domain", "obs-writer", 1, 0, prefix, []EvidenceRef{closeRef}, obsVal)
	if err := ValidateAxisTransition(commission, nil, obsRev, evidence); err != nil {
		t.Fatalf("closed observation with unknown knowledge must pass: %v", err)
	}

	claimUnknown := ExecutionClaim{
		ClaimID: "claim-1", Scope: "execution_lifecycle", State: ExecCompleted,
		ApplicationAssertions: []CommitmentAssertion{
			{AssertionID: "a-1", Value: "committed", Span: "entire_attempt",
				BoundaryRef: NewMissing("not_applicable"), EvidenceRefs: []EvidenceRef{support}},
		},
		NativeRunID: "native-1", NativeMessageID: "msg-1",
		NativeReport: testArtifact("exec-domain", 'n'), Mapping: testPin("map", "v1", 'g'),
		SourceChecks: verifiedChecks(support),
		MadeAt: testTP(150), ReceivedAt: testTP(160),
		EvidenceAvailableToClaimant: []EvidenceRef{},
		EvidenceRefs:                []EvidenceRef{support},
		Limitations:                 []string{},
	}
	execVal := ExecutionValue{Claims: []ExecutionClaim{claimUnknown}}
	execRev := axisRev(attempt, digest, AxisExecution, "exec-domain", "exec-writer", 1, 0, prefix, []EvidenceRef{support}, execVal)
	if err := ValidateAxisTransition(commission, nil, execRev, evidence); err != nil {
		t.Fatalf("execution claim must pass: %v", err)
	}

	// First reconcile with no origin facts: incomplete, never contradicted.
	inputs0 := ReportInputPins{
		Dispatch: pinZero("not_observed"), Observation: pinFor(t, obsRev),
		Execution: pinFor(t, execRev), Application: pinZero("not_observed"),
	}
	report0, err := ReconcileAttempt(commission, inputs0, []AxisRevision{obsRev, execRev}, evidence, testPin("eval", "v1", 'e'))
	if err != nil {
		t.Fatalf("reconcile without facts must succeed: %v", err)
	}
	if s, _ := report0.State.(string); s == "contradicted" {
		t.Fatalf("unknown without facts must not contradict")
	}
	if report0.Coverage == "complete" {
		t.Fatalf("unresolved comparisons stay incomplete, got complete")
	}

	// Later commitment arrives: still compatible, now decidable.
	appVal := ApplicationValue{Facts: []OriginFact{committedFact("candidate-1", "job-1", closeRef, support)}}
	appRev := axisRev(attempt, digest, AxisApplication, "origin-domain", "app-writer", 1, 0, prefix, []EvidenceRef{support}, appVal)
	if err := ValidateAxisTransition(commission, nil, appRev, evidence); err != nil {
		t.Fatalf("committed fact must pass: %v", err)
	}
	inputs1 := ReportInputPins{
		Dispatch: pinZero("not_observed"), Observation: pinFor(t, obsRev),
		Execution: pinFor(t, execRev), Application: pinFor(t, appRev),
	}
	report1, err := ReconcileAttempt(commission, inputs1, []AxisRevision{obsRev, execRev, appRev}, evidence, testPin("eval", "v1", 'e'))
	if err != nil {
		t.Fatalf("reconcile with later commitment must succeed: %v", err)
	}
	if s, _ := report1.State.(string); s == "contradicted" {
		t.Fatalf("close-time unknown must stay compatible with a later verified commitment")
	}
}

// ---------------------------------------------------------------------------
// 3. Entire-attempt no-commit is contradicted by a verified commitment.
// ---------------------------------------------------------------------------

func TestEntireAttemptNoCommitIsContradictedByVerifiedCommitment(t *testing.T) {
	commission := testCommission("subject")
	evidence, prefix := newChain(t, 4)
	support := refFor(evidence[2], "")
	boundary := refFor(evidence[3], "")
	attempt := testAttempt()
	digest := testDigest('c')

	claim := ExecutionClaim{
		ClaimID: "claim-1", Scope: "execution_lifecycle", State: ExecCompleted,
		ApplicationAssertions: []CommitmentAssertion{
			{AssertionID: "a-1", Value: "not_committed", Span: "entire_attempt",
				BoundaryRef: NewMissing("not_applicable"), EvidenceRefs: []EvidenceRef{support}},
		},
		NativeRunID: "native-1", NativeMessageID: "msg-1",
		NativeReport: testArtifact("exec-domain", 'n'), Mapping: testPin("map", "v1", 'g'),
		SourceChecks: verifiedChecks(support),
		MadeAt: testTP(150), ReceivedAt: testTP(160),
		EvidenceAvailableToClaimant: []EvidenceRef{},
		EvidenceRefs:                []EvidenceRef{support},
		Limitations:                 []string{},
	}
	execRev := axisRev(attempt, digest, AxisExecution, "exec-domain", "exec-writer", 1, 0, prefix, []EvidenceRef{support}, ExecutionValue{Claims: []ExecutionClaim{claim}})
	if err := ValidateAxisTransition(commission, nil, execRev, evidence); err != nil {
		t.Fatalf("execution claim must pass: %v", err)
	}
	fact := OriginFact{
		FactID: "fact-1", OriginID: "origin-lab-1", CandidateID: "candidate-1", JobID: "job-1",
		State: "committed", Coverage: "at_boundary", BoundaryRef: boundary,
		OriginApplicationID: "app-1", OriginRevision: "rev-1",
		Receipt: testArtifact("origin-domain", 'e'), VerificationKind: "local_origin_transaction",
		SourceChecks: verifiedChecks(support), AuthoritySealRef: NewMissing("not_applicable"),
		OccurredAt: testTP(250), ReceivedAt: testTP(260),
		EvidenceRefs: []EvidenceRef{support},
	}
	appRev := axisRev(attempt, digest, AxisApplication, "origin-domain", "app-writer", 1, 0, prefix, []EvidenceRef{support}, ApplicationValue{Facts: []OriginFact{fact}})
	if err := ValidateAxisTransition(commission, nil, appRev, evidence); err != nil {
		t.Fatalf("application fact must pass: %v", err)
	}
	inputs := ReportInputPins{
		Dispatch: pinZero("not_observed"), Observation: pinZero("not_observed"),
		Execution: pinFor(t, execRev), Application: pinFor(t, appRev),
	}
	report, err := ReconcileAttempt(commission, inputs, []AxisRevision{execRev, appRev}, evidence, testPin("eval", "v1", 'e'))
	if err != nil {
		t.Fatalf("reconcile must succeed: %v", err)
	}
	if s, _ := report.State.(string); s != "contradicted" {
		t.Fatalf("entire-attempt no-commit must be contradicted by a verified commitment, got state %v", report.State)
	}
	found := false
	for _, cc := range report.Comparisons {
		if cc.Result == "contradicted" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a contradicted comparison")
	}
}

// ---------------------------------------------------------------------------
// 4. A stopped claim alone asserts no no-commitment proposition.
// ---------------------------------------------------------------------------

func TestStoppedClaimAloneDoesNotAssertNoCommitment(t *testing.T) {
	commission := testCommission("subject")
	evidence, prefix := newChain(t, 4)
	support := refFor(evidence[2], "")
	boundary := refFor(evidence[3], "")
	attempt := testAttempt()
	digest := testDigest('c')

	execRev := axisRev(attempt, digest, AxisExecution, "exec-domain", "exec-writer", 1, 0, prefix,
		[]EvidenceRef{support}, ExecutionValue{Claims: []ExecutionClaim{stoppedClaim(support)}})
	if err := ValidateAxisTransition(commission, nil, execRev, evidence); err != nil {
		t.Fatalf("stopped claim without assertions must validate: %v", err)
	}
	appRev := axisRev(attempt, digest, AxisApplication, "origin-domain", "app-writer", 1, 0, prefix,
		[]EvidenceRef{support}, ApplicationValue{Facts: []OriginFact{committedFact("candidate-1", "job-1", boundary, support)}})
	if err := ValidateAxisTransition(commission, nil, appRev, evidence); err != nil {
		t.Fatalf("committed fact must validate: %v", err)
	}
	inputs := ReportInputPins{
		Dispatch: pinZero("not_observed"), Observation: pinZero("not_observed"),
		Execution: pinFor(t, execRev), Application: pinFor(t, appRev),
	}
	report, err := ReconcileAttempt(commission, inputs, []AxisRevision{execRev, appRev}, evidence, testPin("eval", "v1", 'e'))
	if err != nil {
		t.Fatalf("reconcile must succeed: %v", err)
	}
	if s, _ := report.State.(string); s == "contradicted" {
		t.Fatalf("stopped alone must not contradict a verified commitment")
	}
	if len(report.Comparisons) != 1 {
		t.Fatalf("expected one comparison for the stopped claim, got %d", len(report.Comparisons))
	}
	cc := report.Comparisons[0]
	if cc.Result == "contradicted" || cc.Result == "consistent" {
		t.Fatalf("stopped claim without assertions is not comparable on commitment, got %q", cc.Result)
	}
	if _, ok := cc.AssertionID.(Missing); !ok {
		// After reconciliation the assertion ID is a Missing struct; also
		// accept its map form for robustness.
		if !isMissing(cc.AssertionID) {
			t.Fatalf("narrow stopped claim carries assertion_id Missing(not_applicable)")
		}
	}
}

// ---------------------------------------------------------------------------
// 5. Conflicting native claims stay cumulative and immutable.
// ---------------------------------------------------------------------------

func lifecycleClaim(id, state, assertionValue string, support EvidenceRef) ExecutionClaim {
	assertions := []CommitmentAssertion{}
	if assertionValue != "" {
		assertions = append(assertions, CommitmentAssertion{
			AssertionID: "a-" + id, Value: assertionValue, Span: "entire_attempt",
			BoundaryRef: NewMissing("not_applicable"), EvidenceRefs: []EvidenceRef{support},
		})
	}
	return ExecutionClaim{
		ClaimID: "claim-" + id, Scope: "execution_lifecycle", State: state,
		ApplicationAssertions: assertions,
		NativeRunID:           "native-1", NativeMessageID: "msg-" + id,
		NativeReport: testArtifact("exec-domain", 'n'), Mapping: testPin("map", "v1", 'g'),
		SourceChecks: verifiedChecks(support),
		MadeAt: testTP(150), ReceivedAt: testTP(160),
		EvidenceAvailableToClaimant: []EvidenceRef{},
		EvidenceRefs:                []EvidenceRef{support},
		Limitations:                 []string{},
	}
}

func TestConflictingNativeClaimsRemainCumulativeAndImmutable(t *testing.T) {
	commission := testCommission("subject")
	evidence, prefix := newChain(t, 4)
	support := refFor(evidence[2], "")
	attempt := testAttempt()
	digest := testDigest('c')

	claimA := lifecycleClaim("a", ExecCompleted, "committed", support)
	rev1 := axisRev(attempt, digest, AxisExecution, "exec-domain", "exec-writer", 1, 0, prefix,
		[]EvidenceRef{support}, ExecutionValue{Claims: []ExecutionClaim{claimA}})
	if err := ValidateAxisTransition(commission, nil, rev1, evidence); err != nil {
		t.Fatalf("first claim must pass: %v", err)
	}
	// Conflicting second claim appends; the first survives byte-identical.
	claimB := lifecycleClaim("b", ExecFailed, "not_committed", support)
	rev2 := axisRev(attempt, digest, AxisExecution, "exec-domain", "exec-writer", 2, 1, prefix,
		[]EvidenceRef{support}, ExecutionValue{Claims: []ExecutionClaim{claimA, claimB}})
	if err := ValidateAxisTransition(commission, []AxisRevision{rev1}, rev2, evidence); err != nil {
		t.Fatalf("conflicting claims must remain cumulative: %v", err)
	}
	// Rewriting the first claim is rejected.
	mutated := claimA
	mutated.State = ExecFailed
	revBad := axisRev(attempt, digest, AxisExecution, "exec-domain", "exec-writer", 2, 1, prefix,
		[]EvidenceRef{support}, ExecutionValue{Claims: []ExecutionClaim{mutated, claimB}})
	if err := ValidateAxisTransition(commission, []AxisRevision{rev1}, revBad, evidence); err == nil {
		t.Fatalf("rewriting a preserved claim must be rejected")
	}
	// Dropping the first claim is rejected.
	revDrop := axisRev(attempt, digest, AxisExecution, "exec-domain", "exec-writer", 2, 1, prefix,
		[]EvidenceRef{support}, ExecutionValue{Claims: []ExecutionClaim{claimB}})
	if err := ValidateAxisTransition(commission, []AxisRevision{rev1}, revDrop, evidence); err == nil {
		t.Fatalf("dropping a preserved claim must be rejected")
	}
	// Reconciliation preserves both and discloses the conflict.
	inputs := ReportInputPins{
		Dispatch: pinZero("not_observed"), Observation: pinZero("not_observed"),
		Execution: pinFor(t, rev2), Application: pinZero("not_observed"),
	}
	report, err := ReconcileAttempt(commission, inputs, []AxisRevision{rev2}, evidence, testPin("eval", "v1", 'e'))
	if err != nil {
		t.Fatalf("reconcile must succeed: %v", err)
	}
	if len(report.Comparisons) != 2 {
		t.Fatalf("both conflicting claims need comparisons, got %d", len(report.Comparisons))
	}
	foundConflict := false
	for _, is := range report.Issues {
		if is.Kind == "subject_claim_conflict" {
			foundConflict = true
		}
	}
	if !foundConflict {
		t.Fatalf("expected a subject_claim_conflict issue")
	}
}

// ---------------------------------------------------------------------------
// 6. Manual dispatch/execution stay unpublished and inapplicable.
// ---------------------------------------------------------------------------

func TestManualDispatchAndExecutionStayUnpublishedInapplicable(t *testing.T) {
	commission := testCommission("manual")
	evidence, prefix := newChain(t, 4)
	support := refFor(evidence[2], "")
	attempt := testAttempt()
	digest := testDigest('c')

	dispatchVal := DispatchValue{
		State: DispatchNotStarted, LocalHandle: NewMissing("not_applicable"),
		NativeRunID: NewMissing("not_applicable"), RequestDigest: NewMissing("not_applicable"),
		DeliveryRefs: []EvidenceRef{}, AcceptanceRefs: []EvidenceRef{},
		RecoveryAuthorizationRefs: []EvidenceRef{}, Reason: NewMissing("not_applicable"),
	}
	dispRev := axisRev(attempt, digest, AxisDispatch, "dispatch-domain", "dispatch-writer", 1, 0, prefix, []EvidenceRef{support}, dispatchVal)
	if err := ValidateAxisTransition(commission, nil, dispRev, evidence); err == nil {
		t.Fatalf("manual dispatch publication must be rejected")
	}
	execVal := ExecutionValue{Claims: []ExecutionClaim{stoppedClaim(support)}}
	execRev := axisRev(attempt, digest, AxisExecution, "exec-domain", "exec-writer", 1, 0, prefix, []EvidenceRef{support}, execVal)
	if err := ValidateAxisTransition(commission, nil, execRev, evidence); err == nil {
		t.Fatalf("manual execution publication must be rejected")
	}
	// Observation stays available under the recorder.
	obsVal := ObservationValue{
		State: ObsOpen, WindowID: "win-manual",
		OpenedAt: testTP(100), ActiveDeadline: testTP(200),
		DrainStartedAt: NewMissing("not_applicable"), DrainDeadline: NewMissing("not_applicable"),
		ClosedAt: NewMissing("not_applicable"), CloseReason: NewMissing("not_applicable"),
		AtClose: NewMissing("not_applicable"),
		ControlObservations: []ControlObservation{},
		LateEvidenceRefs:    []EvidenceRef{}, Measurements: []MeasurementEvidence{},
	}
	obsRev := axisRev(attempt, digest, AxisObservation, "obs-domain", "obs-writer", 1, 0, prefix, []EvidenceRef{support}, obsVal)
	if err := ValidateAxisTransition(commission, nil, obsRev, evidence); err != nil {
		t.Fatalf("manual observation must validate: %v", err)
	}
	// Employer receipt evidence can still establish an application fact.
	boundary := refFor(evidence[3], "")
	fact := committedFact("candidate-1", "job-1", boundary, support)
	fact.VerificationKind = "local_origin_transaction"
	appRev := axisRev(attempt, digest, AxisApplication, "origin-domain", "app-writer", 1, 0, prefix,
		[]EvidenceRef{support}, ApplicationValue{Facts: []OriginFact{fact}})
	if err := ValidateAxisTransition(commission, nil, appRev, evidence); err != nil {
		t.Fatalf("manual application fact must validate: %v", err)
	}
	inputs := ReportInputPins{
		Dispatch: pinZero("not_applicable"), Observation: pinFor(t, obsRev),
		Execution: pinZero("not_applicable"), Application: pinFor(t, appRev),
	}
	report, err := ReconcileAttempt(commission, inputs, []AxisRevision{obsRev, appRev}, evidence, testPin("eval", "v1", 'e'))
	if err != nil {
		t.Fatalf("manual reconcile must succeed: %v", err)
	}
	if report.Coverage != "not_applicable" {
		t.Fatalf("manual report coverage must be not_applicable, got %q", report.Coverage)
	}
	if !isMissingWithReason(report.State, "not_applicable") {
		t.Fatalf("manual report state must be Missing(not_applicable)")
	}
	if len(report.Comparisons) != 0 {
		t.Fatalf("manual report carries no fabricated comparisons")
	}
	// Non-zero manual pins are rejected.
	badInputs := inputs
	badInputs.Dispatch = DomainPin{Revision: 1, RecordDigest: testDigest('x')}
	if _, err := ReconcileAttempt(commission, badInputs, []AxisRevision{obsRev, appRev}, evidence, testPin("eval", "v1", 'e')); err == nil {
		t.Fatalf("manual dispatch pin must stay revision zero")
	}
}

// ---------------------------------------------------------------------------
// 7. New origin facts make older report pins visibly stale.
// ---------------------------------------------------------------------------

func TestNewOriginFactsMakeOlderReportInputPinsVisiblyStale(t *testing.T) {
	commission := testCommission("subject")
	evidence, prefix := newChain(t, 6)
	support := refFor(evidence[2], "")
	b1 := refFor(evidence[3], "")
	b2 := refFor(evidence[4], "")
	attempt := testAttempt()
	digest := testDigest('c')

	claim := lifecycleClaim("a", ExecCompleted, "committed", support)
	execRev := axisRev(attempt, digest, AxisExecution, "exec-domain", "exec-writer", 1, 0, prefix,
		[]EvidenceRef{support}, ExecutionValue{Claims: []ExecutionClaim{claim}})
	if err := ValidateAxisTransition(commission, nil, execRev, evidence); err != nil {
		t.Fatalf("exec must pass: %v", err)
	}
	fact1 := committedFact("candidate-1", "job-1", b1, support)
	appRev1 := axisRev(attempt, digest, AxisApplication, "origin-domain", "app-writer", 1, 0, prefix,
		[]EvidenceRef{support}, ApplicationValue{Facts: []OriginFact{fact1}})
	if err := ValidateAxisTransition(commission, nil, appRev1, evidence); err != nil {
		t.Fatalf("app rev1 must pass: %v", err)
	}
	inputs1 := ReportInputPins{
		Dispatch: pinZero("not_observed"), Observation: pinZero("not_observed"),
		Execution: pinFor(t, execRev), Application: pinFor(t, appRev1),
	}
	report1, err := ReconcileAttempt(commission, inputs1, []AxisRevision{execRev, appRev1}, evidence, testPin("eval", "v1", 'e'))
	if err != nil {
		t.Fatalf("report1 must succeed: %v", err)
	}
	// A second corroborating fact arrives cumulatively.
	fact2 := committedFact("candidate-1", "job-1", b2, support)
	fact2.FactID = "fact-2"
	appRev2 := axisRev(attempt, digest, AxisApplication, "origin-domain", "app-writer", 2, 1, prefix,
		[]EvidenceRef{support}, ApplicationValue{Facts: []OriginFact{fact1, fact2}})
	if err := ValidateAxisTransition(commission, []AxisRevision{appRev1}, appRev2, evidence); err != nil {
		t.Fatalf("app rev2 must pass: %v", err)
	}
	inputs2 := ReportInputPins{
		Dispatch: pinZero("not_observed"), Observation: pinZero("not_observed"),
		Execution: pinFor(t, execRev), Application: pinFor(t, appRev2),
	}
	report2, err := ReconcileAttempt(commission, inputs2, []AxisRevision{execRev, appRev2}, evidence, testPin("eval", "v1", 'e'))
	if err != nil {
		t.Fatalf("report2 must succeed: %v", err)
	}
	if report1.Inputs.Application.Revision != 1 || report2.Inputs.Application.Revision != 2 {
		t.Fatalf("pins must record the revisions read: got %d and %d",
			report1.Inputs.Application.Revision, report2.Inputs.Application.Revision)
	}
	if report1.Inputs.Application.Revision == appRev2.Revision {
		t.Fatalf("older pins must stay visibly stale after new facts")
	}
	// Report revisions advance pins and never regress them.
	repRev1 := axisRev(attempt, digest, AxisReport, "report-domain", "report-writer", 1, 0, prefix, []EvidenceRef{support}, report1)
	if err := ValidateAxisTransition(commission, nil, repRev1, evidence); err != nil {
		t.Fatalf("report rev1 must validate: %v", err)
	}
	repRev2 := axisRev(attempt, digest, AxisReport, "report-domain", "report-writer", 2, 1, prefix, []EvidenceRef{support}, report2)
	if err := ValidateAxisTransition(commission, []AxisRevision{repRev1}, repRev2, evidence); err != nil {
		t.Fatalf("report rev2 with advanced pins must validate: %v", err)
	}
	repRegress := axisRev(attempt, digest, AxisReport, "report-domain", "report-writer", 3, 2, prefix, []EvidenceRef{support}, report1)
	if err := ValidateAxisTransition(commission, []AxisRevision{repRev1, repRev2}, repRegress, evidence); err == nil {
		t.Fatalf("regressing report pins must be rejected")
	}
}

// ---------------------------------------------------------------------------
// 8. Closed observation revisions cannot rewrite close knowledge.
// ---------------------------------------------------------------------------

func TestObservationClosedRevisionsCannotRewriteCloseKnowledge(t *testing.T) {
	commission := testCommission("subject")
	evidence, prefix := newChain(t, 5)
	closeRef := refFor(evidence[3], "")
	lateRef := refFor(evidence[4], "")
	attempt := testAttempt()
	digest := testDigest('c')

	rev1Val := closedUnknownObservation(t, closeRef)
	rev1 := axisRev(attempt, digest, AxisObservation, "obs-domain", "obs-writer", 1, 0, prefix, []EvidenceRef{closeRef}, rev1Val)
	if err := ValidateAxisTransition(commission, nil, rev1, evidence); err != nil {
		t.Fatalf("closed rev1 must pass: %v", err)
	}
	// Rewriting closed_at is rejected.
	mutTime := rev1Val
	mutTime.ClosedAt = testTP(999)
	revBadTime := axisRev(attempt, digest, AxisObservation, "obs-domain", "obs-writer", 2, 1, prefix, []EvidenceRef{closeRef}, mutTime)
	if err := ValidateAxisTransition(commission, []AxisRevision{rev1}, revBadTime, evidence); err == nil {
		t.Fatalf("rewriting closed_at must be rejected")
	}
	// Rewriting the close snapshot is rejected.
	mutSnap := rev1Val
	cs, _ := asCloseSnapshotValue(rev1Val.AtClose)
	cs.ApplicationKnowledge = "committed"
	mutSnap.AtClose = cs
	revBadSnap := axisRev(attempt, digest, AxisObservation, "obs-domain", "obs-writer", 2, 1, prefix, []EvidenceRef{closeRef}, mutSnap)
	if err := ValidateAxisTransition(commission, []AxisRevision{rev1}, revBadSnap, evidence); err == nil {
		t.Fatalf("rewriting close knowledge must be rejected")
	}
	// Appending late evidence with frozen closure passes.
	rev2Val := rev1Val
	rev2Val.LateEvidenceRefs = []EvidenceRef{lateRef}
	rev2Val.ControlObservations = []ControlObservation{
		{
			ControlEventID: "ctl-1", OperationID: "op-1", Operation: "CloseObservationConnection",
			TargetScope: "observation_connection", Disposition: "effect_observed",
			At: testTP(310), AuthorizationRef: closeRef,
			CapabilityRef: NewMissing("not_observed"),
			Opportunity: Opportunity{State: "exposed", EvidenceRefs: []EvidenceRef{closeRef}, Rationale: "connection observed"},
			RequestRef: NewMissing("not_observed"), ResponseRef: NewMissing("not_observed"),
			ResponseChecks: NewMissing("not_observed"),
			NativeClaimRefs: []EvidenceRef{}, EffectRefs: []EvidenceRef{lateRef},
			AffectedAttempts: []AttemptReference{}, Measurements: []MeasurementEvidence{},
			Limitations: []string{},
		},
	}
	rev2 := axisRev(attempt, digest, AxisObservation, "obs-domain", "obs-writer", 2, 1, prefix, []EvidenceRef{lateRef}, rev2Val)
	if err := ValidateAxisTransition(commission, []AxisRevision{rev1}, rev2, evidence); err != nil {
		t.Fatalf("closed-to-closed with appended late evidence must pass: %v", err)
	}
}

// ---------------------------------------------------------------------------
// 9. Receipt order alone cannot establish occurrence order.
// ---------------------------------------------------------------------------

func TestReceiptOrderAloneCannotEstablishOccurrenceOrder(t *testing.T) {
	commission := testCommission("subject")
	evidence, prefix := newChain(t, 5)
	// Boundaries carry no occurrence coordinates: only receipt order differs.
	b1 := refFor(evidence[3], "")
	b2 := refFor(evidence[4], "")
	support := refFor(evidence[2], "")
	attempt := testAttempt()
	digest := testDigest('c')

	// Assertion at boundary b1; fact at a different boundary b2. Receipt
	// order (claim 1000, fact 2000) suggests an order, but no same-clock,
	// causal, or origin-sequence evidence exists.
	claim := ExecutionClaim{
		ClaimID: "claim-1", Scope: "execution_lifecycle", State: ExecCompleted,
		ApplicationAssertions: []CommitmentAssertion{
			{AssertionID: "a-1", Value: "committed", Span: "at_boundary",
				BoundaryRef: b1, EvidenceRefs: []EvidenceRef{support}},
		},
		NativeRunID: "native-1", NativeMessageID: "msg-1",
		NativeReport: testArtifact("exec-domain", 'n'), Mapping: testPin("map", "v1", 'g'),
		SourceChecks: verifiedChecks(support),
		MadeAt: testTP(100), ReceivedAt: testTPOn("clk-1", "boot-1", "engine_measured", 1000),
		EvidenceAvailableToClaimant: []EvidenceRef{},
		EvidenceRefs:                []EvidenceRef{support},
		Limitations:                 []string{},
	}
	execRev := axisRev(attempt, digest, AxisExecution, "exec-domain", "exec-writer", 1, 0, prefix,
		[]EvidenceRef{support}, ExecutionValue{Claims: []ExecutionClaim{claim}})
	if err := ValidateAxisTransition(commission, nil, execRev, evidence); err != nil {
		t.Fatalf("exec must pass: %v", err)
	}
	fact := OriginFact{
		FactID: "fact-1", OriginID: "origin-lab-1", CandidateID: "candidate-1", JobID: "job-1",
		State: "committed", Coverage: "at_boundary", BoundaryRef: b2,
		OriginApplicationID: "app-1", OriginRevision: "rev-10",
		Receipt: testArtifact("origin-domain", 'e'), VerificationKind: "local_origin_transaction",
		SourceChecks: verifiedChecks(support), AuthoritySealRef: NewMissing("not_applicable"),
		OccurredAt: NewMissing("not_observed"),
		ReceivedAt: testTPOn("clk-9", "boot-9", "engine_measured", 2000),
		EvidenceRefs: []EvidenceRef{support},
	}
	appRev := axisRev(attempt, digest, AxisApplication, "origin-domain", "app-writer", 1, 0, prefix,
		[]EvidenceRef{support}, ApplicationValue{Facts: []OriginFact{fact}})
	if err := ValidateAxisTransition(commission, nil, appRev, evidence); err != nil {
		t.Fatalf("fact must pass: %v", err)
	}
	inputs := ReportInputPins{
		Dispatch: pinZero("not_observed"), Observation: pinZero("not_observed"),
		Execution: pinFor(t, execRev), Application: pinFor(t, appRev),
	}
	report, err := ReconcileAttempt(commission, inputs, []AxisRevision{execRev, appRev}, evidence, testPin("eval", "v1", 'e'))
	if err != nil {
		t.Fatalf("reconcile must succeed: %v", err)
	}
	if len(report.Comparisons) != 1 {
		t.Fatalf("expected one comparison, got %d", len(report.Comparisons))
	}
	tr := report.Comparisons[0].TemporalRelation
	if tr.Relation == "before" || tr.Relation == "after" || tr.Relation == "at" {
		t.Fatalf("receipt order alone must not establish %q", tr.Relation)
	}
	if tr.Relation != "unknown" || tr.Basis != "not_established" {
		t.Fatalf("expected unknown/not_established temporal, got %q/%q", tr.Relation, tr.Basis)
	}
}

package diagnostic_render

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	evidence_codec "evidence_codec"
)

// testDigest builds a well-formed shared digest from one repeated hex digit.
func testDigest(c string) string {
	return "sha256:" + strings.Repeat(c, 64)
}

func testRef(journal, event string, seq int) EvidenceRef {
	return EvidenceRef{
		JournalID: journal,
		Sequence:  seq,
		EventID:   event,
		EventHash: testDigest("a"),
		Pointer:   "",
	}
}

func testTimePoint(offset float64) TimePoint {
	return TimePoint{
		ClockID:           "clock-engine-1",
		BootID:            "boot-1",
		Origin:            "engine_measured",
		MonotonicOffsetMs: offset,
		UtcAnnotation:     Missing{Reason: "not_observed", Detail: "no wall-clock annotation recorded"},
	}
}

func testAttempt() AttemptContext {
	return AttemptContext{
		AttemptID:           "attempt-1",
		Kind:                "practice",
		TargetClass:         "laboratory_fixture",
		TargetID:            "fixture-login-3",
		EvaluationPartition: "held_in",
		RehearsalOf:         []AttemptReference{},
		PerformanceOf:       []AttemptReference{},
		DerivedFrom:         []AttemptReference{},
	}
}

func testExecutionManual() ExecutionDescriptor {
	return ExecutionDescriptor{
		Mode:             "manual",
		Subject:          Missing{Reason: "not_applicable", Detail: "manual mode judges no automation subject"},
		ConnectorVersion: Missing{Reason: "not_applicable", Detail: "manual mode uses no connector"},
		BindingVersion:   Missing{Reason: "not_applicable", Detail: "manual mode uses no binding"},
		Assistance: AssistanceRecord{
			PlanningOwner:    "operator",
			AssistanceTrack:  "manual-walkthrough",
			PlannerIdentity:  Missing{Reason: "not_applicable", Detail: "operator planning has no planner identity"},
			Plan:             Missing{Reason: "not_observed", Detail: "no recorded plan artifact"},
			OnlineReplanning: false,
			Description:      "operator-led walkthrough without planner assistance",
		},
	}
}

// baseDiagnostic returns a complete diagnostic exercising every rendered
// section. Callers mutate the copy for scenario-specific coverage.
func baseDiagnostic() DiagnosticDocument {
	return DiagnosticDocument{
		RecordType:       "diagnostic",
		SchemaVersion:    "0.1.0",
		DiagnosticID:     "diag-7f3a",
		AnalysisRevision: 2,
		RunID:            "run-9c1e",
		ManifestHash:     testDigest("b"),
		InputPrefix: JournalPrefix{
			JournalID:    "journal-primary",
			LastSequence: 12,
			HeadHash:     testDigest("c"),
		},
		AnalysisRequestRef:  testRef("journal-primary", "evt-analysis-requested", 12),
		Classifier:          VersionPin{ID: "hellscape-classifier", Version: "v3.2.0", ArtifactDigest: testDigest("d")},
		RequirementRegistry: VersionPin{ID: "hellscape-requirements", Version: "r10.1", ArtifactDigest: testDigest("e")},
		FixRegistry:         Missing{Reason: "not_enabled", Detail: "M1 analysis runs without a fix registry"},
		Attempt:             testAttempt(),
		Execution:           testExecutionManual(),
		DeliveredTaskHash:   testDigest("f"),
		NativeRequestHash:   Missing{Reason: "not_applicable", Detail: "manual mode issues no native request"},
		Validity: DiagnosticValidity{
			ScopedChecks: []ValidityCheck{
				{
					CheckID:      "fixture-valid",
					Scope:        Scope{Kind: "run", ID: "run-9c1e"},
					State:        "valid",
					EvidenceRefs: []EvidenceRef{testRef("journal-primary", "evt-admission", 1)},
					Rationale:    "manifest and fixture configuration verified at admission",
				},
			},
			ProducerCompleteness: []ProducerCompleteness{
				{
					ProducerID:     "producer-spa",
					State:          "complete",
					ObservedRanges: []SequenceRange{{First: 1, Last: 12}},
					MissingRanges:  []SequenceRange{},
					FinalSequence:  12,
					EvidenceRefs:   []EvidenceRef{testRef("journal-primary", "evt-producer-close", 11)},
				},
			},
			InfrastructureIncidents: []EvidenceNote{},
			Limitations:             []string{"telemetry covers the SPA producer only; browser profile state is out of scope"},
		},
		CapabilityDescriptors: []ArtifactSlot{},
		RequirementAssessments: []RequirementAssessment{
			{
				RequirementID:   "R3",
				Facet:           "task-claims",
				ContractVersion: "r10.1",
				Scope:           Scope{Kind: "workflow_step", ID: "step-submit"},
				CapabilityRefs:  []CapabilityReference{},
				Opportunity: Opportunity{
					State:        "exposed",
					EvidenceRefs: []EvidenceRef{testRef("journal-primary", "evt-exposure", 5)},
					Rationale:    "submit control rendered and armed before the attempt",
				},
				Result:               "satisfied",
				EvidenceRefs:         []EvidenceRef{testRef("journal-primary", "evt-postcondition", 8)},
				ContraryEvidenceRefs: []EvidenceRef{},
				FindingRefs:          []string{"finding-1"},
				Rationale:            "authoritative postcondition held at cutoff",
			},
		},
		ObservedActions: []ObservedAction{
			{
				ActionID:         "action-1",
				Kind:             "click",
				TargetAlias:      "submit-button",
				FrameAlias:       "main-frame",
				RenderGeneration: 4,
				EvidenceRefs:     []EvidenceRef{testRef("journal-primary", "evt-action", 6)},
				ObservedEffect:   map[string]any{"navigated": true},
				Provenance:       "fixture_client",
				Limitations:      []string{"effect observed via fixture client only"},
			},
		},
		FeatureExposures: []FeatureExposure{
			{
				InstanceID:       "feat-captcha",
				Configured:       true,
				RenderedOrArmed:  true,
				Exposed:          false,
				Activated:        false,
				RecoveryObserved: Missing{Reason: "not_applicable", Detail: "unexposed feature has no recovery to observe"},
				EvidenceRefs:     []EvidenceRef{testRef("journal-primary", "evt-exposure", 5)},
			},
		},
		Steps: []StepDiagnostic{
			{
				StepID:     "step-submit",
				ContractID: "contract-submit-form",
				Status:     "passed",
				Attempts: []StepAttempt{
					{
						Ordinal:      1,
						Disposition:  "accepted",
						EvidenceRefs: []EvidenceRef{testRef("journal-primary", "evt-action", 6)},
						Postconditions: []PredicateResult{
							{
								PredicateID:     "form-accepted",
								Scope:           Scope{Kind: "application_operation", ID: "submit"},
								Truth:           "satisfied",
								AuthorityDomain: "application",
								EvidenceRefs:    []EvidenceRef{testRef("journal-primary", "evt-postcondition", 8)},
							},
						},
						MeasurementRefs: []string{"measure-submit-latency"},
					},
				},
				AuthoritativePostconditions: []PredicateResult{
					{
						PredicateID:     "form-accepted",
						Scope:           Scope{Kind: "application_operation", ID: "submit"},
						Truth:           "satisfied",
						AuthorityDomain: "application",
						EvidenceRefs:    []EvidenceRef{testRef("journal-primary", "evt-postcondition", 8)},
					},
				},
				MeasurementRefs: []string{"measure-submit-latency"},
				FindingRefs:     []string{},
			},
		},
		Measurements: []MeasurementEvidence{
			{
				Measurement: Measurement{
					MeasurementID:      "measure-submit-latency",
					Name:               "submit-latency",
					Scope:              Scope{Kind: "workflow_step", ID: "step-submit"},
					Quantity:           "duration",
					Unit:               "ms",
					Origin:             "engine_measured",
					ClockID:            "clock-engine-1",
					BootID:             "boot-1",
					Method:             "endpoint_difference",
					Start:              testTimePoint(1000),
					End:                testTimePoint(1460),
					Estimate:           map[string]any{"kind": "exact", "value": 460},
					Resolution:         1,
					Censoring:          "none",
					ComparabilityGroup: "submit-latency-v1",
				},
				EvidenceRefs: []EvidenceRef{testRef("journal-primary", "evt-timing", 9)},
			},
		},
		Claims: []Claim{
			{
				ClaimID:     "claim-exec-1",
				Source:      "connector",
				Scope:       "execution_lifecycle",
				Proposition: map[string]any{"run_completed": true},
				MadeAt:      testTimePoint(1400),
				ReceivedAt:  testTimePoint(1450),
				EvidenceRefs: []EvidenceRef{
					testRef("journal-primary", "evt-claim", 7),
				},
				EvidenceAvailableToClaimant: []EvidenceRef{testRef("journal-primary", "evt-action", 6)},
				KnowledgeLimitations:        []string{"connector observes dispatch and acknowledgement, not origin commitment"},
				Comparison:                  "consistent",
				ComparisonEvidenceRefs:      []EvidenceRef{testRef("journal-primary", "evt-postcondition", 8)},
			},
			{
				ClaimID:     "claim-outcome-1",
				Source:      "manual_operator",
				Scope:       "application_postcondition",
				Proposition: map[string]any{"no_commit": true},
				MadeAt:      Missing{Reason: "not_observed", Detail: "operator noted the claim without a clock reading"},
				ReceivedAt:  testTimePoint(1500),
				EvidenceRefs: []EvidenceRef{
					testRef("journal-primary", "evt-note", 10),
				},
				EvidenceAvailableToClaimant: []EvidenceRef{},
				KnowledgeLimitations:        []string{"operator note predates the commitment record review"},
				Comparison:                  "contradicted",
				ComparisonEvidenceRefs:      []EvidenceRef{testRef("journal-primary", "evt-postcondition", 8)},
			},
		},
		Findings: []Finding{
			{
				FindingID:            "finding-1",
				Kind:                 "observation",
				RequirementRefs:      []string{"R3"},
				Symptom:              "submit postcondition held at cutoff",
				Scope:                Scope{Kind: "workflow_step", ID: "step-submit"},
				CausalRole:           "not_applicable",
				TriggerFeatureRefs:   []string{},
				DefectLocus:          "not_applicable",
				Attribution:          "supported",
				EvidenceRefs:         []EvidenceRef{testRef("journal-primary", "evt-postcondition", 8)},
				ContraryEvidenceRefs: []EvidenceRef{},
				Limitations:          []string{"single-observation window; no longitudinal evidence"},
				SuggestedFix:         Missing{Reason: "not_enabled", Detail: "M1 analysis runs without a fix registry"},
			},
		},
		Observation: ObservationSummary{
			OpenedRef:        testRef("journal-primary", "evt-admission", 1),
			ClosedRef:        Missing{Reason: "not_observed", Detail: "observation still open at analysis cutoff"},
			ClosureReason:    Missing{Reason: "not_observed", Detail: "no closure recorded before cutoff"},
			LifecycleRefs:    []EvidenceRef{testRef("journal-primary", "evt-lifecycle", 4)},
			ContainmentRefs:  []EvidenceRef{},
			LateEvidenceRefs: []EvidenceRef{},
		},
		Application: ApplicationSummary{
			Goal:         "completed",
			AsOfSequence: 12,
			Postconditions: []PredicateResult{
				{
					PredicateID:     "form-accepted",
					Scope:           Scope{Kind: "application_operation", ID: "submit"},
					Truth:           "satisfied",
					AuthorityDomain: "application",
					EvidenceRefs:    []EvidenceRef{testRef("journal-primary", "evt-postcondition", 8)},
				},
			},
			CommitmentRefs:   []EvidenceRef{testRef("journal-primary", "evt-postcondition", 8)},
			ConfirmationRefs: []EvidenceRef{},
		},
		BehavioralProfile: AnalysisSection{
			Data: map[string]any{
				"human_likeness_notes": "keystroke cadence within walkthrough baseline",
				"samples":              14,
			},
			EvidenceRefs: []EvidenceRef{testRef("journal-primary", "evt-timing", 9)},
		},
		FingerprintProfile: AnalysisSection{
			Data:         Missing{Reason: "not_enabled", Detail: "transport fingerprint analysis disabled for M1"},
			EvidenceRefs: []EvidenceRef{},
		},
		Artifacts: []ArtifactSlot{
			{
				Name:           "task-definition",
				ExpectedDigest: testDigest("1"),
				Content: ArtifactReference{
					Digest:      testDigest("1"),
					SizeBytes:   2048,
					MediaType:   "application/json",
					OwnerDomain: "fixture",
					Access:      "public",
				},
				EvidenceRefs: []EvidenceRef{testRef("journal-primary", "evt-admission", 1)},
			},
			{
				Name:           "native-transport-capture",
				ExpectedDigest: testDigest("2"),
				Content:        Missing{Reason: "observation_lost", Detail: "capture file lost before analysis; known digest retained"},
				EvidenceRefs:   []EvidenceRef{testRef("journal-primary", "evt-loss", 11)},
			},
		},
	}
}

// decodeJSONReport parses a JSON report into a generic map.
func decodeJSONReport(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("JSON report is not valid JSON: %v", err)
	}
	return v
}

// missingReason extracts the reason from a decoded Missing envelope.
func missingReason(t *testing.T, v any) string {
	t.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("expected Missing envelope, got %T (%v)", v, v)
	}
	if m["value"] != nil {
		t.Fatalf("Missing envelope value must be null, got %v", m["value"])
	}
	reason, _ := m["reason"].(string)
	if reason == "" {
		t.Fatalf("Missing envelope has no reason: %v", m)
	}
	return reason
}

// TestReadableAndJSONReportsRenderTheSameDiagnostic covers
// [ReadableAndJSONReportsRenderTheSameDiagnostic]: both reports derive from
// the same canonical object, carry the same diagnostic identity and content,
// and render deterministically without adding verdicts or evidence.
func TestReadableAndJSONReportsRenderTheSameDiagnostic(t *testing.T) {
	doc := baseDiagnostic()

	jsonReport, readableReport, err := RenderDiagnostic(doc)
	if err != nil {
		t.Fatalf("RenderDiagnostic failed: %v", err)
	}
	if len(jsonReport) == 0 || len(readableReport) == 0 {
		t.Fatalf("expected nonempty JSON and readable reports")
	}

	// The JSON report carries the full diagnostic identity and content.
	decoded := decodeJSONReport(t, jsonReport)
	if decoded["diagnostic_id"] != doc.DiagnosticID {
		t.Errorf("JSON diagnostic_id = %v, want %s", decoded["diagnostic_id"], doc.DiagnosticID)
	}
	if decoded["analysis_revision"] != float64(doc.AnalysisRevision) {
		t.Errorf("JSON analysis_revision = %v, want %d", decoded["analysis_revision"], doc.AnalysisRevision)
	}
	if decoded["run_id"] != doc.RunID {
		t.Errorf("JSON run_id = %v, want %s", decoded["run_id"], doc.RunID)
	}
	if decoded["manifest_hash"] != doc.ManifestHash {
		t.Errorf("JSON manifest_hash = %v, want %s", decoded["manifest_hash"], doc.ManifestHash)
	}
	for _, field := range []string{
		"input_prefix", "analysis_request_ref", "classifier", "requirement_registry",
		"fix_registry", "attempt", "execution", "validity", "claims", "findings",
		"observation", "application", "behavioral_profile", "fingerprint_profile", "artifacts",
	} {
		if _, ok := decoded[field]; !ok {
			t.Errorf("JSON report drops field %q", field)
		}
	}
	if got := len(decoded["claims"].([]any)); got != len(doc.Claims) {
		t.Errorf("JSON claims = %d, want %d", got, len(doc.Claims))
	}
	if got := len(decoded["findings"].([]any)); got != len(doc.Findings) {
		t.Errorf("JSON findings = %d, want %d", got, len(doc.Findings))
	}

	// The JSON report is canonical: re-canonicalizing is a fixed point.
	recanonical, err := evidence_codec.CanonicalJSON(jsonReport, "application/json")
	if err != nil {
		t.Fatalf("re-canonicalizing JSON report failed: %v", err)
	}
	if string(recanonical) != string(jsonReport) {
		t.Errorf("JSON report is not canonical: re-canonicalization differs")
	}

	// The readable report carries the same diagnostic identity and content.
	readable := string(readableReport)
	for _, want := range []string{
		doc.DiagnosticID, doc.RunID, doc.ManifestHash,
		doc.InputPrefix.JournalID, doc.InputPrefix.HeadHash,
		"hellscape-classifier", "hellscape-requirements",
		"claim-exec-1", "claim-outcome-1", "finding-1",
		"R3", "step-submit", "action-1", "measure-submit-latency",
		"task-definition", "native-transport-capture",
	} {
		if !strings.Contains(readable, want) {
			t.Errorf("readable report omits %q", want)
		}
	}

	// Rendering is deterministic: same document, byte-identical reports.
	jsonAgain, readableAgain, err := RenderDiagnostic(doc)
	if err != nil {
		t.Fatalf("second RenderDiagnostic failed: %v", err)
	}
	if string(jsonAgain) != string(jsonReport) {
		t.Errorf("JSON report is not deterministic across renders")
	}
	if string(readableAgain) != string(readableReport) {
		t.Errorf("readable report is not deterministic across renders")
	}

	// Rendering adds no overall verdict, qualification, or fresh evidence.
	for _, forbidden := range []string{
		"overall_status", "overall_verdict", "qualification", "attempt_status",
		"\"overall\"", "Overall verdict", "FINAL VERDICT",
	} {
		if strings.Contains(string(jsonReport), forbidden) {
			t.Errorf("JSON report adds forbidden field %q", forbidden)
		}
		if strings.Contains(readable, forbidden) {
			t.Errorf("readable report adds forbidden verdict %q", forbidden)
		}
	}

	// Structural validation is real: missing identity is rejected.
	bad := baseDiagnostic()
	bad.DiagnosticID = ""
	if _, _, err := RenderDiagnostic(bad); err == nil {
		t.Errorf("expected error for empty diagnostic_id, got nil")
	}
	bad = baseDiagnostic()
	bad.AnalysisRevision = 0
	if _, _, err := RenderDiagnostic(bad); err == nil {
		t.Errorf("expected error for zero analysis_revision, got nil")
	}
}

// TestDisabledAnalysesRenderReasonedMissingnessNotScores covers
// [DisabledAnalysesRenderReasonedMissingnessNotScores]: disabled profiles and
// fixes render as Missing(not_enabled) with their detail, and no zero-valued
// scores are synthesized in either report.
func TestDisabledAnalysesRenderReasonedMissingnessNotScores(t *testing.T) {
	doc := baseDiagnostic()
	doc.BehavioralProfile = AnalysisSection{
		Data:         Missing{Reason: "not_enabled", Detail: "behavioral scoring disabled for manual walkthrough"},
		EvidenceRefs: []EvidenceRef{},
	}
	doc.FingerprintProfile = AnalysisSection{
		Data:         Missing{Reason: "not_enabled", Detail: "transport fingerprint analysis disabled for M1"},
		EvidenceRefs: []EvidenceRef{},
	}

	jsonReport, readableReport, err := RenderDiagnostic(doc)
	if err != nil {
		t.Fatalf("RenderDiagnostic failed: %v", err)
	}
	decoded := decodeJSONReport(t, jsonReport)

	// JSON preserves both disabled envelopes with reasons and details.
	behavioral := decoded["behavioral_profile"].(map[string]any)
	if got := missingReason(t, behavioral["data"]); got != "not_enabled" {
		t.Errorf("behavioral_profile reason = %q, want not_enabled", got)
	}
	fingerprint := decoded["fingerprint_profile"].(map[string]any)
	if got := missingReason(t, fingerprint["data"]); got != "not_enabled" {
		t.Errorf("fingerprint_profile reason = %q, want not_enabled", got)
	}
	for _, section := range []map[string]any{behavioral, fingerprint} {
		data := section["data"].(map[string]any)
		if detail, _ := data["detail"].(string); detail == "" {
			t.Errorf("disabled profile drops its Missing detail: %v", data)
		}
	}
	findings := decoded["findings"].([]any)
	fix := findings[0].(map[string]any)["suggested_fix"]
	if got := missingReason(t, fix); got != "not_enabled" {
		t.Errorf("suggested_fix reason = %q, want not_enabled", got)
	}

	// The readable report names the disabled state and its reasons.
	readable := string(readableReport)
	for _, want := range []string{
		"Behavioral profile", "Fingerprint profile",
		"disabled", "not_enabled",
		"behavioral scoring disabled for manual walkthrough",
		"transport fingerprint analysis disabled for M1",
	} {
		if !strings.Contains(readable, want) {
			t.Errorf("readable report omits disabled-analysis marker %q", want)
		}
	}

	// No zero-valued scores are synthesized for disabled analyses.
	for _, forbidden := range []string{
		"score: 0", "score 0", `"score":0`, `"score": 0`,
		"human_likeness: 0", "risk_score",
	} {
		if strings.Contains(readable, forbidden) {
			t.Errorf("readable report fabricates disabled-analysis value %q", forbidden)
		}
		if strings.Contains(string(jsonReport), forbidden) {
			t.Errorf("JSON report fabricates disabled-analysis value %q", forbidden)
		}
	}

	// Contrast: a present analysis renders its data instead of Missing.
	enabled := baseDiagnostic()
	enabled.BehavioralProfile = AnalysisSection{
		Data: map[string]any{
			"human_likeness_notes": "keystroke cadence within walkthrough baseline",
			"samples":              14,
		},
		EvidenceRefs: []EvidenceRef{testRef("journal-primary", "evt-timing", 9)},
	}
	enabledJSON, enabledReadable, err := RenderDiagnostic(enabled)
	if err != nil {
		t.Fatalf("RenderDiagnostic with enabled profile failed: %v", err)
	}
	enabledDecoded := decodeJSONReport(t, enabledJSON)
	enabledData, ok := enabledDecoded["behavioral_profile"].(map[string]any)["data"].(map[string]any)
	if !ok {
		t.Fatalf("enabled behavioral data should be a map, got %T", enabledDecoded["behavioral_profile"])
	}
	if _, isMissing := enabledData["reason"]; isMissing {
		t.Errorf("enabled behavioral data wrongly renders as Missing: %v", enabledData)
	}
	if !strings.Contains(string(enabledReadable), "keystroke cadence within walkthrough baseline") {
		t.Errorf("readable report drops present behavioral data")
	}
	if !strings.Contains(string(enabledReadable), "state: present") {
		t.Errorf("readable report does not mark the enabled profile present")
	}
}

// TestReportRenderingPreservesScopeCoverageAndLimitations covers
// [ReportRenderingPreservesScopeCoverageAndLimitations]: every claim renders
// with source, scope, receipt, comparison, and knowledge boundary; every
// limitation renders verbatim; missing artifacts, incomplete observation, and
// source pins stay visible; and neutral EK vocabulary is never upgraded into
// success or pass language.
func TestReportRenderingPreservesScopeCoverageAndLimitations(t *testing.T) {
	doc := baseDiagnostic()
	doc.Claims = append(doc.Claims,
		Claim{
			ClaimID:     "claim-primitive-1",
			Source:      "native_framework",
			Scope:       "primitive",
			Proposition: map[string]any{"primitive_completed": "dom-query"},
			MadeAt:      Missing{Reason: "not_observed", Detail: "native framework gave no made-at reading"},
			ReceivedAt:  testTimePoint(1200),
			EvidenceRefs: []EvidenceRef{
				testRef("journal-primary", "evt-native", 3),
			},
			EvidenceAvailableToClaimant: []EvidenceRef{},
			KnowledgeLimitations:        []string{"native scope covers the primitive only, not the application step"},
			Comparison:                  "not_comparable",
			ComparisonEvidenceRefs:      []EvidenceRef{},
		},
		Claim{
			ClaimID:     "claim-plan-1",
			Source:      "native_planner",
			Scope:       "unknown",
			Proposition: map[string]any{"plan_step": "retry-once"},
			MadeAt:      testTimePoint(1100),
			ReceivedAt:  testTimePoint(1150),
			EvidenceRefs: []EvidenceRef{
				testRef("journal-primary", "evt-plan", 2),
			},
			EvidenceAvailableToClaimant: []EvidenceRef{},
			KnowledgeLimitations:        []string{"planner evidence unavailable to the analyzer"},
			Comparison:                  "indeterminate",
			ComparisonEvidenceRefs:      []EvidenceRef{},
		},
	)

	jsonReport, readableReport, err := RenderDiagnostic(doc)
	if err != nil {
		t.Fatalf("RenderDiagnostic failed: %v", err)
	}
	decoded := decodeJSONReport(t, jsonReport)
	readable := string(readableReport)

	// Every claim is accounted for in both reports with source, semantic
	// scope, receipt, comparison, and knowledge boundary.
	jsonClaims := decoded["claims"].([]any)
	if len(jsonClaims) != 4 {
		t.Fatalf("JSON claims = %d, want 4", len(jsonClaims))
	}
	comparisons := map[string]bool{}
	for _, c := range jsonClaims {
		cm := c.(map[string]any)
		for _, field := range []string{
			"claim_id", "source", "scope", "proposition", "made_at",
			"received_at", "evidence_refs", "knowledge_limitations",
			"comparison", "comparison_evidence_refs",
		} {
			if _, ok := cm[field]; !ok {
				t.Errorf("JSON claim %v drops field %q", cm["claim_id"], field)
			}
		}
		comparisons[cm["comparison"].(string)] = true
	}
	for _, want := range []string{"consistent", "contradicted", "not_comparable", "indeterminate"} {
		if !comparisons[want] {
			t.Errorf("JSON report loses comparison coverage %q", want)
		}
		if !strings.Contains(readable, want) {
			t.Errorf("readable report loses comparison coverage %q", want)
		}
	}
	for _, want := range []string{
		"claim-exec-1", "claim-outcome-1", "claim-primitive-1", "claim-plan-1",
		"connector", "manual_operator", "native_framework", "native_planner",
		"execution_lifecycle", "application_postcondition", "primitive",
		"connector observes dispatch and acknowledgement, not origin commitment",
		"operator note predates the commitment record review",
		"native scope covers the primitive only, not the application step",
		"planner evidence unavailable to the analyzer",
	} {
		if !strings.Contains(readable, want) {
			t.Errorf("readable report omits claim coverage %q", want)
		}
	}
	// The proved contradiction stays visible; it is not softened or dropped.
	if !strings.Contains(readable, "claim-outcome-1") || !strings.Contains(readable, "contradicted") {
		t.Errorf("readable report conceals the proved claim contradiction")
	}

	// Every limitation renders verbatim in both reports.
	limitations := []string{
		"telemetry covers the SPA producer only; browser profile state is out of scope",
		"single-observation window; no longitudinal evidence",
		"effect observed via fixture client only",
	}
	for _, want := range limitations {
		if !strings.Contains(readable, want) {
			t.Errorf("readable report drops limitation %q", want)
		}
		if !strings.Contains(string(jsonReport), want) {
			t.Errorf("JSON report drops limitation %q", want)
		}
	}

	// Missing artifacts, incomplete observation, and source pins stay visible.
	for _, want := range []string{
		"native-transport-capture", "observation_lost",
		"capture file lost before analysis; known digest retained",
		"closed: Missing (reason: not_observed",
		"observation still open at analysis cutoff",
		doc.ManifestHash, doc.InputPrefix.HeadHash,
		"hellscape-classifier", "hellscape-requirements",
	} {
		if !strings.Contains(readable, want) {
			t.Errorf("readable report conceals %q", want)
		}
	}

	// Scope and result coverage render for requirements, steps, and the
	// application/observation summaries.
	for _, want := range []string{
		"workflow_step:step-submit", "opportunity: exposed", "result: satisfied",
		"step-submit", "contract-submit-form", "status passed",
		"goal: completed", "as_of_sequence: 12",
		"form-accepted",
	} {
		if !strings.Contains(readable, want) {
			t.Errorf("readable report omits scope coverage %q", want)
		}
	}

	// Neutral EK vocabulary is never upgraded into success or pass language,
	// and inapplicable/not-comparable states are never presented as passing.
	lower := strings.ToLower(readable)
	for _, forbidden := range []string{
		"application success", "attempt succeeded", "overall pass",
		"all checks passed", "reconciled", "no issues found",
		"inapplicable (pass)", "not_comparable (pass)",
	} {
		if strings.Contains(lower, forbidden) {
			t.Errorf("readable report misrepresents coverage as success: %q", forbidden)
		}
	}

	// EK-NULL holds end to end: the JSON report carries no bare nulls.
	var generic any
	dec := json.NewDecoder(strings.NewReader(string(jsonReport)))
	dec.UseNumber()
	if err := dec.Decode(&generic); err != nil {
		t.Fatalf("decoding JSON report: %v", err)
	}
	assertNoBareNulls(t, generic, "$")

	// A caller-side bare null (nil Maybe without an envelope) is rejected
	// rather than rendered.
	bad := baseDiagnostic()
	bad.DeliveredTaskHash = nil
	if _, _, err := RenderDiagnostic(bad); err == nil {
		t.Errorf("expected bare-null rejection for nil delivered_task_hash, got nil error")
	} else if !strings.Contains(err.Error(), "bare null") {
		t.Errorf("expected bare-null error, got: %v", err)
	}
}

// assertNoBareNulls walks decoded JSON and fails on any null outside a
// Missing envelope.
func assertNoBareNulls(t *testing.T, v any, path string) {
	t.Helper()
	switch typed := v.(type) {
	case nil:
		t.Fatalf("bare null at %s", path)
	case map[string]any:
		if raw, ok := typed["value"]; ok && raw == nil {
			if _, ok := typed["reason"].(string); !ok {
				t.Fatalf("Missing envelope without reason at %s", path)
			}
			return
		}
		for k, e := range typed {
			assertNoBareNulls(t, e, path+"."+k)
		}
	case []any:
		for i, e := range typed {
			assertNoBareNulls(t, e, fmt.Sprintf("%s[%d]", path, i))
		}
	}
}

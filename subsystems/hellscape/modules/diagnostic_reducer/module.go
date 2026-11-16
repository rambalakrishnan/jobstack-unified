// Package diagnostic_reducer implements the tier-4 Hellscape deterministic
// diagnostic analysis over a pinned journal prefix.
//
// It enforces seam-mappings/hellscape-seam-mapping.md sections 10.1
// (deterministic analysis), 10.5 (RequirementAssessment), 10.6 (R1-R10 facet
// map), 10.7 (findings), 10.8 (steps, attempts, predicates), and 16.5
// (lifecycle and diagnostic corpus), plus the EK-DIAGNOSTIC, EK-ASSESSMENT,
// EK-CAPABILITY, EK-CLAIMS, EK-MANUAL, EK-TIMING-INTERPRETATION,
// EK-ATTEMPT-SCOPE, EXT-DECLARE-NOT-ASSESS, and OWD-SESSION invariants.
//
// A diagnostic is a deterministic function of its immutable manifest, named
// journal prefix ending at analysis_requested, registered referenced
// evidence inside that prefix, and pinned classifier/requirement/fix
// registries. It uses no current wall time, unrecorded network lookups, or
// mutable application rows as additional evidence.
//
// Stages (seam 10.1):
//  1. Validate configuration and fixture invariants (fixture_policy).
//  2. Establish completeness and scoped validity (journal_rules prefix).
//  3. Join actions, requests, validations, transitions, claims, exposures,
//     timings from the pinned prefix.
//  4. Evaluate authoritative postconditions.
//  5. Identify first unmet contract and downstream reachability.
//  6. Produce typed findings.
//  7. Render JSON and readable output from the same object (diagnostic_render).
//
// Capability, opportunity, and result are independent fields (EK-ASSESSMENT).
// Satisfied/violated requires a valid exposed opportunity, applicable
// controls, and supporting evidence. Native absence requires a required,
// evidenced absent native capability in the exact scope. Unexposed work is
// not_exercised; blocked or invalidly controlled work is not_exercised or
// indeterminate according to what was actually observed.
//
// Structural gates delegate to evidence_codec, journal completeness to
// journal_rules, timing semantics to clock_rules, fixture admission to
// fixture_policy, and attempt reconciliation to lifecycle_rules.
package diagnostic_reducer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"clock_rules"
	"evidence_codec"
	"fixture_policy"
	"journal_rules"
	"lifecycle_rules"
)

// ---------------------------------------------------------------------------
// Aliases and CONSUMES linkage.
// ---------------------------------------------------------------------------

// JournalEnvelope is the complete stored journal event envelope.
type JournalEnvelope = journal_rules.JournalEnvelope

// JournalPrefix is an immutable journal prefix.
type JournalPrefix = journal_rules.JournalPrefix

// EvidenceRef cites one retained journal event coordinate plus a JSON Pointer.
type EvidenceRef = journal_rules.EvidenceRef

// ClockDescriptor registers one clock lifetime.
type ClockDescriptor = journal_rules.ClockDescriptor

// TimePoint is a coordinate in a registered monotonic clock.
type TimePoint = journal_rules.TimePoint

// Missing is a typed EK Missing envelope: {"value":null,"reason":...}.
type Missing = journal_rules.MissingEnvelope

// NewMissing builds a reasoned Missing envelope with a null value.
func NewMissing(reason string) Missing {
	return journal_rules.NewMissing(reason)
}

// Compile-time CONSUMES linkage. These references fail compilation if the
// declared upstream signatures disappear.
var (
	_ = lifecycle_rules.ReconcileAttempt
	_ = journal_rules.ValidateJournal
	_ = journal_rules.ResolveEvidence
	_ = clock_rules.ValidateMeasurement
	_ = fixture_policy.ValidateFixture
	_ = evidence_codec.ValidateRecord
)

// ---------------------------------------------------------------------------
// Constants.
// ---------------------------------------------------------------------------

const (
	RecordDiagnostic = "diagnostic"
	SchemaDiagnostic = "1.0.0"

	// Requirement IDs and facets (seam 10.6).
	ReqR1  = "R1"
	ReqR2  = "R2"
	ReqR3  = "R3"
	ReqR4  = "R4"
	ReqR5  = "R5"
	ReqR6  = "R6"
	ReqR7  = "R7"
	ReqR8  = "R8"
	ReqR9  = "R9"
	ReqR10 = "R10"

	// Opportunity states.
	OppExposed   = "exposed"
	OppUnexposed = "unexposed"
	OppBlocked   = "blocked"

	// Assessment results.
	ResultSatisfied    = "satisfied"
	ResultViolated     = "violated"
	ResultNativeAbsence = "native_absence"
	ResultIndeterminate = "indeterminate"
	ResultNotExercised  = "not_exercised"

	// Capability availability.
	AvailPresent      = "present"
	AvailAbsent       = "absent"
	AvailUnknown      = "unknown"
	AvailInapplicable = "inapplicable"

	// Finding kinds (seam 10.7).
	KindNativeAbsent   = "native_capability_absent"
	KindViolation      = "requirement_violation"
	KindContradiction  = "claim_contradiction"
	KindDiscrepancy    = "measurement_discrepancy"
	KindObservation    = "observation"
	KindIndeterminate  = "indeterminate"
	KindFixtureError   = "fixture_error"
	KindHarnessError   = "harness_error"

	// Defect loci (seam 10.7).
	LocusSubject         = "subject"
	LocusExternalPlanner = "external_planner"
	LocusConnector       = "connector"
	LocusFixture         = "fixture"
	LocusEnvironment     = "environment"
	LocusPolicy          = "policy"
	LocusUnknown         = "unknown"
	LocusInapplicable    = "inapplicable"

	// Attribution (seam 10.7).
	AttrConfirmed  = "confirmed"
	AttrSupported  = "supported"
	AttrSuspected  = "suspected"
	AttrUnknown    = "unknown"

	// Manual rationale (not a seventh NullReason).
	RationaleManualFixtureValidation = "manual_fixture_validation"
)

// RequiredCapabilities is the minimum catalog for every descriptor scope
// (seam 8.3). A new subject version starts unknown for every entry.
var RequiredCapabilities = []string{
	"native_goal_task",
	"native_plan_execution",
	"native_cancel",
	"native_context_release",
	"native_artifact_retrieval",
	"native_revision",
	"native_dom_access",
	"browser_state_isolation",
	"browser_state_persistence",
	"learning_state_control",
}

// RequirementFacets maps each requirement to its primary facet under test.
// Full R1-R10 facet maps (seam 10.6) carry multiple facets per requirement;
// the reducer records one assessment per requirement with the facet that the
// pinned evidence actually exercised.
var RequirementFacets = map[string]string{
	ReqR1:  "rendering",
	ReqR2:  "browser_isolation",
	ReqR3:  "primitive_claims",
	ReqR4:  "native_cancel",
	ReqR5:  "local_access",
	ReqR6:  "capture_validity",
	ReqR7:  "input_semantics",
	ReqR8:  "native_dom_access",
	ReqR9:  "deployment",
	ReqR10: "identity_configuration",
}

// RequirementCapabilities maps each requirement to the catalog entries that
// can satisfy or absent it. Native absence requires exact-scope evidence of
// a required absent native capability.
var RequirementCapabilities = map[string][]string{
	ReqR1:  {"native_dom_access"},
	ReqR2:  {"browser_state_isolation", "browser_state_persistence", "learning_state_control"},
	ReqR3:  {"native_goal_task", "native_plan_execution"},
	ReqR4:  {"native_cancel", "native_context_release"},
	ReqR5:  {"native_goal_task"},
	ReqR6:  {"native_artifact_retrieval"},
	ReqR7:  {"native_goal_task"},
	ReqR8:  {"native_dom_access"},
	ReqR9:  {"native_revision"},
	ReqR10: {"native_revision", "native_artifact_retrieval"},
}

// RequirementOrder fixes deterministic assessment ordering.
var RequirementOrder = []string{ReqR1, ReqR2, ReqR3, ReqR4, ReqR5, ReqR6, ReqR7, ReqR8, ReqR9, ReqR10}

var validNullReasons = map[string]bool{
	"not_enabled": true, "not_applicable": true, "not_observed": true,
	"observation_lost": true, "unsupported_by_subject": true, "manual_override": true,
}

var validAvailabilities = map[string]bool{
	AvailPresent: true, AvailAbsent: true, AvailUnknown: true, AvailInapplicable: true,
}

var validOrigins = map[string]bool{
	"native": true, "composed_subject": true, "harness": true,
}

// ---------------------------------------------------------------------------
// Public types.
// ---------------------------------------------------------------------------

// AttemptContext carries the immutable attempt scope.
type AttemptContext struct {
	Kind           string `json:"kind,omitempty"`
	Context        string `json:"context,omitempty"`
	Scope          string `json:"scope,omitempty"`
	SubjectVersion string `json:"subject_version,omitempty"`
	Assistance     string `json:"assistance,omitempty"`
}

// SubjectDescriptor identifies the measured subject and version.
type SubjectDescriptor struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

// LineageLinks carries kind and lineage references.
type LineageLinks struct {
	Kind          string   `json:"kind,omitempty"`
	DerivedFrom   []string `json:"derived_from,omitempty"`
	RehearsalOf   string   `json:"rehearsal_of,omitempty"`
	PerformanceOf string   `json:"performance_of,omitempty"`
}

// Manifest is the admitted laboratory manifest projection. It converts to
// both the journal_rules wire shape (for prefix validation) and the
// fixture_policy gate shape (for fixture admission) without loss.
type Manifest struct {
	RecordType       string            `json:"record_type"`
	SchemaVersion    string            `json:"schema_version"`
	ManifestID       string            `json:"manifest_id"`
	RunID            string            `json:"run_id"`
	JournalID        string            `json:"journal_id"`
	OwnerDomain      string            `json:"owner_domain"`
	CommissionerID   string            `json:"commissioner_id,omitempty"`
	Activity         string            `json:"activity,omitempty"`
	Attempt          AttemptContext    `json:"attempt,omitempty"`
	Execution        map[string]any    `json:"execution,omitempty"`
	Task             map[string]any    `json:"task,omitempty"`
	TaskSemanticHash  string            `json:"task_semantic_hash,omitempty"`
	Environment      map[string]any    `json:"environment,omitempty"`
	Seed             any               `json:"seed,omitempty"`
	BuildPins        map[string]string `json:"build_pins,omitempty"`
	EventRegistry    map[string]string `json:"event_registry,omitempty"`
	Producers        []map[string]any  `json:"producers,omitempty"`
	Clocks           []ClockDescriptor `json:"clocks,omitempty"`
	Profile          string            `json:"-"`
	Subject          SubjectDescriptor `json:"-"`
	Lineage          LineageLinks      `json:"-"`
}

// VersionPin pins an immutable versioned artifact.
type VersionPin struct {
	ID             string `json:"id"`
	Version        string `json:"version"`
	ArtifactDigest string `json:"artifact_digest"`
}

// SubjectIdentity pins the judged automation subject scope. A descriptor
// applies to exactly one subject_id, subject_version, configured mode, and
// interface surface (EK-CAPABILITY).
type SubjectIdentity struct {
	SubjectID        string `json:"subject_id"`
	SubjectVersion   string `json:"subject_version"`
	ConfiguredMode   string `json:"configured_mode"`
	InterfaceSurface string `json:"interface_surface"`
}

// AnalysisRequest pins the diagnostic inputs. The journal prefix must end at
// the analysis_requested event that fixes these same values.
type AnalysisRequest struct {
	DiagnosticID        string `json:"diagnostic_id"`
	AnalysisRevision    int64  `json:"analysis_revision"`
	Classifier          VersionPin `json:"classifier"`
	RequirementRegistry VersionPin `json:"requirement_registry"`
	// FixRegistry is either a VersionPin or a Missing envelope. M1 fixes
	// normally use Missing(not_enabled).
	FixRegistry any `json:"fix_registry"`
	// Configuration is the effective fixture configuration bytes validated
	// through fixture_policy.
	Configuration []byte `json:"-"`
	// ManualMode selects manual fixture validation: no automation subject,
	// no connector/binding version, every R1-R10 not_exercised with the
	// manual_fixture_validation rationale.
	ManualMode bool `json:"manual_mode"`
	// Subject scopes the capability catalog. Empty for manual execution.
	Subject SubjectIdentity `json:"subject"`
	// Optional lifecycle reconciliation inputs. When Commission is non-nil,
	// DeriveDiagnostic reconciles via lifecycle_rules and records the
	// report value.
	Commission   *lifecycle_rules.AttemptCommission `json:"-"`
	ReportInputs *lifecycle_rules.ReportInputPins   `json:"-"`
	Publications []lifecycle_rules.AxisRevision     `json:"-"`
	Evaluator    *lifecycle_rules.VersionPin        `json:"-"`
}

// Scope identifies the evaluation scope of an assessment or finding.
type Scope struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

// CapabilityReference cites one catalogued capability entry.
type CapabilityReference struct {
	CapabilityID string `json:"capability_id"`
	DescriptorID string `json:"descriptor_id"`
}

// Opportunity records whether the requirement had a valid exercise chance.
type Opportunity struct {
	State     string       `json:"state"`
	Support   []EvidenceRef `json:"support"`
	Rationale string       `json:"rationale"`
}

// RequirementAssessment is one independent capability/opportunity/result record.
type RequirementAssessment struct {
	RequirementID      string                `json:"requirement_id"`
	Facet              string                `json:"facet"`
	ContractVersion    string                `json:"contract_version"`
	Scope              Scope                 `json:"scope"`
	CapabilityRefs     []CapabilityReference `json:"capability_refs"`
	Opportunity        Opportunity           `json:"opportunity"`
	Result             string                `json:"result"`
	Support            []EvidenceRef         `json:"support"`
	ContraryEvidence   []EvidenceRef         `json:"contrary_evidence"`
	FindingRefs        []string              `json:"finding_refs"`
	Rationale          string                `json:"rationale"`
}

// Finding is one evidence-backed typed finding.
type Finding struct {
	ID               string       `json:"id"`
	Kind             string       `json:"kind"`
	RequirementRefs  []string     `json:"requirement_refs"`
	Symptom          string       `json:"symptom"`
	Scope            Scope        `json:"scope"`
	CausalRole       string       `json:"causal_role"`
	TriggerFeatures  []string     `json:"trigger_features"`
	DefectLocus      string       `json:"defect_locus"`
	Attribution      string       `json:"attribution"`
	Support          []EvidenceRef `json:"support"`
	ContraryEvidence []EvidenceRef `json:"contrary_evidence"`
	Limitations      []string     `json:"limitations"`
	SuggestedFix     any          `json:"suggested_fix"`
}

// CapabilityEntry is one catalogued capability.
type CapabilityEntry struct {
	ID               string   `json:"capability_id"`
	RequirementRefs  []string `json:"requirement_refs"`
	Availability     string   `json:"availability"`
	ClaimOrigin      string   `json:"claim_origin"`
	EvidenceBasis    []string `json:"evidence_basis"`
	EvidenceRefs     []EvidenceRef `json:"evidence_refs"`
	Limitations      []string `json:"limitations"`
}

// CapabilityDescriptor describes the complete catalog for one subject scope.
type CapabilityDescriptor struct {
	DescriptorID string            `json:"descriptor_id"`
	Subject      SubjectIdentity   `json:"subject"`
	Capabilities []CapabilityEntry `json:"capabilities"`
	EvidencePrefix JournalPrefix   `json:"evidence_prefix"`
	Limitations  []string          `json:"limitations"`
}

// FeatureExposure is the per-instance configured/armed/exposed/activated chain.
type FeatureExposure struct {
	FeatureID      string       `json:"feature_id"`
	Configured     bool         `json:"configured"`
	RenderedArmed  bool         `json:"rendered_armed"`
	Exposed        bool         `json:"exposed"`
	Activated      bool         `json:"activated"`
	RequirementRef string       `json:"requirement_ref"`
	Support        []EvidenceRef `json:"support"`
	Limitations    []string     `json:"limitations"`
}

// MeasurementEvidence pairs a copied measurement with its journal support.
type MeasurementEvidence struct {
	Measurement journal_rules.Measurement `json:"measurement"`
	Support     []EvidenceRef             `json:"support"`
}

// Claim is an original claim plus its semantic comparison. Comparisons never
// overwrite the original bytes.
type Claim struct {
	ClaimID          string       `json:"claim_id"`
	Source           string       `json:"source"`
	SemanticScope    string       `json:"semantic_scope"`
	Proposition      string       `json:"proposition"`
	Comparison       string       `json:"comparison"`
	Support          []EvidenceRef `json:"support"`
	ComparisonSupport []EvidenceRef `json:"comparison_support"`
	Limitations      []string     `json:"limitations"`
}

// DiagnosticValidity carries scoped checks, completeness, and limitations.
type DiagnosticValidity struct {
	Checks       []string `json:"checks"`
	Completeness string   `json:"completeness"`
	Limitations  []string `json:"limitations"`
}

// DiagnosticDocument is the deterministic analysis output.
type DiagnosticDocument struct {
	RecordType             string                  `json:"record_type"`
	SchemaVersion          string                  `json:"schema_version"`
	DiagnosticID           string                  `json:"diagnostic_id"`
	AnalysisRevision       int64                   `json:"analysis_revision"`
	RunID                  string                  `json:"run_id"`
	ManifestHash           string                  `json:"manifest_hash"`
	InputPrefix            JournalPrefix           `json:"input_prefix"`
	AnalysisRequestRef     EvidenceRef             `json:"analysis_request_ref"`
	Classifier             VersionPin              `json:"classifier"`
	RequirementRegistry    VersionPin              `json:"requirement_registry"`
	FixRegistry            any                     `json:"fix_registry"`
	Subject                SubjectIdentity         `json:"subject"`
	ManualMode             bool                    `json:"manual_mode"`
	CapabilityCatalog      CapabilityDescriptor    `json:"capability_catalog"`
	RequirementAssessments []RequirementAssessment `json:"requirement_assessments"`
	Findings               []Finding               `json:"findings"`
	Measurements           []MeasurementEvidence   `json:"measurements"`
	FeatureExposures       []FeatureExposure       `json:"feature_exposures"`
	Claims                 []Claim                 `json:"claims"`
	Validity               DiagnosticValidity      `json:"validity"`
	// Report holds the lifecycle ReportValue when reconciliation inputs
	// were supplied, otherwise a Missing envelope.
	Report any `json:"report"`
}

// ---------------------------------------------------------------------------
// Small validators.
// ---------------------------------------------------------------------------

func validDigest(s string) bool {
	const prefix = "sha256:"
	if !strings.HasPrefix(s, prefix) {
		return false
	}
	hexPart := s[len(prefix):]
	if len(hexPart) != 64 {
		return false
	}
	for _, c := range hexPart {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func validateVersionPin(p VersionPin, field string) error {
	if strings.TrimSpace(p.ID) == "" {
		return fmt.Errorf("diagnostic_reducer: %s.id must be nonempty", field)
	}
	if strings.TrimSpace(p.Version) == "" {
		return fmt.Errorf("diagnostic_reducer: %s.version must be nonempty", field)
	}
	if !validDigest(p.ArtifactDigest) {
		return fmt.Errorf("diagnostic_reducer: %s.artifact_digest %q must match sha256:<64 lowercase hex>", field, p.ArtifactDigest)
	}
	return nil
}

func asMissing(v any) (Missing, bool) {
	switch m := v.(type) {
	case Missing:
		if m.Value == nil && validNullReasons[m.Reason] {
			return m, true
		}
	case *Missing:
		if m != nil && m.Value == nil && validNullReasons[m.Reason] {
			return *m, true
		}
	case map[string]any:
		raw, hasValue := m["value"]
		if !hasValue || raw != nil {
			return Missing{}, false
		}
		r, _ := m["reason"].(string)
		if !validNullReasons[r] {
			return Missing{}, false
		}
		d, _ := m["detail"].(string)
		return Missing{Value: nil, Reason: r, Detail: d}, true
	}
	return Missing{}, false
}

func validateFixRegistry(v any) (any, error) {
	if v == nil {
		return nil, fmt.Errorf("diagnostic_reducer: fix_registry is an in-band null: use a VersionPin or Missing")
	}
	if m, ok := asMissing(v); ok {
		return m, nil
	}
	switch p := v.(type) {
	case VersionPin:
		if err := validateVersionPin(p, "fix_registry"); err != nil {
			return nil, err
		}
		return p, nil
	case map[string]any:
		id, _ := p["id"].(string)
		ver, _ := p["version"].(string)
		digest, _ := p["artifact_digest"].(string)
		pin := VersionPin{ID: id, Version: ver, ArtifactDigest: digest}
		if err := validateVersionPin(pin, "fix_registry"); err != nil {
			return nil, err
		}
		return pin, nil
	default:
		return nil, fmt.Errorf("diagnostic_reducer: fix_registry must be a VersionPin or Missing, got %T", v)
	}
}

func fixRegistryEqual(a, b any) bool {
	am, aMiss := asMissing(a)
	bm, bMiss := asMissing(b)
	if aMiss || bMiss {
		if aMiss != bMiss {
			return false
		}
		return am.Reason == bm.Reason && am.Detail == bm.Detail
	}
	ap, aok := normalizePin(a)
	bp, bok := normalizePin(b)
	if !aok || !bok {
		return false
	}
	return ap == bp
}

func normalizePin(v any) (VersionPin, bool) {
	switch p := v.(type) {
	case VersionPin:
		return p, true
	case map[string]any:
		id, _ := p["id"].(string)
		ver, _ := p["version"].(string)
		digest, _ := p["artifact_digest"].(string)
		if id == "" || ver == "" || digest == "" {
			return VersionPin{}, false
		}
		return VersionPin{ID: id, Version: ver, ArtifactDigest: digest}, true
	}
	return VersionPin{}, false
}

// ---------------------------------------------------------------------------
// Manifest conversions.
// ---------------------------------------------------------------------------

func (m Manifest) toJournalManifest() journal_rules.Manifest {
	clocks := make([]journal_rules.ClockDescriptor, 0, len(m.Clocks))
	clocks = append(clocks, m.Clocks...)
	return journal_rules.Manifest{
		RecordType:  m.RecordType,
		SchemaVersion: m.SchemaVersion,
		ManifestID:  m.ManifestID,
		RunID:       m.RunID,
		JournalID:   m.JournalID,
		OwnerDomain: m.OwnerDomain,
		Clocks:      clocks,
	}
}

func (m Manifest) toFixtureManifest() fixture_policy.Manifest {
	clocks := make([]map[string]any, 0, len(m.Clocks))
	for _, c := range m.Clocks {
		clocks = append(clocks, map[string]any{
			"clock_id": c.ClockID, "boot_id": c.BootID, "origin": c.Origin,
			"source_id": c.SourceID, "basis": c.Basis, "unit": c.Unit,
		})
	}
	return fixture_policy.Manifest{
		RecordType:      m.RecordType,
		SchemaVersion:   m.SchemaVersion,
		ManifestID:      m.ManifestID,
		RunID:           m.RunID,
		JournalID:       m.JournalID,
		OwnerDomain:     m.OwnerDomain,
		CommissionerID:  m.CommissionerID,
		Activity:        m.Activity,
		Attempt: fixture_policy.AttemptContext{
			Kind: m.Attempt.Kind, Context: m.Attempt.Context, Scope: m.Attempt.Scope,
			SubjectVersion: m.Attempt.SubjectVersion, Assistance: m.Attempt.Assistance,
		},
		Execution:       m.Execution,
		Task:            m.Task,
		TaskSemanticHash: m.TaskSemanticHash,
		Environment:     m.Environment,
		Seed:            m.Seed,
		BuildPins:       m.BuildPins,
		EventRegistry:   m.EventRegistry,
		Producers:       m.Producers,
		Clocks:          clocks,
		Profile:         m.Profile,
		Subject: fixture_policy.SubjectDescriptor{
			Name: m.Subject.Name, Version: m.Subject.Version,
		},
		Lineage: fixture_policy.LineageLinks{
			Kind: m.Lineage.Kind, DerivedFrom: append([]string{}, m.Lineage.DerivedFrom...),
			RehearsalOf: m.Lineage.RehearsalOf, PerformanceOf: m.Lineage.PerformanceOf,
		},
	}
}

func computeManifestDigest(m journal_rules.Manifest) (string, error) {
	raw, err := json.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("diagnostic_reducer: cannot marshal manifest: %v", err)
	}
	canonical, err := evidence_codec.CanonicalJSON(raw, "application/json")
	if err != nil {
		return "", err
	}
	return string(evidence_codec.HashBytes(canonical)), nil
}

// ---------------------------------------------------------------------------
// clock_rules translation.
// ---------------------------------------------------------------------------

func asFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case int32:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		if err != nil {
			return 0, false
		}
		return f, true
	}
	return 0, false
}

func asTimePointValue(v any) (journal_rules.TimePoint, bool) {
	switch t := v.(type) {
	case journal_rules.TimePoint:
		return t, true
	case *journal_rules.TimePoint:
		if t != nil {
			return *t, true
		}
	case map[string]any:
		clockID, _ := t["clock_id"].(string)
		bootID, _ := t["boot_id"].(string)
		origin, _ := t["origin"].(string)
		if clockID == "" || bootID == "" || origin == "" {
			return journal_rules.TimePoint{}, false
		}
		off, ok := asFloat(t["monotonic_offset_ms"])
		if !ok {
			return journal_rules.TimePoint{}, false
		}
		utc, hasUTC := t["utc_annotation"]
		if !hasUTC {
			return journal_rules.TimePoint{}, false
		}
		return journal_rules.TimePoint{
			ClockID: clockID, BootID: bootID, Origin: origin,
			MonotonicOffsetMs: off, UTCAnnotation: utc,
		}, true
	}
	return journal_rules.TimePoint{}, false
}

func toClockRulesClock(cd journal_rules.ClockDescriptor) clock_rules.ClockDescriptor {
	return clock_rules.ClockDescriptor{
		ClockID: cd.ClockID, BootID: cd.BootID, Origin: cd.Origin,
		SourceID: cd.SourceID, Basis: cd.Basis, Unit: cd.Unit,
	}
}

func toClockRulesMissing(m Missing) clock_rules.Missing {
	return clock_rules.Missing{Reason: m.Reason, Detail: m.Detail}
}

func convertUTCAnnotation(v any, field string) (any, error) {
	if v == nil {
		return nil, fmt.Errorf("diagnostic_reducer: %s is an in-band null", field)
	}
	if m, ok := asMissing(v); ok {
		return toClockRulesMissing(m), nil
	}
	if s, ok := v.(string); ok {
		if _, err := time.Parse(time.RFC3339, s); err != nil {
			return nil, fmt.Errorf("diagnostic_reducer: %s invalid date-time %q", field, s)
		}
		return s, nil
	}
	return nil, fmt.Errorf("diagnostic_reducer: %s must be date-time or Missing, got %T", field, v)
}

func convertEndpoint(v any, field string) (any, error) {
	if v == nil {
		return nil, fmt.Errorf("diagnostic_reducer: %s is an in-band null", field)
	}
	if m, ok := asMissing(v); ok {
		return toClockRulesMissing(m), nil
	}
	if tp, ok := asTimePointValue(v); ok {
		utc, err := convertUTCAnnotation(tp.UTCAnnotation, field+".utc_annotation")
		if err != nil {
			return nil, err
		}
		return clock_rules.TimePoint{
			ClockID: tp.ClockID, BootID: tp.BootID, Origin: tp.Origin,
			MonotonicOffsetMs: tp.MonotonicOffsetMs, UTCAnnotation: utc,
		}, nil
	}
	return nil, fmt.Errorf("diagnostic_reducer: %s must be TimePoint or Missing, got %T", field, v)
}

func convertNumberOrMissing(v any, field string) (any, error) {
	if v == nil {
		return nil, fmt.Errorf("diagnostic_reducer: %s is an in-band null", field)
	}
	if m, ok := asMissing(v); ok {
		return toClockRulesMissing(m), nil
	}
	if n, ok := asFloat(v); ok {
		if math.IsNaN(n) || math.IsInf(n, 0) {
			return nil, fmt.Errorf("diagnostic_reducer: %s must be finite", field)
		}
		return n, nil
	}
	return nil, fmt.Errorf("diagnostic_reducer: %s must be numeric or Missing, got %T", field, v)
}

func convertStringOrMissing(v any, field string) (any, error) {
	if v == nil {
		return nil, fmt.Errorf("diagnostic_reducer: %s is an in-band null", field)
	}
	if m, ok := asMissing(v); ok {
		return toClockRulesMissing(m), nil
	}
	if s, ok := v.(string); ok {
		if strings.TrimSpace(s) == "" {
			return nil, fmt.Errorf("diagnostic_reducer: %s identifier must be nonempty", field)
		}
		return s, nil
	}
	return nil, fmt.Errorf("diagnostic_reducer: %s must be identifier or Missing, got %T", field, v)
}

func convertEstimate(e journal_rules.Estimate, field string) (clock_rules.Estimate, error) {
	switch e.Kind {
	case "exact":
		if e.Value == nil {
			return clock_rules.Estimate{}, fmt.Errorf("diagnostic_reducer: %s.value is an in-band null", field)
		}
		if _, ok := asMissing(e.Value); ok {
			return clock_rules.Estimate{}, fmt.Errorf("diagnostic_reducer: %s exact value must be numeric", field)
		}
		n, ok := asFloat(e.Value)
		if !ok {
			return clock_rules.Estimate{}, fmt.Errorf("diagnostic_reducer: %s exact value must be numeric, got %T", field, e.Value)
		}
		if e.LowerBound != nil || e.UpperBound != nil {
			return clock_rules.Estimate{}, fmt.Errorf("diagnostic_reducer: %s exact must not carry bounds", field)
		}
		return clock_rules.Estimate{Kind: "exact", Value: n}, nil
	case "bounded":
		if e.Value != nil {
			return clock_rules.Estimate{}, fmt.Errorf("diagnostic_reducer: %s bounded must not carry exact value", field)
		}
		if e.LowerBound == nil || e.UpperBound == nil {
			return clock_rules.Estimate{}, fmt.Errorf("diagnostic_reducer: %s bounded bounds must each be numeric or Missing", field)
		}
		lo, err := convertNumberOrMissing(e.LowerBound, field+".lower_bound")
		if err != nil {
			return clock_rules.Estimate{}, err
		}
		hi, err := convertNumberOrMissing(e.UpperBound, field+".upper_bound")
		if err != nil {
			return clock_rules.Estimate{}, err
		}
		return clock_rules.Estimate{Kind: "bounded", LowerBound: lo, UpperBound: hi}, nil
	case "unavailable":
		if e.Value == nil {
			return clock_rules.Estimate{}, fmt.Errorf("diagnostic_reducer: %s unavailable value is an in-band null", field)
		}
		m, ok := asMissing(e.Value)
		if !ok {
			return clock_rules.Estimate{}, fmt.Errorf("diagnostic_reducer: %s unavailable value must be Missing, got %T", field, e.Value)
		}
		if e.LowerBound != nil || e.UpperBound != nil {
			return clock_rules.Estimate{}, fmt.Errorf("diagnostic_reducer: %s unavailable must not carry bounds", field)
		}
		return clock_rules.Estimate{Kind: "unavailable", Value: toClockRulesMissing(m)}, nil
	}
	return clock_rules.Estimate{}, fmt.Errorf("diagnostic_reducer: %s estimate kind %q invalid", field, e.Kind)
}

func toClockRulesMeasurement(m journal_rules.Measurement) (clock_rules.Measurement, error) {
	base := fmt.Sprintf("measurement %q", m.MeasurementID)
	start, err := convertEndpoint(m.Start, base+".start")
	if err != nil {
		return clock_rules.Measurement{}, err
	}
	end, err := convertEndpoint(m.End, base+".end")
	if err != nil {
		return clock_rules.Measurement{}, err
	}
	est, err := convertEstimate(m.Estimate, base+".estimate")
	if err != nil {
		return clock_rules.Measurement{}, err
	}
	res, err := convertNumberOrMissing(m.Resolution, base+".resolution")
	if err != nil {
		return clock_rules.Measurement{}, err
	}
	cg, err := convertStringOrMissing(m.ComparabilityGroup, base+".comparability_group")
	if err != nil {
		return clock_rules.Measurement{}, err
	}
	return clock_rules.Measurement{
		MeasurementID: m.MeasurementID, Name: m.Name,
		Scope: clock_rules.Scope{Kind: m.Scope.Kind, ID: m.Scope.ID},
		Quantity: m.Quantity, Unit: m.Unit, Origin: m.Origin,
		ClockID: m.ClockID, BootID: m.BootID, Method: m.Method,
		Start: start, End: end, Estimate: est,
		Resolution: res, Censoring: m.Censoring,
		ComparabilityGroup: cg, AggregateSource: m.AggregateSource,
	}, nil
}

// ---------------------------------------------------------------------------
// Journal data join.
// ---------------------------------------------------------------------------

type capabilityEvidence struct {
	CapabilityID   string
	Availability   string
	ClaimOrigin    string
	SubjectVersion string
	Ref            EvidenceRef
}

type requirementOutcome struct {
	RequirementID          string
	Facet                  string
	ObservedOutcome        string
	ControlsValid          bool
	HasSupportingEvidence  bool
	Ref                    EvidenceRef
}

type isolationProbe struct {
	WriteControlValid bool
	MarkerObserved    bool
	Ref               EvidenceRef
}

type missingDependency struct {
	Dependency           string
	AffectedRequirements []string
	Ref                  EvidenceRef
}

type adapterClaim struct {
	CapabilityID            string
	AdapterClaimsSupported  bool
	NativeSupported         bool
	Ref                     EvidenceRef
}

type fixtureDefect struct {
	AffectedRequirement string
	AffectedFacet       string
	Detail              string
	Ref                 EvidenceRef
}

type subjectClaimNote struct {
	ClaimID string
	Source  string
	Scope   string
	Prop    string
	Ref     EvidenceRef
}

type joinedEvidence struct {
	capabilities  map[string]capabilityEvidence
	outcomes      map[string]requirementOutcome
	isolation     []isolationProbe
	missingDeps   []missingDependency
	adapterClaims []adapterClaim
	exposures     map[string]FeatureExposure
	fixtureDefects map[string]fixtureDefect
	subjectClaims []subjectClaimNote
	measurements  []MeasurementEvidence
}

func refFor(ev JournalEnvelope, pointer string) EvidenceRef {
	return EvidenceRef{
		JournalID: ev.JournalID, Sequence: ev.Sequence,
		EventID: ev.EventID, EventHash: ev.EventHash, Pointer: pointer,
	}
}

func asBool(v any) (bool, bool) {
	b, ok := v.(bool)
	return b, ok
}

func asString(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

func asStringSlice(v any) ([]string, bool) {
	arr, ok := v.([]any)
	if !ok {
		if sarr, ok := v.([]string); ok {
			return sarr, true
		}
		return nil, false
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		s, ok := e.(string)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

func asMap(v any) (map[string]any, bool) {
	switch m := v.(type) {
	case map[string]any:
		return m, true
	case map[string]string:
		out := make(map[string]any, len(m))
		for k, val := range m {
			out[k] = val
		}
		return out, true
	}
	return nil, false
}

func joinEvidence(events []JournalEnvelope) (*joinedEvidence, error) {
	j := &joinedEvidence{
		capabilities:   map[string]capabilityEvidence{},
		outcomes:       map[string]requirementOutcome{},
		exposures:      map[string]FeatureExposure{},
		fixtureDefects: map[string]fixtureDefect{},
	}
	for _, ev := range events {
		if ev.Sequence == 1 && ev.EventKind == "manifest_admitted" {
			continue
		}
		if ev.EventKind == "analysis_requested" {
			continue
		}
		data := ev.Payload.Data
		if data == nil {
			continue
		}
		baseRef := refFor(ev, "")
		// capability_evidence
		if raw, ok := data["capability_evidence"]; ok {
			m, ok := asMap(raw)
			if !ok {
				return nil, fmt.Errorf("diagnostic_reducer: sequence %d capability_evidence must be an object", ev.Sequence)
			}
			id, _ := asString(m["capability_id"])
			avail, _ := asString(m["availability"])
			origin, _ := asString(m["claim_origin"])
			if strings.TrimSpace(id) == "" || !validAvailabilities[avail] || !validOrigins[origin] {
				return nil, fmt.Errorf("diagnostic_reducer: sequence %d capability_evidence has invalid id/availability/origin", ev.Sequence)
			}
			sv, _ := asString(m["subject_version"])
			j.capabilities[id] = capabilityEvidence{
				CapabilityID: id, Availability: avail, ClaimOrigin: origin,
				SubjectVersion: sv, Ref: refFor(ev, "/payload/data/capability_evidence"),
			}
			_ = baseRef
		}
		// requirement_outcome
		if raw, ok := data["requirement_outcome"]; ok {
			m, ok := asMap(raw)
			if !ok {
				return nil, fmt.Errorf("diagnostic_reducer: sequence %d requirement_outcome must be an object", ev.Sequence)
			}
			rid, _ := asString(m["requirement_id"])
			if _, known := RequirementFacets[rid]; !known {
				return nil, fmt.Errorf("diagnostic_reducer: sequence %d requirement_outcome names unknown requirement %q", ev.Sequence, rid)
			}
			facet, _ := asString(m["facet"])
			outcome, _ := asString(m["observed_outcome"])
			if outcome != ResultSatisfied && outcome != ResultViolated {
				return nil, fmt.Errorf("diagnostic_reducer: sequence %d requirement_outcome observed_outcome must be satisfied or violated", ev.Sequence)
			}
			cv, _ := asBool(m["controls_valid"])
			hs, _ := asBool(m["has_supporting_evidence"])
			// Presence check: both keys must exist to distinguish false from missing.
			if _, has := m["controls_valid"]; !has {
				return nil, fmt.Errorf("diagnostic_reducer: sequence %d requirement_outcome must declare controls_valid", ev.Sequence)
			}
			if _, has := m["has_supporting_evidence"]; !has {
				return nil, fmt.Errorf("diagnostic_reducer: sequence %d requirement_outcome must declare has_supporting_evidence", ev.Sequence)
			}
			if strings.TrimSpace(facet) == "" {
				facet = RequirementFacets[rid]
			}
			j.outcomes[rid] = requirementOutcome{
				RequirementID: rid, Facet: facet, ObservedOutcome: outcome,
				ControlsValid: cv, HasSupportingEvidence: hs,
				Ref: refFor(ev, "/payload/data/requirement_outcome"),
			}
		}
		// isolation_probe
		if raw, ok := data["isolation_probe"]; ok {
			m, ok := asMap(raw)
			if !ok {
				return nil, fmt.Errorf("diagnostic_reducer: sequence %d isolation_probe must be an object", ev.Sequence)
			}
			wc, ok1 := asBool(m["write_control_valid"])
			mo, ok2 := asBool(m["marker_observed"])
			if !ok1 || !ok2 {
				return nil, fmt.Errorf("diagnostic_reducer: sequence %d isolation_probe must declare write_control_valid and marker_observed booleans", ev.Sequence)
			}
			j.isolation = append(j.isolation, isolationProbe{
				WriteControlValid: wc, MarkerObserved: mo,
				Ref: refFor(ev, "/payload/data/isolation_probe"),
			})
		}
		// missing_dependency
		if raw, ok := data["missing_dependency"]; ok {
			m, ok := asMap(raw)
			if !ok {
				return nil, fmt.Errorf("diagnostic_reducer: sequence %d missing_dependency must be an object", ev.Sequence)
			}
			dep, _ := asString(m["dependency"])
			if strings.TrimSpace(dep) == "" {
				return nil, fmt.Errorf("diagnostic_reducer: sequence %d missing_dependency.dependency must be nonempty", ev.Sequence)
			}
			var affected []string
			if arr, has := m["affected_requirements"]; has {
				a, ok := asStringSlice(arr)
				if !ok {
					return nil, fmt.Errorf("diagnostic_reducer: sequence %d missing_dependency.affected_requirements must be a string array", ev.Sequence)
				}
				affected = a
			}
			for _, r := range affected {
				if _, known := RequirementFacets[r]; !known {
					return nil, fmt.Errorf("diagnostic_reducer: sequence %d missing_dependency names unknown requirement %q", ev.Sequence, r)
				}
			}
			j.missingDeps = append(j.missingDeps, missingDependency{
				Dependency: dep, AffectedRequirements: affected,
				Ref: refFor(ev, "/payload/data/missing_dependency"),
			})
		}
		// adapter_claim
		if raw, ok := data["adapter_claim"]; ok {
			m, ok := asMap(raw)
			if !ok {
				return nil, fmt.Errorf("diagnostic_reducer: sequence %d adapter_claim must be an object", ev.Sequence)
			}
			cid, _ := asString(m["capability_id"])
			if strings.TrimSpace(cid) == "" {
				return nil, fmt.Errorf("diagnostic_reducer: sequence %d adapter_claim.capability_id must be nonempty", ev.Sequence)
			}
			ac, ok1 := asBool(m["adapter_claims_supported"])
			ns, ok2 := asBool(m["native_supported"])
			if !ok1 || !ok2 {
				return nil, fmt.Errorf("diagnostic_reducer: sequence %d adapter_claim must declare adapter_claims_supported and native_supported booleans", ev.Sequence)
			}
			j.adapterClaims = append(j.adapterClaims, adapterClaim{
				CapabilityID: cid, AdapterClaimsSupported: ac, NativeSupported: ns,
				Ref: refFor(ev, "/payload/data/adapter_claim"),
			})
		}
		// feature_exposure
		if raw, ok := data["feature_exposure"]; ok {
			m, ok := asMap(raw)
			if !ok {
				return nil, fmt.Errorf("diagnostic_reducer: sequence %d feature_exposure must be an object", ev.Sequence)
			}
			fid, _ := asString(m["feature_id"])
			if strings.TrimSpace(fid) == "" {
				return nil, fmt.Errorf("diagnostic_reducer: sequence %d feature_exposure.feature_id must be nonempty", ev.Sequence)
			}
			cfg, ok1 := asBool(m["configured"])
			ra, ok2 := asBool(m["rendered_armed"])
			exp, ok3 := asBool(m["exposed"])
			act, ok4 := asBool(m["activated"])
			if !ok1 || !ok2 || !ok3 || !ok4 {
				return nil, fmt.Errorf("diagnostic_reducer: sequence %d feature_exposure must declare configured/rendered_armed/exposed/activated booleans", ev.Sequence)
			}
			rr, _ := asString(m["requirement_ref"])
			if rr != "" {
				if _, known := RequirementFacets[rr]; !known {
					return nil, fmt.Errorf("diagnostic_reducer: sequence %d feature_exposure names unknown requirement %q", ev.Sequence, rr)
				}
			}
			fe := FeatureExposure{
				FeatureID: fid, Configured: cfg, RenderedArmed: ra,
				Exposed: exp, Activated: act, RequirementRef: rr,
				Support: []EvidenceRef{refFor(ev, "/payload/data/feature_exposure")},
				Limitations: []string{},
			}
			// Chain validation: activated implies exposed; exposed implies
			// rendered/armed and configured. Inconsistent observations are
			// preserved with an explicit limitation, never silently repaired.
			if act && !exp {
				fe.Limitations = append(fe.Limitations, "activated without exposed: inconsistent exposure chain preserved as observed")
			}
			if exp && (!ra || !cfg) {
				fe.Limitations = append(fe.Limitations, "exposed without rendered_armed and configured: inconsistent exposure chain preserved as observed")
			}
			j.exposures[fid] = fe
		}
		// fixture_defect
		if raw, ok := data["fixture_defect"]; ok {
			m, ok := asMap(raw)
			if !ok {
				return nil, fmt.Errorf("diagnostic_reducer: sequence %d fixture_defect must be an object", ev.Sequence)
			}
			ar, _ := asString(m["affected_requirement"])
			if _, known := RequirementFacets[ar]; !known {
				return nil, fmt.Errorf("diagnostic_reducer: sequence %d fixture_defect names unknown requirement %q", ev.Sequence, ar)
			}
			af, _ := asString(m["affected_facet"])
			detail, _ := asString(m["detail"])
			j.fixtureDefects[ar] = fixtureDefect{
				AffectedRequirement: ar, AffectedFacet: af, Detail: detail,
				Ref: refFor(ev, "/payload/data/fixture_defect"),
			}
		}
		// subject_claim
		if raw, ok := data["subject_claim"]; ok {
			m, ok := asMap(raw)
			if !ok {
				return nil, fmt.Errorf("diagnostic_reducer: sequence %d subject_claim must be an object", ev.Sequence)
			}
			cid, _ := asString(m["claim_id"])
			if strings.TrimSpace(cid) == "" {
				cid = fmt.Sprintf("claim-seq-%d", ev.Sequence)
			}
			src, _ := asString(m["source"])
			if src == "" {
				src = "subject"
			}
			scope, _ := asString(m["scope"])
			if scope == "" {
				scope = "execution"
			}
			prop, _ := asString(m["proposition"])
			j.subjectClaims = append(j.subjectClaims, subjectClaimNote{
				ClaimID: cid, Source: src, Scope: scope, Prop: prop,
				Ref: refFor(ev, "/payload/data/subject_claim"),
			})
		}
		// Measurements are copied verbatim after clock validation.
		for mi, meas := range ev.Payload.Measurements {
			j.measurements = append(j.measurements, MeasurementEvidence{
				Measurement: meas,
				Support:     []EvidenceRef{refFor(ev, fmt.Sprintf("/payload/measurements/%d", mi))},
			})
		}
	}
	sort.Slice(j.measurements, func(i, k int) bool {
		return j.measurements[i].Measurement.MeasurementID < j.measurements[k].Measurement.MeasurementID
	})
	sort.Slice(j.subjectClaims, func(i, k int) bool {
		return j.subjectClaims[i].ClaimID < j.subjectClaims[k].ClaimID
	})
	return j, nil
}

// ---------------------------------------------------------------------------
// Analysis request validation.
// ---------------------------------------------------------------------------

func asInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case int:
		return int64(n), true
	case int32:
		return int64(n), true
	case float64:
		if n == math.Trunc(n) {
			return int64(n), true
		}
	case json.Number:
		i, err := n.Int64()
		if err == nil {
			return i, true
		}
	}
	return 0, false
}

func validateAnalysisRequest(r AnalysisRequest) error {
	if strings.TrimSpace(r.DiagnosticID) == "" {
		return fmt.Errorf("diagnostic_reducer: diagnostic_id must be nonempty")
	}
	if r.AnalysisRevision < 1 {
		return fmt.Errorf("diagnostic_reducer: analysis_revision starts at 1")
	}
	if err := validateVersionPin(r.Classifier, "classifier"); err != nil {
		return err
	}
	if err := validateVersionPin(r.RequirementRegistry, "requirement_registry"); err != nil {
		return err
	}
	if _, err := validateFixRegistry(r.FixRegistry); err != nil {
		return err
	}
	if len(bytes.TrimSpace(r.Configuration)) == 0 {
		return fmt.Errorf("diagnostic_reducer: configuration must be nonempty effective fixture configuration")
	}
	if !r.ManualMode {
		if strings.TrimSpace(r.Subject.SubjectID) == "" ||
			strings.TrimSpace(r.Subject.SubjectVersion) == "" ||
			strings.TrimSpace(r.Subject.ConfiguredMode) == "" ||
			strings.TrimSpace(r.Subject.InterfaceSurface) == "" {
			return fmt.Errorf("diagnostic_reducer: non-manual analysis requires complete subject scope (subject_id, subject_version, configured_mode, interface_surface)")
		}
	}
	if (r.Commission == nil) != (r.ReportInputs == nil) || (r.Commission == nil) != (r.Evaluator == nil) {
		return fmt.Errorf("diagnostic_reducer: lifecycle reconciliation inputs (commission, report_inputs, evaluator) must be supplied together or omitted together")
	}
	return nil
}

func parsePinnedRequestData(data map[string]any, field string) (VersionPin, error) {
	raw, ok := data[field]
	if !ok {
		return VersionPin{}, fmt.Errorf("diagnostic_reducer: analysis_requested data must pin %q", field)
	}
	m, ok := asMap(raw)
	if !ok {
		return VersionPin{}, fmt.Errorf("diagnostic_reducer: analysis_requested %s must be an object", field)
	}
	id, _ := asString(m["id"])
	ver, _ := asString(m["version"])
	digest, _ := asString(m["artifact_digest"])
	pin := VersionPin{ID: id, Version: ver, ArtifactDigest: digest}
	if err := validateVersionPin(pin, "analysis_requested."+field); err != nil {
		return VersionPin{}, err
	}
	return pin, nil
}

// ---------------------------------------------------------------------------
// DeriveDiagnostic.
// ---------------------------------------------------------------------------

// DeriveDiagnostic deterministically derives a diagnostic document from the
// immutable manifest, the named journal prefix ending at analysis_requested,
// the retained journal events, and the pinned analysis request.
//
// Evidence beyond the pinned prefix is ignored. No current time, mutable
// row, network lookup, unjournaled native response, or operator recollection
// is consulted.
func DeriveDiagnostic(manifest Manifest, prefix JournalPrefix, events []JournalEnvelope, request AnalysisRequest) (DiagnosticDocument, error) {
	empty := DiagnosticDocument{}
	if err := validateAnalysisRequest(request); err != nil {
		return empty, err
	}
	if strings.TrimSpace(manifest.RecordType) == "" {
		manifest.RecordType = "manifest"
	}
	if strings.TrimSpace(manifest.SchemaVersion) == "" {
		manifest.SchemaVersion = "1.0.0"
	}
	// Prefix sanity before slicing.
	if strings.TrimSpace(prefix.JournalID) == "" || prefix.LastSequence < 1 || !validDigest(prefix.HeadHash) {
		return empty, fmt.Errorf("diagnostic_reducer: prefix must name journal_id, positive last_sequence, and valid head_hash")
	}
	if prefix.JournalID != manifest.JournalID {
		return empty, fmt.Errorf("diagnostic_reducer: prefix journal %q does not match manifest journal %q", prefix.JournalID, manifest.JournalID)
	}
	if int64(len(events)) < prefix.LastSequence {
		return empty, fmt.Errorf("diagnostic_reducer: journal holds %d events but prefix ends at %d: evidence beyond the diagnostic prefix is not silently fetched", len(events), prefix.LastSequence)
	}
	// Only the pinned prefix is evidence. Later events are ignored so that
	// late arrivals create a new revision instead of mutating this one.
	inPrefix := make([]JournalEnvelope, prefix.LastSequence)
	copy(inPrefix, events[:prefix.LastSequence])

	// Stage 1: fixture admission.
	fman := manifest.toFixtureManifest()
	if err := fixture_policy.ValidateFixture(fman, request.Configuration); err != nil {
		return empty, fmt.Errorf("diagnostic_reducer: fixture admission: %v", err)
	}

	// Structural gate on the manifest record itself.
	jman := manifest.toJournalManifest()
	manifestRaw, err := json.Marshal(jman)
	if err != nil {
		return empty, fmt.Errorf("diagnostic_reducer: cannot marshal manifest: %v", err)
	}
	if err := evidence_codec.ValidateRecord(jman.SchemaVersion, "manifest", manifestRaw); err != nil {
		return empty, fmt.Errorf("diagnostic_reducer: manifest structural gate: %v", err)
	}
	manifestDigest, err := computeManifestDigest(jman)
	if err != nil {
		return empty, err
	}

	// Stage 2: journal completeness and scoped validity.
	validated, err := journal_rules.ValidateJournal(jman, inPrefix)
	if err != nil {
		return empty, fmt.Errorf("diagnostic_reducer: journal validation: %v", err)
	}
	if validated.JournalID != prefix.JournalID || validated.LastSequence != prefix.LastSequence || validated.HeadHash != prefix.HeadHash {
		return empty, fmt.Errorf("diagnostic_reducer: supplied prefix (%s/%d/%s) does not match validated prefix (%s/%d/%s): the diagnostic cites its exact input revision",
			prefix.JournalID, prefix.LastSequence, prefix.HeadHash, validated.JournalID, validated.LastSequence, validated.HeadHash)
	}
	last := inPrefix[len(inPrefix)-1]
	if last.EventKind != "analysis_requested" {
		return empty, fmt.Errorf("diagnostic_reducer: prefix must end at analysis_requested, sequence %d carries %q", last.Sequence, last.EventKind)
	}
	// The request-ending event fixes diagnostic ID, revision, classifier,
	// and registries.
	reqData := last.Payload.Data
	if reqData == nil {
		return empty, fmt.Errorf("diagnostic_reducer: analysis_requested data must pin the diagnostic inputs")
	}
	pinnedID, _ := asString(reqData["diagnostic_id"])
	pinnedRev, revOK := asInt64(reqData["analysis_revision"])
	pinnedClassifier, err := parsePinnedRequestData(reqData, "classifier")
	if err != nil {
		return empty, err
	}
	pinnedRegistry, err := parsePinnedRequestData(reqData, "requirement_registry")
	if err != nil {
		return empty, err
	}
	var pinnedFix any
	if raw, has := reqData["fix_registry"]; has {
		pinnedFix, err = validateFixRegistry(raw)
		if err != nil {
			return empty, fmt.Errorf("diagnostic_reducer: analysis_requested fix_registry: %v", err)
		}
	} else {
		pinnedFix = NewMissing("not_enabled")
	}
	if pinnedID != request.DiagnosticID {
		return empty, fmt.Errorf("diagnostic_reducer: analysis_requested pins diagnostic %q, request asks %q", pinnedID, request.DiagnosticID)
	}
	if !revOK || pinnedRev != request.AnalysisRevision {
		return empty, fmt.Errorf("diagnostic_reducer: analysis_requested pins revision %v, request asks %d", reqData["analysis_revision"], request.AnalysisRevision)
	}
	if pinnedClassifier != request.Classifier {
		return empty, fmt.Errorf("diagnostic_reducer: analysis_requested classifier %+v does not match request %+v", pinnedClassifier, request.Classifier)
	}
	if pinnedRegistry != request.RequirementRegistry {
		return empty, fmt.Errorf("diagnostic_reducer: analysis_requested requirement_registry %+v does not match request %+v", pinnedRegistry, request.RequirementRegistry)
	}
	requestFix, err := validateFixRegistry(request.FixRegistry)
	if err != nil {
		return empty, err
	}
	if !fixRegistryEqual(pinnedFix, requestFix) {
		return empty, fmt.Errorf("diagnostic_reducer: analysis_requested fix_registry does not match request fix_registry")
	}
	analysisRef := refFor(last, "")
	if _, err := journal_rules.ResolveEvidence(prefix, inPrefix, analysisRef); err != nil {
		return empty, fmt.Errorf("diagnostic_reducer: analysis request reference does not resolve: %v", err)
	}

	// Collect clocks for measurement validation: manifest registrations
	// plus clock_registered events inside the prefix.
	clockSet := map[string]clock_rules.ClockDescriptor{}
	for _, c := range manifest.Clocks {
		key := c.ClockID + "\x00" + c.BootID + "\x00" + c.Origin
		clockSet[key] = toClockRulesClock(c)
	}
	for _, ev := range inPrefix {
		if ev.EventKind != "clock_registered" {
			continue
		}
		m := ev.Payload.Data
		cid, _ := asString(m["clock_id"])
		bid, _ := asString(m["boot_id"])
		origin, _ := asString(m["origin"])
		sid, _ := asString(m["source_id"])
		basis, _ := asString(m["basis"])
		unit, _ := asString(m["unit"])
		if cid == "" || bid == "" || origin == "" {
			continue
		}
		key := cid + "\x00" + bid + "\x00" + origin
		clockSet[key] = clock_rules.ClockDescriptor{
			ClockID: cid, BootID: bid, Origin: origin,
			SourceID: sid, Basis: basis, Unit: unit,
		}
	}
	clocks := make([]clock_rules.ClockDescriptor, 0, len(clockSet))
	for _, c := range clockSet {
		clocks = append(clocks, c)
	}
	sort.Slice(clocks, func(i, k int) bool {
		if clocks[i].ClockID != clocks[k].ClockID {
			return clocks[i].ClockID < clocks[k].ClockID
		}
		if clocks[i].BootID != clocks[k].BootID {
			return clocks[i].BootID < clocks[k].BootID
		}
		return clocks[i].Origin < clocks[k].Origin
	})

	// Stage 3: join. Measurements are validated before they become evidence.
	for _, ev := range inPrefix {
		for _, meas := range ev.Payload.Measurements {
			cm, err := toClockRulesMeasurement(meas)
			if err != nil {
				return empty, fmt.Errorf("diagnostic_reducer: measurement conversion: %v", err)
			}
			if err := clock_rules.ValidateMeasurement(cm, clocks); err != nil {
				return empty, fmt.Errorf("diagnostic_reducer: measurement %q invalid: %v", meas.MeasurementID, err)
			}
		}
	}
	joined, err := joinEvidence(inPrefix)
	if err != nil {
		return empty, err
	}

	// Stage 4-6: catalog, assessments, findings.
	catalog := buildCatalog(request, prefix, joined)
	assessments, findings, claims := buildAssessments(request, prefix, analysisRef, joined, catalog)

	// Measurements are preserved unchanged with their support.
	measurements := append([]MeasurementEvidence{}, joined.measurements...)

	// Feature exposures sorted by feature ID.
	exposures := make([]FeatureExposure, 0, len(joined.exposures))
	for _, fe := range joined.exposures {
		exposures = append(exposures, fe)
	}
	sort.Slice(exposures, func(i, k int) bool { return exposures[i].FeatureID < exposures[k].FeatureID })

	// Validity.
	validity := DiagnosticValidity{
		Checks: []string{
			"fixture_admission: pass",
			"journal_completeness: contiguous prefix ending at analysis_requested",
			"measurement_validity: all pinned measurements satisfy clock_rules",
			"prefix_pinning: evidence beyond the prefix ignored",
		},
		Completeness: "complete",
		Limitations:  []string{},
	}
	if request.ManualMode {
		validity.Limitations = append(validity.Limitations,
			"manual execution: no automation subject, connector version, or binding version; human actions retain manual provenance",
			"operator notes alone establish no authoritative business predicate",
		)
	}
	if len(joined.missingDeps) > 0 {
		validity.Limitations = append(validity.Limitations, "missing dependencies recorded as environment prerequisites, not subject failures")
	}

	// Lifecycle reconciliation when inputs are supplied.
	var report any = NewMissing("not_observed")
	if request.Commission != nil && request.ReportInputs != nil && request.Evaluator != nil {
		rep, err := lifecycle_rules.ReconcileAttempt(*request.Commission, *request.ReportInputs, request.Publications, inPrefix, *request.Evaluator)
		if err != nil {
			return empty, fmt.Errorf("diagnostic_reducer: lifecycle reconciliation: %v", err)
		}
		report = rep
	}
	if m, ok := asMissing(report); ok {
		report = m
	}

	doc := DiagnosticDocument{
		RecordType:             RecordDiagnostic,
		SchemaVersion:          SchemaDiagnostic,
		DiagnosticID:           request.DiagnosticID,
		AnalysisRevision:       request.AnalysisRevision,
		RunID:                  manifest.RunID,
		ManifestHash:           manifestDigest,
		InputPrefix:            prefix,
		AnalysisRequestRef:     analysisRef,
		Classifier:             request.Classifier,
		RequirementRegistry:    request.RequirementRegistry,
		FixRegistry:            requestFix,
		Subject:                request.Subject,
		ManualMode:             request.ManualMode,
		CapabilityCatalog:      catalog,
		RequirementAssessments: assessments,
		Findings:               findings,
		Measurements:           measurements,
		FeatureExposures:       exposures,
		Claims:                 claims,
		Validity:               validity,
		Report:                 report,
	}
	return doc, nil
}

// ---------------------------------------------------------------------------
// Catalog.
// ---------------------------------------------------------------------------

func buildCatalog(request AnalysisRequest, prefix JournalPrefix, joined *joinedEvidence) CapabilityDescriptor {
	if request.ManualMode {
		return CapabilityDescriptor{
			DescriptorID:   "manual-no-subject",
			Subject:        request.Subject,
			Capabilities:   []CapabilityEntry{},
			EvidencePrefix: prefix,
			Limitations: []string{
				"manual execution has no automation subject; no capability descriptors are fabricated",
			},
		}
	}
	// Every new subject version starts unknown until its own evidence
	// establishes another availability. Omission and predecessor descriptors
	// do not imply inheritance, presence, or absence.
	descID := "desc-" + request.Subject.SubjectID + "-" + request.Subject.SubjectVersion
	entries := make([]CapabilityEntry, 0, len(RequiredCapabilities))
	for _, cid := range RequiredCapabilities {
		reqRefs := requirementsForCapability(cid)
		entry := CapabilityEntry{
			ID:              cid,
			RequirementRefs: reqRefs,
			Availability:    AvailUnknown,
			ClaimOrigin:     "harness",
			EvidenceBasis:   []string{},
			EvidenceRefs:    []EvidenceRef{},
			Limitations: []string{
				"no evidence for subject version " + request.Subject.SubjectVersion + "; unknown until established",
			},
		}
		if ev, ok := joined.capabilities[cid]; ok {
			// Only same-version evidence promotes the catalog. Evidence
			// for another version (or an unversioned declaration that does
			// not name this version) leaves unknown in place.
			if ev.SubjectVersion == "" || ev.SubjectVersion == request.Subject.SubjectVersion {
				entry.Availability = ev.Availability
				entry.ClaimOrigin = ev.ClaimOrigin
				entry.EvidenceBasis = []string{"journal_evidence"}
				entry.EvidenceRefs = []EvidenceRef{ev.Ref}
				entry.Limitations = []string{}
				if ev.SubjectVersion == "" {
					entry.Limitations = append(entry.Limitations, "unversioned capability declaration applied to this scope; version attribution unverified")
				}
			} else {
				entry.Limitations = []string{
					"predecessor evidence for version " + ev.SubjectVersion + " does not populate version " + request.Subject.SubjectVersion,
				}
			}
		}
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, k int) bool { return entries[i].ID < entries[k].ID })
	return CapabilityDescriptor{
		DescriptorID:   descID,
		Subject:        request.Subject,
		Capabilities:   entries,
		EvidencePrefix: prefix,
		Limitations:    []string{},
	}
}

func requirementsForCapability(cid string) []string {
	var out []string
	for req, caps := range RequirementCapabilities {
		for _, c := range caps {
			if c == cid {
				out = append(out, req)
			}
		}
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------------------
// Assessments and findings.
// ---------------------------------------------------------------------------

func capabilityRefsFor(descID, req string) []CapabilityReference {
	caps := RequirementCapabilities[req]
	refs := make([]CapabilityReference, 0, len(caps))
	for _, c := range caps {
		refs = append(refs, CapabilityReference{CapabilityID: c, DescriptorID: descID})
	}
	sort.Slice(refs, func(i, k int) bool { return refs[i].CapabilityID < refs[k].CapabilityID })
	return refs
}

func missingFix() Missing {
	m := NewMissing("not_enabled")
	m.Detail = "M1 suggestions remain Missing(not_enabled) pending reviewed fix authority"
	return m
}

func buildAssessments(request AnalysisRequest, prefix JournalPrefix, analysisRef EvidenceRef, joined *joinedEvidence, catalog CapabilityDescriptor) ([]RequirementAssessment, []Finding, []Claim) {
	assessments := make([]RequirementAssessment, 0, len(RequirementOrder))
	findings := []Finding{}
	claims := []Claim{}

	// Index adapter overclaims by capability.
	overclaimByCap := map[string]adapterClaim{}
	for _, ac := range joined.adapterClaims {
		if ac.AdapterClaimsSupported && !ac.NativeSupported {
			overclaimByCap[ac.CapabilityID] = ac
		}
	}
	// Index missing deps by requirement.
	missingByReq := map[string][]missingDependency{}
	for _, md := range joined.missingDeps {
		if len(md.AffectedRequirements) == 0 {
			for _, r := range RequirementOrder {
				missingByReq[r] = append(missingByReq[r], md)
			}
		} else {
			for _, r := range md.AffectedRequirements {
				missingByReq[r] = append(missingByReq[r], md)
			}
		}
	}
	// Index exposures by requirement.
	exposureByReq := map[string]FeatureExposure{}
	for _, fe := range joined.exposures {
		if fe.RequirementRef != "" {
			exposureByReq[fe.RequirementRef] = fe
		}
	}
	// Catalog availability index.
	availByCap := map[string]CapabilityEntry{}
	for _, e := range catalog.Capabilities {
		availByCap[e.ID] = e
	}

	findingSeq := 0
	nextFindingID := func() string {
		findingSeq++
		return fmt.Sprintf("F%d", findingSeq)
	}

	// Adapter overclaim findings and claims (connector/harness locus).
	adapterCaps := make([]string, 0, len(overclaimByCap))
	for c := range overclaimByCap {
		adapterCaps = append(adapterCaps, c)
	}
	sort.Strings(adapterCaps)
	for _, capID := range adapterCaps {
		ac := overclaimByCap[capID]
		reqs := requirementsForCapability(capID)
		if len(reqs) == 0 {
			reqs = []string{ReqR3}
		}
		fid := nextFindingID()
		findings = append(findings, Finding{
			ID:              fid,
			Kind:            KindContradiction,
			RequirementRefs: reqs,
			Symptom:         "adapter claims support for " + capID + " while native evidence shows unsupported; overclaim attributed to connector/harness, not to native capability",
			Scope:           Scope{Kind: "capability", ID: capID},
			CausalRole:      "contributing",
			TriggerFeatures: []string{},
			DefectLocus:     LocusConnector,
			Attribution:     AttrSupported,
			Support:         []EvidenceRef{ac.Ref},
			ContraryEvidence: []EvidenceRef{},
			Limitations:     []string{"native absence remains separately evidenced; adapter declaration alone establishes no native support"},
			SuggestedFix:    missingFix(),
		})
		claims = append(claims, Claim{
			ClaimID:       "adapter-claim-" + capID,
			Source:        "connector",
			SemanticScope: "capability:" + capID,
			Proposition:   "adapter supports " + capID,
			Comparison:    "contradicted",
			Support:       []EvidenceRef{ac.Ref},
			ComparisonSupport: []EvidenceRef{ac.Ref},
			Limitations:   []string{"original adapter bytes preserved; comparison does not overwrite them"},
		})
	}

	// Missing dependency findings (environment/prerequisite).
	for i, md := range joined.missingDeps {
		reqs := append([]string{}, md.AffectedRequirements...)
		if len(reqs) == 0 {
			reqs = append([]string{}, RequirementOrder...)
		}
		sort.Strings(reqs)
		fid := nextFindingID()
		_ = i
		findings = append(findings, Finding{
			ID:              fid,
			Kind:            KindIndeterminate,
			RequirementRefs: reqs,
			Symptom:         "missing dependency " + md.Dependency + ": environment prerequisite unmet, not a subject driver failure",
			Scope:           Scope{Kind: "environment", ID: md.Dependency},
			CausalRole:      "blocking",
			TriggerFeatures: []string{},
			DefectLocus:     LocusEnvironment,
			Attribution:     AttrSupported,
			Support:         []EvidenceRef{md.Ref},
			ContraryEvidence: []EvidenceRef{},
			Limitations:     []string{"affected opportunities are blocked; unaffected requirements remain independently assessed"},
			SuggestedFix:    missingFix(),
		})
	}

	// Isolation findings: invalid write control retains the signal without
	// establishing non-isolation.
	for _, probe := range joined.isolation {
		if probe.WriteControlValid {
			continue
		}
		fid := nextFindingID()
		symptom := "isolation write control invalid; cross-session signal retained without non-isolation conclusion"
		if probe.MarkerObserved {
			symptom = "cross-session marker observed with invalid isolation write control; non-isolation not established"
		}
		findings = append(findings, Finding{
			ID:              fid,
			Kind:            KindIndeterminate,
			RequirementRefs: []string{ReqR2},
			Symptom:         symptom,
			Scope:           Scope{Kind: "requirement", ID: ReqR2},
			CausalRole:      "blocking",
			TriggerFeatures: []string{},
			DefectLocus:     LocusUnknown,
			Attribution:     AttrUnknown,
			Support:         []EvidenceRef{probe.Ref},
			ContraryEvidence: []EvidenceRef{},
			Limitations:     []string{"a failed write control proves no non-isolation; valid write controls are required for an isolation verdict"},
			SuggestedFix:    missingFix(),
		})
	}

	// Fixture defect findings: each invalidates only its dependent opportunity.
	fixtureReqs := make([]string, 0, len(joined.fixtureDefects))
	for r := range joined.fixtureDefects {
		fixtureReqs = append(fixtureReqs, r)
	}
	sort.Strings(fixtureReqs)
	for _, r := range fixtureReqs {
		fd := joined.fixtureDefects[r]
		fid := nextFindingID()
		symptom := "fixture defect invalidates " + r + " opportunity only"
		if strings.TrimSpace(fd.Detail) != "" {
			symptom = "fixture defect (" + fd.Detail + ") invalidates " + r + " opportunity only"
		}
		findings = append(findings, Finding{
			ID:              fid,
			Kind:            KindFixtureError,
			RequirementRefs: []string{r},
			Symptom:         symptom,
			Scope:           Scope{Kind: "requirement", ID: r},
			CausalRole:      "blocking",
			TriggerFeatures: []string{},
			DefectLocus:     LocusFixture,
			Attribution:     AttrSupported,
			Support:         []EvidenceRef{fd.Ref},
			ContraryEvidence: []EvidenceRef{},
			Limitations:     []string{"undeclared fixture failure is a fixture bug, not extra hostility; other requirements remain independently assessed"},
			SuggestedFix:    missingFix(),
		})
	}

	// Subject claims are preserved (non-manual only). Manual execution
	// fabricates no subject claims.
	if !request.ManualMode {
		for _, sc := range joined.subjectClaims {
			claims = append(claims, Claim{
				ClaimID:       sc.ClaimID,
				Source:        sc.Source,
				SemanticScope: sc.Scope,
				Proposition:   sc.Prop,
				Comparison:    "not_comparable",
				Support:       []EvidenceRef{sc.Ref},
				ComparisonSupport: []EvidenceRef{},
				Limitations:   []string{"claim preserved with source, scope, and receipt boundary; no application commitment inferred"},
			})
		}
	}
	sort.Slice(claims, func(i, k int) bool { return claims[i].ClaimID < claims[k].ClaimID })

	// Per-requirement assessments.
	for _, req := range RequirementOrder {
		facet := RequirementFacets[req]
		capRefs := capabilityRefsFor(catalog.DescriptorID, req)
		scope := Scope{Kind: "requirement", ID: req}

		// Manual fixture validation: every R1-R10 not_exercised.
		if request.ManualMode {
			assessments = append(assessments, RequirementAssessment{
				RequirementID:    req,
				Facet:            facet,
				ContractVersion:  "1.0.0",
				Scope:            scope,
				CapabilityRefs:   []CapabilityReference{},
				Opportunity: Opportunity{
					State: OppUnexposed, Support: []EvidenceRef{analysisRef},
					Rationale: RationaleManualFixtureValidation,
				},
				Result:           ResultNotExercised,
				Support:          []EvidenceRef{analysisRef},
				ContraryEvidence: []EvidenceRef{},
				FindingRefs:      []string{},
				Rationale:        RationaleManualFixtureValidation,
			})
			continue
		}

		// Fixture defect: blocked opportunity plus not_exercised, only for
		// the dependent requirement.
		if fd, ok := joined.fixtureDefects[req]; ok {
			facetUsed := facet
			if strings.TrimSpace(fd.AffectedFacet) != "" {
				facetUsed = fd.AffectedFacet
			}
			findingID := findingForRequirement(findings, KindFixtureError, req)
			assessments = append(assessments, RequirementAssessment{
				RequirementID:   req,
				Facet:           facetUsed,
				ContractVersion: "1.0.0",
				Scope:           scope,
				CapabilityRefs:  capRefs,
				Opportunity: Opportunity{
					State: OppBlocked, Support: []EvidenceRef{fd.Ref},
					Rationale: "fixture_defect_invalidates_dependent_opportunity",
				},
				Result:           ResultNotExercised,
				Support:          []EvidenceRef{fd.Ref},
				ContraryEvidence: []EvidenceRef{},
				FindingRefs:      findingRefsOrEmpty(findingID),
				Rationale:        "fixture_defect_invalidates_dependent_opportunity",
			})
			continue
		}

		// Unexposed feature: no behavioral pass or failure.
		if fe, ok := exposureByReq[req]; ok && !fe.Exposed {
			assessments = append(assessments, RequirementAssessment{
				RequirementID:   req,
				Facet:           facet,
				ContractVersion: "1.0.0",
				Scope:           scope,
				CapabilityRefs:  capRefs,
				Opportunity: Opportunity{
					State: OppUnexposed, Support: append([]EvidenceRef{}, fe.Support...),
					Rationale: "unexposed_feature_no_behavioral_credit",
				},
				Result:           ResultNotExercised,
				Support:          append([]EvidenceRef{}, fe.Support...),
				ContraryEvidence: []EvidenceRef{},
				FindingRefs:      []string{},
				Rationale:        "unexposed_feature_no_behavioral_credit",
			})
			continue
		}

		// Missing dependency: blocked prerequisite.
		if mds, ok := missingByReq[req]; ok && len(mds) > 0 {
			support := make([]EvidenceRef, 0, len(mds))
			for _, md := range mds {
				support = append(support, md.Ref)
			}
			findingID := findingForRequirement(findings, KindIndeterminate, req)
			// Prefer the environment finding for this requirement.
			findingID = findingForLocus(findings, LocusEnvironment, req, findingID)
			assessments = append(assessments, RequirementAssessment{
				RequirementID:   req,
				Facet:           facet,
				ContractVersion: "1.0.0",
				Scope:           scope,
				CapabilityRefs:  capRefs,
				Opportunity: Opportunity{
					State: OppBlocked, Support: support,
					Rationale: "missing_dependency_environment_prerequisite",
				},
				Result:           ResultNotExercised,
				Support:          support,
				ContraryEvidence: []EvidenceRef{},
				FindingRefs:      findingRefsOrEmpty(findingID),
				Rationale:        "missing_dependency_environment_prerequisite",
			})
			continue
		}

		// R2 invalid write control: indeterminate, never violated.
		if req == ReqR2 {
			if probe, ok := invalidIsolationProbe(joined.isolation); ok {
				findingID := findingForRequirement(findings, KindIndeterminate, req)
				assessments = append(assessments, RequirementAssessment{
					RequirementID:   req,
					Facet:           facet,
					ContractVersion: "1.0.0",
					Scope:           scope,
					CapabilityRefs:  capRefs,
					Opportunity: Opportunity{
						State: OppExposed, Support: []EvidenceRef{probe.Ref},
						Rationale: "isolation_attempted_with_invalid_write_control",
					},
					Result:           ResultIndeterminate,
					Support:          []EvidenceRef{probe.Ref},
					ContraryEvidence: []EvidenceRef{},
					FindingRefs:      findingRefsOrEmpty(findingID),
					Rationale:        "invalid_write_control_cannot_establish_non_isolation",
				})
				continue
			}
		}

		// Adapter overclaim on a required capability: indeterminate with
		// connector attribution, never a native verdict.
		if ac, ok := overclaimForRequirement(overclaimByCap, req); ok {
			findingID := findingForLocus(findings, LocusConnector, req, "")
			assessments = append(assessments, RequirementAssessment{
				RequirementID:   req,
				Facet:           facet,
				ContractVersion: "1.0.0",
				Scope:           scope,
				CapabilityRefs:  capRefs,
				Opportunity: Opportunity{
					State: OppExposed, Support: []EvidenceRef{ac.Ref},
					Rationale: "adapter_overclaim_blocks_native_verdict",
				},
				Result:           ResultIndeterminate,
				Support:          []EvidenceRef{ac.Ref},
				ContraryEvidence: []EvidenceRef{},
				FindingRefs:      findingRefsOrEmpty(findingID),
				Rationale:        "adapter_overclaim_attributed_to_connector_or_harness",
			})
			continue
		}

		// Requirement outcome: satisfied/violated only with valid exposed
		// opportunity, applicable controls, and supporting evidence.
		if out, ok := joined.outcomes[req]; ok {
			if !out.ControlsValid || !out.HasSupportingEvidence {
				assessments = append(assessments, RequirementAssessment{
					RequirementID:   req,
					Facet:           out.Facet,
					ContractVersion: "1.0.0",
					Scope:           scope,
					CapabilityRefs:  capRefs,
					Opportunity: Opportunity{
						State: OppExposed, Support: []EvidenceRef{out.Ref},
						Rationale: "exposed_without_applicable_controls_or_support",
					},
					Result:           ResultIndeterminate,
					Support:          []EvidenceRef{out.Ref},
					ContraryEvidence: []EvidenceRef{},
					FindingRefs:      []string{},
					Rationale:        "satisfied_or_violated_requires_valid_controls_and_supporting_evidence",
				})
				continue
			}
			// Valid outcome becomes the result, with a violation finding
			// for violated outcomes.
			findingID := ""
			if out.ObservedOutcome == ResultViolated {
				fid := nextFindingID()
				findingID = fid
				findings = append(findings, Finding{
					ID:              fid,
					Kind:            KindViolation,
					RequirementRefs: []string{req},
					Symptom:         "requirement " + req + " facet " + out.Facet + " violated on valid exposed opportunity with supporting evidence",
					Scope:           scope,
					CausalRole:      "primary",
					TriggerFeatures: []string{},
					DefectLocus:     LocusSubject,
					Attribution:     AttrSupported,
					Support:         []EvidenceRef{out.Ref},
					ContraryEvidence: []EvidenceRef{},
					Limitations:     []string{},
					SuggestedFix:    missingFix(),
				})
			}
			rationale := "evidenced_satisfaction_on_valid_exposed_opportunity"
			if out.ObservedOutcome == ResultViolated {
				rationale = "evidenced_violation_on_valid_exposed_opportunity"
			}
			assessments = append(assessments, RequirementAssessment{
				RequirementID:   req,
				Facet:           out.Facet,
				ContractVersion: "1.0.0",
				Scope:           scope,
				CapabilityRefs:  capRefs,
				Opportunity: Opportunity{
					State: OppExposed, Support: []EvidenceRef{out.Ref},
					Rationale: "valid_exposed_opportunity",
				},
				Result:           out.ObservedOutcome,
				Support:          []EvidenceRef{out.Ref},
				ContraryEvidence: []EvidenceRef{},
				FindingRefs:      findingRefsOrEmpty(findingID),
				Rationale:        rationale,
			})
			continue
		}

		// Native absence: exact-scope evidence of a required absent native
		// capability.
		if entry, ok := absentNativeForRequirement(availByCap, req); ok {
			fid := nextFindingID()
			assessments = append(assessments, RequirementAssessment{
				RequirementID:   req,
				Facet:           facet,
				ContractVersion: "1.0.0",
				Scope:           scope,
				CapabilityRefs:  capRefs,
				Opportunity: Opportunity{
					State: OppExposed, Support: append([]EvidenceRef{}, entry.EvidenceRefs...),
					Rationale: "required_native_capability_absent_in_exact_scope",
				},
				Result:           ResultNativeAbsence,
				Support:          append([]EvidenceRef{}, entry.EvidenceRefs...),
				ContraryEvidence: []EvidenceRef{},
				FindingRefs:      []string{fid},
				Rationale:        "native_absence_requires_exact_scope_evidence_of_required_absent_capability",
			})
			findings = append(findings, Finding{
				ID:              fid,
				Kind:            KindNativeAbsent,
				RequirementRefs: []string{req},
				Symptom:         "required native capability " + entry.ID + " absent in exact scope for " + req,
				Scope:           Scope{Kind: "capability", ID: entry.ID},
				CausalRole:      "primary",
				TriggerFeatures: []string{},
				DefectLocus:     LocusSubject,
				Attribution:     AttrSupported,
				Support:         append([]EvidenceRef{}, entry.EvidenceRefs...),
				ContraryEvidence: []EvidenceRef{},
				Limitations:     []string{"absence established by exact-scope evidence, not by failure to reach a step"},
				SuggestedFix:    missingFix(),
			})
			continue
		}

		// Default: exposed but without supporting evidence. Indeterminate,
		// never an invented pass or failure.
		assessments = append(assessments, RequirementAssessment{
			RequirementID:   req,
			Facet:           facet,
			ContractVersion: "1.0.0",
			Scope:           scope,
			CapabilityRefs:  capRefs,
			Opportunity: Opportunity{
				State: OppExposed, Support: []EvidenceRef{analysisRef},
				Rationale: "no_blocking_or_unexposed_evidence",
			},
			Result:           ResultIndeterminate,
			Support:          []EvidenceRef{analysisRef},
			ContraryEvidence: []EvidenceRef{},
			FindingRefs:      []string{},
			Rationale:        "insufficient_support_for_satisfied_or_violated",
		})
	}

	sort.Slice(assessments, func(i, k int) bool { return assessments[i].RequirementID < assessments[k].RequirementID })
	sort.Slice(findings, func(i, k int) bool { return findings[i].ID < findings[k].ID })
	return assessments, findings, claims
}

func findingRefsOrEmpty(id string) []string {
	if id == "" {
		return []string{}
	}
	return []string{id}
}

func findingForRequirement(findings []Finding, kind, req string) string {
	for _, f := range findings {
		if f.Kind != kind {
			continue
		}
		for _, r := range f.RequirementRefs {
			if r == req {
				return f.ID
			}
		}
	}
	return ""
}

func findingForLocus(findings []Finding, locus, req, fallback string) string {
	for _, f := range findings {
		if f.DefectLocus != locus {
			continue
		}
		for _, r := range f.RequirementRefs {
			if r == req {
				return f.ID
			}
		}
	}
	return fallback
}

func invalidIsolationProbe(probes []isolationProbe) (isolationProbe, bool) {
	for _, p := range probes {
		if !p.WriteControlValid {
			return p, true
		}
	}
	return isolationProbe{}, false
}

func overclaimForRequirement(byCap map[string]adapterClaim, req string) (adapterClaim, bool) {
	for _, capID := range RequirementCapabilities[req] {
		if ac, ok := byCap[capID]; ok {
			return ac, true
		}
	}
	return adapterClaim{}, false
}

func absentNativeForRequirement(avail map[string]CapabilityEntry, req string) (CapabilityEntry, bool) {
	for _, capID := range RequirementCapabilities[req] {
		if e, ok := avail[capID]; ok && e.Availability == AvailAbsent && len(e.EvidenceRefs) > 0 {
			return e, true
		}
	}
	return CapabilityEntry{}, false
}

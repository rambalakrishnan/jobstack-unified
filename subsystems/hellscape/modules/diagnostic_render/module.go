// Package diagnostic_render renders EK DiagnosticDocument records into two
// reports — canonical JSON and a human-readable Markdown document — derived
// from the same object.
//
// It implements stage 7 of seam-mappings/hellscape-seam-mapping.md section
// 10.1 (deterministic analysis): "Render JSON and readable output from the
// same object." Rendering is a pure, deterministic function of the document:
// it recomputes no findings, queries no current state, adds no evidence, and
// introduces no wall-clock time, network lookups, or mutable-row reads.
//
// Guarantees:
//   - The JSON report is the RFC 8785 canonical JSON of the document,
//     produced via evidence_codec.CanonicalJSON. Missing envelopes are
//     preserved verbatim; array order and string contents are untouched.
//   - The readable report is rendered from the canonical bytes (decoded back
//     into a DiagnosticDocument), so both reports provably describe the same
//     diagnostic.
//   - Disabled analyses (behavioral/fingerprint profiles, suggested fixes)
//     render as reasoned Missing envelopes, never as zero-valued scores.
//   - Scope, coverage (claim comparisons, requirement results, step statuses),
//     and limitations render verbatim. Missing artifacts, incomplete
//     observation, and source pins are always shown, never concealed.
//   - No overall attempt status or qualification verdict is added, in either
//     report. Step/claim/requirement states use neutral EK vocabulary and are
//     never presented as an overall pass/fail.
//
// Note on evidence_codec.ValidateRecord: its tier-0 diagnostic record shape
// is a minimal subset (diagnostic_id, analysis_revision, run_id, input_prefix
// plus a few optional fields) that rejects spec-required EK DiagnosticDocument
// fields such as classifier, requirement_registry, behavioral_profile, and
// fingerprint_profile as unknown closed-object fields. Rendering therefore
// does not gate on ValidateRecord; instead it enforces the EK null discipline
// (no bare nulls, six valid Missing reasons) over the full document shape
// locally, and uses evidence_codec.CanonicalJSON for deterministic output.
package diagnostic_render

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"

	evidence_codec "evidence_codec"
)

// RecordType and SchemaVersion are the EK record identity for diagnostics.
const (
	RecordType    = "diagnostic"
	SchemaVersion = "0.1.0"
)

// validNullReasons are the six EK NullReason values (seam-mapping 3.1).
// manual_fixture_validation is a rationale, not a seventh reason.
var validNullReasons = map[string]bool{
	"not_enabled":            true,
	"not_applicable":         true,
	"not_observed":           true,
	"observation_lost":       true,
	"unsupported_by_subject": true,
	"manual_override":        true,
}

// Missing is an EK reasoned null: value is always JSON null, reason is one of
// the six NullReason values, and detail carries extra rationale when the
// reason alone is insufficient.
type Missing struct {
	Value  any    `json:"value"`
	Reason string `json:"reason"`
	Detail string `json:"detail,omitempty"`
}

// NotEnabled builds the Missing envelope used for deliberately disabled
// analyses and facilities.
func NotEnabled(detail string) Missing {
	return Missing{Reason: "not_enabled", Detail: detail}
}

// Scope identifies the evaluation scope of an assessment, predicate, or finding.
type Scope struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

// JournalPrefix is an immutable journal prefix: admission is its first event,
// head_hash is the event hash at last_sequence.
type JournalPrefix struct {
	JournalID    string `json:"journal_id"`
	LastSequence int    `json:"last_sequence"`
	HeadHash     string `json:"head_hash"`
}

// EvidenceRef cites one retained journal event coordinate plus a JSON Pointer
// into it (empty string cites the complete event).
type EvidenceRef struct {
	JournalID string `json:"journal_id"`
	Sequence  int    `json:"sequence"`
	EventID   string `json:"event_id"`
	EventHash string `json:"event_hash"`
	Pointer   string `json:"pointer"`
}

// VersionPin names one immutable code, schema, policy, catalog, or registry
// artifact.
type VersionPin struct {
	ID             string `json:"id"`
	Version        string `json:"version"`
	ArtifactDigest string `json:"artifact_digest"`
}

// ArtifactReference is an immutable byte identity plus resolver metadata.
// Possession grants no read authority.
type ArtifactReference struct {
	Digest      string `json:"digest"`
	SizeBytes   int64  `json:"size_bytes"`
	MediaType   string `json:"media_type"`
	OwnerDomain string `json:"owner_domain"`
	Access      string `json:"access"`
}

// ArtifactSlot binds a retained-or-missing artifact to its expected identity.
// Missing retrieval never erases an already known digest.
type ArtifactSlot struct {
	Name           string        `json:"name"`
	ExpectedDigest any           `json:"expected_digest"`
	Content        any           `json:"content"`
	EvidenceRefs   []EvidenceRef `json:"evidence_refs"`
}

// SequenceRange is an inclusive journal sequence interval.
type SequenceRange struct {
	First int `json:"first"`
	Last  int `json:"last"`
}

// ValidityCheck is one scoped fixture/analysis validity check.
type ValidityCheck struct {
	CheckID      string        `json:"check_id"`
	Scope        Scope         `json:"scope"`
	State        string        `json:"state"`
	EvidenceRefs []EvidenceRef `json:"evidence_refs"`
	Rationale    string        `json:"rationale"`
}

// ProducerCompleteness records per-producer journal completeness over the
// diagnostic prefix.
type ProducerCompleteness struct {
	ProducerID     string          `json:"producer_id"`
	State          string          `json:"state"`
	ObservedRanges []SequenceRange `json:"observed_ranges"`
	MissingRanges  []SequenceRange `json:"missing_ranges"`
	FinalSequence  any             `json:"final_sequence"`
	EvidenceRefs   []EvidenceRef   `json:"evidence_refs"`
}

// EvidenceNote is a coded, evidenced annotation (e.g. infrastructure incident).
type EvidenceNote struct {
	Code         string        `json:"code"`
	Detail       string        `json:"detail"`
	EvidenceRefs []EvidenceRef `json:"evidence_refs"`
}

// DiagnosticValidity carries scoped checks, completeness, incidents, and
// limitations. A failed control invalidates only dependent conclusions.
type DiagnosticValidity struct {
	ScopedChecks            []ValidityCheck        `json:"scoped_checks"`
	ProducerCompleteness    []ProducerCompleteness `json:"producer_completeness"`
	InfrastructureIncidents []EvidenceNote         `json:"infrastructure_incidents"`
	Limitations             []string               `json:"limitations"`
}

// AnalysisSection holds one analysis result plus its evidence. A disabled
// analysis carries Data as Missing(not_enabled), never a zero-valued object.
type AnalysisSection struct {
	Data         any           `json:"data"`
	EvidenceRefs []EvidenceRef `json:"evidence_refs"`
}

// TimePoint is a coordinate in a registered monotonic clock.
type TimePoint struct {
	ClockID           string  `json:"clock_id"`
	BootID            string  `json:"boot_id"`
	Origin            string  `json:"origin"`
	MonotonicOffsetMs float64 `json:"monotonic_offset_ms"`
	UtcAnnotation     any     `json:"utc_annotation"`
}

// Claim is an original subject/connector/operator claim plus its semantic
// comparison against authoritative evidence. Comparisons never overwrite the
// original bytes.
type Claim struct {
	ClaimID                     string         `json:"claim_id"`
	Source                      string         `json:"source"`
	Scope                       string         `json:"scope"`
	Proposition                 map[string]any `json:"proposition"`
	MadeAt                      any            `json:"made_at"`
	ReceivedAt                  TimePoint      `json:"received_at"`
	EvidenceRefs                []EvidenceRef  `json:"evidence_refs"`
	EvidenceAvailableToClaimant []EvidenceRef  `json:"evidence_available_to_claimant"`
	KnowledgeLimitations        []string       `json:"knowledge_limitations"`
	Comparison                  string         `json:"comparison"`
	ComparisonEvidenceRefs      []EvidenceRef  `json:"comparison_evidence_refs"`
}

// FixReference is a recommendation reference, never a claim that a change was
// implemented or verified.
type FixReference struct {
	Registry         VersionPin        `json:"registry"`
	RuleInstanceID   string            `json:"rule_instance_id"`
	EvidenceRefs     []EvidenceRef     `json:"evidence_refs"`
	VerificationPlan ArtifactReference `json:"verification_plan"`
}

// Finding is one evidence-backed typed finding.
type Finding struct {
	FindingID            string        `json:"finding_id"`
	Kind                 string        `json:"kind"`
	RequirementRefs      []string      `json:"requirement_refs"`
	Symptom              string        `json:"symptom"`
	Scope                Scope         `json:"scope"`
	CausalRole           string        `json:"causal_role"`
	TriggerFeatureRefs   []string      `json:"trigger_feature_refs"`
	DefectLocus          string        `json:"defect_locus"`
	Attribution          string        `json:"attribution"`
	EvidenceRefs         []EvidenceRef `json:"evidence_refs"`
	ContraryEvidenceRefs []EvidenceRef `json:"contrary_evidence_refs"`
	Limitations          []string      `json:"limitations"`
	SuggestedFix         any           `json:"suggested_fix"`
}

// CapabilityReference cites one catalogued capability entry.
type CapabilityReference struct {
	DescriptorDigest string      `json:"descriptor_digest"`
	CapabilityID     string      `json:"capability_id"`
	EvidenceRef      EvidenceRef `json:"evidence_ref"`
}

// Opportunity records whether the requirement had a valid exercise chance.
type Opportunity struct {
	State        string        `json:"state"`
	EvidenceRefs []EvidenceRef `json:"evidence_refs"`
	Rationale    string        `json:"rationale"`
}

// RequirementAssessment is one independent capability/opportunity/result record.
type RequirementAssessment struct {
	RequirementID        string                `json:"requirement_id"`
	Facet                string                `json:"facet"`
	ContractVersion      string                `json:"contract_version"`
	Scope                Scope                 `json:"scope"`
	CapabilityRefs       []CapabilityReference `json:"capability_refs"`
	Opportunity          Opportunity           `json:"opportunity"`
	Result               string                `json:"result"`
	EvidenceRefs         []EvidenceRef         `json:"evidence_refs"`
	ContraryEvidenceRefs []EvidenceRef         `json:"contrary_evidence_refs"`
	FindingRefs          []string              `json:"finding_refs"`
	Rationale            string                `json:"rationale"`
}

// ObservedAction is a source-faithful projection of one observed action.
type ObservedAction struct {
	ActionID         string        `json:"action_id"`
	Kind             string        `json:"kind"`
	TargetAlias      any           `json:"target_alias"`
	FrameAlias       any           `json:"frame_alias"`
	RenderGeneration any           `json:"render_generation"`
	EvidenceRefs     []EvidenceRef `json:"evidence_refs"`
	ObservedEffect   any           `json:"observed_effect"`
	Provenance       string        `json:"provenance"`
	Limitations      []string      `json:"limitations"`
}

// FeatureExposure is the per-instance configured/armed/exposed/activated chain.
type FeatureExposure struct {
	InstanceID       string        `json:"instance_id"`
	Configured       bool          `json:"configured"`
	RenderedOrArmed  bool          `json:"rendered_or_armed"`
	Exposed          bool          `json:"exposed"`
	Activated        bool          `json:"activated"`
	RecoveryObserved any           `json:"recovery_observed"`
	EvidenceRefs     []EvidenceRef `json:"evidence_refs"`
}

// PredicateResult is one authoritative postcondition outcome.
type PredicateResult struct {
	PredicateID     string        `json:"predicate_id"`
	Scope           Scope         `json:"scope"`
	Truth           string        `json:"truth"`
	AuthorityDomain any           `json:"authority_domain"`
	EvidenceRefs    []EvidenceRef `json:"evidence_refs"`
}

// StepAttempt retains one attempt ordinal, disposition, and support. A rejected
// attempt is retained even when a later correction succeeds.
type StepAttempt struct {
	Ordinal         int               `json:"ordinal"`
	Disposition     string            `json:"disposition"`
	EvidenceRefs    []EvidenceRef     `json:"evidence_refs"`
	Postconditions  []PredicateResult `json:"postconditions"`
	MeasurementRefs []string          `json:"measurement_refs"`
}

// StepDiagnostic is one contract-based step diagnostic. Status is an
// analyzer-owned per-step state, never an overall attempt outcome.
type StepDiagnostic struct {
	StepID                      string            `json:"step_id"`
	ContractID                  string            `json:"contract_id"`
	Status                      string            `json:"status"`
	Attempts                    []StepAttempt     `json:"attempts"`
	AuthoritativePostconditions []PredicateResult `json:"authoritative_postconditions"`
	MeasurementRefs             []string          `json:"measurement_refs"`
	FindingRefs                 []string          `json:"finding_refs"`
}

// Measurement is one supported complete measurement.
type Measurement struct {
	MeasurementID      string `json:"measurement_id"`
	Name               string `json:"name"`
	Scope              Scope  `json:"scope"`
	Quantity           string `json:"quantity"`
	Unit               string `json:"unit"`
	Origin             string `json:"origin"`
	ClockID            string `json:"clock_id"`
	BootID             string `json:"boot_id"`
	Method             string `json:"method"`
	Start              any    `json:"start"`
	End                any    `json:"end"`
	Estimate           any    `json:"estimate"`
	Resolution         any    `json:"resolution"`
	Censoring          string `json:"censoring"`
	ComparabilityGroup any    `json:"comparability_group"`
}

// MeasurementEvidence pairs a copied measurement with its journal support.
type MeasurementEvidence struct {
	Measurement  Measurement   `json:"measurement"`
	EvidenceRefs []EvidenceRef `json:"evidence_refs"`
}

// AttemptReference links to a commissioned attempt identity.
type AttemptReference struct {
	AttemptID string `json:"attempt_id"`
	Kind      string `json:"kind"`
}

// AttemptContext pins the practice attempt this diagnostic analyzes.
// Hellscape attempts always carry kind practice, target_class
// laboratory_fixture, and evaluation_partition held_in.
type AttemptContext struct {
	AttemptID           string             `json:"attempt_id"`
	Kind                string             `json:"kind"`
	TargetClass         string             `json:"target_class"`
	TargetID            string             `json:"target_id"`
	EvaluationPartition string             `json:"evaluation_partition"`
	RehearsalOf         []AttemptReference `json:"rehearsal_of"`
	PerformanceOf       []AttemptReference `json:"performance_of"`
	DerivedFrom         []AttemptReference `json:"derived_from"`
}

// ComponentIdentity describes one configured stack component.
type ComponentIdentity struct {
	Component           string `json:"component"`
	ReportedVersion     any    `json:"reported_version"`
	BuildDigest         any    `json:"build_digest"`
	ConfigurationDigest any    `json:"configuration_digest"`
}

// SubjectIdentity pins the judged automation subject and its stack.
type SubjectIdentity struct {
	SubjectID           string              `json:"subject_id"`
	SubjectVersion      string              `json:"subject_version"`
	RevisionBasis       string              `json:"revision_basis"`
	NativeRevision      any                 `json:"native_revision"`
	ConfiguredMode      string              `json:"configured_mode"`
	InterfaceSurface    string              `json:"interface_surface"`
	ConfigurationDigest string              `json:"configuration_digest"`
	Stack               []ComponentIdentity `json:"stack"`
}

// AssistanceRecord declares admission-time planning assistance.
type AssistanceRecord struct {
	PlanningOwner    string `json:"planning_owner"`
	AssistanceTrack  string `json:"assistance_track"`
	PlannerIdentity  any    `json:"planner_identity"`
	Plan             any    `json:"plan"`
	OnlineReplanning bool   `json:"online_replanning"`
	Description      string `json:"description"`
}

// ExecutionDescriptor describes realized execution/assistance. Execution
// claims stay separate from origin facts: completion never implies
// application commitment.
type ExecutionDescriptor struct {
	Mode             string           `json:"mode"`
	Subject          any              `json:"subject"`
	ConnectorVersion any              `json:"connector_version"`
	BindingVersion   any              `json:"binding_version"`
	Assistance       AssistanceRecord `json:"assistance"`
}

// ApplicationSummary is the authoritative origin/fixture summary at the
// cutoff: goal, as-of journal sequence, predicates, and separately cited
// commitment/confirmation references.
type ApplicationSummary struct {
	Goal             string            `json:"goal"`
	AsOfSequence     int               `json:"as_of_sequence"`
	Postconditions   []PredicateResult `json:"postconditions"`
	CommitmentRefs   []EvidenceRef     `json:"commitment_refs"`
	ConfirmationRefs []EvidenceRef     `json:"confirmation_refs"`
}

// ObservationSummary retains dispatch, observation, execution-claim,
// application-fact, and reconciliation references separately. It neither
// defines nor collapses the five lifecycle axes.
type ObservationSummary struct {
	OpenedRef        EvidenceRef   `json:"opened_ref"`
	ClosedRef        any           `json:"closed_ref"`
	ClosureReason    any           `json:"closure_reason"`
	LifecycleRefs    []EvidenceRef `json:"lifecycle_refs"`
	ContainmentRefs  []EvidenceRef `json:"containment_refs"`
	LateEvidenceRefs []EvidenceRef `json:"late_evidence_refs"`
}

// DiagnosticDocument is the EK diagnostic record rendered by this module.
// Union fields (digest-or-Missing, string-or-Missing, pin-or-Missing, and
// section data) use any: callers set either the value type or a Missing
// envelope. Slices use empty arrays for established-empty collections.
type DiagnosticDocument struct {
	RecordType             string                  `json:"record_type"`
	SchemaVersion          string                  `json:"schema_version"`
	DiagnosticID           string                  `json:"diagnostic_id"`
	AnalysisRevision       int                     `json:"analysis_revision"`
	RunID                  string                  `json:"run_id"`
	ManifestHash           string                  `json:"manifest_hash"`
	InputPrefix            JournalPrefix           `json:"input_prefix"`
	AnalysisRequestRef     EvidenceRef             `json:"analysis_request_ref"`
	Classifier             VersionPin              `json:"classifier"`
	RequirementRegistry    VersionPin              `json:"requirement_registry"`
	FixRegistry            any                     `json:"fix_registry"`
	Attempt                any                     `json:"attempt"`
	Execution              ExecutionDescriptor     `json:"execution"`
	DeliveredTaskHash      any                     `json:"delivered_task_hash"`
	NativeRequestHash      any                     `json:"native_request_hash"`
	Validity               DiagnosticValidity      `json:"validity"`
	CapabilityDescriptors  []ArtifactSlot          `json:"capability_descriptors"`
	RequirementAssessments []RequirementAssessment `json:"requirement_assessments"`
	ObservedActions        []ObservedAction        `json:"observed_actions"`
	FeatureExposures       []FeatureExposure       `json:"feature_exposures"`
	Steps                  []StepDiagnostic        `json:"steps"`
	Measurements           []MeasurementEvidence   `json:"measurements"`
	Claims                 []Claim                 `json:"claims"`
	Findings               []Finding               `json:"findings"`
	Observation            ObservationSummary      `json:"observation"`
	Application            ApplicationSummary      `json:"application"`
	BehavioralProfile      AnalysisSection         `json:"behavioral_profile"`
	FingerprintProfile     AnalysisSection         `json:"fingerprint_profile"`
	Artifacts              []ArtifactSlot          `json:"artifacts"`
}

// RenderDiagnostic renders document into canonical JSON and a human-readable
// Markdown report. It returns (jsonReport, readableReport, err).
//
// Both reports derive from the same canonical bytes: the document is
// marshaled, canonicalized via evidence_codec.CanonicalJSON, and the readable
// report is rendered from those canonical bytes decoded back. Rendering adds
// no evidence, states no overall attempt status, and uses only the document
// contents (no wall time, network, or mutable state).
func RenderDiagnostic(document DiagnosticDocument) ([]byte, []byte, error) {
	if strings.TrimSpace(document.RecordType) == "" {
		document.RecordType = RecordType
	}
	if strings.TrimSpace(document.SchemaVersion) == "" {
		document.SchemaVersion = SchemaVersion
	}
	if strings.TrimSpace(document.DiagnosticID) == "" {
		return nil, nil, fmt.Errorf("diagnostic_render: diagnostic_id is required")
	}
	if document.AnalysisRevision < 1 {
		return nil, nil, fmt.Errorf("diagnostic_render: analysis_revision must be positive, got %d", document.AnalysisRevision)
	}
	if strings.TrimSpace(document.RunID) == "" {
		return nil, nil, fmt.Errorf("diagnostic_render: run_id is required")
	}

	// Established-empty collections must serialize as [] rather than null.
	normalizeEmpties(reflect.ValueOf(&document).Elem())

	raw, err := json.Marshal(document)
	if err != nil {
		return nil, nil, fmt.Errorf("diagnostic_render: marshal document: %w", err)
	}
	// EK-NULL gate: every normalized absence must be a reasoned Missing
	// envelope; bare nulls are rejected before rendering.
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var decoded any
	if err := dec.Decode(&decoded); err != nil {
		return nil, nil, fmt.Errorf("diagnostic_render: decode document: %w", err)
	}
	if err := rejectBareNulls(decoded, "$"); err != nil {
		return nil, nil, err
	}

	canonical, err := evidence_codec.CanonicalJSON(raw, "application/json")
	if err != nil {
		return nil, nil, fmt.Errorf("diagnostic_render: canonicalize document: %w", err)
	}

	// The readable report renders from the canonical bytes, not from the
	// caller's struct, so both reports provably describe the same object.
	var canonicalDoc DiagnosticDocument
	if err := json.Unmarshal(canonical, &canonicalDoc); err != nil {
		return nil, nil, fmt.Errorf("diagnostic_render: decode canonical document: %w", err)
	}
	readable := renderReadable(canonicalDoc)
	return canonical, readable, nil
}

// normalizeEmpties sets every nil slice and nil map reachable from v to its
// empty form so established-empty collections serialize as [] and {} instead
// of null. Nil any fields are left untouched: Maybe positions require an
// explicit value or Missing envelope, and the bare-null gate reports them.
func normalizeEmpties(v reflect.Value) {
	if !v.IsValid() {
		return
	}
	switch v.Kind() {
	case reflect.Ptr:
		if !v.IsNil() {
			normalizeEmpties(v.Elem())
		}
	case reflect.Interface:
		if v.IsNil() {
			return
		}
		e := v.Elem()
		switch e.Kind() {
		case reflect.Slice:
			if e.IsNil() {
				if v.CanSet() {
					v.Set(reflect.MakeSlice(e.Type(), 0, 0))
				}
				return
			}
			normalizeEmpties(e)
		case reflect.Map:
			if e.IsNil() {
				if v.CanSet() {
					v.Set(reflect.MakeMap(e.Type()))
				}
				return
			}
		case reflect.Struct:
			cp := reflect.New(e.Type()).Elem()
			cp.Set(e)
			normalizeEmpties(cp)
			if v.CanSet() {
				v.Set(cp)
			}
		default:
			normalizeEmpties(e)
		}
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			if !t.Field(i).IsExported() {
				continue
			}
			normalizeEmpties(v.Field(i))
		}
	case reflect.Slice:
		if v.IsNil() {
			if v.CanSet() {
				v.Set(reflect.MakeSlice(v.Type(), 0, 0))
			}
			return
		}
		for i := 0; i < v.Len(); i++ {
			normalizeEmpties(v.Index(i))
		}
	case reflect.Map:
		if v.IsNil() && v.CanSet() {
			v.Set(reflect.MakeMap(v.Type()))
		}
	}
}

// rejectBareNulls enforces the EK null discipline over decoded JSON: nil may
// appear only as the value of a well-formed Missing envelope. Maps decoded
// from typed Missing structs always carry value/reason, so both caller-built
// and round-tripped envelopes pass through the same gate.
func rejectBareNulls(v any, path string) error {
	switch t := v.(type) {
	case nil:
		return fmt.Errorf("diagnostic_render: bare null at %s: use a Missing envelope or an empty array", path)
	case map[string]any:
		if raw, ok := t["value"]; ok && raw == nil {
			reason, _ := t["reason"].(string)
			if !validNullReasons[reason] {
				return fmt.Errorf("diagnostic_render: invalid Missing reason %q at %s", reason, path)
			}
			for k := range t {
				if k != "value" && k != "reason" && k != "detail" {
					return fmt.Errorf("diagnostic_render: unknown field %q in Missing envelope at %s", k, path)
				}
			}
			if d, ok := t["detail"]; ok {
				s, ok := d.(string)
				if !ok || strings.TrimSpace(s) == "" {
					return fmt.Errorf("diagnostic_render: Missing detail at %s must be a nonempty string", path)
				}
			}
			return nil
		}
		for _, k := range sortedKeys(t) {
			if err := rejectBareNulls(t[k], path+"."+k); err != nil {
				return err
			}
		}
		return nil
	case []any:
		for i, e := range t {
			if err := rejectBareNulls(e, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
		return nil
	default:
		return nil
	}
}

// asMissing reports whether v is a Missing envelope in either its typed or
// decoded-map form.
func asMissing(v any) (reason, detail string, ok bool) {
	switch t := v.(type) {
	case Missing:
		return t.Reason, t.Detail, true
	case *Missing:
		if t != nil {
			return t.Reason, t.Detail, true
		}
		return "", "", false
	case map[string]any:
		raw, has := t["value"]
		if has && raw == nil {
			r, _ := t["reason"].(string)
			d, _ := t["detail"].(string)
			return r, d, true
		}
	}
	return "", "", false
}

// fmtMaybe formats a union value: Missing envelopes render with their reason,
// scalars render verbatim, and compound values render as compact JSON with
// deterministically sorted keys.
func fmtMaybe(v any) string {
	if v == nil {
		return "Missing (reason: unknown)"
	}
	if reason, detail, ok := asMissing(v); ok {
		if detail != "" {
			return fmt.Sprintf("Missing (reason: %s, detail: %s)", reason, detail)
		}
		return fmt.Sprintf("Missing (reason: %s)", reason)
	}
	switch t := v.(type) {
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case float64:
		return formatNumber(t)
	case json.Number:
		return t.String()
	case int:
		return fmt.Sprintf("%d", t)
	case int64:
		return fmt.Sprintf("%d", t)
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return fmt.Sprintf("%v", v)
		}
		return string(b)
	}
}

// formatNumber renders a decoded JSON number without a trailing ".0" when it
// is integral.
func formatNumber(f float64) string {
	if f == float64(int64(f)) {
		return fmt.Sprintf("%d", int64(f))
	}
	return fmt.Sprintf("%v", f)
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func fmtEvidenceRef(r EvidenceRef) string {
	if r.Pointer == "" {
		return fmt.Sprintf("journal %s seq %d event %s (%s) pointer <whole-event>", r.JournalID, r.Sequence, r.EventID, r.EventHash)
	}
	return fmt.Sprintf("journal %s seq %d event %s (%s) pointer %q", r.JournalID, r.Sequence, r.EventID, r.EventHash, r.Pointer)
}

func fmtVersionPin(p VersionPin) string {
	return fmt.Sprintf("%s version %s (artifact %s)", p.ID, p.Version, p.ArtifactDigest)
}

func fmtScope(s Scope) string {
	return fmt.Sprintf("%s:%s", s.Kind, s.ID)
}

// renderReadable builds the human-readable report. It must stay a pure
// projection: every line restates document content, and no line introduces
// new claims, overall verdicts, or success language.
func renderReadable(doc DiagnosticDocument) []byte {
	var b strings.Builder
	b.WriteString("# Diagnostic report\n\n")
	b.WriteString("## Identity\n")
	b.WriteString(fmt.Sprintf("- diagnostic_id: %s\n", doc.DiagnosticID))
	b.WriteString(fmt.Sprintf("- analysis_revision: %d\n", doc.AnalysisRevision))
	b.WriteString(fmt.Sprintf("- run_id: %s\n", doc.RunID))
	b.WriteString(fmt.Sprintf("- manifest_hash: %s\n", doc.ManifestHash))
	b.WriteString(fmt.Sprintf("- input_prefix: journal %s last_sequence %d head %s\n",
		doc.InputPrefix.JournalID, doc.InputPrefix.LastSequence, doc.InputPrefix.HeadHash))
	b.WriteString(fmt.Sprintf("- analysis_request: %s\n", fmtEvidenceRef(doc.AnalysisRequestRef)))
	b.WriteString(fmt.Sprintf("- classifier: %s\n", fmtVersionPin(doc.Classifier)))
	b.WriteString(fmt.Sprintf("- requirement_registry: %s\n", fmtVersionPin(doc.RequirementRegistry)))
	b.WriteString(fmt.Sprintf("- fix_registry: %s\n", fmtMaybe(doc.FixRegistry)))
	b.WriteString("- readers compare the pins above against current source pins to judge staleness; this report adds no freshness claim\n")

	b.WriteString("\n## Attempt\n")
	b.WriteString(fmt.Sprintf("- attempt: %s\n", fmtMaybe(doc.Attempt)))

	b.WriteString("\n## Execution\n")
	b.WriteString(fmt.Sprintf("- mode: %s\n", doc.Execution.Mode))
	b.WriteString(fmt.Sprintf("- subject: %s\n", fmtMaybe(doc.Execution.Subject)))
	b.WriteString(fmt.Sprintf("- connector_version: %s\n", fmtMaybe(doc.Execution.ConnectorVersion)))
	b.WriteString(fmt.Sprintf("- binding_version: %s\n", fmtMaybe(doc.Execution.BindingVersion)))
	b.WriteString(fmt.Sprintf("- assistance: owner %s track %s online_replanning %v (%s)\n",
		doc.Execution.Assistance.PlanningOwner, doc.Execution.Assistance.AssistanceTrack,
		doc.Execution.Assistance.OnlineReplanning, doc.Execution.Assistance.Description))
	b.WriteString(fmt.Sprintf("- assistance planner_identity: %s\n", fmtMaybe(doc.Execution.Assistance.PlannerIdentity)))
	b.WriteString(fmt.Sprintf("- assistance plan: %s\n", fmtMaybe(doc.Execution.Assistance.Plan)))
	b.WriteString("- execution completion is recorded separately from origin commitment; one never implies the other\n")

	b.WriteString("\n## Retained hashes\n")
	b.WriteString(fmt.Sprintf("- delivered_task_hash: %s\n", fmtMaybe(doc.DeliveredTaskHash)))
	b.WriteString(fmt.Sprintf("- native_request_hash: %s\n", fmtMaybe(doc.NativeRequestHash)))

	b.WriteString("\n## Validity\n")
	b.WriteString(fmt.Sprintf("### Scoped checks (%d)\n", len(doc.Validity.ScopedChecks)))
	if len(doc.Validity.ScopedChecks) == 0 {
		b.WriteString("- none recorded (established empty)\n")
	}
	for _, c := range doc.Validity.ScopedChecks {
		b.WriteString(fmt.Sprintf("- check %s scope %s state %s: %s (%d evidence ref(s))\n",
			c.CheckID, fmtScope(c.Scope), c.State, c.Rationale, len(c.EvidenceRefs)))
	}
	b.WriteString(fmt.Sprintf("### Producer completeness (%d)\n", len(doc.Validity.ProducerCompleteness)))
	if len(doc.Validity.ProducerCompleteness) == 0 {
		b.WriteString("- none recorded (established empty)\n")
	}
	for _, p := range doc.Validity.ProducerCompleteness {
		b.WriteString(fmt.Sprintf("- producer %s state %s final_sequence %s observed %d range(s) missing %d range(s)\n",
			p.ProducerID, p.State, fmtMaybe(p.FinalSequence), len(p.ObservedRanges), len(p.MissingRanges)))
		for _, r := range p.MissingRanges {
			b.WriteString(fmt.Sprintf("  - missing range first %d last %d\n", r.First, r.Last))
		}
	}
	b.WriteString(fmt.Sprintf("### Infrastructure incidents (%d)\n", len(doc.Validity.InfrastructureIncidents)))
	if len(doc.Validity.InfrastructureIncidents) == 0 {
		b.WriteString("- none recorded (established empty)\n")
	}
	for _, n := range doc.Validity.InfrastructureIncidents {
		b.WriteString(fmt.Sprintf("- %s: %s (%d evidence ref(s))\n", n.Code, n.Detail, len(n.EvidenceRefs)))
	}
	b.WriteString(fmt.Sprintf("### Limitations (%d)\n", len(doc.Validity.Limitations)))
	if len(doc.Validity.Limitations) == 0 {
		b.WriteString("- none recorded (established empty)\n")
	}
	for _, l := range doc.Validity.Limitations {
		b.WriteString(fmt.Sprintf("- %s\n", l))
	}

	renderArtifactSlots(&b, "Capability descriptors", doc.CapabilityDescriptors)

	b.WriteString(fmt.Sprintf("\n## Requirement assessments (%d)\n", len(doc.RequirementAssessments)))
	if len(doc.RequirementAssessments) == 0 {
		b.WriteString("- none recorded (established empty)\n")
	}
	for _, a := range doc.RequirementAssessments {
		b.WriteString(fmt.Sprintf("### %s facet %s\n", a.RequirementID, a.Facet))
		b.WriteString(fmt.Sprintf("- contract_version: %s\n", a.ContractVersion))
		b.WriteString(fmt.Sprintf("- scope: %s\n", fmtScope(a.Scope)))
		b.WriteString(fmt.Sprintf("- opportunity: %s (%s)\n", a.Opportunity.State, a.Opportunity.Rationale))
		b.WriteString(fmt.Sprintf("- result: %s\n", a.Result))
		b.WriteString(fmt.Sprintf("- rationale: %s\n", a.Rationale))
		b.WriteString(fmt.Sprintf("- capability_refs: %d finding_refs: %d (%s)\n",
			len(a.CapabilityRefs), len(a.FindingRefs), strings.Join(a.FindingRefs, ", ")))
	}

	b.WriteString(fmt.Sprintf("\n## Observed actions (%d)\n", len(doc.ObservedActions)))
	if len(doc.ObservedActions) == 0 {
		b.WriteString("- none recorded (established empty)\n")
	}
	for _, a := range doc.ObservedActions {
		b.WriteString(fmt.Sprintf("- action %s kind %s target %s frame %s render_generation %s provenance %s effect %s\n",
			a.ActionID, a.Kind, fmtMaybe(a.TargetAlias), fmtMaybe(a.FrameAlias),
			fmtMaybe(a.RenderGeneration), a.Provenance, fmtMaybe(a.ObservedEffect)))
		for _, l := range a.Limitations {
			b.WriteString(fmt.Sprintf("  - limitation: %s\n", l))
		}
	}

	b.WriteString(fmt.Sprintf("\n## Feature exposures (%d)\n", len(doc.FeatureExposures)))
	if len(doc.FeatureExposures) == 0 {
		b.WriteString("- none recorded (established empty)\n")
	}
	for _, f := range doc.FeatureExposures {
		b.WriteString(fmt.Sprintf("- instance %s configured %v rendered_or_armed %v exposed %v activated %v recovery_observed %s\n",
			f.InstanceID, f.Configured, f.RenderedOrArmed, f.Exposed, f.Activated, fmtMaybe(f.RecoveryObserved)))
	}
	b.WriteString("- configured-but-unexposed features carry no behavioral credit in either direction\n")

	b.WriteString(fmt.Sprintf("\n## Steps (%d)\n", len(doc.Steps)))
	if len(doc.Steps) == 0 {
		b.WriteString("- none recorded (established empty)\n")
	}
	for _, s := range doc.Steps {
		b.WriteString(fmt.Sprintf("### Step %s contract %s status %s\n", s.StepID, s.ContractID, s.Status))
		for _, a := range s.Attempts {
			b.WriteString(fmt.Sprintf("- attempt ordinal %d disposition %s (%d postcondition(s))\n",
				a.Ordinal, a.Disposition, len(a.Postconditions)))
		}
		for _, p := range s.AuthoritativePostconditions {
			b.WriteString(fmt.Sprintf("- postcondition %s scope %s truth %s authority %s\n",
				p.PredicateID, fmtScope(p.Scope), p.Truth, fmtMaybe(p.AuthorityDomain)))
		}
	}
	b.WriteString("- step statuses are per-contract analyzer states, not an overall attempt outcome\n")

	b.WriteString(fmt.Sprintf("\n## Measurements (%d)\n", len(doc.Measurements)))
	if len(doc.Measurements) == 0 {
		b.WriteString("- none recorded (established empty)\n")
	}
	for _, m := range doc.Measurements {
		ms := m.Measurement
		b.WriteString(fmt.Sprintf("- measurement %s name %s scope %s quantity %s unit %s origin %s method %s estimate %s censoring %s\n",
			ms.MeasurementID, ms.Name, fmtScope(ms.Scope), ms.Quantity, ms.Unit, ms.Origin, ms.Method, fmtMaybe(ms.Estimate), ms.Censoring))
	}

	b.WriteString(fmt.Sprintf("\n## Claims (%d)\n", len(doc.Claims)))
	if len(doc.Claims) == 0 {
		b.WriteString("- none recorded (established empty)\n")
	}
	for _, c := range doc.Claims {
		b.WriteString(fmt.Sprintf("### Claim %s\n", c.ClaimID))
		b.WriteString(fmt.Sprintf("- source: %s\n", c.Source))
		b.WriteString(fmt.Sprintf("- scope: %s\n", c.Scope))
		b.WriteString(fmt.Sprintf("- proposition: %s\n", fmtMaybe(c.Proposition)))
		b.WriteString(fmt.Sprintf("- made_at: %s\n", fmtMaybe(c.MadeAt)))
		b.WriteString(fmt.Sprintf("- received_at: clock %s boot %s origin %s offset_ms %s\n",
			c.ReceivedAt.ClockID, c.ReceivedAt.BootID, c.ReceivedAt.Origin, formatNumber(c.ReceivedAt.MonotonicOffsetMs)))
		b.WriteString(fmt.Sprintf("- comparison: %s\n", c.Comparison))
		b.WriteString(fmt.Sprintf("- knowledge_limitations (%d):\n", len(c.KnowledgeLimitations)))
		for _, l := range c.KnowledgeLimitations {
			b.WriteString(fmt.Sprintf("  - %s\n", l))
		}
		b.WriteString(fmt.Sprintf("- evidence_refs: %d claimant_evidence: %d comparison_evidence: %d\n",
			len(c.EvidenceRefs), len(c.EvidenceAvailableToClaimant), len(c.ComparisonEvidenceRefs)))
	}
	b.WriteString("- comparisons (consistent, contradicted, not_comparable, indeterminate) imply no pass or fail on their own\n")

	b.WriteString(fmt.Sprintf("\n## Findings (%d)\n", len(doc.Findings)))
	if len(doc.Findings) == 0 {
		b.WriteString("- none recorded (established empty)\n")
	}
	for _, f := range doc.Findings {
		b.WriteString(fmt.Sprintf("### Finding %s kind %s\n", f.FindingID, f.Kind))
		b.WriteString(fmt.Sprintf("- symptom: %s\n", f.Symptom))
		b.WriteString(fmt.Sprintf("- scope: %s\n", fmtScope(f.Scope)))
		b.WriteString(fmt.Sprintf("- causal_role: %s defect_locus: %s attribution: %s\n", f.CausalRole, f.DefectLocus, f.Attribution))
		b.WriteString(fmt.Sprintf("- requirement_refs: %d (%s)\n", len(f.RequirementRefs), strings.Join(f.RequirementRefs, ", ")))
		b.WriteString(fmt.Sprintf("- suggested_fix: %s\n", fmtMaybe(f.SuggestedFix)))
		for _, l := range f.Limitations {
			b.WriteString(fmt.Sprintf("- limitation: %s\n", l))
		}
	}

	b.WriteString("\n## Observation\n")
	b.WriteString(fmt.Sprintf("- opened: %s\n", fmtEvidenceRef(doc.Observation.OpenedRef)))
	b.WriteString(fmt.Sprintf("- closed: %s\n", fmtMaybe(doc.Observation.ClosedRef)))
	b.WriteString(fmt.Sprintf("- closure_reason: %s\n", fmtMaybe(doc.Observation.ClosureReason)))
	b.WriteString(fmt.Sprintf("- lifecycle_refs: %d containment_refs: %d late_evidence_refs: %d\n",
		len(doc.Observation.LifecycleRefs), len(doc.Observation.ContainmentRefs), len(doc.Observation.LateEvidenceRefs)))

	b.WriteString("\n## Application\n")
	b.WriteString(fmt.Sprintf("- goal: %s\n", doc.Application.Goal))
	b.WriteString(fmt.Sprintf("- as_of_sequence: %d (journal sequence, not a reducer revision)\n", doc.Application.AsOfSequence))
	b.WriteString(fmt.Sprintf("- postconditions (%d):\n", len(doc.Application.Postconditions)))
	for _, p := range doc.Application.Postconditions {
		b.WriteString(fmt.Sprintf("  - %s scope %s truth %s authority %s\n",
			p.PredicateID, fmtScope(p.Scope), p.Truth, fmtMaybe(p.AuthorityDomain)))
	}
	b.WriteString(fmt.Sprintf("- commitment_refs: %d confirmation_refs: %d (cited separately; absence of commitment observation leaves goal unknown unless an authoritative no-commit fact applies)\n",
		len(doc.Application.CommitmentRefs), len(doc.Application.ConfirmationRefs)))

	renderAnalysisSection(&b, "Behavioral profile", doc.BehavioralProfile)
	renderAnalysisSection(&b, "Fingerprint profile", doc.FingerprintProfile)

	renderArtifactSlots(&b, "Artifacts", doc.Artifacts)

	b.WriteString("\n## Provenance note\n")
	b.WriteString(fmt.Sprintf("- rendered deterministically from diagnostic %s revision %d; this report adds no evidence and states no overall attempt verdict\n",
		doc.DiagnosticID, doc.AnalysisRevision))
	return []byte(b.String())
}

// renderAnalysisSection renders one behavioral/fingerprint profile. Disabled or
// otherwise missing analyses show their reasoned Missing envelope; only
// present data renders its keys. No score is ever synthesized.
func renderAnalysisSection(b *strings.Builder, title string, section AnalysisSection) {
	b.WriteString(fmt.Sprintf("\n## %s\n", title))
	if reason, detail, ok := asMissing(section.Data); ok {
		if reason == "not_enabled" {
			b.WriteString("- state: disabled\n")
		} else {
			b.WriteString(fmt.Sprintf("- state: missing (reason: %s)\n", reason))
		}
		if detail != "" {
			b.WriteString(fmt.Sprintf("- detail: %s\n", detail))
		}
	} else {
		b.WriteString("- state: present\n")
		if m, ok := section.Data.(map[string]any); ok {
			for _, k := range sortedKeys(m) {
				b.WriteString(fmt.Sprintf("- %s: %s\n", k, fmtMaybe(m[k])))
			}
		} else {
			b.WriteString(fmt.Sprintf("- data: %s\n", fmtMaybe(section.Data)))
		}
	}
	b.WriteString(fmt.Sprintf("- evidence_refs: %d\n", len(section.EvidenceRefs)))
}

// renderArtifactSlots renders capability-descriptor or artifact slots,
// preserving known digests alongside reasoned-missing content.
func renderArtifactSlots(b *strings.Builder, title string, slots []ArtifactSlot) {
	b.WriteString(fmt.Sprintf("\n## %s (%d)\n", title, len(slots)))
	if len(slots) == 0 {
		b.WriteString("- none recorded (established empty)\n")
		return
	}
	for _, s := range slots {
		b.WriteString(fmt.Sprintf("- slot %s\n", s.Name))
		b.WriteString(fmt.Sprintf("  - expected_digest: %s\n", fmtMaybe(s.ExpectedDigest)))
		b.WriteString(fmt.Sprintf("  - content: %s\n", fmtMaybe(s.Content)))
		b.WriteString(fmt.Sprintf("  - evidence_refs: %d\n", len(s.EvidenceRefs)))
	}
}

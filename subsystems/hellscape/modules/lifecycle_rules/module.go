// Package lifecycle_rules implements the tier-3 Hellscape application-attempt
// lifecycle rules: five-axis publication fencing, per-axis transition guards,
// cumulative immutable execution/application histories, close-time knowledge
// preservation, and report reconciliation over pinned inputs.
//
// Seam references: seam-mappings/hellscape-seam-mapping.md sections 9.1-9.9
// (AxisRevision, dispatch/observation transitions, CloseSnapshot, execution
// and application histories, report history, manual axes, closure protocol)
// and 16.5 (lifecycle and diagnostic corpus), plus
// contracts/01-application-attempt-lifecycle.yaml invariants LIFE-* and
// EK-CLAIMS.
//
// Semantic boundaries enforced here:
//
//   - Exactly one authority role owns each of the five axes; each applicable
//     axis has exactly one bound writer; a report writer holds no
//     execution/application grant; no whole-attempt status or multi-axis
//     update exists (LIFE-AXES).
//   - Axis revisions are complete immutable publications keyed by
//     (attempt_id, kind, axis, revision); same-key different bytes is an
//     integrity conflict; revisions fence previous+1 (LIFE-PUBLICATION).
//   - Prepare is non-executing; dispatching requires a durable handle,
//     request digest, and intent; native run IDs attach only on correlated
//     receipt; local Start acknowledgement is not native acceptance and
//     native acceptance is not execution completion (LIFE-DISPATCH).
//   - Observation, transport, native execution, application mutation
//     authority, and native context lifetimes are distinct; closure freezes
//     knowledge and pins; closed-to-closed preserves closure fields while
//     appending late evidence (LIFE-CLOSE).
//   - Execution publications carry only faithfully mapped,
//     source-attributed claims; absent state is Missing, never an invented
//     unknown; explicit unknown stays a valid subject claim (LIFE-CLAIMS).
//   - Origin facts cite verified source and correlation evidence under the
//     pinned origin policy; HTTP 200, submit clicks, subject results, and
//     operator assertions alone are insufficient (LIFE-ORIGIN).
//   - The reconciler reads pinned execution claims and origin facts and
//     writes only report; a stopped claim alone asserts no no-commitment
//     proposition (LIFE-RECONCILE).
//   - Every pinned claim/assertion is accounted for; any proved
//     contradiction yields contradicted; otherwise complete comparisons
//     yield reconciled and unresolved ones yield Missing; no applicable
//     claims yield not_applicable, never a fabricated success
//     (LIFE-REPORT-COVERAGE).
//   - Manual dispatch/execution stay revision zero with not_applicable;
//     the recorder owns observation with manual provenance (LIFE-MANUAL).
//   - Durations use registered-clock Measurements; UTC and receipt order
//     never establish occurrence order; opaque origin revisions are never
//     lexically ordered (LIFE-TIME, EK-CLAIMS).
//
// Structural gates delegate to evidence_codec, reference resolution to
// journal_rules, and timing semantics to clock_rules.
package lifecycle_rules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"clock_rules"
	"evidence_codec"
	"journal_rules"
)

// ---------------------------------------------------------------------------
// Evidence-kernel primitive aliases.
//
// Journal envelopes, references, prefixes, artifacts, clocks, and
// measurements reuse the journal_rules wire shapes so that CONSUMES calls to
// journal_rules.ResolveEvidence need no translation. Timing validation
// converts to clock_rules shapes explicitly.
// ---------------------------------------------------------------------------

// JournalEnvelope is the complete stored journal event envelope.
type JournalEnvelope = journal_rules.JournalEnvelope

// EvidenceRef cites one retained journal event coordinate plus a JSON Pointer.
type EvidenceRef = journal_rules.EvidenceRef

// JournalPrefix is an immutable journal prefix.
type JournalPrefix = journal_rules.JournalPrefix

// ArtifactReference is an immutable byte identity plus resolver metadata.
type ArtifactReference = journal_rules.ArtifactReference

// TimePoint is a coordinate in a registered monotonic clock.
type TimePoint = journal_rules.TimePoint

// ClockDescriptor registers one clock lifetime.
type ClockDescriptor = journal_rules.ClockDescriptor

// Scope identifies the measured entity.
type Scope = journal_rules.Scope

// Estimate is the discriminated measurement estimate.
type Estimate = journal_rules.Estimate

// Measurement is the EK Measurement record.
type Measurement = journal_rules.Measurement

// Missing is a typed EK Missing envelope: {"value":null,"reason":...}.
type Missing = journal_rules.MissingEnvelope

// NewMissing builds a reasoned Missing envelope with a null value.
func NewMissing(reason string) Missing {
	return journal_rules.NewMissing(reason)
}

// Compile-time CONSUMES linkage. These references fail compilation if the
// declared upstream signatures disappear.
var (
	_ = evidence_codec.ValidateRecord
	_ = journal_rules.ResolveEvidence
	_ = clock_rules.ValidateMeasurement
)

// ---------------------------------------------------------------------------
// Shared lifecycle types (contract 01-application-attempt-lifecycle.yaml).
// ---------------------------------------------------------------------------

// Schema versions pinned by this module.
const (
	SchemaLifecycle = "application-attempt-lifecycle/0.1.0"
	SchemaKernel    = "evidence-kernel/0.1.0"
	RecordAxis      = "attempt_axis_revision"
)

// Axes.
const (
	AxisDispatch    = "dispatch"
	AxisObservation = "observation"
	AxisExecution   = "execution"
	AxisApplication = "application"
	AxisReport      = "report"
)

// Dispatch states.
const (
	DispatchNotStarted  = "not_started"
	DispatchPrepared    = "prepared"
	DispatchDispatching = "dispatching"
	DispatchAccepted    = "accepted"
	DispatchRejected    = "rejected"
	DispatchUncertain   = "uncertain"
)

// Observation states.
const (
	ObsNotOpened = "not_opened"
	ObsOpen      = "open"
	ObsDraining  = "draining"
	ObsClosed    = "closed"
)

// Execution states (subject claims).
const (
	ExecRunning   = "running"
	ExecCompleted = "completed"
	ExecFailed    = "failed"
	ExecStopped   = "stopped"
	ExecUnknown   = "unknown"
)

// AttemptReference identifies one attempt and kind.
type AttemptReference struct {
	AttemptID string `json:"attempt_id"`
	Kind      string `json:"kind"`
}

// AttemptContext is the full attempt identity and lineage.
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

// VersionPin pins an immutable versioned artifact.
type VersionPin struct {
	ID             string `json:"id"`
	Version        string `json:"version"`
	ArtifactDigest string `json:"artifact_digest"`
}

// ComponentIdentity is one stack component of a subject.
type ComponentIdentity struct {
	Component           string `json:"component"`
	ReportedVersion     any    `json:"reported_version"`
	BuildDigest         any    `json:"build_digest"`
	ConfigurationDigest any    `json:"configuration_digest"`
}

// SubjectIdentity identifies the commissioned automation subject.
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

// AssistanceRecord describes planning assistance.
type AssistanceRecord struct {
	PlanningOwner   string `json:"planning_owner"`
	AssistanceTrack string `json:"assistance_track"`
	PlannerIdentity any    `json:"planner_identity"`
	Plan            any    `json:"plan"`
	OnlineReplanning bool  `json:"online_replanning"`
	Description     string `json:"description"`
}

// ExecutionDescriptor restricts application attempts to manual or subject.
type ExecutionDescriptor struct {
	Mode             string           `json:"mode"`
	Subject          any              `json:"subject"`
	ConnectorVersion any              `json:"connector_version"`
	BindingVersion   any              `json:"binding_version"`
	Assistance       AssistanceRecord `json:"assistance"`
}

// AuthorityBinding declares one axis authority and its sole writer.
type AuthorityBinding struct {
	Role              string     `json:"role"`
	SourceID          any        `json:"source_id"`
	WriterID          any        `json:"writer_id"`
	OwnerDomain       string     `json:"owner_domain"`
	PublicationPolicy VersionPin `json:"publication_policy"`
}

// OwnerBindings carries the five axis bindings.
type OwnerBindings struct {
	Dispatch    AuthorityBinding `json:"dispatch"`
	Observation AuthorityBinding `json:"observation"`
	Execution   AuthorityBinding `json:"execution"`
	Application AuthorityBinding `json:"application"`
	Report      AuthorityBinding `json:"report"`
}

// DurationLimit is configuration, never a measurement.
type DurationLimit struct {
	Kind  string  `json:"kind"`
	Unit  string  `json:"unit"`
	Value float64 `json:"value"`
}

// ObservationPolicy carries the commissioned local bounds.
type ObservationPolicy struct {
	ActiveLimit          DurationLimit `json:"active_limit"`
	DrainLimit           DurationLimit `json:"drain_limit"`
	NativeCancelWaitLimit DurationLimit `json:"native_cancel_wait_limit"`
	CleanupWaitLimit     DurationLimit `json:"cleanup_wait_limit"`
	FixtureCloseAction   string        `json:"fixture_close_action"`
}

// JobReference pins the job content used for the decision.
type JobReference struct {
	JobID        string            `json:"job_id"`
	SourceTarget any               `json:"source_target"`
	SourceJobID  any               `json:"source_job_id"`
	Snapshot     ArtifactReference `json:"snapshot"`
}

// AttemptCommission freezes the attempt identity and owner bindings.
type AttemptCommission struct {
	RecordType           string              `json:"record_type"`
	SchemaVersion        string              `json:"schema_version"`
	KernelVersion        string              `json:"kernel_version"`
	CommissionID         string              `json:"commission_id"`
	RunID                string              `json:"run_id"`
	JournalID            string              `json:"journal_id"`
	ManifestHash         string              `json:"manifest_hash"`
	AdmissionRef         EvidenceRef         `json:"admission_ref"`
	CommissionedBy       string              `json:"commissioned_by"`
	CommissionedAt       TimePoint           `json:"commissioned_at"`
	Attempt              AttemptContext      `json:"attempt"`
	CandidateID          string              `json:"candidate_id"`
	CandidateProfile     any                 `json:"candidate_profile"`
	Job                  JobReference        `json:"job"`
	SelectionEvidence    any                 `json:"selection_evidence"`
	Task                 ArtifactReference   `json:"task"`
	TaskSemanticHash     string              `json:"task_semantic_hash"`
	InitialMaterials     []ArtifactReference `json:"initial_materials"`
	Execution            ExecutionDescriptor `json:"execution"`
	Owners               OwnerBindings       `json:"owners"`
	IdempotencyKey       string              `json:"idempotency_key"`
	AuthorizationRefs    []EvidenceRef       `json:"authorization_refs"`
	RecoveryReviewRefs   []EvidenceRef       `json:"recovery_review_refs"`
	ObservationPolicy    ObservationPolicy   `json:"observation_policy"`
	OriginPolicy         VersionPin          `json:"origin_policy"`
}

// DomainPin pins one axis revision and its record digest.
type DomainPin struct {
	Revision     int64 `json:"revision"`
	RecordDigest any   `json:"record_digest"`
}

// ReportInputPins pins the four source axes a report reads.
type ReportInputPins struct {
	Dispatch    DomainPin `json:"dispatch"`
	Observation DomainPin `json:"observation"`
	Execution   DomainPin `json:"execution"`
	Application DomainPin `json:"application"`
}

// CloseInputPins pins knowledge available at closure.
type CloseInputPins struct {
	Dispatch    DomainPin `json:"dispatch"`
	Execution   DomainPin `json:"execution"`
	Application DomainPin `json:"application"`
	Report      DomainPin `json:"report"`
}

// SourceChecks carries authentication/correlation verification.
type SourceChecks struct {
	Authentication     string     `json:"authentication"`
	Correlation        string     `json:"correlation"`
	TraceCorrelation   string     `json:"trace_correlation"`
	VerificationPolicy VersionPin `json:"verification_policy"`
	MatchedBy          []string   `json:"matched_by"`
	EvidenceRefs       []EvidenceRef `json:"evidence_refs"`
}

// DispatchValue is the connector-owned dispatch axis value.
type DispatchValue struct {
	State                     string       `json:"state"`
	LocalHandle               any          `json:"local_handle"`
	NativeRunID               any          `json:"native_run_id"`
	RequestDigest             any          `json:"request_digest"`
	DeliveryRefs              []EvidenceRef `json:"delivery_refs"`
	AcceptanceRefs            []EvidenceRef `json:"acceptance_refs"`
	RecoveryAuthorizationRefs []EvidenceRef `json:"recovery_authorization_refs"`
	Reason                    any          `json:"reason"`
}

// CloseSnapshot freezes close-time knowledge.
type CloseSnapshot struct {
	ClosureID               string        `json:"closure_id"`
	BoundaryRef             EvidenceRef   `json:"boundary_ref"`
	KnownVersions           CloseInputPins `json:"known_versions"`
	ExecutionKnowledge      string        `json:"execution_knowledge"`
	ExecutionEvidenceRefs   []EvidenceRef `json:"execution_evidence_refs"`
	ApplicationKnowledge    string        `json:"application_knowledge"`
	ApplicationEvidenceRefs []EvidenceRef `json:"application_evidence_refs"`
	Limitations             []string      `json:"limitations"`
}

// Opportunity records control-operation opportunity.
type Opportunity struct {
	State        string        `json:"state"`
	EvidenceRefs []EvidenceRef `json:"evidence_refs"`
	Rationale    string        `json:"rationale"`
}

// CapabilityReference cites a capability descriptor.
type CapabilityReference struct {
	DescriptorDigest string      `json:"descriptor_digest"`
	CapabilityID     string      `json:"capability_id"`
	EvidenceRef      EvidenceRef `json:"evidence_ref"`
}

// MeasurementEvidence pairs a measurement with its support.
type MeasurementEvidence struct {
	Measurement  Measurement   `json:"measurement"`
	EvidenceRefs []EvidenceRef `json:"evidence_refs"`
}

// ControlObservation records one separately evidenced control operation.
type ControlObservation struct {
	ControlEventID   string               `json:"control_event_id"`
	OperationID      string               `json:"operation_id"`
	Operation        string               `json:"operation"`
	TargetScope      string               `json:"target_scope"`
	Disposition      string               `json:"disposition"`
	At               TimePoint            `json:"at"`
	AuthorizationRef EvidenceRef          `json:"authorization_ref"`
	CapabilityRef    any                  `json:"capability_ref"`
	Opportunity      Opportunity          `json:"opportunity"`
	RequestRef       any                  `json:"request_ref"`
	ResponseRef      any                  `json:"response_ref"`
	ResponseChecks   any                  `json:"response_checks"`
	NativeClaimRefs  []EvidenceRef        `json:"native_claim_refs"`
	EffectRefs       []EvidenceRef        `json:"effect_refs"`
	AffectedAttempts []AttemptReference   `json:"affected_attempts"`
	Measurements     []MeasurementEvidence `json:"measurements"`
	Limitations      []string             `json:"limitations"`
}

// ObservationValue is the connector-owned observation axis value.
type ObservationValue struct {
	State               string               `json:"state"`
	WindowID            string               `json:"window_id"`
	OpenedAt            any                  `json:"opened_at"`
	ActiveDeadline      any                  `json:"active_deadline"`
	DrainStartedAt      any                  `json:"drain_started_at"`
	DrainDeadline       any                  `json:"drain_deadline"`
	ClosedAt            any                  `json:"closed_at"`
	CloseReason         any                  `json:"close_reason"`
	AtClose             any                  `json:"at_close"`
	ControlObservations []ControlObservation `json:"control_observations"`
	LateEvidenceRefs    []EvidenceRef        `json:"late_evidence_refs"`
	Measurements        []MeasurementEvidence `json:"measurements"`
}

// CommitmentAssertion is one subject application proposition.
type CommitmentAssertion struct {
	AssertionID  string        `json:"assertion_id"`
	Value        string        `json:"value"`
	Span         string        `json:"span"`
	BoundaryRef  any           `json:"boundary_ref"`
	EvidenceRefs []EvidenceRef `json:"evidence_refs"`
}

// ExecutionClaim is one faithfully mapped subject claim.
type ExecutionClaim struct {
	ClaimID                     string                `json:"claim_id"`
	Scope                       string                `json:"scope"`
	State                       any                   `json:"state"`
	ApplicationAssertions       []CommitmentAssertion `json:"application_assertions"`
	NativeRunID                 any                   `json:"native_run_id"`
	NativeMessageID             any                   `json:"native_message_id"`
	NativeReport                ArtifactReference     `json:"native_report"`
	Mapping                     VersionPin            `json:"mapping"`
	SourceChecks                SourceChecks          `json:"source_checks"`
	MadeAt                      any                   `json:"made_at"`
	ReceivedAt                  TimePoint             `json:"received_at"`
	EvidenceAvailableToClaimant []EvidenceRef         `json:"evidence_available_to_claimant"`
	EvidenceRefs                []EvidenceRef         `json:"evidence_refs"`
	Limitations                 []string              `json:"limitations"`
}

// ExecutionValue carries the cumulative immutable claim history.
type ExecutionValue struct {
	Claims []ExecutionClaim `json:"claims"`
}

// OriginFact is one verified origin application fact.
type OriginFact struct {
	FactID             string            `json:"fact_id"`
	OriginID           string            `json:"origin_id"`
	CandidateID        string            `json:"candidate_id"`
	JobID              string            `json:"job_id"`
	State              string            `json:"state"`
	Coverage           string            `json:"coverage"`
	BoundaryRef        EvidenceRef       `json:"boundary_ref"`
	OriginApplicationID any              `json:"origin_application_id"`
	OriginRevision     any               `json:"origin_revision"`
	Receipt            ArtifactReference `json:"receipt"`
	VerificationKind   string            `json:"verification_kind"`
	SourceChecks       SourceChecks      `json:"source_checks"`
	AuthoritySealRef   any               `json:"authority_seal_ref"`
	OccurredAt         any               `json:"occurred_at"`
	ReceivedAt         TimePoint         `json:"received_at"`
	EvidenceRefs       []EvidenceRef     `json:"evidence_refs"`
}

// ApplicationValue carries the cumulative immutable fact history.
type ApplicationValue struct {
	Facts []OriginFact `json:"facts"`
}

// TemporalRelation relates an origin fact to an assertion boundary.
type TemporalRelation struct {
	Relation     string        `json:"relation"`
	Basis        string        `json:"basis"`
	EvidenceRefs []EvidenceRef `json:"evidence_refs"`
}

// ClaimComparison compares one claim/assertion against origin facts.
type ClaimComparison struct {
	ClaimID          string           `json:"claim_id"`
	AssertionID      any              `json:"assertion_id"`
	ClaimRef         EvidenceRef      `json:"claim_ref"`
	FactIDs          []string         `json:"fact_ids"`
	FactRefs         []EvidenceRef    `json:"fact_refs"`
	Result           string           `json:"result"`
	TemporalRelation TemporalRelation `json:"temporal_relation"`
	Rationale        string           `json:"rationale"`
	Limitations      []string         `json:"limitations"`
}

// ReconciliationIssue records a source conflict or evidence gap.
type ReconciliationIssue struct {
	Kind         string        `json:"kind"`
	Detail       string        `json:"detail"`
	EvidenceRefs []EvidenceRef `json:"evidence_refs"`
}

// ReportValue is the reconciler-owned report axis value.
type ReportValue struct {
	State       any               `json:"state"`
	Coverage    string            `json:"coverage"`
	Inputs      ReportInputPins   `json:"inputs"`
	Evaluator   VersionPin        `json:"evaluator"`
	Comparisons []ClaimComparison `json:"comparisons"`
	Issues      []ReconciliationIssue `json:"issues"`
	Limitations []string          `json:"limitations"`
	Diagnostic  any               `json:"diagnostic"`
}

// AxisRevision is one complete immutable axis publication.
type AxisRevision struct {
	RecordType       string        `json:"record_type"`
	SchemaVersion    string        `json:"schema_version"`
	Attempt          AttemptReference `json:"attempt"`
	CommissionDigest string        `json:"commission_digest"`
	Axis             string        `json:"axis"`
	OwnerDomain      string        `json:"owner_domain"`
	WriterID         string        `json:"writer_id"`
	Revision         int64         `json:"revision"`
	PreviousRevision int64         `json:"previous_revision"`
	EvidencePrefix   JournalPrefix `json:"evidence_prefix"`
	EvidenceRefs     []EvidenceRef `json:"evidence_refs"`
	Value            any           `json:"value"`
}

// ---------------------------------------------------------------------------
// Small validators.
// ---------------------------------------------------------------------------

var validNullReasons = map[string]bool{
	"not_enabled": true, "not_applicable": true, "not_observed": true,
	"observation_lost": true, "unsupported_by_subject": true, "manual_override": true,
}

var validAxes = map[string]bool{
	AxisDispatch: true, AxisObservation: true, AxisExecution: true,
	AxisApplication: true, AxisReport: true,
}

var validDispatchStates = map[string]bool{
	DispatchNotStarted: true, DispatchPrepared: true, DispatchDispatching: true,
	DispatchAccepted: true, DispatchRejected: true, DispatchUncertain: true,
}

var validObsStates = map[string]bool{
	ObsNotOpened: true, ObsOpen: true, ObsDraining: true, ObsClosed: true,
}

var validCloseReasons = map[string]bool{
	"normal_completion": true, "operator_stop": true, "local_deadline": true,
	"translation_failure": true, "launch_failure": true, "subject_terminal": true,
	"connection_lost": true, "infrastructure_interruption": true,
}

var validExecStates = map[string]bool{
	ExecRunning: true, ExecCompleted: true, ExecFailed: true,
	ExecStopped: true, ExecUnknown: true,
}

var validClaimScopes = map[string]bool{
	"primitive": true, "application_postcondition": true,
	"execution_lifecycle": true, "unknown": true,
}

var validCommitValues = map[string]bool{
	"committed": true, "not_committed": true, "outcome_unknown": true,
}

var validCommitSpans = map[string]bool{
	"at_boundary": true, "after_boundary": true, "entire_attempt": true,
}

var validFactStates = map[string]bool{
	"not_committed": true, "committed": true,
}

var validFactCoverage = map[string]bool{
	"at_boundary": true, "final_for_attempt": true,
}

var validVerificationKinds = map[string]bool{
	"local_origin_transaction": true, "verified_origin_receipt": true,
}

var validCompareResults = map[string]bool{
	"consistent": true, "contradicted": true,
	"not_comparable": true, "indeterminate": true,
}

var validTemporalRelations = map[string]bool{
	"before": true, "at": true, "after": true,
	"unknown": true, "not_applicable": true,
}

var validTemporalBases = map[string]bool{
	"same_clock": true, "causal_evidence": true, "origin_sequence": true,
	"not_established": true, "not_applicable": true,
}

var validIssueKinds = map[string]bool{
	"origin_fact_conflict": true, "subject_claim_conflict": true,
	"insufficient_evidence": true, "incomparable_scope": true,
	"untrusted_observation": true, "mapping_error": true,
	"multiple_origin_commitments": true,
}

var validOrigins = map[string]bool{
	"engine_measured": true, "browser_measured": true,
	"subject_reported": true, "manual_reference": true,
}

var validControlOps = map[string]bool{
	"RequestNativeCancel": true, "CloseObservationConnection": true,
	"ReleaseNativeContext": true, "Contain": true,
}

func validDigest(s string) bool {
	const prefix = "sha256:"
	if !strings.HasPrefix(s, prefix) {
		return false
	}
	hexPart := s[len(prefix):]
	if len(hexPart) != 64 {
		return false
	}
	for i := range hexPart {
		c := hexPart[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func validIdentifier(s string) bool {
	return strings.TrimSpace(s) != ""
}

func validJSONPointer(s string) bool {
	if s == "" {
		return true
	}
	if !strings.HasPrefix(s, "/") {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] == '~' {
			i++
			if i >= len(s) || (s[i] != '0' && s[i] != '1') {
				return false
			}
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Missing / Maybe-field helpers.
// ---------------------------------------------------------------------------

// asMissing detects a Missing envelope in struct or generic-map form. The
// value field must be JSON null and the reason one of the six kernel reasons.
func asMissing(v any) (Missing, bool) {
	switch t := v.(type) {
	case Missing:
		if t.Value != nil {
			// Value must be null; a non-nil value is not a Missing envelope.
			// json.RawMessage("null") unmarshals to nil interface, so any
			// non-nil payload disqualifies.
			return Missing{}, false
		}
		if !validNullReasons[t.Reason] {
			return Missing{}, false
		}
		return t, true
	case *Missing:
		if t == nil {
			return Missing{}, false
		}
		return asMissing(*t)
	case map[string]any:
		raw, ok := t["value"]
		if !ok {
			return Missing{}, false
		}
		if raw != nil {
			return Missing{}, false
		}
		r, _ := t["reason"].(string)
		if !validNullReasons[r] {
			return Missing{}, false
		}
		detail := ""
		if d, ok := t["detail"].(string); ok {
			detail = d
		} else if d, ok := t["Detail"].(string); ok {
			detail = d
		}
		return Missing{Value: nil, Reason: r, Detail: detail}, true
	default:
		return Missing{}, false
	}
}

func isMissing(v any) bool {
	_, ok := asMissing(v)
	return ok
}

func missingReason(v any) (string, bool) {
	m, ok := asMissing(v)
	if !ok {
		return "", false
	}
	return m.Reason, true
}

func isMissingWithReason(v any, reason string) bool {
	r, ok := missingReason(v)
	return ok && r == reason
}

func asStringValue(v any) (string, bool) {
	s, ok := v.(string)
	if !ok || !validIdentifier(s) {
		return "", false
	}
	return s, true
}

func asTimePointValue(v any) (TimePoint, bool) {
	switch t := v.(type) {
	case TimePoint:
		return t, true
	case *TimePoint:
		if t == nil {
			return TimePoint{}, false
		}
		return *t, true
	case map[string]any:
		raw, err := json.Marshal(t)
		if err != nil {
			return TimePoint{}, false
		}
		var tp TimePoint
		if err := json.Unmarshal(raw, &tp); err != nil {
			return TimePoint{}, false
		}
		// A Missing envelope also unmarshals into a zero TimePoint with
		// empty IDs; reject those so callers can try asMissing first.
		if !validIdentifier(tp.ClockID) || !validIdentifier(tp.BootID) {
			return TimePoint{}, false
		}
		return tp, true
	default:
		return TimePoint{}, false
	}
}

func asCloseSnapshotValue(v any) (CloseSnapshot, bool) {
	switch t := v.(type) {
	case CloseSnapshot:
		return t, true
	case *CloseSnapshot:
		if t == nil {
			return CloseSnapshot{}, false
		}
		return *t, true
	case map[string]any:
		if _, ok := asMissing(v); ok {
			return CloseSnapshot{}, false
		}
		raw, err := json.Marshal(t)
		if err != nil {
			return CloseSnapshot{}, false
		}
		var cs CloseSnapshot
		if err := json.Unmarshal(raw, &cs); err != nil {
			return CloseSnapshot{}, false
		}
		if !validIdentifier(cs.ClosureID) {
			return CloseSnapshot{}, false
		}
		return cs, true
	default:
		return CloseSnapshot{}, false
	}
}

func asEvidenceRefValue(v any) (EvidenceRef, bool) {
	switch t := v.(type) {
	case EvidenceRef:
		return t, true
	case *EvidenceRef:
		if t == nil {
			return EvidenceRef{}, false
		}
		return *t, true
	case map[string]any:
		if _, ok := asMissing(v); ok {
			return EvidenceRef{}, false
		}
		raw, err := json.Marshal(t)
		if err != nil {
			return EvidenceRef{}, false
		}
		var r EvidenceRef
		if err := json.Unmarshal(raw, &r); err != nil {
			return EvidenceRef{}, false
		}
		if !validIdentifier(r.JournalID) || !validIdentifier(r.EventID) {
			return EvidenceRef{}, false
		}
		return r, true
	default:
		return EvidenceRef{}, false
	}
}

func asArtifactValue(v any) (ArtifactReference, bool) {
	switch t := v.(type) {
	case ArtifactReference:
		return t, true
	case *ArtifactReference:
		if t == nil {
			return ArtifactReference{}, false
		}
		return *t, true
	case map[string]any:
		if _, ok := asMissing(v); ok {
			return ArtifactReference{}, false
		}
		raw, err := json.Marshal(t)
		if err != nil {
			return ArtifactReference{}, false
		}
		var a ArtifactReference
		if err := json.Unmarshal(raw, &a); err != nil {
			return ArtifactReference{}, false
		}
		if !validDigest(a.Digest) {
			return ArtifactReference{}, false
		}
		return a, true
	default:
		return ArtifactReference{}, false
	}
}

// roundTrip parses a polymorphic axis Value (typed struct or generic map)
// into the requested typed shape via JSON.
func roundTrip(v any, out any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var mid any
	if err := dec.Decode(&mid); err != nil {
		return err
	}
	// Reject in-band nulls inside lifecycle values: every absence must be a
	// reasoned Missing envelope.
	if err := rejectBareNulls(mid, "$"); err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

func rejectBareNulls(v any, path string) error {
	switch t := v.(type) {
	case nil:
		return fmt.Errorf("lifecycle_rules: bare null at %s: use a typed Missing envelope", path)
	case map[string]any:
		if raw, has := t["value"]; has && raw == nil {
			r, _ := t["reason"].(string)
			if !validNullReasons[r] {
				return fmt.Errorf("lifecycle_rules: invalid Missing reason %q at %s", r, path)
			}
			return nil
		}
		for k, e := range t {
			if err := rejectBareNulls(e, path+"."+k); err != nil {
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

func parseDispatchValue(v any) (DispatchValue, error) {
	var out DispatchValue
	if err := roundTrip(v, &out); err != nil {
		return DispatchValue{}, fmt.Errorf("lifecycle_rules: dispatch value: %v", err)
	}
	return out, nil
}

func parseObservationValue(v any) (ObservationValue, error) {
	var out ObservationValue
	if err := roundTrip(v, &out); err != nil {
		return ObservationValue{}, fmt.Errorf("lifecycle_rules: observation value: %v", err)
	}
	return out, nil
}

func parseExecutionValue(v any) (ExecutionValue, error) {
	var out ExecutionValue
	if err := roundTrip(v, &out); err != nil {
		return ExecutionValue{}, fmt.Errorf("lifecycle_rules: execution value: %v", err)
	}
	return out, nil
}

func parseApplicationValue(v any) (ApplicationValue, error) {
	var out ApplicationValue
	if err := roundTrip(v, &out); err != nil {
		return ApplicationValue{}, fmt.Errorf("lifecycle_rules: application value: %v", err)
	}
	return out, nil
}

func parseReportValue(v any) (ReportValue, error) {
	var out ReportValue
	if err := roundTrip(v, &out); err != nil {
		return ReportValue{}, fmt.Errorf("lifecycle_rules: report value: %v", err)
	}
	return out, nil
}

// canonicalEqual compares two values by canonical JSON bytes.
func canonicalEqual(a, b any) (bool, error) {
	araw, err := json.Marshal(a)
	if err != nil {
		return false, err
	}
	braw, err := json.Marshal(b)
	if err != nil {
		return false, err
	}
	ac, err := evidence_codec.CanonicalJSON(araw, "application/json")
	if err != nil {
		return false, err
	}
	bc, err := evidence_codec.CanonicalJSON(braw, "application/json")
	if err != nil {
		return false, err
	}
	return bytes.Equal(ac, bc), nil
}

func evidenceRefKey(r EvidenceRef) string {
	return r.JournalID + "\x00" + fmt.Sprint(r.Sequence) + "\x00" + r.EventID + "\x00" + r.EventHash + "\x00" + r.Pointer
}

func evidenceRefEqual(a, b EvidenceRef) bool {
	return a.JournalID == b.JournalID && a.Sequence == b.Sequence &&
		a.EventID == b.EventID && a.EventHash == b.EventHash && a.Pointer == b.Pointer
}

// isSubsetRefs reports whether every ref in sub appears in super.
func isSubsetRefs(sub, super []EvidenceRef) bool {
	keys := make(map[string]int, len(super))
	for _, r := range super {
		keys[evidenceRefKey(r)]++
	}
	for _, r := range sub {
		k := evidenceRefKey(r)
		if keys[k] == 0 {
			return false
		}
		keys[k]--
	}
	return true
}

// publicationDigest binds a DomainPin record_digest to exact publication bytes.
func publicationDigest(pub AxisRevision) (string, error) {
	raw, err := json.Marshal(pub)
	if err != nil {
		return "", err
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

func toClockRulesClock(cd ClockDescriptor) clock_rules.ClockDescriptor {
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
		return nil, fmt.Errorf("lifecycle_rules: %s is an in-band null: use a typed Missing envelope", field)
	}
	if s, ok := v.(string); ok {
		if _, err := time.Parse(time.RFC3339, s); err != nil {
			return nil, fmt.Errorf("lifecycle_rules: %s is not a valid date-time %q", field, s)
		}
		return s, nil
	}
	if m, ok := asMissing(v); ok {
		return toClockRulesMissing(m), nil
	}
	// After a JSON round trip a Missing envelope may already be a map; asMissing
	// covers that. Anything else is a type error.
	return nil, fmt.Errorf("lifecycle_rules: %s must be a date-time annotation or Missing, got %T", field, v)
}

func convertEndpoint(v any, field string) (any, error) {
	if v == nil {
		return nil, fmt.Errorf("lifecycle_rules: %s is an in-band null: use TimePoint or Missing", field)
	}
	if m, ok := asMissing(v); ok {
		cm := toClockRulesMissing(m)
		return cm, nil
	}
	tp, ok := asTimePointValue(v)
	if !ok {
		return nil, fmt.Errorf("lifecycle_rules: %s must be a TimePoint or Missing, got %T", field, v)
	}
	utc, err := convertUTCAnnotation(tp.UTCAnnotation, field+".utc_annotation")
	if err != nil {
		return nil, err
	}
	return clock_rules.TimePoint{
		ClockID: tp.ClockID, BootID: tp.BootID, Origin: tp.Origin,
		MonotonicOffsetMs: tp.MonotonicOffsetMs, UTCAnnotation: utc,
	}, nil
}

func convertNumberOrMissing(v any, field string) (any, error) {
	if v == nil {
		return nil, fmt.Errorf("lifecycle_rules: %s is an in-band null: use a number or Missing", field)
	}
	if m, ok := asMissing(v); ok {
		cm := toClockRulesMissing(m)
		return cm, nil
	}
	switch n := v.(type) {
	case float64, float32, int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64, json.Number:
		return v, nil
	default:
		_ = n
		return nil, fmt.Errorf("lifecycle_rules: %s must be numeric or Missing, got %T", field, v)
	}
}

func convertStringOrMissing(v any, field string) (any, error) {
	if v == nil {
		return nil, fmt.Errorf("lifecycle_rules: %s is an in-band null: use a string or Missing", field)
	}
	if s, ok := v.(string); ok {
		return s, nil
	}
	if m, ok := asMissing(v); ok {
		cm := toClockRulesMissing(m)
		return cm, nil
	}
	return nil, fmt.Errorf("lifecycle_rules: %s must be a string or Missing, got %T", field, v)
}

func convertEstimate(e Estimate, field string) (clock_rules.Estimate, error) {
	switch e.Kind {
	case "exact":
		if e.Value == nil {
			return clock_rules.Estimate{}, fmt.Errorf("lifecycle_rules: %s exact estimate needs a numeric value", field)
		}
		if e.LowerBound != nil || e.UpperBound != nil {
			return clock_rules.Estimate{}, fmt.Errorf("lifecycle_rules: %s exact estimate must not carry bounds", field)
		}
		val, err := convertNumberOrMissing(e.Value, field+".value")
		if err != nil {
			return clock_rules.Estimate{}, err
		}
		if _, ok := asMissing(e.Value); ok {
			return clock_rules.Estimate{}, fmt.Errorf("lifecycle_rules: %s exact estimate value must be numeric", field)
		}
		return clock_rules.Estimate{Kind: e.Kind, Value: val}, nil
	case "bounded":
		if e.Value != nil {
			return clock_rules.Estimate{}, fmt.Errorf("lifecycle_rules: %s bounded estimate must not carry a value", field)
		}
		var lo, hi any
		var err error
		if e.LowerBound != nil {
			lo, err = convertNumberOrMissing(e.LowerBound, field+".lower_bound")
			if err != nil {
				return clock_rules.Estimate{}, err
			}
		}
		if e.UpperBound != nil {
			hi, err = convertNumberOrMissing(e.UpperBound, field+".upper_bound")
			if err != nil {
				return clock_rules.Estimate{}, err
			}
		}
		return clock_rules.Estimate{Kind: e.Kind, LowerBound: lo, UpperBound: hi}, nil
	case "unavailable":
		if e.Value == nil {
			return clock_rules.Estimate{}, fmt.Errorf("lifecycle_rules: %s unavailable estimate needs a Missing value", field)
		}
		if e.LowerBound != nil || e.UpperBound != nil {
			return clock_rules.Estimate{}, fmt.Errorf("lifecycle_rules: %s unavailable estimate must not carry bounds", field)
		}
		if _, ok := asMissing(e.Value); !ok {
			return clock_rules.Estimate{}, fmt.Errorf("lifecycle_rules: %s unavailable estimate value must be Missing", field)
		}
		val, err := convertNumberOrMissing(e.Value, field+".value")
		if err != nil {
			return clock_rules.Estimate{}, err
		}
		return clock_rules.Estimate{Kind: e.Kind, Value: val}, nil
	default:
		return clock_rules.Estimate{}, fmt.Errorf("lifecycle_rules: %s has invalid estimate kind %q", field, e.Kind)
	}
}

func toClockRulesMeasurement(m Measurement, field string) (clock_rules.Measurement, error) {
	start, err := convertEndpoint(m.Start, field+".start")
	if err != nil {
		return clock_rules.Measurement{}, err
	}
	end, err := convertEndpoint(m.End, field+".end")
	if err != nil {
		return clock_rules.Measurement{}, err
	}
	res, err := convertNumberOrMissing(m.Resolution, field+".resolution")
	if err != nil {
		return clock_rules.Measurement{}, err
	}
	cg, err := convertStringOrMissing(m.ComparabilityGroup, field+".comparability_group")
	if err != nil {
		return clock_rules.Measurement{}, err
	}
	est, err := convertEstimate(m.Estimate, field+".estimate")
	if err != nil {
		return clock_rules.Measurement{}, err
	}
	return clock_rules.Measurement{
		MeasurementID: m.MeasurementID, Name: m.Name,
		Scope: clock_rules.Scope{Kind: m.Scope.Kind, ID: m.Scope.ID},
		Quantity: m.Quantity, Unit: m.Unit, Origin: m.Origin,
		ClockID: m.ClockID, BootID: m.BootID, Method: m.Method,
		Start: start, End: end, Estimate: est, Resolution: res,
		Censoring: m.Censoring, ComparabilityGroup: cg,
		AggregateSource: m.AggregateSource,
	}, nil
}

// extractClocks collects clock registrations from clock_registered evidence.
func extractClocks(evidence []JournalEnvelope) ([]clock_rules.ClockDescriptor, error) {
	var out []clock_rules.ClockDescriptor
	seen := map[string]bool{}
	for i := range evidence {
		ev := &evidence[i]
		data := ev.Payload.Data
		if data == nil {
			continue
		}
		// Only clock_registered events (or any event carrying a full
		// descriptor object) contribute registrations.
		cid, _ := data["clock_id"].(string)
		bid, _ := data["boot_id"].(string)
		origin, _ := data["origin"].(string)
		source, _ := data["source_id"].(string)
		basis, _ := data["basis"].(string)
		unit, _ := data["unit"].(string)
		if cid == "" || bid == "" || origin == "" || source == "" || basis == "" || unit == "" {
			continue
		}
		if ev.EventKind != "clock_registered" {
			continue
		}
		key := cid + "\x00" + bid + "\x00" + origin
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, clock_rules.ClockDescriptor{
			ClockID: cid, BootID: bid, Origin: origin,
			SourceID: source, Basis: basis, Unit: unit,
		})
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Evidence helpers.
// ---------------------------------------------------------------------------

func validateEvidenceStructural(evidence []JournalEnvelope) error {
	for i := range evidence {
		ev := &evidence[i]
		raw, err := json.Marshal(ev)
		if err != nil {
			return fmt.Errorf("lifecycle_rules: evidence[%d]: cannot marshal: %v", i, err)
		}
		sv := ev.SchemaVersion
		if strings.TrimSpace(sv) == "" {
			return fmt.Errorf("lifecycle_rules: evidence[%d]: schema_version must be nonempty", i)
		}
		if err := evidence_codec.ValidateRecord(sv, "journal_event", raw); err != nil {
			return fmt.Errorf("lifecycle_rules: evidence[%d] structural gate: %v", i, err)
		}
	}
	return nil
}

func validateEvidenceRefShape(r EvidenceRef, field string) error {
	if !validIdentifier(r.JournalID) {
		return fmt.Errorf("lifecycle_rules: %s journal_id must be a nonempty identifier", field)
	}
	if r.Sequence < 1 {
		return fmt.Errorf("lifecycle_rules: %s sequence starts at 1, got %d", field, r.Sequence)
	}
	if !validIdentifier(r.EventID) {
		return fmt.Errorf("lifecycle_rules: %s event_id must be a nonempty identifier", field)
	}
	if !validDigest(r.EventHash) {
		return fmt.Errorf("lifecycle_rules: %s event_hash %q is not a valid digest", field, r.EventHash)
	}
	if !validJSONPointer(r.Pointer) {
		return fmt.Errorf("lifecycle_rules: %s pointer %q is not a valid JSON pointer", field, r.Pointer)
	}
	return nil
}

func resolveRefs(prefix JournalPrefix, evidence []JournalEnvelope, refs []EvidenceRef, field string) error {
	for i, r := range refs {
		where := fmt.Sprintf("%s[%d]", field, i)
		if err := validateEvidenceRefShape(r, where); err != nil {
			return err
		}
		if _, err := journal_rules.ResolveEvidence(prefix, evidence, r); err != nil {
			return fmt.Errorf("lifecycle_rules: %s does not resolve: %v", where, err)
		}
	}
	return nil
}

func findEvent(evidence []JournalEnvelope, ref EvidenceRef) *JournalEnvelope {
	for i := range evidence {
		ev := &evidence[i]
		if ev.JournalID == ref.JournalID && ev.Sequence == ref.Sequence {
			return ev
		}
	}
	return nil
}

func validatePrefix(prefix JournalPrefix, field string) error {
	if !validIdentifier(prefix.JournalID) {
		return fmt.Errorf("lifecycle_rules: %s journal_id must be a nonempty identifier", field)
	}
	if prefix.LastSequence < 1 {
		return fmt.Errorf("lifecycle_rules: %s last_sequence starts at 1, got %d", field, prefix.LastSequence)
	}
	if !validDigest(prefix.HeadHash) {
		return fmt.Errorf("lifecycle_rules: %s head_hash %q is not a valid digest", field, prefix.HeadHash)
	}
	return nil
}

func validateVersionPin(p VersionPin, field string) error {
	if !validIdentifier(p.ID) {
		return fmt.Errorf("lifecycle_rules: %s id must be a nonempty identifier", field)
	}
	if !validIdentifier(p.Version) {
		return fmt.Errorf("lifecycle_rules: %s version must be a nonempty identifier", field)
	}
	if !validDigest(p.ArtifactDigest) {
		return fmt.Errorf("lifecycle_rules: %s artifact_digest %q is not a valid digest", field, p.ArtifactDigest)
	}
	return nil
}

func validateArtifact(a ArtifactReference, field string) error {
	if !validDigest(a.Digest) {
		return fmt.Errorf("lifecycle_rules: %s digest %q is not a valid digest", field, a.Digest)
	}
	if a.SizeBytes < 0 {
		return fmt.Errorf("lifecycle_rules: %s size_bytes must not be negative", field)
	}
	if !validIdentifier(a.MediaType) {
		return fmt.Errorf("lifecycle_rules: %s media_type must be a nonempty identifier", field)
	}
	if !validIdentifier(a.OwnerDomain) {
		return fmt.Errorf("lifecycle_rules: %s owner_domain must be a nonempty identifier", field)
	}
	if a.Access != "public" && a.Access != "restricted" {
		return fmt.Errorf("lifecycle_rules: %s access %q must be public or restricted", field, a.Access)
	}
	return nil
}

func validateTimePointShape(tp TimePoint, field string) error {
	if !validIdentifier(tp.ClockID) {
		return fmt.Errorf("lifecycle_rules: %s clock_id must be a nonempty identifier", field)
	}
	if !validIdentifier(tp.BootID) {
		return fmt.Errorf("lifecycle_rules: %s boot_id must be a nonempty identifier", field)
	}
	if !validOrigins[tp.Origin] {
		return fmt.Errorf("lifecycle_rules: %s has invalid origin %q", field, tp.Origin)
	}
	if tp.MonotonicOffsetMs < 0 {
		return fmt.Errorf("lifecycle_rules: %s monotonic_offset_ms must not be negative", field)
	}
	if tp.UTCAnnotation == nil {
		return fmt.Errorf("lifecycle_rules: %s utc_annotation is an in-band null: use a date-time or Missing", field)
	}
	if s, ok := tp.UTCAnnotation.(string); ok {
		if _, err := time.Parse(time.RFC3339, s); err != nil {
			return fmt.Errorf("lifecycle_rules: %s utc_annotation %q is not RFC3339: %v", field, s, err)
		}
		return nil
	}
	if _, ok := asMissing(tp.UTCAnnotation); ok {
		return nil
	}
	return fmt.Errorf("lifecycle_rules: %s utc_annotation must be a date-time or Missing, got %T", field, tp.UTCAnnotation)
}

func validateMaybeTimePoint(v any, field string) error {
	if v == nil {
		return fmt.Errorf("lifecycle_rules: %s is an in-band null: use TimePoint or Missing", field)
	}
	if _, ok := asMissing(v); ok {
		return nil
	}
	tp, ok := asTimePointValue(v)
	if !ok {
		return fmt.Errorf("lifecycle_rules: %s must be a TimePoint or Missing, got %T", field, v)
	}
	return validateTimePointShape(tp, field)
}

func validateDomainPin(p DomainPin, field string) error {
	if p.Revision < 0 {
		return fmt.Errorf("lifecycle_rules: %s revision must not be negative", field)
	}
	if p.RecordDigest == nil {
		return fmt.Errorf("lifecycle_rules: %s record_digest is an in-band null: use a digest or Missing", field)
	}
	if p.Revision == 0 {
		if _, ok := asMissing(p.RecordDigest); !ok {
			return fmt.Errorf("lifecycle_rules: %s revision zero means no publication: record_digest must be Missing", field)
		}
		return nil
	}
	s, ok := p.RecordDigest.(string)
	if !ok || !validDigest(s) {
		return fmt.Errorf("lifecycle_rules: %s record_digest must be a valid digest for revision %d", field, p.Revision)
	}
	return nil
}

func validateSourceChecks(sc SourceChecks, field string, prefix JournalPrefix, evidence []JournalEnvelope, requireVerified bool) error {
	if sc.Authentication != "verified" && sc.Authentication != "failed" && sc.Authentication != "unknown" {
		return fmt.Errorf("lifecycle_rules: %s authentication %q is invalid", field, sc.Authentication)
	}
	if sc.Correlation != "matched" && sc.Correlation != "mismatched" && sc.Correlation != "unknown" {
		return fmt.Errorf("lifecycle_rules: %s correlation %q is invalid", field, sc.Correlation)
	}
	switch sc.TraceCorrelation {
	case "matched", "mismatched", "not_observed", "not_applicable":
	default:
		return fmt.Errorf("lifecycle_rules: %s trace_correlation %q is invalid", field, sc.TraceCorrelation)
	}
	if err := validateVersionPin(sc.VerificationPolicy, field+".verification_policy"); err != nil {
		return err
	}
	seen := map[string]bool{}
	for i, name := range sc.MatchedBy {
		if !validIdentifier(name) {
			return fmt.Errorf("lifecycle_rules: %s matched_by[%d] must be a nonempty identifier", field, i)
		}
		if seen[name] {
			return fmt.Errorf("lifecycle_rules: %s matched_by duplicates %q", field, name)
		}
		seen[name] = true
	}
	if sc.EvidenceRefs == nil {
		return fmt.Errorf("lifecycle_rules: %s evidence_refs is an in-band null: use an array", field)
	}
	if len(sc.EvidenceRefs) == 0 {
		return fmt.Errorf("lifecycle_rules: %s evidence_refs needs at least one support reference", field)
	}
	if err := resolveRefs(prefix, evidence, sc.EvidenceRefs, field+".evidence_refs"); err != nil {
		return err
	}
	if requireVerified {
		if sc.Authentication != "verified" {
			return fmt.Errorf("lifecycle_rules: %s authentication must be verified for accepted owner evidence, got %q", field, sc.Authentication)
		}
		if sc.Correlation != "matched" {
			return fmt.Errorf("lifecycle_rules: %s correlation must be matched for accepted owner evidence, got %q", field, sc.Correlation)
		}
		if len(sc.MatchedBy) == 0 {
			return fmt.Errorf("lifecycle_rules: %s matched_by must name at least one correlation input", field)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Commission validation.
// ---------------------------------------------------------------------------

func bindingForAxis(owners OwnerBindings, axis string) (AuthorityBinding, bool) {
	switch axis {
	case AxisDispatch:
		return owners.Dispatch, true
	case AxisObservation:
		return owners.Observation, true
	case AxisExecution:
		return owners.Execution, true
	case AxisApplication:
		return owners.Application, true
	case AxisReport:
		return owners.Report, true
	default:
		return AuthorityBinding{}, false
	}
}

func validateAuthorityBinding(b AuthorityBinding, axis, wantRole string) error {
	field := "commission.owners." + axis
	if b.Role != wantRole {
		return fmt.Errorf("lifecycle_rules: %s role must be %q, got %q", field, wantRole, b.Role)
	}
	if b.SourceID == nil || b.WriterID == nil {
		return fmt.Errorf("lifecycle_rules: %s source_id/writer_id must not be in-band nulls", field)
	}
	if _, ok := asMissing(b.SourceID); !ok {
		if _, ok := asStringValue(b.SourceID); !ok {
			return fmt.Errorf("lifecycle_rules: %s source_id must be an identifier or Missing", field)
		}
	}
	if _, ok := asMissing(b.WriterID); !ok {
		if _, ok := asStringValue(b.WriterID); !ok {
			return fmt.Errorf("lifecycle_rules: %s writer_id must be an identifier or Missing", field)
		}
	}
	if !validIdentifier(b.OwnerDomain) {
		return fmt.Errorf("lifecycle_rules: %s owner_domain must be a nonempty identifier", field)
	}
	if err := validateVersionPin(b.PublicationPolicy, field+".publication_policy"); err != nil {
		return err
	}
	return nil
}

func validateCommission(c AttemptCommission) error {
	if c.RecordType != "attempt_commission" {
		return fmt.Errorf("lifecycle_rules: commission record_type must be attempt_commission, got %q", c.RecordType)
	}
	if c.SchemaVersion != SchemaLifecycle {
		return fmt.Errorf("lifecycle_rules: commission schema_version must be %q, got %q", SchemaLifecycle, c.SchemaVersion)
	}
	if c.KernelVersion != SchemaKernel {
		return fmt.Errorf("lifecycle_rules: commission kernel_version must be %q, got %q", SchemaKernel, c.KernelVersion)
	}
	if !validIdentifier(c.CommissionID) {
		return fmt.Errorf("lifecycle_rules: commission commission_id must be a nonempty identifier")
	}
	if !validIdentifier(c.RunID) || !validIdentifier(c.JournalID) {
		return fmt.Errorf("lifecycle_rules: commission run_id/journal_id must be nonempty identifiers")
	}
	if !validDigest(c.ManifestHash) {
		return fmt.Errorf("lifecycle_rules: commission manifest_hash %q is not a valid digest", c.ManifestHash)
	}
	if err := validateEvidenceRefShape(c.AdmissionRef, "commission.admission_ref"); err != nil {
		return err
	}
	if !validIdentifier(c.CommissionedBy) {
		return fmt.Errorf("lifecycle_rules: commission commissioned_by must be a nonempty identifier")
	}
	if err := validateTimePointShape(c.CommissionedAt, "commission.commissioned_at"); err != nil {
		return err
	}
	a := c.Attempt
	if !validIdentifier(a.AttemptID) {
		return fmt.Errorf("lifecycle_rules: commission attempt_id must be a nonempty identifier")
	}
	if a.Kind != "practice" && a.Kind != "production" {
		return fmt.Errorf("lifecycle_rules: commission attempt kind %q must be practice or production", a.Kind)
	}
	if a.TargetClass != "laboratory_fixture" && a.TargetClass != "employer_origin" {
		return fmt.Errorf("lifecycle_rules: commission target_class %q is invalid", a.TargetClass)
	}
	if !validIdentifier(a.TargetID) {
		return fmt.Errorf("lifecycle_rules: commission target_id must be a nonempty identifier")
	}
	if a.EvaluationPartition != "held_in" && a.EvaluationPartition != "held_out" {
		return fmt.Errorf("lifecycle_rules: commission evaluation_partition %q is invalid", a.EvaluationPartition)
	}
	if a.TargetClass == "laboratory_fixture" && (a.Kind != "practice" || a.EvaluationPartition != "held_in") {
		return fmt.Errorf("lifecycle_rules: laboratory_fixture attempts are practice held_in")
	}
	if !validIdentifier(c.CandidateID) {
		return fmt.Errorf("lifecycle_rules: commission candidate_id must be a nonempty identifier")
	}
	if c.CandidateProfile == nil {
		return fmt.Errorf("lifecycle_rules: commission candidate_profile is an in-band null")
	}
	if _, ok := asMissing(c.CandidateProfile); !ok {
		if art, ok := asArtifactValue(c.CandidateProfile); ok {
			if err := validateArtifact(art, "commission.candidate_profile"); err != nil {
				return err
			}
		} else {
			return fmt.Errorf("lifecycle_rules: commission candidate_profile must be an artifact or Missing")
		}
	}
	if !validIdentifier(c.Job.JobID) {
		return fmt.Errorf("lifecycle_rules: commission job job_id must be a nonempty identifier")
	}
	if err := validateArtifact(c.Job.Snapshot, "commission.job.snapshot"); err != nil {
		return err
	}
	if c.SelectionEvidence == nil {
		return fmt.Errorf("lifecycle_rules: commission selection_evidence is an in-band null")
	}
	if _, ok := asMissing(c.SelectionEvidence); !ok {
		if art, ok := asArtifactValue(c.SelectionEvidence); ok {
			if err := validateArtifact(art, "commission.selection_evidence"); err != nil {
				return err
			}
		} else {
			return fmt.Errorf("lifecycle_rules: commission selection_evidence must be an artifact or Missing")
		}
	}
	if err := validateArtifact(c.Task, "commission.task"); err != nil {
		return err
	}
	if !validDigest(c.TaskSemanticHash) {
		return fmt.Errorf("lifecycle_rules: commission task_semantic_hash %q is not a valid digest", c.TaskSemanticHash)
	}
	if c.InitialMaterials == nil {
		return fmt.Errorf("lifecycle_rules: commission initial_materials is an in-band null: use an array")
	}
	for i, m := range c.InitialMaterials {
		if err := validateArtifact(m, fmt.Sprintf("commission.initial_materials[%d]", i)); err != nil {
			return err
		}
	}
	ex := c.Execution
	if ex.Mode != "manual" && ex.Mode != "subject" {
		return fmt.Errorf("lifecycle_rules: commission execution mode %q must be manual or subject", ex.Mode)
	}
	if ex.Subject == nil || ex.ConnectorVersion == nil || ex.BindingVersion == nil {
		return fmt.Errorf("lifecycle_rules: commission execution subject/connector/binding must not be in-band nulls")
	}
	if ex.Mode == "manual" {
		if !isMissingWithReason(ex.Subject, "not_applicable") {
			return fmt.Errorf("lifecycle_rules: manual execution subject must be Missing(not_applicable)")
		}
		if !isMissingWithReason(ex.ConnectorVersion, "not_applicable") {
			return fmt.Errorf("lifecycle_rules: manual connector_version must be Missing(not_applicable)")
		}
		if !isMissingWithReason(ex.BindingVersion, "not_applicable") {
			return fmt.Errorf("lifecycle_rules: manual binding_version must be Missing(not_applicable)")
		}
	} else {
		if isMissing(ex.Subject) {
			return fmt.Errorf("lifecycle_rules: subject-mode execution subject must be a SubjectIdentity")
		}
		if _, ok := asStringValue(ex.ConnectorVersion); !ok {
			return fmt.Errorf("lifecycle_rules: subject-mode connector_version must be an identifier")
		}
		if _, ok := asStringValue(ex.BindingVersion); !ok {
			return fmt.Errorf("lifecycle_rules: subject-mode binding_version must be an identifier")
		}
	}
	if err := validateAuthorityBinding(c.Owners.Dispatch, AxisDispatch, "connector"); err != nil {
		return err
	}
	if err := validateAuthorityBinding(c.Owners.Observation, AxisObservation, "connector"); err != nil {
		return err
	}
	if err := validateAuthorityBinding(c.Owners.Execution, AxisExecution, "subject"); err != nil {
		return err
	}
	if err := validateAuthorityBinding(c.Owners.Application, AxisApplication, "origin"); err != nil {
		return err
	}
	if err := validateAuthorityBinding(c.Owners.Report, AxisReport, "reconciler"); err != nil {
		return err
	}
	if ex.Mode == "manual" {
		if !isMissingWithReason(c.Owners.Execution.SourceID, "not_applicable") {
			return fmt.Errorf("lifecycle_rules: manual execution source_id must be Missing(not_applicable)")
		}
		if !isMissingWithReason(c.Owners.Execution.WriterID, "not_applicable") {
			return fmt.Errorf("lifecycle_rules: manual execution writer_id must be Missing(not_applicable)")
		}
	} else {
		if _, ok := asStringValue(c.Owners.Execution.SourceID); !ok {
			return fmt.Errorf("lifecycle_rules: subject-mode execution source_id must be an identifier")
		}
		if _, ok := asStringValue(c.Owners.Execution.WriterID); !ok {
			return fmt.Errorf("lifecycle_rules: subject-mode execution writer_id must be an identifier")
		}
	}
	// Other owner source/writer IDs must be present identifiers.
	for _, axis := range []string{AxisDispatch, AxisObservation, AxisApplication, AxisReport} {
		b, _ := bindingForAxis(c.Owners, axis)
		if _, ok := asStringValue(b.SourceID); !ok {
			return fmt.Errorf("lifecycle_rules: commission owners.%s source_id must be an identifier", axis)
		}
		if _, ok := asStringValue(b.WriterID); !ok {
			return fmt.Errorf("lifecycle_rules: commission owners.%s writer_id must be an identifier", axis)
		}
	}
	// application.source_id equals the attempt target.
	if src, ok := asStringValue(c.Owners.Application.SourceID); ok && src != a.TargetID {
		return fmt.Errorf("lifecycle_rules: application source_id %q must equal attempt target_id %q", src, a.TargetID)
	}
	// A report writer must not hold execution/application write authority.
	if rw, ok := asStringValue(c.Owners.Report.WriterID); ok {
		if ew, ok := asStringValue(c.Owners.Execution.WriterID); ok && rw == ew {
			return fmt.Errorf("lifecycle_rules: report writer must not hold execution write authority")
		}
		if aw, ok := asStringValue(c.Owners.Application.WriterID); ok && rw == aw {
			return fmt.Errorf("lifecycle_rules: report writer must not hold application write authority")
		}
	}
	if !validIdentifier(c.IdempotencyKey) {
		return fmt.Errorf("lifecycle_rules: commission idempotency_key must be a nonempty identifier")
	}
	if len(c.AuthorizationRefs) == 0 {
		return fmt.Errorf("lifecycle_rules: commission authorization_refs needs at least one reference")
	}
	for i, r := range c.AuthorizationRefs {
		if err := validateEvidenceRefShape(r, fmt.Sprintf("commission.authorization_refs[%d]", i)); err != nil {
			return err
		}
	}
	if c.RecoveryReviewRefs == nil {
		return fmt.Errorf("lifecycle_rules: commission recovery_review_refs is an in-band null: use an array")
	}
	for i, r := range c.RecoveryReviewRefs {
		if err := validateEvidenceRefShape(r, fmt.Sprintf("commission.recovery_review_refs[%d]", i)); err != nil {
			return err
		}
	}
	for _, dl := range []struct {
		name string
		v    DurationLimit
	}{
		{"active_limit", c.ObservationPolicy.ActiveLimit},
		{"drain_limit", c.ObservationPolicy.DrainLimit},
		{"native_cancel_wait_limit", c.ObservationPolicy.NativeCancelWaitLimit},
		{"cleanup_wait_limit", c.ObservationPolicy.CleanupWaitLimit},
	} {
		if dl.v.Kind != "exact" || dl.v.Unit != "ms" || dl.v.Value < 0 {
			return fmt.Errorf("lifecycle_rules: commission observation_policy %s must be an exact ms bound >= 0", dl.name)
		}
	}
	if c.ObservationPolicy.FixtureCloseAction != "seal_after_drain" && c.ObservationPolicy.FixtureCloseAction != "not_applicable" {
		return fmt.Errorf("lifecycle_rules: commission fixture_close_action %q is invalid", c.ObservationPolicy.FixtureCloseAction)
	}
	if a.TargetClass == "employer_origin" && c.ObservationPolicy.FixtureCloseAction != "not_applicable" {
		return fmt.Errorf("lifecycle_rules: employer_origin attempts require fixture_close_action not_applicable")
	}
	if err := validateVersionPin(c.OriginPolicy, "commission.origin_policy"); err != nil {
		return err
	}
	return nil
}

// ---------------------------------------------------------------------------
// Axis header validation.
// ---------------------------------------------------------------------------

func validateAxisHeader(commission AttemptCommission, history []AxisRevision, next AxisRevision) error {
	if next.RecordType != RecordAxis {
		return fmt.Errorf("lifecycle_rules: record_type must be %q, got %q", RecordAxis, next.RecordType)
	}
	if next.SchemaVersion != SchemaLifecycle {
		return fmt.Errorf("lifecycle_rules: schema_version must be %q, got %q", SchemaLifecycle, next.SchemaVersion)
	}
	if !validAxes[next.Axis] {
		return fmt.Errorf("lifecycle_rules: axis %q is invalid", next.Axis)
	}
	if next.Attempt.AttemptID != commission.Attempt.AttemptID || next.Attempt.Kind != commission.Attempt.Kind {
		return fmt.Errorf("lifecycle_rules: attempt (%q,%q) must match commission (%q,%q)",
			next.Attempt.AttemptID, next.Attempt.Kind,
			commission.Attempt.AttemptID, commission.Attempt.Kind)
	}
	if !validDigest(next.CommissionDigest) {
		return fmt.Errorf("lifecycle_rules: commission_digest %q is not a valid digest", next.CommissionDigest)
	}
	// Manual dispatch/execution stay unpublished.
	if commission.Execution.Mode == "manual" && (next.Axis == AxisDispatch || next.Axis == AxisExecution) {
		return fmt.Errorf("lifecycle_rules: manual %s stays revision zero with not_applicable: no %s publication is authorized", next.Axis, next.Axis)
	}
	binding, _ := bindingForAxis(commission.Owners, next.Axis)
	if next.OwnerDomain != binding.OwnerDomain {
		return fmt.Errorf("lifecycle_rules: owner_domain %q must match commission binding %q for axis %s",
			next.OwnerDomain, binding.OwnerDomain, next.Axis)
	}
	wantWriter, ok := asStringValue(binding.WriterID)
	if !ok {
		return fmt.Errorf("lifecycle_rules: axis %s has no authorized writer under this commission", next.Axis)
	}
	if next.WriterID != wantWriter {
		return fmt.Errorf("lifecycle_rules: writer_id %q is not the bound writer %q for axis %s",
			next.WriterID, wantWriter, next.Axis)
	}
	if next.Revision < 1 {
		return fmt.Errorf("lifecycle_rules: revision starts at 1, got %d", next.Revision)
	}
	if next.PreviousRevision != next.Revision-1 {
		return fmt.Errorf("lifecycle_rules: revision %d requires previous_revision %d, got %d",
			next.Revision, next.Revision-1, next.PreviousRevision)
	}
	// History fencing: same axis/attempt, contiguous revisions, stable digest
	// and writer, no key reuse with different bytes.
	for i, h := range history {
		if h.Axis != next.Axis {
			return fmt.Errorf("lifecycle_rules: history[%d] axis %q must match next axis %q", i, h.Axis, next.Axis)
		}
		if h.Attempt != next.Attempt {
			return fmt.Errorf("lifecycle_rules: history[%d] attempt must match next attempt", i)
		}
		if want := int64(i + 1); h.Revision != want {
			return fmt.Errorf("lifecycle_rules: history revisions must be contiguous from 1: history[%d] carries %d, want %d", i, h.Revision, want)
		}
		if h.PreviousRevision != h.Revision-1 {
			return fmt.Errorf("lifecycle_rules: history[%d] previous_revision must be revision-1", i)
		}
		if h.CommissionDigest != next.CommissionDigest {
			return fmt.Errorf("lifecycle_rules: history[%d] commission_digest must match next: publications never rebind the commission", i)
		}
		if h.OwnerDomain != next.OwnerDomain || h.WriterID != next.WriterID {
			return fmt.Errorf("lifecycle_rules: history[%d] owner/writer must match next: one writer owns each axis", i)
		}
		if h.Revision == next.Revision {
			same, err := canonicalEqual(h.Value, next.Value)
			if err != nil {
				return fmt.Errorf("lifecycle_rules: cannot compare revision %d bytes: %v", h.Revision, err)
			}
			if !same {
				return fmt.Errorf("lifecycle_rules: integrity conflict: different value under key (%q,%q,%q,%d)",
					next.Attempt.AttemptID, next.Attempt.Kind, next.Axis, next.Revision)
			}
			return fmt.Errorf("lifecycle_rules: revision %d is already published", next.Revision)
		}
	}
	if len(history) == 0 {
		if next.PreviousRevision != 0 || next.Revision != 1 {
			return fmt.Errorf("lifecycle_rules: first %s revision must be revision 1 with previous 0", next.Axis)
		}
	} else {
		last := history[len(history)-1]
		if next.PreviousRevision != last.Revision {
			return fmt.Errorf("lifecycle_rules: next previous_revision %d must equal history head %d",
				next.PreviousRevision, last.Revision)
		}
		if next.Revision != last.Revision+1 {
			return fmt.Errorf("lifecycle_rules: next revision must be previous_revision + 1")
		}
	}
	if err := validatePrefix(next.EvidencePrefix, "evidence_prefix"); err != nil {
		return err
	}
	if next.EvidenceRefs == nil {
		return fmt.Errorf("lifecycle_rules: evidence_refs is an in-band null: use an array with at least one support reference")
	}
	if len(next.EvidenceRefs) == 0 {
		return fmt.Errorf("lifecycle_rules: evidence_refs needs at least one support reference")
	}
	if next.Value == nil {
		return fmt.Errorf("lifecycle_rules: value is an in-band null: publish a complete typed value")
	}
	return nil
}

// validatePublication checks one pinned publication for reconciliation: header
// identity, ownership, prefix, resolvable support, and axis value shape. It
// does not enforce history fencing (the caller pins exact revisions).
func validatePublication(commission AttemptCommission, pub AxisRevision, evidence []JournalEnvelope) error {
	if pub.RecordType != RecordAxis {
		return fmt.Errorf("lifecycle_rules: record_type must be %q, got %q", RecordAxis, pub.RecordType)
	}
	if pub.SchemaVersion != SchemaLifecycle {
		return fmt.Errorf("lifecycle_rules: schema_version must be %q, got %q", SchemaLifecycle, pub.SchemaVersion)
	}
	if !validAxes[pub.Axis] {
		return fmt.Errorf("lifecycle_rules: axis %q is invalid", pub.Axis)
	}
	if pub.Attempt.AttemptID != commission.Attempt.AttemptID || pub.Attempt.Kind != commission.Attempt.Kind {
		return fmt.Errorf("lifecycle_rules: publication attempt must match commission")
	}
	if !validDigest(pub.CommissionDigest) {
		return fmt.Errorf("lifecycle_rules: commission_digest %q is not a valid digest", pub.CommissionDigest)
	}
	binding, _ := bindingForAxis(commission.Owners, pub.Axis)
	if pub.OwnerDomain != binding.OwnerDomain {
		return fmt.Errorf("lifecycle_rules: owner_domain %q must match commission binding for axis %s", pub.OwnerDomain, pub.Axis)
	}
	wantWriter, ok := asStringValue(binding.WriterID)
	if !ok || pub.WriterID != wantWriter {
		return fmt.Errorf("lifecycle_rules: writer %q is not the bound writer for axis %s", pub.WriterID, pub.Axis)
	}
	if pub.Revision < 1 || pub.PreviousRevision != pub.Revision-1 {
		return fmt.Errorf("lifecycle_rules: revision %d must satisfy previous_revision + 1", pub.Revision)
	}
	if err := validatePrefix(pub.EvidencePrefix, "evidence_prefix"); err != nil {
		return err
	}
	if len(pub.EvidenceRefs) == 0 {
		return fmt.Errorf("lifecycle_rules: evidence_refs needs at least one support reference")
	}
	if pub.Value == nil {
		return fmt.Errorf("lifecycle_rules: value is an in-band null")
	}
	if err := resolveRefs(pub.EvidencePrefix, evidence, pub.EvidenceRefs, "evidence_refs"); err != nil {
		return err
	}
	switch pub.Axis {
	case AxisDispatch:
		v, err := parseDispatchValue(pub.Value)
		if err != nil {
			return err
		}
		return validateDispatchShape(v, pub.EvidencePrefix, evidence)
	case AxisObservation:
		v, err := parseObservationValue(pub.Value)
		if err != nil {
			return err
		}
		return validateObservationShape(commission, v, pub.EvidencePrefix, evidence)
	case AxisExecution:
		v, err := parseExecutionValue(pub.Value)
		if err != nil {
			return err
		}
		return validateExecutionShape(v, pub.EvidencePrefix, evidence)
	case AxisApplication:
		v, err := parseApplicationValue(pub.Value)
		if err != nil {
			return err
		}
		return validateApplicationShape(commission, v, pub.EvidencePrefix, evidence)
	case AxisReport:
		v, err := parseReportValue(pub.Value)
		if err != nil {
			return err
		}
		return validateReportShape(v, pub.EvidencePrefix, evidence)
	default:
		return fmt.Errorf("lifecycle_rules: axis %q is invalid", pub.Axis)
	}
}

// ---------------------------------------------------------------------------
// Dispatch.
// ---------------------------------------------------------------------------

var dispatchTransitions = map[string]map[string]bool{
	"unpublished": {DispatchNotStarted: true, DispatchPrepared: true, DispatchRejected: true},
	DispatchNotStarted: {DispatchPrepared: true, DispatchRejected: true},
	DispatchPrepared:   {DispatchDispatching: true, DispatchRejected: true},
	DispatchDispatching: {DispatchAccepted: true, DispatchRejected: true, DispatchUncertain: true},
	DispatchUncertain:  {DispatchUncertain: true, DispatchAccepted: true, DispatchRejected: true},
	DispatchAccepted:   {DispatchAccepted: true},
	DispatchRejected:   {DispatchRejected: true},
}

func validateDispatchShape(v DispatchValue, prefix JournalPrefix, evidence []JournalEnvelope) error {
	if !validDispatchStates[v.State] {
		return fmt.Errorf("lifecycle_rules: dispatch state %q is invalid", v.State)
	}
	if v.LocalHandle == nil || v.NativeRunID == nil || v.RequestDigest == nil || v.Reason == nil {
		return fmt.Errorf("lifecycle_rules: dispatch local_handle/native_run_id/request_digest/reason must not be in-band nulls")
	}
	if _, ok := asMissing(v.LocalHandle); !ok {
		if _, ok := asStringValue(v.LocalHandle); !ok {
			return fmt.Errorf("lifecycle_rules: dispatch local_handle must be an identifier or Missing")
		}
	}
	if _, ok := asMissing(v.NativeRunID); !ok {
		if _, ok := asStringValue(v.NativeRunID); !ok {
			return fmt.Errorf("lifecycle_rules: dispatch native_run_id must be an identifier or Missing")
		}
	}
	if _, ok := asMissing(v.RequestDigest); !ok {
		s, ok := v.RequestDigest.(string)
		if !ok || !validDigest(s) {
			return fmt.Errorf("lifecycle_rules: dispatch request_digest must be a digest or Missing")
		}
	}
	if _, ok := asMissing(v.Reason); !ok {
		if _, ok := asStringValue(v.Reason); !ok {
			return fmt.Errorf("lifecycle_rules: dispatch reason must be a string or Missing")
		}
	}
	if v.DeliveryRefs == nil || v.AcceptanceRefs == nil || v.RecoveryAuthorizationRefs == nil {
		return fmt.Errorf("lifecycle_rules: dispatch delivery/acceptance/recovery refs must not be in-band nulls")
	}
	if err := resolveRefs(prefix, evidence, v.DeliveryRefs, "dispatch.delivery_refs"); err != nil {
		return err
	}
	if err := resolveRefs(prefix, evidence, v.AcceptanceRefs, "dispatch.acceptance_refs"); err != nil {
		return err
	}
	if err := resolveRefs(prefix, evidence, v.RecoveryAuthorizationRefs, "dispatch.recovery_authorization_refs"); err != nil {
		return err
	}
	switch v.State {
	case DispatchNotStarted:
		if !isMissing(v.NativeRunID) {
			return fmt.Errorf("lifecycle_rules: not_started native_run_id must be Missing")
		}
		if len(v.DeliveryRefs) != 0 || len(v.AcceptanceRefs) != 0 {
			return fmt.Errorf("lifecycle_rules: not_started carries no delivery or acceptance evidence")
		}
	case DispatchPrepared:
		if _, ok := asStringValue(v.RequestDigest); !ok {
			// RequestDigest is a digest string, not a plain identifier check.
			s, ok := v.RequestDigest.(string)
			if !ok || !validDigest(s) {
				return fmt.Errorf("lifecycle_rules: prepared requires a request digest")
			}
		} else if s, _ := v.RequestDigest.(string); !validDigest(s) {
			return fmt.Errorf("lifecycle_rules: prepared requires a request digest")
		}
		if len(v.DeliveryRefs) != 0 || len(v.AcceptanceRefs) != 0 {
			return fmt.Errorf("lifecycle_rules: prepare is non-executing: prepared carries no delivery or acceptance evidence")
		}
		if !isMissing(v.NativeRunID) {
			return fmt.Errorf("lifecycle_rules: prepared native_run_id must be Missing: no native run exists before delivery")
		}
	case DispatchDispatching:
		if _, ok := asStringValue(v.LocalHandle); !ok {
			return fmt.Errorf("lifecycle_rules: dispatching requires a durable connector-local handle")
		}
		if s, ok := v.RequestDigest.(string); !ok || !validDigest(s) {
			return fmt.Errorf("lifecycle_rules: dispatching requires the intended request digest")
		}
		if len(v.DeliveryRefs) == 0 {
			return fmt.Errorf("lifecycle_rules: dispatching requires recorded intent/delivery evidence")
		}
		if !isMissing(v.NativeRunID) {
			return fmt.Errorf("lifecycle_rules: dispatching native_run_id must be Missing until a native run is actually received and correlated")
		}
		if len(v.AcceptanceRefs) != 0 {
			return fmt.Errorf("lifecycle_rules: dispatching carries no native acceptance: local Start acknowledgement is not native acceptance")
		}
	case DispatchUncertain:
		if _, ok := asStringValue(v.LocalHandle); !ok {
			return fmt.Errorf("lifecycle_rules: uncertain requires the durable connector-local handle")
		}
		if s, ok := v.RequestDigest.(string); !ok || !validDigest(s) {
			return fmt.Errorf("lifecycle_rules: uncertain requires the intended request digest")
		}
		if len(v.DeliveryRefs) == 0 {
			return fmt.Errorf("lifecycle_rules: uncertain requires the preserved delivery evidence")
		}
	case DispatchAccepted:
		if _, ok := asStringValue(v.LocalHandle); !ok {
			return fmt.Errorf("lifecycle_rules: accepted requires the durable connector-local handle")
		}
		if s, ok := v.RequestDigest.(string); !ok || !validDigest(s) {
			return fmt.Errorf("lifecycle_rules: accepted requires the intended request digest")
		}
		if len(v.DeliveryRefs) == 0 {
			return fmt.Errorf("lifecycle_rules: accepted requires delivery evidence")
		}
		if len(v.AcceptanceRefs) == 0 {
			return fmt.Errorf("lifecycle_rules: accepted requires correlated native acceptance evidence: local acknowledgement is not native acceptance")
		}
		if _, ok := asStringValue(v.NativeRunID); !ok {
			return fmt.Errorf("lifecycle_rules: accepted requires the correlated native run ID")
		}
	case DispatchRejected:
		if _, ok := asStringValue(v.Reason); !ok {
			return fmt.Errorf("lifecycle_rules: rejected requires a reason")
		}
	}
	return nil
}

func validateDispatchTransition(history []AxisRevision, next AxisRevision, evidence []JournalEnvelope) error {
	nextVal, err := parseDispatchValue(next.Value)
	if err != nil {
		return err
	}
	if err := validateDispatchShape(nextVal, next.EvidencePrefix, evidence); err != nil {
		return err
	}
	prevState := "unpublished"
	var prevVal *DispatchValue
	if len(history) > 0 {
		pv, err := parseDispatchValue(history[len(history)-1].Value)
		if err != nil {
			return err
		}
		prevVal = &pv
		prevState = pv.State
	}
	allowed, ok := dispatchTransitions[prevState]
	if !ok || !allowed[nextVal.State] {
		return fmt.Errorf("lifecycle_rules: dispatch transition %s -> %s is not allowed", prevState, nextVal.State)
	}
	// Rejection after possible delivery requires non-acceptance evidence.
	if nextVal.State == DispatchRejected && (prevState == DispatchDispatching || prevState == DispatchUncertain) {
		if _, ok := asStringValue(nextVal.Reason); !ok {
			return fmt.Errorf("lifecycle_rules: rejection after possible delivery requires a non-acceptance reason with evidence")
		}
		// Non-acceptance must be evidenced, not merely asserted: the axis
		// support plus at least one dispatch-level reference must exist.
		if len(nextVal.DeliveryRefs) == 0 && len(nextVal.AcceptanceRefs) == 0 && len(nextVal.RecoveryAuthorizationRefs) == 0 {
			return fmt.Errorf("lifecycle_rules: rejection after possible delivery requires non-acceptance evidence")
		}
	}
	// Same-state revisions add evidence, never another execution.
	if prevVal != nil && prevVal.State == nextVal.State {
		same, err := canonicalEqual(
			map[string]any{"h": prevVal.LocalHandle, "d": prevVal.RequestDigest, "n": prevVal.NativeRunID},
			map[string]any{"h": nextVal.LocalHandle, "d": nextVal.RequestDigest, "n": nextVal.NativeRunID},
		)
		if err != nil || !same {
			return fmt.Errorf("lifecycle_rules: same-state dispatch revisions add evidence: handle/request/native identity must not change")
		}
		if !isSubsetRefs(prevVal.DeliveryRefs, nextVal.DeliveryRefs) {
			return fmt.Errorf("lifecycle_rules: same-state dispatch revisions must preserve delivery evidence")
		}
		if !isSubsetRefs(prevVal.AcceptanceRefs, nextVal.AcceptanceRefs) {
			return fmt.Errorf("lifecycle_rules: same-state dispatch revisions must preserve acceptance evidence")
		}
		if !isSubsetRefs(prevVal.RecoveryAuthorizationRefs, nextVal.RecoveryAuthorizationRefs) {
			return fmt.Errorf("lifecycle_rules: same-state dispatch revisions must preserve recovery evidence")
		}
	}
	// Native acceptance is not execution completion: dispatch never asserts an
	// execution outcome. (Enforced structurally: DispatchValue has no outcome
	// field, and accepted still requires separate execution claims.)
	return nil
}

// ---------------------------------------------------------------------------
// Observation.
// ---------------------------------------------------------------------------

var observationTransitions = map[string]map[string]bool{
	"unpublished": {ObsNotOpened: true, ObsOpen: true, ObsClosed: true},
	ObsNotOpened:  {ObsOpen: true, ObsClosed: true},
	ObsOpen:       {ObsOpen: true, ObsDraining: true, ObsClosed: true},
	ObsDraining:   {ObsDraining: true, ObsClosed: true},
	ObsClosed:     {ObsClosed: true},
}

func validateCloseSnapshot(cs CloseSnapshot, prefix JournalPrefix, evidence []JournalEnvelope) error {
	if !validIdentifier(cs.ClosureID) {
		return fmt.Errorf("lifecycle_rules: close snapshot closure_id must be a nonempty identifier")
	}
	if err := validateEvidenceRefShape(cs.BoundaryRef, "observation.at_close.boundary_ref"); err != nil {
		return err
	}
	if _, err := journal_rules.ResolveEvidence(prefix, evidence, cs.BoundaryRef); err != nil {
		return fmt.Errorf("lifecycle_rules: observation.at_close.boundary_ref does not resolve: %v", err)
	}
	for _, pin := range []struct {
		name string
		v    DomainPin
	}{
		{"dispatch", cs.KnownVersions.Dispatch},
		{"execution", cs.KnownVersions.Execution},
		{"application", cs.KnownVersions.Application},
		{"report", cs.KnownVersions.Report},
	} {
		if err := validateDomainPin(pin.v, "observation.at_close.known_versions."+pin.name); err != nil {
			return err
		}
	}
	switch cs.ExecutionKnowledge {
	case "running", "terminal", "unknown", "not_applicable":
	default:
		return fmt.Errorf("lifecycle_rules: execution_knowledge %q is invalid", cs.ExecutionKnowledge)
	}
	switch cs.ApplicationKnowledge {
	case "committed", "not_committed", "unknown":
	default:
		return fmt.Errorf("lifecycle_rules: application_knowledge %q is invalid", cs.ApplicationKnowledge)
	}
	if cs.ExecutionEvidenceRefs == nil || cs.ApplicationEvidenceRefs == nil || cs.Limitations == nil {
		return fmt.Errorf("lifecycle_rules: close snapshot evidence/limitations must not be in-band nulls")
	}
	if err := resolveRefs(prefix, evidence, cs.ExecutionEvidenceRefs, "observation.at_close.execution_evidence_refs"); err != nil {
		return err
	}
	if err := resolveRefs(prefix, evidence, cs.ApplicationEvidenceRefs, "observation.at_close.application_evidence_refs"); err != nil {
		return err
	}
	return nil
}

func validateControlObservation(co ControlObservation, prefix JournalPrefix, evidence []JournalEnvelope, clocks []clock_rules.ClockDescriptor) error {
	if !validIdentifier(co.ControlEventID) {
		return fmt.Errorf("lifecycle_rules: control control_event_id must be a nonempty identifier")
	}
	if !validIdentifier(co.OperationID) {
		return fmt.Errorf("lifecycle_rules: control operation_id must be a nonempty identifier")
	}
	if !validControlOps[co.Operation] {
		return fmt.Errorf("lifecycle_rules: control operation %q is invalid", co.Operation)
	}
	switch co.Operation {
	case "RequestNativeCancel":
		if co.TargetScope != "native_execution" {
			return fmt.Errorf("lifecycle_rules: RequestNativeCancel targets native_execution")
		}
	case "CloseObservationConnection":
		if co.TargetScope != "observation_connection" {
			return fmt.Errorf("lifecycle_rules: CloseObservationConnection targets observation_connection")
		}
	case "ReleaseNativeContext":
		if co.TargetScope != "native_context" {
			return fmt.Errorf("lifecycle_rules: ReleaseNativeContext targets native_context")
		}
	case "Contain":
		switch co.TargetScope {
		case "fixture_mutation_authority", "local_process", "deployment_slot", "harness_resources":
		default:
			return fmt.Errorf("lifecycle_rules: Contain target_scope %q is invalid", co.TargetScope)
		}
	}
	switch co.Disposition {
	case "not_requested", "unsupported", "requested", "acknowledged", "effect_observed", "unknown":
	default:
		return fmt.Errorf("lifecycle_rules: control disposition %q is invalid", co.Disposition)
	}
	if err := validateTimePointShape(co.At, "control.at"); err != nil {
		return err
	}
	if err := validateEvidenceRefShape(co.AuthorizationRef, "control.authorization_ref"); err != nil {
		return err
	}
	if _, err := journal_rules.ResolveEvidence(prefix, evidence, co.AuthorizationRef); err != nil {
		return fmt.Errorf("lifecycle_rules: control.authorization_ref does not resolve: %v", err)
	}
	// Capability ref is optional Missing or a descriptor.
	if co.CapabilityRef == nil {
		return fmt.Errorf("lifecycle_rules: control capability_ref is an in-band null")
	}
	if _, ok := asMissing(co.CapabilityRef); !ok {
		raw, err := json.Marshal(co.CapabilityRef)
		if err != nil {
			return fmt.Errorf("lifecycle_rules: control capability_ref: %v", err)
		}
		var cr CapabilityReference
		if err := json.Unmarshal(raw, &cr); err != nil {
			return fmt.Errorf("lifecycle_rules: control capability_ref must be a descriptor or Missing")
		}
		if !validDigest(cr.DescriptorDigest) || !validIdentifier(cr.CapabilityID) {
			return fmt.Errorf("lifecycle_rules: control capability_ref descriptor is invalid")
		}
		if err := validateEvidenceRefShape(cr.EvidenceRef, "control.capability_ref.evidence_ref"); err != nil {
			return err
		}
	}
	switch co.Opportunity.State {
	case "exposed", "unexposed", "blocked":
	default:
		return fmt.Errorf("lifecycle_rules: control opportunity state %q is invalid", co.Opportunity.State)
	}
	if len(co.Opportunity.EvidenceRefs) == 0 {
		return fmt.Errorf("lifecycle_rules: control opportunity needs support evidence")
	}
	if err := resolveRefs(prefix, evidence, co.Opportunity.EvidenceRefs, "control.opportunity.evidence_refs"); err != nil {
		return err
	}
	if !validIdentifier(co.Opportunity.Rationale) {
		return fmt.Errorf("lifecycle_rules: control opportunity rationale must be nonempty")
	}
	// Request/response refs are Maybe refs.
	for _, f := range []struct {
		name string
		v    any
	}{
		{"request_ref", co.RequestRef}, {"response_ref", co.ResponseRef},
	} {
		if f.v == nil {
			return fmt.Errorf("lifecycle_rules: control %s is an in-band null", f.name)
		}
		if _, ok := asMissing(f.v); ok {
			continue
		}
		r, ok := asEvidenceRefValue(f.v)
		if !ok {
			return fmt.Errorf("lifecycle_rules: control %s must be an EvidenceRef or Missing", f.name)
		}
		if err := validateEvidenceRefShape(r, "control."+f.name); err != nil {
			return err
		}
		if _, err := journal_rules.ResolveEvidence(prefix, evidence, r); err != nil {
			return fmt.Errorf("lifecycle_rules: control.%s does not resolve: %v", f.name, err)
		}
	}
	if co.ResponseChecks == nil {
		return fmt.Errorf("lifecycle_rules: control response_checks is an in-band null")
	}
	if _, ok := asMissing(co.ResponseChecks); !ok {
		raw, err := json.Marshal(co.ResponseChecks)
		if err != nil {
			return fmt.Errorf("lifecycle_rules: control response_checks: %v", err)
		}
		var sc SourceChecks
		if err := json.Unmarshal(raw, &sc); err != nil {
			return fmt.Errorf("lifecycle_rules: control response_checks must be SourceChecks or Missing")
		}
		if err := validateSourceChecks(sc, "control.response_checks", prefix, evidence, false); err != nil {
			return err
		}
	}
	if co.NativeClaimRefs == nil || co.EffectRefs == nil || co.AffectedAttempts == nil || co.Measurements == nil || co.Limitations == nil {
		return fmt.Errorf("lifecycle_rules: control claim/effect/attempt/measurement/limitation lists must not be in-band nulls")
	}
	if err := resolveRefs(prefix, evidence, co.NativeClaimRefs, "control.native_claim_refs"); err != nil {
		return err
	}
	if err := resolveRefs(prefix, evidence, co.EffectRefs, "control.effect_refs"); err != nil {
		return err
	}
	if co.Disposition == "acknowledged" {
		if _, ok := asEvidenceRefValue(co.ResponseRef); !ok {
			return fmt.Errorf("lifecycle_rules: acknowledged controls cite their response")
		}
	}
	if co.Disposition == "effect_observed" && len(co.EffectRefs) == 0 {
		return fmt.Errorf("lifecycle_rules: effect_observed controls cite observed effects")
	}
	for i, m := range co.Measurements {
		if len(m.EvidenceRefs) == 0 {
			return fmt.Errorf("lifecycle_rules: control.measurements[%d] needs support evidence", i)
		}
		if err := resolveRefs(prefix, evidence, m.EvidenceRefs, fmt.Sprintf("control.measurements[%d].evidence_refs", i)); err != nil {
			return err
		}
		cm, err := toClockRulesMeasurement(m.Measurement, fmt.Sprintf("control.measurements[%d].measurement", i))
		if err != nil {
			return err
		}
		if err := clock_rules.ValidateMeasurement(cm, clocks); err != nil {
			return fmt.Errorf("lifecycle_rules: control.measurements[%d]: %v", i, err)
		}
	}
	return nil
}

func validateObservationShape(commission AttemptCommission, v ObservationValue, prefix JournalPrefix, evidence []JournalEnvelope) error {
	_ = commission
	if !validObsStates[v.State] {
		return fmt.Errorf("lifecycle_rules: observation state %q is invalid", v.State)
	}
	if !validIdentifier(v.WindowID) {
		return fmt.Errorf("lifecycle_rules: observation window_id must be a nonempty identifier")
	}
	for _, f := range []struct {
		name string
		v    any
	}{
		{"opened_at", v.OpenedAt}, {"active_deadline", v.ActiveDeadline},
		{"drain_started_at", v.DrainStartedAt}, {"drain_deadline", v.DrainDeadline},
		{"closed_at", v.ClosedAt},
	} {
		if err := validateMaybeTimePoint(f.v, "observation."+f.name); err != nil {
			return err
		}
	}
	if v.CloseReason == nil || v.AtClose == nil {
		return fmt.Errorf("lifecycle_rules: observation close_reason/at_close must not be in-band nulls")
	}
	closeIsString := false
	if _, ok := asMissing(v.CloseReason); ok {
	} else if s, ok := v.CloseReason.(string); ok {
		if !validCloseReasons[s] {
			return fmt.Errorf("lifecycle_rules: close_reason %q is invalid", s)
		}
		closeIsString = true
	} else {
		return fmt.Errorf("lifecycle_rules: close_reason must be a CloseReason or Missing")
	}
	atCloseIsSnapshot := false
	if _, ok := asMissing(v.AtClose); ok {
	} else if _, ok := asCloseSnapshotValue(v.AtClose); ok {
		atCloseIsSnapshot = true
	} else {
		return fmt.Errorf("lifecycle_rules: at_close must be a CloseSnapshot or Missing")
	}
	switch v.State {
	case ObsNotOpened:
		if !isMissing(v.OpenedAt) || !isMissing(v.ActiveDeadline) {
			return fmt.Errorf("lifecycle_rules: not_opened carries no opened_at or active_deadline")
		}
	case ObsOpen:
		if isMissing(v.OpenedAt) || isMissing(v.ActiveDeadline) {
			return fmt.Errorf("lifecycle_rules: open requires opened_at and active_deadline")
		}
	case ObsDraining:
		if isMissing(v.OpenedAt) || isMissing(v.ActiveDeadline) {
			return fmt.Errorf("lifecycle_rules: draining requires opened_at and active_deadline")
		}
		if isMissing(v.DrainStartedAt) || isMissing(v.DrainDeadline) {
			return fmt.Errorf("lifecycle_rules: draining requires drain coordinates")
		}
		if !closeIsString {
			return fmt.Errorf("lifecycle_rules: draining requires a close reason")
		}
	case ObsClosed:
		if isMissing(v.ClosedAt) {
			return fmt.Errorf("lifecycle_rules: closed requires closed_at")
		}
		if !closeIsString {
			return fmt.Errorf("lifecycle_rules: closed requires a close reason")
		}
		if !atCloseIsSnapshot {
			return fmt.Errorf("lifecycle_rules: closed requires the close-time knowledge snapshot")
		}
	}
	if v.State != ObsClosed {
		if !isMissingWithReason(v.ClosedAt, "not_applicable") {
			// Non-closed windows carry inapplicable closure coordinates.
			if !isMissing(v.ClosedAt) {
				return fmt.Errorf("lifecycle_rules: non-closed closed_at must be Missing")
			}
		}
		if !isMissingWithReason(v.AtClose, "not_applicable") {
			if !isMissing(v.AtClose) {
				return fmt.Errorf("lifecycle_rules: non-closed at_close must be Missing")
			}
		}
	}
	if v.ControlObservations == nil || v.LateEvidenceRefs == nil || v.Measurements == nil {
		return fmt.Errorf("lifecycle_rules: observation control/late/measurement lists must not be in-band nulls")
	}
	clocks, err := extractClocks(evidence)
	if err != nil {
		return err
	}
	seenControls := map[string]bool{}
	for i, co := range v.ControlObservations {
		if seenControls[co.ControlEventID] {
			return fmt.Errorf("lifecycle_rules: duplicate control_event_id %q", co.ControlEventID)
		}
		seenControls[co.ControlEventID] = true
		if err := validateControlObservation(co, prefix, evidence, clocks); err != nil {
			return fmt.Errorf("lifecycle_rules: control_observations[%d]: %v", i, stripPrefix(err))
		}
	}
	if err := resolveRefs(prefix, evidence, v.LateEvidenceRefs, "observation.late_evidence_refs"); err != nil {
		return err
	}
	for i, m := range v.Measurements {
		if len(m.EvidenceRefs) == 0 {
			return fmt.Errorf("lifecycle_rules: observation.measurements[%d] needs support evidence", i)
		}
		if err := resolveRefs(prefix, evidence, m.EvidenceRefs, fmt.Sprintf("observation.measurements[%d].evidence_refs", i)); err != nil {
			return err
		}
		cm, err := toClockRulesMeasurement(m.Measurement, fmt.Sprintf("observation.measurements[%d].measurement", i))
		if err != nil {
			return err
		}
		if err := clock_rules.ValidateMeasurement(cm, clocks); err != nil {
			return fmt.Errorf("lifecycle_rules: observation.measurements[%d]: %v", i, err)
		}
	}
	if atCloseIsSnapshot {
		cs, _ := asCloseSnapshotValue(v.AtClose)
		if err := validateCloseSnapshot(cs, prefix, evidence); err != nil {
			return err
		}
	}
	return nil
}

func stripPrefix(err error) error {
	msg := err.Error()
	msg = strings.TrimPrefix(msg, "lifecycle_rules: ")
	return fmt.Errorf("%s", msg)
}

func validateObservationTransition(history []AxisRevision, next AxisRevision, evidence []JournalEnvelope) error {
	nextVal, err := parseObservationValue(next.Value)
	if err != nil {
		return err
	}
	// Commission is not needed for shape beyond clocks; pass zero value.
	if err := validateObservationShape(AttemptCommission{}, nextVal, next.EvidencePrefix, evidence); err != nil {
		return err
	}
	prevState := "unpublished"
	var prevVal *ObservationValue
	if len(history) > 0 {
		pv, err := parseObservationValue(history[len(history)-1].Value)
		if err != nil {
			return err
		}
		prevVal = &pv
		prevState = pv.State
	}
	allowed, ok := observationTransitions[prevState]
	if !ok || !allowed[nextVal.State] {
		return fmt.Errorf("lifecycle_rules: observation transition %s -> %s is not allowed", prevState, nextVal.State)
	}
	if prevVal != nil && prevVal.WindowID != nextVal.WindowID {
		return fmt.Errorf("lifecycle_rules: observation window_id is immutable within the attempt")
	}
	// Control history is append-only by control_event_id.
	if prevVal != nil {
		if len(nextVal.ControlObservations) < len(prevVal.ControlObservations) {
			return fmt.Errorf("lifecycle_rules: control history is append-only: cannot drop observations")
		}
		for i, prev := range prevVal.ControlObservations {
			got := nextVal.ControlObservations[i]
			if got.ControlEventID != prev.ControlEventID {
				return fmt.Errorf("lifecycle_rules: control history is append-only by control_event_id")
			}
			same, err := canonicalEqual(prev, got)
			if err != nil || !same {
				return fmt.Errorf("lifecycle_rules: control %q is immutable: append a new control_event_id", prev.ControlEventID)
			}
		}
		if !isSubsetRefs(prevVal.LateEvidenceRefs, nextVal.LateEvidenceRefs) {
			return fmt.Errorf("lifecycle_rules: late evidence is append-only")
		}
	}
	// Closed-to-closed preserves original closure fields.
	if prevVal != nil && prevVal.State == ObsClosed && nextVal.State == ObsClosed {
		for _, f := range []struct {
			name string
			a, b any
		}{
			{"opened_at", prevVal.OpenedAt, nextVal.OpenedAt},
			{"active_deadline", prevVal.ActiveDeadline, nextVal.ActiveDeadline},
			{"drain_started_at", prevVal.DrainStartedAt, nextVal.DrainStartedAt},
			{"drain_deadline", prevVal.DrainDeadline, nextVal.DrainDeadline},
			{"closed_at", prevVal.ClosedAt, nextVal.ClosedAt},
			{"close_reason", prevVal.CloseReason, nextVal.CloseReason},
			{"at_close", prevVal.AtClose, nextVal.AtClose},
		} {
			same, err := canonicalEqual(f.a, f.b)
			if err != nil || !same {
				return fmt.Errorf("lifecycle_rules: closed revisions cannot rewrite close knowledge: field %s is frozen", f.name)
			}
		}
		// Late evidence and cleanup controls may append; nothing else changes.
	}
	return nil
}

// ---------------------------------------------------------------------------
// Execution.
// ---------------------------------------------------------------------------

func validateCommitmentAssertion(a CommitmentAssertion, prefix JournalPrefix, evidence []JournalEnvelope) error {
	if !validIdentifier(a.AssertionID) {
		return fmt.Errorf("lifecycle_rules: assertion_id must be a nonempty identifier")
	}
	if !validCommitValues[a.Value] {
		return fmt.Errorf("lifecycle_rules: assertion %q value %q is invalid", a.AssertionID, a.Value)
	}
	if !validCommitSpans[a.Span] {
		return fmt.Errorf("lifecycle_rules: assertion %q span %q is invalid", a.AssertionID, a.Span)
	}
	if a.BoundaryRef == nil {
		return fmt.Errorf("lifecycle_rules: assertion %q boundary_ref is an in-band null", a.AssertionID)
	}
	if a.Span == "entire_attempt" {
		if !isMissingWithReason(a.BoundaryRef, "not_applicable") {
			return fmt.Errorf("lifecycle_rules: entire_attempt assertions carry boundary_ref Missing(not_applicable)")
		}
	} else {
		r, ok := asEvidenceRefValue(a.BoundaryRef)
		if !ok {
			return fmt.Errorf("lifecycle_rules: assertion %q boundary_ref must be an EvidenceRef for span %s", a.AssertionID, a.Span)
		}
		if err := validateEvidenceRefShape(r, "assertion."+a.AssertionID+".boundary_ref"); err != nil {
			return err
		}
		if _, err := journal_rules.ResolveEvidence(prefix, evidence, r); err != nil {
			return fmt.Errorf("lifecycle_rules: assertion %q boundary_ref does not resolve: %v", a.AssertionID, err)
		}
	}
	if a.EvidenceRefs == nil || len(a.EvidenceRefs) == 0 {
		return fmt.Errorf("lifecycle_rules: assertion %q needs at least one support reference", a.AssertionID)
	}
	if err := resolveRefs(prefix, evidence, a.EvidenceRefs, "assertion."+a.AssertionID+".evidence_refs"); err != nil {
		return err
	}
	return nil
}

func validateExecutionClaim(cl ExecutionClaim, prefix JournalPrefix, evidence []JournalEnvelope) error {
	if !validIdentifier(cl.ClaimID) {
		return fmt.Errorf("lifecycle_rules: claim_id must be a nonempty identifier")
	}
	if !validClaimScopes[cl.Scope] {
		return fmt.Errorf("lifecycle_rules: claim %q scope %q is invalid", cl.ClaimID, cl.Scope)
	}
	if cl.State == nil {
		return fmt.Errorf("lifecycle_rules: claim %q state is an in-band null: use an ExecutionState or Missing", cl.ClaimID)
	}
	switch cl.Scope {
	case "primitive":
		if !isMissingWithReason(cl.State, "not_applicable") {
			return fmt.Errorf("lifecycle_rules: primitive claim %q state must be Missing(not_applicable)", cl.ClaimID)
		}
		if len(cl.ApplicationAssertions) != 0 {
			return fmt.Errorf("lifecycle_rules: primitive claim %q carries no application assertions", cl.ClaimID)
		}
	case "unknown":
		if _, ok := asMissing(cl.State); !ok {
			return fmt.Errorf("lifecycle_rules: unknown-scope claim %q state must be Missing", cl.ClaimID)
		}
		if len(cl.ApplicationAssertions) != 0 {
			return fmt.Errorf("lifecycle_rules: unknown-scope claim %q carries no application assertions", cl.ClaimID)
		}
	default:
		if _, ok := asMissing(cl.State); ok {
			// Missing state is no mapped task-execution statement; allowed.
		} else if s, ok := cl.State.(string); ok {
			if !validExecStates[s] {
				return fmt.Errorf("lifecycle_rules: claim %q state %q is invalid", cl.ClaimID, s)
			}
		} else {
			return fmt.Errorf("lifecycle_rules: claim %q state must be an ExecutionState or Missing", cl.ClaimID)
		}
	}
	if cl.ApplicationAssertions == nil {
		return fmt.Errorf("lifecycle_rules: claim %q application_assertions is an in-band null: use an array", cl.ClaimID)
	}
	seenA := map[string]bool{}
	for _, a := range cl.ApplicationAssertions {
		if seenA[a.AssertionID] {
			return fmt.Errorf("lifecycle_rules: duplicate assertion_id %q in claim %q", a.AssertionID, cl.ClaimID)
		}
		seenA[a.AssertionID] = true
		if err := validateCommitmentAssertion(a, prefix, evidence); err != nil {
			return err
		}
	}
	if cl.NativeRunID == nil || cl.NativeMessageID == nil {
		return fmt.Errorf("lifecycle_rules: claim %q native IDs must not be in-band nulls", cl.ClaimID)
	}
	if _, ok := asMissing(cl.NativeRunID); !ok {
		if _, ok := asStringValue(cl.NativeRunID); !ok {
			return fmt.Errorf("lifecycle_rules: claim %q native_run_id must be an identifier or Missing", cl.ClaimID)
		}
	}
	if _, ok := asMissing(cl.NativeMessageID); !ok {
		if _, ok := asStringValue(cl.NativeMessageID); !ok {
			return fmt.Errorf("lifecycle_rules: claim %q native_message_id must be an identifier or Missing", cl.ClaimID)
		}
	}
	if err := validateArtifact(cl.NativeReport, "claim."+cl.ClaimID+".native_report"); err != nil {
		return err
	}
	if err := validateVersionPin(cl.Mapping, "claim."+cl.ClaimID+".mapping"); err != nil {
		return err
	}
	if err := validateSourceChecks(cl.SourceChecks, "claim."+cl.ClaimID+".source_checks", prefix, evidence, true); err != nil {
		return err
	}
	if err := validateMaybeTimePoint(cl.MadeAt, "claim."+cl.ClaimID+".made_at"); err != nil {
		return err
	}
	if err := validateTimePointShape(cl.ReceivedAt, "claim."+cl.ClaimID+".received_at"); err != nil {
		return fmt.Errorf("lifecycle_rules: claim %q received_at must be a TimePoint: %v", cl.ClaimID, stripPrefix(err))
	}
	if cl.EvidenceAvailableToClaimant == nil || cl.EvidenceRefs == nil || cl.Limitations == nil {
		return fmt.Errorf("lifecycle_rules: claim %q evidence/limitations must not be in-band nulls", cl.ClaimID)
	}
	if err := resolveRefs(prefix, evidence, cl.EvidenceAvailableToClaimant, "claim."+cl.ClaimID+".evidence_available_to_claimant"); err != nil {
		return err
	}
	if len(cl.EvidenceRefs) == 0 {
		return fmt.Errorf("lifecycle_rules: claim %q needs at least one support reference", cl.ClaimID)
	}
	if err := resolveRefs(prefix, evidence, cl.EvidenceRefs, "claim."+cl.ClaimID+".evidence_refs"); err != nil {
		return err
	}
	// A stopped claim alone asserts no commitment proposition. There is
	// nothing to reject here: stopped with zero assertions is valid and the
	// reconciler must not invent a no-commit assertion from the word stopped.
	return nil
}

func validateExecutionShape(v ExecutionValue, prefix JournalPrefix, evidence []JournalEnvelope) error {
	if v.Claims == nil || len(v.Claims) == 0 {
		return fmt.Errorf("lifecycle_rules: execution claims needs at least one accepted claim")
	}
	seen := map[string]bool{}
	for _, cl := range v.Claims {
		if seen[cl.ClaimID] {
			return fmt.Errorf("lifecycle_rules: duplicate claim_id %q: claim IDs are unique within the attempt", cl.ClaimID)
		}
		seen[cl.ClaimID] = true
		if err := validateExecutionClaim(cl, prefix, evidence); err != nil {
			return err
		}
	}
	return nil
}

func validateExecutionTransition(history []AxisRevision, next AxisRevision, evidence []JournalEnvelope) error {
	nextVal, err := parseExecutionValue(next.Value)
	if err != nil {
		return err
	}
	if err := validateExecutionShape(nextVal, next.EvidencePrefix, evidence); err != nil {
		return err
	}
	if len(history) == 0 {
		return nil
	}
	prevVal, err := parseExecutionValue(history[len(history)-1].Value)
	if err != nil {
		return err
	}
	// Cumulative immutable history: every prior claim survives byte-identical.
	byID := map[string]ExecutionClaim{}
	for _, cl := range nextVal.Claims {
		byID[cl.ClaimID] = cl
	}
	for _, prev := range prevVal.Claims {
		got, ok := byID[prev.ClaimID]
		if !ok {
			return fmt.Errorf("lifecycle_rules: execution histories are cumulative: claim %q cannot be dropped", prev.ClaimID)
		}
		same, err := canonicalEqual(prev, got)
		if err != nil || !same {
			return fmt.Errorf("lifecycle_rules: execution claim %q is immutable: contradictory native messages remain cumulative, never overwritten", prev.ClaimID)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Application.
// ---------------------------------------------------------------------------

func validateOriginFact(commission AttemptCommission, f OriginFact, prefix JournalPrefix, evidence []JournalEnvelope) error {
	if !validIdentifier(f.FactID) {
		return fmt.Errorf("lifecycle_rules: fact_id must be a nonempty identifier")
	}
	if f.OriginID != commission.Attempt.TargetID {
		return fmt.Errorf("lifecycle_rules: fact %q origin_id %q must equal attempt target_id %q", f.FactID, f.OriginID, commission.Attempt.TargetID)
	}
	if f.CandidateID != commission.CandidateID {
		return fmt.Errorf("lifecycle_rules: fact %q candidate_id must match commission", f.FactID)
	}
	if f.JobID != commission.Job.JobID {
		return fmt.Errorf("lifecycle_rules: fact %q job_id must match commission", f.FactID)
	}
	if !validFactStates[f.State] {
		return fmt.Errorf("lifecycle_rules: fact %q state %q is invalid", f.FactID, f.State)
	}
	if !validFactCoverage[f.Coverage] {
		return fmt.Errorf("lifecycle_rules: fact %q coverage %q is invalid", f.FactID, f.Coverage)
	}
	if err := validateEvidenceRefShape(f.BoundaryRef, "fact."+f.FactID+".boundary_ref"); err != nil {
		return err
	}
	if _, err := journal_rules.ResolveEvidence(prefix, evidence, f.BoundaryRef); err != nil {
		return fmt.Errorf("lifecycle_rules: fact %q boundary_ref does not resolve: %v", f.FactID, err)
	}
	if f.OriginApplicationID == nil || f.OriginRevision == nil {
		return fmt.Errorf("lifecycle_rules: fact %q origin application/revision must not be in-band nulls", f.FactID)
	}
	if _, ok := asMissing(f.OriginApplicationID); !ok {
		if _, ok := asStringValue(f.OriginApplicationID); !ok {
			return fmt.Errorf("lifecycle_rules: fact %q origin_application_id must be an identifier or Missing", f.FactID)
		}
	}
	if _, ok := asMissing(f.OriginRevision); !ok {
		if _, ok := asStringValue(f.OriginRevision); !ok {
			return fmt.Errorf("lifecycle_rules: fact %q origin_revision must be an identifier or Missing", f.FactID)
		}
	}
	if err := validateArtifact(f.Receipt, "fact."+f.FactID+".receipt"); err != nil {
		return err
	}
	if !validVerificationKinds[f.VerificationKind] {
		return fmt.Errorf("lifecycle_rules: fact %q verification_kind %q is invalid", f.FactID, f.VerificationKind)
	}
	if err := validateSourceChecks(f.SourceChecks, "fact."+f.FactID+".source_checks", prefix, evidence, true); err != nil {
		return err
	}
	if f.AuthoritySealRef == nil {
		return fmt.Errorf("lifecycle_rules: fact %q authority_seal_ref is an in-band null", f.FactID)
	}
	if f.State == "not_committed" && f.Coverage == "final_for_attempt" {
		// Final absence requires origin-owned finality, never an observer
		// deadline, disconnected transport, or missing receipt.
		seal, ok := asEvidenceRefValue(f.AuthoritySealRef)
		if !ok {
			return fmt.Errorf("lifecycle_rules: final not_committed fact %q requires origin-owned finality evidence", f.FactID)
		}
		if err := validateEvidenceRefShape(seal, "fact."+f.FactID+".authority_seal_ref"); err != nil {
			return err
		}
		if _, err := journal_rules.ResolveEvidence(prefix, evidence, seal); err != nil {
			return fmt.Errorf("lifecycle_rules: fact %q authority_seal_ref does not resolve: %v", f.FactID, err)
		}
		sealEvent := findEvent(evidence, seal)
		if sealEvent == nil {
			return fmt.Errorf("lifecycle_rules: fact %q authority seal is not retained", f.FactID)
		}
		if sealEvent.OwnerDomain != commission.Owners.Application.OwnerDomain {
			return fmt.Errorf("lifecycle_rules: final absence requires origin-owned finality: seal owner %q is not the origin domain %q",
				sealEvent.OwnerDomain, commission.Owners.Application.OwnerDomain)
		}
	} else if _, ok := asMissing(f.AuthoritySealRef); !ok {
		seal, ok := asEvidenceRefValue(f.AuthoritySealRef)
		if !ok {
			return fmt.Errorf("lifecycle_rules: fact %q authority_seal_ref must be an EvidenceRef or Missing", f.FactID)
		}
		if err := validateEvidenceRefShape(seal, "fact."+f.FactID+".authority_seal_ref"); err != nil {
			return err
		}
		if _, err := journal_rules.ResolveEvidence(prefix, evidence, seal); err != nil {
			return fmt.Errorf("lifecycle_rules: fact %q authority_seal_ref does not resolve: %v", f.FactID, err)
		}
	}
	if err := validateMaybeTimePoint(f.OccurredAt, "fact."+f.FactID+".occurred_at"); err != nil {
		return err
	}
	if err := validateTimePointShape(f.ReceivedAt, "fact."+f.FactID+".received_at"); err != nil {
		return fmt.Errorf("lifecycle_rules: fact %q received_at must be a TimePoint: %v", f.FactID, stripPrefix(err))
	}
	if f.EvidenceRefs == nil || len(f.EvidenceRefs) == 0 {
		return fmt.Errorf("lifecycle_rules: fact %q needs at least one support reference", f.FactID)
	}
	if err := resolveRefs(prefix, evidence, f.EvidenceRefs, "fact."+f.FactID+".evidence_refs"); err != nil {
		return err
	}
	return nil
}

func validateApplicationShape(commission AttemptCommission, v ApplicationValue, prefix JournalPrefix, evidence []JournalEnvelope) error {
	if v.Facts == nil || len(v.Facts) == 0 {
		return fmt.Errorf("lifecycle_rules: application facts needs at least one accepted fact")
	}
	seen := map[string]bool{}
	for _, f := range v.Facts {
		if seen[f.FactID] {
			return fmt.Errorf("lifecycle_rules: duplicate fact_id %q: fact IDs are unique within the attempt", f.FactID)
		}
		seen[f.FactID] = true
		if err := validateOriginFact(commission, f, prefix, evidence); err != nil {
			return err
		}
	}
	return nil
}

func validateApplicationTransition(commission AttemptCommission, history []AxisRevision, next AxisRevision, evidence []JournalEnvelope) error {
	nextVal, err := parseApplicationValue(next.Value)
	if err != nil {
		return err
	}
	if err := validateApplicationShape(commission, nextVal, next.EvidencePrefix, evidence); err != nil {
		return err
	}
	if len(history) == 0 {
		return nil
	}
	prevVal, err := parseApplicationValue(history[len(history)-1].Value)
	if err != nil {
		return err
	}
	byID := map[string]OriginFact{}
	for _, f := range nextVal.Facts {
		byID[f.FactID] = f
	}
	for _, prev := range prevVal.Facts {
		got, ok := byID[prev.FactID]
		if !ok {
			return fmt.Errorf("lifecycle_rules: application histories are cumulative: fact %q cannot be dropped", prev.FactID)
		}
		same, err := canonicalEqual(prev, got)
		if err != nil || !same {
			return fmt.Errorf("lifecycle_rules: origin fact %q is immutable: a later publication cannot erase an established commitment", prev.FactID)
		}
	}
	// An earlier as-of absence and a later commitment are compatible: no
	// cross-fact contradiction check belongs in the transition guard. The
	// reconciler compares propositions at their actual scope.
	return nil
}

// ---------------------------------------------------------------------------
// Report.
// ---------------------------------------------------------------------------

func validateTemporalRelation(tr TemporalRelation, prefix JournalPrefix, evidence []JournalEnvelope, field string) error {
	if !validTemporalRelations[tr.Relation] {
		return fmt.Errorf("lifecycle_rules: %s relation %q is invalid", field, tr.Relation)
	}
	if !validTemporalBases[tr.Basis] {
		return fmt.Errorf("lifecycle_rules: %s basis %q is invalid", field, tr.Basis)
	}
	if tr.EvidenceRefs == nil {
		return fmt.Errorf("lifecycle_rules: %s evidence_refs is an in-band null: use an array", field)
	}
	switch tr.Relation {
	case "before", "at", "after":
		switch tr.Basis {
		case "same_clock", "causal_evidence", "origin_sequence":
		default:
			return fmt.Errorf("lifecycle_rules: %s relation %s requires basis same_clock, causal_evidence, or origin_sequence", field, tr.Relation)
		}
		if len(tr.EvidenceRefs) == 0 {
			return fmt.Errorf("lifecycle_rules: %s relation %s requires evidence: receipt order alone cannot establish occurrence order", field, tr.Relation)
		}
	case "unknown":
		if tr.Basis != "not_established" {
			return fmt.Errorf("lifecycle_rules: %s unknown relation requires basis not_established", field)
		}
	case "not_applicable":
		if tr.Basis != "not_applicable" {
			return fmt.Errorf("lifecycle_rules: %s not_applicable relation requires basis not_applicable", field)
		}
	}
	if err := resolveRefs(prefix, evidence, tr.EvidenceRefs, field+".evidence_refs"); err != nil {
		return err
	}
	return nil
}

func validateComparison(cc ClaimComparison, prefix JournalPrefix, evidence []JournalEnvelope, field string) error {
	if !validIdentifier(cc.ClaimID) {
		return fmt.Errorf("lifecycle_rules: %s claim_id must be a nonempty identifier", field)
	}
	if cc.AssertionID == nil {
		return fmt.Errorf("lifecycle_rules: %s assertion_id is an in-band null", field)
	}
	if _, ok := asMissing(cc.AssertionID); ok {
		if !isMissingWithReason(cc.AssertionID, "not_applicable") {
			return fmt.Errorf("lifecycle_rules: %s assertion_id Missing must carry not_applicable for narrow claims", field)
		}
	} else if _, ok := asStringValue(cc.AssertionID); !ok {
		return fmt.Errorf("lifecycle_rules: %s assertion_id must be an identifier or Missing(not_applicable)", field)
	}
	if err := validateEvidenceRefShape(cc.ClaimRef, field+".claim_ref"); err != nil {
		return err
	}
	if _, err := journal_rules.ResolveEvidence(prefix, evidence, cc.ClaimRef); err != nil {
		return fmt.Errorf("lifecycle_rules: %s claim_ref does not resolve: %v", field, err)
	}
	if cc.FactIDs == nil || cc.FactRefs == nil || cc.Limitations == nil {
		return fmt.Errorf("lifecycle_rules: %s fact/limitation lists must not be in-band nulls", field)
	}
	seen := map[string]bool{}
	for _, id := range cc.FactIDs {
		if !validIdentifier(id) {
			return fmt.Errorf("lifecycle_rules: %s fact_ids must be nonempty identifiers", field)
		}
		if seen[id] {
			return fmt.Errorf("lifecycle_rules: %s duplicates fact_id %q", field, id)
		}
		seen[id] = true
	}
	if !validCompareResults[cc.Result] {
		return fmt.Errorf("lifecycle_rules: %s result %q is invalid", field, cc.Result)
	}
	if cc.Result == "consistent" || cc.Result == "contradicted" {
		if len(cc.FactIDs) == 0 || len(cc.FactRefs) == 0 {
			return fmt.Errorf("lifecycle_rules: %s result %s requires cited facts", field, cc.Result)
		}
	}
	if err := resolveRefs(prefix, evidence, cc.FactRefs, field+".fact_refs"); err != nil {
		return err
	}
	if err := validateTemporalRelation(cc.TemporalRelation, prefix, evidence, field+".temporal_relation"); err != nil {
		return err
	}
	if !validIdentifier(cc.Rationale) {
		return fmt.Errorf("lifecycle_rules: %s rationale must be nonempty", field)
	}
	return nil
}

func validateReportShape(v ReportValue, prefix JournalPrefix, evidence []JournalEnvelope) error {
	if v.State == nil {
		return fmt.Errorf("lifecycle_rules: report state is an in-band null: use reconciled, contradicted, or Missing")
	}
	stateIsString := false
	stateStr := ""
	if _, ok := asMissing(v.State); ok {
	} else if s, ok := v.State.(string); ok {
		if s != "reconciled" && s != "contradicted" {
			return fmt.Errorf("lifecycle_rules: report state %q must be reconciled or contradicted", s)
		}
		stateIsString = true
		stateStr = s
	} else {
		return fmt.Errorf("lifecycle_rules: report state must be reconciled, contradicted, or Missing")
	}
	switch v.Coverage {
	case "complete", "incomplete", "not_applicable":
	default:
		return fmt.Errorf("lifecycle_rules: report coverage %q is invalid", v.Coverage)
	}
	for _, pin := range []struct {
		name string
		v    DomainPin
	}{
		{"dispatch", v.Inputs.Dispatch}, {"observation", v.Inputs.Observation},
		{"execution", v.Inputs.Execution}, {"application", v.Inputs.Application},
	} {
		if err := validateDomainPin(pin.v, "report.inputs."+pin.name); err != nil {
			return err
		}
	}
	if err := validateVersionPin(v.Evaluator, "report.evaluator"); err != nil {
		return err
	}
	if v.Comparisons == nil || v.Issues == nil || v.Limitations == nil {
		return fmt.Errorf("lifecycle_rules: report comparison/issue/limitation lists must not be in-band nulls")
	}
	for i, cc := range v.Comparisons {
		if err := validateComparison(cc, prefix, evidence, fmt.Sprintf("report.comparisons[%d]", i)); err != nil {
			return err
		}
	}
	for i, is := range v.Issues {
		if !validIssueKinds[is.Kind] {
			return fmt.Errorf("lifecycle_rules: report.issues[%d] kind %q is invalid", i, is.Kind)
		}
		if !validIdentifier(is.Detail) {
			return fmt.Errorf("lifecycle_rules: report.issues[%d] detail must be nonempty", i)
		}
		if len(is.EvidenceRefs) == 0 {
			return fmt.Errorf("lifecycle_rules: report.issues[%d] needs support evidence", i)
		}
		if err := resolveRefs(prefix, evidence, is.EvidenceRefs, fmt.Sprintf("report.issues[%d].evidence_refs", i)); err != nil {
			return err
		}
	}
	if v.Diagnostic == nil {
		return fmt.Errorf("lifecycle_rules: report diagnostic is an in-band null: use an artifact or Missing")
	}
	if _, ok := asMissing(v.Diagnostic); !ok {
		art, ok := asArtifactValue(v.Diagnostic)
		if !ok {
			return fmt.Errorf("lifecycle_rules: report diagnostic must be an artifact or Missing")
		}
		if err := validateArtifact(art, "report.diagnostic"); err != nil {
			return err
		}
	}
	// Contract allOf: state/coverage/comparison coherence.
	hasContradicted := false
	hasIndeterminate := false
	for _, cc := range v.Comparisons {
		if cc.Result == "contradicted" {
			hasContradicted = true
		}
		if cc.Result == "indeterminate" {
			hasIndeterminate = true
		}
	}
	if hasContradicted && !(stateIsString && stateStr == "contradicted") {
		return fmt.Errorf("lifecycle_rules: any proved contradiction makes report.state contradicted")
	}
	if stateIsString && stateStr == "contradicted" && !hasContradicted {
		return fmt.Errorf("lifecycle_rules: contradicted state requires a contradicted comparison")
	}
	if stateIsString && stateStr == "reconciled" {
		if v.Coverage != "complete" {
			return fmt.Errorf("lifecycle_rules: reconciled state requires complete coverage")
		}
		if len(v.Comparisons) == 0 {
			return fmt.Errorf("lifecycle_rules: reconciled state requires at least one comparison")
		}
		for _, cc := range v.Comparisons {
			if cc.Result != "consistent" && cc.Result != "not_comparable" {
				return fmt.Errorf("lifecycle_rules: reconciled comparisons are consistent or not_comparable")
			}
		}
	}
	if v.Coverage == "complete" {
		if !(stateIsString && (stateStr == "reconciled" || stateStr == "contradicted")) {
			return fmt.Errorf("lifecycle_rules: complete coverage requires a decided state")
		}
		if len(v.Comparisons) == 0 {
			return fmt.Errorf("lifecycle_rules: complete coverage requires at least one comparison")
		}
		for _, cc := range v.Comparisons {
			if cc.Result == "indeterminate" {
				return fmt.Errorf("lifecycle_rules: complete coverage admits no indeterminate comparisons")
			}
		}
	}
	if v.Coverage == "not_applicable" {
		if !isMissingWithReason(v.State, "not_applicable") {
			return fmt.Errorf("lifecycle_rules: not_applicable coverage requires state Missing(not_applicable)")
		}
		if len(v.Comparisons) != 0 {
			return fmt.Errorf("lifecycle_rules: not_applicable coverage carries no comparisons, never a fabricated success")
		}
	}
	if v.Coverage == "incomplete" && !hasContradicted {
		r, ok := missingReason(v.State)
		if !ok || (r != "not_observed" && r != "observation_lost") {
			return fmt.Errorf("lifecycle_rules: incomplete coverage without contradiction requires state Missing(not_observed or observation_lost)")
		}
		_ = hasIndeterminate
	}
	return nil
}

func validateReportTransition(history []AxisRevision, next AxisRevision, evidence []JournalEnvelope) error {
	nextVal, err := parseReportValue(next.Value)
	if err != nil {
		return err
	}
	if err := validateReportShape(nextVal, next.EvidencePrefix, evidence); err != nil {
		return err
	}
	if len(history) == 0 {
		return nil
	}
	prevVal, err := parseReportValue(history[len(history)-1].Value)
	if err != nil {
		return err
	}
	// Report input pins never regress: a new report may advance pins to
	// include late evidence but cannot move them backwards to hide facts.
	prevPins := []DomainPin{prevVal.Inputs.Dispatch, prevVal.Inputs.Observation, prevVal.Inputs.Execution, prevVal.Inputs.Application}
	nextPins := []DomainPin{nextVal.Inputs.Dispatch, nextVal.Inputs.Observation, nextVal.Inputs.Execution, nextVal.Inputs.Application}
	names := []string{"dispatch", "observation", "execution", "application"}
	for i := range prevPins {
		if nextPins[i].Revision < prevPins[i].Revision {
			return fmt.Errorf("lifecycle_rules: report input pins cannot regress: %s pin moves %d -> %d",
				names[i], prevPins[i].Revision, nextPins[i].Revision)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Public interface.
// ---------------------------------------------------------------------------

// ValidateAxisTransition enforces header fencing, ownership, resolvable
// support, and the per-axis transition guards for one candidate publication.
func ValidateAxisTransition(commission AttemptCommission, history []AxisRevision, next AxisRevision, evidence []JournalEnvelope) error {
	if err := validateCommission(commission); err != nil {
		return err
	}
	if evidence == nil {
		return fmt.Errorf("lifecycle_rules: evidence is an in-band null: supply the supporting journal events")
	}
	if err := validateEvidenceStructural(evidence); err != nil {
		return err
	}
	if err := validateAxisHeader(commission, history, next); err != nil {
		return err
	}
	if err := resolveRefs(next.EvidencePrefix, evidence, next.EvidenceRefs, "evidence_refs"); err != nil {
		return err
	}
	switch next.Axis {
	case AxisDispatch:
		return validateDispatchTransition(history, next, evidence)
	case AxisObservation:
		if len(history) > 0 {
			// Re-validate shape with the real commission for completeness.
			nextVal, err := parseObservationValue(next.Value)
			if err != nil {
				return err
			}
			if err := validateObservationShape(commission, nextVal, next.EvidencePrefix, evidence); err != nil {
				return err
			}
		}
		return validateObservationTransition(history, next, evidence)
	case AxisExecution:
		return validateExecutionTransition(history, next, evidence)
	case AxisApplication:
		return validateApplicationTransition(commission, history, next, evidence)
	case AxisReport:
		return validateReportTransition(history, next, evidence)
	default:
		return fmt.Errorf("lifecycle_rules: axis %q is invalid", next.Axis)
	}
}

// ReconcileAttempt reads the pinned execution claims and origin facts and
// writes only a report value. It compares propositions at their actual scope
// and knowledge boundary, never invents success, and never uses receipt
// order or opaque revision lexical order as occurrence evidence.
func ReconcileAttempt(commission AttemptCommission, inputs ReportInputPins, publications []AxisRevision, evidence []JournalEnvelope, evaluator VersionPin) (ReportValue, error) {
	empty := ReportValue{}
	if err := validateCommission(commission); err != nil {
		return empty, err
	}
	if err := validateVersionPin(evaluator, "evaluator"); err != nil {
		return empty, err
	}
	for _, pin := range []struct {
		name string
		v    DomainPin
	}{
		{"dispatch", inputs.Dispatch}, {"observation", inputs.Observation},
		{"execution", inputs.Execution}, {"application", inputs.Application},
	} {
		if err := validateDomainPin(pin.v, "inputs."+pin.name); err != nil {
			return empty, err
		}
	}
	if commission.Execution.Mode == "manual" {
		if inputs.Dispatch.Revision != 0 || !isMissingWithReason(inputs.Dispatch.RecordDigest, "not_applicable") {
			return empty, fmt.Errorf("lifecycle_rules: manual dispatch pins stay revision zero with not_applicable")
		}
		if inputs.Execution.Revision != 0 || !isMissingWithReason(inputs.Execution.RecordDigest, "not_applicable") {
			return empty, fmt.Errorf("lifecycle_rules: manual execution pins stay revision zero with not_applicable")
		}
	}
	if evidence == nil {
		return empty, fmt.Errorf("lifecycle_rules: evidence is an in-band null: supply the supporting journal events")
	}
	if err := validateEvidenceStructural(evidence); err != nil {
		return empty, err
	}
	// Index publications and match them against the pinned revisions.
	byAxis := map[string][]AxisRevision{}
	for _, pub := range publications {
		byAxis[pub.Axis] = append(byAxis[pub.Axis], pub)
	}
	pins := map[string]DomainPin{
		AxisDispatch: inputs.Dispatch, AxisObservation: inputs.Observation,
		AxisExecution: inputs.Execution, AxisApplication: inputs.Application,
	}
	matched := map[string]*AxisRevision{}
	for axis, pin := range pins {
		pubs := byAxis[axis]
		if pin.Revision == 0 {
			if len(pubs) != 0 {
				return empty, fmt.Errorf("lifecycle_rules: %s pin is revision zero but %d %s publication(s) were supplied: pins and publications must agree", axis, len(pubs), axis)
			}
			continue
		}
		if len(pubs) != 1 {
			return empty, fmt.Errorf("lifecycle_rules: %s pin %d requires exactly one %s publication, got %d", axis, pin.Revision, axis, len(pubs))
		}
		pub := pubs[0]
		if pub.Revision != pin.Revision {
			return empty, fmt.Errorf("lifecycle_rules: %s pin %d does not match publication revision %d: a snapshot may be newer than its latest report, but reconciliation reads the pinned bytes", axis, pin.Revision, pub.Revision)
		}
		// The pin digest binds the exact publication bytes when present.
		if s, ok := pin.RecordDigest.(string); ok && validDigest(s) {
			digest, err := publicationDigest(pub)
			if err != nil {
				return empty, fmt.Errorf("lifecycle_rules: cannot digest %s publication: %v", axis, err)
			}
			if digest != s {
				return empty, fmt.Errorf("lifecycle_rules: %s pin digest does not match publication bytes: pins make staleness visible, not silent", axis)
			}
		}
		if err := validatePublication(commission, pub, evidence); err != nil {
			return empty, fmt.Errorf("lifecycle_rules: pinned %s publication: %v", axis, stripPrefix(err))
		}
		cp := pub
		matched[axis] = &cp
	}
	// Reject stray axes (e.g. a report publication passed as input).
	for axis, pubs := range byAxis {
		if _, ok := pins[axis]; !ok {
			return empty, fmt.Errorf("lifecycle_rules: unexpected %s publication(s) among report inputs: the reconciler reads dispatch, observation, execution, and application only", axis)
		}
		_ = pubs
	}

	// No applicable subject claims: not_applicable coverage, never a
	// fabricated successful comparison. Manual attempts may still carry
	// committed origin facts; the subject comparison stays inapplicable.
	if matched[AxisExecution] == nil {
		return ReportValue{
			State:       NewMissing("not_applicable"),
			Coverage:    "not_applicable",
			Inputs:      inputs,
			Evaluator:   evaluator,
			Comparisons: []ClaimComparison{},
			Issues:      []ReconciliationIssue{},
			Limitations: []string{"no applicable subject claims in the pinned execution revision; report comparison is not_applicable, not a success verdict"},
			Diagnostic:  NewMissing("not_applicable"),
		}, nil
	}

	execVal, err := parseExecutionValue(matched[AxisExecution].Value)
	if err != nil {
		return empty, err
	}
	var appFacts []OriginFact
	if matched[AxisApplication] != nil {
		appVal, err := parseApplicationValue(matched[AxisApplication].Value)
		if err != nil {
			return empty, err
		}
		appFacts = appVal.Facts
	}
	execPrefix := matched[AxisExecution].EvidencePrefix

	comparisons := []ClaimComparison{}
	issues := []ReconciliationIssue{}
	limitations := []string{}

	// One comparison per claim when it carries no application assertions,
	// otherwise one comparison per assertion.
	for _, cl := range execVal.Claims {
		claimRef := EvidenceRef{}
		if len(cl.EvidenceRefs) > 0 {
			claimRef = cl.EvidenceRefs[0]
		} else if len(matched[AxisExecution].EvidenceRefs) > 0 {
			claimRef = matched[AxisExecution].EvidenceRefs[0]
		}
		if len(cl.ApplicationAssertions) == 0 {
			cc := ClaimComparison{
				ClaimID:     cl.ClaimID,
				AssertionID: NewMissing("not_applicable"),
				ClaimRef:    claimRef,
				FactIDs:     []string{},
				FactRefs:    []EvidenceRef{},
				Result:      "not_comparable",
				TemporalRelation: TemporalRelation{
					Relation: "not_applicable", Basis: "not_applicable", EvidenceRefs: []EvidenceRef{},
				},
				Rationale:   "claim makes no application assertion; a stopped or narrow lifecycle claim alone asserts no commitment proposition",
				Limitations: []string{"narrow execution claim without application scope"},
			}
			comparisons = append(comparisons, cc)
			continue
		}
		for _, a := range cl.ApplicationAssertions {
			cc, lim := compareAssertion(cl, a, appFacts, claimRef, evidence)
			comparisons = append(comparisons, cc)
			if lim != "" {
				limitations = append(limitations, lim)
			}
		}
	}

	// Source-conflict issues. Subject conflicts are preserved, never edited.
	issues = append(issues, detectSubjectConflicts(execVal.Claims, execPrefix, evidence)...)
	issues = append(issues, detectOriginConflicts(appFacts)...)
	if len(appFacts) == 0 && hasApplicationAssertions(execVal.Claims) {
		// Cite the execution support as the evidence that assertions exist
		// without pinned facts.
		ref := EvidenceRef{}
		if len(matched[AxisExecution].EvidenceRefs) > 0 {
			ref = matched[AxisExecution].EvidenceRefs[0]
		}
		issues = append(issues, ReconciliationIssue{
			Kind:         "insufficient_evidence",
			Detail:       "pinned execution assertions exist but no origin facts are pinned",
			EvidenceRefs: []EvidenceRef{ref},
		})
	}

	// Overall state and coverage.
	hasContradicted := false
	hasIndeterminate := false
	hasNotComparable := false
	for _, cc := range comparisons {
		switch cc.Result {
		case "contradicted":
			hasContradicted = true
		case "indeterminate":
			hasIndeterminate = true
		case "not_comparable":
			hasNotComparable = true
		}
	}
	_ = hasNotComparable
	var state any
	var coverage string
	switch {
	case hasContradicted:
		state = "contradicted"
		if hasIndeterminate {
			coverage = "incomplete"
		} else {
			coverage = "complete"
		}
	case hasIndeterminate:
		state = NewMissing("not_observed")
		coverage = "incomplete"
	default:
		state = "reconciled"
		coverage = "complete"
		limitations = append(limitations, "reconciled means the declared comparisons were accounted for, not that the application succeeded")
	}
	if len(comparisons) == 0 {
		// Unreachable: execution claims are non-empty and each yields a
		// comparison. Guarded for totality.
		state = NewMissing("not_observed")
		coverage = "incomplete"
	}

	report := ReportValue{
		State:       state,
		Coverage:    coverage,
		Inputs:      inputs,
		Evaluator:   evaluator,
		Comparisons: comparisons,
		Issues:      issues,
		Limitations: limitations,
		Diagnostic:  NewMissing("not_observed"),
	}
	// The produced report must itself satisfy the report shape gate. Use the
	// execution prefix for reference resolution: all comparison and issue
	// references cite retained journal evidence.
	if err := validateReportShape(report, execPrefix, evidence); err != nil {
		return empty, fmt.Errorf("lifecycle_rules: reconciled report is invalid: %v", stripPrefix(err))
	}
	return report, nil
}

func hasApplicationAssertions(claims []ExecutionClaim) bool {
	for _, cl := range claims {
		if len(cl.ApplicationAssertions) > 0 {
			return true
		}
	}
	return false
}

// compareAssertion compares one subject assertion against the pinned facts at
// their actual scope. Entire-attempt assertions meet every fact; bounded
// assertions meet only facts sharing their boundary.
func compareAssertion(cl ExecutionClaim, a CommitmentAssertion, facts []OriginFact, claimRef EvidenceRef, evidence []JournalEnvelope) (ClaimComparison, string) {
	cc := ClaimComparison{
		ClaimID:     cl.ClaimID,
		AssertionID: a.AssertionID,
		ClaimRef:    claimRef,
		FactIDs:     []string{},
		FactRefs:    []EvidenceRef{},
		Limitations: []string{},
	}
	if a.Value == "outcome_unknown" {
		cc.Result = "indeterminate"
		cc.TemporalRelation = TemporalRelation{Relation: "unknown", Basis: "not_established", EvidenceRefs: []EvidenceRef{}}
		cc.Rationale = "subject asserts outcome unknown: no commitment proposition to confirm or contradict"
		cc.Limitations = []string{"explicit unknown subject claim"}
		return cc, ""
	}
	if len(facts) == 0 {
		cc.Result = "indeterminate"
		cc.TemporalRelation = TemporalRelation{Relation: "unknown", Basis: "not_established", EvidenceRefs: []EvidenceRef{}}
		cc.Rationale = "no origin facts pinned at the cited revisions"
		cc.Limitations = []string{"unresolved comparison; later origin facts may arrive as late evidence"}
		return cc, "unresolved comparisons remain incomplete until origin facts arrive"
	}
	// Select comparable facts by scope.
	type candidate struct {
		fact OriginFact
	}
	var comparable []candidate
	for _, f := range facts {
		if assertionScopeMatches(a, f) {
			comparable = append(comparable, candidate{fact: f})
		}
	}
	if len(comparable) == 0 {
		cc.Result = "not_comparable"
		cc.TemporalRelation = TemporalRelation{Relation: "unknown", Basis: "not_established", EvidenceRefs: []EvidenceRef{}}
		cc.Rationale = "no pinned origin fact shares the assertion scope and boundary"
		cc.Limitations = []string{"incomparable scope: assertion boundary has no matching origin coverage"}
		return cc, "incomparable scopes are disclosed, never forced into a verdict"
	}
	for _, c := range comparable {
		cc.FactIDs = append(cc.FactIDs, c.fact.FactID)
		if len(c.fact.EvidenceRefs) > 0 {
			cc.FactRefs = append(cc.FactRefs, c.fact.EvidenceRefs[0])
		}
	}
	// Temporal relation from the first comparable fact. Receipt order and
	// opaque revision lexical order are never consulted.
	cc.TemporalRelation = temporalFor(a, comparable[0].fact, evidence)
	// Value comparison across all comparable facts. Any proved contradiction
	// dominates: an earlier as-of absence stays compatible with a later
	// commitment only when scopes differ, which the scope filter above
	// already enforces for bounded assertions. Entire-attempt assertions meet
	// every fact, so a committed fact contradicts an entire-attempt
	// no-commit assertion.
	contradicted := false
	consistent := false
	for _, c := range comparable {
		switch {
		case a.Value == "committed" && c.fact.State == "committed":
			consistent = true
		case a.Value == "not_committed" && c.fact.State == "not_committed":
			consistent = true
		case a.Value == "committed" && c.fact.State == "not_committed":
			// A bounded not_committed fact does not refute an
			// entire-attempt committed assertion unless it is final.
			if a.Span == "entire_attempt" && c.fact.Coverage != "final_for_attempt" {
				// As-of absence is compatible with eventual commitment.
				continue
			}
			contradicted = true
		case a.Value == "not_committed" && c.fact.State == "committed":
			contradicted = true
		}
	}
	switch {
	case contradicted:
		cc.Result = "contradicted"
		cc.Rationale = "pinned origin fact contradicts the subject assertion at the asserted scope"
	case consistent:
		cc.Result = "consistent"
		cc.Rationale = "pinned origin facts agree with the subject assertion at the asserted scope"
		cc.Limitations = []string{"consistency at the asserted scope; reconciliation is not proof of application success"}
	default:
		// Comparable scope but only compatible absences (e.g. as-of
		// not_committed against an entire-attempt committed assertion):
		// not yet decidable.
		cc.Result = "indeterminate"
		cc.Rationale = "comparable scope but no decisive origin coverage yet; an as-of absence stays compatible with later commitment"
		cc.Limitations = []string{"awaiting final origin coverage"}
		return cc, "an earlier as-of absence stays compatible with a later commitment"
	}
	if cc.TemporalRelation.Relation == "unknown" {
		return cc, "receipt order alone cannot establish occurrence order; temporal relation stays unknown without same-clock, causal, or origin-sequence evidence"
	}
	return cc, ""
}

// assertionScopeMatches reports whether an origin fact can decide an
// assertion. Entire-attempt assertions meet every fact. Bounded assertions
// meet only facts sharing their boundary reference.
func assertionScopeMatches(a CommitmentAssertion, f OriginFact) bool {
	if a.Span == "entire_attempt" {
		return true
	}
	ar, ok := asEvidenceRefValue(a.BoundaryRef)
	if !ok {
		return false
	}
	return evidenceRefEqual(ar, f.BoundaryRef)
}

// temporalFor determines the origin-fact-to-boundary relation using only
// same-clock evidence, causality, or documented origin sequence. Receipt
// order and opaque revision strings are never consulted.
func temporalFor(a CommitmentAssertion, f OriginFact, evidence []JournalEnvelope) TemporalRelation {
	none := func() TemporalRelation {
		return TemporalRelation{Relation: "unknown", Basis: "not_established", EvidenceRefs: []EvidenceRef{}}
	}
	na := TemporalRelation{Relation: "not_applicable", Basis: "not_applicable", EvidenceRefs: []EvidenceRef{}}
	if a.Span == "entire_attempt" {
		return na
	}
	ar, ok := asEvidenceRefValue(a.BoundaryRef)
	if !ok {
		return none()
	}
	// Same boundary reference: the fact meets the assertion boundary.
	if evidenceRefEqual(ar, f.BoundaryRef) {
		return TemporalRelation{Relation: "at", Basis: "causal_evidence", EvidenceRefs: []EvidenceRef{ar}}
	}
	// Same-clock comparison of occurrence times only. Received_at (receipt)
	// order is never occurrence evidence.
	boundaryTime, okB := occurrenceTimeForRef(evidence, ar)
	factTime, okF := occurrenceTimeForFact(f)
	if !okB || !okF {
		return none()
	}
	if boundaryTime.ClockID != factTime.ClockID || boundaryTime.BootID != factTime.BootID || boundaryTime.Origin != factTime.Origin {
		return none()
	}
	const epsilon = 1e-9
	diff := factTime.MonotonicOffsetMs - boundaryTime.MonotonicOffsetMs
	switch {
	case diff < -epsilon:
		return TemporalRelation{Relation: "before", Basis: "same_clock", EvidenceRefs: []EvidenceRef{ar, f.BoundaryRef}}
	case diff > epsilon:
		return TemporalRelation{Relation: "after", Basis: "same_clock", EvidenceRefs: []EvidenceRef{ar, f.BoundaryRef}}
	default:
		return TemporalRelation{Relation: "at", Basis: "same_clock", EvidenceRefs: []EvidenceRef{ar, f.BoundaryRef}}
	}
}

// occurrenceTimeForRef reads the occurrence coordinate of the referenced
// event. Recorded_at (receipt) is never substituted.
func occurrenceTimeForRef(evidence []JournalEnvelope, ref EvidenceRef) (TimePoint, bool) {
	ev := findEvent(evidence, ref)
	if ev == nil {
		return TimePoint{}, false
	}
	if tp, ok := asTimePointValue(ev.OccurredAt); ok {
		return tp, true
	}
	return TimePoint{}, false
}

// occurrenceTimeForFact reads the fact occurrence coordinate. Received_at
// (receipt) is never substituted, and origin_revision strings are never
// lexically ordered.
func occurrenceTimeForFact(f OriginFact) (TimePoint, bool) {
	if tp, ok := asTimePointValue(f.OccurredAt); ok {
		return tp, true
	}
	return TimePoint{}, false
}

func detectSubjectConflicts(claims []ExecutionClaim, prefix JournalPrefix, evidence []JournalEnvelope) []ReconciliationIssue {
	// Conflicting values at the same span indicate a subject conflict. The
	// claims themselves stay preserved; the issue merely discloses it.
	type key struct{ span, value string }
	seen := map[string]map[string][]ExecutionClaim{} // span -> value -> claims
	for _, cl := range claims {
		for _, a := range cl.ApplicationAssertions {
			if a.Value == "outcome_unknown" {
				continue
			}
			if seen[a.Span] == nil {
				seen[a.Span] = map[string][]ExecutionClaim{}
			}
			seen[a.Span][a.Value] = append(seen[a.Span][a.Value], cl)
		}
	}
	var issues []ReconciliationIssue
	for span, byValue := range seen {
		if len(byValue) < 2 {
			continue
		}
		// Collect one support ref per conflicting side.
		var refs []EvidenceRef
		for _, cls := range byValue {
			for _, cl := range cls {
				if len(cl.EvidenceRefs) > 0 {
					refs = append(refs, cl.EvidenceRefs[0])
					break
				}
			}
		}
		if len(refs) == 0 && len(evidence) > 0 {
			// Fall back is unnecessary in practice; claims always carry
			// support. Kept total for safety.
			_ = prefix
		}
		if len(refs) == 0 {
			continue
		}
		issues = append(issues, ReconciliationIssue{
			Kind:         "subject_claim_conflict",
			Detail:       "conflicting subject assertions at span " + span + " remain cumulative and immutable",
			EvidenceRefs: refs,
		})
	}
	// Conflicting lifecycle states (e.g. completed vs failed) are also a
	// subject conflict worth disclosing.
	states := map[string][]ExecutionClaim{}
	for _, cl := range claims {
		if s, ok := cl.State.(string); ok && validExecStates[s] {
			states[s] = append(states[s], cl)
		}
	}
	terminal := [][]string{{ExecCompleted, ExecFailed}, {ExecCompleted, ExecStopped}, {ExecFailed, ExecStopped}}
	for _, pair := range terminal {
		a, b := states[pair[0]], states[pair[1]]
		if len(a) > 0 && len(b) > 0 {
			var refs []EvidenceRef
			if len(a[0].EvidenceRefs) > 0 {
				refs = append(refs, a[0].EvidenceRefs[0])
			}
			if len(b[0].EvidenceRefs) > 0 {
				refs = append(refs, b[0].EvidenceRefs[0])
			}
			if len(refs) > 0 {
				issues = append(issues, ReconciliationIssue{
					Kind:         "subject_claim_conflict",
					Detail:       "conflicting native lifecycle states " + pair[0] + " vs " + pair[1] + " remain cumulative",
					EvidenceRefs: refs,
				})
			}
		}
	}
	return issues
}

func detectOriginConflicts(facts []OriginFact) []ReconciliationIssue {
	var issues []ReconciliationIssue
	// Same-boundary conflicting states.
	for i := range facts {
		for j := i + 1; j < len(facts); j++ {
			a, b := facts[i], facts[j]
			if evidenceRefEqual(a.BoundaryRef, b.BoundaryRef) && a.State != b.State {
				var refs []EvidenceRef
				if len(a.EvidenceRefs) > 0 {
					refs = append(refs, a.EvidenceRefs[0])
				}
				if len(b.EvidenceRefs) > 0 {
					refs = append(refs, b.EvidenceRefs[0])
				}
				if len(refs) > 0 {
					issues = append(issues, ReconciliationIssue{
						Kind:         "origin_fact_conflict",
						Detail:       "conflicting origin facts at the same boundary remain preserved",
						EvidenceRefs: refs,
					})
				}
			}
		}
	}
	// Multiple distinct commitments.
	var committed []OriginFact
	for _, f := range facts {
		if f.State == "committed" {
			committed = append(committed, f)
		}
	}
	if len(committed) >= 2 {
		ids := map[string]bool{}
		distinct := false
		for _, f := range committed {
			if s, ok := asStringValue(f.OriginApplicationID); ok {
				if len(ids) > 0 && !ids[s] {
					distinct = true
				}
				ids[s] = true
			}
		}
		if distinct {
			var refs []EvidenceRef
			for _, f := range committed {
				if len(f.EvidenceRefs) > 0 {
					refs = append(refs, f.EvidenceRefs[0])
				}
				if len(refs) >= 2 {
					break
				}
			}
			if len(refs) > 0 {
				issues = append(issues, ReconciliationIssue{
					Kind:         "multiple_origin_commitments",
					Detail:       "multiple distinct origin commitments are preserved for review",
					EvidenceRefs: refs,
				})
			}
		}
	}
	return issues
}

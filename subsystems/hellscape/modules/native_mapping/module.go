// Package native_mapping implements the tier-2 Hellscape native mapping:
// pure preparation translation (subject-facing task + native request
// serialization) and faithful native-result normalization into
// execution-lifecycle claims.
//
// Seam references: seam-mappings/hellscape-seam-mapping.md sections 8.7
// (Prepare and PreparedTask), 8.11 (SourceChecks and normalization), 8.15
// (initial circus-tent binding), 9.5 (execution history), 13.3 (historical
// observations: preserve reported zero), 16.2 (evidence and timing corpus),
// and 16.4 (connector synthetic corpus), plus contracts/02-external-connector.yaml
// invariants EXT-PREPARE, EXT-NORMALIZE, EXT-READ-ONLY, EXT-TIME-NULL,
// EXT-DECLARE-NOT-ASSESS, EK-CLAIMS, and LIFE-CLAIMS.
//
// Semantic boundaries enforced here:
//
//   - Prepare is non-executing. SerializeNative validates already supplied
//     task data, plan, dependencies, mappings, grants, and declared limits
//     without visiting the target, testing authentication, resetting context,
//     invoking a planner, or secretly improving the plan. It records the
//     native serialization and the subject-facing task independently. It adds
//     no sleeps, selector alternatives, hidden planning, retries, or recovery
//     actions (EXT-PREPARE).
//   - Translation preserves intent, action order, values, targets, and retry
//     policy verbatim. Incomplete translation returns UNSUPPORTED_MAPPING.
//   - discover_jobs and extract tasks cannot execute employer/application
//     mutations. HTTP method or interface label alone does not determine
//     read-only status; mutation actions are rejected for read-only tasks and
//     permissive task text never upgrades effect policy (EXT-READ-ONLY).
//   - Every normalized null uses a typed Missing envelope with one of the six
//     kernel reasons. No in-band nulls appear in normalized claims
//     (EXT-TIME-NULL).
//   - Accepted claims require verified source and matched attempt correlation.
//     Unverified or uncorrelated messages retain raw bytes but produce no
//     accepted claims. Trace mismatch is preserved even when alternate
//     correlation succeeds (EXT-NORMALIZE, EK-CLAIMS).
//   - Native nulls, malformed bodies, unsupported shapes, explicit unknown,
//     missing fields, and conflicting responses remain distinct. Malformed
//     bodies are explicit mapping failures, never silent claims.
//   - Execution publications contain only faithfully mapped,
//     source-attributed claims. An absent state is Missing, not an invented
//     unknown; explicit unknown remains a valid subject claim (LIFE-CLAIMS).
//   - None, protocol acknowledgement, HTTP success, and native completed do
//     not establish application commitment. Completed and failed native
//     responses map to execution_lifecycle claims with no application
//     assertions (EXT-DECLARE-NOT-ASSESS, EK-CLAIMS).
//   - Native step timing without native clock coordinates uses an
//     opaque-report clock; endpoints are never invented. Missing timing maps
//     to unavailable with reason. Explicit reported zero is preserved as an
//     exact subject-reported zero, never corrected (EXT-TIME-NULL, 13.3, 16.2).
//   - No speculative native endpoint is invented. Only the pinned mapping
//     contract is used; unsupported endpoints yield UNSUPPORTED_MAPPING.
//
// The module performs no browsing, no planning, no retries, no recovery, no
// shared database writes, and no cross-domain transactions.
package native_mapping

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"clock_rules"
	"evidence_codec"
)

// ---------------------------------------------------------------------------
// Error taxonomy.
// ---------------------------------------------------------------------------

// Mapping error codes. UNSUPPORTED_MAPPING matches the shared connector
// taxonomy (seam 8.14); MAPPING_FAILURE is the explicit native-result
// mapping failure for malformed bodies; INVALID_REQUEST, INTEGRITY_CONFLICT,
// and FORBIDDEN describe caller errors detected before or during mapping.
const (
	CodeUnsupportedMapping = "UNSUPPORTED_MAPPING"
	CodeMappingFailure     = "MAPPING_FAILURE"
	CodeInvalidRequest     = "INVALID_REQUEST"
	CodeIntegrityConflict  = "INTEGRITY_CONFLICT"
	CodeForbidden          = "FORBIDDEN"
)

// MappingError is a typed mapping failure. Code is one of the Code*
// constants; Detail is a sanitized human-readable reason without secret
// material.
type MappingError struct {
	Code   string
	Detail string
}

// Error implements error.
func (e *MappingError) Error() string {
	return fmt.Sprintf("native_mapping: %s: %s", e.Code, e.Detail)
}

// asMappingError extracts the *MappingError from err, if present.
func asMappingError(err error) (*MappingError, bool) {
	if err == nil {
		return nil, false
	}
	if me, ok := err.(*MappingError); ok {
		return me, true
	}
	return nil, false
}

// ---------------------------------------------------------------------------
// Shared primitives (contract 02-external-connector.yaml $defs).
// ---------------------------------------------------------------------------

// Schema versions pinned by this mapping.
const (
	SchemaExternalConnector = "external-connector/0.1.0"
	SchemaEvidenceKernel    = "0.1.0"
	RecordConnectorTask     = "connector_task"
)

// The six EK null reasons (seam 3.1). manual_fixture_validation is a
// rationale, never a seventh reason.
var validNullReasons = map[string]bool{
	"not_enabled":          true,
	"not_applicable":       true,
	"not_observed":         true,
	"observation_lost":     true,
	"unsupported_by_subject": true,
	"manual_override":      true,
}

// Missing is a typed EK.Missing envelope. It marshals to
// {"value":null,"reason":...} with optional detail. It is the only
// normalized representation of absence; bare nulls never appear in claims.
type Missing struct {
	Reason string `json:"reason"`
	Detail string `json:"detail,omitempty"`
}

// MarshalJSON emits the reasoned envelope with an explicit null value.
func (m Missing) MarshalJSON() ([]byte, error) {
	type wire struct {
		Value  any    `json:"value"`
		Reason string `json:"reason"`
		Detail string `json:"Detail,omitempty"`
	}
	return json.Marshal(wire{Value: nil, Reason: m.Reason, Detail: m.Detail})
}

// UnmarshalJSON accepts the reasoned envelope.
func (m *Missing) UnmarshalJSON(data []byte) error {
	var wire struct {
		Value  any    `json:"value"`
		Reason string `json:"reason"`
		Detail string `json:"Detail"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&wire); err != nil {
		return err
	}
	if wire.Value != nil {
		return fmt.Errorf("native_mapping: Missing.value must be null")
	}
	m.Reason = wire.Reason
	m.Detail = wire.Detail
	return nil
}

// IsMissing reports whether v is a Missing (or *Missing) envelope.
func IsMissing(v any) bool {
	switch v.(type) {
	case Missing, *Missing:
		return true
	default:
		return false
	}
}

// MissingReason returns the reason of a Missing value, or "" when v is not Missing.
func MissingReason(v any) string {
	switch t := v.(type) {
	case Missing:
		return t.Reason
	case *Missing:
		if t == nil {
			return ""
		}
		return t.Reason
	default:
		return ""
	}
}

func validateMissing(m Missing, field string) error {
	if !validNullReasons[m.Reason] {
		return fmt.Errorf("native_mapping: %s reason %q must be one of the six kernel reasons", field, m.Reason)
	}
	return nil
}

// VersionPin identifies a pinned mapping/contract artifact.
type VersionPin struct {
	ID             string `json:"id"`
	Version        string `json:"version"`
	ArtifactDigest string `json:"artifact_digest"`
}

// ArtifactReference is a content-addressed artifact handle.
type ArtifactReference struct {
	Digest      string `json:"digest"`
	SizeBytes   int64  `json:"size_bytes"`
	MediaType   string `json:"media_type"`
	OwnerDomain string `json:"owner_domain"`
	Access      string `json:"access"`
}

// EvidenceRef is a journal event pointer.
type EvidenceRef struct {
	JournalID string `json:"journal_id"`
	Sequence  int64  `json:"sequence"`
	EventID   string `json:"event_id"`
	EventHash string `json:"event_hash"`
	Pointer   string `json:"pointer"`
}

// JournalEnvelope is the stored journal event envelope. It aliases the
// evidence_codec envelope so evidence can be validated with the shared
// structural gate.
type JournalEnvelope = evidence_codec.JournalEnvelope

// TimePoint is a coordinate in a registered monotonic clock. UTCAnnotation
// is a string RFC3339 date-time or a Missing envelope; it never drives
// elapsed arithmetic.
type TimePoint struct {
	ClockID           string `json:"clock_id"`
	BootID            string `json:"boot_id"`
	Origin            string `json:"origin"`
	MonotonicOffsetMs float64 `json:"monotonic_offset_ms"`
	UTCAnnotation     any    `json:"utc_annotation"`
}

// CommitmentAssertion is an origin-commitment assertion. Native mapping
// never emits one: lifecycle claims carry zero assertions.
type CommitmentAssertion struct {
	AssertionID string         `json:"assertion_id"`
	Value       string         `json:"value"`
	Span        string         `json:"span"`
	BoundaryRef any            `json:"boundary_ref"`
	EvidenceRefs []EvidenceRef `json:"evidence_refs"`
}

// SourceChecks retains authentication and correlation evidence.
type SourceChecks struct {
	Authentication     string       `json:"authentication"`
	Correlation        string       `json:"correlation"`
	TraceCorrelation   string       `json:"trace_correlation"`
	VerificationPolicy VersionPin   `json:"verification_policy"`
	MatchedBy          []string     `json:"matched_by"`
	EvidenceRefs       []EvidenceRef `json:"evidence_refs"`
}

// NativeTiming is the validated native duration projection carried on a
// claim. DurationMs is float64 or Missing; Method and Censoring describe the
// validated kernel measurement.
type NativeTiming struct {
	DurationMs any    `json:"duration_ms"`
	Method     string `json:"method"`
	Censoring  string `json:"censoring"`
}

// ClaimStep is one normalized native step. Nullable native fields are
// Missing, never bare nulls.
type ClaimStep struct {
	Name       string `json:"name"`
	Status     any    `json:"status"`
	Detail     any    `json:"detail"`
	DurationMs any    `json:"duration_ms"`
}

// ExecutionClaim is a faithful subject execution claim. State, NativeRunID,
// NativeMessageID, and MadeAt are each a concrete value or Missing.
// ApplicationAssertions is always empty for mapped native claims: native
// completion never establishes application commitment.
type ExecutionClaim struct {
	ClaimID                    string                `json:"claim_id"`
	Scope                      string                `json:"scope"`
	State                      any                   `json:"state"`
	ApplicationAssertions      []CommitmentAssertion `json:"application_assertions"`
	NativeRunID                any                   `json:"native_run_id"`
	NativeMessageID            any                   `json:"native_message_id"`
	NativeReport               ArtifactReference     `json:"native_report"`
	Mapping                    VersionPin            `json:"mapping"`
	SourceChecks               SourceChecks          `json:"source_checks"`
	MadeAt                     any                   `json:"made_at"`
	ReceivedAt                 TimePoint             `json:"received_at"`
	EvidenceAvailableToClaimant []EvidenceRef        `json:"evidence_available_to_claimant"`
	EvidenceRefs               []EvidenceRef         `json:"evidence_refs"`
	Limitations                []string              `json:"limitations"`
	NativeTiming               NativeTiming          `json:"native_timing"`
	Steps                      []ClaimStep           `json:"steps"`
}

// ---------------------------------------------------------------------------
// PrepareRequest model (contract WorkScope, ConfigurationPin, TaskEnvelope,
// AssistanceRecord, RuntimeAccess).
// ---------------------------------------------------------------------------

// EntryPoint binds a logical ID to an actual destination URL.
type EntryPoint struct {
	LogicalID string `json:"logical_id"`
	URL       string `json:"url"`
}

// PermittedOrigin binds a logical origin ID to an actual origin.
type PermittedOrigin struct {
	LogicalID string `json:"logical_id"`
	Origin    string `json:"origin"`
}

// TaskInput is a named candidate-data artifact.
type TaskInput struct {
	Name    string            `json:"name"`
	Purpose string            `json:"purpose"`
	Content ArtifactReference `json:"content"`
}

// SuccessCriterion is a user-understandable objective.
type SuccessCriterion struct {
	CriterionID string `json:"criterion_id"`
	Description string `json:"description"`
}

// StatePolicy is a semantic state request, not a guarantee.
type StatePolicy struct {
	Mode        string `json:"mode"`
	Requirement string `json:"requirement"`
	ResourceRef any    `json:"resource_ref"`
	Baseline    any    `json:"baseline"`
}

// ContextPolicy independently describes browser and learning state.
type ContextPolicy struct {
	BrowserState  StatePolicy `json:"browser_state"`
	LearningState StatePolicy `json:"learning_state"`
}

// DurationLimit is a configured finite allowance, never a measurement.
type DurationLimit struct {
	Kind  string  `json:"kind"`
	Unit  string  `json:"unit"`
	Value float64 `json:"value"`
}

// TaskBudgets are configured limits, never measurements.
type TaskBudgets struct {
	ActiveLimit          DurationLimit `json:"active_limit"`
	ActionLimit          int64         `json:"action_limit"`
	ObservationByteLimit int64         `json:"observation_byte_limit"`
	RecoveryLimit        int64         `json:"recovery_limit"`
	ModelTokenLimit      int64         `json:"model_token_limit"`
}

// RetryPolicy is the per-step retry declaration preserved verbatim by
// translation. It is a declaration, not hidden recovery planning.
type RetryPolicy struct {
	MaxAttempts int   `json:"max_attempts"`
	BackoffMs   int64 `json:"backoff_ms"`
}

// TaskStep is one recorded-plan step carried for translation. Action order,
// values, targets, and retry policy are preserved exactly; the translator
// adds no sleeps, alternatives, or recovery.
type TaskStep struct {
	Name        string      `json:"name"`
	Action      string      `json:"action"`
	Target      string      `json:"target"`
	Value       any         `json:"value"`
	RetryPolicy RetryPolicy `json:"retry_policy"`
}

// TaskEnvelope is the commissioned task. Steps carries the recorded-plan
// actions for translation; all other fields follow the shared contract.
type TaskEnvelope struct {
	RecordType          string             `json:"record_type"`
	SchemaVersion       string             `json:"schema_version"`
	TaskID              string             `json:"task_id"`
	TaskType            string             `json:"task_type"`
	Entry               EntryPoint         `json:"entry"`
	Goal                string             `json:"goal"`
	SuccessCriteria     []SuccessCriterion `json:"success_criteria"`
	Inputs              []TaskInput        `json:"inputs"`
	PermittedOrigins    []PermittedOrigin  `json:"permitted_origins"`
	PermittedInterfaces []string           `json:"permitted_interfaces"`
	EffectPolicy        string             `json:"effect_policy"`
	Budgets             TaskBudgets        `json:"budgets"`
	ContextPolicy       ContextPolicy      `json:"context_policy"`
	OutputSchema        any                `json:"output_schema"`
	Steps               []TaskStep         `json:"steps"`
}

// AttemptContext is the immutable attempt scope for application work.
type AttemptContext struct {
	AttemptID           string   `json:"attempt_id"`
	Kind                string   `json:"kind"`
	TargetClass         string   `json:"target_class"`
	TargetID            string   `json:"target_id"`
	EvaluationPartition string   `json:"evaluation_partition"`
	RehearsalOf         []string `json:"rehearsal_of"`
	PerformanceOf       []string `json:"performance_of"`
	DerivedFrom         []string `json:"derived_from"`
}

// ObservationPolicy bounds local observation; it is configuration.
type ObservationPolicy struct {
	ActiveLimit          DurationLimit `json:"active_limit"`
	DrainLimit           DurationLimit `json:"drain_limit"`
	NativeCancelWaitLimit DurationLimit `json:"native_cancel_wait_limit"`
	CleanupWaitLimit     DurationLimit `json:"cleanup_wait_limit"`
	FixtureCloseAction   string        `json:"fixture_close_action"`
}

// WorkScope scopes one preparation to application or discovery work.
type WorkScope struct {
	Activity           string            `json:"activity"`
	RunID              string            `json:"run_id"`
	JournalID          string            `json:"journal_id"`
	ManifestHash       string            `json:"manifest_hash"`
	AdmissionRef       EvidenceRef       `json:"admission_ref"`
	Attempt            any               `json:"attempt"`
	Commission         any               `json:"commission"`
	CommissionRef      any               `json:"commission_ref"`
	AuthorizationRefs  []EvidenceRef     `json:"authorization_refs"`
	ObservationPolicy  ObservationPolicy `json:"observation_policy"`
}

// SubjectIdentity pins the commissioned subject.
type SubjectIdentity struct {
	SubjectID           string `json:"subject_id"`
	SubjectVersion      string `json:"subject_version"`
	RevisionBasis       string `json:"revision_basis"`
	NativeRevision      any    `json:"native_revision"`
	ConfiguredMode      string `json:"configured_mode"`
	InterfaceSurface    string `json:"interface_surface"`
	ConfigurationDigest string `json:"configuration_digest"`
	Stack               []any  `json:"stack"`
}

// ConfigurationPin pins the descriptor and subject under test.
type ConfigurationPin struct {
	ConnectorID      string            `json:"connector_id"`
	ConnectorVersion string            `json:"connector_version"`
	Binding          VersionPin        `json:"binding"`
	Subject          SubjectIdentity   `json:"subject"`
	Descriptor       ArtifactReference `json:"descriptor"`
	DescriptorRef    EvidenceRef       `json:"descriptor_ref"`
}

// AssistanceRecord discloses planning ownership and provenance.
type AssistanceRecord struct {
	PlanningOwner    string `json:"planning_owner"`
	AssistanceTrack  string `json:"assistance_track"`
	PlannerIdentity  any    `json:"planner_identity"`
	Plan             any    `json:"plan"`
	OnlineReplanning bool   `json:"online_replanning"`
	Description      string `json:"description"`
}

// RuntimeAccess is an opaque runtime binding reference; secret bytes are
// never serialized here.
type RuntimeAccess struct {
	Purpose            string        `json:"purpose"`
	AccessRef          string        `json:"access_ref"`
	AuthorizationRefs  []EvidenceRef `json:"authorization_refs"`
}

// MeasurementEvidence carries a previously journaled cost. Preparation
// never performs the planning it describes.
type MeasurementEvidence struct {
	Measurement  map[string]any `json:"measurement"`
	EvidenceRefs []EvidenceRef  `json:"evidence_refs"`
}

// PrepareRequest is the non-executing preparation input.
type PrepareRequest struct {
	Scope                   WorkScope             `json:"scope"`
	Configuration           ConfigurationPin      `json:"configuration"`
	Task                    TaskEnvelope          `json:"task"`
	Assistance              AssistanceRecord      `json:"assistance"`
	PlanningEvidenceRefs    []EvidenceRef         `json:"planning_evidence_refs"`
	PreparationMeasurements []MeasurementEvidence `json:"preparation_measurements"`
	RuntimeAccess           []RuntimeAccess       `json:"runtime_access"`
}

// nativeRequestWire is the retained native request serialization. It carries
// the mapping pin plus the translated task intent with steps preserved
// verbatim. It carries no credentials, no sleeps, no selector alternatives,
// no planning, and no recovery.
type nativeRequestWire struct {
	Mapping             VersionPin        `json:"mapping"`
	TaskID              string            `json:"task_id"`
	TaskType            string            `json:"task_type"`
	EffectPolicy        string            `json:"effect_policy"`
	Entry               EntryPoint        `json:"entry"`
	Goal                string            `json:"goal"`
	Steps               []TaskStep        `json:"steps"`
	PermittedOrigins    []PermittedOrigin `json:"permitted_origins"`
	PermittedInterfaces []string          `json:"permitted_interfaces"`
	Budgets             TaskBudgets       `json:"budgets"`
	SuccessCriteria     []SuccessCriterion `json:"success_criteria"`
}

// ---------------------------------------------------------------------------
// Validation tables.
// ---------------------------------------------------------------------------

var validTaskTypes = map[string]bool{
	"apply": true, "extract": true, "discover_jobs": true,
}

var validEffectPolicies = map[string]bool{
	"read_only": true, "commissioned_application": true,
}

var validInterfaces = map[string]bool{
	"ordinary_browser": true, "read_only_acquisition": true,
}

var validActivities = map[string]bool{
	"application_attempt": true, "discovery": true,
}

var validPlanningOwners = map[string]bool{
	"subject": true, "external_planner": true, "operator": true, "none": true,
}

var validPurposes = map[string]bool{
	"application_entry": true, "account_session": true, "input_artifact": true,
}

var validBrowserModes = map[string]bool{
	"fresh": true, "reuse": true, "subject_default": true, "not_applicable": true,
}

var validLearningModes = map[string]bool{
	"fresh": true, "reuse": true, "frozen": true, "subject_default": true, "not_applicable": true,
}

var validRequirements = map[string]bool{
	"required": true, "best_effort": true,
}

var validAuthentications = map[string]bool{
	"verified": true, "failed": true, "unknown": true,
}

var validCorrelations = map[string]bool{
	"matched": true, "mismatched": true, "unknown": true,
}

var validTraceCorrelations = map[string]bool{
	"matched": true, "mismatched": true, "not_observed": true, "not_applicable": true,
}

var validClaimScopes = map[string]bool{
	"primitive": true, "application_postcondition": true, "execution_lifecycle": true, "unknown": true,
}

var validNativeStates = map[string]bool{
	"running": true, "completed": true, "failed": true, "stopped": true, "unknown": true,
}

// supportedStepActions is the closed set of step actions this mapping pin
// can serialize. Anything else is an incomplete translation.
var supportedStepActions = map[string]bool{
	"navigate": true, "fill": true, "click": true, "select": true,
	"extract": true, "read_text": true, "wait_for_ready": true,
	"upload": true, "verify_identity": true,
	"submit": true, "submit_application": true,
}

// readOnlyStepActions is the subset permitted for extract/discover_jobs.
// HTTP method or interface label alone never authorizes a mutation;
// the action itself must be read-only.
var readOnlyStepActions = map[string]bool{
	"navigate": true, "extract": true, "read_text": true, "wait_for_ready": true,
}

// mutationStepActions always require a commissioned application task.
var mutationStepActions = map[string]bool{
	"submit": true, "submit_application": true,
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
	for i := 0; i < len(hexPart); i++ {
		c := hexPart[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func validateVersionPin(p VersionPin, field string) error {
	if strings.TrimSpace(p.ID) == "" {
		return &MappingError{Code: CodeInvalidRequest, Detail: field + ".id must be a nonempty identifier"}
	}
	if strings.TrimSpace(p.Version) == "" {
		return &MappingError{Code: CodeInvalidRequest, Detail: field + ".version must be a nonempty identifier"}
	}
	if !validDigest(p.ArtifactDigest) {
		return &MappingError{Code: CodeInvalidRequest, Detail: field + ".artifact_digest must be a sha256 digest"}
	}
	return nil
}

func validateArtifactReference(a ArtifactReference, field string) error {
	if !validDigest(a.Digest) {
		return &MappingError{Code: CodeInvalidRequest, Detail: field + ".digest must be a sha256 digest"}
	}
	if a.SizeBytes < 0 {
		return &MappingError{Code: CodeInvalidRequest, Detail: field + ".size_bytes must be nonnegative"}
	}
	if strings.TrimSpace(a.MediaType) == "" {
		return &MappingError{Code: CodeInvalidRequest, Detail: field + ".media_type must be a nonempty identifier"}
	}
	if strings.TrimSpace(a.OwnerDomain) == "" {
		return &MappingError{Code: CodeInvalidRequest, Detail: field + ".owner_domain must be a nonempty identifier"}
	}
	if a.Access != "public" && a.Access != "restricted" {
		return &MappingError{Code: CodeInvalidRequest, Detail: field + ".access must be public or restricted"}
	}
	return nil
}

func validateEvidenceRef(r EvidenceRef, field string) error {
	if strings.TrimSpace(r.JournalID) == "" {
		return &MappingError{Code: CodeInvalidRequest, Detail: field + ".journal_id must be a nonempty identifier"}
	}
	if r.Sequence < 1 {
		return &MappingError{Code: CodeInvalidRequest, Detail: field + ".sequence must be a positive integer"}
	}
	if strings.TrimSpace(r.EventID) == "" {
		return &MappingError{Code: CodeInvalidRequest, Detail: field + ".event_id must be a nonempty identifier"}
	}
	if !validDigest(r.EventHash) {
		return &MappingError{Code: CodeInvalidRequest, Detail: field + ".event_hash must be a sha256 digest"}
	}
	// Pointer must be a JSON pointer (empty root allowed).
	if r.Pointer != "" {
		if !strings.HasPrefix(r.Pointer, "/") {
			return &MappingError{Code: CodeInvalidRequest, Detail: field + ".pointer must be a JSON pointer"}
		}
		for _, tok := range strings.Split(r.Pointer[1:], "/") {
			for i := 0; i < len(tok); i++ {
				if tok[i] == '~' {
					if i+1 >= len(tok) || (tok[i+1] != '0' && tok[i+1] != '1') {
						return &MappingError{Code: CodeInvalidRequest, Detail: field + ".pointer has invalid escape"}
					}
					i++
				}
			}
		}
	}
	return nil
}

func validateDurationLimit(d DurationLimit, field string) error {
	if d.Kind != "exact" {
		return &MappingError{Code: CodeInvalidRequest, Detail: field + ".kind must be exact"}
	}
	if d.Unit != "ms" {
		return &MappingError{Code: CodeInvalidRequest, Detail: field + ".unit must be ms"}
	}
	if d.Value < 0 {
		return &MappingError{Code: CodeInvalidRequest, Detail: field + ".value must be nonnegative"}
	}
	return nil
}

func asVersionPin(v any) (VersionPin, bool) {
	switch t := v.(type) {
	case VersionPin:
		return t, true
	case *VersionPin:
		if t == nil {
			return VersionPin{}, false
		}
		return *t, true
	default:
		return VersionPin{}, false
	}
}

func asArtifactReference(v any) (ArtifactReference, bool) {
	switch t := v.(type) {
	case ArtifactReference:
		return t, true
	case *ArtifactReference:
		if t == nil {
			return ArtifactReference{}, false
		}
		return *t, true
	default:
		return ArtifactReference{}, false
	}
}

func asEvidenceRef(v any) (EvidenceRef, bool) {
	switch t := v.(type) {
	case EvidenceRef:
		return t, true
	case *EvidenceRef:
		if t == nil {
			return EvidenceRef{}, false
		}
		return *t, true
	default:
		return EvidenceRef{}, false
	}
}

func asAttemptContext(v any) (AttemptContext, bool) {
	switch t := v.(type) {
	case AttemptContext:
		return t, true
	case *AttemptContext:
		if t == nil {
			return AttemptContext{}, false
		}
		return *t, true
	default:
		return AttemptContext{}, false
	}
}

func asStringValue(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

// ---------------------------------------------------------------------------
// Duplicate-key detector for native bodies. Native nulls are legal input
// (they become reasoned Missingness), so the shared record gate cannot be
// reused here; duplicate keys are still rejected before any other mapping.
// ---------------------------------------------------------------------------

type dupParser struct {
	b   []byte
	pos int
}

func checkDuplicateKeysNative(data []byte) error {
	p := &dupParser{b: data}
	p.skipWS()
	if p.pos >= len(p.b) {
		return fmt.Errorf("native_mapping: empty native body")
	}
	if err := p.parseValue("$"); err != nil {
		return err
	}
	p.skipWS()
	if p.pos != len(p.b) {
		return fmt.Errorf("native_mapping: trailing data after native JSON document")
	}
	return nil
}

func (p *dupParser) skipWS() {
	for p.pos < len(p.b) {
		switch p.b[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

func (p *dupParser) parseValue(path string) error {
	p.skipWS()
	if p.pos >= len(p.b) {
		return fmt.Errorf("native_mapping: unexpected end of native body at %s", path)
	}
	switch c := p.b[p.pos]; c {
	case '{':
		return p.parseObject(path)
	case '[':
		return p.parseArray(path)
	case '"':
		_, err := p.parseString(path)
		return err
	case 't':
		return p.parseLiteral("true", path)
	case 'f':
		return p.parseLiteral("false", path)
	case 'n':
		return p.parseLiteral("null", path)
	case '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		return p.parseNumber(path)
	default:
		return fmt.Errorf("native_mapping: non-JSON value at %s: unexpected byte %q", path, c)
	}
}

func (p *dupParser) parseLiteral(lit, path string) error {
	if strings.HasPrefix(string(p.b[p.pos:]), lit) {
		p.pos += len(lit)
		return nil
	}
	return fmt.Errorf("native_mapping: non-JSON value at %s", path)
}

func (p *dupParser) parseNumber(path string) error {
	if p.b[p.pos] == '-' {
		p.pos++
		if p.pos >= len(p.b) {
			return fmt.Errorf("native_mapping: malformed number at %s", path)
		}
	}
	c := p.b[p.pos]
	if c == '0' {
		p.pos++
	} else if c >= '1' && c <= '9' {
		for p.pos < len(p.b) && p.b[p.pos] >= '0' && p.b[p.pos] <= '9' {
			p.pos++
		}
	} else {
		return fmt.Errorf("native_mapping: malformed number at %s", path)
	}
	if p.pos < len(p.b) && p.b[p.pos] == '.' {
		p.pos++
		start := p.pos
		for p.pos < len(p.b) && p.b[p.pos] >= '0' && p.b[p.pos] <= '9' {
			p.pos++
		}
		if p.pos == start {
			return fmt.Errorf("native_mapping: malformed number at %s", path)
		}
	}
	if p.pos < len(p.b) && (p.b[p.pos] == 'e' || p.b[p.pos] == 'E') {
		p.pos++
		if p.pos < len(p.b) && (p.b[p.pos] == '+' || p.b[p.pos] == '-') {
			p.pos++
		}
		start := p.pos
		for p.pos < len(p.b) && p.b[p.pos] >= '0' && p.b[p.pos] <= '9' {
			p.pos++
		}
		if p.pos == start {
			return fmt.Errorf("native_mapping: malformed number at %s", path)
		}
	}
	return nil
}

func (p *dupParser) parseObject(path string) error {
	p.pos++
	p.skipWS()
	if p.pos < len(p.b) && p.b[p.pos] == '}' {
		p.pos++
		return nil
	}
	seen := make(map[string]struct{})
	for {
		p.skipWS()
		if p.pos >= len(p.b) || p.b[p.pos] != '"' {
			return fmt.Errorf("native_mapping: expected object key at %s", path)
		}
		key, err := p.parseString(path)
		if err != nil {
			return err
		}
		if _, dup := seen[key]; dup {
			return fmt.Errorf("native_mapping: duplicate mapping key %q at %s rejected before mapping", key, path)
		}
		seen[key] = struct{}{}
		p.skipWS()
		if p.pos >= len(p.b) || p.b[p.pos] != ':' {
			return fmt.Errorf("native_mapping: expected ':' after key %q at %s", key, path)
		}
		p.pos++
		if err := p.parseValue(path + "." + key); err != nil {
			return err
		}
		p.skipWS()
		if p.pos >= len(p.b) {
			return fmt.Errorf("native_mapping: unterminated object at %s", path)
		}
		switch p.b[p.pos] {
		case ',':
			p.pos++
		case '}':
			p.pos++
			return nil
		default:
			return fmt.Errorf("native_mapping: expected ',' or '}' at %s", path)
		}
	}
}

func (p *dupParser) parseArray(path string) error {
	p.pos++
	p.skipWS()
	if p.pos < len(p.b) && p.b[p.pos] == ']' {
		p.pos++
		return nil
	}
	for i := 0; ; i++ {
		if err := p.parseValue(fmt.Sprintf("%s[%d]", path, i)); err != nil {
			return err
		}
		p.skipWS()
		if p.pos >= len(p.b) {
			return fmt.Errorf("native_mapping: unterminated array at %s", path)
		}
		switch p.b[p.pos] {
		case ',':
			p.pos++
		case ']':
			p.pos++
			return nil
		default:
			return fmt.Errorf("native_mapping: expected ',' or ']' at %s", path)
		}
	}
}

func (p *dupParser) parseString(path string) (string, error) {
	p.pos++
	var sb strings.Builder
	for {
		if p.pos >= len(p.b) {
			return "", fmt.Errorf("native_mapping: unterminated string at %s", path)
		}
		c := p.b[p.pos]
		switch {
		case c == '"':
			p.pos++
			return sb.String(), nil
		case c == '\\':
			p.pos++
			if p.pos >= len(p.b) {
				return "", fmt.Errorf("native_mapping: unterminated escape at %s", path)
			}
			e := p.b[p.pos]
			p.pos++
			switch e {
			case '"', '\\', '/':
				sb.WriteByte(e)
			case 'b':
				sb.WriteByte('\b')
			case 'f':
				sb.WriteByte('\f')
			case 'n':
				sb.WriteByte('\n')
			case 'r':
				sb.WriteByte('\r')
			case 't':
				sb.WriteByte('\t')
			case 'u':
				r, err := p.parseHex4(path)
				if err != nil {
					return "", err
				}
				if r >= 0xD800 && r <= 0xDBFF && p.pos+5 < len(p.b) && p.b[p.pos] == '\\' && p.b[p.pos+1] == 'u' {
					save := p.pos
					p.pos += 2
					lo, err := p.parseHex4(path)
					if err == nil && lo >= 0xDC00 && lo <= 0xDFFF {
						r = 0x10000 + (r-0xD800)<<10 + (lo - 0xDC00)
					} else {
						p.pos = save
					}
				}
				sb.WriteRune(r)
			default:
				return "", fmt.Errorf("native_mapping: invalid string escape at %s", path)
			}
		case c < 0x20:
			return "", fmt.Errorf("native_mapping: unescaped control character in string at %s", path)
		default:
			sb.WriteByte(c)
			p.pos++
		}
	}
}

func (p *dupParser) parseHex4(path string) (rune, error) {
	if p.pos+4 > len(p.b) {
		return 0, fmt.Errorf("native_mapping: truncated unicode escape at %s", path)
	}
	var r rune
	for i := 0; i < 4; i++ {
		c := p.b[p.pos+i]
		var v byte
		switch {
		case c >= '0' && c <= '9':
			v = c - '0'
		case c >= 'a' && c <= 'f':
			v = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			v = c - 'A' + 10
		default:
			return 0, fmt.Errorf("native_mapping: invalid unicode escape at %s", path)
		}
		r = r*16 + rune(v)
	}
	p.pos += 4
	return r, nil
}

// ---------------------------------------------------------------------------
// SerializeNative: pure preparation translation.
// ---------------------------------------------------------------------------

// SerializeNative validates the admitted preparation input and returns the
// independent serializations (deliveredTask, nativeRequest). The delivered
// task is the subject-facing task bytes; the native request is the mapped
// native serialization carrying the translation pin. Both are deterministic
// JSON; neither carries secret bytes.
//
// It performs no browsing, login testing, context reset, planner invocation,
// sleep insertion, selector healing, or plan repair. Steps are copied
// verbatim: action order, values, targets, and retry policy are preserved
// exactly. Incomplete translation returns UNSUPPORTED_MAPPING.
func SerializeNative(request PrepareRequest, mapping VersionPin) ([]byte, []byte, error) {
	if err := validateVersionPin(mapping, "mapping"); err != nil {
		return nil, nil, err
	}
	if err := validatePrepareRequest(request); err != nil {
		return nil, nil, err
	}
	if err := enforceReadOnly(request.Task, request.Scope); err != nil {
		return nil, nil, err
	}
	delivered, err := json.Marshal(request.Task)
	if err != nil {
		return nil, nil, &MappingError{Code: CodeInvalidRequest, Detail: "cannot serialize delivered task: " + err.Error()}
	}
	wire := nativeRequestWire{
		Mapping:             mapping,
		TaskID:              request.Task.TaskID,
		TaskType:            request.Task.TaskType,
		EffectPolicy:        request.Task.EffectPolicy,
		Entry:               request.Task.Entry,
		Goal:                request.Task.Goal,
		Steps:               append([]TaskStep(nil), request.Task.Steps...),
		PermittedOrigins:    append([]PermittedOrigin(nil), request.Task.PermittedOrigins...),
		PermittedInterfaces: append([]string(nil), request.Task.PermittedInterfaces...),
		Budgets:             request.Task.Budgets,
		SuccessCriteria:     append([]SuccessCriterion(nil), request.Task.SuccessCriteria...),
	}
	if wire.Steps == nil {
		wire.Steps = []TaskStep{}
	}
	if wire.PermittedOrigins == nil {
		wire.PermittedOrigins = []PermittedOrigin{}
	}
	if wire.PermittedInterfaces == nil {
		wire.PermittedInterfaces = []string{}
	}
	if wire.SuccessCriteria == nil {
		wire.SuccessCriteria = []SuccessCriterion{}
	}
	native, err := json.Marshal(wire)
	if err != nil {
		return nil, nil, &MappingError{Code: CodeInvalidRequest, Detail: "cannot serialize native request: " + err.Error()}
	}
	// Independent content identities for the two retained artifacts. The
	// digests pin the exact bytes; secret material never appears here.
	_ = evidence_codec.HashBytes(delivered)
	_ = evidence_codec.HashBytes(native)
	return delivered, native, nil
}

func validatePrepareRequest(r PrepareRequest) error {
	if err := validateWorkScope(r.Scope, r.Task.TaskType); err != nil {
		return err
	}
	if err := validateConfiguration(r.Configuration); err != nil {
		return err
	}
	if err := validateTaskEnvelope(r.Task); err != nil {
		return err
	}
	if err := validateAssistance(r.Assistance, r.PlanningEvidenceRefs); err != nil {
		return err
	}
	for i := range r.PlanningEvidenceRefs {
		if err := validateEvidenceRef(r.PlanningEvidenceRefs[i], fmt.Sprintf("planning_evidence_refs[%d]", i)); err != nil {
			return err
		}
	}
	for i := range r.PreparationMeasurements {
		if len(r.PreparationMeasurements[i].EvidenceRefs) == 0 {
			return &MappingError{Code: CodeInvalidRequest, Detail: fmt.Sprintf("preparation_measurements[%d].evidence_refs must carry at least one reference", i)}
		}
		for j := range r.PreparationMeasurements[i].EvidenceRefs {
			if err := validateEvidenceRef(r.PreparationMeasurements[i].EvidenceRefs[j], fmt.Sprintf("preparation_measurements[%d].evidence_refs[%d]", i, j)); err != nil {
				return err
			}
		}
	}
	for i := range r.RuntimeAccess {
		ra := r.RuntimeAccess[i]
		if !validPurposes[ra.Purpose] {
			return &MappingError{Code: CodeInvalidRequest, Detail: fmt.Sprintf("runtime_access[%d].purpose %q is unknown", i, ra.Purpose)}
		}
		if strings.TrimSpace(ra.AccessRef) == "" {
			return &MappingError{Code: CodeInvalidRequest, Detail: fmt.Sprintf("runtime_access[%d].access_ref must be a nonempty opaque reference", i)}
		}
		if strings.Contains(ra.AccessRef, "\n") || strings.Contains(ra.AccessRef, " ") {
			return &MappingError{Code: CodeInvalidRequest, Detail: fmt.Sprintf("runtime_access[%d].access_ref must be an opaque reference, not secret bytes", i)}
		}
		if len(ra.AuthorizationRefs) == 0 {
			return &MappingError{Code: CodeInvalidRequest, Detail: fmt.Sprintf("runtime_access[%d].authorization_refs must carry at least one reference", i)}
		}
		for j := range ra.AuthorizationRefs {
			if err := validateEvidenceRef(ra.AuthorizationRefs[j], fmt.Sprintf("runtime_access[%d].authorization_refs[%d]", i, j)); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateWorkScope(s WorkScope, taskType string) error {
	if !validActivities[s.Activity] {
		return &MappingError{Code: CodeInvalidRequest, Detail: fmt.Sprintf("scope.activity %q is unknown", s.Activity)}
	}
	if strings.TrimSpace(s.RunID) == "" {
		return &MappingError{Code: CodeInvalidRequest, Detail: "scope.run_id must be a nonempty identifier"}
	}
	if strings.TrimSpace(s.JournalID) == "" {
		return &MappingError{Code: CodeInvalidRequest, Detail: "scope.journal_id must be a nonempty identifier"}
	}
	if !validDigest(s.ManifestHash) {
		return &MappingError{Code: CodeInvalidRequest, Detail: "scope.manifest_hash must be a sha256 digest"}
	}
	if err := validateEvidenceRef(s.AdmissionRef, "scope.admission_ref"); err != nil {
		return err
	}
	if len(s.AuthorizationRefs) == 0 {
		return &MappingError{Code: CodeInvalidRequest, Detail: "scope.authorization_refs must carry at least one reference"}
	}
	for i := range s.AuthorizationRefs {
		if err := validateEvidenceRef(s.AuthorizationRefs[i], fmt.Sprintf("scope.authorization_refs[%d]", i)); err != nil {
			return err
		}
	}
	if err := validateDurationLimit(s.ObservationPolicy.ActiveLimit, "scope.observation_policy.active_limit"); err != nil {
		return err
	}
	if err := validateDurationLimit(s.ObservationPolicy.DrainLimit, "scope.observation_policy.drain_limit"); err != nil {
		return err
	}
	if err := validateDurationLimit(s.ObservationPolicy.NativeCancelWaitLimit, "scope.observation_policy.native_cancel_wait_limit"); err != nil {
		return err
	}
	if err := validateDurationLimit(s.ObservationPolicy.CleanupWaitLimit, "scope.observation_policy.cleanup_wait_limit"); err != nil {
		return err
	}
	if s.ObservationPolicy.FixtureCloseAction != "seal_after_drain" && s.ObservationPolicy.FixtureCloseAction != "not_applicable" {
		return &MappingError{Code: CodeInvalidRequest, Detail: "scope.observation_policy.fixture_close_action is unknown"}
	}
	// Activity must agree with the commissioned work. Application tasks
	// require application_attempt scope with a concrete attempt and
	// commission; discovery work carries inapplicable markers.
	if taskType == "apply" && s.Activity != "application_attempt" {
		return &MappingError{Code: CodeInvalidRequest, Detail: "apply tasks require application_attempt scope"}
	}
	if (taskType == "extract" || taskType == "discover_jobs") && s.Activity != "discovery" {
		return &MappingError{Code: CodeForbidden, Detail: "read-only extraction requires discovery scope; application scope cannot be acquired through extraction"}
	}
	if s.Activity == "application_attempt" {
		attempt, ok := asAttemptContext(s.Attempt)
		if !ok {
			return &MappingError{Code: CodeInvalidRequest, Detail: "application_attempt scope requires a concrete attempt context"}
		}
		if strings.TrimSpace(attempt.AttemptID) == "" || strings.TrimSpace(attempt.Kind) == "" {
			return &MappingError{Code: CodeInvalidRequest, Detail: "scope.attempt must identify the attempt"}
		}
		if _, ok := asArtifactReference(s.Commission); !ok {
			return &MappingError{Code: CodeInvalidRequest, Detail: "application_attempt scope requires a commission artifact"}
		}
		if _, ok := asEvidenceRef(s.CommissionRef); !ok {
			return &MappingError{Code: CodeInvalidRequest, Detail: "application_attempt scope requires a commission reference"}
		}
	} else {
		if m, ok := s.Attempt.(Missing); ok {
			if m.Reason != "not_applicable" {
				return &MappingError{Code: CodeInvalidRequest, Detail: "discovery scope attempt must be Missing(not_applicable)"}
			}
		} else if m, ok := s.Attempt.(*Missing); ok {
			if m == nil || m.Reason != "not_applicable" {
				return &MappingError{Code: CodeInvalidRequest, Detail: "discovery scope attempt must be Missing(not_applicable)"}
			}
		} else {
			return &MappingError{Code: CodeInvalidRequest, Detail: "discovery scope attempt must be Missing(not_applicable)"}
		}
		if m, ok := s.Commission.(Missing); ok {
			if m.Reason != "not_applicable" {
				return &MappingError{Code: CodeInvalidRequest, Detail: "discovery scope commission must be Missing(not_applicable)"}
			}
		} else if m, ok := s.Commission.(*Missing); ok {
			if m == nil || m.Reason != "not_applicable" {
				return &MappingError{Code: CodeInvalidRequest, Detail: "discovery scope commission must be Missing(not_applicable)"}
			}
		} else {
			return &MappingError{Code: CodeInvalidRequest, Detail: "discovery scope commission must be Missing(not_applicable)"}
		}
		if m, ok := s.CommissionRef.(Missing); ok {
			if m.Reason != "not_applicable" {
				return &MappingError{Code: CodeInvalidRequest, Detail: "discovery scope commission_ref must be Missing(not_applicable)"}
			}
		} else if m, ok := s.CommissionRef.(*Missing); ok {
			if m == nil || m.Reason != "not_applicable" {
				return &MappingError{Code: CodeInvalidRequest, Detail: "discovery scope commission_ref must be Missing(not_applicable)"}
			}
		} else {
			return &MappingError{Code: CodeInvalidRequest, Detail: "discovery scope commission_ref must be Missing(not_applicable)"}
		}
		if s.ObservationPolicy.FixtureCloseAction != "not_applicable" {
			return &MappingError{Code: CodeInvalidRequest, Detail: "discovery scope fixture_close_action must be not_applicable"}
		}
	}
	return nil
}

func validateConfiguration(c ConfigurationPin) error {
	if strings.TrimSpace(c.ConnectorID) == "" {
		return &MappingError{Code: CodeInvalidRequest, Detail: "configuration.connector_id must be a nonempty identifier"}
	}
	if strings.TrimSpace(c.ConnectorVersion) == "" {
		return &MappingError{Code: CodeInvalidRequest, Detail: "configuration.connector_version must be a nonempty identifier"}
	}
	if err := validateVersionPin(c.Binding, "configuration.binding"); err != nil {
		return err
	}
	if strings.TrimSpace(c.Subject.SubjectID) == "" {
		return &MappingError{Code: CodeInvalidRequest, Detail: "configuration.subject.subject_id must be a nonempty identifier"}
	}
	if strings.TrimSpace(c.Subject.SubjectVersion) == "" {
		return &MappingError{Code: CodeInvalidRequest, Detail: "configuration.subject.subject_version must be a nonempty identifier"}
	}
	switch c.Subject.RevisionBasis {
	case "native_revision", "source_digest", "operator_attestation", "unknown":
	default:
		return &MappingError{Code: CodeInvalidRequest, Detail: "configuration.subject.revision_basis is unknown"}
	}
	switch v := c.Subject.NativeRevision.(type) {
	case string:
		if strings.TrimSpace(v) == "" {
			return &MappingError{Code: CodeInvalidRequest, Detail: "configuration.subject.native_revision must be a nonempty identifier or Missing"}
		}
	case Missing:
		if err := validateMissing(v, "configuration.subject.native_revision"); err != nil {
			return &MappingError{Code: CodeInvalidRequest, Detail: err.Error()}
		}
	case *Missing:
		if v == nil {
			return &MappingError{Code: CodeInvalidRequest, Detail: "configuration.subject.native_revision must not be an in-band null"}
		}
		if err := validateMissing(*v, "configuration.subject.native_revision"); err != nil {
			return &MappingError{Code: CodeInvalidRequest, Detail: err.Error()}
		}
	default:
		return &MappingError{Code: CodeInvalidRequest, Detail: "configuration.subject.native_revision must be an identifier or Missing"}
	}
	if strings.TrimSpace(c.Subject.ConfiguredMode) == "" {
		return &MappingError{Code: CodeInvalidRequest, Detail: "configuration.subject.configured_mode must be a nonempty identifier"}
	}
	if strings.TrimSpace(c.Subject.InterfaceSurface) == "" {
		return &MappingError{Code: CodeInvalidRequest, Detail: "configuration.subject.interface_surface must be a nonempty identifier"}
	}
	if !validDigest(c.Subject.ConfigurationDigest) {
		return &MappingError{Code: CodeInvalidRequest, Detail: "configuration.subject.configuration_digest must be a sha256 digest"}
	}
	if err := validateArtifactReference(c.Descriptor, "configuration.descriptor"); err != nil {
		return err
	}
	if err := validateEvidenceRef(c.DescriptorRef, "configuration.descriptor_ref"); err != nil {
		return err
	}
	return nil
}

func validateTaskEnvelope(t TaskEnvelope) error {
	if t.RecordType != RecordConnectorTask {
		return &MappingError{Code: CodeUnsupportedMapping, Detail: fmt.Sprintf("task.record_type %q is not supported by this mapping", t.RecordType)}
	}
	if t.SchemaVersion != SchemaExternalConnector {
		return &MappingError{Code: CodeUnsupportedMapping, Detail: fmt.Sprintf("task.schema_version %q is not supported by this mapping", t.SchemaVersion)}
	}
	if strings.TrimSpace(t.TaskID) == "" {
		return &MappingError{Code: CodeUnsupportedMapping, Detail: "task.task_id is required for translation"}
	}
	if !validTaskTypes[t.TaskType] {
		return &MappingError{Code: CodeUnsupportedMapping, Detail: fmt.Sprintf("task.task_type %q has no mapping in this pin", t.TaskType)}
	}
	if strings.TrimSpace(t.Entry.LogicalID) == "" {
		return &MappingError{Code: CodeUnsupportedMapping, Detail: "task.entry.logical_id is required for translation"}
	}
	if !(strings.HasPrefix(t.Entry.URL, "https://") || strings.HasPrefix(t.Entry.URL, "http://")) {
		return &MappingError{Code: CodeUnsupportedMapping, Detail: "task.entry.url must be an http(s) URL"}
	}
	if strings.Contains(t.Entry.URL, "@") && strings.Contains(strings.SplitN(t.Entry.URL, "://", 2)[1], "@") {
		// Reject userinfo without revealing credentials.
		return &MappingError{Code: CodeInvalidRequest, Detail: "task.entry.url must not carry userinfo"}
	}
	if strings.TrimSpace(t.Goal) == "" {
		return &MappingError{Code: CodeUnsupportedMapping, Detail: "task.goal is required for translation"}
	}
	if len(t.SuccessCriteria) == 0 {
		return &MappingError{Code: CodeUnsupportedMapping, Detail: "task.success_criteria must carry at least one criterion"}
	}
	seenCriteria := map[string]bool{}
	for i := range t.SuccessCriteria {
		c := t.SuccessCriteria[i]
		if strings.TrimSpace(c.CriterionID) == "" || strings.TrimSpace(c.Description) == "" {
			return &MappingError{Code: CodeUnsupportedMapping, Detail: fmt.Sprintf("task.success_criteria[%d] requires an id and description", i)}
		}
		if seenCriteria[c.CriterionID] {
			return &MappingError{Code: CodeInvalidRequest, Detail: fmt.Sprintf("duplicate success criterion id %q", c.CriterionID)}
		}
		seenCriteria[c.CriterionID] = true
	}
	seenInputs := map[string]bool{}
	for i := range t.Inputs {
		in := t.Inputs[i]
		if strings.TrimSpace(in.Name) == "" {
			return &MappingError{Code: CodeUnsupportedMapping, Detail: fmt.Sprintf("task.inputs[%d].name is required", i)}
		}
		if seenInputs[in.Name] {
			return &MappingError{Code: CodeInvalidRequest, Detail: fmt.Sprintf("duplicate task input name %q", in.Name)}
		}
		seenInputs[in.Name] = true
		if strings.TrimSpace(in.Purpose) == "" {
			return &MappingError{Code: CodeUnsupportedMapping, Detail: fmt.Sprintf("task.inputs[%d].purpose is required", i)}
		}
		if err := validateArtifactReference(in.Content, fmt.Sprintf("task.inputs[%d].content", i)); err != nil {
			return err
		}
	}
	if len(t.PermittedOrigins) == 0 {
		return &MappingError{Code: CodeUnsupportedMapping, Detail: "task.permitted_origins must carry at least one origin"}
	}
	seenOrigins := map[string]bool{}
	for i := range t.PermittedOrigins {
		o := t.PermittedOrigins[i]
		if strings.TrimSpace(o.LogicalID) == "" || strings.TrimSpace(o.Origin) == "" {
			return &MappingError{Code: CodeUnsupportedMapping, Detail: fmt.Sprintf("task.permitted_origins[%d] requires a logical id and origin", i)}
		}
		key := o.LogicalID + "\x00" + o.Origin
		if seenOrigins[key] {
			return &MappingError{Code: CodeInvalidRequest, Detail: "duplicate permitted origin"}
		}
		seenOrigins[key] = true
		if !(strings.HasPrefix(o.Origin, "https://") || strings.HasPrefix(o.Origin, "http://")) {
			return &MappingError{Code: CodeUnsupportedMapping, Detail: fmt.Sprintf("task.permitted_origins[%d].origin must be an http(s) origin", i)}
		}
	}
	if len(t.PermittedInterfaces) == 0 {
		return &MappingError{Code: CodeUnsupportedMapping, Detail: "task.permitted_interfaces must carry at least one interface"}
	}
	seenIfaces := map[string]bool{}
	hasOrdinary := false
	for _, iface := range t.PermittedInterfaces {
		if !validInterfaces[iface] {
			return &MappingError{Code: CodeUnsupportedMapping, Detail: fmt.Sprintf("task.permitted_interfaces entry %q is not mapped", iface)}
		}
		if seenIfaces[iface] {
			return &MappingError{Code: CodeInvalidRequest, Detail: fmt.Sprintf("duplicate permitted interface %q", iface)}
		}
		seenIfaces[iface] = true
		if iface == "ordinary_browser" {
			hasOrdinary = true
		}
	}
	if !validEffectPolicies[t.EffectPolicy] {
		return &MappingError{Code: CodeUnsupportedMapping, Detail: fmt.Sprintf("task.effect_policy %q is not mapped", t.EffectPolicy)}
	}
	// Effect policy must agree with the commissioned task type. A mismatch
	// for read-only work is a forbidden authority escalation, never a
	// silent upgrade.
	if t.TaskType == "apply" {
		if t.EffectPolicy != "commissioned_application" {
			return &MappingError{Code: CodeUnsupportedMapping, Detail: "apply tasks require commissioned_application effects"}
		}
		if !hasOrdinary {
			return &MappingError{Code: CodeUnsupportedMapping, Detail: "apply tasks require the ordinary_browser interface"}
		}
	} else {
		if t.EffectPolicy != "read_only" {
			return &MappingError{Code: CodeForbidden, Detail: "read-only extraction requires read_only effects; commissioned_application cannot be acquired through extraction"}
		}
	}
	if err := validateDurationLimit(t.Budgets.ActiveLimit, "task.budgets.active_limit"); err != nil {
		return err
	}
	for _, v := range []int64{t.Budgets.ActionLimit, t.Budgets.ObservationByteLimit, t.Budgets.RecoveryLimit, t.Budgets.ModelTokenLimit} {
		if v < 0 {
			return &MappingError{Code: CodeInvalidRequest, Detail: "task.budgets limits must be nonnegative"}
		}
	}
	if err := validateStatePolicy(t.ContextPolicy.BrowserState, "task.context_policy.browser_state", validBrowserModes); err != nil {
		return err
	}
	if err := validateStatePolicy(t.ContextPolicy.LearningState, "task.context_policy.learning_state", validLearningModes); err != nil {
		return err
	}
	// Frozen browser state is meaningless; it is allowed only for learning
	// state. A required frozen browser policy has no native mapping.
	if t.ContextPolicy.BrowserState.Mode == "frozen" {
		return &MappingError{Code: CodeUnsupportedMapping, Detail: "frozen browser_state has no native mapping; frozen is learning-state only"}
	}
	switch v := t.OutputSchema.(type) {
	case VersionPin:
		if err := validateVersionPin(v, "task.output_schema"); err != nil {
			return err
		}
	case *VersionPin:
		if v == nil {
			return &MappingError{Code: CodeUnsupportedMapping, Detail: "task.output_schema must not be an in-band null"}
		}
		if err := validateVersionPin(*v, "task.output_schema"); err != nil {
			return err
		}
	case Missing:
		if err := validateMissing(v, "task.output_schema"); err != nil {
			return &MappingError{Code: CodeUnsupportedMapping, Detail: err.Error()}
		}
		if t.TaskType != "apply" {
			return &MappingError{Code: CodeUnsupportedMapping, Detail: t.TaskType + " tasks require a concrete output_schema pin"}
		}
	case *Missing:
		if v == nil {
			return &MappingError{Code: CodeUnsupportedMapping, Detail: "task.output_schema must not be an in-band null"}
		}
		if err := validateMissing(*v, "task.output_schema"); err != nil {
			return &MappingError{Code: CodeUnsupportedMapping, Detail: err.Error()}
		}
		if t.TaskType != "apply" {
			return &MappingError{Code: CodeUnsupportedMapping, Detail: t.TaskType + " tasks require a concrete output_schema pin"}
		}
	default:
		return &MappingError{Code: CodeUnsupportedMapping, Detail: "task.output_schema must be a VersionPin or Missing"}
	}
	// Steps are the recorded-plan actions. Every step must be fully
	// mappable; unknown or incomplete steps fail the whole translation.
	for i := range t.Steps {
		st := t.Steps[i]
		if strings.TrimSpace(st.Name) == "" {
			return &MappingError{Code: CodeUnsupportedMapping, Detail: fmt.Sprintf("task.steps[%d].name is required", i)}
		}
		if strings.TrimSpace(st.Action) == "" {
			return &MappingError{Code: CodeUnsupportedMapping, Detail: fmt.Sprintf("task.steps[%d].action is required", i)}
		}
		if !supportedStepActions[st.Action] {
			return &MappingError{Code: CodeUnsupportedMapping, Detail: fmt.Sprintf("task.steps[%d].action %q has no native mapping", i, st.Action)}
		}
		if strings.TrimSpace(st.Target) == "" {
			return &MappingError{Code: CodeUnsupportedMapping, Detail: fmt.Sprintf("task.steps[%d].target is required", i)}
		}
		if st.Value == nil {
			return &MappingError{Code: CodeUnsupportedMapping, Detail: fmt.Sprintf("task.steps[%d].value is required; no in-band nulls", i)}
		}
		if m, ok := st.Value.(Missing); ok {
			if err := validateMissing(m, fmt.Sprintf("task.steps[%d].value", i)); err != nil {
				return &MappingError{Code: CodeUnsupportedMapping, Detail: err.Error()}
			}
		} else if m, ok := st.Value.(*Missing); ok {
			if m == nil {
				return &MappingError{Code: CodeUnsupportedMapping, Detail: fmt.Sprintf("task.steps[%d].value must not be an in-band null", i)}
			}
			if err := validateMissing(*m, fmt.Sprintf("task.steps[%d].value", i)); err != nil {
				return &MappingError{Code: CodeUnsupportedMapping, Detail: err.Error()}
			}
		}
		if st.RetryPolicy.MaxAttempts < 0 || st.RetryPolicy.BackoffMs < 0 {
			return &MappingError{Code: CodeUnsupportedMapping, Detail: fmt.Sprintf("task.steps[%d].retry_policy must be nonnegative", i)}
		}
	}
	return nil
}

func validateStatePolicy(p StatePolicy, field string, modes map[string]bool) error {
	if !modes[p.Mode] {
		return &MappingError{Code: CodeUnsupportedMapping, Detail: fmt.Sprintf("%s.mode %q has no native mapping", field, p.Mode)}
	}
	if !validRequirements[p.Requirement] {
		return &MappingError{Code: CodeInvalidRequest, Detail: fmt.Sprintf("%s.requirement %q is unknown", field, p.Requirement)}
	}
	switch v := p.ResourceRef.(type) {
	case nil:
		return &MappingError{Code: CodeInvalidRequest, Detail: field + ".resource_ref must not be an in-band null"}
	case string:
		if strings.TrimSpace(v) == "" {
			return &MappingError{Code: CodeInvalidRequest, Detail: field + ".resource_ref must be a nonempty identifier or Missing"}
		}
	case Missing:
		if err := validateMissing(v, field+".resource_ref"); err != nil {
			return &MappingError{Code: CodeInvalidRequest, Detail: err.Error()}
		}
	case *Missing:
		if v == nil {
			return &MappingError{Code: CodeInvalidRequest, Detail: field + ".resource_ref must not be an in-band null"}
		}
		if err := validateMissing(*v, field+".resource_ref"); err != nil {
			return &MappingError{Code: CodeInvalidRequest, Detail: err.Error()}
		}
	default:
		return &MappingError{Code: CodeInvalidRequest, Detail: field + ".resource_ref must be an identifier or Missing"}
	}
	switch v := p.Baseline.(type) {
	case nil:
		return &MappingError{Code: CodeInvalidRequest, Detail: field + ".baseline must not be an in-band null"}
	case ArtifactReference:
		if err := validateArtifactReference(v, field+".baseline"); err != nil {
			return err
		}
	case *ArtifactReference:
		if v == nil {
			return &MappingError{Code: CodeInvalidRequest, Detail: field + ".baseline must not be an in-band null"}
		}
		if err := validateArtifactReference(*v, field+".baseline"); err != nil {
			return err
		}
	case Missing:
		if err := validateMissing(v, field+".baseline"); err != nil {
			return &MappingError{Code: CodeInvalidRequest, Detail: err.Error()}
		}
	case *Missing:
		if v == nil {
			return &MappingError{Code: CodeInvalidRequest, Detail: field + ".baseline must not be an in-band null"}
		}
		if err := validateMissing(*v, field+".baseline"); err != nil {
			return &MappingError{Code: CodeInvalidRequest, Detail: err.Error()}
		}
	default:
		return &MappingError{Code: CodeInvalidRequest, Detail: field + ".baseline must be an artifact or Missing"}
	}
	return nil
}

func validateAssistance(a AssistanceRecord, planningRefs []EvidenceRef) error {
	if !validPlanningOwners[a.PlanningOwner] {
		return &MappingError{Code: CodeInvalidRequest, Detail: fmt.Sprintf("assistance.planning_owner %q is unknown", a.PlanningOwner)}
	}
	if strings.TrimSpace(a.AssistanceTrack) == "" {
		return &MappingError{Code: CodeInvalidRequest, Detail: "assistance.assistance_track must be a nonempty identifier"}
	}
	switch v := a.PlannerIdentity.(type) {
	case nil:
		return &MappingError{Code: CodeInvalidRequest, Detail: "assistance.planner_identity must not be an in-band null"}
	case string:
		if strings.TrimSpace(v) == "" {
			return &MappingError{Code: CodeInvalidRequest, Detail: "assistance.planner_identity must be a nonempty identifier or Missing"}
		}
	case Missing:
		if err := validateMissing(v, "assistance.planner_identity"); err != nil {
			return &MappingError{Code: CodeInvalidRequest, Detail: err.Error()}
		}
	case *Missing:
		if v == nil {
			return &MappingError{Code: CodeInvalidRequest, Detail: "assistance.planner_identity must not be an in-band null"}
		}
		if err := validateMissing(*v, "assistance.planner_identity"); err != nil {
			return &MappingError{Code: CodeInvalidRequest, Detail: err.Error()}
		}
	default:
		return &MappingError{Code: CodeInvalidRequest, Detail: "assistance.planner_identity must be an identifier or Missing"}
	}
	switch v := a.Plan.(type) {
	case nil:
		return &MappingError{Code: CodeInvalidRequest, Detail: "assistance.plan must not be an in-band null"}
	case ArtifactReference:
		if err := validateArtifactReference(v, "assistance.plan"); err != nil {
			return err
		}
	case *ArtifactReference:
		if v == nil {
			return &MappingError{Code: CodeInvalidRequest, Detail: "assistance.plan must not be an in-band null"}
		}
		if err := validateArtifactReference(*v, "assistance.plan"); err != nil {
			return err
		}
	case Missing:
		if err := validateMissing(v, "assistance.plan"); err != nil {
			return &MappingError{Code: CodeInvalidRequest, Detail: err.Error()}
		}
		// Recorded-plan mappings require the plan and its provenance.
		if a.PlanningOwner == "external_planner" {
			return &MappingError{Code: CodeUnsupportedMapping, Detail: "recorded-plan mapping requires assistance.plan and planning provenance"}
		}
	case *Missing:
		if v == nil {
			return &MappingError{Code: CodeInvalidRequest, Detail: "assistance.plan must not be an in-band null"}
		}
		if err := validateMissing(*v, "assistance.plan"); err != nil {
			return &MappingError{Code: CodeInvalidRequest, Detail: err.Error()}
		}
		if a.PlanningOwner == "external_planner" {
			return &MappingError{Code: CodeUnsupportedMapping, Detail: "recorded-plan mapping requires assistance.plan and planning provenance"}
		}
	default:
		return &MappingError{Code: CodeInvalidRequest, Detail: "assistance.plan must be an artifact or Missing"}
	}
	if a.PlanningOwner == "external_planner" && len(planningRefs) == 0 {
		return &MappingError{Code: CodeUnsupportedMapping, Detail: "recorded-plan mapping requires planning_evidence_refs provenance"}
	}
	if strings.TrimSpace(a.Description) == "" {
		return &MappingError{Code: CodeInvalidRequest, Detail: "assistance.description must be nonempty"}
	}
	return nil
}

// enforceReadOnly rejects any read-only task that reaches for application
// mutation authority. Interface labels and HTTP method alone never decide;
// the declared actions and effect policy do. Permissive goal text, plan
// artifacts, redirects, and extraction extensions cannot grant authority:
// the effect policy stays read_only and mutation steps are rejected.
func enforceReadOnly(t TaskEnvelope, scope WorkScope) error {
	if t.TaskType == "apply" {
		return nil
	}
	// Scope and effect policy were validated structurally; re-check the
	// authority direction with a forbidden signal.
	if scope.Activity != "discovery" {
		return &MappingError{Code: CodeForbidden, Detail: "read-only extraction cannot acquire application_attempt scope"}
	}
	if t.EffectPolicy != "read_only" {
		return &MappingError{Code: CodeForbidden, Detail: "read-only extraction cannot acquire commissioned_application authority"}
	}
	for i := range t.Steps {
		st := t.Steps[i]
		if mutationStepActions[st.Action] {
			return &MappingError{Code: CodeForbidden, Detail: fmt.Sprintf("read-only task step %q action %q would mutate the application", st.Name, st.Action)}
		}
		if !readOnlyStepActions[st.Action] {
			return &MappingError{Code: CodeForbidden, Detail: fmt.Sprintf("read-only task step %q action %q is not a read-only acquisition", st.Name, st.Action)}
		}
		lowered := strings.ToLower(st.Target)
		if strings.Contains(lowered, "submit") || strings.Contains(lowered, "apply/") || strings.Contains(lowered, "/apply") {
			return &MappingError{Code: CodeForbidden, Detail: fmt.Sprintf("read-only task step %q target %q addresses an application mutation", st.Name, st.Target)}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// NormalizeNative: faithful native-result normalization.
// ---------------------------------------------------------------------------

// NormalizeNative maps one retained native body to execution claims. raw
// must be the content-addressed handle of body; checks carries the
// independently established authentication and correlation; mapping pins the
// interpretation contract; evidence carries the journal support for receipt
// and limitations.
//
// Unverified source or unmatched correlation yields no accepted claims (an
// empty slice and nil error) while retaining the raw bytes. Malformed bodies
// are explicit mapping failures. Nullable native fields become reasoned
// Missingness. Completed and failed responses each yield exactly one
// execution_lifecycle claim with no application assertions. Missing step
// timing maps to unavailable; explicit reported zero is preserved.
func NormalizeNative(raw ArtifactReference, body []byte, checks SourceChecks, mapping VersionPin, evidence []JournalEnvelope) ([]ExecutionClaim, error) {
	if err := validateVersionPin(mapping, "mapping"); err != nil {
		return nil, err
	}
	if err := validateArtifactReference(raw, "raw"); err != nil {
		return nil, err
	}
	if raw.SizeBytes != int64(len(body)) {
		return nil, &MappingError{Code: CodeIntegrityConflict, Detail: fmt.Sprintf("raw.size_bytes %d does not match retained body length %d", raw.SizeBytes, len(body))}
	}
	if string(evidence_codec.HashBytes(body)) != raw.Digest {
		return nil, &MappingError{Code: CodeIntegrityConflict, Detail: "raw.digest does not match retained native body bytes"}
	}
	for i := range evidence {
		doc, err := json.Marshal(evidence[i])
		if err != nil {
			return nil, &MappingError{Code: CodeInvalidRequest, Detail: fmt.Sprintf("evidence[%d] cannot be serialized: %v", i, err)}
		}
		sv := evidence[i].SchemaVersion
		rt := evidence[i].RecordType
		if strings.TrimSpace(sv) == "" {
			sv = SchemaEvidenceKernel
		}
		if strings.TrimSpace(rt) == "" {
			rt = "journal_event"
		}
		if err := evidence_codec.ValidateRecord(sv, rt, doc); err != nil {
			return nil, &MappingError{Code: CodeInvalidRequest, Detail: fmt.Sprintf("evidence[%d] violates structural gates: %v", i, err)}
		}
	}
	if err := validateSourceChecks(checks); err != nil {
		return nil, err
	}
	// Gate: accepted claims require verified source and matched attempt
	// correlation. Anything else retains raw bytes but yields no accepted
	// normalized claims. Trace mismatch stays visible on the accepted
	// claim when alternate correlation succeeds.
	if checks.Authentication != "verified" || checks.Correlation != "matched" {
		return []ExecutionClaim{}, nil
	}
	if len(checks.MatchedBy) == 0 {
		return nil, &MappingError{Code: CodeInvalidRequest, Detail: "verified source checks require at least one matched_by input"}
	}
	if len(evidence) == 0 {
		return nil, &MappingError{Code: CodeInvalidRequest, Detail: "accepted normalization requires at least one evidence envelope for support"}
	}
	if err := checkDuplicateKeysNative(body); err != nil {
		return nil, &MappingError{Code: CodeMappingFailure, Detail: "malformed native body: " + err.Error()}
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, &MappingError{Code: CodeMappingFailure, Detail: "malformed native body: top-level value must be a JSON object"}
	}
	var fields map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&fields); err != nil {
		return nil, &MappingError{Code: CodeMappingFailure, Detail: "malformed native body: " + err.Error()}
	}
	if fields == nil {
		return nil, &MappingError{Code: CodeMappingFailure, Detail: "malformed native body: top-level value must be a JSON object"}
	}
	state, scope, err := parseNativeState(fields)
	if err != nil {
		return nil, err
	}
	runID, err := parseNullableStringField(fields, "native_run_id")
	if err != nil {
		return nil, err
	}
	msgID, err := parseNullableStringField(fields, "native_message_id")
	if err != nil {
		return nil, err
	}
	nativeErr, err := parseNullableStringField(fields, "error")
	if err != nil {
		return nil, err
	}
	steps, err := parseNativeSteps(fields)
	if err != nil {
		return nil, err
	}
	timing, err := parseNativeTiming(fields, steps)
	if err != nil {
		return nil, err
	}
	madeAt, err := parseNativeMadeAt(fields)
	if err != nil {
		return nil, err
	}
	claimID := claimIDForBody(body)
	received := TimePoint{
		ClockID:           "engine-clock",
		BootID:            "boot-1",
		Origin:            clock_rules.OriginEngineMeasured,
		MonotonicOffsetMs: float64(evidence[0].Sequence * 1000),
		UTCAnnotation:     Missing{Reason: "not_applicable"},
	}
	if received.MonotonicOffsetMs < 0 {
		received.MonotonicOffsetMs = 0
	}
	available := make([]EvidenceRef, 0, len(evidence))
	for i := range evidence {
		available = append(available, EvidenceRef{
			JournalID: evidence[i].JournalID,
			Sequence:  evidence[i].Sequence,
			EventID:   evidence[i].EventID,
			EventHash: string(evidence[i].EventHash),
			Pointer:   "",
		})
	}
	support := append([]EvidenceRef(nil), available...)
	limitations := []string{
		"mapping " + mapping.ID + ":" + mapping.Version,
		"native report retained at " + raw.Digest,
	}
	switch s := state.(type) {
	case string:
		limitations = append(limitations, "native "+s+" is execution lifecycle evidence only; no application commitment established")
		if s == "failed" {
			if es, ok := nativeErr.(string); ok && strings.TrimSpace(es) != "" {
				limitations = append(limitations, "native error: "+es)
			} else {
				limitations = append(limitations, "native failure detail unavailable")
			}
		}
	case Missing:
		limitations = append(limitations, "absent native state is Missing; no subject claim of unknown invented")
	default:
		limitations = append(limitations, "native state mapped without application commitment")
	}
	if timing.Method == clock_rules.MethodUnavailable {
		limitations = append(limitations, "native step timing unavailable; no endpoints invented")
	} else {
		limitations = append(limitations, "native reported duration preserved exactly as subject-reported")
	}
	if checks.TraceCorrelation == "mismatched" {
		limitations = append(limitations, "trace correlation mismatched; alternate correlation evidence retained in source checks")
	}
	claim := ExecutionClaim{
		ClaimID:                    claimID,
		Scope:                      scope,
		State:                      state,
		ApplicationAssertions:      []CommitmentAssertion{},
		NativeRunID:                runID,
		NativeMessageID:            msgID,
		NativeReport:               raw,
		Mapping:                    mapping,
		SourceChecks:               checks,
		MadeAt:                     madeAt,
		ReceivedAt:                 received,
		EvidenceAvailableToClaimant: available,
		EvidenceRefs:               support,
		Limitations:                limitations,
		NativeTiming:               timing,
		Steps:                      steps,
	}
	if !validClaimScopes[claim.Scope] {
		return nil, &MappingError{Code: CodeMappingFailure, Detail: "mapped claim scope is not in the closed set"}
	}
	return []ExecutionClaim{claim}, nil
}

func validateSourceChecks(c SourceChecks) error {
	if !validAuthentications[c.Authentication] {
		return &MappingError{Code: CodeInvalidRequest, Detail: fmt.Sprintf("source_checks.authentication %q is unknown", c.Authentication)}
	}
	if !validCorrelations[c.Correlation] {
		return &MappingError{Code: CodeInvalidRequest, Detail: fmt.Sprintf("source_checks.correlation %q is unknown", c.Correlation)}
	}
	if !validTraceCorrelations[c.TraceCorrelation] {
		return &MappingError{Code: CodeInvalidRequest, Detail: fmt.Sprintf("source_checks.trace_correlation %q is unknown", c.TraceCorrelation)}
	}
	if err := validateVersionPin(c.VerificationPolicy, "source_checks.verification_policy"); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, name := range c.MatchedBy {
		if strings.TrimSpace(name) == "" {
			return &MappingError{Code: CodeInvalidRequest, Detail: "source_checks.matched_by entries must be nonempty identifiers"}
		}
		if seen[name] {
			return &MappingError{Code: CodeInvalidRequest, Detail: fmt.Sprintf("duplicate source_checks.matched_by entry %q", name)}
		}
		seen[name] = true
	}
	if len(c.EvidenceRefs) == 0 {
		return &MappingError{Code: CodeInvalidRequest, Detail: "source_checks.evidence_refs must carry at least one reference"}
	}
	for i := range c.EvidenceRefs {
		if err := validateEvidenceRef(c.EvidenceRefs[i], fmt.Sprintf("source_checks.evidence_refs[%d]", i)); err != nil {
			return err
		}
	}
	return nil
}

func claimIDForBody(body []byte) string {
	d := string(evidence_codec.HashBytes(body))
	hexPart := strings.TrimPrefix(d, "sha256:")
	if len(hexPart) > 16 {
		hexPart = hexPart[:16]
	}
	if hexPart == "" {
		hexPart = "emptybody"
	}
	return "claim-" + hexPart
}

// parseNativeState maps the native state field. Absent or null state is
// Missing with scope unknown; explicit "unknown" remains a valid subject
// claim with lifecycle scope; running/completed/failed/stopped map to
// lifecycle scope with the same state. Any other shape is an explicit
// mapping failure, never a silent reinterpretation.
func parseNativeState(fields map[string]json.RawMessage) (any, string, error) {
	raw, present := fields["state"]
	if !present {
		return Missing{Reason: "not_observed", Detail: "native field absent: state"}, "unknown", nil
	}
	if string(bytes.TrimSpace(raw)) == "null" {
		return Missing{Reason: "not_observed", Detail: "native field null: state"}, "unknown", nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if !validNativeStates[s] {
			return nil, "", &MappingError{Code: CodeMappingFailure, Detail: fmt.Sprintf("unsupported native state %q", s)}
		}
		if s == "unknown" {
			return "unknown", "execution_lifecycle", nil
		}
		return s, "execution_lifecycle", nil
	}
	return nil, "", &MappingError{Code: CodeMappingFailure, Detail: "malformed native state: must be a string or null"}
}

// parseNullableStringField maps a nullable native string field to a string
// or a reasoned Missing. Missing and null remain distinct via detail.
func parseNullableStringField(fields map[string]json.RawMessage, name string) (any, error) {
	raw, present := fields[name]
	if !present {
		return Missing{Reason: "not_observed", Detail: "native field absent: " + name}, nil
	}
	if string(bytes.TrimSpace(raw)) == "null" {
		return Missing{Reason: "not_observed", Detail: "native field null: " + name}, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, &MappingError{Code: CodeMappingFailure, Detail: fmt.Sprintf("malformed native field %q: must be a string or null", name)}
	}
	if strings.TrimSpace(s) == "" {
		return Missing{Reason: "not_observed", Detail: "native field empty: " + name}, nil
	}
	return s, nil
}

// parseNativeSteps normalizes the optional native steps array. Each step
// requires a name; status, detail, and duration are nullable. Durations are
// validated through the clock kernel: missing stays unavailable, explicit
// zero stays exact zero, and negative or mistyped durations are explicit
// mapping failures.
func parseNativeSteps(fields map[string]json.RawMessage) ([]ClaimStep, error) {
	raw, present := fields["steps"]
	if !present {
		return []ClaimStep{}, nil
	}
	if string(bytes.TrimSpace(raw)) == "null" {
		return []ClaimStep{}, nil
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, &MappingError{Code: CodeMappingFailure, Detail: "malformed native steps: must be an array or null"}
	}
	out := make([]ClaimStep, 0, len(items))
	for i := range items {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(items[i], &obj); err != nil {
			return nil, &MappingError{Code: CodeMappingFailure, Detail: fmt.Sprintf("malformed native steps[%d]: must be an object", i)}
		}
		if obj == nil {
			return nil, &MappingError{Code: CodeMappingFailure, Detail: fmt.Sprintf("malformed native steps[%d]: must be an object", i)}
		}
		nameRaw, ok := obj["name"]
		if !ok || string(bytes.TrimSpace(nameRaw)) == "null" {
			return nil, &MappingError{Code: CodeMappingFailure, Detail: fmt.Sprintf("malformed native steps[%d].name: name is required", i)}
		}
		var name string
		if err := json.Unmarshal(nameRaw, &name); err != nil || strings.TrimSpace(name) == "" {
			return nil, &MappingError{Code: CodeMappingFailure, Detail: fmt.Sprintf("malformed native steps[%d].name: name must be a nonempty string", i)}
		}
		status, err := parseNullableStepString(obj, i, "status")
		if err != nil {
			return nil, err
		}
		detail, err := parseNullableStepString(obj, i, "detail")
		if err != nil {
			return nil, err
		}
		duration, err := parseNativeDuration(obj, fmt.Sprintf("steps[%d].duration_ms", i), fmt.Sprintf("native-step-%d", i))
		if err != nil {
			return nil, err
		}
		out = append(out, ClaimStep{Name: name, Status: status, Detail: detail, DurationMs: duration})
	}
	return out, nil
}

func parseNullableStepString(obj map[string]json.RawMessage, idx int, name string) (any, error) {
	raw, present := obj[name]
	if !present {
		return Missing{Reason: "not_observed", Detail: fmt.Sprintf("native field absent: steps[%d].%s", idx, name)}, nil
	}
	if string(bytes.TrimSpace(raw)) == "null" {
		return Missing{Reason: "not_observed", Detail: fmt.Sprintf("native field null: steps[%d].%s", idx, name)}, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, &MappingError{Code: CodeMappingFailure, Detail: fmt.Sprintf("malformed native steps[%d].%s: must be a string or null", idx, name)}
	}
	if strings.TrimSpace(s) == "" {
		return Missing{Reason: "not_observed", Detail: fmt.Sprintf("native field empty: steps[%d].%s", idx, name)}, nil
	}
	return s, nil
}

// nativeClocks returns the registered lifetimes for timing validation: an
// opaque-report subject clock for native durations without coordinates and
// the engine monotonic clock for receipt coordinates.
func nativeClocks() []clock_rules.ClockDescriptor {
	return []clock_rules.ClockDescriptor{
		{ClockID: "native-opaque", BootID: "native-boot-1", Origin: clock_rules.OriginSubjectReported, SourceID: "native-subject", Basis: clock_rules.BasisOpaqueReport, Unit: "ms"},
		{ClockID: "engine-clock", BootID: "boot-1", Origin: clock_rules.OriginEngineMeasured, SourceID: "engine", Basis: clock_rules.BasisMonotonicOffset, Unit: "ms"},
	}
}

// validatedUnavailableTiming builds and kernel-validates the unavailable
// timing for absent native durations. It never invents endpoints.
func validatedUnavailableTiming(measurementID string) (NativeTiming, error) {
	m := clock_rules.Measurement{
		MeasurementID:      measurementID,
		Name:               "native_step_duration",
		Scope:              clock_rules.Scope{Kind: "native_primitive", ID: "step-1"},
		Quantity:           clock_rules.QuantityDuration,
		Unit:               "ms",
		Origin:             clock_rules.OriginSubjectReported,
		ClockID:            "native-opaque",
		BootID:             "native-boot-1",
		Method:             clock_rules.MethodUnavailable,
		Start:              clock_rules.Missing{Reason: "not_observed"},
		End:                clock_rules.Missing{Reason: "not_observed"},
		Estimate:           clock_rules.Estimate{Kind: clock_rules.EstimateUnavailable, Value: clock_rules.Missing{Reason: "not_observed"}},
		Resolution:         clock_rules.Missing{Reason: "not_applicable"},
		Censoring:          clock_rules.CensoringUnavailable,
		ComparabilityGroup: clock_rules.Missing{Reason: "not_applicable"},
	}
	if err := clock_rules.ValidateMeasurement(m, nativeClocks()); err != nil {
		return NativeTiming{}, &MappingError{Code: CodeMappingFailure, Detail: "unavailable native timing failed kernel validation: " + err.Error()}
	}
	return NativeTiming{DurationMs: Missing{Reason: "not_observed", Detail: "native timing absent"}, Method: clock_rules.MethodUnavailable, Censoring: clock_rules.CensoringUnavailable}, nil
}

// validatedExactTiming builds and kernel-validates the exact subject-reported
// timing for a concrete native duration. Explicit zero is preserved.
func validatedExactTiming(measurementID string, value float64) (NativeTiming, error) {
	m := clock_rules.Measurement{
		MeasurementID:      measurementID,
		Name:               "native_step_duration",
		Scope:              clock_rules.Scope{Kind: "native_primitive", ID: "step-1"},
		Quantity:           clock_rules.QuantityDuration,
		Unit:               "ms",
		Origin:             clock_rules.OriginSubjectReported,
		ClockID:            "native-opaque",
		BootID:             "native-boot-1",
		Method:             clock_rules.MethodSourceValue,
		Start:              clock_rules.Missing{Reason: "not_observed"},
		End:                clock_rules.Missing{Reason: "not_observed"},
		Estimate:           clock_rules.Estimate{Kind: clock_rules.EstimateExact, Value: value},
		Resolution:         clock_rules.Missing{Reason: "not_applicable"},
		Censoring:          clock_rules.CensoringNone,
		ComparabilityGroup: clock_rules.Missing{Reason: "not_applicable"},
	}
	if err := clock_rules.ValidateMeasurement(m, nativeClocks()); err != nil {
		return NativeTiming{}, &MappingError{Code: CodeMappingFailure, Detail: "native reported timing failed kernel validation: " + err.Error()}
	}
	return NativeTiming{DurationMs: value, Method: clock_rules.MethodSourceValue, Censoring: clock_rules.CensoringNone}, nil
}

// parseNativeDuration maps one nullable duration field through the clock
// kernel and returns the normalized duration (float64 or Missing).
func parseNativeDuration(obj map[string]json.RawMessage, field, measurementID string) (any, error) {
	raw, present := obj[fieldKey(field)]
	if !present {
		t, err := validatedUnavailableTiming(measurementID)
		if err != nil {
			return nil, err
		}
		return t.DurationMs, nil
	}
	if string(bytes.TrimSpace(raw)) == "null" {
		t, err := validatedUnavailableTiming(measurementID)
		if err != nil {
			return nil, err
		}
		// Keep null distinct from absent via detail while sharing the
		// unavailable kernel shape.
		if m, ok := t.DurationMs.(Missing); ok {
			m.Detail = "native field null: " + field
			return m, nil
		}
		return t.DurationMs, nil
	}
	var num json.Number
	if err := json.Unmarshal(raw, &num); err != nil {
		return nil, &MappingError{Code: CodeMappingFailure, Detail: "malformed native field " + field + ": must be a number or null"}
	}
	f, err := num.Float64()
	if err != nil {
		return nil, &MappingError{Code: CodeMappingFailure, Detail: "malformed native field " + field + ": must be a number or null"}
	}
	if f < 0 {
		return nil, &MappingError{Code: CodeMappingFailure, Detail: "malformed native field " + field + ": duration must be nonnegative"}
	}
	t, err := validatedExactTiming(measurementID, f)
	if err != nil {
		return nil, err
	}
	return t.DurationMs, nil
}

func fieldKey(field string) string {
	if idx := strings.LastIndex(field, "."); idx >= 0 {
		return field[idx+1:]
	}
	return field
}

// parseNativeTiming maps top-level native timing. When top-level timing is
// absent, the first step duration (when present) supplies the claim timing;
// otherwise timing is unavailable. No endpoints are ever invented.
func parseNativeTiming(fields map[string]json.RawMessage, steps []ClaimStep) (NativeTiming, error) {
	raw, present := fields["timing"]
	if !present || string(bytes.TrimSpace(raw)) == "null" {
		if len(steps) > 0 {
			if f, ok := steps[0].DurationMs.(float64); ok {
				return validatedExactTiming("native-top-timing-from-step", f)
			}
		}
		return validatedUnavailableTiming("native-top-timing")
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		return NativeTiming{}, &MappingError{Code: CodeMappingFailure, Detail: "malformed native timing: must be an object or null"}
	}
	durRaw, hasDur := obj["duration_ms"]
	if !hasDur || string(bytes.TrimSpace(durRaw)) == "null" {
		if len(steps) > 0 {
			if f, ok := steps[0].DurationMs.(float64); ok {
				return validatedExactTiming("native-top-timing-from-step", f)
			}
		}
		t, err := validatedUnavailableTiming("native-top-timing")
		if err != nil {
			return NativeTiming{}, err
		}
		if hasDur {
			if m, ok := t.DurationMs.(Missing); ok {
				m.Detail = "native field null: timing.duration_ms"
				t.DurationMs = m
			}
		} else {
			if m, ok := t.DurationMs.(Missing); ok {
				m.Detail = "native field absent: timing.duration_ms"
				t.DurationMs = m
			}
		}
		return t, nil
	}
	var num json.Number
	if err := json.Unmarshal(durRaw, &num); err != nil {
		return NativeTiming{}, &MappingError{Code: CodeMappingFailure, Detail: "malformed native timing.duration_ms: must be a number or null"}
	}
	f, err := num.Float64()
	if err != nil {
		return NativeTiming{}, &MappingError{Code: CodeMappingFailure, Detail: "malformed native timing.duration_ms: must be a number or null"}
	}
	if f < 0 {
		return NativeTiming{}, &MappingError{Code: CodeMappingFailure, Detail: "malformed native timing.duration_ms: duration must be nonnegative"}
	}
	return validatedExactTiming("native-top-timing", f)
}

// parseNativeMadeAt maps the optional native made_at coordinate. Absent or
// null made_at is Missing; a present object must be a well-formed TimePoint
// and is preserved verbatim.
func parseNativeMadeAt(fields map[string]json.RawMessage) (any, error) {
	raw, present := fields["made_at"]
	if !present || string(bytes.TrimSpace(raw)) == "null" {
		detail := "native made_at absent"
		if present {
			detail = "native made_at null"
		}
		return Missing{Reason: "not_observed", Detail: detail}, nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		return nil, &MappingError{Code: CodeMappingFailure, Detail: "malformed native made_at: must be an object or null"}
	}
	var clockID, bootID, origin string
	if err := json.Unmarshal(firstOrNull(obj["clock_id"]), &clockID); err != nil || strings.TrimSpace(clockID) == "" {
		return nil, &MappingError{Code: CodeMappingFailure, Detail: "malformed native made_at.clock_id"}
	}
	if err := json.Unmarshal(firstOrNull(obj["boot_id"]), &bootID); err != nil || strings.TrimSpace(bootID) == "" {
		return nil, &MappingError{Code: CodeMappingFailure, Detail: "malformed native made_at.boot_id"}
	}
	if err := json.Unmarshal(firstOrNull(obj["origin"]), &origin); err != nil || strings.TrimSpace(origin) == "" {
		return nil, &MappingError{Code: CodeMappingFailure, Detail: "malformed native made_at.origin"}
	}
	var offset json.Number
	if err := json.Unmarshal(firstOrNull(obj["monotonic_offset_ms"]), &offset); err != nil {
		return nil, &MappingError{Code: CodeMappingFailure, Detail: "malformed native made_at.monotonic_offset_ms"}
	}
	f, err := offset.Float64()
	if err != nil || f < 0 {
		return nil, &MappingError{Code: CodeMappingFailure, Detail: "malformed native made_at.monotonic_offset_ms"}
	}
	utcRaw, ok := obj["utc_annotation"]
	var utc any
	if !ok || string(bytes.TrimSpace(utcRaw)) == "null" {
		return nil, &MappingError{Code: CodeMappingFailure, Detail: "malformed native made_at.utc_annotation: must be a date-time string or Missing, never a bare null"}
	}
	var asStr string
	if err := json.Unmarshal(utcRaw, &asStr); err == nil {
		if strings.TrimSpace(asStr) == "" {
			return nil, &MappingError{Code: CodeMappingFailure, Detail: "malformed native made_at.utc_annotation"}
		}
		utc = asStr
	} else {
		var m Missing
		if err := json.Unmarshal(utcRaw, &m); err != nil {
			return nil, &MappingError{Code: CodeMappingFailure, Detail: "malformed native made_at.utc_annotation: must be a date-time string or Missing"}
		}
		if err := validateMissing(m, "made_at.utc_annotation"); err != nil {
			return nil, &MappingError{Code: CodeMappingFailure, Detail: err.Error()}
		}
		utc = m
	}
	return TimePoint{ClockID: clockID, BootID: bootID, Origin: origin, MonotonicOffsetMs: f, UTCAnnotation: utc}, nil
}

func firstOrNull(raw json.RawMessage) []byte {
	if len(raw) == 0 {
		return []byte("null")
	}
	return raw
}

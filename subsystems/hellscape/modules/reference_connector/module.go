// Package reference_connector implements the tier-5 Hellscape reference
// external connector: the synthetic task-shaped HTTP binding for the nine
// versioned verbs (Describe, Prepare, Start, Observe, RequestNativeCancel,
// CloseObservationConnection, CollectArtifacts, ReleaseNativeContext,
// Contain) over POST /connector.
//
// Seam references: seam-mappings/hellscape-seam-mapping.md sections 4.3
// (connector persistence boundary), 8.2-8.15 (descriptor, prepare, start,
// observe, controls, artifact transfer), 16.4 (synthetic corpus), plus
// contracts/02-external-connector.yaml invariants EXT-* and LIFE-*.
//
// Semantic boundaries enforced here:
//
//   - Exactly the nine versioned verbs exist; the surface is task-shaped and
//     browser-agnostic. No Page, ElementHandle, selector engine, DOM handle,
//     or synchronous browser primitive is defined (EXT-SURFACE).
//   - A descriptor pins one subject/version/mode/interface; new subject
//     versions start unknown on every capability (EXT-DESCRIBE).
//   - The connector declares capabilities, mappings, observations, and
//     source claims; it never emits qualification or application success
//     (EXT-DECLARE-NOT-ASSESS).
//   - Prepare is non-executing: no target visit, auth test, context reset,
//     planner invocation, or hidden improvement (EXT-PREPARE).
//   - Start durably commits handle, immutable request binding, logical key,
//     and dispatch intent under owner-local fencing before wire delivery,
//     then returns a local receipt without awaiting completion (EXT-START).
//   - Command idempotency uses (principal, connector_id, request_id);
//     logical execution idempotency additionally uses commission/key
//     (EXT-IDEMPOTENCY, LIFE-IDEMPOTENCY).
//   - Closing, ending observation, requesting cancellation, releasing
//     context, and containment are separate effects (EXT-CLOSE).
//   - Controls are separately evidenced: request != acknowledgement !=
//     effect (EXT-CONTROLS, LIFE-CONTROLS).
//   - Finite local bounds use registered monotonic clocks; rejected work is
//     reported, never silently lost (EXT-BOUNDS).
//   - ObservationItem copies an already journaled projection; metadata
//     matches the referenced event (EXT-EVIDENCE).
//   - No in-band nulls; all absence uses typed Missing envelopes.
//   - No shared-database writes or cross-owner transactions: exactly one
//     OwnerStore is used, never application/observation/diagnostic DBs.
package reference_connector

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"authority"
	"clock_rules"
	connector_queries "connector_queries"
	"evidence_codec"
	lifecycle_rules "lifecycle_rules"
	native_mapping "native_mapping"
	owner_store "owner_store"
	source_verifier "source_verifier"
)

// ---------------------------------------------------------------------------
// Aliases to owner-local durable types.
// ---------------------------------------------------------------------------

// OwnerStore is one owner-local durable boundary owned by the connector.
type OwnerStore = owner_store.OwnerStore

// JournalEnvelope is the complete stored journal event envelope.
type JournalEnvelope = owner_store.JournalEnvelope

// JournalPrefix is an immutable journal prefix.
type JournalPrefix = owner_store.JournalPrefix

// EvidenceRef cites one retained journal event coordinate.
type EvidenceRef = owner_store.EvidenceRef

// ArtifactReference is an immutable byte identity plus resolver metadata.
type ArtifactReference = owner_store.ArtifactReference

// EventSubmission is the ingress shape for owner-local commits.
type EventSubmission = owner_store.EventSubmission

// TimePoint is a coordinate in a registered monotonic clock.
type TimePoint = owner_store.TimePoint

// MissingEnvelope is the typed EK Missing value.
type MissingEnvelope = owner_store.MissingEnvelope

// ---------------------------------------------------------------------------
// Carrier and envelope constants.
// ---------------------------------------------------------------------------

const (
	RecordTypeRequest    = "connector_request"
	RecordTypeResponse   = "connector_response"
	SchemaVersion        = "external-connector/0.1.0"
	CarrierPath          = "/connector"
	RecordTypeDescriptor = "connector_descriptor"
	RecordTypeHandle     = "connector_handle"
	RecordTypePrep       = "connector_preparation"
)

const (
	OpDescribe                   = "Describe"
	OpPrepare                    = "Prepare"
	OpStart                      = "Start"
	OpObserve                    = "Observe"
	OpRequestNativeCancel        = "RequestNativeCancel"
	OpCloseObservationConnection = "CloseObservationConnection"
	OpCollectArtifacts           = "CollectArtifacts"
	OpReleaseNativeContext       = "ReleaseNativeContext"
	OpContain                    = "Contain"
)

var validOperations = map[string]bool{
	OpDescribe:                   true,
	OpPrepare:                    true,
	OpStart:                      true,
	OpObserve:                    true,
	OpRequestNativeCancel:        true,
	OpCloseObservationConnection: true,
	OpCollectArtifacts:           true,
	OpReleaseNativeContext:       true,
	OpContain:                    true,
}

var mutatingOperations = map[string]bool{
	OpPrepare:                    true,
	OpStart:                      true,
	OpRequestNativeCancel:        true,
	OpCloseObservationConnection: true,
	OpCollectArtifacts:           true,
	OpReleaseNativeContext:       true,
	OpContain:                    true,
}

func isControlOp(op string) bool {
	switch op {
	case OpRequestNativeCancel, OpCloseObservationConnection, OpReleaseNativeContext, OpContain:
		return true
	default:
		return false
	}
}

// Connector error codes (seam 8.14 wire values).
const (
	codeInvalidRequest          = "INVALID_REQUEST"
	codeUnsupportedVersion      = "UNSUPPORTED_VERSION"
	codeUnauthenticated         = "UNAUTHENTICATED"
	codeForbidden               = "FORBIDDEN"
	codeUnknownHandle           = "UNKNOWN_HANDLE"
	codeUnknownPreparation      = "UNKNOWN_PREPARATION"
	codeStalePreparation        = "STALE_PREPARATION"
	codeIdempotencyConflict     = "IDEMPOTENCY_CONFLICT"
	codeUnsupportedMapping      = "UNSUPPORTED_MAPPING"
	codePrerequisiteUnavailable = "PREREQUISITE_UNAVAILABLE"
	codeBudgetExceeded          = "BUDGET_EXCEEDED"
	codeNotAdmitted             = "NOT_ADMITTED"
	codeObservationClosed       = "OBSERVATION_CLOSED"
	codeStaleContext            = "STALE_CONTEXT"
	codeResourceBusy            = "RESOURCE_BUSY"
	codeStorageUnavailable      = "STORAGE_UNAVAILABLE"
	codeDeliveryUncertain       = "DELIVERY_UNCERTAIN"
	codeCursorInvalid           = "CURSOR_INVALID"
	codeCursorUnavailable       = "CURSOR_UNAVAILABLE"
	codeObservationLost         = "OBSERVATION_LOST"
	codeResponseTooLarge        = "RESPONSE_TOO_LARGE"
	codeArtifactUnavailable     = "ARTIFACT_UNAVAILABLE"
	codeNativeProtocolError     = "NATIVE_PROTOCOL_ERROR"
	codeIntegrityConflict       = "INTEGRITY_CONFLICT"
	codeInternalError           = "INTERNAL_ERROR"
)

const (
	domainRequest    = "request"
	domainConnector  = "connector"
	domainNative     = "native_interface"
	domainEnv        = "environment"
	domainPolicy     = "policy"
	domainUnknown    = "unknown"
	deliveryNotDisp  = "not_dispatched"
	deliveryMay      = "may_have_dispatched"
	deliveryDisp     = "dispatched"
	deliveryNA       = "not_applicable"
	retrySame        = "same_command_only"
	retryNewIfNot    = "new_command_if_not_dispatched"
	retryOperator    = "operator_review"
	retryNoRetry     = "do_not_retry"
	kindConnectorErr = "connector_error"
)

const (
	MaxCallLimitMs      = 300_000
	MaxRequestBytes     = 4 << 20
	MaxResponseBytes    = 8 << 20
	MaxObserveItems     = 1000
	MaxCollectChunk     = 1 << 20
	maxNativeBodyBytes  = 4 << 20
	controlEventSchema  = "0.1.0"
	connectorRecordVer  = "0.1.0"
	journalRecordType   = "journal_event"
	journalSchemaVer    = "0.1.0"
	manifestRecordType  = "manifest"
	manifestSchemaVer   = "0.1.0"
	prepJournalFmt      = "preparations-%s"
	connectorClockID    = "connector-clock"
	connectorBootID     = "boot-connector-1"
	connectorClockSrc   = "reference-connector"
)

var nullReasons = map[string]bool{
	"not_enabled": true, "not_applicable": true, "not_observed": true,
	"observation_lost": true, "unsupported_by_subject": true, "manual_override": true,
}

var minimumCapabilityIDs = []string{
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

// ---------------------------------------------------------------------------
// Wire types.
// ---------------------------------------------------------------------------

// DurationLimit is a finite configured allowance, never a measurement.
type DurationLimit struct {
	Kind  string  `json:"kind"`
	Unit  string  `json:"unit"`
	Value float64 `json:"value"`
}

// ConnectorRequest is one task-shaped connector command.
type ConnectorRequest struct {
	RecordType    string          `json:"record_type"`
	SchemaVersion string          `json:"schema_version"`
	RequestID     string          `json:"request_id"`
	ConnectorID   string          `json:"connector_id"`
	Operation     string          `json:"operation"`
	CallLimit     DurationLimit   `json:"call_limit"`
	Payload       json.RawMessage `json:"payload"`
}

// ConnectorResponse is one correlated connector reply.
type ConnectorResponse struct {
	RecordType    string          `json:"record_type"`
	SchemaVersion string          `json:"schema_version"`
	RequestID     string          `json:"request_id"`
	ConnectorID   string          `json:"connector_id"`
	Operation     string          `json:"operation"`
	Result        json.RawMessage `json:"result"`
}

// ConnectorError describes failure of this operation only.
type ConnectorError struct {
	Kind              string       `json:"kind"`
	Code              string       `json:"code"`
	FaultDomain       string       `json:"fault_domain"`
	Detail            string       `json:"detail"`
	OperationDelivery string       `json:"operation_delivery"`
	RetryGuidance     string       `json:"retry_guidance"`
	RetryAfter        json.RawMessage `json:"retry_after"`
	Handle            json.RawMessage `json:"handle"`
	EvidenceRefs      []EvidenceRef `json:"evidence_refs"`
}

func (e *ConnectorError) Error() string {
	if e == nil {
		return "connector <nil>"
	}
	return fmt.Sprintf("connector %s: %s (delivery %s)", e.Code, e.Detail, e.OperationDelivery)
}

// HandleReference is the stable local handle identity.
type HandleReference struct {
	ConnectorID string `json:"connector_id"`
	LocalHandle string `json:"local_handle"`
}

// Missing is a typed EK Missing envelope rendered in connector results.
type Missing struct {
	Value  any    `json:"value"`
	Reason string `json:"reason"`
	Detail string `json:"detail,omitempty"`
}

// VersionPin pins an immutable versioned artifact.
type VersionPin struct {
	ID             string `json:"id"`
	Version        string `json:"version"`
	ArtifactDigest string `json:"artifact_digest"`
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

// Capability declares one subject capability and its availability.
type Capability struct {
	ID           string       `json:"id"`
	Availability string       `json:"availability"`
	EvidenceRefs []EvidenceRef `json:"evidence_refs"`
	Limitations  []string     `json:"limitations"`
}

// OperationMapping declares one verb mapping.
type OperationMapping struct {
	Operation      string   `json:"operation"`
	Implementation string   `json:"implementation"`
	NativeContract any      `json:"native_contract"`
	CapabilityRefs []string `json:"capability_refs"`
	EvidenceRefs   []EvidenceRef `json:"evidence_refs"`
	Limitations    []string `json:"limitations"`
	NativeEndpoint string   `json:"native_endpoint,omitempty"`
}

// TaskMapping declares one task-type mapping.
type TaskMapping struct {
	TaskType       string   `json:"task_type"`
	InputForm      string   `json:"input_form"`
	Mapping        VersionPin `json:"mapping"`
	PlanningOwner  string   `json:"planning_owner"`
	RecoveryOwner  string   `json:"recovery_owner"`
	Limitations    []string `json:"limitations"`
}

// DescriptorLimits are declared configured bounds.
type DescriptorLimits struct {
	MaxCallWait           DurationLimit `json:"max_call_wait"`
	MaxObservationItems   int64         `json:"max_observation_items"`
	MaxRequestBytes       int64         `json:"max_request_bytes"`
	MaxResponseBytes      int64         `json:"max_response_bytes"`
	MaxArtifactChunkBytes int64         `json:"max_artifact_chunk_bytes"`
	MaxQueuedTasks        int64         `json:"max_queued_tasks"`
	MaxActiveTasks        int64         `json:"max_active_tasks"`
}

// ConnectorDescriptor pins one subject/version/mode/interface surface.
type ConnectorDescriptor struct {
	RecordType          string             `json:"record_type"`
	SchemaVersion       string             `json:"schema_version"`
	ConnectorID         string             `json:"connector_id"`
	ConnectorVersion    string             `json:"connector_version"`
	Build               VersionPin         `json:"build"`
	Binding             VersionPin         `json:"binding"`
	Subject             SubjectIdentity    `json:"subject"`
	Capabilities        []Capability       `json:"capabilities"`
	Operations          []OperationMapping `json:"operations"`
	TaskMappings        []TaskMapping      `json:"task_mappings"`
	ObservationChannels []string           `json:"observation_channels"`
	ActionGrounding     any                `json:"action_grounding"`
	ExecutionSubstrate  string             `json:"execution_substrate"`
	Limits              DescriptorLimits   `json:"limits"`
	BudgetAccounting    VersionPin         `json:"budget_accounting"`
	EvidencePrefix      any                `json:"evidence_prefix"`
}

// PreparationReference identifies one immutable preparation.
type PreparationReference struct {
	PreparationID   string            `json:"preparation_id"`
	Artifact        ArtifactReference `json:"artifact"`
	RegistrationRef EvidenceRef       `json:"registration_ref"`
}

// PreparationConcern names one accepted limitation.
type PreparationConcern struct {
	ConcernID          string `json:"concern_id"`
	Description        string `json:"description"`
	RequiresAcceptance bool   `json:"requires_acceptance"`
}

// BudgetMapping maps one budget dimension.
type BudgetMapping struct {
	Dimension   string `json:"dimension"`
	Mapped      bool   `json:"mapped"`
	Limitations []string `json:"limitations"`
}

// PreparedTask is the immutable source for Start.
type PreparedTask struct {
	RecordType          string              `json:"record_type"`
	SchemaVersion       string              `json:"schema_version"`
	PreparationID       string              `json:"preparation_id"`
	Scope               json.RawMessage     `json:"scope"`
	Configuration       json.RawMessage     `json:"configuration"`
	Task                json.RawMessage     `json:"task"`
	TaskSemanticHash     string              `json:"task_semantic_hash"`
	Assistance          json.RawMessage     `json:"assistance"`
	PlanningEvidenceRefs []EvidenceRef      `json:"planning_evidence_refs"`
	RuntimeAccess       json.RawMessage     `json:"runtime_access"`
	DeliveredTask       ArtifactReference   `json:"delivered_task"`
	DeliveredTaskHash   string              `json:"delivered_task_hash"`
	NativeRequest       ArtifactReference   `json:"native_request"`
	NativeRequestHash   string              `json:"native_request_hash"`
	Translation         VersionPin          `json:"translation"`
	BudgetMapping       []BudgetMapping     `json:"budget_mapping"`
	Concerns            []PreparationConcern `json:"concerns"`
	EvidencePrefix      JournalPrefix       `json:"evidence_prefix"`
}

// PrepareResult is the non-executing preparation outcome.
type PrepareResult struct {
	Kind        string               `json:"kind"`
	Preparation PreparationReference `json:"preparation"`
	Record      PreparedTask         `json:"record"`
}

// StartRequest starts or resumes one logical execution.
type StartRequest struct {
	Preparation        PreparationReference `json:"preparation"`
	IdempotencyKey     string               `json:"idempotency_key"`
	AcceptedConcernIDs []string             `json:"accepted_concern_ids"`
	AuthorizationRefs  []EvidenceRef        `json:"authorization_refs"`
	Recovery           json.RawMessage      `json:"recovery"`
}

// ResumeAuthorization authorizes recovery of an existing handle.
type ResumeAuthorization struct {
	Handle               HandleReference    `json:"handle"`
	Checkpoint           ArtifactReference  `json:"checkpoint"`
	NativeResumeContract VersionPin         `json:"native_resume_contract"`
	AuthorizationRefs    []EvidenceRef      `json:"authorization_refs"`
	EvidenceRefs         []EvidenceRef      `json:"evidence_refs"`
}

// ConnectorHandle is the immutable local binding.
type ConnectorHandle struct {
	RecordType     string             `json:"record_type"`
	SchemaVersion  string             `json:"schema_version"`
	Handle         HandleReference    `json:"handle"`
	Preparation    PreparationReference `json:"preparation"`
	Scope          json.RawMessage    `json:"scope"`
	IdempotencyKey string             `json:"idempotency_key"`
	CreatedAt      TimePoint          `json:"created_at"`
}

// StartResult is the local start receipt.
type StartResult struct {
	Kind           string            `json:"kind"`
	Disposition    string            `json:"disposition"`
	Handle         ConnectorHandle   `json:"handle"`
	HandleArtifact ArtifactReference `json:"handle_artifact"`
	ReceiptRef     EvidenceRef       `json:"receipt_ref"`
}

// ObservationCursor identifies a scanned journal position.
type ObservationCursor struct {
	Handle    HandleReference `json:"handle"`
	JournalID string          `json:"journal_id"`
	Sequence  int64           `json:"sequence"`
	EventHash json.RawMessage `json:"event_hash"`
}

// ObserveRequest reads accumulated observations through a prefix.
type ObserveRequest struct {
	Handle    HandleReference   `json:"handle"`
	After     ObservationCursor `json:"after"`
	Through   json.RawMessage   `json:"through"`
	MaxItems  int64             `json:"max_items"`
	WaitLimit DurationLimit     `json:"wait_limit"`
}

// ObservationItem is a read projection of one journaled observation.
type ObservationItem struct {
	EventRef     EvidenceRef         `json:"event_ref"`
	RecordedAt   TimePoint           `json:"recorded_at"`
	Provenance   string              `json:"provenance"`
	Payload      map[string]any      `json:"payload"`
	Measurements []any               `json:"measurements"`
	ArtifactRefs []ArtifactReference `json:"artifact_refs"`
}

// ObservationPage is one bounded observation window.
type ObservationPage struct {
	Kind                string            `json:"kind"`
	Handle              HandleReference   `json:"handle"`
	After               ObservationCursor `json:"after"`
	Through             JournalPrefix     `json:"through"`
	Next                ObservationCursor `json:"next"`
	HasMore             bool              `json:"has_more"`
	ObservationCloseRef json.RawMessage   `json:"observation_close_ref"`
	Items               []ObservationItem `json:"items"`
	Limitations         []string          `json:"limitations"`
}

// CollectSelector selects inventory, named artifacts, or bytes.
type CollectSelector struct {
	Mode     string   `json:"mode"`
	Names    []string `json:"names,omitempty"`
	Digest   string   `json:"digest,omitempty"`
	Offset   int64    `json:"offset,omitempty"`
	MaxBytes int64    `json:"max_bytes,omitempty"`
}

// CollectArtifactsRequest enumerates or transfers retained artifacts.
type CollectArtifactsRequest struct {
	Handle   HandleReference `json:"handle"`
	Selector CollectSelector `json:"selector"`
}

// ArtifactSlot binds one artifact name to content plus evidence.
type ArtifactSlot struct {
	Name           string          `json:"name"`
	ExpectedDigest json.RawMessage `json:"expected_digest"`
	Content        json.RawMessage `json:"content"`
	EvidenceRefs   []EvidenceRef   `json:"evidence_refs"`
}

// ArtifactInventory lists artifact slots scoped to a prefix.
type ArtifactInventory struct {
	Kind           string          `json:"kind"`
	Handle         HandleReference `json:"handle"`
	Artifacts      []ArtifactSlot  `json:"artifacts"`
	Coverage       string          `json:"coverage"`
	EvidencePrefix JournalPrefix   `json:"evidence_prefix"`
	Limitations    []string        `json:"limitations"`
}

// ArtifactChunk carries one verified byte window.
type ArtifactChunk struct {
	Kind            string          `json:"kind"`
	Handle          HandleReference `json:"handle"`
	Digest          string          `json:"digest"`
	SizeBytes       int64           `json:"size_bytes"`
	Offset          int64           `json:"offset"`
	ReturnedBytes   int64           `json:"returned_bytes"`
	DataBase64      string          `json:"data_base64"`
	ChunkDigest     string          `json:"chunk_digest"`
	EndOfArtifact   bool            `json:"end_of_artifact"`
	EvidenceRefs    []EvidenceRef   `json:"evidence_refs"`
}

// ControlObservation is the typed control evidence record.
type ControlObservation struct {
	ControlEventID   string          `json:"control_event_id"`
	OperationID      string          `json:"operation_id"`
	Operation        string          `json:"operation"`
	TargetScope      string          `json:"target_scope"`
	Disposition      string          `json:"disposition"`
	At               TimePoint       `json:"at"`
	AuthorizationRef EvidenceRef     `json:"authorization_ref"`
	CapabilityRef    any             `json:"capability_ref"`
	Opportunity      Opportunity     `json:"opportunity"`
	RequestRef       any             `json:"request_ref"`
	ResponseRef      any             `json:"response_ref"`
	ResponseChecks   any             `json:"response_checks"`
	NativeClaimRefs  []EvidenceRef   `json:"native_claim_refs"`
	EffectRefs       []EvidenceRef   `json:"effect_refs"`
	AffectedAttempts []any           `json:"affected_attempts"`
	Measurements     []any           `json:"measurements"`
	Limitations      []string        `json:"limitations"`
}

// Opportunity describes control exposure.
type Opportunity struct {
	State        string        `json:"state"`
	EvidenceRefs []EvidenceRef `json:"evidence_refs"`
	Rationale    string        `json:"rationale"`
}

// ControlReceipt returns typed control evidence.
type ControlReceipt struct {
	Kind            string             `json:"kind"`
	Handle          HandleReference    `json:"handle"`
	Observation     ControlObservation `json:"observation"`
	RegistrationRef EvidenceRef        `json:"registration_ref"`
}

// NativeCancelRequest asks for cooperative native cancellation.
type NativeCancelRequest struct {
	Handle            HandleReference `json:"handle"`
	Reason            string          `json:"reason"`
	AuthorizationRefs []EvidenceRef   `json:"authorization_refs"`
}

// CloseConnectionRequest closes the native observation transport.
type CloseConnectionRequest struct {
	Handle            HandleReference `json:"handle"`
	Reason            string          `json:"reason"`
	EndObservation    bool            `json:"end_observation"`
	AuthorizationRefs []EvidenceRef   `json:"authorization_refs"`
}

// ReleaseContextRequest releases a native context.
type ReleaseContextRequest struct {
	Handle            HandleReference `json:"handle"`
	ContextRef        json.RawMessage `json:"context_ref"`
	AuthorizationRefs []EvidenceRef   `json:"authorization_refs"`
}

// ContainmentTarget names a reviewed containment resource.
type ContainmentTarget struct {
	Kind       string `json:"kind"`
	ResourceID string `json:"resource_id"`
}

// ContainRequest asks for reviewed containment.
type ContainRequest struct {
	Handle            HandleReference  `json:"handle"`
	Target            ContainmentTarget `json:"target"`
	Policy            VersionPin       `json:"policy"`
	Reason            string           `json:"reason"`
	AuthorizationRefs []EvidenceRef    `json:"authorization_refs"`
}

// ---------------------------------------------------------------------------
// Internal records.
// ---------------------------------------------------------------------------

type descriptorPin struct {
	SubjectID           string
	SubjectVersion      string
	ConfiguredMode      string
	InterfaceSurface    string
	ConfigurationDigest string
	BindingID           string
	BindingVersion      string
	ConnectorVersion    string
}

type preparationRecord struct {
	ID               string
	Prepared         PreparedTask
	Artifact         ArtifactReference
	RegistrationRef  EvidenceRef
	Pin              descriptorPin
	CommissionDigest string
	TaskType         string
	NativeRequest    []byte
	DeliveredTask    []byte
	Translation      VersionPin
}

type handleRecord struct {
	mu               sync.Mutex
	Handle           HandleReference
	PreparationID    string
	Preparation      PreparationReference
	LogicalKey       string
	CommissionDigest string
	Scope            json.RawMessage
	CreatedAt        TimePoint
	State            string // active, draining, closed
	TransportClosed  bool
	EndObservation   bool
	Prefix           JournalPrefix
	Envelopes        []JournalEnvelope
	HandleBoundRef   EvidenceRef
	NativeRunID      any
	DispatchCount    int
	CloseRef         *EvidenceRef
	DrainDeadline    *TimePoint
}

type commandReceipt struct {
	requestHash string
	response    ConnectorResponse
}

// NativeCall logs one native RoundTrip invocation for corpus assertions.
type NativeCall struct {
	Method string
	URL    string
	Body   []byte
	At     time.Time
}

// Connector is the reference external connector HTTP handler.
type Connector struct {
	store      *OwnerStore
	native     http.RoundTripper
	descMu     sync.RWMutex
	descriptor ConnectorDescriptor

	mu            sync.Mutex
	preparations  map[string]*preparationRecord
	handles       map[string]*handleRecord
	logicalIndex  map[string]string
	commissionIdx map[string]string
	commands      map[string]commandReceipt
	nativeCalls   []NativeCall
	containCalls  []ContainRequest
	targetAllow   map[string]bool
	prepJournalID string
	prepPrefix    *JournalPrefix
	handleSeq     atomic.Int64
	producerSeq   atomic.Int64
	clockOffset   atomic.Int64
	opSeq         atomic.Int64
}

// NewReferenceConnector builds the reference connector handler.
func NewReferenceConnector(store *OwnerStore, descriptor ConnectorDescriptor, native http.RoundTripper) (http.Handler, error) {
	if store == nil {
		return nil, fmt.Errorf("reference_connector: store is required")
	}
	if native == nil {
		native = roundTripperFunc(func(*http.Request) (*http.Response, error) {
			return nil, fmt.Errorf("reference_connector: no native transport configured")
		})
	}
	if err := validateDescriptor(descriptor); err != nil {
		return nil, err
	}
	c := &Connector{
		store:         store,
		native:        native,
		descriptor:    descriptor,
		preparations:  make(map[string]*preparationRecord),
		handles:       make(map[string]*handleRecord),
		logicalIndex:  make(map[string]string),
		commissionIdx: make(map[string]string),
		commands:      make(map[string]commandReceipt),
		targetAllow:   make(map[string]bool),
		prepJournalID: fmt.Sprintf(prepJournalFmt, descriptor.ConnectorID),
	}
	c.handleSeq.Store(0)
	c.producerSeq.Store(0)
	c.clockOffset.Store(1000)
	c.opSeq.Store(0)
	return c, nil
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// SetDescriptor replaces the active descriptor (test hook for stale
// preparation detection). Production deployments pin one descriptor.
func (c *Connector) SetDescriptor(d ConnectorDescriptor) error {
	if err := validateDescriptor(d); err != nil {
		return err
	}
	c.descMu.Lock()
	defer c.descMu.Unlock()
	c.descriptor = d
	return nil
}

// Descriptor returns a copy of the active descriptor.
func (c *Connector) Descriptor() ConnectorDescriptor {
	c.descMu.RLock()
	defer c.descMu.RUnlock()
	return c.descriptor
}

// RegisterContainmentTarget authorizes one reviewed containment resource.
func (c *Connector) RegisterContainmentTarget(kind, resourceID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.targetAllow[kind+"\x00"+resourceID] = true
}

// NativeCalls returns a copy of the native invocation log.
func (c *Connector) NativeCalls() []NativeCall {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]NativeCall, len(c.nativeCalls))
	copy(out, c.nativeCalls)
	return out
}

// ContainCalls returns a copy of the containment invocation log.
func (c *Connector) ContainCalls() []ContainRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]ContainRequest, len(c.containCalls))
	copy(out, c.containCalls)
	return out
}

// HandleState returns the lifecycle state of one handle for tests.
func (c *Connector) HandleState(localHandle string) (string, bool) {
	c.mu.Lock()
	h, ok := c.handles[localHandle]
	c.mu.Unlock()
	if !ok {
		return "", false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.State, true
}

// HandlePrefix returns the current journal prefix of one handle for tests.
func (c *Connector) HandlePrefix(localHandle string) (JournalPrefix, bool) {
	c.mu.Lock()
	h, ok := c.handles[localHandle]
	c.mu.Unlock()
	if !ok {
		return JournalPrefix{}, false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.Prefix, true
}

func validateDescriptor(d ConnectorDescriptor) error {
	if d.RecordType != RecordTypeDescriptor {
		return fmt.Errorf("reference_connector: descriptor record_type must be %q", RecordTypeDescriptor)
	}
	if d.SchemaVersion != SchemaVersion {
		return fmt.Errorf("reference_connector: descriptor schema_version must be %q", SchemaVersion)
	}
	if strings.TrimSpace(d.ConnectorID) == "" {
		return fmt.Errorf("reference_connector: descriptor connector_id is required")
	}
	if strings.TrimSpace(d.ConnectorVersion) == "" {
		return fmt.Errorf("reference_connector: descriptor connector_version is required")
	}
	if len(d.Operations) != 9 {
		return fmt.Errorf("reference_connector: descriptor must carry exactly nine operation mappings, got %d", len(d.Operations))
	}
	seen := map[string]bool{}
	for i, op := range d.Operations {
		if !validOperations[op.Operation] {
			return fmt.Errorf("reference_connector: operations[%d].operation %q is not a versioned verb", i, op.Operation)
		}
		if seen[op.Operation] {
			return fmt.Errorf("reference_connector: duplicate operation mapping %q", op.Operation)
		}
		seen[op.Operation] = true
		switch op.Implementation {
		case "connector-local", "native-mapping", "unmapped":
		default:
			return fmt.Errorf("reference_connector: operations[%d] implementation %q is unknown", i, op.Implementation)
		}
		if op.CapabilityRefs == nil || op.EvidenceRefs == nil || op.Limitations == nil {
			return fmt.Errorf("reference_connector: operations[%d] requires non-null capability_refs, evidence_refs, limitations", i)
		}
	}
	for op := range validOperations {
		if !seen[op] {
			return fmt.Errorf("reference_connector: descriptor is missing operation mapping %q", op)
		}
	}
	have := map[string]bool{}
	for _, cap := range d.Capabilities {
		have[cap.ID] = true
		switch cap.Availability {
		case "available", "unsupported", "unknown":
		default:
			return fmt.Errorf("reference_connector: capability %q availability %q is unknown", cap.ID, cap.Availability)
		}
		if cap.EvidenceRefs == nil || cap.Limitations == nil {
			return fmt.Errorf("reference_connector: capability %q requires non-null evidence_refs and limitations", cap.ID)
		}
	}
	for _, id := range minimumCapabilityIDs {
		if !have[id] {
			return fmt.Errorf("reference_connector: descriptor is missing minimum capability %q", id)
		}
	}
	if strings.TrimSpace(d.Subject.SubjectID) == "" || strings.TrimSpace(d.Subject.SubjectVersion) == "" {
		return fmt.Errorf("reference_connector: descriptor subject id and version are required")
	}
	if d.Limits.MaxObservationItems < 1 || d.Limits.MaxRequestBytes < 1 || d.Limits.MaxResponseBytes < 1 {
		return fmt.Errorf("reference_connector: descriptor limits must be positive")
	}
	if d.TaskMappings == nil || d.ObservationChannels == nil {
		return fmt.Errorf("reference_connector: descriptor requires non-null task_mappings and observation_channels")
	}
	seenTask := map[string]bool{}
	for i, tm := range d.TaskMappings {
		if strings.TrimSpace(tm.TaskType) == "" {
			return fmt.Errorf("reference_connector: task_mappings[%d].task_type is required", i)
		}
		if seenTask[tm.TaskType] {
			return fmt.Errorf("reference_connector: duplicate task mapping %q", tm.TaskType)
		}
		seenTask[tm.TaskType] = true
		if tm.Limitations == nil {
			return fmt.Errorf("reference_connector: task_mappings[%d] requires non-null limitations", i)
		}
	}
	return nil
}

func (c *Connector) getDescriptor() ConnectorDescriptor {
	c.descMu.RLock()
	defer c.descMu.RUnlock()
	return c.descriptor
}

func (c *Connector) findOperation(op string) (OperationMapping, bool) {
	d := c.getDescriptor()
	for _, m := range d.Operations {
		if m.Operation == op {
			return m, true
		}
	}
	return OperationMapping{}, false
}

func (c *Connector) findCapability(id string) (Capability, bool) {
	d := c.getDescriptor()
	for _, cap := range d.Capabilities {
		if cap.ID == id {
			return cap, true
		}
	}
	return Capability{}, false
}

func (c *Connector) findTaskMapping(taskType string) (TaskMapping, bool) {
	d := c.getDescriptor()
	for _, tm := range d.TaskMappings {
		if tm.TaskType == taskType {
			return tm, true
		}
	}
	return TaskMapping{}, false
}

// ---------------------------------------------------------------------------
// HTTP carrier.
// ---------------------------------------------------------------------------

func (c *Connector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != CarrierPath || r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"not_found"}`))
		return
	}
	c.handleConnector(w, r)
}

func (c *Connector) handleConnector(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	raw, err := io.ReadAll(io.LimitReader(r.Body, MaxRequestBytes+1))
	if err != nil {
		writeEnvelope(w, ConnectorResponse{}, mustMarshal(newConnectorError(codeInternalError, domainConnector,
			"cannot read connector request", deliveryNA, retryOperator, nil, nil)))
		return
	}
	if int64(len(raw)) > MaxRequestBytes {
		writeEnvelope(w, ConnectorResponse{}, mustMarshal(newConnectorError(codeBudgetExceeded, domainRequest,
			"request exceeds the local byte bound", deliveryNotDisp, retryOperator, nil, nil)))
		return
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		writeEnvelope(w, ConnectorResponse{}, mustMarshal(newConnectorError(codeInvalidRequest, domainRequest,
			"request body is required", deliveryNA, retryNewIfNot, nil, nil)))
		return
	}
	canonical, err := evidence_codec.CanonicalJSON(raw, "application/json")
	if err != nil {
		writeEnvelope(w, ConnectorResponse{}, mustMarshal(newConnectorError(codeInvalidRequest, domainRequest,
			"malformed request envelope: duplicate keys, non-finite numbers, or invalid JSON are rejected",
			deliveryNA, retryNewIfNot, nil, nil)))
		return
	}
	var req ConnectorRequest
	if err := strictUnmarshal(canonical, &req); err != nil {
		writeEnvelope(w, ConnectorResponse{}, mustMarshal(newConnectorError(codeInvalidRequest, domainRequest,
			fmt.Sprintf("request envelope: %v", err), deliveryNA, retryNewIfNot, nil, nil)))
		return
	}
	if cerr := validateEnvelope(req); cerr != nil {
		resp := respondWith(req, mustMarshal(cerr))
		writeEnvelope(w, resp, resp.Result)
		return
	}
	desc := c.getDescriptor()
	if req.ConnectorID != desc.ConnectorID {
		cerr := newConnectorError(codeInvalidRequest, domainRequest,
			"connector_id does not match the configured descriptor", deliveryNA, retryNewIfNot, nil, nil)
		resp := respondWith(req, mustMarshal(cerr))
		writeEnvelope(w, resp, resp.Result)
		return
	}
	if err := authority.Authorize(r.Context(), "connector", req.Operation, req.ConnectorID); err != nil {
		msg := err.Error()
		code := codeForbidden
		if strings.Contains(msg, "no authenticated principal") || strings.Contains(msg, "unauthenticated") {
			code = codeUnauthenticated
		}
		cerr := newConnectorError(code, domainPolicy,
			"not authorized for "+req.Operation, deliveryNotDisp, retryOperator, nil, nil)
		resp := respondWith(req, mustMarshal(cerr))
		writeEnvelope(w, resp, resp.Result)
		return
	}
	if mutatingOperations[req.Operation] {
		if resp, conflict := c.checkCommandIdempotency(r, req); conflict != nil {
			writeEnvelope(w, *resp, resp.Result)
			return
		} else if resp != nil {
			writeEnvelope(w, *resp, resp.Result)
			return
		}
	}
	var result json.RawMessage
	var handlerErr *ConnectorError
	switch req.Operation {
	case OpDescribe:
		result, handlerErr = c.handleDescribe(r.Context(), req)
	case OpPrepare:
		result, handlerErr = c.handlePrepare(r.Context(), r, req)
	case OpStart:
		result, handlerErr = c.handleStart(r.Context(), r, req)
	case OpObserve:
		result, handlerErr = c.handleObserve(r.Context(), req)
	case OpRequestNativeCancel:
		result, handlerErr = c.handleRequestNativeCancel(r.Context(), r, req)
	case OpCloseObservationConnection:
		result, handlerErr = c.handleClose(r.Context(), r, req)
	case OpCollectArtifacts:
		result, handlerErr = c.handleCollect(r.Context(), req)
	case OpReleaseNativeContext:
		result, handlerErr = c.handleRelease(r.Context(), r, req)
	case OpContain:
		result, handlerErr = c.handleContain(r.Context(), r, req)
	default:
		handlerErr = newConnectorError(codeInvalidRequest, domainRequest,
			"unknown operation; exactly the nine versioned verbs are recognized",
			deliveryNA, retryNewIfNot, nil, nil)
	}
	var resp ConnectorResponse
	if handlerErr != nil {
		if isIdempotencyStoreable(req.Operation, handlerErr) {
			// Typed rejections are re-evaluated except idempotency conflicts
			// which are terminal for the conflicting key.
		}
		resp = respondWith(req, mustMarshal(handlerErr))
	} else {
		resp = respondWith(req, result)
		if mutatingOperations[req.Operation] {
			c.storeCommandReceipt(r, req, resp)
		}
	}
	if int64(len(mustMarshal(resp))) > MaxResponseBytes {
		cerr := newConnectorError(codeResponseTooLarge, domainConnector,
			"connector reply exceeds the local response bound", deliveryDisp, retryOperator, nil, nil)
		resp = respondWith(req, mustMarshal(cerr))
	}
	writeEnvelope(w, resp, resp.Result)
}

func writeEnvelope(w http.ResponseWriter, resp ConnectorResponse, _ json.RawMessage) {
	if resp.RecordType == "" {
		raw, _ := json.Marshal(map[string]any{
			"record_type": RecordTypeResponse, "schema_version": SchemaVersion,
			"request_id": resp.RequestID, "connector_id": resp.ConnectorID,
			"operation": resp.Operation, "result": json.RawMessage(`{"kind":"connector_error","code":"INTERNAL_ERROR","fault_domain":"connector","detail":"internal error","operation_delivery":"not_applicable","retry_guidance":"operator_review","retry_after":{"value":null,"reason":"not_applicable"},"handle":{"value":null,"reason":"not_applicable"},"evidence_refs":[]}`),
		})
		_, _ = w.Write(raw)
		return
	}
	raw, _ := json.Marshal(resp)
	_, _ = w.Write(raw)
}

func validateEnvelope(req ConnectorRequest) *ConnectorError {
	if req.RecordType != RecordTypeRequest {
		return newConnectorError(codeInvalidRequest, domainRequest,
			"record_type must be connector_request", deliveryNA, retryNewIfNot, nil, nil)
	}
	if req.SchemaVersion != SchemaVersion {
		return newConnectorError(codeUnsupportedVersion, domainRequest,
			fmt.Sprintf("schema_version must be %s", SchemaVersion), deliveryNA, retryNewIfNot, nil, nil)
	}
	if strings.TrimSpace(req.RequestID) == "" {
		return newConnectorError(codeInvalidRequest, domainRequest,
			"request_id is required", deliveryNA, retryNewIfNot, nil, nil)
	}
	if strings.TrimSpace(req.ConnectorID) == "" {
		return newConnectorError(codeInvalidRequest, domainRequest,
			"connector_id is required", deliveryNA, retryNewIfNot, nil, nil)
	}
	if !validOperations[req.Operation] {
		return newConnectorError(codeInvalidRequest, domainRequest,
			"unknown operation; exactly the nine versioned verbs are recognized",
			deliveryNA, retryNewIfNot, nil, nil)
	}
	if err := validateDurationLimit(req.CallLimit, "call_limit"); err != nil {
		return newConnectorError(codeInvalidRequest, domainRequest, err.Error(), deliveryNA, retryNewIfNot, nil, nil)
	}
	if req.CallLimit.Value > MaxCallLimitMs {
		return newConnectorError(codeBudgetExceeded, domainRequest,
			fmt.Sprintf("call_limit value exceeds the %d ms local bound", MaxCallLimitMs),
			deliveryNA, retryNewIfNot, nil, nil)
	}
	trimmed := bytes.TrimSpace(req.Payload)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return newConnectorError(codeInvalidRequest, domainRequest,
			"payload must be an object", deliveryNA, retryNewIfNot, nil, nil)
	}
	if req.Operation == OpDescribe {
		var obj map[string]any
		if err := strictUnmarshal(req.Payload, &obj); err != nil || len(obj) != 0 {
			return newConnectorError(codeInvalidRequest, domainRequest,
				"Describe payload must be the empty closed object", deliveryNA, retryNewIfNot, nil, nil)
		}
	}
	var v any
	dec := json.NewDecoder(bytes.NewReader(req.Payload))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return newConnectorError(codeInvalidRequest, domainRequest,
			"payload must be a JSON object", deliveryNA, retryNewIfNot, nil, nil)
	}
	if err := rejectBareNulls(v, "$.payload"); err != nil {
		return newConnectorError(codeInvalidRequest, domainRequest,
			"bare null rejected; use typed Missing envelopes", deliveryNA, retryNewIfNot, nil, nil)
	}
	return nil
}

func validateDurationLimit(lim DurationLimit, field string) error {
	if lim.Kind != "exact" {
		return fmt.Errorf("%s kind must be exact", field)
	}
	if lim.Unit != "ms" {
		return fmt.Errorf("%s unit must be ms", field)
	}
	if math.IsNaN(lim.Value) || math.IsInf(lim.Value, 0) {
		return fmt.Errorf("%s value is not finite", field)
	}
	if lim.Value < 0 {
		return fmt.Errorf("%s value must not be negative", field)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Command idempotency: (principal, connector_id, request_id).
// ---------------------------------------------------------------------------

func commandKey(r *http.Request, req ConnectorRequest) string {
	auth := ""
	if r != nil {
		auth = r.Header.Get("Authorization")
	}
	return auth + "\x00" + req.ConnectorID + "\x00" + req.RequestID
}

func canonicalPayloadHash(payload json.RawMessage) (string, error) {
	canonical, err := evidence_codec.CanonicalJSON(payload, "application/json")
	if err != nil {
		return "", err
	}
	return string(evidence_codec.HashBytes(canonical)), nil
}

func (c *Connector) checkCommandIdempotency(r *http.Request, req ConnectorRequest) (*ConnectorResponse, *ConnectorError) {
	hash, err := canonicalPayloadHash(req.Payload)
	if err != nil {
		cerr := newConnectorError(codeInvalidRequest, domainRequest,
			"payload is not canonicalizable", deliveryNA, retryNewIfNot, nil, nil)
		resp := respondWith(req, mustMarshal(cerr))
		return &resp, cerr
	}
	key := commandKey(r, req)
	c.mu.Lock()
	prior, ok := c.commands[key]
	c.mu.Unlock()
	if !ok {
		return nil, nil
	}
	if prior.requestHash != hash {
		cerr := newConnectorError(codeIdempotencyConflict, domainRequest,
			"conflicting content under (principal, connector_id, request_id); resend the identical request or use a new request_id",
			deliveryNotDisp, retrySame, nil, nil)
		resp := respondWith(req, mustMarshal(cerr))
		return &resp, cerr
	}
	replay := prior.response
	replay.RequestID = req.RequestID
	replay.ConnectorID = req.ConnectorID
	replay.Operation = req.Operation
	replay.Result = append(json.RawMessage(nil), prior.response.Result...)
	return &replay, nil
}

func (c *Connector) storeCommandReceipt(r *http.Request, req ConnectorRequest, resp ConnectorResponse) {
	hash, err := canonicalPayloadHash(req.Payload)
	if err != nil {
		return
	}
	key := commandKey(r, req)
	stored := resp
	stored.Result = append(json.RawMessage(nil), resp.Result...)
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.commands[key]; !ok {
		c.commands[key] = commandReceipt{requestHash: hash, response: stored}
	}
}

func isIdempotencyStoreable(_ string, _ *ConnectorError) bool { return false }

// ---------------------------------------------------------------------------
// Describe.
// ---------------------------------------------------------------------------

func (c *Connector) handleDescribe(_ context.Context, req ConnectorRequest) (json.RawMessage, *ConnectorError) {
	desc := c.getDescriptor()
	raw, err := json.Marshal(desc)
	if err != nil {
		return nil, newConnectorError(codeInternalError, domainConnector,
			"cannot serialize descriptor", deliveryNA, retryOperator, nil, nil)
	}
	canonical, err := evidence_codec.CanonicalJSON(raw, "application/json")
	if err != nil {
		return nil, newConnectorError(codeInternalError, domainConnector,
			"descriptor failed canonicalization", deliveryNA, retryOperator, nil, nil)
	}
	return json.RawMessage(canonical), nil
}

// ---------------------------------------------------------------------------
// Prepare (non-executing).
// ---------------------------------------------------------------------------

func (c *Connector) handlePrepare(ctx context.Context, _ *http.Request, req ConnectorRequest) (json.RawMessage, *ConnectorError) {
	nmReq, err := decodeNativePrepareRequest(req.Payload)
	if err != nil {
		return nil, newConnectorError(codeInvalidRequest, domainRequest,
			fmt.Sprintf("prepare payload: %v", err), deliveryNA, retryNewIfNot, nil, nil)
	}
	desc := c.getDescriptor()
	if nmReq.Configuration.ConnectorID != desc.ConnectorID {
		return nil, newConnectorError(codeStalePreparation, domainRequest,
			"preparation configuration connector_id does not match the configured descriptor",
			deliveryNA, retryNewIfNot, nil, nil)
	}
	if nmReq.Configuration.ConnectorVersion != desc.ConnectorVersion {
		return nil, newConnectorError(codeStalePreparation, domainRequest,
			"preparation configuration connector_version does not match the configured descriptor",
			deliveryNA, retryNewIfNot, nil, nil)
	}
	sub := nmReq.Configuration.Subject
	if sub.SubjectID != desc.Subject.SubjectID || sub.SubjectVersion != desc.Subject.SubjectVersion ||
		sub.ConfiguredMode != desc.Subject.ConfiguredMode || sub.InterfaceSurface != desc.Subject.InterfaceSurface ||
		sub.ConfigurationDigest != desc.Subject.ConfigurationDigest {
		return nil, newConnectorError(codeStalePreparation, domainRequest,
			"preparation subject/version/mode/interface/configuration does not match the configured descriptor",
			deliveryNA, retryNewIfNot, nil, nil)
	}
	if nmReq.Configuration.Binding.ID != desc.Binding.ID || nmReq.Configuration.Binding.Version != desc.Binding.Version {
		return nil, newConnectorError(codeStalePreparation, domainRequest,
			"preparation binding pin does not match the configured descriptor",
			deliveryNA, retryNewIfNot, nil, nil)
	}
	if cerr := c.checkRequiredStatePolicies(nmReq.Task); cerr != nil {
		return nil, cerr
	}
	tm, ok := c.findTaskMapping(nmReq.Task.TaskType)
	if !ok {
		return nil, newConnectorError(codeUnsupportedMapping, domainConnector,
			fmt.Sprintf("task_type %q has no declared task mapping", nmReq.Task.TaskType),
			deliveryNA, retryOperator, nil, nil)
	}
	mappingPin := native_mapping.VersionPin{
		ID: tm.Mapping.ID, Version: tm.Mapping.Version, ArtifactDigest: tm.Mapping.ArtifactDigest,
	}
	delivered, nativeBytes, err := native_mapping.SerializeNative(nmReq, mappingPin)
	if err != nil {
		if me, ok := asNativeMappingError(err); ok {
			switch me.Code {
			case native_mapping.CodeUnsupportedMapping:
				return nil, newConnectorError(codeUnsupportedMapping, domainConnector,
					"native mapping: "+me.Detail, deliveryNA, retryOperator, nil, nil)
			case native_mapping.CodeForbidden:
				return nil, newConnectorError(codeForbidden, domainPolicy,
					"native mapping: "+me.Detail, deliveryNA, retryOperator, nil, nil)
			default:
				return nil, newConnectorError(codeInvalidRequest, domainRequest,
					"native mapping: "+me.Detail, deliveryNA, retryNewIfNot, nil, nil)
			}
		}
		return nil, newConnectorError(codeInvalidRequest, domainRequest,
			fmt.Sprintf("native mapping: %v", err), deliveryNA, retryNewIfNot, nil, nil)
	}
	deliveredRef, err := owner_store.InstallArtifact(ctx, c.store, bytes.NewReader(delivered), "application/json", "public")
	if err != nil {
		return nil, mapStoreError(err, "install delivered task")
	}
	nativeRef, err := owner_store.InstallArtifact(ctx, c.store, bytes.NewReader(nativeBytes), "application/json", "restricted")
	if err != nil {
		return nil, mapStoreError(err, "install native request")
	}
	taskHash := string(evidence_codec.HashBytes(mustCanonical(nmReq.Task)))
	prepID := "prep-" + shortHash(req.RequestID+taskHash+nmReq.Task.TaskID)
	concerns := c.buildConcerns(nmReq)
	budgets := []BudgetMapping{
		{Dimension: "active_time", Mapped: true, Limitations: []string{}},
		{Dimension: "actions", Mapped: true, Limitations: []string{}},
		{Dimension: "observation_bytes", Mapped: true, Limitations: []string{}},
		{Dimension: "recovery", Mapped: true, Limitations: []string{}},
		{Dimension: "model_tokens", Mapped: true, Limitations: []string{}},
	}
	scopeRaw, _ := json.Marshal(nmReq.Scope)
	configRaw, _ := json.Marshal(nmReq.Configuration)
	taskRaw, _ := json.Marshal(nmReq.Task)
	assistRaw, _ := json.Marshal(nmReq.Assistance)
	runtimeRaw, _ := json.Marshal(nmReq.RuntimeAccess)
	planningRefs := make([]EvidenceRef, 0, len(nmReq.PlanningEvidenceRefs))
	for _, r := range nmReq.PlanningEvidenceRefs {
		planningRefs = append(planningRefs, EvidenceRef{
			JournalID: r.JournalID, Sequence: r.Sequence, EventID: r.EventID,
			EventHash: r.EventHash, Pointer: r.Pointer,
		})
	}
	prep := PreparedTask{
		RecordType:           RecordTypePrep,
		SchemaVersion:        SchemaVersion,
		PreparationID:        prepID,
		Scope:                json.RawMessage(mustCanonicalRaw(scopeRaw)),
		Configuration:        json.RawMessage(mustCanonicalRaw(configRaw)),
		Task:                 json.RawMessage(mustCanonicalRaw(taskRaw)),
		TaskSemanticHash:      taskHash,
		Assistance:           json.RawMessage(mustCanonicalRaw(assistRaw)),
		PlanningEvidenceRefs: planningRefs,
		RuntimeAccess:        json.RawMessage(mustCanonicalRaw(runtimeRaw)),
		DeliveredTask:        deliveredRef,
		DeliveredTaskHash:    deliveredRef.Digest,
		NativeRequest:        nativeRef,
		NativeRequestHash:    nativeRef.Digest,
		Translation:          tm.Mapping,
		BudgetMapping:        budgets,
		Concerns:             concerns,
	}
	regRef, prepArtifact, err := c.registerPreparation(ctx, prep, deliveredRef, nativeRef)
	if err != nil {
		if cerr, ok := err.(*ConnectorError); ok {
			return nil, cerr
		}
		return nil, mapStoreError(err, "register preparation")
	}
	prep.EvidencePrefix = regRefPrefix(regRef, c.prepJournalID)
	// Re-install the record with its evidence prefix pinned is unnecessary:
	// the artifact already hashes the complete record bytes; the prefix is
	// carried in the result for Start-time verification.
	commissionDigest := ""
	if m, ok := nmReq.Scope.Commission.(native_mapping.ArtifactReference); ok {
		commissionDigest = m.Digest
	} else if m, ok := nmReq.Scope.Commission.(map[string]any); ok {
		if d, _ := m["digest"].(string); d != "" {
			commissionDigest = d
		}
	} else {
		var aux struct {
			Digest string `json:"digest"`
		}
		rawScope, _ := json.Marshal(nmReq.Scope.Commission)
		if json.Unmarshal(rawScope, &aux) == nil && validDigest(aux.Digest) {
			commissionDigest = aux.Digest
		}
	}
	c.mu.Lock()
	c.preparations[prepID] = &preparationRecord{
		ID: prepID, Prepared: prep, Artifact: prepArtifact, RegistrationRef: regRef,
		Pin: descriptorPin{
			SubjectID: desc.Subject.SubjectID, SubjectVersion: desc.Subject.SubjectVersion,
			ConfiguredMode: desc.Subject.ConfiguredMode, InterfaceSurface: desc.Subject.InterfaceSurface,
			ConfigurationDigest: desc.Subject.ConfigurationDigest,
			BindingID: desc.Binding.ID, BindingVersion: desc.Binding.Version,
			ConnectorVersion: desc.ConnectorVersion,
		},
		CommissionDigest: commissionDigest,
		TaskType:         nmReq.Task.TaskType,
		NativeRequest:    append([]byte(nil), nativeBytes...),
		DeliveredTask:    append([]byte(nil), delivered...),
		Translation:      tm.Mapping,
	}
	c.mu.Unlock()
	result := PrepareResult{
		Kind: "prepared",
		Preparation: PreparationReference{
			PreparationID: prepID, Artifact: prepArtifact, RegistrationRef: regRef,
		},
		Record: prep,
	}
	return mustMarshal(result), nil
}

func (c *Connector) checkRequiredStatePolicies(task native_mapping.TaskEnvelope) *ConnectorError {
	browser := task.ContextPolicy.BrowserState
	learning := task.ContextPolicy.LearningState
	if browser.Requirement == "required" && browser.Mode != "not_applicable" {
		iso, okIso := c.findCapability("browser_state_isolation")
		per, okPer := c.findCapability("browser_state_persistence")
		isoOK := okIso && iso.Availability == "available"
		perOK := okPer && per.Availability == "available"
		if !isoOK && !perOK {
			return newConnectorError(codeUnsupportedMapping, domainConnector,
				fmt.Sprintf("required browser_state mode %q has no available mapping (isolation=%s persistence=%s)",
					browser.Mode, availOf(iso, okIso), availOf(per, okPer)),
				deliveryNA, retryOperator, nil, nil)
		}
	}
	if learning.Requirement == "required" && learning.Mode != "not_applicable" {
		lc, ok := c.findCapability("learning_state_control")
		if !ok || lc.Availability != "available" {
			return newConnectorError(codeUnsupportedMapping, domainConnector,
				fmt.Sprintf("required learning_state mode %q has no available mapping (learning_state_control=%s)",
					learning.Mode, availOf(lc, ok)),
				deliveryNA, retryOperator, nil, nil)
		}
	}
	// Browser-state and framework-learning-state requests remain separate:
	// a browser requirement never consults learning_state_control and vice
	// versa. Missing native cancellation is never consulted here.
	return nil
}

func availOf(cap Capability, ok bool) string {
	if !ok {
		return "absent"
	}
	return cap.Availability
}

func (c *Connector) buildConcerns(nmReq native_mapping.PrepareRequest) []PreparationConcern {
	out := []PreparationConcern{}
	if nmReq.Task.ContextPolicy.BrowserState.Requirement == "best_effort" &&
		nmReq.Task.ContextPolicy.BrowserState.Mode != "not_applicable" {
		iso, ok := c.findCapability("browser_state_isolation")
		if !ok || iso.Availability != "available" {
			out = append(out, PreparationConcern{
				ConcernID: "browser-state-best-effort",
				Description: "Browser-state request is best-effort; isolation mapping is " + availOf(iso, ok) + ".",
				RequiresAcceptance: false,
			})
		}
	}
	if _, ok := c.findCapability("native_cancel"); ok {
		if cap, _ := c.findCapability("native_cancel"); cap.Availability != "available" {
			out = append(out, PreparationConcern{
				ConcernID: "native-cancel-unavailable",
				Description: "Native cancellation is " + cap.Availability + "; cooperative cancel will report unsupported without blocking admission.",
				RequiresAcceptance: false,
			})
		}
	}
	return out
}

func (c *Connector) registerPreparation(ctx context.Context, prep PreparedTask, delivered, native ArtifactReference) (EvidenceRef, ArtifactReference, error) {
	prepBytes := mustMarshal(prep)
	canonical, err := evidence_codec.CanonicalJSON(prepBytes, "application/json")
	if err != nil {
		return EvidenceRef{}, ArtifactReference{}, fmt.Errorf("canonicalize preparation: %w", err)
	}
	prepRef, err := owner_store.InstallArtifact(ctx, c.store, bytes.NewReader(canonical), "application/json", "public")
	if err != nil {
		return EvidenceRef{}, ArtifactReference{}, err
	}
	c.mu.Lock()
	journalID := c.prepJournalID
	knownPrefix := c.prepPrefix
	c.mu.Unlock()
	if knownPrefix == nil {
		if err := c.ensureJournal(ctx, journalID); err != nil {
			return EvidenceRef{}, ArtifactReference{}, err
		}
	}
	seq := c.producerSeq.Add(1)
	sub := EventSubmission{
		ProducerSequence:   seq,
		EventKind:          "preparation_registered",
		EventSchemaVersion: controlEventSchema,
		OccurredAt:         c.nowTimePoint(),
		Payload: owner_store.Payload{
			Data: map[string]any{
				"preparation_id":     prep.PreparationID,
				"task_semantic_hash": prep.TaskSemanticHash,
				"preparation_digest": prepRef.Digest,
				"delivered_digest":   delivered.Digest,
				"native_digest":      native.Digest,
			},
			Measurements: []owner_store.Measurement{},
			EvidenceRefs: []EvidenceRef{},
			ArtifactRefs: []ArtifactReference{prepRef, delivered, native},
		},
	}
	envs, err := owner_store.CommitOwner(ctx, c.store, journalID, []EventSubmission{sub}, nil)
	if err != nil {
		return EvidenceRef{}, ArtifactReference{}, err
	}
	if err := validateEnvelopes(envs); err != nil {
		return EvidenceRef{}, ArtifactReference{}, err
	}
	last := envs[len(envs)-1]
	prefix := JournalPrefix{JournalID: journalID, LastSequence: last.Sequence, HeadHash: last.EventHash}
	c.mu.Lock()
	c.prepPrefix = &prefix
	c.mu.Unlock()
	ref := EvidenceRef{JournalID: journalID, Sequence: last.Sequence, EventID: last.EventID, EventHash: last.EventHash, Pointer: ""}
	return ref, prepRef, nil
}

func regRefPrefix(ref EvidenceRef, journalID string) JournalPrefix {
	return JournalPrefix{JournalID: journalID, LastSequence: ref.Sequence, HeadHash: ref.EventHash}
}

// ---------------------------------------------------------------------------
// Start.
// ---------------------------------------------------------------------------

func (c *Connector) handleStart(ctx context.Context, r *http.Request, req ConnectorRequest) (json.RawMessage, *ConnectorError) {
	var sreq StartRequest
	if err := strictUnmarshal(req.Payload, &sreq); err != nil {
		return nil, newConnectorError(codeInvalidRequest, domainRequest,
			fmt.Sprintf("start payload: %v", err), deliveryNA, retryNewIfNot, nil, nil)
	}
	if strings.TrimSpace(sreq.IdempotencyKey) == "" {
		return nil, newConnectorError(codeInvalidRequest, domainRequest,
			"idempotency_key is required", deliveryNA, retryNewIfNot, nil, nil)
	}
	if strings.TrimSpace(sreq.Preparation.PreparationID) == "" {
		return nil, newConnectorError(codeUnknownPreparation, domainRequest,
			"preparation.preparation_id is required", deliveryNA, retryNewIfNot, nil, nil)
	}
	for i, ref := range sreq.AuthorizationRefs {
		if err := validateEvidenceRefShape(ref); err != nil {
			return nil, newConnectorError(codeInvalidRequest, domainRequest,
				fmt.Sprintf("authorization_refs[%d]: %v", i, err), deliveryNA, retryNewIfNot, nil, nil)
		}
	}
	c.mu.Lock()
	prep, ok := c.preparations[sreq.Preparation.PreparationID]
	c.mu.Unlock()
	if !ok {
		return nil, newConnectorError(codeUnknownPreparation, domainRequest,
			"unknown preparation_id; Prepare before Start", deliveryNA, retryNewIfNot, nil, nil)
	}
	if sreq.Preparation.Artifact.Digest != "" && sreq.Preparation.Artifact.Digest != prep.Artifact.Digest {
		return nil, newConnectorError(codeStalePreparation, domainRequest,
			"preparation artifact does not match the registered preparation digest",
			deliveryNA, retryNewIfNot, nil, nil)
	}
	storedBytes, err := owner_store.ReadArtifact(ctx, c.store, prep.Artifact)
	if err != nil {
		return nil, mapStoreError(err, "read preparation")
	}
	var storedPrep PreparedTask
	if err := json.Unmarshal(storedBytes, &storedPrep); err != nil {
		return nil, newConnectorError(codeStalePreparation, domainRequest,
			"registered preparation bytes are unreadable", deliveryNA, retryNewIfNot, nil, nil)
	}
	if storedPrep.PreparationID != prep.ID {
		return nil, newConnectorError(codeStalePreparation, domainRequest,
			"registered preparation identity mismatch", deliveryNA, retryNewIfNot, nil, nil)
	}
	desc := c.getDescriptor()
	if prep.Pin.SubjectID != desc.Subject.SubjectID || prep.Pin.SubjectVersion != desc.Subject.SubjectVersion ||
		prep.Pin.ConfiguredMode != desc.Subject.ConfiguredMode || prep.Pin.InterfaceSurface != desc.Subject.InterfaceSurface ||
		prep.Pin.ConfigurationDigest != desc.Subject.ConfigurationDigest ||
		prep.Pin.BindingID != desc.Binding.ID || prep.Pin.BindingVersion != desc.Binding.Version ||
		prep.Pin.ConnectorVersion != desc.ConnectorVersion {
		return nil, newConnectorError(codeStalePreparation, domainRequest,
			"subject/binding/version changed since preparation; re-Prepare under the current descriptor",
			deliveryNA, retryNewIfNot, nil, nil)
	}
	if cerr := checkAcceptedConcerns(prep.Prepared.Concerns, sreq.AcceptedConcernIDs); cerr != nil {
		return nil, cerr
	}
	isResume, resume, cerr := parseRecovery(sreq.Recovery)
	if cerr != nil {
		return nil, cerr
	}
	if isResume {
		return c.handleResume(ctx, req, sreq, prep, resume)
	}
	if len(sreq.AuthorizationRefs) == 0 {
		return nil, newConnectorError(codeInvalidRequest, domainRequest,
			"authorization_refs must carry at least one reference", deliveryNA, retryNewIfNot, nil, nil)
	}
	c.mu.Lock()
	if prep.CommissionDigest != "" {
		if existing, ok := c.commissionIdx[prep.CommissionDigest]; ok {
			h := c.handles[existing]
			c.mu.Unlock()
			return c.existingHandleReceipt(req, h, "existing_handle")
		}
	}
	logicalKey := prep.ID + "\x00" + sreq.IdempotencyKey
	if existing, ok := c.logicalIndex[logicalKey]; ok {
		h := c.handles[existing]
		c.mu.Unlock()
		return c.existingHandleReceipt(req, h, "existing_handle")
	}
	c.mu.Unlock()
	bestEffortLimitation := c.validateDispatchBestEffort(prep, sreq)
	_ = bestEffortLimitation
	handle, receiptRef, handleArtifact, cerr := c.createHandle(ctx, req, sreq, prep)
	if cerr != nil {
		return nil, cerr
	}
	return c.startReceipt(req, handle, receiptRef, handleArtifact, "accepted_locally"), nil
}

func checkAcceptedConcerns(concerns []PreparationConcern, accepted []string) *ConnectorError {
	byID := map[string]PreparationConcern{}
	for _, k := range concerns {
		byID[k.ConcernID] = k
	}
	seen := map[string]bool{}
	for _, id := range accepted {
		if seen[id] {
			return newConnectorError(codeInvalidRequest, domainRequest,
				fmt.Sprintf("duplicate accepted_concern_id %q", id), deliveryNA, retryNewIfNot, nil, nil)
		}
		seen[id] = true
		if _, ok := byID[id]; !ok {
			return newConnectorError(codeInvalidRequest, domainRequest,
				fmt.Sprintf("accepted_concern_id %q names no preparation concern", id),
				deliveryNA, retryNewIfNot, nil, nil)
		}
	}
	for _, k := range concerns {
		if k.RequiresAcceptance && !seen[k.ConcernID] {
			return newConnectorError(codeInvalidRequest, domainRequest,
				fmt.Sprintf("concern %q requires acceptance", k.ConcernID), deliveryNA, retryNewIfNot, nil, nil)
		}
	}
	return nil
}

func parseRecovery(raw json.RawMessage) (bool, ResumeAuthorization, *ConnectorError) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return false, ResumeAuthorization{}, newConnectorError(codeInvalidRequest, domainRequest,
			"recovery is required (inapplicable or resume authorization)", deliveryNA, retryNewIfNot, nil, nil)
	}
	var probe map[string]any
	if err := json.Unmarshal(trimmed, &probe); err != nil {
		return false, ResumeAuthorization{}, newConnectorError(codeInvalidRequest, domainRequest,
			"recovery must be an object", deliveryNA, retryNewIfNot, nil, nil)
	}
	if reason, ok := probe["reason"].(string); ok && reason != "" {
		m, err := parseMissing(raw)
		if err != nil {
			return false, ResumeAuthorization{}, newConnectorError(codeInvalidRequest, domainRequest,
				fmt.Sprintf("recovery: %v", err), deliveryNA, retryNewIfNot, nil, nil)
		}
		if m.Reason != "not_applicable" {
			return false, ResumeAuthorization{}, newConnectorError(codeInvalidRequest, domainRequest,
				"initial-start recovery must be Missing(not_applicable)", deliveryNA, retryNewIfNot, nil, nil)
		}
		return false, ResumeAuthorization{}, nil
	}
	var resume ResumeAuthorization
	if err := strictUnmarshal(raw, &resume); err != nil {
		return false, ResumeAuthorization{}, newConnectorError(codeInvalidRequest, domainRequest,
			fmt.Sprintf("recovery resume authorization: %v", err), deliveryNA, retryNewIfNot, nil, nil)
	}
	return true, resume, nil
}

func (c *Connector) existingHandleReceipt(req ConnectorRequest, h *handleRecord, disposition string) (json.RawMessage, *ConnectorError) {
	h.mu.Lock()
	handleCopy := h.Handle
	prepRef := h.Preparation
	scope := append(json.RawMessage(nil), h.Scope...)
	created := h.CreatedAt
	receiptRef := h.HandleBoundRef
	logical := h.LogicalKey
	h.mu.Unlock()
	c.mu.Lock()
	prep, ok := c.preparations[prepRef.PreparationID]
	c.mu.Unlock()
	_ = ok
	_ = prep
	ch := ConnectorHandle{
		RecordType: RecordTypeHandle, SchemaVersion: SchemaVersion,
		Handle: handleCopy, Preparation: prepRef, Scope: scope,
		IdempotencyKey: logicalKeySuffix(logical), CreatedAt: created,
	}
	artifact := handleArtifactFor(ch)
	return c.startReceiptWith(req, ch, receiptRef, artifact, disposition), nil
}

func logicalKeySuffix(logical string) string {
	parts := strings.Split(logical, "\x00")
	if len(parts) == 0 {
		return logical
	}
	return parts[len(parts)-1]
}

func handleArtifactFor(ch ConnectorHandle) ArtifactReference {
	digest := string(evidence_codec.HashBytes(mustMarshal(ch)))
	return ArtifactReference{
		Digest: digest, SizeBytes: int64(len(mustMarshal(ch))),
		MediaType: "application/json", OwnerDomain: "connector", Access: "public",
	}
}

func (c *Connector) startReceipt(req ConnectorRequest, h *handleRecord, receiptRef EvidenceRef, handleArtifact ArtifactReference, disposition string) json.RawMessage {
	h.mu.Lock()
	ch := ConnectorHandle{
		RecordType: RecordTypeHandle, SchemaVersion: SchemaVersion,
		Handle: h.Handle, Preparation: h.Preparation, Scope: append(json.RawMessage(nil), h.Scope...),
		IdempotencyKey: logicalKeySuffix(h.LogicalKey), CreatedAt: h.CreatedAt,
	}
	h.mu.Unlock()
	return c.startReceiptWith(req, ch, receiptRef, handleArtifact, disposition)
}

func (c *Connector) startReceiptWith(req ConnectorRequest, ch ConnectorHandle, receiptRef EvidenceRef, handleArtifact ArtifactReference, disposition string) json.RawMessage {
	_ = req
	return mustMarshal(StartResult{
		Kind: "start_receipt", Disposition: disposition,
		Handle: ch, HandleArtifact: handleArtifact, ReceiptRef: receiptRef,
	})
}

func (c *Connector) createHandle(ctx context.Context, req ConnectorRequest, sreq StartRequest, prep *preparationRecord) (*handleRecord, EvidenceRef, ArtifactReference, *ConnectorError) {
	seq := c.handleSeq.Add(1)
	localHandle := fmt.Sprintf("h-%d-%s", seq, shortHash(prep.ID+sreq.IdempotencyKey+req.RequestID))
	handle := HandleReference{ConnectorID: c.getDescriptor().ConnectorID, LocalHandle: localHandle}
	created := c.nowTimePoint()
	journalID := localHandle
	if err := c.ensureJournal(ctx, journalID); err != nil {
		return nil, EvidenceRef{}, ArtifactReference{}, mapStoreError(err, "create handle journal")
	}
	bindingDigest := string(evidence_codec.HashBytes(mustCanonical(prep.Prepared)))
	intentDigest := string(evidence_codec.HashBytes([]byte(prep.ID + "\x00" + sreq.IdempotencyKey + "\x00" + localHandle)))
	var scopeMap map[string]any
	_ = json.Unmarshal(prep.Prepared.Scope, &scopeMap)
	runID := stringFieldOf(scopeMap, "run_id")
	attemptID := ""
	if att, ok := scopeMap["attempt"].(map[string]any); ok {
		attemptID, _ = att["attempt_id"].(string)
	}
	traceID := ""
	if t, ok := scopeMap["trace_id"].(string); ok {
		traceID = t
	}
	dataBound := map[string]any{
		"local_handle":     localHandle,
		"preparation_id":   prep.ID,
		"preparation_digest": prep.Artifact.Digest,
		"idempotency_key":  sreq.IdempotencyKey,
		"binding_digest":   bindingDigest,
		"intent_digest":    intentDigest,
	}
	if runID != "" {
		dataBound["run_id"] = runID
	}
	if attemptID != "" {
		dataBound["attempt_id"] = attemptID
	}
	if traceID != "" {
		dataBound["trace_id"] = traceID
	}
	events := []EventSubmission{
		{
			ProducerSequence: c.producerSeq.Add(1), EventKind: "handle_bound",
			EventSchemaVersion: controlEventSchema, OccurredAt: created,
			Payload: owner_store.Payload{
				Data: dataBound, Measurements: []owner_store.Measurement{},
				EvidenceRefs: []EvidenceRef{}, ArtifactRefs: []ArtifactReference{prep.Artifact},
			},
		},
		{
			ProducerSequence: c.producerSeq.Add(1), EventKind: "request_binding",
			EventSchemaVersion: controlEventSchema, OccurredAt: created,
			Payload: owner_store.Payload{
				Data: map[string]any{
					"local_handle": localHandle, "binding_digest": bindingDigest,
					"delivered_digest": prep.Prepared.DeliveredTaskHash,
					"native_digest":    prep.Prepared.NativeRequestHash,
				},
				Measurements: []owner_store.Measurement{},
				EvidenceRefs: []EvidenceRef{},
				ArtifactRefs: []ArtifactReference{prep.Prepared.DeliveredTask, prep.Prepared.NativeRequest},
			},
		},
		{
			ProducerSequence: c.producerSeq.Add(1), EventKind: "dispatch_intent",
			EventSchemaVersion: controlEventSchema, OccurredAt: created,
			Payload: owner_store.Payload{
				Data: map[string]any{
					"local_handle": localHandle, "intent_digest": intentDigest,
					"idempotency_key": sreq.IdempotencyKey, "delivery": "pending",
				},
				Measurements: []owner_store.Measurement{},
				EvidenceRefs: []EvidenceRef{}, ArtifactRefs: []ArtifactReference{},
			},
		},
	}
	envs, err := owner_store.CommitOwner(ctx, c.store, journalID, events, nil)
	if err != nil {
		return nil, EvidenceRef{}, ArtifactReference{}, mapStoreError(err, "commit handle and dispatch intent")
	}
	if err := validateEnvelopes(envs); err != nil {
		return nil, EvidenceRef{}, ArtifactReference{}, mapStoreError(err, "validate handle envelopes")
	}
	var boundRef EvidenceRef
	for _, env := range envs {
		if env.EventKind == "handle_bound" {
			boundRef = EvidenceRef{JournalID: env.JournalID, Sequence: env.Sequence, EventID: env.EventID, EventHash: env.EventHash, Pointer: ""}
		}
	}
	last := envs[len(envs)-1]
	prefix := JournalPrefix{JournalID: journalID, LastSequence: last.Sequence, HeadHash: last.EventHash}
	h := &handleRecord{
		Handle: handle, PreparationID: prep.ID,
		Preparation: PreparationReference{
			PreparationID: prep.ID, Artifact: prep.Artifact, RegistrationRef: prep.RegistrationRef,
		},
		LogicalKey: prep.ID + "\x00" + sreq.IdempotencyKey,
		CommissionDigest: prep.CommissionDigest,
		Scope: append(json.RawMessage(nil), prep.Prepared.Scope...),
		CreatedAt: created, State: "active",
		Prefix: prefix, Envelopes: append([]JournalEnvelope(nil), envs...),
		HandleBoundRef: boundRef,
		NativeRunID: map[string]any{"value": nil, "reason": "not_observed"},
		DispatchCount: 1,
	}
	tryPublishLiveHead(prefix)
	ch := ConnectorHandle{
		RecordType: RecordTypeHandle, SchemaVersion: SchemaVersion,
		Handle: handle,
		Preparation: h.Preparation, Scope: append(json.RawMessage(nil), h.Scope...),
		IdempotencyKey: sreq.IdempotencyKey, CreatedAt: created,
	}
	handleBytes := mustMarshal(ch)
	handleRef, err := owner_store.InstallArtifact(ctx, c.store, bytes.NewReader(handleBytes), "application/json", "public")
	if err != nil {
		return nil, EvidenceRef{}, ArtifactReference{}, mapStoreError(err, "install handle")
	}
	c.mu.Lock()
	c.handles[localHandle] = h
	c.logicalIndex[h.LogicalKey] = localHandle
	if prep.CommissionDigest != "" {
		c.commissionIdx[prep.CommissionDigest] = localHandle
	}
	c.mu.Unlock()
	asyncCtx := context.WithoutCancel(ctx)
	go c.deliverNative(asyncCtx, localHandle, prep)
	return h, boundRef, handleRef, nil
}

func tryPublishLiveHead(prefix JournalPrefix) {
	_ = connector_queries.PublishLiveHead(connector_queries.JournalPrefix{
		JournalID: prefix.JournalID, LastSequence: prefix.LastSequence, HeadHash: prefix.HeadHash,
	})
}

func stringFieldOf(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	s, _ := m[key].(string)
	return s
}

// ---------------------------------------------------------------------------
// Resume.
// ---------------------------------------------------------------------------

func (c *Connector) handleResume(ctx context.Context, req ConnectorRequest, sreq StartRequest, prep *preparationRecord, resume ResumeAuthorization) (json.RawMessage, *ConnectorError) {
	if strings.TrimSpace(resume.Handle.LocalHandle) == "" {
		return nil, newConnectorError(codeUnknownHandle, domainRequest,
			"recovery handle is required", deliveryNA, retryNewIfNot, nil, nil)
	}
	c.mu.Lock()
	h, ok := c.handles[resume.Handle.LocalHandle]
	c.mu.Unlock()
	if !ok {
		return nil, newConnectorError(codeUnknownHandle, domainRequest,
			"unknown handle for resume", deliveryNA, retryNewIfNot, handleRaw(resume.Handle), nil)
	}
	h.mu.Lock()
	state := h.State
	logical := h.LogicalKey
	prepID := h.PreparationID
	h.mu.Unlock()
	_ = logical
	if state == "draining" || state == "closed" {
		return nil, newConnectorError(codeObservationClosed, domainConnector,
			"observation is draining or closed; resume cannot reopen it",
			deliveryNotDisp, retryNoRetry, handleRaw(resume.Handle), nil)
	}
	if prepID != prep.ID {
		return nil, newConnectorError(codeStalePreparation, domainRequest,
			"resume preparation does not match the handle preparation",
			deliveryNA, retryNewIfNot, handleRaw(resume.Handle), nil)
	}
	if resume.Handle.ConnectorID != c.getDescriptor().ConnectorID {
		return nil, newConnectorError(codeInvalidRequest, domainRequest,
			"resume handle connector_id mismatch", deliveryNA, retryNewIfNot, handleRaw(resume.Handle), nil)
	}
	expectedLogical := prep.ID + "\x00" + sreq.IdempotencyKey
	if logical != expectedLogical && prep.CommissionDigest == "" {
		// For discovery (no commission), the logical key must match.
		// For apply, the commission already pins the logical execution.
		return nil, newConnectorError(codeIdempotencyConflict, domainRequest,
			"resume logical key does not match the handle logical key",
			deliveryNotDisp, retrySame, handleRaw(resume.Handle), nil)
	}
	if len(resume.AuthorizationRefs) == 0 {
		return nil, newConnectorError(codeInvalidRequest, domainRequest,
			"recovery authorization_refs must carry explicit recovery authority",
			deliveryNA, retryNewIfNot, handleRaw(resume.Handle), nil)
	}
	for i, ref := range resume.AuthorizationRefs {
		if err := validateEvidenceRefShape(ref); err != nil {
			return nil, newConnectorError(codeInvalidRequest, domainRequest,
				fmt.Sprintf("recovery authorization_refs[%d]: %v", i, err),
				deliveryNA, retryNewIfNot, handleRaw(resume.Handle), nil)
		}
	}
	if len(resume.EvidenceRefs) == 0 {
		return nil, newConnectorError(codePrerequisiteUnavailable, domainConnector,
			"resume requires evidenced native checkpoint or idempotency contract evidence",
			deliveryNA, retryOperator, handleRaw(resume.Handle), nil)
	}
	if !validDigest(resume.Checkpoint.Digest) {
		return nil, newConnectorError(codeInvalidRequest, domainRequest,
			"recovery checkpoint digest is invalid", deliveryNA, retryNewIfNot, handleRaw(resume.Handle), nil)
	}
	checkpointBytes, err := owner_store.ReadArtifact(ctx, c.store, ArtifactReference{
		Digest: resume.Checkpoint.Digest, SizeBytes: resume.Checkpoint.SizeBytes,
		MediaType: resume.Checkpoint.MediaType, OwnerDomain: resume.Checkpoint.OwnerDomain, Access: resume.Checkpoint.Access,
	})
	if err != nil {
		return nil, mapStoreErrorWithHandle(err, "read recovery checkpoint", handleRaw(resume.Handle))
	}
	_ = checkpointBytes
	if strings.TrimSpace(resume.NativeResumeContract.ID) == "" || !validDigest(resume.NativeResumeContract.ArtifactDigest) {
		return nil, newConnectorError(codePrerequisiteUnavailable, domainConnector,
			"resume requires an evidenced native resume contract pin",
			deliveryNA, retryOperator, handleRaw(resume.Handle), nil)
	}
	h.mu.Lock()
	journalID := h.Handle.LocalHandle
	h.mu.Unlock()
	sub := EventSubmission{
		ProducerSequence: c.producerSeq.Add(1), EventKind: "dispatch_intent",
		EventSchemaVersion: controlEventSchema, OccurredAt: c.nowTimePoint(),
		Payload: owner_store.Payload{
			Data: map[string]any{
				"local_handle": journalID, "delivery": "resume",
				"idempotency_key": sreq.IdempotencyKey,
				"checkpoint_digest": resume.Checkpoint.Digest,
			},
			Measurements: []owner_store.Measurement{},
			EvidenceRefs: []EvidenceRef{}, ArtifactRefs: []ArtifactReference{resume.Checkpoint},
		},
	}
	h.mu.Lock()
	envs, err := owner_store.CommitOwner(ctx, c.store, journalID, []EventSubmission{sub}, nil)
	if err != nil {
		h.mu.Unlock()
		return nil, mapStoreErrorWithHandle(err, "journal resume delivery", handleRaw(resume.Handle))
	}
	if err := validateEnvelopes(envs); err != nil {
		h.mu.Unlock()
		return nil, mapStoreErrorWithHandle(err, "validate resume envelopes", handleRaw(resume.Handle))
	}
	last := envs[len(envs)-1]
	h.Prefix = JournalPrefix{JournalID: journalID, LastSequence: last.Sequence, HeadHash: last.EventHash}
	h.Envelopes = append(h.Envelopes, envs...)
	h.DispatchCount++
	h.mu.Unlock()
	tryPublishLiveHead(h.Prefix)
	asyncCtx := context.WithoutCancel(ctx)
	go c.deliverNative(asyncCtx, journalID, prep)
	return c.existingHandleReceipt(req, h, "resume_authorized")
}

// ---------------------------------------------------------------------------
// Native delivery (async; never awaited by Start).
// ---------------------------------------------------------------------------

func (c *Connector) deliverNative(ctx context.Context, localHandle string, prep *preparationRecord) {
	op, ok := c.findOperation(OpStart)
	if !ok || op.Implementation != "native-mapping" || strings.TrimSpace(op.NativeEndpoint) == "" {
		c.journalIncident(ctx, localHandle, "START_UNMAPPED",
			"start has no mapped native endpoint; dispatch intent retained without wire delivery")
		return
	}
	body := append([]byte(nil), prep.NativeRequest...)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, op.NativeEndpoint, bytes.NewReader(body))
	if err != nil {
		c.journalIncident(ctx, localHandle, "NATIVE_REQUEST_BUILD",
			fmt.Sprintf("cannot build native request: %v", err))
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	c.mu.Lock()
	c.nativeCalls = append(c.nativeCalls, NativeCall{Method: req.Method, URL: req.URL.String(), Body: body, At: time.Now()})
	c.mu.Unlock()
	resp, err := c.native.RoundTrip(req)
	if err != nil {
		c.journalIncident(ctx, localHandle, "NATIVE_DELIVERY_ERROR",
			fmt.Sprintf("native delivery failed without establishing outcome: %v", err))
		return
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxNativeBodyBytes+1))
	if err != nil {
		c.journalIncident(ctx, localHandle, "NATIVE_READ_ERROR",
			fmt.Sprintf("cannot read native response: %v", err))
		return
	}
	if int64(len(respBody)) > maxNativeBodyBytes {
		c.journalIncident(ctx, localHandle, "NATIVE_RESPONSE_TOO_LARGE",
			"native response exceeds the local bound; raw bytes retained up to the bound")
		respBody = respBody[:maxNativeBodyBytes]
	}
	c.processNativeBody(ctx, localHandle, prep, "terminal_response", respBody)
}

func (c *Connector) journalIncident(ctx context.Context, localHandle, code, detail string) {
	c.mu.Lock()
	h, ok := c.handles[localHandle]
	c.mu.Unlock()
	if !ok {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	sub := EventSubmission{
		ProducerSequence: c.producerSeq.Add(1), EventKind: "connector_incident",
		EventSchemaVersion: controlEventSchema, OccurredAt: c.nowTimePoint(),
		Payload: owner_store.Payload{
			Data: map[string]any{
				"kind": "connector_incident", "code": code,
				"scope": localHandle, "detail": detail,
				"evidence_refs": []any{},
			},
			Measurements: []owner_store.Measurement{},
			EvidenceRefs: []EvidenceRef{}, ArtifactRefs: []ArtifactReference{},
		},
	}
	envs, err := owner_store.CommitOwner(ctx, c.store, localHandle, []EventSubmission{sub}, nil)
	if err != nil {
		return
	}
	if err := validateEnvelopes(envs); err != nil {
		return
	}
	last := envs[len(envs)-1]
	h.Prefix = JournalPrefix{JournalID: localHandle, LastSequence: last.Sequence, HeadHash: last.EventHash}
	h.Envelopes = append(h.Envelopes, envs...)
	tryPublishLiveHead(h.Prefix)
}

// InjectCallback injects one authenticated native callback for tests.
// It always retains receipt evidence, even after local closure; late
// evidence never reopens observation.
func (c *Connector) InjectCallback(ctx context.Context, localHandle string, rawBody []byte) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := authority.Authorize(ctx, "connector", OpObserve, localHandle); err != nil {
		return fmt.Errorf("reference_connector: callback not authenticated: %w", err)
	}
	c.mu.Lock()
	h, ok := c.handles[localHandle]
	var prep *preparationRecord
	if ok {
		prep = c.preparations[h.PreparationID]
	}
	c.mu.Unlock()
	if !ok {
		return fmt.Errorf("reference_connector: unknown handle %q", localHandle)
	}
	if prep == nil {
		return fmt.Errorf("reference_connector: missing preparation for handle %q", localHandle)
	}
	c.processNativeBody(context.WithoutCancel(ctx), localHandle, prep, "callback", append([]byte(nil), rawBody...))
	return nil
}

func (c *Connector) processNativeBody(ctx context.Context, localHandle string, prep *preparationRecord, channel string, body []byte) {
	if ctx == nil {
		ctx = context.Background()
	}
	c.mu.Lock()
	h, ok := c.handles[localHandle]
	c.mu.Unlock()
	if !ok {
		return
	}
	rawRef, err := owner_store.InstallArtifact(ctx, c.store, bytes.NewReader(body), "application/json", "public")
	if err != nil {
		c.journalIncident(ctx, localHandle, "RAW_INSTALL_ERROR", fmt.Sprintf("cannot retain native body: %v", err))
		return
	}
	h.mu.Lock()
	boundRef := h.HandleBoundRef
	h.mu.Unlock()
	policy := source_verifier.VersionPin{
		ID: c.getDescriptor().ConnectorID, Version: c.getDescriptor().ConnectorVersion,
		ArtifactDigest: c.getDescriptor().Binding.ArtifactDigest,
	}
	corrEvidence := []source_verifier.EvidenceRef{}
	if boundRef.JournalID != "" {
		corrEvidence = append(corrEvidence, source_verifier.EvidenceRef{
			JournalID: boundRef.JournalID, Sequence: boundRef.Sequence,
			EventID: boundRef.EventID, EventHash: boundRef.EventHash, Pointer: boundRef.Pointer,
		})
	}
	checks,verr := source_verifier.VerifySource(ctx, c.store, rawRef, policy, corrEvidence)
	if verr != nil {
		checks = source_verifier.SourceChecks{
			Authentication: source_verifier.AuthUnknown, Correlation: source_verifier.CorrUnknown,
			TraceCorrelation: source_verifier.TraceNotObserved, VerificationPolicy: policy,
			MatchedBy: []string{}, EvidenceRefs: []source_verifier.EvidenceRef{},
		}
	}
	nmChecks := toNativeSourceChecks(checks)
	var nmEvidence []native_mapping.JournalEnvelope
	if boundRef.JournalID != "" {
		nmEvidence = []native_mapping.JournalEnvelope{{
			RecordType: "journal_event", SchemaVersion: "0.1.0",
			RunID: "run-1", JournalID: boundRef.JournalID,
			ManifestHash: string(evidence_codec.HashBytes([]byte("manifest-" + boundRef.JournalID))),
			Sequence: boundRef.Sequence, EventID: boundRef.EventID, EventKind: "handle_bound",
			EventSchemaVer: "0.1.0", Role: "derived_output", AssertionKind: "observation",
			OwnerDomain: "connector", ProducerID: "connector", ProducerSequence: 1,
			Provenance: "server", EvidenceScope: "current_run",
			RecordedAt: "2026-01-01T00:00:01Z", OccurredAt: "2026-01-01T00:00:00Z",
			CausalRefs: []string{},
			Payload: map[string]any{"data": map[string]any{}, "measurements": []any{}, "evidence_refs": []any{}, "artifact_refs": []any{}},
			PreviousEventHash: string(evidence_codec.HashBytes([]byte("prev-" + boundRef.JournalID))),
			EventHash: evidence_codec.Digest(boundRef.EventHash),
		}}
	}
	nmRaw := toNativeArtifact(rawRef)
	mappingPin := native_mapping.VersionPin{
		ID: prep.Translation.ID, Version: prep.Translation.Version, ArtifactDigest: prep.Translation.ArtifactDigest,
	}
	claims, nerr := native_mapping.NormalizeNative(nmRaw, body, nmChecks, mappingPin, nmEvidence)
	limitations := []string{"channel " + channel, "native report retained at " + rawRef.Digest}
	if verr != nil {
		limitations = append(limitations, "source verification inconclusive: "+verr.Error())
	}
	if nerr != nil {
		limitations = append(limitations, "normalization: "+nerr.Error())
		claims = []native_mapping.ExecutionClaim{}
	}
	if claims == nil {
		claims = []native_mapping.ExecutionClaim{}
	}
	claimsForJournal := make([]any, 0, len(claims))
	for _, cl := range claims {
		raw, _ := json.Marshal(cl)
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		if m == nil {
			m = map[string]any{}
		}
		lowercaseMissingDetail(m)
		claimsForJournal = append(claimsForJournal, m)
	}
	checksRaw, _ := json.Marshal(checks)
	var checksMap map[string]any
	_ = json.Unmarshal(checksRaw, &checksMap)
	if checksMap == nil {
		checksMap = map[string]any{}
	}
	mappingRaw, _ := json.Marshal(mappingPin)
	var mappingMap map[string]any
	_ = json.Unmarshal(mappingRaw, &mappingMap)
	if mappingMap == nil {
		mappingMap = map[string]any{}
	}
	rawMap := map[string]any{
		"digest": rawRef.Digest, "size_bytes": rawRef.SizeBytes,
		"media_type": rawRef.MediaType, "owner_domain": rawRef.OwnerDomain, "access": rawRef.Access,
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	// Refresh the bound ref in case verification support advanced the journal.
	currentEnvs, _ := owner_store.LoadPrefix(ctx, c.store, h.Prefix)
	if len(currentEnvs) > len(h.Envelopes) {
		h.Envelopes = append([]JournalEnvelope(nil), currentEnvs...)
		last := currentEnvs[len(currentEnvs)-1]
		h.Prefix = JournalPrefix{JournalID: localHandle, LastSequence: last.Sequence, HeadHash: last.EventHash}
	}
	sourceEventRef := boundRef
	if len(h.Envelopes) > 0 {
		// Prefer the latest verification support event when present.
		for i := len(h.Envelopes) - 1; i >= 0; i-- {
			if h.Envelopes[i].EventKind == "source_verified" {
				ev := h.Envelopes[i]
				sourceEventRef = EvidenceRef{JournalID: ev.JournalID, Sequence: ev.Sequence, EventID: ev.EventID, EventHash: ev.EventHash, Pointer: ""}
				break
			}
		}
	}
	sourceEventMap := map[string]any{
		"journal_id": sourceEventRef.JournalID, "sequence": sourceEventRef.Sequence,
		"event_id": sourceEventRef.EventID, "event_hash": sourceEventRef.EventHash, "pointer": sourceEventRef.Pointer,
	}
	sub := EventSubmission{
		ProducerSequence: c.producerSeq.Add(1), EventKind: "native_report",
		EventSchemaVersion: controlEventSchema, OccurredAt: c.nowTimePoint(),
		Payload: owner_store.Payload{
			Data: map[string]any{
				"kind": "native_report", "channel": channel, "raw": rawMap,
				"source_event": sourceEventMap, "source_checks": checksMap,
				"mapping": mappingMap, "normalized_claims": claimsForJournal,
				"limitations": limitations,
			},
			Measurements: []owner_store.Measurement{},
			EvidenceRefs: []EvidenceRef{sourceEventRef},
			ArtifactRefs: []ArtifactReference{rawRef},
		},
	}
	// The source_event embedded object plus the envelope ref both cite the
	// same retained event; drop the embedded copy when the bound ref is
	// empty (no valid citation exists yet).
	if sourceEventRef.JournalID == "" {
		sub.Payload.Data["source_event"] = map[string]any{"value": nil, "reason": "not_observed"}
		sub.Payload.EvidenceRefs = []EvidenceRef{}
	}
	envs, err := owner_store.CommitOwner(ctx, c.store, localHandle, []EventSubmission{sub}, nil)
	if err != nil {
		return
	}
	if validateEnvelopes(envs) != nil {
		return
	}
	last := envs[len(envs)-1]
	h.Prefix = JournalPrefix{JournalID: localHandle, LastSequence: last.Sequence, HeadHash: last.EventHash}
	h.Envelopes = append(h.Envelopes, envs...)
	tryPublishLiveHead(h.Prefix)
}

// ---------------------------------------------------------------------------
// Observe.
// ---------------------------------------------------------------------------

func (c *Connector) handleObserve(ctx context.Context, req ConnectorRequest) (json.RawMessage, *ConnectorError) {
	var oreq ObserveRequest
	if err := strictUnmarshal(req.Payload, &oreq); err != nil {
		return nil, newConnectorError(codeInvalidRequest, domainRequest,
			fmt.Sprintf("observe payload: %v", err), deliveryNA, retryNewIfNot, nil, nil)
	}
	if err := validateHandle(oreq.Handle); err != nil {
		return nil, newConnectorError(codeInvalidRequest, domainRequest, err.Error(), deliveryNA, retryNewIfNot, nil, nil)
	}
	handleJSON := handleRaw(oreq.Handle)
	if req.ConnectorID != oreq.Handle.ConnectorID {
		return nil, newConnectorError(codeInvalidRequest, domainRequest,
			"payload handle must identify the request connector_id", deliveryNA, retryNewIfNot, handleJSON, nil)
	}
	if oreq.After.Handle != oreq.Handle {
		return nil, newConnectorError(codeInvalidRequest, domainRequest,
			"cursor handle must agree with the request handle", deliveryNA, retryNewIfNot, handleJSON, nil)
	}
	journalID := oreq.Handle.LocalHandle
	if oreq.After.JournalID != journalID {
		return nil, newConnectorError(codeInvalidRequest, domainRequest,
			"cursor journal must be the handle observation journal", deliveryNA, retryNewIfNot, handleJSON, nil)
	}
	if oreq.MaxItems < 1 {
		return nil, newConnectorError(codeInvalidRequest, domainRequest,
			"max_items starts at 1", deliveryNA, retryNewIfNot, handleJSON, nil)
	}
	desc := c.getDescriptor()
	if oreq.MaxItems > desc.Limits.MaxObservationItems || oreq.MaxItems > MaxObserveItems {
		return nil, newConnectorError(codeBudgetExceeded, domainRequest,
			"max_items exceeds the local observation bound", deliveryNA, retryNewIfNot, handleJSON, nil)
	}
	if err := validateDurationLimit(oreq.WaitLimit, "wait_limit"); err != nil {
		return nil, newConnectorError(codeInvalidRequest, domainRequest, err.Error(), deliveryNA, retryNewIfNot, handleJSON, nil)
	}
	if oreq.WaitLimit.Value > req.CallLimit.Value {
		return nil, newConnectorError(codeBudgetExceeded, domainRequest,
			"wait_limit cannot exceed the call limit", deliveryNA, retryNewIfNot, handleJSON, nil)
	}
	c.mu.Lock()
	h, ok := c.handles[journalID]
	c.mu.Unlock()
	if !ok {
		return nil, newConnectorError(codeUnknownHandle, domainRequest,
			"unknown handle; Start before Observe", deliveryNA, retryNewIfNot, handleJSON, nil)
	}
	h.mu.Lock()
	livePrefix := h.Prefix
	h.mu.Unlock()
	var cutoff JournalPrefix
	trimmed := bytes.TrimSpace(oreq.Through)
	if len(trimmed) == 0 {
		return nil, newConnectorError(codeInvalidRequest, domainRequest,
			"through is required", deliveryNA, retryNewIfNot, handleJSON, nil)
	}
	if trimmed[0] != '{' {
		return nil, newConnectorError(codeInvalidRequest, domainRequest,
			"through must be a journal prefix or a Missing envelope", deliveryNA, retryNewIfNot, handleJSON, nil)
	}
	var probe map[string]any
	if err := strictUnmarshal(oreq.Through, &probe); err != nil {
		return nil, newConnectorError(codeInvalidRequest, domainRequest,
			fmt.Sprintf("through: %v", err), deliveryNA, retryNewIfNot, handleJSON, nil)
	}
	if _, isMissing := probe["reason"]; isMissing {
		m, err := parseMissing(oreq.Through)
		if err != nil {
			return nil, newConnectorError(codeInvalidRequest, domainRequest,
				fmt.Sprintf("through: %v", err), deliveryNA, retryNewIfNot, handleJSON, nil)
		}
		if m.Reason != "not_applicable" {
			return nil, newConnectorError(codeInvalidRequest, domainRequest,
				"a missing through cutoff must carry reason not_applicable",
				deliveryNA, retryNewIfNot, handleJSON, nil)
		}
		cutoff = livePrefix
	} else {
		var prefix JournalPrefix
		if err := strictUnmarshal(oreq.Through, &prefix); err != nil {
			return nil, newConnectorError(codeInvalidRequest, domainRequest,
				fmt.Sprintf("through: %v", err), deliveryNA, retryNewIfNot, handleJSON, nil)
		}
		if err := validateJournalPrefix(prefix); err != nil {
			return nil, newConnectorError(codeInvalidRequest, domainRequest,
				fmt.Sprintf("through: %v", err), deliveryNA, retryNewIfNot, handleJSON, nil)
		}
		if prefix.JournalID != journalID {
			return nil, newConnectorError(codeInvalidRequest, domainRequest,
				"cutoff journal must agree with the cursor journal", deliveryNA, retryNewIfNot, handleJSON, nil)
		}
		if oreq.WaitLimit.Value != 0 {
			return nil, newConnectorError(codeInvalidRequest, domainRequest,
				"a fixed through cutoff requires wait_limit value 0",
				deliveryNA, retryNewIfNot, handleJSON, nil)
		}
		cutoff = prefix
	}
	events, err := owner_store.LoadPrefix(ctx, c.store, cutoff)
	if err != nil {
		return nil, newConnectorError(mapLoadCode(err), mapLoadDomain(err),
			mapLoadDetail("observe", cutoff, err), deliveryNA, mapLoadRetry(err), handleJSON, nil)
	}
	if err := verifyPrefixEvents(cutoff, events); err != nil {
		return nil, newConnectorError(codeIntegrityConflict, domainConnector,
			fmt.Sprintf("retained journal failed verification: %v", err),
			deliveryNA, retryOperator, handleJSON, nil)
	}
	bySeq := make(map[int64]JournalEnvelope, len(events))
	for _, env := range events {
		bySeq[env.Sequence] = env
	}
	afterSeq := oreq.After.Sequence
	if afterSeq < 0 {
		return nil, newConnectorError(codeCursorInvalid, domainRequest,
			"cursor sequence must not be negative", deliveryNA, retryNewIfNot, handleJSON, nil)
	}
	if afterSeq == 0 {
		_, missing, err := parseDigestOrMissing(oreq.After.EventHash, "cursor event_hash")
		if err != nil || missing == nil || missing.Reason != "not_applicable" {
			return nil, newConnectorError(codeCursorInvalid, domainRequest,
				"the zero cursor begins before admission and carries an inapplicable hash",
				deliveryNA, retryNewIfNot, handleJSON, nil)
		}
	} else {
		hash, missing, err := parseDigestOrMissing(oreq.After.EventHash, "cursor event_hash")
		if err != nil || missing != nil {
			return nil, newConnectorError(codeCursorInvalid, domainRequest,
				"a positive cursor carries the retained event digest", deliveryNA, retryNewIfNot, handleJSON, nil)
		}
		if afterSeq > cutoff.LastSequence {
			return nil, newConnectorError(codeCursorInvalid, domainRequest,
				fmt.Sprintf("cursor sequence %d is ahead of cutoff %d", afterSeq, cutoff.LastSequence),
				deliveryNA, retryNewIfNot, handleJSON, nil)
		}
		retained, ok := bySeq[afterSeq]
		if !ok || retained.EventHash != hash {
			return nil, newConnectorError(codeCursorUnavailable, domainConnector,
				fmt.Sprintf("cursor history at sequence %d no longer matches the retained journal", afterSeq),
				deliveryNA, retryOperator, handleJSON, nil)
		}
	}
	items := []ObservationItem{}
	nextSeq := afterSeq
	for seq := afterSeq + 1; seq <= cutoff.LastSequence; seq++ {
		env, ok := bySeq[seq]
		if !ok {
			return nil, newConnectorError(codeIntegrityConflict, domainConnector,
				fmt.Sprintf("retained prefix is missing sequence %d", seq),
				deliveryNA, retryOperator, handleJSON, nil)
		}
		if !isObservationKind(env.EventKind) {
			nextSeq = seq
			continue
		}
		if int64(len(items)) >= oreq.MaxItems {
			break
		}
		item, err := projectItem(env)
		if err != nil {
			return nil, newConnectorError(codeIntegrityConflict, domainConnector,
				fmt.Sprintf("sequence %d projection: %v", seq, err),
				deliveryNA, retryOperator, handleJSON, nil)
		}
		items = append(items, item)
		nextSeq = seq
	}
	hasMore := nextSeq < cutoff.LastSequence
	nextCursor := ObservationCursor{Handle: oreq.Handle, JournalID: journalID, Sequence: nextSeq}
	if nextSeq == 0 {
		nextCursor.EventHash = missingRaw("not_applicable", "cursor before admission")
	} else {
		if env, ok := bySeq[nextSeq]; ok {
			nextCursor.EventHash = digestRaw(env.EventHash)
		} else {
			nextCursor.EventHash = missingRaw("not_applicable", "cursor before admission")
			nextCursor.Sequence = 0
		}
	}
	closeRef := json.RawMessage(missingRaw("not_observed", "observation remains open at this cutoff"))
	for _, env := range events {
		if isClosureKind(env.EventKind) && env.Sequence <= cutoff.LastSequence {
			if closeRef == nil || bytes.Contains(closeRef, []byte("not_observed")) {
				closeRef = mustMarshal(EvidenceRef{
					JournalID: env.JournalID, Sequence: env.Sequence,
					EventID: env.EventID, EventHash: env.EventHash, Pointer: "",
				})
			}
		}
	}
	// Prefer the latest closure at or before the cutoff.
	for i := len(events) - 1; i >= 0; i-- {
		if isClosureKind(events[i].EventKind) && events[i].Sequence <= cutoff.LastSequence {
			env := events[i]
			closeRef = mustMarshal(EvidenceRef{
				JournalID: env.JournalID, Sequence: env.Sequence,
				EventID: env.EventID, EventHash: env.EventHash, Pointer: "",
			})
			break
		}
	}
	page := ObservationPage{
		Kind: "observation_page", Handle: oreq.Handle, After: oreq.After,
		Through: cutoff, Next: nextCursor, HasMore: hasMore,
		ObservationCloseRef: closeRef, Items: items, Limitations: []string{},
	}
	if desc.Limits.MaxObservationItems < int64(len(items)) {
		page.Limitations = append(page.Limitations, "descriptor observation bound applied")
	}
	tryDelegateObserve(ctx, c.store, req, oreq)
	return mustMarshal(page), nil
}

func tryDelegateObserve(ctx context.Context, store *OwnerStore, req ConnectorRequest, _ ObserveRequest) {
	cqReq := connector_queries.ConnectorRequest{
		RecordType: req.RecordType, SchemaVersion: req.SchemaVersion,
		RequestID: req.RequestID, ConnectorID: req.ConnectorID,
		Operation: req.Operation,
		CallLimit: connector_queries.DurationLimit{Kind: req.CallLimit.Kind, Unit: req.CallLimit.Unit, Value: req.CallLimit.Value},
		Payload: append(json.RawMessage(nil), req.Payload...),
	}
	_, _ = connector_queries.ObserveHandle(ctx, store, cqReq)
}

func isObservationKind(kind string) bool {
	switch kind {
	case "native_report", "context_observation", "task_output", "connector_incident",
		"control_observation", "lifecycle_publication", "artifact_available", "clock_registered":
		return true
	default:
		return false
	}
}

func isClosureKind(kind string) bool {
	return kind == "observation_closed" || kind == "observation_close"
}

func projectItem(env JournalEnvelope) (ObservationItem, error) {
	data := env.Payload.Data
	if data == nil {
		return ObservationItem{}, fmt.Errorf("payload data is required")
	}
	payloadCopy := make(map[string]any, len(data))
	for k, v := range data {
		payloadCopy[k] = v
	}
	raw, err := json.Marshal(env.RecordedAt)
	if err != nil {
		return ObservationItem{}, fmt.Errorf("recorded_at is unreadable")
	}
	var recordedAt TimePoint
	if err := strictUnmarshal(raw, &recordedAt); err != nil {
		return ObservationItem{}, fmt.Errorf("recorded_at is not a TimePoint")
	}
	eventRef := EvidenceRef{
		JournalID: env.JournalID, Sequence: env.Sequence,
		EventID: env.EventID, EventHash: env.EventHash, Pointer: "",
	}
	measurements := []any{}
	for _, m := range env.Payload.Measurements {
		raw, _ := json.Marshal(m)
		var mm map[string]any
		_ = json.Unmarshal(raw, &mm)
		measurements = append(measurements, map[string]any{
			"measurement": mm, "evidence_refs": []EvidenceRef{eventRef},
		})
	}
	artifactRefs := []ArtifactReference{}
	artifactRefs = append(artifactRefs, env.Payload.ArtifactRefs...)
	return ObservationItem{
		EventRef: eventRef, RecordedAt: recordedAt, Provenance: env.Provenance,
		Payload: payloadCopy, Measurements: measurements, ArtifactRefs: artifactRefs,
	}, nil
}

// ---------------------------------------------------------------------------
// CollectArtifacts.
// ---------------------------------------------------------------------------

func (c *Connector) handleCollect(ctx context.Context, req ConnectorRequest) (json.RawMessage, *ConnectorError) {
	var creq CollectArtifactsRequest
	if err := strictUnmarshal(req.Payload, &creq); err != nil {
		return nil, newConnectorError(codeInvalidRequest, domainRequest,
			fmt.Sprintf("collect_artifacts payload: %v", err), deliveryNA, retryNewIfNot, nil, nil)
	}
	if err := validateHandle(creq.Handle); err != nil {
		return nil, newConnectorError(codeInvalidRequest, domainRequest, err.Error(), deliveryNA, retryNewIfNot, nil, nil)
	}
	handleJSON := handleRaw(creq.Handle)
	if req.ConnectorID != creq.Handle.ConnectorID {
		return nil, newConnectorError(codeInvalidRequest, domainRequest,
			"payload handle must identify the request connector_id", deliveryNA, retryNewIfNot, handleJSON, nil)
	}
	switch creq.Selector.Mode {
	case "inventory", "named", "bytes":
	default:
		return nil, newConnectorError(codeInvalidRequest, domainRequest,
			fmt.Sprintf("selector mode %q is not inventory, named, or bytes", creq.Selector.Mode),
			deliveryNA, retryNewIfNot, handleJSON, nil)
	}
	if creq.Selector.Mode == "named" && len(creq.Selector.Names) == 0 {
		return nil, newConnectorError(codeInvalidRequest, domainRequest,
			"named selector requires at least one name", deliveryNA, retryNewIfNot, handleJSON, nil)
	}
	if creq.Selector.Mode == "bytes" {
		if !validDigest(creq.Selector.Digest) {
			return nil, newConnectorError(codeInvalidRequest, domainRequest,
				"bytes selector digest must be a sha256 digest", deliveryNA, retryNewIfNot, handleJSON, nil)
		}
		if creq.Selector.Offset < 0 || creq.Selector.MaxBytes < 0 {
			return nil, newConnectorError(codeInvalidRequest, domainRequest,
				"bytes selector offset and max_bytes must not be negative",
				deliveryNA, retryNewIfNot, handleJSON, nil)
		}
	}
	journalID := creq.Handle.LocalHandle
	c.mu.Lock()
	h, ok := c.handles[journalID]
	var prep *preparationRecord
	if ok {
		prep = c.preparations[h.PreparationID]
	}
	c.mu.Unlock()
	if !ok {
		return nil, newConnectorError(codeUnknownHandle, domainRequest,
			"unknown handle", deliveryNA, retryNewIfNot, handleJSON, nil)
	}
	h.mu.Lock()
	prefix := h.Prefix
	h.mu.Unlock()
	events, err := owner_store.LoadPrefix(ctx, c.store, prefix)
	if err != nil {
		return nil, newConnectorError(mapLoadCode(err), mapLoadDomain(err),
			mapLoadDetail("collect_artifacts", prefix, err), deliveryNA, mapLoadRetry(err), handleJSON, nil)
	}
	tryDelegateCollect(ctx, c.store, req)
	index := map[string]ArtifactReference{}
	evidenceFor := map[string][]EvidenceRef{}
	for _, env := range events {
		ref := EvidenceRef{JournalID: env.JournalID, Sequence: env.Sequence, EventID: env.EventID, EventHash: env.EventHash, Pointer: ""}
		for _, ar := range env.Payload.ArtifactRefs {
			if _, seen := index[ar.Digest]; !seen {
				index[ar.Digest] = ar
			}
			evidenceFor[ar.Digest] = append(evidenceFor[ar.Digest], ref)
		}
	}
	named := map[string]ArtifactReference{}
	if prep != nil {
		named["delivered_task"] = prep.Prepared.DeliveredTask
		named["native_request"] = prep.Prepared.NativeRequest
		named["preparation"] = prep.Artifact
		for name, ar := range named {
			if _, seen := index[ar.Digest]; !seen {
				index[ar.Digest] = ar
				evidenceFor[ar.Digest] = append(evidenceFor[ar.Digest], prep.RegistrationRef)
			}
			_ = name
		}
	}
	for _, env := range events {
		if env.EventKind == "native_report" {
			if rawMap, ok := env.Payload.Data["raw"].(map[string]any); ok {
				digest, _ := rawMap["digest"].(string)
				if validDigest(digest) {
					if ar, seen := index[digest]; seen {
						named["native_report_"+fmt.Sprint(env.Sequence)] = ar
					}
				}
			}
		}
	}
	switch creq.Selector.Mode {
	case "inventory", "named":
		want := map[string]bool{}
		if creq.Selector.Mode == "named" {
			for _, n := range creq.Selector.Names {
				want[n] = true
			}
		}
		names := make([]string, 0, len(named))
		for n := range named {
			if creq.Selector.Mode == "named" && !want[n] {
				continue
			}
			names = append(names, n)
		}
		sort.Strings(names)
		slots := []ArtifactSlot{}
		for _, n := range names {
			ar := named[n]
			content, _ := json.Marshal(map[string]any{
				"digest": ar.Digest, "size_bytes": ar.SizeBytes,
				"media_type": ar.MediaType, "owner_domain": ar.OwnerDomain, "access": ar.Access,
			})
			refs := evidenceFor[ar.Digest]
			if refs == nil {
				refs = []EvidenceRef{}
			}
			slots = append(slots, ArtifactSlot{
				Name: n, ExpectedDigest: json.RawMessage(`"` + ar.Digest + `"`),
				Content: content, EvidenceRefs: refs,
			})
		}
		if creq.Selector.Mode == "named" {
			for _, n := range creq.Selector.Names {
				if _, ok := named[n]; !ok {
					return nil, newConnectorError(codeArtifactUnavailable, domainConnector,
						fmt.Sprintf("artifact %q is not retained for this handle", n),
						deliveryNA, retryOperator, handleJSON, nil)
				}
			}
		}
		inv := ArtifactInventory{
			Kind: "artifact_inventory", Handle: creq.Handle, Artifacts: slots,
			Coverage: "retained_through_cutoff", EvidencePrefix: prefix, Limitations: []string{},
		}
		return mustMarshal(inv), nil
	default:
		ar, ok := index[creq.Selector.Digest]
		if !ok {
			return nil, newConnectorError(codeArtifactUnavailable, domainConnector,
				"digest is not registered in the handle journal through the cutoff",
				deliveryNA, retryOperator, handleJSON, nil)
		}
		content, err := owner_store.ReadArtifact(ctx, c.store, ar)
		if err != nil {
			return nil, mapStoreErrorWithHandle(err, "read artifact bytes", handleJSON)
		}
		if creq.Selector.Offset > int64(len(content)) {
			return nil, newConnectorError(codeInvalidRequest, domainRequest,
				"offset is beyond the retained artifact", deliveryNA, retryNewIfNot, handleJSON, nil)
		}
		maxBytes := creq.Selector.MaxBytes
		if maxBytes == 0 {
			maxBytes = int64(len(content)) - creq.Selector.Offset
		}
		desc := c.getDescriptor()
		if maxBytes > desc.Limits.MaxArtifactChunkBytes || maxBytes > MaxCollectChunk {
			return nil, newConnectorError(codeBudgetExceeded, domainRequest,
				"max_bytes exceeds the local chunk bound", deliveryNA, retryNewIfNot, handleJSON, nil)
		}
		end := creq.Selector.Offset + maxBytes
		if end > int64(len(content)) {
			end = int64(len(content))
		}
		window := content[creq.Selector.Offset:end]
		chunkDigest := string(evidence_codec.HashBytes(window))
		refs := evidenceFor[ar.Digest]
		if refs == nil {
			refs = []EvidenceRef{}
		}
		chunk := ArtifactChunk{
			Kind: "artifact_chunk", Handle: creq.Handle, Digest: ar.Digest,
			SizeBytes: int64(len(content)), Offset: creq.Selector.Offset,
			ReturnedBytes: int64(len(window)), DataBase64: base64.StdEncoding.EncodeToString(window),
			ChunkDigest: chunkDigest, EndOfArtifact: end == int64(len(content)), EvidenceRefs: refs,
		}
		return mustMarshal(chunk), nil
	}
}

func tryDelegateCollect(ctx context.Context, store *OwnerStore, req ConnectorRequest) {
	cqReq := connector_queries.ConnectorRequest{
		RecordType: req.RecordType, SchemaVersion: req.SchemaVersion,
		RequestID: req.RequestID, ConnectorID: req.ConnectorID,
		Operation: req.Operation,
		CallLimit: connector_queries.DurationLimit{Kind: req.CallLimit.Kind, Unit: req.CallLimit.Unit, Value: req.CallLimit.Value},
		Payload: append(json.RawMessage(nil), req.Payload...),
	}
	_, _ = connector_queries.CollectHandleArtifacts(ctx, store, cqReq)
}

// ---------------------------------------------------------------------------
// Controls.
// ---------------------------------------------------------------------------

func (c *Connector) handleRequestNativeCancel(ctx context.Context, _ *http.Request, req ConnectorRequest) (json.RawMessage, *ConnectorError) {
	var creq NativeCancelRequest
	if err := strictUnmarshal(req.Payload, &creq); err != nil {
		return nil, newConnectorError(codeInvalidRequest, domainRequest,
			fmt.Sprintf("cancel payload: %v", err), deliveryNA, retryNewIfNot, nil, nil)
	}
	if err := validateHandle(creq.Handle); err != nil {
		return nil, newConnectorError(codeInvalidRequest, domainRequest, err.Error(), deliveryNA, retryNewIfNot, nil, nil)
	}
	handleJSON := handleRaw(creq.Handle)
	if req.ConnectorID != creq.Handle.ConnectorID {
		return nil, newConnectorError(codeInvalidRequest, domainRequest,
			"payload handle must identify the request connector_id", deliveryNA, retryNewIfNot, handleJSON, nil)
	}
	if strings.TrimSpace(creq.Reason) == "" {
		return nil, newConnectorError(codeInvalidRequest, domainRequest,
			"reason is required", deliveryNA, retryNewIfNot, handleJSON, nil)
	}
	journalID := creq.Handle.LocalHandle
	c.mu.Lock()
	h, ok := c.handles[journalID]
	c.mu.Unlock()
	if !ok {
		return nil, newConnectorError(codeUnknownHandle, domainRequest,
			"unknown handle", deliveryNA, retryNewIfNot, handleJSON, nil)
	}
	op, _ := c.findOperation(OpRequestNativeCancel)
	cap, capOK := c.findCapability("native_cancel")
	if op.Implementation == "unmapped" {
		obs := c.controlObservation(ctx, creq.Handle, OpRequestNativeCancel, "native_execution",
			"unsupported", missingCapability("not_applicable", "cancel operation is unmapped; no native contract exists"),
			"unexposed", "unmapped cancel operation cannot be exposed",
			[]string{"unmapped operation RequestNativeCancel: no native cancellation contract is declared"})
		return c.journalControl(ctx, h, creq.Handle, obs)
	}
	if capOK && cap.Availability == "unsupported" {
		digests := make([]string, 0, len(cap.EvidenceRefs))
		for _, r := range cap.EvidenceRefs {
			digests = append(digests, r.EventHash)
		}
		capRef := map[string]any{
			"capability_id": "native_cancel", "availability": "unsupported",
			"evidence_refs": []EvidenceRef{},
		}
		limitation := "evidenced native absence for native_cancel: declaration evidence retained; distinct from unmapped operation"
		if len(digests) > 0 {
			limitation += "; declaration digests " + strings.Join(digests, ",")
		}
		obs := c.controlObservation(ctx, creq.Handle, OpRequestNativeCancel, "native_execution",
			"unsupported", capRef, "blocked",
			"evidenced native absence: subject declares native cancellation unsupported",
			[]string{limitation})
		return c.journalControl(ctx, h, creq.Handle, obs)
	}
	if capOK && cap.Availability == "unknown" {
		obs := c.controlObservation(ctx, creq.Handle, OpRequestNativeCancel, "native_execution",
			"unknown", missingCapability("not_observed", "cancel capability is unknown; no run evidence yet"),
			"unexposed", "unknown cancel capability cannot be exposed",
			[]string{"native_cancel availability is unknown for this subject version"})
		return c.journalControl(ctx, h, creq.Handle, obs)
	}
	if strings.TrimSpace(op.NativeEndpoint) == "" {
		obs := c.controlObservation(ctx, creq.Handle, OpRequestNativeCancel, "native_execution",
			"unsupported", missingCapability("not_applicable", "cancel mapping declares no native endpoint"),
			"unexposed", "cancel mapping has no endpoint",
			[]string{"cancel operation is mapped without a native endpoint"})
		return c.journalControl(ctx, h, creq.Handle, obs)
	}
	requestBytes := mustMarshal(map[string]any{"handle": creq.Handle.LocalHandle, "reason": creq.Reason})
	requestRef, err := owner_store.InstallArtifact(ctx, c.store, bytes.NewReader(requestBytes), "application/json", "restricted")
	if err != nil {
		return nil, mapStoreErrorWithHandle(err, "install cancel request", handleJSON)
	}
	nreq, err := http.NewRequestWithContext(ctx, http.MethodPost, op.NativeEndpoint, bytes.NewReader(requestBytes))
	if err != nil {
		obs := c.controlObservation(ctx, creq.Handle, OpRequestNativeCancel, "native_execution",
			"requested", capabilityRefFor(cap, capOK), "exposed",
			"cancel request recorded; wire delivery could not be constructed",
			[]string{"cancel request recorded without wire delivery"})
		obs.RequestRef = artifactEvidencePlaceholder(requestRef)
		return c.journalControl(ctx, h, creq.Handle, obs)
	}
	nreq.Header.Set("Content-Type", "application/json")
	c.mu.Lock()
	c.nativeCalls = append(c.nativeCalls, NativeCall{Method: nreq.Method, URL: nreq.URL.String(), Body: requestBytes, At: time.Now()})
	c.mu.Unlock()
	resp, err := c.native.RoundTrip(nreq)
	if err != nil {
		obs := c.controlObservation(ctx, creq.Handle, OpRequestNativeCancel, "native_execution",
			"requested", capabilityRefFor(cap, capOK), "exposed",
			"cancel request recorded; native delivery uncertain",
			[]string{"cancel requested; native state unknown; no termination asserted"})
		obs.RequestRef = artifactEvidencePlaceholder(requestRef)
		return c.journalControl(ctx, h, creq.Handle, obs)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxNativeBodyBytes+1))
	respRef, _ := owner_store.InstallArtifact(ctx, c.store, bytes.NewReader(respBody), "application/json", "public")
	obs := c.controlObservation(ctx, creq.Handle, OpRequestNativeCancel, "native_execution",
		"acknowledged", capabilityRefFor(cap, capOK), "exposed",
		"native cancel response verified; effect remains unobserved",
		[]string{"cancel acknowledged by native response; stop effect requires independent evidence"})
	obs.RequestRef = artifactEvidencePlaceholder(requestRef)
	obs.ResponseRef = artifactEvidencePlaceholder(respRef)
	obs.ResponseChecks = map[string]any{
		"authentication": "verified", "correlation": "matched", "trace_correlation": "not_applicable",
		"verification_policy": map[string]any{
			"id": c.getDescriptor().ConnectorID, "version": c.getDescriptor().ConnectorVersion,
			"artifact_digest": c.getDescriptor().Binding.ArtifactDigest,
		},
		"matched_by": []string{"handle"}, "evidence_refs": []EvidenceRef{},
	}
	return c.journalControl(ctx, h, creq.Handle, obs)
}

func (c *Connector) handleClose(ctx context.Context, _ *http.Request, req ConnectorRequest) (json.RawMessage, *ConnectorError) {
	var creq CloseConnectionRequest
	if err := strictUnmarshal(req.Payload, &creq); err != nil {
		return nil, newConnectorError(codeInvalidRequest, domainRequest,
			fmt.Sprintf("close payload: %v", err), deliveryNA, retryNewIfNot, nil, nil)
	}
	if err := validateHandle(creq.Handle); err != nil {
		return nil, newConnectorError(codeInvalidRequest, domainRequest, err.Error(), deliveryNA, retryNewIfNot, nil, nil)
	}
	handleJSON := handleRaw(creq.Handle)
	if req.ConnectorID != creq.Handle.ConnectorID {
		return nil, newConnectorError(codeInvalidRequest, domainRequest,
			"payload handle must identify the request connector_id", deliveryNA, retryNewIfNot, handleJSON, nil)
	}
	switch creq.Reason {
	case "operator_stop", "local_deadline", "normal_completion":
	default:
		return nil, newConnectorError(codeInvalidRequest, domainRequest,
			"reason must be operator_stop, local_deadline, or normal_completion",
			deliveryNA, retryNewIfNot, handleJSON, nil)
	}
	journalID := creq.Handle.LocalHandle
	c.mu.Lock()
	h, ok := c.handles[journalID]
	c.mu.Unlock()
	if !ok {
		return nil, newConnectorError(codeUnknownHandle, domainRequest,
			"unknown handle", deliveryNA, retryNewIfNot, handleJSON, nil)
	}
	h.mu.Lock()
	alreadyClosed := h.State == "closed"
	h.TransportClosed = true
	if creq.EndObservation && h.State == "active" {
		h.State = "draining"
		h.EndObservation = true
		deadline, derr := clock_rules.ComputeDeadline(toClockTimePoint(h.CreatedAt), clock_rules.DurationLimit{
			Kind: "exact", Unit: "ms", Value: float64(c.getDescriptor().Limits.MaxCallWait.Value),
		})
		if derr == nil {
			tp := toJournalTimePoint(deadline)
			h.DrainDeadline = &tp
		}
	}
	h.mu.Unlock()
	if alreadyClosed {
		obs := c.controlObservation(ctx, creq.Handle, OpCloseObservationConnection, "observation_connection",
			"acknowledged", missingCapability("not_applicable", "observation already closed; close is idempotent"),
			"unexposed", "repeated close of a closed window is idempotent",
			[]string{"repeated close is idempotent; a closed window cannot be reopened"})
		return c.journalControl(ctx, h, creq.Handle, obs)
	}
	if creq.EndObservation {
		drainMs := 5000.0
		obs := c.controlObservation(ctx, creq.Handle, OpCloseObservationConnection, "observation_connection",
			"acknowledged", missingCapability("not_applicable", "local observation transport closed; bounded drain started"),
			"unexposed", "end_observation begins bounded local finalization; native cancellation is not implied",
			[]string{"end_observation=true starts bounded drain/finalization; false would close only the native transport; neither implies cancellation"})
		result, cerr := c.journalControl(ctx, h, creq.Handle, obs)
		go c.boundedFinalize(context.WithoutCancel(ctx), journalID, time.Duration(drainMs*float64(time.Millisecond)))
		return result, cerr
	}
	obs := c.controlObservation(ctx, creq.Handle, OpCloseObservationConnection, "observation_connection",
		"acknowledged", missingCapability("not_applicable", "native observation transport closed; Observe API remains durable"),
		"unexposed", "transport-only close; later authenticated callbacks remain receivable",
		[]string{"end_observation=false closes only the native observation transport"})
	return c.journalControl(ctx, h, creq.Handle, obs)
}

func (c *Connector) boundedFinalize(ctx context.Context, localHandle string, bound time.Duration) {
	if bound > 5*time.Second {
		bound = 5 * time.Second
	}
	if bound < 50*time.Millisecond {
		bound = 50 * time.Millisecond
	}
	timer := time.NewTimer(bound)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
	c.mu.Lock()
	h, ok := c.handles[localHandle]
	c.mu.Unlock()
	if !ok {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.State == "closed" {
		return
	}
	sub := EventSubmission{
		ProducerSequence: c.producerSeq.Add(1), EventKind: "observation_closed",
		EventSchemaVersion: controlEventSchema, OccurredAt: c.nowTimePoint(),
		Payload: owner_store.Payload{
			Data: map[string]any{
				"local_handle": localHandle, "reason": "bounded_local_finalization",
				"detail": "local drain bound elapsed; remote work cannot prevent bounded local finalization",
			},
			Measurements: []owner_store.Measurement{},
			EvidenceRefs: []EvidenceRef{}, ArtifactRefs: []ArtifactReference{},
		},
	}
	envs, err := owner_store.CommitOwner(ctx, c.store, localHandle, []EventSubmission{sub}, nil)
	if err != nil {
		return
	}
	if validateEnvelopes(envs) != nil {
		return
	}
	last := envs[len(envs)-1]
	h.Prefix = JournalPrefix{JournalID: localHandle, LastSequence: last.Sequence, HeadHash: last.EventHash}
	h.Envelopes = append(h.Envelopes, envs...)
	ref := EvidenceRef{JournalID: last.JournalID, Sequence: last.Sequence, EventID: last.EventID, EventHash: last.EventHash, Pointer: ""}
	h.CloseRef = &ref
	h.State = "closed"
	tryPublishLiveHead(h.Prefix)
}

func (c *Connector) handleRelease(ctx context.Context, _ *http.Request, req ConnectorRequest) (json.RawMessage, *ConnectorError) {
	var creq ReleaseContextRequest
	if err := strictUnmarshal(req.Payload, &creq); err != nil {
		return nil, newConnectorError(codeInvalidRequest, domainRequest,
			fmt.Sprintf("release payload: %v", err), deliveryNA, retryNewIfNot, nil, nil)
	}
	if err := validateHandle(creq.Handle); err != nil {
		return nil, newConnectorError(codeInvalidRequest, domainRequest, err.Error(), deliveryNA, retryNewIfNot, nil, nil)
	}
	handleJSON := handleRaw(creq.Handle)
	if req.ConnectorID != creq.Handle.ConnectorID {
		return nil, newConnectorError(codeInvalidRequest, domainRequest,
			"payload handle must identify the request connector_id", deliveryNA, retryNewIfNot, handleJSON, nil)
	}
	trimmed := bytes.TrimSpace(creq.ContextRef)
	if len(trimmed) == 0 {
		return nil, newConnectorError(codeInvalidRequest, domainRequest,
			"context_ref is required (string identity or Missing)", deliveryNA, retryNewIfNot, handleJSON, nil)
	}
	if trimmed[0] == '"' {
		var s string
		if err := json.Unmarshal(trimmed, &s); err != nil || strings.TrimSpace(s) == "" {
			return nil, newConnectorError(codeInvalidRequest, domainRequest,
				"context_ref string must be a nonempty observed identity", deliveryNA, retryNewIfNot, handleJSON, nil)
		}
	} else if trimmed[0] == '{' {
		m, err := parseMissing(creq.ContextRef)
		if err != nil {
			return nil, newConnectorError(codeInvalidRequest, domainRequest,
				fmt.Sprintf("context_ref: %v", err), deliveryNA, retryNewIfNot, handleJSON, nil)
		}
		if !nullReasons[m.Reason] {
			return nil, newConnectorError(codeInvalidRequest, domainRequest,
				"context_ref Missing reason is unknown", deliveryNA, retryNewIfNot, handleJSON, nil)
		}
	} else {
		return nil, newConnectorError(codeInvalidRequest, domainRequest,
			"context_ref must be a string identity or a Missing envelope", deliveryNA, retryNewIfNot, handleJSON, nil)
	}
	journalID := creq.Handle.LocalHandle
	c.mu.Lock()
	h, ok := c.handles[journalID]
	c.mu.Unlock()
	if !ok {
		return nil, newConnectorError(codeUnknownHandle, domainRequest,
			"unknown handle", deliveryNA, retryNewIfNot, handleJSON, nil)
	}
	op, _ := c.findOperation(OpReleaseNativeContext)
	if op.Implementation == "unmapped" {
		obs := c.controlObservation(ctx, creq.Handle, OpReleaseNativeContext, "native_context",
			"unsupported", missingCapability("not_applicable", "context release is unmapped; no native contract exists"),
			"unexposed", "unmapped release operation cannot be exposed",
			[]string{"unmapped operation ReleaseNativeContext: typed unsupported evidence; release failure never triggers containment"})
		return c.journalControl(ctx, h, creq.Handle, obs)
	}
	cap, capOK := c.findCapability("native_context_release")
	if capOK && cap.Availability == "unsupported" {
		digests := make([]string, 0, len(cap.EvidenceRefs))
		for _, r := range cap.EvidenceRefs {
			digests = append(digests, r.EventHash)
		}
		capRef := map[string]any{
			"capability_id": "native_context_release", "availability": "unsupported",
			"evidence_refs": []EvidenceRef{},
		}
		limitation := "evidenced native absence for native_context_release; typed unsupported evidence; no containment"
		if len(digests) > 0 {
			limitation += "; declaration digests " + strings.Join(digests, ",")
		}
		obs := c.controlObservation(ctx, creq.Handle, OpReleaseNativeContext, "native_context",
			"unsupported", capRef, "blocked",
			"evidenced native absence: subject declares context release unsupported",
			[]string{limitation})
		return c.journalControl(ctx, h, creq.Handle, obs)
	}
	if strings.TrimSpace(op.NativeEndpoint) == "" {
		obs := c.controlObservation(ctx, creq.Handle, OpReleaseNativeContext, "native_context",
			"unsupported", missingCapability("not_applicable", "release mapping declares no native endpoint"),
			"unexposed", "release mapping has no endpoint",
			[]string{"release operation is mapped without a native endpoint; no containment"})
		return c.journalControl(ctx, h, creq.Handle, obs)
	}
	requestBytes := mustMarshal(map[string]any{"handle": creq.Handle.LocalHandle, "context_ref": json.RawMessage(creq.ContextRef)})
	requestRef, err := owner_store.InstallArtifact(ctx, c.store, bytes.NewReader(requestBytes), "application/json", "restricted")
	if err != nil {
		return nil, mapStoreErrorWithHandle(err, "install release request", handleJSON)
	}
	nreq, err := http.NewRequestWithContext(ctx, http.MethodPost, op.NativeEndpoint, bytes.NewReader(requestBytes))
	if err != nil {
		obs := c.controlObservation(ctx, creq.Handle, OpReleaseNativeContext, "native_context",
			"requested", capabilityRefFor(cap, capOK), "exposed",
			"release request recorded; wire delivery could not be constructed; no containment",
			[]string{"release requested without wire delivery; failure never silently invokes containment"})
		obs.RequestRef = artifactEvidencePlaceholder(requestRef)
		return c.journalControl(ctx, h, creq.Handle, obs)
	}
	nreq.Header.Set("Content-Type", "application/json")
	c.mu.Lock()
	c.nativeCalls = append(c.nativeCalls, NativeCall{Method: nreq.Method, URL: nreq.URL.String(), Body: requestBytes, At: time.Now()})
	c.mu.Unlock()
	resp, err := c.native.RoundTrip(nreq)
	if err != nil {
		obs := c.controlObservation(ctx, creq.Handle, OpReleaseNativeContext, "native_context",
			"requested", capabilityRefFor(cap, capOK), "exposed",
			"release request recorded; native delivery failed; containment was not invoked",
			[]string{"release failure never silently invokes containment; use an explicit Contain command with independent authority"})
		obs.RequestRef = artifactEvidencePlaceholder(requestRef)
		return c.journalControl(ctx, h, creq.Handle, obs)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxNativeBodyBytes+1))
	respRef, _ := owner_store.InstallArtifact(ctx, c.store, bytes.NewReader(respBody), "application/json", "public")
	obs := c.controlObservation(ctx, creq.Handle, OpReleaseNativeContext, "native_context",
		"acknowledged", capabilityRefFor(cap, capOK), "exposed",
		"native release response verified; effect remains unobserved; no containment",
		[]string{"release acknowledged; effect requires independent evidence; failure never silently invokes containment"})
	obs.RequestRef = artifactEvidencePlaceholder(requestRef)
	obs.ResponseRef = artifactEvidencePlaceholder(respRef)
	return c.journalControl(ctx, h, creq.Handle, obs)
}

func (c *Connector) handleContain(ctx context.Context, r *http.Request, req ConnectorRequest) (json.RawMessage, *ConnectorError) {
	var creq ContainRequest
	if err := strictUnmarshal(req.Payload, &creq); err != nil {
		return nil, newConnectorError(codeInvalidRequest, domainRequest,
			fmt.Sprintf("contain payload: %v", err), deliveryNA, retryNewIfNot, nil, nil)
	}
	if err := validateHandle(creq.Handle); err != nil {
		return nil, newConnectorError(codeInvalidRequest, domainRequest, err.Error(), deliveryNA, retryNewIfNot, nil, nil)
	}
	handleJSON := handleRaw(creq.Handle)
	if req.ConnectorID != creq.Handle.ConnectorID {
		return nil, newConnectorError(codeInvalidRequest, domainRequest,
			"payload handle must identify the request connector_id", deliveryNA, retryNewIfNot, handleJSON, nil)
	}
	switch creq.Target.Kind {
	case "fixture_mutation_authority", "local_process", "deployment_slot", "harness_resources":
	default:
		return nil, newConnectorError(codeInvalidRequest, domainRequest,
			"target kind must be a reviewed containment scope", deliveryNA, retryNewIfNot, handleJSON, nil)
	}
	if strings.TrimSpace(creq.Target.ResourceID) == "" {
		return nil, newConnectorError(codeInvalidRequest, domainRequest,
			"target resource_id must be an authorized registry identity",
			deliveryNA, retryNewIfNot, handleJSON, nil)
	}
	c.mu.Lock()
	allowed := c.targetAllow[creq.Target.Kind+"\x00"+creq.Target.ResourceID]
	c.mu.Unlock()
	if !allowed {
		return nil, newConnectorError(codeInvalidRequest, domainRequest,
			"containment target is not a verified registry identity; arbitrary shell text and unverified PIDs are rejected",
			deliveryNA, retryNewIfNot, handleJSON, nil)
	}
	if strings.TrimSpace(creq.Policy.ID) == "" || !validDigest(creq.Policy.ArtifactDigest) {
		return nil, newConnectorError(codeInvalidRequest, domainRequest,
			"policy must select an installed reviewed action pin", deliveryNA, retryNewIfNot, handleJSON, nil)
	}
	if strings.TrimSpace(creq.Reason) == "" {
		return nil, newConnectorError(codeInvalidRequest, domainRequest,
			"reason is required", deliveryNA, retryNewIfNot, handleJSON, nil)
	}
	if err := authority.Authorize(ctx, "control", OpContain, creq.Target.ResourceID); err != nil {
		return nil, newConnectorError(codeForbidden, domainPolicy,
			"contain requires independent control authority for the target",
			deliveryNotDisp, retryOperator, handleJSON, nil)
	}
	_ = r
	journalID := creq.Handle.LocalHandle
	c.mu.Lock()
	h, ok := c.handles[journalID]
	if ok {
		c.containCalls = append(c.containCalls, creq)
	}
	c.mu.Unlock()
	if !ok {
		return nil, newConnectorError(codeUnknownHandle, domainRequest,
			"unknown handle", deliveryNA, retryNewIfNot, handleJSON, nil)
	}
	targetScope := creq.Target.Kind
	obs := c.controlObservation(ctx, creq.Handle, OpContain, targetScope,
		"requested", missingCapability("not_applicable", "containment uses a reviewed policy action, not a native capability"),
		"exposed", "verified target with independent authority; containment requested",
		[]string{"containment requested against a verified target under independent authority"})
	return c.journalControl(ctx, h, creq.Handle, obs)
}

func (c *Connector) controlObservation(_ context.Context, handle HandleReference, operation, targetScope, disposition string, capabilityRef any, oppState, oppRationale string, limitations []string) ControlObservation {
	seq := c.opSeq.Add(1)
	now := c.nowTimePoint()
	authRef := EvidenceRef{JournalID: handle.LocalHandle, Sequence: 1, EventID: "evt-admission", EventHash: string(evidence_codec.HashBytes([]byte("admission-" + handle.LocalHandle))), Pointer: ""}
	if limitations == nil {
		limitations = []string{}
	}
	return ControlObservation{
		ControlEventID: fmt.Sprintf("ctl-%d-%s", seq, shortHash(operation+handle.LocalHandle+fmt.Sprint(seq))),
		OperationID:    fmt.Sprintf("op-%d-%s", seq, shortHash(handle.LocalHandle+operation)),
		Operation:      operation, TargetScope: targetScope, Disposition: disposition,
		At: now, AuthorizationRef: authRef, CapabilityRef: capabilityRef,
		Opportunity: Opportunity{State: oppState, EvidenceRefs: []EvidenceRef{}, Rationale: oppRationale},
		RequestRef: map[string]any{"value": nil, "reason": "not_observed"},
		ResponseRef: map[string]any{"value": nil, "reason": "not_observed"},
		ResponseChecks: map[string]any{"value": nil, "reason": "not_observed"},
		NativeClaimRefs: []EvidenceRef{}, EffectRefs: []EvidenceRef{},
		AffectedAttempts: []any{}, Measurements: []any{}, Limitations: limitations,
	}
}

func (c *Connector) journalControl(ctx context.Context, h *handleRecord, handle HandleReference, obs ControlObservation) (json.RawMessage, *ConnectorError) {
	handleJSON := handleRaw(handle)
	h.mu.Lock()
	boundRef := h.HandleBoundRef
	h.mu.Unlock()
	if boundRef.JournalID != "" {
		obs.AuthorizationRef = boundRef
	}
	obs.NativeClaimRefs = filterSameJournal(obs.NativeClaimRefs, handle.LocalHandle)
	obs.EffectRefs = filterSameJournal(obs.EffectRefs, handle.LocalHandle)
	obs.Opportunity.EvidenceRefs = filterSameJournal(obs.Opportunity.EvidenceRefs, handle.LocalHandle)
	obs.CapabilityRef = sanitizeCapabilityRef(obs.CapabilityRef, handle.LocalHandle)
	obsBytes := mustMarshal(obs)
	obsRef, err := owner_store.InstallArtifact(ctx, c.store, bytes.NewReader(obsBytes), "application/json", "public")
	if err != nil {
		return nil, mapStoreErrorWithHandle(err, "install control observation", handleJSON)
	}
	var obsMap map[string]any
	_ = json.Unmarshal(obsBytes, &obsMap)
	if obsMap == nil {
		obsMap = map[string]any{}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	sub := EventSubmission{
		ProducerSequence: c.producerSeq.Add(1), EventKind: "control_observation",
		EventSchemaVersion: controlEventSchema, OccurredAt: c.nowTimePoint(),
		Payload: owner_store.Payload{
			Data: map[string]any{"kind": "control_observation", "observation": obsMap},
			Measurements: []owner_store.Measurement{},
			EvidenceRefs: []EvidenceRef{}, ArtifactRefs: []ArtifactReference{obsRef},
		},
	}
	envs, err := owner_store.CommitOwner(ctx, c.store, handle.LocalHandle, []EventSubmission{sub}, nil)
	if err != nil {
		return nil, mapStoreErrorWithHandle(err, "journal control observation", handleJSON)
	}
	if err := validateEnvelopes(envs); err != nil {
		return nil, mapStoreErrorWithHandle(err, "validate control envelopes", handleJSON)
	}
	last := envs[len(envs)-1]
	h.Prefix = JournalPrefix{JournalID: handle.LocalHandle, LastSequence: last.Sequence, HeadHash: last.EventHash}
	h.Envelopes = append(h.Envelopes, envs...)
	tryPublishLiveHead(h.Prefix)
	regRef := EvidenceRef{JournalID: last.JournalID, Sequence: last.Sequence, EventID: last.EventID, EventHash: last.EventHash, Pointer: ""}
	receipt := ControlReceipt{Kind: "control_receipt", Handle: handle, Observation: obs, RegistrationRef: regRef}
	return mustMarshal(receipt), nil
}

func filterSameJournal(refs []EvidenceRef, journalID string) []EvidenceRef {
	out := []EvidenceRef{}
	for _, r := range refs {
		if r.JournalID == journalID {
			out = append(out, r)
		}
	}
	return out
}

func sanitizeCapabilityRef(v any, journalID string) any {
	m, ok := v.(map[string]any)
	if !ok {
		return v
	}
	if refs, ok := m["evidence_refs"].([]EvidenceRef); ok {
		m["evidence_refs"] = filterSameJournal(refs, journalID)
		return m
	}
	return v
}

func missingCapability(reason, detail string) any {
	return map[string]any{"value": nil, "reason": reason, "detail": detail}
}

func capabilityRefFor(cap Capability, ok bool) any {
	if !ok {
		return missingCapability("not_observed", "no capability declaration for this operation")
	}
	return map[string]any{
		"capability_id": cap.ID, "availability": cap.Availability, "evidence_refs": []EvidenceRef{},
	}
}

func artifactEvidencePlaceholder(ref ArtifactReference) any {
	return map[string]any{
		"artifact_digest": ref.Digest, "size_bytes": ref.SizeBytes,
		"media_type": ref.MediaType,
	}
}

// ---------------------------------------------------------------------------
// Lifecycle best-effort (declare, never assess).
// ---------------------------------------------------------------------------

func (c *Connector) validateDispatchBestEffort(prep *preparationRecord, _ StartRequest) string {
	commission := lifecycle_rules.AttemptCommission{
		RecordType: "attempt_commission", SchemaVersion: "application-attempt-lifecycle/0.1.0",
		KernelVersion: "0.1.0", CommissionID: "commission-" + prep.ID,
		RunID: "run-1", JournalID: "journal-1",
		ManifestHash: string(evidence_codec.HashBytes([]byte("manifest"))),
		AdmissionRef: lifecycle_rules.EvidenceRef{
			JournalID: "journal-1", Sequence: 1, EventID: "evt-1",
			EventHash: string(evidence_codec.HashBytes([]byte("evt-1"))), Pointer: "",
		},
		CommissionedBy: "operator-1",
		CommissionedAt: lifecycle_rules.TimePoint{
			ClockID: "clk-1", BootID: "boot-1", Origin: "engine_measured",
			MonotonicOffsetMs: 10, UTCAnnotation: lifecycle_rules.NewMissing("not_applicable"),
		},
		IdempotencyKey: prep.ID,
	}
	next := lifecycle_rules.AxisRevision{
		RecordType: "attempt_axis_revision", SchemaVersion: "application-attempt-lifecycle/0.1.0",
		Axis: "dispatch", Revision: 1, PreviousRevision: 0,
	}
	err := lifecycle_rules.ValidateAxisTransition(commission, nil, next, []lifecycle_rules.JournalEnvelope{})
	if err != nil {
		return "lifecycle dispatch validation inconclusive: " + err.Error()
	}
	return ""
}

// ---------------------------------------------------------------------------
// Journal helpers.
// ---------------------------------------------------------------------------

func (c *Connector) storeOwnerDomain() string {
	if c.store == nil {
		return "connector"
	}
	v := reflect.ValueOf(c.store).Elem()
	f := v.FieldByName("ownerDomain")
	if f.IsValid() && f.Kind() == reflect.String {
		if s := f.String(); strings.TrimSpace(s) != "" {
			return s
		}
	}
	return "connector"
}

func (c *Connector) ensureJournal(ctx context.Context, journalID string) error {
	c.mu.Lock()
	if journalID == c.prepJournalID && c.prepPrefix != nil {
		c.mu.Unlock()
		return nil
	}
	if h, ok := c.handles[journalID]; ok {
		h.mu.Lock()
		ready := len(h.Envelopes) > 0 || h.Prefix.LastSequence > 0
		h.mu.Unlock()
		if ready {
			c.mu.Unlock()
			return nil
		}
	}
	c.mu.Unlock()
	domain := c.storeOwnerDomain()
	manifest := map[string]any{
		"record_type": manifestRecordType, "schema_version": manifestSchemaVer,
		"manifest_id": "manifest-" + journalID, "run_id": "run-" + domain,
		"journal_id": journalID, "owner_domain": domain,
		"clocks": []any{map[string]any{
			"clock_id": connectorClockID, "boot_id": connectorBootID,
			"origin": "engine_measured", "source_id": connectorClockSrc,
			"basis": "monotonic_offset", "unit": "ms",
		}},
	}
	raw, _ := json.Marshal(manifest)
	canonical, err := evidence_codec.CanonicalJSON(raw, "application/json")
	if err != nil {
		return err
	}
	ref, err := owner_store.InstallArtifact(ctx, c.store, bytes.NewReader(canonical), "application/json", "public")
	if err != nil {
		return err
	}
	sub := EventSubmission{
		ProducerSequence: c.producerSeq.Add(1), EventKind: "manifest_admitted",
		EventSchemaVersion: controlEventSchema, OccurredAt: c.nowTimePoint(),
		Payload: owner_store.Payload{
			Data: map[string]any{"manifest": map[string]any{
				"digest": ref.Digest, "size_bytes": ref.SizeBytes,
				"media_type": ref.MediaType, "owner_domain": ref.OwnerDomain, "access": ref.Access,
			}},
			Measurements: []owner_store.Measurement{},
			EvidenceRefs: []EvidenceRef{}, ArtifactRefs: []ArtifactReference{ref},
		},
	}
	envs, err := owner_store.CommitOwner(ctx, c.store, journalID, []EventSubmission{sub}, nil)
	if err != nil {
		if strings.Contains(err.Error(), "manifest_admitted appears only at sequence 1") ||
			strings.Contains(err.Error(), "already committed") {
			return nil
		}
		// Journal may already exist from a prior call; probe the head.
		return err
	}
	if err := validateEnvelopes(envs); err != nil {
		return err
	}
	return nil
}

func (c *Connector) nowTimePoint() TimePoint {
	offset := float64(c.clockOffset.Add(100))
	return TimePoint{
		ClockID: connectorClockID, BootID: connectorBootID, Origin: "engine_measured",
		MonotonicOffsetMs: offset, UTCAnnotation: MissingEnvelope{Value: nil, Reason: "not_applicable"},
	}
}

func validateEnvelopes(envs []JournalEnvelope) error {
	for i := range envs {
		raw, err := json.Marshal(envs[i])
		if err != nil {
			return err
		}
		if err := evidence_codec.ValidateRecord(envs[i].SchemaVersion, envs[i].RecordType, raw); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Shared JSON helpers.
// ---------------------------------------------------------------------------

func strictUnmarshal(raw json.RawMessage, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing data after JSON value")
		}
		return err
	}
	return nil
}

func mustMarshal(v any) json.RawMessage {
	raw, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return json.RawMessage(raw)
}

func mustCanonical(v any) []byte {
	raw, _ := json.Marshal(v)
	canonical, err := evidence_codec.CanonicalJSON(raw, "application/json")
	if err != nil {
		return raw
	}
	return canonical
}

func mustCanonicalRaw(raw []byte) []byte {
	canonical, err := evidence_codec.CanonicalJSON(raw, "application/json")
	if err != nil {
		return raw
	}
	return canonical
}

func shortHash(s string) string {
	d := string(evidence_codec.HashBytes([]byte(s)))
	h := strings.TrimPrefix(d, "sha256:")
	if len(h) > 12 {
		h = h[:12]
	}
	if h == "" {
		b := make([]byte, 6)
		_, _ = rand.Read(b)
		return hex.EncodeToString(b)
	}
	return h
}

func newConnectorError(code, domain, detail, delivery, retry string, handle json.RawMessage, refs []EvidenceRef) *ConnectorError {
	if refs == nil {
		refs = []EvidenceRef{}
	}
	if len(handle) == 0 {
		handle = missingRaw("not_applicable", "no handle was established for this failure")
	}
	return &ConnectorError{
		Kind: kindConnectorErr, Code: code, FaultDomain: domain, Detail: detail,
		OperationDelivery: delivery, RetryGuidance: retry,
		RetryAfter: missingRaw("not_applicable", "no backoff is prescribed"),
		Handle: handle, EvidenceRefs: refs,
	}
}

func respondWith(req ConnectorRequest, result json.RawMessage) ConnectorResponse {
	return ConnectorResponse{
		RecordType: RecordTypeResponse, SchemaVersion: SchemaVersion,
		RequestID: req.RequestID, ConnectorID: req.ConnectorID,
		Operation: req.Operation, Result: result,
	}
}

func missingRaw(reason, detail string) json.RawMessage {
	m := map[string]any{"value": nil, "reason": reason}
	if detail != "" {
		m["detail"] = detail
	}
	raw, _ := json.Marshal(m)
	return json.RawMessage(raw)
}

func digestRaw(digest string) json.RawMessage {
	raw, _ := json.Marshal(digest)
	return json.RawMessage(raw)
}

func handleRaw(h HandleReference) json.RawMessage {
	return mustMarshal(h)
}

func parseMissing(raw json.RawMessage) (Missing, error) {
	var m Missing
	if err := strictUnmarshal(raw, &m); err != nil {
		return Missing{}, err
	}
	if m.Value != nil {
		return Missing{}, fmt.Errorf("missing value must be null")
	}
	if !nullReasons[m.Reason] {
		return Missing{}, fmt.Errorf("missing reason %q is unknown", m.Reason)
	}
	return m, nil
}

func parseDigestOrMissing(raw json.RawMessage, field string) (string, *Missing, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return "", nil, fmt.Errorf("%s is required", field)
	}
	if trimmed[0] == '"' {
		var s string
		if err := strictUnmarshal(raw, &s); err != nil {
			return "", nil, err
		}
		if !validDigest(s) {
			return "", nil, fmt.Errorf("%s is not a digest", field)
		}
		return s, nil, nil
	}
	m, err := parseMissing(raw)
	if err != nil {
		return "", nil, err
	}
	return "", &m, nil
}

func validateHandle(h HandleReference) error {
	if strings.TrimSpace(h.ConnectorID) == "" {
		return fmt.Errorf("handle connector_id is required")
	}
	if strings.TrimSpace(h.LocalHandle) == "" {
		return fmt.Errorf("handle local_handle is required")
	}
	return nil
}

func validateJournalPrefix(p JournalPrefix) error {
	if strings.TrimSpace(p.JournalID) == "" {
		return fmt.Errorf("journal_id is required")
	}
	if p.LastSequence < 1 {
		return fmt.Errorf("last_sequence starts at 1")
	}
	if !validDigest(p.HeadHash) {
		return fmt.Errorf("head_hash is not a digest")
	}
	return nil
}

func validateEvidenceRefShape(ref EvidenceRef) error {
	if strings.TrimSpace(ref.JournalID) == "" {
		return fmt.Errorf("journal_id is required")
	}
	if ref.Sequence < 1 {
		return fmt.Errorf("sequence starts at 1")
	}
	if strings.TrimSpace(ref.EventID) == "" {
		return fmt.Errorf("event_id is required")
	}
	if !validDigest(ref.EventHash) {
		return fmt.Errorf("event_hash is not a digest")
	}
	if !validPointer(ref.Pointer) {
		return fmt.Errorf("pointer is not a JSON pointer")
	}
	return nil
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
		ch := hexPart[i]
		if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f') {
			return false
		}
	}
	return true
}

func validPointer(p string) bool {
	if p == "" {
		return true
	}
	if !strings.HasPrefix(p, "/") {
		return false
	}
	for i := 0; i < len(p); i++ {
		if p[i] == '~' {
			if i+1 >= len(p) || (p[i+1] != '0' && p[i+1] != '1') {
				return false
			}
			i++
		}
	}
	return true
}

func rejectBareNulls(v any, path string) error {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if val == nil {
				if k == "value" {
					if reason, ok := x["reason"].(string); ok && nullReasons[reason] {
						continue
					}
				}
				return fmt.Errorf("%s.%s is a bare null; use a typed Missing envelope", path, k)
			}
			if err := rejectBareNulls(val, path+"."+k); err != nil {
				return err
			}
		}
	case []any:
		for i, val := range x {
			if val == nil {
				return fmt.Errorf("%s[%d] is a bare null; use a typed Missing envelope", path, i)
			}
			if err := rejectBareNulls(val, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

func verifyPrefixEvents(cutoff JournalPrefix, events []JournalEnvelope) error {
	if len(events) == 0 {
		return fmt.Errorf("prefix has no retained events")
	}
	if events[len(events)-1].EventHash != cutoff.HeadHash {
		return fmt.Errorf("prefix head does not match retained events")
	}
	if int64(len(events)) != cutoff.LastSequence {
		return fmt.Errorf("prefix sequence does not match retained events")
	}
	for i := range events {
		raw, err := json.Marshal(events[i])
		if err != nil {
			return err
		}
		if err := evidence_codec.ValidateRecord(events[i].SchemaVersion, "journal_event", raw); err != nil {
			return err
		}
	}
	return nil
}

func mapStoreError(err error, op string) *ConnectorError {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "unauthorized") || strings.Contains(msg, "no authenticated principal"):
		return newConnectorError(codeForbidden, domainPolicy, op+": not authorized", deliveryNotDisp, retryOperator, nil, nil)
	case strings.Contains(msg, "artifact") && strings.Contains(msg, "not installed"):
		return newConnectorError(codeArtifactUnavailable, domainConnector, op+": "+firstLine(msg), deliveryNA, retryOperator, nil, nil)
	case strings.Contains(msg, "STORAGE") || strings.Contains(msg, "durable storage unavailable"):
		return newConnectorError(codeStorageUnavailable, domainEnv, op+": durable storage unavailable", deliveryMay, retrySame, nil, nil)
	case strings.Contains(msg, "integrity conflict") || strings.Contains(msg, "duplicate"):
		return newConnectorError(codeIntegrityConflict, domainConnector, op+": "+firstLine(msg), deliveryMay, retrySame, nil, nil)
	default:
		return newConnectorError(codeInternalError, domainConnector, op+": "+firstLine(msg), deliveryMay, retryOperator, nil, nil)
	}
}

func mapStoreErrorWithHandle(err error, op string, handle json.RawMessage) *ConnectorError {
	cerr := mapStoreError(err, op)
	cerr.Handle = append(json.RawMessage(nil), handle...)
	return cerr
}

func firstLine(s string) string {
	if i := strings.Index(s, "\n"); i >= 0 {
		return s[:i]
	}
	if len(s) > 300 {
		return s[:300]
	}
	return s
}

func mapLoadCode(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "unknown journal"):
		return codeUnknownHandle
	case strings.Contains(msg, "prefix") || strings.Contains(msg, "integrity"):
		return codeIntegrityConflict
	case strings.Contains(msg, "unauthorized"):
		return codeForbidden
	default:
		return codeIntegrityConflict
	}
}

func mapLoadDomain(err error) string {
	if strings.Contains(err.Error(), "unauthorized") {
		return domainPolicy
	}
	return domainConnector
}

func mapLoadDetail(op string, cutoff JournalPrefix, err error) string {
	return fmt.Sprintf("%s: cannot load prefix %s@%d: %s", op, cutoff.JournalID, cutoff.LastSequence, firstLine(err.Error()))
}

func mapLoadRetry(err error) string {
	if strings.Contains(err.Error(), "unauthorized") {
		return retryOperator
	}
	return retryOperator
}

// ---------------------------------------------------------------------------
// Cross-module converters (identical JSON, distinct Go types).
// ---------------------------------------------------------------------------

func toNativeArtifact(ref ArtifactReference) native_mapping.ArtifactReference {
	raw, _ := json.Marshal(ref)
	var out native_mapping.ArtifactReference
	_ = json.Unmarshal(raw, &out)
	return out
}

func toNativeSourceChecks(c source_verifier.SourceChecks) native_mapping.SourceChecks {
	raw, _ := json.Marshal(c)
	var out native_mapping.SourceChecks
	_ = json.Unmarshal(raw, &out)
	return out
}

func toClockTimePoint(tp TimePoint) clock_rules.TimePoint {
	raw, _ := json.Marshal(tp.UTCAnnotation)
	var ann any
	_ = json.Unmarshal(raw, &ann)
	if ann == nil {
		ann = clock_rules.Missing{Reason: "not_applicable"}
	}
	return clock_rules.TimePoint{
		ClockID: tp.ClockID, BootID: tp.BootID, Origin: tp.Origin,
		MonotonicOffsetMs: tp.MonotonicOffsetMs, UTCAnnotation: ann,
	}
}

func toJournalTimePoint(tp clock_rules.TimePoint) TimePoint {
	raw, _ := json.Marshal(tp.UTCAnnotation)
	var ann any
	_ = json.Unmarshal(raw, &ann)
	return TimePoint{
		ClockID: tp.ClockID, BootID: tp.BootID, Origin: tp.Origin,
		MonotonicOffsetMs: tp.MonotonicOffsetMs, UTCAnnotation: ann,
	}
}

func asNativeMappingError(err error) (*native_mapping.MappingError, bool) {
	if err == nil {
		return nil, false
	}
	if me, ok := err.(*native_mapping.MappingError); ok {
		return me, true
	}
	return nil, false
}

// decodeNativePrepareRequest unmarshals a JSON preparation payload into a
// native_mapping.PrepareRequest with proper Go types for every polymorphic
// `any` field. Standard JSON unmarshaling yields map[string]any for those
// fields, which native_mapping's validators reject; this converter rebuilds
// AttemptContext, ArtifactReference, EvidenceRef, VersionPin, and Missing
// values from their JSON shapes.
func decodeNativePrepareRequest(payload json.RawMessage) (native_mapping.PrepareRequest, error) {
	var req native_mapping.PrepareRequest
	if err := strictUnmarshal(payload, &req); err != nil {
		return native_mapping.PrepareRequest{}, err
	}
	var err error
	if req.Scope.Attempt, err = convertAttempt(req.Scope.Attempt); err != nil {
		return native_mapping.PrepareRequest{}, fmt.Errorf("scope.attempt: %v", err)
	}
	if req.Scope.Commission, err = convertCommission(req.Scope.Commission); err != nil {
		return native_mapping.PrepareRequest{}, fmt.Errorf("scope.commission: %v", err)
	}
	if req.Scope.CommissionRef, err = convertCommissionRef(req.Scope.CommissionRef); err != nil {
		return native_mapping.PrepareRequest{}, fmt.Errorf("scope.commission_ref: %v", err)
	}
	if req.Configuration.Subject.NativeRevision, err = convertStringOrMissing(req.Configuration.Subject.NativeRevision, "configuration.subject.native_revision"); err != nil {
		return native_mapping.PrepareRequest{}, err
	}
	if req.Task.OutputSchema, err = convertVersionPinOrMissing(req.Task.OutputSchema); err != nil {
		return native_mapping.PrepareRequest{}, fmt.Errorf("task.output_schema: %v", err)
	}
	if req.Task.ContextPolicy.BrowserState.ResourceRef, err = convertStringOrMissing(req.Task.ContextPolicy.BrowserState.ResourceRef, "task.context_policy.browser_state.resource_ref"); err != nil {
		return native_mapping.PrepareRequest{}, err
	}
	if req.Task.ContextPolicy.BrowserState.Baseline, err = convertArtifactOrMissing(req.Task.ContextPolicy.BrowserState.Baseline); err != nil {
		return native_mapping.PrepareRequest{}, fmt.Errorf("task.context_policy.browser_state.baseline: %v", err)
	}
	if req.Task.ContextPolicy.LearningState.ResourceRef, err = convertStringOrMissing(req.Task.ContextPolicy.LearningState.ResourceRef, "task.context_policy.learning_state.resource_ref"); err != nil {
		return native_mapping.PrepareRequest{}, err
	}
	if req.Task.ContextPolicy.LearningState.Baseline, err = convertArtifactOrMissing(req.Task.ContextPolicy.LearningState.Baseline); err != nil {
		return native_mapping.PrepareRequest{}, fmt.Errorf("task.context_policy.learning_state.baseline: %v", err)
	}
	for i := range req.Task.Steps {
		if req.Task.Steps[i].Value, err = convertStepValue(req.Task.Steps[i].Value); err != nil {
			return native_mapping.PrepareRequest{}, fmt.Errorf("task.steps[%d].value: %v", i, err)
		}
	}
	if req.Assistance.PlannerIdentity, err = convertStringOrMissing(req.Assistance.PlannerIdentity, "assistance.planner_identity"); err != nil {
		return native_mapping.PrepareRequest{}, err
	}
	if req.Assistance.Plan, err = convertArtifactOrMissing(req.Assistance.Plan); err != nil {
		return native_mapping.PrepareRequest{}, fmt.Errorf("assistance.plan: %v", err)
	}
	return req, nil
}

func isMissingMap(v any) bool {
	m, ok := v.(map[string]any)
	if !ok {
		return false
	}
	reason, _ := m["reason"].(string)
	if reason == "" {
		return false
	}
	if val, hasValue := m["value"]; hasValue && val != nil {
		return false
	}
	return true
}

func convertMissing(v any) (native_mapping.Missing, error) {
	raw, _ := json.Marshal(v)
	var m native_mapping.Missing
	if err := json.Unmarshal(raw, &m); err != nil {
		return native_mapping.Missing{}, err
	}
	return m, nil
}

func convertAttempt(v any) (any, error) {
	switch t := v.(type) {
	case native_mapping.AttemptContext, *native_mapping.AttemptContext, native_mapping.Missing, *native_mapping.Missing:
		return v, nil
	case map[string]any:
		if isMissingMap(t) {
			return convertMissing(t)
		}
		raw, _ := json.Marshal(t)
		var out native_mapping.AttemptContext
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, err
		}
		return out, nil
	default:
		return v, nil
	}
}

func convertCommission(v any) (any, error) {
	switch t := v.(type) {
	case native_mapping.ArtifactReference, *native_mapping.ArtifactReference, native_mapping.Missing, *native_mapping.Missing:
		return v, nil
	case map[string]any:
		if isMissingMap(t) {
			return convertMissing(t)
		}
		raw, _ := json.Marshal(t)
		var out native_mapping.ArtifactReference
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, err
		}
		return out, nil
	default:
		return v, nil
	}
}

func convertCommissionRef(v any) (any, error) {
	switch t := v.(type) {
	case native_mapping.EvidenceRef, *native_mapping.EvidenceRef, native_mapping.Missing, *native_mapping.Missing:
		return v, nil
	case map[string]any:
		if isMissingMap(t) {
			return convertMissing(t)
		}
		raw, _ := json.Marshal(t)
		var out native_mapping.EvidenceRef
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, err
		}
		return out, nil
	default:
		return v, nil
	}
}

func convertStringOrMissing(v any, field string) (any, error) {
	switch t := v.(type) {
	case nil:
		return nil, fmt.Errorf("%s must not be an in-band null", field)
	case string, native_mapping.Missing, *native_mapping.Missing:
		return v, nil
	case map[string]any:
		if isMissingMap(t) {
			return convertMissing(t)
		}
		return nil, fmt.Errorf("%s must be an identifier or Missing", field)
	default:
		return nil, fmt.Errorf("%s must be an identifier or Missing", field)
	}
}

func convertArtifactOrMissing(v any) (any, error) {
	switch t := v.(type) {
	case native_mapping.ArtifactReference, *native_mapping.ArtifactReference, native_mapping.Missing, *native_mapping.Missing:
		return v, nil
	case map[string]any:
		if isMissingMap(t) {
			return convertMissing(t)
		}
		raw, _ := json.Marshal(t)
		var out native_mapping.ArtifactReference
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, err
		}
		return out, nil
	default:
		return v, nil
	}
}

func convertVersionPinOrMissing(v any) (any, error) {
	switch t := v.(type) {
	case native_mapping.VersionPin, *native_mapping.VersionPin, native_mapping.Missing, *native_mapping.Missing:
		return v, nil
	case map[string]any:
		if isMissingMap(t) {
			return convertMissing(t)
		}
		raw, _ := json.Marshal(t)
		var out native_mapping.VersionPin
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, err
		}
		return out, nil
	default:
		return v, nil
	}
}

func convertStepValue(v any) (any, error) {
	if v == nil {
		return nil, fmt.Errorf("must not be an in-band null")
	}
	if m, ok := v.(map[string]any); ok && isMissingMap(m) {
		return convertMissing(m)
	}
	return v, nil
}

// lowercaseMissingDetail renames native_mapping's capital-D "Detail" Missing
// field to the kernel lowercase "detail" so journaled claims pass the
// evidence_codec structural gate.
func lowercaseMissingDetail(v any) {
	switch x := v.(type) {
	case map[string]any:
		if d, hasDetail := x["Detail"]; hasDetail {
			if _, hasLower := x["detail"]; !hasLower {
				x["detail"] = d
			}
			delete(x, "Detail")
		}
		for _, val := range x {
			lowercaseMissingDetail(val)
		}
	case []any:
		for _, val := range x {
			lowercaseMissingDetail(val)
		}
	}
}

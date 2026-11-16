// Package connector_queries implements the tier-4 Hellscape external
// connector read projections: Observe (journal-backed observation pages)
// and CollectArtifacts (retained artifact inventory and byte transfer).
//
// Seam reference: seam-mappings/hellscape-seam-mapping.md sections 8.9
// (Observe), 8.10 (ObservationItem alternatives), and 8.13 (artifact
// transfer), plus contracts/02-external-connector.yaml (ObserveRequest,
// ObservationPage, CollectArtifactsRequest, ArtifactInventory,
// ArtifactChunk, ConnectorError).
//
// Semantic boundaries enforced here:
//
//   - Observe returns registered connector observation projections in
//     journal order for exactly the requested handle. The cursor is a
//     scanned journal position, including positions holding
//     non-observation events; it never claims every entry is an
//     observation, and it is never treated as a producer terminal
//     sequence (EXT-OBSERVE, EK-OBSERVATION).
//   - Every projected item copies an already journaled,
//     registry-validated event. Item metadata equals the envelope, the
//     payload equals the registered payload data, and every cited
//     support reference resolves inside the page cutoff via
//     journal_rules.ResolveEvidence. Nested claims and artifact slots
//     cite earlier supporting events, never themselves.
//     Unjournaled projections and provenance upgrades are refused
//     (EXT-EVIDENCE).
//   - Artifact bytes resolve only within the authorized handle's
//     retained evidence: a bytes request must name a digest already
//     registered in the handle journal through the cutoff before any
//     store read is attempted. No arbitrary caller URL or filesystem
//     path is ever fetched, no workflow action is rerun, and no
//     session is created by collection (EXT-ARTIFACTS, EK-ARTIFACTS).
//   - Collecting calls are idempotent under (connector_id, request_id):
//     an identical retry returns the retained receipt bytes without
//     another effect, and conflicting content under that key is
//     rejected with IDEMPOTENCY_CONFLICT. A recorded receipt never
//     changes when newer artifacts arrive. Observe is a read call
//     whose responses may reflect newer evidence (EXT-IDEMPOTENCY).
//
// Handle binding and live cutoffs:
//
//   - A handle's observation journal is the journal whose ID equals the
//     handle's local_handle. Observe verifies that the request handle,
//     the cursor handle, and the cursor/cutoff journal IDs all agree;
//     CollectArtifacts resolves the journal from the request handle.
//   - owner_store exposes prefix loads but no journal-head discovery,
//     so a live cutoff (through: Missing/not_applicable) resolves to
//     the freshest head published for that journal via PublishLiveHead
//     (every successful explicit-prefix load also refreshes it). Each
//     cached head is revalidated with LoadPrefix before use, so a
//     stale or foreign entry can only pin the page to an older
//     verified prefix or fail explicitly; it can never fabricate
//     evidence. Without a published head, a live request fails with
//     PREREQUISITE_UNAVAILABLE rather than guessing.
//
// This module performs no shared-database writes and no cross-domain
// transactions: both entry points are read-only against the OwnerStore.
// It issues no native traffic and defines no native polling,
// cancellation, or revision endpoint.
package connector_queries

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"regexp"
	"sort"
	"strings"
	"sync"

	evidence_codec "evidence_codec"
	journal_rules "journal_rules"
	owner_store "owner_store"
)

// Shared kernel types are aliased so callers use the same kernels this
// module consumes: owner_store for the durable boundary, journal_rules
// for envelopes/prefixes/references, evidence_codec for digests.
type (
	// OwnerStore is one owner-local durable boundary: one SQLite
	// database plus one content-addressed artifact root.
	OwnerStore = owner_store.OwnerStore
	// JournalEnvelope is the complete stored journal event envelope.
	JournalEnvelope = journal_rules.JournalEnvelope
	// JournalPrefix is an immutable journal prefix.
	JournalPrefix = journal_rules.JournalPrefix
	// EvidenceRef cites one retained journal event coordinate.
	EvidenceRef = journal_rules.EvidenceRef
	// ArtifactReference is an immutable byte identity plus metadata.
	ArtifactReference = journal_rules.ArtifactReference
	// Digest is the shared content digest form.
	Digest = evidence_codec.Digest
	// MissingEnvelope is the typed EK Missing value.
	MissingEnvelope = journal_rules.MissingEnvelope
	// TimePoint is a coordinate in a registered monotonic clock.
	TimePoint = journal_rules.TimePoint
	// Measurement is the EK Measurement record carried in payloads.
	Measurement = journal_rules.Measurement
)

// Envelope and operation constants (contract 02-external-connector).
const (
	// RecordTypeRequest is the required record_type of every request.
	RecordTypeRequest = "connector_request"
	// RecordTypeResponse is the required record_type of every reply.
	RecordTypeResponse = "connector_response"
	// SchemaVersion pins the shared external-connector contract version.
	SchemaVersion = "external-connector/0.1.0"
	// OpObserve reads accumulated journal-backed observations.
	OpObserve = "Observe"
	// OpCollectArtifacts enumerates or transfers retained artifacts.
	OpCollectArtifacts = "CollectArtifacts"
)

// Result discriminators.
const (
	kindObservationPage   = "observation_page"
	kindArtifactInventory = "artifact_inventory"
	kindArtifactChunk     = "artifact_chunk"
	kindConnectorError    = "connector_error"
)

// Local finite bounds (EXT-BOUNDS). The descriptor may impose tighter
// limits; this module never exceeds these.
const (
	// MaxCallLimitMs caps the local call allowance a caller may request.
	MaxCallLimitMs = 300_000
	// MaxObserveItems caps one Observe request's max_items.
	MaxObserveItems = 1000
	// MaxObserveResponseBytes caps the canonical bytes of one projected
	// observation item. A single item above this bound fails the page
	// with RESPONSE_TOO_LARGE rather than being silently dropped.
	MaxObserveResponseBytes = 64 << 10
	// MaxChunkBytes caps one artifact chunk payload.
	MaxChunkBytes = 1 << 20
	// MaxNamedArtifacts caps one named artifact request's name count.
	MaxNamedArtifacts = 500
	// MaxIdempotencyEntries caps the retained Collect receipt cache.
	MaxIdempotencyEntries = 4096
)

// Connector error codes (seam 8.14 wire values).
const (
	codeInvalidRequest          = "INVALID_REQUEST"
	codeUnsupportedVersion      = "UNSUPPORTED_VERSION"
	codeForbidden               = "FORBIDDEN"
	codeUnknownHandle           = "UNKNOWN_HANDLE"
	codeIdempotencyConflict     = "IDEMPOTENCY_CONFLICT"
	codePrerequisiteUnavailable = "PREREQUISITE_UNAVAILABLE"
	codeBudgetExceeded          = "BUDGET_EXCEEDED"
	codeStorageUnavailable      = "STORAGE_UNAVAILABLE"
	codeCursorInvalid           = "CURSOR_INVALID"
	codeCursorUnavailable       = "CURSOR_UNAVAILABLE"
	codeObservationLost         = "OBSERVATION_LOST"
	codeResponseTooLarge        = "RESPONSE_TOO_LARGE"
	codeArtifactUnavailable     = "ARTIFACT_UNAVAILABLE"
	codeIntegrityConflict       = "INTEGRITY_CONFLICT"
	codeInternalError           = "INTERNAL_ERROR"
)

// Fault domains, delivery states, and retry guidance (seam 8.14).
const (
	domainRequest     = "request"
	domainConnector   = "connector"
	domainEnvironment = "environment"
	domainPolicy      = "policy"
	domainUnknown     = "unknown"

	deliveryNotDispatched = "not_dispatched"
	deliveryNotApplicable = "not_applicable"

	retrySameCommandOnly           = "same_command_only"
	retryNewCommandIfNotDispatched = "new_command_if_not_dispatched"
	retryOperatorReview            = "operator_review"
	retryDoNotRetry                = "do_not_retry"
)

// EK NullReason values (seam 3.1).
var nullReasons = map[string]bool{
	"not_enabled": true, "not_applicable": true, "not_observed": true,
	"observation_lost": true, "unsupported_by_subject": true, "manual_override": true,
}

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var pointerPattern = regexp.MustCompile(`^(?:/(?:[^~/]|~[01])*)*$`)

// observationKinds maps journal event kinds carrying connector
// observations to their ObservationPayload discriminator. Every other
// event kind is a non-observation position: skipped for items but still
// advancing the scanned cursor.
var observationKinds = map[string]string{
	"native_report":         "native_report",
	"context_observation":   "context_observation",
	"task_output":           "task_output",
	"connector_incident":    "connector_incident",
	"control_observation":   "control_observation",
	"lifecycle_publication": "lifecycle_publication",
	"artifact_available":    "artifact_available",
	"clock_registered":      "clock_registered",
}

// observationRequiredKeys lists the closed top-level payload.data keys
// per observation kind (including "kind" itself). Projection refuses
// retained events whose registered data violates the closed shape.
var observationRequiredKeys = map[string][]string{
	"native_report": {
		"kind", "channel", "raw", "source_event", "source_checks",
		"mapping", "normalized_claims", "limitations",
	},
	"context_observation": {
		"kind", "domain", "requested_policy_ref", "realization",
		"context_ref", "evidence_refs", "limitations",
	},
	"task_output": {
		"kind", "name", "output_schema", "content", "completeness",
		"evidence_refs", "limitations",
	},
	"connector_incident":    {"kind", "code", "scope", "detail", "evidence_refs"},
	"control_observation":   {"kind", "observation"},
	"lifecycle_publication": {"kind", "publication"},
	"artifact_available":    {"kind", "artifact"},
	"clock_registered":      {"kind", "clock_id", "boot_id", "origin", "source_id", "basis", "unit"},
}

// closureKinds are non-observation event kinds recording locally
// observed observation closure. They never imply native termination.
var closureKinds = map[string]bool{
	"observation_closed": true,
	"observation_close":  true,
}

var validProvenance = map[string]bool{
	"server": true, "fixture_client": true, "connector": true,
	"subject": true, "manual_observer": true, "importer": true,
}

// ---------------------------------------------------------------------------
// Wire types.
// ---------------------------------------------------------------------------

// DurationLimit is a finite configured allowance, never an elapsed
// measurement or a native guarantee.
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

// ConnectorResponse is one correlated connector reply. It establishes
// only completion of this connector call.
type ConnectorResponse struct {
	RecordType    string          `json:"record_type"`
	SchemaVersion string          `json:"schema_version"`
	RequestID     string          `json:"request_id"`
	ConnectorID   string          `json:"connector_id"`
	Operation     string          `json:"operation"`
	Result        json.RawMessage `json:"result"`
}

// HandleReference is the stable local handle identity.
type HandleReference struct {
	ConnectorID string `json:"connector_id"`
	LocalHandle string `json:"local_handle"`
}

// ObservationCursor identifies a scanned journal position. Zero begins
// before admission and carries an inapplicable hash; positive positions
// verify against the retained journal.
type ObservationCursor struct {
	Handle    HandleReference `json:"handle"`
	JournalID string          `json:"journal_id"`
	Sequence  int64           `json:"sequence"`
	EventHash json.RawMessage `json:"event_hash"`
}

// ObserveRequest reads accumulated observations through an explicit
// prefix. Through is either a JournalPrefix (frozen pagination) or a
// Missing/not_applicable envelope (new live cutoff).
type ObserveRequest struct {
	Handle    HandleReference   `json:"handle"`
	After     ObservationCursor `json:"after"`
	Through   json.RawMessage   `json:"through"`
	MaxItems  int64             `json:"max_items"`
	WaitLimit DurationLimit     `json:"wait_limit"`
}

// MeasurementEvidence pairs one journaled measurement with the
// supporting event reference.
type MeasurementEvidence struct {
	Measurement  Measurement   `json:"measurement"`
	EvidenceRefs []EvidenceRef `json:"evidence_refs"`
}

// ObservationItem is a read projection of one journaled observation
// event: metadata equals the envelope and payload equals the
// registered payload data.
type ObservationItem struct {
	EventRef     EvidenceRef           `json:"event_ref"`
	RecordedAt   TimePoint             `json:"recorded_at"`
	Provenance   string                `json:"provenance"`
	Payload      map[string]any        `json:"payload"`
	Measurements []MeasurementEvidence `json:"measurements"`
	ArtifactRefs []ArtifactReference   `json:"artifact_refs"`
}

// ObservationPage is one bounded observation window. ObservationCloseRef
// is an EvidenceRef for locally observed closure at this cutoff, or a
// Missing/not_observed envelope; it never states native termination.
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

// ArtifactSelector selects inventory, named artifacts, or bytes by
// digest/offset/max bytes. It carries no URL or filesystem path.
type ArtifactSelector struct {
	Mode     string   `json:"mode"`
	Names    []string `json:"names,omitempty"`
	Digest   string   `json:"digest,omitempty"`
	Offset   int64    `json:"offset"`
	MaxBytes int64    `json:"max_bytes"`
	// hasOffset/hasMaxBytes record field presence for bytes mode.
	hasOffset   bool
	hasMaxBytes bool
}

// UnmarshalJSON strictly decodes one selector and enforces the
// per-mode closed field sets.
func (s *ArtifactSelector) UnmarshalJSON(raw []byte) error {
	var fields map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&fields); err != nil {
		return fmt.Errorf("selector must be an object: %v", err)
	}
	modeRaw, ok := fields["mode"]
	if !ok {
		return fmt.Errorf("selector is missing required field \"mode\"")
	}
	var mode string
	if err := strictUnmarshal(modeRaw, &mode); err != nil {
		return fmt.Errorf("selector mode: %v", err)
	}
	allowed := map[string]bool{"mode": true}
	switch mode {
	case "inventory":
	case "named":
		allowed["names"] = true
	case "bytes":
		allowed["digest"] = true
		allowed["offset"] = true
		allowed["max_bytes"] = true
	default:
		return fmt.Errorf("selector mode %q is not inventory, named, or bytes", mode)
	}
	for k := range fields {
		if !allowed[k] {
			return fmt.Errorf("selector mode %q has no field %q", mode, k)
		}
	}
	type shadow struct {
		Mode     string   `json:"mode"`
		Names    []string `json:"names"`
		Digest   string   `json:"digest"`
		Offset   int64    `json:"offset"`
		MaxBytes int64    `json:"max_bytes"`
	}
	var sh shadow
	if err := strictUnmarshal(raw, &sh); err != nil {
		return err
	}
	s.Mode = sh.Mode
	s.Names = sh.Names
	s.Digest = sh.Digest
	s.Offset = sh.Offset
	s.MaxBytes = sh.MaxBytes
	_, s.hasOffset = fields["offset"]
	_, s.hasMaxBytes = fields["max_bytes"]
	return nil
}

// CollectArtifactsRequest enumerates or transfers retained artifacts.
type CollectArtifactsRequest struct {
	Handle   HandleReference  `json:"handle"`
	Selector ArtifactSelector `json:"selector"`
}

// ArtifactSlot binds one artifact name to its expected and available
// content plus supporting evidence.
type ArtifactSlot struct {
	Name           string          `json:"name"`
	ExpectedDigest json.RawMessage `json:"expected_digest"`
	Content        json.RawMessage `json:"content"`
	EvidenceRefs   []EvidenceRef   `json:"evidence_refs"`
}

// ArtifactInventory lists artifact slots scoped to an evidence prefix.
type ArtifactInventory struct {
	Kind           string          `json:"kind"`
	Handle         HandleReference `json:"handle"`
	Artifacts      []ArtifactSlot  `json:"artifacts"`
	Coverage       string          `json:"coverage"`
	EvidencePrefix JournalPrefix   `json:"evidence_prefix"`
	Limitations    []string        `json:"limitations"`
}

// ArtifactChunk carries one verified byte window of a retained artifact.
type ArtifactChunk struct {
	Kind          string          `json:"kind"`
	Handle        HandleReference `json:"handle"`
	Digest        string          `json:"digest"`
	SizeBytes     int64           `json:"size_bytes"`
	Offset        int64           `json:"offset"`
	ReturnedBytes int64           `json:"returned_bytes"`
	DataBase64    string          `json:"data_base64"`
	ChunkDigest   string          `json:"chunk_digest"`
	EndOfArtifact bool            `json:"end_of_artifact"`
	EvidenceRefs  []EvidenceRef   `json:"evidence_refs"`
}

// Missing is a typed EK Missing envelope. Absent values are never
// rendered as in-band nulls.
type Missing struct {
	Value  any    `json:"value"`
	Reason string `json:"reason"`
	Detail string `json:"detail,omitempty"`
}

// ConnectorError describes failure to carry out this connector
// operation only. It never states a composite task outcome, an
// application commitment, or a native termination.
type ConnectorError struct {
	Kind              string          `json:"kind"`
	Code              string          `json:"code"`
	FaultDomain       string          `json:"fault_domain"`
	Detail            string          `json:"detail"`
	OperationDelivery string          `json:"operation_delivery"`
	RetryGuidance     string          `json:"retry_guidance"`
	RetryAfter        json.RawMessage `json:"retry_after"`
	Handle            json.RawMessage `json:"handle"`
	EvidenceRefs      []EvidenceRef   `json:"evidence_refs"`
}

// Error renders the typed failure without asserting any task outcome.
func (e *ConnectorError) Error() string {
	if e == nil {
		return "connector <nil>"
	}
	return fmt.Sprintf("connector %s: %s (delivery %s)", e.Code, e.Detail, e.OperationDelivery)
}

// ---------------------------------------------------------------------------
// Process-local live-head and idempotency state.
// ---------------------------------------------------------------------------

var liveHeadsMu sync.RWMutex
var liveHeads = map[string]JournalPrefix{}

// PublishLiveHead publishes the freshest verified journal head known to
// the caller for live-cutoff Observe requests and CollectArtifacts
// journal resolution. Only the newest sequence per journal is kept.
// Every cached head is revalidated with LoadPrefix before use.
func PublishLiveHead(prefix JournalPrefix) error {
	if strings.TrimSpace(prefix.JournalID) == "" {
		return fmt.Errorf("connector_queries: live head journal_id is required")
	}
	if prefix.LastSequence < 1 {
		return fmt.Errorf("connector_queries: live head last_sequence starts at 1")
	}
	if !digestPattern.MatchString(prefix.HeadHash) {
		return fmt.Errorf("connector_queries: live head hash is not a digest")
	}
	liveHeadsMu.Lock()
	defer liveHeadsMu.Unlock()
	if cur, ok := liveHeads[prefix.JournalID]; !ok || prefix.LastSequence > cur.LastSequence {
		liveHeads[prefix.JournalID] = prefix
	}
	return nil
}

func lookupLiveHead(journalID string) (JournalPrefix, bool) {
	liveHeadsMu.RLock()
	defer liveHeadsMu.RUnlock()
	p, ok := liveHeads[journalID]
	return p, ok
}

func noteVerifiedHead(prefix JournalPrefix) {
	liveHeadsMu.Lock()
	defer liveHeadsMu.Unlock()
	if cur, ok := liveHeads[prefix.JournalID]; !ok || prefix.LastSequence > cur.LastSequence {
		liveHeads[prefix.JournalID] = prefix
	}
}

type collectReceipt struct {
	requestHash string
	response    ConnectorResponse
}

var collectMu sync.Mutex
var collectReceipts = map[string]collectReceipt{}
var collectOrder []string

func lookupCollectReceipt(key string) (collectReceipt, bool) {
	collectMu.Lock()
	defer collectMu.Unlock()
	r, ok := collectReceipts[key]
	return r, ok
}

func storeCollectReceipt(key string, receipt collectReceipt) {
	collectMu.Lock()
	defer collectMu.Unlock()
	if _, ok := collectReceipts[key]; !ok {
		collectOrder = append(collectOrder, key)
		for len(collectOrder) > MaxIdempotencyEntries {
			oldest := collectOrder[0]
			collectOrder = collectOrder[1:]
			delete(collectReceipts, oldest)
		}
	}
	collectReceipts[key] = receipt
}

// ---------------------------------------------------------------------------
// Small encoding helpers.
// ---------------------------------------------------------------------------

func strictUnmarshal(raw json.RawMessage, v any) error {
	if len(bytes.TrimSpace(raw)) == 0 {
		return fmt.Errorf("missing value")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing data after value")
		}
		return err
	}
	return nil
}

func mustMarshal(v any) json.RawMessage {
	raw, err := json.Marshal(v)
	if err != nil {
		// Callers only marshal closed wire structs with no unmarshalable
		// values; a failure here is a programming error.
		panic(fmt.Sprintf("connector_queries: marshal wire value: %v", err))
	}
	return raw
}

func missingRaw(reason, detail string) json.RawMessage {
	return mustMarshal(Missing{Value: nil, Reason: reason, Detail: detail})
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
		return Missing{}, fmt.Errorf("missing reason %q is not an EK NullReason", m.Reason)
	}
	return m, nil
}

// parseDigestOrMissing decodes a MaybeDigest wire value.
func parseDigestOrMissing(raw json.RawMessage, field string) (string, *Missing, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return "", nil, fmt.Errorf("%s is required", field)
	}
	if trimmed[0] == '"' {
		var s string
		if err := strictUnmarshal(raw, &s); err != nil {
			return "", nil, fmt.Errorf("%s: %v", field, err)
		}
		if !digestPattern.MatchString(s) {
			return "", nil, fmt.Errorf("%s is not a digest", field)
		}
		return s, nil, nil
	}
	if trimmed[0] == '{' {
		m, err := parseMissing(raw)
		if err != nil {
			return "", nil, fmt.Errorf("%s: %v", field, err)
		}
		return "", &m, nil
	}
	return "", nil, fmt.Errorf("%s must be a digest or a Missing envelope", field)
}

func newConnectorError(code, domain, detail, delivery, retry string, handle json.RawMessage, refs []EvidenceRef) *ConnectorError {
	if refs == nil {
		refs = []EvidenceRef{}
	}
	if len(handle) == 0 {
		handle = missingRaw("not_applicable", "no handle was established for this failure")
	}
	return &ConnectorError{
		Kind:              kindConnectorError,
		Code:              code,
		FaultDomain:       domain,
		Detail:            detail,
		OperationDelivery: delivery,
		RetryGuidance:     retry,
		RetryAfter:        missingRaw("not_applicable", "no backoff is prescribed"),
		Handle:            handle,
		EvidenceRefs:      refs,
	}
}

func respondWith(req ConnectorRequest, result json.RawMessage) ConnectorResponse {
	return ConnectorResponse{
		RecordType:    RecordTypeResponse,
		SchemaVersion: SchemaVersion,
		RequestID:     req.RequestID,
		ConnectorID:   req.ConnectorID,
		Operation:     req.Operation,
		Result:        result,
	}
}

// fail builds a correlated ConnectorResponse carrying the typed error
// and returns it alongside the error itself, so callers may inspect
// either the envelope or the Go error.
func fail(req ConnectorRequest, code, domain, detail, delivery, retry string, handle json.RawMessage, refs []EvidenceRef) (ConnectorResponse, error) {
	cerr := newConnectorError(code, domain, detail, delivery, retry, handle, refs)
	return respondWith(req, mustMarshal(cerr)), cerr
}

// ---------------------------------------------------------------------------
// Shared request validation.
// ---------------------------------------------------------------------------

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

func validateHandle(h HandleReference) error {
	if strings.TrimSpace(h.ConnectorID) == "" {
		return fmt.Errorf("handle connector_id is required")
	}
	if strings.TrimSpace(h.LocalHandle) == "" {
		return fmt.Errorf("handle local_handle is required")
	}
	return nil
}

// validateEnvelope checks the task-shaped envelope common to both verbs.
func validateEnvelope(req ConnectorRequest, operation string) *ConnectorError {
	if req.RecordType != RecordTypeRequest {
		return newConnectorError(codeInvalidRequest, domainRequest,
			"record_type must be connector_request", deliveryNotApplicable,
			retryNewCommandIfNotDispatched, nil, nil)
	}
	if req.SchemaVersion != SchemaVersion {
		return newConnectorError(codeUnsupportedVersion, domainRequest,
			fmt.Sprintf("schema_version must be %s", SchemaVersion), deliveryNotApplicable,
			retryNewCommandIfNotDispatched, nil, nil)
	}
	if strings.TrimSpace(req.RequestID) == "" {
		return newConnectorError(codeInvalidRequest, domainRequest,
			"request_id is required", deliveryNotApplicable,
			retryNewCommandIfNotDispatched, nil, nil)
	}
	if strings.TrimSpace(req.ConnectorID) == "" {
		return newConnectorError(codeInvalidRequest, domainRequest,
			"connector_id is required", deliveryNotApplicable,
			retryNewCommandIfNotDispatched, nil, nil)
	}
	if req.Operation != operation {
		return newConnectorError(codeInvalidRequest, domainRequest,
			fmt.Sprintf("operation must be %s for this call", operation), deliveryNotApplicable,
			retryNewCommandIfNotDispatched, nil, nil)
	}
	if err := validateDurationLimit(req.CallLimit, "call_limit"); err != nil {
		return newConnectorError(codeInvalidRequest, domainRequest,
			err.Error(), deliveryNotApplicable, retryNewCommandIfNotDispatched, nil, nil)
	}
	if req.CallLimit.Value > MaxCallLimitMs {
		return newConnectorError(codeBudgetExceeded, domainRequest,
			fmt.Sprintf("call_limit value exceeds the %d ms local bound", MaxCallLimitMs),
			deliveryNotApplicable, retryNewCommandIfNotDispatched, nil, nil)
	}
	trimmed := bytes.TrimSpace(req.Payload)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return newConnectorError(codeInvalidRequest, domainRequest,
			"payload must be an object", deliveryNotApplicable,
			retryNewCommandIfNotDispatched, nil, nil)
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
	if !digestPattern.MatchString(p.HeadHash) {
		return fmt.Errorf("head_hash is not a digest")
	}
	return nil
}

func validPointer(p string) bool {
	return pointerPattern.MatchString(p)
}

func validateEvidenceRef(ref EvidenceRef) error {
	if strings.TrimSpace(ref.JournalID) == "" {
		return fmt.Errorf("evidence ref journal_id is required")
	}
	if ref.Sequence < 1 {
		return fmt.Errorf("evidence ref sequence starts at 1")
	}
	if strings.TrimSpace(ref.EventID) == "" {
		return fmt.Errorf("evidence ref event_id is required")
	}
	if !digestPattern.MatchString(ref.EventHash) {
		return fmt.Errorf("evidence ref event_hash is not a digest")
	}
	if !validPointer(ref.Pointer) {
		return fmt.Errorf("evidence ref pointer is not a JSON pointer")
	}
	return nil
}

func validateArtifactRef(ref ArtifactReference) error {
	if !digestPattern.MatchString(ref.Digest) {
		return fmt.Errorf("artifact digest is not a digest")
	}
	if ref.SizeBytes < 0 {
		return fmt.Errorf("artifact size_bytes must not be negative")
	}
	if strings.TrimSpace(ref.MediaType) == "" {
		return fmt.Errorf("artifact media_type is required")
	}
	if strings.TrimSpace(ref.OwnerDomain) == "" {
		return fmt.Errorf("artifact owner_domain is required")
	}
	if ref.Access != "public" && ref.Access != "restricted" {
		return fmt.Errorf("artifact access must be public or restricted")
	}
	return nil
}

// evidenceRefFromAny strictly parses one EvidenceRef from journal data.
func evidenceRefFromAny(v any, field string) (EvidenceRef, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return EvidenceRef{}, fmt.Errorf("%s is not an evidence reference: %v", field, err)
	}
	var ref EvidenceRef
	if err := strictUnmarshal(raw, &ref); err != nil {
		return EvidenceRef{}, fmt.Errorf("%s is not an evidence reference: %v", field, err)
	}
	if err := validateEvidenceRef(ref); err != nil {
		return EvidenceRef{}, fmt.Errorf("%s: %v", field, err)
	}
	return ref, nil
}

// artifactRefFromAny strictly parses one ArtifactReference from data.
func artifactRefFromAny(v any, field string) (ArtifactReference, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return ArtifactReference{}, fmt.Errorf("%s is not an artifact reference: %v", field, err)
	}
	var ref ArtifactReference
	if err := strictUnmarshal(raw, &ref); err != nil {
		return ArtifactReference{}, fmt.Errorf("%s is not an artifact reference: %v", field, err)
	}
	if err := validateArtifactRef(ref); err != nil {
		return ArtifactReference{}, fmt.Errorf("%s: %v", field, err)
	}
	return ref, nil
}

func looksLikeArtifactRef(m map[string]any) bool {
	for _, k := range []string{"digest", "size_bytes", "media_type", "owner_domain", "access"} {
		if _, ok := m[k]; !ok {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Retained-envelope verification and support resolution.
// ---------------------------------------------------------------------------

// verifyRetainedEnvelopes revalidates every retained envelope through
// the shared structural gates before any projection copies its metadata.
func verifyRetainedEnvelopes(cutoff JournalPrefix, events []JournalEnvelope) error {
	if int64(len(events)) != cutoff.LastSequence {
		return fmt.Errorf("prefix ends at %d, retained events: %d", cutoff.LastSequence, len(events))
	}
	for i := range events {
		raw, err := json.Marshal(events[i])
		if err != nil {
			return fmt.Errorf("sequence %d: cannot encode retained event: %v", events[i].Sequence, err)
		}
		if err := evidence_codec.ValidateRecord(events[i].SchemaVersion, "journal_event", raw); err != nil {
			return fmt.Errorf("sequence %d: retained event structural gate: %v", events[i].Sequence, err)
		}
	}
	return nil
}

// resolveSupport verifies that one cited support reference resolves
// inside the cutoff prefix.
func resolveSupport(cutoff JournalPrefix, events []JournalEnvelope, ref EvidenceRef) error {
	if err := validateEvidenceRef(ref); err != nil {
		return err
	}
	if _, err := journal_rules.ResolveEvidence(cutoff, events, ref); err != nil {
		return err
	}
	return nil
}

// nestedEvidenceRefs extracts the kind-specific cited support references
// from one observation payload data object.
func nestedEvidenceRefs(payloadKind string, data map[string]any) ([]EvidenceRef, error) {
	var out []EvidenceRef
	single := func(value any, field string) error {
		if value == nil {
			return fmt.Errorf("%s is required", field)
		}
		ref, err := evidenceRefFromAny(value, field)
		if err != nil {
			return err
		}
		out = append(out, ref)
		return nil
	}
	array := func(value any, field string) error {
		if value == nil {
			return fmt.Errorf("%s is required", field)
		}
		items, ok := value.([]any)
		if !ok {
			return fmt.Errorf("%s must be an array", field)
		}
		for i, item := range items {
			ref, err := evidenceRefFromAny(item, fmt.Sprintf("%s[%d]", field, i))
			if err != nil {
				return err
			}
			out = append(out, ref)
		}
		return nil
	}
	switch payloadKind {
	case "native_report":
		if err := single(data["source_event"], "source_event"); err != nil {
			return nil, err
		}
	case "context_observation":
		if err := single(data["requested_policy_ref"], "requested_policy_ref"); err != nil {
			return nil, err
		}
		if err := array(data["evidence_refs"], "evidence_refs"); err != nil {
			return nil, err
		}
	case "task_output":
		if err := array(data["evidence_refs"], "evidence_refs"); err != nil {
			return nil, err
		}
	case "connector_incident":
		if err := array(data["evidence_refs"], "evidence_refs"); err != nil {
			return nil, err
		}
	case "lifecycle_publication":
		pub, ok := data["publication"].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("publication must be an object")
		}
		reg, ok := pub["registration_ref"]
		if !ok {
			return nil, fmt.Errorf("publication.registration_ref is required")
		}
		ref, err := evidenceRefFromAny(reg, "publication.registration_ref")
		if err != nil {
			return nil, err
		}
		out = append(out, ref)
	case "artifact_available":
		slot, ok := data["artifact"].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("artifact must be an object")
		}
		refs, ok := slot["evidence_refs"]
		if !ok {
			return nil, fmt.Errorf("artifact.evidence_refs is required")
		}
		if err := array(refs, "artifact.evidence_refs"); err != nil {
			return nil, err
		}
	case "control_observation", "clock_registered":
		// Support travels in the envelope evidence_refs; the carried
		// record is opaque to citation extraction.
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Observation projection.
// ---------------------------------------------------------------------------

// projectObservationItem copies one journaled observation event into its
// connector projection. Metadata equals the envelope and payload equals
// the registered payload data; nothing is upgraded or invented.
func projectObservationItem(cutoff JournalPrefix, events []JournalEnvelope, env JournalEnvelope) (ObservationItem, error) {
	payloadKind, ok := observationKinds[env.EventKind]
	if !ok {
		return ObservationItem{}, fmt.Errorf("event kind %q is not an observation kind", env.EventKind)
	}
	data := env.Payload.Data
	if data == nil {
		return ObservationItem{}, fmt.Errorf("payload data is required")
	}
	kindValue, _ := data["kind"].(string)
	if kindValue != payloadKind {
		return ObservationItem{}, fmt.Errorf("registered data kind %q does not match event kind %q", kindValue, env.EventKind)
	}
	required := observationRequiredKeys[payloadKind]
	allowed := make(map[string]bool, len(required))
	for _, k := range required {
		allowed[k] = true
		if _, present := data[k]; !present {
			return ObservationItem{}, fmt.Errorf("payload data is missing required field %q", k)
		}
	}
	for k := range data {
		if !allowed[k] {
			return ObservationItem{}, fmt.Errorf("payload data has unknown closed-object field %q", k)
		}
	}
	// Kind-specific carried-record checks. Nested artifact references
	// must be well-formed; slot content must agree with its expectation.
	switch payloadKind {
	case "native_report":
		if _, err := artifactRefFromAny(data["raw"], "raw"); err != nil {
			return ObservationItem{}, err
		}
	case "task_output":
		if _, err := artifactRefFromAny(data["content"], "content"); err != nil {
			return ObservationItem{}, err
		}
	case "artifact_available":
		if _, err := slotFromAny(data["artifact"]); err != nil {
			return ObservationItem{}, err
		}
	case "lifecycle_publication":
		pub, ok := data["publication"].(map[string]any)
		if !ok {
			return ObservationItem{}, fmt.Errorf("publication must be an object")
		}
		content, ok := pub["content"]
		if !ok {
			return ObservationItem{}, fmt.Errorf("publication.content is required")
		}
		if _, err := artifactRefFromAny(content, "publication.content"); err != nil {
			return ObservationItem{}, err
		}
	case "clock_registered":
		// The journal stores the descriptor flat (journal_rules parses
		// the top-level data keys); the projection normalizes it to
		// the {kind, clock} connector shape below without changing
		// any registered value.
		for _, k := range []string{"clock_id", "boot_id", "origin", "source_id", "basis", "unit"} {
			s, _ := data[k].(string)
			if strings.TrimSpace(s) == "" {
				return ObservationItem{}, fmt.Errorf("clock data is missing required field %q", k)
			}
		}
		origin, _ := data["origin"].(string)
		switch origin {
		case "engine_measured", "browser_measured", "subject_reported", "manual_reference":
		default:
			return ObservationItem{}, fmt.Errorf("clock origin %q is not a known value", origin)
		}
		basis, _ := data["basis"].(string)
		if basis != "monotonic_offset" && basis != "opaque_report" {
			return ObservationItem{}, fmt.Errorf("clock basis %q is not a known value", basis)
		}
		if unit, _ := data["unit"].(string); unit != "ms" {
			return ObservationItem{}, fmt.Errorf("clock unit must be ms")
		}
	}
	// Every cited support reference must resolve inside the cutoff.
	for i, ref := range env.Payload.EvidenceRefs {
		if err := resolveSupport(cutoff, events, ref); err != nil {
			return ObservationItem{}, fmt.Errorf("envelope evidence_refs[%d]: %v", i, err)
		}
	}
	nested, err := nestedEvidenceRefs(payloadKind, data)
	if err != nil {
		return ObservationItem{}, err
	}
	for _, ref := range nested {
		if err := resolveSupport(cutoff, events, ref); err != nil {
			return ObservationItem{}, fmt.Errorf("payload support %s@%d: %v", ref.EventID, ref.Sequence, err)
		}
	}
	recordedRaw, err := json.Marshal(env.RecordedAt)
	if err != nil {
		return ObservationItem{}, fmt.Errorf("recorded_at is unreadable: %v", err)
	}
	var recordedAt TimePoint
	if err := strictUnmarshal(recordedRaw, &recordedAt); err != nil {
		return ObservationItem{}, fmt.Errorf("recorded_at is not a TimePoint: %v", err)
	}
	if !validProvenance[env.Provenance] {
		return ObservationItem{}, fmt.Errorf("provenance %q is not a known value", env.Provenance)
	}
	for i, ref := range env.Payload.ArtifactRefs {
		if err := validateArtifactRef(ref); err != nil {
			return ObservationItem{}, fmt.Errorf("envelope artifact_refs[%d]: %v", i, err)
		}
	}
	eventRef := EvidenceRef{
		JournalID: env.JournalID,
		Sequence:  env.Sequence,
		EventID:   env.EventID,
		EventHash: env.EventHash,
		Pointer:   "",
	}
	measurements := make([]MeasurementEvidence, 0, len(env.Payload.Measurements))
	for _, m := range env.Payload.Measurements {
		measurements = append(measurements, MeasurementEvidence{
			Measurement:  m,
			EvidenceRefs: []EvidenceRef{eventRef},
		})
	}
	artifactRefs := make([]ArtifactReference, 0, len(env.Payload.ArtifactRefs))
	artifactRefs = append(artifactRefs, env.Payload.ArtifactRefs...)
	// Copy the registered data verbatim so later mutation of the
	// retained envelope cannot affect the projected item. The flat
	// clock_registered record is normalized to the {kind, clock}
	// connector shape; every value is still copied from registration.
	payloadCopy := make(map[string]any, len(data))
	for k, v := range data {
		payloadCopy[k] = v
	}
	if payloadKind == "clock_registered" {
		clock := make(map[string]any, 6)
		for _, k := range []string{"clock_id", "boot_id", "origin", "source_id", "basis", "unit"} {
			clock[k] = data[k]
		}
		payloadCopy = map[string]any{"kind": "clock_registered", "clock": clock}
	}
	return ObservationItem{
		EventRef:     eventRef,
		RecordedAt:   recordedAt,
		Provenance:   env.Provenance,
		Payload:      payloadCopy,
		Measurements: measurements,
		ArtifactRefs: artifactRefs,
	}, nil
}

// slotFromAny strictly parses one ArtifactSlot from journal data.
func slotFromAny(v any) (ArtifactSlot, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return ArtifactSlot{}, fmt.Errorf("artifact slot must be an object")
	}
	for _, k := range []string{"name", "expected_digest", "content", "evidence_refs"} {
		if _, present := m[k]; !present {
			return ArtifactSlot{}, fmt.Errorf("artifact slot is missing required field %q", k)
		}
	}
	for k := range m {
		switch k {
		case "name", "expected_digest", "content", "evidence_refs":
		default:
			return ArtifactSlot{}, fmt.Errorf("artifact slot has unknown closed-object field %q", k)
		}
	}
	name, _ := m["name"].(string)
	if strings.TrimSpace(name) == "" {
		return ArtifactSlot{}, fmt.Errorf("artifact slot name is required")
	}
	expectedRaw, err := json.Marshal(m["expected_digest"])
	if err != nil {
		return ArtifactSlot{}, fmt.Errorf("artifact slot expected_digest is unreadable: %v", err)
	}
	expectedDigest, expectedMissing, err := parseDigestOrMissing(expectedRaw, "artifact slot expected_digest")
	if err != nil {
		return ArtifactSlot{}, err
	}
	contentRaw, err := json.Marshal(m["content"])
	if err != nil {
		return ArtifactSlot{}, fmt.Errorf("artifact slot content is unreadable: %v", err)
	}
	contentRef, contentMissing, err := parseArtifactOrMissing(contentRaw, "artifact slot content")
	if err != nil {
		return ArtifactSlot{}, err
	}
	if contentRef != nil && expectedMissing == nil && contentRef.Digest != expectedDigest {
		return ArtifactSlot{}, fmt.Errorf("available slot content %s does not match expected_digest %s", contentRef.Digest, expectedDigest)
	}
	_ = contentMissing
	items, ok := m["evidence_refs"].([]any)
	if !ok || len(items) == 0 {
		return ArtifactSlot{}, fmt.Errorf("artifact slot evidence_refs must be a nonempty array")
	}
	refs := make([]EvidenceRef, 0, len(items))
	for i, item := range items {
		ref, err := evidenceRefFromAny(item, fmt.Sprintf("artifact slot evidence_refs[%d]", i))
		if err != nil {
			return ArtifactSlot{}, err
		}
		refs = append(refs, ref)
	}
	return ArtifactSlot{
		Name:           name,
		ExpectedDigest: json.RawMessage(expectedRaw),
		Content:        json.RawMessage(contentRaw),
		EvidenceRefs:   refs,
	}, nil
}

// parseArtifactOrMissing decodes a MaybeArtifact wire value.
func parseArtifactOrMissing(raw json.RawMessage, field string) (*ArtifactReference, *Missing, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, nil, fmt.Errorf("%s is required", field)
	}
	if trimmed[0] != '{' {
		return nil, nil, fmt.Errorf("%s must be an artifact reference or a Missing envelope", field)
	}
	var probe map[string]any
	if err := strictUnmarshal(raw, &probe); err != nil {
		return nil, nil, fmt.Errorf("%s: %v", field, err)
	}
	if _, isMissing := probe["reason"]; isMissing {
		if _, hasValue := probe["value"]; hasValue {
			m, err := parseMissing(raw)
			if err != nil {
				return nil, nil, fmt.Errorf("%s: %v", field, err)
			}
			return nil, &m, nil
		}
	}
	var ref ArtifactReference
	if err := strictUnmarshal(raw, &ref); err != nil {
		return nil, nil, fmt.Errorf("%s: %v", field, err)
	}
	if err := validateArtifactRef(ref); err != nil {
		return nil, nil, fmt.Errorf("%s: %v", field, err)
	}
	return &ref, nil, nil
}

// ---------------------------------------------------------------------------
// Observe.
// ---------------------------------------------------------------------------

// ObserveHandle reads accumulated, journal-backed observations for
// exactly the requested handle through an explicit prefix.
func ObserveHandle(ctx context.Context, store *OwnerStore, request ConnectorRequest) (ConnectorResponse, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return ConnectorResponse{}, err
	}
	if cerr := validateEnvelope(request, OpObserve); cerr != nil {
		return respondWith(request, mustMarshal(cerr)), cerr
	}
	var payload ObserveRequest
	if err := strictUnmarshal(request.Payload, &payload); err != nil {
		return fail(request, codeInvalidRequest, domainRequest,
			fmt.Sprintf("observe payload: %v", err), deliveryNotApplicable,
			retryNewCommandIfNotDispatched, nil, nil)
	}
	if err := validateHandle(payload.Handle); err != nil {
		return fail(request, codeInvalidRequest, domainRequest,
			err.Error(), deliveryNotApplicable, retryNewCommandIfNotDispatched, nil, nil)
	}
	handleJSON := handleRaw(payload.Handle)
	journalID := payload.Handle.LocalHandle
	if request.ConnectorID != payload.Handle.ConnectorID {
		return fail(request, codeInvalidRequest, domainRequest,
			"payload handle must identify the request connector_id", deliveryNotApplicable,
			retryNewCommandIfNotDispatched, handleJSON, nil)
	}
	if payload.After.Handle != payload.Handle {
		return fail(request, codeInvalidRequest, domainRequest,
			"cursor handle must agree with the request handle", deliveryNotApplicable,
			retryNewCommandIfNotDispatched, handleJSON, nil)
	}
	if payload.After.JournalID != journalID {
		return fail(request, codeInvalidRequest, domainRequest,
			"cursor journal must be the handle observation journal", deliveryNotApplicable,
			retryNewCommandIfNotDispatched, handleJSON, nil)
	}
	if payload.MaxItems < 1 {
		return fail(request, codeInvalidRequest, domainRequest,
			"max_items starts at 1", deliveryNotApplicable,
			retryNewCommandIfNotDispatched, handleJSON, nil)
	}
	if payload.MaxItems > MaxObserveItems {
		return fail(request, codeBudgetExceeded, domainRequest,
			fmt.Sprintf("max_items exceeds the %d local bound", MaxObserveItems),
			deliveryNotApplicable, retryNewCommandIfNotDispatched, handleJSON, nil)
	}
	if err := validateDurationLimit(payload.WaitLimit, "wait_limit"); err != nil {
		return fail(request, codeInvalidRequest, domainRequest,
			err.Error(), deliveryNotApplicable, retryNewCommandIfNotDispatched, handleJSON, nil)
	}
	if payload.WaitLimit.Value > request.CallLimit.Value {
		return fail(request, codeBudgetExceeded, domainRequest,
			"wait_limit cannot exceed the call limit", deliveryNotApplicable,
			retryNewCommandIfNotDispatched, handleJSON, nil)
	}

	// Resolve the cutoff: an explicit prefix freezes pagination, while
	// Missing/not_applicable requests the published live head.
	var cutoff JournalPrefix
	var fixedCutoff bool
	throughTrimmed := bytes.TrimSpace(payload.Through)
	if len(throughTrimmed) == 0 {
		return fail(request, codeInvalidRequest, domainRequest,
			"through is required", deliveryNotApplicable,
			retryNewCommandIfNotDispatched, handleJSON, nil)
	}
	if throughTrimmed[0] == '{' {
		var probe map[string]any
		if err := strictUnmarshal(payload.Through, &probe); err != nil {
			return fail(request, codeInvalidRequest, domainRequest,
				fmt.Sprintf("through: %v", err), deliveryNotApplicable,
				retryNewCommandIfNotDispatched, handleJSON, nil)
		}
		if _, isMissing := probe["reason"]; isMissing {
			m, err := parseMissing(payload.Through)
			if err != nil {
				return fail(request, codeInvalidRequest, domainRequest,
					fmt.Sprintf("through: %v", err), deliveryNotApplicable,
					retryNewCommandIfNotDispatched, handleJSON, nil)
			}
			if m.Reason != "not_applicable" {
				return fail(request, codeInvalidRequest, domainRequest,
					"a missing through cutoff must carry reason not_applicable",
					deliveryNotApplicable, retryNewCommandIfNotDispatched, handleJSON, nil)
			}
			live, ok := lookupLiveHead(journalID)
			if !ok {
				return fail(request, codePrerequisiteUnavailable, domainConnector,
					"no live head is published for the handle journal; supply an explicit through prefix or publish the live head",
					deliveryNotApplicable, retryNewCommandIfNotDispatched, handleJSON, nil)
			}
			cutoff = live
		} else {
			var prefix JournalPrefix
			if err := strictUnmarshal(payload.Through, &prefix); err != nil {
				return fail(request, codeInvalidRequest, domainRequest,
					fmt.Sprintf("through: %v", err), deliveryNotApplicable,
					retryNewCommandIfNotDispatched, handleJSON, nil)
			}
			if err := validateJournalPrefix(prefix); err != nil {
				return fail(request, codeInvalidRequest, domainRequest,
					fmt.Sprintf("through: %v", err), deliveryNotApplicable,
					retryNewCommandIfNotDispatched, handleJSON, nil)
			}
			if prefix.JournalID != journalID {
				return fail(request, codeInvalidRequest, domainRequest,
					"cutoff journal must agree with the cursor journal", deliveryNotApplicable,
					retryNewCommandIfNotDispatched, handleJSON, nil)
			}
			if payload.WaitLimit.Value != 0 {
				return fail(request, codeInvalidRequest, domainRequest,
					"a fixed through cutoff requires wait_limit value 0",
					deliveryNotApplicable, retryNewCommandIfNotDispatched, handleJSON, nil)
			}
			cutoff = prefix
			fixedCutoff = true
		}
	} else {
		return fail(request, codeInvalidRequest, domainRequest,
			"through must be a journal prefix or a Missing envelope", deliveryNotApplicable,
			retryNewCommandIfNotDispatched, handleJSON, nil)
	}

	events, err := owner_store.LoadPrefix(ctx, store, cutoff)
	if err != nil {
		return fail(request, mapLoadError(err), mapLoadDomain(err),
			mapLoadDetail("observe", cutoff, err), deliveryNotApplicable,
			mapLoadRetry(err), handleJSON, nil)
	}
	noteVerifiedHead(cutoff)
	if err := verifyRetainedEnvelopes(cutoff, events); err != nil {
		return fail(request, codeIntegrityConflict, domainConnector,
			fmt.Sprintf("retained journal failed verification: %v", err),
			deliveryNotApplicable, retryOperatorReview, handleJSON, nil)
	}
	bySeq := make(map[int64]JournalEnvelope, len(events))
	for _, env := range events {
		bySeq[env.Sequence] = env
	}

	// Validate the cursor against the retained prefix. Lost history is
	// explicit and never skipped.
	afterSeq := payload.After.Sequence
	if afterSeq < 0 {
		return fail(request, codeCursorInvalid, domainRequest,
			"cursor sequence must not be negative", deliveryNotApplicable,
			retryNewCommandIfNotDispatched, handleJSON, nil)
	}
	if afterSeq == 0 {
		_, missing, err := parseDigestOrMissing(payload.After.EventHash, "cursor event_hash")
		if err != nil || missing == nil || missing.Reason != "not_applicable" {
			return fail(request, codeCursorInvalid, domainRequest,
				"the zero cursor begins before admission and carries an inapplicable hash",
				deliveryNotApplicable, retryNewCommandIfNotDispatched, handleJSON, nil)
		}
	} else {
		hash, missing, err := parseDigestOrMissing(payload.After.EventHash, "cursor event_hash")
		if err != nil || missing != nil {
			return fail(request, codeCursorInvalid, domainRequest,
				"a positive cursor carries the retained event digest", deliveryNotApplicable,
				retryNewCommandIfNotDispatched, handleJSON, nil)
		}
		if afterSeq > cutoff.LastSequence {
			return fail(request, codeCursorInvalid, domainRequest,
				fmt.Sprintf("cursor sequence %d is ahead of cutoff %d; supply a cutoff at or beyond the cursor",
					afterSeq, cutoff.LastSequence),
				deliveryNotApplicable, retryNewCommandIfNotDispatched, handleJSON, nil)
		}
		retained, ok := bySeq[afterSeq]
		if !ok || retained.EventHash != hash {
			return fail(request, codeCursorUnavailable, domainConnector,
				fmt.Sprintf("cursor history at sequence %d no longer matches the retained journal; nothing was skipped",
					afterSeq),
				deliveryNotApplicable, retryOperatorReview, handleJSON, nil)
		}
	}

	// Scan forward from the cursor. Next is the last scanned position,
	// including non-observation events; has_more is exactly
	// next < cutoff. Items stay unique and increasing.
	items := []ObservationItem{}
	nextSeq := afterSeq
	lastReturned := afterSeq
	itemsFull := false
	for seq := afterSeq + 1; seq <= cutoff.LastSequence; seq++ {
		env, ok := bySeq[seq]
		if !ok {
			return fail(request, codeIntegrityConflict, domainConnector,
				fmt.Sprintf("retained prefix is missing sequence %d", seq),
				deliveryNotApplicable, retryOperatorReview, handleJSON, nil)
		}
		if _, isObs := observationKinds[env.EventKind]; !isObs {
			nextSeq = seq
			continue
		}
		if int64(len(items)) >= payload.MaxItems {
			itemsFull = true
			break
		}
		item, err := projectObservationItem(cutoff, events, env)
		if err != nil {
			return fail(request, codeIntegrityConflict, domainConnector,
				fmt.Sprintf("sequence %d (%s) cannot be projected: %v", seq, env.EventKind, err),
				deliveryNotApplicable, retryOperatorReview, handleJSON, nil)
		}
		itemRaw, err := json.Marshal(item)
		if err != nil {
			return fail(request, codeInternalError, domainUnknown,
				fmt.Sprintf("sequence %d: cannot encode projected item: %v", seq, err),
				deliveryNotApplicable, retryOperatorReview, handleJSON, nil)
		}
		canonical, err := evidence_codec.CanonicalJSON(itemRaw, "application/json")
		if err != nil {
			return fail(request, codeInternalError, domainUnknown,
				fmt.Sprintf("sequence %d: cannot canonicalize projected item: %v", seq, err),
				deliveryNotApplicable, retryOperatorReview, handleJSON, nil)
		}
		if len(canonical) > MaxObserveResponseBytes {
			return fail(request, codeResponseTooLarge, domainConnector,
				fmt.Sprintf("sequence %d (%s) encodes to %d bytes, above the %d byte item bound; it was not dropped",
					seq, env.EventKind, len(canonical), MaxObserveResponseBytes),
				deliveryNotApplicable, retryOperatorReview, handleJSON, nil)
		}
		items = append(items, item)
		nextSeq = seq
		lastReturned = seq
	}
	if itemsFull {
		// Pagination stops at the last returned item so the
		// unreturned observation is never skipped.
		nextSeq = lastReturned
	}
	var nextHash json.RawMessage
	if nextSeq == 0 {
		nextHash = missingRaw("not_applicable", "no journal position has been scanned")
	} else {
		nextHash = mustMarshal(bySeq[nextSeq].EventHash)
	}
	next := ObservationCursor{
		Handle:    payload.Handle,
		JournalID: journalID,
		Sequence:  nextSeq,
		EventHash: nextHash,
	}
	hasMore := nextSeq < cutoff.LastSequence

	// Locally observed closure at this cutoff, or an explicit
	// not_observed marker. Neither states native termination.
	var closeRef json.RawMessage = missingRaw("not_observed", "no local observation closure is recorded through this cutoff")
	for seq := cutoff.LastSequence; seq >= 1; seq-- {
		if closureKinds[bySeq[seq].EventKind] {
			env := bySeq[seq]
			closeRef = mustMarshal(EvidenceRef{
				JournalID: env.JournalID,
				Sequence:  env.Sequence,
				EventID:   env.EventID,
				EventHash: env.EventHash,
				Pointer:   "",
			})
			break
		}
	}

	limitations := []string{}
	if fixedCutoff {
		limitations = append(limitations,
			fmt.Sprintf("cutoff is pinned to journal prefix %s@%d; late evidence requires a new live cutoff",
				cutoff.JournalID, cutoff.LastSequence))
	} else {
		limitations = append(limitations,
			fmt.Sprintf("live cutoff resolved to journal prefix %s@%d; later evidence requires a newer live cutoff",
				cutoff.JournalID, cutoff.LastSequence))
	}
	if !fixedCutoff && payload.WaitLimit.Value != 0 {
		limitations = append(limitations,
			"bounded waiting was not performed; this page reflects the resolved cutoff only")
	}
	limitations = append(limitations,
		"observation pages reflect the retained journal prefix only; no native endpoint was polled")
	if len(items) == 0 {
		limitations = append(limitations,
			"an empty page does not imply native termination or producer completeness")
	}
	page := ObservationPage{
		Kind:                kindObservationPage,
		Handle:              payload.Handle,
		After:               payload.After,
		Through:             cutoff,
		Next:                next,
		HasMore:             hasMore,
		ObservationCloseRef: closeRef,
		Items:               items,
		Limitations:         limitations,
	}
	return respondWith(request, mustMarshal(page)), nil
}

// ---------------------------------------------------------------------------
// CollectArtifacts.
// ---------------------------------------------------------------------------

// CollectHandleArtifacts enumerates retained artifact slots or transfers
// retained artifact bytes for exactly the requested handle. Collection
// never fetches arbitrary URLs or paths, never reruns workflow actions,
// and never creates sessions.
func CollectHandleArtifacts(ctx context.Context, store *OwnerStore, request ConnectorRequest) (ConnectorResponse, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return ConnectorResponse{}, err
	}
	if cerr := validateEnvelope(request, OpCollectArtifacts); cerr != nil {
		return respondWith(request, mustMarshal(cerr)), cerr
	}
	var payload CollectArtifactsRequest
	if err := strictUnmarshal(request.Payload, &payload); err != nil {
		return fail(request, codeInvalidRequest, domainRequest,
			fmt.Sprintf("collect_artifacts payload: %v", err), deliveryNotApplicable,
			retryNewCommandIfNotDispatched, nil, nil)
	}
	if err := validateHandle(payload.Handle); err != nil {
		return fail(request, codeInvalidRequest, domainRequest,
			err.Error(), deliveryNotApplicable, retryNewCommandIfNotDispatched, nil, nil)
	}
	handleJSON := handleRaw(payload.Handle)
	journalID := payload.Handle.LocalHandle
	if request.ConnectorID != payload.Handle.ConnectorID {
		return fail(request, codeInvalidRequest, domainRequest,
			"payload handle must identify the request connector_id", deliveryNotApplicable,
			retryNewCommandIfNotDispatched, handleJSON, nil)
	}
	if err := validateSelector(payload.Selector); err != nil {
		return fail(request, codeInvalidRequest, domainRequest,
			err.Error(), deliveryNotApplicable, retryNewCommandIfNotDispatched, handleJSON, nil)
	}

	// Idempotency: (connector_id, request_id) identifies one collecting
	// command. An identical retry returns the retained receipt without
	// another effect; conflicting content is rejected. Only completed
	// receipts are retained; typed rejections are re-evaluated.
	cacheKey := request.ConnectorID + "\x00" + request.RequestID
	canonicalPayload, err := evidence_codec.CanonicalJSON(request.Payload, "application/json")
	if err != nil {
		return fail(request, codeInvalidRequest, domainRequest,
			fmt.Sprintf("payload is not canonicalizable: %v", err), deliveryNotApplicable,
			retryNewCommandIfNotDispatched, handleJSON, nil)
	}
	requestHash := string(evidence_codec.HashBytes(canonicalPayload))
	if prior, ok := lookupCollectReceipt(cacheKey); ok {
		if prior.requestHash != requestHash {
			return fail(request, codeIdempotencyConflict, domainRequest,
				"conflicting content under (connector_id, request_id); resend the identical request or use a new request_id",
				deliveryNotDispatched, retrySameCommandOnly, handleJSON, nil)
		}
		replay := prior.response
		replay.Result = append(json.RawMessage(nil), prior.response.Result...)
		return replay, nil
	}

	cutoff, ok := lookupLiveHead(journalID)
	if !ok {
		return fail(request, codePrerequisiteUnavailable, domainConnector,
			"no live head is published for the handle journal; publish the live head before collecting",
			deliveryNotApplicable, retryNewCommandIfNotDispatched, handleJSON, nil)
	}
	events, err := owner_store.LoadPrefix(ctx, store, cutoff)
	if err != nil {
		return fail(request, mapLoadError(err), mapLoadDomain(err),
			mapLoadDetail("collect_artifacts", cutoff, err), deliveryNotApplicable,
			mapLoadRetry(err), handleJSON, nil)
	}
	noteVerifiedHead(cutoff)
	if err := verifyRetainedEnvelopes(cutoff, events); err != nil {
		return fail(request, codeIntegrityConflict, domainConnector,
			fmt.Sprintf("retained journal failed verification: %v", err),
			deliveryNotApplicable, retryOperatorReview, handleJSON, nil)
	}
	index, err := buildArtifactIndex(cutoff, events)
	if err != nil {
		return fail(request, codeIntegrityConflict, domainConnector,
			err.Error(), deliveryNotApplicable, retryOperatorReview, handleJSON, nil)
	}

	var result json.RawMessage
	switch payload.Selector.Mode {
	case "inventory", "named":
		inventory, cerr := buildInventory(payload.Handle, cutoff, events, index, payload.Selector)
		if cerr != nil {
			return respondWith(request, mustMarshal(cerr)), cerr
		}
		result = mustMarshal(inventory)
	case "bytes":
		chunk, cerr := buildChunk(ctx, store, payload.Handle, cutoff, index, payload.Selector)
		if cerr != nil {
			return respondWith(request, mustMarshal(cerr)), cerr
		}
		result = mustMarshal(chunk)
	default:
		return fail(request, codeInvalidRequest, domainRequest,
			fmt.Sprintf("selector mode %q is not inventory, named, or bytes", payload.Selector.Mode),
			deliveryNotApplicable, retryNewCommandIfNotDispatched, handleJSON, nil)
	}
	response := respondWith(request, result)
	stored := response
	stored.Result = append(json.RawMessage(nil), result...)
	storeCollectReceipt(cacheKey, collectReceipt{requestHash: requestHash, response: stored})
	return response, nil
}

func validateSelector(sel ArtifactSelector) error {
	switch sel.Mode {
	case "inventory":
	case "named":
		if len(sel.Names) == 0 {
			return fmt.Errorf("a named selector requests at least one name")
		}
		if len(sel.Names) > MaxNamedArtifacts {
			return fmt.Errorf("a named selector requests at most %d names", MaxNamedArtifacts)
		}
		seen := map[string]bool{}
		for _, name := range sel.Names {
			if strings.TrimSpace(name) == "" {
				return fmt.Errorf("artifact names are nonempty identifiers")
			}
			if seen[name] {
				return fmt.Errorf("artifact name %q is requested twice", name)
			}
			seen[name] = true
		}
	case "bytes":
		if !digestPattern.MatchString(sel.Digest) {
			return fmt.Errorf("bytes digest is not a content digest; URLs and paths are never fetched")
		}
		if !sel.hasOffset || !sel.hasMaxBytes {
			return fmt.Errorf("bytes mode requires digest, offset, and max_bytes")
		}
		if sel.Offset < 0 {
			return fmt.Errorf("bytes offset must not be negative")
		}
		if sel.MaxBytes < 1 {
			return fmt.Errorf("bytes max_bytes starts at 1")
		}
	default:
		return fmt.Errorf("selector mode %q is not inventory, named, or bytes", sel.Mode)
	}
	return nil
}

// artifactIndex records every artifact registration in the handle
// journal through the cutoff: named slots (latest wins) and digests
// with their registering event references.
type artifactIndex struct {
	slots   map[string]ArtifactSlot
	digests map[string][]EvidenceRef
}

// buildArtifactIndex scans the retained prefix for artifact
// registrations. Slots come from artifact_available events; digests
// come from envelope artifact_refs and nested data references.
func buildArtifactIndex(cutoff JournalPrefix, events []JournalEnvelope) (*artifactIndex, error) {
	index := &artifactIndex{slots: map[string]ArtifactSlot{}, digests: map[string][]EvidenceRef{}}
	register := func(ref ArtifactReference, env JournalEnvelope) error {
		if err := validateArtifactRef(ref); err != nil {
			return fmt.Errorf("sequence %d: %v", env.Sequence, err)
		}
		ev := EvidenceRef{
			JournalID: env.JournalID,
			Sequence:  env.Sequence,
			EventID:   env.EventID,
			EventHash: env.EventHash,
			Pointer:   "",
		}
		index.digests[ref.Digest] = append(index.digests[ref.Digest], ev)
		return nil
	}
	var collectNested func(value any, env JournalEnvelope) error
	collectNested = func(value any, env JournalEnvelope) error {
		switch v := value.(type) {
		case map[string]any:
			if looksLikeArtifactRef(v) {
				ref, err := artifactRefFromAny(v, "nested artifact reference")
				if err != nil {
					return fmt.Errorf("sequence %d: %v", env.Sequence, err)
				}
				if err := register(ref, env); err != nil {
					return err
				}
			}
			for _, child := range v {
				if err := collectNested(child, env); err != nil {
					return err
				}
			}
		case []any:
			for _, child := range v {
				if err := collectNested(child, env); err != nil {
					return err
				}
			}
		}
		return nil
	}
	for _, env := range events {
		for _, ref := range env.Payload.ArtifactRefs {
			if err := register(ref, env); err != nil {
				return nil, err
			}
		}
		if env.Payload.Data != nil {
			if err := collectNested(map[string]any(env.Payload.Data), env); err != nil {
				return nil, err
			}
		}
		if env.EventKind == "artifact_available" {
			slotValue, ok := env.Payload.Data["artifact"]
			if !ok {
				return nil, fmt.Errorf("sequence %d: artifact_available data is missing its slot", env.Sequence)
			}
			slot, err := slotFromAny(slotValue)
			if err != nil {
				return nil, fmt.Errorf("sequence %d: %v", env.Sequence, err)
			}
			for _, ref := range slot.EvidenceRefs {
				if err := resolveSupport(cutoff, events, ref); err != nil {
					return nil, fmt.Errorf("sequence %d: slot %q support %s@%d: %v",
						env.Sequence, slot.Name, ref.EventID, ref.Sequence, err)
				}
			}
			index.slots[slot.Name] = slot
		}
	}
	return index, nil
}

func buildInventory(handle HandleReference, cutoff JournalPrefix, events []JournalEnvelope, index *artifactIndex, sel ArtifactSelector) (*ArtifactInventory, *ConnectorError) {
	handleJSON := handleRaw(handle)
	slots := []ArtifactSlot{}
	coverage := "complete"
	switch sel.Mode {
	case "inventory":
		names := make([]string, 0, len(index.slots))
		for name := range index.slots {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			slots = append(slots, index.slots[name])
		}
	case "named":
		head := events[len(events)-1]
		headRef := EvidenceRef{
			JournalID: head.JournalID,
			Sequence:  head.Sequence,
			EventID:   head.EventID,
			EventHash: head.EventHash,
			Pointer:   "",
		}
		found := 0
		for _, name := range sel.Names {
			if slot, ok := index.slots[name]; ok {
				slots = append(slots, slot)
				found++
				continue
			}
			slots = append(slots, ArtifactSlot{
				Name: name,
				ExpectedDigest: missingRaw("not_observed",
					fmt.Sprintf("no slot named %q is registered through %s@%d", name, cutoff.JournalID, cutoff.LastSequence)),
				Content: missingRaw("not_observed",
					fmt.Sprintf("no content for %q is registered through %s@%d", name, cutoff.JournalID, cutoff.LastSequence)),
				EvidenceRefs: []EvidenceRef{headRef},
			})
		}
		if found != len(sel.Names) {
			coverage = "partial"
		}
	}
	unnamed := 0
	slotDigests := map[string]bool{}
	for _, slot := range index.slots {
		if digest, _, err := parseDigestOrMissing(slot.ExpectedDigest, "slot expected_digest"); err == nil {
			slotDigests[digest] = true
		}
		trimmed := bytes.TrimSpace(slot.Content)
		if len(trimmed) > 0 && trimmed[0] == '{' {
			var probe map[string]any
			if err := json.Unmarshal(trimmed, &probe); err == nil {
				if _, isMissing := probe["reason"]; !isMissing {
					if digest, _ := probe["digest"].(string); digest != "" {
						slotDigests[digest] = true
					}
				}
			}
		}
	}
	for digest := range index.digests {
		if !slotDigests[digest] {
			unnamed++
		}
	}
	limitations := []string{
		fmt.Sprintf("inventory is scoped to journal prefix %s@%d; later registrations require a fresh request",
			cutoff.JournalID, cutoff.LastSequence),
	}
	if unnamed > 0 {
		limitations = append(limitations,
			fmt.Sprintf("%d registered digests have no named slot and are addressable only by bytes selector", unnamed))
	}
	if sel.Mode == "named" && coverage == "partial" {
		limitations = append(limitations,
			"one or more requested names are not registered through the cutoff; their slots are explicit Missing values")
	}
	_ = handleJSON
	return &ArtifactInventory{
		Kind:           kindArtifactInventory,
		Handle:         handle,
		Artifacts:      slots,
		Coverage:       coverage,
		EvidencePrefix: cutoff,
		Limitations:    limitations,
	}, nil
}

func buildChunk(ctx context.Context, store *OwnerStore, handle HandleReference, cutoff JournalPrefix, index *artifactIndex, sel ArtifactSelector) (*ArtifactChunk, *ConnectorError) {
	handleJSON := handleRaw(handle)
	registering, ok := index.digests[sel.Digest]
	if !ok || len(registering) == 0 {
		return nil, newConnectorError(codeArtifactUnavailable, domainConnector,
			fmt.Sprintf("digest %s is not registered in the handle journal through %s@%d; no fetch was attempted",
				sel.Digest, cutoff.JournalID, cutoff.LastSequence),
			deliveryNotApplicable, retryNewCommandIfNotDispatched, handleJSON, nil)
	}
	content, err := owner_store.ReadArtifact(ctx, store, ArtifactReference{Digest: sel.Digest})
	if err != nil {
		return nil, mapArtifactError(handleJSON, sel.Digest, err)
	}
	if string(evidence_codec.HashBytes(content)) != sel.Digest {
		return nil, newConnectorError(codeIntegrityConflict, domainConnector,
			fmt.Sprintf("retained bytes for %s no longer match the registered identity", sel.Digest),
			deliveryNotApplicable, retryOperatorReview, handleJSON, nil)
	}
	size := int64(len(content))
	if sel.Offset > size {
		return nil, newConnectorError(codeInvalidRequest, domainRequest,
			fmt.Sprintf("offset %d is beyond end of artifact %d", sel.Offset, size),
			deliveryNotApplicable, retryNewCommandIfNotDispatched, handleJSON, nil)
	}
	width := sel.MaxBytes
	if width > MaxChunkBytes {
		width = MaxChunkBytes
	}
	remaining := size - sel.Offset
	returned := width
	if returned > remaining {
		returned = remaining
	}
	window := content[sel.Offset : sel.Offset+returned]
	endOfArtifact := sel.Offset+returned == size
	if !endOfArtifact && returned == 0 {
		return nil, newConnectorError(codeInternalError, domainUnknown,
			"a non-EOF chunk must make progress", deliveryNotApplicable, retryOperatorReview, handleJSON, nil)
	}
	// Deduplicate registering references; SupportRefs are unique.
	seen := map[string]bool{}
	refs := []EvidenceRef{}
	for _, ref := range registering {
		key := fmt.Sprintf("%s\x00%d\x00%s", ref.JournalID, ref.Sequence, ref.Pointer)
		if seen[key] {
			continue
		}
		seen[key] = true
		refs = append(refs, ref)
	}
	return &ArtifactChunk{
		Kind:          kindArtifactChunk,
		Handle:        handle,
		Digest:        sel.Digest,
		SizeBytes:     size,
		Offset:        sel.Offset,
		ReturnedBytes: returned,
		DataBase64:    base64.StdEncoding.EncodeToString(window),
		ChunkDigest:   string(evidence_codec.HashBytes(window)),
		EndOfArtifact: endOfArtifact,
		EvidenceRefs:  refs,
	}, nil
}

// ---------------------------------------------------------------------------
// Store error mapping.
// ---------------------------------------------------------------------------

func mapLoadError(err error) string {
	switch {
	case err == nil:
		return codeInternalError
	case strings.Contains(err.Error(), owner_store.ErrJournalUnknown.Error()):
		return codeUnknownHandle
	case strings.Contains(err.Error(), owner_store.ErrPrefixMismatch.Error()):
		return codeInvalidRequest
	case strings.Contains(err.Error(), owner_store.ErrUnauthorized.Error()):
		return codeForbidden
	case strings.Contains(err.Error(), owner_store.ErrStorageUnavailable.Error()):
		return codeStorageUnavailable
	case strings.Contains(err.Error(), owner_store.ErrIntegrityConflict.Error()):
		return codeIntegrityConflict
	default:
		return codeInternalError
	}
}

func mapLoadDomain(err error) string {
	switch mapLoadError(err) {
	case codeUnknownHandle, codeInvalidRequest:
		return domainRequest
	case codeForbidden:
		return domainPolicy
	case codeStorageUnavailable:
		return domainEnvironment
	case codeIntegrityConflict:
		return domainConnector
	default:
		return domainUnknown
	}
}

func mapLoadRetry(err error) string {
	switch mapLoadError(err) {
	case codeUnknownHandle:
		return retryDoNotRetry
	case codeInvalidRequest, codeForbidden:
		return retryNewCommandIfNotDispatched
	case codeStorageUnavailable:
		return retrySameCommandOnly
	default:
		return retryOperatorReview
	}
}

func mapLoadDetail(op string, cutoff JournalPrefix, err error) string {
	switch mapLoadError(err) {
	case codeUnknownHandle:
		return fmt.Sprintf("handle journal %q is unknown; no observation state exists for this handle", cutoff.JournalID)
	case codeInvalidRequest:
		return fmt.Sprintf("%s cutoff %s@%d does not match the retained journal", op, cutoff.JournalID, cutoff.LastSequence)
	case codeForbidden:
		return fmt.Sprintf("%s is not authorized for this handle journal", op)
	case codeStorageUnavailable:
		return "durable storage is unavailable; admission halted and no evidence was fabricated"
	case codeIntegrityConflict:
		return fmt.Sprintf("retained journal failed verification: %v", err)
	default:
		_ = op
		return fmt.Sprintf("journal load failed: %v", err)
	}
}

func mapArtifactError(handle json.RawMessage, digest string, err error) *ConnectorError {
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	switch {
	case strings.Contains(msg, owner_store.ErrUnauthorized.Error()):
		return newConnectorError(codeForbidden, domainPolicy,
			fmt.Sprintf("artifact %s is not readable in this authorization context", digest),
			deliveryNotApplicable, retryDoNotRetry, handle, nil)
	case strings.Contains(msg, owner_store.ErrArtifactLost.Error()),
		strings.Contains(msg, owner_store.ErrArtifactMissing.Error()):
		return newConnectorError(codeObservationLost, domainConnector,
			fmt.Sprintf("retained bytes for registered digest %s are lost; the known identity is preserved but no chunk can be served", digest),
			deliveryNotApplicable, retryOperatorReview, handle, nil)
	case strings.Contains(msg, owner_store.ErrIntegrityConflict.Error()):
		return newConnectorError(codeIntegrityConflict, domainConnector,
			fmt.Sprintf("artifact %s failed identity verification: %v", digest, err),
			deliveryNotApplicable, retryOperatorReview, handle, nil)
	case strings.Contains(msg, owner_store.ErrStorageUnavailable.Error()):
		return newConnectorError(codeStorageUnavailable, domainEnvironment,
			"durable storage is unavailable; no evidence was fabricated",
			deliveryNotApplicable, retrySameCommandOnly, handle, nil)
	default:
		return newConnectorError(codeInternalError, domainUnknown,
			fmt.Sprintf("artifact read failed: %v", err),
			deliveryNotApplicable, retryOperatorReview, handle, nil)
	}
}

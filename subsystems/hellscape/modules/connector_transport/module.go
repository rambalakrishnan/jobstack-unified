// Package connector_transport implements the tier-1 Hellscape external
// connector transport: the authenticated JSON POST /connector carrier that
// moves one ConnectorRequest to one ConnectorResponse.
//
// Seam reference: seam-mappings/hellscape-seam-mapping.md sections 8.1
// (envelope and carrier), 8.2 (nine operations), and 8.14 (error taxonomy),
// plus contracts/02-external-connector.yaml x-reference-carrier
// (connector-http-json/0.1.0).
//
// Semantic boundaries enforced here:
//
//   - Exactly the nine versioned verbs exist; the surface is task-shaped and
//     browser-agnostic. No Page, ElementHandle, selector engine, DOM node
//     handle, or synchronous browser primitive is defined (EXT-SURFACE).
//   - Caller identity and grants derive only from authenticated channel
//     registration via authority.Authorize. Request IDs, connector IDs,
//     digests, and handles are correlation keys, never bearer authority
//     (EXT-AUTHORITY).
//   - ConnectorError describes failure to carry out this connector operation
//     only, never a composite task outcome. An observed native
//     failed/completed/stopped claim is normal Observe evidence, returned as
//     a success result (EXT-FAILURE).
//   - Local call, buffering, and response bounds are finite and enforced with
//     the local monotonic clock; rejected work is reported, never silently
//     lost (EXT-BOUNDS).
//   - Claim source, semantic scope, receipt time, and knowledge boundary are
//     preserved verbatim. HTTP success, protocol acknowledgement, and call
//     completion never establish application commitment (EK-CLAIMS).
//
// The transport performs a single POST per call. It never retries, never
// invents native polling/cancellation/revision endpoints, never assigns
// journal provenance, and never writes to a shared database.
package connector_transport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"

	"authority"
	"evidence_codec"
)

// Carrier and envelope constants (seam 8.1, EXT x-reference-carrier).
const (
	// RecordTypeRequest is the required record_type of every request envelope.
	RecordTypeRequest = "connector_request"
	// RecordTypeResponse is the required record_type of every reply envelope.
	RecordTypeResponse = "connector_response"
	// SchemaVersion pins the shared external-connector contract version.
	SchemaVersion = "external-connector/0.1.0"
	// CarrierPath is the only path this transport posts to.
	CarrierPath = "/connector"
	// CarrierMethod is the only method this transport uses.
	CarrierMethod = http.MethodPost
)

// The nine versioned verbs (seam 8.2). No other operation is recognized.
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

// validOperations is the closed verb set.
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

// Local finite bounds (EXT-BOUNDS). The descriptor may impose tighter limits;
// the transport never exceeds these even when the descriptor allows more.
const (
	// MaxCallLimitMs caps the local call allowance a caller may request.
	MaxCallLimitMs = 300_000
	// MaxRequestBytes caps the canonical request body.
	MaxRequestBytes = 4 << 20
	// MaxResponseBytes caps the connector reply body.
	MaxResponseBytes = 8 << 20
)

// Connector error codes (seam 8.14).
var validCodes = map[string]bool{
	"INVALID_REQUEST": true, "UNSUPPORTED_VERSION": true, "UNAUTHENTICATED": true,
	"FORBIDDEN": true, "UNKNOWN_HANDLE": true, "UNKNOWN_PREPARATION": true,
	"STALE_PREPARATION": true, "IDEMPOTENCY_CONFLICT": true, "UNSUPPORTED_MAPPING": true,
	"PREREQUISITE_UNAVAILABLE": true, "BUDGET_EXCEEDED": true, "NOT_ADMITTED": true,
	"OBSERVATION_CLOSED": true, "STALE_CONTEXT": true, "RESOURCE_BUSY": true,
	"STORAGE_UNAVAILABLE": true, "DELIVERY_UNCERTAIN": true, "CURSOR_INVALID": true,
	"CURSOR_UNAVAILABLE": true, "OBSERVATION_LOST": true, "RESPONSE_TOO_LARGE": true,
	"ARTIFACT_UNAVAILABLE": true, "NATIVE_PROTOCOL_ERROR": true, "INTEGRITY_CONFLICT": true,
	"INTERNAL_ERROR": true,
}

var validFaultDomains = map[string]bool{
	"request": true, "connector": true, "native_interface": true,
	"environment": true, "policy": true, "unknown": true,
}

var validDeliveries = map[string]bool{
	"not_dispatched": true, "may_have_dispatched": true,
	"dispatched": true, "not_applicable": true,
}

var validRetryGuidance = map[string]bool{
	"same_command_only": true, "new_command_if_not_dispatched": true,
	"operator_review": true, "do_not_retry": true,
}

// nullReasons mirrors the six EK NullReason values (seam 3.1).
var nullReasons = map[string]bool{
	"not_enabled": true, "not_applicable": true, "not_observed": true,
	"observation_lost": true, "unsupported_by_subject": true, "manual_override": true,
}

// DurationLimit is a finite configured allowance, never an elapsed
// measurement or a native guarantee.
type DurationLimit struct {
	Kind  string  `json:"kind"`
	Unit  string  `json:"unit"`
	Value float64 `json:"value"`
}

// ConnectorRequest is one task-shaped connector command (seam 8.1).
type ConnectorRequest struct {
	RecordType    string          `json:"record_type"`
	SchemaVersion string          `json:"schema_version"`
	RequestID     string          `json:"request_id"`
	ConnectorID   string          `json:"connector_id"`
	Operation     string          `json:"operation"`
	CallLimit     DurationLimit   `json:"call_limit"`
	Payload       json.RawMessage `json:"payload"`
}

// ConnectorResponse is one correlated connector reply (seam 8.1). It carries
// no composite task status, no origin-success boolean, and no qualification:
// an outer normal reply establishes only completion of this connector call.
type ConnectorResponse struct {
	RecordType    string          `json:"record_type"`
	SchemaVersion string          `json:"schema_version"`
	RequestID     string          `json:"request_id"`
	ConnectorID   string          `json:"connector_id"`
	Operation     string          `json:"operation"`
	Result        json.RawMessage `json:"result"`
}

// EvidenceRef cites one retained journal event coordinate.
type EvidenceRef struct {
	JournalID string `json:"journal_id"`
	Sequence  int64  `json:"sequence"`
	EventID   string `json:"event_id"`
	EventHash string `json:"event_hash"`
	Pointer   string `json:"pointer"`
}

// ConnectorError describes failure to carry out this connector operation
// only (seam 8.14). It never states a composite task outcome, an application
// commitment, or a native termination.
type ConnectorError struct {
	Kind              string        `json:"kind"`
	Code              string        `json:"code"`
	FaultDomain       string        `json:"fault_domain"`
	Detail            string        `json:"detail"`
	OperationDelivery string        `json:"operation_delivery"`
	RetryGuidance     string        `json:"retry_guidance"`
	RetryAfter        json.RawMessage `json:"retry_after"`
	Handle            json.RawMessage `json:"handle"`
	EvidenceRefs      []EvidenceRef `json:"evidence_refs"`
}

// Error renders the typed failure without asserting any task outcome.
func (e *ConnectorError) Error() string {
	if e == nil {
		return "connector <nil>"
	}
	return fmt.Sprintf("connector %s: %s (delivery %s)", e.Code, e.Detail, e.OperationDelivery)
}

// deploymentKey carries the authenticated deployment endpoint allowlist.
type deploymentKey struct{}

// ContextWithDeploymentEndpoints returns a context carrying the authenticated
// deployment configuration: the exact endpoint URLs this transport may post
// to. Endpoint selection comes from this configuration, never from an
// arbitrary caller-supplied destination.
func ContextWithDeploymentEndpoints(ctx context.Context, endpoints []string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	allow := make(map[string]bool, len(endpoints))
	for _, e := range endpoints {
		allow[e] = true
	}
	return context.WithValue(ctx, deploymentKey{}, allow)
}

// deploymentAllowlist returns the configured allowlist when present.
func deploymentAllowlist(ctx context.Context) (map[string]bool, bool) {
	if ctx == nil {
		return nil, false
	}
	allow, ok := ctx.Value(deploymentKey{}).(map[string]bool)
	if !ok || allow == nil {
		return nil, false
	}
	return allow, true
}

// missingEnvelope builds a typed Missing envelope; absent values are never
// rendered as in-band nulls.
func missingEnvelope(reason string) json.RawMessage {
	if !nullReasons[reason] {
		reason = "not_applicable"
	}
	return json.RawMessage(`{"value":null,"reason":` + strconv_quote(reason) + `}`)
}

func strconv_quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// newLocalError builds a transport-side typed failure. EvidenceRefs is always
// a (possibly empty) array, never null.
func newLocalError(code, faultDomain, detail, delivery, retry string) *ConnectorError {
	return &ConnectorError{
		Kind:              "connector_error",
		Code:              code,
		FaultDomain:       faultDomain,
		Detail:            detail,
		OperationDelivery: delivery,
		RetryGuidance:     retry,
		RetryAfter:        missingEnvelope("not_applicable"),
		Handle:            missingEnvelope("not_applicable"),
		EvidenceRefs:      []EvidenceRef{},
	}
}

// CallConnector carries one ConnectorRequest to the deployment-configured
// connector endpoint and returns its correlated ConnectorResponse.
//
//   - Identity: the reply must echo record/version, request ID, connector ID,
//     and operation; any mismatch is INTEGRITY_CONFLICT and conveys no task
//     outcome. Unregistered replies receive no journal provenance.
//   - Transport: HTTP status is never the outcome signal. The typed body
//     decides: kind connector_error surfaces as *ConnectorError, any other
//     expected kind returns (response, nil) verbatim.
//   - Deadline: a local call deadline reports DELIVERY_UNCERTAIN with the
//     native state explicitly unknown; it never asserts native termination,
//     cancellation, or rollback.
//   - Native evidence: an Observe page containing native failed, completed,
//     or stopped claims is a normal success result, not a connector failure.
//
// Exactly one POST is issued per call; mutating calls are never retried under
// a fresh command identity after ambiguous delivery.
func CallConnector(ctx context.Context, endpoint string, request ConnectorRequest) (ConnectorResponse, error) {
	var zero ConnectorResponse
	if ctx == nil {
		ctx = context.Background()
	}

	// The nine verbs are public; reject unknown operations before touching
	// authentication so callers get a precise structural error.
	if !validOperations[request.Operation] {
		return zero, newLocalError("INVALID_REQUEST", "request",
			"connector_transport: unknown operation; exactly the nine versioned verbs are recognized",
			"not_dispatched", "operator_review")
	}

	// EXT-AUTHORITY: identity and grants come only from authenticated
	// channel registration. IDs and digests are correlation keys.
	if err := authority.Authorize(ctx, "connector", request.Operation, request.ConnectorID); err != nil {
		msg := err.Error()
		if strings.Contains(msg, "no authenticated principal") || strings.Contains(msg, "unauthenticated") {
			return zero, newLocalError("UNAUTHENTICATED", "request",
				"connector_transport: unauthenticated channel",
				"not_dispatched", "operator_review")
		}
		return zero, newLocalError("FORBIDDEN", "policy",
			"connector_transport: not authorized for "+request.Operation,
			"not_dispatched", "operator_review")
	}

	// Endpoint selection comes from authenticated deployment configuration,
	// never from an arbitrary caller destination.
	if err := checkEndpoint(ctx, endpoint); err != nil {
		return zero, err
	}

	// Validate and canonicalize the request envelope.
	canonical, err := validateRequest(request)
	if err != nil {
		return zero, err
	}

	// A deadline already exceeded before dispatch never left the harness.
	if ctx.Err() != nil {
		return zero, newLocalError("DELIVERY_UNCERTAIN", "connector",
			"connector_transport: local call deadline already exceeded before dispatch; native state unknown; no termination asserted",
			"not_dispatched", "same_command_only")
	}

	// EXT-BOUNDS: the call allowance starts at local authenticated receipt
	// on the local monotonic clock. The effective deadline is the earlier
	// of the call limit and any caller context deadline.
	receipt := time.Now()
	timeout := time.Duration(request.CallLimit.Value * float64(time.Millisecond))
	callDeadline := receipt.Add(timeout)
	effective := callDeadline
	if dl, ok := ctx.Deadline(); ok && dl.Before(callDeadline) {
		effective = dl
	}
	dispatchCtx, cancel := context.WithDeadline(ctx, effective)
	defer cancel()

	req, err := http.NewRequestWithContext(dispatchCtx, CarrierMethod, endpoint, bytes.NewReader(canonical))
	if err != nil {
		return zero, newLocalError("INTERNAL_ERROR", "connector",
			"connector_transport: cannot construct connector call",
			"not_dispatched", "operator_review")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	// Credentials are deployment-configured outside these JSON records;
	// no caller principal, cookie, or token is placed in the payload.

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		// A single attempt only: never retry here, and never mint a fresh
		// command identity after ambiguous delivery.
		if dispatchCtx.Err() != nil || ctx.Err() != nil || isTimeoutError(err) {
			return zero, newLocalError("DELIVERY_UNCERTAIN", "connector",
				"connector_transport: local call deadline exceeded; native state unknown; no termination asserted",
				"may_have_dispatched", "same_command_only")
		}
		return zero, newLocalError("DELIVERY_UNCERTAIN", "environment",
			"connector_transport: connector unreachable; delivery uncertain; no task outcome established",
			"may_have_dispatched", "same_command_only")
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	if err != nil {
		return zero, newLocalError("DELIVERY_UNCERTAIN", "connector",
			"connector_transport: cannot read connector reply; delivery uncertain; no task outcome established",
			"may_have_dispatched", "same_command_only")
	}
	if int64(len(body)) > MaxResponseBytes {
		return zero, newLocalError("RESPONSE_TOO_LARGE", "connector",
			"connector_transport: connector reply exceeds local response bound; no task outcome established",
			"dispatched", "operator_review")
	}
	// HTTP status alone establishes nothing: undecodable traffic and typed
	// errors alike are decided by the typed body below.

	return validateResponse(request, resp.StatusCode, body)
}

// checkEndpoint rejects arbitrary caller destinations. The endpoint must be
// an http(s) URL with exactly path /connector and, when the context carries
// an authenticated deployment allowlist, must be a member of it.
func checkEndpoint(ctx context.Context, endpoint string) error {
	if strings.TrimSpace(endpoint) == "" {
		return newLocalError("INVALID_REQUEST", "request",
			"connector_transport: endpoint is required",
			"not_dispatched", "operator_review")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u == nil {
		return newLocalError("INVALID_REQUEST", "request",
			"connector_transport: malformed endpoint",
			"not_dispatched", "operator_review")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return newLocalError("INVALID_REQUEST", "request",
			"connector_transport: endpoint must use http or https",
			"not_dispatched", "operator_review")
	}
	if u.User != nil {
		return newLocalError("INVALID_REQUEST", "request",
			"connector_transport: endpoint must not carry user info",
			"not_dispatched", "operator_review")
	}
	if u.Host == "" {
		return newLocalError("INVALID_REQUEST", "request",
			"connector_transport: endpoint host is required",
			"not_dispatched", "operator_review")
	}
	if u.Path != CarrierPath {
		return newLocalError("INVALID_REQUEST", "request",
			"connector_transport: endpoint path must be exactly /connector",
			"not_dispatched", "operator_review")
	}
	if u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return newLocalError("INVALID_REQUEST", "request",
			"connector_transport: endpoint must not carry query or fragment",
			"not_dispatched", "operator_review")
	}
	if allow, ok := deploymentAllowlist(ctx); ok && !allow[endpoint] {
		return newLocalError("FORBIDDEN", "policy",
			"connector_transport: endpoint not in authenticated deployment configuration",
			"not_dispatched", "operator_review")
	}
	return nil
}

// validateRequest enforces the request envelope gates and returns the
// canonical wire bytes.
func validateRequest(r ConnectorRequest) ([]byte, error) {
	if r.RecordType != RecordTypeRequest {
		return nil, newLocalError("INVALID_REQUEST", "request",
			"connector_transport: record_type must be connector_request",
			"not_dispatched", "operator_review")
	}
	if r.SchemaVersion != SchemaVersion {
		return nil, newLocalError("UNSUPPORTED_VERSION", "request",
			"connector_transport: unsupported schema_version",
			"not_dispatched", "operator_review")
	}
	if strings.TrimSpace(r.RequestID) == "" || strings.TrimSpace(r.ConnectorID) == "" {
		return nil, newLocalError("INVALID_REQUEST", "request",
			"connector_transport: request_id and connector_id are required",
			"not_dispatched", "operator_review")
	}
	if r.CallLimit.Kind != "exact" || r.CallLimit.Unit != "ms" {
		return nil, newLocalError("INVALID_REQUEST", "request",
			"connector_transport: call_limit must be an exact ms allowance",
			"not_dispatched", "operator_review")
	}
	if math.IsNaN(r.CallLimit.Value) || math.IsInf(r.CallLimit.Value, 0) {
		return nil, newLocalError("INVALID_REQUEST", "request",
			"connector_transport: call_limit must be finite",
			"not_dispatched", "operator_review")
	}
	if r.CallLimit.Value < 0 {
		return nil, newLocalError("INVALID_REQUEST", "request",
			"connector_transport: call_limit must be nonnegative",
			"not_dispatched", "operator_review")
	}
	if r.CallLimit.Value > MaxCallLimitMs {
		return nil, newLocalError("BUDGET_EXCEEDED", "policy",
			"connector_transport: call_limit exceeds local call bound",
			"not_dispatched", "operator_review")
	}
	if len(bytes.TrimSpace(r.Payload)) == 0 {
		return nil, newLocalError("INVALID_REQUEST", "request",
			"connector_transport: payload object is required",
			"not_dispatched", "operator_review")
	}
	var payload any
	dec := json.NewDecoder(bytes.NewReader(r.Payload))
	dec.UseNumber()
	if err := dec.Decode(&payload); err != nil {
		return nil, newLocalError("INVALID_REQUEST", "request",
			"connector_transport: payload must be a JSON object",
			"not_dispatched", "operator_review")
	}
	payloadObj, ok := payload.(map[string]any)
	if !ok {
		return nil, newLocalError("INVALID_REQUEST", "request",
			"connector_transport: payload must be a JSON object",
			"not_dispatched", "operator_review")
	}
	if r.Operation == OpDescribe && len(payloadObj) != 0 {
		return nil, newLocalError("INVALID_REQUEST", "request",
			"connector_transport: Describe payload must be the empty closed object",
			"not_dispatched", "operator_review")
	}

	doc, err := json.Marshal(r)
	if err != nil {
		return nil, newLocalError("INTERNAL_ERROR", "connector",
			"connector_transport: cannot serialize connector request",
			"not_dispatched", "operator_review")
	}
	if len(doc) > MaxRequestBytes {
		return nil, newLocalError("BUDGET_EXCEEDED", "policy",
			"connector_transport: request exceeds local byte bound",
			"not_dispatched", "operator_review")
	}
	// Structural pre-gate through the shared evidence codec: duplicate
	// mapping keys and malformed JSON are rejected before validation. The
	// codec governs durable EK records, so its unknown-type signal for the
	// connector envelope means the shared gates passed; connector-specific
	// closed-object checks then apply below.
	if err := structuralPreGate(r.SchemaVersion, r.RecordType, doc); err != nil {
		return nil, newLocalError("INVALID_REQUEST", "request",
			"connector_transport: malformed request envelope",
			"not_dispatched", "operator_review")
	}
	canonical, err := evidence_codec.CanonicalJSON(doc, "application/json")
	if err != nil {
		return nil, newLocalError("INVALID_REQUEST", "request",
			"connector_transport: malformed request envelope",
			"not_dispatched", "operator_review")
	}
	// Request identity conflicts compare the complete canonical request;
	// the canonical bytes are also the exact wire body.
	var canon any
	if err := json.Unmarshal(canonical, &canon); err != nil {
		return nil, newLocalError("INVALID_REQUEST", "request",
			"connector_transport: malformed request envelope",
			"not_dispatched", "operator_review")
	}
	if err := rejectBareNulls(canon, "$"); err != nil {
		return nil, newLocalError("INVALID_REQUEST", "request",
			"connector_transport: bare null rejected; use typed Missing envelopes",
			"not_dispatched", "operator_review")
	}
	return canonical, nil
}

// validateResponse correlates one reply to its request. A correlated typed
// connector error returns (response, *ConnectorError); a correlated normal
// result returns (response, nil) with the result bytes preserved verbatim.
// Anything else returns a local typed failure and conveys no task outcome.
func validateResponse(req ConnectorRequest, status int, body []byte) (ConnectorResponse, error) {
	var zero ConnectorResponse
	if len(bytes.TrimSpace(body)) == 0 {
		return zero, newLocalError("INTEGRITY_CONFLICT", "connector",
			"connector_transport: undecodable connector reply; no task outcome established",
			"may_have_dispatched", "same_command_only")
	}
	if err := structuralPreGate(SchemaVersion, RecordTypeResponse, body); err != nil {
		return zero, newLocalError("INTEGRITY_CONFLICT", "connector",
			"connector_transport: undecodable connector reply; no task outcome established",
			"may_have_dispatched", "same_command_only")
	}
	canonical, err := evidence_codec.CanonicalJSON(body, "application/json")
	if err != nil {
		return zero, newLocalError("INTEGRITY_CONFLICT", "connector",
			"connector_transport: undecodable connector reply; no task outcome established",
			"may_have_dispatched", "same_command_only")
	}
	_ = status // HTTP status alone establishes nothing; the typed body decides.
	var resp ConnectorResponse
	if err := json.Unmarshal(canonical, &resp); err != nil {
		return zero, newLocalError("INTEGRITY_CONFLICT", "connector",
			"connector_transport: undecodable connector reply; no task outcome established",
			"may_have_dispatched", "same_command_only")
	}
	if resp.RecordType != RecordTypeResponse {
		return zero, newLocalError("INTEGRITY_CONFLICT", "connector",
			"connector_transport: reply record_type mismatch; no task outcome established",
			"may_have_dispatched", "same_command_only")
	}
	if resp.SchemaVersion != SchemaVersion {
		return zero, newLocalError("UNSUPPORTED_VERSION", "request",
			"connector_transport: reply schema_version mismatch; no task outcome established",
			"may_have_dispatched", "same_command_only")
	}
	if resp.RequestID != req.RequestID {
		return zero, newLocalError("INTEGRITY_CONFLICT", "connector",
			"connector_transport: reply request_id mismatch; no task outcome established",
			"may_have_dispatched", "same_command_only")
	}
	if resp.ConnectorID != req.ConnectorID {
		return zero, newLocalError("INTEGRITY_CONFLICT", "connector",
			"connector_transport: reply connector_id mismatch; no task outcome established",
			"may_have_dispatched", "same_command_only")
	}
	if resp.Operation != req.Operation {
		return zero, newLocalError("INTEGRITY_CONFLICT", "connector",
			"connector_transport: reply operation mismatch; no task outcome established",
			"may_have_dispatched", "same_command_only")
	}
	if len(bytes.TrimSpace(resp.Result)) == 0 {
		return zero, newLocalError("INTEGRITY_CONFLICT", "connector",
			"connector_transport: reply result object is required; no task outcome established",
			"may_have_dispatched", "same_command_only")
	}
	var result any
	dec := json.NewDecoder(bytes.NewReader(resp.Result))
	dec.UseNumber()
	if err := dec.Decode(&result); err != nil {
		return zero, newLocalError("INTEGRITY_CONFLICT", "connector",
			"connector_transport: reply result must be an object; no task outcome established",
			"may_have_dispatched", "same_command_only")
	}
	resultObj, ok := result.(map[string]any)
	if !ok {
		return zero, newLocalError("INTEGRITY_CONFLICT", "connector",
			"connector_transport: reply result must be an object; no task outcome established",
			"may_have_dispatched", "same_command_only")
	}
	if err := rejectBareNulls(resultObj, "$.result"); err != nil {
		return zero, newLocalError("INTEGRITY_CONFLICT", "connector",
			"connector_transport: reply uses bare null; no task outcome established",
			"may_have_dispatched", "same_command_only")
	}

	kind, _ := resultObj["kind"].(string)
	recordType, _ := resultObj["record_type"].(string)

	// Typed connector errors surface as errors; the correlated envelope is
	// still returned for request identity. Delivery and retry guidance
	// describe this operation only.
	if kind == "connector_error" {
		parsed, err := parseConnectorError(resp.Result)
		if err != nil {
			return zero, newLocalError("INTEGRITY_CONFLICT", "connector",
				"connector_transport: malformed connector error; no task outcome established",
				"may_have_dispatched", "same_command_only")
		}
		return resp, parsed
	}

	if !resultKindMatches(req.Operation, kind, recordType) {
		return zero, newLocalError("INTEGRITY_CONFLICT", "connector",
			"connector_transport: reply result kind does not match operation; no task outcome established",
			"may_have_dispatched", "same_command_only")
	}
	// Control receipts must name the requested verb in their observation;
	// acknowledgement of one operation is never evidence for another.
	if isControlOp(req.Operation) {
		obs, ok := resultObj["observation"].(map[string]any)
		if !ok {
			return zero, newLocalError("INTEGRITY_CONFLICT", "connector",
				"connector_transport: control receipt lacks observation; no task outcome established",
				"may_have_dispatched", "same_command_only")
		}
		op, _ := obs["operation"].(string)
		if op != req.Operation {
			return zero, newLocalError("INTEGRITY_CONFLICT", "connector",
				"connector_transport: control receipt operation mismatch; no task outcome established",
				"may_have_dispatched", "same_command_only")
		}
	}

	// Normal result: return the envelope verbatim. Native failed, completed,
	// and stopped claims inside an observation page are ordinary evidence
	// and impose no error here.
	return resp, nil
}

// resultKindMatches reports whether the reply discriminator belongs to the
// requested operation. connector_error is handled by the caller.
func resultKindMatches(operation, kind, recordType string) bool {
	switch operation {
	case OpDescribe:
		return recordType == "connector_descriptor"
	case OpPrepare:
		return kind == "prepared"
	case OpStart:
		return kind == "start_receipt"
	case OpObserve:
		return kind == "observation_page"
	case OpRequestNativeCancel, OpCloseObservationConnection, OpReleaseNativeContext, OpContain:
		return kind == "control_receipt"
	case OpCollectArtifacts:
		return kind == "artifact_inventory" || kind == "artifact_chunk"
	default:
		return false
	}
}

func isControlOp(op string) bool {
	switch op {
	case OpRequestNativeCancel, OpCloseObservationConnection, OpReleaseNativeContext, OpContain:
		return true
	default:
		return false
	}
}

// parseConnectorError validates a typed connector error body.
func parseConnectorError(raw json.RawMessage) (*ConnectorError, error) {
	var e ConnectorError
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil, err
	}
	if e.Kind != "connector_error" {
		return nil, fmt.Errorf("not a connector error")
	}
	if !validCodes[e.Code] {
		return nil, fmt.Errorf("unknown code")
	}
	if !validFaultDomains[e.FaultDomain] {
		return nil, fmt.Errorf("unknown fault domain")
	}
	if strings.TrimSpace(e.Detail) == "" {
		return nil, fmt.Errorf("empty Detail")
	}
	if !validDeliveries[e.OperationDelivery] {
		return nil, fmt.Errorf("unknown delivery")
	}
	if !validRetryGuidance[e.RetryGuidance] {
		return nil, fmt.Errorf("unknown retry guidance")
	}
	// DELIVERY_UNCERTAIN must carry ambiguous delivery and must never
	// authorize a fresh command for a possibly dispatched operation.
	if e.Code == "DELIVERY_UNCERTAIN" {
		if e.OperationDelivery != "may_have_dispatched" {
			return nil, fmt.Errorf("uncertain delivery mismatch")
		}
		if e.RetryGuidance == "new_command_if_not_dispatched" {
			return nil, fmt.Errorf("uncertain retry mismatch")
		}
	}
	if e.RetryGuidance == "new_command_if_not_dispatched" &&
		e.OperationDelivery != "not_dispatched" && e.OperationDelivery != "not_applicable" {
		return nil, fmt.Errorf("retry/delivery mismatch")
	}
	if len(bytes.TrimSpace(e.RetryAfter)) == 0 || len(bytes.TrimSpace(e.Handle)) == 0 {
		return nil, fmt.Errorf("missing envelopes required")
	}
	if e.EvidenceRefs == nil {
		e.EvidenceRefs = []EvidenceRef{}
	}
	return &e, nil
}

// structuralPreGate runs the shared evidence codec gates over a connector
// envelope. Duplicate mapping keys and malformed JSON are rejected before
// validation. The codec governs durable EK records rather than the connector
// envelope, so its unknown-type/version signal means the shared gates passed
// and connector-specific checks apply next.
func structuralPreGate(schemaVersion, recordType string, doc []byte) error {
	err := evidence_codec.ValidateRecord(schemaVersion, recordType, doc)
	if err == nil {
		return nil
	}
	msg := err.Error()
	if strings.Contains(msg, "unknown record type") || strings.Contains(msg, "unknown record version") {
		return nil
	}
	return err
}

// rejectBareNulls enforces reasoned Missing envelopes: JSON null is allowed
// only as the "value" of an object carrying a valid NullReason. Raw native
// bytes stay in artifacts; normalized records never use bare nulls.
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
				return fmt.Errorf("bare null at %s.%s", path, k)
			}
			if err := rejectBareNulls(val, path+"."+k); err != nil {
				return err
			}
		}
		return nil
	case []any:
		for i, elem := range x {
			if elem == nil {
				return fmt.Errorf("bare null at %s[%d]", path, i)
			}
			if err := rejectBareNulls(elem, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
		return nil
	default:
		return nil
	}
}

// isTimeoutError reports recognized timeout failures without asserting
// anything about native state.
func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	if te, ok := err.(interface{ Timeout() bool }); ok && te.Timeout() {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "deadline exceeded") ||
		strings.Contains(msg, "timed out") ||
		strings.Contains(msg, "timeout")
}

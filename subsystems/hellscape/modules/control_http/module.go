// Package control_http implements the Hellscape operator control surface.
//
// It is the authenticated control plane over the three owner-local stores:
// admission, dispatch, manual notes, observation close, connector controls,
// reads, export, and replay. Application-plane credentials never authorize
// control operations; every mutation carries a scoped idempotent command
// identity; the five lifecycle control verbs remain separately evidenced.
package control_http

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"admission"
	"analysis_owner"
	"authority"
	"connector_transport"
	"evidence_bundle"
	"manual_acceptance"
	"observation_owner"
	"owner_store"
	"publication"
	"replay"
	"session_runtime"
)

// OwnerStore is one owner-local durable boundary.
type OwnerStore = owner_store.OwnerStore

// Compile-time CONSUMES linkage.
var (
	_ = authority.Authenticate
	_ = authority.Authorize
	_ = admission.AdmitSession
	_ = session_runtime.FinalizeSession
	_ = analysis_owner.AnalyzeSession
	_ = evidence_bundle.ExportReplayInputs
	_ = evidence_bundle.ExportValidationBundle
	_ = replay.ReplayBundle
	_ = manual_acceptance.CheckManualAcceptance
	_ = publication.SealRow
	_ = observation_owner.RecordManualNote
	_ = connector_transport.CallConnector
	_ = owner_store.InstallArtifact
	_ = owner_store.LoadPrefix
)

// ControlHandler is the authenticated control-plane HTTP handler.
type ControlHandler struct {
	primary     *OwnerStore
	application *OwnerStore
	observation *OwnerStore
	policy      []byte

	mu       sync.Mutex
	ledger   map[string]ledgerEntry
	sessions map[string]*sessionRecord

	// ConnectorEndpoint is the authenticated deployment connector carrier
	// (POST <endpoint>). It is operator configuration, never a
	// caller-supplied destination. Tests set it to an httptest stub.
	ConnectorEndpoint string

	admitFn            func(ctx context.Context, store *OwnerStore, manifest admission.Manifest, commission admission.AttemptCommission, regs []admission.EntityRegistration) (admission.EvidenceRef, error)
	finalizeFn         func(ctx context.Context, primary, app, obs *OwnerStore, commission session_runtime.AttemptCommission, reason session_runtime.CloseReason) (session_runtime.DiagnosticDocument, error)
	analyzeFn          func(ctx context.Context, store *OwnerStore, manifest analysis_owner.Manifest, req analysis_owner.AnalysisRequest) (analysis_owner.DiagnosticDocument, error)
	exportInputsFn     func(ctx context.Context, store *OwnerStore, row evidence_bundle.LogicalRow, diag evidence_bundle.DiagnosticDocument) (evidence_bundle.ArtifactReference, error)
	exportValidationFn func(ctx context.Context, store *OwnerStore, row evidence_bundle.LogicalRow, diag evidence_bundle.DiagnosticDocument, receipt evidence_bundle.ReplayReceipt, checks evidence_bundle.ArtifactReference) (evidence_bundle.ArtifactReference, error)
	replayFn           func(ctx context.Context, store *OwnerStore, bundle evidence_bundle.ArtifactReference, sourceDiag evidence_bundle.ArtifactReference, mode string) (evidence_bundle.ReplayReceipt, error)
	checkFn            func(ctx context.Context, store *OwnerStore, inputs evidence_bundle.ArtifactReference, receipt evidence_bundle.ReplayReceipt) ([]byte, error)
	sealFn             func(ctx context.Context, store *OwnerStore, reg publication.EntityRegistration, name, viewID string) (publication.LogicalRow, error)
	noteFn             func(ctx context.Context, store *OwnerStore, attempt observation_owner.AttemptReference, note observation_owner.EventSubmission) (observation_owner.EvidenceRef, error)
	callConnectorFn    func(ctx context.Context, endpoint string, req connector_transport.ConnectorRequest) (connector_transport.ConnectorResponse, error)
	installFn          func(ctx context.Context, store *OwnerStore, content io.Reader, mediaType, access string) (owner_store.ArtifactReference, error)
	loadPrefixFn       func(ctx context.Context, store *OwnerStore, prefix owner_store.JournalPrefix) ([]owner_store.JournalEnvelope, error)
}

type ledgerEntry struct {
	requestDigest string
	status        int
	body          []byte
	receiptID     string
}

type sessionRecord struct {
	sessionID          string
	journalID          string
	runID              string
	attemptKind        string
	targetClass        string
	partition          string
	targetID           string
	taskDigest         string
	taskSemanticHash   string
	entryURL           string
	admissionRef       admission.EvidenceRef
	admissionPrefix    admission.JournalPrefix
	admissionCommission admission.AttemptCommission
	manifestRaw        json.RawMessage
	diagnosticRaw      json.RawMessage
	diagnosticPrefix   owner_store.JournalPrefix
	hasDiagnostic      bool
}

// NewControlHandler builds the control-plane handler over the three
// owner-local stores. The authentication policy is the authority channel
// table; every request authenticates against it and authorizes against the
// control domain, so application-plane credentials are always denied.
func NewControlHandler(primary *OwnerStore, application *OwnerStore, observation *OwnerStore, authenticationPolicy []byte) http.Handler {
	h := &ControlHandler{
		primary:     primary,
		application: application,
		observation: observation,
		policy:      append([]byte(nil), authenticationPolicy...),
		ledger:      map[string]ledgerEntry{},
		sessions:    map[string]*sessionRecord{},
	}
	h.admitFn = admission.AdmitSession
	h.finalizeFn = session_runtime.FinalizeSession
	h.analyzeFn = analysis_owner.AnalyzeSession
	h.exportInputsFn = evidence_bundle.ExportReplayInputs
	h.exportValidationFn = evidence_bundle.ExportValidationBundle
	h.replayFn = replay.ReplayBundle
	h.checkFn = manual_acceptance.CheckManualAcceptance
	h.sealFn = publication.SealRow
	h.noteFn = observation_owner.RecordManualNote
	h.callConnectorFn = connector_transport.CallConnector
	h.installFn = owner_store.InstallArtifact
	h.loadPrefixFn = owner_store.LoadPrefix
	return h
}

// ---------------------------------------------------------------------------
// Small helpers.
// ---------------------------------------------------------------------------

func missing(reason string) map[string]any {
	if reason == "" {
		reason = "not_observed"
	}
	return map[string]any{"value": nil, "reason": reason}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, errCode, detail string) {
	if detail == "" {
		detail = errCode
	}
	writeJSON(w, code, map[string]any{
		"error_code": errCode,
		"detail":     detail,
		"evidence_refs": []any{},
		"limitations":   []any{},
	})
}

func requestIDOf(r *http.Request) string {
	if v := strings.TrimSpace(r.Header.Get("Idempotency-Key")); v != "" {
		return v
	}
	if v := strings.TrimSpace(r.Header.Get("X-Request-ID")); v != "" {
		return v
	}
	return ""
}

func digestOf(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func commandKey(principal, scope, operation, requestID string) string {
	return principal + "|" + scope + "|" + operation + "|" + requestID
}

func receiptIDFor(prefix, key string) string {
	sum := sha256.Sum256([]byte(key))
	return prefix + "-" + hex.EncodeToString(sum[:8])
}

func (h *ControlHandler) principalForToken(token string) (string, string) {
	var pol struct {
		Channels map[string]struct {
			Principal string `json:"principal"`
			Kind      string `json:"kind"`
		} `json:"channels"`
	}
	if err := json.Unmarshal(h.policy, &pol); err != nil {
		return token, ""
	}
	if reg, ok := pol.Channels[token]; ok {
		return reg.Principal, reg.Kind
	}
	return token, ""
}

// authenticate runs authority.Authenticate and derives the ledger principal.
// It must be called before reading the body; Authenticate restores it.
func (h *ControlHandler) authenticate(r *http.Request) (context.Context, string, error) {
	ctx, err := authority.Authenticate(r, h.policy)
	if err != nil {
		return nil, "", err
	}
	auth := r.Header.Get("Authorization")
	parts := strings.Fields(auth)
	token := ""
	if len(parts) == 2 {
		token = parts[1]
	}
	principal, _ := h.principalForToken(token)
	if principal == "" {
		principal = token
	}
	return ctx, principal, nil
}

func (h *ControlHandler) ledgerLookup(key, digest string) (ledgerEntry, bool, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	e, ok := h.ledger[key]
	if !ok {
		return ledgerEntry{}, false, false
	}
	if e.requestDigest != digest {
		return e, true, true
	}
	return e, true, false
}

func (h *ControlHandler) ledgerStore(key, digest string, status int, body []byte, receiptID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ledger[key] = ledgerEntry{requestDigest: digest, status: status, body: append([]byte(nil), body...), receiptID: receiptID}
}

func (h *ControlHandler) getSession(sessionID string) (*sessionRecord, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	rec, ok := h.sessions[sessionID]
	if !ok {
		return nil, false
	}
	cp := *rec
	return &cp, true
}

func (h *ControlHandler) putSession(rec *sessionRecord) {
	h.mu.Lock()
	defer h.mu.Unlock()
	cp := *rec
	h.sessions[rec.sessionID] = &cp
}

// probeHeadSequence reveals the journal head sequence without trusting a
// caller-supplied head hash. It probes with an enormous prefix and parses
// the head out of the prefix-mismatch error.
func (h *ControlHandler) probeHeadSequence(ctx context.Context, store *OwnerStore, journalID string) (int64, error) {
	probe := owner_store.JournalPrefix{JournalID: journalID, LastSequence: 1 << 30, HeadHash: "sha256:" + strings.Repeat("0", 64)}
	_, err := h.loadPrefixFn(ctx, store, probe)
	if err == nil {
		return probe.LastSequence, nil
	}
	msg := err.Error()
	idx := strings.LastIndex(msg, "journal head is ")
	if idx < 0 {
		return 0, err
	}
	substr := msg[idx+len("journal head is "):]
	var head int64
	n, _ := fmt.Sscanf(substr, "%d", &head)
	if n != 1 {
		return 0, err
	}
	return head, nil
}

func convertCommission(in admission.AttemptCommission) (session_runtime.AttemptCommission, error) {
	var out session_runtime.AttemptCommission
	raw, err := json.Marshal(in)
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return out, err
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Routing.
// ---------------------------------------------------------------------------

// ServeHTTP routes the control surface. Unknown paths are 404; there is no
// whole-row update endpoint and no raw storage surface.
func (h *ControlHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	method := r.Method

	switch {
	case path == "/control/sessions" && method == http.MethodPost:
		h.handleAdmit(w, r)
		return
	case path == "/control/connector/cancel" && method == http.MethodPost:
		h.handleConnectorVerb(w, r, connector_transport.OpRequestNativeCancel)
		return
	case path == "/control/connector/close" && method == http.MethodPost:
		h.handleConnectorVerb(w, r, connector_transport.OpCloseObservationConnection)
		return
	case path == "/control/connector/release" && method == http.MethodPost:
		h.handleConnectorVerb(w, r, connector_transport.OpReleaseNativeContext)
		return
	case path == "/control/connector/contain" && method == http.MethodPost:
		h.handleConnectorVerb(w, r, connector_transport.OpContain)
		return
	}

	if !strings.HasPrefix(path, "/control/sessions/") {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "unknown control route")
		return
	}
	rest := strings.TrimPrefix(path, "/control/sessions/")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) != 2 || parts[0] == "" {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "unknown control route")
		return
	}
	sessionID, leaf := parts[0], parts[1]
	switch leaf {
	case "task":
		if method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "task is a read")
			return
		}
		h.handleTask(w, r, sessionID)
	case "dispatch":
		if method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "dispatch is a mutation")
			return
		}
		h.handleDispatch(w, r, sessionID)
	case "notes":
		if method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "notes is a mutation")
			return
		}
		h.handleNotes(w, r, sessionID)
	case "end-observation":
		if method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "end-observation is a mutation")
			return
		}
		h.handleEndObservation(w, r, sessionID)
	case "events":
		if method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "events is a read")
			return
		}
		h.handleEvents(w, r, sessionID)
	case "state":
		if method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "state is a read")
			return
		}
		h.handleState(w, r, sessionID)
	case "diagnostic":
		if method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "diagnostic is a read")
			return
		}
		h.handleDiagnostic(w, r, sessionID)
	case "export":
		if method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "export is a mutation")
			return
		}
		h.handleExport(w, r, sessionID)
	case "replay":
		if method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "replay is a mutation")
			return
		}
		h.handleReplay(w, r, sessionID)
	case "analyze":
		if method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "analyze is a mutation")
			return
		}
		h.handleAnalyze(w, r, sessionID)
	case "seal":
		if method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "seal is a mutation")
			return
		}
		h.handleSeal(w, r, sessionID)
	default:
		writeError(w, http.StatusNotFound, "NOT_FOUND", "unknown control route")
	}
}

// ---------------------------------------------------------------------------
// Admission.
// ---------------------------------------------------------------------------

type admitRequest struct {
	Manifest      admission.Manifest             `json:"manifest"`
	Commission    admission.AttemptCommission    `json:"commission"`
	Registrations []admission.EntityRegistration `json:"registrations"`
	ConnectorID   string                         `json:"connector_id"`
}

func (h *ControlHandler) handleAdmit(w http.ResponseWriter, r *http.Request) {
	ctx, principal, err := h.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED", err.Error())
		return
	}
	if err := authority.Authorize(ctx, "control", "admit", "global"); err != nil {
		writeError(w, http.StatusForbidden, "FORBIDDEN", err.Error())
		return
	}
	requestID := requestIDOf(r)
	if requestID == "" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Idempotency-Key is required")
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "cannot read body")
		return
	}
	if len(bytes.TrimSpace(body)) == 0 {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "admit body is required")
		return
	}
	var req admitRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "admit body is not valid JSON: "+err.Error())
		return
	}
	scope := strings.TrimSpace(req.ConnectorID)
	if scope == "" {
		scope = strings.TrimSpace(r.Header.Get("X-Connector-ID"))
	}
	if scope == "" {
		scope = "admit"
	}
	const operation = "admit"
	key := commandKey(principal, scope, operation, requestID)
	digest := digestOf(body)
	if retained, found, conflict := h.ledgerLookup(key, digest); found {
		if conflict {
			writeError(w, http.StatusConflict, "IDEMPOTENCY_CONFLICT", "conflicting content under idempotency key")
			return
		}
		w.Header().Set("X-Idempotent-Replayed", "true")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(retained.status)
		_, _ = w.Write(retained.body)
		return
	}
	// Hellscape admits practice laboratory fixtures exclusively. The handler
	// enforces the partition before touching the store; the admission saga
	// re-enforces it durably.
	a := req.Commission.Attempt
	if a.Kind != "practice" || req.Commission.Attempt.TargetClass != "laboratory_fixture" || a.EvaluationPartition != "held_in" {
		writeError(w, http.StatusForbidden, "FORBIDDEN", "Hellscape admits only practice/laboratory_fixture/held_in")
		return
	}
	if h.primary == nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "primary store is not configured")
		return
	}
	ref, err := h.admitFn(ctx, h.primary, req.Manifest, req.Commission, req.Registrations)
	if err != nil {
		if errors.Is(err, admission.ErrConflict) {
			writeError(w, http.StatusConflict, "IDEMPOTENCY_CONFLICT", err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	sessionID := strings.TrimSpace(req.Commission.Attempt.AttemptID)
	if sessionID == "" {
		sessionID = strings.TrimSpace(req.Manifest.RunID)
	}
	manifestRaw, _ := json.Marshal(req.Manifest)
	rec := &sessionRecord{
		sessionID:           sessionID,
		journalID:           req.Manifest.JournalID,
		runID:               req.Manifest.RunID,
		attemptKind:         a.Kind,
		targetClass:         a.TargetClass,
		partition:           a.EvaluationPartition,
		targetID:            a.TargetID,
		taskDigest:          req.Commission.Task.Digest,
		taskSemanticHash:    req.Commission.TaskSemanticHash,
		entryURL:            "/entry/" + sessionID,
		admissionRef:        ref,
		admissionPrefix:     admission.JournalPrefix{JournalID: ref.JournalID, LastSequence: ref.Sequence, HeadHash: ref.EventHash},
		admissionCommission: req.Commission,
		manifestRaw:         manifestRaw,
	}
	// The stored commission carries the actual admission event.
	rec.admissionCommission.AdmissionRef = ref
	h.putSession(rec)
	receiptID := receiptIDFor("receipt", key)
	resp := map[string]any{
		"receipt_id":   receiptID,
		"operation":    operation,
		"session_id":   sessionID,
		"journal_id":   req.Manifest.JournalID,
		"run_id":       req.Manifest.RunID,
		"admission_ref": map[string]any{
			"journal_id": ref.JournalID, "sequence": ref.Sequence,
			"event_id": ref.EventID, "event_hash": ref.EventHash, "pointer": ref.Pointer,
		},
		"task_digest":        rec.taskDigest,
		"task_semantic_hash": rec.taskSemanticHash,
		"entry_url":          rec.entryURL,
		"attempt": map[string]any{
			"kind": rec.attemptKind, "target_class": rec.targetClass,
			"evaluation_partition": rec.partition, "target_id": rec.targetID,
		},
		"evidence_refs": []any{},
		"limitations":   []any{},
	}
	raw, _ := json.Marshal(resp)
	h.ledgerStore(key, digest, http.StatusCreated, raw, receiptID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write(raw)
}

// ---------------------------------------------------------------------------
// Task read.
// ---------------------------------------------------------------------------

func (h *ControlHandler) handleTask(w http.ResponseWriter, r *http.Request, sessionID string) {
	ctx, _, err := h.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED", err.Error())
		return
	}
	if err := authority.Authorize(ctx, "control", "read", sessionID); err != nil {
		writeError(w, http.StatusForbidden, "FORBIDDEN", err.Error())
		return
	}
	rec, ok := h.getSession(sessionID)
	if !ok {
		writeError(w, http.StatusNotFound, "NOT_ADMITTED", "unknown session")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"session_id":         rec.sessionID,
		"task_digest":        rec.taskDigest,
		"task_semantic_hash": rec.taskSemanticHash,
		"entry_url":          rec.entryURL,
		"pinned_prefix": map[string]any{
			"journal_id": rec.admissionPrefix.JournalID,
			"last_sequence": rec.admissionPrefix.LastSequence,
			"head_hash":     rec.admissionPrefix.HeadHash,
		},
		"attempt": map[string]any{
			"kind": rec.attemptKind, "target_class": rec.targetClass,
			"evaluation_partition": rec.partition,
		},
		"evidence_refs": []any{},
		"limitations":   []any{},
	})
}

// ---------------------------------------------------------------------------
// Dispatch (practice only; never production).
// ---------------------------------------------------------------------------

type dispatchRequest struct {
	TargetClass string          `json:"target_class"`
	Kind        string          `json:"kind"`
	Production  bool            `json:"production"`
	ConnectorID string          `json:"connector_id"`
	Task        json.RawMessage `json:"task"`
}

func (h *ControlHandler) handleDispatch(w http.ResponseWriter, r *http.Request, sessionID string) {
	ctx, principal, err := h.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED", err.Error())
		return
	}
	if err := authority.Authorize(ctx, "control", "control", sessionID); err != nil {
		writeError(w, http.StatusForbidden, "FORBIDDEN", err.Error())
		return
	}
	requestID := requestIDOf(r)
	if requestID == "" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Idempotency-Key is required")
		return
	}
	rec, ok := h.getSession(sessionID)
	if !ok {
		writeError(w, http.StatusNotFound, "NOT_ADMITTED", "unknown session")
		return
	}
	// Practice sessions never dispatch production work, and production
	// requires an employer origin outside Hellscape.
	if rec.attemptKind != "practice" || rec.targetClass != "laboratory_fixture" || rec.partition != "held_in" {
		writeError(w, http.StatusForbidden, "FORBIDDEN", "only practice laboratory sessions dispatch here")
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "cannot read body")
		return
	}
	if len(bytes.TrimSpace(body)) == 0 {
		body = []byte(`{}`)
	}
	var req dispatchRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "dispatch body is not valid JSON")
		return
	}
	const operation = "dispatch"
	key := commandKey(principal, sessionID, operation, requestID)
	digest := digestOf(body)
	if retained, found, conflict := h.ledgerLookup(key, digest); found {
		if conflict {
			writeError(w, http.StatusConflict, "IDEMPOTENCY_CONFLICT", "conflicting content under idempotency key")
			return
		}
		w.Header().Set("X-Idempotent-Replayed", "true")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(retained.status)
		_, _ = w.Write(retained.body)
		return
	}
	if req.Production {
		writeError(w, http.StatusForbidden, "FORBIDDEN", "practice completion cannot trigger production dispatch")
		return
	}
	if req.Kind != "" && req.Kind != "practice" {
		writeError(w, http.StatusForbidden, "FORBIDDEN", "production dispatch requires an employer origin")
		return
	}
	if req.TargetClass != "" && req.TargetClass != "laboratory_fixture" {
		writeError(w, http.StatusForbidden, "FORBIDDEN", "production dispatch requires an employer origin")
		return
	}
	if strings.Contains(string(body), "employer_origin") {
		writeError(w, http.StatusForbidden, "FORBIDDEN", "production dispatch requires an employer origin")
		return
	}
	if h.ConnectorEndpoint == "" {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "connector endpoint is not configured")
		return
	}
	connectorID := strings.TrimSpace(req.ConnectorID)
	if connectorID == "" {
		connectorID = strings.TrimSpace(r.Header.Get("X-Connector-ID"))
	}
	if connectorID == "" {
		connectorID = sessionID
	}
	payload := map[string]any{
		"session_id": sessionID, "attempt_id": sessionID,
		"kind": "practice", "target_class": "laboratory_fixture",
		"evaluation_partition": "held_in",
		"task_digest":          rec.taskDigest,
	}
	if len(req.Task) > 0 {
		payload["task"] = json.RawMessage(req.Task)
	} else {
		payload["task"] = missing("not_observed")
	}
	payloadRaw, _ := json.Marshal(payload)
	creq := connector_transport.ConnectorRequest{
		RecordType:    connector_transport.RecordTypeRequest,
		SchemaVersion: connector_transport.SchemaVersion,
		RequestID:     requestID,
		ConnectorID:   connectorID,
		Operation:     connector_transport.OpStart,
		CallLimit:     connector_transport.DurationLimit{Kind: "exact", Unit: "ms", Value: 5000},
		Payload:       payloadRaw,
	}
	callCtx := connector_transport.ContextWithDeploymentEndpoints(ctx, []string{h.ConnectorEndpoint})
	resp, err := h.callConnectorFn(callCtx, h.ConnectorEndpoint, creq)
	if err != nil {
		var cerr *connector_transport.ConnectorError
		if errors.As(err, &cerr) {
			writeJSON(w, http.StatusBadGateway, map[string]any{
				"error_code": cerr.Code, "detail": cerr.Detail,
				"operation_delivery": cerr.OperationDelivery,
				"retry_guidance":     cerr.RetryGuidance,
				"evidence_refs":      []any{},
			})
			return
		}
		writeError(w, http.StatusBadGateway, "DELIVERY_UNCERTAIN", err.Error())
		return
	}
	receiptID := receiptIDFor("receipt", key)
	out := map[string]any{
		"receipt_id": receiptID, "operation": operation,
		"session_id": sessionID, "connector_id": connectorID,
		"request_id": requestID,
		"connector_response": map[string]any{
			"record_type": resp.RecordType, "schema_version": resp.SchemaVersion,
			"request_id": resp.RequestID, "connector_id": resp.ConnectorID,
			"operation": resp.Operation, "result": json.RawMessage(resp.Result),
		},
		"production_dispatched": false,
		"evidence_refs":         []any{},
		"limitations":           []any{},
	}
	raw, _ := json.Marshal(out)
	h.ledgerStore(key, digest, http.StatusOK, raw, receiptID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

// ---------------------------------------------------------------------------
// Manual notes (observation only; never origin facts).
// ---------------------------------------------------------------------------

var forbiddenBusinessKeys = map[string]bool{
	"committed": true, "not_committed": true, "verified": true,
	"submission_committed": true, "identity_verified": true,
	"commitment": true, "application_truth": true,
	"business_predicate": true, "accepted_data": true,
	"identity_verification": true,
}

var forbiddenNoteKinds = map[string]bool{
	"submission_committed": true, "identity_verified": true,
	"application_committed": true, "workflow_transition": true,
	"upload_stored": true, "validation_accepted": true,
	"validation_rejected": true, "validation_superseded": true,
	"request_completed": true, "request_rejected": true,
	"fixture_seal": true, "origin_fact": true,
	"commitment_asserted": true, "commitment": true,
	"application_truth": true,
	"manifest_admitted": true, "observation_opened": true,
	"observation_closed": true, "integrity_incident": true,
	"producer_flush": true, "producer_closure": true,
	"transport_close": true, "connection_close": true,
}

func (h *ControlHandler) handleNotes(w http.ResponseWriter, r *http.Request, sessionID string) {
	ctx, principal, err := h.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED", err.Error())
		return
	}
	if err := authority.Authorize(ctx, "control", "control", sessionID); err != nil {
		writeError(w, http.StatusForbidden, "FORBIDDEN", err.Error())
		return
	}
	requestID := requestIDOf(r)
	if requestID == "" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Idempotency-Key is required")
		return
	}
	rec, ok := h.getSession(sessionID)
	if !ok {
		writeError(w, http.StatusNotFound, "NOT_ADMITTED", "unknown session")
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "cannot read body")
		return
	}
	if len(bytes.TrimSpace(body)) == 0 {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "note body is required")
		return
	}
	const operation = "notes"
	key := commandKey(principal, sessionID, operation, requestID)
	digest := digestOf(body)
	if retained, found, conflict := h.ledgerLookup(key, digest); found {
		if conflict {
			writeError(w, http.StatusConflict, "IDEMPOTENCY_CONFLICT", "conflicting content under idempotency key")
			return
		}
		w.Header().Set("X-Idempotent-Replayed", "true")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(retained.status)
		_, _ = w.Write(retained.body)
		return
	}
	var note observation_owner.EventSubmission
	if err := json.Unmarshal(body, &note); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "note body is not valid JSON: "+err.Error())
		return
	}
	if strings.TrimSpace(note.EventKind) == "" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "event_kind is required")
		return
	}
	if forbiddenNoteKinds[note.EventKind] {
		writeError(w, http.StatusUnprocessableEntity, "FORBIDDEN_BUSINESS_PREDICATE", "manual note event_kind asserts authoritative or server-lifecycle semantics")
		return
	}
	if note.ProducerSequence == nil || note.OccurredAt == nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "producer_sequence and occurred_at must not be in-band nulls")
		return
	}
	for k := range note.Payload.Data {
		if forbiddenBusinessKeys[k] {
			writeError(w, http.StatusUnprocessableEntity, "FORBIDDEN_BUSINESS_PREDICATE", "manual note cannot set authoritative business predicate "+k)
			return
		}
	}
	if h.observation == nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "observation store is not configured")
		return
	}
	attempt := observation_owner.AttemptReference{AttemptID: rec.sessionID, Kind: rec.attemptKind}
	if attempt.Kind == "" {
		attempt.Kind = "practice"
	}
	ref, err := h.noteFn(ctx, h.observation, attempt, note)
	if err != nil {
		msg := err.Error()
		if strings.Contains(msg, "business predicate") || strings.Contains(msg, "authoritative") {
			writeError(w, http.StatusUnprocessableEntity, "FORBIDDEN_BUSINESS_PREDICATE", msg)
			return
		}
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", msg)
		return
	}
	receiptID := receiptIDFor("receipt", key)
	out := map[string]any{
		"receipt_id": receiptID, "operation": operation,
		"session_id": sessionID, "request_id": requestID,
		"evidence_ref": map[string]any{
			"journal_id": ref.JournalID, "sequence": ref.Sequence,
			"event_id": ref.EventID, "event_hash": ref.EventHash, "pointer": ref.Pointer,
		},
		"manual_provenance": "manual",
		"evidence_refs":     []any{},
		"limitations":       []any{},
	}
	raw, _ := json.Marshal(out)
	h.ledgerStore(key, digest, http.StatusCreated, raw, receiptID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write(raw)
}

// ---------------------------------------------------------------------------
// End observation (local close; never native cancel).
// ---------------------------------------------------------------------------

type endObservationRequest struct {
	Reason string `json:"reason"`
}

func (h *ControlHandler) handleEndObservation(w http.ResponseWriter, r *http.Request, sessionID string) {
	ctx, principal, err := h.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED", err.Error())
		return
	}
	if err := authority.Authorize(ctx, "control", "control", sessionID); err != nil {
		writeError(w, http.StatusForbidden, "FORBIDDEN", err.Error())
		return
	}
	requestID := requestIDOf(r)
	if requestID == "" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Idempotency-Key is required")
		return
	}
	rec, ok := h.getSession(sessionID)
	if !ok {
		writeError(w, http.StatusNotFound, "NOT_ADMITTED", "unknown session")
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "cannot read body")
		return
	}
	if len(bytes.TrimSpace(body)) == 0 {
		body = []byte(`{"reason":"normal_completion"}`)
	}
	const operation = "end_observation"
	key := commandKey(principal, sessionID, operation, requestID)
	digest := digestOf(body)
	if retained, found, conflict := h.ledgerLookup(key, digest); found {
		if conflict {
			writeError(w, http.StatusConflict, "IDEMPOTENCY_CONFLICT", "conflicting content under idempotency key")
			return
		}
		w.Header().Set("X-Idempotent-Replayed", "true")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(retained.status)
		_, _ = w.Write(retained.body)
		return
	}
	var req endObservationRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "end-observation body is not valid JSON")
		return
	}
	reason := session_runtime.CloseReason(strings.TrimSpace(req.Reason))
	if reason == "" {
		reason = session_runtime.CloseNormalCompletion
	}
	if !reason.Valid() {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "unknown close reason")
		return
	}
	runtimeCommission, err := convertCommission(rec.admissionCommission)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "cannot convert commission: "+err.Error())
		return
	}
	doc, err := h.finalizeFn(ctx, h.primary, h.application, h.observation, runtimeCommission, reason)
	if err != nil {
		writeError(w, http.StatusBadGateway, "FINALIZE_FAILED", err.Error())
		return
	}
	docRaw, _ := json.Marshal(doc)
	rec.diagnosticRaw = docRaw
	rec.hasDiagnostic = true
	// DiagnosticDocument.InputPrefix shares the journal prefix shape.
	rawPrefix, _ := json.Marshal(doc.InputPrefix)
	_ = json.Unmarshal(rawPrefix, &rec.diagnosticPrefix)
	h.putSession(rec)
	receiptID := receiptIDFor("receipt", key)
	operationID := receiptIDFor("op", key)
	controlEventID := receiptIDFor("cev", key)
	out := map[string]any{
		"receipt_id": receiptID, "operation": operation,
		"operation_id": operationID, "control_event_id": controlEventID,
		"session_id": sessionID, "request_id": requestID,
		"reason": string(reason),
		"native_cancel_requested": false,
		"diagnostic_id":           doc.DiagnosticID,
		"analysis_revision":       doc.AnalysisRevision,
		"input_prefix": map[string]any{
			"journal_id": doc.InputPrefix.JournalID,
			"last_sequence": doc.InputPrefix.LastSequence,
			"head_hash":     doc.InputPrefix.HeadHash,
		},
		"evidence_refs": []any{},
		"limitations":   []any{},
	}
	raw, _ := json.Marshal(out)
	h.ledgerStore(key, digest, http.StatusOK, raw, receiptID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

// ---------------------------------------------------------------------------
// Connector controls (four separately evidenced verbs).
// ---------------------------------------------------------------------------

func (h *ControlHandler) handleConnectorVerb(w http.ResponseWriter, r *http.Request, operation string) {
	ctx, principal, err := h.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED", err.Error())
		return
	}
	// Handler-level control authorization denies application credentials
	// even before the connector transport checks its own domain.
	if err := authority.Authorize(ctx, "control", operation, "connector"); err != nil {
		writeError(w, http.StatusForbidden, "FORBIDDEN", err.Error())
		return
	}
	requestID := requestIDOf(r)
	if requestID == "" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Idempotency-Key is required")
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "cannot read body")
		return
	}
	if len(bytes.TrimSpace(body)) == 0 {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "connector request body is required")
		return
	}
	var creq connector_transport.ConnectorRequest
	if err := json.Unmarshal(body, &creq); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "connector request is not valid JSON")
		return
	}
	if creq.Operation != "" && creq.Operation != operation {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "operation mismatch: route "+operation+" body "+creq.Operation)
		return
	}
	creq.Operation = operation
	headerConnector := strings.TrimSpace(r.Header.Get("X-Connector-ID"))
	if creq.ConnectorID != "" && headerConnector != "" && creq.ConnectorID != headerConnector {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "connector_id mismatch between body and header")
		return
	}
	connectorID := creq.ConnectorID
	if connectorID == "" {
		connectorID = headerConnector
	}
	if connectorID == "" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "connector_id is required")
		return
	}
	creq.ConnectorID = connectorID
	if creq.RequestID != "" && creq.RequestID != requestID {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "request_id mismatch between body and Idempotency-Key")
		return
	}
	creq.RequestID = requestID
	if creq.RecordType == "" {
		creq.RecordType = connector_transport.RecordTypeRequest
	}
	if creq.SchemaVersion == "" {
		creq.SchemaVersion = connector_transport.SchemaVersion
	}
	key := commandKey(principal, connectorID, operation, requestID)
	// The digest binds the full connector request bytes so conflicting
	// content under one command key is rejected.
	canonicalReq, _ := json.Marshal(creq)
	digest := digestOf(canonicalReq)
	if retained, found, conflict := h.ledgerLookup(key, digest); found {
		if conflict {
			writeError(w, http.StatusConflict, "IDEMPOTENCY_CONFLICT", "conflicting content under idempotency key")
			return
		}
		w.Header().Set("X-Idempotent-Replayed", "true")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(retained.status)
		_, _ = w.Write(retained.body)
		return
	}
	if h.ConnectorEndpoint == "" {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "connector endpoint is not configured")
		return
	}
	callCtx := connector_transport.ContextWithDeploymentEndpoints(ctx, []string{h.ConnectorEndpoint})
	resp, err := h.callConnectorFn(callCtx, h.ConnectorEndpoint, creq)
	if err != nil {
		var cerr *connector_transport.ConnectorError
		if errors.As(err, &cerr) {
			// A control failure is reported as this operation only. It
			// never silently triggers a different control verb.
			writeJSON(w, http.StatusBadGateway, map[string]any{
				"error_code": cerr.Code, "detail": cerr.Detail,
				"operation": operation, "operation_delivery": cerr.OperationDelivery,
				"retry_guidance": cerr.RetryGuidance,
				"contained":      false,
				"evidence_refs":  []any{},
			})
			return
		}
		writeError(w, http.StatusBadGateway, "DELIVERY_UNCERTAIN", err.Error())
		return
	}
	disposition := "requested"
	limitations := []any{}
	if len(resp.Result) > 0 {
		var resultObj map[string]any
		if err := json.Unmarshal(resp.Result, &resultObj); err == nil {
			if d, _ := resultObj["disposition"].(string); d != "" {
				disposition = d
			}
		}
	}
	// A request is not an acknowledgement and an acknowledgement is not an
	// observed effect. Without independent effect evidence the handler
	// never reports effect_observed.
	if disposition == "effect_observed" || disposition == "effect-observed" {
		disposition = "acknowledged"
		limitations = append(limitations, "effect_observed requires independent effect evidence; capped at acknowledged")
	}
	receiptID := receiptIDFor("receipt", key)
	operationID := receiptIDFor("op", key)
	controlEventID := receiptIDFor("cev", key)
	out := map[string]any{
		"receipt_id": receiptID, "operation": operation,
		"operation_id": operationID, "control_event_id": controlEventID,
		"connector_id": connectorID, "request_id": requestID,
		"disposition": disposition,
		"connector_response": map[string]any{
			"record_type": resp.RecordType, "schema_version": resp.SchemaVersion,
			"request_id": resp.RequestID, "connector_id": resp.ConnectorID,
			"operation": resp.Operation, "result": json.RawMessage(resp.Result),
		},
		"effect_observed": false,
		"evidence_refs":   []any{},
		"limitations":     limitations,
	}
	raw, _ := json.Marshal(out)
	h.ledgerStore(key, digest, http.StatusOK, raw, receiptID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

// ---------------------------------------------------------------------------
// Reads (pinned source + staleness; never cached idempotently).
// ---------------------------------------------------------------------------

func storeForName(h *ControlHandler, name string) *OwnerStore {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "primary", "diagnostic":
		return h.primary
	case "application":
		return h.application
	case "observation":
		return h.observation
	default:
		return nil
	}
}

func parsePrefixQuery(r *http.Request) (owner_store.JournalPrefix, error) {
	q := r.URL.Query()
	journalID := strings.TrimSpace(q.Get("journal_id"))
	headHash := strings.TrimSpace(q.Get("head_hash"))
	seqStr := strings.TrimSpace(q.Get("last_sequence"))
	var prefix owner_store.JournalPrefix
	if journalID == "" || headHash == "" || seqStr == "" {
		return prefix, errors.New("journal_id, last_sequence, and head_hash are required")
	}
	seq, err := strconv.ParseInt(seqStr, 10, 64)
	if err != nil || seq < 1 {
		return prefix, errors.New("last_sequence must be a positive integer")
	}
	return owner_store.JournalPrefix{JournalID: journalID, LastSequence: seq, HeadHash: headHash}, nil
}

func (h *ControlHandler) handleEvents(w http.ResponseWriter, r *http.Request, sessionID string) {
	ctx, _, err := h.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED", err.Error())
		return
	}
	if err := authority.Authorize(ctx, "control", "read", sessionID); err != nil {
		writeError(w, http.StatusForbidden, "FORBIDDEN", err.Error())
		return
	}
	if _, ok := h.getSession(sessionID); !ok {
		writeError(w, http.StatusNotFound, "NOT_ADMITTED", "unknown session")
		return
	}
	prefix, err := parsePrefixQuery(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	store := storeForName(h, r.URL.Query().Get("store"))
	if store == nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "unknown store")
		return
	}
	events, err := h.loadPrefixFn(ctx, store, prefix)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	head, err := h.probeHeadSequence(ctx, store, prefix.JournalID)
	if err != nil {
		head = prefix.LastSequence
	}
	stale := prefix.LastSequence < head
	if events == nil {
		events = []owner_store.JournalEnvelope{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"session_id": sessionID,
		"pinned_prefix": map[string]any{
			"journal_id": prefix.JournalID, "last_sequence": prefix.LastSequence, "head_hash": prefix.HeadHash,
		},
		"pinned_events":    events,
		"pinned_count":     len(events),
		"current_sequence": head,
		"stale":            stale,
		"evidence_refs":    []any{},
		"limitations":      []any{},
	})
}

func (h *ControlHandler) handleState(w http.ResponseWriter, r *http.Request, sessionID string) {
	ctx, _, err := h.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED", err.Error())
		return
	}
	if err := authority.Authorize(ctx, "control", "read", sessionID); err != nil {
		writeError(w, http.StatusForbidden, "FORBIDDEN", err.Error())
		return
	}
	rec, ok := h.getSession(sessionID)
	if !ok {
		writeError(w, http.StatusNotFound, "NOT_ADMITTED", "unknown session")
		return
	}
	pinned := owner_store.JournalPrefix{JournalID: rec.admissionPrefix.JournalID, LastSequence: rec.admissionPrefix.LastSequence, HeadHash: rec.admissionPrefix.HeadHash}
	head := pinned.LastSequence
	if h.primary != nil && pinned.JournalID != "" {
		if probed, err := h.probeHeadSequence(ctx, h.primary, pinned.JournalID); err == nil {
			head = probed
		}
	}
	stale := pinned.LastSequence < head
	out := map[string]any{
		"session_id": sessionID,
		"pinned_prefix": map[string]any{
			"journal_id": pinned.JournalID, "last_sequence": pinned.LastSequence, "head_hash": pinned.HeadHash,
		},
		"current_sequence": head,
		"stale":            stale,
		"attempt": map[string]any{
			"kind": rec.attemptKind, "target_class": rec.targetClass,
			"evaluation_partition": rec.partition,
		},
		"task_digest":   rec.taskDigest,
		"entry_url":     rec.entryURL,
		"evidence_refs": []any{},
		"limitations":   []any{},
	}
	if rec.hasDiagnostic {
		var diag map[string]any
		if err := json.Unmarshal(rec.diagnosticRaw, &diag); err == nil {
			out["diagnostic_id"] = diag["diagnostic_id"]
			out["analysis_revision"] = diag["analysis_revision"]
		}
	} else {
		out["diagnostic_id"] = missing("not_observed")
		out["analysis_revision"] = missing("not_observed")
	}
	// Optional sealed-row display. The seal selection pins the complete
	// version vector; readers compare it with their pinned diagnostic.
	if viewID := strings.TrimSpace(r.URL.Query().Get("seal_view")); viewID != "" {
		name := strings.TrimSpace(r.URL.Query().Get("seal_name"))
		if name == "" {
			name = "evidence_updated"
		}
		regRaw := strings.TrimSpace(r.URL.Query().Get("registration"))
		if regRaw != "" {
			var reg publication.EntityRegistration
			if err := json.Unmarshal([]byte(regRaw), &reg); err == nil {
				if row, err := h.sealFn(ctx, h.primary, reg, name, viewID); err == nil {
					out["sealed_row"] = row
				} else {
					out["seal_error"] = err.Error()
				}
			}
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *ControlHandler) handleDiagnostic(w http.ResponseWriter, r *http.Request, sessionID string) {
	ctx, _, err := h.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED", err.Error())
		return
	}
	if err := authority.Authorize(ctx, "control", "read", sessionID); err != nil {
		writeError(w, http.StatusForbidden, "FORBIDDEN", err.Error())
		return
	}
	rec, ok := h.getSession(sessionID)
	if !ok {
		writeError(w, http.StatusNotFound, "NOT_ADMITTED", "unknown session")
		return
	}
	// The pinned prefix is the diagnostic input when the caller pins it
	// explicitly, otherwise the admission prefix. Either way the handler
	// displays the pinned source and reports staleness against the live head.
	pinned := owner_store.JournalPrefix{JournalID: rec.admissionPrefix.JournalID, LastSequence: rec.admissionPrefix.LastSequence, HeadHash: rec.admissionPrefix.HeadHash}
	if q := r.URL.Query(); q.Get("journal_id") != "" || q.Get("last_sequence") != "" || q.Get("head_hash") != "" {
		p, err := parsePrefixQuery(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
			return
		}
		pinned = p
	}
	if rec.hasDiagnostic && r.URL.Query().Get("journal_id") == "" {
		// Prefer the finalized diagnostic input prefix when the caller did
		// not pin explicitly.
		if rec.diagnosticPrefix.JournalID != "" {
			pinned = rec.diagnosticPrefix
		}
	}
	store := storeForName(h, r.URL.Query().Get("store"))
	if store == nil {
		store = h.primary
	}
	events, err := h.loadPrefixFn(ctx, store, pinned)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	head, err := h.probeHeadSequence(ctx, store, pinned.JournalID)
	if err != nil {
		head = pinned.LastSequence
	}
	stale := pinned.LastSequence < head
	if events == nil {
		events = []owner_store.JournalEnvelope{}
	}
	out := map[string]any{
		"session_id": sessionID,
		"pinned_prefix": map[string]any{
			"journal_id": pinned.JournalID, "last_sequence": pinned.LastSequence, "head_hash": pinned.HeadHash,
		},
		"pinned_count":     len(events),
		"pinned_source":    events,
		"current_sequence": head,
		"stale":            stale,
		"evidence_refs":    []any{},
		"limitations":      []any{},
	}
	if rec.hasDiagnostic {
		var diag map[string]any
		if err := json.Unmarshal(rec.diagnosticRaw, &diag); err == nil {
			out["diagnostic"] = diag
			out["diagnostic_id"] = diag["diagnostic_id"]
			out["analysis_revision"] = diag["analysis_revision"]
		}
	} else {
		out["diagnostic"] = missing("not_observed")
		out["diagnostic_id"] = missing("not_observed")
		out["analysis_revision"] = missing("not_observed")
	}
	writeJSON(w, http.StatusOK, out)
}

// ---------------------------------------------------------------------------
// Export (ordered inputs -> replay -> acceptance -> validation).
// ---------------------------------------------------------------------------

type exportRequest struct {
	Row        evidence_bundle.LogicalRow        `json:"row"`
	Diagnostic evidence_bundle.DiagnosticDocument `json:"diagnostic"`
	Mode       string                            `json:"mode"`
}

func (h *ControlHandler) handleExport(w http.ResponseWriter, r *http.Request, sessionID string) {
	ctx, principal, err := h.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED", err.Error())
		return
	}
	if err := authority.Authorize(ctx, "control", "control", sessionID); err != nil {
		writeError(w, http.StatusForbidden, "FORBIDDEN", err.Error())
		return
	}
	requestID := requestIDOf(r)
	if requestID == "" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Idempotency-Key is required")
		return
	}
	if _, ok := h.getSession(sessionID); !ok {
		writeError(w, http.StatusNotFound, "NOT_ADMITTED", "unknown session")
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "cannot read body")
		return
	}
	if len(bytes.TrimSpace(body)) == 0 {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "export body is required")
		return
	}
	const operation = "export"
	key := commandKey(principal, sessionID, operation, requestID)
	digest := digestOf(body)
	if retained, found, conflict := h.ledgerLookup(key, digest); found {
		if conflict {
			writeError(w, http.StatusConflict, "IDEMPOTENCY_CONFLICT", "conflicting content under idempotency key")
			return
		}
		w.Header().Set("X-Idempotent-Replayed", "true")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(retained.status)
		_, _ = w.Write(retained.body)
		return
	}
	var req exportRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "export body is not valid JSON")
		return
	}
	mode := strings.TrimSpace(req.Mode)
	if mode == "" {
		mode = "exact_fixture"
	}
	if mode != "exact_fixture" && mode != "diagnostic_only" && mode != "diagnostic_rederivation" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "unknown replay mode")
		return
	}
	if h.primary == nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "primary store is not configured")
		return
	}
	// Step 1: ordered replay inputs first. The input bundle never contains
	// its future receipt.
	inputsRef, err := h.exportInputsFn(ctx, h.primary, req.Row, req.Diagnostic)
	if err != nil {
		writeError(w, http.StatusBadGateway, "EXPORT_FAILED", "export inputs: "+err.Error())
		return
	}
	// Step 2: replay the inputs. Replay never sleeps and never invokes a
	// browser, subject, or external mutation.
	diagBytes, _ := json.Marshal(req.Diagnostic)
	sourceDiagRef, err := h.installFn(ctx, h.primary, bytes.NewReader(diagBytes), "application/json", "restricted")
	if err != nil {
		writeError(w, http.StatusBadGateway, "EXPORT_FAILED", "install source diagnostic: "+err.Error())
		return
	}
	// Convert installed ref to the bundle artifact shape (shared alias).
	var sourceBundleRef evidence_bundle.ArtifactReference
	rawRef, _ := json.Marshal(sourceDiagRef)
	_ = json.Unmarshal(rawRef, &sourceBundleRef)
	receipt, err := h.replayFn(ctx, h.primary, inputsRef, sourceBundleRef, mode)
	if err != nil {
		writeError(w, http.StatusBadGateway, "EXPORT_FAILED", "replay: "+err.Error())
		return
	}
	if receipt.InvokedBrowser || receipt.InvokedSubject || receipt.PerformedExternalWrites {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "replay invoked execution")
		return
	}
	// Step 3: acceptance checks over the inputs plus the receipt.
	checksBytes, err := h.checkFn(ctx, h.primary, inputsRef, receipt)
	if err != nil {
		writeError(w, http.StatusBadGateway, "EXPORT_FAILED", "acceptance: "+err.Error())
		return
	}
	if len(checksBytes) == 0 {
		writeError(w, http.StatusBadGateway, "EXPORT_FAILED", "acceptance returned no bytes")
		return
	}
	checksRef, err := h.installFn(ctx, h.primary, bytes.NewReader(checksBytes), "application/json", "restricted")
	if err != nil {
		writeError(w, http.StatusBadGateway, "EXPORT_FAILED", "install checks: "+err.Error())
		return
	}
	var checksBundleRef evidence_bundle.ArtifactReference
	rawChecks, _ := json.Marshal(checksRef)
	_ = json.Unmarshal(rawChecks, &checksBundleRef)
	// Step 4: validation bundle last. It binds inputs, receipt, and checks.
	validationRef, err := h.exportValidationFn(ctx, h.primary, req.Row, req.Diagnostic, receipt, checksBundleRef)
	if err != nil {
		writeError(w, http.StatusBadGateway, "EXPORT_FAILED", "export validation: "+err.Error())
		return
	}
	// Hash-cycle fence: inputs, checks, and validation are distinct
	// identities; the receipt references exactly these inputs and never
	// appears inside them.
	if inputsRef.Digest == validationRef.Digest {
		writeError(w, http.StatusInternalServerError, "HASH_CYCLE", "validation bundle reuses the inputs digest")
		return
	}
	if inputsRef.Digest == checksBundleRef.Digest {
		writeError(w, http.StatusInternalServerError, "HASH_CYCLE", "checks bundle reuses the inputs digest")
		return
	}
	if receipt.InputBundle.Digest != "" && receipt.InputBundle.Digest != inputsRef.Digest {
		writeError(w, http.StatusInternalServerError, "HASH_CYCLE", "receipt does not reference these inputs")
		return
	}
	receiptID := receiptIDFor("receipt", key)
	out := map[string]any{
		"receipt_id": receiptID, "operation": operation,
		"session_id": sessionID, "request_id": requestID,
		"mode":             mode,
		"inputs":           inputsRef,
		"receipt":          receipt,
		"checks":           checksBundleRef,
		"checks_size":      len(checksBytes),
		"validation":       validationRef,
		"invoked_browser":  false,
		"invoked_subject":  false,
		"performed_external_writes": false,
		"evidence_refs":             []any{},
		"limitations":               []any{},
	}
	raw, _ := json.Marshal(out)
	h.ledgerStore(key, digest, http.StatusOK, raw, receiptID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

// ---------------------------------------------------------------------------
// Replay.
// ---------------------------------------------------------------------------

type replayRequest struct {
	Bundle           evidence_bundle.ArtifactReference `json:"bundle"`
	SourceDiagnostic evidence_bundle.ArtifactReference `json:"source_diagnostic"`
	Mode             string                            `json:"mode"`
}

func (h *ControlHandler) handleReplay(w http.ResponseWriter, r *http.Request, sessionID string) {
	ctx, principal, err := h.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED", err.Error())
		return
	}
	if err := authority.Authorize(ctx, "control", "control", sessionID); err != nil {
		writeError(w, http.StatusForbidden, "FORBIDDEN", err.Error())
		return
	}
	requestID := requestIDOf(r)
	if requestID == "" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Idempotency-Key is required")
		return
	}
	if _, ok := h.getSession(sessionID); !ok {
		writeError(w, http.StatusNotFound, "NOT_ADMITTED", "unknown session")
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "cannot read body")
		return
	}
	if len(bytes.TrimSpace(body)) == 0 {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "replay body is required")
		return
	}
	const operation = "replay"
	key := commandKey(principal, sessionID, operation, requestID)
	digest := digestOf(body)
	if retained, found, conflict := h.ledgerLookup(key, digest); found {
		if conflict {
			writeError(w, http.StatusConflict, "IDEMPOTENCY_CONFLICT", "conflicting content under idempotency key")
			return
		}
		w.Header().Set("X-Idempotent-Replayed", "true")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(retained.status)
		_, _ = w.Write(retained.body)
		return
	}
	var req replayRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "replay body is not valid JSON")
		return
	}
	mode := strings.TrimSpace(req.Mode)
	if mode == "" {
		mode = "exact_fixture"
	}
	receipt, err := h.replayFn(ctx, h.primary, req.Bundle, req.SourceDiagnostic, mode)
	if err != nil {
		writeError(w, http.StatusBadGateway, "REPLAY_FAILED", err.Error())
		return
	}
	if receipt.InvokedBrowser || receipt.InvokedSubject || receipt.PerformedExternalWrites {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "replay invoked execution")
		return
	}
	receiptID := receiptIDFor("receipt", key)
	out := map[string]any{
		"receipt_id": receiptID, "operation": operation,
		"session_id": sessionID, "request_id": requestID,
		"receipt": receipt,
		"evidence_refs": []any{},
		"limitations":   []any{},
	}
	raw, _ := json.Marshal(out)
	h.ledgerStore(key, digest, http.StatusOK, raw, receiptID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

// ---------------------------------------------------------------------------
// Analyze and seal (typed owner boundaries).
// ---------------------------------------------------------------------------

type analyzeRequest struct {
	Manifest analysis_owner.Manifest        `json:"manifest"`
	Request  analysis_owner.AnalysisRequest `json:"request"`
}

func (h *ControlHandler) handleAnalyze(w http.ResponseWriter, r *http.Request, sessionID string) {
	ctx, principal, err := h.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED", err.Error())
		return
	}
	if err := authority.Authorize(ctx, "control", "control", sessionID); err != nil {
		writeError(w, http.StatusForbidden, "FORBIDDEN", err.Error())
		return
	}
	requestID := requestIDOf(r)
	if requestID == "" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Idempotency-Key is required")
		return
	}
	if _, ok := h.getSession(sessionID); !ok {
		writeError(w, http.StatusNotFound, "NOT_ADMITTED", "unknown session")
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "cannot read body")
		return
	}
	const operation = "analyze"
	key := commandKey(principal, sessionID, operation, requestID)
	digest := digestOf(body)
	if retained, found, conflict := h.ledgerLookup(key, digest); found {
		if conflict {
			writeError(w, http.StatusConflict, "IDEMPOTENCY_CONFLICT", "conflicting content under idempotency key")
			return
		}
		w.Header().Set("X-Idempotent-Replayed", "true")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(retained.status)
		_, _ = w.Write(retained.body)
		return
	}
	var req analyzeRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "analyze body is not valid JSON")
		return
	}
	doc, err := h.analyzeFn(ctx, h.primary, req.Manifest, req.Request)
	if err != nil {
		writeError(w, http.StatusBadGateway, "ANALYZE_FAILED", err.Error())
		return
	}
	receiptID := receiptIDFor("receipt", key)
	out := map[string]any{
		"receipt_id": receiptID, "operation": operation,
		"session_id": sessionID, "diagnostic": doc,
		"evidence_refs": []any{}, "limitations": []any{},
	}
	raw, _ := json.Marshal(out)
	h.ledgerStore(key, digest, http.StatusOK, raw, receiptID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

type sealRequest struct {
	Registration publication.EntityRegistration `json:"registration"`
	Name         string                         `json:"name"`
	ViewID       string                         `json:"view_id"`
}

func (h *ControlHandler) handleSeal(w http.ResponseWriter, r *http.Request, sessionID string) {
	ctx, principal, err := h.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED", err.Error())
		return
	}
	if err := authority.Authorize(ctx, "control", "control", sessionID); err != nil {
		writeError(w, http.StatusForbidden, "FORBIDDEN", err.Error())
		return
	}
	requestID := requestIDOf(r)
	if requestID == "" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Idempotency-Key is required")
		return
	}
	if _, ok := h.getSession(sessionID); !ok {
		writeError(w, http.StatusNotFound, "NOT_ADMITTED", "unknown session")
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "cannot read body")
		return
	}
	const operation = "seal"
	key := commandKey(principal, sessionID, operation, requestID)
	digest := digestOf(body)
	if retained, found, conflict := h.ledgerLookup(key, digest); found {
		if conflict {
			writeError(w, http.StatusConflict, "IDEMPOTENCY_CONFLICT", "conflicting content under idempotency key")
			return
		}
		w.Header().Set("X-Idempotent-Replayed", "true")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(retained.status)
		_, _ = w.Write(retained.body)
		return
	}
	var req sealRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "seal body is not valid JSON")
		return
	}
	if strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.ViewID) == "" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "name and view_id are required")
		return
	}
	row, err := h.sealFn(ctx, h.primary, req.Registration, req.Name, req.ViewID)
	if err != nil {
		writeError(w, http.StatusBadGateway, "SEAL_FAILED", err.Error())
		return
	}
	receiptID := receiptIDFor("receipt", key)
	out := map[string]any{
		"receipt_id": receiptID, "operation": operation,
		"session_id": sessionID, "row": row,
		"evidence_refs": []any{}, "limitations": []any{},
	}
	raw, _ := json.Marshal(out)
	h.ledgerStore(key, digest, http.StatusOK, raw, receiptID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

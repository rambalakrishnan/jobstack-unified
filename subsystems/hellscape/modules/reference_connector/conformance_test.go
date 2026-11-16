package reference_connector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"authority"
	"evidence_codec"
	native_mapping "native_mapping"
	owner_store "owner_store"
)

// ---------------------------------------------------------------------------
// Test fixtures.
// ---------------------------------------------------------------------------

func testPolicy() []byte {
	return []byte(`{"channels":{"test-channel":{"principal":"test-writer","kind":"owner","grants":[{"domain":"*","operations":["*"]}]}}}`)
}

func connectorOnlyPolicy() []byte {
	return []byte(`{"channels":{"conn-channel":{"principal":"conn-writer","kind":"owner","grants":[{"domain":"connector","operations":["*"]}]}}}`)
}

func testContext(t *testing.T) context.Context {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "http://connector.test/connector", nil)
	if err != nil {
		t.Fatalf("build auth request: %v", err)
	}
	req.Header.Set("Authorization", "Channel test-channel")
	ctx, err := authority.Authenticate(req, testPolicy())
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	return ctx
}

func connectorOnlyContext(t *testing.T) context.Context {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "http://connector.test/connector", nil)
	if err != nil {
		t.Fatalf("build auth request: %v", err)
	}
	req.Header.Set("Authorization", "Channel conn-channel")
	ctx, err := authority.Authenticate(req, connectorOnlyPolicy())
	if err != nil {
		t.Fatalf("authenticate connector-only: %v", err)
	}
	return ctx
}

func openStore(t *testing.T) *OwnerStore {
	t.Helper()
	home := t.TempDir()
	store, err := owner_store.OpenOwner(
		filepath.Join(home, "connector.db"),
		filepath.Join(home, "artifacts"),
		"connector",
	)
	if err != nil {
		t.Fatalf("OpenOwner: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func testDigest(seed string) string {
	return string(evidence_codec.HashBytes([]byte(seed)))
}

func testEvidenceRef(journalID string, seq int64, eventID string) EvidenceRef {
	return EvidenceRef{
		JournalID: journalID, Sequence: seq, EventID: eventID,
		EventHash: testDigest("event-" + eventID), Pointer: "",
	}
}

func testVersionPin(id, version, seed string) VersionPin {
	return VersionPin{ID: id, Version: version, ArtifactDigest: testDigest(seed)}
}

func testDescriptor(contractDigest string) ConnectorDescriptor {
	caps := []Capability{}
	for _, id := range minimumCapabilityIDs {
		caps = append(caps, Capability{ID: id, Availability: "available", EvidenceRefs: []EvidenceRef{}, Limitations: []string{}})
	}
	ops := []OperationMapping{
		{Operation: OpDescribe, Implementation: "connector-local", NativeContract: map[string]any{"value": nil, "reason": "not_applicable"}, CapabilityRefs: []string{}, EvidenceRefs: []EvidenceRef{}, Limitations: []string{}},
		{Operation: OpPrepare, Implementation: "connector-local", NativeContract: map[string]any{"value": nil, "reason": "not_applicable"}, CapabilityRefs: []string{}, EvidenceRefs: []EvidenceRef{}, Limitations: []string{}},
		{Operation: OpStart, Implementation: "native-mapping", NativeContract: testVersionPin("native-start", "v1", "native-start-v1"), CapabilityRefs: []string{"native_goal_task"}, EvidenceRefs: []EvidenceRef{}, Limitations: []string{}, NativeEndpoint: "http://native.test/start"},
		{Operation: OpObserve, Implementation: "connector-local", NativeContract: map[string]any{"value": nil, "reason": "not_applicable"}, CapabilityRefs: []string{}, EvidenceRefs: []EvidenceRef{}, Limitations: []string{}},
		{Operation: OpRequestNativeCancel, Implementation: "native-mapping", NativeContract: testVersionPin("native-cancel", "v1", "native-cancel-v1"), CapabilityRefs: []string{"native_cancel"}, EvidenceRefs: []EvidenceRef{}, Limitations: []string{}, NativeEndpoint: "http://native.test/cancel"},
		{Operation: OpCloseObservationConnection, Implementation: "connector-local", NativeContract: map[string]any{"value": nil, "reason": "not_applicable"}, CapabilityRefs: []string{}, EvidenceRefs: []EvidenceRef{}, Limitations: []string{}},
		{Operation: OpCollectArtifacts, Implementation: "connector-local", NativeContract: map[string]any{"value": nil, "reason": "not_applicable"}, CapabilityRefs: []string{"native_artifact_retrieval"}, EvidenceRefs: []EvidenceRef{}, Limitations: []string{}},
		{Operation: OpReleaseNativeContext, Implementation: "native-mapping", NativeContract: testVersionPin("native-release", "v1", "native-release-v1"), CapabilityRefs: []string{"native_context_release"}, EvidenceRefs: []EvidenceRef{}, Limitations: []string{}, NativeEndpoint: "http://native.test/release"},
		{Operation: OpContain, Implementation: "connector-local", NativeContract: map[string]any{"value": nil, "reason": "not_applicable"}, CapabilityRefs: []string{}, EvidenceRefs: []EvidenceRef{}, Limitations: []string{}},
	}
	return ConnectorDescriptor{
		RecordType: RecordTypeDescriptor, SchemaVersion: SchemaVersion,
		ConnectorID: "test-connector", ConnectorVersion: "m1-test",
		Build:   testVersionPin("test-build", "m1", "build-m1"),
		Binding: VersionPin{ID: "test-binding", Version: "m1", ArtifactDigest: contractDigest},
		Subject: SubjectIdentity{
			SubjectID: "test-subject", SubjectVersion: "v1", RevisionBasis: "operator_attestation",
			NativeRevision: map[string]any{"value": nil, "reason": "not_applicable"},
			ConfiguredMode: "cooperative", InterfaceSurface: "browser",
			ConfigurationDigest: testDigest("subject-config"), Stack: []any{},
		},
		Capabilities: caps, Operations: ops,
		TaskMappings: []TaskMapping{
			{TaskType: "apply", InputForm: "task_envelope", Mapping: testVersionPin("native-mapping", "m1-1", "mapping-m1-1"), PlanningOwner: "subject", RecoveryOwner: "connector", Limitations: []string{}},
			{TaskType: "extract", InputForm: "task_envelope", Mapping: testVersionPin("native-mapping", "m1-1", "mapping-m1-1"), PlanningOwner: "subject", RecoveryOwner: "connector", Limitations: []string{}},
			{TaskType: "discover_jobs", InputForm: "task_envelope", Mapping: testVersionPin("native-mapping", "m1-1", "mapping-m1-1"), PlanningOwner: "subject", RecoveryOwner: "connector", Limitations: []string{}},
		},
		ObservationChannels: []string{"terminal_response", "callback", "native_stream"},
		ActionGrounding:     map[string]any{"mode": "ordinary_browser"},
		ExecutionSubstrate:  "browser",
		Limits: DescriptorLimits{
			MaxCallWait: DurationLimit{Kind: "exact", Unit: "ms", Value: 60000},
			MaxObservationItems: 1000, MaxRequestBytes: 4 << 20, MaxResponseBytes: 8 << 20,
			MaxArtifactChunkBytes: 1 << 20, MaxQueuedTasks: 10, MaxActiveTasks: 5,
		},
		BudgetAccounting: testVersionPin("budget", "v1", "budget-v1"),
		EvidencePrefix:   map[string]any{"value": nil, "reason": "not_applicable"},
	}
}

func setCapability(desc *ConnectorDescriptor, id, availability string, evidence []EvidenceRef) {
	for i := range desc.Capabilities {
		if desc.Capabilities[i].ID == id {
			desc.Capabilities[i].Availability = availability
			if evidence != nil {
				desc.Capabilities[i].EvidenceRefs = evidence
			}
			return
		}
	}
}

func setOperation(desc *ConnectorDescriptor, op, impl, endpoint string) {
	for i := range desc.Operations {
		if desc.Operations[i].Operation == op {
			desc.Operations[i].Implementation = impl
			desc.Operations[i].NativeEndpoint = endpoint
			return
		}
	}
}

func installContract(t *testing.T, ctx context.Context, store *OwnerStore) string {
	t.Helper()
	content := []byte(`{"contract":"test-signing-contract","version":"m1"}`)
	digest := string(evidence_codec.HashBytes(content))
	_, err := owner_store.InstallArtifact(ctx, store, bytes.NewReader(content), "application/json", "public")
	if err != nil {
		t.Fatalf("InstallArtifact(contract): %v", err)
	}
	return digest
}

// --- native_mapping request builders matching the descriptor ---

func nmDurationLimit(ms float64) native_mapping.DurationLimit {
	return native_mapping.DurationLimit{Kind: "exact", Unit: "ms", Value: ms}
}

func nmEvidenceRef(journalID string, seq int64, eventID string) native_mapping.EvidenceRef {
	return native_mapping.EvidenceRef{
		JournalID: journalID, Sequence: seq, EventID: eventID,
		EventHash: testDigest("event-" + eventID), Pointer: "",
	}
}

func nmScopeForApply() native_mapping.WorkScope {
	return native_mapping.WorkScope{
		Activity: "application_attempt", RunID: "run-1", JournalID: "journal-1",
		ManifestHash: testDigest("manifest-1"),
		AdmissionRef: nmEvidenceRef("journal-1", 1, "admit-1"),
		Attempt: native_mapping.AttemptContext{
			AttemptID: "attempt-1", Kind: "practice", TargetClass: "laboratory_fixture",
			TargetID: "fixture-1", EvaluationPartition: "held_in",
			RehearsalOf: []string{}, PerformanceOf: []string{}, DerivedFrom: []string{},
		},
		Commission: native_mapping.ArtifactReference{
			Digest: testDigest("commission-1"), SizeBytes: 10,
			MediaType: "application/json", OwnerDomain: "lifecycle", Access: "restricted",
		},
		CommissionRef:     nmEvidenceRef("journal-1", 2, "commission-ev-1"),
		AuthorizationRefs: []native_mapping.EvidenceRef{nmEvidenceRef("journal-1", 1, "auth-1")},
		ObservationPolicy: native_mapping.ObservationPolicy{
			ActiveLimit: nmDurationLimit(60000), DrainLimit: nmDurationLimit(5000),
			NativeCancelWaitLimit: nmDurationLimit(2000), CleanupWaitLimit: nmDurationLimit(2000),
			FixtureCloseAction: "seal_after_drain",
		},
	}
}

func nmConfiguration(desc ConnectorDescriptor) native_mapping.ConfigurationPin {
	return native_mapping.ConfigurationPin{
		ConnectorID: desc.ConnectorID, ConnectorVersion: desc.ConnectorVersion,
		Binding: native_mapping.VersionPin{ID: desc.Binding.ID, Version: desc.Binding.Version, ArtifactDigest: desc.Binding.ArtifactDigest},
		Subject: native_mapping.SubjectIdentity{
			SubjectID: desc.Subject.SubjectID, SubjectVersion: desc.Subject.SubjectVersion,
			RevisionBasis: desc.Subject.RevisionBasis,
			NativeRevision: native_mapping.Missing{Reason: "not_applicable"},
			ConfiguredMode: desc.Subject.ConfiguredMode, InterfaceSurface: desc.Subject.InterfaceSurface,
			ConfigurationDigest: desc.Subject.ConfigurationDigest, Stack: []any{},
		},
		Descriptor: native_mapping.ArtifactReference{
			Digest: testDigest("descriptor-1"), SizeBytes: 12,
			MediaType: "application/json", OwnerDomain: "connector", Access: "public",
		},
		DescriptorRef: nmEvidenceRef("journal-1", 3, "desc-ev-1"),
	}
}

func nmBudgets() native_mapping.TaskBudgets {
	return native_mapping.TaskBudgets{
		ActiveLimit: nmDurationLimit(60000), ActionLimit: 100,
		ObservationByteLimit: 1 << 20, RecoveryLimit: 3, ModelTokenLimit: 10000,
	}
}

func nmContextPolicy() native_mapping.ContextPolicy {
	return native_mapping.ContextPolicy{
		BrowserState:  native_mapping.StatePolicy{Mode: "fresh", Requirement: "best_effort", ResourceRef: native_mapping.Missing{Reason: "not_applicable"}, Baseline: native_mapping.Missing{Reason: "not_applicable"}},
		LearningState: native_mapping.StatePolicy{Mode: "not_applicable", Requirement: "best_effort", ResourceRef: native_mapping.Missing{Reason: "not_applicable"}, Baseline: native_mapping.Missing{Reason: "not_applicable"}},
	}
}

func nmApplyTask() native_mapping.TaskEnvelope {
	return native_mapping.TaskEnvelope{
		RecordType: "connector_task", SchemaVersion: "external-connector/0.1.0",
		TaskID: "task-1", TaskType: "apply",
		Entry: native_mapping.EntryPoint{LogicalID: "entry-1", URL: "https://fixture.local/jobs/1"},
		Goal:  "Complete the synthetic application for the listed role.",
		SuccessCriteria: []native_mapping.SuccessCriterion{
			{CriterionID: "c1", Description: "Application submitted through ordinary controls"},
		},
		Inputs:              []native_mapping.TaskInput{},
		PermittedOrigins:    []native_mapping.PermittedOrigin{{LogicalID: "origin-1", Origin: "https://fixture.local"}},
		PermittedInterfaces: []string{"ordinary_browser"},
		EffectPolicy:        "commissioned_application",
		Budgets:             nmBudgets(),
		ContextPolicy:       nmContextPolicy(),
		OutputSchema:        native_mapping.Missing{Reason: "not_applicable"},
		Steps: []native_mapping.TaskStep{
			{Name: "open-listing", Action: "navigate", Target: "entry-1", Value: "https://fixture.local/jobs/1", RetryPolicy: native_mapping.RetryPolicy{MaxAttempts: 1, BackoffMs: 0}},
			{Name: "fill-contact", Action: "fill", Target: "contact-email", Value: "candidate@fixture.local", RetryPolicy: native_mapping.RetryPolicy{MaxAttempts: 2, BackoffMs: 250}},
		},
	}
}

func nmAssistance() native_mapping.AssistanceRecord {
	return native_mapping.AssistanceRecord{
		PlanningOwner: "subject", AssistanceTrack: "m1-cooperative",
		PlannerIdentity: native_mapping.Missing{Reason: "not_applicable"},
		Plan:            native_mapping.Missing{Reason: "not_applicable"},
		OnlineReplanning: false, Description: "No external planning; subject executes the recorded task.",
	}
}

func nmPrepareRequest(desc ConnectorDescriptor) native_mapping.PrepareRequest {
	return native_mapping.PrepareRequest{
		Scope: nmScopeForApply(), Configuration: nmConfiguration(desc), Task: nmApplyTask(),
		Assistance: nmAssistance(), PlanningEvidenceRefs: []native_mapping.EvidenceRef{},
		PreparationMeasurements: []native_mapping.MeasurementEvidence{}, RuntimeAccess: []native_mapping.RuntimeAccess{},
	}
}

// --- connector wire helpers ---

func connectorRequest(operation, requestID, connectorID string, payload any) ConnectorRequest {
	raw, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	return ConnectorRequest{
		RecordType: RecordTypeRequest, SchemaVersion: SchemaVersion,
		RequestID: requestID, ConnectorID: connectorID, Operation: operation,
		CallLimit: DurationLimit{Kind: "exact", Unit: "ms", Value: 30000},
		Payload:   json.RawMessage(raw),
	}
}

func doConnector(t *testing.T, handler http.Handler, ctx context.Context, authHeader string, req ConnectorRequest) ConnectorResponse {
	t.Helper()
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	httpReq := httptest.NewRequest(http.MethodPost, "/connector", bytes.NewReader(raw))
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", authHeader)
	httpReq = httpReq.WithContext(ctx)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httpReq)
	if rec.Code != http.StatusOK {
		// Our handler always writes 200 with a typed envelope; a non-200
		// means a carrier-level failure.
		t.Fatalf("carrier status %d: %s", rec.Code, rec.Body.String())
	}
	var resp ConnectorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v: %s", err, rec.Body.String())
	}
	if resp.RequestID != req.RequestID || resp.Operation != req.Operation || resp.ConnectorID != req.ConnectorID {
		t.Fatalf("response correlation mismatch: %+v vs %+v", resp, req)
	}
	assertNoBareNulls(t, rec.Body.Bytes())
	return resp
}

func parseResult(t *testing.T, resp ConnectorResponse, out any) {
	t.Helper()
	if err := json.Unmarshal(resp.Result, out); err != nil {
		t.Fatalf("decode result: %v: %s", err, string(resp.Result))
	}
}

func parseConnectorError(t *testing.T, resp ConnectorResponse) ConnectorError {
	t.Helper()
	var cerr ConnectorError
	if err := json.Unmarshal(resp.Result, &cerr); err != nil {
		t.Fatalf("decode connector error: %v: %s", err, string(resp.Result))
	}
	if cerr.Kind != "connector_error" {
		t.Fatalf("expected connector_error, got kind %q: %s", cerr.Kind, string(resp.Result))
	}
	return cerr
}

func requireSuccessKind(t *testing.T, resp ConnectorResponse, kind string) json.RawMessage {
	t.Helper()
	var probe map[string]any
	if err := json.Unmarshal(resp.Result, &probe); err != nil {
		t.Fatalf("decode result probe: %v", err)
	}
	if k, _ := probe["kind"].(string); k == "connector_error" {
		t.Fatalf("expected success kind %q, got connector_error: %s", kind, string(resp.Result))
	}
	if kind != "" {
		if k, _ := probe["kind"].(string); k != kind {
			// Describe returns a descriptor without kind; allow record_type check.
			if rt, _ := probe["record_type"].(string); rt == "" || kind != rt {
				t.Fatalf("expected kind %q, got %q: %s", kind, k, string(resp.Result))
			}
		}
	}
	return resp.Result
}

func assertNoBareNulls(t *testing.T, data []byte) {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("cannot decode for null check: %v", err)
	}
	var walk func(val any, path string)
	walk = func(val any, path string) {
		switch typed := val.(type) {
		case nil:
			t.Fatalf("bare null at %s: use typed Missing envelopes", path)
		case map[string]any:
			if raw, hasValue := typed["value"]; hasValue && raw == nil {
				reason, _ := typed["reason"].(string)
				switch reason {
				case "not_enabled", "not_applicable", "not_observed", "observation_lost", "unsupported_by_subject", "manual_override":
					for k, e := range typed {
						if k == "value" {
							continue
						}
						walk(e, path+"."+k)
					}
					return
				default:
					t.Fatalf("Missing envelope without valid reason at %s", path)
				}
			}
			for k, e := range typed {
				walk(e, path+"."+k)
			}
		case []any:
			for i, e := range typed {
				walk(e, fmt.Sprintf("%s[%d]", path, i))
			}
		}
	}
	walk(v, "$")
}

// --- mock natives ---

type mockNative struct {
	mu      sync.Mutex
	handler func(*http.Request) (*http.Response, error)
	calls   []NativeCall
}

func (m *mockNative) RoundTrip(r *http.Request) (*http.Response, error) {
	var body []byte
	if r.Body != nil {
		body, _ = io.ReadAll(r.Body)
	}
	m.mu.Lock()
	m.calls = append(m.calls, NativeCall{Method: r.Method, URL: r.URL.String(), Body: body, At: time.Now()})
	h := m.handler
	m.mu.Unlock()
	if h != nil {
		return h(r)
	}
	return jsonNativeResponse(`{"state":"completed","native_run_id":"run-1","native_message_id":"msg-1","timing":{"duration_ms":10}}`), nil
}

func (m *mockNative) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.calls)
}

func (m *mockNative) urls() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.calls))
	for i := range m.calls {
		out[i] = m.calls[i].URL
	}
	return out
}

func jsonNativeResponse(body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func verifiedNativeBody(state, runID, attemptID, traceID, sourceID, contract string) string {
	m := map[string]any{
		"state": state, "native_run_id": runID + "-native", "native_message_id": "msg-" + state,
		"timing": map[string]any{"duration_ms": 42},
		"source_id": sourceID, "signing_contract": contract, "signature": "test-signature-present",
		"run_id": runID, "attempt_id": attemptID,
	}
	if traceID != "" {
		m["trace_id"] = traceID
	}
	if state == "failed" {
		m["error"] = "synthetic native failure"
	}
	raw, _ := json.Marshal(m)
	return string(raw)
}

func waitFor(t *testing.T, timeout time.Duration, what string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// observeLive performs one live Observe and returns the page.
func observeLive(t *testing.T, handler http.Handler, ctx context.Context, handle HandleReference, after ObservationCursor, maxItems int64) ObservationPage {
	t.Helper()
	through := json.RawMessage(`{"value":null,"reason":"not_applicable"}`)
	oreq := ObserveRequest{
		Handle: handle, After: after, Through: through,
		MaxItems: maxItems, WaitLimit: DurationLimit{Kind: "exact", Unit: "ms", Value: 0},
	}
	req := connectorRequest(OpObserve, fmt.Sprintf("obs-%d", time.Now().UnixNano()), handle.ConnectorID, oreq)
	resp := doConnector(t, handler, ctx, "Channel test-channel", req)
	raw := requireSuccessKind(t, resp, "observation_page")
	var page ObservationPage
	if err := json.Unmarshal(raw, &page); err != nil {
		t.Fatalf("decode observation page: %v", err)
	}
	return page
}

func zeroCursor(handle HandleReference) ObservationCursor {
	return ObservationCursor{
		Handle: handle, JournalID: handle.LocalHandle, Sequence: 0,
		EventHash: json.RawMessage(`{"value":null,"reason":"not_applicable"}`),
	}
}

func prepareOnce(t *testing.T, handler http.Handler, ctx context.Context, desc ConnectorDescriptor, mutate func(*native_mapping.PrepareRequest)) PrepareResult {
	t.Helper()
	nmReq := nmPrepareRequest(desc)
	if mutate != nil {
		mutate(&nmReq)
	}
	req := connectorRequest(OpPrepare, fmt.Sprintf("prep-%d", time.Now().UnixNano()), desc.ConnectorID, nmReq)
	resp := doConnector(t, handler, ctx, "Channel test-channel", req)
	raw := requireSuccessKind(t, resp, "prepared")
	var result PrepareResult
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("decode prepare result: %v", err)
	}
	return result
}

func startOnce(t *testing.T, handler http.Handler, ctx context.Context, authHeader string, requestID string, prep PrepareResult, key string, recovery any) (StartResult, ConnectorResponse) {
	t.Helper()
	var recoveryRaw json.RawMessage
	switch r := recovery.(type) {
	case nil:
		recoveryRaw = json.RawMessage(`{"value":null,"reason":"not_applicable"}`)
	case json.RawMessage:
		recoveryRaw = r
	default:
		raw, _ := json.Marshal(r)
		recoveryRaw = raw
	}
	sreq := StartRequest{
		Preparation: prep.Preparation, IdempotencyKey: key,
		AcceptedConcernIDs: []string{},
		AuthorizationRefs:  []EvidenceRef{testEvidenceRef("journal-1", 1, "auth-1")},
		Recovery:           recoveryRaw,
	}
	// Accept all requires_acceptance concerns (none in the default fixture,
	// but honor any the preparation declared).
	for _, k := range prep.Record.Concerns {
		if k.RequiresAcceptance {
			sreq.AcceptedConcernIDs = append(sreq.AcceptedConcernIDs, k.ConcernID)
		}
	}
	req := connectorRequest(OpStart, requestID, prep.Record.Translation.ID, sreq)
	// connector_id must be the descriptor connector, not the translation id.
	req.ConnectorID = "test-connector"
	resp := doConnector(t, handler, ctx, authHeader, req)
	var probe map[string]any
	_ = json.Unmarshal(resp.Result, &probe)
	if k, _ := probe["kind"].(string); k == "connector_error" {
		return StartResult{}, resp
	}
	var result StartResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("decode start result: %v: %s", err, string(resp.Result))
	}
	return result, resp
}

func setup(t *testing.T, native http.RoundTripper, mutateDesc func(*ConnectorDescriptor)) (*OwnerStore, context.Context, *Connector, ConnectorDescriptor) {
	t.Helper()
	store := openStore(t)
	ctx := testContext(t)
	contract := installContract(t, ctx, store)
	desc := testDescriptor(contract)
	if mutateDesc != nil {
		mutateDesc(&desc)
	}
	h, err := NewReferenceConnector(store, desc, native)
	if err != nil {
		t.Fatalf("NewReferenceConnector: %v", err)
	}
	conn, ok := h.(*Connector)
	if !ok {
		t.Fatalf("handler is %T, want *Connector", h)
	}
	return store, ctx, conn, desc
}

// ---------------------------------------------------------------------------
// Conformance assertions.
// ---------------------------------------------------------------------------

func TestStartReturnsBeforeNativeCompletionWithDurableHandle(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	mock := &mockNative{handler: func(r *http.Request) (*http.Response, error) {
		<-release
		return jsonNativeResponse(`{"state":"completed","native_run_id":"run-1","native_message_id":"msg-1","timing":{"duration_ms":10}}`), nil
	}}
	store, ctx, conn, desc := setup(t, mock, nil)
	prep := prepareOnce(t, conn, ctx, desc, nil)

	type startOut struct {
		result StartResult
		resp   ConnectorResponse
		err    error
	}
	outCh := make(chan startOut, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				outCh <- startOut{err: fmt.Errorf("start panicked: %v", r)}
			}
		}()
		result, resp := startOnce(t, conn, ctx, "Channel test-channel", "req-start-durable", prep, "key-durable", nil)
		outCh <- startOut{result: result, resp: resp}
	}()
	select {
	case out := <-outCh:
		if out.err != nil {
			t.Fatalf("start failed: %v", out.err)
		}
		if out.result.Disposition != "accepted_locally" {
			t.Fatalf("disposition = %q, want accepted_locally", out.result.Disposition)
		}
		if out.result.Handle.Handle.LocalHandle == "" {
			t.Fatalf("empty local handle")
		}
		// Durability while native is still blocked.
		prefix, ok := conn.HandlePrefix(out.result.Handle.Handle.LocalHandle)
		if !ok {
			t.Fatalf("no handle prefix while native blocked")
		}
		events, err := owner_store.LoadPrefix(ctx, store, prefix)
		if err != nil {
			t.Fatalf("LoadPrefix while native blocked: %v", err)
		}
		kinds := map[string]bool{}
		for _, env := range events {
			kinds[env.EventKind] = true
		}
		for _, want := range []string{"handle_bound", "request_binding", "dispatch_intent"} {
			if !kinds[want] {
				t.Fatalf("durable handle journal missing %q while native blocked; have %v", want, kinds)
			}
		}
		once.Do(func() { close(release) })
		handle := out.result.Handle.Handle
		waitFor(t, 5*time.Second, "native report after release", func() bool {
			page := observeLive(t, conn, ctx, handle, zeroCursor(handle), 100)
			for _, it := range page.Items {
				if k, _ := it.Payload["kind"].(string); k == "native_report" {
					return true
				}
			}
			return false
		})
	case <-time.After(3 * time.Second):
		once.Do(func() { close(release) })
		t.Fatalf("Start did not return before native completion")
	}
}

func TestDispatchIntentAndRequestBindingPrecedeWireDelivery(t *testing.T) {
	invoked := make(chan struct{}, 1)
	release := make(chan struct{})
	var once sync.Once
	mock := &mockNative{handler: func(r *http.Request) (*http.Response, error) {
		select {
		case invoked <- struct{}{}:
		default:
		}
		<-release
		return jsonNativeResponse(`{"state":"completed","native_run_id":"run-1","native_message_id":"msg-1","timing":{"duration_ms":10}}`), nil
	}}
	store, ctx, conn, desc := setup(t, mock, nil)
	prep := prepareOnce(t, conn, ctx, desc, nil)
	result, _ := startOnce(t, conn, ctx, "Channel test-channel", "req-start-order", prep, "key-order", nil)
	if result.Handle.Handle.LocalHandle == "" {
		t.Fatalf("empty handle")
	}
	select {
	case <-invoked:
	case <-time.After(3 * time.Second):
		once.Do(func() { close(release) })
		t.Fatalf("native was never invoked")
	}
	// Wire delivery has started; the binding and intent must already be durable.
	prefix, ok := conn.HandlePrefix(result.Handle.Handle.LocalHandle)
	if !ok {
		once.Do(func() { close(release) })
		t.Fatalf("no handle prefix at wire delivery")
	}
	events, err := owner_store.LoadPrefix(ctx, store, prefix)
	if err != nil {
		once.Do(func() { close(release) })
		t.Fatalf("LoadPrefix at wire delivery: %v", err)
	}
	kinds := map[string]bool{}
	for _, env := range events {
		kinds[env.EventKind] = true
	}
	for _, want := range []string{"request_binding", "dispatch_intent"} {
		if !kinds[want] {
			once.Do(func() { close(release) })
			t.Fatalf("at wire delivery, journal missing %q; have %v", want, kinds)
		}
	}
	once.Do(func() { close(release) })
}

func TestRepeatedLogicalStartReturnsTheSameHandle(t *testing.T) {
	mock := &mockNative{}
	store, ctx, conn, desc := setup(t, mock, nil)
	_ = store
	prep := prepareOnce(t, conn, ctx, desc, nil)
	first, _ := startOnce(t, conn, ctx, "Channel test-channel", "req-logical-1", prep, "key-logical", nil)
	if first.Disposition != "accepted_locally" {
		t.Fatalf("first disposition = %q", first.Disposition)
	}
	h1 := first.Handle.Handle.LocalHandle
	waitFor(t, 5*time.Second, "first dispatch", func() bool { return mock.count() >= 1 })
	second, _ := startOnce(t, conn, ctx, "Channel test-channel", "req-logical-2", prep, "key-logical", nil)
	if second.Handle.Handle.LocalHandle != h1 {
		t.Fatalf("repeated logical start returned %q, want %q", second.Handle.Handle.LocalHandle, h1)
	}
	if second.Disposition != "existing_handle" {
		t.Fatalf("repeated disposition = %q, want existing_handle", second.Disposition)
	}
	time.Sleep(300 * time.Millisecond)
	if got := mock.count(); got != 1 {
		t.Fatalf("native invocations = %d, want 1 (no second logical execution)", got)
	}
}

func TestChangedCommandContentRaisesIdempotencyConflict(t *testing.T) {
	mock := &mockNative{}
	_, ctx, conn, desc := setup(t, mock, nil)
	prep := prepareOnce(t, conn, ctx, desc, nil)
	first, _ := startOnce(t, conn, ctx, "Channel test-channel", "req-conflict", prep, "key-A", nil)
	if first.Handle.Handle.LocalHandle == "" {
		t.Fatalf("empty first handle")
	}
	// Identical retry returns the retained receipt without another effect.
	replay, _ := startOnce(t, conn, ctx, "Channel test-channel", "req-conflict", prep, "key-A", nil)
	if replay.Handle.Handle.LocalHandle != first.Handle.Handle.LocalHandle {
		t.Fatalf("identical retry returned %q, want %q", replay.Handle.Handle.LocalHandle, first.Handle.Handle.LocalHandle)
	}
	waitFor(t, 5*time.Second, "first dispatch", func() bool { return mock.count() >= 1 })
	// Conflicting content under the same command key is rejected.
	_, resp := startOnce(t, conn, ctx, "Channel test-channel", "req-conflict", prep, "key-B", nil)
	cerr := parseConnectorError(t, resp)
	if cerr.Code != "IDEMPOTENCY_CONFLICT" {
		t.Fatalf("conflicting content code = %q, want IDEMPOTENCY_CONFLICT: %s", cerr.Code, string(resp.Result))
	}
	time.Sleep(300 * time.Millisecond)
	if got := mock.count(); got != 1 {
		t.Fatalf("native invocations = %d, want 1", got)
	}
}

func TestChangedSubjectConfigurationRejectsStalePreparation(t *testing.T) {
	mock := &mockNative{}
	_, ctx, conn, desc := setup(t, mock, nil)
	prep := prepareOnce(t, conn, ctx, desc, nil)
	stale := desc
	stale.Subject.SubjectVersion = "v2-stale"
	stale.Subject.ConfigurationDigest = testDigest("subject-config-v2")
	if err := conn.SetDescriptor(stale); err != nil {
		t.Fatalf("SetDescriptor: %v", err)
	}
	_, resp := startOnce(t, conn, ctx, "Channel test-channel", "req-stale", prep, "key-stale", nil)
	cerr := parseConnectorError(t, resp)
	if cerr.Code != "STALE_PREPARATION" {
		t.Fatalf("stale preparation code = %q, want STALE_PREPARATION: %s", cerr.Code, string(resp.Result))
	}
	if mock.count() != 0 {
		t.Fatalf("stale preparation must not dispatch; native calls = %d", mock.count())
	}
}

func TestRequiredUnsupportedStatePolicyRejectsPreparation(t *testing.T) {
	mock := &mockNative{}
	_, ctx, conn, desc := setup(t, mock, func(d *ConnectorDescriptor) {
		setCapability(d, "browser_state_isolation", "unsupported", []EvidenceRef{testEvidenceRef("cap-journal", 1, "cap-ev-1")})
		setCapability(d, "browser_state_persistence", "unsupported", nil)
		setCapability(d, "learning_state_control", "unsupported", nil)
	})
	// Required browser state with no available mapping is rejected.
	nmReq := nmPrepareRequest(desc)
	nmReq.Task.ContextPolicy.BrowserState.Requirement = "required"
	nmReq.Task.ContextPolicy.BrowserState.Mode = "fresh"
	req := connectorRequest(OpPrepare, "prep-browser-required", desc.ConnectorID, nmReq)
	resp := doConnector(t, conn, ctx, "Channel test-channel", req)
	cerr := parseConnectorError(t, resp)
	if cerr.Code != "UNSUPPORTED_MAPPING" {
		t.Fatalf("required unsupported browser state code = %q, want UNSUPPORTED_MAPPING: %s", cerr.Code, string(resp.Result))
	}
	// Required learning state with no available mapping is rejected.
	nmReq2 := nmPrepareRequest(desc)
	nmReq2.Task.ContextPolicy.BrowserState.Mode = "not_applicable"
	nmReq2.Task.ContextPolicy.BrowserState.Requirement = "best_effort"
	nmReq2.Task.ContextPolicy.LearningState.Mode = "frozen"
	nmReq2.Task.ContextPolicy.LearningState.Requirement = "required"
	req2 := connectorRequest(OpPrepare, "prep-learning-required", desc.ConnectorID, nmReq2)
	resp2 := doConnector(t, conn, ctx, "Channel test-channel", req2)
	cerr2 := parseConnectorError(t, resp2)
	if cerr2.Code != "UNSUPPORTED_MAPPING" {
		t.Fatalf("required unsupported learning state code = %q, want UNSUPPORTED_MAPPING: %s", cerr2.Code, string(resp2.Result))
	}
	if mock.count() != 0 {
		t.Fatalf("rejected preparations must not touch native; calls = %d", mock.count())
	}
}

func TestMissingNativeCancellationIsNotUniversalAdmissionBlocker(t *testing.T) {
	mock := &mockNative{}
	_, ctx, conn, desc := setup(t, mock, func(d *ConnectorDescriptor) {
		setCapability(d, "native_cancel", "unsupported", []EvidenceRef{testEvidenceRef("cap-journal", 2, "cap-ev-2")})
	})
	prep := prepareOnce(t, conn, ctx, desc, nil)
	result, _ := startOnce(t, conn, ctx, "Channel test-channel", "req-no-cancel-block", prep, "key-no-cancel", nil)
	if result.Disposition != "accepted_locally" {
		t.Fatalf("admission with missing native cancellation failed: %+v", result)
	}
	waitFor(t, 5*time.Second, "dispatch without cancel", func() bool { return mock.count() >= 1 })
}

func TestEvidencedNativeAbsenceIsDistinctFromUnmappedOperation(t *testing.T) {
	// Unmapped cancel.
	mockA := &mockNative{}
	_, ctxA, connA, descA := setup(t, mockA, func(d *ConnectorDescriptor) {
		setOperation(d, OpRequestNativeCancel, "unmapped", "")
	})
	prepA := prepareOnce(t, connA, ctxA, descA, nil)
	startA, _ := startOnce(t, connA, ctxA, "Channel test-channel", "req-absence-a", prepA, "key-a", nil)
	cancelReq := NativeCancelRequest{
		Handle: startA.Handle.Handle, Reason: "operator stop",
		AuthorizationRefs: []EvidenceRef{testEvidenceRef("journal-1", 1, "auth-1")},
	}
	respA := doConnector(t, connA, ctxA, "Channel test-channel",
		connectorRequest(OpRequestNativeCancel, "cancel-a", descA.ConnectorID, cancelReq))
	rawA := requireSuccessKind(t, respA, "control_receipt")
	var receiptA ControlReceipt
	if err := json.Unmarshal(rawA, &receiptA); err != nil {
		t.Fatalf("decode cancel receipt A: %v", err)
	}
	if receiptA.Observation.Disposition != "unsupported" {
		t.Fatalf("unmapped cancel disposition = %q, want unsupported", receiptA.Observation.Disposition)
	}
	// Evidenced native absence: mapped but capability unsupported with evidence.
	mockB := &mockNative{}
	_, ctxB, connB, descB := setup(t, mockB, func(d *ConnectorDescriptor) {
		setOperation(d, OpRequestNativeCancel, "native-mapping", "http://native.test/cancel")
		setCapability(d, "native_cancel", "unsupported", []EvidenceRef{testEvidenceRef("cap-journal", 3, "cap-ev-3")})
	})
	prepB := prepareOnce(t, connB, ctxB, descB, nil)
	startB, _ := startOnce(t, connB, ctxB, "Channel test-channel", "req-absence-b", prepB, "key-b", nil)
	cancelReqB := NativeCancelRequest{
		Handle: startB.Handle.Handle, Reason: "operator stop",
		AuthorizationRefs: []EvidenceRef{testEvidenceRef("journal-1", 1, "auth-1")},
	}
	respB := doConnector(t, connB, ctxB, "Channel test-channel",
		connectorRequest(OpRequestNativeCancel, "cancel-b", descB.ConnectorID, cancelReqB))
	rawB := requireSuccessKind(t, respB, "control_receipt")
	var receiptB ControlReceipt
	if err := json.Unmarshal(rawB, &receiptB); err != nil {
		t.Fatalf("decode cancel receipt B: %v", err)
	}
	if receiptB.Observation.Disposition != "unsupported" {
		t.Fatalf("evidenced-absence cancel disposition = %q, want unsupported", receiptB.Observation.Disposition)
	}
	joinedA := strings.Join(receiptA.Observation.Limitations, " ")
	joinedB := strings.Join(receiptB.Observation.Limitations, " ")
	if !strings.Contains(strings.ToLower(joinedA), "unmapped") {
		t.Fatalf("unmapped limitations must name unmapped, got %q", joinedA)
	}
	if !strings.Contains(strings.ToLower(joinedB), "evidenced native absence") {
		t.Fatalf("evidenced-absence limitations must name evidenced native absence, got %q", joinedB)
	}
	if joinedA == joinedB {
		t.Fatalf("unmapped and evidenced absence must be distinct; both %q", joinedA)
	}
	capA, _ := json.Marshal(receiptA.Observation.CapabilityRef)
	capB, _ := json.Marshal(receiptB.Observation.CapabilityRef)
	if string(capA) == string(capB) {
		t.Fatalf("capability refs must differ: unmapped %s vs evidenced %s", capA, capB)
	}
	if mockA.count() != 1 || mockB.count() != 1 {
		t.Fatalf("unsupported cancels must not add native calls; A=%d B=%d (each has one start)", mockA.count(), mockB.count())
	}
}

func TestUnsupportedContextReleaseReturnsTypedControlEvidence(t *testing.T) {
	mock := &mockNative{}
	_, ctx, conn, desc := setup(t, mock, func(d *ConnectorDescriptor) {
		setOperation(d, OpReleaseNativeContext, "unmapped", "")
	})
	prep := prepareOnce(t, conn, ctx, desc, nil)
	started, _ := startOnce(t, conn, ctx, "Channel test-channel", "req-release-typed", prep, "key-release", nil)
	relReq := ReleaseContextRequest{
		Handle: started.Handle.Handle,
		ContextRef: json.RawMessage(`{"value":null,"reason":"not_observed","detail":"native exposes no context identity"}`),
		AuthorizationRefs: []EvidenceRef{testEvidenceRef("journal-1", 1, "auth-1")},
	}
	resp := doConnector(t, conn, ctx, "Channel test-channel",
		connectorRequest(OpReleaseNativeContext, "rel-1", desc.ConnectorID, relReq))
	raw := requireSuccessKind(t, resp, "control_receipt")
	var receipt ControlReceipt
	if err := json.Unmarshal(raw, &receipt); err != nil {
		t.Fatalf("decode release receipt: %v", err)
	}
	if receipt.Observation.Operation != OpReleaseNativeContext {
		t.Fatalf("observation operation = %q", receipt.Observation.Operation)
	}
	if receipt.Observation.Disposition != "unsupported" {
		t.Fatalf("disposition = %q, want unsupported", receipt.Observation.Disposition)
	}
	if receipt.Observation.TargetScope != "native_context" {
		t.Fatalf("target_scope = %q, want native_context", receipt.Observation.TargetScope)
	}
	capRaw, _ := json.Marshal(receipt.Observation.CapabilityRef)
	var capProbe map[string]any
	_ = json.Unmarshal(capRaw, &capProbe)
	if _, hasReason := capProbe["reason"]; !hasReason {
		t.Fatalf("unsupported capability_ref must be a typed Missing envelope, got %s", capRaw)
	}
	if len(receipt.Observation.Limitations) == 0 {
		t.Fatalf("typed control evidence must carry limitations")
	}
}

func TestConnectionCloseAllowsLaterAuthenticatedCallback(t *testing.T) {
	mock := &mockNative{handler: func(r *http.Request) (*http.Response, error) {
		return jsonNativeResponse(verifiedNativeBody("completed", "run-1", "attempt-1", "", "test-connector", testDigest("contract-placeholder"))), nil
	}}
	// Fix the contract digest after setup: rebuild the mock to use the real one.
	store, ctx, conn, desc := setup(t, mock, nil)
	_ = store
	contract := desc.Binding.ArtifactDigest
	mock.handler = func(r *http.Request) (*http.Response, error) {
		return jsonNativeResponse(verifiedNativeBody("completed", "run-1", "attempt-1", "", "test-connector", contract)), nil
	}
	prep := prepareOnce(t, conn, ctx, desc, nil)
	started, _ := startOnce(t, conn, ctx, "Channel test-channel", "req-close-callback", prep, "key-close-cb", nil)
	handle := started.Handle.Handle
	waitFor(t, 5*time.Second, "terminal response", func() bool {
		page := observeLive(t, conn, ctx, handle, zeroCursor(handle), 100)
		for _, it := range page.Items {
			if k, _ := it.Payload["kind"].(string); k == "native_report" {
				if ch, _ := it.Payload["channel"].(string); ch == "terminal_response" {
					return true
				}
			}
		}
		return false
	})
	closeReq := CloseConnectionRequest{
		Handle: handle, Reason: "operator_stop", EndObservation: false,
		AuthorizationRefs: []EvidenceRef{testEvidenceRef("journal-1", 1, "auth-1")},
	}
	closeResp := doConnector(t, conn, ctx, "Channel test-channel",
		connectorRequest(OpCloseObservationConnection, "close-1", desc.ConnectorID, closeReq))
	requireSuccessKind(t, closeResp, "control_receipt")
	callbackBody := verifiedNativeBody("failed", "run-1", "attempt-1", "", "test-connector", contract)
	if err := conn.InjectCallback(ctx, handle.LocalHandle, []byte(callbackBody)); err != nil {
		t.Fatalf("later authenticated callback after close: %v", err)
	}
	waitFor(t, 5*time.Second, "callback retained after close", func() bool {
		page := observeLive(t, conn, ctx, handle, zeroCursor(handle), 100)
		channels := map[string]int{}
		for _, it := range page.Items {
			if k, _ := it.Payload["kind"].(string); k == "native_report" {
				ch, _ := it.Payload["channel"].(string)
				channels[ch]++
			}
		}
		return channels["terminal_response"] >= 1 && channels["callback"] >= 1
	})
	page := observeLive(t, conn, ctx, handle, zeroCursor(handle), 100)
	var closeProbe map[string]any
	_ = json.Unmarshal(page.ObservationCloseRef, &closeProbe)
	if _, isMissing := closeProbe["reason"]; !isMissing {
		t.Fatalf("transport-only close must leave observation open; close_ref = %s", string(page.ObservationCloseRef))
	}
}

func TestConflictingResponseAndCallbackClaimsAreBothRetained(t *testing.T) {
	store, ctx, conn, desc := setup(t, &mockNative{}, nil)
	_ = store
	contract := desc.Binding.ArtifactDigest
	mock := &mockNative{handler: func(r *http.Request) (*http.Response, error) {
		return jsonNativeResponse(verifiedNativeBody("completed", "run-1", "attempt-1", "", "test-connector", contract)), nil
	}}
	// Swap the native transport to the verified mock.
	conn.mu.Lock()
	conn.native = mock
	conn.mu.Unlock()
	prep := prepareOnce(t, conn, ctx, desc, nil)
	started, _ := startOnce(t, conn, ctx, "Channel test-channel", "req-conflict-claims", prep, "key-conflict", nil)
	handle := started.Handle.Handle
	waitFor(t, 5*time.Second, "completed response", func() bool {
		page := observeLive(t, conn, ctx, handle, zeroCursor(handle), 100)
		for _, it := range page.Items {
			if k, _ := it.Payload["kind"].(string); k == "native_report" {
				return true
			}
		}
		return false
	})
	callbackBody := verifiedNativeBody("failed", "run-1", "attempt-1", "", "test-connector", contract)
	if err := conn.InjectCallback(ctx, handle.LocalHandle, []byte(callbackBody)); err != nil {
		t.Fatalf("inject conflicting callback: %v", err)
	}
	waitFor(t, 5*time.Second, "both claims retained", func() bool {
		page := observeLive(t, conn, ctx, handle, zeroCursor(handle), 100)
		n := 0
		for _, it := range page.Items {
			if k, _ := it.Payload["kind"].(string); k == "native_report" {
				n++
			}
		}
		return n >= 2
	})
	page := observeLive(t, conn, ctx, handle, zeroCursor(handle), 100)
	states := map[string]int{}
	digests := map[string]bool{}
	for _, it := range page.Items {
		if k, _ := it.Payload["kind"].(string); k != "native_report" {
			continue
		}
		if raw, ok := it.Payload["raw"].(map[string]any); ok {
			if d, _ := raw["digest"].(string); d != "" {
				digests[d] = true
			}
		}
		if claims, ok := it.Payload["normalized_claims"].([]any); ok {
			for _, c := range claims {
				if cm, ok := c.(map[string]any); ok {
					if s, ok := cm["state"].(string); ok {
						states[s]++
					}
				}
			}
		}
	}
	if len(digests) < 2 {
		t.Fatalf("conflicting raw reports must both be retained; digests = %v", digests)
	}
	if states["completed"] < 1 || states["failed"] < 1 {
		t.Fatalf("conflicting claims must both be retained; states = %v", states)
	}
}

func TestContinuingRemoteWorkCannotPreventBoundedLocalFinalization(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	mock := &mockNative{handler: func(r *http.Request) (*http.Response, error) {
		<-release
		return jsonNativeResponse(`{"state":"completed","native_run_id":"run-1","native_message_id":"msg-1","timing":{"duration_ms":10}}`), nil
	}}
	_, ctx, conn, desc := setup(t, mock, nil)
	prep := prepareOnce(t, conn, ctx, desc, nil)
	started, _ := startOnce(t, conn, ctx, "Channel test-channel", "req-bounded", prep, "key-bounded", nil)
	handle := started.Handle.Handle
	closeReq := CloseConnectionRequest{
		Handle: handle, Reason: "local_deadline", EndObservation: true,
		AuthorizationRefs: []EvidenceRef{testEvidenceRef("journal-1", 1, "auth-1")},
	}
	closeResp := doConnector(t, conn, ctx, "Channel test-channel",
		connectorRequest(OpCloseObservationConnection, "close-bounded", desc.ConnectorID, closeReq))
	requireSuccessKind(t, closeResp, "control_receipt")
	start := time.Now()
	waitFor(t, 8*time.Second, "bounded local finalization while remote continues", func() bool {
		page := observeLive(t, conn, ctx, handle, zeroCursor(handle), 100)
		var probe map[string]any
		_ = json.Unmarshal(page.ObservationCloseRef, &probe)
		_, isMissing := probe["reason"]
		return !isMissing
	})
	elapsed := time.Since(start)
	if elapsed > 7*time.Second {
		t.Fatalf("local finalization took %v; remote work must not prevent bounded finalization", elapsed)
	}
	if st, _ := conn.HandleState(handle.LocalHandle); st != "closed" {
		t.Fatalf("handle state = %q, want closed", st)
	}
	once.Do(func() { close(release) })
}

func TestReleaseFailureNeverSilentlyInvokesContainment(t *testing.T) {
	mock := &mockNative{handler: func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.String(), "/release") {
			return nil, fmt.Errorf("synthetic native release failure")
		}
		return jsonNativeResponse(`{"state":"completed","native_run_id":"run-1","native_message_id":"msg-1","timing":{"duration_ms":10}}`), nil
	}}
	_, ctx, conn, desc := setup(t, mock, nil)
	prep := prepareOnce(t, conn, ctx, desc, nil)
	started, _ := startOnce(t, conn, ctx, "Channel test-channel", "req-rel-fail", prep, "key-rel-fail", nil)
	relReq := ReleaseContextRequest{
		Handle: started.Handle.Handle, ContextRef: json.RawMessage(`"ctx-observed-1"`),
		AuthorizationRefs: []EvidenceRef{testEvidenceRef("journal-1", 1, "auth-1")},
	}
	resp := doConnector(t, conn, ctx, "Channel test-channel",
		connectorRequest(OpReleaseNativeContext, "rel-fail-1", desc.ConnectorID, relReq))
	raw := requireSuccessKind(t, resp, "control_receipt")
	var receipt ControlReceipt
	if err := json.Unmarshal(raw, &receipt); err != nil {
		t.Fatalf("decode release receipt: %v", err)
	}
	if receipt.Observation.Disposition != "requested" {
		t.Fatalf("failed release disposition = %q, want requested", receipt.Observation.Disposition)
	}
	if got := len(conn.ContainCalls()); got != 0 {
		t.Fatalf("release failure invoked containment %d times; must never silently contain", got)
	}
	for _, u := range mock.urls() {
		if strings.Contains(u, "contain") {
			t.Fatalf("release failure invoked native containment endpoint %q", u)
		}
	}
}

func TestContainmentRequiresVerifiedTargetAndIndependentAuthority(t *testing.T) {
	mock := &mockNative{}
	_, ctx, conn, desc := setup(t, mock, nil)
	prep := prepareOnce(t, conn, ctx, desc, nil)
	started, _ := startOnce(t, conn, ctx, "Channel test-channel", "req-contain", prep, "key-contain", nil)
	handle := started.Handle.Handle
	policy := testVersionPin("reviewed-action", "v1", "reviewed-v1")
	// Unverified target is rejected even with full grants.
	badReq := ContainRequest{
		Handle: handle, Target: ContainmentTarget{Kind: "local_process", ResourceID: "unverified-pid-99999"},
		Policy: policy, Reason: "test containment",
		AuthorizationRefs: []EvidenceRef{testEvidenceRef("journal-1", 1, "auth-1")},
	}
	respBad := doConnector(t, conn, ctx, "Channel test-channel",
		connectorRequest(OpContain, "contain-bad", desc.ConnectorID, badReq))
	cerrBad := parseConnectorError(t, respBad)
	if cerrBad.Code != "INVALID_REQUEST" {
		t.Fatalf("unverified target code = %q, want INVALID_REQUEST", cerrBad.Code)
	}
	// Verified target without independent authority is forbidden.
	conn.RegisterContainmentTarget("local_process", "proc-verified-1")
	goodReq := ContainRequest{
		Handle: handle, Target: ContainmentTarget{Kind: "local_process", ResourceID: "proc-verified-1"},
		Policy: policy, Reason: "test containment",
		AuthorizationRefs: []EvidenceRef{testEvidenceRef("journal-1", 1, "auth-1")},
	}
	connOnlyCtx := connectorOnlyContext(t)
	respNoAuth := doConnector(t, conn, connOnlyCtx, "Channel conn-channel",
		connectorRequest(OpContain, "contain-noauth", desc.ConnectorID, goodReq))
	cerrNoAuth := parseConnectorError(t, respNoAuth)
	if cerrNoAuth.Code != "FORBIDDEN" {
		t.Fatalf("missing independent authority code = %q, want FORBIDDEN: %s", cerrNoAuth.Code, string(respNoAuth.Result))
	}
	// Verified target with independent authority succeeds.
	respOK := doConnector(t, conn, ctx, "Channel test-channel",
		connectorRequest(OpContain, "contain-ok", desc.ConnectorID, goodReq))
	rawOK := requireSuccessKind(t, respOK, "control_receipt")
	var receipt ControlReceipt
	if err := json.Unmarshal(rawOK, &receipt); err != nil {
		t.Fatalf("decode contain receipt: %v", err)
	}
	if receipt.Observation.Operation != OpContain || receipt.Observation.Disposition != "requested" {
		t.Fatalf("contain receipt = %+v", receipt.Observation)
	}
}

func TestDrainingOrClosedObservationRejectsResume(t *testing.T) {
	mock := &mockNative{}
	store, ctx, conn, desc := setup(t, mock, nil)
	prep := prepareOnce(t, conn, ctx, desc, nil)
	started, _ := startOnce(t, conn, ctx, "Channel test-channel", "req-resume-base", prep, "key-resume", nil)
	handle := started.Handle.Handle
	closeReq := CloseConnectionRequest{
		Handle: handle, Reason: "local_deadline", EndObservation: true,
		AuthorizationRefs: []EvidenceRef{testEvidenceRef("journal-1", 1, "auth-1")},
	}
	closeResp := doConnector(t, conn, ctx, "Channel test-channel",
		connectorRequest(OpCloseObservationConnection, "close-resume", desc.ConnectorID, closeReq))
	requireSuccessKind(t, closeResp, "control_receipt")
	waitFor(t, 8*time.Second, "closure before resume", func() bool {
		st, _ := conn.HandleState(handle.LocalHandle)
		return st == "closed"
	})
	checkpointBytes := []byte(`{"handle":"` + handle.LocalHandle + `","offset_ms":123}`)
	checkpointRef, err := owner_store.InstallArtifact(ctx, store, bytes.NewReader(checkpointBytes), "application/json", "restricted")
	if err != nil {
		t.Fatalf("install checkpoint: %v", err)
	}
	resume := ResumeAuthorization{
		Handle: handle, Checkpoint: checkpointRef,
		NativeResumeContract: testVersionPin("native-resume", "v1", "resume-v1"),
		AuthorizationRefs: []EvidenceRef{testEvidenceRef("journal-1", 1, "auth-1")},
		EvidenceRefs:      []EvidenceRef{testEvidenceRef("journal-1", 2, "ev-2")},
	}
	_, resp := startOnce(t, conn, ctx, "Channel test-channel", "req-resume-attempt", prep, "key-resume", resume)
	cerr := parseConnectorError(t, resp)
	if cerr.Code != "OBSERVATION_CLOSED" {
		t.Fatalf("resume after draining/closed code = %q, want OBSERVATION_CLOSED: %s", cerr.Code, string(resp.Result))
	}
}

func TestSpeculativeNativeEndpointsAreNeverInvoked(t *testing.T) {
	mock := &mockNative{}
	_, ctx, conn, desc := setup(t, mock, nil)
	allowed := map[string]bool{
		"http://native.test/start": true, "http://native.test/cancel": true, "http://native.test/release": true,
	}
	// Describe and Prepare never touch native.
	descReq := connectorRequest(OpDescribe, "desc-spec", desc.ConnectorID, map[string]any{})
	descResp := doConnector(t, conn, ctx, "Channel test-channel", descReq)
	var descProbe map[string]any
	if err := json.Unmarshal(descResp.Result, &descProbe); err != nil {
		t.Fatalf("decode describe: %v", err)
	}
	if rt, _ := descProbe["record_type"].(string); rt != "connector_descriptor" {
		t.Fatalf("describe record_type = %q", rt)
	}
	if got := mock.count(); got != 0 {
		t.Fatalf("Describe invoked native %d times", got)
	}
	prep := prepareOnce(t, conn, ctx, desc, nil)
	if got := mock.count(); got != 0 {
		t.Fatalf("Prepare invoked native %d times; prepare is non-executing", got)
	}
	// Start invokes exactly the declared start endpoint.
	started, _ := startOnce(t, conn, ctx, "Channel test-channel", "req-spec-start", prep, "key-spec", nil)
	waitFor(t, 5*time.Second, "start delivery", func() bool { return mock.count() >= 1 })
	if got := mock.count(); got != 1 {
		t.Fatalf("start native calls = %d, want 1", got)
	}
	handle := started.Handle.Handle
	// Read-only calls never touch native.
	_ = observeLive(t, conn, ctx, handle, zeroCursor(handle), 10)
	collReq := CollectArtifactsRequest{Handle: handle, Selector: CollectSelector{Mode: "inventory"}}
	collResp := doConnector(t, conn, ctx, "Channel test-channel",
		connectorRequest(OpCollectArtifacts, "coll-spec", desc.ConnectorID, collReq))
	requireSuccessKind(t, collResp, "artifact_inventory")
	if got := mock.count(); got != 1 {
		t.Fatalf("Observe/Collect invoked native; calls = %d, want 1", got)
	}
	// Mapped controls invoke only their declared endpoints.
	cancelReq := NativeCancelRequest{
		Handle: handle, Reason: "test", AuthorizationRefs: []EvidenceRef{testEvidenceRef("journal-1", 1, "auth-1")},
	}
	doConnector(t, conn, ctx, "Channel test-channel",
		connectorRequest(OpRequestNativeCancel, "cancel-spec", desc.ConnectorID, cancelReq))
	relReq := ReleaseContextRequest{
		Handle: handle, ContextRef: json.RawMessage(`"ctx-1"`),
		AuthorizationRefs: []EvidenceRef{testEvidenceRef("journal-1", 1, "auth-1")},
	}
	doConnector(t, conn, ctx, "Channel test-channel",
		connectorRequest(OpReleaseNativeContext, "rel-spec", desc.ConnectorID, relReq))
	closeReq := CloseConnectionRequest{
		Handle: handle, Reason: "operator_stop", EndObservation: false,
		AuthorizationRefs: []EvidenceRef{testEvidenceRef("journal-1", 1, "auth-1")},
	}
	doConnector(t, conn, ctx, "Channel test-channel",
		connectorRequest(OpCloseObservationConnection, "close-spec", desc.ConnectorID, closeReq))
	for _, u := range mock.urls() {
		if !allowed[u] {
			t.Fatalf("speculative native endpoint invoked: %q (allowed %v)", u, allowed)
		}
		if strings.Contains(strings.ToLower(u), "speculat") || strings.Contains(strings.ToLower(u), "probe") {
			t.Fatalf("speculative endpoint invoked: %q", u)
		}
	}
}

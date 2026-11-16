package connector_entrypoint

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"authority"
	"evidence_codec"
	native_mapping "native_mapping"
	owner_store "owner_store"
	reference_connector "reference_connector"
)

// ---------------------------------------------------------------------------
// Auth and owner-store fixtures.
// ---------------------------------------------------------------------------

func testPolicy() []byte {
	return []byte(`{"channels":{"test-channel":{"principal":"test-writer","kind":"owner","grants":[{"domain":"*","operations":["*"]}]}}}`)
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

func testManifest(domain, journalID string) owner_store.Manifest {
	return owner_store.Manifest{
		RecordType:    "manifest",
		SchemaVersion: "0.1.0",
		ManifestID:    "manifest-" + journalID,
		RunID:         "run-" + domain,
		JournalID:     journalID,
		OwnerDomain:   domain,
		Clocks: []owner_store.ClockDescriptor{{
			ClockID: "clock-" + domain, BootID: "boot-" + domain,
			Origin: "engine_measured", SourceID: "owner-store",
			Basis: "monotonic_offset", Unit: "ms",
		}},
	}
}

func testTimePoint(m owner_store.Manifest, offsetMs float64) owner_store.TimePoint {
	clock := m.Clocks[0]
	return owner_store.TimePoint{
		ClockID: clock.ClockID, BootID: clock.BootID, Origin: clock.Origin,
		MonotonicOffsetMs: offsetMs, UTCAnnotation: owner_store.NewMissing("not_applicable"),
	}
}

func canonicalManifest(t *testing.T, m owner_store.Manifest) []byte {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	canonical, err := evidence_codec.CanonicalJSON(raw, "application/json")
	if err != nil {
		t.Fatalf("canonicalize manifest: %v", err)
	}
	return canonical
}

func installTestArtifact(t *testing.T, ctx context.Context, store *owner_store.OwnerStore, content []byte, mediaType, access string) owner_store.ArtifactReference {
	t.Helper()
	ref, err := owner_store.InstallArtifact(ctx, store, bytes.NewReader(content), mediaType, access)
	if err != nil {
		t.Fatalf("InstallArtifact: %v", err)
	}
	return ref
}

func artifactRefMap(ref owner_store.ArtifactReference) map[string]any {
	return map[string]any{
		"digest":       string(ref.Digest),
		"size_bytes":   ref.SizeBytes,
		"media_type":   ref.MediaType,
		"owner_domain": ref.OwnerDomain,
		"access":       ref.Access,
	}
}

func admitJournal(t *testing.T, ctx context.Context, store *owner_store.OwnerStore, m owner_store.Manifest) ([]owner_store.JournalEnvelope, owner_store.JournalPrefix) {
	t.Helper()
	ref := installTestArtifact(t, ctx, store, canonicalManifest(t, m), "application/json", "public")
	submission := owner_store.EventSubmission{
		ProducerSequence:   int64(1),
		EventKind:          "manifest_admitted",
		EventSchemaVersion: "0.1.0",
		OccurredAt:         testTimePoint(m, 0),
		Payload: owner_store.Payload{
			Data:         map[string]any{"manifest": artifactRefMap(ref)},
			Measurements: []owner_store.Measurement{},
			EvidenceRefs: []owner_store.EvidenceRef{},
			ArtifactRefs: []owner_store.ArtifactReference{ref},
		},
	}
	envelopes, err := owner_store.CommitOwner(ctx, store, m.JournalID, []owner_store.EventSubmission{submission}, nil)
	if err != nil {
		t.Fatalf("admit journal: %v", err)
	}
	if len(envelopes) != 1 {
		t.Fatalf("admission returned %d envelopes", len(envelopes))
	}
	return envelopes, owner_store.JournalPrefix{
		JournalID:    m.JournalID,
		LastSequence: envelopes[0].Sequence,
		HeadHash:     envelopes[0].EventHash,
	}
}

func eventSubmission(m owner_store.Manifest, sequence int64, kind string, data map[string]any, refs ...owner_store.ArtifactReference) owner_store.EventSubmission {
	if data == nil {
		data = map[string]any{}
	}
	if refs == nil {
		refs = []owner_store.ArtifactReference{}
	}
	return owner_store.EventSubmission{
		ProducerSequence:   sequence,
		EventKind:          kind,
		EventSchemaVersion: "0.1.0",
		OccurredAt:         testTimePoint(m, float64(sequence)),
		Payload: owner_store.Payload{
			Data:         data,
			Measurements: []owner_store.Measurement{},
			EvidenceRefs: []owner_store.EvidenceRef{},
			ArtifactRefs: refs,
		},
	}
}

func mustCommit(t *testing.T, ctx context.Context, store *owner_store.OwnerStore, journalID string, events ...owner_store.EventSubmission) []owner_store.JournalEnvelope {
	t.Helper()
	envelopes, err := owner_store.CommitOwner(ctx, store, journalID, events, nil)
	if err != nil {
		t.Fatalf("CommitOwner: %v", err)
	}
	return envelopes
}

// ---------------------------------------------------------------------------
// Connector wire fixtures (synthetic only).
// ---------------------------------------------------------------------------

func testDigest(seed string) string {
	return string(evidence_codec.HashBytes([]byte(seed)))
}

func testEvidenceRef(journalID string, seq int64, eventID string) reference_connector.EvidenceRef {
	return reference_connector.EvidenceRef{
		JournalID: journalID, Sequence: seq, EventID: eventID,
		EventHash: testDigest("event-" + eventID), Pointer: "",
	}
}

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

func nmConfiguration(desc reference_connector.ConnectorDescriptor) native_mapping.ConfigurationPin {
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

func nmPrepareRequest(desc reference_connector.ConnectorDescriptor) native_mapping.PrepareRequest {
	return native_mapping.PrepareRequest{
		Scope: nmScopeForApply(), Configuration: nmConfiguration(desc), Task: nmApplyTask(),
		Assistance: nmAssistance(), PlanningEvidenceRefs: []native_mapping.EvidenceRef{},
		PreparationMeasurements: []native_mapping.MeasurementEvidence{}, RuntimeAccess: []native_mapping.RuntimeAccess{},
	}
}

func connectorRequest(operation, requestID, connectorID string, payload any) reference_connector.ConnectorRequest {
	raw, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	return reference_connector.ConnectorRequest{
		RecordType: reference_connector.RecordTypeRequest, SchemaVersion: reference_connector.SchemaVersion,
		RequestID: requestID, ConnectorID: connectorID, Operation: operation,
		CallLimit: reference_connector.DurationLimit{Kind: "exact", Unit: "ms", Value: 30000},
		Payload:   json.RawMessage(raw),
	}
}

func doConnector(t *testing.T, handler http.Handler, ctx context.Context, authHeader string, req reference_connector.ConnectorRequest) reference_connector.ConnectorResponse {
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
		t.Fatalf("carrier status %d: %s", rec.Code, rec.Body.String())
	}
	var resp reference_connector.ConnectorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v: %s", err, rec.Body.String())
	}
	if resp.RequestID != req.RequestID || resp.Operation != req.Operation || resp.ConnectorID != req.ConnectorID {
		t.Fatalf("response correlation mismatch: %+v vs %+v", resp, req)
	}
	assertNoBareNulls(t, rec.Body.Bytes())
	return resp
}

func parseConnectorError(t *testing.T, resp reference_connector.ConnectorResponse) reference_connector.ConnectorError {
	t.Helper()
	var cerr reference_connector.ConnectorError
	if err := json.Unmarshal(resp.Result, &cerr); err != nil {
		t.Fatalf("decode connector error: %v: %s", err, string(resp.Result))
	}
	if cerr.Kind != "connector_error" {
		t.Fatalf("expected connector_error, got kind %q: %s", cerr.Kind, string(resp.Result))
	}
	return cerr
}

func requireSuccessKind(t *testing.T, resp reference_connector.ConnectorResponse, kind string) json.RawMessage {
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

func jsonNativeResponse(body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
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

func zeroCursor(handle reference_connector.HandleReference) reference_connector.ObservationCursor {
	return reference_connector.ObservationCursor{
		Handle: handle, JournalID: handle.LocalHandle, Sequence: 0,
		EventHash: json.RawMessage(`{"value":null,"reason":"not_applicable"}`),
	}
}

func observeLive(t *testing.T, handler http.Handler, ctx context.Context, handle reference_connector.HandleReference, after reference_connector.ObservationCursor, maxItems int64) reference_connector.ObservationPage {
	t.Helper()
	through := json.RawMessage(`{"value":null,"reason":"not_applicable"}`)
	oreq := reference_connector.ObserveRequest{
		Handle: handle, After: after, Through: through,
		MaxItems: maxItems, WaitLimit: reference_connector.DurationLimit{Kind: "exact", Unit: "ms", Value: 0},
	}
	req := connectorRequest(reference_connector.OpObserve, fmt.Sprintf("obs-%d", time.Now().UnixNano()), handle.ConnectorID, oreq)
	resp := doConnector(t, handler, ctx, "Channel test-channel", req)
	raw := requireSuccessKind(t, resp, "observation_page")
	var page reference_connector.ObservationPage
	if err := json.Unmarshal(raw, &page); err != nil {
		t.Fatalf("decode observation page: %v", err)
	}
	return page
}

func prepareOnce(t *testing.T, handler http.Handler, ctx context.Context, desc reference_connector.ConnectorDescriptor, mutate func(*native_mapping.PrepareRequest)) reference_connector.PrepareResult {
	t.Helper()
	nmReq := nmPrepareRequest(desc)
	if mutate != nil {
		mutate(&nmReq)
	}
	req := connectorRequest(reference_connector.OpPrepare, fmt.Sprintf("prep-%d", time.Now().UnixNano()), desc.ConnectorID, nmReq)
	resp := doConnector(t, handler, ctx, "Channel test-channel", req)
	raw := requireSuccessKind(t, resp, "prepared")
	var result reference_connector.PrepareResult
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("decode prepare result: %v", err)
	}
	return result
}

func startOnce(t *testing.T, handler http.Handler, ctx context.Context, authHeader string, requestID string, prep reference_connector.PrepareResult, key string, recovery any) (reference_connector.StartResult, reference_connector.ConnectorResponse) {
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
	sreq := reference_connector.StartRequest{
		Preparation: prep.Preparation, IdempotencyKey: key,
		AcceptedConcernIDs: []string{},
		AuthorizationRefs:  []reference_connector.EvidenceRef{testEvidenceRef("journal-1", 1, "auth-1")},
		Recovery:           recoveryRaw,
	}
	for _, k := range prep.Record.Concerns {
		if k.RequiresAcceptance {
			sreq.AcceptedConcernIDs = append(sreq.AcceptedConcernIDs, k.ConcernID)
		}
	}
	req := connectorRequest(reference_connector.OpStart, requestID, "test-connector", sreq)
	resp := doConnector(t, handler, ctx, authHeader, req)
	var probe map[string]any
	_ = json.Unmarshal(resp.Result, &probe)
	if k, _ := probe["kind"].(string); k == "connector_error" {
		return reference_connector.StartResult{}, resp
	}
	var result reference_connector.StartResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("decode start result: %v: %s", err, string(resp.Result))
	}
	return result, resp
}

// ---------------------------------------------------------------------------
// Crash-child helper: real OS process holding the connector store.
// ---------------------------------------------------------------------------

// TestConnectorCrashChild is the re-executed child for process-failure
// isolation. It is not part of the verification filter; the parent spawns it
// via os.Executable with CONNECTOR_ENTRYPOINT_CRASH_CHILD=1 and kills it with
// SIGKILL while it hammers the connector store.
func TestConnectorCrashChild(t *testing.T) {
	if os.Getenv("CONNECTOR_ENTRYPOINT_CRASH_CHILD") != "1" {
		t.Skip("crash child only runs when re-executed by the parent test")
	}
	root := os.Getenv("CONNECTOR_ENTRYPOINT_CRASH_ROOT")
	if root == "" {
		t.Fatalf("crash child: CONNECTOR_ENTRYPOINT_CRASH_ROOT is empty")
	}
	store, err := owner_store.OpenOwner(
		filepath.Join(root, "connector.db"),
		filepath.Join(root, "artifacts", "connector"),
		"connector",
	)
	if err != nil {
		t.Fatalf("crash child: OpenOwner: %v", err)
	}
	defer store.Close()
	ctx := testContext(t)
	journalID := fmt.Sprintf("crash-child-%d", os.Getpid())
	manifest := testManifest("connector", journalID)
	if _, _, err := func() ([]owner_store.JournalEnvelope, owner_store.JournalPrefix, error) {
		ref := installTestArtifact(t, ctx, store, canonicalManifest(t, manifest), "application/json", "public")
		submission := owner_store.EventSubmission{
			ProducerSequence:   int64(1),
			EventKind:          "manifest_admitted",
			EventSchemaVersion: "0.1.0",
			OccurredAt:         testTimePoint(manifest, 0),
			Payload: owner_store.Payload{
				Data:         map[string]any{"manifest": artifactRefMap(ref)},
				Measurements: []owner_store.Measurement{},
				EvidenceRefs: []owner_store.EvidenceRef{},
				ArtifactRefs: []owner_store.ArtifactReference{ref},
			},
		}
		envs, err := owner_store.CommitOwner(ctx, store, manifest.JournalID, []owner_store.EventSubmission{submission}, nil)
		if err != nil {
			return nil, owner_store.JournalPrefix{}, err
		}
		last := envs[len(envs)-1]
		return envs, owner_store.JournalPrefix{JournalID: manifest.JournalID, LastSequence: last.Sequence, HeadHash: last.EventHash}, nil
	}(); err != nil {
		t.Fatalf("crash child: admit journal: %v", err)
	}
	readyPath := filepath.Join(root, "child-ready")
	if err := os.WriteFile(readyPath, []byte("ready"), 0o644); err != nil {
		t.Fatalf("crash child: signal ready: %v", err)
	}
	// Hammer the connector store until the parent kills us. Each iteration
	// is one owner-local commit; none touches the laboratory databases.
	var seq int64 = 2
	for {
		sub := eventSubmission(manifest, seq, "crash_probe", map[string]any{"iteration": seq})
		if _, err := owner_store.CommitOwner(ctx, store, journalID, []owner_store.EventSubmission{sub}, nil); err != nil {
			// A busy or halting store still proves we were writing; keep
			// hammering until SIGKILL.
			time.Sleep(5 * time.Millisecond)
			continue
		}
		seq++
	}
}

// ---------------------------------------------------------------------------
// Conformance assertions.
// ---------------------------------------------------------------------------

// TestReferenceConnectorPassesItsSuiteWithOnlySyntheticBackend drives the
// reference connector through its EXT wire suite (Describe, Prepare, Start
// durability and idempotency, Observe) using only the synthetic loopback
// backend. No live circus-tent or Ringmaster deployment is consulted.
func TestReferenceConnectorPassesItsSuiteWithOnlySyntheticBackend(t *testing.T) {
	for _, k := range []string{"CIRCUS_TENT_URL", "RINGMASTER_URL", "HELLSACPE_LIVE_SUBJECT", "CIRCUS_TENT_ADDR", "RINGMASTER_ADDR"} {
		if v := os.Getenv(k); v != "" {
			t.Fatalf("silo acceptance must not require %s (got %q)", k, v)
		}
	}
	root := t.TempDir()
	backend := newSyntheticBackend()
	descriptor := defaultDescriptor()
	if descriptor.ConnectorID != "test-connector" {
		t.Fatalf("descriptor connector_id = %q, want test-connector", descriptor.ConnectorID)
	}
	endpoint, err := openConnector(root, nil, descriptor, backend)
	if err != nil {
		t.Fatalf("openConnector: %v", err)
	}
	t.Cleanup(func() { _ = endpoint.close() })
	ctx := testContext(t)
	handler := endpoint.handler
	if handler == nil {
		t.Fatalf("connector handler is nil")
	}
	conn, ok := handler.(*reference_connector.Connector)
	if !ok {
		t.Fatalf("handler is %T, want *reference_connector.Connector", handler)
	}

	// Describe: exactly nine verbs and the minimum capability set.
	descReq := connectorRequest(reference_connector.OpDescribe, "desc-silo-1", descriptor.ConnectorID, map[string]any{})
	descResp := doConnector(t, handler, ctx, "Channel test-channel", descReq)
	descRaw := requireSuccessKind(t, descResp, "connector_descriptor")
	var gotDesc reference_connector.ConnectorDescriptor
	if err := json.Unmarshal(descRaw, &gotDesc); err != nil {
		t.Fatalf("decode descriptor: %v", err)
	}
	if len(gotDesc.Operations) != 9 {
		t.Fatalf("descriptor operations = %d, want exactly 9", len(gotDesc.Operations))
	}
	seenOps := map[string]bool{}
	for _, op := range gotDesc.Operations {
		seenOps[op.Operation] = true
	}
	for _, want := range []string{
		reference_connector.OpDescribe, reference_connector.OpPrepare, reference_connector.OpStart,
		reference_connector.OpObserve, reference_connector.OpRequestNativeCancel,
		reference_connector.OpCloseObservationConnection, reference_connector.OpCollectArtifacts,
		reference_connector.OpReleaseNativeContext, reference_connector.OpContain,
	} {
		if !seenOps[want] {
			t.Fatalf("descriptor missing verb %q", want)
		}
	}
	haveCaps := map[string]bool{}
	for _, c := range gotDesc.Capabilities {
		haveCaps[c.ID] = true
	}
	for _, want := range []string{
		"native_goal_task", "native_plan_execution", "native_cancel",
		"native_context_release", "native_artifact_retrieval", "native_revision",
		"native_dom_access", "browser_state_isolation", "browser_state_persistence",
		"learning_state_control",
	} {
		if !haveCaps[want] {
			t.Fatalf("descriptor missing capability %q", want)
		}
	}

	// Prepare is non-executing: no native invocation.
	if backend.callCount() != 0 {
		t.Fatalf("native calls before Prepare = %d, want 0", backend.callCount())
	}
	prep := prepareOnce(t, handler, ctx, descriptor, nil)
	if prep.Preparation.PreparationID == "" {
		t.Fatalf("empty preparation id")
	}
	if backend.callCount() != 0 {
		t.Fatalf("Prepare invoked native %d times; must be non-executing", backend.callCount())
	}

	// Start returns before native completion with a durable handle. Block
	// the synthetic native and prove the receipt, handle, and dispatch
	// intent are durable while native is still blocked.
	release := make(chan struct{})
	var once sync.Once
	backend.handler = func(r *http.Request) (*http.Response, error) {
		<-release
		return jsonNativeResponse(`{"state":"completed","native_run_id":"run-1","native_message_id":"msg-1","timing":{"duration_ms":10}}`), nil
	}
	type startOut struct {
		result reference_connector.StartResult
		resp   reference_connector.ConnectorResponse
	}
	outCh := make(chan startOut, 1)
	go func() {
		result, resp := startOnce(t, handler, ctx, "Channel test-channel", "req-silo-durable", prep, "key-silo-durable", nil)
		outCh <- startOut{result: result, resp: resp}
	}()
	select {
	case out := <-outCh:
		if out.result.Disposition != "accepted_locally" {
			t.Fatalf("disposition = %q, want accepted_locally", out.result.Disposition)
		}
		local := out.result.Handle.Handle.LocalHandle
		if local == "" {
			t.Fatalf("empty local handle")
		}
		prefix, ok := conn.HandlePrefix(local)
		if !ok {
			t.Fatalf("no handle prefix while native blocked")
		}
		stPrefix := owner_store.JournalPrefix{JournalID: prefix.JournalID, LastSequence: prefix.LastSequence, HeadHash: prefix.HeadHash}
		events, err := owner_store.LoadPrefix(ctx, endpoint.store, stPrefix)
		if err != nil {
			t.Fatalf("LoadPrefix while native blocked: %v", err)
		}
		kinds := map[string]bool{}
		for _, env := range events {
			kinds[env.EventKind] = true
		}
		for _, want := range []string{"handle_bound", "request_binding", "dispatch_intent"} {
			if !kinds[want] {
				t.Fatalf("durable journal missing %q while native blocked; have %v", want, kinds)
			}
		}
		once.Do(func() { close(release) })
		waitFor(t, 5*time.Second, "synthetic native delivery after release", func() bool {
			return backend.callCount() >= 1
		})
		// Repeated logical Start returns the same handle.
		second, _ := startOnce(t, handler, ctx, "Channel test-channel", "req-silo-repeat", prep, "key-silo-durable", nil)
		if second.Disposition != "existing_handle" {
			t.Fatalf("repeated disposition = %q, want existing_handle", second.Disposition)
		}
		if second.Handle.Handle.LocalHandle != local {
			t.Fatalf("repeated handle = %q, want %q", second.Handle.Handle.LocalHandle, local)
		}
		// Identical command retry returns the retained receipt.
		replay, _ := startOnce(t, handler, ctx, "Channel test-channel", "req-silo-durable", prep, "key-silo-durable", nil)
		if replay.Handle.Handle.LocalHandle != local {
			t.Fatalf("identical retry handle = %q, want %q", replay.Handle.Handle.LocalHandle, local)
		}
		// Conflicting content under the same command key is rejected.
		_, conflictResp := startOnce(t, handler, ctx, "Channel test-channel", "req-silo-durable", prep, "key-silo-other", nil)
		cerr := parseConnectorError(t, conflictResp)
		if cerr.Code != "IDEMPOTENCY_CONFLICT" {
			t.Fatalf("conflict code = %q, want IDEMPOTENCY_CONFLICT: %s", cerr.Code, string(conflictResp.Result))
		}
		// Observe returns the journaled projection; poll until the async
		// synthetic native report is journaled, then verify all native URLs
		// are synthetic loopback endpoints, never live deployments.
		waitFor(t, 5*time.Second, "synthetic native report via Observe", func() bool {
			page := observeLive(t, handler, ctx, out.result.Handle.Handle, zeroCursor(out.result.Handle.Handle), 100)
			for _, it := range page.Items {
				if k, _ := it.Payload["kind"].(string); k == "native_report" {
					return true
				}
			}
			return len(page.Items) > 0
		})
		for _, u := range backend.urls() {
			if !strings.HasPrefix(u, "http://native.test/") {
				t.Fatalf("native URL %q is not synthetic loopback", u)
			}
		}
	case <-time.After(10 * time.Second):
		once.Do(func() { close(release) })
		t.Fatalf("Start did not return while native blocked; it must not await completion")
	}
}

// TestConnectorAuthorityUsesStorageOutsideThreeLaboratoryDatabases proves the
// connector authority writes to connector.db and a connector-owned artifact
// root, never to application.db, observation.db, or diagnostic.db.
func TestConnectorAuthorityUsesStorageOutsideThreeLaboratoryDatabases(t *testing.T) {
	root := t.TempDir()
	lab, err := openLaboratory(root)
	if err != nil {
		t.Fatalf("openLaboratory: %v", err)
	}
	t.Cleanup(func() { _ = lab.close() })
	names := laboratoryDatabaseNames()
	if len(names) != 3 || names[0] != "application.db" || names[1] != "observation.db" || names[2] != "diagnostic.db" {
		t.Fatalf("laboratory names = %v, want exactly the three laboratory databases", names)
	}
	labPaths := lab.databasePaths()
	seenPaths := map[string]bool{}
	for i, p := range labPaths {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("laboratory database %s missing at %s: %v", names[i], p, err)
		}
		abs, _ := filepath.Abs(p)
		if seenPaths[abs] {
			t.Fatalf("laboratory database paths are not independent: %v", labPaths)
		}
		seenPaths[abs] = true
	}
	labArts := lab.artifactRoots()
	seenArts := map[string]bool{}
	for _, a := range labArts {
		if _, err := os.Stat(a); err != nil {
			t.Fatalf("laboratory artifact root %s missing: %v", a, err)
		}
		abs, _ := filepath.Abs(a)
		if seenArts[abs] {
			t.Fatalf("laboratory artifact roots are not independent: %v", labArts)
		}
		seenArts[abs] = true
	}

	ctx := testContext(t)
	// Baseline laboratory journals: one admitted journal per owner.
	labManifests := map[string]owner_store.Manifest{
		"application": testManifest("application", "journal-storage-app"),
		"observation": testManifest("observation", "journal-storage-obs"),
		"diagnostic":  testManifest("diagnostic", "journal-storage-diag"),
	}
	labStores := map[string]*owner_store.OwnerStore{
		"application": lab.application, "observation": lab.observation, "diagnostic": lab.diagnostic,
	}
	labPrefixes := map[string]owner_store.JournalPrefix{}
	for domain, store := range labStores {
		_, prefix := admitJournal(t, ctx, store, labManifests[domain])
		labPrefixes[domain] = prefix
	}
	snapshot := func() map[string]string {
		out := map[string]string{}
		for domain, store := range labStores {
			envs, err := owner_store.LoadPrefix(ctx, store, labPrefixes[domain])
			if err != nil {
				t.Fatalf("%s: LoadPrefix baseline: %v", domain, err)
			}
			raw, _ := json.Marshal(envs)
			out[domain] = string(raw)
		}
		return out
	}
	before := snapshot()

	// Wire the connector through the entrypoint; storage must be outside.
	backend := newSyntheticBackend()
	descriptor := defaultDescriptor()
	endpoint, err := openConnector(root, lab, descriptor, backend)
	if err != nil {
		t.Fatalf("openConnector: %v", err)
	}
	t.Cleanup(func() { _ = endpoint.close() })
	if got := filepath.Base(endpoint.storePath); got != connectorDatabaseName() {
		t.Fatalf("connector database base = %q, want %q", got, connectorDatabaseName())
	}
	if isLaboratoryDatabaseName(filepath.Base(endpoint.storePath)) {
		t.Fatalf("connector database %q is a laboratory name", endpoint.storePath)
	}
	absConn, _ := filepath.Abs(endpoint.storePath)
	for _, p := range labPaths {
		absLab, _ := filepath.Abs(p)
		if absConn == absLab {
			t.Fatalf("connector storage %q collides with laboratory %q", endpoint.storePath, p)
		}
	}
	absConnArt, _ := filepath.Abs(endpoint.artifactRoot)
	for _, a := range labArts {
		absLabArt, _ := filepath.Abs(a)
		if absConnArt == absLabArt {
			t.Fatalf("connector artifact root %q collides with laboratory %q", endpoint.artifactRoot, a)
		}
	}
	if _, err := os.Stat(endpoint.storePath); err != nil {
		t.Fatalf("connector database missing at %s: %v", endpoint.storePath, err)
	}
	if _, err := os.Stat(endpoint.artifactRoot); err != nil {
		t.Fatalf("connector artifact root missing at %s: %v", endpoint.artifactRoot, err)
	}
	// The entrypoint rejects laboratory paths for connector storage.
	for _, p := range labPaths {
		if err := checkStorageOutsideLaboratory(p, endpoint.artifactRoot, lab); err == nil {
			t.Fatalf("checkStorageOutsideLaboratory accepted laboratory path %q", p)
		}
	}
	if err := checkStorageOutsideLaboratory(filepath.Join(root, "application.db"), endpoint.artifactRoot, lab); err == nil {
		t.Fatalf("checkStorageOutsideLaboratory accepted application.db")
	}

	// Connector writes land in connector.db with connector-owned artifacts.
	prep := prepareOnce(t, endpoint.handler, ctx, descriptor, nil)
	result, _ := startOnce(t, endpoint.handler, ctx, "Channel test-channel", "req-storage-1", prep, "key-storage-1", nil)
	if result.Handle.Handle.LocalHandle == "" {
		t.Fatalf("empty connector handle")
	}
	waitFor(t, 5*time.Second, "synthetic delivery", func() bool { return backend.callCount() >= 1 })
	conn, ok := endpoint.handler.(*reference_connector.Connector)
	if !ok {
		t.Fatalf("handler is %T", endpoint.handler)
	}
	prefix, ok := conn.HandlePrefix(result.Handle.Handle.LocalHandle)
	if !ok {
		t.Fatalf("no connector handle prefix")
	}
	stPrefix := owner_store.JournalPrefix{JournalID: prefix.JournalID, LastSequence: prefix.LastSequence, HeadHash: prefix.HeadHash}
	connEvents, err := owner_store.LoadPrefix(ctx, endpoint.store, stPrefix)
	if err != nil {
		t.Fatalf("LoadPrefix connector handle: %v", err)
	}
	if len(connEvents) < 3 {
		t.Fatalf("connector handle journal has %d events, want >= 3", len(connEvents))
	}
	// The connector handle journal exists only in connector.db.
	for domain, store := range labStores {
		if _, err := owner_store.LoadPrefix(ctx, store, stPrefix); err == nil {
			t.Fatalf("%s: connector handle journal %q is visible in a laboratory database", domain, stPrefix.JournalID)
		}
	}
	// Laboratory journals are byte-identical after connector writes.
	after := snapshot()
	for domain := range labStores {
		if before[domain] != after[domain] {
			t.Fatalf("%s: laboratory journal changed after connector writes", domain)
		}
	}
	// Artifact ownership proves separate authority: connector artifacts are
	// owned by "connector", laboratory artifacts by their own domains.
	connRef := installTestArtifact(t, ctx, endpoint.store, []byte(`{"owner":"connector"}`), "application/json", "public")
	if connRef.OwnerDomain != "connector" {
		t.Fatalf("connector artifact owner = %q, want connector", connRef.OwnerDomain)
	}
	for domain, store := range labStores {
		ref := installTestArtifact(t, ctx, store, []byte(`{"owner":"`+domain+`"}`), "application/json", "public")
		if ref.OwnerDomain != domain {
			t.Fatalf("%s: artifact owner = %q", domain, ref.OwnerDomain)
		}
	}
}

// TestConnectorProcessFailureCannotCorruptLaboratoryOwnerStores kills a real
// OS process holding the connector store with SIGKILL and proves the three
// laboratory owner stores remain readable and committable. An in-process
// double is never treated as proof of process isolation.
func TestConnectorProcessFailureCannotCorruptLaboratoryOwnerStores(t *testing.T) {
	root := t.TempDir()
	lab, err := openLaboratory(root)
	if err != nil {
		t.Fatalf("openLaboratory: %v", err)
	}
	t.Cleanup(func() { _ = lab.close() })
	ctx := testContext(t)

	// Baseline laboratory state, one journal per owner plus one probe event.
	labManifests := map[string]owner_store.Manifest{
		"application": testManifest("application", "journal-crash-app"),
		"observation": testManifest("observation", "journal-crash-obs"),
		"diagnostic":  testManifest("diagnostic", "journal-crash-diag"),
	}
	labStores := map[string]*owner_store.OwnerStore{
		"application": lab.application, "observation": lab.observation, "diagnostic": lab.diagnostic,
	}
	labPrefixes := map[string]owner_store.JournalPrefix{}
	for domain, store := range labStores {
		_, prefix := admitJournal(t, ctx, store, labManifests[domain])
		envs := mustCommit(t, ctx, store, labManifests[domain].JournalID,
			eventSubmission(labManifests[domain], 2, "baseline_probe", map[string]any{"domain": domain}))
		last := envs[len(envs)-1]
		labPrefixes[domain] = owner_store.JournalPrefix{JournalID: last.JournalID, LastSequence: last.Sequence, HeadHash: last.EventHash}
		_ = prefix
	}
	baseline := map[string]string{}
	for domain, store := range labStores {
		envs, err := owner_store.LoadPrefix(ctx, store, labPrefixes[domain])
		if err != nil {
			t.Fatalf("%s: LoadPrefix baseline: %v", domain, err)
		}
		raw, _ := json.Marshal(envs)
		baseline[domain] = string(raw)
	}

	// Create the connector store file, then close it so the child is the
	// sole writer while it hammers connector.db.
	backend := newSyntheticBackend()
	descriptor := defaultDescriptor()
	endpoint, err := openConnector(root, lab, descriptor, backend)
	if err != nil {
		t.Fatalf("openConnector: %v", err)
	}
	connectorDB := endpoint.storePath
	if err := endpoint.close(); err != nil {
		t.Fatalf("close connector before crash: %v", err)
	}
	if _, err := os.Stat(connectorDB); err != nil {
		t.Fatalf("connector database missing before crash: %v", err)
	}

	// Spawn the real child process and SIGKILL it mid-write.
	childBin, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	cmd := exec.Command(childBin, "-test.run", "^TestConnectorCrashChild$", "-test.count", "1", "-test.timeout", "60s")
	cmd.Env = append(os.Environ(),
		"CONNECTOR_ENTRYPOINT_CRASH_CHILD=1",
		"CONNECTOR_ENTRYPOINT_CRASH_ROOT="+root,
	)
	var childOut bytes.Buffer
	cmd.Stdout = &childOut
	cmd.Stderr = &childOut
	if err := cmd.Start(); err != nil {
		t.Fatalf("start crash child: %v", err)
	}
	readyPath := filepath.Join(root, "child-ready")
	waitFor(t, 15*time.Second, "crash child ready", func() bool {
		_, err := os.Stat(readyPath)
		return err == nil
	})
	// Let the child hammer connector.db, then kill -9 (no cleanup).
	time.Sleep(500 * time.Millisecond)
	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("kill crash child: %v", err)
	}
	_ = cmd.Wait()

	// Laboratory stores remain intact: baseline prefixes load byte-identical
	// and new owner-local commits succeed on every database.
	for domain, store := range labStores {
		envs, err := owner_store.LoadPrefix(ctx, store, labPrefixes[domain])
		if err != nil {
			t.Fatalf("%s: LoadPrefix after connector SIGKILL: %v\nchild output: %s", domain, err, childOut.String())
		}
		raw, _ := json.Marshal(envs)
		if string(raw) != baseline[domain] {
			t.Fatalf("%s: laboratory journal changed after connector SIGKILL", domain)
		}
	}
	for domain, store := range labStores {
		m := labManifests[domain]
		envs := mustCommit(t, ctx, store, m.JournalID,
			eventSubmission(m, 3, "post_crash_probe", map[string]any{"domain": domain, "after": "connector_sigkill"}))
		if len(envs) != 1 {
			t.Fatalf("%s: post-crash commit returned %d envelopes", domain, len(envs))
		}
		last := envs[len(envs)-1]
		extended := owner_store.JournalPrefix{JournalID: last.JournalID, LastSequence: last.Sequence, HeadHash: last.EventHash}
		all, err := owner_store.LoadPrefix(ctx, store, extended)
		if err != nil {
			t.Fatalf("%s: LoadPrefix after post-crash commit: %v", domain, err)
		}
		if int64(len(all)) != extended.LastSequence {
			t.Fatalf("%s: prefix length %d != last sequence %d", domain, len(all), extended.LastSequence)
		}
	}

	// The connector store file still exists and reopens as its own boundary;
	// laboratory databases were never attached to it.
	if _, err := os.Stat(connectorDB); err != nil {
		t.Fatalf("connector database missing after SIGKILL: %v", err)
	}
	reopened, err := owner_store.OpenOwner(connectorDB, filepath.Join(root, "artifacts", "connector"), "connector")
	if err != nil {
		t.Fatalf("reopen connector store after SIGKILL: %v", err)
	}
	_ = reopened.Close()
}

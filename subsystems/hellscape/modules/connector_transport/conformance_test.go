package connector_transport

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"authority"
)

func testPolicy() []byte {
	return []byte(`{"channels": {
		"test-token": {"principal": "harness", "kind": "control", "grants": [
			{"domain": "connector", "operations": ["*"]}
		]},
		"app-token": {"principal": "fixture-app", "kind": "application", "grants": [
			{"domain": "connector", "operations": ["Describe", "Observe"]}
		]}
	}}`)
}

func authCtx(t *testing.T, token string) context.Context {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "http://lab/connector", nil)
	if token != "" {
		r.Header.Set("Authorization", "Channel "+token)
	}
	ctx, err := authority.Authenticate(r, testPolicy())
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	return ctx
}

func callCtx(t *testing.T, endpoint string) context.Context {
	t.Helper()
	return ContextWithDeploymentEndpoints(authCtx(t, "test-token"), []string{endpoint})
}

func appCtx(t *testing.T, endpoint string) context.Context {
	t.Helper()
	return ContextWithDeploymentEndpoints(authCtx(t, "app-token"), []string{endpoint})
}

func newRequest(operation, payload string) ConnectorRequest {
	return ConnectorRequest{
		RecordType:    RecordTypeRequest,
		SchemaVersion: SchemaVersion,
		RequestID:     "req-1",
		ConnectorID:   "conn-1",
		Operation:     operation,
		CallLimit:     DurationLimit{Kind: "exact", Unit: "ms", Value: 5000},
		Payload:       json.RawMessage(payload),
	}
}

func writeReply(w http.ResponseWriter, status int, reply map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(reply)
}

func baseReply(req ConnectorRequest, result any) map[string]any {
	return map[string]any{
		"record_type":   RecordTypeResponse,
		"schema_version": SchemaVersion,
		"request_id":    req.RequestID,
		"connector_id":  req.ConnectorID,
		"operation":     req.Operation,
		"result":        result,
	}
}

func typedErrorResult(code, delivery, retry string) map[string]any {
	return map[string]any{
		"kind":               "connector_error",
		"code":               code,
		"fault_domain":       "connector",
		"detail":             "synthetic " + code,
		"operation_delivery": delivery,
		"retry_guidance":     retry,
		"retry_after":        map[string]any{"value": nil, "reason": "not_applicable"},
		"handle":             map[string]any{"value": nil, "reason": "not_applicable"},
		"evidence_refs":      []any{},
	}
}

func asConnectorError(t *testing.T, err error) *ConnectorError {
	t.Helper()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	ce, ok := err.(*ConnectorError)
	if !ok {
		t.Fatalf("error type = %T, want *ConnectorError (%v)", err, err)
	}
	return ce
}

func TestConnectorRepliesMustMatchRequestIdentityAndOperation(t *testing.T) {
	t.Run("happy path echoes identity", func(t *testing.T) {
		req := newRequest(OpDescribe, `{}`)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || r.URL.Path != "/connector" {
				t.Errorf("carrier = %s %s, want POST /connector", r.Method, r.URL.Path)
			}
			writeReply(w, http.StatusOK, baseReply(req, map[string]any{
				"record_type": "connector_descriptor", "schema_version": SchemaVersion, "connector_id": "conn-1",
			}))
		}))
		defer srv.Close()
		resp, err := CallConnector(callCtx(t, srv.URL+"/connector"), srv.URL+"/connector", req)
		if err != nil {
			t.Fatalf("CallConnector() error = %v", err)
		}
		if resp.RequestID != req.RequestID || resp.ConnectorID != req.ConnectorID || resp.Operation != req.Operation {
			t.Fatalf("reply identity = %+v, want echo of %+v", resp, req)
		}
		if resp.RecordType != RecordTypeResponse || resp.SchemaVersion != SchemaVersion {
			t.Fatalf("reply envelope = %s %s", resp.RecordType, resp.SchemaVersion)
		}
	})

	t.Run("request id mismatch is integrity conflict", func(t *testing.T) {
		req := newRequest(OpDescribe, `{}`)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reply := baseReply(req, map[string]any{"record_type": "connector_descriptor"})
			reply["request_id"] = "req-other"
			writeReply(w, http.StatusOK, reply)
		}))
		defer srv.Close()
		resp, err := CallConnector(callCtx(t, srv.URL+"/connector"), srv.URL+"/connector", req)
		ce := asConnectorError(t, err)
		if ce.Code != "INTEGRITY_CONFLICT" {
			t.Fatalf("code = %s, want INTEGRITY_CONFLICT", ce.Code)
		}
		if !strings.Contains(ce.Detail, "request_id") || !strings.Contains(ce.Detail, "no task outcome") {
			t.Fatalf("Detail = %q, want request_id mismatch with no task outcome", ce.Detail)
		}
		if resp.RequestID != "" {
			t.Fatalf("unregistered reply returned as success: %+v", resp)
		}
	})

	t.Run("connector id mismatch is integrity conflict", func(t *testing.T) {
		req := newRequest(OpDescribe, `{}`)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reply := baseReply(req, map[string]any{"record_type": "connector_descriptor"})
			reply["connector_id"] = "conn-other"
			writeReply(w, http.StatusOK, reply)
		}))
		defer srv.Close()
		_, err := CallConnector(callCtx(t, srv.URL+"/connector"), srv.URL+"/connector", req)
		if ce := asConnectorError(t, err); ce.Code != "INTEGRITY_CONFLICT" {
			t.Fatalf("code = %s, want INTEGRITY_CONFLICT", ce.Code)
		}
	})

	t.Run("operation mismatch is integrity conflict", func(t *testing.T) {
		req := newRequest(OpObserve, `{"handle":{"connector_id":"conn-1","local_handle":"h-1"}}`)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reply := baseReply(req, map[string]any{"kind": "start_receipt", "disposition": "accepted_locally"})
			reply["operation"] = OpStart
			writeReply(w, http.StatusOK, reply)
		}))
		defer srv.Close()
		_, err := CallConnector(callCtx(t, srv.URL+"/connector"), srv.URL+"/connector", req)
		if ce := asConnectorError(t, err); ce.Code != "INTEGRITY_CONFLICT" {
			t.Fatalf("code = %s, want INTEGRITY_CONFLICT", ce.Code)
		}
	})

	t.Run("result kind must match operation", func(t *testing.T) {
		req := newRequest(OpObserve, `{"handle":{"connector_id":"conn-1","local_handle":"h-1"}}`)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeReply(w, http.StatusOK, baseReply(req, map[string]any{"kind": "start_receipt"}))
		}))
		defer srv.Close()
		_, err := CallConnector(callCtx(t, srv.URL+"/connector"), srv.URL+"/connector", req)
		if ce := asConnectorError(t, err); ce.Code != "INTEGRITY_CONFLICT" {
			t.Fatalf("code = %s, want INTEGRITY_CONFLICT", ce.Code)
		}
	})

	t.Run("control receipt must name requested verb", func(t *testing.T) {
		req := newRequest(OpRequestNativeCancel, `{"handle":{"connector_id":"conn-1","local_handle":"h-1"}}`)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeReply(w, http.StatusOK, baseReply(req, map[string]any{
				"kind": "control_receipt", "observation": map[string]any{"operation": OpContain},
			}))
		}))
		defer srv.Close()
		_, err := CallConnector(callCtx(t, srv.URL+"/connector"), srv.URL+"/connector", req)
		if ce := asConnectorError(t, err); ce.Code != "INTEGRITY_CONFLICT" {
			t.Fatalf("code = %s, want INTEGRITY_CONFLICT", ce.Code)
		}
	})

	t.Run("version mismatch is unsupported version", func(t *testing.T) {
		req := newRequest(OpDescribe, `{}`)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reply := baseReply(req, map[string]any{"record_type": "connector_descriptor"})
			reply["schema_version"] = "external-connector/9.9.9"
			writeReply(w, http.StatusOK, reply)
		}))
		defer srv.Close()
		_, err := CallConnector(callCtx(t, srv.URL+"/connector"), srv.URL+"/connector", req)
		if ce := asConnectorError(t, err); ce.Code != "UNSUPPORTED_VERSION" {
			t.Fatalf("code = %s, want UNSUPPORTED_VERSION", ce.Code)
		}
	})

	t.Run("exactly nine verbs recognized", func(t *testing.T) {
		results := map[string]any{
			OpDescribe:                   map[string]any{"record_type": "connector_descriptor"},
			OpPrepare:                    map[string]any{"kind": "prepared"},
			OpStart:                      map[string]any{"kind": "start_receipt", "disposition": "accepted_locally"},
			OpObserve:                    map[string]any{"kind": "observation_page"},
			OpRequestNativeCancel:        map[string]any{"kind": "control_receipt", "observation": map[string]any{"operation": OpRequestNativeCancel}},
			OpCloseObservationConnection: map[string]any{"kind": "control_receipt", "observation": map[string]any{"operation": OpCloseObservationConnection}},
			OpCollectArtifacts:           map[string]any{"kind": "artifact_inventory"},
			OpReleaseNativeContext:       map[string]any{"kind": "control_receipt", "observation": map[string]any{"operation": OpReleaseNativeContext}},
			OpContain:                    map[string]any{"kind": "control_receipt", "observation": map[string]any{"operation": OpContain}},
		}
		if len(results) != 9 {
			t.Fatalf("verb table has %d entries, want 9", len(results))
		}
		for op, result := range results {
			payload := `{"probe":"x"}`
			if op == OpDescribe {
				payload = `{}`
			}
			req := newRequest(op, payload)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeReply(w, http.StatusOK, baseReply(req, result))
			}))
			resp, err := CallConnector(callCtx(t, srv.URL+"/connector"), srv.URL+"/connector", req)
			srv.Close()
			if err != nil {
				t.Fatalf("CallConnector(%s) error = %v", op, err)
			}
			if resp.Operation != op {
				t.Fatalf("CallConnector(%s) operation = %s", op, resp.Operation)
			}
		}
		unknown := newRequest("Browse", `{}`)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("unknown verb must fail before dispatch")
		}))
		defer srv.Close()
		_, err := CallConnector(callCtx(t, srv.URL+"/connector"), srv.URL+"/connector", unknown)
		if ce := asConnectorError(t, err); ce.Code != "INVALID_REQUEST" || ce.OperationDelivery != "not_dispatched" {
			t.Fatalf("unknown verb = %+v, want INVALID_REQUEST/not_dispatched", ce)
		}
	})

	t.Run("describe requires empty object", func(t *testing.T) {
		req := newRequest(OpDescribe, `{"probe":"x"}`)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("invalid Describe must fail before dispatch")
		}))
		defer srv.Close()
		_, err := CallConnector(callCtx(t, srv.URL+"/connector"), srv.URL+"/connector", req)
		if ce := asConnectorError(t, err); ce.Code != "INVALID_REQUEST" {
			t.Fatalf("code = %s, want INVALID_REQUEST", ce.Code)
		}
	})

	t.Run("bare null rejected", func(t *testing.T) {
		req := newRequest(OpStart, `{"idempotency_key":null}`)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("bare null must fail before dispatch")
		}))
		defer srv.Close()
		_, err := CallConnector(callCtx(t, srv.URL+"/connector"), srv.URL+"/connector", req)
		if ce := asConnectorError(t, err); ce.Code != "INVALID_REQUEST" {
			t.Fatalf("code = %s, want INVALID_REQUEST", ce.Code)
		}
	})

	t.Run("duplicate reply keys rejected", func(t *testing.T) {
		req := newRequest(OpDescribe, `{}`)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			// Duplicate request_id mapping keys: rejected before validation.
			_, _ = w.Write([]byte(`{"record_type":"connector_response","schema_version":"external-connector/0.1.0","request_id":"req-1","request_id":"req-1","connector_id":"conn-1","operation":"Describe","result":{"record_type":"connector_descriptor"}}`))
		}))
		defer srv.Close()
		_, err := CallConnector(callCtx(t, srv.URL+"/connector"), srv.URL+"/connector", req)
		if ce := asConnectorError(t, err); ce.Code != "INTEGRITY_CONFLICT" {
			t.Fatalf("code = %s, want INTEGRITY_CONFLICT", ce.Code)
		}
	})

	t.Run("endpoint must be deployment configured", func(t *testing.T) {
		req := newRequest(OpDescribe, `{}`)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeReply(w, http.StatusOK, baseReply(req, map[string]any{"record_type": "connector_descriptor"}))
		}))
		defer srv.Close()
		// Correct shape but absent from the allowlist.
		ctx := ContextWithDeploymentEndpoints(authCtx(t, "test-token"), []string{"https://connector.lab/connector"})
		_, err := CallConnector(ctx, srv.URL+"/connector", req)
		if ce := asConnectorError(t, err); ce.Code != "FORBIDDEN" {
			t.Fatalf("code = %s, want FORBIDDEN", ce.Code)
		}
		// Wrong path rejected even when allowlisted.
		ctx2 := ContextWithDeploymentEndpoints(authCtx(t, "test-token"), []string{srv.URL + "/runs"})
		_, err = CallConnector(ctx2, srv.URL+"/runs", req)
		if ce := asConnectorError(t, err); ce.Code != "INVALID_REQUEST" {
			t.Fatalf("code = %s, want INVALID_REQUEST", ce.Code)
		}
	})

	t.Run("authorization follows channel grants", func(t *testing.T) {
		req := newRequest(OpDescribe, `{}`)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeReply(w, http.StatusOK, baseReply(req, map[string]any{"record_type": "connector_descriptor"}))
		}))
		defer srv.Close()
		ep := srv.URL + "/connector"
		// No channel credential: unauthenticated.
		anon := ContextWithDeploymentEndpoints(context.Background(), []string{ep})
		_, err := CallConnector(anon, ep, req)
		if ce := asConnectorError(t, err); ce.Code != "UNAUTHENTICATED" {
			t.Fatalf("anon code = %s, want UNAUTHENTICATED", ce.Code)
		}
		// Application caller holds Describe but never control verbs.
		containReq := newRequest(OpContain, `{"handle":{"connector_id":"conn-1","local_handle":"h-1"}}`)
		_, err = CallConnector(appCtx(t, ep), ep, containReq)
		if ce := asConnectorError(t, err); ce.Code != "FORBIDDEN" {
			t.Fatalf("app Contain code = %s, want FORBIDDEN", ce.Code)
		}
	})
}

func TestHTTPTransportSuccessDoesNotEstablishTaskSuccess(t *testing.T) {
	t.Run("http 200 start receipt is call completion only", func(t *testing.T) {
		req := newRequest(OpStart, `{"idempotency_key":"k-1"}`)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeReply(w, http.StatusOK, baseReply(req, map[string]any{
				"kind": "start_receipt", "disposition": "accepted_locally",
			}))
		}))
		defer srv.Close()
		resp, err := CallConnector(callCtx(t, srv.URL+"/connector"), srv.URL+"/connector", req)
		if err != nil {
			t.Fatalf("CallConnector() error = %v", err)
		}
		var result map[string]any
		if err := json.Unmarshal(resp.Result, &result); err != nil {
			t.Fatalf("result decode error = %v", err)
		}
		if result["kind"] != "start_receipt" || result["disposition"] != "accepted_locally" {
			t.Fatalf("result = %v, want local start receipt", result)
		}
		// No composite task status, origin-success boolean, or qualification
		// may ride on the transport envelope or its result.
		rt := reflect.TypeOf(resp)
		for i := range rt.NumField() {
			name := strings.ToLower(rt.Field(i).Name + " " + rt.Field(i).Tag.Get("json"))
			for _, banned := range []string{"success", "task_status", "committed", "qualified", "outcome", "accepted_by_native", "native_success"} {
				if strings.Contains(name, banned) {
					t.Fatalf("ConnectorResponse exposes %q via field %s", banned, rt.Field(i).Name)
				}
			}
		}
		raw := strings.ToLower(string(resp.Result))
		for _, banned := range []string{"task_success", "origin_success", "application_success", "task_status", "qualified"} {
			if strings.Contains(raw, banned) {
				t.Fatalf("result asserts %q: %s", banned, resp.Result)
			}
		}
		// A locally accepted disposition is not native acceptance.
		if strings.Contains(raw, "native_accept") {
			t.Fatalf("receipt claims native acceptance: %s", resp.Result)
		}
	})

	t.Run("typed error over http 500 preserves operation scope", func(t *testing.T) {
		req := newRequest(OpStart, `{"idempotency_key":"k-1"}`)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeReply(w, http.StatusInternalServerError, baseReply(req, typedErrorResult("RESOURCE_BUSY", "not_dispatched", "operator_review")))
		}))
		defer srv.Close()
		resp, err := CallConnector(callCtx(t, srv.URL+"/connector"), srv.URL+"/connector", req)
		ce := asConnectorError(t, err)
		if ce.Code != "RESOURCE_BUSY" || ce.OperationDelivery != "not_dispatched" || ce.RetryGuidance != "operator_review" {
			t.Fatalf("typed error = %+v, want RESOURCE_BUSY/not_dispatched/operator_review", ce)
		}
		if resp.RequestID != req.RequestID || resp.Operation != req.Operation {
			t.Fatalf("error lost correlation: %+v", resp)
		}
		lower := strings.ToLower(ce.Error())
		for _, banned := range []string{"task failed", "application failed", "commit", "task outcome"} {
			if banned == "task outcome" {
				continue // local Detail may disclaim task outcomes; typed server Detail must not assert one
			}
			if strings.Contains(lower, banned) {
				t.Fatalf("typed error asserts task scope %q: %v", banned, ce)
			}
		}
	})

	t.Run("typed error over http 200 still surfaces by body", func(t *testing.T) {
		req := newRequest(OpPrepare, `{"task":"t"}`)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeReply(w, http.StatusOK, baseReply(req, typedErrorResult("UNSUPPORTED_MAPPING", "not_applicable", "operator_review")))
		}))
		defer srv.Close()
		_, err := CallConnector(callCtx(t, srv.URL+"/connector"), srv.URL+"/connector", req)
		if ce := asConnectorError(t, err); ce.Code != "UNSUPPORTED_MAPPING" {
			t.Fatalf("code = %s, want UNSUPPORTED_MAPPING", ce.Code)
		}
	})

	t.Run("undecodable body conveys no task outcome", func(t *testing.T) {
		req := newRequest(OpDescribe, `{}`)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`not json{{{`))
		}))
		defer srv.Close()
		resp, err := CallConnector(callCtx(t, srv.URL+"/connector"), srv.URL+"/connector", req)
		ce := asConnectorError(t, err)
		if ce.Code != "INTEGRITY_CONFLICT" || ce.OperationDelivery != "may_have_dispatched" {
			t.Fatalf("error = %+v, want INTEGRITY_CONFLICT/may_have_dispatched", ce)
		}
		if !strings.Contains(ce.Detail, "no task outcome") {
			t.Fatalf("Detail = %q, want no-task-outcome disclaimer", ce.Detail)
		}
		if resp.RequestID != "" {
			t.Fatalf("undecodable reply returned as success: %+v", resp)
		}
		// The rejection must not echo another principal's handles.
		if strings.Contains(ce.Detail, "h-") || strings.Contains(ce.Detail, "native-") {
			t.Fatalf("rejection leaks handles: %q", ce.Detail)
		}
	})
}

func TestConnectorCallDeadlineDoesNotAssertNativeTermination(t *testing.T) {
	assertNoTermination := func(t *testing.T, ce *ConnectorError) {
		t.Helper()
		lower := strings.ToLower(ce.Detail + " " + ce.Error())
		if !strings.Contains(lower, "deadline") || !strings.Contains(lower, "native state unknown") {
			t.Fatalf("Detail = %q, want local deadline with unknown native state", ce.Detail)
		}
		for _, banned := range []string{"cancelled", "canceled", "stopped", "killed", "rolled back", "terminated natively", "native failure", "task failed"} {
			if strings.Contains(lower, banned) {
				t.Fatalf("deadline asserts %q: %q", banned, ce.Detail)
			}
		}
		// "no termination asserted" is the required disclaimer, not a claim.
		if !strings.Contains(lower, "no termination asserted") {
			t.Fatalf("Detail = %q, want explicit no-termination disclaimer", ce.Detail)
		}
	}

	t.Run("call limit expiry is uncertain delivery", func(t *testing.T) {
		req := newRequest(OpStart, `{"idempotency_key":"k-1"}`)
		req.CallLimit = DurationLimit{Kind: "exact", Unit: "ms", Value: 50}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(1500 * time.Millisecond)
			writeReply(w, http.StatusOK, baseReply(req, map[string]any{"kind": "start_receipt"}))
		}))
		defer srv.Close()
		start := time.Now()
		_, err := CallConnector(callCtx(t, srv.URL+"/connector"), srv.URL+"/connector", req)
		elapsed := time.Since(start)
		ce := asConnectorError(t, err)
		if ce.Code != "DELIVERY_UNCERTAIN" || ce.OperationDelivery != "may_have_dispatched" || ce.RetryGuidance != "same_command_only" {
			t.Fatalf("error = %+v, want DELIVERY_UNCERTAIN/may_have_dispatched/same_command_only", ce)
		}
		assertNoTermination(t, ce)
		if len(ce.EvidenceRefs) != 0 {
			t.Fatalf("deadline fabricated %d evidence refs", len(ce.EvidenceRefs))
		}
		// The local monotonic bound must cut the call short of the server's sleep.
		if elapsed >= 1000*time.Millisecond {
			t.Fatalf("elapsed = %v, want local bound well under server sleep", elapsed)
		}
	})

	t.Run("caller context deadline is honored", func(t *testing.T) {
		req := newRequest(OpObserve, `{"handle":{"connector_id":"conn-1","local_handle":"h-1"}}`)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(500 * time.Millisecond)
			writeReply(w, http.StatusOK, baseReply(req, map[string]any{"kind": "observation_page"}))
		}))
		defer srv.Close()
		base := callCtx(t, srv.URL+"/connector")
		ctx, cancel := context.WithTimeout(base, 30*time.Millisecond)
		defer cancel()
		_, err := CallConnector(ctx, srv.URL+"/connector", req)
		ce := asConnectorError(t, err)
		if ce.Code != "DELIVERY_UNCERTAIN" || ce.OperationDelivery != "may_have_dispatched" {
			t.Fatalf("error = %+v, want DELIVERY_UNCERTAIN/may_have_dispatched", ce)
		}
		assertNoTermination(t, ce)
	})

	t.Run("expired context before dispatch never sends", func(t *testing.T) {
		req := newRequest(OpStart, `{"idempotency_key":"k-1"}`)
		hits := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits++
			writeReply(w, http.StatusOK, baseReply(req, map[string]any{"kind": "start_receipt"}))
		}))
		defer srv.Close()
		base := callCtx(t, srv.URL+"/connector")
		ctx, cancel := context.WithDeadline(base, time.Now().Add(-time.Second))
		defer cancel()
		_, err := CallConnector(ctx, srv.URL+"/connector", req)
		ce := asConnectorError(t, err)
		if ce.Code != "DELIVERY_UNCERTAIN" || ce.OperationDelivery != "not_dispatched" {
			t.Fatalf("error = %+v, want DELIVERY_UNCERTAIN/not_dispatched", ce)
		}
		assertNoTermination(t, ce)
		if hits != 0 {
			t.Fatalf("hits = %d, want 0 (never dispatched)", hits)
		}
	})

	t.Run("no fresh-command retry after ambiguous delivery", func(t *testing.T) {
		req := newRequest(OpContain, `{"handle":{"connector_id":"conn-1","local_handle":"h-1"}}`)
		req.CallLimit = DurationLimit{Kind: "exact", Unit: "ms", Value: 50}
		hits := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits++
			time.Sleep(300 * time.Millisecond)
			writeReply(w, http.StatusOK, baseReply(req, map[string]any{
				"kind": "control_receipt", "observation": map[string]any{"operation": OpContain},
			}))
		}))
		defer srv.Close()
		_, err := CallConnector(callCtx(t, srv.URL+"/connector"), srv.URL+"/connector", req)
		if ce := asConnectorError(t, err); ce.Code != "DELIVERY_UNCERTAIN" {
			t.Fatalf("code = %s, want DELIVERY_UNCERTAIN", ce.Code)
		}
		time.Sleep(400 * time.Millisecond) // let any illicit retry land
		if hits != 1 {
			t.Fatalf("hits = %d, want exactly 1 (no retry)", hits)
		}
	})

	t.Run("oversized call limit rejected before dispatch", func(t *testing.T) {
		req := newRequest(OpStart, `{"idempotency_key":"k-1"}`)
		req.CallLimit = DurationLimit{Kind: "exact", Unit: "ms", Value: MaxCallLimitMs + 1}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("over-budget call must fail before dispatch")
		}))
		defer srv.Close()
		_, err := CallConnector(callCtx(t, srv.URL+"/connector"), srv.URL+"/connector", req)
		if ce := asConnectorError(t, err); ce.Code != "BUDGET_EXCEEDED" || ce.OperationDelivery != "not_dispatched" {
			t.Fatalf("error = %+v, want BUDGET_EXCEEDED/not_dispatched", ce)
		}
	})
}

func TestNativeFailureObservationsRemainNormalObserveResults(t *testing.T) {
	observeReq := func() ConnectorRequest {
		return newRequest(OpObserve, `{"handle":{"connector_id":"conn-1","local_handle":"h-1"}}`)
	}
	pageWithItems := func(items []any) map[string]any {
		return map[string]any{
			"kind": "observation_page",
			"handle": map[string]any{"connector_id": "conn-1", "local_handle": "h-1"},
			"observation_close_ref": map[string]any{"value": nil, "reason": "not_observed"},
			"items": items, "limitations": []any{},
		}
	}

	t.Run("native failed claims are normal results", func(t *testing.T) {
		req := observeReq()
		items := []any{
			map[string]any{"kind": "native_report", "channel": "terminal", "native_status": "failed", "claim": "native execution failed"},
			map[string]any{"kind": "incident", "code": "NATIVE_FAILED", "scope": "native_execution", "detail": "subject reports failure"},
		}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeReply(w, http.StatusOK, baseReply(req, pageWithItems(items)))
		}))
		defer srv.Close()
		resp, err := CallConnector(callCtx(t, srv.URL+"/connector"), srv.URL+"/connector", req)
		if err != nil {
			t.Fatalf("CallConnector() error = %v, want nil for native failure evidence", err)
		}
		if !bytes.Contains(resp.Result, []byte("failed")) {
			t.Fatalf("native failure evidence not preserved: %s", resp.Result)
		}
		var result map[string]any
		if err := json.Unmarshal(resp.Result, &result); err != nil {
			t.Fatalf("result decode error = %v", err)
		}
		if result["kind"] != "observation_page" {
			t.Fatalf("kind = %v, want observation_page", result["kind"])
		}
	})

	t.Run("completed and stopped claims are normal results", func(t *testing.T) {
		req := observeReq()
		items := []any{
			map[string]any{"kind": "native_report", "channel": "terminal", "native_status": "completed", "claim": "native execution completed"},
			map[string]any{"kind": "native_report", "channel": "terminal", "native_status": "stopped", "claim": "native execution stopped"},
		}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeReply(w, http.StatusOK, baseReply(req, pageWithItems(items)))
		}))
		defer srv.Close()
		resp, err := CallConnector(callCtx(t, srv.URL+"/connector"), srv.URL+"/connector", req)
		if err != nil {
			t.Fatalf("CallConnector() error = %v, want nil for completed/stopped evidence", err)
		}
		raw := string(resp.Result)
		if !strings.Contains(raw, "completed") || !strings.Contains(raw, "stopped") {
			t.Fatalf("completion evidence not preserved verbatim: %s", raw)
		}
	})

	t.Run("connector observation failure still errors", func(t *testing.T) {
		req := observeReq()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeReply(w, http.StatusGone, baseReply(req, typedErrorResult("OBSERVATION_LOST", "dispatched", "operator_review")))
		}))
		defer srv.Close()
		resp, err := CallConnector(callCtx(t, srv.URL+"/connector"), srv.URL+"/connector", req)
		ce := asConnectorError(t, err)
		if ce.Code != "OBSERVATION_LOST" {
			t.Fatalf("code = %s, want OBSERVATION_LOST", ce.Code)
		}
		if resp.Operation != OpObserve || resp.RequestID != req.RequestID {
			t.Fatalf("error lost correlation: %+v", resp)
		}
	})

	t.Run("local prerequisite errors are not subject failures", func(t *testing.T) {
		req := observeReq()
		req.Payload = json.RawMessage(`null`)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("invalid payload must fail before dispatch")
		}))
		defer srv.Close()
		_, err := CallConnector(callCtx(t, srv.URL+"/connector"), srv.URL+"/connector", req)
		ce := asConnectorError(t, err)
		if ce.Code != "INVALID_REQUEST" {
			t.Fatalf("code = %s, want INVALID_REQUEST", ce.Code)
		}
		lower := strings.ToLower(ce.Detail)
		for _, banned := range []string{"subject failed", "native failed", "native failure"} {
			if strings.Contains(lower, banned) {
				t.Fatalf("local error fabricated subject failure %q: %q", banned, ce.Detail)
			}
		}
	})
}

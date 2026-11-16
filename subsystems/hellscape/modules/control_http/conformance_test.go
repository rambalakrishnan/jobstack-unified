package control_http

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"admission"
	"application_owner"
	"authority"
	"connector_transport"
	"evidence_bundle"
	"evidence_codec"
	"observation_owner"
	"owner_store"
)

// ---------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------

func testPolicy() []byte {
	return []byte(`{"channels":{
		"opA-token":{"principal":"operator-a","kind":"control","grants":[{"domain":"*","operations":["*"]}]},
		"opB-token":{"principal":"operator-b","kind":"control","grants":[{"domain":"*","operations":["*"]}]},
		"app-token":{"principal":"fixture-app","kind":"application","grants":[{"domain":"*","operations":["*"]}]},
		"test-channel":{"principal":"test-writer","kind":"owner","grants":[{"domain":"*","operations":["*"]}]}}}`)
}

func authedContext(t *testing.T, token string) context.Context {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "http://control.test/direct", nil)
	if err != nil {
		t.Fatalf("build auth request: %v", err)
	}
	req.Header.Set("Authorization", "Channel "+token)
	ctx, err := authority.Authenticate(req, testPolicy())
	if err != nil {
		t.Fatalf("authenticate %s: %v", token, err)
	}
	return ctx
}

func openStores(t *testing.T) (*OwnerStore, *OwnerStore, *OwnerStore) {
	t.Helper()
	home := t.TempDir()
	primary, err := owner_store.OpenOwner(filepath.Join(home, "primary.db"), filepath.Join(home, "primary-art"), "diagnostic")
	if err != nil {
		t.Fatalf("OpenOwner primary: %v", err)
	}
	t.Cleanup(func() { _ = primary.Close() })
	application, err := owner_store.OpenOwner(filepath.Join(home, "app.db"), filepath.Join(home, "app-art"), "application")
	if err != nil {
		t.Fatalf("OpenOwner application: %v", err)
	}
	t.Cleanup(func() { _ = application.Close() })
	observation, err := owner_store.OpenOwner(filepath.Join(home, "obs.db"), filepath.Join(home, "obs-art"), "observation")
	if err != nil {
		t.Fatalf("OpenOwner observation: %v", err)
	}
	t.Cleanup(func() { _ = observation.Close() })
	return primary, application, observation
}

func newTestHandler(primary, application, observation *OwnerStore) *ControlHandler {
	h := NewControlHandler(primary, application, observation, testPolicy()).(*ControlHandler)
	return h
}

func testDigest(seed string) string {
	return string(evidence_codec.HashBytes([]byte(seed)))
}

func testArtifact(seed, ownerDomain, access string) admission.ArtifactReference {
	return admission.ArtifactReference{
		Digest:      testDigest(seed),
		SizeBytes:   int64(len(seed) + 1),
		MediaType:   "application/json",
		OwnerDomain: ownerDomain,
		Access:      access,
	}
}

func testEvidenceRef(journalID, suffix string, seq int64) admission.EvidenceRef {
	return admission.EvidenceRef{
		JournalID: journalID, Sequence: seq,
		EventID: "evt-" + suffix, EventHash: testDigest("evt-" + suffix), Pointer: "",
	}
}

func testTimePoint(journalID string) admission.TimePoint {
	return admission.TimePoint{
		ClockID: "clock-" + journalID, BootID: "boot-" + journalID,
		Origin: "engine_measured", MonotonicOffsetMs: 0,
		UTCAnnotation: admission.NewMissing("not_applicable"),
	}
}

func testVersionPin(id string) admission.VersionPin {
	return admission.VersionPin{ID: id, Version: "1.0", ArtifactDigest: testDigest(id)}
}

func testManifest(suffix, subjectVersion string) admission.Manifest {
	m := admission.Manifest{
		RecordType: "manifest", SchemaVersion: "1.0.0",
		ManifestID: "manifest-" + suffix, RunID: "attempt-" + suffix, JournalID: "journal-" + suffix,
		OwnerDomain: "diagnostic", CommissionerID: "operator-a",
		Activity: "application_attempt",
		Execution: map[string]any{"mode": "manual"},
		Task:      map[string]any{"task_id": "task-" + suffix},
		TaskSemanticHash: testDigest("task-sem-" + suffix),
		Environment:      map[string]any{"deployment": "laboratory"},
		Seed:             "seed-" + suffix,
		BuildPins:        map[string]string{"fixture": "1.0.0"},
		EventRegistry:    map[string]string{"kind1": "v1"},
		Producers:        []map[string]any{{"producer_id": "p1"}},
		Clocks:           []map[string]any{{"clock_id": "c1"}},
		Profile:          "M1",
	}
	m.Attempt.Kind = "practice"
	m.Attempt.Context = "laboratory_fixture"
	m.Attempt.Scope = "held_in"
	m.Attempt.SubjectVersion = subjectVersion
	m.Attempt.Assistance = "none"
	if subjectVersion != "" {
		m.Subject.Name = "subject-A"
		m.Subject.Version = subjectVersion
		m.Execution = map[string]any{"mode": "subject"}
	}
	m.Lineage.Kind = "practice"
	return m
}

func testOwners(targetID, mode string) admission.OwnerBindings {
	pub := func(id string) admission.VersionPin { return testVersionPin(id) }
	execSource, execWriter := admission.NewMissing("not_applicable"), admission.NewMissing("not_applicable")
	var es, ew any = execSource, execWriter
	if mode == "subject" {
		es = "exec-source"
		ew = "exec-writer"
	}
	return admission.OwnerBindings{
		Dispatch:    admission.AuthorityBinding{Role: "connector", SourceID: "dispatch-source", WriterID: "dispatch-writer", OwnerDomain: "dispatch", PublicationPolicy: pub("pub-dispatch")},
		Observation: admission.AuthorityBinding{Role: "connector", SourceID: "obs-source", WriterID: "obs-writer", OwnerDomain: "observation", PublicationPolicy: pub("pub-observation")},
		Execution:   admission.AuthorityBinding{Role: "subject", SourceID: es, WriterID: ew, OwnerDomain: "execution", PublicationPolicy: pub("pub-execution")},
		Application: admission.AuthorityBinding{Role: "origin", SourceID: targetID, WriterID: "app-writer", OwnerDomain: "application", PublicationPolicy: pub("pub-application")},
		Report:      admission.AuthorityBinding{Role: "reconciler", SourceID: "report-source", WriterID: "report-writer", OwnerDomain: "report", PublicationPolicy: pub("pub-report")},
	}
}

func testCommission(t *testing.T, suffix string, manifest admission.Manifest, mode string) admission.AttemptCommission {
	t.Helper()
	targetID := "target-" + suffix
	digest, err := admission.PrimaryManifestDigest(manifest)
	if err != nil {
		t.Fatalf("PrimaryManifestDigest: %v", err)
	}
	ex := admission.ExecutionDescriptor{Mode: mode}
	if mode == "manual" {
		ex.Subject = admission.NewMissing("not_applicable")
		ex.ConnectorVersion = admission.NewMissing("not_applicable")
		ex.BindingVersion = admission.NewMissing("not_applicable")
	} else {
		ex.Subject = admission.SubjectIdentity{
			SubjectID: "subject-A", SubjectVersion: "subject-1.0", RevisionBasis: "basis-1",
			NativeRevision: admission.NewMissing("not_observed"), ConfiguredMode: "subject",
			InterfaceSurface: "test-surface", ConfigurationDigest: testDigest("config-" + suffix),
			Stack: []admission.ComponentIdentity{{Component: "comp", ReportedVersion: "1.0", BuildDigest: "build-1", ConfigurationDigest: "cfg-1"}},
		}
		ex.ConnectorVersion = "connector-1.0"
		ex.BindingVersion = "binding-1.0"
	}
	ex.Assistance = admission.AssistanceRecord{
		PlanningOwner: "operator", AssistanceTrack: "manual",
		PlannerIdentity: admission.NewMissing("not_applicable"), Plan: admission.NewMissing("not_applicable"),
		OnlineReplanning: false, Description: "test execution",
	}
	return admission.AttemptCommission{
		RecordType: "attempt_commission", SchemaVersion: "application-attempt-lifecycle/0.1.0", KernelVersion: "evidence-kernel/0.1.0",
		CommissionID: "commission-" + suffix, RunID: manifest.RunID, JournalID: manifest.JournalID,
		ManifestHash: digest, AdmissionRef: testEvidenceRef(manifest.JournalID, suffix+"-admission", 2),
		CommissionedBy: "operator-a", CommissionedAt: testTimePoint(manifest.JournalID),
		Attempt: admission.AttemptContext{
			AttemptID: "attempt-" + suffix, Kind: "practice",
			TargetClass: "laboratory_fixture", TargetID: targetID, EvaluationPartition: "held_in",
			RehearsalOf: []admission.AttemptReference{}, PerformanceOf: []admission.AttemptReference{}, DerivedFrom: []admission.AttemptReference{},
		},
		CandidateID: "candidate-" + suffix, CandidateProfile: admission.NewMissing("not_observed"),
		Job: admission.JobReference{JobID: "job-" + suffix, SourceTarget: admission.NewMissing("not_observed"), SourceJobID: admission.NewMissing("not_observed"), Snapshot: testArtifact("job-snap-"+suffix, "diagnostic", "restricted")},
		SelectionEvidence: admission.NewMissing("not_observed"),
		Task:              testArtifact("task-"+suffix, "diagnostic", "restricted"),
		TaskSemanticHash:  testDigest("task-sem-comm-" + suffix),
		InitialMaterials:  []admission.ArtifactReference{},
		Execution:         ex, Owners: testOwners(targetID, mode),
		IdempotencyKey:     "idem-" + suffix,
		AuthorizationRefs:  []admission.EvidenceRef{testEvidenceRef(manifest.JournalID, suffix+"-auth", 1)},
		RecoveryReviewRefs: []admission.EvidenceRef{},
		ObservationPolicy: admission.ObservationPolicy{
			ActiveLimit: admission.DurationLimit{Kind: "exact", Unit: "ms", Value: 60000},
			DrainLimit:  admission.DurationLimit{Kind: "exact", Unit: "ms", Value: 10000},
			NativeCancelWaitLimit: admission.DurationLimit{Kind: "exact", Unit: "ms", Value: 5000},
			CleanupWaitLimit:      admission.DurationLimit{Kind: "exact", Unit: "ms", Value: 5000},
			FixtureCloseAction:    "seal_after_drain",
		},
		OriginPolicy: testVersionPin("origin-" + suffix),
	}
}

func testRegistration(suffix string, manifest admission.Manifest, targetID string) admission.EntityRegistration {
	dummyPolicy := func(seed string) map[string]any {
		return map[string]any{"id": "pub", "version": "1.0", "artifact_digest": testDigest(seed)}
	}
	return admission.EntityRegistration{
		RecordType: "write_domain_entity", SchemaVersion: "0.1.0",
		RegistrationID: "registration-" + suffix,
		Entity: map[string]any{"entity_type": "hellscape_session", "entity_id": "session-" + suffix, "session_id": manifest.RunID},
		Identity: map[string]any{
			"run_id": manifest.RunID, "journal_id": manifest.JournalID,
			"attempt": map[string]any{"kind": "practice", "target_class": "laboratory_fixture", "evaluation_partition": "held_in"},
		},
		Owners: map[string]any{
			"application": map[string]any{"role": "origin", "source_id": targetID, "writer_id": "app-writer-" + suffix, "owner_domain": "application", "publication_policy": dummyPolicy("pub-app-" + suffix)},
			"observation": map[string]any{"role": "observer", "source_id": "obs-source-" + suffix, "writer_id": "obs-writer-" + suffix, "owner_domain": "observation", "publication_policy": dummyPolicy("pub-obs-" + suffix)},
			"diagnostic":  map[string]any{"role": "analyzer", "source_id": "diag-source-" + suffix, "writer_id": "diag-writer-" + suffix, "owner_domain": "diagnostic", "publication_policy": dummyPolicy("pub-diag-" + suffix)},
		},
		EvidencePrefix: admission.JournalPrefix{},
		EvidenceRefs:   []admission.EvidenceRef{},
		Configuration:  append([]byte(nil), application_owner.DefaultFixtureConfiguration()...),
	}
}

func doControl(t *testing.T, h http.Handler, method, path string, body any, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		switch v := body.(type) {
		case string:
			rdr = strings.NewReader(v)
		case []byte:
			rdr = bytes.NewReader(v)
		default:
			raw, err := json.Marshal(v)
			if err != nil {
				t.Fatalf("marshal body: %v", err)
			}
			rdr = bytes.NewReader(raw)
		}
	}
	req := httptest.NewRequest(method, path, rdr)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if body != nil && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %d body %q: %v", rec.Code, rec.Body.String(), err)
	}
	return out
}

func admitSession(t *testing.T, h *ControlHandler, suffix, mode, token, requestID string) (sessionID, journalID string, admissionRef map[string]any) {
	t.Helper()
	manifest := testManifest(suffix, "")
	if mode == "subject" {
		manifest = testManifest(suffix, "subject-1.0")
	}
	commission := testCommission(t, suffix, manifest, mode)
	regs := []admission.EntityRegistration{testRegistration(suffix, manifest, "target-"+suffix)}
	payload := map[string]any{"manifest": manifest, "commission": commission, "registrations": regs}
	rec := doControl(t, h, http.MethodPost, "/control/sessions", payload, map[string]string{
		"Authorization": "Channel " + token, "Idempotency-Key": requestID,
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("admit %s: status %d body %s", suffix, rec.Code, rec.Body.String())
	}
	out := decodeBody(t, rec)
	sessionID, _ = out["session_id"].(string)
	journalID, _ = out["journal_id"].(string)
	admissionRef, _ = out["admission_ref"].(map[string]any)
	if sessionID == "" || journalID == "" {
		t.Fatalf("admit %s missing ids: %s", suffix, rec.Body.String())
	}
	return sessionID, journalID, admissionRef
}

// Connector stub counting per-operation calls and returning valid receipts.
type connectorStub struct {
	mu         sync.Mutex
	calls      []connector_transport.ConnectorRequest
	perOp      map[string]int
	failOp     string
	failCode   string
	server     *httptest.Server
	t          *testing.T
}

func newConnectorStub(t *testing.T) *connectorStub {
	t.Helper()
	st := &connectorStub{perOp: map[string]int{}, t: t}
	st.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/connector" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"want POST /connector"}`))
			return
		}
		raw, _ := io.ReadAll(r.Body)
		var req connector_transport.ConnectorRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"bad json"}`))
			return
		}
		st.mu.Lock()
		st.calls = append(st.calls, req)
		st.perOp[req.Operation]++
		failOp, failCode := st.failOp, st.failCode
		st.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if failOp != "" && req.Operation == failOp {
			code := failCode
			if code == "" {
				code = "NATIVE_PROTOCOL_ERROR"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"record_type": "connector_response", "schema_version": connector_transport.SchemaVersion,
				"request_id": req.RequestID, "connector_id": req.ConnectorID, "operation": req.Operation,
				"result": map[string]any{
					"kind": "connector_error", "code": code, "fault_domain": "connector",
					"detail": "synthetic " + code, "operation_delivery": "not_dispatched",
					"retry_guidance": "operator_review",
					"retry_after": map[string]any{"value": nil, "reason": "not_applicable"},
					"handle":      map[string]any{"value": nil, "reason": "not_applicable"},
					"evidence_refs": []any{},
				},
			})
			return
		}
		var result map[string]any
		switch req.Operation {
		case connector_transport.OpStart:
			result = map[string]any{
				"kind": "start_receipt", "disposition": "locally_accepted",
				"handle": map[string]any{"connector_id": req.ConnectorID, "local_handle": "h-1"},
			}
		case connector_transport.OpRequestNativeCancel, connector_transport.OpCloseObservationConnection, connector_transport.OpReleaseNativeContext, connector_transport.OpContain:
			result = map[string]any{
				"kind": "control_receipt", "disposition": "acknowledged",
				"observation": map[string]any{"operation": req.Operation, "disposition": "acknowledged"},
			}
		case connector_transport.OpDescribe:
			result = map[string]any{"record_type": "connector_descriptor", "connector_id": req.ConnectorID}
		case connector_transport.OpObserve:
			result = map[string]any{"kind": "observation_page", "has_more": false, "items": []any{}}
		default:
			result = map[string]any{"kind": "control_receipt", "disposition": "acknowledged", "observation": map[string]any{"operation": req.Operation}}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"record_type": "connector_response", "schema_version": connector_transport.SchemaVersion,
			"request_id": req.RequestID, "connector_id": req.ConnectorID, "operation": req.Operation,
			"result": result,
		})
	}))
	t.Cleanup(st.server.Close)
	return st
}

func (st *connectorStub) count(op string) int {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.perOp[op]
}

func (st *connectorStub) total() int {
	st.mu.Lock()
	defer st.mu.Unlock()
	return len(st.calls)
}

func (st *connectorStub) setFail(op, code string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.failOp, st.failCode = op, code
}

func cancelBody(connectorID, requestID, reason string) map[string]any {
	return map[string]any{
		"record_type": "connector_request", "schema_version": connector_transport.SchemaVersion,
		"request_id": requestID, "connector_id": connectorID, "operation": connector_transport.OpRequestNativeCancel,
		"call_limit": map[string]any{"kind": "exact", "unit": "ms", "value": 5000},
		"payload":   map[string]any{"handle": "h-1", "reason": reason},
	}
}

func initObservationForSession(t *testing.T, obs *OwnerStore, sessionID, obsJournal string) {
	t.Helper()
	manifest := observation_owner.Manifest{
		RecordType: "manifest", SchemaVersion: "0.1.0",
		ManifestID: "manifest-" + obsJournal, RunID: sessionID, JournalID: obsJournal, OwnerDomain: "observation",
		Clocks: []observation_owner.ClockDescriptor{{
			ClockID: "clock-" + obsJournal, BootID: "boot-" + obsJournal,
			Origin: "engine_measured", SourceID: "observation-owner", Basis: "monotonic_offset", Unit: "ms",
		}},
	}
	reg := observation_owner.EntityRegistration{
		RecordType: "write_domain_entity", SchemaVersion: "0.1.0",
		RegistrationID: "registration-" + obsJournal,
		Entity:         map[string]any{"entity_type": "hellscape_session", "entity_id": "session-" + sessionID},
		Identity:       map[string]any{"run_id": sessionID, "journal_id": obsJournal},
		Owners:         map[string]any{"observation": map[string]any{"role": "connector"}},
		EvidenceRefs:   []observation_owner.EvidenceRef{},
	}
	if _, err := observation_owner.InitializeObservation(authedContext(t, "opA-token"), obs, manifest, reg); err != nil {
		t.Fatalf("InitializeObservation: %v", err)
	}
}

// ---------------------------------------------------------------------------
// 1. Scoped idempotent command identity.
// ---------------------------------------------------------------------------

func TestControlMutationsUseScopedIdempotentCommandIdentity(t *testing.T) {
	primary, application, observation := openStores(t)
	h := newTestHandler(primary, application, observation)
	stub := newConnectorStub(t)
	h.ConnectorEndpoint = stub.server.URL + "/connector"

	// Same command + identical request returns the retained receipt without
	// another effect.
	first := cancelBody("conn-1", "k1", "stop-1")
	rec1 := doControl(t, h, http.MethodPost, "/control/connector/cancel", first, map[string]string{
		"Authorization": "Channel opA-token", "Idempotency-Key": "k1",
	})
	if rec1.Code != http.StatusOK {
		t.Fatalf("cancel first: %d %s", rec1.Code, rec1.Body.String())
	}
	if stub.total() != 1 {
		t.Fatalf("stub calls = %d, want 1", stub.total())
	}
	out1 := decodeBody(t, rec1)
	receipt1, _ := out1["receipt_id"].(string)
	if receipt1 == "" {
		t.Fatalf("missing receipt_id: %s", rec1.Body.String())
	}
	rec2 := doControl(t, h, http.MethodPost, "/control/connector/cancel", first, map[string]string{
		"Authorization": "Channel opA-token", "Idempotency-Key": "k1",
	})
	if rec2.Code != http.StatusOK {
		t.Fatalf("cancel replay: %d %s", rec2.Code, rec2.Body.String())
	}
	if rec2.Header().Get("X-Idempotent-Replayed") != "true" {
		t.Fatalf("replay missing X-Idempotent-Replayed")
	}
	out2 := decodeBody(t, rec2)
	if out2["receipt_id"] != receipt1 {
		t.Fatalf("replay receipt %v != %v", out2["receipt_id"], receipt1)
	}
	if stub.total() != 1 {
		t.Fatalf("replay caused second effect: calls=%d", stub.total())
	}

	// Conflicting content under the same key is rejected.
	conflict := cancelBody("conn-1", "k1", "different-reason")
	rec3 := doControl(t, h, http.MethodPost, "/control/connector/cancel", conflict, map[string]string{
		"Authorization": "Channel opA-token", "Idempotency-Key": "k1",
	})
	if rec3.Code != http.StatusConflict {
		t.Fatalf("conflict: %d %s, want 409", rec3.Code, rec3.Body.String())
	}
	if stub.total() != 1 {
		t.Fatalf("conflict caused effect: calls=%d", stub.total())
	}

	// Same key+body under a different principal is a distinct command.
	rec4 := doControl(t, h, http.MethodPost, "/control/connector/cancel", first, map[string]string{
		"Authorization": "Channel opB-token", "Idempotency-Key": "k1",
	})
	if rec4.Code != http.StatusOK {
		t.Fatalf("other principal: %d %s", rec4.Code, rec4.Body.String())
	}
	out4 := decodeBody(t, rec4)
	if out4["receipt_id"] == receipt1 {
		t.Fatalf("distinct principal reused receipt")
	}
	if stub.total() != 2 {
		t.Fatalf("distinct principal calls=%d, want 2", stub.total())
	}

	// Same key+body under a different connector scope is distinct.
	otherScope := cancelBody("conn-2", "k1", "stop-1")
	rec5 := doControl(t, h, http.MethodPost, "/control/connector/cancel", otherScope, map[string]string{
		"Authorization": "Channel opA-token", "Idempotency-Key": "k1",
	})
	if rec5.Code != http.StatusOK {
		t.Fatalf("other scope: %d %s", rec5.Code, rec5.Body.String())
	}
	if stub.total() != 3 {
		t.Fatalf("distinct scope calls=%d, want 3", stub.total())
	}

	// Application-plane credentials never authorize control mutations.
	recApp := doControl(t, h, http.MethodPost, "/control/connector/cancel", cancelBody("conn-1", "k-app", "x"), map[string]string{
		"Authorization": "Channel app-token", "Idempotency-Key": "k-app",
	})
	if recApp.Code != http.StatusForbidden {
		t.Fatalf("app cancel: %d %s, want 403", recApp.Code, recApp.Body.String())
	}
	if stub.total() != 3 {
		t.Fatalf("app credential caused effect")
	}

	// Reads are not idempotently cached: the same pinned read reflects
	// newer evidence after the journal advances.
	sessionID, journalID, admRef := admitSession(t, h, "t1reads", "manual", "opA-token", "admit-t1")
	_ = admRef
	pinnedSeq := int64(2)
	pinnedHash, _ := admRef["event_hash"].(string)
	eventsPath := "/control/sessions/" + sessionID + "/events?journal_id=" + journalID + "&last_sequence=2&head_hash=" + pinnedHash
	g1 := doControl(t, h, http.MethodGet, eventsPath, nil, map[string]string{"Authorization": "Channel opA-token"})
	if g1.Code != http.StatusOK {
		t.Fatalf("events first: %d %s", g1.Code, g1.Body.String())
	}
	if g1.Header().Get("X-Idempotent-Replayed") != "" {
		t.Fatalf("reads must not be idempotently replayed")
	}
	// Advance the journal with one owner-local event.
	ctx := authedContext(t, "opA-token")
	extra := []owner_store.EventSubmission{{
		ProducerSequence: owner_store.NewMissing("not_applicable"), EventKind: "operator_marker",
		EventSchemaVersion: "1.0.0", OccurredAt: owner_store.NewMissing("not_observed"),
		Payload: owner_store.Payload{Data: map[string]any{"marker": "probe"}, Measurements: []owner_store.Measurement{}, EvidenceRefs: []owner_store.EvidenceRef{}, ArtifactRefs: []owner_store.ArtifactReference{}},
	}}
	if _, err := owner_store.CommitOwner(ctx, primary, journalID, extra, nil); err != nil {
		t.Fatalf("advance journal: %v", err)
	}
	g2 := doControl(t, h, http.MethodGet, eventsPath, nil, map[string]string{"Authorization": "Channel opA-token"})
	if g2.Code != http.StatusOK {
		t.Fatalf("events second: %d %s", g2.Code, g2.Body.String())
	}
	outG2 := decodeBody(t, g2)
	if outG2["stale"] != true {
		t.Fatalf("second read stale=%v, want true (pinned %d)", outG2["stale"], pinnedSeq)
	}
	if outG2["current_sequence"] == float64(pinnedSeq) {
		t.Fatalf("current_sequence did not advance: %v", outG2["current_sequence"])
	}

	// Admit itself is idempotent under the same scoped key.
	manifest := testManifest("t1admit", "")
	commission := testCommission(t, "t1admit", manifest, "manual")
	regs := []admission.EntityRegistration{testRegistration("t1admit", manifest, "target-t1admit")}
	payload := map[string]any{"manifest": manifest, "commission": commission, "registrations": regs}
	a1 := doControl(t, h, http.MethodPost, "/control/sessions", payload, map[string]string{
		"Authorization": "Channel opA-token", "Idempotency-Key": "admit-dup",
	})
	if a1.Code != http.StatusCreated {
		t.Fatalf("admit first: %d %s", a1.Code, a1.Body.String())
	}
	a2 := doControl(t, h, http.MethodPost, "/control/sessions", payload, map[string]string{
		"Authorization": "Channel opA-token", "Idempotency-Key": "admit-dup",
	})
	if a2.Code != http.StatusCreated {
		t.Fatalf("admit replay: %d %s", a2.Code, a2.Body.String())
	}
	if a2.Header().Get("X-Idempotent-Replayed") != "true" {
		t.Fatalf("admit replay missing header")
	}
	if decodeBody(t, a1)["receipt_id"] != decodeBody(t, a2)["receipt_id"] {
		t.Fatalf("admit replay receipt mismatch")
	}
}

// ---------------------------------------------------------------------------
// 2. End-observation and native-cancel remain separate commands.
// ---------------------------------------------------------------------------

func TestEndObservationAndNativeCancelRemainSeparateCommands(t *testing.T) {
	primary, application, observation := openStores(t)
	h := newTestHandler(primary, application, observation)
	stub := newConnectorStub(t)
	h.ConnectorEndpoint = stub.server.URL + "/connector"
	sessionID, _, _ := admitSession(t, h, "t2sep", "manual", "opA-token", "admit-t2")

	postConnector := func(route, op, requestID string) map[string]any {
		t.Helper()
		body := map[string]any{
			"record_type": "connector_request", "schema_version": connector_transport.SchemaVersion,
			"request_id": requestID, "connector_id": "conn-1", "operation": op,
			"call_limit": map[string]any{"kind": "exact", "unit": "ms", "value": 5000},
			"payload":   map[string]any{"handle": "h-1", "reason": "test"},
		}
		rec := doControl(t, h, http.MethodPost, route, body, map[string]string{
			"Authorization": "Channel opA-token", "Idempotency-Key": requestID,
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("%s %s: %d %s", route, requestID, rec.Code, rec.Body.String())
		}
		return decodeBody(t, rec)
	}

	// The same request_id under different verbs yields distinct commands.
	cancelOut := postConnector("/control/connector/cancel", connector_transport.OpRequestNativeCancel, "r-shared")
	closeOut := postConnector("/control/connector/close", connector_transport.OpCloseObservationConnection, "r-shared")
	releaseOut := postConnector("/control/connector/release", connector_transport.OpReleaseNativeContext, "r-shared")
	containOut := postConnector("/control/connector/contain", connector_transport.OpContain, "r-shared")
	receipts := map[string]bool{
		cancelOut["receipt_id"].(string): true, closeOut["receipt_id"].(string): true,
		releaseOut["receipt_id"].(string): true, containOut["receipt_id"].(string): true,
	}
	if len(receipts) != 4 {
		t.Fatalf("control receipts not distinct: %v", receipts)
	}
	cevs := map[string]bool{
		cancelOut["control_event_id"].(string): true, closeOut["control_event_id"].(string): true,
		releaseOut["control_event_id"].(string): true, containOut["control_event_id"].(string): true,
	}
	if len(cevs) != 4 {
		t.Fatalf("control_event_ids not distinct")
	}
	for name, out := range map[string]map[string]any{"cancel": cancelOut, "close": closeOut, "release": releaseOut, "contain": containOut} {
		if out["disposition"] == "effect_observed" {
			t.Fatalf("%s claims effect_observed without effect evidence", name)
		}
		if out["effect_observed"] == true {
			t.Fatalf("%s effect_observed true", name)
		}
	}
	if stub.count(connector_transport.OpRequestNativeCancel) != 1 || stub.count(connector_transport.OpCloseObservationConnection) != 1 {
		t.Fatalf("per-verb counts wrong: %+v", stub.perOp)
	}

	// End-observation with the same request_id is a fifth distinct command
	// and, for manual mode, issues no connector call at all.
	cancelBefore := stub.count(connector_transport.OpRequestNativeCancel)
	endRec := doControl(t, h, http.MethodPost, "/control/sessions/"+sessionID+"/end-observation", map[string]any{"reason": "normal_completion"}, map[string]string{
		"Authorization": "Channel opA-token", "Idempotency-Key": "r-shared",
	})
	if endRec.Code != http.StatusOK {
		t.Fatalf("end-observation: %d %s", endRec.Code, endRec.Body.String())
	}
	endOut := decodeBody(t, endRec)
	if endOut["receipt_id"] == cancelOut["receipt_id"] {
		t.Fatalf("end-observation reused cancel receipt")
	}
	if endOut["operation"] != "end_observation" {
		t.Fatalf("end operation = %v", endOut["operation"])
	}
	if endOut["native_cancel_requested"] == true {
		t.Fatalf("end-observation must not imply native cancel")
	}
	if stub.count(connector_transport.OpRequestNativeCancel) != cancelBefore {
		t.Fatalf("manual end-observation triggered connector cancel")
	}

	// Release failure never silently triggers containment.
	stub.setFail(connector_transport.OpReleaseNativeContext, "NATIVE_PROTOCOL_ERROR")
	failBody := map[string]any{
		"record_type": "connector_request", "schema_version": connector_transport.SchemaVersion,
		"request_id": "r-release-fail", "connector_id": "conn-1", "operation": connector_transport.OpReleaseNativeContext,
		"call_limit": map[string]any{"kind": "exact", "unit": "ms", "value": 5000},
		"payload":   map[string]any{"handle": "h-1"},
	}
	failRec := doControl(t, h, http.MethodPost, "/control/connector/release", failBody, map[string]string{
		"Authorization": "Channel opA-token", "Idempotency-Key": "r-release-fail",
	})
	if failRec.Code == http.StatusOK {
		t.Fatalf("failing release returned 200: %s", failRec.Body.String())
	}
	if stub.count(connector_transport.OpContain) != 1 {
		t.Fatalf("release failure triggered containment: contain=%d", stub.count(connector_transport.OpContain))
	}
}

// ---------------------------------------------------------------------------
// 3. Manual control cannot patch origin business predicates.
// ---------------------------------------------------------------------------

func TestManualControlCannotPatchOriginBusinessPredicates(t *testing.T) {
	primary, application, observation := openStores(t)
	h := newTestHandler(primary, application, observation)
	sessionID, _, _ := admitSession(t, h, "t3manual", "manual", "opA-token", "admit-t3")
	obsJournal := "obs-journal-t3manual"
	initObservationForSession(t, observation, sessionID, obsJournal)

	notePath := "/control/sessions/" + sessionID + "/notes"
	postNote := func(body map[string]any, token, key string) *httptest.ResponseRecorder {
		return doControl(t, h, http.MethodPost, notePath, body, map[string]string{
			"Authorization": "Channel " + token, "Idempotency-Key": key,
		})
	}
	missingSeq := map[string]any{"value": nil, "reason": "not_applicable"}
	missingOcc := map[string]any{"value": nil, "reason": "not_observed"}

	// Business-predicate data keys are rejected before any effect.
	badData := map[string]any{
		"producer_sequence": missingSeq, "event_kind": "operator_note", "event_schema_version": "1.0.0",
		"occurred_at": missingOcc,
		"payload": map[string]any{
			"data": map[string]any{"note": "x", "committed": true},
			"measurements": []any{}, "evidence_refs": []any{}, "artifact_refs": []any{},
		},
	}
	recBad := postNote(badData, "opA-token", "note-bad-1")
	if recBad.Code != http.StatusUnprocessableEntity {
		t.Fatalf("bad data: %d %s, want 422", recBad.Code, recBad.Body.String())
	}
	// Authoritative event kinds are rejected as well.
	badKind := map[string]any{
		"producer_sequence": missingSeq, "event_kind": "submission_committed", "event_schema_version": "1.0.0",
		"occurred_at": missingOcc,
		"payload": map[string]any{"data": map[string]any{"note": "x"}, "measurements": []any{}, "evidence_refs": []any{}, "artifact_refs": []any{}},
	}
	recKind := postNote(badKind, "opA-token", "note-bad-2")
	if recKind.Code != http.StatusUnprocessableEntity {
		t.Fatalf("bad kind: %d %s, want 422", recKind.Code, recKind.Body.String())
	}

	// A valid operator note succeeds with manual provenance and disclosed
	// assistance, and sets no business predicate.
	good := map[string]any{
		"producer_sequence": missingSeq, "event_kind": "operator_note", "event_schema_version": "1.0.0",
		"occurred_at": missingOcc,
		"payload": map[string]any{
			"data": map[string]any{"note": "operator observed receipt X", "interval": "t1-t2"},
			"measurements": []any{}, "evidence_refs": []any{}, "artifact_refs": []any{},
		},
	}
	recGood := postNote(good, "opA-token", "note-good-1")
	if recGood.Code != http.StatusCreated {
		t.Fatalf("good note: %d %s", recGood.Code, recGood.Body.String())
	}
	outGood := decodeBody(t, recGood)
	ref, _ := outGood["evidence_ref"].(map[string]any)
	if ref == nil || ref["journal_id"] == "" {
		t.Fatalf("good note missing evidence_ref: %s", recGood.Body.String())
	}
	// The stored envelope retains manual framing and no predicate keys.
	ctx := authedContext(t, "opA-token")
	seq := int64(ref["sequence"].(float64))
	prefix := owner_store.JournalPrefix{JournalID: ref["journal_id"].(string), LastSequence: seq, HeadHash: ref["event_hash"].(string)}
	events, err := owner_store.LoadPrefix(ctx, observation, prefix)
	if err != nil {
		t.Fatalf("LoadPrefix obs: %v", err)
	}
	last := events[len(events)-1]
	data := last.Payload.Data
	if data["provenance"] != "manual" || data["recorded_by"] != "manual_recorder" {
		t.Fatalf("manual provenance missing: %v", data)
	}
	if _, has := data["assistance"]; !has {
		t.Fatalf("disclosed assistance missing: %v", data)
	}
	for _, k := range []string{"committed", "verified", "submission_committed", "identity_verified", "commitment"} {
		if _, has := data[k]; has {
			t.Fatalf("note set predicate %q", k)
		}
	}
	// Application credentials cannot post notes.
	recApp := postNote(good, "app-token", "note-app-1")
	if recApp.Code != http.StatusForbidden {
		t.Fatalf("app note: %d %s, want 403", recApp.Code, recApp.Body.String())
	}
}

// ---------------------------------------------------------------------------
// 4. Export orders inputs, receipt, acceptance without hash cycles.
// ---------------------------------------------------------------------------

func TestExportOrdersInputsReceiptAndAcceptanceWithoutHashCycles(t *testing.T) {
	primary, application, observation := openStores(t)
	h := newTestHandler(primary, application, observation)
	stub := newConnectorStub(t)
	h.ConnectorEndpoint = stub.server.URL + "/connector"
	sessionID, _, _ := admitSession(t, h, "t4export", "manual", "opA-token", "admit-t4")

	dInputs := "sha256:" + strings.Repeat("1", 64)
	dSource := "sha256:" + strings.Repeat("2", 64)
	dChecks := "sha256:" + strings.Repeat("3", 64)
	dValid := "sha256:" + strings.Repeat("4", 64)
	var mu sync.Mutex
	var order []string
	mkRef := func(d string) evidence_bundle.ArtifactReference {
		return evidence_bundle.ArtifactReference{Digest: d, SizeBytes: 64, MediaType: "application/json", OwnerDomain: "diagnostic", Access: "restricted"}
	}
	h.exportInputsFn = func(ctx context.Context, store *OwnerStore, row evidence_bundle.LogicalRow, diag evidence_bundle.DiagnosticDocument) (evidence_bundle.ArtifactReference, error) {
		mu.Lock()
		order = append(order, "inputs")
		mu.Unlock()
		return mkRef(dInputs), nil
	}
	installCalls := 0
	h.installFn = func(ctx context.Context, store *OwnerStore, content io.Reader, mediaType, access string) (owner_store.ArtifactReference, error) {
		mu.Lock()
		installCalls++
		n := installCalls
		mu.Unlock()
		raw, _ := io.ReadAll(content)
		_ = raw
		if n == 1 {
			mu.Lock()
			order = append(order, "install-source")
			mu.Unlock()
			return owner_store.ArtifactReference(mkRef(dSource)), nil
		}
		mu.Lock()
		order = append(order, "install-checks")
		mu.Unlock()
		return owner_store.ArtifactReference(mkRef(dChecks)), nil
	}
	h.replayFn = func(ctx context.Context, store *OwnerStore, bundle, source evidence_bundle.ArtifactReference, mode string) (evidence_bundle.ReplayReceipt, error) {
		mu.Lock()
		order = append(order, "replay")
		mu.Unlock()
		if bundle.Digest != dInputs {
			t.Errorf("replay got bundle %s, want inputs %s", bundle.Digest, dInputs)
		}
		if mode != "exact_fixture" {
			t.Errorf("replay mode = %s", mode)
		}
		return evidence_bundle.ReplayReceipt{
			RecordType: "replay_receipt", SchemaVersion: "0.1.0", ReplayID: "replay-t4", Mode: mode,
			RunID: "attempt-t4export", ManifestHash: dInputs,
			SourcePrefix: evidence_bundle.JournalPrefix{JournalID: "journal-t4export", LastSequence: 2, HeadHash: dInputs},
			SourceDiagnostic: source, InputBundle: bundle,
			Classifier: evidence_bundle.VersionPin{ID: "c", Version: "1.0", ArtifactDigest: dSource},
			Reducer: evidence_bundle.VersionPin{ID: "r", Version: "1.0", ArtifactDigest: dSource},
			ReplayEngine: evidence_bundle.VersionPin{ID: "e", Version: "1.0", ArtifactDigest: dSource},
			Comparisons: []evidence_bundle.ReplayComparison{{Output: "diagnostic", ExpectedDigest: dInputs, ActualDigest: dInputs, Result: "matched"}},
			Result: "matched", Limitations: []string{},
			InvokedBrowser: false, InvokedSubject: false, PerformedExternalWrites: false,
		}, nil
	}
	h.checkFn = func(ctx context.Context, store *OwnerStore, inputs evidence_bundle.ArtifactReference, receipt evidence_bundle.ReplayReceipt) ([]byte, error) {
		mu.Lock()
		order = append(order, "checks")
		mu.Unlock()
		if inputs.Digest != dInputs || receipt.ReplayID != "replay-t4" {
			t.Errorf("checks got inputs %s receipt %s", inputs.Digest, receipt.ReplayID)
		}
		return []byte(`{"checks":["ok"]}`), nil
	}
	h.exportValidationFn = func(ctx context.Context, store *OwnerStore, row evidence_bundle.LogicalRow, diag evidence_bundle.DiagnosticDocument, receipt evidence_bundle.ReplayReceipt, checks evidence_bundle.ArtifactReference) (evidence_bundle.ArtifactReference, error) {
		mu.Lock()
		order = append(order, "validation")
		mu.Unlock()
		if receipt.InputBundle.Digest != dInputs || checks.Digest != dChecks {
			t.Errorf("validation got receipt %s checks %s", receipt.InputBundle.Digest, checks.Digest)
		}
		return mkRef(dValid), nil
	}

	exportBody := map[string]any{
		"row":        map[string]any{"record_type": "logical_row"},
		"diagnostic": map[string]any{"record_type": "diagnostic", "diagnostic_id": "d-t4"},
		"mode":       "exact_fixture",
	}
	rec := doControl(t, h, http.MethodPost, "/control/sessions/"+sessionID+"/export", exportBody, map[string]string{
		"Authorization": "Channel opA-token", "Idempotency-Key": "export-1",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("export: %d %s", rec.Code, rec.Body.String())
	}
	out := decodeBody(t, rec)
	inputs, _ := out["inputs"].(map[string]any)
	validation, _ := out["validation"].(map[string]any)
	receipt, _ := out["receipt"].(map[string]any)
	if inputs["digest"] != dInputs || validation["digest"] != dValid {
		t.Fatalf("export digests wrong: %s", rec.Body.String())
	}
	if receipt["replay_id"] != "replay-t4" {
		t.Fatalf("export receipt wrong: %s", rec.Body.String())
	}
	if out["invoked_browser"] == true || out["invoked_subject"] == true || out["performed_external_writes"] == true {
		t.Fatalf("export invoked execution: %s", rec.Body.String())
	}
	mu.Lock()
	gotOrder := append([]string(nil), order...)
	mu.Unlock()
	wantSeq := []string{"inputs", "install-source", "replay", "checks", "install-checks", "validation"}
	if len(gotOrder) != len(wantSeq) {
		t.Fatalf("export order %v, want %v", gotOrder, wantSeq)
	}
	for i := range wantSeq {
		if gotOrder[i] != wantSeq[i] {
			t.Fatalf("export order %v, want %v", gotOrder, wantSeq)
		}
	}
	if stub.total() != 0 {
		t.Fatalf("export called connector %d times", stub.total())
	}

	// Repeating the identical export replays without re-executing the chain.
	recDup := doControl(t, h, http.MethodPost, "/control/sessions/"+sessionID+"/export", exportBody, map[string]string{
		"Authorization": "Channel opA-token", "Idempotency-Key": "export-1",
	})
	if recDup.Code != http.StatusOK || recDup.Header().Get("X-Idempotent-Replayed") != "true" {
		t.Fatalf("export replay: %d %s", recDup.Code, recDup.Body.String())
	}
	mu.Lock()
	afterDup := len(order)
	mu.Unlock()
	if afterDup != len(wantSeq) {
		t.Fatalf("export replay re-executed chain: %v", order)
	}

	// A validation bundle reusing the inputs digest is a hash cycle.
	h.exportValidationFn = func(ctx context.Context, store *OwnerStore, row evidence_bundle.LogicalRow, diag evidence_bundle.DiagnosticDocument, receipt evidence_bundle.ReplayReceipt, checks evidence_bundle.ArtifactReference) (evidence_bundle.ArtifactReference, error) {
		return mkRef(dInputs), nil
	}
	recCycle := doControl(t, h, http.MethodPost, "/control/sessions/"+sessionID+"/export", exportBody, map[string]string{
		"Authorization": "Channel opA-token", "Idempotency-Key": "export-cycle",
	})
	if recCycle.Code != http.StatusInternalServerError {
		t.Fatalf("hash cycle: %d %s, want 500", recCycle.Code, recCycle.Body.String())
	}
	if !strings.Contains(recCycle.Body.String(), "HASH_CYCLE") {
		t.Fatalf("hash cycle missing code: %s", recCycle.Body.String())
	}
}

// ---------------------------------------------------------------------------
// 5. Control reads display pinned source and report staleness.
// ---------------------------------------------------------------------------

func TestControlReadsDisplayPinnedSourceAndReportStaleness(t *testing.T) {
	primary, application, observation := openStores(t)
	h := newTestHandler(primary, application, observation)
	sessionID, journalID, admRef := admitSession(t, h, "t5reads", "manual", "opA-token", "admit-t5")
	pinnedHash, _ := admRef["event_hash"].(string)
	pinnedPath := func() string {
		return "/control/sessions/" + sessionID + "/events?journal_id=" + journalID + "&last_sequence=2&head_hash=" + pinnedHash
	}
	diagPath := func() string {
		return "/control/sessions/" + sessionID + "/diagnostic?journal_id=" + journalID + "&last_sequence=2&head_hash=" + pinnedHash
	}

	// At admission the pinned prefix is the head: not stale.
	g1 := doControl(t, h, http.MethodGet, pinnedPath(), nil, map[string]string{"Authorization": "Channel opA-token"})
	if g1.Code != http.StatusOK {
		t.Fatalf("events pinned: %d %s", g1.Code, g1.Body.String())
	}
	out1 := decodeBody(t, g1)
	if out1["stale"] == true {
		t.Fatalf("fresh read stale=true")
	}
	if out1["pinned_count"] != float64(2) {
		t.Fatalf("pinned_count=%v, want 2", out1["pinned_count"])
	}
	pinned, _ := out1["pinned_prefix"].(map[string]any)
	if pinned["journal_id"] != journalID || pinned["head_hash"] != pinnedHash {
		t.Fatalf("pinned source not displayed: %v", pinned)
	}
	if strings.Contains(g1.Body.String(), `"evidence_refs":null`) || strings.Contains(g1.Body.String(), `"pinned_events":null`) {
		t.Fatalf("read used bare nulls: %s", g1.Body.String())
	}

	// Advance the journal; the same pinned read is now stale.
	ctx := authedContext(t, "opA-token")
	extra := []owner_store.EventSubmission{{
		ProducerSequence: owner_store.NewMissing("not_applicable"), EventKind: "operator_marker",
		EventSchemaVersion: "1.0.0", OccurredAt: owner_store.NewMissing("not_observed"),
		Payload: owner_store.Payload{Data: map[string]any{"marker": "late"}, Measurements: []owner_store.Measurement{}, EvidenceRefs: []owner_store.EvidenceRef{}, ArtifactRefs: []owner_store.ArtifactReference{}},
	}}
	envelopes, err := owner_store.CommitOwner(ctx, primary, journalID, extra, nil)
	if err != nil {
		t.Fatalf("advance: %v", err)
	}
	if len(envelopes) != 1 || envelopes[0].Sequence != 3 {
		t.Fatalf("advance envelopes: %+v", envelopes)
	}
	g2 := doControl(t, h, http.MethodGet, pinnedPath(), nil, map[string]string{"Authorization": "Channel opA-token"})
	if g2.Code != http.StatusOK {
		t.Fatalf("events stale: %d %s", g2.Code, g2.Body.String())
	}
	out2 := decodeBody(t, g2)
	if out2["stale"] != true {
		t.Fatalf("stale=%v, want true", out2["stale"])
	}
	if out2["current_sequence"] != float64(3) {
		t.Fatalf("current_sequence=%v, want 3", out2["current_sequence"])
	}
	// The pinned source still shows exactly the two pinned events.
	if out2["pinned_count"] != float64(2) {
		t.Fatalf("stale pinned_count=%v, want 2", out2["pinned_count"])
	}

	// Diagnostic reads report the same staleness against the pinned input.
	d1 := doControl(t, h, http.MethodGet, diagPath(), nil, map[string]string{"Authorization": "Channel opA-token"})
	if d1.Code != http.StatusOK {
		t.Fatalf("diagnostic pinned: %d %s", d1.Code, d1.Body.String())
	}
	dout := decodeBody(t, d1)
	if dout["stale"] != true || dout["current_sequence"] != float64(3) {
		t.Fatalf("diagnostic staleness wrong: %s", d1.Body.String())
	}
	if dout["pinned_count"] != float64(2) {
		t.Fatalf("diagnostic pinned_count wrong: %s", d1.Body.String())
	}

	// Reading at the new head is fresh again.
	headHash := envelopes[0].EventHash
	freshPath := "/control/sessions/" + sessionID + "/events?journal_id=" + journalID + "&last_sequence=3&head_hash=" + headHash
	g3 := doControl(t, h, http.MethodGet, freshPath, nil, map[string]string{"Authorization": "Channel opA-token"})
	if g3.Code != http.StatusOK {
		t.Fatalf("events fresh: %d %s", g3.Code, g3.Body.String())
	}
	if decodeBody(t, g3)["stale"] == true {
		t.Fatalf("head read stale=true")
	}

	// Application credentials cannot read the control surface.
	gApp := doControl(t, h, http.MethodGet, pinnedPath(), nil, map[string]string{"Authorization": "Channel app-token"})
	if gApp.Code != http.StatusForbidden {
		t.Fatalf("app read: %d %s, want 403", gApp.Code, gApp.Body.String())
	}
}

// ---------------------------------------------------------------------------
// 6. Practice completion cannot trigger production dispatch.
// ---------------------------------------------------------------------------

func TestPracticeCompletionCannotTriggerProductionDispatch(t *testing.T) {
	primary, application, observation := openStores(t)
	h := newTestHandler(primary, application, observation)
	stub := newConnectorStub(t)
	h.ConnectorEndpoint = stub.server.URL + "/connector"
	sessionID, _, _ := admitSession(t, h, "t6practice", "manual", "opA-token", "admit-t6")

	// Completing the practice session issues no production dispatch.
	endRec := doControl(t, h, http.MethodPost, "/control/sessions/"+sessionID+"/end-observation", map[string]any{"reason": "normal_completion"}, map[string]string{
		"Authorization": "Channel opA-token", "Idempotency-Key": "end-t6",
	})
	if endRec.Code != http.StatusOK {
		t.Fatalf("end-observation: %d %s", endRec.Code, endRec.Body.String())
	}
	if stub.count(connector_transport.OpStart) != 0 {
		t.Fatalf("practice completion dispatched Start")
	}
	if stub.total() != 0 {
		t.Fatalf("practice completion called connector %d times", stub.total())
	}

	// Explicit production dispatch is refused.
	prodBody := map[string]any{"kind": "production", "target_class": "employer_origin", "production": true}
	prodRec := doControl(t, h, http.MethodPost, "/control/sessions/"+sessionID+"/dispatch", prodBody, map[string]string{
		"Authorization": "Channel opA-token", "Idempotency-Key": "dispatch-prod",
	})
	if prodRec.Code != http.StatusForbidden {
		t.Fatalf("production dispatch: %d %s, want 403", prodRec.Code, prodRec.Body.String())
	}
	if stub.count(connector_transport.OpStart) != 0 {
		t.Fatalf("refused production dispatch still called Start")
	}
	// Employer-origin strings are refused even without the boolean.
	sneaky := map[string]any{"kind": "practice", "target_class": "employer_origin"}
	sneakyRec := doControl(t, h, http.MethodPost, "/control/sessions/"+sessionID+"/dispatch", sneaky, map[string]string{
		"Authorization": "Channel opA-token", "Idempotency-Key": "dispatch-sneaky",
	})
	if sneakyRec.Code != http.StatusForbidden {
		t.Fatalf("sneaky dispatch: %d %s, want 403", sneakyRec.Code, sneakyRec.Body.String())
	}

	// Explicit practice dispatch succeeds and stays practice-scoped.
	goodBody := map[string]any{"kind": "practice", "target_class": "laboratory_fixture"}
	goodRec := doControl(t, h, http.MethodPost, "/control/sessions/"+sessionID+"/dispatch", goodBody, map[string]string{
		"Authorization": "Channel opA-token", "Idempotency-Key": "dispatch-good",
	})
	if goodRec.Code != http.StatusOK {
		t.Fatalf("practice dispatch: %d %s", goodRec.Code, goodRec.Body.String())
	}
	goodOut := decodeBody(t, goodRec)
	if goodOut["production_dispatched"] == true {
		t.Fatalf("practice dispatch flagged production")
	}
	if stub.count(connector_transport.OpStart) != 1 {
		t.Fatalf("practice Start count=%d, want 1", stub.count(connector_transport.OpStart))
	}
	// The connector payload retains the practice scope.
	stub.mu.Lock()
	var payload map[string]any
	if len(stub.calls) > 0 {
		_ = json.Unmarshal(stub.calls[0].Payload, &payload)
	}
	stub.mu.Unlock()
	if payload["kind"] != "practice" || payload["target_class"] != "laboratory_fixture" {
		t.Fatalf("dispatch payload lost practice scope: %v", payload)
	}

	// Repeating the practice dispatch replays without a second effect.
	dupRec := doControl(t, h, http.MethodPost, "/control/sessions/"+sessionID+"/dispatch", goodBody, map[string]string{
		"Authorization": "Channel opA-token", "Idempotency-Key": "dispatch-good",
	})
	if dupRec.Code != http.StatusOK || dupRec.Header().Get("X-Idempotent-Replayed") != "true" {
		t.Fatalf("dispatch replay: %d %s", dupRec.Code, dupRec.Body.String())
	}
	if stub.count(connector_transport.OpStart) != 1 {
		t.Fatalf("dispatch replay caused second Start")
	}

	// Application credentials cannot dispatch.
	appRec := doControl(t, h, http.MethodPost, "/control/sessions/"+sessionID+"/dispatch", goodBody, map[string]string{
		"Authorization": "Channel app-token", "Idempotency-Key": "dispatch-app",
	})
	if appRec.Code != http.StatusForbidden {
		t.Fatalf("app dispatch: %d %s, want 403", appRec.Code, appRec.Body.String())
	}
}

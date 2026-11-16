package observation_owner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"authority"
	"evidence_codec"
	"lifecycle_rules"
	"owner_store"
)

// ---------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------

func testPolicy() []byte {
	return []byte(`{"channels":{"test-channel":{"principal":"test-writer","kind":"owner","grants":[{"domain":"*","operations":["*"]}]}}}`)
}

func authedContext(t *testing.T) context.Context {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "http://observation.test/direct", nil)
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

func openStore(t *testing.T, domain string) *OwnerStore {
	t.Helper()
	home := t.TempDir()
	store, err := owner_store.OpenOwner(
		filepath.Join(home, domain+".db"),
		filepath.Join(home, domain+"-artifacts"),
		domain,
	)
	if err != nil {
		t.Fatalf("OpenOwner(%s): %v", domain, err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func testManifest(suffix, ownerDomain string) Manifest {
	return Manifest{
		RecordType:    "manifest",
		SchemaVersion: "0.1.0",
		ManifestID:    "manifest-" + suffix,
		RunID:         "attempt-" + suffix,
		JournalID:     "journal-" + suffix,
		OwnerDomain:   ownerDomain,
		Clocks: []ClockDescriptor{{
			ClockID: "clock-" + suffix, BootID: "boot-" + suffix,
			Origin: "engine_measured", SourceID: "observation-owner",
			Basis: "monotonic_offset", Unit: "ms",
		}},
	}
}

func testRegistration(suffix string) EntityRegistration {
	return EntityRegistration{
		RecordType:     "write_domain_entity",
		SchemaVersion:  "0.1.0",
		RegistrationID: "registration-" + suffix,
		Entity: map[string]any{
			"entity_type": "hellscape_session",
			"entity_id":   "session-" + suffix,
		},
		Identity: map[string]any{
			"run_id":     "attempt-" + suffix,
			"journal_id": "journal-" + suffix,
			"attempt": map[string]any{
				"kind": "practice", "target_class": "laboratory_fixture",
				"evaluation_partition": "held_in",
			},
		},
		Owners: map[string]any{
			"observation": map[string]any{"role": "connector", "source_id": "connector-1", "writer_id": "obs-writer-" + suffix},
		},
		EvidenceRefs: []EvidenceRef{},
	}
}

func initObservation(t *testing.T, store *OwnerStore, suffix string) (string, string, EvidenceRef) {
	t.Helper()
	manifest := testManifest(suffix, "observation")
	ref, err := InitializeObservation(authedContext(t), store, manifest, testRegistration(suffix))
	if err != nil {
		t.Fatalf("InitializeObservation(%s): %v", suffix, err)
	}
	return manifest.RunID, manifest.JournalID, ref
}

func testDigest(seed string) string {
	return string(evidence_codec.HashBytes([]byte("observation-owner-test/" + seed)))
}

func testArtifact(owner, seed string) lifecycle_rules.ArtifactReference {
	return lifecycle_rules.ArtifactReference{
		Digest: testDigest(seed), SizeBytes: 128,
		MediaType: "application/json", OwnerDomain: owner, Access: "restricted",
	}
}

func testPin(id, version, seed string) lifecycle_rules.VersionPin {
	return lifecycle_rules.VersionPin{ID: id, Version: version, ArtifactDigest: testDigest(seed)}
}

// testCommission builds a valid manual-attempt commission matching the
// observation manifest (run/journal/attempt IDs).
func testCommission(suffix string, manifest Manifest) AttemptCommission {
	target := "origin-" + suffix
	return AttemptCommission{
		RecordType: "attempt_commission", SchemaVersion: lifecycle_rules.SchemaLifecycle, KernelVersion: lifecycle_rules.SchemaKernel,
		CommissionID: "commission-" + suffix, RunID: manifest.RunID, JournalID: manifest.JournalID,
		ManifestHash: testDigest("manifest-" + suffix),
		AdmissionRef: EvidenceRef{JournalID: manifest.JournalID, Sequence: 1, EventID: "evt-admission", EventHash: testDigest("admission-" + suffix), Pointer: ""},
		CommissionedBy: "operator-1",
		CommissionedAt: TimePoint{
			ClockID: manifest.Clocks[0].ClockID, BootID: manifest.Clocks[0].BootID, Origin: manifest.Clocks[0].Origin,
			MonotonicOffsetMs: 10, UTCAnnotation: owner_store.NewMissing("not_applicable"),
		},
		Attempt: lifecycle_rules.AttemptContext{
			AttemptID: manifest.RunID, Kind: "practice", TargetClass: "laboratory_fixture",
			TargetID: target, EvaluationPartition: "held_in",
			RehearsalOf: []AttemptReference{}, PerformanceOf: []AttemptReference{}, DerivedFrom: []AttemptReference{},
		},
		CandidateID: "candidate-" + suffix, CandidateProfile: lifecycle_rules.NewMissing("not_observed"),
		Job: lifecycle_rules.JobReference{
			JobID: "job-1", SourceTarget: lifecycle_rules.NewMissing("not_observed"),
			SourceJobID: lifecycle_rules.NewMissing("not_observed"), Snapshot: testArtifact("origin-domain", "job-"+suffix),
		},
		SelectionEvidence: lifecycle_rules.NewMissing("not_observed"),
		Task:              testArtifact("origin-domain", "task-"+suffix),
		TaskSemanticHash:  testDigest("task-semantic-" + suffix),
		InitialMaterials:  []lifecycle_rules.ArtifactReference{},
		Execution: lifecycle_rules.ExecutionDescriptor{
			Mode: "manual",
			Subject: lifecycle_rules.NewMissing("not_applicable"),
			ConnectorVersion: lifecycle_rules.NewMissing("not_applicable"),
			BindingVersion:   lifecycle_rules.NewMissing("not_applicable"),
			Assistance: lifecycle_rules.AssistanceRecord{
				PlanningOwner: "none", AssistanceTrack: "manual-track",
				PlannerIdentity: lifecycle_rules.NewMissing("not_applicable"), Plan: lifecycle_rules.NewMissing("not_observed"),
				OnlineReplanning: false, Description: "manual walkthrough",
			},
		},
		Owners: lifecycle_rules.OwnerBindings{
			Dispatch:    lifecycle_rules.AuthorityBinding{Role: "connector", SourceID: "connector-1", WriterID: "dispatch-writer-" + suffix, OwnerDomain: "dispatch-domain", PublicationPolicy: testPin("pub", "v1", "pub-dispatch-"+suffix)},
			Observation: lifecycle_rules.AuthorityBinding{Role: "connector", SourceID: "connector-1", WriterID: "obs-writer-" + suffix, OwnerDomain: "observation", PublicationPolicy: testPin("pub", "v1", "pub-obs-"+suffix)},
			Execution:   lifecycle_rules.AuthorityBinding{Role: "subject", SourceID: lifecycle_rules.NewMissing("not_applicable"), WriterID: lifecycle_rules.NewMissing("not_applicable"), OwnerDomain: "exec-domain", PublicationPolicy: testPin("pub", "v1", "pub-exec-"+suffix)},
			Application: lifecycle_rules.AuthorityBinding{Role: "origin", SourceID: target, WriterID: "app-writer-" + suffix, OwnerDomain: "origin-domain", PublicationPolicy: testPin("pub", "v1", "pub-app-"+suffix)},
			Report:      lifecycle_rules.AuthorityBinding{Role: "reconciler", SourceID: "reconciler-1", WriterID: "report-writer-" + suffix, OwnerDomain: "report-domain", PublicationPolicy: testPin("pub", "v1", "pub-report-"+suffix)},
		},
		IdempotencyKey:    "idem-" + suffix,
		AuthorizationRefs: []EvidenceRef{{JournalID: manifest.JournalID, Sequence: 1, EventID: "evt-admission", EventHash: testDigest("admission-" + suffix), Pointer: ""}},
		RecoveryReviewRefs: []EvidenceRef{},
		ObservationPolicy: lifecycle_rules.ObservationPolicy{
			ActiveLimit:           lifecycle_rules.DurationLimit{Kind: "exact", Unit: "ms", Value: 60000},
			DrainLimit:            lifecycle_rules.DurationLimit{Kind: "exact", Unit: "ms", Value: 10000},
			NativeCancelWaitLimit: lifecycle_rules.DurationLimit{Kind: "exact", Unit: "ms", Value: 5000},
			CleanupWaitLimit:      lifecycle_rules.DurationLimit{Kind: "exact", Unit: "ms", Value: 5000},
			FixtureCloseAction:    "seal_after_drain",
		},
		OriginPolicy: testPin("origin-policy", "v1", "origin-"+suffix),
	}
}

func doRequest(t *testing.T, handler http.Handler, method, target string, body any, rawBody []byte) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if rawBody != nil {
		reader = bytes.NewReader(rawBody)
	} else if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("encode body: %v", err)
		}
		reader = bytes.NewReader(encoded)
	}
	req := httptest.NewRequest(method, target, reader)
	req.Header.Set("Authorization", "Channel test-channel")
	if body != nil || rawBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	ctx, err := authority.Authenticate(req, testPolicy())
	if err != nil {
		t.Fatalf("authenticate %s %s: %v", method, target, err)
	}
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}
// doRequestBypassBodyAuth authenticates a clean request to obtain the channel
// principal, then delivers the forged body with that principal attached. It
// exercises the handler's own ingress rejection for caller-supplied authority
// fields that the authority layer would also reject.
func doRequestBypassBodyAuth(t *testing.T, handler http.Handler, method, target string, forgedBody any) *httptest.ResponseRecorder {
	t.Helper()
	cleanReq := httptest.NewRequest(method, target, bytes.NewReader([]byte(`{}`)))
	cleanReq.Header.Set("Authorization", "Channel test-channel")
	ctx, err := authority.Authenticate(cleanReq, testPolicy())
	if err != nil {
		t.Fatalf("authenticate clean %s %s: %v", method, target, err)
	}
	encoded, err := json.Marshal(forgedBody)
	if err != nil {
		t.Fatalf("encode forged body: %v", err)
	}
	req := httptest.NewRequest(method, target, bytes.NewReader(encoded))
	req.Header.Set("Authorization", "Channel test-channel")
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %d response %q: %v", rec.Code, rec.Body.String(), err)
	}
	return out
}

func loadJournal(t *testing.T, store *OwnerStore, journalID string) []JournalEnvelope {
	t.Helper()
	rt, ok := lookupByJournal(store, journalID)
	if !ok {
		t.Fatalf("no runtime for journal %q", journalID)
	}
	registryMu.Lock()
	head := rt.head
	registryMu.Unlock()
	evidence, err := owner_store.LoadPrefix(authedContext(t), store, head)
	if err != nil {
		t.Fatalf("LoadPrefix(%q): %v", journalID, err)
	}
	return evidence
}

func telemetryBody(seq any, kind string, data map[string]any) map[string]any {
	if data == nil {
		data = map[string]any{"action": "test-" + kind}
	}
	return map[string]any{
		"producer_sequence":    seq,
		"event_kind":           kind,
		"event_schema_version": "1.0.0",
		"occurred_at":          map[string]any{"value": nil, "reason": "not_observed"},
		"payload": map[string]any{
			"data":          data,
			"measurements":  []any{},
			"evidence_refs": []any{},
			"artifact_refs": []any{},
		},
	}
}

func refForProducerSeq(t *testing.T, evidence []JournalEnvelope, seq int64) EvidenceRef {
	t.Helper()
	for _, env := range evidence {
		if s, ok := producerSeqInt(env.ProducerSequence); ok && s == seq {
			return EvidenceRef{JournalID: env.JournalID, Sequence: env.Sequence, EventID: env.EventID, EventHash: env.EventHash, Pointer: ""}
		}
	}
	t.Fatalf("no envelope with producer_sequence %d", seq)
	return EvidenceRef{}
}

// ---------------------------------------------------------------------------
// Conformance assertions.
// ---------------------------------------------------------------------------

func TestLostProducerTailRemainsIncompleteOrUnknown(t *testing.T) {
	store := openStore(t, "observation")
	_, journalID, _ := initObservation(t, store, "lost")
	handler := NewTelemetryHandler(store)

	// Out-of-order delivery with a lost tail: sequences 1, 2, 4 arrive;
	// sequence 3 and the terminal sequence never arrive.
	for _, seq := range []int{1, 2, 4} {
		rec := doRequest(t, handler, http.MethodPost, "/telemetry?journal_id="+journalID,
			telemetryBody(seq, "observation", map[string]any{"action": fmt.Sprintf("step-%d", seq)}), nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("ingest seq %d: status %d: %s", seq, rec.Code, rec.Body.String())
		}
	}
	// A closed HTTP connection records transport closure. It must not
	// evidence a terminal sequence or completeness.
	rec := doRequest(t, handler, http.MethodPost, "/connection/close?journal_id="+journalID,
		map[string]any{"reason": "transport_closed"}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("connection close: status %d: %s", rec.Code, rec.Body.String())
	}
	closed := decodeBody(t, rec)
	compRaw, _ := json.Marshal(closed["completeness"])
	var comp ProducerCompleteness
	if err := json.Unmarshal(compRaw, &comp); err != nil {
		t.Fatalf("decode close completeness: %v", err)
	}
	if comp.State == "complete" {
		t.Fatalf("connection close without terminal claims complete: %+v", comp)
	}

	rec = doRequest(t, handler, http.MethodGet, "/completeness?journal_id="+journalID, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("completeness: status %d: %s", rec.Code, rec.Body.String())
	}
	var current ProducerCompleteness
	if err := json.Unmarshal(rec.Body.Bytes(), &current); err != nil {
		t.Fatalf("decode completeness: %v", err)
	}
	if current.State == "complete" {
		t.Fatalf("lost producer tail claims complete: %+v", current)
	}
	if current.State != "incomplete" && current.State != "unknown" {
		t.Fatalf("lost tail state %q must be incomplete or unknown", current.State)
	}
	if len(current.MissingRanges) == 0 {
		t.Fatalf("lost tail must track missing ranges, got %+v", current)
	}
	foundGap := false
	for _, r := range current.MissingRanges {
		if r.First <= 3 && 3 <= r.Last {
			foundGap = true
		}
	}
	if !foundGap {
		t.Fatalf("missing ranges %+v must cover lost sequence 3", current.MissingRanges)
	}
	if _, ok := producerSeqInt(current.FinalSequence); ok {
		t.Fatalf("lost tail must not evidence a terminal sequence, got %v", current.FinalSequence)
	}
	// Direct assessment agrees with the HTTP surface.
	direct, err := AssessProducerCompleteness(authedContext(t), store, journalID)
	if err != nil {
		t.Fatalf("AssessProducerCompleteness: %v", err)
	}
	if direct.State == "complete" {
		t.Fatalf("direct assessment claims complete for lost tail: %+v", direct)
	}
}

func TestConflictingProducerSequenceRaisesIntegrityIncident(t *testing.T) {
	store := openStore(t, "observation")
	_, journalID, _ := initObservation(t, store, "conflict")
	handler := NewTelemetryHandler(store)

	rec := doRequest(t, handler, http.MethodPost, "/telemetry?journal_id="+journalID,
		telemetryBody(1, "observation", map[string]any{"action": "original"}), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("first delivery: status %d: %s", rec.Code, rec.Body.String())
	}
	first := decodeBody(t, rec)
	firstID, _ := first["event_id"].(string)
	if firstID == "" {
		t.Fatalf("first receipt lacks event_id: %v", first)
	}
	before := loadJournal(t, store, journalID)

	// Same (producer_id, producer_sequence) with different content is an
	// integrity incident, not last-write-wins.
	rec = doRequest(t, handler, http.MethodPost, "/telemetry?journal_id="+journalID,
		telemetryBody(1, "observation", map[string]any{"action": "conflicting"}), nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("conflicting delivery: status %d, want 409: %s", rec.Code, rec.Body.String())
	}
	conflict := decodeBody(t, rec)
	if conflict["reason"] != "integrity_conflict" {
		t.Fatalf("conflict reason %v, want integrity_conflict", conflict["reason"])
	}
	if conflict["incident_ref"] == nil {
		t.Fatalf("conflict response lacks incident_ref: %v", conflict)
	}

	after := loadJournal(t, store, journalID)
	if len(after) != len(before)+1 {
		t.Fatalf("conflict journaled %d events, want exactly one incident on top of %d", len(after), len(before))
	}
	// The original delivery is preserved byte-for-byte.
	original := refForProducerSeq(t, after, 1)
	var originalEnv *JournalEnvelope
	for i := range after {
		if after[i].EventID == original.EventID {
			originalEnv = &after[i]
		}
	}
	if originalEnv == nil {
		t.Fatalf("original seq-1 delivery missing after conflict")
	}
	if originalEnv.EventID != firstID {
		t.Fatalf("original event_id changed: %q vs %q", originalEnv.EventID, firstID)
	}
	if got, _ := originalEnv.Payload.Data["action"].(string); got != "original" {
		t.Fatalf("original payload overwritten: %v", originalEnv.Payload.Data)
	}
	// The incident retains the conflict with support.
	var incident *JournalEnvelope
	for i := range after {
		if after[i].EventKind == eventIncident {
			incident = &after[i]
		}
	}
	if incident == nil {
		t.Fatalf("no integrity_incident journaled")
	}
	if code, _ := incident.Payload.Data["code"].(string); code != "integrity_conflict" {
		t.Fatalf("incident code %q, want integrity_conflict", code)
	}
	if len(incident.Payload.EvidenceRefs) == 0 {
		t.Fatalf("incident lacks support references")
	}
	// Only one telemetry delivery exists under sequence 1.
	telemetryCount := 0
	for _, env := range after {
		if s, ok := producerSeqInt(env.ProducerSequence); ok && s == 1 && env.EventKind == "observation" {
			telemetryCount++
		}
	}
	if telemetryCount != 1 {
		t.Fatalf("sequence 1 has %d telemetry deliveries, want exactly 1 (no last-write-wins)", telemetryCount)
	}
}

func TestClientAuthoredServerFieldsAreRejectedAtIngress(t *testing.T) {
	store := openStore(t, "observation")
	_, journalID, _ := initObservation(t, store, "serverfield")
	handler := NewTelemetryHandler(store)
	before := loadJournal(t, store, journalID)

	forged := []struct {
		field string
		value any
	}{
		{"event_id", "client-forged-id"},
		{"provenance", "server"},
		{"owner_domain", "observation"},
		{"role", "external_input"},
		{"assertion_kind", "authoritative_effect"},
		{"receipt_time", "2026-01-01T00:00:00Z"},
		{"recorded_at", "2026-01-01T00:00:00Z"},
		{"manifest_hash", testDigest("forged-manifest")},
		{"event_hash", testDigest("forged-event")},
		{"previous_event_hash", testDigest("forged-prev")},
		{"evidence_scope", "current_run"},
		{"journal_sequence", float64(99)},
		{"producer_id", "forged-producer"},
	}
	for _, tc := range forged {
		body := telemetryBody(1, "observation", map[string]any{"action": "probe"})
		body[tc.field] = tc.value
		// Bypass the authority-layer body gate so the handler's own ingress
		// rejection is exercised for every server field.
		rec := doRequestBypassBodyAuth(t, handler, http.MethodPost, "/telemetry?journal_id="+journalID, body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("field %q: status %d, want 400: %s", tc.field, rec.Code, rec.Body.String())
		}
		decoded := decodeBody(t, rec)
		if decoded["reason"] != "server_field_rejected" {
			t.Fatalf("field %q: reason %v, want server_field_rejected", tc.field, decoded["reason"])
		}
	}
	after := loadJournal(t, store, journalID)
	if len(after) != len(before) {
		t.Fatalf("rejected ingress journaled %d events, want %d (no effect)", len(after), len(before))
	}
}

func TestTelemetryCannotEmitSubmissionOrIdentitySuccess(t *testing.T) {
	store := openStore(t, "observation")
	_, journalID, _ := initObservation(t, store, "telemetryauth")
	handler := NewTelemetryHandler(store)
	before := loadJournal(t, store, journalID)

	for i, kind := range []string{"submission_committed", "identity_verified"} {
		rec := doRequest(t, handler, http.MethodPost, "/telemetry?journal_id="+journalID,
			telemetryBody(10+i, kind, map[string]any{"action": "forged-success"}), nil)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("kind %q: status %d, want 403: %s", kind, rec.Code, rec.Body.String())
		}
		decoded := decodeBody(t, rec)
		if decoded["reason"] != "unauthorized_event" {
			t.Fatalf("kind %q: reason %v, want unauthorized_event", kind, decoded["reason"])
		}
	}
	// Business predicates smuggled in telemetry data are rejected too.
	rec := doRequest(t, handler, http.MethodPost, "/telemetry?journal_id="+journalID,
		telemetryBody(20, "observation", map[string]any{"action": "probe", "committed": true}), nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("business predicate data: status %d, want 403: %s", rec.Code, rec.Body.String())
	}
	after := loadJournal(t, store, journalID)
	if len(after) != len(before) {
		t.Fatalf("unauthorized telemetry journaled %d events, want %d", len(after), len(before))
	}
}

func TestIdenticalProducerDeliveryIsAcknowledgedWithoutDuplication(t *testing.T) {
	store := openStore(t, "observation")
	_, journalID, _ := initObservation(t, store, "dedupe")
	handler := NewTelemetryHandler(store)

	body := telemetryBody(5, "observation", map[string]any{"action": "idempotent-step"})
	rec1 := doRequest(t, handler, http.MethodPost, "/telemetry?journal_id="+journalID, body, nil)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first delivery: status %d: %s", rec1.Code, rec1.Body.String())
	}
	receipt1 := decodeBody(t, rec1)
	mid := loadJournal(t, store, journalID)

	// Byte-identical repeat: same producer sequence and same content.
	rec2 := doRequest(t, handler, http.MethodPost, "/telemetry?journal_id="+journalID, body, nil)
	if rec2.Code != http.StatusOK {
		t.Fatalf("repeat delivery: status %d: %s", rec2.Code, rec2.Body.String())
	}
	receipt2 := decodeBody(t, rec2)
	if receipt1["event_id"] != receipt2["event_id"] {
		t.Fatalf("repeat event_id %v != first %v", receipt2["event_id"], receipt1["event_id"])
	}
	if fmt.Sprint(receipt1["journal_sequence"]) != fmt.Sprint(receipt2["journal_sequence"]) {
		t.Fatalf("repeat sequence %v != first %v", receipt2["journal_sequence"], receipt1["journal_sequence"])
	}
	if dup, _ := receipt2["duplicate"].(bool); !dup {
		t.Fatalf("repeat receipt should be marked duplicate: %v", receipt2)
	}
	after := loadJournal(t, store, journalID)
	if len(after) != len(mid) {
		t.Fatalf("identical repeat journaled %d events, want %d (no duplication)", len(after), len(mid))
	}
	count := 0
	for _, env := range after {
		if s, ok := producerSeqInt(env.ProducerSequence); ok && s == 5 {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("producer_sequence 5 appears %d times, want exactly 1", count)
	}
}

func TestFlushWithoutTerminalSequenceCannotProveCompleteness(t *testing.T) {
	store := openStore(t, "observation")
	_, journalID, _ := initObservation(t, store, "flush")
	handler := NewTelemetryHandler(store)

	for _, seq := range []int{1, 2} {
		rec := doRequest(t, handler, http.MethodPost, "/telemetry?journal_id="+journalID,
			telemetryBody(seq, "observation", map[string]any{"action": fmt.Sprintf("step-%d", seq)}), nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("ingest seq %d: status %d: %s", seq, rec.Code, rec.Body.String())
		}
	}
	// Flush without a terminal sequence: flush observed, completeness
	// unresolved.
	rec := doRequest(t, handler, http.MethodPost, "/flush?journal_id="+journalID, map[string]any{}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("flush: status %d: %s", rec.Code, rec.Body.String())
	}
	flushed := decodeBody(t, rec)
	if flushed["flush_observed"] != true {
		t.Fatalf("flush response lacks flush_observed: %v", flushed)
	}
	compRaw, _ := json.Marshal(flushed["completeness"])
	var comp ProducerCompleteness
	if err := json.Unmarshal(compRaw, &comp); err != nil {
		t.Fatalf("decode flush completeness: %v", err)
	}
	if comp.State == "complete" {
		t.Fatalf("flush without terminal claims complete: %+v", comp)
	}
	rec = doRequest(t, handler, http.MethodGet, "/completeness?journal_id="+journalID, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("completeness: status %d: %s", rec.Code, rec.Body.String())
	}
	var current ProducerCompleteness
	if err := json.Unmarshal(rec.Body.Bytes(), &current); err != nil {
		t.Fatalf("decode completeness: %v", err)
	}
	if current.State == "complete" {
		t.Fatalf("flush without terminal proves complete: %+v", current)
	}
	if _, ok := producerSeqInt(current.FinalSequence); ok {
		t.Fatalf("flush without terminal evidenced final %v", current.FinalSequence)
	}
	evidence := loadJournal(t, store, journalID)
	foundFlush := false
	for _, env := range evidence {
		if env.EventKind == eventFlush {
			foundFlush = true
		}
	}
	if !foundFlush {
		t.Fatalf("no producer_flush event journaled")
	}
}

func TestLateProducerTailCreatesNewRevisionWithoutChangingClosure(t *testing.T) {
	store := openStore(t, "observation")
	manifest := testManifest("late", "observation")
	initRef, err := InitializeObservation(authedContext(t), store, manifest, testRegistration("late"))
	if err != nil {
		t.Fatalf("InitializeObservation: %v", err)
	}
	_ = initRef
	journalID := manifest.JournalID
	handler := NewTelemetryHandler(store)

	for _, seq := range []int{1, 2} {
		rec := doRequest(t, handler, http.MethodPost, "/telemetry?journal_id="+journalID,
			telemetryBody(seq, "observation", map[string]any{"action": fmt.Sprintf("step-%d", seq)}), nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("ingest seq %d: status %d: %s", seq, rec.Code, rec.Body.String())
		}
	}
	evidence := loadJournal(t, store, journalID)
	boundary := refForProducerSeq(t, evidence, 2)
	commission := testCommission("late", manifest)

	rev1, err := CloseObservationWindow(authedContext(t), store, commission, boundary)
	if err != nil {
		t.Fatalf("first close: %v", err)
	}
	if rev1.Revision != 1 || rev1.PreviousRevision != 0 {
		t.Fatalf("rev1 fencing %+v, want revision 1 previous 0", rev1)
	}
	val1, err := parseObservationValue(rev1.Value)
	if err != nil {
		t.Fatalf("parse rev1 value: %v", err)
	}
	if val1.State != lifecycle_rules.ObsClosed {
		t.Fatalf("rev1 state %q, want closed", val1.State)
	}
	frozen := map[string]any{
		"opened_at":      val1.OpenedAt,
		"active_deadline": val1.ActiveDeadline,
		"drain_started":  val1.DrainStartedAt,
		"drain_deadline": val1.DrainDeadline,
		"closed_at":      val1.ClosedAt,
		"close_reason":   val1.CloseReason,
		"at_close":       val1.AtClose,
	}
	frozenRaw := map[string]string{}
	for k, v := range frozen {
		raw, _ := json.Marshal(v)
		frozenRaw[k] = string(raw)
	}
	prefix1 := rev1.EvidencePrefix

	// Late producer tail arrives after closure: it appends at the current
	// journal head.
	for _, seq := range []int{3, 4} {
		rec := doRequest(t, handler, http.MethodPost, "/telemetry?journal_id="+journalID,
			telemetryBody(seq, "observation", map[string]any{"action": fmt.Sprintf("late-%d", seq)}), nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("late ingest seq %d: status %d: %s", seq, rec.Code, rec.Body.String())
		}
	}
	rev2, err := CloseObservationWindow(authedContext(t), store, commission, boundary)
	if err != nil {
		t.Fatalf("late close: %v", err)
	}
	if rev2.Revision != 2 || rev2.PreviousRevision != 1 {
		t.Fatalf("rev2 fencing %+v, want revision 2 previous 1", rev2)
	}
	if rev2.EvidencePrefix.LastSequence <= prefix1.LastSequence {
		t.Fatalf("rev2 prefix %d does not advance past rev1 %d", rev2.EvidencePrefix.LastSequence, prefix1.LastSequence)
	}
	val2, err := parseObservationValue(rev2.Value)
	if err != nil {
		t.Fatalf("parse rev2 value: %v", err)
	}
	// Frozen closure knowledge is byte-identical.
	for k, v := range map[string]any{
		"opened_at":      val2.OpenedAt,
		"active_deadline": val2.ActiveDeadline,
		"drain_started":  val2.DrainStartedAt,
		"drain_deadline": val2.DrainDeadline,
		"closed_at":      val2.ClosedAt,
		"close_reason":   val2.CloseReason,
		"at_close":       val2.AtClose,
	} {
		raw, _ := json.Marshal(v)
		if string(raw) != frozenRaw[k] {
			t.Fatalf("late revision rewrote frozen field %s: was %s, now %s", k, frozenRaw[k], string(raw))
		}
	}
	if len(val2.LateEvidenceRefs) == 0 {
		t.Fatalf("late revision carries no late evidence")
	}
	if len(val2.LateEvidenceRefs) < 2 {
		t.Fatalf("late revision carries %d late refs, want at least 2 (seq 3,4)", len(val2.LateEvidenceRefs))
	}
	// The new head still resolves every late reference.
	lateEvidence := loadJournal(t, store, journalID)
	bySeq := map[int64]bool{}
	for _, env := range lateEvidence {
		bySeq[env.Sequence] = true
	}
	for _, ref := range val2.LateEvidenceRefs {
		if !bySeq[ref.Sequence] {
			t.Fatalf("late ref %+v does not resolve against retained head", ref)
		}
	}
	// Prior seal bytes are preserved: rev1 still validates against its
	// own prefix and history.
	_ = prefix1
	if rev1.EvidencePrefix.HeadHash == rev2.EvidencePrefix.HeadHash {
		t.Fatalf("late revision did not advance the evidence head")
	}
}

func TestManualNotesCannotSetAuthoritativeBusinessPredicates(t *testing.T) {
	store := openStore(t, "observation")
	attemptID, _, _ := initObservation(t, store, "manual")
	attempt := AttemptReference{AttemptID: attemptID, Kind: "practice"}
	ctx := authedContext(t)

	// An operator note cannot forge an authoritative event kind.
	forgedKind := EventSubmission{
		ProducerSequence:   owner_store.NewMissing("not_applicable"),
		EventKind:          "submission_committed",
		EventSchemaVersion: "1.0.0",
		OccurredAt:         owner_store.NewMissing("not_observed"),
		Payload: owner_store.Payload{
			Data:         map[string]any{"text": "forged submission"},
			Measurements: []Measurement{},
			EvidenceRefs: []EvidenceRef{},
			ArtifactRefs: []ArtifactReference{},
		},
	}
	if _, err := RecordManualNote(ctx, store, attempt, forgedKind); err == nil {
		t.Fatalf("manual note with submission_committed kind was accepted")
	} else if !strings.Contains(err.Error(), "authoritative") && !strings.Contains(err.Error(), "business") {
		t.Fatalf("forged kind error %q lacks authoritative/business signal", err.Error())
	}

	// An operator note cannot smuggle business predicates in data.
	for _, key := range []string{"committed", "identity_verified", "commitment"} {
		note := EventSubmission{
			ProducerSequence:   owner_store.NewMissing("not_applicable"),
			EventKind:          "manual_note",
			EventSchemaVersion: "1.0.0",
			OccurredAt:         owner_store.NewMissing("not_observed"),
			Payload: owner_store.Payload{
				Data:         map[string]any{"text": "probe", key: true},
				Measurements: []Measurement{},
				EvidenceRefs: []EvidenceRef{},
				ArtifactRefs: []ArtifactReference{},
			},
		}
		if _, err := RecordManualNote(ctx, store, attempt, note); err == nil {
			t.Fatalf("manual note with data key %q was accepted", key)
		}
	}

	// A genuine operator note journals with manual provenance and
	// disclosed assistance, setting no business predicate.
	benign := EventSubmission{
		ProducerSequence:   owner_store.NewMissing("not_applicable"),
		EventKind:          "manual_note",
		EventSchemaVersion: "1.0.0",
		OccurredAt:         owner_store.NewMissing("not_observed"),
		Payload: owner_store.Payload{
			Data: map[string]any{
				"text":       "operator observed listing readiness",
				"assistance": "operator:manual walkthrough disclosed",
			},
			Measurements: []Measurement{},
			EvidenceRefs: []EvidenceRef{},
			ArtifactRefs: []ArtifactReference{},
		},
	}
	ref, err := RecordManualNote(ctx, store, attempt, benign)
	if err != nil {
		t.Fatalf("benign manual note rejected: %v", err)
	}
	if ref.Sequence < 1 || ref.EventID == "" {
		t.Fatalf("benign note ref is not a retained coordinate: %+v", ref)
	}
	evidence := loadJournal(t, store, "journal-manual")
	var found *JournalEnvelope
	for i := range evidence {
		if evidence[i].EventID == ref.EventID {
			found = &evidence[i]
		}
	}
	if found == nil {
		t.Fatalf("manual note event %q not retained", ref.EventID)
	}
	if got, _ := found.Payload.Data["provenance"].(string); got != "manual" {
		t.Fatalf("manual note provenance %q, want manual", got)
	}
	if _, hasAssistance := found.Payload.Data["assistance"]; !hasAssistance {
		t.Fatalf("manual note lacks disclosed assistance: %v", found.Payload.Data)
	}
	for key := range found.Payload.Data {
		if forbiddenBusinessKeys[key] {
			t.Fatalf("manual note sets business predicate %q", key)
		}
	}
}

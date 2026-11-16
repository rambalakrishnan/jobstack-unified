package session_runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"admission"
	"application_owner"
	"authority"
	"evidence_codec"
	"journal_rules"
	"lifecycle_rules"
	"observation_owner"
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
	req, err := http.NewRequest(http.MethodPost, "http://session-runtime.test/direct", nil)
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

func testDigest(seed string) string {
	return string(evidence_codec.HashBytes([]byte("session-runtime-test/" + seed)))
}

type storePaths struct {
	db     string
	root   string
	domain string
}

type fixtureOptions struct {
	Mode               string
	ActiveLimitMs      float64
	DrainLimitMs       float64
	CancelWaitLimitMs  float64
	CleanupWaitLimitMs float64
	Capacity           int
	ControlReserve     int
	ConnectApplication bool
	ConnectObservation bool
}

type testFixture struct {
	t    *testing.T
	ctx  context.Context
	home string

	primaryPaths     storePaths
	applicationPaths storePaths
	observationPaths storePaths

	primary     *OwnerStore
	application *OwnerStore
	observation *OwnerStore

	server *httptest.Server
	calls  *int32

	commission AttemptCommission
	sessionID  string
	journalID  string
	mode       string

	appRef EvidenceRef
	obsRef EvidenceRef

	runtime *Runtime
}

func openStoreAt(t *testing.T, paths storePaths) *OwnerStore {
	t.Helper()
	store, err := owner_store.OpenOwner(paths.db, paths.root, paths.domain)
	if err != nil {
		t.Fatalf("OpenOwner(%s): %v", paths.domain, err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func newTestFixture(t *testing.T, opts fixtureOptions) *testFixture {
	t.Helper()
	if opts.Mode == "" {
		opts.Mode = "manual"
	}
	f := &testFixture{t: t, ctx: authedContext(t), home: t.TempDir()}
	f.sessionID = "attempt-1"
	f.journalID = "journal-1"
	f.mode = opts.Mode
	f.primaryPaths = storePaths{
		db: filepath.Join(f.home, "diagnostic.db"), root: filepath.Join(f.home, "diagnostic-artifacts"),
		domain: "diagnostic",
	}
	f.applicationPaths = storePaths{
		db: filepath.Join(f.home, "application.db"), root: filepath.Join(f.home, "application-artifacts"),
		domain: "application",
	}
	f.observationPaths = storePaths{
		db: filepath.Join(f.home, "observation.db"), root: filepath.Join(f.home, "observation-artifacts"),
		domain: "observation",
	}
	f.primary = openStoreAt(t, f.primaryPaths)
	f.application = openStoreAt(t, f.applicationPaths)
	f.observation = openStoreAt(t, f.observationPaths)

	f.bootstrapSessionJournal()
	f.commission = buildLifecycleCommission(t, f, opts)

	if opts.ConnectApplication {
		f.connectApplication()
	}
	if opts.ConnectObservation {
		f.connectObservation()
	}

	var calls int32
	f.calls = &calls
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(f.calls, 1)
		var req struct {
			RequestID   string `json:"request_id"`
			ConnectorID string `json:"connector_id"`
			Operation   string `json:"operation"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		result := map[string]any{}
		switch req.Operation {
		case "Start":
			result = map[string]any{"kind": "start_receipt", "native_run_id": "native-1"}
		case "RequestNativeCancel", "CloseObservationConnection", "ReleaseNativeContext", "Contain":
			result = map[string]any{
				"kind": "control_receipt",
				"observation": map[string]any{
					"operation": req.Operation, "disposition": "requested",
					"native_termination": "unknown",
				},
			}
		default:
			result = map[string]any{"kind": "observation_page", "cursor": "c1"}
		}
		response := map[string]any{
			"record_type": "connector_response", "schema_version": "external-connector/0.1.0",
			"request_id": req.RequestID, "connector_id": req.ConnectorID,
			"operation": req.Operation, "result": result,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	t.Cleanup(f.server.Close)

	runtime, err := NewRuntime(f.ctx, f.primary, f.application, f.observation, Options{
		ConnectorEndpoint: f.endpoint(),
		Limits:            QueueLimits{Capacity: opts.Capacity, ControlReserve: opts.ControlReserve},
		CallLimitMs:       2000,
	})
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	f.runtime = runtime
	if err := runtime.OpenSession(f.ctx, SessionSpec{
		Commission: f.commission, ConnectorEndpoint: f.endpoint(),
	}); err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	return f
}

func (f *testFixture) endpoint() string { return f.server.URL + "/connector" }

// bootstrapSessionJournal admits a minimal session journal in the primary
// store, exactly as the admission owner does (manifest at sequence 1, then
// the session admission marker).
func (f *testFixture) bootstrapSessionJournal() {
	f.t.Helper()
	manifest := journal_rules.Manifest{
		RecordType: "manifest", SchemaVersion: "0.1.0",
		ManifestID: "manifest-" + f.journalID, RunID: f.sessionID,
		JournalID: f.journalID, OwnerDomain: f.primaryPaths.domain,
		Clocks: []journal_rules.ClockDescriptor{{
			ClockID: "clock-" + f.journalID, BootID: "boot-" + f.journalID,
			Origin: "engine_measured", SourceID: "admission",
			Basis: "monotonic_offset", Unit: "ms",
		}},
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		f.t.Fatalf("marshal session manifest: %v", err)
	}
	canonical, err := evidence_codec.CanonicalJSON(raw, "application/json")
	if err != nil {
		f.t.Fatalf("canonicalize session manifest: %v", err)
	}
	ref, err := owner_store.InstallArtifact(f.ctx, f.primary, bytesReader(canonical), "application/json", "public")
	if err != nil {
		f.t.Fatalf("install session manifest: %v", err)
	}
	admissionEvent := EventSubmission{
		ProducerSequence:   owner_store.NewMissing("not_applicable"),
		EventKind:          "manifest_admitted",
		EventSchemaVersion: "0.1.0",
		OccurredAt:         owner_store.NewMissing("not_applicable"),
		Payload: owner_store.Payload{
			Data:         map[string]any{"manifest": artifactRefMap(ref)},
			Measurements: []Measurement{},
			EvidenceRefs: []EvidenceRef{}, ArtifactRefs: []ArtifactReference{ref},
		},
	}
	sessionEvent := EventSubmission{
		ProducerSequence:   owner_store.NewMissing("not_applicable"),
		EventKind:          "session_admitted",
		EventSchemaVersion: "1.0.0",
		OccurredAt:         owner_store.NewMissing("not_observed"),
		Payload: owner_store.Payload{
			Data: map[string]any{
				"session_id": f.sessionID, "attempt_id": f.sessionID,
				"journal_id": f.journalID, "mode": f.mode,
			},
			Measurements: []Measurement{},
			EvidenceRefs: []EvidenceRef{}, ArtifactRefs: []ArtifactReference{},
		},
	}
	if _, err := owner_store.CommitOwner(f.ctx, f.primary, f.journalID, []EventSubmission{admissionEvent, sessionEvent}, nil); err != nil {
		f.t.Fatalf("admit session journal: %v", err)
	}
}

// connectApplication initializes the application owner and records the
// primary-local initialization receipt.
func (f *testFixture) connectApplication() {
	f.t.Helper()
	manifest := application_owner.Manifest{
		RecordType: "manifest", SchemaVersion: "1.0.0",
		ManifestID: "manifest-" + f.journalID, RunID: f.sessionID,
		JournalID: f.journalID, OwnerDomain: f.applicationPaths.domain,
		CommissionerID: "test-writer", Activity: "application_attempt",
		Execution:        map[string]any{"mode": f.mode},
		Task:             map[string]any{"task_id": "task-" + f.sessionID},
		TaskSemanticHash: testDigest("task-semantic"),
		Environment:      map[string]any{"deployment": "laboratory"},
		Seed:             "seed-1",
		BuildPins:        map[string]string{"fixture": "1.0.0"},
		EventRegistry:    map[string]string{"kind1": "v1"},
		Producers:        []map[string]any{{"producer_id": "p1"}},
		Clocks: []map[string]any{{
			"clock_id": "clock-" + f.journalID, "boot_id": "boot-" + f.journalID,
			"origin": "engine_measured", "source_id": "application",
			"basis": "monotonic_offset", "unit": "ms",
		}},
		Profile: "M1",
	}
	manifest.Attempt.Kind = "practice"
	manifest.Attempt.Context = "laboratory_fixture"
	manifest.Attempt.Scope = "held_in"
	manifest.Attempt.Assistance = "none"
	manifest.Lineage.Kind = "practice"
	registration := application_owner.EntityRegistration{
		RecordType: "write_domain_entity", SchemaVersion: "0.1.0",
		RegistrationID: "registration-application-" + f.sessionID,
		Entity: map[string]any{
			"entity_type": "hellscape_session", "session_id": f.sessionID,
		},
		Identity: map[string]any{
			"run_id": f.sessionID, "journal_id": f.journalID,
			"attempt": map[string]any{"kind": "practice"},
		},
		Owners: map[string]any{
			"application": map[string]any{"role": "origin", "owner_domain": "application"},
		},
		Configuration: application_owner.DefaultFixtureConfiguration(),
	}
	ref, err := application_owner.InitializeApplication(f.ctx, f.application, manifest, registration)
	if err != nil {
		f.t.Fatalf("InitializeApplication: %v", err)
	}
	f.appRef = ref
	f.recordReceipt("application_init_receipt", "application_initialized", ref)
}

// connectObservation initializes the observation owner and records the
// primary-local initialization receipt.
func (f *testFixture) connectObservation() {
	f.t.Helper()
	manifest := journal_rules.Manifest{
		RecordType: "manifest", SchemaVersion: "0.1.0",
		ManifestID: "manifest-" + f.journalID, RunID: f.sessionID,
		JournalID: f.journalID, OwnerDomain: f.observationPaths.domain,
		Clocks: []journal_rules.ClockDescriptor{{
			ClockID: "clock-" + f.journalID, BootID: "boot-" + f.journalID,
			Origin: "engine_measured", SourceID: "observation",
			Basis: "monotonic_offset", Unit: "ms",
		}},
	}
	registration := observation_owner.EntityRegistration{
		RecordType: "write_domain_entity", SchemaVersion: "0.1.0",
		RegistrationID: "registration-observation-" + f.sessionID,
		Entity: map[string]any{
			"entity_type": "hellscape_session", "entity_id": f.sessionID,
			"session_id": f.sessionID,
		},
		Identity: map[string]any{"run_id": f.sessionID, "journal_id": f.journalID},
		Owners: map[string]any{
			"observation": map[string]any{"role": "connector", "source_id": "connector-1", "writer_id": "observation-writer"},
		},
		EvidenceRefs: []observation_owner.EvidenceRef{},
	}
	ref, err := observation_owner.InitializeObservation(f.ctx, f.observation, manifest, registration)
	if err != nil {
		f.t.Fatalf("InitializeObservation: %v", err)
	}
	f.obsRef = ref
	f.recordReceipt("observation_init_receipt", "observation_opened", ref)
}

// recordReceipt writes one primary-local owner initialization receipt.
func (f *testFixture) recordReceipt(kind, receiptKind string, ref EvidenceRef) {
	f.t.Helper()
	_, err := owner_store.CommitOwner(f.ctx, f.primary, f.journalID, []EventSubmission{{
		ProducerSequence:   owner_store.NewMissing("not_applicable"),
		EventKind:          kind,
		EventSchemaVersion: "1.0.0",
		OccurredAt:         owner_store.NewMissing("not_observed"),
		Payload: owner_store.Payload{
			Data: map[string]any{
				"session_id": f.sessionID, "attempt_id": f.sessionID,
				"receipt_journal": ref.JournalID, "receipt_sequence": ref.Sequence,
				"receipt_event": ref.EventID, "receipt_hash": ref.EventHash,
				"receipt_kind": receiptKind, "initialization_receipt": true,
			},
			Measurements: []Measurement{},
			EvidenceRefs: []EvidenceRef{}, ArtifactRefs: []ArtifactReference{},
		},
	}}, nil)
	if err != nil {
		f.t.Fatalf("record receipt %s: %v", kind, err)
	}
}

func lifecyclePin(seed string) lifecycle_rules.VersionPin {
	return lifecycle_rules.VersionPin{ID: seed, Version: "1.0", ArtifactDigest: testDigest(seed)}
}

func lifecycleArtifact(seed, owner, access string) lifecycle_rules.ArtifactReference {
	return lifecycle_rules.ArtifactReference{
		Digest: testDigest(seed), SizeBytes: 128,
		MediaType: "application/json", OwnerDomain: owner, Access: access,
	}
}

func buildLifecycleCommission(t *testing.T, f *testFixture, opts fixtureOptions) AttemptCommission {
	t.Helper()
	active := opts.ActiveLimitMs
	if active <= 0 {
		active = 60_000
	}
	drain := opts.DrainLimitMs
	if drain <= 0 {
		drain = 10_000
	}
	cancelWait := opts.CancelWaitLimitMs
	if cancelWait <= 0 {
		cancelWait = 5_000
	}
	cleanup := opts.CleanupWaitLimitMs
	if cleanup <= 0 {
		cleanup = 5_000
	}
	target := "origin-" + f.sessionID
	execution := lifecycle_rules.ExecutionDescriptor{Mode: f.mode}
	if f.mode == "manual" {
		execution.Subject = lifecycle_rules.NewMissing("not_applicable")
		execution.ConnectorVersion = lifecycle_rules.NewMissing("not_applicable")
		execution.BindingVersion = lifecycle_rules.NewMissing("not_applicable")
	} else {
		execution.Subject = lifecycle_rules.NewMissing("not_applicable")
		execution.ConnectorVersion = "connector-1.0"
		execution.BindingVersion = "binding-1.0"
	}
	execution.Assistance = lifecycle_rules.AssistanceRecord{
		PlanningOwner: "operator", AssistanceTrack: "manual",
		PlannerIdentity:  lifecycle_rules.NewMissing("not_applicable"),
		Plan:             lifecycle_rules.NewMissing("not_observed"),
		OnlineReplanning: false, Description: "session runtime test",
	}
	return AttemptCommission{
		RecordType:    "attempt_commission",
		SchemaVersion: lifecycle_rules.SchemaLifecycle,
		KernelVersion: lifecycle_rules.SchemaKernel,
		CommissionID:  "commission-" + f.sessionID,
		RunID:         f.sessionID, JournalID: f.journalID,
		ManifestHash: testDigest("manifest-" + f.journalID),
		AdmissionRef: EvidenceRef{
			JournalID: f.journalID, Sequence: 1,
			EventID: "evt-admission", EventHash: testDigest("admission"),
		},
		CommissionedBy: "test-writer",
		CommissionedAt: TimePoint{
			ClockID: "clock-" + f.journalID, BootID: "boot-" + f.journalID,
			Origin: "engine_measured", MonotonicOffsetMs: 10,
			UTCAnnotation: owner_store.NewMissing("not_applicable"),
		},
		Attempt: lifecycle_rules.AttemptContext{
			AttemptID: f.sessionID, Kind: "practice",
			TargetClass: "laboratory_fixture", TargetID: target,
			EvaluationPartition: "held_in",
			RehearsalOf:         []lifecycle_rules.AttemptReference{},
			PerformanceOf:       []lifecycle_rules.AttemptReference{},
			DerivedFrom:         []lifecycle_rules.AttemptReference{},
		},
		CandidateID:      "candidate-" + f.sessionID,
		CandidateProfile: lifecycle_rules.NewMissing("not_observed"),
		Job: lifecycle_rules.JobReference{
			JobID:        "job-1",
			SourceTarget: lifecycle_rules.NewMissing("not_observed"),
			SourceJobID:  lifecycle_rules.NewMissing("not_observed"),
			Snapshot:     lifecycleArtifact("job-snapshot", "origin-domain", "restricted"),
		},
		SelectionEvidence: lifecycle_rules.NewMissing("not_observed"),
		Task:              lifecycleArtifact("task", "origin-domain", "restricted"),
		TaskSemanticHash:  testDigest("task-semantic"),
		InitialMaterials:  []lifecycle_rules.ArtifactReference{},
		Execution:         execution,
		Owners: lifecycle_rules.OwnerBindings{
			Dispatch: lifecycle_rules.AuthorityBinding{
				Role: "connector", SourceID: "connector-1", WriterID: "dispatch-writer",
				OwnerDomain: "dispatch", PublicationPolicy: lifecyclePin("pub-dispatch"),
			},
			Observation: lifecycle_rules.AuthorityBinding{
				Role: "connector", SourceID: "connector-1", WriterID: "observation-writer",
				OwnerDomain: "observation", PublicationPolicy: lifecyclePin("pub-observation"),
			},
			Execution: lifecycle_rules.AuthorityBinding{
				Role: "subject", SourceID: lifecycle_rules.NewMissing("not_applicable"),
				WriterID:    lifecycle_rules.NewMissing("not_applicable"),
				OwnerDomain: "execution", PublicationPolicy: lifecyclePin("pub-execution"),
			},
			Application: lifecycle_rules.AuthorityBinding{
				Role: "origin", SourceID: target, WriterID: "application-writer",
				OwnerDomain: "application", PublicationPolicy: lifecyclePin("pub-application"),
			},
			Report: lifecycle_rules.AuthorityBinding{
				Role: "reconciler", SourceID: "reconciler-1", WriterID: "report-writer",
				OwnerDomain: "report", PublicationPolicy: lifecyclePin("pub-report"),
			},
		},
		IdempotencyKey:     "idem-" + f.sessionID,
		AuthorizationRefs:  []EvidenceRef{{JournalID: f.journalID, Sequence: 1, EventID: "evt-auth", EventHash: testDigest("auth")}},
		RecoveryReviewRefs: []EvidenceRef{},
		ObservationPolicy: lifecycle_rules.ObservationPolicy{
			ActiveLimit:           lifecycle_rules.DurationLimit{Kind: "exact", Unit: "ms", Value: active},
			DrainLimit:            lifecycle_rules.DurationLimit{Kind: "exact", Unit: "ms", Value: drain},
			NativeCancelWaitLimit: lifecycle_rules.DurationLimit{Kind: "exact", Unit: "ms", Value: cancelWait},
			CleanupWaitLimit:      lifecycle_rules.DurationLimit{Kind: "exact", Unit: "ms", Value: cleanup},
			FixtureCloseAction:    "seal_after_drain",
		},
		OriginPolicy: lifecyclePin("origin-policy"),
	}
}

// eventsOfKind filters the runtime journal for one event kind.
func eventsOfKind(events []JournalEnvelope, kind string) []JournalEnvelope {
	var out []JournalEnvelope
	for i := range events {
		if events[i].EventKind == kind {
			out = append(out, events[i])
		}
	}
	return out
}

func lastEventOfKind(t *testing.T, events []JournalEnvelope, kind string) JournalEnvelope {
	t.Helper()
	found := eventsOfKind(events, kind)
	if len(found) == 0 {
		t.Fatalf("no %q event recorded", kind)
	}
	return found[len(found)-1]
}

func missingReason(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal missing value: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode missing value: %v", err)
	}
	if decoded["value"] != nil {
		t.Fatalf("expected a typed Missing envelope, got %v", decoded)
	}
	reason, _ := decoded["reason"].(string)
	return reason
}

// reopenPrimary simulates a process restart of the runtime's primary store:
// the store is closed and reopened, which advances the durable lease-authority
// epoch and registers a new boot.
func (f *testFixture) reopenPrimary() *OwnerStore {
	f.t.Helper()
	if err := f.primary.Close(); err != nil {
		f.t.Fatalf("close primary store: %v", err)
	}
	f.primary = openStoreAt(f.t, f.primaryPaths)
	return f.primary
}

// ---------------------------------------------------------------------------
// 1. Crash around native delivery recovers dispatch uncertain.
// ---------------------------------------------------------------------------

func TestCrashAroundNativeDeliveryRecoversDispatchUncertain(t *testing.T) {
	f := newTestFixture(t, fixtureOptions{})
	if err := f.runtime.Accept(f.ctx, WorkItem{SessionID: f.sessionID, Kind: WorkflowWork, Operation: "Start"}); err != nil {
		t.Fatalf("Accept: %v", err)
	}
	commandID, requestID, err := f.runtime.PrepareDispatch(f.ctx, f.sessionID, "Start")
	if err != nil {
		t.Fatalf("PrepareDispatch: %v", err)
	}
	if got := atomic.LoadInt32(f.calls); got != 0 {
		t.Fatalf("connector calls before crash = %d, want 0", got)
	}

	// Crash: the store is reopened under a new authority epoch and a new
	// runtime boot recovers the durable journal.
	primary := f.reopenPrimary()
	restarted, err := NewRuntime(f.ctx, primary, f.application, f.observation, Options{ConnectorEndpoint: f.endpoint()})
	if err != nil {
		t.Fatalf("NewRuntime after restart: %v", err)
	}
	if err := restarted.Recover(f.ctx); err != nil {
		t.Fatalf("Recover: %v", err)
	}

	events := restarted.Events()
	uncertain := eventsOfKind(events, eventDispatchUncertain)
	if len(uncertain) != 1 {
		t.Fatalf("dispatch_uncertain events = %d, want 1", len(uncertain))
	}
	data := uncertain[0].Payload.Data
	if got := asString(data["command_id"]); got != commandID {
		t.Fatalf("uncertain command = %q, want %q", got, commandID)
	}
	if got := asString(data["request_id"]); got != requestID {
		t.Fatalf("uncertain request = %q, want %q", got, requestID)
	}
	if got := asString(data["native_state"]); got != "unknown" {
		t.Fatalf("native_state = %q, want unknown", got)
	}
	if got := asString(data["resend"]); got != "forbidden" {
		t.Fatalf("resend = %q, want forbidden", got)
	}
	if len(eventsOfKind(events, eventDispatchRecorded)) != 0 {
		t.Fatalf("a delivery outcome was fabricated after the crash")
	}
	if got := atomic.LoadInt32(f.calls); got != 0 {
		t.Fatalf("connector calls during recovery = %d, want 0 (no automatic resend)", got)
	}
	snapshot, ok := restarted.Snapshot(f.sessionID)
	if !ok {
		t.Fatalf("session state missing after recovery")
	}
	if snapshot.PendingDispatch != "" {
		t.Fatalf("pending dispatch = %q, want cleared", snapshot.PendingDispatch)
	}
	if snapshot.LastDispatchState != "uncertain" {
		t.Fatalf("last dispatch state = %q, want uncertain", snapshot.LastDispatchState)
	}
}

// ---------------------------------------------------------------------------
// 2. Restart fences the observation epoch without assuming a native stop.
// ---------------------------------------------------------------------------

func TestRestartFencesObservationEpochWithoutAssumingNativeStop(t *testing.T) {
	f := newTestFixture(t, fixtureOptions{ConnectApplication: true, ConnectObservation: true})
	oldEvents := f.runtime.Events()
	var oldBoot string
	for _, env := range eventsOfKind(oldEvents, eventClockRegistered) {
		oldBoot = asString(env.Payload.Data["boot_id"])
	}
	if oldBoot == "" {
		t.Fatalf("first boot registered no clock")
	}
	snapshotBefore, _ := f.runtime.Snapshot(f.sessionID)
	if snapshotBefore.BootID != oldBoot {
		t.Fatalf("session boot = %q, want %q", snapshotBefore.BootID, oldBoot)
	}

	primary := f.reopenPrimary()
	restarted, err := NewRuntime(f.ctx, primary, f.application, f.observation, Options{ConnectorEndpoint: f.endpoint()})
	if err != nil {
		t.Fatalf("NewRuntime after restart: %v", err)
	}
	if err := restarted.Recover(f.ctx); err != nil {
		t.Fatalf("Recover: %v", err)
	}

	events := restarted.Events()
	var newBoot string
	clockEvents := eventsOfKind(events, eventClockRegistered)
	if len(clockEvents) < 2 {
		t.Fatalf("clock_registered events = %d, want at least 2 (one per boot)", len(clockEvents))
	}
	newBoot = asString(clockEvents[len(clockEvents)-1].Payload.Data["boot_id"])
	if newBoot == oldBoot {
		t.Fatalf("restart reused the old boot identity %q", oldBoot)
	}

	fences := eventsOfKind(events, eventObservationFenced)
	if len(fences) != 1 {
		t.Fatalf("observation_epoch_fenced events = %d, want 1", len(fences))
	}
	fence := fences[0].Payload.Data
	if got := asString(fence["previous_boot"]); got != oldBoot {
		t.Fatalf("fenced previous_boot = %q, want %q", got, oldBoot)
	}
	if got := asString(fence["serving_boot"]); got != newBoot {
		t.Fatalf("fenced serving_boot = %q, want %q", got, newBoot)
	}
	if got := asString(fence["native_termination_claimed"]); got == "" {
		// booleans decode from typed data directly; ensure the claim is false.
		if b, ok := fence["native_termination_claimed"].(bool); !ok || b {
			t.Fatalf("native termination was claimed by the fence: %v", fence["native_termination_claimed"])
		}
	}
	if b, ok := fence["native_termination_claimed"].(bool); !ok || b {
		t.Fatalf("fence asserts native termination: %v", fence["native_termination_claimed"])
	}
	if got := missingReason(t, fence["native_stop"]); got != "not_observed" {
		t.Fatalf("native_stop missing reason = %q, want not_observed", got)
	}
	if got := asString(fence["observation_completeness"]); got != "unknown" {
		t.Fatalf("fenced completeness = %q, want unknown", got)
	}
	if got := asInt64(fence["new_lease_epoch"]); got <= asInt64(fence["previous_lease_epoch"]) {
		t.Fatalf("lease epoch was not fenced: new=%d previous=%d", got, asInt64(fence["previous_lease_epoch"]))
	}
	if got := asBool(fence["previous_lease_fenced"]); !got {
		t.Fatalf("previous lease was not reported fenced")
	}
	interrupted := eventsOfKind(events, eventSessionInterrupted)
	if len(interrupted) != 1 {
		t.Fatalf("session_interrupted events = %d, want 1", len(interrupted))
	}
	if got := asString(interrupted[0].Payload.Data["reason"]); got != string(CloseInfrastructureInterruption) {
		t.Fatalf("interruption reason = %q", got)
	}
	if got := atomic.LoadInt32(f.calls); got != 0 {
		t.Fatalf("connector calls during restart recovery = %d, want 0", got)
	}
	for _, env := range events {
		if env.EventKind == eventDispatchRecorded || env.EventKind == eventDispatchUncertain {
			t.Fatalf("recovery fabricated a dispatch outcome in %q", env.EventKind)
		}
	}
}

// ---------------------------------------------------------------------------
// 3. Local closure completes despite an unavailable origin seal.
// ---------------------------------------------------------------------------

func TestLocalClosureCompletesDespiteUnavailableOriginSeal(t *testing.T) {
	f := newTestFixture(t, fixtureOptions{ConnectApplication: true, ConnectObservation: true})
	if err := f.application.Close(); err != nil {
		t.Fatalf("close application store: %v", err)
	}

	doc, err := f.runtime.Finalize(f.ctx, f.commission, CloseOperatorStop)
	if err != nil {
		t.Fatalf("FinalizeSession: %v", err)
	}
	if doc.DiagnosticID != "diagnostic-"+f.sessionID || doc.AnalysisRevision != 1 {
		t.Fatalf("unexpected diagnostic identity: %q revision %d", doc.DiagnosticID, doc.AnalysisRevision)
	}
	events := f.runtime.Events()
	seal := lastEventOfKind(t, events, eventOriginSealRecorded)
	if got := asString(seal.Payload.Data["state"]); got != "unavailable" {
		t.Fatalf("origin seal state = %q, want unavailable", got)
	}
	if b, ok := seal.Payload.Data["final_absence_claimed"].(bool); !ok || b {
		t.Fatalf("unavailable origin seal manufactured a final-absence claim")
	}
	closed := lastEventOfKind(t, events, eventObservationClosed)
	if got := asString(closed.Payload.Data["state"]); got != "closed" {
		t.Fatalf("observation close state = %q, want closed (local closure must complete)", got)
	}
	if got := asInt64(closed.Payload.Data["revision"]); got < 1 {
		t.Fatalf("observation revision = %d, want at least 1", got)
	}
	frozen := lastEventOfKind(t, events, eventKnowledgeFrozen)
	if got := asString(frozen.Payload.Data["application_state"]); got != "unavailable" {
		t.Fatalf("frozen application state = %q, want unavailable", got)
	}
	finalized := lastEventOfKind(t, events, eventFinalizationRecorded)
	if got := asString(finalized.Payload.Data["outcome"]); got != "finalized" {
		t.Fatalf("finalization outcome = %q, want finalized", got)
	}
	if b, ok := finalized.Payload.Data["observation_reopened"].(bool); !ok || b {
		t.Fatalf("finalization claims observation was reopened")
	}
	snapshot, _ := f.runtime.Snapshot(f.sessionID)
	if snapshot.Phase != phaseFinalized {
		t.Fatalf("session phase = %q, want finalized", snapshot.Phase)
	}
}

// ---------------------------------------------------------------------------
// 4. Close and control progress survives task queue pressure.
// ---------------------------------------------------------------------------

func TestCloseAndControlProgressSurvivesTaskQueuePressure(t *testing.T) {
	f := newTestFixture(t, fixtureOptions{
		ConnectApplication: true, ConnectObservation: true,
		Capacity: 4, ControlReserve: 2,
	})
	for i := range 2 {
		if err := f.runtime.Accept(f.ctx, WorkItem{
			SessionID: f.sessionID, Kind: WorkflowWork, Operation: "Start",
			RequestID: fmt.Sprintf("work-%d", i),
		}); err != nil {
			t.Fatalf("accept workflow %d: %v", i, err)
		}
	}
	// The general region is exhausted: another workflow item must be
	// rejected while the control reserve stays available.
	err := f.runtime.Accept(f.ctx, WorkItem{SessionID: f.sessionID, Kind: WorkflowWork, Operation: "Start"})
	if !errors.Is(err, ErrQueueFull) {
		t.Fatalf("third workflow accepted under pressure: %v", err)
	}
	rejections := eventsOfKind(f.runtime.Events(), eventWorkRejected)
	if len(rejections) != 1 {
		t.Fatalf("durable work_rejected events = %d, want 1", len(rejections))
	}
	if got := asString(rejections[0].Payload.Data["reason"]); got != "queue_full" {
		t.Fatalf("rejection reason = %q, want queue_full", got)
	}

	// Control and close work still make progress.
	if err := f.runtime.Accept(f.ctx, WorkItem{
		SessionID: f.sessionID, Kind: ControlWork, Operation: "RequestNativeCancel",
	}); err != nil {
		t.Fatalf("accept control under pressure: %v", err)
	}
	if err := f.runtime.Accept(f.ctx, WorkItem{
		SessionID: f.sessionID, Kind: CloseWork, Reason: CloseOperatorStop,
	}); err != nil {
		t.Fatalf("accept close under pressure: %v", err)
	}

	// Step the loop: close is served before control and before workflow.
	for i := range 2 {
		more, err := f.runtime.Step(f.ctx)
		if err != nil {
			t.Fatalf("Step %d: %v", i, err)
		}
		if !more {
			t.Fatalf("Step %d: no item available, expected close and control items", i)
		}
		snapshot, _ := f.runtime.Snapshot(f.sessionID)
		if i == 0 && snapshot.Phase != phaseFinalized {
			t.Fatalf("close was not served first: phase %q", snapshot.Phase)
		}
	}
	if depth := f.runtime.queue.depth(); depth != 0 {
		t.Fatalf("queued items after close+control = %d, want 0 (closed work is rejected, not served)", depth)
	}
	if got := atomic.LoadInt32(f.calls); got != 0 {
		t.Fatalf("connector calls = %d, want 0: no workflow delivery may begin after the close boundary", got)
	}
	events := f.runtime.Events()
	if len(eventsOfKind(events, eventDispatchIntent)) != 0 {
		t.Fatalf("a workflow dispatch intent was issued under close pressure")
	}
	afterClose := 0
	for _, env := range eventsOfKind(events, eventWorkRejected) {
		if asString(env.Payload.Data["reason"]) == "no_delivery_after_close" ||
			asString(env.Payload.Data["reason"]) == "close_requested" {
			afterClose++
		}
	}
	if afterClose == 0 {
		t.Fatalf("queued workflow work was silently discarded instead of recorded as rejected")
	}
	if len(eventsOfKind(events, eventFinalizationRecorded)) != 1 {
		t.Fatalf("close did not finalize exactly once")
	}
}

// ---------------------------------------------------------------------------
// 5. Accepted queued work consumes its active observation budget.
// ---------------------------------------------------------------------------

func TestAcceptedQueuedWorkConsumesActiveObservationBudget(t *testing.T) {
	f := newTestFixture(t, fixtureOptions{ActiveLimitMs: 40})
	if err := f.runtime.Accept(f.ctx, WorkItem{
		SessionID: f.sessionID, Kind: WorkflowWork, Operation: "Start",
	}); err != nil {
		t.Fatalf("Accept: %v", err)
	}
	accepted := lastEventOfKind(t, f.runtime.Events(), eventWorkAccepted)
	if got := asFloat(accepted.Payload.Data["active_budget_ms"]); got != 40 {
		t.Fatalf("accepted active budget = %v, want 40", got)
	}
	deadline := asFloat(accepted.Payload.Data["deadline_offset_ms"])
	if deadline <= 0 {
		t.Fatalf("accepted deadline offset = %v, want a scheduled deadline", deadline)
	}

	// The item waits in the queue beyond its active budget.
	time.Sleep(90 * time.Millisecond)
	more, err := f.runtime.Step(f.ctx)
	if err != nil {
		t.Fatalf("Step: %v", err)
	}
	if !more {
		t.Fatalf("expected one queued item")
	}
	if got := atomic.LoadInt32(f.calls); got != 0 {
		t.Fatalf("connector calls = %d, want 0: budget-exhausted work must not be delivered", got)
	}
	if len(eventsOfKind(f.runtime.Events(), eventDispatchIntent)) != 0 {
		t.Fatalf("budget-exhausted work produced a dispatch intent")
	}
	rejected := lastEventOfKind(t, f.runtime.Events(), eventWorkRejected)
	if got := asString(rejected.Payload.Data["reason"]); got != "active_budget_exhausted" {
		t.Fatalf("rejection reason = %q, want active_budget_exhausted", got)
	}
	if got := asFloat(rejected.Payload.Data["observed_offset_ms"]); got <= deadline {
		t.Fatalf("observed offset %v does not exceed the deadline %v", got, deadline)
	}
}

// ---------------------------------------------------------------------------
// 6. Late callback appends without reopening observation.
// ---------------------------------------------------------------------------

func TestLateCallbackAppendsWithoutReopeningObservation(t *testing.T) {
	f := newTestFixture(t, fixtureOptions{ConnectApplication: true, ConnectObservation: true})
	doc1, err := f.runtime.Finalize(f.ctx, f.commission, CloseNormalCompletion)
	if err != nil {
		t.Fatalf("first FinalizeSession: %v", err)
	}
	eventsAfterClose := f.runtime.Events()
	closedEvents := eventsOfKind(eventsAfterClose, eventObservationClosed)
	if len(closedEvents) != 1 || asString(closedEvents[0].Payload.Data["state"]) != "closed" {
		t.Fatalf("first close did not record a closed observation revision")
	}
	closureDigest := asString(closedEvents[0].Payload.Data["closure_snapshot_digest"])
	if closureDigest == "" {
		t.Fatalf("first close did not freeze a closure snapshot digest")
	}
	publicationsBefore := eventsOfKind(eventsAfterClose, eventPublicationRecorded)
	var priorPublishedDigest string
	for _, env := range publicationsBefore {
		if asString(env.Payload.Data["state"]) == "published" {
			priorPublishedDigest = asString(env.Payload.Data["document_digest"])
		}
	}

	lateRef, err := f.runtime.RecordLateEvidence(f.ctx, f.sessionID, "late_callback", "origin committed after close")
	if err != nil {
		t.Fatalf("RecordLateEvidence: %v", err)
	}
	if lateRef.JournalID != f.obsRef.JournalID {
		t.Fatalf("late evidence journal = %q, want observation journal %q", lateRef.JournalID, f.obsRef.JournalID)
	}
	if lateRef.Sequence <= f.obsRef.Sequence {
		t.Fatalf("late evidence appended at sequence %d, not beyond the close boundary %d", lateRef.Sequence, f.obsRef.Sequence)
	}

	doc2, err := f.runtime.Finalize(f.ctx, f.commission, CloseNormalCompletion)
	if err != nil {
		t.Fatalf("second FinalizeSession: %v", err)
	}
	if doc2.AnalysisRevision != 2 {
		t.Fatalf("late diagnostic revision = %d, want 2", doc2.AnalysisRevision)
	}
	if doc2.AnalysisRequestRef.Sequence <= doc1.AnalysisRequestRef.Sequence {
		t.Fatalf("late analysis request did not advance: %d -> %d", doc1.AnalysisRequestRef.Sequence, doc2.AnalysisRequestRef.Sequence)
	}
	if doc2.InputPrefix.LastSequence <= doc1.InputPrefix.LastSequence {
		t.Fatalf("late input prefix did not advance: %d -> %d", doc1.InputPrefix.LastSequence, doc2.InputPrefix.LastSequence)
	}
	if digest1, _ := canonicalDigest(doc1); digest1 == mustDigest(t, doc2) {
		t.Fatalf("late analysis produced identical document bytes")
	}

	events := f.runtime.Events()
	if got := len(eventsOfKind(events, eventObservationClosed)); got != 1 {
		t.Fatalf("observation_close_recorded events = %d, want 1: observation must not be reopened", got)
	}
	if asString(lastEventOfKind(t, events, eventObservationClosed).Payload.Data["closure_snapshot_digest"]) != closureDigest {
		t.Fatalf("the original closure snapshot was not preserved")
	}
	for _, env := range events {
		if b, ok := env.Payload.Data["observation_reopened"].(bool); ok && b {
			t.Fatalf("event %q reopened observation", env.EventKind)
		}
	}
	late := lastEventOfKind(t, events, eventLateEvidenceRecorded)
	if b, ok := late.Payload.Data["workflow_commands_resumed"].(bool); !ok || b {
		t.Fatalf("late evidence resumed workflow commands")
	}
	finalized := lastEventOfKind(t, events, eventLateEvidenceFinalized)
	if b, ok := finalized.Payload.Data["late_evidence"].(bool); !ok || !b {
		t.Fatalf("late finalization did not record the late-evidence revision")
	}
	if got := asInt64(finalized.Payload.Data["observation_revision"]); got != 1 {
		t.Fatalf("late finalization changed the observation revision to %d", got)
	}
	publicationsAfter := eventsOfKind(events, eventPublicationRecorded)
	if len(publicationsAfter) != 2 {
		t.Fatalf("publication records = %d, want one per diagnostic revision", len(publicationsAfter))
	}
	for i, env := range publicationsAfter {
		data := env.Payload.Data
		if got := asInt64(data["analysis_revision"]); got != int64(i+1) {
			t.Fatalf("publication record %d covers analysis revision %d, want %d", i, got, i+1)
		}
		switch asString(data["state"]) {
		case "published":
			if got := asInt64(data["revision"]); got != int64(i+1) {
				t.Fatalf("publication revision %d, want %d", got, i+1)
			}
			if i > 0 {
				if got := asInt64(data["supersedes_revision"]); got != int64(i) {
					t.Fatalf("publication supersedes revision = %d, want %d", got, i)
				}
			}
		case "unavailable":
			// The failure matrix permits an independent publication failure:
			// the committed source and any prior read view stay as they were,
			// and no report was fabricated.
			if b, ok := data["source_committed"].(bool); !ok || !b {
				t.Fatalf("failed publication did not preserve the committed source")
			}
			if b, ok := data["read_view_advanced"].(bool); ok && b {
				t.Fatalf("failed publication advanced the read view")
			}
			if asString(data["detail"]) == "" {
				t.Fatalf("failed publication recorded no typed detail")
			}
		default:
			t.Fatalf("publication record %d has unknown state %q", i, asString(data["state"]))
		}
	}
	// Every retained diagnostic artifact stays readable: a publication
	// outcome never mutates or deletes the derived bytes.
	for _, env := range eventsOfKind(events, eventDiagnosticRecorded) {
		ref := ArtifactReference{
			Digest:      asString(env.Payload.Data["document_digest"]),
			SizeBytes:   asInt64(env.Payload.Data["document_size_bytes"]),
			MediaType:   asString(env.Payload.Data["document_media_type"]),
			OwnerDomain: asString(env.Payload.Data["document_owner_domain"]),
			Access:      asString(env.Payload.Data["document_access"]),
		}
		if ref.Digest == "" || ref.SizeBytes == 0 {
			t.Fatalf("diagnostic record did not retain its document artifact reference")
		}
		bytes, err := owner_store.ReadArtifact(f.ctx, f.primary, ref)
		if err != nil {
			t.Fatalf("retained diagnostic bytes are not readable: %v", err)
		}
		if string(evidence_codec.HashBytes(bytes)) != ref.Digest {
			t.Fatalf("retained diagnostic bytes changed")
		}
	}
	for _, env := range publicationsBefore {
		if asString(env.Payload.Data["state"]) != "published" {
			continue
		}
		ref := ArtifactReference{
			Digest:      asString(env.Payload.Data["document_digest"]),
			SizeBytes:   asInt64(env.Payload.Data["document_size_bytes"]),
			MediaType:   asString(env.Payload.Data["document_media_type"]),
			OwnerDomain: asString(env.Payload.Data["document_owner_domain"]),
			Access:      asString(env.Payload.Data["document_access"]),
		}
		if priorPublishedDigest != "" && ref.Digest != priorPublishedDigest {
			t.Fatalf("prior publication digest changed after late evidence")
		}
		if _, err := owner_store.ReadArtifact(f.ctx, f.primary, ref); err != nil {
			t.Fatalf("prior published bytes are no longer readable: %v", err)
		}
	}
}

func mustDigest(t *testing.T, doc DiagnosticDocument) string {
	t.Helper()
	digest, err := canonicalDigest(doc)
	if err != nil {
		t.Fatalf("digest diagnostic: %v", err)
	}
	return digest
}

// ---------------------------------------------------------------------------
// 7. Every durably admitted session finalizes or records interruption.
// ---------------------------------------------------------------------------

func TestEveryDurablyAdmittedSessionFinalizesOrRecordsInterruption(t *testing.T) {
	for _, tc := range []struct {
		name         string
		suffix       string
		subject      bool
		wantFinalize bool
	}{
		{name: "finalizes", suffix: "ok", subject: false, wantFinalize: true},
		{name: "records interruption", suffix: "broken", subject: true, wantFinalize: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := authedContext(t)
			home := t.TempDir()
			primary := openStoreAt(t, storePaths{
				db: filepath.Join(home, "diagnostic.db"), root: filepath.Join(home, "diagnostic-artifacts"),
				domain: "diagnostic",
			})
			application := openStoreAt(t, storePaths{
				db: filepath.Join(home, "application.db"), root: filepath.Join(home, "application-artifacts"),
				domain: "application",
			})
			observation := openStoreAt(t, storePaths{
				db: filepath.Join(home, "observation.db"), root: filepath.Join(home, "observation-artifacts"),
				domain: "observation",
			})

			manifest := admissionManifest(tc.suffix, "")
			commission := admissionCommission(t, tc.suffix, manifest, "manual")
			registration := admissionRegistration(tc.suffix, manifest)
			if _, err := admission.AdmitSession(ctx, primary, manifest, commission, []admission.EntityRegistration{registration}); err != nil {
				t.Fatalf("AdmitSession: %v", err)
			}

			mode := "manual"
			subject := any(lifecycle_rules.NewMissing("not_applicable"))
			if tc.subject {
				// The commissioning claim says subject mode, but no subject
				// identity was commissioned: analysis cannot fabricate scope.
				mode = "subject"
				subject = lifecycle_rules.NewMissing("not_applicable")
			}
			fixture := &testFixture{
				t: t, ctx: ctx, sessionID: manifest.RunID, journalID: manifest.JournalID, mode: mode,
			}
			fixture.commission = buildLifecycleCommission(t, fixture, fixtureOptions{Mode: mode})
			fixture.commission.Execution.Subject = subject

			runtime, err := NewRuntime(ctx, primary, application, observation, Options{})
			if err != nil {
				t.Fatalf("NewRuntime: %v", err)
			}
			if err := runtime.OpenSession(ctx, SessionSpec{Commission: fixture.commission}); err != nil {
				t.Fatalf("OpenSession: %v", err)
			}

			doc, finalizeErr := runtime.Finalize(ctx, fixture.commission, CloseNormalCompletion)
			events := runtime.Events()
			interrupted := eventsOfKind(events, eventSessionInterrupted)
			finalized := eventsOfKind(events, eventFinalizationRecorded)
			if tc.wantFinalize {
				if finalizeErr != nil {
					t.Fatalf("FinalizeSession: %v", finalizeErr)
				}
				if doc.AnalysisRevision != 1 || doc.DiagnosticID == "" {
					t.Fatalf("unexpected diagnostic document: %+v", doc)
				}
				if len(finalized) != 1 {
					t.Fatalf("finalization_recorded events = %d, want 1", len(finalized))
				}
				snapshot, _ := runtime.Snapshot(fixture.sessionID)
				if snapshot.Phase != phaseFinalized {
					t.Fatalf("session phase = %q, want finalized", snapshot.Phase)
				}
			} else {
				if finalizeErr == nil {
					t.Fatalf("subject-mode session without a commissioned subject unexpectedly finalized")
				}
				if len(interrupted) != 1 {
					t.Fatalf("session_interrupted events = %d, want 1 durable interruption", len(interrupted))
				}
				if b, ok := interrupted[0].Payload.Data["diagnostic_pending"].(bool); !ok || !b {
					t.Fatalf("interruption did not record the pending diagnostic")
				}
				if len(finalized) != 0 {
					t.Fatalf("interrupted session fabricated a finalized record")
				}
				snapshot, _ := runtime.Snapshot(fixture.sessionID)
				if snapshot.Phase != phaseInterrupted && snapshot.Phase != phaseClosing {
					t.Fatalf("session phase = %q, want interrupted/recorded", snapshot.Phase)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 8. An unpersisted observation tail is never called complete.
// ---------------------------------------------------------------------------

func TestUnpersistedObservationTailIsNeverCalledComplete(t *testing.T) {
	f := newTestFixture(t, fixtureOptions{ConnectApplication: true, ConnectObservation: true})
	if err := f.observation.Close(); err != nil {
		t.Fatalf("close observation store: %v", err)
	}
	doc, err := f.runtime.Finalize(f.ctx, f.commission, CloseLocalDeadline)
	if err != nil {
		t.Fatalf("FinalizeSession: %v", err)
	}
	if doc.DiagnosticID == "" {
		t.Fatalf("local closure produced no diagnostic over retained source evidence")
	}
	events := f.runtime.Events()
	drain := lastEventOfKind(t, events, eventDrainRecorded)
	if got := asString(drain.Payload.Data["state"]); got != drainUnavailable {
		t.Fatalf("drain state = %q, want unavailable", got)
	}
	close := lastEventOfKind(t, events, eventObservationClosed)
	if got := asString(close.Payload.Data["state"]); got == "closed" {
		t.Fatalf("an unavailable observation store was called closed")
	}
	frozen := lastEventOfKind(t, events, eventKnowledgeFrozen)
	if got := asString(frozen.Payload.Data["observation_completeness"]); got == "complete" {
		t.Fatalf("unpersisted observation tail was called complete")
	}
	if got := asString(frozen.Payload.Data["observation_completeness"]); got != "unknown" {
		t.Fatalf("frozen completeness = %q, want unknown", got)
	}
	finalized := lastEventOfKind(t, events, eventFinalizationRecorded)
	if got := asString(finalized.Payload.Data["observation_completeness"]); got == "complete" {
		t.Fatalf("finalization called the unavailable observation tail complete")
	}

	// Persistence failure after the fact: the runtime cannot append, so it
	// reports a storage failure instead of fabricating a completion event.
	if err := f.primary.Close(); err != nil {
		t.Fatalf("close primary store: %v", err)
	}
	_, err = FinalizeSession(f.ctx, f.primary, f.application, f.observation, f.commission, CloseLocalDeadline)
	if err == nil {
		t.Fatalf("FinalizeSession with a closed primary store unexpectedly succeeded")
	}
	if !errors.Is(err, ErrStorageUnavailable) {
		t.Fatalf("storage failure was mislabelled: %v", err)
	}
	if strings.Contains(strings.ToLower(err.Error()), "complete") {
		t.Fatalf("storage failure asserted completeness: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Admission-owner fixtures (durable admission, minimal fixture manifest).
// ---------------------------------------------------------------------------

func admissionManifest(suffix, subjectVersion string) admission.Manifest {
	m := admission.Manifest{
		RecordType: "manifest", SchemaVersion: "1.0.0",
		ManifestID: "manifest-" + suffix, RunID: "attempt-" + suffix,
		JournalID: "journal-" + suffix, OwnerDomain: "diagnostic",
		CommissionerID: "test-writer", Activity: "application_attempt",
		Execution:        map[string]any{"mode": "manual"},
		Task:             map[string]any{"task_id": "task-" + suffix},
		TaskSemanticHash: testDigest("task-sem-" + suffix),
		Environment:      map[string]any{"deployment": "laboratory"},
		Seed:             "seed-" + suffix,
		BuildPins:        map[string]string{"fixture": "1.0.0"},
		EventRegistry:    map[string]string{"kind1": "v1"},
		Producers:        []map[string]any{{"producer_id": "p1"}},
		Clocks: []map[string]any{{
			"clock_id": "clock-journal-" + suffix, "boot_id": "boot-journal-" + suffix,
			"origin": "engine_measured", "source_id": "admission",
			"basis": "monotonic_offset", "unit": "ms",
		}},
		Profile: "M1",
	}
	m.Attempt.Kind = "practice"
	m.Attempt.Context = "laboratory_fixture"
	m.Attempt.Scope = "held_in"
	m.Attempt.Assistance = "none"
	m.Lineage.Kind = "practice"
	return m
}

func admissionArtifact(seed, owner, access string) admission.ArtifactReference {
	return admission.ArtifactReference{
		Digest: testDigest(seed), SizeBytes: 64,
		MediaType: "application/json", OwnerDomain: owner, Access: access,
	}
}

func admissionPin(id string) admission.VersionPin {
	return admission.VersionPin{ID: id, Version: "1.0", ArtifactDigest: testDigest(id)}
}

func admissionCommission(t *testing.T, suffix string, manifest admission.Manifest, mode string) admission.AttemptCommission {
	t.Helper()
	manifestHash, err := admission.PrimaryManifestDigest(manifest)
	if err != nil {
		t.Fatalf("PrimaryManifestDigest: %v", err)
	}
	execution := admission.ExecutionDescriptor{Mode: mode}
	execution.Subject = admission.NewMissing("not_applicable")
	execution.ConnectorVersion = admission.NewMissing("not_applicable")
	execution.BindingVersion = admission.NewMissing("not_applicable")
	execution.Assistance = admission.AssistanceRecord{
		PlanningOwner: "operator", AssistanceTrack: "manual",
		PlannerIdentity: admission.NewMissing("not_applicable"),
		Plan:            admission.NewMissing("not_observed"),
		Description:     "session runtime conformance",
	}
	target := "target-" + suffix
	return admission.AttemptCommission{
		RecordType:    "attempt_commission",
		SchemaVersion: "application-attempt-lifecycle/0.1.0",
		KernelVersion: "evidence-kernel/0.1.0",
		CommissionID:  "commission-" + suffix,
		RunID:         manifest.RunID, JournalID: manifest.JournalID,
		ManifestHash: manifestHash,
		AdmissionRef: admission.EvidenceRef{
			JournalID: manifest.JournalID, Sequence: 1,
			EventID: "evt-admission", EventHash: testDigest("admission-" + suffix),
		},
		CommissionedBy: "test-writer",
		CommissionedAt: admission.TimePoint{
			ClockID: "clock-journal-" + suffix, BootID: "boot-journal-" + suffix,
			Origin: "engine_measured", MonotonicOffsetMs: 0,
			UTCAnnotation: admission.NewMissing("not_applicable"),
		},
		Attempt: admission.AttemptContext{
			AttemptID: manifest.RunID, Kind: "practice",
			TargetClass: "laboratory_fixture", TargetID: target,
			EvaluationPartition: "held_in",
			RehearsalOf:         []admission.AttemptReference{},
			PerformanceOf:       []admission.AttemptReference{},
			DerivedFrom:         []admission.AttemptReference{},
		},
		CandidateID:      "candidate-" + suffix,
		CandidateProfile: admission.NewMissing("not_observed"),
		Job: admission.JobReference{
			JobID:        "job-" + suffix,
			SourceTarget: admission.NewMissing("not_observed"),
			SourceJobID:  admission.NewMissing("not_observed"),
			Snapshot:     admissionArtifact("job-snap-"+suffix, "origin-domain", "restricted"),
		},
		SelectionEvidence: admission.NewMissing("not_observed"),
		Task:              admissionArtifact("task-"+suffix, "origin-domain", "restricted"),
		TaskSemanticHash:  testDigest("task-sem-comm-" + suffix),
		InitialMaterials:  []admission.ArtifactReference{},
		Execution:         execution,
		Owners: admission.OwnerBindings{
			Dispatch: admission.AuthorityBinding{
				Role: "connector", SourceID: "dispatch-source", WriterID: "dispatch-writer",
				OwnerDomain: "dispatch", PublicationPolicy: admissionPin("pub-dispatch"),
			},
			Observation: admission.AuthorityBinding{
				Role: "connector", SourceID: "obs-source", WriterID: "obs-writer",
				OwnerDomain: "observation", PublicationPolicy: admissionPin("pub-observation"),
			},
			Execution: admission.AuthorityBinding{
				Role: "subject", SourceID: admission.NewMissing("not_applicable"),
				WriterID:    admission.NewMissing("not_applicable"),
				OwnerDomain: "execution", PublicationPolicy: admissionPin("pub-execution"),
			},
			Application: admission.AuthorityBinding{
				Role: "origin", SourceID: target, WriterID: "app-writer",
				OwnerDomain: "application", PublicationPolicy: admissionPin("pub-application"),
			},
			Report: admission.AuthorityBinding{
				Role: "reconciler", SourceID: "report-source", WriterID: "report-writer",
				OwnerDomain: "report", PublicationPolicy: admissionPin("pub-report"),
			},
		},
		IdempotencyKey:     "idem-" + suffix,
		AuthorizationRefs:  []admission.EvidenceRef{{JournalID: manifest.JournalID, Sequence: 1, EventID: "evt-auth", EventHash: testDigest("auth-" + suffix)}},
		RecoveryReviewRefs: []admission.EvidenceRef{},
		ObservationPolicy: admission.ObservationPolicy{
			ActiveLimit:           admission.DurationLimit{Kind: "exact", Unit: "ms", Value: 60000},
			DrainLimit:            admission.DurationLimit{Kind: "exact", Unit: "ms", Value: 10000},
			NativeCancelWaitLimit: admission.DurationLimit{Kind: "exact", Unit: "ms", Value: 5000},
			CleanupWaitLimit:      admission.DurationLimit{Kind: "exact", Unit: "ms", Value: 5000},
			FixtureCloseAction:    "seal_after_drain",
		},
		OriginPolicy: admissionPin("origin-" + suffix),
	}
}

func admissionRegistration(suffix string, manifest admission.Manifest) admission.EntityRegistration {
	target := "target-" + suffix
	policy := func(seed string) map[string]any {
		return map[string]any{"id": "pub", "version": "1.0", "artifact_digest": testDigest(seed)}
	}
	return admission.EntityRegistration{
		RecordType: "write_domain_entity", SchemaVersion: "0.1.0",
		RegistrationID: "registration-" + suffix,
		Entity: map[string]any{
			"entity_type": "hellscape_session", "entity_id": "session-" + suffix,
			"session_id": manifest.RunID,
		},
		Identity: map[string]any{
			"run_id": manifest.RunID, "journal_id": manifest.JournalID,
			"attempt": map[string]any{
				"kind": "practice", "target_class": "laboratory_fixture",
				"evaluation_partition": "held_in",
			},
		},
		Owners: map[string]any{
			"application": map[string]any{"role": "origin", "source_id": target, "writer_id": "app-writer-" + suffix, "owner_domain": "application", "publication_policy": policy("pub-app-" + suffix)},
			"observation": map[string]any{"role": "observer", "source_id": "obs-source-" + suffix, "writer_id": "obs-writer-" + suffix, "owner_domain": "observation", "publication_policy": policy("pub-obs-" + suffix)},
			"diagnostic":  map[string]any{"role": "analyzer", "source_id": "diag-source-" + suffix, "writer_id": "diag-writer-" + suffix, "owner_domain": "diagnostic", "publication_policy": policy("pub-diag-" + suffix)},
		},
		EvidencePrefix: admission.JournalPrefix{},
		EvidenceRefs:   []admission.EvidenceRef{},
		Configuration:  append([]byte(nil), application_owner.DefaultFixtureConfiguration()...),
	}
}

// journal_rules is referenced so the fixture types stay pinned to the exact
// shared kernels the module consumes.
var _ = journal_rules.Manifest{}

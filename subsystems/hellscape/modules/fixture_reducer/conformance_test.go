package fixture_reducer

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

const testDigestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const testUploadDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func testManifest() Manifest {
	return Manifest{
		RecordType:     "manifest",
		SchemaVersion:  "1.0.0",
		ManifestID:     "m1",
		RunID:          "r1",
		JournalID:      "j1",
		OwnerDomain:    "laboratory",
		CommissionerID: "commissioner-1",
		Activity:       "application_attempt",
		Attempt: struct {
			Kind           string `json:"kind,omitempty"`
			Context        string `json:"context,omitempty"`
			Scope          string `json:"scope,omitempty"`
			SubjectVersion string `json:"subject_version,omitempty"`
			Assistance     string `json:"assistance,omitempty"`
		}{
			Kind:           "practice",
			Context:        "laboratory_fixture",
			Scope:          "held_in",
			SubjectVersion: "subject-1.0",
			Assistance:     "none",
		},
		Execution:        map[string]any{"mode": "manual"},
		Task:             map[string]any{"task_id": "task-1"},
		TaskSemanticHash: testDigestA,
		Environment:      map[string]any{"deployment": "laboratory"},
		Seed:             "seed-1",
		BuildPins:        map[string]string{"fixture": "1.0.0"},
		EventRegistry:    map[string]string{"kind1": "v1"},
		Producers:        []map[string]any{{"producer_id": "p1"}},
		Clocks:           []map[string]any{{"clock_id": "c1"}},
		Profile:          "M1",
		Subject: struct {
			Name    string `json:"name,omitempty"`
			Version string `json:"version,omitempty"`
		}{Name: "subject-A", Version: "subject-1.0"},
		Lineage: struct {
			Kind          string   `json:"kind,omitempty"`
			DerivedFrom   []string `json:"derived_from,omitempty"`
			RehearsalOf   string   `json:"rehearsal_of,omitempty"`
			PerformanceOf string   `json:"performance_of,omitempty"`
		}{Kind: "practice"},
	}
}

func testConfig(t *testing.T) []byte {
	t.Helper()
	cfg := map[string]any{
		"profile": "M1",
		"features": []any{
			map[string]any{"name": "cooperative-form", "recipe": "primitive:cooperative-form/1.0"},
		},
		"task": map[string]any{
			"kind":                           "completion",
			"required_controls":              []any{"contact-name"},
			"hidden_controls":                []any{},
			"human_path":                     true,
			"required_verifiers":             []any{"v1"},
			"permanently_rejected_verifiers": []any{},
			"requires_recovery":              false,
			"recovery_paths":                 []any{"retry"},
			"required_browser_capabilities":  []any{},
			"available_browser_capabilities": []any{"dom"},
		},
		"budgets": map[string]any{
			"task_ms":             60000.0,
			"required_ms":         5000.0,
			"artificial_delay_ms": 100.0,
		},
		"identity_epoch":      "epoch-1",
		"known_jobs":          []any{"job-1", "job-2"},
		"review_dependencies": []any{"contact", "history"},
		"upload_max_bytes":    float64(5 * 1024 * 1024),
	}
	out, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("cannot encode config: %v", err)
	}
	return out
}

func mustInit(t *testing.T) (Manifest, []byte, []byte) {
	t.Helper()
	m := testManifest()
	c := testConfig(t)
	s, err := InitialFixtureState(m, c)
	if err != nil {
		t.Fatalf("InitialFixtureState failed: %v", err)
	}
	st := decodeState(t, s)
	if st.WorkflowState != StateListing || st.StateRevision != 0 || st.MutationAuthority != AuthorityOpen {
		t.Fatalf("initial state = %s rev %d authority %s, want LISTING rev 0 open",
			st.WorkflowState, st.StateRevision, st.MutationAuthority)
	}
	return m, c, s
}

func decodeState(t *testing.T, s []byte) fixtureState {
	t.Helper()
	var st fixtureState
	if err := json.Unmarshal(s, &st); err != nil {
		t.Fatalf("cannot decode state: %v", err)
	}
	return st
}

func decodeResponse(t *testing.T, r []byte) reducerResponse {
	t.Helper()
	var resp reducerResponse
	if err := json.Unmarshal(r, &resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}
	return resp
}

func intPtr(i int) *int { return &i }

func payload(t *testing.T, obj map[string]any) json.RawMessage {
	t.Helper()
	out, err := json.Marshal(obj)
	if err != nil {
		t.Fatalf("cannot encode payload: %v", err)
	}
	return json.RawMessage(out)
}

func contactPayload(t *testing.T, name string) json.RawMessage {
	t.Helper()
	return payload(t, map[string]any{"full_name": name, "email": "candidate@example.test"})
}

func historyPayload(t *testing.T, start, end string) json.RawMessage {
	t.Helper()
	return payload(t, map[string]any{"start_date": start, "end_date": end, "employer": "Example Co"})
}

func uploadPayload(t *testing.T) json.RawMessage {
	t.Helper()
	return payload(t, map[string]any{
		"filename":     "resume.pdf",
		"content_type": "application/pdf",
		"size_bytes":   float64(1024),
		"digest":       testUploadDigest,
	})
}

func identityPayload(t *testing.T) json.RawMessage {
	t.Helper()
	return payload(t, map[string]any{"epoch": "epoch-1", "receipt": "receipt-1", "attempt_id": "r1"})
}

func reviewPayload(t *testing.T, cRev, cGen, hRev, hGen int) json.RawMessage {
	t.Helper()
	return payload(t, map[string]any{
		"contact_value_revision": float64(cRev),
		"contact_generation":     float64(cGen),
		"history_value_revision": float64(hRev),
		"history_generation":     float64(hGen),
	})
}

func jobCmd(key string, rev int, jobID string, t *testing.T) EventSubmission {
	return EventSubmission{
		OperationKey: key, OperationKind: OpJobSelection, AttemptID: "r1",
		ExpectedRevision: rev, Payload: payload(t, map[string]any{"job_id": jobID}),
	}
}

func contactCmd(key string, rev, cRev, cGen int, p json.RawMessage) EventSubmission {
	return EventSubmission{
		OperationKey: key, OperationKind: OpContact, AttemptID: "r1",
		ExpectedRevision: rev, Section: "contact",
		SectionValueRevision: intPtr(cRev), SectionValueRevisionApplicable: true,
		ValidationGeneration: intPtr(cGen), ValidationGenerationApplicable: true,
		Payload: p,
	}
}

func enterCmd(key string, rev int) EventSubmission {
	return EventSubmission{
		OperationKey: key, OperationKind: OpHistoryEnter, AttemptID: "r1",
		ExpectedRevision: rev,
	}
}

func historyCmd(key string, rev, hRev, hGen int, p json.RawMessage) EventSubmission {
	return EventSubmission{
		OperationKey: key, OperationKind: OpHistory, AttemptID: "r1",
		ExpectedRevision: rev, Section: "history",
		SectionValueRevision: intPtr(hRev), SectionValueRevisionApplicable: true,
		ValidationGeneration: intPtr(hGen), ValidationGenerationApplicable: true,
		Payload: p,
	}
}

func uploadCmd(key string, rev int, p json.RawMessage) EventSubmission {
	return EventSubmission{
		OperationKey: key, OperationKind: OpUpload, AttemptID: "r1",
		ExpectedRevision: rev, Payload: p,
	}
}

func identityCmd(key string, rev int, p json.RawMessage) EventSubmission {
	return EventSubmission{
		OperationKey: key, OperationKind: OpIdentityVerify, AttemptID: "r1",
		ExpectedRevision: rev, Payload: p,
	}
}

func reviewCmd(key string, rev int, p json.RawMessage) EventSubmission {
	return EventSubmission{
		OperationKey: key, OperationKind: OpReviewValidate, AttemptID: "r1",
		ExpectedRevision: rev, Payload: p,
	}
}

func submitCmd(key string, rev int, p json.RawMessage) EventSubmission {
	c := EventSubmission{
		OperationKey: key, OperationKind: OpSubmit, AttemptID: "r1",
		ExpectedRevision: rev,
	}
	if p != nil {
		c.Payload = p
	}
	return c
}

func sealCmd(key string, rev int, t *testing.T) EventSubmission {
	return EventSubmission{
		OperationKey: key, OperationKind: OpSeal, AttemptID: "r1",
		ExpectedRevision: rev, Payload: payload(t, map[string]any{"seal_ref": "seal-evidence-1"}),
	}
}

// toHistory drives LISTING -> HISTORY (rev 3) through the accepted path.
func toHistory(t *testing.T, m Manifest, c []byte, s []byte) []byte {
	t.Helper()
	var err error
	var events []EventSubmission
	var resp []byte
	s, events, resp, err = ReduceFixture(m, c, s, jobCmd("job-k1", 0, "job-1", t))
	if err != nil {
		t.Fatalf("job-selection failed: %v", err)
	}
	if got := decodeResponse(t, resp); got.Status != OutcomeAccepted || got.StateRevision != 1 || got.WorkflowState != StateDetail {
		t.Fatalf("job-selection response = %+v, want accepted rev 1 DETAIL", got)
	}
	if len(events) != 1 || events[0].EventKind != EventWorkflowTransition {
		t.Fatalf("job-selection events = %+v, want one workflow_transition", events)
	}
	s, events, resp, err = ReduceFixture(m, c, s, contactCmd("contact-k1", 1, 0, 0, contactPayload(t, "Ada")))
	if err != nil {
		t.Fatalf("contact failed: %v", err)
	}
	if got := decodeResponse(t, resp); got.Status != OutcomeAccepted || got.StateRevision != 2 || got.WorkflowState != StateContact {
		t.Fatalf("contact response = %+v, want accepted rev 2 CONTACT", got)
	}
	s, _, resp, err = ReduceFixture(m, c, s, enterCmd("enter-k1", 2))
	if err != nil {
		t.Fatalf("history-enter failed: %v", err)
	}
	if got := decodeResponse(t, resp); got.Status != OutcomeAccepted || got.StateRevision != 3 || got.WorkflowState != StateHistory {
		t.Fatalf("history-enter response = %+v, want accepted rev 3 HISTORY", got)
	}
	if got := decodeState(t, s); got.WorkflowState != StateHistory || got.StateRevision != 3 {
		t.Fatalf("state = %s rev %d, want HISTORY rev 3", got.WorkflowState, got.StateRevision)
	}
	return s
}

// toReview drives HISTORY (rev 3) -> REVIEW with a recorded review (rev 7).
func toReview(t *testing.T, m Manifest, c []byte, s []byte) []byte {
	t.Helper()
	var err error
	var resp []byte
	s, _, resp, err = ReduceFixture(m, c, s, historyCmd("history-k1", 3, 0, 0, historyPayload(t, "2024-01-01", "2024-12-31")))
	if err != nil {
		t.Fatalf("history failed: %v", err)
	}
	if got := decodeResponse(t, resp); got.Status != OutcomeAccepted || got.StateRevision != 4 || got.WorkflowState != StateUpload {
		t.Fatalf("history response = %+v, want accepted rev 4 UPLOAD", got)
	}
	s, _, resp, err = ReduceFixture(m, c, s, uploadCmd("upload-k1", 4, uploadPayload(t)))
	if err != nil {
		t.Fatalf("upload failed: %v", err)
	}
	if got := decodeResponse(t, resp); got.Status != OutcomeAccepted || got.StateRevision != 5 || got.WorkflowState != StateIdentity {
		t.Fatalf("upload response = %+v, want accepted rev 5 IDENTITY", got)
	}
	s, _, resp, err = ReduceFixture(m, c, s, identityCmd("identity-k1", 5, identityPayload(t)))
	if err != nil {
		t.Fatalf("identity-verify failed: %v", err)
	}
	if got := decodeResponse(t, resp); got.Status != OutcomeAccepted || got.StateRevision != 6 || got.WorkflowState != StateReview {
		t.Fatalf("identity response = %+v, want accepted rev 6 REVIEW", got)
	}
	s, _, resp, err = ReduceFixture(m, c, s, reviewCmd("review-k1", 6, reviewPayload(t, 1, 1, 1, 1)))
	if err != nil {
		t.Fatalf("review-validate failed: %v", err)
	}
	if got := decodeResponse(t, resp); got.Status != OutcomeAccepted || got.StateRevision != 7 || got.WorkflowState != StateReview {
		t.Fatalf("review response = %+v, want accepted rev 7 REVIEW", got)
	}
	st := decodeState(t, s)
	if st.Review == nil || st.Review.ContactValueRevision != 1 || st.Review.HistoryValueRevision != 1 {
		t.Fatalf("review not recorded: %+v", st.Review)
	}
	return s
}

func TestInvalidHistoryIntervalRetainsHistoryAndRejectedAttempt(t *testing.T) {
	m, c, s := mustInit(t)
	s = toHistory(t, m, c, s)
	cmd := historyCmd("history-bad-1", 3, 0, 0, historyPayload(t, "2024-12-31", "2024-01-01"))
	newState, events, respBytes, err := ReduceFixture(m, c, s, cmd)
	if err != nil {
		t.Fatalf("invalid history must be a durable rejection with nil error, got: %v", err)
	}
	resp := decodeResponse(t, respBytes)
	if resp.Status != OutcomeRejected {
		t.Fatalf("status = %q, want rejected", resp.Status)
	}
	if resp.Reason != "invalid_interval" {
		t.Fatalf("reason = %q, want invalid_interval", resp.Reason)
	}
	if resp.StateRevision != 4 || resp.WorkflowState != StateHistory {
		t.Fatalf("response = rev %d %s, want rev 4 HISTORY", resp.StateRevision, resp.WorkflowState)
	}
	st := decodeState(t, newState)
	if st.WorkflowState != StateHistory || st.StateRevision != 4 {
		t.Fatalf("state = %s rev %d, want HISTORY rev 4", st.WorkflowState, st.StateRevision)
	}
	if st.History != nil {
		t.Fatalf("invalid history must not create acceptance, got %+v", st.History)
	}
	if len(st.Journal) != 4 {
		t.Fatalf("journal len = %d, want 4 (3 accepts + 1 rejection)", len(st.Journal))
	}
	last := st.Journal[len(st.Journal)-1]
	if last.Outcome != OutcomeRejected || last.OperationKey != "history-bad-1" || last.Reason != "invalid_interval" {
		t.Fatalf("last journal entry = %+v, want rejected history-bad-1 invalid_interval", last)
	}
	if last.WorkflowBefore != StateHistory || last.WorkflowAfter != StateHistory {
		t.Fatalf("rejection must retain HISTORY, got %s -> %s", last.WorkflowBefore, last.WorkflowAfter)
	}
	if len(events) != 1 || events[0].EventKind != EventValidationRejected {
		t.Fatalf("events = %+v, want one validation_rejected", events)
	}
	if _, ok := st.Operations["history-bad-1"]; !ok {
		t.Fatalf("rejected attempt must be stored in the operation ledger for replay")
	}
	// Identical replay returns the exact stored rejection with no new effect.
	replayState, replayEvents, replayResp, err := ReduceFixture(m, c, newState, cmd)
	if err != nil {
		t.Fatalf("replay of rejected attempt failed: %v", err)
	}
	if !bytes.Equal(replayResp, respBytes) {
		t.Fatalf("replay response differs from stored rejection")
	}
	if !bytes.Equal(replayState, newState) {
		t.Fatalf("replay must not change state")
	}
	if len(replayEvents) != 0 {
		t.Fatalf("replay must emit no events, got %d", len(replayEvents))
	}
}

func TestCorrectedHistoryPreservesRejectionAndAdvancesToUpload(t *testing.T) {
	m, c, s := mustInit(t)
	s = toHistory(t, m, c, s)
	bad := historyCmd("history-bad-1", 3, 0, 0, historyPayload(t, "2024-12-31", "2024-01-01"))
	s, _, _, err := ReduceFixture(m, c, s, bad)
	if err != nil {
		t.Fatalf("invalid history failed: %v", err)
	}
	good := historyCmd("history-good-1", 4, 0, 0, historyPayload(t, "2024-01-01", "2024-12-31"))
	newState, events, respBytes, err := ReduceFixture(m, c, s, good)
	if err != nil {
		t.Fatalf("corrected history failed: %v", err)
	}
	resp := decodeResponse(t, respBytes)
	if resp.Status != OutcomeAccepted || resp.StateRevision != 5 || resp.WorkflowState != StateUpload {
		t.Fatalf("corrected response = %+v, want accepted rev 5 UPLOAD", resp)
	}
	st := decodeState(t, newState)
	if st.WorkflowState != StateUpload || st.StateRevision != 5 {
		t.Fatalf("state = %s rev %d, want UPLOAD rev 5", st.WorkflowState, st.StateRevision)
	}
	if st.History == nil || st.History.ValueRevision != 1 || st.History.ValidationGeneration != 1 {
		t.Fatalf("history acceptance missing: %+v", st.History)
	}
	var preserved map[string]any
	if err := json.Unmarshal(st.History.Data, &preserved); err != nil {
		t.Fatalf("accepted history data is not JSON: %v", err)
	}
	if preserved["start_date"] != "2024-01-01" || preserved["end_date"] != "2024-12-31" {
		t.Fatalf("complete history value object not preserved: %v", preserved)
	}
	if len(st.Journal) != 5 {
		t.Fatalf("journal len = %d, want 5", len(st.Journal))
	}
	rejection, acceptance := st.Journal[3], st.Journal[4]
	if rejection.Outcome != OutcomeRejected || rejection.OperationKey != "history-bad-1" {
		t.Fatalf("journal[3] = %+v, want preserved rejection of history-bad-1", rejection)
	}
	if acceptance.Outcome != OutcomeAccepted || acceptance.OperationKey != "history-good-1" {
		t.Fatalf("journal[4] = %+v, want acceptance of history-good-1", acceptance)
	}
	if _, ok := st.Operations["history-bad-1"]; !ok {
		t.Fatalf("rejection ledger entry for history-bad-1 was erased")
	}
	if _, ok := st.Operations["history-good-1"]; !ok {
		t.Fatalf("acceptance ledger entry for history-good-1 missing")
	}
	if len(events) != 1 || events[0].EventKind != EventValidationAccepted {
		t.Fatalf("events = %+v, want one validation_accepted", events)
	}
}

func TestStaleValidationCannotAuthorizeCurrentProgress(t *testing.T) {
	m, c, s := mustInit(t)
	s = toHistory(t, m, c, s)
	s = toReview(t, m, c, s)
	// Accepted contact edit advances contact to 2/2 and invalidates review.
	edit := contactCmd("contact-k2", 7, 1, 1, contactPayload(t, "Ada Updated"))
	s, _, respBytes, err := ReduceFixture(m, c, s, edit)
	if err != nil {
		t.Fatalf("contact edit failed: %v", err)
	}
	if got := decodeResponse(t, respBytes); got.Status != OutcomeAccepted || got.StateRevision != 8 {
		t.Fatalf("contact edit response = %+v, want accepted rev 8", got)
	}
	if got := decodeState(t, s); got.Contact == nil || got.Contact.ValueRevision != 2 || got.Contact.ValidationGeneration != 2 {
		t.Fatalf("contact not advanced to 2/2: %+v", got.Contact)
	}
	// Stale review pins (contact 1/1) cannot authorize progress.
	staleReview := reviewCmd("review-stale-1", 8, reviewPayload(t, 1, 1, 1, 1))
	s2, events, respBytes, err := ReduceFixture(m, c, s, staleReview)
	if err != nil {
		t.Fatalf("stale review must be a durable rejection, got error: %v", err)
	}
	resp := decodeResponse(t, respBytes)
	if resp.Status != OutcomeRejected || resp.Reason != "stale_dependency" {
		t.Fatalf("stale review response = %+v, want rejected stale_dependency", resp)
	}
	if resp.StateRevision != 9 || resp.WorkflowState != StateReview {
		t.Fatalf("stale review must retain REVIEW at rev 9, got %+v", resp)
	}
	if got := decodeState(t, s2); got.Review != nil {
		t.Fatalf("stale review must not record acceptance, got %+v", got.Review)
	}
	if len(events) != 1 || events[0].EventKind != EventValidationRejected {
		t.Fatalf("stale review events = %+v, want one validation_rejected", events)
	}
	s = s2
	// Stale section coordinates (rev 1 vs current 2) cannot authorize an edit.
	staleEdit := contactCmd("contact-stale-1", 9, 1, 1, contactPayload(t, "Stale"))
	s2, _, respBytes, err = ReduceFixture(m, c, s, staleEdit)
	if err != nil {
		t.Fatalf("stale contact edit must be a durable rejection, got error: %v", err)
	}
	if resp = decodeResponse(t, respBytes); resp.Status != OutcomeRejected || resp.Reason != "stale_section_revision" {
		t.Fatalf("stale coords response = %+v, want rejected stale_section_revision", resp)
	}
	s = s2
	// Current value revision with a stale generation also rejects.
	mixedStale := contactCmd("contact-stale-2", 10, 2, 1, contactPayload(t, "Mixed"))
	s2, _, respBytes, err = ReduceFixture(m, c, s, mixedStale)
	if err != nil {
		t.Fatalf("mixed stale edit must be a durable rejection, got error: %v", err)
	}
	if resp = decodeResponse(t, respBytes); resp.Status != OutcomeRejected || resp.Reason != "stale_generation" {
		t.Fatalf("mixed coords response = %+v, want rejected stale_generation", resp)
	}
	s = s2
	// Current pins authorize progress again.
	current := reviewCmd("review-k2", 11, reviewPayload(t, 2, 2, 1, 1))
	s, _, respBytes, err = ReduceFixture(m, c, s, current)
	if err != nil {
		t.Fatalf("current review failed: %v", err)
	}
	if resp = decodeResponse(t, respBytes); resp.Status != OutcomeAccepted || resp.StateRevision != 12 {
		t.Fatalf("current review response = %+v, want accepted rev 12", resp)
	}
	if got := decodeState(t, s); got.Review == nil || got.Review.ContactValueRevision != 2 {
		t.Fatalf("current review not recorded: %+v", got.Review)
	}
}

func TestEarlierAcceptedEditsInvalidateDependentReview(t *testing.T) {
	m, c, s := mustInit(t)
	s = toHistory(t, m, c, s)
	s = toReview(t, m, c, s)
	// Contact edit invalidates the recorded review.
	s, _, respBytes, err := ReduceFixture(m, c, s, contactCmd("contact-k2", 7, 1, 1, contactPayload(t, "Ada Updated")))
	if err != nil {
		t.Fatalf("contact edit failed: %v", err)
	}
	resp := decodeResponse(t, respBytes)
	if resp.Status != OutcomeAccepted || !resp.InvalidatedReview {
		t.Fatalf("contact edit response = %+v, want accepted with invalidated_review", resp)
	}
	st := decodeState(t, s)
	if st.Review != nil {
		t.Fatalf("contact edit must invalidate dependent review, got %+v", st.Review)
	}
	if st.WorkflowState != StateReview || st.StateRevision != 8 {
		t.Fatalf("state = %s rev %d, want REVIEW rev 8", st.WorkflowState, st.StateRevision)
	}
	if last := st.Journal[len(st.Journal)-1]; last.Detail != "invalidated_review" {
		t.Fatalf("journal detail = %q, want invalidated_review", last.Detail)
	}
	// Re-validate on current pins, then a history edit invalidates again.
	s, _, _, err = ReduceFixture(m, c, s, reviewCmd("review-k2", 8, reviewPayload(t, 2, 2, 1, 1)))
	if err != nil {
		t.Fatalf("re-validation failed: %v", err)
	}
	if got := decodeState(t, s); got.Review == nil {
		t.Fatalf("re-validation must record review")
	}
	s, _, respBytes, err = ReduceFixture(m, c, s, historyCmd("history-k2", 9, 1, 1, historyPayload(t, "2024-02-01", "2024-12-31")))
	if err != nil {
		t.Fatalf("history edit failed: %v", err)
	}
	if resp = decodeResponse(t, respBytes); resp.Status != OutcomeAccepted || !resp.InvalidatedReview {
		t.Fatalf("history edit response = %+v, want accepted with invalidated_review", resp)
	}
	if got := decodeState(t, s); got.Review != nil || got.History.ValueRevision != 2 {
		t.Fatalf("history edit must invalidate review and advance history: %+v %+v", got.Review, got.History)
	}
	// Submit is guarded until review is current again.
	s2, _, respBytes, err := ReduceFixture(m, c, s, submitCmd("submit-blocked-1", 10, nil))
	if err != nil {
		t.Fatalf("guarded submit must be a durable rejection, got error: %v", err)
	}
	if resp = decodeResponse(t, respBytes); resp.Status != OutcomeRejected || resp.Reason != "missing_review" {
		t.Fatalf("guarded submit response = %+v, want rejected missing_review", resp)
	}
	if got := decodeState(t, s2); got.Submission != nil || got.WorkflowState != StateReview {
		t.Fatalf("guarded submit must not commit")
	}
	s = s2
	s, _, _, err = ReduceFixture(m, c, s, reviewCmd("review-k3", 11, reviewPayload(t, 2, 2, 2, 2)))
	if err != nil {
		t.Fatalf("final re-validation failed: %v", err)
	}
	s, _, respBytes, err = ReduceFixture(m, c, s, submitCmd("submit-k1", 12, nil))
	if err != nil {
		t.Fatalf("submit after re-validation failed: %v", err)
	}
	if resp = decodeResponse(t, respBytes); resp.Status != OutcomeCommitted || resp.WorkflowState != StateConfirmation {
		t.Fatalf("submit response = %+v, want committed CONFIRMATION", resp)
	}
	if got := decodeState(t, s); got.Submission == nil {
		t.Fatalf("submission missing after current review plus submit")
	}
}

func TestReusedOperationKeyWithDifferentContentConflicts(t *testing.T) {
	m, c, s := mustInit(t)
	first := jobCmd("job-k1", 0, "job-1", t)
	s, _, firstResp, err := ReduceFixture(m, c, s, first)
	if err != nil {
		t.Fatalf("job-selection failed: %v", err)
	}
	before := append([]byte(nil), s...)
	// Same key, different content (different job) conflicts.
	conflict := jobCmd("job-k1", 0, "job-2", t)
	outState, events, outResp, err := ReduceFixture(m, c, s, conflict)
	if err == nil {
		t.Fatalf("reused key with different content must conflict, got status %+v", decodeResponse(t, outResp))
	}
	if !strings.Contains(strings.ToLower(err.Error()), "conflict") && !strings.Contains(err.Error(), "already bound") {
		t.Fatalf("conflict error = %q, want key-conflict wording", err.Error())
	}
	if !bytes.Equal(outState, before) {
		t.Fatalf("conflict must not change state")
	}
	if len(events) != 0 || outResp != nil {
		t.Fatalf("conflict must emit no events and no response")
	}
	st := decodeState(t, outState)
	if st.StateRevision != 1 || len(st.Journal) != 1 {
		t.Fatalf("conflict must not append to the journal: rev %d journal %d", st.StateRevision, len(st.Journal))
	}
	// Identical key/digest replays the exact stored response.
	replayState, replayEvents, replayResp, err := ReduceFixture(m, c, s, first)
	if err != nil {
		t.Fatalf("identical replay failed: %v", err)
	}
	if !bytes.Equal(replayResp, firstResp) {
		t.Fatalf("replay response differs from stored response")
	}
	if !bytes.Equal(replayState, s) || len(replayEvents) != 0 {
		t.Fatalf("replay must not change state or emit events")
	}
	// Same rule holds for section writes: same key, different value conflicts.
	contactFirst := contactCmd("contact-k1", 1, 0, 0, contactPayload(t, "Ada"))
	s, _, _, err = ReduceFixture(m, c, s, contactFirst)
	if err != nil {
		t.Fatalf("contact failed: %v", err)
	}
	contactConflict := contactCmd("contact-k1", 1, 0, 0, contactPayload(t, "Different"))
	outState, _, _, err = ReduceFixture(m, c, s, contactConflict)
	if err == nil {
		t.Fatalf("reused contact key with different content must conflict")
	}
	if got := decodeState(t, outState); got.StateRevision != 2 || got.Contact == nil {
		t.Fatalf("contact conflict must leave rev 2 acceptance intact: %+v", got.Contact)
	}
}

func TestDifferentSubmitKeysCannotCreateSecondCommitment(t *testing.T) {
	m, c, s := mustInit(t)
	s = toHistory(t, m, c, s)
	s = toReview(t, m, c, s)
	s, _, firstRespBytes, err := ReduceFixture(m, c, s, submitCmd("submit-k1", 7, nil))
	if err != nil {
		t.Fatalf("first submit failed: %v", err)
	}
	first := decodeResponse(t, firstRespBytes)
	if first.Status != OutcomeCommitted || first.WorkflowState != StateConfirmation || first.Commitment == nil {
		t.Fatalf("first submit response = %+v, want committed with commitment", first)
	}
	firstAppID := first.Commitment.ApplicationID
	if firstAppID == "" || first.Commitment.OperationKey != "submit-k1" {
		t.Fatalf("first commitment = %+v, want app ID bound to submit-k1", first.Commitment)
	}
	// A different key with current content resolves to the existing
	// commitment instead of creating a second one.
	s2, events, respBytes, err := ReduceFixture(m, c, s, submitCmd("submit-k2", 8, nil))
	if err != nil {
		t.Fatalf("second submit must resolve, got error: %v", err)
	}
	second := decodeResponse(t, respBytes)
	if second.Status != OutcomeResolvedExisting {
		t.Fatalf("second submit status = %q, want resolved_existing", second.Status)
	}
	if second.Commitment == nil || second.Commitment.ApplicationID != firstAppID {
		t.Fatalf("second submit must resolve to %q, got %+v", firstAppID, second.Commitment)
	}
	if second.Commitment.OperationKey != "submit-k1" || second.Commitment.RequestDigest != first.Commitment.RequestDigest {
		t.Fatalf("resolved commitment must be the original: %+v vs %+v", second.Commitment, first.Commitment)
	}
	st := decodeState(t, s2)
	if st.WorkflowState != StateConfirmation || st.StateRevision != 9 {
		t.Fatalf("state = %s rev %d, want CONFIRMATION rev 9", st.WorkflowState, st.StateRevision)
	}
	if st.Submission == nil || st.Submission.ApplicationID != firstAppID {
		t.Fatalf("submission mutated by second key: %+v", st.Submission)
	}
	if last := st.Journal[len(st.Journal)-1]; last.Outcome != OutcomeResolvedExisting || last.OperationKey != "submit-k2" {
		t.Fatalf("journal last = %+v, want resolved submit-k2", last)
	}
	if len(events) != 1 || events[0].EventKind != EventRequestCompleted {
		t.Fatalf("resolve events = %+v, want one request_completed", events)
	}
	s = s2
	// Stale content under a third key rejects without touching the commitment.
	stale := submitCmd("submit-k3", 8, nil)
	s2, _, respBytes, err = ReduceFixture(m, c, s, stale)
	if err != nil {
		t.Fatalf("stale submit must be a durable rejection, got error: %v", err)
	}
	if got := decodeResponse(t, respBytes); got.Status != OutcomeRejected || got.Reason != "stale_revision" {
		t.Fatalf("stale submit response = %+v, want rejected stale_revision", got)
	}
	s = s2
	incompatible := submitCmd("submit-k4", 10, reviewPayload(t, 0, 0, 1, 1))
	s2, _, respBytes, err = ReduceFixture(m, c, s, incompatible)
	if err != nil {
		t.Fatalf("incompatible submit must be a durable rejection, got error: %v", err)
	}
	if got := decodeResponse(t, respBytes); got.Status != OutcomeRejected || got.Reason != "stale_dependency" {
		t.Fatalf("incompatible submit response = %+v, want rejected stale_dependency", got)
	}
	if got := decodeState(t, s2); got.Submission == nil || got.Submission.ApplicationID != firstAppID {
		t.Fatalf("incompatible submit must not touch the commitment: %+v", got.Submission)
	}
	// The original key/digest still replays the original receipt exactly.
	_, replayEvents, replayResp, err := ReduceFixture(m, c, s2, submitCmd("submit-k1", 7, nil))
	if err != nil {
		t.Fatalf("original submit replay failed: %v", err)
	}
	if !bytes.Equal(replayResp, firstRespBytes) {
		t.Fatalf("original submit replay differs from stored receipt")
	}
	if len(replayEvents) != 0 {
		t.Fatalf("replay must emit no events")
	}
}

func TestSealedAuthorityRejectsNewEffectsButReplaysStoredResponses(t *testing.T) {
	m, c, s := mustInit(t)
	var err error
	var respBytes []byte
	stored := map[string][]byte{}
	s, _, respBytes, err = ReduceFixture(m, c, s, jobCmd("job-k1", 0, "job-1", t))
	if err != nil {
		t.Fatalf("job-selection failed: %v", err)
	}
	stored["job-k1"] = append([]byte(nil), respBytes...)
	s, _, respBytes, err = ReduceFixture(m, c, s, contactCmd("contact-k1", 1, 0, 0, contactPayload(t, "Ada")))
	if err != nil {
		t.Fatalf("contact failed: %v", err)
	}
	stored["contact-k1"] = append([]byte(nil), respBytes...)
	s, _, respBytes, err = ReduceFixture(m, c, s, enterCmd("enter-k1", 2))
	if err != nil {
		t.Fatalf("history-enter failed: %v", err)
	}
	stored["enter-k1"] = append([]byte(nil), respBytes...)
	s, _, respBytes, err = ReduceFixture(m, c, s, sealCmd("seal-k1", 3, t))
	if err != nil {
		t.Fatalf("seal failed: %v", err)
	}
	sealResp := decodeResponse(t, respBytes)
	if sealResp.Status != OutcomeAccepted || sealResp.StateRevision != 4 {
		t.Fatalf("seal response = %+v, want accepted rev 4", sealResp)
	}
	stored["seal-k1"] = append([]byte(nil), respBytes...)
	st := decodeState(t, s)
	if st.MutationAuthority != AuthoritySealed || st.AuthoritySealRef != "seal-evidence-1" {
		t.Fatalf("authority = %q ref %q, want sealed with evidence", st.MutationAuthority, st.AuthoritySealRef)
	}
	if st.WorkflowState != StateHistory {
		t.Fatalf("seal must not move workflow, got %s", st.WorkflowState)
	}
	// New effects after sealing are rejected without business change.
	blocked := historyCmd("history-k1", 4, 0, 0, historyPayload(t, "2024-01-01", "2024-12-31"))
	s2, events, respBytes, err := ReduceFixture(m, c, s, blocked)
	if err != nil {
		t.Fatalf("post-seal operation must be a durable rejection, got error: %v", err)
	}
	blockedResp := decodeResponse(t, respBytes)
	if blockedResp.Status != OutcomeRejected || blockedResp.Reason != "authority_sealed" {
		t.Fatalf("post-seal response = %+v, want rejected authority_sealed", blockedResp)
	}
	st2 := decodeState(t, s2)
	if st2.WorkflowState != StateHistory || st2.History != nil {
		t.Fatalf("post-seal rejection must create no business effect: %+v", st2.History)
	}
	if st2.MutationAuthority != AuthoritySealed {
		t.Fatalf("authority must remain sealed")
	}
	if len(events) != 1 || events[0].EventKind != EventRequestRejected {
		t.Fatalf("post-seal events = %+v, want one request_rejected", events)
	}
	s = s2
	// Stored responses replay exactly after sealing.
	replays := []EventSubmission{
		jobCmd("job-k1", 0, "job-1", t),
		contactCmd("contact-k1", 1, 0, 0, contactPayload(t, "Ada")),
		enterCmd("enter-k1", 2),
		sealCmd("seal-k1", 3, t),
	}
	for _, cmd := range replays {
		rs, re, rr, err := ReduceFixture(m, c, s, cmd)
		if err != nil {
			t.Fatalf("replay of %s failed after seal: %v", cmd.OperationKey, err)
		}
		if !bytes.Equal(rr, stored[cmd.OperationKey]) {
			t.Fatalf("replay of %s differs from stored response", cmd.OperationKey)
		}
		if !bytes.Equal(rs, s) || len(re) != 0 {
			t.Fatalf("replay of %s must not change state or emit events", cmd.OperationKey)
		}
	}
	// A second seal key cannot create a new effect either.
	s2, _, respBytes, err = ReduceFixture(m, c, s, sealCmd("seal-k2", 5, t))
	if err != nil {
		t.Fatalf("second seal must be a durable rejection, got error: %v", err)
	}
	if got := decodeResponse(t, respBytes); got.Status != OutcomeRejected || got.Reason != "authority_sealed" {
		t.Fatalf("second seal response = %+v, want rejected authority_sealed", got)
	}
	if got := decodeState(t, s2); got.AuthoritySealRef != "seal-evidence-1" {
		t.Fatalf("seal evidence changed: %q", got.AuthoritySealRef)
	}
}

package application_owner

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"authority"
	"lifecycle_rules"
	"owner_store"
)

// ---------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------

func testPolicy() []byte {
	return []byte(`{"channels":{"test-channel":{"principal":"test-writer","kind":"owner","grants":[{"domain":"*","operations":["*"]}]}}}`)
}

// authedContext authenticates a synthetic request and returns its context
// for direct module calls.
func authedContext(t *testing.T) context.Context {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "http://application.test/direct", nil)
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
		RecordType:     "manifest",
		SchemaVersion:  "1.0.0",
		ManifestID:     "manifest-" + suffix,
		RunID:          "attempt-" + suffix,
		JournalID:      "journal-" + suffix,
		OwnerDomain:    ownerDomain,
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
		TaskSemanticHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
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

func testRegistration(suffix string, config []byte) EntityRegistration {
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
			"application": map[string]any{"role": "origin", "source_id": "origin-attempt-" + suffix, "writer_id": "app-writer-attempt-" + suffix},
		},
		EvidenceRefs:  []EvidenceRef{},
		Configuration: append([]byte(nil), config...),
	}
}

func initAttempt(t *testing.T, store *OwnerStore, suffix, domain string, config []byte) (string, EvidenceRef) {
	t.Helper()
	if config == nil {
		config = DefaultFixtureConfiguration()
	}
	ref, err := InitializeApplication(authedContext(t), store, testManifest(suffix, domain), testRegistration(suffix, config))
	if err != nil {
		t.Fatalf("InitializeApplication(%s): %v", suffix, err)
	}
	return "attempt-" + suffix, ref
}

// doRequest issues an authenticated HTTP request against the handler. The
// real request (headers, query, body) passes through authority.Authenticate
// so caller-supplied authority labels would be rejected exactly as in
// production.
func doRequest(t *testing.T, handler http.Handler, method, target string, body any, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("encode body: %v", err)
		}
		reader = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, target, reader)
	req.Header.Set("Authorization", "Channel test-channel")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
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

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %d response %q: %v", rec.Code, rec.Body.String(), err)
	}
	return out
}

func getString(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

func getInt(m map[string]any, key string) int {
	switch n := m[key].(type) {
	case float64:
		return int(n)
	case int:
		return n
	default:
		return -1
	}
}

// journalNumber coerces numbers decoded from retained journal envelopes,
// which use json.Number, alongside plain float64/int forms.
func journalNumber(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case int64:
		return int(n)
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return int(i)
		}
		return -1
	default:
		return -1
	}
}

// flow drives the accepted happy path for one attempt, tracking the live
// revision from each acknowledgement.
type flow struct {
	t       *testing.T
	handler http.Handler
	attempt string
	rev     int
	seq     int
}

func newFlow(t *testing.T, handler http.Handler, attempt string) *flow {
	return &flow{t: t, handler: handler, attempt: attempt}
}

func (f *flow) key(prefix string) string {
	f.seq++
	return fmt.Sprintf("%s-%s-%d", prefix, f.attempt, f.seq)
}

func (f *flow) mutate(method, path string, body map[string]any) (int, map[string]any) {
	f.t.Helper()
	body["attempt_id"] = f.attempt
	rec := doRequest(f.t, f.handler, method, path, body, nil)
	out := decodeBody(f.t, rec)
	if rev := getInt(out, "state_revision"); rev >= 0 {
		f.rev = rev
	}
	return rec.Code, out
}

func (f *flow) mustAccept(method, path string, body map[string]any) map[string]any {
	f.t.Helper()
	code, out := f.mutate(method, path, body)
	if code != http.StatusOK {
		f.t.Fatalf("%s %s: code %d, body %v", method, path, code, out)
	}
	if st := getString(out, "status"); st != "accepted" && st != "committed" && st != "resolved_existing" {
		f.t.Fatalf("%s %s: status %q, body %v", method, path, st, out)
	}
	return out
}

func (f *flow) job(jobID string) map[string]any {
	return f.mustAccept(http.MethodPost, "/api/job-selection", map[string]any{
		"operation_key": f.key("job"), "expected_revision": f.rev, "job_id": jobID,
	})
}

func (f *flow) contact() map[string]any {
	return f.mustAccept(http.MethodPut, "/api/contact", map[string]any{
		"operation_key": f.key("contact"), "expected_revision": f.rev,
		"section_value_revision": 0, "validation_generation": 0,
		"data": map[string]any{"full_name": "Candidate " + f.attempt, "email": "candidate@example.test"},
	})
}

func (f *flow) historyEnter() map[string]any {
	return f.mustAccept(http.MethodPost, "/api/history/enter", map[string]any{
		"operation_key": f.key("enter"), "expected_revision": f.rev,
	})
}

func (f *flow) history() map[string]any {
	return f.mustAccept(http.MethodPut, "/api/history", map[string]any{
		"operation_key": f.key("history"), "expected_revision": f.rev,
		"section_value_revision": 0, "validation_generation": 0,
		"data": map[string]any{"start_date": "2020-01-01", "end_date": "2024-01-01", "employer": "Example Co"},
	})
}

func (f *flow) upload(content []byte) map[string]any {
	return f.mustAccept(http.MethodPost, "/api/upload", map[string]any{
		"operation_key": f.key("upload"), "expected_revision": f.rev,
		"filename": "resume.pdf", "content_type": "application/pdf",
		"content_base64": base64.StdEncoding.EncodeToString(content),
	})
}

func (f *flow) identity(epoch, receipt string) map[string]any {
	return f.mustAccept(http.MethodPost, "/api/identity/verify", map[string]any{
		"operation_key": f.key("identity"), "expected_revision": f.rev,
		"epoch": epoch, "receipt": receipt,
	})
}

func (f *flow) review() map[string]any {
	return f.mustAccept(http.MethodPost, "/api/review/validate", map[string]any{
		"operation_key": f.key("review"), "expected_revision": f.rev,
		"contact_value_revision": 1, "contact_generation": 1,
		"history_value_revision": 1, "history_generation": 1,
	})
}

func (f *flow) submit() map[string]any {
	return f.mustAccept(http.MethodPost, "/api/submit", map[string]any{
		"operation_key": f.key("submit"), "expected_revision": f.rev,
	})
}

func (f *flow) draft() (int, map[string]any) {
	f.t.Helper()
	target := "/api/draft?attempt_id=" + url.QueryEscape(f.attempt)
	rec := doRequest(f.t, f.handler, http.MethodGet, target, nil, nil)
	return rec.Code, decodeBody(f.t, rec)
}

func (f *flow) confirmation() *httptest.ResponseRecorder {
	f.t.Helper()
	target := "/api/confirmation?attempt_id=" + url.QueryEscape(f.attempt)
	return doRequest(f.t, f.handler, http.MethodGet, target, nil, nil)
}

// ---------------------------------------------------------------------------
// Conformance assertions.
// ---------------------------------------------------------------------------

// The committed application, its retrievable receipt, and receipt rendering
// are three separate facts: commitment survives with no rendering telemetry
// at all, and the owner never invents rendering assertions.
func TestApplicationCommitCanExistWithoutConfirmationRendering(t *testing.T) {
	store := openStore(t, "laboratory")
	handler := NewApplicationHandler(store)
	attempt, _ := initAttempt(t, store, "commit", "laboratory", nil)
	f := newFlow(t, handler, attempt)

	f.job("job-1")
	f.contact()
	f.historyEnter()
	f.history()
	f.upload([]byte("resume-bytes-" + attempt))
	f.identity("epoch-1", "receipt-"+attempt)
	f.review()
	submitted := f.submit()
	if getString(submitted, "status") != "committed" {
		t.Fatalf("submit status = %q, want committed", getString(submitted, "status"))
	}
	commit, ok := submitted["commitment"].(map[string]any)
	if !ok || getString(commit, "application_id") == "" {
		t.Fatalf("submit carries no commitment: %v", submitted)
	}

	// No rendering telemetry exists anywhere in this test, yet the receipt
	// retrieves with its committed coordinates.
	first := f.confirmation()
	if first.Code != http.StatusOK {
		t.Fatalf("confirmation code = %d, body %s", first.Code, first.Body.String())
	}
	receipt := decodeBody(t, first)
	for _, key := range []string{"application_id", "request_digest", "receipt", "commit_ref"} {
		if getString(receipt, key) == "" {
			t.Fatalf("confirmation receipt lacks %s: %v", key, receipt)
		}
	}
	if getString(receipt, "application_id") != getString(commit, "application_id") {
		t.Fatalf("confirmation application %q != committed %q", getString(receipt, "application_id"), getString(commit, "application_id"))
	}
	if strings.Contains(strings.ToLower(first.Body.String()), "render") {
		t.Fatalf("confirmation asserts rendering: %s", first.Body.String())
	}

	// Retrieval is stable without any rendering side effect.
	second := f.confirmation()
	if second.Body.String() != first.Body.String() {
		t.Fatalf("confirmation unstable:\n%s\n%s", first.Body.String(), second.Body.String())
	}

	// The draft likewise cites the submission with no rendering field.
	if code, draft := f.draft(); code != http.StatusOK {
		t.Fatalf("draft code = %d", code)
	} else {
		sub, ok := draft["submission"].(map[string]any)
		if !ok || getString(sub, "application_id") != getString(commit, "application_id") {
			t.Fatalf("draft submission = %v, want committed %v", draft["submission"], commit)
		}
		raw, _ := json.Marshal(draft)
		if strings.Contains(strings.ToLower(string(raw)), "render") {
			t.Fatalf("draft asserts rendering: %s", raw)
		}
	}
}

// Upload acknowledgement requires durably installed, server-verified bytes:
// the bytes read back exactly, oversized uploads reject without acceptance,
// and caller-claimed digests are never trusted.
func TestUploadAcknowledgementRequiresDurableVerifiedBytes(t *testing.T) {
	store := openStore(t, "laboratory")
	handler := NewApplicationHandler(store)
	ctx := authedContext(t)

	attempt, _ := initAttempt(t, store, "upload", "laboratory", nil)
	f := newFlow(t, handler, attempt)
	f.job("job-1")
	f.contact()
	f.historyEnter()
	f.history()

	content := []byte("resume-bytes-" + attempt + "-with-verified-content")
	ack := f.upload(content)
	if getString(ack, "workflow_state") != "IDENTITY" {
		t.Fatalf("upload workflow = %q, want IDENTITY", getString(ack, "workflow_state"))
	}

	// The acknowledged bytes are durably installed under the accepted digest.
	_, draft := f.draft()
	upload, ok := draft["upload"].(map[string]any)
	if !ok {
		t.Fatalf("draft upload = %v, want accepted artifact", draft["upload"])
	}
	digest := getString(upload, "digest")
	if !strings.HasPrefix(digest, "sha256:") {
		t.Fatalf("upload digest = %q, want content digest", digest)
	}
	stored, err := owner_store.ReadArtifact(ctx, store, owner_store.ArtifactReference{Digest: digest})
	if err != nil {
		t.Fatalf("ReadArtifact(%s): %v", digest, err)
	}
	if !bytes.Equal(stored, content) {
		t.Fatalf("stored upload bytes do not match submitted content")
	}

	// An oversized upload rejects and is never accepted: the workflow stays
	// in UPLOAD with no upload acceptance.
	small := map[string]any{}
	if err := json.Unmarshal(DefaultFixtureConfiguration(), &small); err != nil {
		t.Fatalf("decode default config: %v", err)
	}
	small["upload_max_bytes"] = float64(64)
	smallRaw, _ := json.Marshal(small)
	attempt2, _ := initAttempt(t, store, "upload-small", "laboratory", smallRaw)
	g := newFlow(t, handler, attempt2)
	g.job("job-1")
	g.contact()
	g.historyEnter()
	g.history()
	code, rejected := g.mutate(http.MethodPost, "/api/upload", map[string]any{
		"operation_key": g.key("big"), "expected_revision": g.rev,
		"filename": "big.pdf", "content_type": "application/pdf",
		"content_base64": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("x"), 1024)),
	})
	if code != http.StatusUnprocessableEntity || getString(rejected, "status") != "rejected" {
		t.Fatalf("oversized upload: code %d status %q, want 422 rejected", code, getString(rejected, "status"))
	}
	if getString(rejected, "reason") != "size_exceeded" {
		t.Fatalf("oversized upload reason = %q, want size_exceeded", getString(rejected, "reason"))
	}
	if _, after := g.draft(); getString(after, "workflow_state") != "UPLOAD" {
		t.Fatalf("workflow after oversized upload = %q, want UPLOAD", getString(after, "workflow_state"))
	} else if _, isMissing := after["upload"].(map[string]any)["reason"]; !isMissing {
		t.Fatalf("oversized upload was accepted: %v", after["upload"])
	}

	// A small upload on the same bounded attempt is accepted with the
	// server-computed digest, proving the bound (not the transport) decided.
	g.upload([]byte("tiny"))
}

// Identity verification requires the pinned epoch and the opaque attempt
// binding: wrong epochs, bare token possession, and cross-attempt receipts
// all reject.
func TestIdentityVerificationRequiresAttemptAndEpochBinding(t *testing.T) {
	store := openStore(t, "laboratory")
	handler := NewApplicationHandler(store)

	attempt, _ := initAttempt(t, store, "identity", "laboratory", nil)
	f := newFlow(t, handler, attempt)
	f.job("job-1")
	f.contact()
	f.historyEnter()
	f.history()
	f.upload([]byte("resume-bytes-" + attempt))

	// Wrong epoch: rejected, identity stays unverified.
	code, out := f.mutate(http.MethodPost, "/api/identity/verify", map[string]any{
		"operation_key": f.key("id"), "expected_revision": f.rev,
		"epoch": "epoch-foreign", "receipt": "receipt-" + attempt,
	})
	if code != http.StatusUnprocessableEntity || getString(out, "reason") != "epoch_mismatch" {
		t.Fatalf("foreign epoch: code %d reason %q, want 422 epoch_mismatch", code, getString(out, "reason"))
	}

	// Bare token possession (empty receipt) verifies nothing.
	code, out = f.mutate(http.MethodPost, "/api/identity/verify", map[string]any{
		"operation_key": f.key("id"), "expected_revision": f.rev,
		"epoch": "epoch-1", "receipt": "",
	})
	if code != http.StatusUnprocessableEntity || getString(out, "reason") != "unverified_identity" {
		t.Fatalf("empty receipt: code %d reason %q, want 422 unverified_identity", code, getString(out, "reason"))
	}

	// A receipt presented against a different attempt's state cannot verify
	// there: verification is attempt-bound, not a global token.
	other, _ := initAttempt(t, store, "identity-other", "laboratory", nil)
	g := newFlow(t, handler, other)
	code, out = g.mutate(http.MethodPost, "/api/identity/verify", map[string]any{
		"operation_key": g.key("id"), "expected_revision": g.rev,
		"epoch": "epoch-1", "receipt": "receipt-" + attempt,
	})
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("cross-attempt verify: code %d, want 422 rejection, body %v", code, out)
	}

	// The bound epoch plus a receipt for this attempt verifies.
	verified := f.identity("epoch-1", "receipt-"+attempt)
	if getString(verified, "workflow_state") != "REVIEW" {
		t.Fatalf("bound verify workflow = %q, want REVIEW", getString(verified, "workflow_state"))
	}
	if _, draft := f.draft(); draft["identity_receipt"] == nil {
		t.Fatalf("draft lacks identity receipt after verification")
	} else if id, ok := draft["identity_receipt"].(map[string]any); !ok || id["verified"] != true {
		t.Fatalf("identity receipt not verified: %v", draft["identity_receipt"])
	}
}

// Sealing fences new mutations while accounting for every already admitted
// transaction: the seal event records the admitted count and head, fresh
// mutations reject as sealed, and identical replays still resolve.
func TestApplicationSealAccountsForAlreadyAdmittedTransactions(t *testing.T) {
	store := openStore(t, "laboratory")
	handler := NewApplicationHandler(store)
	ctx := authedContext(t)

	// Partial attempt: two admitted operations, no submission.
	attempt, initRef := initAttempt(t, store, "seal-partial", "laboratory", nil)
	f := newFlow(t, handler, attempt)
	jobAck := f.job("job-1")
	jobDigest := getString(jobAck, "request_digest")
	f.contact()

	pub, err := SealApplication(ctx, store, AttemptReference{AttemptID: attempt, Kind: "practice"}, initRef)
	if err != nil {
		t.Fatalf("SealApplication: %v", err)
	}
	if pub.Axis != lifecycle_rules.AxisApplication || pub.Revision != 1 || pub.PreviousRevision != 0 {
		t.Fatalf("seal publication = axis %q rev %d prev %d", pub.Axis, pub.Revision, pub.PreviousRevision)
	}
	value, ok := pub.Value.(lifecycle_rules.ApplicationValue)
	if !ok || len(value.Facts) != 1 {
		t.Fatalf("seal value = %#v, want one origin fact", pub.Value)
	}
	if value.Facts[0].State != "not_committed" || value.Facts[0].Coverage != "final_for_attempt" {
		t.Fatalf("partial seal fact = %q/%q, want not_committed/final_for_attempt",
			value.Facts[0].State, value.Facts[0].Coverage)
	}

	// The seal event accounts for exactly the two admitted transactions and
	// pins the pre-seal head.
	sealed, err := owner_store.LoadPrefix(ctx, store, owner_store.JournalPrefix{
		JournalID: pub.EvidencePrefix.JournalID, LastSequence: pub.EvidencePrefix.LastSequence, HeadHash: pub.EvidencePrefix.HeadHash,
	})
	if err != nil {
		t.Fatalf("LoadPrefix(sealed): %v", err)
	}
	var sealData map[string]any
	for _, env := range sealed {
		if env.EventKind == "fixture_seal" {
			sealData = env.Payload.Data
		}
	}
	if sealData == nil {
		t.Fatalf("no fixture_seal event in sealed prefix of %d events", len(sealed))
	}
	admitted := journalNumber(sealData["admitted_operations"])
	if admitted != 2 {
		t.Fatalf("admitted_operations = %v, want 2", sealData["admitted_operations"])
	}
	preHead, _ := sealData["admitted_head"].(string)
	if preHead != sealed[len(sealed)-2].EventHash {
		t.Fatalf("admitted_head does not pin the pre-seal head")
	}

	// Fresh mutations fence as sealed.
	code, fenced := f.mutate(http.MethodPost, "/api/history/enter", map[string]any{
		"operation_key": f.key("enter"), "expected_revision": f.rev,
	})
	if code != http.StatusUnprocessableEntity || getString(fenced, "reason") != "authority_sealed" {
		t.Fatalf("post-seal mutation: code %d reason %q, want 422 authority_sealed", code, getString(fenced, "reason"))
	}

	// Identical replay of an admitted key still resolves to its stored
	// response after sealing.
	rec := doRequest(t, handler, http.MethodPost, "/api/job-selection", map[string]any{
		"attempt_id":        attempt,
		"operation_key":     getString(jobAck, "operation_key"),
		"expected_revision": 0, "job_id": "job-1",
	}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("post-seal replay code = %d, body %s", rec.Code, rec.Body.String())
	}
	replay := decodeBody(t, rec)
	if getString(replay, "request_digest") != jobDigest {
		t.Fatalf("replay digest %q != original %q", getString(replay, "request_digest"), jobDigest)
	}

	// Full attempt: the seal carries the commitment forward.
	attempt2, initRef2 := initAttempt(t, store, "seal-full", "laboratory", nil)
	g := newFlow(t, handler, attempt2)
	g.job("job-2")
	g.contact()
	g.historyEnter()
	g.history()
	g.upload([]byte("resume-bytes-" + attempt2))
	g.identity("epoch-1", "receipt-"+attempt2)
	g.review()
	commit := g.submit()
	commitID := getString(commit["commitment"].(map[string]any), "application_id")
	pub2, err := SealApplication(ctx, store, AttemptReference{AttemptID: attempt2, Kind: "practice"}, initRef2)
	if err != nil {
		t.Fatalf("SealApplication(full): %v", err)
	}
	value2, ok := pub2.Value.(lifecycle_rules.ApplicationValue)
	if !ok || len(value2.Facts) != 1 || value2.Facts[0].State != "committed" {
		t.Fatalf("full seal value = %#v, want one committed fact", pub2.Value)
	}
	if id, _ := value2.Facts[0].OriginApplicationID.(string); id != commitID {
		t.Fatalf("sealed origin application %q != committed %q", id, commitID)
	}
	if value2.Facts[0].JobID != "job-2" {
		t.Fatalf("sealed job %q, want job-2", value2.Facts[0].JobID)
	}
}

// The attempt binding is opaque and exact: foreign attempt material never
// selects or redirects an attempt, and global session identifiers carry no
// authority.
func TestOpaqueAttemptBindingPreventsGlobalSessionRedirection(t *testing.T) {
	store := openStore(t, "laboratory")
	handler := NewApplicationHandler(store)

	attemptA, _ := initAttempt(t, store, "bind-a", "laboratory", nil)
	attemptB, _ := initAttempt(t, store, "bind-b", "laboratory", nil)
	a := newFlow(t, handler, attemptA)
	b := newFlow(t, handler, attemptB)
	a.job("job-1")
	a.contact()
	revABefore := a.rev

	// B's coordinates presented against B reject on B's own state; A is
	// untouched: no redirection moves the effect across attempts.
	code, out := b.mutate(http.MethodPut, "/api/contact", map[string]any{
		"operation_key": b.key("contact"), "expected_revision": revABefore,
		"section_value_revision": 1, "validation_generation": 1,
		"data": map[string]any{"full_name": "Intruder", "email": "intruder@example.test"},
	})
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("foreign-coordinate contact: code %d, want rejection, body %v", code, out)
	}
	if _, draft := a.draft(); getInt(draft, "state_revision") != revABefore {
		t.Fatalf("attempt A moved to rev %d, want %d (no redirection)", getInt(draft, "state_revision"), revABefore)
	}

	// A global session pointing at B cannot redirect A's operation: the
	// effect lands on A exactly, and B never advances because of it.
	bRevBefore := b.rev
	rec := doRequest(t, handler, http.MethodPost,
		"/api/history/enter?attempt_id="+url.QueryEscape(attemptA)+"&session_id="+url.QueryEscape(attemptB),
		map[string]any{
			"attempt_id":    attemptA,
			"operation_key": a.key("enter"), "expected_revision": a.rev,
		},
		map[string]string{"Cookie": "session=" + attemptB},
	)
	if rec.Code != http.StatusOK {
		t.Fatalf("session-decorated enter: code %d, body %s", rec.Code, rec.Body.String())
	}
	enterAck := decodeBody(t, rec)
	a.rev = getInt(enterAck, "state_revision")
	if getString(enterAck, "workflow_state") != "HISTORY" {
		t.Fatalf("enter workflow = %q, want HISTORY", getString(enterAck, "workflow_state"))
	}
	if _, draft := b.draft(); getInt(draft, "state_revision") != bRevBefore {
		t.Fatalf("attempt B moved via session redirect to rev %d", getInt(draft, "state_revision"))
	}

	// An unknown attempt binds nothing.
	rec = doRequest(t, handler, http.MethodGet, "/api/draft?attempt_id=attempt-ghost", nil, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("ghost attempt draft code = %d, want 404", rec.Code)
	}

	// Ambiguous bindings (query names B, body names A) are rejected rather
	// than resolved by any global preference.
	rec = doRequest(t, handler, http.MethodPost, "/api/history/enter?attempt_id="+url.QueryEscape(attemptB),
		map[string]any{
			"attempt_id":    attemptA,
			"operation_key": a.key("enter"), "expected_revision": a.rev,
		}, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("ambiguous binding code = %d, want 400", rec.Code)
	}
}

// Application acknowledgement never waits for peer publication: with the
// observation peer closed and unusable, mutations still commit and
// acknowledge from the owner-local boundary alone.
func TestApplicationAcknowledgementDoesNotWaitForPeerPublication(t *testing.T) {
	appStore := openStore(t, "laboratory")
	peerHome := t.TempDir()
	peer, err := owner_store.OpenOwner(
		filepath.Join(peerHome, "observation.db"),
		filepath.Join(peerHome, "observation-artifacts"),
		"observation",
	)
	if err != nil {
		t.Fatalf("OpenOwner(peer): %v", err)
	}
	handler := NewApplicationHandler(appStore)
	attempt, _ := initAttempt(t, appStore, "solo", "laboratory", nil)

	// The peer becomes completely unusable before any application mutation.
	if err := peer.Close(); err != nil {
		t.Fatalf("close peer: %v", err)
	}

	f := newFlow(t, handler, attempt)
	jobAck := f.job("job-1")
	contactAck := f.contact()
	for name, ack := range map[string]map[string]any{"job": jobAck, "contact": contactAck} {
		raw, _ := json.Marshal(ack)
		for _, marker := range []string{"observation", "peer", "pending_publication", "publication_wait", "awaiting_peer"} {
			if strings.Contains(strings.ToLower(string(raw)), marker) {
				t.Fatalf("%s ack references peer publication (%s): %s", name, marker, raw)
			}
		}
	}
	if code, draft := f.draft(); code != http.StatusOK {
		t.Fatalf("draft with peer closed: code %d", code)
	} else if getInt(draft, "state_revision") != f.rev {
		t.Fatalf("draft rev %d !=flow rev %d", getInt(draft, "state_revision"), f.rev)
	}
}

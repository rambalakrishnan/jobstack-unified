package connector_queries

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	authority "authority"
	evidence_codec "evidence_codec"
	journal_rules "journal_rules"
	owner_store "owner_store"
)

// ---------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------

type testJournal struct {
	t         *testing.T
	store     *owner_store.OwnerStore
	ctx       context.Context
	domain    string
	journalID string
	manifest  journal_rules.Manifest
	envelopes []journal_rules.JournalEnvelope
}

func testPolicy(domain string) []byte {
	return []byte(fmt.Sprintf(
		`{"channels":{"channel-%s":{"principal":"writer-%s","kind":"owner","grants":[{"domain":"*","operations":["*"]}]}}}`,
		domain, domain))
}

func testContext(t *testing.T, domain string) context.Context {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, "http://connector-queries.test/"+domain, nil)
	if err != nil {
		t.Fatalf("build authentication request: %v", err)
	}
	request.Header.Set("Authorization", "Channel channel-"+domain)
	ctx, err := authority.Authenticate(request, testPolicy(domain))
	if err != nil {
		t.Fatalf("authenticate %s writer: %v", domain, err)
	}
	return ctx
}

func testManifest(domain, journalID string) journal_rules.Manifest {
	return journal_rules.Manifest{
		RecordType:    "manifest",
		SchemaVersion: "0.1.0",
		ManifestID:    "manifest-" + journalID,
		RunID:         "run-" + domain,
		JournalID:     journalID,
		OwnerDomain:   domain,
		Clocks: []journal_rules.ClockDescriptor{{
			ClockID: "clock-" + domain, BootID: "boot-" + domain,
			Origin: "engine_measured", SourceID: "connector-queries",
			Basis: "monotonic_offset", Unit: "ms",
		}},
	}
}

func testTimePoint(m journal_rules.Manifest, offset float64) journal_rules.TimePoint {
	clock := m.Clocks[0]
	return journal_rules.TimePoint{
		ClockID: clock.ClockID, BootID: clock.BootID, Origin: clock.Origin,
		MonotonicOffsetMs: offset, UTCAnnotation: journal_rules.NewMissing("not_applicable"),
	}
}

func newTestJournal(t *testing.T, journalID string) *testJournal {
	t.Helper()
	domain := "observation"
	home := t.TempDir()
	store, err := owner_store.OpenOwner(
		filepath.Join(home, domain+".db"), filepath.Join(home, "artifacts"), domain)
	if err != nil {
		t.Fatalf("OpenOwner: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	j := &testJournal{
		t:         t,
		store:     store,
		ctx:       testContext(t, domain),
		domain:    domain,
		journalID: journalID,
		manifest:  testManifest(domain, journalID),
	}
	rawManifest, err := json.Marshal(j.manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	canonical, err := evidence_codec.CanonicalJSON(rawManifest, "application/json")
	if err != nil {
		t.Fatalf("canonicalize manifest: %v", err)
	}
	ref, err := owner_store.InstallArtifact(j.ctx, store, bytes.NewReader(canonical), "application/json", "public")
	if err != nil {
		t.Fatalf("InstallArtifact(manifest): %v", err)
	}
	admission := owner_store.EventSubmission{
		ProducerSequence:   int64(1),
		EventKind:          "manifest_admitted",
		EventSchemaVersion: "0.1.0",
		OccurredAt:         testTimePoint(j.manifest, 0),
		Payload: journal_rules.Payload{
			Data:         map[string]any{"manifest": refMap(ref)},
			Measurements: []journal_rules.Measurement{},
			EvidenceRefs: []journal_rules.EvidenceRef{},
			ArtifactRefs: []journal_rules.ArtifactReference{ref},
		},
	}
	j.commit(admission)
	return j
}

func (j *testJournal) commit(subs ...owner_store.EventSubmission) []journal_rules.JournalEnvelope {
	j.t.Helper()
	envs, err := owner_store.CommitOwner(j.ctx, j.store, j.journalID, subs, nil)
	if err != nil {
		j.t.Fatalf("CommitOwner: %v", err)
	}
	j.envelopes = append(j.envelopes, envs...)
	return envs
}

func (j *testJournal) submission(producer int64, kind string, data map[string]any, refs ...journal_rules.ArtifactReference) owner_store.EventSubmission {
	if refs == nil {
		refs = []journal_rules.ArtifactReference{}
	}
	return owner_store.EventSubmission{
		ProducerSequence:   producer,
		EventKind:          kind,
		EventSchemaVersion: "0.1.0",
		OccurredAt:         testTimePoint(j.manifest, float64(producer)),
		Payload: journal_rules.Payload{
			Data:         data,
			Measurements: []journal_rules.Measurement{},
			EvidenceRefs: []journal_rules.EvidenceRef{},
			ArtifactRefs: refs,
		},
	}
}

func (j *testJournal) install(content []byte, mediaType string) journal_rules.ArtifactReference {
	j.t.Helper()
	ref, err := owner_store.InstallArtifact(j.ctx, j.store, bytes.NewReader(content), mediaType, "public")
	if err != nil {
		j.t.Fatalf("InstallArtifact: %v", err)
	}
	return ref
}

func (j *testJournal) prefix() journal_rules.JournalPrefix {
	last := j.envelopes[len(j.envelopes)-1]
	return journal_rules.JournalPrefix{JournalID: last.JournalID, LastSequence: last.Sequence, HeadHash: last.EventHash}
}

func (j *testJournal) prefixAt(seq int64) journal_rules.JournalPrefix {
	env := j.envelopes[seq-1]
	return journal_rules.JournalPrefix{JournalID: env.JournalID, LastSequence: env.Sequence, HeadHash: env.EventHash}
}

// seqRef cites an earlier retained event with an empty pointer.
func (j *testJournal) seqRef(seq int64) map[string]any {
	env := j.envelopes[seq-1]
	return map[string]any{
		"journal_id": env.JournalID,
		"sequence":   env.Sequence,
		"event_id":   env.EventID,
		"event_hash": env.EventHash,
		"pointer":    "",
	}
}

func refMap(ref journal_rules.ArtifactReference) map[string]any {
	return map[string]any{
		"digest":       ref.Digest,
		"size_bytes":   ref.SizeBytes,
		"media_type":   ref.MediaType,
		"owner_domain": ref.OwnerDomain,
		"access":       ref.Access,
	}
}

// ---------------------------------------------------------------------------
// Observation payload builders (all support cites sequence 1).
// ---------------------------------------------------------------------------

func (j *testJournal) nativeReportPayload(raw journal_rules.ArtifactReference) map[string]any {
	return map[string]any{
		"kind":         "native_report",
		"channel":      "terminal_response",
		"raw":          refMap(raw),
		"source_event": j.seqRef(1),
		"source_checks": map[string]any{
			"authentication": "verified",
			"correlation":    "matched",
		},
		"mapping": map[string]any{
			"id": "native-map", "version": "1", "artifact_digest": raw.Digest,
		},
		"normalized_claims": []any{},
		"limitations":       []any{"synthetic report carries no accepted claim"},
	}
}

func (j *testJournal) taskOutputPayload(name string, content journal_rules.ArtifactReference, bloat string) map[string]any {
	limitations := []any{"synthetic output for conformance"}
	if bloat != "" {
		limitations = []any{bloat}
	}
	return map[string]any{
		"kind": "task_output",
		"name": name,
		"output_schema": map[string]any{
			"id": "task-schema", "version": "1", "artifact_digest": content.Digest,
		},
		"content":       refMap(content),
		"completeness":  "complete",
		"evidence_refs": []any{j.seqRef(1)},
		"limitations":   limitations,
	}
}

func (j *testJournal) incidentPayload() map[string]any {
	return map[string]any{
		"kind":   "connector_incident",
		"code":   "producer_gap",
		"scope":  map[string]any{"kind": "handle", "id": j.journalID},
		"detail": "synthetic producer gap for conformance",
		"evidence_refs": []any{
			j.seqRef(1),
		},
	}
}

func (j *testJournal) slotPayload(name string, content journal_rules.ArtifactReference) map[string]any {
	return map[string]any{
		"kind": "artifact_available",
		"artifact": map[string]any{
			"name":            name,
			"expected_digest": content.Digest,
			"content":         refMap(content),
			"evidence_refs":   []any{j.seqRef(1)},
		},
	}
}

func controlPayload() map[string]any {
	return map[string]any{
		"kind": "control_observation",
		"observation": map[string]any{
			"operation": "Contain",
			"detail":    "synthetic control record for conformance",
		},
	}
}

func clockPayload(clockID, bootID string) map[string]any {
	// The journal stores the descriptor flat; projection normalizes it.
	return map[string]any{
		"kind":      "clock_registered",
		"clock_id":  clockID,
		"boot_id":   bootID,
		"origin":    "engine_measured",
		"source_id": "synthetic",
		"basis":     "monotonic_offset",
		"unit":      "ms",
	}
}

func (j *testJournal) contextPayload() map[string]any {
	return map[string]any{
		"kind":                 "context_observation",
		"domain":               "browser_state",
		"requested_policy_ref": j.seqRef(1),
		"realization":          "fresh",
		"context_ref":          "ctx-synthetic-1",
		"evidence_refs":        []any{j.seqRef(1)},
		"limitations":          []any{"synthetic context observation"},
	}
}

func (j *testJournal) lifecyclePayload(content journal_rules.ArtifactReference) map[string]any {
	return map[string]any{
		"kind": "lifecycle_publication",
		"publication": map[string]any{
			"schema_version":    "application-attempt-lifecycle/0.1.0",
			"attempt":           map[string]any{"attempt_id": "attempt-synthetic-1"},
			"commission_digest": content.Digest,
			"axis":              "observation",
			"revision":          1,
			"owner_domain":      "observation",
			"content":           refMap(content),
			"registration_ref":  j.seqRef(1),
		},
	}
}

func nonObsPayload(kind, note string) map[string]any {
	return map[string]any{"kind": kind, "note": note}
}

// ---------------------------------------------------------------------------
// Request/response helpers.
// ---------------------------------------------------------------------------

func handleMap(connectorID, localHandle string) map[string]any {
	return map[string]any{"connector_id": connectorID, "local_handle": localHandle}
}

func zeroCursor(connectorID, journalID string) map[string]any {
	return map[string]any{
		"handle":     handleMap(connectorID, journalID),
		"journal_id": journalID,
		"sequence":   0,
		"event_hash": map[string]any{"value": nil, "reason": "not_applicable"},
	}
}

func seqCursor(connectorID, journalID string, seq int64, hash string) map[string]any {
	return map[string]any{
		"handle":     handleMap(connectorID, journalID),
		"journal_id": journalID,
		"sequence":   seq,
		"event_hash": hash,
	}
}

func prefixMap(p journal_rules.JournalPrefix) map[string]any {
	return map[string]any{
		"journal_id": p.JournalID, "last_sequence": p.LastSequence, "head_hash": p.HeadHash,
	}
}

func liveThrough() map[string]any {
	return map[string]any{"value": nil, "reason": "not_applicable"}
}

func observePayload(t *testing.T, handle, after, through any, maxItems int64, wait float64) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"handle": handle, "after": after, "through": through,
		"max_items":  maxItems,
		"wait_limit": map[string]any{"kind": "exact", "unit": "ms", "value": wait},
	})
	if err != nil {
		t.Fatalf("marshal observe payload: %v", err)
	}
	return raw
}

func collectPayload(t *testing.T, handle, selector any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"handle": handle, "selector": selector})
	if err != nil {
		t.Fatalf("marshal collect payload: %v", err)
	}
	return raw
}

func connectorRequest(op, reqID, connID string, callMs float64, payload json.RawMessage) ConnectorRequest {
	return ConnectorRequest{
		RecordType:    RecordTypeRequest,
		SchemaVersion: SchemaVersion,
		RequestID:     reqID,
		ConnectorID:   connID,
		Operation:     op,
		CallLimit:     DurationLimit{Kind: "exact", Unit: "ms", Value: callMs},
		Payload:       payload,
	}
}

func doObserve(t *testing.T, j *testJournal, req ConnectorRequest) (ConnectorResponse, *ConnectorError) {
	t.Helper()
	resp, err := ObserveHandle(j.ctx, j.store, req)
	if err == nil {
		return resp, nil
	}
	cerr, ok := err.(*ConnectorError)
	if !ok {
		t.Fatalf("ObserveHandle returned non-connector error: %v", err)
	}
	return resp, cerr
}

func doCollect(t *testing.T, j *testJournal, req ConnectorRequest) (ConnectorResponse, *ConnectorError) {
	t.Helper()
	resp, err := CollectHandleArtifacts(j.ctx, j.store, req)
	if err == nil {
		return resp, nil
	}
	cerr, ok := err.(*ConnectorError)
	if !ok {
		t.Fatalf("CollectHandleArtifacts returned non-connector error: %v", err)
	}
	return resp, cerr
}

func decodeResult(t *testing.T, resp ConnectorResponse, out any) {
	t.Helper()
	if err := json.Unmarshal(resp.Result, out); err != nil {
		t.Fatalf("decode result: %v\n%s", err, resp.Result)
	}
}

func assertEnvelope(t *testing.T, req ConnectorRequest, resp ConnectorResponse) {
	t.Helper()
	if resp.RecordType != RecordTypeResponse {
		t.Fatalf("record_type = %q", resp.RecordType)
	}
	if resp.SchemaVersion != SchemaVersion {
		t.Fatalf("schema_version = %q", resp.SchemaVersion)
	}
	if resp.RequestID != req.RequestID || resp.ConnectorID != req.ConnectorID || resp.Operation != req.Operation {
		t.Fatalf("response identity %+v does not echo request", resp)
	}
}

func assertNoBareNulls(t *testing.T, raw json.RawMessage, what string) {
	t.Helper()
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("%s: result is not JSON: %v", what, err)
	}
	var walk func(path string, node any)
	walk = func(path string, node any) {
		switch n := node.(type) {
		case nil:
			t.Fatalf("%s: bare null at %s", what, path)
		case map[string]any:
			if value, ok := n["value"]; ok && value == nil {
				reason, _ := n["reason"].(string)
				if !nullReasons[reason] {
					t.Fatalf("%s: null value without EK NullReason at %s", what, path)
				}
				for k, child := range n {
					if k == "value" {
						continue
					}
					walk(path+"."+k, child)
				}
				return
			}
			for k, child := range n {
				walk(path+"."+k, child)
			}
		case []any:
			for i, child := range n {
				walk(fmt.Sprintf("%s[%d]", path, i), child)
			}
		}
	}
	walk("$", v)
}

func cursorHash(t *testing.T, c ObservationCursor) (string, bool) {
	t.Helper()
	trimmed := bytes.TrimSpace(c.EventHash)
	if len(trimmed) == 0 {
		t.Fatalf("cursor event_hash is empty")
	}
	if trimmed[0] == '"' {
		var s string
		if err := json.Unmarshal(c.EventHash, &s); err != nil {
			t.Fatalf("decode cursor hash: %v", err)
		}
		return s, false
	}
	var m Missing
	if err := json.Unmarshal(c.EventHash, &m); err != nil {
		t.Fatalf("decode cursor missing hash: %v", err)
	}
	return m.Reason, true
}

func itemSequences(items []ObservationItem) []int64 {
	out := make([]int64, 0, len(items))
	for _, it := range items {
		out = append(out, it.EventRef.Sequence)
	}
	return out
}

func equalInt64s(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Conformance assertions.
// ---------------------------------------------------------------------------

func TestObserveCursorAdvancesAcrossNonObservationPositions(t *testing.T) {
	const connectorID = "connector-a"
	j := newTestJournal(t, "handle-cursor-1")
	rawRef := j.install([]byte("native-body"), "application/octet-stream")
	outRef := j.install([]byte("task-output"), "application/json")
	slotRef := j.install([]byte("slot-bytes"), "application/octet-stream")
	pubRef := j.install([]byte("publication-bytes"), "application/json")

	j.commit(
		j.submission(2, "native_report", j.nativeReportPayload(rawRef), rawRef),
		j.submission(3, "dispatch_marker", nonObsPayload("dispatch_marker", "queued")),
		j.submission(4, "task_output", j.taskOutputPayload("extract", outRef, ""), outRef),
		j.submission(5, "internal_note", nonObsPayload("internal_note", "housekeeping")),
		j.submission(6, "artifact_available", j.slotPayload("report", slotRef), slotRef),
		j.submission(7, "connector_incident", j.incidentPayload()),
		j.submission(8, "control_observation", controlPayload()),
		j.submission(9, "clock_registered", clockPayload("clock-extra-1", "boot-extra-1")),
		j.submission(10, "context_observation", j.contextPayload()),
		j.submission(11, "lifecycle_publication", j.lifecyclePayload(pubRef), pubRef),
		j.submission(12, "observation_closed", nonObsPayload("observation_closed", "local drain complete")),
	)
	cutoff := j.prefix()
	if err := PublishLiveHead(cutoff); err != nil {
		t.Fatalf("PublishLiveHead: %v", err)
	}
	handle := handleMap(connectorID, j.journalID)

	// Full page: every observation kind projects, non-observation
	// positions are skipped for items but advance the cursor.
	req := connectorRequest(OpObserve, "t1-full", connectorID, 5000,
		observePayload(t, handle, zeroCursor(connectorID, j.journalID), prefixMap(cutoff), 10, 0))
	resp, cerr := doObserve(t, j, req)
	if cerr != nil {
		t.Fatalf("ObserveHandle: %v", cerr)
	}
	assertEnvelope(t, req, resp)
	assertNoBareNulls(t, resp.Result, "observation page")
	var page ObservationPage
	decodeResult(t, resp, &page)
	if page.Kind != "observation_page" {
		t.Fatalf("kind = %q", page.Kind)
	}
	want := []int64{2, 4, 6, 7, 8, 9, 10, 11}
	if got := itemSequences(page.Items); !equalInt64s(got, want) {
		t.Fatalf("item sequences = %v, want %v", got, want)
	}
	if page.Through != cutoff {
		t.Fatalf("through = %+v, want %+v", page.Through, cutoff)
	}
	if page.After.Sequence != 0 {
		t.Fatalf("after echo sequence = %d", page.After.Sequence)
	}
	// Next scanned through the trailing closure at 12 even though the
	// last item sits at 11.
	if page.Next.Sequence != 12 {
		t.Fatalf("next sequence = %d, want 12 (last scanned position)", page.Next.Sequence)
	}
	if hash, isMissing := cursorHash(t, page.Next); isMissing || hash != cutoff.HeadHash {
		t.Fatalf("next hash = %q (missing=%v), want head %q", hash, isMissing, cutoff.HeadHash)
	}
	if page.HasMore {
		t.Fatalf("has_more must be exactly next < cutoff (12 < 12 is false)")
	}
	for _, it := range page.Items {
		if !(0 < it.EventRef.Sequence && it.EventRef.Sequence <= page.Next.Sequence && page.Next.Sequence <= cutoff.LastSequence) {
			t.Fatalf("item %d violates cursor < item <= next <= cutoff", it.EventRef.Sequence)
		}
		if it.Provenance != "server" {
			t.Fatalf("item %d provenance = %q, want server", it.EventRef.Sequence, it.Provenance)
		}
		if it.Measurements == nil || it.ArtifactRefs == nil {
			t.Fatalf("item %d must carry (possibly empty) arrays, never null", it.EventRef.Sequence)
		}
		env := j.envelopes[it.EventRef.Sequence-1]
		if it.EventRef.EventID != env.EventID || it.EventRef.EventHash != env.EventHash {
			t.Fatalf("item %d metadata does not match its envelope", it.EventRef.Sequence)
		}
	}
	// Payload discriminators project per kind, including the normalized
	// clock shape.
	kinds := map[int64]string{}
	for _, it := range page.Items {
		kind, _ := it.Payload["kind"].(string)
		kinds[it.EventRef.Sequence] = kind
	}
	for seq, kind := range map[int64]string{
		2: "native_report", 4: "task_output", 6: "artifact_available",
		7: "connector_incident", 8: "control_observation", 9: "clock_registered",
		10: "context_observation", 11: "lifecycle_publication",
	} {
		if kinds[seq] != kind {
			t.Fatalf("sequence %d payload kind = %q, want %q", seq, kinds[seq], kind)
		}
	}
	clockPayload, _ := page.Items[5].Payload["clock"].(map[string]any)
	if clockPayload["clock_id"] != "clock-extra-1" {
		t.Fatalf("clock payload was not normalized from registration: %v", page.Items[5].Payload)
	}
	// Local closure is cited without claiming native termination.
	var closeRef EvidenceRef
	if err := json.Unmarshal(page.ObservationCloseRef, &closeRef); err != nil {
		t.Fatalf("close ref should cite the local closure event: %v", err)
	}
	if closeRef.Sequence != 12 {
		t.Fatalf("close ref sequence = %d, want 12", closeRef.Sequence)
	}

	// Pagination honors max_items while the cutoff stays fixed: pages
	// of 3, 3, 2 with next at 6, 9, 12.
	var union []int64
	after := any(zeroCursor(connectorID, j.journalID))
	for i, wantPage := range [][]int64{{2, 4, 6}, {7, 8, 9}, {10, 11}} {
		req := connectorRequest(OpObserve, fmt.Sprintf("t1-p%d", i+1), connectorID, 5000,
			observePayload(t, handle, after, prefixMap(cutoff), 3, 0))
		resp, cerr := doObserve(t, j, req)
		if cerr != nil {
			t.Fatalf("page %d: %v", i+1, cerr)
		}
		var p ObservationPage
		decodeResult(t, resp, &p)
		if got := itemSequences(p.Items); !equalInt64s(got, wantPage) {
			t.Fatalf("page %d sequences = %v, want %v", i+1, got, wantPage)
		}
		if p.Through != cutoff {
			t.Fatalf("page %d lost the fixed cutoff: %+v", i+1, p.Through)
		}
		union = append(union, itemSequences(p.Items)...)
		after = p.Next
		if i < 2 && !p.HasMore {
			t.Fatalf("page %d should report has_more", i+1)
		}
	}
	var last ObservationPage
	decodeResult(t, resp, &last)
	if last.Next.Sequence != 12 || last.HasMore {
		t.Fatalf("final page next=%d has_more=%v, want 12/false", last.Next.Sequence, last.HasMore)
	}
	if !equalInt64s(union, want) {
		t.Fatalf("paginated union = %v, want %v", union, want)
	}

	// A mid-journal cursor skips the non-observation at 5 silently in
	// the items while still scanning it.
	mid := connectorRequest(OpObserve, "t1-after4", connectorID, 5000,
		observePayload(t, handle, seqCursor(connectorID, j.journalID, 4, j.envelopes[3].EventHash), prefixMap(cutoff), 10, 0))
	resp, cerr = doObserve(t, j, mid)
	if cerr != nil {
		t.Fatalf("mid-journal observe: %v", cerr)
	}
	var midPage ObservationPage
	decodeResult(t, resp, &midPage)
	if got := itemSequences(midPage.Items); !equalInt64s(got, []int64{6, 7, 8, 9, 10, 11}) {
		t.Fatalf("mid-journal sequences = %v", got)
	}
	if midPage.Next.Sequence != 12 {
		t.Fatalf("mid-journal next = %d, want 12", midPage.Next.Sequence)
	}
}

func TestFixedObserveCutoffRemainsStableDuringLateEvidence(t *testing.T) {
	const connectorID = "connector-a"
	j := newTestJournal(t, "handle-cutoff-1")
	rawRef := j.install([]byte("native-body"), "application/octet-stream")
	outRef := j.install([]byte("task-output"), "application/json")
	j.commit(
		j.submission(2, "native_report", j.nativeReportPayload(rawRef), rawRef),
		j.submission(3, "task_output", j.taskOutputPayload("extract", outRef, ""), outRef),
	)
	fixed := j.prefix()
	handle := handleMap(connectorID, j.journalID)

	first := connectorRequest(OpObserve, "t2-first", connectorID, 5000,
		observePayload(t, handle, zeroCursor(connectorID, j.journalID), prefixMap(fixed), 10, 0))
	resp, cerr := doObserve(t, j, first)
	if cerr != nil {
		t.Fatalf("first observe: %v", cerr)
	}
	var firstPage ObservationPage
	decodeResult(t, resp, &firstPage)
	if firstPage.Through != fixed || len(firstPage.Items) != 2 {
		t.Fatalf("first page through=%+v items=%d", firstPage.Through, len(firstPage.Items))
	}

	// Late evidence arrives after the fixed cutoff was taken.
	lateRef := j.install([]byte("late-body"), "application/octet-stream")
	j.commit(j.submission(4, "native_report", j.nativeReportPayload(lateRef), lateRef))
	live := j.prefix()
	if err := PublishLiveHead(live); err != nil {
		t.Fatalf("PublishLiveHead: %v", err)
	}

	// The frozen continuation sees no late evidence and keeps its cutoff.
	cont := connectorRequest(OpObserve, "t2-frozen", connectorID, 5000,
		observePayload(t, handle, firstPage.Next, prefixMap(fixed), 10, 0))
	resp, cerr = doObserve(t, j, cont)
	if cerr != nil {
		t.Fatalf("frozen continuation: %v", cerr)
	}
	var frozen ObservationPage
	decodeResult(t, resp, &frozen)
	if frozen.Through != fixed {
		t.Fatalf("frozen page moved its cutoff to %+v", frozen.Through)
	}
	if len(frozen.Items) != 0 || frozen.HasMore {
		t.Fatalf("frozen page leaks late evidence: items=%d has_more=%v", len(frozen.Items), frozen.HasMore)
	}

	// A new live cutoff exposes the late evidence.
	fresh := connectorRequest(OpObserve, "t2-live", connectorID, 5000,
		observePayload(t, handle, firstPage.Next, prefixMap(live), 10, 0))
	resp, cerr = doObserve(t, j, fresh)
	if cerr != nil {
		t.Fatalf("live continuation: %v", cerr)
	}
	var livePage ObservationPage
	decodeResult(t, resp, &livePage)
	if livePage.Through != live {
		t.Fatalf("live page through=%+v, want %+v", livePage.Through, live)
	}
	if got := itemSequences(livePage.Items); !equalInt64s(got, []int64{4}) {
		t.Fatalf("live page sequences = %v, want [4]", got)
	}

	// The published live head also resolves an inapplicable through.
	viaHead := connectorRequest(OpObserve, "t2-head", connectorID, 5000,
		observePayload(t, handle, firstPage.Next, liveThrough(), 10, 100))
	resp, cerr = doObserve(t, j, viaHead)
	if cerr != nil {
		t.Fatalf("live-head observe: %v", cerr)
	}
	var headPage ObservationPage
	decodeResult(t, resp, &headPage)
	if headPage.Through != live {
		t.Fatalf("live-head page through=%+v, want %+v", headPage.Through, live)
	}
	if got := itemSequences(headPage.Items); !equalInt64s(got, []int64{4}) {
		t.Fatalf("live-head sequences = %v, want [4]", got)
	}

	// A fixed cutoff requires zero wait.
	waiting := connectorRequest(OpObserve, "t2-wait", connectorID, 5000,
		observePayload(t, handle, zeroCursor(connectorID, j.journalID), prefixMap(fixed), 10, 50))
	_, cerr = doObserve(t, j, waiting)
	if cerr == nil || cerr.Code != "INVALID_REQUEST" {
		t.Fatalf("fixed cutoff with wait should be INVALID_REQUEST, got %v", cerr)
	}
}

func TestOversizedObservationReturnsErrorWithoutSilentDropping(t *testing.T) {
	const connectorID = "connector-a"
	j := newTestJournal(t, "handle-oversize-1")
	rawRef := j.install([]byte("native-body"), "application/octet-stream")
	outRef := j.install([]byte("task-output"), "application/json")
	bloat := strings.Repeat("x", MaxObserveResponseBytes+1024)
	j.commit(
		j.submission(2, "native_report", j.nativeReportPayload(rawRef), rawRef),
		j.submission(3, "task_output", j.taskOutputPayload("huge", outRef, bloat), outRef),
	)
	cutoff := j.prefix()
	handle := handleMap(connectorID, j.journalID)

	req := connectorRequest(OpObserve, "t3-full", connectorID, 5000,
		observePayload(t, handle, zeroCursor(connectorID, j.journalID), prefixMap(cutoff), 10, 0))
	resp, cerr := doObserve(t, j, req)
	if cerr == nil {
		t.Fatalf("oversized observation should fail explicitly, not paginate silently")
	}
	if cerr.Code != "RESPONSE_TOO_LARGE" {
		t.Fatalf("code = %q, want RESPONSE_TOO_LARGE (%s)", cerr.Code, cerr.Detail)
	}
	if !strings.Contains(cerr.Detail, "sequence 3") || !strings.Contains(cerr.Detail, "not dropped") {
		t.Fatalf("detail should name the item and deny dropping: %q", cerr.Detail)
	}
	assertEnvelope(t, req, resp)
	var wire ConnectorError
	decodeResult(t, resp, &wire)
	if wire.Kind != "connector_error" || wire.EvidenceRefs == nil {
		t.Fatalf("error result must be a typed connector_error with an array: %+v", wire)
	}

	// The healthy prefix stays readable: nothing was corrupted or lost.
	healthy := connectorRequest(OpObserve, "t3-healthy", connectorID, 5000,
		observePayload(t, handle, zeroCursor(connectorID, j.journalID), prefixMap(j.prefixAt(2)), 10, 0))
	resp, cerr = doObserve(t, j, healthy)
	if cerr != nil {
		t.Fatalf("healthy prefix observe: %v", cerr)
	}
	var page ObservationPage
	decodeResult(t, resp, &page)
	if got := itemSequences(page.Items); !equalInt64s(got, []int64{2}) {
		t.Fatalf("healthy sequences = %v, want [2]", got)
	}
}

func TestLostCursorHistoryIsExplicitAndNeverSkipped(t *testing.T) {
	const connectorID = "connector-a"
	j := newTestJournal(t, "handle-cursor-2")
	rawRef := j.install([]byte("native-body"), "application/octet-stream")
	j.commit(j.submission(2, "native_report", j.nativeReportPayload(rawRef), rawRef))
	cutoff := j.prefix()
	handle := handleMap(connectorID, j.journalID)
	bogus := string(evidence_codec.HashBytes([]byte("bogus-history")))

	cases := []struct {
		name    string
		after   any
		through any
		code    string
	}{
		{"ahead of cutoff", seqCursor(connectorID, j.journalID, 99, bogus), prefixMap(cutoff), "CURSOR_INVALID"},
		{"hash mismatch in range", seqCursor(connectorID, j.journalID, 2, bogus), prefixMap(cutoff), "CURSOR_UNAVAILABLE"},
		{"zero with digest hash", seqCursor(connectorID, j.journalID, 0, cutoff.HeadHash), prefixMap(cutoff), "CURSOR_INVALID"},
		{"positive with missing hash", map[string]any{
			"handle": handleMap(connectorID, j.journalID), "journal_id": j.journalID,
			"sequence": 1, "event_hash": map[string]any{"value": nil, "reason": "not_applicable"},
		}, prefixMap(cutoff), "CURSOR_INVALID"},
	}
	for _, tc := range cases {
		req := connectorRequest(OpObserve, "t4-case", connectorID, 5000,
			observePayload(t, handle, tc.after, tc.through, 10, 0))
		_, cerr := doObserve(t, j, req)
		if cerr == nil {
			t.Fatalf("%s: expected an explicit error, got a page", tc.name)
		}
		if cerr.Code != tc.code {
			t.Fatalf("%s: code = %q, want %q (%s)", tc.name, cerr.Code, tc.code, cerr.Detail)
		}
	}

	// An unknown handle journal is explicit.
	unknownHandle := handleMap(connectorID, "handle-unknown-xyz")
	unknownReq := connectorRequest(OpObserve, "t4-unknown", connectorID, 5000,
		observePayload(t, unknownHandle, zeroCursor(connectorID, "handle-unknown-xyz"),
			prefixMap(journal_rules.JournalPrefix{JournalID: "handle-unknown-xyz", LastSequence: 1, HeadHash: bogus}), 10, 0))
	_, cerr := doObserve(t, j, unknownReq)
	if cerr == nil || cerr.Code != "UNKNOWN_HANDLE" {
		t.Fatalf("unknown handle should be UNKNOWN_HANDLE, got %v", cerr)
	}

	// Handle/cursor disagreement is a malformed request.
	foreignAfter := seqCursor("connector-b", j.journalID, 0, "")
	foreignAfter["handle"] = handleMap("connector-b", j.journalID)
	foreignAfter["event_hash"] = map[string]any{"value": nil, "reason": "not_applicable"}
	foreignReq := connectorRequest(OpObserve, "t4-foreign", connectorID, 5000,
		observePayload(t, handle, foreignAfter, prefixMap(cutoff), 10, 0))
	_, cerr = doObserve(t, j, foreignReq)
	if cerr == nil || cerr.Code != "INVALID_REQUEST" {
		t.Fatalf("handle disagreement should be INVALID_REQUEST, got %v", cerr)
	}

	// Malformed envelopes stay explicit: bad version, bad operation,
	// empty max_items, and wait beyond the call limit.
	badVersion := connectorRequest(OpObserve, "t4-version", connectorID, 5000,
		observePayload(t, handle, zeroCursor(connectorID, j.journalID), prefixMap(cutoff), 10, 0))
	badVersion.SchemaVersion = "external-connector/9.9.9"
	_, cerr = doObserve(t, j, badVersion)
	if cerr == nil || cerr.Code != "UNSUPPORTED_VERSION" {
		t.Fatalf("bad version should be UNSUPPORTED_VERSION, got %v", cerr)
	}
	badOp := connectorRequest("CollectArtifacts", "t4-op", connectorID, 5000,
		observePayload(t, handle, zeroCursor(connectorID, j.journalID), prefixMap(cutoff), 10, 0))
	_, cerr = doObserve(t, j, badOp)
	if cerr == nil || cerr.Code != "INVALID_REQUEST" {
		t.Fatalf("wrong operation should be INVALID_REQUEST, got %v", cerr)
	}
	emptyMax := connectorRequest(OpObserve, "t4-max", connectorID, 5000,
		observePayload(t, handle, zeroCursor(connectorID, j.journalID), prefixMap(cutoff), 0, 0))
	_, cerr = doObserve(t, j, emptyMax)
	if cerr == nil || cerr.Code != "INVALID_REQUEST" {
		t.Fatalf("max_items=0 should be INVALID_REQUEST, got %v", cerr)
	}
	overWait := connectorRequest(OpObserve, "t4-overwait", connectorID, 5000,
		observePayload(t, handle, zeroCursor(connectorID, j.journalID), liveThrough(), 10, 999999))
	_, cerr = doObserve(t, j, overWait)
	if cerr == nil || cerr.Code != "BUDGET_EXCEEDED" {
		t.Fatalf("wait beyond call limit should be BUDGET_EXCEEDED, got %v", cerr)
	}

	// An unauthenticated channel cannot read the journal.
	anonReq := connectorRequest(OpObserve, "t4-anon", connectorID, 5000,
		observePayload(t, handle, zeroCursor(connectorID, j.journalID), prefixMap(cutoff), 10, 0))
	_, err := ObserveHandle(context.Background(), j.store, anonReq)
	cerr, ok := err.(*ConnectorError)
	if !ok || cerr.Code != "FORBIDDEN" {
		t.Fatalf("unauthenticated observe should be FORBIDDEN, got %v", err)
	}
}

func TestEmptyObservationPageDoesNotImplyNativeTermination(t *testing.T) {
	const connectorID = "connector-a"
	j := newTestJournal(t, "handle-empty-1")
	j.commit(
		j.submission(2, "dispatch_marker", nonObsPayload("dispatch_marker", "queued")),
		j.submission(3, "internal_note", nonObsPayload("internal_note", "housekeeping")),
	)
	cutoff := j.prefix()
	handle := handleMap(connectorID, j.journalID)

	req := connectorRequest(OpObserve, "t5-empty", connectorID, 5000,
		observePayload(t, handle, zeroCursor(connectorID, j.journalID), prefixMap(cutoff), 10, 0))
	resp, cerr := doObserve(t, j, req)
	if cerr != nil {
		t.Fatalf("ObserveHandle: %v", cerr)
	}
	assertEnvelope(t, req, resp)
	assertNoBareNulls(t, resp.Result, "empty page")
	var page ObservationPage
	decodeResult(t, resp, &page)
	if page.Kind != "observation_page" {
		t.Fatalf("kind = %q", page.Kind)
	}
	if len(page.Items) != 0 {
		t.Fatalf("items should be empty, got %d", len(page.Items))
	}
	if !bytes.Contains(resp.Result, []byte(`"items":[]`)) {
		t.Fatalf("empty items must render as [], got %s", resp.Result)
	}
	if page.Next.Sequence != 3 || page.HasMore {
		t.Fatalf("next=%d has_more=%v, want 3/false", page.Next.Sequence, page.HasMore)
	}
	var closeMissing Missing
	if err := json.Unmarshal(page.ObservationCloseRef, &closeMissing); err != nil {
		t.Fatalf("close ref should be Missing(not_observed): %v", err)
	}
	if closeMissing.Reason != "not_observed" {
		t.Fatalf("close reason = %q, want not_observed", closeMissing.Reason)
	}
	joined := strings.Join(page.Limitations, "\n")
	if !strings.Contains(joined, "does not imply native termination") {
		t.Fatalf("limitations must deny termination: %q", joined)
	}
	if strings.Contains(strings.ToLower(string(resp.Result)), "native_terminated") {
		t.Fatalf("page must never claim native termination: %s", resp.Result)
	}

	// A continuation already at the head is equally empty and explicit.
	head := connectorRequest(OpObserve, "t5-head", connectorID, 5000,
		observePayload(t, handle, seqCursor(connectorID, j.journalID, 3, cutoff.HeadHash), prefixMap(cutoff), 10, 0))
	resp, cerr = doObserve(t, j, head)
	if cerr != nil {
		t.Fatalf("head continuation: %v", cerr)
	}
	var headPage ObservationPage
	decodeResult(t, resp, &headPage)
	if len(headPage.Items) != 0 || headPage.Next.Sequence != 3 || headPage.HasMore {
		t.Fatalf("head continuation = items %d next %d more %v",
			len(headPage.Items), headPage.Next.Sequence, headPage.HasMore)
	}
}

func TestArtifactChunksValidateDigestProgressBoundsAndEOF(t *testing.T) {
	const connectorID = "connector-a"
	j := newTestJournal(t, "handle-chunk-1")
	content := []byte("chunkable-artifact-bytes-0123456789-abcdefghijklmnopqrstuvwxyz-0123456789-abcdefghij")
	ref := j.install(content, "application/octet-stream")
	j.commit(j.submission(2, "artifact_available", j.slotPayload("blob", ref), ref))
	cutoff := j.prefix()
	if err := PublishLiveHead(cutoff); err != nil {
		t.Fatalf("PublishLiveHead: %v", err)
	}
	handle := handleMap(connectorID, j.journalID)
	size := int64(len(content))

	collect := func(reqID string, selector any) (ConnectorResponse, *ConnectorError) {
		req := connectorRequest(OpCollectArtifacts, reqID, connectorID, 5000,
			collectPayload(t, handle, selector))
		return doCollect(t, j, req)
	}
	bytesSelector := func(offset, max int64) map[string]any {
		return map[string]any{"mode": "bytes", "digest": ref.Digest, "offset": offset, "max_bytes": max}
	}

	// First window: digest, progress, bounds, and chunk digest verify.
	resp, cerr := collect("t6-c1", bytesSelector(0, 30))
	if cerr != nil {
		t.Fatalf("chunk 1: %v", cerr)
	}
	assertNoBareNulls(t, resp.Result, "chunk 1")
	var first ArtifactChunk
	decodeResult(t, resp, &first)
	if first.Kind != "artifact_chunk" || first.Digest != ref.Digest || first.SizeBytes != size {
		t.Fatalf("chunk 1 identity: %+v", first)
	}
	if first.Offset != 0 || first.ReturnedBytes != 30 || first.EndOfArtifact {
		t.Fatalf("chunk 1 window: offset=%d returned=%d eof=%v", first.Offset, first.ReturnedBytes, first.EndOfArtifact)
	}
	decoded, err := base64.StdEncoding.DecodeString(first.DataBase64)
	if err != nil {
		t.Fatalf("chunk 1 base64: %v", err)
	}
	if !bytes.Equal(decoded, content[:30]) {
		t.Fatalf("chunk 1 bytes mismatch")
	}
	if int64(len(decoded)) != first.ReturnedBytes {
		t.Fatalf("decoded size %d != returned %d", len(decoded), first.ReturnedBytes)
	}
	if first.ChunkDigest != string(evidence_codec.HashBytes(decoded)) {
		t.Fatalf("chunk 1 digest mismatch")
	}
	if len(first.EvidenceRefs) == 0 {
		t.Fatalf("chunk 1 must carry support")
	}

	// Second window reaches EOF exactly.
	resp, cerr = collect("t6-c2", bytesSelector(30, 1000))
	if cerr != nil {
		t.Fatalf("chunk 2: %v", cerr)
	}
	var second ArtifactChunk
	decodeResult(t, resp, &second)
	if second.ReturnedBytes != size-30 || !second.EndOfArtifact {
		t.Fatalf("chunk 2 window: returned=%d eof=%v", second.ReturnedBytes, second.EndOfArtifact)
	}
	decoded2, _ := base64.StdEncoding.DecodeString(second.DataBase64)
	if !bytes.Equal(decoded2, content[30:]) {
		t.Fatalf("chunk 2 bytes mismatch")
	}
	// The assembled bytes verify against the full registered digest.
	assembled := append(append([]byte{}, decoded...), decoded2...)
	if string(evidence_codec.HashBytes(assembled)) != ref.Digest {
		t.Fatalf("assembled bytes do not match the full digest")
	}

	// An EOF request may return zero bytes.
	resp, cerr = collect("t6-eof", bytesSelector(size, 10))
	if cerr != nil {
		t.Fatalf("eof chunk: %v", cerr)
	}
	var eof ArtifactChunk
	decodeResult(t, resp, &eof)
	if eof.ReturnedBytes != 0 || !eof.EndOfArtifact {
		t.Fatalf("eof window: returned=%d eof=%v", eof.ReturnedBytes, eof.EndOfArtifact)
	}
	if eof.DataBase64 != "" {
		t.Fatalf("eof data should be empty, got %q", eof.DataBase64)
	}

	// Offsets beyond EOF are rejected, never clamped silently.
	_, cerr = collect("t6-beyond", bytesSelector(size+1, 10))
	if cerr == nil || cerr.Code != "INVALID_REQUEST" {
		t.Fatalf("offset beyond EOF should be INVALID_REQUEST, got %v", cerr)
	}

	// Non-digest selectors are rejected without any fetch attempt.
	_, cerr = collect("t6-bad", map[string]any{
		"mode": "bytes", "digest": "not-a-digest", "offset": 0, "max_bytes": 10,
	})
	if cerr == nil || cerr.Code != "INVALID_REQUEST" {
		t.Fatalf("bad digest should be INVALID_REQUEST, got %v", cerr)
	}
}

func TestNamedArtifactRequestsReturnEveryRequestedMissingSlot(t *testing.T) {
	const connectorID = "connector-a"
	j := newTestJournal(t, "handle-named-1")
	alpha := j.install([]byte("alpha-bytes"), "application/octet-stream")
	beta := j.install([]byte("beta-bytes"), "application/octet-stream")
	j.commit(
		j.submission(2, "artifact_available", j.slotPayload("alpha", alpha), alpha),
		j.submission(3, "artifact_available", j.slotPayload("beta", beta), beta),
	)
	cutoff := j.prefix()
	if err := PublishLiveHead(cutoff); err != nil {
		t.Fatalf("PublishLiveHead: %v", err)
	}
	handle := handleMap(connectorID, j.journalID)

	req := connectorRequest(OpCollectArtifacts, "t7-named", connectorID, 5000,
		collectPayload(t, handle, map[string]any{"mode": "named", "names": []string{"alpha", "gamma", "beta"}}))
	resp, cerr := doCollect(t, j, req)
	if cerr != nil {
		t.Fatalf("named collect: %v", cerr)
	}
	assertEnvelope(t, req, resp)
	assertNoBareNulls(t, resp.Result, "named inventory")
	var inv ArtifactInventory
	decodeResult(t, resp, &inv)
	if inv.Kind != "artifact_inventory" || inv.EvidencePrefix != cutoff {
		t.Fatalf("inventory kind/prefix: %+v", inv)
	}
	if len(inv.Artifacts) != 3 {
		t.Fatalf("named inventory should return every requested slot, got %d", len(inv.Artifacts))
	}
	// Requested order is preserved and every name appears exactly once.
	for i, want := range []string{"alpha", "gamma", "beta"} {
		if inv.Artifacts[i].Name != want {
			t.Fatalf("slot %d = %q, want %q", i, inv.Artifacts[i].Name, want)
		}
	}
	seen := map[string]int{}
	for _, slot := range inv.Artifacts {
		seen[slot.Name]++
	}
	for _, name := range []string{"alpha", "gamma", "beta"} {
		if seen[name] != 1 {
			t.Fatalf("name %q appears %d times", name, seen[name])
		}
	}
	// Present slots resolve; the missing slot is explicit.
	var alphaContent ArtifactReference
	if err := json.Unmarshal(inv.Artifacts[0].Content, &alphaContent); err != nil {
		t.Fatalf("alpha content should resolve: %v", err)
	}
	if alphaContent.Digest != alpha.Digest {
		t.Fatalf("alpha digest = %q, want %q", alphaContent.Digest, alpha.Digest)
	}
	var gammaContent Missing
	if err := json.Unmarshal(inv.Artifacts[1].Content, &gammaContent); err != nil {
		t.Fatalf("gamma content should be Missing: %v", err)
	}
	if gammaContent.Reason != "not_observed" {
		t.Fatalf("gamma reason = %q", gammaContent.Reason)
	}
	if len(inv.Artifacts[1].EvidenceRefs) == 0 {
		t.Fatalf("missing slots still cite their inventory scope")
	}
	if inv.Coverage != "partial" {
		t.Fatalf("coverage = %q, want partial", inv.Coverage)
	}

	// A fully satisfied request reports complete coverage.
	allReq := connectorRequest(OpCollectArtifacts, "t7-all", connectorID, 5000,
		collectPayload(t, handle, map[string]any{"mode": "named", "names": []string{"alpha", "beta"}}))
	resp, cerr = doCollect(t, j, allReq)
	if cerr != nil {
		t.Fatalf("satisfied named collect: %v", cerr)
	}
	var all ArtifactInventory
	decodeResult(t, resp, &all)
	if all.Coverage != "complete" || len(all.Artifacts) != 2 {
		t.Fatalf("satisfied coverage=%q slots=%d", all.Coverage, len(all.Artifacts))
	}

	// Full inventory enumerates every registered slot.
	invReq := connectorRequest(OpCollectArtifacts, "t7-inv", connectorID, 5000,
		collectPayload(t, handle, map[string]any{"mode": "inventory"}))
	resp, cerr = doCollect(t, j, invReq)
	if cerr != nil {
		t.Fatalf("inventory collect: %v", cerr)
	}
	var full ArtifactInventory
	decodeResult(t, resp, &full)
	if full.Coverage != "complete" || len(full.Artifacts) != 2 {
		t.Fatalf("full inventory coverage=%q slots=%d", full.Coverage, len(full.Artifacts))
	}
}

func TestArtifactCollectionNeverRerunsWorkflowActions(t *testing.T) {
	const connectorID = "connector-a"
	j := newTestJournal(t, "handle-collect-1")
	registered := j.install([]byte("registered-bytes"), "application/octet-stream")
	// Installed in the store but never registered in the handle journal.
	unregistered := j.install([]byte("unregistered-bytes"), "application/octet-stream")
	j.commit(j.submission(2, "artifact_available", j.slotPayload("doc", registered), registered))
	before := j.prefix()
	if err := PublishLiveHead(before); err != nil {
		t.Fatalf("PublishLiveHead: %v", err)
	}
	handle := handleMap(connectorID, j.journalID)

	collect := func(reqID string, selector any) (ConnectorResponse, *ConnectorError) {
		req := connectorRequest(OpCollectArtifacts, reqID, connectorID, 5000,
			collectPayload(t, handle, selector))
		resp, cerr := doCollect(t, j, req)
		if cerr == nil {
			assertNoBareNulls(t, resp.Result, reqID)
		}
		return resp, cerr
	}

	// Reads succeed across all selector modes.
	if _, cerr := collect("t8-inv", map[string]any{"mode": "inventory"}); cerr != nil {
		t.Fatalf("inventory: %v", cerr)
	}
	if _, cerr := collect("t8-named", map[string]any{"mode": "named", "names": []string{"doc"}}); cerr != nil {
		t.Fatalf("named: %v", cerr)
	}
	if _, cerr := collect("t8-bytes", map[string]any{
		"mode": "bytes", "digest": registered.Digest, "offset": 0, "max_bytes": 4,
	}); cerr != nil {
		t.Fatalf("bytes: %v", cerr)
	}

	// Installed-but-unregistered bytes are not served: registration in
	// the handle journal is checked before any store read.
	_, cerr := collect("t8-unreg", map[string]any{
		"mode": "bytes", "digest": unregistered.Digest, "offset": 0, "max_bytes": 4,
	})
	if cerr == nil || cerr.Code != "ARTIFACT_UNAVAILABLE" {
		t.Fatalf("unregistered digest should be ARTIFACT_UNAVAILABLE, got %v", cerr)
	}
	// URLs and paths are never fetched; they are not even digests.
	_, cerr = collect("t8-url", map[string]any{
		"mode": "bytes", "digest": "https://example.com/evil.bin", "offset": 0, "max_bytes": 4,
	})
	if cerr == nil || cerr.Code != "INVALID_REQUEST" {
		t.Fatalf("URL digest should be INVALID_REQUEST, got %v", cerr)
	}
	neverSeen := string(evidence_codec.HashBytes([]byte("never-installed")))
	_, cerr = collect("t8-unknown", map[string]any{
		"mode": "bytes", "digest": neverSeen, "offset": 0, "max_bytes": 4,
	})
	if cerr == nil || cerr.Code != "ARTIFACT_UNAVAILABLE" {
		t.Fatalf("unknown digest should be ARTIFACT_UNAVAILABLE, got %v", cerr)
	}

	// Idempotency: an identical retry returns the retained receipt
	// without another effect; conflicting content is rejected.
	first, cerr := collect("t8-same", map[string]any{"mode": "inventory"})
	if cerr != nil {
		t.Fatalf("first collect: %v", cerr)
	}
	replay, cerr := collect("t8-same", map[string]any{"mode": "inventory"})
	if cerr != nil {
		t.Fatalf("identical retry: %v", cerr)
	}
	if !bytes.Equal(first.Result, replay.Result) {
		t.Fatalf("identical retry did not return the retained receipt")
	}
	_, cerr = collect("t8-same", map[string]any{"mode": "named", "names": []string{"doc"}})
	if cerr == nil || cerr.Code != "IDEMPOTENCY_CONFLICT" {
		t.Fatalf("conflicting content should be IDEMPOTENCY_CONFLICT, got %v", cerr)
	}

	// None of the collects above journaled anything: the retained
	// prefix is byte-identical to before.
	loaded, err := owner_store.LoadPrefix(j.ctx, j.store, before)
	if err != nil {
		t.Fatalf("reload prefix: %v", err)
	}
	if len(loaded) != 2 {
		t.Fatalf("collects must not append journal events: %d events", len(loaded))
	}

	// A recorded receipt never changes when newer artifacts arrive.
	doc2 := j.install([]byte("doc2-bytes"), "application/octet-stream")
	j.commit(j.submission(3, "artifact_available", j.slotPayload("doc2", doc2), doc2))
	after := j.prefix()
	if err := PublishLiveHead(after); err != nil {
		t.Fatalf("PublishLiveHead: %v", err)
	}
	stale, cerr := collect("t8-same", map[string]any{"mode": "inventory"})
	if cerr != nil {
		t.Fatalf("retained retry after late evidence: %v", cerr)
	}
	if !bytes.Equal(first.Result, stale.Result) {
		t.Fatalf("recorded receipt changed when newer artifacts arrived")
	}
	fresh, cerr := collect("t8-fresh", map[string]any{"mode": "inventory"})
	if cerr != nil {
		t.Fatalf("fresh collect: %v", cerr)
	}
	var freshInv ArtifactInventory
	decodeResult(t, fresh, &freshInv)
	if len(freshInv.Artifacts) != 2 || freshInv.EvidencePrefix != after {
		t.Fatalf("fresh inventory should see the late slot: %+v", freshInv)
	}

	// The journal advanced only by the explicit test commit: still
	// exactly one event per committed submission, nothing rerun.
	loaded, err = owner_store.LoadPrefix(j.ctx, j.store, after)
	if err != nil {
		t.Fatalf("reload after prefix: %v", err)
	}
	if len(loaded) != 3 {
		t.Fatalf("journal holds %d events, want exactly 3", len(loaded))
	}

	// Operation mismatch stays explicit on the collect entry point too.
	wrongOp := connectorRequest(OpObserve, "t8-op", connectorID, 5000,
		collectPayload(t, handle, map[string]any{"mode": "inventory"}))
	_, cerr = doCollect(t, j, wrongOp)
	if cerr == nil || cerr.Code != "INVALID_REQUEST" {
		t.Fatalf("wrong operation should be INVALID_REQUEST, got %v", cerr)
	}
}

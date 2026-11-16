package evidence_import

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"testing"

	authority "authority"
	evidence_codec "evidence_codec"
	journal_rules "journal_rules"
	owner_store "owner_store"
)

// ---------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------

type destFixture struct {
	t            *testing.T
	store        *owner_store.OwnerStore
	ctx          context.Context
	dbPath       string
	artifactRoot string
	domain       string
}

func newDestFixture(t *testing.T, domain string) *destFixture {
	t.Helper()
	home := t.TempDir()
	f := &destFixture{
		t:            t,
		dbPath:       filepath.Join(home, domain+".db"),
		artifactRoot: filepath.Join(home, domain+"-artifacts"),
		domain:       domain,
	}
	store, err := owner_store.OpenOwner(f.dbPath, f.artifactRoot, domain)
	if err != nil {
		t.Fatalf("OpenOwner(%s): %v", domain, err)
	}
	f.store = store
	t.Cleanup(func() { _ = f.store.Close() })
	f.ctx = testContext(t, domain)
	return f
}

func testPolicy(domain string) []byte {
	return []byte(fmt.Sprintf(
		`{"channels":{"channel-%s":{"principal":"writer-%s","kind":"owner","grants":[{"domain":"*","operations":["*"]}]}}}`,
		domain, domain))
}

func testContext(t *testing.T, domain string) context.Context {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, "http://evidence-import.test/"+domain, nil)
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

func installPolicy(t *testing.T, ctx context.Context, store *owner_store.OwnerStore, sourceID, version string) VersionPin {
	t.Helper()
	doc := map[string]any{
		"policy_id":          sourceID,
		"version":            version,
		"authorized_sources": []string{sourceID},
		"verification_kind":  "pinned_contract_presence",
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal policy: %v", err)
	}
	ref, err := owner_store.InstallArtifact(ctx, store, bytes.NewReader(raw), "application/json", "public")
	if err != nil {
		t.Fatalf("InstallArtifact(policy): %v", err)
	}
	return VersionPin{ID: sourceID, Version: version, ArtifactDigest: string(ref.Digest)}
}

// sourceSpec describes one tail event (sequence >= 2) of a source journal.
type sourceSpec struct {
	EventID    string
	Kind       string
	Role       string
	Assertion  string
	Provenance string
	Scope      string
	ProducerID string
	Data       map[string]any
}

func testSourceClock() journal_rules.ClockDescriptor {
	return journal_rules.ClockDescriptor{
		ClockID: "src-clock", BootID: "src-boot", Origin: "engine_measured",
		SourceID: "src", Basis: "monotonic_offset", Unit: "ms",
	}
}

func testSourceManifest(journalID, runID, owner string) Manifest {
	return Manifest{
		RecordType:    "manifest",
		SchemaVersion: "0.1.0",
		ManifestID:    "manifest-" + journalID,
		RunID:         runID,
		JournalID:     journalID,
		OwnerDomain:   owner,
		Clocks:        []journal_rules.ClockDescriptor{testSourceClock()},
	}
}

func testSourceTimePoint(offset float64) journal_rules.TimePoint {
	return journal_rules.TimePoint{
		ClockID: "src-clock", BootID: "src-boot", Origin: "engine_measured",
		MonotonicOffsetMs: offset, UTCAnnotation: journal_rules.NewMissing("not_applicable"),
	}
}

func manifestDigest(t *testing.T, m Manifest) string {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	canonical, err := evidence_codec.CanonicalJSON(raw, "application/json")
	if err != nil {
		t.Fatalf("canonicalize manifest: %v", err)
	}
	return string(evidence_codec.HashBytes(canonical))
}

func finalizeSourceEnvelope(t *testing.T, ev *JournalEnvelope) {
	t.Helper()
	if ev.CausalRefs == nil {
		ev.CausalRefs = []EvidenceRef{}
	}
	if ev.Payload.Data == nil {
		ev.Payload.Data = map[string]any{}
	}
	if ev.Payload.Measurements == nil {
		ev.Payload.Measurements = []journal_rules.Measurement{}
	}
	if ev.Payload.EvidenceRefs == nil {
		ev.Payload.EvidenceRefs = []EvidenceRef{}
	}
	if ev.Payload.ArtifactRefs == nil {
		ev.Payload.ArtifactRefs = []ArtifactReference{}
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("envelope is not an object")
	}
	delete(m, "event_hash")
	if m["causal_refs"] == nil {
		m["causal_refs"] = []any{}
	}
	if m["payload"] == nil {
		m["payload"] = map[string]any{}
	}
	remarshaled, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("re-encode envelope: %v", err)
	}
	canonical, err := evidence_codec.CanonicalJSON(remarshaled, "application/json")
	if err != nil {
		t.Fatalf("canonicalize envelope: %v", err)
	}
	ev.EventHash = string(evidence_codec.HashBytes(canonical))
}

// buildSourceChain creates a valid source journal: sequence 1 admission plus
// one event per tail spec. It validates the result and returns the events
// with their verified prefix.
func buildSourceChain(t *testing.T, m Manifest, tail []sourceSpec) ([]JournalEnvelope, JournalPrefix) {
	t.Helper()
	digest := manifestDigest(t, m)
	events := make([]JournalEnvelope, 0, 1+len(tail))
	ev1 := JournalEnvelope{
		RecordType: "journal_event", SchemaVersion: "0.1.0",
		RunID: m.RunID, JournalID: m.JournalID, ManifestHash: digest,
		Sequence: 1, EventID: "evt-" + m.JournalID + "-admit",
		EventKind: "manifest_admitted", EventSchemaVersion: "0.1.0",
		Role: "external_input", AssertionKind: "authoritative_effect",
		OwnerDomain: m.OwnerDomain, ProducerID: "kernel", ProducerSequence: int64(1),
		Provenance: "server", EvidenceScope: "current_run",
		RecordedAt: testSourceTimePoint(1010), OccurredAt: journal_rules.NewMissing("not_observed"),
		CausalRefs: []EvidenceRef{},
		Payload: journal_rules.Payload{
			Data: map[string]any{
				"manifest": map[string]any{
					"digest": digest, "size_bytes": int64(123),
					"media_type": "application/json", "owner_domain": m.OwnerDomain, "access": "restricted",
				},
			},
			Measurements: []journal_rules.Measurement{},
			EvidenceRefs: []EvidenceRef{},
			ArtifactRefs: []ArtifactReference{},
		},
		PreviousEventHash: journal_rules.NewMissing("not_applicable"),
		EventHash:         "",
	}
	finalizeSourceEnvelope(t, &ev1)
	events = append(events, ev1)
	for i, spec := range tail {
		seq := int64(i + 2)
		eventID := spec.EventID
		if eventID == "" {
			eventID = fmt.Sprintf("evt-%s-%d", m.JournalID, seq)
		}
		producer := spec.ProducerID
		if producer == "" {
			producer = "recorder-1"
		}
		data := spec.Data
		if data == nil {
			data = map[string]any{"note": fmt.Sprintf("source event %d", seq)}
		}
		ev := JournalEnvelope{
			RecordType: "journal_event", SchemaVersion: "0.1.0",
			RunID: m.RunID, JournalID: m.JournalID, ManifestHash: digest,
			Sequence: seq, EventID: eventID,
			EventKind: spec.Kind, EventSchemaVersion: "0.1.0",
			Role: spec.Role, AssertionKind: spec.Assertion,
			OwnerDomain: m.OwnerDomain, ProducerID: producer, ProducerSequence: seq,
			Provenance: spec.Provenance, EvidenceScope: spec.Scope,
			RecordedAt: testSourceTimePoint(float64(1000 + seq*10)), OccurredAt: journal_rules.NewMissing("not_observed"),
			CausalRefs: []EvidenceRef{},
			Payload: journal_rules.Payload{
				Data:         data,
				Measurements: []journal_rules.Measurement{},
				EvidenceRefs: []EvidenceRef{},
				ArtifactRefs: []ArtifactReference{},
			},
			PreviousEventHash: events[len(events)-1].EventHash,
			EventHash:         "",
		}
		finalizeSourceEnvelope(t, &ev)
		events = append(events, ev)
	}
	prefix, err := journal_rules.ValidateJournal(m, events)
	if err != nil {
		t.Fatalf("source fixture validation: %v", err)
	}
	return events, prefix
}

func loadLocalEvents(t *testing.T, f *destFixture, refs []EvidenceRef) []owner_store.JournalEnvelope {
	t.Helper()
	if len(refs) == 0 {
		t.Fatalf("no refs to load")
	}
	last := refs[len(refs)-1]
	prefix := owner_store.JournalPrefix{
		JournalID: last.JournalID, LastSequence: last.Sequence, HeadHash: last.EventHash,
	}
	events, err := owner_store.LoadPrefix(f.ctx, f.store, prefix)
	if err != nil {
		t.Fatalf("LoadPrefix(%+v): %v", prefix, err)
	}
	return events
}

func requireString(t *testing.T, data map[string]any, key, want string) {
	t.Helper()
	got, ok := data[key].(string)
	if !ok {
		t.Fatalf("payload data[%q] = %T (%v), want string %q", key, data[key], data[key], want)
	}
	if got != want {
		t.Fatalf("payload data[%q] = %q, want %q", key, got, want)
	}
}

func asInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case int:
		return int64(n), true
	case int32:
		return int64(n), true
	case float64:
		return int64(n), true
	case float32:
		return int64(n), true
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return i, true
		}
	}
	return 0, false
}

func requireInt(t *testing.T, data map[string]any, key string, want int64) {
	t.Helper()
	got, ok := asInt64(data[key])
	if !ok {
		t.Fatalf("payload data[%q] = %T (%v), want int %d", key, data[key], data[key], want)
	}
	if got != want {
		t.Fatalf("payload data[%q] = %d, want %d", key, got, want)
	}
}

// ---------------------------------------------------------------------------
// Conformance assertions.
// ---------------------------------------------------------------------------

// Historical imports must remain historical-unscored evidence: the import
// preserves the original scope and trust instead of promoting the event to
// current-run by the act of import.
func TestHistoricalImportsRemainHistoricalUnscoredEvidence(t *testing.T) {
	f := newDestFixture(t, "observation")
	policy := installPolicy(t, f.ctx, f.store, "src-historical", "v1")
	srcManifest := testSourceManifest("journal-historical", "run-historical", "source-domain")
	source, srcPrefix := buildSourceChain(t, srcManifest, []sourceSpec{{
		EventID:    "evt-historical-1",
		Kind:       "historical_noted",
		Role:       "lifecycle_observation",
		Assertion:  "observation",
		Provenance: "manual_observer",
		Scope:      "historical_unscored",
		ProducerID: "historian-1",
		Data:       map[string]any{"finding": "cancel routes returned 404"},
	}})

	refs, err := ImportSourcePrefix(f.ctx, f.store, srcManifest, srcPrefix, source, policy)
	if err != nil {
		t.Fatalf("ImportSourcePrefix: %v", err)
	}
	if len(refs) != len(source) {
		t.Fatalf("refs = %d, want %d", len(refs), len(source))
	}
	for _, ref := range refs {
		if ref.JournalID == srcPrefix.JournalID {
			t.Fatalf("import ref cites source journal %q: must cite the local import journal", ref.JournalID)
		}
		if ref.JournalID != "import-"+srcPrefix.JournalID {
			t.Fatalf("import ref journal = %q, want %q", ref.JournalID, "import-"+srcPrefix.JournalID)
		}
	}
	// Source sequences are never copied into the local sequence field.
	for i := range refs {
		if refs[i].Sequence == source[i].Sequence && len(source) > 1 {
			// Local journal carries its own admission at 1, so import
			// positions necessarily differ from source positions.
			t.Fatalf("import %d reuses source sequence %d as its local sequence", i, source[i].Sequence)
		}
	}

	local := loadLocalEvents(t, f, refs)
	if int64(len(local)) != refs[len(refs)-1].Sequence {
		t.Fatalf("local journal holds %d events, head refs sequence %d", len(local), refs[len(refs)-1].Sequence)
	}
	// Local head is admission plus one import per source event.
	if len(local) != 1+len(source) {
		t.Fatalf("local journal holds %d events, want %d (admission + imports)", len(local), 1+len(source))
	}
	if local[0].EventKind != "manifest_admitted" {
		t.Fatalf("local sequence 1 kind = %q, want manifest_admitted", local[0].EventKind)
	}
	for i, src := range source {
		imp := local[i+1]
		if imp.EventKind != "source_imported" {
			t.Fatalf("import %d kind = %q, want source_imported (must not become an application effect)", i, imp.EventKind)
		}
		if imp.JournalID != refs[i].JournalID || imp.Sequence != refs[i].Sequence ||
			imp.EventID != refs[i].EventID || imp.EventHash != refs[i].EventHash {
			t.Fatalf("import %d envelope does not match returned ref %+v", i, refs[i])
		}
		requireString(t, imp.Payload.Data, "original_evidence_scope", src.EvidenceScope)
		if got := imp.Payload.Data["original_evidence_scope"]; got == "current_run" && src.EvidenceScope != "current_run" {
			t.Fatalf("import %d promoted %q to current_run", i, src.EvidenceScope)
		}
	}
	// The historical tail event specifically retains its scope.
	historical := local[2]
	requireString(t, historical.Payload.Data, "original_evidence_scope", "historical_unscored")
	requireString(t, historical.Payload.Data, "original_provenance", "manual_observer")
	requireString(t, historical.Payload.Data, "source_event_kind", "historical_noted")
	requireInt(t, historical.Payload.Data, "source_sequence", 2)
	// Every nested artifact appears in artifact_refs.
	if len(historical.Payload.ArtifactRefs) != 3 {
		t.Fatalf("historical import lists %d artifacts, want 3 (envelope, manifest, checks)", len(historical.Payload.ArtifactRefs))
	}
	for _, key := range []string{"source_envelope", "source_manifest", "source_checks"} {
		nested, ok := historical.Payload.Data[key].(map[string]any)
		if !ok {
			t.Fatalf("payload data[%q] is %T, want artifact object", key, historical.Payload.Data[key])
		}
		digest, _ := nested["digest"].(string)
		found := false
		for _, ref := range historical.Payload.ArtifactRefs {
			if ref.Digest == digest {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("nested artifact %q (%s) is not listed in artifact_refs", key, digest)
		}
	}
}

// Synthetic-backend imports must retain synthetic evidence scope: import
// never promotes a synthetic response into current-run production evidence.
func TestSyntheticBackendImportsRetainSyntheticEvidenceScope(t *testing.T) {
	f := newDestFixture(t, "observation")
	policy := installPolicy(t, f.ctx, f.store, "src-synthetic", "v3")
	srcManifest := testSourceManifest("journal-synthetic", "run-synthetic", "synthetic-backend")
	source, srcPrefix := buildSourceChain(t, srcManifest, []sourceSpec{{
		EventID:    "evt-synthetic-1",
		Kind:       "synthetic_response",
		Role:       "derived_output",
		Assertion:  "observation",
		Provenance: "connector",
		Scope:      "synthetic",
		ProducerID: "synthetic-producer",
		Data:       map[string]any{"response": "synthetic backend output"},
	}})

	refs, err := ImportSourcePrefix(f.ctx, f.store, srcManifest, srcPrefix, source, policy)
	if err != nil {
		t.Fatalf("ImportSourcePrefix: %v", err)
	}
	if len(refs) != len(source) {
		t.Fatalf("refs = %d, want %d", len(refs), len(source))
	}
	local := loadLocalEvents(t, f, refs)
	if len(local) != 1+len(source) {
		t.Fatalf("local journal holds %d events, want %d", len(local), 1+len(source))
	}
	synth := local[2]
	requireString(t, synth.Payload.Data, "original_evidence_scope", "synthetic")
	requireString(t, synth.Payload.Data, "original_provenance", "connector")
	requireString(t, synth.Payload.Data, "source_event_kind", "synthetic_response")
	if got := synth.Payload.Data["original_evidence_scope"]; got == "current_run" {
		t.Fatal("synthetic import was promoted to current_run")
	}
	// The import record itself is not relabeled as a locally authored
	// application effect.
	if synth.EventKind != "source_imported" {
		t.Fatalf("import kind = %q, want source_imported", synth.EventKind)
	}
	requireString(t, synth.Payload.Data, "original_owner_domain", "synthetic-backend")
	requireString(t, synth.Payload.Data, "original_producer_id", "synthetic-producer")
}

// Identical source imports must deduplicate without new effects: a
// byte-identical re-import returns the original refs and leaves the local
// head untouched.
func TestIdenticalSourceImportsDeduplicateWithoutNewEffects(t *testing.T) {
	f := newDestFixture(t, "observation")
	policy := installPolicy(t, f.ctx, f.store, "src-dedupe", "v1")
	srcManifest := testSourceManifest("journal-dedupe", "run-dedupe", "source-domain")
	source, srcPrefix := buildSourceChain(t, srcManifest, []sourceSpec{
		{
			EventID: "evt-dedupe-1", Kind: "observation_noted",
			Role: "derived_output", Assertion: "authoritative_effect",
			Provenance: "server", Scope: "current_run",
			Data: map[string]any{"note": "first"},
		},
		{
			EventID: "evt-dedupe-2", Kind: "observation_noted",
			Role: "derived_output", Assertion: "authoritative_effect",
			Provenance: "server", Scope: "current_run",
			Data: map[string]any{"note": "second"},
		},
	})

	first, err := ImportSourcePrefix(f.ctx, f.store, srcManifest, srcPrefix, source, policy)
	if err != nil {
		t.Fatalf("first import: %v", err)
	}
	before := loadLocalEvents(t, f, first)
	headBefore := before[len(before)-1].EventHash
	seqBefore := before[len(before)-1].Sequence

	second, err := ImportSourcePrefix(f.ctx, f.store, srcManifest, srcPrefix, source, policy)
	if err != nil {
		t.Fatalf("identical re-import: %v", err)
	}
	if len(first) != len(second) {
		t.Fatalf("first refs = %d, second = %d", len(first), len(second))
	}
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("ref %d differs: first %+v, second %+v (identical imports must deduplicate)", i, first[i], second[i])
		}
	}
	after := loadLocalEvents(t, f, second)
	if len(after) != len(before) {
		t.Fatalf("local journal grew from %d to %d events on identical re-import", len(before), len(after))
	}
	if after[len(after)-1].EventHash != headBefore || after[len(after)-1].Sequence != seqBefore {
		t.Fatal("local head moved on identical re-import: no new effects are permitted")
	}
}

// Conflicting bytes under the same source identity must raise an integrity
// incident: the same source sequence/event with different content never
// overwrites the retained import.
func TestConflictingSourceIdentityBytesRaiseIntegrityIncident(t *testing.T) {
	f := newDestFixture(t, "observation")
	policy := installPolicy(t, f.ctx, f.store, "src-conflict", "v1")
	srcManifest := testSourceManifest("journal-conflict", "run-conflict", "source-domain")
	original, originalPrefix := buildSourceChain(t, srcManifest, []sourceSpec{{
		EventID: "evt-conflict-stable", Kind: "observation_noted",
		Role: "derived_output", Assertion: "authoritative_effect",
		Provenance: "server", Scope: "current_run",
		Data: map[string]any{"note": "original bytes"},
	}})
	first, err := ImportSourcePrefix(f.ctx, f.store, srcManifest, originalPrefix, original, policy)
	if err != nil {
		t.Fatalf("first import: %v", err)
	}
	before := loadLocalEvents(t, f, first)

	// Same source identity (journal, sequence, event ID) with different
	// bytes: a valid journal on its own with a different head hash.
	conflicting, conflictingPrefix := buildSourceChain(t, srcManifest, []sourceSpec{{
		EventID: "evt-conflict-stable", Kind: "observation_noted",
		Role: "derived_output", Assertion: "authoritative_effect",
		Provenance: "server", Scope: "current_run",
		Data: map[string]any{"note": "CONFLICTING bytes"},
	}})
	if conflictingPrefix.HeadHash == originalPrefix.HeadHash {
		t.Fatal("conflicting fixture must differ in bytes and head hash")
	}
	_, err = ImportSourcePrefix(f.ctx, f.store, srcManifest, conflictingPrefix, conflicting, policy)
	if err == nil {
		t.Fatal("conflicting import succeeded: want an integrity incident")
	}
	if !errors.Is(err, owner_store.ErrIntegrityConflict) {
		t.Fatalf("conflicting import error = %v, want integrity conflict (%v)", err, owner_store.ErrIntegrityConflict)
	}
	// The failed import leaves no new effects.
	after := loadLocalEvents(t, f, first)
	if len(after) != len(before) {
		t.Fatalf("local journal grew from %d to %d events on conflicting import", len(before), len(after))
	}
	if after[len(after)-1].EventHash != before[len(before)-1].EventHash {
		t.Fatal("local head moved on conflicting import")
	}
}

// Imported origin effects must retain the original authority, not the
// importer authority: diagnostics cite the local import while the payload
// preserves the source role, assertion, provenance, owner, and producer.
func TestImportedOriginEffectsRetainOriginalAuthorityNotImporterAuthority(t *testing.T) {
	f := newDestFixture(t, "observation")
	policy := installPolicy(t, f.ctx, f.store, "src-origin", "v2")
	srcManifest := testSourceManifest("journal-origin", "run-origin", "origin-domain")
	source, srcPrefix := buildSourceChain(t, srcManifest, []sourceSpec{{
		EventID:    "evt-origin-1",
		Kind:       "origin_recorded",
		Role:       "derived_output",
		Assertion:  "claim",
		Provenance: "subject",
		Scope:      "current_run",
		ProducerID: "source-producer-1",
		Data:       map[string]any{"origin": "subject claim bytes"},
	}})

	refs, err := ImportSourcePrefix(f.ctx, f.store, srcManifest, srcPrefix, source, policy)
	if err != nil {
		t.Fatalf("ImportSourcePrefix: %v", err)
	}
	local := loadLocalEvents(t, f, refs)
	origin := local[2]
	src := source[1]

	// The payload preserves the complete original authority.
	requireString(t, origin.Payload.Data, "original_role", src.Role)
	requireString(t, origin.Payload.Data, "original_assertion_kind", src.AssertionKind)
	requireString(t, origin.Payload.Data, "original_provenance", src.Provenance)
	requireString(t, origin.Payload.Data, "original_owner_domain", src.OwnerDomain)
	requireString(t, origin.Payload.Data, "original_producer_id", src.ProducerID)
	requireString(t, origin.Payload.Data, "original_evidence_scope", src.EvidenceScope)
	requireString(t, origin.Payload.Data, "source_event_kind", src.EventKind)
	requireString(t, origin.Payload.Data, "source_event_id", src.EventID)
	requireString(t, origin.Payload.Data, "source_event_hash", src.EventHash)

	// The preserved authority is the source authority, not the importer
	// authority assigned to the local envelope.
	if origin.Payload.Data["original_owner_domain"] == origin.OwnerDomain {
		t.Fatalf("original owner %q equals importer owner: source authority was not preserved distinctly",
			origin.OwnerDomain)
	}
	if origin.Payload.Data["original_producer_id"] == origin.ProducerID {
		t.Fatalf("original producer %q equals importer producer: source authority was not preserved",
			origin.ProducerID)
	}
	if origin.Payload.Data["original_provenance"] == origin.Provenance &&
		origin.Payload.Data["original_assertion_kind"] == origin.AssertionKind {
		t.Fatal("original provenance/assertion equal importer provenance/assertion: fixture must distinguish them")
	}
	// The import does not become an origin fact itself.
	if origin.EventKind == src.EventKind {
		t.Fatalf("import kind %q copies the origin kind: the outer record must stay source_imported", origin.EventKind)
	}
	if origin.EventKind != "source_imported" {
		t.Fatalf("import kind = %q, want source_imported", origin.EventKind)
	}
	// Verification evidence and policy pin travel with the import.
	requireString(t, origin.Payload.Data, "import_policy_id", policy.ID)
	requireString(t, origin.Payload.Data, "import_policy_version", policy.Version)
	requireString(t, origin.Payload.Data, "import_policy_digest", policy.ArtifactDigest)
	for _, key := range []string{"source_authentication", "source_correlation", "source_trace_correlation"} {
		if _, ok := origin.Payload.Data[key].(string); !ok {
			t.Fatalf("payload data[%q] is missing or not a string", key)
		}
	}
}

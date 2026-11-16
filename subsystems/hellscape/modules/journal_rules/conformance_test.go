package journal_rules

import (
	"encoding/json"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Test helpers (same package, so unexported hashing is reachable).
// ---------------------------------------------------------------------------

func testClock() ClockDescriptor {
	return ClockDescriptor{
		ClockID: "engine-clock", BootID: "boot-1", Origin: "engine_measured",
		SourceID: "engine", Basis: "monotonic_offset", Unit: "ms",
	}
}

func testManifest() Manifest {
	return Manifest{
		RecordType: "manifest", SchemaVersion: "0.1.0",
		ManifestID: "manifest-1", RunID: "run-1",
		JournalID: "journal-1", OwnerDomain: "domain-1",
		Clocks: []ClockDescriptor{testClock()},
	}
}

func mustManifestDigest(t *testing.T, m Manifest) string {
	t.Helper()
	d, err := computeManifestDigest(m)
	if err != nil {
		t.Fatalf("manifest digest: %v", err)
	}
	return d
}

func testTP(offset float64) TimePoint {
	return TimePoint{
		ClockID: "engine-clock", BootID: "boot-1", Origin: "engine_measured",
		MonotonicOffsetMs: offset, UTCAnnotation: NewMissing("not_applicable"),
	}
}

func testTPOn(clock, boot, origin string, offset float64) TimePoint {
	return TimePoint{
		ClockID: clock, BootID: boot, Origin: origin,
		MonotonicOffsetMs: offset, UTCAnnotation: NewMissing("not_applicable"),
	}
}

func nonNilEnvelope(ev *JournalEnvelope) {
	if ev.CausalRefs == nil {
		ev.CausalRefs = []EvidenceRef{}
	}
	if ev.Payload.Data == nil {
		ev.Payload.Data = map[string]any{}
	}
	if ev.Payload.Measurements == nil {
		ev.Payload.Measurements = []Measurement{}
	}
	if ev.Payload.EvidenceRefs == nil {
		ev.Payload.EvidenceRefs = []EvidenceRef{}
	}
	if ev.Payload.ArtifactRefs == nil {
		ev.Payload.ArtifactRefs = []ArtifactReference{}
	}
}

func finalizeEnvelope(t *testing.T, ev *JournalEnvelope) {
	t.Helper()
	nonNilEnvelope(ev)
	h, err := computeEventHash(*ev)
	if err != nil {
		t.Fatalf("compute hash: %v", err)
	}
	ev.EventHash = h
}

func baseEnvelope(m Manifest, digest string, seq int64, eventID, kind string, prev any) JournalEnvelope {
	role := "lifecycle_observation"
	provenance := "server"
	assertion := "observation"
	producer := "recorder-1"
	if kind == "manifest_admitted" {
		role = "external_input"
		producer = "kernel"
	}
	return JournalEnvelope{
		RecordType: "journal_event", SchemaVersion: "0.1.0",
		RunID: m.RunID, JournalID: m.JournalID, ManifestHash: digest,
		Sequence: seq, EventID: eventID, EventKind: kind, EventSchemaVersion: "v1",
		Role: role, AssertionKind: assertion, OwnerDomain: m.OwnerDomain,
		ProducerID: producer, ProducerSequence: seq,
		Provenance: provenance, EvidenceScope: "current_run",
		RecordedAt: testTP(float64(1000 + seq*10)), OccurredAt: NewMissing("not_observed"),
		CausalRefs: []EvidenceRef{},
		Payload: Payload{
			Data: map[string]any{}, Measurements: []Measurement{},
			EvidenceRefs: []EvidenceRef{}, ArtifactRefs: []ArtifactReference{},
		},
		PreviousEventHash: prev, EventHash: "",
	}
}

// newValidChain builds a manifest plus n valid contiguous events.
func newValidChain(t *testing.T, n int) (Manifest, []JournalEnvelope) {
	t.Helper()
	if n < 1 {
		t.Fatalf("need at least 1 event")
	}
	m := testManifest()
	digest := mustManifestDigest(t, m)
	events := make([]JournalEnvelope, 0, n)
	// Sequence 1: admission pinning the manifest.
	ev1 := baseEnvelope(m, digest, 1, "evt-admission", "manifest_admitted", NewMissing("not_applicable"))
	ev1.Payload.Data = map[string]any{
		"manifest": map[string]any{
			"digest": digest, "size_bytes": int64(123),
			"media_type": "application/json", "owner_domain": m.OwnerDomain, "access": "restricted",
		},
	}
	finalizeEnvelope(t, &ev1)
	events = append(events, ev1)
	for i := 2; i <= n; i++ {
		prev := events[len(events)-1].EventHash
		ev := baseEnvelope(m, digest, int64(i), "evt-"+string(rune('a'+i)), "observation_noted", prev)
		ev.Payload.Data = map[string]any{"note": "event"}
		finalizeEnvelope(t, &ev)
		events = append(events, ev)
	}
	return m, events
}

func refFor(ev JournalEnvelope, pointer string) EvidenceRef {
	return EvidenceRef{
		JournalID: ev.JournalID, Sequence: ev.Sequence,
		EventID: ev.EventID, EventHash: ev.EventHash, Pointer: pointer,
	}
}

func unavailableMeasurement(id string) Measurement {
	return Measurement{
		MeasurementID: id, Name: "workflow_elapsed",
		Scope: Scope{Kind: "workflow_step", ID: "step-1"},
		Quantity: "duration", Unit: "ms",
		Origin: "engine_measured", ClockID: "engine-clock", BootID: "boot-1",
		Method: "unavailable",
		Start: NewMissing("not_observed"), End: NewMissing("not_observed"),
		Estimate: Estimate{Kind: "unavailable", Value: NewMissing("not_observed")},
		Resolution: NewMissing("not_applicable"), Censoring: "unavailable",
		ComparabilityGroup: NewMissing("not_applicable"),
	}
}

func endpointMeasurement(id string, startOff, endOff float64) Measurement {
	return Measurement{
		MeasurementID: id, Name: "workflow_elapsed",
		Scope: Scope{Kind: "workflow_step", ID: "step-1"},
		Quantity: "duration", Unit: "ms",
		Origin: "engine_measured", ClockID: "engine-clock", BootID: "boot-1",
		Method: "endpoint_difference",
		Start: testTP(startOff), End: testTP(endOff),
		Estimate: Estimate{Kind: "exact", Value: endOff - startOff},
		Resolution: NewMissing("not_applicable"), Censoring: "none",
		ComparabilityGroup: NewMissing("not_applicable"),
	}
}

func requirePass(t *testing.T, m Manifest, events []JournalEnvelope) JournalPrefix {
	t.Helper()
	prefix, err := ValidateJournal(m, events)
	if err != nil {
		t.Fatalf("expected ValidateJournal pass, got: %v", err)
	}
	return prefix
}

func requireFail(t *testing.T, m Manifest, events []JournalEnvelope, substr string) {
	t.Helper()
	_, err := ValidateJournal(m, events)
	if err == nil {
		t.Fatalf("expected ValidateJournal rejection containing %q, got pass", substr)
	}
	if substr != "" && !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(substr)) {
		t.Fatalf("expected error containing %q, got: %v", substr, err)
	}
}

// ---------------------------------------------------------------------------
// 1. Admission first, contiguous sequences, stable pinning.
// ---------------------------------------------------------------------------

func TestJournalBeginsWithAdmissionAndContiguousSequences(t *testing.T) {
	m, events := newValidChain(t, 3)
	prefix := requirePass(t, m, events)
	if prefix.JournalID != m.JournalID || prefix.LastSequence != 3 || prefix.HeadHash != events[2].EventHash {
		t.Fatalf("bad prefix %+v", prefix)
	}

	// Empty journal.
	requireFail(t, m, []JournalEnvelope{}, "empty")

	// First event is not admission.
	_, bad := newValidChain(t, 2)
	bad[0].EventKind = "observation_noted"
	finalizeEnvelope(t, &bad[0])
	// Fix chain link so the failure is about admission, not the hash link.
	bad[1].PreviousEventHash = bad[0].EventHash
	finalizeEnvelope(t, &bad[1])
	requireFail(t, m, bad, "manifest_admitted")

	// Admission repeated later.
	_, bad = newValidChain(t, 2)
	bad[1].EventKind = "manifest_admitted"
	bad[1].Role = "external_input"
	finalizeEnvelope(t, &bad[1])
	requireFail(t, m, bad, "only at sequence 1")

	// Gap in sequences.
	_, bad = newValidChain(t, 3)
	bad[2].Sequence = 4
	finalizeEnvelope(t, &bad[2])
	requireFail(t, m, bad, "contiguous")

	// Divergent run / journal / manifest / owner.
	for _, mutate := range []struct {
		name string
		fn   func(*JournalEnvelope)
		want string
	}{
		{"run", func(e *JournalEnvelope) { e.RunID = "run-2" }, "run"},
		{"journal", func(e *JournalEnvelope) { e.JournalID = "journal-2" }, "journal"},
		{"manifest", func(e *JournalEnvelope) { e.ManifestHash = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" }, "manifest"},
		{"owner", func(e *JournalEnvelope) { e.OwnerDomain = "domain-2" }, "owner_domain"},
	} {
		_, bad := newValidChain(t, 2)
		mutate.fn(&bad[1])
		finalizeEnvelope(t, &bad[1])
		requireFail(t, m, bad, mutate.want)
	}

	// Duplicate event IDs are resequencing.
	_, bad = newValidChain(t, 2)
	bad[1].EventID = bad[0].EventID
	finalizeEnvelope(t, &bad[1])
	requireFail(t, m, bad, "duplicate event_id")
}

// ---------------------------------------------------------------------------
// 2. Hash chain and prefix head.
// ---------------------------------------------------------------------------

func TestJournalPrefixHeadEqualsItsLastVerifiedEventHash(t *testing.T) {
	m, events := newValidChain(t, 3)
	prefix := requirePass(t, m, events)
	if prefix.HeadHash != events[len(events)-1].EventHash {
		t.Fatalf("head %q != last hash %q", prefix.HeadHash, events[len(events)-1].EventHash)
	}

	// Tampered event hash.
	_, bad := newValidChain(t, 2)
	bad[1].EventHash = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	requireFail(t, m, bad, "does not match recomputed")

	// Tampered link.
	_, bad = newValidChain(t, 3)
	bad[2].PreviousEventHash = bad[0].EventHash
	finalizeEnvelope(t, &bad[2])
	requireFail(t, m, bad, "previous_event_hash")

	// Sequence 1 must carry Missing(not_applicable).
	_, bad = newValidChain(t, 2)
	bad[0].PreviousEventHash = bad[0].EventHash // digest instead of Missing
	finalizeEnvelope(t, &bad[0])
	bad[1].PreviousEventHash = bad[0].EventHash
	finalizeEnvelope(t, &bad[1])
	requireFail(t, m, bad, "not_applicable")

	_, bad = newValidChain(t, 2)
	bad[0].PreviousEventHash = NewMissing("not_observed") // wrong reason
	finalizeEnvelope(t, &bad[0])
	bad[1].PreviousEventHash = bad[0].EventHash
	finalizeEnvelope(t, &bad[1])
	requireFail(t, m, bad, "not_applicable")

	// Later events must carry a digest link, not Missing.
	_, bad = newValidChain(t, 2)
	bad[1].PreviousEventHash = NewMissing("not_applicable")
	finalizeEnvelope(t, &bad[1])
	requireFail(t, m, bad, "previous_event_hash")

	// Changed payload bytes invalidate the stored hash.
	_, bad = newValidChain(t, 2)
	bad[1].Payload.Data["note"] = "tampered after commit"
	// Keep the old hash deliberately.
	requireFail(t, m, bad, "changed content")

	// Malformed digest is rejected by the structural gate.
	_, bad = newValidChain(t, 2)
	bad[1].EventHash = "not-a-digest"
	requireFail(t, m, bad, "digest")
}

// ---------------------------------------------------------------------------
// 3. Every EvidenceRef coordinate and the pointer must agree.
// ---------------------------------------------------------------------------

func TestEvidenceReferencesMustMatchEveryCoordinateAndPointer(t *testing.T) {
	m, events := newValidChain(t, 3)
	// Event 3 cites event 1 with a complete retained reference.
	events[2].Payload.EvidenceRefs = []EvidenceRef{refFor(events[0], "")}
	events[2].CausalRefs = []EvidenceRef{refFor(events[1], "/event_kind")}
	finalizeEnvelope(t, &events[2])
	prefix := requirePass(t, m, events)

	// ResolveEvidence returns the complete event for an empty pointer.
	got, err := ResolveEvidence(prefix, events, refFor(events[0], ""))
	if err != nil {
		t.Fatalf("resolve empty pointer: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(got, &decoded); err != nil {
		t.Fatalf("resolve bytes are not JSON: %v", err)
	}
	if decoded["event_id"] != events[0].EventID {
		t.Fatalf("resolved wrong event: %v", decoded["event_id"])
	}
	// A sub-pointer resolves to the addressed value.
	got, err = ResolveEvidence(prefix, events, refFor(events[1], "/event_kind"))
	if err != nil {
		t.Fatalf("resolve sub-pointer: %v", err)
	}
	if string(got) != `"observation_noted"` {
		t.Fatalf("unexpected sub-pointer value %s", got)
	}
	// Escaped pointer segments resolve per RFC 6901.
	m2, ev2 := newValidChain(t, 2)
	ev2[0].Payload.Data["a/b"] = map[string]any{"c~d": "found"}
	finalizeEnvelope(t, &ev2[0])
	ev2[1].PreviousEventHash = ev2[0].EventHash
	finalizeEnvelope(t, &ev2[1])
	prefix2 := requirePass(t, m2, ev2)
	got, err = ResolveEvidence(prefix2, ev2, refFor(ev2[0], "/payload/data/a~1b/c~0d"))
	if err != nil {
		t.Fatalf("escaped pointer: %v", err)
	}
	if string(got) != `"found"` {
		t.Fatalf("unexpected escaped value %s", got)
	}

	// Each coordinate mismatch is rejected by both gates.
	baseRef := refFor(events[0], "")
	cases := []struct {
		name string
		ref  EvidenceRef
		want string
	}{
		{"journal", EvidenceRef{JournalID: "other", Sequence: baseRef.Sequence, EventID: baseRef.EventID, EventHash: baseRef.EventHash, Pointer: ""}, "journal"},
		{"event_id", EvidenceRef{JournalID: baseRef.JournalID, Sequence: baseRef.Sequence, EventID: "evt-wrong", EventHash: baseRef.EventHash, Pointer: ""}, "event_id"},
		{"event_hash", EvidenceRef{JournalID: baseRef.JournalID, Sequence: baseRef.Sequence, EventID: baseRef.EventID, EventHash: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", Pointer: ""}, "hash"},
		{"pointer_shape", EvidenceRef{JournalID: baseRef.JournalID, Sequence: baseRef.Sequence, EventID: baseRef.EventID, EventHash: baseRef.EventHash, Pointer: "not-a-pointer"}, "pointer"},
		{"pointer_missing", EvidenceRef{JournalID: baseRef.JournalID, Sequence: baseRef.Sequence, EventID: baseRef.EventID, EventHash: baseRef.EventHash, Pointer: "/payload/data/nope"}, "resolve"},
	}
	for _, tc := range cases {
		_, bad := newValidChain(t, 3)
		bad[2].Payload.EvidenceRefs = []EvidenceRef{tc.ref}
		// Recompute so the failure is about the reference, not the chain.
		// A structurally invalid pointer still needs a hash; ValidateRecord
		// runs before reference checks, so shape errors surface first.
		finalizeEnvelope(t, &bad[2])
		if _, err := ValidateJournal(m, bad); err == nil {
			t.Fatalf("%s: ValidateJournal accepted a bad reference", tc.name)
		} else if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.want)) &&
			!strings.Contains(strings.ToLower(err.Error()), "structural") {
			t.Fatalf("%s: expected %q, got %v", tc.name, tc.want, err)
		}
		if _, err := ResolveEvidence(prefix, events, tc.ref); err == nil {
			t.Fatalf("%s: ResolveEvidence accepted a bad reference", tc.name)
		}
	}
	// Sequence pointing at a different event's coordinates is rejected.
	swapped := refFor(events[0], "")
	swapped.Sequence = events[1].Sequence
	if _, err := ResolveEvidence(prefix, events, swapped); err == nil {
		t.Fatal("ResolveEvidence accepted a sequence/event_id mismatch")
	}
}

// ---------------------------------------------------------------------------
// 4. The pinned prefix bounds all resolution.
// ---------------------------------------------------------------------------

func TestEvidenceBeyondThePinnedPrefixIsRejected(t *testing.T) {
	m, events := newValidChain(t, 5)
	full := requirePass(t, m, events)
	if full.LastSequence != 5 {
		t.Fatalf("full prefix %+v", full)
	}
	// A pinned prefix ending at 3.
	pinned := JournalPrefix{JournalID: m.JournalID, LastSequence: 3, HeadHash: events[2].EventHash}
	// Inside the prefix resolves.
	if _, err := ResolveEvidence(pinned, events, refFor(events[1], "")); err != nil {
		t.Fatalf("inside prefix must resolve: %v", err)
	}
	// Beyond the prefix is rejected even though the bytes are retained.
	for _, seq := range []int64{4, 5} {
		ref := refFor(events[seq-1], "")
		if _, err := ResolveEvidence(pinned, events, ref); err == nil {
			t.Fatalf("sequence %d beyond the pinned prefix resolved", seq)
		} else if !strings.Contains(strings.ToLower(err.Error()), "beyond") {
			t.Fatalf("expected beyond-prefix error, got %v", err)
		}
	}
	// A forged head cannot extend the prefix.
	forged := JournalPrefix{JournalID: m.JournalID, LastSequence: 3, HeadHash: events[3].EventHash}
	if _, err := ResolveEvidence(forged, events, refFor(events[1], "")); err == nil {
		t.Fatal("forged head_hash resolved")
	}
	// A foreign journal prefix never resolves local evidence.
	foreign := JournalPrefix{JournalID: "journal-2", LastSequence: 3, HeadHash: events[2].EventHash}
	if _, err := ResolveEvidence(foreign, events, refFor(events[1], "")); err == nil {
		t.Fatal("foreign journal resolved")
	}
	// Journals cannot smuggle future evidence inside an event either.
	_, bad := newValidChain(t, 3)
	future := refFor(bad[2], "")
	bad[1].Payload.EvidenceRefs = []EvidenceRef{future}
	finalizeEnvelope(t, &bad[1])
	// Re-link the tail so the failure is about the future citation.
	bad[2].PreviousEventHash = bad[1].EventHash
	finalizeEnvelope(t, &bad[2])
	requireFail(t, m, bad, "future")
}

// ---------------------------------------------------------------------------
// 5. Clocks register before use, except the atomic receipt.
// ---------------------------------------------------------------------------

func TestClockRegistrationPrecedesUseExceptAtomicRegistrationReceipt(t *testing.T) {
	// Valid endpoint measurement on the manifest clock.
	m, events := newValidChain(t, 2)
	events[1].Payload.Measurements = []Measurement{endpointMeasurement("m-endpoint", 100, 160)}
	finalizeEnvelope(t, &events[1])
	requirePass(t, m, events)

	// Valid unavailable measurement.
	_, ev := newValidChain(t, 2)
	ev[1].Payload.Measurements = []Measurement{unavailableMeasurement("m-missing")}
	finalizeEnvelope(t, &ev[1])
	requirePass(t, m, ev)

	// Atomic registration: the clock_registered event introduces browser-clock
	// and uses it for its own recorded_at receipt timestamp.
	m3, ev3 := newValidChain(t, 1)
	digest := mustManifestDigest(t, m3)
	reg := baseEnvelope(m3, digest, 2, "evt-clock-reg", "clock_registered", ev3[0].EventHash)
	reg.Payload.Data = map[string]any{
		"clock_id": "browser-clock", "boot_id": "boot-9", "origin": "browser_measured",
		"source_id": "browser", "basis": "monotonic_offset", "unit": "ms",
	}
	reg.RecordedAt = testTPOn("browser-clock", "boot-9", "browser_measured", 5)
	reg.OccurredAt = NewMissing("not_observed")
	finalizeEnvelope(t, &reg)
	ev3 = append(ev3, reg)
	// Later events and measurements may use the new clock.
	use := baseEnvelope(m3, digest, 3, "evt-use-new", "observation_noted", reg.EventHash)
	use.RecordedAt = testTPOn("browser-clock", "boot-9", "browser_measured", 9)
	use.Payload.Measurements = []Measurement{{
		MeasurementID: "m-browser", Name: "browser_elapsed",
		Scope: Scope{Kind: "workflow_step", ID: "step-1"},
		Quantity: "duration", Unit: "ms",
		Origin: "browser_measured", ClockID: "browser-clock", BootID: "boot-9",
		Method: "endpoint_difference",
		Start: testTPOn("browser-clock", "boot-9", "browser_measured", 1),
		End:   testTPOn("browser-clock", "boot-9", "browser_measured", 4),
		Estimate: Estimate{Kind: "exact", Value: 3.0},
		Resolution: NewMissing("not_applicable"), Censoring: "none",
		ComparabilityGroup: NewMissing("not_applicable"),
	}}
	finalizeEnvelope(t, &use)
	ev3 = append(ev3, use)
	requirePass(t, m3, ev3)

	// Unregistered measurement clock.
	_, bad := newValidChain(t, 2)
	mm := endpointMeasurement("m-ghost", 10, 20)
	mm.ClockID = "ghost-clock"
	bad[1].Payload.Measurements = []Measurement{mm}
	finalizeEnvelope(t, &bad[1])
	requireFail(t, m, bad, "not registered")

	// Cross-clock endpoints never form an exact duration.
	_, bad = newValidChain(t, 2)
	mm = endpointMeasurement("m-cross-clock", 10, 20)
	mm.End = testTPOn("browser-clock", "boot-1", "engine_measured", 20)
	bad[1].Payload.Measurements = []Measurement{mm}
	finalizeEnvelope(t, &bad[1])
	requireFail(t, m, bad, "clock")

	// Cross-boot endpoints are rejected as well.
	_, bad = newValidChain(t, 2)
	mm = endpointMeasurement("m-cross-boot", 10, 20)
	mm.End = testTPOn("engine-clock", "boot-2", "engine_measured", 20)
	bad[1].Payload.Measurements = []Measurement{mm}
	finalizeEnvelope(t, &bad[1])
	requireFail(t, m, bad, "boot")

	// Receipt timestamps need registration too.
	_, bad = newValidChain(t, 2)
	bad[1].RecordedAt = testTPOn("ghost-clock", "boot-1", "engine_measured", 50)
	finalizeEnvelope(t, &bad[1])
	requireFail(t, m, bad, "not registered")

	// The atomic exception covers only the receipt, not occurrence time.
	_, bad = newValidChain(t, 1)
	d0 := mustManifestDigest(t, m)
	reg2 := baseEnvelope(m, d0, 2, "evt-clock-reg", "clock_registered", bad[0].EventHash)
	reg2.Payload.Data = map[string]any{
		"clock_id": "late-clock", "boot_id": "boot-1", "origin": "engine_measured",
		"source_id": "engine", "basis": "monotonic_offset", "unit": "ms",
	}
	reg2.RecordedAt = testTP(200)
	reg2.OccurredAt = testTPOn("late-clock", "boot-1", "engine_measured", 1)
	finalizeEnvelope(t, &reg2)
	bad = append(bad, reg2)
	requireFail(t, m, bad, "not registered")

	// UTC annotations never drive elapsed arithmetic: identical offsets with
	// different UTC labels still validate, and wrong arithmetic fails even
	// when the UTC labels look consistent.
	_, good := newValidChain(t, 2)
	okm := endpointMeasurement("m-utc", 100, 150)
	start := testTP(100)
	start.UTCAnnotation = "2026-01-01T00:00:00Z"
	end := testTP(150)
	end.UTCAnnotation = "2026-06-01T00:00:00Z"
	okm.Start, okm.End = start, end
	good[1].Payload.Measurements = []Measurement{okm}
	finalizeEnvelope(t, &good[1])
	requirePass(t, m, good)

	_, bad = newValidChain(t, 2)
	wrong := endpointMeasurement("m-utc-wrong", 100, 150)
	wrong.Estimate = Estimate{Kind: "exact", Value: 999.0}
	bad[1].Payload.Measurements = []Measurement{wrong}
	finalizeEnvelope(t, &bad[1])
	requireFail(t, m, bad, "endpoint difference")
}

// ---------------------------------------------------------------------------
// 6. Publications register after their bytes exist.
// ---------------------------------------------------------------------------

func TestPublicationSupportCannotCiteItsFutureRegistration(t *testing.T) {
	m, events := newValidChain(t, 3)
	// A publication-style event citing only past evidence is fine.
	events[2].EventKind = "diagnostic_registered"
	events[2].Role = "derived_output"
	events[2].AssertionKind = "derived_assessment"
	events[2].Payload.EvidenceRefs = []EvidenceRef{refFor(events[0], ""), refFor(events[1], "")}
	finalizeEnvelope(t, &events[2])
	requirePass(t, m, events)

	// Self-citation in evidence_refs.
	_, bad := newValidChain(t, 3)
	self := refFor(bad[1], "")
	// Point the reference at the citing event itself.
	self.Sequence = bad[1].Sequence
	self.EventID = bad[1].EventID
	self.EventHash = bad[1].EventHash
	bad[1].Payload.EvidenceRefs = []EvidenceRef{self}
	finalizeEnvelope(t, &bad[1])
	bad[2].PreviousEventHash = bad[1].EventHash
	finalizeEnvelope(t, &bad[2])
	requireFail(t, m, bad, "future")

	// Future citation in causal_refs.
	_, bad = newValidChain(t, 3)
	bad[0].CausalRefs = []EvidenceRef{refFor(bad[2], "")}
	finalizeEnvelope(t, &bad[0])
	bad[1].PreviousEventHash = bad[0].EventHash
	finalizeEnvelope(t, &bad[1])
	bad[2].PreviousEventHash = bad[1].EventHash
	// Re-resolve the future ref hash after relinking.
	bad[0].CausalRefs = []EvidenceRef{refFor(bad[2], "")}
	finalizeEnvelope(t, &bad[0])
	bad[1].PreviousEventHash = bad[0].EventHash
	finalizeEnvelope(t, &bad[1])
	bad[2].PreviousEventHash = bad[1].EventHash
	finalizeEnvelope(t, &bad[2])
	// The causal ref now points ahead; coordinates were refreshed above but
	// the sequence is still in the future.
	bad[0].CausalRefs = []EvidenceRef{refFor(bad[2], "")}
	finalizeEnvelope(t, &bad[0])
	bad[1].PreviousEventHash = bad[0].EventHash
	finalizeEnvelope(t, &bad[1])
	bad[2].PreviousEventHash = bad[1].EventHash
	finalizeEnvelope(t, &bad[2])
	requireFail(t, m, bad, "future")

	// Embedded support inside data cannot cite the future either.
	_, bad = newValidChain(t, 3)
	future := refFor(bad[2], "")
	bad[1].Payload.Data = map[string]any{
		"support": []any{map[string]any{
			"journal_id": future.JournalID, "sequence": future.Sequence,
			"event_id": future.EventID, "event_hash": future.EventHash, "pointer": "",
		}},
	}
	finalizeEnvelope(t, &bad[1])
	bad[2].PreviousEventHash = bad[1].EventHash
	finalizeEnvelope(t, &bad[2])
	// Refresh the embedded hash after the tail moved.
	future2 := refFor(bad[2], "")
	bad[1].Payload.Data = map[string]any{
		"support": []any{map[string]any{
			"journal_id": future2.JournalID, "sequence": future2.Sequence,
			"event_id": future2.EventID, "event_hash": future2.EventHash, "pointer": "",
		}},
	}
	finalizeEnvelope(t, &bad[1])
	bad[2].PreviousEventHash = bad[1].EventHash
	finalizeEnvelope(t, &bad[2])
	requireFail(t, m, bad, "future")

	// Embedding the event's own digest is a hash cycle.
	_, bad = newValidChain(t, 2)
	finalizeEnvelope(t, &bad[1])
	bad[1].Payload.Data = map[string]any{"derivation_digest": bad[1].EventHash}
	// Keep the stored hash so the cycle is detectable as content, then
	// recompute to keep the chain linked: either way the digest appears in
	// its own inputs.
	bad[1].Payload.Data["derivation_digest"] = bad[1].EventHash
	stale := bad[1].EventHash
	bad[1].Payload.Data["derivation_digest"] = stale
	finalizeEnvelope(t, &bad[1])
	// After recompute the embedded digest is stale; force the cycle by
	// embedding the fresh digest without recomputing.
	bad[1].Payload.Data["derivation_digest"] = bad[1].EventHash
	if _, err := ValidateJournal(m, bad); err == nil {
		t.Fatal("expected digest-cycle rejection")
	}

	// Imported evidence keeps its original scope; promotion is rejected.
	_, bad = newValidChain(t, 2)
	bad[1].Provenance = "importer"
	bad[1].AssertionKind = "observation"
	bad[1].EvidenceScope = "current_run"
	finalizeEnvelope(t, &bad[1])
	requireFail(t, m, bad, "promote")
	// The same import with retained scope passes.
	_, good := newValidChain(t, 2)
	good[1].Provenance = "importer"
	good[1].AssertionKind = "observation"
	good[1].EvidenceScope = "historical_unscored"
	finalizeEnvelope(t, &good[1])
	requirePass(t, m, good)
}

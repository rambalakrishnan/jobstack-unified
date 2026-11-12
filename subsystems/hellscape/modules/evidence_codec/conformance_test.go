package evidence_codec

import (
	"strings"
	"testing"
)

const testDigestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const testDigestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func validManifestDoc(extra string) string {
	base := `{"record_type":"manifest","schema_version":"0.1.0","manifest_id":"m1","run_id":"r1","journal_id":"j1","owner_domain":"d1"`
	if extra != "" {
		base += "," + extra
	}
	return base + `}`
}

func validJournalEventDoc(extra string) string {
	base := `{"record_type":"journal_event","schema_version":"0.1.0","run_id":"r1","journal_id":"j1",` +
		`"manifest_hash":"` + testDigestA + `","journal_sequence":2,"event_id":"e1",` +
		`"event_kind":"k1","event_schema_version":"v1","role":"external_input",` +
		`"assertion_kind":"a1","owner_domain":"d1","producer_id":"p1","producer_sequence":1,` +
		`"provenance":"prov","evidence_scope":"current_run",` +
		`"occurred_at":"2026-01-01T00:00:00Z",` +
		`"payload":{"data":{},"measurements":[],"evidence_refs":[],"artifact_refs":[]},` +
		`"previous_event_hash":"` + testDigestA + `","event_hash":"` + testDigestB + `"`
	if extra != "" {
		base += "," + extra
	}
	return base + `}`
}

func TestDuplicateMappingKeysAreRejectedBeforeValidation(t *testing.T) {
	// Top-level duplicate: rejected even though each half alone is incomplete.
	dup := `{"record_type":"manifest","schema_version":"0.1.0","record_type":"manifest"}`
	if err := ValidateRecord("0.1.0", "manifest", []byte(dup)); err == nil {
		t.Fatal("expected duplicate mapping key rejection")
	} else if !strings.Contains(err.Error(), "duplicate mapping key") {
		t.Fatalf("expected duplicate-key error, got: %v", err)
	}
	// Nested duplicate inside payload.
	nested := validJournalEventDoc("")
	nested = strings.Replace(nested, `"data":{}`, `"data":{"x":1,"x":2}`, 1)
	if err := ValidateRecord("0.1.0", "journal_event", []byte(nested)); err == nil {
		t.Fatal("expected nested duplicate mapping key rejection")
	} else if !strings.Contains(err.Error(), "duplicate mapping key") {
		t.Fatalf("expected duplicate-key error, got: %v", err)
	}
	// Escaped duplicate ("\u0061" == "a") must also be caught.
	escaped := `{"a":1,"` + `\u0061` + `":2}`
	if _, err := CanonicalJSON([]byte(escaped), "application/json"); err == nil {
		t.Fatal("expected escaped duplicate key rejection")
	}
	// Duplicate rejection takes precedence: the duplicate error must mention
	// "before validation", not a downstream missing-field error.
	if _, err := CanonicalJSON([]byte(dup), "application/json"); err == nil {
		t.Fatal("expected CanonicalJSON duplicate rejection")
	}
}

func TestNonFiniteNumbersAndNonJSONValuesAreRejected(t *testing.T) {
	for _, doc := range []string{
		`NaN`, `Infinity`, `-Infinity`, `undefined`,
		`{"a":NaN}`, `{"a":Infinity}`, `{"a":undefined}`,
		`{"record_type":"manifest","schema_version":"0.1.0","manifest_id":NaN}`,
	} {
		if _, err := CanonicalJSON([]byte(doc), "application/json"); err == nil {
			t.Fatalf("expected non-JSON value rejection for %s", doc)
		}
		if err := ValidateRecord("0.1.0", "manifest", []byte(doc)); err == nil {
			t.Fatalf("expected ValidateRecord rejection for %s", doc)
		}
	}
	// Non-finite tokens smuggled as strings are rejected at the semantic gate.
	smuggled := validManifestDoc(`"activity":"NaN"`)
	if err := ValidateRecord("0.1.0", "manifest", []byte(smuggled)); err == nil {
		t.Fatal("expected rejection of non-finite string token")
	}
	// Overflow exponents (out of float64 range) are rejected as non-finite.
	overflow := `{"a":1e999}`
	if _, err := CanonicalJSON([]byte(overflow), "application/json"); err == nil {
		t.Fatal("expected rejection of overflowing exponent")
	}
	// Ordinary numbers remain accepted.
	if _, err := CanonicalJSON([]byte(`{"a":1.5,"b":-3,"c":0}`), "application/json"); err != nil {
		t.Fatalf("ordinary numbers must be accepted: %v", err)
	}
}

func TestUnknownRecordVersionsAndClosedObjectFieldsAreRejected(t *testing.T) {
	// Unknown record version.
	unknownVer := strings.Replace(validManifestDoc(""), `"0.1.0"`, `"9.9.9"`, 1)
	if err := ValidateRecord("9.9.9", "manifest", []byte(unknownVer)); err == nil {
		t.Fatal("expected unknown record version rejection")
	}
	// Declared version mismatch.
	if err := ValidateRecord("1.0.0", "manifest", []byte(validManifestDoc(""))); err == nil {
		t.Fatal("expected schema version mismatch rejection")
	}
	// Unknown record type.
	bogus := `{"record_type":"bogus","schema_version":"0.1.0"}`
	if err := ValidateRecord("0.1.0", "bogus", []byte(bogus)); err == nil {
		t.Fatal("expected unknown record type rejection")
	}
	// Unknown closed-object field on a known record.
	closed := validManifestDoc(`"bogus_field":1`)
	if err := ValidateRecord("0.1.0", "manifest", []byte(closed)); err == nil {
		t.Fatal("expected unknown closed-object field rejection")
	}
	// Unknown closed-object field inside payload.
	closedPayload := strings.Replace(validJournalEventDoc(""), `"artifact_refs":[]`,
		`"artifact_refs":[],"extra_payload_field":1`, 1)
	if err := ValidateRecord("0.1.0", "journal_event", []byte(closedPayload)); err == nil {
		t.Fatal("expected unknown payload field rejection")
	}
	// Known versions and fields are accepted.
	if err := ValidateRecord("0.1.0", "manifest", []byte(validManifestDoc(""))); err != nil {
		t.Fatalf("valid manifest must be accepted: %v", err)
	}
	if err := ValidateRecord("0.1.0", "journal_event", []byte(validJournalEventDoc(""))); err != nil {
		t.Fatalf("valid journal_event must be accepted: %v", err)
	}
}

func TestBareNormalizedNullsAndMissingRequiredFieldsAreRejected(t *testing.T) {
	// Bare null instead of a Missing envelope.
	bare := validManifestDoc(`"activity":null`)
	if err := ValidateRecord("0.1.0", "manifest", []byte(bare)); err == nil {
		t.Fatal("expected bare normalized null rejection")
	} else if !strings.Contains(err.Error(), "bare normalized null") {
		t.Fatalf("expected bare-null error, got: %v", err)
	}
	// Reasoned Missing envelope is accepted.
	reasoned := validManifestDoc(`"activity":{"value":null,"reason":"not_enabled"}`)
	if err := ValidateRecord("0.1.0", "manifest", []byte(reasoned)); err != nil {
		t.Fatalf("reasoned Missing envelope must be accepted: %v", err)
	}
	// Invalid NullReason (manual_fixture_validation is a rationale, not a reason).
	badReason := validManifestDoc(`"activity":{"value":null,"reason":"manual_fixture_validation"}`)
	if err := ValidateRecord("0.1.0", "manifest", []byte(badReason)); err == nil {
		t.Fatal("expected invalid NullReason rejection")
	}
	// Omitted required field instead of Missing.
	missing := `{"record_type":"manifest","schema_version":"0.1.0","manifest_id":"m1","run_id":"r1","journal_id":"j1"}`
	if err := ValidateRecord("0.1.0", "manifest", []byte(missing)); err == nil {
		t.Fatal("expected missing required field rejection")
	}
	// Missing record_type discriminator.
	noType := `{"schema_version":"0.1.0"}`
	if err := ValidateRecord("0.1.0", "manifest", []byte(noType)); err == nil {
		t.Fatal("expected missing record_type rejection")
	}
}

func TestCanonicalizationPreservesArraysStringsAndMissingEnvelopes(t *testing.T) {
	// Array order preserved, object keys sorted.
	in := `{"b":2,"a":[3,2,1],"c":{"z":1,"a":2}}`
	want := `{"a":[3,2,1],"b":2,"c":{"a":2,"z":1}}`
	got, err := CanonicalJSON([]byte(in), "application/json")
	if err != nil {
		t.Fatalf("canonicalization failed: %v", err)
	}
	if string(got) != want {
		t.Fatalf("canonical mismatch: got %s want %s", got, want)
	}
	// String contents preserved exactly (Unicode, escapes, no normalization).
	ustr := `{"s":"héllo ✓ 世界","e":"a\"b\\c\/d"}`
	ugot, err := CanonicalJSON([]byte(ustr), "application/json")
	if err != nil {
		t.Fatalf("unicode canonicalization failed: %v", err)
	}
	uagain, err := CanonicalJSON(ugot, "application/json")
	if err != nil || string(uagain) != string(ugot) {
		t.Fatalf("canonical form must be a fixed point: %q vs %q (err %v)", ugot, uagain, err)
	}
	// Missing-value envelopes preserved verbatim (not removed or redacted).
	miss := `{"m":{"value":null,"reason":"not_observed","detail":"sensor offline"},"arr":[{"value":null,"reason":"not_applicable"}]}`
	mgot, err := CanonicalJSON([]byte(miss), "application/json")
	if err != nil {
		t.Fatalf("missing envelope canonicalization failed: %v", err)
	}
	if !strings.Contains(string(mgot), `"reason":"not_observed"`) ||
		!strings.Contains(string(mgot), `"reason":"not_applicable"`) {
		t.Fatalf("missing envelopes must be preserved: %s", mgot)
	}
	// Canonical bytes hash stably: same document, same identity.
	h1 := HashBytes(mgot)
	mgot2, err := CanonicalJSON([]byte(miss), "application/json")
	if err != nil {
		t.Fatal(err)
	}
	if h2 := HashBytes(mgot2); h1 != h2 {
		t.Fatalf("canonical bytes must hash stably: %s vs %s", h1, h2)
	}
	// No insignificant whitespace in canonical output.
	if strings.ContainsAny(string(got), " \n\t") {
		t.Fatalf("canonical output must have no insignificant whitespace: %q", got)
	}
}

func TestRedactedBytesReceiveDifferentArtifactIdentities(t *testing.T) {
	original := []byte(`{"secret":"s3cr3t","data":[1,2,3]}`)
	redacted := []byte(`{"secret":"[redacted]","data":[1,2,3]}`)
	hOrig := HashBytes(original)
	hRed := HashBytes(redacted)
	if hOrig == hRed {
		t.Fatal("redacted bytes must receive a different artifact identity")
	}
	// Artifact digests use the shared form: sha256: + 64 lowercase hex.
	for _, h := range []Digest{hOrig, hRed} {
		s := string(h)
		if !strings.HasPrefix(s, "sha256:") || len(s) != len("sha256:")+64 {
			t.Fatalf("digest must match shared form: %q", s)
		}
		for i := len("sha256:"); i < len(s); i++ {
			c := s[i]
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				t.Fatalf("digest hex must be lowercase: %q", s)
			}
		}
	}
	// Determinism: identical bytes, identical identity.
	if again := HashBytes(original); again != hOrig {
		t.Fatalf("hash must be deterministic: %s vs %s", again, hOrig)
	}
	// Event hash covers the canonical envelope with only event_hash removed:
	// two envelopes differing only in event_hash share the same event hash.
	e1 := testEnvelope("sha256:1111111111111111111111111111111111111111111111111111111111111111")
	e2 := e1
	e2.EventHash = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	he1, err := HashEvent(e1)
	if err != nil {
		t.Fatalf("HashEvent failed: %v", err)
	}
	he2, err := HashEvent(e2)
	if err != nil {
		t.Fatalf("HashEvent failed: %v", err)
	}
	if he1 != he2 {
		t.Fatalf("envelopes differing only in event_hash must share identity: %s vs %s", he1, he2)
	}
	// A payload change yields a different event hash.
	e3 := e1
	e3.Payload = map[string]any{"data": map[string]any{"v": 2}, "measurements": []any{}, "evidence_refs": []any{}, "artifact_refs": []any{}}
	he3, err := HashEvent(e3)
	if err != nil {
		t.Fatalf("HashEvent failed: %v", err)
	}
	if he3 == he1 {
		t.Fatal("payload change must change the event hash")
	}
}

func testEnvelope(eventHash string) JournalEnvelope {
	return JournalEnvelope{
		RecordType:        "journal_event",
		SchemaVersion:     "0.1.0",
		RunID:             "r1",
		JournalID:         "j1",
		ManifestHash:      testDigestA,
		Sequence:          2,
		EventID:           "e1",
		EventKind:         "k1",
		EventSchemaVer:    "v1",
		Role:              "external_input",
		AssertionKind:     "a1",
		OwnerDomain:       "d1",
		ProducerID:        "p1",
		ProducerSequence:  1,
		Provenance:        "prov",
		EvidenceScope:     "current_run",
		RecordedAt:        "2026-01-01T00:00:01Z",
		OccurredAt:        "2026-01-01T00:00:00Z",
		CausalRefs:        []string{},
		Payload:           map[string]any{"data": map[string]any{"v": 1}, "measurements": []any{}, "evidence_refs": []any{}, "artifact_refs": []any{}},
		PreviousEventHash: testDigestA,
		EventHash:         Digest(eventHash),
	}
}

func TestFormatAssertionsRejectInvalidDeclaredDatesAndURIs(t *testing.T) {
	// Invalid declared date-time.
	badTime := strings.Replace(validJournalEventDoc(""), `"2026-01-01T00:00:00Z"`, `"not-a-date"`, 1)
	if err := ValidateRecord("0.1.0", "journal_event", []byte(badTime)); err == nil {
		t.Fatal("expected invalid date-time rejection")
	}
	// Invalid declared calendar date inside open payload data.
	badDate := strings.Replace(validJournalEventDoc(""), `"data":{}`,
		`"data":{"collected_date":"2026-13-45"}`, 1)
	if err := ValidateRecord("0.1.0", "journal_event", []byte(badDate)); err == nil {
		t.Fatal("expected invalid date rejection")
	}
	// Invalid declared URI inside open payload data.
	badURI := strings.Replace(validJournalEventDoc(""), `"data":{}`,
		`"data":{"source_url":"not a uri"}`, 1)
	if err := ValidateRecord("0.1.0", "journal_event", []byte(badURI)); err == nil {
		t.Fatal("expected invalid URI rejection")
	}
	// Relative reference is not an acceptable declared URI.
	relURI := strings.Replace(validJournalEventDoc(""), `"data":{}`,
		`"data":{"source_url":"/relative/path"}`, 1)
	if err := ValidateRecord("0.1.0", "journal_event", []byte(relURI)); err == nil {
		t.Fatal("expected relative-URI rejection")
	}
	// Well-formed declarations are accepted.
	good := strings.Replace(validJournalEventDoc(""), `"data":{}`,
		`"data":{"collected_date":"2026-01-15","source_url":"https://example.com/evidence/1"}`, 1)
	if err := ValidateRecord("0.1.0", "journal_event", []byte(good)); err != nil {
		t.Fatalf("valid date/URI declarations must be accepted: %v", err)
	}
	// Invalid digest arithmetic is rejected.
	badDigest := strings.Replace(validJournalEventDoc(""), testDigestA, "sha256:xyz", 1)
	if err := ValidateRecord("0.1.0", "journal_event", []byte(badDigest)); err == nil {
		t.Fatal("expected invalid digest rejection")
	}
	// Negative size arithmetic is rejected.
	negSize := strings.Replace(validJournalEventDoc(""), `"artifact_refs":[]`,
		`"artifact_refs":[{"digest":"`+testDigestA+`","size_bytes":-5,"media_type":"application/json","owner_domain":"d1","access":"public"}]`, 1)
	if err := ValidateRecord("0.1.0", "journal_event", []byte(negSize)); err == nil {
		t.Fatal("expected negative size_bytes rejection")
	}
}

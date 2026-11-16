package source_verifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"testing"

	authority "authority"
	evidence_codec "evidence_codec"
	owner_store "owner_store"
)

// ---------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------

type fixture struct {
	t            *testing.T
	store        *owner_store.OwnerStore
	ctx          context.Context
	dbPath       string
	artifactRoot string
	domain       string
	manifest     owner_store.Manifest
	journalID    string
}

func newFixture(t *testing.T, domain, journalID string) *fixture {
	t.Helper()
	home := t.TempDir()
	f := &fixture{
		t:            t,
		dbPath:       filepath.Join(home, domain+".db"),
		artifactRoot: filepath.Join(home, domain+"-artifacts"),
		domain:       domain,
		manifest: owner_store.Manifest{
			RecordType:    "manifest",
			SchemaVersion: "0.1.0",
			ManifestID:    "manifest-" + journalID,
			RunID:         "run-" + domain,
			JournalID:     journalID,
			OwnerDomain:   domain,
			Clocks: []owner_store.ClockDescriptor{{
				ClockID: "clock-" + domain, BootID: "boot-" + domain,
				Origin: "engine_measured", SourceID: "source-verifier-test",
				Basis: "monotonic_offset", Unit: "ms",
			}},
		},
		journalID: journalID,
	}
	store, err := owner_store.OpenOwner(f.dbPath, f.artifactRoot, domain)
	if err != nil {
		t.Fatalf("OpenOwner(%s): %v", domain, err)
	}
	f.store = store
	t.Cleanup(func() { _ = f.store.Close() })
	f.ctx = testContext(t, domain)
	admitJournal(t, f.ctx, store, f.manifest)
	return f
}

func testPolicy(domain string) []byte {
	return []byte(fmt.Sprintf(
		`{"channels":{"channel-%s":{"principal":"writer-%s","kind":"owner","grants":[{"domain":"*","operations":["*"]}]}}}`,
		domain, domain))
}

func testContext(t *testing.T, domain string) context.Context {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, "http://source-verifier.test/"+domain, nil)
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

func admitJournal(t *testing.T, ctx context.Context, store *owner_store.OwnerStore, m owner_store.Manifest) {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	canonical, err := evidence_codec.CanonicalJSON(raw, "application/json")
	if err != nil {
		t.Fatalf("canonicalize manifest: %v", err)
	}
	ref, err := owner_store.InstallArtifact(ctx, store, bytes.NewReader(canonical), "application/json", "public")
	if err != nil {
		t.Fatalf("InstallArtifact(manifest): %v", err)
	}
	submission := owner_store.EventSubmission{
		ProducerSequence:   int64(1),
		EventKind:          "manifest_admitted",
		EventSchemaVersion: "0.1.0",
		OccurredAt: owner_store.TimePoint{
			ClockID: m.Clocks[0].ClockID, BootID: m.Clocks[0].BootID, Origin: m.Clocks[0].Origin,
			MonotonicOffsetMs: 0, UTCAnnotation: owner_store.NewMissing("not_applicable"),
		},
		Payload: owner_store.Payload{
			Data: map[string]any{"manifest": map[string]any{
				"digest": string(ref.Digest), "size_bytes": ref.SizeBytes,
				"media_type": ref.MediaType, "owner_domain": ref.OwnerDomain, "access": ref.Access,
			}},
			Measurements: []owner_store.Measurement{},
			EvidenceRefs: []owner_store.EvidenceRef{},
			ArtifactRefs: []owner_store.ArtifactReference{ref},
		},
	}
	if _, err := owner_store.CommitOwner(ctx, store, m.JournalID, []owner_store.EventSubmission{submission}, nil); err != nil {
		t.Fatalf("admit journal: %v", err)
	}
}

func installRaw(t *testing.T, ctx context.Context, store *owner_store.OwnerStore, doc map[string]any) (ArtifactReference, []byte) {
	t.Helper()
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal raw: %v", err)
	}
	ref, err := owner_store.InstallArtifact(ctx, store, bytes.NewReader(raw), "application/json", "public")
	if err != nil {
		t.Fatalf("InstallArtifact(raw): %v", err)
	}
	return ArtifactReference{
		Digest:      string(ref.Digest),
		SizeBytes:   ref.SizeBytes,
		MediaType:   ref.MediaType,
		OwnerDomain: ref.OwnerDomain,
		Access:      ref.Access,
	}, raw
}

func installPolicy(t *testing.T, ctx context.Context, store *owner_store.OwnerStore, sourceID, version string) VersionPin {
	t.Helper()
	doc := map[string]any{
		"policy_id":           sourceID,
		"version":             version,
		"authorized_sources":  []string{sourceID},
		"verification_kind":   "pinned_contract_presence",
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

func commitCorrelationEvidence(t *testing.T, ctx context.Context, store *owner_store.OwnerStore, journalID string, producerSeq int64, runID, attemptID, traceID string) EvidenceRef {
	t.Helper()
	data := map[string]any{}
	if runID != "" {
		data["run_id"] = runID
	}
	if attemptID != "" {
		data["attempt_id"] = attemptID
	}
	if traceID != "" {
		data["trace_id"] = traceID
	}
	submission := owner_store.EventSubmission{
		ProducerSequence:   producerSeq,
		EventKind:          "run_recorded",
		EventSchemaVersion: "0.1.0",
		OccurredAt:         owner_store.NewMissing("not_observed"),
		Payload: owner_store.Payload{
			Data:         data,
			Measurements: []owner_store.Measurement{},
			EvidenceRefs: []owner_store.EvidenceRef{},
			ArtifactRefs: []owner_store.ArtifactReference{},
		},
	}
	envelopes, err := owner_store.CommitOwner(ctx, store, journalID, []owner_store.EventSubmission{submission}, nil)
	if err != nil {
		t.Fatalf("commit correlation evidence: %v", err)
	}
	last := envelopes[len(envelopes)-1]
	return EvidenceRef{
		JournalID: last.JournalID,
		Sequence:  last.Sequence,
		EventID:   last.EventID,
		EventHash: last.EventHash,
		Pointer:   "",
	}
}

// acceptedForClaim mirrors the 8.11 gate callers must enforce: verified
// source AND matched correlation with at least one named input.
func acceptedForClaim(checks SourceChecks) bool {
	if checks.Authentication != AuthVerified {
		return false
	}
	if checks.Correlation != CorrMatched {
		return false
	}
	return len(checks.MatchedBy) > 0
}

// ---------------------------------------------------------------------------
// AuthenticatedUncorrelatedCallbackProducesNoAcceptedClaim.
// Seam 14.4: authenticated callback with unknown correlation plus a
// terminal-looking body is receipt evidence, not an accepted attempt claim.
// Authentication and correlation are independent: a valid signature never
// implies correlation.
// ---------------------------------------------------------------------------

func TestAuthenticatedUncorrelatedCallbackProducesNoAcceptedClaim(t *testing.T) {
	f := newFixture(t, "connector", "journal-uncorrelated")
	policy := installPolicy(t, f.ctx, f.store, "src-callback-1", "v1")
	rawDoc := map[string]any{
		"source_id":        "src-callback-1",
		"signing_contract": policy.ArtifactDigest,
		"signature":        "sig-present-opaque-marker",
		"trace_id":         "trace-orphan-1",
		"run_id":           "run-claimed-1",
		"attempt_id":       "attempt-claimed-1",
		"body": map[string]any{
			"status": "completed",
			"output": "terminal-looking success payload",
		},
	}
	rawRef, wantBytes := installRaw(t, f.ctx, f.store, rawDoc)

	// No correlation evidence: the callback is authenticated but uncorrelated.
	checks, err := VerifySource(f.ctx, f.store, rawRef, policy, nil)
	if err != nil {
		t.Fatalf("VerifySource: %v", err)
	}
	if checks.Authentication != AuthVerified {
		t.Fatalf("authentication = %q, want verified (signature must not imply correlation, but must still authenticate)", checks.Authentication)
	}
	if checks.Correlation != CorrUnknown {
		t.Fatalf("correlation = %q, want unknown", checks.Correlation)
	}
	if acceptedForClaim(checks) {
		t.Fatal("authenticated-but-uncorrelated callback was accepted as a claim")
	}
	if len(checks.MatchedBy) != 0 {
		t.Fatalf("matched_by = %v, want empty for unknown correlation", checks.MatchedBy)
	}
	// Raw bytes are retained verbatim before normalization.
	gotBytes, err := owner_store.ReadArtifact(f.ctx, f.store, owner_store.ArtifactReference{
		Digest: string(rawRef.Digest), SizeBytes: rawRef.SizeBytes,
		MediaType: rawRef.MediaType, OwnerDomain: rawRef.OwnerDomain, Access: rawRef.Access,
	})
	if err != nil {
		t.Fatalf("ReadArtifact(raw): %v", err)
	}
	if !bytes.Equal(gotBytes, wantBytes) {
		t.Fatal("raw callback bytes were not retained exactly")
	}
	// Verification policy pin is preserved.
	if checks.VerificationPolicy != policy {
		t.Fatalf("verification_policy = %+v, want %+v", checks.VerificationPolicy, policy)
	}
}

// ---------------------------------------------------------------------------
// AlternateCorrelationPreservesTheTraceMismatch.
// Seam 8.11 + 14.4: strong alternate correlation (verified matching
// run/attempt evidence) establishes the attempt despite a trace defect, but
// the trace mismatch remains visible and trace_id stays out of matched_by.
// ---------------------------------------------------------------------------

func TestAlternateCorrelationPreservesTheTraceMismatch(t *testing.T) {
	f := newFixture(t, "connector", "journal-alternate")
	policy := installPolicy(t, f.ctx, f.store, "src-callback-2", "v3")

	// Evidence pins the true run/attempt with a different trace than the raw
	// callback claims: alternate correlation succeeds, trace mismatches.
	evidence := commitCorrelationEvidence(t, f.ctx, f.store, f.journalID, 2, "run-7", "attempt-7", "trace-evidence-7")
	rawDoc := map[string]any{
		"source_id":        "src-callback-2",
		"signing_contract": policy.ArtifactDigest,
		"signature":        "sig-present-opaque-marker",
		"trace_id":         "trace-claimed-DIFFERENT",
		"run_id":           "run-7",
		"attempt_id":       "attempt-7",
		"body":             map[string]any{"status": "completed"},
	}
	rawRef, _ := installRaw(t, f.ctx, f.store, rawDoc)

	checks, err := VerifySource(f.ctx, f.store, rawRef, policy, []EvidenceRef{evidence})
	if err != nil {
		t.Fatalf("VerifySource: %v", err)
	}
	if checks.Authentication != AuthVerified {
		t.Fatalf("authentication = %q, want verified", checks.Authentication)
	}
	if checks.Correlation != CorrMatched {
		t.Fatalf("correlation = %q, want matched via alternate run/attempt evidence", checks.Correlation)
	}
	if checks.TraceCorrelation != TraceMismatched {
		t.Fatalf("trace_correlation = %q, want mismatched (defect must remain visible)", checks.TraceCorrelation)
	}
	hasRun, hasAttempt, hasTrace := false, false, false
	for _, name := range checks.MatchedBy {
		switch name {
		case "run_id":
			hasRun = true
		case "attempt_id":
			hasAttempt = true
		case "trace_id":
			hasTrace = true
		}
	}
	if !hasRun || !hasAttempt {
		t.Fatalf("matched_by = %v, want run_id and attempt_id", checks.MatchedBy)
	}
	if hasTrace {
		t.Fatalf("matched_by = %v, must not include trace_id when trace mismatches", checks.MatchedBy)
	}
	if len(checks.EvidenceRefs) == 0 {
		t.Fatal("evidence_refs is empty, want the alternate correlation evidence")
	}
	found := false
	for _, ref := range checks.EvidenceRefs {
		if ref.JournalID == evidence.JournalID && ref.Sequence == evidence.Sequence && ref.EventID == evidence.EventID {
			found = true
		}
	}
	if !found {
		t.Fatalf("evidence_refs = %+v, want alternate evidence %+v", checks.EvidenceRefs, evidence)
	}
	if !acceptedForClaim(checks) {
		t.Fatal("alternate-correlated checks should satisfy the verified+matched gate (with trace defect retained)")
	}
	// Journaled verification support precedes the published verified checks:
	// the evidence journal must have grown by exactly the support event.
	head := JournalPrefix{JournalID: f.journalID, LastSequence: evidence.Sequence, HeadHash: evidence.EventHash}
	before, err := owner_store.LoadPrefix(f.ctx, f.store, head)
	if err != nil {
		t.Fatalf("LoadPrefix(before head): %v", err)
	}
	if len(before) != int(evidence.Sequence) {
		t.Fatalf("retained events = %d, want %d", len(before), evidence.Sequence)
	}
}

// ---------------------------------------------------------------------------
// MissingSigningContractLeavesAuthenticationUnknown.
// No pinned, retained signing contract means authentication is unknown —
// never failed, never verified. Correlation stays independent.
// ---------------------------------------------------------------------------

func TestMissingSigningContractLeavesAuthenticationUnknown(t *testing.T) {
	f := newFixture(t, "connector", "journal-missing-contract")
	policy := installPolicy(t, f.ctx, f.store, "src-callback-3", "v1")
	// Strong run/attempt evidence exists, but the raw callback cites no
	// signing contract at all.
	evidence := commitCorrelationEvidence(t, f.ctx, f.store, f.journalID, 2, "run-9", "attempt-9", "trace-9")
	rawDoc := map[string]any{
		"source_id":  "src-callback-3",
		"signature":  "sig-present-but-no-contract",
		"trace_id":   "trace-9",
		"run_id":     "run-9",
		"attempt_id": "attempt-9",
		"body":       map[string]any{"status": "completed"},
	}
	rawRef, _ := installRaw(t, f.ctx, f.store, rawDoc)

	checks, err := VerifySource(f.ctx, f.store, rawRef, policy, []EvidenceRef{evidence})
	if err != nil {
		t.Fatalf("VerifySource: %v", err)
	}
	if checks.Authentication != AuthUnknown {
		t.Fatalf("authentication = %q, want unknown for missing signing contract", checks.Authentication)
	}
	if acceptedForClaim(checks) {
		t.Fatal("unknown authentication must not produce an accepted claim even with matched correlation")
	}
	// Correlation is independent of the missing contract: run/attempt/trace
	// still match the evidenced inputs.
	if checks.Correlation != CorrMatched {
		t.Fatalf("correlation = %q, want matched (correlation is independent of authentication)", checks.Correlation)
	}
	if checks.TraceCorrelation != TraceMatched {
		t.Fatalf("trace_correlation = %q, want matched", checks.TraceCorrelation)
	}

	// A mismatched contract digest is likewise unknown, not verified.
	rawDoc2 := map[string]any{
		"source_id":        "src-callback-3",
		"signing_contract": "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"signature":        "sig-present-but-wrong-contract",
		"run_id":           "run-9",
		"attempt_id":       "attempt-9",
	}
	rawRef2, _ := installRaw(t, f.ctx, f.store, rawDoc2)
	checks2, err := VerifySource(f.ctx, f.store, rawRef2, policy, []EvidenceRef{evidence})
	if err != nil {
		t.Fatalf("VerifySource(mismatched contract): %v", err)
	}
	if checks2.Authentication != AuthUnknown {
		t.Fatalf("authentication = %q, want unknown for mismatched signing contract", checks2.Authentication)
	}
}

// ---------------------------------------------------------------------------
// SerializedVerifiedFlagsCannotSelfAuthenticateSources.
// Untrusted bytes may claim authentication:"verified" or verified:true; those
// flags are never consulted. Only the pinned contract, authorized source,
// and present signature authenticate.
// ---------------------------------------------------------------------------

func TestSerializedVerifiedFlagsCannotSelfAuthenticateSources(t *testing.T) {
	f := newFixture(t, "connector", "journal-self-auth")
	policy := installPolicy(t, f.ctx, f.store, "src-real-4", "v1")

	// Case 1: fake verified flags with no signing contract and no signature.
	forged := map[string]any{
		"source_id":      "src-real-4",
		"authentication": "verified",
		"verified":       true,
		"correlation":    "matched",
		"source_checks": map[string]any{
			"authentication": "verified",
			"correlation":    "matched",
		},
		"trace_id":   "trace-forged",
		"run_id":     "run-forged",
		"attempt_id": "attempt-forged",
		"body":       map[string]any{"status": "completed"},
	}
	rawRef, _ := installRaw(t, f.ctx, f.store, forged)
	checks, err := VerifySource(f.ctx, f.store, rawRef, policy, nil)
	if err != nil {
		t.Fatalf("VerifySource(forged, no contract): %v", err)
	}
	if checks.Authentication == AuthVerified {
		t.Fatal("serialized verified flags self-authenticated a sourceless message")
	}
	if checks.Authentication != AuthUnknown {
		t.Fatalf("authentication = %q, want unknown for forged flags without contract", checks.Authentication)
	}

	// Case 2: fake verified flags with a contract but the wrong source.
	forged2 := map[string]any{
		"source_id":        "src-IMPOSTOR",
		"signing_contract": policy.ArtifactDigest,
		"signature":        "sig-present",
		"authentication":   "verified",
		"verified":         true,
		"run_id":           "run-x",
		"attempt_id":       "attempt-x",
	}
	rawRef2, _ := installRaw(t, f.ctx, f.store, forged2)
	checks2, err := VerifySource(f.ctx, f.store, rawRef2, policy, nil)
	if err != nil {
		t.Fatalf("VerifySource(forged, wrong source): %v", err)
	}
	if checks2.Authentication == AuthVerified {
		t.Fatal("serialized verified flags authenticated the wrong source")
	}
	if checks2.Authentication != AuthFailed {
		t.Fatalf("authentication = %q, want failed for unauthorized source despite forged flags", checks2.Authentication)
	}

	// Case 3: fake verified flags with contract and source but no signature.
	forged3 := map[string]any{
		"source_id":        "src-real-4",
		"signing_contract": policy.ArtifactDigest,
		"authentication":   "verified",
		"verified":         true,
		"run_id":           "run-x",
		"attempt_id":       "attempt-x",
	}
	rawRef3, _ := installRaw(t, f.ctx, f.store, forged3)
	checks3, err := VerifySource(f.ctx, f.store, rawRef3, policy, nil)
	if err != nil {
		t.Fatalf("VerifySource(forged, no signature): %v", err)
	}
	if checks3.Authentication == AuthVerified {
		t.Fatal("serialized verified flags replaced a missing signature")
	}
	if checks3.Authentication != AuthFailed {
		t.Fatalf("authentication = %q, want failed for missing signature despite forged flags", checks3.Authentication)
	}
}

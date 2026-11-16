// Package source_verifier implements tier-4 Hellscape source verification.
//
// It enforces seam-mappings/hellscape-seam-mapping.md sections 4.6 (imported
// evidence), 8.11 (SourceChecks and normalization), and 14.4 (late-evidence
// truth cases), plus invariants EK-PROVENANCE, EK-CLAIMS,
// LIFE-SOURCE-CHECKS, LIFE-ORIGIN, EXT-NORMALIZE, and EXT-AUTHORITY:
//
//   - Source identity and attempt correlation are verified independently.
//     A valid signature with a trace mismatch remains authenticated but not
//     reliably correlated to the claimed attempt.
//   - Accepted claims require verified source AND matched attempt
//     correlation. Authenticated-but-uncorrelated messages remain receipt
//     evidence, never accepted attempt claims.
//   - Trace mismatch stays visible even when strong alternate correlation
//     (run/attempt evidence) establishes the attempt.
//   - Exact native bodies are retained before normalization; unverified or
//     uncorrelated messages keep raw bytes but produce no accepted claims.
//   - Caller identity derives only from authenticated channel registration.
//     IDs and digests are correlation keys, never bearer authority.
//   - Serialized "verified" flags inside untrusted bytes never authenticate
//     a source; authentication requires a pinned, retained signing contract,
//     an authorized source ID, and a present signature marker.
//
// This module invents no signing algorithms, key-distribution contracts,
// native message IDs, or receipt IDs. It checks contract pinning and field
// presence against retained evidence; cryptographic verification itself lives
// with the authenticated channel registration. It runs no target probes and
// performs only owner-local reads and commits.
package source_verifier

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	authority "authority"
	evidence_codec "evidence_codec"
	journal_rules "journal_rules"
	owner_store "owner_store"
)

// ---------------------------------------------------------------------------
// Evidence-kernel aliases: shared wire shapes so CONSUMES calls need no
// translation.
// ---------------------------------------------------------------------------

// OwnerStore is one owner-local durable boundary.
type OwnerStore = owner_store.OwnerStore

// EventSubmission is the ingress shape for owner-local commits.
type EventSubmission = owner_store.EventSubmission

// JournalEnvelope is the complete stored journal event envelope.
type JournalEnvelope = journal_rules.JournalEnvelope

// JournalPrefix is an immutable journal prefix.
type JournalPrefix = journal_rules.JournalPrefix

// EvidenceRef cites one retained journal event coordinate plus a JSON pointer.
type EvidenceRef = journal_rules.EvidenceRef

// ArtifactReference is an immutable byte identity plus resolver metadata.
type ArtifactReference = journal_rules.ArtifactReference

// TimePoint is a coordinate in a registered monotonic clock.
type TimePoint = journal_rules.TimePoint

// MissingEnvelope is a typed EK Missing value.
type MissingEnvelope = journal_rules.MissingEnvelope

// NewMissing builds a reasoned Missing envelope with a null value.
func NewMissing(reason string) MissingEnvelope { return journal_rules.NewMissing(reason) }

// Compile-time CONSUMES linkage: fail compilation if a declared upstream
// signature disappears.
var (
	_ = owner_store.ReadArtifact
	_ = owner_store.CommitOwner
	_ = authority.Authorize
	_ = journal_rules.ResolveEvidence
	_ = evidence_codec.ValidateRecord
)

// ---------------------------------------------------------------------------
// Shared contract types (contracts/02-external-connector.yaml SourceChecks).
// ---------------------------------------------------------------------------

// VersionPin pins an immutable versioned artifact.
type VersionPin struct {
	ID             string `json:"id"`
	Version        string `json:"version"`
	ArtifactDigest string `json:"artifact_digest"`
}

// SourceChecks retains authentication and correlation verification.
type SourceChecks struct {
	Authentication     string       `json:"authentication"`
	Correlation        string       `json:"correlation"`
	TraceCorrelation   string       `json:"trace_correlation"`
	VerificationPolicy VersionPin   `json:"verification_policy"`
	MatchedBy          []string     `json:"matched_by"`
	EvidenceRefs       []EvidenceRef `json:"evidence_refs"`
}

// Authentication values.
const (
	AuthVerified = "verified"
	AuthFailed   = "failed"
	AuthUnknown  = "unknown"
)

// Correlation values.
const (
	CorrMatched    = "matched"
	CorrMismatched = "mismatched"
	CorrUnknown    = "unknown"
)

// Trace correlation values.
const (
	TraceMatched       = "matched"
	TraceMismatched    = "mismatched"
	TraceNotObserved   = "not_observed"
	TraceNotApplicable = "not_applicable"
)

// verifyOperation is the authority operation for source verification. Caller
// identity still derives solely from authenticated channel registration; the
// raw digest passed as resourceID is correlation only, never authority.
const verifyOperation = "verify_source"

// verificationEventKind journals verification support before verified checks
// are published. It carries no special registry semantics; the owner-local
// ingestion authority assigns role, assertion kind, provenance, and scope.
const verificationEventKind = "source_verified"

// verificationEventSchema is the event document version for support events.
const verificationEventSchema = "0.1.0"

// ---------------------------------------------------------------------------
// VerifySource.
// ---------------------------------------------------------------------------

// VerifySource verifies one retained native/callback body against a pinned
// verification policy and independently evidenced attempt correlation.
//
//   - raw must already be installed: its exact bytes are read via ReadArtifact
//     and retained before any normalization. The bytes are parsed for
//     source_id, signing_contract, signature, trace_id, run_id, and
//     attempt_id. Embedded "authentication", "verified", "correlation", or
//     "source_checks" fields are never consulted.
//   - policy pins the authorized source (ID) and signing contract
//     (ArtifactDigest). The contract artifact must be retained in the same
//     store; a missing contract leaves authentication unknown.
//   - correlationEvidence cites retained journal events whose payload data
//     carries run/attempt/trace correlation inputs. Each ref is resolved via
//     LoadPrefix plus ResolveEvidence pinned at its own sequence, so no
//     additional prefix needs to be supplied. Authentication never implies
//     correlation and a matching trace never implies authentication.
//   - Verified-plus-matched checks are published only after a verification
//     support event is durably journaled via CommitOwner and its envelopes
//     pass the ValidateRecord structural gate and resolve via ResolveEvidence.
//
// It returns SourceChecks with verified/failed/unknown authentication,
// matched/mismatched/unknown correlation, and
// matched/mismatched/not_observed trace correlation, plus the actual
// matching-input names and the resolved support refs. Unverified or
// uncorrelated inputs keep raw bytes but must not be treated as accepted
// attempt claims by callers.
func VerifySource(ctx context.Context, store *OwnerStore, raw ArtifactReference, policy VersionPin, correlationEvidence []EvidenceRef) (SourceChecks, error) {
	empty := SourceChecks{
		Authentication:     AuthUnknown,
		Correlation:        CorrUnknown,
		TraceCorrelation:   TraceNotObserved,
		VerificationPolicy: policy,
		MatchedBy:          []string{},
		EvidenceRefs:       []EvidenceRef{},
	}
	if store == nil {
		return empty, fmt.Errorf("source_verifier: store is required")
	}
	if err := validateVersionPin(policy); err != nil {
		return empty, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	// EXT-AUTHORITY: identity from authenticated channel registration only.
	// The raw digest is correlation, never bearer authority.
	if err := authority.Authorize(ctx, raw.OwnerDomain, verifyOperation, raw.Digest); err != nil {
		return empty, fmt.Errorf("source_verifier: unauthorized: %v", err)
	}
	// EXT-NORMALIZE: retain exact native bytes before normalization.
	rawBytes, err := owner_store.ReadArtifact(ctx, store, raw)
	if err != nil {
		return empty, fmt.Errorf("source_verifier: read raw body: %w", err)
	}
	mediaType := raw.MediaType
	if strings.TrimSpace(mediaType) == "" {
		mediaType = "application/json"
	}
	// Reject duplicate keys, non-JSON, and non-finite literals before use.
	// Retention still uses rawBytes verbatim; this gate only validates.
	if _, err := evidence_codec.CanonicalJSON(rawBytes, mediaType); err != nil {
		return empty, fmt.Errorf("source_verifier: raw body is not canonical JSON: %v", err)
	}
	var rawDoc map[string]any
	if err := json.Unmarshal(rawBytes, &rawDoc); err != nil {
		return empty, fmt.Errorf("source_verifier: raw body is not a JSON object: %v", err)
	}
	if rawDoc == nil {
		return empty, fmt.Errorf("source_verifier: raw body is not a JSON object")
	}

	// Authentication and correlation are independent checks. Neither implies
	// the other.
	authentication := verifyAuthentication(ctx, store, rawDoc, policy)
	correlation, trace, matchedBy, resolved := verifyCorrelation(ctx, store, rawDoc, correlationEvidence)

	checks := SourceChecks{
		Authentication:     authentication,
		Correlation:        correlation,
		TraceCorrelation:   trace,
		VerificationPolicy: policy,
		MatchedBy:          matchedBy,
		EvidenceRefs:       resolved,
	}
	if checks.MatchedBy == nil {
		checks.MatchedBy = []string{}
	}
	if checks.EvidenceRefs == nil {
		checks.EvidenceRefs = []EvidenceRef{}
	}

	// Publish verified checks only after journaled verification support is
	// durable, structurally valid, and resolvable. Unverified results return
	// without a new commit; the raw body is already retained and the
	// supplied correlation journals are the support.
	if authentication == AuthVerified && correlation == CorrMatched {
		if len(correlationEvidence) == 0 {
			return empty, fmt.Errorf("source_verifier: matched correlation requires at least one evidenced reference")
		}
		journalID := strings.TrimSpace(correlationEvidence[0].JournalID)
		if journalID == "" {
			return empty, fmt.Errorf("source_verifier: correlation evidence must name a journal")
		}
		if err := journalVerificationSupport(ctx, store, journalID, raw, policy, checks, correlationEvidence); err != nil {
			return empty, err
		}
	}
	return checks, nil
}

// ---------------------------------------------------------------------------
// Authentication: pinned contract, authorized source, present signature.
// Serialized verified flags are never consulted.
// ---------------------------------------------------------------------------

func verifyAuthentication(ctx context.Context, store *OwnerStore, rawDoc map[string]any, policy VersionPin) string {
	// The signing contract must be pinned by the policy and retained. A
	// missing contract leaves authentication unknown rather than failed:
	// absence of proof is not proof of forgery.
	contract, hasContract := stringField(rawDoc, "signing_contract")
	if !hasContract || strings.TrimSpace(contract) == "" {
		return AuthUnknown
	}
	if !validDigest(contract) {
		return AuthUnknown
	}
	if contract != policy.ArtifactDigest {
		return AuthUnknown
	}
	// The pinned contract bytes must exist in the owner-local store.
	if _, err := owner_store.ReadArtifact(ctx, store, ArtifactReference{Digest: policy.ArtifactDigest}); err != nil {
		return AuthUnknown
	}
	// The source must be the policy-authorized source. No native IDs are
	// invented here; the raw source_id is compared verbatim to the pin.
	sourceID, hasSource := stringField(rawDoc, "source_id")
	if !hasSource || strings.TrimSpace(sourceID) == "" {
		return AuthFailed
	}
	if sourceID != policy.ID {
		return AuthFailed
	}
	// A signature marker must be present. This module performs no
	// cryptographic verification and invents no signing algorithms; it only
	// checks presence against the pinned, retained contract. Absence with a
	// present contract is a failed proof, not unknown provenance.
	sig, hasSig := stringField(rawDoc, "signature")
	if !hasSig || strings.TrimSpace(sig) == "" {
		return AuthFailed
	}
	return AuthVerified
}

// ---------------------------------------------------------------------------
// Correlation: run/attempt matching with preserved trace mismatch.
// ---------------------------------------------------------------------------

// correlationIDs carries one claimed or evidenced correlation triple.
type correlationIDs struct {
	runID     string
	attemptID string
	traceID   string
	hasRun    bool
	hasAtt    bool
	hasTrace  bool
}

// resolvedOne pairs a resolved evidence ref with its correlation inputs.
type resolvedOne struct {
	ref EvidenceRef
	ids correlationIDs
}

func verifyCorrelation(ctx context.Context, store *OwnerStore, rawDoc map[string]any, refs []EvidenceRef) (string, string, []string, []EvidenceRef) {
	claimed := claimedIDs(rawDoc)
	if len(refs) == 0 {
		trace := TraceNotObserved
		// No evidence to compare against: correlation is unknown however
		// terminal-looking the body is. Trace with no observation stays
		// not_observed rather than mismatched.
		return CorrUnknown, trace, []string{}, []EvidenceRef{}
	}
	var resolved []resolvedOne
	seen := map[string]bool{}
	var outRefs []EvidenceRef
	for _, ref := range refs {
		key := ref.JournalID + "\x00" + fmt.Sprint(ref.Sequence) + "\x00" + ref.EventID + "\x00" + ref.EventHash + "\x00" + ref.Pointer
		if seen[key] {
			continue
		}
		seen[key] = true
		ids, ok := resolveOneCorrelation(ctx, store, ref)
		if !ok {
			continue
		}
		resolved = append(resolved, resolvedOne{ref: ref, ids: ids})
		outRefs = append(outRefs, ref)
	}
	if outRefs == nil {
		outRefs = []EvidenceRef{}
	}
	if len(resolved) == 0 {
		// Supplied refs but none resolve: unknown, not a contradiction.
		return CorrUnknown, traceForUnresolved(claimed), []string{}, outRefs
	}
	var matchedBy []string
	runMatched := claimed.hasRun && anyMatch(resolved, func(c correlationIDs) (string, bool) { return c.runID, c.hasRun }, claimed.runID)
	attMatched := claimed.hasAtt && anyMatch(resolved, func(c correlationIDs) (string, bool) { return c.attemptID, c.hasAtt }, claimed.attemptID)
	traceMatched := claimed.hasTrace && anyMatch(resolved, func(c correlationIDs) (string, bool) { return c.traceID, c.hasTrace }, claimed.traceID)
	if runMatched {
		matchedBy = append(matchedBy, "run_id")
	}
	if attMatched {
		matchedBy = append(matchedBy, "attempt_id")
	}
	if traceMatched {
		matchedBy = append(matchedBy, "trace_id")
	}
	if matchedBy == nil {
		matchedBy = []string{}
	}

	// Correlation requires both run and attempt to match via evidenced
	// inputs. Trace alone never establishes the attempt.
	var correlation string
	switch {
	case runMatched && attMatched:
		correlation = CorrMatched
	case traceMatched && claimed.hasRun && claimed.hasAtt:
		// Same trace but a different run/attempt is an explicit
		// contradiction, not mere absence of proof.
		correlation = CorrMismatched
	default:
		correlation = CorrUnknown
	}

	// Trace mismatch remains visible even when alternate correlation
	// succeeds: a matched attempt with a trace defect keeps
	// trace_correlation mismatched and omits trace_id from matched_by.
	var trace string
	switch {
	case !claimed.hasTrace:
		trace = TraceNotObserved
	case traceMatched:
		trace = TraceMatched
	case evidencedTracePresent(resolved):
		trace = TraceMismatched
	default:
		trace = TraceNotObserved
	}
	return correlation, trace, matchedBy, outRefs
}

func claimedIDs(rawDoc map[string]any) correlationIDs {
	var out correlationIDs
	if v, ok := stringField(rawDoc, "run_id"); ok && strings.TrimSpace(v) != "" {
		out.runID, out.hasRun = v, true
	}
	if v, ok := stringField(rawDoc, "attempt_id"); ok && strings.TrimSpace(v) != "" {
		out.attemptID, out.hasAtt = v, true
	}
	if v, ok := stringField(rawDoc, "trace_id"); ok && strings.TrimSpace(v) != "" {
		out.traceID, out.hasTrace = v, true
	}
	return out
}

func traceForUnresolved(claimed correlationIDs) string {
	if !claimed.hasTrace {
		return TraceNotObserved
	}
	return TraceNotObserved
}

func anyMatch(resolved []resolvedOne, pick func(correlationIDs) (string, bool), want string) bool {
	for _, r := range resolved {
		got, ok := pick(r.ids)
		if ok && got == want {
			return true
		}
	}
	return false
}

func evidencedTracePresent(resolved []resolvedOne) bool {
	for _, r := range resolved {
		if r.ids.hasTrace {
			return true
		}
	}
	return false
}

// resolveOneCorrelation resolves one EvidenceRef by pinning a prefix at its
// own sequence, loading the retained events owner-locally, and resolving via
// the journal kernel. Whole-envelope resolutions pass the ValidateRecord
// structural gate. It returns false for any unresolvable or malformed
// support without failing the whole verification: unknown evidence yields
// unknown correlation, not an error.
func resolveOneCorrelation(ctx context.Context, store *OwnerStore, ref EvidenceRef) (correlationIDs, bool) {
	var empty correlationIDs
	if strings.TrimSpace(ref.JournalID) == "" {
		return empty, false
	}
	if ref.Sequence < 1 {
		return empty, false
	}
	if !validDigest(ref.EventHash) {
		return empty, false
	}
	if !validJSONPointer(ref.Pointer) {
		return empty, false
	}
	prefix := JournalPrefix{
		JournalID:    ref.JournalID,
		LastSequence: ref.Sequence,
		HeadHash:     ref.EventHash,
	}
	events, err := owner_store.LoadPrefix(ctx, store, prefix)
	if err != nil {
		return empty, false
	}
	resolvedBytes, err := journal_rules.ResolveEvidence(prefix, events, ref)
	if err != nil {
		return empty, false
	}
	if len(resolvedBytes) == 0 {
		return empty, false
	}
	// Whole-envelope evidence must pass the structural gate.
	if ref.Pointer == "" {
		var env JournalEnvelope
		if err := json.Unmarshal(resolvedBytes, &env); err == nil && env.RecordType != "" {
			if err := evidence_codec.ValidateRecord(env.SchemaVersion, env.RecordType, resolvedBytes); err != nil {
				return empty, false
			}
			return idsFromEnvelope(env), true
		}
	}
	// Generic object carrying correlation inputs.
	var obj map[string]any
	if err := json.Unmarshal(resolvedBytes, &obj); err == nil && obj != nil {
		if _, hasPayload := obj["payload"]; hasPayload {
			var env JournalEnvelope
			if err := json.Unmarshal(resolvedBytes, &env); err == nil && env.Payload.Data != nil {
				return idsFromEnvelope(env), true
			}
		}
		if ids, ok := idsFromMap(obj); ok {
			return ids, true
		}
	}
	// Single string value addressed by pointer: attribute by pointer suffix.
	var s string
	if err := json.Unmarshal(resolvedBytes, &s); err == nil {
		lower := strings.ToLower(ref.Pointer)
		switch {
		case strings.HasSuffix(lower, "run_id"):
			if strings.TrimSpace(s) != "" {
				return correlationIDs{runID: s, hasRun: true}, true
			}
		case strings.HasSuffix(lower, "attempt_id"):
			if strings.TrimSpace(s) != "" {
				return correlationIDs{attemptID: s, hasAtt: true}, true
			}
		case strings.HasSuffix(lower, "trace_id"):
			if strings.TrimSpace(s) != "" {
				return correlationIDs{traceID: s, hasTrace: true}, true
			}
		}
		return empty, false
	}
	return empty, false
}

func idsFromEnvelope(env JournalEnvelope) correlationIDs {
	var out correlationIDs
	if env.Payload.Data == nil {
		return out
	}
	return idsFromData(env.Payload.Data)
}

func idsFromMap(obj map[string]any) (correlationIDs, bool) {
	ids := idsFromData(obj)
	if ids.hasRun || ids.hasAtt || ids.hasTrace {
		return ids, true
	}
	return correlationIDs{}, false
}

func idsFromData(data map[string]any) correlationIDs {
	var out correlationIDs
	if v, ok := stringField(data, "run_id"); ok && strings.TrimSpace(v) != "" {
		out.runID, out.hasRun = v, true
	}
	if v, ok := stringField(data, "attempt_id"); ok && strings.TrimSpace(v) != "" {
		out.attemptID, out.hasAtt = v, true
	}
	if v, ok := stringField(data, "trace_id"); ok && strings.TrimSpace(v) != "" {
		out.traceID, out.hasTrace = v, true
	}
	return out
}

// ---------------------------------------------------------------------------
// Journaled verification support before publishing verified checks.
// ---------------------------------------------------------------------------

func journalVerificationSupport(ctx context.Context, store *OwnerStore, journalID string, raw ArtifactReference, policy VersionPin, checks SourceChecks, support []EvidenceRef) error {
	matched := make([]any, 0, len(checks.MatchedBy))
	for _, name := range checks.MatchedBy {
		matched = append(matched, name)
	}
	supportRefs := make([]EvidenceRef, 0, len(support))
	seen := map[string]bool{}
	for _, ref := range support {
		key := ref.JournalID + "\x00" + fmt.Sprint(ref.Sequence) + "\x00" + ref.EventID + "\x00" + ref.EventHash + "\x00" + ref.Pointer
		if seen[key] {
			continue
		}
		seen[key] = true
		supportRefs = append(supportRefs, ref)
	}
	submission := EventSubmission{
		ProducerSequence:   NewMissing("not_applicable"),
		EventKind:          verificationEventKind,
		EventSchemaVersion: verificationEventSchema,
		OccurredAt:         NewMissing("not_observed"),
		Payload: journal_rules.Payload{
			Data: map[string]any{
				"raw_digest":        raw.Digest,
				"verification_policy": map[string]any{
					"id":              policy.ID,
					"version":         policy.Version,
					"artifact_digest": policy.ArtifactDigest,
				},
				"authentication":   checks.Authentication,
				"correlation":      checks.Correlation,
				"trace_correlation": checks.TraceCorrelation,
				"matched_by":       matched,
			},
			Measurements: []journal_rules.Measurement{},
			EvidenceRefs: supportRefs,
			ArtifactRefs: []ArtifactReference{raw},
		},
	}
	envelopes, err := owner_store.CommitOwner(ctx, store, journalID, []EventSubmission{submission}, nil)
	if err != nil {
		return fmt.Errorf("source_verifier: journal verification support: %w", err)
	}
	if len(envelopes) == 0 {
		return fmt.Errorf("source_verifier: verification commit returned no envelopes")
	}
	for i := range envelopes {
		envRaw, err := json.Marshal(envelopes[i])
		if err != nil {
			return fmt.Errorf("source_verifier: encode verification envelope: %v", err)
		}
		if err := evidence_codec.ValidateRecord(envelopes[i].SchemaVersion, envelopes[i].RecordType, envRaw); err != nil {
			return fmt.Errorf("source_verifier: verification envelope structural gate: %v", err)
		}
	}
	// Prove the journaled support resolves before publishing verified checks.
	last := envelopes[len(envelopes)-1]
	prefix := JournalPrefix{
		JournalID:    journalID,
		LastSequence: last.Sequence,
		HeadHash:     last.EventHash,
	}
	events, err := owner_store.LoadPrefix(ctx, store, prefix)
	if err != nil {
		return fmt.Errorf("source_verifier: load verification prefix: %w", err)
	}
	verRef := EvidenceRef{
		JournalID: journalID,
		Sequence:  last.Sequence,
		EventID:   last.EventID,
		EventHash: last.EventHash,
		Pointer:   "",
	}
	if _, err := journal_rules.ResolveEvidence(prefix, events, verRef); err != nil {
		return fmt.Errorf("source_verifier: verification support does not resolve: %v", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Field helpers: typed Missing and native nulls stay distinct; only nonempty
// strings count as present correlation/authentication inputs. Decoy
// authentication/correlation/source_checks keys are never read.
// ---------------------------------------------------------------------------

func stringField(obj map[string]any, key string) (string, bool) {
	if obj == nil {
		return "", false
	}
	v, ok := obj[key]
	if !ok || v == nil {
		return "", false
	}
	switch t := v.(type) {
	case string:
		if strings.TrimSpace(t) == "" {
			return "", false
		}
		return t, true
	case map[string]any:
		// Typed Missing envelope: explicitly absent, never a value.
		if raw, has := t["value"]; has && raw == nil {
			if reason, _ := t["reason"].(string); reason != "" {
				return "", false
			}
		}
		return "", false
	default:
		return "", false
	}
}

func validateVersionPin(pin VersionPin) error {
	if strings.TrimSpace(pin.ID) == "" {
		return fmt.Errorf("source_verifier: verification_policy id is required")
	}
	if strings.TrimSpace(pin.Version) == "" {
		return fmt.Errorf("source_verifier: verification_policy version is required")
	}
	if !validDigest(pin.ArtifactDigest) {
		return fmt.Errorf("source_verifier: verification_policy artifact_digest %q is not a valid digest", pin.ArtifactDigest)
	}
	return nil
}

func validDigest(s string) bool {
	const prefix = "sha256:"
	if !strings.HasPrefix(s, prefix) {
		return false
	}
	hexPart := s[len(prefix):]
	if len(hexPart) != 64 {
		return false
	}
	for i := range hexPart {
		c := hexPart[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func validJSONPointer(s string) bool {
	if s == "" {
		return true
	}
	if !strings.HasPrefix(s, "/") {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] == '~' {
			i++
			if i >= len(s) || (s[i] != '0' && s[i] != '1') {
				return false
			}
		}
	}
	return true
}

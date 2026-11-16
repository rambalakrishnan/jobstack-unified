// Package evidence_import implements tier-5 Hellscape source-evidence import.
//
// It enforces seam-mappings/hellscape-seam-mapping.md sections 4.5 (owner-local
// journals), 4.6 (imported evidence), 13.3 (historical observations), 16.2
// (evidence and timing corpus) plus invariants EK-JOURNAL, EK-PROVENANCE,
// EK-HASHES, EK-ARTIFACTS, LIFE-EVIDENCE and OWD-TIME-PROVENANCE:
//
//   - A registered source-event import contains the complete original
//     JournalEnvelope, an artifact reference to its exact canonical bytes, the
//     source manifest artifact, the source prefix, source
//     authentication/correlation checks, and the import-policy pin.
//   - Imported evidence is registered locally with its original scope and
//     trust, never promoted by the act of import. Historical imports stay
//     historical-unscored; synthetic backends stay synthetic.
//   - Source sequences are never copied into the local journal sequence field:
//     local sequences are assigned by the owner-local ingestion authority.
//   - Identical imports deduplicate via the owner-local idempotency receipt
//     without new effects. Conflicting bytes under the same source identity
//     surface as an integrity conflict, never last-write-wins.
//   - Diagnostics cite the local import and preserve the original source
//     authority. Import never turns a manual note, connector claim, or
//     historical event into an origin fact.
//
// The outer import record preserves the original envelope authority
// (role, assertion kind, provenance, owner domain, producer, scope, kind) in
// its payload data while the owner-local ingestion authority assigns the
// local envelope authority. References are registered only after the complete
// source manifest, bytes, verification evidence, and dependency closure are
// durably available.
package evidence_import

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	evidence_codec "evidence_codec"
	journal_rules "journal_rules"
	owner_store "owner_store"
	source_verifier "source_verifier"
)

// ---------------------------------------------------------------------------
// Evidence-kernel aliases: shared wire shapes so CONSUMES calls need no
// translation.
// ---------------------------------------------------------------------------

// OwnerStore is one owner-local durable boundary.
type OwnerStore = owner_store.OwnerStore

// EventSubmission is the ingress shape for owner-local commits.
type EventSubmission = owner_store.EventSubmission

// Manifest is the admitted journal manifest.
type Manifest = journal_rules.Manifest

// JournalEnvelope is the complete stored journal event envelope.
type JournalEnvelope = journal_rules.JournalEnvelope

// JournalPrefix is an immutable journal prefix.
type JournalPrefix = journal_rules.JournalPrefix

// EvidenceRef cites one retained journal event coordinate plus a JSON pointer.
type EvidenceRef = journal_rules.EvidenceRef

// ArtifactReference is an immutable byte identity plus resolver metadata.
type ArtifactReference = journal_rules.ArtifactReference

// VersionPin pins an immutable versioned artifact.
type VersionPin = source_verifier.VersionPin

// SourceChecks retains authentication and correlation verification.
type SourceChecks = source_verifier.SourceChecks

// Compile-time CONSUMES linkage: fail compilation if a declared upstream
// signature disappears.
var (
	_ = owner_store.InstallArtifact
	_ = owner_store.CommitOwner
	_ = source_verifier.VerifySource
	_ = journal_rules.ValidateJournal
	_ = evidence_codec.CanonicalJSON
)

// importEventKind is the local event kind for registered source imports. It
// is never an application effect kind: the payload preserves the original
// source kind and authority instead of relabeling the import.
const importEventKind = "source_imported"

// importEventSchema is the event document version for import records.
const importEventSchema = "0.1.0"

// importMediaType is the canonical media type for installed import bytes.
const importMediaType = "application/json"

// importAccess classifies installed import bytes. Imports are citable
// evidence registered for local diagnostics.
const importAccess = "public"

// ImportSourcePrefix registers one verified source journal prefix in the
// local owner store and returns one local EvidenceRef per source event.
//
//   - sourceManifest and source must form a valid journal whose verified
//     prefix exactly equals sourcePrefix (journal, last sequence, head hash).
//     A mismatch is rejected before anything is registered.
//   - The source manifest canonical bytes, every source envelope canonical
//     bytes, and every source-checks record are installed via InstallArtifact
//     before any reference is acknowledged.
//   - Every source envelope is verified via VerifySource against the pinned
//     import policy. Verification evidence is retained even when
//     authentication or correlation is unknown: absence of proof is not
//     promotion.
//   - Imports commit into the deterministic local journal
//     "import-<source journal>" with a distinct local manifest. Local
//     sequences are assigned by the owner-local ingestion authority; source
//     sequences are preserved in payload data, never copied into the local
//     sequence field.
//   - Each import payload preserves the complete original authority: source
//     journal, sequence, event ID, hash, kind, role, assertion kind,
//     provenance, scope, owner domain, producer, run, prefix, checks, and
//     policy pin. Every nested artifact appears in payload artifact_refs.
//   - A byte-identical re-import returns the original refs without new
//     effects via the owner-local commit receipt. Conflicting bytes under the
//     same source identity (same source sequence, same local journal) fail
//     with an integrity conflict wrapping owner_store.ErrIntegrityConflict.
func ImportSourcePrefix(ctx context.Context, store *OwnerStore, sourceManifest Manifest, sourcePrefix JournalPrefix, source []JournalEnvelope, policy VersionPin) ([]EvidenceRef, error) {
	if store == nil {
		return nil, fmt.Errorf("evidence_import: store is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(source) == 0 {
		return nil, fmt.Errorf("evidence_import: source prefix is empty: nothing to import")
	}
	if err := validateVersionPin(policy); err != nil {
		return nil, err
	}
	if strings.TrimSpace(sourcePrefix.JournalID) == "" {
		return nil, fmt.Errorf("evidence_import: source prefix journal_id is required")
	}
	if sourcePrefix.LastSequence < 1 {
		return nil, fmt.Errorf("evidence_import: source prefix last_sequence starts at 1")
	}
	if !validDigest(sourcePrefix.HeadHash) {
		return nil, fmt.Errorf("evidence_import: source prefix head_hash %q is not a valid digest", sourcePrefix.HeadHash)
	}

	// Source manifest and chain verification comes first: nothing is
	// registered until the source journal validates and pins the claimed
	// prefix.
	verified, err := journal_rules.ValidateJournal(sourceManifest, source)
	if err != nil {
		return nil, fmt.Errorf("evidence_import: source journal validation: %w", err)
	}
	if verified.JournalID != sourcePrefix.JournalID ||
		verified.LastSequence != sourcePrefix.LastSequence ||
		verified.HeadHash != sourcePrefix.HeadHash {
		return nil, fmt.Errorf("evidence_import: source prefix %+v does not match verified %+v: all coordinates must agree",
			sourcePrefix, verified)
	}
	if int64(len(source)) != sourcePrefix.LastSequence {
		return nil, fmt.Errorf("evidence_import: source carries %d events, prefix ends at %d",
			len(source), sourcePrefix.LastSequence)
	}

	// Install the source manifest canonical bytes before any reference.
	manifestRaw, err := json.Marshal(sourceManifest)
	if err != nil {
		return nil, fmt.Errorf("evidence_import: marshal source manifest: %v", err)
	}
	manifestCanonical, err := evidence_codec.CanonicalJSON(manifestRaw, importMediaType)
	if err != nil {
		return nil, fmt.Errorf("evidence_import: canonicalize source manifest: %v", err)
	}
	sourceManifestRef, err := owner_store.InstallArtifact(ctx, store, bytes.NewReader(manifestCanonical), importMediaType, importAccess)
	if err != nil {
		return nil, fmt.Errorf("evidence_import: install source manifest: %w", err)
	}
	storeOwner := strings.TrimSpace(sourceManifestRef.OwnerDomain)
	if storeOwner == "" {
		return nil, fmt.Errorf("evidence_import: installed source manifest names no owner domain")
	}

	// Install every source envelope's exact canonical bytes.
	envelopeRefs := make([]ArtifactReference, len(source))
	for i := range source {
		envRaw, err := json.Marshal(source[i])
		if err != nil {
			return nil, fmt.Errorf("evidence_import: marshal source event %d: %v", source[i].Sequence, err)
		}
		envCanonical, err := evidence_codec.CanonicalJSON(envRaw, importMediaType)
		if err != nil {
			return nil, fmt.Errorf("evidence_import: canonicalize source event %d: %v", source[i].Sequence, err)
		}
		ref, err := owner_store.InstallArtifact(ctx, store, bytes.NewReader(envCanonical), importMediaType, importAccess)
		if err != nil {
			return nil, fmt.Errorf("evidence_import: install source event %d bytes: %w", source[i].Sequence, err)
		}
		envelopeRefs[i] = ref
	}

	// Verify each retained source body against the pinned import policy.
	// Correlation evidence is intentionally empty: source envelopes are
	// journal records, not native callback bodies, so correlation stays
	// unknown rather than inventing an attempt match. Unknown checks are
	// retained as verification evidence, never promoted.
	checksList := make([]SourceChecks, len(source))
	checksRefs := make([]ArtifactReference, len(source))
	for i := range envelopeRefs {
		checks, err := source_verifier.VerifySource(ctx, store, envelopeRefs[i], policy, nil)
		if err != nil {
			return nil, fmt.Errorf("evidence_import: verify source event %d: %w", source[i].Sequence, err)
		}
		checksList[i] = checks
		checksRaw, err := json.Marshal(checks)
		if err != nil {
			return nil, fmt.Errorf("evidence_import: marshal source checks %d: %v", source[i].Sequence, err)
		}
		checksCanonical, err := evidence_codec.CanonicalJSON(checksRaw, importMediaType)
		if err != nil {
			return nil, fmt.Errorf("evidence_import: canonicalize source checks %d: %v", source[i].Sequence, err)
		}
		ref, err := owner_store.InstallArtifact(ctx, store, bytes.NewReader(checksCanonical), importMediaType, importAccess)
		if err != nil {
			return nil, fmt.Errorf("evidence_import: install source checks %d: %w", source[i].Sequence, err)
		}
		checksRefs[i] = ref
	}

	// Admit the deterministic local import journal. It pins a distinct
	// complete manifest: same run and clocks as the source, but its own
	// journal ID and the local owner domain.
	localJournalID := "import-" + sourcePrefix.JournalID
	clocks := append([]journal_rules.ClockDescriptor(nil), sourceManifest.Clocks...)
	if len(clocks) == 0 {
		clocks = []journal_rules.ClockDescriptor{{
			ClockID: "clock-import", BootID: "boot-import",
			Origin: "engine_measured", SourceID: "evidence-import",
			Basis: "monotonic_offset", Unit: "ms",
		}}
	}
	localManifest := Manifest{
		RecordType:    "manifest",
		SchemaVersion: "0.1.0",
		ManifestID:    "manifest-" + localJournalID,
		RunID:         sourceManifest.RunID,
		JournalID:     localJournalID,
		OwnerDomain:   storeOwner,
		Clocks:        clocks,
	}
	localRaw, err := json.Marshal(localManifest)
	if err != nil {
		return nil, fmt.Errorf("evidence_import: marshal local manifest: %v", err)
	}
	localCanonical, err := evidence_codec.CanonicalJSON(localRaw, importMediaType)
	if err != nil {
		return nil, fmt.Errorf("evidence_import: canonicalize local manifest: %v", err)
	}
	localRef, err := owner_store.InstallArtifact(ctx, store, bytes.NewReader(localCanonical), importMediaType, importAccess)
	if err != nil {
		return nil, fmt.Errorf("evidence_import: install local manifest: %w", err)
	}
	admission := EventSubmission{
		ProducerSequence:   int64(1),
		EventKind:          "manifest_admitted",
		EventSchemaVersion: importEventSchema,
		OccurredAt: journal_rules.TimePoint{
			ClockID: clocks[0].ClockID, BootID: clocks[0].BootID, Origin: clocks[0].Origin,
			MonotonicOffsetMs: 0, UTCAnnotation: journal_rules.NewMissing("not_applicable"),
		},
		Payload: journal_rules.Payload{
			Data:         map[string]any{"manifest": artifactRefMap(localRef)},
			Measurements: []journal_rules.Measurement{},
			EvidenceRefs: []EvidenceRef{},
			ArtifactRefs: []ArtifactReference{localRef},
		},
	}
	if _, err := owner_store.CommitOwner(ctx, store, localJournalID, []EventSubmission{admission}, nil); err != nil {
		// A byte-identical admission replays without error. A journal that
		// already holds imports rejects any new manifest_admitted: that is
		// the expected already-admitted signal, not a failure.
		if !strings.Contains(err.Error(), "manifest_admitted appears only at sequence 1") {
			return nil, fmt.Errorf("evidence_import: admit local journal: %w", err)
		}
	}

	// One deterministic import submission per source event. The producer
	// sequence derives from the source sequence (offset past admission) so
	// a byte-identical re-import replays the commit receipt while
	// conflicting bytes under the same identity collide on the committed
	// producer sequence and raise an integrity conflict.
	submissions := make([]EventSubmission, len(source))
	for i := range source {
		src := &source[i]
		matchedBy := make([]any, 0, len(checksList[i].MatchedBy))
		for _, name := range checksList[i].MatchedBy {
			matchedBy = append(matchedBy, name)
		}
		data := map[string]any{
			"source_envelope":          artifactRefMap(envelopeRefs[i]),
			"source_manifest":          artifactRefMap(sourceManifestRef),
			"source_checks":            artifactRefMap(checksRefs[i]),
			"source_journal_id":        src.JournalID,
			"source_sequence":          src.Sequence,
			"source_event_id":          src.EventID,
			"source_event_hash":        src.EventHash,
			"source_event_kind":        src.EventKind,
			"original_role":            src.Role,
			"original_assertion_kind":  src.AssertionKind,
			"original_provenance":      src.Provenance,
			"original_evidence_scope":  src.EvidenceScope,
			"original_owner_domain":    src.OwnerDomain,
			"original_producer_id":     src.ProducerID,
			"source_prefix_last_sequence": int64(sourcePrefix.LastSequence),
			"source_prefix_head_hash":     sourcePrefix.HeadHash,
			"source_run_id":               sourceManifest.RunID,
			"import_policy_id":            policy.ID,
			"import_policy_version":       policy.Version,
			"import_policy_digest":        policy.ArtifactDigest,
			"source_authentication":       checksList[i].Authentication,
			"source_correlation":          checksList[i].Correlation,
			"source_trace_correlation":    checksList[i].TraceCorrelation,
			"source_matched_by":           matchedBy,
		}
		refs := []ArtifactReference{envelopeRefs[i], sourceManifestRef, checksRefs[i]}
		sort.Slice(refs, func(a, b int) bool { return refs[a].Digest < refs[b].Digest })
		submissions[i] = EventSubmission{
			ProducerSequence:   src.Sequence + 1,
			EventKind:          importEventKind,
			EventSchemaVersion: importEventSchema,
			OccurredAt:         journal_rules.NewMissing("not_observed"),
			Payload: journal_rules.Payload{
				Data:         data,
				Measurements: []journal_rules.Measurement{},
				EvidenceRefs: []EvidenceRef{},
				ArtifactRefs: refs,
			},
		}
	}
	envelopes, err := owner_store.CommitOwner(ctx, store, localJournalID, submissions, nil)
	if err != nil {
		return nil, fmt.Errorf("evidence_import: commit imports: %w", err)
	}
	if len(envelopes) != len(source) {
		return nil, fmt.Errorf("evidence_import: commit returned %d envelopes, want %d", len(envelopes), len(source))
	}
	// Local sequences are authority-assigned: they must never equal a
	// copied source sequence for the same position. The local journal
	// carries its own admission at sequence 1, so every import sits past
	// it while the source prefix starts at 1.
	for i := range envelopes {
		if envelopes[i].JournalID != localJournalID {
			return nil, fmt.Errorf("evidence_import: import %d cites journal %q, local journal is %q",
				i, envelopes[i].JournalID, localJournalID)
		}
		if envelopes[i].EventKind == source[i].EventKind && envelopes[i].EventKind != importEventKind {
			return nil, fmt.Errorf("evidence_import: import %d relabels source kind %q as a local effect",
				i, source[i].EventKind)
		}
	}

	refs := make([]EvidenceRef, len(envelopes))
	for i := range envelopes {
		refs[i] = EvidenceRef{
			JournalID: envelopes[i].JournalID,
			Sequence:  envelopes[i].Sequence,
			EventID:   envelopes[i].EventID,
			EventHash: envelopes[i].EventHash,
			Pointer:   "",
		}
	}
	return refs, nil
}

// artifactRefMap renders one artifact reference as retained payload data.
// The shape is recognized as a nested artifact identity, so callers must
// list the same digest in payload artifact_refs.
func artifactRefMap(ref ArtifactReference) map[string]any {
	return map[string]any{
		"digest":       ref.Digest,
		"size_bytes":   ref.SizeBytes,
		"media_type":   ref.MediaType,
		"owner_domain": ref.OwnerDomain,
		"access":       ref.Access,
	}
}

// validateVersionPin rejects an empty or malformed import-policy pin before
// any verification or registration.
func validateVersionPin(pin VersionPin) error {
	if strings.TrimSpace(pin.ID) == "" {
		return fmt.Errorf("evidence_import: import-policy pin id is required")
	}
	if strings.TrimSpace(pin.Version) == "" {
		return fmt.Errorf("evidence_import: import-policy pin version is required")
	}
	if !validDigest(pin.ArtifactDigest) {
		return fmt.Errorf("evidence_import: import-policy pin digest %q is not a valid digest", pin.ArtifactDigest)
	}
	return nil
}

// validDigest reports whether s matches the shared digest form.
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

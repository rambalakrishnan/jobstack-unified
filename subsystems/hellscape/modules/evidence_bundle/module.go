// Package evidence_bundle implements tier-7 Hellscape replay-input and
// validation-bundle export.
//
// It enforces seam-mappings/hellscape-seam-mapping.md sections 11.3 (hash
// reconciliation), 11.4 (export bundle), 11.5 (archive representation) and
// 11.6 (retention) plus invariants EK-ARTIFACTS, EK-HASHES, EK-REPLAY,
// OWD-ARCHIVE, OWD-RETENTION and LIFE-EVIDENCE:
//
//   - An export bundle retains the M1 human-readable layout (manifest,
//     journal, diagnostic, authoritative state, receipt, checks) and
//     additionally embeds every transitive contract-required dependency:
//     owner manifests, journal prefixes, configuration, commission,
//     registrations, owner publications, classifier/reducer/registry
//     artifacts, import-verification evidence, and the artifact inventory.
//   - Friendly filenames are bundle entries, never artifact identity. The
//     bundle manifest binds each name to an exact digest, size, media type,
//     owner, and access classification, and every blob is verified by hash.
//   - A replay-input bundle never contains the replay receipt that hashes
//     it. The receipt lives only in the separate validation bundle.
//   - A restricted dependency keeps the archive root and the exported
//     bundle restricted. Access is never downgraded.
//   - Redaction creates a new artifact. A redacted bundle cannot claim
//     unavailable exact replay inputs: loading it as exact inputs fails
//     with the known missing identities instead of succeeding.
//   - Lost artifact bytes are known loss, not successful collection: an
//     export that requires them fails while preserving every known digest.
//
// The durable truth of a bundle is the installed, content-addressed bundle
// artifact plus the retained dependency closure pinned by RetainRoot. The
// bundle embeds exact bytes for every dependency so verification never
// substitutes a hash, locator, mutable-peer query, or current revision for
// promised archived content.
package evidence_bundle

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	evidence_codec "evidence_codec"
	journal_rules "journal_rules"
	owner_store "owner_store"
	publication "publication"
)

// ---------------------------------------------------------------------------
// Evidence-kernel aliases: shared wire shapes so CONSUMES calls need no
// translation.
// ---------------------------------------------------------------------------

type (
	// OwnerStore is one owner-local durable boundary.
	OwnerStore = owner_store.OwnerStore
	// Manifest is the admitted journal manifest.
	Manifest = journal_rules.Manifest
	// JournalEnvelope is the complete stored journal event envelope.
	JournalEnvelope = journal_rules.JournalEnvelope
	// JournalPrefix is an immutable journal prefix.
	JournalPrefix = journal_rules.JournalPrefix
	// EvidenceRef cites one retained journal event coordinate plus a pointer.
	EvidenceRef = journal_rules.EvidenceRef
	// ArtifactReference is an immutable byte identity plus resolver metadata.
	ArtifactReference = journal_rules.ArtifactReference
	// MissingEnvelope is the typed EK Missing value.
	MissingEnvelope = journal_rules.MissingEnvelope
	// TimePoint is a coordinate in a registered monotonic clock.
	TimePoint = journal_rules.TimePoint
	// ClockDescriptor registers one clock lifetime.
	ClockDescriptor = journal_rules.ClockDescriptor
	// Measurement is the EK Measurement record carried in payloads.
	Measurement = journal_rules.Measurement
	// Digest is the shared content digest ("sha256:" + 64 lowercase hex).
	Digest = evidence_codec.Digest
	// LogicalRow is the complete derived read value for one entity.
	LogicalRow = publication.LogicalRow
	// ArchiveStorageManifest is the physical archive root representation.
	ArchiveStorageManifest = publication.ArchiveStorageManifest
	// ArchiveRecord is the complete expanded logical archive.
	ArchiveRecord = publication.ArchiveRecord
	// EntityRegistration is the immutable registration of one entity.
	EntityRegistration = publication.EntityRegistration
	// DomainSlot is one LogicalRow domain slot.
	DomainSlot = publication.DomainSlot
	// SealPoint pins the state named by one seal.
	SealPoint = publication.SealPoint
)

// Compile-time CONSUMES linkage: fail compilation if a declared upstream
// signature disappears.
var (
	_ = owner_store.LoadPrefix
	_ = owner_store.InstallArtifact
	_ = owner_store.ReadArtifact
	_ = owner_store.RetainRoot
	_ = publication.ExpandArchive
	_ = journal_rules.ValidateJournal
	_ = evidence_codec.CanonicalJSON
	_ = evidence_codec.HashBytes
)

// ---------------------------------------------------------------------------
// Constants and sentinel errors.
// ---------------------------------------------------------------------------

const (
	// Bundle record types.
	bundleInputsRecordType     = "replay_input_bundle"
	bundleValidationRecordType = "validation_bundle"
	bundleSchemaVersion        = "1.0.0"

	// Diagnostic record identity.
	diagnosticRecordType  = "diagnostic"
	diagnosticSchema      = "1.0.0"
	manifestRecordType    = "manifest"
	manifestSchemaVersion = "0.1.0"

	// Replay receipt identity.
	receiptRecordType  = "replay_receipt"
	receiptSchema      = "1.0.0"
	modeExactFixture   = "exact_fixture"
	modeDiagnosticOnly = "diagnostic_only"

	// Replay availability claims.
	availabilityExact       = "exact"
	availabilityUnavailable = "unavailable"

	// Comparison outputs and results (seam 11.2).
	comparisonSemanticEvents = "semantic_events"
	comparisonFinalState     = "final_state"
	comparisonDiagnostic     = "diagnostic"

	resultMatched     = "matched"
	resultMismatched  = "mismatched"
	resultUnavailable = "unavailable"

	// M1 friendly entry names (seam 11.4).
	entryManifest        = "manifest.json"
	entryJournal         = "journal.jsonl"
	entryDiagnostic      = "diagnostic.json"
	entryDiagnosticMD    = "diagnostic.md"
	entryAuthoritative   = "authoritative-state.json"
	entryReplayReceipt   = "replay-receipt.json"
	entryAcceptance      = "acceptance-checks.json"
	entryRegistration    = "registration.json"
	entryInventory       = "artifact-inventory.json"
	entryTask            = "task.json"
	entryBuildReceipt    = "build-receipt.json"
	entryTiming          = "timing-measurements.json"
	entryManualObs       = "manual-observations.json"
	entrySyntheticDoc    = "artifacts/synthetic-document"
	entriesDirPrefix     = "artifacts/"
	domainsDirPrefix     = "domains/"

	mediaTypeJSON     = "application/json"
	mediaTypeMarkdown = "text/markdown"
	mediaTypeOctet    = "application/octet-stream"

	accessPublic     = "public"
	accessRestricted = "restricted"
)

var (
	// ErrInvalid marks malformed bundle inputs.
	ErrInvalid = errors.New("evidence_bundle: invalid input")
	// ErrIntegrityConflict marks digest, size, or identity mismatches.
	ErrIntegrityConflict = errors.New("evidence_bundle: integrity conflict")
	// ErrUnavailable marks a bundle that cannot claim exact replay inputs:
	// a required dependency is missing, redacted, or otherwise
	// unavailable. The error message always preserves the known digest.
	ErrUnavailable = errors.New("evidence_bundle: exact replay inputs unavailable")
)

// ---------------------------------------------------------------------------
// Public wire types.
// ---------------------------------------------------------------------------

// VersionPin pins an immutable versioned artifact.
type VersionPin struct {
	ID             string `json:"id"`
	Version        string `json:"version"`
	ArtifactDigest string `json:"artifact_digest"`
}

// DiagnosticDocument is the deterministic analysis output consumed and
// produced by bundles. Union fields (pin-or-Missing) use any: callers set
// either a VersionPin or a MissingEnvelope, never a bare null. Artifacts
// carries the full content-addressed identities for the pinned classifier,
// registries, and any additional diagnostic dependencies (import
// verification evidence, measurement support, capability descriptors).
// Extra carries optional additional diagnostic sections; any embedded
// artifact-reference-shaped object inside Extra is collected as a
// transitive dependency.
type DiagnosticDocument struct {
	RecordType          string              `json:"record_type"`
	SchemaVersion       string              `json:"schema_version"`
	DiagnosticID        string              `json:"diagnostic_id"`
	AnalysisRevision    int64               `json:"analysis_revision"`
	RunID               string              `json:"run_id"`
	ManifestHash        string              `json:"manifest_hash"`
	InputPrefix         JournalPrefix       `json:"input_prefix"`
	AnalysisRequestRef  EvidenceRef         `json:"analysis_request_ref"`
	Classifier          VersionPin          `json:"classifier"`
	RequirementRegistry VersionPin          `json:"requirement_registry"`
	FixRegistry         any                 `json:"fix_registry"`
	EvidenceRefs        []EvidenceRef       `json:"evidence_refs,omitempty"`
	Artifacts           []ArtifactReference `json:"artifacts,omitempty"`
	Extra               map[string]any      `json:"extra,omitempty"`
}

// ReplayComparison is one required replay comparison (seam 11.2): the
// output name, the expected digest, the actual digest (a digest string or
// a Missing envelope), and the matched/mismatched/unavailable result.
type ReplayComparison struct {
	Output         string `json:"output"`
	ExpectedDigest string `json:"expected_digest"`
	ActualDigest   any    `json:"actual_digest"`
	Result         string `json:"result"`
}

// ReplayReceipt is the separate immutable replay record (seam 11.2). It is
// never embedded in the input bundle it hashes; it lives only in the
// validation bundle. Reducer is a VersionPin for exact_fixture mode and a
// Missing(not_applicable) envelope for diagnostic_only mode.
type ReplayReceipt struct {
	RecordType            string             `json:"record_type"`
	SchemaVersion         string             `json:"schema_version"`
	ReplayID              string             `json:"replay_id"`
	Mode                  string             `json:"mode"`
	RunID                 string             `json:"run_id"`
	ManifestHash          string             `json:"manifest_hash"`
	SourcePrefix          JournalPrefix      `json:"source_prefix"`
	SourceDiagnostic      ArtifactReference  `json:"source_diagnostic"`
	InputBundle           ArtifactReference  `json:"input_bundle"`
	Classifier            VersionPin         `json:"classifier"`
	Reducer               any                `json:"reducer"`
	ReplayEngine          VersionPin         `json:"replay_engine"`
	Comparisons           []ReplayComparison `json:"comparisons"`
	Result                string             `json:"result"`
	Limitations           []string           `json:"limitations"`
	InvokedBrowser        bool               `json:"invoked_browser"`
	InvokedSubject        bool               `json:"invoked_subject"`
	PerformedExternalWrites bool             `json:"performed_external_writes"`
}

// BundleEntry binds one friendly bundle name to one exact artifact
// identity. Names are entries, never identity: every load re-verifies the
// digest, size, and bytes.
type BundleEntry struct {
	Name        string `json:"name"`
	Digest      string `json:"digest"`
	SizeBytes   int64  `json:"size_bytes"`
	MediaType   string `json:"media_type"`
	OwnerDomain string `json:"owner_domain"`
	Access      string `json:"access"`
}

// BundleDocument is the installed bundle body. Entries binds friendly
// names to exact digests; Blobs maps each digest to the base64-encoded
// exact bytes. ReplayAvailability is "exact" only when every transitive
// replay dependency is embedded; a redacted bundle carries "unavailable"
// and the redacted digests and can never load as exact inputs.
type BundleDocument struct {
	RecordType         string                 `json:"record_type"`
	SchemaVersion      string                 `json:"schema_version"`
	Manifest           Manifest               `json:"manifest"`
	Events             []JournalEnvelope      `json:"events"`
	Diagnostic         DiagnosticDocument     `json:"diagnostic"`
	Row                LogicalRow             `json:"row"`
	ArchiveManifest    ArchiveStorageManifest `json:"archive_manifest"`
	Receipt            *ReplayReceipt         `json:"receipt,omitempty"`
	Checks             *ArtifactReference     `json:"checks,omitempty"`
	Entries            []BundleEntry          `json:"entries"`
	Blobs              map[string]string      `json:"blobs"`
	ReplayAvailability string                 `json:"replay_availability"`
	Redacted           []string               `json:"redacted,omitempty"`
}

// ---------------------------------------------------------------------------
// Export: replay inputs.
// ---------------------------------------------------------------------------

// ExportReplayInputs builds the self-contained exact-replay input bundle
// for one diagnostic prefix and one sealed row, installs it, pins its
// transitive closure, and returns its artifact reference.
//
// The bundle embeds the manifest, the complete prefix events, the
// diagnostic, the row, the derived archive storage manifest, and the exact
// bytes of every transitive dependency: the manifest artifact, every
// event artifact (including nested data identities), the registration and
// every published domain document, the classifier/registry/fix pins, and
// any additional diagnostic artifacts. Friendly M1 names (manifest.json,
// journal.jsonl, diagnostic.json, authoritative-state.json, and per-artifact
// entries) bind to exact digests; they are never treated as identity.
//
// The input bundle never contains a replay receipt: the receipt that
// hashes this bundle is published separately in the validation bundle.
//
// A restricted dependency keeps the exported bundle restricted. A lost or
// missing dependency fails the export while preserving the known digest
// in the returned error.
func ExportReplayInputs(ctx context.Context, store *OwnerStore, row LogicalRow, diagnostic DiagnosticDocument) (ArtifactReference, error) {
	empty := ArtifactReference{}
	if store == nil {
		return empty, fmt.Errorf("%w: store is required", ErrInvalid)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if err := validateDiagnosticShape(diagnostic); err != nil {
		return empty, err
	}
	events, err := owner_store.LoadPrefix(ctx, store, diagnostic.InputPrefix)
	if err != nil {
		return empty, fmt.Errorf("evidence_bundle: load diagnostic prefix %+v: %w", diagnostic.InputPrefix, err)
	}
	manifest, manifestRef, manifestBytes, err := recoverManifest(ctx, store, events)
	if err != nil {
		return empty, err
	}
	verified, err := journal_rules.ValidateJournal(manifest, events)
	if err != nil {
		return empty, fmt.Errorf("evidence_bundle: diagnostic journal is invalid: %w", err)
	}
	if verified.JournalID != diagnostic.InputPrefix.JournalID ||
		verified.LastSequence != diagnostic.InputPrefix.LastSequence ||
		verified.HeadHash != diagnostic.InputPrefix.HeadHash {
		return empty, fmt.Errorf("%w: diagnostic input prefix %+v does not match the verified prefix %+v",
			ErrIntegrityConflict, diagnostic.InputPrefix, verified)
	}
	manifestDigest, err := canonicalDigest(manifest)
	if err != nil {
		return empty, err
	}
	if diagnostic.ManifestHash != manifestDigest {
		return empty, fmt.Errorf("%w: diagnostic manifest_hash %q does not match the admitted manifest %q",
			ErrIntegrityConflict, diagnostic.ManifestHash, manifestDigest)
	}
	if diagnostic.RunID != manifest.RunID {
		return empty, fmt.Errorf("%w: diagnostic run %q does not match the manifest run %q",
			ErrIntegrityConflict, diagnostic.RunID, manifest.RunID)
	}
	if err := checkEvidenceRefResolves(events, diagnostic.AnalysisRequestRef, "diagnostic.analysis_request_ref"); err != nil {
		return empty, err
	}
	archiveManifest, expanded, registrationRef, registrationBytes, err := deriveAndVerifyArchive(ctx, store, row)
	if err != nil {
		return empty, err
	}
	collected, pinDigests, err := collectInputDependencies(diagnostic, events, manifestRef, registrationRef, row)
	if err != nil {
		return empty, err
	}
	blobs, entryRefs, bundleAccess, err := readDependencyBytes(ctx, store, collected, pinDigests)
	if err != nil {
		return empty, err
	}
	// The registration extent is a derived install, not a prior dependency:
	// record its exact bytes and identity alongside the collected closure.
	blobs[registrationRef.Digest] = append([]byte(nil), registrationBytes...)
	if _, ok := entryRefs[registrationRef.Digest]; !ok {
		entryRefs[registrationRef.Digest] = registrationRef
	}
	if registrationRef.Access == accessRestricted {
		bundleAccess = accessRestricted
	}
	doc, err := buildInputsBundle(manifest, manifestBytes, events, diagnostic, row, archiveManifest, expanded, blobs, entryRefs, bundleAccess)
	if err != nil {
		return empty, err
	}
	return installBundle(ctx, store, doc, entryRefs, events)
}

// ---------------------------------------------------------------------------
// Export: validation bundle.
// ---------------------------------------------------------------------------

// ExportValidationBundle builds the complete M1 validation bundle: the
// replay inputs plus the separate replay receipt, the acceptance checks,
// and the readable diagnostic report. It installs the bundle, pins its
// transitive closure, and returns its artifact reference.
//
// The receipt is validated against seam 11.2 (mode-required comparisons,
// aggregate result, three false invocation flags, classifier/reducer/engine
// pins, and source/input identities) before anything is installed. The
// input bundle named by the receipt must already exist as an installed
// replay-input bundle; this validation bundle never rewrites it.
//
// A restricted receipt, checks artifact, or transitive input keeps the
// validation bundle restricted. A lost or missing dependency fails the
// export while preserving the known digest.
func ExportValidationBundle(ctx context.Context, store *OwnerStore, row LogicalRow, diagnostic DiagnosticDocument, receipt ReplayReceipt, checks ArtifactReference) (ArtifactReference, error) {
	empty := ArtifactReference{}
	if store == nil {
		return empty, fmt.Errorf("%w: store is required", ErrInvalid)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if err := validateDiagnosticShape(diagnostic); err != nil {
		return empty, err
	}
	events, err := owner_store.LoadPrefix(ctx, store, diagnostic.InputPrefix)
	if err != nil {
		return empty, fmt.Errorf("evidence_bundle: load diagnostic prefix %+v: %w", diagnostic.InputPrefix, err)
	}
	manifest, manifestRef, manifestBytes, err := recoverManifest(ctx, store, events)
	if err != nil {
		return empty, err
	}
	verified, err := journal_rules.ValidateJournal(manifest, events)
	if err != nil {
		return empty, fmt.Errorf("evidence_bundle: diagnostic journal is invalid: %w", err)
	}
	if verified.JournalID != diagnostic.InputPrefix.JournalID ||
		verified.LastSequence != diagnostic.InputPrefix.LastSequence ||
		verified.HeadHash != diagnostic.InputPrefix.HeadHash {
		return empty, fmt.Errorf("%w: diagnostic input prefix %+v does not match the verified prefix %+v",
			ErrIntegrityConflict, diagnostic.InputPrefix, verified)
	}
	manifestDigest, err := canonicalDigest(manifest)
	if err != nil {
		return empty, err
	}
	if diagnostic.ManifestHash != manifestDigest {
		return empty, fmt.Errorf("%w: diagnostic manifest_hash %q does not match the admitted manifest %q",
			ErrIntegrityConflict, diagnostic.ManifestHash, manifestDigest)
	}
	if diagnostic.RunID != manifest.RunID {
		return empty, fmt.Errorf("%w: diagnostic run %q does not match the manifest run %q",
			ErrIntegrityConflict, diagnostic.RunID, manifest.RunID)
	}
	if err := checkEvidenceRefResolves(events, diagnostic.AnalysisRequestRef, "diagnostic.analysis_request_ref"); err != nil {
		return empty, err
	}
	archiveManifest, expanded, registrationRef, registrationBytes, err := deriveAndVerifyArchive(ctx, store, row)
	if err != nil {
		return empty, err
	}
	diagnosticBytes, err := canonicalJSONValue(diagnostic)
	if err != nil {
		return empty, err
	}
	if err := validateReceiptShape(receipt); err != nil {
		return empty, err
	}
	if err := validateReceiptAgainstInputs(ctx, store, receipt, diagnostic, diagnosticBytes, manifestDigest, events); err != nil {
		return empty, err
	}
	if !validDigest(checks.Digest) {
		return empty, fmt.Errorf("%w: checks artifact digest %q is invalid", ErrInvalid, checks.Digest)
	}
	checksBytes, err := owner_store.ReadArtifact(ctx, store, checks)
	if err != nil {
		return empty, fmt.Errorf("evidence_bundle: validation bundle requires acceptance checks %s: %w", checks.Digest, err)
	}
	if string(evidence_codec.HashBytes(checksBytes)) != checks.Digest {
		return empty, fmt.Errorf("%w: acceptance checks bytes do not match %q", ErrIntegrityConflict, checks.Digest)
	}
	collected, pinDigests, err := collectValidationDependencies(diagnostic, events, manifestRef, registrationRef, row, receipt, checks)
	if err != nil {
		return empty, err
	}
	blobs, entryRefs, bundleAccess, err := readDependencyBytes(ctx, store, collected, pinDigests)
	if err != nil {
		return empty, err
	}
	blobs[registrationRef.Digest] = append([]byte(nil), registrationBytes...)
	if _, ok := entryRefs[registrationRef.Digest]; !ok {
		entryRefs[registrationRef.Digest] = registrationRef
	}
	if registrationRef.Access == accessRestricted {
		bundleAccess = accessRestricted
	}
	blobs[checks.Digest] = append([]byte(nil), checksBytes...)
	if _, ok := entryRefs[checks.Digest]; !ok {
		entryRefs[checks.Digest] = checks
	}
	if checks.Access == accessRestricted {
		bundleAccess = accessRestricted
	}
	doc, err := buildValidationBundle(manifest, manifestBytes, events, diagnostic, row, archiveManifest, expanded, receipt, checks, blobs, entryRefs, bundleAccess)
	if err != nil {
		return empty, err
	}
	return installBundle(ctx, store, doc, entryRefs, events)
}

// ---------------------------------------------------------------------------
// Load: replay inputs.
// ---------------------------------------------------------------------------

// LoadReplayInputs resolves one installed bundle to its exact replay
// inputs: the admitted manifest, the complete prefix events, and the
// diagnostic. It accepts both replay-input bundles and validation bundles
// (a validation bundle carries the same inputs plus the separate receipt).
//
// Every friendly name is resolved through its bound digest and verified
// against the exact embedded bytes: hash, size, and derived-document
// equality (manifest, journal, diagnostic, authoritative state, receipt)
// must all agree. Filenames are never trusted as identity.
//
// A bundle that is redacted, tampered, or otherwise unable to supply an
// exact input fails with ErrUnavailable (or an integrity error) that
// preserves the known digest. It never succeeds while claiming exact
// inputs it cannot produce.
func LoadReplayInputs(ctx context.Context, store *OwnerStore, bundle ArtifactReference) (Manifest, []JournalEnvelope, DiagnosticDocument, error) {
	emptyManifest := Manifest{}
	emptyDiagnostic := DiagnosticDocument{}
	if store == nil {
		return emptyManifest, nil, emptyDiagnostic, fmt.Errorf("%w: store is required", ErrInvalid)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return emptyManifest, nil, emptyDiagnostic, err
	}
	if !validDigest(bundle.Digest) {
		return emptyManifest, nil, emptyDiagnostic, fmt.Errorf("%w: bundle digest %q is invalid", ErrInvalid, bundle.Digest)
	}
	raw, err := owner_store.ReadArtifact(ctx, store, bundle)
	if err != nil {
		return emptyManifest, nil, emptyDiagnostic, fmt.Errorf("evidence_bundle: load bundle %s: %w", bundle.Digest, err)
	}
	if string(evidence_codec.HashBytes(raw)) != bundle.Digest {
		return emptyManifest, nil, emptyDiagnostic, fmt.Errorf("%w: bundle bytes do not match %q", ErrIntegrityConflict, bundle.Digest)
	}
	var doc BundleDocument
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&doc); err != nil {
		return emptyManifest, nil, emptyDiagnostic, fmt.Errorf("%w: bundle %s is not a BundleDocument: %v", ErrInvalid, bundle.Digest, err)
	}
	if doc.RecordType != bundleInputsRecordType && doc.RecordType != bundleValidationRecordType {
		return emptyManifest, nil, emptyDiagnostic, fmt.Errorf("%w: bundle %s record_type %q is not a replay bundle",
			ErrInvalid, bundle.Digest, doc.RecordType)
	}
	if doc.SchemaVersion != bundleSchemaVersion {
		return emptyManifest, nil, emptyDiagnostic, fmt.Errorf("%w: bundle %s schema_version %q is not %q",
			ErrInvalid, bundle.Digest, doc.SchemaVersion, bundleSchemaVersion)
	}
	if doc.RecordType == bundleInputsRecordType && doc.Receipt != nil {
		return emptyManifest, nil, emptyDiagnostic, fmt.Errorf("%w: replay-input bundle %s embeds a receipt it must exclude",
			ErrIntegrityConflict, bundle.Digest)
	}
	if doc.ReplayAvailability != availabilityExact {
		return emptyManifest, nil, emptyDiagnostic, fmt.Errorf("%w: bundle %s availability is %q (redacted %v): it cannot supply exact replay inputs",
			ErrUnavailable, bundle.Digest, doc.ReplayAvailability, doc.Redacted)
	}
	if len(doc.Redacted) != 0 {
		return emptyManifest, nil, emptyDiagnostic, fmt.Errorf("%w: bundle %s redacts %v: it cannot supply exact replay inputs",
			ErrUnavailable, bundle.Digest, doc.Redacted)
	}
	decoded, err := verifyBundleEntries(doc, bundle.Digest)
	if err != nil {
		return emptyManifest, nil, emptyDiagnostic, err
	}
	if err := verifyDerivedDocuments(doc, decoded, bundle.Digest); err != nil {
		return emptyManifest, nil, emptyDiagnostic, err
	}
	if err := verifyBundleCompleteness(doc, bundle.Digest); err != nil {
		return emptyManifest, nil, emptyDiagnostic, err
	}
	if bundle.Access == accessPublic {
		for _, entry := range doc.Entries {
			if entry.Access == accessRestricted {
				return emptyManifest, nil, emptyDiagnostic, fmt.Errorf(
					"%w: bundle %s is public but entry %q (%s) is restricted: access cannot be downgraded",
					ErrIntegrityConflict, bundle.Digest, entry.Name, entry.Digest)
			}
		}
	}
	verified, err := journal_rules.ValidateJournal(doc.Manifest, doc.Events)
	if err != nil {
		return emptyManifest, nil, emptyDiagnostic, fmt.Errorf("evidence_bundle: bundle %s journal is invalid: %w", bundle.Digest, err)
	}
	if verified.JournalID != doc.Diagnostic.InputPrefix.JournalID ||
		verified.LastSequence != doc.Diagnostic.InputPrefix.LastSequence ||
		verified.HeadHash != doc.Diagnostic.InputPrefix.HeadHash {
		return emptyManifest, nil, emptyDiagnostic, fmt.Errorf(
			"%w: bundle %s diagnostic prefix %+v does not match the verified prefix %+v",
			ErrIntegrityConflict, bundle.Digest, doc.Diagnostic.InputPrefix, verified)
	}
	manifestDigest, err := canonicalDigest(doc.Manifest)
	if err != nil {
		return emptyManifest, nil, emptyDiagnostic, err
	}
	if doc.Diagnostic.ManifestHash != manifestDigest {
		return emptyManifest, nil, emptyDiagnostic, fmt.Errorf(
			"%w: bundle %s diagnostic manifest_hash %q does not match the embedded manifest %q",
			ErrIntegrityConflict, bundle.Digest, doc.Diagnostic.ManifestHash, manifestDigest)
	}
	if err := checkEvidenceRefResolves(doc.Events, doc.Diagnostic.AnalysisRequestRef, "diagnostic.analysis_request_ref"); err != nil {
		return emptyManifest, nil, emptyDiagnostic, fmt.Errorf("evidence_bundle: bundle %s: %w", bundle.Digest, err)
	}
	if err := validateDiagnosticShape(doc.Diagnostic); err != nil {
		return emptyManifest, nil, emptyDiagnostic, fmt.Errorf("evidence_bundle: bundle %s: %w", bundle.Digest, err)
	}
	return doc.Manifest, doc.Events, doc.Diagnostic, nil
}

// ---------------------------------------------------------------------------
// Manifest recovery.
// ---------------------------------------------------------------------------

func recoverManifest(ctx context.Context, store *OwnerStore, events []JournalEnvelope) (Manifest, ArtifactReference, []byte, error) {
	empty := Manifest{}
	if len(events) == 0 {
		return empty, ArtifactReference{}, nil, fmt.Errorf("%w: journal prefix carries no events", ErrInvalid)
	}
	first := events[0]
	rawManifest, ok := first.Payload.Data["manifest"]
	if !ok {
		return empty, ArtifactReference{}, nil, fmt.Errorf("%w: sequence 1 pins no manifest under data.manifest", ErrInvalid)
	}
	ref, err := artifactRefFromAny(rawManifest)
	if err != nil {
		return empty, ArtifactReference{}, nil, fmt.Errorf("%w: sequence 1 manifest identity is invalid: %v", ErrInvalid, err)
	}
	found := false
	for _, candidate := range first.Payload.ArtifactRefs {
		if candidate.Digest == ref.Digest {
			found = true
			ref = candidate
			break
		}
	}
	if !found {
		return empty, ArtifactReference{}, nil, fmt.Errorf(
			"%w: manifest artifact %s is not listed in sequence 1 artifact_refs", ErrInvalid, ref.Digest)
	}
	content, err := owner_store.ReadArtifact(ctx, store, ref)
	if err != nil {
		return empty, ArtifactReference{}, nil, fmt.Errorf(
			"evidence_bundle: replay bundle requires manifest artifact %s: %w", ref.Digest, err)
	}
	if string(evidence_codec.HashBytes(content)) != ref.Digest {
		return empty, ArtifactReference{}, nil, fmt.Errorf(
			"%w: manifest bytes do not match %q", ErrIntegrityConflict, ref.Digest)
	}
	if ref.Digest != first.ManifestHash {
		return empty, ArtifactReference{}, nil, fmt.Errorf(
			"%w: manifest artifact %q does not match the journal manifest_hash %q",
			ErrIntegrityConflict, ref.Digest, first.ManifestHash)
	}
	canonical, err := evidence_codec.CanonicalJSON(content, mediaTypeJSON)
	if err != nil {
		return empty, ArtifactReference{}, nil, fmt.Errorf("%w: manifest bytes are not canonical JSON: %v", ErrInvalid, err)
	}
	if !bytes.Equal(canonical, content) {
		return empty, ArtifactReference{}, nil, fmt.Errorf("%w: manifest bytes are not canonical JSON", ErrInvalid)
	}
	var manifest Manifest
	if err := json.Unmarshal(content, &manifest); err != nil {
		return empty, ArtifactReference{}, nil, fmt.Errorf("%w: manifest bytes are unreadable: %v", ErrInvalid, err)
	}
	if manifest.RecordType != manifestRecordType || manifest.SchemaVersion != manifestSchemaVersion {
		return empty, ArtifactReference{}, nil, fmt.Errorf(
			"%w: manifest record_type/schema %q/%q must be %q/%q",
			ErrInvalid, manifest.RecordType, manifest.SchemaVersion, manifestRecordType, manifestSchemaVersion)
	}
	if manifest.JournalID != first.JournalID || manifest.RunID != first.RunID || manifest.OwnerDomain != first.OwnerDomain {
		return empty, ArtifactReference{}, nil, fmt.Errorf("%w: manifest coordinates do not match the journal events", ErrIntegrityConflict)
	}
	digest, err := canonicalDigest(manifest)
	if err != nil {
		return empty, ArtifactReference{}, nil, err
	}
	if digest != ref.Digest {
		return empty, ArtifactReference{}, nil, fmt.Errorf(
			"%w: manifest digest %q does not match its artifact %q", ErrIntegrityConflict, digest, ref.Digest)
	}
	return manifest, ref, content, nil
}

// ---------------------------------------------------------------------------
// Archive derivation and verification.
// ---------------------------------------------------------------------------

func deriveAndVerifyArchive(ctx context.Context, store *OwnerStore, row LogicalRow) (ArchiveStorageManifest, ArchiveRecord, ArtifactReference, []byte, error) {
	emptyManifest := ArchiveStorageManifest{}
	emptyRecord := ArchiveRecord{}
	emptyRef := ArtifactReference{}
	if len(row.Domains) == 0 {
		return emptyManifest, emptyRecord, emptyRef, nil, fmt.Errorf("%w: logical row carries no domains", ErrInvalid)
	}
	if strings.TrimSpace(row.Registration.RegistrationID) == "" {
		return emptyManifest, emptyRecord, emptyRef, nil, fmt.Errorf("%w: logical row names no registration", ErrInvalid)
	}
	registrationBytes, err := canonicalJSONValue(row.Registration)
	if err != nil {
		return emptyManifest, emptyRecord, emptyRef, nil, err
	}
	registrationRef, err := installRegistrationExtent(ctx, store, registrationBytes)
	if err != nil {
		return emptyManifest, emptyRecord, emptyRef, nil, err
	}
	slots := make(map[string]publication.ArchiveDomainSlot, len(row.Domains))
	for domain, slot := range row.Domains {
		if slot.Revision == 0 {
			missing, ok := asMissingEnvelope(slot.Value)
			if !ok {
				return emptyManifest, emptyRecord, emptyRef, nil, fmt.Errorf(
					"%w: unpublished row slot %q must carry a typed Missing value", ErrInvalid, domain)
			}
			if slot.Document != nil || slot.PublicationRef != nil || len(slot.Snapshot) != 0 {
				return emptyManifest, emptyRecord, emptyRef, nil, fmt.Errorf(
					"%w: unpublished row slot %q carries published identities", ErrInvalid, domain)
			}
			slots[domain] = publication.ArchiveDomainSlot{Revision: 0, Value: missing}
			continue
		}
		if slot.Document == nil {
			return emptyManifest, emptyRecord, emptyRef, nil, fmt.Errorf(
				"%w: published row slot %q names no document", ErrInvalid, domain)
		}
		if slot.PublicationRef == nil {
			return emptyManifest, emptyRecord, emptyRef, nil, fmt.Errorf(
				"%w: published row slot %q names no publication reference", ErrInvalid, domain)
		}
		if err := validateArtifactRefShape(*slot.Document, "row.domains."+domain+".document"); err != nil {
			return emptyManifest, emptyRecord, emptyRef, nil, err
		}
		if err := validateEvidenceRefShape(*slot.PublicationRef, "row.domains."+domain+".publication_ref"); err != nil {
			return emptyManifest, emptyRecord, emptyRef, nil, err
		}
		snapshot, err := owner_store.ReadArtifact(ctx, store, *slot.Document)
		if err != nil {
			return emptyManifest, emptyRecord, emptyRef, nil, fmt.Errorf(
				"evidence_bundle: replay bundle requires row document %s for domain %q: %w",
				slot.Document.Digest, domain, err)
		}
		if string(evidence_codec.HashBytes(snapshot)) != slot.Document.Digest {
			return emptyManifest, emptyRecord, emptyRef, nil, fmt.Errorf(
				"%w: row document bytes for domain %q do not match %q",
				ErrIntegrityConflict, domain, slot.Document.Digest)
		}
		if len(slot.Snapshot) != 0 && !bytes.Equal(json.RawMessage(slot.Snapshot), json.RawMessage(snapshot)) {
			// The row snapshot must be the exact archived bytes, not a
			// current-revision substitution.
			slotCanonical, err := evidence_codec.CanonicalJSON(slot.Snapshot, mediaTypeJSON)
			if err != nil {
				return emptyManifest, emptyRecord, emptyRef, nil, fmt.Errorf(
					"%w: row snapshot for domain %q is not canonical JSON: %v", ErrInvalid, domain, err)
			}
			extentCanonical, err := evidence_codec.CanonicalJSON(snapshot, mediaTypeJSON)
			if err != nil {
				return emptyManifest, emptyRecord, emptyRef, nil, fmt.Errorf(
					"%w: archived extent for domain %q is not canonical JSON: %v", ErrInvalid, domain, err)
			}
			if !bytes.Equal(slotCanonical, extentCanonical) {
				return emptyManifest, emptyRecord, emptyRef, nil, fmt.Errorf(
					"%w: row snapshot for domain %q does not match its archived extent %q",
					ErrIntegrityConflict, domain, slot.Document.Digest)
			}
		}
		documentRef := *slot.Document
		publicationRef := *slot.PublicationRef
		slots[domain] = publication.ArchiveDomainSlot{
			Revision:       slot.Revision,
			Document:       &documentRef,
			PublicationRef: &publicationRef,
		}
	}
	manifest := ArchiveStorageManifest{
		Encoding:      "owner-domain-extents/1",
		SchemaVersion: row.SchemaVersion,
		Entity:        row.Entity,
		Registration:  registrationRef,
		Domains:       slots,
		SealPoint:     row.SealPoint,
	}
	if strings.TrimSpace(manifest.SchemaVersion) == "" {
		manifest.SchemaVersion = row.Registration.SchemaVersion
	}
	expanded, err := publication.ExpandArchive(ctx, store, manifest)
	if err != nil {
		return emptyManifest, emptyRecord, emptyRef, nil, fmt.Errorf("evidence_bundle: row archive is incomplete: %w", err)
	}
	if err := compareExpandedRow(row, expanded.PayloadJSON); err != nil {
		return emptyManifest, emptyRecord, emptyRef, nil, err
	}
	return manifest, expanded, registrationRef, registrationBytes, nil
}

// installRegistrationExtent installs the canonical registration bytes,
// reusing the existing registration when the same bytes are already
// registered under either access classification.
func installRegistrationExtent(ctx context.Context, store *OwnerStore, canonical []byte) (ArtifactReference, error) {
	ref, err := owner_store.InstallArtifact(ctx, store, bytes.NewReader(canonical), mediaTypeJSON, accessPublic)
	if err == nil {
		return ref, nil
	}
	if !strings.Contains(err.Error(), "different metadata") {
		return ArtifactReference{}, fmt.Errorf("evidence_bundle: install registration extent: %w", err)
	}
	ref, retryErr := owner_store.InstallArtifact(ctx, store, bytes.NewReader(canonical), mediaTypeJSON, accessRestricted)
	if retryErr != nil {
		return ArtifactReference{}, fmt.Errorf("evidence_bundle: install registration extent: %w", err)
	}
	return ref, nil
}

func compareExpandedRow(input, expanded LogicalRow) error {
	if input.RegistrationDigest != expanded.RegistrationDigest {
		return fmt.Errorf("%w: row registration_digest %q does not match the archived registration %q",
			ErrIntegrityConflict, input.RegistrationDigest, expanded.RegistrationDigest)
	}
	if len(input.Domains) != len(expanded.Domains) {
		return fmt.Errorf("%w: row carries %d domains, archive expands to %d",
			ErrIntegrityConflict, len(input.Domains), len(expanded.Domains))
	}
	for domain, slot := range input.Domains {
		other, ok := expanded.Domains[domain]
		if !ok {
			return fmt.Errorf("%w: archive omits row domain %q", ErrIntegrityConflict, domain)
		}
		if slot.Revision != other.Revision {
			return fmt.Errorf("%w: row domain %q revision %d does not match archived revision %d",
				ErrIntegrityConflict, domain, slot.Revision, other.Revision)
		}
		if slot.Revision == 0 {
			continue
		}
		if slot.Document == nil || other.Document == nil || slot.Document.Digest != other.Document.Digest {
			return fmt.Errorf("%w: row domain %q document does not match its archived extent",
				ErrIntegrityConflict, domain)
		}
	}
	for domain, version := range input.SealPoint.Versions {
		if expanded.SealPoint.Versions[domain] != version {
			return fmt.Errorf("%w: row seal vector for %q does not match the archive", ErrIntegrityConflict, domain)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Dependency collection.
// ---------------------------------------------------------------------------

// collectInputDependencies gathers every transitive replay dependency for
// an input bundle: the manifest artifact, every event artifact (declared
// and nested), the registration and every published row document, and the
// diagnostic pins and artifacts. It returns the full references keyed by
// digest plus the pin-only digests that must additionally be readable.
func collectInputDependencies(diagnostic DiagnosticDocument, events []JournalEnvelope, manifestRef, registrationRef ArtifactReference, row LogicalRow) (map[string]ArtifactReference, []string, error) {
	collected := make(map[string]ArtifactReference)
	collected[manifestRef.Digest] = manifestRef
	collected[registrationRef.Digest] = registrationRef
	for _, event := range events {
		for _, ref := range event.Payload.ArtifactRefs {
			if err := validateArtifactRefShape(ref, "journal.artifact_refs"); err != nil {
				return nil, nil, err
			}
			if prev, ok := collected[ref.Digest]; ok {
				if prev.SizeBytes != ref.SizeBytes || prev.MediaType != ref.MediaType ||
					prev.OwnerDomain != ref.OwnerDomain || prev.Access != ref.Access {
					return nil, nil, fmt.Errorf(
						"%w: artifact %s is referenced with conflicting metadata",
						ErrIntegrityConflict, ref.Digest)
				}
				continue
			}
			collected[ref.Digest] = ref
		}
		nested, err := nestedArtifactRefs(event.Payload.Data)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: journal data identities are invalid: %v", ErrInvalid, err)
		}
		for _, ref := range nested {
			if _, ok := collected[ref.Digest]; !ok {
				collected[ref.Digest] = ref
			}
		}
	}
	for domain, slot := range row.Domains {
		if slot.Revision == 0 || slot.Document == nil {
			continue
		}
		if _, ok := collected[slot.Document.Digest]; !ok {
			collected[slot.Document.Digest] = *slot.Document
		}
		_ = domain
	}
	pins, err := diagnosticPinDigests(diagnostic)
	if err != nil {
		return nil, nil, err
	}
	for _, artifact := range diagnostic.Artifacts {
		if err := validateArtifactRefShape(artifact, "diagnostic.artifacts"); err != nil {
			return nil, nil, err
		}
		if _, ok := collected[artifact.Digest]; !ok {
			collected[artifact.Digest] = artifact
		}
	}
	nestedDiagnostic, err := nestedArtifactRefsFromValue(diagnostic)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: diagnostic identities are invalid: %v", ErrInvalid, err)
	}
	for _, ref := range nestedDiagnostic {
		if _, ok := collected[ref.Digest]; !ok {
			collected[ref.Digest] = ref
		}
	}
	var pinOnly []string
	for _, digest := range pins {
		if _, ok := collected[digest]; !ok {
			pinOnly = append(pinOnly, digest)
		}
	}
	sort.Strings(pinOnly)
	return collected, pinOnly, nil
}

func collectValidationDependencies(diagnostic DiagnosticDocument, events []JournalEnvelope, manifestRef, registrationRef ArtifactReference, row LogicalRow, receipt ReplayReceipt, checks ArtifactReference) (map[string]ArtifactReference, []string, error) {
	collected, pinOnly, err := collectInputDependencies(diagnostic, events, manifestRef, registrationRef, row)
	if err != nil {
		return nil, nil, err
	}
	extra := []ArtifactReference{receipt.SourceDiagnostic, receipt.InputBundle, checks}
	for _, ref := range extra {
		if !validDigest(ref.Digest) {
			continue
		}
		if _, ok := collected[ref.Digest]; !ok {
			// Source/input/checks identities may legitimately carry
			// fuller metadata than the pin lists; keep them whole when
			// they are shape-valid, otherwise keep the digest for a
			// digest-only readability check below.
			if validateArtifactRefShape(ref, "receipt") == nil {
				collected[ref.Digest] = ref
			} else if !containsDigest(pinOnly, ref.Digest) {
				pinOnly = append(pinOnly, ref.Digest)
			}
		}
	}
	receiptPins, err := receiptPinDigests(receipt)
	if err != nil {
		return nil, nil, err
	}
	for _, digest := range receiptPins {
		if _, ok := collected[digest]; !ok && !containsDigest(pinOnly, digest) {
			pinOnly = append(pinOnly, digest)
		}
	}
	nestedReceipt, err := nestedArtifactRefsFromValue(receipt)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: receipt identities are invalid: %v", ErrInvalid, err)
	}
	for _, ref := range nestedReceipt {
		if _, ok := collected[ref.Digest]; !ok {
			collected[ref.Digest] = ref
		}
	}
	sort.Strings(pinOnly)
	return collected, pinOnly, nil
}

// readDependencyBytes reads every collected dependency and every pin-only
// digest, verifies hash identity, and computes the propagated bundle
// access. Any failure preserves the known digest.
func readDependencyBytes(ctx context.Context, store *OwnerStore, collected map[string]ArtifactReference, pinOnly []string) (map[string][]byte, map[string]ArtifactReference, string, error) {
	blobs := make(map[string][]byte, len(collected)+len(pinOnly))
	entryRefs := make(map[string]ArtifactReference, len(collected)+len(pinOnly))
	access := accessPublic
	digests := make([]string, 0, len(collected))
	for digest := range collected {
		digests = append(digests, digest)
	}
	sort.Strings(digests)
	for _, digest := range digests {
		ref := collected[digest]
		content, err := owner_store.ReadArtifact(ctx, store, ref)
		if err != nil {
			return nil, nil, "", fmt.Errorf("evidence_bundle: export requires artifact %s: %w", digest, err)
		}
		if string(evidence_codec.HashBytes(content)) != digest {
			return nil, nil, "", fmt.Errorf("%w: artifact bytes do not match %q", ErrIntegrityConflict, digest)
		}
		if int64(len(content)) != ref.SizeBytes {
			return nil, nil, "", fmt.Errorf("%w: artifact %s size %d does not match its %d stored bytes",
				ErrIntegrityConflict, digest, ref.SizeBytes, len(content))
		}
		blobs[digest] = content
		entryRefs[digest] = ref
		if ref.Access == accessRestricted {
			access = accessRestricted
		}
	}
	for _, digest := range pinOnly {
		if _, ok := blobs[digest]; ok {
			continue
		}
		content, err := owner_store.ReadArtifact(ctx, store, ArtifactReference{Digest: digest})
		if err != nil {
			return nil, nil, "", fmt.Errorf("evidence_bundle: export requires pinned artifact %s: %w", digest, err)
		}
		if string(evidence_codec.HashBytes(content)) != digest {
			return nil, nil, "", fmt.Errorf("%w: pinned artifact bytes do not match %q", ErrIntegrityConflict, digest)
		}
		blobs[digest] = content
		entryRefs[digest] = ArtifactReference{
			Digest:      digest,
			SizeBytes:   int64(len(content)),
			MediaType:   mediaTypeOctet,
			OwnerDomain: "",
			Access:      accessPublic,
		}
	}
	return blobs, entryRefs, access, nil
}

// ---------------------------------------------------------------------------
// Bundle assembly.
// ---------------------------------------------------------------------------

func buildInputsBundle(manifest Manifest, manifestBytes []byte, events []JournalEnvelope, diagnostic DiagnosticDocument, row LogicalRow, archiveManifest ArchiveStorageManifest, expanded ArchiveRecord, blobs map[string][]byte, entryRefs map[string]ArtifactReference, bundleAccess string) (*BundleDocument, error) {
	diagnosticBytes, err := canonicalJSONValue(diagnostic)
	if err != nil {
		return nil, err
	}
	rowBytes, err := canonicalJSONValue(row)
	if err != nil {
		return nil, err
	}
	journalBytes, err := canonicalJournalLines(events)
	if err != nil {
		return nil, err
	}
	_ = expanded
	derived := map[string]derivedBlob{
		entryManifest:      {bytes: manifestBytes, mediaType: mediaTypeJSON, access: accessForDigest(entryRefs, manifestDigestOf(manifestBytes), bundleAccess)},
		entryJournal:       {bytes: journalBytes, mediaType: mediaTypeJSON, access: bundleAccess},
		entryDiagnostic:    {bytes: diagnosticBytes, mediaType: mediaTypeJSON, access: bundleAccess},
		entryAuthoritative: {bytes: rowBytes, mediaType: mediaTypeJSON, access: bundleAccess},
	}
	// Registration and domain documents keep their store identities but
	// gain friendly domain names in addition to content-addressed entries.
	names := map[string]string{}
	registrationDigest := string(evidence_codec.HashBytes(mustCanonicalRegistration(row.Registration)))
	_ = registrationDigest
	doc := &BundleDocument{
		RecordType:         bundleInputsRecordType,
		SchemaVersion:      bundleSchemaVersion,
		Manifest:           manifest,
		Events:             events,
		Diagnostic:         diagnostic,
		Row:                row,
		ArchiveManifest:    archiveManifest,
		ReplayAvailability: availabilityExact,
		Blobs:              map[string]string{},
	}
	entries, blobMap, err := assembleEntries(blobs, entryRefs, derived, names, row, nil, bundleAccess)
	if err != nil {
		return nil, err
	}
	doc.Entries = entries
	doc.Blobs = blobMap
	if err := rejectReceiptLeak(doc, nil); err != nil {
		return nil, err
	}
	return doc, nil
}

func buildValidationBundle(manifest Manifest, manifestBytes []byte, events []JournalEnvelope, diagnostic DiagnosticDocument, row LogicalRow, archiveManifest ArchiveStorageManifest, expanded ArchiveRecord, receipt ReplayReceipt, checks ArtifactReference, blobs map[string][]byte, entryRefs map[string]ArtifactReference, bundleAccess string) (*BundleDocument, error) {
	diagnosticBytes, err := canonicalJSONValue(diagnostic)
	if err != nil {
		return nil, err
	}
	rowBytes, err := canonicalJSONValue(row)
	if err != nil {
		return nil, err
	}
	journalBytes, err := canonicalJournalLines(events)
	if err != nil {
		return nil, err
	}
	receiptBytes, err := canonicalJSONValue(receipt)
	if err != nil {
		return nil, err
	}
	markdown := renderDiagnosticMarkdown(diagnostic)
	_ = expanded
	derived := map[string]derivedBlob{
		entryManifest:      {bytes: manifestBytes, mediaType: mediaTypeJSON, access: accessForDigest(entryRefs, manifestDigestOf(manifestBytes), bundleAccess)},
		entryJournal:       {bytes: journalBytes, mediaType: mediaTypeJSON, access: bundleAccess},
		entryDiagnostic:    {bytes: diagnosticBytes, mediaType: mediaTypeJSON, access: bundleAccess},
		entryDiagnosticMD:  {bytes: markdown, mediaType: mediaTypeMarkdown, access: bundleAccess},
		entryAuthoritative: {bytes: rowBytes, mediaType: mediaTypeJSON, access: bundleAccess},
		entryReplayReceipt: {bytes: receiptBytes, mediaType: mediaTypeJSON, access: bundleAccess},
	}
	names := map[string]string{}
	doc := &BundleDocument{
		RecordType:         bundleValidationRecordType,
		SchemaVersion:      bundleSchemaVersion,
		Manifest:           manifest,
		Events:             events,
		Diagnostic:         diagnostic,
		Row:                row,
		ArchiveManifest:    archiveManifest,
		Receipt:            &receipt,
		Checks:             &checks,
		ReplayAvailability: availabilityExact,
		Blobs:              map[string]string{},
	}
	// The checks bytes keep their store identity under the M1 friendly name.
	names[checks.Digest] = entryAcceptance
	entries, blobMap, err := assembleEntries(blobs, entryRefs, derived, names, row, &receipt, bundleAccess)
	if err != nil {
		return nil, err
	}
	doc.Entries = entries
	doc.Blobs = blobMap
	return doc, nil
}

type derivedBlob struct {
	bytes     []byte
	mediaType string
	access    string
}

func assembleEntries(blobs map[string][]byte, entryRefs map[string]ArtifactReference, derived map[string]derivedBlob, preferredNames map[string]string, row LogicalRow, receipt *ReplayReceipt, bundleAccess string) ([]BundleEntry, map[string]string, error) {
	_ = receipt
	blobMap := make(map[string]string, len(blobs)+len(derived)+2)
	entries := make([]BundleEntry, 0, len(blobs)+len(derived)+2)
	assigned := make(map[string]string) // digest -> name

	emit := func(name string, digest string, content []byte, mediaType, ownerDomain, access string) {
		if prev, ok := assigned[digest]; ok {
			_ = prev
			// One digest may back several friendly names only when the
			// names are identical; otherwise the first (M1-preferred)
			// name wins and the duplicate is dropped to keep the
			// manifest deterministic.
			for _, entry := range entries {
				if entry.Name == name {
					return
				}
			}
			if name == prev {
				return
			}
			// Keep both names when they genuinely differ: the same
			// bytes are reachable under two friendly names.
			entries = append(entries, BundleEntry{
				Name: name, Digest: digest, SizeBytes: int64(len(content)),
				MediaType: mediaType, OwnerDomain: ownerDomain, Access: access,
			})
			return
		}
		assigned[digest] = name
		entries = append(entries, BundleEntry{
			Name: name, Digest: digest, SizeBytes: int64(len(content)),
			MediaType: mediaType, OwnerDomain: ownerDomain, Access: access,
		})
		blobMap[digest] = base64.StdEncoding.EncodeToString(content)
	}

	// Derived M1 documents first so their friendly names win over
	// content-addressed aliases for the same bytes.
	derivedNames := make([]string, 0, len(derived))
	for name := range derived {
		derivedNames = append(derivedNames, name)
	}
	sort.Strings(derivedNames)
	for _, name := range derivedNames {
		content := derived[name]
		digest := string(evidence_codec.HashBytes(content.bytes))
		emit(name, digest, content.bytes, content.mediaType, "", content.access)
	}

	// Registration under its friendly name.
	registrationBytes, err := canonicalJSONValue(row.Registration)
	if err != nil {
		return nil, nil, err
	}
	registrationDigest := string(evidence_codec.HashBytes(registrationBytes))
	if content, ok := blobs[registrationDigest]; ok {
		ref := entryRefs[registrationDigest]
		emit(entryRegistration, registrationDigest, content, ref.MediaType, ref.OwnerDomain, ref.Access)
	}

	// Domain documents under per-domain friendly names.
	domains := make([]string, 0, len(row.Domains))
	for domain := range row.Domains {
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	for _, domain := range domains {
		slot := row.Domains[domain]
		if slot.Revision == 0 || slot.Document == nil {
			continue
		}
		content, ok := blobs[slot.Document.Digest]
		if !ok {
			return nil, nil, fmt.Errorf("%w: bundle omits row document %s for domain %q",
				ErrUnavailable, slot.Document.Digest, domain)
		}
		name := domainsDirPrefix + domain + ".json"
		ref := entryRefs[slot.Document.Digest]
		emit(name, slot.Document.Digest, content, ref.MediaType, ref.OwnerDomain, ref.Access)
	}

	// Preferred M1 aliases (acceptance checks, task/build/timing carriers).
	for digest, name := range preferredNames {
		content, ok := blobs[digest]
		if !ok {
			continue
		}
		ref, ok := entryRefs[digest]
		if !ok {
			continue
		}
		emit(name, digest, content, ref.MediaType, ref.OwnerDomain, ref.Access)
	}

	// Remaining store dependencies under content-addressed friendly names.
	remaining := make([]string, 0, len(blobs))
	for digest := range blobs {
		if _, ok := assigned[digest]; ok {
			continue
		}
		remaining = append(remaining, digest)
	}
	sort.Strings(remaining)
	for _, digest := range remaining {
		ref := entryRefs[digest]
		name := entriesDirPrefix + strings.TrimPrefix(digest, "sha256:")
		emit(name, digest, blobs[digest], ref.MediaType, ref.OwnerDomain, ref.Access)
	}

	// Artifact inventory: canonical JSON of every other entry, so the
	// inventory itself is content-addressed and verifiable without
	// self-reference.
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	inventoryBytes, err := canonicalJSONValue(entries)
	if err != nil {
		return nil, nil, err
	}
	inventoryDigest := string(evidence_codec.HashBytes(inventoryBytes))
	if _, ok := assigned[inventoryDigest]; !ok {
		entries = append(entries, BundleEntry{
			Name: entryInventory, Digest: inventoryDigest, SizeBytes: int64(len(inventoryBytes)),
			MediaType: mediaTypeJSON, OwnerDomain: "", Access: bundleAccess,
		})
		blobMap[inventoryDigest] = base64.StdEncoding.EncodeToString(inventoryBytes)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })

	// Every blob must be reachable through at least one entry.
	for digest := range blobMap {
		if _, ok := assigned[digest]; !ok && digest != inventoryDigest {
			return nil, nil, fmt.Errorf("%w: bundle blob %s has no friendly entry", ErrIntegrityConflict, digest)
		}
	}
	seen := make(map[string]bool, len(entries))
	for _, entry := range entries {
		if seen[entry.Name] {
			return nil, nil, fmt.Errorf("%w: bundle entry %q appears twice", ErrIntegrityConflict, entry.Name)
		}
		seen[entry.Name] = true
		if !validDigest(entry.Digest) {
			return nil, nil, fmt.Errorf("%w: bundle entry %q carries invalid digest %q", ErrInvalid, entry.Name, entry.Digest)
		}
	}
	return entries, blobMap, nil
}

func accessForDigest(entryRefs map[string]ArtifactReference, digest, fallback string) string {
	if ref, ok := entryRefs[digest]; ok && ref.Access != "" {
		return ref.Access
	}
	return fallback
}

func manifestDigestOf(content []byte) string {
	return string(evidence_codec.HashBytes(content))
}

func mustCanonicalRegistration(registration EntityRegistration) []byte {
	raw, err := canonicalJSONValue(registration)
	if err != nil {
		return []byte("{}")
	}
	return raw
}

// rejectReceiptLeak guarantees the input bundle carries no receipt bytes,
// names, or identifiers.
func rejectReceiptLeak(doc *BundleDocument, receipt *ReplayReceipt) error {
	_ = receipt
	if doc.Receipt != nil {
		return fmt.Errorf("%w: replay-input bundle embeds a receipt", ErrIntegrityConflict)
	}
	for _, entry := range doc.Entries {
		if entry.Name == entryReplayReceipt {
			return fmt.Errorf("%w: replay-input bundle carries %q", ErrIntegrityConflict, entryReplayReceipt)
		}
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("%w: encode bundle for leak check: %v", ErrInvalid, err)
	}
	lowered := strings.ToLower(string(raw))
	for _, token := range []string{"replay_id", "replay-receipt", "performed_external_writes"} {
		if strings.Contains(lowered, token) {
			return fmt.Errorf("%w: replay-input bundle leaks receipt field %q", ErrIntegrityConflict, token)
		}
	}
	return nil
}

func installBundle(ctx context.Context, store *OwnerStore, doc *BundleDocument, entryRefs map[string]ArtifactReference, events []JournalEnvelope) (ArtifactReference, error) {
	empty := ArtifactReference{}
	if len(events) == 0 {
		return empty, fmt.Errorf("%w: bundle pins no journal events", ErrInvalid)
	}
	bundleAccess := accessPublic
	for _, entry := range doc.Entries {
		if entry.Access == accessRestricted {
			bundleAccess = accessRestricted
			break
		}
	}
	canonical, err := canonicalJSONValue(doc)
	if err != nil {
		return empty, err
	}
	// Defensive re-parse: the installed bytes must decode to the same
	// bundle, so no encoder aliasing can smuggle a receipt into inputs.
	var reparsed BundleDocument
	if err := json.Unmarshal(canonical, &reparsed); err != nil {
		return empty, fmt.Errorf("%w: bundle bytes do not round-trip: %v", ErrInvalid, err)
	}
	if doc.RecordType == bundleInputsRecordType && reparsed.Receipt != nil {
		return empty, fmt.Errorf("%w: replay-input bundle embeds a receipt", ErrIntegrityConflict)
	}
	ref, err := owner_store.InstallArtifact(ctx, store, bytes.NewReader(canonical), mediaTypeJSON, bundleAccess)
	if err != nil {
		return empty, fmt.Errorf("evidence_bundle: install %s: %w", doc.RecordType, err)
	}
	dependencies := make([]ArtifactReference, 0, len(entryRefs))
	for _, candidate := range entryRefs {
		if candidate.Digest == ref.Digest {
			continue
		}
		// RetainRoot requires exact registered metadata; pin-only
		// placeholders (empty owner) are embedded in the bundle blobs
		// but cannot be retention edges.
		if candidate.OwnerDomain == "" {
			continue
		}
		dependencies = append(dependencies, candidate)
	}
	sort.Slice(dependencies, func(i, j int) bool { return dependencies[i].Digest < dependencies[j].Digest })
	last := events[len(events)-1]
	support := EvidenceRef{
		JournalID: last.JournalID,
		Sequence:  last.Sequence,
		EventID:   last.EventID,
		EventHash: last.EventHash,
		Pointer:   "",
	}
	if err := owner_store.RetainRoot(ctx, store, ref, dependencies, support); err != nil {
		return empty, fmt.Errorf("evidence_bundle: retain %s %s: %w", doc.RecordType, ref.Digest, err)
	}
	return ref, nil
}

// ---------------------------------------------------------------------------
// Bundle verification (load path).
// ---------------------------------------------------------------------------

func verifyBundleEntries(doc BundleDocument, bundleDigest string) (map[string][]byte, error) {
	if len(doc.Entries) == 0 {
		return nil, fmt.Errorf("%w: bundle %s carries no entries", ErrUnavailable, bundleDigest)
	}
	if len(doc.Blobs) == 0 {
		return nil, fmt.Errorf("%w: bundle %s carries no blobs", ErrUnavailable, bundleDigest)
	}
	seen := make(map[string]string, len(doc.Entries))
	for _, entry := range doc.Entries {
		if strings.TrimSpace(entry.Name) == "" {
			return nil, fmt.Errorf("%w: bundle %s carries an unnamed entry", ErrInvalid, bundleDigest)
		}
		if prev, dup := seen[entry.Name]; dup {
			return nil, fmt.Errorf("%w: bundle %s entry %q appears twice (%s vs %s)",
				ErrIntegrityConflict, bundleDigest, entry.Name, prev, entry.Digest)
		}
		seen[entry.Name] = entry.Digest
		if !validDigest(entry.Digest) {
			return nil, fmt.Errorf("%w: bundle %s entry %q carries invalid digest %q",
				ErrInvalid, bundleDigest, entry.Name, entry.Digest)
		}
		if entry.Access != accessPublic && entry.Access != accessRestricted {
			return nil, fmt.Errorf("%w: bundle %s entry %q carries invalid access %q",
				ErrInvalid, bundleDigest, entry.Name, entry.Access)
		}
	}
	decoded := make(map[string][]byte, len(doc.Blobs))
	for digest, encoded := range doc.Blobs {
		if !validDigest(digest) {
			return nil, fmt.Errorf("%w: bundle %s blob key %q is not a digest", ErrInvalid, bundleDigest, digest)
		}
		content, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("%w: bundle %s blob %s is not base64: %v", ErrInvalid, bundleDigest, digest, err)
		}
		if string(evidence_codec.HashBytes(content)) != digest {
			return nil, fmt.Errorf("%w: bundle %s blob %s does not match its digest",
				ErrIntegrityConflict, bundleDigest, digest)
		}
		decoded[digest] = content
	}
	for _, entry := range doc.Entries {
		content, ok := decoded[entry.Digest]
		if !ok {
			return nil, fmt.Errorf("%w: bundle %s entry %q requires blob %s: unavailable",
				ErrUnavailable, bundleDigest, entry.Name, entry.Digest)
		}
		if int64(len(content)) != entry.SizeBytes {
			return nil, fmt.Errorf("%w: bundle %s entry %q size %d does not match its %d blob bytes",
				ErrIntegrityConflict, bundleDigest, entry.Name, entry.SizeBytes, len(content))
		}
	}
	covered := make(map[string]bool, len(doc.Entries))
	for _, entry := range doc.Entries {
		covered[entry.Digest] = true
	}
	for digest := range decoded {
		if !covered[digest] {
			return nil, fmt.Errorf("%w: bundle %s blob %s has no friendly entry",
				ErrIntegrityConflict, bundleDigest, digest)
		}
	}
	return decoded, nil
}

func verifyDerivedDocuments(doc BundleDocument, decoded map[string][]byte, bundleDigest string) error {
	byName := make(map[string]BundleEntry, len(doc.Entries))
	for _, entry := range doc.Entries {
		byName[entry.Name] = entry
	}
	require := func(name string) ([]byte, error) {
		entry, ok := byName[name]
		if !ok {
			return nil, fmt.Errorf("%w: bundle %s omits required entry %q: unavailable",
				ErrUnavailable, bundleDigest, name)
		}
		content, ok := decoded[entry.Digest]
		if !ok {
			return nil, fmt.Errorf("%w: bundle %s entry %q requires blob %s: unavailable",
				ErrUnavailable, bundleDigest, name, entry.Digest)
		}
		return content, nil
	}
	manifestBytes, err := require(entryManifest)
	if err != nil {
		return err
	}
	canonicalManifest, err := canonicalJSONValue(doc.Manifest)
	if err != nil {
		return err
	}
	if !bytes.Equal(manifestBytes, canonicalManifest) {
		return fmt.Errorf("%w: bundle %s entry %q does not match the embedded manifest",
			ErrIntegrityConflict, bundleDigest, entryManifest)
	}
	journalBytes, err := require(entryJournal)
	if err != nil {
		return err
	}
	expectedJournal, err := canonicalJournalLines(doc.Events)
	if err != nil {
		return err
	}
	if !bytes.Equal(journalBytes, expectedJournal) {
		return fmt.Errorf("%w: bundle %s entry %q does not match the embedded events",
			ErrIntegrityConflict, bundleDigest, entryJournal)
	}
	diagnosticBytes, err := require(entryDiagnostic)
	if err != nil {
		return err
	}
	canonicalDiagnostic, err := canonicalJSONValue(doc.Diagnostic)
	if err != nil {
		return err
	}
	if !bytes.Equal(diagnosticBytes, canonicalDiagnostic) {
		return fmt.Errorf("%w: bundle %s entry %q does not match the embedded diagnostic",
			ErrIntegrityConflict, bundleDigest, entryDiagnostic)
	}
	rowBytes, err := require(entryAuthoritative)
	if err != nil {
		return err
	}
	canonicalRow, err := canonicalJSONValue(doc.Row)
	if err != nil {
		return err
	}
	if !bytes.Equal(rowBytes, canonicalRow) {
		return fmt.Errorf("%w: bundle %s entry %q does not match the embedded row",
			ErrIntegrityConflict, bundleDigest, entryAuthoritative)
	}
	registrationBytes, err := require(entryRegistration)
	if err != nil {
		return err
	}
	canonicalRegistration, err := canonicalJSONValue(doc.Row.Registration)
	if err != nil {
		return err
	}
	if !bytes.Equal(registrationBytes, canonicalRegistration) {
		return fmt.Errorf("%w: bundle %s entry %q does not match the row registration",
			ErrIntegrityConflict, bundleDigest, entryRegistration)
	}
	for domain, slot := range doc.Row.Domains {
		if slot.Revision == 0 || slot.Document == nil {
			continue
		}
		name := domainsDirPrefix + domain + ".json"
		content, err := require(name)
		if err != nil {
			return err
		}
		if string(evidence_codec.HashBytes(content)) != slot.Document.Digest {
			return fmt.Errorf("%w: bundle %s entry %q does not match the row document %s",
				ErrIntegrityConflict, bundleDigest, name, slot.Document.Digest)
		}
		if len(slot.Snapshot) != 0 && !bytes.Equal(json.RawMessage(slot.Snapshot), json.RawMessage(content)) {
			return fmt.Errorf("%w: bundle %s entry %q does not match the row snapshot for %q",
				ErrIntegrityConflict, bundleDigest, name, domain)
		}
	}
	if doc.RecordType == bundleValidationRecordType {
		if doc.Receipt == nil {
			return fmt.Errorf("%w: bundle %s is a validation bundle without a receipt", ErrInvalid, bundleDigest)
		}
		receiptBytes, err := require(entryReplayReceipt)
		if err != nil {
			return err
		}
		canonicalReceipt, err := canonicalJSONValue(*doc.Receipt)
		if err != nil {
			return err
		}
		if !bytes.Equal(receiptBytes, canonicalReceipt) {
			return fmt.Errorf("%w: bundle %s entry %q does not match the embedded receipt",
				ErrIntegrityConflict, bundleDigest, entryReplayReceipt)
		}
		if doc.Checks == nil {
			return fmt.Errorf("%w: bundle %s is a validation bundle without checks", ErrInvalid, bundleDigest)
		}
		checksBytes, err := require(entryAcceptance)
		if err != nil {
			return err
		}
		if string(evidence_codec.HashBytes(checksBytes)) != doc.Checks.Digest {
			return fmt.Errorf("%w: bundle %s entry %q does not match checks %s",
				ErrIntegrityConflict, bundleDigest, entryAcceptance, doc.Checks.Digest)
		}
	} else if _, ok := byName[entryReplayReceipt]; ok {
		return fmt.Errorf("%w: replay-input bundle %s carries %q", ErrIntegrityConflict, bundleDigest, entryReplayReceipt)
	}
	inventoryBytes, err := require(entryInventory)
	if err != nil {
		return err
	}
	var inventory []BundleEntry
	if err := json.Unmarshal(inventoryBytes, &inventory); err != nil {
		return fmt.Errorf("%w: bundle %s inventory is unreadable: %v", ErrInvalid, bundleDigest, err)
	}
	// The inventory lists every other entry; it never lists itself.
	want := make(map[string]string, len(doc.Entries))
	for _, entry := range doc.Entries {
		if entry.Name == entryInventory {
			continue
		}
		want[entry.Name] = entry.Digest
	}
	got := make(map[string]string, len(inventory))
	for _, entry := range inventory {
		got[entry.Name] = entry.Digest
	}
	if len(got) != len(want) {
		return fmt.Errorf("%w: bundle %s inventory lists %d entries, bundle carries %d",
			ErrIntegrityConflict, bundleDigest, len(got), len(want))
	}
	for name, digest := range want {
		if got[name] != digest {
			return fmt.Errorf("%w: bundle %s inventory entry %q mismatch", ErrIntegrityConflict, bundleDigest, name)
		}
	}
	return nil
}

// verifyBundleCompleteness re-derives the expected transitive closure from
// the embedded manifest, events, diagnostic, row, and receipt, and requires
// every expected digest to be present. A redacted or tampered bundle fails
// here with the known missing identities.
func verifyBundleCompleteness(doc BundleDocument, bundleDigest string) error {
	present := make(map[string]bool, len(doc.Entries))
	for _, entry := range doc.Entries {
		present[entry.Digest] = true
	}
	manifestDigest, err := canonicalDigest(doc.Manifest)
	if err != nil {
		return err
	}
	expected := map[string]string{manifestDigest: "manifest"}
	for _, event := range doc.Events {
		for _, ref := range event.Payload.ArtifactRefs {
			expected[ref.Digest] = "journal.artifact_refs"
		}
		nested, err := nestedArtifactRefs(event.Payload.Data)
		if err != nil {
			return fmt.Errorf("%w: bundle %s journal identities are invalid: %v", ErrInvalid, bundleDigest, err)
		}
		for _, ref := range nested {
			expected[ref.Digest] = "journal.data"
		}
	}
	registrationBytes, err := canonicalJSONValue(doc.Row.Registration)
	if err != nil {
		return err
	}
	expected[string(evidence_codec.HashBytes(registrationBytes))] = "row.registration"
	for domain, slot := range doc.Row.Domains {
		if slot.Revision == 0 || slot.Document == nil {
			continue
		}
		expected[slot.Document.Digest] = "row.domains." + domain
	}
	pins, err := diagnosticPinDigests(doc.Diagnostic)
	if err != nil {
		return fmt.Errorf("%w: bundle %s: %v", ErrInvalid, bundleDigest, err)
	}
	for _, digest := range pins {
		expected[digest] = "diagnostic.pin"
	}
	for _, ref := range doc.Diagnostic.Artifacts {
		expected[ref.Digest] = "diagnostic.artifacts"
	}
	nestedDiagnostic, err := nestedArtifactRefsFromValue(doc.Diagnostic)
	if err != nil {
		return fmt.Errorf("%w: bundle %s diagnostic identities are invalid: %v", ErrInvalid, bundleDigest, err)
	}
	for _, ref := range nestedDiagnostic {
		expected[ref.Digest] = "diagnostic.data"
	}
	if doc.Receipt != nil {
		for _, ref := range []ArtifactReference{doc.Receipt.SourceDiagnostic, doc.Receipt.InputBundle} {
			if validDigest(ref.Digest) {
				expected[ref.Digest] = "receipt.ref"
			}
		}
		receiptPins, err := receiptPinDigests(*doc.Receipt)
		if err != nil {
			return fmt.Errorf("%w: bundle %s: %v", ErrInvalid, bundleDigest, err)
		}
		for _, digest := range receiptPins {
			expected[digest] = "receipt.pin"
		}
	}
	if doc.Checks != nil && validDigest(doc.Checks.Digest) {
		expected[doc.Checks.Digest] = "checks"
	}
	var missing []string
	for digest, where := range expected {
		if !validDigest(digest) {
			return fmt.Errorf("%w: bundle %s %s carries invalid digest %q", ErrInvalid, bundleDigest, where, digest)
		}
		if !present[digest] {
			missing = append(missing, digest+" ("+where+")")
		}
	}
	sort.Strings(missing)
	if len(missing) != 0 {
		return fmt.Errorf("%w: bundle %s omits %d exact replay inputs: %s",
			ErrUnavailable, bundleDigest, len(missing), strings.Join(missing, ", "))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Receipt validation.
// ---------------------------------------------------------------------------

func validateReceiptShape(receipt ReplayReceipt) error {
	if receipt.RecordType != receiptRecordType {
		return fmt.Errorf("%w: receipt record_type %q must be %q", ErrInvalid, receipt.RecordType, receiptRecordType)
	}
	if receipt.SchemaVersion != receiptSchema {
		return fmt.Errorf("%w: receipt schema_version %q must be %q", ErrInvalid, receipt.SchemaVersion, receiptSchema)
	}
	if strings.TrimSpace(receipt.ReplayID) == "" {
		return fmt.Errorf("%w: receipt replay_id is required", ErrInvalid)
	}
	if receipt.Mode != modeExactFixture && receipt.Mode != modeDiagnosticOnly {
		return fmt.Errorf("%w: receipt mode %q must be %q or %q", ErrInvalid, receipt.Mode, modeExactFixture, modeDiagnosticOnly)
	}
	if strings.TrimSpace(receipt.RunID) == "" {
		return fmt.Errorf("%w: receipt run_id is required", ErrInvalid)
	}
	if !validDigest(receipt.ManifestHash) {
		return fmt.Errorf("%w: receipt manifest_hash %q is invalid", ErrInvalid, receipt.ManifestHash)
	}
	if strings.TrimSpace(receipt.SourcePrefix.JournalID) == "" || receipt.SourcePrefix.LastSequence < 1 || !validDigest(receipt.SourcePrefix.HeadHash) {
		return fmt.Errorf("%w: receipt source_prefix is invalid", ErrInvalid)
	}
	if err := validateArtifactRefShape(receipt.SourceDiagnostic, "receipt.source_diagnostic"); err != nil {
		return err
	}
	if err := validateArtifactRefShape(receipt.InputBundle, "receipt.input_bundle"); err != nil {
		return err
	}
	if err := validateVersionPin(receipt.Classifier, "receipt.classifier"); err != nil {
		return err
	}
	if receipt.Mode == modeExactFixture {
		pin, ok := asVersionPin(receipt.Reducer)
		if !ok {
			return fmt.Errorf("%w: exact_fixture receipt reducer must be a VersionPin", ErrInvalid)
		}
		if err := validateVersionPin(pin, "receipt.reducer"); err != nil {
			return err
		}
	} else {
		missing, ok := asMissingEnvelope(receipt.Reducer)
		if !ok {
			return fmt.Errorf("%w: diagnostic_only receipt reducer must be Missing(not_applicable)", ErrInvalid)
		}
		if missing.Reason != "not_applicable" {
			return fmt.Errorf("%w: diagnostic_only receipt reducer reason %q must be not_applicable", ErrInvalid, missing.Reason)
		}
	}
	if err := validateVersionPin(receipt.ReplayEngine, "receipt.replay_engine"); err != nil {
		return err
	}
	if len(receipt.Comparisons) == 0 {
		return fmt.Errorf("%w: receipt carries no comparisons", ErrInvalid)
	}
	outputs := make(map[string]bool, len(receipt.Comparisons))
	for i, comparison := range receipt.Comparisons {
		where := fmt.Sprintf("receipt.comparisons[%d]", i)
		if strings.TrimSpace(comparison.Output) == "" {
			return fmt.Errorf("%w: %s names no output", ErrInvalid, where)
		}
		if outputs[comparison.Output] {
			return fmt.Errorf("%w: %s duplicates output %q", ErrInvalid, where, comparison.Output)
		}
		outputs[comparison.Output] = true
		if !validDigest(comparison.ExpectedDigest) {
			return fmt.Errorf("%w: %s expected_digest %q is invalid", ErrInvalid, where, comparison.ExpectedDigest)
		}
		switch actual := comparison.ActualDigest.(type) {
		case string:
			if !validDigest(actual) {
				return fmt.Errorf("%w: %s actual_digest %q is invalid", ErrInvalid, where, actual)
			}
		default:
			if _, ok := asMissingEnvelope(comparison.ActualDigest); !ok {
				return fmt.Errorf("%w: %s actual_digest must be a digest or Missing", ErrInvalid, where)
			}
		}
		if comparison.Result != resultMatched && comparison.Result != resultMismatched && comparison.Result != resultUnavailable {
			return fmt.Errorf("%w: %s result %q must be matched, mismatched, or unavailable", ErrInvalid, where, comparison.Result)
		}
		if _, isMissing := asMissingEnvelope(comparison.ActualDigest); isMissing && comparison.Result == resultMatched {
			return fmt.Errorf("%w: %s is matched with a Missing actual digest", ErrInvalid, where)
		}
	}
	if receipt.Mode == modeExactFixture {
		for _, required := range []string{comparisonSemanticEvents, comparisonFinalState, comparisonDiagnostic} {
			if !outputs[required] {
				return fmt.Errorf("%w: exact_fixture receipt omits %q comparison", ErrInvalid, required)
			}
		}
	} else {
		if !outputs[comparisonDiagnostic] {
			return fmt.Errorf("%w: diagnostic_only receipt omits %q comparison", ErrInvalid, comparisonDiagnostic)
		}
	}
	expected := aggregateResult(receipt.Comparisons)
	if receipt.Result != expected {
		return fmt.Errorf("%w: receipt result %q does not match the aggregate %q of its comparisons",
			ErrInvalid, receipt.Result, expected)
	}
	if receipt.Result == resultMatched {
		for _, comparison := range receipt.Comparisons {
			if _, isMissing := asMissingEnvelope(comparison.ActualDigest); isMissing {
				return fmt.Errorf("%w: matched receipt carries an unavailable comparison", ErrInvalid)
			}
		}
	}
	if receipt.Limitations == nil {
		return fmt.Errorf("%w: receipt limitations must be an array, not null", ErrInvalid)
	}
	if receipt.InvokedBrowser || receipt.InvokedSubject || receipt.PerformedExternalWrites {
		return fmt.Errorf("%w: receipt invocation flags must all be false", ErrInvalid)
	}
	return nil
}

func validateReceiptAgainstInputs(ctx context.Context, store *OwnerStore, receipt ReplayReceipt, diagnostic DiagnosticDocument, diagnosticBytes []byte, manifestDigest string, events []JournalEnvelope) error {
	if receipt.ManifestHash != manifestDigest {
		return fmt.Errorf("%w: receipt manifest_hash %q does not match the bundle manifest %q",
			ErrIntegrityConflict, receipt.ManifestHash, manifestDigest)
	}
	if receipt.SourcePrefix != diagnostic.InputPrefix {
		return fmt.Errorf("%w: receipt source prefix %+v does not match the diagnostic prefix %+v",
			ErrIntegrityConflict, receipt.SourcePrefix, diagnostic.InputPrefix)
	}
	if receipt.RunID != diagnostic.RunID {
		return fmt.Errorf("%w: receipt run %q does not match the diagnostic run %q",
			ErrIntegrityConflict, receipt.RunID, diagnostic.RunID)
	}
	if receipt.Classifier != diagnostic.Classifier {
		return fmt.Errorf("%w: receipt classifier %+v does not match the diagnostic classifier %+v",
			ErrIntegrityConflict, receipt.Classifier, diagnostic.Classifier)
	}
	sourceBytes, err := owner_store.ReadArtifact(ctx, store, receipt.SourceDiagnostic)
	if err != nil {
		return fmt.Errorf("evidence_bundle: validation bundle requires source diagnostic %s: %w",
			receipt.SourceDiagnostic.Digest, err)
	}
	if string(evidence_codec.HashBytes(sourceBytes)) != receipt.SourceDiagnostic.Digest {
		return fmt.Errorf("%w: source diagnostic bytes do not match %q",
			ErrIntegrityConflict, receipt.SourceDiagnostic.Digest)
	}
	sourceCanonical, err := evidence_codec.CanonicalJSON(sourceBytes, mediaTypeJSON)
	if err != nil {
		return fmt.Errorf("%w: source diagnostic bytes are not canonical JSON: %v", ErrInvalid, err)
	}
	if !bytes.Equal(sourceCanonical, diagnosticBytes) {
		return fmt.Errorf("%w: source diagnostic %s does not match the bundled diagnostic",
			ErrIntegrityConflict, receipt.SourceDiagnostic.Digest)
	}
	inputRaw, err := owner_store.ReadArtifact(ctx, store, receipt.InputBundle)
	if err != nil {
		return fmt.Errorf("evidence_bundle: validation bundle requires input bundle %s: %w",
			receipt.InputBundle.Digest, err)
	}
	var inputDoc BundleDocument
	if err := json.Unmarshal(inputRaw, &inputDoc); err != nil {
		return fmt.Errorf("%w: input bundle %s is unreadable: %v", ErrInvalid, receipt.InputBundle.Digest, err)
	}
	if inputDoc.RecordType != bundleInputsRecordType {
		return fmt.Errorf("%w: receipt input bundle %s is %q, not a replay-input bundle",
			ErrInvalid, receipt.InputBundle.Digest, inputDoc.RecordType)
	}
	if inputDoc.Diagnostic.DiagnosticID != diagnostic.DiagnosticID {
		return fmt.Errorf("%w: receipt input bundle diagnostic %q does not match %q",
			ErrIntegrityConflict, inputDoc.Diagnostic.DiagnosticID, diagnostic.DiagnosticID)
	}
	inputManifestDigest, err := canonicalDigest(inputDoc.Manifest)
	if err != nil {
		return err
	}
	if inputManifestDigest != manifestDigest {
		return fmt.Errorf("%w: receipt input bundle manifest %q does not match %q",
			ErrIntegrityConflict, inputManifestDigest, manifestDigest)
	}
	return nil
}

func aggregateResult(comparisons []ReplayComparison) string {
	for _, comparison := range comparisons {
		if comparison.Result == resultMismatched {
			return resultMismatched
		}
	}
	for _, comparison := range comparisons {
		if comparison.Result == resultUnavailable {
			return resultUnavailable
		}
	}
	return resultMatched
}

// ---------------------------------------------------------------------------
// Diagnostic validation.
// ---------------------------------------------------------------------------

func validateDiagnosticShape(diagnostic DiagnosticDocument) error {
	if diagnostic.RecordType != diagnosticRecordType {
		return fmt.Errorf("%w: diagnostic record_type %q must be %q", ErrInvalid, diagnostic.RecordType, diagnosticRecordType)
	}
	if diagnostic.SchemaVersion != diagnosticSchema {
		return fmt.Errorf("%w: diagnostic schema_version %q must be %q", ErrInvalid, diagnostic.SchemaVersion, diagnosticSchema)
	}
	if strings.TrimSpace(diagnostic.DiagnosticID) == "" {
		return fmt.Errorf("%w: diagnostic diagnostic_id is required", ErrInvalid)
	}
	if diagnostic.AnalysisRevision < 1 {
		return fmt.Errorf("%w: diagnostic analysis_revision must be positive", ErrInvalid)
	}
	if strings.TrimSpace(diagnostic.RunID) == "" {
		return fmt.Errorf("%w: diagnostic run_id is required", ErrInvalid)
	}
	if !validDigest(diagnostic.ManifestHash) {
		return fmt.Errorf("%w: diagnostic manifest_hash %q is invalid", ErrInvalid, diagnostic.ManifestHash)
	}
	if strings.TrimSpace(diagnostic.InputPrefix.JournalID) == "" || diagnostic.InputPrefix.LastSequence < 1 || !validDigest(diagnostic.InputPrefix.HeadHash) {
		return fmt.Errorf("%w: diagnostic input_prefix is invalid", ErrInvalid)
	}
	if err := validateEvidenceRefShape(diagnostic.AnalysisRequestRef, "diagnostic.analysis_request_ref"); err != nil {
		return err
	}
	if err := validateVersionPin(diagnostic.Classifier, "diagnostic.classifier"); err != nil {
		return err
	}
	if err := validateVersionPin(diagnostic.RequirementRegistry, "diagnostic.requirement_registry"); err != nil {
		return err
	}
	if diagnostic.FixRegistry == nil {
		return fmt.Errorf("%w: diagnostic fix_registry is an in-band null: use a VersionPin or Missing", ErrInvalid)
	}
	if pin, ok := asVersionPin(diagnostic.FixRegistry); ok {
		if err := validateVersionPin(pin, "diagnostic.fix_registry"); err != nil {
			return err
		}
	} else if _, ok := asMissingEnvelope(diagnostic.FixRegistry); !ok {
		return fmt.Errorf("%w: diagnostic fix_registry must be a VersionPin or Missing", ErrInvalid)
	}
	for i, ref := range diagnostic.EvidenceRefs {
		if err := validateEvidenceRefShape(ref, fmt.Sprintf("diagnostic.evidence_refs[%d]", i)); err != nil {
			return err
		}
	}
	for i, ref := range diagnostic.Artifacts {
		if err := validateArtifactRefShape(ref, fmt.Sprintf("diagnostic.artifacts[%d]", i)); err != nil {
			return err
		}
	}
	if diagnostic.Extra != nil {
		if err := rejectBareNulls(diagnostic.Extra, "$.extra"); err != nil {
			return err
		}
	}
	return nil
}

func diagnosticPinDigests(diagnostic DiagnosticDocument) ([]string, error) {
	var digests []string
	digests = append(digests, diagnostic.Classifier.ArtifactDigest, diagnostic.RequirementRegistry.ArtifactDigest)
	if pin, ok := asVersionPin(diagnostic.FixRegistry); ok {
		digests = append(digests, pin.ArtifactDigest)
	} else if _, ok := asMissingEnvelope(diagnostic.FixRegistry); !ok {
		return nil, fmt.Errorf("%w: diagnostic fix_registry must be a VersionPin or Missing", ErrInvalid)
	}
	for _, digest := range digests {
		if !validDigest(digest) {
			return nil, fmt.Errorf("%w: diagnostic pin digest %q is invalid", ErrInvalid, digest)
		}
	}
	return digests, nil
}

func receiptPinDigests(receipt ReplayReceipt) ([]string, error) {
	digests := []string{receipt.Classifier.ArtifactDigest, receipt.ReplayEngine.ArtifactDigest}
	if pin, ok := asVersionPin(receipt.Reducer); ok {
		digests = append(digests, pin.ArtifactDigest)
	}
	for _, digest := range digests {
		if !validDigest(digest) {
			return nil, fmt.Errorf("%w: receipt pin digest %q is invalid", ErrInvalid, digest)
		}
	}
	return digests, nil
}

// ---------------------------------------------------------------------------
// Small validators and canonical helpers.
// ---------------------------------------------------------------------------

func validateVersionPin(pin VersionPin, field string) error {
	if strings.TrimSpace(pin.ID) == "" {
		return fmt.Errorf("%w: %s.id is required", ErrInvalid, field)
	}
	if strings.TrimSpace(pin.Version) == "" {
		return fmt.Errorf("%w: %s.version is required", ErrInvalid, field)
	}
	if !validDigest(pin.ArtifactDigest) {
		return fmt.Errorf("%w: %s.artifact_digest %q is invalid", ErrInvalid, field, pin.ArtifactDigest)
	}
	return nil
}

func validateArtifactRefShape(ref ArtifactReference, field string) error {
	if !validDigest(ref.Digest) {
		return fmt.Errorf("%w: %s.digest %q is invalid", ErrInvalid, field, ref.Digest)
	}
	if ref.SizeBytes < 0 {
		return fmt.Errorf("%w: %s.size_bytes must not be negative", ErrInvalid, field)
	}
	if strings.TrimSpace(ref.MediaType) == "" {
		return fmt.Errorf("%w: %s.media_type is required", ErrInvalid, field)
	}
	if strings.TrimSpace(ref.OwnerDomain) == "" {
		return fmt.Errorf("%w: %s.owner_domain is required", ErrInvalid, field)
	}
	if ref.Access != accessPublic && ref.Access != accessRestricted {
		return fmt.Errorf("%w: %s.access %q must be public or restricted", ErrInvalid, field, ref.Access)
	}
	return nil
}

func validateEvidenceRefShape(ref EvidenceRef, field string) error {
	if strings.TrimSpace(ref.JournalID) == "" {
		return fmt.Errorf("%w: %s.journal_id is required", ErrInvalid, field)
	}
	if ref.Sequence < 1 {
		return fmt.Errorf("%w: %s.sequence starts at 1", ErrInvalid, field)
	}
	if strings.TrimSpace(ref.EventID) == "" {
		return fmt.Errorf("%w: %s.event_id is required", ErrInvalid, field)
	}
	if !validDigest(ref.EventHash) {
		return fmt.Errorf("%w: %s.event_hash %q is invalid", ErrInvalid, field, ref.EventHash)
	}
	if !validJSONPointer(ref.Pointer) {
		return fmt.Errorf("%w: %s.pointer %q is not a JSON pointer", ErrInvalid, field, ref.Pointer)
	}
	return nil
}

func checkEvidenceRefResolves(events []JournalEnvelope, ref EvidenceRef, field string) error {
	if err := validateEvidenceRefShape(ref, field); err != nil {
		return err
	}
	for _, event := range events {
		if event.JournalID != ref.JournalID || event.Sequence != ref.Sequence {
			continue
		}
		if event.EventID != ref.EventID {
			return fmt.Errorf("%w: %s event_id %q does not match retained event %q",
				ErrIntegrityConflict, field, ref.EventID, event.EventID)
		}
		if event.EventHash != ref.EventHash {
			return fmt.Errorf("%w: %s event_hash %q does not match retained event %q",
				ErrIntegrityConflict, field, ref.EventHash, event.EventHash)
		}
		return nil
	}
	return fmt.Errorf("%w: %s cites sequence %d outside the %d retained events",
		ErrIntegrityConflict, field, ref.Sequence, len(events))
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
	for _, c := range hexPart {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
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
			if i+1 >= len(s) || (s[i+1] != '0' && s[i+1] != '1') {
				return false
			}
			i++
		}
	}
	return true
}

func canonicalJSONValue(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("%w: marshal document: %v", ErrInvalid, err)
	}
	canonical, err := evidence_codec.CanonicalJSON(raw, mediaTypeJSON)
	if err != nil {
		return nil, fmt.Errorf("%w: canonicalize document: %v", ErrInvalid, err)
	}
	return canonical, nil
}

func canonicalDigest(value any) (string, error) {
	canonical, err := canonicalJSONValue(value)
	if err != nil {
		return "", err
	}
	return string(evidence_codec.HashBytes(canonical)), nil
}

func canonicalJournalLines(events []JournalEnvelope) ([]byte, error) {
	var buffer bytes.Buffer
	for i := range events {
		raw, err := json.Marshal(events[i])
		if err != nil {
			return nil, fmt.Errorf("%w: marshal journal event %d: %v", ErrInvalid, events[i].Sequence, err)
		}
		canonical, err := evidence_codec.CanonicalJSON(raw, mediaTypeJSON)
		if err != nil {
			return nil, fmt.Errorf("%w: canonicalize journal event %d: %v", ErrInvalid, events[i].Sequence, err)
		}
		buffer.Write(canonical)
		buffer.WriteByte('\n')
	}
	return buffer.Bytes(), nil
}

func renderDiagnosticMarkdown(diagnostic DiagnosticDocument) []byte {
	var buffer bytes.Buffer
	buffer.WriteString("# Diagnostic ")
	buffer.WriteString(diagnostic.DiagnosticID)
	buffer.WriteString("\n\n")
	buffer.WriteString("- Analysis revision: ")
	buffer.WriteString(fmt.Sprintf("%d", diagnostic.AnalysisRevision))
	buffer.WriteString("\n- Run: ")
	buffer.WriteString(diagnostic.RunID)
	buffer.WriteString("\n- Manifest: ")
	buffer.WriteString(diagnostic.ManifestHash)
	buffer.WriteString("\n- Journal: ")
	buffer.WriteString(diagnostic.InputPrefix.JournalID)
	buffer.WriteString(" through sequence ")
	buffer.WriteString(fmt.Sprintf("%d", diagnostic.InputPrefix.LastSequence))
	buffer.WriteString(" (")
	buffer.WriteString(diagnostic.InputPrefix.HeadHash)
	buffer.WriteString(")\n- Classifier: ")
	buffer.WriteString(diagnostic.Classifier.ID)
	buffer.WriteString(" ")
	buffer.WriteString(diagnostic.Classifier.Version)
	buffer.WriteString(" (")
	buffer.WriteString(diagnostic.Classifier.ArtifactDigest)
	buffer.WriteString(")\n")
	return buffer.Bytes()
}

// ---------------------------------------------------------------------------
// Artifact-identity scanning.
// ---------------------------------------------------------------------------

func artifactRefFromAny(value any) (ArtifactReference, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return ArtifactReference{}, err
	}
	var ref ArtifactReference
	if err := json.Unmarshal(raw, &ref); err != nil {
		return ArtifactReference{}, err
	}
	if !validDigest(ref.Digest) {
		return ArtifactReference{}, fmt.Errorf("invalid digest %q", ref.Digest)
	}
	if ref.SizeBytes < 0 {
		return ArtifactReference{}, fmt.Errorf("negative size")
	}
	if strings.TrimSpace(ref.MediaType) == "" || strings.TrimSpace(ref.OwnerDomain) == "" {
		return ArtifactReference{}, fmt.Errorf("incomplete identity")
	}
	if ref.Access != accessPublic && ref.Access != accessRestricted {
		return ArtifactReference{}, fmt.Errorf("invalid access %q", ref.Access)
	}
	return ref, nil
}

func looksLikeArtifactRef(node map[string]any) bool {
	digest, ok := node["digest"].(string)
	if !ok || !validDigest(digest) {
		return false
	}
	if _, ok := node["size_bytes"]; !ok {
		return false
	}
	for key := range node {
		switch key {
		case "digest", "size_bytes", "media_type", "owner_domain", "access":
		default:
			return false
		}
	}
	return true
}

func nestedArtifactRefs(value any) ([]ArtifactReference, error) {
	found := make(map[string]ArtifactReference)
	var walk func(any) error
	walk = func(node any) error {
		switch typed := node.(type) {
		case map[string]any:
			if looksLikeArtifactRef(typed) {
				ref, err := artifactRefFromAny(typed)
				if err != nil {
					return err
				}
				found[ref.Digest] = ref
			}
			for _, child := range typed {
				if err := walk(child); err != nil {
					return err
				}
			}
		case []any:
			for _, child := range typed {
				if err := walk(child); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(value); err != nil {
		return nil, err
	}
	out := make([]ArtifactReference, 0, len(found))
	for _, ref := range found {
		out = append(out, ref)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Digest < out[j].Digest })
	return out, nil
}

func nestedArtifactRefsFromValue(value any) ([]ArtifactReference, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil {
		return nil, err
	}
	normalized := normalizeNumbers(decoded)
	return nestedArtifactRefs(normalized)
}

func normalizeNumbers(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, child := range typed {
			out[key] = normalizeNumbers(child)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i, child := range typed {
			out[i] = normalizeNumbers(child)
		}
		return out
	case json.Number:
		if integer, err := typed.Int64(); err == nil {
			return float64(integer)
		}
		if floating, err := typed.Float64(); err == nil {
			return floating
		}
		return typed.String()
	default:
		return value
	}
}

func asMissingEnvelope(value any) (MissingEnvelope, bool) {
	switch node := value.(type) {
	case MissingEnvelope:
		if node.Value == nil && node.Reason != "" {
			return node, true
		}
	case *MissingEnvelope:
		if node != nil && node.Value == nil && node.Reason != "" {
			return *node, true
		}
	case map[string]any:
		raw, hasValue := node["value"]
		if !hasValue || raw != nil {
			return MissingEnvelope{}, false
		}
		reason, _ := node["reason"].(string)
		if reason == "" {
			return MissingEnvelope{}, false
		}
		detail, _ := node["detail"].(string)
		return MissingEnvelope{Value: nil, Reason: reason, Detail: detail}, true
	}
	return MissingEnvelope{}, false
}

func asVersionPin(value any) (VersionPin, bool) {
	switch node := value.(type) {
	case VersionPin:
		return node, true
	case *VersionPin:
		if node != nil {
			return *node, true
		}
	case map[string]any:
		id, _ := node["id"].(string)
		version, _ := node["version"].(string)
		digest, _ := node["artifact_digest"].(string)
		if id == "" || version == "" || digest == "" {
			return VersionPin{}, false
		}
		if len(node) > 3 {
			return VersionPin{}, false
		}
		return VersionPin{ID: id, Version: version, ArtifactDigest: digest}, true
	}
	return VersionPin{}, false
}

func rejectBareNulls(value any, path string) error {
	switch node := value.(type) {
	case nil:
		return fmt.Errorf("%w: bare null at %s: use a Missing envelope", ErrInvalid, path)
	case map[string]any:
		if raw, hasValue := node["value"]; hasValue && raw == nil {
			if _, ok := asMissingEnvelope(node); !ok {
				return fmt.Errorf("%w: malformed Missing envelope at %s", ErrInvalid, path)
			}
			return nil
		}
		for key, child := range node {
			if err := rejectBareNulls(child, path+"."+key); err != nil {
				return err
			}
		}
	case []any:
		for i, child := range node {
			if err := rejectBareNulls(child, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

func containsDigest(digests []string, target string) bool {
	for _, digest := range digests {
		if digest == target {
			return true
		}
	}
	return false
}

// Ensure io is referenced for future streaming installs.
var _ = io.EOF

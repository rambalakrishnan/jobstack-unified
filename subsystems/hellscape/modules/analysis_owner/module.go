// Package analysis_owner implements the tier-7 Hellscape diagnostic owner.
//
// The diagnostic owner derives deterministic session diagnostics from pinned
// source journal prefixes (seam-mapping 10.1), renders JSON and readable
// reports from the same object, durably installs every byte before
// registering it, and commits one atomic diagnostic transaction per analysis
// revision (seam-mapping 4.7). It never writes application, observation,
// execution, dispatch, or report source domains; it never reads mutable
// owner rows as supplementary evidence; and it never lets a storage failure
// fabricate a published report (seam-mapping 14.1).
//
// Source evidence lives in a source journal (in production, imported into
// this store before analysis). Diagnostic registrations and replay receipts
// live in a separate diagnostic-owned journal derived deterministically from
// the source journal ID, so a diagnostic's own registration event is never
// part of its analysis prefix.
//
// A diagnostic is a deterministic function of its immutable manifest, the
// named journal prefix ending at its pinned analysis_requested event, and
// the pinned classifier/requirement/fix registries (EK-DIAGNOSTIC). Late
// evidence produces a new immutable revision; earlier bytes never change;
// replay receipts advance the diagnostic domain without mutating the
// selected diagnostic (seam-mapping 10.11).
package analysis_owner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	diagnostic_reducer "diagnostic_reducer"
	rr "diagnostic_render"
	evidence_codec "evidence_codec"
	lifecycle_rules "lifecycle_rules"
	owner_store "owner_store"
	publication "publication"
)

// ---------------------------------------------------------------------------
// Shared types.
// ---------------------------------------------------------------------------

type (
	// OwnerStore is the owner-local durable boundary (one SQLite database
	// plus one content-addressed artifact root).
	OwnerStore = owner_store.OwnerStore
	// Manifest is the admitted laboratory manifest projection.
	Manifest = diagnostic_reducer.Manifest
	// AnalysisRequest pins one diagnostic revision's inputs.
	AnalysisRequest = diagnostic_reducer.AnalysisRequest
	// DiagnosticDocument is the deterministic analysis output.
	DiagnosticDocument = diagnostic_reducer.DiagnosticDocument
	// JournalEnvelope is the complete stored journal event envelope.
	JournalEnvelope = owner_store.JournalEnvelope
	// JournalPrefix is an immutable journal prefix.
	JournalPrefix = owner_store.JournalPrefix
	// EvidenceRef cites one retained journal event coordinate.
	EvidenceRef = owner_store.EvidenceRef
	// ArtifactReference is an immutable byte identity plus metadata.
	ArtifactReference = owner_store.ArtifactReference
	// EventSubmission is the untrusted ingress shape (no authority fields).
	EventSubmission = owner_store.EventSubmission
	// VersionPin pins an immutable versioned artifact.
	VersionPin = diagnostic_reducer.VersionPin
	// ClockDescriptor registers one clock lifetime.
	ClockDescriptor = diagnostic_reducer.ClockDescriptor
	// SubjectIdentity pins the judged automation subject scope.
	SubjectIdentity = diagnostic_reducer.SubjectIdentity
	// AttemptContext describes the laboratory attempt context.
	AttemptContext = diagnostic_reducer.AttemptContext
	// SubjectDescriptor identifies the measured subject and version.
	SubjectDescriptor = diagnostic_reducer.SubjectDescriptor
	// LineageLinks carries kind and lineage references.
	LineageLinks = diagnostic_reducer.LineageLinks
	// Measurement is the EK Measurement record carried in payloads.
	Measurement = owner_store.Measurement
)

// Compile-time CONSUMES linkage. These references fail compilation if the
// declared upstream signatures disappear.
// DeriveDiagnostic, RenderDiagnostic, CommitOwner, LoadPrefix,
// InstallArtifact, and HashBytes are called on the analysis path below.
// ReconcileAttempt executes inside DeriveDiagnostic over the exact pinned
// prefix (single-flight; this owner never evaluates it twice over
// different inputs). SealRow installs read views, which is a reader-side
// step after the diagnostic transaction commits, not part of atomic
// analysis — hence linkage without a call.
var (
	_ = diagnostic_reducer.DeriveDiagnostic
	_ = rr.RenderDiagnostic
	_ = publication.SealRow
	_ = owner_store.CommitOwner
	_ = owner_store.LoadPrefix
	_ = owner_store.InstallArtifact
	_ = lifecycle_rules.ReconcileAttempt
	_ = evidence_codec.HashBytes
)

// Sentinel errors.
var (
	// ErrInvalid marks malformed caller input or an unreadable stored record.
	ErrInvalid = errors.New("analysis_owner: invalid input")
	// ErrUnknownSource marks a source journal with no recorded head. Source
	// events must be committed via AppendSourceEvents so the owner tracks
	// the imported head; the owner never scans a peer database.
	ErrUnknownSource = errors.New("analysis_owner: unknown source journal")
	// ErrUnknownDiagnostic marks a diagnostic revision with no registration.
	ErrUnknownDiagnostic = errors.New("analysis_owner: unknown diagnostic revision")
)

// Diagnostic-owned journal event kinds and record identity.
const (
	// eventDiagnosticRegistered records one completed diagnostic revision:
	// already installed diagnostic/report bytes, the exact input pins, and
	// the resulting artifact references.
	eventDiagnosticRegistered = "diagnostic_registered"
	// eventReplayReceipt records one replay receipt against a registered
	// diagnostic revision without touching its bytes.
	eventReplayReceipt = "replay_receipt"

	// diagnosticJournalPrefix derives the diagnostic-owned journal ID from
	// the source journal ID. The two journals never share an ID, so a
	// diagnostic's own registration is never inside its analysis prefix.
	diagnosticJournalPrefix = "diagnostic-"

	// recordDiagnosticValue is the SessionDiagnosticValue record identity.
	recordDiagnosticValue = "session_diagnostic"
	// schemaDiagnosticValue is its schema version.
	schemaDiagnosticValue = "1.0.0"

	// eventSchemaVersion is the diagnostic journal event document version.
	eventSchemaVersion = "1.0.0"

	// mediaJSON and mediaMarkdown label installed diagnostic/report bytes.
	mediaJSON     = "application/json"
	mediaMarkdown = "text/markdown"
	// accessRestricted classifies diagnostic bytes (EK-ARTIFACTS).
	accessRestricted = "restricted"
	// accessPublic classifies the diagnostic journal manifest.
	accessPublic = "public"
)

// ---------------------------------------------------------------------------
// Head registry.
// ---------------------------------------------------------------------------

// The owner tracks source journal heads as import receipts and
// diagnostic-owned heads from its own commits. Production source heads
// arrive via the import outbox; the conformance harness records them via
// AppendSourceEvents. Heads are content pins (sequence plus head hash), so
// every LoadPrefix below revalidates the chain against the recorded pin.
var (
	registryMu      sync.Mutex
	sourceHeads     = map[string]JournalPrefix{}
	diagnosticHeads = map[string]JournalPrefix{}
)

func registryKey(store *OwnerStore, journalID string) string {
	return fmt.Sprintf("%p\x00%s", store, journalID)
}

func recordSourceHead(store *OwnerStore, head JournalPrefix) {
	registryMu.Lock()
	defer registryMu.Unlock()
	sourceHeads[registryKey(store, head.JournalID)] = head
}

func recordedSourceHead(store *OwnerStore, journalID string) (JournalPrefix, bool) {
	registryMu.Lock()
	defer registryMu.Unlock()
	head, ok := sourceHeads[registryKey(store, journalID)]
	return head, ok
}

func recordDiagnosticHead(store *OwnerStore, head JournalPrefix) {
	registryMu.Lock()
	defer registryMu.Unlock()
	diagnosticHeads[registryKey(store, head.JournalID)] = head
}

func recordedDiagnosticHead(store *OwnerStore, journalID string) (JournalPrefix, bool) {
	registryMu.Lock()
	defer registryMu.Unlock()
	head, ok := diagnosticHeads[registryKey(store, journalID)]
	return head, ok
}

// DiagnosticJournalID derives the diagnostic-owned journal ID for a source
// manifest. It is deterministic: one source journal maps to exactly one
// diagnostic journal.
func DiagnosticJournalID(manifest Manifest) string {
	return diagnosticJournalPrefix + manifest.JournalID
}

// DiagnosticHead returns the recorded head of the diagnostic-owned journal
// for a source manifest, if this owner has committed to it.
func DiagnosticHead(store *OwnerStore, manifest Manifest) (JournalPrefix, bool) {
	if store == nil {
		return JournalPrefix{}, false
	}
	return recordedDiagnosticHead(store, DiagnosticJournalID(manifest))
}

// ---------------------------------------------------------------------------
// Session diagnostic domain value.
// ---------------------------------------------------------------------------

// ReplayReceipt records one replay observation against a registered
// diagnostic revision. Receipts accumulate on the diagnostic domain value;
// they never modify the selected diagnostic's bytes (seam-mapping 10.11).
type ReplayReceipt struct {
	ReceiptID            string     `json:"receipt_id"`
	DiagnosticID         string     `json:"diagnostic_id"`
	AnalysisRevision     int64      `json:"analysis_revision"`
	ReplayDigest         string     `json:"replay_digest"`
	Detail               string     `json:"detail,omitempty"`
	RegistrationSequence int64      `json:"registration_sequence"`
	EvidenceRef          EvidenceRef `json:"evidence_ref"`
}

// SessionDiagnosticValue is the diagnostic domain's citable value for one
// registered revision: the diagnostic identity, its installed artifacts,
// its exact input pins, and its accumulated replay receipts.
type SessionDiagnosticValue struct {
	RecordType           string             `json:"record_type"`
	SchemaVersion        string             `json:"schema_version"`
	DiagnosticID         string             `json:"diagnostic_id"`
	AnalysisRevision     int64              `json:"analysis_revision"`
	DiagnosticArtifact   ArtifactReference  `json:"diagnostic_artifact"`
	ReportJSONArtifact   ArtifactReference  `json:"report_json_artifact"`
	ReadableArtifact     ArtifactReference  `json:"readable_artifact"`
	DiagnosticDigest     string             `json:"diagnostic_digest"`
	InputPrefix          JournalPrefix      `json:"input_prefix"`
	AnalysisRequestRef   EvidenceRef        `json:"analysis_request_ref"`
	Classifier           VersionPin         `json:"classifier"`
	RequirementRegistry  VersionPin         `json:"requirement_registry"`
	FixRegistry          any                `json:"fix_registry"`
	ReportInputs         any                `json:"report_inputs"`
	ReplayReceipts       []ReplayReceipt    `json:"replay_receipts"`
	RegistrationSequence int64              `json:"registration_sequence"`
	RegistrationRef      EvidenceRef        `json:"registration_ref"`
}

// ---------------------------------------------------------------------------
// Source ingest (harness import receipt).
// ---------------------------------------------------------------------------

// AppendSourceEvents commits source-journal events and records the resulting
// head as this owner's import receipt for the journal. Production source
// prefixes arrive through the import outbox before analysis; the
// conformance harness commits them here so AnalyzeSession can resolve the
// pinned prefix without scanning a peer database. It returns the committed
// envelopes.
func AppendSourceEvents(ctx context.Context, store *OwnerStore, journalID string, submissions []EventSubmission) ([]JournalEnvelope, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: store is required", ErrInvalid)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(journalID) == "" {
		return nil, fmt.Errorf("%w: journal_id is required", ErrInvalid)
	}
	if len(submissions) == 0 {
		return nil, fmt.Errorf("%w: at least one event submission is required", ErrInvalid)
	}
	envelopes, err := owner_store.CommitOwner(ctx, store, journalID, submissions, nil)
	if err != nil {
		return nil, fmt.Errorf("analysis_owner: commit source events: %w", err)
	}
	if len(envelopes) == 0 {
		return nil, fmt.Errorf("%w: commit returned no envelopes", ErrInvalid)
	}
	last := envelopes[len(envelopes)-1]
	recordSourceHead(store, JournalPrefix{JournalID: last.JournalID, LastSequence: last.Sequence, HeadHash: last.EventHash})
	return envelopes, nil
}

// ---------------------------------------------------------------------------
// AnalyzeSession.
// ---------------------------------------------------------------------------

// AnalyzeSession derives, renders, installs, and registers one diagnostic
// revision.
//
// It resolves the recorded source head, selects the journal prefix ending
// at the analysis_requested event pinned by the request (the head may lie
// beyond it when late evidence has arrived), derives the diagnostic
// deterministically from the manifest, prefix, retained events, and pinned
// registries, renders JSON and readable reports from the same object,
// installs all bytes before registering them, and atomically commits one
// diagnostic_registered event recording the exact input pins.
//
// Any failure before the commit leaves no registration behind: installed
// but unregistered bytes are orphans eligible for safe GC, and no report
// is fabricated (seam-mapping 14.1). Retrying with identical inputs
// replays the commit receipt instead of duplicating the registration.
func AnalyzeSession(ctx context.Context, store *OwnerStore, manifest Manifest, request AnalysisRequest) (DiagnosticDocument, error) {
	empty := DiagnosticDocument{}
	if store == nil {
		return empty, fmt.Errorf("%w: store is required", ErrInvalid)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if strings.TrimSpace(manifest.JournalID) == "" || strings.TrimSpace(manifest.RunID) == "" {
		return empty, fmt.Errorf("%w: manifest must name journal_id and run_id", ErrInvalid)
	}
	if strings.TrimSpace(request.DiagnosticID) == "" {
		return empty, fmt.Errorf("%w: diagnostic_id is required", ErrInvalid)
	}
	if request.AnalysisRevision < 1 {
		return empty, fmt.Errorf("%w: analysis_revision starts at 1", ErrInvalid)
	}

	// Resolve the recorded source head. The owner never scans for heads:
	// the pin arrives via the import receipt (AppendSourceEvents).
	head, ok := recordedSourceHead(store, manifest.JournalID)
	if !ok {
		return empty, fmt.Errorf("%w: journal %q has no recorded head; commit source events via AppendSourceEvents",
			ErrUnknownSource, manifest.JournalID)
	}
	headEvents, err := owner_store.LoadPrefix(ctx, store, head)
	if err != nil {
		return empty, fmt.Errorf("analysis_owner: load source head: %w", err)
	}

	// Select the prefix ending at the pinned analysis_requested event. The
	// journal head may lie beyond it; late evidence never moves this pin.
	requestEvent, err := selectAnalysisRequest(headEvents, request.DiagnosticID, request.AnalysisRevision)
	if err != nil {
		return empty, err
	}
	pinned := JournalPrefix{
		JournalID:    requestEvent.JournalID,
		LastSequence: requestEvent.Sequence,
		HeadHash:     requestEvent.EventHash,
	}
	if pinned.JournalID != manifest.JournalID {
		return empty, fmt.Errorf("%w: pinned prefix journal %q does not match manifest journal %q",
			ErrInvalid, pinned.JournalID, manifest.JournalID)
	}
	// Reload the exact pinned prefix so the chain, head hash, and manifest
	// pin are revalidated against retained events.
	pinnedEvents, err := owner_store.LoadPrefix(ctx, store, pinned)
	if err != nil {
		return empty, fmt.Errorf("analysis_owner: load pinned prefix: %w", err)
	}
	if len(pinnedEvents) == 0 || pinnedEvents[len(pinnedEvents)-1].EventKind != "analysis_requested" {
		return empty, fmt.Errorf("%w: pinned prefix does not end at analysis_requested", ErrInvalid)
	}

	// Derive deterministically. No writes have happened yet, so a
	// derivation failure leaves no trace.
	document, err := diagnostic_reducer.DeriveDiagnostic(manifest, pinned, pinnedEvents, request)
	if err != nil {
		return empty, fmt.Errorf("analysis_owner: derive diagnostic: %w", err)
	}

	// Canonical diagnostic bytes (the authoritative derivation output).
	raw, err := json.Marshal(document)
	if err != nil {
		return empty, fmt.Errorf("analysis_owner: encode diagnostic: %w", err)
	}
	diagnosticJSON, err := evidence_codec.CanonicalJSON(raw, mediaJSON)
	if err != nil {
		return empty, fmt.Errorf("analysis_owner: canonicalize diagnostic: %w", err)
	}

	// Render JSON and readable reports from the same projected object.
	reportJSON, readable, err := rr.RenderDiagnostic(toRenderDocument(document))
	if err != nil {
		return empty, fmt.Errorf("analysis_owner: render diagnostic: %w", err)
	}

	// Install every byte before registering any of it. A failure here
	// commits nothing; partial bytes stay unregistered.
	diagnosticRef, err := owner_store.InstallArtifact(ctx, store, bytes.NewReader(diagnosticJSON), mediaJSON, accessRestricted)
	if err != nil {
		return empty, fmt.Errorf("analysis_owner: install diagnostic bytes: %w", err)
	}
	reportRef, err := owner_store.InstallArtifact(ctx, store, bytes.NewReader(reportJSON), mediaJSON, accessRestricted)
	if err != nil {
		return empty, fmt.Errorf("analysis_owner: install report bytes: %w", err)
	}
	readableRef, err := owner_store.InstallArtifact(ctx, store, bytes.NewReader(readable), mediaMarkdown, accessRestricted)
	if err != nil {
		return empty, fmt.Errorf("analysis_owner: install readable report: %w", err)
	}
	// Integrity: installed identities must match the content hashes.
	if string(evidence_codec.HashBytes(diagnosticJSON)) != diagnosticRef.Digest {
		return empty, fmt.Errorf("%w: installed diagnostic digest does not match its bytes", ErrInvalid)
	}
	if string(evidence_codec.HashBytes(reportJSON)) != reportRef.Digest {
		return empty, fmt.Errorf("%w: installed report digest does not match its bytes", ErrInvalid)
	}

	// Atomically register the installed bytes, the exact input pins, and
	// the diagnostic-owned revision advance.
	if err := commitRegistration(ctx, store, manifest, request, pinned, requestEvent, document, diagnosticRef, reportRef, readableRef); err != nil {
		return empty, err
	}
	return document, nil
}

// selectAnalysisRequest finds the single analysis_requested event pinning a
// diagnostic revision. Duplicates are rejected: one revision has exactly
// one pin.
func selectAnalysisRequest(events []JournalEnvelope, diagnosticID string, revision int64) (JournalEnvelope, error) {
	var zero JournalEnvelope
	var matches []JournalEnvelope
	for _, env := range events {
		if env.EventKind != "analysis_requested" {
			continue
		}
		if env.Payload.Data == nil {
			continue
		}
		id, _ := env.Payload.Data["diagnostic_id"].(string)
		rev, ok := numberAsInt64(env.Payload.Data["analysis_revision"])
		if !ok || id != diagnosticID || rev != revision {
			continue
		}
		matches = append(matches, env)
	}
	if len(matches) == 0 {
		return zero, fmt.Errorf("%w: no analysis_requested pins diagnostic %q revision %d in the recorded prefix",
			ErrInvalid, diagnosticID, revision)
	}
	if len(matches) > 1 {
		return zero, fmt.Errorf("%w: %d analysis_requested events pin diagnostic %q revision %d: one revision has exactly one pin",
			ErrInvalid, len(matches), diagnosticID, revision)
	}
	return matches[0], nil
}

// commitRegistration appends one diagnostic_registered event to the
// diagnostic-owned journal, admitting that journal on first use. Admission
// and registration commit as separate steps (as in evidence_import), each
// with deterministic content: a retry after a lost response replays the
// commit receipt instead of duplicating events.
func commitRegistration(ctx context.Context, store *OwnerStore, manifest Manifest, request AnalysisRequest, pinned JournalPrefix, requestEvent JournalEnvelope, document DiagnosticDocument, diagnosticRef, reportRef, readableRef ArtifactReference) error {
	diagnosticJournalID := DiagnosticJournalID(manifest)
	data, err := registrationData(request, pinned, requestEvent, document, diagnosticRef, reportRef, readableRef)
	if err != nil {
		return err
	}
	registration := EventSubmission{
		ProducerSequence:   owner_store.NewMissing("not_applicable"),
		EventKind:          eventDiagnosticRegistered,
		EventSchemaVersion: eventSchemaVersion,
		OccurredAt:         owner_store.NewMissing("not_observed"),
		Payload: owner_store.Payload{
			Data:         data,
			Measurements: []owner_store.Measurement{},
			EvidenceRefs: []EvidenceRef{},
			ArtifactRefs: []ArtifactReference{diagnosticRef, reportRef, readableRef},
		},
	}
	if _, ok := recordedDiagnosticHead(store, diagnosticJournalID); !ok {
		if err := ensureDiagnosticJournal(ctx, store, manifest, diagnosticJournalID, diagnosticRef.OwnerDomain); err != nil {
			return err
		}
	}
	envelopes, err := owner_store.CommitOwner(ctx, store, diagnosticJournalID, []EventSubmission{registration}, nil)
	if err != nil {
		return fmt.Errorf("analysis_owner: commit diagnostic registration: %w", err)
	}
	return recordCommitHead(store, envelopes)
}

// ensureDiagnosticJournal admits the diagnostic-owned journal. The local
// manifest pins its own journal ID with the store's owner domain, learned
// from the installed diagnostic bytes (as in evidence_import): same run
// and clocks as the source, but a distinct complete manifest.
func ensureDiagnosticJournal(ctx context.Context, store *OwnerStore, manifest Manifest, diagnosticJournalID, storeOwner string) error {
	storeOwner = strings.TrimSpace(storeOwner)
	if storeOwner == "" {
		return fmt.Errorf("%w: installed diagnostic names no owner domain", ErrInvalid)
	}
	clocks := append([]owner_store.ClockDescriptor(nil), manifest.Clocks...)
	if len(clocks) == 0 {
		return fmt.Errorf("%w: manifest registers no clocks for the diagnostic journal", ErrInvalid)
	}
	diagnosticManifest := owner_store.Manifest{
		RecordType:    "manifest",
		SchemaVersion: manifest.SchemaVersion,
		ManifestID:    "manifest-" + diagnosticJournalID,
		RunID:         manifest.RunID,
		JournalID:     diagnosticJournalID,
		OwnerDomain:   storeOwner,
		Clocks:        clocks,
	}
	manifestRaw, err := json.Marshal(diagnosticManifest)
	if err != nil {
		return fmt.Errorf("analysis_owner: encode diagnostic manifest: %w", err)
	}
	manifestCanonical, err := evidence_codec.CanonicalJSON(manifestRaw, mediaJSON)
	if err != nil {
		return fmt.Errorf("analysis_owner: canonicalize diagnostic manifest: %w", err)
	}
	manifestRef, err := owner_store.InstallArtifact(ctx, store, bytes.NewReader(manifestCanonical), mediaJSON, accessPublic)
	if err != nil {
		return fmt.Errorf("analysis_owner: install diagnostic manifest: %w", err)
	}
	admission := EventSubmission{
		ProducerSequence:   owner_store.NewMissing("not_applicable"),
		EventKind:          "manifest_admitted",
		EventSchemaVersion: eventSchemaVersion,
		OccurredAt:         owner_store.NewMissing("not_observed"),
		Payload: owner_store.Payload{
			Data:         map[string]any{"manifest": artifactRefMap(manifestRef)},
			Measurements: []owner_store.Measurement{},
			EvidenceRefs: []EvidenceRef{},
			ArtifactRefs: []ArtifactReference{manifestRef},
		},
	}
	envelopes, err := owner_store.CommitOwner(ctx, store, diagnosticJournalID, []EventSubmission{admission}, nil)
	if err != nil {
		// A lost head after a restart lands here: the journal already
		// exists, so the registration step proceeds (as in
		// evidence_import).
		if !strings.Contains(err.Error(), "manifest_admitted appears only at sequence 1") {
			return fmt.Errorf("analysis_owner: admit diagnostic journal: %w", err)
		}
		return nil
	}
	return recordCommitHead(store, envelopes)
}

// registrationData builds the diagnostic_registered payload. Cross-journal
// coordinates ride as flat scalars, never as embedded EvidenceRef objects:
// journal validation requires every embedded ref to cite the same journal,
// so source pins are recorded by value (as in evidence_import).
func registrationData(request AnalysisRequest, pinned JournalPrefix, requestEvent JournalEnvelope, document DiagnosticDocument, diagnosticRef, reportRef, readableRef ArtifactReference) (map[string]any, error) {
	fixRegistry, err := jsonRoundTrip(request.FixRegistry)
	if err != nil {
		return nil, fmt.Errorf("%w: fix_registry is not JSON: %v", ErrInvalid, err)
	}
	reportInputs := any(owner_store.NewMissing("not_observed"))
	if request.ReportInputs != nil {
		pins, err := jsonRoundTrip(request.ReportInputs)
		if err != nil {
			return nil, fmt.Errorf("%w: report inputs are not JSON: %v", ErrInvalid, err)
		}
		reportInputs = pins
	}
	return map[string]any{
		"diagnostic_id":                 request.DiagnosticID,
		"analysis_revision":             request.AnalysisRevision,
		"diagnostic_artifact":           artifactRefMap(diagnosticRef),
		"report_json_artifact":          artifactRefMap(reportRef),
		"readable_artifact":             artifactRefMap(readableRef),
		"diagnostic_digest":             diagnosticRef.Digest,
		"input_prefix_journal_id":       pinned.JournalID,
		"input_prefix_last_sequence":    pinned.LastSequence,
		"input_prefix_head_hash":        pinned.HeadHash,
		"analysis_request_journal_id":   requestEvent.JournalID,
		"analysis_request_sequence":     requestEvent.Sequence,
		"analysis_request_event_id":     requestEvent.EventID,
		"analysis_request_event_hash":   requestEvent.EventHash,
		"analysis_request_pointer":      "",
		"classifier_id":                 document.Classifier.ID,
		"classifier_version":            document.Classifier.Version,
		"classifier_digest":             document.Classifier.ArtifactDigest,
		"requirement_registry_id":       document.RequirementRegistry.ID,
		"requirement_registry_version":  document.RequirementRegistry.Version,
		"requirement_registry_digest":   document.RequirementRegistry.ArtifactDigest,
		"fix_registry":                  fixRegistry,
		"report_inputs":                 reportInputs,
	}, nil
}

func recordCommitHead(store *OwnerStore, envelopes []JournalEnvelope) error {
	if len(envelopes) == 0 {
		return fmt.Errorf("%w: commit returned no envelopes", ErrInvalid)
	}
	last := envelopes[len(envelopes)-1]
	recordDiagnosticHead(store, JournalPrefix{JournalID: last.JournalID, LastSequence: last.Sequence, HeadHash: last.EventHash})
	return nil
}

// ---------------------------------------------------------------------------
// Diagnostic domain reads and replay receipts.
// ---------------------------------------------------------------------------

// LoadSessionDiagnostic reads the diagnostic domain value for one registered
// revision: the installed artifact identities, the exact input pins, and
// every replay receipt recorded against it, in journal order.
func LoadSessionDiagnostic(ctx context.Context, store *OwnerStore, manifest Manifest, diagnosticID string, revision int64) (SessionDiagnosticValue, error) {
	var zero SessionDiagnosticValue
	if store == nil {
		return zero, fmt.Errorf("%w: store is required", ErrInvalid)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	if strings.TrimSpace(diagnosticID) == "" || revision < 1 {
		return zero, fmt.Errorf("%w: diagnostic_id and a positive revision are required", ErrInvalid)
	}
	head, ok := recordedDiagnosticHead(store, DiagnosticJournalID(manifest))
	if !ok {
		return zero, fmt.Errorf("%w: diagnostic %q has no recorded journal; run AnalyzeSession first",
			ErrUnknownDiagnostic, diagnosticID)
	}
	events, err := owner_store.LoadPrefix(ctx, store, head)
	if err != nil {
		return zero, fmt.Errorf("analysis_owner: load diagnostic journal: %w", err)
	}
	var registration *JournalEnvelope
	for i := range events {
		env := &events[i]
		if env.EventKind != eventDiagnosticRegistered || env.Payload.Data == nil {
			continue
		}
		id, _ := env.Payload.Data["diagnostic_id"].(string)
		rev, ok := numberAsInt64(env.Payload.Data["analysis_revision"])
		if !ok || id != diagnosticID || rev != revision {
			continue
		}
		if registration != nil {
			return zero, fmt.Errorf("%w: duplicate registration for diagnostic %q revision %d",
				ErrInvalid, diagnosticID, revision)
		}
		registration = env
	}
	if registration == nil {
		return zero, fmt.Errorf("%w: diagnostic %q revision %d is not registered",
			ErrUnknownDiagnostic, diagnosticID, revision)
	}
	value, err := diagnosticValueFromRegistration(registration)
	if err != nil {
		return zero, err
	}
	for i := range events {
		env := &events[i]
		if env.EventKind != eventReplayReceipt || env.Payload.Data == nil {
			continue
		}
		id, _ := env.Payload.Data["diagnostic_id"].(string)
		rev, ok := numberAsInt64(env.Payload.Data["analysis_revision"])
		if !ok || id != diagnosticID || rev != revision {
			continue
		}
		receipt, err := replayReceiptFromEvent(env)
		if err != nil {
			return zero, err
		}
		value.ReplayReceipts = append(value.ReplayReceipts, receipt)
	}
	if value.ReplayReceipts == nil {
		value.ReplayReceipts = []ReplayReceipt{}
	}
	return value, nil
}

// AttachReplayReceipt records one replay receipt against a registered
// diagnostic revision and returns the updated domain value. The selected
// diagnostic's bytes are untouched: the receipt advances only the domain
// value's receipt list. Receipts against unknown revisions are rejected,
// and byte-identical retries replay the commit receipt.
func AttachReplayReceipt(ctx context.Context, store *OwnerStore, manifest Manifest, diagnosticID string, revision int64, replayDigest string, detail string) (SessionDiagnosticValue, error) {
	var zero SessionDiagnosticValue
	if store == nil {
		return zero, fmt.Errorf("%w: store is required", ErrInvalid)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	if !validDigest(replayDigest) {
		return zero, fmt.Errorf("%w: replay_digest %q is not a valid digest", ErrInvalid, replayDigest)
	}
	current, err := LoadSessionDiagnostic(ctx, store, manifest, diagnosticID, revision)
	if err != nil {
		return zero, err
	}
	receiptID := replayReceiptID(diagnosticID, revision, replayDigest, detail)
	submission := EventSubmission{
		ProducerSequence:   owner_store.NewMissing("not_applicable"),
		EventKind:          eventReplayReceipt,
		EventSchemaVersion: eventSchemaVersion,
		OccurredAt:         owner_store.NewMissing("not_observed"),
		Payload: owner_store.Payload{
			Data: map[string]any{
				"receipt_id":            receiptID,
				"diagnostic_id":         diagnosticID,
				"analysis_revision":     revision,
				"replay_digest":         replayDigest,
				"detail":                detail,
				"registration_sequence": current.RegistrationSequence,
			},
			Measurements: []owner_store.Measurement{},
			EvidenceRefs: []EvidenceRef{},
			ArtifactRefs: []ArtifactReference{},
		},
	}
	envelopes, err := owner_store.CommitOwner(ctx, store, DiagnosticJournalID(manifest), []EventSubmission{submission}, nil)
	if err != nil {
		return zero, fmt.Errorf("analysis_owner: commit replay receipt: %w", err)
	}
	if err := recordCommitHead(store, envelopes); err != nil {
		return zero, err
	}
	return LoadSessionDiagnostic(ctx, store, manifest, diagnosticID, revision)
}

// replayReceiptID derives a deterministic receipt identity from the receipt
// content, so byte-identical retries replay instead of duplicating.
func replayReceiptID(diagnosticID string, revision int64, replayDigest, detail string) string {
	core := fmt.Sprintf("%s\x00%d\x00%s\x00%s", diagnosticID, revision, replayDigest, detail)
	digest := string(evidence_codec.HashBytes([]byte(core)))
	hexPart := strings.TrimPrefix(digest, "sha256:")
	if len(hexPart) > 16 {
		hexPart = hexPart[:16]
	}
	return "replay-" + hexPart
}

func diagnosticValueFromRegistration(env *JournalEnvelope) (SessionDiagnosticValue, error) {
	var zero SessionDiagnosticValue
	data := env.Payload.Data
	id, _ := data["diagnostic_id"].(string)
	rev, ok := numberAsInt64(data["analysis_revision"])
	if id == "" || !ok {
		return zero, fmt.Errorf("%w: stored registration names no diagnostic revision", ErrInvalid)
	}
	diagnosticRef, err := artifactRefFromValue(data["diagnostic_artifact"])
	if err != nil {
		return zero, fmt.Errorf("%w: stored diagnostic artifact: %v", ErrInvalid, err)
	}
	reportRef, err := artifactRefFromValue(data["report_json_artifact"])
	if err != nil {
		return zero, fmt.Errorf("%w: stored report artifact: %v", ErrInvalid, err)
	}
	readableRef, err := artifactRefFromValue(data["readable_artifact"])
	if err != nil {
		return zero, fmt.Errorf("%w: stored readable artifact: %v", ErrInvalid, err)
	}
	prefixSeq, ok := numberAsInt64(data["input_prefix_last_sequence"])
	if !ok {
		return zero, fmt.Errorf("%w: stored input prefix has no last_sequence", ErrInvalid)
	}
	requestSeq, ok := numberAsInt64(data["analysis_request_sequence"])
	if !ok {
		return zero, fmt.Errorf("%w: stored analysis request has no sequence", ErrInvalid)
	}
	prefixJournal, _ := data["input_prefix_journal_id"].(string)
	prefixHash, _ := data["input_prefix_head_hash"].(string)
	requestJournal, _ := data["analysis_request_journal_id"].(string)
	requestID, _ := data["analysis_request_event_id"].(string)
	requestHash, _ := data["analysis_request_event_hash"].(string)
	requestPointer, _ := data["analysis_request_pointer"].(string)
	if prefixJournal == "" || !validDigest(prefixHash) || requestJournal == "" || requestID == "" || !validDigest(requestHash) {
		return zero, fmt.Errorf("%w: stored input pins are incomplete", ErrInvalid)
	}
	classifierID, _ := data["classifier_id"].(string)
	classifierVersion, _ := data["classifier_version"].(string)
	classifierDigest, _ := data["classifier_digest"].(string)
	registryID, _ := data["requirement_registry_id"].(string)
	registryVersion, _ := data["requirement_registry_version"].(string)
	registryDigest, _ := data["requirement_registry_digest"].(string)
	if classifierID == "" || registryID == "" {
		return zero, fmt.Errorf("%w: stored registry pins are incomplete", ErrInvalid)
	}
	digest, _ := data["diagnostic_digest"].(string)
	if digest == "" {
		digest = diagnosticRef.Digest
	}
	return SessionDiagnosticValue{
		RecordType:         recordDiagnosticValue,
		SchemaVersion:      schemaDiagnosticValue,
		DiagnosticID:       id,
		AnalysisRevision:   rev,
		DiagnosticArtifact: diagnosticRef,
		ReportJSONArtifact: reportRef,
		ReadableArtifact:   readableRef,
		DiagnosticDigest:   digest,
		InputPrefix: JournalPrefix{
			JournalID:    prefixJournal,
			LastSequence: prefixSeq,
			HeadHash:     prefixHash,
		},
		AnalysisRequestRef: EvidenceRef{
			JournalID: requestJournal,
			Sequence:  requestSeq,
			EventID:   requestID,
			EventHash: requestHash,
			Pointer:   requestPointer,
		},
		Classifier:           VersionPin{ID: classifierID, Version: classifierVersion, ArtifactDigest: classifierDigest},
		RequirementRegistry:  VersionPin{ID: registryID, Version: registryVersion, ArtifactDigest: registryDigest},
		FixRegistry:          data["fix_registry"],
		ReportInputs:         data["report_inputs"],
		ReplayReceipts:       []ReplayReceipt{},
		RegistrationSequence: env.Sequence,
		RegistrationRef: EvidenceRef{
			JournalID: env.JournalID,
			Sequence:  env.Sequence,
			EventID:   env.EventID,
			EventHash: env.EventHash,
			Pointer:   "",
		},
	}, nil
}

func replayReceiptFromEvent(env *JournalEnvelope) (ReplayReceipt, error) {
	var zero ReplayReceipt
	data := env.Payload.Data
	id, _ := data["receipt_id"].(string)
	diagnosticID, _ := data["diagnostic_id"].(string)
	rev, ok := numberAsInt64(data["analysis_revision"])
	digest, _ := data["replay_digest"].(string)
	detail, _ := data["detail"].(string)
	regSeq, regOK := numberAsInt64(data["registration_sequence"])
	if id == "" || diagnosticID == "" || !ok || !validDigest(digest) || !regOK {
		return zero, fmt.Errorf("%w: stored replay receipt is incomplete", ErrInvalid)
	}
	return ReplayReceipt{
		ReceiptID:        id,
		DiagnosticID:     diagnosticID,
		AnalysisRevision: rev,
		ReplayDigest:     digest,
		Detail:           detail,
		RegistrationSequence: regSeq,
		EvidenceRef: EvidenceRef{
			JournalID: env.JournalID,
			Sequence:  env.Sequence,
			EventID:   env.EventID,
			EventHash: env.EventHash,
			Pointer:   "",
		},
	}, nil
}

// ---------------------------------------------------------------------------
// Reducer-to-render projection.
// ---------------------------------------------------------------------------

// toRenderDocument projects the authoritative derivation output onto the
// render record shape so JSON and readable reports describe the same
// object (seam-mapping 10.1 stage 7). Fields the derivation does not join
// carry reasoned Missing envelopes or established-empty collections; no
// bare null survives, and no overall attempt verdict is added.
func toRenderDocument(document DiagnosticDocument) rr.DiagnosticDocument {
	exposures, exposureNotes := convertFeatureExposures(document.FeatureExposures)
	limitations := append([]string{}, document.Validity.Limitations...)
	limitations = append(limitations, exposureNotes...)
	return rr.DiagnosticDocument{
		RecordType:            rr.RecordType,
		SchemaVersion:         rr.SchemaVersion,
		DiagnosticID:          document.DiagnosticID,
		AnalysisRevision:      int(document.AnalysisRevision),
		RunID:                 document.RunID,
		ManifestHash:          document.ManifestHash,
		InputPrefix:           convertPrefix(document.InputPrefix),
		AnalysisRequestRef:    convertEvidenceRef(document.AnalysisRequestRef),
		Classifier:            convertVersionPin(document.Classifier),
		RequirementRegistry:   convertVersionPin(document.RequirementRegistry),
		FixRegistry:           document.FixRegistry,
		Attempt:               rr.Missing{Reason: "not_applicable", Detail: "attempt commissioning is admission metadata; this diagnostic cites run and manifest"},
		Execution:             convertExecution(document),
		DeliveredTaskHash:     rr.Missing{Reason: "not_observed", Detail: "no delivered-task hash was joined into this diagnostic"},
		NativeRequestHash:     rr.Missing{Reason: "not_observed", Detail: "no native-request hash was joined into this diagnostic"},
		Validity:              convertValidity(document, limitations),
		CapabilityDescriptors: []rr.ArtifactSlot{},
		RequirementAssessments: convertAssessments(document.RequirementAssessments),
		ObservedActions:       []rr.ObservedAction{},
		FeatureExposures:      exposures,
		Steps:                 []rr.StepDiagnostic{},
		Measurements:          convertMeasurements(document.Measurements),
		Claims:                convertClaims(document.Claims),
		Findings:              convertFindings(document.Findings),
		Observation: rr.ObservationSummary{
			OpenedRef:        rr.EvidenceRef{},
			ClosedRef:        rr.Missing{Reason: "not_observed", Detail: "closure was not joined into this diagnostic"},
			ClosureReason:    rr.Missing{Reason: "not_observed", Detail: "closure was not joined into this diagnostic"},
			LifecycleRefs:    []rr.EvidenceRef{},
			ContainmentRefs:  []rr.EvidenceRef{},
			LateEvidenceRefs: []rr.EvidenceRef{},
		},
		Application: rr.ApplicationSummary{
			Goal:             "unknown",
			AsOfSequence:     int(document.InputPrefix.LastSequence),
			Postconditions:   []rr.PredicateResult{},
			CommitmentRefs:   []rr.EvidenceRef{},
			ConfirmationRefs: []rr.EvidenceRef{},
		},
		BehavioralProfile:  rr.AnalysisSection{Data: rr.Missing{Reason: "not_enabled", Detail: "behavioral scoring is not an M1 analysis"}, EvidenceRefs: []rr.EvidenceRef{}},
		FingerprintProfile: rr.AnalysisSection{Data: rr.Missing{Reason: "not_enabled", Detail: "transport fingerprint analysis is not an M1 analysis"}, EvidenceRefs: []rr.EvidenceRef{}},
		Artifacts:          []rr.ArtifactSlot{},
	}
}

func convertPrefix(prefix JournalPrefix) rr.JournalPrefix {
	return rr.JournalPrefix{JournalID: prefix.JournalID, LastSequence: int(prefix.LastSequence), HeadHash: prefix.HeadHash}
}

func convertEvidenceRef(ref EvidenceRef) rr.EvidenceRef {
	return rr.EvidenceRef{
		JournalID: ref.JournalID,
		Sequence:  int(ref.Sequence),
		EventID:   ref.EventID,
		EventHash: ref.EventHash,
		Pointer:   ref.Pointer,
	}
}

func convertEvidenceRefs(refs []EvidenceRef) []rr.EvidenceRef {
	out := make([]rr.EvidenceRef, 0, len(refs))
	for _, ref := range refs {
		out = append(out, convertEvidenceRef(ref))
	}
	if out == nil {
		out = []rr.EvidenceRef{}
	}
	return out
}

func convertScope(scope diagnostic_reducer.Scope) rr.Scope {
	return rr.Scope{Kind: scope.Kind, ID: scope.ID}
}

func convertVersionPin(pin VersionPin) rr.VersionPin {
	return rr.VersionPin{ID: pin.ID, Version: pin.Version, ArtifactDigest: pin.ArtifactDigest}
}

func convertExecution(document DiagnosticDocument) rr.ExecutionDescriptor {
	mode := "subject"
	subject := any(map[string]any{
		"subject_id":        document.Subject.SubjectID,
		"subject_version":   document.Subject.SubjectVersion,
		"configured_mode":   document.Subject.ConfiguredMode,
		"interface_surface": document.Subject.InterfaceSurface,
	})
	if document.ManualMode {
		mode = "manual"
		subject = rr.Missing{Reason: "not_applicable", Detail: "manual execution judges no automation subject"}
	}
	return rr.ExecutionDescriptor{
		Mode:             mode,
		Subject:          subject,
		ConnectorVersion: rr.Missing{Reason: "not_observed", Detail: "connector version is not pinned by this analysis prefix"},
		BindingVersion:   rr.Missing{Reason: "not_observed", Detail: "binding version is not pinned by this analysis prefix"},
		Assistance: rr.AssistanceRecord{
			PlanningOwner:    "not_pinned",
			AssistanceTrack:  "not_pinned",
			PlannerIdentity:  rr.Missing{Reason: "not_observed", Detail: "no planner identity was joined into this diagnostic"},
			Plan:             rr.Missing{Reason: "not_observed", Detail: "no recorded plan was joined into this diagnostic"},
			OnlineReplanning: false,
			Description:      "planner assistance is admission metadata, not prefix evidence",
		},
	}
}

func convertValidity(document DiagnosticDocument, limitations []string) rr.DiagnosticValidity {
	checks := make([]rr.ValidityCheck, 0, len(document.Validity.Checks))
	for i, check := range document.Validity.Checks {
		checks = append(checks, rr.ValidityCheck{
			CheckID:      fmt.Sprintf("derivation-check-%d", i+1),
			Scope:        rr.Scope{Kind: "run", ID: document.RunID},
			State:        "recorded",
			EvidenceRefs: []rr.EvidenceRef{},
			Rationale:    check,
		})
	}
	if checks == nil {
		checks = []rr.ValidityCheck{}
	}
	if limitations == nil {
		limitations = []string{}
	}
	return rr.DiagnosticValidity{
		ScopedChecks:            checks,
		ProducerCompleteness:    []rr.ProducerCompleteness{},
		InfrastructureIncidents: []rr.EvidenceNote{},
		Limitations:             limitations,
	}
}

func convertAssessments(assessments []diagnostic_reducer.RequirementAssessment) []rr.RequirementAssessment {
	out := make([]rr.RequirementAssessment, 0, len(assessments))
	for _, assessment := range assessments {
		refs := make([]rr.CapabilityReference, 0, len(assessment.CapabilityRefs))
		for _, ref := range assessment.CapabilityRefs {
			// The render shape wants a descriptor digest this derivation
			// does not compute; the capability linkage is preserved and
			// the unknown digest stays an empty string, never a null.
			refs = append(refs, rr.CapabilityReference{
				DescriptorDigest: "",
				CapabilityID:     ref.CapabilityID,
				EvidenceRef:      rr.EvidenceRef{},
			})
		}
		if refs == nil {
			refs = []rr.CapabilityReference{}
		}
		findingRefs := append([]string{}, assessment.FindingRefs...)
		if findingRefs == nil {
			findingRefs = []string{}
		}
		out = append(out, rr.RequirementAssessment{
			RequirementID:   assessment.RequirementID,
			Facet:           assessment.Facet,
			ContractVersion: assessment.ContractVersion,
			Scope:           convertScope(assessment.Scope),
			CapabilityRefs:  refs,
			Opportunity: rr.Opportunity{
				State:        assessment.Opportunity.State,
				EvidenceRefs: convertEvidenceRefs(assessment.Opportunity.Support),
				Rationale:    assessment.Opportunity.Rationale,
			},
			Result:               assessment.Result,
			EvidenceRefs:         convertEvidenceRefs(assessment.Support),
			ContraryEvidenceRefs: convertEvidenceRefs(assessment.ContraryEvidence),
			FindingRefs:          findingRefs,
			Rationale:            assessment.Rationale,
		})
	}
	if out == nil {
		out = []rr.RequirementAssessment{}
	}
	return out
}

// convertFeatureExposures projects per-instance exposures. The render shape
// has no requirement or limitation slots, so non-empty values are folded
// into validity limitation notes (returned second) instead of being
// dropped silently.
func convertFeatureExposures(exposures []diagnostic_reducer.FeatureExposure) ([]rr.FeatureExposure, []string) {
	out := make([]rr.FeatureExposure, 0, len(exposures))
	var notes []string
	for _, exposure := range exposures {
		out = append(out, rr.FeatureExposure{
			InstanceID:       exposure.FeatureID,
			Configured:       exposure.Configured,
			RenderedOrArmed:  exposure.RenderedArmed,
			Exposed:          exposure.Exposed,
			Activated:        exposure.Activated,
			RecoveryObserved: rr.Missing{Reason: "not_applicable", Detail: "recovery is observed per attempt step, not per feature instance"},
			EvidenceRefs:     convertEvidenceRefs(exposure.Support),
		})
		if strings.TrimSpace(exposure.RequirementRef) != "" {
			notes = append(notes, fmt.Sprintf("feature_exposure %s requirement_ref: %s", exposure.FeatureID, exposure.RequirementRef))
		}
		for _, limitation := range exposure.Limitations {
			notes = append(notes, fmt.Sprintf("feature_exposure %s: %s", exposure.FeatureID, limitation))
		}
	}
	if out == nil {
		out = []rr.FeatureExposure{}
	}
	return out, notes
}

func convertMeasurements(measurements []diagnostic_reducer.MeasurementEvidence) []rr.MeasurementEvidence {
	out := make([]rr.MeasurementEvidence, 0, len(measurements))
	for _, evidence := range measurements {
		measurement := evidence.Measurement
		out = append(out, rr.MeasurementEvidence{
			Measurement: rr.Measurement{
				MeasurementID:      measurement.MeasurementID,
				Name:               measurement.Name,
				Scope:              rr.Scope{Kind: measurement.Scope.Kind, ID: measurement.Scope.ID},
				Quantity:           measurement.Quantity,
				Unit:               measurement.Unit,
				Origin:             measurement.Origin,
				ClockID:            measurement.ClockID,
				BootID:             measurement.BootID,
				Method:             measurement.Method,
				Start:              measurement.Start,
				End:                measurement.End,
				Estimate:           measurement.Estimate,
				Resolution:         measurement.Resolution,
				Censoring:          measurement.Censoring,
				ComparabilityGroup: measurement.ComparabilityGroup,
			},
			EvidenceRefs: convertEvidenceRefs(evidence.Support),
		})
	}
	if out == nil {
		out = []rr.MeasurementEvidence{}
	}
	return out
}

func convertClaims(claims []diagnostic_reducer.Claim) []rr.Claim {
	out := make([]rr.Claim, 0, len(claims))
	for _, claim := range claims {
		limitations := append([]string{}, claim.Limitations...)
		if limitations == nil {
			limitations = []string{}
		}
		out = append(out, rr.Claim{
			ClaimID:     claim.ClaimID,
			Source:      claim.Source,
			Scope:       claim.SemanticScope,
			Proposition: map[string]any{"statement": claim.Proposition},
			MadeAt:      rr.Missing{Reason: "not_observed", Detail: "claim airing time was not joined into this diagnostic"},
			ReceivedAt: rr.TimePoint{
				ClockID:           "",
				BootID:            "",
				Origin:            "",
				MonotonicOffsetMs: 0,
				UtcAnnotation:     rr.Missing{Reason: "not_applicable"},
			},
			EvidenceRefs:                convertEvidenceRefs(claim.Support),
			EvidenceAvailableToClaimant: []rr.EvidenceRef{},
			KnowledgeLimitations:        limitations,
			Comparison:                  claim.Comparison,
			ComparisonEvidenceRefs:      convertEvidenceRefs(claim.ComparisonSupport),
		})
	}
	if out == nil {
		out = []rr.Claim{}
	}
	return out
}

func convertFindings(findings []diagnostic_reducer.Finding) []rr.Finding {
	out := make([]rr.Finding, 0, len(findings))
	for _, finding := range findings {
		requirementRefs := append([]string{}, finding.RequirementRefs...)
		if requirementRefs == nil {
			requirementRefs = []string{}
		}
		triggerRefs := append([]string{}, finding.TriggerFeatures...)
		if triggerRefs == nil {
			triggerRefs = []string{}
		}
		limitations := append([]string{}, finding.Limitations...)
		if limitations == nil {
			limitations = []string{}
		}
		out = append(out, rr.Finding{
			FindingID:            finding.ID,
			Kind:                 finding.Kind,
			RequirementRefs:      requirementRefs,
			Symptom:              finding.Symptom,
			Scope:                convertScope(finding.Scope),
			CausalRole:           finding.CausalRole,
			TriggerFeatureRefs:   triggerRefs,
			DefectLocus:          finding.DefectLocus,
			Attribution:          finding.Attribution,
			EvidenceRefs:         convertEvidenceRefs(finding.Support),
			ContraryEvidenceRefs: convertEvidenceRefs(finding.ContraryEvidence),
			Limitations:          limitations,
			SuggestedFix:         finding.SuggestedFix,
		})
	}
	if out == nil {
		out = []rr.Finding{}
	}
	return out
}

// ---------------------------------------------------------------------------
// Small helpers.
// ---------------------------------------------------------------------------

func validDigest(value string) bool {
	const prefix = "sha256:"
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	hexPart := value[len(prefix):]
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

func numberAsInt64(value any) (int64, bool) {
	switch n := value.(type) {
	case int64:
		return n, true
	case int:
		return int64(n), true
	case int32:
		return int64(n), true
	case float64:
		if n == float64(int64(n)) {
			return int64(n), true
		}
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return i, true
		}
	}
	return 0, false
}

func artifactRefMap(ref ArtifactReference) map[string]any {
	return map[string]any{
		"digest":       ref.Digest,
		"size_bytes":   ref.SizeBytes,
		"media_type":   ref.MediaType,
		"owner_domain": ref.OwnerDomain,
		"access":       ref.Access,
	}
}

func artifactRefFromValue(value any) (ArtifactReference, error) {
	var zero ArtifactReference
	m, ok := value.(map[string]any)
	if !ok {
		return zero, fmt.Errorf("must be an object, got %T", value)
	}
	digest, _ := m["digest"].(string)
	size, sizeOK := numberAsInt64(m["size_bytes"])
	mediaType, _ := m["media_type"].(string)
	ownerDomain, _ := m["owner_domain"].(string)
	access, _ := m["access"].(string)
	if !validDigest(digest) || !sizeOK || size < 0 || strings.TrimSpace(mediaType) == "" || strings.TrimSpace(ownerDomain) == "" || (access != accessRestricted && access != accessPublic) {
		return zero, fmt.Errorf("has incomplete identity fields")
	}
	return ArtifactReference{
		Digest:      digest,
		SizeBytes:   size,
		MediaType:   mediaType,
		OwnerDomain: ownerDomain,
		Access:      access,
	}, nil
}

// jsonRoundTrip normalizes a Go value (struct, map, or Missing envelope)
// into its plain JSON-decoded form for journal storage.
func jsonRoundTrip(value any) (any, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var out any
	if err := decoder.Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

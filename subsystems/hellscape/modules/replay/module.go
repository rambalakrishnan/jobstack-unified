// Package replay implements tier-8 Hellscape exact fixture replay and
// diagnostic re-derivation.
//
// It enforces seam-mappings/hellscape-seam-mapping.md sections 11.1 (exact
// replay), 11.2 (ReplayReceipt), 11.3 (hash reconciliation) and 16.5
// (lifecycle and diagnostic corpus), plus invariants EK-REPLAY,
// EK-DIAGNOSTIC, EK-HASHES, EK-ATTEMPT-SCOPE and LIFE-IDEMPOTENCY:
//
//   - Exact fixture replay verifies manifest, chain, artifact, and
//     source-import identities, loads the pinned reducer and classifier,
//     consumes recorded external inputs and lifecycle observations, never
//     feeds recorded derived outputs back as authoritative inputs, unwraps
//     imported source inputs exactly once, recomputes semantic outputs and
//     state, re-derives the diagnostic with the original analysis request,
//     compares required hashes, and publishes a separate immutable receipt.
//   - Recorded timing remains input. Replay never sleeps and never invokes
//     a browser, subject, or external mutation.
//   - Every receipt carries record/version, replay ID, mode, run ID,
//     manifest hash, source prefix, source diagnostic, input bundle,
//     classifier, reducer, replay engine, comparisons, result, limitations,
//     and three false invocation/write flags.
//   - Exact fixture mode requires semantic-event, final-state, and
//     diagnostic comparisons. Diagnostic re-derivation requires only the
//     diagnostic comparison with an inapplicable reducer.
//   - Each comparison carries output, expected digest, actual digest or
//     Missing, and a matched/mismatched/unavailable result. The aggregate
//     is mismatched if any required comparison mismatches; otherwise
//     unavailable if any is unavailable; otherwise matched. Missing inputs
//     can never yield matched. Mismatch and unavailable remain distinct.
//
// Expected-digest convention: the recorded diagnostic pins its record-time
// recomputable digests in Extra:
//
//   - "semantic_events_digest": expected semantic-events projection digest.
//   - "final_state_digest": expected final fixture-state digest.
//   - "diagnostic_digest": expected re-derived diagnostic digest, i.e. the
//     canonical hash of the diagnostic_reducer document at record time.
//   - "effective_configuration": the pinned fixture configuration, either
//     an inline JSON object, an inline JSON string, or an artifact
//     reference object ({digest,size_bytes,media_type,owner_domain,access}).
//   - "subject": the judged subject scope
//     ({subject_id,subject_version,configured_mode,interface_surface}).
//   - "manual_mode": optional boolean selecting manual fixture validation.
//
// When an expected digest is absent or its inputs are missing, the
// comparison is unavailable (typed Missing), never matched. When both
// digests are present but differ, the comparison is mismatched. Only equal
// digests yield matched.
//
// Fixture-command convention: consumed input events (role external_input or
// lifecycle_observation) may carry "fixture_command" (one object) or
// "fixture_commands" (array) in payload.data. Each command decodes as a
// fixture_reducer.EventSubmission and is applied in journal order starting
// from InitialFixtureState. Derived-output events are never decoded.
//
// Import convention: an input whose payload.data carries one of
// "imported_from", "imported_source", "import_digest", "source_import", or
// "import_reference" is an imported source input. Its import key is the
// digest string itself or the canonical hash of the embedded object.
// Repeated keys are applied exactly once; later duplicates are skipped and
// reported in limitations.
//
// Employer-mutation convention: a fixture command or journal event is an
// employer mutation when its operation/event kind contains "employer"
// (case-insensitive), its payload sets "employer_mutation" to true, or its
// payload sets "target_origin"/"attempt_kind" to "employer"/"production".
// Exact fixture replay refuses to apply employer mutations (the laboratory
// fixture is practice/held_in). Diagnostic-only replay never invokes the
// fixture reducer at all, so it cannot repeat an employer mutation.
//
// This package performs no database writes, no artifact installs, no
// sleeps, and no browser/subject/external invocations. It reads through
// evidence_bundle.LoadReplayInputs, journal_rules.ValidateJournal, and
// owner_store.ReadArtifact, recomputes purely, and returns a receipt.
package replay

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	diagnostic_reducer "diagnostic_reducer"
	evidence_bundle "evidence_bundle"
	evidence_codec "evidence_codec"
	fixture_reducer "fixture_reducer"
	journal_rules "journal_rules"
	owner_store "owner_store"
)

// ---------------------------------------------------------------------------
// Aliases: shared wire shapes so CONSUMES calls need no translation.
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
	// Digest is the shared content digest ("sha256:" + 64 lowercase hex).
	Digest = evidence_codec.Digest
	// DiagnosticDocument is the recorded bundle diagnostic.
	DiagnosticDocument = evidence_bundle.DiagnosticDocument
	// ReplayReceipt is the separate immutable replay record.
	ReplayReceipt = evidence_bundle.ReplayReceipt
	// ReplayComparison is one required replay comparison.
	ReplayComparison = evidence_bundle.ReplayComparison
	// VersionPin pins an immutable versioned artifact.
	VersionPin = evidence_bundle.VersionPin
)

// Compile-time CONSUMES linkage: fail compilation if a declared upstream
// signature disappears.
var (
	_ = evidence_bundle.LoadReplayInputs
	_ = diagnostic_reducer.DeriveDiagnostic
	_ = fixture_reducer.InitialFixtureState
	_ = fixture_reducer.ReduceFixture
	_ = journal_rules.ValidateJournal
	_ = owner_store.ReadArtifact
	_ = owner_store.InstallArtifact
	_ = owner_store.CommitOwner
	_ = evidence_codec.HashBytes
	_ = evidence_codec.CanonicalJSON
)

// Ensure io and sql are referenced: CommitOwner/InstallArtifact linkage uses
// them, but replay itself performs no writes.
var (
	_ io.Reader
	_ = sql.ErrNoRows
)

// ---------------------------------------------------------------------------
// Constants and sentinel errors.
// ---------------------------------------------------------------------------

const (
	receiptRecordType = "replay_receipt"
	receiptSchema     = "1.0.0"

	modeExactFixture   = "exact_fixture"
	modeDiagnosticOnly = "diagnostic_only"
	// modeDiagnosticRederivation is the contract alias for diagnostic_only.
	modeDiagnosticRederivation = "diagnostic_rederivation"

	comparisonSemanticEvents = "semantic_events"
	comparisonFinalState     = "final_state"
	comparisonDiagnostic     = "diagnostic"

	resultMatched     = "matched"
	resultMismatched  = "mismatched"
	resultUnavailable = "unavailable"

	mediaTypeJSON = "application/json"

	extraSemanticDigest = "semantic_events_digest"
	extraFinalDigest    = "final_state_digest"
	extraDiagDigest     = "diagnostic_digest"
	extraConfig         = "effective_configuration"
	extraSubject        = "subject"
	extraManualMode     = "manual_mode"

	replayEngineID      = "replay-engine"
	replayEngineVersion = "v1"
	reducerID           = "fixture-reducer"
	reducerVersion      = "v1"
)

var (
	// ErrInvalid marks malformed replay inputs (unknown mode, bad shape).
	ErrInvalid = fmt.Errorf("replay: invalid input")
	// ErrIntegrityConflict marks digest, identity, or pin mismatches.
	ErrIntegrityConflict = fmt.Errorf("replay: integrity conflict")
)

// ---------------------------------------------------------------------------
// ReplayBundle.
// ---------------------------------------------------------------------------

// ReplayBundle replays one installed bundle against its recorded source
// diagnostic and returns a separate immutable receipt.
//
// Accepted modes are "exact_fixture" (three comparisons: semantic events,
// final state, diagnostic) and "diagnostic_only"/"diagnostic_rederivation"
// (diagnostic comparison only, reducer inapplicable). The receipt always
// normalizes the diagnostic alias to "diagnostic_only" so it satisfies the
// bundle receipt shape.
//
// ReplayBundle is read-only: it never installs artifacts, commits journal
// events, sleeps, or invokes a browser, subject, or external mutation. All
// three invocation flags on the receipt are always false.
func ReplayBundle(ctx context.Context, store *OwnerStore, bundle ArtifactReference, sourceDiagnostic ArtifactReference, mode string) (ReplayReceipt, error) {
	empty := ReplayReceipt{}
	if store == nil {
		return empty, fmt.Errorf("%w: store is required", ErrInvalid)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	normalized, err := normalizeMode(mode)
	if err != nil {
		return empty, err
	}
	exact := normalized == modeExactFixture

	manifest, events, recorded, err := evidence_bundle.LoadReplayInputs(ctx, store, bundle)
	if err != nil {
		return empty, fmt.Errorf("replay: load replay inputs %s: %w", bundle.Digest, err)
	}
	validated, err := journal_rules.ValidateJournal(manifest, events)
	if err != nil {
		return empty, fmt.Errorf("replay: journal validation: %w", err)
	}
	if validated != recorded.InputPrefix {
		return empty, fmt.Errorf("%w: bundle diagnostic prefix %+v does not match the validated prefix %+v",
			ErrIntegrityConflict, recorded.InputPrefix, validated)
	}
	manifestHash, err := manifestDigestOf(manifest)
	if err != nil {
		return empty, err
	}
	if recorded.ManifestHash != manifestHash {
		return empty, fmt.Errorf("%w: diagnostic manifest_hash %q does not match the admitted manifest %q",
			ErrIntegrityConflict, recorded.ManifestHash, manifestHash)
	}
	if err := validateVersionPinShape(recorded.Classifier, "diagnostic.classifier"); err != nil {
		return empty, err
	}

	// Verify the source diagnostic identity and its equality with the
	// bundled diagnostic. A missing source makes the diagnostic comparison
	// unavailable; a corrupt or divergent source is an integrity conflict.
	sourceBytes, sourceErr := readAndHashArtifact(ctx, store, sourceDiagnostic)
	sourceUnavailableReason := ""
	if sourceErr != nil {
		if isMissingArtifact(sourceErr) {
			sourceUnavailableReason = missingReasonOf(sourceErr, sourceDiagnostic.Digest)
		} else {
			return empty, sourceErr
		}
	}
	if sourceErr == nil {
		if err := checkSourceMatchesRecorded(sourceBytes, recorded, sourceDiagnostic.Digest); err != nil {
			return empty, err
		}
	}

	consumed, ignored := filterReplayInputs(events)
	deduped, dupSkipped := unwrapImportedInputs(consumed)

	limitations := []string{}
	if len(ignored) > 0 {
		limitations = append(limitations, fmt.Sprintf(
			"ignored %d recorded derived-output event(s); derived outputs are never fed back as inputs", len(ignored)))
	}
	if dupSkipped > 0 {
		limitations = append(limitations, fmt.Sprintf(
			"unwrapped imported source inputs exactly once; skipped %d duplicate import(s)", dupSkipped))
	}
	limitations = append(limitations,
		"recorded timing is input: replay consumes recorded clock offsets and measurements without sleeping",
		"replay invokes no browser, subject, or external mutation")

	// Configuration is a pinned replay input shared by fixture and
	// diagnostic recomputation.
	var configuration []byte
	var configErr error
	if sourceErr == nil {
		configuration, configErr = loadConfiguration(ctx, store, events, recorded)
		if configErr != nil && exact {
			limitations = append(limitations, "fixture configuration unavailable: "+configErr.Error())
		}
	}

	var comparisons []ReplayComparison
	if exact {
		comparisons, err = replayExact(ctx, store, manifest, events, recorded, deduped, configuration, configErr, sourceBytes, sourceErr, sourceUnavailableReason, &limitations)
		if err != nil {
			return empty, err
		}
	} else {
		comparisons, err = replayDiagnosticOnly(manifest, events, recorded, configuration, configErr, sourceUnavailableReason, &limitations)
		if err != nil {
			return empty, err
		}
	}

	result := aggregateResult(comparisons)
	reducer := reducerPinFor(normalized)
	receipt := ReplayReceipt{
		RecordType:              receiptRecordType,
		SchemaVersion:           receiptSchema,
		ReplayID:                replayIDFor(bundle, sourceDiagnostic, normalized),
		Mode:                    normalized,
		RunID:                   manifest.RunID,
		ManifestHash:            manifestHash,
		SourcePrefix:            recorded.InputPrefix,
		SourceDiagnostic:        sourceDiagnostic,
		InputBundle:             bundle,
		Classifier:              recorded.Classifier,
		Reducer:                 reducer,
		ReplayEngine:            replayEnginePin(),
		Comparisons:             comparisons,
		Result:                  result,
		Limitations:             limitations,
		InvokedBrowser:          false,
		InvokedSubject:          false,
		PerformedExternalWrites: false,
	}
	if err := validateReceiptShape(receipt, normalized); err != nil {
		return empty, err
	}
	return receipt, nil
}

// ---------------------------------------------------------------------------
// Exact and diagnostic-only paths.
// ---------------------------------------------------------------------------

func replayExact(ctx context.Context, store *OwnerStore, manifest Manifest, events []JournalEnvelope, recorded DiagnosticDocument, deduped []JournalEnvelope, configuration []byte, configErr error, sourceBytes []byte, sourceErr error, sourceUnavailableReason string, limitations *[]string) ([]ReplayComparison, error) {
	_ = ctx
	_ = store
	_ = events
	_ = sourceBytes
	expectedSemantic, semanticPinned := expectedDigest(recorded, extraSemanticDigest)
	expectedFinal, finalPinned := expectedDigest(recorded, extraFinalDigest)

	var semanticActual, finalActual string
	var semanticMissing, finalMissing *MissingEnvelope
	if configErr != nil {
		reason := missingReasonOf(configErr, "")
		if reason == "" {
			reason = "not_observed"
		}
		m := newMissing(reason, configErr.Error())
		semanticMissing = &m
		fm := newMissing(reason, configErr.Error())
		finalMissing = &fm
	} else if employerEvent, found := firstEmployerMutationEvent(deduped); found {
		detail := fmt.Sprintf("sequence %d carries an employer mutation (%s); the laboratory fixture is practice/held_in and cannot replay it", employerEvent.Sequence, employerEvent.EventKind)
		*limitations = append(*limitations, detail)
		m := newMissing("not_observed", detail)
		semanticMissing = &m
		fm := newMissing("not_observed", detail)
		finalMissing = &fm
	} else {
		actual, final, missing, detail := runFixtureReplay(manifest, configuration, deduped)
		if missing != nil {
			*limitations = append(*limitations, detail)
			semanticMissing = missing
			fm := *missing
			finalMissing = &fm
		} else {
			semanticActual = actual
			finalActual = final
		}
	}

	comparisons := []ReplayComparison{
		compareDigests(comparisonSemanticEvents, expectedSemantic, semanticPinned, semanticActual, semanticMissing),
		compareDigests(comparisonFinalState, expectedFinal, finalPinned, finalActual, finalMissing),
	}
	diag, err := compareDiagnostic(manifest, events, recorded, configuration, configErr, sourceErr, sourceUnavailableReason, limitations)
	if err != nil {
		return nil, err
	}
	comparisons = append(comparisons, diag)
	return comparisons, nil
}

func replayDiagnosticOnly(manifest Manifest, events []JournalEnvelope, recorded DiagnosticDocument, configuration []byte, configErr error, sourceUnavailableReason string, limitations *[]string) ([]ReplayComparison, error) {
	// Diagnostic-only replay never invokes the fixture reducer, so it
	// cannot repeat an employer mutation even when the journal carries
	// one. Only the diagnostic comparison is required.
	*limitations = append(*limitations, "diagnostic-only replay does not invoke the fixture reducer and cannot repeat employer mutations")
	var sourceErr error
	if sourceUnavailableReason != "" {
		sourceErr = fmt.Errorf("source diagnostic %s", sourceUnavailableReason)
	}
	diag, err := compareDiagnostic(manifest, events, recorded, configuration, configErr, sourceErr, sourceUnavailableReason, limitations)
	if err != nil {
		return nil, err
	}
	return []ReplayComparison{diag}, nil
}

// compareDiagnostic re-derives the diagnostic with the original analysis
// request and compares its canonical digest against the pinned expected
// digest. Any missing input yields unavailable, never matched.
func compareDiagnostic(manifest Manifest, events []JournalEnvelope, recorded DiagnosticDocument, configuration []byte, configErr error, sourceErr error, sourceUnavailableReason string, limitations *[]string) (ReplayComparison, error) {
	expected, pinned := expectedDigest(recorded, extraDiagDigest)
	if sourceErr != nil {
		reason := sourceUnavailableReason
		if reason == "" {
			reason = "not_observed"
		}
		m := newMissing(reason, "source diagnostic bytes unavailable; the recorded diagnostic cannot be compared")
		*limitations = append(*limitations, "source diagnostic unavailable: the diagnostic comparison is unavailable")
		return compareDigests(comparisonDiagnostic, expected, pinned, "", &m), nil
	}
	if configErr != nil {
		*limitations = append(*limitations, "diagnostic configuration unavailable: "+configErr.Error())
		m := newMissing(missingReasonOf(configErr, ""), configErr.Error())
		return compareDigests(comparisonDiagnostic, expected, pinned, "", &m), nil
	}
	actual, missing, detail := rederiveDiagnosticDigest(manifest, events, recorded, configuration)
	if missing != nil {
		*limitations = append(*limitations, detail)
		return compareDigests(comparisonDiagnostic, expected, pinned, "", missing), nil
	}
	return compareDigests(comparisonDiagnostic, expected, pinned, actual, nil), nil
}

// ---------------------------------------------------------------------------
// Input filtering: external inputs in, derived outputs out.
// ---------------------------------------------------------------------------

// filterReplayInputs partitions recorded events into consumed inputs
// (external_input and lifecycle_observation) and ignored derived outputs.
// Ordering within each partition follows journal sequence.
func filterReplayInputs(events []JournalEnvelope) (consumed, ignored []JournalEnvelope) {
	consumed = []JournalEnvelope{}
	ignored = []JournalEnvelope{}
	for _, ev := range events {
		switch ev.Role {
		case "external_input", "lifecycle_observation":
			consumed = append(consumed, ev)
		default:
			ignored = append(ignored, ev)
		}
	}
	return consumed, ignored
}

var importKeys = []string{"imported_from", "imported_source", "import_digest", "source_import", "import_reference"}

// unwrapImportedInputs deduplicates imported source inputs so each distinct
// import key is applied exactly once. Later duplicates are skipped. It
// returns the deduplicated inputs and the number of skipped duplicates.
func unwrapImportedInputs(consumed []JournalEnvelope) ([]JournalEnvelope, int) {
	seen := map[string]bool{}
	out := make([]JournalEnvelope, 0, len(consumed))
	skipped := 0
	for _, ev := range consumed {
		key, isImport := importKeyOf(ev)
		if !isImport {
			out = append(out, ev)
			continue
		}
		if seen[key] {
			skipped++
			continue
		}
		seen[key] = true
		out = append(out, ev)
	}
	return out, skipped
}

// importKeyOf reports whether the event carries an imported source input
// and, when it does, the canonical import key. A digest string is its own
// key; an embedded object is keyed by its canonical hash.
func importKeyOf(ev JournalEnvelope) (string, bool) {
	if ev.Payload.Data == nil {
		return "", false
	}
	for _, key := range importKeys {
		raw, ok := ev.Payload.Data[key]
		if !ok || raw == nil {
			continue
		}
		if s, ok := raw.(string); ok {
			if strings.TrimSpace(s) == "" {
				continue
			}
			if validDigest(s) {
				return "digest:" + s, true
			}
			return "literal:" + s, true
		}
		encoded, err := json.Marshal(raw)
		if err != nil {
			continue
		}
		canonical, err := evidence_codec.CanonicalJSON(encoded, mediaTypeJSON)
		if err != nil {
			continue
		}
		return "object:" + string(evidence_codec.HashBytes(canonical)), true
	}
	return "", false
}

// ---------------------------------------------------------------------------
// Employer mutations.
// ---------------------------------------------------------------------------

// isEmployerMutationEvent reports whether a journal event carries an
// employer mutation: an employer/production kind, an explicit
// employer_mutation flag, or an employer/production origin marker.
func isEmployerMutationEvent(ev JournalEnvelope) bool {
	if strings.Contains(strings.ToLower(ev.EventKind), "employer") {
		return true
	}
	return payloadRequestsEmployer(ev.Payload.Data)
}

// isEmployerMutationCommand reports whether a fixture command requests an
// employer mutation.
func isEmployerMutationCommand(kind string, data map[string]any) bool {
	if strings.Contains(strings.ToLower(kind), "employer") {
		return true
	}
	return payloadRequestsEmployer(data)
}

func payloadRequestsEmployer(data map[string]any) bool {
	if data == nil {
		return false
	}
	if flag, ok := data["employer_mutation"].(bool); ok && flag {
		return true
	}
	for _, key := range []string{"target_origin", "attempt_kind", "origin"} {
		if s, ok := data[key].(string); ok {
			lower := strings.ToLower(strings.TrimSpace(s))
			if lower == "employer" || lower == "production" {
				return true
			}
		}
	}
	if cmd, ok := data["fixture_command"].(map[string]any); ok && payloadRequestsEmployer(cmd) {
		return true
	}
	return false
}

func firstEmployerMutationEvent(deduped []JournalEnvelope) (JournalEnvelope, bool) {
	for _, ev := range deduped {
		if isEmployerMutationEvent(ev) {
			return ev, true
		}
		for _, cmd := range fixtureCommandsIn(ev) {
			if isEmployerMutationCommand(cmd.OperationKind, commandDataMap(cmd)) {
				return ev, true
			}
		}
	}
	return JournalEnvelope{}, false
}

// ---------------------------------------------------------------------------
// Configuration loading.
// ---------------------------------------------------------------------------

// loadConfiguration resolves the pinned fixture configuration: the
// diagnostic Extra entry first, then diagnostic artifacts, then journal
// payloads and artifact references. The returned bytes are canonicalizable
// JSON.
func loadConfiguration(ctx context.Context, store *OwnerStore, events []JournalEnvelope, recorded DiagnosticDocument) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if recorded.Extra != nil {
		if raw, ok := recorded.Extra[extraConfig]; ok {
			if config, err := configFromValue(ctx, store, raw); err == nil {
				return config, nil
			} else if !isNotFoundConfig(err) {
				return nil, err
			}
		}
	}
	for _, ref := range recorded.Artifacts {
		config, err := tryReadConfig(ctx, store, ref)
		if err == nil {
			return config, nil
		}
	}
	for _, ev := range events {
		for _, key := range []string{"configuration", extraConfig} {
			if raw, ok := ev.Payload.Data[key]; ok {
				if config, err := configFromValue(ctx, store, raw); err == nil {
					return config, nil
				} else if !isNotFoundConfig(err) {
					return nil, err
				}
			}
		}
		for _, ref := range ev.Payload.ArtifactRefs {
			if config, err := tryReadConfig(ctx, store, ref); err == nil {
				return config, nil
			}
		}
	}
	return nil, &configError{reason: "not_observed", detail: "no pinned fixture configuration found in the diagnostic or journal"}
}

type configError struct {
	reason string
	detail string
}

func (e *configError) Error() string { return e.detail }

func isNotFoundConfig(err error) bool {
	_, ok := err.(*configError)
	return ok
}

func configFromValue(ctx context.Context, store *OwnerStore, raw any) ([]byte, error) {
	switch node := raw.(type) {
	case string:
		trimmed := strings.TrimSpace(node)
		if trimmed == "" {
			return nil, &configError{reason: "not_observed", detail: "empty inline configuration"}
		}
		if validDigest(trimmed) {
			return nil, &configError{reason: "not_observed", detail: "configuration digest without resolvable bytes: " + trimmed}
		}
		return normalizeConfigBytes([]byte(node))
	case map[string]any:
		if looksLikeArtifactRef(node) {
			ref, err := artifactRefFromMap(node)
			if err != nil {
				return nil, err
			}
			return tryReadConfig(ctx, store, ref)
		}
		encoded, err := json.Marshal(node)
		if err != nil {
			return nil, &configError{reason: "not_observed", detail: fmt.Sprintf("configuration is not encodable: %v", err)}
		}
		return normalizeConfigBytes(encoded)
	case []byte:
		return normalizeConfigBytes(node)
	default:
		encoded, err := json.Marshal(raw)
		if err != nil {
			return nil, &configError{reason: "not_observed", detail: "configuration value is not encodable"}
		}
		return normalizeConfigBytes(encoded)
	}
}

func tryReadConfig(ctx context.Context, store *OwnerStore, ref ArtifactReference) ([]byte, error) {
	raw, err := owner_store.ReadArtifact(ctx, store, ref)
	if err != nil {
		return nil, &configError{reason: missingReasonOf(err, ref.Digest), detail: fmt.Sprintf("configuration artifact %s unreadable: %v", ref.Digest, err)}
	}
	if string(evidence_codec.HashBytes(raw)) != ref.Digest {
		return nil, fmt.Errorf("%w: configuration bytes do not match %q", ErrIntegrityConflict, ref.Digest)
	}
	if !looksLikeConfig(raw) {
		return nil, &configError{reason: "not_observed", detail: "artifact is not fixture configuration"}
	}
	return normalizeConfigBytes(raw)
}

func looksLikeConfig(raw []byte) bool {
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return false
	}
	for _, key := range []string{"profile", "task", "features", "budgets"} {
		if _, ok := decoded[key]; ok {
			return true
		}
	}
	return false
}

func normalizeConfigBytes(raw []byte) ([]byte, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, &configError{reason: "not_observed", detail: "empty fixture configuration"}
	}
	canonical, err := evidence_codec.CanonicalJSON(raw, mediaTypeJSON)
	if err != nil {
		return nil, &configError{reason: "not_observed", detail: fmt.Sprintf("fixture configuration is not canonicalizable JSON: %v", err)}
	}
	var decoded any
	if err := json.Unmarshal(canonical, &decoded); err != nil {
		return nil, &configError{reason: "not_observed", detail: "fixture configuration is not a JSON value"}
	}
	obj, ok := decoded.(map[string]any)
	if !ok {
		return nil, &configError{reason: "not_observed", detail: "fixture configuration must be a JSON object"}
	}
	if _, ok := obj["profile"]; !ok {
		if _, ok := obj["task"]; !ok {
			return nil, &configError{reason: "not_observed", detail: "bytes do not carry fixture configuration keys"}
		}
	}
	return canonical, nil
}

// ---------------------------------------------------------------------------
// Fixture replay.
// ---------------------------------------------------------------------------

// fixtureCommandsIn extracts the fixture commands carried by one consumed
// input event, in order.
func fixtureCommandsIn(ev JournalEnvelope) []fixture_reducer.EventSubmission {
	out := []fixture_reducer.EventSubmission{}
	if ev.Payload.Data == nil {
		return out
	}
	if raw, ok := ev.Payload.Data["fixture_command"]; ok {
		if cmd, err := decodeFixtureCommand(raw); err == nil {
			out = append(out, cmd)
		}
	}
	if raw, ok := ev.Payload.Data["fixture_commands"]; ok {
		if arr, ok := raw.([]any); ok {
			for _, item := range arr {
				if cmd, err := decodeFixtureCommand(item); err == nil {
					out = append(out, cmd)
				}
			}
		}
	}
	return out
}

func decodeFixtureCommand(raw any) (fixture_reducer.EventSubmission, error) {
	var cmd fixture_reducer.EventSubmission
	encoded, err := json.Marshal(raw)
	if err != nil {
		return cmd, err
	}
	if err := json.Unmarshal(encoded, &cmd); err != nil {
		return cmd, err
	}
	return cmd, nil
}

func commandDataMap(cmd fixture_reducer.EventSubmission) map[string]any {
	if len(cmd.Payload) == 0 {
		return map[string]any{}
	}
	var decoded map[string]any
	if err := json.Unmarshal(cmd.Payload, &decoded); err != nil {
		return map[string]any{}
	}
	return decoded
}

// appliedCommand records one fixture command applied during replay with its
// journal sequence, reducer-emitted business events, and replayable response.
type appliedCommand struct {
	Sequence int64
	Command  fixture_reducer.EventSubmission
	Emitted  []fixture_reducer.EventSubmission
	Response []byte
}

// runFixtureReplay replays consumed inputs through the pinned fixture
// reducer and returns the semantic-events and final-state digests. On
// missing or unreplayable inputs it returns a Missing envelope and a
// limitation describing the reason.
func runFixtureReplay(manifest Manifest, configuration []byte, deduped []JournalEnvelope) (semantic, final string, missing *MissingEnvelope, detail string) {
	fixManifest := synthesizeFixtureManifest(manifest)
	state, err := fixture_reducer.InitialFixtureState(fixManifest, configuration)
	if err != nil {
		m := newMissing("not_observed", fmt.Sprintf("initial fixture state unavailable: %v", err))
		return "", "", &m, fmt.Sprintf("initial fixture state unavailable: %v", err)
	}
	applied := []appliedCommand{}
	for _, ev := range deduped {
		for _, cmd := range fixtureCommandsIn(ev) {
			if isEmployerMutationCommand(cmd.OperationKind, commandDataMap(cmd)) {
				m := newMissing("not_observed", "employer mutation refused in laboratory fixture replay")
				return "", "", &m, fmt.Sprintf("sequence %d requests an employer mutation; exact fixture replay refuses it", ev.Sequence)
			}
			next, emitted, response, err := fixture_reducer.ReduceFixture(fixManifest, configuration, state, cmd)
			if err != nil {
				m := newMissing("not_observed", fmt.Sprintf("fixture command %q unreplayable: %v", cmd.OperationKey, err))
				return "", "", &m, fmt.Sprintf("fixture command %q at sequence %d is unreplayable: %v", cmd.OperationKey, ev.Sequence, err)
			}
			state = next
			applied = append(applied, appliedCommand{Sequence: ev.Sequence, Command: cmd, Emitted: emitted, Response: response})
		}
	}
	semanticBytes, err := semanticProjectionBytes(deduped, applied)
	if err != nil {
		m := newMissing("not_observed", fmt.Sprintf("semantic projection unavailable: %v", err))
		return "", "", &m, fmt.Sprintf("semantic projection unavailable: %v", err)
	}
	canonicalState, err := evidence_codec.CanonicalJSON(state, mediaTypeJSON)
	if err != nil {
		m := newMissing("not_observed", fmt.Sprintf("final state unavailable: %v", err))
		return "", "", &m, fmt.Sprintf("final state is not canonicalizable: %v", err)
	}
	return string(evidence_codec.HashBytes(semanticBytes)), string(evidence_codec.HashBytes(canonicalState)), nil, ""
}

// semanticProjectionBytes builds the versioned semantic projection over
// consumed inputs (with recorded timing) and reducer-emitted business
// events. Derived-output events never enter the projection. Recorded clock
// offsets and measurements are data; replay never sleeps.
func semanticProjectionBytes(deduped []JournalEnvelope, applied []appliedCommand) ([]byte, error) {
	bySeq := map[int64][]appliedCommand{}
	for _, a := range applied {
		bySeq[a.Sequence] = append(bySeq[a.Sequence], a)
	}
	projection := []map[string]any{}
	for _, ev := range deduped {
		entry := map[string]any{
			"sequence":   ev.Sequence,
			"event_kind": ev.EventKind,
			"role":       ev.Role,
		}
		if dataCanonical, err := canonicalJSONOf(ev.Payload.Data); err == nil {
			entry["data"] = json.RawMessage(dataCanonical)
		} else {
			entry["data"] = map[string]any{}
		}
		entry["occurred_at"] = timingOf(ev.OccurredAt)
		entry["recorded_at"] = timingOf(ev.RecordedAt)
		if meas, err := canonicalJSONOf(ev.Payload.Measurements); err == nil {
			entry["measurements"] = json.RawMessage(meas)
		}
		projection = append(projection, entry)
		for _, a := range bySeq[ev.Sequence] {
			cmdEntry := map[string]any{
				"sequence":       ev.Sequence,
				"event_kind":     "fixture_command_applied",
				"role":           "derived_output",
				"operation_key":  a.Command.OperationKey,
				"operation_kind": a.Command.OperationKind,
				"attempt_id":     a.Command.AttemptID,
				"occurred_at":    timingOf(ev.OccurredAt),
			}
			if len(a.Command.Payload) > 0 {
				if canonical, err := evidence_codec.CanonicalJSON(a.Command.Payload, mediaTypeJSON); err == nil {
					cmdEntry["payload"] = json.RawMessage(canonical)
				}
			}
			if emitted, err := canonicalJSONOf(a.Emitted); err == nil {
				cmdEntry["emitted"] = json.RawMessage(emitted)
			}
			if len(a.Response) > 0 {
				if canonical, err := evidence_codec.CanonicalJSON(a.Response, mediaTypeJSON); err == nil {
					cmdEntry["response"] = json.RawMessage(canonical)
				}
			}
			projection = append(projection, cmdEntry)
		}
	}
	encoded, err := json.Marshal(projection)
	if err != nil {
		return nil, err
	}
	return evidence_codec.CanonicalJSON(encoded, mediaTypeJSON)
}

// semanticProjectionFromInputs renders consumed inputs plus their recorded
// timing into canonical bytes without reducer outputs. Tests use it to
// verify that derived outputs never enter the projection.
func semanticProjectionFromInputs(deduped []JournalEnvelope) ([]byte, error) {
	return semanticProjectionBytes(deduped, nil)
}

// timingOf normalizes a recorded TimePoint-or-Missing value into
// canonicalizable data. Missing stays Missing; TimePoints keep their
// recorded monotonic offset. No wall clock is consulted.
func timingOf(value any) any {
	if value == nil {
		return newMissing("not_observed", "")
	}
	if m, ok := asMissingEnvelope(value); ok {
		return m
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return newMissing("not_observed", "")
	}
	var decoded any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return newMissing("not_observed", "")
	}
	return decoded
}

// ---------------------------------------------------------------------------
// Diagnostic re-derivation.
// ---------------------------------------------------------------------------

// rederiveDiagnosticDigest rebuilds the original analysis request from the
// pinned analysis_requested event and the recorded diagnostic, re-derives
// the diagnostic, and returns its canonical digest.
func rederiveDiagnosticDigest(manifest Manifest, events []JournalEnvelope, recorded DiagnosticDocument, configuration []byte) (string, *MissingEnvelope, string) {
	request, missing, detail := buildAnalysisRequest(events, recorded, configuration)
	if missing != nil {
		return "", missing, detail
	}
	diagManifest := synthesizeDiagnosticManifest(manifest, recorded)
	rederived, err := diagnostic_reducer.DeriveDiagnostic(diagManifest, recorded.InputPrefix, events, request)
	if err != nil {
		m := newMissing("not_observed", truncateDetail(err.Error()))
		return "", &m, fmt.Sprintf("diagnostic re-derivation unavailable: %v", err)
	}
	encoded, err := json.Marshal(rederived)
	if err != nil {
		m := newMissing("not_observed", "re-derived diagnostic is not encodable")
		return "", &m, "re-derived diagnostic is not encodable"
	}
	canonical, err := evidence_codec.CanonicalJSON(encoded, mediaTypeJSON)
	if err != nil {
		m := newMissing("not_observed", "re-derived diagnostic is not canonicalizable")
		return "", &m, "re-derived diagnostic is not canonicalizable"
	}
	return string(evidence_codec.HashBytes(canonical)), nil, ""
}

// buildAnalysisRequest reconstructs the original analysis request. The
// journal's analysis_requested event pins diagnostic ID, revision,
// classifier, and registries; the recorded diagnostic must agree with those
// pins. Subject and manual mode come from the event first, then from the
// recorded Extra.
func buildAnalysisRequest(events []JournalEnvelope, recorded DiagnosticDocument, configuration []byte) (diagnostic_reducer.AnalysisRequest, *MissingEnvelope, string) {
	var empty diagnostic_reducer.AnalysisRequest
	if len(events) == 0 {
		m := newMissing("not_observed", "journal is empty; no analysis_requested event")
		return empty, &m, "journal is empty; the analysis request cannot be rebuilt"
	}
	last := events[len(events)-1]
	if last.EventKind != "analysis_requested" {
		m := newMissing("not_observed", fmt.Sprintf("prefix ends at %q, not analysis_requested", last.EventKind))
		return empty, &m, fmt.Sprintf("prefix ends at %q, not analysis_requested; the diagnostic cannot be re-derived", last.EventKind)
	}
	data := last.Payload.Data
	if data == nil {
		m := newMissing("not_observed", "analysis_requested carries no data")
		return empty, &m, "analysis_requested carries no data; the diagnostic cannot be re-derived"
	}
	pinnedID, _ := data["diagnostic_id"].(string)
	if pinnedID != recorded.DiagnosticID {
		m := newMissing("not_observed", "analysis_requested diagnostic_id diverges from the recorded diagnostic")
		return empty, &m, fmt.Sprintf("analysis_requested pins diagnostic %q but the recorded diagnostic is %q", pinnedID, recorded.DiagnosticID)
	}
	pinnedRev := int64From(data["analysis_revision"])
	if pinnedRev != recorded.AnalysisRevision {
		m := newMissing("not_observed", "analysis_requested revision diverges from the recorded diagnostic")
		return empty, &m, "analysis_requested revision diverges from the recorded diagnostic"
	}
	pinnedClassifier, err := pinFromValue(data["classifier"])
	if err != nil {
		m := newMissing("not_observed", "analysis_requested classifier pin is malformed")
		return empty, &m, fmt.Sprintf("analysis_requested classifier pin is malformed: %v", err)
	}
	if pinnedClassifier != toDiagnosticPin(recorded.Classifier) {
		m := newMissing("not_observed", "analysis_requested classifier diverges from the recorded diagnostic")
		return empty, &m, "analysis_requested classifier diverges from the recorded diagnostic"
	}
	pinnedRegistry, err := pinFromValue(data["requirement_registry"])
	if err != nil {
		m := newMissing("not_observed", "analysis_requested requirement_registry pin is malformed")
		return empty, &m, fmt.Sprintf("analysis_requested requirement_registry pin is malformed: %v", err)
	}
	if pinnedRegistry != toDiagnosticPin(recorded.RequirementRegistry) {
		m := newMissing("not_observed", "analysis_requested requirement_registry diverges from the recorded diagnostic")
		return empty, &m, "analysis_requested requirement_registry diverges from the recorded diagnostic"
	}
	pinnedFix := data["fix_registry"]
	if pinnedFix == nil {
		pinnedFix = newMissing("not_enabled", "")
	}
	if !fixRegistryEqual(pinnedFix, recorded.FixRegistry) {
		m := newMissing("not_observed", "analysis_requested fix_registry diverges from the recorded diagnostic")
		return empty, &m, "analysis_requested fix_registry diverges from the recorded diagnostic"
	}
	manual := manualModeFrom(data, recorded)
	subject, ok := subjectFrom(data, recorded)
	if !manual && !ok {
		m := newMissing("not_observed", "non-manual analysis requires a complete subject scope")
		return empty, &m, "non-manual analysis requires a complete subject scope; the diagnostic cannot be re-derived"
	}
	fix, err := normalizeFixRegistry(recorded.FixRegistry)
	if err != nil {
		m := newMissing("not_observed", "recorded fix_registry is malformed")
		return empty, &m, fmt.Sprintf("recorded fix_registry is malformed: %v", err)
	}
	return diagnostic_reducer.AnalysisRequest{
		DiagnosticID:        recorded.DiagnosticID,
		AnalysisRevision:    recorded.AnalysisRevision,
		Classifier:          toDiagnosticPin(recorded.Classifier),
		RequirementRegistry: toDiagnosticPin(recorded.RequirementRegistry),
		FixRegistry:         fix,
		Configuration:       append([]byte(nil), configuration...),
		ManualMode:          manual,
		Subject:             subject,
	}, nil, ""
}

func manualModeFrom(data map[string]any, recorded DiagnosticDocument) bool {
	if flag, ok := data["manual_mode"].(bool); ok {
		return flag
	}
	if recorded.Extra != nil {
		if flag, ok := recorded.Extra[extraManualMode].(bool); ok {
			return flag
		}
	}
	return false
}

func subjectFrom(data map[string]any, recorded DiagnosticDocument) (diagnostic_reducer.SubjectIdentity, bool) {
	if raw, ok := data["subject"]; ok {
		if subject, ok := decodeSubject(raw); ok {
			return subject, true
		}
	}
	if recorded.Extra != nil {
		if raw, ok := recorded.Extra[extraSubject]; ok {
			if subject, ok := decodeSubject(raw); ok {
				return subject, true
			}
		}
	}
	return diagnostic_reducer.SubjectIdentity{}, false
}

func decodeSubject(raw any) (diagnostic_reducer.SubjectIdentity, bool) {
	encoded, err := json.Marshal(raw)
	if err != nil {
		return diagnostic_reducer.SubjectIdentity{}, false
	}
	var subject diagnostic_reducer.SubjectIdentity
	if err := json.Unmarshal(encoded, &subject); err != nil {
		return diagnostic_reducer.SubjectIdentity{}, false
	}
	if strings.TrimSpace(subject.SubjectID) == "" || strings.TrimSpace(subject.SubjectVersion) == "" ||
		strings.TrimSpace(subject.ConfiguredMode) == "" || strings.TrimSpace(subject.InterfaceSurface) == "" {
		return diagnostic_reducer.SubjectIdentity{}, false
	}
	return subject, true
}

// ---------------------------------------------------------------------------
// Manifest synthesis.
// ---------------------------------------------------------------------------

// synthesizeFixtureManifest projects the admitted journal manifest into the
// fixture gate shape. The laboratory fixture is always
// practice/laboratory_fixture/held_in; richer record-time fields are
// intentionally not invented beyond these pinned replay defaults.
func synthesizeFixtureManifest(manifest Manifest) fixture_reducer.Manifest {
	var out fixture_reducer.Manifest
	out.RecordType = manifest.RecordType
	if strings.TrimSpace(out.RecordType) == "" {
		out.RecordType = "manifest"
	}
	out.SchemaVersion = "1.0.0"
	out.ManifestID = manifest.ManifestID
	out.RunID = manifest.RunID
	out.JournalID = manifest.JournalID
	out.OwnerDomain = manifest.OwnerDomain
	out.CommissionerID = "replay-commissioner"
	out.Activity = "application_attempt"
	out.Attempt.Kind = "practice"
	out.Attempt.Context = "laboratory_fixture"
	out.Attempt.Scope = "held_in"
	out.Attempt.SubjectVersion = "subject-1.0"
	out.Attempt.Assistance = "none"
	out.Execution = map[string]any{"mode": "replay"}
	out.Task = map[string]any{"task_id": "replay-task"}
	out.Environment = map[string]any{"deployment": "laboratory"}
	out.Seed = "replay-seed"
	out.BuildPins = map[string]string{"fixture": "1.0.0"}
	out.EventRegistry = map[string]string{"replay": "v1"}
	out.Producers = []map[string]any{{"producer_id": "replay"}}
	clocks := make([]map[string]any, 0, len(manifest.Clocks))
	for _, c := range manifest.Clocks {
		clocks = append(clocks, map[string]any{
			"clock_id": c.ClockID, "boot_id": c.BootID, "origin": c.Origin,
			"source_id": c.SourceID, "basis": c.Basis, "unit": c.Unit,
		})
	}
	out.Clocks = clocks
	out.Profile = "M1"
	out.Subject.Name = "subject-A"
	out.Subject.Version = "subject-1.0"
	out.Lineage.Kind = "practice"
	return out
}

// synthesizeDiagnosticManifest projects the admitted journal manifest into
// the diagnostic gate shape with the same pinned replay defaults. The EK
// journal identity (record type, schema version, manifest/run/journal IDs,
// owner, clocks) is preserved exactly so the projected journal manifest
// digests to the admitted manifest hash pinned by every journal event.
func synthesizeDiagnosticManifest(manifest Manifest, _ DiagnosticDocument) diagnostic_reducer.Manifest {
	var out diagnostic_reducer.Manifest
	out.RecordType = manifest.RecordType
	if strings.TrimSpace(out.RecordType) == "" {
		out.RecordType = "manifest"
	}
	out.SchemaVersion = manifest.SchemaVersion
	if strings.TrimSpace(out.SchemaVersion) == "" {
		out.SchemaVersion = "1.0.0"
	}
	out.ManifestID = manifest.ManifestID
	out.RunID = manifest.RunID
	out.JournalID = manifest.JournalID
	out.OwnerDomain = manifest.OwnerDomain
	out.CommissionerID = "replay-commissioner"
	out.Activity = "application_attempt"
	out.Attempt.Kind = "practice"
	out.Attempt.Context = "laboratory_fixture"
	out.Attempt.Scope = "held_in"
	out.Attempt.SubjectVersion = "subject-1.0"
	out.Attempt.Assistance = "none"
	out.Execution = map[string]any{"mode": "replay"}
	out.Task = map[string]any{"task_id": "replay-task"}
	out.Environment = map[string]any{"deployment": "laboratory"}
	out.Seed = "replay-seed"
	out.BuildPins = map[string]string{"fixture": "1.0.0"}
	out.EventRegistry = map[string]string{"replay": "v1"}
	out.Producers = []map[string]any{{"producer_id": "replay"}}
	for _, c := range manifest.Clocks {
		out.Clocks = append(out.Clocks, diagnostic_reducer.ClockDescriptor{
			ClockID: c.ClockID, BootID: c.BootID, Origin: c.Origin,
			SourceID: c.SourceID, Basis: c.Basis, Unit: c.Unit,
		})
	}
	out.Profile = "M1"
	out.Subject = diagnostic_reducer.SubjectDescriptor{Name: "subject-A", Version: "subject-1.0"}
	out.Lineage = diagnostic_reducer.LineageLinks{Kind: "practice"}
	return out
}

// ---------------------------------------------------------------------------
// Comparisons and receipt shape.
// ---------------------------------------------------------------------------

func expectedDigest(recorded DiagnosticDocument, key string) (string, bool) {
	if recorded.Extra == nil {
		return "", false
	}
	raw, ok := recorded.Extra[key]
	if !ok {
		return "", false
	}
	s, ok := raw.(string)
	if !ok || !validDigest(s) {
		return "", false
	}
	return s, true
}

// compareDigests builds one comparison. A missing expected digest, a
// missing actual digest, or an explicit Missing envelope yields
// unavailable. Equal digests yield matched; unequal digests yield
// mismatched. Unavailable and mismatched are never conflated.
func compareDigests(output, expected string, pinned bool, actual string, missing *MissingEnvelope) ReplayComparison {
	if !pinned || !validDigest(expected) {
		if missing == nil {
			m := newMissing("not_observed", "no pinned expected digest for "+output)
			missing = &m
		}
		// The expected digest is required by the receipt shape; use the
		// zero digest as a placeholder that can never match.
		if !validDigest(expected) {
			expected = zeroDigest()
		}
		return ReplayComparison{Output: output, ExpectedDigest: expected, ActualDigest: *missing, Result: resultUnavailable}
	}
	if missing != nil {
		return ReplayComparison{Output: output, ExpectedDigest: expected, ActualDigest: *missing, Result: resultUnavailable}
	}
	if !validDigest(actual) {
		m := newMissing("not_observed", "recomputed digest unavailable for "+output)
		return ReplayComparison{Output: output, ExpectedDigest: expected, ActualDigest: m, Result: resultUnavailable}
	}
	if actual == expected {
		return ReplayComparison{Output: output, ExpectedDigest: expected, ActualDigest: actual, Result: resultMatched}
	}
	return ReplayComparison{Output: output, ExpectedDigest: expected, ActualDigest: actual, Result: resultMismatched}
}

func aggregateResult(comparisons []ReplayComparison) string {
	for _, c := range comparisons {
		if c.Result == resultMismatched {
			return resultMismatched
		}
	}
	for _, c := range comparisons {
		if c.Result == resultUnavailable {
			return resultUnavailable
		}
	}
	return resultMatched
}

func normalizeMode(mode string) (string, error) {
	switch mode {
	case modeExactFixture:
		return modeExactFixture, nil
	case modeDiagnosticOnly, modeDiagnosticRederivation:
		return modeDiagnosticOnly, nil
	default:
		return "", fmt.Errorf("%w: mode %q must be %q, %q, or %q", ErrInvalid, mode, modeExactFixture, modeDiagnosticOnly, modeDiagnosticRederivation)
	}
}

func replayIDFor(bundle, source ArtifactReference, mode string) string {
	digest := evidence_codec.HashBytes([]byte("replay:" + bundle.Digest + ":" + source.Digest + ":" + mode))
	hex := strings.TrimPrefix(string(digest), "sha256:")
	if len(hex) > 32 {
		hex = hex[:32]
	}
	return "replay-" + hex
}

func replayEnginePin() VersionPin {
	return VersionPin{
		ID:             replayEngineID,
		Version:        replayEngineVersion,
		ArtifactDigest: string(evidence_codec.HashBytes([]byte("hellscape-replay-engine/v1"))),
	}
}

func reducerPinFor(mode string) any {
	if mode == modeExactFixture {
		return VersionPin{
			ID:             reducerID,
			Version:        reducerVersion,
			ArtifactDigest: string(evidence_codec.HashBytes([]byte("hellscape-fixture-reducer/v1"))),
		}
	}
	return newMissing("not_applicable", "")
}

func validateReceiptShape(receipt ReplayReceipt, mode string) error {
	if receipt.RecordType != receiptRecordType {
		return fmt.Errorf("%w: receipt record_type %q must be %q", ErrInvalid, receipt.RecordType, receiptRecordType)
	}
	if receipt.SchemaVersion != receiptSchema {
		return fmt.Errorf("%w: receipt schema_version %q must be %q", ErrInvalid, receipt.SchemaVersion, receiptSchema)
	}
	if strings.TrimSpace(receipt.ReplayID) == "" {
		return fmt.Errorf("%w: receipt replay_id is required", ErrInvalid)
	}
	if receipt.Mode != mode {
		return fmt.Errorf("%w: receipt mode %q does not match requested mode %q", ErrInvalid, receipt.Mode, mode)
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
	if err := validateVersionPinShape(receipt.Classifier, "receipt.classifier"); err != nil {
		return err
	}
	if mode == modeExactFixture {
		if _, ok := asVersionPin(receipt.Reducer); !ok {
			return fmt.Errorf("%w: exact_fixture receipt reducer must be a VersionPin", ErrInvalid)
		}
		if len(receipt.Comparisons) != 3 {
			return fmt.Errorf("%w: exact_fixture receipt must carry exactly 3 comparisons, got %d", ErrInvalid, len(receipt.Comparisons))
		}
	} else {
		missing, ok := asMissingEnvelope(receipt.Reducer)
		if !ok || missing.Reason != "not_applicable" {
			return fmt.Errorf("%w: diagnostic_only receipt reducer must be Missing(not_applicable)", ErrInvalid)
		}
		if len(receipt.Comparisons) != 1 || receipt.Comparisons[0].Output != comparisonDiagnostic {
			return fmt.Errorf("%w: diagnostic_only receipt must carry exactly the diagnostic comparison", ErrInvalid)
		}
	}
	seen := map[string]bool{}
	for i, c := range receipt.Comparisons {
		where := fmt.Sprintf("receipt.comparisons[%d]", i)
		if strings.TrimSpace(c.Output) == "" {
			return fmt.Errorf("%w: %s names no output", ErrInvalid, where)
		}
		if seen[c.Output] {
			return fmt.Errorf("%w: %s duplicates output %q", ErrInvalid, where, c.Output)
		}
		seen[c.Output] = true
		if !validDigest(c.ExpectedDigest) {
			return fmt.Errorf("%w: %s expected_digest %q is invalid", ErrInvalid, where, c.ExpectedDigest)
		}
		switch actual := c.ActualDigest.(type) {
		case string:
			if !validDigest(actual) {
				return fmt.Errorf("%w: %s actual_digest %q is invalid", ErrInvalid, where, actual)
			}
		default:
			if _, ok := asMissingEnvelope(c.ActualDigest); !ok {
				return fmt.Errorf("%w: %s actual_digest must be a digest or Missing", ErrInvalid, where)
			}
		}
		if c.Result != resultMatched && c.Result != resultMismatched && c.Result != resultUnavailable {
			return fmt.Errorf("%w: %s result %q is invalid", ErrInvalid, where, c.Result)
		}
		if _, isMissing := asMissingEnvelope(c.ActualDigest); isMissing && c.Result == resultMatched {
			return fmt.Errorf("%w: %s is matched with a Missing actual digest", ErrInvalid, where)
		}
	}
	if mode == modeExactFixture {
		for _, required := range []string{comparisonSemanticEvents, comparisonFinalState, comparisonDiagnostic} {
			if !seen[required] {
				return fmt.Errorf("%w: exact_fixture receipt omits %q comparison", ErrInvalid, required)
			}
		}
	}
	if expected := aggregateResult(receipt.Comparisons); receipt.Result != expected {
		return fmt.Errorf("%w: receipt result %q does not match the aggregate %q", ErrInvalid, receipt.Result, expected)
	}
	if receipt.Result == resultMatched {
		for _, c := range receipt.Comparisons {
			if _, isMissing := asMissingEnvelope(c.ActualDigest); isMissing {
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

// ---------------------------------------------------------------------------
// Source verification and artifact helpers.
// ---------------------------------------------------------------------------

func readAndHashArtifact(ctx context.Context, store *OwnerStore, ref ArtifactReference) ([]byte, error) {
	if !validDigest(ref.Digest) {
		return nil, fmt.Errorf("%w: artifact digest %q is invalid", ErrInvalid, ref.Digest)
	}
	raw, err := owner_store.ReadArtifact(ctx, store, ref)
	if err != nil {
		return nil, err
	}
	if string(evidence_codec.HashBytes(raw)) != ref.Digest {
		return nil, fmt.Errorf("%w: artifact bytes do not match %q", ErrIntegrityConflict, ref.Digest)
	}
	return raw, nil
}

func checkSourceMatchesRecorded(sourceBytes []byte, recorded DiagnosticDocument, digest string) error {
	sourceCanonical, err := evidence_codec.CanonicalJSON(sourceBytes, mediaTypeJSON)
	if err != nil {
		return fmt.Errorf("%w: source diagnostic bytes are not canonical JSON: %v", ErrInvalid, err)
	}
	recordedRaw, err := json.Marshal(recorded)
	if err != nil {
		return fmt.Errorf("%w: recorded diagnostic is not encodable: %v", ErrInvalid, err)
	}
	recordedCanonical, err := evidence_codec.CanonicalJSON(recordedRaw, mediaTypeJSON)
	if err != nil {
		return fmt.Errorf("%w: recorded diagnostic is not canonicalizable: %v", ErrInvalid, err)
	}
	if !bytes.Equal(sourceCanonical, recordedCanonical) {
		return fmt.Errorf("%w: source diagnostic %s does not match the bundled diagnostic", ErrIntegrityConflict, digest)
	}
	return nil
}

func isMissingArtifact(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "missing") || strings.Contains(msg, "lost") ||
		strings.Contains(msg, "not found") || strings.Contains(msg, "no such") ||
		strings.Contains(msg, "absent") || strings.Contains(msg, "unavailable")
}

func missingReasonOf(err error, digest string) string {
	if err == nil {
		return "not_observed"
	}
	if cfg, ok := err.(*configError); ok {
		return cfg.reason
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "not_applicable"):
		return "not_applicable"
	case strings.Contains(msg, "not_enabled"):
		return "not_enabled"
	case strings.Contains(msg, "redact"):
		return "redacted"
	case strings.Contains(msg, "lost"):
		return "observation_lost"
	default:
		_ = digest
		return "not_observed"
	}
}

// ---------------------------------------------------------------------------
// Small validators and canonical helpers.
// ---------------------------------------------------------------------------

func newMissing(reason, detail string) MissingEnvelope {
	m := journal_rules.NewMissing(reason)
	if detail != "" {
		m.Detail = detail
	}
	return m
}

func validDigest(s string) bool {
	if !strings.HasPrefix(s, "sha256:") || len(s) != 7+64 {
		return false
	}
	for _, c := range s[7:] {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func zeroDigest() string {
	return "sha256:" + strings.Repeat("0", 64)
}

func manifestDigestOf(manifest Manifest) (string, error) {
	raw, err := json.Marshal(manifest)
	if err != nil {
		return "", fmt.Errorf("%w: manifest is not encodable: %v", ErrInvalid, err)
	}
	canonical, err := evidence_codec.CanonicalJSON(raw, mediaTypeJSON)
	if err != nil {
		return "", fmt.Errorf("%w: manifest is not canonicalizable: %v", ErrInvalid, err)
	}
	return string(evidence_codec.HashBytes(canonical)), nil
}

func canonicalJSONOf(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return evidence_codec.CanonicalJSON(raw, mediaTypeJSON)
}

func validateVersionPinShape(pin VersionPin, field string) error {
	if strings.TrimSpace(pin.ID) == "" || strings.TrimSpace(pin.Version) == "" || !validDigest(pin.ArtifactDigest) {
		return fmt.Errorf("%w: %s must pin id, version, and a valid artifact_digest", ErrInvalid, field)
	}
	return nil
}

func validateArtifactRefShape(ref ArtifactReference, field string) error {
	if !validDigest(ref.Digest) {
		return fmt.Errorf("%w: %s digest %q is invalid", ErrInvalid, field, ref.Digest)
	}
	if ref.SizeBytes < 0 {
		return fmt.Errorf("%w: %s size_bytes is negative", ErrInvalid, field)
	}
	if strings.TrimSpace(ref.MediaType) == "" || strings.TrimSpace(ref.OwnerDomain) == "" {
		return fmt.Errorf("%w: %s must name media_type and owner_domain", ErrInvalid, field)
	}
	if ref.Access != "public" && ref.Access != "restricted" {
		return fmt.Errorf("%w: %s access %q must be public or restricted", ErrInvalid, field, ref.Access)
	}
	return nil
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
		if detail == "" {
			detail, _ = node["Detail"].(string)
		}
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
		return VersionPin{ID: id, Version: version, ArtifactDigest: digest}, true
	}
	return VersionPin{}, false
}

func toDiagnosticPin(pin VersionPin) diagnostic_reducer.VersionPin {
	return diagnostic_reducer.VersionPin{ID: pin.ID, Version: pin.Version, ArtifactDigest: pin.ArtifactDigest}
}

func pinFromValue(raw any) (diagnostic_reducer.VersionPin, error) {
	encoded, err := json.Marshal(raw)
	if err != nil {
		return diagnostic_reducer.VersionPin{}, err
	}
	var pin diagnostic_reducer.VersionPin
	if err := json.Unmarshal(encoded, &pin); err != nil {
		return diagnostic_reducer.VersionPin{}, err
	}
	if strings.TrimSpace(pin.ID) == "" || strings.TrimSpace(pin.Version) == "" || !validDigest(pin.ArtifactDigest) {
		return diagnostic_reducer.VersionPin{}, fmt.Errorf("pin must carry id, version, and a valid artifact_digest")
	}
	return pin, nil
}

func normalizeFixRegistry(raw any) (any, error) {
	if missing, ok := asMissingEnvelope(raw); ok {
		return diagnostic_reducer.Missing{Value: nil, Reason: missing.Reason, Detail: missing.Detail}, nil
	}
	pin, err := pinFromValue(raw)
	if err != nil {
		return nil, err
	}
	return pin, nil
}

func fixRegistryEqual(a, b any) bool {
	am, aMiss := asMissingEnvelope(a)
	bm, bMiss := asMissingEnvelope(b)
	if aMiss || bMiss {
		return aMiss && bMiss && am.Reason == bm.Reason && am.Detail == bm.Detail
	}
	ap, aok := asVersionPin(a)
	bp, bok := asVersionPin(b)
	// Diagnostic pins share the same shape; accept either alias.
	if !aok {
		if dp, err := pinFromValue(a); err == nil {
			ap, aok = VersionPin(dp), true
		}
	}
	if !bok {
		if dp, err := pinFromValue(b); err == nil {
			bp, bok = VersionPin(dp), true
		}
	}
	return aok && bok && ap == bp
}

func int64From(raw any) int64 {
	switch n := raw.(type) {
	case int64:
		return n
	case int:
		return int64(n)
	case int32:
		return int64(n)
	case float64:
		return int64(n)
	case float32:
		return int64(n)
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return i
		}
	}
	return -1
}

func looksLikeArtifactRef(node map[string]any) bool {
	_, hasDigest := node["digest"]
	_, hasSize := node["size_bytes"]
	_, hasMedia := node["media_type"]
	_, hasOwner := node["owner_domain"]
	_, hasAccess := node["access"]
	return hasDigest && hasSize && hasMedia && hasOwner && hasAccess
}

func artifactRefFromMap(node map[string]any) (ArtifactReference, error) {
	encoded, err := json.Marshal(node)
	if err != nil {
		return ArtifactReference{}, err
	}
	var ref ArtifactReference
	if err := json.Unmarshal(encoded, &ref); err != nil {
		return ArtifactReference{}, err
	}
	if err := validateArtifactRefShape(ref, "artifact_ref"); err != nil {
		return ArtifactReference{}, err
	}
	return ref, nil
}

func truncateDetail(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 300 {
		return s[:300] + "..."
	}
	return s
}

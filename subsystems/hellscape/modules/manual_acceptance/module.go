// Package manual_acceptance implements tier-9 Hellscape manual acceptance
// checking for the fourteen-step walkthrough (seam-mapping 16.6) and its
// companion cases (16.7).
//
// CheckManualAcceptance loads exact replay inputs via evidence_bundle,
// verifies the journal prefix, resolves every diagnostic reference inside the
// retained prefix, validates measurements via clock_rules, enforces
// structural gates via evidence_codec, and checks the diagnostic content
// required by feature-inventory 7.3:
//
//   - all eight workflow postconditions satisfied, application goal completed
//   - invalid history attempt preserved, history status recovered
//   - validation rejection not attributed to a subject
//   - timed pause in the measured interval agreeing with the independent
//     manual reference within declared uncertainty
//   - exactly one authoritative commitment; accepted values and document
//     digest match the synthetic task
//   - server-provenance identity; rendering separate from commitment
//   - no fabricated subject or native duration; R1-R10 not_exercised
//   - exact replay matched; references within the retained prefix closure
//
// Companion scenarios (stop before submit, repeat submit, incomplete field,
// browser close before flush, restart after acknowledgement) are validated
// for honest partial characterization, never fabricated completion.
package manual_acceptance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"

	clock_rules "clock_rules"
	evidence_bundle "evidence_bundle"
	evidence_codec "evidence_codec"
	journal_rules "journal_rules"
	owner_store "owner_store"
)

// ---------------------------------------------------------------------------
// Shared types.
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
	// EvidenceRef cites one retained journal event coordinate.
	EvidenceRef = journal_rules.EvidenceRef
	// ArtifactReference is an immutable byte identity plus metadata.
	ArtifactReference = journal_rules.ArtifactReference
	// Measurement is the EK Measurement record carried in payloads.
	Measurement = journal_rules.Measurement
	// ClockDescriptor registers one clock lifetime.
	ClockDescriptor = journal_rules.ClockDescriptor
	// TimePoint is a coordinate in a registered monotonic clock.
	TimePoint = journal_rules.TimePoint
	// MissingEnvelope is the typed EK Missing value.
	MissingEnvelope = journal_rules.MissingEnvelope
	// DiagnosticDocument is the deterministic analysis output.
	DiagnosticDocument = evidence_bundle.DiagnosticDocument
	// ReplayReceipt is the separate immutable replay record.
	ReplayReceipt = evidence_bundle.ReplayReceipt
	// ReplayComparison is one required replay comparison.
	ReplayComparison = evidence_bundle.ReplayComparison
)

// Compile-time CONSUMES linkage: fail compilation if a declared upstream
// signature disappears. The replay module has no implementation yet; the
// receipt is supplied by the caller and validated structurally, so no
// replay import is required.
var (
	_ = evidence_bundle.LoadReplayInputs
	_ = journal_rules.ResolveEvidence
	_ = journal_rules.ValidateJournal
	_ = clock_rules.ValidateMeasurement
	_ = evidence_codec.ValidateRecord
	_ = owner_store.ReadArtifact
)

// Sentinel errors.
var (
	ErrInvalid     = errors.New("manual_acceptance: invalid input")
	ErrMismatch    = errors.New("manual_acceptance: acceptance mismatch")
	ErrIncomplete  = errors.New("manual_acceptance: incomplete acceptance evidence")
	ErrNotHonest   = errors.New("manual_acceptance: dishonest characterization")
	ErrOutOfPrefix = errors.New("manual_acceptance: reference outside retained prefix")
)

// Scenarios.
const (
	ScenarioFullWalkthrough     = "full_walkthrough"
	ScenarioStopBeforeSubmit    = "stop_before_submit"
	ScenarioRepeatSubmit        = "repeat_submit"
	ScenarioIncompleteField     = "incomplete_field"
	ScenarioBrowserClose        = "browser_close_before_flush"
	ScenarioRestartAfterAck     = "restart_after_ack"
)

// Workflow states.
const (
	StateListing      = "LISTING"
	StateDetail       = "DETAIL"
	StateContact      = "CONTACT"
	StateHistory      = "HISTORY"
	StateUpload       = "UPLOAD"
	StateIdentity     = "IDENTITY"
	StateReview       = "REVIEW"
	StateConfirmation = "CONFIRMATION"
)

// Manual walkthrough event kinds.
const (
	EKListingObserved      = "listing_observed"
	EKJobSelected          = "job_selected"
	EKContactAccepted      = "contact_accepted"
	EKHistoryEntered       = "history_entered"
	EKHistoryRejected      = "history_rejected"
	EKHistoryErrorObserved = "history_error_observed"
	EKHistoryCorrected     = "history_corrected"
	EKDocumentUploaded     = "document_uploaded"
	EKIdentityVerified     = "identity_verified"
	EKReviewValidated      = "review_validated"
	EKPauseRecorded        = "pause_recorded"
	EKSubmissionCommitted  = "submission_committed"
	EKConfirmationRendered = "confirmation_rendered"
	EKObservationClosed    = "observation_closed"
	EKSubmissionRepeated   = "submission_repeated"
	EKBrowserClosed        = "browser_closed"
	EKObservationRestarted = "observation_restarted"
)

// fullStepOrder is the required event order for the fourteen-step walkthrough.
var fullStepOrder = []string{
	EKListingObserved,
	EKJobSelected,
	EKContactAccepted,
	EKHistoryEntered,
	EKHistoryRejected,
	EKHistoryErrorObserved,
	EKHistoryCorrected,
	EKDocumentUploaded,
	EKIdentityVerified,
	EKReviewValidated,
	EKPauseRecorded,
	EKSubmissionCommitted,
	EKConfirmationRendered,
	EKObservationClosed,
}

var requiredPostconditions = []string{
	StateListing, StateDetail, StateContact, StateHistory,
	StateUpload, StateIdentity, StateReview, StateConfirmation,
}

// AcceptanceCheck is one named acceptance result.
type AcceptanceCheck struct {
	ID     string `json:"id"`
	Step   int    `json:"step,omitempty"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// AcceptanceReport is the acceptance artifact returned by CheckManualAcceptance.
type AcceptanceReport struct {
	RecordType             string            `json:"record_type"`
	SchemaVersion          string            `json:"schema_version"`
	Scenario               string            `json:"scenario"`
	Result                 string            `json:"result"`
	DiagnosticID           string            `json:"diagnostic_id"`
	InputPrefix            JournalPrefix     `json:"input_prefix"`
	ReplayResult           string            `json:"replay_result"`
	Checks                 []AcceptanceCheck `json:"checks"`
	WorkflowPostconditions map[string]bool   `json:"workflow_postconditions,omitempty"`
}

// CheckManualAcceptance validates one manual acceptance bundle against its
// replay receipt and returns the canonical acceptance-checks JSON.
//
// It loads exact replay inputs, verifies the journal prefix, resolves every
// diagnostic reference within the retained prefix, validates measurements,
// rejects fabricated subjects or durations, enforces R1-R10 not_exercised,
// and checks scenario-specific workflow and diagnostic content.
func CheckManualAcceptance(ctx context.Context, store *OwnerStore, inputs ArtifactReference, receipt ReplayReceipt) ([]byte, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: store is required", ErrInvalid)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(inputs.Digest) == "" {
		return nil, fmt.Errorf("%w: inputs artifact reference is required", ErrInvalid)
	}

	manifest, events, diagnostic, err := evidence_bundle.LoadReplayInputs(ctx, store, inputs)
	if err != nil {
		return nil, fmt.Errorf("%w: load replay inputs: %v", ErrIncomplete, err)
	}
	if len(events) == 0 {
		return nil, fmt.Errorf("%w: journal is empty", ErrIncomplete)
	}

	if err := validateReceipt(receipt, diagnostic, inputs); err != nil {
		return nil, err
	}

	prefix, err := validatePrefixAndJournal(manifest, events, diagnostic)
	if err != nil {
		return nil, err
	}

	if err := validateMeasurements(manifest, events); err != nil {
		return nil, err
	}

	extra := diagnostic.Extra
	if extra == nil {
		extra = map[string]any{}
	}

	if err := validateNoSubjectFabrication(events, extra); err != nil {
		return nil, err
	}
	if err := validateRequirementAssessments(extra); err != nil {
		return nil, err
	}
	if err := validateReferences(prefix, events, diagnostic); err != nil {
		return nil, err
	}
	if err := validateReproduction(extra, receipt); err != nil {
		return nil, err
	}

	scenario := extraString(extra, "scenario")
	if scenario == "" {
		scenario = ScenarioFullWalkthrough
	}

	var checks []AcceptanceCheck
	var postconditions map[string]bool
	switch scenario {
	case ScenarioFullWalkthrough:
		checks, postconditions, err = validateFullWalkthrough(events, extra)
	case ScenarioStopBeforeSubmit:
		checks, postconditions, err = validateStopBeforeSubmit(events, extra)
	case ScenarioRepeatSubmit:
		checks, postconditions, err = validateRepeatSubmit(events, extra)
	case ScenarioIncompleteField:
		checks, postconditions, err = validateIncompleteField(events, extra)
	case ScenarioBrowserClose:
		checks, postconditions, err = validateBrowserClose(events, extra)
	case ScenarioRestartAfterAck:
		checks, postconditions, err = validateRestartAfterAck(events, extra)
	default:
		return nil, fmt.Errorf("%w: unknown scenario %q", ErrInvalid, scenario)
	}
	if err != nil {
		return nil, err
	}

	// Structural gate on the acceptance report itself: no bare nulls.
	report := AcceptanceReport{
		RecordType:             "acceptance_checks",
		SchemaVersion:          "1.0.0",
		Scenario:               scenario,
		Result:                 "pass",
		DiagnosticID:           diagnostic.DiagnosticID,
		InputPrefix:            prefix,
		ReplayResult:           receipt.Result,
		Checks:                 checks,
		WorkflowPostconditions: postconditions,
	}
	raw, err := json.Marshal(report)
	if err != nil {
		return nil, fmt.Errorf("%w: encode acceptance report: %v", ErrInvalid, err)
	}
	canonical, err := evidence_codec.CanonicalJSON(raw, "application/json")
	if err != nil {
		return nil, fmt.Errorf("%w: canonicalize acceptance report: %v", ErrInvalid, err)
	}
	if err := rejectBareNulls(canonical); err != nil {
		return nil, err
	}
	return canonical, nil
}

// ---------------------------------------------------------------------------
// Receipt validation.
// ---------------------------------------------------------------------------

func validateReceipt(receipt ReplayReceipt, diagnostic DiagnosticDocument, inputs ArtifactReference) error {
	if receipt.RecordType != "replay_receipt" {
		return fmt.Errorf("%w: receipt record_type %q must be replay_receipt", ErrInvalid, receipt.RecordType)
	}
	if receipt.SchemaVersion != "1.0.0" {
		return fmt.Errorf("%w: receipt schema_version %q must be 1.0.0", ErrInvalid, receipt.SchemaVersion)
	}
	if receipt.Mode != "exact_fixture" {
		return fmt.Errorf("%w: manual acceptance requires exact_fixture replay, got %q", ErrMismatch, receipt.Mode)
	}
	if receipt.Result != "matched" {
		return fmt.Errorf("%w: exact replay result %q must be matched", ErrMismatch, receipt.Result)
	}
	if receipt.InvokedBrowser || receipt.InvokedSubject || receipt.PerformedExternalWrites {
		return fmt.Errorf("%w: replay must not invoke browser/subject or perform external writes", ErrMismatch)
	}
	if receipt.ManifestHash != diagnostic.ManifestHash {
		return fmt.Errorf("%w: receipt manifest_hash does not match diagnostic manifest_hash", ErrMismatch)
	}
	if receipt.SourcePrefix.JournalID != diagnostic.InputPrefix.JournalID ||
		receipt.SourcePrefix.LastSequence != diagnostic.InputPrefix.LastSequence ||
		receipt.SourcePrefix.HeadHash != diagnostic.InputPrefix.HeadHash {
		return fmt.Errorf("%w: receipt source prefix does not match diagnostic input prefix", ErrMismatch)
	}
	if receipt.InputBundle.Digest != inputs.Digest {
		return fmt.Errorf("%w: receipt input bundle does not name the supplied inputs", ErrMismatch)
	}
	need := map[string]bool{"semantic_events": false, "final_state": false, "diagnostic": false}
	for _, c := range receipt.Comparisons {
		if _, ok := need[c.Output]; !ok {
			continue
		}
		if c.Result != "matched" {
			return fmt.Errorf("%w: replay comparison %q result %q must be matched", ErrMismatch, c.Output, c.Result)
		}
		if strings.TrimSpace(c.ExpectedDigest) == "" {
			return fmt.Errorf("%w: replay comparison %q has empty expected digest", ErrInvalid, c.Output)
		}
		need[c.Output] = true
	}
	for output, seen := range need {
		if !seen {
			return fmt.Errorf("%w: exact fixture replay requires %q comparison", ErrIncomplete, output)
		}
	}
	if receipt.Classifier.ID != diagnostic.Classifier.ID ||
		receipt.Classifier.Version != diagnostic.Classifier.Version ||
		receipt.Classifier.ArtifactDigest != diagnostic.Classifier.ArtifactDigest {
		return fmt.Errorf("%w: receipt classifier does not match diagnostic classifier", ErrMismatch)
	}
	if isMissingValue(receipt.Reducer) {
		return fmt.Errorf("%w: exact_fixture replay requires a pinned reducer, got Missing", ErrIncomplete)
	}
	// Structural gate on the receipt envelope.
	raw, err := json.Marshal(receipt)
	if err != nil {
		return fmt.Errorf("%w: encode receipt: %v", ErrInvalid, err)
	}
	if err := evidence_codec.ValidateRecord("1.0.0", "replay_receipt", raw); err != nil {
		// The evidence_bundle receipt carries more fields than the minimal
		// codec shape; enforce no-bare-nulls only.
		if !strings.Contains(err.Error(), "unknown closed-object field") {
			return fmt.Errorf("%w: receipt structural gate: %v", ErrInvalid, err)
		}
		if err := rejectBareNulls(raw); err != nil {
			return fmt.Errorf("%w: receipt contains bare nulls: %v", ErrInvalid, err)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Prefix and journal validation.
// ---------------------------------------------------------------------------

func validatePrefixAndJournal(manifest Manifest, events []JournalEnvelope, diagnostic DiagnosticDocument) (JournalPrefix, error) {
	empty := JournalPrefix{}
	manifestRaw, err := json.Marshal(manifest)
	if err != nil {
		return empty, fmt.Errorf("%w: encode manifest: %v", ErrInvalid, err)
	}
	if err := evidence_codec.ValidateRecord(manifest.SchemaVersion, "manifest", manifestRaw); err != nil {
		return empty, fmt.Errorf("%w: manifest structural gate: %v", ErrInvalid, err)
	}
	verified, err := journal_rules.ValidateJournal(manifest, events)
	if err != nil {
		return empty, fmt.Errorf("%w: journal invalid: %v", ErrMismatch, err)
	}
	if verified.JournalID != diagnostic.InputPrefix.JournalID ||
		verified.LastSequence != diagnostic.InputPrefix.LastSequence ||
		verified.HeadHash != diagnostic.InputPrefix.HeadHash {
		return empty, fmt.Errorf("%w: diagnostic input prefix does not match verified prefix", ErrMismatch)
	}
	// Every event envelope must pass the structural gate individually.
	for i := range events {
		evRaw, err := json.Marshal(events[i])
		if err != nil {
			return empty, fmt.Errorf("%w: encode event %d: %v", ErrInvalid, events[i].Sequence, err)
		}
		if err := evidence_codec.ValidateRecord(events[i].SchemaVersion, "journal_event", evRaw); err != nil {
			return empty, fmt.Errorf("%w: event %d structural gate: %v", ErrInvalid, events[i].Sequence, err)
		}
	}
	return verified, nil
}

// ---------------------------------------------------------------------------
// Measurement validation.
// ---------------------------------------------------------------------------

func validateMeasurements(manifest Manifest, events []JournalEnvelope) error {
	clocks := make([]clock_rules.ClockDescriptor, 0, len(manifest.Clocks))
	for _, cd := range manifest.Clocks {
		clocks = append(clocks, clock_rules.ClockDescriptor{
			ClockID: cd.ClockID, BootID: cd.BootID, Origin: cd.Origin,
			SourceID: cd.SourceID, Basis: cd.Basis, Unit: cd.Unit,
		})
	}
	for _, ev := range events {
		for mi, meas := range ev.Payload.Measurements {
			if meas.Origin == "subject_reported" {
				return fmt.Errorf("%w: event %d measurement %q has subject_reported origin: no native subject is exercised in manual mode",
					ErrMismatch, ev.Sequence, meas.MeasurementID)
			}
			cm, err := convertMeasurement(meas)
			if err != nil {
				return fmt.Errorf("%w: event %d measurements[%d]: %v", ErrInvalid, ev.Sequence, mi, err)
			}
			if err := clock_rules.ValidateMeasurement(cm, clocks); err != nil {
				return fmt.Errorf("%w: event %d measurement %q: %v", ErrMismatch, ev.Sequence, meas.MeasurementID, err)
			}
		}
	}
	return nil
}

// --- journal_rules -> clock_rules conversion (handles struct and map forms
// after bundle JSON round-trips). ---

func asMissingAny(v any) (clock_rules.Missing, bool) {
	switch m := v.(type) {
	case MissingEnvelope:
		if m.Value == nil && m.Reason != "" {
			return clock_rules.Missing{Reason: m.Reason, Detail: m.Detail}, true
		}
	case *MissingEnvelope:
		if m != nil && m.Value == nil && m.Reason != "" {
			return clock_rules.Missing{Reason: m.Reason, Detail: m.Detail}, true
		}
	case clock_rules.Missing:
		if m.Reason != "" {
			return m, true
		}
	case map[string]any:
		raw, hasValue := m["value"]
		if !hasValue || raw != nil {
			return clock_rules.Missing{}, false
		}
		reason, _ := m["reason"].(string)
		if reason == "" {
			return clock_rules.Missing{}, false
		}
		detail, _ := m["detail"].(string)
		return clock_rules.Missing{Reason: reason, Detail: detail}, true
	}
	return clock_rules.Missing{}, false
}

func asTimePointAny(v any) (TimePoint, bool) {
	switch t := v.(type) {
	case TimePoint:
		return t, true
	case *TimePoint:
		if t != nil {
			return *t, true
		}
	case map[string]any:
		clockID, _ := t["clock_id"].(string)
		bootID, _ := t["boot_id"].(string)
		origin, _ := t["origin"].(string)
		if clockID == "" || bootID == "" || origin == "" {
			return TimePoint{}, false
		}
		offset, ok := asFloatAny(t["monotonic_offset_ms"])
		if !ok {
			return TimePoint{}, false
		}
		utc, hasUTC := t["utc_annotation"]
		if !hasUTC {
			return TimePoint{}, false
		}
		return TimePoint{ClockID: clockID, BootID: bootID, Origin: origin, MonotonicOffsetMs: offset, UTCAnnotation: utc}, true
	}
	return TimePoint{}, false
}

func asFloatAny(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	case uint64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		if err != nil {
			return 0, false
		}
		return f, true
	}
	return 0, false
}

func convertUTC(v any) (any, error) {
	if m, ok := asMissingAny(v); ok {
		return m, nil
	}
	if s, ok := v.(string); ok {
		return s, nil
	}
	return nil, fmt.Errorf("utc_annotation must be date-time or Missing, got %T", v)
}

func convertEndpoint(v any) (any, error) {
	if v == nil {
		return nil, errors.New("endpoint is an in-band null")
	}
	if m, ok := asMissingAny(v); ok {
		return m, nil
	}
	if tp, ok := asTimePointAny(v); ok {
		utc, err := convertUTC(tp.UTCAnnotation)
		if err != nil {
			return nil, err
		}
		return clock_rules.TimePoint{
			ClockID: tp.ClockID, BootID: tp.BootID, Origin: tp.Origin,
			MonotonicOffsetMs: tp.MonotonicOffsetMs, UTCAnnotation: utc,
		}, nil
	}
	return nil, fmt.Errorf("endpoint must be TimePoint or Missing, got %T", v)
}

func convertNumberOrMissing(v any) (any, error) {
	if v == nil {
		return nil, errors.New("value is an in-band null")
	}
	if m, ok := asMissingAny(v); ok {
		return m, nil
	}
	if n, ok := asFloatAny(v); ok {
		if math.IsNaN(n) || math.IsInf(n, 0) {
			return nil, fmt.Errorf("value must be finite, got %v", n)
		}
		return n, nil
	}
	return nil, fmt.Errorf("value must be numeric or Missing, got %T", v)
}

func convertStringOrMissing(v any) (any, error) {
	if v == nil {
		return nil, errors.New("value is an in-band null")
	}
	if m, ok := asMissingAny(v); ok {
		return m, nil
	}
	if s, ok := v.(string); ok {
		return s, nil
	}
	return nil, fmt.Errorf("value must be identifier or Missing, got %T", v)
}

func convertEstimate(kind string, value, lo, hi any) (clock_rules.Estimate, error) {
	switch kind {
	case "exact":
		if value == nil {
			return clock_rules.Estimate{}, errors.New("exact estimate value is an in-band null")
		}
		if _, ok := asMissingAny(value); ok {
			return clock_rules.Estimate{}, errors.New("exact estimate value must be numeric")
		}
		n, ok := asFloatAny(value)
		if !ok {
			return clock_rules.Estimate{}, fmt.Errorf("exact estimate value must be numeric, got %T", value)
		}
		if lo != nil || hi != nil {
			return clock_rules.Estimate{}, errors.New("exact estimate must not carry bounds")
		}
		return clock_rules.Estimate{Kind: "exact", Value: n}, nil
	case "bounded":
		if value != nil {
			return clock_rules.Estimate{}, errors.New("bounded estimate must not carry an exact value")
		}
		if lo == nil || hi == nil {
			return clock_rules.Estimate{}, errors.New("bounded estimate bounds must each be numeric or Missing")
		}
		loConv, err := convertNumberOrMissing(lo)
		if err != nil {
			return clock_rules.Estimate{}, err
		}
		hiConv, err := convertNumberOrMissing(hi)
		if err != nil {
			return clock_rules.Estimate{}, err
		}
		return clock_rules.Estimate{Kind: "bounded", LowerBound: loConv, UpperBound: hiConv}, nil
	case "unavailable":
		if value == nil {
			return clock_rules.Estimate{}, errors.New("unavailable estimate value is an in-band null")
		}
		m, ok := asMissingAny(value)
		if !ok {
			return clock_rules.Estimate{}, fmt.Errorf("unavailable estimate value must be Missing, got %T", value)
		}
		if lo != nil || hi != nil {
			return clock_rules.Estimate{}, errors.New("unavailable estimate must not carry bounds")
		}
		return clock_rules.Estimate{Kind: "unavailable", Value: m}, nil
	}
	return clock_rules.Estimate{}, fmt.Errorf("estimate kind %q must be exact, bounded, or unavailable", kind)
}

func convertMeasurement(m Measurement) (clock_rules.Measurement, error) {
	start, err := convertEndpoint(m.Start)
	if err != nil {
		return clock_rules.Measurement{}, fmt.Errorf("start: %v", err)
	}
	end, err := convertEndpoint(m.End)
	if err != nil {
		return clock_rules.Measurement{}, fmt.Errorf("end: %v", err)
	}
	est, err := convertEstimate(m.Estimate.Kind, m.Estimate.Value, m.Estimate.LowerBound, m.Estimate.UpperBound)
	if err != nil {
		return clock_rules.Measurement{}, fmt.Errorf("estimate: %v", err)
	}
	res, err := convertNumberOrMissing(m.Resolution)
	if err != nil {
		return clock_rules.Measurement{}, fmt.Errorf("resolution: %v", err)
	}
	cg, err := convertStringOrMissing(m.ComparabilityGroup)
	if err != nil {
		return clock_rules.Measurement{}, fmt.Errorf("comparability_group: %v", err)
	}
	return clock_rules.Measurement{
		MeasurementID: m.MeasurementID, Name: m.Name,
		Scope:    clock_rules.Scope{Kind: m.Scope.Kind, ID: m.Scope.ID},
		Quantity: m.Quantity, Unit: m.Unit, Origin: m.Origin,
		ClockID: m.ClockID, BootID: m.BootID, Method: m.Method,
		Start: start, End: end, Estimate: est,
		Resolution: res, Censoring: m.Censoring,
		ComparabilityGroup: cg, AggregateSource: m.AggregateSource,
	}, nil
}

// ---------------------------------------------------------------------------
// Subject, requirements, references, reproduction.
// ---------------------------------------------------------------------------

func validateNoSubjectFabrication(events []JournalEnvelope, extra map[string]any) error {
	for _, ev := range events {
		for _, meas := range ev.Payload.Measurements {
			if meas.Origin == clock_rules.OriginSubjectReported {
				return fmt.Errorf("%w: measurement %q claims subject_reported origin without an automation subject",
					ErrMismatch, meas.MeasurementID)
			}
		}
		if provenance := strings.ToLower(fmt.Sprintf("%v", extraValue(extra, "provenance"))); provenance == "subject" {
			return fmt.Errorf("%w: manual execution has no automation subject", ErrMismatch)
		}
	}
	if execMap, ok := extra["execution"].(map[string]any); ok {
		if subject, present := execMap["subject"]; present {
			if !isMissingValue(subject) {
				// A null subject may appear as Missing only; any concrete
				// subject identity is fabrication in manual mode.
				if s, ok := subject.(string); ok && s != "" {
					return fmt.Errorf("%w: execution.subject %q is fabricated: manual mode has no automation subject", ErrMismatch, s)
				}
				if m, ok := subject.(map[string]any); ok {
					if _, hasID := m["subject_id"]; hasID {
						return fmt.Errorf("%w: execution.subject is fabricated: manual mode has no automation subject", ErrMismatch)
					}
					if !isMissingValue(subject) {
						return fmt.Errorf("%w: execution.subject must be Missing (manual mode has no subject)", ErrMismatch)
					}
				}
			}
		}
	}
	if locus, ok := extra["defect_locus"].(string); ok && locus == "subject" {
		return fmt.Errorf("%w: ordinary validation rejection is not attributed to a subject", ErrMismatch)
	}
	return nil
}

func validateRequirementAssessments(extra map[string]any) error {
	raw, ok := extra["requirement_assessments"]
	if !ok {
		return fmt.Errorf("%w: requirement_assessments is required", ErrIncomplete)
	}
	list, ok := raw.([]any)
	if !ok {
		return fmt.Errorf("%w: requirement_assessments must be a list", ErrInvalid)
	}
	seen := map[string]bool{}
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			return fmt.Errorf("%w: requirement assessment must be an object", ErrInvalid)
		}
		id, _ := m["id"].(string)
		result, _ := m["result"].(string)
		reason, _ := m["reason"].(string)
		if id == "" {
			return fmt.Errorf("%w: requirement assessment without id", ErrInvalid)
		}
		seen[id] = true
		if result != "not_exercised" {
			return fmt.Errorf("%w: requirement %s result %q must be not_exercised in manual mode: no subject is exercised",
				ErrMismatch, id, result)
		}
		if reason != "manual_fixture_validation" {
			return fmt.Errorf("%w: requirement %s reason %q must be manual_fixture_validation", ErrMismatch, id, reason)
		}
	}
	for i := 1; i <= 10; i++ {
		id := fmt.Sprintf("R%d", i)
		if !seen[id] {
			return fmt.Errorf("%w: requirement %s is missing: R1-R10 must all be not_exercised", ErrIncomplete, id)
		}
	}
	return nil
}

func validateReferences(prefix JournalPrefix, events []JournalEnvelope, diagnostic DiagnosticDocument) error {
	if _, err := journal_rules.ResolveEvidence(prefix, events, diagnostic.AnalysisRequestRef); err != nil {
		return fmt.Errorf("%w: analysis_request_ref: %v", ErrOutOfPrefix, err)
	}
	for i, ref := range diagnostic.EvidenceRefs {
		if _, err := journal_rules.ResolveEvidence(prefix, events, ref); err != nil {
			return fmt.Errorf("%w: evidence_refs[%d]: %v", ErrOutOfPrefix, i, err)
		}
	}
	var extraRefs []EvidenceRef
	collectExtraRefs(diagnostic.Extra, &extraRefs)
	for i, ref := range extraRefs {
		if _, err := journal_rules.ResolveEvidence(prefix, events, ref); err != nil {
			return fmt.Errorf("%w: extra reference[%d] (%s/%d): %v", ErrOutOfPrefix, i, ref.JournalID, ref.Sequence, err)
		}
	}
	return nil
}

func collectExtraRefs(node any, out *[]EvidenceRef) {
	switch v := node.(type) {
	case map[string]any:
		if ref, ok := parseEvidenceRefMap(v); ok {
			*out = append(*out, ref)
		}
		for _, child := range v {
			collectExtraRefs(child, out)
		}
	case []any:
		for _, child := range v {
			collectExtraRefs(child, out)
		}
	case EvidenceRef:
		*out = append(*out, v)
	case *EvidenceRef:
		if v != nil {
			*out = append(*out, *v)
		}
	}
}

func parseEvidenceRefMap(m map[string]any) (EvidenceRef, bool) {
	journalID, _ := m["journal_id"].(string)
	eventID, _ := m["event_id"].(string)
	eventHash, _ := m["event_hash"].(string)
	pointer, _ := m["pointer"].(string)
	if journalID == "" || eventID == "" || eventHash == "" {
		return EvidenceRef{}, false
	}
	if _, hasPointer := m["pointer"]; !hasPointer {
		return EvidenceRef{}, false
	}
	seqRaw, hasSeq := m["sequence"]
	if !hasSeq {
		return EvidenceRef{}, false
	}
	var seq int64
	switch n := seqRaw.(type) {
	case int:
		seq = int64(n)
	case int32:
		seq = int64(n)
	case int64:
		seq = n
	case float64:
		seq = int64(n)
	case json.Number:
		parsed, err := n.Int64()
		if err != nil {
			return EvidenceRef{}, false
		}
		seq = parsed
	default:
		return EvidenceRef{}, false
	}
	_ = pointer
	return EvidenceRef{JournalID: journalID, Sequence: seq, EventID: eventID, EventHash: eventHash, Pointer: pointer}, true
}

func validateReproduction(extra map[string]any, receipt ReplayReceipt) error {
	rep, ok := extra["reproduction"].(map[string]any)
	if !ok {
		return fmt.Errorf("%w: reproduction section is required", ErrIncomplete)
	}
	status, _ := rep["exact_replay"].(string)
	if status != "matched" {
		return fmt.Errorf("%w: reproduction.exact_replay %q must be matched", ErrMismatch, status)
	}
	if receipt.Result != "matched" {
		return fmt.Errorf("%w: receipt result %q must be matched", ErrMismatch, receipt.Result)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Full fourteen-step walkthrough.
// ---------------------------------------------------------------------------

func validateFullWalkthrough(events []JournalEnvelope, extra map[string]any) ([]AcceptanceCheck, map[string]bool, error) {
	outcome, _ := extra["outcome"].(map[string]any)
	if outcome == nil {
		return nil, nil, fmt.Errorf("%w: outcome section is required", ErrIncomplete)
	}
	if goal, _ := outcome["application_goal"].(string); goal != "completed" {
		return nil, nil, fmt.Errorf("%w: outcome.application_goal %q must be completed", ErrMismatch, goal)
	}
	if met, _ := outcome["expectation_met"].(bool); !met {
		return nil, nil, fmt.Errorf("%w: outcome.expectation_met must be true", ErrMismatch)
	}

	postconditions, err := requirePostconditions(extra, requiredPostconditions)
	if err != nil {
		return nil, nil, err
	}

	// Steps must appear in order.
	prevIndex := -1
	for _, kind := range fullStepOrder {
		idx := indexOfKind(events, kind, prevIndex+1)
		if idx < 0 {
			return nil, nil, fmt.Errorf("%w: required step event %q is missing or out of order", ErrIncomplete, kind)
		}
		prevIndex = idx
	}

	var checks []AcceptanceCheck
	pass := func(id string, step int, detail string) {
		checks = append(checks, AcceptanceCheck{ID: id, Step: step, Status: "pass", Detail: detail})
	}

	// Step 1: listing readiness observation.
	listing := findKind(events, EKListingObserved)
	if dataString(listing, "workflow_state") != StateListing {
		return nil, nil, fmt.Errorf("%w: listing_observed must record LISTING workflow state", ErrMismatch)
	}
	if !dataBool(listing, "readiness") {
		return nil, nil, fmt.Errorf("%w: listing_observed must record readiness observation", ErrMismatch)
	}
	if dataString(listing, "entry_url") == "" {
		return nil, nil, fmt.Errorf("%w: listing_observed must cite the ordinary entry URL", ErrIncomplete)
	}
	pass("listing_readiness", 1, "LISTING readiness observation recorded")

	// Step 2: specified job selection commits DETAIL.
	selected := findKind(events, EKJobSelected)
	if dataString(selected, "workflow_state") != StateDetail {
		return nil, nil, fmt.Errorf("%w: job_selected must record DETAIL transition", ErrMismatch)
	}
	if dataString(selected, "job_id") == "" || dataString(selected, "transaction") == "" {
		return nil, nil, fmt.Errorf("%w: job_selected must cite the specified job and selection transaction", ErrIncomplete)
	}
	pass("job_selection", 2, "specified job selection commits DETAIL")

	// Step 3: valid contact records current accepted revision.
	contact := findKind(events, EKContactAccepted)
	if dataString(contact, "workflow_state") != StateContact {
		return nil, nil, fmt.Errorf("%w: contact_accepted must record CONTACT transition", ErrMismatch)
	}
	if !dataBool(contact, "accepted") {
		return nil, nil, fmt.Errorf("%w: contact_accepted must record acceptance", ErrMismatch)
	}
	contactRev := dataInt(contact, "value_revision")
	if contactRev < 1 {
		return nil, nil, fmt.Errorf("%w: contact_accepted must record a current accepted revision", ErrIncomplete)
	}
	pass("contact_accepted", 3, "current accepted contact revision recorded")

	// Step 4: continue to history checks contact currency.
	entered := findKind(events, EKHistoryEntered)
	if dataString(entered, "workflow_state") != StateHistory {
		return nil, nil, fmt.Errorf("%w: history_entered must record HISTORY transition", ErrMismatch)
	}
	if !dataBool(entered, "contact_currency") {
		return nil, nil, fmt.Errorf("%w: history_entered must record a contact-currency check", ErrMismatch)
	}
	if dataInt(entered, "contact_revision") != contactRev {
		return nil, nil, fmt.Errorf("%w: history_entered contact revision must match the current accepted contact", ErrMismatch)
	}
	pass("history_enter", 4, "contact-currency check commits HISTORY")

	// Step 5: invalid history attempt preserved as rejected.
	rejected := findKind(events, EKHistoryRejected)
	if dataString(rejected, "workflow_state") != StateHistory {
		return nil, nil, fmt.Errorf("%w: history_rejected must remain in HISTORY", ErrMismatch)
	}
	if dataString(rejected, "outcome") != "rejected" {
		return nil, nil, fmt.Errorf("%w: history_rejected outcome must be rejected", ErrMismatch)
	}
	if err := requireRejectedAttempt(extra); err != nil {
		return nil, nil, err
	}
	pass("history_rejected", 5, "rejected history attempt preserved")

	// Step 6: visible error leaves workflow in HISTORY.
	observed := findKind(events, EKHistoryErrorObserved)
	if dataString(observed, "workflow_state") != StateHistory {
		return nil, nil, fmt.Errorf("%w: history_error_observed must leave workflow in HISTORY", ErrMismatch)
	}
	if !dataBool(observed, "error_visible") {
		return nil, nil, fmt.Errorf("%w: history_error_observed must record a visible UI error", ErrMismatch)
	}
	pass("history_error", 6, "visible error leaves workflow in HISTORY")

	// Step 7: correction produces recovered step and UPLOAD.
	corrected := findKind(events, EKHistoryCorrected)
	if dataString(corrected, "workflow_state") != StateUpload {
		return nil, nil, fmt.Errorf("%w: history_corrected must record UPLOAD transition", ErrMismatch)
	}
	if err := requireRecoveredHistory(extra); err != nil {
		return nil, nil, err
	}
	pass("history_recovered", 7, "corrected history recovers step and commits UPLOAD")

	// Step 8: synthetic document upload verifies digest, IDENTITY.
	uploaded := findKind(events, EKDocumentUploaded)
	if dataString(uploaded, "workflow_state") != StateIdentity {
		return nil, nil, fmt.Errorf("%w: document_uploaded must record IDENTITY transition", ErrMismatch)
	}
	digest := dataString(uploaded, "document_digest")
	if !isDigest(digest) {
		return nil, nil, fmt.Errorf("%w: document_uploaded must record a valid document digest", ErrIncomplete)
	}
	if !dataBool(uploaded, "durable") {
		return nil, nil, fmt.Errorf("%w: document_uploaded must record durable exact bytes", ErrMismatch)
	}
	if len(uploaded.Payload.ArtifactRefs) == 0 {
		return nil, nil, fmt.Errorf("%w: document_uploaded must carry the installed document artifact", ErrIncomplete)
	}
	if err := requireTaskMatch(extra, digest); err != nil {
		return nil, nil, err
	}
	pass("document_upload", 8, "synthetic document digest verified")

	// Step 9: local identity action records origin-verified REVIEW.
	verified := findKind(events, EKIdentityVerified)
	if dataString(verified, "workflow_state") != StateReview {
		return nil, nil, fmt.Errorf("%w: identity_verified must record REVIEW transition", ErrMismatch)
	}
	if dataString(verified, "provenance") != "server" {
		return nil, nil, fmt.Errorf("%w: identity_verified must have server provenance", ErrMismatch)
	}
	identity, _ := extra["identity"].(map[string]any)
	if identity == nil || identity["provenance"] != "server" {
		return nil, nil, fmt.Errorf("%w: identity verification must have server provenance", ErrMismatch)
	}
	pass("identity_verified", 9, "origin-verified identity commits REVIEW")

	// Step 10: review validation pins current prerequisite revisions.
	review := findKind(events, EKReviewValidated)
	if dataString(review, "workflow_state") != StateReview {
		return nil, nil, fmt.Errorf("%w: review_validated must remain in REVIEW", ErrMismatch)
	}
	if !dataBool(review, "prerequisites_current") {
		return nil, nil, fmt.Errorf("%w: review_validated must pin current prerequisite revisions", ErrMismatch)
	}
	pass("review_validated", 10, "review pins current prerequisite revisions")

	// Step 11: recorded pause matches independent monotonic reference.
	pause := findKind(events, EKPauseRecorded)
	if !dataBool(pause, "markers_authenticated") {
		return nil, nil, fmt.Errorf("%w: pause_recorded must carry authenticated markers", ErrMismatch)
	}
	if err := requirePauseAgreement(events, extra); err != nil {
		return nil, nil, err
	}
	pass("pause_recorded", 11, "pause matches independent monotonic reference")

	// Step 12: exactly one authoritative commitment, CONFIRMATION.
	if countKind(events, EKSubmissionCommitted) != 1 {
		return nil, nil, fmt.Errorf("%w: exactly one submission_committed event is required", ErrMismatch)
	}
	committed := findKind(events, EKSubmissionCommitted)
	if dataString(committed, "workflow_state") != StateConfirmation {
		return nil, nil, fmt.Errorf("%w: submission_committed must record CONFIRMATION transition", ErrMismatch)
	}
	if !dataBool(committed, "authoritative") {
		return nil, nil, fmt.Errorf("%w: submission_committed must be authoritative", ErrMismatch)
	}
	submission, _ := extra["submission"].(map[string]any)
	if submission == nil {
		return nil, nil, fmt.Errorf("%w: submission section is required", ErrIncomplete)
	}
	if ok, _ := submission["committed"].(bool); !ok {
		return nil, nil, fmt.Errorf("%w: submission.committed must be true", ErrMismatch)
	}
	if n := extraInt(submission, "commit_count"); n != 1 {
		return nil, nil, fmt.Errorf("%w: submission.commit_count must be exactly 1", ErrMismatch)
	}
	if n := extraInt(submission, "operation_count"); n != 1 {
		return nil, nil, fmt.Errorf("%w: submit operation count must be exactly 1", ErrMismatch)
	}
	pass("submission_committed", 12, "exactly one authoritative commitment")

	// Step 13: confirmation rendering separate from commitment.
	rendered := findKind(events, EKConfirmationRendered)
	if dataString(rendered, "workflow_state") != StateConfirmation {
		return nil, nil, fmt.Errorf("%w: confirmation_rendered must remain in CONFIRMATION", ErrMismatch)
	}
	if err := requireRenderingSeparate(extra); err != nil {
		return nil, nil, err
	}
	pass("confirmation_rendered", 13, "rendering recorded separate from commitment")

	// Step 14: bounded flush closure and diagnostic.
	closed := findKind(events, EKObservationClosed)
	if !dataBool(closed, "flush_bounded") || !dataBool(closed, "closed") {
		return nil, nil, fmt.Errorf("%w: observation_closed must record bounded flush closure", ErrMismatch)
	}
	if dataString(closed, "completeness") == "" {
		return nil, nil, fmt.Errorf("%w: observation_closed must record a completeness assessment", ErrIncomplete)
	}
	pass("observation_closed", 14, "bounded flush closure and diagnostic recorded")

	return checks, postconditions, nil
}

// ---------------------------------------------------------------------------
// Companion cases.
// ---------------------------------------------------------------------------

func validateStopBeforeSubmit(events []JournalEnvelope, extra map[string]any) ([]AcceptanceCheck, map[string]bool, error) {
	outcome, _ := extra["outcome"].(map[string]any)
	if outcome == nil {
		return nil, nil, fmt.Errorf("%w: outcome section is required", ErrIncomplete)
	}
	if goal, _ := outcome["application_goal"].(string); goal == "completed" {
		return nil, nil, fmt.Errorf("%w: stop-before-submit must not claim completion", ErrNotHonest)
	}
	if countKind(events, EKSubmissionCommitted) != 0 {
		return nil, nil, fmt.Errorf("%w: stop-before-submit must have no submission commitment", ErrMismatch)
	}
	submission, _ := extra["submission"].(map[string]any)
	if submission != nil {
		if ok, _ := submission["committed"].(bool); ok {
			return nil, nil, fmt.Errorf("%w: stop-before-submit submission.committed must be false", ErrNotHonest)
		}
	}
	cutoff, _ := extra["cutoff"].(map[string]any)
	if cutoff == nil {
		return nil, nil, fmt.Errorf("%w: cutoff fact is required: non-completion needs fixture-origin authority, not missing-receipt inference", ErrIncomplete)
	}
	if ok, _ := cutoff["authoritative"].(bool); !ok {
		return nil, nil, fmt.Errorf("%w: cutoff must be authoritative", ErrMismatch)
	}
	if origin, _ := cutoff["origin"].(string); origin == "" {
		return nil, nil, fmt.Errorf("%w: cutoff must cite its fixture origin", ErrIncomplete)
	}
	if ok, _ := cutoff["not_completed"].(bool); !ok {
		return nil, nil, fmt.Errorf("%w: cutoff must assert authoritative not-completion", ErrMismatch)
	}
	if has, _ := cutoff["has_receipt"].(bool); has {
		return nil, nil, fmt.Errorf("%w: stop-before-submit must have no receipt", ErrNotHonest)
	}
	downstream, _ := extra["downstream"].(map[string]any)
	if downstream == nil {
		return nil, nil, fmt.Errorf("%w: downstream characterization is required", ErrIncomplete)
	}
	for _, key := range []string{"confirmation", "rendering"} {
		if v, ok := downstream[key].(string); !ok || (v != "blocked" && v != "unobserved") {
			return nil, nil, fmt.Errorf("%w: downstream.%s must be blocked or unobserved", ErrMismatch, key)
		}
	}
	postconditions := optionalPostconditions(extra)
	checks := []AcceptanceCheck{{ID: "stop_before_submit", Status: "pass", Detail: "authoritative non-completion at cutoff; no receipt"}}
	return checks, postconditions, nil
}

func validateRepeatSubmit(events []JournalEnvelope, extra map[string]any) ([]AcceptanceCheck, map[string]bool, error) {
	if countKind(events, EKSubmissionCommitted) != 1 {
		return nil, nil, fmt.Errorf("%w: repeat-submit must retain exactly one commitment", ErrMismatch)
	}
	repeated := findKind(events, EKSubmissionRepeated)
	if repeated == nil {
		return nil, nil, fmt.Errorf("%w: submission_repeated event is required", ErrIncomplete)
	}
	if !dataBool(repeated, "returns_original") {
		return nil, nil, fmt.Errorf("%w: submission_repeated must return the original receipt", ErrMismatch)
	}
	repeat, _ := extra["repeat"].(map[string]any)
	if repeat == nil {
		return nil, nil, fmt.Errorf("%w: repeat section is required", ErrIncomplete)
	}
	if ok, _ := repeat["returns_original_receipt"].(bool); !ok {
		return nil, nil, fmt.Errorf("%w: repeat.returns_original_receipt must be true", ErrMismatch)
	}
	if n := extraInt(repeat, "new_commitments"); n != 0 {
		return nil, nil, fmt.Errorf("%w: repeat.new_commitments must be 0", ErrMismatch)
	}
	if s, _ := repeat["original_receipt"].(string); s == "" {
		return nil, nil, fmt.Errorf("%w: repeat.original_receipt is required", ErrIncomplete)
	}
	submission, _ := extra["submission"].(map[string]any)
	if submission == nil {
		return nil, nil, fmt.Errorf("%w: submission section is required", ErrIncomplete)
	}
	if n := extraInt(submission, "commit_count"); n != 1 {
		return nil, nil, fmt.Errorf("%w: submission.commit_count must remain 1", ErrMismatch)
	}
	postconditions := optionalPostconditions(extra)
	checks := []AcceptanceCheck{{ID: "repeat_submit", Status: "pass", Detail: "identical submit returns original receipt without new commitment"}}
	return checks, postconditions, nil
}

func validateIncompleteField(events []JournalEnvelope, extra map[string]any) ([]AcceptanceCheck, map[string]bool, error) {
	partial, _ := extra["partial"].(map[string]any)
	if partial == nil {
		return nil, nil, fmt.Errorf("%w: partial section is required", ErrIncomplete)
	}
	if field, _ := partial["incomplete_field"].(string); field == "" {
		return nil, nil, fmt.Errorf("%w: partial.incomplete_field is required", ErrIncomplete)
	}
	if ok, _ := partial["honest"].(bool); !ok {
		return nil, nil, fmt.Errorf("%w: partial.honest must be true", ErrMismatch)
	}
	if bad, _ := partial["fabricated_failure"].(bool); bad {
		return nil, nil, fmt.Errorf("%w: partial state must not fabricate a field failure", ErrNotHonest)
	}
	if outcome, _ := extra["outcome"].(map[string]any); outcome != nil {
		if goal, _ := outcome["application_goal"].(string); goal == "completed" {
			return nil, nil, fmt.Errorf("%w: incomplete-field case must not claim completion", ErrNotHonest)
		}
	}
	postconditions := optionalPostconditions(extra)
	checks := []AcceptanceCheck{{ID: "incomplete_field", Status: "pass", Detail: "honest partial knowledge preserved"}}
	return checks, postconditions, nil
}

func validateBrowserClose(events []JournalEnvelope, extra map[string]any) ([]AcceptanceCheck, map[string]bool, error) {
	closed := findKind(events, EKBrowserClosed)
	if closed == nil {
		return nil, nil, fmt.Errorf("%w: browser_closed event is required", ErrIncomplete)
	}
	flush, _ := extra["flush"].(map[string]any)
	if flush == nil {
		return nil, nil, fmt.Errorf("%w: flush section is required", ErrIncomplete)
	}
	if ok, _ := flush["server_facts_retained"].(bool); !ok {
		return nil, nil, fmt.Errorf("%w: flush.server_facts_retained must be true", ErrMismatch)
	}
	if tail, _ := flush["client_tail"].(string); tail != "incomplete" {
		return nil, nil, fmt.Errorf("%w: flush.client_tail must be incomplete", ErrMismatch)
	}
	postconditions := optionalPostconditions(extra)
	checks := []AcceptanceCheck{{ID: "browser_close_before_flush", Status: "pass", Detail: "server facts retained; client tail incomplete"}}
	return checks, postconditions, nil
}

func validateRestartAfterAck(events []JournalEnvelope, extra map[string]any) ([]AcceptanceCheck, map[string]bool, error) {
	restarted := findKind(events, EKObservationRestarted)
	if restarted == nil {
		return nil, nil, fmt.Errorf("%w: observation_restarted event is required", ErrIncomplete)
	}
	restart, _ := extra["restart"].(map[string]any)
	if restart == nil {
		return nil, nil, fmt.Errorf("%w: restart section is required", ErrIncomplete)
	}
	if ok, _ := restart["durable_operation"].(bool); !ok {
		return nil, nil, fmt.Errorf("%w: restart.durable_operation must be true", ErrMismatch)
	}
	if ok, _ := restart["interrupted_observation"].(bool); !ok {
		return nil, nil, fmt.Errorf("%w: restart.interrupted_observation must be true", ErrMismatch)
	}
	if n := extraInt(restart, "duplicate_actions"); n != 0 {
		return nil, nil, fmt.Errorf("%w: restart.duplicate_actions must be 0", ErrMismatch)
	}
	if countKind(events, EKSubmissionCommitted) > 1 {
		return nil, nil, fmt.Errorf("%w: restart must not duplicate the authoritative commitment", ErrMismatch)
	}
	postconditions := optionalPostconditions(extra)
	checks := []AcceptanceCheck{{ID: "restart_after_ack", Status: "pass", Detail: "durable operation preserved without duplicate"}}
	return checks, postconditions, nil
}

// ---------------------------------------------------------------------------
// Diagnostic content helpers.
// ---------------------------------------------------------------------------

func requirePostconditions(extra map[string]any, required []string) (map[string]bool, error) {
	raw, ok := extra["postconditions"].(map[string]any)
	if !ok || raw == nil {
		return nil, fmt.Errorf("%w: postconditions section is required", ErrIncomplete)
	}
	out := map[string]bool{}
	for _, state := range required {
		v, present := raw[state]
		if !present {
			return nil, fmt.Errorf("%w: postcondition %s is missing", ErrIncomplete, state)
		}
		ok, isBool := v.(bool)
		if !isBool || !ok {
			return nil, fmt.Errorf("%w: postcondition %s must be satisfied", ErrMismatch, state)
		}
		out[state] = true
	}
	return out, nil
}

func optionalPostconditions(extra map[string]any) map[string]bool {
	out := map[string]bool{}
	if raw, ok := extra["postconditions"].(map[string]any); ok {
		for _, state := range requiredPostconditions {
			if v, present := raw[state]; present {
				if ok, isBool := v.(bool); isBool {
					out[state] = ok
				}
			}
		}
	}
	return out
}

func requireRejectedAttempt(extra map[string]any) error {
	steps, _ := extra["steps"].(map[string]any)
	if steps == nil {
		return fmt.Errorf("%w: steps section is required", ErrIncomplete)
	}
	history, _ := steps["history"].(map[string]any)
	if history == nil {
		return fmt.Errorf("%w: steps.history section is required", ErrIncomplete)
	}
	attempts, _ := history["attempts"].([]any)
	if len(attempts) == 0 {
		return fmt.Errorf("%w: steps.history.attempts must preserve the invalid attempt", ErrIncomplete)
	}
	for _, item := range attempts {
		m, _ := item.(map[string]any)
		if m == nil {
			continue
		}
		if outcome, _ := m["outcome"].(string); outcome == "rejected" {
			return nil
		}
	}
	return fmt.Errorf("%w: steps.history.attempts must contain a rejected attempt", ErrMismatch)
}

func requireRecoveredHistory(extra map[string]any) error {
	steps, _ := extra["steps"].(map[string]any)
	if steps == nil {
		return fmt.Errorf("%w: steps section is required", ErrIncomplete)
	}
	history, _ := steps["history"].(map[string]any)
	if history == nil {
		return fmt.Errorf("%w: steps.history section is required", ErrIncomplete)
	}
	if status, _ := history["status"].(string); status != "recovered" {
		return fmt.Errorf("%w: steps.history.status %q must be recovered", ErrMismatch, status)
	}
	attempts, _ := history["attempts"].([]any)
	hasRejected, hasAccepted := false, false
	for _, item := range attempts {
		m, _ := item.(map[string]any)
		if m == nil {
			continue
		}
		switch m["outcome"] {
		case "rejected":
			hasRejected = true
		case "accepted":
			hasAccepted = true
		}
	}
	if !hasRejected || !hasAccepted {
		return fmt.Errorf("%w: recovered history must show both the rejected attempt and the accepted correction", ErrMismatch)
	}
	return nil
}

func requireTaskMatch(extra map[string]any, uploadedDigest string) error {
	accepted, _ := extra["accepted"].(map[string]any)
	task, _ := extra["task"].(map[string]any)
	if accepted == nil || task == nil {
		return fmt.Errorf("%w: accepted and task sections are required", ErrIncomplete)
	}
	acceptedDigest, _ := accepted["document_digest"].(string)
	taskDigest, _ := task["document_digest"].(string)
	if acceptedDigest == "" || taskDigest == "" {
		return fmt.Errorf("%w: document digests are required in accepted and task", ErrIncomplete)
	}
	if acceptedDigest != taskDigest {
		return fmt.Errorf("%w: accepted document digest does not match the synthetic task", ErrMismatch)
	}
	if uploadedDigest != "" && acceptedDigest != uploadedDigest {
		return fmt.Errorf("%w: accepted document digest does not match the uploaded bytes", ErrMismatch)
	}
	for _, key := range []string{"contact", "history"} {
		aRaw, aErr := json.Marshal(accepted[key])
		tRaw, tErr := json.Marshal(task[key])
		if aErr != nil || tErr != nil {
			return fmt.Errorf("%w: accepted/task %s must be JSON values", ErrInvalid, key)
		}
		aCanon, aErr := evidence_codec.CanonicalJSON(aRaw, "application/json")
		tCanon, tErr := evidence_codec.CanonicalJSON(tRaw, "application/json")
		if aErr != nil || tErr != nil {
			return fmt.Errorf("%w: accepted/task %s must canonicalize", ErrInvalid, key)
		}
		if string(aCanon) != string(tCanon) {
			return fmt.Errorf("%w: accepted %s does not match the synthetic task", ErrMismatch, key)
		}
	}
	return nil
}

func requirePauseAgreement(events []JournalEnvelope, extra map[string]any) error {
	pause, _ := extra["pause"].(map[string]any)
	if pause == nil {
		return fmt.Errorf("%w: pause section is required", ErrIncomplete)
	}
	interval, _ := pause["interval"].(string)
	if interval == "" {
		return fmt.Errorf("%w: pause.interval must name the measured workflow interval", ErrIncomplete)
	}
	engineMs, okEngine := asFloatAny(pause["engine_ms"])
	manualMs, okManual := asFloatAny(pause["manual_ms"])
	uncertainty, okUncertainty := asFloatAny(pause["uncertainty_ms"])
	if !okEngine || !okManual || !okUncertainty {
		return fmt.Errorf("%w: pause must declare engine_ms, manual_ms, and uncertainty_ms", ErrIncomplete)
	}
	if uncertainty < 0 {
		return fmt.Errorf("%w: pause uncertainty must be nonnegative", ErrInvalid)
	}
	if math.Abs(engineMs-manualMs) > uncertainty {
		return fmt.Errorf("%w: pause engine/manual disagreement exceeds declared uncertainty", ErrMismatch)
	}
	if ok, _ := pause["agreement"].(bool); !ok {
		return fmt.Errorf("%w: pause.agreement must be true within declared uncertainty", ErrMismatch)
	}
	// The pause event must carry an endpoint-difference measurement on a
	// registered monotonic clock; the measurement itself was already
	// validated by clock_rules. Here we require its presence and interval.
	found := false
	for _, ev := range events {
		if ev.EventKind != EKPauseRecorded {
			continue
		}
		for _, meas := range ev.Payload.Measurements {
			if meas.Method == clock_rules.MethodEndpointDifference {
				found = true
			}
		}
	}
	if !found {
		return fmt.Errorf("%w: pause_recorded must carry an endpoint-difference measurement in the workflow interval", ErrIncomplete)
	}
	return nil
}

func requireRenderingSeparate(extra map[string]any) error {
	confirmation, _ := extra["confirmation"].(map[string]any)
	if confirmation == nil {
		return fmt.Errorf("%w: confirmation section is required", ErrIncomplete)
	}
	if ok, _ := confirmation["rendered"].(bool); !ok {
		return fmt.Errorf("%w: confirmation.rendered must be true", ErrMismatch)
	}
	renderRaw, hasRender := confirmation["rendering_ref"]
	commitRaw, hasCommit := confirmation["commitment_ref"]
	if !hasRender || !hasCommit {
		return fmt.Errorf("%w: confirmation must cite rendering and commitment evidence separately", ErrIncomplete)
	}
	renderRef, okRender := toEvidenceRef(renderRaw)
	commitRef, okCommit := toEvidenceRef(commitRaw)
	if !okRender || !okCommit {
		return fmt.Errorf("%w: confirmation rendering and commitment refs must be evidence references", ErrInvalid)
	}
	if renderRef.JournalID == commitRef.JournalID &&
		renderRef.Sequence == commitRef.Sequence &&
		renderRef.Pointer == commitRef.Pointer {
		return fmt.Errorf("%w: rendering and commitment must be independently cited", ErrMismatch)
	}
	return nil
}

func toEvidenceRef(v any) (EvidenceRef, bool) {
	switch r := v.(type) {
	case EvidenceRef:
		return r, true
	case *EvidenceRef:
		if r != nil {
			return *r, true
		}
	case map[string]any:
		return parseEvidenceRefMap(r)
	}
	return EvidenceRef{}, false
}

// ---------------------------------------------------------------------------
// Event helpers.
// ---------------------------------------------------------------------------

func indexOfKind(events []JournalEnvelope, kind string, from int) int {
	for i := from; i < len(events); i++ {
		if events[i].EventKind == kind {
			return i
		}
	}
	return -1
}

func findKind(events []JournalEnvelope, kind string) *JournalEnvelope {
	for i := range events {
		if events[i].EventKind == kind {
			return &events[i]
		}
	}
	return nil
}

func countKind(events []JournalEnvelope, kind string) int {
	n := 0
	for i := range events {
		if events[i].EventKind == kind {
			n++
		}
	}
	return n
}

func dataString(ev *JournalEnvelope, key string) string {
	if ev == nil || ev.Payload.Data == nil {
		return ""
	}
	s, _ := ev.Payload.Data[key].(string)
	return s
}

func dataBool(ev *JournalEnvelope, key string) bool {
	if ev == nil || ev.Payload.Data == nil {
		return false
	}
	ok, _ := ev.Payload.Data[key].(bool)
	return ok
}

func dataInt(ev *JournalEnvelope, key string) int64 {
	if ev == nil || ev.Payload.Data == nil {
		return 0
	}
	switch n := ev.Payload.Data[key].(type) {
	case int:
		return int64(n)
	case int32:
		return int64(n)
	case int64:
		return n
	case float64:
		return int64(n)
	case json.Number:
		parsed, err := n.Int64()
		if err != nil {
			return 0
		}
		return parsed
	}
	return 0
}

// ---------------------------------------------------------------------------
// Generic JSON helpers.
// ---------------------------------------------------------------------------

func extraValue(extra map[string]any, key string) any {
	if extra == nil {
		return nil
	}
	return extra[key]
}

func extraString(extra map[string]any, key string) string {
	s, _ := extraValue(extra, key).(string)
	return s
}

func extraInt(m map[string]any, key string) int64 {
	if m == nil {
		return -1
	}
	switch n := m[key].(type) {
	case int:
		return int64(n)
	case int32:
		return int64(n)
	case int64:
		return n
	case float64:
		return int64(n)
	case json.Number:
		parsed, err := n.Int64()
		if err != nil {
			return -1
		}
		return parsed
	}
	return -1
}

func isMissingValue(v any) bool {
	if v == nil {
		return false
	}
	if _, ok := asMissingAny(v); ok {
		return true
	}
	return false
}

func isDigest(s string) bool {
	const prefix = "sha256:"
	if !strings.HasPrefix(s, prefix) || len(s) != len(prefix)+64 {
		return false
	}
	for _, c := range s[len(prefix):] {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func rejectBareNulls(document []byte) error {
	dec := json.NewDecoder(strings.NewReader(string(document)))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return fmt.Errorf("%w: acceptance report is not JSON: %v", ErrInvalid, err)
	}
	return walkNoNulls(v, "$")
}

func walkNoNulls(v any, path string) error {
	switch n := v.(type) {
	case nil:
		return fmt.Errorf("%w: bare null at %s: use a typed Missing envelope", ErrInvalid, path)
	case map[string]any:
		// A Missing envelope legitimately contains value:null.
		if raw, hasValue := n["value"]; hasValue {
			if reason, _ := n["reason"].(string); reason != "" && raw == nil {
				return nil
			}
		}
		for key, child := range n {
			if err := walkNoNulls(child, path+"."+key); err != nil {
				return err
			}
		}
	case []any:
		for i, child := range n {
			if err := walkNoNulls(child, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

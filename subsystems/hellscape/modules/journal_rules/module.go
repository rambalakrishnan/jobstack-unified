// Package journal_rules implements tier-2 Hellscape journal validation.
//
// It enforces seam-mappings/hellscape-seam-mapping.md sections 3.3 (evidence
// references), 4.5 (owner-local journals), 7.2 (complete JournalEnvelope) and
// the EK-JOURNAL, EK-HASHES, EK-TIME and LIFE-EVIDENCE invariants:
//
//   - Journals begin at sequence 1 with manifest_admitted, use contiguous
//     sequences, pin one immutable manifest digest, and never resequence.
//   - previous_event_hash is Missing(not_applicable) at sequence 1 and the
//     prior event hash afterwards; JournalPrefix.head_hash is the last hash.
//   - EvidenceRef coordinates (journal, sequence, event ID, hash, pointer)
//     must all agree and resolve inside the named prefix.
//   - Clocks register in the manifest or a clock_registered event before use,
//     except a clock_registered event may atomically use its own clock for
//     its receipt timestamp. Measurements delegate to clock_rules.
//   - No event cites its own or a future registration in its derivation
//     inputs.
//
// Structural gates (duplicate keys, bare nulls, digests, closed objects)
// delegate to evidence_codec. Timing semantics delegate to clock_rules.
package journal_rules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	evidence_codec "evidence_codec"
	clock_rules "clock_rules"
)
// Compile-time dependency check: evidence_codec exposes HashEvent for its own
// string-timestamp envelope. Journals here carry structured TimePoint objects
// per the EK contract, so hashing uses the same kernel-jcs-sha256/1 profile
// via CanonicalJSON+HashBytes (see computeEventHash). The reference below
// fails compilation if the declared CONSUMES signature disappears.
var _ = evidence_codec.HashEvent


// ---------------------------------------------------------------------------
// Public types (wire shapes match contracts/00-evidence-kernel.yaml).
// ---------------------------------------------------------------------------

// MissingEnvelope is a typed EK Missing value: {"value":null,"reason":...}.
type MissingEnvelope struct {
	Value  any    `json:"value"`
	Reason string `json:"reason"`
	Detail string `json:"detail,omitempty"`
}

// NewMissing builds a reasoned Missing envelope with a null value.
func NewMissing(reason string) MissingEnvelope {
	return MissingEnvelope{Value: nil, Reason: reason}
}

// TimePoint is a coordinate in a registered monotonic clock.
type TimePoint struct {
	ClockID           string  `json:"clock_id"`
	BootID            string  `json:"boot_id"`
	Origin            string  `json:"origin"`
	MonotonicOffsetMs float64 `json:"monotonic_offset_ms"`
	UTCAnnotation     any     `json:"utc_annotation"`
}

// ClockDescriptor registers one clock lifetime.
type ClockDescriptor struct {
	ClockID  string `json:"clock_id"`
	BootID   string `json:"boot_id"`
	Origin   string `json:"origin"`
	SourceID string `json:"source_id"`
	Basis    string `json:"basis"`
	Unit     string `json:"unit"`
}

// Scope identifies the measured entity.
type Scope struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

// Estimate is the discriminated measurement estimate.
type Estimate struct {
	Kind       string `json:"kind"`
	Value      any    `json:"value,omitempty"`
	LowerBound any    `json:"lower_bound,omitempty"`
	UpperBound any    `json:"upper_bound,omitempty"`
}

// Measurement is the EK Measurement record carried in payload.measurements.
type Measurement struct {
	MeasurementID      string `json:"measurement_id"`
	Name               string `json:"name"`
	Scope              Scope  `json:"scope"`
	Quantity           string `json:"quantity"`
	Unit               string `json:"unit"`
	Origin             string `json:"origin"`
	ClockID            string `json:"clock_id"`
	BootID             string `json:"boot_id"`
	Method             string `json:"method"`
	Start              any    `json:"start"`
	End                any    `json:"end"`
	Estimate           Estimate `json:"estimate"`
	Resolution         any    `json:"resolution"`
	Censoring          string `json:"censoring"`
	ComparabilityGroup any    `json:"comparability_group"`
	AggregateSource    string `json:"aggregate_source,omitempty"`
}

// ArtifactReference is an immutable byte identity plus resolver metadata.
type ArtifactReference struct {
	Digest      string `json:"digest"`
	SizeBytes   int64  `json:"size_bytes"`
	MediaType   string `json:"media_type"`
	OwnerDomain string `json:"owner_domain"`
	Access      string `json:"access"`
}

// Payload contains exactly data, measurements, evidence and artifact refs.
type Payload struct {
	Data          map[string]any     `json:"data"`
	Measurements  []Measurement      `json:"measurements"`
	EvidenceRefs  []EvidenceRef      `json:"evidence_refs"`
	ArtifactRefs  []ArtifactReference `json:"artifact_refs"`
}

// JournalEnvelope is the complete stored journal event envelope.
type JournalEnvelope struct {
	RecordType        string `json:"record_type"`
	SchemaVersion     string `json:"schema_version"`
	RunID             string `json:"run_id"`
	JournalID         string `json:"journal_id"`
	ManifestHash      string `json:"manifest_hash"`
	Sequence          int64  `json:"journal_sequence"`
	EventID           string `json:"event_id"`
	EventKind         string `json:"event_kind"`
	EventSchemaVersion string `json:"event_schema_version"`
	Role              string `json:"role"`
	AssertionKind     string `json:"assertion_kind"`
	OwnerDomain       string `json:"owner_domain"`
	ProducerID        string `json:"producer_id"`
	ProducerSequence  any    `json:"producer_sequence"`
	Provenance        string `json:"provenance"`
	EvidenceScope     string `json:"evidence_scope"`
	RecordedAt        any    `json:"recorded_at"`
	OccurredAt        any    `json:"occurred_at"`
	CausalRefs        []EvidenceRef `json:"causal_refs"`
	Payload           Payload `json:"payload"`
	PreviousEventHash any    `json:"previous_event_hash"`
	EventHash         string `json:"event_hash"`
}

// Manifest is the minimal admitted manifest shape. Only fields allowed by the
// evidence_codec manifest record shape are present so structural validation
// passes; clocks carry the initial clock registrations.
type Manifest struct {
	RecordType  string            `json:"record_type"`
	SchemaVersion string          `json:"schema_version"`
	ManifestID  string            `json:"manifest_id"`
	RunID       string            `json:"run_id"`
	JournalID   string            `json:"journal_id"`
	OwnerDomain string            `json:"owner_domain"`
	Clocks      []ClockDescriptor `json:"clocks,omitempty"`
}

// JournalPrefix is an immutable journal prefix.
type JournalPrefix struct {
	JournalID    string `json:"journal_id"`
	LastSequence int64  `json:"last_sequence"`
	HeadHash     string `json:"head_hash"`
}

// EvidenceRef cites one retained journal event coordinate plus a JSON Pointer.
type EvidenceRef struct {
	JournalID string `json:"journal_id"`
	Sequence  int64  `json:"sequence"`
	EventID   string `json:"event_id"`
	EventHash string `json:"event_hash"`
	Pointer   string `json:"pointer"`
}

// ---------------------------------------------------------------------------
// Small validators.
// ---------------------------------------------------------------------------

var validOrigins = map[string]bool{
	"engine_measured": true, "browser_measured": true,
	"subject_reported": true, "manual_reference": true,
}

var validBases = map[string]bool{
	"monotonic_offset": true, "opaque_report": true,
}

var validNullReasons = map[string]bool{
	"not_enabled": true, "not_applicable": true, "not_observed": true,
	"observation_lost": true, "unsupported_by_subject": true, "manual_override": true,
}

var validRoles = map[string]bool{
	"external_input": true, "derived_output": true, "lifecycle_observation": true,
}

var validAssertions = map[string]bool{
	"observation": true, "claim": true,
	"authoritative_effect": true, "derived_assessment": true,
}

var validProvenance = map[string]bool{
	"server": true, "fixture_client": true, "connector": true,
	"subject": true, "manual_observer": true, "importer": true,
}

var validScopes = map[string]bool{
	"current_run": true, "historical_unscored": true, "synthetic": true,
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

// ---------------------------------------------------------------------------
// Any-field classifiers (accept structs and generic maps).
// ---------------------------------------------------------------------------

func asMissingEnvelope(v any) (MissingEnvelope, bool) {
	switch t := v.(type) {
	case MissingEnvelope:
		return t, true
	case *MissingEnvelope:
		if t == nil {
			return MissingEnvelope{}, false
		}
		return *t, true
	case map[string]any:
		raw, hasValue := t["value"]
		if !hasValue || raw != nil {
			return MissingEnvelope{}, false
		}
		reason, _ := t["reason"].(string)
		if reason == "" {
			return MissingEnvelope{}, false
		}
		Detail, _ := t["detail"].(string)
		return MissingEnvelope{Value: nil, Reason: reason, Detail: Detail}, true
	}
	return MissingEnvelope{}, false
}

func asTimePointValue(v any) (TimePoint, bool) {
	switch t := v.(type) {
	case TimePoint:
		return t, true
	case *TimePoint:
		if t == nil {
			return TimePoint{}, false
		}
		return *t, true
	case map[string]any:
		cid, _ := t["clock_id"].(string)
		bid, _ := t["boot_id"].(string)
		origin, _ := t["origin"].(string)
		if cid == "" || bid == "" || origin == "" {
			return TimePoint{}, false
		}
		rawOff, ok := t["monotonic_offset_ms"]
		if !ok {
			return TimePoint{}, false
		}
		off, ok := asFloat(rawOff)
		if !ok {
			return TimePoint{}, false
		}
		utc, hasUTC := t["utc_annotation"]
		if !hasUTC {
			return TimePoint{}, false
		}
		return TimePoint{ClockID: cid, BootID: bid, Origin: origin, MonotonicOffsetMs: off, UTCAnnotation: utc}, true
	}
	return TimePoint{}, false
}

func asFloat(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case float32:
		return float64(t), true
	case int:
		return float64(t), true
	case int8:
		return float64(t), true
	case int16:
		return float64(t), true
	case int32:
		return float64(t), true
	case int64:
		return float64(t), true
	case uint:
		return float64(t), true
	case uint32:
		return float64(t), true
	case uint64:
		return float64(t), true
	case json.Number:
		f, err := t.Float64()
		if err != nil {
			return 0, false
		}
		return f, true
	}
	return 0, false
}

func asInt64(v any) (int64, bool) {
	switch t := v.(type) {
	case int:
		return int64(t), true
	case int8:
		return int64(t), true
	case int16:
		return int64(t), true
	case int32:
		return int64(t), true
	case int64:
		return t, true
	case uint:
		return int64(t), true
	case uint32:
		return int64(t), true
	case uint64:
		if t > math.MaxInt64 {
			return 0, false
		}
		return int64(t), true
	case float64:
		if math.Trunc(t) != t {
			return 0, false
		}
		return int64(t), true
	case float32:
		f := float64(t)
		if math.Trunc(f) != f {
			return 0, false
		}
		return int64(f), true
	case json.Number:
		n, err := t.Int64()
		if err != nil {
			return 0, false
		}
		return n, true
	}
	return 0, false
}

func validateMissingEnvelope(m MissingEnvelope, field string) error {
	if !validNullReasons[m.Reason] {
		return fmt.Errorf("journal_rules: %s has invalid NullReason %q", field, m.Reason)
	}
	if strings.Contains(m.Detail, "\x00") {
		return fmt.Errorf("journal_rules: %s Missing Detail carries in-band null", field)
	}
	return nil
}

func validateUTCAnnotation(v any, field string) error {
	if v == nil {
		return fmt.Errorf("journal_rules: %s must be a date-time annotation or Missing, got in-band null", field)
	}
	if m, ok := asMissingEnvelope(v); ok {
		return validateMissingEnvelope(m, field)
	}
	if s, ok := v.(string); ok {
		if _, err := time.Parse(time.RFC3339, s); err != nil {
			return fmt.Errorf("journal_rules: %s is not a valid date-time annotation %q: %v", field, s, err)
		}
		return nil
	}
	return fmt.Errorf("journal_rules: %s must be a date-time annotation or Missing, got %T", field, v)
}

func validateTimePointShape(tp TimePoint, field string) error {
	if strings.TrimSpace(tp.ClockID) == "" {
		return fmt.Errorf("journal_rules: %s clock_id must be a nonempty identifier", field)
	}
	if strings.TrimSpace(tp.BootID) == "" {
		return fmt.Errorf("journal_rules: %s boot_id must be a nonempty identifier", field)
	}
	if !validOrigins[tp.Origin] {
		return fmt.Errorf("journal_rules: %s has invalid origin %q", field, tp.Origin)
	}
	if math.IsNaN(tp.MonotonicOffsetMs) || math.IsInf(tp.MonotonicOffsetMs, 0) {
		return fmt.Errorf("journal_rules: %s monotonic_offset_ms must be finite, got %v", field, tp.MonotonicOffsetMs)
	}
	if tp.MonotonicOffsetMs < 0 {
		return fmt.Errorf("journal_rules: %s monotonic_offset_ms must be nonnegative, got %v", field, tp.MonotonicOffsetMs)
	}
	if err := validateUTCAnnotation(tp.UTCAnnotation, field+".utc_annotation"); err != nil {
		return err
	}
	return nil
}

func validateClockShape(cd ClockDescriptor, field string) error {
	if strings.TrimSpace(cd.ClockID) == "" {
		return fmt.Errorf("journal_rules: %s clock_id must be a nonempty identifier", field)
	}
	if strings.TrimSpace(cd.BootID) == "" {
		return fmt.Errorf("journal_rules: %s boot_id must be a nonempty identifier", field)
	}
	if !validOrigins[cd.Origin] {
		return fmt.Errorf("journal_rules: %s has invalid origin %q", field, cd.Origin)
	}
	if strings.TrimSpace(cd.SourceID) == "" {
		return fmt.Errorf("journal_rules: %s source_id must be a nonempty identifier", field)
	}
	if !validBases[cd.Basis] {
		return fmt.Errorf("journal_rules: %s has invalid basis %q: must be monotonic_offset or opaque_report", field, cd.Basis)
	}
	if cd.Unit != "ms" {
		return fmt.Errorf("journal_rules: %s unit must be ms, got %q", field, cd.Unit)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Hashing (kernel-jcs-sha256/1 via evidence_codec canonicalization).
//
// evidence_codec.HashEvent hashes its own JournalEnvelope struct whose
// timestamps are strings. Journals here carry structured TimePoint objects
// per the EK contract, so the hash is computed over the canonical envelope
// with only event_hash removed using the same CanonicalJSON+HashBytes
// profile.
// ---------------------------------------------------------------------------

func canonicalBytesWithoutEventHash(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("journal_rules: cannot decode envelope: %v", err)
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("journal_rules: envelope must be a JSON object")
	}
	delete(m, "event_hash")
	// Normalize nil collections the same way evidence_codec does so that a
	// missing causal_refs/payload cannot fork the digest.
	if m["causal_refs"] == nil {
		m["causal_refs"] = []any{}
	}
	if m["payload"] == nil {
		m["payload"] = map[string]any{}
	}
	remarshaled, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("journal_rules: cannot re-encode envelope: %v", err)
	}
	canonical, err := evidence_codec.CanonicalJSON(remarshaled, "application/json")
	if err != nil {
		return nil, err
	}
	return canonical, nil
}

func computeEventHash(env JournalEnvelope) (string, error) {
	raw, err := json.Marshal(env)
	if err != nil {
		return "", fmt.Errorf("journal_rules: cannot marshal envelope: %v", err)
	}
	canonical, err := canonicalBytesWithoutEventHash(raw)
	if err != nil {
		return "", err
	}
	return string(evidence_codec.HashBytes(canonical)), nil
}

func computeManifestDigest(manifest Manifest) (string, error) {
	raw, err := json.Marshal(manifest)
	if err != nil {
		return "", fmt.Errorf("journal_rules: cannot marshal manifest: %v", err)
	}
	canonical, err := evidence_codec.CanonicalJSON(raw, "application/json")
	if err != nil {
		return "", err
	}
	return string(evidence_codec.HashBytes(canonical)), nil
}

// ---------------------------------------------------------------------------
// clock_rules translation.
// ---------------------------------------------------------------------------

func toClockRulesClock(cd ClockDescriptor) clock_rules.ClockDescriptor {
	return clock_rules.ClockDescriptor{
		ClockID: cd.ClockID, BootID: cd.BootID, Origin: cd.Origin,
		SourceID: cd.SourceID, Basis: cd.Basis, Unit: cd.Unit,
	}
}

func toClockRulesMissing(m MissingEnvelope) clock_rules.Missing {
	return clock_rules.Missing{Reason: m.Reason, Detail: m.Detail}
}

func convertUTCAnnotation(v any, field string) (any, error) {
	if v == nil {
		return nil, fmt.Errorf("journal_rules: %s is an in-band null: must be date-time or Missing", field)
	}
	if m, ok := asMissingEnvelope(v); ok {
		if err := validateMissingEnvelope(m, field); err != nil {
			return nil, err
		}
		return toClockRulesMissing(m), nil
	}
	if s, ok := v.(string); ok {
		if _, err := time.Parse(time.RFC3339, s); err != nil {
			return nil, fmt.Errorf("journal_rules: %s is not a valid date-time %q: %v", field, s, err)
		}
		return s, nil
	}
	return nil, fmt.Errorf("journal_rules: %s must be a date-time annotation or Missing, got %T", field, v)
}

func convertEndpoint(v any, field string) (any, error) {
	if v == nil {
		return nil, fmt.Errorf("journal_rules: %s is an in-band null: must be TimePoint or Missing", field)
	}
	if m, ok := asMissingEnvelope(v); ok {
		if err := validateMissingEnvelope(m, field); err != nil {
			return nil, err
		}
		return toClockRulesMissing(m), nil
	}
	if tp, ok := asTimePointValue(v); ok {
		if err := validateTimePointShape(tp, field); err != nil {
			return nil, err
		}
		utc, err := convertUTCAnnotation(tp.UTCAnnotation, field+".utc_annotation")
		if err != nil {
			return nil, err
		}
		return clock_rules.TimePoint{
			ClockID: tp.ClockID, BootID: tp.BootID, Origin: tp.Origin,
			MonotonicOffsetMs: tp.MonotonicOffsetMs, UTCAnnotation: utc,
		}, nil
	}
	return nil, fmt.Errorf("journal_rules: %s must be TimePoint or Missing, got %T", field, v)
}

func convertNumberOrMissing(v any, field string) (any, error) {
	if v == nil {
		return nil, fmt.Errorf("journal_rules: %s is an in-band null: must be numeric or Missing", field)
	}
	if m, ok := asMissingEnvelope(v); ok {
		if err := validateMissingEnvelope(m, field); err != nil {
			return nil, err
		}
		return toClockRulesMissing(m), nil
	}
	if n, ok := asFloat(v); ok {
		if math.IsNaN(n) || math.IsInf(n, 0) {
			return nil, fmt.Errorf("journal_rules: %s must be finite, got %v", field, n)
		}
		return n, nil
	}
	return nil, fmt.Errorf("journal_rules: %s must be numeric or Missing, got %T", field, v)
}

func convertStringOrMissing(v any, field string) (any, error) {
	if v == nil {
		return nil, fmt.Errorf("journal_rules: %s is an in-band null: must be identifier or Missing", field)
	}
	if m, ok := asMissingEnvelope(v); ok {
		if err := validateMissingEnvelope(m, field); err != nil {
			return nil, err
		}
		return toClockRulesMissing(m), nil
	}
	if s, ok := v.(string); ok {
		if strings.TrimSpace(s) == "" {
			return nil, fmt.Errorf("journal_rules: %s identifier must be nonempty", field)
		}
		return s, nil
	}
	return nil, fmt.Errorf("journal_rules: %s must be identifier or Missing, got %T", field, v)
}

func convertEstimate(e Estimate, field string) (clock_rules.Estimate, error) {
	switch e.Kind {
	case "exact":
		if e.Value == nil {
			return clock_rules.Estimate{}, fmt.Errorf("journal_rules: %s.value is an in-band null for exact estimate", field)
		}
		if _, ok := asMissingEnvelope(e.Value); ok {
			return clock_rules.Estimate{}, fmt.Errorf("journal_rules: %s exact estimate value must be numeric, got Missing", field)
		}
		n, ok := asFloat(e.Value)
		if !ok {
			return clock_rules.Estimate{}, fmt.Errorf("journal_rules: %s exact estimate value must be numeric, got %T", field, e.Value)
		}
		if e.LowerBound != nil || e.UpperBound != nil {
			return clock_rules.Estimate{}, fmt.Errorf("journal_rules: %s exact estimate must not carry bounds", field)
		}
		return clock_rules.Estimate{Kind: "exact", Value: n}, nil
	case "bounded":
		if e.Value != nil {
			return clock_rules.Estimate{}, fmt.Errorf("journal_rules: %s bounded estimate must not carry an exact value", field)
		}
		if e.LowerBound == nil || e.UpperBound == nil {
			return clock_rules.Estimate{}, fmt.Errorf("journal_rules: %s bounded estimate bounds must each be numeric or Missing", field)
		}
		lo, err := convertNumberOrMissing(e.LowerBound, field+".lower_bound")
		if err != nil {
			return clock_rules.Estimate{}, err
		}
		hi, err := convertNumberOrMissing(e.UpperBound, field+".upper_bound")
		if err != nil {
			return clock_rules.Estimate{}, err
		}
		return clock_rules.Estimate{Kind: "bounded", LowerBound: lo, UpperBound: hi}, nil
	case "unavailable":
		if e.Value == nil {
			return clock_rules.Estimate{}, fmt.Errorf("journal_rules: %s unavailable estimate value is an in-band null", field)
		}
		m, ok := asMissingEnvelope(e.Value)
		if !ok {
			return clock_rules.Estimate{}, fmt.Errorf("journal_rules: %s unavailable estimate value must be Missing, got %T", field, e.Value)
		}
		if err := validateMissingEnvelope(m, field+".value"); err != nil {
			return clock_rules.Estimate{}, err
		}
		if e.LowerBound != nil || e.UpperBound != nil {
			return clock_rules.Estimate{}, fmt.Errorf("journal_rules: %s unavailable estimate must not carry bounds", field)
		}
		return clock_rules.Estimate{Kind: "unavailable", Value: toClockRulesMissing(m)}, nil
	}
	return clock_rules.Estimate{}, fmt.Errorf("journal_rules: %s estimate kind %q must be exact, bounded, or unavailable", field, e.Kind)
}

func toClockRulesMeasurement(m Measurement) (clock_rules.Measurement, error) {
	base := fmt.Sprintf("measurement %q", m.MeasurementID)
	start, err := convertEndpoint(m.Start, base+".start")
	if err != nil {
		return clock_rules.Measurement{}, err
	}
	end, err := convertEndpoint(m.End, base+".end")
	if err != nil {
		return clock_rules.Measurement{}, err
	}
	est, err := convertEstimate(m.Estimate, base+".estimate")
	if err != nil {
		return clock_rules.Measurement{}, err
	}
	res, err := convertNumberOrMissing(m.Resolution, base+".resolution")
	if err != nil {
		return clock_rules.Measurement{}, err
	}
	cg, err := convertStringOrMissing(m.ComparabilityGroup, base+".comparability_group")
	if err != nil {
		return clock_rules.Measurement{}, err
	}
	return clock_rules.Measurement{
		MeasurementID: m.MeasurementID, Name: m.Name,
		Scope: clock_rules.Scope{Kind: m.Scope.Kind, ID: m.Scope.ID},
		Quantity: m.Quantity, Unit: m.Unit, Origin: m.Origin,
		ClockID: m.ClockID, BootID: m.BootID, Method: m.Method,
		Start: start, End: end, Estimate: est,
		Resolution: res, Censoring: m.Censoring,
		ComparabilityGroup: cg, AggregateSource: m.AggregateSource,
	}, nil
}

// ---------------------------------------------------------------------------
// JSON Pointer (RFC 6901).
// ---------------------------------------------------------------------------

func resolvePointer(document []byte, pointer string) ([]byte, error) {
	if !validJSONPointer(pointer) {
		return nil, fmt.Errorf("journal_rules: invalid JSON pointer %q", pointer)
	}
	dec := json.NewDecoder(bytes.NewReader(document))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("journal_rules: cannot decode pointed document: %v", err)
	}
	if pointer == "" {
		out, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		return out, nil
	}
	parts := strings.Split(pointer[1:], "/")
	cur := v
	for _, raw := range parts {
		token := strings.ReplaceAll(strings.ReplaceAll(raw, "~1", "/"), "~0", "~")
		switch t := cur.(type) {
		case map[string]any:
			val, ok := t[token]
			if !ok {
				return nil, fmt.Errorf("journal_rules: pointer %q does not resolve: missing key %q", pointer, token)
			}
			cur = val
		case []any:
			if token == "-" {
				return nil, fmt.Errorf("journal_rules: pointer %q does not resolve: '-' names no element", pointer)
			}
			idx, err := parseArrayIndex(token, len(t))
			if err != nil {
				return nil, fmt.Errorf("journal_rules: pointer %q does not resolve: %v", pointer, err)
			}
			cur = t[idx]
		default:
			return nil, fmt.Errorf("journal_rules: pointer %q does not resolve: cannot traverse scalar", pointer)
		}
	}
	out, err := json.Marshal(cur)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func parseArrayIndex(token string, length int) (int, error) {
	if token == "" {
		return 0, fmt.Errorf("empty array index")
	}
	if len(token) > 1 && token[0] == '0' {
		return 0, fmt.Errorf("array index %q has a leading zero", token)
	}
	n := 0
	for i := 0; i < len(token); i++ {
		if token[i] < '0' || token[i] > '9' {
			return 0, fmt.Errorf("array index %q is not numeric", token)
		}
		n = n*10 + int(token[i]-'0')
		if n >= length {
			return 0, fmt.Errorf("array index %d out of bounds (length %d)", n, length)
		}
	}
	return n, nil
}

// ---------------------------------------------------------------------------
// Data scanning for embedded evidence references and digest cycles.
// ---------------------------------------------------------------------------

// embeddedRef is an EvidenceRef-shaped object found inside payload data.
type embeddedRef struct {
	ref EvidenceRef
	ok  bool
}

func parseEmbeddedRef(m map[string]any) (embeddedRef, bool) {
	jid, _ := m["journal_id"].(string)
	eid, _ := m["event_id"].(string)
	ehash, _ := m["event_hash"].(string)
	ptr, _ := m["pointer"].(string)
	rawSeq, hasSeq := m["sequence"]
	if jid == "" || eid == "" || ehash == "" || !hasSeq {
		return embeddedRef{}, false
	}
	// pointer may legitimately be empty string; require the key to exist.
	if _, hasPtr := m["pointer"]; !hasPtr {
		return embeddedRef{}, false
	}
	seq, ok := asInt64(rawSeq)
	if !ok {
		// json.Number from a decoded document is handled by asInt64 too;
		// anything else is not a usable sequence.
		return embeddedRef{}, false
	}
	_ = ptr
	return embeddedRef{ref: EvidenceRef{JournalID: jid, Sequence: seq, EventID: eid, EventHash: ehash, Pointer: ptr}, ok: true}, true
}

func collectEmbeddedRefs(v any, out *[]EvidenceRef) {
	switch t := v.(type) {
	case map[string]any:
		if er, ok := parseEmbeddedRef(t); ok {
			*out = append(*out, er.ref)
		}
		for _, e := range t {
			collectEmbeddedRefs(e, out)
		}
	case []any:
		for _, e := range t {
			collectEmbeddedRefs(e, out)
		}
	case []EvidenceRef:
		*out = append(*out, t...)
	}
}

func dataContainsString(v any, target string) bool {
	switch t := v.(type) {
	case string:
		return t == target
	case map[string]any:
		for _, e := range t {
			if dataContainsString(e, target) {
				return true
			}
		}
	case []any:
		for _, e := range t {
			if dataContainsString(e, target) {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// ValidateJournal.
// ---------------------------------------------------------------------------

// ValidateJournal verifies a complete owner-local journal against its manifest
// and returns the resulting prefix. Every structural gate delegates to
// evidence_codec; every measurement delegates to clock_rules.
func ValidateJournal(manifest Manifest, events []JournalEnvelope) (JournalPrefix, error) {
	empty := JournalPrefix{}
	// Manifest structural gate.
	manifestRaw, err := json.Marshal(manifest)
	if err != nil {
		return empty, fmt.Errorf("journal_rules: cannot marshal manifest: %v", err)
	}
	if strings.TrimSpace(manifest.SchemaVersion) == "" {
		return empty, fmt.Errorf("journal_rules: manifest schema_version must be nonempty")
	}
	if err := evidence_codec.ValidateRecord(manifest.SchemaVersion, "manifest", manifestRaw); err != nil {
		return empty, fmt.Errorf("journal_rules: manifest structural gate: %v", err)
	}
	manifestDigest, err := computeManifestDigest(manifest)
	if err != nil {
		return empty, err
	}
	if strings.TrimSpace(manifest.RunID) == "" || strings.TrimSpace(manifest.JournalID) == "" {
		return empty, fmt.Errorf("journal_rules: manifest run_id and journal_id must be nonempty")
	}
	// Manifest clock registry.
	registered := make(map[string]ClockDescriptor)
	registeredList := make([]clock_rules.ClockDescriptor, 0, len(manifest.Clocks)+len(events))
	for i, cd := range manifest.Clocks {
		if err := validateClockShape(cd, fmt.Sprintf("manifest.clocks[%d]", i)); err != nil {
			return empty, err
		}
		key := cd.ClockID + "\x00" + cd.BootID + "\x00" + cd.Origin
		if _, dup := registered[key]; dup {
			return empty, fmt.Errorf("journal_rules: duplicate manifest clock registration for %s/%s/%s", cd.ClockID, cd.BootID, cd.Origin)
		}
		registered[key] = cd
		registeredList = append(registeredList, toClockRulesClock(cd))
	}

	if len(events) == 0 {
		return empty, fmt.Errorf("journal_rules: journal is empty: admission is its first event")
	}

	seenIDs := make(map[string]int64, len(events))
	// Index by sequence for evidence resolution inside the journal.
	bySeq := make(map[int64]*JournalEnvelope, len(events))

	for i := range events {
		ev := &events[i]
		where := fmt.Sprintf("sequence %d", ev.Sequence)
		// Structural gate per event.
		evRaw, err := json.Marshal(ev)
		if err != nil {
			return empty, fmt.Errorf("journal_rules: %s: cannot marshal: %v", where, err)
		}
		if strings.TrimSpace(ev.SchemaVersion) == "" {
			return empty, fmt.Errorf("journal_rules: %s: schema_version must be nonempty", where)
		}
		if err := evidence_codec.ValidateRecord(ev.SchemaVersion, "journal_event", evRaw); err != nil {
			return empty, fmt.Errorf("journal_rules: %s structural gate: %v", where, err)
		}
		// Contiguous sequences beginning at 1.
		expected := int64(i + 1)
		if ev.Sequence != expected {
			return empty, fmt.Errorf("journal_rules: sequences must be contiguous beginning at 1: position %d carries journal_sequence %d, want %d", i+1, ev.Sequence, expected)
		}
		// Stable run/journal/manifest/owner pinning.
		if ev.RunID != manifest.RunID {
			return empty, fmt.Errorf("journal_rules: %s names run %q, manifest pins %q", where, ev.RunID, manifest.RunID)
		}
		if ev.JournalID != manifest.JournalID {
			return empty, fmt.Errorf("journal_rules: %s names journal %q, manifest pins %q", where, ev.JournalID, manifest.JournalID)
		}
		if ev.ManifestHash != manifestDigest {
			return empty, fmt.Errorf("journal_rules: %s pins manifest %q, manifest digest is %q", where, ev.ManifestHash, manifestDigest)
		}
		if ev.OwnerDomain != manifest.OwnerDomain {
			return empty, fmt.Errorf("journal_rules: %s names owner_domain %q, manifest pins %q", where, ev.OwnerDomain, manifest.OwnerDomain)
		}
		if strings.TrimSpace(ev.EventID) == "" {
			return empty, fmt.Errorf("journal_rules: %s has an empty event_id", where)
		}
		if prev, dup := seenIDs[ev.EventID]; dup {
			return empty, fmt.Errorf("journal_rules: duplicate event_id %q at sequences %d and %d: events are never resequenced", ev.EventID, prev, ev.Sequence)
		}
		seenIDs[ev.EventID] = ev.Sequence
		if !validRoles[ev.Role] {
			return empty, fmt.Errorf("journal_rules: %s has invalid role %q", where, ev.Role)
		}
		if !validAssertions[ev.AssertionKind] {
			return empty, fmt.Errorf("journal_rules: %s has invalid assertion_kind %q", where, ev.AssertionKind)
		}
		if !validProvenance[ev.Provenance] {
			return empty, fmt.Errorf("journal_rules: %s has invalid provenance %q", where, ev.Provenance)
		}
		if !validScopes[ev.EvidenceScope] {
			return empty, fmt.Errorf("journal_rules: %s has invalid evidence_scope %q", where, ev.EvidenceScope)
		}
		if strings.TrimSpace(ev.EventKind) == "" || strings.TrimSpace(ev.EventSchemaVersion) == "" {
			return empty, fmt.Errorf("journal_rules: %s must name event kind and version", where)
		}
		if strings.TrimSpace(ev.ProducerID) == "" {
			return empty, fmt.Errorf("journal_rules: %s has an empty producer_id", where)
		}
		// Producer sequence is an integer or a reasoned Missing.
		if ev.ProducerSequence == nil {
			return empty, fmt.Errorf("journal_rules: %s producer_sequence is an in-band null: use a typed Missing envelope", where)
		}
		if m, ok := asMissingEnvelope(ev.ProducerSequence); ok {
			if err := validateMissingEnvelope(m, where+".producer_sequence"); err != nil {
				return empty, err
			}
		} else if n, ok := asInt64(ev.ProducerSequence); ok {
			if n < 0 {
				return empty, fmt.Errorf("journal_rules: %s producer_sequence must not be negative", where)
			}
		} else {
			return empty, fmt.Errorf("journal_rules: %s producer_sequence must be an integer or Missing, got %T", where, ev.ProducerSequence)
		}
		// Authority matrix (contract JournalEnvelope allOf).
		if ev.Sequence == 1 {
			if ev.EventKind != "manifest_admitted" {
				return empty, fmt.Errorf("journal_rules: journal begins with manifest_admitted: sequence 1 carries %q", ev.EventKind)
			}
			if ev.Provenance != "server" {
				return empty, fmt.Errorf("journal_rules: sequence 1 provenance must be server, got %q", ev.Provenance)
			}
			if ev.Role != "external_input" {
				return empty, fmt.Errorf("journal_rules: sequence 1 role must be external_input, got %q", ev.Role)
			}
		} else if ev.EventKind == "manifest_admitted" {
			return empty, fmt.Errorf("journal_rules: manifest_admitted appears only at sequence 1, found at %s", where)
		}
		if ev.EventKind == "clock_registered" && ev.Provenance != "server" {
			return empty, fmt.Errorf("journal_rules: %s clock_registered provenance must be server, got %q", where, ev.Provenance)
		}
		if ev.EventKind == "producer_registered" && ev.Provenance != "server" {
			return empty, fmt.Errorf("journal_rules: %s producer_registered provenance must be server, got %q", where, ev.Provenance)
		}
		if ev.EventKind == "analysis_requested" {
			if ev.Provenance != "server" {
				return empty, fmt.Errorf("journal_rules: %s analysis_requested provenance must be server, got %q", where, ev.Provenance)
			}
			if ev.Role != "lifecycle_observation" {
				return empty, fmt.Errorf("journal_rules: %s analysis_requested role must be lifecycle_observation, got %q", where, ev.Role)
			}
		}
		switch ev.Provenance {
		case "fixture_client", "subject", "manual_observer", "importer":
			if ev.AssertionKind != "observation" && ev.AssertionKind != "claim" {
				return empty, fmt.Errorf("journal_rules: %s provenance %q allows only observation or claim assertion, got %q", where, ev.Provenance, ev.AssertionKind)
			}
		}
		// Imported evidence keeps its original scope; import never promotes.
		if ev.Provenance == "importer" && ev.EvidenceScope == "current_run" {
			return empty, fmt.Errorf("journal_rules: %s importer provenance must not promote evidence to current_run: register historical_unscored or synthetic", where)
		}
		// Admission pins the complete immutable manifest.
		if ev.Sequence == 1 {
			if ev.Payload.Data == nil {
				return empty, fmt.Errorf("journal_rules: sequence 1 data must pin the admitted manifest")
			}
			rawMan, ok := ev.Payload.Data["manifest"]
			if !ok {
				return empty, fmt.Errorf("journal_rules: sequence 1 data must pin the admitted manifest under data.manifest")
			}
			manMap, ok := rawMan.(map[string]any)
			if !ok {
				return empty, fmt.Errorf("journal_rules: sequence 1 data.manifest must be an artifact object")
			}
			digest, _ := manMap["digest"].(string)
			if digest != manifestDigest {
				return empty, fmt.Errorf("journal_rules: sequence 1 pins manifest %q, manifest digest is %q", digest, manifestDigest)
			}
		}
		// Hash chain: recompute, then link.
		recomputed, err := computeEventHash(*ev)
		if err != nil {
			return empty, fmt.Errorf("journal_rules: %s hash: %v", where, err)
		}
		if ev.EventHash != recomputed {
			return empty, fmt.Errorf("journal_rules: %s event_hash %q does not match recomputed %q: changed content detected", where, ev.EventHash, recomputed)
		}
		if !validDigest(ev.EventHash) {
			return empty, fmt.Errorf("journal_rules: %s event_hash %q is not a valid digest", where, ev.EventHash)
		}
		if ev.Sequence == 1 {
			m, ok := asMissingEnvelope(ev.PreviousEventHash)
			if !ok {
				return empty, fmt.Errorf("journal_rules: sequence 1 previous_event_hash is Missing(not_applicable), got %T", ev.PreviousEventHash)
			}
			if m.Reason != "not_applicable" {
				return empty, fmt.Errorf("journal_rules: sequence 1 previous_event_hash reason must be not_applicable, got %q", m.Reason)
			}
			if err := validateMissingEnvelope(m, "sequence 1 previous_event_hash"); err != nil {
				return empty, err
			}
		} else {
			prevStr, ok := ev.PreviousEventHash.(string)
			if !ok {
				return empty, fmt.Errorf("journal_rules: %s previous_event_hash must equal event_hash at %d, got %T", where, ev.Sequence-1, ev.PreviousEventHash)
			}
			if prevStr != events[i-1].EventHash {
				return empty, fmt.Errorf("journal_rules: %s previous_event_hash %q does not equal event_hash at %d %q", where, prevStr, ev.Sequence-1, events[i-1].EventHash)
			}
		}

		// Clock registration for this event (atomic receipt exception).
		var newlyRegistered *ClockDescriptor
		if ev.EventKind == "clock_registered" {
			cd, err := parseClockDescriptorData(ev.Payload.Data)
			if err != nil {
				return empty, fmt.Errorf("journal_rules: %s clock_registered data: %v", where, err)
			}
			if err := validateClockShape(cd, where+".payload.data"); err != nil {
				return empty, err
			}
			key := cd.ClockID + "\x00" + cd.BootID + "\x00" + cd.Origin
			if _, dup := registered[key]; dup {
				return empty, fmt.Errorf("journal_rules: %s re-registers clock %s/%s/%s", where, cd.ClockID, cd.BootID, cd.Origin)
			}
			newlyRegistered = &cd
		}

		// Receipt timestamp: TimePoint on a registered clock. A
		// clock_registered event may atomically use the clock it registers.
		if ev.RecordedAt == nil {
			return empty, fmt.Errorf("journal_rules: %s recorded_at is an in-band null: receipt time is a TimePoint", where)
		}
		recTP, ok := asTimePointValue(ev.RecordedAt)
		if !ok {
			if _, isMiss := asMissingEnvelope(ev.RecordedAt); isMiss {
				return empty, fmt.Errorf("journal_rules: %s recorded_at must be a TimePoint, got Missing", where)
			}
			return empty, fmt.Errorf("journal_rules: %s recorded_at must be a TimePoint, got %T", where, ev.RecordedAt)
		}
		if err := validateTimePointShape(recTP, where+".recorded_at"); err != nil {
			return empty, err
		}
		if !clockIsRegistered(registered, newlyRegistered, recTP.ClockID, recTP.BootID, recTP.Origin) {
			return empty, fmt.Errorf("journal_rules: %s recorded_at clock (%s/%s/%s) is not registered: register clocks before use", where, recTP.ClockID, recTP.BootID, recTP.Origin)
		}
		// Occurrence time: TimePoint or Missing; no atomic exception.
		if ev.OccurredAt == nil {
			return empty, fmt.Errorf("journal_rules: %s occurred_at is an in-band null: use a typed Missing envelope", where)
		}
		if m, ok := asMissingEnvelope(ev.OccurredAt); ok {
			if err := validateMissingEnvelope(m, where+".occurred_at"); err != nil {
				return empty, err
			}
		} else if occTP, ok := asTimePointValue(ev.OccurredAt); ok {
			if err := validateTimePointShape(occTP, where+".occurred_at"); err != nil {
				return empty, err
			}
			if !clockIsRegistered(registered, nil, occTP.ClockID, occTP.BootID, occTP.Origin) {
				return empty, fmt.Errorf("journal_rules: %s occurred_at clock (%s/%s/%s) is not registered: register clocks before use", where, occTP.ClockID, occTP.BootID, occTP.Origin)
			}
		} else {
			return empty, fmt.Errorf("journal_rules: %s occurred_at must be TimePoint or Missing, got %T", where, ev.OccurredAt)
		}

		// Measurements delegate to clock_rules against pre-registration clocks.
		for mi, meas := range ev.Payload.Measurements {
			cm, err := toClockRulesMeasurement(meas)
			if err != nil {
				return empty, fmt.Errorf("journal_rules: %s measurements[%d]: %v", where, mi, err)
			}
			if err := clock_rules.ValidateMeasurement(cm, registeredList); err != nil {
				return empty, fmt.Errorf("journal_rules: %s measurements[%d] %q: %v", where, mi, meas.MeasurementID, err)
			}
		}

		// Commit the atomic registration after this event's own checks.
		if newlyRegistered != nil {
			key := newlyRegistered.ClockID + "\x00" + newlyRegistered.BootID + "\x00" + newlyRegistered.Origin
			registered[key] = *newlyRegistered
			registeredList = append(registeredList, toClockRulesClock(*newlyRegistered))
		}

		bySeq[ev.Sequence] = ev
	}

	// Evidence references: every coordinate agrees and nothing cites its own
	// or a future registration.
	for i := range events {
		ev := &events[i]
		where := fmt.Sprintf("sequence %d", ev.Sequence)
		refs := make([]EvidenceRef, 0, len(ev.Payload.EvidenceRefs)+len(ev.CausalRefs)+2)
		refs = append(refs, ev.Payload.EvidenceRefs...)
		refs = append(refs, ev.CausalRefs...)
		var embedded []EvidenceRef
		collectEmbeddedRefs(map[string]any(ev.Payload.Data), &embedded)
		refs = append(refs, embedded...)
		for _, ref := range refs {
			if ref.JournalID != manifest.JournalID {
				return empty, fmt.Errorf("journal_rules: %s cites journal %q, journal is %q: all coordinates must agree", where, ref.JournalID, manifest.JournalID)
			}
			if ref.Sequence >= ev.Sequence {
				return empty, fmt.Errorf("journal_rules: %s cites sequence %d: a publication cannot cite its own future registration", where, ref.Sequence)
			}
			if ref.Sequence < 1 {
				return empty, fmt.Errorf("journal_rules: %s cites invalid sequence %d", where, ref.Sequence)
			}
			target := bySeq[ref.Sequence]
			if target == nil {
				return empty, fmt.Errorf("journal_rules: %s cites missing sequence %d", where, ref.Sequence)
			}
			if target.EventID != ref.EventID {
				return empty, fmt.Errorf("journal_rules: %s cites sequence %d event_id %q, journal holds %q: all coordinates must agree", where, ref.Sequence, ref.EventID, target.EventID)
			}
			if target.EventHash != ref.EventHash {
				return empty, fmt.Errorf("journal_rules: %s cites sequence %d hash %q, journal holds %q: all coordinates must agree", where, ref.Sequence, ref.EventHash, target.EventHash)
			}
			if !validJSONPointer(ref.Pointer) {
				return empty, fmt.Errorf("journal_rules: %s cites invalid JSON pointer %q", where, ref.Pointer)
			}
			targetRaw, err := json.Marshal(target)
			if err != nil {
				return empty, fmt.Errorf("journal_rules: %s: cannot marshal target: %v", where, err)
			}
			if _, err := resolvePointer(targetRaw, ref.Pointer); err != nil {
				return empty, fmt.Errorf("journal_rules: %s cites unresolvable pointer %q at sequence %d: %v", where, ref.Pointer, ref.Sequence, err)
			}
		}
		// A derivation must not embed its own digest: that is a hash cycle.
		if ev.EventHash != "" && dataContainsString(map[string]any(ev.Payload.Data), ev.EventHash) {
			return empty, fmt.Errorf("journal_rules: %s embeds its own event digest in its derivation inputs: register after bytes exist", where)
		}
	}

	head := events[len(events)-1].EventHash
	return JournalPrefix{JournalID: manifest.JournalID, LastSequence: int64(len(events)), HeadHash: head}, nil
}

func clockIsRegistered(registered map[string]ClockDescriptor, extra *ClockDescriptor, clockID, bootID, origin string) bool {
	key := clockID + "\x00" + bootID + "\x00" + origin
	if _, ok := registered[key]; ok {
		return true
	}
	if extra != nil && extra.ClockID == clockID && extra.BootID == bootID && extra.Origin == origin {
		return true
	}
	return false
}

func parseClockDescriptorData(data map[string]any) (ClockDescriptor, error) {
	if data == nil {
		return ClockDescriptor{}, fmt.Errorf("data must be a clock descriptor object")
	}
	get := func(key string) (string, error) {
		raw, ok := data[key]
		if !ok {
			return "", fmt.Errorf("missing required field %q", key)
		}
		s, ok := raw.(string)
		if !ok || strings.TrimSpace(s) == "" {
			return "", fmt.Errorf("field %q must be a nonempty string", key)
		}
		return s, nil
	}
	cid, err := get("clock_id")
	if err != nil {
		return ClockDescriptor{}, err
	}
	bid, err := get("boot_id")
	if err != nil {
		return ClockDescriptor{}, err
	}
	origin, err := get("origin")
	if err != nil {
		return ClockDescriptor{}, err
	}
	source, err := get("source_id")
	if err != nil {
		return ClockDescriptor{}, err
	}
	basis, err := get("basis")
	if err != nil {
		return ClockDescriptor{}, err
	}
	unit, err := get("unit")
	if err != nil {
		return ClockDescriptor{}, err
	}
	return ClockDescriptor{ClockID: cid, BootID: bid, Origin: origin, SourceID: source, Basis: basis, Unit: unit}, nil
}

// ---------------------------------------------------------------------------
// ResolveEvidence.
// ---------------------------------------------------------------------------

// ResolveEvidence resolves one EvidenceRef against the named prefix. The
// reference must lie inside the prefix, every coordinate must agree with the
// retained event, the prefix head must match its verified hash, and the JSON
// pointer must resolve. Evidence beyond the pinned prefix is rejected.
func ResolveEvidence(prefix JournalPrefix, events []JournalEnvelope, reference EvidenceRef) ([]byte, error) {
	if strings.TrimSpace(prefix.JournalID) == "" {
		return nil, fmt.Errorf("journal_rules: prefix journal_id must be nonempty")
	}
	if prefix.LastSequence < 1 {
		return nil, fmt.Errorf("journal_rules: prefix last_sequence starts at 1, got %d", prefix.LastSequence)
	}
	if !validDigest(prefix.HeadHash) {
		return nil, fmt.Errorf("journal_rules: prefix head_hash %q is not a valid digest", prefix.HeadHash)
	}
	if len(events) == 0 {
		return nil, fmt.Errorf("journal_rules: cannot resolve against an empty journal")
	}
	if reference.JournalID != prefix.JournalID {
		return nil, fmt.Errorf("journal_rules: reference journal %q does not match prefix journal %q: all coordinates must agree", reference.JournalID, prefix.JournalID)
	}
	if reference.Sequence < 1 {
		return nil, fmt.Errorf("journal_rules: reference sequence starts at 1, got %d", reference.Sequence)
	}
	if reference.Sequence > prefix.LastSequence {
		return nil, fmt.Errorf("journal_rules: reference sequence %d is beyond pinned prefix ending at %d", reference.Sequence, prefix.LastSequence)
	}
	if !validDigest(reference.EventHash) {
		return nil, fmt.Errorf("journal_rules: reference event_hash %q is not a valid digest", reference.EventHash)
	}
	if !validJSONPointer(reference.Pointer) {
		return nil, fmt.Errorf("journal_rules: reference pointer %q is not a valid JSON pointer", reference.Pointer)
	}
	// Locate the prefix head and the target by their recorded sequences.
	var head *JournalEnvelope
	var target *JournalEnvelope
	for i := range events {
		if events[i].Sequence == prefix.LastSequence && events[i].JournalID == prefix.JournalID {
			head = &events[i]
		}
		if events[i].Sequence == reference.Sequence && events[i].JournalID == reference.JournalID {
			target = &events[i]
		}
	}
	if head == nil {
		return nil, fmt.Errorf("journal_rules: prefix head sequence %d is not retained", prefix.LastSequence)
	}
	headHash, err := computeEventHash(*head)
	if err != nil {
		return nil, fmt.Errorf("journal_rules: prefix head hash: %v", err)
	}
	if head.EventHash != headHash {
		return nil, fmt.Errorf("journal_rules: prefix head at %d carries hash %q, recomputed %q: changed content detected", prefix.LastSequence, head.EventHash, headHash)
	}
	if prefix.HeadHash != head.EventHash {
		return nil, fmt.Errorf("journal_rules: prefix head_hash %q does not equal verified event hash %q at %d", prefix.HeadHash, head.EventHash, prefix.LastSequence)
	}
	if target == nil {
		return nil, fmt.Errorf("journal_rules: reference sequence %d is not retained", reference.Sequence)
	}
	if target.EventID != reference.EventID {
		return nil, fmt.Errorf("journal_rules: reference event_id %q does not match retained %q at sequence %d: all coordinates must agree", reference.EventID, target.EventID, reference.Sequence)
	}
	if target.EventHash != reference.EventHash {
		return nil, fmt.Errorf("journal_rules: reference event_hash %q does not match retained %q at sequence %d: all coordinates must agree", reference.EventHash, target.EventHash, reference.Sequence)
	}
	recomputed, err := computeEventHash(*target)
	if err != nil {
		return nil, fmt.Errorf("journal_rules: target hash: %v", err)
	}
	if target.EventHash != recomputed {
		return nil, fmt.Errorf("journal_rules: retained event at %d carries hash %q, recomputed %q: changed content detected", reference.Sequence, target.EventHash, recomputed)
	}
	targetRaw, err := json.Marshal(target)
	if err != nil {
		return nil, fmt.Errorf("journal_rules: cannot marshal target: %v", err)
	}
	return resolvePointer(targetRaw, reference.Pointer)
}

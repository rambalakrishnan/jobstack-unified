// Package clock_rules implements the tier-1 Hellscape clock and timing rules.
//
// It enforces seam-mappings/hellscape-seam-mapping.md sections 3.5
// (TimePoint and ClockDescriptor), 3.6 (Measurement), and the timing rows of
// 16.2 (Evidence and timing corpus), together with the EK-TIME,
// EK-TIMING-INTERPRETATION, LIFE-TIME, EXT-TIME-NULL, and OWD-TIME-PROVENANCE
// invariants:
//
//   - Every Measurement and TimePoint identifies its origin, clock, and boot.
//     Clocks are registered before use. Monotonic offsets persist relative to
//     that boot. Subtraction across clock IDs, boot identities, or origins is
//     rejected. UTC is annotation only.
//   - Exact describes the recorded value at its declared origin. Subject
//     reports are preserved unchanged, including exact zero. A native duration
//     without native clock coordinates uses an opaque-report clock; native
//     endpoints are never invented.
//   - Endpoint subtraction requires one registered clock/boot/origin and
//     ordered endpoints; the value equals the endpoint difference within
//     serialization resolution. Bounded estimates carry at least one numeric
//     bound, ordered when both exist. Unavailable estimates carry a reasoned
//     Missing envelope with unavailable method and censoring.
//   - A comparability_group label alone never proves compatible boundaries.
//     Aggregate runtime is never divided into invented primitive durations.
//     Human pauses remain workflow elapsed time, never framework primitive time.
//   - Configured limits are not measurements and local deadlines are not
//     native cancellation.
//
// Structural gates (duplicate keys, bare nulls, reasoned Missing envelopes,
// digest/date/URI format assertions) are delegated to evidence_codec before
// timing-specific semantic rules are applied.
package clock_rules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	evidence_codec "evidence_codec"
)

// Origins identifies the four EK measurement origins.
const (
	OriginEngineMeasured  = "engine_measured"
	OriginBrowserMeasured = "browser_measured"
	OriginSubjectReported = "subject_reported"
	OriginManualReference = "manual_reference"
)

// Clock bases.
const (
	BasisMonotonicOffset = "monotonic_offset"
	BasisOpaqueReport    = "opaque_report"
)

// Estimate kinds.
const (
	EstimateExact       = "exact"
	EstimateBounded     = "bounded"
	EstimateUnavailable = "unavailable"
)

// Measurement methods.
const (
	MethodEndpointDifference = "endpoint_difference"
	MethodSourceValue        = "source_value"
	MethodEvidenceBound      = "evidence_bound"
	MethodUnavailable        = "unavailable"
)

// Censoring flags.
const (
	CensoringNone        = "none"
	CensoringLeft        = "left"
	CensoringRight       = "right"
	CensoringBoth        = "both"
	CensoringUnavailable = "unavailable"
)

// Quantities.
const (
	QuantityDuration = "duration"
	QuantityScalar   = "scalar"
)

// testDigestHead is a well-formed digest used only to build the minimal
// diagnostic envelope submitted to the evidence_codec structural gate. It is
// not measurement evidence.
const testDigestHead = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// epsilon is the floating-point comparison tolerance for exact endpoint
// arithmetic when no serialization resolution is declared. A declared numeric
// resolution widens the tolerance by exactly that resolution; the kernel
// endpoint-difference value itself is never altered.
const epsilon = 1e-9

// Missing is a typed EK.Missing envelope: {"value":null,"reason":...}.
// Detail is optional; empty means absent.
type Missing struct {
	Reason string
	Detail string
}

// TimePoint is a coordinate in a registered monotonic clock. UTCAnnotation is
// either a string RFC3339 date-time annotation or a Missing envelope. It is
// never a basis for duration subtraction.
type TimePoint struct {
	ClockID           string
	BootID            string
	Origin            string
	MonotonicOffsetMs float64
	UTCAnnotation     any
}

// ClockDescriptor registers one clock lifetime.
type ClockDescriptor struct {
	ClockID  string
	BootID   string
	Origin   string
	SourceID string
	Basis    string
	Unit     string
}

// Scope identifies the measured entity.
type Scope struct {
	Kind string
	ID   string
}

// Estimate is the discriminated measurement estimate.
//   - Exact: Value is numeric; LowerBound/UpperBound must be nil.
//   - Bounded: Value must be nil; LowerBound/UpperBound are each numeric or
//     Missing with at least one numeric.
//   - Unavailable: Value is Missing; LowerBound/UpperBound must be nil.
type Estimate struct {
	Kind       string
	Value      any
	LowerBound any
	UpperBound any
}

// Measurement is the EK Measurement record validated by this module. Start
// and End are each a TimePoint (or *TimePoint) or a Missing (or *Missing).
// Resolution is numeric or Missing. ComparabilityGroup is a string identifier
// or Missing. AggregateSource, when nonempty, declares that this measurement
// was derived by splitting the named aggregate runtime; such derivations are
// rejected unless the measurement carries independent endpoint_difference
// evidence on its own registered clock.
type Measurement struct {
	MeasurementID      string
	Name               string
	Scope              Scope
	Quantity           string
	Unit               string
	Origin             string
	ClockID            string
	BootID             string
	Method             string
	Start              any
	End                any
	Estimate           Estimate
	Resolution         any
	Censoring          string
	ComparabilityGroup any
	AggregateSource    string
}

// DurationLimit is a configured local bound: configuration, not an elapsed
// measurement or native cancellation guarantee.
type DurationLimit struct {
	Kind  string
	Unit  string
	Value float64
}

var validOrigins = map[string]bool{
	OriginEngineMeasured:  true,
	OriginBrowserMeasured: true,
	OriginSubjectReported: true,
	OriginManualReference: true,
}

var validBases = map[string]bool{
	BasisMonotonicOffset: true,
	BasisOpaqueReport:    true,
}

var validMethods = map[string]bool{
	MethodEndpointDifference: true,
	MethodSourceValue:        true,
	MethodEvidenceBound:      true,
	MethodUnavailable:        true,
}

var validCensoring = map[string]bool{
	CensoringNone:        true,
	CensoringLeft:        true,
	CensoringRight:       true,
	CensoringBoth:        true,
	CensoringUnavailable: true,
}

var validQuantities = map[string]bool{
	QuantityDuration: true,
	QuantityScalar:   true,
}

var validScopeKinds = map[string]bool{
	"run": true, "session": true, "connector_call": true, "workflow_step": true,
	"application_operation": true, "native_primitive": true, "recovery": true,
	"discovery": true, "capability": true, "resource": true,
}

var validNullReasons = map[string]bool{
	"not_enabled":          true,
	"not_applicable":       true,
	"not_observed":         true,
	"observation_lost":     true,
	"unsupported_by_subject": true,
	"manual_override":      true,
}

// ---------------------------------------------------------------------------
// Type coercion helpers (no in-band nulls).
// ---------------------------------------------------------------------------

func asMissing(v any) (Missing, bool) {
	switch t := v.(type) {
	case Missing:
		return t, true
	case *Missing:
		if t == nil {
			return Missing{}, false
		}
		return *t, true
	}
	return Missing{}, false
}

func asTimePoint(v any) (TimePoint, bool) {
	switch t := v.(type) {
	case TimePoint:
		return t, true
	case *TimePoint:
		if t == nil {
			return TimePoint{}, false
		}
		return *t, true
	}
	return TimePoint{}, false
}

func asNumber(v any) (float64, bool) {
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

func asString(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

// ---------------------------------------------------------------------------
// Field validators.
// ---------------------------------------------------------------------------

func validateMissing(m Missing, field string) error {
	if !validNullReasons[m.Reason] {
		return fmt.Errorf("clock_rules: %s has invalid NullReason %q: must be one of not_enabled, not_applicable, not_observed, observation_lost, unsupported_by_subject, manual_override", field, m.Reason)
	}
	if m.Detail != "" && strings.TrimSpace(m.Detail) == "" {
		return fmt.Errorf("clock_rules: %s Missing detail must be a nonempty string", field)
	}
	return nil
}

func validateUTCAnnotation(v any, field string) error {
	if v == nil {
		return fmt.Errorf("clock_rules: %s must be a date-time annotation or Missing, got in-band null", field)
	}
	if m, ok := asMissing(v); ok {
		return validateMissing(m, field)
	}
	if s, ok := asString(v); ok {
		if _, err := time.Parse(time.RFC3339, s); err != nil {
			return fmt.Errorf("clock_rules: %s is not a valid date-time annotation %q: %v", field, s, err)
		}
		return nil
	}
	return fmt.Errorf("clock_rules: %s must be a date-time annotation or Missing, got %T", field, v)
}

func validateTimePoint(tp TimePoint, field string) error {
	if strings.TrimSpace(tp.ClockID) == "" {
		return fmt.Errorf("clock_rules: %s clock_id must be a nonempty identifier", field)
	}
	if strings.TrimSpace(tp.BootID) == "" {
		return fmt.Errorf("clock_rules: %s boot_id must be a nonempty identifier", field)
	}
	if !validOrigins[tp.Origin] {
		return fmt.Errorf("clock_rules: %s has invalid origin %q", field, tp.Origin)
	}
	if math.IsNaN(tp.MonotonicOffsetMs) || math.IsInf(tp.MonotonicOffsetMs, 0) {
		return fmt.Errorf("clock_rules: %s monotonic_offset_ms must be finite, got %v", field, tp.MonotonicOffsetMs)
	}
	if tp.MonotonicOffsetMs < 0 {
		return fmt.Errorf("clock_rules: %s monotonic_offset_ms must be nonnegative, got %v", field, tp.MonotonicOffsetMs)
	}
	if err := validateUTCAnnotation(tp.UTCAnnotation, field+".utc_annotation"); err != nil {
		return err
	}
	return nil
}

func validateClockDescriptor(cd ClockDescriptor, field string) error {
	if strings.TrimSpace(cd.ClockID) == "" {
		return fmt.Errorf("clock_rules: %s clock_id must be a nonempty identifier", field)
	}
	if strings.TrimSpace(cd.BootID) == "" {
		return fmt.Errorf("clock_rules: %s boot_id must be a nonempty identifier", field)
	}
	if !validOrigins[cd.Origin] {
		return fmt.Errorf("clock_rules: %s has invalid origin %q", field, cd.Origin)
	}
	if strings.TrimSpace(cd.SourceID) == "" {
		return fmt.Errorf("clock_rules: %s source_id must be a nonempty identifier", field)
	}
	if !validBases[cd.Basis] {
		return fmt.Errorf("clock_rules: %s has invalid basis %q: must be monotonic_offset or opaque_report", field, cd.Basis)
	}
	if cd.Unit != "ms" {
		return fmt.Errorf("clock_rules: %s unit must be ms, got %q", field, cd.Unit)
	}
	return nil
}

// findClock returns the descriptor registered for the exact
// (clock_id, boot_id, origin) triple.
func findClock(clocks []ClockDescriptor, clockID, bootID, origin string) *ClockDescriptor {
	for i := range clocks {
		if clocks[i].ClockID == clockID && clocks[i].BootID == bootID && clocks[i].Origin == origin {
			return &clocks[i]
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// JSON projection for the evidence_codec structural gate.
// ---------------------------------------------------------------------------

func missingToJSON(m Missing) map[string]any {
	out := map[string]any{"value": nil, "reason": m.Reason}
	if m.Detail != "" {
		out["detail"] = m.Detail
	}
	return out
}

func timePointToJSON(tp TimePoint) (map[string]any, error) {
	var utc any
	if m, ok := asMissing(tp.UTCAnnotation); ok {
		utc = missingToJSON(m)
	} else if s, ok := asString(tp.UTCAnnotation); ok {
		utc = s
	} else if tp.UTCAnnotation == nil {
		return nil, fmt.Errorf("utc_annotation is an in-band null")
	} else {
		return nil, fmt.Errorf("utc_annotation has invalid type %T", tp.UTCAnnotation)
	}
	return map[string]any{
		"clock_id":            tp.ClockID,
		"boot_id":             tp.BootID,
		"origin":              tp.Origin,
		"monotonic_offset_ms": tp.MonotonicOffsetMs,
		"utc_annotation":      utc,
	}, nil
}

func endpointToJSON(v any, field string) (any, error) {
	if v == nil {
		return nil, fmt.Errorf("%s is an in-band null: must be TimePoint or Missing", field)
	}
	if m, ok := asMissing(v); ok {
		return missingToJSON(m), nil
	}
	if tp, ok := asTimePoint(v); ok {
		return timePointToJSON(tp)
	}
	return nil, fmt.Errorf("%s must be TimePoint or Missing, got %T", field, v)
}

func maybeNumberToJSON(v any, field string) (any, error) {
	if v == nil {
		return nil, fmt.Errorf("%s is an in-band null: must be numeric or Missing", field)
	}
	if m, ok := asMissing(v); ok {
		return missingToJSON(m), nil
	}
	if n, ok := asNumber(v); ok {
		return n, nil
	}
	return nil, fmt.Errorf("%s must be numeric or Missing, got %T", field, v)
}

func maybeStringToJSON(v any, field string) (any, error) {
	if v == nil {
		return nil, fmt.Errorf("%s is an in-band null: must be an identifier or Missing", field)
	}
	if m, ok := asMissing(v); ok {
		return missingToJSON(m), nil
	}
	if s, ok := asString(v); ok {
		return s, nil
	}
	return nil, fmt.Errorf("%s must be an identifier or Missing, got %T", field, v)
}

func estimateToJSON(e Estimate) (map[string]any, error) {
	switch e.Kind {
	case EstimateExact:
		if e.Value == nil {
			return nil, fmt.Errorf("estimate.value is an in-band null for exact estimate")
		}
		if m, ok := asMissing(e.Value); ok {
			_ = m
			return nil, fmt.Errorf("exact estimate value must be numeric, got Missing")
		}
		n, ok := asNumber(e.Value)
		if !ok {
			return nil, fmt.Errorf("exact estimate value must be numeric, got %T", e.Value)
		}
		return map[string]any{"kind": EstimateExact, "value": n}, nil
	case EstimateBounded:
		if e.LowerBound == nil || e.UpperBound == nil {
			return nil, fmt.Errorf("bounded estimate bounds must each be numeric or Missing")
		}
		lo, err := maybeNumberToJSON(e.LowerBound, "estimate.lower_bound")
		if err != nil {
			return nil, err
		}
		hi, err := maybeNumberToJSON(e.UpperBound, "estimate.upper_bound")
		if err != nil {
			return nil, err
		}
		return map[string]any{"kind": EstimateBounded, "lower_bound": lo, "upper_bound": hi}, nil
	case EstimateUnavailable:
		if e.Value == nil {
			return nil, fmt.Errorf("unavailable estimate value is an in-band null: must be Missing with reason")
		}
		m, ok := asMissing(e.Value)
		if !ok {
			return nil, fmt.Errorf("unavailable estimate value must be Missing with reason, got %T", e.Value)
		}
		return map[string]any{"kind": EstimateUnavailable, "value": missingToJSON(m)}, nil
	}
	return nil, fmt.Errorf("estimate has invalid kind %q", e.Kind)
}

func measurementToJSON(m Measurement) (map[string]any, error) {
	start, err := endpointToJSON(m.Start, "start")
	if err != nil {
		return nil, err
	}
	end, err := endpointToJSON(m.End, "end")
	if err != nil {
		return nil, err
	}
	est, err := estimateToJSON(m.Estimate)
	if err != nil {
		return nil, err
	}
	res, err := maybeNumberToJSON(m.Resolution, "resolution")
	if err != nil {
		return nil, err
	}
	cg, err := maybeStringToJSON(m.ComparabilityGroup, "comparability_group")
	if err != nil {
		return nil, err
	}
	out := map[string]any{
		"measurement_id":      m.MeasurementID,
		"name":                m.Name,
		"scope":               map[string]any{"kind": m.Scope.Kind, "id": m.Scope.ID},
		"quantity":            m.Quantity,
		"unit":                m.Unit,
		"origin":              m.Origin,
		"clock_id":            m.ClockID,
		"boot_id":             m.BootID,
		"method":              m.Method,
		"start":               start,
		"end":                 end,
		"estimate":            est,
		"resolution":          res,
		"censoring":           m.Censoring,
		"comparability_group": cg,
	}
	if m.AggregateSource != "" {
		out["aggregate_source"] = m.AggregateSource
	}
	return out, nil
}

// runStructuralGate projects the measurement into a minimal diagnostic record
// and enforces the evidence_codec structural gates (no bare nulls, reasoned
// Missing envelopes, digest/date/URI format assertions, closed top-level
// object). Timing semantics are checked separately below.
func runStructuralGate(m Measurement) error {
	mm, err := measurementToJSON(m)
	if err != nil {
		return fmt.Errorf("clock_rules: structural projection: %v", err)
	}
	doc := map[string]any{
		"record_type":      "diagnostic",
		"schema_version":   "0.1.0",
		"diagnostic_id":    "clock-rules-structural-probe",
		"analysis_revision": 1,
		"run_id":           "clock-rules-probe-run",
		"input_prefix": map[string]any{
			"journal_id":    "probe-journal",
			"last_sequence": 1,
			"head_hash":     testDigestHead,
		},
		"measurements": []any{mm},
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("clock_rules: structural projection encode: %v", err)
	}
	if err := evidence_codec.ValidateRecord("0.1.0", "diagnostic", bytes.TrimSpace(buf.Bytes())); err != nil {
		return fmt.Errorf("clock_rules: structural gate: %v", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Public interface.
// ---------------------------------------------------------------------------

// ValidateMeasurement enforces the EK/LIFE/EXT/OWD timing rules for one
// measurement against the registered clock lifetimes. It never subtracts
// coordinates across clock IDs, boot identities, or origins; UTC annotations
// are validated as date-time-or-Missing but never drive elapsed arithmetic.
func ValidateMeasurement(m Measurement, clocks []ClockDescriptor) error {
	if strings.TrimSpace(m.MeasurementID) == "" {
		return fmt.Errorf("clock_rules: measurement_id must be a nonempty identifier")
	}
	if strings.TrimSpace(m.Name) == "" {
		return fmt.Errorf("clock_rules: name must be a registered semantic measurement name")
	}
	if !validScopeKinds[m.Scope.Kind] {
		return fmt.Errorf("clock_rules: scope.kind %q is not a registered scope kind", m.Scope.Kind)
	}
	if strings.TrimSpace(m.Scope.ID) == "" {
		return fmt.Errorf("clock_rules: scope.id must be a nonempty identifier")
	}
	if !validQuantities[m.Quantity] {
		return fmt.Errorf("clock_rules: quantity %q must be duration or scalar", m.Quantity)
	}
	if m.Quantity == QuantityDuration {
		if m.Unit != "ms" {
			return fmt.Errorf("clock_rules: duration unit must be ms, got %q", m.Unit)
		}
	} else if strings.TrimSpace(m.Unit) == "" {
		return fmt.Errorf("clock_rules: scalar unit must be a nonempty identifier")
	}
	if !validOrigins[m.Origin] {
		return fmt.Errorf("clock_rules: origin %q must be one of engine_measured, browser_measured, subject_reported, manual_reference", m.Origin)
	}
	if !validMethods[m.Method] {
		return fmt.Errorf("clock_rules: method %q must be one of endpoint_difference, source_value, evidence_bound, unavailable", m.Method)
	}
	if !validCensoring[m.Censoring] {
		return fmt.Errorf("clock_rules: censoring %q must be one of none, left, right, both, unavailable", m.Censoring)
	}
	if strings.TrimSpace(m.ClockID) == "" || strings.TrimSpace(m.BootID) == "" {
		return fmt.Errorf("clock_rules: measurement clock_id and boot_id must be nonempty identifiers")
	}
	// Human pauses remain workflow elapsed time, never framework primitive time.
	if m.Origin == OriginManualReference && m.Scope.Kind == "native_primitive" {
		return fmt.Errorf("clock_rules: human pauses remain workflow elapsed time, not framework primitive time: manual_reference origin cannot scope native_primitive")
	}

	for i := range clocks {
		if err := validateClockDescriptor(clocks[i], fmt.Sprintf("clocks[%d]", i)); err != nil {
			return err
		}
	}
	registered := findClock(clocks, m.ClockID, m.BootID, m.Origin)
	if registered == nil {
		// Distinguish unknown lifetime from origin mismatch for diagnostics.
		for i := range clocks {
			if clocks[i].ClockID == m.ClockID && clocks[i].BootID == m.BootID {
				return fmt.Errorf("clock_rules: measurement origin %q does not match registered clock (%s/%s) origin %q: one clock, boot, and origin required", m.Origin, m.ClockID, m.BootID, clocks[i].Origin)
			}
		}
		return fmt.Errorf("clock_rules: measurement clock (%s/%s/%s) is not registered: register clocks before use", m.ClockID, m.BootID, m.Origin)
	}

	// Endpoints: TimePoint or Missing, never in-band nulls.
	if m.Start == nil || m.End == nil {
		return fmt.Errorf("clock_rules: start and end must each be TimePoint or Missing: no in-band nulls")
	}
	startTP, startIsTP := asTimePoint(m.Start)
	endTP, endIsTP := asTimePoint(m.End)
	startMiss, startIsMiss := asMissing(m.Start)
	endMiss, endIsMiss := asMissing(m.End)
	if !startIsTP && !startIsMiss {
		return fmt.Errorf("clock_rules: start must be TimePoint or Missing, got %T: no in-band nulls", m.Start)
	}
	if !endIsTP && !endIsMiss {
		return fmt.Errorf("clock_rules: end must be TimePoint or Missing, got %T: no in-band nulls", m.End)
	}
	if startIsTP {
		if err := validateTimePoint(startTP, "start"); err != nil {
			return err
		}
		if findClock(clocks, startTP.ClockID, startTP.BootID, startTP.Origin) == nil {
			return fmt.Errorf("clock_rules: start TimePoint clock (%s/%s/%s) is not registered", startTP.ClockID, startTP.BootID, startTP.Origin)
		}
	} else if err := validateMissing(startMiss, "start"); err != nil {
		return err
	}
	if endIsTP {
		if err := validateTimePoint(endTP, "end"); err != nil {
			return err
		}
		if findClock(clocks, endTP.ClockID, endTP.BootID, endTP.Origin) == nil {
			return fmt.Errorf("clock_rules: end TimePoint clock (%s/%s/%s) is not registered", endTP.ClockID, endTP.BootID, endTP.Origin)
		}
	} else if err := validateMissing(endMiss, "end"); err != nil {
		return err
	}

	// Opaque-report clocks never carry native endpoints.
	if registered.Basis == BasisOpaqueReport && (startIsTP || endIsTP) {
		return fmt.Errorf("clock_rules: opaque report clock (%s/%s) must not invent native endpoints: start and end must be Missing", m.ClockID, m.BootID)
	}

	// Resolution: nonnegative number or Missing.
	var resolutionNumeric bool
	var resolutionValue float64
	if m.Resolution == nil {
		return fmt.Errorf("clock_rules: resolution must be a nonnegative number or Missing: no in-band nulls")
	}
	if rm, ok := asMissing(m.Resolution); ok {
		if err := validateMissing(rm, "resolution"); err != nil {
			return err
		}
	} else if n, ok := asNumber(m.Resolution); ok {
		if math.IsNaN(n) || math.IsInf(n, 0) {
			return fmt.Errorf("clock_rules: resolution must be finite, got %v", n)
		}
		if n < 0 {
			return fmt.Errorf("clock_rules: resolution must be nonnegative, got %v", n)
		}
		resolutionNumeric = true
		resolutionValue = n
	} else {
		return fmt.Errorf("clock_rules: resolution must be a nonnegative number or Missing, got %T", m.Resolution)
	}

	// Comparability group: identifier or Missing. A label alone never proves
	// compatible boundaries; it is validated for shape only and ignored below.
	if m.ComparabilityGroup == nil {
		return fmt.Errorf("clock_rules: comparability_group must be an identifier or Missing: no in-band nulls")
	}
	if cm, ok := asMissing(m.ComparabilityGroup); ok {
		if err := validateMissing(cm, "comparability_group"); err != nil {
			return err
		}
	} else if s, ok := asString(m.ComparabilityGroup); ok {
		if strings.TrimSpace(s) == "" {
			return fmt.Errorf("clock_rules: comparability_group identifier must be nonempty")
		}
	} else {
		return fmt.Errorf("clock_rules: comparability_group must be an identifier or Missing, got %T", m.ComparabilityGroup)
	}

	// Estimate alternatives.
	switch m.Estimate.Kind {
	case EstimateExact:
		if m.Estimate.Value == nil {
			return fmt.Errorf("clock_rules: exact estimate value is an in-band null: must be numeric")
		}
		if _, ok := asMissing(m.Estimate.Value); ok {
			return fmt.Errorf("clock_rules: exact estimate value must be numeric, got Missing")
		}
		v, ok := asNumber(m.Estimate.Value)
		if !ok {
			return fmt.Errorf("clock_rules: exact estimate value must be numeric, got %T", m.Estimate.Value)
		}
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return fmt.Errorf("clock_rules: exact estimate value must be finite, got %v", v)
		}
		if m.Quantity == QuantityDuration && v < 0 {
			return fmt.Errorf("clock_rules: duration values must be nonnegative, got %v", v)
		}
		if m.Estimate.LowerBound != nil || m.Estimate.UpperBound != nil {
			return fmt.Errorf("clock_rules: exact estimate must not carry bounds")
		}
		// Exact estimates have no censoring; exact pairs with
		// endpoint_difference or source_value only.
		if m.Censoring != CensoringNone {
			return fmt.Errorf("clock_rules: exact estimates have no censoring, got %q", m.Censoring)
		}
		if m.Method != MethodEndpointDifference && m.Method != MethodSourceValue {
			return fmt.Errorf("clock_rules: exact estimate requires method endpoint_difference or source_value, got %q", m.Method)
		}
	case EstimateBounded:
		if m.Estimate.Value != nil {
			return fmt.Errorf("clock_rules: bounded estimate must not carry an exact value")
		}
		if m.Estimate.LowerBound == nil || m.Estimate.UpperBound == nil {
			return fmt.Errorf("clock_rules: bounded estimate lower_bound and upper_bound must each be numeric or Missing")
		}
		var loNum, hiNum bool
		var loVal, hiVal float64
		if lm, ok := asMissing(m.Estimate.LowerBound); ok {
			if err := validateMissing(lm, "estimate.lower_bound"); err != nil {
				return err
			}
		} else if n, ok := asNumber(m.Estimate.LowerBound); ok {
			if math.IsNaN(n) || math.IsInf(n, 0) {
				return fmt.Errorf("clock_rules: bounded lower_bound must be finite, got %v", n)
			}
			if m.Quantity == QuantityDuration && n < 0 {
				return fmt.Errorf("clock_rules: duration bounds must be nonnegative, got lower %v", n)
			}
			loNum, loVal = true, n
		} else {
			return fmt.Errorf("clock_rules: bounded lower_bound must be numeric or Missing, got %T", m.Estimate.LowerBound)
		}
		if hm, ok := asMissing(m.Estimate.UpperBound); ok {
			if err := validateMissing(hm, "estimate.upper_bound"); err != nil {
				return err
			}
		} else if n, ok := asNumber(m.Estimate.UpperBound); ok {
			if math.IsNaN(n) || math.IsInf(n, 0) {
				return fmt.Errorf("clock_rules: bounded upper_bound must be finite, got %v", n)
			}
			if m.Quantity == QuantityDuration && n < 0 {
				return fmt.Errorf("clock_rules: duration bounds must be nonnegative, got upper %v", n)
			}
			hiNum, hiVal = true, n
		} else {
			return fmt.Errorf("clock_rules: bounded upper_bound must be numeric or Missing, got %T", m.Estimate.UpperBound)
		}
		if !loNum && !hiNum {
			return fmt.Errorf("clock_rules: bounded interval requires at least one numeric bound")
		}
		if loNum && hiNum && loVal > hiVal {
			return fmt.Errorf("clock_rules: bounded interval requires lower_bound <= upper_bound, got %v > %v", loVal, hiVal)
		}
		if m.Method != MethodEvidenceBound {
			return fmt.Errorf("clock_rules: bounded estimates use evidence_bound method, got %q", m.Method)
		}
		if m.Censoring == CensoringUnavailable {
			return fmt.Errorf("clock_rules: bounded estimates must not use unavailable censoring")
		}
	case EstimateUnavailable:
		if m.Estimate.Value == nil {
			return fmt.Errorf("clock_rules: unavailable estimate value is an in-band null: must be Missing with reason")
		}
		vm, ok := asMissing(m.Estimate.Value)
		if !ok {
			return fmt.Errorf("clock_rules: missing duration is unavailable with reason: estimate value must be Missing, got %T", m.Estimate.Value)
		}
		if err := validateMissing(vm, "estimate.value"); err != nil {
			return err
		}
		if m.Estimate.LowerBound != nil || m.Estimate.UpperBound != nil {
			return fmt.Errorf("clock_rules: unavailable estimate must not carry bounds")
		}
		if m.Method != MethodUnavailable {
			return fmt.Errorf("clock_rules: unavailable estimates use unavailable method, got %q", m.Method)
		}
		if m.Censoring != CensoringUnavailable {
			return fmt.Errorf("clock_rules: unavailable estimates use unavailable censoring, got %q", m.Censoring)
		}
	default:
		return fmt.Errorf("clock_rules: estimate kind %q must be exact, bounded, or unavailable", m.Estimate.Kind)
	}

	// Method-specific endpoint rules. Comparability groups never override
	// these checks.
	switch m.Method {
	case MethodEndpointDifference:
		if m.Quantity != QuantityDuration {
			return fmt.Errorf("clock_rules: endpoint_difference requires duration quantity, got %q", m.Quantity)
		}
		if m.Estimate.Kind != EstimateExact {
			return fmt.Errorf("clock_rules: endpoint_difference requires an exact estimate, got %q", m.Estimate.Kind)
		}
		if !startIsTP || !endIsTP {
			return fmt.Errorf("clock_rules: endpoint_difference requires concrete start and end TimePoints")
		}
		if registered.Basis != BasisMonotonicOffset {
			return fmt.Errorf("clock_rules: endpoint_difference requires a monotonic_offset clock, got %q", registered.Basis)
		}
		// One clock, boot, and origin across measurement and both endpoints.
		// No subtraction happens unless all three agree.
		if startTP.ClockID != m.ClockID || endTP.ClockID != m.ClockID {
			return fmt.Errorf("clock_rules: cross-clock endpoints reject exact duration: measurement clock %q but endpoints %q/%q", m.ClockID, startTP.ClockID, endTP.ClockID)
		}
		if startTP.BootID != m.BootID || endTP.BootID != m.BootID {
			return fmt.Errorf("clock_rules: cross-boot endpoints reject exact duration: measurement boot %q but endpoints %q/%q", m.BootID, startTP.BootID, endTP.BootID)
		}
		if startTP.Origin != m.Origin || endTP.Origin != m.Origin {
			return fmt.Errorf("clock_rules: endpoint_difference requires one origin: measurement %q but endpoints %q/%q", m.Origin, startTP.Origin, endTP.Origin)
		}
		if endTP.MonotonicOffsetMs < startTP.MonotonicOffsetMs {
			return fmt.Errorf("clock_rules: end is not before start: start %v > end %v", startTP.MonotonicOffsetMs, endTP.MonotonicOffsetMs)
		}
		// The value equals the endpoint difference within serialization
		// resolution. Resolution widens tolerance only; the kernel value is
		// never altered. UTC annotations play no role here.
		value, _ := asNumber(m.Estimate.Value)
		diff := endTP.MonotonicOffsetMs - startTP.MonotonicOffsetMs
		tolerance := epsilon
		if resolutionNumeric {
			tolerance = resolutionValue + epsilon
		}
		if math.Abs(value-diff) > tolerance {
			return fmt.Errorf("clock_rules: endpoint difference must equal recorded arithmetic: endpoints %v-%v=%v but estimate %v exceeds tolerance %v", startTP.MonotonicOffsetMs, endTP.MonotonicOffsetMs, diff, value, tolerance)
		}
	case MethodSourceValue:
		if m.Estimate.Kind != EstimateExact {
			return fmt.Errorf("clock_rules: source_value requires an exact estimate, got %q", m.Estimate.Kind)
		}
		if startIsTP != endIsTP {
			return fmt.Errorf("clock_rules: source_value start and end must both be Missing or both be TimePoints")
		}
		if startIsTP {
			if registered.Basis != BasisMonotonicOffset {
				return fmt.Errorf("clock_rules: opaque report clock must not invent native endpoints for source_value")
			}
			if startTP.ClockID != m.ClockID || endTP.ClockID != m.ClockID {
				return fmt.Errorf("clock_rules: cross-clock endpoints reject exact duration: measurement clock %q but endpoints %q/%q", m.ClockID, startTP.ClockID, endTP.ClockID)
			}
			if startTP.BootID != m.BootID || endTP.BootID != m.BootID {
				return fmt.Errorf("clock_rules: cross-boot endpoints reject exact duration: measurement boot %q but endpoints %q/%q", m.BootID, startTP.BootID, endTP.BootID)
			}
			if startTP.Origin != m.Origin || endTP.Origin != m.Origin {
				return fmt.Errorf("clock_rules: source_value endpoints require one origin: measurement %q but endpoints %q/%q", m.Origin, startTP.Origin, endTP.Origin)
			}
			if endTP.MonotonicOffsetMs < startTP.MonotonicOffsetMs {
				return fmt.Errorf("clock_rules: end is not before start: start %v > end %v", startTP.MonotonicOffsetMs, endTP.MonotonicOffsetMs)
			}
			// Reported values are preserved unchanged; no arithmetic
			// comparison against endpoint context for source_value.
		} else if m.Quantity == QuantityDuration {
			// A native duration without native clock coordinates uses an
			// opaque-report clock.
			if registered.Basis != BasisOpaqueReport {
				return fmt.Errorf("clock_rules: missing native endpoints require opaque report clock: exact duration with Missing endpoints on %q clock (%s/%s)", registered.Basis, m.ClockID, m.BootID)
			}
		}
	case MethodEvidenceBound:
		if m.Estimate.Kind != EstimateBounded {
			return fmt.Errorf("clock_rules: evidence_bound requires a bounded estimate, got %q", m.Estimate.Kind)
		}
		if startIsTP != endIsTP {
			return fmt.Errorf("clock_rules: evidence_bound start and end must both be Missing or both be TimePoints")
		}
		if startIsTP {
			if startTP.ClockID != m.ClockID || endTP.ClockID != m.ClockID {
				return fmt.Errorf("clock_rules: cross-clock endpoints rejected: measurement clock %q but endpoints %q/%q", m.ClockID, startTP.ClockID, endTP.ClockID)
			}
			if startTP.BootID != m.BootID || endTP.BootID != m.BootID {
				return fmt.Errorf("clock_rules: cross-boot endpoints rejected: measurement boot %q but endpoints %q/%q", m.BootID, startTP.BootID, endTP.BootID)
			}
			if startTP.Origin != m.Origin || endTP.Origin != m.Origin {
				return fmt.Errorf("clock_rules: bounded endpoints require one origin: measurement %q but endpoints %q/%q", m.Origin, startTP.Origin, endTP.Origin)
			}
			if endTP.MonotonicOffsetMs < startTP.MonotonicOffsetMs {
				return fmt.Errorf("clock_rules: end is not before start: start %v > end %v", startTP.MonotonicOffsetMs, endTP.MonotonicOffsetMs)
			}
		}
	case MethodUnavailable:
		if m.Estimate.Kind != EstimateUnavailable {
			return fmt.Errorf("clock_rules: unavailable method requires an unavailable estimate, got %q", m.Estimate.Kind)
		}
		if startIsTP != endIsTP {
			return fmt.Errorf("clock_rules: unavailable start and end must both be Missing or both be TimePoints")
		}
		if startIsTP {
			if startTP.ClockID != m.ClockID || endTP.ClockID != m.ClockID {
				return fmt.Errorf("clock_rules: cross-clock endpoints rejected: measurement clock %q but endpoints %q/%q", m.ClockID, startTP.ClockID, endTP.ClockID)
			}
			if startTP.BootID != m.BootID || endTP.BootID != m.BootID {
				return fmt.Errorf("clock_rules: cross-boot endpoints rejected: measurement boot %q but endpoints %q/%q", m.BootID, startTP.BootID, endTP.BootID)
			}
			if startTP.Origin != m.Origin || endTP.Origin != m.Origin {
				return fmt.Errorf("clock_rules: unavailable endpoints require one origin: measurement %q but endpoints %q/%q", m.Origin, startTP.Origin, endTP.Origin)
			}
			if endTP.MonotonicOffsetMs < startTP.MonotonicOffsetMs {
				return fmt.Errorf("clock_rules: end is not before start: start %v > end %v", startTP.MonotonicOffsetMs, endTP.MonotonicOffsetMs)
			}
		}
	}

	// Aggregate runtime is never divided into invented primitive durations.
	// An explicit AggregateSource derivation is accepted only with
	// independent endpoint_difference evidence on the measurement's own
	// registered clock.
	if strings.TrimSpace(m.AggregateSource) != "" {
		if m.Method != MethodEndpointDifference || !startIsTP || !endIsTP || m.Estimate.Kind != EstimateExact {
			return fmt.Errorf("clock_rules: aggregate runtime cannot invent primitive durations: derivation of %q from aggregate %q lacks independent endpoint_difference evidence", m.MeasurementID, m.AggregateSource)
		}
	}

	// Structural gates via the shared codec. Runs after semantic field-shape
	// checks so that timing errors keep their precise messages, but every
	// accepted measurement has passed the shared structural gate.
	if err := runStructuralGate(m); err != nil {
		return err
	}
	return nil
}

// ComputeDeadline returns the local deadline coordinate for start plus the
// configured limit on the same clock, boot, and origin. The limit is
// configuration, not a measurement; the returned TimePoint is a scheduled
// coordinate, not evidence that the clock reached it and not native
// cancellation. UTC annotations never affect the arithmetic: the deadline
// carries a Missing UTC annotation.
func ComputeDeadline(start TimePoint, limit DurationLimit) (TimePoint, error) {
	if err := validateTimePoint(start, "start"); err != nil {
		return TimePoint{}, err
	}
	if limit.Kind != EstimateExact {
		return TimePoint{}, fmt.Errorf("clock_rules: DurationLimit kind must be exact, got %q: configured limits are not measurements", limit.Kind)
	}
	if limit.Unit != "ms" {
		return TimePoint{}, fmt.Errorf("clock_rules: DurationLimit unit must be ms, got %q", limit.Unit)
	}
	if math.IsNaN(limit.Value) || math.IsInf(limit.Value, 0) {
		return TimePoint{}, fmt.Errorf("clock_rules: DurationLimit value must be finite, got %v", limit.Value)
	}
	if limit.Value < 0 {
		return TimePoint{}, fmt.Errorf("clock_rules: DurationLimit value must be nonnegative, got %v", limit.Value)
	}
	sum := start.MonotonicOffsetMs + limit.Value
	if math.IsNaN(sum) || math.IsInf(sum, 0) {
		return TimePoint{}, fmt.Errorf("clock_rules: deadline offset overflows finite arithmetic")
	}
	return TimePoint{
		ClockID:           start.ClockID,
		BootID:            start.BootID,
		Origin:            start.Origin,
		MonotonicOffsetMs: sum,
		UTCAnnotation:     Missing{Reason: "not_applicable", Detail: "deadline coordinate carries no observed UTC"},
	}, nil
}

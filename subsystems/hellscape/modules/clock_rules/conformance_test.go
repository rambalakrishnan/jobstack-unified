package clock_rules

import (
	"strings"
	"testing"
)

func testClocks() []ClockDescriptor {
	return []ClockDescriptor{
		{ClockID: "engine-clock", BootID: "boot-1", Origin: OriginEngineMeasured, SourceID: "engine", Basis: BasisMonotonicOffset, Unit: "ms"},
		{ClockID: "engine-clock", BootID: "boot-2", Origin: OriginEngineMeasured, SourceID: "engine", Basis: BasisMonotonicOffset, Unit: "ms"},
		{ClockID: "browser-clock", BootID: "boot-1", Origin: OriginBrowserMeasured, SourceID: "browser", Basis: BasisMonotonicOffset, Unit: "ms"},
		{ClockID: "subject-clock", BootID: "boot-1", Origin: OriginSubjectReported, SourceID: "subject", Basis: BasisOpaqueReport, Unit: "ms"},
		{ClockID: "manual-clock", BootID: "boot-1", Origin: OriginManualReference, SourceID: "operator", Basis: BasisMonotonicOffset, Unit: "ms"},
	}
}

func missing(reason string) Missing {
	return Missing{Reason: reason}
}

func tp(clock, boot, origin string, offset float64, utc any) TimePoint {
	return TimePoint{ClockID: clock, BootID: boot, Origin: origin, MonotonicOffsetMs: offset, UTCAnnotation: utc}
}

func baseMeasurement() Measurement {
	return Measurement{
		MeasurementID:      "m1",
		Name:               "workflow_elapsed",
		Scope:              Scope{Kind: "workflow_step", ID: "step-1"},
		Quantity:           QuantityDuration,
		Unit:               "ms",
		Origin:             OriginEngineMeasured,
		ClockID:            "engine-clock",
		BootID:             "boot-1",
		Method:             MethodUnavailable,
		Start:              missing("not_observed"),
		End:                missing("not_observed"),
		Estimate:           Estimate{Kind: EstimateUnavailable, Value: missing("not_observed")},
		Resolution:         missing("not_applicable"),
		Censoring:          CensoringUnavailable,
		ComparabilityGroup: missing("not_applicable"),
	}
}

func requirePass(t *testing.T, m Measurement, clocks []ClockDescriptor) {
	t.Helper()
	if err := ValidateMeasurement(m, clocks); err != nil {
		t.Fatalf("expected pass, got error: %v", err)
	}
}

func requireFail(t *testing.T, m Measurement, clocks []ClockDescriptor, substr string) {
	t.Helper()
	err := ValidateMeasurement(m, clocks)
	if err == nil {
		t.Fatalf("expected rejection containing %q, got pass", substr)
	}
	if substr != "" && !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(substr)) {
		t.Fatalf("expected error containing %q, got: %v", substr, err)
	}
}

func TestMissingDurationIsUnavailableWithReason(t *testing.T) {
	clocks := testClocks()
	valid := baseMeasurement()
	requirePass(t, valid, clocks)

	// Missing duration represented by exact zero on a monotonic clock is rejected.
	zeroAsMissing := baseMeasurement()
	zeroAsMissing.Method = MethodSourceValue
	zeroAsMissing.Estimate = Estimate{Kind: EstimateExact, Value: 0.0}
	zeroAsMissing.Censoring = CensoringNone
	requireFail(t, zeroAsMissing, clocks, "opaque")

	// Unavailable without a valid reason is rejected.
	badReason := baseMeasurement()
	badReason.Estimate = Estimate{Kind: EstimateUnavailable, Value: Missing{Reason: "manual_fixture_validation"}}
	requireFail(t, badReason, clocks, "NullReason")

	// Unavailable requires unavailable method and censoring.
	wrongMethod := baseMeasurement()
	wrongMethod.Method = MethodEndpointDifference
	requireFail(t, wrongMethod, clocks, "unavailable")

	wrongCensoring := baseMeasurement()
	wrongCensoring.Censoring = CensoringNone
	requireFail(t, wrongCensoring, clocks, "unavailable")

	// In-band nulls are rejected.
	nilStart := baseMeasurement()
	nilStart.Start = nil
	requireFail(t, nilStart, clocks, "in-band null")
}

func TestNativeZeroRemainsExactSubjectReportedZero(t *testing.T) {
	clocks := testClocks()
	// Opaque subject-reported zero is preserved as exact.
	reported := baseMeasurement()
	reported.MeasurementID = "native-zero"
	reported.Scope = Scope{Kind: "native_primitive", ID: "prim-1"}
	reported.Origin = OriginSubjectReported
	reported.ClockID = "subject-clock"
	reported.BootID = "boot-1"
	reported.Method = MethodSourceValue
	reported.Estimate = Estimate{Kind: EstimateExact, Value: 0.0}
	reported.Censoring = CensoringNone
	requirePass(t, reported, clocks)

	// Exact zero via endpoint difference with identical endpoints is valid.
	endpointZero := baseMeasurement()
	endpointZero.MeasurementID = "endpoint-zero"
	endpointZero.Method = MethodEndpointDifference
	endpointZero.Start = tp("engine-clock", "boot-1", OriginEngineMeasured, 100, missing("not_applicable"))
	endpointZero.End = tp("engine-clock", "boot-1", OriginEngineMeasured, 100, missing("not_applicable"))
	endpointZero.Estimate = Estimate{Kind: EstimateExact, Value: 0.0}
	endpointZero.Censoring = CensoringNone
	requirePass(t, endpointZero, clocks)

	// Exact zero still requires no censoring.
	censoredZero := reported
	censoredZero.MeasurementID = "censored-zero"
	censoredZero.Censoring = CensoringUnavailable
	requireFail(t, censoredZero, clocks, "censoring")

	// Negative durations are rejected even for subject reports.
	negative := reported
	negative.MeasurementID = "negative"
	negative.Estimate = Estimate{Kind: EstimateExact, Value: -1.0}
	requireFail(t, negative, clocks, "nonnegative")
}

func TestCrossClockEndpointsRejectExactDuration(t *testing.T) {
	clocks := testClocks()
	control := baseMeasurement()
	control.MeasurementID = "same-clock"
	control.Method = MethodEndpointDifference
	control.Start = tp("engine-clock", "boot-1", OriginEngineMeasured, 100, missing("not_applicable"))
	control.End = tp("engine-clock", "boot-1", OriginEngineMeasured, 150, missing("not_applicable"))
	control.Estimate = Estimate{Kind: EstimateExact, Value: 50.0}
	control.Censoring = CensoringNone
	requirePass(t, control, clocks)

	cross := control
	cross.MeasurementID = "cross-clock"
	cross.End = tp("browser-clock", "boot-1", OriginBrowserMeasured, 150, missing("not_applicable"))
	requireFail(t, cross, clocks, "clock")

	// A comparability-group label alone does not authorize cross-clock subtraction.
	labeled := cross
	labeled.MeasurementID = "cross-clock-labeled"
	labeled.ComparabilityGroup = "group-1"
	requireFail(t, labeled, clocks, "clock")
}

func TestCrossBootEndpointsRejectExactDuration(t *testing.T) {
	clocks := testClocks()
	cross := baseMeasurement()
	cross.MeasurementID = "cross-boot"
	cross.Method = MethodEndpointDifference
	cross.Start = tp("engine-clock", "boot-1", OriginEngineMeasured, 100, missing("not_applicable"))
	cross.End = tp("engine-clock", "boot-2", OriginEngineMeasured, 150, missing("not_applicable"))
	cross.Estimate = Estimate{Kind: EstimateExact, Value: 50.0}
	cross.Censoring = CensoringNone
	requireFail(t, cross, clocks, "boot")

	labeled := cross
	labeled.MeasurementID = "cross-boot-labeled"
	labeled.ComparabilityGroup = "group-1"
	requireFail(t, labeled, clocks, "boot")
}

func TestMissingNativeEndpointsRequireOpaqueReportClock(t *testing.T) {
	clocks := testClocks()
	// Opaque report clock with missing endpoints passes.
	opaque := baseMeasurement()
	opaque.MeasurementID = "opaque-duration"
	opaque.Origin = OriginSubjectReported
	opaque.ClockID = "subject-clock"
	opaque.BootID = "boot-1"
	opaque.Method = MethodSourceValue
	opaque.Estimate = Estimate{Kind: EstimateExact, Value: 42.0}
	opaque.Censoring = CensoringNone
	requirePass(t, opaque, clocks)

	// Exact duration with missing endpoints on a monotonic clock is rejected.
	native := baseMeasurement()
	native.MeasurementID = "monotonic-missing-endpoints"
	native.Method = MethodSourceValue
	native.Estimate = Estimate{Kind: EstimateExact, Value: 42.0}
	native.Censoring = CensoringNone
	requireFail(t, native, clocks, "opaque")

	// Opaque report clock must not invent native endpoints.
	invented := opaque
	invented.MeasurementID = "invented-endpoints"
	invented.Start = tp("subject-clock", "boot-1", OriginSubjectReported, 10, missing("not_applicable"))
	invented.End = tp("subject-clock", "boot-1", OriginSubjectReported, 52, missing("not_applicable"))
	requireFail(t, invented, clocks, "invent")

	// The monotonic-clock alternative for missing data is unavailable, not exact.
	unavail := baseMeasurement()
	unavail.MeasurementID = "monotonic-unavailable"
	requirePass(t, unavail, clocks)
}

func TestEndpointDifferenceMustEqualRecordedArithmetic(t *testing.T) {
	clocks := testClocks()
	mk := func(id string, start, end, value float64, res any) Measurement {
		m := baseMeasurement()
		m.MeasurementID = id
		m.Method = MethodEndpointDifference
		m.Start = tp("engine-clock", "boot-1", OriginEngineMeasured, start, missing("not_applicable"))
		m.End = tp("engine-clock", "boot-1", OriginEngineMeasured, end, missing("not_applicable"))
		m.Estimate = Estimate{Kind: EstimateExact, Value: value}
		m.Censoring = CensoringNone
		m.Resolution = res
		return m
	}
	requirePass(t, mk("arith-exact", 100, 150, 50, missing("not_applicable")), clocks)
	requirePass(t, mk("arith-within-resolution", 100, 150.4, 50, 1.0), clocks)

	// Beyond resolution: rejected.
	requireFail(t, mk("arith-beyond-resolution", 100, 150, 49, 0.5), clocks, "arithmetic")
	// Exact mismatch with no declared resolution: rejected.
	requireFail(t, mk("arith-mismatch", 100, 150, 49, missing("not_applicable")), clocks, "arithmetic")

	// End before start: rejected.
	requireFail(t, mk("arith-reversed", 150, 100, 50, missing("not_applicable")), clocks, "not before start")

	// Origin mismatch across endpoints: rejected.
	mixed := mk("arith-mixed-origin", 100, 150, 50, missing("not_applicable"))
	mixed.End = tp("engine-clock", "boot-1", OriginBrowserMeasured, 150, missing("not_applicable"))
	// Register a matching clock for the browser-origin endpoint so the failure
	// is the one-origin rule, not unknown-clock registration.
	clocksPlus := append(append([]ClockDescriptor{}, clocks...), ClockDescriptor{
		ClockID: "engine-clock", BootID: "boot-1", Origin: OriginBrowserMeasured,
		SourceID: "engine", Basis: BasisMonotonicOffset, Unit: "ms",
	})
	requireFail(t, mixed, clocksPlus, "origin")
}

func TestBoundedIntervalsRequireNumericAndOrderedBounds(t *testing.T) {
	clocks := testClocks()
	mk := func(id string, lo, hi any) Measurement {
		m := baseMeasurement()
		m.MeasurementID = id
		m.Method = MethodEvidenceBound
		m.Estimate = Estimate{Kind: EstimateBounded, LowerBound: lo, UpperBound: hi}
		m.Censoring = CensoringNone
		return m
	}
	requirePass(t, mk("bound-lower-only", 10.0, missing("not_observed")), clocks)
	requirePass(t, mk("bound-upper-only", missing("not_observed"), 20.0), clocks)
	requirePass(t, mk("bound-both-ordered", 10.0, 20.0), clocks)
	requirePass(t, mk("bound-equal", 10.0, 10.0), clocks)

	requireFail(t, mk("bound-none", missing("not_observed"), missing("not_observed")), clocks, "at least one")
	requireFail(t, mk("bound-unordered", 20.0, 10.0), clocks, "lower_bound")
	requireFail(t, mk("bound-negative", -5.0, 10.0), clocks, "nonnegative")

	wrongMethod := mk("bound-wrong-method", 10.0, 20.0)
	wrongMethod.Method = MethodEndpointDifference
	requireFail(t, wrongMethod, clocks, "evidence_bound")

	badCensoring := mk("bound-bad-censoring", 10.0, 20.0)
	badCensoring.Censoring = CensoringUnavailable
	requireFail(t, badCensoring, clocks, "censoring")
}

func TestUTCAdjustmentsCannotChangeElapsedArithmetic(t *testing.T) {
	clocks := testClocks()
	mk := func(id string, startUTC, endUTC any) Measurement {
		m := baseMeasurement()
		m.MeasurementID = id
		m.Method = MethodEndpointDifference
		m.Start = tp("engine-clock", "boot-1", OriginEngineMeasured, 100, startUTC)
		m.End = tp("engine-clock", "boot-1", OriginEngineMeasured, 150, endUTC)
		m.Estimate = Estimate{Kind: EstimateExact, Value: 50.0}
		m.Censoring = CensoringNone
		return m
	}
	// Same monotonic arithmetic under different UTC annotations.
	requirePass(t, mk("utc-a", "2026-01-01T00:00:00Z", "2026-01-01T00:00:05Z"), clocks)
	requirePass(t, mk("utc-b", "2026-06-01T12:00:00Z", "2026-06-01T12:00:05Z"), clocks)
	requirePass(t, mk("utc-missing", missing("not_applicable"), missing("not_applicable")), clocks)
	// UTC difference wildly disagrees with monotonic difference; monotonic wins.
	requirePass(t, mk("utc-disagree", "2026-01-01T00:00:00Z", "2026-01-01T01:00:00Z"), clocks)

	// Invalid UTC annotations are still rejected as malformed.
	requireFail(t, mk("utc-invalid", "not-a-date", "2026-01-01T00:00:00Z"), clocks, "date-time")

	// ComputeDeadline ignores UTC: same monotonic start yields same deadline.
	s1 := tp("engine-clock", "boot-1", OriginEngineMeasured, 100, "2026-01-01T00:00:00Z")
	s2 := tp("engine-clock", "boot-1", OriginEngineMeasured, 100, "2027-05-05T05:05:05Z")
	limit := DurationLimit{Kind: "exact", Unit: "ms", Value: 25}
	d1, err := ComputeDeadline(s1, limit)
	if err != nil {
		t.Fatalf("ComputeDeadline s1: %v", err)
	}
	d2, err := ComputeDeadline(s2, limit)
	if err != nil {
		t.Fatalf("ComputeDeadline s2: %v", err)
	}
	if d1.MonotonicOffsetMs != 125 || d2.MonotonicOffsetMs != 125 {
		t.Fatalf("deadline arithmetic must follow monotonic offsets: got %v and %v", d1.MonotonicOffsetMs, d2.MonotonicOffsetMs)
	}
	if d1.ClockID != s1.ClockID || d1.BootID != s1.BootID || d1.Origin != s1.Origin {
		t.Fatalf("deadline must preserve clock/boot/origin: %+v", d1)
	}
	if _, ok := d1.UTCAnnotation.(Missing); !ok {
		if _, ok := d1.UTCAnnotation.(*Missing); !ok {
			t.Fatalf("deadline UTC must be a Missing annotation, got %T", d1.UTCAnnotation)
		}
	}
}

func TestAggregateRuntimeCannotInventPrimitiveDurations(t *testing.T) {
	clocks := testClocks()
	// Invented split: claims derivation from an aggregate without independent
	// endpoint_difference evidence.
	invented := baseMeasurement()
	invented.MeasurementID = "prim-split"
	invented.Scope = Scope{Kind: "native_primitive", ID: "prim-1"}
	invented.Origin = OriginSubjectReported
	invented.ClockID = "subject-clock"
	invented.BootID = "boot-1"
	invented.Method = MethodSourceValue
	invented.Estimate = Estimate{Kind: EstimateExact, Value: 10.0}
	invented.Censoring = CensoringNone
	invented.AggregateSource = "aggregate-run-1"
	requireFail(t, invented, clocks, "aggregate")

	// Independent primitive with its own endpoint_difference evidence passes,
	// even when it cites the aggregate for context.
	independent := baseMeasurement()
	independent.MeasurementID = "prim-independent"
	independent.Scope = Scope{Kind: "native_primitive", ID: "prim-1"}
	independent.Method = MethodEndpointDifference
	independent.Start = tp("engine-clock", "boot-1", OriginEngineMeasured, 200, missing("not_applicable"))
	independent.End = tp("engine-clock", "boot-1", OriginEngineMeasured, 230, missing("not_applicable"))
	independent.Estimate = Estimate{Kind: EstimateExact, Value: 30.0}
	independent.Censoring = CensoringNone
	independent.AggregateSource = "aggregate-run-1"
	requirePass(t, independent, clocks)

	// Same independent evidence without the aggregate label also passes.
	plain := independent
	plain.MeasurementID = "prim-plain"
	plain.AggregateSource = ""
	requirePass(t, plain, clocks)

	// A comparability-group label alone never justifies an invented split.
	labeled := invented
	labeled.MeasurementID = "prim-labeled"
	labeled.AggregateSource = ""
	labeled.ComparabilityGroup = "aggregate-run-1"
	// Without AggregateSource this is a legitimate opaque subject report, so
	// it passes on its own; the point is the label grants no cross-boundary
	// arithmetic. Cross-clock misuse of the same label is still rejected:
	cross := baseMeasurement()
	cross.MeasurementID = "prim-cross-labeled"
	cross.Method = MethodEndpointDifference
	cross.Start = tp("engine-clock", "boot-1", OriginEngineMeasured, 100, missing("not_applicable"))
	cross.End = tp("browser-clock", "boot-1", OriginBrowserMeasured, 130, missing("not_applicable"))
	cross.Estimate = Estimate{Kind: EstimateExact, Value: 30.0}
	cross.Censoring = CensoringNone
	cross.ComparabilityGroup = "aggregate-run-1"
	requireFail(t, cross, clocks, "clock")
	requirePass(t, labeled, clocks)

	// Human pauses remain workflow elapsed time, not framework primitive time.
	pause := baseMeasurement()
	pause.MeasurementID = "manual-pause-primitive"
	pause.Origin = OriginManualReference
	pause.ClockID = "manual-clock"
	pause.BootID = "boot-1"
	pause.Scope = Scope{Kind: "native_primitive", ID: "prim-1"}
	pause.Method = MethodEndpointDifference
	pause.Start = tp("manual-clock", "boot-1", OriginManualReference, 0, missing("not_applicable"))
	pause.End = tp("manual-clock", "boot-1", OriginManualReference, 5000, missing("not_applicable"))
	pause.Estimate = Estimate{Kind: EstimateExact, Value: 5000.0}
	pause.Censoring = CensoringNone
	requireFail(t, pause, clocks, "workflow")

	workflowPause := pause
	workflowPause.MeasurementID = "manual-pause-workflow"
	workflowPause.Scope = Scope{Kind: "workflow_step", ID: "pause-1"}
	requirePass(t, workflowPause, clocks)
}

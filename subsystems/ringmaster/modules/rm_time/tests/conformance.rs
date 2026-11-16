// Conformance runner for rm_time (custom harness: `harness = false`).
//
// The verification command passes lowercase conformance filters
// (`cargo test -p rm_time -- rm_c03 rm_c04`). The stock libtest harness
// cannot match these filters against Rust `#[test]` identifiers portably
// across hyphen/underscore spellings, so this file is a custom `main` that
// honors exactly those registered lowercase filters (accepting both
// `rm_c03` and `rm-c03` spellings). Each case runs every check for its ID;
// any failure is printed and the process exits nonzero.

use rm_time::{
    Censoring, ClockBasis, ClockDescriptor, Estimate, MaybeNumber, MaybeString, MaybeTimePoint,
    Measurement, MeasurementOrigin, Method, Missing, Quantity, Scope, ScopeKind, TimePoint,
    UtcAnnotation,
};
use std::collections::HashSet;

// ---------------------------------------------------------------------------
// tiny assertion helpers
// ---------------------------------------------------------------------------

type Failure = String;

fn fail(what: &str, detail: impl std::fmt::Display) -> Failure {
    format!("{what}: {detail}")
}

fn expect_ok(result: Result<(), String>, what: &str) -> Result<(), Failure> {
    result.map_err(|e| fail(what, format!("expected Ok, got Err({e})")))
}

fn expect_err(result: Result<(), String>, what: &str) -> Result<(), Failure> {
    match result {
        Ok(()) => Err(fail(what, "expected Err, got Ok")),
        Err(_) => Ok(()),
    }
}

fn expect_boundary(
    result: Result<bool, String>,
    expected: bool,
    what: &str,
) -> Result<(), Failure> {
    match result {
        Ok(got) if got == expected => Ok(()),
        Ok(got) => Err(fail(
            what,
            format!("expected Ok({expected}), got Ok({got})"),
        )),
        Err(e) => Err(fail(what, format!("expected Ok({expected}), got Err({e})"))),
    }
}

fn expect_boundary_err(result: Result<bool, String>, what: &str) -> Result<(), Failure> {
    match result {
        Ok(got) => Err(fail(what, format!("expected Err, got Ok({got})"))),
        Err(_) => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

fn missing_not_observed() -> Missing {
    Missing::new("not_observed")
}

fn engine_clock() -> ClockDescriptor {
    ClockDescriptor {
        clock_id: "clk-engine-1".to_string(),
        boot_id: "boot-9".to_string(),
        origin: MeasurementOrigin::EngineMeasured,
        source_id: "src-engine-1".to_string(),
        basis: ClockBasis::MonotonicOffset,
        unit: "ms".to_string(),
    }
}

fn native_clock() -> ClockDescriptor {
    // Opaque-report clock for subject-native coordinates.
    ClockDescriptor {
        clock_id: "clk-subject-1".to_string(),
        boot_id: "boot-3".to_string(),
        origin: MeasurementOrigin::SubjectReported,
        source_id: "src-subject-1".to_string(),
        basis: ClockBasis::OpaqueReport,
        unit: "ms".to_string(),
    }
}

fn point(clock: &ClockDescriptor, offset: f64) -> TimePoint {
    TimePoint {
        clock_id: clock.clock_id.clone(),
        boot_id: clock.boot_id.clone(),
        origin: clock.origin,
        monotonic_offset_ms: offset,
        utc_annotation: UtcAnnotation::Missing(missing_not_observed()),
    }
}

fn base_measurement(clock: &ClockDescriptor) -> Measurement {
    Measurement {
        measurement_id: "m-1".to_string(),
        name: "native.execute".to_string(),
        scope: Scope {
            kind: ScopeKind::NativePrimitive,
            id: "op-1".to_string(),
        },
        quantity: Quantity::Duration,
        unit: "ms".to_string(),
        origin: clock.origin,
        clock_id: clock.clock_id.clone(),
        boot_id: clock.boot_id.clone(),
        method: Method::SourceValue,
        start: MaybeTimePoint::Missing(missing_not_observed()),
        end: MaybeTimePoint::Missing(missing_not_observed()),
        estimate: Estimate::Exact { value: 0.0 },
        resolution: MaybeNumber::Missing(missing_not_observed()),
        censoring: Censoring::None,
        comparability_group: MaybeString::Missing(Missing::new("not_applicable")),
    }
}

// ---------------------------------------------------------------------------
// RM-C03: native exact zero and missing duration
// ---------------------------------------------------------------------------

fn rm_c03_native_exact_zero() -> Result<(), Failure> {
    // A native exact zero (subject-reported, opaque clock, source value) is
    // valid and preserved exactly — never coerced into missingness.
    let clock = native_clock();
    let measurement = base_measurement(&clock);
    expect_ok(
        rm_time::validate_measurement(&measurement, &[clock]),
        "native exact zero",
    )?;
    match &measurement.estimate {
        Estimate::Exact { value } if *value == 0.0 => Ok(()),
        other => Err(fail("native exact zero", format!("zero not preserved: {other:?}"))),
    }
}

fn rm_c03_endpoint_zero() -> Result<(), Failure> {
    // Exact zero via endpoint difference with identical endpoints is valid.
    let clock = engine_clock();
    let mut measurement = base_measurement(&clock);
    measurement.method = Method::EndpointDifference;
    measurement.start = MaybeTimePoint::Present(point(&clock, 42.5));
    measurement.end = MaybeTimePoint::Present(point(&clock, 42.5));
    measurement.estimate = Estimate::Exact { value: 0.0 };
    expect_ok(
        rm_time::validate_measurement(&measurement, &[clock]),
        "endpoint-difference zero",
    )
}

fn rm_c03_missing_duration_unavailable() -> Result<(), Failure> {
    // A missing duration uses the unavailable estimate form throughout.
    let clock = engine_clock();
    let mut measurement = base_measurement(&clock);
    measurement.method = Method::Unavailable;
    measurement.estimate = Estimate::Unavailable {
        value: Missing::new("not_observed"),
    };
    measurement.censoring = Censoring::Unavailable;
    expect_ok(
        rm_time::validate_measurement(&measurement, &[clock]),
        "missing duration",
    )
}

fn rm_c03_missing_not_zero() -> Result<(), Failure> {
    let clock = engine_clock();
    // Missing endpoints cannot back an endpoint-difference zero.
    let mut missing_endpoints = base_measurement(&clock);
    missing_endpoints.method = Method::EndpointDifference;
    missing_endpoints.estimate = Estimate::Exact { value: 0.0 };
    expect_err(
        rm_time::validate_measurement(&missing_endpoints, &[clock.clone()]),
        "endpoint difference with missing endpoints",
    )?;
    // An exact zero with unavailable censoring is incoherent.
    let mut censored_zero = base_measurement(&clock);
    censored_zero.censoring = Censoring::Unavailable;
    expect_err(
        rm_time::validate_measurement(&censored_zero, &[clock.clone()]),
        "exact zero with unavailable censoring",
    )?;
    // An unavailable estimate with a concrete method is incoherent.
    let mut unavailable_method = base_measurement(&clock);
    unavailable_method.estimate = Estimate::Unavailable {
        value: Missing::new("observation_lost"),
    };
    unavailable_method.censoring = Censoring::Unavailable;
    unavailable_method.method = Method::SourceValue;
    expect_err(
        rm_time::validate_measurement(&unavailable_method, &[clock.clone()]),
        "unavailable estimate with source_value method",
    )?;
    // An unavailable estimate with concrete censoring is incoherent.
    let mut unavailable_censoring = base_measurement(&clock);
    unavailable_censoring.estimate = Estimate::Unavailable {
        value: Missing::new("observation_lost"),
    };
    unavailable_censoring.method = Method::Unavailable;
    unavailable_censoring.censoring = Censoring::None;
    expect_err(
        rm_time::validate_measurement(&unavailable_censoring, &[clock]),
        "unavailable estimate with none censoring",
    )
}

fn rm_c03_bounded_forms() -> Result<(), Failure> {
    let clock = engine_clock();
    let bounded = |lower: MaybeNumber, upper: MaybeNumber| {
        let mut measurement = base_measurement(&clock);
        measurement.method = Method::EvidenceBound;
        measurement.censoring = Censoring::Right;
        measurement.estimate = Estimate::Bounded {
            lower_bound: lower,
            upper_bound: upper,
        };
        measurement
    };
    let clocks = [clock.clone()];
    // Lower-only, upper-only, and ordered-pair bounds are valid.
    expect_ok(
        rm_time::validate_measurement(
            &bounded(
                MaybeNumber::Num(2.0),
                MaybeNumber::Missing(Missing::new("not_observed")),
            ),
            &clocks,
        ),
        "lower-only bound",
    )?;
    expect_ok(
        rm_time::validate_measurement(
            &bounded(
                MaybeNumber::Missing(Missing::new("not_observed")),
                MaybeNumber::Num(9.0),
            ),
            &clocks,
        ),
        "upper-only bound",
    )?;
    expect_ok(
        rm_time::validate_measurement(
            &bounded(MaybeNumber::Num(2.0), MaybeNumber::Num(2.0)),
            &clocks,
        ),
        "equal bounds",
    )?;
    // Two missing bounds leave nothing bounded.
    expect_err(
        rm_time::validate_measurement(
            &bounded(
                MaybeNumber::Missing(Missing::new("not_observed")),
                MaybeNumber::Missing(Missing::new("not_observed")),
            ),
            &clocks,
        ),
        "both bounds missing",
    )?;
    // Inverted bounds are rejected.
    expect_err(
        rm_time::validate_measurement(
            &bounded(MaybeNumber::Num(9.0), MaybeNumber::Num(2.0)),
            &clocks,
        ),
        "inverted bounds",
    )?;
    // Bounded estimates require the evidence-bound method ...
    let mut wrong_method = bounded(MaybeNumber::Num(1.0), MaybeNumber::Num(2.0));
    wrong_method.method = Method::SourceValue;
    expect_err(
        rm_time::validate_measurement(&wrong_method, &clocks),
        "bounded estimate with source_value method",
    )?;
    // ... and a concrete censoring flag.
    let mut wrong_censoring = bounded(MaybeNumber::Num(1.0), MaybeNumber::Num(2.0));
    wrong_censoring.censoring = Censoring::Unavailable;
    expect_err(
        rm_time::validate_measurement(&wrong_censoring, &clocks),
        "bounded estimate with unavailable censoring",
    )?;
    // Duration bounds are nonnegative.
    expect_err(
        rm_time::validate_measurement(
            &bounded(MaybeNumber::Num(-1.0), MaybeNumber::Num(2.0)),
            &clocks,
        ),
        "negative duration bound",
    )?;
    // Scalar bounds may be negative.
    let mut scalar = bounded(MaybeNumber::Num(-4.0), MaybeNumber::Num(-1.0));
    scalar.quantity = Quantity::Scalar;
    scalar.unit = "count".to_string();
    expect_ok(
        rm_time::validate_measurement(&scalar, &clocks),
        "negative scalar bounds",
    )
}

fn rm_c03_scalar_and_units() -> Result<(), Failure> {
    let clock = engine_clock();
    let clocks = [clock.clone()];
    // Negative scalar values are valid with an explicit unit.
    let mut scalar = base_measurement(&clock);
    scalar.quantity = Quantity::Scalar;
    scalar.unit = "count".to_string();
    scalar.estimate = Estimate::Exact { value: -3.5 };
    expect_ok(
        rm_time::validate_measurement(&scalar, &clocks),
        "negative scalar",
    )?;
    // Durations require the ms unit ...
    let mut wrong_unit = base_measurement(&clock);
    wrong_unit.unit = "s".to_string();
    expect_err(
        rm_time::validate_measurement(&wrong_unit, &clocks),
        "duration with unit s",
    )?;
    // ... and nonnegative values ...
    let mut negative = base_measurement(&clock);
    negative.estimate = Estimate::Exact { value: -0.5 };
    expect_err(
        rm_time::validate_measurement(&negative, &clocks),
        "negative duration value",
    )?;
    // ... and finite values.
    let mut nonfinite = base_measurement(&clock);
    nonfinite.estimate = Estimate::Exact {
        value: f64::INFINITY,
    };
    expect_err(
        rm_time::validate_measurement(&nonfinite, &clocks),
        "non-finite duration value",
    )?;
    // Scalar units must be explicit (nonempty).
    let mut empty_unit = base_measurement(&clock);
    empty_unit.quantity = Quantity::Scalar;
    empty_unit.unit = String::new();
    empty_unit.estimate = Estimate::Exact { value: 1.0 };
    expect_err(
        rm_time::validate_measurement(&empty_unit, &clocks),
        "scalar with empty unit",
    )
}

fn rm_c03_missing_envelopes() -> Result<(), Failure> {
    let clock = engine_clock();
    let clocks = [clock];
    // Typed validation rejects bad reasons and empty details.
    let mut bad_reason = base_measurement(&clocks[0]);
    bad_reason.resolution = MaybeNumber::Missing(Missing::new("bogus"));
    expect_err(
        rm_time::validate_measurement(&bad_reason, &clocks),
        "typed bad Missing reason",
    )?;
    let mut empty_detail = base_measurement(&clocks[0]);
    empty_detail.resolution = MaybeNumber::Missing(Missing {
        reason: "not_observed".to_string(),
        detail: Some(String::new()),
    });
    expect_err(
        rm_time::validate_measurement(&empty_detail, &clocks),
        "typed empty Missing detail",
    )?;
    // JSON parsing enforces the envelope shape too.
    let valid: Missing = serde_json::from_str(r#"{"value":null,"reason":"not_observed"}"#)
        .map_err(|e| fail("valid envelope parses", e))?;
    if valid.reason != "not_observed" || valid.detail.is_some() {
        return Err(fail("valid envelope parses", "fields not preserved"));
    }
    for (what, json) in [
        ("bad reason", r#"{"value":null,"reason":"bogus"}"#),
        ("missing value", r#"{"reason":"not_observed"}"#),
        (
            "non-null value",
            r#"{"value":0,"reason":"not_observed"}"#,
        ),
        (
            "empty detail",
            r#"{"value":null,"reason":"not_observed","detail":""}"#,
        ),
        (
            "extra field",
            r#"{"value":null,"reason":"not_observed","x":1}"#,
        ),
    ] {
        if serde_json::from_str::<Missing>(json).is_ok() {
            return Err(fail(what, format!("malformed envelope accepted: {json}")));
        }
    }
    // Closed objects reject undeclared fields.
    let point_json = serde_json::to_value(point(&clocks[0], 1.0))
        .map_err(|e| fail("serialize TimePoint", e))?;
    let mut extra = point_json
        .as_object()
        .cloned()
        .ok_or_else(|| fail("serialize TimePoint", "not an object"))?;
    extra.insert("extra".to_string(), serde_json::Value::Bool(true));
    if serde_json::from_value::<TimePoint>(serde_json::Value::Object(extra)).is_ok() {
        return Err(fail("closed TimePoint", "undeclared field accepted"));
    }
    Ok(())
}

fn rm_c03_resolution_and_group() -> Result<(), Failure> {
    let clock = engine_clock();
    let clocks = [clock];
    let mut numeric_resolution = base_measurement(&clocks[0]);
    numeric_resolution.resolution = MaybeNumber::Num(0.5);
    expect_ok(
        rm_time::validate_measurement(&numeric_resolution, &clocks),
        "numeric resolution",
    )?;
    let mut zero_resolution = base_measurement(&clocks[0]);
    zero_resolution.resolution = MaybeNumber::Num(0.0);
    expect_ok(
        rm_time::validate_measurement(&zero_resolution, &clocks),
        "zero resolution",
    )?;
    let mut negative_resolution = base_measurement(&clocks[0]);
    negative_resolution.resolution = MaybeNumber::Num(-1.0);
    expect_err(
        rm_time::validate_measurement(&negative_resolution, &clocks),
        "negative resolution",
    )?;
    let mut named_group = base_measurement(&clocks[0]);
    named_group.comparability_group = MaybeString::Text("g1".to_string());
    expect_ok(
        rm_time::validate_measurement(&named_group, &clocks),
        "named comparability group",
    )?;
    let mut empty_group = base_measurement(&clocks[0]);
    empty_group.comparability_group = MaybeString::Text(String::new());
    expect_err(
        rm_time::validate_measurement(&empty_group, &clocks),
        "empty comparability group",
    )
}

fn rm_c03_wire_agreement() -> Result<(), Failure> {
    // Valid measurements serialize with no bare nulls, so the serialized
    // form passes the wire tier's structural rules when embedded in a
    // record; a bare null in the same position is rejected by that tier.
    let clock = engine_clock();
    let mut measurement = base_measurement(&clock);
    measurement.method = Method::Unavailable;
    measurement.estimate = Estimate::Unavailable {
        value: Missing::with_detail("observation_lost", "shard compacted"),
    };
    measurement.censoring = Censoring::Unavailable;
    expect_ok(
        rm_time::validate_measurement(&measurement, &[clock]),
        "wire-agreement fixture",
    )?;
    let body =
        serde_json::to_value(&measurement).map_err(|e| fail("serialize measurement", e))?;
    // JSON round-trip preserves the measurement.
    let round_trip: Measurement =
        serde_json::from_value(body.clone()).map_err(|e| fail("round-trip", e))?;
    if round_trip != measurement {
        return Err(fail("round-trip", "measurement not preserved"));
    }
    let record = serde_json::json!({
        "record_type": "ringmaster_plan",
        "schema_version": "ringmaster-plan/0.1.0",
        "steps": [body],
    });
    let bytes = serde_json::to_vec(&record).map_err(|e| fail("encode record", e))?;
    rm_wire::validate_record("ringmaster_plan/v1", &bytes)
        .map_err(|e| fail("wire tier accepts serialized measurement", e))?;
    let bare = serde_json::json!({
        "record_type": "ringmaster_plan",
        "schema_version": "ringmaster-plan/0.1.0",
        "steps": [{"value": null}],
    });
    let bare_bytes = serde_json::to_vec(&bare).map_err(|e| fail("encode bare record", e))?;
    match rm_wire::validate_record("ringmaster_plan/v1", &bare_bytes) {
        Ok(()) => Err(fail("wire tier rejects bare null", "bare null accepted")),
        Err(_) => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// RM-C04: cross-clock/boot subtraction
// ---------------------------------------------------------------------------

fn rm_c04_cross_clock_endpoints() -> Result<(), Failure> {
    let engine = engine_clock();
    let native = native_clock();
    let clocks = [engine.clone(), native.clone()];
    // Endpoints on two different clocks are rejected even though both are
    // registered: no cross-clock subtraction.
    let mut measurement = base_measurement(&engine);
    measurement.method = Method::EndpointDifference;
    measurement.start = MaybeTimePoint::Present(point(&engine, 1.0));
    measurement.end = MaybeTimePoint::Present(point(&native, 4.0));
    measurement.estimate = Estimate::Exact { value: 3.0 };
    expect_err(
        rm_time::validate_measurement(&measurement, &clocks),
        "cross-clock endpoints",
    )?;
    // An endpoint on an unregistered clock is rejected as well.
    let mut rogue = point(&engine, 4.0);
    rogue.clock_id = "clk-rogue".to_string();
    let mut unregistered = base_measurement(&engine);
    unregistered.method = Method::EndpointDifference;
    unregistered.start = MaybeTimePoint::Present(point(&engine, 1.0));
    unregistered.end = MaybeTimePoint::Present(rogue);
    unregistered.estimate = Estimate::Exact { value: 3.0 };
    expect_err(
        rm_time::validate_measurement(&unregistered, &clocks),
        "unregistered endpoint clock",
    )
}

fn rm_c04_cross_boot_endpoints() -> Result<(), Failure> {
    let engine = engine_clock();
    let mut rebooted = engine.clone();
    rebooted.boot_id = "boot-10".to_string();
    let clocks = [engine.clone(), rebooted.clone()];
    // Same clock, different boots: a restart boundary forbids subtraction.
    let mut measurement = base_measurement(&engine);
    measurement.method = Method::EndpointDifference;
    measurement.start = MaybeTimePoint::Present(point(&engine, 1.0));
    let mut end = point(&rebooted, 4.0);
    end.origin = MeasurementOrigin::EngineMeasured;
    measurement.end = MaybeTimePoint::Present(end);
    measurement.estimate = Estimate::Exact { value: 3.0 };
    expect_err(
        rm_time::validate_measurement(&measurement, &clocks),
        "cross-boot endpoints",
    )
}

fn rm_c04_cross_origin_endpoints() -> Result<(), Failure> {
    let engine = engine_clock();
    let clocks = [engine.clone()];
    // Endpoints must share the measurement origin.
    let mut measurement = base_measurement(&engine);
    measurement.method = Method::EndpointDifference;
    measurement.start = MaybeTimePoint::Present(point(&engine, 1.0));
    let mut end = point(&engine, 4.0);
    end.origin = MeasurementOrigin::SubjectReported;
    measurement.end = MaybeTimePoint::Present(end);
    measurement.estimate = Estimate::Exact { value: 3.0 };
    expect_err(
        rm_time::validate_measurement(&measurement, &clocks),
        "cross-origin endpoints",
    )
}

fn rm_c04_unregistered_lifetime() -> Result<(), Failure> {
    let engine = engine_clock();
    // Unknown clock/boot has no registered lifetime.
    let measurement = base_measurement(&engine);
    expect_err(
        rm_time::validate_measurement(&measurement, &[]),
        "empty clock registry",
    )?;
    let other = native_clock();
    expect_err(
        rm_time::validate_measurement(&measurement, &[other]),
        "wrong clock registry",
    )?;
    // The measurement origin must match the registered clock origin.
    let mut mismatched = engine.clone();
    mismatched.origin = MeasurementOrigin::BrowserMeasured;
    expect_err(
        rm_time::validate_measurement(&measurement, &[mismatched]),
        "registry origin mismatch",
    )?;
    // Registered descriptors must themselves be well-formed.
    let mut bad_unit = engine.clone();
    bad_unit.unit = "s".to_string();
    expect_err(
        rm_time::validate_measurement(&measurement, &[bad_unit]),
        "registry descriptor with unit s",
    )?;
    let mut empty_id = base_measurement(&native_clock());
    empty_id.measurement_id = String::new();
    expect_err(
        rm_time::validate_measurement(&empty_id, &[native_clock()]),
        "empty measurement_id",
    )
}

fn rm_c04_unordered_and_inexact() -> Result<(), Failure> {
    let clock = engine_clock();
    let clocks = [clock.clone()];
    let difference = |start: f64, end: f64, value: f64| {
        let mut measurement = base_measurement(&clock);
        measurement.method = Method::EndpointDifference;
        measurement.start = MaybeTimePoint::Present(point(&clock, start));
        measurement.end = MaybeTimePoint::Present(point(&clock, end));
        measurement.estimate = Estimate::Exact { value };
        measurement
    };
    // Control: ordered endpoints with exact arithmetic validate.
    expect_ok(
        rm_time::validate_measurement(&difference(1.0, 4.0, 3.0), &clocks),
        "exact endpoint difference",
    )?;
    // Unordered endpoints are rejected.
    expect_err(
        rm_time::validate_measurement(&difference(4.0, 1.0, 3.0), &clocks),
        "unordered endpoints",
    )?;
    // Inexact arithmetic is rejected.
    expect_err(
        rm_time::validate_measurement(&difference(1.0, 4.0, 3.1), &clocks),
        "inexact endpoint arithmetic",
    )?;
    expect_err(
        rm_time::validate_measurement(&difference(1.0, 4.0, -3.0), &clocks),
        "negative endpoint arithmetic",
    )?;
    // Endpoint differences are durations, not scalars.
    let mut scalar = difference(1.0, 4.0, 3.0);
    scalar.quantity = Quantity::Scalar;
    scalar.unit = "count".to_string();
    expect_err(
        rm_time::validate_measurement(&scalar, &clocks),
        "scalar endpoint difference",
    )
}

fn rm_c04_boundary_same_lifetime() -> Result<(), Failure> {
    let clock = engine_clock();
    expect_boundary(
        rm_time::boundary_reached(&point(&clock, 10.0), &point(&clock, 5.0)),
        true,
        "now past deadline",
    )?;
    expect_boundary(
        rm_time::boundary_reached(&point(&clock, 5.0), &point(&clock, 10.0)),
        false,
        "now before deadline",
    )?;
    expect_boundary(
        rm_time::boundary_reached(&point(&clock, 7.5), &point(&clock, 7.5)),
        true,
        "now equals deadline",
    )
}

fn rm_c04_boundary_cross_rejected() -> Result<(), Failure> {
    let engine = engine_clock();
    let native = native_clock();
    let mut rebooted = engine.clone();
    rebooted.boot_id = "boot-10".to_string();
    expect_boundary_err(
        rm_time::boundary_reached(&point(&engine, 10.0), &point(&native, 5.0)),
        "boundary across clocks",
    )?;
    expect_boundary_err(
        rm_time::boundary_reached(&point(&engine, 10.0), &point(&rebooted, 5.0)),
        "boundary across boots",
    )?;
    let mut crossed = point(&engine, 5.0);
    crossed.origin = MeasurementOrigin::ManualReference;
    expect_boundary_err(
        rm_time::boundary_reached(&point(&engine, 10.0), &crossed),
        "boundary across origins",
    )
}

fn rm_c04_boundary_ignores_utc() -> Result<(), Failure> {
    // UTC annotations run opposite to the offsets; the offsets decide.
    let clock = engine_clock();
    let mut now = point(&clock, 10.0);
    now.utc_annotation =
        UtcAnnotation::DateTime("2020-01-01T00:00:00Z".to_string());
    let mut deadline = point(&clock, 5.0);
    deadline.utc_annotation =
        UtcAnnotation::DateTime("2030-06-30T12:00:00.5+02:00".to_string());
    expect_boundary(
        rm_time::boundary_reached(&now, &deadline),
        true,
        "later UTC deadline does not move the boundary",
    )?;
    expect_boundary(
        rm_time::boundary_reached(&deadline, &now),
        false,
        "earlier UTC now does not reach the boundary",
    )
}

fn rm_c04_rejects_bad_coordinates() -> Result<(), Failure> {
    let clock = engine_clock();
    let clocks = [clock.clone()];
    for (what, offset) in [
        ("NaN endpoint", f64::NAN),
        ("infinite endpoint", f64::INFINITY),
        ("negative endpoint", -1.0),
    ] {
        let mut measurement = base_measurement(&clock);
        measurement.method = Method::EndpointDifference;
        measurement.start = MaybeTimePoint::Present(point(&clock, 0.0));
        measurement.end = MaybeTimePoint::Present(point(&clock, offset));
        measurement.estimate = Estimate::Exact { value: offset };
        expect_err(
            rm_time::validate_measurement(&measurement, &clocks),
            what,
        )?;
    }
    expect_boundary_err(
        rm_time::boundary_reached(&point(&clock, f64::NAN), &point(&clock, 5.0)),
        "boundary with NaN now",
    )?;
    // Malformed UTC annotations are rejected even though they are never
    // consulted for ordering.
    let mut bad_utc = point(&clock, 10.0);
    bad_utc.utc_annotation = UtcAnnotation::DateTime("not-a-time".to_string());
    expect_boundary_err(
        rm_time::boundary_reached(&bad_utc, &point(&clock, 5.0)),
        "boundary with malformed UTC",
    )?;
    // Well-formed UTC annotations are accepted.
    let mut good_utc = point(&clock, 10.0);
    good_utc.utc_annotation =
        UtcAnnotation::DateTime("2026-02-28T23:59:60Z".to_string());
    expect_boundary(
        rm_time::boundary_reached(&good_utc, &point(&clock, 5.0)),
        true,
        "boundary with well-formed UTC",
    )
}

fn rm_c04_datetime_shapes() -> Result<(), Failure> {
    let clock = engine_clock();
    for valid in [
        "2026-01-02T03:04:05Z",
        "2026-01-02t03:04:05z",
        "2024-02-29T00:00:00Z",
        "2026-01-02T03:04:05.123Z",
        "2026-01-02T03:04:05+02:00",
        "2026-01-02T03:04:05.123456-05:30",
    ] {
        let mut now = point(&clock, 10.0);
        now.utc_annotation = UtcAnnotation::DateTime(valid.to_string());
        expect_boundary(
            rm_time::boundary_reached(&now, &point(&clock, 5.0)),
            true,
            &format!("valid date-time {valid}"),
        )?;
    }
    for invalid in [
        "",
        "2026-01-01",
        "2026-13-01T00:00:00Z",
        "2026-00-10T00:00:00Z",
        "2026-02-30T00:00:00Z",
        "2023-02-29T00:00:00Z",
        "2026-01-01T25:00:00Z",
        "2026-01-01T00:00:00",
        "2026-01-01T00:00:00.",
        "2026-01-01T00:00:00+24:00",
        "2026-01-01 00:00:00Z",
    ] {
        let mut now = point(&clock, 10.0);
        now.utc_annotation = UtcAnnotation::DateTime(invalid.to_string());
        expect_boundary_err(
            rm_time::boundary_reached(&now, &point(&clock, 5.0)),
            &format!("invalid date-time {invalid:?}"),
        )?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// runner
// ---------------------------------------------------------------------------

type CheckFn = fn() -> Result<(), Failure>;

fn run_case(id: &str) -> Vec<Failure> {
    let checks: &[(&str, CheckFn)] = match id {
        "rm-c03" => &[
            ("native exact zero", rm_c03_native_exact_zero),
            ("endpoint zero", rm_c03_endpoint_zero),
            ("missing duration unavailable", rm_c03_missing_duration_unavailable),
            ("missing not zero", rm_c03_missing_not_zero),
            ("bounded forms", rm_c03_bounded_forms),
            ("scalar and units", rm_c03_scalar_and_units),
            ("missing envelopes", rm_c03_missing_envelopes),
            ("resolution and group", rm_c03_resolution_and_group),
            ("wire agreement", rm_c03_wire_agreement),
        ],
        "rm-c04" => &[
            ("cross-clock endpoints", rm_c04_cross_clock_endpoints),
            ("cross-boot endpoints", rm_c04_cross_boot_endpoints),
            ("cross-origin endpoints", rm_c04_cross_origin_endpoints),
            ("unregistered lifetime", rm_c04_unregistered_lifetime),
            ("unordered and inexact", rm_c04_unordered_and_inexact),
            ("boundary same lifetime", rm_c04_boundary_same_lifetime),
            ("boundary cross rejected", rm_c04_boundary_cross_rejected),
            ("boundary ignores UTC", rm_c04_boundary_ignores_utc),
            ("bad coordinates", rm_c04_rejects_bad_coordinates),
            ("date-time shapes", rm_c04_datetime_shapes),
        ],
        _ => return vec![format!("unknown case {id}")],
    };
    let mut failures = Vec::new();
    for (name, check) in checks {
        if let Err(e) = check() {
            failures.push(format!("{id} [{name}]: {e}"));
        }
    }
    failures
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // Registered lowercase conformance filters (spec FORBIDDEN: never replace).
    let mut selected: HashSet<&str> = HashSet::new();
    for arg in &args {
        let normalized = match arg.as_str() {
            "rm_c03" | "rm-c03" => Some("rm-c03"),
            "rm_c04" | "rm-c04" => Some("rm-c04"),
            _ => None,
        };
        if let Some(id) = normalized {
            selected.insert(id);
        } else if arg.starts_with("rm-") || arg.starts_with("rm_") {
            eprintln!("unknown conformance filter: {arg}");
            std::process::exit(2);
        }
    }
    if selected.is_empty() {
        selected.insert("rm-c03");
        selected.insert("rm-c04");
    }
    let mut ids: Vec<&str> = selected.into_iter().collect();
    ids.sort_unstable();

    let mut passed = 0usize;
    let mut failures: Vec<Failure> = Vec::new();
    for id in &ids {
        let case_failures = run_case(id);
        if case_failures.is_empty() {
            println!("{id}: ok");
            passed += 1;
        } else {
            for f in case_failures {
                println!("{id}: FAILED: {f}");
                failures.push(f);
            }
        }
    }
    if failures.is_empty() {
        println!("{passed} passed; 0 failed");
    } else {
        println!("{} passed; {} failed", passed, failures.len());
        std::process::exit(1);
    }
}

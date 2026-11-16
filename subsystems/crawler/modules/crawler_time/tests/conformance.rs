//! Conformance: [C03] UTC-only history, [C04] timing arithmetic.

use crawler_schema::{record_value, validate, CheckedRecord};
use crawler_time::{
    compare_deadline, normalize_timestamp, validate_measurement, ClockAuthority,
};
use serde_json::{json, Value};
use std::cmp::Ordering;

fn checked(value: Value) -> CheckedRecord {
    validate("audit_log", value).expect("fixture must satisfy the schema gate")
}

fn missing(reason: &str) -> Value {
    json!({"value": null, "reason": reason})
}

fn timepoint(clock_id: &str, boot_id: &str, origin: &str, offset_ms: i64, utc: Value) -> Value {
    json!({
        "clock_id": clock_id,
        "boot_id": boot_id,
        "origin": origin,
        "monotonic_offset_ms": offset_ms,
        "utc_annotation": utc,
    })
}

/// Registered clocks: a monotonic lease-authority clock plus an opaque
/// subject-report clock, with an independent import receipt.
fn lease_clocks() -> Value {
    json!({
        "clocks": [
            {"clock_id": "lease-clk", "boot_id": "boot-7", "origin": "engine_measured",
             "source_id": "lease-authority-1", "basis": "monotonic_offset", "unit": "ms"},
            {"clock_id": "report-clk", "boot_id": "rep-3", "origin": "subject_reported",
             "source_id": "subject-9", "basis": "opaque_report", "unit": "ms"}
        ],
        "receipt": timepoint("lease-clk", "boot-7", "engine_measured", 50_000, missing("not_observed")),
    })
}

fn base_measurement() -> Value {
    json!({
        "measurement_id": "m-1",
        "name": "fetch_latency",
        "scope": {"kind": "connector_call", "id": "call-1"},
        "quantity": "duration",
        "unit": "ms",
        "origin": "engine_measured",
        "clock_id": "lease-clk",
        "boot_id": "boot-7",
        "method": "endpoint_difference",
        "start": timepoint("lease-clk", "boot-7", "engine_measured", 1000, missing("not_observed")),
        "end": timepoint("lease-clk", "boot-7", "engine_measured", 1250, missing("not_observed")),
        "estimate": {"kind": "exact", "value": 250},
        "resolution": 1,
        "censoring": "none",
        "comparability_group": missing("not_applicable"),
    })
}

fn with(mut base: Value, key: &str, value: Value) -> Value {
    base.as_object_mut()
        .expect("measurement fixture must be an object")
        .insert(key.to_string(), value);
    base
}

// ---------------------------------------------------------------------------
// [C03] UTC-only history
// ---------------------------------------------------------------------------

/// UTC-only history yields Missing(not_observed): no invented offset, boot,
/// clock, or origin. [C03]
#[test]
fn c03_utc_only_yields_missing_without_invented_coordinates() {
    for source in [
        checked(json!({"utc": "2024-05-01T12:00:00Z", "field": "posted_date"})),
        // Partial coordinates are still not established: nothing is filled in.
        checked(json!({"clock_id": "lease-clk", "utc": "2024-05-01T12:00:00Z"})),
        checked(json!({
            "clock_id": "lease-clk", "boot_id": "boot-7", "origin": "engine_measured",
            "utc": "2024-05-01T12:00:00Z",
        })),
    ] {
        let out = normalize_timestamp(&source, &checked(lease_clocks()))
            .expect("UTC-only history must normalize");
        let tp = &record_value(&out)["timepoint"];
        assert_eq!(tp["value"], Value::Null, "timepoint must be Missing");
        assert_eq!(tp["reason"], json!("not_observed"));
        assert!(
            tp.get("monotonic_offset_ms").is_none(),
            "must not invent offset zero"
        );
        assert!(tp.get("boot_id").is_none(), "must not invent a boot");
        assert!(tp.get("clock_id").is_none(), "must not invent a clock");
        assert!(tp.get("origin").is_none(), "must not invent an origin");
    }
}

/// The original UTC is retained verbatim in field evidence. [C03]
#[test]
fn c03_utc_only_retains_exact_utc_evidence() {
    let utc = "2024-05-01T12:00:00.123Z";
    for source in [
        checked(json!({"utc": utc})),
        checked(json!({"utc_annotation": utc})),
    ] {
        let out = normalize_timestamp(&source, &checked(lease_clocks()))
            .expect("UTC-only history must normalize");
        assert_eq!(record_value(&out)["utc_evidence"], json!(utc));
    }
}

/// A required held lease cannot be rebuilt from UTC alone: publication is
/// blocked instead of fabricating authority-clock coordinates. [C03]
#[test]
fn c03_required_held_lease_publication_blocked() {
    for source in [
        checked(json!({"utc": "2024-05-01T12:00:00Z", "required": true, "field": "leased_at"})),
        checked(json!({"utc": "2024-05-01T12:00:00Z", "lease": "held"})),
    ] {
        let err = normalize_timestamp(&source, &checked(lease_clocks()))
            .expect_err("required TimePoint must not be rebuilt from UTC");
        assert_eq!(err.code, "required_timepoint_unrecoverable");
        assert!(!err.detail.is_empty());
    }
}

/// Established coordinates on a registered clock are emitted unchanged. [C03]
#[test]
fn c03_established_timepoint_emitted_unchanged() {
    let tp_in = timepoint(
        "lease-clk",
        "boot-7",
        "engine_measured",
        4200,
        json!("2026-03-04T05:06:07Z"),
    );
    let out = normalize_timestamp(&checked(tp_in.clone()), &checked(lease_clocks()))
        .expect("established coordinates must normalize");
    let v = record_value(&out);
    assert_eq!(v["timepoint"], tp_in, "original TimePoint must survive");
    assert_eq!(v["utc_evidence"], json!("2026-03-04T05:06:07Z"));
    // A required field with established coordinates is fine.
    let mut with_req = tp_in.clone();
    with_req
        .as_object_mut()
        .unwrap()
        .insert("required".to_string(), json!(true));
    normalize_timestamp(&checked(with_req), &checked(lease_clocks()))
        .expect("required field with coordinates must normalize");
}

/// Lost established coordinates use observation_lost, never not_observed.
/// [C03]
#[test]
fn c03_lost_coordinates_use_observation_lost() {
    let source = checked(json!({
        "clock_id": "lease-clk",
        "boot_id": "boot-7",
        "origin": "engine_measured",
        "monotonic_offset_ms": missing("observation_lost"),
        "utc": "2024-05-01T12:00:00Z",
    }));
    let out = normalize_timestamp(&source, &checked(lease_clocks()))
        .expect("lost coordinates must normalize to Missing");
    let v = record_value(&out);
    assert_eq!(v["timepoint"]["reason"], json!("observation_lost"));
    assert_eq!(v["utc_evidence"], json!("2024-05-01T12:00:00Z"));
}

/// Import receipt is recorded independently and never substituted for the
/// source occurrence time. [C03]
#[test]
fn c03_import_receipt_never_substituted_for_source_time() {
    let evidence = checked(lease_clocks());
    // UTC-only: Missing, not the receipt's coordinates (offset 50000).
    let out = normalize_timestamp(
        &checked(json!({"utc": "2024-05-01T12:00:00Z"})),
        &evidence,
    )
    .expect("UTC-only history must normalize");
    let v = record_value(&out);
    assert!(v["timepoint"].get("monotonic_offset_ms").is_none());
    assert_eq!(v["receipt"]["monotonic_offset_ms"], json!(50_000));
    // Established: source coordinates win, not the receipt.
    let out = normalize_timestamp(
        &checked(timepoint(
            "lease-clk",
            "boot-7",
            "engine_measured",
            100,
            missing("not_observed"),
        )),
        &evidence,
    )
    .expect("established coordinates must normalize");
    let v = record_value(&out);
    assert_eq!(v["timepoint"]["monotonic_offset_ms"], json!(100));
    assert_eq!(v["receipt"]["monotonic_offset_ms"], json!(50_000));
}

/// Coordinates on an unregistered clock are rejected. [C03]
#[test]
fn c03_unregistered_clock_rejected() {
    let source = checked(timepoint(
        "ghost-clk",
        "boot-1",
        "engine_measured",
        10,
        missing("not_observed"),
    ));
    let err = normalize_timestamp(&source, &checked(lease_clocks()))
        .expect_err("unregistered clock must be rejected");
    assert_eq!(err.code, "unregistered_clock");
}

/// A claimed negative offset is corrupt data, not UTC-only history. [C03]
#[test]
fn c03_negative_offset_rejected() {
    let source = checked(json!({
        "clock_id": "lease-clk",
        "boot_id": "boot-7",
        "origin": "engine_measured",
        "monotonic_offset_ms": -5,
    }));
    let err = normalize_timestamp(&source, &checked(lease_clocks()))
        .expect_err("negative offset must be rejected");
    assert_eq!(err.code, "invalid_offset");
}

// ---------------------------------------------------------------------------
// [C04] Timing arithmetic
// ---------------------------------------------------------------------------

/// Ordering across clock IDs is rejected. [C04]
#[test]
fn c04_cross_clock_deadline_ordering_rejected() {
    let a = checked(timepoint(
        "lease-clk",
        "boot-7",
        "engine_measured",
        100,
        missing("not_observed"),
    ));
    let b = checked(timepoint(
        "report-clk",
        "rep-3",
        "subject_reported",
        100,
        missing("not_observed"),
    ));
    let err = compare_deadline(&a, &b).expect_err("cross-clock ordering must fail");
    assert_eq!(err.code, "cross_clock");
}

/// Ordering across boots of one clock is rejected. [C04]
#[test]
fn c04_cross_boot_deadline_ordering_rejected() {
    let a = checked(timepoint(
        "lease-clk",
        "boot-7",
        "engine_measured",
        100,
        missing("not_observed"),
    ));
    let b = checked(timepoint(
        "lease-clk",
        "boot-8",
        "engine_measured",
        50,
        missing("not_observed"),
    ));
    let err = compare_deadline(&a, &b).expect_err("cross-boot ordering must fail");
    assert_eq!(err.code, "cross_boot");
}

/// Endpoint subtraction across clocks or boots is rejected. [C04]
#[test]
fn c04_cross_clock_endpoints_rejected() {
    let clocks = checked(lease_clocks());
    // End on another (registered) clock.
    let m = with(
        base_measurement(),
        "end",
        timepoint(
            "report-clk",
            "rep-3",
            "subject_reported",
            1250,
            missing("not_observed"),
        ),
    );
    let err =
        validate_measurement(&checked(m), &clocks).expect_err("cross-clock endpoints must fail");
    assert_eq!(err.code, "cross_clock");
    // End on another boot of the same clock (registered for this check).
    let mut two_boots = lease_clocks();
    two_boots["clocks"].as_array_mut().unwrap().push(json!({
        "clock_id": "lease-clk", "boot_id": "boot-8", "origin": "engine_measured",
        "source_id": "lease-authority-1", "basis": "monotonic_offset", "unit": "ms",
    }));
    let m = with(
        base_measurement(),
        "end",
        timepoint(
            "lease-clk",
            "boot-8",
            "engine_measured",
            1250,
            missing("not_observed"),
        ),
    );
    let err = validate_measurement(&checked(m), &checked(two_boots))
        .expect_err("cross-boot endpoints must fail");
    assert_eq!(err.code, "cross_boot");
}

/// Same clock and boot orders by offset only; UTC is ignored. [C04]
#[test]
fn c04_same_clock_deadline_orders_by_offset_and_ignores_utc() {
    let at = |offset: i64, utc: &str| {
        checked(timepoint(
            "lease-clk",
            "boot-7",
            "engine_measured",
            offset,
            json!(utc),
        ))
    };
    // UTC annotations disagree with the monotonic order throughout.
    let early = at(100, "2026-01-01T00:00:00Z");
    let late = at(200, "2025-01-01T00:00:00Z");
    assert_eq!(
        compare_deadline(&early, &late).expect("same clock must order"),
        Ordering::Less
    );
    assert_eq!(
        compare_deadline(&late, &early).expect("same clock must order"),
        Ordering::Greater
    );
    let same_a = at(100, "2026-01-01T00:00:00Z");
    let same_b = at(100, "1999-12-31T23:59:59Z");
    assert_eq!(
        compare_deadline(&same_a, &same_b).expect("same clock must order"),
        Ordering::Equal
    );
    // normalize() envelopes compare directly too.
    let env_a = normalize_timestamp(&checked(json!({
        "clock_id": "lease-clk", "boot_id": "boot-7", "origin": "engine_measured",
        "monotonic_offset_ms": 100, "utc_annotation": missing("not_observed"),
    })), &checked(lease_clocks()))
    .expect("envelope must build");
    assert_eq!(
        compare_deadline(&env_a, &late).expect("envelopes must order"),
        Ordering::Less
    );
}

/// Source-reported zero remains exact zero. [C04]
#[test]
fn c04_exact_zero_preserved() {
    let m = with(base_measurement(), "method", json!("source_value"));
    let m = with(m, "estimate", json!({"kind": "exact", "value": 0}));
    let m = with(m, "start", missing("not_observed"));
    let m = with(m, "end", missing("not_observed"));
    validate_measurement(&checked(m), &checked(lease_clocks()))
        .expect("exact zero must be preserved, not discarded");
}

/// Unavailable estimates: Missing value, unavailable method/censoring, no
/// established endpoints; zero must never replace them. [C04]
#[test]
fn c04_unavailable_estimate_enforced() {
    let clocks = checked(lease_clocks());
    let m = with(base_measurement(), "method", json!("unavailable"));
    let m = with(
        m,
        "estimate",
        json!({"kind": "unavailable", "value": missing("not_observed")}),
    );
    let m = with(m, "censoring", json!("unavailable"));
    let m = with(m, "start", missing("not_observed"));
    let m = with(m, "end", missing("not_observed"));
    validate_measurement(&checked(m.clone()), &clocks)
        .expect("well-formed unavailable must validate");
    // Zero must not replace unavailable.
    let bad = with(
        m.clone(),
        "estimate",
        json!({"kind": "unavailable", "value": 0}),
    );
    let err =
        validate_measurement(&checked(bad), &clocks).expect_err("unavailable must not be zero");
    assert_eq!(err.code, "invalid_estimate");
    // Censoring must agree.
    let bad = with(m.clone(), "censoring", json!("none"));
    let err = validate_measurement(&checked(bad), &clocks)
        .expect_err("unavailable requires censoring=unavailable");
    assert_eq!(err.code, "invalid_censoring");
    // Established endpoints would evidence a value.
    let bad = with(
        m.clone(),
        "start",
        timepoint(
            "lease-clk",
            "boot-7",
            "engine_measured",
            1000,
            missing("not_observed"),
        ),
    );
    validate_measurement(&checked(bad), &clocks)
        .expect_err("unavailable must not carry established endpoints");
}

/// Bounded estimates require at least one numeric bound with lower <= upper.
/// [C04]
#[test]
fn c04_bounded_estimate_requires_numeric_bound() {
    let clocks = checked(lease_clocks());
    let bounded = |estimate: Value| {
        let m = with(base_measurement(), "method", json!("evidence_bound"));
        let m = with(m, "estimate", estimate);
        let m = with(m, "censoring", json!("both"));
        let m = with(m, "start", missing("not_observed"));
        let m = with(m, "end", missing("not_observed"));
        validate_measurement(&checked(m), &clocks)
    };
    bounded(json!({
        "kind": "bounded",
        "lower_bound": 100,
        "upper_bound": missing("not_observed"),
    }))
    .expect("one-sided bound must validate");
    bounded(json!({"kind": "bounded", "lower_bound": 100, "upper_bound": 300}))
        .expect("two-sided bound must validate");
    let err = bounded(json!({
        "kind": "bounded",
        "lower_bound": missing("not_observed"),
        "upper_bound": missing("not_observed"),
    }))
    .expect_err("boundless bounded estimate must fail");
    assert_eq!(err.code, "invalid_estimate");
    bounded(json!({"kind": "bounded", "lower_bound": 300, "upper_bound": 100}))
        .expect_err("inverted bounds must fail");
}

/// Endpoint differences must equal end minus start on one clock/boot. [C04]
#[test]
fn c04_endpoint_difference_value_must_match() {
    let clocks = checked(lease_clocks());
    validate_measurement(&checked(base_measurement()), &clocks)
        .expect("consistent endpoint difference must validate");
    let bad = with(
        base_measurement(),
        "estimate",
        json!({"kind": "exact", "value": 999}),
    );
    let err = validate_measurement(&checked(bad), &clocks)
        .expect_err("mismatched endpoint value must fail");
    assert_eq!(err.code, "estimate_mismatch");
    let bad = with(
        base_measurement(),
        "end",
        timepoint(
            "lease-clk",
            "boot-7",
            "engine_measured",
            500,
            missing("not_observed"),
        ),
    );
    let err = validate_measurement(&checked(bad), &clocks)
        .expect_err("end before start must fail");
    assert_eq!(err.code, "negative_duration");
    // Missing endpoints cannot support an endpoint difference.
    let bad = with(base_measurement(), "start", missing("not_observed"));
    let err = validate_measurement(&checked(bad), &clocks)
        .expect_err("endpoint difference without endpoints must fail");
    assert_eq!(err.code, "missing_endpoint");
}

/// Opaque-report clocks forbid native endpoints; reporting lifetimes never
/// justify invented coordinates. [C04]
#[test]
fn c04_opaque_clock_forbids_native_endpoints() {
    let clocks = checked(lease_clocks());
    let m = with(base_measurement(), "clock_id", json!("report-clk"));
    let m = with(m, "boot_id", json!("rep-3"));
    let m = with(m, "origin", json!("subject_reported"));
    let m = with(m, "method", json!("source_value"));
    let m = with(m, "estimate", json!({"kind": "exact", "value": 7}));
    let m = with(m, "start", missing("not_observed"));
    let m = with(m, "end", missing("not_observed"));
    validate_measurement(&checked(m.clone()), &clocks)
        .expect("opaque report without endpoints must validate");
    let bad = with(
        m,
        "start",
        timepoint(
            "report-clk",
            "rep-3",
            "subject_reported",
            10,
            missing("not_observed"),
        ),
    );
    let err = validate_measurement(&checked(bad), &clocks)
        .expect_err("native endpoints on an opaque clock must fail");
    assert_eq!(err.code, "invented_endpoints");
}

/// A clock authority reports the current instant as a checked record that
/// orders against same-clock deadlines. [C04]
#[test]
fn c04_clock_authority_now_returns_registered_timepoint() {
    struct FixedClock;
    impl ClockAuthority for FixedClock {
        fn now(&self) -> Result<CheckedRecord, crawler_schema::Fault> {
            validate(
                "audit_log",
                timepoint(
                    "lease-clk",
                    "boot-7",
                    "engine_measured",
                    777,
                    missing("not_observed"),
                ),
            )
        }
    }
    fn assert_authority<A: ClockAuthority>(authority: &A) -> CheckedRecord {
        authority.now().expect("authority must report now")
    }
    let now = assert_authority(&FixedClock);
    assert_eq!(record_value(&now)["clock_id"], json!("lease-clk"));
    let deadline = checked(timepoint(
        "lease-clk",
        "boot-7",
        "engine_measured",
        1000,
        missing("not_observed"),
    ));
    assert_eq!(
        compare_deadline(&now, &deadline).expect("same clock must order"),
        Ordering::Less
    );
}

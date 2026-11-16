"""Conformance tests for contract_codec (seam mapping sections 3.1/3.3/3.4)."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

try:
    from contract_codec import (
        ClockDescriptor,
        Measurement,
        TimePoint,
        canonical_digest,
        make_missing,
        validate_measurement,
        validate_record,
    )
except ImportError:  # pragma: no cover - system pytest without editable install
    _pkg_path = Path(__file__).resolve().parents[1] / "src" / "__init__.py"
    _spec = importlib.util.spec_from_file_location("contract_codec", _pkg_path)
    assert _spec is not None and _spec.loader is not None
    _mod = importlib.util.module_from_spec(_spec)
    sys.modules["contract_codec"] = _mod
    _spec.loader.exec_module(_mod)
    ClockDescriptor = _mod.ClockDescriptor
    Measurement = _mod.Measurement
    TimePoint = _mod.TimePoint
    canonical_digest = _mod.canonical_digest
    make_missing = _mod.make_missing
    validate_measurement = _mod.validate_measurement
    validate_record = _mod.validate_record

import pytest


def _clocks():
    return (ClockDescriptor(clock_id="clock-a", boot_id="boot-1"),)


def _base_measurement(**over) -> Measurement:
    kw = dict(
        measurement_id="m-1",
        name="step_latency",
        scope="job-hunter/run",
        quantity="duration",
        unit="ms",
        origin="runner",
        clock_id="clock-a",
        boot_id="boot-1",
        method="endpoint_difference",
        start=TimePoint(clock_id="clock-a", boot_id="boot-1", origin="runner", t_mono_ms=1000),
        end=TimePoint(clock_id="clock-a", boot_id="boot-1", origin="runner", t_mono_ms=1500),
        estimate={"kind": "exact", "value": 500},
        resolution=1,
        censoring="none",
        comparability_group=make_missing("not_applicable"),
    )
    kw.update(over)
    return Measurement(**kw)


def test_bare_normalized_null_is_rejected():
    # Bare nulls in normalized records are rejected; Missing envelopes pass.
    raw = json.dumps({"id": "r1", "salary": None}).encode()
    with pytest.raises(ValueError):
        validate_record(raw, "record/v1")
    nested = json.dumps({"id": "r1", "tokens": [1, None]}).encode()
    with pytest.raises(ValueError):
        validate_record(nested, "record/v1")
    ok = json.dumps({"id": "r1", "salary": make_missing("not_observed")}).encode()
    out = validate_record(ok, "record/v1")
    assert json.loads(out)["salary"]["reason"] == "not_observed"
    # Bad reasons and duplicate keys also rejected.
    bad_reason = json.dumps({"id": "r1", "salary": {"value": None, "reason": "unknown"}}).encode()
    with pytest.raises(ValueError):
        validate_record(bad_reason, "record/v1")
    with pytest.raises(ValueError):
        validate_record(b'{"id": "a", "id": "b"}', "record/v1")
    with pytest.raises(ValueError):
        validate_record(b'{"id": "r1", "bogus": 1}', "record/v1")
    with pytest.raises(ValueError):
        validate_record(b'{"id": "r1"}', "nope/v9")


def test_missing_salary_tokens_timing_preserve_missing_never_zero():
    # Missing salary/tokens/timing must stay Missing — never coerced to zero —
    # and digest/validation round-trips preserve the envelopes.
    rec = {
        "id": "r2",
        "salary": make_missing("not_observed"),
        "tokens": make_missing("observation_lost"),
        "timing": make_missing("not_applicable"),
    }
    canonical = validate_record(json.dumps(rec).encode(), "record/v1")
    parsed = json.loads(canonical)
    for field in ("salary", "tokens", "timing"):
        assert parsed[field]["value"] is None
        assert parsed[field]["reason"] in (
            "not_enabled", "not_applicable", "not_observed",
            "observation_lost", "unsupported_by_subject", "manual_override",
        )
        assert parsed[field] != 0
    digest = canonical_digest(canonical)
    assert digest.startswith("sha256:") and len(digest) == len("sha256:") + 64
    # Unavailable-typed measurement with Missing endpoints validates.
    m = _base_measurement(
        method="unavailable",
        start=make_missing("not_observed"),
        end=make_missing("not_observed"),
        estimate={"kind": "unavailable", "value": make_missing("not_observed")},
        censoring="unavailable",
    )
    assert validate_measurement(m, _clocks()) is None
    # Missing estimate value must never validate as exact zero.
    bad = _base_measurement(estimate={"kind": "exact", "value": make_missing("not_observed")})
    with pytest.raises(ValueError):
        validate_measurement(bad, _clocks())


def test_native_exact_zero_preserves_the_reported_source_value():
    # A native exact zero is a real report: it validates and round-trips as 0.
    m = _base_measurement(
        method="source_value",
        start=TimePoint(clock_id="clock-a", boot_id="boot-1", origin="runner", t_mono_ms=1000),
        end=TimePoint(clock_id="clock-a", boot_id="boot-1", origin="runner", t_mono_ms=1000),
        estimate={"kind": "exact", "value": 0},
    )
    assert validate_measurement(m, _clocks()) is None
    rec = {"id": "r3", "salary": 0, "tokens": 0}
    canonical = validate_record(json.dumps(rec).encode(), "record/v1")
    parsed = json.loads(canonical)
    assert parsed["salary"] == 0 and parsed["tokens"] == 0
    assert not isinstance(parsed["salary"], dict)


def test_cross_clock_or_cross_boot_subtraction_is_rejected():
    # Endpoint differences must share clock AND boot; UTC annotation never licenses subtraction.
    base = dict(
        measurement_id="m-x", name="step_latency", scope="job-hunter/run",
        quantity="duration", unit="ms", origin="runner",
        clock_id="clock-a", boot_id="boot-1", method="endpoint_difference",
        estimate={"kind": "exact", "value": 500}, resolution=1, censoring="none",
        comparability_group=make_missing("not_applicable"),
    )
    clocks = (
        ClockDescriptor(clock_id="clock-a", boot_id="boot-1"),
        ClockDescriptor(clock_id="clock-b", boot_id="boot-1"),
        ClockDescriptor(clock_id="clock-a", boot_id="boot-2"),
    )
    cross_clock = Measurement(
        **base,
        start=TimePoint(clock_id="clock-a", boot_id="boot-1", origin="runner", t_mono_ms=1000),
        end=TimePoint(clock_id="clock-b", boot_id="boot-1", origin="runner", t_mono_ms=1500),
    )
    with pytest.raises(ValueError):
        validate_measurement(cross_clock, clocks)
    cross_boot = Measurement(
        **base,
        start=TimePoint(clock_id="clock-a", boot_id="boot-1", origin="runner", t_mono_ms=1000),
        end=TimePoint(clock_id="clock-a", boot_id="boot-2", origin="runner", t_mono_ms=1500),
    )
    with pytest.raises(ValueError):
        validate_measurement(cross_boot, clocks)
    # Unordered endpoints and arithmetic mismatch rejected; matching endpoints pass.
    unordered = Measurement(
        **base,
        start=TimePoint(clock_id="clock-a", boot_id="boot-1", origin="runner", t_mono_ms=1500),
        end=TimePoint(clock_id="clock-a", boot_id="boot-1", origin="runner", t_mono_ms=1000),
    )
    with pytest.raises(ValueError):
        validate_measurement(unordered, clocks)
    mismatch = Measurement(
        **{**base, "estimate": {"kind": "exact", "value": 499}},
        start=TimePoint(clock_id="clock-a", boot_id="boot-1", origin="runner", t_mono_ms=1000),
        end=TimePoint(clock_id="clock-a", boot_id="boot-1", origin="runner", t_mono_ms=1500),
    )
    with pytest.raises(ValueError):
        validate_measurement(mismatch, clocks)
    okm = Measurement(
        **base,
        start={"clock_id": "clock-a", "boot_id": "boot-1", "origin": "runner", "t_mono_ms": 1000, "utc": "2026-01-01T00:00:00Z"},
        end={"clock_id": "clock-a", "boot_id": "boot-1", "origin": "runner", "t_mono_ms": 1500, "utc": "2026-06-01T00:00:00Z"},
    )
    assert validate_measurement(okm, clocks) is None
    # Unregistered clock use rejected.
    unreg = _base_measurement()
    with pytest.raises(ValueError):
        validate_measurement(unreg, (ClockDescriptor(clock_id="other", boot_id="boot-9"),))

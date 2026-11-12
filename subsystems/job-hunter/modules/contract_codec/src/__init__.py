"""contract_codec: kernel missingness / measurement / digest codec (tier 0)."""
from __future__ import annotations

import hashlib
import json
import math
from dataclasses import asdict, dataclass, is_dataclass
from typing import Any

__all__ = [
    "Digest",
    "Measurement",
    "ClockDescriptor",
    "TimePoint",
    "Missing",
    "VALID_MISSING_REASONS",
    "validate_record",
    "canonical_digest",
    "validate_measurement",
]


class Digest(str):
    """Canonical structured-record digest: ``sha256:<64 lowercase hex>``."""


Missing = dict[str, Any]

VALID_MISSING_REASONS = frozenset({
    "not_enabled",
    "not_applicable",
    "not_observed",
    "observation_lost",
    "unsupported_by_subject",
    "manual_override",
})

VALID_METHODS = frozenset({
    "endpoint_difference",
    "source_value",
    "evidence_bound",
    "unavailable",
})

VALID_CENSORING = frozenset({"none", "left", "right", "both", "unavailable"})

SCHEMAS: dict[str, frozenset[str]] = {
    "contract/v1": frozenset({"id", "salary", "tokens", "timing", "measurement", "label", "note"}),
    "record/v1": frozenset({"id", "salary", "tokens", "timing"}),
}


def make_missing(reason: str, detail: str | None = None) -> Missing:
    if reason not in VALID_MISSING_REASONS:
        raise ValueError(f"unknown missing reason: {reason!r}")
    m: Missing = {"value": None, "reason": reason}
    if detail is not None:
        if not isinstance(detail, str) or not detail:
            raise ValueError("detail must be a nonempty string")
        m["detail"] = detail
    return m


def is_missing_envelope(v: Any) -> bool:
    return (
        isinstance(v, dict)
        and v.get("value") is None
        and "value" in v
        and "reason" in v
    )


def _validate_missing_envelope(v: dict[str, Any], path: str) -> None:
    allowed = {"value", "reason", "detail"}
    extra = set(v.keys()) - allowed
    if extra:
        raise ValueError(f"undeclared Missing property at {path}: {sorted(extra)}")
    if v.get("value") is not None:
        raise ValueError(f"Missing.value must be null at {path}")
    reason = v.get("reason")
    if reason not in VALID_MISSING_REASONS:
        raise ValueError(f"unknown missing reason at {path}: {reason!r}")
    if "detail" in v:
        detail = v["detail"]
        if not isinstance(detail, str) or not detail:
            raise ValueError(f"Missing.detail must be nonempty at {path}")


def _reject_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for k, v in pairs:
        if k in obj:
            raise ValueError(f"duplicate mapping key: {k!r}")
        obj[k] = v
    return obj


def _reject_nonfinite(s: str) -> Any:
    raise ValueError(f"nonfinite number literal rejected: {s!r}")


def _parse_strict_json(data: bytes) -> Any:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ValueError(f"invalid utf-8: {e}") from e
    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_object,
            parse_constant=_reject_nonfinite,
        )
    except json.JSONDecodeError as e:
        raise ValueError(f"invalid JSON: {e}") from e


def _canonical_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _check_no_bare_null(node: Any, path: str) -> None:
    if node is None:
        raise ValueError(f"bare null rejected at {path} (use Missing envelope)")
    if isinstance(node, dict):
        if is_missing_envelope(node):
            _validate_missing_envelope(node, path)
            return
        # A dict that claims a reason but is malformed must still be rejected,
        # never coerced.
        if "reason" in node and "value" in node:
            _validate_missing_envelope(node, path)
            return
        for k, v in node.items():
            if v is None:
                raise ValueError(f"bare null rejected at {path}.{k} (use Missing envelope)")
            _check_no_bare_null(v, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            if v is None:
                raise ValueError(f"bare null rejected at {path}[{i}] (use Missing envelope)")
            _check_no_bare_null(v, f"{path}[{i}]")


def validate_record(data: bytes, schema_id: str) -> bytes:
    """Validate a normalized record; return canonical JSON bytes.

    Rejects: unknown schema versions, duplicate keys, nonfinite numbers,
    undeclared closed-object properties, and bare nulls (every normalized
    null must be a ``Missing`` envelope with one of the six reasons).
    """
    if schema_id not in SCHEMAS:
        raise ValueError(f"unknown schema version: {schema_id!r}")
    obj = _parse_strict_json(data)
    if not isinstance(obj, dict):
        raise ValueError("normalized record must be a JSON object")
    allowed = SCHEMAS[schema_id]
    extra = set(obj.keys()) - allowed
    if extra:
        raise ValueError(f"undeclared closed-object properties: {sorted(extra)}")
    _check_no_bare_null(obj, "$")
    return _canonical_bytes(obj)


def canonical_digest(data: bytes) -> Digest:
    """Digest a structured record with ``kernel-jcs-sha256/1``.

    Parses strict JSON (rejecting duplicates / nonfinite numbers), applies
    JCS-style canonicalization (sorted keys, no whitespace, UTF-8), and
    returns ``sha256:<64 lowercase hex>``. Arbitrary non-JSON artifact bytes
    are rejected: use exact-byte digests for artifacts, not this function.
    """
    obj = _parse_strict_json(data)
    if not isinstance(obj, dict):
        raise ValueError("canonical_digest requires a JSON object record")
    _check_no_bare_null(obj, "$")
    canonical = _canonical_bytes(obj)
    hexpart = hashlib.sha256(canonical).hexdigest()
    digest = Digest(f"sha256:{hexpart}")
    if len(hexpart) != 64 or not all(c in "0123456789abcdef" for c in hexpart):
        raise ValueError("internal digest format error")
    return digest


@dataclass(frozen=True)
class ClockDescriptor:
    clock_id: str
    boot_id: str


@dataclass(frozen=True)
class TimePoint:
    clock_id: str
    boot_id: str
    origin: str
    t_mono_ms: float | int


@dataclass
class Measurement:
    measurement_id: str
    name: str
    scope: str
    quantity: str  # duration | scalar
    unit: str  # ms for duration
    origin: str
    clock_id: str
    boot_id: str
    method: str  # endpoint_difference | source_value | evidence_bound | unavailable
    start: Any  # TimePoint | dict | Missing
    end: Any
    estimate: Any  # dict: exact | bounded | unavailable
    resolution: Any  # number | Missing
    censoring: str  # none | left | right | both | unavailable
    comparability_group: Any  # str | Missing


def _as_dict(obj: Any) -> dict[str, Any]:
    if is_dataclass(obj) and not isinstance(obj, type):
        return asdict(obj)
    if isinstance(obj, dict):
        return obj
    raise TypeError(f"expected dataclass or dict, got {type(obj).__name__}")


def _is_number(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _require_finite_number(v: Any, path: str) -> float | int:
    if not _is_number(v):
        raise ValueError(f"{path} must be numeric, got {v!r}")
    if not math.isfinite(float(v)):
        raise ValueError(f"{path} must be finite, got {v!r}")
    return v


def _normalize_endpoint(v: Any, path: str) -> dict[str, Any] | Missing:
    if is_missing_envelope(v):
        if not isinstance(v, dict):
            raise ValueError(f"{path} Missing envelope must be a dict")
        _validate_missing_envelope(v, path)
        return v
    if isinstance(v, TimePoint):
        d = asdict(v)
    elif isinstance(v, dict):
        d = v
    else:
        raise ValueError(f"{path} must be a TimePoint or Missing, got {v!r}")
    for f in ("clock_id", "boot_id", "origin", "t_mono_ms"):
        if f not in d:
            raise ValueError(f"{path} missing field {f!r}")
    for f in ("clock_id", "boot_id", "origin"):
        if not isinstance(d[f], str) or not d[f]:
            raise ValueError(f"{path}.{f} must be a nonempty string")
    extra = set(d.keys()) - {"clock_id", "boot_id", "origin", "t_mono_ms", "utc"}
    if extra:
        raise ValueError(f"{path} has undeclared properties: {sorted(extra)}")
    _require_finite_number(d["t_mono_ms"], f"{path}.t_mono_ms")
    if float(d["t_mono_ms"]) < 0:
        raise ValueError(f"{path}.t_mono_ms must be a nonnegative monotonic offset")
    return d


def validate_measurement(measurement: Measurement, clocks: tuple[ClockDescriptor, ...]) -> None:
    """Validate a ``K.Measurement`` against kernel time/timing rules.

    Raises on any violation; returns ``None`` when valid. Never mutates the
    input and never coerces ``Missing`` to zero or zero to ``Missing``.
    """
    m = _as_dict(measurement)
    required = (
        "measurement_id", "name", "scope", "quantity", "unit", "origin",
        "clock_id", "boot_id", "method", "start", "end", "estimate",
        "resolution", "censoring", "comparability_group",
    )
    for f in required:
        if f not in m:
            raise ValueError(f"measurement missing required field {f!r}")
    for f in ("measurement_id", "name", "scope", "origin", "clock_id", "boot_id"):
        if not isinstance(m[f], str) or not m[f]:
            raise ValueError(f"measurement.{f} must be a nonempty string")
    if m["quantity"] not in ("duration", "scalar"):
        raise ValueError(f"unknown quantity: {m['quantity']!r}")
    if m["quantity"] == "duration" and m["unit"] != "ms":
        raise ValueError("duration measurements must use unit 'ms'")
    if m["quantity"] == "scalar" and (not isinstance(m["unit"], str) or not m["unit"]):
        raise ValueError("scalar measurements need an explicit unit")
    if m["method"] not in VALID_METHODS:
        raise ValueError(f"unknown method: {m['method']!r}")
    if m["censoring"] not in VALID_CENSORING:
        raise ValueError(f"unknown censoring: {m['censoring']!r}")

    registered: set[tuple[str, str]] = set()
    for c in clocks:
        cd = _as_dict(c)
        if "clock_id" not in cd or "boot_id" not in cd:
            raise ValueError("clock descriptor needs clock_id and boot_id")
        registered.add((cd["clock_id"], cd["boot_id"]))
    if (m["clock_id"], m["boot_id"]) not in registered:
        raise ValueError(f"unregistered clock/boot: {(m['clock_id'], m['boot_id'])}")

    start = _normalize_endpoint(m["start"], "start")
    end = _normalize_endpoint(m["end"], "end")
    for ep, label in ((start, "start"), (end, "end")):
        if isinstance(ep, dict) and "t_mono_ms" in ep:
            if (ep["clock_id"], ep["boot_id"]) not in registered:
                raise ValueError(f"unregistered endpoint clock/boot at {label}")

    est = m["estimate"]
    if not isinstance(est, dict) or "kind" not in est:
        raise ValueError("estimate must be a dict with 'kind'")
    kind = est["kind"]
    if kind not in ("exact", "bounded", "unavailable"):
        raise ValueError(f"unknown estimate kind: {kind!r}")

    resolution = m["resolution"]
    if is_missing_envelope(resolution):
        _validate_missing_envelope(resolution, "resolution")
    else:
        _require_finite_number(resolution, "resolution")
        if float(resolution) < 0:
            raise ValueError("resolution must be nonnegative or Missing")

    cg = m["comparability_group"]
    if is_missing_envelope(cg):
        _validate_missing_envelope(cg, "comparability_group")
    elif not (isinstance(cg, str) and cg):
        raise ValueError("comparability_group must be a nonempty string or Missing")

    is_duration = m["quantity"] == "duration"

    if kind == "exact":
        if set(est.keys()) != {"kind", "value"}:
            raise ValueError("exact estimate must be exactly {kind, value}")
        value = est["value"]
        if value is None or is_missing_envelope(value):
            raise ValueError("exact estimate value must be numeric, never Missing")
        _require_finite_number(value, "estimate.value")
        if is_duration and float(value) < 0:
            raise ValueError("duration estimate must be nonnegative")
        if m["censoring"] != "none":
            raise ValueError("exact values use no censoring (censoring must be 'none')")
        if m["method"] == "unavailable":
            raise ValueError("exact estimate cannot use unavailable method")
    elif kind == "bounded":
        if set(est.keys()) != {"kind", "lower_bound", "upper_bound"}:
            raise ValueError("bounded estimate must be exactly {kind, lower_bound, upper_bound}")
        lo, hi = est["lower_bound"], est["upper_bound"]
        lo_num = _is_number(lo)
        hi_num = _is_number(hi)
        if is_missing_envelope(lo):
            _validate_missing_envelope(lo, "estimate.lower_bound")
            lo_num = False
        if is_missing_envelope(hi):
            _validate_missing_envelope(hi, "estimate.upper_bound")
            hi_num = False
        if lo is None or hi is None:
            raise ValueError("bounded bounds must be numeric or Missing, never bare null")
        if not lo_num and not hi_num:
            raise ValueError("bounded estimate needs at least one numeric bound")
        for b, label in ((lo, "lower_bound"), ((hi, "upper_bound"))):
            if _is_number(b):
                _require_finite_number(b, f"estimate.{label}")
                if is_duration and float(b) < 0:
                    raise ValueError(f"duration estimate.{label} must be nonnegative")
        if lo_num and hi_num and float(lo) > float(hi):  # type: ignore[arg-type]
            raise ValueError("bounded lower_bound must not exceed upper_bound")
        if m["method"] != "evidence_bound":
            raise ValueError("bounded values use method 'evidence_bound'")
    else:  # unavailable
        if set(est.keys()) != {"kind", "value"}:
            raise ValueError("unavailable estimate must be exactly {kind, value}")
        if not is_missing_envelope(est["value"]):
            raise ValueError("unavailable estimate value must be Missing")
        _validate_missing_envelope(est["value"], "estimate.value")
        if m["method"] != "unavailable" or m["censoring"] != "unavailable":
            raise ValueError("unavailable values use unavailable method and censoring")

    if m["method"] == "unavailable":
        if not is_missing_envelope(start) or not is_missing_envelope(end):
            raise ValueError("unavailable measurements use Missing endpoints")
        return None

    if m["method"] == "endpoint_difference":
        if is_missing_envelope(start) or is_missing_envelope(end):
            raise ValueError("endpoint_difference requires concrete TimePoint endpoints")
        assert isinstance(start, dict) and isinstance(end, dict)
        # Never subtract across clock IDs or boots; UTC is annotation only.
        if start["clock_id"] != end["clock_id"]:
            raise ValueError("cross-clock subtraction rejected")
        if start["boot_id"] != end["boot_id"]:
            raise ValueError("cross-boot subtraction rejected")
        if start["origin"] != end["origin"]:
            raise ValueError("endpoint origins must match for endpoint_difference")
        if start["clock_id"] != m["clock_id"] or start["boot_id"] != m["boot_id"]:
            raise ValueError("endpoints must share the measurement clock/boot")
        if end["clock_id"] != m["clock_id"] or end["boot_id"] != m["boot_id"]:
            raise ValueError("endpoints must share the measurement clock/boot")
        duration = float(end["t_mono_ms"]) - float(start["t_mono_ms"])
        if duration < 0:
            raise ValueError("endpoints are unordered (end < start)")
        if kind == "exact":
            if float(est["value"]) != duration:
                raise ValueError("endpoint_difference arithmetic mismatch")
        elif kind == "bounded":
            lo, hi = est["lower_bound"], est["upper_bound"]
            if _is_number(lo) and duration < float(lo):  # type: ignore[arg-type]
                raise ValueError("duration below bounded lower_bound")
            if _is_number(hi) and duration > float(hi):  # type: ignore[arg-type]
                raise ValueError("duration above bounded upper_bound")
    return None

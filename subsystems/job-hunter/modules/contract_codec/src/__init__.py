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
    "VALID_METHODS",
    "VALID_CENSORING",
    "make_missing",
    "is_missing_envelope",
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

VALID_CLOCK_BASES = frozenset({"monotonic_offset", "opaque_report"})

VALID_SCOPE_KINDS = frozenset({
    "run", "session", "connector_call", "workflow_step",
    "application_operation", "native_primitive", "recovery",
    "discovery", "capability", "resource",
})

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
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _check_finite_numbers(node: Any, path: str) -> None:
    # json.loads accepts overflow literals like 1e1000 as inf without calling
    # parse_constant; JCS canonicalization must never emit nonfinite numbers.
    if isinstance(node, float) and not math.isfinite(node):
        raise ValueError(f"nonfinite number rejected at {path}")
    if isinstance(node, dict):
        for k, v in node.items():
            _check_finite_numbers(v, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            _check_finite_numbers(v, f"{path}[{i}]")


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
    _check_finite_numbers(obj, "$")
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
    _check_finite_numbers(obj, "$")
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
    # Optional kernel fields (evidence-kernel ClockDescriptor). Minimal
    # (clock_id, boot_id) descriptors remain valid; when the full shape is
    # supplied it is validated.
    origin: str | None = None
    source_id: str | None = None
    basis: str | None = None
    unit: str | None = None


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
    scope: Any  # str | dict{kind, id}: local string or kernel Scope object
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


def _endpoint_offset(d: dict[str, Any], path: str) -> float | int:
    # Canonical accessor: exactly one of t_mono_ms / monotonic_offset_ms must
    # supply the coordinate; when both appear they must agree.
    has_short = "t_mono_ms" in d
    has_long = "monotonic_offset_ms" in d
    if not has_short and not has_long:
        raise ValueError(f"{path} missing field 't_mono_ms'")
    if has_short:
        _require_finite_number(d["t_mono_ms"], f"{path}.t_mono_ms")
    if has_long:
        _require_finite_number(d["monotonic_offset_ms"], f"{path}.monotonic_offset_ms")
    if has_short and has_long and float(d["t_mono_ms"]) != float(d["monotonic_offset_ms"]):
        raise ValueError(f"{path} conflicting t_mono_ms / monotonic_offset_ms")
    raw = d["t_mono_ms"] if has_short else d["monotonic_offset_ms"]
    label = "t_mono_ms" if has_short else "monotonic_offset_ms"
    if float(raw) < 0:
        raise ValueError(f"{path}.{label} must be a nonnegative monotonic offset")
    return raw


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
    for f in ("clock_id", "boot_id", "origin"):
        if f not in d:
            raise ValueError(f"{path} missing field {f!r}")
    for f in ("clock_id", "boot_id", "origin"):
        if not isinstance(d[f], str) or not d[f]:
            raise ValueError(f"{path}.{f} must be a nonempty string")
    extra = set(d.keys()) - {
        "clock_id", "boot_id", "origin", "t_mono_ms",
        "monotonic_offset_ms", "utc", "utc_annotation",
    }
    if extra:
        raise ValueError(f"{path} has undeclared properties: {sorted(extra)}")
    _endpoint_offset(d, path)
    # UTC is annotation only: a string timestamp or a Missing envelope. It
    # never licenses cross-clock/boot/origin subtraction.
    for f in ("utc", "utc_annotation"):
        if f in d:
            uv = d[f]
            if is_missing_envelope(uv):
                _validate_missing_envelope(uv, f"{path}.{f}")
            elif not (isinstance(uv, str) and uv):
                raise ValueError(f"{path}.{f} must be a date-time string or Missing")
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
    extra_top = set(m.keys()) - set(required)
    if extra_top:
        raise ValueError(f"measurement has undeclared properties: {sorted(extra_top)}")
    for f in ("measurement_id", "name", "origin", "clock_id", "boot_id"):
        if not isinstance(m[f], str) or not m[f]:
            raise ValueError(f"measurement.{f} must be a nonempty string")
    scope = m["scope"]
    if isinstance(scope, dict):
        if set(scope.keys()) != {"kind", "id"}:
            raise ValueError("measurement.scope object must be exactly {kind, id}")
        if scope["kind"] not in VALID_SCOPE_KINDS:
            raise ValueError(f"unknown scope kind: {scope['kind']!r}")
        if not isinstance(scope["id"], str) or not scope["id"]:
            raise ValueError("measurement.scope.id must be a nonempty string")
    elif not (isinstance(scope, str) and scope):
        raise ValueError("measurement.scope must be a nonempty string or Scope object")
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
        for f in ("clock_id", "boot_id"):
            if not isinstance(cd[f], str) or not cd[f]:
                raise ValueError(f"clock descriptor {f} must be a nonempty string")
        extra_cd = set(cd.keys()) - {
            "clock_id", "boot_id", "origin", "source_id", "basis", "unit",
        }
        if extra_cd:
            raise ValueError(f"clock descriptor has undeclared properties: {sorted(extra_cd)}")
        # Optional kernel fields: validated when supplied, ignored when None.
        if cd.get("origin") is not None and (
            not isinstance(cd["origin"], str) or not cd["origin"]
        ):
            raise ValueError("clock descriptor origin must be a nonempty string")
        if cd.get("source_id") is not None and (
            not isinstance(cd["source_id"], str) or not cd["source_id"]
        ):
            raise ValueError("clock descriptor source_id must be a nonempty string")
        if cd.get("basis") is not None and cd["basis"] not in VALID_CLOCK_BASES:
            raise ValueError(f"unknown clock basis: {cd['basis']!r}")
        if cd.get("unit") is not None and cd["unit"] != "ms":
            raise ValueError("clock descriptor unit must be 'ms'")
        registered.add((cd["clock_id"], cd["boot_id"]))
    if (m["clock_id"], m["boot_id"]) not in registered:
        raise ValueError(f"unregistered clock/boot: {(m['clock_id'], m['boot_id'])}")

    start = _normalize_endpoint(m["start"], "start")
    end = _normalize_endpoint(m["end"], "end")
    for ep, label in ((start, "start"), (end, "end")):
        if isinstance(ep, dict) and ("t_mono_ms" in ep or "monotonic_offset_ms" in ep):
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
        if m["method"] not in ("endpoint_difference", "source_value"):
            raise ValueError("exact values use method 'endpoint_difference' or 'source_value'")
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
        if m["censoring"] not in ("none", "left", "right", "both"):
            raise ValueError("bounded values use censoring 'none', 'left', 'right', or 'both'")
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
        if m["quantity"] != "duration":
            raise ValueError("endpoint_difference requires quantity 'duration'")
        if kind != "exact":
            raise ValueError("endpoint_difference requires an exact estimate")
        if is_missing_envelope(start) or is_missing_envelope(end):
            raise ValueError("endpoint_difference requires concrete TimePoint endpoints")
        assert isinstance(start, dict) and isinstance(end, dict)
        # Never subtract across clock IDs, boots, or origins; UTC is annotation only.
        if start["clock_id"] != end["clock_id"]:
            raise ValueError("cross-clock subtraction rejected")
        if start["boot_id"] != end["boot_id"]:
            raise ValueError("cross-boot subtraction rejected")
        if start["origin"] != end["origin"]:
            raise ValueError("endpoint origins must match for endpoint_difference")
        if start["origin"] != m["origin"] or end["origin"] != m["origin"]:
            raise ValueError("endpoints must share the measurement origin")
        if start["clock_id"] != m["clock_id"] or start["boot_id"] != m["boot_id"]:
            raise ValueError("endpoints must share the measurement clock/boot")
        if end["clock_id"] != m["clock_id"] or end["boot_id"] != m["boot_id"]:
            raise ValueError("endpoints must share the measurement clock/boot")
        duration = float(_endpoint_offset(end, "end")) - float(_endpoint_offset(start, "start"))
        if duration < 0:
            raise ValueError("endpoints are unordered (end < start)")
        if float(est["value"]) != duration:
            raise ValueError("endpoint_difference arithmetic mismatch")
    return None

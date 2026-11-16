"""dashboard_gateway: HTTP dashboard projections and authorized command intake (tier 5).

Implements seam mapping 17.5 / 11.8 for job-hunter:

* The dashboard consumes an HTTP API independent of orchestrator language.
* It displays product selection and basis, crawler input revision and
  coverage, evaluation freshness, attempt kind/target, all five axes (or
  explicit inapplicability), close-time knowledge separately from later
  facts, report coverage and input-pin staleness, missing/lost evidence,
  and duplicate-risk/integrity issues.
* It never offers a generic "set application status" write, whole-row
  replacement, or direct owner-domain mutation. Buttons submit authorized
  commands (select job, commission, request control, record manual
  observation) which are journaled as intent for separately authorized
  workflow handling. An accepted command never claims its requested
  external effect occurred.
* Dashboard caches are projections, never authority. No shared database
  writes or cross-domain transactions occur here.
* Missing values are always typed Missing envelopes; bare nulls are
  rejected at ingress via the tier-0 strict JSON gate.
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import math
import re
import sys
import threading
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse


def _load_sibling(name: str):  # pragma: no cover - import plumbing
    if name in sys.modules:
        return sys.modules[name]
    try:
        return importlib.import_module(name)
    except ModuleNotFoundError:
        pass
    sibling_path = (
        Path(__file__).resolve().parents[2] / name / "src" / "__init__.py"
    )
    spec = importlib.util.spec_from_file_location(name, sibling_path)
    if spec is None or spec.loader is None:  # pragma: no cover
        raise ModuleNotFoundError(f"sibling module {name!r} not found")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


contract_codec = _load_sibling("contract_codec")
access_policy = _load_sibling("access_policy")
artifact_store = _load_sibling("artifact_store")
evidence_journal = _load_sibling("evidence_journal")
read_publications = _load_sibling("read_publications")

__all__ = [
    "SCHEMA_VERSION",
    "RECORD_TYPE",
    "ALLOWED_COMMANDS",
    "handle_http",
    "reset_for_tests",
]

SCHEMA_VERSION = "dashboard-gateway/0.1.0"
RECORD_TYPE = "attempt_snapshot"
PROJECTION_RECORD_TYPE = "dashboard_projection"

AXES: tuple[str, ...] = ("dispatch", "observation", "execution", "application", "report")
REPORT_INPUT_AXES: tuple[str, ...] = ("dispatch", "observation", "execution", "application")
SEAL_NAMES = frozenset({"commissioned", "observation_closed", "evidence_updated"})
ATTEMPT_KINDS = frozenset({"practice", "production"})
EXECUTION_KNOWLEDGE = frozenset({"running", "terminal", "unknown", "not_applicable"})
APPLICATION_KNOWLEDGE = frozenset({"committed", "not_committed", "unknown"})
FACT_STATES = frozenset({"committed", "not_committed"})
FACT_COVERAGE = frozenset({"at_boundary", "final_for_attempt"})

ALLOWED_COMMANDS = frozenset(
    {
        "select_job",
        "commission_attempt",
        "request_control",
        "record_manual_observation",
    }
)

_FORBIDDEN_COMMAND_EXACT = frozenset(
    {
        "set_application_status",
        "set_status",
        "update_application_status",
        "update_status",
        "set_scalar_status",
        "application_status",
        "replace_row",
        "update_row",
        "set_row",
        "mutate_owner_domain",
        "write_owner_domain",
        "set_owner_domain",
    }
)

_FORBIDDEN_PATH_SUBSTRINGS = (
    "status",
    "replace_row",
    "replace-row",
    "mutate_owner",
    "write_owner",
    "set_owner",
)

_CODEC_GATE_SCHEMA = "record/v1"
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

_LOCK = threading.Lock()
_SNAPSHOTS: dict[str, Any] = {}


class DashboardError(Exception):
    """An HTTP-mapped dashboard failure (never a bare traceback to callers)."""

    def __init__(self, http_status: int, code: str, message: str, extra: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.http_status = http_status
        self.code = code
        self.message = message
        self.extra = dict(extra) if extra else {}


def reset_for_tests() -> None:
    """Clear dashboard projection index (test harness only)."""
    with _LOCK:
        _SNAPSHOTS.clear()


# ---------------------------------------------------------------------------
# Canonical JSON + strict gate
# ---------------------------------------------------------------------------


def _canonical_bytes(obj: Any) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _reject_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f"duplicate mapping key: {key!r}")
        obj[key] = value
    return obj


def _strict_parse_body(raw: bytes, context: str) -> dict[str, Any]:
    if not isinstance(raw, bytes):
        raise DashboardError(400, "invalid_body", f"{context} body must be bytes")
    if not raw.strip():
        raise DashboardError(400, "invalid_body", f"{context} body is empty; JSON object required")
    wrapper = b'{"id":"dashboard_gateway_gate","timing":' + raw + b"}"
    try:
        contract_codec.validate_record(wrapper, _CODEC_GATE_SCHEMA)
    except (ValueError, TypeError) as exc:
        raise DashboardError(
            400, "invalid_json", f"{context}: strict JSON gate rejected body: {exc}"
        ) from exc
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DashboardError(400, "invalid_json", f"{context}: body is not valid utf-8") from exc
    try:
        obj = json.loads(text, object_pairs_hook=_reject_duplicate_object)
    except ValueError as exc:
        raise DashboardError(400, "invalid_json", f"{context}: body is not valid JSON: {exc}") from exc
    if not isinstance(obj, dict):
        raise DashboardError(400, "invalid_body", f"{context} body must be a JSON object")
    return obj


def _missing(reason: str, detail: str | None = None) -> dict[str, Any]:
    return contract_codec.make_missing(reason, detail)


def _is_missing(value: Any) -> bool:
    try:
        return bool(contract_codec.is_missing_envelope(value))
    except Exception:
        return False


def _validate_missing(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise DashboardError(400, "invalid_missing", f"{field} must be a typed Missing envelope")
    keys = set(value.keys())
    if keys - {"value", "reason", "detail"} or "value" not in keys or "reason" not in keys:
        raise DashboardError(400, "invalid_missing", f"{field} is not a typed Missing envelope")
    if value.get("value") is not None:
        raise DashboardError(400, "invalid_missing", f"{field}.value must be null")
    reason = value.get("reason")
    if reason not in contract_codec.VALID_MISSING_REASONS:
        raise DashboardError(400, "invalid_missing", f"{field} has unknown Missing reason {reason!r}")
    if "detail" in value:
        detail = value["detail"]
        if not isinstance(detail, str) or not detail:
            raise DashboardError(400, "invalid_missing", f"{field}.detail must be a nonempty string")
    return {"value": None, "reason": reason, **({"detail": value["detail"]} if "detail" in value else {})}


def _require_identifier(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise DashboardError(400, "invalid_identifier", f"{field} must be a str, not {type(value).__name__}")
    if not value or value != value.strip():
        raise DashboardError(400, "invalid_identifier", f"{field} must be a nonempty identifier without padding")
    if len(value) > 256:
        raise DashboardError(400, "invalid_identifier", f"{field} must be at most 256 characters")
    if "\x00" in value or any(ord(ch) < 0x20 for ch in value):
        raise DashboardError(400, "invalid_identifier", f"{field} must not contain control characters")
    return value


def _require_digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.match(value):
        raise DashboardError(400, "invalid_digest", f"{field} must be a sha256:<64 lowercase hex> digest")
    return value


def _require_int(value: Any, field: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise DashboardError(400, "invalid_number", f"{field} must be an int")
    if value < minimum:
        raise DashboardError(400, "invalid_number", f"{field} must be >= {minimum}")
    if value > 9007199254740991:
        raise DashboardError(400, "invalid_number", f"{field} exceeds safe-integer bounds")
    return value


def _require_bool(value: Any, field: str) -> bool:
    if type(value) is not bool:
        raise DashboardError(400, "invalid_boolean", f"{field} must be a bool")
    return value


def _require_nonempty_str(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise DashboardError(400, "invalid_string", f"{field} must be a nonempty string")
    if "\x00" in value or any(ord(ch) < 0x20 and ch not in ("\t", "\n") for ch in value):
        raise DashboardError(400, "invalid_string", f"{field} must not contain control characters")
    return value


def _error_bytes(err: DashboardError) -> bytes:
    payload: dict[str, Any] = {
        "http_status": err.http_status,
        "error": err.code,
        "message": err.message,
    }
    payload.update(err.extra)
    return _canonical_bytes(payload)


def _ok_bytes(http_status: int, payload: dict[str, Any]) -> bytes:
    body = {"http_status": http_status}
    body.update(payload)
    return _canonical_bytes(body)


# ---------------------------------------------------------------------------
# Snapshot validation
# ---------------------------------------------------------------------------


def _validate_input_prefix(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise DashboardError(400, "invalid_prefix", f"{field} must be a mapping")
    if set(value.keys()) != {"journal_id", "last_sequence", "head_hash"}:
        raise DashboardError(
            400, "invalid_prefix", f"{field} must contain exactly journal_id, last_sequence, head_hash"
        )
    return {
        "journal_id": _require_identifier(value["journal_id"], f"{field}.journal_id"),
        "last_sequence": _require_int(value["last_sequence"], f"{field}.last_sequence", minimum=1),
        "head_hash": _require_digest(value["head_hash"], f"{field}.head_hash"),
    }


def _validate_attempt(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise DashboardError(400, "invalid_attempt", "attempt must be a mapping")
    if set(value.keys()) != {"attempt_id", "kind", "target"}:
        raise DashboardError(400, "invalid_attempt", "attempt must contain exactly attempt_id, kind, target")
    kind = _require_identifier(value["kind"], "attempt.kind")
    if kind not in ATTEMPT_KINDS:
        raise DashboardError(400, "invalid_attempt", f"attempt.kind must be one of {sorted(ATTEMPT_KINDS)}")
    return {
        "attempt_id": _require_identifier(value["attempt_id"], "attempt.attempt_id"),
        "kind": kind,
        "target": _require_identifier(value["target"], "attempt.target"),
    }


def _validate_commission(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise DashboardError(400, "invalid_commission", "commission must be a mapping")
    if set(value.keys()) != {"commission_id", "job_id", "basis"}:
        raise DashboardError(
            400, "invalid_commission", "commission must contain exactly commission_id, job_id, basis"
        )
    return {
        "commission_id": _require_identifier(value["commission_id"], "commission.commission_id"),
        "job_id": _require_identifier(value["job_id"], "commission.job_id"),
        "basis": _require_nonempty_str(value["basis"], "commission.basis"),
    }


def _validate_known_versions(value: Any, field: str) -> dict[str, int]:
    if not isinstance(value, dict):
        raise DashboardError(400, "invalid_close_snapshot", f"{field} must be a mapping")
    if set(value.keys()) != set(REPORT_INPUT_AXES):
        raise DashboardError(
            400, "invalid_close_snapshot", f"{field} must contain exactly {list(REPORT_INPUT_AXES)}"
        )
    return {axis: _require_int(value[axis], f"{field}.{axis}", minimum=0) for axis in REPORT_INPUT_AXES}


def _validate_close_snapshot(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise DashboardError(400, "invalid_close_snapshot", f"{field} must be a mapping")
    allowed = {
        "closure_id",
        "known_versions",
        "execution_knowledge",
        "application_knowledge",
        "limitations",
        "boundary_ref",
        "execution_evidence_refs",
        "application_evidence_refs",
    }
    keys = set(value.keys())
    required = {"closure_id", "known_versions", "execution_knowledge", "application_knowledge", "limitations"}
    if not required <= keys:
        raise DashboardError(400, "invalid_close_snapshot", f"{field} is missing {sorted(required - keys)}")
    if keys - allowed:
        raise DashboardError(400, "invalid_close_snapshot", f"{field} has undeclared properties {sorted(keys - allowed)}")
    exec_knowledge = _require_identifier(value["execution_knowledge"], f"{field}.execution_knowledge")
    if exec_knowledge not in EXECUTION_KNOWLEDGE:
        raise DashboardError(400, "invalid_close_snapshot", f"{field}.execution_knowledge is unknown")
    app_knowledge = _require_identifier(value["application_knowledge"], f"{field}.application_knowledge")
    if app_knowledge not in APPLICATION_KNOWLEDGE:
        raise DashboardError(400, "invalid_close_snapshot", f"{field}.application_knowledge is unknown")
    limitations = value["limitations"]
    if not isinstance(limitations, list):
        raise DashboardError(400, "invalid_close_snapshot", f"{field}.limitations must be an array")
    for index, item in enumerate(limitations):
        _require_nonempty_str(item, f"{field}.limitations[{index}]")
    out: dict[str, Any] = {
        "closure_id": _require_identifier(value["closure_id"], f"{field}.closure_id"),
        "known_versions": _validate_known_versions(value["known_versions"], f"{field}.known_versions"),
        "execution_knowledge": exec_knowledge,
        "application_knowledge": app_knowledge,
        "limitations": list(limitations),
    }
    if "boundary_ref" in value:
        boundary = value["boundary_ref"]
        if _is_missing(boundary):
            out["boundary_ref"] = _validate_missing(boundary, f"{field}.boundary_ref")
        elif isinstance(boundary, dict):
            out["boundary_ref"] = dict(boundary)
        else:
            raise DashboardError(400, "invalid_close_snapshot", f"{field}.boundary_ref must be a mapping or Missing")
    if "execution_evidence_refs" in value:
        refs = value["execution_evidence_refs"]
        if not isinstance(refs, list):
            raise DashboardError(400, "invalid_close_snapshot", f"{field}.execution_evidence_refs must be an array")
        out["execution_evidence_refs"] = list(refs)
    if "application_evidence_refs" in value:
        refs = value["application_evidence_refs"]
        if not isinstance(refs, list):
            raise DashboardError(400, "invalid_close_snapshot", f"{field}.application_evidence_refs must be an array")
        out["application_evidence_refs"] = list(refs)
    return out


def _validate_record_digest(value: Any, revision: int, field: str) -> Any:
    if revision == 0:
        if not _is_missing(value):
            raise DashboardError(
                400, "invalid_axis", f"{field} must be a typed Missing envelope when revision is 0"
            )
        return _validate_missing(value, field)
    return _require_digest(value, field)


def _validate_str_or_missing(value: Any, field: str) -> Any:
    if _is_missing(value):
        return _validate_missing(value, field)
    return _require_identifier(value, field)


def _validate_axis_dispatch(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise DashboardError(400, "invalid_axis", "axes.dispatch must be a mapping")
    if set(value.keys()) != {"revision", "record_digest", "state"}:
        raise DashboardError(400, "invalid_axis", "axes.dispatch must contain exactly revision, record_digest, state")
    revision = _require_int(value["revision"], "axes.dispatch.revision", minimum=0)
    digest = _validate_record_digest(value["record_digest"], revision, "axes.dispatch.record_digest")
    state = _validate_str_or_missing(value["state"], "axes.dispatch.state")
    if revision == 0 and not _is_missing(value["state"]):
        raise DashboardError(400, "invalid_axis", "axes.dispatch.state must be Missing when revision is 0")
    return {"revision": revision, "record_digest": digest, "state": state}


def _validate_axis_observation(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise DashboardError(400, "invalid_axis", "axes.observation must be a mapping")
    if set(value.keys()) != {"revision", "record_digest", "closed", "close_snapshot"}:
        raise DashboardError(
            400, "invalid_axis", "axes.observation must contain exactly revision, record_digest, closed, close_snapshot"
        )
    revision = _require_int(value["revision"], "axes.observation.revision", minimum=0)
    digest = _validate_record_digest(value["record_digest"], revision, "axes.observation.record_digest")
    closed = _require_bool(value["closed"], "axes.observation.closed")
    raw_close = value["close_snapshot"]
    if closed:
        if _is_missing(raw_close):
            raise DashboardError(
                400, "invalid_axis", "axes.observation.close_snapshot must be a CloseSnapshot when closed"
            )
        close_snapshot = _validate_close_snapshot(raw_close, "axes.observation.close_snapshot")
    else:
        if not _is_missing(raw_close):
            raise DashboardError(
                400, "invalid_axis", "axes.observation.close_snapshot must be Missing when not closed"
            )
        close_snapshot = _validate_missing(raw_close, "axes.observation.close_snapshot")
    if revision == 0:
        if closed:
            raise DashboardError(400, "invalid_axis", "axes.observation cannot be closed when revision is 0")
    return {"revision": revision, "record_digest": digest, "closed": closed, "close_snapshot": close_snapshot}


def _validate_claim(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise DashboardError(400, "invalid_claim", f"{field} must be a mapping")
    if "claim_id" not in value:
        raise DashboardError(400, "invalid_claim", f"{field} is missing claim_id")
    claim_id = _require_identifier(value["claim_id"], f"{field}.claim_id")
    out = dict(value)
    out["claim_id"] = claim_id
    if "state" in value:
        out["state"] = _validate_str_or_missing(value["state"], f"{field}.state")
    return out


def _validate_axis_execution(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise DashboardError(400, "invalid_axis", "axes.execution must be a mapping")
    if set(value.keys()) != {"revision", "record_digest", "claims"}:
        raise DashboardError(400, "invalid_axis", "axes.execution must contain exactly revision, record_digest, claims")
    revision = _require_int(value["revision"], "axes.execution.revision", minimum=0)
    digest = _validate_record_digest(value["record_digest"], revision, "axes.execution.record_digest")
    claims = value["claims"]
    if not isinstance(claims, list):
        raise DashboardError(400, "invalid_axis", "axes.execution.claims must be an array")
    if revision == 0 and claims:
        raise DashboardError(400, "invalid_axis", "axes.execution.claims must be empty when revision is 0")
    return {
        "revision": revision,
        "record_digest": digest,
        "claims": [_validate_claim(item, f"axes.execution.claims[{i}]") for i, item in enumerate(claims)],
    }


def _validate_fact(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise DashboardError(400, "invalid_fact", f"{field} must be a mapping")
    for required in ("fact_id", "revision", "state", "coverage"):
        if required not in value:
            raise DashboardError(400, "invalid_fact", f"{field} is missing {required}")
    fact_id = _require_identifier(value["fact_id"], f"{field}.fact_id")
    revision = _require_int(value["revision"], f"{field}.revision", minimum=1)
    state = _require_identifier(value["state"], f"{field}.state")
    if state not in FACT_STATES:
        raise DashboardError(400, "invalid_fact", f"{field}.state must be committed or not_committed")
    coverage = _require_identifier(value["coverage"], f"{field}.coverage")
    if coverage not in FACT_COVERAGE:
        raise DashboardError(400, "invalid_fact", f"{field}.coverage must be at_boundary or final_for_attempt")
    out = dict(value)
    out["fact_id"] = fact_id
    out["revision"] = revision
    out["state"] = state
    out["coverage"] = coverage
    return out


def _validate_axis_application(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise DashboardError(400, "invalid_axis", "axes.application must be a mapping")
    if set(value.keys()) != {"revision", "record_digest", "facts"}:
        raise DashboardError(400, "invalid_axis", "axes.application must contain exactly revision, record_digest, facts")
    revision = _require_int(value["revision"], "axes.application.revision", minimum=0)
    digest = _validate_record_digest(value["record_digest"], revision, "axes.application.record_digest")
    facts = value["facts"]
    if not isinstance(facts, list):
        raise DashboardError(400, "invalid_axis", "axes.application.facts must be an array")
    if revision == 0 and facts:
        raise DashboardError(400, "invalid_axis", "axes.application.facts must be empty when revision is 0")
    validated = [_validate_fact(item, f"axes.application.facts[{i}]") for i, item in enumerate(facts)]
    if validated:
        highest = max(item["revision"] for item in validated)
        if highest > revision:
            raise DashboardError(
                400, "invalid_axis", "axes.application.facts contain a revision newer than the slot revision"
            )
    return {"revision": revision, "record_digest": digest, "facts": validated}


def _validate_report_pin(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise DashboardError(400, "invalid_report", f"{field} must be a mapping")
    if set(value.keys()) != {"revision", "record_digest"}:
        raise DashboardError(400, "invalid_report", f"{field} must contain exactly revision, record_digest")
    revision = _require_int(value["revision"], f"{field}.revision", minimum=0)
    if revision == 0:
        if not _is_missing(value["record_digest"]):
            raise DashboardError(400, "invalid_report", f"{field}.record_digest must be Missing when revision is 0")
        digest: Any = _validate_missing(value["record_digest"], f"{field}.record_digest")
    else:
        digest = _require_digest(value["record_digest"], f"{field}.record_digest")
    return {"revision": revision, "record_digest": digest}


def _validate_axis_report(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise DashboardError(400, "invalid_axis", "axes.report must be a mapping")
    allowed = {"revision", "record_digest", "state", "coverage", "inputs", "issues", "limitations"}
    keys = set(value.keys())
    required = {"revision", "record_digest", "state", "coverage", "inputs"}
    if not required <= keys:
        raise DashboardError(400, "invalid_axis", f"axes.report is missing {sorted(required - keys)}")
    if keys - allowed:
        raise DashboardError(400, "invalid_axis", f"axes.report has undeclared properties {sorted(keys - allowed)}")
    revision = _require_int(value["revision"], "axes.report.revision", minimum=0)
    digest = _validate_record_digest(value["record_digest"], revision, "axes.report.record_digest")
    state = _validate_str_or_missing(value["state"], "axes.report.state")
    coverage = _validate_str_or_missing(value["coverage"], "axes.report.coverage")
    if revision == 0:
        if not _is_missing(value["state"]) or not _is_missing(value["coverage"]):
            raise DashboardError(400, "invalid_axis", "axes.report.state/coverage must be Missing when revision is 0")
    inputs = value["inputs"]
    if not isinstance(inputs, dict) or set(inputs.keys()) != set(REPORT_INPUT_AXES):
        raise DashboardError(
            400, "invalid_report", f"axes.report.inputs must contain exactly {list(REPORT_INPUT_AXES)}"
        )
    validated_inputs = {
        axis: _validate_report_pin(inputs[axis], f"axes.report.inputs.{axis}") for axis in REPORT_INPUT_AXES
    }
    out: dict[str, Any] = {
        "revision": revision,
        "record_digest": digest,
        "state": state,
        "coverage": coverage,
        "inputs": validated_inputs,
    }
    if "issues" in value:
        issues = value["issues"]
        if not isinstance(issues, list):
            raise DashboardError(400, "invalid_report", "axes.report.issues must be an array")
        validated_issues = []
        for index, item in enumerate(issues):
            if not isinstance(item, dict) or "kind" not in item:
                raise DashboardError(400, "invalid_report", f"axes.report.issues[{index}] must have kind")
            kind = _require_identifier(item["kind"], f"axes.report.issues[{index}].kind")
            entry = dict(item)
            entry["kind"] = kind
            validated_issues.append(entry)
        out["issues"] = validated_issues
    else:
        out["issues"] = []
    if "limitations" in value:
        limitations = value["limitations"]
        if not isinstance(limitations, list):
            raise DashboardError(400, "invalid_report", "axes.report.limitations must be an array")
        for index, item in enumerate(limitations):
            _require_nonempty_str(item, f"axes.report.limitations[{index}]")
        out["limitations"] = list(limitations)
    else:
        out["limitations"] = []
    return out


def _validate_axes(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise DashboardError(400, "invalid_axes", "axes must be a mapping")
    if set(value.keys()) != set(AXES):
        raise DashboardError(400, "invalid_axes", f"axes must contain every declared slot {list(AXES)}")
    return {
        "dispatch": _validate_axis_dispatch(value["dispatch"]),
        "observation": _validate_axis_observation(value["observation"]),
        "execution": _validate_axis_execution(value["execution"]),
        "application": _validate_axis_application(value["application"]),
        "report": _validate_axis_report(value["report"]),
    }


def _validate_seal_point(value: Any, axes: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise DashboardError(400, "invalid_seal", "seal_point must be a mapping")
    if set(value.keys()) != {"seal_id", "name", "versions"}:
        raise DashboardError(400, "invalid_seal", "seal_point must contain exactly seal_id, name, versions")
    seal_id = _require_identifier(value["seal_id"], "seal_point.seal_id")
    name = _require_identifier(value["name"], "seal_point.name")
    if name not in SEAL_NAMES:
        raise DashboardError(400, "invalid_seal", f"seal_point.name must be one of {sorted(SEAL_NAMES)}")
    versions = value["versions"]
    if not isinstance(versions, dict) or set(versions.keys()) != set(AXES):
        raise DashboardError(400, "invalid_seal", f"seal_point.versions must contain every axis {list(AXES)}")
    normalized = {axis: _require_int(versions[axis], f"seal_point.versions.{axis}", minimum=0) for axis in AXES}
    for axis in AXES:
        if normalized[axis] != axes[axis]["revision"]:
            raise DashboardError(
                400, "invalid_seal", "seal vector must exactly equal the domain slot revisions"
            )
    if name == "observation_closed" and not axes["observation"]["closed"]:
        raise DashboardError(400, "invalid_seal", "a closed seal requires closed observation")
    return {"seal_id": seal_id, "name": name, "versions": normalized}


def _validate_job_ref(value: Any) -> Any:
    if _is_missing(value):
        return _validate_missing(value, "job_ref")
    if not isinstance(value, dict):
        raise DashboardError(400, "invalid_job_ref", "job_ref must be a mapping or Missing")
    if set(value.keys()) != {"entity", "view_id"}:
        raise DashboardError(400, "invalid_job_ref", "job_ref must contain exactly entity, view_id")
    entity = value["entity"]
    if not isinstance(entity, dict) or set(entity.keys()) != {"entity_type", "target", "job_id"}:
        raise DashboardError(400, "invalid_job_ref", "job_ref.entity must be a JobEntityKey")
    if entity["entity_type"] != "job":
        raise DashboardError(400, "invalid_job_ref", "job_ref.entity.entity_type must be 'job'")
    normalized_entity = {
        "entity_type": "job",
        "target": _require_identifier(entity["target"], "job_ref.entity.target"),
        "job_id": _require_identifier(entity["job_id"], "job_ref.entity.job_id"),
    }
    return {"entity": normalized_entity, "view_id": _require_identifier(value["view_id"], "job_ref.view_id")}


def _validate_snapshot(obj: dict[str, Any]) -> dict[str, Any]:
    allowed = {
        "record_type",
        "schema_version",
        "attempt",
        "commission",
        "commission_digest",
        "input_prefix",
        "axes",
        "seal_point",
        "job_ref",
        "issues",
        "limitations",
    }
    keys = set(obj.keys())
    required = {
        "record_type",
        "schema_version",
        "attempt",
        "commission",
        "commission_digest",
        "input_prefix",
        "axes",
        "seal_point",
    }
    if not required <= keys:
        raise DashboardError(400, "invalid_snapshot", f"snapshot is missing {sorted(required - keys)}")
    if keys - allowed:
        raise DashboardError(400, "invalid_snapshot", f"snapshot has undeclared properties {sorted(keys - allowed)}")
    if obj["record_type"] != RECORD_TYPE:
        raise DashboardError(400, "invalid_snapshot", f"record_type must be {RECORD_TYPE!r}")
    if obj["schema_version"] != SCHEMA_VERSION:
        raise DashboardError(400, "invalid_snapshot", f"schema_version must be {SCHEMA_VERSION!r}")
    axes = _validate_axes(obj["axes"])
    out: dict[str, Any] = {
        "record_type": RECORD_TYPE,
        "schema_version": SCHEMA_VERSION,
        "attempt": _validate_attempt(obj["attempt"]),
        "commission": _validate_commission(obj["commission"]),
        "commission_digest": _require_digest(obj["commission_digest"], "commission_digest"),
        "input_prefix": _validate_input_prefix(obj["input_prefix"], "input_prefix"),
        "axes": axes,
        "seal_point": _validate_seal_point(obj["seal_point"], axes),
    }
    if "job_ref" in obj:
        out["job_ref"] = _validate_job_ref(obj["job_ref"])
    else:
        out["job_ref"] = _missing("not_observed", "no job row is pinned for this attempt snapshot")
    if "issues" in obj:
        issues = obj["issues"]
        if not isinstance(issues, list):
            raise DashboardError(400, "invalid_snapshot", "issues must be an array")
        validated = []
        for index, item in enumerate(issues):
            if not isinstance(item, dict) or "kind" not in item:
                raise DashboardError(400, "invalid_snapshot", f"issues[{index}] must have kind")
            kind = _require_identifier(item["kind"], f"issues[{index}].kind")
            entry = dict(item)
            entry["kind"] = kind
            validated.append(entry)
        out["issues"] = validated
    else:
        out["issues"] = []
    if "limitations" in obj:
        limitations = obj["limitations"]
        if not isinstance(limitations, list):
            raise DashboardError(400, "invalid_snapshot", "limitations must be an array")
        for index, item in enumerate(limitations):
            _require_nonempty_str(item, f"limitations[{index}]")
        out["limitations"] = list(limitations)
    else:
        out["limitations"] = []
    # Report pins must not name revisions newer than the current slots.
    report = axes["report"]
    if report["revision"] > 0:
        for axis in REPORT_INPUT_AXES:
            pinned = report["inputs"][axis]["revision"]
            current = axes[axis]["revision"]
            if pinned > current:
                raise DashboardError(
                    400, "invalid_report", f"report input pin for {axis} names a revision newer than the current slot"
                )
    return out


# ---------------------------------------------------------------------------
# Staleness + close-time separation
# ---------------------------------------------------------------------------


def _report_staleness(snapshot: dict[str, Any]) -> dict[str, Any]:
    axes = snapshot["axes"]
    report = axes["report"]
    current_versions = {axis: axes[axis]["revision"] for axis in REPORT_INPUT_AXES}
    if report["revision"] == 0:
        return {
            "report_present": False,
            "report_stale": False,
            "stale_axes": [],
            "current_versions": current_versions,
            "report_inputs": {
                axis: dict(report["inputs"][axis]) for axis in REPORT_INPUT_AXES
            },
            "detail": "no report has been published; staleness does not apply",
        }
    stale: list[str] = []
    for axis in REPORT_INPUT_AXES:
        pinned_revision = report["inputs"][axis]["revision"]
        if current_versions[axis] > pinned_revision:
            stale.append(axis)
            continue
        if current_versions[axis] == pinned_revision and pinned_revision > 0:
            current_digest = axes[axis]["record_digest"]
            pinned_digest = report["inputs"][axis]["record_digest"]
            if isinstance(current_digest, str) and isinstance(pinned_digest, str):
                if current_digest != pinned_digest:
                    stale.append(axis)
    stale_sorted = sorted(stale)
    return {
        "report_present": True,
        "report_stale": bool(stale_sorted),
        "stale_axes": stale_sorted,
        "current_versions": current_versions,
        "report_inputs": {axis: dict(report["inputs"][axis]) for axis in REPORT_INPUT_AXES},
        "detail": (
            "report inputs are current; no axis has advanced past the pinned revisions"
            if not stale_sorted
            else f"report is stale: {', '.join(stale_sorted)} advanced past the pinned input revisions"
        ),
    }


def _close_time_split(snapshot: dict[str, Any]) -> dict[str, Any]:
    observation = snapshot["axes"]["observation"]
    application = snapshot["axes"]["application"]
    facts = list(application["facts"])
    if not observation["closed"] or _is_missing(observation["close_snapshot"]):
        return {
            "close_applicable": False,
            "close_time_knowledge": _missing(
                "not_observed", "observation has not closed; no close-time knowledge exists yet"
            ),
            "at_close_facts": [],
            "later_facts": [],
            "close_preserved": True,
            "detail": "observation is not closed; every application fact is current knowledge, not later-than-close",
        }
    close_snapshot = observation["close_snapshot"]
    known = close_snapshot["known_versions"]
    known_application = known["application"]
    at_close = [fact for fact in facts if fact["revision"] <= known_application]
    later = [fact for fact in facts if fact["revision"] > known_application]
    return {
        "close_applicable": True,
        "close_time_knowledge": {
            "closure_id": close_snapshot["closure_id"],
            "known_versions": dict(known),
            "execution_knowledge": close_snapshot["execution_knowledge"],
            "application_knowledge": close_snapshot["application_knowledge"],
            "limitations": list(close_snapshot["limitations"]),
        },
        "at_close_facts": at_close,
        "later_facts": later,
        "close_preserved": True,
        "detail": (
            "close-time knowledge is preserved exactly as observed at the boundary; "
            f"{len(at_close)} fact(s) at or before close, {len(later)} later fact(s)"
        ),
    }


def _collect_missing_evidence(snapshot: dict[str, Any], job_section: Any) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    axes = snapshot["axes"]
    for axis in AXES:
        slot = axes[axis]
        if slot["revision"] == 0:
            reason = slot["record_digest"].get("reason", "not_observed") if isinstance(slot["record_digest"], dict) else "not_observed"
            found.append(
                {
                    "location": f"axes.{axis}",
                    "missing": _missing(reason, f"axis {axis} has no publication in this view"),
                }
            )
    report = axes["report"]
    if _is_missing(report["state"]):
        found.append({"location": "axes.report.state", "missing": dict(report["state"])})
    if _is_missing(report["coverage"]):
        found.append({"location": "axes.report.coverage", "missing": dict(report["coverage"])})
    if _is_missing(job_section):
        found.append({"location": "job_row", "missing": dict(job_section)})
    return found


def _build_projection(
    snapshot: dict[str, Any], job_section: Any, integrity_notes: list[dict[str, Any]]
) -> dict[str, Any]:
    staleness = _report_staleness(snapshot)
    close_split = _close_time_split(snapshot)
    report = snapshot["axes"]["report"]
    issues: list[dict[str, Any]] = []
    issues.extend(list(snapshot.get("issues", [])))
    issues.extend(list(report.get("issues", [])))
    if staleness["report_stale"]:
        issues.append(
            {
                "kind": "stale_report",
                "detail": staleness["detail"],
                "stale_axes": list(staleness["stale_axes"]),
            }
        )
    issues.extend(list(integrity_notes))
    limitations: list[str] = []
    limitations.extend(list(snapshot.get("limitations", [])))
    limitations.extend(list(report.get("limitations", [])))
    if close_split["close_applicable"]:
        limitations.extend(list(close_split["close_time_knowledge"]["limitations"]))
    missing_evidence = _collect_missing_evidence(snapshot, job_section)
    return {
        "record_type": PROJECTION_RECORD_TYPE,
        "schema_version": SCHEMA_VERSION,
        "attempt": dict(snapshot["attempt"]),
        "commission": dict(snapshot["commission"]),
        "commission_digest": snapshot["commission_digest"],
        "input_prefix": dict(snapshot["input_prefix"]),
        "axes": {axis: snapshot["axes"][axis] for axis in AXES},
        "seal_point": dict(snapshot["seal_point"]),
        "job_row": job_section,
        "close_time": close_split,
        "report": {
            "revision": report["revision"],
            "record_digest": report["record_digest"],
            "state": report["state"],
            "coverage": report["coverage"],
            "inputs": {axis: dict(report["inputs"][axis]) for axis in REPORT_INPUT_AXES},
            "current_versions": dict(staleness["current_versions"]),
            "report_present": staleness["report_present"],
            "report_stale": staleness["report_stale"],
            "stale_axes": list(staleness["stale_axes"]),
            "detail": staleness["detail"],
        },
        "missing_evidence": missing_evidence,
        "issues": issues,
        "limitations": limitations,
        "projection_notes": {
            "authoritative": False,
            "cache": "dashboard_projection",
            "effect_claim": _missing(
                "not_observed",
                "dashboard projection records presentation only; no external effect is claimed",
            ),
        },
    }


# ---------------------------------------------------------------------------
# Command + path policy
# ---------------------------------------------------------------------------


def _is_forbidden_command(command: str) -> bool:
    normalized = command.strip().lower()
    if normalized in _FORBIDDEN_COMMAND_EXACT:
        return True
    if "status" in normalized:
        return True
    for token in ("replace_row", "replace-row", "whole_row", "mutate_owner", "write_owner", "set_owner"):
        if token in normalized:
            return True
    return False


def _is_forbidden_path(path: str) -> bool:
    lowered = path.lower()
    for token in _FORBIDDEN_PATH_SUBSTRINGS:
        if token in lowered:
            return True
    return False


def _forbidden_status_bytes(path: str, command: str | None = None) -> bytes:
    if command is None:
        detail = (
            f"dashboard path {path!r} names a generic scalar-status or row-replacement write; "
            "no such endpoint exists and the mutation is rejected"
        )
    else:
        detail = (
            f"dashboard command {command!r} is a generic scalar application-status mutation; "
            "no generic set-status write exists and the mutation is rejected"
        )
    return _ok_bytes(
        403,
        {
            "error": "forbidden_status_mutation",
            "message": "scalar application-status mutation is rejected; no generic set-status write exists",
            "detail": detail,
            "effect_claim": _missing(
                "not_observed", "rejected command claimed no effect and journaled nothing"
            ),
        },
    )


# ---------------------------------------------------------------------------
# Endpoint handlers
# ---------------------------------------------------------------------------


def _handle_snapshot_ingest(channel_id: str, projection: dict[str, Any], body: bytes) -> bytes:
    grants = list(projection.get("grants", []))
    if not grants:
        raise DashboardError(
            403, "forbidden", "authenticated channel holds no write grant for dashboard snapshot ingest"
        )
    snapshot_raw = _strict_parse_body(body, "snapshot")
    snapshot = _validate_snapshot(snapshot_raw)
    attempt_id = snapshot["attempt"]["attempt_id"]
    content = _canonical_bytes(snapshot)
    owner_domain = projection["axis"]
    if not isinstance(owner_domain, str) or not owner_domain:
        raise DashboardError(403, "forbidden", "channel has no owner axis for snapshot retention")
    try:
        ref = artifact_store.retain_artifact(channel_id, owner_domain, "application/json", content, "public")
    except Exception as exc:  # map sibling errors to HTTP JSON
        if isinstance(exc, PermissionError):
            raise DashboardError(403, "forbidden", f"snapshot retention denied: {exc}") from exc
        if isinstance(exc, (ValueError, TypeError)):
            raise DashboardError(400, "retention_failed", f"snapshot retention failed: {exc}") from exc
        raise DashboardError(500, "retention_failed", f"snapshot retention failed: {exc}") from exc
    with _LOCK:
        _SNAPSHOTS[attempt_id] = ref
    try:
        ref_dict = ref.to_dict()
    except Exception:
        ref_dict = {"digest": getattr(ref, "digest", ""), "size_bytes": len(content)}
    staleness = _report_staleness(snapshot)
    close_split = _close_time_split(snapshot)
    return _ok_bytes(
        201,
        {
            "stored": True,
            "attempt_id": attempt_id,
            "artifact": ref_dict,
            "report_present": staleness["report_present"],
            "report_stale": staleness["report_stale"],
            "stale_axes": staleness["stale_axes"],
            "close_applicable": close_split["close_applicable"],
            "projection_notes": {
                "authoritative": False,
                "cache": "dashboard_projection",
                "effect_claim": _missing(
                    "not_observed",
                    "snapshot ingest stores a dashboard projection only; no workflow effect is claimed",
                ),
            },
        },
    )


def _load_job_section(channel_id: str, snapshot: dict[str, Any]) -> tuple[Any, list[dict[str, Any]]]:
    notes: list[dict[str, Any]] = []
    job_ref = snapshot.get("job_ref")
    if job_ref is None or _is_missing(job_ref):
        if _is_missing(job_ref):
            return dict(job_ref), notes
        return _missing("not_observed", "no job row is pinned for this attempt snapshot"), notes
    entity = job_ref["entity"]
    view_id = job_ref["view_id"]
    try:
        row = read_publications.load_row(channel_id, dict(entity), view_id)
    except Exception as exc:
        name = type(exc).__name__
        message = str(exc) or name
        if "NotFound" in name:
            missing = _missing("not_observed", f"no sealed row for this entity in view {view_id!r}: {message[:200]}")
        elif "Lost" in name or "Integrity" in name or "Unavailable" in name:
            missing = _missing("observation_lost", f"job row bytes are unavailable or failed verification: {message[:200]}")
            notes.append({"kind": "integrity_issue", "detail": f"job row load failed: {message[:300]}"})
        elif isinstance(exc, PermissionError):
            missing = _missing("not_observed", f"channel is not authorized to load this job row: {message[:200]}")
        elif "publisher" in message.lower() or "read_view_publisher" in message:
            missing = _missing(
                "not_observed",
                f"job row requires a read_view_publisher channel for view {view_id!r}; caller cannot load it",
            )
        else:
            missing = _missing("not_observed", f"job row could not be loaded: {message[:200]}")
        return missing, notes
    try:
        row_dict = row.to_dict()
    except Exception as exc:
        return _missing("observation_lost", f"sealed row root is invalid: {exc}"), notes
    try:
        domains = row_dict.get("domains", {})
        crawler = domains.get("crawler", {})
        downstream = domains.get("downstream", {})
        section = {
            "entity": dict(row_dict.get("entity", entity)),
            "view_id": view_id,
            "registration_digest": row_dict.get("registration_digest", ""),
            "crawler_revision": crawler.get("revision", 0),
            "crawler_digest": (crawler.get("document", {}) or {}).get("digest", "")
            if isinstance(crawler.get("document"), dict)
            else "",
            "crawler_value": crawler.get("snapshot", {}).get("value", {})
            if isinstance(crawler.get("snapshot"), dict)
            else {},
            "downstream_revision": downstream.get("revision", 0),
            "downstream_digest": (downstream.get("document", {}) or {}).get("digest", "")
            if isinstance(downstream.get("document"), dict)
            else "",
            "downstream_value": downstream.get("snapshot", {}).get("value", {})
            if isinstance(downstream.get("snapshot"), dict)
            else {},
            "seal_point": row_dict.get("seal_point", {}),
        }
    except Exception as exc:
        return _missing("observation_lost", f"sealed row projection failed: {exc}"), notes
    return section, notes


def _handle_attempt_get(channel_id: str, attempt_id: str) -> bytes:
    attempt_id = attempt_id.strip()
    if not attempt_id:
        raise DashboardError(400, "invalid_attempt_id", "attempt id must be a nonempty identifier")
    with _LOCK:
        ref = _SNAPSHOTS.get(attempt_id)
    if ref is None:
        raise DashboardError(
            404,
            "attempt_not_found",
            f"no dashboard snapshot is stored for attempt {attempt_id!r}",
            extra={"missing": _missing("not_observed", f"attempt {attempt_id!r} has no dashboard projection")},
        )
    try:
        raw = artifact_store.resolve_artifact(channel_id, ref)
    except Exception as exc:
        if exc.__class__.__name__ == "ArtifactLostError":
            missing = getattr(exc, "missing", None) or _missing(
                "observation_lost", f"retained snapshot bytes for {attempt_id!r} are unavailable"
            )
            digest = getattr(exc, "digest", getattr(ref, "digest", ""))
            return _ok_bytes(
                502,
                {
                    "error": "snapshot_lost",
                    "message": "dashboard snapshot bytes are unavailable; loss is an integrity incident",
                    "attempt_id": attempt_id,
                    "digest": digest,
                    "missing": dict(missing) if isinstance(missing, dict) else missing,
                    "issues": [
                        {"kind": "integrity_issue", "detail": f"snapshot bytes lost for {attempt_id!r}"}
                    ],
                    "effect_claim": _missing(
                        "not_observed", "lost snapshot claims no projection and no external effect"
                    ),
                },
            )
        if exc.__class__.__name__ == "ArtifactUnavailableError":
            missing = getattr(exc, "missing", None) or _missing("not_observed", "snapshot bytes were never retained")
            return _ok_bytes(
                404,
                {
                    "error": "snapshot_unavailable",
                    "message": "dashboard snapshot bytes were never retained",
                    "attempt_id": attempt_id,
                    "missing": dict(missing) if isinstance(missing, dict) else missing,
                },
            )
        if isinstance(exc, PermissionError):
            raise DashboardError(403, "forbidden", f"snapshot resolution denied: {exc}") from exc
        raise DashboardError(500, "resolution_failed", f"snapshot resolution failed: {exc}") from exc
    try:
        snapshot_obj = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_object)
    except (UnicodeDecodeError, ValueError) as exc:
        raise DashboardError(500, "snapshot_corrupt", f"stored snapshot bytes are not valid JSON: {exc}") from exc
    if not isinstance(snapshot_obj, dict):
        raise DashboardError(500, "snapshot_corrupt", "stored snapshot bytes are not a JSON object")
    try:
        snapshot = _validate_snapshot(snapshot_obj)
    except DashboardError as exc:
        raise DashboardError(500, "snapshot_corrupt", f"stored snapshot failed validation: {exc.message}") from exc
    job_section, integrity_notes = _load_job_section(channel_id, snapshot)
    projection = _build_projection(snapshot, job_section, integrity_notes)
    return _ok_bytes(200, {"attempt_id": attempt_id, "projection": projection})


def _handle_row_get(channel_id: str, query: dict[str, list[str]], segments: list[str]) -> bytes:
    view_id: str | None = None
    target: str | None = None
    job_id: str | None = None
    if len(segments) >= 5:
        # /dashboard/rows/<view_id>/<target>/<job_id>
        _, _, _, view_id, *rest = segments
        if len(rest) >= 2:
            target, job_id = rest[0], rest[1]
    if view_id is None:
        view_id = (query.get("view_id") or [None])[0]
    if target is None:
        target = (query.get("target") or [None])[0]
    if job_id is None:
        job_id = (query.get("job_id") or [None])[0]
    if not view_id or not target or not job_id:
        raise DashboardError(
            400,
            "invalid_row_request",
            "row request requires view_id, target, and job_id in path or query",
        )
    try:
        _require_identifier(view_id, "view_id")
        _require_identifier(target, "target")
        _require_identifier(job_id, "job_id")
    except DashboardError as exc:
        raise DashboardError(400, exc.code, exc.message) from exc
    entity = {"entity_type": "job", "target": target, "job_id": job_id}
    try:
        row = read_publications.load_row(channel_id, dict(entity), view_id)
    except Exception as exc:
        name = type(exc).__name__
        message = str(exc) or name
        if "NotFound" in name:
            raise DashboardError(
                404, "row_not_found", f"no sealed row for job {job_id!r} in view {view_id!r}",
                extra={"missing": _missing("not_observed", message[:300])},
            ) from exc
        if isinstance(exc, PermissionError):
            raise DashboardError(403, "forbidden", f"row load denied: {message[:300]}") from exc
        raise DashboardError(409, "row_unavailable", f"job row could not be loaded: {message[:300]}") from exc
    try:
        row_dict = row.to_dict()
    except Exception as exc:
        raise DashboardError(500, "row_corrupt", f"sealed row root is invalid: {exc}") from exc
    domains = row_dict.get("domains", {})
    crawler = domains.get("crawler", {}) if isinstance(domains, dict) else {}
    downstream = domains.get("downstream", {}) if isinstance(domains, dict) else {}
    projection = {
        "record_type": PROJECTION_RECORD_TYPE,
        "schema_version": SCHEMA_VERSION,
        "entity": dict(entity),
        "view_id": view_id,
        "registration_digest": row_dict.get("registration_digest", ""),
        "crawler_revision": crawler.get("revision", 0) if isinstance(crawler, dict) else 0,
        "crawler_value": crawler.get("snapshot", {}).get("value", {}) if isinstance(crawler.get("snapshot"), dict) else {},
        "downstream_revision": downstream.get("revision", 0) if isinstance(downstream, dict) else 0,
        "downstream_value": downstream.get("snapshot", {}).get("value", {})
        if isinstance(downstream.get("snapshot"), dict)
        else {},
        "seal_point": row_dict.get("seal_point", {}),
        "projection_notes": {
            "authoritative": False,
            "cache": "dashboard_projection",
            "effect_claim": _missing(
                "not_observed", "dashboard row projection records presentation only"
            ),
        },
    }
    return _ok_bytes(200, {"projection": projection})


def _handle_command_post(channel_id: str, projection: dict[str, Any], body: bytes) -> bytes:
    cmd_raw = _strict_parse_body(body, "command")
    allowed_top = {
        "command",
        "resource_id",
        "producer_sequence",
        "event_kind",
        "event_schema_version",
        "occurred_at",
        "payload_data",
    }
    keys = set(cmd_raw.keys())
    required = {"command", "resource_id", "producer_sequence", "event_kind", "event_schema_version", "occurred_at"}
    if not required <= keys:
        raise DashboardError(400, "invalid_command", f"command is missing {sorted(required - keys)}")
    if keys - allowed_top:
        raise DashboardError(400, "invalid_command", f"command has undeclared properties {sorted(keys - allowed_top)}")
    command = cmd_raw["command"]
    resource_id = cmd_raw["resource_id"]
    if not isinstance(command, str) or not command:
        raise DashboardError(400, "invalid_command", "command must be a nonempty string")
    command = _require_identifier(command, "command")
    resource_id = _require_identifier(resource_id, "resource_id")
    if _is_forbidden_command(command):
        return _forbidden_status_bytes("/dashboard/commands", command)
    if command not in ALLOWED_COMMANDS:
        return _ok_bytes(
            403,
            {
                "error": "unknown_command",
                "message": f"dashboard command {command!r} is not an authorized operation and is rejected",
                "detail": f"authorized commands are exactly {sorted(ALLOWED_COMMANDS)}; no multi-axis or whole-attempt command exists",
                "effect_claim": _missing("not_observed", "rejected command claimed no effect and journaled nothing"),
            },
        )
    event_kind = _require_identifier(cmd_raw["event_kind"], "event_kind")
    event_schema_version = _require_identifier(cmd_raw["event_schema_version"], "event_schema_version")
    producer_sequence = cmd_raw["producer_sequence"]
    if _is_missing(producer_sequence):
        producer_sequence = _validate_missing(producer_sequence, "producer_sequence")
    elif isinstance(producer_sequence, bool) or not isinstance(producer_sequence, int) or producer_sequence < 1:
        raise DashboardError(400, "invalid_command", "producer_sequence must be a positive integer or Missing")
    occurred_at = cmd_raw["occurred_at"]
    if _is_missing(occurred_at):
        occurred_at = _validate_missing(occurred_at, "occurred_at")
    elif not isinstance(occurred_at, dict):
        raise DashboardError(400, "invalid_command", "occurred_at must be a TimePoint mapping or Missing")
    else:
        occurred_at = dict(occurred_at)
    payload_data: dict[str, Any] = {}
    if "payload_data" in cmd_raw:
        if not isinstance(cmd_raw["payload_data"], dict):
            raise DashboardError(400, "invalid_command", "payload_data must be a mapping")
        payload_data = dict(cmd_raw["payload_data"])
        for reserved in ("command", "resource_id", "effect_claim"):
            if reserved in payload_data:
                raise DashboardError(
                    400, "invalid_command", f"payload_data must not override reserved field {reserved!r}"
                )
    grants = list(projection.get("grants", []))
    if not grants:
        raise DashboardError(403, "forbidden", "authenticated channel holds no write grant for dashboard commands")
    try:
        access_policy.authorize(channel_id, grants[0], resource_id)
    except Exception as exc:
        if isinstance(exc, PermissionError):
            raise DashboardError(403, "forbidden", f"dashboard command denied: {exc}") from exc
        if isinstance(exc, (ValueError, TypeError)):
            raise DashboardError(400, "invalid_command", f"dashboard command authorization failed: {exc}") from exc
        raise DashboardError(500, "authorization_failed", f"authorization failed: {exc}") from exc
    owner_domain = projection.get("axis")
    if not isinstance(owner_domain, str) or not owner_domain:
        raise DashboardError(403, "forbidden", "channel has no owner axis for command journaling")
    payload_data_full: dict[str, Any] = {
        "command": command,
        "resource_id": resource_id,
    }
    payload_data_full.update(payload_data)
    payload_data_full["effect_claim"] = _missing(
        "not_observed",
        "dashboard command records intent only; no external effect is claimed until separately authorized handling",
    )
    submission_payload: dict[str, Any] = {
        "data": payload_data_full,
        "measurements": [],
        "evidence_refs": [],
        "artifact_refs": [],
    }
    try:
        submission = evidence_journal.EventSubmission(
            producer_sequence=producer_sequence,
            event_kind=event_kind,
            event_schema_version=event_schema_version,
            occurred_at=occurred_at,
            payload=submission_payload,
        )
    except (ValueError, TypeError) as exc:
        raise DashboardError(400, "invalid_command", f"command submission is invalid: {exc}") from exc
    try:
        envelope = evidence_journal.append_event(channel_id, owner_domain, submission)
    except Exception as exc:
        name = type(exc).__name__
        message = str(exc) or name
        if isinstance(exc, PermissionError):
            raise DashboardError(403, "forbidden", f"command journaling denied: {message[:400]}") from exc
        if "NotAdmitted" in name:
            raise DashboardError(
                409, "journal_not_admitted", f"owner journal for {owner_domain!r} is not admitted: {message[:400]}"
            ) from exc
        if "IntegrityIncident" in name:
            incident = getattr(exc, "incident", None)
            detail = ""
            try:
                if incident is not None and hasattr(incident, "to_dict"):
                    detail = json.dumps(incident.to_dict(), sort_keys=True)[:400]
                else:
                    detail = message[:400]
            except Exception:
                detail = message[:400]
            raise DashboardError(
                409, "integrity_incident", f"conflicting command content under one producer sequence: {detail}"
            ) from exc
        if isinstance(exc, (ValueError, TypeError)):
            raise DashboardError(400, "invalid_command", f"command journaling rejected the submission: {message[:400]}") from exc
        raise DashboardError(500, "journal_failed", f"command journaling failed: {message[:400]}") from exc
    try:
        envelope_dict = envelope.to_dict()
    except Exception:
        envelope_dict = {"event_kind": event_kind}
    return _ok_bytes(
        201,
        {
            "accepted": True,
            "command": command,
            "resource_id": resource_id,
            "journal_envelope": envelope_dict,
            "external_effect": _missing(
                "not_observed",
                "accepted dashboard command claims no external effect; separately authorized handling is required",
            ),
            "projection_notes": {
                "authoritative": False,
                "cache": "dashboard_projection",
            },
        },
    )


# ---------------------------------------------------------------------------
# Public HTTP entry point
# ---------------------------------------------------------------------------


def handle_http(channel_id: str, method: str, path: str, body: bytes) -> bytes:
    """Serve one dashboard HTTP request; always returns canonical JSON bytes."""
    try:
        if not isinstance(channel_id, str) or not isinstance(method, str) or not isinstance(path, str):
            raise DashboardError(400, "invalid_request", "channel_id, method, and path must be strings")
        if not isinstance(body, bytes):
            raise DashboardError(400, "invalid_request", "body must be bytes")
        normalized_method = method.strip().upper()
        if not normalized_method:
            raise DashboardError(400, "invalid_request", "method must be a nonempty string")
        parsed = urlparse(path)
        base_path = parsed.path or "/"
        query = parse_qs(parsed.query)
        segments = [segment for segment in base_path.split("/") if segment]
        # Authenticate: every dashboard call requires an authenticated channel.
        try:
            projection = access_policy.channel_projection(channel_id)
        except Exception as exc:
            if isinstance(exc, PermissionError):
                raise DashboardError(401, "unauthenticated", f"unknown channel: {exc}") from exc
            raise DashboardError(401, "unauthenticated", f"channel authentication failed: {exc}") from exc
        # Forbidden scalar-status / row-replacement paths never exist.
        if _is_forbidden_path(base_path):
            return _forbidden_status_bytes(base_path)
        lowered = base_path.rstrip("/").lower()
        if lowered in ("", "/"):
            raise DashboardError(404, "not_found", f"no dashboard resource at {base_path!r}")
        if lowered == "/dashboard/health":
            if normalized_method != "GET":
                raise DashboardError(405, "method_not_allowed", "health supports GET only")
            return _ok_bytes(
                200,
                {
                    "status": "ok",
                    "schema_version": SCHEMA_VERSION,
                    "projection_notes": {
                        "authoritative": False,
                        "cache": "dashboard_projection",
                    },
                },
            )
        if lowered == "/dashboard/snapshots":
            if normalized_method != "POST":
                raise DashboardError(405, "method_not_allowed", "snapshots supports POST only")
            return _handle_snapshot_ingest(channel_id, projection, body)
        if lowered == "/dashboard/commands":
            if normalized_method != "POST":
                raise DashboardError(405, "method_not_allowed", "commands supports POST only")
            return _handle_command_post(channel_id, projection, body)
        if lowered.startswith("/dashboard/attempts"):
            if normalized_method != "GET":
                raise DashboardError(405, "method_not_allowed", "attempts supports GET only")
            # Expected: /dashboard/attempts/<attempt_id>
            parts = base_path.split("?")
            clean = parts[0].rstrip("/")
            prefix = "/dashboard/attempts/"
            if not clean.lower().startswith(prefix) or len(clean) <= len(prefix):
                raise DashboardError(400, "invalid_attempt_id", "attempt request requires /dashboard/attempts/<attempt_id>")
            attempt_id = clean[len(prefix):]
            # Guard against nested paths: only one segment allowed.
            if "/" in attempt_id:
                raise DashboardError(404, "not_found", f"no dashboard resource at {base_path!r}")
            try:
                _require_identifier(attempt_id, "attempt_id")
            except DashboardError as exc:
                raise DashboardError(400, exc.code, exc.message) from exc
            return _handle_attempt_get(channel_id, attempt_id)
        if lowered.startswith("/dashboard/rows"):
            if normalized_method != "GET":
                raise DashboardError(405, "method_not_allowed", "rows supports GET only")
            raw_segments = [segment for segment in base_path.split("/") if segment]
            return _handle_row_get(channel_id, query, raw_segments)
        raise DashboardError(404, "not_found", f"no dashboard resource at {base_path!r}")
    except DashboardError as exc:
        return _error_bytes(exc)
    except Exception as exc:  # never leak a traceback; always JSON bytes
        return _error_bytes(DashboardError(500, "internal_error", f"dashboard request failed: {exc}"))


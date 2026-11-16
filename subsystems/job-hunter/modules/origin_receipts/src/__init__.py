"""origin_receipts: verified origin-receipt ingress for the application axis (tier 6).

Implements seam-mapping #14 (origin verification and reconciliation ingress)
and #11.5/#11.6 (application facts / source checks):

* A confirmation page, email, screenshot, portal response, or receipt enters
  first as a restricted observation artifact (the ``receipt`` input).
* The recorder checks independently: source identity, receipt semantics under
  the pinned origin policy, candidate/job/origin/attempt correlation, trace
  correlation (or evidenced alternate matching), commitment versus absence,
  temporal/origin-sequence scope, practice/production/synthetic/historical
  scope, and raw artifact integrity.
* HTTP 200, mailbox access, authenticated transport, a submit click, or a
  human note alone is insufficient. Practice, historical, or synthetic
  commitments never become production facts. Rejection/withdrawal/closure
  never erases historical commitment.
* On success the module journals a verification observation and commits a
  cumulative ``application`` AxisRevision (facts are append-only). On
  verification failure it journals the observation and returns a typed
  Missing (unknown), publishing no accepted OriginFact.

A production origin need not implement the portfolio protocol; the
designated recorder normalizes verified receipts without becoming the
origin.
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import re
import sys
import threading
from dataclasses import is_dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


def _load_sibling(name: str):
    """Import a declared CONSUMES sibling, falling back to its source path."""
    if name in sys.modules:
        return sys.modules[name]
    try:
        return importlib.import_module(name)
    except ModuleNotFoundError:
        pass
    sibling_path = Path(__file__).resolve().parents[2] / name / "src" / "__init__.py"
    spec = importlib.util.spec_from_file_location(name, sibling_path)
    if spec is None or spec.loader is None:  # pragma: no cover - import plumbing
        raise ModuleNotFoundError(f"sibling module {name!r} not found")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


contract_codec = _load_sibling("contract_codec")
access_policy = _load_sibling("access_policy")
artifact_store = _load_sibling("artifact_store")
evidence_journal = _load_sibling("evidence_journal")
owner_revisions = _load_sibling("owner_revisions")
attempt_commissioning = _load_sibling("attempt_commissioning")

__all__ = [
    "RECORD_TYPE",
    "SCHEMA_VERSION",
    "EVENT_KIND",
    "EVENT_VERSION",
    "OriginReceiptError",
    "InvalidReceiptError",
    "ReceiptAuthError",
    "ReceiptCommitError",
    "CommandConflictError",
    "record_origin_receipt",
    "reset_for_tests",
]

RECORD_TYPE = "origin_receipt_observation"
SCHEMA_VERSION = "origin-receipts/0.1.0"
VERIFICATION_RECORD_TYPE = "origin_verification_record"
EVENT_KIND = "origin.receipt_observed"
EVENT_VERSION = "1"

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_POINTER_RE = re.compile(r"^(?:/(?:[^~/]|~[01])*)*$")
_MAX_IDENTIFIER_LEN = 256
_MAX_SAFE_INT = 9007199254740991

_VALID_KINDS = frozenset({"practice", "production"})
_VALID_SCOPES = frozenset({"current_run", "historical_unscored", "synthetic"})
_VALID_AUTH = frozenset({"verified", "failed", "unknown"})
_VALID_CORR = frozenset({"matched", "mismatched", "unknown"})
_VALID_TRACE = frozenset({"matched", "mismatched", "not_observed", "not_applicable"})
_VALID_STATES = frozenset({"committed", "not_committed"})
_VALID_COVERAGE = frozenset({"at_boundary", "final_for_attempt"})
_VALID_ORIGINS = frozenset(
    {"engine_measured", "browser_measured", "subject_reported", "manual_reference"}
)
_VALID_PROVENANCES = frozenset(
    {"server", "fixture_client", "connector", "subject", "manual_observer", "importer"}
)
_ACCEPTED_SIGNAL = "verified_receipt"

_LOCK = threading.RLock()
# (attempt_id, command_id) -> (input_fingerprint, result)
_RECEIPTS: dict[tuple[str, str], tuple[str, Any]] = {}
# Fallback cumulative facts when owner_revisions.read_domain is unavailable.
_FACTS: dict[str, list[dict[str, Any]]] = {}


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class OriginReceiptError(Exception):
    """Base class for origin-receipt contract violations."""


class InvalidReceiptError(OriginReceiptError, ValueError):
    """The receipt artifact is structurally invalid."""


class ReceiptAuthError(OriginReceiptError, PermissionError):
    """The authenticated channel may not record for this attempt."""


class ReceiptCommitError(OriginReceiptError):
    """The verified fact could not be committed."""


class CommandConflictError(OriginReceiptError):
    """A command id was reused with different content."""


# ---------------------------------------------------------------------------
# Missing / strict-JSON helpers
# ---------------------------------------------------------------------------


def _valid_missing_reasons() -> frozenset[str]:
    reasons = getattr(contract_codec, "VALID_MISSING_REASONS", None)
    if reasons is not None:
        return frozenset(reasons)
    return frozenset(
        {
            "not_enabled",
            "not_applicable",
            "not_observed",
            "observation_lost",
            "unsupported_by_subject",
            "manual_override",
        }
    )


def _is_missing(value: Any) -> bool:
    if is_dataclass(value) and not isinstance(value, type):
        if type(value).__name__ == "Missing":
            reason = getattr(value, "reason", None)
            return reason in _valid_missing_reasons()
        return False
    if not isinstance(value, Mapping):
        return False
    keys = set(value.keys())
    if keys not in ({"value", "reason"}, {"value", "reason", "detail"}):
        return False
    if value.get("value") is not None:
        return False
    reason = value.get("reason")
    if reason not in _valid_missing_reasons():
        return False
    if "detail" in value:
        detail = value["detail"]
        if not isinstance(detail, str) or not detail:
            return False
    return True


def _missing_reason(value: Any) -> str | None:
    if is_dataclass(value) and not isinstance(value, type):
        if type(value).__name__ == "Missing":
            reason = getattr(value, "reason", None)
            if reason in _valid_missing_reasons():
                return str(reason)
        return None
    if _is_missing(value):
        assert isinstance(value, Mapping)
        return str(value["reason"])
    return None


def _missing_dict(reason: str, detail: str | None = None) -> dict[str, Any]:
    if reason not in _valid_missing_reasons():
        raise InvalidReceiptError(f"unknown Missing reason: {reason!r}")
    out: dict[str, Any] = {"value": None, "reason": reason}
    if detail is not None:
        if not isinstance(detail, str) or not detail:
            raise InvalidReceiptError("Missing.detail must be nonempty")
        out["detail"] = detail
    return out


def _jsonable(value: Any, path: str = "$") -> Any:
    if _is_missing(value):
        reason = _missing_reason(value)
        assert reason is not None
        detail = None
        if isinstance(value, Mapping):
            detail = value.get("detail")
        else:
            detail = getattr(value, "detail", None)
        out: dict[str, Any] = {"value": None, "reason": reason}
        if detail is not None:
            if not isinstance(detail, str) or not detail:
                raise InvalidReceiptError(f"Missing.detail must be nonempty at {path}")
            out["detail"] = detail
        return out
    if value is None:
        raise InvalidReceiptError(f"bare null at {path}; use a typed Missing envelope")
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise InvalidReceiptError(
                    f"non-string mapping key at {path}: {type(key).__name__}"
                )
            normalized[key] = _jsonable(item, f"{path}.{key}")
        return normalized
    if isinstance(value, (list, tuple)):
        return [_jsonable(item, f"{path}[{index}]") for index, item in enumerate(value)]
    if isinstance(value, bool) or isinstance(value, int) or isinstance(value, str):
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise InvalidReceiptError(f"nonfinite number at {path}")
        return value
    if isinstance(value, (bytes, bytearray)):
        raise InvalidReceiptError(
            f"raw bytes at {path}; retain an ArtifactReference instead"
        )
    if is_dataclass(value) and not isinstance(value, type):
        if hasattr(value, "to_dict") and callable(value.to_dict):
            try:
                as_dict = value.to_dict()  # type: ignore[union-attr]
            except Exception:
                as_dict = None
            if isinstance(as_dict, Mapping):
                return _jsonable(as_dict, path)
        from dataclasses import fields as _fields

        return _jsonable(
            {item.name: getattr(value, item.name) for item in _fields(value)}, path
        )
    raise InvalidReceiptError(
        f"value at {path} is not ordinary JSON content ({type(value).__name__})"
    )


def _canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise InvalidReceiptError(f"record is not canonicalizable JSON: {exc}") from exc


def _strict_gate(record: Mapping[str, Any], label: str) -> bytes:
    normalized = _jsonable(record, label)
    wrapper = {"id": "origin_receipt_gate", "timing": normalized}
    try:
        contract_codec.validate_record(_canonical_bytes(wrapper), "record/v1")
    except (TypeError, ValueError) as exc:
        raise InvalidReceiptError(f"{label} is not strict JSON evidence: {exc}") from exc
    payload = _canonical_bytes(normalized)
    try:
        contract_codec.canonical_digest(payload)
    except (TypeError, ValueError) as exc:
        raise InvalidReceiptError(f"{label} has no canonical digest: {exc}") from exc
    return payload


def _digest_of(payload: bytes) -> str:
    return str(contract_codec.canonical_digest(payload))


# ---------------------------------------------------------------------------
# Field validators
# ---------------------------------------------------------------------------


def _require_identifier(value: Any, field_name: str) -> str:
    if not isinstance(value, str):
        raise InvalidReceiptError(f"{field_name} must be a str")
    if not value or value != value.strip():
        raise InvalidReceiptError(
            f"{field_name} must be a nonempty identifier without padding"
        )
    if len(value) > _MAX_IDENTIFIER_LEN:
        raise InvalidReceiptError(
            f"{field_name} must be at most {_MAX_IDENTIFIER_LEN} characters"
        )
    if any(ord(ch) < 0x20 for ch in value):
        raise InvalidReceiptError(f"{field_name} must not contain control characters")
    return value


def _require_digest(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.match(value):
        raise InvalidReceiptError(
            f"{field_name} must be a sha256:<64 lowercase hex> digest"
        )
    return value


def _require_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidReceiptError(f"{field_name} must be an int")
    return value


def _require_nonnegative_number(value: Any, field_name: str) -> int | float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise InvalidReceiptError(f"{field_name} must be a number")
    if isinstance(value, float) and (
        value != value or value in (float("inf"), float("-inf"))
    ):
        raise InvalidReceiptError(f"{field_name} must be finite")
    if value < 0:
        raise InvalidReceiptError(f"{field_name} must be nonnegative")
    return value


def _require_exact_keys(value: Any, required: set[str] | frozenset[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise InvalidReceiptError(f"{label} must be a mapping")
    keys = set(value.keys())
    missing = set(required) - keys
    if missing:
        raise InvalidReceiptError(f"{label} is missing required keys: {sorted(missing)}")
    extra = keys - set(required)
    if extra:
        raise InvalidReceiptError(f"{label} has undeclared properties: {sorted(extra)}")
    return value


def _require_maybe_identifier(value: Any, field_name: str) -> Any:
    if _is_missing(value):
        return _jsonable(value, field_name)
    return _require_identifier(value, field_name)


def _require_timepoint(value: Any, field_name: str) -> dict[str, Any]:
    if is_dataclass(value) and not isinstance(value, type) and hasattr(value, "to_dict"):
        try:
            as_dict = value.to_dict()  # type: ignore[union-attr]
        except Exception as exc:
            raise InvalidReceiptError(f"{field_name} is not a TimePoint: {exc}") from exc
        if isinstance(as_dict, Mapping):
            value = as_dict
    data = _require_exact_keys(
        value,
        frozenset(
            {"clock_id", "boot_id", "origin", "monotonic_offset_ms", "utc_annotation"}
        ),
        field_name,
    )
    clock_id = _require_identifier(data["clock_id"], f"{field_name}.clock_id")
    boot_id = _require_identifier(data["boot_id"], f"{field_name}.boot_id")
    origin = data["origin"]
    if origin not in _VALID_ORIGINS:
        raise InvalidReceiptError(f"{field_name}.origin is invalid: {origin!r}")
    offset = _require_nonnegative_number(
        data["monotonic_offset_ms"], f"{field_name}.monotonic_offset_ms"
    )
    utc = data["utc_annotation"]
    if _is_missing(utc):
        utc_norm: Any = _jsonable(utc, f"{field_name}.utc_annotation")
    elif isinstance(utc, str) and utc:
        utc_norm = utc
    else:
        raise InvalidReceiptError(
            f"{field_name}.utc_annotation must be a date-time string or Missing"
        )
    return {
        "clock_id": clock_id,
        "boot_id": boot_id,
        "origin": origin,
        "monotonic_offset_ms": offset,
        "utc_annotation": utc_norm,
    }


def _require_maybe_timepoint(value: Any, field_name: str) -> dict[str, Any]:
    if _is_missing(value):
        return _jsonable(value, field_name)
    return _require_timepoint(value, field_name)


def _require_version_pin(value: Any, field_name: str) -> dict[str, Any]:
    data = _require_exact_keys(
        value, frozenset({"id", "version", "artifact_digest"}), field_name
    )
    return {
        "id": _require_identifier(data["id"], f"{field_name}.id"),
        "version": _require_identifier(data["version"], f"{field_name}.version"),
        "artifact_digest": _require_digest(
            data["artifact_digest"], f"{field_name}.artifact_digest"
        ),
    }


def _require_evidence_ref(value: Any, field_name: str) -> dict[str, Any]:
    if is_dataclass(value) and not isinstance(value, type) and hasattr(value, "to_dict"):
        try:
            as_dict = value.to_dict()  # type: ignore[union-attr]
        except Exception as exc:
            raise InvalidReceiptError(
                f"{field_name} is not an EvidenceRef: {exc}"
            ) from exc
        if isinstance(as_dict, Mapping):
            value = as_dict
    data = _require_exact_keys(
        value,
        frozenset({"journal_id", "sequence", "event_id", "event_hash", "pointer"}),
        field_name,
    )
    journal_id = _require_identifier(data["journal_id"], f"{field_name}.journal_id")
    sequence = _require_int(data["sequence"], f"{field_name}.sequence")
    if sequence < 1 or sequence > _MAX_SAFE_INT:
        raise InvalidReceiptError(f"{field_name}.sequence must be a positive safe integer")
    event_id = _require_identifier(data["event_id"], f"{field_name}.event_id")
    event_hash = _require_digest(data["event_hash"], f"{field_name}.event_hash")
    pointer = data["pointer"]
    if not isinstance(pointer, str) or not _POINTER_RE.match(pointer):
        raise InvalidReceiptError(f"{field_name}.pointer is not a valid JSON pointer")
    return {
        "journal_id": journal_id,
        "sequence": sequence,
        "event_id": event_id,
        "event_hash": event_hash,
        "pointer": pointer,
    }


def _require_maybe_evidence_ref(value: Any, field_name: str) -> dict[str, Any]:
    if _is_missing(value):
        return _jsonable(value, field_name)
    return _require_evidence_ref(value, field_name)


def _coerce_artifact_ref(value: Any, field_name: str) -> Any:
    if hasattr(value, "digest") and hasattr(value, "to_dict"):
        return value
    if isinstance(value, Mapping):
        try:
            return artifact_store.ArtifactReference.from_dict(dict(value))
        except (TypeError, ValueError) as exc:
            raise InvalidReceiptError(
                f"{field_name} is not an ArtifactReference: {exc}"
            ) from exc
    raise InvalidReceiptError(
        f"{field_name} must be an ArtifactReference, not {type(value).__name__}"
    )


# ---------------------------------------------------------------------------
# Receipt structure
# ---------------------------------------------------------------------------

_RECEIPT_FIELDS = frozenset(
    {
        "record_type",
        "schema_version",
        "origin_id",
        "candidate_id",
        "job_id",
        "attempt_id",
        "attempt_kind",
        "evidence_scope",
        "signal",
        "provenance",
        "authentication",
        "correlation",
        "trace_correlation",
        "matched_by",
        "origin_application_id",
        "origin_revision",
        "state",
        "coverage",
        "occurred_at",
        "received_at",
        "verification_policy",
        "authority_seal_ref",
        "alternate_basis",
    }
)


def _validate_receipt_structure(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise InvalidReceiptError("receipt record must be a JSON object mapping")
    _require_exact_keys(raw, _RECEIPT_FIELDS, "OriginReceipt")
    if raw["record_type"] != RECORD_TYPE:
        raise InvalidReceiptError(
            f"record_type must be {RECORD_TYPE!r}, got {raw['record_type']!r}"
        )
    if raw["schema_version"] != SCHEMA_VERSION:
        raise InvalidReceiptError(
            f"schema_version must be {SCHEMA_VERSION!r}, got {raw['schema_version']!r}"
        )
    origin_id = _require_identifier(raw["origin_id"], "receipt.origin_id")
    candidate_id = _require_identifier(raw["candidate_id"], "receipt.candidate_id")
    job_id = _require_identifier(raw["job_id"], "receipt.job_id")
    attempt_id = _require_identifier(raw["attempt_id"], "receipt.attempt_id")
    attempt_kind = raw["attempt_kind"]
    if attempt_kind not in _VALID_KINDS:
        raise InvalidReceiptError(f"receipt.attempt_kind is invalid: {attempt_kind!r}")
    evidence_scope = raw["evidence_scope"]
    if evidence_scope not in _VALID_SCOPES:
        raise InvalidReceiptError(
            f"receipt.evidence_scope is invalid: {evidence_scope!r}"
        )
    # Signal is an open identifier: unknown signals are structurally valid but
    # semantically insufficient. Only verified_receipt can support a fact.
    signal = _require_identifier(raw["signal"], "receipt.signal")
    provenance = raw["provenance"]
    if provenance not in _VALID_PROVENANCES:
        raise InvalidReceiptError(f"receipt.provenance is invalid: {provenance!r}")
    authentication = raw["authentication"]
    if authentication not in _VALID_AUTH:
        raise InvalidReceiptError(
            f"receipt.authentication is invalid: {authentication!r}"
        )
    correlation = raw["correlation"]
    if correlation not in _VALID_CORR:
        raise InvalidReceiptError(f"receipt.correlation is invalid: {correlation!r}")
    trace = raw["trace_correlation"]
    if trace not in _VALID_TRACE:
        raise InvalidReceiptError(
            f"receipt.trace_correlation is invalid: {trace!r}"
        )
    matched_raw = raw["matched_by"]
    if isinstance(matched_raw, (str, bytes)) or not isinstance(matched_raw, Sequence):
        raise InvalidReceiptError("receipt.matched_by must be a sequence")
    matched_by: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(matched_raw):
        name = _require_identifier(item, f"receipt.matched_by[{index}]")
        if name in seen:
            raise InvalidReceiptError("receipt.matched_by must be unique")
        seen.add(name)
        matched_by.append(name)
    origin_application_id = _require_maybe_identifier(
        raw["origin_application_id"], "receipt.origin_application_id"
    )
    origin_revision = _require_maybe_identifier(
        raw["origin_revision"], "receipt.origin_revision"
    )
    state = raw["state"]
    if state not in _VALID_STATES:
        raise InvalidReceiptError(f"receipt.state is invalid: {state!r}")
    coverage = raw["coverage"]
    if coverage not in _VALID_COVERAGE:
        raise InvalidReceiptError(f"receipt.coverage is invalid: {coverage!r}")
    occurred_at = _require_maybe_timepoint(raw["occurred_at"], "receipt.occurred_at")
    received_at = _require_timepoint(raw["received_at"], "receipt.received_at")
    verification_policy = _require_version_pin(
        raw["verification_policy"], "receipt.verification_policy"
    )
    authority_seal_ref = _require_maybe_evidence_ref(
        raw["authority_seal_ref"], "receipt.authority_seal_ref"
    )
    alternate_basis = _require_maybe_identifier(
        raw["alternate_basis"], "receipt.alternate_basis"
    )
    return {
        "record_type": RECORD_TYPE,
        "schema_version": SCHEMA_VERSION,
        "origin_id": origin_id,
        "candidate_id": candidate_id,
        "job_id": job_id,
        "attempt_id": attempt_id,
        "attempt_kind": attempt_kind,
        "evidence_scope": evidence_scope,
        "signal": signal,
        "provenance": provenance,
        "authentication": authentication,
        "correlation": correlation,
        "trace_correlation": trace,
        "matched_by": matched_by,
        "origin_application_id": origin_application_id,
        "origin_revision": origin_revision,
        "state": state,
        "coverage": coverage,
        "occurred_at": occurred_at,
        "received_at": received_at,
        "verification_policy": verification_policy,
        "authority_seal_ref": authority_seal_ref,
        "alternate_basis": alternate_basis,
    }


# ---------------------------------------------------------------------------
# Verification (seam #14 eight checks)
# ---------------------------------------------------------------------------


def _verify_receipt(commission: dict[str, Any], receipt: dict[str, Any]) -> tuple[bool, str]:
    """Apply the eight independent origin checks. Returns (accepted, reason)."""
    attempt = commission["attempt"]
    # 1. Source identity + 3. candidate/job/origin/attempt correlation.
    if receipt["origin_id"] != attempt["target_id"]:
        return False, (
            f"origin mismatch: receipt origin {receipt['origin_id']!r} does not "
            f"identify the commissioned target {attempt['target_id']!r}"
        )
    app_source = commission["owners"]["application"]["source_id"]
    if isinstance(app_source, str) and receipt["origin_id"] != app_source:
        return False, (
            f"origin mismatch: receipt origin {receipt['origin_id']!r} does not "
            "match the bound application source"
        )
    if receipt["candidate_id"] != commission["candidate_id"]:
        return False, "candidate correlation failed: receipt candidate does not match"
    if receipt["job_id"] != commission["job"]["job_id"]:
        return False, "job correlation failed: receipt job does not match"
    if receipt["attempt_id"] != attempt["attempt_id"]:
        return False, "attempt correlation failed: receipt attempt does not match"
    # 7. Practice / production / synthetic / historical scope.
    if receipt["attempt_kind"] != attempt["kind"]:
        return False, (
            f"scope mismatch: {receipt['attempt_kind']} evidence cannot support a "
            f"{attempt['kind']} commitment; lineage links never promote evidence"
        )
    if receipt["evidence_scope"] != "current_run":
        return False, (
            f"evidence scope {receipt['evidence_scope']!r} is preserved as "
            "observation, not an accepted fact; only current_run evidence "
            "supports commitment"
        )
    # 2. Receipt semantics under the pinned policy.
    if receipt["signal"] != _ACCEPTED_SIGNAL:
        return False, (
            f"signal {receipt['signal']!r} is insufficient for origin commitment; "
            "HTTP 200, a submit click, a subject result, or an operator note "
            "alone establishes no fact"
        )
    # Source checks: authentication and correlation are independent.
    if receipt["authentication"] != "verified":
        return False, (
            f"source authentication is {receipt['authentication']!r}, not verified; "
            "a serialized verified label is insufficient"
        )
    if receipt["correlation"] != "matched":
        return False, (
            f"correlation is {receipt['correlation']!r}, not matched; an "
            "authenticated but uncorrelated message remains evidence of "
            "receipt, not an accepted fact"
        )
    if not receipt["matched_by"]:
        return False, "matched correlation requires nonempty matching inputs"
    # 4. Trace correlation or evidenced alternate matching.
    if receipt["trace_correlation"] == "mismatched" and _is_missing(
        receipt["alternate_basis"]
    ):
        return False, (
            "trace mismatch without explicit alternate correlation basis; a "
            "trace defect requires strong, evidenced alternate matching"
        )
    # Pinned origin policy agreement.
    pinned = commission["origin_policy"]
    claimed = receipt["verification_policy"]
    if (
        claimed["id"] != pinned["id"]
        or claimed["version"] != pinned["version"]
        or claimed["artifact_digest"] != pinned["artifact_digest"]
    ):
        return False, (
            "receipt verification_policy does not match the pinned origin_policy; "
            "observation is retained but no fact is accepted"
        )
    # 5. Commitment versus as-of absence versus final absence.
    if (
        receipt["state"] == "not_committed"
        and receipt["coverage"] == "final_for_attempt"
        and _is_missing(receipt["authority_seal_ref"])
    ):
        return False, (
            "final noncommitment requires origin-owned finality evidence; local "
            "timeout, missing receipt, or observation closure is not final"
        )
    # 6. Temporal scope and 8. integrity are structural (TimePoints validated,
    # artifact bytes resolved). No invented coordinates or IDs.
    return True, "verified under the pinned origin policy"


def _verification_kind_for(commission: dict[str, Any]) -> str:
    if commission["attempt"]["kind"] == "practice":
        return "local_origin_transaction"
    return "verified_origin_receipt"


# ---------------------------------------------------------------------------
# Journaling + registration reconstruction
# ---------------------------------------------------------------------------


def _journal_verification(
    channel_id: str,
    commission: dict[str, Any],
    commission_ref: Any,
    receipt: dict[str, Any],
    receipt_ref: Any,
    accepted: bool,
    reason: str,
) -> Any:
    """Retain a verification record and journal the observation. Always runs."""
    verification_record = {
        "record_type": VERIFICATION_RECORD_TYPE,
        "schema_version": SCHEMA_VERSION,
        "commission_id": commission["commission_id"],
        "attempt_id": commission["attempt"]["attempt_id"],
        "origin_id": receipt["origin_id"],
        "receipt_digest": receipt_ref.digest,
        "accepted": accepted,
        "reason": reason,
        "signal": receipt["signal"],
    }
    payload = _strict_gate(verification_record, "VerificationRecord")
    try:
        verification_ref = artifact_store.retain_artifact(
            channel_id, "attempt.application", "application/json", payload, "restricted"
        )
    except access_policy.AuthorizationError as exc:
        raise ReceiptAuthError(f"verification retention is not authorized: {exc}") from exc
    data = {
        "commission_id": commission["commission_id"],
        "attempt_id": commission["attempt"]["attempt_id"],
        "origin_id": receipt["origin_id"],
        "receipt_digest": receipt_ref.digest,
        "verification_digest": verification_ref.digest,
        "accepted": accepted,
        "reason": reason,
        "signal": receipt["signal"],
    }
    submission = evidence_journal.EventSubmission(
        producer_sequence={"value": None, "reason": "not_applicable"},
        event_kind=EVENT_KIND,
        event_schema_version=EVENT_VERSION,
        occurred_at=dict(receipt["received_at"]),
        payload={
            "data": data,
            "measurements": [],
            "evidence_refs": [dict(commission["admission_ref"])],
            "artifact_refs": [
                receipt_ref.to_dict(),
                commission_ref.to_dict(),
                verification_ref.to_dict(),
            ],
        },
    )
    try:
        return evidence_journal.append_event(
            channel_id, "attempt.application", submission
        )
    except access_policy.AuthorizationError as exc:
        raise ReceiptAuthError(
            f"verification journaling is not authorized: {exc}"
        ) from exc
    except evidence_journal.EvidenceJournalError as exc:
        raise ReceiptCommitError(f"verification journaling failed: {exc}") from exc


def _reconstruct_registration(
    commission: dict[str, Any], commission_ref: Any, commit_prefix: dict[str, Any]
) -> Any:
    attempt = commission["attempt"]
    entity = {
        "entity_type": "application_attempt",
        "attempt_id": attempt["attempt_id"],
        "kind": attempt["kind"],
    }
    identity = {
        "commission": commission_ref.to_dict(),
        "attempt": {key: attempt[key] for key in sorted(attempt)},
        "execution": {
            key: commission["execution"][key] for key in sorted(commission["execution"])
        },
    }
    owners = {key: commission["owners"][key] for key in sorted(commission["owners"])}
    return owner_revisions.EntityRegistration(
        registration_id=f"reg_{commission['commission_id']}",
        entity=entity,
        identity=identity,
        owners=owners,
        evidence_prefix=dict(commit_prefix),
        evidence_refs=[dict(commission["admission_ref"])],
    )


def _prior_facts(
    channel_id: str, attempt_id: str, kind: str
) -> list[dict[str, Any]]:
    entity = {"entity_type": "application_attempt", "attempt_id": attempt_id, "kind": kind}
    read_domain = getattr(owner_revisions, "read_domain", None)
    if read_domain is not None:
        try:
            current = read_domain(channel_id, entity, "application")
        except owner_revisions.OwnerRevisionError:
            raise
        except access_policy.AuthorizationError:
            raise
        if _is_missing(current):
            return []
        if hasattr(current, "record"):
            record = current.record
            value = record.get("value", {})
            facts = value.get("facts", [])
            return [dict(f) for f in facts]
        if isinstance(current, Mapping):
            value = current.get("value", {})
            facts = value.get("facts", [])
            return [dict(f) for f in facts]
        return []
    with _LOCK:
        return [dict(f) for f in _FACTS.get(attempt_id, [])]


# ---------------------------------------------------------------------------
# Public interface (EXPOSES)
# ---------------------------------------------------------------------------


def record_origin_receipt(
    channel_id: str,
    commission: Any,
    receipt: Any,
    expected_revision: int,
    command_id: str,
) -> Any:
    """Record one verified origin receipt as an application-axis fact.

    On verification success, journals the observation and commits a
    cumulative ``application`` AxisRevision. On verification failure
    (insufficient semantics, correlation mismatch, policy mismatch, or
    scope mismatch), journals the observation and returns a typed
    Missing (unknown) without publishing a fact.
    """
    if not isinstance(channel_id, str) or not channel_id:
        raise ReceiptAuthError("channel_id must be a nonempty identifier")
    _require_identifier(command_id, "command_id")
    if isinstance(expected_revision, bool) or not isinstance(expected_revision, int):
        raise InvalidReceiptError("expected_revision must be an int")
    if expected_revision < 0:
        raise InvalidReceiptError("expected_revision must be nonnegative")
    commission_ref = _coerce_artifact_ref(commission, "commission")
    receipt_ref = _coerce_artifact_ref(receipt, "receipt")

    try:
        loaded = attempt_commissioning.load_commission(channel_id, commission_ref)
    except attempt_commissioning.CommissionAuthError as exc:
        raise ReceiptAuthError(str(exc)) from exc
    except attempt_commissioning.CommissionError as exc:
        raise InvalidReceiptError(f"commission is invalid: {exc}") from exc
    if hasattr(loaded, "to_dict"):
        commission_record = loaded.to_dict()
    elif isinstance(loaded, Mapping):
        commission_record = dict(loaded)
    else:  # pragma: no cover - defensive
        raise InvalidReceiptError("commission did not load to a mapping")
    attempt_id = commission_record["attempt"]["attempt_id"]
    kind = commission_record["attempt"]["kind"]

    # Idempotent command replay: identical retries return the stored result
    # without duplicating journal or revision effects.
    fingerprint = _digest_of(
        _canonical_bytes(
            {
                "commission": commission_ref.digest,
                "receipt": receipt_ref.digest,
                "expected_revision": expected_revision,
            }
        )
    )
    with _LOCK:
        cached = _RECEIPTS.get((attempt_id, command_id))
        if cached is not None:
            prior_fingerprint, result = cached
            if prior_fingerprint != fingerprint:
                raise CommandConflictError(
                    f"command {command_id!r} was already used for different content"
                )
            return result

    try:
        receipt_bytes = artifact_store.resolve_artifact(channel_id, receipt_ref)
    except artifact_store.ArtifactError as exc:
        raise InvalidReceiptError(f"receipt bytes are unavailable: {exc}") from exc
    try:
        receipt_raw = json.loads(receipt_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise InvalidReceiptError(f"receipt bytes are not JSON: {exc}") from exc
    receipt_record = _validate_receipt_structure(receipt_raw)
    _strict_gate(receipt_record, "OriginReceipt")

    # Authenticated writer check: the channel must hold the application grant
    # and be the bound application writer. Serialized writer labels grant
    # nothing.
    try:
        descriptor = access_policy.authorize(
            channel_id, "attempt.application.write", attempt_id
        )
    except access_policy.UnknownChannelError as exc:
        raise ReceiptAuthError(f"unknown channel {channel_id!r}: {exc}") from exc
    except access_policy.AuthorizationError as exc:
        raise ReceiptAuthError(
            f"channel is not authorized for application writes: {exc}"
        ) from exc
    bound_writer = commission_record["owners"]["application"]["writer_id"]
    if _is_missing(bound_writer):
        raise ReceiptAuthError("the commission has no applicable application writer")
    if descriptor.owner_domain != "attempt.application":
        raise ReceiptAuthError(
            f"authenticated producer writes {descriptor.owner_domain!r}, not "
            "'attempt.application'"
        )
    if descriptor.producer_id != bound_writer:
        raise ReceiptAuthError(
            "the serialized writer_id is not the authenticated producer"
        )

    accepted, reason = _verify_receipt(commission_record, receipt_record)
    envelope = _journal_verification(
        channel_id,
        commission_record,
        commission_ref,
        receipt_record,
        receipt_ref,
        accepted,
        reason,
    )

    if not accepted:
        missing = _missing_dict("not_observed", reason[:256] if reason else "insufficient evidence")
        with _LOCK:
            _RECEIPTS[(attempt_id, command_id)] = (fingerprint, missing)
        return missing

    # Recover the commission commit prefix (journal sequence 2) from the
    # verified prefix ending at the new verification event, then rebuild the
    # exact registration bytes for the owner-local commit.
    journal_id = commission_record["journal_id"]
    head = evidence_journal.JournalPrefix(
        journal_id=journal_id,
        last_sequence=envelope.journal_sequence,
        head_hash=envelope.event_hash,
    )
    try:
        events = evidence_journal.read_prefix(channel_id, head)
    except evidence_journal.EvidenceJournalError as exc:
        raise ReceiptCommitError(f"verification prefix does not verify: {exc}") from exc
    except access_policy.AuthorizationError as exc:
        raise ReceiptAuthError(f"verification prefix is not readable: {exc}") from exc
    commit_prefix: dict[str, Any] | None = None
    for event in events:
        if event.event_kind == "attempt.commissioned":
            commit_prefix = {
                "journal_id": event.journal_id,
                "last_sequence": event.journal_sequence,
                "head_hash": event.event_hash,
            }
            break
    if commit_prefix is None:  # pragma: no cover - defensive
        raise ReceiptCommitError("the commission event is not in the verified prefix")
    registration = _reconstruct_registration(
        commission_record, commission_ref, commit_prefix
    )

    prior = _prior_facts(channel_id, attempt_id, kind)
    if len(prior) != expected_revision:
        # The owner store is the authority; a stale expectation never commits.
        # Surface the same conflict the owner fence would raise.
        pass

    verification_ref = {
        "journal_id": envelope.journal_id,
        "sequence": envelope.journal_sequence,
        "event_id": envelope.event_id,
        "event_hash": envelope.event_hash,
        "pointer": "",
    }
    fact_id = f"fact_{command_id}"
    _require_identifier(fact_id, "fact.fact_id")
    for existing in prior:
        if existing.get("fact_id") == fact_id:
            raise CommandConflictError(
                f"fact {fact_id!r} is already published for this attempt"
            )
    new_fact = {
        "fact_id": fact_id,
        "origin_id": receipt_record["origin_id"],
        "candidate_id": receipt_record["candidate_id"],
        "job_id": receipt_record["job_id"],
        "state": receipt_record["state"],
        "coverage": receipt_record["coverage"],
        "boundary_ref": dict(verification_ref),
        "origin_application_id": receipt_record["origin_application_id"],
        "origin_revision": receipt_record["origin_revision"],
        "receipt": receipt_ref.to_dict(),
        "verification_kind": _verification_kind_for(commission_record),
        "source_checks": {
            "authentication": "verified",
            "correlation": "matched",
            "trace_correlation": receipt_record["trace_correlation"],
            "verification_policy": dict(commission_record["origin_policy"]),
            "matched_by": list(receipt_record["matched_by"]),
            "evidence_refs": [dict(verification_ref)],
        },
        "authority_seal_ref": receipt_record["authority_seal_ref"],
        "occurred_at": receipt_record["occurred_at"],
        "received_at": dict(receipt_record["received_at"]),
        "evidence_refs": [dict(verification_ref)],
    }
    value = {"facts": prior + [new_fact]}
    revision = owner_revisions.AxisRevision(
        attempt={"attempt_id": attempt_id, "kind": kind},
        commission_digest=commission_ref.digest,
        axis="application",
        owner_domain=commission_record["owners"]["application"]["owner_domain"],
        writer_id=descriptor.producer_id,
        revision=expected_revision + 1,
        previous_revision=expected_revision,
        evidence_prefix={
            "journal_id": head.journal_id,
            "last_sequence": head.last_sequence,
            "head_hash": head.head_hash,
        },
        evidence_refs=[dict(verification_ref)],
        value=value,
    )
    lease = _missing_dict("not_applicable")
    try:
        owner_revisions.commit_domain(
            channel_id, registration, revision, command_id, lease
        )
    except owner_revisions.CommandConflictError as exc:
        raise CommandConflictError(str(exc)) from exc
    except owner_revisions.StaleRevisionError as exc:
        raise ReceiptCommitError(f"stale application revision: {exc}") from exc
    except owner_revisions.OwnerRevisionError as exc:
        raise ReceiptCommitError(f"application commit failed: {exc}") from exc
    except access_policy.AuthorizationError as exc:
        raise ReceiptAuthError(f"application commit is not authorized: {exc}") from exc

    with _LOCK:
        _RECEIPTS[(attempt_id, command_id)] = (fingerprint, revision)
        _FACTS[attempt_id] = [dict(f) for f in value["facts"]]
    return revision


def reset_for_tests() -> None:
    """Clear idempotency receipts and fallback facts (tests only)."""
    with _LOCK:
        _RECEIPTS.clear()
        _FACTS.clear()

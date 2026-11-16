"""attempt_commissioning: immutable application-attempt commissioning (tier 5).

Implements ``L.AttemptCommission`` construction, validation, retention,
journaling, and owner-separated entity registration per
``job-hunter-seam-mapping.md#10`` (commissioning and manual execution),
``#4.1`` (manual discovery), and ``#13.1`` (idempotency levels).

Durable order (seam 10.1):

1. Caller installs immutable input artifacts and admits a manifest.
2. Caller records/imports authorization and selection evidence.
3. This module validates the commission, verifies manifest agreement via
   ``evidence_journal.read_prefix``, and verifies input artifacts resolve.
4. Commission bytes are retained via ``artifact_store.retain_artifact``.
5. The commission is journaled via ``evidence_journal.commit_effect`` as an
   owner-local authoritative effect (state = commission bytes).
6. The owner-separated attempt entity is registered via
   ``owner_revisions.register_entity`` citing the post-commit prefix.
7. Downstream attempt linking stays asynchronous and is never part of the
   durability transaction here.

Invariants enforced: LIFE-COMMISSION, LIFE-IDEMPOTENCY, LIFE-LINEAGE,
LIFE-MANUAL, LIFE-AXES, EK-ATTEMPT-SCOPE, EK-MANUAL, OWD-ATTEMPT.
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import re
import sys
import threading
from dataclasses import dataclass, fields, is_dataclass
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
    sibling_path = (
        Path(__file__).resolve().parents[2] / name / "src" / "__init__.py"
    )
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

__all__ = [
    "AttemptCommission",
    "CommissionError",
    "InvalidCommissionError",
    "CommissionAuthError",
    "ManifestAgreementError",
    "IdempotencyConflictError",
    "NewIdentityRequiredError",
    "DuplicateRiskReviewRequiredError",
    "LineageError",
    "CommissionConflictError",
    "register_attempt",
    "load_commission",
    "reset_for_tests",
]

RECORD_TYPE = "attempt_commission"
SCHEMA_VERSION = "application-attempt-lifecycle/0.1.0"
KERNEL_VERSION = "evidence-kernel/0.1.0"
COMMISSION_EVENT_KIND = "attempt.commissioned"
COMMISSION_EVENT_VERSION = "1"

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_POINTER_RE = re.compile(r"^(?:/(?:[^~/]|~[01])*)*$")

_VALID_KINDS = frozenset({"practice", "production"})
_VALID_TARGET_CLASSES = frozenset({"laboratory_fixture", "employer_origin"})
_VALID_PARTITIONS = frozenset({"held_in", "held_out"})
_VALID_MODES = frozenset({"manual", "subject"})
_VALID_PLANNING_OWNERS = frozenset({"subject", "external_planner", "operator", "none"})
_VALID_REVISION_BASES = frozenset(
    {"native_revision", "source_digest", "operator_attestation", "unknown"}
)
_VALID_ORIGINS = frozenset(
    {"engine_measured", "browser_measured", "subject_reported", "manual_reference"}
)
_VALID_FIXTURE_ACTIONS = frozenset({"seal_after_drain", "not_applicable"})
_VALID_ROLES = {
    "dispatch": "connector",
    "observation": "connector",
    "execution": "subject",
    "application": "origin",
    "report": "reconciler",
}
_OWNER_DOMAINS = (
    "dispatch",
    "observation",
    "execution",
    "application",
    "report",
)
_MAX_IDENTIFIER_LEN = 256
_MAX_SAFE_INT = 9007199254740991


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class CommissionError(Exception):
    """Base class for attempt-commissioning contract violations."""


class InvalidCommissionError(CommissionError, ValueError):
    """The commission record is structurally invalid or violates a guard."""


class CommissionAuthError(CommissionError, PermissionError):
    """The authenticated channel may not commission this attempt."""


class ManifestAgreementError(CommissionError, ValueError):
    """The commission does not agree with its admitted manifest."""


class IdempotencyConflictError(CommissionError):
    """Changed content was submitted under a reused idempotency key."""


class CommissionConflictError(CommissionError):
    """A commission id was reused with different content."""


class NewIdentityRequiredError(CommissionError):
    """An immutable commission change requires a new attempt identity."""


class DuplicateRiskReviewRequiredError(CommissionError, ValueError):
    """A resubmission-risk attempt lacks evidenced duplicate-risk review."""


class LineageError(CommissionError, ValueError):
    """A lineage link is cross-kind, uncommissioned, cyclic, or misdirected."""


# ---------------------------------------------------------------------------
# Public record type
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AttemptCommission:
    """Immutable ``L.AttemptCommission`` for one application attempt."""

    commission_id: str
    run_id: str
    journal_id: str
    manifest_hash: str
    admission_ref: Mapping[str, Any]
    commissioned_by: str
    commissioned_at: Mapping[str, Any]
    attempt: Mapping[str, Any]
    candidate_id: str
    candidate_profile: Mapping[str, Any]
    job: Mapping[str, Any]
    selection_evidence: Mapping[str, Any]
    task: Mapping[str, Any]
    task_semantic_hash: str
    initial_materials: Sequence[Mapping[str, Any]]
    execution: Mapping[str, Any]
    owners: Mapping[str, Any]
    idempotency_key: str
    authorization_refs: Sequence[Mapping[str, Any]]
    recovery_review_refs: Sequence[Mapping[str, Any]]
    observation_policy: Mapping[str, Any]
    origin_policy: Mapping[str, Any]
    record_type: str = RECORD_TYPE
    schema_version: str = SCHEMA_VERSION
    kernel_version: str = KERNEL_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": self.record_type,
            "schema_version": self.schema_version,
            "kernel_version": self.kernel_version,
            "commission_id": self.commission_id,
            "run_id": self.run_id,
            "journal_id": self.journal_id,
            "manifest_hash": self.manifest_hash,
            "admission_ref": self.admission_ref,
            "commissioned_by": self.commissioned_by,
            "commissioned_at": self.commissioned_at,
            "attempt": self.attempt,
            "candidate_id": self.candidate_id,
            "candidate_profile": self.candidate_profile,
            "job": self.job,
            "selection_evidence": self.selection_evidence,
            "task": self.task,
            "task_semantic_hash": self.task_semantic_hash,
            "initial_materials": list(self.initial_materials),
            "execution": self.execution,
            "owners": self.owners,
            "idempotency_key": self.idempotency_key,
            "authorization_refs": list(self.authorization_refs),
            "recovery_review_refs": list(self.recovery_review_refs),
            "observation_policy": self.observation_policy,
            "origin_policy": self.origin_policy,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "AttemptCommission":
        allowed = {
            "record_type",
            "schema_version",
            "kernel_version",
            "commission_id",
            "run_id",
            "journal_id",
            "manifest_hash",
            "admission_ref",
            "commissioned_by",
            "commissioned_at",
            "attempt",
            "candidate_id",
            "candidate_profile",
            "job",
            "selection_evidence",
            "task",
            "task_semantic_hash",
            "initial_materials",
            "execution",
            "owners",
            "idempotency_key",
            "authorization_refs",
            "recovery_review_refs",
            "observation_policy",
            "origin_policy",
        }
        _require_exact_keys(data, allowed, "AttemptCommission")
        return cls(
            commission_id=data["commission_id"],
            run_id=data["run_id"],
            journal_id=data["journal_id"],
            manifest_hash=data["manifest_hash"],
            admission_ref=data["admission_ref"],
            commissioned_by=data["commissioned_by"],
            commissioned_at=data["commissioned_at"],
            attempt=data["attempt"],
            candidate_id=data["candidate_id"],
            candidate_profile=data["candidate_profile"],
            job=data["job"],
            selection_evidence=data["selection_evidence"],
            task=data["task"],
            task_semantic_hash=data["task_semantic_hash"],
            initial_materials=data["initial_materials"],
            execution=data["execution"],
            owners=data["owners"],
            idempotency_key=data["idempotency_key"],
            authorization_refs=data["authorization_refs"],
            recovery_review_refs=data["recovery_review_refs"],
            observation_policy=data["observation_policy"],
            origin_policy=data["origin_policy"],
            record_type=data["record_type"],
            schema_version=data["schema_version"],
            kernel_version=data["kernel_version"],
        )


# ---------------------------------------------------------------------------
# Strict JSON / missingness helpers
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
        name = type(value).__name__
        if name == "Missing":
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
        raise InvalidCommissionError(f"unknown Missing reason: {reason!r}")
    out: dict[str, Any] = {"value": None, "reason": reason}
    if detail is not None:
        if not isinstance(detail, str) or not detail:
            raise InvalidCommissionError("Missing.detail must be nonempty")
        out["detail"] = detail
    return out


def _jsonable(value: Any, path: str = "$") -> Any:
    """Normalize to strict JSON content; bare nulls and raw bytes are refused."""
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
                raise InvalidCommissionError(
                    f"Missing.detail must be nonempty at {path}"
                )
            out["detail"] = detail
        return out
    if value is None:
        raise InvalidCommissionError(
            f"bare null at {path}; use a typed Missing envelope"
        )
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise InvalidCommissionError(
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
            raise InvalidCommissionError(f"nonfinite number at {path}")
        return value
    if isinstance(value, (bytes, bytearray)):
        raise InvalidCommissionError(
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
        return _jsonable(
            {item.name: getattr(value, item.name) for item in fields(value)}, path
        )
    raise InvalidCommissionError(
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
        raise InvalidCommissionError(
            f"record is not canonicalizable JSON: {exc}"
        ) from exc


def _strict_gate(record: Mapping[str, Any], label: str) -> bytes:
    """Run the kernel strict-JSON gate and return canonical record bytes."""
    normalized = _jsonable(record, label)
    wrapper = {"id": "attempt_commission_gate", "timing": normalized}
    try:
        contract_codec.validate_record(_canonical_bytes(wrapper), "record/v1")
    except (TypeError, ValueError) as exc:
        raise InvalidCommissionError(
            f"{label} is not strict JSON evidence: {exc}"
        ) from exc
    payload = _canonical_bytes(normalized)
    try:
        contract_codec.canonical_digest(payload)
    except (TypeError, ValueError) as exc:
        raise InvalidCommissionError(
            f"{label} has no canonical digest: {exc}"
        ) from exc
    return payload


def _digest_of(payload: bytes) -> str:
    return str(contract_codec.canonical_digest(payload))


# ---------------------------------------------------------------------------
# Field validators
# ---------------------------------------------------------------------------


def _require_identifier(value: Any, field_name: str) -> str:
    if not isinstance(value, str):
        raise InvalidCommissionError(f"{field_name} must be a str")
    if not value or value != value.strip():
        raise InvalidCommissionError(
            f"{field_name} must be a nonempty identifier without padding"
        )
    if len(value) > _MAX_IDENTIFIER_LEN:
        raise InvalidCommissionError(
            f"{field_name} must be at most {_MAX_IDENTIFIER_LEN} characters"
        )
    if any(ord(ch) < 0x20 for ch in value):
        raise InvalidCommissionError(
            f"{field_name} must not contain control characters"
        )
    return value


def _require_digest(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.match(value):
        raise InvalidCommissionError(
            f"{field_name} must be a sha256:<64 lowercase hex> digest"
        )
    return value


def _require_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidCommissionError(f"{field_name} must be an int")
    return value


def _require_positive_int(value: Any, field_name: str) -> int:
    number = _require_int(value, field_name)
    if number < 1 or number > _MAX_SAFE_INT:
        raise InvalidCommissionError(f"{field_name} must be a positive safe integer")
    return number


def _require_nonnegative_number(value: Any, field_name: str) -> int | float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise InvalidCommissionError(f"{field_name} must be a number")
    if isinstance(value, float) and (value != value or value in (float("inf"), float("-inf"))):
        raise InvalidCommissionError(f"{field_name} must be finite")
    if value < 0:
        raise InvalidCommissionError(f"{field_name} must be nonnegative")
    return value


def _require_exact_keys(
    value: Any, required: frozenset[str] | set[str], label: str
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise InvalidCommissionError(f"{label} must be a mapping")
    keys = set(value.keys())
    missing = set(required) - keys
    if missing:
        raise InvalidCommissionError(
            f"{label} is missing required keys: {sorted(missing)}"
        )
    extra = keys - set(required)
    if extra:
        raise InvalidCommissionError(
            f"{label} has undeclared properties: {sorted(extra)}"
        )
    return value


def _require_maybe_string(value: Any, field_name: str) -> Any:
    if _is_missing(value):
        return _jsonable(value, field_name)
    return _require_identifier(value, field_name)


def _require_maybe_digest(value: Any, field_name: str) -> Any:
    if _is_missing(value):
        return _jsonable(value, field_name)
    return _require_digest(value, field_name)


def _require_artifact_ref(value: Any, field_name: str) -> dict[str, Any]:
    if is_dataclass(value) and not isinstance(value, type):
        if hasattr(value, "to_dict"):
            try:
                as_dict = value.to_dict()  # type: ignore[union-attr]
            except Exception as exc:
                raise InvalidCommissionError(
                    f"{field_name} is not an ArtifactReference: {exc}"
                ) from exc
            if isinstance(as_dict, Mapping):
                value = as_dict
    data = _require_exact_keys(
        value, frozenset({"digest", "size_bytes", "media_type", "owner_domain", "access"}), field_name
    )
    digest = _require_digest(data["digest"], f"{field_name}.digest")
    size = _require_int(data["size_bytes"], f"{field_name}.size_bytes")
    if size < 0 or size > _MAX_SAFE_INT:
        raise InvalidCommissionError(
            f"{field_name}.size_bytes must be a nonnegative safe integer"
        )
    media_type = _require_identifier(data["media_type"], f"{field_name}.media_type")
    owner_domain = _require_identifier(data["owner_domain"], f"{field_name}.owner_domain")
    access = data["access"]
    if access not in ("public", "restricted"):
        raise InvalidCommissionError(f"{field_name}.access must be public or restricted")
    return {
        "digest": digest,
        "size_bytes": size,
        "media_type": media_type,
        "owner_domain": owner_domain,
        "access": access,
    }


def _require_artifact_or_missing(value: Any, field_name: str) -> dict[str, Any]:
    if _is_missing(value):
        return _jsonable(value, field_name)
    return _require_artifact_ref(value, field_name)


def _require_evidence_ref(value: Any, field_name: str) -> dict[str, Any]:
    if is_dataclass(value) and not isinstance(value, type):
        if hasattr(value, "to_dict"):
            try:
                as_dict = value.to_dict()  # type: ignore[union-attr]
            except Exception as exc:
                raise InvalidCommissionError(
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
    sequence = _require_positive_int(data["sequence"], f"{field_name}.sequence")
    event_id = _require_identifier(data["event_id"], f"{field_name}.event_id")
    event_hash = _require_digest(data["event_hash"], f"{field_name}.event_hash")
    pointer = data["pointer"]
    if not isinstance(pointer, str) or not _POINTER_RE.match(pointer):
        raise InvalidCommissionError(f"{field_name}.pointer is not a valid JSON pointer")
    return {
        "journal_id": journal_id,
        "sequence": sequence,
        "event_id": event_id,
        "event_hash": event_hash,
        "pointer": pointer,
    }


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


def _require_timepoint(value: Any, field_name: str) -> dict[str, Any]:
    if is_dataclass(value) and not isinstance(value, type):
        if hasattr(value, "to_dict"):
            try:
                as_dict = value.to_dict()  # type: ignore[union-attr]
            except Exception as exc:
                raise InvalidCommissionError(
                    f"{field_name} is not a TimePoint: {exc}"
                ) from exc
            if isinstance(as_dict, Mapping):
                value = as_dict
    data = _require_exact_keys(
        value,
        frozenset({"clock_id", "boot_id", "origin", "monotonic_offset_ms", "utc_annotation"}),
        field_name,
    )
    clock_id = _require_identifier(data["clock_id"], f"{field_name}.clock_id")
    boot_id = _require_identifier(data["boot_id"], f"{field_name}.boot_id")
    origin = data["origin"]
    if origin not in _VALID_ORIGINS:
        raise InvalidCommissionError(f"{field_name}.origin is invalid: {origin!r}")
    offset = _require_nonnegative_number(
        data["monotonic_offset_ms"], f"{field_name}.monotonic_offset_ms"
    )
    utc = data["utc_annotation"]
    if _is_missing(utc):
        utc_norm: Any = _jsonable(utc, f"{field_name}.utc_annotation")
    elif isinstance(utc, str) and utc:
        utc_norm = utc
    else:
        raise InvalidCommissionError(
            f"{field_name}.utc_annotation must be a date-time string or Missing"
        )
    return {
        "clock_id": clock_id,
        "boot_id": boot_id,
        "origin": origin,
        "monotonic_offset_ms": offset,
        "utc_annotation": utc_norm,
    }


def _require_attempt_link(value: Any, field_name: str) -> dict[str, Any]:
    data = _require_exact_keys(value, frozenset({"attempt_id", "kind"}), field_name)
    attempt_id = _require_identifier(data["attempt_id"], f"{field_name}.attempt_id")
    kind = data["kind"]
    if kind not in _VALID_KINDS:
        raise InvalidCommissionError(f"{field_name}.kind is invalid: {kind!r}")
    return {"attempt_id": attempt_id, "kind": kind}


def _require_attempt_context(value: Any) -> dict[str, Any]:
    data = _require_exact_keys(
        value,
        frozenset(
            {
                "attempt_id",
                "kind",
                "target_class",
                "target_id",
                "evaluation_partition",
                "rehearsal_of",
                "performance_of",
                "derived_from",
            }
        ),
        "attempt",
    )
    attempt_id = _require_identifier(data["attempt_id"], "attempt.attempt_id")
    kind = data["kind"]
    if kind not in _VALID_KINDS:
        raise InvalidCommissionError(f"attempt.kind is invalid: {kind!r}")
    target_class = data["target_class"]
    if target_class not in _VALID_TARGET_CLASSES:
        raise InvalidCommissionError(f"attempt.target_class is invalid: {target_class!r}")
    target_id = _require_identifier(data["target_id"], "attempt.target_id")
    partition = data["evaluation_partition"]
    if partition not in _VALID_PARTITIONS:
        raise InvalidCommissionError(
            f"attempt.evaluation_partition is invalid: {partition!r}"
        )
    links: dict[str, list[dict[str, Any]]] = {}
    for field_name in ("rehearsal_of", "performance_of", "derived_from"):
        raw = data[field_name]
        if isinstance(raw, (str, bytes)) or not isinstance(raw, Sequence):
            raise InvalidCommissionError(f"attempt.{field_name} must be a sequence")
        seen: set[tuple[str, str]] = set()
        normalized: list[dict[str, Any]] = []
        for index, item in enumerate(raw):
            link = _require_attempt_link(item, f"attempt.{field_name}[{index}]")
            key = (link["attempt_id"], link["kind"])
            if key in seen:
                raise InvalidCommissionError(
                    f"attempt.{field_name} has a duplicate link: {key!r}"
                )
            seen.add(key)
            normalized.append(link)
        links[field_name] = normalized
    # Contract allOf guards (kind/target/partition + lineage direction).
    if target_class == "laboratory_fixture":
        if kind != "practice" or partition != "held_in":
            raise InvalidCommissionError(
                "a laboratory_fixture attempt requires practice and held_in"
            )
    else:
        if partition != "held_out":
            raise InvalidCommissionError(
                "an employer_origin attempt requires held_out"
            )
    if kind == "practice":
        if target_class != "laboratory_fixture" or partition != "held_in":
            raise InvalidCommissionError(
                "a practice attempt requires laboratory_fixture and held_in"
            )
        if links["performance_of"]:
            raise InvalidCommissionError(
                "a practice attempt must not carry performance_of links"
            )
        for link in links["rehearsal_of"]:
            if link["kind"] != "production":
                raise InvalidCommissionError(
                    "practice rehearsal_of links must name production attempts"
                )
        for link in links["derived_from"]:
            if link["kind"] != "practice":
                raise InvalidCommissionError(
                    "practice derived_from links must name practice attempts"
                )
    else:
        if target_class != "employer_origin":
            raise InvalidCommissionError(
                "a production attempt requires employer_origin"
            )
        if links["rehearsal_of"]:
            raise InvalidCommissionError(
                "a production attempt must not carry rehearsal_of links"
            )
        for link in links["performance_of"]:
            if link["kind"] != "practice":
                raise InvalidCommissionError(
                    "production performance_of links must name practice attempts"
                )
        for link in links["derived_from"]:
            if link["kind"] != "production":
                raise InvalidCommissionError(
                    "production derived_from links must name production attempts"
                )
    return {
        "attempt_id": attempt_id,
        "kind": kind,
        "target_class": target_class,
        "target_id": target_id,
        "evaluation_partition": partition,
        "rehearsal_of": links["rehearsal_of"],
        "performance_of": links["performance_of"],
        "derived_from": links["derived_from"],
    }


def _require_component_identity(value: Any, field_name: str) -> dict[str, Any]:
    data = _require_exact_keys(
        value,
        frozenset(
            {"component", "reported_version", "build_digest", "configuration_digest"}
        ),
        field_name,
    )
    return {
        "component": _require_identifier(data["component"], f"{field_name}.component"),
        "reported_version": _require_maybe_string(
            data["reported_version"], f"{field_name}.reported_version"
        ),
        "build_digest": _require_maybe_digest(
            data["build_digest"], f"{field_name}.build_digest"
        ),
        "configuration_digest": _require_maybe_digest(
            data["configuration_digest"], f"{field_name}.configuration_digest"
        ),
    }


def _require_subject_identity(value: Any) -> dict[str, Any]:
    data = _require_exact_keys(
        value,
        frozenset(
            {
                "subject_id",
                "subject_version",
                "revision_basis",
                "native_revision",
                "configured_mode",
                "interface_surface",
                "configuration_digest",
                "stack",
            }
        ),
        "execution.subject",
    )
    basis = data["revision_basis"]
    if basis not in _VALID_REVISION_BASES:
        raise InvalidCommissionError(
            f"execution.subject.revision_basis is invalid: {basis!r}"
        )
    stack_raw = data["stack"]
    if isinstance(stack_raw, (str, bytes)) or not isinstance(stack_raw, Sequence):
        raise InvalidCommissionError("execution.subject.stack must be a sequence")
    stack = [
        _require_component_identity(item, f"execution.subject.stack[{index}]")
        for index, item in enumerate(stack_raw)
    ]
    return {
        "subject_id": _require_identifier(
            data["subject_id"], "execution.subject.subject_id"
        ),
        "subject_version": _require_identifier(
            data["subject_version"], "execution.subject.subject_version"
        ),
        "revision_basis": basis,
        "native_revision": _require_maybe_string(
            data["native_revision"], "execution.subject.native_revision"
        ),
        "configured_mode": _require_identifier(
            data["configured_mode"], "execution.subject.configured_mode"
        ),
        "interface_surface": _require_identifier(
            data["interface_surface"], "execution.subject.interface_surface"
        ),
        "configuration_digest": _require_digest(
            data["configuration_digest"], "execution.subject.configuration_digest"
        ),
        "stack": stack,
    }


def _require_assistance(value: Any) -> dict[str, Any]:
    data = _require_exact_keys(
        value,
        frozenset(
            {
                "planning_owner",
                "assistance_track",
                "planner_identity",
                "plan",
                "online_replanning",
                "description",
            }
        ),
        "execution.assistance",
    )
    owner = data["planning_owner"]
    if owner not in _VALID_PLANNING_OWNERS:
        raise InvalidCommissionError(
            f"execution.assistance.planning_owner is invalid: {owner!r}"
        )
    track = _require_identifier(
        data["assistance_track"], "execution.assistance.assistance_track"
    )
    planner = _require_maybe_string(
        data["planner_identity"], "execution.assistance.planner_identity"
    )
    plan = _require_artifact_or_missing(data["plan"], "execution.assistance.plan")
    online = data["online_replanning"]
    if type(online) is not bool:
        raise InvalidCommissionError(
            "execution.assistance.online_replanning must be a bool"
        )
    description = data["description"]
    if not isinstance(description, str) or not description:
        raise InvalidCommissionError(
            "execution.assistance.description must be a nonempty string"
        )
    return {
        "planning_owner": owner,
        "assistance_track": track,
        "planner_identity": planner,
        "plan": plan,
        "online_replanning": online,
        "description": description,
    }


def _require_execution(value: Any) -> dict[str, Any]:
    data = _require_exact_keys(
        value,
        frozenset(
            {"mode", "subject", "connector_version", "binding_version", "assistance"}
        ),
        "execution",
    )
    mode = data["mode"]
    if mode not in _VALID_MODES:
        raise InvalidCommissionError(
            f"execution.mode must be manual or subject, got {mode!r}"
        )
    if mode == "manual":
        for field_name in ("subject", "connector_version", "binding_version"):
            reason = _missing_reason(data[field_name])
            if reason != "not_applicable":
                raise InvalidCommissionError(
                    f"manual execution requires Missing(not_applicable) "
                    f"for {field_name}"
                )
        subject: Any = _missing_dict("not_applicable")
        connector: Any = _missing_dict("not_applicable")
        binding: Any = _missing_dict("not_applicable")
    else:
        subject = _require_subject_identity(data["subject"])
        connector = _require_identifier(
            data["connector_version"], "execution.connector_version"
        )
        binding = _require_identifier(
            data["binding_version"], "execution.binding_version"
        )
    assistance = _require_assistance(data["assistance"])
    return {
        "mode": mode,
        "subject": subject,
        "connector_version": connector,
        "binding_version": binding,
        "assistance": assistance,
    }


def _require_job_reference(value: Any) -> dict[str, Any]:
    # Exactly four fields: no crawler coverage, render verdict, revision, or
    # JobEntityKey may be smuggled into a commission.
    data = _require_exact_keys(
        value, frozenset({"job_id", "source_target", "source_job_id", "snapshot"}), "job"
    )
    job_id = _require_identifier(data["job_id"], "job.job_id")
    source_target: Any
    source_job_id: Any
    for field_name in ("source_target", "source_job_id"):
        raw = data[field_name]
        if _is_missing(raw):
            reason = _missing_reason(raw)
            if reason != "not_observed":
                raise InvalidCommissionError(
                    f"job.{field_name} uses Missing({reason}); unknown manual "
                    "discovery must use Missing(not_observed)"
                )
            normalized = _jsonable(raw, f"job.{field_name}")
        else:
            normalized = _require_identifier(raw, f"job.{field_name}")
        if field_name == "source_target":
            source_target = normalized
        else:
            source_job_id = normalized
    snapshot = _require_artifact_ref(data["snapshot"], "job.snapshot")
    return {
        "job_id": job_id,
        "source_target": source_target,
        "source_job_id": source_job_id,
        "snapshot": snapshot,
    }


def _require_owner_binding(
    value: Any, domain: str, expected_role: str, manual_inapplicable: bool
) -> dict[str, Any]:
    data = _require_exact_keys(
        value,
        frozenset({"role", "source_id", "writer_id", "owner_domain", "publication_policy"}),
        f"owners.{domain}",
    )
    role = data["role"]
    if role != expected_role:
        raise InvalidCommissionError(
            f"owners.{domain}.role must be {expected_role!r}, got {role!r}"
        )
    owner_domain = _require_identifier(
        data["owner_domain"], f"owners.{domain}.owner_domain"
    )
    policy = _require_version_pin(
        data["publication_policy"], f"owners.{domain}.publication_policy"
    )
    if manual_inapplicable:
        for field_name in ("source_id", "writer_id"):
            reason = _missing_reason(data[field_name])
            if reason != "not_applicable":
                raise InvalidCommissionError(
                    f"owners.{domain}.{field_name} must be "
                    "Missing(not_applicable) for a manual attempt"
                )
        source: Any = _missing_dict("not_applicable")
        writer: Any = _missing_dict("not_applicable")
    else:
        source = _require_identifier(data["source_id"], f"owners.{domain}.source_id")
        writer = _require_identifier(data["writer_id"], f"owners.{domain}.writer_id")
    return {
        "role": role,
        "source_id": source,
        "writer_id": writer,
        "owner_domain": owner_domain,
        "publication_policy": policy,
    }


def _require_owners(
    value: Any, attempt: Mapping[str, Any], execution: Mapping[str, Any]
) -> dict[str, Any]:
    data = _require_exact_keys(value, frozenset(_OWNER_DOMAINS), "owners")
    manual = execution["mode"] == "manual"
    normalized: dict[str, Any] = {}
    for domain in _OWNER_DOMAINS:
        inapplicable = manual and domain in ("dispatch", "execution")
        normalized[domain] = _require_owner_binding(
            data[domain], domain, _VALID_ROLES[domain], inapplicable
        )
    # Exactly one owner domain per axis; exactly one bound writer per
    # applicable axis; writers never shared across axes.
    seen_domains: set[str] = set()
    for domain in _OWNER_DOMAINS:
        owner_domain = normalized[domain]["owner_domain"]
        if owner_domain in seen_domains:
            raise InvalidCommissionError(
                f"owner domain {owner_domain!r} is declared more than once"
            )
        seen_domains.add(owner_domain)
    seen_writers: set[str] = set()
    for domain in _OWNER_DOMAINS:
        writer = normalized[domain]["writer_id"]
        if _is_missing(writer):
            continue
        assert isinstance(writer, str)
        if writer in seen_writers:
            raise InvalidCommissionError(
                "each applicable domain needs its own bound publication writer"
            )
        seen_writers.add(writer)
    # The report writer must not hold execution/application write authority.
    report_writer = normalized["report"]["writer_id"]
    if not _is_missing(report_writer):
        for other in ("execution", "application"):
            other_writer = normalized[other]["writer_id"]
            if not _is_missing(other_writer) and other_writer == report_writer:
                raise InvalidCommissionError(
                    "the report writer must not hold execution/application "
                    "write authority"
                )
    # Authoritative-source identity is preserved in the bindings.
    app_source = normalized["application"]["source_id"]
    if isinstance(app_source, str) and app_source != attempt["target_id"]:
        raise InvalidCommissionError(
            "application.source_id must identify the commissioned target"
        )
    if execution["mode"] == "subject":
        exec_source = normalized["execution"]["source_id"]
        subject = execution["subject"]
        if (
            isinstance(exec_source, str)
            and isinstance(subject, Mapping)
            and subject.get("subject_id") != exec_source
        ):
            raise InvalidCommissionError(
                "execution.source_id must identify the commissioned subject"
            )
    return normalized


def _require_duration_limit(value: Any, field_name: str) -> dict[str, Any]:
    data = _require_exact_keys(value, frozenset({"kind", "unit", "value"}), field_name)
    if data["kind"] != "exact":
        raise InvalidCommissionError(f"{field_name}.kind must be exact")
    if data["unit"] != "ms":
        raise InvalidCommissionError(f"{field_name}.unit must be ms")
    number = _require_nonnegative_number(data["value"], f"{field_name}.value")
    return {"kind": "exact", "unit": "ms", "value": number}


def _require_observation_policy(value: Any) -> dict[str, Any]:
    data = _require_exact_keys(
        value,
        frozenset(
            {
                "active_limit",
                "drain_limit",
                "native_cancel_wait_limit",
                "cleanup_wait_limit",
                "fixture_close_action",
            }
        ),
        "observation_policy",
    )
    policy = {
        "active_limit": _require_duration_limit(
            data["active_limit"], "observation_policy.active_limit"
        ),
        "drain_limit": _require_duration_limit(
            data["drain_limit"], "observation_policy.drain_limit"
        ),
        "native_cancel_wait_limit": _require_duration_limit(
            data["native_cancel_wait_limit"],
            "observation_policy.native_cancel_wait_limit",
        ),
        "cleanup_wait_limit": _require_duration_limit(
            data["cleanup_wait_limit"], "observation_policy.cleanup_wait_limit"
        ),
    }
    action = data["fixture_close_action"]
    if action not in _VALID_FIXTURE_ACTIONS:
        raise InvalidCommissionError(
            f"observation_policy.fixture_close_action is invalid: {action!r}"
        )
    policy["fixture_close_action"] = action
    return policy


def _validate_commission(commission: Any) -> dict[str, Any]:
    """Validate a commission record and return its normalized mapping."""
    if isinstance(commission, AttemptCommission):
        raw: Mapping[str, Any] = commission.to_dict()
    elif isinstance(commission, Mapping):
        raw = AttemptCommission.from_dict(commission).to_dict()
    else:
        raise InvalidCommissionError(
            "commission must be an AttemptCommission or mapping"
        )
    _require_exact_keys(
        raw,
        frozenset(
            {
                "record_type",
                "schema_version",
                "kernel_version",
                "commission_id",
                "run_id",
                "journal_id",
                "manifest_hash",
                "admission_ref",
                "commissioned_by",
                "commissioned_at",
                "attempt",
                "candidate_id",
                "candidate_profile",
                "job",
                "selection_evidence",
                "task",
                "task_semantic_hash",
                "initial_materials",
                "execution",
                "owners",
                "idempotency_key",
                "authorization_refs",
                "recovery_review_refs",
                "observation_policy",
                "origin_policy",
            }
        ),
        "AttemptCommission",
    )
    if raw["record_type"] != RECORD_TYPE:
        raise InvalidCommissionError(
            f"record_type must be {RECORD_TYPE!r}, got {raw['record_type']!r}"
        )
    if raw["schema_version"] != SCHEMA_VERSION:
        raise InvalidCommissionError(
            f"schema_version must be {SCHEMA_VERSION!r}, got {raw['schema_version']!r}"
        )
    if raw["kernel_version"] != KERNEL_VERSION:
        raise InvalidCommissionError(
            f"kernel_version must be {KERNEL_VERSION!r}, got {raw['kernel_version']!r}"
        )
    commission_id = _require_identifier(raw["commission_id"], "commission_id")
    run_id = _require_identifier(raw["run_id"], "run_id")
    journal_id = _require_identifier(raw["journal_id"], "journal_id")
    manifest_hash = _require_digest(raw["manifest_hash"], "manifest_hash")
    admission_ref = _require_evidence_ref(raw["admission_ref"], "admission_ref")
    commissioned_by = _require_identifier(raw["commissioned_by"], "commissioned_by")
    commissioned_at = _require_timepoint(raw["commissioned_at"], "commissioned_at")
    attempt = _require_attempt_context(raw["attempt"])
    candidate_id = _require_identifier(raw["candidate_id"], "candidate_id")
    candidate_profile = _require_artifact_or_missing(
        raw["candidate_profile"], "candidate_profile"
    )
    job = _require_job_reference(raw["job"])
    selection_evidence = _require_artifact_or_missing(
        raw["selection_evidence"], "selection_evidence"
    )
    task = _require_artifact_ref(raw["task"], "task")
    task_semantic_hash = _require_digest(
        raw["task_semantic_hash"], "task_semantic_hash"
    )
    materials_raw = raw["initial_materials"]
    if isinstance(materials_raw, (str, bytes)) or not isinstance(materials_raw, Sequence):
        raise InvalidCommissionError("initial_materials must be a sequence")
    materials: list[dict[str, Any]] = []
    seen_digests: set[str] = set()
    for index, item in enumerate(materials_raw):
        ref = _require_artifact_ref(item, f"initial_materials[{index}]")
        if ref["digest"] in seen_digests:
            raise InvalidCommissionError(
                f"initial_materials has a duplicate digest {ref['digest']}"
            )
        seen_digests.add(ref["digest"])
        materials.append(ref)
    execution = _require_execution(raw["execution"])
    owners = _require_owners(raw["owners"], attempt, execution)
    idempotency_key = _require_identifier(raw["idempotency_key"], "idempotency_key")
    auth_raw = raw["authorization_refs"]
    if isinstance(auth_raw, (str, bytes)) or not isinstance(auth_raw, Sequence):
        raise InvalidCommissionError("authorization_refs must be a sequence")
    if not auth_raw:
        raise InvalidCommissionError(
            "authorization_refs must be nonempty task authority"
        )
    authorization_refs: list[dict[str, Any]] = []
    seen_refs: set[tuple[str, int, str, str, str]] = set()
    for index, item in enumerate(auth_raw):
        ref = _require_evidence_ref(item, f"authorization_refs[{index}]")
        key = (
            ref["journal_id"],
            ref["sequence"],
            ref["event_id"],
            ref["event_hash"],
            ref["pointer"],
        )
        if key in seen_refs:
            raise InvalidCommissionError("authorization_refs has a duplicate entry")
        seen_refs.add(key)
        authorization_refs.append(ref)
    recovery_raw = raw["recovery_review_refs"]
    if isinstance(recovery_raw, (str, bytes)) or not isinstance(recovery_raw, Sequence):
        raise InvalidCommissionError("recovery_review_refs must be a sequence")
    recovery_review_refs: list[dict[str, Any]] = []
    seen_recovery: set[tuple[str, int, str, str, str]] = set()
    for index, item in enumerate(recovery_raw):
        ref = _require_evidence_ref(item, f"recovery_review_refs[{index}]")
        key = (
            ref["journal_id"],
            ref["sequence"],
            ref["event_id"],
            ref["event_hash"],
            ref["pointer"],
        )
        if key in seen_recovery:
            raise InvalidCommissionError("recovery_review_refs has a duplicate entry")
        seen_recovery.add(key)
        recovery_review_refs.append(ref)
    observation_policy = _require_observation_policy(raw["observation_policy"])
    origin_policy = _require_version_pin(raw["origin_policy"], "origin_policy")
    # Cross-record guards.
    if (
        attempt["target_class"] == "employer_origin"
        and observation_policy["fixture_close_action"] != "not_applicable"
    ):
        raise InvalidCommissionError(
            "employer_origin attempts require fixture_close_action not_applicable"
        )
    return {
        "record_type": RECORD_TYPE,
        "schema_version": SCHEMA_VERSION,
        "kernel_version": KERNEL_VERSION,
        "commission_id": commission_id,
        "run_id": run_id,
        "journal_id": journal_id,
        "manifest_hash": manifest_hash,
        "admission_ref": admission_ref,
        "commissioned_by": commissioned_by,
        "commissioned_at": commissioned_at,
        "attempt": attempt,
        "candidate_id": candidate_id,
        "candidate_profile": candidate_profile,
        "job": job,
        "selection_evidence": selection_evidence,
        "task": task,
        "task_semantic_hash": task_semantic_hash,
        "initial_materials": materials,
        "execution": execution,
        "owners": owners,
        "idempotency_key": idempotency_key,
        "authorization_refs": authorization_refs,
        "recovery_review_refs": recovery_review_refs,
        "observation_policy": observation_policy,
        "origin_policy": origin_policy,
    }


# ---------------------------------------------------------------------------
# Commission store (idempotency + identity + lineage)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _AttemptEntry:
    fingerprint: str
    reference: Any  # artifact_store.ArtifactReference
    record: dict[str, Any]
    principal_id: str
    commission_id: str
    attempt_id: str


@dataclass(frozen=True, slots=True)
class _IdempotencyEntry:
    fingerprint: str
    reference: Any
    attempt_id: str
    commission_id: str


_LOCK = threading.RLock()
_ATTEMPTS: dict[str, _AttemptEntry] = {}
_COMMISSIONS: dict[str, _AttemptEntry] = {}
_IDEMPOTENCY: dict[tuple[str, str], _IdempotencyEntry] = {}


def _derived_graph_includes_cycle(
    new_attempt_id: str, new_derived: Sequence[Mapping[str, Any]]
) -> bool:
    """True when the new derived_from edges close a derivation cycle."""
    adjacency: dict[str, list[str]] = {}
    for attempt_id, entry in _ATTEMPTS.items():
        adjacency[attempt_id] = [
            link["attempt_id"] for link in entry.record["attempt"]["derived_from"]
        ]
    adjacency[new_attempt_id] = [link["attempt_id"] for link in new_derived]
    # A cycle can only be new: prior commissions were acyclic. Check whether
    # the new identity is reachable from any of its own derivation targets.
    stack = list(adjacency[new_attempt_id])
    seen = {new_attempt_id}
    while stack:
        current = stack.pop()
        if current == new_attempt_id:
            return True
        if current in seen:
            continue
        seen.add(current)
        stack.extend(adjacency.get(current, ()))
    return False


def _check_stored_guards(
    record: dict[str, Any], fingerprint: str, principal_id: str
) -> Any | None:
    """Enforce idempotency, identity, duplicate-risk, and lineage guards.

    Returns an existing artifact reference for an idempotent retry, else None.
    """
    attempt_id = record["attempt"]["attempt_id"]
    commission_id = record["commission_id"]
    idem_key = (principal_id, record["idempotency_key"])
    with _LOCK:
        idem = _IDEMPOTENCY.get(idem_key)
        if idem is not None:
            if idem.fingerprint != fingerprint:
                raise IdempotencyConflictError(
                    f"changed content under idempotency key "
                    f"{record['idempotency_key']!r} is rejected"
                )
            return idem.reference
        commission_entry = _COMMISSIONS.get(commission_id)
        if commission_entry is not None:
            if commission_entry.fingerprint != fingerprint:
                raise CommissionConflictError(
                    f"commission {commission_id!r} already holds different bytes"
                )
            return commission_entry.reference
        attempt_entry = _ATTEMPTS.get(attempt_id)
        if attempt_entry is not None:
            if attempt_entry.fingerprint != fingerprint:
                raise NewIdentityRequiredError(
                    f"attempt {attempt_id!r} is already commissioned with "
                    "different immutable content; changing kind, candidate, "
                    "target, job/task identity, subject version, execution "
                    "configuration, task permissions, or logical execution "
                    "requires a new attempt"
                )
            return attempt_entry.reference
        # Duplicate-risk review: same candidate + same portfolio job under a
        # new attempt identity requires evidenced review support.
        for prior in _ATTEMPTS.values():
            if (
                prior.record["candidate_id"] == record["candidate_id"]
                and prior.record["job"]["job_id"] == record["job"]["job_id"]
            ):
                if not record["recovery_review_refs"]:
                    raise DuplicateRiskReviewRequiredError(
                        f"attempt {attempt_id!r} re-targets candidate "
                        f"{record['candidate_id']!r} and job "
                        f"{record['job']['job_id']!r} without evidenced "
                        "duplicate-risk review"
                    )
                break
        # Lineage links resolve to already commissioned identities and confer
        # no outcome; they never promote commitment or authorize production.
        attempt = record["attempt"]
        for field_name in ("rehearsal_of", "performance_of", "derived_from"):
            for link in attempt[field_name]:
                target_id = link["attempt_id"]
                if target_id == attempt_id:
                    raise LineageError(
                        f"attempt {attempt_id!r} must not link to itself "
                        f"via {field_name}"
                    )
                target = _ATTEMPTS.get(target_id)
                if target is None:
                    raise LineageError(
                        f"attempt {attempt_id!r} links {field_name} to "
                        f"uncommissioned attempt {target_id!r}; lineage links "
                        "resolve to already commissioned identities"
                    )
                actual_kind = target.record["attempt"]["kind"]
                if actual_kind != link["kind"]:
                    raise LineageError(
                        f"attempt {attempt_id!r} links {field_name} to "
                        f"{target_id!r} as {link['kind']!r} but the "
                        f"commissioned kind is {actual_kind!r}"
                    )
        if _derived_graph_includes_cycle(attempt_id, attempt["derived_from"]):
            raise LineageError(
                f"attempt {attempt_id!r} would close a derived_from cycle"
            )
        return None


def _store_commission(
    record: dict[str, Any],
    fingerprint: str,
    principal_id: str,
    reference: Any,
) -> None:
    attempt_id = record["attempt"]["attempt_id"]
    commission_id = record["commission_id"]
    entry = _AttemptEntry(
        fingerprint=fingerprint,
        reference=reference,
        record=record,
        principal_id=principal_id,
        commission_id=commission_id,
        attempt_id=attempt_id,
    )
    idem_entry = _IdempotencyEntry(
        fingerprint=fingerprint,
        reference=reference,
        attempt_id=attempt_id,
        commission_id=commission_id,
    )
    with _LOCK:
        _ATTEMPTS[attempt_id] = entry
        _COMMISSIONS[commission_id] = entry
        _IDEMPOTENCY[(principal_id, record["idempotency_key"])] = idem_entry


# ---------------------------------------------------------------------------
# Authentication + admission + input verification
# ---------------------------------------------------------------------------


def _authenticate(
    channel_id: str, record: dict[str, Any]
) -> tuple[Any, str]:
    """Authorize the commissioning channel against one owner binding."""
    if not isinstance(channel_id, str) or not channel_id:
        raise CommissionAuthError("channel_id must be a nonempty identifier")
    commission_id = record["commission_id"]
    owners = record["owners"]
    descriptor: Any | None = None
    matched_domain: str | None = None
    unknown_channel: Exception | None = None
    for domain in _OWNER_DOMAINS:
        owner_domain = owners[domain]["owner_domain"]
        operation = f"{owner_domain}.write"
        try:
            candidate = access_policy.authorize(
                channel_id, operation, commission_id
            )
        except access_policy.UnknownChannelError as exc:
            unknown_channel = exc
            break
        except access_policy.AuthorizationError:
            continue
        except (TypeError, ValueError):
            continue
        descriptor = candidate
        matched_domain = owner_domain
        break
    if unknown_channel is not None:
        raise CommissionAuthError(
            f"unknown channel {channel_id!r}: {unknown_channel}"
        ) from unknown_channel
    if descriptor is None or matched_domain is None:
        raise CommissionAuthError(
            "the authenticated channel holds no write grant for any "
            "commissioned owner domain"
        )
    # The commissioning channel must be the bound writer of its own domain.
    bound: dict[str, Any] | None = None
    for domain in _OWNER_DOMAINS:
        if owners[domain]["owner_domain"] == matched_domain:
            bound = owners[domain]
            break
    assert bound is not None
    writer = bound["writer_id"]
    if _is_missing(writer):
        raise CommissionAuthError(
            f"owner domain {matched_domain!r} has no applicable publication "
            "writer for this commission"
        )
    if descriptor.owner_domain != matched_domain:
        raise CommissionAuthError(
            f"authenticated producer writes {descriptor.owner_domain!r}, not "
            f"{matched_domain!r}"
        )
    if descriptor.producer_id != writer:
        raise CommissionAuthError(
            "the serialized writer_id is not the authenticated producer"
        )
    commissioned_by = record["commissioned_by"]
    if commissioned_by not in (descriptor.producer_id, descriptor.principal_id):
        raise CommissionAuthError(
            "commissioned_by is not the authenticated commissioning principal"
        )
    return descriptor, matched_domain


def _verify_manifest(
    channel_id: str, record: dict[str, Any], matched_domain: str
) -> dict[str, Any]:
    """Verify admission exists and the commission agrees with the manifest."""
    admission_ref = record["admission_ref"]
    if admission_ref["journal_id"] != record["journal_id"]:
        raise ManifestAgreementError(
            "admission_ref.journal_id must equal the commission journal_id"
        )
    if admission_ref["sequence"] != 1:
        raise ManifestAgreementError(
            "admission_ref must cite journal sequence 1 (manifest_admitted)"
        )
    prefix = evidence_journal.JournalPrefix(
        journal_id=admission_ref["journal_id"],
        last_sequence=1,
        head_hash=admission_ref["event_hash"],
    )
    try:
        envelopes = evidence_journal.read_prefix(channel_id, prefix)
    except evidence_journal.JournalNotAdmittedError as exc:
        raise ManifestAgreementError(
            "the commission journal is not admitted; register a commission "
            "only after its manifest admission exists"
        ) from exc
    except access_policy.AuthorizationError as exc:
        raise CommissionAuthError(
            f"admission evidence is not readable: {exc}"
        ) from exc
    except evidence_journal.EvidenceJournalError as exc:
        raise ManifestAgreementError(
            f"admission prefix does not verify: {exc}"
        ) from exc
    if len(envelopes) != 1:
        raise ManifestAgreementError("admission prefix must hold exactly one event")
    envelope = envelopes[0]
    if envelope.event_kind != "manifest_admitted":
        raise ManifestAgreementError(
            f"admission event kind is {envelope.event_kind!r}, not manifest_admitted"
        )
    if envelope.journal_id != record["journal_id"]:
        raise ManifestAgreementError("admission journal_id does not match")
    if envelope.run_id != record["run_id"]:
        raise ManifestAgreementError("admission run_id does not match")
    if envelope.manifest_hash != record["manifest_hash"]:
        raise ManifestAgreementError("admission manifest_hash does not match")
    if envelope.owner_domain != matched_domain:
        raise ManifestAgreementError(
            f"admission owner {envelope.owner_domain!r} does not match the "
            f"commissioning domain {matched_domain!r}"
        )
    if envelope.event_id != admission_ref["event_id"]:
        raise ManifestAgreementError("admission_ref.event_id does not match")
    if envelope.event_hash != admission_ref["event_hash"]:
        raise ManifestAgreementError("admission_ref.event_hash does not match")
    # The retained manifest bytes are the agreement source of truth.
    try:
        payload = envelope.payload
        manifest_ref_raw = payload["data"]["manifest"]
        manifest_ref = artifact_store.ArtifactReference.from_dict(
            dict(manifest_ref_raw)
        )
        manifest_bytes = artifact_store.resolve_artifact(channel_id, manifest_ref)
    except artifact_store.ArtifactError as exc:
        raise ManifestAgreementError(
            f"admitted manifest bytes are unavailable: {exc}"
        ) from exc
    except (KeyError, TypeError, ValueError) as exc:
        raise ManifestAgreementError(
            f"admission payload carries no manifest reference: {exc}"
        ) from exc
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ManifestAgreementError(f"admitted manifest is not JSON: {exc}") from exc
    if not isinstance(manifest, Mapping):
        raise ManifestAgreementError("admitted manifest must be a mapping")
    if manifest.get("run_id") != record["run_id"]:
        raise ManifestAgreementError("manifest run_id does not match the commission")
    if manifest.get("journal_id") != record["journal_id"]:
        raise ManifestAgreementError(
            "manifest journal_id does not match the commission"
        )
    if manifest.get("owner_domain") != matched_domain:
        raise ManifestAgreementError("manifest owner_domain does not match")
    if manifest.get("activity") != "application_attempt":
        raise ManifestAgreementError(
            "application commissions require an application_attempt manifest"
        )
    manifest_attempt = manifest.get("attempt")
    if not isinstance(manifest_attempt, Mapping):
        raise ManifestAgreementError("manifest attempt must be an AttemptContext")
    for key in (
        "attempt_id",
        "kind",
        "target_class",
        "target_id",
        "evaluation_partition",
    ):
        if manifest_attempt.get(key) != record["attempt"][key]:
            raise ManifestAgreementError(
                f"manifest attempt.{key} does not match the commission"
            )
    for key in ("rehearsal_of", "performance_of", "derived_from"):
        if list(manifest_attempt.get(key, [])) != list(record["attempt"][key]):
            raise ManifestAgreementError(
                f"manifest attempt.{key} does not match the commission"
            )
    manifest_execution = manifest.get("execution")
    if not isinstance(manifest_execution, Mapping):
        raise ManifestAgreementError("manifest execution must be a mapping")
    if manifest_execution.get("mode") != record["execution"]["mode"]:
        raise ManifestAgreementError("manifest execution.mode does not match")
    manifest_task = manifest.get("task")
    if not isinstance(manifest_task, Mapping):
        raise ManifestAgreementError("manifest task must be an ArtifactReference")
    if manifest_task.get("digest") != record["task"]["digest"]:
        raise ManifestAgreementError("manifest task digest does not match")
    if manifest.get("task_semantic_hash") != record["task_semantic_hash"]:
        raise ManifestAgreementError("manifest task_semantic_hash does not match")
    if manifest.get("commissioner_id") != record["commissioned_by"]:
        # The manifest pins the authenticated admission ownership; the
        # commission pins the authenticated commissioning principal. They
        # agree on one authenticated principal for the attempt.
        raise ManifestAgreementError(
            "manifest commissioner_id does not match commissioned_by"
        )
    clocks = manifest.get("clocks", [])
    if not isinstance(clocks, Sequence) or isinstance(clocks, (str, bytes)):
        raise ManifestAgreementError("manifest clocks must be a sequence")
    commissioned_at = record["commissioned_at"]
    for clock in clocks:
        if not isinstance(clock, Mapping):
            continue
        if (
            clock.get("clock_id") == commissioned_at["clock_id"]
            and clock.get("boot_id") == commissioned_at["boot_id"]
        ):
            if clock.get("origin") != commissioned_at["origin"]:
                raise ManifestAgreementError(
                    "commissioned_at.origin disagrees with the registered clock"
                )
            break
    else:
        raise ManifestAgreementError(
            "commissioned_at names a clock/boot not registered by the manifest"
        )
    return dict(manifest)


def _verify_inputs(channel_id: str, record: dict[str, Any]) -> None:
    """Verify every commissioned input artifact is installed and resolvable."""
    refs: list[tuple[str, Mapping[str, Any]]] = [
        ("task", record["task"]),
        ("job.snapshot", record["job"]["snapshot"]),
    ]
    for index, item in enumerate(record["initial_materials"]):
        refs.append((f"initial_materials[{index}]", item))
    if not _is_missing(record["candidate_profile"]):
        refs.append(("candidate_profile", record["candidate_profile"]))
    if not _is_missing(record["selection_evidence"]):
        refs.append(("selection_evidence", record["selection_evidence"]))
    assistance_plan = record["execution"]["assistance"]["plan"]
    if not _is_missing(assistance_plan):
        refs.append(("execution.assistance.plan", assistance_plan))
    for label, raw in refs:
        try:
            ref = artifact_store.ArtifactReference.from_dict(dict(raw))
            artifact_store.resolve_artifact(channel_id, ref)
        except artifact_store.ArtifactError as exc:
            raise InvalidCommissionError(
                f"commissioned input {label} is not installed: {exc}"
            ) from exc
        except (TypeError, ValueError) as exc:
            raise InvalidCommissionError(
                f"commissioned input {label} is invalid: {exc}"
            ) from exc


# ---------------------------------------------------------------------------
# Durability: retain -> journal -> register
# ---------------------------------------------------------------------------


def _journal_commission(
    channel_id: str,
    matched_domain: str,
    record: dict[str, Any],
    commission_ref: Any,
) -> Any:
    """Journal the commission as an owner-local authoritative effect."""
    attempt_id = record["attempt"]["attempt_id"]
    commission_id = record["commission_id"]
    data = {
        "commission_id": commission_id,
        "attempt_id": attempt_id,
        "kind": record["attempt"]["kind"],
        "commission_digest": commission_ref.digest,
    }
    submission = evidence_journal.EventSubmission(
        producer_sequence={"value": None, "reason": "not_applicable"},
        event_kind=COMMISSION_EVENT_KIND,
        event_schema_version=COMMISSION_EVENT_VERSION,
        occurred_at=dict(record["commissioned_at"]),
        payload={
            "data": data,
            "measurements": [],
            "evidence_refs": [dict(record["admission_ref"])],
            "artifact_refs": [commission_ref.to_dict()],
        },
    )
    try:
        return evidence_journal.commit_effect(
            channel_id,
            matched_domain,
            attempt_id,
            commission_id,
            0,
            commission_ref,
            (submission,),
        )
    except evidence_journal.CommandConflictError as exc:
        raise IdempotencyConflictError(
            f"commission {commission_id!r} was already journaled with "
            "different content"
        ) from exc
    except evidence_journal.RevisionConflictError as exc:
        raise CommissionConflictError(
            f"attempt {attempt_id!r} already holds a journaled commission"
        ) from exc
    except access_policy.AuthorizationError as exc:
        raise CommissionAuthError(f"commission journaling is not authorized: {exc}") from exc
    except evidence_journal.EvidenceJournalError as exc:
        raise CommissionError(f"commission journaling failed: {exc}") from exc


def _register_attempt_entity(
    channel_id: str,
    record: dict[str, Any],
    commission_ref: Any,
    commit_prefix: Any,
) -> Any:
    """Register the owner-separated attempt entity citing the commit prefix."""
    attempt = record["attempt"]
    entity = {
        "entity_type": "application_attempt",
        "attempt_id": attempt["attempt_id"],
        "kind": attempt["kind"],
    }
    identity = {
        "commission": commission_ref.to_dict(),
        "attempt": {key: attempt[key] for key in sorted(attempt)},
        "execution": {key: record["execution"][key] for key in sorted(record["execution"])},
    }
    if hasattr(commit_prefix, "journal_id"):
        evidence_prefix = {
            "journal_id": commit_prefix.journal_id,
            "last_sequence": commit_prefix.last_sequence,
            "head_hash": commit_prefix.head_hash,
        }
    else:
        evidence_prefix = dict(commit_prefix)
    registration = owner_revisions.EntityRegistration(
        registration_id=f"reg_{record['commission_id']}",
        entity=entity,
        identity=identity,
        owners={key: record["owners"][key] for key in sorted(record["owners"])},
        evidence_prefix=evidence_prefix,
        evidence_refs=[dict(record["admission_ref"])],
    )
    try:
        return owner_revisions.register_entity(channel_id, registration)
    except owner_revisions.RegistrationConflictError as exc:
        raise CommissionConflictError(str(exc)) from exc
    except owner_revisions.WriterAuthorityError as exc:
        raise CommissionAuthError(str(exc)) from exc
    except owner_revisions.OwnerRevisionError as exc:
        raise CommissionError(f"attempt entity registration failed: {exc}") from exc
    except access_policy.AuthorizationError as exc:
        raise CommissionAuthError(str(exc)) from exc


# ---------------------------------------------------------------------------
# Public interface (EXPOSES)
# ---------------------------------------------------------------------------


def register_attempt(channel_id: str, commission: AttemptCommission) -> Any:
    """Commission one immutable application attempt.

    Validates the commission, verifies manifest agreement and input
    artifacts, retains the commission bytes, journals the commission as an
    owner-local effect, and registers the owner-separated attempt entity.
    The same principal + idempotency key + request returns the same
    artifact; changed content under a reused key or identity is rejected.
    Downstream attempt linking is asynchronous and never joins this
    transaction.
    """
    record = _validate_commission(commission)
    descriptor, matched_domain = _authenticate(channel_id, record)
    principal_id = descriptor.principal_id
    payload = _strict_gate(record, "AttemptCommission")
    fingerprint = _digest_of(payload)
    replayed = _check_stored_guards(record, fingerprint, principal_id)
    if replayed is not None:
        return replayed
    _verify_manifest(channel_id, record, matched_domain)
    _verify_inputs(channel_id, record)
    try:
        commission_ref = artifact_store.retain_artifact(
            channel_id, matched_domain, "application/json", payload, "public"
        )
    except access_policy.AuthorizationError as exc:
        raise CommissionAuthError(
            f"commission retention is not authorized: {exc}"
        ) from exc
    if commission_ref.digest != fingerprint:
        raise CommissionError(
            "the commission artifact digest does not match its canonical digest"
        )
    commit_prefix = _journal_commission(
        channel_id, matched_domain, record, commission_ref
    )
    _register_attempt_entity(channel_id, record, commission_ref, commit_prefix)
    _store_commission(record, fingerprint, principal_id, commission_ref)
    return commission_ref


def load_commission(channel_id: str, content: Any) -> AttemptCommission:
    """Load and validate a retained commission artifact."""
    if not isinstance(channel_id, str) or not channel_id:
        raise CommissionAuthError("channel_id must be a nonempty identifier")
    if isinstance(content, Mapping) and not hasattr(content, "digest"):
        try:
            reference = artifact_store.ArtifactReference.from_dict(dict(content))
        except (TypeError, ValueError) as exc:
            raise InvalidCommissionError(
                f"content is not an ArtifactReference: {exc}"
            ) from exc
    else:
        reference = content
    try:
        payload = artifact_store.resolve_artifact(channel_id, reference)
    except artifact_store.ArtifactError as exc:
        raise InvalidCommissionError(
            f"commission bytes are unavailable: {exc}"
        ) from exc
    try:
        raw = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise InvalidCommissionError(f"commission bytes are not JSON: {exc}") from exc
    record = _validate_commission(raw)
    _strict_gate(record, "AttemptCommission")
    return AttemptCommission.from_dict(record)


def reset_for_tests() -> None:
    """Clear commissioned attempts and idempotency receipts (tests only)."""
    with _LOCK:
        _ATTEMPTS.clear()
        _COMMISSIONS.clear()
        _IDEMPOTENCY.clear()

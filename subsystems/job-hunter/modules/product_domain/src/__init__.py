"""product_domain: product-owned downstream write gateway (tier 7).

Implements the product-owned downstream interface per
``job-hunter-seam-mapping.md#6`` (product-owned downstream interface),
``#15.5`` (product leases), and ``#16.13`` (noGoList):

- ``W.JobDownstreamValue`` contains exactly ``track``, ``priority_hint``,
  ``selection``, ``ownership``, ``evaluations``, ``materials``, and
  ``application_attempts``. Any crawler-owned field rejects the entire write.
- Every downstream write produces a complete ``W.DataDomainRevision`` with
  ``revision == previous_revision + 1``. Stale expected revisions reject.
- Selection transitions among ``go``/``no_go``/``review`` require a new
  authorized rationale with nonempty evidence. Prior decisions remain
  journaled; selection changes never mutate commissions or stop native work.
- Attempt links require an already-durable registered commission that
  identifies this portfolio job. A link carries no inherited outcome.

Durable order (owner-local, no peer locks):

1. Validate the complete downstream value (strict shape, no crawler fields,
   no outcome inheritance, typed Missing only) via the kernel strict-JSON
   gate (``contract_codec.validate_record``).
2. Authorize the product writer via ``access_policy.authorize`` and verify
   the authenticated producer matches the registered downstream writer.
3. Verify the cited registration evidence prefix via
   ``evidence_journal.read_prefix`` when its journal is locally admitted.
4. Validate selection transitions against the current downstream head and
   enforce append-only preservation for evaluations/materials/attempts.
5. Resolve each linked commission via ``artifact_store.resolve_artifact``
   and verify it identifies this portfolio job and attempt.
6. Construct the complete ``W.DataDomainRevision`` and commit it via
   ``owner_revisions.commit_domain`` (owner-local fence, idempotent
   command). Publication to readers stays asynchronous.

``crawler_intake.accept_job_row`` is a declared CONSUMES entry that this
downstream-only writer intentionally never calls: product publication writes
no crawler field and never initializes a pretend crawler revision. The
dependency is inspected at import (gracefully absent pre-tier-6) but is not
required for these conformance assertions.

Invariants enforced: OWD-JOB, OWD-OWNER, OWD-REVISION, OWD-LOCAL-COMMIT,
EK-LEASE (via owner commit), LIFE-COMMISSION (link side), LIFE-AXES.
"""

from __future__ import annotations

import copy
import hashlib
import importlib
import importlib.util
import json
import math
import re
import sys
import threading
from dataclasses import is_dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


def _load_sibling(name: str, *, required: bool = True):  # pragma: no cover - import plumbing
    if name in sys.modules:
        return sys.modules[name]
    try:
        return importlib.import_module(name)
    except ModuleNotFoundError:
        pass
    sibling_path = Path(__file__).resolve().parents[2] / name / "src" / "__init__.py"
    if not sibling_path.exists():
        if required:
            raise ModuleNotFoundError(f"sibling module {name!r} not found")
        return None
    spec = importlib.util.spec_from_file_location(name, sibling_path)
    if spec is None or spec.loader is None:
        if required:
            raise ModuleNotFoundError(f"sibling module {name!r} not found")
        return None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


contract_codec = _load_sibling("contract_codec")
access_policy = _load_sibling("access_policy")
artifact_store = _load_sibling("artifact_store")
evidence_journal = _load_sibling("evidence_journal")
owner_revisions = _load_sibling("owner_revisions")
# Declared but intentionally unused on the downstream write path (see docstring).
crawler_intake = _load_sibling("crawler_intake", required=False)
# LeaseRecord type source (transitive via owner_revisions); optional for isinstance.
lease_authority = _load_sibling("lease_authority", required=False)

__all__ = [
    "SCHEMA_VERSION",
    "RECORD_TYPE",
    "DOWNSTREAM_FIELDS",
    "CRAWLER_FIELDS",
    "JobDownstreamValue",
    "ProductDomainError",
    "InvalidDownstreamValueError",
    "CrawlerFieldRejectedError",
    "SelectionTransitionError",
    "AttemptLinkError",
    "CommissionNotDurableError",
    "publish_product_revision",
    "register_commission_reference",
    "known_commission_digests",
    "selection_history",
    "prior_value",
    "reset_for_tests",
]

SCHEMA_VERSION = "owner-separated-write-domains/0.1.0"
RECORD_TYPE = "owned_domain_revision"
DOWNSTREAM_DOMAIN = "downstream"
DOWNSTREAM_OWNER_DOMAIN = "job.downstream"
DOWNSTREAM_WRITE_OP = "job.downstream.write"

DOWNSTREAM_FIELDS: tuple[str, ...] = (
    "track",
    "priority_hint",
    "selection",
    "ownership",
    "evaluations",
    "materials",
    "application_attempts",
)

# Crawler-owned fields per seam 5.2 (read-only to Job Hunter) plus the
# owner_revisions crawler group names. Any of these at the top level of a
# downstream value — or any other undeclared top-level key — rejects the
# entire write. This list is used for precise error messages; unknown keys
# are rejected even when absent from this set.
CRAWLER_FIELDS = frozenset(
    {
        # Acquisition provenance / identity.
        "source_url",
        "listing_page_url",
        "source_response",
        "extractor",
        "rendered_at",
        "fetch_key",
        "fetch_key_profile",
        "fetch_identity",
        # Content contract / render evidence.
        "content_declarations",
        "content",
        "render_verdict",
        "render_basis",
        "render_history",
        # Processing state / fencing / retry accounting.
        "pipeline_state",
        "classification_surface",
        "active_run_id",
        "input_revision",
        "generation_id",
        "lease",
        "retry_count",
        "max_retries_effective",
        "last_failure_reason",
        # Classification / semantic / discovery / replacement.
        "classifier_results",
        "final_genuine_result_id",
        "bypass_reason",
        "semantic_candidate",
        "semantic_evidence_refs",
        "first_seen_run_id",
        "last_seen_run_id",
        "first_seen_at",
        "last_seen_at",
        "coverage",
        "replacement_lineage",
        # Crawler domain group names (owner_revisions crawler value).
        "acquisition",
        "processing",
        "discovery",
        # Legacy aliases sometimes smuggled from Firestore rows.
        "rawDescription",
        "sourceUrl",
        "directApplyUrl",
        "portalType",
        "closingDate",
        "semantic_state",
    }
)

# Outcome-like keys that must never appear on an AttemptLink or a downstream
# value. AttemptLink has exactly {attempt, commission_digest, evidence_refs};
# any extra key — outcome-flavored or otherwise — rejects the entire write.
_OUTCOME_LIKE_FIELDS = frozenset(
    {
        "status",
        "outcome",
        "result",
        "application_status",
        "application_outcome",
        "tracker_status",
        "decision_outcome",
        "hired",
        "offer",
        "rejected",
    }
)

_VALID_DECISIONS = frozenset({"go", "no_go", "review"})
_VALID_MATERIAL_ROLES = frozenset({"resume", "cover_letter", "supplemental_responses", "other"})
_VALID_OWNERSHIP_STATES = frozenset({"unclaimed", "claimed"})
_VALID_ATTEMPT_KINDS = frozenset({"practice", "production"})

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_POINTER_RE = re.compile(r"^(?:/(?:[^~/]|~[01])*)*$")
_MAX_SAFE_INT = 9007199254740991

# Type alias for the complete product value (plain JSON mapping). Callers may
# also pass an object exposing ``to_dict()`` (e.g. a dataclass) which is
# normalized to a mapping before validation.
JobDownstreamValue = dict  # noqa: N816 - contract type alias


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ProductDomainError(Exception):
    """Base class for product-domain contract violations."""


class InvalidDownstreamValueError(ProductDomainError, ValueError):
    """The downstream value is not a complete valid ``W.JobDownstreamValue``."""


class CrawlerFieldRejectedError(InvalidDownstreamValueError):
    """A crawler-owned (or otherwise undeclared) field rejects the entire write."""


class SelectionTransitionError(InvalidDownstreamValueError):
    """A selection transition lacks a new authorized rationale or drops history."""


class AttemptLinkError(InvalidDownstreamValueError):
    """An attempt link is malformed, outcome-inheriting, or mislinked."""


class CommissionNotDurableError(AttemptLinkError):
    """A linked commission is not registered/durable or names another job."""


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
    return value.get("reason") in _valid_missing_reasons()


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


def _missing_to_dict(value: Any) -> dict[str, Any]:
    if is_dataclass(value) and not isinstance(value, type):
        out: dict[str, Any] = {"value": None, "reason": str(getattr(value, "reason"))}
        detail = getattr(value, "detail", None)
        if detail is not None:
            out["detail"] = str(detail)
        return out
    assert isinstance(value, Mapping)
    out = {"value": None, "reason": str(value["reason"])}
    if "detail" in value:
        out["detail"] = str(value["detail"])
    return out


def _require_identifier(value: Any, field_name: str) -> str:
    if not isinstance(value, str):
        raise InvalidDownstreamValueError(f"{field_name} must be a str")
    if not value or value != value.strip():
        raise InvalidDownstreamValueError(
            f"{field_name} must be a nonempty identifier without padding"
        )
    if len(value) > 256:
        raise InvalidDownstreamValueError(f"{field_name} must be at most 256 characters")
    if "\x00" in value or any(ord(c) < 0x20 for c in value):
        raise InvalidDownstreamValueError(f"{field_name} must not contain control characters")
    return value


def _require_digest(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.match(value):
        raise InvalidDownstreamValueError(
            f"{field_name} must be a sha256:<64 lowercase hex> digest"
        )
    return value


def _require_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidDownstreamValueError(f"{field_name} must be an int")
    return value


def _require_exact_keys(value: Any, required: frozenset[str] | set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise InvalidDownstreamValueError(f"{label} must be a mapping")
    keys = set(value.keys())
    missing = set(required) - keys
    extra = keys - set(required)
    if missing:
        raise InvalidDownstreamValueError(f"{label} is missing required keys: {sorted(missing)}")
    if extra:
        # Distinguish crawler smuggling from generic shape errors at top level.
        raise InvalidDownstreamValueError(
            f"{label} has undeclared properties: {sorted(extra)}"
        )
    return value


def _jsonable(value: Any, path: str = "$") -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        if type(value).__name__ == "Missing":
            reason = getattr(value, "reason", None)
            if reason not in _valid_missing_reasons():
                raise InvalidDownstreamValueError(f"{path}: unknown Missing reason: {reason!r}")
            out: dict[str, Any] = {"value": None, "reason": str(reason)}
            detail = getattr(value, "detail", None)
            if detail is not None:
                if not isinstance(detail, str) or not detail:
                    raise InvalidDownstreamValueError(f"{path}.detail must be nonempty")
                out["detail"] = detail
            return out
        to_dict = getattr(value, "to_dict", None)
        if callable(to_dict):
            try:
                value = to_dict()
            except Exception as exc:
                raise InvalidDownstreamValueError(f"{path}: cannot serialize dataclass: {exc}") from exc
        else:
            raise InvalidDownstreamValueError(f"{path}: unsupported dataclass {type(value).__name__}")
    if isinstance(value, Mapping):
        if _is_missing(value):
            data = _missing_to_dict(value)
            if "detail" in data and (not isinstance(data["detail"], str) or not data["detail"]):
                raise InvalidDownstreamValueError(f"{path}.detail must be nonempty")
            return data
        return {str(k): _jsonable(v, f"{path}.{k}") for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v, f"{path}[{i}]") for i, v in enumerate(value)]
    if isinstance(value, str):
        if "\x00" in value:
            raise InvalidDownstreamValueError(f"{path} must not contain NUL bytes")
        return value
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        if abs(value) > _MAX_SAFE_INT:
            raise InvalidDownstreamValueError(f"{path} exceeds the safe integer range")
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise InvalidDownstreamValueError(f"{path} must be a finite number")
        return value
    if value is None:
        raise InvalidDownstreamValueError(
            f"{path} must not be a bare null; use a typed Missing envelope"
        )
    if isinstance(value, (bytes, bytearray)):
        raise InvalidDownstreamValueError(f"{path} must not be raw bytes")
    raise InvalidDownstreamValueError(f"{path} is not strict JSON content: {type(value).__name__}")


def _canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise InvalidDownstreamValueError(f"value is not canonicalizable JSON: {exc}") from exc


def _strict_gate(record: Mapping[str, Any], label: str) -> bytes:
    """Run the kernel strict-JSON gate over a normalized record."""
    normalized = _jsonable(record, label)
    wrapper = {"id": "product_domain_gate", "timing": normalized}
    try:
        contract_codec.validate_record(_canonical_bytes(wrapper), "record/v1")
    except (TypeError, ValueError) as exc:
        raise InvalidDownstreamValueError(f"{label} is not strict JSON evidence: {exc}") from exc
    payload = _canonical_bytes(normalized)
    try:
        contract_codec.canonical_digest(payload)
    except (TypeError, ValueError) as exc:
        raise InvalidDownstreamValueError(f"{label} has no canonical digest: {exc}") from exc
    return payload


def _coerce_artifact(value: Any, field_name: str) -> dict[str, Any]:
    if is_dataclass(value) and not isinstance(value, type) and hasattr(value, "to_dict"):
        try:
            value = value.to_dict()  # type: ignore[union-attr]
        except Exception as exc:
            raise InvalidDownstreamValueError(f"{field_name} is not an ArtifactReference: {exc}") from exc
    data = _require_exact_keys(
        value, frozenset({"digest", "size_bytes", "media_type", "owner_domain", "access"}), field_name
    )
    digest = _require_digest(data["digest"], f"{field_name}.digest")
    size = data["size_bytes"]
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise InvalidDownstreamValueError(f"{field_name}.size_bytes must be a nonnegative int")
    media_type = _require_identifier(data["media_type"], f"{field_name}.media_type")
    owner_domain = _require_identifier(data["owner_domain"], f"{field_name}.owner_domain")
    access = data["access"]
    if access not in ("public", "restricted"):
        raise InvalidDownstreamValueError(f"{field_name}.access must be public or restricted")
    return {
        "digest": digest,
        "size_bytes": size,
        "media_type": media_type,
        "owner_domain": owner_domain,
        "access": access,
    }


def _coerce_evidence_ref(value: Any, field_name: str) -> dict[str, Any]:
    if is_dataclass(value) and not isinstance(value, type) and hasattr(value, "to_dict"):
        try:
            value = value.to_dict()  # type: ignore[union-attr]
        except Exception as exc:
            raise InvalidDownstreamValueError(f"{field_name} is not an EvidenceRef: {exc}") from exc
    data = _require_exact_keys(
        value,
        frozenset({"journal_id", "sequence", "event_id", "event_hash", "pointer"}),
        field_name,
    )
    journal_id = _require_identifier(data["journal_id"], f"{field_name}.journal_id")
    sequence = data["sequence"]
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
        raise InvalidDownstreamValueError(f"{field_name}.sequence must be a positive int")
    event_id = _require_identifier(data["event_id"], f"{field_name}.event_id")
    event_hash = _require_digest(data["event_hash"], f"{field_name}.event_hash")
    pointer = data["pointer"]
    if not isinstance(pointer, str) or not _POINTER_RE.match(pointer):
        raise InvalidDownstreamValueError(f"{field_name}.pointer must be a valid JSON pointer")
    return {
        "journal_id": journal_id,
        "sequence": sequence,
        "event_id": event_id,
        "event_hash": event_hash,
        "pointer": pointer,
    }


def _coerce_evidence_refs(value: Any, field_name: str, *, nonempty: bool) -> list[dict[str, Any]]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise InvalidDownstreamValueError(f"{field_name} must be a sequence of EvidenceRef")
    refs = [_coerce_evidence_ref(item, f"{field_name}[{i}]") for i, item in enumerate(value)]
    if nonempty and not refs:
        raise InvalidDownstreamValueError(f"{field_name} must be nonempty support evidence")
    seen: set[tuple[str, int, str, str, str]] = set()
    for ref in refs:
        key = (ref["journal_id"], ref["sequence"], ref["event_id"], ref["event_hash"], ref["pointer"])
        if key in seen:
            raise InvalidDownstreamValueError(f"{field_name} must not contain duplicate refs")
        seen.add(key)
    return refs


def _coerce_prefix(value: Any, field_name: str) -> dict[str, Any]:
    if is_dataclass(value) and not isinstance(value, type) and hasattr(value, "to_dict"):
        try:
            value = value.to_dict()  # type: ignore[union-attr]
        except Exception as exc:
            raise InvalidDownstreamValueError(f"{field_name} is not a JournalPrefix: {exc}") from exc
    data = _require_exact_keys(
        value, frozenset({"journal_id", "last_sequence", "head_hash"}), field_name
    )
    journal_id = _require_identifier(data["journal_id"], f"{field_name}.journal_id")
    last_sequence = data["last_sequence"]
    if isinstance(last_sequence, bool) or not isinstance(last_sequence, int) or last_sequence < 1:
        raise InvalidDownstreamValueError(f"{field_name}.last_sequence must be a positive int")
    head_hash = _require_digest(data["head_hash"], f"{field_name}.head_hash")
    return {"journal_id": journal_id, "last_sequence": last_sequence, "head_hash": head_hash}


def _validate_maybe_string(value: Any, field_name: str) -> Any:
    if _is_missing(value):
        return _missing_to_dict(value)
    if isinstance(value, str):
        return _require_identifier(value, field_name)
    raise InvalidDownstreamValueError(f"{field_name} must be an Identifier or a Missing envelope")


def _validate_maybe_number(value: Any, field_name: str) -> Any:
    if _is_missing(value):
        return _missing_to_dict(value)
    if isinstance(value, bool):
        raise InvalidDownstreamValueError(f"{field_name} must be a number or a Missing envelope")
    if isinstance(value, (int, float)):
        if isinstance(value, float) and not math.isfinite(value):
            raise InvalidDownstreamValueError(f"{field_name} must be a finite number")
        if isinstance(value, int) and abs(value) > _MAX_SAFE_INT:
            raise InvalidDownstreamValueError(f"{field_name} exceeds the safe integer range")
        return value
    raise InvalidDownstreamValueError(f"{field_name} must be a number or a Missing envelope")


# ---------------------------------------------------------------------------
# Owner-local stores (test-isolated; never a peer lock)
# ---------------------------------------------------------------------------

_STATE_LOCK = threading.RLock()
_PRIOR_VALUES: dict[str, dict[str, Any]] = {}
_SELECTION_HISTORY: dict[str, list[dict[str, Any]]] = {}
_HEADS: dict[str, int] = {}
_COMMISSIONS: dict[str, dict[str, Any]] = {}


def _entity_id(entity: Mapping[str, Any]) -> str:
    entity_type = entity.get("entity_type")
    if entity_type == "job":
        target = entity.get("target")
        job_id = entity.get("job_id")
        if not isinstance(target, str) or not target or not isinstance(job_id, str) or not job_id:
            raise InvalidDownstreamValueError("job entity requires target and job_id identifiers")
        return f"job.{target}.{job_id}"
    raise InvalidDownstreamValueError(f"product_domain publishes only job downstream, got {entity_type!r}")


def register_commission_reference(reference: Any) -> str:
    """Record a durable commission reference for attempt-link verification.

    Commissions are retained by the commissioning path (not by this gateway);
    tests and operators retain the bytes via ``artifact_store`` and then
    register the full reference here so that digest-only ``AttemptLink``
    entries can be resolved through the declared
    ``artifact_store.resolve_artifact`` dependency. Returns the digest.
    """
    ref = _coerce_artifact(reference, "commission_reference")
    with _STATE_LOCK:
        _COMMISSIONS[ref["digest"]] = ref
    return ref["digest"]


def known_commission_digests() -> frozenset[str]:
    """Digests currently registered for link verification (tests/debugging)."""
    with _STATE_LOCK:
        return frozenset(_COMMISSIONS.keys())


def selection_history(entity: Any) -> tuple[dict[str, Any], ...]:
    """Prior authorized selections for one job entity, oldest first.

    Each entry holds ``revision``, ``decision``, ``evaluation_id``,
    ``rationale``, and ``evidence_refs``. Entries are immutable snapshots;
    later transitions append without rewriting prior entries.
    """
    if is_dataclass(entity) and not isinstance(entity, type) and hasattr(entity, "to_dict"):
        try:
            entity = entity.to_dict()  # type: ignore[union-attr]
        except Exception as exc:
            raise InvalidDownstreamValueError(f"entity is not serializable: {exc}") from exc
    if isinstance(entity, Mapping) and "entity" in entity:
        # Allow passing a registration mapping by mistake-proofing.
        inner = entity.get("entity")
        if isinstance(inner, Mapping):
            entity = inner
    entity_id = _entity_id(entity)  # type: ignore[arg-type]
    with _STATE_LOCK:
        return tuple(copy.deepcopy(_SELECTION_HISTORY.get(entity_id, [])))


def prior_value(entity: Any) -> dict[str, Any] | None:
    """Last committed downstream value snapshot for one entity, if any."""
    if isinstance(entity, Mapping) and "entity" in entity:
        inner = entity.get("entity")
        if isinstance(inner, Mapping):
            entity = inner
    entity_id = _entity_id(entity)  # type: ignore[arg-type]
    with _STATE_LOCK:
        held = _PRIOR_VALUES.get(entity_id)
        return copy.deepcopy(held) if held is not None else None


def reset_for_tests() -> None:
    """Clear owner-local downstream caches (test harness only)."""
    with _STATE_LOCK:
        _PRIOR_VALUES.clear()
        _SELECTION_HISTORY.clear()
        _HEADS.clear()
        _COMMISSIONS.clear()


# ---------------------------------------------------------------------------
# Downstream value validation
# ---------------------------------------------------------------------------


def _validate_selection(value: Any) -> Any:
    if _is_missing(value):
        return _missing_to_dict(value)
    data = _require_exact_keys(
        value, frozenset({"decision", "evaluation_id", "rationale", "evidence_refs"}), "value.selection"
    )
    decision = data["decision"]
    if decision not in _VALID_DECISIONS:
        raise InvalidDownstreamValueError(
            f"value.selection.decision must be one of {sorted(_VALID_DECISIONS)}"
        )
    evaluation_id = _validate_maybe_string(data["evaluation_id"], "value.selection.evaluation_id")
    rationale = data["rationale"]
    if not isinstance(rationale, str) or not rationale.strip():
        raise InvalidDownstreamValueError("value.selection.rationale must be a nonempty string")
    if len(rationale) > 4096:
        raise InvalidDownstreamValueError("value.selection.rationale must be at most 4096 characters")
    evidence_refs = _coerce_evidence_refs(data["evidence_refs"], "value.selection.evidence_refs", nonempty=True)
    return {
        "decision": decision,
        "evaluation_id": evaluation_id,
        "rationale": rationale,
        "evidence_refs": evidence_refs,
    }


def _validate_ownership(value: Any) -> dict[str, Any]:
    data = _require_exact_keys(
        value, frozenset({"state", "claimant", "lease", "evidence_refs"}), "value.ownership"
    )
    state = data["state"]
    if state not in _VALID_OWNERSHIP_STATES:
        raise InvalidDownstreamValueError("value.ownership.state must be unclaimed or claimed")
    evidence_refs = _coerce_evidence_refs(data["evidence_refs"], "value.ownership.evidence_refs", nonempty=True)
    if state == "claimed":
        claimant = data["claimant"]
        if _is_missing(claimant):
            raise InvalidDownstreamValueError("claimed ownership requires a claimant identifier")
        claimant = _require_identifier(claimant, "value.ownership.claimant")
        lease_raw = data["lease"]
        if _is_missing(lease_raw):
            raise InvalidDownstreamValueError("claimed ownership requires a kernel lease artifact")
        lease = _coerce_artifact(lease_raw, "value.ownership.lease")
    else:
        if _missing_reason(data["claimant"]) != "not_applicable":
            raise InvalidDownstreamValueError(
                "unclaimed ownership requires claimant Missing(not_applicable)"
            )
        if _missing_reason(data["lease"]) != "not_applicable":
            raise InvalidDownstreamValueError(
                "unclaimed ownership requires lease Missing(not_applicable)"
            )
        claimant = _missing_to_dict(data["claimant"])
        lease = _missing_to_dict(data["lease"])
    return {"state": state, "claimant": claimant, "lease": lease, "evidence_refs": evidence_refs}


def _validate_evaluation(value: Any, index: int) -> dict[str, Any]:
    label = f"value.evaluations[{index}]"
    data = _require_exact_keys(
        value,
        frozenset({"evaluation_id", "crawler_input", "candidate_profile", "evaluation", "evidence_refs"}),
        label,
    )
    evaluation_id = _require_identifier(data["evaluation_id"], f"{label}.evaluation_id")
    crawler_raw = data["crawler_input"]
    crawler_data = _require_exact_keys(
        crawler_raw, frozenset({"revision", "record_digest"}), f"{label}.crawler_input"
    )
    crawler_revision = crawler_data["revision"]
    if isinstance(crawler_revision, bool) or not isinstance(crawler_revision, int) or crawler_revision < 1:
        raise InvalidDownstreamValueError(f"{label}.crawler_input.revision must be a positive int")
    crawler_digest = _require_digest(crawler_data["record_digest"], f"{label}.crawler_input.record_digest")
    candidate_profile = _coerce_artifact(data["candidate_profile"], f"{label}.candidate_profile")
    evaluation = _coerce_artifact(data["evaluation"], f"{label}.evaluation")
    evidence_refs = _coerce_evidence_refs(data["evidence_refs"], f"{label}.evidence_refs", nonempty=True)
    return {
        "evaluation_id": evaluation_id,
        "crawler_input": {"revision": crawler_revision, "record_digest": crawler_digest},
        "candidate_profile": candidate_profile,
        "evaluation": evaluation,
        "evidence_refs": evidence_refs,
    }


def _validate_material(value: Any, index: int) -> dict[str, Any]:
    label = f"value.materials[{index}]"
    data = _require_exact_keys(
        value, frozenset({"artifact_id", "role", "content", "evidence_refs"}), label
    )
    artifact_id = _require_identifier(data["artifact_id"], f"{label}.artifact_id")
    role = data["role"]
    if role not in _VALID_MATERIAL_ROLES:
        raise InvalidDownstreamValueError(
            f"{label}.role must be one of {sorted(_VALID_MATERIAL_ROLES)}"
        )
    content = _coerce_artifact(data["content"], f"{label}.content")
    evidence_refs = _coerce_evidence_refs(data["evidence_refs"], f"{label}.evidence_refs", nonempty=True)
    return {"artifact_id": artifact_id, "role": role, "content": content, "evidence_refs": evidence_refs}


def _validate_attempt_link_shape(value: Any, index: int) -> dict[str, Any]:
    label = f"value.application_attempts[{index}]"
    if not isinstance(value, Mapping):
        raise AttemptLinkError(f"{label} must be a mapping")
    keys = set(value.keys())
    required = {"attempt", "commission_digest", "evidence_refs"}
    missing = required - keys
    extra = keys - required
    if missing:
        raise AttemptLinkError(f"{label} is missing required keys: {sorted(missing)}")
    if extra:
        outcome_like = sorted(extra & _OUTCOME_LIKE_FIELDS)
        if outcome_like:
            raise AttemptLinkError(
                f"{label} inherits outcomes via {outcome_like}; "
                "an AttemptLink carries only attempt, commission_digest, evidence_refs"
            )
        raise AttemptLinkError(f"{label} has undeclared properties: {sorted(extra)}")
    attempt_raw = value["attempt"]
    attempt_data = _require_exact_keys(
        attempt_raw, frozenset({"attempt_id", "kind"}), f"{label}.attempt"
    )
    try:
        attempt_id = _require_identifier(attempt_data["attempt_id"], f"{label}.attempt.attempt_id")
    except InvalidDownstreamValueError as exc:
        raise AttemptLinkError(str(exc)) from exc
    kind = attempt_data["kind"]
    if kind not in _VALID_ATTEMPT_KINDS:
        raise AttemptLinkError(f"{label}.attempt.kind must be practice or production")
    try:
        commission_digest = _require_digest(value["commission_digest"], f"{label}.commission_digest")
    except InvalidDownstreamValueError as exc:
        raise AttemptLinkError(str(exc)) from exc
    try:
        evidence_refs = _coerce_evidence_refs(
            value["evidence_refs"], f"{label}.evidence_refs", nonempty=True
        )
    except InvalidDownstreamValueError as exc:
        raise AttemptLinkError(str(exc)) from exc
    return {
        "attempt": {"attempt_id": attempt_id, "kind": kind},
        "commission_digest": commission_digest,
        "evidence_refs": evidence_refs,
    }


def _normalize_value_mapping(value: Any) -> dict[str, Any]:
    if is_dataclass(value) and not isinstance(value, type) and hasattr(value, "to_dict"):
        try:
            value = value.to_dict()  # type: ignore[union-attr]
        except Exception as exc:
            raise InvalidDownstreamValueError(f"value is not serializable: {exc}") from exc
    if not isinstance(value, Mapping):
        raise InvalidDownstreamValueError("value must be a complete W.JobDownstreamValue mapping")
    return dict(value)


def _validate_downstream_value(value: Any) -> dict[str, Any]:
    """Validate a complete downstream value; reject crawler/outcome smuggling."""
    raw = _normalize_value_mapping(value)
    keys = set(raw.keys())
    required = set(DOWNSTREAM_FIELDS)
    missing = required - keys
    extra = keys - required
    if missing:
        raise InvalidDownstreamValueError(
            f"value is missing required downstream fields: {sorted(missing)}"
        )
    if extra:
        crawler_like = sorted(extra & CRAWLER_FIELDS)
        outcome_like = sorted(extra & _OUTCOME_LIKE_FIELDS)
        if crawler_like:
            raise CrawlerFieldRejectedError(
                f"downstream write carries crawler-owned fields {crawler_like}; "
                "the entire write is rejected and no revision advances"
            )
        if outcome_like:
            raise AttemptLinkError(
                f"downstream value inherits outcomes via {outcome_like}; "
                "a product go, claimed work, or attempt link is not application commitment"
            )
        # Any other undeclared key is also a cross-domain write.
        crawler_hint = sorted(extra)[0]
        if crawler_hint in CRAWLER_FIELDS:
            raise CrawlerFieldRejectedError(
                f"downstream write carries crawler-owned field {crawler_hint!r}; "
                "the entire write is rejected and no revision advances"
            )
        raise CrawlerFieldRejectedError(
            f"downstream write carries undeclared fields {sorted(extra)} outside "
            "the product domain; the entire write is rejected and no revision advances"
        )
    track = _validate_maybe_string(raw["track"], "value.track")
    priority_hint = _validate_maybe_number(raw["priority_hint"], "value.priority_hint")
    selection = _validate_selection(raw["selection"])
    ownership = _validate_ownership(raw["ownership"])
    evaluations_raw = raw["evaluations"]
    materials_raw = raw["materials"]
    attempts_raw = raw["application_attempts"]
    if isinstance(evaluations_raw, (str, bytes)) or not isinstance(evaluations_raw, Sequence):
        raise InvalidDownstreamValueError("value.evaluations must be a sequence")
    if isinstance(materials_raw, (str, bytes)) or not isinstance(materials_raw, Sequence):
        raise InvalidDownstreamValueError("value.materials must be a sequence")
    if isinstance(attempts_raw, (str, bytes)) or not isinstance(attempts_raw, Sequence):
        raise InvalidDownstreamValueError("value.application_attempts must be a sequence")
    evaluations = [_validate_evaluation(item, i) for i, item in enumerate(evaluations_raw)]
    materials = [_validate_material(item, i) for i, item in enumerate(materials_raw)]
    attempts = [_validate_attempt_link_shape(item, i) for i, item in enumerate(attempts_raw)]
    # Intra-value uniqueness (append-only registries never reuse identities).
    seen_evaluations: set[str] = set()
    for entry in evaluations:
        if entry["evaluation_id"] in seen_evaluations:
            raise InvalidDownstreamValueError(
                f"duplicate evaluation_id {entry['evaluation_id']!r} in value.evaluations"
            )
        seen_evaluations.add(entry["evaluation_id"])
    seen_materials: set[str] = set()
    for entry in materials:
        if entry["artifact_id"] in seen_materials:
            raise InvalidDownstreamValueError(
                f"duplicate artifact_id {entry['artifact_id']!r} in value.materials"
            )
        seen_materials.add(entry["artifact_id"])
    seen_attempts: set[tuple[str, str]] = set()
    for entry in attempts:
        key = (entry["attempt"]["attempt_id"], entry["attempt"]["kind"])
        if key in seen_attempts:
            raise AttemptLinkError(f"duplicate attempt link {key!r} in value.application_attempts")
        seen_attempts.add(key)
    # A concrete selection citing an evaluation must name a listed evaluation;
    # a human decision may use a Missing evaluation ID.
    if not _is_missing(selection):
        evaluation_id = selection["evaluation_id"]
        if not _is_missing(evaluation_id) and evaluation_id not in seen_evaluations:
            raise SelectionTransitionError(
                f"selection cites unknown evaluation_id {evaluation_id!r}; "
                "human decisions without a model evaluation must use a Missing evaluation ID"
            )
    normalized = {
        "track": track,
        "priority_hint": priority_hint,
        "selection": selection,
        "ownership": ownership,
        "evaluations": evaluations,
        "materials": materials,
        "application_attempts": attempts,
    }
    # Kernel strict-JSON gate (duplicate keys, bare nulls, nonfinite numbers).
    _strict_gate(normalized, "W.JobDownstreamValue")
    return _jsonable(normalized, "W.JobDownstreamValue")


# ---------------------------------------------------------------------------
# Registration helpers
# ---------------------------------------------------------------------------


def _normalize_registration(registration: Any) -> dict[str, Any]:
    if is_dataclass(registration) and not isinstance(registration, type) and hasattr(
        registration, "to_dict"
    ):
        try:
            registration = registration.to_dict()  # type: ignore[union-attr]
        except Exception as exc:
            raise InvalidDownstreamValueError(f"registration is not serializable: {exc}") from exc
    if not isinstance(registration, Mapping):
        raise InvalidDownstreamValueError("registration must be an EntityRegistration mapping")
    data = dict(registration)
    for field_name in (
        "record_type",
        "schema_version",
        "registration_id",
        "entity",
        "identity",
        "owners",
        "evidence_prefix",
        "evidence_refs",
    ):
        if field_name not in data:
            raise InvalidDownstreamValueError(f"registration is missing {field_name!r}")
    if data["record_type"] != "write_domain_entity":
        raise InvalidDownstreamValueError("registration.record_type must be write_domain_entity")
    if data["schema_version"] != SCHEMA_VERSION:
        raise InvalidDownstreamValueError(f"registration.schema_version must be {SCHEMA_VERSION!r}")
    _require_identifier(data["registration_id"], "registration.registration_id")
    entity = data["entity"]
    if not isinstance(entity, Mapping):
        raise InvalidDownstreamValueError("registration.entity must be a mapping")
    if entity.get("entity_type") != "job":
        raise InvalidDownstreamValueError("product_domain publishes only job downstream")
    _require_identifier(entity.get("target"), "registration.entity.target")
    _require_identifier(entity.get("job_id"), "registration.entity.job_id")
    identity = data["identity"]
    if not isinstance(identity, Mapping):
        raise InvalidDownstreamValueError("registration.identity must be a mapping")
    _require_identifier(identity.get("portfolio_job_id"), "registration.identity.portfolio_job_id")
    owners = data["owners"]
    if not isinstance(owners, Mapping) or "downstream" not in owners:
        raise InvalidDownstreamValueError("registration.owners must declare downstream")
    downstream_owner = owners["downstream"]
    if not isinstance(downstream_owner, Mapping):
        raise InvalidDownstreamValueError("registration.owners.downstream must be a mapping")
    if downstream_owner.get("role") != "product":
        raise InvalidDownstreamValueError("registration.owners.downstream.role must be product")
    _require_identifier(downstream_owner.get("owner_domain"), "registration.owners.downstream.owner_domain")
    _require_identifier(downstream_owner.get("writer_id"), "registration.owners.downstream.writer_id")
    prefix = _coerce_prefix(data["evidence_prefix"], "registration.evidence_prefix")
    refs = _coerce_evidence_refs(data["evidence_refs"], "registration.evidence_refs", nonempty=False)
    return {
        "registration_id": data["registration_id"],
        "entity": {
            "entity_type": "job",
            "target": entity["target"],
            "job_id": entity["job_id"],
        },
        "portfolio_job_id": identity["portfolio_job_id"],
        "owner_domain": downstream_owner["owner_domain"],
        "writer_id": downstream_owner["writer_id"],
        "evidence_prefix": prefix,
        "evidence_refs": refs,
        "raw": data,
    }


def _registration_digest(entity_id: str, registration: Any) -> str:
    """Resolve the immutable registration digest for a revision header."""
    with_state = getattr(owner_revisions, "_REGISTRATIONS", None)
    if isinstance(with_state, dict):
        entry = with_state.get(entity_id)
        digest = getattr(entry, "digest", None) if entry is not None else None
        if isinstance(digest, str) and _DIGEST_RE.match(digest):
            return digest
        if isinstance(entry, Mapping) and isinstance(entry.get("digest"), str):
            candidate = entry["digest"]
            if _DIGEST_RE.match(candidate):
                return candidate
    # Fallback: canonical digest of the normalized registration mapping. When
    # the entity is registered, owner_revisions recomputes this identically;
    # when unregistered, commit_domain raises UnknownEntityError regardless.
    if is_dataclass(registration) and not isinstance(registration, type) and hasattr(
        registration, "to_dict"
    ):
        try:
            registration = registration.to_dict()  # type: ignore[union-attr]
        except Exception as exc:
            raise InvalidDownstreamValueError(f"registration is not serializable: {exc}") from exc
    normalized = _jsonable(dict(registration), "registration")
    payload = _canonical_bytes(normalized)
    try:
        return str(contract_codec.canonical_digest(payload))
    except (TypeError, ValueError) as exc:
        raise InvalidDownstreamValueError(f"registration has no canonical digest: {exc}") from exc


def _normalize_lease(lease: Any) -> Any:
    if lease is None:
        raise InvalidDownstreamValueError("lease must be a LeaseRecord or a typed Missing envelope")
    if _is_missing(lease):
        return _missing_to_dict(lease)
    if lease_authority is not None and hasattr(lease_authority, "LeaseRecord"):
        try:
            if isinstance(lease, lease_authority.LeaseRecord):  # type: ignore[attr-defined]
                return lease
        except Exception:
            pass
    # Duck-typed LeaseRecord (has resource + lease_owner): pass through so the
    # owner commit validates fencing; anything else is a shape error here.
    if is_dataclass(lease) and not isinstance(lease, type):
        if hasattr(lease, "resource") and hasattr(lease, "lease_owner"):
            return lease
    if isinstance(lease, Mapping) and "resource" in lease and "lease_state" in lease:
        return lease
    raise InvalidDownstreamValueError("lease must be a LeaseRecord or a typed Missing envelope")


# ---------------------------------------------------------------------------
# Prior-head and transition validation
# ---------------------------------------------------------------------------


def _load_prior(channel_id: str, entity: Mapping[str, Any]) -> tuple[dict[str, Any] | None, int]:
    """Load the current downstream head value and revision, if any."""
    read_domain = getattr(owner_revisions, "read_domain", None)
    if callable(read_domain):
        try:
            published = read_domain(channel_id, entity, DOWNSTREAM_DOMAIN)
        except Exception:
            published = None
        if published is not None and not isinstance(published, dict):
            record = getattr(published, "record", None)
            value = getattr(published, "value", None)
            revision = getattr(published, "revision", None)
            if isinstance(record, Mapping) and isinstance(record.get("value"), Mapping):
                value = record["value"]
            if isinstance(value, Mapping) and isinstance(revision, int):
                return copy.deepcopy(dict(value)), revision
            return None, 0
        if isinstance(published, Mapping) and _is_missing(published):
            return None, 0
    entity_id = _entity_id(entity)
    with _STATE_LOCK:
        held = _PRIOR_VALUES.get(entity_id)
        head = _HEADS.get(entity_id, 0 if held is None else 0)
        if held is None:
            return None, 0
        return copy.deepcopy(held), head


def _validate_append_only(
    prior: Sequence[Mapping[str, Any]],
    new: Sequence[Mapping[str, Any]],
    *,
    label: str,
    identity: str,
) -> None:
    if len(new) < len(prior):
        raise InvalidDownstreamValueError(
            f"{label} dropped {len(prior) - len(new)} prior entries; "
            "evaluations, materials, and attempt links are append-only"
        )
    for index, old_entry in enumerate(prior):
        current = new[index]
        if dict(current) != dict(old_entry):
            raise InvalidDownstreamValueError(
                f"{label}[{index}] rewrote the committed {identity}; "
                "prior entries are immutable and preserved in order"
            )


def _validate_selection_transition(
    prior_selection: Any | None,
    new_selection: Any,
    evaluations: Sequence[Mapping[str, Any]],
) -> None:
    prior_missing = prior_selection is None or _is_missing(prior_selection)
    new_missing = _is_missing(new_selection)
    if new_missing:
        if not prior_missing:
            raise SelectionTransitionError(
                "selection cannot return to Missing; reconsideration creates a new "
                "go/no_go/review decision while retaining the old entry's evidence"
            )
        return
    # New selection is concrete here (shape already validated).
    assert isinstance(new_selection, Mapping)
    new_decision = new_selection["decision"]
    new_rationale = new_selection["rationale"]
    if prior_missing:
        # Initial selection may become go, no_go, or review with evidence.
        return
    assert isinstance(prior_selection, Mapping)
    prior_decision = prior_selection.get("decision")
    prior_rationale = prior_selection.get("rationale")
    if prior_decision not in _VALID_DECISIONS:
        raise SelectionTransitionError("prior selection decision is not a known state")
    if new_decision not in _VALID_DECISIONS:
        raise SelectionTransitionError("new selection decision is not a known state")
    if new_decision == prior_decision:
        # Same-state revisions may add support; identical preservation while
        # other fields change is also allowed. Only a selection-only rewrite
        # that changes nothing is still harmless (idempotent content).
        return
    # Every pairwise transition requires a new authorized rationale.
    if not isinstance(new_rationale, str) or not new_rationale.strip():
        raise SelectionTransitionError("selection transition requires a new nonempty rationale")
    if new_rationale == prior_rationale:
        raise SelectionTransitionError(
            f"selection transition {prior_decision} -> {new_decision} reuses the prior "
            "rationale; every pairwise transition requires a new authorized decision "
            "with explicit new rationale"
        )
    if new_decision == "go" and prior_decision == "no_go":
        # No-go becomes go only with explicit new rationale (already checked
        # for difference); require it to be substantive, not whitespace.
        if len(new_rationale.strip()) < 8:
            raise SelectionTransitionError(
                "no_go -> go reconsideration requires an explicit substantive rationale"
            )


# ---------------------------------------------------------------------------
# Commission verification (attempt links)
# ---------------------------------------------------------------------------


def _commission_reference_for(digest: str) -> dict[str, Any] | None:
    with _STATE_LOCK:
        held = _COMMISSIONS.get(digest)
        return copy.deepcopy(held) if held is not None else None


def _resolve_commission_bytes(
    channel_id: str, reference: Mapping[str, Any], digest: str
) -> bytes:
    coerced = _coerce_artifact(reference, "commission_reference")
    artifact_cls = getattr(artifact_store, "ArtifactReference", None)
    if artifact_cls is not None:
        try:
            ref_obj = artifact_cls(
                digest=coerced["digest"],
                size_bytes=coerced["size_bytes"],
                media_type=coerced["media_type"],
                owner_domain=coerced["owner_domain"],
                access=coerced["access"],
            )
        except Exception:
            ref_obj = coerced
    else:
        ref_obj = coerced
    try:
        payload = artifact_store.resolve_artifact(channel_id, ref_obj)
    except Exception as exc:
        raise CommissionNotDurableError(
            f"linked commission {digest} is not durable/resolvable: {exc}"
        ) from exc
    if not isinstance(payload, (bytes, bytearray)):
        raise CommissionNotDurableError(f"linked commission {digest} resolved to non-bytes")
    payload = bytes(payload)
    if "sha256:" + hashlib.sha256(payload).hexdigest() != digest:
        raise CommissionNotDurableError(
            f"linked commission {digest} digest does not match its durable bytes"
        )
    return payload


def _parse_commission(payload: bytes, digest: str) -> dict[str, Any]:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CommissionNotDurableError(
            f"linked commission {digest} is not UTF-8 JSON: {exc}"
        ) from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise CommissionNotDurableError(
            f"linked commission {digest} is not valid JSON: {exc}"
        ) from exc
    if not isinstance(data, Mapping):
        raise CommissionNotDurableError(f"linked commission {digest} is not a mapping")
    return dict(data)


def _verify_attempt_links(
    channel_id: str,
    entity: Mapping[str, Any],
    portfolio_job_id: str,
    attempts: Sequence[Mapping[str, Any]],
) -> None:
    for index, link in enumerate(attempts):
        label = f"value.application_attempts[{index}]"
        digest = link["commission_digest"]
        reference = _commission_reference_for(digest)
        if reference is None:
            raise CommissionNotDurableError(
                f"{label} links unregistered commission {digest}; "
                "linking requires an already-durable registered commission"
            )
        payload = _resolve_commission_bytes(channel_id, reference, digest)
        commission = _parse_commission(payload, digest)
        if commission.get("record_type") != "attempt_commission":
            raise CommissionNotDurableError(
                f"{label} links digest {digest} which is not an attempt_commission record"
            )
        attempt_ctx = commission.get("attempt")
        if not isinstance(attempt_ctx, Mapping):
            raise CommissionNotDurableError(f"{label} commission has no attempt context")
        if (
            attempt_ctx.get("attempt_id") != link["attempt"]["attempt_id"]
            or attempt_ctx.get("kind") != link["attempt"]["kind"]
        ):
            raise CommissionNotDurableError(
                f"{label} attempt {link['attempt']!r} does not match its commissioned "
                f"attempt {(attempt_ctx.get('attempt_id'), attempt_ctx.get('kind'))!r}"
            )
        job_ref = commission.get("job")
        if not isinstance(job_ref, Mapping):
            raise CommissionNotDurableError(f"{label} commission has no job reference")
        if job_ref.get("job_id") != portfolio_job_id:
            raise CommissionNotDurableError(
                f"{label} commission job_id {job_ref.get('job_id')!r} does not identify "
                f"this portfolio job {portfolio_job_id!r}; cross-job linking is rejected"
            )
        # When the commission pins source identities, they must agree with the
        # downstream entity; Missing pins remain honest unknownness.
        for source_field, entity_field in (("source_target", "target"), ("source_job_id", "job_id")):
            pinned = job_ref.get(source_field)
            if pinned is None:
                continue
            if _is_missing(pinned):
                continue
            if isinstance(pinned, str) and pinned != entity.get(entity_field):
                raise CommissionNotDurableError(
                    f"{label} commission {source_field} {pinned!r} does not match "
                    f"this job entity {entity_field} {entity.get(entity_field)!r}"
                )


# ---------------------------------------------------------------------------
# Public: downstream publication
# ---------------------------------------------------------------------------


def publish_product_revision(
    channel_id: str,
    registration: Any,
    expected_revision: int,
    command_id: str,
    value: Any,
    lease: Any,
) -> Any:
    """Publish one complete product downstream revision.

    Args:
        channel_id: Authenticated product-writer ingress channel.
        registration: Immutable ``W.EntityRegistration`` for the job entity.
        expected_revision: Caller-expected current head (``previous_revision``).
        command_id: Owner-local idempotency key for this write.
        value: Complete ``W.JobDownstreamValue`` mapping.
        lease: Kernel ``LeaseRecord`` or typed ``Missing`` envelope.

    Returns:
        The committed complete ``W.DataDomainRevision``.

    Raises:
        CrawlerFieldRejectedError: The value carries crawler-owned or
            otherwise undeclared fields; the entire write is rejected.
        SelectionTransitionError: The selection transition lacks a new
            authorized rationale or would drop history.
        AttemptLinkError / CommissionNotDurableError: An attempt link is
            malformed, inherits an outcome, or names an unregistered,
            undurable, or cross-job commission.
        InvalidDownstreamValueError: Any other downstream shape violation.
        PermissionError: The channel is not the registered product writer.
        OwnerRevision errors (stale/integrity/conflict): propagated from the
            owner-local commit without partial effects.
    """
    if not isinstance(channel_id, str) or not channel_id:
        raise InvalidDownstreamValueError("channel_id must be a nonempty identifier")
    if not isinstance(command_id, str) or not command_id:
        raise InvalidDownstreamValueError("command_id must be a nonempty identifier")
    if isinstance(expected_revision, bool) or not isinstance(expected_revision, int):
        raise InvalidDownstreamValueError("expected_revision must be an int")
    if expected_revision < 0 or expected_revision > _MAX_SAFE_INT:
        raise InvalidDownstreamValueError("expected_revision is out of range")
    normalized_lease = _normalize_lease(lease)
    normalized_value = _validate_downstream_value(value)
    reg = _normalize_registration(registration)
    entity = reg["entity"]
    entity_id = _entity_id(entity)
    portfolio_job_id = reg["portfolio_job_id"]

    # Authorize the product writer before any durability work. The resource id
    # is the portfolio job (opaque to authority; grants decide).
    try:
        descriptor = access_policy.authorize(channel_id, DOWNSTREAM_WRITE_OP, portfolio_job_id)
    except Exception:
        raise
    descriptor_owner = getattr(descriptor, "owner_domain", None)
    descriptor_producer = getattr(descriptor, "producer_id", None)
    descriptor_role = getattr(descriptor, "role", None)
    if descriptor_owner != reg["owner_domain"]:
        raise PermissionError(
            f"authenticated producer writes {descriptor_owner!r}, not {reg['owner_domain']!r}"
        )
    if descriptor_producer != reg["writer_id"]:
        raise PermissionError("the serialized writer_id is not the authenticated producer")
    if descriptor_role != "kernel":
        raise PermissionError(
            f"authenticated role {descriptor_role!r} does not match owner role 'product'"
        )

    # Verify the cited registration evidence prefix when locally admitted.
    # This exercises the declared evidence_journal.read_prefix dependency.
    try:
        prefix_cls = getattr(evidence_journal, "JournalPrefix", None)
        if prefix_cls is not None:
            cited = prefix_cls(
                journal_id=reg["evidence_prefix"]["journal_id"],
                last_sequence=reg["evidence_prefix"]["last_sequence"],
                head_hash=reg["evidence_prefix"]["head_hash"],
            )
            try:
                evidence_journal.read_prefix(channel_id, cited)
            except Exception as exc:
                not_admitted = getattr(evidence_journal, "JournalNotAdmittedError", ())
                if isinstance(not_admitted, type) and isinstance(exc, not_admitted):
                    pass
                else:
                    journal_err = getattr(evidence_journal, "EvidenceJournalError", ())
                    auth_err = getattr(access_policy, "AuthorizationError", ())
                    if (
                        (isinstance(journal_err, type) and isinstance(exc, journal_err))
                        or (isinstance(auth_err, type) and isinstance(exc, auth_err))
                    ):
                        raise InvalidDownstreamValueError(
                            f"registration.evidence_prefix does not verify: {exc}"
                        ) from exc
                    raise
    except InvalidDownstreamValueError:
        raise
    except Exception:
        # Prefix-shape errors already raised; anything else here must not mask
        # the authoritative owner commit below. Re-raise unexpected failures.
        raise

    # Load the current head for transition and append-only checks. Staleness
    # itself is enforced authoritatively by owner_revisions.commit_domain so
    # that idempotent retries (same command, same bytes) still succeed.
    prior_value, _prior_revision = _load_prior(channel_id, entity)
    prior_selection = prior_value["selection"] if prior_value is not None else None
    _validate_selection_transition(
        prior_selection, normalized_value["selection"], normalized_value["evaluations"]
    )
    if prior_value is not None:
        _validate_append_only(
            prior_value.get("evaluations", []),
            normalized_value["evaluations"],
            label="value.evaluations",
            identity="evaluation reference",
        )
        _validate_append_only(
            prior_value.get("materials", []),
            normalized_value["materials"],
            label="value.materials",
            identity="material reference",
        )
        _validate_append_only(
            prior_value.get("application_attempts", []),
            normalized_value["application_attempts"],
            label="value.application_attempts",
            identity="attempt link",
        )

    # Attempt links require already-durable registered commissions that
    # identify this portfolio job; links carry no inherited outcome (shape
    # already enforced exactly).
    if normalized_value["application_attempts"]:
        _verify_attempt_links(
            channel_id, entity, portfolio_job_id, normalized_value["application_attempts"]
        )

    # Collect revision-level support evidence from the complete value. Every
    # component carries nonempty SupportRefs, so ownership alone guarantees a
    # nonempty set; dedupe to satisfy uniqueItems.
    collected: list[dict[str, Any]] = []
    seen_refs: set[tuple[str, int, str, str, str]] = set()

    def _collect(refs: Sequence[Mapping[str, Any]]) -> None:
        for ref in refs:
            key = (
                str(ref["journal_id"]),
                int(ref["sequence"]),
                str(ref["event_id"]),
                str(ref["event_hash"]),
                str(ref["pointer"]),
            )
            if key not in seen_refs:
                seen_refs.add(key)
                collected.append(dict(ref))

    if not _is_missing(normalized_value["selection"]):
        _collect(normalized_value["selection"]["evidence_refs"])
    _collect(normalized_value["ownership"]["evidence_refs"])
    for entry in normalized_value["evaluations"]:
        _collect(entry["evidence_refs"])
    for entry in normalized_value["materials"]:
        _collect(entry["evidence_refs"])
    for entry in normalized_value["application_attempts"]:
        _collect(entry["evidence_refs"])
    if not collected:
        for ref in reg["evidence_refs"]:
            _collect([ref])
    if not collected:  # pragma: no cover - ownership guarantees nonempty
        raise InvalidDownstreamValueError("downstream revision requires nonempty evidence_refs")

    registration_digest = _registration_digest(entity_id, registration)
    new_revision_number = expected_revision + 1
    revision_dict = {
        "record_type": RECORD_TYPE,
        "schema_version": SCHEMA_VERSION,
        "entity": dict(entity),
        "registration_digest": registration_digest,
        "domain": DOWNSTREAM_DOMAIN,
        "owner_domain": reg["owner_domain"],
        "writer_id": reg["writer_id"],
        "revision": new_revision_number,
        "previous_revision": expected_revision,
        "evidence_prefix": dict(reg["evidence_prefix"]),
        "evidence_refs": collected,
        "value": copy.deepcopy(normalized_value),
    }
    # Strict-gate the complete revision document before the owner commit.
    _strict_gate(revision_dict, "W.DataDomainRevision")

    revision_cls = getattr(owner_revisions, "DataDomainRevision", None)
    if revision_cls is not None:
        try:
            revision_obj = revision_cls.from_dict(revision_dict)
        except Exception as exc:
            raise InvalidDownstreamValueError(f"cannot construct DataDomainRevision: {exc}") from exc
    else:  # pragma: no cover - owner_revisions always exposes the type
        revision_obj = revision_dict

    registration_cls = getattr(owner_revisions, "EntityRegistration", None)
    if registration_cls is not None and not isinstance(registration, registration_cls):
        try:
            if isinstance(registration, Mapping):
                registration_obj = registration_cls.from_dict(dict(reg["raw"]))
            else:
                registration_obj = registration
        except Exception:
            registration_obj = registration
    else:
        registration_obj = registration

    # Owner-local atomic commit (revision advance + journal evidence). No peer
    # lock, no read-view wait, no crawler acknowledgement. Stale expected
    # revisions, integrity conflicts, and command conflicts propagate with no
    # partial effects and no local-cache mutation below.
    owner_revisions.commit_domain(
        channel_id, registration_obj, revision_obj, command_id, normalized_lease
    )

    # Record owner-local caches only after durability is acknowledged.
    with _STATE_LOCK:
        _PRIOR_VALUES[entity_id] = copy.deepcopy(normalized_value)
        _HEADS[entity_id] = new_revision_number
        if not _is_missing(normalized_value["selection"]):
            selection = normalized_value["selection"]
            history = _SELECTION_HISTORY.setdefault(entity_id, [])
            last = history[-1] if history else None
            changed = (
                last is None
                or last.get("decision") != selection["decision"]
                or last.get("rationale") != selection["rationale"]
                or last.get("evidence_refs") != selection["evidence_refs"]
                or last.get("evaluation_id") != selection["evaluation_id"]
            )
            if changed:
                history.append(
                    {
                        "revision": new_revision_number,
                        "decision": selection["decision"],
                        "evaluation_id": copy.deepcopy(selection["evaluation_id"]),
                        "rationale": selection["rationale"],
                        "evidence_refs": copy.deepcopy(selection["evidence_refs"]),
                    }
                )
    return revision_obj

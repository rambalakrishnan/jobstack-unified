"""job_evaluation: pinned evaluation, normalization, and ranking (tier 7).

Implements seam mapping section 8 (evaluation pipeline and artifacts) and
section 6.2 (EvaluationReference / LogicalRow linkage) on top of the
evidence kernel siblings:

* Evaluations pin the exact logical row artifact, seal, crawler revision,
  candidate profile, playbook catalog, and policy versions they evaluated.
* The raw reranker response is retained unchanged; normalization maps eight
  closed fields and surfaces issues for unknown playbook labels, unmapped
  pay representations, and scores without a pinned rubric.
* The automatic two-stage decision table never invents waivers, thresholds,
  or tolerance: missing prerequisites yield review.
* Embedding similarity is versioned evidence, not eligibility; model or
  dimension mismatches invalidate comparison.
* Rankings are scoped to their pinned included evaluations; rank is the
  one-based position within that artifact only.

Missing values are always typed ``K.Missing`` envelopes; bare nulls and
nonfinite numbers are rejected. No compensation thresholds, score ranges,
weights, eligibility waivers, or tolerance policies are invented here.
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
import math
import re
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


def _load_sibling(name: str):  # pragma: no cover - import plumbing
    if name in sys.modules:
        return sys.modules[name]
    try:
        return importlib.import_module(name)
    except ModuleNotFoundError:
        pass
    sibling_path = Path(__file__).resolve().parents[2] / name / "src" / "__init__.py"
    spec = importlib.util.spec_from_file_location(name, sibling_path)
    if spec is None or spec.loader is None:
        raise ModuleNotFoundError(f"sibling module {name!r} not found")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _load_optional(name: str):  # pragma: no cover - import plumbing
    if name in sys.modules:
        return sys.modules[name]
    try:
        return importlib.import_module(name)
    except ModuleNotFoundError:
        pass
    sibling_path = Path(__file__).resolve().parents[2] / name / "src" / "__init__.py"
    if not sibling_path.exists():
        return None
    spec = importlib.util.spec_from_file_location(name, sibling_path)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


contract_codec = _load_sibling("contract_codec")
access_policy = _load_sibling("access_policy")
artifact_store = _load_sibling("artifact_store")
evidence_journal = _load_sibling("evidence_journal")
candidate_inputs = _load_sibling("candidate_inputs")
model_gateway = _load_sibling("model_gateway")
crawler_intake = _load_optional("crawler_intake")

__all__ = [
    "EVALUATION_RECORD_TYPE",
    "EVALUATION_SCHEMA_VERSION",
    "RANKING_RECORD_TYPE",
    "RANKING_SCHEMA_VERSION",
    "EMBEDDING_RECORD_TYPE",
    "EMBEDDING_SCHEMA_VERSION",
    "PLAYBOOK_IDS",
    "OWNER_DOWNSTREAM",
    "JobEvaluationError",
    "PinMismatchError",
    "ProfilePinMismatchError",
    "EvaluationLinkageError",
    "NormalizationError",
    "EmbeddingMismatchError",
    "PolicyError",
    "RankingError",
    "Missing",
    "VersionPin",
    "NonzeroDomainPin",
    "JobEntityKey",
    "EvaluationJobInput",
    "EvaluationPolicyPins",
    "NormalizedRerankerOutput",
    "EvaluationStage",
    "PlaybookMatch",
    "UnresolvedItem",
    "EvaluationArtifact",
    "RankingArtifact",
    "EvaluationReference",
    "evaluate_job",
    "rank_evaluations",
    "validate_crawler_pin",
    "validate_profile_pin",
    "check_evaluation_reference",
    "build_evaluation_reference",
    "normalize_reranker_response",
    "decide_stages",
    "validate_embedding_comparison",
    "extract_crawler_pin",
    "reset_for_tests",
]

EVALUATION_RECORD_TYPE = "job_hunter_evaluation"
EVALUATION_SCHEMA_VERSION = "job-hunter-evaluation/0.1.0"
RANKING_RECORD_TYPE = "job_hunter_ranking"
RANKING_SCHEMA_VERSION = "job-hunter-ranking/0.1.0"
EMBEDDING_RECORD_TYPE = "job_profile_embedding_comparison"
EMBEDDING_SCHEMA_VERSION = "job-hunter-embedding/0.1.0"

PLAYBOOK_IDS: tuple[str, ...] = (
    "pb01_structural_deconstruction",
    "pb02_human_asset_optimization",
    "pb03_compliance_automation",
    "pb04_field_triage",
    "pb05_hardware_software_integration",
    "pb06_cognitive_offloading",
    "pb07_public_governance",
    "pb08_campaign_engineering",
)
_PLAYBOOK_ID_SET = frozenset(PLAYBOOK_IDS)

VALID_METHODS = frozenset({"llm", "deterministic", "human_assessment"})
VALID_PAY = frozenset({"acceptable", "unacceptable", "unknown"})
VALID_STAGE_RESULTS = frozenset({"pass", "fail", "review"})
VALID_SELECTIONS = frozenset({"go", "no_go", "review"})
VALID_MISSING_REASONS = frozenset({
    "not_enabled",
    "not_applicable",
    "not_observed",
    "observation_lost",
    "unsupported_by_subject",
    "manual_override",
})

OWNER_DOWNSTREAM = "job.downstream"

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_CODEC_GATE_SCHEMA = "record/v1"

_EVALUATION_FIELDS = frozenset({
    "record_type", "schema_version", "evaluation_id", "candidate_id",
    "job_input", "candidate_profile", "playbook_catalog", "policies",
    "method", "raw_reranker", "normalized_reranker", "embedding",
    "stage_one", "stage_two", "pay_decision", "recommended_selection",
    "playbook_matches", "normalization_issues", "model_calls",
    "input_prefix", "evidence_refs",
})
_JOB_INPUT_FIELDS = frozenset({
    "portfolio_job_id", "source_key", "logical_row", "logical_row_ref",
    "seal_id", "crawler_input",
})
_POLICY_FIELDS = frozenset({
    "rubric", "eligibility", "tolerance", "pay", "veto", "normalizer", "prompt",
})
_NORMALIZED_FIELDS = frozenset({
    "can_do_70_percent", "hard_blockers", "playbooks_matched",
    "would_tolerate", "pay_ok", "legibility_gap", "resume_translation",
    "score",
})
_STAGE_FIELDS = frozenset({"result", "rationale", "evidence_refs"})
_MATCH_FIELDS = frozenset({
    "playbook_id", "job_primitives", "candidate_source_refs",
    "job_source_refs", "rationale", "limitations",
})
_ISSUE_FIELDS = frozenset({"code", "detail", "affected_fields", "evidence_refs"})
_REFERENCE_FIELDS = frozenset({
    "evaluation_id", "crawler_input", "candidate_profile", "evaluation",
    "evidence_refs",
})
_RANKING_FIELDS = frozenset({
    "record_type", "schema_version", "ranking_id", "policy",
    "evaluation_refs", "ordered_evaluation_ids", "input_prefix",
    "evidence_refs",
})
_EMBEDDING_FIELDS = frozenset({
    "record_type", "schema_version", "comparison_id", "candidate_profile",
    "job_snapshot", "chunking_policy", "model", "vector_dimension",
    "profile_vectors", "job_vector", "similarity_method", "similarities",
    "evidence_refs",
})

_LOCK = threading.Lock()
_EVAL_COUNTER = 0
_RANK_COUNTER = 0


def reset_for_tests() -> None:
    """Reset module-local idempotency counters (tests only)."""
    global _EVAL_COUNTER, _RANK_COUNTER
    with _LOCK:
        _EVAL_COUNTER = 0
        _RANK_COUNTER = 0


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class JobEvaluationError(Exception):
    """Base class for job-evaluation failures."""


class PinMismatchError(JobEvaluationError, ValueError):
    """An evaluation pin differs from the logical-row crawler slot."""


class ProfilePinMismatchError(JobEvaluationError, ValueError):
    """A profile pin differs between reference and evaluation artifact."""


class EvaluationLinkageError(JobEvaluationError, ValueError):
    """Row / evaluation / reference linkage does not agree exactly."""


class NormalizationError(JobEvaluationError, ValueError):
    """A raw reranker response cannot be normalized without invention."""


class EmbeddingMismatchError(JobEvaluationError, ValueError):
    """An embedding model/version or dimension mismatch invalidates comparison."""


class PolicyError(JobEvaluationError, ValueError):
    """A policy pin is missing, malformed, or unretained."""


class RankingError(JobEvaluationError, ValueError):
    """A ranking scope is empty, ambiguous, or inconsistent."""


# ---------------------------------------------------------------------------
# Scalar helpers
# ---------------------------------------------------------------------------


def _require_identifier(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field} must be a str, not {type(value).__name__}")
    if not value or value != value.strip():
        raise ValueError(f"{field} must be a nonempty identifier without padding")
    if len(value) > 256:
        raise ValueError(f"{field} must be at most 256 characters")
    if any(ord(ch) < 0x20 for ch in value):
        raise ValueError(f"{field} must not contain control characters")
    return value


def _require_nonempty_str(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field} must be a str, not {type(value).__name__}")
    if not value:
        raise ValueError(f"{field} must be a nonempty string")
    return value


def _require_digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.match(value):
        raise ValueError(f"{field} must be a sha256:<64 lowercase hex> digest")
    return value


def _require_positive_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{field} must be an int")
    if value <= 0:
        raise ValueError(f"{field} must be a positive integer")
    return value


def _require_revision(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{field} must be an int")
    if value < 0:
        raise ValueError(f"{field} must be a nonnegative integer")
    return value


def _canonical_bytes(obj: Any) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _is_finite_number(v: Any) -> bool:
    if isinstance(v, bool):
        return False
    if isinstance(v, int):
        return True
    return isinstance(v, float) and math.isfinite(v)


def _reject_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for k, v in pairs:
        if k in obj:
            raise ValueError(f"duplicate object key: {k!r}")
        obj[k] = v
    return obj


def _strict_gate(raw: bytes, context: str) -> Any:
    """Parse strict JSON: no duplicates, no bare-null confusion, no nonfinite."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise NormalizationError(f"{context} is not valid UTF-8: {exc}") from exc
    try:
        obj = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_object,
            parse_constant=_reject_nonfinite_literal,
        )
    except ValueError as exc:
        raise NormalizationError(f"{context} is not valid JSON: {exc}") from exc
    _check_finite_raw(obj, context)
    return obj


def _parse_raw_json(raw: Any, context: str) -> Any:
    if isinstance(raw, (bytes, bytearray)):
        return _strict_gate(bytes(raw), context)
    if isinstance(raw, str):
        return _strict_gate(raw.encode("utf-8"), context)
    if isinstance(raw, Mapping):
        # Re-encode through the strict gate to reject nonfinite/duplicates.
        try:
            encoded = _canonical_bytes(dict(raw))
        except (ValueError, TypeError) as exc:
            raise NormalizationError(
                f"{context} is not strict JSON content: {exc}"
            ) from exc
        return _strict_gate(encoded, context)
    if hasattr(raw, "to_dict") and callable(raw.to_dict):
        return _parse_raw_json(raw.to_dict(), context)
    raise NormalizationError(
        f"{context} must be bytes, str, or a mapping; got {type(raw).__name__}"
    )


def _reject_nonfinite_literal(s: str) -> Any:
    raise ValueError(f"nonfinite number literal rejected: {s!r}")


def _check_finite_raw(node: Any, path: str) -> None:
    if isinstance(node, float) and not math.isfinite(node):
        raise NormalizationError(f"nonfinite number at {path}")
    if isinstance(node, dict):
        for k, v in node.items():
            _check_finite_raw(v, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            _check_finite_raw(v, f"{path}[{i}]")


def _prefix_to_dict(prefix: Any) -> dict[str, Any]:
    if hasattr(prefix, "to_dict") and callable(prefix.to_dict):
        d = prefix.to_dict()
        if isinstance(d, dict):
            return dict(d)
    if isinstance(prefix, Mapping):
        return dict(prefix)
    return {
        "journal_id": prefix.journal_id,
        "last_sequence": prefix.last_sequence,
        "head_hash": prefix.head_hash,
    }


def _plain(value: Any) -> Any:
    """Convert sibling dataclasses to plain JSON-ready content."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Missing):
        return value.to_dict()
    if isinstance(value, Mapping):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    if hasattr(value, "to_dict") and callable(value.to_dict):
        try:
            return _plain(value.to_dict())
        except TypeError:
            pass
    return value


# ---------------------------------------------------------------------------
# Missing + VersionPin
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Missing:
    """Typed missingness envelope (``K.Missing``); never an in-band null."""

    reason: str = "not_observed"
    detail: str | None = None

    def __post_init__(self) -> None:
        if self.reason not in VALID_MISSING_REASONS:
            raise ValueError(f"unknown Missing reason: {self.reason!r}")
        if self.detail is not None and (
            not isinstance(self.detail, str) or not self.detail
        ):
            raise ValueError("Missing.detail must be a nonempty string when present")

    @property
    def value(self) -> None:
        return None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"value": None, "reason": self.reason}
        if self.detail is not None:
            out["detail"] = self.detail
        return out

    @classmethod
    def from_dict(cls, data: Any) -> "Missing":
        if isinstance(data, Missing):
            return data
        if hasattr(data, "to_dict") and callable(data.to_dict) and not isinstance(data, dict):
            return cls.from_dict(data.to_dict())
        if not isinstance(data, dict):
            raise TypeError("Missing must be decoded from a dict")
        keys = set(data.keys())
        allowed = {"value", "reason", "detail", "detail".lower()}
        extra = keys - allowed - {"detail"}
        if extra:
            raise ValueError(f"undeclared Missing properties: {sorted(extra)}")
        if data.get("value") is not None or "value" not in data:
            raise ValueError("Missing.value must be null")
        reason = data.get("reason")
        if not isinstance(reason, str):
            raise ValueError("Missing.reason must be a string")
        detail = data.get("Detail", data.get("detail"))
        if "Detail" in data and "detail" in data:
            raise ValueError("Missing must not carry both Detail spellings")
        if detail is not None and (not isinstance(detail, str) or not detail):
            raise ValueError("Missing.detail must be a nonempty string when present")
        return cls(reason=reason, detail=detail)


def _is_missing_dict(data: Any) -> bool:
    return (
        isinstance(data, dict)
        and data.get("value") is None
        and "value" in data
        and "reason" in data
    )


def _is_missing_value(v: Any) -> bool:
    if isinstance(v, Missing):
        return True
    # Sibling Missing types (candidate_inputs, evidence_journal, access_policy).
    mod_name = type(v).__module__ + "." + type(v).__name__
    if mod_name.endswith("Missing") and hasattr(v, "reason"):
        return True
    if _is_missing_dict(v):
        return True
    if hasattr(v, "to_dict") and callable(v.to_dict) and not isinstance(
        v, (str, bytes, int, float, bool)
    ):
        try:
            d = v.to_dict()
        except Exception:
            return False
        return _is_missing_dict(d)
    return False


def _missing_reason(v: Any) -> str | None:
    if isinstance(v, Missing):
        return v.reason
    if isinstance(v, dict) and _is_missing_dict(v):
        r = v.get("reason")
        return r if isinstance(r, str) else None
    if hasattr(v, "reason"):
        r = getattr(v, "reason")
        return r if isinstance(r, str) else None
    if hasattr(v, "to_dict") and callable(v.to_dict):
        try:
            return _missing_reason(v.to_dict())
        except Exception:
            return None
    return None


def _missing_to_dict(v: Any) -> dict[str, Any]:
    if isinstance(v, Missing):
        return v.to_dict()
    if isinstance(v, dict) and _is_missing_dict(v):
        return Missing.from_dict(v).to_dict()
    if hasattr(v, "to_dict") and callable(v.to_dict):
        return Missing.from_dict(v.to_dict()).to_dict()
    raise TypeError(f"expected a Missing envelope, got {type(v).__name__}")


@dataclass(frozen=True, slots=True)
class VersionPin:
    """Immutable pin of a code/schema/policy/catalog artifact."""

    id: str
    version: str
    artifact_digest: str

    def __post_init__(self) -> None:
        _require_identifier(self.id, "VersionPin.id")
        _require_identifier(self.version, "VersionPin.version")
        _require_digest(self.artifact_digest, "VersionPin.artifact_digest")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "version": self.version,
            "artifact_digest": self.artifact_digest,
        }

    @classmethod
    def from_dict(cls, data: Any) -> "VersionPin":
        if isinstance(data, VersionPin):
            return data
        if hasattr(data, "to_dict") and callable(data.to_dict) and not isinstance(data, dict):
            return cls.from_dict(data.to_dict())
        if not isinstance(data, dict):
            raise TypeError("VersionPin must be decoded from a dict")
        keys = set(data.keys())
        if keys != {"id", "version", "artifact_digest"}:
            raise ValueError(
                "VersionPin must contain exactly id, version, artifact_digest; "
                f"got {sorted(keys)}"
            )
        for key in ("id", "version", "artifact_digest"):
            if data[key] is None:
                raise ValueError(f"VersionPin.{key} must not be a bare null")
        return cls(
            id=data["id"], version=data["version"],
            artifact_digest=data["artifact_digest"],
        )


def _coerce_version_pin(value: Any, field: str) -> VersionPin:
    try:
        if isinstance(value, VersionPin):
            return value
        if isinstance(value, dict):
            return VersionPin.from_dict(value)
        if hasattr(value, "to_dict") and callable(value.to_dict):
            return VersionPin.from_dict(value.to_dict())
        # Sibling VersionPin dataclasses expose id/version/artifact_digest.
        if (
            hasattr(value, "id")
            and hasattr(value, "version")
            and hasattr(value, "artifact_digest")
        ):
            return VersionPin(
                id=value.id, version=value.version,
                artifact_digest=value.artifact_digest,
            )
    except (TypeError, ValueError) as exc:
        raise PolicyError(f"{field} is not a valid VersionPin: {exc}") from exc
    raise PolicyError(f"{field} is not a valid VersionPin: {type(value).__name__}")


def _coerce_version_pin_or_missing(value: Any, field: str) -> Any:
    if _is_missing_value(value):
        try:
            if isinstance(value, Missing):
                return value
            if isinstance(value, dict):
                return Missing.from_dict(value)
            d = value.to_dict() if hasattr(value, "to_dict") else None
            if isinstance(d, dict):
                return Missing.from_dict(d)
            reason = _missing_reason(value)
            detail = getattr(value, "detail", None)
            if isinstance(reason, str):
                return Missing(
                    reason=reason,
                    detail=detail if isinstance(detail, str) else None,
                )
        except (TypeError, ValueError) as exc:
            raise PolicyError(
                f"{field} is not a valid VersionPin or Missing: {exc}"
            ) from exc
        raise PolicyError(f"{field} is not a valid VersionPin or Missing")
    return _coerce_version_pin(value, field)


@dataclass(frozen=True, slots=True)
class NonzeroDomainPin:
    """Exact nonzero crawler revision and document digest."""

    revision: int
    record_digest: str

    def __post_init__(self) -> None:
        if isinstance(self.revision, bool) or not isinstance(self.revision, int):
            raise TypeError("NonzeroDomainPin.revision must be an int")
        if self.revision <= 0:
            raise ValueError("NonzeroDomainPin.revision must be positive")
        _require_digest(self.record_digest, "NonzeroDomainPin.record_digest")

    def to_dict(self) -> dict[str, Any]:
        return {"revision": self.revision, "record_digest": self.record_digest}

    @classmethod
    def from_dict(cls, data: Any) -> "NonzeroDomainPin":
        if isinstance(data, NonzeroDomainPin):
            return data
        if hasattr(data, "to_dict") and callable(data.to_dict) and not isinstance(data, dict):
            return cls.from_dict(data.to_dict())
        if not isinstance(data, dict):
            raise TypeError("NonzeroDomainPin must be decoded from a dict")
        keys = set(data.keys())
        if keys != {"revision", "record_digest"}:
            raise ValueError(
                "NonzeroDomainPin must contain exactly revision, record_digest; "
                f"got {sorted(keys)}"
            )
        return cls(revision=data["revision"], record_digest=data["record_digest"])


@dataclass(frozen=True, slots=True)
class JobEntityKey:
    """Source posting root ``(target, job_id)``."""

    target: str
    job_id: str
    entity_type: str = "job"

    def __post_init__(self) -> None:
        _require_identifier(self.target, "JobEntityKey.target")
        _require_identifier(self.job_id, "JobEntityKey.job_id")
        if self.entity_type != "job":
            raise ValueError("JobEntityKey.entity_type must be 'job'")

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity_type": self.entity_type,
            "target": self.target,
            "job_id": self.job_id,
        }

    @classmethod
    def from_dict(cls, data: Any) -> "JobEntityKey":
        if isinstance(data, JobEntityKey):
            return data
        if hasattr(data, "to_dict") and callable(data.to_dict) and not isinstance(data, dict):
            return cls.from_dict(data.to_dict())
        if not isinstance(data, dict):
            raise TypeError("JobEntityKey must be decoded from a dict")
        keys = set(data.keys())
        if keys != {"entity_type", "target", "job_id"}:
            raise ValueError(
                "JobEntityKey must contain exactly entity_type, target, job_id; "
                f"got {sorted(keys)}"
            )
        return cls(
            target=data["target"], job_id=data["job_id"],
            entity_type=data["entity_type"],
        )


def _coerce_artifact_ref(value: Any, field: str) -> Any:
    try:
        if isinstance(value, artifact_store.ArtifactReference):
            return value
        if isinstance(value, dict):
            return artifact_store.ArtifactReference.from_dict(dict(value))
        if hasattr(value, "to_dict") and callable(value.to_dict):
            d = value.to_dict()
            if isinstance(d, dict):
                return artifact_store.ArtifactReference.from_dict(d)
        if (
            hasattr(value, "digest")
            and hasattr(value, "size_bytes")
            and hasattr(value, "media_type")
        ):
            return artifact_store.ArtifactReference(
                digest=value.digest,
                size_bytes=value.size_bytes,
                media_type=value.media_type,
                owner_domain=value.owner_domain,
                access=value.access,
            )
    except (TypeError, ValueError) as exc:
        raise EvaluationLinkageError(
            f"{field} is not a valid ArtifactReference: {exc}"
        ) from exc
    raise EvaluationLinkageError(
        f"{field} is not a valid ArtifactReference: {type(value).__name__}"
    )


def _coerce_evidence_ref(value: Any, field: str) -> Any:
    try:
        if isinstance(value, evidence_journal.EvidenceRef):
            return value
        if isinstance(value, Mapping):
            return evidence_journal.EvidenceRef.from_dict(dict(value))
        if hasattr(value, "to_dict") and callable(value.to_dict):
            d = value.to_dict()
            if isinstance(d, Mapping):
                return evidence_journal.EvidenceRef.from_dict(dict(d))
        if hasattr(value, "journal_id") and hasattr(value, "sequence"):
            return evidence_journal.EvidenceRef(
                journal_id=value.journal_id,
                sequence=value.sequence,
                event_id=value.event_id,
                event_hash=value.event_hash,
                pointer=getattr(value, "pointer", ""),
            )
    except (TypeError, ValueError) as exc:
        raise EvaluationLinkageError(
            f"{field} is not a valid EvidenceRef: {exc}"
        ) from exc
    raise EvaluationLinkageError(
        f"{field} is not a valid EvidenceRef: {type(value).__name__}"
    )


def _coerce_prefix(value: Any, field: str = "input_prefix") -> Any:
    try:
        if isinstance(value, evidence_journal.JournalPrefix):
            return value
        if isinstance(value, Mapping):
            d = dict(value)
            return evidence_journal.JournalPrefix(
                journal_id=d["journal_id"],
                last_sequence=d["last_sequence"],
                head_hash=d["head_hash"],
            )
        if hasattr(value, "to_dict") and callable(value.to_dict):
            d = value.to_dict()
            if isinstance(d, Mapping):
                return _coerce_prefix(dict(d), field)
        if hasattr(value, "journal_id") and hasattr(value, "last_sequence"):
            return evidence_journal.JournalPrefix(
                journal_id=value.journal_id,
                last_sequence=value.last_sequence,
                head_hash=value.head_hash,
            )
    except (TypeError, ValueError, KeyError) as exc:
        raise EvaluationLinkageError(
            f"{field} is not a valid JournalPrefix: {exc}"
        ) from exc
    raise EvaluationLinkageError(
        f"{field} is not a valid JournalPrefix: {type(value).__name__}"
    )


def _artifact_digest(ref: Any) -> str:
    if isinstance(ref, dict):
        d = ref.get("digest")
        if isinstance(d, str):
            return d
    if hasattr(ref, "digest"):
        d = ref.digest
        if isinstance(d, str):
            return d
    if hasattr(ref, "to_dict") and callable(ref.to_dict):
        try:
            return _artifact_digest(ref.to_dict())
        except Exception:
            pass
    raise EvaluationLinkageError(
        f"artifact reference carries no digest: {type(ref).__name__}"
    )


def _artifact_to_dict(ref: Any) -> dict[str, Any]:
    if isinstance(ref, dict):
        return dict(ref)
    if hasattr(ref, "to_dict") and callable(ref.to_dict):
        d = ref.to_dict()
        if isinstance(d, dict):
            return dict(d)
    raise EvaluationLinkageError(
        f"artifact reference is not serializable: {type(ref).__name__}"
    )


def _require_known_digest(digest: str, field: str) -> None:
    try:
        known = artifact_store.known_digests()
    except Exception:
        return
    if digest not in known:
        raise EvaluationLinkageError(
            f"{field} names digest {digest} with no retained bytes; "
            "a locator or hash alone cannot substitute for archived content"
        )


def _resolve_pinned_bytes(channel_id: str, ref: Any) -> bytes:
    coerced = _coerce_artifact_ref(ref, "artifact_ref")
    return artifact_store.resolve_artifact(channel_id, coerced)


# ---------------------------------------------------------------------------
# Evaluation records
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EvaluationJobInput:
    """Pinned crawler input consumed by one evaluation."""

    portfolio_job_id: str
    source_key: JobEntityKey
    logical_row: Any
    logical_row_ref: Any
    seal_id: str
    crawler_input: NonzeroDomainPin

    def __post_init__(self) -> None:
        _require_identifier(self.portfolio_job_id, "job_input.portfolio_job_id")
        if not isinstance(self.source_key, JobEntityKey):
            raise TypeError("job_input.source_key must be a JobEntityKey")
        _coerce_artifact_ref(self.logical_row, "job_input.logical_row")
        _coerce_evidence_ref(self.logical_row_ref, "job_input.logical_row_ref")
        _require_identifier(self.seal_id, "job_input.seal_id")
        if not isinstance(self.crawler_input, NonzeroDomainPin):
            raise TypeError("job_input.crawler_input must be a NonzeroDomainPin")

    def to_dict(self) -> dict[str, Any]:
        return {
            "portfolio_job_id": self.portfolio_job_id,
            "source_key": self.source_key.to_dict(),
            "logical_row": _artifact_to_dict(self.logical_row),
            "logical_row_ref": self.logical_row_ref.to_dict()
            if hasattr(self.logical_row_ref, "to_dict")
            else dict(self.logical_row_ref),
            "seal_id": self.seal_id,
            "crawler_input": self.crawler_input.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: Any) -> "EvaluationJobInput":
        if isinstance(data, EvaluationJobInput):
            return data
        if hasattr(data, "to_dict") and callable(data.to_dict) and not isinstance(data, dict):
            return cls.from_dict(data.to_dict())
        if not isinstance(data, dict):
            raise TypeError("EvaluationJobInput must be decoded from a dict")
        if set(data.keys()) != _JOB_INPUT_FIELDS:
            raise ValueError(
                "EvaluationJobInput must contain exactly "
                f"{sorted(_JOB_INPUT_FIELDS)}; got {sorted(data.keys())}"
            )
        return cls(
            portfolio_job_id=data["portfolio_job_id"],
            source_key=JobEntityKey.from_dict(data["source_key"]),
            logical_row=_coerce_artifact_ref(data["logical_row"], "job_input.logical_row"),
            logical_row_ref=_coerce_evidence_ref(
                data["logical_row_ref"], "job_input.logical_row_ref"
            ),
            seal_id=data["seal_id"],
            crawler_input=NonzeroDomainPin.from_dict(data["crawler_input"]),
        )


@dataclass(frozen=True, slots=True)
class EvaluationPolicyPins:
    """Version pins for every policy input; veto/normalizer always pinned."""

    rubric: Any
    eligibility: Any
    tolerance: Any
    pay: Any
    veto: VersionPin
    normalizer: VersionPin
    prompt: Any

    def __post_init__(self) -> None:
        for field in ("rubric", "eligibility", "tolerance", "pay", "prompt"):
            v = getattr(self, field)
            if _is_missing_value(v):
                Missing.from_dict(
                    v.to_dict() if hasattr(v, "to_dict") else v
                    if isinstance(v, (dict, Missing)) or hasattr(v, "to_dict")
                    else {"value": None, "reason": _missing_reason(v) or "not_observed"}
                ) if not isinstance(v, Missing) else None
            elif not isinstance(v, VersionPin):
                raise TypeError(f"policies.{field} must be a VersionPin or Missing")
        if not isinstance(self.veto, VersionPin):
            raise TypeError("policies.veto must be a VersionPin")
        if not isinstance(self.normalizer, VersionPin):
            raise TypeError("policies.normalizer must be a VersionPin")

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for field in ("rubric", "eligibility", "tolerance", "pay", "prompt"):
            v = getattr(self, field)
            if isinstance(v, VersionPin):
                out[field] = v.to_dict()
            elif isinstance(v, Missing):
                out[field] = v.to_dict()
            elif _is_missing_value(v):
                out[field] = _missing_to_dict(v)
            else:
                out[field] = v.to_dict() if hasattr(v, "to_dict") else v
        out["veto"] = self.veto.to_dict()
        out["normalizer"] = self.normalizer.to_dict()
        return out

    @classmethod
    def from_dict(cls, data: Any) -> "EvaluationPolicyPins":
        if isinstance(data, EvaluationPolicyPins):
            return data
        if hasattr(data, "to_dict") and callable(data.to_dict) and not isinstance(data, dict):
            return cls.from_dict(data.to_dict())
        if not isinstance(data, dict):
            raise TypeError("EvaluationPolicyPins must be decoded from a dict")
        if set(data.keys()) != _POLICY_FIELDS:
            raise ValueError(
                "EvaluationPolicyPins must contain exactly "
                f"{sorted(_POLICY_FIELDS)}; got {sorted(data.keys())}"
            )
        return cls(
            rubric=_coerce_version_pin_or_missing(data["rubric"], "policies.rubric"),
            eligibility=_coerce_version_pin_or_missing(
                data["eligibility"], "policies.eligibility"
            ),
            tolerance=_coerce_version_pin_or_missing(
                data["tolerance"], "policies.tolerance"
            ),
            pay=_coerce_version_pin_or_missing(data["pay"], "policies.pay"),
            veto=_coerce_version_pin(data["veto"], "policies.veto"),
            normalizer=_coerce_version_pin(data["normalizer"], "policies.normalizer"),
            prompt=_coerce_version_pin_or_missing(data["prompt"], "policies.prompt"),
        )


@dataclass(frozen=True, slots=True)
class NormalizedRerankerOutput:
    """Closed eight-field normalized reranker assessment."""

    can_do_70_percent: Any
    hard_blockers: Any
    playbooks_matched: Any
    would_tolerate: Any
    pay_ok: str
    legibility_gap: Any
    resume_translation: Any
    score: Any

    def __post_init__(self) -> None:
        for field in ("can_do_70_percent", "would_tolerate"):
            v = getattr(self, field)
            if isinstance(v, bool):
                continue
            if _is_missing_value(v):
                continue
            raise TypeError(f"normalized.{field} must be a bool or Missing")
        for field in ("hard_blockers", "playbooks_matched", "resume_translation"):
            v = getattr(self, field)
            if _is_missing_value(v):
                continue
            if not isinstance(v, tuple):
                raise TypeError(f"normalized.{field} must be a tuple or Missing")
            for entry in v:
                if not isinstance(entry, str) or not entry:
                    raise ValueError(
                        f"normalized.{field} entries must be nonempty strings"
                    )
        if self.pay_ok not in VALID_PAY:
            raise NormalizationError(
                f"pay_ok must be one of {sorted(VALID_PAY)}; got {self.pay_ok!r}"
            )
        if not _is_missing_value(self.legibility_gap) and not (
            isinstance(self.legibility_gap, str) and self.legibility_gap
        ):
            raise TypeError("normalized.legibility_gap must be a string or Missing")
        if not _is_missing_value(self.score) and not _is_finite_number(self.score):
            raise TypeError("normalized.score must be a finite number or Missing")

    def to_dict(self) -> dict[str, Any]:
        def _enc(v: Any) -> Any:
            if isinstance(v, bool | str | int | float):
                return v
            if isinstance(v, tuple):
                return list(v)
            if _is_missing_value(v):
                return _missing_to_dict(v)
            return _plain(v)

        return {
            "can_do_70_percent": _enc(self.can_do_70_percent),
            "hard_blockers": _enc(self.hard_blockers),
            "playbooks_matched": _enc(self.playbooks_matched),
            "would_tolerate": _enc(self.would_tolerate),
            "pay_ok": self.pay_ok,
            "legibility_gap": _enc(self.legibility_gap),
            "resume_translation": _enc(self.resume_translation),
            "score": _enc(self.score),
        }

    @classmethod
    def from_dict(cls, data: Any) -> "NormalizedRerankerOutput":
        if isinstance(data, NormalizedRerankerOutput):
            return data
        if hasattr(data, "to_dict") and callable(data.to_dict) and not isinstance(data, dict):
            return cls.from_dict(data.to_dict())
        if not isinstance(data, dict):
            raise TypeError("NormalizedRerankerOutput must be decoded from a dict")
        if set(data.keys()) != _NORMALIZED_FIELDS:
            raise ValueError(
                "NormalizedRerankerOutput must contain exactly "
                f"{sorted(_NORMALIZED_FIELDS)}; got {sorted(data.keys())}"
            )

        def _dec_bool(v: Any, field: str) -> Any:
            if isinstance(v, bool):
                return v
            if _is_missing_value(v):
                return Missing.from_dict(
                    v if isinstance(v, dict) else v.to_dict()
                )
            raise NormalizationError(f"normalized.{field} must be a bool or Missing")

        def _dec_str_tuple(v: Any, field: str) -> Any:
            if _is_missing_value(v):
                return Missing.from_dict(v if isinstance(v, dict) else v.to_dict())
            if isinstance(v, list):
                for entry in v:
                    if not isinstance(entry, str) or not entry:
                        raise NormalizationError(
                            f"normalized.{field} entries must be nonempty strings"
                        )
                return tuple(v)
            if isinstance(v, tuple):
                return v
            raise NormalizationError(f"normalized.{field} must be an array or Missing")

        def _dec_str(v: Any, field: str) -> Any:
            if isinstance(v, str):
                if not v:
                    raise NormalizationError(f"normalized.{field} must be nonempty")
                return v
            if _is_missing_value(v):
                return Missing.from_dict(v if isinstance(v, dict) else v.to_dict())
            raise NormalizationError(f"normalized.{field} must be a string or Missing")

        pay = data["pay_ok"]
        if pay is None or pay not in VALID_PAY:
            raise NormalizationError(
                f"normalized.pay_ok must be one of {sorted(VALID_PAY)}; got {pay!r}"
            )
        score = data["score"]
        if not _is_missing_value(score) and not _is_finite_number(score):
            if isinstance(score, dict):
                score = Missing.from_dict(score)
            else:
                raise NormalizationError(
                    "normalized.score must be a finite number or Missing"
                )
        elif _is_missing_value(score):
            score = Missing.from_dict(score if isinstance(score, dict) else score.to_dict())
        return cls(
            can_do_70_percent=_dec_bool(data["can_do_70_percent"], "can_do_70_percent"),
            hard_blockers=_dec_str_tuple(data["hard_blockers"], "hard_blockers"),
            playbooks_matched=_dec_str_tuple(data["playbooks_matched"], "playbooks_matched"),
            would_tolerate=_dec_bool(data["would_tolerate"], "would_tolerate"),
            pay_ok=pay,
            legibility_gap=_dec_str(data["legibility_gap"], "legibility_gap"),
            resume_translation=_dec_str_tuple(data["resume_translation"], "resume_translation"),
            score=score,
        )


@dataclass(frozen=True, slots=True)
class EvaluationStage:
    """One automatic decision stage with rationale and evidence."""

    result: str
    rationale: str
    evidence_refs: tuple[Any, ...]

    def __post_init__(self) -> None:
        if self.result not in VALID_STAGE_RESULTS:
            raise ValueError(
                f"stage.result must be one of {sorted(VALID_STAGE_RESULTS)}; "
                f"got {self.result!r}"
            )
        _require_nonempty_str(self.rationale, "stage.rationale")
        if not isinstance(self.evidence_refs, tuple) or not self.evidence_refs:
            raise ValueError("stage.evidence_refs must be a nonempty tuple")
        for ref in self.evidence_refs:
            _coerce_evidence_ref(ref, "stage.evidence_refs[]")

    def to_dict(self) -> dict[str, Any]:
        return {
            "result": self.result,
            "rationale": self.rationale,
            "evidence_refs": [
                r.to_dict() if hasattr(r, "to_dict") else dict(r)
                for r in self.evidence_refs
            ],
        }

    @classmethod
    def from_dict(cls, data: Any) -> "EvaluationStage":
        if isinstance(data, EvaluationStage):
            return data
        if hasattr(data, "to_dict") and callable(data.to_dict) and not isinstance(data, dict):
            return cls.from_dict(data.to_dict())
        if not isinstance(data, dict):
            raise TypeError("EvaluationStage must be decoded from a dict")
        if set(data.keys()) != _STAGE_FIELDS:
            raise ValueError(
                f"EvaluationStage must contain exactly {sorted(_STAGE_FIELDS)}; "
                f"got {sorted(data.keys())}"
            )
        refs = data["evidence_refs"]
        if not isinstance(refs, list) or not refs:
            raise ValueError("stage.evidence_refs must be a nonempty array")
        return cls(
            result=data["result"],
            rationale=data["rationale"],
            evidence_refs=tuple(
                _coerce_evidence_ref(r, f"stage.evidence_refs[{i}]")
                for i, r in enumerate(refs)
            ),
        )


@dataclass(frozen=True, slots=True)
class PlaybookMatch:
    """One evidenced playbook match."""

    playbook_id: str
    job_primitives: tuple[str, ...]
    candidate_source_refs: tuple[Any, ...]
    job_source_refs: tuple[Any, ...]
    rationale: str
    limitations: tuple[str, ...]

    def __post_init__(self) -> None:
        _require_identifier(self.playbook_id, "match.playbook_id")
        if not isinstance(self.job_primitives, tuple) or not self.job_primitives:
            raise ValueError("match.job_primitives must be a nonempty tuple")
        for p in self.job_primitives:
            if not isinstance(p, str) or not p:
                raise ValueError("match.job_primitives entries must be nonempty strings")
        if not isinstance(self.candidate_source_refs, tuple) or not self.candidate_source_refs:
            raise ValueError("match.candidate_source_refs must be a nonempty tuple")
        if not isinstance(self.job_source_refs, tuple) or not self.job_source_refs:
            raise ValueError("match.job_source_refs must be a nonempty tuple")
        _require_nonempty_str(self.rationale, "match.rationale")
        if not isinstance(self.limitations, tuple):
            raise TypeError("match.limitations must be a tuple")
        for entry in self.limitations:
            if not isinstance(entry, str):
                raise TypeError("match.limitations entries must be strings")

    def to_dict(self) -> dict[str, Any]:
        def _refs(rs: tuple[Any, ...]) -> list[Any]:
            return [r.to_dict() if hasattr(r, "to_dict") else dict(r) for r in rs]

        return {
            "playbook_id": self.playbook_id,
            "job_primitives": list(self.job_primitives),
            "candidate_source_refs": _refs(self.candidate_source_refs),
            "job_source_refs": _refs(self.job_source_refs),
            "rationale": self.rationale,
            "limitations": list(self.limitations),
        }

    @classmethod
    def from_dict(cls, data: Any) -> "PlaybookMatch":
        if isinstance(data, PlaybookMatch):
            return data
        if hasattr(data, "to_dict") and callable(data.to_dict) and not isinstance(data, dict):
            return cls.from_dict(data.to_dict())
        if not isinstance(data, dict):
            raise TypeError("PlaybookMatch must be decoded from a dict")
        if set(data.keys()) != _MATCH_FIELDS:
            raise ValueError(
                f"PlaybookMatch must contain exactly {sorted(_MATCH_FIELDS)}; "
                f"got {sorted(data.keys())}"
            )
        return cls(
            playbook_id=data["playbook_id"],
            job_primitives=tuple(data["job_primitives"]),
            candidate_source_refs=tuple(data["candidate_source_refs"]),
            job_source_refs=tuple(data["job_source_refs"]),
            rationale=data["rationale"],
            limitations=tuple(data["limitations"]),
        )


@dataclass(frozen=True, slots=True)
class UnresolvedItem:
    """One explicitly unresolved ambiguity."""

    code: str
    detail: str
    affected_fields: tuple[str, ...]
    evidence_refs: tuple[Any, ...]

    def __post_init__(self) -> None:
        _require_identifier(self.code, "issue.code")
        _require_nonempty_str(self.detail, "issue.detail")
        if not isinstance(self.affected_fields, tuple):
            raise TypeError("issue.affected_fields must be a tuple")
        for f in self.affected_fields:
            if not isinstance(f, str) or not f:
                raise ValueError("issue.affected_fields entries must be nonempty strings")
        if not isinstance(self.evidence_refs, tuple):
            raise TypeError("issue.evidence_refs must be a tuple")
        for ref in self.evidence_refs:
            _coerce_evidence_ref(ref, "issue.evidence_refs[]")

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "detail": self.detail,
            "affected_fields": list(self.affected_fields),
            "evidence_refs": [
                r.to_dict() if hasattr(r, "to_dict") else dict(r)
                for r in self.evidence_refs
            ],
        }

    @classmethod
    def from_dict(cls, data: Any) -> "UnresolvedItem":
        if isinstance(data, UnresolvedItem):
            return data
        if hasattr(data, "to_dict") and callable(data.to_dict) and not isinstance(data, dict):
            return cls.from_dict(data.to_dict())
        if not isinstance(data, dict):
            raise TypeError("UnresolvedItem must be decoded from a dict")
        if set(data.keys()) != _ISSUE_FIELDS:
            raise ValueError(
                f"UnresolvedItem must contain exactly {sorted(_ISSUE_FIELDS)}; "
                f"got {sorted(data.keys())}"
            )
        refs = data["evidence_refs"]
        if not isinstance(refs, list):
            raise TypeError("issue.evidence_refs must be an array")
        return cls(
            code=data["code"],
            detail=data["detail"],
            affected_fields=tuple(data["affected_fields"]),
            evidence_refs=tuple(
                _coerce_evidence_ref(r, f"issue.evidence_refs[{i}]")
                for i, r in enumerate(refs)
            ),
        )


@dataclass(frozen=True, slots=True)
class EvaluationArtifact:
    """One pinned job evaluation (seam mapping 8.4)."""

    evaluation_id: str
    candidate_id: str
    job_input: EvaluationJobInput
    candidate_profile: Any
    playbook_catalog: VersionPin
    policies: EvaluationPolicyPins
    method: str
    raw_reranker: Any
    normalized_reranker: NormalizedRerankerOutput
    embedding: Any
    stage_one: EvaluationStage
    stage_two: EvaluationStage
    pay_decision: str
    recommended_selection: str
    playbook_matches: tuple[PlaybookMatch, ...]
    normalization_issues: tuple[UnresolvedItem, ...]
    model_calls: tuple[Any, ...]
    input_prefix: Any
    evidence_refs: tuple[Any, ...]
    record_type: str = EVALUATION_RECORD_TYPE
    schema_version: str = EVALUATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.record_type != EVALUATION_RECORD_TYPE:
            raise EvaluationLinkageError(
                f"record_type must be {EVALUATION_RECORD_TYPE!r}"
            )
        if self.schema_version != EVALUATION_SCHEMA_VERSION:
            raise EvaluationLinkageError(
                f"schema_version must be {EVALUATION_SCHEMA_VERSION!r}"
            )
        _require_identifier(self.evaluation_id, "evaluation.evaluation_id")
        _require_identifier(self.candidate_id, "evaluation.candidate_id")
        if not isinstance(self.job_input, EvaluationJobInput):
            raise TypeError("evaluation.job_input must be an EvaluationJobInput")
        _coerce_artifact_ref(self.candidate_profile, "evaluation.candidate_profile")
        if not isinstance(self.playbook_catalog, VersionPin):
            raise TypeError("evaluation.playbook_catalog must be a VersionPin")
        if not isinstance(self.policies, EvaluationPolicyPins):
            raise TypeError("evaluation.policies must be EvaluationPolicyPins")
        if self.method not in VALID_METHODS:
            raise ValueError(
                f"evaluation.method must be one of {sorted(VALID_METHODS)}; "
                f"got {self.method!r}"
            )
        if not _is_missing_value(self.raw_reranker):
            _coerce_artifact_ref(self.raw_reranker, "evaluation.raw_reranker")
        if not isinstance(self.normalized_reranker, NormalizedRerankerOutput):
            raise TypeError(
                "evaluation.normalized_reranker must be a NormalizedRerankerOutput"
            )
        if not _is_missing_value(self.embedding):
            _coerce_artifact_ref(self.embedding, "evaluation.embedding")
        if not isinstance(self.stage_one, EvaluationStage) or not isinstance(
            self.stage_two, EvaluationStage
        ):
            raise TypeError("evaluation stages must be EvaluationStage records")
        if self.pay_decision not in VALID_PAY:
            raise ValueError(
                f"evaluation.pay_decision must be one of {sorted(VALID_PAY)}; "
                f"got {self.pay_decision!r}"
            )
        if self.recommended_selection not in VALID_SELECTIONS:
            raise ValueError(
                "evaluation.recommended_selection must be one of "
                f"{sorted(VALID_SELECTIONS)}; got {self.recommended_selection!r}"
            )
        if not isinstance(self.playbook_matches, tuple):
            raise TypeError("evaluation.playbook_matches must be a tuple")
        for m in self.playbook_matches:
            if not isinstance(m, PlaybookMatch):
                raise TypeError("evaluation.playbook_matches must hold PlaybookMatch")
        if not isinstance(self.normalization_issues, tuple):
            raise TypeError("evaluation.normalization_issues must be a tuple")
        for issue in self.normalization_issues:
            if not isinstance(issue, UnresolvedItem):
                raise TypeError(
                    "evaluation.normalization_issues must hold UnresolvedItem"
                )
        if not isinstance(self.model_calls, tuple):
            raise TypeError("evaluation.model_calls must be a tuple")
        for ref in self.model_calls:
            _coerce_artifact_ref(ref, "evaluation.model_calls[]")
        _coerce_prefix(self.input_prefix, "evaluation.input_prefix")
        if not isinstance(self.evidence_refs, tuple) or not self.evidence_refs:
            raise ValueError("evaluation.evidence_refs must be a nonempty tuple")
        for ref in self.evidence_refs:
            _coerce_evidence_ref(ref, "evaluation.evidence_refs[]")

    def to_dict(self) -> dict[str, Any]:
        def _ref_or_missing(v: Any) -> Any:
            if _is_missing_value(v):
                return _missing_to_dict(v)
            return _artifact_to_dict(v)

        return {
            "record_type": self.record_type,
            "schema_version": self.schema_version,
            "evaluation_id": self.evaluation_id,
            "candidate_id": self.candidate_id,
            "job_input": self.job_input.to_dict(),
            "candidate_profile": _artifact_to_dict(self.candidate_profile),
            "playbook_catalog": self.playbook_catalog.to_dict(),
            "policies": self.policies.to_dict(),
            "method": self.method,
            "raw_reranker": _ref_or_missing(self.raw_reranker),
            "normalized_reranker": self.normalized_reranker.to_dict(),
            "embedding": _ref_or_missing(self.embedding),
            "stage_one": self.stage_one.to_dict(),
            "stage_two": self.stage_two.to_dict(),
            "pay_decision": self.pay_decision,
            "recommended_selection": self.recommended_selection,
            "playbook_matches": [m.to_dict() for m in self.playbook_matches],
            "normalization_issues": [i.to_dict() for i in self.normalization_issues],
            "model_calls": [_artifact_to_dict(r) for r in self.model_calls],
            "input_prefix": _prefix_to_dict(self.input_prefix),
            "evidence_refs": [
                r.to_dict() if hasattr(r, "to_dict") else dict(r)
                for r in self.evidence_refs
            ],
        }

    @classmethod
    def from_dict(cls, data: Any) -> "EvaluationArtifact":
        if isinstance(data, EvaluationArtifact):
            return data
        if hasattr(data, "to_dict") and callable(data.to_dict) and not isinstance(data, dict):
            return cls.from_dict(data.to_dict())
        if not isinstance(data, dict):
            raise TypeError("EvaluationArtifact must be decoded from a dict")
        if set(data.keys()) != _EVALUATION_FIELDS:
            raise EvaluationLinkageError(
                "EvaluationArtifact must contain exactly "
                f"{sorted(_EVALUATION_FIELDS)}; got {sorted(data.keys())}"
            )

        def _ref_or_missing(v: Any, field: str) -> Any:
            if _is_missing_value(v):
                return Missing.from_dict(v if isinstance(v, dict) else v.to_dict())
            return _coerce_artifact_ref(v, field)

        matches = data["playbook_matches"]
        issues = data["normalization_issues"]
        calls = data["model_calls"]
        refs = data["evidence_refs"]
        if not isinstance(matches, list) or not isinstance(issues, list):
            raise TypeError("evaluation matches/issues must be arrays")
        if not isinstance(calls, list) or not isinstance(refs, list) or not refs:
            raise ValueError("evaluation model_calls/evidence_refs must be arrays")
        return cls(
            evaluation_id=data["evaluation_id"],
            candidate_id=data["candidate_id"],
            job_input=EvaluationJobInput.from_dict(data["job_input"]),
            candidate_profile=_coerce_artifact_ref(
                data["candidate_profile"], "evaluation.candidate_profile"
            ),
            playbook_catalog=VersionPin.from_dict(data["playbook_catalog"]),
            policies=EvaluationPolicyPins.from_dict(data["policies"]),
            method=data["method"],
            raw_reranker=_ref_or_missing(data["raw_reranker"], "evaluation.raw_reranker"),
            normalized_reranker=NormalizedRerankerOutput.from_dict(
                data["normalized_reranker"]
            ),
            embedding=_ref_or_missing(data["embedding"], "evaluation.embedding"),
            stage_one=EvaluationStage.from_dict(data["stage_one"]),
            stage_two=EvaluationStage.from_dict(data["stage_two"]),
            pay_decision=data["pay_decision"],
            recommended_selection=data["recommended_selection"],
            playbook_matches=tuple(PlaybookMatch.from_dict(m) for m in matches),
            normalization_issues=tuple(UnresolvedItem.from_dict(i) for i in issues),
            model_calls=tuple(
                _coerce_artifact_ref(r, f"evaluation.model_calls[{i}]")
                for i, r in enumerate(calls)
            ),
            input_prefix=_coerce_prefix(data["input_prefix"], "evaluation.input_prefix"),
            evidence_refs=tuple(
                _coerce_evidence_ref(r, f"evaluation.evidence_refs[{i}]")
                for i, r in enumerate(refs)
            ),
            record_type=data["record_type"],
            schema_version=data["schema_version"],
        )


@dataclass(frozen=True, slots=True)
class EvaluationReference:
    """Downstream pointer to one immutable evaluation."""

    evaluation_id: str
    crawler_input: NonzeroDomainPin
    candidate_profile: Any
    evaluation: Any
    evidence_refs: tuple[Any, ...]

    def __post_init__(self) -> None:
        _require_identifier(self.evaluation_id, "reference.evaluation_id")
        if not isinstance(self.crawler_input, NonzeroDomainPin):
            raise TypeError("reference.crawler_input must be a NonzeroDomainPin")
        _coerce_artifact_ref(self.candidate_profile, "reference.candidate_profile")
        _coerce_artifact_ref(self.evaluation, "reference.evaluation")
        if not isinstance(self.evidence_refs, tuple) or not self.evidence_refs:
            raise ValueError("reference.evidence_refs must be a nonempty tuple")
        for ref in self.evidence_refs:
            _coerce_evidence_ref(ref, "reference.evidence_refs[]")

    def to_dict(self) -> dict[str, Any]:
        return {
            "evaluation_id": self.evaluation_id,
            "crawler_input": self.crawler_input.to_dict(),
            "candidate_profile": _artifact_to_dict(self.candidate_profile),
            "evaluation": _artifact_to_dict(self.evaluation),
            "evidence_refs": [
                r.to_dict() if hasattr(r, "to_dict") else dict(r)
                for r in self.evidence_refs
            ],
        }

    @classmethod
    def from_dict(cls, data: Any) -> "EvaluationReference":
        if isinstance(data, EvaluationReference):
            return data
        if hasattr(data, "to_dict") and callable(data.to_dict) and not isinstance(data, dict):
            return cls.from_dict(data.to_dict())
        if not isinstance(data, dict):
            raise TypeError("EvaluationReference must be decoded from a dict")
        if set(data.keys()) != _REFERENCE_FIELDS:
            raise ValueError(
                "EvaluationReference must contain exactly "
                f"{sorted(_REFERENCE_FIELDS)}; got {sorted(data.keys())}"
            )
        refs = data["evidence_refs"]
        if not isinstance(refs, list) or not refs:
            raise ValueError("reference.evidence_refs must be a nonempty array")
        return cls(
            evaluation_id=data["evaluation_id"],
            crawler_input=NonzeroDomainPin.from_dict(data["crawler_input"]),
            candidate_profile=_coerce_artifact_ref(
                data["candidate_profile"], "reference.candidate_profile"
            ),
            evaluation=_coerce_artifact_ref(data["evaluation"], "reference.evaluation"),
            evidence_refs=tuple(
                _coerce_evidence_ref(r, f"reference.evidence_refs[{i}]")
                for i, r in enumerate(refs)
            ),
        )


@dataclass(frozen=True, slots=True)
class RankingArtifact:
    """One scoped ranking over pinned included evaluations."""

    ranking_id: str
    policy: VersionPin
    evaluation_refs: tuple[Any, ...]
    ordered_evaluation_ids: tuple[str, ...]
    input_prefix: Any
    evidence_refs: tuple[Any, ...]
    record_type: str = RANKING_RECORD_TYPE
    schema_version: str = RANKING_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.record_type != RANKING_RECORD_TYPE:
            raise RankingError(f"record_type must be {RANKING_RECORD_TYPE!r}")
        if self.schema_version != RANKING_SCHEMA_VERSION:
            raise RankingError(f"schema_version must be {RANKING_SCHEMA_VERSION!r}")
        _require_identifier(self.ranking_id, "ranking.ranking_id")
        if not isinstance(self.policy, VersionPin):
            raise TypeError("ranking.policy must be a VersionPin")
        if not isinstance(self.evaluation_refs, tuple) or not self.evaluation_refs:
            raise RankingError("ranking.evaluation_refs must be a nonempty tuple")
        for ref in self.evaluation_refs:
            _coerce_artifact_ref(ref, "ranking.evaluation_refs[]")
        if not isinstance(self.ordered_evaluation_ids, tuple) or not self.ordered_evaluation_ids:
            raise RankingError("ranking.ordered_evaluation_ids must be nonempty")
        for eid in self.ordered_evaluation_ids:
            _require_identifier(eid, "ranking.ordered_evaluation_ids[]")
        if len(set(self.ordered_evaluation_ids)) != len(self.ordered_evaluation_ids):
            raise RankingError("ranking ordered ids must be unique")
        if len(self.evaluation_refs) != len(self.ordered_evaluation_ids):
            raise RankingError(
                "ranking ordered ids must identify exactly the included evaluations"
            )
        _coerce_prefix(self.input_prefix, "ranking.input_prefix")
        if not isinstance(self.evidence_refs, tuple) or not self.evidence_refs:
            raise RankingError("ranking.evidence_refs must be a nonempty tuple")
        for ref in self.evidence_refs:
            _coerce_evidence_ref(ref, "ranking.evidence_refs[]")

    def rank_of(self, evaluation_id: str) -> int:
        """One-based position within this artifact only."""
        try:
            return self.ordered_evaluation_ids.index(evaluation_id) + 1
        except ValueError as exc:
            raise RankingError(
                f"evaluation {evaluation_id!r} is not in this ranking"
            ) from exc

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": self.record_type,
            "schema_version": self.schema_version,
            "ranking_id": self.ranking_id,
            "policy": self.policy.to_dict(),
            "evaluation_refs": [_artifact_to_dict(r) for r in self.evaluation_refs],
            "ordered_evaluation_ids": list(self.ordered_evaluation_ids),
            "input_prefix": _prefix_to_dict(self.input_prefix),
            "evidence_refs": [
                r.to_dict() if hasattr(r, "to_dict") else dict(r)
                for r in self.evidence_refs
            ],
        }

    @classmethod
    def from_dict(cls, data: Any) -> "RankingArtifact":
        if isinstance(data, RankingArtifact):
            return data
        if hasattr(data, "to_dict") and callable(data.to_dict) and not isinstance(data, dict):
            return cls.from_dict(data.to_dict())
        if not isinstance(data, dict):
            raise TypeError("RankingArtifact must be decoded from a dict")
        if set(data.keys()) != _RANKING_FIELDS:
            raise RankingError(
                "RankingArtifact must contain exactly "
                f"{sorted(_RANKING_FIELDS)}; got {sorted(data.keys())}"
            )
        refs = data["evaluation_refs"]
        ids = data["ordered_evaluation_ids"]
        ev_refs = data["evidence_refs"]
        if not isinstance(refs, list) or not refs:
            raise RankingError("ranking.evaluation_refs must be a nonempty array")
        if not isinstance(ids, list) or not ids:
            raise RankingError("ranking.ordered_evaluation_ids must be nonempty")
        if not isinstance(ev_refs, list) or not ev_refs:
            raise RankingError("ranking.evidence_refs must be a nonempty array")
        return cls(
            ranking_id=data["ranking_id"],
            policy=VersionPin.from_dict(data["policy"]),
            evaluation_refs=tuple(
                _coerce_artifact_ref(r, f"ranking.evaluation_refs[{i}]")
                for i, r in enumerate(refs)
            ),
            ordered_evaluation_ids=tuple(ids),
            input_prefix=_coerce_prefix(data["input_prefix"], "ranking.input_prefix"),
            evidence_refs=tuple(
                _coerce_evidence_ref(r, f"ranking.evidence_refs[{i}]")
                for i, r in enumerate(ev_refs)
            ),
            record_type=data["record_type"],
            schema_version=data["schema_version"],
        )


# ---------------------------------------------------------------------------
# LogicalRow admission + pin linkage
# ---------------------------------------------------------------------------


def _row_to_dict(row: Any) -> dict[str, Any]:
    if isinstance(row, dict):
        return dict(row)
    if hasattr(row, "to_dict") and callable(row.to_dict):
        d = row.to_dict()
        if isinstance(d, dict):
            return dict(d)
    raise EvaluationLinkageError(
        f"row must be a LogicalRow mapping; got {type(row).__name__}"
    )


def _extract_entity(row_dict: Mapping[str, Any]) -> JobEntityKey:
    entity = row_dict.get("entity")
    if not isinstance(entity, dict):
        raise EvaluationLinkageError("row.entity must be a job entity mapping")
    try:
        return JobEntityKey.from_dict(entity)
    except (TypeError, ValueError) as exc:
        raise EvaluationLinkageError(f"row.entity is not a job key: {exc}") from exc


def extract_crawler_pin(row: Any) -> NonzeroDomainPin:
    """Return the row's exact crawler slot pin (revision + document digest)."""
    row_dict = _row_to_dict(row)
    domains = row_dict.get("domains")
    if not isinstance(domains, dict):
        raise EvaluationLinkageError(
            "row.domains must contain crawler and downstream slots"
        )
    if "crawler" not in domains or "downstream" not in domains:
        raise EvaluationLinkageError(
            "row.domains must contain crawler and downstream slots"
        )
    crawler = domains.get("crawler")
    if not isinstance(crawler, dict):
        raise EvaluationLinkageError("row.domains.crawler is required")
    revision = crawler.get("revision")
    if revision is None:
        raise EvaluationLinkageError("row.domains.crawler.revision is required")
    _require_revision(revision, "row.domains.crawler.revision")
    if revision == 0:
        raise EvaluationLinkageError(
            "row crawler slot is zero; a crawler-backed evaluation requires "
            "a nonzero slot"
        )
    document = crawler.get("document")
    if document is None:
        raise EvaluationLinkageError(
            "row crawler slot must name its document artifact"
        )
    try:
        ref = _coerce_artifact_ref(document, "row.domains.crawler.document")
    except EvaluationLinkageError as exc:
        raise EvaluationLinkageError(str(exc)) from exc
    digest = _artifact_digest(ref)
    snapshot = crawler.get("snapshot")
    if isinstance(snapshot, dict) and "revision" in snapshot:
        embedded = snapshot.get("revision")
        if embedded != revision:
            raise EvaluationLinkageError(
                f"row crawler slot revision {revision} differs from embedded "
                f"revision {embedded}"
            )
    seal = row_dict.get("seal_point")
    if isinstance(seal, dict):
        versions = seal.get("versions")
        if isinstance(versions, dict) and "crawler" in versions:
            if versions.get("crawler") != revision:
                raise EvaluationLinkageError(
                    "row seal vector differs from the crawler slot revision; "
                    "the row is inconsistent"
                )
    return NonzeroDomainPin(revision=revision, record_digest=digest)


def _extract_seal_id(row_dict: Mapping[str, Any]) -> str:
    seal = row_dict.get("seal_point")
    if not isinstance(seal, dict):
        raise EvaluationLinkageError("row.seal_point is required")
    seal_id = seal.get("seal_id")
    return _require_identifier(seal_id, "row.seal_point.seal_id")


def _extract_crawler_publication_ref(row_dict: Mapping[str, Any]) -> Any:
    domains = row_dict.get("domains")
    if not isinstance(domains, dict):
        raise EvaluationLinkageError("row.domains must contain crawler slot")
    crawler = domains.get("crawler")
    if not isinstance(crawler, dict):
        raise EvaluationLinkageError("row.domains.crawler is required")
    pub = crawler.get("publication_ref")
    if pub is None:
        raise EvaluationLinkageError(
            "row crawler slot must name its publication_ref"
        )
    return _coerce_evidence_ref(pub, "row.domains.crawler.publication_ref")


def _extract_seal_evidence(row_dict: Mapping[str, Any]) -> Any:
    seal = row_dict.get("seal_point")
    if isinstance(seal, dict):
        refs = seal.get("evidence_refs")
        if isinstance(refs, list) and refs:
            return _coerce_evidence_ref(refs[0], "row.seal_point.evidence_refs[0]")
    return _extract_crawler_publication_ref(row_dict)


def validate_crawler_pin(row: Any, crawler_pin: Any) -> NonzeroDomainPin:
    """Reject any evaluation pin differing from the row crawler slot.

    Returns the validated pin on agreement. Both revision and document
    digest must equal the row's crawler slot exactly.
    """
    expected = extract_crawler_pin(row)
    try:
        if isinstance(crawler_pin, NonzeroDomainPin):
            candidate = crawler_pin
        elif isinstance(crawler_pin, dict):
            candidate = NonzeroDomainPin.from_dict(crawler_pin)
        elif hasattr(crawler_pin, "to_dict") and callable(crawler_pin.to_dict):
            candidate = NonzeroDomainPin.from_dict(crawler_pin.to_dict())
        elif hasattr(crawler_pin, "revision") and hasattr(crawler_pin, "record_digest"):
            candidate = NonzeroDomainPin(
                revision=crawler_pin.revision,
                record_digest=crawler_pin.record_digest,
            )
        else:
            raise PinMismatchError(
                f"evaluation crawler pin is malformed: {type(crawler_pin).__name__}"
            )
    except (TypeError, ValueError) as exc:
        raise PinMismatchError(f"evaluation crawler pin is malformed: {exc}") from exc
    if (
        candidate.revision != expected.revision
        or candidate.record_digest != expected.record_digest
    ):
        raise PinMismatchError(
            f"evaluation pin revision={candidate.revision} "
            f"digest={candidate.record_digest} differs from logical-row "
            f"crawler slot revision={expected.revision} "
            f"digest={expected.record_digest}; the evaluation does not "
            "identify the row it evaluated"
        )
    return candidate


def validate_profile_pin(reference_profile: Any, evaluation_profile: Any) -> str:
    """Reject any profile pin mismatch between reference and evaluation.

    Returns the agreed digest on success. Both references must be retained
    artifact identities with equal digests.
    """
    try:
        ref_a = _coerce_artifact_ref(reference_profile, "reference.candidate_profile")
        ref_b = _coerce_artifact_ref(evaluation_profile, "evaluation.candidate_profile")
    except EvaluationLinkageError as exc:
        raise ProfilePinMismatchError(str(exc)) from exc
    try:
        digest_a = _artifact_digest(ref_a)
        digest_b = _artifact_digest(ref_b)
    except EvaluationLinkageError as exc:
        raise ProfilePinMismatchError(str(exc)) from exc
    if digest_a != digest_b:
        raise ProfilePinMismatchError(
            f"profile pin mismatch: reference names {digest_a} but the "
            f"evaluation artifact names {digest_b}; copied pins must agree "
            "with the EvaluationReference"
        )
    return digest_a


def check_evaluation_reference(
    row: Any, evaluation: Any, reference: Any
) -> NonzeroDomainPin:
    """Verify row / evaluation / reference linkage agrees exactly.

    Checks: evaluation_id agreement, crawler pin equality across all three,
    and profile pin equality between reference and evaluation artifact.
    """
    ev = EvaluationArtifact.from_dict(
        evaluation if isinstance(evaluation, dict) else evaluation
    ) if not isinstance(evaluation, EvaluationArtifact) else evaluation
    ref = EvaluationReference.from_dict(
        reference if isinstance(reference, dict) else reference
    ) if not isinstance(reference, EvaluationReference) else reference
    if ev.evaluation_id != ref.evaluation_id:
        raise EvaluationLinkageError(
            f"evaluation_id mismatch: evaluation names {ev.evaluation_id!r} "
            f"but the reference names {ref.evaluation_id!r}"
        )
    # Row slot vs evaluation pin.
    validate_crawler_pin(row, ev.job_input.crawler_input)
    # Reference pin vs row slot.
    try:
        validate_crawler_pin(row, ref.crawler_input)
    except PinMismatchError as exc:
        raise EvaluationLinkageError(
            "evaluation crawler pin differs from the reference crawler_input; "
            "the reference must name the exact evaluated revision: "
            f"{exc}"
        ) from exc
    # Evaluation pin vs reference pin (belt and suspenders: both equal row).
    if (
        ev.job_input.crawler_input.revision != ref.crawler_input.revision
        or ev.job_input.crawler_input.record_digest != ref.crawler_input.record_digest
    ):
        raise EvaluationLinkageError(
            "evaluation crawler pin differs from the reference crawler_input; "
            "the reference must name the exact evaluated revision"
        )
    validate_profile_pin(ref.candidate_profile, ev.candidate_profile)
    return ev.job_input.crawler_input


def build_evaluation_reference(
    evaluation: Any, evaluation_ref: Any, evidence_refs: Sequence[Any]
) -> EvaluationReference:
    """Build the downstream reference that exactly mirrors an evaluation."""
    ev = evaluation if isinstance(evaluation, EvaluationArtifact) else EvaluationArtifact.from_dict(evaluation)
    artifact = _coerce_artifact_ref(evaluation_ref, "reference.evaluation")
    if not isinstance(evidence_refs, (list, tuple)) or not evidence_refs:
        raise EvaluationLinkageError("reference.evidence_refs must be a nonempty array")
    refs = tuple(
        _coerce_evidence_ref(r, f"reference.evidence_refs[{i}]")
        for i, r in enumerate(evidence_refs)
    )
    return EvaluationReference(
        evaluation_id=ev.evaluation_id,
        crawler_input=ev.job_input.crawler_input,
        candidate_profile=ev.candidate_profile,
        evaluation=artifact,
        evidence_refs=refs,
    )


# ---------------------------------------------------------------------------
# Reranker normalization
# ---------------------------------------------------------------------------


def _catalog_ids(catalog: Any) -> frozenset[str]:
    entries: Any = None
    if isinstance(catalog, Mapping):
        entries = catalog.get("entries")
    elif hasattr(catalog, "entries"):
        entries = catalog.entries
    elif hasattr(catalog, "to_dict") and callable(catalog.to_dict):
        d = catalog.to_dict()
        if isinstance(d, Mapping):
            entries = d.get("entries")
    if not isinstance(entries, (list, tuple)) or not entries:
        raise NormalizationError("playbook catalog must carry a nonempty entries array")
    ids: list[str] = []
    for entry in entries:
        if isinstance(entry, Mapping):
            pid = entry.get("playbook_id")
        elif hasattr(entry, "playbook_id"):
            pid = entry.playbook_id
        elif hasattr(entry, "to_dict") and callable(entry.to_dict):
            d = entry.to_dict()
            pid = d.get("playbook_id") if isinstance(d, Mapping) else None
        else:
            pid = None
        if not isinstance(pid, str) or not pid:
            raise NormalizationError("playbook catalog entries must name playbook_id")
        ids.append(pid)
    return frozenset(ids)


def _normalize_bool_or_missing(raw_map: Mapping[str, Any], field: str) -> Any:
    if field not in raw_map:
        return Missing(
            reason="not_observed",
            detail=f"{field} was not established by the assessment.",
        )
    v = raw_map[field]
    if isinstance(v, bool):
        return v
    if _is_missing_value(v):
        if isinstance(v, dict):
            return Missing.from_dict(v)
        if isinstance(v, Missing):
            return v
        return Missing.from_dict(v.to_dict())
    # Wrong type: stay explicit rather than inventing a boolean.
    return Missing(
        reason="not_observed",
        detail=f"Field {field} is not a boolean or Missing; the raw value is "
        "retained unchanged and the normalized value stays explicit.",
    )


def _normalize_string_array_or_missing(raw_map: Mapping[str, Any], field: str) -> Any:
    if field not in raw_map:
        return Missing(
            reason="not_observed",
            detail=f"{field} was not established by the assessment.",
        )
    v = raw_map[field]
    if _is_missing_value(v):
        if isinstance(v, dict):
            return Missing.from_dict(v)
        if isinstance(v, Missing):
            return v
        return Missing.from_dict(v.to_dict())
    if isinstance(v, list):
        for entry in v:
            if not isinstance(entry, str):
                return Missing(
                    reason="not_observed",
                    detail=f"Field {field} contains a non-string entry; the raw "
                    "value is retained unchanged and the normalized value stays "
                    "explicit.",
                )
        return tuple(v)
    return Missing(
        reason="not_observed",
        detail=f"Field {field} is not a string array or Missing; the raw value "
        "is retained unchanged and the normalized value stays explicit.",
    )


def _normalize_string_or_missing(raw_map: Mapping[str, Any], field: str) -> Any:
    if field not in raw_map:
        return Missing(
            reason="not_observed",
            detail=f"{field} was not established by the assessment.",
        )
    v = raw_map[field]
    if isinstance(v, str):
        if not v:
            return Missing(
                reason="not_observed",
                detail=f"Field {field} is empty; the raw value is retained "
                "unchanged and the normalized value stays explicit.",
            )
        return v
    if _is_missing_value(v):
        if isinstance(v, dict):
            return Missing.from_dict(v)
        if isinstance(v, Missing):
            return v
        return Missing.from_dict(v.to_dict())
    return Missing(
        reason="not_observed",
        detail=f"Field {field} is not a string or Missing; the raw value is "
        "retained unchanged and the normalized value stays explicit.",
    )


def normalize_reranker_response(
    raw: Any,
    playbook_catalog: Any,
    rubric: Any,
    normalizer: Any,
    evidence_refs: Sequence[Any],
) -> tuple[NormalizedRerankerOutput, tuple[UnresolvedItem, ...]]:
    """Normalize a raw reranker response without inventing semantics.

    The caller retains the exact raw bytes separately; this function never
    mutates them. Unknown playbook labels are filtered from the normalized
    output and surfaced as issues. Scores without a pinned rubric stay
    Missing. Pay maps only through its pinned interpretation.
    """
    if _is_missing_value(normalizer):
        raise NormalizationError(
            "policies.normalizer must be a VersionPin for reranker normalization"
        )
    try:
        if isinstance(normalizer, dict):
            VersionPin.from_dict(normalizer)
        elif hasattr(normalizer, "to_dict") and callable(normalizer.to_dict) and not isinstance(
            normalizer, VersionPin
        ):
            VersionPin.from_dict(normalizer.to_dict())
        elif not isinstance(normalizer, VersionPin):
            if not (
                hasattr(normalizer, "id")
                and hasattr(normalizer, "version")
                and hasattr(normalizer, "artifact_digest")
            ):
                raise NormalizationError(
                    "policies.normalizer must be a VersionPin for reranker normalization"
                )
    except (TypeError, ValueError) as exc:
        raise NormalizationError(
            f"policies.normalizer is not a valid VersionPin: {exc}"
        ) from exc
    try:
        _coerce_version_pin_or_missing(rubric, "policies.rubric")
    except PolicyError as exc:
        raise NormalizationError(
            f"policies.rubric is not a valid VersionPin or Missing: {exc}"
        ) from exc
    rubric_missing = _is_missing_value(rubric)
    try:
        known_ids = _catalog_ids(playbook_catalog)
    except NormalizationError:
        raise
    except (TypeError, ValueError) as exc:
        raise NormalizationError(f"playbook catalog is invalid: {exc}") from exc
    if not isinstance(evidence_refs, (list, tuple)):
        raise NormalizationError("evidence_refs must be an array")
    evidence = tuple(
        _coerce_evidence_ref(r, f"evidence_refs[{i}]")
        for i, r in enumerate(evidence_refs)
    )
    issue_evidence = evidence
    obj = _parse_raw_json(raw, "raw reranker response")
    if not isinstance(obj, dict):
        raise NormalizationError("raw reranker response must be a JSON object")
    raw_map: dict[str, Any] = dict(obj)
    issues: list[UnresolvedItem] = []

    can_do = _normalize_bool_or_missing(raw_map, "can_do_70_percent")
    hard_blockers = _normalize_string_array_or_missing(raw_map, "hard_blockers")
    would_tolerate = _normalize_bool_or_missing(raw_map, "would_tolerate")
    legibility_gap = _normalize_string_or_missing(raw_map, "legibility_gap")
    resume_translation = _normalize_string_array_or_missing(raw_map, "resume_translation")

    # Playbooks: catalog-ID array or Missing; unknown labels -> issues.
    if "playbooks_matched" not in raw_map:
        playbooks: Any = Missing(
            reason="not_observed",
            detail="playbooks_matched was not established by the assessment.",
        )
    else:
        raw_playbooks = raw_map["playbooks_matched"]
        if _is_missing_value(raw_playbooks):
            if isinstance(raw_playbooks, dict):
                playbooks = Missing.from_dict(raw_playbooks)
            elif isinstance(raw_playbooks, Missing):
                playbooks = raw_playbooks
            else:
                playbooks = Missing.from_dict(raw_playbooks.to_dict())
        elif isinstance(raw_playbooks, list):
            non_string = [e for e in raw_playbooks if not isinstance(e, str)]
            if non_string:
                playbooks = Missing(
                    reason="not_observed",
                    detail="playbooks_matched had no pinned catalog-ID interpretation.",
                )
                issues.append(
                    UnresolvedItem(
                        code="reranker_type_mismatch",
                        detail="Field playbooks_matched contains a non-string entry; "
                        "the raw value is retained unchanged and the normalized "
                        "value stays explicit.",
                        affected_fields=("playbooks_matched",),
                        evidence_refs=issue_evidence,
                    )
                )
            else:
                known: list[str] = []
                unknown: list[str] = []
                for entry in raw_playbooks:
                    if entry in known_ids:
                        known.append(entry)
                    else:
                        unknown.append(entry)
                # Deduplicate known IDs while preserving order.
                seen: set[str] = set()
                deduped: list[str] = []
                for pid in known:
                    if pid not in seen:
                        seen.add(pid)
                        deduped.append(pid)
                playbooks = tuple(deduped)
                for label in unknown:
                    issues.append(
                        UnresolvedItem(
                            code="unknown_playbook_label",
                            detail=f"Raw playbook label {label} is not in the pinned "
                            "catalog; the raw response is retained unchanged and "
                            "the label is excluded from normalized "
                            "playbooks_matched.",
                            affected_fields=("playbooks_matched",),
                            evidence_refs=issue_evidence,
                        )
                    )
        else:
            playbooks = Missing(
                reason="not_observed",
                detail="playbooks_matched had no pinned catalog-ID interpretation.",
            )
            issues.append(
                UnresolvedItem(
                    code="reranker_type_mismatch",
                    detail="Field playbooks_matched is not a catalog-ID array or "
                    "Missing; the raw value is retained unchanged and the "
                    "normalized value stays explicit.",
                    affected_fields=("playbooks_matched",),
                    evidence_refs=issue_evidence,
                )
            )

    # Pay: pinned interpretation only. Explicit "unknown" stays unknown.
    raw_pay = raw_map.get("pay_ok", None) if "pay_ok" in raw_map else None
    if "pay_ok" not in raw_map:
        pay_ok = "unknown"
        issues.append(
            UnresolvedItem(
                code="pay_unobserved",
                detail="Raw pay assessment is absent; normalized pay stays unknown. "
                "Raw retained unchanged.",
                affected_fields=("pay_ok",),
                evidence_refs=issue_evidence,
            )
        )
    elif _is_missing_value(raw_pay):
        pay_ok = "unknown"
        issues.append(
            UnresolvedItem(
                code="pay_unobserved",
                detail="Raw pay assessment is missing; normalized pay stays unknown. "
                "Raw retained unchanged.",
                affected_fields=("pay_ok",),
                evidence_refs=issue_evidence,
            )
        )
    elif isinstance(raw_pay, str) and raw_pay in VALID_PAY:
        pay_ok = raw_pay
    else:
        pay_ok = "unknown"
        issues.append(
            UnresolvedItem(
                code="pay_unmapped_representation",
                detail=f"Raw pay representation {raw_pay!r} has no pinned normalizer "
                "mapping; normalized pay stays unknown and the raw value is "
                "retained unchanged.",
                affected_fields=("pay_ok",),
                evidence_refs=issue_evidence,
            )
        )

    # Score: scale supplied by rubric only.
    if "score" not in raw_map:
        score: Any = Missing(
            reason="not_observed",
            detail="score was not established by the assessment.",
        )
    else:
        raw_score = raw_map["score"]
        if _is_missing_value(raw_score):
            if isinstance(raw_score, dict):
                score = Missing.from_dict(raw_score)
            elif isinstance(raw_score, Missing):
                score = raw_score
            else:
                score = Missing.from_dict(raw_score.to_dict())
        elif _is_finite_number(raw_score):
            if rubric_missing:
                score = Missing(
                    reason="not_observed",
                    detail="Raw score is retained without semantics; no scoring "
                    "rubric is pinned.",
                )
                issues.append(
                    UnresolvedItem(
                        code="missing_scoring_rubric",
                        detail="A raw numeric score is present but no scoring rubric "
                        "is pinned; the normalized score stays Missing and no "
                        "0-100 scale or threshold is assumed. The raw response is "
                        "retained unchanged.",
                        affected_fields=("score",),
                        evidence_refs=issue_evidence,
                    )
                )
            else:
                score = raw_score
        else:
            score = Missing(
                reason="not_observed",
                detail="score had no pinned numeric interpretation.",
            )
            issues.append(
                UnresolvedItem(
                    code="reranker_type_mismatch",
                    detail="Field score is not a finite number or Missing; the raw "
                    "value is retained unchanged and the normalized value stays "
                    "explicit.",
                    affected_fields=("score",),
                    evidence_refs=issue_evidence,
                )
            )

    normalized = NormalizedRerankerOutput(
        can_do_70_percent=can_do,
        hard_blockers=hard_blockers,
        playbooks_matched=playbooks,
        would_tolerate=would_tolerate,
        pay_ok=pay_ok,
        legibility_gap=legibility_gap,
        resume_translation=resume_translation,
        score=score,
    )
    return normalized, tuple(issues)


# ---------------------------------------------------------------------------
# Two-stage decision table
# ---------------------------------------------------------------------------


def decide_stages(
    normalized: Any,
    policies: Any,
    evidence_refs: Sequence[Any],
) -> tuple[EvaluationStage, EvaluationStage, str, str]:
    """Apply the automatic two-stage decision table.

    Never invents waivers, thresholds, or tolerance: missing prerequisites
    yield review, unknown pay yields review, and failures yield no_go.
    Embedding similarity is never consulted here.
    """
    norm = normalized if isinstance(normalized, NormalizedRerankerOutput) else NormalizedRerankerOutput.from_dict(normalized)
    pins = policies if isinstance(policies, EvaluationPolicyPins) else EvaluationPolicyPins.from_dict(policies)
    if not isinstance(evidence_refs, (list, tuple)) or not evidence_refs:
        raise EvaluationLinkageError("decision evidence_refs must be a nonempty array")
    evidence = tuple(
        _coerce_evidence_ref(r, f"decision.evidence_refs[{i}]")
        for i, r in enumerate(evidence_refs)
    )
    eligibility_missing = _is_missing_value(pins.eligibility)
    tolerance_missing = _is_missing_value(pins.tolerance)
    pay_missing = _is_missing_value(pins.pay)

    can_do = norm.can_do_70_percent
    blockers = norm.hard_blockers
    tolerate = norm.would_tolerate
    pay_ok = norm.pay_ok

    can_do_missing = _is_missing_value(can_do)
    blockers_missing = _is_missing_value(blockers)
    tolerate_missing = _is_missing_value(tolerate)

    # -- Stage one (capability / eligibility) -------------------------------
    stage_one_result = "review"
    stage_one_rationale = "Stage-one inputs are inconclusive; review is required."
    blockers_established = (
        not blockers_missing and isinstance(blockers, tuple) and len(blockers) > 0
    )
    blockers_absent = (
        not blockers_missing and isinstance(blockers, tuple) and len(blockers) == 0
    )
    if blockers_established:
        if eligibility_missing:
            stage_one_result = "review"
            stage_one_rationale = (
                "Hard blockers are established but the eligibility policy is "
                "missing; waivability cannot be determined without invention, "
                "so automatic review is required."
            )
        else:
            stage_one_result = "fail"
            stage_one_rationale = (
                "Established nonwaivable hard blockers under the pinned "
                f"eligibility policy: {len(blockers)} blocker(s)."
            )
    elif not can_do_missing and can_do is False:
        if eligibility_missing:
            stage_one_result = "review"
            stage_one_rationale = (
                "Capability assessment is negative but the eligibility policy is "
                "missing; criterion semantics cannot be established without "
                "invention."
            )
        else:
            stage_one_result = "fail"
            stage_one_rationale = (
                "Established capability criterion failure under the pinned "
                "eligibility policy."
            )
    elif can_do_missing or blockers_missing or eligibility_missing:
        stage_one_result = "review"
        stage_one_rationale = (
            "Eligibility evidence or policy is missing or conflicting; automatic "
            "evaluation requires review rather than invented business logic."
        )
    elif can_do is True and blockers_absent:
        stage_one_result = "pass"
        stage_one_rationale = (
            "Capability criterion satisfied and assessed absence of hard blockers."
        )
    else:
        stage_one_result = "review"
        stage_one_rationale = "Stage-one inputs are inconclusive; review is required."

    # -- Stage two (tolerance) ----------------------------------------------
    if not tolerate_missing and tolerate is False:
        stage_two_result = "fail"
        stage_two_rationale = "Tolerance explicitly unacceptable in the assessment."
    elif tolerate_missing or tolerance_missing:
        stage_two_result = "review"
        stage_two_rationale = (
            "Required tolerance facts or the tolerance policy are missing; "
            "automatic evaluation requires review."
        )
    elif tolerate is True:
        stage_two_result = "pass"
        stage_two_rationale = "Tolerance established acceptable."
    else:
        stage_two_result = "review"
        stage_two_rationale = "Stage-two inputs are inconclusive; review is required."

    # -- Pay + recommendation -------------------------------------------------
    pay_decision = pay_ok
    if pay_decision not in VALID_PAY:
        raise JobEvaluationError(
            f"pay decision must be one of {sorted(VALID_PAY)}; got {pay_decision!r}"
        )
    if stage_one_result == "fail" or stage_two_result == "fail" or pay_decision == "unacceptable":
        recommended = "no_go"
    elif (
        stage_one_result == "review"
        or stage_two_result == "review"
        or pay_decision == "unknown"
        or pay_missing
    ):
        recommended = "review"
    elif pay_decision == "acceptable":
        recommended = "go"
    else:
        recommended = "review"

    stage_one = EvaluationStage(
        result=stage_one_result, rationale=stage_one_rationale, evidence_refs=evidence
    )
    stage_two = EvaluationStage(
        result=stage_two_result, rationale=stage_two_rationale, evidence_refs=evidence
    )
    return stage_one, stage_two, pay_decision, recommended


# ---------------------------------------------------------------------------
# Embedding evidence
# ---------------------------------------------------------------------------


def _model_key(model: Any) -> str:
    if isinstance(model, str):
        return model
    if isinstance(model, Mapping):
        mid = model.get("id", model.get("model"))
        ver = model.get("version", "")
        if isinstance(mid, str):
            return f"{mid}@{ver}" if ver else mid
    if hasattr(model, "to_dict") and callable(model.to_dict):
        return _model_key(model.to_dict())
    raise EmbeddingMismatchError(f"embedding model must be a string; got {model!r}")


def _vector_values(vector: Any, field: str) -> tuple[float, ...]:
    values: Any = None
    if isinstance(vector, Mapping):
        values = vector.get("values", vector.get("vector"))
    elif isinstance(vector, (list, tuple)):
        values = vector
    elif hasattr(vector, "to_dict") and callable(vector.to_dict):
        d = vector.to_dict()
        if isinstance(d, Mapping):
            values = d.get("values", d.get("vector"))
    if not isinstance(values, (list, tuple)):
        raise EmbeddingMismatchError(f"{field} must contain finite numbers")
    out: list[float] = []
    for value in values:
        if not _is_finite_number(value):
            raise EmbeddingMismatchError(f"{field} must contain finite numbers")
        out.append(float(value))
    return tuple(out)


def validate_embedding_comparison(
    embedding: Any,
    expected_model: Any = None,
    expected_dimension: Any = None,
) -> dict[str, Any]:
    """Validate an embedding comparison; mismatches invalidate it.

    ``Missing(not_enabled)`` means disabled embedding, never zero
    similarity. Any model/version or dimension mismatch raises
    :class:`EmbeddingMismatchError`. Returns a summary dict on success.
    """
    if _is_missing_value(embedding):
        reason = _missing_reason(embedding)
        if reason != "not_enabled":
            raise EmbeddingMismatchError(
                f"embedding is Missing({reason}); only Missing(not_enabled) means "
                "disabled embedding"
            )
        return {"status": "disabled", "reason": "not_enabled"}
    if isinstance(embedding, Missing):
        raise EmbeddingMismatchError(
            "embedding is Missing; only Missing(not_enabled) means disabled embedding"
        )
    if isinstance(embedding, (bytes, bytearray)):
        try:
            text = bytes(embedding).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise EmbeddingMismatchError(f"embedding artifact is not UTF-8: {exc}") from exc
        try:
            obj = json.loads(
                text,
                object_pairs_hook=_reject_duplicate_object,
                parse_constant=_reject_nonfinite_literal,
            )
        except ValueError as exc:
            raise EmbeddingMismatchError(
                f"embedding artifact is not valid JSON: {exc}"
            ) from exc
    elif isinstance(embedding, str):
        try:
            obj = json.loads(
                embedding,
                object_pairs_hook=_reject_duplicate_object,
                parse_constant=_reject_nonfinite_literal,
            )
        except ValueError as exc:
            raise EmbeddingMismatchError(
                f"embedding artifact is not valid JSON: {exc}"
            ) from exc
    elif isinstance(embedding, Mapping):
        obj = dict(embedding)
    elif hasattr(embedding, "to_dict") and callable(embedding.to_dict):
        obj = embedding.to_dict()
        if not isinstance(obj, Mapping):
            raise EmbeddingMismatchError(
                f"embedding artifact is not a mapping: {type(obj).__name__}"
            )
        obj = dict(obj)
    else:
        raise EmbeddingMismatchError(
            f"embedding artifact must be a mapping, bytes, or Missing; "
            f"got {type(embedding).__name__}"
        )
    if not isinstance(obj, dict):
        raise EmbeddingMismatchError("embedding artifact must be a JSON object")
    if set(obj.keys()) != _EMBEDDING_FIELDS:
        raise EmbeddingMismatchError(
            f"EmbeddingArtifact must contain exactly {sorted(_EMBEDDING_FIELDS)}; "
            f"got {sorted(obj.keys())}"
        )
    if obj.get("record_type") != EMBEDDING_RECORD_TYPE:
        raise EmbeddingMismatchError(
            f"embedding record_type must be {EMBEDDING_RECORD_TYPE!r}"
        )
    if obj.get("schema_version") != EMBEDDING_SCHEMA_VERSION:
        raise EmbeddingMismatchError(
            f"embedding schema_version must be {EMBEDDING_SCHEMA_VERSION!r}"
        )
    _require_identifier(obj.get("comparison_id"), "embedding.comparison_id")
    if obj.get("similarity_method") != "cosine":
        raise EmbeddingMismatchError("embedding similarity_method must be cosine")
    dimension = obj.get("vector_dimension")
    if isinstance(dimension, bool) or not isinstance(dimension, int) or dimension <= 0:
        try:
            _require_positive_int(dimension, "embedding.vector_dimension")
        except (TypeError, ValueError) as exc:
            raise EmbeddingMismatchError(str(exc)) from exc
    model = obj.get("model")
    if model is None:
        raise EmbeddingMismatchError("embedding.model must not be a bare null")
    model_key = _model_key(model)
    if expected_model is not None:
        exp_key = _model_key(expected_model)
        if model_key != exp_key:
            raise EmbeddingMismatchError(
                f"embedding model mismatch: artifact declares {model_key!r} but the "
                f"comparison expects {exp_key!r}; model/version mismatches "
                "invalidate comparison"
            )
    if expected_dimension is not None:
        if isinstance(expected_dimension, bool) or not isinstance(expected_dimension, int):
            raise EmbeddingMismatchError("expected_dimension must be a positive int")
        if dimension != expected_dimension:
            raise EmbeddingMismatchError(
                f"embedding dimension mismatch: artifact declares {dimension} but "
                f"the comparison expects {expected_dimension}; model/version "
                "mismatches invalidate comparison"
            )
    profile_vectors = obj.get("profile_vectors")
    if not isinstance(profile_vectors, list) or not profile_vectors:
        raise EmbeddingMismatchError("embedding.profile_vectors must be a nonempty array")
    for idx, vector in enumerate(profile_vectors):
        values = _vector_values(vector, f"embedding.profile_vectors[{idx}]")
        if len(values) != dimension:
            raise EmbeddingMismatchError(
                f"embedding profile vector {idx} has length {len(values)} but the "
                f"artifact declares vector_dimension {dimension}"
            )
    job_values = _vector_values(obj.get("job_vector"), "embedding.job_vector")
    if len(job_values) != dimension:
        raise EmbeddingMismatchError(
            f"embedding job vector has length {len(job_values)} but the artifact "
            f"declares vector_dimension {dimension}"
        )
    # Job vector finite check is inside _vector_values; surface explicitly.
    for value in job_values:
        if not math.isfinite(value):
            raise EmbeddingMismatchError(
                "embedding job vector must contain finite numbers"
            )
    similarities = obj.get("similarities")
    if not isinstance(similarities, list) or not similarities:
        raise EmbeddingMismatchError("embedding.similarities must be a nonempty array")
    for entry in similarities:
        if isinstance(entry, Mapping):
            score = entry.get("score", entry.get("similarity", entry.get("value")))
            if score is not None and not _is_finite_number(score):
                raise EmbeddingMismatchError(
                    "embedding similarities must contain finite numbers"
                )
        elif not _is_finite_number(entry):
            raise EmbeddingMismatchError(
                "embedding similarities must contain finite numbers"
            )
    refs = obj.get("evidence_refs")
    if not isinstance(refs, list) or not refs:
        raise EmbeddingMismatchError("embedding.evidence_refs must be a nonempty array")
    for ref in refs:
        try:
            _coerce_evidence_ref(ref, "embedding.evidence_refs[]")
        except EvaluationLinkageError as exc:
            raise EmbeddingMismatchError(str(exc)) from exc
    return {
        "status": "valid",
        "model": model_key,
        "vector_dimension": dimension,
        "profile_chunks": len(profile_vectors),
    }


# ---------------------------------------------------------------------------
# IDs + job input + entry points
# ---------------------------------------------------------------------------


def _next_evaluation_id() -> str:
    global _EVAL_COUNTER
    with _LOCK:
        _EVAL_COUNTER += 1
        return f"eval_{_EVAL_COUNTER:06d}"


def _next_ranking_id() -> str:
    global _RANK_COUNTER
    with _LOCK:
        _RANK_COUNTER += 1
        return f"rank_{_RANK_COUNTER:06d}"


def _build_job_input(
    channel_id: str, row: Any, owner_domain: str = OWNER_DOWNSTREAM
) -> EvaluationJobInput:
    row_dict = _row_to_dict(row)
    entity = _extract_entity(row_dict)
    crawler_pin = extract_crawler_pin(row_dict)
    seal_id = _extract_seal_id(row_dict)
    publication_ref = _extract_crawler_publication_ref(row_dict)
    row_bytes = _canonical_bytes(_plain(row_dict))
    logical_row_ref = artifact_store.retain_artifact(
        channel_id, owner_domain, "application/json", row_bytes, "restricted"
    )
    portfolio_job_id = f"{entity.target}:{entity.job_id}"
    return EvaluationJobInput(
        portfolio_job_id=portfolio_job_id,
        source_key=entity,
        logical_row=logical_row_ref,
        logical_row_ref=publication_ref,
        seal_id=seal_id,
        crawler_input=crawler_pin,
    )


async def evaluate_job(
    channel_id: str,
    row: Any,
    candidate_profile: Any,
    policies: Any,
    method: str,
) -> EvaluationArtifact:
    """Evaluate one pinned logical row for one pinned candidate profile.

    The evaluation pins the exact row artifact, seal, crawler revision,
    profile, catalog, and policy versions. Without an established raw
    assessment the automatic stages stay at review; nothing is invented.
    """
    _require_identifier(channel_id, "channel_id")
    if method not in VALID_METHODS:
        raise JobEvaluationError(
            f"method must be one of {sorted(VALID_METHODS)}; got {method!r}"
        )
    pins = policies if isinstance(policies, EvaluationPolicyPins) else EvaluationPolicyPins.from_dict(policies)
    profile_ref = _coerce_artifact_ref(candidate_profile, "candidate_profile")
    try:
        loaded_profile = candidate_inputs.load_candidate_profile(channel_id, profile_ref)
    except Exception as exc:
        raise EvaluationLinkageError(
            f"candidate profile cannot be loaded: {exc}"
        ) from exc
    catalog_pin_raw = getattr(loaded_profile, "playbook_catalog", None)
    if catalog_pin_raw is None:
        raise EvaluationLinkageError("candidate profile carries no playbook catalog pin")
    if isinstance(catalog_pin_raw, dict):
        catalog_pin_dict = dict(catalog_pin_raw)
    elif hasattr(catalog_pin_raw, "to_dict") and callable(catalog_pin_raw.to_dict):
        catalog_pin_dict = dict(catalog_pin_raw.to_dict())
    elif hasattr(catalog_pin_raw, "id"):
        catalog_pin_dict = {
            "id": catalog_pin_raw.id,
            "version": catalog_pin_raw.version,
            "artifact_digest": catalog_pin_raw.artifact_digest,
        }
    else:
        raise EvaluationLinkageError("candidate profile carries no playbook catalog pin")
    if "id" not in catalog_pin_dict:
        raise EvaluationLinkageError("candidate profile carries no playbook catalog pin")
    try:
        catalog = candidate_inputs.load_playbook_catalog(channel_id, catalog_pin_raw)
    except Exception as exc:
        raise EvaluationLinkageError(f"playbook catalog cannot be loaded: {exc}") from exc
    _ = catalog
    catalog_pin = VersionPin.from_dict(catalog_pin_dict)
    job_input = _build_job_input(channel_id, row)
    if crawler_intake is not None:
        accepted = getattr(crawler_intake, "accept_job_row", None)
        if callable(accepted):
            try:
                _ = accepted(channel_id, row)
            except Exception:
                pass
    candidate_id = getattr(loaded_profile, "candidate_id", None)
    if not isinstance(candidate_id, str) or not candidate_id:
        raise EvaluationLinkageError("candidate profile carries no candidate_id")
    row_dict = _row_to_dict(row)
    seal_evidence = _extract_seal_evidence(row_dict)
    profile_prefix_raw = getattr(loaded_profile, "evidence_prefix", None)
    if profile_prefix_raw is None:
        raise EvaluationLinkageError("candidate profile carries no evidence_prefix")
    try:
        input_prefix = _coerce_prefix(profile_prefix_raw, "evaluation.input_prefix")
    except EvaluationLinkageError as exc:
        raise EvaluationLinkageError(
            f"candidate profile carries no valid evidence_prefix: {exc}"
        ) from exc
    raw_missing = Missing(
        reason="not_observed",
        detail="No raw reranker response was supplied for this evaluation.",
    )
    embedding_missing = Missing(
        reason="not_enabled",
        detail="Embedding similarity was not enabled for this evaluation.",
    )
    normalized = NormalizedRerankerOutput(
        can_do_70_percent=Missing(
            reason="not_observed", detail="No capability assessment was established."
        ),
        hard_blockers=Missing(
            reason="not_observed", detail="No blocker assessment was established."
        ),
        playbooks_matched=Missing(
            reason="not_observed", detail="No playbook assessment was established."
        ),
        would_tolerate=Missing(
            reason="not_observed", detail="No tolerance assessment was established."
        ),
        pay_ok="unknown",
        legibility_gap=Missing(
            reason="not_observed", detail="No legibility assessment was established."
        ),
        resume_translation=Missing(
            reason="not_observed",
            detail="No translation recommendations were established.",
        ),
        score=Missing(
            reason="not_observed",
            detail="No score was established; no rubric scale is assumed.",
        ),
    )
    stage_one, stage_two, pay_decision, recommended = decide_stages(
        normalized, pins, [seal_evidence]
    )
    evaluation = EvaluationArtifact(
        evaluation_id=_next_evaluation_id(),
        candidate_id=candidate_id,
        job_input=job_input,
        candidate_profile=profile_ref,
        playbook_catalog=catalog_pin,
        policies=pins,
        method=method,
        raw_reranker=raw_missing,
        normalized_reranker=normalized,
        embedding=embedding_missing,
        stage_one=stage_one,
        stage_two=stage_two,
        pay_decision=pay_decision,
        recommended_selection=recommended,
        playbook_matches=(),
        normalization_issues=(),
        model_calls=(),
        input_prefix=input_prefix,
        evidence_refs=(seal_evidence,),
    )
    artifact_store.retain_artifact(
        channel_id,
        OWNER_DOWNSTREAM,
        "application/json",
        _canonical_bytes(evaluation.to_dict()),
        "restricted",
    )
    return evaluation


def rank_evaluations(
    channel_id: str,
    evaluations: tuple[EvaluationArtifact, ...] | list[Any],
    policy: Any,
) -> RankingArtifact:
    """Rank a pinned set of evaluations under a pinned ranking policy.

    The ranking preserves the caller-supplied order as the explicit product
    ordering; it never invents score thresholds or global ranks. Ordered IDs
    identify exactly the included evaluations, and rank is the one-based
    position within this artifact only.
    """
    _require_identifier(channel_id, "channel_id")
    if not isinstance(evaluations, (tuple, list)) or not evaluations:
        raise RankingError(
            "evaluations must be a nonempty tuple of EvaluationArtifact records"
        )
    parsed: list[EvaluationArtifact] = []
    for idx, item in enumerate(evaluations):
        try:
            if isinstance(item, EvaluationArtifact):
                parsed.append(item)
            elif isinstance(item, dict):
                parsed.append(EvaluationArtifact.from_dict(item))
            elif hasattr(item, "to_dict") and callable(item.to_dict):
                parsed.append(EvaluationArtifact.from_dict(item.to_dict()))
            else:
                raise RankingError(f"evaluations[{idx}] is not an EvaluationArtifact")
        except (TypeError, ValueError) as exc:
            raise RankingError(
                f"evaluations[{idx}] is not a valid EvaluationArtifact: {exc}"
            ) from exc
    ids = [e.evaluation_id for e in parsed]
    if len(set(ids)) != len(ids):
        raise RankingError("ranking evaluations must carry unique evaluation_ids")
    pin = policy if isinstance(policy, VersionPin) else VersionPin.from_dict(
        policy if isinstance(policy, dict) else policy.to_dict()
        if hasattr(policy, "to_dict") else policy
    )
    refs: list[Any] = []
    for item in parsed:
        payload = _canonical_bytes(item.to_dict())
        ref = artifact_store.retain_artifact(
            channel_id, OWNER_DOWNSTREAM, "application/json", payload, "restricted"
        )
        refs.append(ref)
    input_prefix = parsed[0].input_prefix
    evidence_refs = tuple(e.evidence_refs[0] for e in parsed)
    ranking = RankingArtifact(
        ranking_id=_next_ranking_id(),
        policy=pin,
        evaluation_refs=tuple(refs),
        ordered_evaluation_ids=tuple(ids),
        input_prefix=input_prefix,
        evidence_refs=evidence_refs,
    )
    artifact_store.retain_artifact(
        channel_id,
        OWNER_DOWNSTREAM,
        "application/json",
        _canonical_bytes(ranking.to_dict()),
        "restricted",
    )
    return ranking

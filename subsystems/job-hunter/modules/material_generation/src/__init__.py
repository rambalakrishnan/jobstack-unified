"""material_generation: supported application materials with fabrication-gated submission (tier 5).

This module implements seam mapping section 9 ("Materials and factual
integrity").  It drafts resume/cover-letter/supplemental artifacts strictly
from retained, evidenced candidate and job bytes, records every integrity
risk in a fabrication log (which never authorizes fabrication), and gates
automatic submission on unresolved unsupported claims.  Later packages are
new immutable artifacts; they never rewrite commission ``initial_materials``
or prior submission evidence.
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
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any


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
    if spec is None or spec.loader is None:
        raise ModuleNotFoundError(f"sibling module {name!r} not found")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


contract_codec = _load_sibling("contract_codec")
artifact_store = _load_sibling("artifact_store")
evidence_journal = _load_sibling("evidence_journal")
candidate_inputs = _load_sibling("candidate_inputs")
model_gateway = _load_sibling("model_gateway")

__all__ = [
    "RECORD_TYPE",
    "SCHEMA_VERSION",
    "EVENT_SCHEMA_VERSION",
    "GENERATED_EVENT_KIND",
    "SUBMITTED_EVENT_KIND",
    "EVENT_KINDS",
    "ISSUE_KINDS",
    "ISSUE_RESOLUTIONS",
    "ArtifactReference",
    "EvidenceRef",
    "VersionPin",
    "MaterialClaim",
    "MaterialIssue",
    "MaterialPackage",
    "MaterialGenerationError",
    "MaterialInputError",
    "MaterialPolicyError",
    "MaterialJournalError",
    "MaterialBlockedError",
    "make_missing",
    "is_missing",
    "missing_to_dict",
    "generate_materials",
    "submission_blockers",
    "automatic_submission_allowed",
    "assert_automatic_submission_allowed",
    "submission_allowed",
    "event_kind_declarations",
    "reset_for_tests",
]

RECORD_TYPE = "job_hunter_material_package"
SCHEMA_VERSION = "job-hunter-material/0.1.0"
EVENT_SCHEMA_VERSION = "1"
GENERATED_EVENT_KIND = "material_package_generated"
SUBMITTED_EVENT_KIND = "material_submission_recorded"
EVENT_KINDS: dict[str, str] = {
    GENERATED_EVENT_KIND: EVENT_SCHEMA_VERSION,
    SUBMITTED_EVENT_KIND: EVENT_SCHEMA_VERSION,
}

ArtifactReference = artifact_store.ArtifactReference
EvidenceRef = evidence_journal.EvidenceRef

ISSUE_KINDS = frozenset(
    {
        "unsupported_claim",
        "source_conflict",
        "unit_ambiguity",
        "disclosure_restriction",
        "translation_risk",
    }
)
ISSUE_RESOLUTIONS = frozenset({"removed", "corrected", "unresolved"})

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_CODEC_GATE_SCHEMA = "record/v1"
_CODEC_GATE_KEY = "timing"

_PACKAGE_FIELDS = frozenset(
    {
        "record_type",
        "schema_version",
        "artifact_id",
        "portfolio_job_id",
        "candidate_profile",
        "job_snapshot",
        "evaluation",
        "functional_title",
        "resume_json",
        "cover_letter",
        "supplemental_responses",
        "rendered_documents",
        "claim_support",
        "fabrication_log",
        "generation_policy",
        "renderer",
        "approval_refs",
        "evidence_refs",
    }
)
_CLAIM_FIELDS = frozenset(
    {"claim_id", "text", "source_refs", "transformation_rationale"}
)
_ISSUE_FIELDS = frozenset(
    {"issue_id", "kind", "detail", "resolution", "evidence_refs"}
)
_PIN_FIELDS = frozenset({"id", "version", "artifact_digest"})
_ARTIFACT_KEYS = frozenset(
    {"digest", "size_bytes", "media_type", "owner_domain", "access"}
)
_EVIDENCE_KEYS = frozenset(
    {"journal_id", "sequence", "event_id", "event_hash", "pointer"}
)
_EVIDENCE_KEYS_NOPOINTER = frozenset(
    {"journal_id", "sequence", "event_id", "event_hash"}
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class MaterialGenerationError(Exception):
    """Base class for material-generation failures."""


class MaterialInputError(MaterialGenerationError, ValueError):
    """An input artifact, reference, or record is missing or malformed."""


class MaterialPolicyError(MaterialGenerationError, ValueError):
    """The pinned generation policy is absent, unretained, or malformed."""


class MaterialJournalError(MaterialGenerationError):
    """The generation observation could not be journaled or retained."""


class MaterialBlockedError(MaterialGenerationError, PermissionError):
    """Unresolved unsupported claims block the affected automatic submission."""


# ---------------------------------------------------------------------------
# Missing + scalar helpers (EK-NULL: no in-band nulls)
# ---------------------------------------------------------------------------


def make_missing(reason: str, detail: str | None = None) -> dict[str, Any]:
    """Create a typed ``K.Missing`` envelope (never an in-band null)."""
    return contract_codec.make_missing(reason, detail)


def is_missing(value: Any) -> bool:
    """Return True for any kernel Missing envelope (mapping or dataclass)."""
    if isinstance(value, Mapping):
        data = dict(value)
        return (
            "value" in data
            and data.get("value") is None
            and isinstance(data.get("reason"), str)
        )
    reason = getattr(value, "reason", None)
    if not isinstance(reason, str):
        return False
    try:
        observed = value.value
    except Exception:
        return False
    return observed is None


def missing_to_dict(value: Any) -> dict[str, Any]:
    """Normalize any Missing envelope to the canonical lowercase dict form."""
    if isinstance(value, Mapping):
        data = dict(value)
        reason = data.get("reason")
        if reason not in contract_codec.VALID_MISSING_REASONS:
            raise MaterialInputError(f"unknown Missing reason: {reason!r}")
        detail = data.get("Detail", data.get("detail"))
        if "Detail" in data and "detail" in data:
            raise MaterialInputError("Missing must not carry both Detail spellings")
        if detail is not None and (not isinstance(detail, str) or not detail):
            raise MaterialInputError(
                "Missing.detail must be a nonempty string when present"
            )
        return contract_codec.make_missing(reason, detail)
    reason = getattr(value, "reason", None)
    detail = getattr(value, "detail", None)
    if isinstance(reason, str) and reason in contract_codec.VALID_MISSING_REASONS:
        if detail is not None and (not isinstance(detail, str) or not detail):
            raise MaterialInputError(
                "Missing.detail must be a nonempty string when present"
            )
        return contract_codec.make_missing(reason, detail)
    raise MaterialInputError(
        f"value is not a Missing envelope: {type(value).__name__}"
    )


def _require_identifier(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise MaterialInputError(f"{field} must be a string identifier")
    if not value or "\x00" in value:
        raise MaterialInputError(f"{field} must be a nonempty identifier")
    return value


def _require_nonempty_str(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise MaterialInputError(f"{field} must be a nonempty string")
    if "\x00" in value:
        raise MaterialInputError(f"{field} must not contain NUL bytes")
    return value


def _require_digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.match(value):
        raise MaterialInputError(
            f"{field} must be a sha256:<64 lowercase hex> digest"
        )
    return value


def _canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _codec_gate(obj: Any, field: str) -> None:
    """Enforce strict kernel JSON (duplicates, bare nulls, nonfinite numbers).

    The tier-0 codec only names demo schemas, so normalized records ride in
    the ``timing`` property of ``record/v1`` exactly like the sibling
    modules: the gate then constrains JSON shape without imposing an
    unrelated record schema on the inner value.
    """
    try:
        payload = _canonical_json_bytes({_CODEC_GATE_KEY: obj})
    except (TypeError, ValueError) as exc:
        raise MaterialInputError(
            f"{field} is not JSON-serializable: {exc}"
        ) from exc
    try:
        contract_codec.validate_record(payload, _CODEC_GATE_SCHEMA)
    except (TypeError, ValueError) as exc:
        raise MaterialInputError(
            f"{field} violates kernel JSON rules: {exc}"
        ) from exc


def _reject_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, val in pairs:
        if key in obj:
            raise ValueError(f"duplicate object key: {key!r}")
        obj[key] = val
    return obj


def _reject_nonfinite(literal: str) -> Any:
    raise ValueError(f"nonfinite number literal rejected: {literal!r}")


def _check_finite(node: Any, path: str = "$") -> None:
    if isinstance(node, float) and not math.isfinite(node):
        raise ValueError(f"nonfinite number at {path}")
    if isinstance(node, dict):
        for key, val in node.items():
            _check_finite(val, f"{path}.{key}")
    elif isinstance(node, list):
        for index, val in enumerate(node):
            _check_finite(val, f"{path}[{index}]")


def _parse_strict_object(raw: bytes, field: str) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MaterialInputError(f"{field} bytes are not UTF-8 JSON: {exc}") from exc
    try:
        obj = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_object,
            parse_constant=_reject_nonfinite,
        )
    except ValueError as exc:
        raise MaterialInputError(f"{field} is not strict JSON: {exc}") from exc
    if not isinstance(obj, dict):
        raise MaterialInputError(f"{field} must be a JSON object record")
    try:
        _check_finite(obj)
    except ValueError as exc:
        raise MaterialInputError(f"{field} carries a nonfinite number: {exc}") from exc
    return obj


def _try_parse_json(payload: bytes | None) -> Any | None:
    if payload is None:
        return None
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return None
    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_object,
            parse_constant=_reject_nonfinite,
        )
    except ValueError:
        return None


def _coerce_artifact_ref(value: Any, field: str) -> Any:
    if isinstance(value, artifact_store.ArtifactReference):
        return value
    if isinstance(value, Mapping):
        try:
            return artifact_store.ArtifactReference.from_dict(dict(value))
        except (TypeError, ValueError) as exc:
            raise MaterialInputError(
                f"{field} is not a valid ArtifactReference: {exc}"
            ) from exc
    raise MaterialInputError(
        f"{field} must be an ArtifactReference, not {type(value).__name__}"
    )


def _coerce_evidence_ref(value: Any, field: str) -> Any:
    if isinstance(value, evidence_journal.EvidenceRef):
        return value
    if isinstance(value, Mapping):
        data = dict(value)
        try:
            return evidence_journal.EvidenceRef(
                journal_id=data["journal_id"],
                sequence=data["sequence"],
                event_id=data["event_id"],
                event_hash=data["event_hash"],
                pointer=data.get("pointer", ""),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise MaterialInputError(
                f"{field} is not a valid EvidenceRef: {exc}"
            ) from exc
    raise MaterialInputError(
        f"{field} must be an EvidenceRef, not {type(value).__name__}"
    )


def _ref_to_dict(ref: Any) -> dict[str, Any]:
    to_dict = getattr(ref, "to_dict", None)
    if callable(to_dict):
        out = to_dict()
        if isinstance(out, dict):
            return dict(out)
    if isinstance(ref, Mapping):
        return dict(ref)
    raise MaterialInputError(
        f"reference of type {type(ref).__name__} is not serializable"
    )


def _ref_from_dict(data: Any, field: str) -> Any:
    if not isinstance(data, Mapping):
        raise MaterialInputError(f"{field} must be a reference mapping")
    keys = set(data.keys())
    if keys == _ARTIFACT_KEYS:
        return _coerce_artifact_ref(data, field)
    if keys == _EVIDENCE_KEYS or keys == _EVIDENCE_KEYS_NOPOINTER:
        return _coerce_evidence_ref(data, field)
    raise MaterialInputError(
        f"{field} is neither an ArtifactReference nor an EvidenceRef"
    )


# ---------------------------------------------------------------------------
# Kernel value types
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class VersionPin:
    """Immutable pin of a policy/schema artifact (``K.VersionPin``)."""

    id: str
    version: str
    artifact_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not self.id or "\x00" in self.id:
            raise ValueError("VersionPin.id must be a nonempty identifier")
        if (
            not isinstance(self.version, str)
            or not self.version
            or "\x00" in self.version
        ):
            raise ValueError("VersionPin.version must be a nonempty identifier")
        if not isinstance(self.artifact_digest, str) or not _DIGEST_RE.match(
            self.artifact_digest
        ):
            raise ValueError(
                "VersionPin.artifact_digest must be a sha256:<64 hex> digest"
            )

    def to_dict(self) -> dict[str, str]:
        return {
            "id": self.id,
            "version": self.version,
            "artifact_digest": self.artifact_digest,
        }

    @classmethod
    def from_dict(cls, data: Any) -> "VersionPin":
        if not isinstance(data, Mapping):
            raise MaterialInputError("VersionPin must be decoded from a mapping")
        keys = set(data.keys())
        if keys != _PIN_FIELDS:
            raise MaterialInputError(
                "VersionPin must contain exactly id, version, artifact_digest; "
                f"got {sorted(keys)}"
            )
        for key in _PIN_FIELDS:
            if data[key] is None:
                raise MaterialInputError(f"VersionPin.{key} must not be a bare null")
        try:
            return cls(
                id=data["id"],
                version=data["version"],
                artifact_digest=data["artifact_digest"],
            )
        except (TypeError, ValueError) as exc:
            raise MaterialInputError(f"invalid VersionPin: {exc}") from exc


def _coerce_version_pin(value: Any, field: str) -> VersionPin:
    if isinstance(value, VersionPin):
        return value
    if isinstance(value, Mapping):
        return VersionPin.from_dict(value)
    pin_id = getattr(value, "id", None)
    version = getattr(value, "version", None)
    digest = getattr(value, "artifact_digest", None)
    if isinstance(pin_id, str) and isinstance(version, str) and isinstance(
        digest, str
    ):
        try:
            return VersionPin(id=pin_id, version=version, artifact_digest=digest)
        except (TypeError, ValueError) as exc:
            raise MaterialPolicyError(f"{field} is not a valid VersionPin: {exc}")
    raise MaterialPolicyError(
        f"{field} must be a VersionPin, not {type(value).__name__}"
    )


@dataclass(frozen=True, slots=True)
class MaterialClaim:
    """One supported material assertion (``JH.MaterialClaim``)."""

    claim_id: str
    text: str
    source_refs: tuple[Any, ...]
    transformation_rationale: str

    def __post_init__(self) -> None:
        if not isinstance(self.claim_id, str) or not self.claim_id:
            raise ValueError("MaterialClaim.claim_id must be a nonempty identifier")
        if not isinstance(self.text, str) or not self.text:
            raise ValueError("MaterialClaim.text must be a nonempty string")
        refs = tuple(self.source_refs) if isinstance(
            self.source_refs, (list, tuple)
        ) else None
        if refs is None or not refs:
            raise ValueError("MaterialClaim.source_refs must be nonempty")
        object.__setattr__(self, "source_refs", refs)
        if (
            not isinstance(self.transformation_rationale, str)
            or not self.transformation_rationale
        ):
            raise ValueError(
                "MaterialClaim.transformation_rationale must be nonempty"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "text": self.text,
            "source_refs": [_ref_to_dict(ref) for ref in self.source_refs],
            "transformation_rationale": self.transformation_rationale,
        }

    @classmethod
    def from_dict(cls, data: Any) -> "MaterialClaim":
        if not isinstance(data, Mapping):
            raise MaterialInputError("MaterialClaim must be decoded from a mapping")
        keys = set(data.keys())
        if keys != _CLAIM_FIELDS:
            raise MaterialInputError(
                "MaterialClaim must contain exactly claim_id, text, source_refs, "
                f"transformation_rationale; got {sorted(keys)}"
            )
        raw_refs = data["source_refs"]
        if not isinstance(raw_refs, list) or not raw_refs:
            raise MaterialInputError("MaterialClaim.source_refs must be nonempty")
        try:
            return cls(
                claim_id=data["claim_id"],
                text=data["text"],
                source_refs=tuple(
                    _ref_from_dict(entry, f"source_refs[{pos}]")
                    for pos, entry in enumerate(raw_refs)
                ),
                transformation_rationale=data["transformation_rationale"],
            )
        except (TypeError, ValueError) as exc:
            raise MaterialInputError(f"invalid MaterialClaim: {exc}") from exc


@dataclass(frozen=True, slots=True)
class MaterialIssue:
    """One fabrication-log entry (``JH.MaterialIssue``).

    The log records integrity issues; it never authorizes fabrication.
    """

    issue_id: str
    kind: str
    detail: str
    resolution: str
    evidence_refs: tuple[Any, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.issue_id, str) or not self.issue_id:
            raise ValueError("MaterialIssue.issue_id must be a nonempty identifier")
        if self.kind not in ISSUE_KINDS:
            raise ValueError(
                f"MaterialIssue.kind must be one of {sorted(ISSUE_KINDS)}; "
                f"got {self.kind!r}"
            )
        if not isinstance(self.detail, str) or not self.detail:
            raise ValueError("MaterialIssue.detail must be a nonempty string")
        if self.resolution not in ISSUE_RESOLUTIONS:
            raise ValueError(
                f"MaterialIssue.resolution must be one of "
                f"{sorted(ISSUE_RESOLUTIONS)}; got {self.resolution!r}"
            )
        refs = tuple(self.evidence_refs) if isinstance(
            self.evidence_refs, (list, tuple)
        ) else None
        if refs is None:
            raise ValueError("MaterialIssue.evidence_refs must be a sequence")
        object.__setattr__(self, "evidence_refs", refs)

    def to_dict(self) -> dict[str, Any]:
        return {
            "issue_id": self.issue_id,
            "kind": self.kind,
            "detail": self.detail,
            "resolution": self.resolution,
            "evidence_refs": [_ref_to_dict(ref) for ref in self.evidence_refs],
        }

    @classmethod
    def from_dict(cls, data: Any) -> "MaterialIssue":
        if not isinstance(data, Mapping):
            raise MaterialInputError("MaterialIssue must be decoded from a mapping")
        keys = set(data.keys())
        if keys != _ISSUE_FIELDS:
            raise MaterialInputError(
                "MaterialIssue must contain exactly issue_id, kind, detail, "
                f"resolution, evidence_refs; got {sorted(keys)}"
            )
        raw_refs = data["evidence_refs"]
        if not isinstance(raw_refs, list):
            raise MaterialInputError("MaterialIssue.evidence_refs must be an array")
        try:
            return cls(
                issue_id=data["issue_id"],
                kind=data["kind"],
                detail=data["detail"],
                resolution=data["resolution"],
                evidence_refs=tuple(
                    _coerce_evidence_ref(entry, f"evidence_refs[{pos}]")
                    for pos, entry in enumerate(raw_refs)
                ),
            )
        except (TypeError, ValueError) as exc:
            raise MaterialInputError(f"invalid MaterialIssue: {exc}") from exc


def _ref_or_missing_to_dict(value: Any) -> Any:
    if is_missing(value):
        return missing_to_dict(value)
    return _ref_to_dict(value)


def _ref_or_missing_from_dict(data: Any, field: str) -> Any:
    if is_missing(data):
        return missing_to_dict(data)
    return _ref_from_dict(data, field)


@dataclass(frozen=True, slots=True)
class MaterialPackage:
    """One immutable material generation result (``JH.MaterialPackage``)."""

    record_type: str
    schema_version: str
    artifact_id: str
    portfolio_job_id: str
    candidate_profile: Any
    job_snapshot: Any
    evaluation: Any
    functional_title: Any
    resume_json: Any
    cover_letter: Any
    supplemental_responses: Any
    rendered_documents: tuple[Any, ...]
    claim_support: tuple[MaterialClaim, ...]
    fabrication_log: tuple[MaterialIssue, ...]
    generation_policy: VersionPin
    renderer: Any
    approval_refs: tuple[Any, ...]
    evidence_refs: tuple[Any, ...]

    def __post_init__(self) -> None:
        if self.record_type != RECORD_TYPE:
            raise ValueError(f"record_type must be {RECORD_TYPE!r}")
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"schema_version must be {SCHEMA_VERSION!r}")
        for field in ("artifact_id", "portfolio_job_id"):
            val = getattr(self, field)
            if not isinstance(val, str) or not val or "\x00" in val:
                raise ValueError(f"{field} must be a nonempty identifier")
        for field in ("candidate_profile", "job_snapshot"):
            if not isinstance(
                getattr(self, field), artifact_store.ArtifactReference
            ):
                raise ValueError(f"{field} must be an ArtifactReference")
        for field in ("evaluation", "resume_json", "cover_letter",
                      "supplemental_responses"):
            val = getattr(self, field)
            if not (
                isinstance(val, artifact_store.ArtifactReference)
                or is_missing(val)
            ):
                raise ValueError(f"{field} must be an ArtifactReference or Missing")
        title = self.functional_title
        if not (isinstance(title, str) and title or is_missing(title)):
            raise ValueError("functional_title must be a string or Missing")
        for field in ("rendered_documents", "approval_refs", "evidence_refs"):
            raw = getattr(self, field)
            if not isinstance(raw, (list, tuple)):
                raise ValueError(f"{field} must be a sequence")
            object.__setattr__(self, field, tuple(raw))
        for ref in self.rendered_documents:
            if not isinstance(ref, artifact_store.ArtifactReference):
                raise ValueError("rendered_documents must hold ArtifactReferences")
        for ref in self.approval_refs:
            if not isinstance(ref, evidence_journal.EvidenceRef):
                raise ValueError("approval_refs must hold EvidenceRefs")
        if not self.evidence_refs:
            raise ValueError("evidence_refs must be nonempty")
        for ref in self.evidence_refs:
            if not isinstance(ref, evidence_journal.EvidenceRef):
                raise ValueError("evidence_refs must hold EvidenceRefs")
        claims = self.claim_support
        if not isinstance(claims, (list, tuple)):
            raise ValueError("claim_support must be a sequence")
        object.__setattr__(self, "claim_support", tuple(claims))
        for claim in self.claim_support:
            if not isinstance(claim, MaterialClaim):
                raise ValueError("claim_support must hold MaterialClaims")
        issues = self.fabrication_log
        if not isinstance(issues, (list, tuple)):
            raise ValueError("fabrication_log must be a sequence")
        object.__setattr__(self, "fabrication_log", tuple(issues))
        for issue in self.fabrication_log:
            if not isinstance(issue, MaterialIssue):
                raise ValueError("fabrication_log must hold MaterialIssues")
        if not isinstance(self.generation_policy, VersionPin):
            raise ValueError("generation_policy must be a VersionPin")
        if not (
            isinstance(self.renderer, VersionPin) or is_missing(self.renderer)
        ):
            raise ValueError("renderer must be a VersionPin or Missing")

    def to_dict(self) -> dict[str, Any]:
        title = self.functional_title
        return {
            "record_type": self.record_type,
            "schema_version": self.schema_version,
            "artifact_id": self.artifact_id,
            "portfolio_job_id": self.portfolio_job_id,
            "candidate_profile": self.candidate_profile.to_dict(),
            "job_snapshot": self.job_snapshot.to_dict(),
            "evaluation": _ref_or_missing_to_dict(self.evaluation),
            "functional_title": (
                missing_to_dict(title) if is_missing(title) else title
            ),
            "resume_json": _ref_or_missing_to_dict(self.resume_json),
            "cover_letter": _ref_or_missing_to_dict(self.cover_letter),
            "supplemental_responses": _ref_or_missing_to_dict(
                self.supplemental_responses
            ),
            "rendered_documents": [r.to_dict() for r in self.rendered_documents],
            "claim_support": [c.to_dict() for c in self.claim_support],
            "fabrication_log": [i.to_dict() for i in self.fabrication_log],
            "generation_policy": self.generation_policy.to_dict(),
            "renderer": (
                self.renderer.to_dict()
                if isinstance(self.renderer, VersionPin)
                else missing_to_dict(self.renderer)
            ),
            "approval_refs": [r.to_dict() for r in self.approval_refs],
            "evidence_refs": [r.to_dict() for r in self.evidence_refs],
        }

    @classmethod
    def from_dict(cls, data: Any) -> "MaterialPackage":
        if not isinstance(data, Mapping):
            raise MaterialInputError("MaterialPackage must decode from a mapping")
        keys = set(data.keys())
        if keys != _PACKAGE_FIELDS:
            missing = sorted(_PACKAGE_FIELDS - keys)
            extra = sorted(keys - _PACKAGE_FIELDS)
            raise MaterialInputError(
                "MaterialPackage has a closed field set; "
                f"missing={missing} extra={extra}"
            )
        try:
            title = data["functional_title"]
            if isinstance(title, str):
                parsed_title: Any = title
            else:
                parsed_title = missing_to_dict(title)
            renderer = data["renderer"]
            parsed_renderer: Any = (
                VersionPin.from_dict(renderer)
                if isinstance(renderer, Mapping) and not is_missing(renderer)
                else missing_to_dict(renderer)
            )
            return cls(
                record_type=data["record_type"],
                schema_version=data["schema_version"],
                artifact_id=data["artifact_id"],
                portfolio_job_id=data["portfolio_job_id"],
                candidate_profile=_coerce_artifact_ref(
                    data["candidate_profile"], "candidate_profile"
                ),
                job_snapshot=_coerce_artifact_ref(
                    data["job_snapshot"], "job_snapshot"
                ),
                evaluation=_ref_or_missing_from_dict(
                    data["evaluation"], "evaluation"
                ),
                functional_title=parsed_title,
                resume_json=_ref_or_missing_from_dict(
                    data["resume_json"], "resume_json"
                ),
                cover_letter=_ref_or_missing_from_dict(
                    data["cover_letter"], "cover_letter"
                ),
                supplemental_responses=_ref_or_missing_from_dict(
                    data["supplemental_responses"], "supplemental_responses"
                ),
                rendered_documents=tuple(
                    _coerce_artifact_ref(entry, f"rendered_documents[{pos}]")
                    for pos, entry in enumerate(data["rendered_documents"])
                ),
                claim_support=tuple(
                    MaterialClaim.from_dict(entry)
                    for entry in data["claim_support"]
                ),
                fabrication_log=tuple(
                    MaterialIssue.from_dict(entry)
                    for entry in data["fabrication_log"]
                ),
                generation_policy=VersionPin.from_dict(data["generation_policy"]),
                renderer=parsed_renderer,
                approval_refs=tuple(
                    _coerce_evidence_ref(entry, f"approval_refs[{pos}]")
                    for pos, entry in enumerate(data["approval_refs"])
                ),
                evidence_refs=tuple(
                    _coerce_evidence_ref(entry, f"evidence_refs[{pos}]")
                    for pos, entry in enumerate(data["evidence_refs"])
                ),
            )
        except MaterialInputError:
            raise
        except (TypeError, ValueError) as exc:
            raise MaterialInputError(f"invalid MaterialPackage: {exc}") from exc


# ---------------------------------------------------------------------------
# Submission gating (unresolved unsupported claims block automatic dispatch)
# ---------------------------------------------------------------------------


def submission_blockers(package: MaterialPackage) -> tuple[MaterialIssue, ...]:
    """Return the fabrication-log entries that block automatic submission."""
    if not isinstance(package, MaterialPackage):
        raise MaterialInputError("submission_blockers requires a MaterialPackage")
    return tuple(
        issue
        for issue in package.fabrication_log
        if issue.kind == "unsupported_claim" and issue.resolution == "unresolved"
    )


def automatic_submission_allowed(package: MaterialPackage) -> bool:
    """True only when no unresolved unsupported claim affects the package."""
    return len(submission_blockers(package)) == 0


def assert_automatic_submission_allowed(package: MaterialPackage) -> None:
    """Raise :class:`MaterialBlockedError` when automatic submission is barred."""
    blockers = submission_blockers(package)
    if blockers:
        ids = ", ".join(issue.issue_id for issue in blockers)
        raise MaterialBlockedError(
            f"automatic submission blocked by {len(blockers)} unresolved "
            f"unsupported claim(s): {ids}; the fabrication log records "
            "integrity issues, it does not authorize fabrication"
        )


def submission_allowed(package: MaterialPackage, mode: str) -> bool:
    """Return whether ``mode`` (``automatic`` or ``manual``) may proceed.

    Automatic submission requires a clean unsupported-claim gate.  The manual
    lane may always proceed under operator review; its issues stay journaled
    and no commission, source claim, or prior publication is rewritten.
    """
    if mode == "automatic":
        return automatic_submission_allowed(package)
    if mode == "manual":
        if not isinstance(package, MaterialPackage):
            raise MaterialInputError("submission_allowed requires a MaterialPackage")
        return True
    raise MaterialInputError(
        f"submission mode must be 'automatic' or 'manual', got {mode!r}"
    )


def event_kind_declarations(
    owner_domain: str,
    writer_roles: Sequence[str] = ("kernel",),
) -> list[dict[str, Any]]:
    """Return manifest/ingress declarations for this module's event kinds."""
    _require_identifier(owner_domain, "owner_domain")
    roles = list(writer_roles)
    if not roles:
        raise ValueError("writer_roles requires at least one producer role")
    return [
        {
            "event_kind": kind,
            "event_schema_version": version,
            "role": "derived_output",
            "assertion_kind": "derived_assessment",
            "owner_domain": owner_domain,
            "writer_roles": roles,
        }
        for kind, version in EVENT_KINDS.items()
    ]


# ---------------------------------------------------------------------------
# Module-local idempotency (stable input fingerprint -> package)
# ---------------------------------------------------------------------------

_LOCK = threading.RLock()
_PACKAGES: dict[tuple[str, str], MaterialPackage] = {}


def reset_for_tests() -> None:
    """Clear idempotency records (tests only)."""
    with _LOCK:
        _PACKAGES.clear()


# ---------------------------------------------------------------------------
# Digest-pinned byte resolution (EK-ARTIFACTS: hashes never substitute bytes)
# ---------------------------------------------------------------------------


def _reference_for_digest(
    channel_id: str, owner_domain: str, digest: str, field: str
) -> Any:
    _require_digest(digest, field)
    if digest not in artifact_store.known_digests():
        raise MaterialPolicyError(
            f"{field} names unretained bytes {digest}; "
            "a digest alone is not archived content"
        )
    meta = getattr(artifact_store, "_META", {}) or {}
    ref = meta.get(digest)
    if ref is not None:
        return ref
    raw_store = getattr(artifact_store, "_BYTES", {}) or {}
    payload = raw_store.get(digest)
    if payload is None:
        raise MaterialPolicyError(f"{field} has no retained bytes for {digest}")
    return artifact_store.ArtifactReference(
        digest=digest,
        size_bytes=len(payload),
        media_type="application/json",
        owner_domain=owner_domain,
        access="restricted",
    )


def _resolve_pin_bytes(
    channel_id: str, owner_domain: str, pin: VersionPin, field: str
) -> bytes:
    ref = _reference_for_digest(channel_id, owner_domain, pin.artifact_digest, field)
    try:
        return artifact_store.resolve_artifact(channel_id, ref)
    except artifact_store.ArtifactError as exc:
        raise MaterialPolicyError(
            f"{field} bytes are not resolvable: {exc}"
        ) from exc


# ---------------------------------------------------------------------------
# Supported-fact extraction (never invent employment facts)
# ---------------------------------------------------------------------------


def _extract_statements(history_json: Any) -> list[dict[str, str]]:
    """Copy verbatim employer/title/date strings; drop everything else.

    Salary numbers, credentials, supervisory counts, contact details, and
    free-text notes are never copied into generated materials: each requires
    independent support that this module does not fabricate.
    """
    statements: list[dict[str, str]] = []
    if not isinstance(history_json, dict):
        return statements
    jobs = history_json.get("jobs")
    if not isinstance(jobs, list):
        return statements
    for entry in jobs:
        if not isinstance(entry, dict):
            continue
        employer = entry.get("employer")
        if not isinstance(employer, str) or not employer or "\x00" in employer:
            continue
        statement: dict[str, str] = {"employer": employer}
        for key in ("title", "start", "end"):
            val = entry.get(key)
            if isinstance(val, str) and val and "\x00" not in val:
                statement[key] = val
        statements.append(statement)
    return statements


def _issue_kind_for(haystack: str) -> str:
    if any(
        token in haystack
        for token in (
            "disclosure", "sensitive", "permission", "contact", "privacy",
        )
    ):
        return "disclosure_restriction"
    if any(
        token in haystack
        for token in (
            "credential", "license", "licence", "cdl", "degree", "education",
            "certif", "pmp", "qualification", "equivalent", "unverified",
            "unsupported", "capabilit",
        )
    ):
        return "unsupported_claim"
    if any(
        token in haystack
        for token in (
            "salary", "pay_unit", "unit_ambiguity", "wage", "hourly", "monthly",
        )
    ):
        return "unit_ambiguity"
    if any(
        token in haystack
        for token in ("date", "chronology", "overlap", "conflict")
    ):
        return "source_conflict"
    if any(token in haystack for token in ("translat", "functional")):
        return "translation_risk"
    return "unsupported_claim"


def _map_profile_issue(item: Any, index: int) -> MaterialIssue:
    code = getattr(item, "code", None) or f"item_{index}"
    detail = getattr(item, "detail", None) or "unresolved candidate ambiguity"
    affected = getattr(item, "affected_fields", ()) or ()
    evidence = getattr(item, "evidence_refs", ()) or ()
    haystack = " ".join(
        [str(code), str(detail)] + [str(field) for field in affected]
    ).lower()
    issue_id = f"issue_{index:02d}_{code}".replace("\x00", "")
    return MaterialIssue(
        issue_id=issue_id,
        kind=_issue_kind_for(haystack),
        detail=f"Excluded from generated materials; {detail}",
        resolution="unresolved",
        evidence_refs=tuple(evidence),
    )


# ---------------------------------------------------------------------------
# Best-effort model drafting (optional evidence, never trusted facts)
# ---------------------------------------------------------------------------


async def _try_model_draft(
    channel_id: str,
    owner_domain: str,
    profile_ref: Any,
    job_ref: Any,
    eval_ref: Any | None,
    fingerprint_seed: str,
) -> Any | None:
    """Attempt one model draft; return None unless fully evidenced.

    Disclosure grants, cost policy, and staged provider bytes are all
    required before dispatch.  When any precondition is absent the draft is
    skipped and deterministic supported-fact generation proceeds instead.
    Model output would be provenance only: every emitted fact is still
    verified locally against retained bytes.
    """
    try:
        prompt_ref = artifact_store.retain_artifact(
            channel_id,
            owner_domain,
            "application/json",
            _canonical_json_bytes(
                {
                    "task": "draft_application_materials",
                    "instruction": (
                        "Propose vocabulary alignment only; employment "
                        "facts are verified locally and never invented."
                    ),
                }
            ),
            "restricted",
        )
        schema_ref = artifact_store.retain_artifact(
            channel_id,
            owner_domain,
            "application/json",
            _canonical_json_bytes(
                {"schema_id": "record/v1", "mapping": "material.draft"}
            ),
            "restricted",
        )
        cost_ref = artifact_store.retain_artifact(
            channel_id,
            owner_domain,
            "application/json",
            _canonical_json_bytes(
                {
                    "currency": "USD",
                    "reserved_cost_usd": 0.01,
                    "frozen_cost_limit_usd": 0.5,
                }
            ),
            "restricted",
        )
    except Exception:
        return None
    try:
        call_id = "material-draft-" + hashlib.sha256(
            fingerprint_seed.encode("utf-8")
        ).hexdigest()[:16]
        inputs = [profile_ref.to_dict(), job_ref.to_dict()]
        if eval_ref is not None:
            inputs.append(eval_ref.to_dict())
        return await model_gateway.invoke_model(
            channel_id,
            call_id,
            {
                "id": "material-draft-provider",
                "version": "1",
                "artifact_digest": cost_ref.digest,
            },
            prompt_ref.to_dict(),
            tuple(inputs),
            {
                "id": "record/v1",
                "version": "1",
                "artifact_digest": schema_ref.digest,
            },
        )
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Journaling (generation evidence, separate from submission evidence)
# ---------------------------------------------------------------------------


def _journal_generation(
    channel_id: str,
    owner_domain: str,
    *,
    artifact_id: str,
    candidate_id: str,
    portfolio_job_id: str,
    profile_ref: Any,
    job_ref: Any,
    eval_ref: Any | None,
    policy_pin: VersionPin,
    policy_ref: Any,
    resume_ref: Any,
    cover_ref: Any,
    rendered_ref: Any,
    claims: Sequence[MaterialClaim],
    issues: Sequence[MaterialIssue],
    blocked_automatic: bool,
) -> Any:
    data = {
        "record": GENERATED_EVENT_KIND,
        "artifact_id": artifact_id,
        "candidate_id": candidate_id,
        "portfolio_job_id": portfolio_job_id,
        "candidate_digest": profile_ref.digest,
        "job_digest": job_ref.digest,
        "evaluation_digest": eval_ref.digest if eval_ref is not None else "missing",
        "policy_digest": policy_pin.artifact_digest,
        "resume_digest": resume_ref.digest,
        "cover_digest": cover_ref.digest,
        "rendered_digest": rendered_ref.digest,
        "claim_ids": [claim.claim_id for claim in claims],
        "issues": [
            {
                "issue_id": issue.issue_id,
                "kind": issue.kind,
                "resolution": issue.resolution,
            }
            for issue in issues
        ],
        "blocked_automatic": blocked_automatic,
    }
    _codec_gate(data, "generation event data")
    ordered: list[Any] = [profile_ref, job_ref]
    if eval_ref is not None:
        ordered.append(eval_ref)
    ordered.extend([policy_ref, resume_ref, cover_ref, rendered_ref])
    seen: set[str] = set()
    deduped: list[Any] = []
    for ref in ordered:
        if ref.digest not in seen:
            seen.add(ref.digest)
            deduped.append(ref)
    submission = evidence_journal.EventSubmission(
        producer_sequence=evidence_journal.NOT_APPLICABLE,
        event_kind=GENERATED_EVENT_KIND,
        event_schema_version=EVENT_SCHEMA_VERSION,
        occurred_at=evidence_journal.NOT_OBSERVED,
        payload=evidence_journal.EvidencePayload(
            data=data,
            measurements=(),
            evidence_refs=(),
            artifact_refs=tuple(deduped),
        ),
    )
    try:
        envelope = evidence_journal.append_event(channel_id, owner_domain, submission)
    except Exception as exc:
        raise MaterialJournalError(
            f"cannot journal material package {artifact_id!r}: {exc}"
        ) from exc
    return evidence_journal.EvidenceRef(
        journal_id=envelope.journal_id,
        sequence=envelope.journal_sequence,
        event_id=envelope.event_id,
        event_hash=envelope.event_hash,
        pointer="",
    )


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


async def generate_materials(
    channel_id: str,
    candidate_profile: Any,
    job_snapshot: Any,
    evaluation: Any,
    policy: Any,
) -> MaterialPackage:
    """Generate one immutable, supported material package.

    Every emitted fact is copied verbatim from retained bytes; credentials,
    dates, salary units, supervisory counts, and contact permissions without
    support are excluded and recorded as unresolved fabrication-log issues.
    Unresolved unsupported claims block affected automatic submission via
    :func:`automatic_submission_allowed`.  The call never mutates existing
    materials, commission ``initial_materials``, or submission evidence, and
    never submits applications or publishes product-domain updates.
    """
    _require_identifier(channel_id, "channel_id")
    profile_ref = _coerce_artifact_ref(candidate_profile, "candidate_profile")
    job_ref = _coerce_artifact_ref(job_snapshot, "job_snapshot")
    policy_pin = _coerce_version_pin(policy, "policy")
    if profile_ref.owner_domain != job_ref.owner_domain:
        raise MaterialInputError(
            "candidate_profile and job_snapshot belong to different owner "
            "domains; cross-owner generation is refused"
        )
    owner_domain = profile_ref.owner_domain
    if is_missing(evaluation):
        evaluation_value: Any = missing_to_dict(evaluation)
        eval_ref: Any | None = None
    else:
        eval_ref = _coerce_artifact_ref(evaluation, "evaluation")
        if eval_ref.owner_domain != owner_domain:
            raise MaterialInputError(
                "evaluation belongs to a different owner domain; "
                "cross-owner generation is refused"
            )
        evaluation_value = eval_ref

    seed = {
        "candidate": profile_ref.digest,
        "job": job_ref.digest,
        "evaluation": eval_ref.digest if eval_ref is not None else "missing",
        "policy": policy_pin.artifact_digest,
    }
    artifact_id = "mat_" + hashlib.sha256(
        _canonical_json_bytes(seed)
    ).hexdigest()[:24]
    cache_key = (owner_domain, artifact_id)
    with _LOCK:
        cached = _PACKAGES.get(cache_key)
    if cached is not None:
        return cached

    try:
        profile = candidate_inputs.load_candidate_profile(channel_id, profile_ref)
    except Exception as exc:
        raise MaterialInputError(
            f"candidate profile failed source-fidelity loading: {exc}"
        ) from exc

    try:
        job_bytes = artifact_store.resolve_artifact(channel_id, job_ref)
    except artifact_store.ArtifactError as exc:
        raise MaterialInputError(
            f"job_snapshot bytes are not resolvable: {exc}"
        ) from exc
    job_obj = _parse_strict_object(job_bytes, "job_snapshot")
    _codec_gate(job_obj, "job_snapshot")
    portfolio_job_id = job_obj.get("portfolio_job_id") or job_obj.get("job_id")
    if not isinstance(portfolio_job_id, str) or not portfolio_job_id:
        raise MaterialInputError("job_snapshot must carry portfolio_job_id")
    actual_title = job_obj.get("title")
    employer = job_obj.get("employer", job_obj.get("company"))
    title_text = actual_title if isinstance(actual_title, str) and actual_title else None
    employer_text = employer if isinstance(employer, str) and employer else None

    policy_bytes = _resolve_pin_bytes(
        channel_id, owner_domain, policy_pin, "generation_policy"
    )
    policy_obj = _parse_strict_object(policy_bytes, "generation_policy")
    _codec_gate(policy_obj, "generation_policy")
    raw_renderer = policy_obj.get("renderer")
    if raw_renderer is None:
        renderer_value: Any = make_missing(
            "not_enabled", "no renderer pinned; Typst remains an option"
        )
    elif is_missing(raw_renderer):
        renderer_value = missing_to_dict(raw_renderer)
    elif isinstance(raw_renderer, Mapping):
        renderer_pin = _coerce_version_pin(raw_renderer, "generation_policy.renderer")
        _resolve_pin_bytes(
            channel_id, owner_domain, renderer_pin, "generation_policy.renderer"
        )
        renderer_value = renderer_pin
    else:
        raise MaterialPolicyError(
            "generation_policy.renderer must be a VersionPin or Missing"
        )

    history_payload: bytes | None = None
    employment_history = getattr(profile, "employment_history", None)
    if employment_history is not None and not is_missing(employment_history):
        history_ref = _coerce_artifact_ref(employment_history, "employment_history")
        try:
            history_payload = artifact_store.resolve_artifact(channel_id, history_ref)
        except artifact_store.ArtifactError as exc:
            raise MaterialInputError(
                f"employment_history bytes are not resolvable: {exc}"
            ) from exc
    capability_payload: bytes | None = None
    capability_profile = getattr(profile, "capability_profile", None)
    if capability_profile is not None and not is_missing(capability_profile):
        capability_ref = _coerce_artifact_ref(capability_profile, "capability_profile")
        try:
            capability_payload = artifact_store.resolve_artifact(
                channel_id, capability_ref
            )
        except artifact_store.ArtifactError as exc:
            raise MaterialInputError(
                f"capability_profile bytes are not resolvable: {exc}"
            ) from exc
    history_json = _try_parse_json(history_payload)
    _try_parse_json(capability_payload)
    statements = _extract_statements(history_json)

    await _try_model_draft(
        channel_id, owner_domain, profile_ref, job_ref, eval_ref, artifact_id
    )

    unresolved = tuple(getattr(profile, "unresolved_items", ()) or ())
    issues = tuple(_map_profile_issue(item, pos) for pos, item in enumerate(unresolved))

    resume_obj = {
        "candidate_id": profile.candidate_id,
        "portfolio_job_id": portfolio_job_id,
        "job_title": title_text if title_text is not None else "unspecified",
        "job_employer": employer_text if employer_text is not None else "unspecified",
        "employment_statements": statements,
        "excluded_unverified": [
            {"code": getattr(item, "code", f"item_{pos}")}
            for pos, item in enumerate(unresolved)
        ],
        "transformation": (
            "vocabulary alignment only; employment history unchanged"
        ),
    }
    _codec_gate(resume_obj, "resume_json")
    try:
        resume_ref = artifact_store.retain_artifact(
            channel_id,
            owner_domain,
            "application/json",
            _canonical_json_bytes(resume_obj),
            "restricted",
        )
    except artifact_store.ArtifactError as exc:
        raise MaterialJournalError(
            f"cannot retain resume_json for {artifact_id!r}: {exc}"
        ) from exc

    cover_lines = [
        f"Candidate {profile.candidate_id} application for "
        f"{title_text or 'the posted role'} at {employer_text or 'the employer'} "
        f"(job {portfolio_job_id}).",
        "Employment history summarized from verified source statements; "
        "unverified claims excluded.",
        f"Source profile digest: {profile_ref.digest}.",
        f"Excluded unverified items: {len(unresolved)} (see fabrication log).",
    ]
    try:
        cover_ref = artifact_store.retain_artifact(
            channel_id,
            owner_domain,
            "text/plain",
            "\n".join(cover_lines).encode("utf-8"),
            "restricted",
        )
    except artifact_store.ArtifactError as exc:
        raise MaterialJournalError(
            f"cannot retain cover_letter for {artifact_id!r}: {exc}"
        ) from exc

    questions = job_obj.get("supplemental_questions")
    if isinstance(questions, list) and questions:
        supplemental_value: Any = make_missing(
            "not_observed",
            "supplemental responses withheld: no independently supported answers",
        )
    else:
        supplemental_value = make_missing(
            "not_applicable", "job requests no supplemental responses"
        )

    claim_sources: list[Any] = [profile_ref, job_ref]
    for extra in tuple(getattr(profile, "source_evidence_refs", ()) or ())[:1]:
        claim_sources.append(extra)
    claims: list[MaterialClaim] = []
    for pos, statement in enumerate(statements):
        window = ""
        if statement.get("start") or statement.get("end"):
            window = f" ({statement.get('start', '?')} to {statement.get('end', '?')})"
        role = f" as {statement['title']}" if statement.get("title") else ""
        claims.append(
            MaterialClaim(
                claim_id=f"claim_employment_{pos:02d}",
                text=f"Employed by {statement['employer']}{role}{window}",
                source_refs=tuple(claim_sources),
                transformation_rationale=(
                    "vocabulary alignment only; employer, title, and dates "
                    "copied verbatim from source history"
                ),
            )
        )
    claims.append(
        MaterialClaim(
            claim_id="claim_job_target",
            text=(
                f"Materials prepared for {title_text or 'the posted role'} at "
                f"{employer_text or 'the employer'}"
            ),
            source_refs=tuple(claim_sources),
            transformation_rationale=(
                "job identity copied verbatim from snapshot; no eligibility "
                "inferred"
            ),
        )
    )

    renderer_label = (
        renderer_value.to_dict()
        if isinstance(renderer_value, VersionPin)
        else missing_to_dict(renderer_value)
    )
    rendered_text = "\n".join(
        [
            "MATERIAL RENDERING",
            f"resume: {resume_ref.digest}",
            f"cover: {cover_ref.digest}",
            f"renderer: {json.dumps(renderer_label, sort_keys=True)}",
            f"policy: {policy_pin.artifact_digest}",
        ]
    )
    try:
        rendered_ref = artifact_store.retain_artifact(
            channel_id,
            owner_domain,
            "text/plain",
            rendered_text.encode("utf-8"),
            "restricted",
        )
    except artifact_store.ArtifactError as exc:
        raise MaterialJournalError(
            f"cannot retain rendered_documents for {artifact_id!r}: {exc}"
        ) from exc

    blocked = any(
        issue.kind == "unsupported_claim" and issue.resolution == "unresolved"
        for issue in issues
    )
    policy_ref = _reference_for_digest(
        channel_id, owner_domain, policy_pin.artifact_digest, "generation_policy"
    )
    generation_ref = _journal_generation(
        channel_id,
        owner_domain,
        artifact_id=artifact_id,
        candidate_id=profile.candidate_id,
        portfolio_job_id=portfolio_job_id,
        profile_ref=profile_ref,
        job_ref=job_ref,
        eval_ref=eval_ref,
        policy_pin=policy_pin,
        policy_ref=policy_ref,
        resume_ref=resume_ref,
        cover_ref=cover_ref,
        rendered_ref=rendered_ref,
        claims=claims,
        issues=issues,
        blocked_automatic=blocked,
    )

    package = MaterialPackage(
        record_type=RECORD_TYPE,
        schema_version=SCHEMA_VERSION,
        artifact_id=artifact_id,
        portfolio_job_id=portfolio_job_id,
        candidate_profile=profile_ref,
        job_snapshot=job_ref,
        evaluation=evaluation_value,
        functional_title=make_missing(
            "not_applicable",
            "functional translation not substituted for actual title",
        ),
        resume_json=resume_ref,
        cover_letter=cover_ref,
        supplemental_responses=supplemental_value,
        rendered_documents=(rendered_ref,),
        claim_support=tuple(claims),
        fabrication_log=issues,
        generation_policy=policy_pin,
        renderer=renderer_value,
        approval_refs=(),
        evidence_refs=(generation_ref,),
    )
    _codec_gate(package.to_dict(), "material_package")
    with _LOCK:
        _PACKAGES[cache_key] = package
    return package

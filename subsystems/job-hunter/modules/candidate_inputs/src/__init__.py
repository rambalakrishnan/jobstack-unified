"""candidate_inputs: source-faithful candidate profile + playbook catalog loading (tier 3).

Implements seam mapping 7.1-7.3: distinguishes raw history, candidate
statements, analytical interpretation, proposed translations, and
independently verified credentials. Ambiguous salary units, conflicting
dates, license possession, inferred capabilities, disclosure permissions,
and degree-equivalence claims remain unresolved until evidenced. The
eight playbooks preserve their documentary sources and are never
reinterpreted as executor CapabilityDescriptor capabilities.
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import re
import sys
from dataclasses import dataclass, field
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

__all__ = [
    "CANDIDATE_PROFILE_RECORD_TYPE",
    "CANDIDATE_PROFILE_SCHEMA_VERSION",
    "PLAYBOOK_CATALOG_RECORD_TYPE",
    "PLAYBOOK_CATALOG_SCHEMA_VERSION",
    "PLAYBOOK_IDS",
    "CandidateInputsError",
    "InvalidCatalogError",
    "InvalidProfileError",
    "Missing",
    "VersionPin",
    "UnresolvedItem",
    "CandidateProfileArtifact",
    "PlaybookEntry",
    "PlaybookCatalog",
    "load_candidate_profile",
    "load_playbook_catalog",
]

CANDIDATE_PROFILE_RECORD_TYPE = "candidate_profile_artifact"
CANDIDATE_PROFILE_SCHEMA_VERSION = "job-hunter-candidate-profile/0.1.0"
PLAYBOOK_CATALOG_RECORD_TYPE = "playbook_catalog"
PLAYBOOK_CATALOG_SCHEMA_VERSION = "job-hunter-playbooks/0.1.0"

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

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_CODEC_GATE_SCHEMA = "record/v1"

_PROFILE_FIELDS = frozenset({
    "record_type",
    "schema_version",
    "candidate_id",
    "source_documents",
    "source_evidence_refs",
    "employment_history",
    "capability_profile",
    "playbook_catalog",
    "constraints",
    "disclosure_policy",
    "unresolved_items",
    "evidence_prefix",
})
_CATALOG_FIELDS = frozenset({"record_type", "schema_version", "entries"})
_ENTRY_FIELDS = frozenset({
    "playbook_id",
    "name",
    "primitive_actions",
    "trigger_conditions",
    "limitations",
    "source_refs",
})
_UNRESOLVED_FIELDS = frozenset({"code", "detail", "affected_fields", "evidence_refs"})
_VERSION_PIN_FIELDS = frozenset({"id", "version", "artifact_digest"})


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class CandidateInputsError(Exception):
    """Base class for candidate-input loading failures."""


class InvalidProfileError(CandidateInputsError, ValueError):
    """A candidate profile artifact violates source-fidelity rules."""


class InvalidCatalogError(CandidateInputsError, ValueError):
    """A playbook catalog artifact violates the eight-playbook contract."""


# ---------------------------------------------------------------------------
# Local value types
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Missing:
    """Typed missingness envelope (``K.Missing``); never an in-band null."""

    reason: str = "not_applicable"
    detail: str | None = None

    def __post_init__(self) -> None:
        if self.reason not in contract_codec.VALID_MISSING_REASONS:
            raise ValueError(f"unknown Missing reason: {self.reason!r}")
        if self.detail is not None and (
            not isinstance(self.detail, str) or not self.detail
        ):
            raise ValueError("Missing.detail must be a nonempty string when present")

    @property
    def value(self) -> None:
        return None

    def to_dict(self) -> dict[str, Any]:
        # NOTE: the tier-0 codec gate accepts ``Detail`` (capital D); the
        # lowercase spelling is rejected as an undeclared Missing property.
        # Emit the gate-compatible spelling; accept both on input.
        out: dict[str, Any] = {"value": None, "reason": self.reason}
        if self.detail is not None:
            out["Detail"] = self.detail
        return out

    @classmethod
    def from_dict(cls, data: Any) -> "Missing":
        if not isinstance(data, dict):
            raise TypeError("Missing must be decoded from a dict")
        keys = set(data.keys())
        allowed = {"value", "reason", "Detail", "detail"}
        extra = keys - allowed
        if extra:
            raise ValueError(f"undeclared Missing properties: {sorted(extra)}")
        if data.get("value") is not None or "value" not in data:
            raise ValueError("Missing.value must be null")
        reason = data.get("reason")
        if not isinstance(reason, str):
            raise ValueError("Missing.reason must be a string")
        detail = data.get("Detail", data.get("detail"))
        if detail is not None and (not isinstance(detail, str) or not detail):
            raise ValueError("Missing.detail must be a nonempty string when present")
        if "Detail" in data and "detail" in data:
            raise ValueError("Missing must not carry both Detail spellings")
        return cls(reason=reason, detail=detail)


@dataclass(frozen=True, slots=True)
class VersionPin:
    """Immutable pin of a code/schema/policy/catalog artifact (``K.VersionPin``)."""

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
        if not isinstance(data, dict):
            raise TypeError("VersionPin must be decoded from a dict")
        keys = set(data.keys())
        if keys != _VERSION_PIN_FIELDS:
            raise ValueError(
                "VersionPin must contain exactly id, version, artifact_digest; "
                f"got {sorted(keys)}"
            )
        for key in _VERSION_PIN_FIELDS:
            if data[key] is None:
                raise ValueError(f"VersionPin.{key} must not be a bare null")
        return cls(
            id=data["id"], version=data["version"],
            artifact_digest=data["artifact_digest"],
        )


@dataclass(frozen=True, slots=True)
class UnresolvedItem:
    """One explicitly unresolved ambiguity (``JH.UnresolvedItem``)."""

    code: str
    detail: str
    affected_fields: tuple[str, ...]
    evidence_refs: tuple[Any, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "detail": self.detail,
            "affected_fields": list(self.affected_fields),
            "evidence_refs": [ref.to_dict() for ref in self.evidence_refs],
        }


@dataclass(frozen=True, slots=True)
class CandidateProfileArtifact:
    """Validated candidate profile (seam mapping 7.2)."""

    record_type: str
    schema_version: str
    candidate_id: str
    source_documents: tuple[Any, ...]
    source_evidence_refs: tuple[Any, ...]
    employment_history: Any  # ArtifactReference | Missing
    capability_profile: Any  # ArtifactReference
    playbook_catalog: VersionPin
    constraints: Any  # ArtifactReference | Missing
    disclosure_policy: VersionPin
    unresolved_items: tuple[UnresolvedItem, ...]
    evidence_prefix: Any  # JournalPrefix

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": self.record_type,
            "schema_version": self.schema_version,
            "candidate_id": self.candidate_id,
            "source_documents": [ref.to_dict() for ref in self.source_documents],
            "source_evidence_refs": [ref.to_dict() for ref in self.source_evidence_refs],
            "employment_history": _ref_or_missing_to_dict(self.employment_history),
            "capability_profile": self.capability_profile.to_dict(),
            "playbook_catalog": self.playbook_catalog.to_dict(),
            "constraints": _ref_or_missing_to_dict(self.constraints),
            "disclosure_policy": self.disclosure_policy.to_dict(),
            "unresolved_items": [item.to_dict() for item in self.unresolved_items],
            "evidence_prefix": {
                "journal_id": self.evidence_prefix.journal_id,
                "last_sequence": self.evidence_prefix.last_sequence,
                "head_hash": self.evidence_prefix.head_hash,
            },
        }


@dataclass(frozen=True, slots=True)
class PlaybookEntry:
    """One documentary playbook; never an executor capability."""

    playbook_id: str
    name: str
    primitive_actions: tuple[str, ...]
    trigger_conditions: tuple[str, ...]
    limitations: tuple[str, ...]
    source_refs: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "playbook_id": self.playbook_id,
            "name": self.name,
            "primitive_actions": list(self.primitive_actions),
            "trigger_conditions": list(self.trigger_conditions),
            "limitations": list(self.limitations),
            "source_refs": list(self.source_refs),
        }


@dataclass(frozen=True, slots=True)
class PlaybookCatalog:
    """The eight-playbook documentary catalog (seam mapping 7.3)."""

    record_type: str
    schema_version: str
    entries: tuple[PlaybookEntry, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": self.record_type,
            "schema_version": self.schema_version,
            "entries": [entry.to_dict() for entry in self.entries],
        }


# ---------------------------------------------------------------------------
# Scalar validation
# ---------------------------------------------------------------------------


def _require_identifier(value: Any, field_name: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a str, not {type(value).__name__}")
    if not value or value != value.strip():
        raise ValueError(f"{field_name} must be a nonempty identifier without padding")
    if len(value) > 256:
        raise ValueError(f"{field_name} must be at most 256 characters")
    if "\x00" in value or any(ord(c) < 0x20 for c in value):
        raise ValueError(f"{field_name} must not contain control characters")
    return value


def _require_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a str, not {type(value).__name__}")
    if not value:
        raise ValueError(f"{field_name} must be nonempty")
    if "\x00" in value:
        raise ValueError(f"{field_name} must not contain NUL bytes")
    return value


def _require_digest(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.match(value):
        raise ValueError(f"{field_name} must be a sha256:<64 lowercase hex> digest")
    return value


def _ref_or_missing_to_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, Missing):
        return value.to_dict()
    return value.to_dict()


def _is_missing_dict(data: Any) -> bool:
    return (
        isinstance(data, dict)
        and "value" in data
        and data.get("value") is None
        and "reason" in data
    )


def _reject_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f"duplicate mapping key: {key!r}")
        obj[key] = value
    return obj


# ---------------------------------------------------------------------------
# Sibling-backed gates
# ---------------------------------------------------------------------------


def _authorize(channel_id: str) -> Any:
    """Authorize the channel through its own bounded grant (data plane)."""
    projection = access_policy.channel_projection(channel_id)
    grants = list(projection.get("grants", []))
    if not grants:
        raise access_policy.GrantDeniedError(
            "authenticated channel holds no write grant; "
            "candidate loading requires an authorized channel"
        )
    axis = projection.get("axis")
    if not isinstance(axis, str) or not axis:
        raise access_policy.GrantDeniedError("channel has no owner axis")
    return access_policy.authorize(channel_id, grants[0], axis)


def _strict_gate(raw: bytes, context: str, error_cls: type) -> Any:
    """Validate raw record bytes through the tier-0 strict JSON gate.

    The wrapper reuses ``record/v1`` so duplicate keys, bare nulls,
    nonfinite numbers, and malformed Missing envelopes are rejected by the
    kernel codec before this module applies its closed-object shapes.
    """
    if not isinstance(raw, bytes):
        raise error_cls(f"{context} must decode from bytes")
    wrapper = b'{"id":"candidate_inputs_gate","timing":' + raw + b"}"
    try:
        contract_codec.validate_record(wrapper, _CODEC_GATE_SCHEMA)
    except (ValueError, TypeError) as exc:
        raise error_cls(f"{context}: strict JSON gate rejected record: {exc}") from exc
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise error_cls(f"{context}: record bytes are not valid utf-8") from exc
    try:
        return json.loads(text, object_pairs_hook=_reject_duplicate_object)
    except json.JSONDecodeError as exc:
        raise error_cls(f"{context}: record bytes are not valid JSON: {exc}") from exc


def _coerce_artifact_ref(data: Any, field_name: str, error_cls: type) -> Any:
    try:
        if isinstance(data, artifact_store.ArtifactReference):
            return data
        return artifact_store.ArtifactReference.from_dict(data)
    except (TypeError, ValueError) as exc:
        raise error_cls(f"{field_name} is not a valid ArtifactReference: {exc}") from exc


def _coerce_evidence_ref(data: Any, field_name: str, error_cls: type) -> Any:
    try:
        if isinstance(data, evidence_journal.EvidenceRef):
            return data
        return evidence_journal.EvidenceRef.from_dict(data)
    except (TypeError, ValueError) as exc:
        raise error_cls(f"{field_name} is not a valid EvidenceRef: {exc}") from exc


def _coerce_prefix(data: Any, error_cls: type) -> Any:
    try:
        if isinstance(data, evidence_journal.JournalPrefix):
            return data
        if not isinstance(data, dict):
            raise TypeError("JournalPrefix must be decoded from a dict")
        keys = set(data.keys())
        if keys != {"journal_id", "last_sequence", "head_hash"}:
            raise ValueError(
                "JournalPrefix must contain exactly journal_id, "
                f"last_sequence, head_hash; got {sorted(keys)}"
            )
        return evidence_journal.JournalPrefix(
            journal_id=data["journal_id"],
            last_sequence=data["last_sequence"],
            head_hash=data["head_hash"],
        )
    except (TypeError, ValueError) as exc:
        raise error_cls(f"evidence_prefix is not a valid JournalPrefix: {exc}") from exc


def _coerce_version_pin(data: Any, field_name: str, error_cls: type) -> VersionPin:
    try:
        if isinstance(data, VersionPin):
            return data
        return VersionPin.from_dict(data)
    except (TypeError, ValueError) as exc:
        raise error_cls(f"{field_name} is not a valid VersionPin: {exc}") from exc


def _coerce_missing(data: Any, field_name: str, error_cls: type) -> Missing:
    try:
        if isinstance(data, Missing):
            return data
        return Missing.from_dict(data)
    except (TypeError, ValueError) as exc:
        raise error_cls(f"{field_name} is not a valid Missing envelope: {exc}") from exc


def _require_known_digest(digest: str, field_name: str, error_cls: type) -> None:
    """Reject locator/hash-only references (EK-ARTIFACTS)."""
    try:
        known = artifact_store.known_digests()
    except Exception as exc:  # pragma: no cover - defensive
        raise error_cls(f"{field_name}: cannot verify artifact retention: {exc}") from exc
    if digest not in known:
        raise error_cls(
            f"{field_name}: no retained artifact for {digest}; "
            "a digest alone is not archived content"
        )


def _resolve_by_digest(channel_id: str, digest: str) -> bytes:
    """Resolve pinned bytes by digest through the artifact store.

    VersionPins carry only ``artifact_digest``; the full reference metadata
    is recovered from the store's retained identities so the resolution
    still passes through ``resolve_artifact`` authorization and integrity
    checks rather than trusting the hash alone.
    """
    _require_digest(digest, "artifact_digest")
    _require_known_digest(digest, "catalog pin", InvalidCatalogError)
    meta = getattr(artifact_store, "_META", {}) or {}
    ref = meta.get(digest)
    if ref is None:
        # Fall back to channel-local metadata: resolve_artifact verifies the
        # digest and size against the retained bytes, so a correct digest
        # with a recovered size still enforces integrity.
        raw_store = getattr(artifact_store, "_BYTES", {}) or {}
        payload = raw_store.get(digest)
        if payload is None:
            raise InvalidCatalogError(
                f"catalog pin: no retained bytes for {digest}; "
                "a digest alone is not archived content"
            )
        projection = access_policy.channel_projection(channel_id)
        axis = projection.get("axis")
        if not isinstance(axis, str) or not axis:
            raise access_policy.GrantDeniedError("channel has no owner axis")
        ref = artifact_store.ArtifactReference(
            digest=digest,
            size_bytes=len(payload),
            media_type="application/json",
            owner_domain=axis,
            access="restricted",
        )
    return artifact_store.resolve_artifact(channel_id, ref)


# ---------------------------------------------------------------------------
# Ambiguity scanning (seam mapping 7.1)
# ---------------------------------------------------------------------------


def _decoded_text(payload: bytes | None) -> str | None:
    if payload is None:
        return None
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _parsed_json(payload: bytes | None) -> Any | None:
    text = _decoded_text(payload)
    if text is None:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _month_index(value: Any) -> int | None:
    if not isinstance(value, str):
        return None
    match = re.match(r"^(\d{4})-(\d{2})$", value.strip())
    if not match:
        return None
    year, month = int(match.group(1)), int(match.group(2))
    if month < 1 or month > 12:
        return None
    return year * 12 + month


def _jobs_overlap(jobs: Any) -> bool:
    if not isinstance(jobs, list) or len(jobs) < 2:
        return False
    intervals: list[tuple[int, int]] = []
    for job in jobs:
        if not isinstance(job, dict):
            continue
        start = _month_index(job.get("start"))
        end = _month_index(job.get("end"))
        if start is None or end is None or end < start:
            continue
        intervals.append((start, end))
    for index in range(len(intervals)):
        for other in range(index + 1, len(intervals)):
            latest_start = max(intervals[index][0], intervals[other][0])
            earliest_end = min(intervals[index][1], intervals[other][1])
            if latest_start <= earliest_end:
                return True
    return False


def _item_text(item: UnresolvedItem) -> str:
    parts = [item.code, item.detail, " ".join(item.affected_fields)]
    return " ".join(parts).lower()


def _require_coverage(
    items: tuple[UnresolvedItem, ...],
    keywords: tuple[str, ...],
    message: str,
) -> None:
    for item in items:
        text = _item_text(item)
        if any(keyword in text for keyword in keywords):
            return
    raise InvalidProfileError(message)


def _check_ambiguity_coverage(
    items: tuple[UnresolvedItem, ...],
    history_payload: bytes | None,
    capability_payload: bytes | None,
) -> None:
    """Require explicit unresolved items for detected ambiguities.

    The loader never reconciles or converts: when the retained bytes carry
    a known ambiguity signal, the profile must name it in
    ``unresolved_items`` instead of silently resolving it.
    """
    history_json = _parsed_json(history_payload)
    history_text = _decoded_text(history_payload)
    capability_text = _decoded_text(capability_payload)

    if isinstance(history_json, dict) and history_json.get("monthly_salary") == 22:
        _require_coverage(
            items,
            ("salary", "pay_unit", "unit_ambiguity", "wage"),
            "ambiguous salary value 22 in a monthly-salary field must remain "
            "an unresolved item; silent conversion to hourly pay is forbidden",
        )

    if isinstance(history_json, dict) and _jobs_overlap(history_json.get("jobs")):
        _require_coverage(
            items,
            ("date", "employment_date", "conflict", "chronology", "overlap"),
            "conflicting employment dates must remain an unresolved item "
            "until evidenced; silent reconciliation is forbidden",
        )

    combined_text = " ".join(
        part for part in (history_text, capability_text) if part is not None
    )
    if "CDL" in combined_text:
        _require_coverage(
            items,
            ("license", "licence", "cdl"),
            "CDL in source history does not establish current license "
            "possession; it must remain an unresolved item until verified",
        )

    lowered = combined_text.lower()
    if "equivalent_experience" in lowered or "equivalent experience" in lowered:
        _require_coverage(
            items,
            ("degree", "education", "equivalent", "qualification"),
            '"equivalent experience" does not automatically satisfy a '
            "mandatory degree rule; it must remain an unresolved item",
        )


# ---------------------------------------------------------------------------
# Profile parsing
# ---------------------------------------------------------------------------


def _parse_string_array(
    data: Any, field_name: str, *, allow_empty: bool, error_cls: type
) -> tuple[str, ...]:
    if not isinstance(data, list):
        raise error_cls(f"{field_name} must be a string array")
    items: list[str] = []
    for index, entry in enumerate(data):
        if not isinstance(entry, str):
            raise error_cls(f"{field_name}[{index}] must be a string")
        if not entry:
            raise error_cls(f"{field_name}[{index}] must be nonempty")
        items.append(entry)
    if not allow_empty and not items:
        raise error_cls(f"{field_name} must be a nonempty string array")
    return tuple(items)


def _parse_unresolved_item(data: Any, index: int) -> UnresolvedItem:
    field_name = f"unresolved_items[{index}]"
    if not isinstance(data, dict):
        raise InvalidProfileError(f"{field_name} must be an object")
    keys = set(data.keys())
    if keys != _UNRESOLVED_FIELDS:
        raise InvalidProfileError(
            f"{field_name} must contain exactly code, detail, "
            f"affected_fields, evidence_refs; got {sorted(keys)}"
        )
    try:
        code = _require_identifier(data["code"], f"{field_name}.code")
        detail = _require_nonempty_str(data["detail"], f"{field_name}.detail")
    except (TypeError, ValueError) as exc:
        raise InvalidProfileError(str(exc)) from exc
    affected = _parse_string_array(
        data["affected_fields"],
        f"{field_name}.affected_fields",
        allow_empty=False,
        error_cls=InvalidProfileError,
    )
    raw_refs = data["evidence_refs"]
    if not isinstance(raw_refs, list):
        raise InvalidProfileError(f"{field_name}.evidence_refs must be an array")
    refs = tuple(
        _coerce_evidence_ref(entry, f"{field_name}.evidence_refs[{pos}]", InvalidProfileError)
        for pos, entry in enumerate(raw_refs)
    )
    return UnresolvedItem(
        code=code, detail=detail, affected_fields=affected, evidence_refs=refs
    )


def _parse_ref_or_missing(data: Any, field_name: str) -> Any:
    if _is_missing_dict(data):
        missing = _coerce_missing(data, field_name, InvalidProfileError)
        if missing.reason == "manual_override" and missing.detail is None:
            raise InvalidProfileError(
                f"{field_name}: manual_override must preserve the superseded "
                "observation in Missing.detail"
            )
        return missing
    if isinstance(data, Missing):
        if data.reason == "manual_override" and data.detail is None:
            raise InvalidProfileError(
                f"{field_name}: manual_override must preserve the superseded "
                "observation in Missing.detail"
            )
        return data
    if isinstance(data, dict):
        ref = _coerce_artifact_ref(data, field_name, InvalidProfileError)
        _require_known_digest(ref.digest, field_name, InvalidProfileError)
        return ref
    raise InvalidProfileError(
        f"{field_name} must be an ArtifactReference or a Missing envelope"
    )


def _verify_prefix_citations(
    channel_id: str,
    prefix: Any,
    source_refs: tuple[Any, ...],
    items: tuple[UnresolvedItem, ...],
) -> tuple[Any, ...]:
    """Verify the evidence prefix and every same-journal citation."""
    events = evidence_journal.read_prefix(channel_id, prefix)
    by_sequence = {event.journal_sequence: event for event in events}
    citations: list[Any] = list(source_refs)
    for item in items:
        citations.extend(item.evidence_refs)
    for ref in citations:
        if ref.journal_id != prefix.journal_id:
            continue
        if ref.sequence < 1 or ref.sequence > prefix.last_sequence:
            raise InvalidProfileError(
                f"evidence ref sequence {ref.sequence} falls outside "
                f"prefix last_sequence {prefix.last_sequence}"
            )
        event = by_sequence.get(ref.sequence)
        if event is None:
            raise InvalidProfileError(
                f"evidence ref sequence {ref.sequence} has no event "
                "in the verified prefix"
            )
        if event.event_id != ref.event_id or event.event_hash != ref.event_hash:
            raise InvalidProfileError(
                "evidence ref journal/sequence/event id/hash does not agree "
                "with the verified prefix"
            )
    return events


def _parse_and_verify_profile(channel_id: str, obj: Any) -> CandidateProfileArtifact:
    if not isinstance(obj, dict):
        raise InvalidProfileError("candidate profile record must be a JSON object")
    keys = set(obj.keys())
    if keys != _PROFILE_FIELDS:
        missing = sorted(_PROFILE_FIELDS - keys)
        extra = sorted(keys - _PROFILE_FIELDS)
        parts: list[str] = []
        if missing:
            parts.append(f"missing properties: {missing}")
        if extra:
            parts.append(f"undeclared properties: {extra}")
        raise InvalidProfileError(
            "candidate profile must declare exactly the twelve closed "
            f"properties ({'; '.join(parts)})"
        )
    if obj["record_type"] != CANDIDATE_PROFILE_RECORD_TYPE:
        raise InvalidProfileError(
            f"record_type must be {CANDIDATE_PROFILE_RECORD_TYPE!r}"
        )
    if obj["schema_version"] != CANDIDATE_PROFILE_SCHEMA_VERSION:
        raise InvalidProfileError(
            "unknown candidate profile schema_version: "
            f"{obj['schema_version']!r} (expected "
            f"{CANDIDATE_PROFILE_SCHEMA_VERSION!r})"
        )
    try:
        candidate_id = _require_identifier(obj["candidate_id"], "candidate_id")
    except (TypeError, ValueError) as exc:
        raise InvalidProfileError(str(exc)) from exc

    raw_docs = obj["source_documents"]
    if not isinstance(raw_docs, list):
        raise InvalidProfileError("source_documents must be an artifact reference array")
    source_documents = tuple(
        _coerce_artifact_ref(entry, f"source_documents[{pos}]", InvalidProfileError)
        for pos, entry in enumerate(raw_docs)
    )
    for pos, ref in enumerate(source_documents):
        _require_known_digest(ref.digest, f"source_documents[{pos}]", InvalidProfileError)

    raw_source_refs = obj["source_evidence_refs"]
    if not isinstance(raw_source_refs, list):
        raise InvalidProfileError("source_evidence_refs must be an evidence reference array")
    source_evidence_refs = tuple(
        _coerce_evidence_ref(entry, f"source_evidence_refs[{pos}]", InvalidProfileError)
        for pos, entry in enumerate(raw_source_refs)
    )

    employment_history = _parse_ref_or_missing(obj["employment_history"], "employment_history")
    capability_profile = _coerce_artifact_ref(
        obj["capability_profile"], "capability_profile", InvalidProfileError
    )
    _require_known_digest(capability_profile.digest, "capability_profile", InvalidProfileError)
    playbook_catalog = _coerce_version_pin(
        obj["playbook_catalog"], "playbook_catalog", InvalidProfileError
    )
    _require_known_digest(
        playbook_catalog.artifact_digest, "playbook_catalog", InvalidProfileError
    )
    constraints = _parse_ref_or_missing(obj["constraints"], "constraints")
    if _is_missing_dict(obj["disclosure_policy"]) or isinstance(
        obj["disclosure_policy"], Missing
    ):
        raise InvalidProfileError(
            "disclosure_policy must be a pinned VersionPin; disclosure "
            "permissions are never inferred from analysis"
        )
    disclosure_policy = _coerce_version_pin(
        obj["disclosure_policy"], "disclosure_policy", InvalidProfileError
    )
    _require_known_digest(
        disclosure_policy.artifact_digest, "disclosure_policy", InvalidProfileError
    )

    raw_items = obj["unresolved_items"]
    if not isinstance(raw_items, list):
        raise InvalidProfileError("unresolved_items must be an array")
    unresolved_items = tuple(
        _parse_unresolved_item(entry, pos) for pos, entry in enumerate(raw_items)
    )

    prefix = _coerce_prefix(obj["evidence_prefix"], InvalidProfileError)
    _verify_prefix_citations(channel_id, prefix, source_evidence_refs, unresolved_items)

    # Resolve the interpreted artifacts so ambiguity scanning inspects the
    # exact retained bytes (EK-ARTIFACTS); hashes alone never suffice.
    history_payload: bytes | None = None
    if not isinstance(employment_history, Missing):
        history_payload = artifact_store.resolve_artifact(channel_id, employment_history)
    capability_payload = artifact_store.resolve_artifact(channel_id, capability_profile)
    _check_ambiguity_coverage(unresolved_items, history_payload, capability_payload)

    return CandidateProfileArtifact(
        record_type=CANDIDATE_PROFILE_RECORD_TYPE,
        schema_version=CANDIDATE_PROFILE_SCHEMA_VERSION,
        candidate_id=candidate_id,
        source_documents=source_documents,
        source_evidence_refs=source_evidence_refs,
        employment_history=employment_history,
        capability_profile=capability_profile,
        playbook_catalog=playbook_catalog,
        constraints=constraints,
        disclosure_policy=disclosure_policy,
        unresolved_items=unresolved_items,
        evidence_prefix=prefix,
    )


# ---------------------------------------------------------------------------
# Catalog parsing
# ---------------------------------------------------------------------------


def _parse_playbook_entry(data: Any, index: int) -> PlaybookEntry:
    field_name = f"entries[{index}]"
    if not isinstance(data, dict):
        raise InvalidCatalogError(f"{field_name} must be an object")
    keys = set(data.keys())
    if keys != _ENTRY_FIELDS:
        missing = sorted(_ENTRY_FIELDS - keys)
        extra = sorted(keys - _ENTRY_FIELDS)
        parts: list[str] = []
        if missing:
            parts.append(f"missing properties: {missing}")
        if extra:
            parts.append(f"undeclared properties: {extra}")
        raise InvalidCatalogError(
            f"{field_name} must declare exactly playbook_id, name, "
            f"primitive_actions, trigger_conditions, limitations, "
            f"source_refs ({'; '.join(parts)})"
        )
    playbook_id = data["playbook_id"]
    if playbook_id not in _PLAYBOOK_ID_SET:
        raise InvalidCatalogError(
            f"{field_name}.playbook_id must be one of the eight stable "
            f"identifiers; got {playbook_id!r}"
        )
    try:
        name = _require_nonempty_str(data["name"], f"{field_name}.name")
    except (TypeError, ValueError) as exc:
        raise InvalidCatalogError(str(exc)) from exc
    primitive_actions = _parse_string_array(
        data["primitive_actions"],
        f"{field_name}.primitive_actions",
        allow_empty=True,
        error_cls=InvalidCatalogError,
    )
    trigger_conditions = _parse_string_array(
        data["trigger_conditions"],
        f"{field_name}.trigger_conditions",
        allow_empty=True,
        error_cls=InvalidCatalogError,
    )
    limitations = _parse_string_array(
        data["limitations"],
        f"{field_name}.limitations",
        allow_empty=True,
        error_cls=InvalidCatalogError,
    )
    source_refs = _parse_string_array(
        data["source_refs"],
        f"{field_name}.source_refs",
        allow_empty=False,
        error_cls=InvalidCatalogError,
    )
    return PlaybookEntry(
        playbook_id=playbook_id,
        name=name,
        primitive_actions=primitive_actions,
        trigger_conditions=trigger_conditions,
        limitations=limitations,
        source_refs=source_refs,
    )


def _parse_catalog(obj: Any) -> PlaybookCatalog:
    if not isinstance(obj, dict):
        raise InvalidCatalogError("playbook catalog record must be a JSON object")
    keys = set(obj.keys())
    if keys != _CATALOG_FIELDS:
        missing = sorted(_CATALOG_FIELDS - keys)
        extra = sorted(keys - _CATALOG_FIELDS)
        parts: list[str] = []
        if missing:
            parts.append(f"missing properties: {missing}")
        if extra:
            parts.append(f"undeclared properties: {extra}")
        raise InvalidCatalogError(
            "playbook catalog must declare exactly record_type, "
            f"schema_version, entries ({'; '.join(parts)})"
        )
    if obj["record_type"] != PLAYBOOK_CATALOG_RECORD_TYPE:
        raise InvalidCatalogError(f"record_type must be {PLAYBOOK_CATALOG_RECORD_TYPE!r}")
    if obj["schema_version"] != PLAYBOOK_CATALOG_SCHEMA_VERSION:
        raise InvalidCatalogError(
            "unknown playbook catalog schema_version: "
            f"{obj['schema_version']!r} (expected "
            f"{PLAYBOOK_CATALOG_SCHEMA_VERSION!r})"
        )
    raw_entries = obj["entries"]
    if not isinstance(raw_entries, list):
        raise InvalidCatalogError("entries must be an array")
    if len(raw_entries) != 8:
        raise InvalidCatalogError(
            f"playbook catalog must contain exactly eight entries; "
            f"got {len(raw_entries)}"
        )
    entries = tuple(_parse_playbook_entry(entry, pos) for pos, entry in enumerate(raw_entries))
    seen = [entry.playbook_id for entry in entries]
    if len(set(seen)) != 8:
        raise InvalidCatalogError("playbook_ids must occur exactly once; duplicates found")
    if set(seen) != _PLAYBOOK_ID_SET:
        raise InvalidCatalogError(
            "playbook catalog must contain exactly the eight stable "
            f"identifiers; got {sorted(seen)}"
        )
    return PlaybookCatalog(
        record_type=PLAYBOOK_CATALOG_RECORD_TYPE,
        schema_version=PLAYBOOK_CATALOG_SCHEMA_VERSION,
        entries=entries,
    )


# ---------------------------------------------------------------------------
# Public interface (EXPOSES)
# ---------------------------------------------------------------------------


def load_candidate_profile(channel_id: str, profile: Any) -> CandidateProfileArtifact:
    """Load and validate the exact retained candidate profile artifact.

    Authorizes the channel, resolves the exact retained bytes (never a hash
    alone), validates strict JSON through the kernel codec, enforces the
    closed twelve-field shape, verifies the evidence prefix and every
    same-journal citation, and requires explicit unresolved items for
    salary-unit, date-conflict, license, and degree ambiguities. Nothing is
    reconciled, converted, or inferred.
    """
    _require_identifier(channel_id, "channel_id")
    ref = _coerce_artifact_ref(profile, "profile", InvalidProfileError)
    _authorize(channel_id)
    raw = artifact_store.resolve_artifact(channel_id, ref)
    obj = _strict_gate(raw, "candidate profile", InvalidProfileError)
    return _parse_and_verify_profile(channel_id, obj)


def load_playbook_catalog(channel_id: str, catalog: Any) -> PlaybookCatalog:
    """Load and validate the pinned eight-playbook documentary catalog.

    Authorizes the channel, resolves the pinned bytes through the artifact
    store, validates strict JSON through the kernel codec, and enforces
    exactly eight entries with unique stable identifiers and nonempty
    documentary sources. Entries carry no executor capability fields.
    """
    _require_identifier(channel_id, "channel_id")
    pin = _coerce_version_pin(catalog, "catalog", InvalidCatalogError)
    _authorize(channel_id)
    raw = _resolve_by_digest(channel_id, pin.artifact_digest)
    obj = _strict_gate(raw, "playbook catalog", InvalidCatalogError)
    return _parse_catalog(obj)

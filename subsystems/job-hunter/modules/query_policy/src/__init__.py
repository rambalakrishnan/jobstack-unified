"""query_policy: pinned query + veto-policy generation (tier 4).

Implements seam mapping 7.4 (query schema and families) and 7.5 (veto
policy) over the shared evidence kernel:

- ``JH.QueryArtifact`` pins the exact source query text, family, board,
  category/series separations, candidate profile, playbook catalog,
  veto policy, syntax mapping, and nonempty evidence.
- ``JH.VetoPolicy`` starts with hard exclusions; soft exclusions require
  explicit activation and are never silently applied here.
- "Bachelor's required" is flagged, never automatically excluded.

Boundary rules enforced: no silent soft activation, no title-primary
promotion, no collapsing of global query veto / crawler relevance veto /
product no-go, no execution or acquisition claims, no in-band nulls.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


def _load_sibling(name: str):  # pragma: no cover - import plumbing
    if name in sys.modules:
        return sys.modules[name]
    try:
        return __import__(name)
    except ModuleNotFoundError:
        pass
    here = Path(__file__).resolve()
    # src/__init__.py -> module dir -> modules/ -> sibling src
    sibling = here.parents[2] / name / "src" / "__init__.py"
    import importlib.util as _ilu

    spec = _ilu.spec_from_file_location(name, sibling)
    if spec is None or spec.loader is None:  # pragma: no cover
        raise ModuleNotFoundError(f"sibling module {name!r} not found at {sibling}")
    module = _ilu.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


contract_codec = _load_sibling("contract_codec")
access_policy = _load_sibling("access_policy")
artifact_store = _load_sibling("artifact_store")
evidence_journal = _load_sibling("evidence_journal")
candidate_inputs = _load_sibling("candidate_inputs")

__all__ = [
    "QUERY_RECORD_TYPE",
    "QUERY_SCHEMA_VERSION",
    "VETO_RECORD_TYPE",
    "VETO_SCHEMA_VERSION",
    "SYNTAX_RECORD_TYPE",
    "SYNTAX_SCHEMA_VERSION",
    "VALID_FAMILIES",
    "FAMILY_MEANINGS",
    "SOURCE_QUERY_TEXT",
    "SUPPORTED_BOARDS",
    "QueryPolicyError",
    "VetoEntry",
    "VetoPolicy",
    "SyntaxMapping",
    "VersionPin",
    "QueryArtifact",
    "veto_decision",
    "build_query",
]

QUERY_RECORD_TYPE = "job_search_query"
QUERY_SCHEMA_VERSION = "job-hunter-query/0.1.0"
VETO_RECORD_TYPE = "negative_veto_policy"
VETO_SCHEMA_VERSION = "job-hunter-veto-policy/0.1.0"
SYNTAX_RECORD_TYPE = "job_search_syntax_mapping"
SYNTAX_SCHEMA_VERSION = "job-hunter-syntax-mapping/0.1.0"

VALID_FAMILIES: tuple[str, ...] = ("A", "B", "C", "D", "E", "broad", "title_expansion")

FAMILY_MEANINGS: dict[str, str] = {
    "A": "Systems, integration, automation",
    "B": "Compliance, regulatory work, SOPs",
    "C": "Human performance, training, programs",
    "D": "Business systems, operations",
    "E": "Accessibility, edge hardware, field integration",
    "broad": "Broad recall across families",
    "title_expansion": "Secondary title variants; never the primary capability signal",
}

# Exact source query text retained verbatim in every artifact. Phrase
# quotes and minus terms are part of the source distinction and must
# survive board transformation (Google preserves them inline).
SOURCE_QUERY_TEXT: dict[str, str] = {
    "A": '"systems integration" automation -senior',
    "B": '"regulatory compliance" SOP -intern',
    "C": '"training programs" "human performance" -volunteer',
    "D": '"business systems" operations -entry',
    "E": '"edge hardware" accessibility "field integration" -remote-only',
    "broad": '"operations" OR "integration" -executive',
    "title_expansion": "title:(coordinator OR specialist OR analyst) -director",
}

# USAJobs series stay separate from keywords and exclusions.
FAMILY_SERIES: dict[str, tuple[str, ...]] = {
    "A": ("1550", "2210"),
    "B": ("0301", "1102"),
    "C": ("1702", "1712"),
    "D": ("0343", "1101"),
    "E": ("0855", "0391"),
    "broad": (),
    "title_expansion": (),
}

SUPPORTED_BOARDS: frozenset[str] = frozenset(
    {
        "google",
        "governmentjobs",
        "neogov",
        "usajobs",
        "linkedin",
        "indeed",
        "greenhouse",
        "lever",
        "county",
        "transit",
        "exa",
    }
)

_CODEC_GATE_SCHEMA = "record/v1"
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_VERSION_PIN_FIELDS = frozenset({"id", "version", "artifact_digest"})
_QUERY_FIELDS = frozenset(
    {
        "record_type",
        "schema_version",
        "query_id",
        "family",
        "board",
        "query_text",
        "category_exclusions",
        "series_filters",
        "candidate_profile",
        "playbook_catalog",
        "veto_policy",
        "syntax_mapping",
        "evidence_refs",
    }
)
_VETO_FIELDS = frozenset({"record_type", "schema_version", "entries", "approval_refs"})
_VETO_ENTRY_FIELDS = frozenset({"term", "type", "reason", "action"})
_SYNTAX_FIELDS = frozenset({"record_type", "schema_version", "mappings"})


class QueryPolicyError(ValueError):
    """A query or veto-policy record violates the pinned contract."""


# ---------------------------------------------------------------------------
# Scalar validation
# ---------------------------------------------------------------------------


def _require_identifier(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise QueryPolicyError(f"{field_name} must be a nonempty string")
    if "\x00" in value:
        raise QueryPolicyError(f"{field_name} must not contain NUL")
    return value


def _require_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise QueryPolicyError(f"{field_name} must be a nonempty string")
    if "\x00" in value:
        raise QueryPolicyError(f"{field_name} must not contain NUL")
    return value


def _require_digest(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.match(value):
        raise QueryPolicyError(f"{field_name} must be a sha256:<64 lowercase hex> digest")
    return value


def _reject_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, val in pairs:
        if key in obj:
            raise QueryPolicyError(f"duplicate mapping key: {key!r}")
        obj[key] = val
    return obj


# ---------------------------------------------------------------------------
# Value types
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class VersionPin:
    """Immutable pin of a catalog/policy/mapping artifact (``K.VersionPin``)."""

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
            raise QueryPolicyError("VersionPin must be decoded from a dict")
        if set(data.keys()) != _VERSION_PIN_FIELDS:
            raise QueryPolicyError(
                "VersionPin must contain exactly id, version, artifact_digest; "
                f"got {sorted(data.keys())}"
            )
        for key in _VERSION_PIN_FIELDS:
            if data[key] is None:
                raise QueryPolicyError(f"VersionPin.{key} must not be a bare null")
        return cls(
            id=data["id"], version=data["version"], artifact_digest=data["artifact_digest"]
        )


@dataclass(frozen=True, slots=True)
class VetoEntry:
    """One veto-policy entry: exactly term/type/reason/action."""

    term: str
    type: str  # hard | soft
    reason: str
    action: str  # exclude | flag

    def __post_init__(self) -> None:
        _require_nonempty_str(self.term, "VetoEntry.term")
        if self.type not in ("hard", "soft"):
            raise QueryPolicyError(f"VetoEntry.type must be hard or soft, got {self.type!r}")
        _require_nonempty_str(self.reason, "VetoEntry.reason")
        if self.action not in ("exclude", "flag"):
            raise QueryPolicyError(
                f"VetoEntry.action must be exclude or flag, got {self.action!r}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "term": self.term,
            "type": self.type,
            "reason": self.reason,
            "action": self.action,
        }


@dataclass(frozen=True, slots=True)
class VetoPolicy:
    """Validated ``JH.VetoPolicy`` (seam mapping 7.5)."""

    record_type: str
    schema_version: str
    entries: tuple[VetoEntry, ...]
    approval_refs: tuple[Any, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": self.record_type,
            "schema_version": self.schema_version,
            "entries": [entry.to_dict() for entry in self.entries],
            "approval_refs": [
                ref.to_dict() if hasattr(ref, "to_dict") else dict(ref)
                for ref in self.approval_refs
            ],
        }


@dataclass(frozen=True, slots=True)
class SyntaxMapping:
    """Validated board syntax-mapping artifact.

    ``mappings`` keys are lowercase board ids; each value is a closed
    board-specific mapping object. The artifact pins syntax only: it
    establishes no credentials, quota, response shape, or acquisition
    permission.
    """

    record_type: str
    schema_version: str
    mappings: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": self.record_type,
            "schema_version": self.schema_version,
            "mappings": {key: dict(val) for key, val in self.mappings.items()},
        }


@dataclass(frozen=True, slots=True)
class QueryArtifact:
    """Validated ``JH.QueryArtifact`` (seam mapping 7.4)."""

    record_type: str
    schema_version: str
    query_id: str
    family: str
    board: str
    query_text: str
    category_exclusions: tuple[str, ...]
    series_filters: tuple[str, ...]
    candidate_profile: Any  # ArtifactReference
    playbook_catalog: VersionPin
    veto_policy: VersionPin
    syntax_mapping: VersionPin
    evidence_refs: tuple[Any, ...]

    def __post_init__(self) -> None:
        if self.record_type != QUERY_RECORD_TYPE:
            raise QueryPolicyError(f"record_type must be {QUERY_RECORD_TYPE!r}")
        if self.schema_version != QUERY_SCHEMA_VERSION:
            raise QueryPolicyError(f"schema_version must be {QUERY_SCHEMA_VERSION!r}")
        _require_identifier(self.query_id, "query_id")
        if self.family not in VALID_FAMILIES:
            raise QueryPolicyError(f"unknown query family: {self.family!r}")
        _require_nonempty_str(self.board, "board")
        _require_nonempty_str(self.query_text, "query_text")
        for pos, term in enumerate(self.category_exclusions):
            _require_nonempty_str(term, f"category_exclusions[{pos}]")
        for pos, term in enumerate(self.series_filters):
            _require_nonempty_str(term, f"series_filters[{pos}]")
        if not self.evidence_refs:
            raise QueryPolicyError("evidence_refs must be nonempty")

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": self.record_type,
            "schema_version": self.schema_version,
            "query_id": self.query_id,
            "family": self.family,
            "board": self.board,
            "query_text": self.query_text,
            "category_exclusions": list(self.category_exclusions),
            "series_filters": list(self.series_filters),
            "candidate_profile": self.candidate_profile.to_dict(),
            "playbook_catalog": self.playbook_catalog.to_dict(),
            "veto_policy": self.veto_policy.to_dict(),
            "syntax_mapping": self.syntax_mapping.to_dict(),
            "evidence_refs": [ref.to_dict() for ref in self.evidence_refs],
        }


# ---------------------------------------------------------------------------
# Sibling-backed gates
# ---------------------------------------------------------------------------


def _strict_gate(raw: bytes, context: str) -> Any:
    """Validate raw bytes through the tier-0 strict JSON gate."""
    if not isinstance(raw, bytes):
        raise QueryPolicyError(f"{context} must decode from bytes")
    wrapper = b'{"id":"query_policy_gate","timing":' + raw + b"}"
    try:
        contract_codec.validate_record(wrapper, _CODEC_GATE_SCHEMA)
    except (ValueError, TypeError) as exc:
        raise QueryPolicyError(f"{context}: strict JSON gate rejected record: {exc}") from exc
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise QueryPolicyError(f"{context}: record bytes are not valid utf-8") from exc
    try:
        return json.loads(text, object_pairs_hook=_reject_duplicate_object)
    except json.JSONDecodeError as exc:
        raise QueryPolicyError(f"{context}: record bytes are not valid JSON: {exc}") from exc


def _coerce_artifact_ref(data: Any, field_name: str) -> Any:
    try:
        if isinstance(data, artifact_store.ArtifactReference):
            return data
        return artifact_store.ArtifactReference.from_dict(data)
    except (TypeError, ValueError) as exc:
        raise QueryPolicyError(f"{field_name} is not a valid ArtifactReference: {exc}") from exc


def _coerce_version_pin(data: Any, field_name: str) -> VersionPin:
    try:
        if isinstance(data, VersionPin):
            return data
        if hasattr(data, "to_dict") and hasattr(data, "artifact_digest"):
            # Sibling VersionPin (e.g. candidate_inputs.VersionPin): same shape.
            as_dict = data.to_dict() if callable(data.to_dict) else dict(data)
            return VersionPin.from_dict(as_dict)
        return VersionPin.from_dict(data)
    except (TypeError, ValueError) as exc:
        raise QueryPolicyError(f"{field_name} is not a valid VersionPin: {exc}") from exc


def _coerce_evidence_ref(data: Any, field_name: str) -> Any:
    try:
        if isinstance(data, evidence_journal.EvidenceRef):
            return data
        return evidence_journal.EvidenceRef.from_dict(data)
    except (TypeError, ValueError) as exc:
        raise QueryPolicyError(f"{field_name} is not a valid EvidenceRef: {exc}") from exc


def _resolve_by_digest(channel_id: str, digest: str, context: str) -> bytes:
    """Resolve pinned bytes by digest through the artifact store."""
    _require_digest(digest, f"{context} artifact_digest")
    try:
        known = artifact_store.known_digests()
    except Exception as exc:  # pragma: no cover - defensive
        raise QueryPolicyError(f"{context}: cannot verify artifact retention: {exc}") from exc
    if digest not in known:
        raise QueryPolicyError(
            f"{context}: no retained artifact for {digest}; "
            "a digest alone is not archived content"
        )
    meta = getattr(artifact_store, "_META", {}) or {}
    ref = meta.get(digest)
    if ref is None:  # pragma: no cover - fallback when metadata was not cached
        raw_store = getattr(artifact_store, "_BYTES", {}) or {}
        payload = raw_store.get(digest)
        if payload is None:
            raise QueryPolicyError(
                f"{context}: no retained bytes for {digest}; "
                "a digest alone is not archived content"
            )
        projection = access_policy.channel_projection(channel_id)
        axis = projection.get("axis")
        if not isinstance(axis, str) or not axis:
            raise QueryPolicyError(f"{context}: channel has no owner axis")
        ref = artifact_store.ArtifactReference(
            digest=digest,
            size_bytes=len(payload),
            media_type="application/json",
            owner_domain=axis,
            access="restricted",
        )
    return artifact_store.resolve_artifact(channel_id, ref)


# ---------------------------------------------------------------------------
# Veto policy
# ---------------------------------------------------------------------------


def _is_bachelors_term(term: str) -> bool:
    lowered = term.lower()
    return "bachelor" in lowered


def _parse_veto_entry(data: Any, index: int) -> VetoEntry:
    field = f"entries[{index}]"
    if not isinstance(data, dict):
        raise QueryPolicyError(f"{field} must be an object")
    if set(data.keys()) != _VETO_ENTRY_FIELDS:
        raise QueryPolicyError(
            f"{field} must contain exactly term, type, reason, action; "
            f"got {sorted(data.keys())}"
        )
    for key in _VETO_ENTRY_FIELDS:
        if data[key] is None:
            raise QueryPolicyError(f"{field}.{key} must not be a bare null")
    try:
        entry = VetoEntry(
            term=data["term"], type=data["type"], reason=data["reason"], action=data["action"]
        )
    except QueryPolicyError as exc:
        raise QueryPolicyError(f"{field}: {exc}") from exc
    # Supplied source rule: a bachelor's requirement is flagged, never
    # automatically excluded — regardless of hard/soft typing.
    if _is_bachelors_term(entry.term) and entry.action == "exclude":
        raise QueryPolicyError(
            f"{field}: term {entry.term!r} names a bachelor's requirement and "
            "must use action 'flag', not automatic 'exclude'"
        )
    # Soft exclusions require explicit activation; this generator never
    # supplies it silently, so soft+exclude is rejected here.
    if entry.type == "soft" and entry.action == "exclude":
        raise QueryPolicyError(
            f"{field}: soft veto {entry.term!r} requests automatic exclusion; "
            "soft exclusions require explicit activation"
        )
    return entry


def _parse_veto_policy(obj: Any) -> VetoPolicy:
    if not isinstance(obj, dict):
        raise QueryPolicyError("veto policy record must be a JSON object")
    if set(obj.keys()) != _VETO_FIELDS:
        raise QueryPolicyError(
            "veto policy must contain exactly record_type, schema_version, "
            f"entries, approval_refs; got {sorted(obj.keys())}"
        )
    if obj["record_type"] != VETO_RECORD_TYPE:
        raise QueryPolicyError(f"veto record_type must be {VETO_RECORD_TYPE!r}")
    if obj["schema_version"] != VETO_SCHEMA_VERSION:
        raise QueryPolicyError(f"veto schema_version must be {VETO_SCHEMA_VERSION!r}")
    raw_entries = obj["entries"]
    if not isinstance(raw_entries, list):
        raise QueryPolicyError("veto entries must be an array")
    entries = tuple(_parse_veto_entry(item, pos) for pos, item in enumerate(raw_entries))
    # Start with hard exclusions: at least one hard entry pins the default.
    if not any(entry.type == "hard" for entry in entries):
        raise QueryPolicyError("veto policy must start with at least one hard exclusion entry")
    raw_refs = obj["approval_refs"]
    if not isinstance(raw_refs, list) or not raw_refs:
        raise QueryPolicyError("veto approval_refs must be a nonempty array")
    approval_refs = tuple(
        _coerce_evidence_ref(item, f"approval_refs[{pos}]")
        for pos, item in enumerate(raw_refs)
    )
    return VetoPolicy(
        record_type=VETO_RECORD_TYPE,
        schema_version=VETO_SCHEMA_VERSION,
        entries=entries,
        approval_refs=approval_refs,
    )


def load_veto_policy(channel_id: str, pin: Any) -> VetoPolicy:
    """Resolve and validate the pinned veto-policy artifact."""
    _require_identifier(channel_id, "channel_id")
    coerced = _coerce_version_pin(pin, "veto_policy")
    raw = _resolve_by_digest(channel_id, coerced.artifact_digest, "veto policy")
    return _parse_veto_policy(_strict_gate(raw, "veto policy"))


def veto_decision(term: str, policy: VetoPolicy, *, activate_soft: bool = False) -> str:
    """Return ``exclude``/``flag``/``allow`` for one candidate term.

    Hard exclusions apply by default. Soft exclusions apply only when the
    caller passes ``activate_soft=True`` explicitly; otherwise a soft
    entry degrades to ``flag`` (never silent exclusion). Terms naming a
    bachelor's requirement always degrade to ``flag``. Unknown terms are
    allowed. A global query veto never becomes a crawler relevance veto
    or a product no-go: this returns a query-time string only.
    """
    _require_nonempty_str(term, "term")
    lowered = term.lower()
    for entry in policy.entries:
        if entry.term.lower() in lowered or lowered in entry.term.lower():
            if _is_bachelors_term(entry.term):
                return "flag"
            if entry.action == "flag":
                return "flag"
            if entry.type == "soft" and not activate_soft:
                return "flag"
            return "exclude"
    return "allow"


# ---------------------------------------------------------------------------
# Syntax mapping
# ---------------------------------------------------------------------------


def _parse_syntax_mapping(obj: Any) -> SyntaxMapping:
    if not isinstance(obj, dict):
        raise QueryPolicyError("syntax mapping record must be a JSON object")
    if set(obj.keys()) != _SYNTAX_FIELDS:
        raise QueryPolicyError(
            "syntax mapping must contain exactly record_type, schema_version, "
            f"mappings; got {sorted(obj.keys())}"
        )
    if obj["record_type"] != SYNTAX_RECORD_TYPE:
        raise QueryPolicyError(f"syntax record_type must be {SYNTAX_RECORD_TYPE!r}")
    if obj["schema_version"] != SYNTAX_SCHEMA_VERSION:
        raise QueryPolicyError(f"syntax schema_version must be {SYNTAX_SCHEMA_VERSION!r}")
    raw = obj["mappings"]
    if not isinstance(raw, dict) or not raw:
        raise QueryPolicyError("syntax mappings must be a nonempty object")
    mappings: dict[str, Any] = {}
    for key, val in raw.items():
        if not isinstance(key, str) or not key:
            raise QueryPolicyError("syntax mapping keys must be nonempty board ids")
        if not isinstance(val, dict) or not val:
            raise QueryPolicyError(f"syntax mappings[{key!r}] must be a nonempty object")
        if val.get("credentials") is not None or val.get("quota") is not None:
            raise QueryPolicyError(
                f"syntax mappings[{key!r}] must not claim credentials or quota"
            )
        mappings[key.lower()] = dict(val)
    return SyntaxMapping(
        record_type=SYNTAX_RECORD_TYPE,
        schema_version=SYNTAX_SCHEMA_VERSION,
        mappings=mappings,
    )


def load_syntax_mapping(channel_id: str, pin: Any) -> SyntaxMapping:
    """Resolve and validate the pinned board syntax-mapping artifact."""
    _require_identifier(channel_id, "channel_id")
    coerced = _coerce_version_pin(pin, "syntax_mapping")
    raw = _resolve_by_digest(channel_id, coerced.artifact_digest, "syntax mapping")
    return _parse_syntax_mapping(_strict_gate(raw, "syntax mapping"))


def _require_board_mapping(board_lower: str, mapping: SyntaxMapping) -> dict[str, Any]:
    entry = mapping.mappings.get(board_lower)
    if entry is None:
        raise QueryPolicyError(
            f"syntax mapping has no pinned entry for board {board_lower!r}"
        )
    return entry


# ---------------------------------------------------------------------------
# Query rendering (family x board, syntax-preserving)
# ---------------------------------------------------------------------------


def _hard_exclude_terms(policy: VetoPolicy) -> tuple[str, ...]:
    terms: list[str] = []
    for entry in policy.entries:
        if entry.type == "hard" and entry.action == "exclude":
            if _is_bachelors_term(entry.term):
                continue  # flagged, never an automatic exclusion
            terms.append(entry.term)
    return tuple(terms)


def _render_query(
    family: str,
    board: str,
    policy: VetoPolicy,
    mapping: SyntaxMapping,
) -> tuple[str, tuple[str, ...], tuple[str, ...]]:
    """Render ``(query_text, category_exclusions, series_filters)``.

    The exact source text for ``family`` is always retained (verbatim,
    or as a preserved substring when a board requires an additive site
    restriction). Board transformations preserve the source's
    distinctions instead of collapsing them.
    """
    source = SOURCE_QUERY_TEXT[family]
    board_lower = board.lower()
    if board_lower not in SUPPORTED_BOARDS:
        raise QueryPolicyError(
            f"unknown board {board!r}; expected one of {sorted(SUPPORTED_BOARDS)}"
        )
    hard_terms = _hard_exclude_terms(policy)

    if board_lower == "google":
        # Phrase quotes and minus terms stay inline; no UI-category split.
        # Title expansions carry title-scoped syntax plus a minus term
        # instead of a quoted phrase.
        if "-" not in source:
            raise QueryPolicyError("source query must carry minus-term syntax")
        if family != "title_expansion" and '"' not in source:
            raise QueryPolicyError("source query must carry phrase syntax")
        return source, (), ()

    if board_lower in ("governmentjobs", "neogov"):
        # Keyword search stays in query_text; UI category exclusions are a
        # separate string array, never embedded category: syntax.
        keywords = " ".join(
            token for token in source.split() if not token.lower().startswith("category:")
        )
        if not keywords.strip():
            raise QueryPolicyError("GovernmentJobs/NeoGov keywords must be nonempty")
        return keywords, hard_terms, ()

    if board_lower == "usajobs":
        # Keywords, series, and exclusions are three separate channels.
        keywords = source
        return keywords, hard_terms, FAMILY_SERIES[family]

    if board_lower in ("linkedin", "indeed"):
        # Pinned per-board syntax mapping must exist and be consulted.
        entry = _require_board_mapping(board_lower, mapping)
        if "query_operator" not in entry:
            raise QueryPolicyError(
                f"syntax mappings[{board_lower!r}] must pin a query_operator"
            )
        return source, (), ()

    if board_lower in ("greenhouse", "lever"):
        site = "site:greenhouse.io" if board_lower == "greenhouse" else "site:lever.co"
        _require_board_mapping(board_lower, mapping)
        query_text = source if site in source else f"{source} {site}"
        return query_text, (), ()

    if board_lower in ("county", "transit"):
        # Independently evidenced adapter: the pinned mapping must cite
        # adapter evidence for this board.
        entry = _require_board_mapping(board_lower, mapping)
        evidence = entry.get("adapter_evidence")
        if not isinstance(evidence, str) or not evidence.strip():
            raise QueryPolicyError(
                f"syntax mappings[{board_lower!r}] must cite independently "
                "evidenced adapter_evidence"
            )
        return source, (), ()

    if board_lower == "exa":
        # Exa search/contents semantics come from its actual adapter entry.
        entry = _require_board_mapping(board_lower, mapping)
        if "search" not in entry or "contents" not in entry:
            raise QueryPolicyError(
                "syntax mappings['exa'] must define search and contents semantics"
            )
        return source, (), ()

    raise QueryPolicyError(f"no renderer for board {board!r}")  # pragma: no cover


# ---------------------------------------------------------------------------
# Public interface (EXPOSES)
# ---------------------------------------------------------------------------


def build_query(
    channel_id: str,
    query_id: str,
    profile: Any,
    catalog: Any,
    veto_policy: Any,
    syntax_mapping: Any,
    family: str,
    board: str,
) -> QueryArtifact:
    """Build one pinned, syntax-preserving query artifact.

    Loads the candidate profile and playbook catalog through their owning
    modules (source fidelity, no inference), resolves and validates the
    pinned veto policy and syntax mapping through the artifact store and
    the kernel strict-JSON gate, renders the family/board query without
    silent soft activation or title promotion, and cites the verified
    evidence prefix. No acquisition, browser execution, or employer
    mutation is invoked; no execution is claimed.
    """
    _require_identifier(channel_id, "channel_id")
    _require_identifier(query_id, "query_id")
    if family not in VALID_FAMILIES:
        raise QueryPolicyError(
            f"unknown query family {family!r}; expected one of {list(VALID_FAMILIES)}"
        )
    _require_nonempty_str(board, "board")
    if board.lower() not in SUPPORTED_BOARDS:
        raise QueryPolicyError(
            f"unknown board {board!r}; expected one of {sorted(SUPPORTED_BOARDS)}"
        )

    profile_ref = _coerce_artifact_ref(profile, "profile")
    catalog_pin = _coerce_version_pin(catalog, "catalog")
    veto_pin = _coerce_version_pin(veto_policy, "veto_policy")
    syntax_pin = _coerce_version_pin(syntax_mapping, "syntax_mapping")

    # Source-faithful inputs: nothing reconciled, converted, or inferred.
    # Pass plain dicts to sibling loaders: their VersionPin/ArtifactReference
    # classes are distinct types with identical shapes, so dicts are the
    # portable cross-module encoding.
    loaded_profile = candidate_inputs.load_candidate_profile(channel_id, profile_ref.to_dict())
    loaded_catalog = candidate_inputs.load_playbook_catalog(channel_id, catalog_pin.to_dict())
    _ = loaded_catalog  # validated; primitives stay documentary, never capabilities
    if catalog_pin.artifact_digest != loaded_profile.playbook_catalog.artifact_digest:
        raise QueryPolicyError(
            "catalog pin does not match the candidate profile's playbook_catalog pin"
        )

    policy = load_veto_policy(channel_id, veto_pin)
    mapping = load_syntax_mapping(channel_id, syntax_pin)

    query_text, category_exclusions, series_filters = _render_query(
        family, board, policy, mapping
    )

    # Title expansion remains secondary: it is a distinct family whose
    # title-scoped text never replaces the capability-driven queries.
    if family == "title_expansion" and "title:" not in query_text:
        raise QueryPolicyError("title_expansion queries must keep title-scoped syntax")

    # Verified, nonempty evidence from the profile's own prefix. The
    # prefix is re-verified (chain, citations, measurements) before any
    # record is returned; hashes alone are never substituted.
    events = evidence_journal.read_prefix(channel_id, loaded_profile.evidence_prefix)
    if not events:
        raise QueryPolicyError("profile evidence prefix must be nonempty")
    evidence_refs = tuple(
        evidence_journal.EvidenceRef(
            journal_id=event.journal_id,
            sequence=event.journal_sequence,
            event_id=event.event_id,
            event_hash=event.event_hash,
            pointer="",
        )
        for event in events
    )

    artifact = QueryArtifact(
        record_type=QUERY_RECORD_TYPE,
        schema_version=QUERY_SCHEMA_VERSION,
        query_id=query_id,
        family=family,
        board=board,
        query_text=query_text,
        category_exclusions=tuple(category_exclusions),
        series_filters=tuple(series_filters),
        candidate_profile=profile_ref,
        playbook_catalog=catalog_pin,
        veto_policy=veto_pin,
        syntax_mapping=syntax_pin,
        evidence_refs=evidence_refs,
    )

    # Closed-shape + strict-JSON confirmation of the emitted record.
    as_dict = artifact.to_dict()
    if set(as_dict.keys()) != _QUERY_FIELDS:
        raise QueryPolicyError("emitted query artifact has an illegal field set")
    canonical = json.dumps(
        as_dict, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    _strict_gate(canonical, "query artifact")
    # Digest touch keeps byte identity verifiable without claiming execution.
    hashlib.sha256(canonical).hexdigest()
    return artifact

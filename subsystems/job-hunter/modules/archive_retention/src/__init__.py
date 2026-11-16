"""archive_retention: complete prior-row archives and retention pins (tier 5).

Implements the Job Hunter obligations for crawler fetch-key replacement
(``OWD-REPLACE``), complete logical-row archives (``OWD-ARCHIVE``), and
transitive retention protection (``OWD-RETENTION``) under
``OWD-SEAL`` / ``EK-ARTIFACTS`` / ``EK-HASHES``.

The module never performs a crawler replacement write.  It verifies the
replacement evidence a crawler owner supplies, and it revises retention-pin
revisions as an owner-local journal effect of the archive's persistence
domain.

Verification rules implemented here:

* the named ``archive_root`` resolves to a canonical ``ArchiveRecord`` whose
  ``root`` hashes the canonical ``ArchiveStorageManifest`` bytes;
* the manifest expands to exactly ``payload_json``: the complete previous
  ``LogicalRow``, every declared domain slot, reasoned nulls, publication
  references, registration, and the ``fetch_key_replacement`` seal vector;
* every archived document is an immutable, already-retained local extent with
  verified exact bytes -- a peer locator, hash list, diff, crawler-only row,
  or "latest downstream record" is not an archive;
* the replacement receipt agrees with the archived cut and with the journaled
  replacement commit event, names a genuinely changed fetch key, and the
  journaled active retention pin already protects the archive root;
* a retention revision only shortens nothing: release requires journaled
  retirement evidence and fails while any other active pin still reaches the
  root, directly or through a retained later archive's backward link;
* lost retained bytes raise an explicit integrity incident instead of being
  reconstructed from mutable peer state.

Missing optionality is always a typed ``Missing`` envelope; in-band nulls are
rejected.  Nothing here reads mutable peer state: every expansion component is
an immutable local extent resolved through :mod:`artifact_store`.
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
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


def _load_sibling(name: str):
    """Import a sibling module, falling back to its source path."""
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

ArtifactReference = artifact_store.ArtifactReference

__all__ = [
    "SCHEMA_VERSION",
    "EVENT_SCHEMA_VERSION",
    "ARCHIVE_ENCODING",
    "ARCHIVE_RECORD_TYPE",
    "REPLACEMENT_RECORD_TYPE",
    "PIN_RECORD_TYPE",
    "RETIREMENT_RECORD_TYPE",
    "LOGICAL_ROW_RECORD_TYPE",
    "OWNED_REVISION_RECORD_TYPE",
    "REGISTRATION_RECORD_TYPE",
    "JOB_DOMAINS",
    "DOMAIN_OWNERS",
    "PIN_STATES",
    "DEPENDENT_KINDS",
    "PIN_EVENT_KIND",
    "RETIREMENT_EVENT_KIND",
    "REPLACEMENT_EVENT_KIND",
    "ArchiveRetentionError",
    "ReplacementRejectedError",
    "IncompleteArchiveError",
    "ArchiveIntegrityError",
    "RetentionRejectedError",
    "RetentionAuthorityError",
    "RetentionStillReachableError",
    "ArchiveRecord",
    "FetchKeyReplacement",
    "RetentionPinRevision",
    "ArtifactReference",
    "verify_replacement",
    "revise_retention",
]

SCHEMA_VERSION = "owner-separated-write-domains/0.1.0"
EVENT_SCHEMA_VERSION = "archive-retention/0.1.0"

ARCHIVE_ENCODING = "owner-domain-extents/1"
ARCHIVE_RECORD_TYPE = "logical_row_archive"
REPLACEMENT_RECORD_TYPE = "fetch_key_replacement"
PIN_RECORD_TYPE = "archive_retention_pin"
RETIREMENT_RECORD_TYPE = "archive_retention_retirement"
LOGICAL_ROW_RECORD_TYPE = "logical_row"
OWNED_REVISION_RECORD_TYPE = "owned_domain_revision"
REGISTRATION_RECORD_TYPE = "write_domain_entity"

JOB_DOMAINS = ("crawler", "downstream")
DOMAIN_OWNERS = {"crawler": "job.crawler", "downstream": "job.downstream"}
PIN_STATES = frozenset({"active", "released"})
DEPENDENT_KINDS = frozenset(
    {"live_replacement", "retained_archive", "retained_evidence"}
)
JOB_SEAL_NAMES = frozenset({"published", "fetch_key_replacement", "evidence_updated"})

PIN_EVENT_KIND = "archive.retention_revised"
RETIREMENT_EVENT_KIND = "archive.retention_retired"
REPLACEMENT_EVENT_KIND = "crawler.fetch_key_replaced"

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_POINTER_RE = re.compile(r"^(?:/(?:[^~/]|~[01])*)*$")
_MAX_REVISION = 9007199254740991

_REFERENCE_KEYS = frozenset(
    {"digest", "size_bytes", "media_type", "owner_domain", "access"}
)
_EVIDENCE_REF_KEYS = frozenset(
    {"journal_id", "sequence", "event_id", "event_hash", "pointer"}
)
_PREFIX_KEYS = frozenset({"journal_id", "last_sequence", "head_hash"})
_MISSING_KEYS = frozenset({"value", "reason", "detail"})

_ENTITY_KEYS = frozenset({"entity_type", "target", "job_id"})
_ARCHIVE_RECORD_KEYS = frozenset(
    {"record_type", "schema_version", "root", "storage_manifest", "payload_json"}
)
_MANIFEST_KEYS = frozenset(
    {"encoding", "schema_version", "entity", "registration", "domains", "seal_point"}
)
_MANIFEST_SLOT_PUBLISHED_KEYS = frozenset(
    {"revision", "document", "publication_ref"}
)
_MANIFEST_SLOT_UNPUBLISHED_KEYS = frozenset({"revision", "value"})
_SEAL_KEYS = frozenset(
    {
        "seal_id",
        "name",
        "view_id",
        "versions",
        "sealed_at",
        "input_prefix",
        "evidence_refs",
    }
)
_TIME_POINT_KEYS = frozenset(
    {"clock_id", "boot_id", "origin", "monotonic_offset_ms", "utc_annotation"}
)
_REGISTRATION_KEYS = frozenset(
    {
        "record_type",
        "schema_version",
        "registration_id",
        "entity",
        "identity",
        "owners",
        "evidence_prefix",
        "evidence_refs",
    }
)
_OWNED_DOCUMENT_KEYS = frozenset(
    {
        "record_type",
        "schema_version",
        "entity",
        "registration_digest",
        "domain",
        "owner_domain",
        "writer_id",
        "revision",
        "previous_revision",
        "evidence_prefix",
        "evidence_refs",
        "value",
    }
)
_ROW_KEYS = frozenset(
    {
        "record_type",
        "schema_version",
        "entity",
        "registration_digest",
        "registration",
        "domains",
        "seal_point",
    }
)
_REPLACEMENT_KEYS = frozenset(
    {
        "record_type",
        "schema_version",
        "replacement_id",
        "entity",
        "registration_digest",
        "old_crawler",
        "old_fetch_key",
        "new_crawler",
        "archive_root",
        "archived_vector",
        "retention_pin_id",
        "commit_ref",
        "evidence_prefix",
        "evidence_refs",
    }
)
_OLD_CRAWLER_KEYS = frozenset({"revision", "record_digest"})
_LINEAGE_KEYS = frozenset(
    {"replacement_id", "prior_crawler_revision", "archive_root"}
)
_DEPENDENT_KEYS = frozenset({"entity", "kind", "root_id"})
_PIN_KEYS = frozenset(
    {
        "record_type",
        "schema_version",
        "pin_id",
        "owner_domain",
        "writer_id",
        "revision",
        "previous_revision",
        "dependent",
        "archive_root",
        "state",
        "release_ref",
        "evidence_prefix",
        "evidence_refs",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ArchiveRetentionError(Exception):
    """Base class for archive verification and retention failures."""


class ReplacementRejectedError(ArchiveRetentionError, ValueError):
    """Received replacement evidence is not a valid changed-fetch-key cut."""


class IncompleteArchiveError(ArchiveRetentionError, ValueError):
    """The archive does not expand to the complete prior logical row.

    Carries the typed ``Missing`` envelope of the component that could not be
    reconstructed locally, if one applies.  A locator to peer state is never
    resolved into different bytes.
    """

    def __init__(self, message: str, missing: dict[str, Any] | None = None) -> None:
        self.missing = missing
        super().__init__(message)


class ArchiveIntegrityError(ArchiveRetentionError):
    """Retained archive bytes are absent, changed, or otherwise inconsistent."""

    def __init__(self, message: str, missing: dict[str, Any] | None = None) -> None:
        self.missing = missing
        super().__init__(message)


class RetentionRejectedError(ArchiveRetentionError, ValueError):
    """A retention-pin revision is not an authorized, fenced transition."""


class RetentionAuthorityError(RetentionRejectedError):
    """The writer asking for the retention revision is not its authority."""


class RetentionStillReachableError(RetentionRejectedError):
    """A release would drop protection another active root still needs."""


# ---------------------------------------------------------------------------
# Small validators (closed records, typed missingness, digests)
# ---------------------------------------------------------------------------


def _require_mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{field} must be a mapping, not {type(value).__name__}")
    return value


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


def _require_digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.match(value):
        raise ValueError(f"{field} must be a sha256:<64 lowercase hex> digest")
    return value


def _require_revision(value: Any, field: str, *, positive: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{field} must be an int")
    if positive and value < 1:
        raise ValueError(f"{field} must be a positive integer")
    if value < 0 or value > _MAX_REVISION:
        raise ValueError(f"{field} is outside the supported revision range")
    return value


def _closed(
    value: Any,
    required: Sequence[str],
    where: str,
    *,
    optional: Sequence[str] = (),
) -> dict[str, Any]:
    """Return a shallow copy after rejecting missing or undeclared properties."""
    data = _require_mapping(value, where)
    keys = set(data.keys())
    required_set = set(required)
    allowed = required_set | set(optional)
    missing = sorted(required_set - keys)
    if missing:
        raise ValueError(f"{where} is missing required properties: {missing}")
    extra = sorted(keys - allowed)
    if extra:
        raise ValueError(f"{where} has undeclared properties: {extra}")
    return dict(data)


def _missing_envelope(
    value: Any, where: str, *, reason: str | None = None
) -> dict[str, Any]:
    data = _require_mapping(value, where)
    extra = sorted(set(data) - _MISSING_KEYS)
    if extra:
        raise ValueError(f"{where} has undeclared Missing properties: {extra}")
    if "value" not in data or data["value"] is not None:
        raise ValueError(f"{where} is not a typed Missing envelope")
    why = data.get("reason")
    if why not in contract_codec.VALID_MISSING_REASONS:
        raise ValueError(f"{where} has an unknown Missing reason: {why!r}")
    if reason is not None and why != reason:
        raise ValueError(f"{where} must be Missing({reason}), got {why!r}")
    if "detail" in data and (
        not isinstance(data["detail"], str) or not data["detail"]
    ):
        raise ValueError(f"{where}.detail must be a nonempty string")
    return dict(data)


def _reference(value: Any, where: str) -> ArtifactReference:
    if isinstance(value, ArtifactReference):
        return value
    data = _closed(value, sorted(_REFERENCE_KEYS), where)
    return ArtifactReference.from_dict(data)


def _evidence_ref(value: Any, where: str) -> dict[str, Any]:
    data = _closed(value, sorted(_EVIDENCE_REF_KEYS), where)
    _require_identifier(data["journal_id"], f"{where}.journal_id")
    _require_revision(data["sequence"], f"{where}.sequence", positive=True)
    _require_identifier(data["event_id"], f"{where}.event_id")
    _require_digest(data["event_hash"], f"{where}.event_hash")
    pointer = data["pointer"]
    if not isinstance(pointer, str) or not _POINTER_RE.match(pointer):
        raise ValueError(f"{where}.pointer must be an RFC 6901 JSON Pointer")
    return dict(data)


def _support_refs(value: Any, where: str) -> tuple[dict[str, Any], ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise TypeError(f"{where} must be a sequence of evidence references")
    refs = tuple(
        _evidence_ref(ref, f"{where}[{index}]") for index, ref in enumerate(value)
    )
    if not refs:
        raise ValueError(f"{where} requires at least one evidence reference")
    return refs


def _prefix(value: Any, where: str) -> dict[str, Any]:
    data = _closed(value, sorted(_PREFIX_KEYS), where)
    _require_identifier(data["journal_id"], f"{where}.journal_id")
    _require_revision(data["last_sequence"], f"{where}.last_sequence", positive=True)
    _require_digest(data["head_hash"], f"{where}.head_hash")
    return dict(data)


def _time_point(value: Any, where: str) -> dict[str, Any]:
    data = _closed(value, sorted(_TIME_POINT_KEYS), where)
    _require_identifier(data["clock_id"], f"{where}.clock_id")
    _require_identifier(data["boot_id"], f"{where}.boot_id")
    _require_identifier(data["origin"], f"{where}.origin")
    offset = data["monotonic_offset_ms"]
    if isinstance(offset, bool) or not isinstance(offset, (int, float)):
        raise TypeError(f"{where}.monotonic_offset_ms must be a number")
    if not math.isfinite(float(offset)) or offset < 0:
        raise ValueError(f"{where}.monotonic_offset_ms must be finite and nonnegative")
    annotation = data["utc_annotation"]
    if not isinstance(annotation, str):
        _missing_envelope(annotation, f"{where}.utc_annotation")
    return dict(data)


def _entity(value: Any, where: str) -> dict[str, Any]:
    data = _closed(value, sorted(_ENTITY_KEYS), where)
    if data["entity_type"] != "job":
        raise ValueError(f"{where} must be a job entity key")
    _require_identifier(data["target"], f"{where}.target")
    _require_identifier(data["job_id"], f"{where}.job_id")
    return dict(data)


def _job_vector(value: Any, where: str) -> dict[str, int]:
    data = _closed(value, JOB_DOMAINS, where)
    return {
        domain: _require_revision(data[domain], f"{where}.{domain}")
        for domain in JOB_DOMAINS
    }


# ---------------------------------------------------------------------------
# Strict canonical JSON handling
# ---------------------------------------------------------------------------


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f"duplicate JSON key {key!r} rejected")
        obj[key] = value
    return obj


def _reject_nonfinite_literal(text: str) -> Any:
    raise ValueError(f"nonfinite JSON literal rejected: {text!r}")


def _check_no_bare_null(node: Any, path: str) -> None:
    if node is None:
        raise ValueError(f"bare null at {path}; use a typed Missing envelope")
    if isinstance(node, Mapping):
        if (
            set(node.keys()) <= _MISSING_KEYS
            and "value" in node
            and node.get("value") is None
        ):
            _missing_envelope(node, path)
            return
        for key, item in node.items():
            if not isinstance(key, str):
                raise TypeError(f"non-string JSON key at {path}")
            _check_no_bare_null(item, f"{path}.{key}")
        return
    if isinstance(node, (list, tuple)):
        for index, item in enumerate(node):
            _check_no_bare_null(item, f"{path}[{index}]")
        return
    if isinstance(node, float) and not math.isfinite(node):
        raise ValueError(f"nonfinite number at {path}")


def _strict_load(raw: bytes) -> Any:
    if not isinstance(raw, bytes):
        raise TypeError("archive bytes must be bytes")
    text = raw.decode("utf-8")
    obj = json.loads(
        text,
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_nonfinite_literal,
    )
    _check_no_bare_null(obj, "$")
    return obj


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _same(a: Any, b: Any) -> bool:
    return _canonical_bytes(a) == _canonical_bytes(b)


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _plain(value: Any) -> Any:
    return json.loads(json.dumps(value, sort_keys=True))


# ---------------------------------------------------------------------------
# Value records
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ArchiveRecord:
    """``W.ArchiveRecord``: the complete archived logical row plus its root."""

    record_type: str
    schema_version: str
    root: ArtifactReference
    storage_manifest: dict[str, Any]
    payload_json: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": self.record_type,
            "schema_version": self.schema_version,
            "root": self.root.to_dict(),
            "storage_manifest": _plain(self.storage_manifest),
            "payload_json": _plain(self.payload_json),
        }

    @classmethod
    def from_dict(cls, data: Any) -> "ArchiveRecord":
        raw = _closed(data, sorted(_ARCHIVE_RECORD_KEYS), "ArchiveRecord")
        if raw["record_type"] != ARCHIVE_RECORD_TYPE:
            raise ValueError("ArchiveRecord.record_type must be logical_row_archive")
        if raw["schema_version"] != SCHEMA_VERSION:
            raise ValueError(f"ArchiveRecord.schema_version must be {SCHEMA_VERSION!r}")
        manifest = _require_mapping(raw["storage_manifest"], "ArchiveRecord.storage_manifest")
        payload = _require_mapping(raw["payload_json"], "ArchiveRecord.payload_json")
        return cls(
            record_type=raw["record_type"],
            schema_version=raw["schema_version"],
            root=_reference(raw["root"], "ArchiveRecord.root"),
            storage_manifest=dict(manifest),
            payload_json=dict(payload),
        )


@dataclass(frozen=True, slots=True)
class FetchKeyReplacement:
    """Committed-effect receipt for a crawler fetch-key replacement."""

    record_type: str
    schema_version: str
    replacement_id: str
    entity: dict[str, Any]
    registration_digest: str
    old_crawler: dict[str, Any]
    old_fetch_key: str
    new_crawler: dict[str, Any]
    archive_root: ArtifactReference
    archived_vector: dict[str, int]
    retention_pin_id: str
    commit_ref: dict[str, Any]
    evidence_prefix: dict[str, Any]
    evidence_refs: tuple[dict[str, Any], ...]

    @classmethod
    def from_dict(cls, data: Any) -> "FetchKeyReplacement":
        raw = _closed(data, sorted(_REPLACEMENT_KEYS), "FetchKeyReplacement")
        if raw["record_type"] != REPLACEMENT_RECORD_TYPE:
            raise ValueError(
                "FetchKeyReplacement.record_type must be fetch_key_replacement"
            )
        if raw["schema_version"] != SCHEMA_VERSION:
            raise ValueError(
                f"FetchKeyReplacement.schema_version must be {SCHEMA_VERSION!r}"
            )
        old = _closed(
            raw["old_crawler"], sorted(_OLD_CRAWLER_KEYS), "FetchKeyReplacement.old_crawler"
        )
        old_crawler = {
            "revision": _require_revision(
                old["revision"], "FetchKeyReplacement.old_crawler.revision", positive=True
            ),
            "record_digest": _require_digest(
                old["record_digest"], "FetchKeyReplacement.old_crawler.record_digest"
            ),
        }
        new_crawler = _require_mapping(
            raw["new_crawler"], "FetchKeyReplacement.new_crawler"
        )
        _check_no_bare_null(new_crawler, "FetchKeyReplacement.new_crawler")
        return cls(
            record_type=raw["record_type"],
            schema_version=raw["schema_version"],
            replacement_id=_require_identifier(
                raw["replacement_id"], "FetchKeyReplacement.replacement_id"
            ),
            entity=_entity(raw["entity"], "FetchKeyReplacement.entity"),
            registration_digest=_require_digest(
                raw["registration_digest"], "FetchKeyReplacement.registration_digest"
            ),
            old_crawler=old_crawler,
            old_fetch_key=_require_digest(
                raw["old_fetch_key"], "FetchKeyReplacement.old_fetch_key"
            ),
            new_crawler=dict(new_crawler),
            archive_root=_reference(
                raw["archive_root"], "FetchKeyReplacement.archive_root"
            ),
            archived_vector=_job_vector(
                raw["archived_vector"], "FetchKeyReplacement.archived_vector"
            ),
            retention_pin_id=_require_identifier(
                raw["retention_pin_id"], "FetchKeyReplacement.retention_pin_id"
            ),
            commit_ref=_evidence_ref(
                raw["commit_ref"], "FetchKeyReplacement.commit_ref"
            ),
            evidence_prefix=_prefix(
                raw["evidence_prefix"], "FetchKeyReplacement.evidence_prefix"
            ),
            evidence_refs=_support_refs(
                raw["evidence_refs"], "FetchKeyReplacement.evidence_refs"
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": self.record_type,
            "schema_version": self.schema_version,
            "replacement_id": self.replacement_id,
            "entity": _plain(self.entity),
            "registration_digest": self.registration_digest,
            "old_crawler": _plain(self.old_crawler),
            "old_fetch_key": self.old_fetch_key,
            "new_crawler": _plain(self.new_crawler),
            "archive_root": self.archive_root.to_dict(),
            "archived_vector": _plain(self.archived_vector),
            "retention_pin_id": self.retention_pin_id,
            "commit_ref": _plain(self.commit_ref),
            "evidence_prefix": _plain(self.evidence_prefix),
            "evidence_refs": [_plain(ref) for ref in self.evidence_refs],
        }


@dataclass(frozen=True, slots=True)
class RetentionPinRevision:
    """``W.RetentionPinRevision``: one revision of a retention protection."""

    record_type: str
    schema_version: str
    pin_id: str
    owner_domain: str
    writer_id: str
    revision: int
    previous_revision: int
    dependent: dict[str, Any]
    archive_root: ArtifactReference
    state: str
    release_ref: dict[str, Any]
    evidence_prefix: dict[str, Any]
    evidence_refs: tuple[dict[str, Any], ...]

    @classmethod
    def from_dict(cls, data: Any) -> "RetentionPinRevision":
        raw = _closed(data, sorted(_PIN_KEYS), "RetentionPinRevision")
        if raw["record_type"] != PIN_RECORD_TYPE:
            raise ValueError(
                "RetentionPinRevision.record_type must be archive_retention_pin"
            )
        if raw["schema_version"] != SCHEMA_VERSION:
            raise ValueError(
                f"RetentionPinRevision.schema_version must be {SCHEMA_VERSION!r}"
            )
        dependent = _closed(
            raw["dependent"], sorted(_DEPENDENT_KEYS), "RetentionPinRevision.dependent"
        )
        kind = dependent["kind"]
        if kind not in DEPENDENT_KINDS:
            raise ValueError(f"unknown retention dependent kind: {kind!r}")
        dependent_data = {
            "entity": _entity(
                dependent["entity"], "RetentionPinRevision.dependent.entity"
            ),
            "kind": kind,
            "root_id": _require_identifier(
                dependent["root_id"], "RetentionPinRevision.dependent.root_id"
            ),
        }
        owner_domain = _require_identifier(
            raw["owner_domain"], "RetentionPinRevision.owner_domain"
        )
        archive_root = _reference(
            raw["archive_root"], "RetentionPinRevision.archive_root"
        )
        if archive_root.owner_domain != owner_domain:
            raise ValueError(
                "RetentionPinRevision.archive_root must be retained in the pin's "
                "own persistence domain"
            )
        state = raw["state"]
        if state not in PIN_STATES:
            raise ValueError(f"unknown retention pin state: {state!r}")
        if state == "active":
            release_ref = _missing_envelope(
                raw["release_ref"],
                "RetentionPinRevision.release_ref",
                reason="not_applicable",
            )
        else:
            release_ref = _evidence_ref(
                raw["release_ref"], "RetentionPinRevision.release_ref"
            )
        return cls(
            record_type=raw["record_type"],
            schema_version=raw["schema_version"],
            pin_id=_require_identifier(raw["pin_id"], "RetentionPinRevision.pin_id"),
            owner_domain=owner_domain,
            writer_id=_require_identifier(
                raw["writer_id"], "RetentionPinRevision.writer_id"
            ),
            revision=_require_revision(
                raw["revision"], "RetentionPinRevision.revision", positive=True
            ),
            previous_revision=_require_revision(
                raw["previous_revision"], "RetentionPinRevision.previous_revision"
            ),
            dependent=dependent_data,
            archive_root=archive_root,
            state=state,
            release_ref=release_ref,
            evidence_prefix=_prefix(
                raw["evidence_prefix"], "RetentionPinRevision.evidence_prefix"
            ),
            evidence_refs=_support_refs(
                raw["evidence_refs"], "RetentionPinRevision.evidence_refs"
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": self.record_type,
            "schema_version": self.schema_version,
            "pin_id": self.pin_id,
            "owner_domain": self.owner_domain,
            "writer_id": self.writer_id,
            "revision": self.revision,
            "previous_revision": self.previous_revision,
            "dependent": copy.deepcopy(self.dependent),
            "archive_root": self.archive_root.to_dict(),
            "state": self.state,
            "release_ref": copy.deepcopy(self.release_ref),
            "evidence_prefix": copy.deepcopy(self.evidence_prefix),
            "evidence_refs": [copy.deepcopy(ref) for ref in self.evidence_refs],
        }


@dataclass(frozen=True, slots=True)
class _Expansion:
    """Verified expansion of an archive record from immutable local extents."""

    row: dict[str, Any]
    dependencies: tuple[ArtifactReference, ...]
    linked_roots: tuple[ArtifactReference, ...]
    slot_revisions: dict[str, int]
    documents: dict[str, ArtifactReference]


@dataclass(frozen=True, slots=True)
class _LoadedArchive:
    record: ArchiveRecord
    expansion: _Expansion


# ---------------------------------------------------------------------------
# Immutable extent resolution
# ---------------------------------------------------------------------------


def _resolve_extent(
    channel_id: str, reference: ArtifactReference, where: str
) -> Any:
    """Resolve one complete immutable JSON extent; never contact a peer."""
    try:
        raw = artifact_store.resolve_artifact(channel_id, reference)
    except artifact_store.ArtifactUnavailableError as exc:
        raise IncompleteArchiveError(
            f"{where}: exact bytes for {reference.digest} were never retained "
            "locally; an archive is not a promise to fetch peer state later",
            missing=exc.missing,
        ) from exc
    except artifact_store.ArtifactLostError as exc:
        raise ArchiveIntegrityError(
            f"{where}: retained bytes for {reference.digest} are no longer "
            "available; loss is an integrity incident, not garbage collection",
            missing=exc.missing,
        ) from exc
    except artifact_store.ArtifactAccessDeniedError as exc:
        raise IncompleteArchiveError(
            f"{where}: {reference.digest} is a restricted artifact owned by "
            f"{reference.owner_domain!r}; the archive must import complete local "
            "extents instead of resolving a peer's mutable state",
            missing=getattr(exc, "missing", None),
        ) from exc
    if len(raw) != reference.size_bytes:
        raise ArchiveIntegrityError(
            f"{where}: reference names {reference.size_bytes} bytes but "
            f"{len(raw)} are retained for {reference.digest}"
        )
    try:
        obj = _strict_load(raw)
        canonical = _canonical_bytes(obj)
    except (TypeError, ValueError, UnicodeDecodeError) as exc:
        raise IncompleteArchiveError(
            f"{where}: extent is not a complete canonical JSON record: {exc}"
        ) from exc
    if canonical != raw:
        raise IncompleteArchiveError(
            f"{where}: extent bytes are not canonical; expansion would differ "
            "from the retained bytes"
        )
    try:
        actual = str(contract_codec.canonical_digest(raw))
    except (TypeError, ValueError) as exc:  # pragma: no cover - defensive
        raise ArchiveIntegrityError(f"{where}: extent digest is invalid: {exc}") from exc
    if actual != reference.digest:
        raise ArchiveIntegrityError(
            f"{where}: retained bytes hash to {actual}, not {reference.digest}"
        )
    return obj


# ---------------------------------------------------------------------------
# Manifest expansion (OWD-ARCHIVE)
# ---------------------------------------------------------------------------


def _registration_document(
    document: Any, entity: dict[str, Any], extent_digest: str, where: str
) -> dict[str, Any]:
    data = _closed(document, sorted(_REGISTRATION_KEYS), where)
    if data["record_type"] != REGISTRATION_RECORD_TYPE:
        raise IncompleteArchiveError(
            f"{where}: not a complete entity registration record"
        )
    if data["schema_version"] != SCHEMA_VERSION:
        raise IncompleteArchiveError(f"{where}: unknown registration schema version")
    _require_identifier(data["registration_id"], f"{where}.registration_id")
    if not _same(data["entity"], entity):
        raise IncompleteArchiveError(
            f"{where}: registration entity does not match the archive entity"
        )
    identity = _require_mapping(data["identity"], f"{where}.identity")
    owners = _require_mapping(data["owners"], f"{where}.owners")
    if not identity:
        raise IncompleteArchiveError(f"{where}: registration identity is empty")
    if not {"crawler", "downstream"} <= set(owners):
        raise IncompleteArchiveError(
            f"{where}: registration omits a declared job domain owner"
        )
    _prefix(data["evidence_prefix"], f"{where}.evidence_prefix")
    _support_refs(data["evidence_refs"], f"{where}.evidence_refs")
    if extent_digest != _digest(data):
        raise ArchiveIntegrityError(
            f"{where}: registration extent digest disagrees with its content"
        )
    return dict(data)


def _replacement_lineage(
    document: Mapping[str, Any], where: str
) -> dict[str, Any] | None:
    """Return the validated backward ``ReplacementLink`` of a crawler revision."""
    value = _require_mapping(document.get("value"), f"{where}.value")
    if "replacement_lineage" not in value:
        raise IncompleteArchiveError(
            f"{where}: crawler revision omits replacement_lineage; a crawler-only "
            "snapshot is not a complete archived row"
        )
    lineage = value["replacement_lineage"]
    if isinstance(lineage, Mapping) and "value" in lineage and lineage.get("value") is None:
        _missing_envelope(lineage, f"{where}.value.replacement_lineage")
        return None
    data = _closed(
        lineage, sorted(_LINEAGE_KEYS), f"{where}.value.replacement_lineage"
    )
    _require_identifier(
        data["replacement_id"], f"{where}.value.replacement_lineage.replacement_id"
    )
    _require_revision(
        data["prior_crawler_revision"],
        f"{where}.value.replacement_lineage.prior_crawler_revision",
        positive=True,
    )
    root = _reference(
        data["archive_root"], f"{where}.value.replacement_lineage.archive_root"
    )
    return {
        "replacement_id": data["replacement_id"],
        "prior_crawler_revision": data["prior_crawler_revision"],
        "archive_root": root,
    }


def _crawler_fetch_key(document: Mapping[str, Any], where: str) -> str:
    value = _require_mapping(document.get("value"), f"{where}.value")
    acquisition = _require_mapping(value.get("acquisition"), f"{where}.value.acquisition")
    return _require_digest(
        acquisition.get("fetch_key"), f"{where}.value.acquisition.fetch_key"
    )


def _owned_document(
    document: Any,
    domain: str,
    entity: dict[str, Any],
    revision: int,
    registration_digest: str,
    extent_digest: str,
    where: str,
) -> dict[str, Any]:
    data = _closed(document, sorted(_OWNED_DOCUMENT_KEYS), where)
    if data["record_type"] != OWNED_REVISION_RECORD_TYPE:
        raise IncompleteArchiveError(
            f"{where}: archived {domain} slot is not a complete owned revision"
        )
    if data["schema_version"] != SCHEMA_VERSION:
        raise IncompleteArchiveError(f"{where}: unknown owned-revision schema version")
    if not _same(data["entity"], entity):
        raise IncompleteArchiveError(f"{where}: archived document entity mismatch")
    if data["registration_digest"] != registration_digest:
        raise IncompleteArchiveError(
            f"{where}: archived document names a different registration"
        )
    if data["domain"] != domain:
        raise IncompleteArchiveError(
            f"{where}: archived document domain {data['domain']!r} is not {domain!r}"
        )
    if data["owner_domain"] != DOMAIN_OWNERS[domain]:
        raise IncompleteArchiveError(
            f"{where}: archived document owner domain must be {DOMAIN_OWNERS[domain]!r}"
        )
    _require_identifier(data["writer_id"], f"{where}.writer_id")
    if _require_revision(data["revision"], f"{where}.revision", positive=True) != revision:
        raise IncompleteArchiveError(
            f"{where}: archived document revision disagrees with its manifest slot"
        )
    if data["previous_revision"] != revision - 1:
        raise IncompleteArchiveError(
            f"{where}: archived revision is not a contiguous complete snapshot"
        )
    _prefix(data["evidence_prefix"], f"{where}.evidence_prefix")
    _support_refs(data["evidence_refs"], f"{where}.evidence_refs")
    value = _require_mapping(data["value"], f"{where}.value")
    if not value:
        raise IncompleteArchiveError(f"{where}: archived domain value is empty")
    _check_no_bare_null(value, f"{where}.value")
    if domain == "crawler":
        _crawler_fetch_key(data, where)
        _replacement_lineage(data, where)
    if extent_digest != _digest(data):
        raise ArchiveIntegrityError(
            f"{where}: archived document digest disagrees with its content"
        )
    return dict(data)


def _seal_point(
    seal: Any, slot_revisions: Mapping[str, int], where: str
) -> dict[str, Any]:
    data = _closed(seal, sorted(_SEAL_KEYS), where)
    _require_identifier(data["seal_id"], f"{where}.seal_id")
    if data["name"] not in JOB_SEAL_NAMES:
        raise IncompleteArchiveError(f"{where}: unknown job seal name")
    if data["name"] != "fetch_key_replacement":
        raise IncompleteArchiveError(
            f"{where}: a replacement archive must be cut at the "
            "fetch_key_replacement seal"
        )
    _require_identifier(data["view_id"], f"{where}.view_id")
    versions = _job_vector(data["versions"], f"{where}.versions")
    for domain in JOB_DOMAINS:
        if versions[domain] != slot_revisions[domain]:
            raise IncompleteArchiveError(
                f"{where}: seal vector {domain}={versions[domain]} disagrees with "
                f"the archived slot revision {slot_revisions[domain]}"
            )
    _time_point(data["sealed_at"], f"{where}.sealed_at")
    _prefix(data["input_prefix"], f"{where}.input_prefix")
    _support_refs(data["evidence_refs"], f"{where}.evidence_refs")
    return dict(data)


def _expand_archive(channel_id: str, record: ArchiveRecord) -> _Expansion:
    """Reconstruct the exact complete previous row from local extents."""
    manifest = _closed(
        record.storage_manifest, sorted(_MANIFEST_KEYS), "storage_manifest"
    )
    if manifest["encoding"] != ARCHIVE_ENCODING:
        raise IncompleteArchiveError(
            "storage_manifest: unknown archive encoding; only immutable local "
            f"extents ({ARCHIVE_ENCODING}) are accepted"
        )
    if manifest["schema_version"] != SCHEMA_VERSION:
        raise IncompleteArchiveError("storage_manifest: unknown schema version")
    entity = _entity(manifest["entity"], "storage_manifest.entity")
    registration_ref = _reference(
        manifest["registration"], "storage_manifest.registration"
    )
    registration_doc = _registration_document(
        _resolve_extent(channel_id, registration_ref, "storage_manifest.registration"),
        entity,
        registration_ref.digest,
        "storage_manifest.registration",
    )

    domains_raw = _require_mapping(manifest["domains"], "storage_manifest.domains")
    if set(domains_raw) != set(JOB_DOMAINS):
        raise IncompleteArchiveError(
            "storage_manifest.domains: a job archive must declare exactly "
            f"{list(JOB_DOMAINS)}; got {sorted(domains_raw)}"
        )

    dependencies: list[ArtifactReference] = [registration_ref]
    linked_roots: list[ArtifactReference] = []
    slot_revisions: dict[str, int] = {}
    manifest_slots: dict[str, Any] = {}
    row_slots: dict[str, Any] = {}
    documents: dict[str, ArtifactReference] = {}

    for domain in JOB_DOMAINS:
        where = f"storage_manifest.domains.{domain}"
        slot = _require_mapping(domains_raw[domain], where)
        keys = set(slot)
        if keys == set(_MANIFEST_SLOT_UNPUBLISHED_KEYS):
            revision = _require_revision(
                slot["revision"], f"{where}.revision"
            )
            if revision != 0:
                raise IncompleteArchiveError(
                    f"{where}: an unpublished slot must name revision 0"
                )
            missing = _missing_envelope(slot["value"], f"{where}.value")
            slot_revisions[domain] = 0
            manifest_slots[domain] = {"revision": 0, "value": missing}
            row_slots[domain] = {"revision": 0, "value": missing}
            continue
        if keys != set(_MANIFEST_SLOT_PUBLISHED_KEYS):
            raise IncompleteArchiveError(
                f"{where}: a domain slot is either a complete PublishedDomain "
                "(revision, document, publication_ref) or a typed UnpublishedDomain; "
                f"got {sorted(keys)}; hash lists, diffs, and locators are not archives"
            )
        revision = _require_revision(
            slot["revision"], f"{where}.revision", positive=True
        )
        document_ref = _reference(slot["document"], f"{where}.document")
        publication_ref = _evidence_ref(
            slot["publication_ref"], f"{where}.publication_ref"
        )
        document = _owned_document(
            _resolve_extent(channel_id, document_ref, f"{where}.document"),
            domain,
            entity,
            revision,
            registration_ref.digest,
            document_ref.digest,
            f"{where}.document",
        )
        slot_revisions[domain] = revision
        documents[domain] = document_ref
        manifest_slots[domain] = {
            "revision": revision,
            "document": document_ref.to_dict(),
            "publication_ref": publication_ref,
        }
        # PublishedDomain embeds the complete verified snapshot.
        row_slots[domain] = {
            **manifest_slots[domain],
            "snapshot": document,
        }
        dependencies.append(document_ref)
        if domain == "crawler":
            lineage = _replacement_lineage(document, f"{where}.document")
            if lineage is not None:
                linked_roots.append(lineage["archive_root"])

    seal = _seal_point(manifest["seal_point"], slot_revisions, "storage_manifest.seal_point")

    payload = _closed(record.payload_json, sorted(_ROW_KEYS), "payload_json")
    if payload["record_type"] != LOGICAL_ROW_RECORD_TYPE:
        raise IncompleteArchiveError("payload_json: not a complete logical row")
    if payload["schema_version"] != SCHEMA_VERSION:
        raise IncompleteArchiveError("payload_json: unknown logical-row schema version")
    if not _same(payload["entity"], entity):
        raise IncompleteArchiveError("payload_json: entity disagrees with the manifest")
    if payload["registration_digest"] != registration_ref.digest:
        raise IncompleteArchiveError(
            "payload_json: registration digest disagrees with the archive manifest"
        )
    if not _same(payload["registration"], registration_doc):
        raise IncompleteArchiveError(
            "payload_json: registration is not the complete verified registration"
        )
    if not _same(payload["seal_point"], seal):
        raise IncompleteArchiveError(
            "payload_json: seal point disagrees with the archive manifest"
        )
    if not _same(payload["domains"], row_slots):
        raise IncompleteArchiveError(
            "payload_json: expansion differs from the archived row; the archive "
            "is a diff, crawler-only row, hash list, or peer lookup, not the "
            "complete previous logical row"
        )

    return _Expansion(
        row=dict(payload),
        dependencies=tuple(dependencies),
        linked_roots=tuple(linked_roots),
        slot_revisions=slot_revisions,
        documents=documents,
    )


def _load_archive(channel_id: str, root: Any, *, where: str = "archive_root") -> _LoadedArchive:
    reference = _reference(root, where)
    obj = _resolve_extent(channel_id, reference, where)
    try:
        record = ArchiveRecord.from_dict(obj)
        manifest_bytes = _canonical_bytes(record.storage_manifest)
        expected_root = str(contract_codec.canonical_digest(manifest_bytes))
        if record.root.digest != expected_root or record.root.size_bytes != len(manifest_bytes):
            raise ArchiveIntegrityError(
                f"{where}: ArchiveRecord.root must hash the canonical storage manifest "
                "bytes, not the expanded wrapper"
            )
        expansion = _expand_archive(channel_id, record)
    except IncompleteArchiveError:
        raise
    except ArchiveRetentionError:
        raise
    except (TypeError, ValueError) as exc:
        raise IncompleteArchiveError(
            f"{where}: not a complete ArchiveRecord: {exc}"
        ) from exc
    return _LoadedArchive(record=record, expansion=expansion)


def _closure(
    channel_id: str, root: Any, *, visited: set[str] | None = None
) -> set[str]:
    """Every digest a pinned archive root reaches, following backward links."""
    reference = _reference(root, "archive_root")
    if visited is None:
        visited = set()
    if reference.digest in visited:
        return set()
    visited.add(reference.digest)
    loaded = _load_archive(channel_id, reference)
    digests = {reference.digest}
    digests.update(dep.digest for dep in loaded.expansion.dependencies)
    for linked in loaded.expansion.linked_roots:
        digests |= _closure(channel_id, linked, visited=visited)
    return digests


# ---------------------------------------------------------------------------
# Journal citation helpers
# ---------------------------------------------------------------------------


class _CitationError(ValueError):
    """A journal citation does not resolve to the claimed event or value."""


def _pointer_resolves(document: Any, pointer: str) -> bool:
    if pointer == "":
        return True
    node = document
    for raw in pointer.split("/")[1:]:
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(node, Mapping):
            if token not in node:
                return False
            node = node[token]
        elif isinstance(node, (list, tuple)):
            if token == "-" or not token.isdigit():
                return False
            if len(token) > 1 and token[0] == "0":
                return False
            index = int(token)
            if index >= len(node):
                return False
            node = node[index]
        else:
            return False
    return True


def _events_for_prefix(channel_id: str, prefix: dict[str, Any]) -> tuple[Any, ...]:
    try:
        validated = _prefix(prefix, "evidence_prefix")
        journal_prefix = evidence_journal.JournalPrefix(**validated)
    except (TypeError, ValueError) as exc:
        raise _CitationError(f"evidence prefix is not a valid JournalPrefix: {exc}") from exc
    try:
        events = evidence_journal.read_prefix(channel_id, journal_prefix)
    except evidence_journal.EvidenceJournalError as exc:
        raise _CitationError(f"evidence prefix does not verify: {exc}") from exc
    if not events:
        raise _CitationError("evidence prefix contains no events")
    return events


def _fresh_events(channel_id: str, prefix: dict[str, Any]) -> tuple[Any, ...]:
    """Verify the declared cut, then return the journal's current full prefix."""
    events = _events_for_prefix(channel_id, prefix)
    journal_id = events[0].journal_id
    try:
        head = evidence_journal.journal_head(channel_id, journal_id)
        return evidence_journal.read_prefix(channel_id, head)
    except evidence_journal.EvidenceJournalError as exc:
        raise _CitationError(f"retention journal head is unavailable: {exc}") from exc


def _payload_data(envelope: Any) -> Mapping[str, Any]:
    payload = envelope.payload
    data = payload.get("data") if isinstance(payload, Mapping) else None
    return data if isinstance(data, Mapping) else {}


def _resolve_local_ref(
    events: Sequence[Any], ref: Mapping[str, Any], where: str
) -> Any | None:
    """Resolve a citation the named journal owns; foreign citations are opaque."""
    data = _evidence_ref(ref, where)
    journal_id = events[0].journal_id
    if data["journal_id"] != journal_id:
        return None
    sequence = data["sequence"]
    if sequence > len(events):
        raise _CitationError(
            f"{where}: sequence {sequence} is outside the acknowledged prefix"
        )
    target = events[sequence - 1]
    if target.journal_sequence != sequence:
        raise _CitationError(f"{where}: prefix is not contiguous at {sequence}")
    if target.event_id != data["event_id"]:
        raise _CitationError(
            f"{where}: event id {data['event_id']!r} does not name sequence {sequence}"
        )
    if target.event_hash != data["event_hash"]:
        raise _CitationError(
            f"{where}: event hash does not match sequence {sequence}"
        )
    if not _pointer_resolves(target.to_dict(), data["pointer"]):
        raise _CitationError(
            f"{where}: pointer {data['pointer']!r} does not resolve at {sequence}"
        )
    return target


def _ref_matches(ref: Mapping[str, Any], envelope: Any) -> bool:
    return (
        ref["journal_id"] == envelope.journal_id
        and ref["sequence"] == envelope.journal_sequence
        and ref["event_id"] == envelope.event_id
        and ref["event_hash"] == envelope.event_hash
    )


def _next_producer_sequence(descriptor: Any, events: Sequence[Any]) -> Any:
    if not descriptor.sequence_required:
        return evidence_journal.NOT_OBSERVED
    highest = 0
    for event in events:
        if event.producer_id != descriptor.producer_id:
            continue
        value = event.producer_sequence
        if isinstance(value, int) and not isinstance(value, bool) and value > highest:
            highest = value
    return highest + 1


# ---------------------------------------------------------------------------
# Replacement verification (OWD-REPLACE, OWD-SEAL)
# ---------------------------------------------------------------------------


def _new_crawler_document(
    receipt: FetchKeyReplacement, old_revision: int
) -> tuple[dict[str, Any], str, dict[str, Any]]:
    where = "FetchKeyReplacement.new_crawler"
    data = _closed(receipt.new_crawler, sorted(_OWNED_DOCUMENT_KEYS), where)
    if data["record_type"] != OWNED_REVISION_RECORD_TYPE:
        raise ReplacementRejectedError(
            "new_crawler must be a complete owned crawler revision, not a diff"
        )
    if data["schema_version"] != SCHEMA_VERSION:
        raise ReplacementRejectedError("new_crawler: unknown schema version")
    if not _same(data["entity"], receipt.entity):
        raise ReplacementRejectedError("new_crawler: entity does not match the receipt")
    if data["registration_digest"] != receipt.registration_digest:
        raise ReplacementRejectedError(
            "new_crawler: registration digest does not match the receipt"
        )
    if data["domain"] != "crawler":
        raise ReplacementRejectedError("new_crawler: domain must be crawler")
    if data["owner_domain"] != DOMAIN_OWNERS["crawler"]:
        raise ReplacementRejectedError(
            "new_crawler: crawler revisions belong to job.crawler"
        )
    _require_identifier(data["writer_id"], f"{where}.writer_id")
    revision = _require_revision(data["revision"], f"{where}.revision", positive=True)
    if revision != old_revision + 1:
        raise ReplacementRejectedError(
            "new_crawler: a replacement advances the crawler revision by exactly one"
        )
    if data["previous_revision"] != old_revision:
        raise ReplacementRejectedError(
            "new_crawler: previous_revision must name the archived crawler revision"
        )
    _prefix(data["evidence_prefix"], f"{where}.evidence_prefix")
    _support_refs(data["evidence_refs"], f"{where}.evidence_refs")
    value = _require_mapping(data["value"], f"{where}.value")
    if not value:
        raise ReplacementRejectedError(
            "new_crawler: a complete crawler revision requires a value"
        )
    _check_no_bare_null(value, f"{where}.value")
    new_fetch_key = _crawler_fetch_key(data, where)
    if new_fetch_key == receipt.old_fetch_key:
        raise ReplacementRejectedError(
            "same fetch key is an acquisition no-op, not a replacement; a "
            "different response under the same key is new observation"
        )
    lineage = _replacement_lineage(data, where)
    if lineage is None:
        raise ReplacementRejectedError(
            "new_crawler: a replacement revision requires a backward "
            "ReplacementLink, not Missing(not_applicable)"
        )
    if lineage["replacement_id"] != receipt.replacement_id:
        raise ReplacementRejectedError(
            "new_crawler: replacement link names a different replacement"
        )
    if lineage["prior_crawler_revision"] != old_revision:
        raise ReplacementRejectedError(
            "new_crawler: replacement link does not name the prior crawler revision"
        )
    if lineage["archive_root"].to_dict() != receipt.archive_root.to_dict():
        raise ReplacementRejectedError(
            "new_crawler: replacement link does not name this archive root"
        )
    return dict(data), new_fetch_key, lineage


def _check_archived_cut(
    receipt: FetchKeyReplacement, loaded: _LoadedArchive
) -> None:
    row = loaded.expansion.row
    if not _same(row["entity"], receipt.entity):
        raise ReplacementRejectedError(
            "replacement entity does not match the archived logical row"
        )
    if row["registration_digest"] != receipt.registration_digest:
        raise ReplacementRejectedError(
            "replacement registration identity does not match the archived row"
        )
    if not _same(receipt.archived_vector, row["seal_point"]["versions"]):
        raise ReplacementRejectedError(
            "archived_vector must equal the seal vector of the archived cut"
        )
    slot = row["domains"]["crawler"]
    if slot["revision"] < 1:
        raise IncompleteArchiveError(
            "replacement archive has no published crawler slot to replace"
        )
    crawler_document = slot["snapshot"]
    crawler_extent = loaded.expansion.documents["crawler"]
    if receipt.old_crawler["revision"] != crawler_document["revision"]:
        raise ReplacementRejectedError(
            "old_crawler pin does not name the archived crawler revision"
        )
    if receipt.old_crawler["record_digest"] != crawler_extent.digest:
        raise ReplacementRejectedError(
            "old_crawler record digest does not name the archived crawler document"
        )
    archived_fetch_key = _crawler_fetch_key(crawler_document, "payload_json.domains.crawler")
    if archived_fetch_key != receipt.old_fetch_key:
        raise ReplacementRejectedError(
            "old_fetch_key does not match the archived crawler acquisition identity"
        )


def _check_commit_event(
    receipt: FetchKeyReplacement, events: Sequence[Any]
) -> Any:
    envelope = _resolve_local_ref(events, receipt.commit_ref, "commit_ref")
    if envelope is None:
        raise _CitationError(
            "commit_ref must cite an event of the receipt's own journal prefix"
        )
    if envelope.event_kind != REPLACEMENT_EVENT_KIND:
        raise _CitationError(
            f"commit_ref names {envelope.event_kind!r}, not a committed "
            f"replacement ({REPLACEMENT_EVENT_KIND!r})"
        )
    data = _payload_data(envelope)
    expected = {
        "record_type": REPLACEMENT_RECORD_TYPE,
        "replacement_id": receipt.replacement_id,
        "registration_digest": receipt.registration_digest,
        "old_crawler_revision": receipt.old_crawler["revision"],
        "old_crawler_record_digest": receipt.old_crawler["record_digest"],
        "old_fetch_key": receipt.old_fetch_key,
        "new_crawler_revision": receipt.new_crawler["revision"],
        "new_crawler_previous_revision": receipt.new_crawler["previous_revision"],
        "archive_root_digest": receipt.archive_root.digest,
        "retention_pin_id": receipt.retention_pin_id,
    }
    for key, value in expected.items():
        if data.get(key) != value:
            raise _CitationError(
                f"the journaled replacement commit disagrees with the receipt: {key}"
            )
    if not _same(data.get("entity"), receipt.entity):
        raise _CitationError(
            "the journaled replacement commit names a different entity"
        )
    if not _same(data.get("archived_vector"), receipt.archived_vector):
        raise _CitationError(
            "the journaled replacement commit names a different archived vector"
        )
    if data.get("new_fetch_key") != _crawler_fetch_key(
        _require_mapping(receipt.new_crawler, "new_crawler"), "new_crawler"
    ):
        raise _CitationError(
            "the journaled replacement commit names a different new fetch key"
        )
    return envelope


def _check_active_pin(
    receipt: FetchKeyReplacement, events: Sequence[Any], commit_envelope: Any
) -> None:
    latest: tuple[Any, Mapping[str, Any]] | None = None
    for envelope in events:
        if envelope.journal_sequence >= commit_envelope.journal_sequence:
            break
        if envelope.event_kind != PIN_EVENT_KIND:
            continue
        data = _payload_data(envelope)
        if data.get("record_type") != PIN_RECORD_TYPE:
            continue
        if data.get("pin_id") != receipt.retention_pin_id:
            continue
        latest = (envelope, data)
    if latest is None:
        raise _CitationError(
            "no journaled retention-pin revision precedes the replacement commit; "
            "the replacement is not protected"
        )
    envelope, data = latest
    if data.get("state") != "active":
        raise _CitationError(
            "the named retention pin is not active at the replacement cut"
        )
    if not _same(data.get("archive_root"), receipt.archive_root.to_dict()):
        raise _CitationError(
            "the active retention pin protects a different archive root"
        )
    dependent = data.get("dependent")
    if not isinstance(dependent, Mapping) or not _same(
        dependent.get("entity"), receipt.entity
    ):
        raise _CitationError(
            "the active retention pin protects a different logical entity"
        )
    if dependent.get("kind") not in DEPENDENT_KINDS:
        raise _CitationError("the active retention pin has an unknown dependent kind")
    if data.get("owner_domain") != commit_envelope.owner_domain:
        raise _CitationError(
            "the active retention pin belongs to a different persistence domain "
            "than the journal that received the replacement commit"
        )
    if not any(_ref_matches(ref, envelope) for ref in receipt.evidence_refs):
        raise _CitationError(
            "evidence_refs must cite the active retention-pin revision that "
            "protects the replacement archive root"
        )


def _check_support_refs(receipt: FetchKeyReplacement, events: Sequence[Any]) -> None:
    for index, ref in enumerate(receipt.evidence_refs):
        _resolve_local_ref(events, ref, f"evidence_refs[{index}]")


def verify_replacement(
    channel_id: str, replacement: FetchKeyReplacement
) -> ArchiveRecord:
    """Verify received crawler replacement evidence without assuming its authority.

    Returns the complete :class:`ArchiveRecord` for the prior logical row.  A
    changed fetch key without that complete archive, a same-key no-op, a stale
    or mismatched cut, a peer-state locator, or an unprotected root is rejected
    with an explicit error.  The caller's channel must be an authenticated
    channel of the archive's persistence domain; no peer-owned write is made.
    """
    if not isinstance(channel_id, str) or not channel_id:
        raise ReplacementRejectedError("channel_id must be a nonempty identifier")
    try:
        receipt = (
            replacement
            if isinstance(replacement, FetchKeyReplacement)
            else FetchKeyReplacement.from_dict(replacement)
        )
    except (TypeError, ValueError) as exc:
        raise ReplacementRejectedError(f"invalid FetchKeyReplacement: {exc}") from exc

    loaded = _load_archive(channel_id, receipt.archive_root)
    _check_archived_cut(receipt, loaded)
    _new_crawler_document(receipt, receipt.old_crawler["revision"])

    # Every transitive dependency of the pinned archive must be present now;
    # a reclaimed dependency is an integrity incident, never a peer lookup.
    for linked in loaded.expansion.linked_roots:
        _closure(channel_id, linked, visited={receipt.archive_root.digest})

    try:
        events = _events_for_prefix(channel_id, receipt.evidence_prefix)
        commit_envelope = _check_commit_event(receipt, events)
        _check_active_pin(receipt, events, commit_envelope)
        _check_support_refs(receipt, events)
    except _CitationError as exc:
        raise ReplacementRejectedError(str(exc)) from exc
    return loaded.record


# ---------------------------------------------------------------------------
# Retention revisions (OWD-RETENTION, OWD-LOCAL-COMMIT)
# ---------------------------------------------------------------------------


_OWNER_LOCKS: dict[str, threading.RLock] = {}
_OWNER_LOCKS_GUARD = threading.Lock()


def _owner_lock(owner_domain: str) -> threading.RLock:
    with _OWNER_LOCKS_GUARD:
        lock = _OWNER_LOCKS.get(owner_domain)
        if lock is None:
            lock = threading.RLock()
            _OWNER_LOCKS[owner_domain] = lock
        return lock


def _write_operation(owner_domain: str) -> str:
    # Data-domain writers hold exactly one authoritative write grant: <axis>.write.
    return f"{owner_domain}.write"


def _differs(first: Any, second: Any) -> bool:
    try:
        return not _same(first, second)
    except (TypeError, ValueError):
        return True


def _latest_pin_event(
    events: Sequence[Any], pin_id: str
) -> tuple[Any, Mapping[str, Any]] | None:
    latest: tuple[Any, Mapping[str, Any]] | None = None
    for envelope in events:
        if envelope.event_kind != PIN_EVENT_KIND:
            continue
        data = _payload_data(envelope)
        if data.get("record_type") != PIN_RECORD_TYPE:
            continue
        if data.get("pin_id") != pin_id:
            continue
        latest = (envelope, data)
    return latest


def _check_pin_lineage(
    pin: RetentionPinRevision,
    previous: tuple[Any, Mapping[str, Any]] | None,
) -> None:
    if previous is None:
        if pin.revision != 1 or pin.previous_revision != 0:
            raise RetentionRejectedError(
                "a pin's first journaled revision is 1 with previous_revision 0"
            )
        if pin.state != "active":
            raise RetentionRejectedError(
                "a retention pin's initial revision is active; release requires "
                "a journaled retirement"
            )
        return
    _, data = previous
    recorded_revision = data.get("revision")
    if isinstance(recorded_revision, bool) or not isinstance(recorded_revision, int):
        raise ArchiveIntegrityError(
            "the journaled retention revision has no valid revision number"
        )
    if data.get("state") == "released":
        raise RetentionRejectedError(
            "a released retention pin is terminal; later revisions cannot "
            "revive or re-release it"
        )
    if pin.previous_revision != recorded_revision or pin.revision != recorded_revision + 1:
        raise RetentionRejectedError(
            "retention revision must advance exactly one step from the journaled "
            "pin revision"
        )
    if data.get("archive_root_digest") != pin.archive_root.digest:
        raise RetentionRejectedError(
            "archive_root never changes under a pin ID"
        )
    if _differs(data.get("dependent"), pin.dependent):
        raise RetentionRejectedError(
            "dependent never changes under a pin ID"
        )
    if data.get("owner_domain") != pin.owner_domain or data.get("writer_id") != pin.writer_id:
        raise RetentionRejectedError(
            "pin owner/writer identity never changes under a pin ID"
        )


def _check_retirement_evidence(
    pin: RetentionPinRevision, events: Sequence[Any]
) -> None:
    envelope = _resolve_local_ref(events, pin.release_ref, "release_ref")
    if envelope is None:
        raise RetentionRejectedError(
            "release_ref must cite evidenced retirement in the retention journal"
        )
    if envelope.event_kind != RETIREMENT_EVENT_KIND:
        raise RetentionRejectedError(
            f"release_ref names {envelope.event_kind!r}, not retirement evidence "
            f"({RETIREMENT_EVENT_KIND!r})"
        )
    data = _payload_data(envelope)
    if data.get("record_type") != RETIREMENT_RECORD_TYPE:
        raise RetentionRejectedError(
            "release_ref does not name a retention retirement record"
        )
    if data.get("pin_id") != pin.pin_id:
        raise RetentionRejectedError(
            "release_ref evidences retirement of a different pin"
        )
    if data.get("archive_root_digest") != pin.archive_root.digest:
        raise RetentionRejectedError(
            "release_ref evidences retirement of a different archive root"
        )
    if not any(_ref_matches(ref, envelope) for ref in pin.evidence_refs):
        raise RetentionRejectedError(
            "evidence_refs must cite the retirement evidence backing the release"
        )


def _assert_not_reachable(
    channel_id: str, pin: RetentionPinRevision, events: Sequence[Any]
) -> None:
    target = pin.archive_root.digest
    latest: dict[str, Mapping[str, Any]] = {}
    for envelope in events:
        if envelope.event_kind != PIN_EVENT_KIND:
            continue
        data = _payload_data(envelope)
        if data.get("record_type") != PIN_RECORD_TYPE:
            continue
        pin_id = data.get("pin_id")
        if isinstance(pin_id, str):
            latest[pin_id] = data
    for pin_id, data in latest.items():
        if pin_id == pin.pin_id:
            continue
        if data.get("state") != "active":
            continue
        other = data.get("archive_root")
        if not isinstance(other, Mapping):
            raise ArchiveIntegrityError(
                "an active retention pin's journaled archive root is not resolvable"
            )
        other_root = _reference(other, "journaled archive_root")
        if target in _closure(channel_id, other_root):
            raise RetentionStillReachableError(
                f"archive root {target} is still reachable from active pin "
                f"{pin_id!r}; release would drop a transitive dependency "
                "another retained root needs"
            )


def _pin_event_data(pin: RetentionPinRevision) -> dict[str, Any]:
    return {
        "record_type": PIN_RECORD_TYPE,
        "pin_id": pin.pin_id,
        "owner_domain": pin.owner_domain,
        "writer_id": pin.writer_id,
        "revision": pin.revision,
        "previous_revision": pin.previous_revision,
        "dependent": {
            "entity": copy.deepcopy(pin.dependent["entity"]),
            "kind": pin.dependent["kind"],
            "root_id": pin.dependent["root_id"],
        },
        "archive_root": pin.archive_root.to_dict(),
        "archive_root_digest": pin.archive_root.digest,
        "state": pin.state,
    }


def revise_retention(
    channel_id: str, pin: RetentionPinRevision
) -> ArtifactReference:
    """Commit one retention-pin revision as an owner-local journal effect.

    The archive's complete expansion is re-verified before the revision, so a
    reclaimed dependency fails retention instead of being replaced by peer
    state.  Release requires journaled retirement evidence and is rejected
    while any other active pin still reaches the root directly or through a
    retained later archive's backward link.  Returns the retained state
    artifact for the committed pin revision.
    """
    if not isinstance(channel_id, str) or not channel_id:
        raise RetentionRejectedError("channel_id must be a nonempty identifier")
    try:
        revision = (
            pin if isinstance(pin, RetentionPinRevision) else RetentionPinRevision.from_dict(pin)
        )
    except (TypeError, ValueError) as exc:
        raise RetentionRejectedError(f"invalid RetentionPinRevision: {exc}") from exc

    try:
        descriptor = access_policy.authorize(
            channel_id, _write_operation(revision.owner_domain), revision.pin_id
        )
    except access_policy.AuthorizationError as exc:
        raise RetentionAuthorityError(
            f"retention revisions require the registered writer for "
            f"{revision.owner_domain!r}: {exc}"
        ) from exc
    if descriptor.owner_domain != revision.owner_domain:
        raise RetentionAuthorityError(
            "the authenticated channel is not in the archive's persistence domain"
        )
    if descriptor.producer_id != revision.writer_id:
        raise RetentionAuthorityError(
            "pin.writer_id does not match the registered retention authority"
        )

    with _owner_lock(revision.owner_domain):
        try:
            events = _fresh_events(channel_id, revision.evidence_prefix)
        except _CitationError as exc:
            raise RetentionRejectedError(str(exc)) from exc

        previous = _latest_pin_event(events, revision.pin_id)
        _check_pin_lineage(revision, previous)
        if revision.state == "released":
            _check_retirement_evidence(revision, events)
            _assert_not_reachable(channel_id, revision, events)

        loaded = _load_archive(channel_id, revision.archive_root)
        if not _same(loaded.expansion.row["entity"], revision.dependent["entity"]):
            raise RetentionRejectedError(
                "pin dependent entity does not match the archived logical row"
            )
        # Every transitive dependency of this pinned root must be intact.
        for linked in loaded.expansion.linked_roots:
            _closure(channel_id, linked, visited={revision.archive_root.digest})

        try:
            for index, ref in enumerate(revision.evidence_refs):
                _resolve_local_ref(events, ref, f"evidence_refs[{index}]")
        except _CitationError as exc:
            raise RetentionRejectedError(str(exc)) from exc

        state_ref = artifact_store.retain_artifact(
            channel_id,
            revision.owner_domain,
            "application/json",
            _canonical_bytes(revision.to_dict()),
            "restricted",
        )
        submission = evidence_journal.EventSubmission(
            producer_sequence=_next_producer_sequence(descriptor, events),
            event_kind=PIN_EVENT_KIND,
            event_schema_version=EVENT_SCHEMA_VERSION,
            occurred_at=evidence_journal.NOT_OBSERVED,
            payload=evidence_journal.EvidencePayload(
                data=_pin_event_data(revision),
                measurements=(),
                evidence_refs=tuple(copy.deepcopy(list(revision.evidence_refs))),
                artifact_refs=(revision.archive_root,),
            ),
        )
        committed = evidence_journal.commit_effect(
            channel_id,
            revision.owner_domain,
            revision.pin_id,
            f"retention_{revision.pin_id}_rev_{revision.revision}",
            revision.previous_revision,
            state_ref,
            (submission,),
        )
        if committed.journal_id != revision.evidence_prefix["journal_id"]:
            raise ArchiveRetentionError(
                "retention journal changed underneath the owner-local commit"
            )
        return state_ref

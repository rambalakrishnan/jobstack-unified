"""read_publications: durable read-view publications and LogicalRow seals (tier 4).

Implements the owner-separated read view rules (``OWD-PUBLISH``, ``OWD-VIEW``,
``OWD-SEAL``, ``LIFE-PUBLICATION``) and seam mapping 5.1 / 15.1 / 15.2 for job
entities:

* Owner durability and read-view visibility are different events.  This module
  never writes a source domain and never makes an owner acknowledgement wait
  for it.
* A publication is installed only after its complete immutable document bytes
  were resolved, validated as the exact canonical ``owned_domain_revision``,
  and retained locally.  Only then does the view's domain pointer advance, as
  bounded metadata work committed through the owner-local journal.
* A view pointer only moves forward.  A reordered delivery is rejected, a
  conflicting body under the same revision identity is rejected, and an
  identical retry returns the already issued receipt without a new effect.
* A seal pins the locally installed complete publications.  It does not read
  another owner's journal, does not require global synchronous freshness, and
  does not freeze future writes.  The seal-selection event is inside the row's
  input prefix; the row's own registration event is not.

Cross-owner evidence (registration support, owner evidence prefixes) is
structurally validated here and never read across the owner boundary.
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
import time
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

__all__ = [
    "SCHEMA_VERSION",
    "PUBLISHER_AXIS",
    "POINTER_OPERATION",
    "SEAL_OPERATION",
    "INSTALL_EVENT_KIND",
    "SEAL_EVENT_KIND",
    "ROW_EVENT_KIND",
    "EVENT_SCHEMA_VERSION",
    "CLOCK_ID",
    "BOOT_ID",
    "CLOCK_ORIGIN",
    "JOB_DOMAINS",
    "JOB_SEAL_NAMES",
    "ReadPublicationsError",
    "PublicationRejectedError",
    "StalePublicationError",
    "RevisionIdentityConflictError",
    "RowAdmissionError",
    "RowNotFoundError",
    "ViewIntegrityError",
    "EntityRegistration",
    "DomainSlot",
    "SealPoint",
    "PublicationReceipt",
    "LogicalRow",
    "install_publication",
    "seal_row",
    "load_row",
    "publisher_journal_id",
    "reset_for_tests",
]

SCHEMA_VERSION = "owner-separated-write-domains/0.1.0"

PUBLISHER_AXIS = "publication.derived"
POINTER_OPERATION = "publication.pointer.write"
SEAL_OPERATION = "publication.seal.write"

INSTALL_EVENT_KIND = "domain.publication_installed"
SEAL_EVENT_KIND = "view.seal_selected"
ROW_EVENT_KIND = "logical_row.registered"
EVENT_SCHEMA_VERSION = "1"

CLOCK_ID = "clock_read_publications"
BOOT_ID = "boot_read_publications"
CLOCK_ORIGIN = "engine_measured"
CLOCK_SOURCE_ID = "src_read_publications"

JOB_DOMAINS: tuple[str, ...] = ("crawler", "downstream")
JOB_SEAL_NAMES = frozenset({"published", "fetch_key_replacement", "evidence_updated"})

_DOMAIN_OWNER = {"crawler": "job.crawler", "downstream": "job.downstream"}
_DOMAIN_ROLE = {"crawler": "crawler", "downstream": "product"}

_REVISION_MAX = 9007199254740991
_IDENTIFIER_MAX = 256
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

_ORIGINS = frozenset(
    {"engine_measured", "browser_measured", "subject_reported", "manual_reference"}
)
_TIME_POINT_FIELDS = frozenset(
    {"clock_id", "boot_id", "origin", "monotonic_offset_ms", "utc_annotation"}
)
_PREFIX_FIELDS = frozenset({"journal_id", "last_sequence", "head_hash"})
_PIN_FIELDS = frozenset({"revision", "record_digest"})
_DOMAIN_OWNER_FIELDS = frozenset(
    {"role", "source_id", "writer_id", "owner_domain", "publication_policy"}
)
_VERSION_PIN_FIELDS = frozenset({"id", "version", "artifact_digest"})
_REGISTRATION_FIELDS = frozenset(
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
_DOCUMENT_FIELDS = frozenset(
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
_JOB_ENTITY_FIELDS = frozenset({"entity_type", "target", "job_id"})
_JOB_IDENTITY_FIELDS = frozenset({"portfolio_job_id", "first_discovery_ref"})
_ROW_FIELDS = frozenset(
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
_SEAL_FIELDS = frozenset(
    {"seal_id", "name", "view_id", "versions", "sealed_at", "input_prefix", "evidence_refs"}
)
_RECEIPT_FIELDS = frozenset(
    {
        "record_type",
        "schema_version",
        "receipt_id",
        "entity",
        "registration_digest",
        "view_id",
        "publisher_id",
        "domain",
        "revision",
        "document",
        "supersedes",
        "observed_owner_head",
        "source_prefix",
        "installed_at",
        "publication_ref",
        "publication_delay",
    }
)
_INSTALL_DATA_FIELDS = frozenset(
    {
        "view_id",
        "entity",
        "registration_digest",
        "domain",
        "revision",
        "previous_revision",
        "document",
        "supersedes",
        "observed_owner_head",
        "installed_at",
        "publication_delay",
        "publisher_id",
        "source_prefix",
    }
)
_SEAL_DATA_FIELDS = frozenset(
    {
        "seal_name",
        "view_id",
        "entity",
        "registration_digest",
        "versions",
        "selected",
        "sealed_at",
    }
)
_ROW_DATA_FIELDS = frozenset(
    {
        "view_id",
        "entity",
        "seal_id",
        "seal_name",
        "registration_digest",
        "versions",
        "row",
        "row_digest",
        "input_prefix",
    }
)

_BOOT_NS = time.monotonic_ns()

_CLOCK_DESCRIPTOR = contract_codec.ClockDescriptor(
    clock_id=CLOCK_ID,
    boot_id=BOOT_ID,
    origin=CLOCK_ORIGIN,
    source_id=CLOCK_SOURCE_ID,
    basis="monotonic_offset",
    unit="ms",
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ReadPublicationsError(Exception):
    """Base class for read-view publication/seal contract violations."""


class PublicationRejectedError(ReadPublicationsError):
    """A delivery cannot be installed; the prior complete revision stays visible.

    Carries the typed :class:`Missing` envelope that explains unavailable or
    lost bytes, when the rejection came from artifact resolution.
    """

    def __init__(self, message: str, *, missing: Mapping[str, Any] | None = None) -> None:
        self.missing = missing
        super().__init__(message)


class StalePublicationError(ReadPublicationsError):
    """A reordered delivery would move the read-view pointer backwards."""


class RevisionIdentityConflictError(ReadPublicationsError):
    """One revision identity was offered two different bodies."""


class RowAdmissionError(ReadPublicationsError, ValueError):
    """A LogicalRow cannot be sealed or admitted."""


class RowNotFoundError(ReadPublicationsError, LookupError):
    """No registered LogicalRow exists for the requested entity/view."""


class ViewIntegrityError(ReadPublicationsError):
    """Durable view state disagrees with its journal evidence."""


# ---------------------------------------------------------------------------
# Small validation helpers
# ---------------------------------------------------------------------------


def _is_missing_like(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    keys = set(value.keys())
    return (
        keys in ({"value", "reason"}, {"value", "reason", "detail"})
        and value.get("value") is None
        and "reason" in value
    )


def _plain(value: Any) -> Any:
    """Return a deep, JSON-ready copy of a kernel value (no bare nulls)."""
    if hasattr(value, "to_dict") and not isinstance(value, Mapping):
        return _plain(value.to_dict())
    if isinstance(value, Mapping):
        if _is_missing_like(value):
            return _missing_envelope(value, "missing")
        out: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ReadPublicationsError(
                    f"non-string mapping key: {type(key).__name__}"
                )
            out[key] = _plain(item)
        return out
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    if value is None:
        raise ReadPublicationsError("bare null; use a typed Missing envelope")
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ReadPublicationsError("nonfinite number literal is not evidence")
        return value
    if isinstance(value, (str, bool, int)):
        return value
    raise ReadPublicationsError(
        f"value is not ordinary JSON content ({type(value).__name__})"
    )


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        _plain(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _reject_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, item in pairs:
        if key in obj:
            raise ValueError(f"duplicate mapping key: {key!r}")
        obj[key] = item
    return obj


def _reject_nonfinite(token: str) -> Any:
    raise ValueError(f"nonfinite number literal rejected: {token!r}")


def _require_identifier(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise ReadPublicationsError(f"{field} must be a str, not {type(value).__name__}")
    if not value or value != value.strip():
        raise ReadPublicationsError(f"{field} must be a nonempty identifier without padding")
    if len(value) > _IDENTIFIER_MAX:
        raise ReadPublicationsError(f"{field} must be at most {_IDENTIFIER_MAX} characters")
    if any(ord(ch) < 0x20 for ch in value):
        raise ReadPublicationsError(f"{field} must not contain control characters")
    return value


def _require_digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.match(value):
        raise ReadPublicationsError(f"{field} must be a sha256 digest, got {value!r}")
    return value


def _require_mapping(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ReadPublicationsError(f"{field} must be a mapping")
    return _plain(value)


def _require_int(value: Any, field: str, *, minimum: int = 0, maximum: int = _REVISION_MAX) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ReadPublicationsError(f"{field} must be an int, not {type(value).__name__}")
    if value < minimum or value > maximum:
        raise ReadPublicationsError(f"{field} must be between {minimum} and {maximum}")
    return value


def _missing_envelope(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ReadPublicationsError(f"{field} is not a typed Missing envelope")
    data = dict(value)
    if set(data.keys()) - {"value", "reason", "detail"} or "value" not in data:
        raise ReadPublicationsError(f"{field} is not a typed Missing envelope")
    if data.get("value") is not None:
        raise ReadPublicationsError(f"{field}.value must be null")
    if data.get("reason") not in contract_codec.VALID_MISSING_REASONS:
        raise ReadPublicationsError(f"{field} has an unknown Missing reason")
    if "detail" in data and (
        not isinstance(data["detail"], str) or not data["detail"]
    ):
        raise ReadPublicationsError(f"{field}.detail must be a nonempty string")
    return data


def _time_point(value: Any, field: str) -> dict[str, Any]:
    data = _require_mapping(value, field)
    if set(data.keys()) != _TIME_POINT_FIELDS:
        raise ReadPublicationsError(f"{field} must contain exactly {sorted(_TIME_POINT_FIELDS)}")
    for name in ("clock_id", "boot_id"):
        _require_identifier(data[name], f"{field}.{name}")
    if data["origin"] not in _ORIGINS:
        raise ReadPublicationsError(f"{field}.origin is unknown: {data['origin']!r}")
    offset = data["monotonic_offset_ms"]
    if isinstance(offset, bool) or not isinstance(offset, (int, float)):
        raise ReadPublicationsError(f"{field}.monotonic_offset_ms must be numeric")
    if not math.isfinite(float(offset)) or float(offset) < 0:
        raise ReadPublicationsError(
            f"{field}.monotonic_offset_ms must be finite and nonnegative"
        )
    utc = data["utc_annotation"]
    if isinstance(utc, str):
        if not utc:
            raise ReadPublicationsError(f"{field}.utc_annotation must be nonempty")
    else:
        _missing_envelope(utc, f"{field}.utc_annotation")
    return data


def _journal_prefix(value: Any, field: str) -> dict[str, Any]:
    data = _require_mapping(value, field)
    if set(data.keys()) != _PREFIX_FIELDS:
        raise ReadPublicationsError(f"{field} must contain exactly {sorted(_PREFIX_FIELDS)}")
    _require_identifier(data["journal_id"], f"{field}.journal_id")
    _require_int(data["last_sequence"], f"{field}.last_sequence", minimum=1)
    _require_digest(data["head_hash"], f"{field}.head_hash")
    return data


def _prefix_dict(prefix: Any) -> dict[str, Any]:
    if isinstance(prefix, Mapping):
        return _journal_prefix(prefix, "journal prefix")
    return {
        "journal_id": prefix.journal_id,
        "last_sequence": prefix.last_sequence,
        "head_hash": prefix.head_hash,
    }


def _evidence_ref(value: Any, field: str) -> Mapping[str, Any]:
    try:
        if isinstance(value, evidence_journal.EvidenceRef):
            ref = value
        else:
            ref = evidence_journal.EvidenceRef.from_dict(_require_mapping(value, field))
    except (TypeError, ValueError) as exc:
        raise ReadPublicationsError(f"{field} is not a valid EvidenceRef: {exc}") from exc
    return ref


def _artifact_ref(value: Any, field: str) -> Any:
    try:
        if isinstance(value, artifact_store.ArtifactReference):
            return value
        return artifact_store.ArtifactReference.from_dict(_require_mapping(value, field))
    except (TypeError, ValueError) as exc:
        raise ReadPublicationsError(
            f"{field} is not a valid ArtifactReference: {exc}"
        ) from exc


def _domain_pin(value: Any, field: str) -> dict[str, Any]:
    data = _require_mapping(value, field)
    if set(data.keys()) != _PIN_FIELDS:
        raise ReadPublicationsError(f"{field} must contain exactly {sorted(_PIN_FIELDS)}")
    revision = _require_int(data["revision"], f"{field}.revision")
    record_digest = data["record_digest"]
    if revision == 0:
        _missing_envelope(record_digest, f"{field}.record_digest")
    else:
        _require_digest(record_digest, f"{field}.record_digest")
    return data


def _maybe_pin(value: Any, field: str) -> dict[str, Any]:
    data = _require_mapping(value, field)
    if "reason" in data:
        return _missing_envelope(data, field)
    return _domain_pin(data, field)


def _validate_job_entity(value: Any, field: str = "entity") -> dict[str, Any]:
    data = _require_mapping(value, field)
    if set(data.keys()) != _JOB_ENTITY_FIELDS:
        raise ReadPublicationsError(
            f"{field} must be a JobEntityKey with exactly {sorted(_JOB_ENTITY_FIELDS)}"
        )
    if data["entity_type"] != "job":
        raise ReadPublicationsError(
            f"{field}.entity_type must be 'job'; read_publications admits job rows only"
        )
    _require_identifier(data["target"], f"{field}.target")
    _require_identifier(data["job_id"], f"{field}.job_id")
    return data


def _validate_job_identity(value: Any) -> dict[str, Any]:
    data = _require_mapping(value, "registration.identity")
    if set(data.keys()) != _JOB_IDENTITY_FIELDS:
        raise ReadPublicationsError(
            "registration.identity must be a JobIdentity with exactly "
            f"{sorted(_JOB_IDENTITY_FIELDS)}"
        )
    _require_identifier(data["portfolio_job_id"], "registration.identity.portfolio_job_id")
    _evidence_ref(data["first_discovery_ref"], "registration.identity.first_discovery_ref")
    return data


def _validate_version_pin(value: Any, field: str) -> dict[str, Any]:
    data = _require_mapping(value, field)
    if set(data.keys()) != _VERSION_PIN_FIELDS:
        raise ReadPublicationsError(f"{field} must be a VersionPin")
    _require_identifier(data["id"], f"{field}.id")
    _require_identifier(data["version"], f"{field}.version")
    _require_digest(data["artifact_digest"], f"{field}.artifact_digest")
    return data


def _validate_owners(value: Any) -> dict[str, Any]:
    data = _require_mapping(value, "registration.owners")
    if set(data.keys()) != set(JOB_DOMAINS):
        raise ReadPublicationsError(
            f"a job registration must declare exactly {list(JOB_DOMAINS)} owners"
        )
    for domain in JOB_DOMAINS:
        owner = _require_mapping(data[domain], f"registration.owners.{domain}")
        if set(owner.keys()) != _DOMAIN_OWNER_FIELDS:
            raise ReadPublicationsError(
                f"registration.owners.{domain} must be a DomainOwner with exactly "
                f"{sorted(_DOMAIN_OWNER_FIELDS)}"
            )
        if owner["role"] != _DOMAIN_ROLE[domain]:
            raise ReadPublicationsError(
                f"registration.owners.{domain}.role must be {_DOMAIN_ROLE[domain]!r}"
            )
        if owner["owner_domain"] != _DOMAIN_OWNER[domain]:
            raise ReadPublicationsError(
                f"registration.owners.{domain}.owner_domain must be "
                f"{_DOMAIN_OWNER[domain]!r}"
            )
        _require_identifier(owner["source_id"], f"registration.owners.{domain}.source_id")
        _require_identifier(owner["writer_id"], f"registration.owners.{domain}.writer_id")
        _validate_version_pin(
            owner["publication_policy"], f"registration.owners.{domain}.publication_policy"
        )
    return data


def _parse_record(data: bytes, where: str) -> tuple[dict[str, Any], str]:
    """Parse a complete canonical structured record and return (record, digest)."""
    try:
        digest = str(contract_codec.canonical_digest(data))
    except (TypeError, ValueError) as exc:
        raise ReadPublicationsError(
            f"{where} is not a canonical structured record: {exc}"
        ) from exc
    try:
        obj = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_object,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeDecodeError, ValueError) as exc:
        raise ReadPublicationsError(f"{where} is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(obj, dict):
        raise ReadPublicationsError(f"{where} must be a JSON object")
    if _canonical_bytes(obj) != data:
        raise ReadPublicationsError(
            f"{where} bytes are not the canonical complete record"
        )
    return obj, digest


def _record_digest(record: Mapping[str, Any]) -> str:
    return str(contract_codec.canonical_digest(_canonical_bytes(record)))


def _short_hash(value: Any, length: int = 40) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()[:length]


def _offset_ms() -> float:
    return round((time.monotonic_ns() - _BOOT_NS) / 1_000_000, 3)


def _timepoint() -> Any:
    return evidence_journal.TimePoint(
        clock_id=CLOCK_ID,
        boot_id=BOOT_ID,
        origin=CLOCK_ORIGIN,
        monotonic_offset_ms=_offset_ms(),
    )


# ---------------------------------------------------------------------------
# Publication delay measurement
# ---------------------------------------------------------------------------


def _publication_delay(run_id: str, manifest_ref: Mapping[str, Any]) -> dict[str, Any]:
    """An explicit unavailable delay measurement (never UTC subtraction)."""
    inter_clock = contract_codec.make_missing(
        "not_observed",
        "no same-clock source/destination pair was observed; cross-clock "
        "subtraction is not permitted",
    )
    measurement = {
        "measurement_id": "measure_publication_delay",
        "name": "publication_delay",
        "scope": {"kind": "run", "id": run_id},
        "quantity": "duration",
        "unit": "ms",
        "origin": CLOCK_ORIGIN,
        "clock_id": CLOCK_ID,
        "boot_id": BOOT_ID,
        "method": "unavailable",
        "start": contract_codec.make_missing("not_observed"),
        "end": contract_codec.make_missing("not_observed"),
        "estimate": {"kind": "unavailable", "value": inter_clock},
        "resolution": contract_codec.make_missing("not_observed"),
        "censoring": "unavailable",
        "comparability_group": contract_codec.make_missing(
            "not_applicable", "no comparable same-clock endpoints exist"
        ),
    }
    try:
        contract_codec.validate_measurement(measurement, (_CLOCK_DESCRIPTOR,))
    except (TypeError, ValueError) as exc:  # pragma: no cover - defensive
        raise ReadPublicationsError(f"invalid publication delay: {exc}") from exc
    return {
        "measurement": measurement,
        "evidence_refs": [dict(manifest_ref)],
    }


def _validate_measurement_evidence(value: Any) -> dict[str, Any]:
    data = _require_mapping(value, "publication_delay")
    if set(data.keys()) != {"measurement", "evidence_refs"}:
        raise ReadPublicationsError(
            "publication_delay must contain exactly measurement and evidence_refs"
        )
    measurement = _require_mapping(data["measurement"], "publication_delay.measurement")
    try:
        contract_codec.validate_measurement(measurement, (_CLOCK_DESCRIPTOR,))
    except (TypeError, ValueError) as exc:
        raise ReadPublicationsError(
            f"publication_delay.measurement is not a valid kernel measurement: {exc}"
        ) from exc
    refs = data["evidence_refs"]
    if isinstance(refs, (str, bytes)) or not isinstance(refs, (list, tuple)) or not refs:
        raise ReadPublicationsError(
            "publication_delay.evidence_refs requires at least one EvidenceRef"
        )
    for index, ref in enumerate(refs):
        _evidence_ref(ref, f"publication_delay.evidence_refs[{index}]")
    return data


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EntityRegistration:
    """The immutable, authenticated job registration a row embeds."""

    registration_id: str
    entity: Mapping[str, Any]
    identity: Mapping[str, Any]
    owners: Mapping[str, Any]
    evidence_prefix: Mapping[str, Any]
    evidence_refs: tuple[Mapping[str, Any], ...]
    record_type: str = "write_domain_entity"
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.record_type != "write_domain_entity":
            raise ReadPublicationsError("registration.record_type must be 'write_domain_entity'")
        if self.schema_version != SCHEMA_VERSION:
            raise ReadPublicationsError(
                f"registration.schema_version must be {SCHEMA_VERSION!r}"
            )
        _require_identifier(self.registration_id, "registration.registration_id")
        entity = _validate_job_entity(self.entity)
        identity = _validate_job_identity(self.identity)
        owners = _validate_owners(self.owners)
        prefix = _journal_prefix(self.evidence_prefix, "registration.evidence_prefix")
        refs = self.evidence_refs
        if isinstance(refs, (str, bytes)) or not isinstance(refs, Sequence) or not refs:
            raise ReadPublicationsError(
                "registration.evidence_refs requires at least one EvidenceRef"
            )
        normalized_refs = tuple(
            _evidence_ref(
                ref, f"registration.evidence_refs[{index}]"
            ).to_dict()
            for index, ref in enumerate(refs)
        )
        if len({_canonical_bytes(ref) for ref in normalized_refs}) != len(
            normalized_refs
        ):
            raise ReadPublicationsError(
                "registration.evidence_refs must be unique"
            )
        object.__setattr__(self, "entity", entity)
        object.__setattr__(self, "identity", identity)
        object.__setattr__(self, "owners", owners)
        object.__setattr__(self, "evidence_prefix", prefix)
        object.__setattr__(self, "evidence_refs", normalized_refs)

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": self.record_type,
            "schema_version": self.schema_version,
            "registration_id": self.registration_id,
            "entity": _plain(self.entity),
            "identity": _plain(self.identity),
            "owners": _plain(self.owners),
            "evidence_prefix": _plain(self.evidence_prefix),
            "evidence_refs": [_plain(ref) for ref in self.evidence_refs],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "EntityRegistration":
        raw = _require_mapping(data, "registration")
        if set(raw.keys()) != _REGISTRATION_FIELDS:
            raise ReadPublicationsError(
                f"registration must contain exactly {sorted(_REGISTRATION_FIELDS)}"
            )
        return cls(
            registration_id=raw["registration_id"],
            entity=raw["entity"],
            identity=raw["identity"],
            owners=raw["owners"],
            evidence_prefix=raw["evidence_prefix"],
            evidence_refs=tuple(raw["evidence_refs"]),
            record_type=raw["record_type"],
            schema_version=raw["schema_version"],
        )


def _coerce_registration(value: Any) -> EntityRegistration:
    if isinstance(value, EntityRegistration):
        return EntityRegistration.from_dict(value.to_dict())
    if isinstance(value, Mapping):
        return EntityRegistration.from_dict(value)
    raise ReadPublicationsError(
        f"registration must be an EntityRegistration, not {type(value).__name__}"
    )


def _registration_digest(registration: EntityRegistration) -> str:
    return _record_digest(registration.to_dict())


# ---------------------------------------------------------------------------
# Domain slots and seals
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DomainSlot:
    """One complete domain slot of a LogicalRow (``UnpublishedDomain``/``PublishedDomain``)."""

    revision: int
    document: Any = None
    publication_ref: Any = None
    snapshot: Any = None
    missing: Any = None

    def __post_init__(self) -> None:
        revision = _require_int(self.revision, "slot.revision")
        if revision == 0:
            if self.document is not None or self.publication_ref is not None or self.snapshot is not None:
                raise ReadPublicationsError(
                    "a zero slot cannot name a document, receipt, or snapshot"
                )
            if self.missing is None:
                raise ReadPublicationsError("a zero slot requires a typed Missing value")
            missing = _missing_envelope(self.missing, "slot.value")
            object.__setattr__(self, "missing", missing)
        else:
            if self.missing is not None:
                raise ReadPublicationsError("a published slot cannot carry Missing")
            document = _artifact_ref(self.document, "slot.document")
            publication_ref = _evidence_ref(self.publication_ref, "slot.publication_ref")
            snapshot = _require_mapping(self.snapshot, "slot.snapshot")
            object.__setattr__(self, "document", document)
            object.__setattr__(self, "publication_ref", publication_ref)
            object.__setattr__(self, "snapshot", snapshot)

    @property
    def published(self) -> bool:
        return self.revision != 0

    @classmethod
    def unpublished(cls, reason: str = "not_observed", detail: str | None = None) -> "DomainSlot":
        return cls(revision=0, missing=contract_codec.make_missing(reason, detail))

    def to_dict(self) -> dict[str, Any]:
        if self.revision == 0:
            return {"revision": 0, "value": _plain(self.missing)}
        return {
            "revision": self.revision,
            "document": self.document.to_dict(),
            "publication_ref": self.publication_ref.to_dict(),
            "snapshot": _plain(self.snapshot),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any], field: str = "slot") -> "DomainSlot":
        raw = _require_mapping(data, field)
        if set(raw.keys()) == {"revision", "value"}:
            revision = _require_int(raw["revision"], f"{field}.revision")
            if revision != 0:
                raise ReadPublicationsError(f"{field}: unpublished slots must use revision 0")
            return cls(revision=0, missing=raw["value"])
        if set(raw.keys()) == {"revision", "document", "publication_ref", "snapshot"}:
            return cls(
                revision=raw["revision"],
                document=raw["document"],
                publication_ref=raw["publication_ref"],
                snapshot=raw["snapshot"],
            )
        raise ReadPublicationsError(
            f"{field} must be an UnpublishedDomain or PublishedDomain shape"
        )


@dataclass(frozen=True, slots=True)
class SealPoint:
    """A point-in-time seal over locally installed complete publications."""

    seal_id: str
    name: str
    view_id: str
    versions: Mapping[str, int]
    sealed_at: Mapping[str, Any]
    input_prefix: Mapping[str, Any]
    evidence_refs: tuple[Mapping[str, Any], ...]

    def __post_init__(self) -> None:
        _require_identifier(self.seal_id, "seal.seal_id")
        if self.name not in JOB_SEAL_NAMES:
            raise ReadPublicationsError(
                f"job seals use one of {sorted(JOB_SEAL_NAMES)}; got {self.name!r}"
            )
        _require_identifier(self.view_id, "seal.view_id")
        versions = _require_mapping(self.versions, "seal.versions")
        if set(versions.keys()) != set(JOB_DOMAINS):
            raise ReadPublicationsError(
                f"seal.versions must contain exactly {list(JOB_DOMAINS)}"
            )
        for domain in JOB_DOMAINS:
            _require_int(versions[domain], f"seal.versions.{domain}")
        sealed_at = _time_point(self.sealed_at, "seal.sealed_at")
        prefix = _journal_prefix(self.input_prefix, "seal.input_prefix")
        refs = self.evidence_refs
        if isinstance(refs, (str, bytes)) or not isinstance(refs, Sequence) or not refs:
            raise ReadPublicationsError("seal.evidence_refs requires at least one EvidenceRef")
        normalized_refs = tuple(
            _evidence_ref(ref, f"seal.evidence_refs[{index}]").to_dict()
            for index, ref in enumerate(refs)
        )
        if len({_canonical_bytes(ref) for ref in normalized_refs}) != len(
            normalized_refs
        ):
            raise ReadPublicationsError("seal.evidence_refs must be unique")
        object.__setattr__(self, "versions", versions)
        object.__setattr__(self, "sealed_at", sealed_at)
        object.__setattr__(self, "input_prefix", prefix)
        object.__setattr__(self, "evidence_refs", normalized_refs)

    def to_dict(self) -> dict[str, Any]:
        return {
            "seal_id": self.seal_id,
            "name": self.name,
            "view_id": self.view_id,
            "versions": _plain(self.versions),
            "sealed_at": _plain(self.sealed_at),
            "input_prefix": _plain(self.input_prefix),
            "evidence_refs": [_plain(ref) for ref in self.evidence_refs],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "SealPoint":
        raw = _require_mapping(data, "seal_point")
        if set(raw.keys()) != _SEAL_FIELDS:
            raise ReadPublicationsError(
                f"seal_point must contain exactly {sorted(_SEAL_FIELDS)}"
            )
        return cls(
            seal_id=raw["seal_id"],
            name=raw["name"],
            view_id=raw["view_id"],
            versions=raw["versions"],
            sealed_at=raw["sealed_at"],
            input_prefix=raw["input_prefix"],
            evidence_refs=tuple(raw["evidence_refs"]),
        )


@dataclass(frozen=True, slots=True)
class PublicationReceipt:
    """Durable proof of one complete domain publication in a named view."""

    receipt_id: str
    entity: Mapping[str, Any]
    registration_digest: str
    view_id: str
    publisher_id: str
    domain: str
    revision: int
    document: Any
    supersedes: Mapping[str, Any]
    observed_owner_head: Mapping[str, Any]
    source_prefix: Mapping[str, Any]
    installed_at: Mapping[str, Any]
    publication_ref: Any
    publication_delay: Mapping[str, Any]
    record_type: str = "domain_publication_receipt"
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.record_type != "domain_publication_receipt":
            raise ReadPublicationsError(
                "receipt.record_type must be 'domain_publication_receipt'"
            )
        if self.schema_version != SCHEMA_VERSION:
            raise ReadPublicationsError(
                f"receipt.schema_version must be {SCHEMA_VERSION!r}"
            )
        _require_identifier(self.receipt_id, "receipt.receipt_id")
        entity = _validate_job_entity(self.entity, "receipt.entity")
        _require_digest(self.registration_digest, "receipt.registration_digest")
        _require_identifier(self.view_id, "receipt.view_id")
        _require_identifier(self.publisher_id, "receipt.publisher_id")
        if self.domain not in JOB_DOMAINS:
            raise ReadPublicationsError(f"receipt.domain must be one of {list(JOB_DOMAINS)}")
        revision = _require_int(self.revision, "receipt.revision", minimum=1)
        document = _artifact_ref(self.document, "receipt.document")
        supersedes = _domain_pin(self.supersedes, "receipt.supersedes")
        if revision <= supersedes["revision"]:
            raise ReadPublicationsError(
                "receipt.revision must be greater than supersedes.revision"
            )
        observed = _maybe_pin(self.observed_owner_head, "receipt.observed_owner_head")
        source_prefix = _journal_prefix(self.source_prefix, "receipt.source_prefix")
        installed_at = _time_point(self.installed_at, "receipt.installed_at")
        publication_ref = _evidence_ref(self.publication_ref, "receipt.publication_ref")
        delay = _validate_measurement_evidence(self.publication_delay)
        object.__setattr__(self, "entity", entity)
        object.__setattr__(self, "document", document)
        object.__setattr__(self, "supersedes", supersedes)
        object.__setattr__(self, "observed_owner_head", observed)
        object.__setattr__(self, "source_prefix", source_prefix)
        object.__setattr__(self, "installed_at", installed_at)
        object.__setattr__(self, "publication_ref", publication_ref)
        object.__setattr__(self, "publication_delay", delay)

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": self.record_type,
            "schema_version": self.schema_version,
            "receipt_id": self.receipt_id,
            "entity": _plain(self.entity),
            "registration_digest": self.registration_digest,
            "view_id": self.view_id,
            "publisher_id": self.publisher_id,
            "domain": self.domain,
            "revision": self.revision,
            "document": self.document.to_dict(),
            "supersedes": _plain(self.supersedes),
            "observed_owner_head": _plain(self.observed_owner_head),
            "source_prefix": _plain(self.source_prefix),
            "installed_at": _plain(self.installed_at),
            "publication_ref": self.publication_ref.to_dict(),
            "publication_delay": _plain(self.publication_delay),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "PublicationReceipt":
        raw = _require_mapping(data, "receipt")
        if set(raw.keys()) != _RECEIPT_FIELDS:
            raise ReadPublicationsError(
                f"receipt must contain exactly {sorted(_RECEIPT_FIELDS)}"
            )
        return cls(
            receipt_id=raw["receipt_id"],
            entity=raw["entity"],
            registration_digest=raw["registration_digest"],
            view_id=raw["view_id"],
            publisher_id=raw["publisher_id"],
            domain=raw["domain"],
            revision=raw["revision"],
            document=raw["document"],
            supersedes=raw["supersedes"],
            observed_owner_head=raw["observed_owner_head"],
            source_prefix=raw["source_prefix"],
            installed_at=raw["installed_at"],
            publication_ref=raw["publication_ref"],
            publication_delay=raw["publication_delay"],
            record_type=raw["record_type"],
            schema_version=raw["schema_version"],
        )


@dataclass(frozen=True, slots=True)
class LogicalRow:
    """One complete immutable row root (``W.LogicalRow``) for a job entity."""

    entity: Mapping[str, Any]
    registration_digest: str
    registration: EntityRegistration
    domains: Mapping[str, DomainSlot]
    seal_point: SealPoint
    record_type: str = "logical_row"
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.record_type != "logical_row":
            raise ReadPublicationsError("row.record_type must be 'logical_row'")
        if self.schema_version != SCHEMA_VERSION:
            raise ReadPublicationsError(f"row.schema_version must be {SCHEMA_VERSION!r}")
        entity = _validate_job_entity(self.entity, "row.entity")
        _require_digest(self.registration_digest, "row.registration_digest")
        registration = (
            self.registration
            if isinstance(self.registration, EntityRegistration)
            else _coerce_registration(self.registration)
        )
        if registration.entity != entity:
            raise ReadPublicationsError("row.entity and registration.entity disagree")
        if set(registration.owners.keys()) != set(JOB_DOMAINS):
            raise ReadPublicationsError("row registration owners are incomplete")
        domains = _require_mapping(self.domains, "row.domains")
        if set(domains.keys()) != set(JOB_DOMAINS):
            raise ReadPublicationsError(
                f"row.domains must contain every declared slot {list(JOB_DOMAINS)}"
            )
        normalized = {
            domain: (
                domains[domain]
                if isinstance(domains[domain], DomainSlot)
                else DomainSlot.from_dict(domains[domain], f"row.domains.{domain}")
            )
            for domain in JOB_DOMAINS
        }
        seal_point = (
            self.seal_point
            if isinstance(self.seal_point, SealPoint)
            else SealPoint.from_dict(self.seal_point)
        )
        if dict(seal_point.versions) != {
            domain: slot.revision for domain, slot in normalized.items()
        }:
            raise ReadPublicationsError(
                "row seal vector must exactly equal the domain slot revisions"
            )
        object.__setattr__(self, "entity", entity)
        object.__setattr__(self, "registration", registration)
        object.__setattr__(self, "domains", normalized)
        object.__setattr__(self, "seal_point", seal_point)

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": self.record_type,
            "schema_version": self.schema_version,
            "entity": _plain(self.entity),
            "registration_digest": self.registration_digest,
            "registration": self.registration.to_dict(),
            "domains": {
                domain: self.domains[domain].to_dict() for domain in JOB_DOMAINS
            },
            "seal_point": self.seal_point.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "LogicalRow":
        raw = _require_mapping(data, "row")
        if set(raw.keys()) != _ROW_FIELDS:
            raise ReadPublicationsError(
                f"row must contain exactly {sorted(_ROW_FIELDS)}"
            )
        domains_raw = _require_mapping(raw["domains"], "row.domains")
        if set(domains_raw.keys()) != set(JOB_DOMAINS):
            raise ReadPublicationsError(
                f"row.domains must contain every declared slot {list(JOB_DOMAINS)}"
            )
        return cls(
            entity=raw["entity"],
            registration_digest=raw["registration_digest"],
            registration=_coerce_registration(raw["registration"]),
            domains={
                domain: DomainSlot.from_dict(
                    domains_raw[domain], f"row.domains.{domain}"
                )
                for domain in JOB_DOMAINS
            },
            seal_point=SealPoint.from_dict(raw["seal_point"]),
            record_type=raw["record_type"],
            schema_version=raw["schema_version"],
        )

    def sealed_versions(self) -> dict[str, int]:
        return {domain: self.domains[domain].revision for domain in JOB_DOMAINS}


# ---------------------------------------------------------------------------
# Publisher context (authenticated channel + derived journal)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _PublisherContext:
    channel_id: str
    journal_id: str
    run_id: str
    producer_id: str
    principal_id: str
    role: str
    provenance: str
    sequence_required: bool
    clock_id: str
    boot_id: str


_CONTEXT: dict[str, _PublisherContext] = {}
_SETUP_LOCK = threading.Lock()


def _event_kind_entries() -> list[dict[str, Any]]:
    return [
        {
            "event_kind": kind,
            "event_schema_version": EVENT_SCHEMA_VERSION,
            "role": "derived_output",
            "assertion_kind": "authoritative_effect",
            "owner_domain": PUBLISHER_AXIS,
            "writer_roles": ["kernel"],
        }
        for kind in (INSTALL_EVENT_KIND, SEAL_EVENT_KIND, ROW_EVENT_KIND)
    ]


def _ensure_event_kinds() -> None:
    for kind in (INSTALL_EVENT_KIND, SEAL_EVENT_KIND, ROW_EVENT_KIND):
        try:
            access_policy.register_event_kind(
                kind,
                EVENT_SCHEMA_VERSION,
                role="derived_output",
                assertion_kind="authoritative_effect",
                owner_domain=PUBLISHER_AXIS,
                writer_roles=("kernel",),
            )
        except access_policy.RegistrationConflictError:
            # A previous admission (or the process harness) already registered
            # the declaration; the journal pins the authoritative copy.
            continue


def _journal_available(channel_id: str, ctx: _PublisherContext) -> bool:
    try:
        evidence_journal.journal_head(channel_id, ctx.journal_id)
    except evidence_journal.JournalNotAdmittedError:
        return False
    return True


def _admit_derived_journal(
    channel_id: str, projection: Mapping[str, Any]
) -> _PublisherContext:
    producer = projection["producer"]
    tag = _short_hash({"channel": channel_id, "axis": PUBLISHER_AXIS}, 16)
    journal_id = f"journal_read_publications_{tag}"
    manifest_id = f"manifest_read_publications_{tag}"
    run_id = f"run_read_publications_{tag}"

    task = artifact_store.retain_artifact(
        channel_id,
        PUBLISHER_AXIS,
        "application/json",
        _canonical_bytes({"kind": "read_view_task", "journal_id": journal_id}),
        "restricted",
    )
    configuration = artifact_store.retain_artifact(
        channel_id,
        PUBLISHER_AXIS,
        "application/json",
        _canonical_bytes(
            {
                "kind": "read_view_configuration",
                "seal_names": sorted(JOB_SEAL_NAMES),
                "domains": list(JOB_DOMAINS),
            }
        ),
        "restricted",
    )
    manifest = evidence_journal.Manifest(
        manifest_id=manifest_id,
        run_id=run_id,
        journal_id=journal_id,
        owner_domain=PUBLISHER_AXIS,
        commissioner_id="commissioner_read_publications",
        activity="kernel_conformance",
        attempt=evidence_journal.NOT_APPLICABLE,
        execution={
            "mode": "service",
            "subject": evidence_journal.NOT_APPLICABLE,
            "connector_version": evidence_journal.NOT_APPLICABLE,
            "binding_version": evidence_journal.NOT_APPLICABLE,
            "assistance": {
                "planning_owner": "none",
                "assistance_track": "no_assistance",
                "planner_identity": evidence_journal.NOT_APPLICABLE,
                "plan": evidence_journal.NOT_APPLICABLE,
                "online_replanning": False,
                "description": (
                    "Read-view publication is a kernel projection; no assistance "
                    "is declared at admission."
                ),
            },
        },
        task=task,
        task_semantic_hash=task.digest,
        effective_configuration=configuration,
        environment={},
        seed=evidence_journal.NOT_OBSERVED,
        build_pins=[
            {
                "id": "read_publications",
                "version": "1",
                "artifact_digest": task.digest,
            }
        ],
        event_registry=_event_kind_entries(),
        producers=[
            {
                "producer_id": producer["producer_id"],
                "principal_id": producer["principal_id"],
                "owner_domain": PUBLISHER_AXIS,
                "role": producer["role"],
                "provenance": producer["provenance"],
                "sequence_required": producer["sequence_required"],
                "allowed_event_kinds": [INSTALL_EVENT_KIND, SEAL_EVENT_KIND, ROW_EVENT_KIND],
            }
        ],
        clocks=[
            {
                "clock_id": CLOCK_ID,
                "boot_id": BOOT_ID,
                "origin": CLOCK_ORIGIN,
                "source_id": CLOCK_SOURCE_ID,
                "basis": "monotonic_offset",
                "unit": "ms",
            }
        ],
    )
    evidence_journal.admit_manifest(channel_id, manifest)
    return _PublisherContext(
        channel_id=channel_id,
        journal_id=journal_id,
        run_id=run_id,
        producer_id=str(producer["producer_id"]),
        principal_id=str(producer["principal_id"]),
        role=str(producer["role"]),
        provenance=str(producer["provenance"]),
        sequence_required=bool(producer["sequence_required"]),
        clock_id=CLOCK_ID,
        boot_id=BOOT_ID,
    )


def _publisher_context(channel_id: str) -> _PublisherContext:
    _require_identifier(channel_id, "channel_id")
    projection = access_policy.channel_projection(channel_id)
    if projection["actor"] != "read_view_publisher":
        raise ReadPublicationsError(
            "channel is not a read_view_publisher; a read view installs and "
            "seals through its own derived publication domain"
        )
    if projection["axis"] != PUBLISHER_AXIS:
        raise ReadPublicationsError(
            f"read-view publisher axis must be {PUBLISHER_AXIS!r}"
        )
    with _SETUP_LOCK:
        cached = _CONTEXT.get(channel_id)
        if cached is not None and _journal_available(channel_id, cached):
            _ensure_event_kinds()
            return cached
        _ensure_event_kinds()
        context = _admit_derived_journal(channel_id, projection)
        _CONTEXT[channel_id] = context
        return context


def publisher_journal_id(channel_id: str) -> str:
    """Return the derived publication journal bound to ``channel_id``."""
    return _publisher_context(channel_id).journal_id


def reset_for_tests() -> None:
    """Drop cached publisher setup (test isolation only)."""
    with _SETUP_LOCK:
        _CONTEXT.clear()


# ---------------------------------------------------------------------------
# Journal access helpers
# ---------------------------------------------------------------------------


def _journal_events(channel_id: str, journal_id: str) -> tuple[Any, ...]:
    head = evidence_journal.journal_head(channel_id, journal_id)
    return evidence_journal.read_prefix(channel_id, head)


def _manifest_ref(events: Sequence[Any], ctx: _PublisherContext) -> dict[str, Any]:
    admission = events[0]
    if (
        admission.event_kind != "manifest_admitted"
        or admission.journal_sequence != 1
    ):
        raise ViewIntegrityError("derived journal does not start with its manifest")
    return dict(
        evidence_journal.EvidenceRef(
            journal_id=ctx.journal_id,
            sequence=1,
            event_id=admission.event_id,
            event_hash=admission.event_hash,
            pointer="",
        ).to_dict()
    )


def _next_producer_sequence(ctx: _PublisherContext, events: Sequence[Any]) -> Any:
    if not ctx.sequence_required:
        return evidence_journal.NOT_APPLICABLE
    highest = 0
    for event in events:
        value = event.producer_sequence
        if isinstance(value, int) and not isinstance(value, bool) and value > highest:
            highest = value
    return highest + 1


def _submission(
    ctx: _PublisherContext,
    event_kind: str,
    data: Mapping[str, Any],
    *,
    evidence_refs: Sequence[Any] = (),
    artifact_refs: Sequence[Any] = (),
) -> Any:
    events = (
        _journal_events(ctx.channel_id, ctx.journal_id)
        if ctx.sequence_required
        else ()
    )
    return evidence_journal.EventSubmission(
        producer_sequence=_next_producer_sequence(ctx, events),
        event_kind=event_kind,
        event_schema_version=EVENT_SCHEMA_VERSION,
        occurred_at=_timepoint(),
        payload=evidence_journal.EvidencePayload(
            data=_plain(data),
            measurements=(),
            evidence_refs=[
                ref.to_dict() if hasattr(ref, "to_dict") else _plain(ref)
                for ref in evidence_refs
            ],
            artifact_refs=[
                ref.to_dict() if hasattr(ref, "to_dict") else _plain(ref)
                for ref in artifact_refs
            ],
        ),
    )


# ---------------------------------------------------------------------------
# Ownership-scoped pointer identities
# ---------------------------------------------------------------------------


def _pointer_entity_id(view_id: str, entity: Mapping[str, Any], domain: str) -> str:
    return (
        "viewptr_"
        + _short_hash({"view_id": view_id, "entity": entity, "domain": domain})
    )


def _row_entity_id(view_id: str, entity: Mapping[str, Any]) -> str:
    return "viewrow_" + _short_hash({"view_id": view_id, "entity": entity})


def _pointer_command_id(
    view_id: str, entity: Mapping[str, Any], domain: str, revision: int, digest: str
) -> str:
    return (
        "install_"
        + _short_hash(
            {
                "view_id": view_id,
                "entity": entity,
                "domain": domain,
                "revision": revision,
                "digest": digest,
            }
        )
    )


# ---------------------------------------------------------------------------
# Document validation
# ---------------------------------------------------------------------------


def _owned_revision(channel_id: str, reference: Any) -> dict[str, Any]:
    """Resolve and validate the exact canonical complete domain document."""
    try:
        raw = artifact_store.resolve_artifact(channel_id, reference)
    except artifact_store.ArtifactUnavailableError as exc:
        raise PublicationRejectedError(
            "publication bytes were never fully installed; the prior complete "
            "revision remains visible",
            missing=dict(exc.missing),
        ) from exc
    except artifact_store.ArtifactLostError as exc:
        raise PublicationRejectedError(
            "published bytes are unavailable or changed; archived/lost content "
            "is never replaced with revision zero",
            missing=dict(exc.missing),
        ) from exc
    except artifact_store.ArtifactAccessDeniedError as exc:
        raise PublicationRejectedError(
            "publication document is not readable from this read-view channel"
        ) from exc
    try:
        doc, digest = _parse_record(raw, "publication document")
    except ReadPublicationsError as exc:
        raise PublicationRejectedError(str(exc)) from exc
    if digest != reference.digest:
        raise PublicationRejectedError(
            "publication document digest does not match the complete embedded bytes"
        )
    if set(doc.keys()) != _DOCUMENT_FIELDS:
        raise PublicationRejectedError(
            f"publication document must contain exactly {sorted(_DOCUMENT_FIELDS)}"
        )
    if doc["record_type"] != "owned_domain_revision":
        raise PublicationRejectedError(
            "publication document record_type must be 'owned_domain_revision'"
        )
    if doc["schema_version"] != SCHEMA_VERSION:
        raise PublicationRejectedError(
            f"publication document schema_version must be {SCHEMA_VERSION!r}"
        )
    _validate_job_entity(doc["entity"], "publication document entity")
    _require_digest(doc["registration_digest"], "publication document registration_digest")
    if doc["domain"] not in JOB_DOMAINS:
        raise PublicationRejectedError(
            f"publication document domain must be one of {list(JOB_DOMAINS)}"
        )
    if doc["owner_domain"] != _DOMAIN_OWNER[doc["domain"]]:
        raise PublicationRejectedError(
            "publication document owner_domain disagrees with its domain"
        )
    _require_identifier(doc["writer_id"], "publication document writer_id")
    revision = _require_int(doc["revision"], "publication document revision", minimum=1)
    previous = _require_int(
        doc["previous_revision"], "publication document previous_revision"
    )
    if previous != revision - 1:
        raise PublicationRejectedError(
            "each owner revision must be previous_revision + 1"
        )
    _journal_prefix(doc["evidence_prefix"], "publication document evidence_prefix")
    refs = doc["evidence_refs"]
    if isinstance(refs, (str, bytes)) or not isinstance(refs, (list, tuple)) or not refs:
        raise PublicationRejectedError(
            "publication document evidence_refs requires at least one EvidenceRef"
        )
    for index, ref in enumerate(refs):
        _evidence_ref(ref, f"publication document evidence_refs[{index}]")
    value = _require_mapping(doc["value"], "publication document value")
    if not value:
        raise PublicationRejectedError("publication document value must be nonempty")
    return doc


def _assert_document_matches_registration(
    document: Mapping[str, Any],
    registration: EntityRegistration,
    registration_digest: str,
) -> None:
    if document["entity"] != registration.entity:
        raise PublicationRejectedError(
            "publication document entity disagrees with the registration entity"
        )
    if document["registration_digest"] != registration_digest:
        raise PublicationRejectedError(
            "publication document registration_digest disagrees with the "
            "complete registration bytes"
        )
    domain = document["domain"]
    if domain not in registration.owners:
        raise PublicationRejectedError(
            f"registration declares no {domain!r} domain owner"
        )
    owner = registration.owners[domain]
    if document["owner_domain"] != owner["owner_domain"]:
        raise PublicationRejectedError(
            "publication document owner_domain disagrees with the registration owner"
        )
    if document["writer_id"] != owner["writer_id"]:
        raise PublicationRejectedError(
            "publication document writer_id disagrees with the registration writer"
        )


# ---------------------------------------------------------------------------
# Journal evidence helpers
# ---------------------------------------------------------------------------


def _resolve_evidence(
    ctx: _PublisherContext,
    events: Sequence[Any],
    reference: Any,
    *,
    limit: int | None = None,
) -> Any:
    sequence = reference.sequence
    if reference.journal_id != ctx.journal_id:
        raise ViewIntegrityError(
            "view evidence must cite this read view's own publication journal"
        )
    if sequence < 1 or sequence > len(events):
        raise ViewIntegrityError(
            f"view evidence cites sequence {sequence} beyond the acknowledged prefix"
        )
    if limit is not None and sequence > limit:
        raise ViewIntegrityError(
            f"view evidence at sequence {sequence} is outside its prefix"
        )
    event = events[sequence - 1]
    if event.event_id != reference.event_id:
        raise ViewIntegrityError(
            f"view evidence event id disagrees at sequence {sequence}"
        )
    if event.event_hash != reference.event_hash:
        raise ViewIntegrityError(
            f"view evidence event hash disagrees at sequence {sequence}"
        )
    if not _pointer_resolves(event.to_dict(), reference.pointer):
        raise ViewIntegrityError(
            f"view evidence pointer {reference.pointer!r} does not resolve"
        )
    return event


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
        elif isinstance(node, Sequence) and not isinstance(node, (str, bytes)):
            if not token.isdigit() or int(token) >= len(node):
                return False
            node = node[int(token)]
        else:
            return False
    return True


def _assert_install_event(
    event: Any,
    receipt: PublicationReceipt,
    view_id: str,
    entity: Mapping[str, Any],
    domain: str,
) -> None:
    if event.event_kind != INSTALL_EVENT_KIND:
        raise ViewIntegrityError("publication_ref does not name an installation event")
    if event.event_schema_version != EVENT_SCHEMA_VERSION:
        raise ViewIntegrityError("installation event schema version disagrees")
    if event.owner_domain != PUBLISHER_AXIS:
        raise ViewIntegrityError("installation event belongs to another owner domain")
    data = event.payload["data"]
    if set(data.keys()) != _INSTALL_DATA_FIELDS:
        raise ViewIntegrityError("installation event payload is malformed")
    if (
        data["view_id"] != view_id
        or data["entity"] != _plain(entity)
        or data["domain"] != domain
        or data["revision"] != receipt.revision
        or data["registration_digest"] != receipt.registration_digest
        or data["publisher_id"] != receipt.publisher_id
        or data["document"] != receipt.document.to_dict()
        or data["supersedes"] != _plain(receipt.supersedes)
        or data["observed_owner_head"] != _plain(receipt.observed_owner_head)
        or data["installed_at"] != _plain(receipt.installed_at)
        or data["publication_delay"] != _plain(receipt.publication_delay)
        or data["source_prefix"] != _plain(receipt.source_prefix)
    ):
        raise ViewIntegrityError(
            "installation event payload disagrees with the publication receipt"
        )
    artifact_digests = {
        ref["digest"]
        for ref in event.payload["artifact_refs"]
        if isinstance(ref, Mapping) and "digest" in ref
    }
    if receipt.document.digest not in artifact_digests:
        raise ViewIntegrityError(
            "installation event does not prove complete document bytes"
        )


def _receipt_id(journal_id: str, sequence: int) -> str:
    return (
        "rcpt_"
        + hashlib.sha256(f"{journal_id}|{sequence}".encode("utf-8")).hexdigest()[:24]
    )


def _receipt_from_install(event: Any) -> PublicationReceipt:
    data = event.payload["data"]
    if set(data.keys()) != _INSTALL_DATA_FIELDS:
        raise ViewIntegrityError("installation event payload is malformed")
    try:
        return PublicationReceipt(
            receipt_id=_receipt_id(event.journal_id, event.journal_sequence),
            entity=data["entity"],
            registration_digest=data["registration_digest"],
            view_id=data["view_id"],
            publisher_id=data["publisher_id"],
            domain=data["domain"],
            revision=data["revision"],
            document=data["document"],
            supersedes=data["supersedes"],
            observed_owner_head=data["observed_owner_head"],
            source_prefix=data["source_prefix"],
            installed_at=data["installed_at"],
            publication_ref=evidence_journal.EvidenceRef(
                journal_id=event.journal_id,
                sequence=event.journal_sequence,
                event_id=event.event_id,
                event_hash=event.event_hash,
                pointer="",
            ),
            publication_delay=data["publication_delay"],
        )
    except ReadPublicationsError as exc:
        raise ViewIntegrityError(f"installation event is not a valid receipt: {exc}") from exc


@dataclass(frozen=True, slots=True)
class _Installed:
    receipt: PublicationReceipt
    document: Mapping[str, Any]


def _read_installed(
    channel_id: str,
    ctx: _PublisherContext,
    events: Sequence[Any],
    view_id: str,
    entity: Mapping[str, Any],
    domain: str,
    *,
    state: Any = None,
) -> _Installed | None:
    pointer_id = _pointer_entity_id(view_id, entity, domain)
    if state is None:
        state = evidence_journal.entity_state(
            channel_id, PUBLISHER_AXIS, pointer_id
        )
    if not isinstance(state.state, artifact_store.ArtifactReference):
        return None
    try:
        raw = artifact_store.resolve_artifact(channel_id, state.state)
    except artifact_store.ArtifactError as exc:
        raise ViewIntegrityError(
            "durable view pointer artifact is unavailable; published content "
            "is never replaced with revision zero"
        ) from exc
    if "sha256:" + hashlib.sha256(raw).hexdigest() != state.state.digest:
        raise ViewIntegrityError("durable view pointer bytes changed")
    record, digest = _parse_record(raw, "view domain pointer")
    if digest != state.state.digest:
        raise ViewIntegrityError("view pointer digest disagrees with its artifact")
    try:
        receipt = PublicationReceipt.from_dict(record)
    except ReadPublicationsError as exc:
        raise ViewIntegrityError(f"view pointer is not a valid receipt: {exc}") from exc
    if (
        receipt.view_id != view_id
        or receipt.domain != domain
        or receipt.entity != _plain(entity)
    ):
        raise ViewIntegrityError("view pointer identity disagrees with its scope")
    event = _resolve_evidence(ctx, events, receipt.publication_ref)
    _assert_install_event(event, receipt, view_id, entity, domain)
    document = _owned_revision(channel_id, receipt.document)
    if (
        document["revision"] != receipt.revision
        or document["domain"] != domain
        or document["entity"] != _plain(entity)
        or document["registration_digest"] != receipt.registration_digest
    ):
        raise ViewIntegrityError(
            "installed document disagrees with the publication receipt"
        )
    return _Installed(receipt=receipt, document=document)


def _find_install_event(
    events: Sequence[Any],
    view_id: str,
    entity: Mapping[str, Any],
    domain: str,
    revision: int,
) -> Any | None:
    entity_plain = _plain(entity)
    match: Any | None = None
    for event in events:
        if event.event_kind != INSTALL_EVENT_KIND:
            continue
        data = event.payload["data"]
        if (
            data.get("view_id") == view_id
            and data.get("entity") == entity_plain
            and data.get("domain") == domain
            and data.get("revision") == revision
        ):
            match = event
    return match


# ---------------------------------------------------------------------------
# Publication installation
# ---------------------------------------------------------------------------


def install_publication(
    channel_id: str,
    registration: EntityRegistration,
    document: artifact_store.ArtifactReference,
    view_id: str,
) -> PublicationReceipt:
    """Install one complete immutable domain publication into a read view.

    Complete bytes are resolved and validated before any pointer advance.
    A failed delivery leaves the prior complete revision visible.  A reordered
    delivery cannot roll the pointer back, and an identical retry returns the
    existing receipt without a new effect.
    """
    view = _require_identifier(view_id, "view_id")
    reg = _coerce_registration(registration)
    reg_digest = _registration_digest(reg)
    reference = _artifact_ref(document, "document")
    ctx = _publisher_context(channel_id)

    parsed = _owned_revision(channel_id, reference)
    _assert_document_matches_registration(parsed, reg, reg_digest)
    domain = parsed["domain"]
    revision = parsed["revision"]
    pointer_id = _pointer_entity_id(view, reg.entity, domain)
    access_policy.authorize(channel_id, POINTER_OPERATION, pointer_id)

    events = _journal_events(channel_id, ctx.journal_id)
    pointer_state = evidence_journal.entity_state(
        channel_id, PUBLISHER_AXIS, pointer_id
    )
    installed = _read_installed(
        channel_id, ctx, events, view, reg.entity, domain, state=pointer_state
    )
    if installed is not None:
        prior = installed.receipt
        if prior.registration_digest != reg_digest:
            raise RevisionIdentityConflictError(
                "the view pointer belongs to a different registration; a view "
                "never silently repoints one entity registration to another"
            )
        if prior.revision == revision and prior.document.digest == reference.digest:
            return prior
        if prior.revision == revision:
            raise RevisionIdentityConflictError(
                f"revision {revision} is already installed with a different "
                "complete body; the pointer does not change"
            )
        if prior.revision > revision:
            raise StalePublicationError(
                f"revision {revision} was delivered after revision "
                f"{prior.revision} was installed; a reordered delivery never "
                "rolls the view pointer back"
            )

    supersedes = {
        "revision": installed.receipt.revision if installed is not None else 0,
        "record_digest": (
            installed.receipt.document.digest
            if installed is not None
            else contract_codec.make_missing("not_observed")
        ),
    }
    installed_at = _timepoint().to_dict()
    data = {
        "view_id": view,
        "entity": _plain(reg.entity),
        "registration_digest": reg_digest,
        "domain": domain,
        "revision": revision,
        "previous_revision": parsed["previous_revision"],
        "document": reference.to_dict(),
        "supersedes": supersedes,
        "observed_owner_head": contract_codec.make_missing("not_observed"),
        "installed_at": installed_at,
        "publication_delay": _publication_delay(ctx.run_id, _manifest_ref(events, ctx)),
        "publisher_id": ctx.producer_id,
        "source_prefix": _plain(parsed["evidence_prefix"]),
    }
    envelope = _find_install_event(events, view, reg.entity, domain, revision)
    if envelope is not None:
        prior_data = envelope.payload["data"]
        if prior_data["document"]["digest"] != reference.digest:
            raise RevisionIdentityConflictError(
                f"revision {revision} already has conflicting published content; "
                "an integrity conflict never becomes last-write-wins"
            )
        if prior_data["supersedes"]["revision"] != supersedes["revision"]:
            # The orphaned installation evidence predates the current pointer;
            # never reuse a stale supersedes pin for a newer state.
            envelope = None
    if envelope is None:
        envelope = evidence_journal.append_event(
            channel_id,
            PUBLISHER_AXIS,
            _submission(
                ctx,
                INSTALL_EVENT_KIND,
                data,
                artifact_refs=(reference,),
            ),
        )
    receipt = _receipt_from_install(envelope)
    if receipt.registration_digest != reg_digest:
        raise RevisionIdentityConflictError(
            "installation evidence belongs to a different registration"
        )

    pointer_bytes = _canonical_bytes(receipt.to_dict())
    pointer_ref = artifact_store.retain_artifact(
        channel_id, PUBLISHER_AXIS, "application/json", pointer_bytes, "restricted"
    )
    try:
        evidence_journal.commit_effect(
            channel_id,
            PUBLISHER_AXIS,
            pointer_id,
            _pointer_command_id(view, reg.entity, domain, revision, reference.digest),
            pointer_state.revision,
            pointer_ref,
            (),
        )
    except evidence_journal.RevisionConflictError as exc:
        current = _read_installed(
            channel_id,
            ctx,
            _journal_events(channel_id, ctx.journal_id),
            view,
            reg.entity,
            domain,
        )
        if current is not None and (
            current.receipt.revision == revision
            and current.receipt.document.digest == reference.digest
        ):
            return current.receipt
        raise StalePublicationError(
            "a concurrent delivery advanced this view pointer; the stale "
            "delivery is rejected and the installed revision stays visible"
        ) from exc
    return receipt


# ---------------------------------------------------------------------------
# Sealing
# ---------------------------------------------------------------------------


def _seal_id(
    view_id: str,
    registration_digest: str,
    seal_name: str,
    versions: Mapping[str, int],
    selection_ref: Any,
) -> str:
    return (
        "seal_"
        + _short_hash(
            {
                "view_id": view_id,
                "registration_digest": registration_digest,
                "seal_name": seal_name,
                "versions": versions,
                "selection": selection_ref.to_dict(),
            },
            32,
        )
    )


def _selected_entries(
    slots: Mapping[str, DomainSlot]
) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for domain in JOB_DOMAINS:
        slot = slots[domain]
        if not slot.published:
            entries.append(
                {"domain": domain, "revision": 0, "value": _plain(slot.missing)}
            )
            continue
        entries.append(
            {
                "domain": domain,
                "revision": slot.revision,
                "document": slot.document.to_dict(),
                "publication_ref": slot.publication_ref.to_dict(),
            }
        )
    return entries


def _assert_selection_event(
    event: Any,
    row: LogicalRow,
    selection_ref: Any,
) -> None:
    if event.event_kind != SEAL_EVENT_KIND:
        raise RowAdmissionError(
            "the row's input prefix does not end with its seal-selection event"
        )
    if event.event_schema_version != EVENT_SCHEMA_VERSION:
        raise RowAdmissionError("seal-selection event schema version disagrees")
    data = event.payload["data"]
    if set(data.keys()) != _SEAL_DATA_FIELDS:
        raise RowAdmissionError("seal-selection event payload is malformed")
    seal = row.seal_point
    if (
        data["seal_name"] != seal.name
        or data["view_id"] != seal.view_id
        or data["entity"] != _plain(row.entity)
        or data["registration_digest"] != row.registration_digest
        or data["versions"] != _plain(seal.versions)
        or data["sealed_at"] != _plain(seal.sealed_at)
        or data["selected"] != _selected_entries(row.domains)
    ):
        raise RowAdmissionError(
            "seal-selection evidence disagrees with the seal point"
        )
    expected = _seal_id(
        seal.view_id,
        row.registration_digest,
        seal.name,
        seal.versions,
        selection_ref,
    )
    if seal.seal_id != expected:
        raise RowAdmissionError(
            "seal id does not derive from the pinned seal-selection evidence"
        )


def _assert_no_conflicting_revisions(
    events: Sequence[Any],
    row: LogicalRow,
    selection_sequence: int,
) -> None:
    seen: dict[tuple[bytes, str, str, int], str] = {}
    entity_bytes = _canonical_bytes(row.entity)
    view_id = row.seal_point.view_id
    for event in events:
        if event.event_kind != INSTALL_EVENT_KIND:
            continue
        if event.journal_sequence >= selection_sequence:
            continue
        data = event.payload["data"]
        if data["view_id"] != view_id:
            continue
        key = (entity_bytes, view_id, str(data["domain"]), int(data["revision"]))
        digest = data["document"]["digest"]
        prior = seen.get(key)
        if prior is not None and prior != digest:
            raise ViewIntegrityError(
                "one revision identity carries two different complete bodies"
            )
        seen[key] = digest
    for domain, slot in row.domains.items():
        if not slot.published:
            continue
        key = (entity_bytes, view_id, domain, slot.revision)
        if seen.get(key) != slot.document.digest:
            raise ViewIntegrityError(
                "published slot does not match the journaled installation"
            )


def _verify_row(
    channel_id: str,
    ctx: _PublisherContext,
    view_id: str,
    entity: Mapping[str, Any],
    row: LogicalRow,
    row_reference: Any,
    events: Sequence[Any],
) -> None:
    # 1. Job entity and registration identity agree.
    if row.entity != _plain(entity):
        raise RowAdmissionError("row entity disagrees with the requested entity")
    registration = row.registration
    if registration.entity != row.entity:
        raise RowAdmissionError("row entity and embedded registration disagree")
    # 2. Registration digest matches complete bytes.
    if _registration_digest(registration) != row.registration_digest:
        raise RowAdmissionError(
            "registration digest does not match the complete embedded registration"
        )
    # 3. Crawler slot is nonzero.
    if row.domains["crawler"].revision == 0:
        raise RowAdmissionError(
            "crawler slot is unpublished; a crawler-backed row cannot be admitted"
        )
    # 8. Seal vector matches every slot (also enforced by LogicalRow).
    if row.seal_point.view_id != view_id:
        raise RowAdmissionError("seal was taken in a different read view")
    if dict(row.seal_point.versions) != row.sealed_versions():
        raise RowAdmissionError("seal vector does not match the domain slots")

    # 9. Seal-selection evidence is within its prefix.
    prefix = evidence_journal.JournalPrefix(
        journal_id=row.seal_point.input_prefix["journal_id"],
        last_sequence=row.seal_point.input_prefix["last_sequence"],
        head_hash=row.seal_point.input_prefix["head_hash"],
    )
    if prefix.journal_id != ctx.journal_id:
        raise RowAdmissionError("row input prefix does not name this read view journal")
    prefix_events = evidence_journal.read_prefix(channel_id, prefix)
    selection_event = prefix_events[-1]
    selection_ref = evidence_journal.EvidenceRef(
        journal_id=ctx.journal_id,
        sequence=selection_event.journal_sequence,
        event_id=selection_event.event_id,
        event_hash=selection_event.event_hash,
        pointer="",
    )
    _assert_selection_event(selection_event, row, selection_ref)

    expected_refs = {_canonical_bytes(selection_ref.to_dict())}
    for domain, slot in row.domains.items():
        if slot.published:
            expected_refs.add(_canonical_bytes(slot.publication_ref.to_dict()))
    actual_refs = {
        _canonical_bytes(dict(ref)) for ref in row.seal_point.evidence_refs
    }
    if actual_refs != expected_refs:
        raise RowAdmissionError(
            "seal evidence must name the seal selection and every installed "
            "publication exactly"
        )
    for ref in row.seal_point.evidence_refs:
        _resolve_evidence(
            ctx,
            prefix_events,
            _evidence_ref(ref, "seal.evidence_refs"),
            limit=prefix.last_sequence,
        )

    # 4-7, 10. Each published slot is a complete locally installed publication.
    for domain in JOB_DOMAINS:
        slot = row.domains[domain]
        if not slot.published:
            continue
        document = _owned_revision(channel_id, slot.document)
        if slot.revision != document["revision"]:
            raise RowAdmissionError(
                "slot revision disagrees with the embedded domain document"
            )
        if (
            document["entity"] != row.entity
            or document["registration_digest"] != row.registration_digest
            or document["domain"] != domain
            or document["owner_domain"] != registration.owners[domain]["owner_domain"]
            or document["writer_id"] != registration.owners[domain]["writer_id"]
        ):
            raise RowAdmissionError(
                "embedded domain document disagrees with entity/registration/"
                "domain/owner/writer"
            )
        if _canonical_bytes(slot.snapshot) != _canonical_bytes(document):
            raise RowAdmissionError(
                "slot snapshot is not the complete embedded publication"
            )
        install_event = _resolve_evidence(
            ctx,
            prefix_events,
            slot.publication_ref,
            limit=prefix.last_sequence - 1,
        )
        if install_event.event_kind != INSTALL_EVENT_KIND:
            raise RowAdmissionError(
                "slot publication_ref does not name an installation event"
            )
        data = install_event.payload["data"]
        if data.get("view_id") != view_id:
            raise RowAdmissionError(
                "publication evidence does not prove installation in this view"
            )
        if (
            data.get("entity") != _plain(row.entity)
            or data.get("registration_digest") != row.registration_digest
            or data.get("domain") != domain
            or data.get("revision") != slot.revision
            or data.get("previous_revision") != document["previous_revision"]
            or data.get("document") != slot.document.to_dict()
            or data.get("source_prefix") != document["evidence_prefix"]
        ):
            raise RowAdmissionError(
                "publication evidence disagrees with the slot pin"
            )
        digests = {
            ref["digest"]
            for ref in install_event.payload["artifact_refs"]
            if isinstance(ref, Mapping) and "digest" in ref
        }
        if slot.document.digest not in digests:
            raise RowAdmissionError(
                "installation evidence omits the complete document bytes"
            )

    # 11. No revision identity has conflicting content.
    _assert_no_conflicting_revisions(
        prefix_events, row, selection_event.journal_sequence
    )

    # The row's own registration event is not part of its derivation prefix.
    registrations = [
        event
        for event in events
        if event.event_kind == ROW_EVENT_KIND
        and event.payload["data"].get("row_digest") == row_reference.digest
    ]
    if not registrations:
        raise ViewIntegrityError(
            "row root is not registered in the read-view journal"
        )
    registration_event = registrations[-1]
    if registration_event.journal_sequence <= prefix.last_sequence:
        raise RowAdmissionError(
            "row input prefix includes the row's own registration event"
        )
    data = registration_event.payload["data"]
    if set(data.keys()) != _ROW_DATA_FIELDS:
        raise ViewIntegrityError("row registration event payload is malformed")
    if (
        data["view_id"] != view_id
        or data["entity"] != _plain(row.entity)
        or data["seal_id"] != row.seal_point.seal_id
        or data["seal_name"] != row.seal_point.name
        or data["registration_digest"] != row.registration_digest
        or data["versions"] != _plain(row.seal_point.versions)
        or data["row"] != row_reference.to_dict()
        or data["input_prefix"] != _plain(row.seal_point.input_prefix)
    ):
        raise ViewIntegrityError(
            "row registration event disagrees with the registered row"
        )


def _load_verified_row(
    channel_id: str,
    ctx: _PublisherContext,
    view_id: str,
    entity: Mapping[str, Any],
) -> tuple[LogicalRow, Any, Any]:
    events = _journal_events(channel_id, ctx.journal_id)
    state = evidence_journal.entity_state(
        channel_id, PUBLISHER_AXIS, _row_entity_id(view_id, entity)
    )
    if not isinstance(state.state, artifact_store.ArtifactReference):
        raise RowNotFoundError(
            f"no row has been sealed for this entity in view {view_id!r}"
        )
    reference = state.state
    try:
        raw = artifact_store.resolve_artifact(channel_id, reference)
    except artifact_store.ArtifactError as exc:
        raise ViewIntegrityError(
            "registered row root is unavailable; sealed content is never "
            "replaced with revision zero"
        ) from exc
    record, digest = _parse_record(raw, "logical row")
    if digest != reference.digest:
        raise ViewIntegrityError("row root digest disagrees with its artifact")
    try:
        row = LogicalRow.from_dict(record)
    except ReadPublicationsError as exc:
        raise ViewIntegrityError(f"registered row root is invalid: {exc}") from exc
    _verify_row(channel_id, ctx, view_id, entity, row, reference, events)
    return row, reference, events


def seal_row(
    channel_id: str,
    registration: EntityRegistration,
    view_id: str,
    seal_name: str,
) -> LogicalRow:
    """Seal the locally installed complete publications into one frozen row.

    The seal pins local revisions and digests only: no owner journal is read,
    no global synchronous freshness is required, and future writes are not
    frozen.  The seal-selection event is journaled before the row exists; the
    row's registration event is deliberately outside the row's input prefix.
    """
    view = _require_identifier(view_id, "view_id")
    if not isinstance(seal_name, str) or seal_name not in JOB_SEAL_NAMES:
        raise RowAdmissionError(
            f"job seals use one of {sorted(JOB_SEAL_NAMES)}; got {seal_name!r}"
        )
    reg = _coerce_registration(registration)
    reg_digest = _registration_digest(reg)
    ctx = _publisher_context(channel_id)
    access_policy.authorize(channel_id, SEAL_OPERATION, _row_entity_id(view, reg.entity))

    events = _journal_events(channel_id, ctx.journal_id)
    slots: dict[str, DomainSlot] = {}
    publication_refs: list[Any] = []
    artifact_refs: list[Any] = []
    for domain in JOB_DOMAINS:
        installed = _read_installed(
            channel_id, ctx, events, view, reg.entity, domain
        )
        if installed is None:
            if domain == "crawler":
                raise RowAdmissionError(
                    "crawler slot is unpublished; a crawler-backed evaluation "
                    "cannot consume a partial publication"
                )
            slots[domain] = DomainSlot.unpublished(
                "not_observed",
                "no downstream publication is installed in this view",
            )
            continue
        if installed.receipt.registration_digest != reg_digest:
            raise RowAdmissionError(
                f"installed {domain} publication belongs to a different registration"
            )
        slots[domain] = DomainSlot(
            revision=installed.receipt.revision,
            document=installed.receipt.document,
            publication_ref=installed.receipt.publication_ref,
            snapshot=installed.document,
        )
        publication_refs.append(installed.receipt.publication_ref)
        artifact_refs.append(installed.receipt.document)

    versions = {domain: slots[domain].revision for domain in JOB_DOMAINS}

    # A repeated seal of the same name over the same local vector is idempotent.
    try:
        existing, _reference, _events = _load_verified_row(
            channel_id, ctx, view, reg.entity
        )
    except RowNotFoundError:
        existing = None
    if (
        existing is not None
        and existing.seal_point.name == seal_name
        and existing.registration_digest == reg_digest
        and dict(existing.seal_point.versions) == versions
    ):
        return existing

    sealed_at = _timepoint().to_dict()
    selection_data = {
        "seal_name": seal_name,
        "view_id": view,
        "entity": _plain(reg.entity),
        "registration_digest": reg_digest,
        "versions": versions,
        "selected": _selected_entries(slots),
        "sealed_at": sealed_at,
    }
    selection_event = evidence_journal.append_event(
        channel_id,
        PUBLISHER_AXIS,
        _submission(
            ctx,
            SEAL_EVENT_KIND,
            selection_data,
            evidence_refs=publication_refs,
            artifact_refs=artifact_refs,
        ),
    )
    selection_ref = evidence_journal.EvidenceRef(
        journal_id=selection_event.journal_id,
        sequence=selection_event.journal_sequence,
        event_id=selection_event.event_id,
        event_hash=selection_event.event_hash,
        pointer="",
    )
    input_prefix = evidence_journal.JournalPrefix(
        journal_id=selection_event.journal_id,
        last_sequence=selection_event.journal_sequence,
        head_hash=selection_event.event_hash,
    )
    seal_point = SealPoint(
        seal_id=_seal_id(view, reg_digest, seal_name, versions, selection_ref),
        name=seal_name,
        view_id=view,
        versions=versions,
        sealed_at=sealed_at,
        input_prefix=_prefix_dict(input_prefix),
        evidence_refs=(selection_ref.to_dict(),)
        + tuple(ref.to_dict() for ref in publication_refs),
    )
    row = LogicalRow(
        entity=_plain(reg.entity),
        registration_digest=reg_digest,
        registration=reg,
        domains=slots,
        seal_point=seal_point,
    )
    row_bytes = _canonical_bytes(row.to_dict())
    row_ref = artifact_store.retain_artifact(
        channel_id, PUBLISHER_AXIS, "application/json", row_bytes, "public"
    )
    registration_data = {
        "view_id": view,
        "entity": _plain(reg.entity),
        "seal_id": seal_point.seal_id,
        "seal_name": seal_point.name,
        "registration_digest": reg_digest,
        "versions": versions,
        "row": row_ref.to_dict(),
        "row_digest": row_ref.digest,
        "input_prefix": _prefix_dict(input_prefix),
    }
    row_pointer_id = _row_entity_id(view, reg.entity)
    state = evidence_journal.entity_state(channel_id, PUBLISHER_AXIS, row_pointer_id)
    registration_submission = _submission(
        ctx,
        ROW_EVENT_KIND,
        registration_data,
        evidence_refs=(selection_ref,) + tuple(publication_refs),
        artifact_refs=(row_ref,),
    )
    evidence_journal.commit_effect(
        channel_id,
        PUBLISHER_AXIS,
        row_pointer_id,
        "seal_" + _short_hash({"view_id": view, "seal_id": seal_point.seal_id}),
        state.revision,
        row_ref,
        (registration_submission,),
    )
    return row


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------


def load_row(
    channel_id: str,
    entity: Mapping[str, Any],
    view_id: str,
) -> LogicalRow:
    """Load and fully re-verify one immutable row root for a job entity."""
    view = _require_identifier(view_id, "view_id")
    entity_data = _validate_job_entity(entity)
    ctx = _publisher_context(channel_id)
    row, _reference, _events = _load_verified_row(
        channel_id, ctx, view, entity_data
    )
    return row

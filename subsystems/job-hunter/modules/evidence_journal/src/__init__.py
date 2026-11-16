"""evidence_journal: append-only, hash-chained evidence journal (tier 2).

Implements the kernel journal and producer rules (``EK-JOURNAL``,
``EK-ATOMICITY``, ``EK-HASHES``, ``EK-PROVENANCE``, ``EK-OBSERVATION``,
``OWD-LOCAL-COMMIT``):

* Admission pins one complete, immutable manifest as journal sequence 1
  (``manifest_admitted``).  Later events name the same run, journal, and
  manifest digest and form a contiguous, strictly increasing hash chain.
* Untrusted callers submit :class:`EventSubmission` only.  Identity,
  sequence, provenance, role, assertion kind, receipt time, and hashes are
  derived from the authenticated channel, the registered event kinds, and
  the manifest pins.  A caller-supplied :class:`JournalEnvelope` is rejected
  as ingress.
* Identical ``(producer_id, producer_sequence)`` retries return the already
  acknowledged envelope without duplicating an effect.  Conflicting content
  under that key is retained as an integrity incident; the original event is
  never replaced and the journal head does not move.
* ``commit_effect`` commits the owner's authoritative state, revision
  advance, journal events, and replayable response as one owner-local
  copy-on-write swap.  Nothing is acknowledged before that durability
  boundary, and each owner domain has its own lock (no central writer, no
  peer-owned lock).

Missing values are always typed: in-band nulls are rejected at ingress.
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import math
import re
import secrets
import sys
import threading
import time
from dataclasses import dataclass, fields, is_dataclass, replace
from datetime import datetime, timezone
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

__all__ = [
    "SCHEMA_VERSION",
    "Missing",
    "NOT_APPLICABLE",
    "NOT_OBSERVED",
    "TimePoint",
    "EvidenceRef",
    "JournalPrefix",
    "EvidencePayload",
    "EventSubmission",
    "Manifest",
    "JournalEnvelope",
    "EntityState",
    "IntegrityIncident",
    "EvidenceJournalError",
    "IngressAuthorityError",
    "AdmissionRejectedError",
    "AdmissionConflictError",
    "JournalNotAdmittedError",
    "JournalIntegrityError",
    "InvalidEvidenceRefError",
    "InvalidMeasurementError",
    "IntegrityIncidentError",
    "ManifestPinError",
    "ProvenanceConflictError",
    "RevisionConflictError",
    "CommandConflictError",
    "InvalidEventError",
    "InvalidCommandError",
    "admit_manifest",
    "append_event",
    "read_prefix",
    "commit_effect",
    "journal_head",
    "entity_state",
    "integrity_incidents",
    "reset_for_tests",
]

# ---------------------------------------------------------------------------
# Kernel vocabulary
# ---------------------------------------------------------------------------

SCHEMA_VERSION = "evidence-kernel/0.1.0"

_MANIFEST_RECORD_TYPE = "manifest"
_ENVELOPE_RECORD_TYPE = "journal_event"
_MANIFEST_EVENT_KIND = "manifest_admitted"

_ACTIVITIES = frozenset({"discovery", "application_attempt", "kernel_conformance"})
_ATTEMPT_KINDS = frozenset({"practice", "production"})
_TARGET_CLASSES = frozenset({"laboratory_fixture", "employer_origin"})
_EVALUATION_PARTITIONS = frozenset({"held_in", "held_out"})
_EXECUTION_MODES = frozenset({"manual", "subject", "service"})
_PLANNING_OWNERS = frozenset({"subject", "external_planner", "operator", "none"})
_MEASUREMENT_ORIGINS = frozenset(
    {"engine_measured", "browser_measured", "subject_reported", "manual_reference"}
)
_EVIDENCE_SCOPES = frozenset({"current_run", "historical_unscored", "synthetic"})
_NON_SERVER_PROVENANCES = frozenset(
    {"fixture_client", "subject", "manual_observer", "importer"}
)

SUBMISSION_FIELDS = frozenset(
    {"producer_sequence", "event_kind", "event_schema_version", "occurred_at", "payload"}
)
PAYLOAD_FIELDS = frozenset({"data", "measurements", "evidence_refs", "artifact_refs"})
ARTIFACT_REF_FIELDS = frozenset(
    {"digest", "size_bytes", "media_type", "owner_domain", "access"}
)
CLOCK_FIELDS = frozenset(
    {"clock_id", "boot_id", "origin", "source_id", "basis", "unit"}
)
PRODUCER_FIELDS = frozenset(
    {
        "producer_id",
        "principal_id",
        "owner_domain",
        "role",
        "provenance",
        "sequence_required",
        "allowed_event_kinds",
    }
)
EVENT_KIND_FIELDS = frozenset(
    {"event_kind", "event_schema_version", "role", "assertion_kind", "writer_roles"}
)
TIME_POINT_FIELDS = frozenset(
    {"clock_id", "boot_id", "origin", "monotonic_offset_ms", "utc_annotation"}
)
VERSION_PIN_FIELDS = frozenset({"id", "version", "artifact_digest"})
ATTEMPT_FIELDS = frozenset(
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
)
ATTEMPT_REFERENCE_FIELDS = frozenset({"attempt_id", "kind"})
EXECUTION_FIELDS = frozenset(
    {"mode", "subject", "connector_version", "binding_version", "assistance"}
)
ASSISTANCE_FIELDS = frozenset(
    {
        "planning_owner",
        "assistance_track",
        "planner_identity",
        "plan",
        "online_replanning",
        "description",
    }
)

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_POINTER_RE = re.compile(r"^(?:/(?:[^~/]|~[01])*)*$")

# The tier-0 codec exposes fixed demo schemas; ``record/v1`` has a ``timing``
# property with no nested shape rule.  Wrapping evidence in that property is
# how this module reuses the kernel's strict JSON gate (duplicate keys, bare
# nulls, nonfinite numbers, undeclared top-level properties).
_CODEC_GATE_SCHEMA = "record/v1"
_CODEC_GATE_KEY = "timing"

_BOOT_NS = time.monotonic_ns()

_REGISTRY_LOCK = threading.Lock()
_OWNER_LOCKS: dict[str, threading.RLock] = {}
_JOURNALS: dict[str, "_Journal"] = {}
_ACTIVE_JOURNAL: dict[str, str] = {}


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class EvidenceJournalError(Exception):
    """Base class for evidence-journal contract violations."""


class IngressAuthorityError(EvidenceJournalError):
    """A caller tried to submit server-assigned envelope authority."""


class AdmissionRejectedError(EvidenceJournalError, ValueError):
    """The manifest cannot be admitted as sequence 1 of a journal."""


class AdmissionConflictError(EvidenceJournalError):
    """A journal is already admitted, or a second admission was attempted."""


class JournalNotAdmittedError(EvidenceJournalError):
    """No admitted journal backs the requested identity."""


class JournalIntegrityError(EvidenceJournalError):
    """Stored events or a requested prefix do not verify."""


class InvalidEvidenceRefError(JournalIntegrityError):
    """An EvidenceRef journal/sequence/event id/hash/pointer does not agree."""


class InvalidMeasurementError(EvidenceJournalError, ValueError):
    """A submitted measurement violates kernel time/timing rules."""


class IntegrityIncidentError(JournalIntegrityError):
    """Conflicting content was delivered under an acknowledged producer key."""

    def __init__(self, incident: "IntegrityIncident") -> None:
        self.incident = incident
        super().__init__(
            "conflicting content for producer "
            f"{incident.producer_id!r} sequence {incident.producer_sequence}; "
            f"retained as integrity incident {incident.incident_id}"
        )


class ManifestPinError(EvidenceJournalError):
    """The event kind or producer is not pinned by the admitted manifest."""


class ProvenanceConflictError(JournalIntegrityError):
    """The authenticated assignment disagrees with the manifest pins."""


class RevisionConflictError(EvidenceJournalError):
    """The owner-local expected revision does not match the current revision."""

    def __init__(self, entity_id: str, current_revision: int, expected_revision: int) -> None:
        self.entity_id = entity_id
        self.current_revision = current_revision
        self.expected_revision = expected_revision
        super().__init__(
            f"entity {entity_id!r} is at revision {current_revision}, "
            f"not the expected revision {expected_revision}"
        )


class CommandConflictError(EvidenceJournalError):
    """An idempotency key was reused with different command content."""

    def __init__(self, command_id: str) -> None:
        self.command_id = command_id
        super().__init__(
            f"command {command_id!r} is already committed with different content; "
            "an idempotency key never becomes last-write-wins"
        )


class InvalidEventError(EvidenceJournalError, ValueError):
    """The submission is not a valid untrusted EventSubmission."""


class InvalidCommandError(EvidenceJournalError, ValueError):
    """The owner-local command envelope is malformed."""


# ---------------------------------------------------------------------------
# Kernel record types
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
        out: dict[str, Any] = {"value": None, "reason": self.reason}
        if self.detail is not None:
            out["detail"] = self.detail
        return out


NOT_APPLICABLE = Missing("not_applicable")
NOT_OBSERVED = Missing("not_observed")


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


def _is_missing_mapping(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    keys = set(value.keys())
    return (
        keys in ({"value", "reason"}, {"value", "reason", "detail"})
        and value.get("value") is None
    )


def _as_missing(value: Any) -> Missing | None:
    if isinstance(value, Missing):
        return value
    if isinstance(value, access_policy.Missing):
        return Missing(value.reason, value.detail)
    if _is_missing_mapping(value):
        return Missing(str(value["reason"]), value.get("detail"))
    return None


def _jsonable(value: Any, path: str = "$") -> Any:
    """Normalize a kernel value to strict, JSON-ready content.

    Dataclasses and Missing envelopes become plain mappings; bare nulls, raw
    bytes, non-string mapping keys, and nonfinite numbers are rejected.
    """
    missing = _as_missing(value)
    if missing is not None:
        return missing.to_dict()
    if value is None:
        raise InvalidEventError(
            f"bare null at {path}; use a typed Missing envelope"
        )
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise InvalidEventError(
                    f"non-string mapping key at {path}: {type(key).__name__}"
                )
            out[key] = _jsonable(item, f"{path}.{key}")
        return out
    if isinstance(value, (list, tuple)):
        return [_jsonable(item, f"{path}[{index}]") for index, item in enumerate(value)]
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise InvalidEventError(f"nonfinite number at {path}")
        return value
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray)):
        raise InvalidEventError(
            f"raw bytes at {path}; retain them as an artifact instead"
        )
    if is_dataclass(value) and not isinstance(value, type):
        return _jsonable(
            {item.name: getattr(value, item.name) for item in fields(value)}, path
        )
    raise InvalidEventError(
        f"value at {path} is not ordinary JSON content ({type(value).__name__})"
    )


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _canonical_text(value: Any) -> str:
    return _canonical_bytes(value).decode("utf-8")


def _strict_evidence(value: Any, path: str = "$") -> Any:
    """Validate arbitrary evidence through the kernel's strict JSON gate."""
    normalized = _jsonable(value, path)
    wrapper = {"id": "evidence_gate", _CODEC_GATE_KEY: normalized}
    try:
        contract_codec.validate_record(_canonical_bytes(wrapper), _CODEC_GATE_SCHEMA)
    except (ValueError, TypeError) as exc:  # pragma: no cover - defensive
        raise InvalidEventError(f"invalid evidence at {path}: {exc}") from exc
    return normalized


def _digest_of(value: Any) -> str:
    return str(contract_codec.canonical_digest(_canonical_bytes(value)))


def _new_event_id() -> str:
    return "evt_" + secrets.token_hex(12)


def _new_incident_id() -> str:
    return "inc_" + secrets.token_hex(12)


def _offset_ms() -> float:
    return round((time.monotonic_ns() - _BOOT_NS) / 1_000_000, 3)


def _utc_annotation() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@dataclass(frozen=True, slots=True)
class TimePoint:
    """A coordinate in one registered clock/boot lifetime (``K.TimePoint``)."""

    clock_id: str
    boot_id: str
    origin: str
    monotonic_offset_ms: float | int
    utc_annotation: Any = NOT_OBSERVED

    def __post_init__(self) -> None:
        _require_identifier(self.clock_id, "clock_id")
        _require_identifier(self.boot_id, "boot_id")
        if self.origin not in _MEASUREMENT_ORIGINS:
            raise ValueError(f"unknown measurement origin: {self.origin!r}")
        if isinstance(self.monotonic_offset_ms, bool) or not isinstance(
            self.monotonic_offset_ms, (int, float)
        ):
            raise TypeError("monotonic_offset_ms must be a number")
        if not math.isfinite(float(self.monotonic_offset_ms)):
            raise ValueError("monotonic_offset_ms must be finite")
        if self.monotonic_offset_ms < 0:
            raise ValueError("monotonic_offset_ms must be nonnegative")
        if _as_missing(self.utc_annotation) is None and not isinstance(
            self.utc_annotation, str
        ):
            raise ValueError("utc_annotation must be a date-time string or Missing")

    def to_dict(self) -> dict[str, Any]:
        utc = _as_missing(self.utc_annotation)
        return {
            "clock_id": self.clock_id,
            "boot_id": self.boot_id,
            "origin": self.origin,
            "monotonic_offset_ms": self.monotonic_offset_ms,
            "utc_annotation": utc.to_dict() if utc is not None else self.utc_annotation,
        }


@dataclass(frozen=True, slots=True)
class EvidenceRef:
    """A resolvable citation of one journal event or one of its JSON values."""

    journal_id: str
    sequence: int
    event_id: str
    event_hash: str
    pointer: str = ""

    def __post_init__(self) -> None:
        _require_identifier(self.journal_id, "journal_id")
        if isinstance(self.sequence, bool) or not isinstance(self.sequence, int):
            raise TypeError("EvidenceRef.sequence must be an int")
        if self.sequence < 1:
            raise ValueError("EvidenceRef.sequence must be a positive integer")
        _require_identifier(self.event_id, "event_id")
        _require_digest(self.event_hash, "event_hash")
        if not isinstance(self.pointer, str) or not _POINTER_RE.match(self.pointer):
            raise ValueError(
                "EvidenceRef.pointer must be an RFC 6901 JSON Pointer string"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "journal_id": self.journal_id,
            "sequence": self.sequence,
            "event_id": self.event_id,
            "event_hash": self.event_hash,
            "pointer": self.pointer,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "EvidenceRef":
        if not isinstance(data, Mapping):
            raise TypeError("EvidenceRef must be decoded from a mapping")
        keys = set(data.keys())
        if keys != {
            "journal_id",
            "sequence",
            "event_id",
            "event_hash",
            "pointer",
        }:
            raise ValueError(
                "EvidenceRef must contain exactly journal_id, sequence, "
                "event_id, event_hash, pointer"
            )
        return cls(
            journal_id=data["journal_id"],
            sequence=data["sequence"],
            event_id=data["event_id"],
            event_hash=data["event_hash"],
            pointer=data["pointer"],
        )


@dataclass(frozen=True, slots=True)
class JournalPrefix:
    """A nonempty, immutable journal prefix (``K.JournalPrefix``)."""

    journal_id: str
    last_sequence: int
    head_hash: str

    def __post_init__(self) -> None:
        _require_identifier(self.journal_id, "journal_id")
        if isinstance(self.last_sequence, bool) or not isinstance(
            self.last_sequence, int
        ):
            raise TypeError("JournalPrefix.last_sequence must be an int")
        if self.last_sequence < 1:
            raise ValueError(
                "JournalPrefix.last_sequence must be a positive integer; "
                "a prefix always starts at admission"
            )
        _require_digest(self.head_hash, "head_hash")


@dataclass(frozen=True, slots=True)
class EvidencePayload:
    """The client-supplied portion of an event (``K.EvidencePayload``)."""

    data: Mapping[str, Any]
    measurements: Sequence[Any] = ()
    evidence_refs: Sequence[Any] = ()
    artifact_refs: Sequence[Any] = ()


@dataclass(frozen=True, slots=True)
class EventSubmission:
    """Untrusted ingress shape (``K.EventSubmission``).

    The authenticated channel and the ingestion authority assign the journal
    envelope's identity, sequence, producer, provenance, role, assertion kind,
    receipt time, and hashes.  Nothing in this record is trusted authority.
    """

    producer_sequence: Any
    event_kind: str
    event_schema_version: str
    occurred_at: Any
    payload: Any

    def __post_init__(self) -> None:
        _require_identifier(self.event_kind, "event_kind")
        _require_identifier(self.event_schema_version, "event_schema_version")

    def to_mapping(self) -> dict[str, Any]:
        return {
            "producer_sequence": self.producer_sequence,
            "event_kind": self.event_kind,
            "event_schema_version": self.event_schema_version,
            "occurred_at": self.occurred_at,
            "payload": self.payload,
        }


@dataclass(frozen=True, slots=True)
class Manifest:
    """The complete immutable manifest pinned by journal sequence 1."""

    manifest_id: str
    run_id: str
    journal_id: str
    owner_domain: str
    commissioner_id: str
    activity: str
    attempt: Any
    execution: Any
    task: Any
    task_semantic_hash: str
    effective_configuration: Any
    environment: Any
    seed: Any
    build_pins: Sequence[Any]
    event_registry: Sequence[Any]
    producers: Sequence[Any]
    clocks: Sequence[Any]
    record_type: str = _MANIFEST_RECORD_TYPE
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": self.record_type,
            "schema_version": self.schema_version,
            "manifest_id": self.manifest_id,
            "run_id": self.run_id,
            "journal_id": self.journal_id,
            "owner_domain": self.owner_domain,
            "commissioner_id": self.commissioner_id,
            "activity": self.activity,
            "attempt": _jsonable(self.attempt, "manifest.attempt"),
            "execution": _jsonable(self.execution, "manifest.execution"),
            "task": _artifact_dict(self.task, "manifest.task"),
            "task_semantic_hash": self.task_semantic_hash,
            "effective_configuration": _artifact_dict(
                self.effective_configuration, "manifest.effective_configuration"
            ),
            "environment": _jsonable(self.environment, "manifest.environment"),
            "seed": _jsonable(self.seed, "manifest.seed"),
            "build_pins": [
                _jsonable(pin, f"manifest.build_pins[{index}]")
                for index, pin in enumerate(self.build_pins)
            ],
            "event_registry": [
                _jsonable(entry, f"manifest.event_registry[{index}]")
                for index, entry in enumerate(self.event_registry)
            ],
            "producers": [
                _jsonable(entry, f"manifest.producers[{index}]")
                for index, entry in enumerate(self.producers)
            ],
            "clocks": [
                _jsonable(entry, f"manifest.clocks[{index}]")
                for index, entry in enumerate(self.clocks)
            ],
        }


@dataclass(frozen=True, slots=True)
class JournalEnvelope:
    """One acknowledged, immutable journal event (``K.JournalEnvelope``)."""

    record_type: str
    schema_version: str
    run_id: str
    journal_id: str
    manifest_hash: str
    journal_sequence: int
    event_id: str
    event_kind: str
    event_schema_version: str
    role: str
    assertion_kind: str
    owner_domain: str
    producer_id: str
    producer_sequence: Any
    provenance: str
    evidence_scope: str
    recorded_at: TimePoint
    occurred_at: Any
    causal_refs: tuple[EvidenceRef, ...]
    payload_json: str
    previous_event_hash: Any
    event_hash: str

    @property
    def payload(self) -> dict[str, Any]:
        """Return a fresh decoded copy of the EvidencePayload mapping."""
        return json.loads(self.payload_json)

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": self.record_type,
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "journal_id": self.journal_id,
            "manifest_hash": self.manifest_hash,
            "journal_sequence": self.journal_sequence,
            "event_id": self.event_id,
            "event_kind": self.event_kind,
            "event_schema_version": self.event_schema_version,
            "role": self.role,
            "assertion_kind": self.assertion_kind,
            "owner_domain": self.owner_domain,
            "producer_id": self.producer_id,
            "producer_sequence": _serialize(self.producer_sequence),
            "provenance": self.provenance,
            "evidence_scope": self.evidence_scope,
            "recorded_at": self.recorded_at.to_dict(),
            "occurred_at": _serialize(self.occurred_at),
            "causal_refs": [ref.to_dict() for ref in self.causal_refs],
            "payload": self.payload,
            "previous_event_hash": _serialize(self.previous_event_hash),
            "event_hash": self.event_hash,
        }


def _serialize(value: Any) -> Any:
    if isinstance(value, TimePoint):
        return value.to_dict()
    missing = _as_missing(value)
    if missing is not None:
        return missing.to_dict()
    return value


@dataclass(frozen=True, slots=True)
class EntityState:
    """The owner-local authoritative state snapshot of one entity."""

    owner_domain: str
    entity_id: str
    revision: int
    state: Any  # ArtifactReference | Missing


@dataclass(frozen=True, slots=True)
class IntegrityIncident:
    """Retained evidence that two contents claimed one producer sequence."""

    incident_id: str
    journal_id: str
    producer_id: str
    producer_sequence: Any
    accepted_event_id: str
    accepted_event_hash: str
    accepted_content_digest: str
    observed_content_digest: str
    recorded_at: TimePoint
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "journal_id": self.journal_id,
            "producer_id": self.producer_id,
            "producer_sequence": _serialize(self.producer_sequence),
            "accepted_event_id": self.accepted_event_id,
            "accepted_event_hash": self.accepted_event_hash,
            "accepted_content_digest": self.accepted_content_digest,
            "observed_content_digest": self.observed_content_digest,
            "recorded_at": self.recorded_at.to_dict(),
            "detail": self.detail,
        }


# ---------------------------------------------------------------------------
# Internal journal state (copy-on-write; never mutated in place)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Delivery:
    content_digest: str
    journal_sequence: int


@dataclass(frozen=True, slots=True)
class _CommandReceipt:
    fingerprint: str
    response: JournalPrefix


@dataclass(frozen=True, slots=True)
class _Journal:
    journal_id: str
    run_id: str
    owner_domain: str
    manifest_hash: str
    manifest_ref: Any
    manifest: Mapping[str, Any]
    manifest_clocks: Mapping[Any, Mapping[str, Any]]
    manifest_producers: Mapping[str, Mapping[str, Any]]
    events: tuple[JournalEnvelope, ...]
    deliveries: Mapping[Any, _Delivery]
    revisions: Mapping[Any, int]
    states: Mapping[Any, Any]
    receipts: Mapping[Any, _CommandReceipt]
    clocks: Mapping[Any, Mapping[str, Any]]
    producer_registry: Mapping[str, Mapping[str, Any]]
    event_registry: Mapping[Any, Mapping[str, Any]]
    recorder_clock: tuple[str, str, str]
    incidents: tuple[IntegrityIncident, ...]


@dataclass(frozen=True, slots=True)
class _NormalizedSubmission:
    mapping: dict[str, Any]
    producer_sequence: Any
    occurred_at: Any
    payload: dict[str, Any]
    content_digest: str


def _owner_lock(owner_domain: str) -> threading.RLock:
    with _REGISTRY_LOCK:
        lock = _OWNER_LOCKS.get(owner_domain)
        if lock is None:
            lock = threading.RLock()
            _OWNER_LOCKS[owner_domain] = lock
        return lock


def _store_journal(journal: _Journal) -> None:
    with _REGISTRY_LOCK:
        _JOURNALS[journal.journal_id] = journal


def _get_journal(journal_id: str) -> _Journal:
    with _REGISTRY_LOCK:
        journal = _JOURNALS.get(journal_id)
    if journal is None:
        raise JournalNotAdmittedError(
            f"journal {journal_id!r} has no admitted manifest"
        )
    return journal


def _active_journal(owner_domain: str) -> _Journal:
    with _REGISTRY_LOCK:
        journal_id = _ACTIVE_JOURNAL.get(owner_domain)
        journal = _JOURNALS.get(journal_id) if journal_id else None
    if journal is None:
        raise JournalNotAdmittedError(
            f"owner domain {owner_domain!r} has no admitted journal; "
            "admit a manifest before appending evidence"
        )
    return journal


# ---------------------------------------------------------------------------
# Authorization helpers
# ---------------------------------------------------------------------------


def _authorize_write(channel_id: str, owner_domain: str, resource_id: str) -> Any:
    _require_identifier(owner_domain, "owner_domain")
    projection = access_policy.channel_projection(channel_id)
    if projection["axis"] != owner_domain:
        raise access_policy.GrantDeniedError(
            f"owner-local write required: channel axis {projection['axis']!r} "
            f"cannot write owner domain {owner_domain!r}"
        )
    grants = list(projection["grants"])
    if not grants:
        raise access_policy.GrantDeniedError(
            f"authenticated channel holds no write grant for {owner_domain!r}"
        )
    return access_policy.authorize(channel_id, grants[0], resource_id)


def _require_axis(projection: Mapping[str, Any], owner_domain: str) -> None:
    if projection["axis"] != owner_domain:
        raise access_policy.GrantDeniedError(
            f"owner-local access required: channel axis {projection['axis']!r} "
            f"cannot access owner domain {owner_domain!r}"
        )


# ---------------------------------------------------------------------------
# Artifact and clock validation helpers
# ---------------------------------------------------------------------------


def _artifact_dict(value: Any, field: str) -> dict[str, Any]:
    return _coerce_artifact_ref(value, field).to_dict()


def _coerce_artifact_ref(value: Any, field: str) -> Any:
    if isinstance(value, artifact_store.ArtifactReference):
        return value
    if isinstance(value, Mapping):
        try:
            return artifact_store.ArtifactReference.from_dict(dict(value))
        except (TypeError, ValueError) as exc:
            raise InvalidEventError(f"{field} is not an ArtifactReference: {exc}") from exc
    raise InvalidEventError(
        f"{field} must be an ArtifactReference, not {type(value).__name__}"
    )


def _coerce_timepoint(value: Any, field: str) -> Any:
    missing = _as_missing(value)
    if missing is not None:
        return missing
    if isinstance(value, TimePoint):
        return value
    if not isinstance(value, Mapping):
        raise InvalidEventError(
            f"{field} must be a TimePoint mapping or a typed Missing envelope"
        )
    data = _jsonable(value, field)
    if set(data.keys()) != TIME_POINT_FIELDS:
        raise InvalidEventError(
            f"{field} must contain exactly {sorted(TIME_POINT_FIELDS)}"
        )
    if _as_missing(data["utc_annotation"]) is None and not isinstance(
        data["utc_annotation"], str
    ):
        raise InvalidEventError(
            f"{field}.utc_annotation must be a date-time string or Missing"
        )
    try:
        return TimePoint(
            clock_id=data["clock_id"],
            boot_id=data["boot_id"],
            origin=data["origin"],
            monotonic_offset_ms=data["monotonic_offset_ms"],
            utc_annotation=data["utc_annotation"],
        )
    except (TypeError, ValueError) as exc:
        raise InvalidEventError(f"{field} is not a valid TimePoint: {exc}") from exc


def _validate_timepoint(
    timepoint: Any, clocks: Mapping[Any, Mapping[str, Any]], field: str
) -> None:
    missing = _as_missing(timepoint)
    if missing is not None:
        if missing.reason == "manual_override":
            raise InvalidEventError(
                f"{field} cannot claim a manual_override without an "
                "authenticated journaled operator decision"
            )
        return
    key = (timepoint.clock_id, timepoint.boot_id)
    descriptor = clocks.get(key)
    if descriptor is None:
        raise InvalidEventError(
            f"{field} names unregistered clock/boot {key}; register the clock "
            "in the manifest or a clock_registered event"
        )
    if descriptor["origin"] != timepoint.origin:
        raise InvalidEventError(
            f"{field}.origin {timepoint.origin!r} disagrees with the registered "
            f"clock origin {descriptor['origin']!r}"
        )


def _validate_clock_descriptor(value: Any) -> dict[str, Any]:
    data = _jsonable(value, "clock")
    if set(data.keys()) != CLOCK_FIELDS:
        raise InvalidEventError(
            f"ClockDescriptor must contain exactly {sorted(CLOCK_FIELDS)}"
        )
    for field in ("clock_id", "boot_id", "source_id"):
        try:
            _require_identifier(data[field], f"clock.{field}")
        except (TypeError, ValueError) as exc:
            raise InvalidEventError(str(exc)) from exc
    if data["origin"] not in _MEASUREMENT_ORIGINS:
        raise InvalidEventError(f"unknown clock origin: {data['origin']!r}")
    if data["basis"] not in contract_codec.VALID_CLOCK_BASES:
        raise InvalidEventError(f"unknown clock basis: {data['basis']!r}")
    if data["unit"] != "ms":
        raise InvalidEventError("ClockDescriptor.unit must be 'ms'")
    return data


def _validate_producer_descriptor(
    value: Any, owner_domain: str
) -> dict[str, Any]:
    data = _jsonable(value, "producer")
    if set(data.keys()) != PRODUCER_FIELDS:
        raise InvalidEventError(
            f"ProducerDescriptor must contain exactly {sorted(PRODUCER_FIELDS)}"
        )
    for field in ("producer_id", "principal_id", "owner_domain"):
        try:
            _require_identifier(data[field], f"producer.{field}")
        except (TypeError, ValueError) as exc:
            raise InvalidEventError(str(exc)) from exc
    if data["owner_domain"] != owner_domain:
        raise InvalidEventError(
            f"producer {data['producer_id']!r} belongs to owner domain "
            f"{data['owner_domain']!r}, not this journal's {owner_domain!r}"
        )
    if data["role"] not in access_policy.PRODUCER_ROLES:
        raise InvalidEventError(f"unknown producer role: {data['role']!r}")
    if data["provenance"] not in access_policy.PROVENANCES:
        raise InvalidEventError(f"unknown provenance: {data['provenance']!r}")
    if type(data["sequence_required"]) is not bool:
        raise InvalidEventError("producer.sequence_required must be a bool")
    kinds = data["allowed_event_kinds"]
    if not isinstance(kinds, list) or not kinds:
        raise InvalidEventError(
            "producer.allowed_event_kinds requires at least one event kind"
        )
    for kind in kinds:
        try:
            _require_identifier(kind, "producer.allowed_event_kinds")
        except (TypeError, ValueError) as exc:
            raise InvalidEventError(str(exc)) from exc
    if len(set(kinds)) != len(kinds):
        raise InvalidEventError("producer.allowed_event_kinds must be unique")
    return data


def _validate_event_kind_entry(
    value: Any, owner_domain: str
) -> dict[str, Any]:
    data = _jsonable(value, "event_kind")
    keys = set(data.keys())
    if not EVENT_KIND_FIELDS <= keys or keys - (EVENT_KIND_FIELDS | {"owner_domain"}):
        raise InvalidEventError(
            "EventKindDeclaration must contain exactly "
            f"{sorted(EVENT_KIND_FIELDS)} (owner_domain optional)"
        )
    try:
        _require_identifier(data["event_kind"], "event_kind.event_kind")
        _require_identifier(
            data["event_schema_version"], "event_kind.event_schema_version"
        )
    except (TypeError, ValueError) as exc:
        raise InvalidEventError(str(exc)) from exc
    if data["role"] not in access_policy.EVENT_ROLES:
        raise InvalidEventError(f"unknown event role: {data['role']!r}")
    if data["assertion_kind"] not in access_policy.ASSERTION_KINDS:
        raise InvalidEventError(
            f"unknown assertion kind: {data['assertion_kind']!r}"
        )
    if "owner_domain" in data:
        if data["owner_domain"] != owner_domain:
            raise InvalidEventError(
                "event kind belongs to owner domain "
                f"{data['owner_domain']!r}, not {owner_domain!r}"
            )
    roles = data["writer_roles"]
    if not isinstance(roles, list) or not roles:
        raise InvalidEventError("event_kind.writer_roles requires at least one role")
    for role in roles:
        if role not in access_policy.PRODUCER_ROLES:
            raise InvalidEventError(f"unknown writer role: {role!r}")
    if len(set(roles)) != len(roles):
        raise InvalidEventError("event_kind.writer_roles must be unique")
    if (
        data["assertion_kind"] == "authoritative_effect"
        and owner_domain == "attempt.application"
        and set(roles) != {"application_origin"}
    ):
        raise InvalidEventError(
            "application authoritative_effect entries admit application_origin only"
        )
    return data


# ---------------------------------------------------------------------------
# JSON Pointer and evidence resolution
# ---------------------------------------------------------------------------


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


def _assert_ref_resolves(
    ref: EvidenceRef,
    journal: _Journal,
    *,
    before_sequence: int,
    events: Sequence[JournalEnvelope],
    where: str,
) -> None:
    """Resolve a citation that names this journal.

    Citations of another owner's journal are structurally validated here and
    resolved by that journal's owner; a cross-owner citation is never read
    across the owner boundary by this module.
    """
    if ref.journal_id != journal.journal_id:
        return
    if ref.sequence >= before_sequence:
        raise InvalidEvidenceRefError(
            f"{where}: citation of journal sequence {ref.sequence} is not "
            f"earlier than sequence {before_sequence}; an event never cites "
            "itself or a future event"
        )
    if ref.sequence < 1 or ref.sequence > len(events):
        raise InvalidEvidenceRefError(
            f"{where}: citation of journal sequence {ref.sequence} does not "
            "resolve in the acknowledged prefix"
        )
    target = events[ref.sequence - 1]
    if target.event_id != ref.event_id:
        raise InvalidEvidenceRefError(
            f"{where}: event id {ref.event_id!r} does not name sequence "
            f"{ref.sequence} (stored id {target.event_id!r})"
        )
    if target.event_hash != ref.event_hash:
        raise InvalidEvidenceRefError(
            f"{where}: event hash {ref.event_hash} does not match the stored "
            f"hash {target.event_hash} at sequence {ref.sequence}"
        )
    if not _pointer_resolves(target.to_dict(), ref.pointer):
        raise InvalidEvidenceRefError(
            f"{where}: JSON pointer {ref.pointer!r} does not resolve in "
            f"journal sequence {ref.sequence}"
        )


# ---------------------------------------------------------------------------
# Submission / payload normalization
# ---------------------------------------------------------------------------


def _raw_submission_mapping(submission: Any) -> dict[str, Any]:
    if isinstance(submission, JournalEnvelope):
        raise IngressAuthorityError(
            "JournalEnvelope is a durable record, not untrusted ingress; "
            "submit an EventSubmission"
        )
    if isinstance(submission, EventSubmission):
        return submission.to_mapping()
    if isinstance(submission, Mapping):
        return dict(submission)
    raise InvalidEventError(
        "an EventSubmission mapping is required, "
        f"not {type(submission).__name__}"
    )


def _normalize_payload(
    payload: Any,
    *,
    journal: _Journal,
    channel_id: str,
    where: str,
) -> dict[str, Any]:
    if isinstance(payload, EvidencePayload):
        raw: Mapping[str, Any] = {
            "data": payload.data,
            "measurements": payload.measurements,
            "evidence_refs": payload.evidence_refs,
            "artifact_refs": payload.artifact_refs,
        }
    elif isinstance(payload, Mapping):
        raw = payload
    else:
        raise InvalidEventError(f"{where}: payload must be an EvidencePayload mapping")

    if set(raw.keys()) != PAYLOAD_FIELDS:
        raise InvalidEventError(
            f"{where}: payload must contain exactly {sorted(PAYLOAD_FIELDS)}"
        )

    data = _strict_evidence(raw["data"], f"{where}.data")
    if not isinstance(data, Mapping):
        raise InvalidEventError(f"{where}.data must be an EvidenceMap mapping")

    measurements_raw = raw["measurements"]
    if isinstance(measurements_raw, (str, bytes)) or not isinstance(
        measurements_raw, Sequence
    ):
        raise InvalidEventError(f"{where}.measurements must be a sequence")
    measurements: list[dict[str, Any]] = []
    clocks = tuple(journal.clocks.values())
    for index, measurement in enumerate(measurements_raw):
        normalized = _jsonable(measurement, f"{where}.measurements[{index}]")
        try:
            contract_codec.validate_measurement(normalized, clocks)
        except (TypeError, ValueError) as exc:
            raise InvalidMeasurementError(
                f"{where}.measurements[{index}]: {exc}"
            ) from exc
        measurements.append(normalized)

    refs_raw = raw["evidence_refs"]
    if isinstance(refs_raw, (str, bytes)) or not isinstance(refs_raw, Sequence):
        raise InvalidEventError(f"{where}.evidence_refs must be a sequence")
    evidence_refs: list[dict[str, Any]] = []
    for index, ref_value in enumerate(refs_raw):
        try:
            ref = (
                ref_value
                if isinstance(ref_value, EvidenceRef)
                else EvidenceRef.from_dict(_jsonable(ref_value))
            )
        except (TypeError, ValueError) as exc:
            raise InvalidEvidenceRefError(
                f"{where}.evidence_refs[{index}]: {exc}"
            ) from exc
        _assert_ref_resolves(
            ref,
            journal,
            before_sequence=len(journal.events) + 1,
            events=journal.events,
            where=f"{where}.evidence_refs[{index}]",
        )
        evidence_refs.append(ref.to_dict())

    artifacts_raw = raw["artifact_refs"]
    if isinstance(artifacts_raw, (str, bytes)) or not isinstance(
        artifacts_raw, Sequence
    ):
        raise InvalidEventError(f"{where}.artifact_refs must be a sequence")
    artifact_refs: list[dict[str, Any]] = []
    seen_digests: set[str] = set()
    for index, ref_value in enumerate(artifacts_raw):
        ref = _coerce_artifact_ref(ref_value, f"{where}.artifact_refs[{index}]")
        if ref.digest in seen_digests:
            raise InvalidEventError(
                f"{where}.artifact_refs has duplicate digest {ref.digest}"
            )
        seen_digests.add(ref.digest)
        artifact_store.resolve_artifact(channel_id, ref)
        artifact_refs.append(ref.to_dict())

    for digest, pointer in _nested_artifact_identities(data):
        if digest not in seen_digests:
            raise InvalidEventError(
                f"{where}.data references artifact {digest} at {pointer} "
                "but artifact_refs omits it"
            )

    return {
        "data": data,
        "measurements": measurements,
        "evidence_refs": evidence_refs,
        "artifact_refs": artifact_refs,
    }


def _nested_artifact_identities(
    node: Any, path: str = "$.data"
) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    if isinstance(node, Mapping):
        if set(node.keys()) == ARTIFACT_REF_FIELDS:
            digest = node.get("digest")
            if isinstance(digest, str) and _DIGEST_RE.match(digest):
                found.append((digest, path))
        for key, value in node.items():
            found.extend(_nested_artifact_identities(value, f"{path}.{key}"))
    elif isinstance(node, (list, tuple)):
        for index, value in enumerate(node):
            found.extend(_nested_artifact_identities(value, f"{path}[{index}]"))
    return found


def _normalize_submission(
    raw: Mapping[str, Any],
    *,
    journal: _Journal,
    descriptor: Any,
    channel_id: str,
    where: str,
) -> _NormalizedSubmission:
    if set(raw.keys()) != SUBMISSION_FIELDS:
        raise InvalidEventError(
            f"{where}: EventSubmission must contain exactly {sorted(SUBMISSION_FIELDS)}"
        )
    try:
        _require_identifier(raw["event_kind"], "event_kind")
        _require_identifier(
            raw["event_schema_version"], "event_schema_version"
        )
    except (TypeError, ValueError) as exc:
        raise InvalidEventError(f"{where}: {exc}") from exc

    sequence_raw = raw["producer_sequence"]
    sequence_missing = _as_missing(sequence_raw)
    if sequence_missing is not None:
        if descriptor.sequence_required:
            raise InvalidEventError(
                f"{where}: registered producer {descriptor.producer_id!r} "
                "requires a positive producer_sequence"
            )
        producer_sequence: Any = sequence_missing
    elif isinstance(sequence_raw, bool) or not isinstance(sequence_raw, int):
        raise InvalidEventError(
            f"{where}: producer_sequence must be a positive integer or a "
            "typed Missing envelope"
        )
    elif sequence_raw < 1:
        raise InvalidEventError(
            f"{where}: producer_sequence must be a positive integer"
        )
    else:
        producer_sequence = sequence_raw

    occurred_at = _coerce_timepoint(raw["occurred_at"], f"{where}.occurred_at")
    _validate_timepoint(occurred_at, journal.clocks, f"{where}.occurred_at")

    payload = _normalize_payload(
        raw["payload"], journal=journal, channel_id=channel_id, where=where
    )

    mapping = {
        "producer_sequence": (
            producer_sequence.to_dict()
            if isinstance(producer_sequence, Missing)
            else producer_sequence
        ),
        "event_kind": raw["event_kind"],
        "event_schema_version": raw["event_schema_version"],
        "occurred_at": _serialize(occurred_at),
        "payload": payload,
    }
    _strict_evidence(mapping, where)
    return _NormalizedSubmission(
        mapping=mapping,
        producer_sequence=producer_sequence,
        occurred_at=occurred_at,
        payload=payload,
        content_digest=_digest_of(mapping),
    )


# ---------------------------------------------------------------------------
# Manifest admission
# ---------------------------------------------------------------------------


def _coerce_manifest(value: Any) -> Manifest:
    if isinstance(value, JournalEnvelope):
        raise IngressAuthorityError(
            "JournalEnvelope is a durable record, not an admission input"
        )
    if isinstance(value, Manifest):
        return value
    if not isinstance(value, Mapping):
        raise AdmissionRejectedError(
            f"manifest must be a Manifest, not {type(value).__name__}"
        )
    raw = _jsonable(value, "manifest")
    names = {item.name for item in fields(Manifest)}
    required = names - {"record_type", "schema_version"}
    missing = sorted(required - set(raw.keys()))
    if missing:
        raise AdmissionRejectedError(
            f"manifest is missing required fields: {missing}"
        )
    unknown = sorted(set(raw.keys()) - names)
    if unknown:
        raise AdmissionRejectedError(
            f"manifest has undeclared properties: {unknown}"
        )
    try:
        return Manifest(**raw)
    except (TypeError, ValueError) as exc:
        raise AdmissionRejectedError(f"invalid manifest: {exc}") from exc


def _validate_manifest(
    manifest: Manifest, manifest_dict: Mapping[str, Any], owner_domain: str
) -> tuple[
    dict[Any, dict[str, Any]],
    dict[str, dict[str, Any]],
    dict[Any, dict[str, Any]],
]:
    if manifest_dict["record_type"] != _MANIFEST_RECORD_TYPE:
        raise AdmissionRejectedError("manifest.record_type must be 'manifest'")
    if manifest_dict["schema_version"] != SCHEMA_VERSION:
        raise AdmissionRejectedError(
            f"manifest.schema_version must be {SCHEMA_VERSION!r}"
        )
    for field in (
        "manifest_id",
        "run_id",
        "journal_id",
        "owner_domain",
        "commissioner_id",
    ):
        try:
            _require_identifier(manifest_dict[field], f"manifest.{field}")
        except (TypeError, ValueError) as exc:
            raise AdmissionRejectedError(str(exc)) from exc
    if manifest_dict["owner_domain"] != owner_domain:
        raise AdmissionRejectedError(
            f"manifest owner domain {manifest_dict['owner_domain']!r} does not "
            f"match the authenticated owner domain {owner_domain!r}"
        )
    if manifest_dict["activity"] not in _ACTIVITIES:
        raise AdmissionRejectedError(
            f"unknown manifest activity: {manifest_dict['activity']!r}"
        )

    activity = manifest_dict["activity"]
    attempt = manifest_dict["attempt"]
    attempt_missing = _as_missing(attempt)
    if activity == "discovery":
        if attempt_missing is None or attempt_missing.reason != "not_applicable":
            raise AdmissionRejectedError(
                "a discovery manifest must carry Missing(not_applicable) for "
                "the application attempt"
            )
    elif activity == "application_attempt":
        if attempt_missing is not None:
            raise AdmissionRejectedError(
                "an application_attempt manifest must declare the attempt context"
            )
    if attempt_missing is None:
        attempt_data = _jsonable(attempt, "manifest.attempt")
        if set(attempt_data.keys()) != ATTEMPT_FIELDS:
            raise AdmissionRejectedError(
                f"manifest.attempt must contain exactly {sorted(ATTEMPT_FIELDS)}"
            )
        if attempt_data["kind"] not in _ATTEMPT_KINDS:
            raise AdmissionRejectedError(
                f"unknown attempt kind: {attempt_data['kind']!r}"
            )
        if attempt_data["target_class"] not in _TARGET_CLASSES:
            raise AdmissionRejectedError(
                f"unknown target class: {attempt_data['target_class']!r}"
            )
        if attempt_data["evaluation_partition"] not in _EVALUATION_PARTITIONS:
            raise AdmissionRejectedError(
                "unknown evaluation partition: "
                f"{attempt_data['evaluation_partition']!r}"
            )
        for field in ("rehearsal_of", "performance_of", "derived_from"):
            links = attempt_data[field]
            if not isinstance(links, list):
                raise AdmissionRejectedError(
                    f"manifest.attempt.{field} must be an array"
                )
            for link in links:
                if (
                    not isinstance(link, Mapping)
                    or set(link.keys()) != ATTEMPT_REFERENCE_FIELDS
                ):
                    raise AdmissionRejectedError(
                        f"manifest.attempt.{field} entries must be "
                        "AttemptReference records"
                    )
                if link["kind"] not in _ATTEMPT_KINDS:
                    raise AdmissionRejectedError(
                        f"unknown attempt reference kind: {link['kind']!r}"
                    )
                try:
                    _require_identifier(link["attempt_id"], "attempt_id")
                except (TypeError, ValueError) as exc:
                    raise AdmissionRejectedError(str(exc)) from exc

    execution = manifest_dict["execution"]
    if not isinstance(execution, Mapping):
        raise AdmissionRejectedError("manifest.execution must be a mapping")
    if set(execution.keys()) != EXECUTION_FIELDS:
        raise AdmissionRejectedError(
            f"manifest.execution must contain exactly {sorted(EXECUTION_FIELDS)}"
        )
    if execution["mode"] not in _EXECUTION_MODES:
        raise AdmissionRejectedError(
            f"unknown execution mode: {execution['mode']!r}"
        )
    if execution["mode"] in ("manual", "service"):
        subject_missing = _as_missing(execution["subject"])
        if subject_missing is None or subject_missing.reason != "not_applicable":
            raise AdmissionRejectedError(
                f"execution mode {execution['mode']!r} requires "
                "Missing(not_applicable) for the subject"
            )
    if execution["mode"] == "manual":
        for field in ("connector_version", "binding_version"):
            missing = _as_missing(execution[field])
            if missing is None or missing.reason != "not_applicable":
                raise AdmissionRejectedError(
                    f"manual execution requires Missing(not_applicable) for {field}"
                )
    assistance = execution["assistance"]
    if not isinstance(assistance, Mapping) or set(assistance.keys()) != ASSISTANCE_FIELDS:
        raise AdmissionRejectedError(
            f"manifest.execution.assistance must contain exactly "
            f"{sorted(ASSISTANCE_FIELDS)}"
        )
    if assistance["planning_owner"] not in _PLANNING_OWNERS:
        raise AdmissionRejectedError(
            f"unknown planning owner: {assistance['planning_owner']!r}"
        )
    try:
        _require_identifier(assistance["assistance_track"], "assistance_track")
    except (TypeError, ValueError) as exc:
        raise AdmissionRejectedError(str(exc)) from exc
    if _as_missing(assistance["planner_identity"]) is None:
        try:
            _require_identifier(assistance["planner_identity"], "planner_identity")
        except (TypeError, ValueError) as exc:
            raise AdmissionRejectedError(str(exc)) from exc
    plan_missing = _as_missing(assistance["plan"])
    if plan_missing is None:
        _coerce_artifact_ref(assistance["plan"], "assistance.plan")
    if type(assistance["online_replanning"]) is not bool:
        raise AdmissionRejectedError(
            "assistance.online_replanning must be a bool"
        )
    if not isinstance(assistance["description"], str) or not assistance["description"]:
        raise AdmissionRejectedError(
            "assistance.description must be a nonempty string"
        )

    try:
        _require_digest(manifest_dict["task_semantic_hash"], "task_semantic_hash")
    except (TypeError, ValueError) as exc:
        raise AdmissionRejectedError(str(exc)) from exc
    if _as_missing(manifest_dict["seed"]) is None:
        try:
            _require_identifier(manifest_dict["seed"], "seed")
        except (TypeError, ValueError) as exc:
            raise AdmissionRejectedError(str(exc)) from exc
    if not isinstance(manifest_dict["environment"], Mapping):
        raise AdmissionRejectedError("manifest.environment must be an EvidenceMap")
    _coerce_artifact_ref(manifest_dict["task"], "manifest.task")
    _coerce_artifact_ref(
        manifest_dict["effective_configuration"], "manifest.effective_configuration"
    )

    pins = manifest_dict["build_pins"]
    if not isinstance(pins, list) or not pins:
        raise AdmissionRejectedError("manifest.build_pins requires at least one pin")
    for index, pin in enumerate(pins):
        if not isinstance(pin, Mapping) or set(pin.keys()) != VERSION_PIN_FIELDS:
            raise AdmissionRejectedError(
                f"manifest.build_pins[{index}] must be a VersionPin"
            )
        try:
            _require_identifier(pin["id"], "build_pin.id")
            _require_identifier(pin["version"], "build_pin.version")
            _require_digest(pin["artifact_digest"], "build_pin.artifact_digest")
        except (TypeError, ValueError) as exc:
            raise AdmissionRejectedError(str(exc)) from exc

    registry_raw = manifest_dict["event_registry"]
    if not isinstance(registry_raw, list) or not registry_raw:
        raise AdmissionRejectedError(
            "manifest.event_registry requires at least one declaration"
        )
    registry: dict[Any, dict[str, Any]] = {}
    for index, entry in enumerate(registry_raw):
        data = _validate_event_kind_entry(entry, owner_domain)
        key = (data["event_kind"], data["event_schema_version"])
        if key in registry:
            raise AdmissionRejectedError(
                f"duplicate event kind declaration {key}"
            )
        registry[key] = data

    producers_raw = manifest_dict["producers"]
    if not isinstance(producers_raw, list) or not producers_raw:
        raise AdmissionRejectedError(
            "manifest.producers requires at least one registered producer"
        )
    producers: dict[str, dict[str, Any]] = {}
    known_kinds = {kind for kind, _version in registry}
    for index, entry in enumerate(producers_raw):
        data = _validate_producer_descriptor(entry, owner_domain)
        if data["producer_id"] in producers:
            raise AdmissionRejectedError(
                f"duplicate producer id {data['producer_id']!r}"
            )
        for kind in data["allowed_event_kinds"]:
            if kind not in known_kinds:
                raise AdmissionRejectedError(
                    f"producer {data['producer_id']!r} allows event kind "
                    f"{kind!r} that the manifest event registry does not declare"
                )
        producers[data["producer_id"]] = data

    clocks_raw = manifest_dict["clocks"]
    if not isinstance(clocks_raw, list) or not clocks_raw:
        raise AdmissionRejectedError(
            "manifest.clocks requires at least one registered clock"
        )
    clocks: dict[Any, dict[str, Any]] = {}
    for index, entry in enumerate(clocks_raw):
        data = _validate_clock_descriptor(entry)
        key = (data["clock_id"], data["boot_id"])
        if key in clocks:
            raise AdmissionRejectedError(f"duplicate clock/boot {key}")
        clocks[key] = data

    return registry, producers, clocks


def admit_manifest(channel_id: str, manifest: Manifest) -> JournalEnvelope:
    """Admit ``manifest`` and pin it as journal sequence 1.

    The manifest's task and effective-configuration artifacts must already be
    durably installed.  The complete canonical manifest is retained as a
    restricted artifact; its exact digest becomes ``manifest_hash`` for every
    event in the journal.

    Admission selects this journal as the owner domain's append target; a
    later admission for the same owner domain selects the newer journal, while
    every acknowledged prefix remains readable by its own journal id.
    """
    try:
        coerced = _coerce_manifest(manifest)
    except AdmissionRejectedError:
        raise
    except (InvalidEventError, TypeError, ValueError) as exc:
        raise AdmissionRejectedError(f"invalid manifest: {exc}") from exc
    try:
        manifest_dict = coerced.to_dict()
    except (InvalidEventError, TypeError, ValueError) as exc:
        raise AdmissionRejectedError(f"invalid manifest: {exc}") from exc
    owner_domain = coerced.owner_domain
    try:
        _require_identifier(owner_domain, "manifest.owner_domain")
        _require_identifier(coerced.journal_id, "manifest.journal_id")
        _require_identifier(coerced.manifest_id, "manifest.manifest_id")
    except (TypeError, ValueError) as exc:
        raise AdmissionRejectedError(str(exc)) from exc

    lock = _owner_lock(owner_domain)
    with lock:
        descriptor = _authorize_write(
            channel_id, owner_domain, coerced.manifest_id
        )
        if descriptor.provenance != "server":
            raise AdmissionRejectedError(
                "manifest admission is a server control-plane operation; "
                f"authenticated provenance is {descriptor.provenance!r}"
            )
        registry, producers, clocks = _validate_manifest(
            coerced, manifest_dict, owner_domain
        )
        producer_entry = producers.get(descriptor.producer_id)
        if producer_entry is None:
            raise AdmissionRejectedError(
                f"admitting producer {descriptor.producer_id!r} is not registered "
                "in the manifest producer registry"
            )
        if producer_entry["role"] != descriptor.role:
            raise ProvenanceConflictError(
                f"manifest producer role {producer_entry['role']!r} does not "
                f"match the authenticated role {descriptor.role!r}"
            )
        if producer_entry["provenance"] != descriptor.provenance:
            raise ProvenanceConflictError(
                "manifest producer provenance does not match the authenticated "
                "registration"
            )

        task_ref = _coerce_artifact_ref(coerced.task, "manifest.task")
        config_ref = _coerce_artifact_ref(
            coerced.effective_configuration, "manifest.effective_configuration"
        )
        for label, ref in (
            ("task", task_ref),
            ("effective_configuration", config_ref),
        ):
            if ref.owner_domain != owner_domain:
                raise AdmissionRejectedError(
                    f"manifest.{label} belongs to owner domain "
                    f"{ref.owner_domain!r}, not {owner_domain!r}"
                )
            artifact_store.resolve_artifact(channel_id, ref)

        with _REGISTRY_LOCK:
            if coerced.journal_id in _JOURNALS:
                raise AdmissionConflictError(
                    f"journal {coerced.journal_id!r} is already admitted; "
                    "acknowledged prefixes are never re-admitted or resequenced"
                )

        manifest_bytes = _canonical_bytes(manifest_dict)
        try:
            contract_codec.validate_record(
                _canonical_bytes(
                    {"id": coerced.manifest_id, _CODEC_GATE_KEY: manifest_dict}
                ),
                _CODEC_GATE_SCHEMA,
            )
        except (TypeError, ValueError) as exc:
            raise AdmissionRejectedError(
                f"manifest is not strict JSON evidence: {exc}"
            ) from exc
        manifest_hash = str(contract_codec.canonical_digest(manifest_bytes))
        manifest_ref = artifact_store.retain_artifact(
            channel_id,
            owner_domain,
            "application/json",
            manifest_bytes,
            "restricted",
        )
        if manifest_ref.digest != manifest_hash:
            raise AdmissionRejectedError(
                "manifest artifact digest does not match its canonical digest"
            )
        artifact_store.resolve_artifact(channel_id, manifest_ref)

        engine_clocks = [
            clock
            for clock in clocks.values()
            if clock["origin"] == "engine_measured"
        ]
        if not engine_clocks:
            raise AdmissionRejectedError(
                "manifest.clocks must register an engine_measured recorder clock"
            )
        recorder = engine_clocks[0]
        recorder_clock = (
            recorder["clock_id"],
            recorder["boot_id"],
            recorder["origin"],
        )

        payload = {
            "data": {"manifest": manifest_ref.to_dict()},
            "measurements": [],
            "evidence_refs": [],
            "artifact_refs": [manifest_ref.to_dict()],
        }
        envelope = JournalEnvelope(
            record_type=_ENVELOPE_RECORD_TYPE,
            schema_version=SCHEMA_VERSION,
            run_id=coerced.run_id,
            journal_id=coerced.journal_id,
            manifest_hash=manifest_hash,
            journal_sequence=1,
            event_id=_new_event_id(),
            event_kind=_MANIFEST_EVENT_KIND,
            event_schema_version=SCHEMA_VERSION,
            role="external_input",
            assertion_kind="observation",
            owner_domain=owner_domain,
            producer_id=descriptor.producer_id,
            producer_sequence=NOT_APPLICABLE,
            provenance="server",
            evidence_scope="current_run",
            recorded_at=_recorded_at(recorder_clock),
            occurred_at=NOT_APPLICABLE,
            causal_refs=(),
            payload_json=_canonical_text(payload),
            previous_event_hash=NOT_APPLICABLE,
            event_hash="",
        )
        envelope = replace(envelope, event_hash=_envelope_hash(envelope))

        journal = _Journal(
            journal_id=coerced.journal_id,
            run_id=coerced.run_id,
            owner_domain=owner_domain,
            manifest_hash=manifest_hash,
            manifest_ref=manifest_ref,
            manifest=manifest_dict,
            manifest_clocks=clocks,
            manifest_producers=producers,
            events=(envelope,),
            deliveries={},
            revisions={},
            states={},
            receipts={},
            clocks=clocks,
            producer_registry=producers,
            event_registry=registry,
            recorder_clock=recorder_clock,
            incidents=(),
        )
        _verify_prefix(journal, JournalPrefix(coerced.journal_id, 1, envelope.event_hash))
        with _REGISTRY_LOCK:
            if coerced.journal_id in _JOURNALS:
                raise AdmissionConflictError(
                    f"journal {coerced.journal_id!r} is already admitted; "
                    "acknowledged prefixes are never re-admitted or resequenced"
                )
            _JOURNALS[coerced.journal_id] = journal
            _ACTIVE_JOURNAL[owner_domain] = coerced.journal_id
        return envelope


def _recorded_at(recorder_clock: tuple[str, str, str]) -> TimePoint:
    clock_id, boot_id, origin = recorder_clock
    return TimePoint(
        clock_id=clock_id,
        boot_id=boot_id,
        origin=origin,
        monotonic_offset_ms=_offset_ms(),
        utc_annotation=_utc_annotation(),
    )


def _envelope_hash(envelope: JournalEnvelope) -> str:
    body = envelope.to_dict()
    body.pop("event_hash", None)
    return str(contract_codec.canonical_digest(_canonical_bytes(body)))


# ---------------------------------------------------------------------------
# Manifest pin checks and registration events
# ---------------------------------------------------------------------------


def _producer_pin(journal: _Journal, producer_id: str) -> Mapping[str, Any]:
    entry = journal.producer_registry.get(producer_id)
    if entry is None:
        raise ManifestPinError(
            f"producer {producer_id!r} is not registered in the admitted manifest"
        )
    return entry


def _event_pin(
    journal: _Journal, event_kind: str, event_schema_version: str
) -> Mapping[str, Any]:
    entry = journal.event_registry.get((event_kind, event_schema_version))
    if entry is None:
        raise ManifestPinError(
            f"event kind {event_kind!r} version {event_schema_version!r} is not "
            "declared in the admitted manifest event registry"
        )
    return entry


def _preflight_pins(
    journal: _Journal,
    descriptor: Any,
    normalized: _NormalizedSubmission,
    where: str,
) -> Mapping[str, Any]:
    kind = normalized.mapping["event_kind"]
    version = normalized.mapping["event_schema_version"]
    if kind == _MANIFEST_EVENT_KIND:
        raise AdmissionConflictError(
            f"{where}: a second manifest_admitted event is never admitted; "
            "admission is only journal sequence 1"
        )
    producer_entry = _producer_pin(journal, descriptor.producer_id)
    if producer_entry["role"] != descriptor.role:
        raise ProvenanceConflictError(
            f"{where}: manifest producer role {producer_entry['role']!r} does not "
            f"match the authenticated role {descriptor.role!r}"
        )
    if producer_entry["provenance"] != descriptor.provenance:
        raise ProvenanceConflictError(
            f"{where}: manifest producer provenance does not match the "
            "authenticated registration"
        )
    if producer_entry["sequence_required"] is not descriptor.sequence_required:
        raise ProvenanceConflictError(
            f"{where}: manifest sequence_required does not match the authenticated "
            "producer registration"
        )
    if kind not in producer_entry["allowed_event_kinds"]:
        raise ManifestPinError(
            f"{where}: event kind {kind!r} is outside producer "
            f"{descriptor.producer_id!r}'s manifest write grant"
        )
    entry = _event_pin(journal, kind, version)
    if descriptor.role not in entry["writer_roles"]:
        raise ManifestPinError(
            f"{where}: producer role {descriptor.role!r} is not admitted for "
            f"event kind {kind!r}"
        )
    if "owner_domain" in entry and entry["owner_domain"] != journal.owner_domain:
        raise ManifestPinError(
            f"{where}: event kind {kind!r} belongs to a different owner domain"
        )
    if (
        descriptor.provenance in _NON_SERVER_PROVENANCES
        and entry["assertion_kind"] not in {"observation", "claim"}
    ):
        raise ProvenanceConflictError(
            f"{where}: provenance {descriptor.provenance!r} may assert only "
            "observation or claim, not "
            f"{entry['assertion_kind']!r}"
        )
    if kind in {"clock_registered", "producer_registered"}:
        if descriptor.provenance != "server":
            raise ProvenanceConflictError(
                f"{where}: {kind} is a server registration event"
            )
    return entry


def _registration_updates(
    journal: _Journal,
    normalized: _NormalizedSubmission,
    where: str,
) -> tuple[dict[Any, dict[str, Any]], dict[str, dict[str, Any]]]:
    kind = normalized.mapping["event_kind"]
    data = normalized.payload["data"]
    new_clocks: dict[Any, dict[str, Any]] = {}
    new_producers: dict[str, dict[str, Any]] = {}
    if kind == "clock_registered":
        clock = _validate_clock_descriptor(data)
        key = (clock["clock_id"], clock["boot_id"])
        existing = journal.clocks.get(key)
        if existing is not None:
            raise AdmissionConflictError(
                f"{where}: clock/boot {key} is already registered in this journal"
            )
        new_clocks[key] = clock
    elif kind == "producer_registered":
        producer = _validate_producer_descriptor(data, journal.owner_domain)
        if producer["producer_id"] in journal.producer_registry:
            raise AdmissionConflictError(
                f"{where}: producer {producer['producer_id']!r} is already "
                "registered; producer ids are never recycled"
            )
        declared = {event_kind for event_kind, _version in journal.event_registry}
        for allowed in producer["allowed_event_kinds"]:
            if allowed not in declared:
                raise InvalidEventError(
                    f"{where}: producer {producer['producer_id']!r} allows event "
                    f"kind {allowed!r} that the manifest event registry does "
                    "not declare"
                )
        new_producers[producer["producer_id"]] = producer
    return new_clocks, new_producers


def _check_assignment(
    journal: _Journal,
    descriptor: Any,
    assignment: Any,
    event_entry: Mapping[str, Any],
    where: str,
) -> None:
    if assignment.producer_id != descriptor.producer_id:
        raise ProvenanceConflictError(
            f"{where}: assignment producer disagrees with the authenticated channel"
        )
    if assignment.owner_domain != journal.owner_domain:
        raise ProvenanceConflictError(
            f"{where}: assignment owner domain does not match the journal"
        )
    if assignment.role != descriptor.role or assignment.provenance != descriptor.provenance:
        raise ProvenanceConflictError(
            f"{where}: assignment role/provenance disagrees with registration"
        )
    if assignment.assertion_kind != event_entry["assertion_kind"]:
        raise ProvenanceConflictError(
            f"{where}: live event registry assertion kind does not match the "
            "admitted manifest pin"
        )
    if assignment.role not in event_entry["writer_roles"]:
        raise ProvenanceConflictError(
            f"{where}: assignment role is not admitted for this event kind"
        )
    if (
        assignment.provenance in _NON_SERVER_PROVENANCES
        and assignment.assertion_kind not in {"observation", "claim"}
    ):
        raise ProvenanceConflictError(
            f"{where}: provenance {assignment.provenance!r} may assert only "
            "observation or claim"
        )


# ---------------------------------------------------------------------------
# Envelope construction and prefix verification
# ---------------------------------------------------------------------------


def _event_envelope(
    journal: _Journal,
    *,
    assignment: Any,
    event_entry: Mapping[str, Any],
    normalized: _NormalizedSubmission,
    recorder_clock: tuple[str, str, str],
) -> JournalEnvelope:
    sequence = len(journal.events) + 1
    envelope = JournalEnvelope(
        record_type=_ENVELOPE_RECORD_TYPE,
        schema_version=SCHEMA_VERSION,
        run_id=journal.run_id,
        journal_id=journal.journal_id,
        manifest_hash=journal.manifest_hash,
        journal_sequence=sequence,
        event_id=assignment.event_id,
        event_kind=normalized.mapping["event_kind"],
        event_schema_version=normalized.mapping["event_schema_version"],
        role=event_entry["role"],
        assertion_kind=assignment.assertion_kind,
        owner_domain=journal.owner_domain,
        producer_id=assignment.producer_id,
        producer_sequence=normalized.producer_sequence,
        provenance=assignment.provenance,
        evidence_scope="current_run",
        recorded_at=_recorded_at(recorder_clock),
        occurred_at=normalized.occurred_at,
        causal_refs=(),
        payload_json=_canonical_text(normalized.payload),
        previous_event_hash=journal.events[-1].event_hash,
        event_hash="",
    )
    return replace(envelope, event_hash=_envelope_hash(envelope))


def _verify_prefix(journal: _Journal, prefix: JournalPrefix) -> None:
    events = journal.events
    if prefix.journal_id != journal.journal_id:
        raise InvalidEvidenceRefError(
            f"prefix journal {prefix.journal_id!r} does not name this journal"
        )
    if prefix.last_sequence > len(events):
        raise JournalIntegrityError(
            f"prefix head {prefix.last_sequence} is beyond the durable tail "
            f"{len(events)}"
        )
    head = events[prefix.last_sequence - 1]
    if head.event_hash != prefix.head_hash:
        raise JournalIntegrityError(
            f"prefix head hash {prefix.head_hash} does not match the event hash "
            f"{head.event_hash} at sequence {prefix.last_sequence}"
        )
    if (
        str(contract_codec.canonical_digest(_canonical_bytes(journal.manifest)))
        != journal.manifest_hash
    ):
        raise JournalIntegrityError(
            "the admitted manifest no longer matches the pinned manifest digest"
        )

    clocks: dict[Any, Mapping[str, Any]] = dict(journal.manifest_clocks)
    producers: dict[str, Mapping[str, Any]] = dict(journal.manifest_producers)
    last_sequence_by_producer: dict[str, int] = {}
    for index in range(prefix.last_sequence):
        envelope = events[index]
        _verify_envelope(
            journal,
            envelope,
            index=index,
            events=events,
            clocks=clocks,
            producers=producers,
            last_sequence_by_producer=last_sequence_by_producer,
        )
        sequence_value = envelope.producer_sequence
        if isinstance(sequence_value, int):
            last_sequence_by_producer[envelope.producer_id] = sequence_value
        if envelope.event_kind == "clock_registered":
            try:
                data = _validate_clock_descriptor(envelope.payload["data"])
            except (TypeError, ValueError) as exc:
                raise JournalIntegrityError(
                    f"stored clock registration at sequence {index + 1} is "
                    f"invalid: {exc}"
                ) from exc
            clock_key = (data["clock_id"], data["boot_id"])
            if clock_key in clocks:
                raise JournalIntegrityError(
                    f"clock/boot {clock_key} is registered twice in the journal"
                )
            clocks[clock_key] = data
        elif envelope.event_kind == "producer_registered":
            try:
                data = _validate_producer_descriptor(
                    envelope.payload["data"], journal.owner_domain
                )
            except (TypeError, ValueError) as exc:
                raise JournalIntegrityError(
                    f"stored producer registration at sequence {index + 1} is "
                    f"invalid: {exc}"
                ) from exc
            if data["producer_id"] in producers:
                raise JournalIntegrityError(
                    f"producer {data['producer_id']!r} is registered twice"
                )
            declared = {kind for kind, _version in journal.event_registry}
            for allowed in data["allowed_event_kinds"]:
                if allowed not in declared:
                    raise JournalIntegrityError(
                        f"producer {data['producer_id']!r} allows event kind "
                        f"{allowed!r} that the manifest registry does not declare"
                    )
            producers[data["producer_id"]] = data


def _verify_envelope(
    journal: _Journal,
    envelope: JournalEnvelope,
    *,
    index: int,
    events: Sequence[JournalEnvelope],
    clocks: Mapping[Any, Mapping[str, Any]],
    producers: Mapping[str, Mapping[str, Any]],
    last_sequence_by_producer: Mapping[str, int],
) -> None:
    sequence = index + 1
    if envelope.journal_sequence != sequence:
        raise JournalIntegrityError(
            f"event at index {index} claims sequence {envelope.journal_sequence}; "
            "sequences are contiguous and begin at 1"
        )
    if envelope.record_type != _ENVELOPE_RECORD_TYPE:
        raise JournalIntegrityError("journal event record_type is not journal_event")
    if envelope.schema_version != SCHEMA_VERSION:
        raise JournalIntegrityError("journal event schema_version is not the kernel pin")
    if envelope.journal_id != journal.journal_id:
        raise JournalIntegrityError("event names a different journal id")
    if envelope.run_id != journal.run_id:
        raise JournalIntegrityError("event names a different run id")
    if envelope.manifest_hash != journal.manifest_hash:
        raise JournalIntegrityError(
            "event names a different manifest digest than the admitted manifest"
        )
    if envelope.owner_domain != journal.owner_domain:
        raise JournalIntegrityError("event names a different owner domain")
    if envelope.evidence_scope not in _EVIDENCE_SCOPES:
        raise JournalIntegrityError("event evidence_scope is not a kernel scope")
    if envelope.role not in access_policy.EVENT_ROLES:
        raise JournalIntegrityError("event role is not a kernel role")
    if envelope.assertion_kind not in access_policy.ASSERTION_KINDS:
        raise JournalIntegrityError("event assertion kind is not a kernel kind")
    if envelope.provenance not in access_policy.PROVENANCES:
        raise JournalIntegrityError("event provenance is not a kernel provenance")
    if (
        envelope.provenance in _NON_SERVER_PROVENANCES
        and envelope.assertion_kind not in {"observation", "claim"}
    ):
        raise JournalIntegrityError(
            "non-server provenance may assert only observation or claim"
        )
    if (
        envelope.event_kind in {"clock_registered", "producer_registered"}
        and envelope.provenance != "server"
    ):
        raise JournalIntegrityError(
            f"{envelope.event_kind} is a server registration event"
        )

    registry_entry: Mapping[str, Any] | None = None
    if sequence > 1:
        registry_entry = journal.event_registry.get(
            (envelope.event_kind, envelope.event_schema_version)
        )
        if registry_entry is None:
            raise JournalIntegrityError(
                "event kind/version is not declared in the admitted manifest registry"
            )
        if registry_entry["assertion_kind"] != envelope.assertion_kind:
            raise JournalIntegrityError(
                "event assertion kind disagrees with the manifest event registry"
            )
        if registry_entry["role"] != envelope.role:
            raise JournalIntegrityError(
                "event role disagrees with the manifest event registry"
            )

    expected_hash = _envelope_hash(envelope)
    if expected_hash != envelope.event_hash:
        raise JournalIntegrityError(
            f"event hash mismatch at sequence {sequence}: stored "
            f"{envelope.event_hash}, recomputed {expected_hash}"
        )

    previous_missing = _as_missing(envelope.previous_event_hash)
    if sequence == 1:
        if envelope.event_kind != _MANIFEST_EVENT_KIND:
            raise JournalIntegrityError(
                "journal sequence 1 must be the manifest_admitted event"
            )
        if envelope.role != "external_input" or envelope.provenance != "server":
            raise JournalIntegrityError(
                "manifest_admitted must be an external_input server event"
            )
        if previous_missing is None or previous_missing.reason != "not_applicable":
            raise JournalIntegrityError(
                "manifest_admitted must carry Missing(not_applicable) for "
                "previous_event_hash"
            )
    else:
        if envelope.event_kind == _MANIFEST_EVENT_KIND:
            raise JournalIntegrityError(
                "a second manifest_admitted event is never admitted"
            )
        if not isinstance(envelope.previous_event_hash, str):
            raise JournalIntegrityError(
                "events after admission must name their predecessor's hash"
            )
        if envelope.previous_event_hash != events[index - 1].event_hash:
            raise JournalIntegrityError(
                f"previous_event_hash mismatch at sequence {sequence}"
            )

    producer_sequence = envelope.producer_sequence
    producer_entry = producers.get(envelope.producer_id)
    if producer_entry is None:
        raise JournalIntegrityError(
            f"event producer {envelope.producer_id!r} is not registered"
        )
    if producer_entry["provenance"] != envelope.provenance:
        raise JournalIntegrityError(
            "event provenance disagrees with the producer registry"
        )
    if registry_entry is not None and producer_entry["role"] not in registry_entry[
        "writer_roles"
    ]:
        raise JournalIntegrityError(
            "event producer role is not admitted for this event kind"
        )
    if sequence > 1 and envelope.event_kind not in producer_entry["allowed_event_kinds"]:
        raise JournalIntegrityError(
            "event kind is outside the producer's registered write grant"
        )
    if isinstance(producer_sequence, int):
        if producer_sequence < 1:
            raise JournalIntegrityError("producer_sequence must be positive")
        previous = last_sequence_by_producer.get(envelope.producer_id, 0)
        if producer_sequence <= previous:
            raise JournalIntegrityError(
                "producer sequences must strictly increase within one lifetime"
            )
    else:
        missing = _as_missing(producer_sequence)
        if missing is None:
            raise JournalIntegrityError(
                "producer_sequence must be a positive integer or Missing"
            )
        if sequence > 1 and producer_entry["sequence_required"]:
            raise JournalIntegrityError(
                "registered producer requires a positive producer_sequence"
            )

    _verify_payload(
        journal,
        envelope,
        index=index,
        events=events,
        clocks=clocks,
        sequence=sequence,
    )


def _verify_payload(
    journal: _Journal,
    envelope: JournalEnvelope,
    *,
    index: int,
    events: Sequence[JournalEnvelope],
    clocks: Mapping[Any, Mapping[str, Any]],
    sequence: int,
) -> None:
    payload = envelope.payload
    if not isinstance(payload, Mapping) or set(payload.keys()) != PAYLOAD_FIELDS:
        raise JournalIntegrityError(
            f"event payload at sequence {sequence} is not an EvidencePayload"
        )
    try:
        payload = _strict_evidence(payload, f"sequence {sequence}.payload")
    except (TypeError, ValueError) as exc:
        raise JournalIntegrityError(
            f"stored payload at sequence {sequence} is not strict evidence: {exc}"
        ) from exc
    data = payload["data"]
    if not isinstance(data, Mapping):
        raise JournalIntegrityError(
            f"event payload data at sequence {sequence} is not an EvidenceMap"
        )
    measurements = payload["measurements"]
    if not isinstance(measurements, list):
        raise JournalIntegrityError("event measurements must be an array")
    for measurement in measurements:
        try:
            contract_codec.validate_measurement(
                measurement, tuple(clocks.values())
            )
        except (TypeError, ValueError) as exc:
            raise JournalIntegrityError(
                f"stored measurement at sequence {sequence} is invalid: {exc}"
            ) from exc

    refs = payload["evidence_refs"]
    if not isinstance(refs, list):
        raise JournalIntegrityError("event evidence_refs must be an array")
    for ref_value in refs:
        try:
            ref = EvidenceRef.from_dict(ref_value)
        except (TypeError, ValueError) as exc:
            raise JournalIntegrityError(
                f"stored evidence reference at sequence {sequence} is invalid: {exc}"
            ) from exc
        _assert_ref_resolves(
            ref,
            journal,
            before_sequence=sequence,
            events=events,
            where=f"journal sequence {sequence}",
        )

    artifacts = payload["artifact_refs"]
    if not isinstance(artifacts, list):
        raise JournalIntegrityError("event artifact_refs must be an array")
    digests: set[str] = set()
    for ref_value in artifacts:
        try:
            ref = _coerce_artifact_ref(
                ref_value, f"sequence {sequence}.artifact_refs"
            )
        except (TypeError, ValueError) as exc:
            raise JournalIntegrityError(
                f"stored artifact reference at sequence {sequence} is invalid: {exc}"
            ) from exc
        if ref.digest in digests:
            raise JournalIntegrityError(
                "stored artifact_refs repeats one digest"
            )
        digests.add(ref.digest)

    if sequence == 1:
        if set(data.keys()) != {"manifest"}:
            raise JournalIntegrityError(
                "manifest_admitted payload data must be a ManifestAdmission"
            )
        try:
            ref = _coerce_artifact_ref(data["manifest"], "ManifestAdmission.manifest")
        except (TypeError, ValueError) as exc:
            raise JournalIntegrityError(
                f"ManifestAdmission.manifest is invalid: {exc}"
            ) from exc
        if ref.digest != journal.manifest_hash:
            raise JournalIntegrityError(
                "ManifestAdmission.manifest digest does not match manifest_hash"
            )
        if journal.manifest_ref.to_dict() != ref.to_dict():
            raise JournalIntegrityError(
                "ManifestAdmission.manifest is not the retained manifest artifact"
            )
        if ref.digest not in digests:
            raise JournalIntegrityError(
                "ManifestAdmission.manifest must appear in artifact_refs"
            )


# ---------------------------------------------------------------------------
# Append (producer submissions)
# ---------------------------------------------------------------------------


def _integrity_conflict(
    journal: _Journal,
    descriptor: Any,
    sequence: int,
    accepted: _Delivery,
    observed_digest: str,
) -> "IntegrityIncident":
    accepted_event = journal.events[accepted.journal_sequence - 1]
    return IntegrityIncident(
        incident_id=_new_incident_id(),
        journal_id=journal.journal_id,
        producer_id=descriptor.producer_id,
        producer_sequence=sequence,
        accepted_event_id=accepted_event.event_id,
        accepted_event_hash=accepted_event.event_hash,
        accepted_content_digest=accepted.content_digest,
        observed_content_digest=observed_digest,
        recorded_at=_recorded_at(journal.recorder_clock),
        detail=(
            f"producer {descriptor.producer_id!r} delivered conflicting content "
            f"under sequence {sequence}; the acknowledged event was not replaced"
        ),
    )


def append_event(
    channel_id: str, owner_domain: str, submission: EventSubmission
) -> JournalEnvelope:
    """Append one authorized producer submission to its owner journal.

    Identical ``(producer_id, producer_sequence)`` retries return the already
    acknowledged envelope.  Conflicting content under that key records an
    integrity incident and leaves the acknowledged prefix untouched.
    """
    _require_identifier(owner_domain, "owner_domain")
    lock = _owner_lock(owner_domain)
    with lock:
        raw = _raw_submission_mapping(submission)
        if set(raw.keys()) != SUBMISSION_FIELDS:
            # No valid submission exists to deduplicate; let the authenticated
            # ingress authority reject spoofed/unknown/missing fields precisely.
            access_policy.authorize_event_submission(channel_id, raw)
            raise InvalidEventError(
                f"EventSubmission must contain exactly {sorted(SUBMISSION_FIELDS)}"
            )
        event_kind = raw["event_kind"]
        if not isinstance(event_kind, str):
            raise InvalidEventError("event_kind must be a string identifier")
        descriptor = _authorize_write(channel_id, owner_domain, event_kind)
        journal = _active_journal(owner_domain)
        normalized = _normalize_submission(
            raw,
            journal=journal,
            descriptor=descriptor,
            channel_id=channel_id,
            where="append_event",
        )

        key: tuple[str, int] | None = None
        if isinstance(normalized.producer_sequence, int):
            key = (descriptor.producer_id, normalized.producer_sequence)
            accepted = journal.deliveries.get(key)
            if accepted is not None:
                if accepted.content_digest == normalized.content_digest:
                    return journal.events[accepted.journal_sequence - 1]
                incident = _integrity_conflict(
                    journal,
                    descriptor,
                    normalized.producer_sequence,
                    accepted,
                    normalized.content_digest,
                )
                _store_journal(
                    replace(journal, incidents=journal.incidents + (incident,))
                )
                raise IntegrityIncidentError(incident)

        event_entry = _preflight_pins(
            journal, descriptor, normalized, "append_event"
        )
        new_clocks, new_producers = _registration_updates(
            journal, normalized, "append_event"
        )
        assignment = access_policy.authorize_event_submission(channel_id, normalized.mapping)
        _check_assignment(
            journal, descriptor, assignment, event_entry, "append_event"
        )
        if _as_missing(assignment.producer_sequence) is None:
            if assignment.producer_sequence != normalized.producer_sequence:
                raise ProvenanceConflictError(
                    "assignment producer sequence disagrees with the submission"
                )

        envelope = _event_envelope(
            journal,
            assignment=assignment,
            event_entry=event_entry,
            normalized=normalized,
            recorder_clock=journal.recorder_clock,
        )
        deliveries = dict(journal.deliveries)
        if key is not None:
            deliveries[key] = _Delivery(
                content_digest=normalized.content_digest,
                journal_sequence=envelope.journal_sequence,
            )
        new_journal = replace(
            journal,
            events=journal.events + (envelope,),
            deliveries=deliveries,
            clocks={**journal.clocks, **new_clocks},
            producer_registry={**journal.producer_registry, **new_producers},
        )
        _store_journal(new_journal)
        return envelope


# ---------------------------------------------------------------------------
# Prefix and head reads
# ---------------------------------------------------------------------------


def read_prefix(channel_id: str, prefix: JournalPrefix) -> tuple[JournalEnvelope, ...]:
    """Return the verified, immutable events of ``prefix``.

    The head hash, the chain, every producer sequence, every same-journal
    evidence citation, and every measurement are re-verified before any record
    is returned.  A corrupted or inconsistent prefix raises.

    Artifact *byte* availability is a resolution-time concern: a lost artifact
    surfaces as an explicit Missing/observation_lost at resolution, never as a
    different event body here.
    """
    projection = access_policy.channel_projection(channel_id)
    journal = _get_journal(prefix.journal_id)
    _require_axis(projection, journal.owner_domain)
    _verify_prefix(journal, prefix)
    return journal.events[: prefix.last_sequence]


def journal_head(channel_id: str, journal_id: str) -> JournalPrefix:
    """Return the current acknowledged prefix for ``journal_id``."""
    projection = access_policy.channel_projection(channel_id)
    journal = _get_journal(journal_id)
    _require_axis(projection, journal.owner_domain)
    head = journal.events[-1]
    return JournalPrefix(
        journal_id=journal.journal_id,
        last_sequence=len(journal.events),
        head_hash=head.event_hash,
    )


def integrity_incidents(
    channel_id: str, journal_id: str
) -> tuple[IntegrityIncident, ...]:
    """Return the retained producer-sequence integrity incidents."""
    projection = access_policy.channel_projection(channel_id)
    journal = _get_journal(journal_id)
    _require_axis(projection, journal.owner_domain)
    return journal.incidents


def entity_state(channel_id: str, owner_domain: str, entity_id: str) -> EntityState:
    """Return the owner-local revision and authoritative state of one entity."""
    _require_identifier(owner_domain, "owner_domain")
    _require_identifier(entity_id, "entity_id")
    projection = access_policy.channel_projection(channel_id)
    journal = _active_journal(owner_domain)
    _require_axis(projection, journal.owner_domain)
    key = (owner_domain, entity_id)
    revision = journal.revisions.get(key, 0)
    state = journal.states.get(key)
    return EntityState(
        owner_domain=owner_domain,
        entity_id=entity_id,
        revision=revision,
        state=state if state is not None else NOT_OBSERVED,
    )


# ---------------------------------------------------------------------------
# Owner-local atomic commit
# ---------------------------------------------------------------------------


def _command_fingerprint(
    owner_domain: str,
    entity_id: str,
    command_id: str,
    expected_revision: int,
    state_ref: Any,
    request_events: Sequence[Any],
) -> str:
    return _digest_of(
        {
            "owner_domain": owner_domain,
            "entity_id": entity_id,
            "command_id": command_id,
            "expected_revision": expected_revision,
            "state": state_ref.to_dict(),
            "events": list(request_events),
        }
    )


def commit_effect(
    channel_id: str,
    owner_domain: str,
    entity_id: str,
    command_id: str,
    expected_revision: int,
    state: artifact_store.ArtifactReference,
    events: tuple[EventSubmission, ...],
) -> JournalPrefix:
    """Commit one owner-local authoritative effect atomically.

    The admitted input artifacts, authoritative state, revision advance,
    idempotency receipt, journal events, and replayable response become durable
    together (one copy-on-write swap).  Nothing is acknowledged before that
    swap, and a retried ``command_id`` replays the stored response without
    duplicating any effect.
    """
    _require_identifier(owner_domain, "owner_domain")
    _require_identifier(entity_id, "entity_id")
    _require_identifier(command_id, "command_id")
    if isinstance(expected_revision, bool) or not isinstance(expected_revision, int):
        raise InvalidCommandError("expected_revision must be an int")
    if expected_revision < 0:
        raise InvalidCommandError("expected_revision must be nonnegative")
    if isinstance(events, (str, bytes)) or not isinstance(events, Sequence):
        raise InvalidCommandError("events must be a sequence of EventSubmissions")

    state_ref = _coerce_artifact_ref(state, "commit state")
    if state_ref.owner_domain != owner_domain:
        raise access_policy.GrantDeniedError(
            f"owner-local commit required: state artifact belongs to "
            f"{state_ref.owner_domain!r}, not {owner_domain!r}"
        )

    lock = _owner_lock(owner_domain)
    with lock:
        descriptor = _authorize_write(channel_id, owner_domain, entity_id)
        journal = _active_journal(owner_domain)

        raw_events: list[dict[str, Any]] = []
        for index, submission in enumerate(events):
            raw = _raw_submission_mapping(submission)
            if set(raw.keys()) != SUBMISSION_FIELDS:
                access_policy.authorize_event_submission(channel_id, raw)
                raise InvalidEventError(
                    f"events[{index}] must contain exactly "
                    f"{sorted(SUBMISSION_FIELDS)}"
                )
            raw_events.append(raw)

        # The request fingerprint is derived from untrusted content alone so an
        # idempotent retry can replay the stored response without revalidating
        # the world (or re-resolving artifacts that may since have been lost).
        request_events = [
            _jsonable(raw, f"commit_effect.events[{index}]")
            for index, raw in enumerate(raw_events)
        ]
        key = (owner_domain, entity_id, command_id)
        fingerprint = _command_fingerprint(
            owner_domain,
            entity_id,
            command_id,
            expected_revision,
            state_ref,
            request_events,
        )
        receipt = journal.receipts.get(key)
        if receipt is not None:
            if receipt.fingerprint != fingerprint:
                raise CommandConflictError(command_id)
            return receipt.response

        current_revision = journal.revisions.get((owner_domain, entity_id), 0)
        if expected_revision != current_revision:
            raise RevisionConflictError(entity_id, current_revision, expected_revision)

        # The authoritative effect's bytes are durably installed before commit.
        artifact_store.resolve_artifact(channel_id, state_ref)

        normalized_events = [
            _normalize_submission(
                raw,
                journal=journal,
                descriptor=descriptor,
                channel_id=channel_id,
                where=f"commit_effect.events[{index}]",
            )
            for index, raw in enumerate(raw_events)
        ]

        last_accepted: dict[str, int] = {}
        for producer_id, sequence in journal.deliveries:
            if sequence > last_accepted.get(producer_id, 0):
                last_accepted[producer_id] = sequence

        pending_keys: dict[tuple[str, int], str] = {}
        reused: set[int] = set()
        updates: dict[int, tuple[dict[Any, dict[str, Any]], dict[str, dict[str, Any]]]] = {}
        batch_clock_keys: set[Any] = set()
        batch_producer_ids: set[str] = set()

        # Preflight the whole batch before any producer sequence is consumed.
        for index, normalized in enumerate(normalized_events):
            where = f"commit_effect.events[{index}]"
            sequence_value = normalized.producer_sequence
            if isinstance(sequence_value, int):
                delivery_key = (descriptor.producer_id, sequence_value)
                accepted = journal.deliveries.get(delivery_key)
                if accepted is not None:
                    if accepted.content_digest != normalized.content_digest:
                        incident = _integrity_conflict(
                            journal,
                            descriptor,
                            sequence_value,
                            accepted,
                            normalized.content_digest,
                        )
                        _store_journal(
                            replace(
                                journal,
                                incidents=journal.incidents + (incident,),
                            )
                        )
                        raise IntegrityIncidentError(incident)
                    reused.add(index)
                    continue
                if delivery_key in pending_keys:
                    if pending_keys[delivery_key] != normalized.content_digest:
                        raise CommandConflictError(command_id)
                    reused.add(index)
                    continue
                if sequence_value <= last_accepted.get(descriptor.producer_id, 0):
                    raise ManifestPinError(
                        f"{where}: producer sequence {sequence_value} does not "
                        "advance beyond the acknowledged sequence; gaps are never "
                        "backfilled into an earlier prefix"
                    )
                pending_keys[delivery_key] = normalized.content_digest
                last_accepted[descriptor.producer_id] = sequence_value
            _preflight_pins(journal, descriptor, normalized, where)
            clocks_update, producers_update = _registration_updates(
                journal, normalized, where
            )
            for clock_key in clocks_update:
                if clock_key in batch_clock_keys:
                    raise AdmissionConflictError(
                        f"{where}: clock/boot {clock_key} is registered twice"
                    )
                batch_clock_keys.add(clock_key)
            for producer_id in producers_update:
                if producer_id in batch_producer_ids:
                    raise AdmissionConflictError(
                        f"{where}: producer {producer_id!r} is registered twice"
                    )
                batch_producer_ids.add(producer_id)
            updates[index] = (clocks_update, producers_update)

        # Assign identity for every new event, then commit the whole batch.
        deliveries = dict(journal.deliveries)
        working = journal
        for index, normalized in enumerate(normalized_events):
            if index in reused:
                continue
            event_entry = _event_pin(
                journal,
                normalized.mapping["event_kind"],
                normalized.mapping["event_schema_version"],
            )
            assignment = access_policy.authorize_event_submission(
                channel_id, normalized.mapping
            )
            _check_assignment(
                journal, descriptor, assignment, event_entry, "commit_effect"
            )
            envelope = _event_envelope(
                working,
                assignment=assignment,
                event_entry=event_entry,
                normalized=normalized,
                recorder_clock=journal.recorder_clock,
            )
            clocks_update, producers_update = updates[index]
            working = replace(
                working,
                events=working.events + (envelope,),
                clocks={**working.clocks, **clocks_update},
                producer_registry={
                    **working.producer_registry,
                    **producers_update,
                },
            )
            if isinstance(normalized.producer_sequence, int):
                deliveries[
                    (descriptor.producer_id, normalized.producer_sequence)
                ] = _Delivery(
                    content_digest=normalized.content_digest,
                    journal_sequence=envelope.journal_sequence,
                )

        revision = expected_revision + 1
        events_after = working.events
        response = JournalPrefix(
            journal_id=journal.journal_id,
            last_sequence=len(events_after),
            head_hash=events_after[-1].event_hash,
        )
        new_journal = replace(
            journal,
            events=events_after,
            deliveries=deliveries,
            revisions={**journal.revisions, (owner_domain, entity_id): revision},
            states={**journal.states, (owner_domain, entity_id): state_ref},
            receipts={
                **journal.receipts,
                key: _CommandReceipt(fingerprint=fingerprint, response=response),
            },
            clocks=working.clocks,
            producer_registry=working.producer_registry,
        )
        # The replayable response must verify before anything is acknowledged.
        _verify_prefix(new_journal, response)
        _store_journal(new_journal)
        return response


# ---------------------------------------------------------------------------
# Test isolation
# ---------------------------------------------------------------------------


def reset_for_tests() -> None:
    """Clear every journal, incident, and owner lock (test harness only)."""
    with _REGISTRY_LOCK:
        _JOURNALS.clear()
        _ACTIVE_JOURNAL.clear()
        _OWNER_LOCKS.clear()

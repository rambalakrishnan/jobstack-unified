"""owner_revisions: owner-separated revision commitment at tier 4.

This module is the owner-local durability boundary for complete, immutable
domain publications (``W.DataDomainRevision``) and lifecycle axis publications
(``W.AxisRevision``).  It enforces the rules that no caller may route around:

* an entity registration fixes every declared domain's role, authority source,
  single publication writer, storage-domain identity, and publication policy;
* a publication is a complete snapshot whose revision is
  ``previous_revision + 1`` and whose first revision is ``1``;
* the key ``(entity, domain, revision)`` identifies exactly one canonical
  content digest; identical retries replay the existing publication and
  different bytes under the same key are an integrity conflict;
* stale expected revisions never commit and a rejected write has no effect;
* dispatch and observation may only advance through their declared state
  transitions; execution claims and application facts are cumulative histories
  whose prior entries are never dropped or rewritten; report input pins never
  regress between publications;
* authenticated writer identity, not a serialized ``writer_id`` label, grants
  authority; and
* a supplied kernel lease is validated inside the same owner-local fence as the
  revision advance.

When the owner domain already has an admitted evidence journal, the revision
artifact, the journal-derived state, and the revision advance commit through
:func:`evidence_journal.commit_effect` before acknowledgement.  Domains whose
journal is admitted later by another owner keep their complete publication in
this module's owner-local revision store; admitting a journal for a domain that
already committed locally raises an explicit state-drift error rather than
silently resetting the revision counter.

Owner commits take only the committing owner's lock.  No peer owner lock,
acknowledgement, or peer payload serialization is acquired.
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
lease_authority = _load_sibling("lease_authority")

__all__ = [
    "SCHEMA_VERSION",
    "AXIS_SCHEMA_VERSION",
    "RECORD_TYPE_ENTITY",
    "RECORD_TYPE_DOMAIN",
    "RECORD_TYPE_AXIS",
    "DOMAINS_BY_ENTITY",
    "AXIS_DOMAINS",
    "DOMAIN_ROLES",
    "AXIS_TRANSITIONS",
    "OBSERVATION_TRANSITIONS",
    "CLOSE_REASONS",
    "EntityRegistration",
    "DataDomainRevision",
    "AxisRevision",
    "PublishedRevision",
    "OwnerRevisionError",
    "InvalidRecordError",
    "RegistrationConflictError",
    "RegistrationMismatchError",
    "UnknownEntityError",
    "WriterAuthorityError",
    "DomainMismatchError",
    "StaleRevisionError",
    "RevisionIntegrityError",
    "CommandConflictError",
    "TransitionRejectedError",
    "CumulativeHistoryError",
    "PinRegressionError",
    "PinResolutionError",
    "LeaseValidationError",
    "OwnerRevisionStateError",
    "OwnerCommitError",
    "register_entity",
    "commit_domain",
    "read_domain",
    "read_revision",
    "domain_head",
    "reset_for_tests",
]

SCHEMA_VERSION = "owner-separated-write-domains/0.1.0"
AXIS_SCHEMA_VERSION = "application-attempt-lifecycle/0.1.0"
RECORD_TYPE_ENTITY = "write_domain_entity"
RECORD_TYPE_DOMAIN = "owned_domain_revision"
RECORD_TYPE_AXIS = "attempt_axis_revision"

DOMAINS_BY_ENTITY: dict[str, tuple[str, ...]] = {
    "job": ("crawler", "downstream"),
    "application_attempt": (
        "dispatch",
        "observation",
        "execution",
        "application",
        "report",
    ),
    "hellscape_session": ("application", "observation", "diagnostic"),
}
AXIS_DOMAINS = frozenset(
    {"dispatch", "observation", "execution", "application", "report"}
)

DOMAIN_ROLES: dict[tuple[str, str], str] = {
    ("job", "crawler"): "crawler",
    ("job", "downstream"): "product",
    ("application_attempt", "dispatch"): "connector",
    ("application_attempt", "observation"): "connector",
    ("application_attempt", "execution"): "subject",
    ("application_attempt", "application"): "origin",
    ("application_attempt", "report"): "reconciler",
    ("hellscape_session", "application"): "origin",
    ("hellscape_session", "observation"): "observer",
    ("hellscape_session", "diagnostic"): "analyzer",
}

# Owner role -> authenticated producer role assigned by access_policy.
_ROLE_TO_ACCESS_ROLE: dict[str, str] = {
    "crawler": "kernel",
    "product": "kernel",
    "connector": "connector",
    "subject": "subject",
    "origin": "application_origin",
    "reconciler": "analyzer",
    "observer": "observer",
    "analyzer": "analyzer",
}

# Required complete-value fields, from contracts/04 and contracts/01.
DOMAIN_VALUE_FIELDS: dict[tuple[str, str], tuple[str, ...]] = {
    ("job", "crawler"): (
        "acquisition",
        "processing",
        "discovery",
        "replacement_lineage",
    ),
    ("job", "downstream"): (
        "track",
        "priority_hint",
        "selection",
        "ownership",
        "evaluations",
        "materials",
        "application_attempts",
    ),
    ("application_attempt", "dispatch"): (
        "state",
        "local_handle",
        "native_run_id",
        "request_digest",
        "delivery_refs",
        "acceptance_refs",
        "recovery_authorization_refs",
        "reason",
    ),
    ("application_attempt", "observation"): (
        "state",
        "window_id",
        "opened_at",
        "active_deadline",
        "drain_started_at",
        "drain_deadline",
        "closed_at",
        "close_reason",
        "at_close",
        "control_observations",
        "late_evidence_refs",
        "measurements",
    ),
    ("application_attempt", "execution"): ("claims",),
    ("application_attempt", "application"): ("facts",),
    ("application_attempt", "report"): (
        "state",
        "coverage",
        "inputs",
        "evaluator",
        "comparisons",
        "issues",
        "limitations",
        "diagnostic",
    ),
    ("hellscape_session", "application"): (
        "state_revision",
        "workflow_state",
        "selected_job",
        "accepted_sections",
        "upload",
        "identity_receipt",
        "authoritative_state",
        "submission",
        "mutation_authority",
        "authority_seal_ref",
    ),
    ("hellscape_session", "observation"): (
        "attempt_observation",
        "attempt_observation_ref",
        "producer_completeness",
        "observed_action_refs",
        "confirmation_render_refs",
        "late_evidence_refs",
        "measurements",
        "infrastructure_incidents",
    ),
    ("hellscape_session", "diagnostic"): (
        "diagnostic_id",
        "analysis_revision",
        "diagnostic",
        "input_prefix",
        "inputs",
        "classifier",
        "replay_receipts",
    ),
}

AXIS_TRANSITIONS: dict[str, frozenset[str]] = {
    "unpublished": frozenset({"not_started", "prepared", "rejected"}),
    "not_started": frozenset({"prepared", "rejected"}),
    "prepared": frozenset({"dispatching", "rejected"}),
    "dispatching": frozenset({"accepted", "rejected", "uncertain"}),
    "uncertain": frozenset({"uncertain", "accepted", "rejected"}),
    "accepted": frozenset({"accepted"}),
    "rejected": frozenset({"rejected"}),
}

OBSERVATION_TRANSITIONS: dict[str, frozenset[str]] = {
    "unpublished": frozenset({"not_opened", "open", "closed"}),
    "not_opened": frozenset({"open", "closed"}),
    "open": frozenset({"open", "draining", "closed"}),
    "draining": frozenset({"draining", "closed"}),
    "closed": frozenset({"closed"}),
}

CLOSE_REASONS = frozenset(
    {
        "normal_completion",
        "operator_stop",
        "local_deadline",
        "translation_failure",
        "launch_failure",
        "subject_terminal",
        "connection_lost",
        "infrastructure_interruption",
    }
)

_REPORT_PIN_AXES = ("dispatch", "observation", "execution", "application")
_OBSERVATION_CLOSURE_FIELDS = (
    "window_id",
    "opened_at",
    "active_deadline",
    "drain_started_at",
    "drain_deadline",
    "closed_at",
    "close_reason",
    "at_close",
)
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_ENTITY_FIELDS = {
    "job": frozenset({"entity_type", "target", "job_id"}),
    "application_attempt": frozenset({"entity_type", "attempt_id", "kind"}),
    "hellscape_session": frozenset({"entity_type", "session_id"}),
}
_OWNER_FIELDS = frozenset(
    {"role", "source_id", "writer_id", "owner_domain", "publication_policy"}
)
_PIN_FIELDS = frozenset({"id", "version", "artifact_digest"})
_ARTIFACT_FIELDS = frozenset(
    {"digest", "size_bytes", "media_type", "owner_domain", "access"}
)
_EVIDENCE_REF_FIELDS = frozenset(
    {"journal_id", "sequence", "event_id", "event_hash", "pointer"}
)
_PREFIX_FIELDS = frozenset({"journal_id", "last_sequence", "head_hash"})


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class OwnerRevisionError(Exception):
    """Base class for owner-revision contract violations."""


class InvalidRecordError(OwnerRevisionError, ValueError):
    """A registration or revision is not a valid complete contract record."""


class RegistrationConflictError(OwnerRevisionError):
    """An entity registration is immutable; conflicting bytes are rejected."""


class RegistrationMismatchError(OwnerRevisionError):
    """A revision does not belong to the registered entity/registration."""


class UnknownEntityError(OwnerRevisionError):
    """The entity must be registered before its domains publish."""


class WriterAuthorityError(OwnerRevisionError, PermissionError):
    """The authenticated channel is not the registered writer for the domain."""


class DomainMismatchError(OwnerRevisionError):
    """A domain or revision record type does not fit the entity."""


class StaleRevisionError(OwnerRevisionError):
    """The publication does not extend the currently committed revision."""


class RevisionIntegrityError(OwnerRevisionError):
    """One (entity, domain, revision) key holds two different contents."""


class CommandConflictError(OwnerRevisionError):
    """A command id was reused with different content."""


class TransitionRejectedError(OwnerRevisionError):
    """A dispatch/observation state transition is not declared."""


class CumulativeHistoryError(OwnerRevisionError):
    """A cumulative claim/fact history dropped or rewrote a prior entry."""


class PinRegressionError(OwnerRevisionError):
    """A report input pin regressed or changed under one revision."""


class PinResolutionError(OwnerRevisionError):
    """A report input pin names an unpublished or mismatched revision."""


class LeaseValidationError(OwnerRevisionError, PermissionError):
    """The supplied kernel lease is stale, expired, fenced, or mismatched."""


class OwnerRevisionStateError(OwnerRevisionError):
    """The owner-local revision store and the admitted journal disagree."""


class OwnerCommitError(OwnerRevisionError):
    """The owner-local journal commit failed."""


# ---------------------------------------------------------------------------
# Strict JSON / missingness helpers
# ---------------------------------------------------------------------------


def _is_missing(value: Any) -> bool:
    if isinstance(value, Mapping):
        keys = set(value.keys())
        return (
            keys in ({"value", "reason"}, {"value", "reason", "detail"})
            and value.get("value") is None
        )
    if is_dataclass(value) and not isinstance(value, type):
        return hasattr(value, "reason") and getattr(value, "value", "") is None
    return False


def _missing_reason(value: Any) -> str | None:
    if isinstance(value, Mapping) and _is_missing(value):
        return str(value.get("reason"))
    if is_dataclass(value) and not isinstance(value, type) and _is_missing(value):
        return str(getattr(value, "reason"))
    return None


def _missing_dict(reason: str = "not_applicable") -> dict[str, Any]:
    if reason not in contract_codec.VALID_MISSING_REASONS:
        raise InvalidRecordError(f"unknown Missing reason: {reason!r}")
    return {"value": None, "reason": reason}


def _jsonable(value: Any, path: str = "$") -> Any:
    """Normalize to strict JSON content; bare nulls and raw bytes are refused."""
    if _is_missing(value):
        reason = _missing_reason(value)
        detail = (
            value.get("detail")
            if isinstance(value, Mapping)
            else getattr(value, "detail", None)
        )
        out: dict[str, Any] = {"value": None, "reason": reason}
        if detail is not None:
            out["detail"] = detail
        return out
    if value is None:
        raise InvalidRecordError(f"bare null at {path}; use a typed Missing envelope")
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise InvalidRecordError(
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
            raise InvalidRecordError(f"nonfinite number at {path}")
        return value
    if isinstance(value, (bytes, bytearray)):
        raise InvalidRecordError(
            f"raw bytes at {path}; retain an ArtifactReference instead"
        )
    if is_dataclass(value) and not isinstance(value, type):
        return _jsonable(
            {item.name: getattr(value, item.name) for item in fields(value)}, path
        )
    raise InvalidRecordError(
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
        raise InvalidRecordError(f"record is not canonicalizable JSON: {exc}") from exc


def _strict_gate(record: Mapping[str, Any], label: str) -> bytes:
    """Run the kernel strict-JSON gate and return canonical record bytes."""
    normalized = _jsonable(record, label)
    wrapper = {"id": "owner_revision_gate", "timing": normalized}
    try:
        contract_codec.validate_record(_canonical_bytes(wrapper), "record/v1")
    except (TypeError, ValueError) as exc:
        raise InvalidRecordError(f"{label} is not strict JSON evidence: {exc}") from exc
    payload = _canonical_bytes(normalized)
    try:
        contract_codec.canonical_digest(payload)
    except (TypeError, ValueError) as exc:
        raise InvalidRecordError(f"{label} has no canonical digest: {exc}") from exc
    return payload


def _digest_of(payload: bytes) -> str:
    return str(contract_codec.canonical_digest(payload))


def _require_identifier(value: Any, field_name: str) -> str:
    if not isinstance(value, str):
        raise InvalidRecordError(f"{field_name} must be a str")
    if not value or value != value.strip():
        raise InvalidRecordError(
            f"{field_name} must be a nonempty identifier without padding"
        )
    if len(value) > 256:
        raise InvalidRecordError(f"{field_name} must be at most 256 characters")
    if any(ord(ch) < 0x20 for ch in value):
        raise InvalidRecordError(f"{field_name} must not contain control characters")
    return value


def _require_digest(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.match(value):
        raise InvalidRecordError(
            f"{field_name} must be a sha256:<64 lowercase hex> digest"
        )
    return value


def _require_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidRecordError(f"{field_name} must be an int")
    return value


def _require_exact_keys(
    value: Any, required: frozenset[str] | set[str], label: str
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise InvalidRecordError(f"{label} must be a mapping")
    keys = set(value.keys())
    required = set(required)
    if keys != required:
        missing = sorted(required - keys)
        extra = sorted(keys - required)
        raise InvalidRecordError(
            f"{label} must contain exactly {sorted(required)}; "
            f"missing={missing}, undeclared={extra}"
        )
    return value


def _coerce_prefix(value: Any, field_name: str) -> dict[str, Any]:
    if isinstance(value, evidence_journal.JournalPrefix):
        data = {
            "journal_id": value.journal_id,
            "last_sequence": value.last_sequence,
            "head_hash": value.head_hash,
        }
    elif isinstance(value, Mapping):
        data = _require_exact_keys(value, _PREFIX_FIELDS, field_name)
    else:
        raise InvalidRecordError(f"{field_name} must be a JournalPrefix")
    journal_id = _require_identifier(data["journal_id"], f"{field_name}.journal_id")
    last_sequence = _require_int(data["last_sequence"], f"{field_name}.last_sequence")
    if last_sequence < 1:
        raise InvalidRecordError(f"{field_name}.last_sequence must be positive")
    head_hash = _require_digest(data["head_hash"], f"{field_name}.head_hash")
    return {
        "journal_id": journal_id,
        "last_sequence": last_sequence,
        "head_hash": head_hash,
    }


def _coerce_evidence_refs(value: Any, field_name: str) -> tuple[dict[str, Any], ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise InvalidRecordError(f"{field_name} must be a sequence of EvidenceRefs")
    refs: list[dict[str, Any]] = []
    for index, raw in enumerate(value):
        if isinstance(raw, evidence_journal.EvidenceRef):
            try:
                ref = evidence_journal.EvidenceRef.from_dict(raw.to_dict())
            except (TypeError, ValueError) as exc:
                raise InvalidRecordError(
                    f"{field_name}[{index}] is invalid: {exc}"
                ) from exc
        elif isinstance(raw, Mapping):
            data = _require_exact_keys(
                raw, _EVIDENCE_REF_FIELDS, f"{field_name}[{index}]"
            )
            try:
                ref = evidence_journal.EvidenceRef.from_dict(dict(data))
            except (TypeError, ValueError) as exc:
                raise InvalidRecordError(
                    f"{field_name}[{index}] is invalid: {exc}"
                ) from exc
        else:
            raise InvalidRecordError(
                f"{field_name}[{index}] must be an EvidenceRef"
            )
        refs.append(ref.to_dict())
    if not refs:
        raise InvalidRecordError(f"{field_name} requires at least one EvidenceRef")
    return tuple(refs)


def _coerce_artifact(value: Any, field_name: str) -> dict[str, Any]:
    if isinstance(value, artifact_store.ArtifactReference):
        return value.to_dict()
    if isinstance(value, Mapping):
        data = _require_exact_keys(value, _ARTIFACT_FIELDS, field_name)
        try:
            ref = artifact_store.ArtifactReference.from_dict(dict(data))
        except (TypeError, ValueError) as exc:
            raise InvalidRecordError(f"{field_name} is invalid: {exc}") from exc
        return ref.to_dict()
    raise InvalidRecordError(f"{field_name} must be an ArtifactReference")


def _coerce_version_pin(value: Any, field_name: str) -> dict[str, Any]:
    data = _require_exact_keys(value, _PIN_FIELDS, field_name)
    return {
        "id": _require_identifier(data["id"], f"{field_name}.id"),
        "version": _require_identifier(data["version"], f"{field_name}.version"),
        "artifact_digest": _require_digest(
            data["artifact_digest"], f"{field_name}.artifact_digest"
        ),
    }


# ---------------------------------------------------------------------------
# Public record types
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EntityRegistration:
    """Immutable ``W.EntityRegistration`` for one owner-separated entity."""

    registration_id: str
    entity: Mapping[str, Any]
    identity: Mapping[str, Any]
    owners: Mapping[str, Any]
    evidence_prefix: Any
    evidence_refs: Sequence[Any]
    record_type: str = RECORD_TYPE_ENTITY
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": self.record_type,
            "schema_version": self.schema_version,
            "registration_id": self.registration_id,
            "entity": self.entity,
            "identity": self.identity,
            "owners": self.owners,
            "evidence_prefix": self.evidence_prefix,
            "evidence_refs": self.evidence_refs,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "EntityRegistration":
        allowed = {
            "record_type",
            "schema_version",
            "registration_id",
            "entity",
            "identity",
            "owners",
            "evidence_prefix",
            "evidence_refs",
        }
        _require_exact_keys(data, allowed, "EntityRegistration")
        return cls(
            registration_id=data["registration_id"],
            entity=data["entity"],
            identity=data["identity"],
            owners=data["owners"],
            evidence_prefix=data["evidence_prefix"],
            evidence_refs=data["evidence_refs"],
            record_type=data["record_type"],
            schema_version=data["schema_version"],
        )


@dataclass(frozen=True, slots=True)
class DataDomainRevision:
    """Complete ``W.DataDomainRevision`` for a job/session domain."""

    entity: Mapping[str, Any]
    registration_digest: str
    domain: str
    owner_domain: str
    writer_id: str
    revision: int
    previous_revision: int
    evidence_prefix: Any
    evidence_refs: Sequence[Any]
    value: Mapping[str, Any]
    record_type: str = RECORD_TYPE_DOMAIN
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": self.record_type,
            "schema_version": self.schema_version,
            "entity": self.entity,
            "registration_digest": self.registration_digest,
            "domain": self.domain,
            "owner_domain": self.owner_domain,
            "writer_id": self.writer_id,
            "revision": self.revision,
            "previous_revision": self.previous_revision,
            "evidence_prefix": self.evidence_prefix,
            "evidence_refs": self.evidence_refs,
            "value": self.value,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "DataDomainRevision":
        allowed = {
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
        _require_exact_keys(data, allowed, "DataDomainRevision")
        return cls(
            entity=data["entity"],
            registration_digest=data["registration_digest"],
            domain=data["domain"],
            owner_domain=data["owner_domain"],
            writer_id=data["writer_id"],
            revision=data["revision"],
            previous_revision=data["previous_revision"],
            evidence_prefix=data["evidence_prefix"],
            evidence_refs=data["evidence_refs"],
            value=data["value"],
            record_type=data["record_type"],
            schema_version=data["schema_version"],
        )


@dataclass(frozen=True, slots=True)
class AxisRevision:
    """Complete ``W.AxisRevision`` for one lifecycle axis."""

    attempt: Mapping[str, Any]
    commission_digest: str
    axis: str
    owner_domain: str
    writer_id: str
    revision: int
    previous_revision: int
    evidence_prefix: Any
    evidence_refs: Sequence[Any]
    value: Mapping[str, Any]
    record_type: str = RECORD_TYPE_AXIS
    schema_version: str = AXIS_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": self.record_type,
            "schema_version": self.schema_version,
            "attempt": self.attempt,
            "commission_digest": self.commission_digest,
            "axis": self.axis,
            "owner_domain": self.owner_domain,
            "writer_id": self.writer_id,
            "revision": self.revision,
            "previous_revision": self.previous_revision,
            "evidence_prefix": self.evidence_prefix,
            "evidence_refs": self.evidence_refs,
            "value": self.value,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "AxisRevision":
        allowed = {
            "record_type",
            "schema_version",
            "attempt",
            "commission_digest",
            "axis",
            "owner_domain",
            "writer_id",
            "revision",
            "previous_revision",
            "evidence_prefix",
            "evidence_refs",
            "value",
        }
        _require_exact_keys(data, allowed, "AxisRevision")
        return cls(
            attempt=data["attempt"],
            commission_digest=data["commission_digest"],
            axis=data["axis"],
            owner_domain=data["owner_domain"],
            writer_id=data["writer_id"],
            revision=data["revision"],
            previous_revision=data["previous_revision"],
            evidence_prefix=data["evidence_prefix"],
            evidence_refs=data["evidence_refs"],
            value=data["value"],
            record_type=data["record_type"],
            schema_version=data["schema_version"],
        )


@dataclass(frozen=True, slots=True)
class PublishedRevision:
    """Verified locally published revision returned by the read helpers."""

    entity: Mapping[str, Any]
    domain: str
    owner_domain: str
    writer_id: str
    revision: int
    previous_revision: int
    content_digest: str
    reference: artifact_store.ArtifactReference
    record: Mapping[str, Any]

    @property
    def value(self) -> Mapping[str, Any]:
        return self.record["value"]


# ---------------------------------------------------------------------------
# Internal verified views and store
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _RevisionView:
    kind: str  # "data" | "axis"
    record: dict[str, Any]
    entity: dict[str, Any]
    domain: str
    owner_domain: str
    writer_id: str
    revision: int
    previous_revision: int
    value: dict[str, Any]
    evidence_prefix: dict[str, Any]
    payload: bytes
    digest: str


@dataclass(frozen=True, slots=True)
class _RegistrationEntry:
    record: dict[str, Any]
    digest: str
    reference: artifact_store.ArtifactReference


@dataclass(frozen=True, slots=True)
class _PublishedEntry:
    revision: int
    previous_revision: int
    digest: str
    reference: artifact_store.ArtifactReference
    record: dict[str, Any]
    value: dict[str, Any]
    owner_domain: str
    writer_id: str


@dataclass(frozen=True, slots=True)
class _Receipt:
    fingerprint: str
    reference: artifact_store.ArtifactReference


_STATE_LOCK = threading.RLock()
_REGISTRATION_LOCK = threading.RLock()
_OWNER_LOCKS: dict[str, threading.RLock] = {}
_REGISTRATIONS: dict[str, _RegistrationEntry] = {}
_REGISTRATION_IDS: dict[str, str] = {}
_HEADS: dict[tuple[str, str], _PublishedEntry] = {}
_REVISIONS: dict[tuple[str, str, int], _PublishedEntry] = {}
_RECEIPTS: dict[tuple[str, str, str], _Receipt] = {}


def _owner_lock(owner_domain: str) -> threading.RLock:
    with _STATE_LOCK:
        lock = _OWNER_LOCKS.get(owner_domain)
        if lock is None:
            lock = threading.RLock()
            _OWNER_LOCKS[owner_domain] = lock
        return lock


def _entity_id(entity: Mapping[str, Any]) -> str:
    entity_type = entity.get("entity_type")
    if entity_type == "job":
        return (
            f"job.{_require_identifier(entity.get('target'), 'entity.target')}."
            f"{_require_identifier(entity.get('job_id'), 'entity.job_id')}"
        )
    if entity_type == "application_attempt":
        return (
            f"attempt."
            f"{_require_identifier(entity.get('attempt_id'), 'entity.attempt_id')}."
            f"{_require_identifier(entity.get('kind'), 'entity.kind')}"
        )
    if entity_type == "hellscape_session":
        return f"session.{_require_identifier(entity.get('session_id'), 'entity.session_id')}"
    raise InvalidRecordError(f"unknown entity_type: {entity_type!r}")


def _canonical(value: Any) -> bytes:
    return _canonical_bytes(_jsonable(value))


# ---------------------------------------------------------------------------
# Registration validation
# ---------------------------------------------------------------------------


def _validate_entity(entity: Any) -> tuple[dict[str, Any], str, tuple[str, ...]]:
    if not isinstance(entity, Mapping):
        raise InvalidRecordError("registration.entity must be a mapping")
    entity_type = entity.get("entity_type")
    if entity_type not in _ENTITY_FIELDS:
        raise InvalidRecordError(f"unknown entity_type: {entity_type!r}")
    data = _require_exact_keys(
        entity, _ENTITY_FIELDS[entity_type], "registration.entity"
    )
    normalized = {key: data[key] for key in sorted(data)}
    if entity_type == "job":
        _require_identifier(normalized["target"], "entity.target")
        _require_identifier(normalized["job_id"], "entity.job_id")
    elif entity_type == "application_attempt":
        _require_identifier(normalized["attempt_id"], "entity.attempt_id")
        if normalized["kind"] not in ("practice", "production"):
            raise InvalidRecordError("entity.kind must be practice or production")
    else:
        _require_identifier(normalized["session_id"], "entity.session_id")
    return normalized, entity_type, DOMAINS_BY_ENTITY[entity_type]


def _validate_attempt_context(attempt: Any, entity: Mapping[str, Any]) -> dict[str, Any]:
    required = {
        "attempt_id",
        "kind",
        "target_class",
        "target_id",
        "evaluation_partition",
        "rehearsal_of",
        "performance_of",
        "derived_from",
    }
    data = _require_exact_keys(attempt, required, "identity.attempt")
    if data["attempt_id"] != entity["attempt_id"] or data["kind"] != entity["kind"]:
        raise InvalidRecordError("identity.attempt does not match the entity key")
    if data["kind"] == "production":
        if (
            data["target_class"] != "employer_origin"
            or data["evaluation_partition"] != "held_out"
        ):
            raise InvalidRecordError(
                "a production attempt requires employer_origin and held_out"
            )
    else:
        if (
            data["target_class"] != "laboratory_fixture"
            or data["evaluation_partition"] != "held_in"
        ):
            raise InvalidRecordError(
                "a practice attempt requires laboratory_fixture and held_in"
            )
    _require_identifier(data["target_id"], "identity.attempt.target_id")
    for field_name in ("rehearsal_of", "performance_of", "derived_from"):
        links = data[field_name]
        if isinstance(links, (str, bytes)) or not isinstance(links, Sequence):
            raise InvalidRecordError(
                f"identity.attempt.{field_name} must be a sequence"
            )
        for index, link in enumerate(links):
            _require_exact_keys(
                link,
                frozenset({"attempt_id", "kind"}),
                f"identity.attempt.{field_name}[{index}]",
            )
            _require_identifier(
                link["attempt_id"],
                f"identity.attempt.{field_name}[{index}].attempt_id",
            )
            if link["kind"] not in ("practice", "production"):
                raise InvalidRecordError(
                    f"identity.attempt.{field_name}[{index}].kind is invalid"
                )
    return {key: data[key] for key in sorted(data)}


def _validate_execution_descriptor(execution: Any) -> dict[str, Any]:
    required = {
        "mode",
        "subject",
        "connector_version",
        "binding_version",
        "assistance",
    }
    data = _require_exact_keys(execution, required, "identity.execution")
    mode = data["mode"]
    if mode not in ("manual", "subject"):
        raise InvalidRecordError("identity.execution.mode must be manual or subject")
    if mode == "manual":
        if _missing_reason(data["subject"]) != "not_applicable":
            raise InvalidRecordError(
                "manual execution requires Missing(not_applicable) for subject"
            )
        for field_name in ("connector_version", "binding_version"):
            if _missing_reason(data[field_name]) != "not_applicable":
                raise InvalidRecordError(
                    f"manual execution requires Missing(not_applicable) for "
                    f"{field_name}"
                )
    else:
        subject = data["subject"]
        if not isinstance(subject, Mapping):
            raise InvalidRecordError("subject execution requires a SubjectIdentity")
        _require_identifier(subject.get("subject_id"), "identity.execution.subject.subject_id")
        _require_identifier(
            data["connector_version"], "identity.execution.connector_version"
        )
        _require_identifier(
            data["binding_version"], "identity.execution.binding_version"
        )
    assistance = data["assistance"]
    if not isinstance(assistance, Mapping):
        raise InvalidRecordError("identity.execution.assistance must be a mapping")
    for field_name in (
        "planning_owner",
        "assistance_track",
        "planner_identity",
        "plan",
        "online_replanning",
        "description",
    ):
        if field_name not in assistance:
            raise InvalidRecordError(
                f"identity.execution.assistance.{field_name} is required"
            )
    if assistance["planning_owner"] not in {
        "subject",
        "external_planner",
        "operator",
        "none",
    }:
        raise InvalidRecordError(
            "identity.execution.assistance.planning_owner is invalid"
        )
    _require_identifier(
        assistance["assistance_track"],
        "identity.execution.assistance.assistance_track",
    )
    if type(assistance["online_replanning"]) is not bool:
        raise InvalidRecordError(
            "identity.execution.assistance.online_replanning must be a bool"
        )
    if not isinstance(assistance["description"], str) or not assistance[
        "description"
    ]:
        raise InvalidRecordError(
            "identity.execution.assistance.description must be nonempty"
        )
    return {key: data[key] for key in sorted(data)}


def _validate_identity(
    entity_type: str, entity: Mapping[str, Any], identity: Any
) -> dict[str, Any]:
    if not isinstance(identity, Mapping):
        raise InvalidRecordError("registration.identity must be a mapping")
    if entity_type == "job":
        data = _require_exact_keys(
            identity,
            frozenset({"portfolio_job_id", "first_discovery_ref"}),
            "registration.identity",
        )
        _require_identifier(data["portfolio_job_id"], "identity.portfolio_job_id")
        _coerce_evidence_refs([data["first_discovery_ref"]], "identity.first_discovery_ref")
        return {
            "portfolio_job_id": data["portfolio_job_id"],
            "first_discovery_ref": _jsonable(data["first_discovery_ref"]),
        }
    if entity_type == "application_attempt":
        data = _require_exact_keys(
            identity,
            frozenset({"commission", "attempt", "execution"}),
            "registration.identity",
        )
        commission = _coerce_artifact(data["commission"], "identity.commission")
        attempt = _validate_attempt_context(data["attempt"], entity)
        execution = _validate_execution_descriptor(data["execution"])
        return {
            "commission": commission,
            "attempt": attempt,
            "execution": execution,
        }
    required = {
        "run_id",
        "journal_id",
        "manifest",
        "fixture_build",
        "attempt",
        "execution",
        "job_content",
    }
    data = _require_exact_keys(identity, required, "registration.identity")
    _require_identifier(data["run_id"], "identity.run_id")
    _require_identifier(data["journal_id"], "identity.journal_id")
    _coerce_artifact(data["manifest"], "identity.manifest")
    _coerce_version_pin(data["fixture_build"], "identity.fixture_build")
    if not isinstance(data["attempt"], Mapping):
        raise InvalidRecordError("identity.attempt must be an AttemptContext")
    _validate_execution_descriptor(data["execution"])
    if not isinstance(data["job_content"], Mapping):
        raise InvalidRecordError("identity.job_content must be a mapping")
    return {key: _jsonable(data[key]) for key in sorted(data)}


def _validate_owners(
    entity_type: str,
    domains: tuple[str, ...],
    owners: Any,
    identity: Mapping[str, Any],
    entity: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(owners, Mapping):
        raise InvalidRecordError("registration.owners must be a mapping")
    _require_exact_keys(owners, frozenset(domains), "registration.owners")
    normalized: dict[str, Any] = {}
    seen_owner_domains: set[str] = set()
    seen_writers: set[str] = set()
    execution_mode = (
        identity["execution"]["mode"]
        if entity_type == "application_attempt"
        else None
    )
    for domain in domains:
        owner = _require_exact_keys(
            owners[domain], _OWNER_FIELDS, f"registration.owners.{domain}"
        )
        expected_role = DOMAIN_ROLES[(entity_type, domain)]
        role = owner["role"]
        allowed_roles = {expected_role}
        if (entity_type, domain) == ("application_attempt", "observation"):
            allowed_roles.add("observer")
        if role not in allowed_roles:
            raise InvalidRecordError(
                f"registration.owners.{domain}.role must be {expected_role!r}"
            )
        owner_domain = _require_identifier(
            owner["owner_domain"], f"registration.owners.{domain}.owner_domain"
        )
        if owner_domain in seen_owner_domains:
            raise InvalidRecordError(
                f"owner domain {owner_domain!r} is declared more than once"
            )
        seen_owner_domains.add(owner_domain)
        source_id = owner["source_id"]
        writer_id = owner["writer_id"]
        manual_slot = (
            entity_type == "application_attempt"
            and execution_mode == "manual"
            and domain in ("dispatch", "execution")
        )
        if manual_slot:
            if _missing_reason(source_id) != "not_applicable":
                raise InvalidRecordError(
                    f"registration.owners.{domain}.source_id must be "
                    "Missing(not_applicable) for a manual attempt"
                )
            if _missing_reason(writer_id) != "not_applicable":
                raise InvalidRecordError(
                    f"registration.owners.{domain}.writer_id must be "
                    "Missing(not_applicable) for a manual attempt"
                )
            normalized_source: Any = _missing_dict("not_applicable")
            normalized_writer: Any = _missing_dict("not_applicable")
        else:
            normalized_source = _require_identifier(
                source_id, f"registration.owners.{domain}.source_id"
            )
            normalized_writer = _require_identifier(
                writer_id, f"registration.owners.{domain}.writer_id"
            )
            if normalized_writer in seen_writers:
                raise InvalidRecordError(
                    "each applicable domain needs its own bound publication writer"
                )
            seen_writers.add(normalized_writer)
        policy = _coerce_version_pin(
            owner["publication_policy"],
            f"registration.owners.{domain}.publication_policy",
        )
        normalized[domain] = {
            "role": role,
            "source_id": normalized_source,
            "writer_id": normalized_writer,
            "owner_domain": owner_domain,
            "publication_policy": policy,
        }
    if entity_type == "application_attempt":
        attempt = identity["attempt"]
        execution = identity["execution"]
        application_source = normalized["application"]["source_id"]
        if isinstance(application_source, str) and application_source != attempt[
            "target_id"
        ]:
            raise InvalidRecordError(
                "application.source_id must identify the commissioned target"
            )
        execution_source = normalized["execution"]["source_id"]
        if execution_mode == "subject" and isinstance(execution_source, str):
            subject = execution["subject"]
            if isinstance(subject, Mapping) and subject.get(
                "subject_id"
            ) != execution_source:
                raise InvalidRecordError(
                    "execution.source_id must identify the commissioned subject"
                )
    return normalized


def _validate_registration(registration: Any) -> dict[str, Any]:
    if isinstance(registration, EntityRegistration):
        raw = registration.to_dict()
    elif isinstance(registration, Mapping):
        raw = EntityRegistration.from_dict(registration).to_dict()
    else:
        raise InvalidRecordError(
            "registration must be an EntityRegistration or mapping"
        )
    _require_exact_keys(
        raw,
        frozenset(
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
        ),
        "EntityRegistration",
    )
    if raw["record_type"] != RECORD_TYPE_ENTITY:
        raise InvalidRecordError(
            f"registration.record_type must be {RECORD_TYPE_ENTITY!r}"
        )
    if raw["schema_version"] != SCHEMA_VERSION:
        raise InvalidRecordError(
            f"registration.schema_version must be {SCHEMA_VERSION!r}"
        )
    registration_id = _require_identifier(
        raw["registration_id"], "registration.registration_id"
    )
    entity, entity_type, domains = _validate_entity(raw["entity"])
    identity = _validate_identity(entity_type, entity, raw["identity"])
    owners = _validate_owners(
        entity_type, domains, raw["owners"], identity, entity
    )
    prefix = _coerce_prefix(raw["evidence_prefix"], "registration.evidence_prefix")
    refs = _coerce_evidence_refs(raw["evidence_refs"], "registration.evidence_refs")
    return _jsonable(
        {
            "record_type": RECORD_TYPE_ENTITY,
            "schema_version": SCHEMA_VERSION,
            "registration_id": registration_id,
            "entity": entity,
            "identity": identity,
            "owners": owners,
            "evidence_prefix": prefix,
            "evidence_refs": list(refs),
        },
        "EntityRegistration",
    )


# ---------------------------------------------------------------------------
# Revision validation
# ---------------------------------------------------------------------------


def _validate_revision_record(
    revision: Any,
) -> tuple[str, dict[str, Any], dict[str, Any], str, tuple[str, ...]]:
    if isinstance(revision, DataDomainRevision):
        raw = revision.to_dict()
        kind = "data"
    elif isinstance(revision, AxisRevision):
        raw = revision.to_dict()
        kind = "axis"
    elif isinstance(revision, Mapping):
        record_type = revision.get("record_type")
        if record_type == RECORD_TYPE_DOMAIN:
            raw = DataDomainRevision.from_dict(revision).to_dict()
            kind = "data"
        elif record_type == RECORD_TYPE_AXIS:
            raw = AxisRevision.from_dict(revision).to_dict()
            kind = "axis"
        else:
            raise InvalidRecordError(
                "a revision must be DataDomainRevision or AxisRevision"
            )
    else:
        raise InvalidRecordError(
            "a revision must be DataDomainRevision or AxisRevision"
        )
    required = (
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
        if kind == "data"
        else {
            "record_type",
            "schema_version",
            "attempt",
            "commission_digest",
            "axis",
            "owner_domain",
            "writer_id",
            "revision",
            "previous_revision",
            "evidence_prefix",
            "evidence_refs",
            "value",
        }
    )
    _require_exact_keys(raw, frozenset(required), "revision")
    if kind == "data":
        entity, entity_type, domains = _validate_entity(raw["entity"])
    else:
        attempt = _require_exact_keys(
            raw["attempt"],
            frozenset({"attempt_id", "kind"}),
            "revision.attempt",
        )
        _require_identifier(attempt["attempt_id"], "revision.attempt.attempt_id")
        if attempt["kind"] not in ("practice", "production"):
            raise InvalidRecordError(
                "revision.attempt.kind must be practice or production"
            )
        entity, entity_type, domains = _validate_entity(
            {
                "entity_type": "application_attempt",
                "attempt_id": attempt["attempt_id"],
                "kind": attempt["kind"],
            }
        )
    if kind == "data":
        if raw["record_type"] != RECORD_TYPE_DOMAIN:
            raise InvalidRecordError(
                f"revision.record_type must be {RECORD_TYPE_DOMAIN!r}"
            )
        if raw["schema_version"] != SCHEMA_VERSION:
            raise InvalidRecordError(
                f"revision.schema_version must be {SCHEMA_VERSION!r}"
            )
        domain = raw["domain"]
        if not isinstance(domain, str) or domain not in domains:
            raise DomainMismatchError(
                f"domain {domain!r} is not a declared domain of {entity_type}"
            )
        if entity_type not in ("job", "hellscape_session"):
            raise DomainMismatchError(
                "application attempts publish AxisRevision records, not "
                "DataDomainRevision"
            )
        registration_digest = _require_digest(
            raw["registration_digest"], "revision.registration_digest"
        )
    else:
        if raw["record_type"] != RECORD_TYPE_AXIS:
            raise InvalidRecordError(
                f"revision.record_type must be {RECORD_TYPE_AXIS!r}"
            )
        if raw["schema_version"] != AXIS_SCHEMA_VERSION:
            raise InvalidRecordError(
                f"revision.schema_version must be {AXIS_SCHEMA_VERSION!r}"
            )
        if entity_type != "application_attempt":
            raise DomainMismatchError(
                "AxisRevision records apply only to application attempts"
            )
        axis = raw["axis"]
        if not isinstance(axis, str) or axis not in AXIS_DOMAINS:
            raise DomainMismatchError(f"unknown lifecycle axis: {axis!r}")
        domain = axis
        _require_digest(raw["commission_digest"], "revision.commission_digest")
    value = raw["value"]
    if not isinstance(value, Mapping):
        raise InvalidRecordError("revision.value must be a complete mapping")
    value = _jsonable(value, "revision.value")
    revision_number = _require_int(raw["revision"], "revision.revision")
    previous_revision = _require_int(
        raw["previous_revision"], "revision.previous_revision"
    )
    if revision_number < 1:
        raise InvalidRecordError("revision.revision must be positive")
    if previous_revision < 0:
        raise InvalidRecordError("revision.previous_revision must be nonnegative")
    if revision_number != previous_revision + 1:
        raise InvalidRecordError(
            "revision.revision must equal previous_revision + 1"
        )
    owner_domain = _require_identifier(
        raw["owner_domain"], "revision.owner_domain"
    )
    writer_id = _require_identifier(raw["writer_id"], "revision.writer_id")
    prefix = _coerce_prefix(raw["evidence_prefix"], "revision.evidence_prefix")
    refs = _coerce_evidence_refs(raw["evidence_refs"], "revision.evidence_refs")
    _require_domain_value(entity_type, domain, value)
    base = {
        "record_type": raw["record_type"],
        "schema_version": raw["schema_version"],
        "owner_domain": owner_domain,
        "writer_id": writer_id,
        "revision": revision_number,
        "previous_revision": previous_revision,
        "evidence_prefix": prefix,
        "evidence_refs": list(refs),
        "value": value,
    }
    if kind == "data":
        normalized = {
            **base,
            "entity": entity,
            "registration_digest": registration_digest,
            "domain": domain,
        }
    else:
        normalized = {
            **base,
            "attempt": {
                "attempt_id": raw["attempt"]["attempt_id"],
                "kind": raw["attempt"]["kind"],
            },
            "commission_digest": raw["commission_digest"],
            "axis": domain,
        }
    return (
        _jsonable(normalized, "revision"),
        entity,
        domain,
        kind,
        tuple(domains),
    )


def _require_domain_value(
    entity_type: str, domain: str, value: Mapping[str, Any]
) -> None:
    required = DOMAIN_VALUE_FIELDS.get((entity_type, domain))
    if required is None:
        raise DomainMismatchError(
            f"no value contract for {entity_type}.{domain}"
        )
    keys = set(value.keys())
    missing = [field for field in required if field not in keys]
    if missing:
        raise InvalidRecordError(
            f"{entity_type}.{domain} value is incomplete; missing {missing}"
        )
    extra = sorted(keys - set(required))
    if extra:
        raise InvalidRecordError(
            f"{entity_type}.{domain} value must be a closed complete snapshot; "
            f"undeclared fields: {extra}"
        )
    if domain == "dispatch":
        _validate_dispatch_value(value)
    elif domain == "observation" and entity_type == "application_attempt":
        _validate_observation_value(value)
    elif domain == "report" and entity_type == "application_attempt":
        _validate_report_value(value)


def _validate_dispatch_value(value: Mapping[str, Any]) -> None:
    state = value.get("state")
    if not isinstance(state, str):
        raise InvalidRecordError("dispatch.state must be a string or Missing")
    allowed = {
        "not_started",
        "prepared",
        "dispatching",
        "accepted",
        "rejected",
        "uncertain",
    }
    if state not in allowed:
        raise InvalidRecordError(f"unknown dispatch state: {state!r}")
    if state == "prepared" and _is_missing(value.get("request_digest")):
        raise InvalidRecordError("a prepared dispatch requires request_digest")
    if state in ("dispatching", "accepted", "uncertain"):
        _require_identifier(value.get("local_handle"), "dispatch.local_handle")
        _require_digest(value.get("request_digest"), "dispatch.request_digest")
        refs = value.get("delivery_refs")
        if not isinstance(refs, Sequence) or isinstance(refs, (str, bytes)) or not refs:
            raise InvalidRecordError(
                "dispatching/accepted/uncertain requires delivery_refs"
            )
    if state == "accepted":
        refs = value.get("acceptance_refs")
        if not isinstance(refs, Sequence) or isinstance(refs, (str, bytes)) or not refs:
            raise InvalidRecordError("accepted dispatch requires acceptance_refs")
    if state == "not_started":
        if not _is_missing(value.get("native_run_id")):
            raise InvalidRecordError(
                "not_started dispatch requires Missing native_run_id"
            )
        for field_name in ("delivery_refs", "acceptance_refs"):
            refs = value.get(field_name)
            if refs:
                raise InvalidRecordError(
                    f"not_started dispatch requires empty {field_name}"
                )


def _validate_observation_value(value: Mapping[str, Any]) -> None:
    state = value.get("state")
    allowed = {"not_opened", "open", "draining", "closed"}
    if not isinstance(state, str) or state not in allowed:
        raise InvalidRecordError(f"unknown observation state: {state!r}")
    if state == "not_opened":
        if not _is_missing(value.get("opened_at")):
            raise InvalidRecordError(
                "not_opened observation requires Missing opened_at"
            )
        if not _is_missing(value.get("active_deadline")):
            raise InvalidRecordError(
                "not_opened observation requires Missing active_deadline"
            )
    if state in ("open", "draining"):
        if _is_missing(value.get("opened_at")):
            raise InvalidRecordError(f"{state} observation requires opened_at")
        if _is_missing(value.get("active_deadline")):
            raise InvalidRecordError(
                f"{state} observation requires active_deadline"
            )
    if state in ("draining", "closed"):
        reason = value.get("close_reason")
        if not isinstance(reason, str) or reason not in CLOSE_REASONS:
            raise InvalidRecordError(
                f"{state} observation requires a declared close_reason"
            )
    if state == "draining":
        for field_name in ("drain_started_at", "drain_deadline"):
            if _is_missing(value.get(field_name)):
                raise InvalidRecordError(
                    f"draining observation requires {field_name}"
                )
    if state == "closed":
        closed_at = value.get("closed_at")
        if _is_missing(closed_at) or not isinstance(closed_at, Mapping):
            raise InvalidRecordError("closed observation requires closed_at")
        at_close = value.get("at_close")
        if _is_missing(at_close) or not isinstance(at_close, Mapping):
            raise InvalidRecordError("closed observation requires a CloseSnapshot")


def _validate_report_value(value: Mapping[str, Any]) -> None:
    state = value.get("state")
    if not (_is_missing(state) or state in ("reconciled", "contradicted")):
        raise InvalidRecordError("report.state is invalid")
    coverage = value.get("coverage")
    if coverage not in ("complete", "incomplete", "not_applicable"):
        raise InvalidRecordError("report.coverage is invalid")
    comparisons = value.get("comparisons")
    if not isinstance(comparisons, Sequence) or isinstance(comparisons, (str, bytes)):
        raise InvalidRecordError("report.comparisons must be a sequence")
    results: list[Any] = []
    for index, comparison in enumerate(comparisons):
        if not isinstance(comparison, Mapping):
            raise InvalidRecordError(
                f"report.comparisons[{index}] must be a mapping"
            )
        if "claim_id" not in comparison:
            raise InvalidRecordError(
                f"report.comparisons[{index}].claim_id is required"
            )
        result = comparison.get("result")
        if result not in (
            "consistent",
            "contradicted",
            "not_comparable",
            "indeterminate",
        ):
            raise InvalidRecordError(
                f"report.comparisons[{index}].result is invalid"
            )
        results.append(result)
    if state == "reconciled":
        if coverage != "complete":
            raise InvalidRecordError("a reconciled report requires complete coverage")
        if not comparisons or "contradicted" in results:
            raise InvalidRecordError(
                "a reconciled report requires non-contradicted comparisons"
            )
    if state == "contradicted" and "contradicted" not in results:
        raise InvalidRecordError(
            "a contradicted report requires a contradicted comparison"
        )
    if "contradicted" in results and state != "contradicted":
        raise InvalidRecordError(
            "a contradicted comparison requires the contradicted state"
        )
    if coverage == "complete" and state not in ("reconciled", "contradicted"):
        raise InvalidRecordError(
            "complete coverage requires a reconciled or contradicted state"
        )


# ---------------------------------------------------------------------------
# Transition, cumulative-history, and pin rules
# ---------------------------------------------------------------------------


def _value_state(value: Mapping[str, Any]) -> str:
    state = value.get("state")
    if not isinstance(state, str):
        raise InvalidRecordError("axis value state must be a string")
    return state


def _validate_axis_transition(
    axis: str,
    previous: Mapping[str, Any] | None,
    current: Mapping[str, Any],
) -> None:
    if axis == "dispatch":
        table = AXIS_TRANSITIONS
    elif axis == "observation":
        table = OBSERVATION_TRANSITIONS
    else:
        return
    previous_state = "unpublished" if previous is None else _value_state(previous)
    if previous_state not in table:
        raise InvalidRecordError(
            f"the committed {axis} publication carries an undeclared state "
            f"{previous_state!r}"
        )
    new_state = _value_state(current)
    if new_state not in table[previous_state]:
        raise TransitionRejectedError(
            f"{axis} transition {previous_state!r} -> {new_state!r} is not "
            "declared"
        )
    if (
        axis == "observation"
        and previous_state == "closed"
        and new_state == "closed"
        and previous is not None
    ):
        for field_name in _OBSERVATION_CLOSURE_FIELDS:
            if _canonical(previous.get(field_name)) != _canonical(
                current.get(field_name)
            ):
                raise TransitionRejectedError(
                    "closed-to-closed observation must preserve the original "
                    f"closure field {field_name!r}"
                )


def _validate_cumulative(
    axis: str,
    previous: Mapping[str, Any] | None,
    current: Mapping[str, Any],
) -> None:
    if axis not in ("execution", "application"):
        return
    entry_field = "claims" if axis == "execution" else "facts"
    id_field = "claim_id" if axis == "execution" else "fact_id"
    entries = current.get(entry_field)
    if not isinstance(entries, Sequence) or isinstance(entries, (str, bytes)):
        raise InvalidRecordError(f"{axis}.{entry_field} must be an array")
    if not entries:
        raise InvalidRecordError(
            f"{axis}.{entry_field} requires at least one entry when published"
        )
    seen: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, Mapping):
            raise InvalidRecordError(
                f"{axis}.{entry_field}[{index}] must be a mapping"
            )
        entry_id = _require_identifier(
            entry.get(id_field), f"{axis}.{entry_field}[{index}].{id_field}"
        )
        if entry_id in seen:
            raise CumulativeHistoryError(
                f"duplicate {id_field} {entry_id!r} in one publication"
            )
        seen.add(entry_id)
        if axis == "execution":
            if entry.get("scope") not in (
                "primitive",
                "application_postcondition",
                "execution_lifecycle",
                "unknown",
            ):
                raise InvalidRecordError(
                    f"execution.claims[{index}].scope is invalid"
                )
            state = entry.get("state")
            if not (
                _is_missing(state)
                or state in ("running", "completed", "failed", "stopped", "unknown")
            ):
                raise InvalidRecordError(
                    f"execution.claims[{index}].state is invalid"
                )
        else:
            for field_name in ("origin_id", "candidate_id", "job_id"):
                _require_identifier(
                    entry.get(field_name),
                    f"application.facts[{index}].{field_name}",
                )
            if entry.get("state") not in ("committed", "not_committed"):
                raise InvalidRecordError(
                    f"application.facts[{index}].state is invalid"
                )
            if entry.get("coverage") not in (
                "at_boundary",
                "final_for_attempt",
            ):
                raise InvalidRecordError(
                    f"application.facts[{index}].coverage is invalid"
                )
        refs = entry.get("evidence_refs")
        if (
            not isinstance(refs, Sequence)
            or isinstance(refs, (str, bytes))
            or not refs
        ):
            raise InvalidRecordError(
                f"{axis}.{entry_field}[{index}] requires evidence_refs"
            )
    if previous is None:
        return
    prior_entries = previous.get(entry_field)
    if not isinstance(prior_entries, Sequence) or isinstance(
        prior_entries, (str, bytes)
    ):
        raise OwnerRevisionStateError(
            f"the committed {axis} publication has no cumulative {entry_field}"
        )
    if len(entries) < len(prior_entries):
        raise CumulativeHistoryError(
            f"{axis}.{entry_field} cannot drop prior entries"
        )
    for index, prior in enumerate(prior_entries):
        if _canonical(prior) != _canonical(entries[index]):
            raise CumulativeHistoryError(
                f"{axis}.{entry_field}[{index}] was rewritten; cumulative "
                "histories may only append"
            )


def _normalize_pin(value: Any, label: str) -> dict[str, Any]:
    pin = _require_exact_keys(
        value, frozenset({"revision", "record_digest"}), label
    )
    revision = _require_int(pin["revision"], f"{label}.revision")
    if revision < 0:
        raise InvalidRecordError(f"{label}.revision must be nonnegative")
    digest = pin["record_digest"]
    if revision == 0:
        if _missing_reason(digest) is None:
            raise InvalidRecordError(
                f"{label}.record_digest must be a Missing envelope at revision 0"
            )
        return {"revision": 0, "record_digest": _missing_dict(_missing_reason(digest))}
    return {
        "revision": revision,
        "record_digest": _require_digest(digest, f"{label}.record_digest"),
    }


def _report_pins(value: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    inputs = value.get("inputs")
    if not isinstance(inputs, Mapping):
        raise InvalidRecordError("report.inputs must be a mapping")
    _require_exact_keys(
        inputs, frozenset(_REPORT_PIN_AXES), "report.inputs"
    )
    return {
        axis: _normalize_pin(inputs[axis], f"report.inputs.{axis}")
        for axis in _REPORT_PIN_AXES
    }


def _validate_report_pins(
    entity_id: str,
    previous: Mapping[str, Any] | None,
    current: Mapping[str, Any],
) -> None:
    new_pins = _report_pins(current)
    if previous is not None:
        prior_pins = _report_pins(previous)
        for axis in _REPORT_PIN_AXES:
            old = prior_pins[axis]
            new = new_pins[axis]
            if new["revision"] < old["revision"]:
                raise PinRegressionError(
                    f"report input pin {axis!r} regressed from revision "
                    f"{old['revision']} to {new['revision']}"
                )
            if new["revision"] == old["revision"] and _canonical(
                new["record_digest"]
            ) != _canonical(old["record_digest"]):
                raise PinRegressionError(
                    f"report input pin {axis!r} changed digest without advancing "
                    "its revision"
                )
    for axis in _REPORT_PIN_AXES:
        pin = new_pins[axis]
        if pin["revision"] == 0:
            continue
        with _STATE_LOCK:
            published = _REVISIONS.get((entity_id, axis, pin["revision"]))
        if published is None:
            raise PinResolutionError(
                f"report input pin {axis!r} names unpublished revision "
                f"{pin['revision']}"
            )
        if published.digest != pin["record_digest"]:
            raise PinResolutionError(
                f"report input pin {axis!r} digest does not identify the "
                f"published revision {pin['revision']}"
            )


# ---------------------------------------------------------------------------
# Journal / prefix / lease integration
# ---------------------------------------------------------------------------


def _verify_cited_prefix(channel_id: str, prefix: Mapping[str, Any], label: str) -> None:
    """Verify a cited prefix when its journal is locally admitted.

    A registration or publication may cite a journal that this process has not
    admitted yet (for example, a connector-owned journal).  In that case the
    structurally validated JournalPrefix remains the caller's cited evidence;
    once the journal is admitted, a bad prefix is rejected here.
    """
    journal_prefix = evidence_journal.JournalPrefix(
        journal_id=prefix["journal_id"],
        last_sequence=prefix["last_sequence"],
        head_hash=prefix["head_hash"],
    )
    try:
        evidence_journal.read_prefix(channel_id, journal_prefix)
    except evidence_journal.JournalNotAdmittedError:
        return
    except access_policy.AuthorizationError as exc:
        raise InvalidRecordError(
            f"{label} is not readable by the authenticated channel: {exc}"
        ) from exc
    except evidence_journal.EvidenceJournalError as exc:
        raise InvalidRecordError(f"{label} does not verify: {exc}") from exc


def _authenticate_writer(
    channel_id: str, owner: Mapping[str, Any]
) -> access_policy.ProducerDescriptor:
    owner_domain = owner["owner_domain"]
    writer_id = owner["writer_id"]
    if not isinstance(writer_id, str):
        raise WriterAuthorityError(
            f"owner domain {owner_domain!r} has no applicable publication writer"
        )
    try:
        descriptor = access_policy.authorize(
            channel_id, f"{owner_domain}.write", writer_id
        )
    except access_policy.UnknownChannelError:
        raise
    except access_policy.AuthorizationError as exc:
        raise WriterAuthorityError(
            f"the authenticated channel is not the writer for "
            f"{owner_domain!r}: {exc}"
        ) from exc
    if descriptor.owner_domain != owner_domain:
        raise WriterAuthorityError(
            f"authenticated producer writes {descriptor.owner_domain!r}, not "
            f"{owner_domain!r}"
        )
    if descriptor.producer_id != writer_id:
        raise WriterAuthorityError(
            "the serialized writer_id is not the authenticated producer"
        )
    expected_access_role = _ROLE_TO_ACCESS_ROLE.get(owner["role"])
    if expected_access_role is not None and descriptor.role != expected_access_role:
        raise WriterAuthorityError(
            f"authenticated role {descriptor.role!r} does not match owner role "
            f"{owner['role']!r}"
        )
    return descriptor


def _authenticate_registration(
    channel_id: str, registration: Mapping[str, Any]
) -> str:
    owners = registration["owners"]
    found: tuple[str, access_policy.ProducerDescriptor] | None = None
    for domain in sorted(owners):
        owner = owners[domain]
        try:
            descriptor = access_policy.authorize(
                channel_id,
                f"{owner['owner_domain']}.write",
                registration["registration_id"],
            )
        except access_policy.GrantDeniedError:
            continue
        except access_policy.UnknownChannelError:
            raise
        if descriptor.owner_domain != owner["owner_domain"]:
            continue
        if descriptor.producer_id != owner["writer_id"]:
            raise WriterAuthorityError(
                "the registering channel is not the declared writer for "
                f"{owner['owner_domain']!r}"
            )
        expected_access_role = _ROLE_TO_ACCESS_ROLE.get(owner["role"])
        if expected_access_role is not None and descriptor.role != expected_access_role:
            raise WriterAuthorityError(
                f"authenticated role {descriptor.role!r} does not match the "
                f"registered {owner['role']!r} role"
            )
        if found is not None:
            raise WriterAuthorityError(
                "one registration cannot be authorized through two owner domains"
            )
        found = (owner["owner_domain"], descriptor)
    if found is None:
        raise WriterAuthorityError(
            "the authenticated channel is not a registered writer for this entity"
        )
    return found[0]


def _journal_revision_if_present(
    channel_id: str, owner_domain: str, entity_id: str
) -> int | None:
    """Return the admitted journal revision, or None when no journal exists."""
    try:
        state = evidence_journal.entity_state(channel_id, owner_domain, entity_id)
    except evidence_journal.JournalNotAdmittedError:
        return None
    return state.revision


def _validate_lease(
    channel_id: str, lease: Any, revision: _RevisionView
) -> Any:
    if lease is None:
        raise InvalidRecordError(
            "lease must be a LeaseRecord or a typed Missing envelope"
        )
    if _is_missing(lease):
        reason = _missing_reason(lease)
        if reason not in contract_codec.VALID_MISSING_REASONS:
            raise InvalidRecordError(f"unknown lease Missing reason: {reason!r}")
        return lease
    if not isinstance(lease, lease_authority.LeaseRecord):
        raise InvalidRecordError(
            "lease must be a LeaseRecord or a typed Missing envelope"
        )
    if lease.resource.owner_domain != revision.owner_domain:
        raise LeaseValidationError(
            "the lease resource belongs to another owner domain"
        )
    if lease.resource.entity_type != revision.entity["entity_type"]:
        raise LeaseValidationError(
            "the lease resource names a different entity type"
        )
    entity_values = {
        str(value)
        for key, value in revision.entity.items()
        if key != "entity_type" and isinstance(value, str)
    }
    entity_values.add(_entity_id(revision.entity))
    if lease.resource.entity_id not in entity_values:
        raise LeaseValidationError(
            "the lease resource names a different owner entity"
        )
    if lease.lease_owner != revision.writer_id:
        raise LeaseValidationError(
            "the completing lease is owned by a different authenticated writer"
        )
    try:
        current = lease_authority.load_lease(channel_id, lease.resource)
    except lease_authority.LeaseAuthorityError as exc:
        raise LeaseValidationError(f"no fenced current lease: {exc}") from exc
    if _is_missing(current):
        raise LeaseValidationError("the fenced authority holds no current lease")
    now = lease_authority.authority_now()
    try:
        lease_authority.validate_completion(
            lease,
            current,
            now,
            lease.entity_revision,
            lease.input_revision,
        )
    except lease_authority.LeaseAuthorityError as exc:
        raise LeaseValidationError(str(exc)) from exc
    return lease


# ---------------------------------------------------------------------------
# Public: entity registration
# ---------------------------------------------------------------------------


def register_entity(
    channel_id: str, registration: EntityRegistration
) -> artifact_store.ArtifactReference:
    """Register one immutable owner-separated entity and its owner bindings.

    Registration is authenticated through the registering channel's fixed
    access-policy grant.  Every declared domain gets exactly one writer and one
    distinct owner domain.  Identical retries return the existing registration
    artifact; different bytes for the same entity are a conflict.
    """
    _require_identifier(channel_id, "channel_id")
    record = _validate_registration(registration)
    entity_id = _entity_id(record["entity"])
    matched_owner_domain = _authenticate_registration(channel_id, record)
    _verify_cited_prefix(
        channel_id, record["evidence_prefix"], "registration.evidence_prefix"
    )
    payload = _strict_gate(record, "EntityRegistration")
    digest = _digest_of(payload)

    with _REGISTRATION_LOCK:
        with _STATE_LOCK:
            existing = _REGISTRATIONS.get(entity_id)
            existing_id = _REGISTRATION_IDS.get(record["registration_id"])
        if existing is not None:
            if existing.digest == digest:
                return existing.reference
            raise RegistrationConflictError(
                f"entity {entity_id!r} already has a different immutable "
                "registration"
            )
        if existing_id is not None and existing_id != entity_id:
            raise RegistrationConflictError(
                "registration_id is already bound to another entity"
            )
        reference = artifact_store.retain_artifact(
            channel_id,
            matched_owner_domain,
            "application/json",
            payload,
            "public",
        )
        if reference.digest != digest:
            raise OwnerRevisionStateError(
                "the registration artifact digest does not match its canonical "
                "record digest"
            )
        entry = _RegistrationEntry(
            record=record,
            digest=digest,
            reference=reference,
        )
        with _STATE_LOCK:
            _REGISTRATIONS[entity_id] = entry
            _REGISTRATION_IDS[record["registration_id"]] = entity_id
    return reference


# ---------------------------------------------------------------------------
# Public: owner-local revision commit
# ---------------------------------------------------------------------------


def _fingerprint(view: _RevisionView, lease: Any) -> str:
    if isinstance(lease, lease_authority.LeaseRecord):
        lease_form: Any = lease.to_dict()
    elif _is_missing(lease):
        lease_form = {"missing": _missing_reason(lease)}
    else:  # pragma: no cover - validated earlier
        lease_form = {"invalid": True}
    return _digest_of(
        _canonical_bytes(
            {"record_digest": view.digest, "lease": lease_form}
        )
    )


def _receipt_lookup(
    owner_domain: str, entity_id: str, command_id: str
) -> _Receipt | None:
    with _STATE_LOCK:
        return _RECEIPTS.get((owner_domain, entity_id, command_id))


def _store_receipt(
    owner_domain: str,
    entity_id: str,
    command_id: str,
    fingerprint: str,
    reference: artifact_store.ArtifactReference,
) -> None:
    with _STATE_LOCK:
        _RECEIPTS[(owner_domain, entity_id, command_id)] = _Receipt(
            fingerprint=fingerprint, reference=reference
        )


def commit_domain(
    channel_id: str,
    registration: EntityRegistration,
    revision: DataDomainRevision | AxisRevision,
    command_id: str,
    lease: lease_authority.LeaseRecord | contract_codec.Missing,
) -> artifact_store.ArtifactReference:
    """Commit one complete owner revision atomically inside its own fence.

    The supplied revision must be a complete publication whose header matches
    the immutable registration.  ``previous_revision`` is the caller's expected
    base: a commit that does not extend the current head is rejected with no
    effect.  Idempotent retries return the already published artifact.
    """
    _require_identifier(channel_id, "channel_id")
    _require_identifier(command_id, "command_id")
    registration_record = _validate_registration(registration)
    registration_payload = _strict_gate(
        registration_record, "EntityRegistration"
    )
    registration_digest = _digest_of(registration_payload)
    (
        revision_record,
        entity,
        domain,
        kind,
        _domains,
    ) = _validate_revision_record(revision)
    entity_id = _entity_id(entity)

    with _STATE_LOCK:
        registered = _REGISTRATIONS.get(entity_id)
    if registered is None:
        raise UnknownEntityError(
            "the entity must be registered before any domain may publish"
        )
    if registered.digest != registration_digest:
        raise RegistrationMismatchError(
            "the supplied registration is not the immutable registered bytes"
        )
    if entity != registered.record["entity"]:
        raise RegistrationMismatchError(
            "the revision entity does not match the registered entity"
        )
    domain_owner = registered.record["owners"].get(domain)
    if domain_owner is None:
        raise RegistrationMismatchError(
            f"domain {domain!r} is not declared by the registration"
        )
    if domain_owner["owner_domain"] != revision_record["owner_domain"]:
        raise WriterAuthorityError(
            "the revision owner_domain does not match the registered binding"
        )
    if domain_owner["writer_id"] != revision_record["writer_id"]:
        raise WriterAuthorityError(
            "the revision writer_id does not match the registered writer"
        )
    if kind == "data" and revision_record["registration_digest"] != registered.digest:
        raise RegistrationMismatchError(
            "revision.registration_digest does not identify the registration"
        )
    if kind == "axis":
        commission_digest = registered.record["identity"]["commission"]["digest"]
        if revision_record["commission_digest"] != commission_digest:
            raise RegistrationMismatchError(
                "revision.commission_digest does not identify the commissioned "
                "subject"
            )
        subject_mode = registered.record["identity"]["execution"]["mode"]
        if domain in ("dispatch", "execution") and subject_mode == "manual":
            raise DomainMismatchError(
                "manual attempts do not publish dispatch or execution axes"
            )

    _authenticate_writer(channel_id, domain_owner)
    payload = _strict_gate(revision_record, "revision")
    view = _RevisionView(
        kind=kind,
        record=revision_record,
        entity=entity,
        domain=domain,
        owner_domain=revision_record["owner_domain"],
        writer_id=revision_record["writer_id"],
        revision=revision_record["revision"],
        previous_revision=revision_record["previous_revision"],
        value=revision_record["value"],
        evidence_prefix=revision_record["evidence_prefix"],
        payload=payload,
        digest=_digest_of(payload),
    )
    owner_lock = _owner_lock(view.owner_domain)
    with owner_lock:
        # An idempotent command replays its durable receipt without revalidating
        # the world.  The fingerprint uses only the submitted content, so a
        # replayed command cannot smuggle in different bytes or a different
        # lease snapshot.
        fingerprint = _fingerprint(view, lease)
        receipt = _receipt_lookup(view.owner_domain, entity_id, command_id)
        if receipt is not None:
            if receipt.fingerprint != fingerprint:
                raise CommandConflictError(
                    f"command id {command_id!r} was already used for different "
                    "content"
                )
            return receipt.reference

        # A new effect validates its lease inside the same owner-local fence
        # that checks revisions and performs the journal commit.
        _validate_lease(channel_id, lease, view)

        with _STATE_LOCK:
            head = _HEADS.get((entity_id, view.domain))
            existing = _REVISIONS.get(
                (entity_id, view.domain, view.revision)
            )
        if existing is not None:
            if existing.digest != view.digest:
                raise RevisionIntegrityError(
                    f"({entity_id}, {view.domain}, {view.revision}) already "
                    "identifies different bytes"
                )
            _store_receipt(
                view.owner_domain,
                entity_id,
                command_id,
                fingerprint,
                existing.reference,
            )
            return existing.reference

        current_revision = head.revision if head is not None else 0
        if view.previous_revision != current_revision:
            raise StaleRevisionError(
                f"stale publication: expected previous_revision "
                f"{current_revision}, got {view.previous_revision}; the entire "
                "write is rejected"
            )
        previous_value = head.value if head is not None else None

        _validate_axis_transition(view.domain, previous_value, view.value)
        _validate_cumulative(view.domain, previous_value, view.value)
        if view.domain == "report" and kind == "axis":
            _validate_report_pins(entity_id, previous_value, view.value)
        _verify_cited_prefix(
            channel_id, view.evidence_prefix, "revision.evidence_prefix"
        )

        journal_revision = _journal_revision_if_present(
            channel_id, view.owner_domain, entity_id
        )
        if journal_revision is not None and journal_revision != current_revision:
            raise OwnerRevisionStateError(
                f"owner domain {view.owner_domain!r} has journal revision "
                f"{journal_revision} but the owner revision store holds "
                f"{current_revision}; refusing a silent reset"
            )

        reference = artifact_store.retain_artifact(
            channel_id,
            view.owner_domain,
            "application/json",
            view.payload,
            "public",
        )
        if reference.digest != view.digest:
            raise OwnerRevisionStateError(
                "the publication artifact digest does not match its canonical "
                "record digest"
            )

        if journal_revision is not None:
            try:
                evidence_journal.commit_effect(
                    channel_id,
                    view.owner_domain,
                    entity_id,
                    command_id,
                    current_revision,
                    reference,
                    (),
                )
            except evidence_journal.RevisionConflictError as exc:
                raise StaleRevisionError(
                    f"the owner journal rejected a stale revision: {exc}"
                ) from exc
            except evidence_journal.CommandConflictError as exc:
                raise CommandConflictError(str(exc)) from exc
            except evidence_journal.IntegrityIncidentError as exc:
                raise RevisionIntegrityError(str(exc)) from exc
            except (evidence_journal.EvidenceJournalError, access_policy.AuthorizationError) as exc:
                raise OwnerCommitError(
                    f"the owner-local journal commit failed: {exc}"
                ) from exc

        entry = _PublishedEntry(
            revision=view.revision,
            previous_revision=view.previous_revision,
            digest=view.digest,
            reference=reference,
            record=view.record,
            value=view.value,
            owner_domain=view.owner_domain,
            writer_id=view.writer_id,
        )
        with _STATE_LOCK:
            _HEADS[(entity_id, view.domain)] = entry
            _REVISIONS[(entity_id, view.domain, view.revision)] = entry
            _RECEIPTS[(view.owner_domain, entity_id, command_id)] = _Receipt(
                fingerprint=fingerprint, reference=reference
            )
        return reference


# ---------------------------------------------------------------------------
# Public: reads
# ---------------------------------------------------------------------------


def _published_result(
    channel_id: str, entity_id: str, entry: _PublishedEntry
) -> PublishedRevision:
    payload = artifact_store.resolve_artifact(channel_id, entry.reference)
    try:
        record = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:  # pragma: no cover - defensive
        raise OwnerRevisionStateError(
            "the retained publication is not decodable JSON"
        ) from exc
    if _digest_of(payload) != entry.digest:  # pragma: no cover - defensive
        raise OwnerRevisionStateError(
            "the retained publication digest does not match the owner store"
        )
    if record.get("value") != entry.value:  # pragma: no cover - defensive
        raise OwnerRevisionStateError(
            "the retained publication value does not match the owner store"
        )
    if "entity" in record:
        entity = record["entity"]
    else:
        attempt = record.get("attempt")
        if not isinstance(attempt, Mapping):  # pragma: no cover - defensive
            raise OwnerRevisionStateError(
                "an axis publication carries no attempt reference"
            )
        entity = {
            "entity_type": "application_attempt",
            "attempt_id": attempt["attempt_id"],
            "kind": attempt["kind"],
        }
    return PublishedRevision(
        entity=entity,
        domain=next(
            (
                record[key]
                for key in ("domain", "axis")
                if isinstance(record.get(key), str)
            ),
            "",
        ),
        owner_domain=entry.owner_domain,
        writer_id=entry.writer_id,
        revision=entry.revision,
        previous_revision=entry.previous_revision,
        content_digest=entry.digest,
        reference=entry.reference,
        record=record,
    )


def read_domain(
    channel_id: str, entity: Mapping[str, Any], domain: str
) -> PublishedRevision | dict[str, Any]:
    """Return the current complete publication for one entity domain."""
    entity_data, _entity_type, domains = _validate_entity(entity)
    if domain not in domains:
        raise DomainMismatchError(f"unknown domain for entity: {domain!r}")
    entity_id = _entity_id(entity_data)
    with _STATE_LOCK:
        entry = _HEADS.get((entity_id, domain))
    if entry is None:
        return contract_codec.make_missing(
            "not_observed", f"no {domain} publication has been committed"
        )
    return _published_result(channel_id, entity_id, entry)


def read_revision(
    channel_id: str,
    entity: Mapping[str, Any],
    domain: str,
    revision: int,
) -> PublishedRevision | dict[str, Any]:
    """Return one exact complete publication, or Missing(not_observed)."""
    entity_data, _entity_type, domains = _validate_entity(entity)
    if domain not in domains:
        raise DomainMismatchError(f"unknown domain for entity: {domain!r}")
    revision_number = _require_int(revision, "revision")
    entity_id = _entity_id(entity_data)
    with _STATE_LOCK:
        entry = _REVISIONS.get((entity_id, domain, revision_number))
    if entry is None:
        return contract_codec.make_missing(
            "not_observed",
            f"no {domain} publication exists at revision {revision_number}",
        )
    return _published_result(channel_id, entity_id, entry)


def domain_head(channel_id: str, entity: Mapping[str, Any], domain: str) -> int:
    """Return the current committed revision number (0 when unpublished)."""
    access_policy.channel_projection(channel_id)
    entity_data, _entity_type, domains = _validate_entity(entity)
    if domain not in domains:
        raise DomainMismatchError(f"unknown domain for entity: {domain!r}")
    entity_id = _entity_id(entity_data)
    with _STATE_LOCK:
        entry = _HEADS.get((entity_id, domain))
    return entry.revision if entry is not None else 0


# ---------------------------------------------------------------------------
# Test isolation
# ---------------------------------------------------------------------------


def reset_for_tests() -> None:
    """Clear this module's owner-local store (test harness only)."""
    with _STATE_LOCK:
        _REGISTRATIONS.clear()
        _REGISTRATION_IDS.clear()
        _HEADS.clear()
        _REVISIONS.clear()
        _RECEIPTS.clear()
        _OWNER_LOCKS.clear()

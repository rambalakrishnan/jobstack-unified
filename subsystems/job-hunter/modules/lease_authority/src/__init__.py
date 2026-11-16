"""lease_authority: owner-fenced product leases over the evidence journal (tier 3).

Product work uses kernel leases independently of crawler leases
(``job-hunter-seam-mapping.md#15.5``).  A lease record is a journal-derived
snapshot: it retains the resource, the pinned owner policy, issuer, authority
epoch, entity/input revisions, generation, resource/eligible state, lease
state, fencing token, owner and owner/session epochs, issue/expiry points,
retry count, failure reason, journal prefix, and evidence references.

Rules implemented here (``EK-LEASE``, ``EK-LEASE-RESTART``, ``EK-TIME``):

* Claiming atomically checks the eligible resource state and the absence of an
  unexpired lease, assigns a fresh fencing token and owner epoch, advances the
  entity revision, clears ``last_failure_reason``, and appends evidence.  It
  never changes ``resource_state``.
* Completion checks the current token, the unexpired authority-clock deadline,
  the entity/input revisions, and the applicable owner/session epochs.  A
  stale completion has no effect.  A failed generation increments the retry
  count at most once.
* ``leased_at`` and ``lease_expires_at`` use one registered lease-authority
  clock and boot; expiry is always later than issue.  Renewal requires a
  still-current token and epoch.
* An authority restart durably fences the old authority epoch *before*
  reclaiming its leases.  Monotonic offsets are never compared across clock
  IDs or boots; elapsed downtime and native/employer outcomes are never
  inferred from UTC.
* Expiry revokes local commit authority only.  It is evidence that this
  authority may no longer commit, never evidence that native work or employer
  transactions stopped; the outcome is retained as ``Missing(not_observed)``.

All authoritative mutations commit through :func:`evidence_journal.commit_effect`:
the lease snapshot artifact, revision advance, journal event, and replayable
response become durable together before acknowledgement.  Workers never
supply the authority clock, a fencing token, or an owner epoch.

The composition root registers each owner's pinned lease policy with
:func:`register_policy` at boot: a ``K.VersionPin`` names only a content
digest, so the retained reference and parsed duration/retry/eligibility policy
are bound to that digest before the first transition.  Every transition
re-resolves the pinned bytes, so policy configuration is never a module
default and never silently replaced.

A snapshot can cite only evidence acknowledged *before* its own commit (the
event hash of its own commit is not knowable in advance).  Its
``journal_prefix`` is therefore the head it was derived from, and its own
committed event becomes the head that the next snapshot cites.
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
import math
import re
import secrets
import sys
import threading
import time
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
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

__all__ = [
    "SCHEMA_VERSION",
    "LEASE_RECORD_TYPE",
    "LEASE_EVENT_SCHEMA_VERSION",
    "AUTHORITY_CLOCK_ID",
    "AUTHORITY_SOURCE_ID",
    "AUTHORITY_ISSUER_ID",
    "EVENT_KINDS",
    "LEASE_OPERATIONS",
    "Missing",
    "TimePoint",
    "ResourceReference",
    "VersionPin",
    "LeaseRecord",
    "LeaseAuthorityError",
    "LeasePolicyError",
    "LeaseOperationError",
    "LeaseStaleError",
    "LeaseBusyError",
    "LeaseIneligibleError",
    "LeaseExpiredError",
    "LeaseNotExpiredError",
    "LeaseFencedError",
    "LeaseClockMismatchError",
    "LeaseRevisionConflictError",
    "LeaseFailureAlreadyCountedError",
    "LeaseRetriesExhaustedError",
    "LeaseIntegrityError",
    "make_missing",
    "event_kind_declarations",
    "register_policy",
    "transition_lease",
    "validate_completion",
    "load_lease",
    "restart_authority",
    "authority_now",
    "authority_epoch",
    "authority_clock",
    "advance_authority_clock_for_tests",
    "reset_for_tests",
]

SCHEMA_VERSION = "evidence-kernel/0.1.0"
LEASE_RECORD_TYPE = "lease_record"
LEASE_EVENT_SCHEMA_VERSION = "1"

AUTHORITY_CLOCK_ID = "clock_lease_authority"
AUTHORITY_SOURCE_ID = "src_lease_authority"
AUTHORITY_ISSUER_ID = "issuer_lease_authority"

#: Every event this module writes, with its pinned schema version.  The
#: composition root registers each kind in the manifest event registry and in
#: the ingress authority before the first lease transition.
EVENT_KINDS: Mapping[str, str] = {
    "clock_registered": LEASE_EVENT_SCHEMA_VERSION,
    "lease_claimed": LEASE_EVENT_SCHEMA_VERSION,
    "lease_renewed": LEASE_EVENT_SCHEMA_VERSION,
    "lease_completed": LEASE_EVENT_SCHEMA_VERSION,
    "lease_released": LEASE_EVENT_SCHEMA_VERSION,
    "lease_expired": LEASE_EVENT_SCHEMA_VERSION,
    "lease_generation_failed": LEASE_EVENT_SCHEMA_VERSION,
    "authority_epoch_fenced": LEASE_EVENT_SCHEMA_VERSION,
}

LEASE_OPERATIONS = frozenset(
    {"claim", "renew", "complete", "release", "expire", "fail_generation"}
)

#: ``K.Missing`` is a typed envelope mapping (never an in-band null).
Missing = contract_codec.Missing
#: ``K.TimePoint`` is the kernel coordinate shape with ``monotonic_offset_ms``.
TimePoint = evidence_journal.TimePoint

_EPOCH_EVENT_ROLE = "lifecycle_observation"
_EPOCH_EVENT_ASSERTION = "authoritative_effect"

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_LEASE_STATES = frozenset({"unleased", "held"})
_INAPPLICABLE_LEASE_FIELDS = (
    "lease_id",
    "lease_owner",
    "owner_epoch",
    "session_epoch",
    "leased_at",
    "lease_expires_at",
)
_FENCED_DISPOSITIONS = frozenset({"epoch_fenced"})
_POLICY_FIELDS = frozenset(
    {
        "lease_duration_ms",
        "max_retries",
        "failure_code",
        "eligible_state",
        "renewal_allowed",
    }
)
_POLICY_OPTIONAL_FIELDS = frozenset({"initial_resource_state"})


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class LeaseAuthorityError(Exception):
    """Base class for lease-authority rejections and integrity failures."""


class LeasePolicyError(LeaseAuthorityError, ValueError):
    """The pinned owner policy, token, or epoch is not usable for the request."""


class LeaseOperationError(LeaseAuthorityError, ValueError):
    """The requested operation or its inputs are not a supported lease request."""


class LeaseStaleError(LeaseAuthorityError):
    """The caller's expected lease snapshot is not the fenced current snapshot."""


class LeaseBusyError(LeaseAuthorityError):
    """The resource already holds an unexpired lease under this authority."""


class LeaseIneligibleError(LeaseAuthorityError):
    """The resource is not in its claimable eligible state."""


class LeaseExpiredError(LeaseAuthorityError):
    """The authority-clock deadline has been reached; local commit is revoked."""


class LeaseNotExpiredError(LeaseAuthorityError):
    """Expiry was requested before the authority-clock deadline."""


class LeaseFencedError(LeaseAuthorityError):
    """The lease belongs to a fenced authority or owner epoch."""


class LeaseClockMismatchError(LeaseAuthorityError):
    """A cross-clock or cross-boot comparison was attempted and refused."""


class LeaseRevisionConflictError(LeaseAuthorityError):
    """The completed entity/input revision is not the lease's admitted revision."""


class LeaseFailureAlreadyCountedError(LeaseAuthorityError):
    """The current generation already recorded one failure."""


class LeaseRetriesExhaustedError(LeaseAuthorityError):
    """The pinned policy's retry ceiling is already reached."""


class LeaseIntegrityError(LeaseAuthorityError):
    """A durable lease record or its evidence prefix is inconsistent."""


# ---------------------------------------------------------------------------
# Small validators / Missing helpers
# ---------------------------------------------------------------------------


def _require_identifier(value: Any, field_name: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a str, not {type(value).__name__}")
    if not value or value != value.strip():
        raise ValueError(f"{field_name} must be a nonempty identifier")
    if len(value) > 256:
        raise ValueError(f"{field_name} must be at most 256 characters")
    if any(ord(ch) < 0x20 for ch in value):
        raise ValueError(f"{field_name} must not contain control characters")
    return value


def _require_revision(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{field_name} must be an int revision")
    if value < 0 or value > 9007199254740991:
        raise ValueError(f"{field_name} is outside the kernel Revision range")
    return value


def make_missing(reason: str, detail: str | None = None) -> Missing:
    """Create a typed ``K.Missing`` envelope (a fresh mapping each call)."""
    return contract_codec.make_missing(reason, detail)


def _missing(reason: str) -> dict[str, Any]:
    return contract_codec.make_missing(reason)


def _is_missing(value: Any) -> bool:
    if isinstance(value, evidence_journal.Missing):
        return True
    return contract_codec.is_missing_envelope(value)


def _as_missing(value: Any) -> dict[str, Any] | None:
    """Return a validated Missing envelope mapping, or ``None``."""
    if isinstance(value, evidence_journal.Missing):
        return value.to_dict()
    if value is None or not isinstance(value, Mapping):
        return None
    if not contract_codec.is_missing_envelope(dict(value)):
        return None
    return _require_missing(value, "$")


def _require_missing(value: Any, field_name: str) -> dict[str, Any]:
    if isinstance(value, evidence_journal.Missing):
        return value.to_dict()
    if not isinstance(value, Mapping):
        raise TypeError(f"{field_name} must be a typed Missing envelope")
    data = dict(value)
    extra = set(data) - {"value", "reason", "detail"}
    if extra:
        raise ValueError(f"{field_name}: undeclared Missing properties {sorted(extra)}")
    if data.get("value") is not None or "value" not in data:
        raise ValueError(f"{field_name}: Missing.value must be null")
    reason = data.get("reason")
    if reason not in contract_codec.VALID_MISSING_REASONS:
        raise ValueError(f"{field_name}: unknown Missing reason {reason!r}")
    if "detail" in data and (
        not isinstance(data["detail"], str) or not data["detail"]
    ):
        raise ValueError(f"{field_name}: Missing.detail must be a nonempty string")
    return {"value": None, "reason": reason, **({"detail": data["detail"]} if "detail" in data else {})}


def _require_timepoint(value: Any, field_name: str) -> TimePoint:
    if isinstance(value, TimePoint):
        return value
    if not isinstance(value, Mapping):
        raise TypeError(f"{field_name} must be a TimePoint")
    expected = {
        "clock_id",
        "boot_id",
        "origin",
        "monotonic_offset_ms",
        "utc_annotation",
    }
    if set(value.keys()) != expected:
        raise ValueError(f"{field_name} must contain exactly {sorted(expected)}")
    return TimePoint(
        clock_id=value["clock_id"],
        boot_id=value["boot_id"],
        origin=value["origin"],
        monotonic_offset_ms=value["monotonic_offset_ms"],
        utc_annotation=value["utc_annotation"],
    )


def _field_to_json(value: Any) -> Any:
    if isinstance(value, TimePoint):
        return value.to_dict()
    if isinstance(value, evidence_journal.Missing):
        return value.to_dict()
    return value


def _canonical_json(obj: Any) -> bytes:
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _codec_gate(payload: Mapping[str, Any], field_name: str) -> None:
    """Reject bare nulls, duplicate keys, and nonfinite numbers (strict JSON)."""
    try:
        contract_codec.validate_record(
            _canonical_json({"timing": dict(payload)}), "record/v1"
        )
    except (TypeError, ValueError) as exc:
        raise LeaseIntegrityError(f"{field_name} is not strict JSON evidence: {exc}") from exc


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate mapping key: {key!r}")
        out[key] = value
    return out


def _reject_constant(token: str) -> Any:
    raise ValueError(f"nonfinite number literal rejected: {token!r}")


def _parse_strict_object(raw: bytes, field_name: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise LeaseIntegrityError(f"{field_name} is not strict JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise LeaseIntegrityError(f"{field_name} must be a JSON object")
    return value


# ---------------------------------------------------------------------------
# Kernel record shapes
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ResourceReference:
    """``K.ResourceReference``: the owner-local resource a lease fences."""

    owner_domain: str
    entity_type: str
    entity_id: str

    def __post_init__(self) -> None:
        _require_identifier(self.owner_domain, "resource.owner_domain")
        _require_identifier(self.entity_type, "resource.entity_type")
        _require_identifier(self.entity_id, "resource.entity_id")

    def to_dict(self) -> dict[str, str]:
        return {
            "owner_domain": self.owner_domain,
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
        }


@dataclass(frozen=True, slots=True)
class VersionPin:
    """``K.VersionPin``: an immutable pinned policy artifact."""

    id: str
    version: str
    artifact_digest: str

    def __post_init__(self) -> None:
        _require_identifier(self.id, "policy.id")
        _require_identifier(self.version, "policy.version")
        if not isinstance(self.artifact_digest, str) or not _DIGEST_RE.match(
            self.artifact_digest
        ):
            raise ValueError(
                "policy.artifact_digest must be sha256:<64 lowercase hex>"
            )

    def to_dict(self) -> dict[str, str]:
        return {
            "id": self.id,
            "version": self.version,
            "artifact_digest": self.artifact_digest,
        }


@dataclass(frozen=True, slots=True)
class LeaseRecord:
    """A journal-derived lease snapshot (``K.LeaseRecord``).

    A ``held`` record carries a live fencing token, owner/session epochs, and
    same-clock issue/expiry points.  An ``unleased`` record carries
    ``Missing(not_applicable)`` in every lease-identity field.  Claiming does
    not change ``resource_state``; a held record always has
    ``resource_state == eligible_state``.
    """

    record_type: str
    schema_version: str
    resource: ResourceReference
    policy: VersionPin
    issuer_id: str
    authority_epoch: str
    entity_revision: int
    input_revision: int
    generation_id: str
    resource_state: str
    eligible_state: str
    lease_state: str
    lease_id: Any
    lease_owner: Any
    owner_epoch: Any
    session_epoch: Any
    leased_at: Any
    lease_expires_at: Any
    retry_count: int
    max_retries_effective: int
    last_failure_reason: Any
    journal_prefix: evidence_journal.JournalPrefix
    evidence_refs: tuple[evidence_journal.EvidenceRef, ...]

    def __post_init__(self) -> None:
        if self.record_type != LEASE_RECORD_TYPE:
            raise ValueError(f"record_type must be {LEASE_RECORD_TYPE!r}")
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"schema_version must be {SCHEMA_VERSION!r}")
        if not isinstance(self.resource, ResourceReference):
            raise TypeError("resource must be a ResourceReference")
        if not isinstance(self.policy, VersionPin):
            raise TypeError("policy must be a VersionPin")
        for field_name in (
            "issuer_id",
            "authority_epoch",
            "generation_id",
            "resource_state",
            "eligible_state",
        ):
            _require_identifier(getattr(self, field_name), field_name)
        _require_revision(self.entity_revision, "entity_revision")
        _require_revision(self.input_revision, "input_revision")
        if self.lease_state not in _LEASE_STATES:
            raise ValueError(f"unknown lease_state: {self.lease_state!r}")
        if isinstance(self.retry_count, bool) or not isinstance(self.retry_count, int):
            raise TypeError("retry_count must be an int")
        if self.retry_count < 0:
            raise ValueError("retry_count must be nonnegative")
        if (
            isinstance(self.max_retries_effective, bool)
            or not isinstance(self.max_retries_effective, int)
            or self.max_retries_effective < 1
        ):
            raise ValueError("max_retries_effective must be a positive integer")
        if self.retry_count > self.max_retries_effective:
            raise ValueError("retry_count cannot exceed max_retries_effective")
        if not isinstance(self.journal_prefix, evidence_journal.JournalPrefix):
            raise TypeError("journal_prefix must be a JournalPrefix")
        refs = tuple(self.evidence_refs)
        if not refs:
            raise ValueError("evidence_refs requires at least one EvidenceRef")
        for ref in refs:
            if not isinstance(ref, evidence_journal.EvidenceRef):
                raise TypeError("evidence_refs entries must be EvidenceRef records")
        object.__setattr__(self, "evidence_refs", refs)
        if not (
            isinstance(self.last_failure_reason, str)
            or _is_missing(self.last_failure_reason)
        ):
            raise TypeError(
                "last_failure_reason must be a policy code or a Missing envelope"
            )
        if _is_missing(self.last_failure_reason):
            object.__setattr__(
                self,
                "last_failure_reason",
                _require_missing(self.last_failure_reason, "last_failure_reason"),
            )
        if self.lease_state == "unleased":
            for field_name in _INAPPLICABLE_LEASE_FIELDS:
                envelope = _as_missing(getattr(self, field_name))
                if envelope is None or envelope["reason"] != "not_applicable":
                    raise ValueError(
                        f"{field_name} must be Missing(not_applicable) when unleased"
                    )
                object.__setattr__(self, field_name, envelope)
        else:
            for field_name in ("lease_id", "lease_owner", "owner_epoch"):
                _require_identifier(getattr(self, field_name), field_name)
            session_epoch = self.session_epoch
            if isinstance(session_epoch, str):
                _require_identifier(session_epoch, "session_epoch")
            else:
                envelope = _as_missing(session_epoch)
                if envelope is None or envelope["reason"] != "not_applicable":
                    raise ValueError(
                        "session_epoch must be an identifier or "
                        "Missing(not_applicable)"
                    )
                object.__setattr__(self, "session_epoch", envelope)
            issued = _require_timepoint(self.leased_at, "leased_at")
            expires = _require_timepoint(self.lease_expires_at, "lease_expires_at")
            if (issued.clock_id, issued.boot_id) != (expires.clock_id, expires.boot_id):
                raise ValueError(
                    "leased_at and lease_expires_at must use one clock and boot"
                )
            if issued.origin != expires.origin:
                raise ValueError(
                    "leased_at and lease_expires_at must share one clock origin"
                )
            if not (
                float(expires.monotonic_offset_ms)
                > float(issued.monotonic_offset_ms)
            ):
                raise ValueError("lease_expires_at must be later than leased_at")
            if self.resource_state != self.eligible_state:
                raise ValueError(
                    "a held lease requires resource_state == eligible_state"
                )
            object.__setattr__(self, "leased_at", issued)
            object.__setattr__(self, "lease_expires_at", expires)

    # -- serialization -----------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": self.record_type,
            "schema_version": self.schema_version,
            "resource": self.resource.to_dict(),
            "policy": self.policy.to_dict(),
            "issuer_id": self.issuer_id,
            "authority_epoch": self.authority_epoch,
            "entity_revision": self.entity_revision,
            "input_revision": self.input_revision,
            "generation_id": self.generation_id,
            "resource_state": self.resource_state,
            "eligible_state": self.eligible_state,
            "lease_state": self.lease_state,
            "lease_id": _field_to_json(self.lease_id),
            "lease_owner": _field_to_json(self.lease_owner),
            "owner_epoch": _field_to_json(self.owner_epoch),
            "session_epoch": _field_to_json(self.session_epoch),
            "leased_at": _field_to_json(self.leased_at),
            "lease_expires_at": _field_to_json(self.lease_expires_at),
            "retry_count": self.retry_count,
            "max_retries_effective": self.max_retries_effective,
            "last_failure_reason": _field_to_json(self.last_failure_reason),
            "journal_prefix": {
                "journal_id": self.journal_prefix.journal_id,
                "last_sequence": self.journal_prefix.last_sequence,
                "head_hash": self.journal_prefix.head_hash,
            },
            "evidence_refs": [ref.to_dict() for ref in self.evidence_refs],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "LeaseRecord":
        if not isinstance(data, Mapping):
            raise TypeError("lease record must be decoded from a mapping")
        expected = {
            "record_type",
            "schema_version",
            "resource",
            "policy",
            "issuer_id",
            "authority_epoch",
            "entity_revision",
            "input_revision",
            "generation_id",
            "resource_state",
            "eligible_state",
            "lease_state",
            "lease_id",
            "lease_owner",
            "owner_epoch",
            "session_epoch",
            "leased_at",
            "lease_expires_at",
            "retry_count",
            "max_retries_effective",
            "last_failure_reason",
            "journal_prefix",
            "evidence_refs",
        }
        if set(data.keys()) != expected:
            raise ValueError(
                "lease record must contain exactly the kernel LeaseRecord fields"
            )
        raw_resource = data["resource"]
        if not isinstance(raw_resource, Mapping) or set(raw_resource.keys()) != {
            "owner_domain",
            "entity_type",
            "entity_id",
        }:
            raise ValueError("resource must be a ResourceReference mapping")
        raw_policy = data["policy"]
        if not isinstance(raw_policy, Mapping) or set(raw_policy.keys()) != {
            "id",
            "version",
            "artifact_digest",
        }:
            raise ValueError("policy must be a VersionPin mapping")
        raw_prefix = data["journal_prefix"]
        if not isinstance(raw_prefix, Mapping) or set(raw_prefix.keys()) != {
            "journal_id",
            "last_sequence",
            "head_hash",
        }:
            raise ValueError("journal_prefix must be a JournalPrefix mapping")
        raw_refs = data["evidence_refs"]
        if isinstance(raw_refs, (str, bytes)) or not isinstance(
            raw_refs, Sequence
        ):
            raise TypeError("evidence_refs must be a sequence of EvidenceRefs")

        def _maybe_tp(value: Any, field_name: str) -> Any:
            if _is_missing(value):
                return _require_missing(value, field_name)
            return _require_timepoint(value, field_name)

        def _maybe_id(value: Any, field_name: str) -> Any:
            if isinstance(value, str):
                return _require_identifier(value, field_name)
            return _require_missing(value, field_name)

        return cls(
            record_type=data["record_type"],
            schema_version=data["schema_version"],
            resource=ResourceReference(
                owner_domain=raw_resource["owner_domain"],
                entity_type=raw_resource["entity_type"],
                entity_id=raw_resource["entity_id"],
            ),
            policy=VersionPin(
                id=raw_policy["id"],
                version=raw_policy["version"],
                artifact_digest=raw_policy["artifact_digest"],
            ),
            issuer_id=data["issuer_id"],
            authority_epoch=data["authority_epoch"],
            entity_revision=data["entity_revision"],
            input_revision=data["input_revision"],
            generation_id=data["generation_id"],
            resource_state=data["resource_state"],
            eligible_state=data["eligible_state"],
            lease_state=data["lease_state"],
            lease_id=_maybe_id(data["lease_id"], "lease_id"),
            lease_owner=_maybe_id(data["lease_owner"], "lease_owner"),
            owner_epoch=_maybe_id(data["owner_epoch"], "owner_epoch"),
            session_epoch=(
                data["session_epoch"]
                if isinstance(data["session_epoch"], str)
                else _require_missing(data["session_epoch"], "session_epoch")
            ),
            leased_at=_maybe_tp(data["leased_at"], "leased_at"),
            lease_expires_at=_maybe_tp(data["lease_expires_at"], "lease_expires_at"),
            retry_count=data["retry_count"],
            max_retries_effective=data["max_retries_effective"],
            last_failure_reason=(
                data["last_failure_reason"]
                if isinstance(data["last_failure_reason"], str)
                else _require_missing(
                    data["last_failure_reason"], "last_failure_reason"
                )
            ),
            journal_prefix=evidence_journal.JournalPrefix(
                journal_id=raw_prefix["journal_id"],
                last_sequence=raw_prefix["last_sequence"],
                head_hash=raw_prefix["head_hash"],
            ),
            evidence_refs=tuple(
                evidence_journal.EvidenceRef.from_dict(ref) for ref in raw_refs
            ),
        )


def _record_bytes(record: LeaseRecord) -> bytes:
    payload = record.to_dict()
    _codec_gate(payload, "lease record")
    return _canonical_json(payload)


def _record_digest(record: LeaseRecord) -> str:
    return str(contract_codec.canonical_digest(_canonical_json({"timing": record.to_dict()})))


# ---------------------------------------------------------------------------
# Authority clock, boot, and epoch state
# ---------------------------------------------------------------------------


@dataclass
class _AuthorityState:
    epoch: str
    boot_id: str
    boot_ns: int
    test_offset_ms: float = 0.0
    journals: dict[str, str] = field(default_factory=dict)
    registered: set[str] = field(default_factory=set)
    fenced: set[tuple[str, str]] = field(default_factory=set)


_AUTH_LOCK = threading.RLock()


def _new_epoch_id() -> str:
    return "authority_epoch_" + secrets.token_hex(12)


def _new_owner_epoch_id() -> str:
    return "lease_owner_epoch_" + secrets.token_hex(12)


def _new_lease_id() -> str:
    return "lease_" + secrets.token_hex(16)


def _new_generation_id() -> str:
    return "generation_" + secrets.token_hex(12)


def _new_boot_state() -> _AuthorityState:
    return _AuthorityState(
        epoch=_new_epoch_id(),
        boot_id="boot_lease_authority_" + secrets.token_hex(8),
        boot_ns=time.monotonic_ns(),
    )


_AUTH = _new_boot_state()


def _offset_ms() -> float:
    elapsed = (time.monotonic_ns() - _AUTH.boot_ns) / 1_000_000
    return round(elapsed + _AUTH.test_offset_ms, 3)


def _now() -> TimePoint:
    return TimePoint(
        clock_id=AUTHORITY_CLOCK_ID,
        boot_id=_AUTH.boot_id,
        origin="engine_measured",
        monotonic_offset_ms=_offset_ms(),
        utc_annotation=datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        ),
    )


def _deadline(start: TimePoint, duration_ms: float) -> TimePoint:
    return TimePoint(
        clock_id=start.clock_id,
        boot_id=start.boot_id,
        origin=start.origin,
        monotonic_offset_ms=round(
            float(start.monotonic_offset_ms) + float(duration_ms), 3
        ),
        utc_annotation=_missing("not_observed"),
    )


def authority_now() -> TimePoint:
    """Return the fenced authority's current time (never worker-supplied)."""
    with _AUTH_LOCK:
        return _now()


def authority_epoch() -> str:
    """Return the current durable authority epoch identifier."""
    with _AUTH_LOCK:
        return _AUTH.epoch


def authority_clock() -> tuple[str, str]:
    """Return the current authority ``(clock_id, boot_id)`` pair."""
    with _AUTH_LOCK:
        return (AUTHORITY_CLOCK_ID, _AUTH.boot_id)


def advance_authority_clock_for_tests(milliseconds: float) -> None:
    """Advance the authority's own clock (test harness only, never ingress)."""
    if isinstance(milliseconds, bool) or not isinstance(milliseconds, (int, float)):
        raise TypeError("milliseconds must be a number")
    if not math.isfinite(float(milliseconds)) or milliseconds < 0:
        raise ValueError("milliseconds must be a finite nonnegative offset")
    with _AUTH_LOCK:
        _AUTH.test_offset_ms += float(milliseconds)


def reset_for_tests() -> None:
    """Reset the authority to a fresh boot/epoch and clear in-process caches."""
    global _AUTH
    with _AUTH_LOCK:
        _AUTH = _new_boot_state()
        _POLICIES.clear()


# ---------------------------------------------------------------------------
# Pinned owner policy
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _LeasePolicy:
    pin: VersionPin
    owner_domain: str
    reference: Any
    lease_duration_ms: int | float
    max_retries: int
    failure_code: str
    eligible_state: str
    initial_resource_state: str
    renewal_allowed: bool


#: Pins registered by the composition root at boot, keyed by content digest.
#: A ``K.VersionPin`` names only a digest; the retained reference (which the
#: artifact store needs for resolution) is bound here together with the
#: parsed owner policy.  Every transition re-resolves the registered reference
#: so the pinned bytes remain durable and unchanged.
_POLICIES: dict[str, _LeasePolicy] = {}


def _parse_policy_document(
    pin: VersionPin, owner_domain: str, reference: Any, data: Mapping[str, Any]
) -> _LeasePolicy:
    _codec_gate(data, "lease policy")
    keys = set(data.keys())
    if not _POLICY_FIELDS <= keys or keys - (_POLICY_FIELDS | _POLICY_OPTIONAL_FIELDS):
        raise LeasePolicyError(
            "pinned lease policy must declare exactly "
            f"{sorted(_POLICY_FIELDS)} (initial_resource_state optional)"
        )
    duration = data["lease_duration_ms"]
    if isinstance(duration, bool) or not isinstance(duration, (int, float)):
        raise LeasePolicyError("lease_duration_ms must be a number")
    if not math.isfinite(float(duration)) or float(duration) <= 0:
        raise LeasePolicyError("lease_duration_ms must be finite and positive")
    max_retries = data["max_retries"]
    if isinstance(max_retries, bool) or not isinstance(max_retries, int):
        raise LeasePolicyError("max_retries must be an integer")
    if max_retries < 0 or max_retries > 9007199254740991:
        raise LeasePolicyError("max_retries must be a nonnegative integer")
    eligible_state = _require_identifier(data["eligible_state"], "eligible_state")
    initial_state = data.get("initial_resource_state", eligible_state)
    initial_state = _require_identifier(initial_state, "initial_resource_state")
    if not isinstance(data["renewal_allowed"], bool):
        raise LeasePolicyError("renewal_allowed must be a boolean")
    failure_code = data["failure_code"]
    if not isinstance(failure_code, str):
        raise LeasePolicyError("failure_code must be a string")
    if failure_code == "" or failure_code != failure_code.strip():
        raise LeasePolicyError("failure_code must be a nonempty identifier")
    return _LeasePolicy(
        pin=pin,
        owner_domain=owner_domain,
        reference=reference,
        lease_duration_ms=duration,
        max_retries=max_retries,
        failure_code=failure_code,
        eligible_state=eligible_state,
        initial_resource_state=initial_state,
        renewal_allowed=data["renewal_allowed"],
    )


def register_policy(
    channel_id: str,
    owner_domain: str,
    policy_id: str,
    policy_version: str,
    document: Mapping[str, Any],
) -> VersionPin:
    """Retain and pin one owner policy document; return its content pin.

    The composition root loads configuration at boot and registers each owner
    policy before the first lease transition.  The document is retained as
    owner-restricted bytes; the returned :class:`VersionPin` names exactly
    those bytes, so every later transition can re-verify the pin.
    """
    _require_identifier(owner_domain, "owner_domain")
    _require_identifier(policy_id, "policy_id")
    _require_identifier(policy_version, "policy_version")
    if not isinstance(document, Mapping):
        raise LeasePolicyError("policy document must be a mapping")
    data = dict(document)
    raw = _canonical_json(data)
    try:
        reference = artifact_store.retain_artifact(
            channel_id, owner_domain, "application/json", raw, "restricted"
        )
    except artifact_store.ArtifactError as exc:
        raise LeasePolicyError(f"cannot retain the lease policy: {exc}") from exc
    pin = VersionPin(
        id=policy_id, version=policy_version, artifact_digest=reference.digest
    )
    parsed = _parse_policy_document(pin, owner_domain, reference, data)
    with _AUTH_LOCK:
        existing = _POLICIES.get(reference.digest)
        if existing is not None and existing.pin.to_dict() != pin.to_dict():
            raise LeasePolicyError(
                "policy bytes are already registered under a different "
                "id/version; one content digest carries one pin identity"
            )
        _POLICIES[reference.digest] = parsed
    return pin


def _resolve_policy(
    channel_id: str, resource: ResourceReference, pin: VersionPin
) -> _LeasePolicy:
    """Re-verify a registered pin and return its parsed owner policy."""
    if not isinstance(pin, VersionPin):
        raise LeasePolicyError("policy must be a VersionPin")
    with _AUTH_LOCK:
        parsed = _POLICIES.get(pin.artifact_digest)
    if parsed is None:
        raise LeasePolicyError(
            f"pinned lease policy {pin.id!r} version {pin.version!r} is not "
            "registered with this lease authority boot"
        )
    if parsed.owner_domain != resource.owner_domain:
        raise LeasePolicyError(
            f"pinned lease policy belongs to owner domain "
            f"{parsed.owner_domain!r}, not {resource.owner_domain!r}"
        )
    if parsed.pin.to_dict() != pin.to_dict():
        raise LeasePolicyError(
            "the policy pin's id, version, or digest does not match the "
            "registered policy provenance"
        )
    # The pinned bytes must still be durably available and unchanged.
    try:
        artifact_store.resolve_artifact(channel_id, parsed.reference)
    except artifact_store.ArtifactError as exc:
        raise LeasePolicyError(
            f"pinned lease policy bytes are not resolvable: {exc}"
        ) from exc
    return parsed


def event_kind_declarations() -> tuple[dict[str, Any], ...]:
    """Manifest event-registry entries for every kind this module writes."""
    return tuple(
        {
            "event_kind": kind,
            "event_schema_version": version,
            "role": _EPOCH_EVENT_ROLE,
            "assertion_kind": _EPOCH_EVENT_ASSERTION,
            "writer_roles": ["kernel"],
        }
        for kind, version in EVENT_KINDS.items()
    )


# ---------------------------------------------------------------------------
# Journal integration
# ---------------------------------------------------------------------------


def _lease_entity_id(resource: ResourceReference) -> str:
    return f"lease.{resource.entity_type}.{resource.entity_id}"


def _grant_for(resource: ResourceReference) -> str:
    # Every access_policy axis grants exactly ``<axis>.write`` for its writers.
    return f"{resource.owner_domain}.write"


def _authorize(channel_id: str, resource: ResourceReference) -> Any:
    return access_policy.authorize(
        channel_id, _grant_for(resource), resource.entity_id
    )


def _ensure_clock_registered(channel_id: str, owner_domain: str) -> str:
    """Register this boot's lease-authority clock once per owner journal.

    Returns the active journal id.  A ``clock_registered`` event may introduce
    the clock used by its own and later receipts; the registration event's own
    ``occurred_at`` is ``Missing(not_observed)`` because no lease clock was yet
    registered in that journal.
    """
    if owner_domain in _AUTH.registered:
        journal_id = _AUTH.journals.get(owner_domain)
        if journal_id is None:  # pragma: no cover - defensive
            raise LeaseIntegrityError("lease-authority clock cache is inconsistent")
        return journal_id
    submission = evidence_journal.EventSubmission(
        producer_sequence=_missing("not_applicable"),
        event_kind="clock_registered",
        event_schema_version=LEASE_EVENT_SCHEMA_VERSION,
        occurred_at=_missing("not_observed"),
        payload=evidence_journal.EvidencePayload(
            data={
                "clock_id": AUTHORITY_CLOCK_ID,
                "boot_id": _AUTH.boot_id,
                "origin": "engine_measured",
                "source_id": AUTHORITY_SOURCE_ID,
                "basis": "monotonic_offset",
                "unit": "ms",
            },
            measurements=[],
            evidence_refs=[],
            artifact_refs=[],
        ),
    )
    try:
        envelope = evidence_journal.append_event(
            channel_id, owner_domain, submission
        )
    except (evidence_journal.EvidenceJournalError, access_policy.AuthorizationError) as exc:
        raise LeaseIntegrityError(
            f"cannot register the lease-authority clock in {owner_domain!r}: {exc}"
        ) from exc
    _AUTH.journals[owner_domain] = envelope.journal_id
    _AUTH.registered.add(owner_domain)
    return envelope.journal_id


def _append_fence(
    channel_id: str,
    owner_domain: str,
    *,
    fenced_epoch: str,
    fenced_clock: TimePoint | None,
    fenced_boot_id: str | None,
    reason: str,
) -> evidence_journal.JournalEnvelope:
    """Durably fence an authority epoch before any of its leases are reclaimed."""
    key = (owner_domain, fenced_epoch)
    if key in _AUTH.fenced:
        # The epoch was already fenced in this journal during this boot.
        head = evidence_journal.journal_head(
            channel_id, _ensure_clock_registered(channel_id, owner_domain)
        )
        events = evidence_journal.read_prefix(channel_id, head)
        for envelope in reversed(events):
            if envelope.event_kind != "authority_epoch_fenced":
                continue
            if envelope.payload["data"].get("fenced_authority_epoch") == fenced_epoch:
                return envelope
        raise LeaseIntegrityError("fence cache disagrees with the journal")
    _ensure_clock_registered(channel_id, owner_domain)
    now = _now()
    data: dict[str, Any] = {
        "fenced_authority_epoch": fenced_epoch,
        "new_authority_epoch": _AUTH.epoch,
        "fenced_clock_id": (
            fenced_clock.clock_id if fenced_clock is not None else _missing("not_observed")
        ),
        "fenced_boot_id": (
            fenced_boot_id
            if fenced_boot_id is not None
            else _missing("not_observed")
        ),
        "new_clock_id": AUTHORITY_CLOCK_ID,
        "new_boot_id": _AUTH.boot_id,
        "reason": reason,
        "commit_authority": "revoked",
        "native_outcome": _missing("not_observed"),
        "downtime": _missing("not_observed"),
    }
    submission = evidence_journal.EventSubmission(
        producer_sequence=_missing("not_applicable"),
        event_kind="authority_epoch_fenced",
        event_schema_version=LEASE_EVENT_SCHEMA_VERSION,
        occurred_at=now.to_dict(),
        payload=evidence_journal.EvidencePayload(
            data=data, measurements=[], evidence_refs=[], artifact_refs=[]
        ),
    )
    try:
        envelope = evidence_journal.append_event(
            channel_id, owner_domain, submission
        )
    except (evidence_journal.EvidenceJournalError, access_policy.AuthorizationError) as exc:
        raise LeaseIntegrityError(
            f"cannot durably fence authority epoch {fenced_epoch!r}: {exc}"
        ) from exc
    _AUTH.fenced.add(key)
    return envelope


def _load_current(
    channel_id: str, resource: ResourceReference
) -> tuple[LeaseRecord | None, int]:
    """Load and verify the fenced current lease snapshot and journal revision."""
    owner = resource.owner_domain
    entity_id = _lease_entity_id(resource)
    try:
        state = evidence_journal.entity_state(channel_id, owner, entity_id)
    except evidence_journal.EvidenceJournalError as exc:
        raise LeaseIntegrityError(
            f"no owner-local lease fence for {owner!r}: {exc}"
        ) from exc
    revision = state.revision
    if isinstance(state.state, evidence_journal.Missing):
        if revision != 0:
            raise LeaseIntegrityError(
                "lease entity has a committed revision but no authoritative state"
            )
        return None, revision
    raw = artifact_store.resolve_artifact(channel_id, state.state)
    try:
        record = LeaseRecord.from_dict(_parse_strict_object(raw, "lease snapshot"))
    except (TypeError, ValueError) as exc:
        raise LeaseIntegrityError(f"durable lease snapshot is invalid: {exc}") from exc
    _verify_record_evidence(channel_id, record)
    return record, revision


def _verify_record_evidence(channel_id: str, record: LeaseRecord) -> None:
    """Verify that a snapshot's retained prefix and citations still resolve."""
    try:
        events = evidence_journal.read_prefix(channel_id, record.journal_prefix)
    except evidence_journal.EvidenceJournalError as exc:
        raise LeaseIntegrityError(
            f"lease snapshot evidence prefix does not verify: {exc}"
        ) from exc
    by_sequence = {event.journal_sequence: event for event in events}
    for ref in record.evidence_refs:
        event = by_sequence.get(ref.sequence)
        if event is None:
            raise LeaseIntegrityError(
                f"lease evidence ref sequence {ref.sequence} is outside the "
                "snapshot's prefix"
            )
        if event.event_id != ref.event_id or event.event_hash != ref.event_hash:
            raise LeaseIntegrityError(
                f"lease evidence ref at sequence {ref.sequence} does not match "
                "the acknowledged event"
            )
        if event.journal_id != ref.journal_id:
            raise LeaseIntegrityError("lease evidence ref names another journal")


def _snapshot_evidence(
    channel_id: str, journal_id: str
) -> tuple[evidence_journal.JournalPrefix, evidence_journal.EvidenceRef]:
    """Return the current head prefix and a citation of its last event.

    A snapshot cannot cite its own commit before that commit exists, so this
    prefix/ref pair is the evidence the transition is derived from; the
    transition's own event becomes the head cited by the next snapshot.
    """
    head = evidence_journal.journal_head(channel_id, journal_id)
    events = evidence_journal.read_prefix(channel_id, head)
    if not events:  # pragma: no cover - admission is always sequence 1
        raise LeaseIntegrityError("an admitted journal has no acknowledged event")
    last = events[-1]
    return head, evidence_journal.EvidenceRef(
        journal_id=journal_id,
        sequence=last.journal_sequence,
        event_id=last.event_id,
        event_hash=last.event_hash,
        pointer="",
    )


def _command_id(
    operation: str,
    resource: ResourceReference,
    policy: VersionPin,
    expected: LeaseRecord | None,
) -> str:
    expected_digest = (
        _record_digest(expected)
        if expected is not None
        else str(
            contract_codec.canonical_digest(
                _canonical_json({"timing": _missing("not_observed")})
            )
        )
    )
    request = {
        "operation": operation,
        "resource": resource.to_dict(),
        "policy": policy.to_dict(),
        "expected": expected_digest,
        "authority_epoch": _AUTH.epoch,
    }
    digest = hashlib.sha256(_canonical_json(request)).hexdigest()
    return "lease_command_" + digest[:40]


def _commit_transition(
    channel_id: str,
    resource: ResourceReference,
    operation: str,
    expected: LeaseRecord | None,
    record: LeaseRecord,
    current_revision: int,
    now: TimePoint,
    event_kind: str,
    event_data: Mapping[str, Any],
) -> LeaseRecord:
    owner = resource.owner_domain
    entity_id = _lease_entity_id(resource)
    data = dict(event_data)
    data["operation"] = operation
    data["lease"] = record.to_dict()
    state_reference = artifact_store.retain_artifact(
        channel_id,
        owner,
        "application/json",
        _record_bytes(record),
        "restricted",
    )
    submission = evidence_journal.EventSubmission(
        producer_sequence=_missing("not_applicable"),
        event_kind=event_kind,
        event_schema_version=LEASE_EVENT_SCHEMA_VERSION,
        occurred_at=now.to_dict(),
        payload=evidence_journal.EvidencePayload(
            data=data, measurements=[], evidence_refs=[], artifact_refs=[]
        ),
    )
    try:
        prefix = evidence_journal.commit_effect(
            channel_id,
            owner,
            entity_id,
            _command_id(operation, resource, record.policy, expected),
            current_revision,
            state_reference,
            (submission,),
        )
    except evidence_journal.RevisionConflictError as exc:
        raise LeaseStaleError(
            "the lease entity advanced after the caller's expected snapshot"
        ) from exc
    except evidence_journal.CommandConflictError as exc:
        raise LeaseStaleError(
            "the same lease command was already applied with different content"
        ) from exc
    # The acknowledged prefix must replay our authoritative event.
    events = evidence_journal.read_prefix(channel_id, prefix)
    if not events or events[-1].event_kind != event_kind:
        raise LeaseIntegrityError(
            "acknowledged lease prefix does not carry the committed event"
        )
    acknowledged = events[-1].payload.get("data", {}).get("lease")
    if acknowledged != record.to_dict():
        raise LeaseIntegrityError(
            "acknowledged lease event does not match the committed snapshot"
        )
    return record


# ---------------------------------------------------------------------------
# Expiry / epoch disposition (never cross a clock or boot)
# ---------------------------------------------------------------------------


def _held_disposition(record: LeaseRecord, now: TimePoint) -> str:
    """Classify a held lease without ever comparing across clocks or boots."""
    if record.lease_state != "held":
        raise LeaseIntegrityError("disposition requires a held lease record")
    issued = _require_timepoint(record.leased_at, "leased_at")
    expires = _require_timepoint(record.lease_expires_at, "lease_expires_at")
    if record.authority_epoch != _AUTH.epoch:
        return "epoch_fenced"
    # One authority epoch is bound to exactly one boot.  The same epoch on a
    # different clock or boot is a corrupt record, never a numeric comparison.
    if (expires.clock_id, expires.boot_id) != (now.clock_id, now.boot_id):
        raise LeaseIntegrityError(
            "a held lease under the current authority epoch names a different "
            "clock or boot"
        )
    if issued.origin != now.origin or expires.origin != now.origin:
        raise LeaseIntegrityError(
            "a held lease's clock origin is not the authority's clock origin"
        )
    if float(now.monotonic_offset_ms) >= float(expires.monotonic_offset_ms):
        return "expired"
    return "active"


def _require_live_lease(
    record: LeaseRecord, now: TimePoint, operation: str
) -> None:
    disposition = _held_disposition(record, now)
    if disposition == "expired":
        raise LeaseExpiredError(
            f"the authority-clock deadline for lease {record.lease_id!r} has "
            f"been reached; {operation} cannot commit"
        )
    if disposition in _FENCED_DISPOSITIONS:
        raise LeaseFencedError(
            f"lease {record.lease_id!r} belongs to a fenced authority epoch or "
            "boot; its deadline is not comparable to this authority's clock"
        )
    if disposition != "active":
        raise LeaseIntegrityError(f"unknown lease disposition {disposition!r}")


def _require_fresh_fence(
    channel_id: str, resource: ResourceReference, record: LeaseRecord | None
) -> None:
    """Durably fence a fenced epoch before this authority touches its leases."""
    if record is None or record.lease_state != "held":
        return
    if record.authority_epoch == _AUTH.epoch:
        return
    issued = _require_timepoint(record.leased_at, "leased_at")
    _append_fence(
        channel_id,
        resource.owner_domain,
        fenced_epoch=record.authority_epoch,
        fenced_clock=issued,
        fenced_boot_id=issued.boot_id,
        reason="authority_restart",
    )


# ---------------------------------------------------------------------------
# Operation builders
# ---------------------------------------------------------------------------


def _base_record(
    *,
    resource: ResourceReference,
    policy: VersionPin,
    entity_revision: int,
    input_revision: int,
    generation_id: str,
    resource_state: str,
    eligible_state: str,
    retry_count: int,
    max_retries: int,
    last_failure_reason: Any,
    journal_prefix: evidence_journal.JournalPrefix,
    evidence_refs: tuple[evidence_journal.EvidenceRef, ...],
) -> LeaseRecord:
    return LeaseRecord(
        record_type=LEASE_RECORD_TYPE,
        schema_version=SCHEMA_VERSION,
        resource=resource,
        policy=policy,
        issuer_id=AUTHORITY_ISSUER_ID,
        authority_epoch=_AUTH.epoch,
        entity_revision=entity_revision,
        input_revision=input_revision,
        generation_id=generation_id,
        resource_state=resource_state,
        eligible_state=eligible_state,
        lease_state="unleased",
        lease_id=_missing("not_applicable"),
        lease_owner=_missing("not_applicable"),
        owner_epoch=_missing("not_applicable"),
        session_epoch=_missing("not_applicable"),
        leased_at=_missing("not_applicable"),
        lease_expires_at=_missing("not_applicable"),
        retry_count=retry_count,
        max_retries_effective=max_retries,
        last_failure_reason=last_failure_reason,
        journal_prefix=journal_prefix,
        evidence_refs=evidence_refs,
    )


def _held_record(
    *,
    prior: LeaseRecord,
    lease_id: str,
    lease_owner: str,
    owner_epoch: str,
    leased_at: TimePoint,
    lease_expires_at: TimePoint,
    journal_prefix: evidence_journal.JournalPrefix,
    evidence_refs: tuple[evidence_journal.EvidenceRef, ...],
) -> LeaseRecord:
    return replace(
        prior,
        authority_epoch=_AUTH.epoch,
        entity_revision=prior.entity_revision + 1,
        lease_id=lease_id,
        lease_owner=lease_owner,
        owner_epoch=owner_epoch,
        leased_at=leased_at,
        lease_expires_at=lease_expires_at,
        journal_prefix=journal_prefix,
        evidence_refs=evidence_refs,
    )


def _event_common(
    prior: LeaseRecord | None,
    *,
    commit_authority: str,
    extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    data: dict[str, Any] = {
        "commit_authority": commit_authority,
        "native_outcome": _missing("not_observed"),
        "prior_lease_id": (
            prior.lease_id if prior is not None else _missing("not_applicable")
        ),
        "prior_owner_epoch": (
            prior.owner_epoch if prior is not None else _missing("not_applicable")
        ),
        "prior_generation_id": (
            prior.generation_id if prior is not None else _missing("not_applicable")
        ),
        "prior_authority_epoch": (
            prior.authority_epoch if prior is not None else _missing("not_applicable")
        ),
    }
    if extra:
        data.update(extra)
    return data


def _op_claim(
    channel_id: str,
    resource: ResourceReference,
    policy: _LeasePolicy,
    current: LeaseRecord | None,
    current_revision: int,
    now: TimePoint,
    prefix: evidence_journal.JournalPrefix,
    ref: evidence_journal.EvidenceRef,
    descriptor: Any,
) -> LeaseRecord:
    reclaimed: Any = _missing("not_applicable")
    prior_retry_count = 0
    prior_entity_revision = 0
    prior_input_revision = 0
    resource_state = policy.initial_resource_state
    eligible_state = policy.eligible_state
    if current is not None:
        if current.policy.to_dict() != policy.pin.to_dict():
            raise LeasePolicyError(
                "the resource's lease is pinned to a different owner policy artifact"
            )
        if current.resource_state != current.eligible_state:
            raise LeaseIneligibleError(
                f"resource state {current.resource_state!r} is not its eligible "
                f"state {current.eligible_state!r}"
            )
        prior_retry_count = current.retry_count
        prior_entity_revision = current.entity_revision
        prior_input_revision = current.input_revision
        resource_state = current.resource_state
        eligible_state = current.eligible_state
        if current.lease_state == "held":
            disposition = _held_disposition(current, now)
            if disposition == "active":
                raise LeaseBusyError(
                    f"resource {resource.entity_type!r}:{resource.entity_id!r} "
                    f"holds unexpired lease {current.lease_id!r}"
                )
            reclaimed = {
                "lease_id": current.lease_id,
                "owner_epoch": current.owner_epoch,
                "disposition": disposition,
                "commit_authority": "revoked",
                "native_outcome": _missing("not_observed"),
            }
    if resource_state != eligible_state:
        raise LeaseIneligibleError(
            f"resource state {resource_state!r} is not its eligible state "
            f"{eligible_state!r}"
        )
    if prior_retry_count >= policy.max_retries:
        raise LeaseRetriesExhaustedError(
            f"retry_count {prior_retry_count} has reached the pinned "
            f"max_retries {policy.max_retries}"
        )
    record = LeaseRecord(
        record_type=LEASE_RECORD_TYPE,
        schema_version=SCHEMA_VERSION,
        resource=resource,
        policy=policy.pin,
        issuer_id=AUTHORITY_ISSUER_ID,
        authority_epoch=_AUTH.epoch,
        entity_revision=prior_entity_revision + 1,
        input_revision=prior_input_revision,
        generation_id=_new_generation_id(),
        resource_state=resource_state,
        eligible_state=eligible_state,
        lease_state="held",
        lease_id=_new_lease_id(),
        lease_owner=descriptor.producer_id,
        owner_epoch=_new_owner_epoch_id(),
        session_epoch=_missing("not_applicable"),
        leased_at=now,
        lease_expires_at=_deadline(now, policy.lease_duration_ms),
        retry_count=prior_retry_count,
        max_retries_effective=policy.max_retries,
        last_failure_reason=_missing("not_applicable"),
        journal_prefix=prefix,
        evidence_refs=(ref,),
    )
    data = _event_common(
        current,
        commit_authority="granted",
        extra={
            "reclaimed_from": reclaimed,
            "policy": policy.pin.to_dict(),
            "lease_duration_ms": policy.lease_duration_ms,
        },
    )
    return _commit_transition(
        channel_id,
        resource,
        "claim",
        current,
        record,
        current_revision,
        now,
        "lease_claimed",
        data,
    )


def _require_same_policy(record: LeaseRecord, policy: _LeasePolicy) -> None:
    if record.policy.to_dict() != policy.pin.to_dict():
        raise LeasePolicyError(
            "the lease is pinned to a different owner policy artifact; other "
            "lease operations require the lease's own pin"
        )


def _op_renew(
    channel_id: str,
    resource: ResourceReference,
    policy: _LeasePolicy,
    current: LeaseRecord,
    current_revision: int,
    now: TimePoint,
    prefix: evidence_journal.JournalPrefix,
    ref: evidence_journal.EvidenceRef,
) -> LeaseRecord:
    _require_same_policy(current, policy)
    if not policy.renewal_allowed:
        raise LeasePolicyError("the pinned owner policy does not allow renewal")
    if current.lease_state != "held":
        raise LeaseStaleError("only a held lease can be renewed")
    _require_live_lease(current, now, "renewal")
    previous_expiry = _require_timepoint(
        current.lease_expires_at, "lease_expires_at"
    )
    record = _held_record(
        prior=current,
        lease_id=current.lease_id,
        lease_owner=current.lease_owner,
        owner_epoch=current.owner_epoch,
        leased_at=_require_timepoint(current.leased_at, "leased_at"),
        lease_expires_at=_deadline(now, policy.lease_duration_ms),
        journal_prefix=prefix,
        evidence_refs=(ref,),
    )
    if float(record.lease_expires_at.monotonic_offset_ms) <= float(
        previous_expiry.monotonic_offset_ms
    ):  # pragma: no cover - positive duration guarantees extension
        raise LeaseIntegrityError("renewal did not extend the lease deadline")
    data = _event_common(
        current,
        commit_authority="granted",
        extra={
            "previous_expires_at": previous_expiry.to_dict(),
            "policy": policy.pin.to_dict(),
        },
    )
    return _commit_transition(
        channel_id,
        resource,
        "renew",
        current,
        record,
        current_revision,
        now,
        "lease_renewed",
        data,
    )


def _op_complete(
    channel_id: str,
    resource: ResourceReference,
    policy: _LeasePolicy,
    current: LeaseRecord,
    current_revision: int,
    now: TimePoint,
    prefix: evidence_journal.JournalPrefix,
    ref: evidence_journal.EvidenceRef,
) -> LeaseRecord:
    _require_same_policy(current, policy)
    if current.lease_state != "held":
        raise LeaseStaleError("only a held lease can be completed")
    # The owner-local commit fence supplies the current record and the
    # authority time; workers cannot supply either.
    validate_completion(
        current,
        current,
        now,
        current.entity_revision,
        current.input_revision,
    )
    record = _base_record(
        resource=resource,
        policy=policy.pin,
        entity_revision=current.entity_revision + 1,
        input_revision=current.input_revision,
        generation_id=current.generation_id,
        resource_state=current.resource_state,
        eligible_state=current.eligible_state,
        retry_count=current.retry_count,
        max_retries=policy.max_retries,
        last_failure_reason=_missing("not_applicable"),
        journal_prefix=prefix,
        evidence_refs=(ref,),
    )
    data = _event_common(
        current,
        commit_authority="revoked",
        extra={
            "previous_expires_at": _field_to_json(current.lease_expires_at),
            "policy": policy.pin.to_dict(),
        },
    )
    return _commit_transition(
        channel_id,
        resource,
        "complete",
        current,
        record,
        current_revision,
        now,
        "lease_completed",
        data,
    )


def _op_release(
    channel_id: str,
    resource: ResourceReference,
    policy: _LeasePolicy,
    current: LeaseRecord,
    current_revision: int,
    now: TimePoint,
    prefix: evidence_journal.JournalPrefix,
    ref: evidence_journal.EvidenceRef,
) -> LeaseRecord:
    _require_same_policy(current, policy)
    if current.lease_state != "held":
        raise LeaseStaleError("only a held lease can be released")
    _require_live_lease(current, now, "release")
    record = _base_record(
        resource=resource,
        policy=policy.pin,
        entity_revision=current.entity_revision + 1,
        input_revision=current.input_revision,
        generation_id=current.generation_id,
        resource_state=current.resource_state,
        eligible_state=current.eligible_state,
        retry_count=current.retry_count,
        max_retries=policy.max_retries,
        last_failure_reason=_missing("not_applicable"),
        journal_prefix=prefix,
        evidence_refs=(ref,),
    )
    data = _event_common(
        current,
        commit_authority="revoked",
        extra={"policy": policy.pin.to_dict()},
    )
    return _commit_transition(
        channel_id,
        resource,
        "release",
        current,
        record,
        current_revision,
        now,
        "lease_released",
        data,
    )


def _op_expire(
    channel_id: str,
    resource: ResourceReference,
    policy: _LeasePolicy,
    current: LeaseRecord,
    current_revision: int,
    now: TimePoint,
    prefix: evidence_journal.JournalPrefix,
    ref: evidence_journal.EvidenceRef,
) -> LeaseRecord:
    _require_same_policy(current, policy)
    if current.lease_state != "held":
        raise LeaseStaleError("only a held lease can expire")
    disposition = _held_disposition(current, now)
    if disposition == "active":
        raise LeaseNotExpiredError(
            f"lease {current.lease_id!r} has not reached its authority-clock "
            "deadline"
        )
    record = _base_record(
        resource=resource,
        policy=policy.pin,
        entity_revision=current.entity_revision + 1,
        input_revision=current.input_revision,
        generation_id=current.generation_id,
        resource_state=current.resource_state,
        eligible_state=current.eligible_state,
        retry_count=current.retry_count,
        max_retries=policy.max_retries,
        # Expiry revokes local commit authority only.  Whether the generation
        # ever reached an employer remains an unobserved outcome.
        last_failure_reason=_missing("not_observed"),
        journal_prefix=prefix,
        evidence_refs=(ref,),
    )
    data = _event_common(
        current,
        commit_authority="revoked",
        extra={
            "disposition": disposition,
            "elapsed_downtime": _missing("not_observed"),
            "employer_noncommitment": _missing("not_observed"),
            "policy": policy.pin.to_dict(),
        },
    )
    return _commit_transition(
        channel_id,
        resource,
        "expire",
        current,
        record,
        current_revision,
        now,
        "lease_expired",
        data,
    )


def _op_fail_generation(
    channel_id: str,
    resource: ResourceReference,
    policy: _LeasePolicy,
    current: LeaseRecord,
    current_revision: int,
    now: TimePoint,
    prefix: evidence_journal.JournalPrefix,
    ref: evidence_journal.EvidenceRef,
) -> LeaseRecord:
    _require_same_policy(current, policy)
    if not _is_missing(current.last_failure_reason):
        raise LeaseFailureAlreadyCountedError(
            f"generation {current.generation_id!r} already recorded failure "
            f"{current.last_failure_reason!r}; a failed generation counts once"
        )
    if current.retry_count >= policy.max_retries:
        raise LeaseRetriesExhaustedError(
            f"retry_count {current.retry_count} has reached the pinned "
            f"max_retries {policy.max_retries}"
        )
    record = _base_record(
        resource=resource,
        policy=policy.pin,
        entity_revision=current.entity_revision + 1,
        input_revision=current.input_revision,
        generation_id=current.generation_id,
        resource_state=current.resource_state,
        eligible_state=current.eligible_state,
        retry_count=current.retry_count + 1,
        max_retries=policy.max_retries,
        last_failure_reason=policy.failure_code,
        journal_prefix=prefix,
        evidence_refs=(ref,),
    )
    data = _event_common(
        current,
        commit_authority="revoked",
        extra={
            "failure_code": policy.failure_code,
            "retry_count_before": current.retry_count,
            "retry_count_after": record.retry_count,
            "policy": policy.pin.to_dict(),
        },
    )
    return _commit_transition(
        channel_id,
        resource,
        "fail_generation",
        current,
        record,
        current_revision,
        now,
        "lease_generation_failed",
        data,
    )


# ---------------------------------------------------------------------------
# Public: completion validation
# ---------------------------------------------------------------------------


def validate_completion(
    lease: LeaseRecord,
    current: LeaseRecord,
    authority_now: TimePoint,
    entity_revision: int,
    input_revision: int,
) -> None:
    """Validate a completion inside the owner-local commit fence.

    ``current`` and ``authority_now`` must come from the fenced authority
    context, never from the worker.  Raises a specific
    :class:`LeaseAuthorityError` subclass on any stale, expired, fenced,
    cross-boot, or revision-mismatched completion; returns ``None`` when the
    completion may commit.
    """
    if not isinstance(lease, LeaseRecord) or not isinstance(current, LeaseRecord):
        raise LeaseOperationError("completion requires lease and current records")
    if not isinstance(authority_now, TimePoint):
        raise LeaseOperationError("authority_now must be an authority TimePoint")
    _require_revision(entity_revision, "entity_revision")
    _require_revision(input_revision, "input_revision")

    if current.lease_state != "held":
        raise LeaseStaleError("the fenced current state holds no live lease")
    if lease.lease_state != "held":
        raise LeaseStaleError("the completing lease is not a held lease")
    if lease.resource.to_dict() != current.resource.to_dict():
        raise LeaseStaleError("completion names a different resource than the fence")
    if lease.policy.to_dict() != current.policy.to_dict():
        raise LeaseStaleError("completion names a different pinned policy")

    issued = _require_timepoint(lease.leased_at, "leased_at")
    expires = _require_timepoint(lease.lease_expires_at, "lease_expires_at")
    if (issued.clock_id, issued.boot_id) != (expires.clock_id, expires.boot_id):
        raise LeaseIntegrityError(
            "the lease's issue and expiry points use different clocks or boots"
        )
    if not (
        float(expires.monotonic_offset_ms) > float(issued.monotonic_offset_ms)
    ):
        raise LeaseIntegrityError("the lease expires no later than it was issued")

    # The fenced current snapshot is authoritative: the completing snapshot
    # must be byte-for-byte the same lease, including its issue/expiry points,
    # generation, and token.  A forged extension is stale, not an extension.
    if (
        _field_to_json(lease.leased_at) != _field_to_json(current.leased_at)
        or _field_to_json(lease.lease_expires_at)
        != _field_to_json(current.lease_expires_at)
        or lease.generation_id != current.generation_id
        or lease.lease_id != current.lease_id
        or lease.lease_owner != current.lease_owner
        or lease.owner_epoch != current.owner_epoch
        or lease.session_epoch != current.session_epoch
    ):
        raise LeaseStaleError(
            "the completing token, generation, owner/session epoch, or lease "
            "deadline is not the fenced current lease"
        )
    current_expires = _require_timepoint(
        current.lease_expires_at, "lease_expires_at"
    )
    if (
        current_expires.clock_id,
        current_expires.boot_id,
        current_expires.origin,
    ) != (expires.clock_id, expires.boot_id, expires.origin):
        raise LeaseStaleError(
            "the completing deadline is not the fenced current deadline"
        )

    # Cross-clock and cross-boot comparisons are refused before any arithmetic.
    if (
        authority_now.clock_id,
        authority_now.boot_id,
        authority_now.origin,
    ) != (expires.clock_id, expires.boot_id, expires.origin):
        raise LeaseClockMismatchError(
            "authority_now uses a different clock, boot, or origin than the "
            "lease; monotonic offsets are never compared across clock lifetimes"
        )
    if (
        lease.authority_epoch != _AUTH.epoch
        or current.authority_epoch != _AUTH.epoch
    ):
        raise LeaseFencedError(
            "the lease belongs to a fenced authority epoch; a durable epoch "
            "fence precedes any reclaim"
        )
    if float(authority_now.monotonic_offset_ms) < float(issued.monotonic_offset_ms):
        raise LeaseIntegrityError(
            "the authority clock is earlier than the lease's issue point"
        )
    if float(authority_now.monotonic_offset_ms) >= float(
        current_expires.monotonic_offset_ms
    ):
        raise LeaseExpiredError(
            f"lease {lease.lease_id!r} reached its authority-clock deadline; "
            "local commit authority is revoked"
        )
    if (
        lease.entity_revision != entity_revision
        or current.entity_revision != lease.entity_revision
    ):
        raise LeaseRevisionConflictError(
            "the completing entity revision is not the lease's admitted revision"
        )
    if (
        lease.input_revision != input_revision
        or current.input_revision != lease.input_revision
    ):
        raise LeaseRevisionConflictError(
            "the completing input revision is not the lease's admitted revision"
        )


# ---------------------------------------------------------------------------
# Public: lease transitions
# ---------------------------------------------------------------------------


def transition_lease(
    channel_id: str,
    resource: ResourceReference,
    operation: str,
    expected: LeaseRecord | Missing,
    policy: VersionPin,
) -> LeaseRecord:
    """Apply one owner-fenced lease transition and commit its evidence.

    ``expected`` is the caller's expected current snapshot: a
    :class:`LeaseRecord` or a typed ``Missing`` envelope meaning "no lease
    record has ever been committed for this resource".  The fenced current
    snapshot must equal ``expected`` exactly; otherwise the transition is
    rejected with :class:`LeaseStaleError` and has no effect.

    Supported operations: ``claim``, ``renew``, ``complete``, ``release``,
    ``expire``, ``fail_generation``.  The returned record is the durable
    snapshot (the same bytes committed as the entity's authoritative state).
    """
    if not isinstance(resource, ResourceReference):
        raise LeaseOperationError("resource must be a ResourceReference")
    if not isinstance(operation, str) or operation not in LEASE_OPERATIONS:
        raise LeaseOperationError(
            f"unsupported lease operation {operation!r}; expected one of "
            f"{sorted(LEASE_OPERATIONS)}"
        )
    if not isinstance(policy, VersionPin):
        raise LeasePolicyError("policy must be a VersionPin")
    missing_expected = _as_missing(expected)
    if missing_expected is None and not isinstance(expected, LeaseRecord):
        raise LeaseOperationError(
            "expected must be a LeaseRecord or a typed Missing envelope"
        )

    with _AUTH_LOCK:
        descriptor = _authorize(channel_id, resource)
        current, current_revision = _load_current(channel_id, resource)
        if missing_expected is not None:
            if current is not None:
                raise LeaseStaleError(
                    "expected no committed lease record, but the fence holds one"
                )
        elif current is None:
            raise LeaseStaleError(
                "expected a committed lease record, but the fence holds none"
            )
        elif _record_bytes(expected) != _record_bytes(current):
            raise LeaseStaleError(
                "expected lease snapshot is not the fenced current snapshot"
            )

        resolved = _resolve_policy(channel_id, resource, policy)
        journal_id = _ensure_clock_registered(channel_id, resource.owner_domain)

        if current is not None and current.lease_state == "held":
            disposition = _held_disposition(current, _now())
            if disposition in _FENCED_DISPOSITIONS:
                if operation in {"complete", "renew", "release"}:
                    raise LeaseFencedError(
                        f"lease {current.leased_at!r} was issued by a fenced "
                        "authority epoch; it cannot be extended or completed"
                    )
                _require_fresh_fence(channel_id, resource, current)

        now = _now()
        prefix, evidence_ref = _snapshot_evidence(channel_id, journal_id)

        if operation == "claim":
            return _op_claim(
                channel_id,
                resource,
                resolved,
                current,
                current_revision,
                now,
                prefix,
                evidence_ref,
                descriptor,
            )
        if current is None:  # pragma: no cover - guarded above
            raise LeaseStaleError("no current lease record")
        handlers = {
            "renew": _op_renew,
            "complete": _op_complete,
            "release": _op_release,
            "expire": _op_expire,
            "fail_generation": _op_fail_generation,
        }
        return handlers[operation](
            channel_id,
            resource,
            resolved,
            current,
            current_revision,
            now,
            prefix,
            evidence_ref,
        )


# ---------------------------------------------------------------------------
# Public: reads, restart, and inspection
# ---------------------------------------------------------------------------


def load_lease(
    channel_id: str, resource: ResourceReference
) -> LeaseRecord | Missing:
    """Return the verified fenced lease snapshot, or ``Missing(not_observed)``."""
    if not isinstance(resource, ResourceReference):
        raise LeaseOperationError("resource must be a ResourceReference")
    with _AUTH_LOCK:
        record, _revision = _load_current(channel_id, resource)
        if record is None:
            return _missing("not_observed")
        return record


def restart_authority(
    channel_id: str, owner_domain: str
) -> evidence_journal.JournalEnvelope:
    """Restart the lease authority and durably fence the previous epoch.

    A new authority epoch, clock boot, and monotonic base are established.  The
    old epoch is fenced in ``owner_domain``'s journal *before* this function
    returns, so no lease issued under the old epoch can be reclaimed or
    completed without the durable fence.  The old boot's monotonic offsets are
    never compared with the new boot; downtime is ``Missing(not_observed)``.
    """
    _require_identifier(owner_domain, "owner_domain")
    with _AUTH_LOCK:
        # Authorize the control-plane write through the authenticated channel.
        access_policy.authorize(
            channel_id, f"{owner_domain}.write", owner_domain
        )
        old_epoch = _AUTH.epoch
        old_boot_id = _AUTH.boot_id
        old_clock = TimePoint(
            clock_id=AUTHORITY_CLOCK_ID,
            boot_id=old_boot_id,
            origin="engine_measured",
            monotonic_offset_ms=_offset_ms(),
            utc_annotation=_missing("not_observed"),
        )
        _AUTH.epoch = _new_epoch_id()
        _AUTH.boot_id = "boot_lease_authority_" + secrets.token_hex(8)
        _AUTH.boot_ns = time.monotonic_ns()
        _AUTH.test_offset_ms = 0.0
        _AUTH.journals.pop(owner_domain, None)
        _AUTH.registered.discard(owner_domain)
        envelope = _append_fence(
            channel_id,
            owner_domain,
            fenced_epoch=old_epoch,
            fenced_clock=old_clock,
            fenced_boot_id=old_boot_id,
            reason="authority_restart",
        )
        return envelope

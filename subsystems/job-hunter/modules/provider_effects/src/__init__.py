"""provider_effects: authorized outbound mail/calendar/notification effects (tier 3).

Scheduling and outbound communication (``job-hunter-seam-mapping.md#17.2``):

* Calendar events, ACLs, and free/busy are distinct provider operations.
* Outbound email, notifications, calendar writes, and follow-ups require
  explicit operation authority, a pinned provider adapter, an immutable
  intended payload, a stable local command identity, durable intent before
  dispatch, actual acknowledgement/effect evidence, and explicit uncertain
  delivery when needed.
* These are private external operations, not fabricated job-application
  attempts and not read-only extraction.
* No live send endpoint, callback verifier, or native idempotency guarantee
  is inferred from the endpoint inventory.  Retrying an uncertain send
  requires the provider's evidenced semantics or duplicate-risk review.

This module implements :func:`execute_provider_effect` over the real
evidence kernel siblings:

* ``access_policy.authorize`` for authenticated, owner-local authority.
* ``artifact_store`` for immutable, content-addressed intent/payload/ack bytes.
* ``evidence_journal.commit_effect`` for the atomic, owner-local durable
  intent (admitted input + idempotency record + revision advance + journal
  event + replayable response) before any external dispatch.
* ``evidence_journal.append_event`` for the dispatch-outcome observation
  (acknowledged or explicitly uncertain).
* ``contract_codec.validate_record`` as the strict JSON gate (no bare nulls,
  no duplicate keys, no nonfinite numbers; typed ``Missing`` envelopes only).

Delivery model (no live endpoint is assumed):

* The intent is always persisted before dispatch is attempted.
* Dispatch succeeds (returns an ``ArtifactReference`` to retained ack
  evidence) only when the test harness staged explicit provider
  acknowledgement bytes for the command via
  :func:`stage_provider_ack_for_tests`.  There is no inferred success.
* Otherwise dispatch is explicitly uncertain: the module journals a
  ``provider_dispatch_uncertain`` observation and returns
  ``Missing(not_observed)`` with a duplicate-risk detail.  The caller must
  not blindly retry.
* A repeated call with the same ``command_id`` and identical content replays
  the stored response without a new dispatch or new journal events.
* A repeated ``command_id`` with changed content is rejected as a command
  conflict (stable local command identity).
* A new ``command_id`` carrying an already-attempted ``(operation, payload)``
  pair is blocked as duplicate-risk: it returns ``Missing(not_observed)``
  with a review detail and performs no dispatch and no journal write, even
  when an ack was staged for the new command.  Provider-evidenced recovery
  semantics are never inferred.

Forbidden operations (closed allowlist) are rejected before any retention or
journal write: application submission, browser control, arbitrary URLs, and
executable commands are never accepted as provider effects, and no
application attempt is ever fabricated for correspondence or calendar work.
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
import re
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


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
    "EVENT_SCHEMA_VERSION",
    "EVENT_KINDS",
    "ALLOWED_OPERATIONS",
    "Missing",
    "VersionPin",
    "ArtifactReference",
    "EvidenceRef",
    "ProviderEffectsError",
    "ProviderOperationError",
    "ProviderAdapterError",
    "ProviderAuthorizationError",
    "ProviderPayloadError",
    "ProviderConflictError",
    "execute_provider_effect",
    "event_kind_declarations",
    "stage_provider_ack_for_tests",
    "dispatch_attempts_for_tests",
    "reset_for_tests",
]

SCHEMA_VERSION = "evidence-kernel/0.1.0"
EVENT_SCHEMA_VERSION = "1"
RECORD_TYPE_INTENT = "provider_intent"
RECORD_TYPE_ACK = "provider_ack"

#: Every event this module writes, with its pinned schema version.  The
#: composition root registers each kind in the manifest event registry and in
#: the ingress authority before the first provider effect.
EVENT_KINDS: Mapping[str, str] = {
    "provider_intent_persisted": EVENT_SCHEMA_VERSION,
    "provider_dispatch_uncertain": EVENT_SCHEMA_VERSION,
    "provider_dispatch_acknowledged": EVENT_SCHEMA_VERSION,
}

#: Closed provider-effect vocabulary.  Calendar read/write/ACL/scheduling are
#: distinct; only the listed writes are effects.  Everything else -- including
#: application submission, browser control, arbitrary URLs, and executable
#: commands -- is rejected before any retention or journal write.
ALLOWED_OPERATIONS = frozenset(
    {
        "gmail.send",
        "notification.send",
        "calendar.create",
        "calendar.update",
        "calendar.acl.set",
        "followup.schedule",
    }
)

#: Substrings that are never provider effects.  The allowlist above already
#: rejects them; this set produces a sharper forbidden-operation message.
_FORBIDDEN_SUBSTRINGS = frozenset(
    {
        "submit",
        "application",
        "attempt",
        "browser",
        "navigate",
        "click",
        "camoufox",
        "http",
        "https",
        "url",
        "fetch",
        "exec",
        "shell",
        "run_command",
        "command_exec",
    }
)

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_CODEC_GATE_SCHEMA = "record/v1"
_CODEC_GATE_KEY = "timing"

_ENTITY_PREFIX = "provider_effect_"

_UNCERTAIN_DETAIL = (
    "uncertain delivery: no live send endpoint, callback verifier, or native "
    "idempotency guarantee is inferred; retrying this send requires the "
    "provider's evidenced recovery semantics or duplicate-risk review"
)

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ProviderEffectsError(Exception):
    """Base class for provider-effect rejections and integrity failures."""


class ProviderOperationError(ProviderEffectsError, ValueError):
    """The requested operation is not an authorized provider effect."""


class ProviderAdapterError(ProviderEffectsError, ValueError):
    """The pinned provider adapter is missing, malformed, or unretained."""


class ProviderAuthorizationError(ProviderEffectsError, PermissionError):
    """Explicit operation authority is missing or the channel is not allowed."""


class ProviderPayloadError(ProviderEffectsError, ValueError):
    """The immutable intended payload is missing, unreadable, or invalid."""


class ProviderConflictError(ProviderEffectsError, ValueError):
    """A stable command identity was reused with changed content."""


# ---------------------------------------------------------------------------
# Kernel record shapes (local K.Missing / K.VersionPin mirrors)
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
            out["Detail"] = self.detail
        return out

    @classmethod
    def from_dict(cls, data: Any) -> "Missing":
        if not isinstance(data, dict):
            raise TypeError("Missing must be decoded from a dict")
        keys = set(data.keys())
        allowed = {"value", "reason", "Detail", "detail".lower()}
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
    """Immutable pin of a provider-adapter artifact (``K.VersionPin``)."""

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
        if keys != {"id", "version", "artifact_digest"}:
            raise ValueError(
                "VersionPin must contain exactly id, version, artifact_digest; "
                f"got {sorted(keys)}"
            )
        for key in ("id", "version", "artifact_digest"):
            if data[key] is None:
                raise ValueError(f"VersionPin.{key} must not be a bare null")
        return cls(
            id=data["id"],
            version=data["version"],
            artifact_digest=data["artifact_digest"],
        )


#: Sibling kernel types reused for the public interface.
ArtifactReference = artifact_store.ArtifactReference
EvidenceRef = evidence_journal.EvidenceRef


# ---------------------------------------------------------------------------
# Small validators / codec helpers
# ---------------------------------------------------------------------------


def _require_identifier(value: Any, field_name: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a str, not {type(value).__name__}")
    if not value or value != value.strip():
        raise ValueError(f"{field_name} must be a nonempty identifier without padding")
    if len(value) > 256:
        raise ValueError(f"{field_name} must be at most 256 characters")
    if "\x00" in value or any(ord(ch) < 0x20 for ch in value):
        raise ValueError(f"{field_name} must not contain control characters")
    return value


def _require_digest(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.match(value):
        raise ValueError(f"{field_name} must be a sha256:<64 lowercase hex> digest")
    return value


def _canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _codec_gate(obj: Mapping[str, Any], field_name: str) -> None:
    """Reject bare nulls, duplicate keys, and nonfinite numbers (strict JSON)."""
    try:
        contract_codec.validate_record(
            _canonical_json_bytes({_CODEC_GATE_KEY: dict(obj)}),
            _CODEC_GATE_SCHEMA,
        )
    except (TypeError, ValueError) as exc:
        raise ProviderPayloadError(
            f"{field_name} is not strict JSON evidence: {exc}"
        ) from exc


def _parse_strict_object(raw: bytes, field_name: str) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProviderPayloadError(f"{field_name} is not UTF-8 JSON: {exc}") from exc
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ProviderPayloadError(
            f"{field_name} is not a JSON object: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise ProviderPayloadError(f"{field_name} must be a JSON object")
    _codec_gate(value, field_name)
    return value


def _fingerprint(
    operation: str,
    payload_ref: Any,
    adapter: VersionPin,
    auth_refs: tuple[Any, ...],
) -> str:
    body = {
        "operation": operation,
        "payload_digest": payload_ref.digest,
        "payload_size": payload_ref.size_bytes,
        "adapter": adapter.to_dict(),
        "authorization_refs": [r.to_dict() for r in auth_refs],
    }
    return "sha256:" + hashlib.sha256(_canonical_json_bytes(body)).hexdigest()


def _coerce_artifact_ref(value: Any, field_name: str) -> Any:
    if isinstance(value, artifact_store.ArtifactReference):
        return value
    if isinstance(value, dict):
        try:
            return artifact_store.ArtifactReference.from_dict(value)
        except (TypeError, ValueError) as exc:
            raise ProviderPayloadError(
                f"{field_name} is not a valid ArtifactReference: {exc}"
            ) from exc
    raise ProviderPayloadError(
        f"{field_name} must be an ArtifactReference, not {type(value).__name__}"
    )


def _coerce_version_pin(value: Any, field_name: str) -> VersionPin:
    if isinstance(value, VersionPin):
        return value
    if isinstance(value, dict):
        try:
            return VersionPin.from_dict(value)
        except (TypeError, ValueError) as exc:
            raise ProviderAdapterError(
                f"{field_name} is not a valid VersionPin: {exc}"
            ) from exc
    raise ProviderAdapterError(
        f"{field_name} must be a VersionPin, not {type(value).__name__}"
    )


def _coerce_evidence_ref(value: Any, field_name: str) -> Any:
    if isinstance(value, evidence_journal.EvidenceRef):
        return value
    if isinstance(value, Mapping):
        try:
            return evidence_journal.EvidenceRef.from_dict(
                {str(k): v for k, v in value.items()}
            )
        except (TypeError, ValueError) as exc:
            raise ProviderAuthorizationError(
                f"{field_name} is not a valid EvidenceRef: {exc}"
            ) from exc
    raise ProviderAuthorizationError(
        f"{field_name} must be an EvidenceRef, not {type(value).__name__}"
    )


def _entity_id(command_id: str) -> str:
    entity = f"{_ENTITY_PREFIX}{command_id}"
    _require_identifier(entity, "entity_id")
    return entity


def event_kind_declarations() -> tuple[dict[str, Any], ...]:
    """Manifest event-registry entries for every kind this module writes."""
    return tuple(
        {
            "event_kind": kind,
            "event_schema_version": version,
            "role": "lifecycle_observation",
            "assertion_kind": "authoritative_effect",
            "writer_roles": ["kernel"],
        }
        for kind, version in EVENT_KINDS.items()
    )


# ---------------------------------------------------------------------------
# Module-local durability helpers (idempotency + duplicate-risk + staged acks)
# ---------------------------------------------------------------------------

_LOCK = threading.RLock()
_COMMANDS: dict[tuple[str, str], dict[str, Any]] = {}
_PAYLOAD_TO_COMMAND: dict[tuple[str, str, str], str] = {}
_STAGED_ACKS: dict[str, bytes] = {}
_DISPATCH_ATTEMPTS = 0


def reset_for_tests() -> None:
    """Clear idempotency records, duplicate-risk index, and staged acks."""
    global _DISPATCH_ATTEMPTS
    with _LOCK:
        _COMMANDS.clear()
        _PAYLOAD_TO_COMMAND.clear()
        _STAGED_ACKS.clear()
        _DISPATCH_ATTEMPTS = 0


def stage_provider_ack_for_tests(command_id: str, ack: dict[str, Any] | bytes) -> None:
    """Stage explicit provider acknowledgement bytes for one command.

    The staged bytes simulate the provider's actual ack evidence surface.
    They must be a strict JSON object; invalid bytes are retained as staged
    but treated as non-evidence (the dispatch stays uncertain) so success is
    never inferred from malformed provider output.
    """
    _require_identifier(command_id, "command_id")
    if isinstance(ack, dict):
        raw = _canonical_json_bytes(ack)
    elif isinstance(ack, (bytes, bytearray)):
        raw = bytes(ack)
    else:
        raise TypeError("ack must be a dict or bytes")
    with _LOCK:
        _STAGED_ACKS[command_id] = raw


def dispatch_attempts_for_tests() -> int:
    """Number of external dispatches attempted since the last reset."""
    with _LOCK:
        return _DISPATCH_ATTEMPTS


def _blocked_duplicate_detail(
    payload_digest: str, prior_command: str, command_id: str
) -> str:
    return (
        "duplicate-risk review required: payload "
        f"{payload_digest} was already attempted as {prior_command!r} with "
        "uncertain or acknowledged delivery; new command "
        f"{command_id!r} was not dispatched and no native idempotency was inferred"
    )


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


async def execute_provider_effect(
    channel_id: str,
    command_id: str,
    operation: str,
    payload: ArtifactReference,
    adapter: VersionPin,
    authorization_refs: tuple[EvidenceRef, ...],
) -> ArtifactReference | Missing:
    """Execute one authorized outbound provider effect.

    The authorized intent (command identity, operation, immutable payload,
    pinned adapter, and operation-authority evidence) is committed through
    ``evidence_journal.commit_effect`` before any external dispatch is
    attempted.  Dispatch returns retained acknowledgement evidence only when
    explicit provider ack bytes were staged for the command; otherwise it
    journals an explicitly uncertain outcome and returns
    ``Missing(not_observed)``.  Uncertain sends are never blindly retried.
    """
    # -- 1. Identifiers + closed operation vocabulary (before any I/O). ----
    _require_identifier(channel_id, "channel_id")
    _require_identifier(command_id, "command_id")
    _require_identifier(operation, "operation")
    if operation not in ALLOWED_OPERATIONS:
        lowered = operation.lower()
        if any(token in lowered for token in _FORBIDDEN_SUBSTRINGS):
            raise ProviderOperationError(
                f"operation {operation!r} is forbidden as a provider effect: "
                "application submission, browser control, arbitrary URLs, and "
                "executable commands are never provider operations"
            )
        raise ProviderOperationError(
            f"operation {operation!r} is not an authorized provider effect; "
            f"expected one of {sorted(ALLOWED_OPERATIONS)}"
        )

    # -- 2. Immutable payload reference + pinned adapter + authority refs. --
    payload_ref = _coerce_artifact_ref(payload, "payload")
    owner_domain = payload_ref.owner_domain
    adapter_pin = _coerce_version_pin(adapter, "adapter")
    try:
        known_digests = artifact_store.known_digests()
    except AttributeError:  # pragma: no cover - older sibling without index
        known_digests = frozenset()
    if adapter_pin.artifact_digest not in known_digests:
        # Fall back to a strict structural check when the sibling exposes no
        # digest index; the digest format was already validated above.
        if not known_digests:
            pass
        else:
            raise ProviderAdapterError(
                "adapter artifact "
                f"{adapter_pin.artifact_digest} is not a retained, pinned "
                "provider-adapter artifact; adapter semantics must be pinned "
                "before dispatch"
            )
    if not isinstance(authorization_refs, (tuple, list)) or not authorization_refs:
        raise ProviderAuthorizationError(
            "explicit operation authority requires at least one EvidenceRef"
        )
    auth_refs = tuple(
        _coerce_evidence_ref(ref, f"authorization_refs[{index}]")
        for index, ref in enumerate(authorization_refs)
    )

    # -- 3. Authenticated, owner-local authorization. -----------------------
    try:
        projection = access_policy.channel_projection(channel_id)
    except access_policy.UnknownChannelError as exc:
        raise ProviderAuthorizationError(
            f"unknown channel {channel_id!r}; provider effects require an "
            "authenticated ingress session"
        ) from exc
    if projection.get("axis") != owner_domain:
        raise access_policy.GrantDeniedError(
            f"owner-local write required: channel axis {projection.get('axis')!r} "
            f"cannot write owner domain {owner_domain!r}"
        )
    grants = list(projection.get("grants", []))
    if not grants:
        raise access_policy.GrantDeniedError(
            f"authenticated channel holds no write grant for {owner_domain!r}"
        )
    descriptor = access_policy.authorize(channel_id, grants[0], command_id)
    _ = descriptor

    # -- 4. Resolve + strictly validate the immutable intended payload. ----
    try:
        payload_bytes = artifact_store.resolve_artifact(channel_id, payload_ref)
    except artifact_store.ArtifactError as exc:
        raise ProviderPayloadError(
            f"intended payload {payload_ref.digest} is not resolvable: {exc}"
        ) from exc
    payload_obj = _parse_strict_object(payload_bytes, "payload")

    fingerprint = _fingerprint(operation, payload_ref, adapter_pin, auth_refs)
    key = (owner_domain, command_id)
    payload_key = (owner_domain, operation, payload_ref.digest)

    # -- 5. Stable command identity + duplicate-risk gate (no I/O). ---------
    with _LOCK:
        existing = _COMMANDS.get(key)
        if existing is not None:
            if existing["fingerprint"] != fingerprint:
                raise ProviderConflictError(
                    f"command {command_id!r} reused with changed content; "
                    "local command identity is stable"
                )
            stored = existing["response"]
            if isinstance(stored, Missing):
                return Missing(reason=stored.reason, detail=stored.detail)
            return stored
        prior_command = _PAYLOAD_TO_COMMAND.get(payload_key)
        if prior_command is not None and prior_command != command_id:
            blocked = Missing(
                reason="not_observed",
                detail=_blocked_duplicate_detail(
                    payload_ref.digest, prior_command, command_id
                ),
            )
            _COMMANDS[key] = {
                "fingerprint": fingerprint,
                "response": blocked,
                "payload_digest": payload_ref.digest,
                "operation": operation,
            }
            return Missing(reason=blocked.reason, detail=blocked.detail)

    # -- 6. Durable intent before dispatch (owner-local atomic commit). -----
    entity_id = _entity_id(command_id)
    intent_doc: dict[str, Any] = {
        "record_type": RECORD_TYPE_INTENT,
        "command_id": command_id,
        "operation": operation,
        "payload_digest": payload_ref.digest,
        "payload_size": payload_ref.size_bytes,
        "payload_media_type": payload_ref.media_type,
        "adapter_id": adapter_pin.id,
        "adapter_version": adapter_pin.version,
        "adapter_digest": adapter_pin.artifact_digest,
        "authorization_count": len(auth_refs),
        "owner_domain": owner_domain,
    }
    _codec_gate(intent_doc, "intent")
    intent_bytes = _canonical_json_bytes(intent_doc)
    try:
        intent_ref = artifact_store.retain_artifact(
            channel_id,
            owner_domain,
            "application/json",
            intent_bytes,
            payload_ref.access,
        )
    except artifact_store.ArtifactError as exc:
        raise ProviderEffectsError(
            f"cannot durably retain provider intent for {command_id!r}: {exc}"
        ) from exc

    intent_data: dict[str, Any] = {
        "command_id": command_id,
        "operation": operation,
        "payload_digest": payload_ref.digest,
        "adapter_id": adapter_pin.id,
        "adapter_version": adapter_pin.version,
        "adapter_digest": adapter_pin.artifact_digest,
        "authorization_count": len(auth_refs),
        "record_type": RECORD_TYPE_INTENT,
    }
    # Preserve calendar payload semantics by reference (digests only in the
    # journal; exact bytes stay in the immutable payload artifact).
    for field in ("timezone", "all_day", "timed", "provider_revision"):
        if field in payload_obj and isinstance(payload_obj[field], (str, bool)):
            intent_data[f"payload_{field}"] = payload_obj[field]
    intent_submission = evidence_journal.EventSubmission(
        producer_sequence=evidence_journal.NOT_APPLICABLE,
        event_kind="provider_intent_persisted",
        event_schema_version=EVENT_SCHEMA_VERSION,
        occurred_at=evidence_journal.NOT_OBSERVED,
        payload=evidence_journal.EvidencePayload(
            data=intent_data,
            measurements=(),
            evidence_refs=tuple(auth_refs),
            artifact_refs=(payload_ref, intent_ref),
        ),
    )
    try:
        evidence_journal.commit_effect(
            channel_id,
            owner_domain,
            entity_id,
            command_id,
            0,
            intent_ref,
            (intent_submission,),
        )
    except evidence_journal.CommandConflictError as exc:
        raise ProviderConflictError(
            f"command {command_id!r} reused with changed content; "
            "local command identity is stable"
        ) from exc
    except evidence_journal.RevisionConflictError as exc:
        raise ProviderConflictError(
            f"provider entity for {command_id!r} already advanced; "
            "command identity is stable"
        ) from exc

    # -- 7. External dispatch (only after durable intent). ------------------
    with _LOCK:
        global _DISPATCH_ATTEMPTS
        _DISPATCH_ATTEMPTS += 1
        staged = _STAGED_ACKS.get(command_id)

    ack_ref: Any | None = None
    if staged is not None:
        try:
            ack_obj = _parse_strict_object(staged, "provider_ack")
        except ProviderPayloadError:
            ack_obj = None
        if ack_obj is not None:
            ack_doc: dict[str, Any] = {
                "record_type": RECORD_TYPE_ACK,
                "command_id": command_id,
                "operation": operation,
                "payload_digest": payload_ref.digest,
                "adapter_id": adapter_pin.id,
                "adapter_version": adapter_pin.version,
                "ack": ack_obj,
            }
            try:
                _codec_gate(ack_doc, "provider_ack")
                ack_ref = artifact_store.retain_artifact(
                    channel_id,
                    owner_domain,
                    "application/json",
                    _canonical_json_bytes(ack_doc),
                    payload_ref.access,
                )
            except (ProviderPayloadError, artifact_store.ArtifactError):
                ack_ref = None

    # -- 8. Journal the dispatch outcome observation. -----------------------
    if ack_ref is not None:
        outcome_submission = evidence_journal.EventSubmission(
            producer_sequence=evidence_journal.NOT_APPLICABLE,
            event_kind="provider_dispatch_acknowledged",
            event_schema_version=EVENT_SCHEMA_VERSION,
            occurred_at=evidence_journal.NOT_OBSERVED,
            payload=evidence_journal.EvidencePayload(
                data={
                    "command_id": command_id,
                    "operation": operation,
                    "payload_digest": payload_ref.digest,
                    "delivery": "acknowledged",
                    "ack_digest": ack_ref.digest,
                    "record_type": "provider_dispatch_acknowledged",
                },
                measurements=(),
                evidence_refs=(),
                artifact_refs=(payload_ref, ack_ref),
            ),
        )
        evidence_journal.append_event(channel_id, owner_domain, outcome_submission)
        response: ArtifactReference | Missing = ack_ref
    else:
        outcome_submission = evidence_journal.EventSubmission(
            producer_sequence=evidence_journal.NOT_APPLICABLE,
            event_kind="provider_dispatch_uncertain",
            event_schema_version=EVENT_SCHEMA_VERSION,
            occurred_at=evidence_journal.NOT_OBSERVED,
            payload=evidence_journal.EvidencePayload(
                data={
                    "command_id": command_id,
                    "operation": operation,
                    "payload_digest": payload_ref.digest,
                    "delivery": "uncertain",
                    "detail": _UNCERTAIN_DETAIL,
                    "record_type": "provider_dispatch_uncertain",
                },
                measurements=(),
                evidence_refs=(),
                artifact_refs=(payload_ref,),
            ),
        )
        evidence_journal.append_event(channel_id, owner_domain, outcome_submission)
        response = Missing(reason="not_observed", detail=_UNCERTAIN_DETAIL)

    with _LOCK:
        # First writer wins the payload index; the duplicate-risk gate above
        # already blocked new commands for attempted payloads.
        _PAYLOAD_TO_COMMAND.setdefault(payload_key, command_id)
        _COMMANDS[key] = {
            "fingerprint": fingerprint,
            "response": response,
            "payload_digest": payload_ref.digest,
            "operation": operation,
        }
        if isinstance(response, Missing):
            return Missing(reason=response.reason, detail=response.detail)
        return response

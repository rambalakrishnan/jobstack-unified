"""correspondence: private mail observation without fabricated attempt facts (tier 5)."""
from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
import re
import sys
import threading
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any


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
model_gateway = _load_sibling("model_gateway")
provider_effects = _load_sibling("provider_effects")

__all__ = [
    "SCHEMA_VERSION",
    "EVENT_SCHEMA_VERSION",
    "OPERATION_FOLLOWUP",
    "MESSAGE_OBSERVED_EVENT_KIND",
    "HISTORY_GAP_EVENT_KIND",
    "SYNC_COMPLETED_EVENT_KIND",
    "FOLLOWUP_DISPATCHED_EVENT_KIND",
    "EVENT_KINDS",
    "RECORD_TYPE_MESSAGE",
    "RECORD_TYPE_GAP",
    "RECORD_TYPE_SYNC",
    "RECORD_TYPE_FOLLOWUP",
    "Missing",
    "ArtifactReference",
    "EvidenceRef",
    "VersionPin",
    "CorrespondenceError",
    "CorrespondencePayloadError",
    "CorrespondenceAuthorizationError",
    "CorrespondenceAdapterError",
    "CorrespondenceConflictError",
    "CorrespondenceJournalError",
    "CorrespondenceIntegrityError",
    "make_missing",
    "is_missing_envelope",
    "event_kind_declarations",
    "reset_for_tests",
    "stage_mailbox_for_tests",
    "stage_mail_notification_for_tests",
    "observed_messages_for_tests",
    "synchronize_mail",
    "send_followup",
]

SCHEMA_VERSION = "1"
EVENT_SCHEMA_VERSION = "1"
OPERATION_FOLLOWUP = "gmail.send"

MESSAGE_OBSERVED_EVENT_KIND = "mail.message_observed"
HISTORY_GAP_EVENT_KIND = "mail.history_gap"
SYNC_COMPLETED_EVENT_KIND = "mail.sync_completed"
FOLLOWUP_DISPATCHED_EVENT_KIND = "mail.followup_dispatched"

EVENT_KINDS: Mapping[str, str] = {
    MESSAGE_OBSERVED_EVENT_KIND: EVENT_SCHEMA_VERSION,
    HISTORY_GAP_EVENT_KIND: EVENT_SCHEMA_VERSION,
    SYNC_COMPLETED_EVENT_KIND: EVENT_SCHEMA_VERSION,
    FOLLOWUP_DISPATCHED_EVENT_KIND: EVENT_SCHEMA_VERSION,
}

RECORD_TYPE_MESSAGE = "mail_message_observation"
RECORD_TYPE_GAP = "mail_history_gap"
RECORD_TYPE_SYNC = "mail_sync_report"
RECORD_TYPE_FOLLOWUP = "mail_followup_dispatched"

Missing = contract_codec.Missing
ArtifactReference = artifact_store.ArtifactReference
EvidenceRef = evidence_journal.EvidenceRef
VersionPin = provider_effects.VersionPin

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_CODEC_GATE_SCHEMA = "record/v1"
_CODEC_GATE_KEY = "timing"

_FORBIDDEN_OWNER_AXES = frozenset({"attempt.application", "attempt.report"})

_COMPANY_TITLE_DETAIL = (
    "company/title similarity alone cannot bind an email to an attempt; "
    "classification is not origin verification"
)
_NO_ATTEMPT_DETAIL = (
    "no automatic attempt fact created from email similarity or classification; "
    "only independently verified and correlated receipt semantics may affect "
    "the application axis"
)
_HISTORY_GAP_DEFAULT = (
    "provider history gap: mailbox history is incomplete; explicit "
    "resynchronization evidence recorded, completeness not observed"
)
_NOTIFICATION_DETAIL = (
    "notifications trigger retrieval; they are not themselves complete "
    "message evidence"
)
_FOLLOWUP_AUTHORITY_DETAIL = (
    "follow-up requires explicit operation authority, a pinned provider "
    "adapter, an immutable intended payload, durable intent, and actual "
    "acknowledgement evidence; a model action_required label alone never "
    "authorizes dispatch"
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class CorrespondenceError(Exception):
    """Base class for correspondence rejections and integrity failures."""


class CorrespondencePayloadError(CorrespondenceError, ValueError):
    """A mailbox, message, or follow-up payload is missing or invalid."""


class CorrespondenceAuthorizationError(CorrespondenceError, PermissionError):
    """Explicit operation authority is missing or the channel is not allowed."""


class CorrespondenceAdapterError(CorrespondenceError, ValueError):
    """The pinned provider adapter is missing, malformed, or unretained."""


class CorrespondenceConflictError(CorrespondenceError, ValueError):
    """A stable command identity was reused with changed content."""


class CorrespondenceJournalError(CorrespondenceError):
    """A mail observation could not be retained or journaled."""


class CorrespondenceIntegrityError(CorrespondenceError):
    """Conflicting content claimed one provider message identity."""


# ---------------------------------------------------------------------------
# Missing + codec helpers
# ---------------------------------------------------------------------------


def make_missing(reason: str, detail: str | None = None) -> Missing:
    """Create a typed ``K.Missing`` envelope (never an in-band null)."""
    return contract_codec.make_missing(reason, detail)


def is_missing_envelope(value: Any) -> bool:
    """Return True for any kernel Missing envelope (mapping or dataclass)."""
    if isinstance(value, Mapping):
        try:
            return bool(contract_codec.is_missing_envelope(value))
        except Exception:
            return False
    if isinstance(value, provider_effects.Missing):
        return True
    return False


def _require_identifier(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field} must be a string, not {type(value).__name__}")
    if not value:
        raise ValueError(f"{field} must be a nonempty identifier")
    if "\x00" in value:
        raise ValueError(f"{field} must not contain NUL bytes")
    if len(value) > 256:
        raise ValueError(f"{field} exceeds the 256-character identifier bound")
    return value


def _require_digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.match(value):
        raise ValueError(f"{field} must be a sha256:<64 lowercase hex> digest")
    return value


def _canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _codec_gate(obj: Mapping[str, Any], field_name: str) -> None:
    """Reject bare nulls, duplicate keys, and nonfinite numbers (strict JSON)."""
    try:
        contract_codec.validate_record(
            _canonical_json_bytes(
                {"id": f"correspondence_{field_name}", _CODEC_GATE_KEY: dict(obj)}
            ),
            _CODEC_GATE_SCHEMA,
        )
    except (ValueError, TypeError) as exc:
        raise CorrespondencePayloadError(
            f"invalid {field_name} record (bare nulls and nonfinite numbers "
            f"rejected; missingness must use typed Missing): {exc}"
        ) from exc


def _parse_strict_object(raw: bytes, field_name: str) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CorrespondencePayloadError(
            f"{field_name} is not valid UTF-8: {exc}"
        ) from exc

    def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        obj: dict[str, Any] = {}
        for key, val in pairs:
            if key in obj:
                raise ValueError(f"duplicate mapping key: {key!r}")
            obj[key] = val
        return obj

    def _reject_nonfinite(token: str) -> Any:
        raise ValueError(f"nonfinite number literal rejected: {token!r}")

    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_nonfinite,
        )
    except (json.JSONDecodeError, ValueError) as exc:
        raise CorrespondencePayloadError(f"invalid {field_name} JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise CorrespondencePayloadError(f"{field_name} must be a JSON object")
    import math

    stack: list[Any] = [value]
    while stack:
        node = stack.pop()
        if isinstance(node, float):
            if not math.isfinite(node):
                raise CorrespondencePayloadError(
                    f"nonfinite number rejected in {field_name}"
                )
        elif isinstance(node, dict):
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return value


def _coerce_artifact_ref(value: Any, field_name: str) -> Any:
    if isinstance(value, artifact_store.ArtifactReference):
        return value
    if isinstance(value, Mapping):
        try:
            return artifact_store.ArtifactReference(
                digest=value["digest"],
                size_bytes=value["size_bytes"],
                media_type=value["media_type"],
                owner_domain=value["owner_domain"],
                access=value["access"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise CorrespondencePayloadError(
                f"{field_name} must be an ArtifactReference: {exc}"
            ) from exc
    raise CorrespondencePayloadError(
        f"{field_name} must be an ArtifactReference, not {type(value).__name__}"
    )


def _coerce_version_pin(value: Any, field_name: str) -> Any:
    if isinstance(value, provider_effects.VersionPin):
        return value
    if isinstance(value, Mapping):
        try:
            return provider_effects.VersionPin(
                id=value["id"],
                version=value["version"],
                artifact_digest=value["artifact_digest"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise CorrespondencePayloadError(
                f"{field_name} must be a VersionPin: {exc}"
            ) from exc
    raise CorrespondencePayloadError(
        f"{field_name} must be a VersionPin, not {type(value).__name__}"
    )


def _coerce_evidence_ref(value: Any, field_name: str) -> Any:
    if isinstance(value, evidence_journal.EvidenceRef):
        return value
    if isinstance(value, Mapping):
        try:
            return evidence_journal.EvidenceRef.from_dict(value)
        except (TypeError, ValueError) as exc:
            raise CorrespondencePayloadError(
                f"{field_name} must be an EvidenceRef: {exc}"
            ) from exc
    raise CorrespondencePayloadError(
        f"{field_name} must be an EvidenceRef, not {type(value).__name__}"
    )


def _fingerprint(
    operation: str,
    payload_ref: Any,
    adapter_pin: Any,
    auth_refs: tuple[Any, ...],
) -> str:
    body = {
        "operation": operation,
        "payload_digest": payload_ref.digest,
        "adapter_id": adapter_pin.id,
        "adapter_version": adapter_pin.version,
        "adapter_digest": adapter_pin.artifact_digest,
        "authorizations": [
            f"{ref.journal_id}:{ref.sequence}:{ref.event_id}:{ref.event_hash}:{ref.pointer}"
            for ref in auth_refs
        ],
    }
    return "sha256:" + hashlib.sha256(_canonical_json_bytes(body)).hexdigest()


def event_kind_declarations() -> tuple[dict[str, Any], ...]:
    """Manifest event-registry entries for every kind this module writes."""
    return tuple(
        {
            "event_kind": kind,
            "event_schema_version": version,
            "role": "lifecycle_observation",
            "assertion_kind": "observation",
            "owner_domain": "",
            "writer_roles": ["kernel"],
        }
        for kind, version in EVENT_KINDS.items()
    )


# ---------------------------------------------------------------------------
# Module-local state (staged provider transport + idempotency for tests)
# ---------------------------------------------------------------------------

_LOCK = threading.RLock()
_MAILBOXES: dict[tuple[str, str], dict[str, Any]] = {}
_NOTIFICATIONS: dict[tuple[str, str], list[dict[str, Any]]] = {}
_OBSERVED: dict[tuple[str, str, str, str], dict[str, Any]] = {}
_COMMANDS: dict[tuple[str, str], dict[str, Any]] = {}


def reset_for_tests() -> None:
    """Clear staged mailboxes, notifications, observations, and commands."""
    with _LOCK:
        _MAILBOXES.clear()
        _NOTIFICATIONS.clear()
        _OBSERVED.clear()
        _COMMANDS.clear()


def _normalize_message_for_staging(raw: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise CorrespondencePayloadError("staged message must be a mapping")
    try:
        provider_id = _require_identifier(raw.get("provider_id"), "provider_id")
        message_id = _require_identifier(raw.get("message_id"), "message_id")
    except (TypeError, ValueError) as exc:
        raise CorrespondencePayloadError(f"invalid staged message identity: {exc}") from exc
    thread_raw = raw.get("thread_id")
    if thread_raw is None:
        thread_id = f"thread_{message_id}"
    else:
        try:
            thread_id = _require_identifier(thread_raw, "thread_id")
        except (TypeError, ValueError) as exc:
            raise CorrespondencePayloadError(
                f"invalid staged thread identity: {exc}"
            ) from exc
    payload = raw.get("raw_bytes", raw.get("raw", raw.get("raw_text")))
    if isinstance(payload, str):
        raw_bytes = payload.encode("utf-8")
    elif isinstance(payload, (bytes, bytearray)):
        raw_bytes = bytes(payload)
    elif payload is None:
        # Deterministic fallback bytes preserve identity when tests stage only
        # metadata; real adapter bytes always arrive as message/rfc822.
        raw_bytes = _canonical_json_bytes(
            {"provider_id": provider_id, "message_id": message_id, "thread_id": thread_id}
        )
    else:
        raise CorrespondencePayloadError(
            "staged message raw bytes must be bytes or str"
        )
    if b"\x00" in raw_bytes:
        raise CorrespondencePayloadError("staged message bytes must not contain NUL")
    category = raw.get("category", "ambiguous")
    if not isinstance(category, str) or not category:
        raise CorrespondencePayloadError("staged message category must be nonempty")
    company = raw.get("company_match")
    if company is not None and not isinstance(company, str):
        raise CorrespondencePayloadError("staged company_match must be a string")
    title = raw.get("title_match")
    if title is not None and not isinstance(title, str):
        raise CorrespondencePayloadError("staged title_match must be a string")
    action_required = raw.get("action_required", False)
    if not isinstance(action_required, bool):
        raise CorrespondencePayloadError("staged action_required must be a bool")
    return {
        "provider_id": provider_id,
        "message_id": message_id,
        "thread_id": thread_id,
        "raw_bytes": raw_bytes,
        "category": category,
        "company_match": company,
        "title_match": title,
        "action_required": action_required,
    }


def stage_mailbox_for_tests(
    owner_domain: str,
    mailbox_id: str,
    messages: Sequence[Mapping[str, Any]] | None = None,
    *,
    history_complete: bool = True,
    history_gap_detail: str | None = None,
    classification_version: str = "classifier/1",
) -> None:
    """Stage one provider mailbox view for the next ``synchronize_mail`` call."""
    _require_identifier(owner_domain, "owner_domain")
    _require_identifier(mailbox_id, "mailbox_id")
    if type(history_complete) is not bool:
        raise CorrespondencePayloadError("history_complete must be a bool")
    if history_gap_detail is not None:
        if not isinstance(history_gap_detail, str) or not history_gap_detail:
            raise CorrespondencePayloadError(
                "history_gap_detail must be a nonempty string"
            )
    _require_identifier(classification_version, "classification_version")
    normalized: list[dict[str, Any]] = []
    for entry in list(messages or []):
        normalized.append(_normalize_message_for_staging(entry))
    with _LOCK:
        _MAILBOXES[(owner_domain, mailbox_id)] = {
            "messages": normalized,
            "history_complete": history_complete,
            "history_gap_detail": history_gap_detail,
            "classification_version": classification_version,
        }


def stage_mail_notification_for_tests(
    owner_domain: str, mailbox_id: str, notification: Mapping[str, Any]
) -> None:
    """Queue one watch notification; retrieval still requires mailbox bytes."""
    _require_identifier(owner_domain, "owner_domain")
    _require_identifier(mailbox_id, "mailbox_id")
    if not isinstance(notification, Mapping):
        raise CorrespondencePayloadError("notification must be a mapping")
    try:
        provider_id = _require_identifier(
            notification.get("provider_id"), "notification.provider_id"
        )
        message_id = _require_identifier(
            notification.get("message_id"), "notification.message_id"
        )
    except (TypeError, ValueError) as exc:
        raise CorrespondencePayloadError(
            f"invalid notification identity: {exc}"
        ) from exc
    entry: dict[str, Any] = {"provider_id": provider_id, "message_id": message_id}
    carried = notification.get("message")
    if carried is not None:
        if not isinstance(carried, Mapping):
            raise CorrespondencePayloadError("notification.message must be a mapping")
        entry["message"] = _normalize_message_for_staging(carried)
    with _LOCK:
        _NOTIFICATIONS.setdefault((owner_domain, mailbox_id), []).append(entry)


def observed_messages_for_tests(
    owner_domain: str, mailbox_id: str
) -> tuple[dict[str, Any], ...]:
    """Return the deduplicated provider identities observed so far."""
    with _LOCK:
        return tuple(
            {
                "provider_id": key[2],
                "message_id": key[3],
                "digest": value["digest"],
                "thread_id": value["thread_id"],
            }
            for key, value in sorted(_OBSERVED.items())
            if key[0] == owner_domain and key[1] == mailbox_id
        )


async def _classify_via_model_for_tests(
    channel_id: str,
    owner_domain: str,
    message_ref: Any,
    classification_version: str,
) -> dict[str, Any]:
    """Optional model-backed classification path (unused by conformance).

    When mailbox staging carries explicit model pins, classification runs
    through :func:`model_gateway.invoke_model` with retained prompt/input
    evidence.  The default conformance path keeps the staged provider
    classification version without a live model call; either way the result
    is a versioned assessment, never origin verification.
    """
    with _LOCK:
        pins: dict[str, Any] | None = None
        for staged in _MAILBOXES.values():
            candidate = staged.get("model_pins")
            if isinstance(candidate, dict):
                pins = candidate
                break
    if pins is None:
        return {
            "classification_version": classification_version,
            "via_model": False,
            "category": make_missing("not_observed"),
        }
    policy = pins["policy"]
    prompt = pins["prompt"]
    output_schema = pins["output_schema"]
    call_id = str(pins.get("call_id", f"classify_{message_ref.digest[:16]}"))
    record_ref = await model_gateway.invoke_model(
        channel_id, call_id, policy, prompt, (message_ref,), output_schema
    )
    record_bytes = artifact_store.resolve_artifact(channel_id, record_ref)
    record = _parse_strict_object(record_bytes, "classification_record")
    return {
        "classification_version": classification_version,
        "via_model": True,
        "record_digest": record_ref.digest,
        "record": record,
    }


# ---------------------------------------------------------------------------
# synchronize_mail
# ---------------------------------------------------------------------------


async def synchronize_mail(
    channel_id: str, mailbox_id: str, adapter: VersionPin
) -> ArtifactReference:
    """Observe one mailbox window without inventing attempt facts.

    Retains mailbox identity, message identity, raw bytes, provider
    metadata, ingestion evidence, and classification version.  Company or
    title similarity alone never binds a message to an attempt.  History
    gaps journal explicit incomplete observations.  Duplicate notifications
    deduplicate by provider/message identity.
    """
    try:
        _require_identifier(channel_id, "channel_id")
        _require_identifier(mailbox_id, "mailbox_id")
    except (TypeError, ValueError) as exc:
        raise CorrespondencePayloadError(f"invalid mail identity: {exc}") from exc

    adapter_pin = _coerce_version_pin(adapter, "adapter")
    try:
        _require_identifier(adapter_pin.id, "adapter.id")
        _require_identifier(adapter_pin.version, "adapter.version")
        _require_digest(adapter_pin.artifact_digest, "adapter.artifact_digest")
    except (TypeError, ValueError) as exc:
        raise CorrespondenceAdapterError(f"invalid adapter pin: {exc}") from exc

    try:
        projection = access_policy.channel_projection(channel_id)
    except access_policy.AuthorizationError as exc:
        raise CorrespondenceAuthorizationError(
            f"unknown channel {channel_id!r}; mail sync requires an authenticated "
            f"ingress session: {exc}"
        ) from exc
    owner_domain = projection.get("axis")
    try:
        _require_identifier(owner_domain, "owner_domain")
    except (TypeError, ValueError) as exc:
        raise CorrespondencePayloadError(
            f"invalid channel owner domain: {exc}"
        ) from exc
    assert isinstance(owner_domain, str)
    if owner_domain in _FORBIDDEN_OWNER_AXES:
        raise CorrespondenceAuthorizationError(
            "correspondence never writes the application or report axes; "
            f"refusing owner domain {owner_domain!r}"
        )
    grants = list(projection.get("grants", []))
    if not grants:
        raise CorrespondenceAuthorizationError(
            f"authenticated channel holds no write grant for {owner_domain!r}"
        )
    try:
        access_policy.authorize(channel_id, grants[0], mailbox_id)
    except access_policy.AuthorizationError as exc:
        raise CorrespondenceAuthorizationError(str(exc)) from exc

    try:
        known_digests = artifact_store.known_digests()
    except AttributeError:  # pragma: no cover - older sibling without index
        known_digests = frozenset()
    if known_digests and adapter_pin.artifact_digest not in known_digests:
        raise CorrespondenceAdapterError(
            f"adapter artifact {adapter_pin.artifact_digest} is not a retained, "
            "pinned provider-adapter artifact; adapter semantics must be pinned "
            "before sync"
        )

    with _LOCK:
        staged = _MAILBOXES.get(
            (owner_domain, mailbox_id),
            {
                "messages": [],
                "history_complete": True,
                "history_gap_detail": None,
                "classification_version": "classifier/1",
            },
        )
        mailbox_messages = list(staged.get("messages", []))
        history_complete = bool(staged.get("history_complete", True))
        gap_detail = staged.get("history_gap_detail") or _HISTORY_GAP_DEFAULT
        classification_version = str(
            staged.get("classification_version", "classifier/1")
        )
        pending = list(_NOTIFICATIONS.get((owner_domain, mailbox_id), []))
        if (owner_domain, mailbox_id) in _NOTIFICATIONS:
            _NOTIFICATIONS[(owner_domain, mailbox_id)] = []

    by_key = {
        (m["provider_id"], m["message_id"]): m for m in mailbox_messages
    }
    candidates: list[dict[str, Any]] = list(mailbox_messages)
    for notification in pending:
        carried = notification.get("message")
        if isinstance(carried, dict):
            candidates.append(carried)
            continue
        found = by_key.get(
            (notification["provider_id"], notification["message_id"])
        )
        if found is not None:
            candidates.append(found)
        # A notification without retrievable bytes contributes no message
        # evidence at all: it is a retrieval trigger, not a receipt.

    newly_observed: list[dict[str, Any]] = []
    deduplicated = 0
    message_refs: list[Any] = []
    observation_refs: list[Any] = []

    for message in candidates:
        provider_id = message["provider_id"]
        message_id = message["message_id"]
        thread_id = message.get("thread_id") or f"thread_{message_id}"
        raw_bytes = message["raw_bytes"]
        digest = "sha256:" + hashlib.sha256(raw_bytes).hexdigest()
        key = (owner_domain, mailbox_id, provider_id, message_id)
        with _LOCK:
            previous = _OBSERVED.get(key)
        if previous is not None:
            if previous["digest"] != digest:
                raise CorrespondenceIntegrityError(
                    f"conflicting content under provider identity "
                    f"({provider_id!r},{message_id!r}): acknowledged digest "
                    f"{previous['digest']} differs from redelivered digest "
                    f"{digest}; integrity incident, not last-write-wins"
                )
            deduplicated += 1
            continue
        try:
            message_ref = artifact_store.retain_artifact(
                channel_id, owner_domain, "message/rfc822", raw_bytes, "restricted"
            )
        except artifact_store.ArtifactError as exc:
            raise CorrespondenceJournalError(
                f"cannot durably retain message bytes for {message_id!r}: {exc}"
            ) from exc
        category = message.get("category") or "ambiguous"
        company_raw = message.get("company_match")
        title_raw = message.get("title_match")
        if isinstance(company_raw, str) and company_raw:
            company_value: Any = company_raw
        else:
            company_value = make_missing(
                "not_observed", "no candidate employer match extracted"
            )
        if isinstance(title_raw, str) and title_raw:
            title_value: Any = title_raw
        else:
            title_value = make_missing(
                "not_observed", "no candidate job match extracted"
            )
        action_required = bool(message.get("action_required", False))
        observation_data: dict[str, Any] = {
            "record_type": RECORD_TYPE_MESSAGE,
            "mailbox_id": mailbox_id,
            "provider_id": provider_id,
            "message_id": message_id,
            "thread_id": thread_id,
            "message_digest": message_ref.digest,
            "message_size": message_ref.size_bytes,
            "category": category,
            "classification_version": classification_version,
            "company_match": company_value,
            "title_match": title_value,
            "action_required": action_required,
            "attempt_binding": make_missing("not_observed", _COMPANY_TITLE_DETAIL),
            "attempt_fact": make_missing("not_observed", _NO_ATTEMPT_DETAIL),
            "summary": make_missing(
                "not_observed",
                "derived summary requires retained message bytes; "
                "classification alone is not evidence",
            ),
            "adapter_id": adapter_pin.id,
            "adapter_version": adapter_pin.version,
            "adapter_digest": adapter_pin.artifact_digest,
            "notification_note": _NOTIFICATION_DETAIL,
            "detail": (
                "retained mailbox identity, message identity, raw bytes, "
                "provider metadata, ingestion evidence, and classification "
                "version"
            ),
        }
        _codec_gate(observation_data, "message_observation")
        try:
            observation_ref = artifact_store.retain_artifact(
                channel_id,
                owner_domain,
                "application/json",
                _canonical_json_bytes(observation_data),
                "restricted",
            )
        except artifact_store.ArtifactError as exc:
            raise CorrespondenceJournalError(
                f"cannot durably retain message observation for {message_id!r}: {exc}"
            ) from exc
        submission = evidence_journal.EventSubmission(
            producer_sequence=evidence_journal.NOT_APPLICABLE,
            event_kind=MESSAGE_OBSERVED_EVENT_KIND,
            event_schema_version=EVENT_SCHEMA_VERSION,
            occurred_at=evidence_journal.NOT_OBSERVED,
            payload=evidence_journal.EvidencePayload(
                data=dict(observation_data),
                measurements=(),
                evidence_refs=(),
                artifact_refs=(message_ref, observation_ref),
            ),
        )
        try:
            evidence_journal.append_event(channel_id, owner_domain, submission)
        except Exception as exc:
            raise CorrespondenceJournalError(
                f"cannot journal message observation for {message_id!r}: {exc}"
            ) from exc
        with _LOCK:
            _OBSERVED[key] = {
                "digest": digest,
                "thread_id": thread_id,
                "message_ref": message_ref,
                "observation_ref": observation_ref,
            }
        newly_observed.append(
            {
                "provider_id": provider_id,
                "message_id": message_id,
                "thread_id": thread_id,
                "digest": message_ref.digest,
                "size_bytes": message_ref.size_bytes,
                "category": category,
                "company_match": company_value,
                "title_match": title_value,
                "action_required": action_required,
                "attempt_binding": make_missing("not_observed", _COMPANY_TITLE_DETAIL),
            }
        )
        message_refs.append(message_ref)
        observation_refs.append(observation_ref)

    gap_ref: Any | None = None
    if not history_complete:
        gap_data: dict[str, Any] = {
            "record_type": RECORD_TYPE_GAP,
            "mailbox_id": mailbox_id,
            "history_completeness": make_missing("not_observed", gap_detail),
            "history_gap": {"status": "gap", "detail": gap_detail},
            "resynchronization_required": True,
            "observed_count": len(newly_observed),
            "adapter_id": adapter_pin.id,
            "adapter_version": adapter_pin.version,
            "adapter_digest": adapter_pin.artifact_digest,
            "detail": (
                "history gap causes explicit resynchronization evidence, "
                "not assumed completeness"
            ),
        }
        _codec_gate(gap_data, "history_gap")
        try:
            gap_ref = artifact_store.retain_artifact(
                channel_id,
                owner_domain,
                "application/json",
                _canonical_json_bytes(gap_data),
                "restricted",
            )
        except artifact_store.ArtifactError as exc:
            raise CorrespondenceJournalError(
                f"cannot durably retain history-gap evidence for {mailbox_id!r}: {exc}"
            ) from exc
        gap_submission = evidence_journal.EventSubmission(
            producer_sequence=evidence_journal.NOT_APPLICABLE,
            event_kind=HISTORY_GAP_EVENT_KIND,
            event_schema_version=EVENT_SCHEMA_VERSION,
            occurred_at=evidence_journal.NOT_OBSERVED,
            payload=evidence_journal.EvidencePayload(
                data=dict(gap_data),
                measurements=(),
                evidence_refs=(),
                artifact_refs=(gap_ref,),
            ),
        )
        try:
            evidence_journal.append_event(channel_id, owner_domain, gap_submission)
        except Exception as exc:
            raise CorrespondenceJournalError(
                f"cannot journal history gap for {mailbox_id!r}: {exc}"
            ) from exc
        completeness: Any = make_missing("not_observed", gap_detail)
        gap_for_report: Any = {"status": "gap", "detail": gap_detail}
    else:
        completeness = "complete"
        gap_for_report = make_missing(
            "not_applicable",
            "no history gap observed in this sync window",
        )

    report_messages: list[dict[str, Any]] = []
    for entry in newly_observed:
        report_messages.append(
            {
                "provider_id": entry["provider_id"],
                "message_id": entry["message_id"],
                "thread_id": entry["thread_id"],
                "digest": entry["digest"],
                "size_bytes": entry["size_bytes"],
                "category": entry["category"],
                "classification_version": classification_version,
                "company_match": entry["company_match"],
                "title_match": entry["title_match"],
                "action_required": entry["action_required"],
                "attempt_binding": make_missing("not_observed", _COMPANY_TITLE_DETAIL),
            }
        )
    report_data: dict[str, Any] = {
        "record_type": RECORD_TYPE_SYNC,
        "mailbox_id": mailbox_id,
        "owner_domain": owner_domain,
        "adapter_id": adapter_pin.id,
        "adapter_version": adapter_pin.version,
        "adapter_digest": adapter_pin.artifact_digest,
        "classification_version": classification_version,
        "messages": report_messages,
        "observed_count": len(newly_observed),
        "deduplicated_count": deduplicated,
        "total_candidates": len(candidates),
        "history_completeness": completeness,
        "history_gap": gap_for_report,
        "attempt_facts_created": 0,
        "attempt_fact": make_missing("not_observed", _NO_ATTEMPT_DETAIL),
        "detail": (
            "mailbox sync observation; classification and company/title "
            "similarity never create application attempt facts"
        ),
    }
    _codec_gate(report_data, "sync_report")
    try:
        report_ref = artifact_store.retain_artifact(
            channel_id,
            owner_domain,
            "application/json",
            _canonical_json_bytes(report_data),
            "restricted",
        )
    except artifact_store.ArtifactError as exc:
        raise CorrespondenceJournalError(
            f"cannot durably retain sync report for {mailbox_id!r}: {exc}"
        ) from exc
    sync_refs: list[Any] = list(message_refs) + list(observation_refs)
    if gap_ref is not None:
        sync_refs.append(gap_ref)
    sync_refs.append(report_ref)
    sync_submission = evidence_journal.EventSubmission(
        producer_sequence=evidence_journal.NOT_APPLICABLE,
        event_kind=SYNC_COMPLETED_EVENT_KIND,
        event_schema_version=EVENT_SCHEMA_VERSION,
        occurred_at=evidence_journal.NOT_OBSERVED,
        payload=evidence_journal.EvidencePayload(
            data=dict(report_data),
            measurements=(),
            evidence_refs=(),
            artifact_refs=tuple(sync_refs),
        ),
    )
    try:
        evidence_journal.append_event(channel_id, owner_domain, sync_submission)
    except Exception as exc:
        raise CorrespondenceJournalError(
            f"cannot journal sync completion for {mailbox_id!r}: {exc}"
        ) from exc
    return report_ref


# ---------------------------------------------------------------------------
# send_followup
# ---------------------------------------------------------------------------


def _validate_followup_payload(event_obj: dict[str, Any]) -> dict[str, Any]:
    allowed = {
        "recipient",
        "subject",
        "body",
        "thread_id",
        "in_reply_to",
        "action_required",
    }
    extra = set(event_obj.keys()) - allowed
    if extra:
        raise CorrespondencePayloadError(
            f"undeclared follow-up properties: {sorted(extra)}"
        )
    for field in ("recipient", "subject", "body"):
        value = event_obj.get(field)
        if not isinstance(value, str) or not value:
            raise CorrespondencePayloadError(
                f"follow-up {field} must be a nonempty string; a model "
                "action_required label alone never authorizes dispatch"
            )
        if "\x00" in value:
            raise CorrespondencePayloadError(f"follow-up {field} must not contain NUL")
    thread_id = event_obj.get("thread_id")
    if thread_id is not None and (not isinstance(thread_id, str) or not thread_id):
        raise CorrespondencePayloadError("follow-up thread_id must be a nonempty string")
    in_reply_to = event_obj.get("in_reply_to")
    if in_reply_to is not None and (
        not isinstance(in_reply_to, str) or not in_reply_to
    ):
        raise CorrespondencePayloadError(
            "follow-up in_reply_to must be a nonempty string"
        )
    action_required = event_obj.get("action_required", False)
    if not isinstance(action_required, bool):
        raise CorrespondencePayloadError("follow-up action_required must be a bool")
    return {
        "recipient": event_obj["recipient"],
        "subject": event_obj["subject"],
        "body": event_obj["body"],
        "thread_id": thread_id,
        "in_reply_to": in_reply_to,
        "action_required": action_required,
    }


async def send_followup(
    channel_id: str,
    command_id: str,
    payload: ArtifactReference,
    adapter: VersionPin,
    authorization_refs: tuple[EvidenceRef, ...],
) -> ArtifactReference | Missing:
    """Send one explicitly authorized follow-up email.

    Requires explicit operation authority, a pinned adapter, an immutable
    intended payload, durable intent, and actual acknowledgement evidence.
    A model ``action_required`` label alone never authorizes dispatch, and
    an uncertain delivery is returned as explicit ``Missing``.
    """
    try:
        _require_identifier(channel_id, "channel_id")
        _require_identifier(command_id, "command_id")
    except (TypeError, ValueError) as exc:
        raise CorrespondencePayloadError(f"invalid follow-up identity: {exc}") from exc

    payload_ref = _coerce_artifact_ref(payload, "payload")
    adapter_pin = _coerce_version_pin(adapter, "adapter")
    try:
        _require_identifier(adapter_pin.id, "adapter.id")
        _require_identifier(adapter_pin.version, "adapter.version")
        _require_digest(adapter_pin.artifact_digest, "adapter.artifact_digest")
    except (TypeError, ValueError) as exc:
        raise CorrespondenceAdapterError(f"invalid adapter pin: {exc}") from exc

    if not isinstance(authorization_refs, (tuple, list)) or not authorization_refs:
        raise CorrespondenceAuthorizationError(
            "explicit operation authority requires at least one EvidenceRef; "
            "a model action_required label alone never authorizes dispatch"
        )
    auth_refs = tuple(
        _coerce_evidence_ref(ref, f"authorization_refs[{index}]")
        for index, ref in enumerate(authorization_refs)
    )

    owner_domain = payload_ref.owner_domain
    try:
        _require_identifier(owner_domain, "owner_domain")
    except (TypeError, ValueError) as exc:
        raise CorrespondencePayloadError(
            f"invalid payload owner domain: {exc}"
        ) from exc
    if owner_domain in _FORBIDDEN_OWNER_AXES:
        raise CorrespondenceAuthorizationError(
            "correspondence never writes the application or report axes"
        )

    try:
        projection = access_policy.channel_projection(channel_id)
    except access_policy.AuthorizationError as exc:
        raise CorrespondenceAuthorizationError(
            f"unknown channel {channel_id!r}: {exc}"
        ) from exc
    if projection.get("axis") != owner_domain:
        raise CorrespondenceAuthorizationError(
            f"owner-local write required: channel axis {projection.get('axis')!r} "
            f"cannot write owner domain {owner_domain!r}"
        )
    grants = list(projection.get("grants", []))
    if not grants:
        raise CorrespondenceAuthorizationError(
            f"authenticated channel holds no write grant for {owner_domain!r}"
        )
    try:
        access_policy.authorize(channel_id, grants[0], command_id)
    except access_policy.AuthorizationError as exc:
        raise CorrespondenceAuthorizationError(str(exc)) from exc

    fingerprint = _fingerprint(OPERATION_FOLLOWUP, payload_ref, adapter_pin, auth_refs)
    key = (owner_domain, command_id)
    with _LOCK:
        existing = _COMMANDS.get(key)
        if existing is not None:
            if existing["fingerprint"] != fingerprint:
                raise CorrespondenceConflictError(
                    f"command {command_id!r} reused with changed content; "
                    "local command identity is stable"
                )
            stored = existing["response"]
            if isinstance(stored, dict):
                return dict(stored)
            return stored

    try:
        payload_bytes = artifact_store.resolve_artifact(channel_id, payload_ref)
    except artifact_store.ArtifactError as exc:
        raise CorrespondencePayloadError(
            f"follow-up payload {payload_ref.digest} is not resolvable: {exc}"
        ) from exc
    payload_obj = _parse_strict_object(payload_bytes, "payload")
    _codec_gate(payload_obj, "payload")
    parsed = _validate_followup_payload(payload_obj)

    provider_response = await provider_effects.execute_provider_effect(
        channel_id, command_id, OPERATION_FOLLOWUP, payload_ref, adapter_pin, auth_refs
    )

    if isinstance(provider_response, provider_effects.Missing):
        uncertain_data: dict[str, Any] = {
            "record_type": RECORD_TYPE_FOLLOWUP,
            "command_id": command_id,
            "operation": OPERATION_FOLLOWUP,
            "recipient": parsed["recipient"],
            "subject": parsed["subject"],
            "thread_id": parsed["thread_id"]
            if parsed["thread_id"] is not None
            else make_missing("not_applicable"),
            "in_reply_to": parsed["in_reply_to"]
            if parsed["in_reply_to"] is not None
            else make_missing("not_applicable"),
            "delivery": "uncertain",
            "ack_digest": make_missing("not_observed"),
            "provider_message_id": make_missing("not_observed"),
            "authorization_count": len(auth_refs),
            "detail": (provider_response.detail or "uncertain delivery")
            + "; "
            + _FOLLOWUP_AUTHORITY_DETAIL,
        }
        _codec_gate(uncertain_data, "uncertain_followup")
        try:
            uncertain_ref = artifact_store.retain_artifact(
                channel_id,
                owner_domain,
                "application/json",
                _canonical_json_bytes(uncertain_data),
                payload_ref.access,
            )
        except artifact_store.ArtifactError as exc:
            raise CorrespondenceJournalError(
                f"cannot durably retain uncertain follow-up outcome for "
                f"{command_id!r}: {exc}"
            ) from exc
        submission = evidence_journal.EventSubmission(
            producer_sequence=evidence_journal.NOT_APPLICABLE,
            event_kind=FOLLOWUP_DISPATCHED_EVENT_KIND,
            event_schema_version=EVENT_SCHEMA_VERSION,
            occurred_at=evidence_journal.NOT_OBSERVED,
            payload=evidence_journal.EvidencePayload(
                data=dict(uncertain_data),
                measurements=(),
                evidence_refs=(),
                artifact_refs=(payload_ref, uncertain_ref),
            ),
        )
        try:
            evidence_journal.append_event(channel_id, owner_domain, submission)
        except Exception as exc:
            raise CorrespondenceJournalError(
                f"cannot journal uncertain follow-up outcome for {command_id!r}: {exc}"
            ) from exc
        response: Any = make_missing(
            provider_response.reason, provider_response.detail
        )
        with _LOCK:
            _COMMANDS[key] = {"fingerprint": fingerprint, "response": dict(response)}
        return dict(response)

    ack_ref = _coerce_artifact_ref(provider_response, "provider_ack")
    try:
        ack_bytes = artifact_store.resolve_artifact(channel_id, ack_ref)
    except artifact_store.ArtifactError:
        ack_bytes = b""
    provider_message_id: Any = make_missing("not_observed")
    if ack_bytes:
        try:
            ack_doc = _parse_strict_object(ack_bytes, "provider_ack")
            ack_inner = ack_doc.get("ack")
            if isinstance(ack_inner, dict):
                candidate = ack_inner.get(
                    "provider_message_id", ack_inner.get("message_id")
                )
                if isinstance(candidate, str) and candidate:
                    provider_message_id = candidate
        except CorrespondencePayloadError:
            provider_message_id = make_missing("not_observed")
    acknowledged_data: dict[str, Any] = {
        "record_type": RECORD_TYPE_FOLLOWUP,
        "command_id": command_id,
        "operation": OPERATION_FOLLOWUP,
        "recipient": parsed["recipient"],
        "subject": parsed["subject"],
        "thread_id": parsed["thread_id"]
        if parsed["thread_id"] is not None
        else make_missing("not_applicable"),
        "in_reply_to": parsed["in_reply_to"]
        if parsed["in_reply_to"] is not None
        else make_missing("not_applicable"),
        "delivery": "acknowledged",
        "ack_digest": ack_ref.digest,
        "provider_message_id": provider_message_id,
        "authorization_count": len(auth_refs),
        "detail": (
            "follow-up dispatched under explicit operation authority with "
            "actual acknowledgement evidence"
        ),
    }
    _codec_gate(acknowledged_data, "acknowledged_followup")
    try:
        outcome_ref = artifact_store.retain_artifact(
            channel_id,
            owner_domain,
            "application/json",
            _canonical_json_bytes(acknowledged_data),
            payload_ref.access,
        )
    except artifact_store.ArtifactError as exc:
        raise CorrespondenceJournalError(
            f"cannot durably retain acknowledged follow-up outcome for "
            f"{command_id!r}: {exc}"
        ) from exc
    submission = evidence_journal.EventSubmission(
        producer_sequence=evidence_journal.NOT_APPLICABLE,
        event_kind=FOLLOWUP_DISPATCHED_EVENT_KIND,
        event_schema_version=EVENT_SCHEMA_VERSION,
        occurred_at=evidence_journal.NOT_OBSERVED,
        payload=evidence_journal.EvidencePayload(
            data=dict(acknowledged_data),
            measurements=(),
            evidence_refs=(),
            artifact_refs=(payload_ref, ack_ref, outcome_ref),
        ),
    )
    try:
        evidence_journal.append_event(channel_id, owner_domain, submission)
    except Exception as exc:
        raise CorrespondenceJournalError(
            f"cannot journal acknowledged follow-up outcome for {command_id!r}: {exc}"
        ) from exc
    with _LOCK:
        _COMMANDS[key] = {"fingerprint": fingerprint, "response": ack_ref}
    return ack_ref

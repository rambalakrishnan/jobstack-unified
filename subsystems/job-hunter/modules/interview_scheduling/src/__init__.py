"""interview_scheduling: timezone-honest calendar writes without invented attendance (tier 4).

Implements the ``schedules`` seam (``job-hunter-seam-mapping.md`` 16.7 and
17.2) over the authorized provider-effect path:

* ``eventId`` is actual provider event identity, never invented locally.
* ``startTime``/``endTime`` are typed calendar values with actual timezone
  semantics; a missing timezone never becomes an invented instant, UTC
  default, or monotonic observation.
* ``calendarId`` is an authorized provider calendar.
* ``cheatSheetUrl`` is a private resolver output, never durable evidence
  identity; only retained artifact bytes carry document identity.
* A calendar write acknowledgement does not prove interview attendance or
  employer confirmation.  Attendance and confirmation remain
  ``Missing(not_observed)`` unless separate verified evidence arrives
  (this module accepts no such input, so it never fabricates them).
* Calendar create/update, ACL, and free/busy are distinct operations.  This
  module performs only ``calendar.create`` and journals that operation
  explicitly.

Outbound writes delegate to :func:`provider_effects.execute_provider_effect`
so explicit operation authority, pinned adapter semantics, immutable
payloads, stable command identity, durable intent before dispatch, actual
ack evidence, and explicit uncertain delivery are preserved.  This module
adds scheduling-level guards before dispatch and scheduling-level
observations after dispatch, journaled via
:func:`evidence_journal.append_event`.
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
import re
import sys
import threading
from collections.abc import Mapping
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
artifact_store = _load_sibling("artifact_store")
evidence_journal = _load_sibling("evidence_journal")
provider_effects = _load_sibling("provider_effects")

__all__ = [
    "SCHEMA_VERSION",
    "EVENT_SCHEMA_VERSION",
    "OPERATION_CALENDAR_CREATE",
    "REFUSED_EVENT_KIND",
    "DISPATCHED_EVENT_KIND",
    "EVENT_KINDS",
    "Missing",
    "ArtifactReference",
    "EvidenceRef",
    "VersionPin",
    "InterviewSchedulingError",
    "SchedulingPayloadError",
    "SchedulingAuthorizationError",
    "SchedulingConflictError",
    "SchedulingJournalError",
    "make_missing",
    "is_missing_envelope",
    "event_kind_declarations",
    "reset_for_tests",
    "schedule_interview",
]

SCHEMA_VERSION = "1"
EVENT_SCHEMA_VERSION = "1"
OPERATION_CALENDAR_CREATE = "calendar.create"

REFUSED_EVENT_KIND = "interview_schedule_refused"
DISPATCHED_EVENT_KIND = "interview_schedule_dispatched"

#: Every event this module writes.  The composition root registers each kind
#: in the manifest event registry and in the ingress authority before the
#: first scheduling decision.
EVENT_KINDS: Mapping[str, str] = {
    REFUSED_EVENT_KIND: EVENT_SCHEMA_VERSION,
    DISPATCHED_EVENT_KIND: EVENT_SCHEMA_VERSION,
}

RECORD_TYPE_REFUSED = "interview_schedule_refused"
RECORD_TYPE_DISPATCHED = "interview_schedule_dispatched"

#: ``K.Missing`` is a typed envelope mapping (never an in-band null).
Missing = contract_codec.Missing

ArtifactReference = artifact_store.ArtifactReference
EvidenceRef = evidence_journal.EvidenceRef
VersionPin = provider_effects.VersionPin

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_CODEC_GATE_SCHEMA = "record/v1"
_CODEC_GATE_KEY = "timing"

_TOP_LEVEL_FIELDS = frozenset(
    {
        "calendar_id",
        "job_id",
        "start",
        "end",
        "cheat_sheet",
        "cheat_sheet_url",
        "provider_event_id",
        "provider_revision",
    }
)
_REQUIRED_TOP_LEVEL = frozenset({"calendar_id", "job_id", "start", "end"})
_CALENDAR_VALUE_FIELDS = frozenset({"date_time", "timezone", "all_day"})

_TIMEZONE_MISSING_DETAIL = (
    "calendar timezone missing: no instant invented, no UTC default applied, "
    "no monotonic observation derived from future interview business time; "
    "timed calendar values require actual timezone semantics before dispatch"
)
_ACK_NOT_ATTENDANCE_DETAIL = (
    "calendar write acknowledgement records provider delivery only; it does "
    "not prove interview attendance or employer confirmation"
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class InterviewSchedulingError(Exception):
    """Base class for interview-scheduling rejections and integrity failures."""


class SchedulingPayloadError(InterviewSchedulingError, ValueError):
    """The calendar event payload is missing, unreadable, or semantically invalid."""


class SchedulingAuthorizationError(InterviewSchedulingError, PermissionError):
    """Explicit operation authority is missing or the channel is not allowed."""


class SchedulingConflictError(InterviewSchedulingError, ValueError):
    """A stable command identity was reused with changed content."""


class SchedulingJournalError(InterviewSchedulingError):
    """The scheduling observation could not be journaled or retained."""


# ---------------------------------------------------------------------------
# Missing + codec helpers
# ---------------------------------------------------------------------------


def make_missing(reason: str, detail: str | None = None) -> Missing:
    """Create a typed ``K.Missing`` envelope (never an in-band null)."""
    return contract_codec.make_missing(reason, detail)


def is_missing_envelope(value: Any) -> bool:
    """Return True for any kernel Missing envelope (mapping or dataclass)."""
    if isinstance(
        value,
        (
            evidence_journal.Missing,
            provider_effects.Missing,
        ),
    ):
        return True
    try:
        import access_policy as _ap  # type: ignore[import-not-found]

        if isinstance(value, _ap.Missing):
            return True
    except Exception:
        pass
    return contract_codec.is_missing_envelope(value)


def _missing_to_dict(value: Any) -> dict[str, Any] | None:
    """Normalize any kernel Missing envelope to a plain dict, or None."""
    if isinstance(value, (evidence_journal.Missing, provider_effects.Missing)):
        return make_missing(value.reason, value.detail)
    try:
        import access_policy as _ap  # type: ignore[import-not-found]

        if isinstance(value, _ap.Missing):
            return make_missing(value.reason, value.detail)
    except Exception:
        pass
    if isinstance(value, Mapping):
        keys = set(value.keys())
        if "value" in keys and value.get("value") is None and "reason" in keys:
            extra = keys - {"value", "reason", "detail"}
            if extra:
                raise SchedulingPayloadError(
                    f"undeclared Missing property: {sorted(extra)}"
                )
            reason = value.get("reason")
            if reason not in contract_codec.VALID_MISSING_REASONS:
                raise SchedulingPayloadError(
                    f"unknown Missing reason: {reason!r}"
                )
            detail = value.get("detail")
            if detail is not None and (
                not isinstance(detail, str) or not detail
            ):
                raise SchedulingPayloadError(
                    "Missing.detail must be a nonempty string when present"
                )
            return make_missing(str(reason), detail)
    return None


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


def _canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _codec_gate(obj: Mapping[str, Any], field_name: str) -> None:
    """Reject bare nulls, duplicate keys, and nonfinite numbers (strict JSON)."""
    try:
        contract_codec.validate_record(
            _canonical_json_bytes({"id": f"scheduling_{field_name}", _CODEC_GATE_KEY: dict(obj)}),
            _CODEC_GATE_SCHEMA,
        )
    except (ValueError, TypeError) as exc:
        raise SchedulingPayloadError(
            f"invalid {field_name} record (bare nulls and nonfinite numbers "
            f"rejected; missingness must use typed Missing): {exc}"
        ) from exc


def _parse_strict_object(raw: bytes, field_name: str) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SchedulingPayloadError(f"{field_name} is not valid UTF-8: {exc}") from exc

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
        raise SchedulingPayloadError(f"invalid {field_name} JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise SchedulingPayloadError(f"{field_name} must be a JSON object")
    # Overflow literals like 1e1000 decode to inf without parse_constant.
    stack: list[Any] = [value]
    while stack:
        node = stack.pop()
        if isinstance(node, float):
            import math

            if not math.isfinite(node):
                raise SchedulingPayloadError(
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
            raise SchedulingPayloadError(
                f"{field_name} must be an ArtifactReference: {exc}"
            ) from exc
    raise SchedulingPayloadError(
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
            raise SchedulingPayloadError(
                f"{field_name} must be a VersionPin: {exc}"
            ) from exc
    raise SchedulingPayloadError(
        f"{field_name} must be a VersionPin, not {type(value).__name__}"
    )


def _coerce_evidence_ref(value: Any, field_name: str) -> Any:
    if isinstance(value, evidence_journal.EvidenceRef):
        return value
    if isinstance(value, Mapping):
        try:
            return evidence_journal.EvidenceRef.from_dict(value)
        except (TypeError, ValueError) as exc:
            raise SchedulingPayloadError(
                f"{field_name} must be an EvidenceRef: {exc}"
            ) from exc
    raise SchedulingPayloadError(
        f"{field_name} must be an EvidenceRef, not {type(value).__name__}"
    )


def _fingerprint(
    operation: str,
    event_ref: Any,
    adapter_pin: Any,
    auth_refs: tuple[Any, ...],
) -> str:
    body = {
        "operation": operation,
        "payload_digest": event_ref.digest,
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
# Module-local idempotency (stable local command identity)
# ---------------------------------------------------------------------------

_LOCK = threading.RLock()
_COMMANDS: dict[tuple[str, str], dict[str, Any]] = {}


def reset_for_tests() -> None:
    """Clear idempotency records (tests only)."""
    with _LOCK:
        _COMMANDS.clear()


# ---------------------------------------------------------------------------
# Calendar validation (no invented semantics)
# ---------------------------------------------------------------------------


def _validate_calendar_value(raw: Any, field_name: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise SchedulingPayloadError(f"{field_name} must be a typed calendar value object")
    extra = set(raw.keys()) - _CALENDAR_VALUE_FIELDS
    if extra:
        raise SchedulingPayloadError(
            f"{field_name} has undeclared properties: {sorted(extra)}"
        )
    missing_keys = _CALENDAR_VALUE_FIELDS - set(raw.keys())
    if missing_keys:
        raise SchedulingPayloadError(
            f"{field_name} is missing required properties: {sorted(missing_keys)}"
        )
    date_time = raw["date_time"]
    if not isinstance(date_time, str) or not date_time or date_time != date_time.strip():
        raise SchedulingPayloadError(
            f"{field_name}.date_time must be a nonempty business-time string "
            "(preserved verbatim; never converted to an instant here)"
        )
    if any(ord(ch) < 0x20 for ch in date_time):
        raise SchedulingPayloadError(f"{field_name}.date_time must not contain controls")
    all_day = raw["all_day"]
    if type(all_day) is not bool:
        raise SchedulingPayloadError(
            f"{field_name}.all_day must be an explicit bool; all-day versus "
            "timed interpretation is never invented"
        )
    timezone_raw = raw["timezone"]
    missing = None
    try:
        missing = _missing_to_dict(timezone_raw)
    except SchedulingPayloadError as exc:
        raise SchedulingPayloadError(f"{field_name}.timezone is malformed: {exc}") from exc
    if missing is not None:
        timezone: Any = missing
    elif isinstance(timezone_raw, str):
        if not timezone_raw or timezone_raw != timezone_raw.strip():
            raise SchedulingPayloadError(
                f"{field_name}.timezone must be a nonempty IANA-style name "
                "or a typed Missing envelope"
            )
        if len(timezone_raw) > 256 or any(ord(ch) < 0x20 for ch in timezone_raw):
            raise SchedulingPayloadError(f"{field_name}.timezone is not a valid name")
        timezone = timezone_raw
    else:
        raise SchedulingPayloadError(
            f"{field_name}.timezone must be a timezone name or a typed Missing "
            "envelope; bare nulls and invented defaults are rejected"
        )
    if all_day is True and not isinstance(timezone, dict):
        raise SchedulingPayloadError(
            f"{field_name} is all-day, so timezone must be a typed Missing "
            "envelope (typically not_applicable), not a timezone name"
        )
    return {"date_time": date_time, "timezone": timezone, "all_day": all_day}


def _validate_event_payload(event_obj: dict[str, Any]) -> dict[str, Any]:
    extra = set(event_obj.keys()) - _TOP_LEVEL_FIELDS
    if extra:
        raise SchedulingPayloadError(
            f"calendar event has undeclared properties: {sorted(extra)}"
        )
    missing_top = _REQUIRED_TOP_LEVEL - set(event_obj.keys())
    if missing_top:
        raise SchedulingPayloadError(
            f"calendar event is missing required properties: {sorted(missing_top)}"
        )
    try:
        calendar_id = _require_identifier(event_obj["calendar_id"], "calendar_id")
        job_id = _require_identifier(event_obj["job_id"], "job_id")
    except (TypeError, ValueError) as exc:
        raise SchedulingPayloadError(f"invalid calendar event identity: {exc}") from exc

    start = _validate_calendar_value(event_obj["start"], "start")
    end = _validate_calendar_value(event_obj["end"], "end")
    if start["all_day"] != end["all_day"]:
        raise SchedulingPayloadError(
            "start.all_day and end.all_day disagree; all-day versus timed "
            "semantics must be consistent and are never inferred"
        )
    all_day = bool(start["all_day"])

    # Provider identity/revision must never be invented for a create.
    provider_event_id: Any = make_missing("not_observed")
    if "provider_event_id" in event_obj:
        normalized = _missing_to_dict(event_obj["provider_event_id"])
        if normalized is None:
            raise SchedulingPayloadError(
                "provider_event_id must be a typed Missing envelope for a "
                "calendar.create; actual provider event identity is assigned "
                "by the provider and never invented locally"
            )
        provider_event_id = normalized
    provider_revision: Any = make_missing("not_observed")
    if "provider_revision" in event_obj:
        normalized = _missing_to_dict(event_obj["provider_revision"])
        if normalized is None:
            raise SchedulingPayloadError(
                "provider_revision must be a typed Missing envelope for a "
                "calendar.create; provider revisions are observed, never invented"
            )
        provider_revision = normalized

    # Cheat sheet: retained artifact bytes carry identity; a URL never does.
    cheat_sheet: Any = make_missing("not_applicable")
    if "cheat_sheet" in event_obj:
        raw_sheet = event_obj["cheat_sheet"]
        if isinstance(raw_sheet, str):
            raise SchedulingPayloadError(
                "cheat_sheet must be a retained artifact reference or a typed "
                "Missing envelope; a cheat-sheet URL is a private resolver "
                "output, not durable evidence identity"
            )
        normalized = _missing_to_dict(raw_sheet)
        if normalized is not None:
            cheat_sheet = normalized
        elif isinstance(raw_sheet, Mapping):
            cheat_sheet = _coerce_artifact_ref(raw_sheet, "cheat_sheet")
            _require_digest(cheat_sheet.digest, "cheat_sheet.digest")
        else:
            raise SchedulingPayloadError(
                "cheat_sheet must be a retained artifact reference or a typed "
                "Missing envelope"
            )

    cheat_sheet_url: Any = make_missing("not_applicable")
    if "cheat_sheet_url" in event_obj:
        raw_url = event_obj["cheat_sheet_url"]
        if not isinstance(raw_url, str) or not raw_url:
            raise SchedulingPayloadError(
                "cheat_sheet_url must be a nonempty resolver-output string when present"
            )
        cheat_sheet_url = raw_url

    return {
        "calendar_id": calendar_id,
        "job_id": job_id,
        "start": start,
        "end": end,
        "all_day": all_day,
        "cheat_sheet": cheat_sheet,
        "cheat_sheet_url": cheat_sheet_url,
        "provider_event_id": provider_event_id,
        "provider_revision": provider_revision,
    }


def _timezone_missing_for_timed(parsed: dict[str, Any]) -> bool:
    if bool(parsed["all_day"]) is True:
        return False
    return isinstance(parsed["start"]["timezone"], dict) or isinstance(
        parsed["end"]["timezone"], dict
    )


def _cheat_sheet_for_record(cheat_sheet: Any) -> Any:
    if isinstance(cheat_sheet, dict):
        return dict(cheat_sheet)
    return {
        "digest": cheat_sheet.digest,
        "size_bytes": cheat_sheet.size_bytes,
        "media_type": cheat_sheet.media_type,
        "owner_domain": cheat_sheet.owner_domain,
        "access": cheat_sheet.access,
    }


def _extract_provider_fields(ack_doc: dict[str, Any] | None) -> tuple[Any, Any, Any]:
    """Extract actual provider identity/revision/response from an ack document.

    Only string values actually present in the provider's acknowledgement are
    preserved.  Anything absent remains an explicit Missing envelope.
    """
    if ack_doc is None:
        return (
            make_missing("not_observed"),
            make_missing("not_observed"),
            make_missing("not_observed"),
        )
    ack_inner = ack_doc.get("ack")
    if not isinstance(ack_inner, dict):
        return (
            make_missing("not_observed"),
            make_missing("not_observed"),
            make_missing("not_observed"),
        )
    event_id: Any = make_missing("not_observed")
    for key in ("eventId", "event_id", "id"):
        candidate = ack_inner.get(key)
        if isinstance(candidate, str) and candidate and candidate == candidate.strip():
            event_id = candidate
            break
    revision: Any = make_missing("not_observed")
    for key in ("revision", "provider_revision", "etag"):
        candidate = ack_inner.get(key)
        if isinstance(candidate, str) and candidate and candidate == candidate.strip():
            revision = candidate
            break
    # Preserve the actual provider response object verbatim when it is strict
    # JSON content; otherwise keep it missing rather than inventing a summary.
    try:
        _codec_gate({"response": ack_inner}, "provider_response")
        response: Any = json.loads(json.dumps(ack_inner, sort_keys=True))
    except SchedulingPayloadError:
        response = make_missing(
            "not_observed",
            "provider ack response was not strict evidence content; no summary invented",
        )
    return event_id, revision, response


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


async def schedule_interview(
    channel_id: str,
    command_id: str,
    event: ArtifactReference,
    adapter: VersionPin,
    authorization_refs: tuple[EvidenceRef, ...],
) -> ArtifactReference | Missing:
    """Schedule one interview calendar event without inventing semantics.

    The immutable calendar payload is resolved and validated with its actual
    timezone, all-day versus timed, and provider-revision semantics
    preserved.  A timed event whose timezone is missing is refused with
    ``Missing(not_observed)``: no instant is invented, no UTC default is
    applied, and no provider dispatch is attempted.  Otherwise the event is
    dispatched once as ``calendar.create`` through
    :func:`provider_effects.execute_provider_effect`, and the outcome is
    journaled with attendance and employer confirmation held as
    ``Missing(not_observed)`` regardless of acknowledgement.
    """
    try:
        _require_identifier(channel_id, "channel_id")
        _require_identifier(command_id, "command_id")
    except (TypeError, ValueError) as exc:
        raise SchedulingPayloadError(f"invalid scheduling identity: {exc}") from exc

    event_ref = _coerce_artifact_ref(event, "event")
    adapter_pin = _coerce_version_pin(adapter, "adapter")
    try:
        _require_identifier(adapter_pin.id, "adapter.id")
        _require_identifier(adapter_pin.version, "adapter.version")
        _require_digest(adapter_pin.artifact_digest, "adapter.artifact_digest")
    except (TypeError, ValueError) as exc:
        raise SchedulingPayloadError(f"invalid adapter pin: {exc}") from exc

    if not isinstance(authorization_refs, (tuple, list)) or not authorization_refs:
        raise SchedulingAuthorizationError(
            "explicit operation authority requires at least one EvidenceRef"
        )
    auth_refs = tuple(
        _coerce_evidence_ref(ref, f"authorization_refs[{index}]")
        for index, ref in enumerate(authorization_refs)
    )

    owner_domain = event_ref.owner_domain
    try:
        _require_identifier(owner_domain, "owner_domain")
    except (TypeError, ValueError) as exc:
        raise SchedulingPayloadError(f"invalid event owner domain: {exc}") from exc

    fingerprint = _fingerprint(
        OPERATION_CALENDAR_CREATE, event_ref, adapter_pin, auth_refs
    )
    key = (owner_domain, command_id)
    with _LOCK:
        existing = _COMMANDS.get(key)
        if existing is not None:
            if existing["fingerprint"] != fingerprint:
                raise SchedulingConflictError(
                    f"command {command_id!r} reused with changed content; "
                    "local command identity is stable"
                )
            stored = existing["response"]
            if isinstance(stored, dict):
                return dict(stored)
            return stored

    # Resolve + strictly validate the immutable intended calendar payload.
    try:
        event_bytes = artifact_store.resolve_artifact(channel_id, event_ref)
    except artifact_store.ArtifactError as exc:
        raise SchedulingPayloadError(
            f"calendar event {event_ref.digest} is not resolvable: {exc}"
        ) from exc
    event_obj = _parse_strict_object(event_bytes, "event")
    _codec_gate(event_obj, "event")
    parsed = _validate_event_payload(event_obj)

    # A retained cheat-sheet artifact must resolve; a URL alone never does.
    if not isinstance(parsed["cheat_sheet"], dict):
        try:
            artifact_store.resolve_artifact(channel_id, parsed["cheat_sheet"])
        except artifact_store.ArtifactError as exc:
            raise SchedulingPayloadError(
                "cheat_sheet artifact "
                f"{parsed['cheat_sheet'].digest} is not resolvable; a "
                f"cheat-sheet URL is not a substitute for retained bytes: {exc}"
            ) from exc

    # Timed values without actual timezone semantics cannot be dispatched.
    if _timezone_missing_for_timed(parsed):
        refusal_data: dict[str, Any] = {
            "record_type": RECORD_TYPE_REFUSED,
            "command_id": command_id,
            "operation": OPERATION_CALENDAR_CREATE,
            "calendar_id": parsed["calendar_id"],
            "job_id": parsed["job_id"],
            "start": {
                "date_time": parsed["start"]["date_time"],
                "timezone": parsed["start"]["timezone"],
                "all_day": parsed["start"]["all_day"],
            },
            "end": {
                "date_time": parsed["end"]["date_time"],
                "timezone": parsed["end"]["timezone"],
                "all_day": parsed["end"]["all_day"],
            },
            "all_day": bool(parsed["all_day"]),
            "instant": make_missing("not_observed", _TIMEZONE_MISSING_DETAIL),
            "provider_event_id": make_missing("not_observed"),
            "provider_revision": make_missing("not_observed"),
            "attendance": make_missing("not_observed"),
            "employer_confirmation": make_missing("not_observed"),
            "cheat_sheet": _cheat_sheet_for_record(parsed["cheat_sheet"]),
            "cheat_sheet_url": parsed["cheat_sheet_url"],
            "dispatched": False,
            "delivery": "refused_timezone_missing",
            "detail": _TIMEZONE_MISSING_DETAIL,
        }
        _codec_gate(refusal_data, "refusal")
        try:
            refusal_ref = artifact_store.retain_artifact(
                channel_id,
                owner_domain,
                "application/json",
                _canonical_json_bytes(refusal_data),
                event_ref.access,
            )
        except artifact_store.ArtifactError as exc:
            raise SchedulingJournalError(
                f"cannot durably retain scheduling refusal for {command_id!r}: {exc}"
            ) from exc
        submission = evidence_journal.EventSubmission(
            producer_sequence=evidence_journal.NOT_APPLICABLE,
            event_kind=REFUSED_EVENT_KIND,
            event_schema_version=EVENT_SCHEMA_VERSION,
            occurred_at=evidence_journal.NOT_OBSERVED,
            payload=evidence_journal.EvidencePayload(
                data=dict(refusal_data),
                measurements=(),
                evidence_refs=tuple(auth_refs),
                artifact_refs=(event_ref, refusal_ref),
            ),
        )
        try:
            evidence_journal.append_event(channel_id, owner_domain, submission)
        except Exception as exc:
            raise SchedulingJournalError(
                f"cannot journal scheduling refusal for {command_id!r}: {exc}"
            ) from exc
        response: ArtifactReference | Missing = make_missing(
            "not_observed", _TIMEZONE_MISSING_DETAIL
        )
        with _LOCK:
            _COMMANDS[key] = {"fingerprint": fingerprint, "response": dict(response)}
        return dict(response)

    # Dispatch once as a distinct calendar.create provider effect.
    provider_response = await provider_effects.execute_provider_effect(
        channel_id, command_id, OPERATION_CALENDAR_CREATE, event_ref, adapter_pin, auth_refs
    )

    if isinstance(provider_response, provider_effects.Missing):
        uncertain_data: dict[str, Any] = {
            "record_type": RECORD_TYPE_DISPATCHED,
            "command_id": command_id,
            "operation": OPERATION_CALENDAR_CREATE,
            "calendar_id": parsed["calendar_id"],
            "job_id": parsed["job_id"],
            "start": {
                "date_time": parsed["start"]["date_time"],
                "timezone": parsed["start"]["timezone"],
                "all_day": parsed["start"]["all_day"],
            },
            "end": {
                "date_time": parsed["end"]["date_time"],
                "timezone": parsed["end"]["timezone"],
                "all_day": parsed["end"]["all_day"],
            },
            "all_day": bool(parsed["all_day"]),
            "delivery": "uncertain",
            "ack_digest": make_missing("not_observed"),
            "provider_event_id": make_missing("not_observed"),
            "provider_revision": make_missing("not_observed"),
            "provider_response": make_missing("not_observed"),
            "attendance": make_missing("not_observed"),
            "employer_confirmation": make_missing("not_observed"),
            "cheat_sheet": _cheat_sheet_for_record(parsed["cheat_sheet"]),
            "cheat_sheet_url": parsed["cheat_sheet_url"],
            "detail": provider_response.detail
            or "uncertain delivery; no acknowledgement observed",
        }
        _codec_gate(uncertain_data, "uncertain_outcome")
        try:
            uncertain_ref = artifact_store.retain_artifact(
                channel_id,
                owner_domain,
                "application/json",
                _canonical_json_bytes(uncertain_data),
                event_ref.access,
            )
        except artifact_store.ArtifactError as exc:
            raise SchedulingJournalError(
                f"cannot durably retain uncertain scheduling outcome for "
                f"{command_id!r}: {exc}"
            ) from exc
        submission = evidence_journal.EventSubmission(
            producer_sequence=evidence_journal.NOT_APPLICABLE,
            event_kind=DISPATCHED_EVENT_KIND,
            event_schema_version=EVENT_SCHEMA_VERSION,
            occurred_at=evidence_journal.NOT_OBSERVED,
            payload=evidence_journal.EvidencePayload(
                data=dict(uncertain_data),
                measurements=(),
                evidence_refs=(),
                artifact_refs=(event_ref, uncertain_ref),
            ),
        )
        try:
            evidence_journal.append_event(channel_id, owner_domain, submission)
        except Exception as exc:
            raise SchedulingJournalError(
                f"cannot journal uncertain scheduling outcome for {command_id!r}: {exc}"
            ) from exc
        detail = provider_response.detail or "uncertain delivery"
        response = make_missing(
            provider_response.reason,
            f"{detail}; {_ACK_NOT_ATTENDANCE_DETAIL.lower()}",
        )
        with _LOCK:
            _COMMANDS[key] = {"fingerprint": fingerprint, "response": dict(response)}
        return dict(response)

    ack_ref = _coerce_artifact_ref(provider_response, "provider_ack")
    try:
        ack_bytes = artifact_store.resolve_artifact(channel_id, ack_ref)
    except artifact_store.ArtifactError:
        ack_bytes = b""
    ack_doc: dict[str, Any] | None = None
    if ack_bytes:
        try:
            ack_doc = _parse_strict_object(ack_bytes, "provider_ack")
        except SchedulingPayloadError:
            ack_doc = None
    provider_event_id, provider_revision, provider_response_data = (
        _extract_provider_fields(ack_doc)
    )
    acknowledged_data: dict[str, Any] = {
        "record_type": RECORD_TYPE_DISPATCHED,
        "command_id": command_id,
        "operation": OPERATION_CALENDAR_CREATE,
        "calendar_id": parsed["calendar_id"],
        "job_id": parsed["job_id"],
        "start": {
            "date_time": parsed["start"]["date_time"],
            "timezone": parsed["start"]["timezone"],
            "all_day": parsed["start"]["all_day"],
        },
        "end": {
            "date_time": parsed["end"]["date_time"],
            "timezone": parsed["end"]["timezone"],
            "all_day": parsed["end"]["all_day"],
        },
        "all_day": bool(parsed["all_day"]),
        "delivery": "acknowledged",
        "ack_digest": ack_ref.digest,
        "provider_event_id": provider_event_id,
        "provider_revision": provider_revision,
        "provider_response": provider_response_data,
        "attendance": make_missing(
            "not_observed",
            "interview attendance is not observed from a calendar write "
            "acknowledgement",
        ),
        "employer_confirmation": make_missing(
            "not_observed",
            "employer confirmation is not observed from a calendar write "
            "acknowledgement",
        ),
        "cheat_sheet": _cheat_sheet_for_record(parsed["cheat_sheet"]),
        "cheat_sheet_url": parsed["cheat_sheet_url"],
        "detail": _ACK_NOT_ATTENDANCE_DETAIL,
    }
    _codec_gate(acknowledged_data, "acknowledged_outcome")
    try:
        outcome_ref = artifact_store.retain_artifact(
            channel_id,
            owner_domain,
            "application/json",
            _canonical_json_bytes(acknowledged_data),
            event_ref.access,
        )
    except artifact_store.ArtifactError as exc:
        raise SchedulingJournalError(
            f"cannot durably retain acknowledged scheduling outcome for "
            f"{command_id!r}: {exc}"
        ) from exc
    submission = evidence_journal.EventSubmission(
        producer_sequence=evidence_journal.NOT_APPLICABLE,
        event_kind=DISPATCHED_EVENT_KIND,
        event_schema_version=EVENT_SCHEMA_VERSION,
        occurred_at=evidence_journal.NOT_OBSERVED,
        payload=evidence_journal.EvidencePayload(
            data=dict(acknowledged_data),
            measurements=(),
            evidence_refs=(),
            artifact_refs=(event_ref, ack_ref, outcome_ref),
        ),
    )
    try:
        evidence_journal.append_event(channel_id, owner_domain, submission)
    except Exception as exc:
        raise SchedulingJournalError(
            f"cannot journal acknowledged scheduling outcome for {command_id!r}: {exc}"
        ) from exc
    with _LOCK:
        _COMMANDS[key] = {"fingerprint": fingerprint, "response": ack_ref}
    return ack_ref

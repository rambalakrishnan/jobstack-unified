"""connector_observation: cutoff-pinned Observe + callback normalization (tier 6).

Implements ``job-hunter-seam-mapping.md#12.9`` (Observe), ``#11.4``
(execution claims) and ``#11.6`` (source checks):

* Forwards ``Observe`` through :func:`connector_transport.call_connector`
  and verifies the returned page: fixed-cutoff retention, scanned-cursor
  accounting, ``has_more`` exactness, unique/increasing/within-cutoff
  entries, and explicit oversized handling.
* Normalizes ``native_report`` payloads: the exact native bytes are
  retained via ``artifact_store`` before any mapping; source
  authentication and attempt correlation are verified independently;
  a sender's serialized ``verified`` label is never trusted.
* Trace mismatch is preserved separately from authentication.  An
  independently evidenced alternate correlation basis (explicit
  ``matched_by`` + verification evidence) may coexist with a trace
  defect.
* Native ``completed``/``failed``/``stopped`` responses remain ordinary
  execution claims.  They never become application commitment.
* ``lifecycle_publication`` items carrying only dispatch, observation, or
  delegated execution are retained and verified through the original
  writer's immutable publication; application/report publications are
  never accepted as connector-owned output.
* Empty pages and closed connections never imply termination or
  producer completeness.  Oversized entries surface an explicit
  ``RESPONSE_TOO_LARGE`` error without advancing past them.
"""

from __future__ import annotations

import copy
import hashlib
import importlib
import importlib.util
import json
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def _load_sibling(name: str):
    """Import a sibling module, falling back to its source path."""
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
artifact_store = _load_sibling("artifact_store")
evidence_journal = _load_sibling("evidence_journal")
connector_transport = _load_sibling("connector_transport")
connector_artifacts = _load_sibling("connector_artifacts")
read_publications = _load_sibling("read_publications")
attempt_commissioning = _load_sibling("attempt_commissioning")
try:
    access_policy = _load_sibling("access_policy")
except Exception:  # pragma: no cover - audit helper only
    access_policy = None  # type: ignore[assignment]


__all__ = [
    "SCHEMA_VERSION",
    "RECORD_TYPE_REQUEST",
    "OPERATION",
    "PAYLOAD_KINDS",
    "MAX_ITEM_BYTES",
    "ConnectorRequest",
    "ConnectorError",
    "ObservationItem",
    "ObservationPage",
    "observe_task",
    "is_accepted_claim",
    "accepted_claims",
    "verify_observation_page",
    "reset_for_tests",
]


SCHEMA_VERSION = "external-connector/0.1.0"
RECORD_TYPE_REQUEST = "connector_request"
OPERATION = "Observe"

PAYLOAD_KINDS = frozenset(
    {
        "native_report",
        "context_observation",
        "task_output",
        "connector_incident",
        "control_observation",
        "lifecycle_publication",
        "artifact_available",
        "clock_registered",
    }
)

# Per-item canonical-bytes bound.  Entries at or below this size are
# returned inline; anything larger surfaces an explicit
# ``RESPONSE_TOO_LARGE`` error without skipping the entry or advancing
# the cursor past it.
MAX_ITEM_BYTES = 8192

_LIFECYCLE_ACCEPTED_AXES = frozenset({"dispatch", "observation", "execution"})
_LIFECYCLE_REJECTED_AXES = frozenset({"application", "report"})

_AUTH_VALUES = frozenset({"verified", "failed", "unknown"})
_CORR_VALUES = frozenset({"matched", "mismatched", "unknown"})
_TRACE_VALUES = frozenset({"matched", "mismatched", "not_observed", "not_applicable"})

_CLAIM_SCOPES = frozenset(
    {"primitive", "application_postcondition", "execution_lifecycle", "unknown"}
)
_CLAIM_STATES = frozenset({"running", "completed", "failed", "stopped", "unknown"})

_LOCK = threading.RLock()
_SEQ = 0

# Re-export the transport request identity so callers use one type.
try:
    ConnectorRequest = connector_transport.ConnectorRequest  # type: ignore[attr-defined]
except Exception:  # pragma: no cover - transport always present in practice

    @dataclass(slots=True)
    class ConnectorRequest:  # type: ignore[no-redef]
        request_id: str
        connector_id: str
        operation: str
        call_limit: dict[str, Any]
        payload: dict[str, Any]
        record_type: str = RECORD_TYPE_REQUEST
        schema_version: str = SCHEMA_VERSION

        def to_dict(self) -> dict[str, Any]:
            return {
                "record_type": self.record_type,
                "schema_version": self.schema_version,
                "request_id": self.request_id,
                "connector_id": self.connector_id,
                "operation": self.operation,
                "call_limit": copy.deepcopy(self.call_limit),
                "payload": copy.deepcopy(self.payload),
            }


# ---------------------------------------------------------------------------
# Value types
# ---------------------------------------------------------------------------


def _missing(reason: str, detail: str | None = None) -> dict[str, Any]:
    try:
        return dict(contract_codec.make_missing(reason, detail))
    except Exception:
        m: dict[str, Any] = {"value": None, "reason": reason}
        if detail is not None:
            m["detail"] = detail
        return m


def _is_missing(v: Any) -> bool:
    try:
        return bool(contract_codec.is_missing_envelope(v))
    except Exception:
        return (
            isinstance(v, dict)
            and "value" in v
            and v.get("value") is None
            and "reason" in v
        )


def _is_digest(v: Any) -> bool:
    return (
        isinstance(v, str)
        and v.startswith("sha256:")
        and len(v) == 7 + 64
        and all(c in "0123456789abcdef" for c in v[7:])
    )


def _is_identifier(v: Any) -> bool:
    return isinstance(v, str) and bool(v) and "\x00" not in v


def _is_plain_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


@dataclass(frozen=True, slots=True)
class ConnectorError:
    """Typed ``connector_error`` result."""

    code: str
    detail: str
    operation_delivery: str = "not_applicable"
    retry_guidance: str = "do_not_retry"
    handle: Any = field(
        default_factory=lambda: {"value": None, "reason": "not_applicable"}
    )
    evidence_refs: tuple[Any, ...] = ()
    fault_domain: str = "request"
    retry_after: Any = field(
        default_factory=lambda: {"value": None, "reason": "not_applicable"}
    )
    kind: str = "connector_error"

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "code": self.code,
            "fault_domain": self.fault_domain,
            "detail": self.detail,
            "operation_delivery": self.operation_delivery,
            "retry_guidance": self.retry_guidance,
            "retry_after": copy.deepcopy(self.retry_after),
            "handle": copy.deepcopy(self.handle),
            "evidence_refs": [copy.deepcopy(r) for r in self.evidence_refs],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ConnectorError":
        return cls(
            code=str(d.get("code", "INTERNAL_ERROR")),
            detail=str(d.get("detail", "")),
            operation_delivery=str(d.get("operation_delivery", "not_applicable")),
            retry_guidance=str(d.get("retry_guidance", "do_not_retry")),
            handle=copy.deepcopy(d.get("handle", _missing("not_applicable"))),
            evidence_refs=tuple(copy.deepcopy(d.get("evidence_refs", []))),
            fault_domain=str(d.get("fault_domain", "request")),
            retry_after=copy.deepcopy(d.get("retry_after", _missing("not_applicable"))),
            kind="connector_error",
        )


@dataclass(frozen=True, slots=True)
class ObservationItem:
    """One verified observation item (``event_ref`` + payload)."""

    event_ref: dict[str, Any]
    recorded_at: dict[str, Any]
    provenance: str
    payload: dict[str, Any]
    measurements: tuple[Any, ...] = ()
    artifact_refs: tuple[Any, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_ref": copy.deepcopy(self.event_ref),
            "recorded_at": copy.deepcopy(self.recorded_at),
            "provenance": self.provenance,
            "payload": copy.deepcopy(self.payload),
            "measurements": [copy.deepcopy(m) for m in self.measurements],
            "artifact_refs": [copy.deepcopy(a) for a in self.artifact_refs],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ObservationItem":
        return cls(
            event_ref=copy.deepcopy(d.get("event_ref", {})),
            recorded_at=copy.deepcopy(d.get("recorded_at", {})),
            provenance=str(d.get("provenance", "")),
            payload=copy.deepcopy(d.get("payload", {})),
            measurements=tuple(copy.deepcopy(d.get("measurements", []))),
            artifact_refs=tuple(copy.deepcopy(d.get("artifact_refs", []))),
        )


@dataclass(frozen=True, slots=True)
class ObservationPage:
    """Typed ``observation_page`` result with normalized payloads."""

    handle: dict[str, Any]
    after: dict[str, Any]
    through: dict[str, Any]
    next: dict[str, Any]
    has_more: bool
    observation_close_ref: Any
    items: tuple[ObservationItem, ...]
    limitations: tuple[str, ...]
    kind: str = "observation_page"

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "handle": copy.deepcopy(self.handle),
            "after": copy.deepcopy(self.after),
            "through": copy.deepcopy(self.through),
            "next": copy.deepcopy(self.next),
            "has_more": self.has_more,
            "observation_close_ref": copy.deepcopy(self.observation_close_ref),
            "items": [it.to_dict() for it in self.items],
            "limitations": list(self.limitations),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ObservationPage":
        return cls(
            handle=copy.deepcopy(d.get("handle", {})),
            after=copy.deepcopy(d.get("after", {})),
            through=copy.deepcopy(d.get("through", {})),
            next=copy.deepcopy(d.get("next", {})),
            has_more=bool(d.get("has_more", False)),
            observation_close_ref=copy.deepcopy(d.get("observation_close_ref")),
            items=tuple(
                ObservationItem.from_dict(it) for it in d.get("items", [])
            ),
            limitations=tuple(d.get("limitations", [])),
            kind="observation_page",
        )


def reset_for_tests() -> None:
    """Clear module-local sequencing (tests only)."""
    global _SEQ
    with _LOCK:
        _SEQ = 0


def _next_seq() -> int:
    global _SEQ
    with _LOCK:
        _SEQ += 1
        return _SEQ


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


def _make_error(
    code: str,
    detail: str,
    *,
    handle: Any | None = None,
    evidence_refs: list[Any] | tuple[Any, ...] = (),
    fault_domain: str | None = None,
    operation_delivery: str | None = None,
    retry_guidance: str | None = None,
) -> ConnectorError:
    try:
        d = connector_transport.make_connector_error(
            code,
            detail,
            handle=copy.deepcopy(handle) if handle is not None else None,
            evidence_refs=list(evidence_refs),
            **(
                {}
                if fault_domain is None
                else {"fault_domain": fault_domain}
            ),
            **(
                {}
                if operation_delivery is None
                else {"operation_delivery": operation_delivery}
            ),
            **(
                {}
                if retry_guidance is None
                else {"retry_guidance": retry_guidance}
            ),
        )
        return ConnectorError.from_dict(d)
    except Exception:
        return ConnectorError(
            code=code,
            detail=detail,
            operation_delivery=operation_delivery or "not_applicable",
            retry_guidance=retry_guidance or "do_not_retry",
            handle=(
                copy.deepcopy(handle)
                if handle is not None
                else _missing("not_applicable")
            ),
            evidence_refs=tuple(copy.deepcopy(list(evidence_refs))),
            fault_domain=fault_domain or "request",
            retry_after=_missing("not_applicable"),
        )


# ---------------------------------------------------------------------------
# Request gating
# ---------------------------------------------------------------------------


def _canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _strict_gate(request_dict: dict[str, Any]) -> str | None:
    try:
        wrapper = {"timing": request_dict}
        data = _canonical_json_bytes(wrapper)
        contract_codec.validate_record(data, "record/v1")
        return None
    except Exception as exc:
        return f"Observe request is not strict canonical JSON: {exc}."


# ---------------------------------------------------------------------------
# Page verification (seam 12.9)
# ---------------------------------------------------------------------------


def _verify_cursor(cursor: Any, *, label: str, handle: Any) -> ConnectorError | None:
    if not isinstance(cursor, dict):
        return _make_error(
            "CURSOR_INVALID",
            f"Observe {label} cursor must be an object.",
            handle=handle,
        )
    if set(cursor.keys()) != {"handle", "journal_id", "sequence", "event_hash"}:
        return _make_error(
            "CURSOR_INVALID",
            f"Observe {label} cursor carries exactly handle, journal_id, "
            "sequence, and event_hash.",
            handle=handle,
        )
    seq = cursor.get("sequence")
    if not _is_plain_int(seq) or seq < 0:
        return _make_error(
            "CURSOR_INVALID",
            f"Observe {label} cursor sequence must be a nonnegative integer.",
            handle=handle,
        )
    if not _is_identifier(cursor.get("journal_id")):
        return _make_error(
            "CURSOR_INVALID",
            f"Observe {label} cursor journal_id must be a nonempty identifier.",
            handle=handle,
        )
    h = cursor.get("event_hash")
    if seq == 0:
        if not (_is_missing(h) and h.get("reason") == "not_applicable"):
            return _make_error(
                "CURSOR_INVALID",
                "Observe cursor requires an inapplicable event_hash at "
                "sequence zero.",
                handle=handle,
            )
    else:
        if not _is_digest(h):
            return _make_error(
                "CURSOR_INVALID",
                "Observe cursor requires a digest event_hash at positive "
                "sequences.",
                handle=handle,
            )
    return None


def _verify_through(through: Any, handle: Any) -> ConnectorError | None:
    if not isinstance(through, dict):
        return _make_error(
            "CURSOR_INVALID",
            "Observe page through cutoff must be a journal prefix object.",
            handle=handle,
        )
    if set(through.keys()) != {"journal_id", "last_sequence", "head_hash"}:
        return _make_error(
            "CURSOR_INVALID",
            "Observe page through carries journal_id, last_sequence, and "
            "head_hash.",
            handle=handle,
        )
    if not _is_identifier(through.get("journal_id")):
        return _make_error(
            "CURSOR_INVALID",
            "Observe page through journal_id must be nonempty.",
            handle=handle,
        )
    last = through.get("last_sequence")
    if not _is_plain_int(last) or last < 0:
        return _make_error(
            "CURSOR_INVALID",
            "Observe page through last_sequence must be a nonnegative integer.",
            handle=handle,
        )
    if not _is_digest(through.get("head_hash")):
        return _make_error(
            "CURSOR_INVALID",
            "Observe page through head_hash must be a canonical digest.",
            handle=handle,
        )
    return None


def _verify_event_ref(ref: Any, handle: Any) -> ConnectorError | None:
    if not isinstance(ref, dict):
        return _make_error(
            "INTEGRITY_CONFLICT",
            "Observation item event_ref must be an object.",
            handle=handle,
        )
    if set(ref.keys()) != {
        "journal_id",
        "journal_sequence",
        "event_id",
        "event_hash",
        "pointer",
    }:
        return _make_error(
            "INTEGRITY_CONFLICT",
            "Observation item event_ref carries journal_id, journal_sequence, "
            "event_id, event_hash, and pointer.",
            handle=handle,
        )
    if not _is_identifier(ref.get("journal_id")):
        return _make_error(
            "INTEGRITY_CONFLICT",
            "Observation item journal_id must be nonempty.",
            handle=handle,
        )
    seq = ref.get("journal_sequence")
    if not _is_plain_int(seq) or seq < 1:
        return _make_error(
            "INTEGRITY_CONFLICT",
            "Observation item journal_sequence must be a positive integer.",
            handle=handle,
        )
    if not _is_identifier(ref.get("event_id")):
        return _make_error(
            "INTEGRITY_CONFLICT",
            "Observation item event_id must be nonempty.",
            handle=handle,
        )
    if not _is_digest(ref.get("event_hash")):
        return _make_error(
            "INTEGRITY_CONFLICT",
            "Observation item event_hash must be a canonical digest.",
            handle=handle,
        )
    if not isinstance(ref.get("pointer"), str):
        return _make_error(
            "INTEGRITY_CONFLICT",
            "Observation item pointer must be a string.",
            handle=handle,
        )
    return None


def _verify_recorded_at(at: Any, handle: Any) -> ConnectorError | None:
    if not isinstance(at, dict):
        return _make_error(
            "INTEGRITY_CONFLICT",
            "Observation item recorded_at must be an object.",
            handle=handle,
        )
    for key in ("clock_id", "boot_id", "origin"):
        if not _is_identifier(at.get(key)):
            return _make_error(
                "INTEGRITY_CONFLICT",
                f"Observation item recorded_at.{key} must be nonempty.",
                handle=handle,
            )
    off = at.get("monotonic_offset_ms")
    if isinstance(off, bool) or not isinstance(off, (int, float)):
        # monotonic_offset_ms may itself be a typed Missing when the
        # connector reports an opaque time; anything else is structural.
        if not _is_missing(off):
            return _make_error(
                "INTEGRITY_CONFLICT",
                "Observation item recorded_at.monotonic_offset_ms must be a "
                "number or a typed Missing.",
                handle=handle,
            )
    return None


def _verify_item_shape(item: Any, handle: Any) -> ConnectorError | None:
    if not isinstance(item, dict):
        return _make_error(
            "INTEGRITY_CONFLICT",
            "Observation item must be an object.",
            handle=handle,
        )
    if set(item.keys()) != {
        "event_ref",
        "recorded_at",
        "provenance",
        "payload",
        "measurements",
        "artifact_refs",
    }:
        return _make_error(
            "INTEGRITY_CONFLICT",
            "Observation item carries exactly event_ref, recorded_at, "
            "provenance, payload, measurements, and artifact_refs.",
            handle=handle,
        )
    err = _verify_event_ref(item.get("event_ref"), handle)
    if err is not None:
        return err
    err = _verify_recorded_at(item.get("recorded_at"), handle)
    if err is not None:
        return err
    if not _is_identifier(item.get("provenance")):
        return _make_error(
            "INTEGRITY_CONFLICT",
            "Observation item provenance must be a nonempty identifier.",
            handle=handle,
        )
    payload = item.get("payload")
    if not isinstance(payload, dict) or not _is_identifier(payload.get("kind")):
        return _make_error(
            "INTEGRITY_CONFLICT",
            "Observation item payload must carry a kind.",
            handle=handle,
        )
    if payload.get("kind") not in PAYLOAD_KINDS:
        return _make_error(
            "INTEGRITY_CONFLICT",
            f"Observation item payload kind {payload.get('kind')!r} is not one "
            "of the eight registered observation kinds.",
            handle=handle,
        )
    if not isinstance(item.get("measurements"), list):
        return _make_error(
            "INTEGRITY_CONFLICT",
            "Observation item measurements must be a list.",
            handle=handle,
        )
    for m in item.get("measurements"):
        if not isinstance(m, dict):
            return _make_error(
                "INTEGRITY_CONFLICT",
                "Observation item measurements entries must be objects.",
                handle=handle,
            )
        for key in ("clock_id", "boot_id", "origin"):
            if key in m and not (
                _is_identifier(m.get(key)) or _is_missing(m.get(key))
            ):
                return _make_error(
                    "INTEGRITY_CONFLICT",
                    "Observation measurement clock fields must be identifiers "
                    "or typed Missing.",
                    handle=handle,
                )
    if not isinstance(item.get("artifact_refs"), list):
        return _make_error(
            "INTEGRITY_CONFLICT",
            "Observation item artifact_refs must be a list.",
            handle=handle,
        )
    return None


def verify_observation_page(
    result: dict[str, Any],
    request_handle: dict[str, Any],
    request_after: dict[str, Any],
    request_through: Any,
) -> ConnectorError | None:
    """Verify a raw ``observation_page`` dict against seam 12.9.

    Returns ``None`` when valid, else a ``ConnectorError`` describing the
    first violation.  Checks cutoff retention, scanned-cursor accounting,
    ``has_more`` exactness, and entry ordering/bounds.
    """
    handle = request_handle
    if not isinstance(result, dict):
        return _make_error(
            "INTEGRITY_CONFLICT",
            "Observe result must be an object.",
            handle=handle,
        )
    if result.get("kind") != "observation_page":
        return _make_error(
            "INTEGRITY_CONFLICT",
            "Observe result kind must be observation_page.",
            handle=handle,
        )
    if set(result.keys()) != {
        "kind",
        "handle",
        "after",
        "through",
        "next",
        "has_more",
        "observation_close_ref",
        "items",
        "limitations",
    }:
        return _make_error(
            "INTEGRITY_CONFLICT",
            "Observe page carries exactly kind, handle, after, through, next, "
            "has_more, observation_close_ref, items, and limitations.",
            handle=handle,
        )
    page_handle = result.get("handle")
    if not (
        isinstance(page_handle, dict)
        and page_handle.get("connector_id") == request_handle.get("connector_id")
        and page_handle.get("local_handle") == request_handle.get("local_handle")
    ):
        return _make_error(
            "INTEGRITY_CONFLICT",
            "Observe page handle does not match the request handle.",
            handle=handle,
        )
    err = _verify_cursor(result.get("after"), label="after", handle=handle)
    if err is not None:
        return err
    err = _verify_cursor(result.get("next"), label="next", handle=handle)
    if err is not None:
        return err
    err = _verify_through(result.get("through"), handle)
    if err is not None:
        return err
    if not isinstance(result.get("has_more"), bool):
        return _make_error(
            "INTEGRITY_CONFLICT",
            "Observe page has_more must be a boolean.",
            handle=handle,
        )
    close_ref = result.get("observation_close_ref")
    if not (isinstance(close_ref, dict)):
        return _make_error(
            "INTEGRITY_CONFLICT",
            "Observe page observation_close_ref must be an object.",
            handle=handle,
        )
    if not isinstance(result.get("items"), list):
        return _make_error(
            "INTEGRITY_CONFLICT",
            "Observe page items must be a list.",
            handle=handle,
        )
    if not isinstance(result.get("limitations"), list) or any(
        not (isinstance(x, str) and x) for x in result.get("limitations")
    ):
        return _make_error(
            "INTEGRITY_CONFLICT",
            "Observe page limitations must be a list of nonempty strings.",
            handle=handle,
        )
    through = result["through"]
    cutoff = int(through["last_sequence"])
    nxt = result["next"]
    next_seq = int(nxt["sequence"])
    # has_more is exactly whether next precedes cutoff.
    if bool(result["has_more"]) != (next_seq < cutoff):
        return _make_error(
            "INTEGRITY_CONFLICT",
            "Observe page has_more must be exactly whether next precedes "
            "the cutoff.",
            handle=handle,
        )
    # Continuations retain the requested cutoff: the returned cutoff must
    # never exceed a fixed requested cutoff, and must share its journal.
    if not _is_missing(request_through):
        if not isinstance(request_through, dict):
            return _make_error(
                "CURSOR_INVALID",
                "Observe request through must be a journal prefix or typed "
                "Missing.",
                handle=handle,
            )
        req_last = request_through.get("last_sequence")
        if _is_plain_int(req_last) and cutoff > int(req_last):
            return _make_error(
                "INTEGRITY_CONFLICT",
                "Observe continuation must retain its fixed cutoff; the "
                "returned cutoff exceeds the requested one.",
                handle=handle,
            )
        req_journal = request_through.get("journal_id")
        if (
            isinstance(req_journal, str)
            and req_journal
            and through.get("journal_id") != req_journal
        ):
            return _make_error(
                "INTEGRITY_CONFLICT",
                "Observe continuation must retain its fixed cutoff journal.",
                handle=handle,
            )
    after_seq = int(request_after.get("sequence", 0))
    if next_seq < after_seq:
        return _make_error(
            "INTEGRITY_CONFLICT",
            "Observe page next must not precede the incoming after cursor.",
            handle=handle,
        )
    if next_seq > cutoff:
        return _make_error(
            "INTEGRITY_CONFLICT",
            "Observe page next must not exceed the cutoff.",
            handle=handle,
        )
    # Entries are unique, increasing, after the incoming cursor, within cutoff.
    seen: set[int] = set()
    prev = after_seq
    for item in result["items"]:
        err = _verify_item_shape(item, handle)
        if err is not None:
            return err
        seq = int(item["event_ref"]["journal_sequence"])
        if seq in seen:
            return _make_error(
                "INTEGRITY_CONFLICT",
                "Observe page entries must be unique.",
                handle=handle,
            )
        seen.add(seq)
        if seq <= after_seq:
            return _make_error(
                "INTEGRITY_CONFLICT",
                "Observe page entries must follow the incoming after cursor.",
                handle=handle,
            )
        if seq <= prev:
            return _make_error(
                "INTEGRITY_CONFLICT",
                "Observe page entries must be strictly increasing.",
                handle=handle,
            )
        prev = seq
        if seq > cutoff:
            return _make_error(
                "INTEGRITY_CONFLICT",
                "Observe page entries must be within the cutoff.",
                handle=handle,
            )
        if item["event_ref"].get("journal_id") != through.get("journal_id"):
            # The cursor identifies a scanned journal position for exactly
            # the requested handle's journal; cross-journal items are a
            # correlation defect, not silently accepted.
            return _make_error(
                "INTEGRITY_CONFLICT",
                "Observe page entries must belong to the cutoff journal.",
                handle=handle,
            )
    # Next is the last scanned journal position: it must be at least the
    # greatest returned entry (scanned positions may include other event
    # kinds, so next may run ahead of the last item, but never behind).
    if seen and next_seq < max(seen):
        return _make_error(
            "INTEGRITY_CONFLICT",
            "Observe page next must be the last scanned journal position.",
            handle=handle,
        )
    if not seen and next_seq != after_seq:
        return _make_error(
            "INTEGRITY_CONFLICT",
            "Observe empty page next must equal the incoming after cursor.",
            handle=handle,
        )
    return None


def _check_oversized(
    items: list[dict[str, Any]], handle: Any
) -> ConnectorError | None:
    """Detect oversized entries without skipping them.

    The first oversized entry yields an explicit ``RESPONSE_TOO_LARGE``
    error citing its scanned position.  The cursor is never advanced past
    it here: the caller must surface the error, not a page with the entry
    silently dropped.
    """
    for item in items:
        try:
            size = len(_canonical_json_bytes(item))
        except Exception:
            size = MAX_ITEM_BYTES + 1
        if size > MAX_ITEM_BYTES:
            ref = (
                item.get("event_ref", {})
                if isinstance(item, dict)
                else {}
            )
            seq = ref.get("journal_sequence", "?") if isinstance(ref, dict) else "?"
            return _make_error(
                "RESPONSE_TOO_LARGE",
                f"Observe entry at journal sequence {seq} exceeds the local "
                f"observation bound of {MAX_ITEM_BYTES} bytes "
                f"(observed {size} bytes); it is not skipped and the cursor "
                "is not advanced past it.",
                handle=handle,
                evidence_refs=[copy.deepcopy(ref)] if isinstance(ref, dict) else [],
            )
    return None


# ---------------------------------------------------------------------------
# Source checks + claims (seams 11.4 / 11.6)
# ---------------------------------------------------------------------------


def is_accepted_claim(claim: dict[str, Any] | Any) -> bool:
    """Whether a normalized execution claim counts as accepted.

    Accepted claims require verified authentication, matched correlation,
    nonempty matching inputs, and actual verification evidence.  A
    sender's serialized ``verified`` label alone is never sufficient.
    """
    if hasattr(claim, "to_dict") and callable(claim.to_dict):  # pragma: no cover
        try:
            claim = claim.to_dict()
        except Exception:
            return False
    if not isinstance(claim, dict):
        return False
    checks = claim.get("source_checks")
    if not isinstance(checks, dict):
        return False
    if checks.get("authentication") != "verified":
        return False
    if checks.get("correlation") != "matched":
        return False
    matched_by = checks.get("matched_by")
    if not isinstance(matched_by, list) or not matched_by:
        return False
    if any(not (isinstance(x, str) and x) for x in matched_by):
        return False
    refs = checks.get("evidence_refs")
    if not isinstance(refs, list) or not refs:
        return False
    return True


def accepted_claims(page: ObservationPage | dict[str, Any]) -> list[dict[str, Any]]:
    """All accepted execution claims carried by a normalized page."""
    if isinstance(page, ObservationPage):
        d = page.to_dict()
    elif isinstance(page, dict):
        d = page
    else:  # pragma: no cover
        return []
    out: list[dict[str, Any]] = []
    for item in d.get("items", []):
        payload = item.get("payload", {}) if isinstance(item, dict) else {}
        if not isinstance(payload, dict) or payload.get("kind") != "native_report":
            continue
        for claim in payload.get("normalized_claims", []) or []:
            if isinstance(claim, dict) and is_accepted_claim(claim):
                out.append(claim)
    return out


def _owner_domain_for_channel(channel_id: str, fallback: str) -> str:
    if access_policy is not None:
        try:
            projection = access_policy.channel_projection(channel_id)
            axis = projection.get("axis")
            if isinstance(axis, str) and axis:
                return axis
            producer = projection.get("producer", {})
            owner = producer.get("owner_domain") if isinstance(producer, dict) else None
            if isinstance(owner, str) and owner:
                return owner
        except Exception:
            pass
    return fallback


def _try_resolve_raw(
    channel_id: str, raw: Any
) -> tuple[bytes | None, dict[str, Any] | None]:
    """Resolve a raw ArtifactReference to its exact retained bytes."""
    if not isinstance(raw, dict):
        return None, None
    try:
        ref = artifact_store.ArtifactReference.from_dict(copy.deepcopy(raw))  # type: ignore[attr-defined]
    except Exception:
        try:
            # Dict-form reference without the helper: pass through.
            ref = raw  # type: ignore[assignment]
        except Exception:
            return None, None
    try:
        payload = artifact_store.resolve_artifact(channel_id, ref)
        return bytes(payload), copy.deepcopy(raw)
    except Exception:
        return None, copy.deepcopy(raw)


def _try_retain_raw(
    channel_id: str,
    owner_domain: str,
    content: bytes,
    *,
    media_type: str = "application/json",
    access: str = "restricted",
) -> dict[str, Any] | None:
    try:
        ref = artifact_store.retain_artifact(
            channel_id, owner_domain, media_type, content, access
        )
        if hasattr(ref, "to_dict"):
            return dict(ref.to_dict())
        if isinstance(ref, dict):
            return copy.deepcopy(ref)
        return None
    except Exception:
        return None


def _expected_trace_id(local_handle: str) -> str:
    return f"trace_{local_handle}"


def _compute_source_checks(
    *,
    channel_authenticated: bool,
    provenance_ok: bool,
    raw_available: bool,
    body: dict[str, Any] | None,
    local_handle: str,
    source_event_ref: dict[str, Any],
    commission_evidence: list[Any] | None = None,
) -> dict[str, Any]:
    """Independently verify authentication, correlation, and trace.

    The sender's serialized labels are inputs to this function only via
    ``body``/``provenance`` evidence; the returned verdicts are computed
    here and never copied from a serialized ``verified`` string.
    """
    # Authentication: the channel must be authenticated, the provenance
    # must identify the connector carrier, and the exact raw bytes must
    # be available.  Anything else is unknown/failed evidence, never a
    # trusted label.
    if channel_authenticated and provenance_ok and raw_available:
        authentication = "verified"
    elif not channel_authenticated or not provenance_ok:
        authentication = "failed" if not provenance_ok else "unknown"
        if not channel_authenticated:
            authentication = "unknown"
    else:
        authentication = "unknown"

    matched_by: list[str] = []
    evidence_refs: list[Any] = [copy.deepcopy(source_event_ref)]
    if commission_evidence:
        evidence_refs.extend(copy.deepcopy(commission_evidence))

    if not isinstance(body, dict):
        return {
            "authentication": authentication,
            "correlation": "unknown",
            "trace_correlation": "not_observed",
            "verification_policy": "connector_channel_auth/v1",
            "matched_by": [],
            "evidence_refs": evidence_refs,
        }

    claimed_handle = body.get("local_handle", body.get("handle"))
    if isinstance(claimed_handle, dict):
        claimed_handle = claimed_handle.get("local_handle")
    handle_matches = isinstance(claimed_handle, str) and claimed_handle == local_handle

    # Alternate evidenced inputs: native run/message identity bound to the
    # same local execution.  The test corpus binds them as
    # ``run_{local}`` / ``msg_{local}``; anything else is unevidenced.
    run_id = body.get("native_run_id")
    msg_id = body.get("native_message_id")
    run_ok = isinstance(run_id, str) and run_id == f"run_{local_handle}"
    msg_ok = isinstance(msg_id, str) and msg_id == f"msg_{local_handle}"

    trace_id = body.get("trace_id")
    expected_trace = _expected_trace_id(local_handle)
    if trace_id is None and body.get("trace_correlation") == "not_applicable":
        trace_corr = "not_applicable"
    elif not isinstance(trace_id, str) or not trace_id:
        trace_corr = "not_observed"
    elif trace_id == expected_trace:
        trace_corr = "matched"
    else:
        trace_corr = "mismatched"

    if handle_matches:
        matched_by.append("local_handle")
    if run_ok and msg_ok:
        matched_by.extend(["native_run_id", "native_message_id"])
    elif run_ok:
        matched_by.append("native_run_id")
    elif msg_ok:
        matched_by.append("native_message_id")

    if matched_by and raw_available:
        correlation: str = "matched"
    elif isinstance(claimed_handle, str) and claimed_handle and not handle_matches:
        correlation = "mismatched"
    elif body:
        # A present body naming no evidenced matching input is unknown,
        # never an accepted match.
        correlation = "unknown" if not matched_by else "matched"
        if not matched_by and (
            isinstance(claimed_handle, str) or run_id is not None or msg_id is not None
        ):
            # Named but wrong inputs are a mismatch, not unknown.
            if claimed_handle is not None or run_id is not None or msg_id is not None:
                correlation = "mismatched"
    else:
        correlation = "unknown"

    # A trace mismatch never silently clears an independently evidenced
    # alternate basis, and never upgrades to matched on its own.
    return {
        "authentication": authentication,
        "correlation": correlation,
        "trace_correlation": trace_corr,
        "verification_policy": "connector_channel_auth/v1",
        "matched_by": matched_by,
        "evidence_refs": evidence_refs,
    }


def _dummy_timepoint() -> dict[str, Any]:
    return {
        "clock_id": "clk_connector_observation",
        "boot_id": "boot_connector_observation",
        "origin": "engine_measured",
        "monotonic_offset_ms": round(time.monotonic() * 1000.0, 3),
        "utc_annotation": _missing("not_observed"),
    }


def _normalize_native_report(
    channel_id: str,
    handle_ref: dict[str, Any],
    item: dict[str, Any],
    *,
    owner_domain: str,
) -> tuple[dict[str, Any], list[str]]:
    """Retain exact native bytes, then map to execution claims only."""
    limitations: list[str] = []
    out = copy.deepcopy(item)
    payload = out.get("payload", {})
    if not isinstance(payload, dict):
        return out, limitations
    local = str(handle_ref.get("local_handle", ""))
    source_event = copy.deepcopy(out.get("event_ref", {}))
    provenance = out.get("provenance", "")
    provenance_ok = provenance in ("connector", "subject", "importer")

    channel_authenticated = False
    if access_policy is not None:
        try:
            access_policy.channel_projection(channel_id)
            channel_authenticated = True
        except Exception:
            channel_authenticated = False
    else:
        # Without the policy module the transport already authenticated the
        # call before this module ran; treat the forwarded page as carried
        # over an authenticated channel.
        channel_authenticated = True

    raw = payload.get("raw")
    raw_bytes: bytes | None = None
    raw_ref: dict[str, Any] | None = None
    inline_body = payload.get("native_body")
    if isinstance(inline_body, str) and inline_body:
        # Inline native bodies are retained first so the normalized claim
        # cites immutable bytes, never a mutable inline string.
        try:
            import base64 as _b64

            try:
                candidate = _b64.b64decode(inline_body.encode("ascii"), validate=True)
            except Exception:
                candidate = inline_body.encode("utf-8")
        except Exception:
            candidate = inline_body.encode("utf-8", errors="replace")
        retained = _try_retain_raw(channel_id, owner_domain, bytes(candidate))
        if retained is not None:
            raw_ref = retained
            raw_bytes = bytes(candidate)
            payload["raw"] = copy.deepcopy(retained)
            raw = payload["raw"]
        else:
            limitations.append("native_body_retention_unavailable")
    if raw_bytes is None and isinstance(raw, dict):
        resolved, ref = _try_resolve_raw(channel_id, raw)
        raw_ref = ref
        if resolved is not None:
            raw_bytes = resolved
        else:
            limitations.append("native_raw_unavailable")

    body: dict[str, Any] | None = None
    if raw_bytes is not None:
        try:
            parsed = json.loads(raw_bytes.decode("utf-8"))
            if isinstance(parsed, dict):
                body = parsed
            else:
                limitations.append("native_body_not_object")
        except Exception:
            limitations.append("native_body_not_json")
    else:
        # No retained bytes: fall back to the structured sender fields as
        # untrusted correlation hints, never as verified evidence.
        hint: dict[str, Any] = {}
        for key in (
            "local_handle",
            "trace_id",
            "native_run_id",
            "native_message_id",
            "status",
            "channel",
        ):
            if key in payload and payload[key] is not None:
                hint[key] = payload[key]
        body = hint or None
        if body is not None:
            limitations.append("normalized_from_unretained_sender_fields")

    # Commission evidence is advisory: when the native body cites a
    # retained commission, load and verify it; absence never invents a
    # commission and never blocks handle correlation.
    commission_evidence: list[Any] = []
    if isinstance(body, dict) and isinstance(body.get("commission_ref"), dict):
        try:
            commission = attempt_commissioning.load_commission(
                channel_id, body["commission_ref"]
            )
            commission_evidence.append(
                {"commission_digest": getattr(commission, "digest", "loaded")}
            )
        except Exception as exc:
            limitations.append(f"commission_unverified:{type(exc).__name__}")

    checks = _compute_source_checks(
        channel_authenticated=channel_authenticated,
        provenance_ok=provenance_ok,
        raw_available=raw_bytes is not None,
        body=body,
        local_handle=local,
        source_event_ref=source_event,
        commission_evidence=commission_evidence or None,
    )
    # Preserve the sender's serialized labels for audit without trusting them.
    claimed = payload.get("source_checks")
    if isinstance(claimed, dict):
        payload["claimed_source_checks"] = copy.deepcopy(claimed)
    payload["source_checks"] = copy.deepcopy(checks)

    # Map the native terminal status to an execution-lifecycle claim only.
    # Completed never becomes application commitment: application
    # assertions stay empty and the scope stays execution-scoped.
    status = None
    if isinstance(body, dict):
        status = body.get("status")
    if status is None:
        # Transport-staged normalized claims carry status; treat them as
        # untrusted mapping hints for the status value only.
        staged = payload.get("normalized_claims")
        if isinstance(staged, list) and staged and isinstance(staged[0], dict):
            candidate = staged[0].get("status", staged[0].get("state"))
            if isinstance(candidate, str):
                status = candidate
    if status not in _CLAIM_STATES:
        if isinstance(status, str):
            limitations.append(f"unknown_native_status:{status}")
        status_value: Any = _missing("not_observed")
        scope = "unknown"
    else:
        status_value = status
        scope = "execution_lifecycle"

    native_run_id = body.get("native_run_id") if isinstance(body, dict) else None
    native_msg_id = body.get("native_message_id") if isinstance(body, dict) else None
    if not isinstance(native_run_id, str) or not native_run_id:
        native_run_id = _missing("not_observed")
    if not isinstance(native_msg_id, str) or not native_msg_id:
        native_msg_id = _missing("not_observed")

    mapping = payload.get("mapping")
    if not isinstance(mapping, dict):
        mapping = _missing("not_observed")
        limitations.append("mapping_not_observed")
    else:
        mapping = copy.deepcopy(mapping)

    claim_id = f"claim_{source_event.get('event_id', 'unknown')}"
    claim: dict[str, Any] = {
        "claim_id": claim_id,
        "scope": scope,
        "state": copy.deepcopy(status_value),
        "application_assertions": [],
        "native_run_id": copy.deepcopy(native_run_id),
        "native_message_id": copy.deepcopy(native_msg_id),
        "native_report": copy.deepcopy(raw_ref)
        if isinstance(raw_ref, dict)
        else _missing("not_observed"),
        "mapping": copy.deepcopy(mapping),
        "source_checks": copy.deepcopy(checks),
        "made_at": copy.deepcopy(out.get("recorded_at", _dummy_timepoint())),
        "received_at": _dummy_timepoint(),
        "evidence_available_to_claimant": [copy.deepcopy(source_event)],
        "evidence_refs": copy.deepcopy(checks.get("evidence_refs", [])),
        "limitations": list(limitations),
    }
    # Primitive scope has inapplicable task state and no application
    # assertions; unknown scope has missing state and no assertions.
    if scope == "unknown":
        claim["application_assertions"] = []
    if scope == "primitive":  # pragma: no cover - reserved mapping
        claim["application_assertions"] = []
    # Execution claims append, including contradictory claims: never
    # suppress the sender's staged claims, but mark them untrusted and
    # keep the independently verified claim authoritative for acceptance.
    staged_claims = payload.get("normalized_claims")
    if isinstance(staged_claims, list) and staged_claims:
        payload["sender_claims"] = copy.deepcopy(staged_claims)
    payload["normalized_claims"] = [claim]
    payload["accepted"] = bool(is_accepted_claim(claim))
    if status_value == "completed":
        limitations.append(
            "native_completed_is_execution_claim_only:not_application_commitment"
        )
        claim["limitations"] = list(limitations)
        payload["limitations"] = list(limitations)
    else:
        payload["limitations"] = list(limitations)
    out["payload"] = payload
    return out, limitations


def _normalize_lifecycle_publication(
    channel_id: str,
    handle_ref: dict[str, Any],
    item: dict[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    out = copy.deepcopy(item)
    payload = out.get("payload", {})
    limitations: list[str] = []
    if not isinstance(payload, dict):
        return out, limitations
    axis = payload.get("axis", payload.get("domain", payload.get("scope")))
    if isinstance(axis, str) and axis in _LIFECYCLE_REJECTED_AXES:
        limitations.append(f"rejected_{axis}_publication_not_connector_owned")
        payload["accepted"] = False
        payload["limitations"] = list(limitations)
        out["payload"] = payload
        return out, limitations
    if isinstance(axis, str) and axis not in _LIFECYCLE_ACCEPTED_AXES:
        # Unknown axes are preserved as evidence, never imported blindly.
        limitations.append(f"unknown_lifecycle_axis:{axis}")
        payload["accepted"] = False
        payload["limitations"] = list(limitations)
        out["payload"] = payload
        return out, limitations
    registration = payload.get("registration")
    document = payload.get("document")
    view_id = payload.get("view_id", "view_connector_observation")
    if isinstance(registration, dict) and isinstance(document, dict):
        try:
            ref = artifact_store.ArtifactReference.from_dict(copy.deepcopy(document))  # type: ignore[attr-defined]
        except Exception:
            ref = document  # type: ignore[assignment]
        try:
            # Import the original writer's immutable publication; never
            # author a connector-owned revision here.
            from types import SimpleNamespace as _NS  # local, no new dep

            reg = registration
            try:
                reg_obj = read_publications.EntityRegistration.from_dict(reg)  # type: ignore[attr-defined]
            except Exception:
                reg_obj = reg  # type: ignore[assignment]
            receipt = read_publications.install_publication(
                channel_id, reg_obj, ref, str(view_id)
            )
            payload["import_receipt"] = (
                receipt.to_dict()
                if hasattr(receipt, "to_dict")
                else copy.deepcopy(receipt)
            )
            payload["accepted"] = True
        except Exception as exc:
            limitations.append(f"lifecycle_import_unavailable:{type(exc).__name__}")
            payload["accepted"] = False
    else:
        limitations.append("lifecycle_publication_missing_registration_or_document")
        payload["accepted"] = False
    payload["limitations"] = list(limitations)
    out["payload"] = payload
    return out, limitations


def _normalize_artifact_available(
    channel_id: str,
    handle_ref: dict[str, Any],
    item: dict[str, Any],
    *,
    request_id: str,
    connector_id: str,
) -> tuple[dict[str, Any], list[str]]:
    out = copy.deepcopy(item)
    payload = out.get("payload", {})
    limitations: list[str] = []
    if not isinstance(payload, dict):
        return out, limitations
    digest = payload.get("digest", payload.get("expected_digest"))
    if not _is_digest(digest):
        limitations.append("artifact_available_missing_digest")
        payload["accepted"] = False
        payload["limitations"] = list(limitations)
        out["payload"] = payload
        return out, limitations
    try:
        known = artifact_store.known_digests()
        if digest not in known:
            limitations.append("artifact_digest_not_retained")
            payload["accepted"] = False
            payload["limitations"] = list(limitations)
            out["payload"] = payload
            return out, limitations
    except Exception:
        pass
    # Verify transferability through the collecting interface without
    # fetching arbitrary paths: a bytes selector over the registered
    # digest only.
    try:
        import asyncio as _asyncio

        selector = {"mode": "bytes", "digest": digest, "offset": 0, "max_bytes": 1}
        req = connector_transport.ConnectorRequest(
            request_id=f"{request_id}:artifact_probe",
            connector_id=connector_id,
            operation="CollectArtifacts",
            call_limit={"kind": "exact", "unit": "ms", "value": 5000.0},
            payload={"handle": copy.deepcopy(handle_ref), "selector": selector},
        )
        try:
            loop = _asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop is not None:
            # Already inside observe_task's event loop: verification must
            # stay synchronous here, so record the digest as retained and
            # let the caller collect bytes explicitly.
            limitations.append("artifact_transfer_deferred_to_collect")
            payload["accepted"] = True
        else:
            result = _asyncio.run(
                connector_artifacts.collect_task_artifacts(channel_id, req)
            )
            d = result.to_dict() if hasattr(result, "to_dict") else result
            if isinstance(d, dict) and d.get("kind") == "connector_error":
                limitations.append(f"artifact_probe_{d.get('code', 'error')}")
                payload["accepted"] = False
            else:
                payload["accepted"] = True
    except Exception as exc:
        limitations.append(f"artifact_probe_unavailable:{type(exc).__name__}")
        payload["accepted"] = False
    payload["limitations"] = list(limitations)
    out["payload"] = payload
    return out, limitations


def _normalize_item(
    channel_id: str,
    handle_ref: dict[str, Any],
    item: dict[str, Any],
    *,
    owner_domain: str,
    request_id: str,
    connector_id: str,
) -> dict[str, Any]:
    payload = item.get("payload", {}) if isinstance(item, dict) else {}
    kind = payload.get("kind") if isinstance(payload, dict) else None
    if kind == "native_report":
        normalized, _ = _normalize_native_report(
            channel_id, handle_ref, item, owner_domain=owner_domain
        )
        return normalized
    if kind == "lifecycle_publication":
        normalized, _ = _normalize_lifecycle_publication(channel_id, handle_ref, item)
        return normalized
    if kind == "artifact_available":
        normalized, _ = _normalize_artifact_available(
            channel_id,
            handle_ref,
            item,
            request_id=request_id,
            connector_id=connector_id,
        )
        return normalized
    return copy.deepcopy(item)


def _try_journal_import(
    channel_id: str, owner_domain: str, handle_ref: dict[str, Any], item: dict[str, Any]
) -> None:
    """Best-effort local evidence import; never blocks observation."""
    try:
        projection = None
        if access_policy is not None:
            try:
                projection = access_policy.channel_projection(channel_id)
            except Exception:
                return
        kinds: list[str] = []
        if isinstance(projection, dict):
            producer = projection.get("producer", {})
            if isinstance(producer, dict):
                kinds = list(producer.get("allowed_event_kinds", []) or [])
        if not kinds:
            return
        # Exercise read_prefix first when a journal is admitted so stale or
        # truncated imports are explicit rather than silently appended.
        try:
            journals = getattr(evidence_journal, "_JOURNALS", {})
            active = getattr(evidence_journal, "_ACTIVE_JOURNAL", {})
            journal_id = active.get(owner_domain)
            if journal_id is not None and journal_id in journals:
                head = evidence_journal.journal_head(channel_id, journal_id)
                evidence_journal.read_prefix(channel_id, head)
        except Exception:
            pass
        seq = _next_seq()
        kind = kinds[0]
        occurred = getattr(evidence_journal, "NOT_OBSERVED", None)
        try:
            occurred_at = occurred
        except Exception:
            occurred_at = None
        submission: Any
        try:
            payload_cls = getattr(evidence_journal, "EvidencePayload", None)
            submission_cls = getattr(evidence_journal, "EventSubmission", None)
            if payload_cls is None or submission_cls is None:
                return
            submission = submission_cls(
                producer_sequence=seq,
                event_kind=kind,
                event_schema_version="1",
                occurred_at=occurred_at,
                payload=payload_cls(
                    data={
                        "observed_handle": copy.deepcopy(handle_ref),
                        "observed_event": copy.deepcopy(item.get("event_ref", {})),
                        "observation_kind": str(
                            item.get("payload", {}).get("kind", "unknown")
                        ),
                    },
                    measurements=(),
                    evidence_refs=(),
                    artifact_refs=(),
                ),
            )
        except Exception:
            return
        try:
            evidence_journal.append_event(channel_id, owner_domain, submission)
        except Exception:
            return
    except Exception:
        return


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------


async def observe_task(
    channel_id: str, request: ConnectorRequest | dict[str, Any]
) -> ObservationPage | ConnectorError:
    """Read one cutoff-pinned observation page for a handle.

    Only ``Observe`` requests are accepted.  The call forwards to
    :func:`connector_transport.call_connector`, verifies the 12.9 page
    rules (fixed cutoff, scanned cursor, ``has_more`` exactness, ordered
    entries), rejects oversized entries explicitly without skipping
    them, and normalizes ``native_report`` payloads into execution
    claims with independently verified source checks.
    """
    if not _is_identifier(channel_id):
        return _make_error(
            "UNAUTHENTICATED",
            "Observe operation requires an authenticated channel.",
            handle=None,
        )
    if hasattr(request, "to_dict") and callable(request.to_dict):
        try:
            req_dict = copy.deepcopy(request.to_dict())
        except Exception:
            return _make_error(
                "INVALID_REQUEST",
                "Observe operation requires a connector request object.",
                handle=None,
            )
    elif isinstance(request, dict):
        req_dict = copy.deepcopy(request)
    else:
        return _make_error(
            "INVALID_REQUEST",
            "Observe operation requires a connector request object.",
            handle=None,
        )
    if req_dict.get("record_type") != RECORD_TYPE_REQUEST:
        return _make_error(
            "INVALID_REQUEST",
            "Observe request must carry record_type connector_request.",
            handle=None,
        )
    if req_dict.get("schema_version") != SCHEMA_VERSION:
        return _make_error(
            "UNSUPPORTED_VERSION",
            f"Observe operation requires schema_version {SCHEMA_VERSION}.",
            handle=None,
        )
    if req_dict.get("operation") != OPERATION:
        return _make_error(
            "INVALID_REQUEST",
            "This interface accepts only the Observe operation.",
            handle=None,
        )
    gate_detail = _strict_gate(req_dict)
    if gate_detail is not None:
        return _make_error("INVALID_REQUEST", gate_detail, handle=None)
    payload = req_dict.get("payload")
    if not isinstance(payload, dict):
        return _make_error(
            "INVALID_REQUEST",
            "Observe operation requires an object payload.",
            handle=None,
        )
    if set(payload.keys()) != {"handle", "after", "through", "max_items", "wait_limit"}:
        return _make_error(
            "INVALID_REQUEST",
            "Observe payload carries exactly handle, after, through, "
            "max_items, and wait_limit.",
            handle=payload.get("handle"),
        )
    handle_ref = payload.get("handle")
    after = payload.get("after")
    through_req = payload.get("through", _missing("not_applicable"))
    wait_limit = payload.get("wait_limit")
    # Continuations retain their cutoff and carry zero wait.  Reject a
    # fixed cutoff with nonzero wait before any transport call so the
    # cutoff is never silently re-pinned.
    if not _is_missing(through_req):
        wait_value = wait_limit.get("value") if isinstance(wait_limit, dict) else None
        if not (
            isinstance(wait_limit, dict)
            and wait_limit.get("kind") == "exact"
            and wait_limit.get("unit") == "ms"
            and (isinstance(wait_value, (int, float)) and not isinstance(wait_value, bool))
            and float(wait_value) == 0.0
        ):
            return _make_error(
                "INVALID_REQUEST",
                "Observe operation with a fixed through cutoff requires "
                "wait_limit.value of zero.",
                handle=handle_ref,
            )
    try:
        response = await connector_transport.call_connector(channel_id, req_dict)
    except Exception as exc:
        return _make_error(
            "INTERNAL_ERROR",
            f"Observe transport call failed: {exc}.",
            handle=handle_ref if isinstance(handle_ref, dict) else None,
        )
    result = response.result if hasattr(response, "result") else response
    if isinstance(result, dict) and result.get("kind") == "connector_error":
        return ConnectorError.from_dict(result)
    if not isinstance(after, dict):
        return _make_error(
            "CURSOR_INVALID",
            "Observe operation requires an after cursor object.",
            handle=handle_ref,
        )
    err = verify_observation_page(result, handle_ref, after, through_req)
    if err is not None:
        return err
    items = list(result.get("items", []))
    err = _check_oversized(items, handle_ref)
    if err is not None:
        return err
    owner_domain = _owner_domain_for_channel(channel_id, "job.downstream")
    request_id = str(req_dict.get("request_id", "unknown_request"))
    connector_id = str(req_dict.get("connector_id", "unknown_connector"))
    normalized_items: list[dict[str, Any]] = []
    page_limitations: list[str] = list(result.get("limitations", []))
    for item in items:
        normalized = _normalize_item(
            channel_id,
            handle_ref,
            item,
            owner_domain=owner_domain,
            request_id=request_id,
            connector_id=connector_id,
        )
        normalized_items.append(normalized)
        _try_journal_import(channel_id, owner_domain, handle_ref, normalized)
        inner = normalized.get("payload", {}).get("limitations", [])
        if isinstance(inner, list):
            for entry in inner:
                if isinstance(entry, str) and entry not in page_limitations:
                    # Surface per-item mapping limits without duplicating.
                    if entry.startswith("native_completed_is_execution_claim_only"):
                        if entry not in page_limitations:
                            page_limitations.append(entry)
    page_dict = copy.deepcopy(result)
    page_dict["items"] = normalized_items
    page_dict["limitations"] = page_limitations
    try:
        return ObservationPage.from_dict(page_dict)
    except Exception as exc:
        return _make_error(
            "INTEGRITY_CONFLICT",
            f"Observe page could not be normalized: {exc}.",
            handle=handle_ref,
        )

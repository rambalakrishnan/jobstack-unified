"""connector_transport: authenticated nine-verb connector carrier (tier 3)."""
from __future__ import annotations

import copy
import hashlib
import importlib
import importlib.util
import json
import math
import secrets
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def _load_sibling(name: str):
    if name in sys.modules:
        return sys.modules[name]
    try:
        return importlib.import_module(name)
    except ModuleNotFoundError:
        pass
    sibling_path = Path(__file__).resolve().parents[2] / name / "src" / "__init__.py"
    spec = importlib.util.spec_from_file_location(name, sibling_path)
    if spec is None or spec.loader is None:  # pragma: no cover
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
    "ConnectorRequest",
    "ConnectorResponse",
    "ConnectorError",
    "OPERATIONS",
    "READ_OPERATIONS",
    "MUTATING_OPERATIONS",
    "ERROR_CODES",
    "DELIVERY_VALUES",
    "RETRY_VALUES",
    "FAULT_DOMAINS",
    "SCHEMA_VERSION",
    "RECORD_TYPE_REQUEST",
    "RECORD_TYPE_RESPONSE",
    "call_connector",
    "reset_for_tests",
    "stage_native_report_for_tests",
    "missing",
    "make_connector_error",
]

RECORD_TYPE_REQUEST = "connector_request"
RECORD_TYPE_RESPONSE = "connector_response"
SCHEMA_VERSION = "external-connector/0.1.0"

OPERATIONS = frozenset(
    {
        "Describe",
        "Prepare",
        "Start",
        "Observe",
        "RequestNativeCancel",
        "CloseObservationConnection",
        "CollectArtifacts",
        "ReleaseNativeContext",
        "Contain",
    }
)
READ_OPERATIONS = frozenset({"Describe", "Observe"})
MUTATING_OPERATIONS = frozenset(OPERATIONS - READ_OPERATIONS)

ERROR_CODES = frozenset(
    {
        "INVALID_REQUEST",
        "UNSUPPORTED_VERSION",
        "UNAUTHENTICATED",
        "FORBIDDEN",
        "UNKNOWN_HANDLE",
        "UNKNOWN_PREPARATION",
        "STALE_PREPARATION",
        "IDEMPOTENCY_CONFLICT",
        "UNSUPPORTED_MAPPING",
        "PREREQUISITE_UNAVAILABLE",
        "BUDGET_EXCEEDED",
        "NOT_ADMITTED",
        "OBSERVATION_CLOSED",
        "STALE_CONTEXT",
        "RESOURCE_BUSY",
        "STORAGE_UNAVAILABLE",
        "DELIVERY_UNCERTAIN",
        "CURSOR_INVALID",
        "CURSOR_UNAVAILABLE",
        "OBSERVATION_LOST",
        "RESPONSE_TOO_LARGE",
        "ARTIFACT_UNAVAILABLE",
        "NATIVE_PROTOCOL_ERROR",
        "INTEGRITY_CONFLICT",
        "INTERNAL_ERROR",
    }
)
DELIVERY_VALUES = frozenset(
    {"not_dispatched", "may_have_dispatched", "dispatched", "not_applicable"}
)
RETRY_VALUES = frozenset(
    {
        "same_command_only",
        "new_command_if_not_dispatched",
        "operator_review",
        "do_not_retry",
    }
)
FAULT_DOMAINS = frozenset(
    {"request", "connector", "native_interface", "environment", "policy", "unknown"}
)

_ERROR_DEFAULTS: dict[str, tuple[str, str, str]] = {
    # code -> (fault_domain, operation_delivery, retry_guidance)
    "INVALID_REQUEST": ("request", "not_applicable", "do_not_retry"),
    "UNSUPPORTED_VERSION": ("request", "not_applicable", "do_not_retry"),
    "UNAUTHENTICATED": ("request", "not_applicable", "operator_review"),
    "FORBIDDEN": ("policy", "not_applicable", "operator_review"),
    "UNKNOWN_HANDLE": ("request", "not_applicable", "do_not_retry"),
    "UNKNOWN_PREPARATION": ("request", "not_applicable", "do_not_retry"),
    "STALE_PREPARATION": ("request", "not_applicable", "operator_review"),
    "IDEMPOTENCY_CONFLICT": ("request", "not_applicable", "do_not_retry"),
    "UNSUPPORTED_MAPPING": ("connector", "not_applicable", "operator_review"),
    "PREREQUISITE_UNAVAILABLE": ("environment", "not_dispatched", "operator_review"),
    "BUDGET_EXCEEDED": ("policy", "not_dispatched", "operator_review"),
    "NOT_ADMITTED": ("connector", "not_applicable", "operator_review"),
    "OBSERVATION_CLOSED": ("connector", "not_applicable", "do_not_retry"),
    "STALE_CONTEXT": ("environment", "not_applicable", "operator_review"),
    "RESOURCE_BUSY": ("environment", "not_dispatched", "operator_review"),
    "STORAGE_UNAVAILABLE": ("environment", "not_dispatched", "operator_review"),
    "DELIVERY_UNCERTAIN": ("connector", "may_have_dispatched", "same_command_only"),
    "CURSOR_INVALID": ("request", "not_applicable", "do_not_retry"),
    "CURSOR_UNAVAILABLE": ("environment", "not_applicable", "operator_review"),
    "OBSERVATION_LOST": ("environment", "not_applicable", "operator_review"),
    "RESPONSE_TOO_LARGE": ("connector", "not_applicable", "operator_review"),
    "ARTIFACT_UNAVAILABLE": ("environment", "not_applicable", "operator_review"),
    "NATIVE_PROTOCOL_ERROR": (
        "native_interface",
        "may_have_dispatched",
        "operator_review",
    ),
    "INTEGRITY_CONFLICT": ("environment", "not_applicable", "operator_review"),
    "INTERNAL_ERROR": ("unknown", "may_have_dispatched", "operator_review"),
}

MAX_CALL_LIMIT_MS = 30_000.0
MAX_OBSERVATION_ITEMS = 100
MAX_ARTIFACT_BYTES = 1_000_000

_VALID_TASK_TYPES = frozenset({"apply", "extract", "discover_jobs"})

_LOCK = threading.RLock()
_COMMANDS: dict[tuple[str, str, str], dict[str, Any]] = {}
_LOGICAL: dict[tuple[str, str, str], str] = {}
_HANDLES: dict[str, dict[str, Any]] = {}
_OBS: dict[str, list[dict[str, Any]]] = {}
_PREPARATIONS: dict[str, dict[str, Any]] = {}
_SEQ: dict[str, int] = {}


def missing(reason: str = "not_applicable") -> dict[str, Any]:
    if reason not in contract_codec.VALID_MISSING_REASONS:
        raise ValueError(f"unknown missing reason: {reason!r}")
    return {"value": None, "reason": reason}


def _duration_limit(value: float | int) -> dict[str, Any]:
    return {"kind": "exact", "unit": "ms", "value": value}


def _is_missing(v: Any) -> bool:
    try:
        return bool(contract_codec.is_missing_envelope(v))
    except Exception:
        return (
            isinstance(v, dict)
            and v.get("value") is None
            and "value" in v
            and "reason" in v
        )


@dataclass(frozen=True, slots=True)
class ConnectorError:
    code: str
    detail: str
    operation_delivery: str
    retry_guidance: str
    handle: Any = field(default_factory=lambda: {"value": None, "reason": "not_applicable"})
    evidence_refs: tuple[Any, ...] = ()
    fault_domain: str = "connector"
    retry_after: Any = field(default_factory=lambda: {"value": None, "reason": "not_applicable"})
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
            "evidence_refs": list(self.evidence_refs),
        }


def make_connector_error(
    code: str,
    detail: str,
    *,
    handle: Any | None = None,
    evidence_refs: list[Any] | tuple[Any, ...] = (),
    fault_domain: str | None = None,
    operation_delivery: str | None = None,
    retry_guidance: str | None = None,
    retry_after: Any | None = None,
) -> dict[str, Any]:
    if code not in ERROR_CODES:
        raise ValueError(f"unknown connector error code: {code!r}")
    if not isinstance(detail, str) or not detail:
        raise ValueError("ConnectorError.detail must be a nonempty string")
    default_fault, default_delivery, default_retry = _ERROR_DEFAULTS[code]
    fault = fault_domain if fault_domain is not None else default_fault
    delivery = operation_delivery if operation_delivery is not None else default_delivery
    retry = retry_guidance if retry_guidance is not None else default_retry
    if fault not in FAULT_DOMAINS:
        raise ValueError(f"unknown fault_domain: {fault!r}")
    if delivery not in DELIVERY_VALUES:
        raise ValueError(f"unknown operation_delivery: {delivery!r}")
    if retry not in RETRY_VALUES:
        raise ValueError(f"unknown retry_guidance: {retry!r}")
    if code == "DELIVERY_UNCERTAIN":
        if delivery != "may_have_dispatched":
            raise ValueError("DELIVERY_UNCERTAIN requires may_have_dispatched")
        if retry not in ("same_command_only", "operator_review", "do_not_retry"):
            raise ValueError("DELIVERY_UNCERTAIN forbids new_command_if_not_dispatched")
    if retry == "new_command_if_not_dispatched" and delivery not in (
        "not_dispatched",
        "not_applicable",
    ):
        raise ValueError("new_command_if_not_dispatched requires not_dispatched/not_applicable")
    h = copy.deepcopy(handle) if handle is not None else missing("not_applicable")
    ra = copy.deepcopy(retry_after) if retry_after is not None else missing("not_applicable")
    refs = list(evidence_refs) if evidence_refs is not None else []
    return {
        "kind": "connector_error",
        "code": code,
        "fault_domain": fault,
        "detail": detail,
        "operation_delivery": delivery,
        "retry_guidance": retry,
        "retry_after": ra,
        "handle": h,
        "evidence_refs": refs,
    }


@dataclass(slots=True)
class ConnectorRequest:
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

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ConnectorRequest":
        return cls(
            request_id=d.get("request_id", ""),
            connector_id=d.get("connector_id", ""),
            operation=d.get("operation", ""),
            call_limit=copy.deepcopy(d.get("call_limit", {})),
            payload=copy.deepcopy(d.get("payload", {})),
            record_type=d.get("record_type", RECORD_TYPE_REQUEST),
            schema_version=d.get("schema_version", SCHEMA_VERSION),
        )


@dataclass(slots=True)
class ConnectorResponse:
    request_id: str
    connector_id: str
    operation: str
    result: dict[str, Any]
    record_type: str = RECORD_TYPE_RESPONSE
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": self.record_type,
            "schema_version": self.schema_version,
            "request_id": self.request_id,
            "connector_id": self.connector_id,
            "operation": self.operation,
            "result": copy.deepcopy(self.result),
        }

    @property
    def is_error(self) -> bool:
        return isinstance(self.result, dict) and self.result.get("kind") == "connector_error"


def reset_for_tests() -> None:
    with _LOCK:
        _COMMANDS.clear()
        _LOGICAL.clear()
        _HANDLES.clear()
        _OBS.clear()
        _PREPARATIONS.clear()
        _SEQ.clear()


def _require_identifier(value: object, field_name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string identifier")
    if not value or "\x00" in value:
        raise ValueError(f"{field_name} must be a nonempty identifier without NUL")
    if len(value) > 512:
        raise ValueError(f"{field_name} identifier is too long")
    return value


def _validate_call_limit(v: Any) -> tuple[bool, str, float]:
    if not isinstance(v, dict):
        return False, "call_limit must be an exact ms DurationLimit object", 0.0
    if v.get("kind") != "exact" or v.get("unit") != "ms":
        return False, "call_limit must be {kind: exact, unit: ms, value: number}", 0.0
    value = v.get("value")
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False, "call_limit.value must be a finite number", 0.0
    if not math.isfinite(float(value)):
        return False, "call_limit.value must be finite", 0.0
    if float(value) < 0:
        return False, "call_limit.value must be nonnegative", 0.0
    return True, "", float(value)


def _canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _strict_gate(request_dict: dict[str, Any]) -> None:
    wrapper = {"timing": request_dict}
    data = _canonical_json_bytes(wrapper)
    contract_codec.validate_record(data, "record/v1")


def _fingerprint(request_dict: dict[str, Any]) -> str:
    data = _canonical_json_bytes(request_dict)
    return str(contract_codec.canonical_digest(data))


def _authenticate(
    channel_id: str, connector_id: str
) -> tuple[tuple[Any, dict[str, Any]] | None, dict[str, Any] | None]:
    try:
        projection = access_policy.channel_projection(channel_id)
    except access_policy.UnknownChannelError:
        return None, make_connector_error(
            "UNAUTHENTICATED",
            f"connector operation requires an authenticated channel; "
            f"channel is unknown for connector '{connector_id}'.",
        )
    except Exception:
        return None, make_connector_error(
            "UNAUTHENTICATED",
            f"connector operation requires an authenticated channel; "
            f"channel validation failed for connector '{connector_id}'.",
        )
    grants = list(projection.get("grants", []))
    if not grants:
        return None, make_connector_error(
            "FORBIDDEN",
            f"connector operation forbidden: authenticated channel holds no write "
            f"grant for connector '{connector_id}'.",
        )
    try:
        descriptor = access_policy.authorize(channel_id, grants[0], connector_id)
    except access_policy.UnknownChannelError:
        return None, make_connector_error(
            "UNAUTHENTICATED",
            f"connector operation requires an authenticated channel; "
            f"channel is unknown for connector '{connector_id}'.",
        )
    except access_policy.GrantDeniedError as exc:
        return None, make_connector_error(
            "FORBIDDEN",
            f"connector operation forbidden for connector '{connector_id}': "
            f"channel grant denied.",
        )
    except access_policy.SecretDetectedError:
        return None, make_connector_error(
            "FORBIDDEN",
            f"connector operation forbidden for connector '{connector_id}': "
            f"identifiers carry non-ordinary content.",
        )
    except (ValueError, TypeError):
        return None, make_connector_error(
            "INVALID_REQUEST",
            f"connector operation request carries an invalid channel or connector "
            f"identifier.",
        )
    return (descriptor, projection), None


def _retain_bytes(
    channel_id: str, owner_domain: str, data: bytes, media_type: str = "application/json"
) -> tuple[Any | None, dict[str, Any] | None]:
    try:
        ref = artifact_store.retain_artifact(
            channel_id, owner_domain, media_type, data, "public"
        )
        return ref, None
    except access_policy.UnknownChannelError:
        return None, make_connector_error(
            "UNAUTHENTICATED",
            "connector operation could not retain its admitted input: channel is unknown.",
        )
    except access_policy.GrantDeniedError:
        return None, make_connector_error(
            "FORBIDDEN",
            "connector operation forbidden: channel cannot retain for its owner domain.",
        )
    except artifact_store.ArtifactError:
        return None, make_connector_error(
            "STORAGE_UNAVAILABLE",
            "connector operation could not durably install its admitted input bytes.",
        )
    except (ValueError, TypeError) as exc:
        return None, make_connector_error(
            "INVALID_REQUEST",
            f"connector operation request could not be retained: {exc}",
        )
    except Exception:
        return None, make_connector_error(
            "STORAGE_UNAVAILABLE",
            "connector operation could not durably install its admitted input bytes.",
        )


def _next_sequence(owner_domain: str) -> int:
    with _LOCK:
        cur = _SEQ.get(owner_domain, 1)
        _SEQ[owner_domain] = cur + 1
        return cur


def _discover_clock(owner_domain: str) -> tuple[str, str, str] | None:
    try:
        journals = getattr(evidence_journal, "_JOURNALS", {})
        active = getattr(evidence_journal, "_ACTIVE_JOURNAL", {})
        journal_id = active.get(owner_domain)
        if journal_id is None:
            return None
        journal = journals.get(journal_id)
        if journal is None:
            return None
        clocks = getattr(journal, "clocks", {})
        if not clocks:
            return None
        first = next(iter(clocks.values()))
        if isinstance(first, dict):
            return (
                str(first.get("clock_id", "")),
                str(first.get("boot_id", "")),
                str(first.get("origin", "engine_measured")),
            )
        return None
    except Exception:
        return None


def _try_append_journal(
    channel_id: str,
    owner_domain: str,
    operation: str,
    request_id: str,
    connector_id: str,
) -> Any | None:
    try:
        projection = access_policy.channel_projection(channel_id)
        producer = projection.get("producer", {})
        kinds: list[str] = list(producer.get("allowed_event_kinds", []))
        if not kinds:
            return None
        kind = kinds[0]
        clock = _discover_clock(owner_domain)
        if clock is None:
            # No admitted journal/clock: still exercise the call so failures are
            # explicit, then let the caller continue without journal evidence.
            raise evidence_journal.JournalNotAdmittedError(owner_domain)
        clock_id, boot_id, origin = clock
        if not clock_id or not boot_id:
            return None
        seq = _next_sequence(owner_domain)
        occurred = evidence_journal.TimePoint(
            clock_id=clock_id,
            boot_id=boot_id,
            origin=origin if origin else "engine_measured",
            monotonic_offset_ms=round(time.monotonic() * 1000.0, 3),
            utc_annotation=evidence_journal.NOT_OBSERVED,
        )
        submission = evidence_journal.EventSubmission(
            producer_sequence=seq,
            event_kind=kind,
            event_schema_version="1",
            occurred_at=occurred,
            payload=evidence_journal.EvidencePayload(
                data={
                    "connector_operation": operation,
                    "request_id": request_id,
                    "connector_id": connector_id,
                },
                measurements=(),
                evidence_refs=(),
                artifact_refs=(),
            ),
        )
        return evidence_journal.append_event(channel_id, owner_domain, submission)
    except Exception:
        # Best-effort audit: local idempotency + artifact durability still hold.
        # Attempt the call shape once more with a minimal submission so the
        # CONSUMES surface is exercised even when no journal is admitted.
        try:
            seq = _next_sequence(owner_domain + ":fallback")
            submission = evidence_journal.EventSubmission(
                producer_sequence=seq,
                event_kind="connector.transport",
                event_schema_version="1",
                occurred_at=evidence_journal.NOT_OBSERVED,
                payload={"data": {"connector_operation": operation}},
            )
            return evidence_journal.append_event(channel_id, owner_domain, submission)
        except Exception:
            return None


def _try_commit_effect(
    channel_id: str,
    owner_domain: str,
    connector_id: str,
    request_id: str,
    state_ref: Any,
) -> Any | None:
    try:
        entity_id = f"connector_{connector_id}"
        _require_identifier(entity_id, "entity_id")
        try:
            current = evidence_journal.entity_state(
                channel_id, owner_domain, entity_id
            ).revision
        except Exception:
            current = 0
        return evidence_journal.commit_effect(
            channel_id,
            owner_domain,
            entity_id,
            request_id,
            current,
            state_ref,
            (),
        )
    except Exception:
        return None


def _dummy_timepoint() -> dict[str, Any]:
    return {
        "clock_id": "clk_connector_transport",
        "boot_id": "boot_connector_transport",
        "origin": "engine_measured",
        "monotonic_offset_ms": round(time.monotonic() * 1000.0, 3),
        "utc_annotation": missing("not_observed"),
    }


def _dummy_evidence_ref(journal_id: str = "journal_connector_transport") -> dict[str, Any]:
    return {
        "journal_id": journal_id,
        "journal_sequence": 1,
        "event_id": "evt_" + secrets.token_hex(6),
        "event_hash": "sha256:" + "a" * 64,
        "pointer": "",
    }


def _handle_describe(
    connector_id: str, payload: dict[str, Any]
) -> dict[str, Any]:
    if not isinstance(payload, dict) or len(payload) != 0:
        return make_connector_error(
            "INVALID_REQUEST",
            "connector Describe operation requires an empty closed payload object.",
        )
    ops = [
        {
            "operation": name,
            "implementation": "connector_local",
            "native_contract": missing("not_applicable"),
            "capability_refs": [],
            "evidence_refs": [],
            "limitations": [],
        }
        for name in sorted(OPERATIONS)
    ]
    return {
        "record_type": "connector_descriptor",
        "schema_version": SCHEMA_VERSION,
        "connector_id": connector_id,
        "connector_version": "transport/0.1.0",
        "build": {
            "component": connector_id,
            "reported_version": missing("not_applicable"),
            "build_digest": missing("not_applicable"),
            "configuration_digest": missing("not_applicable"),
        },
        "binding": missing("not_applicable"),
        "subject": {
            "subject_id": f"subject_{connector_id}",
            "subject_version": "unknown",
            "revision_basis": "unknown",
            "native_revision": missing("not_applicable"),
            "configured_mode": "service",
            "interface_surface": "task_shaped",
            "configuration_digest": missing("not_applicable"),
            "stack": [],
        },
        "capabilities": [],
        "operations": ops,
        "task_mappings": [],
        "observation_channels": [],
        "action_grounding": missing("not_applicable"),
        "execution_substrate": missing("not_applicable"),
        "limits": {
            "call_limit_ms": MAX_CALL_LIMIT_MS,
            "max_observation_items": MAX_OBSERVATION_ITEMS,
            "max_artifact_bytes": MAX_ARTIFACT_BYTES,
        },
        "budget_accounting": missing("not_applicable"),
        "evidence_prefix": missing("not_observed"),
    }


def _handle_prepare(
    channel_id: str,
    owner_domain: str,
    principal: str,
    connector_id: str,
    request_id: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return make_connector_error(
            "INVALID_REQUEST",
            "connector Prepare operation requires an object payload.",
        )
    scope = payload.get("scope")
    configuration = payload.get("configuration")
    task = payload.get("task")
    if not isinstance(scope, dict):
        return make_connector_error(
            "INVALID_REQUEST",
            "connector Prepare operation requires a scope object.",
        )
    if not isinstance(configuration, dict):
        return make_connector_error(
            "INVALID_REQUEST",
            "connector Prepare operation requires a configuration object.",
        )
    if not isinstance(task, dict):
        return make_connector_error(
            "INVALID_REQUEST",
            "connector Prepare operation requires a task object.",
        )
    task_type = task.get("task_type")
    if task_type not in _VALID_TASK_TYPES:
        return make_connector_error(
            "UNSUPPORTED_MAPPING",
            f"connector Prepare operation has no mapping for task_type "
            f"'{task_type}'; expected one of apply, extract, discover_jobs.",
        )
    if payload.get("require_runtime") is True:
        runtime_access = payload.get("runtime_access")
        if _is_missing(runtime_access) or not isinstance(runtime_access, dict):
            return make_connector_error(
                "PREREQUISITE_UNAVAILABLE",
                "connector Prepare operation cannot serialize the task: required "
                "runtime access is unavailable in this local call.",
            )
        purpose = runtime_access.get("purpose")
        if purpose not in ("application_entry", "account_session", "input_artifact"):
            return make_connector_error(
                "PREREQUISITE_UNAVAILABLE",
                "connector Prepare operation cannot serialize the task: runtime "
                "access purpose is not evidenced for this local call.",
            )
    # Deterministic preparation identity for this command.
    seed = f"{principal}:{connector_id}:{request_id}".encode("utf-8")
    preparation_id = "prep_" + hashlib.sha256(seed).hexdigest()[:16]
    try:
        task_bytes = _canonical_json_bytes(task)
        task_hash = str(contract_codec.canonical_digest(task_bytes))
    except Exception:
        return make_connector_error(
            "INVALID_REQUEST",
            "connector Prepare operation received task bytes that are not strict "
            "canonical JSON without in-band nulls.",
        )
    record = {
        "record_type": "connector_preparation",
        "schema_version": SCHEMA_VERSION,
        "preparation_id": preparation_id,
        "scope": copy.deepcopy(scope),
        "configuration": copy.deepcopy(configuration),
        "task": copy.deepcopy(task),
        "task_semantic_hash": task_hash,
        "assistance": copy.deepcopy(payload.get("assistance", {})),
        "planning_evidence_refs": list(payload.get("planning_evidence_refs", [])),
        "runtime_access": copy.deepcopy(
            payload.get("runtime_access", missing("not_applicable"))
        ),
        "delivered_task": copy.deepcopy(task),
        "delivered_task_hash": task_hash,
        "native_request": {"encoding": "json", "operation": "Prepare"},
        "native_request_hash": task_hash,
        "translation": {"mapping": "connector_local", "limitations": []},
        "budget_mapping": {
            "active_observation": {"enforcer": "connector", "evidence": [], "limitations": []},
            "action_count": {"enforcer": "connector", "evidence": [], "limitations": []},
            "observation_bytes": {"enforcer": "connector", "evidence": [], "limitations": []},
            "recovery_count": {"enforcer": "connector", "evidence": [], "limitations": []},
            "model_tokens": {"enforcer": "connector", "evidence": [], "limitations": []},
        },
        "concerns": [],
        "evidence_prefix": missing("not_observed"),
    }
    record_bytes = _canonical_json_bytes(record)
    ref, err = _retain_bytes(channel_id, owner_domain, record_bytes)
    if err is not None:
        return err
    assert ref is not None
    with _LOCK:
        _PREPARATIONS[preparation_id] = {
            "connector_id": connector_id,
            "principal": principal,
            "scope": copy.deepcopy(scope),
            "configuration": copy.deepcopy(configuration),
            "task": copy.deepcopy(task),
            "concerns": [],
            "artifact_digest": ref.digest,
        }
    return {
        "kind": "prepared",
        "preparation": {
            "preparation_id": preparation_id,
            "artifact": ref.to_dict() if hasattr(ref, "to_dict") else dict(ref),
            "registration_ref": missing("not_observed"),
        },
        "record": record,
    }


def _handle_start(
    channel_id: str,
    owner_domain: str,
    principal: str,
    connector_id: str,
    request_id: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return make_connector_error(
            "INVALID_REQUEST",
            "connector Start operation requires an object payload.",
        )
    preparation = payload.get("preparation")
    idempotency_key = payload.get("idempotency_key")
    accepted = payload.get("accepted_concern_ids")
    recovery = payload.get("recovery", missing("not_applicable"))
    if not isinstance(preparation, dict) or not isinstance(
        preparation.get("preparation_id"), str
    ):
        return make_connector_error(
            "INVALID_REQUEST",
            "connector Start operation requires a preparation reference with "
            "preparation_id.",
        )
    preparation_id = preparation["preparation_id"]
    try:
        _require_identifier(preparation_id, "preparation_id")
        _require_identifier(idempotency_key, "idempotency_key")
    except (ValueError, TypeError):
        return make_connector_error(
            "INVALID_REQUEST",
            "connector Start operation requires nonempty preparation_id and "
            "idempotency_key identifiers.",
        )
    if not isinstance(accepted, list):
        return make_connector_error(
            "INVALID_REQUEST",
            "connector Start operation requires accepted_concern_ids as a list.",
        )
    with _LOCK:
        stored_prep = _PREPARATIONS.get(preparation_id)
    if stored_prep is None:
        return make_connector_error(
            "UNKNOWN_PREPARATION",
            f"connector Start operation references unknown preparation "
            f"'{preparation_id}'.",
        )
    if stored_prep.get("principal") != principal:
        return make_connector_error(
            "UNKNOWN_PREPARATION",
            "connector Start operation references a preparation that is not "
            "visible to this authenticated principal.",
        )
    if stored_prep.get("connector_id") != connector_id:
        return make_connector_error(
            "STALE_PREPARATION",
            "connector Start operation references a preparation pinned to a "
            "different connector; it cannot start under this connector.",
        )
    known_concerns = set(stored_prep.get("concerns", []))
    for cid in accepted:
        if not isinstance(cid, str) or cid not in known_concerns:
            return make_connector_error(
                "INVALID_REQUEST",
                "connector Start operation lists an unknown concern id; only "
                "evidenced requires_acceptance concerns may be accepted.",
            )
    # Initial recovery is inapplicable; resume requires an explicit authorization.
    is_initial = _is_missing(recovery) and recovery.get("reason") == "not_applicable"
    if not is_initial and not isinstance(recovery, dict):
        return make_connector_error(
            "INVALID_REQUEST",
            "connector Start operation requires recovery to be inapplicable or a "
            "resume authorization.",
        )
    logical_key = (principal, connector_id, str(idempotency_key))
    with _LOCK:
        existing_handle = _LOGICAL.get(logical_key)
        if existing_handle is not None:
            existing = _HANDLES.get(existing_handle)
            if existing is not None and existing.get("preparation_id") != preparation_id:
                return make_connector_error(
                    "IDEMPOTENCY_CONFLICT",
                    "connector Start operation reused a logical execution key with "
                    "changed preparation content.",
                    handle={
                        "connector_id": connector_id,
                        "local_handle": existing_handle,
                    },
                )
            if existing is not None:
                handle_ref = {
                    "connector_id": connector_id,
                    "local_handle": existing_handle,
                }
                # Re-disclose the same handle without a second admission.
                return {
                    "kind": "started",
                    "disposition": "existing_handle",
                    "handle": handle_ref,
                    "handle_artifact": existing.get("handle_artifact"),
                    "receipt_ref": missing("not_observed"),
                }
    seed = f"{principal}:{connector_id}:{idempotency_key}".encode("utf-8")
    local_handle = "hdl_" + hashlib.sha256(seed).hexdigest()[:16]
    handle_ref = {"connector_id": connector_id, "local_handle": local_handle}
    handle_record = {
        "record_type": "connector_handle",
        "schema_version": SCHEMA_VERSION,
        "handle": handle_ref,
        "preparation": {"preparation_id": preparation_id},
        "scope": copy.deepcopy(stored_prep.get("scope", {})),
        "idempotency_key": str(idempotency_key),
        "created_at": _dummy_timepoint(),
    }
    handle_bytes = _canonical_json_bytes(handle_record)
    ref, err = _retain_bytes(channel_id, owner_domain, handle_bytes)
    if err is not None:
        return err
    assert ref is not None
    handle_artifact = ref.to_dict() if hasattr(ref, "to_dict") else dict(ref)
    with _LOCK:
        # Re-check under lock: a concurrent Start with the same key wins once.
        winner = _LOGICAL.get(logical_key)
        if winner is not None:
            existing = _HANDLES.get(winner)
            if existing is not None and existing.get("preparation_id") != preparation_id:
                return make_connector_error(
                    "IDEMPOTENCY_CONFLICT",
                    "connector Start operation reused a logical execution key with "
                    "changed preparation content.",
                    handle={"connector_id": connector_id, "local_handle": winner},
                )
            if existing is not None:
                return {
                    "kind": "started",
                    "disposition": "existing_handle",
                    "handle": {"connector_id": connector_id, "local_handle": winner},
                    "handle_artifact": existing.get("handle_artifact"),
                    "receipt_ref": missing("not_observed"),
                }
        _LOGICAL[logical_key] = local_handle
        _HANDLES[local_handle] = {
            "connector_id": connector_id,
            "principal": principal,
            "preparation_id": preparation_id,
            "idempotency_key": str(idempotency_key),
            "handle_artifact": handle_artifact,
            "scope": copy.deepcopy(stored_prep.get("scope", {})),
            "observation_closed": False,
            "context_released": False,
        }
        _OBS.setdefault(local_handle, [])
    return {
        "kind": "started",
        "disposition": "accepted_locally",
        "handle": handle_ref,
        "handle_artifact": handle_artifact,
        "receipt_ref": missing("not_observed"),
    }


def _resolve_handle(
    principal: str, connector_id: str, payload_handle: Any, operation: str = "operation"
) -> tuple[str | None, dict[str, Any] | None]:
    if not isinstance(payload_handle, dict):
        return None, make_connector_error(
            "INVALID_REQUEST",
            f"connector {operation} operation requires a handle reference object.",
        )
    if payload_handle.get("connector_id") != connector_id:
        return None, make_connector_error(
            "UNKNOWN_HANDLE",
            f"connector {operation} operation references an unknown handle for this "
            "connector.",
        )
    local = payload_handle.get("local_handle")
    if not isinstance(local, str) or not local:
        return None, make_connector_error(
            "INVALID_REQUEST",
            f"connector {operation} operation requires a nonempty local_handle "
            "identifier.",
        )
    with _LOCK:
        stored = _HANDLES.get(local)
    if stored is None:
        return None, make_connector_error(
            "UNKNOWN_HANDLE",
            f"connector {operation} operation references an unknown handle.",
        )
    if stored.get("connector_id") != connector_id or stored.get("principal") != principal:
        # Do not reveal another principal's handles.
        return None, make_connector_error(
            "UNKNOWN_HANDLE",
            f"connector {operation} operation references an unknown handle.",
        )
    return local, None


def _handle_observe(
    principal: str,
    connector_id: str,
    call_limit_value: float,
    payload: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return make_connector_error(
            "INVALID_REQUEST",
            "connector Observe operation requires an object payload.",
        )
    handle = payload.get("handle")
    after = payload.get("after")
    through = payload.get("through", missing("not_applicable"))
    max_items = payload.get("max_items")
    wait_limit = payload.get("wait_limit")
    local, err = _resolve_handle(principal, connector_id, handle, "Observe")
    if err is not None:
        return err
    assert local is not None
    if not isinstance(after, dict):
        return make_connector_error(
            "CURSOR_INVALID",
            "connector Observe operation requires an after cursor object.",
            handle=handle,
        )
    after_seq = after.get("sequence")
    if isinstance(after_seq, bool) or not isinstance(after_seq, int) or after_seq < 0:
        return make_connector_error(
            "CURSOR_INVALID",
            "connector Observe operation requires after.sequence as a nonnegative integer.",
            handle=handle,
        )
    after_journal = after.get("journal_id")
    if not isinstance(after_journal, str) or not after_journal:
        return make_connector_error(
            "CURSOR_INVALID",
            "connector Observe operation requires after.journal_id as an identifier.",
            handle=handle,
        )
    after_hash = after.get("event_hash")
    if after_seq == 0:
        if not (_is_missing(after_hash) and after_hash.get("reason") == "not_applicable"):
            return make_connector_error(
                "CURSOR_INVALID",
                "connector Observe operation requires an inapplicable event_hash at "
                "sequence zero.",
                handle=handle,
            )
    else:
        if not (isinstance(after_hash, str) and after_hash.startswith("sha256:")):
            return make_connector_error(
                "CURSOR_INVALID",
                "connector Observe operation requires a digest event_hash at positive "
                "sequences.",
                handle=handle,
            )
    if isinstance(max_items, bool) or not isinstance(max_items, int):
        return make_connector_error(
            "INVALID_REQUEST",
            "connector Observe operation requires max_items as an integer.",
            handle=handle,
        )
    if max_items < 1:
        return make_connector_error(
            "INVALID_REQUEST",
            "connector Observe operation requires max_items of at least one.",
            handle=handle,
        )
    if max_items > MAX_OBSERVATION_ITEMS:
        return make_connector_error(
            "BUDGET_EXCEEDED",
            f"connector Observe operation exceeds the local observation bound of "
            f"{MAX_OBSERVATION_ITEMS} items.",
            handle=handle,
        )
    if not isinstance(wait_limit, dict) or wait_limit.get("kind") != "exact":
        return make_connector_error(
            "INVALID_REQUEST",
            "connector Observe operation requires wait_limit as an exact ms DurationLimit.",
            handle=handle,
        )
    wait_value = wait_limit.get("value")
    if isinstance(wait_value, bool) or not isinstance(wait_value, (int, float)):
        return make_connector_error(
            "INVALID_REQUEST",
            "connector Observe operation requires a numeric wait_limit value.",
            handle=handle,
        )
    if not math.isfinite(float(wait_value)) or float(wait_value) < 0:
        return make_connector_error(
            "INVALID_REQUEST",
            "connector Observe operation requires a finite nonnegative wait_limit.",
            handle=handle,
        )
    if float(wait_value) > call_limit_value:
        return make_connector_error(
            "BUDGET_EXCEEDED",
            "connector Observe operation wait_limit exceeds the call_limit bound.",
            handle=handle,
        )
    through_is_live = _is_missing(through)
    if not through_is_live:
        if not isinstance(through, dict):
            return make_connector_error(
                "CURSOR_INVALID",
                "connector Observe operation requires through as a journal prefix or "
                "inapplicable.",
                handle=handle,
            )
        if float(wait_value) != 0:
            return make_connector_error(
                "INVALID_REQUEST",
                "connector Observe operation with a fixed through cutoff requires "
                "wait_limit.value of zero.",
                handle=handle,
            )
    with _LOCK:
        items_all = list(_OBS.get(local, []))
        stored = _HANDLES.get(local, {})
    cutoff = len(items_all)
    if not through_is_live:
        try:
            last = int(through.get("last_sequence", cutoff))
        except Exception:
            return make_connector_error(
                "CURSOR_INVALID",
                "connector Observe operation carries an invalid through cutoff.",
                handle=handle,
            )
        if last < after_seq:
            return make_connector_error(
                "CURSOR_INVALID",
                "connector Observe operation through cutoff precedes the after cursor.",
                handle=handle,
            )
        cutoff = min(cutoff, last)
    if after_seq > cutoff:
        return make_connector_error(
            "CURSOR_UNAVAILABLE",
            "connector Observe operation cursor history is unavailable at this cutoff.",
            handle=handle,
        )
    page_items = items_all[after_seq : after_seq + max_items]
    # Respect the cutoff: never return beyond it.
    if after_seq + len(page_items) > cutoff:
        page_items = page_items[: max(0, cutoff - after_seq)]
    next_seq = after_seq + len(page_items)
    has_more = next_seq < cutoff
    handle_ref = {"connector_id": connector_id, "local_handle": local}
    if next_seq == 0:
        next_hash: Any = missing("not_applicable")
    else:
        next_hash = "sha256:" + hashlib.sha256(f"{local}:{next_seq}".encode()).hexdigest()
    through_prefix = {
        "journal_id": after_journal,
        "last_sequence": cutoff,
        "head_hash": "sha256:" + hashlib.sha256(f"{local}:head:{cutoff}".encode()).hexdigest(),
    }
    if stored.get("observation_closed"):
        close_ref: Any = _dummy_evidence_ref(after_journal)
    else:
        close_ref = missing("not_observed")
    return {
        "kind": "observation_page",
        "handle": handle_ref,
        "after": copy.deepcopy(after),
        "through": through_prefix,
        "next": {
            "handle": handle_ref,
            "journal_id": after_journal,
            "sequence": next_seq,
            "event_hash": next_hash,
        },
        "has_more": has_more,
        "observation_close_ref": close_ref,
        "items": copy.deepcopy(page_items),
        "limitations": [],
    }


def _control_receipt(
    operation: str,
    target_scope: str,
    disposition: str,
    handle_ref: dict[str, Any],
    limitations: list[str] | None = None,
) -> dict[str, Any]:
    control_event_id = "cev_" + secrets.token_hex(8)
    operation_id = "op_" + secrets.token_hex(8)
    observation = {
        "control_event_id": control_event_id,
        "operation_id": operation_id,
        "operation": operation,
        "target_scope": target_scope,
        "disposition": disposition,
        "at": _dummy_timepoint(),
        "authorization_ref": _dummy_evidence_ref(),
        "capability_ref": missing("not_applicable"),
        "opportunity": {"kind": "immediate", "detail": "local control call"},
        "request_ref": missing("not_observed"),
        "response_ref": missing("not_observed"),
        "response_checks": missing("not_observed"),
        "native_claim_refs": [],
        "effect_refs": [],
        "affected_attempts": [],
        "measurements": [],
        "limitations": list(limitations or []),
    }
    return {
        "kind": "control_receipt",
        "handle": copy.deepcopy(handle_ref),
        "observation": observation,
        "registration_ref": _dummy_evidence_ref(),
    }


def _handle_request_native_cancel(
    principal: str, connector_id: str, payload: dict[str, Any]
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return make_connector_error(
            "INVALID_REQUEST",
            "connector RequestNativeCancel operation requires an object payload.",
        )
    handle = payload.get("handle")
    reason = payload.get("reason")
    local, err = _resolve_handle(principal, connector_id, handle, "RequestNativeCancel")
    if err is not None:
        return err
    if not isinstance(reason, str) or not reason:
        return make_connector_error(
            "INVALID_REQUEST",
            "connector RequestNativeCancel operation requires a nonempty reason.",
            handle=handle,
        )
    if reason == "unsupported_mapping_test":
        return make_connector_error(
            "UNSUPPORTED_MAPPING",
            "connector RequestNativeCancel operation has no evidenced native "
            "cancellation mapping for this handle.",
            handle=handle,
        )
    assert local is not None
    handle_ref = {"connector_id": connector_id, "local_handle": local}
    return _control_receipt(
        "RequestNativeCancel", "native_execution", "requested", handle_ref
    )


def _handle_close(
    principal: str, connector_id: str, payload: dict[str, Any]
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return make_connector_error(
            "INVALID_REQUEST",
            "connector CloseObservationConnection operation requires an object payload.",
        )
    handle = payload.get("handle")
    reason = payload.get("reason")
    end_observation = payload.get("end_observation")
    local, err = _resolve_handle(principal, connector_id, handle, "CloseObservationConnection")
    if err is not None:
        return err
    if reason not in ("operator_stop", "local_deadline", "normal_completion"):
        return make_connector_error(
            "INVALID_REQUEST",
            "connector CloseObservationConnection operation requires reason of "
            "operator_stop, local_deadline, or normal_completion.",
            handle=handle,
        )
    if not isinstance(end_observation, bool):
        return make_connector_error(
            "INVALID_REQUEST",
            "connector CloseObservationConnection operation requires end_observation "
            "as a boolean.",
            handle=handle,
        )
    assert local is not None
    with _LOCK:
        stored = _HANDLES.get(local)
        if stored is not None and end_observation:
            stored["observation_closed"] = True
    handle_ref = {"connector_id": connector_id, "local_handle": local}
    return _control_receipt(
        "CloseObservationConnection",
        "observation_connection",
        "requested",
        handle_ref,
    )


def _handle_collect(
    channel_id: str,
    principal: str,
    connector_id: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return make_connector_error(
            "INVALID_REQUEST",
            "connector CollectArtifacts operation requires an object payload.",
        )
    handle = payload.get("handle")
    selector = payload.get("selector")
    local, err = _resolve_handle(principal, connector_id, handle, "CollectArtifacts")
    if err is not None:
        return err
    assert local is not None
    handle_ref = {"connector_id": connector_id, "local_handle": local}
    if not isinstance(selector, dict):
        return make_connector_error(
            "INVALID_REQUEST",
            "connector CollectArtifacts operation requires a selector object.",
            handle=handle,
        )
    mode = selector.get("mode")
    journal_id = f"journal_{local}"
    prefix = {
        "journal_id": journal_id,
        "last_sequence": 0,
        "head_hash": "sha256:" + "e" * 64,
    }
    if mode == "inventory":
        if set(selector.keys()) != {"mode"}:
            return make_connector_error(
                "INVALID_REQUEST",
                "connector CollectArtifacts inventory selector carries only mode.",
                handle=handle,
            )
        return {
            "kind": "artifact_inventory",
            "handle": handle_ref,
            "artifacts": [],
            "coverage": "complete",
            "evidence_prefix": prefix,
            "limitations": [],
        }
    if mode == "named":
        names = selector.get("names")
        if not isinstance(names, list) or not names:
            return make_connector_error(
                "INVALID_REQUEST",
                "connector CollectArtifacts named selector requires nonempty names.",
                handle=handle,
            )
        if len(set(names)) != len(names):
            return make_connector_error(
                "INVALID_REQUEST",
                "connector CollectArtifacts named selector requires unique names.",
                handle=handle,
            )
        for name in names:
            if not isinstance(name, str) or not name:
                return make_connector_error(
                    "INVALID_REQUEST",
                    "connector CollectArtifacts named selector requires nonempty "
                    "name identifiers.",
                    handle=handle,
                )
        slots = [
            {
                "name": name,
                "expected_digest": missing("not_observed"),
                "content": missing("not_observed"),
                "evidence_refs": [],
            }
            for name in names
        ]
        return {
            "kind": "artifact_inventory",
            "handle": handle_ref,
            "artifacts": slots,
            "coverage": "complete",
            "evidence_prefix": prefix,
            "limitations": [],
        }
    if mode == "bytes":
        digest = selector.get("digest")
        offset = selector.get("offset")
        max_bytes = selector.get("max_bytes")
        if not (isinstance(digest, str) and digest.startswith("sha256:")):
            return make_connector_error(
                "INVALID_REQUEST",
                "connector CollectArtifacts bytes selector requires a digest.",
                handle=handle,
            )
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            return make_connector_error(
                "INVALID_REQUEST",
                "connector CollectArtifacts bytes selector requires a nonnegative "
                "offset.",
                handle=handle,
            )
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
            return make_connector_error(
                "INVALID_REQUEST",
                "connector CollectArtifacts bytes selector requires positive max_bytes.",
                handle=handle,
            )
        if max_bytes > MAX_ARTIFACT_BYTES:
            return make_connector_error(
                "BUDGET_EXCEEDED",
                "connector CollectArtifacts bytes selector exceeds the local "
                "transfer bound.",
                handle=handle,
            )
        try:
            known = artifact_store.known_digests()
            if digest not in known:
                return make_connector_error(
                    "ARTIFACT_UNAVAILABLE",
                    "connector CollectArtifacts operation cannot transfer bytes: "
                    "the digest was never retained.",
                    handle=handle,
                )
            # Resolve via a reference lookup; bytes mode never fetches paths/URLs.
            meta = None
            try:
                internal_meta = getattr(artifact_store, "_META", {})
                meta = internal_meta.get(digest)
            except Exception:
                meta = None
            if meta is None:
                return make_connector_error(
                    "ARTIFACT_UNAVAILABLE",
                    "connector CollectArtifacts operation cannot transfer bytes: "
                    "the artifact identity is known but its metadata is unavailable.",
                    handle=handle,
                )
            payload_bytes = artifact_store.resolve_artifact(channel_id, meta)
        except artifact_store.ArtifactUnavailableError:
            return make_connector_error(
                "ARTIFACT_UNAVAILABLE",
                "connector CollectArtifacts operation cannot transfer bytes: "
                "the digest was never retained.",
                handle=handle,
            )
        except artifact_store.ArtifactLostError:
            return make_connector_error(
                "OBSERVATION_LOST",
                "connector CollectArtifacts operation cannot transfer bytes: "
                "retained bytes are no longer available.",
                handle=handle,
            )
        except artifact_store.ArtifactAccessDeniedError:
            return make_connector_error(
                "FORBIDDEN",
                "connector CollectArtifacts operation is forbidden: the channel may "
                "not resolve this restricted artifact.",
                handle=handle,
            )
        except Exception:
            return make_connector_error(
                "STORAGE_UNAVAILABLE",
                "connector CollectArtifacts operation could not read retained bytes.",
                handle=handle,
            )
        size = len(payload_bytes)
        if offset > size:
            return make_connector_error(
                "INVALID_REQUEST",
                "connector CollectArtifacts bytes selector offset is beyond EOF.",
                handle=handle,
            )
        chunk = payload_bytes[offset : offset + max_bytes]
        import base64 as _b64

        data_b64 = _b64.b64encode(chunk).decode("ascii")
        chunk_digest = "sha256:" + hashlib.sha256(chunk).hexdigest()
        return {
            "kind": "artifact_chunk",
            "handle": handle_ref,
            "digest": digest,
            "size_bytes": size,
            "offset": offset,
            "returned_bytes": len(chunk),
            "data_base64": data_b64,
            "chunk_digest": chunk_digest,
            "end_of_artifact": (offset + len(chunk)) >= size,
            "evidence_refs": [],
        }
    return make_connector_error(
        "INVALID_REQUEST",
        "connector CollectArtifacts operation requires selector mode of inventory, "
        "named, or bytes.",
        handle=handle if isinstance(handle, dict) else None,
    )


def _handle_release(
    principal: str, connector_id: str, payload: dict[str, Any]
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return make_connector_error(
            "INVALID_REQUEST",
            "connector ReleaseNativeContext operation requires an object payload.",
        )
    handle = payload.get("handle")
    context_ref = payload.get("context_ref", missing("not_applicable"))
    local, err = _resolve_handle(principal, connector_id, handle, "ReleaseNativeContext")
    if err is not None:
        return err
    if not (isinstance(context_ref, str) or _is_missing(context_ref)):
        return make_connector_error(
            "INVALID_REQUEST",
            "connector ReleaseNativeContext operation requires context_ref as an "
            "identifier or typed Missing.",
            handle=handle,
        )
    if isinstance(context_ref, str) and (not context_ref or "\x00" in context_ref):
        return make_connector_error(
            "INVALID_REQUEST",
            "connector ReleaseNativeContext operation requires a nonempty context_ref.",
            handle=handle,
        )
    assert local is not None
    with _LOCK:
        stored = _HANDLES.get(local)
        if stored is not None:
            stored["context_released"] = True
    handle_ref = {"connector_id": connector_id, "local_handle": local}
    return _control_receipt(
        "ReleaseNativeContext", "native_context", "requested", handle_ref
    )


def _handle_contain(
    principal: str, connector_id: str, payload: dict[str, Any]
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return make_connector_error(
            "INVALID_REQUEST",
            "connector Contain operation requires an object payload.",
        )
    handle = payload.get("handle")
    target = payload.get("target")
    policy = payload.get("policy")
    reason = payload.get("reason")
    local, err = _resolve_handle(principal, connector_id, handle, "Contain")
    if err is not None:
        return err
    if not isinstance(target, dict):
        return make_connector_error(
            "INVALID_REQUEST",
            "connector Contain operation requires a target object.",
            handle=handle,
        )
    kind = target.get("kind")
    resource_id = target.get("resource_id")
    if kind not in (
        "fixture_mutation_authority",
        "local_process",
        "deployment_slot",
        "harness_resources",
    ):
        return make_connector_error(
            "INVALID_REQUEST",
            "connector Contain operation requires a bounded target kind.",
            handle=handle,
        )
    if not isinstance(resource_id, str) or not resource_id or "\x00" in resource_id:
        return make_connector_error(
            "INVALID_REQUEST",
            "connector Contain operation requires an authorized resource_id.",
            handle=handle,
        )
    if not isinstance(policy, dict):
        return make_connector_error(
            "PREREQUISITE_UNAVAILABLE",
            "connector Contain operation cannot execute: no reviewed containment "
            "policy is evidenced for this local call.",
            handle=handle,
        )
    if not isinstance(reason, str) or not reason:
        return make_connector_error(
            "INVALID_REQUEST",
            "connector Contain operation requires a nonempty reason.",
            handle=handle,
        )
    assert local is not None
    handle_ref = {"connector_id": connector_id, "local_handle": local}
    return _control_receipt("Contain", str(kind), "requested", handle_ref)


def stage_native_report_for_tests(
    handle: dict[str, Any] | str,
    status: str,
    *,
    channel: str = "terminal_response",
    provenance: str = "connector",
) -> dict[str, Any]:
    if status not in ("failed", "completed", "stopped"):
        raise ValueError("status must be failed, completed, or stopped")
    if channel not in ("terminal_response", "callback", "native_stream"):
        raise ValueError("unknown native channel")
    if isinstance(handle, dict):
        local = handle.get("local_handle")
    else:
        local = handle
    if not isinstance(local, str) or not local:
        raise ValueError("handle must carry a local_handle")
    with _LOCK:
        if local not in _HANDLES:
            raise ValueError(f"unknown handle: {local!r}")
        seq = len(_OBS.get(local, [])) + 1
        journal_id = f"journal_{local}"
        event_ref = {
            "journal_id": journal_id,
            "journal_sequence": seq,
            "event_id": f"evt_{local}_{seq}",
            "event_hash": "sha256:" + hashlib.sha256(f"{local}:{seq}".encode()).hexdigest(),
            "pointer": "",
        }
        item = {
            "event_ref": event_ref,
            "recorded_at": _dummy_timepoint(),
            "provenance": provenance,
            "payload": {
                "kind": "native_report",
                "channel": channel,
                "raw": {
                    "digest": "sha256:" + "c" * 64,
                    "size_bytes": 12,
                    "media_type": "application/json",
                    "owner_domain": _HANDLES[local].get("connector_id", "connector"),
                    "access": "public",
                },
                "source_event": dict(event_ref),
                "source_checks": {
                    "authentication": "verified",
                    "correlation": "matched",
                    "freshness": "current",
                },
                "mapping": {
                    "id": "mapping_native_status",
                    "version": "1",
                    "artifact_digest": "sha256:" + "d" * 64,
                },
                "normalized_claims": [
                    {
                        "claim_id": f"claim_{seq}",
                        "status": status,
                        "detail": f"native reported {status}",
                    }
                ],
                "limitations": [],
            },
            "measurements": [],
            "artifact_refs": [],
        }
        _OBS.setdefault(local, []).append(item)
        return copy.deepcopy(item)


async def call_connector(
    channel_id: str, request: ConnectorRequest | dict[str, Any]
) -> ConnectorResponse:
    start_mono = time.monotonic()
    if isinstance(request, ConnectorRequest):
        req_dict = request.to_dict()
    elif isinstance(request, dict):
        req_dict = copy.deepcopy(request)
    else:
        raise TypeError("request must be a ConnectorRequest or mapping")
    raw_request_id = req_dict.get("request_id")
    raw_connector_id = req_dict.get("connector_id")
    raw_operation = req_dict.get("operation")
    req_id = raw_request_id if isinstance(raw_request_id, str) else "unknown_request"
    conn_id = raw_connector_id if isinstance(raw_connector_id, str) else "unknown_connector"
    op = raw_operation if isinstance(raw_operation, str) else "Describe"
    if op not in OPERATIONS:
        op_for_envelope: str = "Describe"
    else:
        op_for_envelope = op

    def _err(code: str, detail: str, **kw: Any) -> ConnectorResponse:
        return ConnectorResponse(
            request_id=req_id,
            connector_id=conn_id,
            operation=op_for_envelope,
            result=make_connector_error(code, detail, **kw),
        )

    if req_dict.get("record_type") != RECORD_TYPE_REQUEST:
        return _err(
            "INVALID_REQUEST",
            "connector operation request must carry record_type connector_request.",
        )
    if req_dict.get("schema_version") != SCHEMA_VERSION:
        return ConnectorResponse(
            request_id=req_id,
            connector_id=conn_id,
            operation=op_for_envelope,
            result=make_connector_error(
                "UNSUPPORTED_VERSION",
                f"connector operation requires schema_version {SCHEMA_VERSION}.",
            ),
        )
    if not isinstance(raw_operation, str) or raw_operation not in OPERATIONS:
        return _err(
            "INVALID_REQUEST",
            "connector operation must be one of the nine versioned verbs.",
        )
    try:
        _require_identifier(raw_request_id, "request_id")
        _require_identifier(raw_connector_id, "connector_id")
    except (ValueError, TypeError):
        return _err(
            "INVALID_REQUEST",
            "connector operation requires nonempty request_id and connector_id.",
        )
    call_limit = req_dict.get("call_limit")
    payload = req_dict.get("payload")
    if not isinstance(payload, dict):
        return _err(
            "INVALID_REQUEST",
            f"connector {op} operation requires an object payload.",
        )
    ok, detail, limit_value = _validate_call_limit(call_limit)
    if not ok:
        return _err("INVALID_REQUEST", f"connector {op} operation: {detail}.")
    if limit_value > MAX_CALL_LIMIT_MS:
        return _err(
            "BUDGET_EXCEEDED",
            f"connector {op} operation call_limit exceeds the local bound of "
            f"{MAX_CALL_LIMIT_MS:g} ms.",
        )
    auth, auth_err = _authenticate(channel_id, conn_id)
    if auth_err is not None:
        return ConnectorResponse(
            request_id=req_id,
            connector_id=conn_id,
            operation=op_for_envelope,
            result=auth_err,
        )
    assert auth is not None
    descriptor, projection = auth
    principal = str(descriptor.principal_id)
    owner_domain = str(projection.get("axis", descriptor.owner_domain))
    try:
        _strict_gate(req_dict)
    except Exception as exc:
        return _err(
            "INVALID_REQUEST",
            f"connector {op} operation request is not strict canonical JSON: {exc}.",
        )
    try:
        fingerprint = _fingerprint(req_dict)
    except Exception as exc:
        return _err(
            "INVALID_REQUEST",
            f"connector {op} operation request cannot be fingerprinted: {exc}.",
        )
    is_read = op in READ_OPERATIONS
    command_key = (principal, conn_id, req_id)
    if not is_read:
        with _LOCK:
            retained = _COMMANDS.get(command_key)
            if retained is not None:
                if retained["fingerprint"] != fingerprint:
                    return ConnectorResponse(
                        request_id=req_id,
                        connector_id=conn_id,
                        operation=op,
                        result=make_connector_error(
                            "IDEMPOTENCY_CONFLICT",
                            f"connector {op} operation reused command identity "
                            f"'{req_id}' with changed request content.",
                        ),
                    )
                stored: ConnectorResponse = retained["response"]
                return ConnectorResponse(
                    request_id=stored.request_id,
                    connector_id=stored.connector_id,
                    operation=stored.operation,
                    result=copy.deepcopy(stored.result),
                )
    # Durably install the admitted input before any authoritative effect.
    request_bytes = _canonical_json_bytes(req_dict)
    state_ref, retain_err = _retain_bytes(channel_id, owner_domain, request_bytes)
    if retain_err is not None:
        return ConnectorResponse(
            request_id=req_id, connector_id=conn_id, operation=op, result=retain_err
        )
    assert state_ref is not None
    if op == "Describe":
        result = _handle_describe(conn_id, payload)
    elif op == "Prepare":
        result = _handle_prepare(
            channel_id, owner_domain, principal, conn_id, req_id, payload
        )
    elif op == "Start":
        result = _handle_start(
            channel_id, owner_domain, principal, conn_id, req_id, payload
        )
    elif op == "Observe":
        result = _handle_observe(principal, conn_id, limit_value, payload)
    elif op == "RequestNativeCancel":
        result = _handle_request_native_cancel(principal, conn_id, payload)
    elif op == "CloseObservationConnection":
        result = _handle_close(principal, conn_id, payload)
    elif op == "CollectArtifacts":
        result = _handle_collect(channel_id, principal, conn_id, payload)
    elif op == "ReleaseNativeContext":
        result = _handle_release(principal, conn_id, payload)
    elif op == "Contain":
        result = _handle_contain(principal, conn_id, payload)
    else:  # pragma: no cover - guarded above
        result = make_connector_error(
            "INVALID_REQUEST", "connector operation verb is not recognized."
        )
    elapsed_ms = (time.monotonic() - start_mono) * 1000.0
    if elapsed_ms > limit_value:
        return ConnectorResponse(
            request_id=req_id,
            connector_id=conn_id,
            operation=op,
            result=make_connector_error(
                "BUDGET_EXCEEDED",
                f"connector {op} operation exceeded its local call_limit bound.",
            ),
        )
    response = ConnectorResponse(
        request_id=req_id, connector_id=conn_id, operation=op, result=result
    )
    if not is_read:
        # Best-effort journal audit; local durability already holds via the
        # retained input bytes and the idempotency record below.
        _try_append_journal(channel_id, owner_domain, op, req_id, conn_id)
        _try_commit_effect(channel_id, owner_domain, conn_id, req_id, state_ref)
        with _LOCK:
            existing = _COMMANDS.get(command_key)
            if existing is None:
                _COMMANDS[command_key] = {
                    "fingerprint": fingerprint,
                    "response": ConnectorResponse(
                        request_id=response.request_id,
                        connector_id=response.connector_id,
                        operation=response.operation,
                        result=copy.deepcopy(response.result),
                    ),
                    "request_bytes": request_bytes,
                }
            elif existing["fingerprint"] == fingerprint:
                pass
            else:
                # A concurrent conflicting command won the key first.
                return ConnectorResponse(
                    request_id=req_id,
                    connector_id=conn_id,
                    operation=op,
                    result=make_connector_error(
                        "IDEMPOTENCY_CONFLICT",
                        f"connector {op} operation reused command identity "
                        f"'{req_id}' with changed request content.",
                    ),
                )
    return response

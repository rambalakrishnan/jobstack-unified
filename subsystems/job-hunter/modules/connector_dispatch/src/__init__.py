"""connector_dispatch: lifecycle-gated Describe/Prepare/Start orchestration (tier 6).

Job Hunter-side dispatch gate in front of the connector carrier. It enforces
the lifecycle invariants that the raw transport cannot know:

- Describe pins one subject/version/mode/surface with a complete capability
  catalog; a new subject version starts ``unknown`` on every capability until
  its own version-scoped evidence establishes another availability.
- Prepare is non-executing: requests that browse, probe, invoke planning,
  test authentication, reset context, or otherwise execute are rejected.
- Start requires a registered attempt commission for application scopes,
  requires acceptance of every ``requires_acceptance`` preparation concern,
  rejects stale configurations/preparations, preserves logical-execution
  idempotency, never acquires a second execution by changing key/caller/
  executor, and rejects resume after the observation window drains or closes.

Delegation: mutating/collecting calls are forwarded to
``connector_transport.call_connector`` only after every dispatch gate passes.
Journal writes (``evidence_journal``) are best-effort: local durability
(retained bytes + idempotency records) holds even when no journal is
admitted, and journal failures never mask a dispatch decision.
"""

from __future__ import annotations

import copy
import importlib
import importlib.util
import json
import sys
import threading
import time
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
connector_transport = _load_sibling("connector_transport")
attempt_commissioning = _load_sibling("attempt_commissioning")

__all__ = [
    "ConnectorRequest",
    "ConnectorResponse",
    "SCHEMA_VERSION",
    "RECORD_TYPE_REQUEST",
    "RECORD_TYPE_RESPONSE",
    "MINIMUM_CAPABILITY_IDS",
    "OPERATIONS",
    "describe_subject",
    "prepare_task",
    "start_task",
    "reset_for_tests",
    "register_subject_for_tests",
    "record_capability_evidence_for_tests",
    "rotate_configuration_for_tests",
    "set_observation_state_for_tests",
    "get_observation_state_for_tests",
    "mark_delivery_uncertain_for_tests",
    "get_commission_execution_for_tests",
    "get_preparation_for_tests",
]

ConnectorRequest = connector_transport.ConnectorRequest
ConnectorResponse = connector_transport.ConnectorResponse

SCHEMA_VERSION = connector_transport.SCHEMA_VERSION
RECORD_TYPE_REQUEST = connector_transport.RECORD_TYPE_REQUEST
RECORD_TYPE_RESPONSE = connector_transport.RECORD_TYPE_RESPONSE
OPERATIONS = connector_transport.OPERATIONS
MAX_CALL_LIMIT_MS = connector_transport.MAX_CALL_LIMIT_MS

CONNECTOR_VERSION = "dispatch/0.1.0"

MINIMUM_CAPABILITY_IDS = (
    "native_goal_task",
    "native_plan_execution",
    "native_cancel",
    "native_context_release",
    "native_artifact_retrieval",
    "native_revision",
    "native_dom_access",
    "browser_state_isolation",
    "browser_state_persistence",
    "learning_state_control",
)

_VALID_TASK_TYPES = frozenset({"apply", "extract", "discover_jobs"})
_VALID_CONCERN_CATEGORIES = frozenset(
    {
        "native_capability_absent",
        "native_capability_unknown",
        "budget_not_enforced",
        "state_policy_unverified",
        "assistance_limit",
        "observation_limit",
    }
)
_VALID_AVAILABILITY = frozenset({"present", "absent", "unknown", "not_applicable"})
_EVIDENCED_AVAILABILITY = frozenset({"present", "absent", "not_applicable"})
_VALID_EVIDENCE_BASIS = frozenset(
    {"documentation", "executed_observation", "source_diagnosis", "operator_attestation"}
)
_VALID_CLAIM_ORIGINS = frozenset({"native", "composed_subject", "harness"})
_VALID_BROWSER_MODES = frozenset({"fresh", "reuse", "subject_default", "not_applicable"})
_VALID_LEARNING_MODES = _VALID_BROWSER_MODES | frozenset({"frozen"})
_VALID_REQUIREMENTS = frozenset({"required", "best_effort"})
_VALID_RUNTIME_PURPOSES = frozenset({"application_entry", "account_session", "input_artifact"})
_VALID_OBSERVATION_STATES = frozenset({"open", "draining", "closed"})

# Any of these mapping keys anywhere inside a Prepare payload means the caller
# asks the connector to browse, probe, plan, authenticate, mutate local state,
# or otherwise execute during what must be a non-executing call.
_FORBIDDEN_PREPARE_KEYS = frozenset(
    {
        "browse",
        "browse_target",
        "visit_target",
        "probe",
        "probe_subject",
        "native_probe",
        "invoke_planner",
        "invoke_planning",
        "planning_request",
        "test_login",
        "test_authentication",
        "reset_context",
        "improve_plan",
        "execute_actions",
    }
)

# Gate rejections that depend on mutable registry state are recomputed on
# every call rather than retained: a later registration, rotation, or window
# transition legitimately changes the answer for an identical command.
_NON_RETAINED_GATE_CODES = frozenset(
    {"NOT_ADMITTED", "STALE_PREPARATION", "OBSERVATION_CLOSED", "IDEMPOTENCY_CONFLICT"}
)

_LOCK = threading.RLock()
# connector_id -> {"subject": SubjectIdentity, "configuration": dict, "configuration_digest": str}
_SUBJECTS: dict[str, dict[str, Any]] = {}
# (connector_id, subject_id, subject_version) -> descriptor record
_DESCRIPTORS: dict[tuple[str, str, str], dict[str, Any]] = {}
_CURRENT_DESCRIPTOR_DIGEST: dict[str, str] = {}
# (subject_id, subject_version, capability_id) -> evidence record
_CAPABILITY_EVIDENCE: dict[tuple[str, str, str], dict[str, Any]] = {}
# preparation_id -> dispatch preparation context
_PREPARATIONS: dict[str, dict[str, Any]] = {}
# (principal, connector_id, request_id) -> {"fingerprint": str, "response": ConnectorResponse}
_COMMANDS: dict[tuple[str, str, str], dict[str, Any]] = {}
# (principal, connector_id, idempotency_key) -> logical execution mirror
_LOGICAL: dict[tuple[str, str, str], dict[str, Any]] = {}
# commission_id -> {"principal", "connector_id", "idempotency_key", "local_handle", "delivery"}
_COMMISSION_EXECUTION: dict[str, dict[str, Any]] = {}
# local_handle -> open | draining | closed
_OBSERVATION: dict[str, str] = {}
# local_handle -> count of journaled deliveries
_DELIVERIES: dict[str, int] = {}
_SEQ: dict[str, int] = {}


def reset_for_tests() -> None:
    """Clear all dispatch registries (tests only)."""
    with _LOCK:
        _SUBJECTS.clear()
        _DESCRIPTORS.clear()
        _CURRENT_DESCRIPTOR_DIGEST.clear()
        _CAPABILITY_EVIDENCE.clear()
        _PREPARATIONS.clear()
        _COMMANDS.clear()
        _LOGICAL.clear()
        _COMMISSION_EXECUTION.clear()
        _OBSERVATION.clear()
        _DELIVERIES.clear()
        _SEQ.clear()


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _missing(reason: str = "not_applicable") -> dict[str, Any]:
    return connector_transport.missing(reason)


def _is_missing(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and value.get("value") is None
        and isinstance(value.get("reason"), str)
        and value.get("reason") in contract_codec.VALID_MISSING_REASONS
        and set(value.keys()) <= {"value", "reason", "detail"}
    )


def _require_identifier(value: object, field_name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string identifier")
    if not value or len(value) > 256:
        raise ValueError(f"{field_name} must be a nonempty identifier")
    return value


def _canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _digest_of_record(record: dict[str, Any]) -> str:
    return str(contract_codec.canonical_digest(_canonical_json_bytes(record)))


def _duration_limit(value: float | int) -> dict[str, Any]:
    return {"kind": "exact", "unit": "ms", "value": value}


def _error_response(
    request_id: str, connector_id: str, operation: str, code: str, detail: str, **kw: Any
) -> ConnectorResponse:
    return ConnectorResponse(
        request_id=request_id,
        connector_id=connector_id,
        operation=operation,
        result=connector_transport.make_connector_error(code, detail, **kw),
    )


def _as_request_dict(request: Any) -> dict[str, Any]:
    if isinstance(request, ConnectorRequest):
        return request.to_dict()
    if isinstance(request, dict):
        return copy.deepcopy(request)
    raise TypeError("request must be a ConnectorRequest or mapping")


def _validate_call_limit(value: Any) -> tuple[bool, str, float]:
    if not isinstance(value, dict):
        return False, "call_limit must be a DurationLimit object", 0.0
    if set(value.keys()) != {"kind", "unit", "value"}:
        return False, "call_limit must carry exactly kind, unit, and value", 0.0
    if value.get("kind") != "exact" or value.get("unit") != "ms":
        return False, "call_limit must be an exact millisecond DurationLimit", 0.0
    number = value.get("value")
    if isinstance(number, bool) or not isinstance(number, (int, float)):
        return False, "call_limit value must be a finite number", 0.0
    if not (0 <= number < float("inf")) or number != number:
        return False, "call_limit value must be a finite nonnegative number", 0.0
    return True, "", float(number)


def _authenticate(
    channel_id: str, connector_id: str
) -> tuple[tuple[Any, dict[str, Any]] | None, dict[str, Any] | None]:
    """Authenticate the channel and resolve principal + owner domain.

    Mirrors the carrier: identity and grants come from the registered
    channel, never from caller-supplied strings.
    """
    try:
        projection = access_policy.channel_projection(channel_id)
    except access_policy.UnknownChannelError:
        return None, connector_transport.make_connector_error(
            "UNAUTHENTICATED",
            "connector operation requires an authenticated channel; "
            f"channel is unknown for connector '{connector_id}'.",
        )
    except Exception:
        return None, connector_transport.make_connector_error(
            "UNAUTHENTICATED",
            "connector operation requires an authenticated channel; "
            f"channel validation failed for connector '{connector_id}'.",
        )
    grants = list(projection.get("grants", []))
    if not grants:
        return None, connector_transport.make_connector_error(
            "FORBIDDEN",
            "connector operation forbidden: authenticated channel holds no write "
            f"grant for connector '{connector_id}'.",
        )
    try:
        descriptor = access_policy.authorize(channel_id, grants[0], connector_id)
    except access_policy.UnknownChannelError:
        return None, connector_transport.make_connector_error(
            "UNAUTHENTICATED",
            "connector operation requires an authenticated channel; "
            f"channel is unknown for connector '{connector_id}'.",
        )
    except access_policy.GrantDeniedError:
        return None, connector_transport.make_connector_error(
            "FORBIDDEN",
            f"connector operation forbidden for connector '{connector_id}': "
            "channel grant denied.",
        )
    except access_policy.SecretDetectedError:
        return None, connector_transport.make_connector_error(
            "FORBIDDEN",
            f"connector operation forbidden for connector '{connector_id}': "
            "identifiers carry non-ordinary content.",
        )
    except (ValueError, TypeError):
        return None, connector_transport.make_connector_error(
            "INVALID_REQUEST",
            "connector operation request carries an invalid channel or connector "
            "identifier.",
        )
    return (descriptor, projection), None


def _check_envelope(
    req_dict: dict[str, Any], expected_operation: str
) -> tuple[str, str, str, dict[str, Any], float] | ConnectorResponse:
    """Validate the shared request envelope for one dispatch verb.

    Returns ``(request_id, connector_id, operation, payload, limit)`` or an
    error ``ConnectorResponse``. A request whose operation differs from the
    selected public function is rejected, never reinterpreted.
    """
    raw_request_id = req_dict.get("request_id")
    raw_connector_id = req_dict.get("connector_id")
    raw_operation = req_dict.get("operation")
    req_id = raw_request_id if isinstance(raw_request_id, str) else "unknown_request"
    conn_id = raw_connector_id if isinstance(raw_connector_id, str) else "unknown_connector"
    op = raw_operation if isinstance(raw_operation, str) else expected_operation
    envelope_op = op if op in OPERATIONS else expected_operation

    def _err(code: str, detail: str, **kw: Any) -> ConnectorResponse:
        return _error_response(req_id, conn_id, envelope_op, code, detail, **kw)

    if req_dict.get("record_type") != RECORD_TYPE_REQUEST:
        return _err(
            "INVALID_REQUEST",
            f"connector {expected_operation} request must carry record_type "
            "connector_request.",
        )
    if req_dict.get("schema_version") != SCHEMA_VERSION:
        return _error_response(
            req_id,
            conn_id,
            envelope_op,
            "UNSUPPORTED_VERSION",
            f"connector {expected_operation} request requires schema_version "
            f"{SCHEMA_VERSION}.",
        )
    if raw_operation != expected_operation:
        return _err(
            "INVALID_REQUEST",
            f"connector {expected_operation} entrypoint cannot accept operation "
            f"'{raw_operation}'.",
        )
    try:
        _require_identifier(raw_request_id, "request_id")
        _require_identifier(raw_connector_id, "connector_id")
    except (ValueError, TypeError):
        return _err(
            "INVALID_REQUEST",
            f"connector {expected_operation} request requires nonempty request_id "
            "and connector_id.",
        )
    payload = req_dict.get("payload")
    if not isinstance(payload, dict):
        return _err(
            "INVALID_REQUEST",
            f"connector {expected_operation} request requires an object payload.",
        )
    ok, detail, limit_value = _validate_call_limit(req_dict.get("call_limit"))
    if not ok:
        return _err("INVALID_REQUEST", f"connector {expected_operation} request: {detail}.")
    if limit_value > MAX_CALL_LIMIT_MS:
        return _err(
            "BUDGET_EXCEEDED",
            f"connector {expected_operation} request call_limit exceeds the local "
            f"bound of {MAX_CALL_LIMIT_MS:g} ms.",
        )
    try:
        _digest_of_record(req_dict)
    except Exception as exc:
        return _err(
            "INVALID_REQUEST",
            f"connector {expected_operation} request is not strict canonical JSON "
            f"without in-band nulls: {exc}.",
        )
    return (req_id, conn_id, expected_operation, payload, limit_value)


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


def _journal_dispatch_event(
    channel_id: str, owner_domain: str, operation: str, data: dict[str, Any]
) -> Any | None:
    """Best-effort journal audit for one dispatch decision.

    Always attempts the ``append_event`` call shape when the channel carries
    an event kind; when no journal/clock is admitted the ingestion authority
    rejects the submission and local durability still holds.
    """
    try:
        projection = access_policy.channel_projection(channel_id)
        producer = projection.get("producer", {})
        kinds: list[str] = list(producer.get("allowed_event_kinds", []))
        if not kinds:
            return None
        clock = _discover_clock(owner_domain)
        if clock is None or not clock[0] or not clock[1]:
            occurred: Any = evidence_journal.NOT_OBSERVED
        else:
            clock_id, boot_id, origin = clock
            occurred = evidence_journal.TimePoint(
                clock_id=clock_id,
                boot_id=boot_id,
                origin=origin if origin else "engine_measured",
                monotonic_offset_ms=round(time.monotonic() * 1000.0, 3),
                utc_annotation=evidence_journal.NOT_OBSERVED,
            )
        submission = evidence_journal.EventSubmission(
            producer_sequence=_next_sequence(owner_domain),
            event_kind=kinds[0],
            event_schema_version="1",
            occurred_at=occurred,
            payload=evidence_journal.EvidencePayload(
                data=dict(data),
                measurements=(),
                evidence_refs=(),
                artifact_refs=(),
            ),
        )
        return evidence_journal.append_event(channel_id, owner_domain, submission)
    except Exception:
        return None


def _commit_dispatch_effect(
    channel_id: str, owner_domain: str, entity_id: str, command_id: str, state_ref: Any
) -> Any | None:
    """Best-effort owner-local fencing commit before wire delivery."""
    try:
        _require_identifier(entity_id, "entity_id")
        try:
            current = evidence_journal.entity_state(
                channel_id, owner_domain, entity_id
            ).revision
        except Exception:
            current = 0
        return evidence_journal.commit_effect(
            channel_id, owner_domain, entity_id, command_id, current, state_ref, ()
        )
    except Exception:
        return None


def _retain_record(
    channel_id: str, owner_domain: str, record: dict[str, Any]
) -> Any | None:
    """Best-effort durable install of one dispatch record."""
    try:
        payload = _canonical_json_bytes(record)
        return artifact_store.retain_artifact(
            channel_id, owner_domain, "application/json", payload, "public"
        )
    except Exception:
        return None


def _live_evidence_prefix(channel_id: str, journal_id: str) -> dict[str, Any] | None:
    """Pin a real evidence prefix when a journal is admitted.

    Exercises ``read_prefix`` for real: the candidate prefix names this
    dispatch journal, and the returned envelopes' tail becomes the pinned
    prefix. Any failure (no admission, unknown journal, head mismatch)
    yields ``None`` so the caller falls back to an explicit synthetic pin.
    """
    try:
        candidate = evidence_journal.JournalPrefix(
            journal_id=journal_id,
            last_sequence=1,
            head_hash="sha256:" + "0" * 64,
        )
        envelopes = evidence_journal.read_prefix(channel_id, candidate)
        if not envelopes:
            return None
        tail = envelopes[-1]
        journal = getattr(tail, "journal_id", journal_id)
        sequence = int(getattr(tail, "sequence", 0) or 0)
        head = getattr(tail, "event_hash", "")
        if sequence <= 0 or not head:
            return None
        return {"journal_id": str(journal), "last_sequence": sequence, "head_hash": str(head)}
    except Exception:
        return None


def _synthetic_evidence_ref(journal_id: str, event_id: str) -> dict[str, Any]:
    return {
        "journal_id": journal_id,
        "sequence": 1,
        "event_id": event_id,
        "event_hash": "sha256:" + "0" * 64,
        "pointer": "",
    }


def _find_forbidden_prepare_key(node: Any) -> str | None:
    if isinstance(node, dict):
        for key, value in node.items():
            if key in _FORBIDDEN_PREPARE_KEYS:
                return str(key)
            hit = _find_forbidden_prepare_key(value)
            if hit is not None:
                return hit
    elif isinstance(node, list):
        for item in node:
            hit = _find_forbidden_prepare_key(item)
            if hit is not None:
                return hit
    return None


# ---------------------------------------------------------------------------
# Test-only subject/version/observation configuration
# ---------------------------------------------------------------------------


def register_subject_for_tests(
    connector_id: str,
    subject_id: str,
    subject_version: str,
    *,
    configured_mode: str = "subject_apply",
    interface_surface: str = "browser_task",
    revision_basis: str = "unknown",
    native_revision: Any | None = None,
    configuration: dict[str, Any] | None = None,
    stack: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Pin the deployment subject + configuration for one connector (tests)."""
    _require_identifier(connector_id, "connector_id")
    _require_identifier(subject_id, "subject_id")
    _require_identifier(subject_version, "subject_version")
    _require_identifier(configured_mode, "configured_mode")
    _require_identifier(interface_surface, "interface_surface")
    if revision_basis not in ("native_revision", "source_digest", "operator_attestation", "unknown"):
        raise ValueError(f"unknown revision_basis: {revision_basis!r}")
    config = (
        copy.deepcopy(configuration)
        if isinstance(configuration, dict)
        else {"connector_id": connector_id, "connector_version": CONNECTOR_VERSION}
    )
    config_digest = _digest_of_record(config)
    subject = {
        "subject_id": subject_id,
        "subject_version": subject_version,
        "revision_basis": revision_basis,
        "native_revision": copy.deepcopy(native_revision)
        if native_revision is not None
        else _missing("not_observed"),
        "configured_mode": configured_mode,
        "interface_surface": interface_surface,
        "configuration_digest": config_digest,
        "stack": copy.deepcopy(stack) if stack is not None else [],
    }
    with _LOCK:
        _SUBJECTS[connector_id] = {
            "subject": subject,
            "configuration": config,
            "configuration_digest": config_digest,
        }
    return copy.deepcopy(subject)


def record_capability_evidence_for_tests(
    subject_id: str,
    subject_version: str,
    capability_id: str,
    availability: str,
    *,
    basis: str = "executed_observation",
    claim_origin: str = "native",
    journal_id: str | None = None,
    event_id: str | None = None,
) -> dict[str, Any]:
    """Establish version-scoped capability evidence (tests only).

    Evidence attaches to exactly one ``(subject_id, subject_version,
    capability_id)`` triple; it never inherits across versions.
    """
    _require_identifier(subject_id, "subject_id")
    _require_identifier(subject_version, "subject_version")
    if capability_id not in MINIMUM_CAPABILITY_IDS:
        raise ValueError(f"unknown capability_id: {capability_id!r}")
    if availability not in _EVIDENCED_AVAILABILITY:
        raise ValueError(
            f"availability {availability!r} needs no evidence; "
            "only present/absent/not_applicable can be evidenced"
        )
    if basis not in _VALID_EVIDENCE_BASIS:
        raise ValueError(f"unknown evidence basis: {basis!r}")
    if claim_origin not in _VALID_CLAIM_ORIGINS:
        raise ValueError(f"unknown claim_origin: {claim_origin!r}")
    record = {
        "availability": availability,
        "basis": basis,
        "claim_origin": claim_origin,
        "ref": _synthetic_evidence_ref(
            journal_id or f"journal_capability_{subject_id}",
            event_id or f"evt_{subject_version}_{capability_id}",
        ),
    }
    with _LOCK:
        _CAPABILITY_EVIDENCE[(subject_id, subject_version, capability_id)] = record
    return copy.deepcopy(record)


def rotate_configuration_for_tests(
    connector_id: str, configuration: dict[str, Any]
) -> str:
    """Replace the live deployment configuration digest (tests only)."""
    _require_identifier(connector_id, "connector_id")
    if not isinstance(configuration, dict):
        raise TypeError("configuration must be a dict")
    digest = _digest_of_record(configuration)
    with _LOCK:
        entry = _SUBJECTS.get(connector_id)
        if entry is None:
            raise KeyError(f"connector {connector_id!r} has no registered subject")
        entry["configuration"] = copy.deepcopy(configuration)
        entry["configuration_digest"] = digest
    return digest


def set_observation_state_for_tests(local_handle: str, state: str) -> None:
    """Move one handle's observation window (tests only)."""
    _require_identifier(local_handle, "local_handle")
    if state not in _VALID_OBSERVATION_STATES:
        raise ValueError(f"unknown observation state: {state!r}")
    with _LOCK:
        if local_handle not in _OBSERVATION:
            raise KeyError(f"unknown local_handle: {local_handle!r}")
        _OBSERVATION[local_handle] = state


def get_observation_state_for_tests(local_handle: str) -> str | None:
    with _LOCK:
        return _OBSERVATION.get(local_handle)


def mark_delivery_uncertain_for_tests(local_handle: str) -> dict[str, Any]:
    """Record that a dispatch may have been delivered (tests only).

    Preserves uncertainty: the execution keeps its handle and commission
    binding, and no second execution is ever launched from this mark.
    """
    _require_identifier(local_handle, "local_handle")
    with _LOCK:
        for commission_id, entry in _COMMISSION_EXECUTION.items():
            if entry.get("local_handle") == local_handle:
                entry["delivery"] = "may_have_dispatched"
                return {"commission_id": commission_id, **copy.deepcopy(entry)}
    raise KeyError(f"no commissioned execution for handle {local_handle!r}")


def get_commission_execution_for_tests(commission_id: str) -> dict[str, Any] | None:
    with _LOCK:
        entry = _COMMISSION_EXECUTION.get(commission_id)
        return copy.deepcopy(entry) if entry is not None else None


def get_preparation_for_tests(preparation_id: str) -> dict[str, Any] | None:
    with _LOCK:
        entry = _PREPARATIONS.get(preparation_id)
        return copy.deepcopy(entry) if entry is not None else None


# ---------------------------------------------------------------------------
# Describe
# ---------------------------------------------------------------------------


def _build_capability_records(subject_id: str, subject_version: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for capability_id in MINIMUM_CAPABILITY_IDS:
        evidence = _CAPABILITY_EVIDENCE.get((subject_id, subject_version, capability_id))
        if evidence is None:
            records.append(
                {
                    "capability_id": capability_id,
                    "requirement_refs": [],
                    "availability": "unknown",
                    "claim_origin": "harness",
                    "evidence": [],
                    "limitations": [],
                }
            )
        else:
            records.append(
                {
                    "capability_id": capability_id,
                    "requirement_refs": [],
                    "availability": evidence["availability"],
                    "claim_origin": evidence["claim_origin"],
                    "evidence": [
                        {"basis": evidence["basis"], "ref": copy.deepcopy(evidence["ref"])}
                    ],
                    "limitations": [],
                }
            )
    return records


def _build_descriptor(
    channel_id: str, connector_id: str, entry: dict[str, Any]
) -> dict[str, Any]:
    subject = copy.deepcopy(entry["subject"])
    subject_id = subject["subject_id"]
    subject_version = subject["subject_version"]
    capabilities = _build_capability_records(subject_id, subject_version)
    catalog_record = {
        "catalog_id": "capability_catalog",
        "capabilities": list(MINIMUM_CAPABILITY_IDS),
    }
    catalog_digest = _digest_of_record(catalog_record)
    with _LOCK:
        evidenced = sum(
            1
            for (sid, sver, _cid) in _CAPABILITY_EVIDENCE
            if sid == subject_id and sver == subject_version
        )
    capability_descriptor = {
        "record_type": "capability_descriptor",
        "schema_version": "evidence-kernel/0.1.0",
        "descriptor_id": f"capdesc_{subject_id}_{subject_version}",
        "descriptor_revision": 1 + evidenced,
        "declared_by": connector_id,
        "subject": copy.deepcopy(subject),
        "catalog": {
            "id": "capability_catalog",
            "version": "external-connector/0.1.0",
            "artifact_digest": catalog_digest,
        },
        "evidence_prefix": {
            "journal_id": f"journal_dispatch_{connector_id}",
            "last_sequence": 1,
            "head_hash": catalog_digest,
        },
        "supersedes": _missing("not_applicable"),
        "capabilities": capabilities,
    }
    operations = [
        {
            "operation": name,
            "implementation": "connector_local",
            "native_contract": _missing("not_applicable"),
            "capability_refs": [],
            "evidence_refs": [],
            "limitations": [],
        }
        for name in sorted(OPERATIONS)
    ]
    limits = {
        "max_call_wait": _duration_limit(MAX_CALL_LIMIT_MS),
        "max_observe_items": 100,
        "max_request_bytes": 1_000_000,
        "max_response_bytes": 1_000_000,
        "max_artifact_chunk_bytes": 262144,
        "max_queued_tasks": 16,
        "max_active_tasks": 4,
    }
    build_digest = _digest_of_record(
        {
            "connector_id": connector_id,
            "connector_version": CONNECTOR_VERSION,
            "subject_version": subject_version,
        }
    )
    binding_digest = _digest_of_record({"connector_id": connector_id, "binding": "dispatch_local"})
    budget_digest = _digest_of_record({"connector_id": connector_id, "limits": limits})
    journal_id = f"journal_dispatch_{connector_id}"
    evidence_prefix = _live_evidence_prefix(channel_id, journal_id)
    if evidence_prefix is None:
        evidence_prefix = {
            "journal_id": journal_id,
            "last_sequence": 1,
            "head_hash": _digest_of_record({"capabilities": capabilities}),
        }
    return {
        "record_type": "connector_descriptor",
        "schema_version": SCHEMA_VERSION,
        "connector_id": connector_id,
        "connector_version": CONNECTOR_VERSION,
        "build": {
            "id": connector_id,
            "version": CONNECTOR_VERSION,
            "artifact_digest": build_digest,
        },
        "binding": {
            "id": "binding_dispatch_local",
            "version": "0.1.0",
            "artifact_digest": binding_digest,
        },
        "subject": subject,
        "capabilities": capability_descriptor,
        "operations": operations,
        "task_mappings": [],
        "observation_channels": [],
        "action_grounding": "unknown",
        "execution_substrate": "unknown",
        "limits": limits,
        "budget_accounting": {
            "id": "budget_dispatch_local",
            "version": "0.1.0",
            "artifact_digest": budget_digest,
        },
        "evidence_prefix": evidence_prefix,
    }


async def describe_subject(
    channel_id: str, request: ConnectorRequest | dict[str, Any]
) -> ConnectorResponse:
    """Return the pinned descriptor for the connector's subject.

    Read-only: no probing, no task execution, no retained command receipt,
    so responses may reflect newer capability evidence.
    """
    try:
        req_dict = _as_request_dict(request)
    except TypeError:
        return _error_response(
            "unknown_request", "unknown_connector", "Describe", "INVALID_REQUEST",
            "connector Describe request must be a ConnectorRequest or mapping.",
        )
    checked = _check_envelope(req_dict, "Describe")
    if isinstance(checked, ConnectorResponse):
        return checked
    req_id, conn_id, _op, payload, _limit = checked
    auth, auth_err = _authenticate(channel_id, conn_id)
    if auth_err is not None:
        return ConnectorResponse(
            request_id=req_id, connector_id=conn_id, operation="Describe", result=auth_err
        )
    assert auth is not None
    _descriptor, projection = auth
    owner_domain = str(projection.get("axis", ""))
    if len(payload) != 0:
        return _error_response(
            req_id, conn_id, "Describe", "INVALID_REQUEST",
            "connector Describe operation requires an empty closed payload object.",
        )
    with _LOCK:
        entry = copy.deepcopy(_SUBJECTS.get(conn_id))
    if entry is None:
        return _error_response(
            req_id, conn_id, "Describe", "PREREQUISITE_UNAVAILABLE",
            f"connector Describe has no registered subject for connector "
            f"'{conn_id}'; describe requires a pinned subject/version.",
        )
    try:
        descriptor = _build_descriptor(channel_id, conn_id, entry)
        descriptor_digest = _digest_of_record(descriptor)
    except Exception as exc:
        return _error_response(
            req_id, conn_id, "Describe", "INTERNAL_ERROR",
            f"connector Describe could not assemble its pinned descriptor: {exc}.",
        )
    subject = descriptor["subject"]
    with _LOCK:
        _DESCRIPTORS[(conn_id, subject["subject_id"], subject["subject_version"])] = copy.deepcopy(
            descriptor
        )
        _CURRENT_DESCRIPTOR_DIGEST[conn_id] = descriptor_digest
    _retain_record(channel_id, owner_domain, descriptor)
    _journal_dispatch_event(
        channel_id,
        owner_domain,
        "Describe",
        {
            "connector_operation": "Describe",
            "request_id": req_id,
            "connector_id": conn_id,
            "subject_version": subject["subject_version"],
            "descriptor_digest": descriptor_digest,
        },
    )
    return ConnectorResponse(
        request_id=req_id, connector_id=conn_id, operation="Describe", result=descriptor
    )


# ---------------------------------------------------------------------------
# Prepare
# ---------------------------------------------------------------------------


def _validate_prepare_task(task: Any) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Validate the supplied task envelope (never execute or improve it)."""
    if not isinstance(task, dict):
        return None, connector_transport.make_connector_error(
            "INVALID_REQUEST", "connector Prepare operation requires a task object."
        )
    task_type = task.get("task_type")
    if task_type not in _VALID_TASK_TYPES:
        return None, connector_transport.make_connector_error(
            "UNSUPPORTED_MAPPING",
            f"connector Prepare operation has no mapping for task_type "
            f"'{task_type}'; expected one of apply, extract, discover_jobs.",
        )
    task_id = task.get("task_id")
    if not isinstance(task_id, str) or not task_id:
        return None, connector_transport.make_connector_error(
            "INVALID_REQUEST",
            "connector Prepare operation requires a nonempty task_id identifier.",
        )
    entry = task.get("entry")
    if not isinstance(entry, dict) or not isinstance(entry.get("logical_id"), str):
        return None, connector_transport.make_connector_error(
            "INVALID_REQUEST",
            "connector Prepare operation requires a task entry with a logical_id.",
        )
    goal = task.get("goal")
    if not isinstance(goal, str) or not goal:
        return None, connector_transport.make_connector_error(
            "INVALID_REQUEST",
            "connector Prepare operation requires an explicit bounded task goal.",
        )
    # Read-only invariant: HTTP method or task text never grants mutation
    # authority to discovery/extraction work.
    effect_policy = task.get("effect_policy")
    if task_type in ("extract", "discover_jobs"):
        if effect_policy != "read_only":
            return None, connector_transport.make_connector_error(
                "INVALID_REQUEST",
                f"connector Prepare operation: {task_type} tasks require "
                "effect_policy read_only; extraction cannot carry application "
                "authority.",
            )
    else:
        if effect_policy != "commissioned_application":
            return None, connector_transport.make_connector_error(
                "INVALID_REQUEST",
                "connector Prepare operation: apply tasks require effect_policy "
                "commissioned_application.",
            )
    context_policy = task.get("context_policy")
    if context_policy is not None:
        if not isinstance(context_policy, dict):
            return None, connector_transport.make_connector_error(
                "INVALID_REQUEST",
                "connector Prepare operation requires context_policy to be an object.",
            )
        for dimension, valid_modes in (
            ("browser_state", _VALID_BROWSER_MODES),
            ("learning_state", _VALID_LEARNING_MODES),
        ):
            policy = context_policy.get(dimension)
            if policy is None:
                continue
            if not isinstance(policy, dict):
                return None, connector_transport.make_connector_error(
                    "INVALID_REQUEST",
                    f"connector Prepare operation requires context_policy "
                    f"{dimension} to be an object.",
                )
            mode = policy.get("mode")
            requirement = policy.get("requirement")
            if mode not in valid_modes:
                return None, connector_transport.make_connector_error(
                    "UNSUPPORTED_MAPPING",
                    f"connector Prepare operation has no mapping for "
                    f"context_policy {dimension} mode '{mode}'.",
                )
            if requirement not in _VALID_REQUIREMENTS:
                return None, connector_transport.make_connector_error(
                    "INVALID_REQUEST",
                    f"connector Prepare operation requires context_policy "
                    f"{dimension} requirement to be required or best_effort.",
                )
            if requirement == "required" and mode == "not_applicable":
                return None, connector_transport.make_connector_error(
                    "INVALID_REQUEST",
                    f"connector Prepare operation: required context_policy "
                    f"{dimension} cannot be not_applicable.",
                )
    budgets = task.get("budgets")
    if budgets is not None:
        if not isinstance(budgets, dict):
            return None, connector_transport.make_connector_error(
                "INVALID_REQUEST",
                "connector Prepare operation requires budgets to be an object.",
            )
        for dimension in (
            "active_limit",
            "action_limit",
            "observation_byte_limit",
            "recovery_limit",
            "model_token_limit",
        ):
            bound = budgets.get(dimension)
            if not isinstance(bound, dict):
                return None, connector_transport.make_connector_error(
                    "INVALID_REQUEST",
                    f"connector Prepare operation requires budgets {dimension} "
                    "to be a DurationLimit.",
                )
            ok, _detail, _value = _validate_call_limit(bound)
            if not ok:
                return None, connector_transport.make_connector_error(
                    "INVALID_REQUEST",
                    f"connector Prepare operation requires budgets {dimension} "
                    "to be an exact millisecond DurationLimit.",
                )
    return task, None


def _derive_prepare_concerns(
    payload: dict[str, Any], connector_id: str
) -> tuple[list[dict[str, Any]] | None, dict[str, Any] | None]:
    """Derive non-blocking preparation concerns from the admitted payload."""
    concerns: list[dict[str, Any]] = []
    journal_id = f"journal_dispatch_{connector_id}"

    def _concern(concern_id: str, category: str, detail: str) -> dict[str, Any]:
        assert category in _VALID_CONCERN_CATEGORIES
        return {
            "concern_id": concern_id,
            "category": category,
            "disposition": "requires_acceptance",
            "detail": detail,
            "evidence_refs": [_synthetic_evidence_ref(journal_id, f"evt_{concern_id}")],
        }

    runtime_access = payload.get("runtime_access")
    if runtime_access is not None and not _is_missing(runtime_access):
        if not isinstance(runtime_access, dict):
            return None, connector_transport.make_connector_error(
                "INVALID_REQUEST",
                "connector Prepare operation requires runtime_access to be an "
                "object or Missing.",
            )
        purpose = runtime_access.get("purpose")
        if purpose not in _VALID_RUNTIME_PURPOSES:
            return None, connector_transport.make_connector_error(
                "INVALID_REQUEST",
                "connector Prepare operation requires runtime_access purpose to be "
                "application_entry, account_session, or input_artifact.",
            )
        if purpose == "account_session":
            concerns.append(
                _concern(
                    "session_use_requires_acceptance",
                    "state_policy_unverified",
                    "The prepared task resolves an account session reference; starting "
                    "it spends session authority that requires explicit acceptance.",
                )
            )
    task = payload.get("task", {})
    if isinstance(task, dict):
        context_policy = task.get("context_policy")
        if isinstance(context_policy, dict):
            for dimension in ("browser_state", "learning_state"):
                policy = context_policy.get(dimension)
                if (
                    isinstance(policy, dict)
                    and policy.get("requirement") == "best_effort"
                    and policy.get("mode") == "reuse"
                ):
                    concerns.append(
                        _concern(
                            f"{dimension}_reuse_best_effort",
                            "state_policy_unverified",
                            f"The prepared task reuses {dimension} on a best-effort basis; "
                            "isolation from prior state is not established.",
                        )
                    )
    assistance = payload.get("assistance")
    if isinstance(assistance, dict) and assistance.get("online_replanning") is True:
        concerns.append(
            _concern(
                "online_replanning",
                "assistance_limit",
                "The prepared task permits online replanning; the delivered plan may "
                "change after preparation and requires explicit acceptance.",
            )
        )
    return concerns, None


def _scope_commission_summary(scope: dict[str, Any]) -> dict[str, Any]:
    """Extract the commission linkage carried inline by a WorkScope."""
    commission = scope.get("commission")
    commission_ref = scope.get("commission_ref")
    commission_id: str | None = None
    if isinstance(commission, dict) and isinstance(commission.get("commission_id"), str):
        commission_id = commission["commission_id"]
    return {"commission": commission, "commission_ref": commission_ref, "commission_id": commission_id}


async def prepare_task(
    channel_id: str, request: ConnectorRequest | dict[str, Any]
) -> ConnectorResponse:
    """Validate and serialize a task without executing anything.

    Fails connector conformance for any request that would browse, probe,
    invoke planning, test authentication, reset context, or otherwise
    execute during preparation.
    """
    try:
        req_dict = _as_request_dict(request)
    except TypeError:
        return _error_response(
            "unknown_request", "unknown_connector", "Prepare", "INVALID_REQUEST",
            "connector Prepare request must be a ConnectorRequest or mapping.",
        )
    checked = _check_envelope(req_dict, "Prepare")
    if isinstance(checked, ConnectorResponse):
        return checked
    req_id, conn_id, _op, payload, _limit = checked
    auth, auth_err = _authenticate(channel_id, conn_id)
    if auth_err is not None:
        return ConnectorResponse(
            request_id=req_id, connector_id=conn_id, operation="Prepare", result=auth_err
        )
    assert auth is not None
    descriptor, projection = auth
    principal = str(descriptor.principal_id)
    owner_domain = str(projection.get("axis", descriptor.owner_domain))
    command_key = (principal, conn_id, req_id)
    try:
        fingerprint = _digest_of_record(req_dict)
    except Exception as exc:  # pragma: no cover - envelope already gated this
        return _error_response(
            req_id, conn_id, "Prepare", "INVALID_REQUEST",
            f"connector Prepare request cannot be fingerprinted: {exc}.",
        )
    with _LOCK:
        retained = _COMMANDS.get(command_key)
        if retained is not None:
            if retained["fingerprint"] != fingerprint:
                return _error_response(
                    req_id, conn_id, "Prepare", "IDEMPOTENCY_CONFLICT",
                    "connector Prepare operation reused command identity "
                    f"'{req_id}' with changed request content.",
                )
            stored: ConnectorResponse = retained["response"]
            return ConnectorResponse(
                request_id=stored.request_id,
                connector_id=stored.connector_id,
                operation=stored.operation,
                result=copy.deepcopy(stored.result),
            )
    with _LOCK:
        subject_entry = copy.deepcopy(_SUBJECTS.get(conn_id))
    if subject_entry is None:
        return _error_response(
            req_id, conn_id, "Prepare", "PREREQUISITE_UNAVAILABLE",
            f"connector Prepare has no registered subject/configuration for "
            f"connector '{conn_id}'; describe the subject before preparing.",
        )
    scope = payload.get("scope")
    configuration = payload.get("configuration")
    task = payload.get("task")
    if not isinstance(scope, dict):
        return _error_response(
            req_id, conn_id, "Prepare", "INVALID_REQUEST",
            "connector Prepare operation requires a scope object.",
        )
    if not isinstance(configuration, dict):
        return _error_response(
            req_id, conn_id, "Prepare", "INVALID_REQUEST",
            "connector Prepare operation requires a configuration object.",
        )
    activity = scope.get("activity")
    if not isinstance(activity, str) or not activity:
        return _error_response(
            req_id, conn_id, "Prepare", "INVALID_REQUEST",
            "connector Prepare operation requires a scope activity identifier.",
        )
    # Prepare is non-executing: any execution-shaped key fails conformance.
    forbidden = _find_forbidden_prepare_key(payload)
    if forbidden is not None:
        return _error_response(
            req_id, conn_id, "Prepare", "INVALID_REQUEST",
            f"connector Prepare operation is non-executing; payload key "
            f"'{forbidden}' asks for browsing, probing, planning, authentication, "
            "state reset, or execution during preparation.",
        )
    if "recovery" in payload:
        return _error_response(
            req_id, conn_id, "Prepare", "INVALID_REQUEST",
            "connector Prepare operation cannot carry recovery; preparation never "
            "resumes an execution.",
        )
    # Manual commissions are not dispatchable through this contract.
    inline_commission = scope.get("commission")
    if isinstance(inline_commission, dict):
        execution = inline_commission.get("execution")
        if isinstance(execution, dict) and execution.get("mode") == "manual":
            return _error_response(
                req_id, conn_id, "Prepare", "FORBIDDEN",
                "connector Prepare operation cannot prepare a manual commission; "
                "manual work is recorded, never dispatched.",
            )
    validated_task, task_err = _validate_prepare_task(task)
    if task_err is not None:
        response = ConnectorResponse(
            request_id=req_id, connector_id=conn_id, operation="Prepare", result=task_err
        )
        with _LOCK:
            _COMMANDS[command_key] = {"fingerprint": fingerprint, "response": response}
        return response
    assert validated_task is not None
    if configuration.get("connector_id") != conn_id:
        return _error_response(
            req_id, conn_id, "Prepare", "INVALID_REQUEST",
            "connector Prepare operation configuration names a different connector "
            "than the request.",
        )
    concerns, concerns_err = _derive_prepare_concerns(payload, conn_id)
    if concerns_err is not None:
        response = ConnectorResponse(
            request_id=req_id, connector_id=conn_id, operation="Prepare", result=concerns_err
        )
        with _LOCK:
            _COMMANDS[command_key] = {"fingerprint": fingerprint, "response": response}
        return response
    assert concerns is not None
    # A pinned descriptor reference must resolve and agree with the supplied
    # configuration; an unresolvable or disagreeing pin is stale.
    descriptor_ref = configuration.get("descriptor")
    if isinstance(descriptor_ref, dict):
        try:
            descriptor_bytes = artifact_store.resolve_artifact(channel_id, descriptor_ref)
            descriptor_record = json.loads(descriptor_bytes.decode("utf-8"))
        except Exception:
            return _error_response(
                req_id, conn_id, "Prepare", "STALE_PREPARATION",
                "connector Prepare operation pins a descriptor reference that does "
                "not resolve to retained descriptor bytes.",
            )
        if not isinstance(descriptor_record, dict):
            return _error_response(
                req_id, conn_id, "Prepare", "STALE_PREPARATION",
                "connector Prepare operation pins descriptor bytes that are not a "
                "descriptor record.",
            )
        if descriptor_record.get("connector_id") != conn_id:
            return _error_response(
                req_id, conn_id, "Prepare", "STALE_PREPARATION",
                "connector Prepare operation pins a descriptor for a different "
                "connector.",
            )
        configured_subject = configuration.get("subject")
        pinned_subject = descriptor_record.get("subject")
        if (
            isinstance(configured_subject, dict)
            and isinstance(pinned_subject, dict)
            and (
                configured_subject.get("subject_id") != pinned_subject.get("subject_id")
                or configured_subject.get("subject_version")
                != pinned_subject.get("subject_version")
            )
        ):
            return _error_response(
                req_id, conn_id, "Prepare", "STALE_PREPARATION",
                "connector Prepare operation configuration subject disagrees with "
                "its pinned descriptor.",
            )
    try:
        configuration_digest = _digest_of_record(configuration)
    except Exception as exc:
        return _error_response(
            req_id, conn_id, "Prepare", "INVALID_REQUEST",
            f"connector Prepare operation configuration is not strict canonical "
            f"JSON: {exc}.",
        )
    with _LOCK:
        descriptor_digest = _CURRENT_DESCRIPTOR_DIGEST.get(conn_id)
    _commit_dispatch_effect(
        channel_id, owner_domain, f"dispatch_prepare_{conn_id}", req_id,
        _retain_record(channel_id, owner_domain, {"prepare_command": req_id}) or _missing("not_observed"),
    )
    forwarded = ConnectorRequest(
        request_id=req_id,
        connector_id=conn_id,
        operation="Prepare",
        call_limit=copy.deepcopy(req_dict.get("call_limit", {})),
        payload=copy.deepcopy(payload),
    )
    try:
        transport_response = await connector_transport.call_connector(channel_id, forwarded)
    except Exception as exc:
        return _error_response(
            req_id, conn_id, "Prepare", "INTERNAL_ERROR",
            f"connector Prepare operation carrier failed: {exc}.",
        )
    result = copy.deepcopy(transport_response.result)
    if isinstance(result, dict) and result.get("kind") == "prepared":
        preparation_id = result.get("preparation", {}).get("preparation_id")
        if not isinstance(preparation_id, str) or not preparation_id:
            return _error_response(
                req_id, conn_id, "Prepare", "INTERNAL_ERROR",
                "connector Prepare operation returned a preparation without identity.",
            )
        # The dispatch gate owns concern semantics: disclose every derived
        # concern on the returned record so Start can require acceptance.
        if isinstance(result.get("record"), dict):
            result["record"]["concerns"] = copy.deepcopy(concerns)
        summary = _scope_commission_summary(scope)
        with _LOCK:
            _PREPARATIONS[preparation_id] = {
                "connector_id": conn_id,
                "principal": principal,
                "scope": copy.deepcopy(scope),
                "configuration": copy.deepcopy(configuration),
                "configuration_digest": configuration_digest,
                "descriptor_digest": descriptor_digest,
                "task": copy.deepcopy(validated_task),
                "concerns": copy.deepcopy(concerns),
                "commission_id": summary["commission_id"],
                "commission_ref": copy.deepcopy(summary["commission_ref"]),
            }
        _journal_dispatch_event(
            channel_id,
            owner_domain,
            "Prepare",
            {
                "connector_operation": "Prepare",
                "request_id": req_id,
                "connector_id": conn_id,
                "preparation_id": preparation_id,
                "configuration_digest": configuration_digest,
                "concern_ids": [c["concern_id"] for c in concerns],
            },
        )
    response = ConnectorResponse(
        request_id=transport_response.request_id,
        connector_id=transport_response.connector_id,
        operation=transport_response.operation,
        result=result,
    )
    if not (isinstance(result, dict) and result.get("kind") == "connector_error"):
        with _LOCK:
            _COMMANDS[command_key] = {
                "fingerprint": fingerprint,
                "response": ConnectorResponse(
                    request_id=response.request_id,
                    connector_id=response.connector_id,
                    operation=response.operation,
                    result=copy.deepcopy(response.result),
                ),
            }
    else:
        code = result.get("code")
        if code not in _NON_RETAINED_GATE_CODES:
            with _LOCK:
                _COMMANDS[command_key] = {
                    "fingerprint": fingerprint,
                    "response": ConnectorResponse(
                        request_id=response.request_id,
                        connector_id=response.connector_id,
                        operation=response.operation,
                        result=copy.deepcopy(response.result),
                    ),
                }
    return response


# ---------------------------------------------------------------------------
# Start
# ---------------------------------------------------------------------------


def _is_initial_recovery(recovery: Any) -> bool:
    return _is_missing(recovery) and recovery.get("reason") == "not_applicable"


def _validate_resume_authorization(
    recovery: Any,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    if _is_missing(recovery):
        return None, connector_transport.make_connector_error(
            "INVALID_REQUEST",
            "connector Start operation requires recovery to be inapplicable or a "
            "resume authorization.",
        )
    if not isinstance(recovery, dict):
        return None, connector_transport.make_connector_error(
            "INVALID_REQUEST",
            "connector Start operation requires recovery to be inapplicable or a "
            "resume authorization.",
        )
    expected = {"handle", "checkpoint", "native_resume_contract", "authorization_refs", "evidence_refs"}
    if set(recovery.keys()) != expected:
        return None, connector_transport.make_connector_error(
            "INVALID_REQUEST",
            "connector Start resume authorization must carry exactly handle, "
            "checkpoint, native_resume_contract, authorization_refs, and "
            "evidence_refs.",
        )
    handle = recovery.get("handle")
    if (
        not isinstance(handle, dict)
        or not isinstance(handle.get("connector_id"), str)
        or not isinstance(handle.get("local_handle"), str)
        or not handle["connector_id"]
        or not handle["local_handle"]
    ):
        return None, connector_transport.make_connector_error(
            "INVALID_REQUEST",
            "connector Start resume authorization requires a handle with "
            "connector_id and local_handle.",
        )
    checkpoint = recovery.get("checkpoint")
    if not isinstance(checkpoint, dict) or _is_missing(checkpoint):
        return None, connector_transport.make_connector_error(
            "INVALID_REQUEST",
            "connector Start resume authorization requires an evidenced native "
            "checkpoint artifact.",
        )
    contract = recovery.get("native_resume_contract")
    if not isinstance(contract, dict) or _is_missing(contract):
        return None, connector_transport.make_connector_error(
            "INVALID_REQUEST",
            "connector Start resume authorization requires a native resume contract.",
        )
    authorization_refs = recovery.get("authorization_refs")
    evidence_refs = recovery.get("evidence_refs")
    if not isinstance(authorization_refs, list) or not authorization_refs:
        return None, connector_transport.make_connector_error(
            "INVALID_REQUEST",
            "connector Start resume authorization requires nonempty explicit "
            "recovery authority.",
        )
    if not isinstance(evidence_refs, list) or not evidence_refs:
        return None, connector_transport.make_connector_error(
            "INVALID_REQUEST",
            "connector Start resume authorization requires nonempty evidence.",
        )
    return recovery, None


def _load_scope_commission(
    channel_id: str, scope: dict[str, Any]
) -> tuple[Any | None, dict[str, Any] | None]:
    """Resolve the registered commission for an application scope.

    Returns ``(commission, None)`` on success or ``(None, error)`` when the
    commission is missing, unregistered, or not dispatchable. Discovery
    scopes carry no commission and return ``(None, None)``.
    """
    if scope.get("activity") != "application_attempt":
        return None, None
    commission_ref = scope.get("commission_ref")
    if commission_ref is None or _is_missing(commission_ref):
        return None, connector_transport.make_connector_error(
            "NOT_ADMITTED",
            "connector Start operation precedes commission registration: an "
            "application scope without a commission reference cannot dispatch.",
        )
    if not isinstance(commission_ref, dict):
        return None, connector_transport.make_connector_error(
            "INVALID_REQUEST",
            "connector Start operation requires commission_ref to be an artifact "
            "reference.",
        )
    try:
        commission = attempt_commissioning.load_commission(channel_id, commission_ref)
    except Exception as exc:
        return None, connector_transport.make_connector_error(
            "NOT_ADMITTED",
            "connector Start operation precedes commission registration: the "
            f"commission reference does not resolve to a registered commission "
            f"({exc}).",
        )
    execution = commission.execution
    mode = execution.get("mode") if isinstance(execution, dict) else getattr(execution, "mode", None)
    if isinstance(execution, dict):
        mode = execution.get("mode")
    else:
        mode = getattr(execution, "mode", None)
    if mode != "subject":
        return None, connector_transport.make_connector_error(
            "FORBIDDEN",
            "connector Start operation cannot dispatch a manual commission; manual "
            "work is recorded, never dispatched.",
        )
    inline = scope.get("commission")
    if isinstance(inline, dict) and isinstance(inline.get("commission_id"), str):
        if inline["commission_id"] != commission.commission_id:
            return None, connector_transport.make_connector_error(
                "INVALID_REQUEST",
                "connector Start operation scope commission disagrees with the "
                "registered commission.",
            )
    for field in ("run_id", "journal_id"):
        scoped = scope.get(field)
        if isinstance(scoped, str) and scoped and scoped != getattr(commission, field):
            return None, connector_transport.make_connector_error(
                "INVALID_REQUEST",
                f"connector Start operation scope {field} disagrees with the "
                "registered commission.",
            )
    return commission, None


async def start_task(
    channel_id: str, request: ConnectorRequest | dict[str, Any]
) -> ConnectorResponse:
    """Durably admit one logical execution without awaiting completion.

    Every gate (commission registration, concern acceptance, staleness,
    executor fence, resume window) passes before the request reaches the
    carrier, so a rejection never causes a native delivery.
    """
    try:
        req_dict = _as_request_dict(request)
    except TypeError:
        return _error_response(
            "unknown_request", "unknown_connector", "Start", "INVALID_REQUEST",
            "connector Start request must be a ConnectorRequest or mapping.",
        )
    checked = _check_envelope(req_dict, "Start")
    if isinstance(checked, ConnectorResponse):
        return checked
    req_id, conn_id, _op, payload, _limit = checked
    auth, auth_err = _authenticate(channel_id, conn_id)
    if auth_err is not None:
        return ConnectorResponse(
            request_id=req_id, connector_id=conn_id, operation="Start", result=auth_err
        )
    assert auth is not None
    descriptor, projection = auth
    principal = str(descriptor.principal_id)
    owner_domain = str(projection.get("axis", descriptor.owner_domain))
    command_key = (principal, conn_id, req_id)
    try:
        fingerprint = _digest_of_record(req_dict)
    except Exception as exc:  # pragma: no cover - envelope already gated this
        return _error_response(
            req_id, conn_id, "Start", "INVALID_REQUEST",
            f"connector Start request cannot be fingerprinted: {exc}.",
        )
    with _LOCK:
        retained = _COMMANDS.get(command_key)
        if retained is not None:
            if retained["fingerprint"] != fingerprint:
                return _error_response(
                    req_id, conn_id, "Start", "IDEMPOTENCY_CONFLICT",
                    "connector Start operation reused command identity "
                    f"'{req_id}' with changed request content.",
                )
            stored: ConnectorResponse = retained["response"]
            return ConnectorResponse(
                request_id=stored.request_id,
                connector_id=stored.connector_id,
                operation=stored.operation,
                result=copy.deepcopy(stored.result),
            )
    preparation_ref = payload.get("preparation")
    idempotency_key = payload.get("idempotency_key")
    accepted = payload.get("accepted_concern_ids")
    authorization_refs = payload.get("authorization_refs")
    recovery = payload.get("recovery", _missing("not_applicable"))
    if not isinstance(preparation_ref, dict) or not isinstance(
        preparation_ref.get("preparation_id"), str
    ):
        return _error_response(
            req_id, conn_id, "Start", "INVALID_REQUEST",
            "connector Start operation requires a preparation reference with "
            "preparation_id.",
        )
    preparation_id = preparation_ref["preparation_id"]
    try:
        _require_identifier(preparation_id, "preparation_id")
        _require_identifier(idempotency_key, "idempotency_key")
    except (ValueError, TypeError):
        return _error_response(
            req_id, conn_id, "Start", "INVALID_REQUEST",
            "connector Start operation requires nonempty preparation_id and "
            "idempotency_key identifiers.",
        )
    if not isinstance(accepted, list):
        return _error_response(
            req_id, conn_id, "Start", "INVALID_REQUEST",
            "connector Start operation requires accepted_concern_ids as a list.",
        )
    if not isinstance(authorization_refs, list):
        return _error_response(
            req_id, conn_id, "Start", "INVALID_REQUEST",
            "connector Start operation requires authorization_refs as a list.",
        )
    assert isinstance(idempotency_key, str)
    with _LOCK:
        stored_prep = copy.deepcopy(_PREPARATIONS.get(preparation_id))
    if stored_prep is None:
        return _error_response(
            req_id, conn_id, "Start", "UNKNOWN_PREPARATION",
            f"connector Start operation references unknown preparation "
            f"'{preparation_id}'.",
        )
    if stored_prep.get("principal") != principal:
        return _error_response(
            req_id, conn_id, "Start", "UNKNOWN_PREPARATION",
            "connector Start operation references a preparation that is not "
            "visible to this authenticated principal.",
        )
    if stored_prep.get("connector_id") != conn_id:
        return _error_response(
            req_id, conn_id, "Start", "STALE_PREPARATION",
            "connector Start operation references a preparation pinned to a "
            "different connector; it cannot start under this connector.",
        )
    # Required concerns must be accepted; unknown concern IDs are rejected.
    known_concerns = {
        c["concern_id"]
        for c in stored_prep.get("concerns", [])
        if isinstance(c, dict) and isinstance(c.get("concern_id"), str)
    }
    for concern_id in accepted:
        if not isinstance(concern_id, str) or concern_id not in known_concerns:
            return _error_response(
                req_id, conn_id, "Start", "INVALID_REQUEST",
                "connector Start operation lists an unknown concern id; only "
                "evidenced requires_acceptance concerns may be accepted.",
            )
    required_unaccepted = [
        c["concern_id"]
        for c in stored_prep.get("concerns", [])
        if isinstance(c, dict)
        and c.get("disposition") == "requires_acceptance"
        and c.get("concern_id") not in set(accepted)
    ]
    if required_unaccepted:
        return _error_response(
            req_id, conn_id, "Start", "FORBIDDEN",
            "connector Start operation requires acceptance of preparation "
            f"concerns {sorted(required_unaccepted)} before dispatch.",
        )
    # Stale configuration or preparation is rejected; never silently reprepared.
    with _LOCK:
        current_config = copy.deepcopy((_SUBJECTS.get(conn_id) or {}).get("configuration_digest"))
        current_descriptor = _CURRENT_DESCRIPTOR_DIGEST.get(conn_id)
    if current_config is not None and stored_prep.get("configuration_digest") != current_config:
        return _error_response(
            req_id, conn_id, "Start", "STALE_PREPARATION",
            "connector Start operation references a preparation whose configuration "
            "changed since preparation; reprepare explicitly under the live "
            "configuration.",
        )
    pinned_descriptor = stored_prep.get("descriptor_digest")
    if (
        pinned_descriptor is not None
        and current_descriptor is not None
        and pinned_descriptor != current_descriptor
    ):
        return _error_response(
            req_id, conn_id, "Start", "STALE_PREPARATION",
            "connector Start operation references a preparation pinned to a "
            "superseded descriptor; reprepare explicitly.",
        )
    # Commission before authorized automated dispatch.
    scope = stored_prep.get("scope", {})
    commission, commission_err = _load_scope_commission(channel_id, scope)
    if commission_err is not None:
        return ConnectorResponse(
            request_id=req_id, connector_id=conn_id, operation="Start", result=commission_err
        )
    commission_id = commission.commission_id if commission is not None else None
    # The commission fence: one commission holds one logical execution.
    # Changing the key, caller, or executor never acquires another.
    logical_key = (principal, conn_id, idempotency_key)
    if commission_id is not None:
        with _LOCK:
            fenced = copy.deepcopy(_COMMISSION_EXECUTION.get(commission_id))
        if fenced is not None:
            if (
                fenced.get("principal") != principal
                or fenced.get("connector_id") != conn_id
                or fenced.get("idempotency_key") != idempotency_key
            ):
                changed = (
                    "executor"
                    if fenced.get("connector_id") != conn_id
                    else ("caller" if fenced.get("principal") != principal else "key")
                )
                return _error_response(
                    req_id, conn_id, "Start", "IDEMPOTENCY_CONFLICT",
                    f"connector Start operation cannot move commission "
                    f"'{commission_id}' to a second logical execution by changing "
                    f"its {changed}; the commissioned execution keeps handle "
                    f"'{fenced.get('local_handle')}' with delivery "
                    f"'{fenced.get('delivery')}'.",
                    handle={"connector_id": fenced.get("connector_id"), "local_handle": fenced.get("local_handle")},
                )
    is_initial = _is_initial_recovery(recovery)
    resume: dict[str, Any] | None = None
    if not is_initial:
        resume, resume_err = _validate_resume_authorization(recovery)
        if resume_err is not None:
            return ConnectorResponse(
                request_id=req_id, connector_id=conn_id, operation="Start", result=resume_err
            )
        assert resume is not None
        with _LOCK:
            mirrored = copy.deepcopy(_LOGICAL.get(logical_key))
        resume_handle = resume["handle"]
        if mirrored is None or mirrored.get("local_handle") != resume_handle.get("local_handle"):
            return _error_response(
                req_id, conn_id, "Start", "INVALID_REQUEST",
                "connector Start resume requires the existing logical idempotency "
                "key and handle for the same request and context.",
            )
        if resume_handle.get("connector_id") != conn_id:
            return _error_response(
                req_id, conn_id, "Start", "INVALID_REQUEST",
                "connector Start resume handle names a different connector than "
                "the request.",
            )
        with _LOCK:
            window = _OBSERVATION.get(str(resume_handle.get("local_handle")))
        if window != "open":
            return _error_response(
                req_id, conn_id, "Start", "OBSERVATION_CLOSED",
                f"connector Start resume is rejected: the observation window for "
                f"handle '{resume_handle.get('local_handle')}' is "
                f"'{window or 'unknown'}', not open.",
                handle={
                    "connector_id": conn_id,
                    "local_handle": resume_handle.get("local_handle"),
                },
            )
        try:
            artifact_store.resolve_artifact(channel_id, resume["checkpoint"])
        except Exception:
            return _error_response(
                req_id, conn_id, "Start", "ARTIFACT_UNAVAILABLE",
                "connector Start resume checkpoint does not resolve to retained "
                "bytes; resume requires an evidenced native checkpoint.",
            )
    else:
        if _is_missing(recovery) and recovery.get("reason") != "not_applicable":
            return _error_response(
                req_id, conn_id, "Start", "INVALID_REQUEST",
                "connector Start initial recovery must be Missing(not_applicable).",
            )
        if not _is_missing(recovery):  # pragma: no cover - defensive
            return _error_response(
                req_id, conn_id, "Start", "INVALID_REQUEST",
                "connector Start operation requires recovery to be inapplicable or "
                "a resume authorization.",
            )
    # Same logical key with changed preparation content is rejected.
    with _LOCK:
        mirrored = copy.deepcopy(_LOGICAL.get(logical_key))
    if mirrored is not None and mirrored.get("preparation_id") != preparation_id:
        return _error_response(
            req_id, conn_id, "Start", "IDEMPOTENCY_CONFLICT",
            "connector Start operation reused a logical execution key with changed "
            "preparation content.",
            handle={"connector_id": conn_id, "local_handle": mirrored.get("local_handle")},
        )
    # Durably commit handle binding, idempotency association, and dispatch
    # intent under owner-local fencing before the carrier delivers.
    state_ref = _retain_record(
        channel_id,
        owner_domain,
        {
            "dispatch_intent": "start",
            "request_id": req_id,
            "connector_id": conn_id,
            "preparation_id": preparation_id,
            "idempotency_key": idempotency_key,
            "resume": not is_initial,
        },
    )
    _commit_dispatch_effect(
        channel_id, owner_domain, f"dispatch_start_{conn_id}", req_id, state_ref
    )
    forwarded_payload = {
        "preparation": {"preparation_id": preparation_id},
        "idempotency_key": idempotency_key,
        # Dispatch-level concerns are already gated above; the carrier tracks
        # no concerns of its own, so forward an empty acceptance list.
        "accepted_concern_ids": [],
        "authorization_refs": copy.deepcopy(authorization_refs),
        "recovery": copy.deepcopy(recovery),
    }
    forwarded = ConnectorRequest(
        request_id=req_id,
        connector_id=conn_id,
        operation="Start",
        call_limit=copy.deepcopy(req_dict.get("call_limit", {})),
        payload=forwarded_payload,
    )
    try:
        transport_response = await connector_transport.call_connector(channel_id, forwarded)
    except Exception as exc:
        return _error_response(
            req_id, conn_id, "Start", "INTERNAL_ERROR",
            f"connector Start operation carrier failed: {exc}.",
        )
    result = copy.deepcopy(transport_response.result)
    response = ConnectorResponse(
        request_id=transport_response.request_id,
        connector_id=transport_response.connector_id,
        operation=transport_response.operation,
        result=result,
    )
    if isinstance(result, dict) and result.get("kind") == "started":
        handle = result.get("handle", {})
        local_handle = handle.get("local_handle") if isinstance(handle, dict) else None
        if not isinstance(local_handle, str) or not local_handle:
            return _error_response(
                req_id, conn_id, "Start", "INTERNAL_ERROR",
                "connector Start operation returned acceptance without a handle.",
            )
        with _LOCK:
            _LOGICAL[logical_key] = {
                "local_handle": local_handle,
                "preparation_id": preparation_id,
                "commission_id": commission_id,
            }
            if commission_id is not None and commission_id not in _COMMISSION_EXECUTION:
                _COMMISSION_EXECUTION[commission_id] = {
                    "principal": principal,
                    "connector_id": conn_id,
                    "idempotency_key": idempotency_key,
                    "local_handle": local_handle,
                    "delivery": "accepted_locally",
                }
            _OBSERVATION.setdefault(local_handle, "open")
            _DELIVERIES[local_handle] = _DELIVERIES.get(local_handle, 0) + 1
        _journal_dispatch_event(
            channel_id,
            owner_domain,
            "Start",
            {
                "connector_operation": "Start",
                "request_id": req_id,
                "connector_id": conn_id,
                "preparation_id": preparation_id,
                "local_handle": local_handle,
                "resume": not is_initial,
            },
        )
        with _LOCK:
            _COMMANDS[command_key] = {
                "fingerprint": fingerprint,
                "response": ConnectorResponse(
                    request_id=response.request_id,
                    connector_id=response.connector_id,
                    operation=response.operation,
                    result=copy.deepcopy(response.result),
                ),
            }
    else:
        code = result.get("code") if isinstance(result, dict) else None
        if code not in _NON_RETAINED_GATE_CODES:
            with _LOCK:
                _COMMANDS[command_key] = {
                    "fingerprint": fingerprint,
                    "response": ConnectorResponse(
                        request_id=response.request_id,
                        connector_id=response.connector_id,
                        operation=response.operation,
                        result=copy.deepcopy(response.result),
                    ),
                }
    return response

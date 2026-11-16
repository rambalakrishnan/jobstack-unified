"""connector_controls: authorized, evidence-preserving connector controls (tier 6).

Implements ``job-hunter-seam-mapping.md#13.3`` (controls and closure) and the
control half of ``LIFE-CLOSE`` / ``LIFE-CONTROLS`` / ``EXT-CONTROLS`` /
``EXT-AUTHORITY`` / ``EK-CLAIMS`` for Job Hunter.

The module accepts exactly four control verbs -- ``RequestNativeCancel``,
``CloseObservationConnection``, ``ReleaseNativeContext`` and ``Contain`` -- and
performs, in order:

1. Verb + connector authorization from the authenticated channel registration
   (never from ids, digests, or caller-supplied strings).
2. Closed-shape payload validation of the seam 13.3 control payloads. Bare
   nulls are rejected; every absent value must be a typed ``Missing`` envelope.
3. Control-target authorization derived from the verb, connector and the
   validated target (handle / containment target).
4. Prerequisite checks for reviewed containment policies (policy bytes resolve;
   fixture-mutation-authority containment requires a commissioned laboratory
   fixture, never an employer origin).
5. The authenticated connector call through ``connector_transport``.
6. Receipt coercion that refuses to upgrade an unbacked claim: an
   ``acknowledged`` disposition requires verified response evidence and an
   ``effect_observed`` disposition requires effect evidence.  Anything weaker
   is recorded as ``unknown`` with an explicit limitation.
7. An owner-local, best-effort control-observation journal append plus
   authorization-citation verification.  Failure of the append never invents a
   registration; the receipt discloses the unpersisted observation.

Knowledge boundaries (deliberate):

* A control *request* is not an acknowledgement; an *acknowledgement* is not an
  observed effect; a *stop claim* remains a subject claim.  The receipt type
  therefore has no path to a no-commit fact: ``no_commit_fact`` is always a
  ``Missing(not_observed)`` envelope and ``commit_absence_state`` is always
  ``"unknown"``.  Cancel acknowledgement never establishes that nothing was
  committed.
* Process containment never certifies native cancellation.  Only a
  ``RequestNativeCancel`` observation carrying effect evidence can certify a
  native cancellation, and containment of a local process says nothing about
  the remote native execution or its application commitment.
* ``CloseObservationConnection`` closes the selected native transport; with
  ``end_observation: true`` it additionally stops new workflow commands and
  starts bounded finalization.  Neither setting requests cancellation or closes
  durable Observe.  ``durable_observation_closed`` is always ``Missing``
  (connector-owned closure state is never published from Job Hunter) and no
  closure state is cached across calls.
* No opaque PIDs, shell text, or unbounded shared-resource cleanup are accepted
  as containment targets.
"""

from __future__ import annotations

import copy
import hashlib
import importlib
import importlib.util
import json
import math
import re
import secrets
import sys
import threading
from dataclasses import dataclass, replace
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping, NoReturn, Sequence


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


access_policy = _load_sibling("access_policy")
artifact_store = _load_sibling("artifact_store")
evidence_journal = _load_sibling("evidence_journal")
connector_transport = _load_sibling("connector_transport")
attempt_commissioning = _load_sibling("attempt_commissioning")

__all__ = [
    "CLOSE_REASONS",
    "CONTAINMENT_TARGET_KINDS",
    "CONTROL_DISPOSITIONS",
    "CONTROL_GRANTS",
    "CONTROL_OPERATIONS",
    "COMMIT_ABSENCE_UNKNOWN",
    "MAX_CONTROL_CALL_LIMIT_MS",
    "ControlAuthorization",
    "ControlObservation",
    "ControlReceipt",
    "JournalAudit",
    "RetainedClaim",
    "control_task",
]

# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------

REQUEST_NATIVE_CANCEL = "RequestNativeCancel"
CLOSE_OBSERVATION_CONNECTION = "CloseObservationConnection"
RELEASE_NATIVE_CONTEXT = "ReleaseNativeContext"
CONTAIN = "Contain"

CONTROL_OPERATIONS = frozenset(
    {
        REQUEST_NATIVE_CANCEL,
        CLOSE_OBSERVATION_CONNECTION,
        RELEASE_NATIVE_CONTEXT,
        CONTAIN,
    }
)

#: Dispositions of one control observation (seam 13.3).  ``acknowledged`` and
#: ``effect_observed`` are only representable with their required evidence.
CONTROL_DISPOSITIONS = frozenset(
    {
        "not_requested",
        "unsupported",
        "requested",
        "acknowledged",
        "effect_observed",
        "unknown",
    }
)

NATIVE_EXECUTION_SCOPE = "native_execution"
OBSERVATION_CONNECTION_SCOPE = "observation_connection"
NATIVE_CONTEXT_SCOPE = "native_context"

#: Bounded containment targets.  Arbitrary shell text, guessed PIDs, and
#: unbounded shared-resource cleanup are never acceptable targets.
CONTAINMENT_TARGET_KINDS = frozenset(
    {
        "fixture_mutation_authority",
        "local_process",
        "deployment_slot",
        "harness_resources",
    }
)

TARGET_SCOPES_BY_OPERATION: Mapping[str, frozenset[str]] = MappingProxyType(
    {
        REQUEST_NATIVE_CANCEL: frozenset({NATIVE_EXECUTION_SCOPE}),
        CLOSE_OBSERVATION_CONNECTION: frozenset({OBSERVATION_CONNECTION_SCOPE}),
        RELEASE_NATIVE_CONTEXT: frozenset({NATIVE_CONTEXT_SCOPE}),
        CONTAIN: CONTAINMENT_TARGET_KINDS,
    }
)

CLOSE_REASONS = frozenset(
    {"operator_stop", "local_deadline", "normal_completion"}
)

#: Grant presets that may carry each control verb.  Close accepts the
#: observation grant because it closes the observation transport; every verb
#: still requires the connector producer role below.
CONTROL_GRANTS: Mapping[str, tuple[str, ...]] = MappingProxyType(
    {
        REQUEST_NATIVE_CANCEL: ("attempt.dispatch.write",),
        CLOSE_OBSERVATION_CONNECTION: (
            "attempt.dispatch.write",
            "attempt.observation.write",
        ),
        RELEASE_NATIVE_CONTEXT: ("attempt.dispatch.write",),
        CONTAIN: ("attempt.dispatch.write",),
    }
)

CONNECTOR_ROLE = "connector"

CONTROL_EVENT_KIND = "connector.control_observed"
CONTROL_EVENT_VERSION = "1"

#: Local bound for one control call.  Zero means immediate; the transport's own
#: 30s ceiling is never the control bound.
MAX_CONTROL_CALL_LIMIT_MS = 10_000.0

#: A control observation never establishes an application commitment or its
#: absence; the absence state is always explicitly unknown.
COMMIT_ABSENCE_UNKNOWN = "unknown"

NOT_OBSERVED = "not_observed"
NOT_APPLICABLE = "not_applicable"

_MISSING_REASONS = frozenset(
    {
        "not_enabled",
        "not_applicable",
        "not_observed",
        "observation_lost",
        "unsupported_by_subject",
        "manual_override",
    }
)

_PAYLOAD_FIELDS: Mapping[str, frozenset[str]] = {
    REQUEST_NATIVE_CANCEL: frozenset({"handle", "reason", "authorization_refs"}),
    CLOSE_OBSERVATION_CONNECTION: frozenset(
        {"handle", "reason", "end_observation", "authorization_refs"}
    ),
    RELEASE_NATIVE_CONTEXT: frozenset(
        {"handle", "context_ref", "authorization_refs"}
    ),
    CONTAIN: frozenset(
        {"handle", "target", "policy", "reason", "authorization_refs"}
    ),
}

_POLICY_FIELDS = frozenset({"policy_id", "version", "review_refs"})
_POLICY_OPTIONAL_FIELDS = frozenset({"artifact", "commission"})

_MEASUREMENT_ORIGINS = frozenset(
    {"engine_measured", "browser_measured", "subject_reported", "manual_reference"}
)

_SOURCE_CHECK_FIELDS = frozenset(
    {
        "authentication",
        "correlation",
        "trace_correlation",
        "verification_policy",
        "matched_by",
        "evidence_refs",
    }
)
_AUTHENTICATION_VALUES = frozenset({"verified", "failed", "unknown"})
_CORRELATION_VALUES = frozenset({"matched", "mismatched", "unknown"})
_TRACE_CORRELATION_VALUES = frozenset(
    {"matched", "mismatched", "not_observed", "not_applicable"}
)

_OPPORTUNITY_STATES = frozenset({"exposed", "unexposed", "blocked"})

#: Containment resource ids: opaque bounded identifiers.  Whitespace, shell
#: metacharacters, quotes, path separators, and control characters are rejected
#: by the character class alone.
_CONTAINMENT_RESOURCE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$")
_UNVERIFIED_PID_RE = re.compile(r"^[A-Za-z]*[:_.-]?[0-9]+$")

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_POINTER_RE = re.compile(r"^(?:/(?:[^~/]|~[01])*)*$")
_DATETIME_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)

_IDENTIFIER_MAX = 256

_SEQUENCE_LOCK = threading.Lock()
_SEQUENCE: dict[str, int] = {}


# ---------------------------------------------------------------------------
# Small typed-value helpers
# ---------------------------------------------------------------------------


def _missing(reason: str = NOT_OBSERVED) -> dict[str, Any]:
    if reason not in _MISSING_REASONS:
        raise ValueError(f"unknown missing reason: {reason!r}")
    return {"value": None, "reason": reason}


def _is_missing(value: object) -> bool:
    if not isinstance(value, Mapping):
        return False
    keys = set(value.keys())
    if keys not in ({"value", "reason"}, {"value", "reason", "detail"}):
        return False
    if value.get("value") is not None or value.get("reason") not in _MISSING_REASONS:
        return False
    if "detail" in keys:
        detail = value["detail"]
        return isinstance(detail, str) and bool(detail)
    return True


def _copy_missing(value: Mapping[str, Any]) -> dict[str, Any]:
    copied = _missing(str(value["reason"]))
    if "detail" in value:
        copied["detail"] = str(value["detail"])
    return copied


def _require_identifier(value: object, field: str, max_len: int = _IDENTIFIER_MAX) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field} must be a string identifier")
    if not value or value != value.strip():
        raise ValueError(f"{field} must be a nonempty identifier without padding")
    if len(value) > max_len:
        raise ValueError(f"{field} must be at most {max_len} characters")
    if any(ord(ch) < 0x20 for ch in value):
        raise ValueError(f"{field} must not contain control characters")
    return value


def _canonical_json_copy(value: object, field: str) -> Any:
    """Copy a JSON-shaped value, rejecting bare nulls and non-JSON leaves."""
    if value is None:
        raise ValueError(f"{field} must use a typed Missing envelope, not a bare null")
    if isinstance(value, Mapping):
        if _is_missing(value):
            return _copy_missing(value)
        copied: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{field} keys must be strings")
            copied[key] = _canonical_json_copy(item, f"{field}.{key}")
        return copied
    if isinstance(value, (list, tuple)):
        return [
            _canonical_json_copy(item, f"{field}[{index}]")
            for index, item in enumerate(value)
        ]
    if isinstance(value, bool) or isinstance(value, str):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{field} must be a finite number")
        return value
    raise ValueError(f"{field} carries a non-JSON value of type {type(value).__name__}")


def _string_list(value: object, field: str) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise TypeError(f"{field} must be a sequence of nonempty strings")
    copied: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            raise ValueError(f"{field}[{index}] must be a nonempty string")
        copied.append(item)
    return tuple(copied)


def _evidence_ref(value: object, field: str, *, allow_alias: bool = False) -> dict[str, Any]:
    """Return one canonical EvidenceRef (``journal_id``/``sequence``/...)."""
    if not isinstance(value, Mapping):
        raise TypeError(f"{field} must be an EvidenceRef mapping")
    keys = set(value.keys())
    canonical = {"journal_id", "sequence", "event_id", "event_hash", "pointer"}
    alias = {"journal_id", "journal_sequence", "event_id", "event_hash", "pointer"}
    if keys == canonical:
        sequence = value["sequence"]
    elif allow_alias and keys == alias:
        sequence = value["journal_sequence"]
    else:
        raise ValueError(
            f"{field} must contain exactly {sorted(canonical)}"
            + (" (or the carrier's journal_sequence alias)" if allow_alias else "")
        )
    journal_id = _require_identifier(value["journal_id"], f"{field}.journal_id")
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
        raise ValueError(f"{field}.sequence must be a positive integer")
    event_id = _require_identifier(value["event_id"], f"{field}.event_id")
    event_hash = value["event_hash"]
    if not isinstance(event_hash, str) or not _DIGEST_RE.match(event_hash):
        raise ValueError(f"{field}.event_hash must be a canonical sha256 digest")
    pointer = value["pointer"]
    if not isinstance(pointer, str) or not _POINTER_RE.match(pointer):
        raise ValueError(f"{field}.pointer must be an RFC 6901 JSON Pointer string")
    return {
        "journal_id": journal_id,
        "sequence": sequence,
        "event_id": event_id,
        "event_hash": event_hash,
        "pointer": pointer,
    }


def _maybe_evidence_ref(value: object, field: str) -> dict[str, Any]:
    if _is_missing(value):
        return _copy_missing(value)
    return _evidence_ref(value, field, allow_alias=True)


def _evidence_refs(
    value: object, field: str, *, allow_empty: bool, allow_alias: bool = False
) -> tuple[dict[str, Any], ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise TypeError(f"{field} must be a sequence of EvidenceRef mappings")
    refs = tuple(
        _evidence_ref(item, f"{field}[{index}]", allow_alias=allow_alias)
        for index, item in enumerate(value)
    )
    if not refs and not allow_empty:
        raise ValueError(f"{field} must cite at least one EvidenceRef")
    return refs


def _timepoint(value: object, field: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{field} must be a TimePoint mapping")
    if set(value.keys()) != {
        "clock_id",
        "boot_id",
        "origin",
        "monotonic_offset_ms",
        "utc_annotation",
    }:
        raise ValueError(
            f"{field} must contain exactly clock_id, boot_id, origin, "
            "monotonic_offset_ms, utc_annotation"
        )
    clock_id = _require_identifier(value["clock_id"], f"{field}.clock_id")
    boot_id = _require_identifier(value["boot_id"], f"{field}.boot_id")
    origin = value["origin"]
    if origin not in _MEASUREMENT_ORIGINS:
        raise ValueError(f"{field}.origin must be one of {sorted(_MEASUREMENT_ORIGINS)}")
    offset = value["monotonic_offset_ms"]
    if isinstance(offset, bool) or not isinstance(offset, (int, float)):
        raise ValueError(f"{field}.monotonic_offset_ms must be a finite number")
    if not math.isfinite(float(offset)) or float(offset) < 0:
        raise ValueError(
            f"{field}.monotonic_offset_ms must be a nonnegative finite number"
        )
    annotation = value["utc_annotation"]
    if _is_missing(annotation):
        utc_annotation: object = _copy_missing(annotation)
    elif isinstance(annotation, str) and _DATETIME_RE.match(annotation):
        utc_annotation = annotation
    else:
        raise ValueError(
            f"{field}.utc_annotation must be a date-time string or a typed Missing"
        )
    return {
        "clock_id": clock_id,
        "boot_id": boot_id,
        "origin": str(origin),
        "monotonic_offset_ms": float(offset),
        "utc_annotation": utc_annotation,
    }


def _source_checks(value: object, field: str) -> tuple[dict[str, Any], bool]:
    """Validate contract SourceChecks; return the copy and its verified state."""
    if not isinstance(value, Mapping):
        raise TypeError(f"{field} must be a SourceChecks mapping")
    if set(value.keys()) != _SOURCE_CHECK_FIELDS:
        raise ValueError(f"{field} must contain exactly {sorted(_SOURCE_CHECK_FIELDS)}")
    authentication = value["authentication"]
    correlation = value["correlation"]
    trace = value["trace_correlation"]
    if authentication not in _AUTHENTICATION_VALUES:
        raise ValueError(f"{field}.authentication must be one of {sorted(_AUTHENTICATION_VALUES)}")
    if correlation not in _CORRELATION_VALUES:
        raise ValueError(f"{field}.correlation must be one of {sorted(_CORRELATION_VALUES)}")
    if trace not in _TRACE_CORRELATION_VALUES:
        raise ValueError(
            f"{field}.trace_correlation must be one of {sorted(_TRACE_CORRELATION_VALUES)}"
        )
    policy = value["verification_policy"]
    if not isinstance(policy, Mapping):
        raise TypeError(f"{field}.verification_policy must be a VersionPin mapping")
    if set(policy.keys()) != {"id", "version"}:
        raise ValueError(f"{field}.verification_policy must contain id and version")
    pin = {
        "id": _require_identifier(policy["id"], f"{field}.verification_policy.id"),
        "version": _require_identifier(
            policy["version"], f"{field}.verification_policy.version"
        ),
    }
    matched_by = _string_list(value["matched_by"], f"{field}.matched_by")
    evidence = _evidence_refs(
        value["evidence_refs"], f"{field}.evidence_refs", allow_empty=False
    )
    checks = {
        "authentication": str(authentication),
        "correlation": str(correlation),
        "trace_correlation": str(trace),
        "verification_policy": pin,
        "matched_by": list(matched_by),
        "evidence_refs": [dict(ref) for ref in evidence],
    }
    verified = (
        authentication == "verified"
        and correlation == "matched"
        and bool(matched_by)
    )
    return checks, verified


def _maybe_source_checks(value: object, field: str) -> dict[str, Any]:
    if _is_missing(value):
        return _copy_missing(value)
    checks, _verified = _source_checks(value, field)
    return checks


def _checks_verified(value: object) -> bool:
    try:
        _checks, verified = _source_checks(value, "response_checks")
    except (TypeError, ValueError):
        return False
    return verified


def _capability_ref(value: object, field: str) -> dict[str, Any]:
    if _is_missing(value):
        return _copy_missing(value)
    if not isinstance(value, Mapping):
        raise TypeError(f"{field} must be a CapabilityReference or typed Missing")
    if set(value.keys()) != {"descriptor_digest", "capability_id", "evidence_ref"}:
        raise ValueError(
            f"{field} must contain exactly descriptor_digest, capability_id, evidence_ref"
        )
    descriptor_digest = value["descriptor_digest"]
    if not isinstance(descriptor_digest, str) or not _DIGEST_RE.match(descriptor_digest):
        raise ValueError(f"{field}.descriptor_digest must be a canonical sha256 digest")
    return {
        "descriptor_digest": descriptor_digest,
        "capability_id": _require_identifier(
            value["capability_id"], f"{field}.capability_id"
        ),
        "evidence_ref": _evidence_ref(value["evidence_ref"], f"{field}.evidence_ref"),
    }


def _opportunity(value: object, field: str) -> tuple[dict[str, Any], str | None]:
    """Preserve the opportunity claim, disclosing a non-contract local shape."""
    if not isinstance(value, Mapping) or not value:
        raise TypeError(f"{field} must be a nonempty opportunity mapping")
    if set(value.keys()) == {"state", "evidence_refs", "rationale"}:
        state = value["state"]
        if state not in _OPPORTUNITY_STATES:
            raise ValueError(f"{field}.state must be one of {sorted(_OPPORTUNITY_STATES)}")
        evidence = _evidence_refs(
            value["evidence_refs"], f"{field}.evidence_refs", allow_empty=False
        )
        rationale = value["rationale"]
        if not isinstance(rationale, str) or not rationale:
            raise ValueError(f"{field}.rationale must be a nonempty string")
        return (
            {
                "state": str(state),
                "evidence_refs": [dict(ref) for ref in evidence],
                "rationale": rationale,
            },
            None,
        )
    copied = _canonical_json_copy(value, field)
    return (
        copied,
        "opportunity is preserved in the carrier's local shape rather than the "
        "contract Opportunity; exposure is not re-derived here",
    )


def _measurements(value: object, field: str) -> tuple[dict[str, Any], ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise TypeError(f"{field} must be a sequence of MeasurementEvidence mappings")
    copied: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        if not isinstance(item, Mapping) or set(item.keys()) != {
            "measurement",
            "evidence_refs",
        }:
            raise ValueError(
                f"{field}[{index}] must contain exactly measurement and evidence_refs"
            )
        measurement = item["measurement"]
        if not isinstance(measurement, Mapping) or not measurement:
            raise ValueError(f"{field}[{index}].measurement must be a nonempty mapping")
        evidence = _evidence_refs(
            item["evidence_refs"],
            f"{field}[{index}].evidence_refs",
            allow_empty=False,
        )
        copied.append(
            {
                "measurement": _canonical_json_copy(
                    measurement, f"{field}[{index}].measurement"
                ),
                "evidence_refs": [dict(ref) for ref in evidence],
            }
        )
    return tuple(copied)


def _attempts(value: object, field: str) -> tuple[dict[str, Any], ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise TypeError(f"{field} must be a sequence of AttemptReference mappings")
    copied: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        if not isinstance(item, Mapping) or not item:
            raise ValueError(f"{field}[{index}] must be a nonempty attempt reference")
        if "attempt_id" in item:
            _require_identifier(item["attempt_id"], f"{field}[{index}].attempt_id")
        copied.append(_canonical_json_copy(item, f"{field}[{index}]"))
    return tuple(copied)


def _new_control_event_id() -> str:
    return "cev_" + secrets.token_hex(8)


def _new_claim_id() -> str:
    return "clm_" + secrets.token_hex(8)


def _next_sequence(owner_domain: str) -> int:
    with _SEQUENCE_LOCK:
        current = _SEQUENCE.get(owner_domain, 1)
        _SEQUENCE[owner_domain] = current + 1
        return current


# ---------------------------------------------------------------------------
# Control observation (seam 13.3 ControlObservation)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ControlObservation:
    """One immutable observation of one control operation.

    ``disposition == "acknowledged"`` is only representable with verified
    response evidence, and ``disposition == "effect_observed"`` only with
    nonempty effect refs; the constructor refuses to hold an unbacked claim.
    Append a new ``control_event_id`` for every later observation of the same
    operation; ``operation_id`` groups the request, acknowledgement, effect and
    timeout.
    """

    control_event_id: str
    operation_id: str
    operation: str
    target_scope: str
    disposition: str
    at: dict[str, Any]
    authorization_ref: dict[str, Any]
    capability_ref: dict[str, Any]
    opportunity: dict[str, Any]
    request_ref: dict[str, Any]
    response_ref: dict[str, Any]
    response_checks: dict[str, Any]
    native_claim_refs: tuple[dict[str, Any], ...] = ()
    effect_refs: tuple[dict[str, Any], ...] = ()
    affected_attempts: tuple[dict[str, Any], ...] = ()
    measurements: tuple[dict[str, Any], ...] = ()
    limitations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "control_event_id", _require_identifier(self.control_event_id, "control_event_id")
        )
        object.__setattr__(
            self, "operation_id", _require_identifier(self.operation_id, "operation_id")
        )
        if self.operation not in CONTROL_OPERATIONS:
            raise ValueError(
                f"control observation operation must be one of {sorted(CONTROL_OPERATIONS)}"
            )
        allowed_scopes = TARGET_SCOPES_BY_OPERATION[self.operation]
        if self.target_scope not in allowed_scopes:
            raise ValueError(
                f"operation {self.operation} requires target_scope in {sorted(allowed_scopes)}"
            )
        if self.disposition not in CONTROL_DISPOSITIONS:
            raise ValueError(
                f"control disposition must be one of {sorted(CONTROL_DISPOSITIONS)}"
            )
        object.__setattr__(self, "at", _timepoint(self.at, "at"))
        object.__setattr__(
            self,
            "authorization_ref",
            _evidence_ref(self.authorization_ref, "authorization_ref", allow_alias=True),
        )
        object.__setattr__(
            self, "capability_ref", _capability_ref(self.capability_ref, "capability_ref")
        )
        opportunity, opportunity_limitation = _opportunity(self.opportunity, "opportunity")
        object.__setattr__(self, "opportunity", opportunity)
        object.__setattr__(self, "request_ref", _maybe_evidence_ref(self.request_ref, "request_ref"))
        object.__setattr__(
            self, "response_ref", _maybe_evidence_ref(self.response_ref, "response_ref")
        )
        object.__setattr__(
            self,
            "response_checks",
            _maybe_source_checks(self.response_checks, "response_checks"),
        )
        object.__setattr__(
            self,
            "native_claim_refs",
            _evidence_refs(
                self.native_claim_refs, "native_claim_refs", allow_empty=True
            ),
        )
        object.__setattr__(
            self, "effect_refs", _evidence_refs(self.effect_refs, "effect_refs", allow_empty=True)
        )
        object.__setattr__(
            self, "affected_attempts", _attempts(self.affected_attempts, "affected_attempts")
        )
        object.__setattr__(
            self, "measurements", _measurements(self.measurements, "measurements")
        )
        limitations = list(_string_list(self.limitations, "limitations"))
        if opportunity_limitation is not None and opportunity_limitation not in limitations:
            limitations.append(opportunity_limitation)
        if self.disposition == "acknowledged":
            if _is_missing(self.response_ref) or not _checks_verified(self.response_checks):
                raise ValueError(
                    "acknowledgement requires a response EvidenceRef and verified "
                    "source checks; a request or an unverified response is not an "
                    "acknowledgement"
                )
        if self.disposition == "effect_observed" and not self.effect_refs:
            raise ValueError("effect_observed requires at least one effect evidence ref")
        object.__setattr__(self, "limitations", tuple(limitations))

    # -- disposition facts -------------------------------------------------

    @property
    def acknowledged(self) -> bool:
        return self.disposition == "acknowledged"

    @property
    def effect_observed(self) -> bool:
        return self.disposition == "effect_observed"

    @property
    def unsupported(self) -> bool:
        return self.disposition == "unsupported"

    # -- knowledge boundaries ---------------------------------------------

    @property
    def no_commit_fact(self) -> dict[str, Any]:
        """A control observation never establishes application commitment absence."""
        return _missing(NOT_OBSERVED)

    @property
    def has_no_commit_fact(self) -> bool:
        return False

    @property
    def commit_absence_state(self) -> str:
        return COMMIT_ABSENCE_UNKNOWN

    @property
    def certifies_native_cancellation(self) -> bool:
        """Only an evidenced native-cancel effect certifies cancellation.

        Process containment, a request, and an acknowledgement never do.
        """
        return self.operation == REQUEST_NATIVE_CANCEL and self.effect_observed

    @property
    def implies_cancellation(self) -> bool:
        return self.certifies_native_cancellation

    @property
    def durable_observation_closed(self) -> dict[str, Any]:
        """Job Hunter never publishes connector-owned closure state."""
        return _missing(NOT_OBSERVED)

    def to_dict(self) -> dict[str, Any]:
        return {
            "control_event_id": self.control_event_id,
            "operation_id": self.operation_id,
            "operation": self.operation,
            "target_scope": self.target_scope,
            "disposition": self.disposition,
            "at": copy.deepcopy(self.at),
            "authorization_ref": copy.deepcopy(self.authorization_ref),
            "capability_ref": copy.deepcopy(self.capability_ref),
            "opportunity": copy.deepcopy(self.opportunity),
            "request_ref": copy.deepcopy(self.request_ref),
            "response_ref": copy.deepcopy(self.response_ref),
            "response_checks": copy.deepcopy(self.response_checks),
            "native_claim_refs": [copy.deepcopy(ref) for ref in self.native_claim_refs],
            "effect_refs": [copy.deepcopy(ref) for ref in self.effect_refs],
            "affected_attempts": [
                copy.deepcopy(attempt) for attempt in self.affected_attempts
            ],
            "measurements": [
                copy.deepcopy(measurement) for measurement in self.measurements
            ],
            "limitations": list(self.limitations),
        }


# ---------------------------------------------------------------------------
# Supporting immutable records
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ControlAuthorization:
    """Server-assigned identity + the scoped grant that authorized one control.

    Derived only from the authenticated channel registration; ids and digests
    are recorded for audit and are never bearer authority.
    """

    grant: str
    resource: str
    producer_id: str
    principal_id: str
    owner_domain: str
    role: str
    provenance: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "grant", _require_identifier(self.grant, "grant"))
        object.__setattr__(
            self, "resource", _require_identifier(self.resource, "resource")
        )
        object.__setattr__(
            self, "producer_id", _require_identifier(self.producer_id, "producer_id")
        )
        object.__setattr__(
            self, "principal_id", _require_identifier(self.principal_id, "principal_id")
        )
        object.__setattr__(
            self, "owner_domain", _require_identifier(self.owner_domain, "owner_domain")
        )
        object.__setattr__(self, "role", _require_identifier(self.role, "role"))
        object.__setattr__(
            self, "provenance", _require_identifier(self.provenance, "provenance")
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "grant": self.grant,
            "resource": self.resource,
            "producer_id": self.producer_id,
            "principal_id": self.principal_id,
            "owner_domain": self.owner_domain,
            "role": self.role,
            "provenance": self.provenance,
        }


@dataclass(frozen=True, slots=True)
class RetainedClaim:
    """A retained claim (never a fact) about a control outcome."""

    claim_id: str
    kind: str
    source: str
    state: str
    refs: tuple[dict[str, Any], ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "claim_id", _require_identifier(self.claim_id, "claim_id"))
        if self.kind != "stop":
            raise ValueError("only stop claims are retained by connector controls")
        if self.source not in {"subject", "connector", "observer"}:
            raise ValueError("claim source must be subject, connector, or observer")
        if self.state != "claimed":
            raise ValueError(
                "a stop report remains a claim; it is never upgraded to a fact state"
            )
        object.__setattr__(
            self, "refs", _evidence_refs(self.refs, "refs", allow_empty=False)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "kind": self.kind,
            "source": self.source,
            "state": self.state,
            "refs": [copy.deepcopy(ref) for ref in self.refs],
        }


@dataclass(frozen=True, slots=True)
class JournalAudit:
    """Best-effort owner-local journaling outcome of one control observation."""

    status: str
    ref: dict[str, Any]
    limitations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.status not in {"appended", "unavailable"}:
            raise ValueError("journal audit status must be appended or unavailable")
        if self.status == "appended":
            object.__setattr__(
                self, "ref", _evidence_ref(self.ref, "audit.ref", allow_alias=True)
            )
        else:
            if not _is_missing(self.ref):
                raise ValueError("an unavailable journal audit requires a typed Missing ref")
            object.__setattr__(self, "ref", _copy_missing(self.ref))
        object.__setattr__(
            self, "limitations", _string_list(self.limitations, "limitations")
        )

    @property
    def appended(self) -> bool:
        return self.status == "appended"

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "ref": copy.deepcopy(self.ref),
            "limitations": list(self.limitations),
        }


# ---------------------------------------------------------------------------
# Control receipt
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ControlReceipt:
    """One immutable control receipt plus its append-only observation history."""

    request_id: str
    connector_id: str
    handle: dict[str, Any]
    authorization: ControlAuthorization
    observation: ControlObservation
    observations: tuple[ControlObservation, ...]
    registration_ref: dict[str, Any]
    registration_verified: bool
    audit: JournalAudit
    limitations: tuple[str, ...]
    close_mode: str
    stop_claims: tuple[RetainedClaim, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "request_id", _require_identifier(self.request_id, "request_id")
        )
        object.__setattr__(
            self, "connector_id", _require_identifier(self.connector_id, "connector_id")
        )
        handle = self.handle
        if not isinstance(handle, Mapping) or set(handle.keys()) != {
            "connector_id",
            "local_handle",
        }:
            raise ValueError("handle must contain exactly connector_id and local_handle")
        if handle["connector_id"] != self.connector_id:
            raise ValueError("handle.connector_id must match the receipt connector")
        object.__setattr__(
            self,
            "handle",
            {
                "connector_id": _require_identifier(
                    handle["connector_id"], "handle.connector_id"
                ),
                "local_handle": _require_identifier(
                    handle["local_handle"], "handle.local_handle"
                ),
            },
        )
        if not isinstance(self.authorization, ControlAuthorization):
            raise TypeError("authorization must be a ControlAuthorization")
        if not isinstance(self.observation, ControlObservation):
            raise TypeError("observation must be a ControlObservation")
        if isinstance(self.observations, (str, bytes)) or not isinstance(
            self.observations, Sequence
        ):
            raise TypeError("observations must be a sequence of ControlObservation")
        observations = tuple(self.observations)
        if not observations:
            raise ValueError("a receipt requires at least its first observation")
        for item in observations:
            if not isinstance(item, ControlObservation):
                raise TypeError("observations must be a sequence of ControlObservation")
            if item.operation_id != self.observation.operation_id:
                raise ValueError("every observation must share one operation_id")
            if item.operation != self.observation.operation:
                raise ValueError("every observation must share the receipt operation")
        if observations[-1].control_event_id != self.observation.control_event_id:
            raise ValueError(
                "the latest observation must be the receipt's current observation"
            )
        if len({item.control_event_id for item in observations}) != len(observations):
            raise ValueError("control_event_id history is append-only and unique")
        object.__setattr__(self, "observations", observations)
        object.__setattr__(
            self,
            "registration_ref",
            _maybe_evidence_ref(self.registration_ref, "registration_ref"),
        )
        if type(self.registration_verified) is not bool:
            raise TypeError("registration_verified must be a bool")
        if not isinstance(self.audit, JournalAudit):
            raise TypeError("audit must be a JournalAudit")
        if self.registration_verified and not self.audit.appended:
            raise ValueError(
                "registration can only be verified by an appended journal observation"
            )
        object.__setattr__(
            self, "limitations", _string_list(self.limitations, "limitations")
        )
        if self.close_mode not in {
            NOT_APPLICABLE,
            "transport_only",
            "end_observation",
        }:
            raise ValueError(
                "close_mode must be not_applicable, transport_only, or end_observation"
            )
        if self.observation.operation == CLOSE_OBSERVATION_CONNECTION:
            if self.close_mode == NOT_APPLICABLE:
                raise ValueError("a close receipt requires an explicit close mode")
        elif self.close_mode != NOT_APPLICABLE:
            raise ValueError("only a close receipt carries a close mode")
        if isinstance(self.stop_claims, (str, bytes)) or not isinstance(
            self.stop_claims, Sequence
        ):
            raise TypeError("stop_claims must be a sequence of RetainedClaim")
        claims = tuple(self.stop_claims)
        for claim in claims:
            if not isinstance(claim, RetainedClaim):
                raise TypeError("stop_claims must be a sequence of RetainedClaim")
        object.__setattr__(self, "stop_claims", claims)

    # -- carrier facts -----------------------------------------------------

    @property
    def operation(self) -> str:
        return self.observation.operation

    @property
    def operation_id(self) -> str:
        return self.observation.operation_id

    @property
    def control_event_id(self) -> str:
        return self.observation.control_event_id

    @property
    def target_scope(self) -> str:
        return self.observation.target_scope

    @property
    def disposition(self) -> str:
        return self.observation.disposition

    @property
    def acknowledged(self) -> bool:
        return self.observation.acknowledged

    @property
    def effect_observed(self) -> bool:
        return self.observation.effect_observed

    # -- closure separateness ---------------------------------------------

    @property
    def closes_transport(self) -> bool:
        return self.observation.operation == CLOSE_OBSERVATION_CONNECTION

    @property
    def ends_observation(self) -> bool:
        return (
            self.observation.operation == CLOSE_OBSERVATION_CONNECTION
            and self.close_mode == "end_observation"
        )

    @property
    def stops_new_commands(self) -> bool:
        return self.ends_observation

    @property
    def begins_finalization(self) -> bool:
        """``end_observation: true`` starts the commissioned bounded drain."""
        return self.ends_observation

    @property
    def durable_observation_closed(self) -> dict[str, Any]:
        return self.observation.durable_observation_closed

    # -- cancellation boundaries ------------------------------------------

    @property
    def certifies_native_cancellation(self) -> bool:
        return self.observation.certifies_native_cancellation

    @property
    def implies_cancellation(self) -> bool:
        return self.observation.implies_cancellation

    @property
    def no_commit_fact(self) -> dict[str, Any]:
        return self.observation.no_commit_fact

    @property
    def has_no_commit_fact(self) -> bool:
        return self.observation.has_no_commit_fact

    @property
    def commit_absence_state(self) -> str:
        return self.observation.commit_absence_state

    @property
    def all_limitations(self) -> tuple[str, ...]:
        return tuple(self.observation.limitations) + tuple(self.limitations) + tuple(
            self.audit.limitations
        )

    # -- append-only history ----------------------------------------------

    def append_observation(self, observation: ControlObservation) -> "ControlReceipt":
        """Append a later observation of the same operation (never a rewrite)."""
        if not isinstance(observation, ControlObservation):
            raise TypeError("observation must be a ControlObservation")
        if observation.operation_id != self.operation_id:
            raise ValueError("appended observations must share the receipt operation_id")
        if observation.operation != self.operation:
            raise ValueError("appended observations must share the receipt operation")
        if any(
            item.control_event_id == observation.control_event_id
            for item in self.observations
        ):
            raise ValueError("control_event_id history is append-only and unique")
        return replace(
            self,
            observation=observation,
            observations=self.observations + (observation,),
        )

    def with_acknowledgement(
        self,
        *,
        at: Mapping[str, Any],
        response_ref: Mapping[str, Any],
        source_checks: object,
    ) -> "ControlReceipt":
        """Record an acknowledgement only when the response evidence verifies."""
        if self.observation.effect_observed:
            raise ValueError(
                "an acknowledgement cannot follow observed effect evidence; "
                "control history is append-only and never regresses"
            )
        moment = _timepoint(at, "at")
        ref = _evidence_ref(response_ref, "response_ref")
        checks = _maybe_source_checks(source_checks, "response_checks")
        verified = _checks_verified(checks)
        limitations = list(self.observation.limitations)
        if verified:
            limitations.append(
                "acknowledgement is a verified response, not an observed effect"
            )
            disposition = "acknowledged"
        else:
            limitations.append(
                "response evidence did not verify; acknowledgement withheld and "
                "the disposition recorded as unknown"
            )
            disposition = "unknown"
        observation = replace(
            self.observation,
            control_event_id=_new_control_event_id(),
            disposition=disposition,
            at=moment,
            response_ref=ref,
            response_checks=checks,
            native_claim_refs=(),
            effect_refs=(),
            limitations=tuple(limitations),
        )
        return self.append_observation(observation)

    def with_effect_evidence(
        self,
        *,
        at: Mapping[str, Any],
        effect_refs: Sequence[Mapping[str, Any]],
        native_claim_refs: Sequence[Mapping[str, Any]] = (),
    ) -> "ControlReceipt":
        """Record observed effects; effects never establish commit absence."""
        moment = _timepoint(at, "at")
        effects = _evidence_refs(effect_refs, "effect_refs", allow_empty=False)
        claims = _evidence_refs(native_claim_refs, "native_claim_refs", allow_empty=True)
        observation = replace(
            self.observation,
            control_event_id=_new_control_event_id(),
            disposition="effect_observed",
            at=moment,
            native_claim_refs=claims,
            effect_refs=effects,
            limitations=tuple(
                list(self.observation.limitations)
                + [
                    "observed control effects are not an application commitment "
                    "and not proof that nothing was committed"
                ]
            ),
        )
        return self.append_observation(observation)

    def with_subject_stop_claim(
        self, claim_ref: Mapping[str, Any], *, source: str = "subject"
    ) -> "ControlReceipt":
        """Retain a stop report as a claim; it is never upgraded to a fact."""
        if source not in {"subject", "connector", "observer"}:
            raise ValueError("claim source must be subject, connector, or observer")
        claim = RetainedClaim(
            claim_id=_new_claim_id(),
            kind="stop",
            source=source,
            state="claimed",
            refs=(_evidence_ref(claim_ref, "claim_ref"),),
        )
        return replace(self, stop_claims=self.stop_claims + (claim,))

    def to_dict(self) -> dict[str, Any]:
        """Emit the seam 13.3 ``ControlReceipt`` shape."""
        return {
            "kind": "control_receipt",
            "handle": copy.deepcopy(self.handle),
            "observation": self.observation.to_dict(),
            "registration_ref": copy.deepcopy(self.registration_ref),
        }


# ---------------------------------------------------------------------------
# Request validation
# ---------------------------------------------------------------------------


class _ControlRejected(Exception):
    def __init__(self, error: Any) -> None:
        self.error = error
        super().__init__(error.detail)


def _connector_error(
    code: str, detail: str, *, handle: Any = None, evidence_refs: Sequence[Any] = ()
) -> Any:
    data = connector_transport.make_connector_error(
        code, detail, handle=handle, evidence_refs=tuple(evidence_refs)
    )
    return connector_transport.ConnectorError(
        code=data["code"],
        detail=data["detail"],
        operation_delivery=data["operation_delivery"],
        retry_guidance=data["retry_guidance"],
        handle=data["handle"],
        evidence_refs=tuple(data["evidence_refs"]),
        fault_domain=data["fault_domain"],
        retry_after=data["retry_after"],
    )


def _reject(code: str, detail: str, *, handle: Any = None) -> NoReturn:
    raise _ControlRejected(_connector_error(code, detail, handle=handle))


def _handle_payload(value: object, connector_id: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value.keys()) != {
        "connector_id",
        "local_handle",
    }:
        _reject(
            "INVALID_REQUEST",
            "connector control operation requires a handle reference with exactly "
            "connector_id and local_handle.",
        )
    if value["connector_id"] != connector_id:
        _reject(
            "UNKNOWN_HANDLE",
            "connector control operation references a handle for a different connector.",
        )
    try:
        local = _require_identifier(value["local_handle"], "handle.local_handle")
    except (TypeError, ValueError) as exc:
        _reject(
            "INVALID_REQUEST",
            f"connector control operation requires a nonempty local_handle: {exc}",
        )
    return {"connector_id": connector_id, "local_handle": local}


def _reason(value: object, operation: str, *, bounded: bool) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        _reject(
            "INVALID_REQUEST",
            f"connector {operation} operation requires a nonempty bounded reason.",
        )
    if any(ord(ch) < 0x20 for ch in value) or len(value) > _IDENTIFIER_MAX:
        _reject(
            "INVALID_REQUEST",
            f"connector {operation} operation reason is not a bounded identifier.",
        )
    if bounded and value not in CLOSE_REASONS:
        _reject(
            "INVALID_REQUEST",
            f"connector {operation} operation requires reason of "
            + ", ".join(sorted(CLOSE_REASONS))
            + ".",
        )
    return value


def _containment_target(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value.keys()) != {"kind", "resource_id"}:
        _reject(
            "INVALID_REQUEST",
            "connector Contain operation requires a target with exactly kind and "
            "resource_id.",
        )
    kind = value["kind"]
    if kind not in CONTAINMENT_TARGET_KINDS:
        _reject(
            "INVALID_REQUEST",
            "connector Contain operation requires a bounded target kind of "
            + ", ".join(sorted(CONTAINMENT_TARGET_KINDS))
            + ".",
        )
    resource_id = value["resource_id"]
    if not isinstance(resource_id, str) or not _CONTAINMENT_RESOURCE_RE.match(resource_id):
        _reject(
            "INVALID_REQUEST",
            "connector Contain operation requires an opaque bounded resource_id; "
            "shell text, paths, and unverified process identifiers are forbidden.",
        )
    if _UNVERIFIED_PID_RE.match(resource_id):
        _reject(
            "INVALID_REQUEST",
            "connector Contain operation rejects unverified process identifiers; "
            "cite an authorized resource reference instead.",
        )
    return {"kind": str(kind), "resource_id": resource_id}


def _artifact_ref_payload(value: object, field: str) -> dict[str, Any]:
    try:
        reference = artifact_store.ArtifactReference.from_dict(dict(value))  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        _reject(
            "INVALID_REQUEST",
            f"connector Contain operation {field} is not an ArtifactReference: {exc}",
        )
    return reference.to_dict()


def _containment_policy(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _reject(
            "INVALID_REQUEST",
            "connector Contain operation requires a reviewed containment policy object.",
        )
    keys = set(value.keys())
    unknown = keys - (_POLICY_FIELDS | _POLICY_OPTIONAL_FIELDS)
    missing = _POLICY_FIELDS - keys
    if unknown or missing:
        _reject(
            "INVALID_REQUEST",
            "connector Contain operation reviewed policy must contain exactly "
            f"{sorted(_POLICY_FIELDS)} and optional {sorted(_POLICY_OPTIONAL_FIELDS)}; "
            f"missing={sorted(missing)} undeclared={sorted(unknown)}.",
        )
    policy: dict[str, Any] = {
        "policy_id": _require_identifier(value["policy_id"], "policy.policy_id"),
        "version": _require_identifier(value["version"], "policy.version"),
    }
    try:
        policy["review_refs"] = [
            dict(ref)
            for ref in _evidence_refs(
                value["review_refs"], "policy.review_refs", allow_empty=False
            )
        ]
    except (TypeError, ValueError) as exc:
        _reject(
            "INVALID_REQUEST",
            f"connector Contain operation reviewed policy requires review evidence: {exc}",
        )
    if "artifact" in value:
        policy["artifact"] = _artifact_ref_payload(value["artifact"], "policy.artifact")
    if "commission" in value:
        policy["commission"] = _artifact_ref_payload(
            value["commission"], "policy.commission"
        )
    return policy


def _scope_token(operation: str, connector_id: str, *parts: str) -> str:
    """Return the bounded opaque resource the scoped grant authorizes.

    The token is derived from the verb, connector, and validated control target
    so the authorization is target-scoped, but it carries no readable identity
    claim, shell text, or caller-supplied authority string.
    """
    material = json.dumps(
        [operation, connector_id, *parts],
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return "control_scope_" + hashlib.sha256(material).hexdigest()[:32]


def _verify_citations(
    channel_id: str, refs: Sequence[Mapping[str, Any]]
) -> tuple[tuple[dict[str, Any], ...], tuple[str, ...]]:
    """Verify cited journal events against their chains where this channel may read.

    Unverifiable citations stay cited claims; they are never silently promoted
    to authority.
    """
    verified: list[dict[str, Any]] = []
    limitations: list[str] = []
    for ref in refs:
        canonical = _evidence_ref(ref, "authorization_refs", allow_alias=True)
        citation = f"{canonical['journal_id']}#{canonical['sequence']}"
        try:
            prefix = evidence_journal.JournalPrefix(
                journal_id=canonical["journal_id"],
                last_sequence=canonical["sequence"],
                head_hash=canonical["event_hash"],
            )
            events = evidence_journal.read_prefix(channel_id, prefix)
        except Exception:
            limitations.append(
                f"authorization citation {citation} was not independently "
                "verified by this channel; it remains a cited claim"
            )
            continue
        if (
            events
            and events[-1].event_id == canonical["event_id"]
            and events[-1].event_hash == canonical["event_hash"]
        ):
            verified.append(canonical)
        else:
            limitations.append(
                f"authorization citation {citation} did not match the verified "
                "journal chain; it remains a cited claim"
            )
    return tuple(verified), tuple(limitations)


@dataclass(frozen=True, slots=True)
class _ControlIntent:
    request_id: str
    connector_id: str
    operation: str
    handle: dict[str, Any]
    reason: str
    close_mode: str
    context_ref: dict[str, Any] | str
    target: dict[str, Any]
    policy: dict[str, Any]
    authorization_refs: tuple[dict[str, Any], ...]
    call_limit_ms: float
    target_scope: str
    scope_resource: str


def _call_limit(request: Any) -> float:
    value = request.call_limit
    if not isinstance(value, Mapping) or set(value.keys()) != {"kind", "unit", "value"}:
        _reject(
            "INVALID_REQUEST",
            "connector control operation call_limit must be an exact ms DurationLimit.",
        )
    if value["kind"] != "exact" or value["unit"] != "ms":
        _reject(
            "INVALID_REQUEST",
            "connector control operation call_limit must be {kind: exact, unit: ms, "
            "value: number}.",
        )
    number = value["value"]
    if isinstance(number, bool) or not isinstance(number, (int, float)):
        _reject(
            "INVALID_REQUEST",
            "connector control operation call_limit.value must be a finite number.",
        )
    if not math.isfinite(float(number)) or float(number) < 0:
        _reject(
            "INVALID_REQUEST",
            "connector control operation call_limit.value must be nonnegative and finite.",
        )
    if float(number) > MAX_CONTROL_CALL_LIMIT_MS:
        _reject(
            "BUDGET_EXCEEDED",
            "connector control operation call_limit exceeds the local control bound "
            f"of {MAX_CONTROL_CALL_LIMIT_MS:g} ms.",
        )
    return float(number)


def _no_bare_nulls(value: object, path: str) -> None:
    if value is None:
        _reject(
            "INVALID_REQUEST",
            f"connector control operation carries a bare null at {path}; every "
            "absent value must be a typed Missing envelope.",
        )
    if isinstance(value, Mapping):
        if _is_missing(value):
            return
        for key, item in value.items():
            if not isinstance(key, str):
                _reject(
                    "INVALID_REQUEST",
                    f"connector control operation payload keys must be strings at {path}.",
                )
            _no_bare_nulls(item, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _no_bare_nulls(item, f"{path}[{index}]")


def _validate_intent(request: Any, operation: str) -> _ControlIntent:
    payload = request.payload
    if not isinstance(payload, Mapping):
        _reject(
            "INVALID_REQUEST",
            f"connector control {operation} operation requires an object payload.",
        )
    expected = _PAYLOAD_FIELDS[operation]
    keys = set(payload.keys())
    if keys - expected or expected - keys:
        _reject(
            "INVALID_REQUEST",
            f"connector control {operation} operation payload must contain exactly "
            f"{sorted(expected)}; missing={sorted(expected - keys)} "
            f"undeclared={sorted(keys - expected)}.",
        )
    _no_bare_nulls(payload, "payload")
    local_handle = _handle_payload(payload["handle"], request.connector_id)
    call_limit_ms = _call_limit(request)
    reason = ""
    if "reason" in expected:
        reason = _reason(
            payload["reason"],
            operation,
            bounded=operation == CLOSE_OBSERVATION_CONNECTION,
        )
    try:
        authorization_refs = _evidence_refs(
            payload["authorization_refs"],
            "authorization_refs",
            allow_empty=operation != CONTAIN,
        )
    except (TypeError, ValueError) as exc:
        _reject(
            "INVALID_REQUEST",
            f"connector control {operation} operation authorization_refs: {exc}",
        )
    close_mode = NOT_APPLICABLE
    context_ref: dict[str, Any] | str = _missing(NOT_APPLICABLE)
    target: dict[str, Any] = {}
    policy: dict[str, Any] = {}
    if operation == CLOSE_OBSERVATION_CONNECTION:
        value = payload["end_observation"]
        if type(value) is not bool:
            _reject(
                "INVALID_REQUEST",
                "connector CloseObservationConnection operation requires "
                "end_observation as a boolean.",
            )
        close_mode = "end_observation" if value else "transport_only"
    elif operation == RELEASE_NATIVE_CONTEXT:
        raw_context = payload["context_ref"]
        if _is_missing(raw_context):
            context_ref = _copy_missing(raw_context)
        else:
            try:
                context_ref = _require_identifier(raw_context, "context_ref")
            except (TypeError, ValueError) as exc:
                _reject(
                    "INVALID_REQUEST",
                    "connector ReleaseNativeContext operation requires context_ref as "
                    f"an identifier or typed Missing: {exc}",
                )
    elif operation == CONTAIN:
        target = _containment_target(payload["target"])
        policy = _containment_policy(payload["policy"])
    if operation == REQUEST_NATIVE_CANCEL:
        target_scope = NATIVE_EXECUTION_SCOPE
        scope_resource = _scope_token(
            operation, request.connector_id, local_handle["local_handle"]
        )
    elif operation == CLOSE_OBSERVATION_CONNECTION:
        target_scope = OBSERVATION_CONNECTION_SCOPE
        scope_resource = _scope_token(
            operation, request.connector_id, local_handle["local_handle"]
        )
    elif operation == RELEASE_NATIVE_CONTEXT:
        target_scope = NATIVE_CONTEXT_SCOPE
        anchor = context_ref if isinstance(context_ref, str) else "unspecified_context"
        scope_resource = _scope_token(
            operation, request.connector_id, local_handle["local_handle"], anchor
        )
    else:
        target_scope = target["kind"]
        scope_resource = _scope_token(
            operation,
            request.connector_id,
            target["kind"],
            target["resource_id"],
        )
    return _ControlIntent(
        request_id=request.request_id,
        connector_id=request.connector_id,
        operation=operation,
        handle=local_handle,
        reason=reason,
        close_mode=close_mode,
        context_ref=context_ref,
        target=target,
        policy=policy,
        authorization_refs=authorization_refs,
        call_limit_ms=call_limit_ms,
        target_scope=target_scope,
        scope_resource=scope_resource,
    )


def _carrier_payload(intent: _ControlIntent) -> dict[str, Any]:
    """Rebuild the carrier payload from the validated control intent.

    The transport acts on exactly the validated request even if the caller
    object is mutated after authorization (no time-of-check/time-of-use gap).
    """
    payload: dict[str, Any] = {
        "handle": copy.deepcopy(intent.handle),
        "authorization_refs": [
            copy.deepcopy(ref) for ref in intent.authorization_refs
        ],
    }
    if intent.operation == CONTAIN:
        payload["target"] = copy.deepcopy(intent.target)
        payload["policy"] = copy.deepcopy(intent.policy)
        payload["reason"] = intent.reason
    elif intent.operation == CLOSE_OBSERVATION_CONNECTION:
        payload["reason"] = intent.reason
        payload["end_observation"] = intent.close_mode == "end_observation"
    elif intent.operation == REQUEST_NATIVE_CANCEL:
        payload["reason"] = intent.reason
    else:
        payload["context_ref"] = copy.deepcopy(intent.context_ref)
    return payload


def _authorize(
    channel_id: str, operation: str, resource: str
) -> tuple[Any, ControlAuthorization]:
    try:
        projection = access_policy.channel_projection(channel_id)
    except access_policy.UnknownChannelError:
        _reject(
            "UNAUTHENTICATED",
            f"connector control {operation} operation requires an authenticated channel.",
        )
    except Exception:
        _reject(
            "UNAUTHENTICATED",
            f"connector control {operation} operation could not authenticate the channel.",
        )
    grants = tuple(projection.get("grants", ()))
    held = tuple(grant for grant in CONTROL_GRANTS[operation] if grant in grants)
    if not held:
        _reject(
            "FORBIDDEN",
            f"connector control {operation} operation is forbidden: the authenticated "
            "channel holds no control grant.",
        )
    try:
        descriptor = access_policy.authorize(channel_id, held[0], resource)
    except access_policy.UnknownChannelError:
        _reject(
            "UNAUTHENTICATED",
            f"connector control {operation} operation requires an authenticated channel.",
        )
    except access_policy.SecretDetectedError:
        _reject(
            "FORBIDDEN",
            f"connector control {operation} operation is forbidden: control "
            "identifiers carry non-ordinary content.",
        )
    except access_policy.AuthorizationError:
        _reject(
            "FORBIDDEN",
            f"connector control {operation} operation is forbidden: the scoped grant "
            "did not authorize this control target.",
        )
    except (ValueError, TypeError) as exc:
        _reject(
            "INVALID_REQUEST",
            f"connector control {operation} operation authorization identifiers are "
            f"invalid: {exc}",
        )
    if descriptor.role != CONNECTOR_ROLE:
        _reject(
            "FORBIDDEN",
            f"connector control {operation} operation requires the connector producer "
            "role; application credentials never grant connector control access.",
        )
    authorization = ControlAuthorization(
        grant=held[0],
        resource=resource,
        producer_id=descriptor.producer_id,
        principal_id=descriptor.principal_id,
        owner_domain=descriptor.owner_domain,
        role=descriptor.role,
        provenance=descriptor.provenance,
    )
    return descriptor, authorization


def _check_containment_prerequisites(channel_id: str, intent: _ControlIntent) -> None:
    if intent.operation != CONTAIN:
        return
    policy = intent.policy
    if "artifact" in policy:
        try:
            reference = artifact_store.ArtifactReference.from_dict(policy["artifact"])
            artifact_store.resolve_artifact(channel_id, reference)
        except (
            artifact_store.ArtifactError,
            access_policy.AuthorizationError,
            TypeError,
            ValueError,
        ) as exc:
            _reject(
                "PREREQUISITE_UNAVAILABLE",
                "connector Contain operation cannot execute: the reviewed containment "
                f"policy bytes are unavailable: {type(exc).__name__}",
            )
    if intent.target["kind"] != "fixture_mutation_authority":
        return
    if "commission" not in policy:
        _reject(
            "PREREQUISITE_UNAVAILABLE",
            "connector Contain operation cannot execute: fixture mutation authority "
            "requires a commissioned laboratory fixture; no commission is cited.",
        )
    try:
        commission = attempt_commissioning.load_commission(
            channel_id, policy["commission"]
        )
    except Exception as exc:
        _reject(
            "PREREQUISITE_UNAVAILABLE",
            "connector Contain operation cannot execute: the cited commission is not "
            f"a loadable retained commission ({type(exc).__name__}).",
        )
    attempt = getattr(commission, "attempt", {})
    target_class = attempt.get("target_class") if isinstance(attempt, Mapping) else None
    if target_class != "laboratory_fixture":
        _reject(
            "PREREQUISITE_UNAVAILABLE",
            "connector Contain operation cannot execute: containment never seals an "
            "employer origin's mutation authority, only a commissioned laboratory "
            "fixture.",
        )


def _coerce_observation(
    result: object, intent: _ControlIntent
) -> tuple[dict[str, Any], ControlObservation, dict[str, Any]]:
    """Validate a carrier receipt and build the canonical observation."""
    operation = intent.operation
    if not isinstance(result, Mapping) or result.get("kind") != "control_receipt":
        _reject(
            "NATIVE_PROTOCOL_ERROR",
            f"connector {operation} operation did not return a control receipt.",
            handle=intent.handle,
        )
    try:
        handle = _handle_payload(result.get("handle"), intent.connector_id)
    except _ControlRejected as rejected:
        _reject(
            "NATIVE_PROTOCOL_ERROR",
            f"connector {operation} operation returned an invalid handle reference: "
            f"{rejected.error.detail}",
            handle=intent.handle,
        )
    raw = result.get("observation")
    if not isinstance(raw, Mapping):
        _reject(
            "NATIVE_PROTOCOL_ERROR",
            f"connector {operation} operation returned no control observation.",
            handle=intent.handle,
        )
    if raw.get("operation") != operation:
        _reject(
            "NATIVE_PROTOCOL_ERROR",
            f"connector {operation} operation returned an observation for a different verb.",
            handle=intent.handle,
        )
    if raw.get("target_scope") != intent.target_scope:
        _reject(
            "NATIVE_PROTOCOL_ERROR",
            f"connector {operation} operation returned an observation for a different "
            "target scope.",
            handle=intent.handle,
        )
    try:
        registration_ref = _evidence_ref(
            result.get("registration_ref"), "registration_ref", allow_alias=True
        )
    except (TypeError, ValueError):
        registration_ref = _missing(NOT_OBSERVED)
    fields = {
        "control_event_id": raw.get("control_event_id"),
        "operation_id": raw.get("operation_id"),
        "operation": raw.get("operation"),
        "target_scope": raw.get("target_scope"),
        "disposition": raw.get("disposition"),
        "at": raw.get("at"),
        "authorization_ref": raw.get("authorization_ref"),
        "capability_ref": raw.get("capability_ref"),
        "opportunity": raw.get("opportunity"),
        "request_ref": raw.get("request_ref"),
        "response_ref": raw.get("response_ref"),
        "response_checks": raw.get("response_checks"),
        "native_claim_refs": raw.get("native_claim_refs", ()),
        "effect_refs": raw.get("effect_refs", ()),
        "affected_attempts": raw.get("affected_attempts", ()),
        "measurements": raw.get("measurements", ()),
        "limitations": raw.get("limitations", ()),
    }
    try:
        observation = ControlObservation(**fields)
    except (TypeError, ValueError) as exc:
        disposition = fields["disposition"]
        if not isinstance(disposition, str) or disposition not in {
            "acknowledged",
            "effect_observed",
        }:
            _reject(
                "NATIVE_PROTOCOL_ERROR",
                f"connector {operation} operation returned an invalid control "
                f"observation: {exc}",
                handle=intent.handle,
            )
        # Never publish an unbacked acknowledgement or effect claim.  Downgrade
        # to the explicit unknown disposition and disclose why.
        downgraded = dict(fields)
        downgraded["disposition"] = "unknown"
        existing_limitations = fields["limitations"]
        if not isinstance(existing_limitations, (list, tuple)):
            existing_limitations = ()
        downgraded["limitations"] = list(existing_limitations) + [
            "connector reported an acknowledgement or effect without the required "
            "evidence; disposition recorded as unknown"
        ]
        try:
            observation = ControlObservation(**downgraded)
        except (TypeError, ValueError) as inner:
            _reject(
                "NATIVE_PROTOCOL_ERROR",
                f"connector {operation} operation returned an invalid control "
                f"observation: {inner}",
                handle=intent.handle,
            )
    return registration_ref, observation, handle


def _record_control_observation(
    channel_id: str,
    authorization: ControlAuthorization,
    intent: _ControlIntent,
    observation: ControlObservation,
    verified_citations: Sequence[Mapping[str, Any]],
) -> JournalAudit:
    """Best-effort owner-local append; the receipt discloses an unavailable audit."""
    data: dict[str, Any] = {
        "request_id": intent.request_id,
        "control_operation": intent.operation,
        "control_observation": observation.to_dict(),
    }
    if intent.target:
        data["containment_target"] = copy.deepcopy(intent.target)
    if intent.reason:
        data["reason"] = intent.reason
    try:
        submission = evidence_journal.EventSubmission(
            producer_sequence=_next_sequence(authorization.owner_domain),
            event_kind=CONTROL_EVENT_KIND,
            event_schema_version=CONTROL_EVENT_VERSION,
            occurred_at=copy.deepcopy(observation.at),
            payload=evidence_journal.EvidencePayload(
                data=data,
                measurements=tuple(observation.measurements),
                evidence_refs=tuple(
                    _evidence_ref(ref, "evidence_ref", allow_alias=True)
                    for ref in verified_citations
                ),
                artifact_refs=(),
            ),
        )
        envelope = evidence_journal.append_event(
            channel_id, authorization.owner_domain, submission
        )
    except Exception as exc:
        return JournalAudit(
            status="unavailable",
            ref=_missing(NOT_OBSERVED),
            limitations=(
                "control observation was not journaled; the receipt remains an "
                f"unpersisted observation ({type(exc).__name__})",
            ),
        )
    return JournalAudit(
        status="appended",
        ref={
            "journal_id": envelope.journal_id,
            "sequence": envelope.journal_sequence,
            "event_id": envelope.event_id,
            "event_hash": envelope.event_hash,
            "pointer": "",
        },
        limitations=(),
    )


async def control_task(
    channel_id: str, request: connector_transport.ConnectorRequest
) -> ControlReceipt | connector_transport.ConnectorError:
    """Execute one authorized connector control and return its receipt.

    Returns :class:`ControlReceipt` on success or a
    :class:`connector_transport.ConnectorError` for every rejection.  The
    operation must be one of the four seam 13.3 controls; prepare/start/
    observe/collect are never accepted here.
    """
    if not isinstance(request, connector_transport.ConnectorRequest):
        return _connector_error(
            "INVALID_REQUEST",
            "connector control operation requires a ConnectorRequest carrier.",
        )
    operation = request.operation
    if not isinstance(operation, str) or operation not in CONTROL_OPERATIONS:
        return _connector_error(
            "INVALID_REQUEST",
            "connector control operation must be one of "
            + ", ".join(sorted(CONTROL_OPERATIONS))
            + "; other connector verbs are not controls.",
        )
    if request.record_type != connector_transport.RECORD_TYPE_REQUEST:
        return _connector_error(
            "INVALID_REQUEST",
            f"connector control {operation} operation requires record_type "
            "connector_request.",
        )
    if request.schema_version != connector_transport.SCHEMA_VERSION:
        return _connector_error(
            "UNSUPPORTED_VERSION",
            f"connector control {operation} operation requires schema_version "
            f"{connector_transport.SCHEMA_VERSION}.",
        )
    try:
        _require_identifier(request.request_id, "request_id")
        _require_identifier(request.connector_id, "connector_id")
    except (TypeError, ValueError) as exc:
        return _connector_error(
            "INVALID_REQUEST",
            f"connector control {operation} operation requires nonempty request_id and "
            f"connector_id: {exc}",
        )
    # Verb + connector authority is checked before any untrusted payload is read.
    try:
        _authorize(
            channel_id, operation, _scope_token(operation, request.connector_id)
        )
    except _ControlRejected as rejected:
        return rejected.error
    try:
        intent = _validate_intent(request, operation)
    except _ControlRejected as rejected:
        return rejected.error
    except (TypeError, ValueError) as exc:
        return _connector_error(
            "INVALID_REQUEST",
            f"connector control {operation} operation payload is not a bounded "
            f"control payload: {exc}",
        )
    # The control target (handle / containment target) is authorized separately.
    try:
        _descriptor, authorization = _authorize(
            channel_id, operation, intent.scope_resource
        )
    except _ControlRejected as rejected:
        return rejected.error
    try:
        _check_containment_prerequisites(channel_id, intent)
    except _ControlRejected as rejected:
        return rejected.error
    verified_citations, citation_limitations = _verify_citations(
        channel_id, intent.authorization_refs
    )
    carrier = connector_transport.ConnectorRequest(
        request_id=request.request_id,
        connector_id=request.connector_id,
        operation=operation,
        call_limit={
            "kind": "exact",
            "unit": "ms",
            "value": intent.call_limit_ms,
        },
        payload=_carrier_payload(intent),
    )
    try:
        response = await connector_transport.call_connector(channel_id, carrier)
    except Exception as exc:  # pragma: no cover - carrier contract is total
        return _connector_error(
            "INTERNAL_ERROR",
            f"connector {operation} operation carrier failed ({type(exc).__name__}); "
            "the control may have been dispatched and must be reconciled.",
            handle=intent.handle,
        )
    if response.is_error:
        return _error_from_result(response.result, operation, intent.handle)
    try:
        registration_ref, observation, handle = _coerce_observation(
            response.result, intent
        )
    except _ControlRejected as rejected:
        return rejected.error
    audit = _record_control_observation(
        channel_id,
        authorization,
        intent,
        observation,
        verified_citations,
    )
    if audit.appended:
        registration_ref = copy.deepcopy(audit.ref)
    try:
        return ControlReceipt(
            request_id=request.request_id,
            connector_id=request.connector_id,
            handle=handle,
            authorization=authorization,
            observation=observation,
            observations=(observation,),
            registration_ref=registration_ref,
            registration_verified=audit.appended,
            audit=audit,
            limitations=citation_limitations,
            close_mode=intent.close_mode,
            stop_claims=(),
        )
    except (TypeError, ValueError) as exc:
        return _connector_error(
            "NATIVE_PROTOCOL_ERROR",
            f"connector {operation} operation receipt is not a valid control receipt: {exc}",
            handle=intent.handle,
        )


def _error_from_result(result: Any, operation: str, handle: Any) -> Any:
    code = result.get("code") if isinstance(result, Mapping) else None
    if not isinstance(code, str) or code not in connector_transport.ERROR_CODES:
        code = "INTERNAL_ERROR"
    detail = result.get("detail") if isinstance(result, Mapping) else None
    if not isinstance(detail, str) or not detail:
        detail = f"connector {operation} operation failed without a bounded detail."
    evidence = result.get("evidence_refs") if isinstance(result, Mapping) else ()
    if isinstance(evidence, (str, bytes)) or not isinstance(evidence, Sequence):
        evidence = ()
    try:
        return _connector_error(
            code, detail, handle=handle, evidence_refs=tuple(evidence)
        )
    except (TypeError, ValueError):
        return _connector_error(
            "INTERNAL_ERROR",
            f"connector {operation} operation failed with an unbounded error carrier.",
            handle=handle,
        )

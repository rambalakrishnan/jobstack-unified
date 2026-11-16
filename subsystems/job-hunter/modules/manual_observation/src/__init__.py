"""manual_observation: manual-lane observation recording at tier 6.

The manual recorder owns the observation axis only.  Dispatch and execution
slots stay at revision zero with inapplicable bindings; human actions, pauses,
and assistance disclosures are journaled with manual provenance; observation
closure is immutable once recorded.
"""

from __future__ import annotations

import importlib
import importlib.util
import sys
from dataclasses import dataclass
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
owner_revisions = _load_sibling("owner_revisions")
attempt_commissioning = _load_sibling("attempt_commissioning")

__all__ = [
    "ObservationValue",
    "ManualObservationError",
    "ManualCommissionError",
    "record_manual_event",
    "publish_manual_observation",
]


OBSERVATION_FIELDS = (
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
)

OBSERVATION_STATES = frozenset({"not_opened", "open", "draining", "closed"})

_ZERO_DIGEST = "sha256:" + "0" * 64


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ManualObservationError(Exception):
    """Base class for manual-observation contract violations."""


class ManualCommissionError(ManualObservationError, ValueError):
    """The commission is not a manual-lane commission."""


# ---------------------------------------------------------------------------
# Missingness / identifier helpers
# ---------------------------------------------------------------------------


def _is_missing(value: Any) -> bool:
    if isinstance(value, Mapping):
        keys = set(value.keys())
        return keys in ({"value", "reason"}, {"value", "reason", "detail"}) and value.get(
            "value"
        ) is None
    return (
        hasattr(value, "reason")
        and getattr(value, "value", "") is None
        and hasattr(value, "to_dict")
    )


def _missing_reason(value: Any) -> str | None:
    if isinstance(value, Mapping) and _is_missing(value):
        reason = value.get("reason")
        return str(reason) if isinstance(reason, str) else None
    if _is_missing(value):
        reason = getattr(value, "reason", None)
        return str(reason) if isinstance(reason, str) else None
    return None


def _require_identifier(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ManualObservationError(f"{field_name} must be a nonempty identifier")
    return value


def _reject_bare_nulls(node: Any, path: str = "$") -> None:
    """Reject in-band nulls; only typed Missing envelopes may carry null."""
    if node is None:
        raise ManualObservationError(f"{path} must use a typed Missing envelope, not null")
    if _is_missing(node):
        return
    if isinstance(node, Mapping):
        for key, item in node.items():
            _reject_bare_nulls(item, f"{path}.{key}")
    elif isinstance(node, (list, tuple)):
        for index, item in enumerate(node):
            _reject_bare_nulls(item, f"{path}[{index}]")


def _jsonable_leaf(value: Any) -> Any:
    """Convert sibling dataclass leaves (TimePoint, refs) to plain dicts."""
    if _is_missing(value):
        if isinstance(value, Mapping):
            return dict(value)
        try:
            return value.to_dict()  # type: ignore[union-attr]
        except Exception:
            return {"value": None, "reason": _missing_reason(value) or "not_applicable"}
    if hasattr(value, "to_dict") and not isinstance(value, (str, bytes, Mapping)):
        try:
            return value.to_dict()  # type: ignore[no-any-return]
        except Exception:
            return value
    if isinstance(value, Mapping):
        return {key: _jsonable_leaf(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_jsonable_leaf(item) for item in value]
    if isinstance(value, list):
        return [_jsonable_leaf(item) for item in value]
    return value


# ---------------------------------------------------------------------------
# Public record type
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ObservationValue:
    """Complete ``L.ObservationValue`` for the manual observation axis."""

    state: str
    window_id: str
    opened_at: Any
    active_deadline: Any
    drain_started_at: Any
    drain_deadline: Any
    closed_at: Any
    close_reason: Any
    at_close: Any
    control_observations: Any
    late_evidence_refs: Any
    measurements: Any

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "window_id": self.window_id,
            "opened_at": _jsonable_leaf(self.opened_at),
            "active_deadline": _jsonable_leaf(self.active_deadline),
            "drain_started_at": _jsonable_leaf(self.drain_started_at),
            "drain_deadline": _jsonable_leaf(self.drain_deadline),
            "closed_at": _jsonable_leaf(self.closed_at),
            "close_reason": _jsonable_leaf(self.close_reason),
            "at_close": _jsonable_leaf(self.at_close),
            "control_observations": _jsonable_leaf(self.control_observations),
            "late_evidence_refs": _jsonable_leaf(self.late_evidence_refs),
            "measurements": _jsonable_leaf(self.measurements),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ObservationValue":
        if not isinstance(data, Mapping):
            raise ManualObservationError("ObservationValue must be a mapping")
        keys = set(data.keys())
        required = set(OBSERVATION_FIELDS)
        missing = sorted(required - keys)
        if missing:
            raise ManualObservationError(
                f"ObservationValue is incomplete; missing {missing}"
            )
        extra = sorted(keys - required)
        if extra:
            raise ManualObservationError(
                f"ObservationValue must be closed; undeclared fields: {extra}"
            )
        state = data["state"]
        if not isinstance(state, str) or state not in OBSERVATION_STATES:
            raise ManualObservationError(f"unknown observation state: {state!r}")
        window_id = data["window_id"]
        if not isinstance(window_id, str) or not window_id:
            raise ManualObservationError("ObservationValue.window_id must be nonempty")
        for field_name in (
            "control_observations",
            "late_evidence_refs",
            "measurements",
        ):
            items = data[field_name]
            if isinstance(items, (str, bytes)) or not isinstance(items, Sequence):
                raise ManualObservationError(
                    f"ObservationValue.{field_name} must be a sequence"
                )
        return cls(
            state=state,
            window_id=window_id,
            opened_at=data["opened_at"],
            active_deadline=data["active_deadline"],
            drain_started_at=data["drain_started_at"],
            drain_deadline=data["drain_deadline"],
            closed_at=data["closed_at"],
            close_reason=data["close_reason"],
            at_close=data["at_close"],
            control_observations=data["control_observations"],
            late_evidence_refs=data["late_evidence_refs"],
            measurements=data["measurements"],
        )


# ---------------------------------------------------------------------------
# Commission guards
# ---------------------------------------------------------------------------


def _ensure_manual(loaded: Any) -> None:
    execution = loaded.execution
    if not isinstance(execution, Mapping):
        raise ManualCommissionError("commission execution must be a mapping")
    if execution.get("mode") != "manual":
        raise ManualCommissionError(
            "manual_observation requires a manual commission; "
            f"got mode {execution.get('mode')!r}"
        )
    for field_name in ("subject", "connector_version", "binding_version"):
        if _missing_reason(execution.get(field_name)) != "not_applicable":
            raise ManualCommissionError(
                f"manual execution requires {field_name} "
                f"Missing(not_applicable); got {execution.get(field_name)!r}"
            )
    owners = loaded.owners
    if not isinstance(owners, Mapping):
        raise ManualCommissionError("commission owners must be a mapping")
    for domain in ("dispatch", "execution"):
        binding = owners.get(domain)
        if not isinstance(binding, Mapping):
            raise ManualCommissionError(f"commission owners.{domain} is missing")
        for field_name in ("source_id", "writer_id"):
            if _missing_reason(binding.get(field_name)) != "not_applicable":
                raise ManualCommissionError(
                    f"manual commission owners.{domain}.{field_name} must be "
                    f"Missing(not_applicable); got {binding.get(field_name)!r}"
                )


def _ref_digest(reference: Any) -> str:
    if hasattr(reference, "digest") and isinstance(reference.digest, str):  # type: ignore[union-attr]
        digest = reference.digest  # type: ignore[union-attr]
    elif isinstance(reference, Mapping) and isinstance(
        reference.get("digest"), str
    ):
        digest = reference["digest"]  # type: ignore[assignment]
    else:
        raise ManualObservationError("commission must be an ArtifactReference")
    if not digest.startswith("sha256:") or len(digest) != 71:
        raise ManualObservationError(f"invalid commission digest: {digest!r}")
    return digest


def _entity_id_for(attempt_id: str, kind: str) -> str:
    return f"attempt.{attempt_id}.{kind}"


def _fetch_registration(attempt_id: str, kind: str) -> Any:
    _require_identifier(attempt_id, "attempt.attempt_id")
    _require_identifier(kind, "attempt.kind")
    entity_id = _entity_id_for(attempt_id, kind)
    store = getattr(owner_revisions, "_REGISTRATIONS", None)
    if not isinstance(store, dict):
        raise ManualObservationError("owner revision store is unavailable")
    entry = store.get(entity_id)
    if entry is None:
        raise ManualObservationError(
            f"attempt {attempt_id!r} is not registered; commission it first"
        )
    record = entry.record if hasattr(entry, "record") else None
    if not isinstance(record, Mapping):
        raise ManualObservationError("stored registration is malformed")
    try:
        return owner_revisions.EntityRegistration.from_dict(dict(record))
    except Exception as exc:
        raise ManualObservationError(f"stored registration is invalid: {exc}") from exc


# ---------------------------------------------------------------------------
# Evidence prefix / refs
# ---------------------------------------------------------------------------


def _observation_prefix(
    channel_id: str, owner_domain: str, attempt_id: str
) -> dict[str, Any]:
    """Return the current observation prefix, or an unadmitted citation.

    When the observation journal is admitted locally (the manual path with
    journaled actions), cite its durable head so the revision pins real
    evidence.  Otherwise cite a structurally valid but unadmitted prefix;
    owner_revisions accepts unadmitted citations and verifies them once the
    journal is available.
    """
    active_map = getattr(evidence_journal, "_ACTIVE_JOURNAL", None)
    if isinstance(active_map, dict):
        journal_id = active_map.get(owner_domain)
        if isinstance(journal_id, str) and journal_id:
            try:
                head = evidence_journal.journal_head(channel_id, journal_id)
                if hasattr(head, "journal_id"):
                    return {
                        "journal_id": head.journal_id,  # type: ignore[union-attr]
                        "last_sequence": head.last_sequence,  # type: ignore[union-attr]
                        "head_hash": head.head_hash,  # type: ignore[union-attr]
                    }
                if isinstance(head, Mapping):
                    return {
                        "journal_id": head["journal_id"],
                        "last_sequence": head["last_sequence"],
                        "head_hash": head["head_hash"],
                    }
            except Exception:
                pass
    journals = getattr(evidence_journal, "_JOURNALS", None)
    if isinstance(journals, dict):
        for journal_id, journal in list(journals.items()):
            try:
                if getattr(journal, "owner_domain", None) != owner_domain:
                    continue
                events = getattr(journal, "events", ())
                if not events:
                    continue
                head_event = events[-1]
                return {
                    "journal_id": journal_id,
                    "last_sequence": len(events),
                    "head_hash": head_event.event_hash,
                }
            except Exception:
                continue
    safe_attempt = "".join(
        ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in attempt_id
    )
    return {
        "journal_id": f"journal_{safe_attempt}_observation",
        "last_sequence": 1,
        "head_hash": _ZERO_DIGEST,
    }


def _build_evidence_refs(
    admission_ref: Any, late_refs: Any
) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    if isinstance(admission_ref, Mapping):
        refs.append(dict(admission_ref))
    elif hasattr(admission_ref, "to_dict"):
        try:
            refs.append(dict(admission_ref.to_dict()))  # type: ignore[arg-type]
        except Exception:
            pass
    if isinstance(late_refs, (list, tuple)):
        for raw in late_refs:
            if isinstance(raw, Mapping):
                refs.append(dict(raw))
            elif hasattr(raw, "to_dict"):
                try:
                    refs.append(dict(raw.to_dict()))  # type: ignore[arg-type]
                except Exception:
                    continue
    if not refs:
        raise ManualObservationError(
            "observation revision requires at least one evidence ref"
        )
    return refs


def _normalize_observation_value(value: Any) -> dict[str, Any]:
    if isinstance(value, ObservationValue):
        normalized = value.to_dict()
    elif isinstance(value, Mapping):
        normalized = ObservationValue.from_dict(value).to_dict()
    else:
        raise ManualObservationError(
            "value must be an ObservationValue or a complete mapping"
        )
    _reject_bare_nulls(normalized)
    return normalized


# ---------------------------------------------------------------------------
# Public interface (EXPOSES)
# ---------------------------------------------------------------------------


def record_manual_event(
    channel_id: str, commission: Any, submission: Any
) -> Any:
    """Journal one human action, pause, note, or assistance disclosure.

    The commission must be manual (no subject, connector, or binding
    versions; dispatch/execution bindings inapplicable).  The event is
    appended to the commissioned observation journal through the
    authenticated manual-recorder channel, so the ingestion authority
    assigns ``manual_observer`` provenance.  Server-assigned envelope
    fields are never trusted from the caller.
    """
    _require_identifier(channel_id, "channel_id")
    try:
        loaded = attempt_commissioning.load_commission(channel_id, commission)
    except ManualObservationError:
        raise
    except Exception as exc:
        raise ManualObservationError(f"cannot load manual commission: {exc}") from exc
    _ensure_manual(loaded)
    owners = loaded.owners
    binding = owners.get("observation") if isinstance(owners, Mapping) else None
    if not isinstance(binding, Mapping):
        raise ManualObservationError("commission has no observation binding")
    owner_domain = binding.get("owner_domain")
    _require_identifier(owner_domain, "owners.observation.owner_domain")

    # Refuse to journal through a non-manual channel before any side effect.
    try:
        projection = access_policy.channel_projection(channel_id)
    except Exception as exc:
        raise ManualObservationError(f"unknown channel {channel_id!r}: {exc}") from exc
    producer = projection.get("producer", {})
    provenance = producer.get("provenance") if isinstance(producer, Mapping) else None
    if provenance != "manual_observer":
        raise ManualObservationError(
            "manual events require a manual_recorder channel with "
            f"manual_observer provenance; got {provenance!r}"
        )
    if projection.get("axis") != owner_domain:
        raise ManualObservationError(
            f"channel axis {projection.get('axis')!r} cannot write owner domain "
            f"{owner_domain!r}"
        )

    envelope = evidence_journal.append_event(channel_id, owner_domain, submission)
    if getattr(envelope, "provenance", None) != "manual_observer":
        raise ManualObservationError(
            "manual event lost manual provenance; got "
            f"{getattr(envelope, 'provenance', None)!r}"
        )
    return envelope


def publish_manual_observation(
    channel_id: str,
    commission: Any,
    value: Any,
    expected_revision: int,
    command_id: str,
) -> Any:
    """Publish one manual observation-axis revision.

    Only the observation axis is ever published; dispatch and execution
    remain at revision zero for manual attempts.  Closed-to-closed
    publications may append late evidence but preserve every original
    closure field.
    """
    _require_identifier(channel_id, "channel_id")
    _require_identifier(command_id, "command_id")
    if (
        isinstance(expected_revision, bool)
        or not isinstance(expected_revision, int)
        or expected_revision < 0
    ):
        raise ManualObservationError("expected_revision must be a nonnegative int")
    value_dict = _normalize_observation_value(value)
    try:
        loaded = attempt_commissioning.load_commission(channel_id, commission)
    except ManualObservationError:
        raise
    except Exception as exc:
        raise ManualObservationError(f"cannot load manual commission: {exc}") from exc
    _ensure_manual(loaded)
    commission_digest = _ref_digest(commission)

    attempt = loaded.attempt
    if not isinstance(attempt, Mapping):
        raise ManualObservationError("commission attempt must be a mapping")
    attempt_id = attempt.get("attempt_id")
    kind = attempt.get("kind")
    _require_identifier(attempt_id, "attempt.attempt_id")
    if kind not in ("practice", "production"):
        raise ManualObservationError(f"invalid attempt kind: {kind!r}")

    registration = _fetch_registration(str(attempt_id), str(kind))
    record = registration.to_dict()
    registered_digest = record["identity"]["commission"]["digest"]
    if registered_digest != commission_digest:
        raise ManualObservationError(
            "commission artifact does not match the registered attempt identity"
        )
    if record["identity"]["execution"]["mode"] != "manual":
        raise ManualObservationError("registered attempt is not manual")
    binding = record["owners"]["observation"]
    owner_domain = binding["owner_domain"]
    writer_id = binding["writer_id"]
    if not isinstance(writer_id, str):
        raise ManualObservationError("manual observation has no bound writer")

    prefix = _observation_prefix(channel_id, owner_domain, str(attempt_id))
    refs = _build_evidence_refs(
        loaded.admission_ref, value_dict.get("late_evidence_refs", [])
    )
    revision = owner_revisions.AxisRevision(
        attempt={"attempt_id": str(attempt_id), "kind": str(kind)},
        commission_digest=commission_digest,
        axis="observation",
        owner_domain=owner_domain,
        writer_id=writer_id,
        revision=expected_revision + 1,
        previous_revision=expected_revision,
        evidence_prefix=prefix,
        evidence_refs=refs,
        value=value_dict,
    )
    lease = {"value": None, "reason": "not_applicable"}
    owner_revisions.commit_domain(channel_id, registration, revision, command_id, lease)
    return revision

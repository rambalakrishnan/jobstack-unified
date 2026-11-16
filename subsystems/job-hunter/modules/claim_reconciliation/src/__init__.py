"""claim_reconciliation: execution-claim vs origin-fact reconciliation (tier 6).

Implements ``job-hunter-seam-mapping.md#11.7`` (Report),
``#14`` (origin verification ingress), and ``#19.3`` (claimed
cancellation contradicted):

- ``derive_report`` reads pinned execution claims and origin facts and
  writes only a report value. It compares propositions at their actual
  scope and knowledge boundary. A stopped claim alone never asserts an
  entire-attempt no-commit.
- ``publish_report`` commits one complete report axis revision via
  ``owner_revisions.commit_domain``. It never writes dispatch,
  observation, execution, or application.
- Temporal ordering requires same-clock, causal, or documented
  origin-sequence evidence. Receipt order and UTC annotations are
  insufficient. Opaque origin revisions are never ordered lexically.
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import re
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, is_dataclass
from pathlib import Path
from typing import Any


def _load_sibling(name: str):  # pragma: no cover - import plumbing
    if name in sys.modules:
        return sys.modules[name]
    try:
        return importlib.import_module(name)
    except ModuleNotFoundError:
        pass
    sibling_path = (
        Path(__file__).resolve().parents[2] / name / "src" / "__init__.py"
    )
    if not sibling_path.exists():
        raise ModuleNotFoundError(f"sibling module {name!r} not found")
    spec = importlib.util.spec_from_file_location(name, sibling_path)
    if spec is None or spec.loader is None:
        raise ModuleNotFoundError(f"sibling module {name!r} not found")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


contract_codec = _load_sibling("contract_codec")
artifact_store = _load_sibling("artifact_store")
evidence_journal = _load_sibling("evidence_journal")
owner_revisions = _load_sibling("owner_revisions")
attempt_commissioning = _load_sibling("attempt_commissioning")

__all__ = [
    "derive_report",
    "publish_report",
    "ReportValue",
    "ReportInputPins",
    "DomainPin",
    "VersionPin",
    "ClaimComparison",
    "TemporalRelation",
    "ReconciliationIssue",
    "ReconciliationError",
    "InvalidReportError",
    "PinResolutionError",
    "reset_for_tests",
]

SCHEMA_VERSION = "application-attempt-lifecycle/0.1.0"
RECORD_TYPE_AXIS = "attempt_axis_revision"
_CODEC_GATE_SCHEMA = "record/v1"
_CODEC_GATE_ID = "claim_reconciliation_gate"

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_PIN_AXES = ("dispatch", "observation", "execution", "application")
_REPORT_STATES = frozenset({"reconciled", "contradicted"})
_REPORT_COVERAGES = frozenset({"complete", "incomplete", "not_applicable"})
_COMPARISON_RESULTS = frozenset(
    {"consistent", "contradicted", "not_comparable", "indeterminate"}
)
_TEMPORAL_RELATIONS = frozenset(
    {"before", "at", "after", "unknown", "not_applicable"}
)
_TEMPORAL_BASES = frozenset(
    {
        "same_clock",
        "causal_evidence",
        "origin_sequence",
        "not_established",
        "not_applicable",
    }
)
_ISSUE_KINDS = frozenset(
    {
        "origin_fact_conflict",
        "subject_claim_conflict",
        "insufficient_evidence",
        "incomparable_scope",
        "untrusted_observation",
        "mapping_error",
        "multiple_origin_commitments",
    }
)
_ASSERTION_VALUES = frozenset({"committed", "not_committed", "outcome_unknown"})
_ASSERTION_SPANS = frozenset({"at_boundary", "after_boundary", "entire_attempt"})

ArtifactReference = artifact_store.ArtifactReference
JournalPrefix = evidence_journal.JournalPrefix
JournalEnvelope = evidence_journal.JournalEnvelope
EvidenceRef = evidence_journal.EvidenceRef
AxisRevision = owner_revisions.AxisRevision
EntityRegistration = owner_revisions.EntityRegistration


class ReconciliationError(Exception):
    """Base class for claim-reconciliation failures."""


class InvalidReportError(ReconciliationError, ValueError):
    """A report value, pin set, or comparison is structurally invalid."""


class PinResolutionError(ReconciliationError, ValueError):
    """A report input pin names an unpublished or mismatched revision."""


class CommissionResolutionError(ReconciliationError, ValueError):
    """The commission cannot be loaded or does not identify the attempt."""


def _require_identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise InvalidReportError(f"{field} must be a nonempty identifier")
    if len(value) > 512 or "\x00" in value:
        raise InvalidReportError(f"{field} must be a bounded identifier")
    return value


def _require_digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.match(value):
        raise InvalidReportError(
            f"{field} must be a sha256:<64 lowercase hex> digest"
        )
    return value


def _valid_missing_reasons() -> frozenset[str]:
    reasons = getattr(contract_codec, "VALID_MISSING_REASONS", None)
    if isinstance(reasons, frozenset):
        return reasons
    return frozenset(
        {
            "not_observed",
            "observation_lost",
            "not_applicable",
            "not_enabled",
            "unsupported_by_subject",
            "manual_override",
        }
    )


def _is_missing(value: Any) -> bool:
    if is_dataclass(value) and not isinstance(value, type):
        return getattr(value, "value", "") is None and hasattr(value, "reason")
    if not isinstance(value, Mapping):
        return False
    keys = set(value.keys())
    if keys != {"value", "reason"} and keys != {"value", "reason", "detail"}:
        return False
    return value.get("value") is None


def _missing_reason(value: Any) -> str | None:
    if is_dataclass(value) and not isinstance(value, type):
        if getattr(value, "value", "") is None and hasattr(value, "reason"):
            return str(getattr(value, "reason"))
        return None
    if _is_missing(value):
        reason = value.get("reason")
        if isinstance(reason, str):
            return str(reason)
        return None
    return None


def _missing_dict(reason: str, detail: str | None = None) -> dict[str, Any]:
    if reason not in _valid_missing_reasons():
        raise InvalidReportError(f"unknown Missing reason: {reason!r}")
    if detail is not None:
        if not isinstance(detail, str) or not detail:
            raise InvalidReportError("Missing.detail must be a nonempty string")
    maker = getattr(contract_codec, "make_missing", None)
    if callable(maker):
        try:
            if detail is not None:
                made = maker(reason, detail)
            else:
                made = maker(reason)
            if isinstance(made, dict):
                return dict(made)
        except (TypeError, ValueError) as exc:
            raise InvalidReportError(str(exc)) from exc
    out: dict[str, Any] = {"value": None, "reason": reason}
    if detail is not None:
        out["detail"] = detail
    return out


def _missing_to_dict(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        if _is_missing(value):
            out: dict[str, Any] = {
                "value": None,
                "reason": str(getattr(value, "reason")),
            }
            detail = getattr(value, "detail", None)
            if detail is not None:
                out["detail"] = detail
            return out
        to_dict = getattr(value, "to_dict", None)
        if callable(to_dict):
            return to_dict()
        return value
    return value


def _jsonable(value: Any, path: str = "$") -> Any:
    value = _missing_to_dict(value)
    if _is_missing(value):
        reason = _missing_reason(value)
        assert reason is not None
        if reason not in _valid_missing_reasons():
            raise InvalidReportError(
                f"unknown Missing reason at {path}: {reason!r}"
            )
        out: dict[str, Any] = {"value": None, "reason": reason}
        detail = value.get("detail") if isinstance(value, Mapping) else None
        if detail is not None:
            if not isinstance(detail, str) or not detail:
                raise InvalidReportError(
                    f"Missing.detail must be nonempty at {path}"
                )
            out["detail"] = detail
        return out
    if value is None:
        raise InvalidReportError(f"bare null rejected at {path} (use Missing)")
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        return value
    if isinstance(value, Mapping):
        return {
            str(k): _jsonable(v, f"{path}.{k}") for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_jsonable(v, f"{path}[{i}]") for i, v in enumerate(value)]
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        return _jsonable(to_dict(), path)
    raise InvalidReportError(
        f"unsupported value at {path}: {type(value).__name__}"
    )


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        _jsonable(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _strict_gate(value: Any, context: str) -> None:
    """Run the kernel strict-JSON gate over one complete value.

    The payload rides inside ``record/v1.timing`` so duplicate keys,
    bare nulls, nonfinite numbers, and malformed Missing envelopes are
    rejected by ``contract_codec`` before closed-shape checks apply.
    """
    try:
        payload = _canonical_bytes(value)
    except (TypeError, ValueError) as exc:
        raise InvalidReportError(
            f"{context}: record is not canonicalizable JSON: {exc}"
        ) from exc
    wrapper = (
        b'{"id":"'
        + _CODEC_GATE_ID.encode("utf-8")
        + b'","timing":'
        + payload
        + b"}"
    )
    try:
        contract_codec.validate_record(wrapper, _CODEC_GATE_SCHEMA)
    except (TypeError, ValueError) as exc:
        raise InvalidReportError(
            f"{context}: strict JSON gate rejected record: {exc}"
        ) from exc


def _require_exact_keys(
    value: Any, required: frozenset[str] | set[str], label: str
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise InvalidReportError(f"{label} must be a mapping")
    keys = set(value.keys())
    if keys != set(required):
        missing = sorted(set(required) - keys)
        extra = sorted(keys - set(required))
        raise InvalidReportError(
            f"{label} must contain exactly {sorted(required)}"
            f"; missing {missing}; extra {extra}"
        )
    return value


def _coerce_evidence_ref(value: Any, field: str) -> dict[str, Any]:
    if isinstance(value, evidence_journal.EvidenceRef):
        return dict(value.to_dict())
    data = _require_exact_keys(
        value,
        frozenset({"journal_id", "sequence", "event_id", "event_hash", "pointer"}),
        field,
    )
    try:
        ref = evidence_journal.EvidenceRef.from_dict(dict(data))
    except (TypeError, ValueError) as exc:
        raise InvalidReportError(
            f"{field} is not a valid EvidenceRef: {exc}"
        ) from exc
    return dict(ref.to_dict())


def _coerce_evidence_ref_list(
    value: Any, field: str, allow_empty: bool = False
) -> list[dict[str, Any]]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise InvalidReportError(f"{field} must be a sequence of EvidenceRefs")
    refs = [
        _coerce_evidence_ref(item, f"{field}[{i}]")
        for i, item in enumerate(value)
    ]
    seen: set[tuple[str, int, str, str, str]] = set()
    for ref in refs:
        key = (
            str(ref["journal_id"]),
            int(ref["sequence"]),
            str(ref["event_id"]),
            str(ref["event_hash"]),
            str(ref["pointer"]),
        )
        if key in seen:
            raise InvalidReportError(f"{field} must not contain duplicate refs")
        seen.add(key)
    if not refs and not allow_empty:
        raise InvalidReportError(f"{field} requires at least one EvidenceRef")
    return refs


def _is_timepoint_dict(value: Any) -> bool:
    return isinstance(value, Mapping) and set(value.keys()) == {
        "clock_id",
        "boot_id",
        "origin",
        "monotonic_offset_ms",
        "utc_annotation",
    }


def _coerce_timepoint_or_missing(value: Any, field: str) -> Any:
    if _missing_reason(value) is not None:
        return _jsonable(value, field)
    if not _is_timepoint_dict(value):
        raise InvalidReportError(f"{field} must be a TimePoint or Missing")
    clock_id = _require_identifier(value.get("clock_id"), f"{field}.clock_id")
    boot_id = _require_identifier(value.get("boot_id"), f"{field}.boot_id")
    origin = value.get("origin")
    if origin not in (
        "engine_measured",
        "browser_measured",
        "subject_reported",
        "manual_reference",
    ):
        raise InvalidReportError(f"{field}.origin is invalid")
    offset = value.get("monotonic_offset_ms")
    if isinstance(offset, bool) or not isinstance(offset, (int, float)):
        raise InvalidReportError(f"{field}.monotonic_offset_ms must be a number")
    if offset < 0:
        raise InvalidReportError(
            f"{field}.monotonic_offset_ms must be nonnegative"
        )
    return _jsonable(value, field)


@dataclass(frozen=True, slots=True)
class DomainPin:
    """One axis revision pin (``L.DomainPin``)."""

    revision: int
    record_digest: Any

    def to_dict(self) -> dict[str, Any]:
        return {
            "revision": self.revision,
            "record_digest": _jsonable(
                self.record_digest, "DomainPin.record_digest"
            ),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> DomainPin:
        _require_exact_keys(data, frozenset({"revision", "record_digest"}), "DomainPin")
        revision = data["revision"]
        if isinstance(revision, bool) or not isinstance(revision, int):
            raise InvalidReportError("DomainPin.revision must be an int")
        if revision < 0:
            raise InvalidReportError("DomainPin.revision must be nonnegative")
        digest = data["record_digest"]
        if revision == 0:
            if _missing_reason(digest) is None:
                raise InvalidReportError(
                    "DomainPin.record_digest must be Missing at revision 0"
                )
            return cls(revision=0, record_digest=_jsonable(digest, "DomainPin"))
        return cls(
            revision=revision,
            record_digest=_require_digest(digest, "DomainPin.record_digest"),
        )


@dataclass(frozen=True, slots=True)
class ReportInputPins:
    """Pinned source revisions (``L.ReportInputPins``)."""

    dispatch: DomainPin
    observation: DomainPin
    execution: DomainPin
    application: DomainPin

    def to_dict(self) -> dict[str, Any]:
        return {
            "dispatch": self.dispatch.to_dict(),
            "observation": self.observation.to_dict(),
            "execution": self.execution.to_dict(),
            "application": self.application.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ReportInputPins:
        _require_exact_keys(data, frozenset(_PIN_AXES), "ReportInputPins")

        def _pin(axis: str) -> DomainPin:
            raw = data[axis]
            if isinstance(raw, DomainPin):
                return raw
            if not isinstance(raw, Mapping):
                raise InvalidReportError(
                    f"ReportInputPins.{axis} must be a DomainPin"
                )
            return DomainPin.from_dict(raw)

        return cls(
            dispatch=_pin("dispatch"),
            observation=_pin("observation"),
            execution=_pin("execution"),
            application=_pin("application"),
        )


@dataclass(frozen=True, slots=True)
class VersionPin:
    """Immutable version pin (``K.VersionPin``)."""

    id: str
    version: str
    artifact_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "version": self.version,
            "artifact_digest": self.artifact_digest,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> VersionPin:
        _require_exact_keys(
            data, frozenset({"id", "version", "artifact_digest"}), "VersionPin"
        )
        return cls(
            id=_require_identifier(data["id"], "VersionPin.id"),
            version=_require_identifier(data["version"], "VersionPin.version"),
            artifact_digest=_require_digest(
                data["artifact_digest"], "VersionPin.artifact_digest"
            ),
        )


@dataclass(frozen=True, slots=True)
class TemporalRelation:
    """Ordering of one origin fact to one assertion boundary."""

    relation: str
    basis: str
    evidence_refs: tuple[dict[str, Any], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "relation": self.relation,
            "basis": self.basis,
            "evidence_refs": [_jsonable(r) for r in self.evidence_refs],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> TemporalRelation:
        _require_exact_keys(
            data,
            frozenset({"relation", "basis", "evidence_refs"}),
            "TemporalRelation",
        )
        relation = data["relation"]
        basis = data["basis"]
        if relation not in _TEMPORAL_RELATIONS:
            raise InvalidReportError("TemporalRelation.relation is invalid")
        if basis not in _TEMPORAL_BASES:
            raise InvalidReportError("TemporalRelation.basis is invalid")
        refs = _coerce_evidence_ref_list(
            data["evidence_refs"],
            "TemporalRelation.evidence_refs",
            allow_empty=True,
        )
        if relation in ("before", "at", "after"):
            if basis not in ("same_clock", "causal_evidence", "origin_sequence"):
                raise InvalidReportError(
                    "a known temporal relation requires a same_clock,"
                    " causal_evidence, or origin_sequence basis"
                )
            if not refs:
                raise InvalidReportError(
                    "a known temporal relation requires evidence_refs"
                )
        if relation == "unknown" and basis != "not_established":
            raise InvalidReportError(
                "unknown temporal relation needs not_established"
            )
        if relation == "not_applicable" and basis != "not_applicable":
            raise InvalidReportError(
                "not_applicable temporal relation needs not_applicable basis"
            )
        return cls(
            relation=relation, basis=basis, evidence_refs=tuple(refs)
        )


@dataclass(frozen=True, slots=True)
class ClaimComparison:
    """One claim-assertion vs origin-fact comparison."""

    claim_id: str
    assertion_id: Any
    claim_ref: dict[str, Any]
    fact_ids: tuple[str, ...]
    fact_refs: tuple[dict[str, Any], ...]
    result: str
    temporal_relation: TemporalRelation
    rationale: str
    limitations: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "assertion_id": _jsonable(
                self.assertion_id, "ClaimComparison.assertion_id"
            ),
            "claim_ref": _jsonable(
                self.claim_ref, "ClaimComparison.claim_ref"
            ),
            "fact_ids": list(self.fact_ids),
            "fact_refs": [_jsonable(r) for r in self.fact_refs],
            "result": self.result,
            "temporal_relation": self.temporal_relation.to_dict(),
            "rationale": self.rationale,
            "limitations": list(self.limitations),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ClaimComparison:
        _require_exact_keys(
            data,
            frozenset(
                {
                    "claim_id",
                    "assertion_id",
                    "claim_ref",
                    "fact_ids",
                    "fact_refs",
                    "result",
                    "temporal_relation",
                    "rationale",
                    "limitations",
                }
            ),
            "ClaimComparison",
        )
        claim_id = _require_identifier(
            data["claim_id"], "ClaimComparison.claim_id"
        )
        assertion_id = data["assertion_id"]
        if _missing_reason(assertion_id) is not None:
            assertion_id = _jsonable(
                assertion_id, "ClaimComparison.assertion_id"
            )
        else:
            assertion_id = _require_identifier(
                assertion_id, "ClaimComparison.assertion_id"
            )
        claim_ref = _coerce_evidence_ref(
            data["claim_ref"], "ClaimComparison.claim_ref"
        )
        fact_ids_raw = data["fact_ids"]
        if isinstance(fact_ids_raw, (str, bytes)) or not isinstance(
            fact_ids_raw, Sequence
        ):
            raise InvalidReportError(
                "ClaimComparison.fact_ids must be a sequence"
            )
        fact_ids = tuple(
            _require_identifier(v, f"ClaimComparison.fact_ids[{i}]")
            for i, v in enumerate(fact_ids_raw)
        )
        if len(set(fact_ids)) != len(fact_ids):
            raise InvalidReportError("ClaimComparison.fact_ids must be unique")
        fact_refs = tuple(
            _coerce_evidence_ref_list(
                data["fact_refs"],
                "ClaimComparison.fact_refs",
                allow_empty=True,
            )
        )
        result = data["result"]
        if result not in _COMPARISON_RESULTS:
            raise InvalidReportError("ClaimComparison.result is invalid")
        if result in ("consistent", "contradicted"):
            if not fact_ids or not fact_refs:
                raise InvalidReportError(
                    f"a {result} comparison requires fact_ids and fact_refs"
                )
        temporal_raw = data["temporal_relation"]
        if isinstance(temporal_raw, TemporalRelation):
            temporal = temporal_raw
        else:
            temporal = TemporalRelation.from_dict(temporal_raw)
        rationale = data["rationale"]
        if not isinstance(rationale, str) or not rationale:
            raise InvalidReportError(
                "ClaimComparison.rationale must be nonempty"
            )
        limitations_raw = data["limitations"]
        if isinstance(limitations_raw, (str, bytes)) or not isinstance(
            limitations_raw, Sequence
        ):
            raise InvalidReportError(
                "ClaimComparison.limitations must be a sequence"
            )
        limitations: list[str] = []
        for i, v in enumerate(limitations_raw):
            if not isinstance(v, str):
                raise InvalidReportError(
                    "ClaimComparison.limitations must be strings"
                )
            limitations.append(
                _require_identifier(v, f"ClaimComparison.limitations[{i}]")
            )
        for text in limitations:
            if not text:
                raise InvalidReportError(
                    "ClaimComparison.limitations must be nonempty strings"
                )
        return cls(
            claim_id=claim_id,
            assertion_id=assertion_id,
            claim_ref=claim_ref,
            fact_ids=fact_ids,
            fact_refs=fact_refs,
            result=result,
            temporal_relation=temporal,
            rationale=rationale,
            limitations=tuple(limitations),
        )


@dataclass(frozen=True, slots=True)
class ReconciliationIssue:
    """One explicit reconciliation issue (never a silent edit)."""

    kind: str
    detail: str
    evidence_refs: tuple[dict[str, Any], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "detail": self.detail,
            "evidence_refs": [_jsonable(r) for r in self.evidence_refs],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ReconciliationIssue:
        _require_exact_keys(
            data,
            frozenset({"kind", "detail", "evidence_refs"}),
            "ReconciliationIssue",
        )
        kind = data["kind"]
        if kind not in _ISSUE_KINDS:
            raise InvalidReportError("ReconciliationIssue.kind is invalid")
        detail = data["detail"]
        if not isinstance(detail, str) or not detail:
            raise InvalidReportError(
                "ReconciliationIssue.detail must be nonempty"
            )
        refs = tuple(
            _coerce_evidence_ref_list(
                data["evidence_refs"],
                "ReconciliationIssue.evidence_refs",
                allow_empty=False,
            )
        )
        return cls(kind=kind, detail=detail, evidence_refs=refs)


@dataclass(frozen=True, slots=True)
class ReportValue:
    """Complete report value (``L.ReportValue``)."""

    state: Any
    coverage: str
    inputs: ReportInputPins
    evaluator: VersionPin
    comparisons: tuple[ClaimComparison, ...]
    issues: tuple[ReconciliationIssue, ...]
    limitations: tuple[str, ...]
    diagnostic: Any

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": _jsonable(self.state, "ReportValue.state"),
            "coverage": self.coverage,
            "inputs": self.inputs.to_dict(),
            "evaluator": self.evaluator.to_dict(),
            "comparisons": [c.to_dict() for c in self.comparisons],
            "issues": [i.to_dict() for i in self.issues],
            "limitations": list(self.limitations),
            "diagnostic": _jsonable(self.diagnostic, "ReportValue.diagnostic"),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ReportValue:
        _require_exact_keys(
            data,
            frozenset(
                {
                    "state",
                    "coverage",
                    "inputs",
                    "evaluator",
                    "comparisons",
                    "issues",
                    "limitations",
                    "diagnostic",
                }
            ),
            "ReportValue",
        )
        state = data["state"]
        if _missing_reason(state) is not None:
            state = _jsonable(state, "ReportValue.state")
        elif state not in _REPORT_STATES:
            raise InvalidReportError("ReportValue.state is invalid")
        coverage = data["coverage"]
        if coverage not in _REPORT_COVERAGES:
            raise InvalidReportError("ReportValue.coverage is invalid")
        inputs_raw = data["inputs"]
        if isinstance(inputs_raw, ReportInputPins):
            inputs = inputs_raw
        else:
            inputs = ReportInputPins.from_dict(inputs_raw)
        evaluator_raw = data["evaluator"]
        if isinstance(evaluator_raw, VersionPin):
            evaluator = evaluator_raw
        else:
            evaluator = VersionPin.from_dict(evaluator_raw)
        comparisons_raw = data["comparisons"]
        if isinstance(comparisons_raw, (str, bytes)) or not isinstance(
            comparisons_raw, Sequence
        ):
            raise InvalidReportError("ReportValue.comparisons must be a sequence")
        comparisons = tuple(
            c if isinstance(c, ClaimComparison) else ClaimComparison.from_dict(c)
            for c in comparisons_raw
        )
        issues_raw = data["issues"]
        if isinstance(issues_raw, (str, bytes)) or not isinstance(
            issues_raw, Sequence
        ):
            raise InvalidReportError("ReportValue.issues must be a sequence")
        issues = tuple(
            i if isinstance(i, ReconciliationIssue) else ReconciliationIssue.from_dict(i)
            for i in issues_raw
        )
        limitations_raw = data["limitations"]
        if isinstance(limitations_raw, (str, bytes)) or not isinstance(
            limitations_raw, Sequence
        ):
            raise InvalidReportError("ReportValue.limitations must be a sequence")
        limitations: list[str] = []
        for index, text in enumerate(limitations_raw):
            if not isinstance(text, str) or not text:
                raise InvalidReportError(
                    f"ReportValue.limitations[{index}] must be a nonempty string"
                )
            limitations.append(text)
        diagnostic = data["diagnostic"]
        if _missing_reason(diagnostic) is not None:
            diagnostic_norm = _jsonable(diagnostic, "ReportValue.diagnostic")
        elif isinstance(diagnostic, Mapping):
            try:
                if isinstance(diagnostic, artifact_store.ArtifactReference):
                    diagnostic_norm = dict(diagnostic.to_dict())
                else:
                    ref = artifact_store.ArtifactReference.from_dict(
                        dict(diagnostic)
                    )
                    diagnostic_norm = dict(ref.to_dict())
            except (TypeError, ValueError) as exc:
                raise InvalidReportError(
                    f"ReportValue.diagnostic is invalid: {exc}"
                ) from exc
        else:
            raise InvalidReportError(
                "ReportValue.diagnostic must be an ArtifactReference or Missing"
            )
        _check_report_rules(state, coverage, comparisons)
        return cls(
            state=state,
            coverage=coverage,
            inputs=inputs,
            evaluator=evaluator,
            comparisons=comparisons,
            issues=issues,
            limitations=tuple(limitations),
            diagnostic=diagnostic_norm,
        )


def _check_report_rules(
    state: Any, coverage: str, comparisons: Sequence[ClaimComparison]
) -> None:
    results = [c.result for c in comparisons]
    if "contradicted" in results and state != "contradicted":
        raise InvalidReportError(
            "a contradicted comparison requires the contradicted state"
        )
    if state == "contradicted" and "contradicted" not in results:
        raise InvalidReportError(
            "a contradicted report requires a contradicted comparison"
        )
    if state == "reconciled":
        if coverage != "complete":
            raise InvalidReportError(
                "a reconciled report requires complete coverage"
            )
        if not comparisons or "contradicted" in results:
            raise InvalidReportError(
                "a reconciled report requires non-contradicted comparisons"
            )
        for result in results:
            if result not in ("consistent", "not_comparable"):
                raise InvalidReportError(
                    "a reconciled report admits only consistent/not_comparable results"
                )
    if coverage == "complete":
        if state not in ("reconciled", "contradicted"):
            raise InvalidReportError(
                "complete coverage requires a reconciled or contradicted state"
            )
        if not comparisons:
            raise InvalidReportError("complete coverage requires comparisons")
        for result in results:
            if result not in ("consistent", "contradicted", "not_comparable"):
                raise InvalidReportError(
                    "complete coverage admits no indeterminate results"
                )
    if coverage == "not_applicable":
        reason = _missing_reason(state)
        if reason is None or reason != "not_applicable":
            raise InvalidReportError(
                "not_applicable coverage requires Missing(not_applicable) state"
            )
        if comparisons:
            raise InvalidReportError(
                "not_applicable coverage requires no comparisons"
            )
    if coverage == "incomplete" and "contradicted" not in results:
        reason = _missing_reason(state)
        if reason not in ("not_observed", "observation_lost"):
            raise InvalidReportError(
                "incomplete coverage without contradiction requires"
                " Missing(not_observed/observation_lost) state"
            )


def _coerce_artifact_reference(value: Any, field: str) -> Any:
    if isinstance(value, artifact_store.ArtifactReference):
        return value
    if not isinstance(value, Mapping):
        raise InvalidReportError(f"{field} must be an ArtifactReference")
    try:
        return artifact_store.ArtifactReference.from_dict(dict(value))
    except (TypeError, ValueError) as exc:
        raise InvalidReportError(
            f"{field} is not an ArtifactReference: {exc}"
        ) from exc


def _coerce_prefix(value: Any) -> Any:
    if isinstance(value, evidence_journal.JournalPrefix):
        return value
    if not isinstance(value, Mapping):
        raise InvalidReportError("prefix must be a JournalPrefix")
    _require_exact_keys(
        value, frozenset({"journal_id", "last_sequence", "head_hash"}), "prefix"
    )
    try:
        return evidence_journal.JournalPrefix(
            journal_id=value["journal_id"],
            last_sequence=value["last_sequence"],
            head_hash=value["head_hash"],
        )
    except (TypeError, ValueError) as exc:
        raise InvalidReportError(
            f"prefix is not a valid JournalPrefix: {exc}"
        ) from exc


def _coerce_pins(value: Any) -> ReportInputPins:
    if isinstance(value, ReportInputPins):
        return value
    if not isinstance(value, Mapping):
        raise InvalidReportError("inputs must be ReportInputPins")
    return ReportInputPins.from_dict(value)


def _coerce_evaluator(value: Any) -> VersionPin:
    if isinstance(value, VersionPin):
        return value
    if not isinstance(value, Mapping):
        raise InvalidReportError("evaluator must be a VersionPin")
    return VersionPin.from_dict(value)


def _load_commission(
    channel_id: str, commission: Any
) -> tuple[Any, dict[str, Any]]:
    _require_identifier(channel_id, "channel_id")
    reference = _coerce_artifact_reference(commission, "commission")
    try:
        artifact_store.resolve_artifact(channel_id, reference)
    except Exception as exc:
        raise CommissionResolutionError(
            f"commission bytes are unavailable: {exc}"
        ) from exc
    try:
        record = attempt_commissioning.load_commission(channel_id, reference)
    except Exception as exc:
        raise CommissionResolutionError(
            f"commission cannot be loaded: {exc}"
        ) from exc
    if hasattr(record, "to_dict"):
        as_dict = record.to_dict()
    else:
        as_dict = dict(record)
    return record, as_dict


def _entity_for_commission(commission_dict: Mapping[str, Any]) -> dict[str, Any]:
    attempt = commission_dict.get("attempt")
    if not isinstance(attempt, Mapping):
        raise CommissionResolutionError("commission carries no attempt context")
    attempt_id = attempt.get("attempt_id")
    kind = attempt.get("kind")
    if not isinstance(attempt_id, str) or not attempt_id:
        raise CommissionResolutionError("commission attempt_id is invalid")
    if kind not in ("practice", "production"):
        raise CommissionResolutionError("commission attempt kind is invalid")
    return {
        "entity_type": "application_attempt",
        "attempt_id": attempt_id,
        "kind": kind,
    }


def _load_pinned_values(
    channel_id: str, entity: Mapping[str, Any], pins: ReportInputPins
) -> dict[str, dict[str, Any] | None]:
    reader = getattr(owner_revisions, "read_revision", None)
    if not callable(reader):
        raise ReconciliationError(
            "owner_revisions.read_revision is unavailable; cannot load pinned inputs"
        )
    pin_map = {
        "dispatch": pins.dispatch,
        "observation": pins.observation,
        "execution": pins.execution,
        "application": pins.application,
    }
    loaded: dict[str, dict[str, Any] | None] = {}
    for axis, pin in pin_map.items():
        if pin.revision == 0:
            loaded[axis] = None
            continue
        try:
            published = reader(channel_id, dict(entity), axis, pin.revision)
        except Exception as exc:
            raise PinResolutionError(
                f"report input pin {axis!r} names unpublished revision "
                f"{pin.revision}: {exc}"
            ) from exc
        if isinstance(published, Mapping) and _missing_reason(published) is not None:
            raise PinResolutionError(
                f"report input pin {axis!r} names unpublished revision "
                f"{pin.revision}"
            )
        digest = getattr(published, "content_digest", None)
        record = getattr(published, "record", None)
        if not isinstance(digest, str) or not isinstance(record, Mapping):
            raise PinResolutionError(
                f"report input pin {axis!r} returned an unreadable publication"
            )
        if digest != pin.record_digest:
            raise PinResolutionError(
                f"report input pin {axis!r} digest does not identify"
                f" the published revision {pin.revision}"
            )
        value = record.get("value")
        if not isinstance(value, Mapping):
            raise PinResolutionError(
                f"report input pin {axis!r} carries no complete value"
            )
        loaded[axis] = {
            "revision": pin.revision,
            "digest": digest,
            "record": dict(record),
            "value": _jsonable(dict(value), f"inputs.{axis}.value"),
        }
    return loaded


def _envelope_timepoint(envelope: Any) -> Any | None:
    occurred = getattr(envelope, "occurred_at", None)
    if occurred is None:
        return None
    as_missing = getattr(evidence_journal, "Missing", None)
    if as_missing is not None and isinstance(occurred, as_missing):
        return None
    if _is_missing(occurred):
        return None
    to_dict = getattr(occurred, "to_dict", None)
    if callable(to_dict):
        try:
            data = to_dict()
        except (TypeError, ValueError):
            return None
    elif isinstance(occurred, Mapping):
        data = dict(occurred)
    else:
        return None
    if not _is_timepoint_dict(data):
        return None
    return data


def _find_envelope(envelopes: Sequence[Any], ref: Mapping[str, Any]) -> Any | None:
    for envelope in envelopes:
        if getattr(envelope, "journal_id", None) != ref.get("journal_id"):
            continue
        if getattr(envelope, "journal_sequence", None) != ref.get("sequence"):
            continue
        if getattr(envelope, "event_id", None) != ref.get("event_id"):
            continue
        if getattr(envelope, "event_hash", None) != ref.get("event_hash"):
            continue
        return envelope
    return None


def _same_clock_relation(
    fact_occurred: Any, boundary_point: Any
) -> str | None:
    """Order two TimePoints on one registered clock/boot/origin.

    Never consults receipt times or UTC annotations.
    """
    if fact_occurred is None or boundary_point is None:
        return None
    if not isinstance(fact_occurred, Mapping) or not isinstance(
        boundary_point, Mapping
    ):
        return None
    for key in ("clock_id", "boot_id", "origin"):
        if fact_occurred.get(key) != boundary_point.get(key):
            return None
    fact_offset = fact_occurred.get("monotonic_offset_ms")
    boundary_offset = boundary_point.get("monotonic_offset_ms")
    if not isinstance(fact_offset, (int, float)) or not isinstance(
        boundary_offset, (int, float)
    ):
        return None
    if isinstance(fact_offset, bool) or isinstance(boundary_offset, bool):
        return None
    if fact_offset < boundary_offset:
        return "before"
    if fact_offset > boundary_offset:
        return "after"
    return "at"


def _causal_relation(
    envelopes: Sequence[Any],
    fact_refs: Sequence[Mapping[str, Any]],
    boundary_ref: Mapping[str, Any],
) -> tuple[str, list[dict[str, Any]]] | None:
    """Order via journal causal links, if any are present.

    The current journal sets ``causal_refs`` empty at admission; this
    check therefore stays unknown unless a future writer records an
    explicit causal edge.
    """
    boundary_key = (
        str(boundary_ref.get("journal_id")),
        boundary_ref.get("sequence"),
        str(boundary_ref.get("event_id")),
    )
    fact_keys = {
        (
            str(ref.get("journal_id")),
            ref.get("sequence"),
            str(ref.get("event_id")),
        )
        for ref in fact_refs
    }
    for envelope in envelopes:
        causal = getattr(envelope, "causal_refs", ()) or ()
        keys: set[tuple[str, Any, str]] = set()
        for ref in causal:
            to_dict = getattr(ref, "to_dict", None)
            data = to_dict() if callable(to_dict) else ref
            if not isinstance(data, Mapping):
                continue
            keys.add(
                (
                    str(data.get("journal_id")),
                    data.get("sequence"),
                    str(data.get("event_id")),
                )
            )
        envelope_key = (
            str(getattr(envelope, "journal_id", "")),
            getattr(envelope, "journal_sequence", None),
            str(getattr(envelope, "event_id", "")),
        )
        if envelope_key in fact_keys and boundary_key in keys:
            return ("after", [dict(boundary_ref)])
        if envelope_key == boundary_key and (keys & fact_keys):
            return ("before", [dict(boundary_ref)])
    return None


def _origin_sequence_relation(
    envelopes: Sequence[Any], fact_id: str, boundary_ref: Mapping[str, Any]
) -> tuple[str, list[dict[str, Any]]] | None:
    """Order via documented origin-sequence evidence, if any.

    Opaque ``origin_revision`` strings are never compared lexically.
    Only an explicit journaled origin-sequence statement establishes
    this basis.
    """
    boundary_pointer = str(boundary_ref.get("pointer", ""))
    boundary_seq = boundary_ref.get("sequence")
    for envelope in envelopes:
        try:
            payload = envelope.payload
        except (TypeError, ValueError, AttributeError):
            continue
        if not isinstance(payload, Mapping):
            continue
        data = payload.get("data")
        if not isinstance(data, Mapping):
            continue
        statement = data.get("origin_sequence")
        if not isinstance(statement, Mapping):
            continue
        if statement.get("fact_id") != fact_id:
            continue
        if statement.get("boundary_sequence") != boundary_seq:
            continue
        if (
            "boundary_pointer" in statement
            and statement.get("boundary_pointer") != boundary_pointer
        ):
            continue
        relation = statement.get("relation")
        if relation not in ("before", "at", "after"):
            continue
        ref = {
            "journal_id": getattr(envelope, "journal_id", ""),
            "sequence": getattr(envelope, "journal_sequence", 0),
            "event_id": getattr(envelope, "event_id", ""),
            "event_hash": getattr(envelope, "event_hash", ""),
            "pointer": "",
        }
        try:
            evidence = _coerce_evidence_ref(ref, "origin_sequence evidence")
        except InvalidReportError:
            continue
        return (str(relation), [evidence, dict(boundary_ref)])
    return None


def _derive_temporal_relation(
    assertion: Mapping[str, Any] | None,
    fact: Mapping[str, Any] | None,
    fact_evidence: Sequence[Mapping[str, Any]],
    envelopes: Sequence[Any],
) -> TemporalRelation:
    if assertion is None:
        return TemporalRelation(
            relation="not_applicable", basis="not_applicable", evidence_refs=()
        )
    span = assertion.get("span")
    if span == "entire_attempt":
        return TemporalRelation(
            relation="not_applicable", basis="not_applicable", evidence_refs=()
        )
    if fact is None:
        return TemporalRelation(
            relation="unknown", basis="not_established", evidence_refs=()
        )
    boundary_ref = assertion.get("boundary_ref")
    if not isinstance(boundary_ref, Mapping) or _is_missing(boundary_ref):
        return TemporalRelation(
            relation="unknown", basis="not_established", evidence_refs=()
        )
    try:
        boundary = _coerce_evidence_ref(boundary_ref, "assertion.boundary_ref")
    except InvalidReportError:
        return TemporalRelation(
            relation="unknown", basis="not_established", evidence_refs=()
        )
    fact_id = fact.get("fact_id")
    if isinstance(fact_id, str) and fact_id:
        documented = _origin_sequence_relation(envelopes, fact_id, boundary)
        if documented is not None:
            relation, refs = documented
            return TemporalRelation(
                relation=relation,
                basis="origin_sequence",
                evidence_refs=tuple(refs),
            )
    causal = _causal_relation(envelopes, fact_evidence, boundary)
    if causal is not None:
        relation, refs = causal
        return TemporalRelation(
            relation=relation,
            basis="causal_evidence",
            evidence_refs=tuple(refs),
        )
    fact_occurred = None
    raw_occurred = fact.get("occurred_at")
    if _is_timepoint_dict(raw_occurred):
        fact_occurred = _jsonable(raw_occurred, "fact.occurred_at")
    boundary_point = None
    envelope = _find_envelope(envelopes, boundary)
    if envelope is not None:
        boundary_point = _envelope_timepoint(envelope)
    ordered = _same_clock_relation(fact_occurred, boundary_point)
    if ordered is not None:
        refs: list[dict[str, Any]] = [dict(boundary)]
        for ref in fact_evidence[:1]:
            try:
                candidate = _coerce_evidence_ref(ref, "fact.evidence_refs")
            except InvalidReportError:
                continue
            if candidate != boundary:
                refs.append(candidate)
        return TemporalRelation(
            relation=ordered, basis="same_clock", evidence_refs=tuple(refs)
        )
    return TemporalRelation(
        relation="unknown", basis="not_established", evidence_refs=()
    )


def _claim_ref_for(claim: Mapping[str, Any]) -> dict[str, Any]:
    refs = claim.get("evidence_refs")
    if (
        not isinstance(refs, Sequence)
        or isinstance(refs, (str, bytes))
        or not refs
    ):
        raise InvalidReportError("execution claim requires evidence_refs")
    return _coerce_evidence_ref(refs[0], "claim.evidence_refs[0]")


def _fact_evidence_for(fact: Mapping[str, Any]) -> list[dict[str, Any]]:
    refs = fact.get("evidence_refs")
    if (
        not isinstance(refs, Sequence)
        or isinstance(refs, (str, bytes))
        or not refs
    ):
        raise InvalidReportError("origin fact requires evidence_refs")
    return [
        _coerce_evidence_ref(item, f"fact.evidence_refs[{i}]")
        for i, item in enumerate(refs)
    ]


def _validate_assertion(
    assertion: Any, claim_id: str, index: int
) -> dict[str, Any]:
    label = f"claim {claim_id!r} application_assertions[{index}]"
    if not isinstance(assertion, Mapping):
        raise InvalidReportError(f"{label} must be a mapping")
    _require_exact_keys(
        assertion,
        frozenset(
            {
                "assertion_id",
                "value",
                "span",
                "boundary_ref",
                "evidence_refs",
            }
        ),
        label,
    )
    assertion_id = _require_identifier(
        assertion.get("assertion_id"), f"{label}.assertion_id"
    )
    value = assertion.get("value")
    if value not in _ASSERTION_VALUES:
        raise InvalidReportError(f"{label}.value is invalid")
    span = assertion.get("span")
    if span not in _ASSERTION_SPANS:
        raise InvalidReportError(f"{label}.span is invalid")
    boundary_ref = assertion.get("boundary_ref")
    if span == "entire_attempt":
        if _missing_reason(boundary_ref) != "not_applicable":
            raise InvalidReportError(
                f"{label}.boundary_ref must be Missing(not_applicable)"
                " for entire_attempt"
            )
        boundary_norm = _jsonable(boundary_ref, f"{label}.boundary_ref")
    else:
        boundary_norm = _coerce_evidence_ref(
            boundary_ref, f"{label}.boundary_ref"
        )
    evidence_refs = _coerce_evidence_ref_list(
        assertion.get("evidence_refs"),
        f"{label}.evidence_refs",
        allow_empty=False,
    )
    return {
        "assertion_id": assertion_id,
        "value": value,
        "span": span,
        "boundary_ref": boundary_norm,
        "evidence_refs": evidence_refs,
    }


def _compare_narrow_claim(
    claim: Mapping[str, Any], envelopes: Sequence[Any]
) -> ClaimComparison:
    claim_id = _require_identifier(claim.get("claim_id"), "claim.claim_id")
    scope = claim.get("scope")
    state = claim.get("state")
    claim_ref = _claim_ref_for(claim)
    if scope == "unknown":
        rationale = (
            "Claim semantics are unknown; the mapping cites no task-execution"
            " statement that can be compared to origin facts."
        )
        return ClaimComparison(
            claim_id=claim_id,
            assertion_id=_missing_dict("not_applicable"),
            claim_ref=claim_ref,
            fact_ids=(),
            fact_refs=(),
            result="indeterminate",
            temporal_relation=TemporalRelation(
                relation="not_applicable",
                basis="not_applicable",
                evidence_refs=(),
            ),
            rationale=rationale,
            limitations=(
                "Unknown claim semantics remain incomplete; no success is inferred.",
            ),
        )
    if _is_missing(state):
        state_text = "narrow execution report"
    else:
        state_text = f"state {state!r}"
    rationale = (
        f"Claim {claim_id!r} is a narrow {scope} execution claim ({state_text})"
        " with no application assertion; there is no application proposition"
        " to compare against origin facts."
    )
    limitations = [
        "A narrow execution completion is not comparable to application"
        " commitment; reconciled never means successful application."
    ]
    if state == "stopped":
        limitations.append(
            "Stopped alone asserts no entire-attempt no-commit proposition."
        )
    return ClaimComparison(
        claim_id=claim_id,
        assertion_id=_missing_dict("not_applicable"),
        claim_ref=claim_ref,
        fact_ids=(),
        fact_refs=(),
        result="not_comparable",
        temporal_relation=TemporalRelation(
            relation="not_applicable",
            basis="not_applicable",
            evidence_refs=(),
        ),
        rationale=rationale,
        limitations=tuple(limitations),
    )


def _compare_assertion(
    claim: Mapping[str, Any],
    assertion: dict[str, Any],
    facts: Sequence[Mapping[str, Any]],
    envelopes: Sequence[Any],
) -> ClaimComparison:
    claim_id = _require_identifier(claim.get("claim_id"), "claim.claim_id")
    claim_ref = _claim_ref_for(claim)
    value = assertion["value"]
    span = assertion["span"]
    assertion_id = assertion["assertion_id"]

    def _collect(
        selected: Sequence[Mapping[str, Any]],
    ) -> tuple[list[str], list[dict[str, Any]]]:
        ids: list[str] = []
        refs: list[dict[str, Any]] = []
        for fact in selected:
            fid = _require_identifier(fact.get("fact_id"), "fact.fact_id")
            if fid not in ids:
                ids.append(fid)
            for ref in _fact_evidence_for(fact):
                if ref not in refs:
                    refs.append(ref)
        return ids, refs

    if not facts:
        temporal = _derive_temporal_relation(
            assertion=assertion, fact=None, fact_evidence=[], envelopes=envelopes
        )
        if value == "outcome_unknown":
            rationale = (
                f"Assertion {assertion_id!r} records outcome_unknown ({span});"
                " with no observed origin facts the close-time uncertainty is"
                " preserved, not resolved."
            )
            limitations = (
                "No origin facts are observed; the unknown outcome stays"
                " incomplete rather than becoming a fabricated comparison.",
            )
        elif value == "committed":
            rationale = (
                f"Assertion {assertion_id!r} claims commitment ({span}); no"
                " origin facts are observed to confirm or contradict it."
            )
            limitations = (
                "Execution completion alone never establishes application"
                " commitment; origin evidence is still missing.",
            )
        else:
            rationale = (
                f"Assertion {assertion_id!r} claims no commitment ({span}); no"
                " origin facts are observed to confirm the absence."
            )
            limitations = (
                "An unobserved origin is not a negative fact; the absence claim"
                " stays incomplete without origin evidence.",
            )
        return ClaimComparison(
            claim_id=claim_id,
            assertion_id=assertion_id,
            claim_ref=claim_ref,
            fact_ids=(),
            fact_refs=(),
            result="indeterminate",
            temporal_relation=temporal,
            rationale=rationale,
            limitations=limitations,
        )

    if value == "outcome_unknown":
        seen: set[str] = set()
        fact_ids: list[str] = []
        fact_refs: list[dict[str, Any]] = []
        first_fact: Mapping[str, Any] = facts[0]
        first_evidence: list[dict[str, Any]] = []
        for fact in facts:
            fid = _require_identifier(fact.get("fact_id"), "fact.fact_id")
            if fid in seen:
                continue
            seen.add(fid)
            fact_ids.append(fid)
            evidence = _fact_evidence_for(fact)
            if not first_evidence:
                first_fact = fact
                first_evidence = evidence
            for ref in evidence:
                if ref not in fact_refs:
                    fact_refs.append(ref)
        temporal = _derive_temporal_relation(
            assertion=assertion,
            fact=first_fact,
            fact_evidence=first_evidence,
            envelopes=envelopes,
        )
        states = sorted({str(f.get("state")) for f in facts})
        rationale = (
            f"Assertion {assertion_id!r} records outcome_unknown ({span});"
            f" observed origin facts ({', '.join(states)}) are compatible with"
            " that uncertainty."
        )
        limitations_list = [
            "Close-time outcome unknown is preserved; the later observation is"
            " compatible, not contradictory, and no success is inferred from"
            " compatibility alone."
        ]
        if temporal.relation == "unknown":
            limitations_list.append(
                "No same-clock, causal, or documented origin-sequence evidence"
                " orders the fact to the boundary; receipt order and UTC"
                " annotations are insufficient."
            )
        return ClaimComparison(
            claim_id=claim_id,
            assertion_id=assertion_id,
            claim_ref=claim_ref,
            fact_ids=tuple(fact_ids),
            fact_refs=tuple(fact_refs),
            result="consistent",
            temporal_relation=temporal,
            rationale=rationale,
            limitations=tuple(limitations_list),
        )

    if value == "committed":
        committed = [f for f in facts if f.get("state") == "committed"]
        if committed:
            fact_ids, fact_refs = _collect(committed)
            first = committed[0]
            temporal = _derive_temporal_relation(
                assertion=assertion,
                fact=first,
                fact_evidence=_fact_evidence_for(first),
                envelopes=envelopes,
            )
            rationale = (
                f"Assertion {assertion_id!r} claims commitment ({span});"
                " verified origin facts record commitment at a compatible scope."
            )
            limitations_list = []
            if temporal.relation == "unknown" and span != "entire_attempt":
                limitations_list.append(
                    "No same-clock, causal, or documented origin-sequence evidence"
                    " orders the fact to the boundary; receipt order and UTC"
                    " annotations are insufficient."
                )
            return ClaimComparison(
                claim_id=claim_id,
                assertion_id=assertion_id,
                claim_ref=claim_ref,
                fact_ids=tuple(fact_ids),
                fact_refs=tuple(fact_refs),
                result="consistent",
                temporal_relation=temporal,
                rationale=rationale,
                limitations=tuple(limitations_list),
            )
        final_absences = [
            f
            for f in facts
            if f.get("state") == "not_committed"
            and f.get("coverage") == "final_for_attempt"
        ]
        if final_absences:
            fact_ids, fact_refs = _collect(final_absences)
            first = final_absences[0]
            temporal = _derive_temporal_relation(
                assertion=assertion,
                fact=first,
                fact_evidence=_fact_evidence_for(first),
                envelopes=envelopes,
            )
            rationale = (
                f"Assertion {assertion_id!r} claims commitment ({span});"
                " verified final origin facts record no commitment for the attempt."
            )
            return ClaimComparison(
                claim_id=claim_id,
                assertion_id=assertion_id,
                claim_ref=claim_ref,
                fact_ids=tuple(fact_ids),
                fact_refs=tuple(fact_refs),
                result="contradicted",
                temporal_relation=temporal,
                rationale=rationale,
                limitations=(
                    "Both the claim and the final origin facts are preserved;"
                    " neither source is rewritten.",
                ),
            )
        first = facts[0]
        temporal = _derive_temporal_relation(
            assertion=assertion,
            fact=first,
            fact_evidence=_fact_evidence_for(first),
            envelopes=envelopes,
        )
        rationale = (
            f"Assertion {assertion_id!r} claims commitment ({span}); only as-of"
            " absences are observed, which cannot prove or disprove eventual"
            " commitment."
        )
        return ClaimComparison(
            claim_id=claim_id,
            assertion_id=assertion_id,
            claim_ref=claim_ref,
            fact_ids=(),
            fact_refs=(),
            result="indeterminate",
            temporal_relation=temporal,
            rationale=rationale,
            limitations=(
                "As-of absence is not final absence; the commitment claim stays"
                " incomplete without a final origin fact.",
            ),
        )

    # value == not_committed
    if span == "entire_attempt":
        committed = [f for f in facts if f.get("state") == "committed"]
        if committed:
            fact_ids, fact_refs = _collect(committed)
            first = committed[0]
            temporal = _derive_temporal_relation(
                assertion=assertion,
                fact=first,
                fact_evidence=_fact_evidence_for(first),
                envelopes=envelopes,
            )
            rationale = (
                f"Assertion {assertion_id!r} claims no commitment for the entire"
                " attempt; verified origin facts record commitment for the same"
                " attempt."
            )
            return ClaimComparison(
                claim_id=claim_id,
                assertion_id=assertion_id,
                claim_ref=claim_ref,
                fact_ids=tuple(fact_ids),
                fact_refs=tuple(fact_refs),
                result="contradicted",
                temporal_relation=temporal,
                rationale=rationale,
                limitations=(
                    "Both the explicit no-commit assertion and the verified"
                    " commitment are preserved; the claim is not rewritten to"
                    " unknown and the commitment is not erased.",
                ),
            )
        final_absences = [
            f
            for f in facts
            if f.get("state") == "not_committed"
            and f.get("coverage") == "final_for_attempt"
        ]
        if final_absences:
            fact_ids, fact_refs = _collect(final_absences)
            first = final_absences[0]
            temporal = _derive_temporal_relation(
                assertion=assertion,
                fact=first,
                fact_evidence=_fact_evidence_for(first),
                envelopes=envelopes,
            )
            rationale = (
                f"Assertion {assertion_id!r} claims no commitment for the entire"
                " attempt; verified final origin facts record no commitment."
            )
            return ClaimComparison(
                claim_id=claim_id,
                assertion_id=assertion_id,
                claim_ref=claim_ref,
                fact_ids=tuple(fact_ids),
                fact_refs=tuple(fact_refs),
                result="consistent",
                temporal_relation=temporal,
                rationale=rationale,
                limitations=(),
            )
        first = facts[0]
        temporal = _derive_temporal_relation(
            assertion=assertion,
            fact=first,
            fact_evidence=_fact_evidence_for(first),
            envelopes=envelopes,
        )
        rationale = (
            f"Assertion {assertion_id!r} claims no commitment for the entire"
            " attempt; only as-of absences are observed, which cannot prove"
            " final absence."
        )
        return ClaimComparison(
            claim_id=claim_id,
            assertion_id=assertion_id,
            claim_ref=claim_ref,
            fact_ids=(),
            fact_refs=(),
            result="indeterminate",
            temporal_relation=temporal,
            rationale=rationale,
            limitations=(
                "As-of absence is not final absence; the entire-attempt absence"
                " claim stays incomplete without a final fact.",
            ),
        )

    # Bounded not_committed (at_boundary / after_boundary)
    matching_absences: list[Mapping[str, Any]] = []
    for f in facts:
        if f.get("state") != "not_committed":
            continue
        if span == "at_boundary" and f.get("coverage") == "at_boundary":
            matching_absences.append(f)
        elif span == "after_boundary":
            matching_absences.append(f)
    committed = [f for f in facts if f.get("state") == "committed"]
    if committed:
        for fact in committed:
            evidence = _fact_evidence_for(fact)
            temporal = _derive_temporal_relation(
                assertion=assertion,
                fact=fact,
                fact_evidence=evidence,
                envelopes=envelopes,
            )
            inside = (span == "at_boundary" and temporal.relation in ("at", "before")) or (
                span == "after_boundary" and temporal.relation in ("at", "after")
            )
            if temporal.relation not in ("before", "at", "after"):
                continue
            if not inside:
                continue
            rationale = (
                f"Assertion {assertion_id!r} claims no commitment {span.replace('_', ' ')};"
                f" a verified origin fact records commitment {temporal.relation}"
                f" the boundary ({temporal.basis})."
            )
            fid = _require_identifier(fact.get("fact_id"), "fact.fact_id")
            return ClaimComparison(
                claim_id=claim_id,
                assertion_id=assertion_id,
                claim_ref=claim_ref,
                fact_ids=(fid,),
                fact_refs=tuple(evidence),
                result="contradicted",
                temporal_relation=temporal,
                rationale=rationale,
                limitations=(
                    "Both the bounded absence assertion and the verified"
                    " commitment are preserved; neither source is rewritten.",
                ),
            )
        first = committed[0]
        evidence = _fact_evidence_for(first)
        temporal = _derive_temporal_relation(
            assertion=assertion,
            fact=first,
            fact_evidence=evidence,
            envelopes=envelopes,
        )
        rationale = (
            f"Assertion {assertion_id!r} claims no commitment {span.replace('_', ' ')};"
            " a commitment is observed but no same-clock, causal, or documented"
            " origin-sequence evidence places it inside the asserted span."
        )
        return ClaimComparison(
            claim_id=claim_id,
            assertion_id=assertion_id,
            claim_ref=claim_ref,
            fact_ids=(),
            fact_refs=(),
            result="indeterminate",
            temporal_relation=temporal,
            rationale=rationale,
            limitations=(
                "Receipt arrival order and UTC annotations cannot establish"
                " cross-clock occurrence order; the bounded comparison requires"
                " an actual temporal relation.",
            ),
        )
    if matching_absences:
        fact_ids, fact_refs = _collect(matching_absences)
        first = matching_absences[0]
        temporal = _derive_temporal_relation(
            assertion=assertion,
            fact=first,
            fact_evidence=_fact_evidence_for(first),
            envelopes=envelopes,
        )
        rationale = (
            f"Assertion {assertion_id!r} claims no commitment {span.replace('_', ' ')};"
            " origin facts record absence at a compatible scope."
        )
        return ClaimComparison(
            claim_id=claim_id,
            assertion_id=assertion_id,
            claim_ref=claim_ref,
            fact_ids=tuple(fact_ids),
            fact_refs=tuple(fact_refs),
            result="consistent",
            temporal_relation=temporal,
            rationale=rationale,
            limitations=(),
        )
    first = facts[0]
    temporal = _derive_temporal_relation(
        assertion=assertion,
        fact=first,
        fact_evidence=_fact_evidence_for(first),
        envelopes=envelopes,
    )
    rationale = (
        f"Assertion {assertion_id!r} claims no commitment {span.replace('_', ' ')};"
        " observed facts do not cover that span."
    )
    return ClaimComparison(
        claim_id=claim_id,
        assertion_id=assertion_id,
        claim_ref=claim_ref,
        fact_ids=(),
        fact_refs=(),
        result="indeterminate",
        temporal_relation=temporal,
        rationale=rationale,
        limitations=(
            "Scope mismatch leaves the bounded absence claim unresolved; no"
            " success or contradiction is inferred.",
        ),
    )


def _detect_issues(
    claims: Sequence[Mapping[str, Any]],
    facts: Sequence[Mapping[str, Any]],
    comparisons: Sequence[ClaimComparison],
) -> list[ReconciliationIssue]:
    issues: list[ReconciliationIssue] = []
    anchor: dict[str, Any] | None = None
    for comparison in comparisons:
        anchor = dict(comparison.claim_ref)
        break
    if anchor is None:
        for claim in claims:
            try:
                anchor = _claim_ref_for(claim)
            except InvalidReportError:
                continue
            break
    if anchor is None:
        for fact in facts:
            try:
                anchor = _fact_evidence_for(fact)[0]
            except (InvalidReportError, IndexError):
                continue
            break
    if anchor is None:
        return issues
    committed = [f for f in facts if f.get("state") == "committed"]
    if len(committed) > 1:
        ids = sorted(str(f.get("fact_id")) for f in committed)
        issues.append(
            ReconciliationIssue(
                kind="multiple_origin_commitments",
                detail=(
                    "Multiple verified origin commitments are preserved"
                    f" ({', '.join(ids)}); they are reported, not deduplicated"
                    " or deleted."
                ),
                evidence_refs=(dict(anchor),),
            )
        )
    final_absences = [
        f
        for f in facts
        if f.get("state") == "not_committed"
        and f.get("coverage") == "final_for_attempt"
    ]
    if committed and final_absences:
        issues.append(
            ReconciliationIssue(
                kind="origin_fact_conflict",
                detail=(
                    "Verified origin facts conflict: commitment and final absence"
                    " are both preserved for explicit resolution."
                ),
                evidence_refs=(dict(anchor),),
            )
        )
    assertion_values: set[str] = set()
    for claim in claims:
        assertions = claim.get("application_assertions") or []
        if not isinstance(assertions, Sequence) or isinstance(
            assertions, (str, bytes)
        ):
            continue
        for assertion in assertions:
            if not isinstance(assertion, Mapping):
                continue
            value = assertion.get("value")
            if not isinstance(value, str):
                continue
            assertion_values.add(value)
    if "committed" in assertion_values and "not_committed" in assertion_values:
        issues.append(
            ReconciliationIssue(
                kind="subject_claim_conflict",
                detail=(
                    "Subject claims conflict: commitment and no-commitment"
                    " assertions are both preserved for explicit resolution."
                ),
                evidence_refs=(dict(anchor),),
            )
        )
    if any(c.result == "not_comparable" for c in comparisons):
        issues.append(
            ReconciliationIssue(
                kind="incomparable_scope",
                detail=(
                    "One or more narrow execution claims carry no application"
                    " proposition and are not comparable to origin facts."
                ),
                evidence_refs=(dict(anchor),),
            )
        )
    if any(c.result == "indeterminate" for c in comparisons):
        issues.append(
            ReconciliationIssue(
                kind="insufficient_evidence",
                detail=(
                    "One or more comparisons lack the origin or temporal evidence"
                    " needed for a proved finding."
                ),
                evidence_refs=(dict(anchor),),
            )
        )
    for claim in claims:
        assertions = claim.get("application_assertions") or []
        if not isinstance(assertions, Sequence) or isinstance(
            assertions, (str, bytes)
        ):
            continue
        for assertion in assertions:
            if not isinstance(assertion, Mapping):
                continue
            span = assertion.get("span")
            boundary = assertion.get("boundary_ref")
            if span == "entire_attempt":
                if _missing_reason(boundary) != "not_applicable":
                    issues.append(
                        ReconciliationIssue(
                            kind="mapping_error",
                            detail=(
                                "An entire-attempt assertion carries a boundary"
                                " reference; entire-attempt scope takes no boundary."
                            ),
                            evidence_refs=(dict(anchor),),
                        )
                    )
                continue
            if span in ("at_boundary", "after_boundary"):
                if not (
                    isinstance(boundary, Mapping)
                    and not _is_missing(boundary)
                ):
                    issues.append(
                        ReconciliationIssue(
                            kind="mapping_error",
                            detail=(
                                "A bounded assertion carries no boundary reference;"
                                " the asserted span cannot be placed."
                            ),
                            evidence_refs=(dict(anchor),),
                        )
                    )
    seen: set[tuple[str, str]] = set()
    unique: list[ReconciliationIssue] = []
    for issue in issues:
        key = (issue.kind, issue.detail)
        if key not in seen:
            seen.add(key)
            unique.append(issue)
    return unique


def derive_report(
    channel_id: str,
    commission: Any,
    inputs: ReportInputPins,
    evaluator: VersionPin,
    prefix: JournalPrefix,
) -> ReportValue:
    """Derive the immutable report for one pinned input set.

    Reads only the pinned execution/application publications and the
    cited journal prefix. Writes nothing. Never uses live network
    lookups, mutable current rows, receipt order, UTC annotations, or
    lexical origin-revision order as comparison evidence.
    """
    _require_identifier(channel_id, "channel_id")
    pins = _coerce_pins(inputs)
    evaluator_pin = _coerce_evaluator(evaluator)
    prefix_obj = _coerce_prefix(prefix)
    _strict_gate(
        {
            "inputs": pins.to_dict(),
            "evaluator": evaluator_pin.to_dict(),
            "prefix": {
                "journal_id": prefix_obj.journal_id,
                "last_sequence": prefix_obj.last_sequence,
                "head_hash": prefix_obj.head_hash,
            },
        },
        "derive_report inputs",
    )
    _, commission_dict = _load_commission(channel_id, commission)
    entity = _entity_for_commission(commission_dict)
    try:
        envelopes = evidence_journal.read_prefix(channel_id, prefix_obj)
    except Exception as exc:
        raise InvalidReportError(
            f"report evidence prefix does not verify: {exc}"
        ) from exc
    envelopes = tuple(envelopes)
    loaded = _load_pinned_values(channel_id, entity, pins)
    execution_value = loaded["execution"]["value"] if loaded["execution"] else None
    application_value = (
        loaded["application"]["value"] if loaded["application"] else None
    )
    claims: list[dict[str, Any]] = []
    if execution_value is not None:
        raw_claims = execution_value.get("claims")
        if not isinstance(raw_claims, Sequence) or isinstance(
            raw_claims, (str, bytes)
        ):
            raise InvalidReportError(
                "pinned execution value carries no claims array"
            )
        for index, raw in enumerate(raw_claims):
            if not isinstance(raw, Mapping):
                raise InvalidReportError(
                    f"pinned execution claims[{index}] must be a mapping"
                )
            claims.append(
                _jsonable(dict(raw), f"execution.claims[{index}]")
            )
    facts: list[dict[str, Any]] = []
    if application_value is not None:
        raw_facts = application_value.get("facts")
        if not isinstance(raw_facts, Sequence) or isinstance(
            raw_facts, (str, bytes)
        ):
            raise InvalidReportError(
                "pinned application value carries no facts array"
            )
        for index, raw in enumerate(raw_facts):
            if not isinstance(raw, Mapping):
                raise InvalidReportError(
                    f"pinned application facts[{index}] must be a mapping"
                )
            facts.append(
                _jsonable(dict(raw), f"application.facts[{index}]")
            )
    execution_mode = ""
    execution_desc = commission_dict.get("execution")
    if isinstance(execution_desc, Mapping):
        execution_mode = str(execution_desc.get("mode", ""))
    diagnostic = _missing_dict("not_observed")
    if execution_mode == "manual" or not claims:
        if execution_mode == "manual":
            reason_detail = (
                "Manual attempt: no automation subject claims are applicable;"
                " no subject comparison is fabricated."
            )
        else:
            reason_detail = (
                "No applicable subject claims are pinned; no comparison is"
                " fabricated from origin facts alone."
            )
        value = ReportValue(
            state=_missing_dict("not_applicable"),
            coverage="not_applicable",
            inputs=pins,
            evaluator=evaluator_pin,
            comparisons=(),
            issues=(),
            limitations=(reason_detail,),
            diagnostic=(
                _missing_dict("not_applicable")
                if execution_mode == "manual"
                else diagnostic
            ),
        )
        _strict_gate(value.to_dict(), "ReportValue")
        return value
    comparisons: list[ClaimComparison] = []
    seen_claims: set[str] = set()
    for claim in claims:
        claim_id = _require_identifier(claim.get("claim_id"), "claim.claim_id")
        if claim_id in seen_claims:
            raise InvalidReportError(
                f"duplicate claim_id {claim_id!r} in pinned claims"
            )
        seen_claims.add(claim_id)
        scope = claim.get("scope")
        if scope not in (
            "primitive",
            "application_postcondition",
            "execution_lifecycle",
            "unknown",
        ):
            raise InvalidReportError(f"claim {claim_id!r} scope is invalid")
        assertions = claim.get("application_assertions", [])
        if assertions is None:
            assertions = []
        if not isinstance(assertions, Sequence) or isinstance(
            assertions, (str, bytes)
        ):
            raise InvalidReportError(
                f"claim {claim_id!r} application_assertions must be a sequence"
            )
        if not assertions:
            comparisons.append(_compare_narrow_claim(claim, envelopes))
            continue
        if scope in ("primitive", "unknown"):
            raise InvalidReportError(
                f"claim {claim_id!r} scope {scope!r} admits no application assertions"
            )
        seen_assertions: set[str] = set()
        for index, raw_assertion in enumerate(assertions):
            assertion = _validate_assertion(raw_assertion, claim_id, index)
            if assertion["assertion_id"] in seen_assertions:
                raise InvalidReportError(
                    f"duplicate assertion_id {assertion['assertion_id']!r}"
                    f" in claim {claim_id!r}"
                )
            seen_assertions.add(assertion["assertion_id"])
            comparisons.append(
                _compare_assertion(
                    claim=claim,
                    assertion=assertion,
                    facts=facts,
                    envelopes=envelopes,
                )
            )
    results = [c.result for c in comparisons]
    issues = _detect_issues(claims=claims, facts=facts, comparisons=comparisons)
    limitations: list[str] = []
    if "contradicted" in results:
        state: Any = "contradicted"
        coverage = "complete" if "indeterminate" not in results else "incomplete"
        limitations.append(
            "A proved contradiction is reported with exact claim and fact"
            " references; both source histories are preserved."
        )
        if coverage == "incomplete":
            limitations.append(
                "Other comparisons remain incomplete; the contradiction stands"
                " while uncertainty elsewhere is preserved."
            )
    elif "indeterminate" in results:
        state = _missing_dict("not_observed")
        coverage = "incomplete"
        limitations.append(
            "Unresolved comparisons stay incomplete with reasoned missingness;"
            " no success or contradiction is inferred."
        )
    else:
        state = "reconciled"
        coverage = "complete"
        limitations.append(
            "Reconciled records that every applicable comparison is accounted"
            " for; it never asserts application success."
        )
    if any(c.result == "not_comparable" for c in comparisons):
        limitations.append(
            "Narrow execution findings are not comparable to application"
            " commitment and prove no application outcome."
        )
    value = ReportValue(
        state=state,
        coverage=coverage,
        inputs=pins,
        evaluator=evaluator_pin,
        comparisons=tuple(comparisons),
        issues=tuple(issues),
        limitations=tuple(limitations),
        diagnostic=diagnostic,
    )
    _strict_gate(value.to_dict(), "ReportValue")
    return value


def _lookup_registration(entity: Mapping[str, Any]) -> Any:
    if entity.get("entity_type") == "application_attempt":
        entity_id = f"attempt.{entity['attempt_id']}.{entity['kind']}"
    else:
        entity_id = ""
    if not entity_id:
        raise InvalidReportError(
            "report publication needs an application attempt"
        )
    registrations = getattr(owner_revisions, "_REGISTRATIONS", None)
    entry = None
    if isinstance(registrations, Mapping):
        entry = registrations.get(entity_id)
    if entry is None:
        raise InvalidReportError(
            f"no registered entity {entity_id!r} backs this report"
        )
    record = getattr(entry, "record", None)
    if not isinstance(record, Mapping):
        raise InvalidReportError("the registered entity record is unreadable")
    try:
        return owner_revisions.EntityRegistration.from_dict(dict(record))
    except (TypeError, ValueError) as exc:
        raise InvalidReportError(
            f"the registered entity record is invalid: {exc}"
        ) from exc


def _collect_report_evidence(
    value: ReportValue, registration: Any
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    collected: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str, str, str]] = set()

    def _add(ref: Mapping[str, Any]) -> None:
        try:
            norm = _coerce_evidence_ref(ref, "report.evidence_refs")
        except InvalidReportError:
            return
        key = (
            str(norm["journal_id"]),
            int(norm["sequence"]),
            str(norm["event_id"]),
            str(norm["event_hash"]),
            str(norm["pointer"]),
        )
        if key not in seen:
            seen.add(key)
            collected.append(norm)

    for comparison in value.comparisons:
        _add(comparison.claim_ref)
        for ref in comparison.fact_refs:
            _add(ref)
        for ref in comparison.temporal_relation.evidence_refs:
            _add(ref)
    for issue in value.issues:
        for ref in issue.evidence_refs:
            _add(ref)
    to_dict = getattr(registration, "to_dict", None)
    if callable(to_dict):
        registration_dict = to_dict()
    elif isinstance(registration, Mapping):
        registration_dict = registration
    else:
        registration_dict = {}
    prefix_raw = registration_dict.get("evidence_prefix")
    if not isinstance(prefix_raw, Mapping):
        raise InvalidReportError("registration carries no evidence_prefix")
    try:
        prefix = {
            "journal_id": _require_identifier(
                prefix_raw["journal_id"],
                "registration.evidence_prefix.journal_id",
            ),
            "last_sequence": prefix_raw["last_sequence"],
            "head_hash": _require_digest(
                prefix_raw["head_hash"],
                "registration.evidence_prefix.head_hash",
            ),
        }
        if (
            isinstance(prefix["last_sequence"], bool)
            or not isinstance(prefix["last_sequence"], int)
            or prefix["last_sequence"] < 1
        ):
            raise InvalidReportError(
                "registration.evidence_prefix.last_sequence is invalid"
            )
    except InvalidReportError:
        raise
    except (TypeError, ValueError) as exc:
        raise InvalidReportError(
            f"registration.evidence_prefix is invalid: {exc}"
        ) from exc
    if not collected:
        fallback = registration_dict.get("evidence_refs")
        if isinstance(fallback, Sequence) and not isinstance(
            fallback, (str, bytes)
        ):
            for ref in fallback:
                if isinstance(ref, Mapping):
                    _add(ref)
    if not collected:
        raise InvalidReportError(
            "a report revision requires at least one EvidenceRef"
        )
    return collected, prefix


def publish_report(
    channel_id: str,
    commission: Any,
    value: ReportValue,
    expected_revision: int,
    command_id: str,
) -> Any:
    """Publish one complete report axis revision.

    Writes only the report axis via ``owner_revisions.commit_domain``.
    Never writes dispatch, observation, execution, or application, and
    never rewrites claims or deletes facts.
    """
    _require_identifier(channel_id, "channel_id")
    _require_identifier(command_id, "command_id")
    if (
        isinstance(expected_revision, bool)
        or not isinstance(expected_revision, int)
        or expected_revision < 0
    ):
        raise InvalidReportError("expected_revision must be a nonnegative int")
    if isinstance(value, ReportValue):
        report = value
    else:
        report = ReportValue.from_dict(value)
    _strict_gate(report.to_dict(), "ReportValue")
    _, commission_dict = _load_commission(channel_id, commission)
    commission_ref = _coerce_artifact_reference(commission, "commission")
    entity = _entity_for_commission(commission_dict)
    registration = _lookup_registration(entity)
    if hasattr(registration, "to_dict"):
        registration_dict = registration.to_dict()
    else:
        registration_dict = dict(registration)
    owners = registration_dict.get("owners", {})
    report_owner = owners.get("report", {})
    execution_owner = owners.get("execution", {})
    application_owner = owners.get("application", {})
    if not isinstance(report_owner, Mapping):
        raise InvalidReportError("registration declares no report owner")
    owner_domain = report_owner.get("owner_domain")
    writer_id = report_owner.get("writer_id")
    _require_identifier(
        owner_domain, "registration.owners.report.owner_domain"
    )
    _require_identifier(writer_id, "registration.owners.report.writer_id")
    for other_label, other in (
        ("execution", execution_owner),
        ("application", application_owner),
    ):
        if not isinstance(other, Mapping):
            continue
        if _is_missing(other.get("writer_id")):
            continue
        if other.get("writer_id") == writer_id:
            raise InvalidReportError(
                f"the report writer must not hold {other_label} write authority"
            )
    registered_commission = (
        registration_dict.get("identity", {}).get("commission", {})
    )
    if isinstance(registered_commission, Mapping):
        if registered_commission.get("digest") != commission_ref.digest:
            raise InvalidReportError(
                "the commission does not identify the registered attempt"
            )
    evidence_refs, evidence_prefix = _collect_report_evidence(report, registration)
    revision_number = expected_revision + 1
    axis_record = {
        "record_type": RECORD_TYPE_AXIS,
        "schema_version": SCHEMA_VERSION,
        "attempt": {
            "attempt_id": entity["attempt_id"],
            "kind": entity["kind"],
        },
        "commission_digest": commission_ref.digest,
        "axis": "report",
        "owner_domain": owner_domain,
        "writer_id": writer_id,
        "revision": revision_number,
        "previous_revision": expected_revision,
        "evidence_prefix": evidence_prefix,
        "evidence_refs": evidence_refs,
        "value": report.to_dict(),
    }
    try:
        revision = owner_revisions.AxisRevision.from_dict(axis_record)
    except (TypeError, ValueError) as exc:
        raise InvalidReportError(
            f"cannot construct report AxisRevision: {exc}"
        ) from exc
    lease = _missing_dict("not_applicable")
    try:
        owner_revisions.commit_domain(
            channel_id, registration, revision, command_id, lease
        )
    except Exception:
        raise
    return revision


def reset_for_tests() -> None:
    """Reset module state (derivation is pure; nothing is retained)."""
    return None

"""attempt_diagnostics: deterministic attempt diagnostics (tier 7).

A diagnostic is a deterministic function of its immutable manifest, named
journal prefix, and pinned classifier bundle (``EK-DIAGNOSTIC``).  This module
implements exactly one public operation:

* :func:`derive_diagnostic` reads the named prefix through
  ``evidence_journal.read_prefix``, resolves the classifier, requirement, and
  optional fix registries pinned by the analysis request through
  ``artifact_store.resolve_artifact``, validates strict JSON and copied
  measurements through ``contract_codec``, and returns an immutable
  :class:`DiagnosticDocument`.

Boundary discipline honored here:

* The prefix must end at the ``analysis_requested`` event that pins this
  request (diagnostic id, analysis revision, classifier, requirement
  registry, fix registry).  Events beyond the prefix are never read, and no
  wall-clock time, network lookup, mutable projection, or
  ``journal_head`` call contributes to the output.
* Capability, opportunity, and result stay independent (``EK-ASSESSMENT``):
  ``satisfied``/``violated`` require a valid exposed opportunity, applicable
  controls, and supporting evidence; ``native_absence`` requires a required,
  evidenced absent native capability in the exact scope; unexposed work is
  ``not_exercised``.
* No subject capability descriptor is created for manual work, no fix
  instance is manufactured, and no ``publish_report`` (or any report
  derivation) runs while deriving: the report cites an already-journaled
  diagnostic, so derivation must not depend on the unpublished report.  The
  declared ``claim_reconciliation`` dependency therefore stays an optional
  composition edge and is never invoked here.
* Every missing value is a typed ``Missing`` envelope; bare nulls are
  rejected.  Disabled fix facilities stay ``not_enabled``, scoped subject
  limitations stay ``unsupported_by_subject``, and insufficient support stays
  ``not_observed`` (or ``observation_lost`` for lost plan bytes).

Pinned bundle formats (all strict JSON, duplicate keys and bare nulls
rejected; optional fields are omitted, never null):

Classifier bundle::

    {"bundle": "classifier", "bundle_version": "1", "rules": [
      {"requirement_id": "R1", "facet": "isolation",
       "contract_version": "1",
       "scope": {"kind": "attempt", "id": "scope:R1"},
       "capability_id": "cap_tab_isolation",
       "defect_locus": "subject",
       "signals": {"exposed": "sig:R1:exposed",
                   "blocked": "sig:R1:blocked",
                   "controls": ["sig:R1:ctl"],
                   "controls_invalid": "sig:R1:ctl_bad",
                   "satisfied": "sig:R1:sat",
                   "violated": "sig:R1:vio",
                   "absent": "sig:R1:absent",
                   "unsupported": "sig:R1:unsup",
                   "descriptor": "cap:R1"}}]}

Requirement registry::

    {"registry": "requirements", "registry_version": "1",
     "requirements": [
       {"requirement_id": "R1", "facet": "isolation",
        "contract_version": "1",
        "scope": {"kind": "attempt", "id": "scope:R1"},
        "required": true}]}

Fix registry::

    {"registry": "fix", "registry_version": "1", "rules": [
      {"rule_instance_id": "FIX-R1-001", "requirement_id": "R1",
       "target": "subject", "target_class": "laboratory_fixture",
       "approved": true, "plan_digest": "sha256:<64 hex>",
       "contraindications_absent": true}]}

Signal keys name boolean fields in prefix event ``data`` maps; a signal
fires only when the field is present and exactly ``True``.  A descriptor
key names a capability record mapping::

    {"availability": "absent", "descriptor_digest": "sha256:<64 hex>",
     "scope": {"kind": "attempt", "id": "scope:R1"}}

This module holds no mutable state: derivation is pure.
"""

from __future__ import annotations

import copy
import importlib
import importlib.util
import json
import math
import sys
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Mapping, Sequence


def _load_sibling(name: str):
    """Import a required sibling module, falling back to its source path."""
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


def _load_optional_sibling(name: str):
    """Import an optional sibling; return None when it is not implemented.

    ``claim_reconciliation`` is a composition edge, not a derivation input:
    EK-DIAGNOSTIC fixes the diagnostic as a function of manifest, prefix,
    and pinned classifier only, and the report cites an already-journaled
    diagnostic, so derivation must not invoke report derivation or publish.
    """
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
        return None
    try:
        spec = importlib.util.spec_from_file_location(name, sibling_path)
        if spec is None or spec.loader is None:
            return None
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module
    except (ModuleNotFoundError, FileNotFoundError, OSError):
        return None


contract_codec = _load_sibling("contract_codec")
artifact_store = _load_sibling("artifact_store")
evidence_journal = _load_sibling("evidence_journal")
claim_reconciliation = _load_optional_sibling("claim_reconciliation")

__all__ = [
    "SCHEMA_VERSION",
    "ANALYSIS_EVENT_KIND",
    "Missing",
    "Manifest",
    "JournalPrefix",
    "JournalEnvelope",
    "EvidenceRef",
    "TimePoint",
    "ArtifactReference",
    "VersionPin",
    "AnalysisRequest",
    "Opportunity",
    "CapabilityReference",
    "RequirementAssessment",
    "FixReference",
    "Finding",
    "MeasurementEvidence",
    "DiagnosticDocument",
    "DiagnosticError",
    "DiagnosticDerivationError",
    "InvalidAnalysisRequestError",
    "derive_diagnostic",
    "to_canonical_bytes",
    "reset_for_tests",
]

SCHEMA_VERSION = evidence_journal.SCHEMA_VERSION
ANALYSIS_EVENT_KIND = "analysis_requested"

# Shared kernel types are aliased, never redefined, so journal prefixes,
# envelopes, references, and artifact identities stay interchangeable with
# the sibling modules that own them.
Missing = evidence_journal.Missing
Manifest = evidence_journal.Manifest
JournalPrefix = evidence_journal.JournalPrefix
JournalEnvelope = evidence_journal.JournalEnvelope
EvidenceRef = evidence_journal.EvidenceRef
TimePoint = evidence_journal.TimePoint
ArtifactReference = artifact_store.ArtifactReference

_OPPORTUNITY_STATES = frozenset({"exposed", "unexposed", "blocked"})
_RESULTS = frozenset(
    {"satisfied", "violated", "native_absence", "indeterminate", "not_exercised"}
)
_FINDING_KINDS = frozenset(
    {
        "native_capability_absent",
        "requirement_violation",
        "claim_contradiction",
        "measurement_discrepancy",
        "observation",
        "indeterminate",
        "fixture_error",
        "harness_error",
    }
)
_CAUSAL_ROLES = frozenset({"primary", "contributing", "downstream", "not_applicable"})
_DEFECT_LOCI = frozenset(
    {
        "subject",
        "external_planner",
        "connector",
        "fixture",
        "environment",
        "policy",
        "unknown",
        "not_applicable",
    }
)
_ATTRIBUTIONS = frozenset({"confirmed", "supported", "suspected", "unknown"})
_AVAILABILITIES = frozenset({"present", "absent", "unknown", "not_applicable"})
_FIX_TARGETS = frozenset(
    {"subject", "external_planner", "connector", "fixture", "environment", "policy"}
)
_SUPPORTED_ATTRIBUTIONS = frozenset({"confirmed", "supported"})
# Fix targets that require an automation subject side.  Manual execution
# has no automation subject, connector version, or binding version, so a
# rule aimed at either side is not_applicable there, never a fabricated
# recommendation.
_SUBJECT_SIDE_TARGETS = frozenset({"subject", "connector"})

_MISSING_MEANINGS = {
    "not_enabled": "deliberately disabled facility",
    "not_applicable": "no meaning in the declared scope",
    "not_observed": "value not established",
    "observation_lost": "expected or previously available observation lost",
    "unsupported_by_subject": "evidenced scoped subject limitation prevents supply",
    "manual_override": "authenticated journaled operator decision withheld a value",
}

_CODEC_GATE_SCHEMA = "record/v1"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class DiagnosticError(Exception):
    """Base class for attempt-diagnostic failures."""


class DiagnosticDerivationError(DiagnosticError, ValueError):
    """The diagnostic cannot be derived from the given inputs.

    Raised for prefix/request mismatches, unresolvable pinned inputs, and
    bundle inconsistencies.  A new analysis request over corrected inputs
    is required; the failed derivation leaves no partial revision behind.
    """


class InvalidAnalysisRequestError(DiagnosticError, ValueError):
    """The analysis request itself is malformed."""


# ---------------------------------------------------------------------------
# Small validators
# ---------------------------------------------------------------------------


def _require_identifier(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise DiagnosticDerivationError(
            f"{field} must be a str, not {type(value).__name__}"
        )
    if not value or value != value.strip():
        raise DiagnosticDerivationError(
            f"{field} must be a nonempty identifier without padding"
        )
    if len(value) > 256:
        raise DiagnosticDerivationError(
            f"{field} must be at most 256 characters"
        )
    if any(ord(ch) < 0x20 for ch in value):
        raise DiagnosticDerivationError(
            f"{field} must not contain control characters"
        )
    return value


def _require_digest(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith("sha256:")
        or len(value) != 71
        or any(c not in "0123456789abcdef" for c in value[7:])
    ):
        raise DiagnosticDerivationError(
            f"{field} must be a sha256:<64 lowercase hex> digest"
        )
    return value


def _as_missing(value: Any) -> Missing | None:
    if isinstance(value, Missing):
        return value
    if isinstance(value, Mapping):
        keys = set(value.keys())
        if keys in ({"value", "reason"}, {"value", "reason", "detail"}) and (
            value.get("value") is None
        ):
            try:
                return Missing(
                    str(value["reason"]),
                    value.get("detail"),
                )
            except (TypeError, ValueError):
                return None
    return None


def _escape_pointer_token(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _reject_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, val in pairs:
        if key in obj:
            raise DiagnosticDerivationError(f"duplicate mapping key: {key!r}")
        obj[key] = val
    return obj


def _strict_gate(raw: bytes, context: str) -> Any:
    """Parse strict JSON bytes through the tier-0 kernel gate.

    The payload rides inside ``record/v1.timing`` so duplicate keys, bare
    nulls, nonfinite numbers, and malformed Missing envelopes are rejected
    by ``contract_codec`` before this module applies its closed shapes.
    """
    if not isinstance(raw, bytes):
        raise DiagnosticDerivationError(f"{context} must decode from bytes")
    wrapper = b'{"id":"attempt_diagnostics_gate","timing":' + raw + b"}"
    try:
        contract_codec.validate_record(wrapper, _CODEC_GATE_SCHEMA)
    except (TypeError, ValueError) as exc:
        raise DiagnosticDerivationError(
            f"{context}: strict JSON gate rejected record: {exc}"
        ) from exc
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DiagnosticDerivationError(
            f"{context}: record bytes are not valid utf-8: {exc}"
        ) from exc
    try:
        return json.loads(text, object_pairs_hook=_reject_duplicate_object)
    except json.JSONDecodeError as exc:
        raise DiagnosticDerivationError(
            f"{context}: record bytes are not valid JSON: {exc}"
        ) from exc


def _missing_to_dict(value: Any) -> Any:
    missing = _as_missing(value)
    if missing is not None:
        return missing.to_dict()
    return value


# ---------------------------------------------------------------------------
# Value types
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class VersionPin:
    """Immutable pin of a classifier/registry artifact (``K.VersionPin``)."""

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
        if not isinstance(data, Mapping):
            raise DiagnosticDerivationError("VersionPin must decode from a mapping")
        keys = set(data.keys())
        if keys != {"id", "version", "artifact_digest"}:
            raise DiagnosticDerivationError(
                "VersionPin must contain exactly id, version, artifact_digest; "
                f"got {sorted(str(k) for k in keys)}"
            )
        for key in ("id", "version", "artifact_digest"):
            if data[key] is None:
                raise DiagnosticDerivationError(
                    f"VersionPin.{key} must not be a bare null"
                )
        try:
            return cls(
                id=data["id"],
                version=data["version"],
                artifact_digest=data["artifact_digest"],
            )
        except (TypeError, ValueError) as exc:
            raise DiagnosticDerivationError(
                f"invalid VersionPin: {exc}"
            ) from exc


@dataclass(frozen=True, slots=True)
class AnalysisRequest:
    """Pinned derivation request (``K.AnalysisRequest``).

    The journal event carrying this request is the last event of the named
    prefix; the resulting diagnostic is published only afterward, so no hash
    cycle exists.
    """

    diagnostic_id: str
    analysis_revision: int
    classifier: VersionPin
    requirement_registry: VersionPin
    fix_registry: Any  # VersionPin | Missing

    def __post_init__(self) -> None:
        _require_identifier(self.diagnostic_id, "diagnostic_id")
        if (
            isinstance(self.analysis_revision, bool)
            or not isinstance(self.analysis_revision, int)
            or self.analysis_revision < 1
        ):
            raise InvalidAnalysisRequestError(
                "analysis_revision must be a positive integer"
            )
        if not isinstance(self.classifier, VersionPin):
            raise InvalidAnalysisRequestError("classifier must be a VersionPin")
        if not isinstance(self.requirement_registry, VersionPin):
            raise InvalidAnalysisRequestError(
                "requirement_registry must be a VersionPin"
            )
        if not isinstance(self.fix_registry, VersionPin) and (
            _as_missing(self.fix_registry) is None
        ):
            raise InvalidAnalysisRequestError(
                "fix_registry must be a VersionPin or a Missing envelope"
            )

    def to_dict(self) -> dict[str, Any]:
        fix = self.fix_registry
        return {
            "diagnostic_id": self.diagnostic_id,
            "analysis_revision": self.analysis_revision,
            "classifier": self.classifier.to_dict(),
            "requirement_registry": self.requirement_registry.to_dict(),
            "fix_registry": (
                fix.to_dict()
                if isinstance(fix, VersionPin)
                else _as_missing(fix).to_dict()  # type: ignore[union-attr]
            ),
        }

    @classmethod
    def from_dict(cls, data: Any) -> "AnalysisRequest":
        if not isinstance(data, Mapping):
            raise InvalidAnalysisRequestError(
                "AnalysisRequest must decode from a mapping"
            )
        keys = set(data.keys())
        if keys != {
            "diagnostic_id",
            "analysis_revision",
            "classifier",
            "requirement_registry",
            "fix_registry",
        }:
            raise InvalidAnalysisRequestError(
                "AnalysisRequest must contain exactly diagnostic_id, "
                "analysis_revision, classifier, requirement_registry, "
                f"fix_registry; got {sorted(str(k) for k in keys)}"
            )
        try:
            classifier = (
                data["classifier"]
                if isinstance(data["classifier"], VersionPin)
                else VersionPin.from_dict(data["classifier"])
            )
            registry = (
                data["requirement_registry"]
                if isinstance(data["requirement_registry"], VersionPin)
                else VersionPin.from_dict(data["requirement_registry"])
            )
        except DiagnosticDerivationError as exc:
            raise InvalidAnalysisRequestError(str(exc)) from exc
        fix_raw = data["fix_registry"]
        if isinstance(fix_raw, VersionPin):
            fix: Any = fix_raw
        elif isinstance(fix_raw, Mapping) and set(fix_raw.keys()) == {
            "id",
            "version",
            "artifact_digest",
        }:
            try:
                fix = VersionPin.from_dict(fix_raw)
            except DiagnosticDerivationError as exc:
                raise InvalidAnalysisRequestError(str(exc)) from exc
        else:
            missing = _as_missing(fix_raw)
            if missing is None:
                raise InvalidAnalysisRequestError(
                    "fix_registry must be a VersionPin or a Missing envelope"
                )
            fix = missing
        try:
            return cls(
                diagnostic_id=data["diagnostic_id"],
                analysis_revision=data["analysis_revision"],
                classifier=classifier,
                requirement_registry=registry,
                fix_registry=fix,
            )
        except (DiagnosticError, TypeError, ValueError) as exc:
            raise InvalidAnalysisRequestError(
                f"invalid AnalysisRequest: {exc}"
            ) from exc


@dataclass(frozen=True, slots=True)
class Opportunity:
    """Whether the requirement was exercised (``K.Opportunity``)."""

    state: str
    evidence_refs: tuple
    rationale: str

    def __post_init__(self) -> None:
        if self.state not in _OPPORTUNITY_STATES:
            raise DiagnosticDerivationError(
                f"unknown opportunity state: {self.state!r}"
            )
        if not self.evidence_refs:
            raise DiagnosticDerivationError(
                "opportunity.evidence_refs must be nonempty support"
            )
        if not isinstance(self.rationale, str) or not self.rationale:
            raise DiagnosticDerivationError(
                "opportunity.rationale must be a nonempty string"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "evidence_refs": [ref.to_dict() for ref in self.evidence_refs],
            "rationale": self.rationale,
        }


@dataclass(frozen=True, slots=True)
class CapabilityReference:
    """Citation of one scoped capability record (``K.CapabilityReference``)."""

    descriptor_digest: str
    capability_id: str
    evidence_ref: Any

    def __post_init__(self) -> None:
        _require_digest(self.descriptor_digest, "descriptor_digest")
        _require_identifier(self.capability_id, "capability_id")

    def to_dict(self) -> dict[str, Any]:
        return {
            "descriptor_digest": self.descriptor_digest,
            "capability_id": self.capability_id,
            "evidence_ref": self.evidence_ref.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class RequirementAssessment:
    """Independent capability/opportunity/result verdict (``K`` assessment)."""

    requirement_id: str
    facet: str
    contract_version: str
    scope: Any
    capability_refs: tuple
    opportunity: Opportunity
    result: str
    evidence_refs: tuple
    contrary_evidence_refs: tuple
    finding_refs: tuple
    rationale: str

    def __post_init__(self) -> None:
        _require_identifier(self.requirement_id, "requirement_id")
        _require_identifier(self.facet, "facet")
        _require_identifier(self.contract_version, "contract_version")
        if self.result not in _RESULTS:
            raise DiagnosticDerivationError(
                f"unknown assessment result: {self.result!r}"
            )
        if self.result in ("satisfied", "violated") and (
            self.opportunity.state != "exposed"
        ):
            raise DiagnosticDerivationError(
                f"{self.result} requires an exposed opportunity "
                f"({self.requirement_id})"
            )
        if self.result == "native_absence" and not self.capability_refs:
            raise DiagnosticDerivationError(
                f"native_absence requires capability evidence ({self.requirement_id})"
            )
        if not self.evidence_refs:
            raise DiagnosticDerivationError(
                "assessment.evidence_refs must be nonempty support"
            )
        if not isinstance(self.rationale, str) or not self.rationale:
            raise DiagnosticDerivationError(
                "assessment.rationale must be a nonempty string"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "requirement_id": self.requirement_id,
            "facet": self.facet,
            "contract_version": self.contract_version,
            "scope": copy.deepcopy(self.scope),
            "capability_refs": [ref.to_dict() for ref in self.capability_refs],
            "opportunity": self.opportunity.to_dict(),
            "result": self.result,
            "evidence_refs": [ref.to_dict() for ref in self.evidence_refs],
            "contrary_evidence_refs": [
                ref.to_dict() for ref in self.contrary_evidence_refs
            ],
            "finding_refs": list(self.finding_refs),
            "rationale": self.rationale,
        }


@dataclass(frozen=True, slots=True)
class FixReference:
    """A recommendation reference, never an implementation claim."""

    registry: VersionPin
    rule_instance_id: str
    evidence_refs: tuple
    verification_plan: Any

    def __post_init__(self) -> None:
        if not isinstance(self.registry, VersionPin):
            raise DiagnosticDerivationError(
                "FixReference.registry must be a VersionPin"
            )
        _require_identifier(self.rule_instance_id, "rule_instance_id")
        if not self.evidence_refs:
            raise DiagnosticDerivationError(
                "FixReference.evidence_refs must be nonempty support"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "registry": self.registry.to_dict(),
            "rule_instance_id": self.rule_instance_id,
            "evidence_refs": [ref.to_dict() for ref in self.evidence_refs],
            "verification_plan": self.verification_plan.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class Finding:
    """One diagnostic finding (``K.Finding``)."""

    finding_id: str
    kind: str
    requirement_refs: tuple
    symptom: str
    scope: Any
    causal_role: str
    trigger_feature_refs: tuple
    defect_locus: str
    attribution: str
    evidence_refs: tuple
    contrary_evidence_refs: tuple
    limitations: tuple
    suggested_fix: Any  # FixReference | Missing

    def __post_init__(self) -> None:
        _require_identifier(self.finding_id, "finding_id")
        if self.kind not in _FINDING_KINDS:
            raise DiagnosticDerivationError(f"unknown finding kind: {self.kind!r}")
        if self.causal_role not in _CAUSAL_ROLES:
            raise DiagnosticDerivationError(
                f"unknown causal role: {self.causal_role!r}"
            )
        if self.defect_locus not in _DEFECT_LOCI:
            raise DiagnosticDerivationError(
                f"unknown defect locus: {self.defect_locus!r}"
            )
        if self.attribution not in _ATTRIBUTIONS:
            raise DiagnosticDerivationError(
                f"unknown attribution: {self.attribution!r}"
            )
        if not isinstance(self.symptom, str) or not self.symptom:
            raise DiagnosticDerivationError(
                "finding.symptom must be a nonempty string"
            )
        if not self.evidence_refs:
            raise DiagnosticDerivationError(
                "finding.evidence_refs must be nonempty support"
            )
        if not isinstance(self.suggested_fix, FixReference) and (
            _as_missing(self.suggested_fix) is None
        ):
            raise DiagnosticDerivationError(
                "finding.suggested_fix must be a FixReference or Missing"
            )

    def to_dict(self) -> dict[str, Any]:
        fix = self.suggested_fix
        return {
            "finding_id": self.finding_id,
            "kind": self.kind,
            "requirement_refs": list(self.requirement_refs),
            "symptom": self.symptom,
            "scope": copy.deepcopy(self.scope),
            "causal_role": self.causal_role,
            "trigger_feature_refs": list(self.trigger_feature_refs),
            "defect_locus": self.defect_locus,
            "attribution": self.attribution,
            "evidence_refs": [ref.to_dict() for ref in self.evidence_refs],
            "contrary_evidence_refs": [
                ref.to_dict() for ref in self.contrary_evidence_refs
            ],
            "limitations": list(self.limitations),
            "suggested_fix": (
                fix.to_dict()
                if isinstance(fix, FixReference)
                else _as_missing(fix).to_dict()  # type: ignore[union-attr]
            ),
        }


@dataclass(frozen=True, slots=True)
class MeasurementEvidence:
    """One copied measurement plus its source citations."""

    measurement: Any
    evidence_refs: tuple

    def to_dict(self) -> dict[str, Any]:
        return {
            "measurement": copy.deepcopy(
                dict(self.measurement)
                if isinstance(self.measurement, Mapping)
                else self.measurement
            ),
            "evidence_refs": [ref.to_dict() for ref in self.evidence_refs],
        }


@dataclass(frozen=True, slots=True)
class DiagnosticDocument:
    """Immutable derived diagnostic (``K.DiagnosticDocument``)."""

    record_type: str
    schema_version: str
    diagnostic_id: str
    analysis_revision: int
    run_id: str
    manifest_hash: str
    input_prefix: Any
    analysis_request_ref: Any
    classifier: VersionPin
    requirement_registry: VersionPin
    fix_registry: Any
    attempt: Any
    execution: Any
    delivered_task_hash: Any
    native_request_hash: Any
    validity: Any
    capability_descriptors: tuple
    requirement_assessments: tuple
    observed_actions: tuple
    feature_exposures: tuple
    steps: tuple
    measurements: tuple
    claims: tuple
    findings: tuple
    observation: Any
    application: Any
    behavioral_profile: Any
    fingerprint_profile: Any
    artifacts: tuple

    def to_dict(self) -> dict[str, Any]:
        fix = self.fix_registry
        return {
            "record_type": self.record_type,
            "schema_version": self.schema_version,
            "diagnostic_id": self.diagnostic_id,
            "analysis_revision": self.analysis_revision,
            "run_id": self.run_id,
            "manifest_hash": self.manifest_hash,
            "input_prefix": {
                "journal_id": self.input_prefix.journal_id,
                "last_sequence": self.input_prefix.last_sequence,
                "head_hash": self.input_prefix.head_hash,
            },
            "analysis_request_ref": self.analysis_request_ref.to_dict(),
            "classifier": self.classifier.to_dict(),
            "requirement_registry": self.requirement_registry.to_dict(),
            "fix_registry": (
                fix.to_dict()
                if isinstance(fix, VersionPin)
                else _as_missing(fix).to_dict()  # type: ignore[union-attr]
            ),
            "attempt": copy.deepcopy(self.attempt),
            "execution": copy.deepcopy(self.execution),
            "delivered_task_hash": _missing_to_dict(self.delivered_task_hash),
            "native_request_hash": _missing_to_dict(self.native_request_hash),
            "validity": copy.deepcopy(self.validity),
            "capability_descriptors": list(self.capability_descriptors),
            "requirement_assessments": [
                item.to_dict() for item in self.requirement_assessments
            ],
            "observed_actions": list(self.observed_actions),
            "feature_exposures": list(self.feature_exposures),
            "steps": list(self.steps),
            "measurements": [item.to_dict() for item in self.measurements],
            "claims": list(self.claims),
            "findings": [item.to_dict() for item in self.findings],
            "observation": copy.deepcopy(self.observation),
            "application": copy.deepcopy(self.application),
            "behavioral_profile": copy.deepcopy(self.behavioral_profile),
            "fingerprint_profile": copy.deepcopy(self.fingerprint_profile),
            "artifacts": list(self.artifacts),
        }


def to_canonical_bytes(document: DiagnosticDocument) -> bytes:
    """Render a diagnostic as canonical JSON bytes (deterministic)."""
    if not isinstance(document, DiagnosticDocument):
        raise TypeError("to_canonical_bytes requires a DiagnosticDocument")
    return _canonical_bytes(document.to_dict())


# ---------------------------------------------------------------------------
# Input coercion
# ---------------------------------------------------------------------------


def _coerce_manifest(manifest: Any) -> Any:
    if isinstance(manifest, Manifest):
        return manifest
    raise DiagnosticDerivationError(
        "manifest must be an evidence_journal.Manifest instance, "
        f"not {type(manifest).__name__}"
    )


def _coerce_prefix(prefix: Any) -> Any:
    if isinstance(prefix, JournalPrefix):
        return prefix
    if isinstance(prefix, Mapping) and set(prefix.keys()) == {
        "journal_id",
        "last_sequence",
        "head_hash",
    }:
        try:
            return JournalPrefix(
                journal_id=prefix["journal_id"],
                last_sequence=prefix["last_sequence"],
                head_hash=prefix["head_hash"],
            )
        except (TypeError, ValueError) as exc:
            raise DiagnosticDerivationError(
                f"invalid JournalPrefix: {exc}"
            ) from exc
    raise DiagnosticDerivationError(
        "prefix must be an evidence_journal.JournalPrefix instance, "
        f"not {type(prefix).__name__}"
    )


def _coerce_request(request: Any) -> AnalysisRequest:
    if isinstance(request, AnalysisRequest):
        return request
    if isinstance(request, Mapping):
        return AnalysisRequest.from_dict(request)
    raise InvalidAnalysisRequestError(
        "request must be an AnalysisRequest instance, "
        f"not {type(request).__name__}"
    )


# ---------------------------------------------------------------------------
# Pinned artifact resolution
# ---------------------------------------------------------------------------


def _resolve_pin(channel_id: str, pin: VersionPin, label: str) -> bytes:
    """Resolve pinned bundle bytes through the artifact store.

    A ``VersionPin`` carries only the digest; the full reference metadata
    is recovered from the store's retained identities so resolution still
    passes authorization and digest/size integrity checks.
    """
    meta = getattr(artifact_store, "_META", {}) or {}
    ref = meta.get(pin.artifact_digest)
    if ref is None:
        raise DiagnosticDerivationError(
            f"{label} pin {pin.artifact_digest} names no retained artifact; "
            "a digest alone is not archived content"
        )
    try:
        return artifact_store.resolve_artifact(channel_id, ref)
    except artifact_store.ArtifactLostError as exc:
        raise DiagnosticDerivationError(
            f"{label} bytes for {pin.artifact_digest} are lost; loss is an "
            f"integrity incident, not empty input: {exc}"
        ) from exc
    except artifact_store.ArtifactUnavailableError as exc:
        raise DiagnosticDerivationError(
            f"{label} bytes for {pin.artifact_digest} are unavailable: {exc}"
        ) from exc
    except artifact_store.ArtifactAccessDeniedError as exc:
        raise DiagnosticDerivationError(
            f"{label} bytes for {pin.artifact_digest} are not readable "
            f"from this channel: {exc}"
        ) from exc


# ---------------------------------------------------------------------------
# Bundle parsing (closed shapes)
# ---------------------------------------------------------------------------


def _require_scope(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value.keys()) != {"kind", "id"}:
        raise DiagnosticDerivationError(
            f"{field} must be exactly {{kind, id}}"
        )
    if not isinstance(value["kind"], str) or not value["kind"]:
        raise DiagnosticDerivationError(f"{field}.kind must be a nonempty string")
    if not isinstance(value["id"], str) or not value["id"]:
        raise DiagnosticDerivationError(f"{field}.id must be a nonempty string")
    return {"kind": value["kind"], "id": value["id"]}


def _parse_classifier(raw: bytes) -> list[dict[str, Any]]:
    data = _strict_gate(raw, "classifier bundle")
    if not isinstance(data, Mapping) or set(data.keys()) != {
        "bundle",
        "bundle_version",
        "rules",
    }:
        raise DiagnosticDerivationError(
            "classifier bundle must contain exactly "
            "bundle, bundle_version, rules"
        )
    if data["bundle"] != "classifier":
        raise DiagnosticDerivationError(
            "classifier bundle.bundle must be 'classifier'"
        )
    if not isinstance(data["bundle_version"], str) or not data["bundle_version"]:
        raise DiagnosticDerivationError(
            "classifier bundle.bundle_version must be a nonempty string"
        )
    if not isinstance(data["rules"], list):
        raise DiagnosticDerivationError("classifier bundle.rules must be an array")
    rules: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, entry in enumerate(data["rules"]):
        where = f"classifier rule[{index}]"
        if not isinstance(entry, Mapping):
            raise DiagnosticDerivationError(f"{where} must be a mapping")
        allowed = {
            "requirement_id",
            "facet",
            "contract_version",
            "scope",
            "capability_id",
            "defect_locus",
            "signals",
        }
        extra = set(entry.keys()) - allowed
        if extra:
            raise DiagnosticDerivationError(
                f"{where} has undeclared properties: {sorted(str(k) for k in extra)}"
            )
        for key in ("requirement_id", "facet", "contract_version"):
            if not isinstance(entry.get(key), str) or not entry[key]:
                raise DiagnosticDerivationError(
                    f"{where}.{key} must be a nonempty string"
                )
        if entry["requirement_id"] in seen:
            raise DiagnosticDerivationError(
                f"duplicate classifier rule for {entry['requirement_id']!r}"
            )
        seen.add(entry["requirement_id"])
        scope = _require_scope(entry.get("scope"), f"{where}.scope")
        capability_id = entry.get("capability_id")
        if capability_id is not None and (
            not isinstance(capability_id, str) or not capability_id
        ):
            raise DiagnosticDerivationError(
                f"{where}.capability_id must be a nonempty string when present"
            )
        locus = entry.get("defect_locus", "unknown")
        if locus not in _DEFECT_LOCI:
            raise DiagnosticDerivationError(
                f"{where}.defect_locus must be one of {sorted(_DEFECT_LOCI)}"
            )
        signals_raw = entry.get("signals")
        if not isinstance(signals_raw, Mapping):
            raise DiagnosticDerivationError(f"{where}.signals must be a mapping")
        signal_extra = set(signals_raw.keys()) - {
            "exposed",
            "blocked",
            "controls",
            "controls_invalid",
            "satisfied",
            "violated",
            "absent",
            "unsupported",
            "descriptor",
        }
        if signal_extra:
            raise DiagnosticDerivationError(
                f"{where}.signals has undeclared properties: "
                f"{sorted(str(k) for k in signal_extra)}"
            )
        signals: dict[str, Any] = {}
        for key in (
            "exposed",
            "blocked",
            "controls_invalid",
            "satisfied",
            "violated",
            "absent",
            "unsupported",
            "descriptor",
        ):
            val = signals_raw.get(key)
            if val is None:
                continue
            if not isinstance(val, str) or not val:
                raise DiagnosticDerivationError(
                    f"{where}.signals.{key} must be a nonempty string when present"
                )
            signals[key] = val
        controls = signals_raw.get("controls", [])
        if not isinstance(controls, list) or any(
            not isinstance(item, str) or not item for item in controls
        ):
            raise DiagnosticDerivationError(
                f"{where}.signals.controls must be an array of nonempty strings"
            )
        signals["controls"] = list(controls)
        rules.append(
            {
                "requirement_id": entry["requirement_id"],
                "facet": entry["facet"],
                "contract_version": entry["contract_version"],
                "scope": scope,
                "capability_id": capability_id,
                "defect_locus": locus,
                "signals": signals,
            }
        )
    return rules


def _parse_requirement_registry(raw: bytes) -> list[dict[str, Any]]:
    data = _strict_gate(raw, "requirement registry")
    if not isinstance(data, Mapping) or set(data.keys()) != {
        "registry",
        "registry_version",
        "requirements",
    }:
        raise DiagnosticDerivationError(
            "requirement registry must contain exactly "
            "registry, registry_version, requirements"
        )
    if data["registry"] != "requirements":
        raise DiagnosticDerivationError(
            "requirement registry.registry must be 'requirements'"
        )
    if not isinstance(data["registry_version"], str) or not data["registry_version"]:
        raise DiagnosticDerivationError(
            "requirement registry.registry_version must be a nonempty string"
        )
    if not isinstance(data["requirements"], list):
        raise DiagnosticDerivationError(
            "requirement registry.requirements must be an array"
        )
    requirements: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, entry in enumerate(data["requirements"]):
        where = f"requirement[{index}]"
        if not isinstance(entry, Mapping) or set(entry.keys()) != {
            "requirement_id",
            "facet",
            "contract_version",
            "scope",
            "required",
        }:
            raise DiagnosticDerivationError(
                f"{where} must contain exactly requirement_id, facet, "
                "contract_version, scope, required"
            )
        for key in ("requirement_id", "facet", "contract_version"):
            if not isinstance(entry[key], str) or not entry[key]:
                raise DiagnosticDerivationError(
                    f"{where}.{key} must be a nonempty string"
                )
        if entry["requirement_id"] in seen:
            raise DiagnosticDerivationError(
                f"duplicate requirement {entry['requirement_id']!r}"
            )
        seen.add(entry["requirement_id"])
        if type(entry["required"]) is not bool:
            raise DiagnosticDerivationError(f"{where}.required must be a bool")
        requirements.append(
            {
                "requirement_id": entry["requirement_id"],
                "facet": entry["facet"],
                "contract_version": entry["contract_version"],
                "scope": _require_scope(entry["scope"], f"{where}.scope"),
                "required": entry["required"],
            }
        )
    return requirements


def _parse_fix_registry(raw: bytes) -> list[dict[str, Any]]:
    data = _strict_gate(raw, "fix registry")
    if not isinstance(data, Mapping) or set(data.keys()) != {
        "registry",
        "registry_version",
        "rules",
    }:
        raise DiagnosticDerivationError(
            "fix registry must contain exactly registry, registry_version, rules"
        )
    if data["registry"] != "fix":
        raise DiagnosticDerivationError("fix registry.registry must be 'fix'")
    if not isinstance(data["registry_version"], str) or not data["registry_version"]:
        raise DiagnosticDerivationError(
            "fix registry.registry_version must be a nonempty string"
        )
    if not isinstance(data["rules"], list):
        raise DiagnosticDerivationError("fix registry.rules must be an array")
    rules: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, entry in enumerate(data["rules"]):
        where = f"fix rule[{index}]"
        if not isinstance(entry, Mapping) or set(entry.keys()) != {
            "rule_instance_id",
            "requirement_id",
            "target",
            "target_class",
            "approved",
            "plan_digest",
            "contraindications_absent",
        }:
            raise DiagnosticDerivationError(
                f"{where} must contain exactly rule_instance_id, "
                "requirement_id, target, target_class, approved, "
                "plan_digest, contraindications_absent"
            )
        for key in ("rule_instance_id", "requirement_id"):
            if not isinstance(entry[key], str) or not entry[key]:
                raise DiagnosticDerivationError(
                    f"{where}.{key} must be a nonempty string"
                )
        if entry["rule_instance_id"] in seen:
            raise DiagnosticDerivationError(
                f"duplicate fix rule {entry['rule_instance_id']!r}"
            )
        seen.add(entry["rule_instance_id"])
        if entry["target"] not in _FIX_TARGETS:
            raise DiagnosticDerivationError(
                f"{where}.target must be one of {sorted(_FIX_TARGETS)}"
            )
        if entry["target_class"] not in ("laboratory_fixture", "employer_origin"):
            raise DiagnosticDerivationError(
                f"{where}.target_class must be laboratory_fixture or employer_origin"
            )
        if type(entry["approved"]) is not bool:
            raise DiagnosticDerivationError(f"{where}.approved must be a bool")
        if type(entry["contraindications_absent"]) is not bool:
            raise DiagnosticDerivationError(
                f"{where}.contraindications_absent must be a bool"
            )
        _require_digest(entry["plan_digest"], f"{where}.plan_digest")
        rules.append(
            {
                "rule_instance_id": entry["rule_instance_id"],
                "requirement_id": entry["requirement_id"],
                "target": entry["target"],
                "target_class": entry["target_class"],
                "approved": entry["approved"],
                "plan_digest": entry["plan_digest"],
                "contraindications_absent": entry["contraindications_absent"],
            }
        )
    return rules


# ---------------------------------------------------------------------------
# Prefix evidence helpers
# ---------------------------------------------------------------------------


def _evidence_ref(prefix: Any, envelope: Any, pointer: str = "") -> Any:
    return EvidenceRef(
        journal_id=prefix.journal_id,
        sequence=envelope.journal_sequence,
        event_id=envelope.event_id,
        event_hash=envelope.event_hash,
        pointer=pointer,
    )


def _data_pointer(key: str) -> str:
    return "/payload/data/" + _escape_pointer_token(key)


def _manifest_hash(manifest: Any) -> str:
    return str(
        contract_codec.canonical_digest(_canonical_bytes(manifest.to_dict()))
    )


def _manifest_clocks(manifest: Any) -> tuple:
    clocks: list[Any] = []
    entries = manifest.clocks
    if not isinstance(entries, Sequence) or isinstance(entries, (str, bytes)):
        raise DiagnosticDerivationError("manifest.clocks must be a sequence")
    for index, entry in enumerate(entries):
        if isinstance(entry, contract_codec.ClockDescriptor):
            clocks.append(entry)
            continue
        if not isinstance(entry, Mapping):
            raise DiagnosticDerivationError(
                f"manifest.clocks[{index}] must be a clock descriptor mapping"
            )
        try:
            clocks.append(
                contract_codec.ClockDescriptor(
                    clock_id=entry["clock_id"],
                    boot_id=entry["boot_id"],
                    origin=entry.get("origin"),
                    source_id=entry.get("source_id"),
                    basis=entry.get("basis"),
                    unit=entry.get("unit"),
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise DiagnosticDerivationError(
                f"manifest.clocks[{index}] is not a valid clock descriptor: {exc}"
            ) from exc
    return tuple(clocks)


def _check_analysis_request(
    last: Any, prefix: Any, request: AnalysisRequest
) -> dict[str, Any]:
    """Require the prefix to end at this request's analysis event."""
    if last.event_kind != ANALYSIS_EVENT_KIND:
        raise DiagnosticDerivationError(
            f"prefix ends at {last.event_kind!r} (sequence "
            f"{last.journal_sequence}), not at the {ANALYSIS_EVENT_KIND!r} "
            "event; a diagnostic reads only its named analysis prefix"
        )
    data = last.payload["data"]
    if not isinstance(data, Mapping):
        raise DiagnosticDerivationError(
            "analysis_requested data must be an EvidenceMap mapping"
        )
    try:
        pinned = AnalysisRequest.from_dict(
            {
                "diagnostic_id": data.get("diagnostic_id"),
                "analysis_revision": data.get("analysis_revision"),
                "classifier": data.get("classifier"),
                "requirement_registry": data.get("requirement_registry"),
                "fix_registry": data.get("fix_registry"),
            }
            if set(data.keys())
            >= {
                "diagnostic_id",
                "analysis_revision",
                "classifier",
                "requirement_registry",
                "fix_registry",
            }
            else data
        )
    except InvalidAnalysisRequestError as exc:
        raise DiagnosticDerivationError(
            f"prefix analysis event does not pin a valid request: {exc}"
        ) from exc
    expected = request.to_dict()
    actual = pinned.to_dict()
    if actual != expected:
        raise DiagnosticDerivationError(
            "prefix analysis event pins a different request than the "
            "supplied AnalysisRequest; corrections need a new request "
            "and immutable revision"
        )
    _ = prefix
    return dict(data)


def _copy_measurements(
    decoded: list[tuple[Any, dict[str, Any]]],
    prefix: Any,
    clocks: tuple,
) -> tuple[MeasurementEvidence, ...]:
    """Validate and copy every prefix measurement verbatim."""
    copied: list[MeasurementEvidence] = []
    seen: set[str] = set()
    for envelope, payload in decoded:
        measurements = payload.get("measurements", [])
        if not isinstance(measurements, list):
            raise DiagnosticDerivationError(
                f"sequence {envelope.journal_sequence}: measurements must be an array"
            )
        for measurement in measurements:
            if not isinstance(measurement, Mapping):
                raise DiagnosticDerivationError(
                    f"sequence {envelope.journal_sequence}: measurement must be "
                    "a mapping"
                )
            try:
                contract_codec.validate_measurement(dict(measurement), clocks)
            except (TypeError, ValueError) as exc:
                raise DiagnosticDerivationError(
                    f"sequence {envelope.journal_sequence}: invalid measurement "
                    f"{measurement.get('measurement_id')!r}: {exc}"
                ) from exc
            measurement_id = measurement["measurement_id"]
            if measurement_id in seen:
                raise DiagnosticDerivationError(
                    f"duplicate measurement_id {measurement_id!r} in prefix; "
                    "copies cannot collide within one diagnostic"
                )
            seen.add(measurement_id)
            copied.append(
                MeasurementEvidence(
                    measurement=copy.deepcopy(dict(measurement)),
                    evidence_refs=(
                        _evidence_ref(prefix, envelope),
                    ),
                )
            )
    return tuple(copied)


def _signal_hits(
    decoded: list[tuple[Any, dict[str, Any]]],
    key: str | None,
) -> list[Any]:
    """Return prefix events whose data marks ``key`` exactly True."""
    if key is None:
        return []
    return [
        envelope
        for envelope, data in decoded
        if data.get(key) is True
    ]


def _descriptor_hits(
    decoded: list[tuple[Any, dict[str, Any]]],
    key: str | None,
    capability_id: str | None,
    limitations: list[str],
) -> list[dict[str, Any]]:
    """Collect well-formed capability records under ``key``.

    Malformed records are not evidence and never fail the derivation;
    they are noted as limitations instead.
    """
    if key is None or capability_id is None:
        return []
    hits: list[dict[str, Any]] = []
    for envelope, data in decoded:
        raw = data.get(key)
        if raw is None:
            continue
        where = f"sequence {envelope.journal_sequence} field {key!r}"
        if not isinstance(raw, Mapping):
            limitations.append(
                f"{where} is not a capability record mapping; ignored"
            )
            continue
        if set(raw.keys()) - {
            "capability_id",
            "availability",
            "descriptor_digest",
            "scope",
        }:
            limitations.append(
                f"{where} has undeclared capability properties; ignored"
            )
            continue
        if raw.get("capability_id", capability_id) != capability_id:
            limitations.append(f"{where} names another capability; ignored")
            continue
        if raw.get("availability") not in _AVAILABILITIES:
            limitations.append(f"{where} has no valid availability; ignored")
            continue
        digest = raw.get("descriptor_digest")
        if (
            not isinstance(digest, str)
            or not digest.startswith("sha256:")
            or len(digest) != 71
        ):
            limitations.append(f"{where} has no valid descriptor digest; ignored")
            continue
        scope = raw.get("scope")
        if (
            not isinstance(scope, Mapping)
            or set(scope.keys()) != {"kind", "id"}
            or not isinstance(scope.get("kind"), str)
            or not isinstance(scope.get("id"), str)
        ):
            limitations.append(f"{where} has no valid scope; ignored")
            continue
        hits.append(
            {
                "availability": raw["availability"],
                "descriptor_digest": digest,
                "scope": {"kind": scope["kind"], "id": scope["id"]},
                "envelope": envelope,
            }
        )
    return hits


# ---------------------------------------------------------------------------
# Assessment
# ---------------------------------------------------------------------------


def _assess_requirement(
    requirement: dict[str, Any],
    rule: dict[str, Any],
    decoded: list[tuple[Any, dict[str, Any]]],
    prefix: Any,
    analysis_request_ref: Any,
    limitations: list[str],
) -> RequirementAssessment:
    signals = rule["signals"]
    exposed = _signal_hits(decoded, signals.get("exposed"))
    blocked = _signal_hits(decoded, signals.get("blocked"))
    control_hits: dict[str, list[Any]] = {
        key: _signal_hits(decoded, key) for key in signals.get("controls", [])
    }
    controls_invalid = _signal_hits(decoded, signals.get("controls_invalid"))
    satisfied = _signal_hits(decoded, signals.get("satisfied"))
    violated = _signal_hits(decoded, signals.get("violated"))
    absent_signal = _signal_hits(decoded, signals.get("absent"))
    descriptors = _descriptor_hits(
        decoded, signals.get("descriptor"), rule.get("capability_id"), limitations
    )

    requirement_id = requirement["requirement_id"]
    scope = requirement["scope"]

    if exposed:
        opportunity = Opportunity(
            state="exposed",
            evidence_refs=tuple(
                _evidence_ref(prefix, env, _data_pointer(signals["exposed"]))
                for env in exposed
            ),
            rationale=(
                f"exposure signal {signals['exposed']!r} observed in the "
                f"named prefix for {requirement_id}"
            ),
        )
    elif blocked:
        opportunity = Opportunity(
            state="blocked",
            evidence_refs=tuple(
                _evidence_ref(prefix, env, _data_pointer(signals["blocked"]))
                for env in blocked
            ),
            rationale=(
                f"block signal {signals['blocked']!r} observed in the named "
                f"prefix for {requirement_id}"
            ),
        )
    else:
        opportunity = Opportunity(
            state="unexposed",
            evidence_refs=(analysis_request_ref,),
            rationale=(
                f"no exposure signal for {requirement_id} in the complete "
                "named prefix as of the analysis request"
            ),
        )

    controls_valid = (
        not controls_invalid
        and all(control_hits[key] for key in control_hits)
    )
    absent_records = [
        item
        for item in descriptors
        if item["availability"] == "absent" and item["scope"] == scope
    ]
    capability_refs = tuple(
        CapabilityReference(
            descriptor_digest=item["descriptor_digest"],
            capability_id=rule["capability_id"],  # type: ignore[arg-type]
            evidence_ref=_evidence_ref(
                prefix, item["envelope"], _data_pointer(signals["descriptor"])
            ),
        )
        for item in descriptors
        if rule.get("capability_id") is not None
    )

    evidence: list[Any] = []
    contrary: list[Any] = []
    if opportunity.state == "unexposed":
        result = "not_exercised"
        rationale = (
            f"{requirement_id} was not exposed in the named prefix; "
            "unexercised work takes no success or failure credit"
        )
        evidence.append(analysis_request_ref)
    elif opportunity.state == "blocked":
        if controls_invalid:
            result = "indeterminate"
            rationale = (
                f"{requirement_id} was blocked and its controls are "
                "invalid; what was actually observed cannot decide it"
            )
            evidence.extend(opportunity.evidence_refs)
            contrary.extend(
                _evidence_ref(prefix, env, _data_pointer(signals["controls_invalid"]))
                for env in controls_invalid
            )
        else:
            result = "not_exercised"
            rationale = (
                f"{requirement_id} was blocked in the named prefix; "
                "blocked work takes no success or failure credit"
            )
            evidence.extend(opportunity.evidence_refs)
    elif not controls_valid:
        result = "indeterminate"
        rationale = (
            f"{requirement_id} was exposed but its applicable controls are "
            "missing or invalid; invalidly controlled work cannot establish "
            "satisfaction or violation"
        )
        evidence.extend(opportunity.evidence_refs)
        for key, hits in control_hits.items():
            if not hits:
                continue
            evidence.extend(
                _evidence_ref(prefix, env, _data_pointer(key)) for env in hits
            )
        contrary.extend(
            _evidence_ref(prefix, env, _data_pointer(signals["controls_invalid"]))
            for env in controls_invalid
        )
    elif satisfied and violated:
        result = "indeterminate"
        rationale = (
            f"{requirement_id} carries both satisfaction and violation "
            "signals in the named prefix; the conflict cannot decide it"
        )
        evidence.extend(
            _evidence_ref(prefix, env, _data_pointer(signals["satisfied"]))
            for env in satisfied
        )
        contrary.extend(
            _evidence_ref(prefix, env, _data_pointer(signals["violated"]))
            for env in violated
        )
    elif violated:
        result = "violated"
        rationale = (
            f"{requirement_id} was exposed under valid controls and its "
            "violation signal is observed with supporting evidence"
        )
        evidence.extend(
            _evidence_ref(prefix, env, _data_pointer(signals["violated"]))
            for env in violated
        )
    elif satisfied:
        result = "satisfied"
        rationale = (
            f"{requirement_id} was exposed under valid controls and its "
            "satisfaction signal is observed with supporting evidence"
        )
        evidence.extend(
            _evidence_ref(prefix, env, _data_pointer(signals["satisfied"]))
            for env in satisfied
        )
    elif absent_records and requirement["required"]:
        result = "native_absence"
        rationale = (
            f"{requirement_id} requires an evidenced absent native "
            "capability in the exact scope, observed with descriptor "
            "evidence"
        )
        evidence.extend(
            _evidence_ref(prefix, item["envelope"], _data_pointer(signals["descriptor"]))
            for item in absent_records
        )
    elif absent_records:
        result = "indeterminate"
        rationale = (
            f"{requirement_id} shows an absent capability record but the "
            "capability is not required here; absence without a "
            "requirement cannot decide it"
        )
        evidence.extend(opportunity.evidence_refs)
    else:
        result = "indeterminate"
        if absent_signal and not absent_records:
            rationale = (
                f"{requirement_id} signals absence without an evidenced "
                "absent native capability in the exact scope; mere failure "
                "to reach a step is not native absence"
            )
        else:
            rationale = (
                f"{requirement_id} was exposed under valid controls but "
                "carries no satisfaction, violation, or absence signal"
            )
        evidence.extend(opportunity.evidence_refs)

    return RequirementAssessment(
        requirement_id=requirement_id,
        facet=requirement["facet"],
        contract_version=requirement["contract_version"],
        scope=copy.deepcopy(scope),
        capability_refs=capability_refs,
        opportunity=opportunity,
        result=result,
        evidence_refs=tuple(evidence),
        contrary_evidence_refs=tuple(contrary),
        finding_refs=(),
        rationale=rationale,
    )


# ---------------------------------------------------------------------------
# Findings and fix suggestions
# ---------------------------------------------------------------------------


def _finding_kind_for(result: str) -> str:
    if result == "violated":
        return "requirement_violation"
    if result == "native_absence":
        return "native_capability_absent"
    return "indeterminate"


def _suggest_fix(
    channel_id: str,
    finding_id: str,
    requirement_id: str,
    assessment: RequirementAssessment,
    attribution: str,
    request: AnalysisRequest,
    fix_rules: list[dict[str, Any]] | None,
    unsupported_hits: list[Any],
    prefix: Any,
    signals: dict[str, Any],
    execution_mode: str,
    attempt_target_class: str | None,
) -> Any:
    fix_registry = request.fix_registry
    if not isinstance(fix_registry, VersionPin):
        reason = _as_missing(fix_registry).reason  # type: ignore[union-attr]
        meaning = _MISSING_MEANINGS.get(reason, reason)
        return Missing(
            reason,
            f"fix facility {reason} ({meaning}); no fix rule evaluated "
            f"for finding {finding_id}",
        )
    if unsupported_hits and signals.get("unsupported") is not None:
        sequences = sorted({env.journal_sequence for env in unsupported_hits})
        return Missing(
            "unsupported_by_subject",
            "evidenced scoped subject limitation at "
            f"sequence(s) {sequences} prevents fix supply for "
            f"{requirement_id}",
        )
    assert fix_rules is not None
    rule = next(
        (
            item
            for item in fix_rules
            if item["requirement_id"] == requirement_id
        ),
        None,
    )
    if rule is None:
        return Missing(
            "not_observed",
            f"no fix rule for requirement {requirement_id} in registry "
            f"{fix_registry.id}/{fix_registry.version}; insufficient "
            "observed support for a recommendation",
        )
    if execution_mode == "manual" and rule["target"] in _SUBJECT_SIDE_TARGETS:
        return Missing(
            "not_applicable",
            f"rule {rule['rule_instance_id']} targets {rule['target']} but "
            "manual execution has no automation subject side",
        )
    if not rule["approved"]:
        return Missing(
            "not_observed",
            f"fix rule {rule['rule_instance_id']} is not approved; no "
            "eligible recommendation exists",
        )
    if attempt_target_class is None:
        return Missing(
            "not_observed",
            f"attempt target class unknown; eligibility of rule "
            f"{rule['rule_instance_id']} not established",
        )
    if rule["target_class"] != attempt_target_class:
        return Missing(
            "not_observed",
            f"rule {rule['rule_instance_id']} is scoped to "
            f"{rule['target_class']} but the attempt targets "
            f"{attempt_target_class}",
        )
    if not rule["contraindications_absent"]:
        return Missing(
            "not_observed",
            f"rule {rule['rule_instance_id']} carries unexcluded "
            "contraindications; silence is not absence",
        )
    if attribution not in _SUPPORTED_ATTRIBUTIONS:
        return Missing(
            "not_observed",
            f"attribution {attribution} cannot support a concrete remedy "
            f"for finding {finding_id}",
        )
    meta = getattr(artifact_store, "_META", {}) or {}
    plan_ref = meta.get(rule["plan_digest"])
    if plan_ref is None:
        return Missing(
            "not_observed",
            f"verification plan {rule['plan_digest']} for rule "
            f"{rule['rule_instance_id']} is not retained",
        )
    try:
        artifact_store.resolve_artifact(channel_id, plan_ref)
    except artifact_store.ArtifactLostError:
        return Missing(
            "observation_lost",
            f"verification plan {rule['plan_digest']} for rule "
            f"{rule['rule_instance_id']} was retained but its bytes are "
            "lost",
        )
    except artifact_store.ArtifactUnavailableError:
        return Missing(
            "not_observed",
            f"verification plan {rule['plan_digest']} for rule "
            f"{rule['rule_instance_id']} has no available bytes",
        )
    except artifact_store.ArtifactAccessDeniedError as exc:
        raise DiagnosticDerivationError(
            f"verification plan {rule['plan_digest']} is not readable "
            f"from this channel: {exc}"
        ) from exc
    return FixReference(
        registry=fix_registry,
        rule_instance_id=rule["rule_instance_id"],
        evidence_refs=assessment.evidence_refs,
        verification_plan=plan_ref,
    )


def _build_findings(
    channel_id: str,
    assessments: list[RequirementAssessment],
    rules_by_requirement: dict[str, dict[str, Any]],
    decoded: list[tuple[Any, dict[str, Any]]],
    prefix: Any,
    request: AnalysisRequest,
    fix_rules: list[dict[str, Any]] | None,
    execution_mode: str,
    attempt_target_class: str | None,
) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    for assessment in assessments:
        if assessment.result not in (
            "violated",
            "native_absence",
            "indeterminate",
        ):
            continue
        rule = rules_by_requirement[assessment.requirement_id]
        signals = rule["signals"]
        if assessment.result == "violated":
            attribution = "supported"
            symptom = (
                f"requirement {assessment.requirement_id} violated under "
                "valid exposed opportunity"
            )
            causal_role = "primary"
        elif assessment.result == "native_absence":
            attribution = "supported"
            symptom = (
                f"requirement {assessment.requirement_id} unmet: required "
                "native capability evidenced absent in the exact scope"
            )
            causal_role = "primary"
        else:
            attribution = "unknown"
            symptom = (
                f"requirement {assessment.requirement_id} indeterminate: "
                f"{assessment.rationale}"
            )
            causal_role = "not_applicable"
        finding_id = f"F-{assessment.requirement_id}-{assessment.facet}"
        unsupported_hits = _signal_hits(decoded, signals.get("unsupported"))
        suggested_fix = _suggest_fix(
            channel_id,
            finding_id,
            assessment.requirement_id,
            assessment,
            attribution,
            request,
            fix_rules,
            unsupported_hits,
            prefix,
            signals,
            execution_mode,
            attempt_target_class,
        )
        findings.append(
            Finding(
                finding_id=finding_id,
                kind=_finding_kind_for(assessment.result),
                requirement_refs=(assessment.requirement_id,),
                symptom=symptom,
                scope=copy.deepcopy(assessment.scope),
                causal_role=causal_role,
                trigger_feature_refs=(),
                defect_locus=rule["defect_locus"],
                attribution=attribution,
                evidence_refs=assessment.evidence_refs,
                contrary_evidence_refs=assessment.contrary_evidence_refs,
                limitations=(),
                suggested_fix=suggested_fix,
            )
        )
    return tuple(findings)


# ---------------------------------------------------------------------------
# Document assembly
# ---------------------------------------------------------------------------


def _producer_completeness(
    decoded: list[tuple[Any, dict[str, Any]]], prefix: Any
) -> list[dict[str, Any]]:
    by_producer: dict[str, list[Any]] = {}
    for envelope, _data in decoded:
        by_producer.setdefault(envelope.producer_id, []).append(envelope)
    completeness: list[dict[str, Any]] = []
    for producer_id in sorted(by_producer):
        envelopes = sorted(
            by_producer[producer_id], key=lambda env: env.journal_sequence
        )
        sequences = sorted(
            env.journal_sequence
            for env in envelopes
            if isinstance(env.producer_sequence, int)
            and not isinstance(env.producer_sequence, bool)
        )
        ranges: list[dict[str, int]] = []
        for sequence in sequences:
            if ranges and sequence == ranges[-1]["last"] + 1:
                ranges[-1]["last"] = sequence
            else:
                ranges.append({"first": sequence, "last": sequence})
        refs = [
            _evidence_ref(prefix, envelopes[0]).to_dict(),
        ]
        if len(envelopes) > 1:
            refs.append(_evidence_ref(prefix, envelopes[-1]).to_dict())
        completeness.append(
            {
                "producer_id": producer_id,
                "state": "unknown",
                "observed_ranges": ranges,
                "missing_ranges": [],
                "final_sequence": Missing(
                    "not_observed",
                    "no evidenced producer closure in the named prefix",
                ).to_dict(),
                "evidence_refs": refs,
            }
        )
    return completeness


def _optional_digest(
    decoded: list[tuple[Any, dict[str, Any]]], key: str
) -> Any:
    for _envelope, data in decoded:
        value = data.get(key)
        if (
            isinstance(value, str)
            and value.startswith("sha256:")
            and len(value) == 71
            and all(c in "0123456789abcdef" for c in value[7:])
        ):
            return value
    return Missing(
        "not_observed", f"no {key} observed in the named prefix"
    )


def _assert_refs_within_prefix(document: DiagnosticDocument, prefix: Any) -> None:
    refs: list[Any] = [document.analysis_request_ref]
    for assessment in document.requirement_assessments:
        refs.extend(assessment.opportunity.evidence_refs)
        refs.extend(assessment.evidence_refs)
        refs.extend(assessment.contrary_evidence_refs)
        refs.extend(ref.evidence_ref for ref in assessment.capability_refs)
    for finding in document.findings:
        refs.extend(finding.evidence_refs)
        refs.extend(finding.contrary_evidence_refs)
        if isinstance(finding.suggested_fix, FixReference):
            refs.extend(finding.suggested_fix.evidence_refs)
    for item in document.measurements:
        refs.extend(item.evidence_refs)
    for ref in refs:
        if ref.journal_id != prefix.journal_id or (
            ref.sequence > prefix.last_sequence
        ):
            raise DiagnosticDerivationError(
                "diagnostic cites evidence outside its named prefix: "
                f"{ref.journal_id} sequence {ref.sequence}"
            )


# ---------------------------------------------------------------------------
# Public operation
# ---------------------------------------------------------------------------


def derive_diagnostic(
    channel_id: str,
    manifest: Manifest,
    prefix: JournalPrefix,
    request: AnalysisRequest,
) -> DiagnosticDocument:
    """Derive the immutable diagnostic for one named analysis prefix.

    The output is a deterministic function of ``manifest``, ``prefix``,
    and the classifier bundle pinned by ``request``.  No other evidence
    contributes: no wall-clock reads, no network lookups, no mutable rows,
    and nothing beyond the prefix's closing analysis request.
    """
    if not isinstance(channel_id, str) or not channel_id:
        raise DiagnosticDerivationError("channel_id must be a nonempty string")
    manifest = _coerce_manifest(manifest)
    prefix = _coerce_prefix(prefix)
    request = _coerce_request(request)

    try:
        events = evidence_journal.read_prefix(channel_id, prefix)
    except Exception as exc:
        raise DiagnosticDerivationError(
            f"named prefix is not readable or not intact: {exc}"
        ) from exc
    if not events:
        raise DiagnosticDerivationError("named prefix contains no events")
    if events[0].event_kind != "manifest_admitted" or (
        events[0].journal_sequence != 1
    ):
        raise DiagnosticDerivationError(
            "named prefix does not start at manifest admission"
        )
    if manifest.journal_id != prefix.journal_id:
        raise DiagnosticDerivationError(
            "manifest journal does not match the named prefix journal"
        )
    if manifest.run_id != events[0].run_id:
        raise DiagnosticDerivationError(
            "manifest run does not match the admitted journal run"
        )
    digest = _manifest_hash(manifest)
    if digest != events[0].manifest_hash:
        raise DiagnosticDerivationError(
            "manifest bytes do not match the admitted manifest digest; "
            "diagnostics never run on a substituted manifest"
        )

    decoded: list[tuple[Any, dict[str, Any]]] = [
        (envelope, dict(envelope.payload)) for envelope in events
    ]
    decoded_data: list[tuple[Any, dict[str, Any]]] = [
        (envelope, dict(payload.get("data", {})))
        for envelope, payload in decoded
    ]
    analysis_request_ref = _evidence_ref(prefix, events[-1])
    _check_analysis_request(events[-1], prefix, request)

    classifier_bytes = _resolve_pin(
        channel_id, request.classifier, "classifier"
    )
    registry_bytes = _resolve_pin(
        channel_id, request.requirement_registry, "requirement registry"
    )
    classifier_rules = _parse_classifier(classifier_bytes)
    requirements = _parse_requirement_registry(registry_bytes)
    fix_rules: list[dict[str, Any]] | None = None
    if isinstance(request.fix_registry, VersionPin):
        fix_rules = _parse_fix_registry(
            _resolve_pin(channel_id, request.fix_registry, "fix registry")
        )

    clocks = _manifest_clocks(manifest)
    measurements = _copy_measurements(
        [(envelope, dict(payload)) for envelope, payload in decoded],
        prefix,
        clocks,
    )

    rules_by_requirement = {
        rule["requirement_id"]: rule for rule in classifier_rules
    }
    registry_by_id = {
        item["requirement_id"]: item for item in requirements
    }
    limitations: list[str] = []
    for requirement_id in sorted(registry_by_id.keys() - rules_by_requirement.keys()):
        limitations.append(
            f"requirement {requirement_id} has no classifier rule in "
            f"{request.classifier.id}/{request.classifier.version}; not assessed"
        )
    for requirement_id in sorted(rules_by_requirement.keys() - registry_by_id.keys()):
        limitations.append(
            f"classifier rule for {requirement_id} names no requirement "
            f"in {request.requirement_registry.id}/"
            f"{request.requirement_registry.version}; ignored"
        )

    assessments: list[RequirementAssessment] = []
    for requirement in requirements:
        rule = rules_by_requirement.get(requirement["requirement_id"])
        if rule is None:
            continue
        assessments.append(
            _assess_requirement(
                requirement,
                rule,
                decoded_data,
                prefix,
                analysis_request_ref,
                limitations,
            )
        )

    execution = manifest.to_dict()["execution"]
    execution_mode = execution.get("mode", "")
    attempt_raw = manifest.to_dict()["attempt"]
    attempt_target_class: str | None = None
    if _as_missing(attempt_raw) is None and isinstance(attempt_raw, Mapping):
        target_class = attempt_raw.get("target_class")
        if isinstance(target_class, str):
            attempt_target_class = target_class

    findings = _build_findings(
        channel_id,
        assessments,
        rules_by_requirement,
        decoded_data,
        prefix,
        request,
        fix_rules,
        execution_mode,
        attempt_target_class,
    )
    findings_by_requirement: dict[str, list[str]] = {}
    for finding in findings:
        for requirement_id in finding.requirement_refs:
            findings_by_requirement.setdefault(requirement_id, []).append(
                finding.finding_id
            )
    assessments = [
        replace(
            assessment,
            finding_refs=tuple(
                findings_by_requirement.get(assessment.requirement_id, ())
            ),
        )
        for assessment in assessments
    ]

    classifier_label = f"{request.classifier.id}/{request.classifier.version}"
    not_enabled_profile = Missing(
        "not_enabled",
        f"behavioral analysis not implemented in classifier {classifier_label}",
    ).to_dict()
    not_enabled_fingerprint = Missing(
        "not_enabled",
        f"fingerprint analysis not implemented in classifier {classifier_label}",
    ).to_dict()
    document = DiagnosticDocument(
        record_type="diagnostic",
        schema_version=SCHEMA_VERSION,
        diagnostic_id=request.diagnostic_id,
        analysis_revision=request.analysis_revision,
        run_id=manifest.run_id,
        manifest_hash=digest,
        input_prefix=JournalPrefix(
            journal_id=prefix.journal_id,
            last_sequence=prefix.last_sequence,
            head_hash=prefix.head_hash,
        ),
        analysis_request_ref=analysis_request_ref,
        classifier=request.classifier,
        requirement_registry=request.requirement_registry,
        fix_registry=request.fix_registry,
        attempt=copy.deepcopy(attempt_raw),
        execution=copy.deepcopy(execution),
        delivered_task_hash=_optional_digest(decoded_data, "delivered_task_hash"),
        native_request_hash=_optional_digest(decoded_data, "native_request_hash"),
        validity={
            "scoped_checks": [],
            "producer_completeness": _producer_completeness(
                decoded_data, prefix
            ),
            "infrastructure_incidents": [],
            "limitations": list(limitations),
        },
        # This classifier version cites no descriptor artifacts, and manual
        # execution must never gain a subject descriptor.
        capability_descriptors=(),
        requirement_assessments=tuple(assessments),
        observed_actions=(),
        feature_exposures=(),
        steps=(),
        measurements=measurements,
        claims=(),
        findings=findings,
        observation={
            "opened_ref": _evidence_ref(prefix, events[0]).to_dict(),
            "closed_ref": Missing(
                "not_observed",
                "observation closure not established in the named prefix",
            ).to_dict(),
            "closure_reason": Missing(
                "not_observed",
                "closure reason not observed in the named prefix",
            ).to_dict(),
            "lifecycle_refs": [],
            "containment_refs": [],
            "late_evidence_refs": [],
        },
        application={
            "goal": "unknown",
            "as_of_sequence": prefix.last_sequence,
            "postconditions": [],
            "commitment_refs": [],
            "confirmation_refs": [],
        },
        behavioral_profile={
            "data": not_enabled_profile,
            "evidence_refs": [],
        },
        fingerprint_profile={
            "data": not_enabled_fingerprint,
            "evidence_refs": [],
        },
        artifacts=(),
    )

    _assert_refs_within_prefix(document, prefix)
    try:
        wrapper = (
            b'{"id":"attempt_diagnostics_gate","timing":'
            + _canonical_bytes(document.to_dict())
            + b"}"
        )
        contract_codec.validate_record(wrapper, _CODEC_GATE_SCHEMA)
    except (TypeError, ValueError) as exc:
        raise DiagnosticDerivationError(
            f"derived diagnostic failed the strict JSON gate: {exc}"
        ) from exc
    return document


def reset_for_tests() -> None:
    """Reset module state (derivation is pure; nothing is retained)."""
    return None

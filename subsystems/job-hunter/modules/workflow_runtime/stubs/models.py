"""Shared domain types for workflow_runtime's CONSUMES stub dependencies.

These are plain, dependency-owned record shapes (no behavior, no I/O).
The composition root (``src``) may import these types; nothing here imports
``src`` back, preserving the composition-root boundary.

Missing optionality uses the typed :class:`Missing` envelope — never None.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Union

__all__ = [
    "MISSING",
    "Missing",
    "AnalysisRequest",
    "ArtifactChunk",
    "ArtifactInventory",
    "ArtifactReference",
    "AttemptCommission",
    "AxisRevision",
    "ConnectorDescriptor",
    "ConnectorError",
    "ConnectorRequest",
    "ControlReceipt",
    "DataDomainRevision",
    "DiagnosticDocument",
    "EvaluationArtifact",
    "EvaluationPolicyPins",
    "EventSubmission",
    "EvidenceRef",
    "JobDownstreamValue",
    "JournalEnvelope",
    "JournalPrefix",
    "LeaseRecord",
    "LogicalRow",
    "Manifest",
    "MaterialPackage",
    "ObservationPage",
    "ObservationValue",
    "PrepareResult",
    "PublicationReceipt",
    "QueryArtifact",
    "RankingArtifact",
    "ReplayReceipt",
    "ReportInputPins",
    "ReportValue",
    "ResourceReference",
    "RetentionPinRevision",
    "StartResult",
    "EntityRegistration",
    "VersionPin",
]


class Missing:
    """Typed envelope for an absent optional field (no in-band nulls)."""

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return "Missing()"

    def __bool__(self) -> bool:
        return False


MISSING = Missing()


@dataclass(frozen=True)
class ArtifactReference:
    artifact_id: str
    channel_id: str = ""
    media_type: str = "application/octet-stream"
    digest: str = ""
    access: str = "restricted"


@dataclass(frozen=True)
class Manifest:
    manifest_id: str
    attempt_kind: str  # "production" | "practice"
    candidate: str = ""
    job_snapshot: str = ""
    target: str = ""
    task: str = ""
    execution_config: str = ""
    owner_bindings: tuple = ()
    permissions: tuple = ()
    idempotency_key: str = ""
    principal: str = ""
    origin: str = ""  # "employer" (held_out) | "fixture" (held_in)
    automation_subject: Union[str, Missing] = MISSING
    connector_version: Union[str, Missing] = MISSING
    binding_version: Union[str, Missing] = MISSING


@dataclass(frozen=True)
class AttemptCommission:
    attempt_id: str
    kind: str  # "production" | "practice"
    candidate: str = ""
    job_snapshot: str = ""
    target: str = ""
    task: str = ""
    execution_config: str = ""
    owner_bindings: tuple = ()
    permissions: tuple = ()
    origin: str = ""
    derived_from: Union[str, Missing] = MISSING
    rehearsal_of: Union[str, Missing] = MISSING
    performance_of: Union[str, Missing] = MISSING


@dataclass(frozen=True)
class EventSubmission:
    event_type: str
    payload: str = ""
    provenance: str = ""  # "manual" | "connector" | "system"


@dataclass(frozen=True)
class JournalEnvelope:
    sequence: int
    owner_domain: str
    event_type: str
    payload: str = ""


@dataclass(frozen=True)
class JournalPrefix:
    channel_id: str
    head_sequence: int = 0


@dataclass(frozen=True)
class ResourceReference:
    resource_id: str
    owner_domain: str = ""


@dataclass(frozen=True)
class LeaseRecord:
    lease_id: str
    resource_id: str = ""
    holder: str = ""
    state: str = "held"


@dataclass(frozen=True)
class VersionPin:
    name: str
    version: str = ""


@dataclass(frozen=True)
class EntityRegistration:
    entity_id: str
    owner_domain: str = ""


@dataclass(frozen=True)
class PublicationReceipt:
    publication_id: str
    view_id: str = ""


@dataclass(frozen=True)
class LogicalRow:
    row_id: str
    seal_name: str = ""
    view_id: str = ""
    payload: str = ""


@dataclass(frozen=True)
class QueryArtifact:
    query_id: str
    family: str = ""
    board: str = ""


@dataclass(frozen=True)
class ConnectorRequest:
    verb: str
    attempt_id: str = ""
    task: str = ""
    stability_key: str = ""
    payload: str = ""


@dataclass(frozen=True)
class ArtifactInventory:
    items: tuple = ()


@dataclass(frozen=True)
class ArtifactChunk:
    chunk_id: str = ""
    data: bytes = b""


@dataclass(frozen=True)
class ConnectorError:
    code: str = ""
    message: str = ""


@dataclass(frozen=True)
class EvidenceRef:
    evidence_id: str = ""


@dataclass(frozen=True)
class RetentionPinRevision:
    pin_id: str = ""
    revision: int = 0


@dataclass(frozen=True)
class MaterialPackage:
    package_id: str = ""
    items: tuple = ()


@dataclass(frozen=True)
class ObservationValue:
    axis: str = ""
    value: str = ""
    provenance: str = "manual"


@dataclass(frozen=True)
class AxisRevision:
    axis: str = ""
    revision: int = 0
    value: str = ""


@dataclass(frozen=True)
class ConnectorDescriptor:
    subject: str = ""
    version: str = ""


@dataclass(frozen=True)
class PrepareResult:
    handle: str = ""
    ready: bool = True


@dataclass(frozen=True)
class StartResult:
    handle: str = ""
    dispatch_revision: int = 0


@dataclass(frozen=True)
class ObservationPage:
    handle: str = ""
    events: tuple = ()
    complete: bool = False


@dataclass(frozen=True)
class ControlReceipt:
    control: str = ""
    accepted: bool = True


@dataclass(frozen=True)
class ReportInputPins:
    pins: tuple = ()


@dataclass(frozen=True)
class ReportValue:
    report_id: str = ""
    content: str = ""
    stale: bool = False
    subject_comparison: Union[str, Missing] = MISSING


@dataclass(frozen=True)
class EvaluationPolicyPins:
    pins: tuple = ()


@dataclass(frozen=True)
class EvaluationArtifact:
    evaluation_id: str = ""
    score: str = ""


@dataclass(frozen=True)
class RankingArtifact:
    ranking_id: str = ""
    order: tuple = ()


@dataclass(frozen=True)
class JobDownstreamValue:
    value_id: str = ""
    content: str = ""


@dataclass(frozen=True)
class DataDomainRevision:
    revision: int = 0
    value_id: str = ""


@dataclass(frozen=True)
class AnalysisRequest:
    analysis_id: str = ""
    method: str = ""


@dataclass(frozen=True)
class DiagnosticDocument:
    diagnostic_id: str = ""
    findings: tuple = ()


@dataclass(frozen=True)
class ReplayReceipt:
    replay_id: str = ""
    matched: bool = True

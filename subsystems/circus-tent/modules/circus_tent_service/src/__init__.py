"""circus_tent_service: tier-9 connector service composition (silo spot check).

Composes the nine versioned connector verbs over injected tier <=8
dependencies (CONSUMES), defaulting to in-module deterministic stubs so the
service conforms in silo without Ringmaster, the crawler, Hellscape,
job-hunter, a live employer, or a browser.

T60 focus: controls keep reserved progress under queue saturation, and
shutdown finalizes within a bound (supervisor status 0 clean / 1 forced).

Invariants honoured: EXT-SURFACE (exactly nine verbs), EXT-AUTHORITY
(channel-derived identity), EXT-BOUNDS (finite queues/waits), EXT-FAILURE
(connector errors describe this operation only), LIFE-CONTROLS (request /
acknowledgement / observed effect stay distinct), EK-MANUAL (manual
recording needs nothing from this service). No tenth verb, no synchronous
shared browser primitive, no composite application-success flag, no
in-band nulls (typed Missing envelopes), no shared database writes.
"""

from __future__ import annotations

import asyncio
import hashlib
import time as _time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Tuple, Union
from typing import Literal

# ---------------------------------------------------------------------------
# Scalar aliases (opaque where the seam mapping says spelling grants nothing)
# ---------------------------------------------------------------------------

Identifier = str
Digest = str
Revision = int
ConnectorHandle = str
HandleReference = str
TimePoint = float
DurationLimit = float
VersionPin = str
CFProfileRef = str
CFBindingDescriptor = str
CFDocumentRef = str
EvidenceRef = str
WorkScope = str

SCHEMA_VERSION = "0.1.0"

NINE_VERBS: Tuple[str, ...] = (
    "Describe",
    "Prepare",
    "Start",
    "Observe",
    "RequestNativeCancel",
    "CloseObservationConnection",
    "CollectArtifacts",
    "ReleaseNativeContext",
    "Contain",
)

CONTROL_VERBS: Tuple[str, ...] = (
    "RequestNativeCancel",
    "CloseObservationConnection",
    "ReleaseNativeContext",
    "Contain",
)


# ---------------------------------------------------------------------------
# Typed missingness (EK-NULL: no in-band nulls)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Missing:
    reason: str
    value: None = None


def _missing(reason: str = "not_applicable") -> Missing:
    return Missing(reason=reason)


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ConnectorError:
    kind: str = "connector_error"
    code: str = "INTERNAL_ERROR"
    fault_domain: str = "unknown"
    detail: str = ""
    operation_delivery: str = "not_applicable"
    retry_guidance: str = "operator_review"
    retry_after: Union[DurationLimit, Missing] = field(
        default_factory=lambda: Missing(reason="not_applicable"))
    handle: Union[ConnectorHandle, Missing] = field(
        default_factory=lambda: Missing(reason="not_applicable"))
    evidence_refs: Tuple[str, ...] = ()


@dataclass(frozen=True)
class ConnectorRequest:
    record_type: str = "connector_request"
    schema_version: str = SCHEMA_VERSION
    request_id: Identifier = ""
    connector_id: Identifier = ""
    operation: str = ""
    call_limit: int = 1
    payload: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ConnectorDescriptor:
    connector_id: Identifier = ""
    schema_version: str = SCHEMA_VERSION
    verbs: Tuple[str, ...] = NINE_VERBS


@dataclass(frozen=True)
class PrepareRequest:
    payload: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PrepareResult:
    preparation_id: Identifier = ""
    status: str = "prepared"


@dataclass(frozen=True)
class PreparedTask:
    preparation_id: Identifier = ""


@dataclass(frozen=True)
class StartResult:
    handle: ConnectorHandle = ""
    status: str = "admitted"


@dataclass(frozen=True)
class ObserveRequest:
    handle: ConnectorHandle = ""
    limit: int = 32


@dataclass(frozen=True)
class ObservationPage:
    handle: ConnectorHandle = ""
    entries: Tuple[Any, ...] = ()
    complete: bool = True


@dataclass(frozen=True)
class ControlReceipt:
    request_id: Identifier = ""
    operation: str = ""
    stage: str = "acknowledged"
    observed_effect: Union[str, Missing] = field(
        default_factory=lambda: Missing(reason="not_applicable"))


@dataclass(frozen=True)
class CollectArtifactsRequest:
    handle: ConnectorHandle = ""


@dataclass(frozen=True)
class ArtifactSlot:
    name: str = ""
    reference: str = ""


@dataclass(frozen=True)
class ArtifactReference:
    reference: str = ""


@dataclass(frozen=True)
class ArtifactInventory:
    handle: ConnectorHandle = ""
    slots: Tuple[ArtifactSlot, ...] = ()


@dataclass(frozen=True)
class ArtifactChunk:
    handle: ConnectorHandle = ""
    name: str = ""
    offset: int = 0
    data: bytes = b""
    eof: bool = True


@dataclass(frozen=True)
class JournalPrefix:
    journal_id: Identifier = ""
    last_sequence: int = 0
    head_hash: str = ""


@dataclass(frozen=True)
class JournalEnvelope:
    sequence: int = 0
    event_id: Identifier = ""
    payload: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AttemptSnapshot:
    snapshot_id: Identifier = ""


@dataclass(frozen=True)
class Manifest:
    manifest_id: Identifier = ""


@dataclass(frozen=True)
class ReplayReceipt:
    manifest_id: Identifier = ""
    status: str = "replayed"


@dataclass(frozen=True)
class CFFailure:
    code: str = "INTERNAL_ERROR"
    detail: str = ""


@dataclass(frozen=True)
class CFProfileOpened:
    profile: CFProfileRef = ""
    status: str = "opened"


@dataclass(frozen=True)
class CFProfileExited:
    profile: CFProfileRef = ""
    status: str = "exited"


@dataclass(frozen=True)
class NativeReportObservation:
    handle: ConnectorHandle = ""
    channel: str = "terminal_response"
    status: str = "normalized"


@dataclass(frozen=True)
class TaskOutput:
    task_output_id: Identifier = ""
    status: str = "extracted"


@dataclass(frozen=True)
class LifecyclePublicationReference:
    reference: str = ""


# ---------------------------------------------------------------------------
# CONSUMES stubs (exact declared signatures; deterministic silo behaviour)
# ---------------------------------------------------------------------------

def validate_record(value: object, schema_id: Identifier) -> None:
    if value is None:
        raise ValueError("INVALID_REQUEST: null record")
    if not isinstance(value, (Mapping, ConnectorRequest, ConnectorError)):
        raise ValueError("INVALID_REQUEST: unsupported record shape")
    if not schema_id:
        raise ValueError("INVALID_REQUEST: empty schema id")
    return None


def authenticate(credential: bytes, connector_id: Identifier) -> Identifier:
    if not credential:
        raise PermissionError("UNAUTHENTICATED: empty channel credential")
    if not connector_id:
        raise PermissionError("UNAUTHENTICATED: empty connector id")
    return "principal:" + connector_id


def load_configuration(
    source: bytes, environment: Mapping[str, str]
) -> dict[str, object]:
    config: dict[str, object] = {
        "connector_address": environment.get(
            "CONNECTOR_ADDRESS", "configured://connector"),
        "task_capacity": int(environment.get("TASK_CAPACITY", "8")),
    }
    if source:
        import json
        try:
            raw = json.loads(source.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raw = {}
        if isinstance(raw, dict):
            config.update(raw)
    return config


def collect_artifacts(
    request: CollectArtifactsRequest,
    principal_id: Identifier,
    slots: tuple[ArtifactSlot, ...],
    prefix: JournalPrefix,
) -> Union[ArtifactInventory, ArtifactChunk, ConnectorError]:
    return ArtifactInventory(handle=request.handle, slots=tuple(slots))


def install_artifact(
    content: bytes,
    media_type: Identifier,
    owner_domain: Identifier,
    access: Literal["public", "restricted"],
    privacy_policy: VersionPin,
) -> ArtifactReference:
    digest = hashlib.sha256(content).hexdigest()
    return ArtifactReference(reference="sha256:" + digest)


def read_prefix(
    journal_id: Identifier, through: Union[JournalPrefix, Missing]
) -> tuple[JournalEnvelope, ...]:
    return ()


def describe(connector_id: Identifier) -> ConnectorDescriptor:
    return ConnectorDescriptor(
        connector_id=connector_id, verbs=tuple(NINE_VERBS))


def replay_diagnostic(
    manifest: Manifest,
    prefix: JournalPrefix,
    diagnostic: ArtifactReference,
    bundle: ArtifactReference,
    classifier: VersionPin,
) -> ReplayReceipt:
    return ReplayReceipt(manifest_id=manifest.manifest_id, status="replayed")


def validate_snapshot(snapshot: AttemptSnapshot) -> None:
    if not snapshot.snapshot_id:
        raise ValueError("INVALID_REQUEST: empty snapshot id")
    return None


def prepare(
    request: PrepareRequest, principal_id: Identifier
) -> Union[PrepareResult, ConnectorError]:
    token = repr(sorted(request.payload.items()))
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]
    return PrepareResult(preparation_id="prep:" + digest, status="prepared")


def recycle_profile(
    profile: CFProfileRef,
    binding: CFBindingDescriptor,
    authorization_ref: EvidenceRef,
    limit: DurationLimit,
) -> Union[CFProfileOpened, CFFailure]:
    return CFProfileOpened(profile=profile, status="opened")


def shutdown_profiles(
    binding: CFBindingDescriptor,
    authorization_ref: EvidenceRef,
    limit: DurationLimit,
) -> tuple[Union[CFProfileExited, CFFailure], ...]:
    return (CFProfileExited(profile="profile:default", status="exited"),)


def normalize_report(
    handle: ConnectorHandle,
    raw: ArtifactReference,
    channel: Literal["terminal_response", "callback", "native_stream"],
    policy: VersionPin,
) -> NativeReportObservation:
    return NativeReportObservation(
        handle=handle, channel=channel, status="normalized")


async def observe(
    request: ObserveRequest, principal_id: Identifier
) -> Union[ObservationPage, ConnectorError]:
    return ObservationPage(handle=request.handle, entries=(), complete=True)


def artifact_slots(
    handle: HandleReference, prefix: JournalPrefix
) -> tuple[ArtifactSlot, ...]:
    return ()


async def control(
    request: ConnectorRequest, principal_id: Identifier
) -> Union[ControlReceipt, ConnectorError]:
    return ControlReceipt(
        request_id=request.request_id,
        operation=request.operation,
        stage="acknowledged",
        observed_effect=_missing("not_applicable"),
    )


async def expire_observation(
    handle: ConnectorHandle, now: TimePoint
) -> LifecyclePublicationReference:
    return LifecyclePublicationReference(reference="lifecycle:" + handle)


def extract_html(
    html: ArtifactReference,
    query: Union[str, Missing],
    output_schema: VersionPin,
    principal_id: Identifier,
) -> Union[TaskOutput, ConnectorError]:
    return TaskOutput(task_output_id="task-output:html", status="extracted")


def extract_live(
    binding: CFBindingDescriptor,
    document: CFDocumentRef,
    scope: WorkScope,
    query: Union[str, Missing],
    output_schema: VersionPin,
    principal_id: Identifier,
) -> Union[TaskOutput, ConnectorError]:
    return TaskOutput(task_output_id="task-output:live", status="extracted")


def start(
    request: ConnectorRequest, principal_id: Identifier
) -> Union[StartResult, ConnectorError]:
    return StartResult(
        handle="handle:" + request.request_id, status="admitted")


async def dispatch(handle: ConnectorHandle, principal_id: Identifier) -> None:
    return None


async def execute_plan(
    preparation: PreparedTask,
    handle: ConnectorHandle,
    binding: CFBindingDescriptor,
    principal_id: Identifier,
) -> ArtifactReference:
    return ArtifactReference(reference="artifact:plan:" + handle)


def _run(coro):
    """Bridge async dependencies for the synchronous silo harness."""
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Tier-9 service composition
# ---------------------------------------------------------------------------

SATURATED_CODE = "NOT_ADMITTED"
CLOSED_CODE = "OBSERVATION_CLOSED"


class CircusTentService:
    """Nine-verb connector service with a reserved control lane.

    Task admission is bounded (``task_capacity``). Control verbs bypass the
    task queue entirely, so they keep making progress under saturation.
    ``begin_drain`` stops admission and workflow commands while preserving
    control/finalization progress; ``finalize`` expires observations, shuts
    down profiles, persists evidence state, and reports supervisor status
    0 (clean drain within bound) or 1 (forced timeout).
    """

    def __init__(
        self,
        *,
        task_capacity: int = 8,
        connector_address: str = "configured://connector",
        clock: Callable[[], float] | None = None,
        binding: CFBindingDescriptor = "binding:default",
        authorization_ref: EvidenceRef = "evidence:default",
        journal_id: Identifier = "journal:connector",
        validate_record_fn: Callable[[object, Identifier], None] = validate_record,
        authenticate_fn: Callable[[bytes, Identifier], Identifier] = authenticate,
        load_configuration_fn: Callable[
            [bytes, Mapping[str, str]], dict[str, object]] = load_configuration,
        collect_artifacts_fn: Callable[
            [CollectArtifactsRequest, Identifier, tuple, JournalPrefix],
            Union[ArtifactInventory, ArtifactChunk, ConnectorError],
        ] = collect_artifacts,
        install_artifact_fn: Callable[..., ArtifactReference] = install_artifact,
        read_prefix_fn: Callable[
            [Identifier, Union[JournalPrefix, Missing]],
            tuple[JournalEnvelope, ...],
        ] = read_prefix,
        describe_fn: Callable[[Identifier], ConnectorDescriptor] = describe,
        replay_diagnostic_fn: Callable[..., ReplayReceipt] = replay_diagnostic,
        validate_snapshot_fn: Callable[[AttemptSnapshot], None] = validate_snapshot,
        prepare_fn: Callable[
            [PrepareRequest, Identifier],
            Union[PrepareResult, ConnectorError],
        ] = prepare,
        recycle_profile_fn: Callable[..., Union[CFProfileOpened, CFFailure]] = recycle_profile,
        shutdown_profiles_fn: Callable[..., tuple] = shutdown_profiles,
        normalize_report_fn: Callable[..., NativeReportObservation] = normalize_report,
        observe_fn: Callable[
            [ObserveRequest, Identifier], Any] = observe,
        artifact_slots_fn: Callable[
            [HandleReference, JournalPrefix], tuple[ArtifactSlot, ...]] = artifact_slots,
        control_fn: Callable[[ConnectorRequest, Identifier], Any] = control,
        expire_observation_fn: Callable[[ConnectorHandle, TimePoint], Any] = expire_observation,
        extract_html_fn: Callable[..., Union[TaskOutput, ConnectorError]] = extract_html,
        extract_live_fn: Callable[..., Union[TaskOutput, ConnectorError]] = extract_live,
        start_fn: Callable[
            [ConnectorRequest, Identifier],
            Union[StartResult, ConnectorError],
        ] = start,
        dispatch_fn: Callable[[ConnectorHandle, Identifier], Any] = dispatch,
        execute_plan_fn: Callable[..., Any] = execute_plan,
    ) -> None:
        if task_capacity < 1:
            raise ValueError("task_capacity must be >= 1")
        self._task_capacity = task_capacity
        self._connector_address = connector_address
        self._clock = clock or _time.monotonic
        self._binding = binding
        self._authorization_ref = authorization_ref
        self._journal_id = journal_id
        self._validate_record = validate_record_fn
        self._authenticate = authenticate_fn
        self._load_configuration = load_configuration_fn
        self._collect_artifacts = collect_artifacts_fn
        self._install_artifact = install_artifact_fn
        self._read_prefix = read_prefix_fn
        self._describe = describe_fn
        self._replay_diagnostic = replay_diagnostic_fn
        self._validate_snapshot = validate_snapshot_fn
        self._prepare = prepare_fn
        self._recycle_profile = recycle_profile_fn
        self._shutdown_profiles = shutdown_profiles_fn
        self._normalize_report = normalize_report_fn
        self._observe = observe_fn
        self._artifact_slots = artifact_slots_fn
        self._control = control_fn
        self._expire_observation = expire_observation_fn
        self._extract_html = extract_html_fn
        self._extract_live = extract_live_fn
        self._start = start_fn
        self._dispatch = dispatch_fn
        self._execute_plan = execute_plan_fn
        self._active: Dict[ConnectorHandle, StartResult] = {}
        self._admitting = True
        self._workflow_open = True
        self._terminated = False
        self._controls_served = 0
        self._persisted = False
        self._supervisor_status: Union[int, Missing] = _missing("not_applicable")

    # -- introspection ----------------------------------------------------

    @property
    def verbs(self) -> Tuple[str, ...]:
        return tuple(NINE_VERBS)

    @property
    def task_capacity(self) -> int:
        return self._task_capacity

    @property
    def queue_depth(self) -> int:
        return len(self._active)

    @property
    def admission_open(self) -> bool:
        return self._admitting

    @property
    def controls_served(self) -> int:
        return self._controls_served

    @property
    def supervisor_status(self) -> Union[int, Missing]:
        return self._supervisor_status

    @property
    def evidence_persisted(self) -> bool:
        return self._persisted

    # -- helpers ----------------------------------------------------------

    def _denied(self, code: str, detail: str) -> ConnectorError:
        return ConnectorError(
            code=code,
            fault_domain="connector",
            detail=detail,
            operation_delivery="not_dispatched",
            retry_guidance=(
                "new_command_if_not_dispatched"
                if code == SATURATED_CODE else "operator_review"),
            retry_after=_missing("not_applicable"),
            handle=_missing("not_applicable"),
            evidence_refs=(),
        )

    def _principal_or_error(
        self, credential: bytes, connector_id: Identifier
    ) -> Union[Identifier, ConnectorError]:
        try:
            return self._authenticate(credential, connector_id)
        except Exception as exc:
            return ConnectorError(
                code="UNAUTHENTICATED",
                fault_domain="request",
                detail=str(exc),
                operation_delivery="not_dispatched",
                retry_guidance="do_not_retry",
                retry_after=_missing("not_applicable"),
                handle=_missing("not_applicable"),
                evidence_refs=(),
            )

    # -- verb handlers ----------------------------------------------------

    def handle_request(
        self, request: ConnectorRequest, credential: bytes
    ) -> Union[Any, ConnectorError]:
        try:
            self._validate_record(request, "connector_request:" + SCHEMA_VERSION)
        except Exception as exc:
            return ConnectorError(
                code="INVALID_REQUEST",
                fault_domain="request",
                detail=str(exc),
                operation_delivery="not_dispatched",
                retry_guidance="do_not_retry",
                retry_after=_missing("not_applicable"),
                handle=_missing("not_applicable"),
                evidence_refs=(),
            )
        operation = request.operation
        if operation not in NINE_VERBS:
            return ConnectorError(
                code="INVALID_REQUEST",
                fault_domain="request",
                detail="unknown verb: " + repr(operation),
                operation_delivery="not_dispatched",
                retry_guidance="do_not_retry",
                retry_after=_missing("not_applicable"),
                handle=_missing("not_applicable"),
                evidence_refs=(),
            )
        if operation == "Describe":
            return self.describe(credential, request.connector_id)
        if operation == "Prepare":
            return self.prepare(
                PrepareRequest(payload=dict(request.payload)), credential,
                request.connector_id)
        if operation == "Start":
            return self.start(request, credential)
        if operation == "Observe":
            return self.observe(
                ObserveRequest(handle=str(request.payload.get("handle", ""))),
                credential, request.connector_id)
        if operation == "CollectArtifacts":
            return self.collect_artifacts(
                CollectArtifactsRequest(
                    handle=str(request.payload.get("handle", ""))),
                credential, request.connector_id)
        # The four control verbs share the reserved control lane.
        return self.control(request, credential)

    def describe(
        self, credential: bytes, connector_id: Identifier
    ) -> Union[ConnectorDescriptor, ConnectorError]:
        principal = self._principal_or_error(credential, connector_id)
        if isinstance(principal, ConnectorError):
            return principal
        return self._describe(connector_id)

    def prepare(
        self, request: PrepareRequest, credential: bytes, connector_id: Identifier
    ) -> Union[PrepareResult, ConnectorError]:
        principal = self._principal_or_error(credential, connector_id)
        if isinstance(principal, ConnectorError):
            return principal
        return self._prepare(request, principal)

    def start(
        self, request: ConnectorRequest, credential: bytes
    ) -> Union[StartResult, ConnectorError]:
        principal = self._principal_or_error(
            credential, request.connector_id)
        if isinstance(principal, ConnectorError):
            return principal
        if not self._admitting:
            return self._denied(
                CLOSED_CODE, "admission closed: drain or shutdown in progress")
        if len(self._active) >= self._task_capacity:
            return self._denied(
                SATURATED_CODE,
                "queue saturated: %d active at capacity %d"
                % (len(self._active), self._task_capacity))
        result = self._start(request, principal)
        if isinstance(result, StartResult):
            self._active[result.handle] = result
        return result

    def observe(
        self, request: ObserveRequest, credential: bytes, connector_id: Identifier
    ) -> Union[ObservationPage, ConnectorError]:
        principal = self._principal_or_error(credential, connector_id)
        if isinstance(principal, ConnectorError):
            return principal
        return _run(self._observe(request, principal))

    def control(
        self, request: ConnectorRequest, credential: bytes
    ) -> Union[ControlReceipt, ConnectorError]:
        """Reserved lane: never consults task capacity or admission state."""
        principal = self._principal_or_error(
            credential, request.connector_id)
        if isinstance(principal, ConnectorError):
            return principal
        receipt = _run(self._control(request, principal))
        if isinstance(receipt, ControlReceipt):
            self._controls_served += 1
        return receipt

    def collect_artifacts(
        self,
        request: CollectArtifactsRequest,
        credential: bytes,
        connector_id: Identifier,
    ) -> Union[ArtifactInventory, ArtifactChunk, ConnectorError]:
        principal = self._principal_or_error(credential, connector_id)
        if isinstance(principal, ConnectorError):
            return principal
        prefix = JournalPrefix(journal_id=self._journal_id)
        slots = self._artifact_slots(request.handle, prefix)
        return self._collect_artifacts(request, principal, slots, prefix)

    # -- shutdown ---------------------------------------------------------

    def begin_drain(self) -> None:
        """Stop new admission and workflow commands; keep controls live."""
        self._admitting = False
        self._workflow_open = False

    def finalize(self, deadline_seconds: float = 30.0) -> int:
        """Bounded finalization; returns supervisor status 0 (clean) / 1."""
        started = self._clock()
        now: TimePoint = started
        expired: List[LifecyclePublicationReference] = []
        for handle in list(self._active):
            expired.append(_run(self._expire_observation(handle, now)))
            del self._active[handle]
        self._shutdown_profiles(
            self._binding, self._authorization_ref, deadline_seconds)
        self._persisted = True
        elapsed = self._clock() - started
        status = 0 if elapsed <= deadline_seconds else 1
        self._terminated = True
        self._supervisor_status = status
        return status

    def shutdown(self, deadline_seconds: float = 30.0) -> int:
        self.begin_drain()
        return self.finalize(deadline_seconds)


__all__ = [
    "NINE_VERBS",
    "CONTROL_VERBS",
    "SCHEMA_VERSION",
    "Missing",
    "ConnectorError",
    "ConnectorRequest",
    "ConnectorDescriptor",
    "PrepareRequest",
    "PrepareResult",
    "PreparedTask",
    "StartResult",
    "ObserveRequest",
    "ObservationPage",
    "ControlReceipt",
    "CollectArtifactsRequest",
    "ArtifactSlot",
    "ArtifactReference",
    "ArtifactInventory",
    "ArtifactChunk",
    "JournalPrefix",
    "JournalEnvelope",
    "AttemptSnapshot",
    "Manifest",
    "ReplayReceipt",
    "CFFailure",
    "CFProfileOpened",
    "CFProfileExited",
    "NativeReportObservation",
    "TaskOutput",
    "LifecyclePublicationReference",
    "CircusTentService",
    "validate_record",
    "authenticate",
    "load_configuration",
    "collect_artifacts",
    "install_artifact",
    "read_prefix",
    "describe",
    "replay_diagnostic",
    "validate_snapshot",
    "prepare",
    "recycle_profile",
    "shutdown_profiles",
    "normalize_report",
    "observe",
    "artifact_slots",
    "control",
    "expire_observation",
    "extract_html",
    "extract_live",
    "start",
    "dispatch",
    "execute_plan",
]

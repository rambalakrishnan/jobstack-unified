"""T60 conformance: controls under queue saturation.

Required result: reserved progress and bounded finalization.
"""

import os
import sys

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src import (  # noqa: E402
    CONTROL_VERBS,
    NINE_VERBS,
    CollectArtifactsRequest,
    ConnectorError,
    ConnectorRequest,
    ControlReceipt,
    ObserveRequest,
    StartResult,
    CircusTentService,
)


CRED = b"channel-credential"
CONNECTOR = "connector:tent"


def make_request(operation, request_id, payload=None):
    return ConnectorRequest(
        request_id=request_id,
        connector_id=CONNECTOR,
        operation=operation,
        call_limit=1,
        payload=dict(payload or {}),
    )


def test_T60_saturation_rejects_task_with_typed_error():
    service = CircusTentService(task_capacity=2)
    first = service.start(make_request("Start", "r-1"), CRED)
    second = service.start(make_request("Start", "r-2"), CRED)
    assert isinstance(first, StartResult)
    assert isinstance(second, StartResult)
    assert service.queue_depth == 2
    rejected = service.start(make_request("Start", "r-3"), CRED)
    assert isinstance(rejected, ConnectorError)
    assert rejected.code == "NOT_ADMITTED"
    assert rejected.operation_delivery == "not_dispatched"
    # Rejected work is not silently lost: explicit typed error, queue intact.
    assert service.queue_depth == 2


def test_T60_controls_keep_reserved_progress_when_saturated():
    service = CircusTentService(task_capacity=1)
    admitted = service.start(make_request("Start", "r-1"), CRED)
    assert isinstance(admitted, StartResult)
    saturated = service.start(make_request("Start", "r-2"), CRED)
    assert isinstance(saturated, ConnectorError)
    for index, verb in enumerate(CONTROL_VERBS):
        receipt = service.handle_request(
            make_request(verb, "c-%d" % index), CRED)
        assert isinstance(receipt, ControlReceipt), verb
        assert receipt.stage == "acknowledged", verb
        # Request is not acknowledgement of effect: observed effect stays
        # an explicit missing envelope, never an upgraded fact.
        assert receipt.observed_effect.reason == "not_applicable", verb
    assert service.controls_served == len(CONTROL_VERBS)


def test_T60_drain_stops_admission_but_preserves_controls():
    service = CircusTentService(task_capacity=4)
    admitted = service.start(make_request("Start", "r-1"), CRED)
    assert isinstance(admitted, StartResult)
    service.begin_drain()
    assert service.admission_open is False
    closed = service.start(make_request("Start", "r-2"), CRED)
    assert isinstance(closed, ConnectorError)
    assert closed.code == "OBSERVATION_CLOSED"
    receipt = service.handle_request(
        make_request("RequestNativeCancel", "c-1"), CRED)
    assert isinstance(receipt, ControlReceipt)
    assert receipt.stage == "acknowledged"


def test_T60_bounded_finalization_clean_drain_status_zero():
    service = CircusTentService(task_capacity=2)
    service.start(make_request("Start", "r-1"), CRED)
    service.start(make_request("Start", "r-2"), CRED)
    status = service.shutdown(deadline_seconds=30.0)
    assert status == 0
    assert service.supervisor_status == 0
    assert service.queue_depth == 0
    assert service.evidence_persisted is True


def test_T60_forced_timeout_reports_status_one():
    times = iter([0.0, 100.0])

    def clock():
        return next(times)

    service = CircusTentService(task_capacity=2, clock=clock)
    service.start(make_request("Start", "r-1"), CRED)
    status = service.shutdown(deadline_seconds=30.0)
    assert status == 1
    assert service.supervisor_status == 1
    assert service.queue_depth == 0


def test_T60_exactly_nine_verbs_no_tenth():
    service = CircusTentService()
    assert service.verbs == tuple(NINE_VERBS)
    assert len(service.verbs) == 9
    assert set(CONTROL_VERBS) <= set(service.verbs)
    tenth = service.handle_request(make_request("Qualify", "r-x"), CRED)
    assert isinstance(tenth, ConnectorError)
    assert tenth.code == "INVALID_REQUEST"


def test_T60_observe_and_artifacts_share_task_lane_not_control_lane():
    service = CircusTentService(task_capacity=8)
    page = service.observe(ObserveRequest(handle="handle:r-1"), CRED, CONNECTOR)
    assert page.complete is True
    inventory = service.collect_artifacts(
        CollectArtifactsRequest(handle="handle:r-1"), CRED, CONNECTOR)
    assert inventory.handle == "handle:r-1"

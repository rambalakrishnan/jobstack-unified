"""Conformance tests for access_policy (tier 0).

Covers exactly the ``-k`` filter named in the module spec:

- ``spoofed_provenance_or_writer_identity_is_rejected``
- ``secrets_in_ordinary_journal_task_or_log_are_rejected_or_quarantined``

Every check exercises the real module: channel registration, the bounded
write-grant table from seam mapping 2.3, untrusted EventSubmission ingress
(EK-PROVENANCE), and the secret screening/quarantine path (16.9, section 18).
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

try:  # installed editable into the module's own .venv
    import access_policy as ap
except ModuleNotFoundError:  # pragma: no cover - bare-interpreter fallback
    _spec = importlib.util.spec_from_file_location(
        "access_policy", Path(__file__).resolve().parents[1] / "src" / "__init__.py"
    )
    assert _spec is not None and _spec.loader is not None
    ap = importlib.util.module_from_spec(_spec)
    sys.modules["access_policy"] = ap
    _spec.loader.exec_module(ap)


@pytest.fixture(autouse=True)
def _fresh_state():
    ap.reset_for_tests()
    yield
    ap.reset_for_tests()


def _payload(
    data: dict[str, object] | None = None,
    measurements: tuple[object, ...] = (),
    evidence_refs: tuple[object, ...] = (),
    artifact_refs: tuple[object, ...] = (),
) -> dict[str, object]:
    return {
        "data": dict(data or {}),
        "measurements": list(measurements),
        "evidence_refs": list(evidence_refs),
        "artifact_refs": list(artifact_refs),
    }


def _timepoint() -> dict[str, object]:
    return {
        "clock_id": "clock-ingest-1",
        "boot_id": "boot-1",
        "origin": "engine_measured",
        "monotonic_offset_ms": 1024,
        "utc_annotation": ap.NOT_APPLICABLE,
    }


def _submission(
    kind: str = "discovery.source_observed",
    version: str = "1",
    sequence: object = 1,
    payload: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "producer_sequence": sequence,
        "event_kind": kind,
        "event_schema_version": version,
        "occurred_at": _timepoint(),
        "payload": _payload({"source": "board-a"}) if payload is None else payload,
    }


def _register_crawler(
    channel_id: str = "ch_crawler_ingress_0001",
    producer_id: str = "prod_crawler",
    principal_id: str = "principal_crawler",
    kinds: tuple[str, ...] = ("discovery.source_observed",),
) -> ap.ProducerDescriptor:
    return ap.register_channel(
        actor="crawler_writer",
        channel_id=channel_id,
        axis="job.crawler",
        producer_id=producer_id,
        principal_id=principal_id,
        sequence_required=True,
        allowed_event_kinds=kinds,
    )


# ---------------------------------------------------------------------------
# Assertion 1
# ---------------------------------------------------------------------------


def test_spoofed_provenance_or_writer_identity_is_rejected():
    crawler = _register_crawler()
    crawler_channel = "ch_crawler_ingress_0001"

    # Identity, role, provenance, and owner domain are assigned by the
    # authenticated registration, never chosen by the caller.
    assert crawler.role == "kernel"
    assert crawler.provenance == "server"
    assert crawler.owner_domain == "job.crawler"
    assert crawler.sequence_required is True
    assert crawler.to_dict() == {
        "producer_id": "prod_crawler",
        "principal_id": "principal_crawler",
        "owner_domain": "job.crawler",
        "role": "kernel",
        "provenance": "server",
        "sequence_required": True,
        "allowed_event_kinds": ["discovery.source_observed"],
    }

    # A role cannot be widened at registration time.
    with pytest.raises(ap.GrantDeniedError):
        ap.register_channel(
            actor="crawler_writer",
            channel_id="ch_crawler_escalation_0001",
            axis="attempt.execution",
            producer_id="prod_crawler_escalated",
            principal_id="principal_crawler",
            sequence_required=True,
            allowed_event_kinds=("attempt.execution_recorded",),
        )
    with pytest.raises(ap.GrantDeniedError):
        ap.register_channel(
            actor="reconciler",
            channel_id="ch_reconciler_escalation_0001",
            axis="attempt.execution",
            producer_id="prod_reconciler_escalated",
            principal_id="principal_reconciler",
            sequence_required=False,
            allowed_event_kinds=("attempt.report_recorded",),
        )
    with pytest.raises(ValueError):
        ap.register_channel(
            actor="unknown_writer",
            channel_id="ch_unknown_actor_0001",
            axis="job.crawler",
            producer_id="prod_unknown",
            principal_id="principal_unknown",
            sequence_required=False,
            allowed_event_kinds=("discovery.source_observed",),
        )

    # A producer id cannot be recycled or reassigned to another principal.
    with pytest.raises(ap.RegistrationConflictError):
        _register_crawler(
            channel_id="ch_crawler_replay_0001",
            principal_id="principal_spoofed",
        )
    with pytest.raises(ap.RegistrationConflictError):
        _register_crawler(
            channel_id="ch_crawler_duplicate_axis_0001",
            producer_id="prod_crawler_alt",
            principal_id="principal_crawler_alt",
        )

    # Authenticated ingress resolution: arbitrary caller-selected identities,
    # producer ids, and digests are not channel handles and not bearer grants.
    for forged_channel in (
        "ch_forged_ingress_0001",
        crawler.producer_id,
        crawler.principal_id,
        "sha256:" + "0" * 64,
    ):
        with pytest.raises(ap.UnknownChannelError):
            ap.authorize(forged_channel, "job.crawler.write", "job-1")

    # The registered descriptor is returned unchanged; the caller's strings
    # never influence identity.
    assert ap.authorize(crawler_channel, "job.crawler.write", "job-1") == crawler

    # Serialized writer/provenance labels in operation strings are rejected.
    with pytest.raises(ap.SpoofDetectedError):
        ap.authorize(
            crawler_channel, "job.crawler.write", "job-1;writer_id=prod_reconciler"
        )
    with pytest.raises(ap.SpoofDetectedError):
        ap.authorize(
            crawler_channel, "job.crawler.write;provenance=server", "job-1"
        )

    # Bounded write grants (seam mapping 2.3): one axis per writer.
    for denied_operation in (
        "job.downstream.write",
        "attempt.dispatch.write",
        "attempt.observation.write",
        "attempt.execution.write",
        "attempt.application.write",
        "attempt.report.write",
        "publication.pointer.write",
        "publication.seal.write",
        "attempt.status.write",
        "job.crawler.write+job.downstream.write",
        "connector.control",
    ):
        with pytest.raises(ap.GrantDeniedError):
            ap.authorize(crawler_channel, denied_operation, "resource-1")

    # Product writer owns only the downstream job domain.
    product_channel = "ch_product_ingress_0001"
    product = ap.register_channel(
        actor="product_writer",
        channel_id=product_channel,
        axis="job.downstream",
        producer_id="prod_product",
        principal_id="principal_product",
        sequence_required=False,
        allowed_event_kinds=("product.job_downstream_observed",),
    )
    assert ap.authorize(product_channel, "job.downstream.write", "job-9") == product
    with pytest.raises(ap.GrantDeniedError):
        ap.authorize(product_channel, "job.crawler.write", "job-9")

    # Connector writes only dispatch/observation, and only when bound.
    with pytest.raises(ap.GrantDeniedError):
        ap.register_channel(
            actor="connector",
            channel_id="ch_connector_unbound_0001",
            axis="attempt.dispatch",
            producer_id="prod_connector_unbound",
            principal_id="principal_connector",
            sequence_required=True,
            allowed_event_kinds=("attempt.dispatched",),
        )
    connector_binding = "binding:connector-primary"
    connector_dispatch_channel = "ch_connector_dispatch_0001"
    connector_observation_channel = "ch_connector_observation_0001"
    connector_dispatch = ap.register_channel(
        actor="connector",
        channel_id=connector_dispatch_channel,
        axis="attempt.dispatch",
        producer_id="prod_connector",
        principal_id="principal_connector",
        sequence_required=True,
        allowed_event_kinds=("attempt.dispatched",),
        binding=connector_binding,
    )
    connector_observation = ap.register_channel(
        actor="connector",
        channel_id=connector_observation_channel,
        axis="attempt.observation",
        producer_id="prod_connector",
        principal_id="principal_connector",
        sequence_required=True,
        allowed_event_kinds=("attempt.observation_recorded",),
        binding=connector_binding,
    )
    assert (
        ap.authorize(connector_dispatch_channel, "attempt.dispatch.write", "attempt-1")
        == connector_dispatch
    )
    assert (
        ap.authorize(
            connector_observation_channel, "attempt.observation.write", "attempt-1"
        )
        == connector_observation
    )
    for denied_operation in (
        "attempt.execution.write",
        "attempt.application.write",
        "attempt.report.write",
        "connector.control",
    ):
        with pytest.raises(ap.GrantDeniedError):
            ap.authorize(connector_dispatch_channel, denied_operation, "attempt-1")

    # Delegated subject adapter owns execution only, preserving subject
    # authorship (assigned provenance, not a submitted label).
    subject_channel = "ch_subject_ingress_0001"
    subject = ap.register_channel(
        actor="subject_adapter",
        channel_id=subject_channel,
        axis="attempt.execution",
        producer_id="prod_subject",
        principal_id="principal_subject",
        sequence_required=True,
        allowed_event_kinds=("attempt.execution_recorded",),
    )
    assert subject.provenance == "subject"
    assert ap.authorize(subject_channel, "attempt.execution.write", "attempt-1") == subject
    for denied_operation in (
        "attempt.application.write",
        "attempt.report.write",
        "attempt.dispatch.write",
    ):
        with pytest.raises(ap.GrantDeniedError):
            ap.authorize(subject_channel, denied_operation, "attempt-1")

    # Manual recorder: observation only; never dispatch or execution.
    manual_channel = "ch_manual_ingress_0001"
    manual = ap.register_channel(
        actor="manual_recorder",
        channel_id=manual_channel,
        axis="attempt.observation",
        producer_id="prod_manual",
        principal_id="principal_recruiter",
        sequence_required=False,
        allowed_event_kinds=("attempt.observation_recorded",),
    )
    assert manual.provenance == "manual_observer"
    assert ap.authorize(manual_channel, "attempt.observation.write", "attempt-1") == manual
    for denied_operation in (
        "attempt.dispatch.write",
        "attempt.execution.write",
        "attempt.application.write",
    ):
        with pytest.raises(ap.GrantDeniedError):
            ap.authorize(manual_channel, denied_operation, "attempt-1")

    # Origin fact recorder: application only, under a bound origin policy.
    with pytest.raises(ap.GrantDeniedError):
        ap.register_channel(
            actor="origin_fact_recorder",
            channel_id="ch_origin_unbound_0001",
            axis="attempt.application",
            producer_id="prod_origin_unbound",
            principal_id="principal_origin",
            sequence_required=True,
            allowed_event_kinds=("attempt.application_submitted",),
        )
    origin_channel = "ch_origin_ingress_0001"
    origin = ap.register_channel(
        actor="origin_fact_recorder",
        channel_id=origin_channel,
        axis="attempt.application",
        producer_id="prod_origin",
        principal_id="principal_origin",
        sequence_required=True,
        allowed_event_kinds=("attempt.application_submitted",),
        binding="binding:origin-policy-primary",
    )
    assert origin.provenance == "server"
    assert (
        ap.authorize(origin_channel, "attempt.application.write", "attempt-1") == origin
    )
    with pytest.raises(ap.GrantDeniedError):
        ap.authorize(origin_channel, "attempt.report.write", "attempt-1")

    # Reconciler: report only. The report writer must never hold execution or
    # application write authority.
    reconciler_channel = "ch_reconciler_ingress_0001"
    reconciler = ap.register_channel(
        actor="reconciler",
        channel_id=reconciler_channel,
        axis="attempt.report",
        producer_id="prod_reconciler",
        principal_id="principal_reconciler",
        sequence_required=True,
        allowed_event_kinds=("attempt.report_recorded",),
    )
    assert ap.authorize(reconciler_channel, "attempt.report.write", "attempt-1") == reconciler
    for denied_operation in (
        "attempt.execution.write",
        "attempt.application.write",
        "attempt.dispatch.write",
    ):
        with pytest.raises(ap.GrantDeniedError):
            ap.authorize(reconciler_channel, denied_operation, "attempt-1")

    # Read-view publisher: derived pointers and seals only.
    publisher_channel = "ch_publisher_ingress_0001"
    publisher = ap.register_channel(
        actor="read_view_publisher",
        channel_id=publisher_channel,
        axis="publication.derived",
        producer_id="prod_publisher",
        principal_id="principal_publisher",
        sequence_required=False,
        allowed_event_kinds=("publication.pointer_installed",),
    )
    assert ap.authorize(publisher_channel, "publication.pointer.write", "view-1") == publisher
    assert ap.authorize(publisher_channel, "publication.seal.write", "view-1") == publisher
    for denied_operation in (
        "publication.derived.write",
        "attempt.report.write",
        "job.crawler.write",
    ):
        with pytest.raises(ap.GrantDeniedError):
            ap.authorize(publisher_channel, denied_operation, "view-1")

    # Dashboard authenticates but holds no authoritative writes at all.
    dashboard_channel = "ch_dashboard_ingress_0001"
    ap.register_channel(
        actor="dashboard",
        channel_id=dashboard_channel,
        axis="presentation.dashboard",
        producer_id="prod_dashboard",
        principal_id="principal_operator",
        sequence_required=False,
        allowed_event_kinds=("dashboard.command_submitted",),
    )
    assert ap.grants_for_actor("dashboard") == frozenset()
    with pytest.raises(ap.GrantDeniedError):
        ap.authorize(dashboard_channel, "presentation.dashboard.write", "dashboard-1")
    with pytest.raises(ap.GrantDeniedError):
        ap.authorize(dashboard_channel, "job.crawler.write", "job-1")

    # Revocation ends the authenticated session and retires the producer id.
    ap.revoke_channel(subject_channel)
    with pytest.raises(ap.UnknownChannelError):
        ap.authorize(subject_channel, "attempt.execution.write", "attempt-1")
    with pytest.raises(ap.RegistrationConflictError):
        ap.register_channel(
            actor="subject_adapter",
            channel_id="ch_subject_ingress_retry_0001",
            axis="attempt.execution",
            producer_id="prod_subject",
            principal_id="principal_subject",
            sequence_required=True,
            allowed_event_kinds=("attempt.execution_recorded",),
        )

    # --- EK-PROVENANCE: untrusted submissions cannot assign identity -------
    ap.register_event_kind(
        "discovery.source_observed",
        "1",
        role="external_input",
        assertion_kind="observation",
        owner_domain="job.crawler",
        writer_roles=("kernel",),
    )
    assignment = ap.authorize_event_submission(
        crawler_channel, _submission(sequence=1)
    )
    assert assignment.producer_id == "prod_crawler"
    assert assignment.principal_id == "principal_crawler"
    assert assignment.provenance == "server"
    assert assignment.role == "kernel"
    assert assignment.owner_domain == "job.crawler"
    assert assignment.assertion_kind == "observation"
    assert assignment.producer_sequence == 1
    assert assignment.event_id.startswith("evt_")

    spoofed = _submission(sequence=9)
    spoofed.update(
        {
            "producer_id": "prod_crawler",
            "principal_id": "principal_recruiter",
            "provenance": "server",
            "owner_domain": "attempt.execution",
            "role": "analyzer",
            "writer_id": "prod_reconciler",
            "assertion_kind": "authoritative_effect",
            "sequence": 42,
            "event_id": "evt_forged",
            "event_hash": "sha256:" + "0" * 64,
        }
    )
    with pytest.raises(ap.SpoofDetectedError) as spoof_error:
        ap.authorize_event_submission(crawler_channel, spoofed)
    spoof_message = str(spoof_error.value)
    assert "producer_id" in spoof_message
    assert "writer_id" in spoof_message
    assert "prod_reconciler" not in spoof_message
    assert "evt_forged" not in spoof_message

    # A rejected spoofed submission consumes neither sequence nor authority.
    assert (
        ap.authorize_event_submission(crawler_channel, _submission(sequence=2))
        .producer_sequence
        == 2
    )
    with pytest.raises(ap.InvalidSubmissionError):
        ap.authorize_event_submission(crawler_channel, _submission(sequence=2))
    with pytest.raises(ap.InvalidSubmissionError):
        ap.authorize_event_submission(
            crawler_channel, _submission(sequence=ap.NOT_APPLICABLE)
        )
    with pytest.raises(ap.InvalidSubmissionError):
        ap.authorize_event_submission(
            crawler_channel, _submission(kind="attempt.execution_recorded")
        )

    # A manual recorder cannot submit into the crawler owner domain even when
    # the event kind is registered.
    ap.register_event_kind(
        "attempt.observation_recorded",
        "1",
        role="lifecycle_observation",
        assertion_kind="claim",
        owner_domain="attempt.observation",
        writer_roles=("observer", "connector"),
    )
    with pytest.raises(ap.GrantDeniedError):
        ap.authorize_event_submission(manual_channel, _submission())
    manual_assignment = ap.authorize_event_submission(
        manual_channel,
        _submission(
            kind="attempt.observation_recorded",
            sequence=ap.NOT_APPLICABLE,
            payload=_payload({"observed": "recruiter screen scheduled"}),
        ),
    )
    assert manual_assignment.provenance == "manual_observer"
    assert manual_assignment.role == "observer"
    assert manual_assignment.owner_domain == "attempt.observation"
    assert manual_assignment.assertion_kind == "claim"

    # Application authoritative_effect entries admit application_origin only.
    with pytest.raises(ValueError):
        ap.register_event_kind(
            "attempt.application_submitted",
            "2",
            role="lifecycle_observation",
            assertion_kind="authoritative_effect",
            owner_domain="attempt.application",
            writer_roles=("connector",),
        )
    ap.register_event_kind(
        "attempt.application_submitted",
        "1",
        role="lifecycle_observation",
        assertion_kind="authoritative_effect",
        owner_domain="attempt.application",
        writer_roles=("application_origin",),
    )
    origin_assignment = ap.authorize_event_submission(
        origin_channel,
        _submission(
            kind="attempt.application_submitted",
            sequence=1,
            payload=_payload({"native_state": "submitted"}),
        ),
    )
    assert origin_assignment.provenance == "server"
    assert origin_assignment.role == "application_origin"
    assert origin_assignment.assertion_kind == "authoritative_effect"
    with pytest.raises(ap.GrantDeniedError):
        ap.authorize_event_submission(
            connector_dispatch_channel,
            _submission(kind="attempt.application_submitted", sequence=1),
        )

    # No actor holds a connector-control (or other control) grant.
    every_grant: set[str] = set()
    for actor in ap.ACTOR_POLICIES:
        every_grant |= ap.grants_for_actor(actor)
    assert not any("control" in operation for operation in every_grant)


# ---------------------------------------------------------------------------
# Assertion 2
# ---------------------------------------------------------------------------


def test_secrets_in_ordinary_journal_task_or_log_are_rejected_or_quarantined():
    runtime_credential = "vault-runtime-credential-synthetic-0001"
    binding_reference = ap.register_runtime_binding(
        "vault_runtime_primary", runtime_credential, ("quarantine.resolve",)
    )
    assert binding_reference.startswith("vaultref:")
    binding_view = ap.binding_projection("vault_runtime_primary")
    assert binding_view["credential_reference"] == binding_reference
    assert runtime_credential not in json.dumps(binding_view)

    crawler_channel = "ch_crawler_ingress_0001"
    crawler = _register_crawler(channel_id=crawler_channel)
    ap.register_event_kind(
        "discovery.source_observed",
        "1",
        role="external_input",
        assertion_kind="observation",
        owner_domain="job.crawler",
        writer_roles=("kernel",),
    )

    # --- ordinary journal sink: secret submission is rejected+quarantined --
    secret_value = "AKIAIOSFODNN7EXAMPLE"
    secret_payload = _payload({"api_key": secret_value, "source": "board-a"})
    with pytest.raises(ap.SecretDetectedError) as journal_error:
        ap.authorize_event_submission(
            crawler_channel, _submission(sequence=1, payload=secret_payload)
        )
    error = journal_error.value
    assert error.receipt is not None
    receipt = error.receipt
    assert secret_value not in str(error)
    assert secret_value not in repr(receipt)
    assert secret_value not in json.dumps(receipt.public_projection())
    assert receipt.public_projection()["vault_access"] == {
        "value": None,
        "reason": "not_observed",
        "detail": "requires scoped runtime binding",
    }
    assert ap.quarantine_count() == 1

    # The bytes are retained off-sink and resolve only through the scoped
    # runtime binding; reference or hash possession alone grants nothing.
    raw = ap.resolve_quarantine(
        "vault_runtime_primary", runtime_credential, receipt.reference
    )
    assert secret_value.encode("utf-8") in raw
    with pytest.raises(ap.VaultAccessDenied):
        ap.resolve_quarantine(
            "vault_runtime_primary",
            "wrong-runtime-credential-0001",
            receipt.reference,
        )
    with pytest.raises(ap.VaultAccessDenied):
        ap.resolve_quarantine(
            "vault_runtime_absent", runtime_credential, receipt.reference
        )
    ap.register_runtime_binding(
        "vault_artifact_reader",
        "vault-artifact-credential-synthetic-0002",
        ("artifact.restricted",),
    )
    with pytest.raises(ap.VaultAccessDenied):
        ap.resolve_quarantine(
            "vault_artifact_reader",
            "vault-artifact-credential-synthetic-0002",
            receipt.reference,
        )

    # --- content screening API --------------------------------------------
    ap.screen_ordinary_content(
        {
            "job_title": "Staff Platform Engineer",
            "token_count": 3,
            "compensation": ap.NOT_APPLICABLE,
        },
        where="journal",
    )
    ap.screen_ordinary_content(
        {"compensation": ap.NOT_APPLICABLE.to_dict()}, where="journal"
    )
    with pytest.raises(ap.ContentContractError):
        ap.screen_ordinary_content({"compensation": None}, where="journal")
    with pytest.raises(ap.SecretDetectedError) as screened:
        ap.screen_ordinary_content(
            {"task_note": "password=hunter2-real-secret"}, where="task_fields"
        )
    assert screened.value.receipt is None
    assert "hunter2-real-secret" not in str(screened.value)
    assert ap.contains_secret_material(
        "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjYW5kaWRhdGUifQ.c2lnbmF0dXJl"
    )
    assert ap.contains_secret_material("quarantine:" + "a" * 16) is False
    assert ap.is_opaque_reference("quarantine:" + "a" * 16) is True

    # --- task fields: secret leaves become opaque references --------------
    private_key_block = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA0syntheticmaterial\n"
        "-----END RSA PRIVATE KEY-----"
    )
    task_fields = {
        "summary": "Staff platform engineer fit",
        "api_key": "sk-synthetic0123456789abcdef",
        "cover_note": {"body": private_key_block},
    }
    sanitization = ap.sanitize_task_fields(task_fields)
    task_blob = json.dumps(sanitization.sanitized)
    assert "sk-synthetic0123456789abcdef" not in task_blob
    assert "PRIVATE KEY" not in task_blob
    assert sanitization.receipts
    assert all(
        ap.is_opaque_reference(receipt.reference)
        for receipt in sanitization.receipts
    )
    for reference in sanitization.references():
        assert reference in task_blob
    ap.screen_ordinary_content(sanitization.sanitized, where="task_fields")
    # The original mapping is untouched and the quarantined leaves remain
    # resolvable only through the restricted binding.
    assert task_fields["api_key"] == "sk-synthetic0123456789abcdef"
    first_leaf = ap.resolve_quarantine(
        "vault_runtime_primary",
        runtime_credential,
        sanitization.receipts[0].reference,
    )
    assert b"sk-synthetic0123456789abcdef" in first_leaf
    assert ap.sanitize_task_fields({"summary": "clean"}).receipts == ()

    # --- logs: secret spans are redacted, not echoed ----------------------
    jwt = (
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjYW5kaWRhdGUifQ.c2lnbmF0dXJlLXByb3h5"
    )
    log_line = (
        "2026-11-16T04:00:00Z WARN connector retry: "
        f"Authorization: Bearer {jwt}"
    )
    redacted = ap.redact_log_text(log_line)
    assert jwt not in redacted
    assert "Bearer " not in redacted
    assert "[redacted:secret]" in redacted
    assert "connector retry" in redacted
    ap.screen_ordinary_content(redacted, where="log")
    assert ap.contains_secret_material(log_line) is True

    # --- public interfaces never carry secret bytes -----------------------
    descriptor_blob = json.dumps(crawler.to_dict())
    assert secret_value not in descriptor_blob
    assert runtime_credential not in descriptor_blob
    assert set(crawler.to_dict()) == {
        "producer_id",
        "principal_id",
        "owner_domain",
        "role",
        "provenance",
        "sequence_required",
        "allowed_event_kinds",
    }
    channel_view = ap.channel_projection(crawler_channel)
    channel_blob = json.dumps(channel_view)
    assert secret_value not in channel_blob
    assert runtime_credential not in channel_blob
    assert channel_view["binding"] == {"value": None, "reason": "not_applicable"}
    assert binding_reference not in json.dumps(channel_view)

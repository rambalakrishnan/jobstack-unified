"""model_gateway: authorized model execution with retained evidence (tier 4).

Every model call retains its call identity, provider/model identity and
available version evidence, prompt/schema/policy pins, input artifact
identities, raw response artifact, structured validation outcome, usage
measurements, pricing version or missingness, cost derivation, and
authorization/disclosure scope (seam mapping 17.3).

Disclosure grants and cost policy are checked *before* provider dispatch
(seam mapping 18.2): models receive only data authorized for that provider
and purpose, and a frozen cost reservation is committed before any external
call.  Historical model preferences are treated as configurable policy, never
as guaranteed availability, prices, or API semantics.

Raw provider bytes are retained verbatim and never repaired: structured
validation produces an explicit outcome (valid/invalid + reasoned error)
alongside the untouched raw artifact.
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
import sys
import threading
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
    here = Path(__file__).resolve()
    path = here.parents[2] / name / "src" / "__init__.py"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:  # pragma: no cover - plumbing
        raise ModuleNotFoundError(f"sibling module {name!r} not found at {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


contract_codec = _load_sibling("contract_codec")
access_policy = _load_sibling("access_policy")
artifact_store = _load_sibling("artifact_store")
evidence_journal = _load_sibling("evidence_journal")
usage_accounting = _load_sibling("usage_accounting")

__all__ = [
    "VersionPin",
    "ArtifactReference",
    "Measurement",
    "Missing",
    "make_missing",
    "ModelGatewayError",
    "ModelPolicyError",
    "ModelAuthorizationError",
    "DisclosureDeniedError",
    "CostPolicyDeniedError",
    "ModelCostError",
    "ProviderUnavailableError",
    "ModelConflictError",
    "ModelInputError",
    "EVENT_KINDS",
    "RECORD_TYPE",
    "event_kind_declarations",
    "invoke_model",
    "stage_model_response_for_tests",
    "authorize_disclosure_for_tests",
    "dispatch_attempts_for_tests",
    "reset_for_tests",
]

#: Sibling kernel types reused for the public interface.  The cost policy pin
#: MUST be usage_accounting's VersionPin: reserve_cost enforces that type and
#: parses the pinned bytes as a strict cost policy (currency + declared
#: amounts only).  Model selection travels in the pin's id/version (provider
#: selector), never as extra cost-policy properties.
VersionPin = usage_accounting.VersionPin
ArtifactReference = artifact_store.ArtifactReference
Measurement = contract_codec.Measurement
Missing = contract_codec.Missing


def make_missing(reason: str, detail: str | None = None) -> dict[str, Any]:
    """Create a typed ``K.Missing`` envelope (never an in-band null)."""
    return contract_codec.make_missing(reason, detail)


RECORD_TYPE = "model_call_record"
EVENT_SCHEMA_VERSION = "1"

#: Every event this module writes.  The composition root registers each kind
#: in the manifest event registry and in the ingress authority before the
#: first model call.
EVENT_KINDS: Mapping[str, str] = {"model_call_recorded": EVENT_SCHEMA_VERSION}

_CODEC_GATE_SCHEMA = "record/v1"
_CODEC_GATE_KEY = "timing"

_ENTITY_PREFIX = "model_gateway:model_call:"
_ACCESS_CLASSES = frozenset({"public", "restricted"})


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ModelGatewayError(Exception):
    """Base class for model-gateway rejections and integrity failures."""


class ModelPolicyError(ModelGatewayError, ValueError):
    """A pinned policy/schema is absent, unretained, or malformed."""


class ModelAuthorizationError(ModelGatewayError, PermissionError):
    """The authenticated channel may not execute this model call."""


class DisclosureDeniedError(ModelGatewayError, PermissionError):
    """Data is not authorized for this provider and purpose."""


class CostPolicyDeniedError(ModelGatewayError, ValueError):
    """The pinned cost policy rejects this call before dispatch."""


class ModelCostError(ModelGatewayError, ValueError):
    """Usage/pricing evidence cannot be priced after dispatch."""


class ProviderUnavailableError(ModelGatewayError, ValueError):
    """No pinned provider response is available for this call."""


class ModelConflictError(ModelGatewayError, ValueError):
    """A stable call identity was reused with changed content."""


class ModelInputError(ModelGatewayError, ValueError):
    """Prompt or input artifacts are missing, unreadable, or cross-owner."""


# ---------------------------------------------------------------------------
# Module-local state (idempotency + staged provider transport for tests)
# ---------------------------------------------------------------------------

_LOCK = threading.RLock()
_CALLS: dict[tuple[str, str], dict[str, Any]] = {}
_STAGED_RESPONSES: dict[str, dict[str, Any]] = {}
_STAGED_DISCLOSURES: dict[str, dict[str, Any]] = {}
_DISPATCH_ATTEMPTS = 0


def reset_for_tests() -> None:
    """Clear idempotency records, staged transport, and dispatch counts."""
    global _DISPATCH_ATTEMPTS
    with _LOCK:
        _CALLS.clear()
        _STAGED_RESPONSES.clear()
        _STAGED_DISCLOSURES.clear()
        _DISPATCH_ATTEMPTS = 0


def dispatch_attempts_for_tests() -> int:
    """Number of provider dispatches attempted since the last reset."""
    with _LOCK:
        return _DISPATCH_ATTEMPTS


def authorize_disclosure_for_tests(
    call_id: str,
    *,
    providers: Sequence[str],
    purpose: str,
    allowed_access: Sequence[str],
) -> None:
    """Stage an explicit provider-specific disclosure grant for one call.

    Models receive only data authorized for that provider and purpose: the
    grant names the exact provider selectors (matching ``policy.id``), a
    nonempty purpose, and the artifact access classes that may be disclosed.
    """
    _require_identifier(call_id, "call_id")
    if isinstance(providers, (str, bytes)) or not isinstance(providers, Sequence):
        raise ValueError("providers must be a nonempty sequence of provider ids")
    grant_providers = tuple(_require_identifier(p, "providers[]") for p in providers)
    if not grant_providers:
        raise ValueError("providers must name at least one provider")
    _require_identifier(purpose, "purpose")
    if isinstance(allowed_access, (str, bytes)) or not isinstance(
        allowed_access, Sequence
    ):
        raise ValueError("allowed_access must be a sequence of access classes")
    grant_access = tuple(allowed_access)
    if not grant_access:
        raise ValueError("allowed_access must name at least one access class")
    for entry in grant_access:
        if entry not in _ACCESS_CLASSES:
            raise ValueError(
                f"allowed_access entries must be one of {sorted(_ACCESS_CLASSES)}"
            )
    with _LOCK:
        _STAGED_DISCLOSURES[call_id] = {
            "providers": grant_providers,
            "purpose": purpose,
            "allowed_access": grant_access,
        }


def stage_model_response_for_tests(
    call_id: str,
    raw: bytes,
    *,
    input_tokens: int | None,
    output_tokens: int | None,
    pricing: Any = None,
    provider: str | None = None,
    model_version: Any = None,
) -> None:
    """Stage exact provider bytes plus reported usage for one call.

    ``raw`` is retained verbatim as the raw response artifact.  Token counts
    are exact reported usage; ``None`` means the provider omitted that
    dimension (recorded as typed missingness, never zero).  ``pricing`` is a
    VersionPin naming retained price bytes, a typed Missing envelope, or None
    (missing).  ``provider``, when given, must equal the policy's provider
    selector; historical preferences alone never select a provider.
    """
    _require_identifier(call_id, "call_id")
    if isinstance(raw, bytearray):
        raw = bytes(raw)
    if not isinstance(raw, bytes):
        raise TypeError(f"raw must be bytes, not {type(raw).__name__}")
    if not raw:
        raise ValueError("raw provider bytes must be nonempty")
    for label, count in (("input_tokens", input_tokens), ("output_tokens", output_tokens)):
        if count is None:
            continue
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError(f"{label} must be a nonnegative int or None")
    if provider is not None:
        _require_identifier(provider, "provider")
    with _LOCK:
        _STAGED_RESPONSES[call_id] = {
            "raw": bytes(raw),
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "pricing": pricing,
            "provider": provider,
            "model_version": model_version,
        }


def event_kind_declarations(
    owner_domain: str,
    writer_roles: Sequence[str] = ("kernel",),
) -> list[dict[str, Any]]:
    """Return the manifest/ingress declarations for this module's events."""
    _require_identifier(owner_domain, "owner_domain")
    roles = list(writer_roles)
    if not roles:
        raise ValueError("writer_roles requires at least one producer role")
    return [
        {
            "event_kind": event_kind,
            "event_schema_version": version,
            "role": "lifecycle_observation",
            "assertion_kind": "authoritative_effect",
            "owner_domain": owner_domain,
            "writer_roles": roles,
        }
        for event_kind, version in EVENT_KINDS.items()
    ]


# ---------------------------------------------------------------------------
# Small validators / codec helpers
# ---------------------------------------------------------------------------


def _require_identifier(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field} must be a str, not {type(value).__name__}")
    if not value or value != value.strip():
        raise ValueError(f"{field} must be a nonempty identifier without padding")
    if len(value) > 256:
        raise ValueError(f"{field} must be at most 256 characters")
    if any(ord(char) < 0x20 for char in value):
        raise ValueError(f"{field} must not contain control characters")
    return value


def _canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _codec_gate(obj: Mapping[str, Any], field_name: str) -> None:
    """Reject bare nulls and nonfinite numbers via the strict JSON gate."""
    try:
        contract_codec.validate_record(
            _canonical_json_bytes({_CODEC_GATE_KEY: dict(obj)}),
            _CODEC_GATE_SCHEMA,
        )
    except (TypeError, ValueError) as exc:
        raise ModelGatewayError(
            f"{field_name} is not strict JSON evidence: {exc}"
        ) from exc


def _coerce_version_pin(value: Any, field_name: str) -> Any:
    if isinstance(value, VersionPin):
        return value
    if isinstance(value, Mapping):
        try:
            return VersionPin.from_dict(dict(value))
        except (TypeError, ValueError) as exc:
            raise ModelPolicyError(f"{field_name} is not a valid VersionPin: {exc}") from exc
    raise ModelPolicyError(
        f"{field_name} must be a VersionPin, not {type(value).__name__}"
    )


def _coerce_artifact_ref(value: Any, field_name: str) -> Any:
    if isinstance(value, artifact_store.ArtifactReference):
        return value
    if isinstance(value, Mapping):
        try:
            return artifact_store.ArtifactReference.from_dict(dict(value))
        except (TypeError, ValueError) as exc:
            raise ModelInputError(
                f"{field_name} is not a valid ArtifactReference: {exc}"
            ) from exc
    raise ModelInputError(
        f"{field_name} must be an ArtifactReference, not {type(value).__name__}"
    )


def _fingerprint(
    policy: Any, prompt: Any, inputs: tuple[Any, ...], output_schema: Any
) -> str:
    body = {
        "policy": policy.to_dict(),
        "prompt": prompt.to_dict(),
        "inputs": [ref.to_dict() for ref in inputs],
        "output_schema": output_schema.to_dict(),
    }
    return "sha256:" + hashlib.sha256(_canonical_json_bytes(body)).hexdigest()


def _reference_for_digest(channel_id: str, owner_domain: str, digest: str) -> Any:
    """Recover retained reference metadata for a pinned digest."""
    if digest not in artifact_store.known_digests():
        raise ModelPolicyError(
            f"no retained artifact for {digest}; a digest alone is not "
            "archived content"
        )
    meta = getattr(artifact_store, "_META", {}) or {}
    reference = meta.get(digest)
    if reference is not None:
        return reference
    payload = (getattr(artifact_store, "_BYTES", {}) or {}).get(digest)
    if payload is None:  # pragma: no cover - known digest without bytes
        raise ModelPolicyError(f"no retained bytes for {digest}")
    return artifact_store.ArtifactReference(
        digest=digest,
        size_bytes=len(payload),
        media_type="application/json",
        owner_domain=owner_domain,
        access="restricted",
    )


def _discover_clock(owner_domain: str) -> tuple[str, str]:
    """Return a registered (clock_id, boot_id) for usage measurements."""
    try:
        journal = evidence_journal._active_journal(owner_domain)
    except evidence_journal.EvidenceJournalError as exc:
        raise ModelCostError(
            f"owner domain {owner_domain!r} has no admitted journal: {exc}"
        ) from exc
    clocks = list(journal.clocks.values())
    if not clocks:
        raise ModelCostError(
            f"owner domain {owner_domain!r} admitted no clocks for measurements"
        )
    for clock in clocks:
        if isinstance(clock, Mapping) and clock.get("basis") == "opaque_report":
            return str(clock["clock_id"]), str(clock["boot_id"])
    first = clocks[0]
    if isinstance(first, Mapping):
        return str(first["clock_id"]), str(first["boot_id"])
    return str(first.clock_id), str(first.boot_id)


def _build_measurements(
    call_id: str,
    clock_id: str,
    boot_id: str,
    input_tokens: int | None,
    output_tokens: int | None,
) -> tuple[Any, Any]:
    """Build provider-reported token measurements (missing stays missing)."""
    counts = {"input_tokens": input_tokens, "output_tokens": output_tokens}
    measurements = []
    for dimension in ("input_tokens", "output_tokens"):
        count = counts[dimension]
        if count is None:
            estimate: dict[str, Any] = {
                "kind": "unavailable",
                "value": make_missing(
                    "not_observed",
                    f"provider omitted {dimension} for this call",
                ),
            }
            method, censoring = "unavailable", "unavailable"
        else:
            estimate = {"kind": "exact", "value": count}
            method, censoring = "source_value", "none"
        measurements.append(
            contract_codec.Measurement(
                measurement_id=f"{call_id}:{dimension}",
                name=dimension,
                scope={"kind": "connector_call", "id": call_id},
                quantity="scalar",
                unit="tokens",
                origin="subject_reported",
                clock_id=clock_id,
                boot_id=boot_id,
                method=method,
                start=make_missing("not_applicable"),
                end=make_missing("not_applicable"),
                estimate=estimate,
                resolution=make_missing("not_applicable"),
                comparability_group=make_missing("not_applicable"),
                censoring=censoring,
            )
        )
    return (measurements[0], measurements[1])


def _coerce_pricing(staged: Any) -> Any:
    """Normalize staged pricing to a VersionPin or a Missing envelope."""
    if staged is None:
        return make_missing(
            "not_observed",
            "no pricing version was supplied; a computed cost would fabricate "
            "a price",
        )
    if isinstance(staged, VersionPin):
        return staged
    if isinstance(staged, Mapping):
        payload = dict(staged)
        if set(payload.keys()) == {"id", "version", "artifact_digest"}:
            try:
                return VersionPin.from_dict(payload)
            except (TypeError, ValueError) as exc:
                raise ModelCostError(f"staged pricing pin is invalid: {exc}") from exc
        return payload
    raise ModelCostError(
        "staged pricing must be a VersionPin, a Missing envelope, or None"
    )


def _coerce_model_version(staged: Any) -> Any:
    """Normalize staged version evidence to a string or Missing envelope."""
    if staged is None:
        return make_missing("not_observed", "provider reported no model version")
    if isinstance(staged, str):
        if not staged.strip():
            raise ModelGatewayError("staged model_version must be nonempty")
        return staged
    if isinstance(staged, Mapping):
        return dict(staged)
    raise ModelGatewayError("staged model_version must be a string, Missing, or None")


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


async def invoke_model(
    channel_id: str,
    call_id: str,
    policy: VersionPin,
    prompt: ArtifactReference,
    inputs: tuple[ArtifactReference, ...],
    output_schema: VersionPin,
) -> ArtifactReference:
    """Execute one authorized model call and retain its complete evidence.

    Disclosure grants and cost policy are checked before provider dispatch;
    a frozen cost reservation commits before any external call.  Raw provider
    bytes are retained verbatim with an explicit structured-validation
    outcome.  The returned artifact is the call record citing every retained
    input, pin, measurement, price, derivation, and authorization.
    """
    # -- 0. Identifiers + type coercion (no I/O). ---------------------------
    _require_identifier(channel_id, "channel_id")
    _require_identifier(call_id, "call_id")
    policy_pin = _coerce_version_pin(policy, "policy")
    prompt_ref = _coerce_artifact_ref(prompt, "prompt")
    if isinstance(inputs, (str, bytes)) or not isinstance(inputs, (tuple, list)):
        raise ModelInputError("inputs must be a tuple of ArtifactReferences")
    input_refs = tuple(
        _coerce_artifact_ref(ref, f"inputs[{index}]")
        for index, ref in enumerate(inputs)
    )
    schema_pin = _coerce_version_pin(output_schema, "output_schema")
    owner_domain = prompt_ref.owner_domain
    fingerprint = _fingerprint(policy_pin, prompt_ref, input_refs, schema_pin)

    # -- 1. Authenticated, owner-local authorization. ------------------------
    try:
        projection = access_policy.channel_projection(channel_id)
    except access_policy.AuthorizationError as exc:
        raise ModelAuthorizationError(
            f"unknown channel {channel_id!r}; model calls require an "
            f"authenticated ingress session: {exc}"
        ) from exc
    if projection.get("axis") != owner_domain:
        raise access_policy.GrantDeniedError(
            f"owner-local call required: channel axis {projection.get('axis')!r} "
            f"cannot invoke for owner domain {owner_domain!r}"
        )
    grants = list(projection.get("grants", []))
    if not grants:
        raise access_policy.GrantDeniedError(
            f"authenticated channel holds no write grant for {owner_domain!r}"
        )
    try:
        descriptor = access_policy.authorize(channel_id, grants[0], call_id)
    except access_policy.AuthorizationError as exc:
        raise ModelAuthorizationError(str(exc)) from exc

    # -- 2. Stable call identity (replay without re-dispatch). ---------------
    with _LOCK:
        existing = _CALLS.get((owner_domain, call_id))
        if existing is not None:
            if existing["fingerprint"] != fingerprint:
                raise ModelConflictError(
                    f"call {call_id!r} reused with changed policy, prompt, "
                    "inputs, or output schema; call identity is stable"
                )
            return existing["response"]

    # -- 3. Pin checks before any disclosure or dispatch. --------------------
    if schema_pin.id not in contract_codec.SCHEMAS:
        raise ModelPolicyError(
            f"output schema {schema_pin.id!r} is not a known structured-output "
            f"schema; expected one of {sorted(contract_codec.SCHEMAS)}"
        )
    for pin, label in ((policy_pin, "policy"), (schema_pin, "output_schema")):
        if pin.artifact_digest not in artifact_store.known_digests():
            raise ModelPolicyError(
                f"{label} artifact {pin.artifact_digest} is not retained; "
                "pins name archived content, never bare digests"
            )

    # -- 4. Disclosure: every input authorized for provider + purpose. -------
    for index, ref in enumerate(input_refs):
        if ref.owner_domain != owner_domain:
            raise DisclosureDeniedError(
                f"inputs[{index}] belongs to {ref.owner_domain!r}, not the "
                f"call owner {owner_domain!r}; cross-owner data is outside "
                "the disclosure scope"
            )
    with _LOCK:
        grant = _STAGED_DISCLOSURES.get(call_id)
    if grant is None:
        raise DisclosureDeniedError(
            f"call {call_id!r} has no disclosure grant; models receive only "
            "data authorized for that provider and purpose"
        )
    if policy_pin.id not in grant["providers"]:
        raise DisclosureDeniedError(
            f"provider {policy_pin.id!r} is outside the disclosure grant for "
            f"call {call_id!r}; granted providers: {sorted(grant['providers'])}"
        )
    for label, ref in [("prompt", prompt_ref)] + [
        (f"inputs[{index}]", ref) for index, ref in enumerate(input_refs)
    ]:
        if ref.access not in grant["allowed_access"]:
            raise DisclosureDeniedError(
                f"{label} access {ref.access!r} is outside the disclosure "
                f"grant for call {call_id!r}; allowed: "
                f"{sorted(grant['allowed_access'])}"
            )
    # Resolve prompt/inputs locally (owner-domain read, never a dispatch)
    # and refuse secret material for the ordinary provider sink.
    try:
        prompt_bytes = artifact_store.resolve_artifact(channel_id, prompt_ref)
    except artifact_store.ArtifactError as exc:
        raise ModelInputError(f"prompt {prompt_ref.digest} is not resolvable: {exc}") from exc
    input_payloads: list[bytes] = []
    for index, ref in enumerate(input_refs):
        try:
            payload = artifact_store.resolve_artifact(channel_id, ref)
        except artifact_store.ArtifactError as exc:
            raise ModelInputError(
                f"inputs[{index}] {ref.digest} is not resolvable: {exc}"
            ) from exc
        input_payloads.append(payload)
    for label, content in [("prompt", prompt_bytes)] + [
        (f"inputs[{index}]", payload)
        for index, payload in enumerate(input_payloads)
    ]:
        if access_policy.contains_secret_material(content):
            raise DisclosureDeniedError(
                f"{label} carries secret material; raw secrets remain behind "
                "runtime access bindings and are never disclosed to models"
            )

    # -- 5. Cost policy checked (and frozen) before provider dispatch. -------
    try:
        reservation_ref = usage_accounting.reserve_cost(channel_id, call_id, policy_pin)
    except usage_accounting.CostAccountingError as exc:
        raise CostPolicyDeniedError(
            f"cost policy rejects call {call_id!r} before dispatch: {exc}"
        ) from exc

    # -- 6. Provider dispatch (only after disclosure + cost checks). ---------
    with _LOCK:
        global _DISPATCH_ATTEMPTS
        _DISPATCH_ATTEMPTS += 1
        staged = _STAGED_RESPONSES.get(call_id)
    if staged is None:
        raise ProviderUnavailableError(
            f"no provider response is pinned for call {call_id!r}; historical "
            "model preferences establish no current availability, prices, or "
            "API semantics"
        )
    if staged["provider"] is not None and staged["provider"] != policy_pin.id:
        raise ProviderUnavailableError(
            f"staged provider {staged['provider']!r} does not match pinned "
            f"policy provider {policy_pin.id!r}; unmapped completions are blocked"
        )
    raw_bytes: bytes = staged["raw"]
    model_version = _coerce_model_version(staged["model_version"])

    # -- 7. Retain raw response bytes verbatim (never repaired). --------------
    raw_access = (
        "restricted"
        if any(ref.access == "restricted" for ref in (prompt_ref, *input_refs))
        else "public"
    )
    try:
        raw_ref = artifact_store.retain_artifact(
            channel_id, owner_domain, "application/octet-stream", raw_bytes, raw_access
        )
    except artifact_store.ArtifactError as exc:
        raise ModelGatewayError(
            f"cannot retain raw response for call {call_id!r}: {exc}"
        ) from exc

    # -- 8. Explicit structured-validation outcome (raw bytes untouched). -----
    try:
        canonical = contract_codec.validate_record(raw_bytes, schema_pin.id)
        canonical_digest: Any = (
            "sha256:" + hashlib.sha256(canonical).hexdigest()
        )
        validation: dict[str, Any] = {
            "valid": True,
            "schema_id": schema_pin.id,
            "schema_version": schema_pin.version,
            "schema_digest": schema_pin.artifact_digest,
            "canonical_digest": canonical_digest,
            "error": make_missing("not_applicable", "structured output validated"),
        }
    except (TypeError, ValueError) as exc:
        validation = {
            "valid": False,
            "schema_id": schema_pin.id,
            "schema_version": schema_pin.version,
            "schema_digest": schema_pin.artifact_digest,
            "canonical_digest": make_missing(
                "not_observed", "no canonical structured value; validation failed"
            ),
            "error": make_missing(
                "not_observed", f"structured validation failed: {exc}"
            ),
        }

    # -- 9. Usage measurements (missing stays missing, never zero). -----------
    clock_id, boot_id = _discover_clock(owner_domain)
    measurements = _build_measurements(
        call_id, clock_id, boot_id, staged["input_tokens"], staged["output_tokens"]
    )

    # -- 10. Pricing version or missingness (never a default price). ----------
    pricing_arg = _coerce_pricing(staged["pricing"])
    if isinstance(pricing_arg, VersionPin):
        pricing_record: Any = pricing_arg.to_dict()
    else:
        pricing_record = dict(pricing_arg)

    # -- 11. Record reported usage + priced derivation. -----------------------
    try:
        cost_ref = usage_accounting.record_model_cost(
            channel_id, call_id, measurements, pricing_arg, ()
        )
    except usage_accounting.CostAccountingError as exc:
        raise ModelCostError(
            f"cannot price call {call_id!r}: {exc}"
        ) from exc

    # -- 12. Journal the complete call evidence. ------------------------------
    usage_summary: dict[str, Any] = {}
    for dimension, count in (
        ("input_tokens", staged["input_tokens"]),
        ("output_tokens", staged["output_tokens"]),
    ):
        if count is None:
            usage_summary[dimension] = make_missing(
                "not_observed", f"provider omitted {dimension} for this call"
            )
        else:
            usage_summary[dimension] = count
    event_data: dict[str, Any] = {
        "record_type": RECORD_TYPE,
        "call_id": call_id,
        "provider": policy_pin.id,
        "provider_version_evidence": model_version,
        "policy_pin": policy_pin.to_dict(),
        "prompt_digest": prompt_ref.digest,
        "input_digests": [ref.digest for ref in input_refs],
        "output_schema_pin": schema_pin.to_dict(),
        "raw_response_digest": raw_ref.digest,
        "raw_response_size": raw_ref.size_bytes,
        "raw_response_media_type": raw_ref.media_type,
        "validation": validation,
        "usage_summary": usage_summary,
        "pricing": pricing_record,
        "cost_record_digest": cost_ref.digest,
        "authorization": {
            "producer_id": descriptor.producer_id,
            "owner_domain": descriptor.owner_domain,
            "channel_axis": projection.get("axis"),
        },
        "disclosure": {
            "providers": sorted(grant["providers"]),
            "purpose": grant["purpose"],
            "allowed_access": sorted(grant["allowed_access"]),
        },
    }
    policy_meta = _reference_for_digest(channel_id, owner_domain, policy_pin.artifact_digest)
    schema_meta = _reference_for_digest(channel_id, owner_domain, schema_pin.artifact_digest)
    journal_refs: list[Any] = [
        prompt_ref,
        *input_refs,
        raw_ref,
        cost_ref,
        reservation_ref,
        policy_meta,
        schema_meta,
    ]
    if isinstance(pricing_arg, VersionPin):
        journal_refs.append(
            _reference_for_digest(channel_id, owner_domain, pricing_arg.artifact_digest)
        )
    deduped: list[Any] = []
    seen: set[str] = set()
    for ref in journal_refs:
        if ref.digest in seen:
            continue
        seen.add(ref.digest)
        deduped.append(ref)
    submission = evidence_journal.EventSubmission(
        producer_sequence=evidence_journal.NOT_APPLICABLE,
        event_kind="model_call_recorded",
        event_schema_version=EVENT_SCHEMA_VERSION,
        occurred_at=evidence_journal.NOT_OBSERVED,
        payload=evidence_journal.EvidencePayload(
            data=event_data,
            measurements=measurements,
            evidence_refs=(),
            artifact_refs=tuple(deduped),
        ),
    )
    envelope = evidence_journal.append_event(channel_id, owner_domain, submission)

    # -- 13. Retain + return the call record. ---------------------------------
    try:
        cost_bytes = artifact_store.resolve_artifact(channel_id, cost_ref)
        cost_document = json.loads(cost_bytes.decode("utf-8"))
        derivation: Any = cost_document.get(
            "cost_derivation",
            make_missing("observation_lost", "cost record omits its derivation"),
        )
    except (artifact_store.ArtifactError, ValueError, UnicodeDecodeError) as exc:
        derivation = make_missing("observation_lost", f"cost derivation unreadable: {exc}")
    call_record: dict[str, Any] = {
        **event_data,
        "reservation_digest": reservation_ref.digest,
        "cost_derivation": derivation,
        "journal": {
            "journal_id": envelope.journal_id,
            "sequence": envelope.journal_sequence,
            "event_id": envelope.event_id,
            "event_hash": envelope.event_hash,
        },
    }
    _codec_gate(call_record, "model_call_record")
    try:
        record_ref = artifact_store.retain_artifact(
            channel_id,
            owner_domain,
            "application/json",
            _canonical_json_bytes(call_record),
            raw_access,
        )
    except artifact_store.ArtifactError as exc:
        raise ModelGatewayError(
            f"cannot retain call record for {call_id!r}: {exc}"
        ) from exc

    with _LOCK:
        replayed = _CALLS.get((owner_domain, call_id))
        if replayed is not None:
            if replayed["fingerprint"] != fingerprint:  # pragma: no cover - raced
                raise ModelConflictError(
                    f"call {call_id!r} reused with changed content; "
                    "call identity is stable"
                )
            return replayed["response"]
        _CALLS[(owner_domain, call_id)] = {
            "fingerprint": fingerprint,
            "response": record_ref,
        }
    return record_ref

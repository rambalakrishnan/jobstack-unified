"""usage_accounting: model-call usage evidence, reservations, and priced cost.

This module owns the ``costs`` accounting seam (``job-hunter-seam-mapping.md``
sections 16.11 and 17.3).  It keeps four things provably distinct:

* a **cost reservation** -- a declaration frozen from a pinned cost policy;
* **reported usage** -- evidence (provider-reported or measured token counts);
* a **priced derivation** -- exact arithmetic over declared, pinned prices;
* an **invoiced charge** -- a provider billing fact, which this module never
  invents.

Rules implemented here:

* Missing provider usage never becomes zero usage, and therefore never becomes
  a zero-dollar charge.  Every absent dimension is a typed ``Missing``
  envelope; an explicitly reported zero stays the number ``0`` and is priced as
  zero.
* Reservations, reported usage, and invoiced charges stay in separate fields
  with separate bases.  Computed cost is marked ``is_invoice_fact: false`` and
  the invoice field remains ``Missing(not_observed)`` unless invoice evidence
  exists (this module accepts no invoice input, so it never fabricates one).
* Model prices, token counts, currency conversions, and budget policies are
  never fabricated.  A pricing pin must resolve to retained, declared price
  bytes; a cost policy must resolve to retained, declared policy bytes.
* Provider-call evidence is never charged twice: the same ``source_refs`` under
  a different ``call_id`` is rejected, and identical retries of one call
  replay the already committed record instead of adding a second effect.
* A cost record and its reservation commit through
  :func:`evidence_journal.commit_effect`, so the retained record, revision
  advance, idempotency receipt, and journal events become durable together
  before acknowledgement.

``VersionPin`` identifies exact retained bytes (``K.VersionPin``).  Because a
pin carries only ``artifact_digest``, pinned bytes are resolved through the
artifact store's retained identities; possession of a digest alone never
resolves content.
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import math
import re
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, fields, is_dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any


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

__all__ = [
    "SCHEMA_VERSION",
    "EVENT_SCHEMA_VERSION",
    "RESERVATION_RECORD_TYPE",
    "MODEL_COST_RECORD_TYPE",
    "RESERVATION_EVENT_KIND",
    "MODEL_COST_EVENT_KIND",
    "EVENT_KINDS",
    "INPUT_TOKENS",
    "OUTPUT_TOKENS",
    "TOKEN_DIMENSIONS",
    "Missing",
    "VersionPin",
    "CostAccountingError",
    "CostAuthorizationError",
    "CostPolicyError",
    "CostPricingError",
    "CostUsageError",
    "CostConflictError",
    "CostDuplicateEvidenceError",
    "CostIntegrityError",
    "CostJournalError",
    "make_missing",
    "event_kind_declarations",
    "reserve_cost",
    "record_model_cost",
]

SCHEMA_VERSION = "1"
EVENT_SCHEMA_VERSION = "1"
RESERVATION_RECORD_TYPE = "cost_reservation"
MODEL_COST_RECORD_TYPE = "model_cost_record"
RESERVATION_EVENT_KIND = "cost_reserved"
MODEL_COST_EVENT_KIND = "model_cost_recorded"

#: Every event this module writes.  The composition root registers each kind in
#: the manifest event registry and in the ingress authority before the first
#: cost record.
EVENT_KINDS: Mapping[str, str] = {
    RESERVATION_EVENT_KIND: EVENT_SCHEMA_VERSION,
    MODEL_COST_EVENT_KIND: EVENT_SCHEMA_VERSION,
}

#: Scalar usage dimensions priced by this module (seam mapping 16.11).
INPUT_TOKENS = "input_tokens"
OUTPUT_TOKENS = "output_tokens"
TOKEN_DIMENSIONS = (INPUT_TOKENS, OUTPUT_TOKENS)
_USAGE_UNIT = "tokens"

#: ``K.Missing`` is a typed envelope mapping (never an in-band null).
Missing = contract_codec.Missing

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_POLICY_FIELDS = frozenset(
    {"currency", "reserved_cost_usd", "frozen_cost_limit_usd"}
)
_PRICING_FIELDS = frozenset(
    {
        "currency",
        "model_id",
        "model_version",
        "input_usd_per_token",
        "output_usd_per_token",
    }
)
_RESERVATION_ENTITY_PREFIX = "usage_accounting:cost_reservation:"
_MODEL_COST_ENTITY_PREFIX = "usage_accounting:model_cost:"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class CostAccountingError(Exception):
    """Base class for usage-accounting rejections and integrity failures."""


class CostAuthorizationError(CostAccountingError, PermissionError):
    """The authenticated channel may not write usage accounting."""


class CostPolicyError(CostAccountingError, ValueError):
    """A pinned cost policy is absent, unreadable, or malformed."""


class CostPricingError(CostAccountingError, ValueError):
    """A pinned price schedule is absent, unreadable, or malformed."""


class CostUsageError(CostAccountingError, ValueError):
    """Reported usage is unsupported, malformed, or duplicated."""


class CostConflictError(CostAccountingError):
    """The same call identity was already recorded with different content."""


class CostDuplicateEvidenceError(CostAccountingError):
    """Provider-call evidence was already priced under another call identity."""


class CostIntegrityError(CostAccountingError):
    """Committed cost evidence does not replay as acknowledged."""


class CostJournalError(CostAccountingError):
    """No owner-local journal is admitted for this accounting operation."""


# ---------------------------------------------------------------------------
# Kernel values
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class VersionPin:
    """``K.VersionPin``: an immutable pinned policy/pricing artifact.

    A pin names exact retained bytes.  It never carries read authority: the
    owner-local channel must still resolve the digest through the artifact
    store.
    """

    id: str
    version: str
    artifact_digest: str

    def __post_init__(self) -> None:
        _require_identifier(self.id, "VersionPin.id")
        _require_identifier(self.version, "VersionPin.version")
        _require_digest(self.artifact_digest, "VersionPin.artifact_digest")

    def to_dict(self) -> dict[str, str]:
        return {
            "id": self.id,
            "version": self.version,
            "artifact_digest": self.artifact_digest,
        }

    @classmethod
    def from_dict(cls, data: Any) -> "VersionPin":
        if not isinstance(data, Mapping):
            raise CostPolicyError("VersionPin must be decoded from a mapping")
        if set(data.keys()) != {"id", "version", "artifact_digest"}:
            raise CostPolicyError(
                "VersionPin must contain exactly id, version, artifact_digest"
            )
        for key in ("id", "version", "artifact_digest"):
            if data[key] is None:
                raise CostPolicyError(f"VersionPin.{key} must not be a bare null")
        return cls(
            id=data["id"],
            version=data["version"],
            artifact_digest=data["artifact_digest"],
        )


def make_missing(reason: str, detail: str | None = None) -> Missing:
    """Create a typed ``K.Missing`` envelope (never an in-band null)."""
    return contract_codec.make_missing(reason, detail)


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


def _require_digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.match(value):
        raise ValueError(f"{field} must be a sha256:<64 lowercase hex> digest")
    return value


def _missing_envelope(value: Any) -> dict[str, Any] | None:
    """Return a canonical typed Missing envelope, or ``None``.

    Accepts the plain kernel mapping plus the dependency dataclass envelopes.
    A bare ``None`` is never treated as missingness.
    """
    if isinstance(value, (evidence_journal.Missing, access_policy.Missing)):
        return make_missing(value.reason, value.detail)
    if isinstance(value, Mapping):
        keys = set(value.keys())
        if "value" in keys and value.get("value") is None and "reason" in keys:
            extra = keys - {"value", "reason", "detail"}
            if extra:
                raise ValueError(
                    f"undeclared Missing properties: {sorted(extra)}"
                )
            detail = value.get("detail")
            if detail is not None and (
                not isinstance(detail, str) or not detail
            ):
                raise ValueError("Missing.detail must be a nonempty string")
            return make_missing(str(value["reason"]), detail)
    return None


def _kernel_json(value: Any, path: str = "$") -> Any:
    """Normalize kernel values to strict, JSON-ready content."""
    missing = _missing_envelope(value)
    if missing is not None:
        return missing
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(
                    f"non-string mapping key at {path}: {type(key).__name__}"
                )
            out[key] = _kernel_json(item, f"{path}.{key}")
        return out
    if isinstance(value, (list, tuple)):
        return [
            _kernel_json(item, f"{path}[{index}]")
            for index, item in enumerate(value)
        ]
    if is_dataclass(value) and not isinstance(value, type):
        return {
            item.name: _kernel_json(
                getattr(value, item.name), f"{path}.{item.name}"
            )
            for item in fields(value)
        }
    if value is None:
        raise ValueError(
            f"bare null at {path}; use a typed Missing envelope"
        )
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, str)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"nonfinite number at {path}")
        return value
    raise TypeError(
        f"value at {path} is not ordinary JSON content "
        f"({type(value).__name__})"
    )


def _canonical_bytes(obj: Any) -> bytes:
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _strict_json(raw: bytes, error_cls: type[Exception]) -> Any:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise error_cls(f"pinned artifact is not utf-8: {exc}") from exc

    def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in pairs:
            if key in out:
                raise ValueError(f"duplicate mapping key: {key!r}")
            out[key] = value
        return out

    def _reject_constant(literal: str) -> Any:
        raise ValueError(f"nonfinite number literal: {literal!r}")

    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, ValueError) as exc:
        raise error_cls(f"pinned artifact is not strict JSON: {exc}") from exc


# ---------------------------------------------------------------------------
# Channel / journal context
# ---------------------------------------------------------------------------


def _channel_context(channel_id: str, resource_id: str) -> str:
    """Authorize a usage-accounting write and return its owner domain."""
    try:
        projection = access_policy.channel_projection(channel_id)
    except access_policy.AuthorizationError as exc:
        raise CostAuthorizationError(str(exc)) from exc
    axis = projection.get("axis")
    grants = list(projection.get("grants") or ())
    if not isinstance(axis, str) or not axis:
        raise CostAuthorizationError(
            "authenticated channel has no owner axis for usage accounting"
        )
    if not grants:
        raise CostAuthorizationError(
            "authenticated channel holds no write grant for usage accounting"
        )
    try:
        descriptor = access_policy.authorize(channel_id, grants[0], resource_id)
    except access_policy.AuthorizationError as exc:
        raise CostAuthorizationError(str(exc)) from exc
    if descriptor.owner_domain != axis:
        raise CostAuthorizationError(
            "authorized producer does not own the channel's accounting domain"
        )
    return axis


def _active_journal(owner_domain: str) -> Any:
    """Return the owner-local journal this accounting write commits into."""
    try:
        return evidence_journal._active_journal(owner_domain)
    except evidence_journal.EvidenceJournalError as exc:
        raise CostJournalError(
            f"owner domain {owner_domain!r} has no admitted journal: {exc}"
        ) from exc


def _clock_descriptors(journal: Any) -> tuple[dict[str, Any], ...]:
    return tuple(dict(clock) for clock in journal.clocks.values())


# ---------------------------------------------------------------------------
# Pinned artifact resolution
# ---------------------------------------------------------------------------


def _reference_for_digest(
    channel_id: str,
    owner_domain: str,
    digest: str,
    error_cls: type[Exception],
) -> Any:
    """Recover the retained reference metadata for a pinned digest."""
    _require_digest(digest, "artifact_digest")
    if digest not in artifact_store.known_digests():
        raise error_cls(
            f"no retained artifact for {digest}; a digest alone is not "
            "archived content"
        )
    meta = getattr(artifact_store, "_META", {}) or {}
    reference = meta.get(digest)
    if reference is not None:
        return reference
    payload = (getattr(artifact_store, "_BYTES", {}) or {}).get(digest)
    if payload is None:
        raise error_cls(f"no retained bytes for {digest}")
    return artifact_store.ArtifactReference(
        digest=digest,
        size_bytes=len(payload),
        media_type="application/json",
        owner_domain=owner_domain,
        access="restricted",
    )


def _resolve_pin(
    channel_id: str,
    owner_domain: str,
    pin: VersionPin,
    error_cls: type[Exception],
) -> tuple[Any, Mapping[str, Any]]:
    """Resolve a pin's exact retained bytes through the artifact store."""
    reference = _reference_for_digest(
        channel_id, owner_domain, pin.artifact_digest, error_cls
    )
    try:
        raw = artifact_store.resolve_artifact(channel_id, reference)
    except artifact_store.ArtifactError as exc:
        raise error_cls(
            f"pinned artifact {pin.artifact_digest} cannot be resolved: {exc}"
        ) from exc
    payload = _strict_json(raw, error_cls)
    if not isinstance(payload, Mapping):
        raise error_cls("pinned artifact must be a JSON object")
    return reference, payload


# ---------------------------------------------------------------------------
# Pinned cost policy and price schedule documents
# ---------------------------------------------------------------------------


def _optional_amount(
    document: Mapping[str, Any],
    key: str,
    error_cls: type[Exception],
) -> float | int | None:
    if key not in document:
        return None
    value = document[key]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise error_cls(f"{key} must be a finite nonnegative number")
    if not math.isfinite(float(value)) or float(value) < 0:
        raise error_cls(f"{key} must be a finite nonnegative number")
    return value


def _parse_policy_document(
    document: Mapping[str, Any],
) -> tuple[str | None, float | int | None, float | int | None]:
    """Parse a pinned cost policy: ``currency`` plus declared frozen amounts.

    Declared schema: exactly ``currency`` and the optional
    ``reserved_cost_usd`` / ``frozen_cost_limit_usd``.  A policy that declares
    amounts must declare its currency; an absent amount stays absent, never
    zero.
    """
    extra = set(document.keys()) - _POLICY_FIELDS
    if extra:
        raise CostPolicyError(
            f"undeclared cost policy properties: {sorted(extra)}"
        )
    currency = document.get("currency")
    if currency is not None:
        if not isinstance(currency, str) or not currency.strip():
            raise CostPolicyError("cost policy currency must be a nonempty string")
    reserved = _optional_amount(document, "reserved_cost_usd", CostPolicyError)
    frozen = _optional_amount(
        document, "frozen_cost_limit_usd", CostPolicyError
    )
    if (reserved is not None or frozen is not None) and currency is None:
        raise CostPolicyError(
            "a cost policy that declares amounts must declare its currency"
        )
    return currency, reserved, frozen


def _price(
    document: Mapping[str, Any], key: str
) -> float | int:
    value = document[key]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CostPricingError(f"{key} must be a finite nonnegative number")
    if not math.isfinite(float(value)) or float(value) < 0:
        raise CostPricingError(f"{key} must be a finite nonnegative number")
    return value


def _parse_pricing_document(
    document: Mapping[str, Any],
) -> dict[str, Any]:
    """Parse a pinned price schedule: currency, model identity, token prices.

    Declared schema: exactly ``currency``, ``model_id``, ``model_version``
    (string or typed Missing), ``input_usd_per_token``, and
    ``output_usd_per_token``.  Prices are declarations from the pinned bytes;
    this module never falls back to an inferred or default price.
    """
    missing = _PRICING_FIELDS - set(document.keys())
    extra = set(document.keys()) - _PRICING_FIELDS
    if missing or extra:
        raise CostPricingError(
            "price schedule must contain exactly "
            f"{sorted(_PRICING_FIELDS)}; missing {sorted(missing)}, "
            f"undeclared {sorted(extra)}"
        )
    currency = document["currency"]
    if not isinstance(currency, str) or not currency.strip():
        raise CostPricingError("price schedule currency must be a nonempty string")
    model_id = document["model_id"]
    if not isinstance(model_id, str) or not model_id.strip():
        raise CostPricingError("price schedule model_id must be a nonempty string")
    version = document["model_version"]
    model_version = _missing_envelope(version)
    if model_version is None:
        if not isinstance(version, str) or not version.strip():
            raise CostPricingError(
                "price schedule model_version must be a nonempty string or "
                "a typed Missing envelope"
            )
        model_version = version
    return {
        "currency": currency,
        "model": {"id": model_id, "version": model_version},
        "input_usd_per_token": _price(document, "input_usd_per_token"),
        "output_usd_per_token": _price(document, "output_usd_per_token"),
    }


def _pricing_state(
    channel_id: str,
    owner_domain: str,
    pricing: Any,
) -> dict[str, Any] | None:
    if pricing is None:
        raise CostPricingError(
            "pricing must be a VersionPin or a typed Missing envelope, "
            "never a bare null"
        )
    missing = _missing_envelope(pricing)
    if missing is not None:
        return None
    if isinstance(pricing, VersionPin):
        pin = pricing
    elif isinstance(pricing, Mapping):
        try:
            pin = VersionPin.from_dict(pricing)
        except CostPolicyError as exc:
            raise CostPricingError(str(exc)) from exc
    else:
        raise CostPricingError(
            "pricing must be a VersionPin or a typed Missing envelope"
        )
    reference, document = _resolve_pin(
        channel_id, owner_domain, pin, CostPricingError
    )
    parsed = _parse_pricing_document(document)
    return {
        "pin": pin,
        "reference": reference,
        "document": parsed,
        "record": {
            "basis": "retained_price_schedule",
            "pin": pin.to_dict(),
            "model": parsed["model"],
            "currency": parsed["currency"],
        },
    }


# ---------------------------------------------------------------------------
# Reported usage measurements
# ---------------------------------------------------------------------------


def _token_count(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CostUsageError(f"{label} must be an integral token count")
    if not math.isfinite(float(value)) or float(value) < 0:
        raise CostUsageError(f"{label} must be a finite nonnegative token count")
    if isinstance(value, float) and not value.is_integer():
        raise CostUsageError(f"{label} must be an integral token count")
    return int(value)


def _bound_value(value: Any, label: str) -> int | dict[str, Any]:
    missing = _missing_envelope(value)
    if missing is not None:
        return missing
    return _token_count(value, label)


def _validate_usage(
    usage: Any, clocks: tuple[dict[str, Any], ...]
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    if isinstance(usage, (str, bytes)) or not isinstance(usage, Sequence):
        raise CostUsageError("usage must be a sequence of Measurements")
    ordered: list[dict[str, Any]] = []
    by_name: dict[str, dict[str, Any]] = {}
    for index, measurement in enumerate(usage):
        try:
            normalized = _kernel_json(measurement, f"usage[{index}]")
        except (TypeError, ValueError) as exc:
            raise CostUsageError(f"usage[{index}]: {exc}") from exc
        try:
            contract_codec.validate_measurement(normalized, clocks)
        except (TypeError, ValueError) as exc:
            raise CostUsageError(f"usage[{index}]: {exc}") from exc
        name = normalized["name"]
        if name not in TOKEN_DIMENSIONS:
            raise CostUsageError(
                f"usage[{index}]: unsupported usage dimension {name!r}; "
                f"expected one of {sorted(TOKEN_DIMENSIONS)}"
            )
        if normalized["quantity"] != "scalar" or normalized["unit"] != _USAGE_UNIT:
            raise CostUsageError(
                f"usage[{index}]: token usage must be a scalar measured in "
                f"{_USAGE_UNIT!r}"
            )
        if name in by_name:
            raise CostUsageError(
                f"usage measurement for {name!r} was supplied more than once"
            )
        ordered.append(normalized)
        by_name[name] = normalized
    return ordered, by_name


def _usage_record(dimension: str, measurement: Mapping[str, Any] | None) -> dict[str, Any]:
    if measurement is None:
        return {
            "measurement_id": make_missing("not_applicable"),
            "name": dimension,
            "quantity": "scalar",
            "unit": _USAGE_UNIT,
            "origin": make_missing("not_observed"),
            "clock_id": make_missing("not_observed"),
            "boot_id": make_missing("not_observed"),
            "method": "unavailable",
            "estimate_kind": "unavailable",
            "censoring": "unavailable",
            "value": make_missing(
                "not_observed",
                f"no provider usage measurement was supplied for {dimension}",
            ),
        }
    estimate = measurement["estimate"]
    kind = estimate["kind"]
    if kind == "exact":
        value: Any = _token_count(estimate["value"], f"{dimension} tokens")
    elif kind == "bounded":
        value = {
            "lower_bound": _bound_value(
                estimate["lower_bound"], f"{dimension} lower bound"
            ),
            "upper_bound": _bound_value(
                estimate["upper_bound"], f"{dimension} upper bound"
            ),
        }
    else:
        value = _kernel_json(estimate["value"], f"{dimension}.estimate.value")
    return {
        "measurement_id": measurement["measurement_id"],
        "name": dimension,
        "quantity": measurement["quantity"],
        "unit": measurement["unit"],
        "origin": measurement["origin"],
        "clock_id": measurement["clock_id"],
        "boot_id": measurement["boot_id"],
        "method": measurement["method"],
        "estimate_kind": kind,
        "censoring": measurement["censoring"],
        "value": value,
    }


# ---------------------------------------------------------------------------
# Cost derivation
# ---------------------------------------------------------------------------


def _decimal_text(total: Decimal) -> str:
    return format(total.normalize(), "f")


def _derive_cost(
    reported_usage: Mapping[str, Mapping[str, Any]],
    pricing_state: Mapping[str, Any] | None,
) -> dict[str, Any]:
    if pricing_state is None:
        return make_missing(
            "not_observed",
            "no pricing version was supplied; a computed cost would fabricate "
            "a price",
        )
    inexact = [
        dimension
        for dimension in TOKEN_DIMENSIONS
        if reported_usage[dimension]["estimate_kind"] != "exact"
    ]
    if inexact:
        return make_missing(
            "not_observed",
            "cost is not derived because reported usage is not exact for: "
            + ", ".join(inexact),
        )
    document = pricing_state["document"]
    input_tokens = int(reported_usage[INPUT_TOKENS]["value"])
    output_tokens = int(reported_usage[OUTPUT_TOKENS]["value"])
    try:
        total = (
            Decimal(str(document["input_usd_per_token"])) * input_tokens
            + Decimal(str(document["output_usd_per_token"])) * output_tokens
        )
    except InvalidOperation as exc:  # pragma: no cover - prices are validated
        raise CostPricingError("declared prices are not decimal numbers") from exc
    amount = float(total)
    if not math.isfinite(amount):
        raise CostPricingError("derived cost is not a finite number")
    return {
        "basis": "declared_price_schedule",
        "model": document["model"],
        "currency": document["currency"],
        "pricing_pin": pricing_state["pin"].to_dict(),
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "input_usd_per_token": document["input_usd_per_token"],
        "output_usd_per_token": document["output_usd_per_token"],
        "amount_usd": amount,
        "exact_amount": _decimal_text(total),
        "exactness": "exact_under_declared_prices",
        "is_invoice_fact": False,
    }


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


def _reservation_entity(call_id: str) -> str:
    return _RESERVATION_ENTITY_PREFIX + call_id


def _model_cost_entity(call_id: str) -> str:
    return _MODEL_COST_ENTITY_PREFIX + call_id


def _reservation_record(
    call_id: str,
    owner_domain: str,
    pin: VersionPin,
    currency: str | None,
    reserved: float | int | None,
    frozen: float | int | None,
) -> dict[str, Any]:
    currency_value: Any = (
        currency
        if currency is not None
        else make_missing(
            "not_observed", "the pinned cost policy declares no currency"
        )
    )
    return {
        "record_type": RESERVATION_RECORD_TYPE,
        "schema_version": SCHEMA_VERSION,
        "call_id": call_id,
        "owner_domain": owner_domain,
        "kind": "reservation",
        "state": "reserved",
        "policy": pin.to_dict(),
        "currency": currency_value,
        "reserved_cost": (
            {
                "amount": reserved,
                "currency": currency,
                "basis": "policy_declaration",
            }
            if reserved is not None
            else make_missing(
                "not_observed",
                "the pinned cost policy declares no reserved cost",
            )
        ),
        "frozen_cost_limit": (
            {
                "amount": frozen,
                "currency": currency,
                "basis": "policy_declaration",
            }
            if frozen is not None
            else make_missing(
                "not_observed",
                "the pinned cost policy declares no frozen cost limit",
            )
        ),
        "reported_usage": make_missing(
            "not_applicable", "a reservation declares no observed usage"
        ),
        "cost_derivation": make_missing(
            "not_applicable", "a reservation is not a priced derivation"
        ),
        "invoiced_charge": make_missing(
            "not_observed", "a reservation is never an invoice fact"
        ),
        "is_observed_usage": False,
        "is_invoice_fact": False,
    }


def _reservation_state(
    channel_id: str, owner_domain: str, call_id: str
) -> tuple[Any, Any]:
    entity_id = _reservation_entity(call_id)
    state = evidence_journal.entity_state(channel_id, owner_domain, entity_id)
    reference = state.state
    if isinstance(reference, artifact_store.ArtifactReference):
        try:
            raw = artifact_store.resolve_artifact(channel_id, reference)
        except artifact_store.ArtifactError as exc:
            raise CostIntegrityError(
                f"the reserved cost artifact for {call_id!r} cannot be "
                f"resolved: {exc}"
            ) from exc
        reservation = _strict_json(raw, CostIntegrityError)
        if not isinstance(reservation, Mapping):
            raise CostIntegrityError(
                "the reserved cost artifact is not a JSON object"
            )
        if reservation.get("record_type") != RESERVATION_RECORD_TYPE:
            raise CostIntegrityError(
                "the reserved cost artifact is not a cost reservation"
            )
        if reservation.get("call_id") != call_id:
            raise CostIntegrityError(
                "the reserved cost artifact names a different call identity"
            )
        try:
            summary = {
                "artifact": reference.to_dict(),
                "call_id": call_id,
                "policy": reservation["policy"],
                "currency": reservation["currency"],
                "reserved_cost": reservation["reserved_cost"],
                "frozen_cost_limit": reservation["frozen_cost_limit"],
            }
        except KeyError as exc:
            raise CostIntegrityError(
                "the reserved cost artifact omits declared cost fields"
            ) from exc
        return summary, reference
    if _missing_envelope(reference) is None:
        raise CostIntegrityError(
            "the reservation entity state is neither an artifact reference "
            "nor a typed Missing envelope"
        )
    return (
        make_missing(
            "not_observed",
            "no cost reservation was committed for this call before the "
            "cost record",
        ),
        None,
    )


def _model_cost_record(
    call_id: str,
    owner_domain: str,
    reported_usage: Mapping[str, Any],
    pricing_state: Mapping[str, Any] | None,
    derivation: Mapping[str, Any],
    reservation: Any,
    source_refs: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    return {
        "record_type": MODEL_COST_RECORD_TYPE,
        "schema_version": SCHEMA_VERSION,
        "call_id": call_id,
        "owner_domain": owner_domain,
        "reported_usage": dict(reported_usage),
        "pricing": (
            pricing_state["record"]
            if pricing_state is not None
            else make_missing(
                "not_observed",
                "no pricing version was supplied for this call",
            )
        ),
        "cost_derivation": dict(derivation),
        "invoiced_charge": make_missing(
            "not_observed",
            "no provider invoice evidence was supplied; a computed cost is "
            "not an invoice fact",
        ),
        "reservation": reservation,
        "source_refs": [dict(reference) for reference in source_refs],
    }


# ---------------------------------------------------------------------------
# Evidence helpers
# ---------------------------------------------------------------------------


def _coerce_source_refs(source_refs: Any) -> list[dict[str, Any]]:
    if isinstance(source_refs, (str, bytes)) or not isinstance(
        source_refs, Sequence
    ):
        raise CostUsageError("source_refs must be a sequence of EvidenceRefs")
    coerced: list[dict[str, Any]] = []
    seen: set[bytes] = set()
    for index, reference in enumerate(source_refs):
        try:
            if isinstance(reference, evidence_journal.EvidenceRef):
                data = reference.to_dict()
            elif isinstance(reference, Mapping):
                data = evidence_journal.EvidenceRef.from_dict(reference).to_dict()
            else:
                raise TypeError(
                    "expected EvidenceRef, got "
                    f"{type(reference).__name__}"
                )
        except (TypeError, ValueError) as exc:
            raise CostUsageError(f"source_refs[{index}]: {exc}") from exc
        canonical = _canonical_bytes(data)
        if canonical in seen:
            raise CostUsageError(
                f"source_refs[{index}] duplicates an earlier citation; "
                "duplicated provider-call evidence is never charged twice"
            )
        seen.add(canonical)
        coerced.append(data)
    return coerced


def _reject_duplicate_evidence(
    journal: Any, call_id: str, source_refs: Sequence[Mapping[str, Any]]
) -> None:
    if not source_refs:
        return
    canonical = _canonical_bytes([dict(reference) for reference in source_refs])
    for envelope in journal.events:
        if envelope.event_kind != MODEL_COST_EVENT_KIND:
            continue
        data = envelope.payload.get("data")
        if not isinstance(data, Mapping):
            continue
        prior = data.get("cost_record")
        if not isinstance(prior, Mapping):
            continue
        prior_refs = prior.get("source_refs")
        if not isinstance(prior_refs, list) or not prior_refs:
            continue
        if _canonical_bytes(prior_refs) == canonical:
            prior_call = prior.get("call_id")
            if prior_call != call_id:
                raise CostDuplicateEvidenceError(
                    f"provider-call evidence is already priced under call "
                    f"{prior_call!r}; the same evidence is never charged twice"
                )


def _gate_record(
    call_id: str, record: Mapping[str, Any], error_cls: type[Exception]
) -> None:
    gate = {"id": call_id, "tokens": dict(record)}
    try:
        contract_codec.validate_record(_canonical_bytes(gate), "record/v1")
    except (TypeError, ValueError) as exc:
        raise error_cls(
            f"cost record is not strict JSON evidence: {exc}"
        ) from exc


def _event_submission(
    event_kind: str,
    data: Mapping[str, Any],
    measurements: Sequence[Mapping[str, Any]],
    evidence_refs: Sequence[Mapping[str, Any]],
    artifact_refs: Sequence[Mapping[str, Any]],
) -> Any:
    return evidence_journal.EventSubmission(
        producer_sequence=evidence_journal.NOT_APPLICABLE,
        event_kind=event_kind,
        event_schema_version=EVENT_SCHEMA_VERSION,
        occurred_at=evidence_journal.NOT_OBSERVED,
        payload=evidence_journal.EvidencePayload(
            data=dict(data),
            measurements=[dict(item) for item in measurements],
            evidence_refs=[dict(item) for item in evidence_refs],
            artifact_refs=[dict(item) for item in artifact_refs],
        ),
    )


def _commit_acknowledged(
    channel_id: str,
    owner_domain: str,
    entity_id: str,
    command_id: str,
    state_reference: Any,
    submission: Any,
    record_key: str,
    record: Mapping[str, Any],
) -> None:
    try:
        prefix = evidence_journal.commit_effect(
            channel_id,
            owner_domain,
            entity_id,
            command_id,
            0,
            state_reference,
            (submission,),
        )
    except evidence_journal.CommandConflictError as exc:
        raise CostConflictError(
            f"{record['call_id']!r} was already recorded with different "
            "content; conflicting cost evidence is never overwritten or "
            "charged twice"
        ) from exc
    except evidence_journal.RevisionConflictError as exc:
        raise CostConflictError(
            f"{record['call_id']!r} advanced after this accounting command; "
            "the caller must not re-charge the call"
        ) from exc
    except evidence_journal.EvidenceJournalError as exc:
        raise CostIntegrityError(
            f"cost accounting could not be committed: {exc}"
        ) from exc
    events = evidence_journal.read_prefix(channel_id, prefix)
    if not events:
        raise CostIntegrityError("acknowledged prefix is empty")
    tail = events[-1]
    if tail.event_kind != submission.event_kind:
        raise CostIntegrityError(
            "acknowledged prefix does not carry the committed accounting event"
        )
    acknowledged = tail.payload.get("data", {}).get(record_key)
    if acknowledged != dict(record):
        raise CostIntegrityError(
            "acknowledged accounting event does not match the committed record"
        )
    stored = evidence_journal.entity_state(channel_id, owner_domain, entity_id)
    if stored.state != state_reference:
        raise CostIntegrityError(
            "owner-local accounting state does not name the committed record"
        )


# ---------------------------------------------------------------------------
# Public interface (EXPOSES)
# ---------------------------------------------------------------------------


def event_kind_declarations(
    owner_domain: str,
    writer_roles: Sequence[str] = ("kernel",),
) -> list[dict[str, Any]]:
    """Return the manifest/ingress declarations for this module's events.

    The composition root registers each declaration with
    :func:`access_policy.register_event_kind` and lists it in the admitted
    manifest's ``event_registry`` before the first accounting write.
    """
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


def reserve_cost(
    channel_id: str, call_id: str, policy: VersionPin
) -> artifact_store.ArtifactReference:
    """Freeze one call's declared cost reservation from a pinned policy.

    The reservation is a declaration about budget, not observed usage and not
    an invoice fact.  Temporarily unknown policy amounts stay ``Missing``;
    they are never zero.  Repeating the same call with the same policy replays
    the committed reservation; repeating it with changed policy content is a
    conflict, so a frozen limit is never silently altered.
    """
    _require_identifier(channel_id, "channel_id")
    _require_identifier(call_id, "call_id")
    owner_domain = _channel_context(channel_id, call_id)
    _active_journal(owner_domain)  # fail before reading or retaining anything
    if not isinstance(policy, VersionPin):
        raise CostPolicyError(
            "policy must be a VersionPin naming retained cost-policy bytes"
        )
    policy_reference, document = _resolve_pin(
        channel_id, owner_domain, policy, CostPolicyError
    )
    currency, reserved, frozen = _parse_policy_document(document)
    record = _reservation_record(
        call_id, owner_domain, policy, currency, reserved, frozen
    )
    _gate_record(call_id, record, CostPolicyError)
    state_bytes = _canonical_bytes(record)
    state_reference = artifact_store.retain_artifact(
        channel_id, owner_domain, "application/json", state_bytes, "restricted"
    )
    submission = _event_submission(
        RESERVATION_EVENT_KIND,
        {"cost_reservation": record},
        (),
        (),
        (state_reference.to_dict(), policy_reference.to_dict()),
    )
    _commit_acknowledged(
        channel_id,
        owner_domain,
        _reservation_entity(call_id),
        "reserve_cost:" + call_id,
        state_reference,
        submission,
        "cost_reservation",
        record,
    )
    return state_reference


def record_model_cost(
    channel_id: str,
    call_id: str,
    usage: tuple[Any, ...],
    pricing: Any,
    source_refs: tuple[Any, ...],
) -> artifact_store.ArtifactReference:
    """Record one model call's reported usage and priced derivation.

    ``usage`` carries provider-reported or measured token evidence.
    Missing dimensions stay typed ``Missing`` envelopes and block cost
    derivation instead of contributing zero tokens.  ``pricing`` is either a
    :class:`VersionPin` naming a retained price schedule or a typed ``Missing``
    envelope; either way the computed cost is recorded as a derivation, while
    the invoice field remains ``Missing(not_observed)``.  A reservation taken
    for the same call is cited as a distinct artifact; it is never merged into
    observed usage or into the invoice.
    """
    _require_identifier(channel_id, "channel_id")
    _require_identifier(call_id, "call_id")
    owner_domain = _channel_context(channel_id, call_id)
    journal = _active_journal(owner_domain)
    clocks = _clock_descriptors(journal)
    measurements, by_name = _validate_usage(usage, clocks)
    reported_usage = {
        dimension: _usage_record(dimension, by_name.get(dimension))
        for dimension in TOKEN_DIMENSIONS
    }
    pricing_state = _pricing_state(channel_id, owner_domain, pricing)
    refs = _coerce_source_refs(source_refs)
    _reject_duplicate_evidence(journal, call_id, refs)
    derivation = _derive_cost(reported_usage, pricing_state)
    reservation, reservation_reference = _reservation_state(
        channel_id, owner_domain, call_id
    )
    record = _model_cost_record(
        call_id,
        owner_domain,
        reported_usage,
        pricing_state,
        derivation,
        reservation,
        refs,
    )
    _gate_record(call_id, record, CostIntegrityError)
    state_bytes = _canonical_bytes(record)
    state_reference = artifact_store.retain_artifact(
        channel_id, owner_domain, "application/json", state_bytes, "restricted"
    )
    artifact_refs = [state_reference.to_dict()]
    if pricing_state is not None:
        artifact_refs.append(pricing_state["reference"].to_dict())
    if reservation_reference is not None:
        artifact_refs.append(reservation_reference.to_dict())
    submission = _event_submission(
        MODEL_COST_EVENT_KIND,
        {"cost_record": record},
        measurements,
        refs,
        artifact_refs,
    )
    _commit_acknowledged(
        channel_id,
        owner_domain,
        _model_cost_entity(call_id),
        "record_model_cost:" + call_id,
        state_reference,
        submission,
        "cost_record",
        record,
    )
    return state_reference

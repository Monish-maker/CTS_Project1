"""Lossless JSON serialization for typed scan-history aggregates."""

from __future__ import annotations

import json
from dataclasses import fields, is_dataclass
from datetime import datetime
from enum import Enum
from typing import Any

from sentinelllm.core import enums, models

_MODEL_TYPES = {
    item.__name__: item
    for item in (
        models.AuthenticationConfiguration,
        models.RetryConfiguration,
        models.LLMConfiguration,
        models.ScanConfiguration,
        models.EndpointProfile,
        models.TargetProfile,
        models.AttackPlan,
        models.AttackJob,
        models.AttackResult,
        models.Evidence,
        models.Observation,
        models.AttackHypothesis,
        models.AdaptationDecision,
        models.PolicyDecision,
        models.CategoryCoverage,
        models.JudgeResult,
        models.Finding,
        models.ScanHistory,
    )
}
_ENUM_TYPES = {
    item.__name__: item
    for item in (
        enums.AdaptiveDecisionType,
        enums.AttackCategory,
        enums.CoverageStatus,
        enums.HypothesisStatus,
        enums.JobStatus,
        enums.JudgeOutcome,
        enums.RiskLevel,
        enums.ScanStatus,
        enums.VerificationStatus,
    )
}


def serialize_history(history: models.ScanHistory) -> str:
    """Serialize a history without flattening its dataclass and enum types."""
    return json.dumps(_encode(history), separators=(",", ":"), sort_keys=True)


def deserialize_history(payload: str) -> models.ScanHistory:
    """Restore a trusted locally generated history snapshot."""
    decoded = _decode(json.loads(payload))
    if not isinstance(decoded, models.ScanHistory):
        raise ValueError("history payload did not contain a ScanHistory")
    return decoded


def _encode(value: Any) -> Any:
    if isinstance(value, Enum):
        return {"__enum__": type(value).__name__, "value": value.value}
    if isinstance(value, datetime):
        return {"__datetime__": value.isoformat()}
    if is_dataclass(value) and not isinstance(value, type):
        return {
            "__type__": type(value).__name__,
            "fields": {field.name: _encode(getattr(value, field.name)) for field in fields(value)},
        }
    if isinstance(value, tuple):
        return {"__tuple__": [_encode(item) for item in value]}
    if isinstance(value, list):
        return [_encode(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _encode(item) for key, item in value.items()}
    return value


def _decode(value: Any) -> Any:
    if isinstance(value, list):
        return [_decode(item) for item in value]
    if not isinstance(value, dict):
        return value
    if "__enum__" in value:
        enum_type = _ENUM_TYPES[str(value["__enum__"])]
        return enum_type(value["value"])
    if "__datetime__" in value:
        return datetime.fromisoformat(str(value["__datetime__"]))
    if "__tuple__" in value:
        return tuple(_decode(item) for item in value["__tuple__"])
    if "__type__" in value:
        model_type = _MODEL_TYPES[str(value["__type__"])]
        decoded_fields = {str(key): _decode(item) for key, item in value.get("fields", {}).items()}
        return model_type(**decoded_fields)
    return {str(key): _decode(item) for key, item in value.items()}

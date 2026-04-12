"""JSON output for GPO analysis results."""

from __future__ import annotations

import json
from datetime import datetime
from enum import Enum
from typing import Any

from ..models.findings import GpoResult


def gpo_results_to_json(results: list[GpoResult], indent: int = 2) -> str:
    """Serialize a list of GpoResult to JSON."""
    data = []
    for result in results:
        entry = {
            "attributes": _serialize(result.attributes),
            "gpo_acl_results": [_serialize(a) for a in result.gpo_acl_results],
            "gpo_attribute_findings": [_serialize(f) for f in result.gpo_attribute_findings],
            "setting_results": [
                {
                    "setting_type": type(sr.setting).__name__ if sr.setting else None,
                    "setting": _serialize(sr.setting),
                    "findings": [_serialize(f) for f in sr.findings],
                }
                for sr in result.setting_results
            ],
        }
        data.append(entry)
    return json.dumps(data, indent=indent, ensure_ascii=True)


def _serialize(obj: Any) -> Any:
    if obj is None:
        return None
    if hasattr(obj, "__dataclass_fields__"):
        result = {}
        for field_name in obj.__dataclass_fields__:
            val = getattr(obj, field_name)
            serialized = _serialize(val)
            # Skip empty/default fields to keep JSON compact
            if serialized in (None, "", [], {}, 0, False):
                continue
            result[field_name] = serialized
        return result
    if isinstance(obj, list):
        return [_serialize(item) for item in obj]
    if isinstance(obj, dict):
        return {k: _serialize(v) for k, v in obj.items()}
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, str):
        return _clean_str(obj)
    return obj


def _clean_str(s: str) -> str:
    """Remove control characters that break JSON."""
    return "".join(c if ord(c) >= 32 else " " for c in s)

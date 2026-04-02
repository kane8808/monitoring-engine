from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Dict, List
from uuid import uuid4

import boto3


def _convert(value: Any) -> Any:
    if isinstance(value, float):
        return Decimal(str(value))
    if isinstance(value, dict):
        return {k: _convert(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_convert(v) for v in value]
    return value


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")


def _normalize_incident(item: Dict[str, Any]) -> Dict[str, Any]:
    incident = dict(item)
    incident.setdefault("incident_id", f"INC-{uuid4().hex[:8]}")
    incident.setdefault("timestamp", _utc_now_iso())
    return incident


def save_incidents(incidents: List[Dict[str, Any]], table_name: str) -> None:
    if not incidents:
        return

    dynamodb = boto3.resource("dynamodb")
    table = dynamodb.Table(table_name)

    for incident in incidents:
        normalized = _normalize_incident(incident)
        item = _convert(normalized)
        table.put_item(Item=item)
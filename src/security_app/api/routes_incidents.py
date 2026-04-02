from __future__ import annotations

from pathlib import Path
from typing import Any

from services.incident_service import list_incidents as _list_incidents
from services.incident_service import get_incident_detail as _get_incident_detail


def get_incidents(evidence_root: Path) -> dict[str, Any]:
    return {
        "ok": True,
        "items": _list_incidents(evidence_root),
    }


def get_incident(evidence_root: Path, incident_id: str) -> dict[str, Any]:
    detail = _get_incident_detail(evidence_root, incident_id)

    if not detail:
        return {
            "ok": False,
            "error": "incident not found",
        }

    return {
        "ok": True,
        "item": detail,
    }
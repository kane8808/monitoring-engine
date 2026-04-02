from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _safe_read_json(path: Path) -> dict[str, Any] | None:
    if not path.exists() or not path.is_file():
        return None

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def list_incidents(evidence_root: Path) -> list[dict[str, Any]]:
    if not evidence_root.exists():
        return []

    items: list[dict[str, Any]] = []

    for p in sorted(evidence_root.iterdir(), reverse=True):
        if not p.is_dir():
            continue

        snapshot = _safe_read_json(p / "snapshot.json") or {}
        decision = _safe_read_json(p / "decision.json") or {}
        status = _safe_read_json(p / "status.json") or {}

        items.append({
            "incident_id": p.name,
            "path": str(p),
            "created_at": snapshot.get("timestamp") or p.name,
            "host": snapshot.get("host"),
            "severity": (
                snapshot.get("level")
                or decision.get("severity")
                or "UNKNOWN"
            ),
            "title": snapshot.get("summary") or "Untitled Incident",
            "status": status.get("summary") or "open",
        })

    return items


def get_incident_detail(evidence_root: Path, incident_id: str) -> dict[str, Any] | None:
    incident_dir = evidence_root / incident_id
    if not incident_dir.exists() or not incident_dir.is_dir():
        return None

    snapshot = _safe_read_json(incident_dir / "snapshot.json")
    metrics = _safe_read_json(incident_dir / "metrics.json")
    status = _safe_read_json(incident_dir / "status.json")
    decision = _safe_read_json(incident_dir / "decision.json")
    response = _safe_read_json(incident_dir / "response.json")

    files: list[dict[str, Any]] = []
    for p in sorted(incident_dir.iterdir()):
        if p.is_file():
            files.append({
                "name": p.name,
                "size": p.stat().st_size,
                "path": str(p),
            })

    return {
        "incident_id": incident_id,
        "snapshot": snapshot,
        "metrics": metrics,
        "status": status,
        "decision": decision,
        "response": response,
        "files": files,
    }
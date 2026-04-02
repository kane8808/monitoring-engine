from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def list_evidence_files(evidence_root: Path, incident_id: str) -> list[dict[str, Any]]:
    incident_dir = evidence_root / incident_id
    if not incident_dir.exists() or not incident_dir.is_dir():
        return []

    results: list[dict[str, Any]] = []
    for p in sorted(incident_dir.iterdir()):
        if p.is_file():
            results.append({
                "name": p.name,
                "size": p.stat().st_size,
            })

    return results


def read_evidence_file(evidence_root: Path, incident_id: str, filename: str) -> dict[str, Any]:
    incident_dir = evidence_root / incident_id

    if not incident_dir.exists() or not incident_dir.is_dir():
        return {
            "ok": False,
            "error": "incident not found",
        }

    target = (incident_dir / filename).resolve()
    incident_dir_resolved = incident_dir.resolve()

    if incident_dir_resolved not in target.parents and target != incident_dir_resolved:
        return {
            "ok": False,
            "error": "invalid file path",
        }

    if not target.exists() or not target.is_file():
        return {
            "ok": False,
            "error": "file not found",
        }

    try:
        if target.suffix.lower() == ".json":
            content: Any = json.loads(target.read_text(encoding="utf-8"))
        else:
            content = target.read_text(encoding="utf-8", errors="replace")

        return {
            "ok": True,
            "filename": target.name,
            "content": content,
        }
    except Exception as e:
        return {
            "ok": False,
            "error": str(e),
        }
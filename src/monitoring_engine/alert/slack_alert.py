import json
import urllib.request
import urllib.error
from typing import Dict, Any, Optional


def send_slack(
    webhook_url: str,
    text: str,
    *,
    extra: Optional[Dict[str, Any]] = None,
    incident_id: Optional[str] = None,
    evidence_path: Optional[str] = None,
) -> None:
    payload: Dict[str, Any] = {"text": text}

    merged: Dict[str, Any] = {}
    if extra:
        merged.update(extra)
    if incident_id:
        merged["incident_id"] = incident_id
    if evidence_path:
        merged["evidence_path"] = evidence_path

    if merged:
        payload["attachments"] = [
            {"text": json.dumps(merged, ensure_ascii=False, indent=2)[:2500]}
        ]

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        print("[ERROR] slack HTTPError:", e.code, body)
        raise
    except Exception as e:
        print("[ERROR] slack Exception:", repr(e))
        raise
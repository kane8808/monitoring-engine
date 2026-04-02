# monitoring_tool/alert/sender.py
import json
import urllib.request
from typing import Any, Dict, Optional

from monitoring_tool.alert.dedup import should_send_alert, mark_alert_sent
from .formatter import build_slack_payload


def _post_webhook(webhook_url: str, payload: Dict[str, Any], timeout: int = 5) -> None:
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        # Slack incoming webhook은 보통 "ok" 또는 2xx를 반환
        _ = resp.read()


def send_slack_alert_if_needed(
    *,
    webhook_url: str,
    snapshot: Dict[str, Any],
    evidence_path: Optional[str] = None,
    dedup_key: Optional[str] = None,
) -> Dict[str, Any]:
    """
    snapshot 기반으로 Slack 알림을 보냅니다(중복 방지 포함).
    반환:
      {"sent": bool, "reason": str, "dedup_key": str}
    """
    level = (snapshot.get("level") or "INFO").upper()
    host = snapshot.get("host", "-")
    anomaly_type = snapshot.get("anomaly_type", "-")

    # dedup_key 기본 규칙: 같은 host+type+level 은 같은 알림으로 취급
    key = dedup_key or f"{host}:{anomaly_type}:{level}"

    if not should_send_alert(key):
        return {"sent": False, "reason": "dedup_blocked", "dedup_key": key}

    payload = build_slack_payload(snapshot, evidence_path=evidence_path)
    _post_webhook(webhook_url, payload)

    mark_alert_sent(key)
    return {"sent": True, "reason": "sent", "dedup_key": key}

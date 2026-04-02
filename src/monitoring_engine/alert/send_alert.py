from __future__ import annotations

import os
import uuid
import json
import urllib.request
from typing import Any, Dict

from monitoring_engine.alert.slack_payload import build_slack_payload
from monitoring_engine.alert.dedup import should_send_alert, mark_alert_sent


class SlackPostError(RuntimeError):
    pass


def post_to_slack(webhook_url: str, payload: Dict[str, Any], timeout_sec: int = 10) -> None:
    if not webhook_url or not str(webhook_url).strip():
        raise ValueError("webhook_url is empty")

    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=data,
        headers={"Content-Type": "application/json; charset=utf-8"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            body = resp.read().decode("utf-8", errors="ignore").strip()
            if resp.status < 200 or resp.status >= 300:
                raise SlackPostError(f"Slack webhook HTTP {resp.status}: {body}")
    except Exception as e:
        raise SlackPostError(f"Slack webhook post failed: {e}") from e


DEFAULT_TTL = 900  # 15분


def build_fingerprint(status: Dict[str, Any]) -> str:
    host = (
        status.get("host")
        or status.get("meta", {}).get("host")
        or "unknown"
    )

    net = status.get("detect", {}).get("network_anomaly", {})
    reason = str(net.get("reason", "")).lower()

    if "critical" in reason:
        rule = "network_crit"
    elif "warn" in reason:
        rule = "network_warn"
    else:
        rule = "network_unknown"

    return f"host={host}|kind=network_rate|rule={rule}"


def _extract_webhook_url() -> str:
    """
    Slack Webhook URL은 환경변수에서만 읽는다.
    """
    return os.environ.get("SLACK_WEBHOOK_URL", "").strip()


def send_alert(status: Dict[str, Any], *, timeout_sec: int = 10) -> Dict[str, Any]:
    decision = status.setdefault("decision", {})
    alert = decision.get("should_alert", False)
    severity = decision.get("severity", "INFO")

    if not alert:
        return status

    fingerprint = build_fingerprint(status)

    net = status.get("detect", {}).get("network_anomaly", {})
    ttl = int(net.get("ttl_seconds", DEFAULT_TTL))
    if ttl <= 0:
        ttl = DEFAULT_TTL

    if not should_send_alert(
        fingerprint=fingerprint,
        ttl_seconds=ttl,
        level=severity,
    ):
        decision["dedup"] = "HIT"
        decision["fingerprint"] = fingerprint
        return status

    incident_id = decision.get("incident_id")
    if not incident_id:
        incident_id = f"INC-{uuid.uuid4().hex[:8]}"
        decision["incident_id"] = incident_id

    decision["fingerprint"] = fingerprint
    decision["dedup"] = "MISS"

    status.setdefault("level", severity)
    status.setdefault("severity", severity)
    status.setdefault("incident_id", incident_id)
    status.setdefault("fingerprint", fingerprint)

    reasons = decision.get("reasons") or []
    if reasons and not status.get("summary"):
        status["summary"] = reasons[0]

    webhook_url = _extract_webhook_url()
    if not webhook_url:
        raise ValueError("SLACK_WEBHOOK_URL environment variable is not set")

    payload = build_slack_payload(status=status)
    post_to_slack(webhook_url, payload, timeout_sec=timeout_sec)

    mark_alert_sent(
        fingerprint=fingerprint,
        ttl_seconds=ttl,
        level=severity,
    )

    return status
from __future__ import annotations

from typing import Any, Dict, Optional


def _u(v: Any) -> str:
    return "" if v is None else str(v).strip()


def _upper(v: Any) -> str:
    return _u(v).upper()


def _emoji(level: str) -> str:
    lvl = _upper(level)
    if lvl in ("CRITICAL", "FATAL"):
        return "🚨"
    if lvl == "HIGH":
        return "🟠"
    if lvl in ("WARN", "WARNING"):
        return "⚠️"
    if lvl in ("OK", "PASS", "HEALTHY", "NORMAL", "RECOVERED"):
        return "✅"
    return "ℹ️"


def _normalize_level(level: Any) -> str:
    lvl = _upper(level)
    if lvl == "FATAL":
        return "CRITICAL"
    if lvl == "WARNING":
        return "WARN"
    if lvl in ("PASS", "HEALTHY", "NORMAL"):
        return "OK"
    if lvl in ("OK", "WARN", "HIGH", "CRITICAL"):
        return lvl
    return "WARN"


def _best_effort_host(status: Dict[str, Any]) -> str:
    if _u(status.get("host")):
        return _u(status["host"])
    return "unknown-host"


def _pick_incident_id(status: Dict[str, Any]) -> str:
    for k in ("incident_id", "incidentId", "id"):
        if _u(status.get(k)):
            return _u(status[k])

    decision = status.get("decision")
    if isinstance(decision, dict):
        for k in ("incident_id", "incidentId", "id"):
            if _u(decision.get(k)):
                return _u(decision[k])

    detect = status.get("detect")
    if isinstance(detect, dict):
        for k in ("incident_id", "incidentId", "id"):
            if _u(detect.get(k)):
                return _u(detect[k])

    return "-"


def _pick_level(status: Dict[str, Any]) -> str:
    decision = status.get("decision")
    if isinstance(decision, dict):
        level = (
            decision.get("severity")
            or decision.get("level")
            or status.get("level")
            or status.get("overall")
            or status.get("severity")
        )
    else:
        level = status.get("level") or status.get("overall") or status.get("severity")

    return _normalize_level(level)


def _pick_summary(status: Dict[str, Any]) -> str:
    if _u(status.get("summary")):
        return _u(status.get("summary"))
    if _u(status.get("title")):
        return _u(status.get("title"))

    decision = status.get("decision")
    if isinstance(decision, dict):
        reasons = decision.get("reasons") or []
        if isinstance(reasons, list) and reasons:
            return _u(reasons[0]) or "Monitoring alert"

    return "Monitoring alert"


def _pick_fingerprint(status: Dict[str, Any]) -> str:
    if _u(status.get("fingerprint")):
        return _u(status.get("fingerprint"))

    decision = status.get("decision")
    if isinstance(decision, dict) and _u(decision.get("fingerprint")):
        return _u(decision.get("fingerprint"))

    return ""


def _summarize_judge_fields(judge: Optional[Dict[str, Any]]) -> list[Dict[str, Any]]:
    if not isinstance(judge, dict):
        return []

    order = ["cpu", "memory", "disk", "network", "log"]
    keys = [k for k in order if k in judge] + [k for k in judge.keys() if k not in order]

    fields: list[Dict[str, Any]] = []
    for k in keys[:10]:
        v = judge.get(k)
        if isinstance(v, dict):
            st = _u(v.get("status")) or _u(v.get("level")) or "-"
            rs = _u(v.get("reason"))

            meta = v.get("meta") if isinstance(v.get("meta"), dict) else {}
            val = meta.get("value")
            thr = meta.get("threshold")

            extra = []
            if val is not None:
                extra.append(f"value={val}")
            if thr is not None:
                extra.append(f"threshold={thr}")
            extra_txt = f" ({', '.join(extra)})" if extra else ""

            line = f"{st}{extra_txt}" + (f"\n_{rs}_" if rs else "")
        else:
            line = _u(v) or "-"

        fields.append({"type": "mrkdwn", "text": f"*{k}*\n{line}"})

    return fields


def _summarize_detect_lines(detect: Optional[Dict[str, Any]]) -> list[str]:
    if not isinstance(detect, dict):
        return []

    lines: list[str] = []
    preferred = ["metric_anomaly", "log_anomaly", "anomaly_engine"]

    for k in preferred:
        v = detect.get(k)
        if isinstance(v, dict):
            st = _u(v.get("status")) or _u(v.get("level")) or "-"
            rs = _u(v.get("reason"))
            lines.append(f"• *{k}*: *{st}*" + (f" — {rs}" if rs else ""))

    for k, v in detect.items():
        if k in preferred:
            continue
        if isinstance(v, dict) and (
            v.get("status") is not None
            or v.get("level") is not None
            or v.get("reason") is not None
        ):
            st = _u(v.get("status")) or _u(v.get("level")) or "-"
            rs = _u(v.get("reason"))
            lines.append(f"• *{k}*: *{st}*" + (f" — {rs}" if rs else ""))

    return lines


def build_slack_payload(*, status: Dict[str, Any], fallback_text: bool = True) -> Dict[str, Any]:
    level = _pick_level(status)
    summary = _pick_summary(status)
    host = _best_effort_host(status)
    incident_id = _pick_incident_id(status)
    evidence_path = _u(status.get("evidence_path")) or _u(status.get("path"))
    fingerprint = _pick_fingerprint(status)

    judge = status.get("judge") if isinstance(status.get("judge"), dict) else None
    detect = status.get("detect") if isinstance(status.get("detect"), dict) else None

    if level == "OK":
        header = f"{_emoji('RECOVERED')} [RECOVERED] {summary}"
        headline = "*복구됨*\n- 상태가 정상 범위로 돌아왔습니다."
    else:
        header = f"{_emoji(level)} [{level}] {summary}"
        headline = "*상태 확인 필요*\n- 임계치/룰 기반 이상이 감지되었습니다."

    blocks: list[Dict[str, Any]] = [
        {"type": "header", "text": {"type": "plain_text", "text": header[:150]}},
        {"type": "section", "text": {"type": "mrkdwn", "text": headline}},
        {"type": "divider"},
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Host*\n{host}"},
                {"type": "mrkdwn", "text": f"*Incident ID*\n{incident_id}"},
            ],
        },
    ]

    judge_fields = _summarize_judge_fields(judge)
    if judge_fields:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": "*Judge Result*"}})
        blocks.append({"type": "section", "fields": judge_fields})

    detect_lines = _summarize_detect_lines(detect)
    if detect_lines:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": "*Detection Detail*"}})
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(detect_lines)[:2900]}})

    ctx_parts = []
    if fingerprint:
        ctx_parts.append(f"fingerprint: `{fingerprint}`")
    if evidence_path:
        ctx_parts.append(f"📂 Evidence: `{evidence_path}`")
    if ctx_parts:
        blocks.append({"type": "divider"})
        blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": " | ".join(ctx_parts)[:2900]}]})

    if evidence_path and evidence_path.lower().startswith(("http://", "https://")):
        blocks.append(
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "📂 View Evidence"},
                        "url": evidence_path,
                    }
                ],
            }
        )

    payload: Dict[str, Any] = {"blocks": blocks}
    if fallback_text:
        payload["text"] = header
    return payload
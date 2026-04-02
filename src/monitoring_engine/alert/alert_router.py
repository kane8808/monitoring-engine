# monitoring_tool/alert/alert_router.py
from __future__ import annotations

from typing import Any, Dict, Optional

from monitoring_tool.alert.sender import send_slack_alert_if_needed


def _find_webhook_url(context: Dict[str, Any]) -> Optional[str]:
    """
    프로젝트마다 config 적재 위치가 다르므로, 여러 후보 키를 순서대로 탐색합니다.
    """
    # 1) context에 바로 들어있는 경우
    for k in ("slack_webhook_url", "SLACK_WEBHOOK_URL", "webhook_url"):
        v = context.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()

    # 2) context['config'] 아래에 있는 경우
    cfg = context.get("config")
    if isinstance(cfg, dict):
        for k in ("slack_webhook_url", "SLACK_WEBHOOK_URL", "webhook_url"):
            v = cfg.get(k)
            if isinstance(v, str) and v.strip():
                return v.strip()

        # 중첩 구조 예: config['slack']['webhook_url']
        slack = cfg.get("slack")
        if isinstance(slack, dict):
            v = slack.get("webhook_url") or slack.get("url")
            if isinstance(v, str) and v.strip():
                return v.strip()

    return None


def _find_snapshot(context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    evidence 단계에서 만든 snapshot을 어디에 담았는지 몰라서 후보 키를 탐색합니다.
    """
    for k in ("snapshot", "evidence_snapshot", "evidence", "last_snapshot"):
        v = context.get(k)
        if isinstance(v, dict) and v:
            return v
    return None


def send(context: Dict[str, Any]) -> Dict[str, Any]:
    """
    레거시 로더가 호출하는 엔트리 함수.
    - evidence에서 만든 snapshot + evidence_path를 기반으로 slack 알림 전송
    - dedup 적용
    결과는 context['alert']에 넣어 반환
    """
    out = dict(context)

    snapshot = _find_snapshot(out)
    evidence_path = out.get("evidence_path") or out.get("evidence_file") or out.get("evidence", {}).get("path") if isinstance(out.get("evidence"), dict) else None
    webhook_url = _find_webhook_url(out)

    # snapshot이 없으면 알림 단계에서 할 게 없음
    if not snapshot:
        out["alert"] = {"sent": False, "reason": "no_snapshot"}
        return out

    # webhook 설정이 없으면 전송 스킵
    if not webhook_url:
        out["alert"] = {"sent": False, "reason": "no_webhook_url"}
        return out

    # dedup_key(선택): 없으면 sender에서 host:type:level로 자동 생성
    dedup_key = out.get("dedup_key") or out.get("alert_dedup_key")

    try:
        result = send_slack_alert_if_needed(
            webhook_url=webhook_url,
            snapshot=snapshot,
            evidence_path=evidence_path,
            dedup_key=dedup_key,
        )
        out["alert"] = result
    except Exception as e:
        out["alert"] = {"sent": False, "reason": "exception", "error": str(e)}

    return out


# 레거시 호환: call_entry가 send/route/run/main을 찾으므로 alias 제공
route = send
run = send
main = send
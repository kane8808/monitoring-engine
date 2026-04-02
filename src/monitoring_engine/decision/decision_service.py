from __future__ import annotations

import socket
import time
from typing import Any, Optional

from monitoring_engine.alert.decision import decide_alert


# 동일 fingerprint incident 병합용 (메모리 캐시)
_LAST_INCIDENT_BY_FP: dict[str, tuple[str, float]] = {}


def decision_fingerprint(host: str, status: dict, detect: dict) -> str:
    """
    judge / detect 결과를 기준으로 동일 이벤트 여부를 판단할 fingerprint 생성
    """
    judge = (status or {}).get("judge") or {}
    judge_bad = [
        k for k, v in judge.items()
        if isinstance(v, dict) and v.get("status") != "OK"
    ]

    detect_bad = []
    if isinstance(detect, dict):
        for k, v in detect.items():
            if isinstance(v, str) and v != "OK":
                detect_bad.append(k)
            elif isinstance(v, dict) and v.get("status") not in (None, "OK"):
                detect_bad.append(k)

    return f"host={host}|judge={','.join(sorted(judge_bad))}|detect={','.join(sorted(detect_bad))}"


def build_decision(
    metrics: dict,
    status: dict,
    cfg: dict,
    merge_ttl_sec: int = 300,
) -> tuple[dict, dict]:
    """
    pipeline 결과(metrics/status)를 받아
    - alert decision 생성
    - fingerprint 기반 incident 병합
    - Slack/response에 필요한 status 보강

    return:
        decision, enriched_status
    """
    judge_status = (status or {}).get("judge") or {}
    detect = (status or {}).get("detect") or {}

    # 1) alert 판단
    decision = decide_alert(judge_status, detect, cfg)

    print(
        "[DECISION]",
        f"alert={decision['should_alert']}",
        f"severity={decision['severity']}",
        f"reasons={decision['reasons']}",
        f"incident={decision['incident_id']}",
    )

    # 2) host 추출
    primary = metrics.get("primary_iface") or {}
    host = socket.gethostname() or metrics.get("host") or primary.get("ipv4") or "unknown-host"

    # 3) fingerprint 생성
    fp = decision_fingerprint(host, status, detect)

    # 4) 동일 fingerprint incident 병합
    now = time.time()
    prev = _LAST_INCIDENT_BY_FP.get(fp)

    if prev is not None:
        prev_incident_id, prev_ts = prev
        if (now - prev_ts) <= merge_ttl_sec:
            decision["incident_id"] = prev_incident_id
        else:
            _LAST_INCIDENT_BY_FP[fp] = (decision["incident_id"], now)
    else:
        _LAST_INCIDENT_BY_FP[fp] = (decision["incident_id"], now)

    # 5) status 보강
    enriched_status = dict(status)
    enriched_status["host"] = host
    enriched_status["fingerprint"] = fp
    enriched_status["incident_id"] = decision.get("incident_id") or "-"
    enriched_status["level"] = decision.get("severity") or "OK"
    enriched_status["summary"] = (
        decision.get("summary")
        or decision.get("title")
        or "Monitoring alert"
    )

    return decision, enriched_status
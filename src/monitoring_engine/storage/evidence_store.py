from __future__ import annotations

import json
import os
from typing import Any, Dict, Tuple, Optional
from datetime import datetime, timezone
from .paths import evidence_dir


def _date_key(ts: str) -> str:
    return ts[:10] if isinstance(ts, str) and len(ts) >= 10 else "unknown-date"

def save_evidence(evidence: Dict[str, Any]) -> Tuple[str, str]:
    """
    evidence(dict)를 incident_id 기준 파일 하나로 누적 저장
    return: (date_key, out_path)
    """
    incident_id = evidence.get("incident_id")
    if not incident_id:
        raise ValueError("save_evidence: evidence['incident_id'] is required")

    ts = evidence.get("timestamp")
    if not ts:
        raise ValueError("save_evidence: evidence['timestamp'] is required")

    date_key = _date_key(ts)
    out_dir = os.path.join(evidence_dir(), date_key)
    os.makedirs(out_dir, exist_ok=True)

    out_path = os.path.join(out_dir, f"{incident_id}.json")

    # -------------------------
    # 기존 evidence 파일 로드
    # -------------------------
    if os.path.exists(out_path):
        try:
            with open(out_path, "r", encoding="utf-8") as f:
                existing = json.load(f)
        except Exception:
            existing = {}
    else:
        existing = {}

    # -------------------------
    # events 로드
    # -------------------------
    events = existing.get("events")
    if not isinstance(events, list):
        events = []

    # -------------------------
    # transition 감지 (prev -> curr)  ※ append 전에 계산해야 정확
    # -------------------------
    prev_level = None
    if events:
        prev = events[-1]
        if isinstance(prev, dict):
            prev_level = prev.get("level")

    curr_level = evidence.get("level")

    last_transition = None
    if prev_level is not None and curr_level is not None and prev_level != curr_level:
        last_transition = {
            "from": prev_level,
            "to": curr_level,
            "at": ts,
        }

    # -------------------------
    # events 누적
    # -------------------------
    
    events.append(evidence)

    # -------------------------
    # RESOLVED 판정 (OK 연속 N회)
    # -------------------------
    RESOLVE_OK_STREAK = 3

    def _is_ok_event(ev: Dict[str, Any]) -> bool:
        lv = ev.get("level")
        if lv in ("INFO", "OK"):
            return True
        return False

    ok_streak = 0
    for ev in reversed(events):
        if isinstance(ev, dict) and _is_ok_event(ev):
            ok_streak += 1
        else:
            break

    resolved_at = None
    state = existing.get("state") if isinstance(existing, dict) else None
    if state is None:
        state = "OPEN"

    if state != "RESOLVED" and ok_streak >= RESOLVE_OK_STREAK:
        state = "RESOLVED"
        resolved_at = ts
    else:
        resolved_at = existing.get("resolved_at") if isinstance(existing, dict) else None

    # -------------------------
    # 🔁 CRITICAL 재발생 시 RESOLVED → OPEN 복귀
    # -------------------------
    curr_level = evidence.get("level")

    if state == "RESOLVED" and curr_level == "CRITICAL":
        state = "OPEN"
        resolved_at = None
        # (선택) 기존 closed 정보도 무효화하고 싶으면 같이 초기화
        # closed_at = None
        # close_reason = None

    # -------------------------
    # CLOSED 판정 (RESOLVED 유지 N초)
    # -------------------------
    CLOSE_AFTER_SECONDS = 600  # 10분(원하는 값으로 조정)

    # existing 문서에 기존 closed 정보가 있으면 유지
    closed_at = existing.get("closed_at")
    close_reason = existing.get("close_reason")
    close_alert_sent = bool(existing.get("close_alert_sent", False))

    def _to_epoch(ts_str: str) -> Optional[float]:
        # 현재 프로젝트 timestamp 예: "2026-02-05T02-00-29Z"
        try:
            dt = datetime.strptime(ts_str, "%Y-%m-%dT%H-%M-%SZ").replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except Exception:
            return None

    # RESOLVED가 된 시점(resolved_at) 이후, 일정 시간 유지되면 CLOSED
    if state == "RESOLVED" and resolved_at and not closed_at:
        now_ep = _to_epoch(ts)
        res_ep = _to_epoch(resolved_at)
        if now_ep is not None and res_ep is not None:
            if (now_ep - res_ep) >= CLOSE_AFTER_SECONDS:
                state = "CLOSED"
                closed_at = ts
                close_reason = f"auto-closed after {CLOSE_AFTER_SECONDS}s in RESOLVED"

    # -------------------------
    # 상단 메타 갱신
    # -------------------------
    created_at = existing.get("created_at") or ts
    updated_at = ts

    summary = evidence.get("summary") or existing.get("summary")
    level_for_doc = evidence.get("level") or existing.get("level")

    doc = {
        "incident_id": incident_id,
        "created_at": created_at,
        "updated_at": updated_at,
        "level": level_for_doc,
        "summary": summary,
        "last_level": curr_level,
        "last_transition": last_transition,
        "state": state,
        "resolved_at": resolved_at,
        "closed_at": closed_at,
        "close_reason": close_reason,
        "close_alert_sent": close_alert_sent,
        "events": events,
    }

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)

    return date_key, out_path
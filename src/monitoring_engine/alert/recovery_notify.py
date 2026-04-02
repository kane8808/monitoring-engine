import json
import os
import time
from typing import Dict, Any, Optional

STATE_PATH = os.path.join("storage", "recovery_state.json")


def _load_state() -> Dict[str, Any]:
    if not os.path.exists(STATE_PATH):
        return {}
    try:
        with open(STATE_PATH, "r", encoding="utf-8") as f:
            return json.load(f) or {}
    except Exception:
        return {}


def _save_state(state: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
    with open(STATE_PATH, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)


def _has_problem(judgements: Dict[str, Any], detections: Dict[str, Any]) -> bool:
    """
    NOT OK 또는 WARN이 하나라도 있으면 '문제 상태'
    """
    for v in (judgements or {}).values():
        if isinstance(v, dict) and v.get("status") in ("NOT OK", "WARN"):
            return True
    for v in (detections or {}).values():
        if isinstance(v, dict) and v.get("status") in ("NOT OK", "WARN"):
            return True
    return False


def check_recovery(
    judgements: Dict[str, Any],
    detections: Dict[str, Any],
) -> Optional[str]:
    """
    반환:
      - "RECOVERED" : 문제 → OK 전이 발생 (알림 1회)
      - None        : 그 외 (아직 문제이거나, 이미 OK)
    """
    state = _load_state()

    was_problem = state.get("was_problem", False)
    is_problem = _has_problem(judgements, detections)

    # 문제 → OK 로 전이된 순간
    if was_problem and not is_problem:
        state["was_problem"] = False
        state["last_recovered_ts"] = int(time.time())
        _save_state(state)
        return "RECOVERED"

    # 현재 문제 상태면 플래그만 유지
    if is_problem:
        state["was_problem"] = True
        _save_state(state)

    return None
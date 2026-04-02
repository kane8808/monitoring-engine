# monitoring_tool/alert/dedup.py
from __future__ import annotations

import json
import os
import time
from typing import Any, Dict

STATE_PATH = os.path.join(os.getcwd(), "data", "dedup_state.json")


def _now() -> int:
    return int(time.time())


def _load_state() -> Dict[str, Any]:
    try:
        with open(STATE_PATH, "r", encoding="utf-8") as f:
            return json.load(f) or {}
    except FileNotFoundError:
        return {}
    except Exception:
        # 깨진 파일이면 안전하게 초기화
        return {}


def _save_state(state: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
    tmp = STATE_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)
    os.replace(tmp, STATE_PATH)


def _key(fingerprint: str, level: str) -> str:
    # ✅ dedup은 fingerprint(+level)만으로 고정
    return f"{level}|{fingerprint}"


def should_send_alert(*, fingerprint: str, ttl_seconds: int, level: str) -> bool:
    ttl = int(ttl_seconds) if ttl_seconds else 0
    if ttl <= 0:
        ttl = 900  # 안전 기본값

    state = _load_state()
    k = _key(fingerprint, level)
    item = state.get(k)

    if not item:
        return True

    last = int(item.get("last_sent_at") or 0)
    if _now() - last < ttl:
        return False
    return True


def mark_alert_sent(*, fingerprint: str, ttl_seconds: int, level: str) -> None:
    state = _load_state()
    k = _key(fingerprint, level)
    state[k] = {
        "last_sent_at": _now(),
        "ttl_seconds": int(ttl_seconds) if ttl_seconds else 900,
    }
    _save_state(state)
# monitoring_tool/alert/recovered.py
from typing import Optional

_last_level: Optional[str] = None


def is_recovered(current_level: str) -> bool:
    """
    이전 상태가 WARN/CRITICAL 이고 현재가 OK면 RECOVERED(True)
    - 메모리 기반(프로세스 재시작 시 초기화)
    """
    global _last_level
    cur = (current_level or "").upper()

    recovered = _last_level in ("WARN", "CRITICAL") and cur == "OK"
    _last_level = cur
    return recovered
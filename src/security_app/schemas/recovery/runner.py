# recovery/runner.py
from __future__ import annotations

import platform
import subprocess
from typing import Any, Dict, List, Tuple


def _run_cmd(cmd: List[str]) -> Tuple[int, str]:
    """
    로컬 명령 실행(필요 최소).
    - 운영에서 위험할 수 있으니 allowlist 방식으로만 사용 권장.
    """
    p = subprocess.run(cmd, capture_output=True, text=True, shell=False)
    out = (p.stdout or "") + (p.stderr or "")
    return p.returncode, out[:3000]


def execute_actions(actions: List[Dict[str, Any]], *, execute: bool = False) -> Dict[str, Any]:
    """
    execute=False: 실행하지 않고 계획만 반환(기본 안전)
    execute=True : 제한된 범위에서만 실행(현재는 예시 수준)
    """
    results: List[Dict[str, Any]] = []

    for a in actions:
        action = a.get("action")
        if not execute:
            results.append({"action": action, "executed": False, "result": "planned"})
            continue

        # ✅ 여기부터는 '정말 실행' (현재는 안전한 예시만)
        if action == "check_interface":
            # Windows: ipconfig, Linux: ip a
            if platform.system().lower().startswith("win"):
                code, out = _run_cmd(["ipconfig"])
            else:
                code, out = _run_cmd(["ip", "a"])
            results.append({"action": action, "executed": True, "code": code, "output": out})
            continue

        # 위험/환경 의존 액션은 기본적으로 실행하지 않음
        results.append(
            {
                "action": action,
                "executed": False,
                "result": "skipped (not allowed by default)",
                "hint": "execute_actions의 allowlist에 명시적으로 추가 후 사용",
            }
        )

    return {"execute": execute, "results": results}
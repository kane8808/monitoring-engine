"""
rollback.py

역할:
- 배포 롤백(복구 액션) 템플릿

주의:
- 롤백은 조직/환경마다 방법이 다릅니다.
  예) git checkout, docker image tag rollback, helm rollback, argo rollback 등
- 잘못 롤백하면 더 큰 장애가 될 수 있으므로 기본은 "비활성"을 권장합니다.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Dict, Any, List, Optional


@dataclass(frozen=True)
class RollbackConfig:
    """
    롤백 설정(예시)
    """
    enabled: bool = False              # 안전 기본값: False
    mode: str = "shell"                # "shell" 템플릿(환경에 맞게 변경)
    command: Optional[List[str]] = None  # 실제 롤백 명령어 (예: ["helm","rollback","myapp","1"])


def rollback(config: RollbackConfig) -> Dict[str, Any]:
    """
    롤백 실행

    Args:
        config: RollbackConfig

    Returns:
        복구 결과(dict)
    """
    if not config.enabled:
        return {
            "action": "rollback",
            "ok": False,
            "reason": "rollback is disabled (safe mode)",
            "mode": config.mode,
        }

    if not config.command:
        return {
            "action": "rollback",
            "ok": False,
            "reason": "rollback command not provided",
            "mode": config.mode,
        }

    try:
        p = subprocess.run(
            config.command,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        ok = (p.returncode == 0)
        return {
            "action": "rollback",
            "ok": ok,
            "reason": "rollback executed" if ok else "rollback failed",
            "mode": config.mode,
            "returncode": p.returncode,
            "stdout": p.stdout.strip(),
            "stderr": p.stderr.strip(),
            "command": config.command,
        }
    except subprocess.TimeoutExpired as e:
        return {
            "action": "rollback",
            "ok": False,
            "reason": f"rollback timeout: {e}",
            "mode": config.mode,
            "command": config.command,
        }
    except Exception as e:
        return {
            "action": "rollback",
            "ok": False,
            "reason": f"rollback exception: {e}",
            "mode": config.mode,
            "command": config.command,
        }

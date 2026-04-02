"""
restart_service.py

역할:
- 시스템 서비스(daemon)를 재시작하는 복구 액션 모듈

지원:
- Linux systemd: systemctl restart <service>
- (옵션) fallback: service <name> restart

주의:
- 이 기능은 운영환경에서 영향도가 큽니다.
- 반드시 권한(sudo)과 서비스명 정확성 검증이 필요합니다.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from typing import Dict, Any, List, Optional, Tuple


@dataclass(frozen=True)
class CommandResult:
    """
    커맨드 실행 결과 표준화
    """
    ok: bool
    cmd: List[str]
    returncode: int
    stdout: str
    stderr: str


def _run(cmd: List[str], timeout_sec: int = 20) -> CommandResult:
    """
    명령어를 실행하고 결과를 반환합니다.
    - shell=False (보안상 권장)
    """
    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False,
        )
        return CommandResult(
            ok=(p.returncode == 0),
            cmd=cmd,
            returncode=p.returncode,
            stdout=p.stdout.strip(),
            stderr=p.stderr.strip(),
        )
    except subprocess.TimeoutExpired as e:
        return CommandResult(
            ok=False,
            cmd=cmd,
            returncode=124,
            stdout="",
            stderr=f"timeout: {e}",
        )
    except Exception as e:
        return CommandResult(
            ok=False,
            cmd=cmd,
            returncode=1,
            stdout="",
            stderr=str(e),
        )


def restart_service(
    service_name: str,
    *,
    use_sudo: bool = False,
    timeout_sec: int = 20,
) -> Dict[str, Any]:
    """
    서비스를 재시작합니다.

    Args:
        service_name: systemd 서비스명 (예: nginx, docker, myapp)
        use_sudo: sudo를 붙일지 여부 (권한 필요 시 True)
        timeout_sec: 커맨드 타임아웃

    Returns:
        dict 형태의 복구 결과
    """
    # systemctl 존재 여부 확인
    has_systemctl = shutil.which("systemctl") is not None
    has_service_cmd = shutil.which("service") is not None

    tried: List[CommandResult] = []

    def build(cmd: List[str]) -> List[str]:
        return (["sudo"] + cmd) if use_sudo else cmd

    if has_systemctl:
        tried.append(_run(build(["systemctl", "restart", service_name]), timeout_sec=timeout_sec))
        # 상태 확인도 함께 해두면 복구 성공 여부 판단이 더 명확해집니다.
        tried.append(_run(build(["systemctl", "is-active", service_name]), timeout_sec=timeout_sec))
    elif has_service_cmd:
        tried.append(_run(build(["service", service_name, "restart"]), timeout_sec=timeout_sec))
    else:
        return {
            "action": "restart_service",
            "ok": False,
            "reason": "no systemctl/service command available",
            "service": service_name,
            "tried": [],
        }

    # 성공 판단: 마지막 상태(is-active)가 active면 OK로 처리
    ok = False
    reason = "restart failed"
    if tried:
        last = tried[-1]
        if last.ok and ("active" in last.stdout or last.returncode == 0):
            ok = True
            reason = "service restarted and active"
        else:
            # restart 자체가 성공했는지라도 확인
            for r in tried:
                if r.ok:
                    reason = "restart command succeeded but status check failed"
                    break

    return {
        "action": "restart_service",
        "ok": ok,
        "reason": reason,
        "service": service_name,
        "tried": [
            {
                "cmd": r.cmd,
                "ok": r.ok,
                "returncode": r.returncode,
                "stdout": r.stdout,
                "stderr": r.stderr,
            }
            for r in tried
        ],
    }
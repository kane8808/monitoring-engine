from __future__ import annotations

import ipaddress
import json
import os
import signal
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from security_app.services.playbook import run_playbook
from security_app.services.playbook import build_playbook

JsonDict = dict[str, Any]
CommandRunner = Callable[..., subprocess.CompletedProcess[str]]


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_write_json(path: Path, data: JsonDict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )


def _append_response_history(incident_dir: Path, result: JsonDict) -> None:
    """
    response.json 파일에 마지막 실행 결과를 저장합니다.
    history 배열에도 누적합니다.
    """
    response_path = incident_dir / "response.json"

    current: JsonDict = {}
    if response_path.exists() and response_path.is_file():
        try:
            current = json.loads(response_path.read_text(encoding="utf-8"))
        except Exception:
            current = {}

    history = current.get("history")
    if not isinstance(history, list):
        history = []

    history.append(result)

    current.update({
        "updated_at": _utc_now_iso(),
        "last_result": result,
        "status": "done" if result.get("ok") else "failed",
        "history": history,
    })

    _safe_write_json(response_path, current)


def _validate_incident_dir(evidence_root: Path, incident_id: str) -> Path:
    incident_dir = (evidence_root / incident_id).resolve()
    evidence_root_resolved = evidence_root.resolve()

    if evidence_root_resolved not in incident_dir.parents:
        raise ValueError("invalid incident path")

    if not incident_dir.exists() or not incident_dir.is_dir():
        raise FileNotFoundError(f"incident not found: {incident_id}")

    return incident_dir


def _validate_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as e:
        raise ValueError(f"invalid ip address: {value}") from e


def _run_command(
    cmd: list[str],
    *,
    runner: CommandRunner = subprocess.run,
) -> subprocess.CompletedProcess[str]:
    return runner(
        cmd,
        check=True,
        text=True,
        capture_output=True,
    )


def _kill_process(
    context: JsonDict,
    *,
    dry_run: bool,
    runner: CommandRunner = subprocess.run,
) -> JsonDict:
    pid = context.get("pid")
    sig_name = str(context.get("signal", "SIGKILL")).upper()

    if pid is None:
        return {"ok": False, "error": "pid not provided"}

    try:
        pid_int = int(pid)
    except (TypeError, ValueError):
        return {"ok": False, "error": f"invalid pid: {pid}"}

    signal_map = {
        "SIGTERM": signal.SIGTERM,
        "SIGKILL": signal.SIGKILL,
        "SIGINT": signal.SIGINT,
    }
    sig = signal_map.get(sig_name)
    if sig is None:
        return {"ok": False, "error": f"unsupported signal: {sig_name}"}

    if dry_run:
        return {
            "ok": True,
            "action": "kill_process",
            "dry_run": True,
            "pid": pid_int,
            "signal": sig_name,
            "message": "process kill simulated",
        }

    try:
        os.kill(pid_int, sig)
        return {
            "ok": True,
            "action": "kill_process",
            "dry_run": False,
            "pid": pid_int,
            "signal": sig_name,
            "message": "process killed",
        }
    except ProcessLookupError:
        return {
            "ok": False,
            "action": "kill_process",
            "error": f"process not found: {pid_int}",
        }
    except PermissionError:
        return {
            "ok": False,
            "action": "kill_process",
            "error": f"permission denied for pid: {pid_int}",
        }
    except Exception as e:
        return {
            "ok": False,
            "action": "kill_process",
            "error": str(e),
        }


def _block_ip(
    context: JsonDict,
    *,
    dry_run: bool,
    runner: CommandRunner = subprocess.run,
) -> JsonDict:
    raw_ip = context.get("ip")
    if not raw_ip:
        return {"ok": False, "error": "ip not provided"}

    try:
        ip = _validate_ip(str(raw_ip))
    except ValueError as e:
        return {"ok": False, "action": "block_ip", "error": str(e)}

    chain = str(context.get("chain", "INPUT")).upper()
    action = str(context.get("rule_action", "DROP")).upper()
    insert_mode = str(context.get("insert_mode", "append")).lower()

    if chain not in {"INPUT", "OUTPUT", "FORWARD"}:
        return {"ok": False, "action": "block_ip", "error": f"unsupported chain: {chain}"}

    if action not in {"DROP", "REJECT"}:
        return {"ok": False, "action": "block_ip", "error": f"unsupported rule_action: {action}"}

    if insert_mode == "insert":
        cmd = ["iptables", "-I", chain, "-s", ip, "-j", action]
    else:
        cmd = ["iptables", "-A", chain, "-s", ip, "-j", action]

    if dry_run:
        return {
            "ok": True,
            "action": "block_ip",
            "dry_run": True,
            "ip": ip,
            "chain": chain,
            "rule_action": action,
            "command": cmd,
            "message": "iptables rule simulated",
        }

    try:
        completed = _run_command(cmd, runner=runner)
        return {
            "ok": True,
            "action": "block_ip",
            "dry_run": False,
            "ip": ip,
            "chain": chain,
            "rule_action": action,
            "command": cmd,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "message": "iptables rule applied",
        }
    except subprocess.CalledProcessError as e:
        return {
            "ok": False,
            "action": "block_ip",
            "ip": ip,
            "command": cmd,
            "returncode": e.returncode,
            "stdout": e.stdout,
            "stderr": e.stderr,
            "error": "iptables command failed",
        }
    except FileNotFoundError:
        return {
            "ok": False,
            "action": "block_ip",
            "error": "iptables not found",
        }
    except Exception as e:
        return {
            "ok": False,
            "action": "block_ip",
            "error": str(e),
        }


def _send_alert(
    context: JsonDict,
    *,
    dry_run: bool,
) -> JsonDict:
    """
    현재는 기본 알림 스텁입니다.
    추후 Slack/SNS/Email 연동 지점으로 확장하세요.
    """
    message = str(context.get("message", "security alert"))
    channel = str(context.get("channel", "console"))

    if dry_run:
        return {
            "ok": True,
            "action": "send_alert",
            "dry_run": True,
            "channel": channel,
            "message": message,
        }

    print(f"[ALERT][{channel}] {message}")

    return {
        "ok": True,
        "action": "send_alert",
        "dry_run": False,
        "channel": channel,
        "message": message,
    }


def _execute_playbook(
    context: JsonDict,
    *,
    dry_run: bool,
) -> JsonDict:
    """
    playbook.py의 run_playbook(context) 호출.
    dry_run 정보도 context에 주입합니다.
    """
    payload = dict(context)
    payload["dry_run"] = dry_run

    try:
        result = run_playbook(payload)

        if isinstance(result, dict):
            result.setdefault("ok", True)
            result.setdefault("action", "playbook")
            result.setdefault("dry_run", dry_run)
            return result

        return {
            "ok": True,
            "action": "playbook",
            "dry_run": dry_run,
            "result": result,
        }
    except Exception as e:
        return {
            "ok": False,
            "action": "playbook",
            "dry_run": dry_run,
            "error": str(e),
        }


def execute_response(
    *,
    evidence_root: Path,
    incident_id: str,
    action: str,
    context: JsonDict | None = None,
    dry_run: bool = True,
    runner: CommandRunner = subprocess.run,
    save_result: bool = True,
) -> JsonDict:
    """
    incident 기준 대응 실행 진입점

    Parameters
    ----------
    evidence_root:
        monitoring_engine evidence 루트 경로
    incident_id:
        incident 디렉터리명
    action:
        kill_process / block_ip / send_alert / playbook
    context:
        대응에 필요한 추가 정보
    dry_run:
        True면 실제 시스템 변경 없이 시뮬레이션
    runner:
        subprocess.run 대체 주입용(테스트용)
    save_result:
        response.json 저장 여부
    """
    context = context or {}

    base_result: JsonDict = {
        "incident_id": incident_id,
        "action": action,
        "requested_at": _utc_now_iso(),
        "dry_run": dry_run,
        "context": context,
    }

    try:
        incident_dir = _validate_incident_dir(evidence_root, incident_id)
    except Exception as e:
        result = {
            **base_result,
            "ok": False,
            "error": str(e),
        }
        return result

    action = action.strip().lower()

    if action == "kill_process":
        result = _kill_process(context, dry_run=dry_run, runner=runner)

    elif action == "block_ip":
        result = _block_ip(context, dry_run=dry_run, runner=runner)

    elif action == "send_alert":
        result = _send_alert(context, dry_run=dry_run)

    elif action == "playbook":
        result = _execute_playbook(context, dry_run=dry_run)

    else:
        result = {
            "ok": False,
            "action": action,
            "error": f"unknown action: {action}",
        }

    final_result: JsonDict = {
        **base_result,
        **result,
        "finished_at": _utc_now_iso(),
    }

    if save_result:
        try:
            _append_response_history(incident_dir, final_result)
        except Exception as e:
            final_result["save_warning"] = f"failed to write response.json: {e}"

    return final_result


def execute_default_response(
    *,
    evidence_root: Path,
    incident_id: str,
    finding: JsonDict | None = None,
    dry_run: bool = True,
) -> JsonDict:
    """
    finding 내용을 보고 기본 대응을 선택하는 간단한 헬퍼입니다.
    프로젝트 초반 자동 대응 연결용으로 사용하면 됩니다.
    """
    finding = finding or {}

    attacker_ip = finding.get("attacker_ip") or finding.get("ip")
    suspicious_pid = finding.get("pid")
    severity = str(finding.get("severity", "")).upper()
    rule_name = str(finding.get("rule") or finding.get("title") or "")

    if attacker_ip and severity in {"HIGH", "CRITICAL"}:
        return execute_response(
            evidence_root=evidence_root,
            incident_id=incident_id,
            action="block_ip",
            context={
                "ip": attacker_ip,
                "chain": "INPUT",
                "rule_action": "DROP",
                "reason": rule_name or "high severity incident",
            },
            dry_run=dry_run,
        )

    if suspicious_pid and severity in {"HIGH", "CRITICAL"}:
        return execute_response(
            evidence_root=evidence_root,
            incident_id=incident_id,
            action="kill_process",
            context={
                "pid": suspicious_pid,
                "signal": "SIGKILL",
                "reason": rule_name or "high severity incident",
            },
            dry_run=dry_run,
        )

    return execute_response(
        evidence_root=evidence_root,
        incident_id=incident_id,
        action="send_alert",
        context={
            "channel": "console",
            "message": f"default response triggered for {incident_id} ({rule_name or 'unknown rule'})",
        },
        dry_run=dry_run,
    )
def generate_playbook_from_incident(
    evidence_root: Path,
    incident_id: str,
) -> dict:
    """
    incident 기반 playbook 생성
    """

    from security_app.services.incident_service import get_incident_detail

    detail = get_incident_detail(evidence_root, incident_id)

    if not detail:
        return {
            "ok": False,
            "error": "incident not found",
        }

    report = detail.get("findings") or detail.get("snapshot") or {}

    playbook = build_playbook(report)

    return {
        "ok": True,
        "incident_id": incident_id,
        "playbook": playbook,
    }
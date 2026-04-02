from __future__ import annotations

from typing import Any, Dict, List
import re


SHELL_NAMES = {
    "bash",
    "sh",
    "zsh",
    "dash",
    "ash",
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
}

# reverse shell 성격이 강한 명령행 패턴
REVERSE_SHELL_PATTERNS = [
    r"/dev/tcp/\d{1,3}(?:\.\d{1,3}){3}/\d+",
    r"\bbash\s+-i\b",
    r"\bsh\s+-i\b",
    r"\bnc(?:at)?\b.*\s-e\s+",
    r"\bsocat\b.*exec:",
    r"\bpython(?:3)?\s+-c\b.*socket",
    r"\bperl\s+-e\b.*socket",
    r"\bpowershell(?:\.exe)?\b.*tcpclient",
]

# 정상 앱 오탐 방지
ALLOWLIST_PROCESS_NAMES = {
    "chrome.exe",
    "msedge.exe",
    "msedgewebview2.exe",
    "code.exe",
    "cursor.exe",
    "slack.exe",
    "notion.exe",
    "widgets.exe",
    "node.exe",
}


def _normalize_cmdline(cmdline_raw: Any) -> str:
    if isinstance(cmdline_raw, list):
        return " ".join(str(x) for x in cmdline_raw if x is not None)
    return str(cmdline_raw or "")


def _is_loopback_or_empty(ip: str | None) -> bool:
    if not ip:
        return True
    ip = str(ip).strip()
    return (
        ip == ""
        or ip.startswith("127.")
        or ip == "::1"
        or ip.lower() == "localhost"
    )


def detect(process_list: List[Dict[str, Any]]) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []

    for proc in process_list:
        name = str(proc.get("name", "") or "").lower().strip()
        cmdline = _normalize_cmdline(proc.get("cmdline"))
        cmdline_l = cmdline.lower()
        connections = proc.get("connections", []) or []

        # 정상 앱 제외
        if name in ALLOWLIST_PROCESS_NAMES:
            continue

        matched_patterns: List[str] = []

        # 1) 셸 계열 또는 위험 패턴 존재 여부
        is_shell = name in SHELL_NAMES
        for pattern in REVERSE_SHELL_PATTERNS:
            if re.search(pattern, cmdline_l):
                matched_patterns.append(pattern)

        # 2) 외부 연결이 있는지
        external_connections = []
        for conn in connections:
            if not isinstance(conn, dict):
                continue

            remote_ip = conn.get("remote_ip")
            remote_port = conn.get("remote_port")
            status = str(conn.get("status", "") or "").upper()

            if _is_loopback_or_empty(remote_ip):
                continue

            # 연결 상태가 의미 있는 경우만
            if status not in {"ESTABLISHED", "SYN_SENT", "LISTEN"} and remote_port is None:
                continue

            external_connections.append(conn)

        # 3) 탐지 조건
        #    - 셸 프로세스 + 외부 연결
        #    - 또는 reverse shell 패턴 + 외부 연결
        if (is_shell or matched_patterns) and external_connections:
            findings.append({
                "pid": proc.get("pid"),
                "name": name,
                "cmdline": cmdline,
                "username": proc.get("username"),
                "ppid": proc.get("ppid"),
                "matched_patterns": matched_patterns,
                "connections": external_connections,
            })

    if findings:
        return {
            "status": "CRITICAL",
            "findings": findings,
        }

    return {
        "status": "OK",
        "findings": [],
    }
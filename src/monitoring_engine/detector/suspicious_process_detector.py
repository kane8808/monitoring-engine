from __future__ import annotations

from typing import Any, Dict, List
import re


# 프로세스 이름 기준 의심 도구
SUSPICIOUS_PROCESS_NAMES = {
    "nc",
    "nc.exe",
    "ncat",
    "ncat.exe",
    "netcat",
    "netcat.exe",
    "socat",
    "socat.exe",
}

# 명령행 기준 의심 패턴
SUSPICIOUS_CMD_PATTERNS = [
    r"\bbash\s+-i\b",
    r"\bsh\s+-i\b",
    r"/dev/tcp/",
    r"\bpython(?:3)?\s+-c\b",
    r"\bperl\s+-e\b",
    r"\bcurl\b.*\|\s*sh\b",
    r"\bwget\b.*\|\s*sh\b",
    r"\bnc(?:at)?\b.*\s-e\s+",
    r"\bsocat\b.*exec:",
]

# 오탐이 많이 나는 정상 프로세스
ALLOWLIST_PROCESS_NAMES = {
    "cursor.exe",
    "code.exe",
    "chrome.exe",
    "msedge.exe",
    "msedgewebview2.exe",
    "notion.exe",
    "slack.exe",
    "widgets.exe",
    "node.exe",
}


def _normalize_cmdline(cmdline_raw: Any) -> str:
    if isinstance(cmdline_raw, list):
        return " ".join(str(x) for x in cmdline_raw if x is not None)
    return str(cmdline_raw or "")


def detect(process_list: List[Dict[str, Any]]) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []

    for proc in process_list:
        name = str(proc.get("name", "") or "").lower().strip()
        cmdline = _normalize_cmdline(proc.get("cmdline"))
        cmdline_l = cmdline.lower()
        connections = proc.get("connections", []) or []

        # 1) 정상 프로세스명은 우선 제외
        if name in ALLOWLIST_PROCESS_NAMES:
            continue

        matched_keywords: List[str] = []

        # 2) 프로세스 이름 자체가 의심 도구인지
        if name in SUSPICIOUS_PROCESS_NAMES:
            matched_keywords.append(f"name:{name}")

        # 3) 명령행 패턴 검사
        for pattern in SUSPICIOUS_CMD_PATTERNS:
            if re.search(pattern, cmdline_l):
                matched_keywords.append(f"cmd:{pattern}")

        # 4) 추가 강화 조건:
        #    nc/ncat/socat 계열은 연결 정보가 있거나 실행 옵션이 위험할 때만 탐지
        high_risk_tool = name in SUSPICIOUS_PROCESS_NAMES
        has_network = any(
            conn.get("remote_ip") or conn.get("local_port")
            for conn in connections
            if isinstance(conn, dict)
        )

        # 단순 문자열만 맞고 실질 근거가 없으면 제외
        if high_risk_tool and not has_network and not matched_keywords:
            continue

        if matched_keywords:
            findings.append({
                "pid": proc.get("pid"),
                "name": name,
                "cmdline": cmdline,
                "username": proc.get("username"),
                "ppid": proc.get("ppid"),
                "connections": connections,
                "matched_keywords": matched_keywords,
            })

    if findings:
        return {
            "status": "HIGH",
            "findings": findings,
        }

    return {
        "status": "OK",
        "findings": [],
    }
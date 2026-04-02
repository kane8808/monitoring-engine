from __future__ import annotations

import re
from collections import defaultdict
from typing import Any, Dict, List


FAILED_PATTERNS = (
    "failed password",
    "authentication failure",
    "invalid user",
)

IP_PATTERNS = [
    re.compile(r"\bfrom\s+(\d+\.\d+\.\d+\.\d+)\b", re.IGNORECASE),
]

USER_PATTERNS = [
    re.compile(r"failed password for invalid user (\S+)", re.IGNORECASE),
    re.compile(r"failed password for (\S+)", re.IGNORECASE),
    re.compile(r"user[=:\s]+(\S+)", re.IGNORECASE),
]

THRESHOLD = 10


def _extract_ip(text: str) -> str | None:
    for pattern in IP_PATTERNS:
        match = pattern.search(text)
        if match:
            return match.group(1)
    return None


def _extract_user(text: str) -> str | None:
    for pattern in USER_PATTERNS:
        match = pattern.search(text)
        if match:
            return match.group(1)
    return None


def detect(log_lines: List[str]) -> Dict[str, Any]:
    counter_by_ip = defaultdict(int)
    matched_lines_by_ip = defaultdict(list)
    users_by_ip = defaultdict(set)

    for line in log_lines:
        text = str(line)
        text_l = text.lower()

        if not any(pat in text_l for pat in FAILED_PATTERNS):
            continue

        ip = _extract_ip(text)
        if not ip:
            continue

        user = _extract_user(text)

        counter_by_ip[ip] += 1
        matched_lines_by_ip[ip].append(text)

        if user:
            users_by_ip[ip].add(user)

    findings: List[Dict[str, Any]] = []

    for ip, count in counter_by_ip.items():
        if count >= THRESHOLD:
            findings.append({
                "source_ip": ip,
                "fail_count": count,
                "target_users": sorted(users_by_ip[ip]),
                "matched_lines": matched_lines_by_ip[ip][-20:],
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
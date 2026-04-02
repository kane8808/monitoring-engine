from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from ..base import BaseDetector


FAILED_PATTERNS = (
    "Failed password",
    "authentication failure",
    "Invalid user",
)

IP_RE = re.compile(r"from\s+(\d+\.\d+\.\d+\.\d+)")
DEFAULT_THRESHOLD = 3


class AuthTraceDetector(BaseDetector):
    name = "auth_trace"

    def detect(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        logs = self._extract_auth_logs(context)
        threshold = self._get_threshold(context)

        counter: dict[str, int] = defaultdict(int)
        matched_lines: dict[str, list[str]] = defaultdict(list)

        for line in logs:
            text = str(line)

            if not any(pattern in text for pattern in FAILED_PATTERNS):
                continue

            match = IP_RE.search(text)
            if not match:
                continue

            ip = match.group(1)
            counter[ip] += 1
            matched_lines[ip].append(text)

        findings: list[dict[str, Any]] = []

        for ip, count in counter.items():
            if count < threshold:
                continue

            findings.append(
                {
                    "detector": self.name,
                    "type": "repeated_auth_failures",
                    "severity": self._severity_from_count(count, threshold),
                    "title": "Repeated authentication failures detected",
                    "summary": f"IP {ip} generated {count} authentication failure events.",
                    "evidence": {
                        "src_ip": ip,
                        "count": count,
                        "threshold": threshold,
                        "matched_lines": matched_lines[ip][:20],
                    },
                }
            )

        return findings

    def _extract_auth_logs(self, context: dict[str, Any]) -> list[str]:
        logs = context.get("logs", {})

        if isinstance(logs, dict):
            auth_logs = logs.get("auth")
            if isinstance(auth_logs, list):
                return [str(x) for x in auth_logs]

        if "log_lines" in context and isinstance(context["log_lines"], list):
            return [str(x) for x in context["log_lines"]]

        return []

    def _get_threshold(self, context: dict[str, Any]) -> int:
        config = context.get("config", {})
        detector_cfg = config.get("detector", {})
        auth_cfg = detector_cfg.get("auth_trace", {})

        threshold = auth_cfg.get("threshold", DEFAULT_THRESHOLD)

        try:
            return int(threshold)
        except Exception:
            return DEFAULT_THRESHOLD

    def _severity_from_count(self, count: int, threshold: int) -> str:
        if count >= threshold * 3:
            return "critical"
        if count >= threshold * 2:
            return "high"
        return "warning"
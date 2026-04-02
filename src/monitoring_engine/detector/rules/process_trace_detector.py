from __future__ import annotations

from typing import Any

from ..base import BaseDetector


SUSPICIOUS_KEYWORDS = (
    "nc ",
    "ncat ",
    "netcat ",
    "socat ",
    "bash -i",
    "/dev/tcp/",
    "python -c",
    "python3 -c",
    "perl -e",
    "ruby -e",
    "php -r",
    "curl | bash",
    "curl|bash",
    "wget | sh",
    "wget|sh",
    "powershell -enc",
    "cmd.exe /c",
)


class ProcessTraceDetector(BaseDetector):
    name = "process_trace"

    def detect(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        processes = self._extract_processes(context)
        findings: list[dict[str, Any]] = []

        for proc in processes:
            cmdline = self._normalize_process(proc)
            lowered = cmdline.lower()

            matched = [kw for kw in SUSPICIOUS_KEYWORDS if kw.lower() in lowered]
            if not matched:
                continue

            severity = self._severity_from_matches(matched)

            findings.append(
                {
                    "detector": self.name,
                    "type": "suspicious_process_execution",
                    "severity": severity,
                    "title": "Suspicious process execution detected",
                    "summary": f"Suspicious process matched keywords: {', '.join(matched)}",
                    "evidence": {
                        "command": cmdline,
                        "matched_keywords": matched,
                    },
                }
            )

        return findings

    def _extract_processes(self, context: dict[str, Any]) -> list[Any]:
        if isinstance(context.get("processes"), list):
            return context["processes"]

        metrics = context.get("metrics", {})
        if isinstance(metrics, dict) and isinstance(metrics.get("processes"), list):
            return metrics["processes"]

        raw_result = context.get("raw_result", {})
        if isinstance(raw_result, dict):
            bundle = raw_result.get("bundle", {})
            if isinstance(bundle, dict):
                proc_bundle = bundle.get("process") or bundle.get("processes") or {}
                if isinstance(proc_bundle, dict):
                    data = proc_bundle.get("data")
                    if isinstance(data, list):
                        return data
                if isinstance(proc_bundle, list):
                    return proc_bundle

        return []

    def _normalize_process(self, proc: Any) -> str:
        if isinstance(proc, str):
            return proc.strip()

        if isinstance(proc, dict):
            for key in ("cmdline", "command", "cmd", "name"):
                value = proc.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()

            if isinstance(proc.get("args"), list):
                return " ".join(str(x) for x in proc["args"])

        return str(proc).strip()

    def _severity_from_matches(self, matched: list[str]) -> str:
        critical_markers = {
            "bash -i",
            "/dev/tcp/",
            "powershell -enc",
            "cmd.exe /c",
            "curl | bash",
            "curl|bash",
            "wget | sh",
            "wget|sh",
        }

        if any(x in critical_markers for x in matched):
            return "critical"

        if len(matched) >= 2:
            return "high"

        return "warning"
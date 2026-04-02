from __future__ import annotations

from typing import Any

from .registry import get_detectors


class DetectorManager:
    def __init__(self) -> None:
        self.detectors = get_detectors()

    def run_all(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []

        for detector in self.detectors:
            try:
                result = detector.detect(context)
                if result:
                    findings.extend(result)
            except Exception as e:
                findings.append(
                    {
                        "detector": getattr(detector, "name", detector.__class__.__name__),
                        "type": "detector_error",
                        "severity": "warning",
                        "title": "Detector execution failed",
                        "summary": str(e),
                        "evidence": {},
                    }
                )

        return findings
from __future__ import annotations

from typing import Any, List, Dict

from monitoring_engine.core.pipeline import run_pipeline as run_once
from monitoring_engine.decision.decision_service import build_decision
from monitoring_engine.detector.manager import DetectorManager
from monitoring_engine.model.incident import build_incident


def run_pipeline(cfg: dict | None = None) -> List[Dict[str, Any]]:
    """
    Lambda용 1회 실행 파이프라인
    """

    cfg = cfg or {}
    detector_manager = DetectorManager()

    # 1회 실행
    result = run_once(cfg, prev_metrics=None, include_debug=True)

    metrics = result.get("metrics") or {}
    judge = result.get("judge") or {}
    detect = result.get("detect") or {}

    # trace detector
    detector_context = {
        "logs": result.get("logs") or {},
        "metrics": metrics,
        "processes": metrics.get("processes") or [],
        "config": cfg,
        "raw_result": result,
    }

    trace_findings = detector_manager.run_all(detector_context)

    # decision 생성
    decision, status = build_decision(
        metrics=metrics,
        status={
            "judge": judge,
            "detect": detect,
        },
        cfg=cfg,
    )

    # 🔥 incident 생성 (핵심)
    incident = build_incident(
        severity=decision.get("severity", "info"),
        category="security_event",
        rule_name="composite_detection",
        message=(decision.get("reasons") or ["anomaly"])[0],
        src_ip=None,
        host_name=None,
        raw_data={
            "metrics": metrics,
            "judge": judge,
            "detect": detect,
            "trace": trace_findings,
            "decision": decision,
        },
    )

    return [incident]
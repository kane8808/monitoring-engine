from typing import Any, Dict, Optional

from .network_rate_detector import calc_network_rate
from .network_anomaly_detector import detect_network_anomaly

from .suspicious_process_detector import detect as detect_suspicious_process
from .reverse_shell_detector import detect as detect_reverse_shell
from .brute_force_login_detector import detect as detect_brute_force


def run_detect(
    metrics: Dict[str, Any],
    cfg: Optional[Dict[str, Any]] = None,
    judge_status: Optional[Dict[str, Any]] = None,
    prev_metrics: Optional[Dict[str, Any]] = None,
    include_debug: bool = True,
) -> Dict[str, Any]:
    cfg = cfg or {}

    # 1) 네트워크 rate 계산/추출
    rate = calc_network_rate(metrics, prev_metrics)

    # 2) 네트워크 기반 이상 판정
    net_anom = detect_network_anomaly(rate, cfg=cfg)

    if isinstance(net_anom, dict):
        network_level = net_anom.get("status", "OK")
    else:
        network_level = str(net_anom)

    if network_level not in ("OK", "WARN", "CRITICAL", "HIGH"):
        network_level = "OK"

    # 3) 신규 보안 탐지 입력 데이터
    process_list = metrics.get("process", []) or []
    log_lines = metrics.get("logs", []) or []

    # 4) 신규 탐지기 실행
    suspicious_result = detect_suspicious_process(process_list)
    reverse_shell_result = detect_reverse_shell(process_list)
    brute_force_result = detect_brute_force(log_lines)

    suspicious_level = _extract_status(suspicious_result)
    reverse_shell_level = _extract_status(reverse_shell_result)
    brute_force_level = _extract_status(brute_force_result)

    # 5) 기존 anomaly + 신규 anomaly 집계
    metric_anomaly = _aggregate_many(
        network_level,
        suspicious_level,
        reverse_shell_level,
    )

    log_anomaly = _aggregate_many(
        brute_force_level,
    )

    anomaly_engine = _aggregate_many(
        metric_anomaly,
        log_anomaly,
    )

    out = {
        "metric_anomaly": metric_anomaly,
        "log_anomaly": log_anomaly,
        "anomaly_engine": anomaly_engine,
        "network_rate": rate,

        "suspicious_process": suspicious_result,
        "reverse_shell_connection": reverse_shell_result,
        "brute_force_login": brute_force_result,
    }

    if include_debug:
        out["network_anomaly"] = net_anom

    return out


def _extract_status(result: Any) -> str:
    if isinstance(result, dict):
        status = result.get("status", "OK")
    elif isinstance(result, str):
        status = result
    else:
        status = "OK"

    if status not in ("OK", "WARN", "HIGH", "CRITICAL"):
        return "OK"
    return status


def _aggregate_many(*levels: str) -> str:
    order = {
        "CRITICAL": 4,
        "HIGH": 3,
        "WARN": 2,
        "OK": 1,
    }
    score = max(order.get(level, 1) for level in levels if level is not None)

    if score == 4:
        return "CRITICAL"
    if score == 3:
        return "HIGH"
    if score == 2:
        return "WARN"
    return "OK"
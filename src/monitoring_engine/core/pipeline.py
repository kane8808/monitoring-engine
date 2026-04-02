from __future__ import annotations

from monitoring_engine.utils.metrics_utils import dig

from monitoring_engine.collector import collect_all
from monitoring_engine.judge.judge import judge_all
from monitoring_engine.detector import run_detect


def _normalize_log_lines(raw) -> list[str]:
    if raw is None:
        return []

    if isinstance(raw, list):
        return [str(x) for x in raw if str(x).strip()]

    if isinstance(raw, str):
        return [line for line in raw.splitlines() if line.strip()]

    return [str(raw)]


def flatten_metrics(bundle: dict) -> dict:
    """
    collect_all()이 반환하는 묶음(metrics_bundle)을
    judge/detect가 기대하는 평탄 구조로 변환합니다.
    """
    cpu = bundle.get("cpu") or {}
    mem = bundle.get("memory") or {}
    disk = bundle.get("disk") or {}
    net = bundle.get("network") or {}
    log = bundle.get("log") or {}
    proc = bundle.get("process") or {}
    proc_data = proc.get("data") or []
    
    cpu_percent = dig(cpu, {"cpu_percent", "percent", "usage_percent", "total_percent"})
    ram_percent = dig(mem, {"ram_percent", "memory_percent", "percent", "used_percent"})
    disk_max_percent = dig(disk, {"disk_max_percent", "max_percent", "percent", "usage_percent"})

    # log_collector 실제 구조 반영
    log_data = log.get("data") or {}
    log_meta = log_data.get("meta") or {}

    log_path = log_meta.get("path")
    log_exists = log_meta.get("exists")
    log_error = log_meta.get("error") or log_meta.get("read_error") or log_meta.get("stat_error")
    log_lines = _normalize_log_lines(log_data.get("lines"))

    host = (
        dig(net, {"host"})
        or dig(cpu, {"host"})
        or dig(mem, {"host"})
        or dig(disk, {"host"})
        or log.get("host")
    )

    return {
        "cpu_percent": cpu_percent,
        "ram_percent": ram_percent,
        "disk_max_percent": disk_max_percent,
        "primary_iface": net,
        "log_path": log_path,
        "log_exists": log_exists,
        "log_error": log_error,
        "log_lines": log_lines,
        "processes": proc_data,
        "host": host,
    }


def run_pipeline(cfg: dict, prev_metrics: dict | None = None, include_debug: bool = True) -> dict:
    """
    엔진 1회 실행 파이프라인
    흐름:
    collect -> flatten -> judge(1차) -> network summary/rate -> judge(2차) -> detect
    """
    sleep_sec = int((cfg or {}).get("cycle_seconds", 5))

    # 1) Collect
    bundle = collect_all(cfg)
    metrics = flatten_metrics(bundle)

    # detector 입력용 logs
    logs = {
        "auth": metrics.get("log_lines") or [],
    }

    # 2) 1차 Judge
    status_judge = judge_all(metrics, cfg)

    # 3) Judge가 고른 NIC 기준으로 summary / rate 생성
    from monitoring_engine.collector.network_summary import build_primary_iface_summary
    from monitoring_engine.collector.network_rate import add_net_rates

    network_bundle = metrics.get("primary_iface") or {}

    prefer = None
    net_j = status_judge.get("network")
    if isinstance(net_j, dict):
        meta = net_j.get("meta") or {}
        if isinstance(meta, dict):
            prefer = meta.get("name")

    summary = build_primary_iface_summary(network_bundle, prefer_name=prefer)

    prev_summary = (
        prev_metrics.get("primary_iface_summary")
        if isinstance(prev_metrics, dict)
        else None
    )

    summary = add_net_rates(summary, prev_summary=prev_summary, delta_sec=sleep_sec)
    metrics["primary_iface_summary"] = summary

    metrics["tx_rate_bps"] = summary.get("tx_rate_bps")
    metrics["rx_rate_bps"] = summary.get("rx_rate_bps")

    # 4) 2차 Judge
    status_judge = judge_all(metrics, cfg)

    # 5) Detect
    detect = run_detect(
        metrics=metrics,
        cfg=cfg,
        judge_status=status_judge,
        prev_metrics=prev_metrics,
        include_debug=include_debug,
    )

    status = {
        "judge": status_judge,
        "detect": detect,
    }

    return {
        "bundle": bundle,
        "metrics": metrics,
        "logs": logs,
        "judge": status_judge,
        "detect": detect,
        "status": status,
    }
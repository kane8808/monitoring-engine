# post_analyze/analyzer.py
from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Tuple


def _load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _judge_not_ok_items(status: Dict[str, Any]) -> List[Tuple[str, Any]]:
    judge = status.get("judge") if isinstance(status, dict) else {}
    if not isinstance(judge, dict):
        return []
    return [(k, v) for k, v in judge.items() if v != "OK"]


def _detect_not_ok_items(detect: Dict[str, Any]) -> List[Tuple[str, Any]]:
    if not isinstance(detect, dict):
        return []
    return [(k, v) for k, v in detect.items() if v != "OK"]


def _guess_root_cause(metrics: Dict[str, Any], status: Dict[str, Any], detect: Dict[str, Any]) -> str:
    """
    아주 단순한 휴리스틱(운영형으로 고도화 가능)
    """
    judge_bad = dict(_judge_not_ok_items(status))
    if "cpu" in judge_bad:
        return "CPU 과부하 가능성"
    if "memory" in judge_bad:
        return "메모리 부족/누수 가능성"
    if "disk" in judge_bad:
        return "디스크 사용량/IO 문제 가능성"
    if "network" in judge_bad:
        return "네트워크 상태/트래픽 이상 가능성"
    if "log" in judge_bad:
        return "로그 에러/예외 발생 가능성"

    detect_bad = dict(_detect_not_ok_items(detect))
    if detect_bad:
        return f"탐지기(detector) 이상 감지: {', '.join(sorted(detect_bad.keys()))}"

    return "원인 추정 불가(추가 데이터 필요)"


def analyze_evidence(evidence_path: str) -> Dict[str, Any]:
    """
    evidence.json 1건 → 분석 리포트(dict) 생성
    """
    e = _load_json(evidence_path)

    # evidence가 단일 스냅샷인지, 누적(events) 구조인지 둘 다 지원
    events = e.get("events")
    if isinstance(events, list) and events:
        latest = events[-1]  # 최신 스냅샷
    else:
        latest = e  # 구버전(단일) 호환

    metrics = latest.get("metrics") or {}
    status = latest.get("status") or {}
    detect = latest.get("detect") or {}
    extra = latest.get("extra") or {}

    judge_bad = _judge_not_ok_items(status)
    detect_bad = _detect_not_ok_items(detect)

    # 상위 프로세스 3개만 요약
    top_procs = []
    if isinstance(extra, dict):
        tp = extra.get("top_processes") or []
        if isinstance(tp, list):
            for p in tp[:3]:
                if isinstance(p, dict):
                    top_procs.append(
                        {
                            "pid": p.get("pid"),
                            "name": p.get("name"),
                            "cpu_percent": p.get("cpu_percent"),
                            "rss_bytes": p.get("rss_bytes"),
                        }
                    )

    # 로그 발췌 5줄만 요약
    log_excerpt = []
    if isinstance(extra, dict):
        le = extra.get("log_excerpt") or []
        if isinstance(le, list):
            log_excerpt = [str(x) for x in le[:5]]

    root_cause = _guess_root_cause(metrics, status, detect)

    report: Dict[str, Any] = {
        "incident_id": e.get("incident_id"),
        "timestamp": latest.get("timestamp") or e.get("updated_at") or e.get("created_at"),
        "level": latest.get("level") or e.get("level"),
        "host": latest.get("host") or e.get("host"),
        "summary": latest.get("summary") or e.get("summary"),

        "root_cause_guess": root_cause,
        "judge_not_ok": [{"item": k, "value": v} for k, v in judge_bad],
        "detect_not_ok": [{"item": k, "value": v} for k, v in detect_bad],
        "metric_brief": {
            "cpu_percent": metrics.get("cpu_percent"),
            "ram_percent": metrics.get("ram_percent"),
            "disk_max_percent": metrics.get("disk_max_percent"),
            "primary_iface": (metrics.get("primary_iface") or {}).get("name"),
            "ipv4": (metrics.get("primary_iface") or {}).get("ipv4"),
            "tx_rate_bps": (metrics.get("primary_iface") or {}).get("tx_rate_bps"),
            "rx_rate_bps": (metrics.get("primary_iface") or {}).get("rx_rate_bps"),
        },
        "top_processes": top_procs,
        "log_excerpt": log_excerpt,
        "source_evidence_path": evidence_path,
    }

    return report
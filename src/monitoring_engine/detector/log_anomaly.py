"""
log_anomaly.py

역할:
- 로그(최근 N줄)에서 특정 패턴(정규식/키워드) 매칭 빈도를 집계하고
  기준을 넘으면 WARN/CRITICAL로 판정합니다.
- collector는 "수집"만, anomaly는 "이상탐지"만 담당합니다.

입력 형태(권장):
- log_collector.collect_log(...)가 반환한 Metric(dict)
  metric["data"]["lines"] 에 tail lines가 들어있다는 가정
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Pattern

Metric = Dict[str, Any]
AnomalyResult = Dict[str, Any]


@dataclass(frozen=True)
class LogRule:
    """
    로그 이상탐지 룰(규칙)

    pattern: 정규식
    warn: WARN 기준 매칭 횟수
    critical: CRITICAL 기준 매칭 횟수
    name: 룰 이름(리포트 표시용)
    """
    name: str
    pattern: Pattern[str]
    warn: int
    critical: int


DEFAULT_RULES: List[LogRule] = [
    LogRule("exception", re.compile(r"\b(exception|traceback)\b", re.IGNORECASE), warn=1, critical=1),
    LogRule("error", re.compile(r"\berror\b", re.IGNORECASE), warn=5, critical=20),
    LogRule("fail", re.compile(r"\bfail(ed|ure)?\b", re.IGNORECASE), warn=5, critical=20),
    LogRule("auth_fail", re.compile(r"(invalid password|authentication failed|failed login)", re.IGNORECASE), warn=3, critical=10),
]


def _safe_lines_from_metric(metric: Metric) -> List[str]:
    """
    metric에서 로그 라인을 안전하게 추출합니다.
    """
    try:
        lines = metric.get("data", {}).get("lines", None)
        if not lines:
            return []
        if isinstance(lines, list):
            return [str(x) for x in lines]
        return []
    except Exception:
        return []


def detect_log_anomaly(
    metric: Metric,
    rules: Optional[List[LogRule]] = None,
    sample_limit: int = 5,
) -> AnomalyResult:
    """
    로그 이상탐지 실행 함수

    Args:
        metric: log collector metric
        rules: 적용할 룰 목록(없으면 DEFAULT_RULES)
        sample_limit: evidence에 포함할 샘플 라인 최대 개수

    Returns:
        표준 AnomalyResult(dict)
    """
    rules = rules or DEFAULT_RULES
    lines = _safe_lines_from_metric(metric)

    # 룰별 매칭 카운트
    counts: Dict[str, int] = {r.name: 0 for r in rules}
    samples: Dict[str, List[str]] = {r.name: [] for r in rules}

    for line in lines:
        for rule in rules:
            if rule.pattern.search(line):
                counts[rule.name] += 1
                # 증거(sampling): 너무 많이 넣지 않도록 제한
                if len(samples[rule.name]) < sample_limit:
                    samples[rule.name].append(line)

    # 가장 심각한 룰 기준으로 상태 결정
    status = "OK"
    reasons: List[str] = []

    for rule in rules:
        c = counts[rule.name]
        if c >= rule.critical:
            status = "CRITICAL"
            reasons.append(f"{rule.name} 매칭 {c}회 ≥ CRITICAL({rule.critical})")
        elif c >= rule.warn and status != "CRITICAL":
            status = "WARN"
            reasons.append(f"{rule.name} 매칭 {c}회 ≥ WARN({rule.warn})")

    if not reasons:
        reasons = ["로그 패턴 이상 없음"]

    return {
        "type": "log_anomaly",
        "status": status,
        "reason": " / ".join(reasons),
        "evidence": {
            "rule_counts": counts,
            "samples": samples,
            "lines_observed": len(lines),
            "source": {
                "path": metric.get("data", {}).get("meta", {}).get("path"),
                "tail_n": metric.get("data", {}).get("stats", {}).get("tail_n"),
            },
        },
    }
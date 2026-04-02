"""
metric_anomaly.py

역할:
- CPU/Memory/Disk/Network 등 "수치 메트릭"에서 급격한 변화(Spike)나
  통계적 이탈(평균 대비 과도한 편차)을 탐지합니다.

핵심 아이디어:
- 최근 히스토리(history)를 받아서 기준을 계산합니다.
- z-score 방식(평균/표준편차) + 간단한 변화율(delta) 체크를 제공합니다.

주의:
- 여기서는 "탐지 로직"만 구현합니다.
- 히스토리 저장은 storage(예: metrics.csv)에서 하고,
  엔진에서 최근 N개를 읽어 history로 넘기는 구조가 가장 깔끔합니다.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

Metric = Dict[str, Any]
AnomalyResult = Dict[str, Any]


@dataclass(frozen=True)
class MetricSpec:
    """
    어떤 metric에서 어떤 값을 꺼내서 이상탐지할지 정의하는 스펙

    key: 스펙 이름 (예: cpu_total, mem_ram_percent)
    path: metric dict에서 값을 꺼내는 경로
    warn_z: z-score WARN 기준
    critical_z: z-score CRITICAL 기준
    warn_delta: 직전 대비 변화량 WARN 기준(절대값)
    critical_delta: 직전 대비 변화량 CRITICAL 기준(절대값)
    """
    key: str
    path: Tuple[str, ...]
    warn_z: float = 2.5
    critical_z: float = 4.0
    warn_delta: Optional[float] = None
    critical_delta: Optional[float] = None


DEFAULT_SPECS: List[MetricSpec] = [
    # CPU: total_percent
    MetricSpec(
        key="cpu_total_percent",
        path=("data", "total_percent"),
        warn_z=2.5,
        critical_z=4.0,
        warn_delta=20.0,        # 직전 대비 +20%p 급등
        critical_delta=35.0,    # 직전 대비 +35%p 급등
    ),
    # Memory: ram percent
    MetricSpec(
        key="mem_ram_percent",
        path=("data", "ram", "percent"),
        warn_z=2.5,
        critical_z=4.0,
        warn_delta=15.0,
        critical_delta=25.0,
    ),
    # Disk: max partition percent (judge가 아닌 anomaly에서 "급등" 감지용)
    MetricSpec(
        key="disk_max_partition_percent",
        path=("data", "max_partition_percent"),  # 엔진에서 미리 만들어 넣는 것을 권장
        warn_z=2.0,
        critical_z=3.5,
        warn_delta=8.0,
        critical_delta=15.0,
    ),
]


def _get_by_path(d: Dict[str, Any], path: Tuple[str, ...]) -> Optional[float]:
    """
    dict에서 path를 따라 값을 꺼내옵니다.
    값이 숫자면 float로 반환, 아니면 None.
    """
    cur: Any = d
    for p in path:
        if not isinstance(cur, dict) or p not in cur:
            return None
        cur = cur[p]
    try:
        if cur is None:
            return None
        return float(cur)
    except Exception:
        return None


def _mean_std(values: List[float]) -> Tuple[float, float]:
    """
    평균/표준편차 계산 (표본 수가 적을 때도 안전하게)
    """
    if not values:
        return 0.0, 0.0
    m = sum(values) / len(values)
    if len(values) < 2:
        return m, 0.0
    var = sum((x - m) ** 2 for x in values) / (len(values) - 1)
    return m, math.sqrt(var)


def detect_metric_anomaly(
    current: Metric,
    history: List[Metric],
    specs: Optional[List[MetricSpec]] = None,
    min_history: int = 8,
) -> AnomalyResult:
    """
    수치 메트릭 이상탐지 (z-score + delta)

    Args:
        current: 현재 metric (cpu/memory/disk/network 등)
        history: 과거 metric 리스트(같은 타입 기준으로 최근 N개)
        specs: 탐지할 스펙 목록(없으면 DEFAULT_SPECS)
        min_history: z-score 계산에 필요한 최소 히스토리 수

    Returns:
        표준 AnomalyResult(dict)
    """
    specs = specs or DEFAULT_SPECS

    # 가장 심각한 상태를 누적
    overall_status = "OK"
    reasons: List[str] = []
    evidence: Dict[str, Any] = {"signals": {}}

    for spec in specs:
        cur_val = _get_by_path(current, spec.path)
        if cur_val is None:
            continue

        hist_vals: List[float] = []
        for h in history:
            v = _get_by_path(h, spec.path)
            if v is not None:
                hist_vals.append(v)

        signal_status = "OK"
        signal_reason_parts: List[str] = []

        # 1) delta(직전 대비 변화량) 체크
        prev_val = hist_vals[-1] if hist_vals else None
        delta = None
        if prev_val is not None:
            delta = cur_val - prev_val
            if spec.critical_delta is not None and abs(delta) >= spec.critical_delta:
                signal_status = "CRITICAL"
                signal_reason_parts.append(f"Δ={delta:+.1f} ≥ {spec.critical_delta}")
            elif spec.warn_delta is not None and abs(delta) >= spec.warn_delta and signal_status != "CRITICAL":
                signal_status = "WARN"
                signal_reason_parts.append(f"Δ={delta:+.1f} ≥ {spec.warn_delta}")

        # 2) z-score 체크 (히스토리 충분할 때)
        z = None
        if len(hist_vals) >= min_history:
            m, s = _mean_std(hist_vals)
            if s > 0:
                z = (cur_val - m) / s
                if abs(z) >= spec.critical_z:
                    signal_status = "CRITICAL"
                    signal_reason_parts.append(f"|z|={abs(z):.2f} ≥ {spec.critical_z}")
                elif abs(z) >= spec.warn_z and signal_status != "CRITICAL":
                    signal_status = "WARN"
                    signal_reason_parts.append(f"|z|={abs(z):.2f} ≥ {spec.warn_z}")

        if signal_status != "OK":
            reasons.append(f"{spec.key}: " + ", ".join(signal_reason_parts))

        # overall 상태 갱신
        if signal_status == "CRITICAL":
            overall_status = "CRITICAL"
        elif signal_status == "WARN" and overall_status != "CRITICAL":
            overall_status = "WARN"

        evidence["signals"][spec.key] = {
            "current": cur_val,
            "prev": prev_val,
            "delta": delta,
            "z": z,
            "history_n": len(hist_vals),
            "status": signal_status,
            "thresholds": {
                "warn_z": spec.warn_z,
                "critical_z": spec.critical_z,
                "warn_delta": spec.warn_delta,
                "critical_delta": spec.critical_delta,
                "min_history": min_history,
            },
        }

    if not reasons:
        reasons = ["메트릭 이상 징후 없음"]

    return {
        "type": "metric_anomaly",
        "status": overall_status,
        "reason": " / ".join(reasons),
        "evidence": evidence,
    }
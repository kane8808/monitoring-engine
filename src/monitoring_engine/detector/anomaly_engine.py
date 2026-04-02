"""
anomaly_engine.py

역할:
- log_anomaly + metric_anomaly를 통합 실행하는 엔진
- 입력: collector 결과(metric) + (필요시) history
- 출력: anomalies 리스트 + overall 상태

권장 사용 흐름:
collector -> judge(임계치) -> anomaly(추세/스파이크) -> alert/responder

주의:
- 엔진은 "정책(무엇을 어떻게 돌릴지)"을 관리하고,
  실제 탐지는 log_anomaly / metric_anomaly에서 합니다.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .log_anomaly import detect_log_anomaly, LogRule
from .metric_anomaly import detect_metric_anomaly, MetricSpec

Metric = Dict[str, Any]
EngineResult = Dict[str, Any]


def _overall_status(results: List[Dict[str, Any]]) -> str:
    """
    여러 결과를 합쳐 가장 심각한 상태를 계산합니다.
    """
    status = "OK"
    for r in results:
        s = r.get("status")
        if s == "CRITICAL":
            return "CRITICAL"
        if s == "WARN":
            status = "WARN"
    return status


def _enrich_disk_metric(metric: Metric) -> Metric:
    """
    disk metric에 anomaly용 파생값을 추가합니다.
    - data.max_partition_percent : 파티션 중 최대 사용률
    """
    if metric.get("type") != "disk":
        return metric

    data = metric.get("data", {})
    parts = data.get("partitions", []) or []

    max_percent = None
    for p in parts:
        if isinstance(p, dict) and "percent" in p:
            try:
                v = float(p["percent"])
                if max_percent is None or v > max_percent:
                    max_percent = v
            except Exception:
                continue

    # 원본 dict을 직접 수정해도 되지만,
    # 여기서는 "얕은 복사"로 안전하게 처리합니다.
    new_metric = dict(metric)
    new_data = dict(data)
    new_data["max_partition_percent"] = max_percent
    new_metric["data"] = new_data
    return new_metric


class AnomalyEngine:
    """
    이상탐지 엔진 클래스

    - run_metric_anomaly: 수치 메트릭 기반 이상탐지
    - run_log_anomaly: 로그 기반 이상탐지
    - run_all: 둘 다 수행 후 통합 결과 반환
    """

    def __init__(
        self,
        metric_specs: Optional[List[MetricSpec]] = None,
        log_rules: Optional[List[LogRule]] = None,
        min_history: int = 8,
    ):
        self.metric_specs = metric_specs
        self.log_rules = log_rules
        self.min_history = min_history

    def run_metric_anomaly(self, current: Metric, history: Optional[List[Metric]] = None) -> Dict[str, Any]:
        """
        수치 메트릭 이상탐지 실행

        Args:
            current: 현재 metric
            history: 같은 타입의 과거 metric 리스트(없으면 빈 리스트로 처리)

        Returns:
            metric_anomaly 결과(dict)
        """
        history = history or []
        current = _enrich_disk_metric(current)  # disk 파생값 보강

        return detect_metric_anomaly(
            current=current,
            history=history,
            specs=self.metric_specs,
            min_history=self.min_history,
        )

    def run_log_anomaly(self, log_metric: Metric) -> Dict[str, Any]:
        """
        로그 이상탐지 실행

        Args:
            log_metric: log collector metric

        Returns:
            log_anomaly 결과(dict)
        """
        return detect_log_anomaly(metric=log_metric, rules=self.log_rules)

    def run_all(
        self,
        current_metric: Optional[Metric] = None,
        metric_history: Optional[List[Metric]] = None,
        log_metric: Optional[Metric] = None,
        enable_metric: bool = True,
        enable_log: bool = True,
    ) -> EngineResult:
        """
        통합 실행

        Args:
            current_metric: 현재 수치 metric (cpu/memory/disk/network 중 하나)
            metric_history: current_metric과 같은 타입의 과거 metric들
            log_metric: 로그 metric
            enable_metric: 수치 이상탐지 on/off
            enable_log: 로그 이상탐지 on/off

        Returns:
            EngineResult:
            {
              "status": "OK|WARN|CRITICAL",
              "anomalies": [ ... ],
            }
        """
        anomalies: List[Dict[str, Any]] = []

        if enable_metric and current_metric is not None:
            anomalies.append(self.run_metric_anomaly(current_metric, metric_history))

        if enable_log and log_metric is not None:
            anomalies.append(self.run_log_anomaly(log_metric))

        return {
            "status": _overall_status(anomalies),
            "anomalies": anomalies,
        }
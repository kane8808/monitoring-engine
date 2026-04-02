"""
CPU 수집기(Collector)

역할:
- CPU 사용률/로드/코어 수 등 "원시 지표(raw metric)"를 수집합니다.
- 이상 판단은 detector가 수행합니다. (collector는 판단하지 않습니다)

반환 형식(표준 Metric dict):
{
  "type": "cpu",
  "timestamp": "...",
  "host": "...",
  "data": {...},
  "meta": {...}
}
"""

from __future__ import annotations

import socket
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import psutil

Metric = Dict[str, Any]


def _now_iso() -> str:
    """UTC ISO8601 타임스탬프를 생성합니다."""
    return datetime.now(timezone.utc).isoformat()


def _host() -> str:
    """호스트 식별자(Hostname)를 가져옵니다."""
    return socket.gethostname()


def collect_cpu(sample_interval_sec: float = 0.5) -> Metric:
    """
    CPU 지표를 수집합니다.

    Args:
        sample_interval_sec: psutil.cpu_percent 측정용 샘플링 간격(초)
            - 0이면 순간값(직전 측정 기반)이 될 수 있어 기본 0.5 권장

    Returns:
        표준 Metric(dict)
    """
    # CPU 사용률(전체/코어별)
    total_percent = psutil.cpu_percent(interval=sample_interval_sec)
    per_cpu_percent = psutil.cpu_percent(interval=None, percpu=True)

    # CPU 코어 수(논리/물리)
    logical = psutil.cpu_count(logical=True)
    physical = psutil.cpu_count(logical=False)

    # 로드 평균(리눅스/유닉스 계열만 제공, 윈도우에서는 예외 가능)
    load1 = load5 = load15 = None
    try:
        load1, load5, load15 = psutil.getloadavg()
    except (AttributeError, OSError):
        # Windows 등에서는 getloadavg가 없거나 지원되지 않을 수 있습니다.
        pass

    # CPU 주파수(지원 환경에서만)
    freq_current_mhz: Optional[float] = None
    freq_min_mhz: Optional[float] = None
    freq_max_mhz: Optional[float] = None
    try:
        f = psutil.cpu_freq()
        if f:
            freq_current_mhz = f.current
            freq_min_mhz = f.min
            freq_max_mhz = f.max
    except Exception:
        pass

    return {
        "type": "cpu",
        "timestamp": _now_iso(),
        "host": _host(),
        "data": {
            "total_percent": float(total_percent),
            "per_cpu_percent": [float(x) for x in per_cpu_percent],
            "cores": {
                "logical": int(logical) if logical is not None else None,
                "physical": int(physical) if physical is not None else None,
            },
            "load_avg": {
                "1m": float(load1) if load1 is not None else None,
                "5m": float(load5) if load5 is not None else None,
                "15m": float(load15) if load15 is not None else None,
            },
            "freq_mhz": {
                "current": float(freq_current_mhz) if freq_current_mhz is not None else None,
                "min": float(freq_min_mhz) if freq_min_mhz is not None else None,
                "max": float(freq_max_mhz) if freq_max_mhz is not None else None,
            },
        },
        "meta": {
            "collector": "psutil",
            "sample_interval_sec": sample_interval_sec,
        },
    }

if __name__ == "__main__":
    import json
    print(json.dumps(collect_cpu(), indent=2, ensure_ascii=False))
# detector/network_rate_detector.py
from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, Optional

@dataclass
class NetPrev:
    ts: float
    bytes_sent: int
    bytes_recv: int

def compute_rate(now_ts: float, bytes_sent: int, bytes_recv: int, prev: Optional[NetPrev]) -> Dict[str, Optional[float]]:
    if prev is None:
        return {"tx_rate_bps": None, "rx_rate_bps": None}

    dt = now_ts - prev.ts
    if dt <= 0:
        return {"tx_rate_bps": None, "rx_rate_bps": None}

    tx = (bytes_sent - prev.bytes_sent) * 8 / dt
    rx = (bytes_recv - prev.bytes_recv) * 8 / dt
    if tx < 0 or rx < 0:  # 재부팅/카운터 리셋 대응
        return {"tx_rate_bps": None, "rx_rate_bps": None}

    return {"tx_rate_bps": tx, "rx_rate_bps": rx}

def detect_spike_drop(rate_bps: Optional[float], high: float, low: float) -> str:
    if rate_bps is None:
        return "UNKNOWN"
    if rate_bps >= high:
        return "SPIKE"
    if rate_bps <= low:
        return "DROP"
    return "OK"

def _to_number_or_none(v: Any) -> Optional[float]:
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        try:
            return float(v.strip())
        except ValueError:
            return None
    return None


def calc_network_rate(
    metrics: Dict[str, Any],
    prev_metrics: Optional[Dict[str, Any]] = None,  # 현재는 미사용(확장용)
) -> Dict[str, Any]:
    """
    rate 계산/추출 전용.
    - 우선 metrics["primary_iface_summary"]를 사용
    - 없으면 metrics["primary_iface"]로 meta만 보완
    """
    summary = metrics.get("primary_iface_summary") or {}
    fallback = metrics.get("primary_iface") or {}

    tx = _to_number_or_none(summary.get("tx_rate_bps"))
    rx = _to_number_or_none(summary.get("rx_rate_bps"))

    return {
        "iface": summary.get("name") or fallback.get("name"),
        "ipv4": summary.get("ipv4") or fallback.get("ipv4"),
        "speed_mbps": summary.get("speed_mbps") or fallback.get("speed_mbps"),
        "tx_rate_bps": tx,
        "rx_rate_bps": rx,
        "delta_sec": _to_number_or_none(summary.get("delta_sec")),  # 있으면
    }
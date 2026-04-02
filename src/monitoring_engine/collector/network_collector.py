"""
Network 수집기(Collector)

역할:
- 네트워크 I/O(바이트/패킷), 인터페이스 상태, 연결 수(옵션) 등을 수집합니다.
- 이상 판단은 detector가 수행합니다.
"""

from __future__ import annotations

import socket
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import psutil

Metric = Dict[str, Any]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _host() -> str:
    return socket.gethostname()


def collect_network(include_connections: bool = False, connection_kind: str = "inet") -> Metric:
    """
    네트워크 지표를 수집합니다.

    Args:
        include_connections: True면 현재 연결(소켓) 목록을 수집(환경에 따라 비용↑)
        connection_kind:
            - psutil.net_connections(kind=...) 파라미터
            - "inet" (TCP/UDP IPv4/IPv6) 정도가 무난합니다.

    Returns:
        표준 Metric(dict)
    """
    # 전체/인터페이스별 I/O
    io_total = psutil.net_io_counters(pernic=False)
    io_pernic = psutil.net_io_counters(pernic=True)

    # 인터페이스 상태(up/down), 속도 등
    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()

    pernic: Dict[str, Any] = {}
    for nic, counters in (io_pernic or {}).items():
        pernic[nic] = {
            "io": {
                "bytes_sent": int(getattr(counters, "bytes_sent", 0)),
                "bytes_recv": int(getattr(counters, "bytes_recv", 0)),
                "packets_sent": int(getattr(counters, "packets_sent", 0)),
                "packets_recv": int(getattr(counters, "packets_recv", 0)),
                "errin": int(getattr(counters, "errin", 0)),
                "errout": int(getattr(counters, "errout", 0)),
                "dropin": int(getattr(counters, "dropin", 0)),
                "dropout": int(getattr(counters, "dropout", 0)),
            },
            "stat": {
                "isup": bool(getattr(stats.get(nic), "isup", False)) if stats else None,
                "duplex": int(getattr(stats.get(nic), "duplex", 0)) if stats and stats.get(nic) else None,
                "speed_mbps": int(getattr(stats.get(nic), "speed", 0)) if stats and stats.get(nic) else None,
                "mtu": int(getattr(stats.get(nic), "mtu", 0)) if stats and stats.get(nic) else None,
            },
            "addrs": [
                {
                    "family": str(a.family),
                    "address": a.address,
                    "netmask": getattr(a, "netmask", None),
                    "broadcast": getattr(a, "broadcast", None),
                }
                for a in (addrs.get(nic) or [])
            ],
        }

    connections_summary: Optional[Dict[str, Any]] = None
    if include_connections:
        try:
            conns = psutil.net_connections(kind=connection_kind)
            # 개인정보/민감정보를 줄이기 위해 “요약” 위주로 제공합니다.
            state_count: Dict[str, int] = {}
            for c in conns:
                st = getattr(c, "status", "UNKNOWN")
                state_count[st] = state_count.get(st, 0) + 1
            connections_summary = {
                "kind": connection_kind,
                "total": len(conns),
                "by_status": state_count,
            }
        except Exception:
            connections_summary = {"error": "net_connections_failed"}

    return {
        "type": "network",
        "timestamp": _now_iso(),
        "host": _host(),
        "data": {
            "total": {
                "bytes_sent": int(getattr(io_total, "bytes_sent", 0)),
                "bytes_recv": int(getattr(io_total, "bytes_recv", 0)),
                "packets_sent": int(getattr(io_total, "packets_sent", 0)),
                "packets_recv": int(getattr(io_total, "packets_recv", 0)),
                "errin": int(getattr(io_total, "errin", 0)),
                "errout": int(getattr(io_total, "errout", 0)),
                "dropin": int(getattr(io_total, "dropin", 0)),
                "dropout": int(getattr(io_total, "dropout", 0)),
            },
            "per_nic": pernic,
            "connections": connections_summary,
        },
        "meta": {
            "collector": "psutil",
            "include_connections": include_connections,
        },
    }
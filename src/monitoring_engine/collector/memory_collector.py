"""
Memory 수집기(Collector)

역할:
- RAM/Swap 사용량 등 원시 지표를 수집합니다.
- 이상 판단은 detector가 수행합니다.
"""

from __future__ import annotations

import socket
from datetime import datetime, timezone
from typing import Any, Dict

import psutil

Metric = Dict[str, Any]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _host() -> str:
    return socket.gethostname()


def collect_memory() -> Metric:
    """
    메모리(RAM/Swap) 지표를 수집합니다.

    Returns:
        표준 Metric(dict)
    """
    vm = psutil.virtual_memory()
    sm = psutil.swap_memory()

    return {
        "type": "memory",
        "timestamp": _now_iso(),
        "host": _host(),
        "data": {
            "ram": {
                "total": int(vm.total),
                "available": int(vm.available),
                "used": int(vm.used),
                "free": int(getattr(vm, "free", 0)),
                "percent": float(vm.percent),
                "active": int(getattr(vm, "active", 0)),
                "inactive": int(getattr(vm, "inactive", 0)),
                "buffers": int(getattr(vm, "buffers", 0)),
                "cached": int(getattr(vm, "cached", 0)),
            },
            "swap": {
                "total": int(sm.total),
                "used": int(sm.used),
                "free": int(sm.free),
                "percent": float(sm.percent),
                "sin": int(getattr(sm, "sin", 0)),
                "sout": int(getattr(sm, "sout", 0)),
            },
        },
        "meta": {
            "collector": "psutil",
        },
    }
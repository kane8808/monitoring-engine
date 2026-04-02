"""
Disk 수집기(Collector)

역할:
- 디스크 파티션별 사용량, 디스크 I/O 카운터 등 원시 지표를 수집합니다.
- 이상 판단은 detector가 수행합니다.
"""

from __future__ import annotations

import socket
from datetime import datetime, timezone
from typing import Any, Dict, List

import psutil

Metric = Dict[str, Any]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _host() -> str:
    return socket.gethostname()


def collect_disk(include_all_partitions: bool = False) -> Metric:
    """
    디스크 지표를 수집합니다.

    Args:
        include_all_partitions:
            - False: 실제 물리/주요 파티션 중심(권장)
            - True : 시스템/가상 파티션까지 포함 (환경에 따라 너무 많이 잡힐 수 있습니다)

    Returns:
        표준 Metric(dict)
    """
    partitions = psutil.disk_partitions(all=include_all_partitions)

    usage_list: List[Dict[str, Any]] = []
    for p in partitions:
        # 일부 마운트는 권한/특성상 usage 호출이 실패할 수 있습니다.
        try:
            u = psutil.disk_usage(p.mountpoint)
            usage_list.append(
                {
                    "device": p.device,
                    "mountpoint": p.mountpoint,
                    "fstype": p.fstype,
                    "opts": p.opts,
                    "total": int(u.total),
                    "used": int(u.used),
                    "free": int(u.free),
                    "percent": float(u.percent),
                }
            )
        except Exception:
            usage_list.append(
                {
                    "device": p.device,
                    "mountpoint": p.mountpoint,
                    "fstype": p.fstype,
                    "opts": p.opts,
                    "error": "disk_usage_failed",
                }
            )

    io = psutil.disk_io_counters(perdisk=True)
    io_by_disk: Dict[str, Any] = {}
    for disk_name, c in (io or {}).items():
        io_by_disk[disk_name] = {
            "read_count": int(getattr(c, "read_count", 0)),
            "write_count": int(getattr(c, "write_count", 0)),
            "read_bytes": int(getattr(c, "read_bytes", 0)),
            "write_bytes": int(getattr(c, "write_bytes", 0)),
            "read_time_ms": int(getattr(c, "read_time", 0)),
            "write_time_ms": int(getattr(c, "write_time", 0)),
            "busy_time_ms": int(getattr(c, "busy_time", 0)),
        }

    return {
        "type": "disk",
        "timestamp": _now_iso(),
        "host": _host(),
        "data": {
            "partitions": usage_list,
            "io_by_disk": io_by_disk,
        },
        "meta": {
            "collector": "psutil",
            "include_all_partitions": include_all_partitions,
        },
    }
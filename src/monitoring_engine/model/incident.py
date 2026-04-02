from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional


def build_incident(
    *,
    severity: str,
    category: str,
    rule_name: str,
    message: str,
    src_ip: Optional[str] = None,
    host_name: Optional[str] = None,
    raw_data: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    return {
        "detected_at": datetime.now(timezone.utc).isoformat(),
        "severity": severity,
        "category": category,
        "rule_name": rule_name,
        "src_ip": src_ip,
        "host_name": host_name,
        "message": message,
        "raw_data": raw_data or {},
    }

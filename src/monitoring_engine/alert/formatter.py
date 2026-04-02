from __future__ import annotations

from typing import Any, Dict, Optional


def _fmt_bps(v: Any) -> str:
    if v is None:
        return "-"
    try:
        bps = float(v)
    except Exception:
        return str(v)

    units = ["B/s", "KB/s", "MB/s", "GB/s"]
    i = 0
    while bps >= 1024 and i < len(units) - 1:
        bps /= 1024
        i += 1
    return f"{bps:.2f} {units[i]}"


def build_alert_text(
    *,
    level: str,
    title: str,
    metrics: Dict[str, Any],
    status: Dict[str, Any],
    detections: Dict[str, Any],
    incident_id: Optional[str] = None,
    evidence_path: Optional[str] = None,
) -> str:
    net = metrics.get("primary_iface") if isinstance(metrics, dict) else None
    net_lines = ""
    if isinstance(net, dict):
        name = net.get("name", "-")
        ipv4 = net.get("ipv4", "-")
        rx = _fmt_bps(net.get("rx_rate_bps"))
        tx = _fmt_bps(net.get("tx_rate_bps"))
        dt = net.get("delta_sec")
        dt_s = f"{float(dt):.2f}s" if isinstance(dt, (int, float)) else "-"

        net_lines = (
            f"\n• IFACE : {name} ({ipv4})"
            f"\n• RX    : {rx}"
            f"\n• TX    : {tx}"
            f"\n• Δt    : {dt_s}"
        )

    ev_lines = ""
    if incident_id or evidence_path:
        ev_lines = "\n\n📁 Evidence"
        if incident_id:
            ev_lines += f"\n- incident_id : {incident_id}"
        if evidence_path:
            ev_lines += f"\n- path        : {evidence_path}"

    emoji = "🚨" if level == "CRITICAL" else "⚠️" if level == "WARN" else "ℹ️"
    return f"{emoji} [{level}] {title}{net_lines}{ev_lines}"
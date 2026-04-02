from __future__ import annotations

from typing import Any, Dict
import os


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


def build_report_markdown(report: Dict[str, Any]) -> str:
    """report(dict) -> markdown(str)"""
    incident_id = report.get("incident_id") or "unknown-incident"
    level = report.get("level") or report.get("severity") or "UNKNOWN"
    ts = report.get("timestamp") or "-"
    summary = report.get("summary") or "Incident Report"

    metrics = report.get("metrics") or {}
    status = report.get("status") or {}
    detect = report.get("detect") or report.get("detections") or {}

    primary = metrics.get("primary_iface") if isinstance(metrics, dict) else {}
    if isinstance(primary, dict):
        iface = primary.get("name", "-")
        ipv4 = primary.get("ipv4", "-")
        tx = _fmt_bps(primary.get("tx_rate_bps"))
        rx = _fmt_bps(primary.get("rx_rate_bps"))
        dt = primary.get("delta_sec")
        dt_s = f"{float(dt):.2f}s" if isinstance(dt, (int, float)) else "-"
    else:
        iface = ipv4 = tx = rx = dt_s = "-"

    lines = []
    lines.append(f"# Incident {incident_id}")
    lines.append("")
    lines.append(f"- **Level**: {level}")
    lines.append(f"- **Time**: {ts}")
    lines.append(f"- **Summary**: {summary}")
    lines.append("")

    lines.append("## Network")
    lines.append(f"- IFACE: {iface} ({ipv4})")
    lines.append(f"- RX: {rx}")
    lines.append(f"- TX: {tx}")
    lines.append(f"- Δt: {dt_s}")
    lines.append("")

    lines.append("## Detect")
    if isinstance(detect, dict) and detect:
        for k, v in detect.items():
            if isinstance(v, dict):
                st = v.get("status", "UNKNOWN")
                reason = v.get("reason", "")
                lines.append(f"- {k}: **{st}** — {reason}".rstrip())
            else:
                lines.append(f"- {k}: **{v}**")
    else:
        lines.append("- (no detect data)")
    lines.append("")

    lines.append("## Judge")
    judge = status.get("judge") if isinstance(status, dict) else {}
    if isinstance(judge, dict) and judge:
        for k, v in judge.items():
            if isinstance(v, dict):
                st = v.get("status", "UNKNOWN")
                reason = v.get("reason", "")
                meta = v.get("meta") or {}
                value = meta.get("value")
                th = meta.get("threshold")
                if value is not None and th is not None:
                    lines.append(f"- {k}: **{st}** ({value} / th={th}) — {reason}")
                else:
                    lines.append(f"- {k}: **{st}** — {reason}")
            else:
                lines.append(f"- {k}: {v}")
    else:
        lines.append("- (no judge data)")
    lines.append("")

    return "\n".join(lines)


def save_report_markdown(md_text: str, md_path: str) -> None:
    os.makedirs(os.path.dirname(md_path), exist_ok=True)
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md_text)

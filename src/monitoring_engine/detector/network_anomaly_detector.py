from __future__ import annotations
from typing import Any, Dict, Optional

from monitoring_engine.judge.thresholds import net_thresholds_from_cfg

def detect_network_anomaly(rate: Dict[str, Any], cfg: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    cfg = cfg or {}

    tx = rate.get("tx_rate_bps")
    rx = rate.get("rx_rate_bps")

    if tx is None or rx is None:
        return {
            "status": "OK",
            "reason": "insufficient_data",
            "tx_rate_bps": tx,
            "rx_rate_bps": rx,
            "meta": {"iface": rate.get("iface"), "ipv4": rate.get("ipv4"), "speed_mbps": rate.get("speed_mbps")},
            "ttl_seconds": 0,
        }

    ttl_cfg = cfg.get("ttl_seconds", {}) if isinstance(cfg, dict) else {}

    th = net_thresholds_from_cfg(cfg)

    tx_warn, tx_crit = th["tx_warn"], th["tx_crit"]
    rx_warn, rx_crit = th["rx_warn"], th["rx_crit"]
    test_mode = th["test_mode"]
    test_multiplier = th["test_multiplier"]


    warn_ttl = int(ttl_cfg.get("warn", 300))
    crit_ttl = int(ttl_cfg.get("critical", 900))

    txf = float(tx)
    rxf = float(rx)

    reasons = []
    if txf >= tx_crit or rxf >= rx_crit:
        level = "CRITICAL"
        if txf >= tx_crit:
            reasons.append(f"tx_rate over CRITICAL ({txf:.0f} >= {tx_crit:.0f})")
        if rxf >= rx_crit:
            reasons.append(f"rx_rate over CRITICAL ({rxf:.0f} >= {rx_crit:.0f})")
        ttl = crit_ttl
    elif txf >= tx_warn or rxf >= rx_warn:
        level = "WARN"
        if txf >= tx_warn:
            reasons.append(f"tx_rate over WARN ({txf:.0f} >= {tx_warn:.0f})")
        if rxf >= rx_warn:
            reasons.append(f"rx_rate over WARN ({rxf:.0f} >= {rx_warn:.0f})")
        ttl = warn_ttl
    else:
        level = "OK"
        reasons.append("normal")
        ttl = 0

    return {
        "status": level,
        "reason": " | ".join(reasons),
        "tx_rate_bps": txf,
        "rx_rate_bps": rxf,
        "meta": {
            "iface": rate.get("iface"),
            "ipv4": rate.get("ipv4"),
            "speed_mbps": rate.get("speed_mbps"),
            "test_mode": test_mode,
            "test_multiplier": test_multiplier,
            "tx_warn": tx_warn,
            "tx_crit": tx_crit,
            "rx_warn": rx_warn,
            "rx_crit": rx_crit,
        },
        "ttl_seconds": ttl,
    }
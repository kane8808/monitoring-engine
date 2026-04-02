# monitoring_tool/common/thresholds.py
from __future__ import annotations
from typing import Any, Dict


def net_thresholds_from_cfg(cfg: Dict[str, Any]) -> Dict[str, Any]:
    cfg = cfg or {}
    net = (cfg.get("network_rate_bps") or {})
    tx = net.get("tx") or {}
    rx = net.get("rx") or {}

    tx_warn = float(tx.get("warn", 1_000_000))
    tx_crit = float(tx.get("critical", 5_000_000))
    rx_warn = float(rx.get("warn", 1_000_000))
    rx_crit = float(rx.get("critical", 500_000_000))

    test_mode = bool(net.get("test_mode", False))
    test_multiplier = net.get("test_multiplier", None)

    if test_mode:
        m = float(test_multiplier or 10)
        tx_warn *= m
        tx_crit *= m
        rx_warn *= m
        rx_crit *= m

    suppress_alert = bool(net.get("suppress_alert", False))
    
    # test_mode multiplier 적용 이후
    assert tx_warn <= tx_crit, "tx_warn > tx_crit"
    assert rx_warn <= rx_crit, "rx_warn > rx_crit"

    return {
        "tx_warn": tx_warn,
        "tx_crit": tx_crit,
        "rx_warn": rx_warn,
        "rx_crit": rx_crit,
        "test_mode": test_mode,
        "test_multiplier": test_multiplier,
        "suppress_alert": suppress_alert,
    }
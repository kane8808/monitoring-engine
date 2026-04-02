# monitoring_tool/judge/judge.py
from __future__ import annotations

import os
from typing import Any, Dict, Optional
from monitoring_engine.judge.thresholds import net_thresholds_from_cfg

def _dig(d: Any, keys: set[str]) -> Optional[Any]:
    """중첩 dict/list에서 keys 중 하나를 찾아 첫 값을 반환"""
    if isinstance(d, dict):
        for k, v in d.items():
            if k in keys and v is not None:
                return v
        for v in d.values():
            found = _dig(v, keys)
            if found is not None:
                return found
    elif isinstance(d, list):
        for item in d:
            found = _dig(item, keys)
            if found is not None:
                return found
    return None

def _ok(type_: str, reason: str, meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return {"type": type_, "status": "OK", "reason": reason, "meta": meta or {}, "raw": None}


def _warn(type_: str, reason: str, meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return {"type": type_, "status": "WARN", "reason": reason, "meta": meta or {}, "raw": None}


def _not_ok(type_: str, reason: str, meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return {"type": type_, "status": "NOT OK", "reason": reason, "meta": meta or {}, "raw": None}


def _is_ipv4(v: Any) -> bool:
    if not isinstance(v, str):
        return False
    parts = v.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _is_link_local_ipv4(ip: str) -> bool:
    return ip.startswith("169.254.") or ip.startswith("127.")


def _extract_best_iface(net_metric: Dict[str, Any]) -> Dict[str, Any]:
    # (사용자님 기존 코드 그대로)
    data = net_metric.get("data") or {}
    per_nic = data.get("per_nic") or {}
    if not isinstance(per_nic, dict) or not per_nic:
        return {}

    def pick_ipv4(addrs: Any) -> Optional[str]:
        if not isinstance(addrs, list):
            return None
        for a in addrs:
            if not isinstance(a, dict):
                continue
            if str(a.get("family")) == "2":
                cand = a.get("address")
                if isinstance(cand, str) and _is_ipv4(cand) and not _is_link_local_ipv4(cand):
                    return cand
        return None

    def score(name: str, nic: Dict[str, Any]) -> float:
        stat = nic.get("stat") or {}
        io = nic.get("io") or {}
        addrs = nic.get("addrs") or []

        isup = bool(stat.get("isup")) is True
        speed = float(stat.get("speed_mbps") or 0)
        bytes_total = float((io.get("bytes_sent") or 0) + (io.get("bytes_recv") or 0))
        ipv4 = pick_ipv4(addrs)

        s = 0.0
        if isup:
            s += 100.0
        if ipv4:
            s += 60.0

        s += min(bytes_total / 1_000_000.0, 50.0)
        s += min(speed / 100.0, 10.0)

        lname = name.lower()
        if "vmware" in lname or "virtual" in lname:
            s -= 80.0
        if "loopback" in lname:
            s -= 200.0
        if lname.startswith("로컬 영역 연결*"):
            s -= 50.0
        if "bluetooth" in lname:
            s -= 40.0

        return s

    best_name: Optional[str] = None
    best_nic: Optional[Dict[str, Any]] = None
    best_score = -1e18

    for name, nic in per_nic.items():
        if not isinstance(nic, dict):
            continue
        sc = score(name, nic)
        if sc > best_score:
            best_score = sc
            best_name = name
            best_nic = nic

    if not best_name or not isinstance(best_nic, dict):
        return {}

    stat = best_nic.get("stat") or {}
    addrs = best_nic.get("addrs") or []
    ipv4 = pick_ipv4(addrs)

    return {
        "name": best_name,
        "ipv4": ipv4,
        "isup": stat.get("isup") if stat.get("isup") is not None else None,
        "speed_mbps": stat.get("speed_mbps"),
    }


def judge_all(metrics: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    CPU_WARN = 90.0
    MEM_WARN = 85.0
    DISK_WARN = 80.0

    # 로컬(Windows)은 down을 WARN 처리
    LOCAL_DEV = (os.name == "nt")
    out: Dict[str, Any] = {}

    # CPU
    cpu = metrics.get("cpu_percent")
    if cpu is None:
        out["cpu"] = _warn("cpu", "cpu percent missing", {"threshold": CPU_WARN})
    elif float(cpu) >= CPU_WARN:
        out["cpu"] = _not_ok("cpu", "cpu high", {"value": float(cpu), "threshold": CPU_WARN})
    else:
        out["cpu"] = _ok("cpu", "cpu normal", {"value": float(cpu), "threshold": CPU_WARN})
    
    # Memory
    mem = metrics.get("ram_percent")
    if mem is None:
        out["memory"] = _warn("memory", "memory percent missing", {"threshold": MEM_WARN})
    elif float(mem) >= MEM_WARN:
        out["memory"] = _not_ok("memory", "memory high", {"value": float(mem), "threshold": MEM_WARN})
    else:
        out["memory"] = _ok("memory", "memory normal", {"value": float(mem), "threshold": MEM_WARN})

    # Disk
    disk = metrics.get("disk_max_percent")
    if disk is None:
        out["disk"] = _warn("disk", "disk percent missing", {"threshold": DISK_WARN})
    elif float(disk) >= DISK_WARN:
        out["disk"] = _not_ok("disk", "disk high", {"value": float(disk), "threshold": DISK_WARN})
    else:
        out["disk"] = _ok("disk", "disk normal", {"value": float(disk), "threshold": DISK_WARN})

    # Network (best iface 선택)
    net_metric = metrics.get("primary_iface") or {}
    best = _extract_best_iface(net_metric)

    name = best.get("name")
    ipv4 = best.get("ipv4")
    isup = best.get("isup")
    speed = best.get("speed_mbps")

    # (A) 링크 up/down 판정
    if isup is None:
        out["network"] = _warn(
            "network",
            "network meta missing",
            {"name": name, "ipv4": ipv4, "speed_mbps": speed, "isup": isup, "local_dev": LOCAL_DEV},
        )
    elif bool(isup) is False:
        meta = {"name": name, "ipv4": ipv4, "speed_mbps": speed, "isup": isup, "local_dev": LOCAL_DEV}
        out["network"] = _warn("network", "interface reported down (local dev -> WARN)", meta) if LOCAL_DEV else _not_ok(
            "network", "interface down", meta
        )
    else:
        # (B) 트래픽 임계치 판정(값이 존재할 때만)
        th = net_thresholds_from_cfg(cfg)
        tx_warn, tx_crit = th["tx_warn"], th["tx_crit"]
        rx_warn, rx_crit = th["rx_warn"], th["rx_crit"]

        tx_rate_bps = metrics.get("tx_rate_bps")
        rx_rate_bps = metrics.get("rx_rate_bps")

        tx_rate = float(tx_rate_bps or 0)
        rx_rate = float(rx_rate_bps or 0)

        meta = {
            "name": name,
            "ipv4": ipv4,
            "speed_mbps": speed,
            "isup": isup,
            "local_dev": LOCAL_DEV,

            "tx_rate_bps": tx_rate_bps,
            "rx_rate_bps": rx_rate_bps,
            "tx_warn": tx_warn,
            "tx_crit": tx_crit,
            "rx_warn": rx_warn,
            "rx_crit": rx_crit,
            "test_mode": th["test_mode"],
            "test_multiplier": th["test_multiplier"],
        }

        # tx/rx rate가 없는 경우: 인터페이스 업만 OK로
        if tx_rate_bps is None and rx_rate_bps is None:
            out["network"] = _ok("network", "interface up (rate missing)", meta)
        else:
            if tx_rate >= tx_crit or rx_rate >= rx_crit:
                out["network"] = _not_ok("network", "network traffic critical", meta)
            elif tx_rate >= tx_warn or rx_rate >= rx_warn:
                out["network"] = _warn("network", "network traffic warn", meta)
            else:
                out["network"] = _ok("network", "network normal", meta)

    # Log (사용자님 기존 코드 그대로)
    exists = metrics.get("log_exists")
    err = metrics.get("log_error")
    path = metrics.get("log_path")

    has_err = False
    if err is None:
        has_err = False
    elif isinstance(err, (int, float)):
        has_err = (err != 0)
    elif isinstance(err, str):
        has_err = (err.strip() != "" and err.strip() != "0")
    else:
        has_err = bool(err)

    if exists is False:
        out["log"] = _warn("log", "log file missing", {"path": path, "exists": exists, "error": err})
    elif has_err:
        out["log"] = _warn("log", "log meta error", {"path": path, "exists": exists, "error": err})
    else:
        out["log"] = _ok("log", "log ok", {"path": path, "exists": exists, "error": err})

    return out


__all__ = ["judge_all"]
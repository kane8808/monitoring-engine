from typing import Dict, Any, Optional


def build_primary_iface_summary(
    network_bundle: Dict[str, Any],
    prefer_name: Optional[str] = "이더넷",
) -> Dict[str, Any]:
    data = (network_bundle or {}).get("data") or {}
    per_nic = data.get("per_nic") or {}

    if not per_nic:
        return {
            "name": None,
            "ipv4": None,
            "isup": None,
            "speed_mbps": None,
            "bytes_sent": None,
            "bytes_recv": None,
        }

    chosen = None
    if prefer_name and prefer_name in per_nic:
        chosen = prefer_name
    else:
        for nic_name, nic in per_nic.items():
            stat = (nic or {}).get("stat") or {}
            if stat.get("isup") is True:
                chosen = nic_name
                break
        if chosen is None:
            chosen = next(iter(per_nic.keys()))

    nic = per_nic.get(chosen) or {}
    io = nic.get("io") or {}
    stat = nic.get("stat") or {}

    ipv4 = None
    for addr in (nic.get("addrs") or []):
        if str(addr.get("family")) == "2":  # AF_INET
            ipv4 = addr.get("address")
            break

    return {
        "name": chosen,
        "ipv4": ipv4,
        "isup": stat.get("isup"),
        "speed_mbps": stat.get("speed_mbps"),
        "bytes_sent": io.get("bytes_sent"),
        "bytes_recv": io.get("bytes_recv"),
    }
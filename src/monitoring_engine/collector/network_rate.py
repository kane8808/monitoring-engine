def add_net_rates(
    summary: dict,
    prev_summary: dict | None = None,
    delta_sec: float | None = None
) -> dict:

    summary.setdefault("tx_rate_bps", None)
    summary.setdefault("rx_rate_bps", None)
    summary["delta_sec"] = None

    if not prev_summary:
        return summary

    try:
        prev_tx = prev_summary.get("bytes_sent")
        prev_rx = prev_summary.get("bytes_recv")
        curr_tx = summary.get("bytes_sent")
        curr_rx = summary.get("bytes_recv")

        if None in (prev_tx, prev_rx, curr_tx, curr_rx):
            return summary

        # delta_sec 활용 (없으면 기본값 5)
        delta = delta_sec or 5

        tx_rate = (curr_tx - prev_tx) * 8 / delta
        rx_rate = (curr_rx - prev_rx) * 8 / delta

        summary["tx_rate_bps"] = max(tx_rate, 0.0)
        summary["rx_rate_bps"] = max(rx_rate, 0.0)
        summary["delta_sec"] = float(delta)

    except Exception:
        pass

    return summary
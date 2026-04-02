from __future__ import annotations

from .cpu_collector import collect_cpu
from .memory_collector import collect_memory
from .disk_collector import collect_disk
from .network_collector import collect_network
from .log_collector import collect_log
from .process_collector import collect_processes


def collect_all(cfg: dict) -> dict:
    log_cfg = cfg.get("log", {}) or {}

    return {
        "cpu": collect_cpu(),
        "memory": collect_memory(),
        "disk": collect_disk(),
        "network": collect_network(),
        "log": collect_log(
            file_path=log_cfg.get("file_path", "logs/app.log"),
            tail_n=int(log_cfg.get("tail_n", 200)),
            encoding=log_cfg.get("encoding", "utf-8"),
            include_lines=True,
        ),
        "process": collect_processes(),
    }
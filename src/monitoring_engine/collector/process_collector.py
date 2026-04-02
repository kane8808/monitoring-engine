from __future__ import annotations

import platform
import subprocess
from datetime import datetime, timezone
from typing import Any


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run_command(cmd: list[str]) -> tuple[bool, str]:
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            check=False,
        )
        if completed.returncode != 0:
            return False, completed.stderr.strip() or completed.stdout.strip()
        return True, completed.stdout
    except Exception as e:
        return False, str(e)


def _collect_windows_processes() -> list[dict[str, Any]]:
    ok, output = _run_command(
        ["powershell", "-NoProfile", "-Command", "Get-CimInstance Win32_Process | Select-Object ProcessId, Name, CommandLine | ConvertTo-Json -Depth 3"]
    )
    if not ok or not output.strip():
        return []

    try:
        import json
        data = json.loads(output)
    except Exception:
        return []

    if isinstance(data, dict):
        data = [data]

    items: list[dict[str, Any]] = []
    if isinstance(data, list):
        for proc in data:
            if not isinstance(proc, dict):
                continue
            items.append(
                {
                    "pid": proc.get("ProcessId"),
                    "name": proc.get("Name"),
                    "cmdline": proc.get("CommandLine") or proc.get("Name") or "",
                }
            )
    return items


def _collect_linux_processes() -> list[dict[str, Any]]:
    ok, output = _run_command(["ps", "-eo", "pid,comm,args"])
    if not ok or not output.strip():
        return []

    lines = output.splitlines()
    items: list[dict[str, Any]] = []

    for line in lines[1:]:
        parts = line.strip().split(maxsplit=2)
        if len(parts) < 2:
            continue

        pid = parts[0]
        name = parts[1]
        cmdline = parts[2] if len(parts) >= 3 else name

        items.append(
            {
                "pid": pid,
                "name": name,
                "cmdline": cmdline,
            }
        )

    return items


def collect_processes() -> dict[str, Any]:
    system_name = platform.system().lower()

    if "windows" in system_name:
        processes = _collect_windows_processes()
    else:
        processes = _collect_linux_processes()

    return {
        "type": "process",
        "timestamp": _now_iso(),
        "host": platform.node(),
        "data": processes,
        "meta": {
            "platform": platform.system(),
            "count": len(processes),
        },
    }
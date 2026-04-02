from __future__ import annotations

import os
import socket
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


Metric = Dict[str, Any]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _host() -> str:
    return socket.gethostname()


def _tail_lines(path: str, n: int = 200, encoding: str = "utf-8") -> List[str]:
    """
    로그 파일의 마지막 n줄을 가져옵니다.
    - 파일이 매우 큰 경우를 대비해 뒤에서부터 읽습니다.
    - 인코딩 오류는 최대한 무시합니다.
    """
    if n <= 0:
        return []

    block_size = 8192
    data = b""
    lines: List[str] = []

    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        end = f.tell()
        pos = end

        while pos > 0 and len(lines) <= n:
            read_size = block_size if pos >= block_size else pos
            pos -= read_size
            f.seek(pos, os.SEEK_SET)
            data = f.read(read_size) + data

            try:
                text = data.decode(encoding, errors="ignore")
            except Exception:
                text = data.decode("utf-8", errors="ignore")

            lines = text.splitlines()

            if len(lines) > n * 3:
                lines = lines[-(n * 2):]
                data = "\n".join(lines).encode("utf-8", errors="ignore")

    tail = lines[-n:]
    tail = [line.replace("\ufeff", "").rstrip() for line in tail]
    tail = [line for line in tail if line.strip()]
    return tail


def collect_log(
    file_path: str,
    tail_n: int = 200,
    encoding: str = "utf-8",
    include_lines: bool = True,
) -> Metric:
    """
    로그 파일에서 최근 N줄을 수집합니다.
    """
    exists = os.path.exists(file_path)
    meta: Dict[str, Any] = {
        "path": file_path,
        "exists": exists,
    }

    lines: Optional[List[str]] = None
    if exists:
        try:
            st = os.stat(file_path)
            meta.update(
                {
                    "size_bytes": int(st.st_size),
                    "mtime": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(),
                }
            )
        except Exception:
            meta["stat_error"] = "os_stat_failed"

        if include_lines:
            try:
                lines = _tail_lines(file_path, n=tail_n, encoding=encoding)
            except Exception:
                lines = None
                meta["read_error"] = "tail_failed"
    else:
        meta["error"] = "file_not_found"

    stats: Dict[str, Any] = {"tail_n": tail_n}
    if lines is not None:
        stats["lines_collected"] = len(lines)
        lowered = "\n".join(lines).lower()
        stats["keyword_count"] = {
            "error": lowered.count("error"),
            "warn": lowered.count("warn"),
            "fail": lowered.count("fail"),
            "exception": lowered.count("exception"),
            "failed_password": lowered.count("failed password"),
            "invalid_user": lowered.count("invalid user"),
            "authentication_failure": lowered.count("authentication failure"),
            "login_failed": lowered.count("login failed"),
        }

    return {
        "type": "log",
        "timestamp": _now_iso(),
        "host": _host(),
        "data": {
            "meta": meta,
            "stats": stats,
            "lines": lines if include_lines else None,
        },
        "meta": {
            "collector": "tail",
            "encoding": encoding,
            "include_lines": include_lines,
        },
    }
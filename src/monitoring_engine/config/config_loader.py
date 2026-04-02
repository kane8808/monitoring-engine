# monitoring_tool/config/config_loader.py
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import yaml


def load_config(config_path: str | None = None) -> Dict[str, Any]:
    """
    main.py에서 표준으로 호출할 설정 로더 함수.
    config_path가 없으면 monitoring_tool/config/config.yaml 사용
    """
    if config_path is None:
        base = Path(__file__).resolve().parent
        config_path = str(base / "config.yaml")

    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}
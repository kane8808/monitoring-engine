from __future__ import annotations

import json
import os
from typing import Any, Dict, Optional


def load_state(path: str) -> Dict[str, Any]:
    """상태 저장 파일(JSON)을 로드합니다. 없거나 깨졌으면 빈 dict 반환."""
    if not os.path.exists(path):
        return {}

    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_state(path: str, state: Dict[str, Any]) -> None:
    """상태 저장 파일(JSON)을 저장합니다. 디렉터리 없으면 생성."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp_path = path + ".tmp"

    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)

    os.replace(tmp_path, path)


def get_state(state: Dict[str, Any], key: str) -> Optional[Dict[str, Any]]:
    v = state.get(key)
    return v if isinstance(v, dict) else None


def set_state(state: Dict[str, Any], key: str, value: Dict[str, Any]) -> None:
    state[key] = value
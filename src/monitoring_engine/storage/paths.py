from __future__ import annotations

import os


def _is_lambda() -> bool:
    return "AWS_LAMBDA_FUNCTION_NAME" in os.environ


def project_root() -> str:
    # Lambda에서는 /var/task가 읽기 전용이라 /tmp 사용
    if _is_lambda():
        return "/tmp"

    # 로컬/서버 실행 시 프로젝트 루트 기준
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))


def storage_root() -> str:
    path = os.path.join(project_root(), "storage")
    os.makedirs(path, exist_ok=True)
    return path


def evidence_dir() -> str:
    path = os.path.join(storage_root(), "evidence")
    os.makedirs(path, exist_ok=True)
    return path
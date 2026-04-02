from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType


def project_root() -> Path:
    """
    워크스페이스 루트(C:\\monitoring_tool)를 반환.
    - 우선 환경변수 MONITORING_WORKSPACE 사용
    - 없으면 '1.collector' 같은 step 폴더가 존재하는 상위 폴더를 탐색
    """
    import os

    env = os.environ.get("MONITORING_WORKSPACE")
    if env:
        return Path(env).resolve()

    cwd = Path.cwd().resolve()
    for p in [cwd, *cwd.parents]:
        if (p / "1.collector").exists():
            return p

    here = Path(__file__).resolve()
    for p in [here, *here.parents]:
        if (p / "1.collector").exists():
            return p

    return cwd
def _ensure_legacy_package(step_dir: str) -> str:
    """
    '3.detector' 같은 폴더를 상대 import가 가능한 '가짜 패키지'로 등록합니다.
    """
    root = project_root()
    step_path = root / step_dir
    if not step_path.exists():
        raise FileNotFoundError(f"legacy step dir not found: {step_path}")

    pkg_name = f"legacy_{step_dir.replace('.', '_')}"
    if pkg_name in sys.modules:
        return pkg_name

    pkg = ModuleType(pkg_name)
    pkg.__path__ = [str(step_path)]  # 핵심: 패키지의 검색 경로
    pkg.__package__ = pkg_name
    sys.modules[pkg_name] = pkg
    return pkg_name


def load_legacy_module(step_dir: str, filename: str) -> ModuleType:
    """
    step_dir: "3.detector"
    filename: "anomaly_engine.py"

    -> legacy_3_detector.anomaly_engine 형태로 로드하여
       anomaly_engine 내부의 from .log_anomaly 같은 상대 import가 동작하게 함
    """
    root = project_root()
    target = root / step_dir / filename
    if not target.exists():
        raise FileNotFoundError(f"legacy module not found: {target}")

    pkg_name = _ensure_legacy_package(step_dir)
    mod_name = f"{pkg_name}.{filename.replace('.py', '')}"

    # 이미 로드된 모듈이면 재사용
    if mod_name in sys.modules:
        return sys.modules[mod_name]

    spec = importlib.util.spec_from_file_location(mod_name, target)
    if spec is None or spec.loader is None:
        raise ImportError(f"failed to load spec for: {target}")

    mod = importlib.util.module_from_spec(spec)
    mod.__package__ = pkg_name  # 핵심: 상대 import 기준점
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


def call_entry(mod: ModuleType, candidates: list[str], *args, **kwargs):
    for name in candidates:
        fn = getattr(mod, name, None)
        if callable(fn):
            return fn(*args, **kwargs)
    raise AttributeError(f"{mod.__name__}: entry not found in {candidates}")

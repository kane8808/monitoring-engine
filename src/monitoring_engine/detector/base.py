from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class BaseDetector(ABC):
    name: str = "base_detector"

    @abstractmethod
    def detect(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        """
        context를 입력받아 findings 리스트를 반환합니다.
        """
        raise NotImplementedError
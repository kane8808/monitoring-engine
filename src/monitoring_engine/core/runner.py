from __future__ import annotations

import time
from typing import Any

from monitoring_engine.config.config_loader import load_config
from monitoring_engine.core.pipeline import run_pipeline


class EngineRunner:
    def __init__(self, cfg: dict | None = None) -> None:
        self.cfg = cfg or load_config()
        self.sleep_sec = int((self.cfg or {}).get("cycle_seconds", 5))
        self.prev_metrics: dict[str, Any] | None = None

    def run_once(self, include_debug: bool = True) -> dict:
        """
        엔진 파이프라인 1회 실행
        """
        result = run_pipeline(
            cfg=self.cfg,
            prev_metrics=self.prev_metrics,
            include_debug=include_debug,
        )

        self.prev_metrics = result.get("metrics")
        return result

    def run_forever(self, include_debug: bool = True) -> None:
        """
        무한 루프 실행
        """
        print(">>> ENGINE RUNNER STARTED")

        try:
            while True:
                result = self.run_once(include_debug=include_debug)

                # 현재 단계에서는 디버그 출력만 유지
                metrics = result.get("metrics", {})
                status = result.get("status", {})

                print("[METRICS.primary_iface_summary]", metrics.get("primary_iface_summary"))
                print("[STATUS]", status)

                time.sleep(self.sleep_sec)

        except KeyboardInterrupt:
            print("\n[EXIT] Monitoring stopped by user (Ctrl+C)")


def main() -> None:
    runner = EngineRunner()
    runner.run_forever()


if __name__ == "__main__":
    main()
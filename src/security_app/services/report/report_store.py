import json
import os
from typing import Any, Dict

from .markdown import build_report_markdown, save_report_markdown


def _base_dir() -> str:
    return os.path.join(os.getcwd(), "data", "reports")


def save_report(report: Dict[str, Any]) -> str:
    incident_id = report.get("incident_id") or "unknown-incident"
    ts = report.get("timestamp") or report.get("time") or ""
    date_key = ts[:10] if isinstance(ts, str) and len(ts) >= 10 else "unknown-date"

    out_dir = os.path.join(_base_dir(), date_key)
    os.makedirs(out_dir, exist_ok=True)

    report_path = os.path.join(out_dir, f"{incident_id}.report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    print(f"[POST_ANALYZE] report saved: {report_path}")

    md_text = build_report_markdown(report)
    md_path = report_path.replace(".report.json", ".report.md")
    save_report_markdown(md_text, md_path)

    print(f"[POST_ANALYZE] md report saved: {md_path}")

    return report_path
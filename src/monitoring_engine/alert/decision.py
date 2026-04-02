# monitoring_tool/alert/decision.py
from __future__ import annotations

from typing import Any, Dict, List, Optional
import uuid

from monitoring_engine.judge.thresholds import net_thresholds_from_cfg

OK_TOKENS = {"OK", "PASS", "HEALTHY", "NORMAL", "INFO"}
WARN_TOKENS = {"WARN", "WARNING"}
HIGH_TOKENS = {"HIGH"}
CRIT_TOKENS = {"CRITICAL", "FATAL"}


def _as_upper_str(v: Any) -> str:
    if v is None:
        return ""
    return str(v).strip().upper()


def _extract_level(v: Any) -> str:
    if isinstance(v, dict):
        for k in ("status", "level", "result", "state"):
            if k in v and v[k] is not None:
                return _as_upper_str(v[k])
        for k in ("ok", "is_ok", "healthy", "is_healthy"):
            if k in v and isinstance(v[k], bool):
                return "OK" if v[k] else "WARN"
        return ""

    if isinstance(v, bool):
        return "WARN" if v else "OK"

    return _as_upper_str(v)


def _is_bad(v: Any) -> bool:
    lvl = _extract_level(v)
    if not lvl:
        return False
    if lvl in OK_TOKENS:
        return False

    bad_tokens = (
        "NOT OK",
        "NOTOK",
        "FAIL",
        "FAILED",
        "ERROR",
        "WARN",
        "WARNING",
        "HIGH",
        "CRITICAL",
        "FATAL",
        "ANOMALY",
        "SPIKE",
        "DROP",
    )
    return any(t in lvl for t in bad_tokens)


def _is_warning(v: Any) -> bool:
    lvl = _extract_level(v)
    if not lvl:
        return False
    return lvl in WARN_TOKENS or "WARN" in lvl or "WARNING" in lvl


def _is_high(v: Any) -> bool:
    lvl = _extract_level(v)
    if not lvl:
        return False
    return lvl in HIGH_TOKENS or "HIGH" in lvl


def _is_critical(v: Any) -> bool:
    lvl = _extract_level(v)
    if not lvl:
        return False
    if lvl in CRIT_TOKENS:
        return True
    return "CRITICAL" in lvl or "FATAL" in lvl


def _collect_reasons(judge: Dict[str, Any], detect: Dict[str, Any]) -> List[str]:
    reasons: List[str] = []

    for k, v in (judge or {}).items():
        if _is_bad(v):
            lvl = _extract_level(v) or "NOT_OK"
            reasons.append(f"JUDGE_{k.upper()}_{lvl}")

    for k, v in (detect or {}).items():
        if not _is_bad(v):
            continue
        lvl = _extract_level(v) or "ANOMALY"
        reasons.append(f"DETECT_{k.upper()}_{lvl}")

    seen = set()
    uniq: List[str] = []
    for r in reasons:
        if r not in seen:
            seen.add(r)
            uniq.append(r)
    return uniq


def _pick_severity(judge: Dict[str, Any], detect: Dict[str, Any]) -> str:
    j = judge or {}
    d = detect or {}

    # 1. CRITICAL 우선
    for k in ("cpu", "memory", "disk", "network", "log"):
        if k in j and _is_critical(j[k]):
            return "CRITICAL"
    for v in d.values():
        if _is_critical(v):
            return "CRITICAL"

    # 2. HIGH
    for k in ("cpu", "memory", "disk", "network", "log"):
        if k in j and _is_high(j[k]):
            return "HIGH"
    for v in d.values():
        if _is_high(v):
            return "HIGH"

    # 3. WARN
    for v in j.values():
        if _is_warning(v):
            return "WARN"
    for v in d.values():
        if _is_warning(v):
            return "WARN"

    # 4. 그 외 bad 값은 WARN
    for v in j.values():
        if _is_bad(v):
            return "WARN"
    for v in d.values():
        if _is_bad(v):
            return "WARN"

    return "INFO"


def decide_alert(
    judge: Dict[str, Any],
    detect: Dict[str, Any],
    cfg: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Returns:
      {
        "should_alert": bool,
        "severity": "INFO" | "WARN" | "HIGH" | "CRITICAL",
        "reasons": [str, ...],
        "incident_id": "INC-xxxxxxxx" | None,
      }
    """
    cfg = cfg or {}

    reasons = _collect_reasons(judge, detect)

    th = net_thresholds_from_cfg(cfg)
    suppress_net = bool(th.get("test_mode")) and bool(th.get("suppress_alert"))

    if suppress_net:
        net_tokens = ("NETWORK", "NETWORK_ANOMALY", "NETWORK_RATE")
        reasons = [r for r in reasons if not any(t in r for t in net_tokens)]

    severity = _pick_severity(judge, detect) if reasons else "INFO"

    # HIGH 이상만 알림, WARN은 정책상 보류
    should_alert = severity in ("HIGH", "CRITICAL")
    incident_id = f"INC-{uuid.uuid4().hex[:8]}" if should_alert else None

    return {
        "should_alert": should_alert,
        "severity": severity,
        "reasons": reasons,
        "incident_id": incident_id,
    }
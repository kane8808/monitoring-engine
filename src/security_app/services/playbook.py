from __future__ import annotations

from typing import Any, Dict, List


def _normalize_item(value: Any) -> str:
    if value is None:
        return ""

    text = str(value).strip().lower()

    alias_map = {
        "cpu": "cpu",
        "processor": "cpu",
        "memory": "memory",
        "mem": "memory",
        "ram": "memory",
        "disk": "disk",
        "filesystem": "disk",
        "fs": "disk",
        "network": "network",
        "net": "network",
        "network_rate": "network",
        "nic": "network",
        "log": "log",
        "logs": "log",
        "auth_log": "log",
    }

    return alias_map.get(text, text)


def _add_action(
    actions: List[Dict[str, Any]],
    seen: set[tuple[str, str]],
    action: str,
    reason: str,
    **extra: Any,
) -> None:
    key = (action, str(extra.get("service", "")))

    if key in seen:
        return

    payload: Dict[str, Any] = {
        "action": action,
        "reason": reason,
    }
    payload.update(extra)

    actions.append(payload)
    seen.add(key)


def build_playbook(report: Dict[str, Any]) -> Dict[str, Any]:
    """
    분석 리포트를 기반으로 추천 조치(playbook)를 생성합니다.

    기대 입력 예:
    {
        "judge_not_ok": [
            {"item": "cpu", "severity": "WARN"},
            {"item": "log", "severity": "CRITICAL"},
        ]
    }
    """
    judge_not_ok = report.get("judge_not_ok") or []

    bad_items: set[str] = set()
    severities: set[str] = set()

    for entry in judge_not_ok:
        if not isinstance(entry, dict):
            continue

        item = _normalize_item(entry.get("item"))
        severity = str(entry.get("severity", "")).strip().upper()

        if item:
            bad_items.add(item)
        if severity:
            severities.add(severity)

    actions: List[Dict[str, Any]] = []
    notes: List[str] = []
    seen_actions: set[tuple[str, str]] = set()

    if "cpu" in bad_items:
        _add_action(
            actions,
            seen_actions,
            "collect_top_processes",
            "CPU 과부하 시 상위 CPU 점유 프로세스 확인",
        )
        _add_action(
            actions,
            seen_actions,
            "restart_service",
            "CPU 과부하가 지속되면 서비스 재시작 검토",
            service="your-service",
        )
        notes.append("CPU 임계치 초과가 일시 스파이크인지, 최근 N회 평균 기준인지 함께 확인하세요.")

    if "memory" in bad_items:
        _add_action(
            actions,
            seen_actions,
            "collect_top_memory_processes",
            "메모리 사용량이 높은 프로세스 확인",
        )
        _add_action(
            actions,
            seen_actions,
            "restart_service",
            "메모리 누수 의심 시 서비스 재시작 검토",
            service="your-service",
        )
        notes.append("RSS/VMS 추적과 누수 의심 프로세스 장기 관찰을 권장합니다.")

    if "disk" in bad_items:
        _add_action(
            actions,
            seen_actions,
            "cleanup_temp",
            "임시 파일 및 불필요 로그 정리",
        )
        _add_action(
            actions,
            seen_actions,
            "check_log_rotation",
            "로그 로테이션 설정 점검",
        )
        notes.append("디스크 사용률과 inode 사용률을 함께 확인하면 더 좋습니다.")

    if "network" in bad_items:
        _add_action(
            actions,
            seen_actions,
            "check_interface",
            "NIC 상태, 링크 속도, isup 상태 확인",
        )
        _add_action(
            actions,
            seen_actions,
            "inspect_connections",
            "비정상 연결, 급증한 세션, 특정 IP 집중 여부 확인",
        )
        notes.append("누적 bytes 기반 tx/rx rate 계산이 정상인지, 샘플링 간격도 같이 확인하세요.")

    if "log" in bad_items:
        _add_action(
            actions,
            seen_actions,
            "inspect_logs",
            "로그 발췌를 기반으로 원인 파악",
        )
        _add_action(
            actions,
            seen_actions,
            "extract_error_patterns",
            "에러 키워드와 스택트레이스 패턴 추가 분석",
        )
        notes.append("로그 발생 시각과 metrics 급변 시점을 비교하면 원인 추적에 도움이 됩니다.")

    if "CRITICAL" in severities:
        _add_action(
            actions,
            seen_actions,
            "send_alert",
            "CRITICAL 이벤트이므로 즉시 알림 전송 권장",
            channel="security",
        )
        notes.append("CRITICAL 등급은 운영자 즉시 확인 대상으로 분류하세요.")

    if not actions:
        _add_action(
            actions,
            seen_actions,
            "manual_check",
            "자동 판단 불가, 운영자 확인 필요",
        )
        notes.append("판단 기준이 부족하므로 evidence 원본을 직접 검토하세요.")

    if "CRITICAL" in severities:
        priority = "high"
    elif "WARN" in severities:
        priority = "medium"
    else:
        priority = "normal"

    summary = {
        "bad_items": sorted(bad_items),
        "detected_severities": sorted(severities),
        "action_count": len(actions),
        "priority": priority,
    }

    return {
        "summary": summary,
        "recommended_actions": actions,
        "notes": notes,
    }

def run_playbook(context: dict) -> dict:
    """
    playbook 실행 스텁
    - 현재는 recommended_actions 또는 actions 를 받아
      실행 예정 목록만 정리해서 반환합니다.
    - 실제 시스템 변경은 하지 않습니다.
    """

    actions = (
        context.get("recommended_actions")
        or context.get("actions")
        or []
    )

    if not isinstance(actions, list):
        return {
            "ok": False,
            "error": "actions must be a list",
        }

    executed_actions = []

    for item in actions:
        if isinstance(item, dict):
            executed_actions.append({
                "action": item.get("action", "unknown"),
                "reason": item.get("reason"),
                "status": "simulated",
            })
        else:
            executed_actions.append({
                "action": str(item),
                "status": "simulated",
            })

    return {
        "ok": True,
        "executed_actions": executed_actions,
        "count": len(executed_actions),
    }
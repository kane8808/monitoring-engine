from __future__ import annotations
from typing import Any, Dict

from monitoring_tool.common.legacy_loader import load_legacy_module, call_entry

# 6.response 폴더의 responder.py를 패키지 컨텍스트로 로드
_responder = load_legacy_module("6.response", "responder.py")


def respond(context: Dict[str, Any]) -> Dict[str, Any]:
    """
    responder 실행 결과를 context에 담아 반환
    - 후보 함수명: respond / run / execute / main
    - 보통 context 1개를 받는 형태
    """
    out = dict(context)
    try:
        out["response"] = call_entry(_responder, ["respond", "run", "execute", "main"], out)
    except TypeError:
        out["response"] = call_entry(_responder, ["respond", "run", "execute", "main"])
    except Exception as e:
        out["response_error"] = str(e)
    return out
from typing import Any, Optional

def dig(d: Any, keys: set[str]) -> Optional[Any]:
    """중첩 dict/list에서 keys 중 하나를 찾아 첫 값을 반환"""
    if isinstance(d, dict):
        for k, v in d.items():
            if k in keys and v is not None:
                return v
        for v in d.values():
            found = dig(v, keys)
            if found is not None:
                return found
    elif isinstance(d, list):
        for item in d:
            found = dig(item, keys)
            if found is not None:
                return found
    return None
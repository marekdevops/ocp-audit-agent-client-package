from __future__ import annotations

import json
from typing import Any


def dumps(data: Any) -> str:
    return json.dumps(data, default=str, ensure_ascii=False, sort_keys=True)


def loads(data: str | None, default: Any = None) -> Any:
    if not data:
        return default
    try:
        return json.loads(data)
    except json.JSONDecodeError:
        return default

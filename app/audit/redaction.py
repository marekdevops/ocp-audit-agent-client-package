from __future__ import annotations

import re
from typing import Any

SENSITIVE_MARKERS = {
    "password",
    "passwd",
    "token",
    "secret",
    "key",
    "apikey",
    "api_key",
    "authorization",
    "bearer",
    "credential",
}

SENSITIVE_TEXT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]+"),
    re.compile(
        r"""(?ix)
        \b(token|password|passwd|secret|apikey|api_key|authorization|credential|client_secret)
        \s*(?:=|:)\s*
        (?:
          "(?:\\.|[^"])*"
          |'(?:\\.|[^'])*'
          |[^\s,;}\]]+
        )
        """
    ),
    re.compile(r"(?i)(https?://[^/\s:@]+:)[^@\s/]+@"),
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----", re.DOTALL),
    re.compile(r"\b[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
)


def is_sensitive_key(key: str) -> bool:
    low = key.lower()
    return any(marker in low for marker in SENSITIVE_MARKERS)


def redact_text(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    redacted = value
    for pattern in SENSITIVE_TEXT_PATTERNS:
        if pattern.pattern.startswith("(?i)\\b(bearer"):
            redacted = pattern.sub(r"\1<redacted>", redacted)
        elif "https?://" in pattern.pattern:
            redacted = pattern.sub(r"\1<redacted>@", redacted)
        elif "PRIVATE KEY" in pattern.pattern:
            redacted = pattern.sub("<redacted-private-key>", redacted)
        elif "client_secret" in pattern.pattern:
            redacted = pattern.sub(lambda match: f"{match.group(1)}=<redacted>", redacted)
        else:
            redacted = pattern.sub("<redacted-token>", redacted)
    return redacted


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        kind = str(value.get("kind", "")).lower()
        if kind == "secret":
            meta = redact(value.get("metadata", {}))
            return {
                "apiVersion": value.get("apiVersion"),
                "kind": value.get("kind"),
                "metadata": meta,
                "type": value.get("type"),
                "data": "<redacted>",
                "stringData": "<redacted>",
            }
        if is_sensitive_key(str(value.get("name", ""))) and "value" in value:
            value = dict(value)
            value["value"] = "<redacted>"
        result: dict[str, Any] = {}
        for key, item in value.items():
            result[key] = "<redacted>" if is_sensitive_key(str(key)) else redact(item)
        return result
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value

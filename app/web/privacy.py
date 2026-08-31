from __future__ import annotations

from fastapi import Request

from app.config import Settings

COOKIE_NAME = "ocp_audit_anonymize"


def effective_anonymization(request: Request, settings: Settings) -> bool:
    cookie = request.cookies.get(COOKIE_NAME)
    if cookie == "false" and settings.allow_ui_deanonymize:
        return False
    if cookie == "true":
        return True
    return settings.anonymize_output

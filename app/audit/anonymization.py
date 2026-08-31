from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from app.audit.anonymization_config import load_terms
from app.audit.redaction import redact_text


IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
ANIMALS = ("doggy", "otter", "badger", "lynx", "panda", "falcon", "orca", "rabbit", "tiger", "koala", "beaver", "gecko")


def _animal_for(term: str, salt: str) -> str:
    return ANIMALS[int(hashlib.sha256(f"{salt}:term:{term.casefold()}".encode()).hexdigest(), 16) % len(ANIMALS)]


def _replace_terms(value: Any, salt: str, terms: list[str] | None = None) -> str:
    text = str(value)
    for term in sorted(terms if terms is not None else load_terms(), key=len, reverse=True):
        if term:
            text = re.sub(re.escape(term), _animal_for(term, salt), text, flags=re.IGNORECASE)
    return text


def _fake_ip(value: str, salt: str) -> str:
    digest = hashlib.sha256(f"{salt}:ip:{value}".encode()).digest()
    # RFC 2544 benchmarking range: non-routable, recognizable as synthetic.
    return f"198.18.{digest[0]}.{max(1, digest[1])}"


def scrub_text(value: Any, salt: str, terms: list[str] | None = None) -> Any:
    """Replace configured customer terms and IPs, preserving all other context.

    Secret redaction remains mandatory and is independent of anonymization policy.
    """
    if value is None:
        return None
    text = _replace_terms(redact_text(str(value)), salt, terms)
    return IP_PATTERN.sub(lambda match: _fake_ip(match.group(0), salt), text)


def anonymize_ip(value: Any, salt: str) -> Any:
    if value in (None, "", "-"):
        return value
    return _fake_ip(str(value), salt) if IP_PATTERN.fullmatch(str(value)) else scrub_text(value, salt)


def anonymize_value(value: Any, salt: str, terms: list[str] | None = None) -> Any:
    if isinstance(value, dict):
        return {key: anonymize_value(item, salt, terms) for key, item in value.items()}
    if isinstance(value, list):
        return [anonymize_value(item, salt, terms) for item in value]
    return scrub_text(value, salt, terms) if isinstance(value, str) else value


def anonymize_event(event: dict[str, Any], salt: str, terms: list[str] | None = None) -> dict[str, Any]:
    return anonymize_value(dict(event), salt, terms)


def anonymize_finding(finding: dict[str, Any], salt: str, terms: list[str] | None = None) -> dict[str, Any]:
    item = anonymize_value(dict(finding), salt, terms)
    if "evidence_obj" in item:
        item["evidence_json"] = json.dumps(item["evidence_obj"], ensure_ascii=False, indent=2, default=str)
    if "resource" in item:
        item["resource"] = f"{item.get('resource_kind') or '-'}/{item.get('namespace') or '-'}/{item.get('resource_name') or '-'}"
    return item


def anonymize_observation(obs: dict[str, Any], salt: str, terms: list[str] | None = None) -> dict[str, Any]:
    return anonymize_value(dict(obs), salt, terms)


def anonymize_events(events: list[dict[str, Any]], salt: str, terms: list[str] | None = None) -> list[dict[str, Any]]:
    return [anonymize_event(item, salt, terms) for item in events]


def anonymize_findings(findings: list[dict[str, Any]], salt: str, terms: list[str] | None = None) -> list[dict[str, Any]]:
    return [anonymize_finding(item, salt, terms) for item in findings]


def anonymize_observations(items: list[dict[str, Any]], salt: str, terms: list[str] | None = None) -> list[dict[str, Any]]:
    return [anonymize_observation(item, salt, terms) for item in items]


def anonymize_operational_records(items: list[dict[str, Any]], salt: str) -> list[dict[str, Any]]:
    return [anonymize_value(dict(item), salt) for item in items]

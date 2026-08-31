from __future__ import annotations

import json
import os
from pathlib import Path


CONFIG_FILENAME = "anonymization-terms.json"


def config_path(data_dir: str | None = None) -> Path:
    return Path(data_dir or os.getenv("AUDIT_DATA_DIR", "/data")) / CONFIG_FILENAME


def load_terms(data_dir: str | None = None) -> list[str]:
    try:
        payload = json.loads(config_path(data_dir).read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return []
    terms = payload.get("terms", []) if isinstance(payload, dict) else []
    return sorted({str(term).strip() for term in terms if str(term).strip()}, key=str.casefold)


def save_terms(terms: list[str], data_dir: str | None = None) -> list[str]:
    cleaned = sorted({str(term).strip() for term in terms if str(term).strip()}, key=str.casefold)
    path = config_path(data_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps({"terms": cleaned}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return cleaned

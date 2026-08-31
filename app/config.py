from __future__ import annotations

from dataclasses import dataclass, replace
import os
from pathlib import Path
import secrets
import time


def _bool(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    namespace: str = os.getenv("AUDIT_NAMESPACE", "ocp-audit")
    data_dir: str = os.getenv("AUDIT_DATA_DIR", "/data")
    db_path: str = os.getenv("AUDIT_DB_PATH", "/data/audit.db")
    database_url: str = os.getenv("AUDIT_DATABASE_URL", "")
    database_password: str = os.getenv("AUDIT_DATABASE_PASSWORD", "")
    report_dir: str = os.getenv("AUDIT_REPORT_DIR", "/data/reports")
    log_level: str = os.getenv("AUDIT_LOG_LEVEL", "INFO")
    cluster_name: str = os.getenv("AUDIT_CLUSTER_NAME", "auto")
    retention_days: int = int(os.getenv("AUDIT_RETENTION_DAYS", "14"))
    snapshot_interval_seconds: int = int(os.getenv("AUDIT_SNAPSHOT_INTERVAL_SECONDS", "900"))
    enable_openshift: bool = _bool("AUDIT_ENABLE_OPENSHIFT", "true")
    enable_secret_audit: bool = _bool("AUDIT_ENABLE_SECRET_AUDIT", "false")
    enable_k8s_job_trigger: bool = _bool("AUDIT_ENABLE_K8S_JOB_TRIGGER", "false")
    anonymize_output: bool = _bool("AUDIT_ANONYMIZE_OUTPUT", "false")
    anonymization_salt: str = os.getenv("AUDIT_ANONYMIZATION_SALT", "")
    allow_ui_deanonymize: bool = _bool("AUDIT_ALLOW_UI_DEANONYMIZE", "true")
    web_host: str = os.getenv("AUDIT_WEB_HOST", "0.0.0.0")
    web_port: int = int(os.getenv("AUDIT_WEB_PORT", "8080"))
    web_expose_docs: bool = _bool("AUDIT_WEB_EXPOSE_DOCS", "false")
    event_buffer_size: int = int(os.getenv("AUDIT_EVENT_BUFFER_SIZE", "500"))
    redact_secrets: bool = _bool("AUDIT_REDACT_SECRETS", "true")
    collect_pod_logs: bool = _bool("AUDIT_COLLECT_POD_LOGS", "false")
    pod_log_tail_lines: int = int(os.getenv("AUDIT_POD_LOG_TAIL_LINES", "80"))
    pod_log_limit_bytes: int = int(os.getenv("AUDIT_POD_LOG_LIMIT_BYTES", "20000"))
    pod_log_min_age_minutes: int = int(os.getenv("AUDIT_POD_LOG_MIN_AGE_MINUTES", "10"))
    pod_log_min_restarts: int = int(os.getenv("AUDIT_POD_LOG_MIN_RESTARTS", "3"))
    pod_log_pattern_min_count: int = int(os.getenv("AUDIT_POD_LOG_PATTERN_MIN_COUNT", "3"))


def get_settings() -> Settings:
    settings = Settings()
    if settings.anonymization_salt:
        return settings
    path = Path(settings.data_dir) / "anonymization-salt"
    path.parent.mkdir(parents=True, exist_ok=True)
    candidate = secrets.token_urlsafe(32)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        descriptor = None
    if descriptor is not None:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(candidate)
            handle.flush()
            os.fsync(handle.fileno())
        salt = candidate
    else:
        salt = ""
        for _ in range(20):
            salt = path.read_text(encoding="utf-8").strip()
            if salt:
                break
            time.sleep(0.05)
        if not salt:
            raise RuntimeError(f"anonymization salt file is empty: {path}")
    return replace(settings, anonymization_salt=salt)

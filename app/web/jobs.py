from __future__ import annotations

import logging
import os
from pathlib import Path

from app.audit.report import generate_report
from app.config import Settings
from app.kube.client import load_kube_config, cluster_name
from app.kube.collectors import run_snapshot
from app.storage.repositories import AuditRepository
from app.utils.time import iso_now, utcnow

LOG = logging.getLogger(__name__)


def run_snapshot_job(repo: AuditRepository, settings: Settings, job_id: int | None = None) -> dict | None:
    job_id = job_id or repo.create_job_if_not_running("snapshot")
    if job_id is None:
        LOG.info("snapshot request ignored because another snapshot is already running")
        return None
    try:
        load_kube_config()
        cluster = cluster_name(settings.cluster_name)
        summary = run_snapshot(
            repo,
            cluster,
            settings.enable_openshift,
            settings.enable_secret_audit,
            settings.collect_pod_logs,
            settings.pod_log_tail_lines,
            settings.pod_log_limit_bytes,
            settings.pod_log_min_age_minutes,
            settings.pod_log_min_restarts,
            settings.pod_log_pattern_min_count,
            settings.retention_days,
        )
        repo.finish_job(job_id, "success", f"Snapshot completed: {summary}")
        return summary
    except Exception as exc:
        LOG.exception("snapshot job failed")
        repo.finish_job(job_id, "failed", error=str(exc))
        return None


def run_report_job(
    repo: AuditRepository,
    settings: Settings,
    fmt: str = "html",
    anonymize: bool | None = None,
    job_id: int | None = None,
) -> None:
    job_id = job_id or repo.create_job("report", f"Generating {fmt.upper()} report")
    try:
        Path(settings.report_dir).mkdir(parents=True, exist_ok=True)
        ext = {"html": "html", "markdown": "md", "json": "json", "pdf": "pdf"}.get(fmt, fmt)
        output = os.path.join(settings.report_dir, f"audit-{iso_now().replace(':', '-')}.{ext}")
        result = generate_report(repo, fmt, output, cluster_name(settings.cluster_name), settings.anonymize_output if anonymize is None else anonymize, settings.anonymization_salt)
        repo.finish_job(
            job_id,
            "success",
            f"Report generated: {result['path']}",
            report_id=int(result["id"]),
        )
    except Exception as exc:
        LOG.exception("report job failed")
        repo.finish_job(job_id, "failed", f"{fmt.upper()} report generation failed", error=str(exc))


def run_cleanup_job(repo: AuditRepository, settings: Settings) -> None:
    job_id = repo.create_job("cleanup")
    try:
        deleted = repo.prune_history(settings.retention_days)
        repo.finish_job(
            job_id,
            "success",
            f"Deleted {deleted['events']} events, {deleted['resource_history']} resource history entries and {deleted['pod_history']} Pod history entries older than {settings.retention_days} days; current inventory was preserved",
        )
    except Exception as exc:
        LOG.exception("cleanup job failed")
        repo.finish_job(job_id, "failed", error=str(exc))

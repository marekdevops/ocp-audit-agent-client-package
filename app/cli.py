from __future__ import annotations

import os
from pathlib import Path

import typer
import uvicorn

from app import __version__
from app.audit.report import generate_report
from app.config import get_settings
from app.kube.client import cluster_name, load_kube_config
from app.web.jobs import run_snapshot_job
from app.kube.watchers import EventBus, watch_forever
from app.logging_config import configure_logging
from app.storage.db import Database
from app.storage.repositories import AuditRepository
from app.utils.json import dumps
from app.web.server import create_app

app = typer.Typer(no_args_is_help=True)


def _repo() -> tuple[AuditRepository, object]:
    settings = get_settings()
    configure_logging(settings.log_level)
    Path(settings.data_dir).mkdir(parents=True, exist_ok=True)
    Path(settings.report_dir).mkdir(parents=True, exist_ok=True)
    db = Database(settings.db_path, settings.database_url, settings.database_password)
    db.init()
    return AuditRepository(db), settings


@app.command()
def server() -> None:
    repo, settings = _repo()
    uvicorn.run(create_app(settings, repo, EventBus(settings.event_buffer_size)), host=settings.web_host, port=settings.web_port)


@app.command()
def watch() -> None:
    repo, settings = _repo()
    load_kube_config()
    watch_forever(repo, cluster_name(settings.cluster_name), EventBus(settings.event_buffer_size), settings.enable_openshift)


@app.command()
def snapshot() -> None:
    repo, settings = _repo()
    summary = run_snapshot_job(repo, settings)
    typer.echo(dumps(summary or {"status": "skipped", "reason": "snapshot already running"}))


@app.command()
def report(
    format: str = typer.Option("html", "--format"),
    output: str = typer.Option(..., "--output"),
    anonymize: bool | None = typer.Option(None, "--anonymize/--no-anonymize"),
) -> None:
    repo, settings = _repo()
    result = generate_report(
        repo,
        format,
        output,
        cluster_name(settings.cluster_name),
        settings.anonymize_output if anonymize is None else anonymize,
        settings.anonymization_salt,
    )
    typer.echo(dumps(result))


@app.command()
def export(output: str = typer.Option(..., "--output")) -> None:
    repo, _ = _repo()
    data = {
        "summary": repo.summary(),
        "events": repo.list_events(limit=10000),
        "findings": repo.list_findings(limit=10000),
        "snapshots": repo.list_snapshots(limit=1000),
        "jobs": repo.list_jobs(limit=1000),
        "reports": repo.list_reports(),
    }
    Path(os.path.dirname(output) or ".").mkdir(parents=True, exist_ok=True)
    Path(output).write_text(dumps(data), encoding="utf-8")
    typer.echo(output)


@app.command()
def version() -> None:
    typer.echo(__version__)

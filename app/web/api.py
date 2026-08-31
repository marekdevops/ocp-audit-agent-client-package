from __future__ import annotations

import asyncio
import json
import os
from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, Request
from fastapi.responses import FileResponse, StreamingResponse

from app.audit.anonymization import (
    anonymize_event,
    anonymize_events,
    anonymize_findings,
    anonymize_observations,
    anonymize_operational_records,
)
from app.audit.presentation import (
    WORKLOAD_OBSERVATION_KINDS,
    build_audit_view,
    filter_findings,
    prepare_findings,
)
from app.config import Settings
from app.storage.repositories import AuditRepository
from app.web.jobs import run_cleanup_job, run_report_job, run_snapshot_job
from app.kube.watchers import EventBus
from app.web.privacy import effective_anonymization
from app.utils.json import loads


def create_api(repo: AuditRepository, settings: Settings, bus: EventBus) -> APIRouter:
    router = APIRouter()

    def prepared_findings() -> list[dict]:
        return prepare_findings(
            repo.list_findings(limit=10000),
            observations=repo.list_observations(50000, kinds=WORKLOAD_OBSERVATION_KINDS),
        )

    @router.get("/healthz")
    def healthz():
        return {"status": "ok"}

    @router.get("/readyz")
    def readyz():
        with repo.db.session() as conn:
            conn.execute("SELECT 1")
        return {"status": "ready"}

    @router.get("/api/summary")
    def summary(request: Request):
        anonymized = effective_anonymization(request, settings)
        summary_findings = prepared_findings()
        if anonymized:
            summary_findings = anonymize_findings(summary_findings, settings.anonymization_salt)
        audit_view = build_audit_view(summary_findings, repo.summary()["events_last_hour"])
        data = dict(audit_view["summary"])
        data["correlated_incidents"] = audit_view["incidents"][:20]
        data["anonymized"] = anonymized
        data["allow_ui_deanonymize"] = settings.allow_ui_deanonymize
        latest_snapshot = repo.latest_snapshot_summary()
        data["audit_coverage"] = latest_snapshot.get("coverage") or {}
        data["not_checked"] = latest_snapshot.get("not_checked") or []
        data["snapshot_status"] = latest_snapshot.get("status")
        operators = repo.latest_observations("ClusterOperator", 50)
        versions = repo.latest_observations("ClusterVersion", 5)
        mcps = repo.latest_observations("MachineConfigPool", 20)
        if anonymized:
            operators = anonymize_observations(operators, settings.anonymization_salt)
            versions = anonymize_observations(versions, settings.anonymization_salt)
            mcps = anonymize_observations(mcps, settings.anonymization_salt)
        data["clusteroperators"] = operators
        data["clusterversions"] = versions
        data["machineconfigpools"] = mcps
        data["cni_components"] = anonymize_observations(repo.latest_observations("CNIComponent", 50), settings.anonymization_salt) if anonymized else repo.latest_observations("CNIComponent", 50)
        data["csi_drivers"] = anonymize_observations(repo.latest_observations("CSIDriver", 100), settings.anonymization_salt) if anonymized else repo.latest_observations("CSIDriver", 100)
        data["csi_nodes_count"] = len(repo.latest_observations("CSINode", 500))
        data["storage_classes"] = anonymize_observations(repo.latest_observations("StorageClass", 100), settings.anonymization_salt) if anonymized else repo.latest_observations("StorageClass", 100)
        data["persistent_volumes_count"] = len(repo.latest_observations("PersistentVolume", 1000))
        data["persistent_volume_claims_count"] = len(repo.latest_observations("PersistentVolumeClaim", 1000))
        return data

    @router.get("/api/privacy")
    def privacy(request: Request):
        anonymized = effective_anonymization(request, settings)
        return {
            "anonymized": anonymized,
            "default_anonymize_output": settings.anonymize_output,
            "allow_ui_deanonymize": settings.allow_ui_deanonymize,
            "cookie": request.cookies.get("ocp_audit_anonymize"),
        }

    @router.get("/api/events")
    def events(request: Request, namespace: str | None = None, reason: str | None = None, type: str | None = None, involved_kind: str | None = None, kind: str | None = None, severity: str | None = None, limit: int = Query(200, le=1000)):
        involved_kind = involved_kind or kind
        events_data = repo.list_events(limit=limit, namespace=namespace, reason=reason, type=type, involved_kind=involved_kind, severity=severity)
        return anonymize_events(events_data, settings.anonymization_salt) if effective_anonymization(request, settings) else events_data

    @router.get("/api/events/recent")
    def recent(request: Request):
        events_data = repo.list_events(limit=50)
        return anonymize_events(events_data, settings.anonymization_salt) if effective_anonymization(request, settings) else events_data

    @router.get("/api/stream/events")
    async def stream_events(request: Request):
        async def gen():
            anonymized = effective_anonymization(request, settings)
            recent = repo.list_events(limit=1)
            last_id = recent[0]["id"] if recent else 0
            yield ": connected\n\n"
            while True:
                rows = repo.events_after_id(last_id, limit=100)
                for event in rows:
                    last_id = max(last_id, event["id"])
                    if anonymized:
                        event = anonymize_event(event, settings.anonymization_salt)
                    yield f"data: {json.dumps(event, default=str)}\n\n"
                await asyncio.sleep(2)

        return StreamingResponse(gen(), media_type="text/event-stream")

    @router.get("/api/findings")
    def findings(request: Request, severity: str | None = None, category: str | None = None, namespace: str | None = None, resource_kind: str | None = None, kind: str | None = None, limit: int = Query(500, le=2000)):
        resource_kind = resource_kind or kind
        findings_data = filter_findings(
            prepared_findings(),
            severity=severity,
            category=category,
            namespace=namespace,
            resource_kind=resource_kind,
        )[:limit]
        if effective_anonymization(request, settings):
            findings_data = anonymize_findings(findings_data, settings.anonymization_salt)
        return findings_data

    @router.get("/api/history")
    def history(request: Request, kind: str | None = None, namespace: str | None = None, event_type: str | None = None, name: str | None = None, limit: int = Query(500, le=5000)):
        items = repo.list_pod_history(limit=limit, namespace=namespace, event_type=event_type, name=name)
        return anonymize_observations(items, settings.anonymization_salt) if effective_anonymization(request, settings) else items

    @router.get("/api/snapshots")
    def snapshots(request: Request):
        items = repo.list_snapshots()
        return anonymize_operational_records(items, settings.anonymization_salt) if effective_anonymization(request, settings) else items

    @router.get("/api/jobs")
    def jobs(request: Request):
        items = repo.list_jobs()
        return anonymize_operational_records(items, settings.anonymization_salt) if effective_anonymization(request, settings) else items

    @router.post("/api/jobs/snapshot")
    def snapshot_job(background: BackgroundTasks):
        background.add_task(run_snapshot_job, repo, settings)
        return {"status": "queued"}

    @router.post("/api/jobs/report")
    def report_job(request: Request, background: BackgroundTasks, fmt: str = "html", anonymize: bool = True):
        report_anonymized = anonymize if settings.allow_ui_deanonymize else True
        job_id = repo.create_job_if_not_running("report", f"Generating {fmt.upper()} report")
        if job_id is None:
            return {"status": "already_running"}
        background.add_task(run_report_job, repo, settings, fmt, report_anonymized, job_id)
        return {"status": "queued", "job_id": job_id}

    @router.post("/api/jobs/cleanup")
    def cleanup_job(background: BackgroundTasks):
        background.add_task(run_cleanup_job, repo, settings)
        return {"status": "queued"}

    @router.get("/api/reports")
    def reports(request: Request):
        items = repo.list_reports()
        return anonymize_operational_records(items, settings.anonymization_salt) if effective_anonymization(request, settings) else items

    @router.get("/api/reports/{report_id}/download")
    def download(request: Request, report_id: int):
        report = next((r for r in repo.list_reports() if r["id"] == report_id), None)
        if not report or not os.path.exists(report["path"]):
            raise HTTPException(status_code=404, detail="report not found")
        metadata = loads(report.get("summary_json"), {})
        if effective_anonymization(request, settings) and metadata.get("anonymized") is not True:
            raise HTTPException(status_code=403, detail="raw report download is disabled by anonymization policy")
        return FileResponse(report["path"], filename=os.path.basename(report["path"]))

    return router

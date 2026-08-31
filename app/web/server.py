from __future__ import annotations

import json
from urllib.parse import urlencode, parse_qs
from pathlib import Path
from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.audit.anonymization import anonymize_events, anonymize_findings, anonymize_ip, anonymize_observations, anonymize_operational_records, scrub_text
from app.audit.anonymization_config import load_terms, save_terms
from app.audit.presentation import (
    LOG_FINDING_TITLE,
    RESTART_FINDING_TITLE,
    WORKLOAD_OBSERVATION_KINDS,
    build_audit_view,
    prepare_findings,
)
from app.config import Settings
from app.kube.watchers import EventBus
from app.storage.db import Database
from app.storage.repositories import AuditRepository
from app.web.api import create_api
from app.web.jobs import run_cleanup_job, run_report_job, run_snapshot_job
from app.web.privacy import COOKIE_NAME, effective_anonymization
from app.utils.json import loads


def _security_headers(response: Response) -> Response:
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; connect-src 'self'; object-src 'none'; "
        "base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


def _node_condition(conditions: list[dict], condition_type: str) -> str:
    for condition in conditions or []:
        if condition.get("type") == condition_type:
            return condition.get("status") or "Unknown"
    return "Unknown"


def _host_os_summary(nodes: list[dict]) -> dict:
    rows = []
    os_images, kernels, runtimes = set(), set(), set()
    ready_count = 0
    pressure_count = 0
    for item in nodes:
        raw = item.get("raw") if isinstance(item.get("raw"), dict) else {}
        status = raw.get("status") or {}
        spec = raw.get("spec") or {}
        info = status.get("nodeInfo") or {}
        conditions = status.get("conditions") or []
        ready = _node_condition(conditions, "Ready")
        pressures = [name for name in ("MemoryPressure", "DiskPressure", "PIDPressure") if _node_condition(conditions, name) == "True"]
        if ready == "True":
            ready_count += 1
        if pressures:
            pressure_count += 1
        os_image = info.get("osImage") or "unknown"
        kernel = info.get("kernelVersion") or "unknown"
        runtime = info.get("containerRuntimeVersion") or "unknown"
        os_images.add(os_image)
        kernels.add(kernel)
        runtimes.add(runtime)
        rows.append(
            {
                "name": item.get("name"),
                "observed": item.get("timestamp"),
                "ready": ready,
                "os_image": os_image,
                "kernel": kernel,
                "runtime": runtime,
                "kubelet": info.get("kubeletVersion") or "unknown",
                "capacity_cpu": (status.get("capacity") or {}).get("cpu") or "-",
                "allocatable_cpu": (status.get("allocatable") or {}).get("cpu") or "-",
                "capacity_memory": (status.get("capacity") or {}).get("memory") or "-",
                "allocatable_memory": (status.get("allocatable") or {}).get("memory") or "-",
                "pressures": ", ".join(pressures) if pressures else "none",
                "taints": len(spec.get("taints") or []),
            }
        )
    return {
        "total": len(rows),
        "ready": ready_count,
        "pressure": pressure_count,
        "os_images": sorted(os_images),
        "kernels": sorted(kernels),
        "runtimes": sorted(runtimes),
        "rows": rows,
    }


def _storage_network_summary(observations: dict[str, list[dict]]) -> dict:
    pvs = observations.get("PersistentVolume", [])
    pvcs = observations.get("PersistentVolumeClaim", [])
    storage_classes = observations.get("StorageClass", [])
    csi_drivers = observations.get("CSIDriver", [])
    csi_nodes = observations.get("CSINode", [])
    csi_capacity = observations.get("CSIStorageCapacity", [])
    cni_components = observations.get("CNIComponent", [])
    nads = observations.get("NetworkAttachmentDefinition", [])

    def phase(item: dict) -> str:
        raw = item.get("raw") if isinstance(item.get("raw"), dict) else {}
        return ((raw.get("status") or {}).get("phase") or "").strip()

    pv_problem = [item for item in pvs if phase(item) in {"Released", "Failed"}]
    pvc_problem = [item for item in pvcs if phase(item) in {"Pending", "Lost"}]
    cni_degraded = [item for item in cni_components if (item.get("raw") or {}).get("status") in {"Degraded", "Unknown"}]
    return {
        "storage_classes": len(storage_classes),
        "pvs": len(pvs),
        "pvcs": len(pvcs),
        "pv_problem": len(pv_problem),
        "pvc_problem": len(pvc_problem),
        "csi_drivers": len(csi_drivers),
        "csi_nodes": len(csi_nodes),
        "csi_capacity": len(csi_capacity),
        "cni_components": cni_components,
        "cni_degraded": len(cni_degraded),
        "network_attachments": len(nads),
        "storage_classes_rows": storage_classes[:20],
        "csi_driver_rows": csi_drivers[:20],
    }


def _decode_finding_payloads(findings: list[dict]) -> list[dict]:
    rows = []
    for finding in findings:
        item = dict(finding)
        item["evidence_obj"] = loads(item.get("evidence"), item.get("evidence"))
        rows.append(item)
    return rows


def _cni_detail_rows(raw_items: list[dict], display_items: list[dict]) -> list[dict]:
    rows = []
    for raw_item, display_item in zip(raw_items, display_items):
        raw = raw_item.get("raw") if isinstance(raw_item.get("raw"), dict) else {}
        rows.append(
            {
                "name": display_item.get("name"),
                "status": display_item.get("status") or raw.get("status") or "unknown",
                "provider": raw.get("provider") or "-",
                "pods_ready": raw.get("pods_ready"),
                "pods_total": raw.get("pods_total"),
                "daemonsets": raw.get("daemonsets") or [],
                "reason": "One or more CNI pods/daemonsets are not ready"
                if raw.get("status") == "Degraded"
                else "CNI provider could not be detected"
                if raw.get("status") == "Unknown"
                else "Detected CNI components are ready",
                "timestamp": display_item.get("timestamp"),
            }
        )
    return rows


def _problem_pvc_rows(raw_items: list[dict], display_items: list[dict]) -> list[dict]:
    rows = []
    for raw_item, display_item in zip(raw_items, display_items):
        raw = raw_item.get("raw") if isinstance(raw_item.get("raw"), dict) else {}
        phase = ((raw.get("status") or {}).get("phase") or "").strip()
        if phase in {"Pending", "Lost"}:
            rows.append(
                {
                    "namespace": display_item.get("namespace"),
                    "name": display_item.get("name"),
                    "status": phase,
                    "storage_class": (raw.get("spec") or {}).get("storageClassName") or "-",
                    "timestamp": display_item.get("timestamp"),
                }
            )
    return rows


def _pod_inventory_rows(raw_items: list[dict], display_items: list[dict], anonymized: bool, salt: str = "") -> list[dict]:
    rows = []
    for raw_item, display_item in zip(raw_items, display_items):
        inventory = ((raw_item.get("raw") or {}).get("auditPodInventory") or {})
        rows.append(
            {
                "namespace": display_item.get("namespace") or "-",
                "name": display_item.get("name") or "-",
                "event_type": raw_item.get("event_type") or "CURRENT",
                "ready": inventory.get("ready") or "-",
                "status": inventory.get("status") or "-",
                "restarts": inventory.get("restarts", 0),
                "pod_ip": anonymize_ip(inventory.get("pod_ip") or "-", salt) if anonymized else inventory.get("pod_ip") or "-",
                "node": scrub_text(inventory.get("node") or "-", salt) if anonymized else inventory.get("node") or "-",
                "nominated_node": scrub_text(inventory.get("nominated_node") or "-", salt) if anonymized else inventory.get("nominated_node") or "-",
                "readiness_gates": inventory.get("readiness_gates") or "-",
                "qos": inventory.get("qos") or "-",
                "cpu_usage": inventory.get("cpu_usage") or "-",
                "cpu_limit": inventory.get("cpu_limit") or "-",
                "cpu_limit_pct": inventory.get("cpu_limit_pct"),
                "memory_usage": inventory.get("memory_usage") or "-",
                "memory_limit": inventory.get("memory_limit") or "-",
                "memory_limit_pct": inventory.get("memory_limit_pct"),
                "ephemeral_storage_limit": inventory.get("ephemeral_storage_limit") or "-",
                "disk_usage": inventory.get("disk_usage") or "unavailable",
                "observed": display_item.get("timestamp"),
            }
        )
    return rows


def _platform_status_rows(raw_items: list[dict], display_items: list[dict], resource_type: str) -> list[dict]:
    """Turn OpenShift condition arrays into a concise operational status."""
    rows = []
    for raw_item, display_item in zip(raw_items, display_items):
        status = (raw_item.get("raw") or {}).get("status") or {}
        conditions = status.get("conditions") or []
        by_type = {str(item.get("type") or ""): str(item.get("status") or "Unknown") for item in conditions}
        degraded = by_type.get("Degraded") == "True" or by_type.get("Failing") == "True"
        progressing = by_type.get("Progressing") == "True" or by_type.get("Updating") == "True"
        healthy = by_type.get("Available") == "True" or by_type.get("Updated") == "True"
        if degraded:
            state, state_class = "Degraded", "degraded"
        elif progressing:
            state, state_class = "Progressing", "progressing"
        elif healthy:
            state, state_class = "Healthy", "healthy"
        else:
            state, state_class = "Unknown", "unknown"
        evidence = []
        for condition in conditions:
            condition_type = condition.get("type") or "Condition"
            condition_status = condition.get("status") or "Unknown"
            reason = condition.get("reason") or ""
            message = condition.get("message") or ""
            transition = condition.get("lastTransitionTime") or ""
            detail = " — ".join(part for part in (reason, message) if part)
            evidence.append(f"{condition_type}={condition_status}" + (f": {detail}" if detail else "") + (f" ({transition})" if transition else ""))
        rows.append(
            {
                "name": display_item.get("name") or "-",
                "state": state,
                "state_class": state_class,
                "evidence": "\n".join(evidence) or "No status conditions reported by the API.",
                "timestamp": display_item.get("timestamp"),
                "resource_type": resource_type,
            }
        )
    return rows


def _clean_filter_values(values: dict[str, str | None], allowed: tuple[str, ...]) -> dict[str, str]:
    return {key: str(values.get(key)).strip() for key in allowed if values.get(key) not in (None, "") and str(values.get(key)).strip()}


def _filter_url(path: str, filters: dict[str, str]) -> str:
    query = urlencode(filters)
    return f"{path}?{query}" if query else path


PAGE_SIZE = 50


def _pagination(path: str, requested_page: int, total: int, filters: dict[str, str]) -> dict:
    pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    page = max(1, min(requested_page, pages))

    def page_url(number: int) -> str:
        return _filter_url(path, {**filters, "page": str(number)})

    return {
        "page": page,
        "pages": pages,
        "total": total,
        "offset": (page - 1) * PAGE_SIZE,
        "start": 0 if total == 0 else (page - 1) * PAGE_SIZE + 1,
        "end": min(page * PAGE_SIZE, total),
        "first_url": page_url(1),
        "previous_url": page_url(page - 1) if page > 1 else None,
        "next_url": page_url(page + 1) if page < pages else None,
        "last_url": page_url(pages),
    }


def _report_job_values(form: dict[str, str], allow_raw: bool) -> tuple[str, bool]:
    fmt = form.get("fmt", "html")
    requested_anonymization = form.get("anonymize", "true").lower() in {"true", "1", "yes", "on"}
    return fmt, requested_anonymization if allow_raw else True


def _report_format(job: dict, report: dict | None) -> str:
    if report and report.get("format"):
        return str(report["format"]).upper()
    message = str(job.get("message") or "").lower()
    for fmt in ("html", "markdown", "json", "pdf"):
        if fmt in message:
            return fmt.upper()
    return "—"


def _report_table_rows(report_jobs: list[dict], reports: list[dict]) -> list[dict]:
    reports_by_id = {int(item["id"]): item for item in reports}
    linked_report_ids: set[int] = set()
    rows = []
    for job in report_jobs:
        report_id = int(job["report_id"]) if job.get("report_id") is not None else None
        report = reports_by_id.get(report_id) if report_id is not None else None
        if report_id is not None:
            linked_report_ids.add(report_id)
        rows.append(
            {
                "job_id": job.get("id"),
                "report_id": report_id,
                "format": _report_format(job, report),
                "status": job.get("status") or "unknown",
                "started_at": job.get("started_at"),
                "finished_at": job.get("finished_at"),
                "path": report.get("path") if report else None,
                "size_bytes": report.get("size_bytes") if report else None,
                "message": job.get("message"),
                "error": job.get("error"),
                "_sort_at": job.get("started_at") or "",
            }
        )
    for report in reports:
        report_id = int(report["id"])
        if report_id in linked_report_ids:
            continue
        rows.append(
            {
                "job_id": None,
                "report_id": report_id,
                "format": str(report.get("format") or "—").upper(),
                "status": "success",
                "started_at": report.get("created_at"),
                "finished_at": report.get("created_at"),
                "path": report.get("path"),
                "size_bytes": report.get("size_bytes"),
                "message": "Report generated outside the WebUI job queue",
                "error": None,
                "_sort_at": report.get("created_at") or "",
            }
        )
    rows.sort(key=lambda item: item["_sort_at"], reverse=True)
    for row in rows:
        row.pop("_sort_at", None)
    return rows


async def _urlencoded_form(request: Request) -> dict[str, str]:
    body = (await request.body()).decode()
    parsed = parse_qs(body, keep_blank_values=True)
    return {key: values[-1] if values else "" for key, values in parsed.items()}


def create_app(settings: Settings, repo: AuditRepository | None = None, bus: EventBus | None = None) -> FastAPI:
    db = Database(settings.db_path, settings.database_url, settings.database_password)
    db.init()
    repo = repo or AuditRepository(db)
    bus = bus or EventBus(settings.event_buffer_size)
    app = FastAPI(
        title="ocp-audit-agent",
        docs_url="/docs" if settings.web_expose_docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.web_expose_docs else None,
    )

    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        return _security_headers(await call_next(request))
    base = Path(__file__).parent
    templates = Jinja2Templates(directory=str(base / "templates"))
    templates.env.filters["json"] = lambda value: json.dumps(value, ensure_ascii=False, default=str)
    templates.env.filters["urlencode"] = lambda value: urlencode(value or {})
    app.mount("/static", StaticFiles(directory=str(base / "static")), name="static")
    app.include_router(create_api(repo, settings, bus))

    def ctx(request: Request, **extra):
        anonymized = effective_anonymization(request, settings)
        data = {
            "request": request,
            "summary": extra.get("summary") if "summary" in extra else repo.summary(),
            "anonymized": anonymized,
            "allow_ui_deanonymize": settings.allow_ui_deanonymize,
            "anonymization_forced": anonymized and not settings.allow_ui_deanonymize,
        }
        data.update(extra)
        return data

    def maybe_findings(request: Request, items):
        return anonymize_findings(items, settings.anonymization_salt) if effective_anonymization(request, settings) else items

    def maybe_presented_findings(request: Request, items):
        prepared = prepare_findings(
            items,
            observations=repo.list_observations(50000, kinds=WORKLOAD_OBSERVATION_KINDS),
        )
        return anonymize_findings(prepared, settings.anonymization_salt) if effective_anonymization(request, settings) else prepared

    def maybe_observations(request: Request, items):
        return anonymize_observations(items, settings.anonymization_salt) if effective_anonymization(request, settings) else items

    @app.post("/ui/anonymization")
    def ui_anonymization(request: Request, enabled: str = "true", next: str = "/"):
        wants_raw = enabled.lower() == "false"
        if wants_raw and not settings.allow_ui_deanonymize:
            enabled = "true"
        response = RedirectResponse(next if next.startswith("/") else "/", status_code=303)
        response.set_cookie(COOKIE_NAME, "false" if enabled.lower() == "false" else "true", httponly=True, samesite="lax")
        return response

    @app.get("/anonymization", response_class=HTMLResponse)
    def anonymization_settings(request: Request):
        return templates.TemplateResponse(
            name="anonymization.html",
            request=request,
            context=ctx(request, terms=load_terms(settings.data_dir)),
        )

    @app.post("/anonymization")
    async def save_anonymization_settings(request: Request):
        form = await _urlencoded_form(request)
        # One term per line makes phrases and copied customer naming fragments unambiguous.
        terms = save_terms(form.get("terms", "").splitlines(), settings.data_dir)
        return RedirectResponse("/anonymization", status_code=303)

    @app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request):
        repository_summary = repo.summary()
        temporal_sources = (
            repo.list_findings(title=LOG_FINDING_TITLE, limit=2000)
            + repo.list_findings(title=RESTART_FINDING_TITLE, limit=2000)
        )
        priority_sources = (
            repo.list_findings(severity="Critical", limit=100)
            + repo.list_findings(severity="High", limit=100)
        )
        dashboard_sources = {
            str(item.get("fingerprint") or id(item)): item
            for item in temporal_sources + priority_sources
        }
        dashboard_findings = maybe_presented_findings(request, list(dashboard_sources.values()))
        temporal_findings = [
            item
            for item in dashboard_findings
            if item.get("title") in {LOG_FINDING_TITLE, RESTART_FINDING_TITLE}
        ]
        temporal_view = build_audit_view(temporal_findings, repository_summary["events_last_hour"])
        noncurrent_temporal = temporal_view["review_findings"] + temporal_view["historical_findings"]
        severity_counts = dict(repository_summary["findings_by_severity"])
        category_counts = repo.finding_counts_by_category()
        for item in noncurrent_temporal:
            severity = str(item.get("severity") or "Info")
            category = str(item.get("category") or "unknown")
            severity_counts[severity] = max(0, int(severity_counts.get(severity, 0)) - 1)
            category_counts[category] = max(0, int(category_counts.get(category, 0)) - 1)
        total_findings = sum(int(value) for value in repository_summary["findings_by_severity"].values())
        dashboard_summary = {
            "current_findings": max(0, total_findings - len(noncurrent_temporal)),
            "review_findings": len(temporal_view["review_findings"]),
            "historical_findings": len(temporal_view["historical_findings"]),
            "findings_by_severity": severity_counts,
            "problematic_pods": repository_summary["problematic_pods"],
            "events_last_hour": repository_summary["events_last_hour"],
            "current_incidents": len(temporal_view["current_incidents"]),
        }
        priority_view = build_audit_view(dashboard_findings, repository_summary["events_last_hour"])
        raw_nodes = repo.latest_observations("Node", 200)
        node_host_os = _host_os_summary(raw_nodes)
        display_nodes = maybe_observations(request, raw_nodes)
        for row, display in zip(node_host_os["rows"], display_nodes):
            row["name"] = display.get("name")
        infra_observations = {
            kind: repo.latest_observations(kind, 300)
            for kind in (
                "PersistentVolume",
                "PersistentVolumeClaim",
                "StorageClass",
                "CSIDriver",
                "CSINode",
                "CSIStorageCapacity",
                "CNIComponent",
                "NetworkAttachmentDefinition",
            )
        }
        infra_summary = _storage_network_summary(infra_observations)
        display_cni = maybe_observations(request, infra_summary["cni_components"])
        display_storage_classes = maybe_observations(request, infra_summary["storage_classes_rows"])
        display_csi_drivers = maybe_observations(request, infra_summary["csi_driver_rows"])
        latest_snapshot = repo.latest_snapshot_summary()
        coverage = latest_snapshot.get("coverage") or {}
        audit_coverage = {
            "checked": sum(1 for item in coverage.values() if item.get("status") == "CHECKED"),
            "errors": sum(1 for item in coverage.values() if item.get("status") == "ERROR"),
            "not_applicable": sum(1 for item in coverage.values() if item.get("status") == "NOT_APPLICABLE"),
            "inventory_only": sum(1 for item in coverage.values() if item.get("status") == "CHECKED" and not item.get("rules")),
            "not_checked": latest_snapshot.get("not_checked") or [],
            "snapshot_status": latest_snapshot.get("status") or "not-run",
        }
        return templates.TemplateResponse(
            name="dashboard.html",
            request=request,
            context=ctx(
                request,
                summary=dashboard_summary,
                priority_findings=[item for item in priority_view["current_findings"] if item.get("severity") in {"Critical", "High"}][:12],
                incidents=temporal_view["incidents"][:8],
                category_counts=[item for item in category_counts.items() if item[1] > 0][:8],
                operators=_platform_status_rows(
                    repo.latest_observations("ClusterOperator", 50),
                    maybe_observations(request, repo.latest_observations("ClusterOperator", 50)),
                    "ClusterOperator",
                ),
                versions=_platform_status_rows(
                    repo.latest_observations("ClusterVersion", 5),
                    maybe_observations(request, repo.latest_observations("ClusterVersion", 5)),
                    "ClusterVersion",
                ),
                mcps=_platform_status_rows(
                    repo.latest_observations("MachineConfigPool", 20),
                    maybe_observations(request, repo.latest_observations("MachineConfigPool", 20)),
                    "MachineConfigPool",
                ),
                node_host_os=node_host_os,
                infra_summary=infra_summary,
                cni_components=display_cni,
                cni_findings=_decode_finding_payloads(maybe_findings(request, repo.list_findings(category="networking", resource_kind="CNIComponent", limit=10))),
                storage_classes=display_storage_classes,
                csi_drivers=display_csi_drivers,
                audit_coverage=audit_coverage,
            ),
        )

    @app.get("/drilldown", response_class=HTMLResponse)
    def drilldown(request: Request):
        anonymized = effective_anonymization(request, settings)
        drilldown_findings = maybe_presented_findings(request, repo.list_findings(limit=10000))
        audit_view = build_audit_view(drilldown_findings, repo.summary()["events_last_hour"])
        current_findings = audit_view["current_findings"]
        raw_nodes = repo.latest_observations("Node", 200)
        node_host_os = _host_os_summary(raw_nodes)
        display_nodes = maybe_observations(request, raw_nodes)
        for row, display in zip(node_host_os["rows"], display_nodes):
            row["name"] = display.get("name")
        infra_observations = {
            kind: repo.latest_observations(kind, 300)
            for kind in (
                "PersistentVolume",
                "PersistentVolumeClaim",
                "StorageClass",
                "CSIDriver",
                "CSINode",
                "CSIStorageCapacity",
                "CNIComponent",
                "NetworkAttachmentDefinition",
            )
        }
        infra_summary = _storage_network_summary(infra_observations)
        display_cni = maybe_observations(request, infra_summary["cni_components"])
        display_csi_drivers = maybe_observations(request, infra_summary["csi_driver_rows"])
        display_pvcs = maybe_observations(request, infra_observations["PersistentVolumeClaim"])
        recent_events = repo.list_events(limit=50)
        if anonymized:
            recent_events = anonymize_events(recent_events, settings.anonymization_salt)
        severity_details = {severity: [item for item in current_findings if item.get("severity") == severity][:50] for severity in ("Critical", "High", "Medium", "Low", "Info")}
        return templates.TemplateResponse(
            name="drilldown.html",
            request=request,
            context=ctx(
                request,
                summary=audit_view["summary"],
                node_host_os=node_host_os,
                infra_summary=infra_summary,
                csi_drivers=display_csi_drivers,
                drilldowns={
                    "recent_events": recent_events,
                    "problem_pods": [
                        item
                        for item in current_findings
                        if item.get("resource_kind") == "Pod"
                        or item.get("grouped_pod_finding")
                        or item.get("pod_profile_drift")
                        or item.get("pod_configuration_drift")
                    ][:50],
                    "node_findings": [item for item in current_findings if item.get("category") == "node-health"][:50],
                    "cni_findings": [item for item in current_findings if item.get("category") == "networking" and item.get("resource_kind") == "CNIComponent"][:50],
                    "storage_findings": [item for item in current_findings if item.get("category") == "storage"][:50],
                    "cni_rows": _cni_detail_rows(infra_summary["cni_components"], display_cni),
                    "problem_pvcs": _problem_pvc_rows(infra_observations["PersistentVolumeClaim"], display_pvcs),
                    "severity": severity_details,
                },
            ),
        )

    @app.get("/pods", response_class=HTMLResponse)
    def pods(request: Request, namespace: str | None = None, name: str | None = None, event_type: str | None = None, history: str = "false", page: int = 1):
        history_enabled = history.lower() in {"1", "true", "yes"}
        filters = _clean_filter_values({"namespace": namespace, "name": name, "event_type": event_type}, ("namespace", "name", "event_type"))
        page_filters = {**filters, "history": "true" if history_enabled else "false"}
        if history_enabled:
            total = repo.count_pod_history(**filters)
            pagination = _pagination("/pods", page, total, page_filters)
            raw_pods = repo.list_pod_history(PAGE_SIZE, offset=pagination["offset"], **filters)
        else:
            total = repo.count_observations("Pod", namespace=filters.get("namespace"), name=filters.get("name"))
            pagination = _pagination("/pods", page, total, page_filters)
            raw_pods = repo.latest_observations(
                "Pod",
                PAGE_SIZE,
                offset=pagination["offset"],
                namespace=filters.get("namespace"),
                name=filters.get("name"),
            )
        anonymized = effective_anonymization(request, settings)
        display_pods = maybe_observations(request, raw_pods)
        return templates.TemplateResponse(
            name="pods.html",
            request=request,
            context=ctx(request, pods=_pod_inventory_rows(raw_pods, display_pods, anonymized, settings.anonymization_salt), pod_count=total, pagination=pagination, filters=page_filters, filter_options=repo.pod_filter_options(), saved_filters=repo.list_saved_filters("pods")),
        )

    @app.post("/pods/filters")
    async def save_pod_filter(request: Request):
        form = await _urlencoded_form(request)
        name = form.get("filter_name", "").strip()
        filters = _clean_filter_values(form, ("namespace", "name", "event_type", "history"))
        if name and filters:
            repo.save_filter("pods", name, filters)
        return RedirectResponse(_filter_url("/pods", filters), status_code=303)

    @app.post("/pods/filters/{filter_id}/delete")
    def delete_pod_filter(filter_id: int):
        repo.delete_saved_filter(filter_id, "pods")
        return RedirectResponse("/pods", status_code=303)

    @app.get("/history", response_class=HTMLResponse)
    def history(request: Request, namespace: str | None = None, event_type: str | None = None, name: str | None = None, page: int = 1):
        filters = _clean_filter_values(
            {"namespace": namespace, "event_type": event_type, "name": name},
            ("namespace", "event_type", "name"),
        )
        total = repo.count_pod_history(**filters)
        pagination = _pagination("/history", page, total, filters)
        items = repo.list_pod_history(limit=PAGE_SIZE, offset=pagination["offset"], **filters)
        return templates.TemplateResponse(
            name="history.html",
            request=request,
            context=ctx(
                request,
                history=maybe_observations(request, items),
                history_count=total,
                pagination=pagination,
                filters=filters,
                filter_options=repo.resource_history_filter_options(),
            ),
        )

    @app.get("/events", response_class=HTMLResponse)
    def events(request: Request, namespace: str | None = None, reason: str | None = None, type: str | None = None, involved_kind: str | None = None, kind: str | None = None, severity: str | None = None, page: int = 1):
        from app.audit.anonymization import anonymize_events

        involved_kind = involved_kind or kind
        filters = _clean_filter_values(
            {"namespace": namespace, "reason": reason, "type": type, "involved_kind": involved_kind, "severity": severity},
            ("namespace", "reason", "type", "involved_kind", "severity"),
        )
        total = repo.count_events(**filters)
        pagination = _pagination("/events", page, total, filters)
        events_data = repo.list_events(PAGE_SIZE, offset=pagination["offset"], **filters)
        if effective_anonymization(request, settings):
            events_data = anonymize_events(events_data, settings.anonymization_salt)
        return templates.TemplateResponse(
            name="events.html",
            request=request,
            context=ctx(
                request,
                events=events_data,
                pagination=pagination,
                live_events=pagination["page"] == 1 and not filters,
                filters=filters,
                filter_options=repo.event_filter_options(),
                saved_filters=repo.list_saved_filters("events"),
            ),
        )

    @app.post("/events/filters")
    async def save_event_filter(request: Request):
        form = await _urlencoded_form(request)
        name = form.get("filter_name", "").strip()
        filters = _clean_filter_values(form, ("namespace", "reason", "type", "involved_kind", "severity"))
        if name and filters:
            repo.save_filter("events", name, filters)
        return RedirectResponse(_filter_url("/events", filters), status_code=303)

    @app.post("/events/filters/{filter_id}/delete")
    def delete_event_filter(filter_id: int):
        repo.delete_saved_filter(filter_id, "events")
        return RedirectResponse("/events", status_code=303)

    @app.get("/findings", response_class=HTMLResponse)
    def findings(request: Request, severity: str | None = None, category: str | None = None, namespace: str | None = None, resource_kind: str | None = None, kind: str | None = None, page: int = 1):
        resource_kind = resource_kind or kind
        filters = _clean_filter_values(
            {"severity": severity, "category": category, "namespace": namespace, "resource_kind": resource_kind},
            ("severity", "category", "namespace", "resource_kind"),
        )
        total = repo.count_findings(**filters)
        pagination = _pagination("/findings", page, total, filters)
        display_findings = maybe_presented_findings(
            request,
            repo.list_findings(limit=PAGE_SIZE, offset=pagination["offset"], **filters),
        )[:PAGE_SIZE]
        filter_options = repo.finding_filter_options()
        return templates.TemplateResponse(
            name="findings.html",
            request=request,
            context=ctx(
                request,
                findings=display_findings,
                pagination=pagination,
                filters=filters,
                filter_options=filter_options,
                saved_filters=repo.list_saved_filters("findings"),
            ),
        )

    @app.post("/findings/filters")
    async def save_finding_filter(request: Request):
        form = await _urlencoded_form(request)
        name = form.get("filter_name", "").strip()
        filters = _clean_filter_values(form, ("severity", "category", "namespace", "resource_kind"))
        if name and filters:
            repo.save_filter("findings", name, filters)
        return RedirectResponse(_filter_url("/findings", filters), status_code=303)

    @app.post("/findings/filters/{filter_id}/delete")
    def delete_finding_filter(filter_id: int):
        repo.delete_saved_filter(filter_id, "findings")
        return RedirectResponse("/findings", status_code=303)

    @app.get("/jobs", response_class=HTMLResponse)
    def jobs(request: Request):
        items = repo.list_jobs()
        if effective_anonymization(request, settings):
            items = anonymize_operational_records(items, settings.anonymization_salt)
        return templates.TemplateResponse(
            name="jobs.html",
            request=request,
            context=ctx(
                request,
                jobs=items,
                jobs_running=any(item.get("status") == "running" for item in items),
            ),
        )

    @app.post("/jobs/snapshot")
    def ui_snapshot(background: BackgroundTasks):
        background.add_task(run_snapshot_job, repo, settings)
        return RedirectResponse("/jobs", status_code=303)

    @app.post("/jobs/report")
    async def ui_report(request: Request, background: BackgroundTasks):
        form = await _urlencoded_form(request)
        fmt, report_anonymized = _report_job_values(form, settings.allow_ui_deanonymize)
        job_id = repo.create_job_if_not_running("report", f"Generating {fmt.upper()} report")
        if job_id is not None:
            background.add_task(run_report_job, repo, settings, fmt, report_anonymized, job_id)
        return RedirectResponse("/reports?report_running=true" if job_id is None else "/reports", status_code=303)

    @app.post("/jobs/cleanup")
    def ui_cleanup(background: BackgroundTasks):
        background.add_task(run_cleanup_job, repo, settings)
        return RedirectResponse("/jobs", status_code=303)

    @app.get("/reports", response_class=HTMLResponse)
    def reports(request: Request, report_running: bool = False):
        items = repo.list_reports()
        report_jobs = [item for item in repo.list_jobs(limit=1000) if item.get("job_type") == "report"][:100]
        if effective_anonymization(request, settings):
            items = anonymize_operational_records(items, settings.anonymization_salt)
            report_jobs = anonymize_operational_records(report_jobs, settings.anonymization_salt)
        return templates.TemplateResponse(
            name="reports.html",
            request=request,
            context=ctx(
                request,
                report_rows=_report_table_rows(report_jobs, items),
                report_anonymized=effective_anonymization(request, settings),
                report_running=report_running,
                report_jobs_running=any(item.get("status") == "running" for item in report_jobs),
            ),
        )

    return app

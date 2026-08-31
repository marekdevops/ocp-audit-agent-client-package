from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from typing import Any, AsyncIterator

from kubernetes import client, watch
from kubernetes.client import ApiException

from app.audit.rules import evaluate_event, evaluate_object, is_negative_event, map_event_severity
from app.kube.discovery import has_resource
from app.storage.repositories import AuditRepository
from app.utils.time import iso_now

LOG = logging.getLogger(__name__)


class EventBus:
    def __init__(self, maxlen: int = 500) -> None:
        self.buffer: deque[dict[str, Any]] = deque(maxlen=maxlen)
        self.queues: set[asyncio.Queue] = set()

    def publish(self, event: dict[str, Any]) -> None:
        self.buffer.append(event)
        for queue in list(self.queues):
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                pass

    async def stream(self) -> AsyncIterator[dict[str, Any]]:
        queue: asyncio.Queue = asyncio.Queue(maxsize=100)
        self.queues.add(queue)
        try:
            for event in list(self.buffer):
                yield event
            while True:
                yield await queue.get()
        finally:
            self.queues.discard(queue)


def _dict(obj: Any) -> dict[str, Any]:
    return client.ApiClient().sanitize_for_serialization(obj)


def _save_k8s_event(repo: AuditRepository, cluster: str, obj: dict[str, Any], bus: EventBus | None) -> None:
    if not is_negative_event(obj):
        return
    meta = obj.get("metadata") or {}
    involved = obj.get("involvedObject") or obj.get("regarding") or {}
    event = {
        "uid": meta.get("uid"),
        "cluster_name": cluster,
        "timestamp": obj.get("eventTime") or obj.get("lastTimestamp") or obj.get("firstTimestamp") or iso_now(),
        "namespace": involved.get("namespace") or meta.get("namespace"),
        "reason": obj.get("reason"),
        "type": obj.get("type"),
        "message": obj.get("message"),
        "involved_kind": involved.get("kind"),
        "involved_name": involved.get("name"),
        "source_component": (obj.get("source") or {}).get("component") or obj.get("reportingComponent"),
        "severity": map_event_severity(obj),
        "raw_json": obj,
    }
    repo.add_event(event)
    for finding in evaluate_event(obj):
        repo.upsert_finding(finding.to_record(cluster))
    if bus:
        bus.publish(event)


def _save_observed(repo: AuditRepository, cluster: str, kind: str, obj: dict[str, Any], event_type: str | None = None) -> None:
    meta = obj.get("metadata") or {}
    repo.add_observation(
        {
            "cluster_name": cluster,
            "timestamp": iso_now(),
            "api_version": obj.get("apiVersion"),
            "kind": kind,
            "namespace": meta.get("namespace"),
            "name": meta.get("name"),
            "status": str(obj.get("status"))[:500],
            "raw_json": obj,
        },
        preserve_audit_inventory=kind == "Pod",
        pod_event_type=event_type,
    )
    if event_type == "DELETED":
        repo.deactivate_findings_for_resource(cluster, kind, meta.get("namespace"), meta.get("name"))
        return
    for finding in evaluate_object(kind, obj):
        repo.upsert_finding(finding.to_record(cluster))


def watch_forever(repo: AuditRepository, cluster: str, bus: EventBus | None = None, enable_openshift: bool = True) -> None:
    targets = [
        ("Event", lambda: client.CoreV1Api().list_event_for_all_namespaces),
        ("Pod", lambda: client.CoreV1Api().list_pod_for_all_namespaces),
        ("Node", lambda: client.CoreV1Api().list_node),
    ]
    if enable_openshift:
        openshift_targets = [
            ("ClusterVersion", "config.openshift.io/v1", "clusterversions", lambda: lambda **kw: client.CustomObjectsApi().list_cluster_custom_object("config.openshift.io", "v1", "clusterversions", **kw)),
            ("ClusterOperator", "config.openshift.io/v1", "clusteroperators", lambda: lambda **kw: client.CustomObjectsApi().list_cluster_custom_object("config.openshift.io", "v1", "clusteroperators", **kw)),
            ("MachineConfigPool", "machineconfiguration.openshift.io/v1", "machineconfigpools", lambda: lambda **kw: client.CustomObjectsApi().list_cluster_custom_object("machineconfiguration.openshift.io", "v1", "machineconfigpools", **kw)),
        ]
        targets.extend((kind, factory) for kind, group_version, plural, factory in openshift_targets if has_resource(group_version, plural))

    def run_target(kind: str, func_factory) -> None:
        backoff = 1
        while True:
            w = watch.Watch()
            try:
                LOG.info("starting watch for %s", kind)
                for item in w.stream(func_factory(), timeout_seconds=300):
                    obj = _dict(item["object"])
                    if kind == "Event":
                        _save_k8s_event(repo, cluster, obj, bus)
                    else:
                        _save_observed(repo, cluster, kind, obj, item.get("type"))
                    backoff = 1
            except ApiException as exc:
                if exc.status == 410:
                    LOG.warning("watch %s resourceVersion expired, reconnecting", kind)
                    backoff = 1
                else:
                    LOG.warning("watch %s API error: status=%s reason=%s", kind, exc.status, exc.reason)
                    time.sleep(backoff)
                    backoff = min(backoff * 2, 60)
            except Exception as exc:
                LOG.warning("watch %s failed: %s", kind, exc)
                time.sleep(backoff)
                backoff = min(backoff * 2, 60)

    import threading

    threads = [threading.Thread(target=run_target, args=(kind, factory), daemon=True) for kind, factory in targets]
    for thread in threads:
        thread.start()
    while True:
        time.sleep(3600)

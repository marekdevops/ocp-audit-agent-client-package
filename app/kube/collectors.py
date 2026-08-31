from __future__ import annotations

import ast
import logging
import re
from typing import Any, Callable

from kubernetes import client
from kubernetes.client import ApiException

from app.audit.rules import evaluate_cluster_inventory, evaluate_namespace_policies, evaluate_object, evaluate_event, is_negative_event, map_event_severity
from app.audit.redaction import redact_text
from app.kube.discovery import has_resource, list_custom
from app.kube.openshift import OPENSHIFT_CLUSTER_RESOURCES
from app.storage.repositories import AuditRepository
from app.utils.time import iso_now, parse_time, utcnow

LOG = logging.getLogger(__name__)

EVALUATED_KINDS = {
    "Pod", "Node", "Namespace", "Service", "Endpoints", "EndpointSlice", "NetworkPolicy",
    "ResourceQuota", "LimitRange", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "ReplicationController", "Job", "CronJob",
    "ServiceAccount", "ConfigMap", "Secret", "StorageClass", "CSIDriver", "CSINode",
    "CSIStorageCapacity", "CNIComponent", "NetworkAttachmentDefinition", "PodDisruptionBudget",
    "Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding", "ClusterOperator", "ClusterVersion",
    "MachineConfigPool", "ClusterServiceVersion", "Subscription", "InstallPlan", "Route",
    "IngressController", "Authentication", "Proxy", "SecurityContextConstraints",
    "APIServer", "KubeAPIServer", "KubeControllerManager", "KubeScheduler", "Etcd",
    "CatalogSource", "Machine", "MachineSet", "MachineHealthCheck",
    "PersistentVolumeClaim", "PersistentVolume", "Ingress", "HorizontalPodAutoscaler",
    "ValidatingWebhookConfiguration", "MutatingWebhookConfiguration", "APIService",
    "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding", "VolumeAttachment",
    "VolumeSnapshot", "VolumeSnapshotContent", "PriorityClass", "CertificateSigningRequest",
    "CustomResourceDefinition", "NodeMetrics",
    "ComplianceCheckResult", "PolicyReport", "ClusterPolicyReport", "VulnerabilityReport",
}

# These are the only complete inventories needed after their individual
# objects have been evaluated. Retaining every collected kind until the end of
# a snapshot made peak memory proportional to the entire cluster inventory.
INVENTORY_RESOURCE_KINDS = {"Node", "NodeMetrics", "Service", "Endpoints", "EndpointSlice"}

API_ONLY_LIMITATIONS = [
    "Host filesystem permissions, sysctl and process flags require an optional host-level collector.",
    "Encryption-at-rest configuration cannot be proven from ordinary read-only Kubernetes APIs.",
    "Etcd backup integrity and restore success require access to the distribution backup system.",
    "Image vulnerabilities, signatures and SBOM require an external registry/scanner integration.",
    "API audit-policy contents and audit-log forwarding require distribution-specific configuration or host access.",
]

LOG_PATTERNS: tuple[tuple[str, tuple[re.Pattern[str], ...]], ...] = (
    ("oom_or_memory", (re.compile(r"\boomkilled\b|\bout of memory\b|cannot allocate memory|memory cgroup out of memory", re.I),)),
    ("application_exception", (re.compile(r"\bexception\b|\btraceback\b|\bpanic(?:ked)?\b|\bfatal\b|segmentation fault", re.I),)),
    ("permission_or_policy", (re.compile(r"permission denied|\bforbidden\b|\bunauthorized\b|operation not permitted|access denied", re.I),)),
    ("network_connectivity", (re.compile(r"connection (?:refused|reset)|no route to host|network is unreachable|i/o timeout|context deadline exceeded|timed out (?:connecting|waiting)|timeout (?:connecting|waiting)", re.I),)),
    ("dns_resolution", (re.compile(r"no such host|temporary failure in name resolution|name or service not known|server misbehaving", re.I),)),
    ("certificate_or_tls", (re.compile(r"x509:|certificate (?:has expired|is expired|verify failed|signed by unknown)|tls handshake (?:error|failed)|ssl handshake (?:error|failed)", re.I),)),
    ("storage_or_filesystem", (re.compile(r"no space left|read-only file system|input/output error|disk quota exceeded", re.I),)),
    ("configuration", (re.compile(r"missing required|invalid configuration|config(?:uration)? error|(?:parse|parsing) error", re.I),)),
)

SENSITIVE_LOG_PATTERNS = (
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._\-]+"),
    re.compile(r"(?i)\b(token|password|passwd|secret|apikey|api_key|authorization|credential)=\S+"),
    re.compile(r"(?i)(authorization:\s*)\S+"),
)


def _dict(obj: Any) -> dict[str, Any]:
    return client.ApiClient().sanitize_for_serialization(obj)


def _meta(obj: dict[str, Any]) -> dict[str, Any]:
    return obj.get("metadata") or {}


def _status(obj: dict[str, Any]) -> str | None:
    status = obj.get("status") or {}
    if isinstance(status, str):
        return status
    return status.get("phase") or status.get("replicas") or status.get("conditions")


_QUANTITY_UNITS = {"Ki": 1024, "Mi": 1024**2, "Gi": 1024**3, "Ti": 1024**4}


def _quantity(value: Any, resource: str) -> float | None:
    """Normalize CPU to millicores and memory/storage to bytes."""
    if value in (None, ""):
        return None
    text = str(value)
    try:
        if resource == "cpu":
            return float(text[:-1]) if text.endswith("m") else float(text) * 1000
        for suffix, multiplier in _QUANTITY_UNITS.items():
            if text.endswith(suffix):
                return float(text[: -len(suffix)]) * multiplier
        return float(text)
    except ValueError:
        return None


def _format_quantity(value: float | None, resource: str) -> str:
    if value is None:
        return "-"
    if resource == "cpu":
        return f"{value:.0f}m"
    return f"{value / 1024**2:.1f}Mi"


def _pod_status(pod: dict[str, Any]) -> str:
    status = pod.get("status") or {}
    for container in (status.get("containerStatuses") or []) + (status.get("initContainerStatuses") or []):
        state = container.get("state") or {}
        for name in ("waiting", "terminated"):
            reason = (state.get(name) or {}).get("reason")
            if reason:
                return reason
    return status.get("reason") or status.get("phase") or "Unknown"


def _pod_inventory(pod: dict[str, Any], metrics: dict[tuple[str, str], dict[str, Any]]) -> dict[str, Any]:
    meta, spec, status = _meta(pod), pod.get("spec") or {}, pod.get("status") or {}
    containers = spec.get("containers") or []
    totals: dict[str, float] = {"cpu": 0, "memory": 0, "ephemeral-storage": 0}
    present: set[str] = set()
    for container in containers:
        limits = ((container.get("resources") or {}).get("limits") or {})
        for resource in totals:
            amount = _quantity(limits.get(resource), resource)
            if amount is not None:
                totals[resource] += amount
                present.add(resource)
    metric = metrics.get((meta.get("namespace") or "", meta.get("name") or ""), {})
    usage = {"cpu": 0.0, "memory": 0.0}
    usage_present: set[str] = set()
    for container in metric.get("containers") or []:
        for resource in usage:
            amount = _quantity((container.get("usage") or {}).get(resource), resource)
            if amount is not None:
                usage[resource] += amount
                usage_present.add(resource)
    ready = sum(1 for item in status.get("containerStatuses") or [] if item.get("ready"))
    result = {
        "ready": f"{ready}/{len(containers)}",
        "status": _pod_status(pod),
        "restarts": _restart_count(pod),
        "pod_ip": status.get("podIP") or "-",
        "node": spec.get("nodeName") or "-",
        "nominated_node": status.get("nominatedNodeName") or "-",
        "readiness_gates": ", ".join(item.get("conditionType") or "" for item in spec.get("readinessGates") or [] if item.get("conditionType")) or "-",
        "qos": status.get("qosClass") or "-",
        "cpu_usage": _format_quantity(usage["cpu"] if "cpu" in usage_present else None, "cpu"),
        "memory_usage": _format_quantity(usage["memory"] if "memory" in usage_present else None, "memory"),
        "cpu_limit": _format_quantity(totals["cpu"] if "cpu" in present else None, "cpu"),
        "memory_limit": _format_quantity(totals["memory"] if "memory" in present else None, "memory"),
        "ephemeral_storage_limit": _format_quantity(totals["ephemeral-storage"] if "ephemeral-storage" in present else None, "ephemeral-storage"),
        "disk_usage": "unavailable via Metrics API",
    }
    for resource, label in (("cpu", "cpu_limit_pct"), ("memory", "memory_limit_pct")):
        result[label] = round(usage[resource] * 100 / totals[resource], 1) if resource in usage_present and resource in present and totals[resource] else None
    return result


def _save_object(repo: AuditRepository, cluster: str, kind: str, obj: dict[str, Any]) -> int:
    meta = _meta(obj)
    repo.add_observation(
        {
            "cluster_name": cluster,
            "timestamp": iso_now(),
            "api_version": obj.get("apiVersion"),
            "kind": kind,
            "namespace": meta.get("namespace"),
            "name": meta.get("name"),
            "status": str(_status(obj))[:500] if _status(obj) is not None else None,
            # The repository redacts immediately before serialization. Passing
            # the source object avoids a short-lived second deep copy here.
            "raw_json": obj,
        }
    )
    count = 0
    for finding in evaluate_object(kind, obj):
        repo.upsert_finding(finding.to_record(cluster))
        count += 1
    return count


def _list(label: str, func: Callable[[], Any], failures: list[str] | None = None) -> list[dict[str, Any]]:
    try:
        return [_dict(item) for item in func().items]
    except ApiException as exc:
        LOG.warning("collector %s failed: status=%s reason=%s", label, exc.status, exc.reason)
        if failures is not None:
            failures.append(label)
        return []
    except Exception as exc:
        LOG.warning("collector %s failed: %s", label, exc)
        if failures is not None:
            failures.append(label)
        return []


def _list_custom(label: str, group: str, version: str, plural: str, failures: list[str], namespace: str | None = None) -> list[dict[str, Any]]:
    try:
        return list_custom(group, version, plural, namespace=namespace)
    except ApiException as exc:
        LOG.warning("collector %s failed: status=%s reason=%s", label, exc.status, exc.reason)
    except Exception as exc:
        LOG.warning("collector %s failed: %s", label, exc)
    failures.append(label)
    return []


CNI_MARKERS = {
    "ovn-kubernetes": ("ovn-kubernetes", "ovnkube", "ovn"),
    "openshift-sdn": ("openshift-sdn",),
    "calico": ("calico", "tigera"),
    "cilium": ("cilium",),
    "flannel": ("flannel",),
    "canal": ("canal", "rke2-canal"),
    "antrea": ("antrea",),
    "weave": ("weave-net", "weave"),
    "kube-router": ("kube-router",),
    "multus": ("multus",),
}


def _pod_ready(pod: dict[str, Any]) -> bool:
    if (pod.get("status") or {}).get("phase") != "Running":
        return False
    conditions = {(c.get("type")): c.get("status") for c in (pod.get("status") or {}).get("conditions") or []}
    return conditions.get("Ready") == "True"


def _redact_log_text(text: str) -> str:
    redacted = str(redact_text(text))
    for pattern in SENSITIVE_LOG_PATTERNS:
        redacted = pattern.sub(lambda match: f"{match.group(1).strip().rstrip('=:')}:<redacted>", redacted)
    return redacted


def _normalize_log_text(text: Any) -> str:
    if isinstance(text, bytes):
        return text.decode("utf-8", errors="replace")
    normalized = str(text)
    if normalized.startswith(("b'", 'b"')):
        try:
            value = ast.literal_eval(normalized)
            if isinstance(value, bytes):
                normalized = value.decode("utf-8", errors="replace")
        except (SyntaxError, ValueError):
            pass
    if normalized.count("\n") <= 1 and normalized.count("\\n") >= 2:
        normalized = normalized.replace("\\r\\n", "\n").replace("\\n", "\n")
    return normalized


def _pod_age_minutes(pod: dict[str, Any]) -> float | None:
    started = parse_time((pod.get("status") or {}).get("startTime"))
    if not started:
        return None
    return max((utcnow() - started).total_seconds() / 60, 0)


def _restart_count(pod: dict[str, Any]) -> int:
    status = pod.get("status") or {}
    return sum((cstat.get("restartCount") or 0) for cstat in (status.get("containerStatuses") or []) + (status.get("initContainerStatuses") or []))


def _has_hard_failure_state(pod: dict[str, Any]) -> bool:
    status = pod.get("status") or {}
    if status.get("phase") == "Failed":
        return True
    for cstat in (status.get("containerStatuses") or []) + (status.get("initContainerStatuses") or []):
        waiting = ((cstat.get("state") or {}).get("waiting") or {})
        if waiting.get("reason") in {"CrashLoopBackOff", "ImagePullBackOff", "ErrImagePull"}:
            return True
        terminated = ((cstat.get("lastState") or {}).get("terminated") or {})
        if terminated.get("reason") in {"Error", "OOMKilled"}:
            return True
    return False


def _is_problematic_pod(pod: dict[str, Any], min_age_minutes: int, min_restarts: int) -> bool:
    status = pod.get("status") or {}
    phase = status.get("phase")
    age = _pod_age_minutes(pod)
    old_enough = age is None or age >= min_age_minutes
    if _has_hard_failure_state(pod):
        return old_enough or _restart_count(pod) >= min_restarts
    if _restart_count(pod) >= min_restarts:
        return True
    if not old_enough:
        return False
    if phase not in {"Running", "Succeeded"}:
        return True
    if not _pod_ready(pod):
        return True
    return False


def _analyze_log_text(text: str, min_count: int) -> dict[str, Any]:
    normalized = _normalize_log_text(text)
    lines = [line.strip() for line in normalized.splitlines() if line.strip()]
    matches: list[str] = []
    counts: dict[str, int] = {}
    matching_lines: dict[str, list[str]] = {}
    for category, patterns in LOG_PATTERNS:
        category_lines = [line for line in lines if any(pattern.search(line) for pattern in patterns)]
        matching_lines[category] = category_lines
        count = len(category_lines)
        counts[category] = count
        if count >= min_count:
            matches.append(category)
    excerpt_lines = []
    for line in lines:
        if any(category in matches and line in matching_lines[category] for category, _ in LOG_PATTERNS):
            excerpt_lines.append(_redact_log_text(line.strip())[:300])
        if len(excerpt_lines) >= 8:
            break
    return {"suspected_causes": matches, "pattern_counts": counts, "matched_lines": excerpt_lines, "min_count": min_count}


def _collect_problem_pod_logs(
    core: client.CoreV1Api,
    pod: dict[str, Any],
    tail_lines: int,
    limit_bytes: int,
    min_age_minutes: int,
    min_restarts: int,
    pattern_min_count: int,
) -> dict[str, Any] | None:
    if not _is_problematic_pod(pod, min_age_minutes, min_restarts):
        return None
    meta = _meta(pod)
    namespace = meta.get("namespace")
    name = meta.get("name")
    if not namespace or not name:
        return None
    status = pod.get("status") or {}
    containers = []
    for cstat in (status.get("containerStatuses") or []) + (status.get("initContainerStatuses") or []):
        cname = cstat.get("name")
        if cname and cname not in containers:
            containers.append(cname)
    collected: list[dict[str, Any]] = []
    for cname in containers:
        for previous in (False, True):
            if previous and not any(c.get("name") == cname and (c.get("restartCount") or 0) > 0 for c in (status.get("containerStatuses") or []) + (status.get("initContainerStatuses") or [])):
                continue
            try:
                text = core.read_namespaced_pod_log(
                    name=name,
                    namespace=namespace,
                    container=cname,
                    previous=previous,
                    tail_lines=tail_lines,
                    limit_bytes=limit_bytes,
                    timestamps=True,
                    _request_timeout=(5, 15),
                )
            except ApiException as exc:
                if exc.status in {400, 404} and previous:
                    continue
                LOG.warning("pod log collection failed for %s/%s container=%s previous=%s: status=%s reason=%s", namespace, name, cname, previous, exc.status, exc.reason)
                continue
            except Exception as exc:
                LOG.warning("pod log collection failed for %s/%s container=%s previous=%s: %s", namespace, name, cname, previous, exc)
                continue
            if not text:
                continue
            redacted = _redact_log_text(_normalize_log_text(text))
            analysis = _analyze_log_text(redacted, pattern_min_count)
            if not analysis["suspected_causes"]:
                continue
            collected.append(
                {
                    "container": cname,
                    "previous": previous,
                    "tail_lines": tail_lines,
                    "limit_bytes": limit_bytes,
                    "log": redacted,
                    "analysis": analysis,
                }
            )
    if not collected:
        return None
    causes = sorted({cause for item in collected for cause in item["analysis"].get("suspected_causes", [])})
    return {
        "containers": collected,
        "suspected_causes": causes,
        "pod_age_minutes": _pod_age_minutes(pod),
        "restart_count": _restart_count(pod),
        "pattern_min_count": pattern_min_count,
    }


def _detect_cni_components(pods: list[dict[str, Any]], daemonsets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    components: dict[str, dict[str, Any]] = {}

    def match_provider(obj: dict[str, Any]) -> str | None:
        meta = _meta(obj)
        labels = meta.get("labels") or {}
        haystack = " ".join(
            [
                str(meta.get("name") or ""),
                str(meta.get("namespace") or ""),
                " ".join(f"{k}={v}" for k, v in labels.items()),
            ]
        ).lower()
        for provider, markers in CNI_MARKERS.items():
            if any(marker in haystack for marker in markers):
                return provider
        return None

    for pod in pods:
        provider = match_provider(pod)
        if not provider:
            continue
        comp = components.setdefault(provider, {"provider": provider, "pods_total": 0, "pods_ready": 0, "daemonsets": []})
        comp["pods_total"] += 1
        if _pod_ready(pod):
            comp["pods_ready"] += 1
    for daemonset in daemonsets:
        provider = match_provider(daemonset)
        if not provider:
            continue
        status = daemonset.get("status") or {}
        desired = status.get("desiredNumberScheduled") or status.get("numberDesired") or 0
        ready = status.get("numberReady") or 0
        comp = components.setdefault(provider, {"provider": provider, "pods_total": 0, "pods_ready": 0, "daemonsets": []})
        comp["daemonsets"].append({"name": _meta(daemonset).get("name"), "namespace": _meta(daemonset).get("namespace"), "desired": desired, "ready": ready})

    if not components:
        return [
            {
                "apiVersion": "audit.neto/v1",
                "kind": "CNIComponent",
                "metadata": {"name": "unknown"},
                "status": "Unknown",
                "provider": "unknown",
                "pods_total": 0,
                "pods_ready": 0,
                "daemonsets": [],
            }
        ]

    result = []
    for provider, data in components.items():
        degraded = data["pods_total"] > 0 and data["pods_ready"] < data["pods_total"]
        for ds in data["daemonsets"]:
            if ds["desired"] and ds["ready"] < ds["desired"]:
                degraded = True
        data.update(
            {
                "apiVersion": "audit.neto/v1",
                "kind": "CNIComponent",
                "metadata": {"name": provider},
                "status": "Degraded" if degraded else "Healthy",
            }
        )
        result.append(data)
    return result


def run_snapshot(
    repo: AuditRepository,
    cluster: str,
    enable_openshift: bool = True,
    enable_secret_audit: bool = False,
    collect_pod_logs: bool = False,
    pod_log_tail_lines: int = 80,
    pod_log_limit_bytes: int = 20000,
    pod_log_min_age_minutes: int = 10,
    pod_log_min_restarts: int = 3,
    pod_log_pattern_min_count: int = 3,
    retention_days: int = 14,
) -> dict[str, Any]:
    core = client.CoreV1Api()
    apps = client.AppsV1Api()
    batch = client.BatchV1Api()
    rbac = client.RbacAuthorizationV1Api()
    net = client.NetworkingV1Api()
    storage = client.StorageV1Api()
    policy = client.PolicyV1Api()
    snapshot_started_at = iso_now()
    summary = {
        "observed": 0,
        "findings": 0,
        "events": 0,
        "pod_logs": 0,
        "collector_errors": 0,
        "resolved_findings": 0,
        "coverage": {},
        "not_checked": API_ONLY_LIMITATIONS,
    }
    snapshot_id = repo.create_snapshot(cluster)
    collector_failures: list[str] = []
    namespaces: list[dict[str, Any]] = []
    networkpolicies: list[dict[str, Any]] = []
    quotas: list[dict[str, Any]] = []
    limitranges: list[dict[str, Any]] = []
    pods: list[dict[str, Any]] = []
    daemonsets: list[dict[str, Any]] = []
    resources_by_kind: dict[str, list[dict[str, Any]]] = {}
    try:
        collectors: list[tuple[str, str, Callable[[], list[dict[str, Any]]]]] = [
            ("Pod", "pods", lambda: _list("pods", core.list_pod_for_all_namespaces, collector_failures)),
            ("Node", "nodes", lambda: _list("nodes", core.list_node, collector_failures)),
            ("Namespace", "namespaces", lambda: _list("namespaces", core.list_namespace, collector_failures)),
            ("Service", "services", lambda: _list("services", core.list_service_for_all_namespaces, collector_failures)),
            ("ConfigMap", "configmaps", lambda: _list("configmaps", core.list_config_map_for_all_namespaces, collector_failures)),
            ("Endpoints", "endpoints", lambda: _list("endpoints", core.list_endpoints_for_all_namespaces, collector_failures)),
            ("PersistentVolume", "persistentvolumes", lambda: _list("pvs", core.list_persistent_volume, collector_failures)),
            ("PersistentVolumeClaim", "persistentvolumeclaims", lambda: _list("pvcs", core.list_persistent_volume_claim_for_all_namespaces, collector_failures)),
            ("StorageClass", "storageclasses", lambda: _list("storageclasses", storage.list_storage_class, collector_failures)),
            ("CSIDriver", "csidrivers", lambda: _list("csidrivers", storage.list_csi_driver, collector_failures)),
            # Some clusters return CSINodes with spec.drivers omitted. The generated
            # Kubernetes Python model rejects that valid wire representation, so use
            # the raw custom-object endpoint instead.
            ("CSINode", "csinodes", lambda: _list_custom("csinodes", "storage.k8s.io", "v1", "csinodes", collector_failures)),
            ("CSIStorageCapacity", "csistoragecapacities", lambda: _list("csistoragecapacities", storage.list_csi_storage_capacity_for_all_namespaces, collector_failures)),
            ("Deployment", "deployments", lambda: _list("deployments", apps.list_deployment_for_all_namespaces, collector_failures)),
            ("DaemonSet", "daemonsets", lambda: _list("daemonsets", apps.list_daemon_set_for_all_namespaces, collector_failures)),
            ("StatefulSet", "statefulsets", lambda: _list("statefulsets", apps.list_stateful_set_for_all_namespaces, collector_failures)),
            ("ReplicaSet", "replicasets", lambda: _list("replicasets", apps.list_replica_set_for_all_namespaces, collector_failures)),
            ("ReplicationController", "replicationcontrollers", lambda: _list("replicationcontrollers", core.list_replication_controller_for_all_namespaces, collector_failures)),
            ("Job", "jobs", lambda: _list("jobs", batch.list_job_for_all_namespaces, collector_failures)),
            ("CronJob", "cronjobs", lambda: _list("cronjobs", batch.list_cron_job_for_all_namespaces, collector_failures)),
            ("ServiceAccount", "serviceaccounts", lambda: _list("serviceaccounts", core.list_service_account_for_all_namespaces, collector_failures)),
            ("Role", "roles", lambda: _list("roles", rbac.list_role_for_all_namespaces, collector_failures)),
            ("RoleBinding", "rolebindings", lambda: _list("rolebindings", rbac.list_role_binding_for_all_namespaces, collector_failures)),
            ("ClusterRole", "clusterroles", lambda: _list("clusterroles", rbac.list_cluster_role, collector_failures)),
            ("ClusterRoleBinding", "clusterrolebindings", lambda: _list("clusterrolebindings", rbac.list_cluster_role_binding, collector_failures)),
            ("NetworkPolicy", "networkpolicies", lambda: _list("networkpolicies", net.list_network_policy_for_all_namespaces, collector_failures)),
            ("PodDisruptionBudget", "poddisruptionbudgets", lambda: _list("poddisruptionbudgets", policy.list_pod_disruption_budget_for_all_namespaces, collector_failures)),
            ("ResourceQuota", "resourcequotas", lambda: _list("resourcequotas", core.list_resource_quota_for_all_namespaces, collector_failures)),
            ("LimitRange", "limitranges", lambda: _list("limitranges", core.list_limit_range_for_all_namespaces, collector_failures)),
        ]
        if enable_secret_audit:
            collectors.append(("Secret", "secrets", lambda: _list("secrets", core.list_secret_for_all_namespaces, collector_failures)))
        else:
            LOG.info("Secret audit disabled; set AUDIT_ENABLE_SECRET_AUDIT=true and grant optional secret RBAC to collect secret metadata")
        if has_resource("discovery.k8s.io/v1", "endpointslices"):
            discovery = client.DiscoveryV1Api()
            collectors.append(("EndpointSlice", "endpointslices", lambda: _list("endpointslices", discovery.list_endpoint_slice_for_all_namespaces, collector_failures)))
        if has_resource("k8s.cni.cncf.io/v1", "network-attachment-definitions"):
            collectors.append(("NetworkAttachmentDefinition", "network-attachment-definitions", lambda: _list_custom("network-attachment-definitions", "k8s.cni.cncf.io", "v1", "network-attachment-definitions", collector_failures)))
        optional_resources = [
            ("networking.k8s.io", "v1", "ingresses", "Ingress"),
            ("networking.k8s.io", "v1", "ingressclasses", "IngressClass"),
            ("autoscaling", "v2", "horizontalpodautoscalers", "HorizontalPodAutoscaler"),
            ("autoscaling.k8s.io", "v1", "verticalpodautoscalers", "VerticalPodAutoscaler"),
            ("admissionregistration.k8s.io", "v1", "validatingwebhookconfigurations", "ValidatingWebhookConfiguration"),
            ("admissionregistration.k8s.io", "v1", "mutatingwebhookconfigurations", "MutatingWebhookConfiguration"),
            ("admissionregistration.k8s.io", "v1", "validatingadmissionpolicies", "ValidatingAdmissionPolicy"),
            ("admissionregistration.k8s.io", "v1", "validatingadmissionpolicybindings", "ValidatingAdmissionPolicyBinding"),
            ("apiregistration.k8s.io", "v1", "apiservices", "APIService"),
            ("apiextensions.k8s.io", "v1", "customresourcedefinitions", "CustomResourceDefinition"),
            ("storage.k8s.io", "v1", "volumeattachments", "VolumeAttachment"),
            ("scheduling.k8s.io", "v1", "priorityclasses", "PriorityClass"),
            ("node.k8s.io", "v1", "runtimeclasses", "RuntimeClass"),
            ("certificates.k8s.io", "v1", "certificatesigningrequests", "CertificateSigningRequest"),
            ("snapshot.storage.k8s.io", "v1", "volumesnapshots", "VolumeSnapshot"),
            ("snapshot.storage.k8s.io", "v1", "volumesnapshotcontents", "VolumeSnapshotContent"),
            ("snapshot.storage.k8s.io", "v1", "volumesnapshotclasses", "VolumeSnapshotClass"),
            ("metrics.k8s.io", "v1beta1", "nodes", "NodeMetrics"),
            ("compliance.openshift.io", "v1alpha1", "compliancecheckresults", "ComplianceCheckResult"),
            ("compliance.openshift.io", "v1alpha1", "compliancescans", "ComplianceScan"),
            ("compliance.openshift.io", "v1alpha1", "compliancesuites", "ComplianceSuite"),
            ("wgpolicyk8s.io", "v1alpha2", "policyreports", "PolicyReport"),
            ("wgpolicyk8s.io", "v1alpha2", "clusterpolicyreports", "ClusterPolicyReport"),
            ("aquasecurity.github.io", "v1alpha1", "vulnerabilityreports", "VulnerabilityReport"),
        ]
        for group, version, plural, kind in optional_resources:
            gv = f"{group}/{version}"
            if has_resource(gv, plural):
                collectors.append((kind, plural, lambda g=group, v=version, p=plural: _list_custom(p, g, v, p, collector_failures)))
            else:
                summary["coverage"][kind] = {"status": "NOT_APPLICABLE", "reason": f"{gv}/{plural} is not served"}
        pod_metrics: dict[tuple[str, str], dict[str, Any]] = {}
        if has_resource("metrics.k8s.io/v1beta1", "pods"):
            metric_items = _list_custom("podmetrics", "metrics.k8s.io", "v1beta1", "pods", collector_failures)
            pod_metrics = {
                ((_meta(item).get("namespace") or ""), (_meta(item).get("name") or "")): item
                for item in metric_items
            }
            summary["coverage"]["PodMetrics"] = {"status": "ERROR" if "podmetrics" in collector_failures else "CHECKED", "objects": len(metric_items), "rules": False}
        else:
            summary["coverage"]["PodMetrics"] = {"status": "NOT_APPLICABLE", "reason": "metrics.k8s.io/v1beta1/pods is not served"}
        for kind, label, func in collectors:
            failures_before = len(collector_failures)
            items = func()
            failed = len(collector_failures) > failures_before
            if kind == "Pod":
                for item in items:
                    item["auditPodInventory"] = _pod_inventory(item, pod_metrics)
            summary["coverage"][kind] = {
                "status": "ERROR" if failed else "CHECKED",
                "objects": len(items),
                "rules": kind in EVALUATED_KINDS,
            }
            if kind in INVENTORY_RESOURCE_KINDS:
                resources_by_kind[kind] = items
            if kind == "Pod":
                if collect_pod_logs:
                    for pod in items:
                        log_bundle = _collect_problem_pod_logs(
                            core,
                            pod,
                            pod_log_tail_lines,
                            pod_log_limit_bytes,
                            pod_log_min_age_minutes,
                            pod_log_min_restarts,
                            pod_log_pattern_min_count,
                        )
                        if log_bundle:
                            pod["auditLogs"] = log_bundle
                            summary["pod_logs"] += len(log_bundle.get("containers") or [])
                pods = items
            elif kind == "DaemonSet":
                daemonsets = items
            elif kind == "Namespace":
                namespaces = items
            elif kind == "NetworkPolicy":
                networkpolicies = items
            elif kind == "ResourceQuota":
                quotas = items
            elif kind == "LimitRange":
                limitranges = items
            for item in items:
                summary["findings"] += _save_object(repo, cluster, kind, item)
                summary["observed"] += 1
        cni_components = _detect_cni_components(pods, daemonsets)
        for item in cni_components:
            summary["findings"] += _save_object(repo, cluster, "CNIComponent", item)
            summary["observed"] += 1
        resources_by_kind["CNIComponent"] = cni_components
        summary["coverage"]["CNIComponent"] = {"status": "CHECKED", "objects": len(resources_by_kind["CNIComponent"]), "rules": True}
        for event in _list("events", core.list_event_for_all_namespaces, collector_failures):
            if not is_negative_event(event):
                continue
            involved = event.get("involvedObject") or {}
            repo.add_event(
                {
                    "uid": _meta(event).get("uid"),
                    "cluster_name": cluster,
                    "timestamp": event.get("eventTime") or event.get("lastTimestamp") or event.get("firstTimestamp") or iso_now(),
                    "namespace": involved.get("namespace") or _meta(event).get("namespace"),
                    "reason": event.get("reason"),
                    "type": event.get("type"),
                    "message": event.get("message"),
                    "involved_kind": involved.get("kind"),
                    "involved_name": involved.get("name"),
                    "source_component": (event.get("source") or {}).get("component") or event.get("reportingComponent"),
                    "severity": map_event_severity(event),
                    "raw_json": event,
                }
            )
            for finding in evaluate_event(event):
                repo.upsert_finding(finding.to_record(cluster))
                summary["findings"] += 1
            summary["events"] += 1
        for finding in evaluate_namespace_policies(namespaces, networkpolicies, quotas, limitranges):
            repo.upsert_finding(finding.to_record(cluster))
            summary["findings"] += 1
        for finding in evaluate_cluster_inventory(resources_by_kind):
            repo.upsert_finding(finding.to_record(cluster))
            summary["findings"] += 1
        if enable_openshift:
            for group, version, plural, kind in OPENSHIFT_CLUSTER_RESOURCES:
                gv = f"{group}/{version}"
                if not has_resource(gv, plural):
                    summary["coverage"][kind] = {"status": "NOT_APPLICABLE", "reason": f"{gv}/{plural} is not served"}
                    continue
                failures_before = len(collector_failures)
                namespace_scoped = plural in {
                    "routes", "clusterserviceversions", "subscriptions", "installplans", "catalogsources",
                    "operatorgroups", "ingresscontrollers", "machines", "machinesets", "machinehealthchecks",
                }
                if namespace_scoped and plural == "ingresscontrollers":
                    items = _list_custom(plural, group, version, plural, collector_failures, namespace="openshift-ingress-operator")
                elif namespace_scoped:
                    items = []
                    for ns in namespaces:
                        namespace = _meta(ns).get("name")
                        if namespace:
                            items.extend(_list_custom(f"{plural}/{namespace}", group, version, plural, collector_failures, namespace=namespace))
                else:
                    items = _list_custom(plural, group, version, plural, collector_failures)
                for item in items:
                    item.setdefault("kind", kind)
                    item.setdefault("apiVersion", gv)
                    summary["findings"] += _save_object(repo, cluster, kind, item)
                    summary["observed"] += 1
                summary["coverage"][kind] = {
                    "status": "ERROR" if len(collector_failures) > failures_before else "CHECKED",
                    "objects": len(items),
                    "rules": kind in EVALUATED_KINDS,
                }
        # All cross-resource and distribution collectors have consumed these
        # lists. Drop their references before serializing the snapshot result.
        resources_by_kind.clear()
        pods.clear()
        daemonsets.clear()
        namespaces.clear()
        networkpolicies.clear()
        quotas.clear()
        limitranges.clear()
        summary["collector_errors"] = len(set(collector_failures))
        if not collector_failures:
            excluded_kinds = set() if enable_secret_audit else {"Secret"}
            summary["resolved_findings"] = repo.deactivate_findings_not_seen_since(cluster, snapshot_started_at, excluded_kinds)
            checked_kinds = {
                kind
                for kind, coverage in summary["coverage"].items()
                if coverage.get("status") == "CHECKED"
            }
            summary["historical_resources"] = repo.reconcile_observations_not_seen_since(
                cluster,
                snapshot_started_at,
                checked_kinds,
            )
            summary["retention_cleanup"] = repo.prune_history(retention_days)
        repo.finish_snapshot(snapshot_id, "success", summary)
        return summary
    except Exception as exc:
        repo.finish_snapshot(snapshot_id, "failed", summary, str(exc))
        raise

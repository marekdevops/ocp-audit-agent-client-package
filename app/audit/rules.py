from __future__ import annotations

from datetime import timedelta
import hashlib
import re
from typing import Any, Iterable

from app.audit.models import Finding
from app.audit.redaction import is_sensitive_key
from app.utils.time import parse_time, utcnow

SYSTEM_NAMESPACES = {
    "kube-system",
    "kube-public",
    "kube-node-lease",
    "openshift",
    "openshift-apiserver",
    "openshift-authentication",
    "openshift-cluster-csi-drivers",
    "openshift-cluster-machine-approver",
    "openshift-cluster-node-tuning-operator",
    "openshift-config",
    "openshift-config-managed",
    "openshift-console",
    "openshift-dns",
    "openshift-etcd",
    "openshift-image-registry",
    "openshift-ingress",
    "openshift-ingress-operator",
    "openshift-kube-apiserver",
    "openshift-kube-controller-manager",
    "openshift-kube-scheduler",
    "openshift-machine-api",
    "openshift-machine-config-operator",
    "openshift-monitoring",
    "openshift-operator-lifecycle-manager",
    "openshift-operators",
    "openshift-route-controller-manager",
}
PLATFORM_NAMESPACE_PREFIXES = ("openshift-",)
PLATFORM_NAMESPACES = SYSTEM_NAMESPACES
KUBE_SYSTEM_COMPONENT_PREFIXES = (
    "cloud-controller-manager-",
    "coredns",
    "etcd-",
    "helm-install-rke2-",
    "kube-apiserver-",
    "kube-controller-manager-",
    "kube-proxy",
    "kube-scheduler-",
    "metrics-server",
    "rke2-",
    "snapshot-controller",
)
PLATFORM_RBAC_PREFIXES = (
    "openshift-",
    "rke2-",
    "system:",
)
CONFIG_CREDENTIAL_KEY = re.compile(
    r"(?:^|[_\-.])(api[_-]?key|access[_-]?key|secret[_-]?key|private[_-]?key|client[_-]?secret|"
    r"password|passwd|token|authorization|bearer|credential)(?:$|[_\-.])",
    re.IGNORECASE,
)
CLUSTER_ADMIN_WHITELIST = {
    ("Group", "system:masters"),
    ("ServiceAccount", "openshift-cluster-version/cluster-version-operator"),
}
OPENSHIFT_DEFAULT_SCCS = {
    "anyuid",
    "hostaccess",
    "hostmount-anyuid",
    "hostnetwork",
    "hostnetwork-v2",
    "node-exporter",
    "nonroot",
    "nonroot-v2",
    "privileged",
    "restricted",
    "restricted-v2",
}
PRIVILEGE_ESCALATION_VERBS = {"bind", "escalate", "impersonate"}
PRIVILEGE_ESCALATION_RESOURCES = {
    "pods/exec",
    "pods/attach",
    "pods/portforward",
    "serviceaccounts/token",
    "certificatesigningrequests/approval",
}
WORKLOAD_CREATION_RESOURCES = {
    "pods", "deployments", "daemonsets", "statefulsets", "replicasets", "replicationcontrollers", "jobs", "cronjobs",
}


def _fp(*parts: Any) -> str:
    raw = "|".join("" if p is None else str(p) for p in parts)
    return hashlib.sha256(raw.encode()).hexdigest()[:24]


def _meta(obj: dict[str, Any]) -> dict[str, Any]:
    return obj.get("metadata") or {}


def _ns(obj: dict[str, Any]) -> str | None:
    return _meta(obj).get("namespace")


def _name(obj: dict[str, Any]) -> str | None:
    return _meta(obj).get("name")


def _labels(obj: dict[str, Any]) -> dict[str, str]:
    return _meta(obj).get("labels") or {}


def _annotations(obj: dict[str, Any]) -> dict[str, str]:
    return _meta(obj).get("annotations") or {}


def _older_than(obj: dict[str, Any], delta: timedelta) -> bool:
    created = parse_time(_meta(obj).get("creationTimestamp"))
    return bool(created and utcnow() - created > delta)


def _is_platform_namespace(namespace: str | None) -> bool:
    return bool(namespace and (namespace in PLATFORM_NAMESPACES or namespace.startswith(PLATFORM_NAMESPACE_PREFIXES)))


def _is_expected_platform_object(obj: dict[str, Any]) -> bool:
    namespace = _ns(obj)
    name = (_name(obj) or "").lower()
    if namespace == "kube-system":
        return name.startswith(KUBE_SYSTEM_COMPONENT_PREFIXES)
    return _is_platform_namespace(namespace)


def _pod_configuration_is_covered_by_controller(pod: dict[str, Any]) -> bool:
    return any(
        owner.get("controller") is True and owner.get("kind") in {"ReplicaSet", "ReplicationController", "StatefulSet", "DaemonSet", "Job"}
        for owner in (_meta(pod).get("ownerReferences") or [])
    )


def _is_platform_managed_rbac(obj: dict[str, Any]) -> bool:
    labels = _labels(obj)
    name = (_name(obj) or "").lower()
    if labels.get("kubernetes.io/bootstrapping") == "rbac-defaults":
        return True
    if _ns(obj):
        return _is_expected_platform_object(obj)
    return name.startswith(PLATFORM_RBAC_PREFIXES)


def _is_expected_rke2_cluster_admin_binding(obj: dict[str, Any], subject: dict[str, Any]) -> bool:
    binding_name = (_name(obj) or "").lower()
    return (
        binding_name.startswith("helm-kube-system-rke2-")
        and subject.get("kind") == "ServiceAccount"
        and subject.get("namespace") == "kube-system"
        and str(subject.get("name") or "").startswith("helm-rke2-")
    )


def _pod_spec_containers(spec: dict[str, Any]) -> Iterable[tuple[str, dict[str, Any]]]:
    for key in ("initContainers", "containers", "ephemeralContainers"):
        for container in spec.get(key) or []:
            yield key, container


def _template_spec(obj: dict[str, Any]) -> dict[str, Any]:
    return (((obj.get("spec") or {}).get("template") or {}).get("spec") or {})


def _cronjob_template_spec(obj: dict[str, Any]) -> dict[str, Any]:
    return (((((obj.get("spec") or {}).get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec") or {})


def _parse_cpu(value: Any) -> float | None:
    if value is None:
        return None
    text = str(value)
    try:
        if text.endswith("n"):
            return float(text[:-1]) / 1_000_000_000
        if text.endswith("u"):
            return float(text[:-1]) / 1_000_000
        if text.endswith("m"):
            return float(text[:-1]) / 1000
        return float(text)
    except ValueError:
        return None


def _parse_memory(value: Any) -> float | None:
    if value is None:
        return None
    text = str(value)
    units = {"Ki": 1024, "Mi": 1024**2, "Gi": 1024**3, "Ti": 1024**4, "K": 1000, "M": 1000**2, "G": 1000**3}
    for suffix, multiplier in units.items():
        if text.endswith(suffix):
            try:
                return float(text[: -len(suffix)]) * multiplier
            except ValueError:
                return None
    try:
        return float(text)
    except ValueError:
        return None


def _pod_security_findings(kind: str, obj: dict[str, Any], spec: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    if _is_expected_platform_object(obj) or (kind == "Pod" and _pod_configuration_is_covered_by_controller(obj)):
        return findings
    windows = ((spec.get("os") or {}).get("name") or "").lower() == "windows"
    if spec.get("hostNetwork"):
        findings.append(_finding("High", "security", kind, obj, f"{kind} uses hostNetwork", "The workload shares the node network namespace.", "Avoid hostNetwork unless explicitly required.", {"hostNetwork": True}))
    if spec.get("hostPID"):
        findings.append(_finding("High", "security", kind, obj, f"{kind} uses hostPID", "The workload can observe host process IDs.", "Disable hostPID.", {"hostPID": True}))
    if spec.get("hostIPC"):
        findings.append(_finding("High", "security", kind, obj, f"{kind} uses hostIPC", "The workload can access host IPC namespace.", "Disable hostIPC.", {"hostIPC": True}))
    if any((container.get("ports") or []) for _, container in _pod_spec_containers(spec)):
        host_ports = [
            port.get("hostPort")
            for _, container in _pod_spec_containers(spec)
            for port in (container.get("ports") or [])
            if port.get("hostPort")
        ]
        if host_ports:
            findings.append(_finding("High", "security", kind, obj, f"{kind} uses hostPort", "The workload exposes container ports directly on the node.", "Remove hostPort or document and constrain the required ports.", {"hostPorts": host_ports}))
    if spec.get("automountServiceAccountToken", True) and spec.get("serviceAccountName", "default") == "default":
        findings.append(_finding("Low", "security", kind, obj, "ServiceAccount token automount enabled", "Pods receive an API token by default.", "Set automountServiceAccountToken=false where API access is not needed.", {}))
    for volume in spec.get("volumes") or []:
        if "hostPath" in volume:
            findings.append(_finding("High", "security", kind, obj, f"{kind} uses hostPath volume", "A hostPath volume exposes node filesystem paths.", "Replace hostPath with a safer storage primitive.", {"volume": volume.get("name"), "path": volume["hostPath"].get("path")}))
    for container_type, container in _pod_spec_containers(spec):
        cname = container.get("name")
        sec = container.get("securityContext") or {}
        resources = container.get("resources") or {}
        requests, limits = resources.get("requests") or {}, resources.get("limits") or {}
        image = container.get("image") or ""
        if sec.get("privileged"):
            findings.append(_finding("Critical", "security", kind, obj, "Privileged container", f"Container {cname} runs privileged.", "Remove privileged mode and use the restricted SCC profile.", {"container": cname}))
        if ((sec.get("windowsOptions") or {}).get("hostProcess")):
            findings.append(_finding("Critical", "security", kind, obj, "Windows HostProcess container", f"Container {cname} runs with host-level Windows privileges.", "Disable hostProcess unless required for a tightly controlled system component.", {"container": cname}))
        if not windows and sec.get("allowPrivilegeEscalation") is True:
            findings.append(_finding("Medium", "security", kind, obj, "Privilege escalation explicitly enabled", f"Container {cname} explicitly enables privilege escalation.", "Set allowPrivilegeEscalation=false.", {"container": cname}))
        pod_sec = spec.get("securityContext") or {}
        if not windows and (sec.get("runAsNonRoot") is False or sec.get("runAsUser") == 0 or pod_sec.get("runAsNonRoot") is False or pod_sec.get("runAsUser") == 0):
            findings.append(_finding("High", "security", kind, obj, "Container explicitly allows root execution", f"Container {cname} explicitly permits or selects UID 0.", "Require non-root execution and use a non-root-compatible image.", {"container": cname, "runAsUser": sec.get("runAsUser", pod_sec.get("runAsUser"))}))
        caps = ((sec.get("capabilities") or {}).get("add") or [])
        if not windows and any(cap in {"SYS_ADMIN", "NET_ADMIN"} for cap in caps):
            findings.append(_finding("High", "security", kind, obj, "Dangerous Linux capability added", f"Container {cname} adds high-risk capabilities.", "Drop unnecessary capabilities and avoid SYS_ADMIN/NET_ADMIN.", {"container": cname, "capabilities": caps}))
        seccomp = sec.get("seccompProfile") or (spec.get("securityContext") or {}).get("seccompProfile") or {}
        if not windows and seccomp.get("type") == "Unconfined":
            findings.append(_finding("High", "security", kind, obj, "Container explicitly disables seccomp confinement", f"Container {cname} selects the Unconfined seccomp profile.", "Use RuntimeDefault or a reviewed Localhost profile.", {"container": cname, "seccompProfile": seccomp}))
        if image.endswith(":latest") or ":" not in image.split("/")[-1]:
            findings.append(_finding("Low", "configuration", kind, obj, "Image tag is mutable", f"Container {cname} uses a mutable or implicit tag.", "Pin images to immutable versions or digests.", {"container": cname, "image": image}))
        if "cpu" not in requests or "memory" not in requests:
            findings.append(_finding("Medium", "resource-management", kind, obj, "Container lacks resource requests", f"Container {cname} omits CPU or memory requests.", "Set CPU and memory requests for scheduling stability.", {"container": cname}))
        if "memory" not in limits:
            findings.append(_finding("Low", "resource-management", kind, obj, "Container lacks memory limit", f"Container {cname} omits a memory limit.", "Set a memory limit where the workload memory envelope is known; CPU limits remain workload-policy dependent.", {"container": cname}))
        exposes_port = any(port.get("containerPort") for port in (container.get("ports") or []))
        if container_type == "containers" and spec.get("restartPolicy", "Always") == "Always" and exposes_port and "livenessProbe" not in container and "readinessProbe" not in container:
            findings.append(_finding("Low", "configuration", kind, obj, "Container has no health probes", f"Container {cname} has no liveness or readiness probe.", "Add probes for long-running services where applicable.", {"container": cname}))
    return findings


def _finding(sev: str, cat: str, kind: str | None, obj: dict[str, Any], title: str, desc: str, rec: str, evidence: dict[str, Any]) -> Finding:
    return Finding(
        fingerprint=_fp(cat, kind, _ns(obj), _name(obj), title),
        severity=sev,
        category=cat,
        namespace=_ns(obj),
        resource_kind=kind,
        resource_name=_name(obj),
        title=title,
        description=desc,
        recommendation=rec,
        evidence=evidence,
        raw_json=obj,
    )


def map_event_severity(event: dict[str, Any]) -> str:
    reason = event.get("reason") or ""
    message = event.get("message") or ""
    if reason in {"BackOff", "FailedMount", "FailedAttachVolume"}:
        return "High"
    if reason == "FailedScheduling":
        return "High" if "Insufficient" in message else "Medium"
    if reason == "Unhealthy":
        return "High"
    if reason == "Killing" and "oom" in message.lower():
        return "High"
    if reason in {"Pulling", "Pulled", "Created", "Started"}:
        return "Info"
    return "Medium" if event.get("type") == "Warning" else "Info"


def is_negative_event(event: dict[str, Any]) -> bool:
    return map_event_severity(event) != "Info"


def evaluate_event(event: dict[str, Any]) -> list[Finding]:
    severity = map_event_severity(event)
    if severity == "Info":
        return []
    involved = event.get("involvedObject") or event.get("regarding") or {}
    obj = {"metadata": {"namespace": involved.get("namespace"), "name": involved.get("name")}}
    return [_finding(severity, "storage" if "Mount" in (event.get("reason") or "") or "Volume" in (event.get("reason") or "") else "workload-health",
                     involved.get("kind") or "Event", obj, f"Event {event.get('reason')}",
                     event.get("message") or "Kubernetes warning event detected.",
                     "Inspect the affected resource and recent controller events.", {"reason": event.get("reason"), "message": event.get("message")})]


def evaluate_pod(pod: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    spec, status = pod.get("spec") or {}, pod.get("status") or {}
    phase = status.get("phase")
    findings.extend(_pod_security_findings("Pod", pod, spec))
    for cstat in (status.get("containerStatuses") or []) + (status.get("initContainerStatuses") or []):
        restart_count = cstat.get("restartCount") or 0
        if restart_count >= 3:
            findings.append(
                _finding(
                    "High" if restart_count >= 10 else "Medium",
                    "workload-health",
                    "Pod",
                    pod,
                    "Pod container is restarting",
                    f"Container {cstat.get('name')} restarted {restart_count} times.",
                    "Inspect previous container logs, probes, resource limits and recent config changes.",
                    {"container": cstat.get("name"), "restartCount": restart_count},
                )
            )
        waiting = ((cstat.get("state") or {}).get("waiting") or {})
        reason = waiting.get("reason")
        if reason == "CrashLoopBackOff":
            findings.append(_finding("High", "workload-health", "Pod", pod, "Pod is CrashLoopBackOff", "A container repeatedly crashes.", "Inspect logs, probes, config and recent image changes.", {"container": cstat.get("name"), "reason": reason}))
        if reason in {"ImagePullBackOff", "ErrImagePull"}:
            findings.append(_finding("High", "workload-health", "Pod", pod, "Pod cannot pull image", "A container image pull is failing.", "Check image name, registry auth, pull secret and network path.", {"container": cstat.get("name"), "reason": reason}))
        terminated = ((cstat.get("lastState") or {}).get("terminated") or {})
        if terminated.get("reason") == "OOMKilled":
            findings.append(_finding("High", "workload-health", "Pod", pod, "Pod was OOMKilled", "A container exceeded available memory.", "Review memory limits, requests and application memory usage.", {"container": cstat.get("name"), "exitCode": terminated.get("exitCode")}))
    if phase == "Pending":
        started = parse_time(status.get("startTime"))
        if started and utcnow() - started > timedelta(minutes=10):
            findings.append(_finding("Medium", "workload-health", "Pod", pod, "Pod pending for more than 10 minutes", "The pod has not been scheduled or started in time.", "Inspect scheduling, PVCs, image pulls and quota.", {"startTime": status.get("startTime")}))
    if phase == "Failed" and status.get("reason") == "Evicted":
        findings.append(_finding("High", "workload-health", "Pod", pod, "Pod evicted", "The pod was evicted from a node.", "Check node pressure and workload resource requests.", {"reason": status.get("reason"), "message": status.get("message")}))
    log_bundle = pod.get("auditLogs") or {}
    suspected_causes = log_bundle.get("suspected_causes") or []
    if suspected_causes:
        lines = []
        for item in log_bundle.get("containers") or []:
            lines.extend((item.get("analysis") or {}).get("matched_lines") or [])
        findings.append(
            _finding(
                "High",
                "workload-health",
                "Pod",
                pod,
                "Pod logs suggest failure cause",
                "Collected logs from a problematic pod match known failure patterns.",
                "Review the matched log excerpts and correlate them with events, probes, resource limits and application configuration.",
                {"suspected_causes": suspected_causes, "matched_lines": lines[:12]},
            )
        )
    return findings


def evaluate_node(node: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    status = node.get("status") or {}
    spec = node.get("spec") or {}
    info = status.get("nodeInfo") or {}
    conditions = {c.get("type"): c for c in status.get("conditions") or []}
    ready = conditions.get("Ready") or {}
    if ready.get("status") in {"False", "Unknown"}:
        findings.append(_finding("Critical", "node-health", "Node", node, "Node is not Ready", "A node is unavailable or readiness is unknown.", "Inspect kubelet, runtime, network and node events.", {"condition": ready}))
    for cond in ("MemoryPressure", "DiskPressure", "PIDPressure"):
        if (conditions.get(cond) or {}).get("status") == "True":
            findings.append(_finding("High", "node-health", "Node", node, f"Node has {cond}", "Node resource pressure is active.", "Reduce pressure, investigate capacity and evictions.", {"condition": conditions[cond]}))
    if spec.get("unschedulable") and _annotations(node).get("cluster.x-k8s.io/paused") != "true":
        findings.append(_finding("Medium", "node-health", "Node", node, "Node is unschedulable", "New pods will not be scheduled to this node.", "Confirm this is intentional maintenance or uncordon the node.", {}))
    if not info.get("osImage") or not info.get("kernelVersion") or not info.get("containerRuntimeVersion"):
        findings.append(_finding("Medium", "node-health", "Node", node, "Node OS/runtime inventory incomplete", "Node status does not expose complete OS, kernel or runtime information.", "Inspect kubelet node status and node readiness.", {"nodeInfo": info}))
    if "openshift" in " ".join(_labels(node).keys()).lower() and "Red Hat Enterprise Linux CoreOS" not in (info.get("osImage") or ""):
        findings.append(_finding("Medium", "node-health", "Node", node, "OpenShift node is not reporting RHCOS", "OpenShift nodes normally report Red Hat Enterprise Linux CoreOS unless using a supported exception.", "Verify node OS supportability and MachineConfigPool membership.", {"osImage": info.get("osImage")}))
    runtime = info.get("containerRuntimeVersion") or ""
    if runtime and not runtime.startswith("cri-o://") and "containerd://" not in runtime:
        findings.append(_finding("Low", "node-health", "Node", node, "Unexpected container runtime", "The node reports a container runtime that is unusual for OpenShift/Kubernetes.", "Verify runtime supportability and upgrade policy.", {"containerRuntimeVersion": runtime}))
    capacity, allocatable = status.get("capacity") or {}, status.get("allocatable") or {}
    cpu_cap, cpu_alloc = _parse_cpu(capacity.get("cpu")), _parse_cpu(allocatable.get("cpu"))
    mem_cap, mem_alloc = _parse_memory(capacity.get("memory")), _parse_memory(allocatable.get("memory"))
    if cpu_cap and cpu_alloc and cpu_alloc / cpu_cap < 0.75:
        findings.append(_finding("Low", "node-health", "Node", node, "Low CPU allocatable ratio", "A large share of node CPU is reserved and unavailable to workloads.", "Review kube/system reserved settings and node sizing.", {"capacity": capacity.get("cpu"), "allocatable": allocatable.get("cpu")}))
    if mem_cap and mem_alloc and mem_alloc / mem_cap < 0.75:
        findings.append(_finding("Low", "node-health", "Node", node, "Low memory allocatable ratio", "A large share of node memory is reserved and unavailable to workloads.", "Review kube/system reserved settings and node sizing.", {"capacity": capacity.get("memory"), "allocatable": allocatable.get("memory")}))
    for taint in spec.get("taints") or []:
        if taint.get("effect") == "NoExecute" and taint.get("key") not in {"node.kubernetes.io/not-ready", "node.kubernetes.io/unreachable"}:
            findings.append(_finding("Medium", "node-health", "Node", node, "Node has NoExecute taint", "Pods without a matching toleration will be evicted from this node.", "Confirm the taint is intentional and documented.", {"taint": taint}))
    return findings


def evaluate_workload(kind: str, obj: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    status, spec = obj.get("status") or {}, obj.get("spec") or {}
    unavailable = status.get("unavailableReplicas") or max((spec.get("replicas") or 0) - (status.get("readyReplicas") or 0), 0)
    if kind in {"Deployment", "StatefulSet"} and unavailable > 0:
        findings.append(_finding("High", "workload-health", kind, obj, f"{kind} has unavailable replicas", "Not all desired replicas are available.", "Inspect rollout status, pods, probes and events.", {"unavailableReplicas": unavailable}))
    replica_owned_by_deployment = kind == "ReplicaSet" and any(
        owner.get("controller") is True and owner.get("kind") == "Deployment"
        for owner in (_meta(obj).get("ownerReferences") or [])
    )
    if kind in {"Deployment", "StatefulSet", "DaemonSet", "ReplicationController", "Job"} or (kind == "ReplicaSet" and not replica_owned_by_deployment):
        findings.extend(_pod_security_findings(kind, obj, _template_spec(obj)))
    ha_optional = _annotations(obj).get("audit.neto.io/ha-optional") == "true"
    if kind == "Deployment" and (spec.get("replicas") or 1) == 1 and not ha_optional and not _is_expected_platform_object(obj):
        findings.append(_finding("Low", "configuration", kind, obj, "Deployment has a single replica", "A non-system Deployment with one replica has limited availability during node or pod disruption.", "Use at least two replicas for services requiring availability.", {"replicas": spec.get("replicas")}))
    if kind == "Deployment" and (spec.get("strategy") or {}).get("type") == "Recreate" and not ha_optional and not _is_expected_platform_object(obj):
        findings.append(_finding("Medium", "availability", kind, obj, "Deployment uses Recreate strategy", "All old replicas can stop before replacement replicas become available.", "Use RollingUpdate unless the application explicitly requires exclusive execution.", {}))
    template_spec = _template_spec(obj)
    if kind in {"Deployment", "StatefulSet"} and (spec.get("replicas") or 0) >= 2 and not ha_optional and not _is_expected_platform_object(obj):
        affinity = template_spec.get("affinity") or {}
        if not template_spec.get("topologySpreadConstraints") and not affinity.get("podAntiAffinity"):
            findings.append(_finding("Low", "availability", kind, obj, "Replicas have no topology distribution policy", "Replicas can be scheduled onto the same failure domain.", "Add topologySpreadConstraints or pod anti-affinity appropriate to the cluster topology.", {"replicas": spec.get("replicas")}))
    if kind == "StatefulSet" and (spec.get("replicas") or 1) == 1 and not ha_optional and not _is_expected_platform_object(obj):
        findings.append(_finding("Low", "configuration", kind, obj, "StatefulSet has a single replica", "A non-system StatefulSet with one replica has limited availability.", "Use multiple replicas when the application supports it.", {"replicas": spec.get("replicas")}))
    if kind == "DaemonSet" and (status.get("numberUnavailable") or 0) > 0:
        findings.append(_finding("High", "workload-health", kind, obj, "DaemonSet has unavailable pods", "The DaemonSet is not healthy on all scheduled nodes.", "Inspect daemon pod scheduling and node conditions.", {"numberUnavailable": status.get("numberUnavailable")}))
    if kind == "Job" and (status.get("failed") or 0) > 0:
        findings.append(_finding("High", "workload-health", kind, obj, "Job has failed pods", "A batch job has failures.", "Inspect pod logs and job backoff limit.", {"failed": status.get("failed")}))
    return findings


def evaluate_cronjob(obj: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    spec, status = obj.get("spec") or {}, obj.get("status") or {}
    platform = _is_expected_platform_object(obj)
    if spec.get("suspend") is True and not platform:
        findings.append(_finding("Low", "workload-health", "CronJob", obj, "CronJob is suspended", "The scheduled workload is explicitly suspended.", "Confirm that suspension is intentional and time-bounded.", {"schedule": spec.get("schedule")}))
    if (not spec.get("concurrencyPolicy") or spec.get("concurrencyPolicy") == "Allow") and not platform:
        findings.append(_finding("Low", "configuration", "CronJob", obj, "CronJob allows concurrent runs", "A slow run can overlap with the next scheduled execution.", "Use Forbid or Replace when overlapping executions are unsafe.", {"concurrencyPolicy": spec.get("concurrencyPolicy", "Allow")}))
    if status.get("active") and len(status["active"]) > 1:
        findings.append(_finding("Medium", "workload-health", "CronJob", obj, "CronJob has concurrent active jobs", "Multiple jobs from the same CronJob are active.", "Check job duration, schedule and concurrencyPolicy.", {"activeJobs": len(status["active"])}))
    findings.extend(_pod_security_findings("CronJob", obj, _cronjob_template_spec(obj)))
    return findings


def evaluate_namespace(obj: dict[str, Any]) -> list[Finding]:
    if _is_platform_namespace(_name(obj)):
        return []
    labels = _labels(obj)
    annotations = _annotations(obj)
    findings: list[Finding] = []
    enforce = labels.get("pod-security.kubernetes.io/enforce")
    openshift_scc_managed = (
        labels.get("security.openshift.io/scc.podSecurityLabelSync") == "true"
        or any(str(key).startswith("openshift.io/sa.scc.") for key in annotations)
    )
    if enforce not in {"baseline", "restricted"} and not openshift_scc_managed:
        findings.append(_finding("Medium", "security", "Namespace", obj, "Namespace does not enforce Pod Security Standards", "The namespace does not enforce the Baseline or Restricted Pod Security Standard.", "Set pod-security.kubernetes.io/enforce to baseline or restricted and pin an appropriate version.", {"enforce": enforce or "unset"}))
    if enforce and not labels.get("pod-security.kubernetes.io/enforce-version"):
        findings.append(_finding("Low", "security", "Namespace", obj, "Pod Security enforcement version is not pinned", "Pod Security behavior can change with a cluster upgrade.", "Set pod-security.kubernetes.io/enforce-version to a reviewed Kubernetes version.", {"enforce": enforce}))
    return findings


def evaluate_service_account(obj: dict[str, Any]) -> list[Finding]:
    # Kubernetes creates this object in every namespace. Actual use of the default
    # account with token automount is evaluated on Pod/workload specs instead.
    return []


def evaluate_ingress(obj: dict[str, Any]) -> list[Finding]:
    if _is_expected_platform_object(obj) or _annotations(obj).get("audit.neto.io/allow-cleartext") == "true":
        return []
    spec = obj.get("spec") or {}
    tls_hosts = {host for item in (spec.get("tls") or []) for host in (item.get("hosts") or [])}
    rule_hosts = {item.get("host") for item in (spec.get("rules") or []) if item.get("host")}
    missing = sorted(rule_hosts - tls_hosts)
    if missing:
        return [_finding("Medium", "networking", "Ingress", obj, "Ingress hosts are not covered by TLS", "One or more Ingress hosts have no TLS entry.", "Configure TLS for every externally exposed host.", {"hostsWithoutTLS": missing})]
    return []


def evaluate_hpa(obj: dict[str, Any]) -> list[Finding]:
    conditions = {item.get("type"): item for item in (obj.get("status") or {}).get("conditions") or []}
    bad = [
        conditions[name]
        for name in ("AbleToScale", "ScalingActive")
        if conditions.get(name, {}).get("status") == "False"
        and conditions.get(name, {}).get("reason") not in {"ScalingDisabled", "BackoffBoth", "BackoffDownscale", "BackoffUpscale"}
    ]
    if bad:
        return [_finding("High", "resource-management", "HorizontalPodAutoscaler", obj, "HPA cannot scale its target", "The autoscaler reports that scaling is unavailable or inactive.", "Inspect metrics availability, target reference and HPA conditions.", {"conditions": bad})]
    return []


def evaluate_admission(kind: str, obj: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for webhook in obj.get("webhooks") or []:
        if kind == "ValidatingWebhookConfiguration" and webhook.get("failurePolicy") == "Ignore":
            findings.append(_finding("Medium", "admission", kind, obj, "Admission webhook fails open", "The webhook allows requests when it is unavailable.", "Use failurePolicy=Fail for security controls after validating availability.", {"webhook": webhook.get("name")}))
        timeout = webhook.get("timeoutSeconds")
        if timeout and timeout > 10:
            findings.append(_finding("Low", "admission", kind, obj, "Admission webhook timeout is high", "A slow webhook can delay API requests.", "Use a timeout of 10 seconds or less and monitor webhook latency.", {"webhook": webhook.get("name"), "timeoutSeconds": timeout}))
    return findings


def evaluate_validating_admission_policy(kind: str, obj: dict[str, Any]) -> list[Finding]:
    spec = obj.get("spec") or {}
    findings: list[Finding] = []
    if kind == "ValidatingAdmissionPolicy" and spec.get("failurePolicy") == "Ignore":
        findings.append(_finding("Medium", "admission", kind, obj, "ValidatingAdmissionPolicy fails open", "Policy evaluation errors do not reject requests.", "Use failurePolicy=Fail for security-relevant policies.", {}))
    if kind == "ValidatingAdmissionPolicyBinding":
        actions = set(spec.get("validationActions") or [])
        if "Deny" not in actions:
            findings.append(_finding("Low", "admission", kind, obj, "Admission policy binding does not enforce Deny", "The binding only audits or warns and does not block violations.", "Confirm audit-only mode is intentional or add Deny after validation.", {"validationActions": sorted(actions)}))
    return findings


def evaluate_api_service(obj: dict[str, Any]) -> list[Finding]:
    unavailable = [c for c in (obj.get("status") or {}).get("conditions") or [] if c.get("type") == "Available" and c.get("status") != "True"]
    if unavailable:
        return [_finding("High", "cluster-health", "APIService", obj, "Aggregated APIService is unavailable", "An aggregated Kubernetes API reports Available=False or Unknown.", "Inspect the backing Service, endpoints, certificates and API aggregation logs.", {"conditions": unavailable})]
    return []


def evaluate_volume_attachment(obj: dict[str, Any]) -> list[Finding]:
    status = obj.get("status") or {}
    if status.get("attachError") or status.get("detachError"):
        return [_finding("High", "storage", "VolumeAttachment", obj, "Volume attachment operation failed", "CSI reports an attach or detach error.", "Inspect CSI controller/node plugins, node health and storage backend.", {"attachError": status.get("attachError"), "detachError": status.get("detachError")})]
    return []


def evaluate_volume_snapshot(kind: str, obj: dict[str, Any]) -> list[Finding]:
    status = obj.get("status") or {}
    error = status.get("error")
    if error:
        return [_finding("High", "storage", kind, obj, "VolumeSnapshot operation failed", "The CSI snapshot object reports an error.", "Inspect snapshot-controller, CSI snapshotter and storage backend.", {"error": error})]
    if kind == "VolumeSnapshot" and status and status.get("readyToUse") is False and _older_than(obj, timedelta(minutes=10)):
        return [_finding("Medium", "storage", kind, obj, "VolumeSnapshot is not ready", "A requested volume snapshot is not ready for restore.", "Inspect snapshot status, events and CSI snapshot components.", {"status": status})]
    return []


def evaluate_external_assessment(kind: str, obj: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    status = obj.get("status")
    if kind == "ComplianceCheckResult":
        result = status.get("result") or status.get("status") if isinstance(status, dict) else status
        if str(result or "").upper() in {"FAIL", "ERROR", "INCONSISTENT"}:
            annotations = _meta(obj).get("annotations") or {}
            severity = str(annotations.get("compliance.openshift.io/severity") or "Medium").title()
            if severity not in {"Critical", "High", "Medium", "Low", "Info"}:
                severity = "Medium"
            findings.append(_finding(severity, "compliance", kind, obj, "Compliance control failed", "An OpenShift Compliance Operator check did not pass.", "Review the referenced rule, remediation and scan evidence before applying changes.", {"result": result, "rule": annotations.get("compliance.openshift.io/rule")}))
    elif kind in {"PolicyReport", "ClusterPolicyReport"}:
        summary = (obj.get("summary") or (status if isinstance(status, dict) else {}) or {})
        failed = summary.get("fail") or 0
        if failed:
            findings.append(_finding("Medium", "policy", kind, obj, "Policy report contains failures", "Admission or background policy evaluation reports failed resources; summary data alone does not prove impact severity.", "Inspect individual policy results and remediate or document valid exceptions.", {"summary": summary}))
    elif kind == "VulnerabilityReport":
        summary = ((obj.get("report") or {}).get("summary") or {})
        critical, high = summary.get("criticalCount") or 0, summary.get("highCount") or 0
        if critical or high:
            findings.append(_finding("Critical" if critical else "High", "supply-chain", kind, obj, "Container image vulnerabilities detected", "An installed image scanner reports Critical or High vulnerabilities.", "Patch or replace the affected image and verify exploitability and runtime exposure.", {"criticalCount": critical, "highCount": high, "image": (obj.get("report") or {}).get("artifact", {}).get("repository")}))
    return findings


def evaluate_priority_class(obj: dict[str, Any]) -> list[Finding]:
    if obj.get("globalDefault") and (obj.get("value") or 0) >= 1000000000:
        return [_finding("Medium", "scheduling", "PriorityClass", obj, "Very high PriorityClass is global default", "Ordinary workloads can receive a system-level scheduling priority.", "Use a lower non-system global default and assign high priorities explicitly.", {"value": obj.get("value")})]
    return []


def evaluate_configmap(obj: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    data = obj.get("data") or {}
    binary_data = obj.get("binaryData") or {}
    sensitive_keys = [key for key in list(data.keys()) + list(binary_data.keys()) if CONFIG_CREDENTIAL_KEY.search(key)]
    if sensitive_keys:
        findings.append(_finding("High", "configuration", "ConfigMap", obj, "ConfigMap appears to contain sensitive keys", "ConfigMaps are not designed for secret material and are commonly readable by broader subjects.", "Move credentials, tokens and private keys into Secrets or an external secret manager.", {"keys": sensitive_keys}))
    return findings


def evaluate_secret(obj: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    meta = _meta(obj)
    secret_type = obj.get("type")
    labels = meta.get("labels") or {}
    annotations = meta.get("annotations") or {}
    data_keys = list((obj.get("data") or {}).keys())
    expected_platform_object = _is_expected_platform_object(obj)
    if not data_keys and not expected_platform_object:
        findings.append(_finding("Low", "security", "Secret", obj, "Secret has no data keys", "A Secret object exists without stored data keys.", "Remove unused Secrets or verify the controller populates them.", {"type": secret_type}))
    if secret_type == "kubernetes.io/tls" and not {"tls.crt", "tls.key"}.issubset(set(data_keys)):
        findings.append(_finding("High", "certificates", "Secret", obj, "TLS Secret is incomplete", "A TLS Secret should contain tls.crt and tls.key keys.", "Recreate the TLS Secret with both certificate and private key entries.", {"keys": data_keys}))
    if secret_type in {"Opaque", None} and not expected_platform_object and not labels.get("app.kubernetes.io/managed-by") and not annotations.get("managed-by"):
        findings.append(_finding("Low", "security", "Secret", obj, "Opaque Secret lacks ownership metadata", "The Secret has no standard managed-by label or ownership hint.", "Add ownership labels/annotations and rotate/remove unmanaged credentials.", {"type": secret_type}))
    if any(is_sensitive_key(key) for key in labels.keys() | annotations.keys()):
        findings.append(_finding("Medium", "security", "Secret", obj, "Secret metadata contains sensitive-looking keys", "Secret labels or annotations contain key names that suggest sensitive data may be in metadata.", "Keep secret values out of metadata because metadata is widely exposed.", {"labelKeys": list(labels.keys()), "annotationKeys": list(annotations.keys())}))
    return findings


def evaluate_storage_class(obj: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    if obj.get("provisioner") in {"kubernetes.io/aws-ebs", "kubernetes.io/gce-pd", "kubernetes.io/azure-disk", "kubernetes.io/cinder"}:
        findings.append(_finding("Medium", "storage", "StorageClass", obj, "StorageClass uses in-tree provisioner", "The StorageClass uses a legacy in-tree volume provisioner.", "Migrate to the vendor CSI driver and CSI-backed StorageClasses.", {"provisioner": obj.get("provisioner")}))
    binding = obj.get("volumeBindingMode") or "Immediate"
    topology_constrained = bool(obj.get("allowedTopologies")) or obj.get("provisioner") == "kubernetes.io/no-provisioner"
    if binding == "Immediate" and topology_constrained:
        findings.append(_finding("Medium", "storage", "StorageClass", obj, "Topology-constrained StorageClass uses Immediate binding", "Immediate binding can select storage before pod scheduling topology is known.", "Use WaitForFirstConsumer for topology-constrained or local storage.", {"volumeBindingMode": binding, "provisioner": obj.get("provisioner")}))
    return findings


def evaluate_csi(kind: str, obj: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    if kind == "CSIStorageCapacity":
        capacity = str(obj.get("capacity") or "")
        if capacity in {"", "0", "0Gi", "0Mi"}:
            findings.append(_finding("Medium", "storage", kind, obj, "CSIStorageCapacity reports no capacity", "A CSI capacity object reports zero or missing capacity.", "Inspect storage backend capacity and CSI external-provisioner state.", {"capacity": capacity}))
    return findings


def evaluate_cni_component(obj: dict[str, Any]) -> list[Finding]:
    status = obj.get("status")
    if status == "Unknown":
        return [_finding("Medium", "networking", "CNIComponent", obj, "CNI provider not detected", "The audit could not identify a known CNI component from pods or daemonsets.", "Verify CNI installation, kube-system networking pods and auditor RBAC visibility.", {})]
    if status == "Degraded":
        return [_finding("High", "networking", "CNIComponent", obj, "CNI component degraded", "One or more detected CNI pods or daemonsets are not fully ready.", "Inspect CNI daemonsets, node networking pods and recent events.", {"provider": obj.get("provider"), "pods_total": obj.get("pods_total"), "pods_ready": obj.get("pods_ready"), "daemonsets": obj.get("daemonsets")})]
    return []


def evaluate_network_attachment_definition(obj: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    config = ((obj.get("spec") or {}).get("config") or "")
    if not config:
        findings.append(_finding("Medium", "networking", "NetworkAttachmentDefinition", obj, "NetworkAttachmentDefinition has no config", "A Multus network attachment definition has no CNI config payload.", "Validate the NAD spec.config and owning operator.", {}))
    if any(marker in config.lower() for marker in ("password", "token", "secret", "authorization")):
        findings.append(_finding("High", "networking", "NetworkAttachmentDefinition", obj, "NetworkAttachmentDefinition may contain sensitive data", "The NAD config contains sensitive-looking text.", "Move credentials out of NetworkAttachmentDefinition config and rotate exposed values.", {}))
    return findings


def evaluate_pdb(obj: dict[str, Any]) -> list[Finding]:
    status = obj.get("status") or {}
    disruptions = status.get("disruptionsAllowed")
    if disruptions == 0 and (status.get("currentHealthy") or 0) < (status.get("desiredHealthy") or 0):
        return [_finding("Medium", "workload-health", "PodDisruptionBudget", obj, "PodDisruptionBudget blocks disruption while unhealthy", "The PDB allows no disruptions and the protected workload is below desired health.", "Inspect protected pods and adjust rollout or availability settings.", {"status": status})]
    return []


def evaluate_csr(obj: dict[str, Any]) -> list[Finding]:
    conditions = (obj.get("status") or {}).get("conditions") or []
    if not conditions:
        created = parse_time(_meta(obj).get("creationTimestamp"))
        if created and utcnow() - created > timedelta(hours=1):
            return [_finding("Medium", "certificates", "CertificateSigningRequest", obj, "CSR is pending for more than one hour", "A certificate request has not been approved or denied.", "Validate the signer, requester and requested identities before approving or denying it.", {"creationTimestamp": _meta(obj).get("creationTimestamp"), "signerName": (obj.get("spec") or {}).get("signerName")})]
    return []


def evaluate_crd(obj: dict[str, Any]) -> list[Finding]:
    conditions = (obj.get("status") or {}).get("conditions") or []
    bad = [c for c in conditions if c.get("type") in {"Established", "NamesAccepted"} and c.get("status") == "False"]
    findings: list[Finding] = []
    if bad:
        findings.append(_finding("High", "api-lifecycle", "CustomResourceDefinition", obj, "CRD is not established", "The custom API is not fully established or its names conflict.", "Inspect CRD conditions and API registration.", {"conditions": bad}))
    conversion = (obj.get("spec") or {}).get("conversion") or {}
    if conversion.get("strategy") == "Webhook" and not (conversion.get("webhook") or {}).get("conversionReviewVersions"):
        findings.append(_finding("Medium", "api-lifecycle", "CustomResourceDefinition", obj, "CRD conversion webhook has no review versions", "The conversion webhook does not declare supported ConversionReview versions.", "Declare supported conversionReviewVersions and test upgrades.", {}))
    return findings


def evaluate_rbac(kind: str, obj: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    if kind in {"Role", "ClusterRole"} and not _is_platform_managed_rbac(obj):
        for rule in obj.get("rules") or []:
            verbs = set(rule.get("verbs") or [])
            resources = set(rule.get("resources") or [])
            if "*" in verbs or "*" in resources or "*" in (rule.get("apiGroups") or []):
                findings.append(_finding("High", "rbac", kind, obj, "RBAC wildcard permission", "A role grants wildcard permissions.", "Replace wildcards with explicit verbs, resources and API groups.", {"rule": rule}))
            dangerous_verbs = sorted(verbs & PRIVILEGE_ESCALATION_VERBS)
            if dangerous_verbs:
                findings.append(_finding("Critical", "rbac", kind, obj, "RBAC grants privilege-escalation verbs", "The role can bind, escalate or impersonate identities and permissions.", "Remove these verbs or isolate them in a tightly controlled administrative role.", {"verbs": dangerous_verbs, "rule": rule}))
            dangerous_resources = sorted(resources & PRIVILEGE_ESCALATION_RESOURCES)
            if dangerous_resources:
                findings.append(_finding("High", "rbac", kind, obj, "RBAC grants interactive or token access", "The role grants access to interactive pod sessions, token creation or CSR approval.", "Validate the operational need and constrain resourceNames, namespaces and subjects.", {"resources": dangerous_resources, "verbs": sorted(verbs)}))
            if verbs & {"create", "*"} and resources & WORKLOAD_CREATION_RESOURCES:
                findings.append(_finding("High", "rbac", kind, obj, "RBAC can create workloads", "Creating workloads can provide access to ServiceAccounts, node resources or privileged runtime settings.", "Constrain workload creation and enforce Pod Security Admission.", {"resources": sorted(resources & WORKLOAD_CREATION_RESOURCES), "verbs": sorted(verbs)}))
            if verbs & {"get", "list", "watch", "*"} and ("secrets" in resources or "*" in resources):
                findings.append(_finding("High", "rbac", kind, obj, "RBAC can read Secrets", "The role permits reading Secret objects and their data.", "Limit Secret access to dedicated identities and namespaces.", {"rule": rule}))
    if kind in {"RoleBinding", "ClusterRoleBinding"}:
        role_ref = obj.get("roleRef") or {}
        subjects = obj.get("subjects") or []
        if kind == "ClusterRoleBinding" and role_ref.get("name") == "cluster-admin":
            for subject in subjects:
                subject_id = (subject.get("kind"), f"{subject.get('namespace')}/{subject.get('name')}" if subject.get("namespace") else subject.get("name"))
                if subject_id not in CLUSTER_ADMIN_WHITELIST and not _is_expected_rke2_cluster_admin_binding(obj, subject):
                    findings.append(_finding("Critical", "rbac", kind, obj, "cluster-admin binding", "A subject is bound to cluster-admin.", "Validate necessity and replace with least-privilege roles.", {"subject": subject, "roleRef": role_ref}))
        for subject in subjects:
            if subject.get("name") in {"system:anonymous", "system:unauthenticated"} and not _is_platform_managed_rbac(obj):
                findings.append(_finding("Critical", "rbac", kind, obj, "Unauthenticated subject has RBAC binding", "Anonymous or unauthenticated users are bound to permissions.", "Remove the binding or restrict it immediately.", {"subject": subject, "roleRef": role_ref}))
    return findings


def evaluate_openshift(kind: str, obj: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    conditions = {c.get("type"): c for c in (obj.get("status") or {}).get("conditions") or []}
    if kind == "ClusterOperator":
        if (conditions.get("Available") or {}).get("status") == "False":
            findings.append(_finding("Critical", "operators", kind, obj, "ClusterOperator unavailable", "An OpenShift cluster operator is unavailable.", "Inspect operator conditions and related namespace pods.", {"condition": conditions.get("Available")}))
        if (conditions.get("Degraded") or {}).get("status") == "True":
            sev = "Critical" if _name(obj) in {"kube-apiserver", "etcd", "authentication", "ingress"} else "High"
            findings.append(_finding(sev, "operators", kind, obj, "ClusterOperator degraded", "An OpenShift cluster operator reports Degraded=True.", "Inspect the degraded condition message and operator logs.", {"condition": conditions.get("Degraded")}))
    if kind == "ClusterVersion" and any(c.get("type") in {"Failing", "Degraded"} and c.get("status") == "True" for c in conditions.values()):
        findings.append(_finding("High", "cluster-health", kind, obj, "ClusterVersion has failing condition", "The cluster version operator reports an unhealthy condition.", "Inspect ClusterVersion conditions and CVO logs.", {"conditions": list(conditions.values())}))
    if kind == "MachineConfigPool":
        if (conditions.get("Degraded") or {}).get("status") == "True":
            findings.append(_finding("Critical", "cluster-health", kind, obj, "MachineConfigPool degraded", "A MachineConfigPool is degraded.", "Inspect MCO, node config drift and failed rendered configs.", {"condition": conditions.get("Degraded")}))
    if kind == "ClusterServiceVersion" and (obj.get("status") or {}).get("phase") != "Succeeded":
        phase = (obj.get("status") or {}).get("phase")
        if phase == "Failed" or _older_than(obj, timedelta(minutes=30)):
            findings.append(_finding("High" if phase == "Failed" else "Medium", "operators", kind, obj, "CSV is not Succeeded", "An OLM operator CSV did not reach Succeeded within the rollout grace period.", "Inspect CSV conditions, install plan and subscription.", {"phase": phase}))
    if kind == "Subscription":
        problem_types = {"CatalogSourcesUnhealthy", "InstallPlanFailed", "ResolutionFailed", "BundleUnpackFailed"}
        bad = [c for c in (obj.get("status") or {}).get("conditions") or [] if c.get("status") == "True" and c.get("type") in problem_types]
        if bad:
            findings.append(_finding("Medium", "operators", kind, obj, "Subscription has problem condition", "An OLM subscription reports an active condition.", "Inspect subscription and catalog source health.", {"conditions": bad}))
    if kind == "InstallPlan" and str((obj.get("status") or {}).get("phase")).lower() == "failed":
        findings.append(_finding("High", "operators", kind, obj, "InstallPlan failed", "An OLM install plan failed.", "Inspect the InstallPlan status and referenced resources.", {"status": obj.get("status")}))
    if kind == "Route":
        if _is_expected_platform_object(obj) or _annotations(obj).get("audit.neto.io/allow-cleartext") == "true":
            return findings
        spec = obj.get("spec") or {}
        tls = spec.get("tls") or {}
        if not tls:
            findings.append(_finding("Medium", "networking", kind, obj, "Route has no TLS", "An OpenShift Route is exposed without TLS.", "Configure edge, passthrough or reencrypt TLS.", {"host": spec.get("host")}))
        if tls.get("insecureEdgeTerminationPolicy") == "Allow":
            findings.append(_finding("Medium", "networking", kind, obj, "Route allows insecure traffic", "The route accepts insecure HTTP traffic.", "Use Redirect or disable insecure traffic.", {"host": spec.get("host")}))
    if kind == "IngressController" and (conditions.get("Degraded") or {}).get("status") == "True":
        findings.append(_finding("High", "networking", kind, obj, "IngressController degraded", "An ingress controller is degraded.", "Inspect ingress operator and router pods.", {"condition": conditions.get("Degraded")}))
    if kind == "MachineConfigPool":
        spec, status = obj.get("spec") or {}, obj.get("status") or {}
        if spec.get("paused"):
            findings.append(_finding("Medium", "cluster-health", kind, obj, "MachineConfigPool is paused", "Machine configuration changes will not roll out to this pool.", "Confirm the pause is intentional and resume before security updates are required.", {}))
        if (status.get("machineCount") or 0) != (status.get("updatedMachineCount") or 0) and (conditions.get("Updating") or {}).get("status") != "True":
            findings.append(_finding("Medium", "cluster-health", kind, obj, "MachineConfigPool nodes are not fully updated", "Not all nodes in the pool use the current rendered configuration.", "Inspect MCO rollout progress and node degradation.", {"machineCount": status.get("machineCount"), "updatedMachineCount": status.get("updatedMachineCount")}))
    if kind == "Authentication" and _name(obj) == "cluster":
        oauth = (obj.get("spec") or {}).get("oauthMetadata") or {}
        if oauth.get("name"):
            findings.append(_finding("Low", "authentication", kind, obj, "Custom OAuth metadata is configured", "Cluster authentication delegates OAuth metadata to a referenced ConfigMap.", "Verify issuer metadata, ownership and change control.", {"configMap": oauth.get("name")}))
    if kind == "Proxy":
        spec = obj.get("spec") or {}
        if (spec.get("httpProxy") or spec.get("httpsProxy")) and not spec.get("noProxy"):
            findings.append(_finding("Medium", "networking", kind, obj, "Cluster proxy has no noProxy exclusions", "Cluster-wide proxying is enabled without explicit exclusions.", "Configure noProxy for cluster, service, machine and internal registry networks.", {}))
    if kind == "SecurityContextConstraints" and _name(obj) not in OPENSHIFT_DEFAULT_SCCS:
        if obj.get("allowPrivilegedContainer") and not (_name(obj) or "").startswith(("privileged", "host")):
            findings.append(_finding("High", "security", kind, obj, "SCC allows privileged containers", "A non-standard SecurityContextConstraints object permits privileged containers.", "Restrict privileged SCC use and review bound users and groups.", {"users": obj.get("users") or [], "groups": obj.get("groups") or []}))
        if "*" in (obj.get("allowedCapabilities") or []):
            findings.append(_finding("High", "security", kind, obj, "SCC allows all capabilities", "The SCC permits every Linux capability.", "Replace wildcard capabilities with the minimum required set.", {}))
    if kind == "APIServer" and _name(obj) == "cluster":
        encryption_type = (((obj.get("spec") or {}).get("encryption") or {}).get("type") or "identity").lower()
        if encryption_type == "identity":
            findings.append(_finding("High", "security", kind, obj, "OpenShift API encryption at rest is not enabled", "The APIServer configuration uses identity/no encryption for API resources at rest.", "Enable a supported encryption type and monitor the encryption rollout.", {"encryptionType": encryption_type}))
    if kind in {"KubeAPIServer", "KubeControllerManager", "KubeScheduler", "Etcd"}:
        degraded = (conditions.get("Degraded") or {}).get("status") == "True"
        available = (conditions.get("Available") or {}).get("status")
        if degraded or available == "False":
            findings.append(_finding("Critical" if kind in {"KubeAPIServer", "Etcd"} else "High", "cluster-health", kind, obj, f"OpenShift {kind} operator is unhealthy", "A core control-plane operator reports degraded or unavailable status.", "Inspect operator conditions, static pods and related ClusterOperator state.", {"conditions": list(conditions.values())}))
    if kind == "CatalogSource":
        state = (((obj.get("status") or {}).get("connectionState") or {}).get("lastObservedState") or "").upper()
        if state in {"TRANSIENT_FAILURE", "FATAL"} and _older_than(obj, timedelta(minutes=10)):
            findings.append(_finding("High", "operators", kind, obj, "CatalogSource is not ready", "An OLM catalog source is not in READY connection state.", "Inspect catalog pod, registry polling, certificates and network access.", {"lastObservedState": state}))
    if kind == "Machine" and str((obj.get("status") or {}).get("phase") or "").lower() in {"failed", "provisionedfailed"}:
        findings.append(_finding("High", "cluster-health", kind, obj, "OpenShift Machine failed", "A Machine API object reports a failed phase.", "Inspect machine events, infrastructure provider status and machine-controller logs.", {"status": obj.get("status")}))
    if kind == "MachineSet":
        spec, status = obj.get("spec") or {}, obj.get("status") or {}
        desired = spec.get("replicas") or 0
        available = status.get("availableReplicas") or 0
        generation = (_meta(obj).get("generation") or 0)
        observed_generation = status.get("observedGeneration")
        rollout_settled = observed_generation in {None, generation}
        if available < desired and rollout_settled and _older_than(obj, timedelta(minutes=15)):
            findings.append(_finding("High", "cluster-health", kind, obj, "MachineSet lacks available replicas", "The MachineSet has fewer available machines than desired.", "Inspect Machine objects, quotas, provider capacity and machine-controller events.", {"desired": desired, "available": available}))
    if kind == "MachineHealthCheck":
        conditions = (obj.get("status") or {}).get("conditions") or []
        if any(c.get("type") == "RemediationAllowed" and c.get("status") == "False" for c in conditions):
            findings.append(_finding("Medium", "cluster-health", kind, obj, "MachineHealthCheck remediation is blocked", "The MachineHealthCheck cannot currently remediate unhealthy machines.", "Inspect maxUnhealthy and current unhealthy targets.", {"conditions": conditions}))
    return findings


def evaluate_storage(kind: str, obj: dict[str, Any]) -> list[Finding]:
    phase = (obj.get("status") or {}).get("phase")
    if kind == "PersistentVolumeClaim" and phase == "Pending" and _older_than(obj, timedelta(minutes=10)):
        return [_finding("High", "storage", kind, obj, "PVC is Pending", "A claim is not bound to storage.", "Inspect storage class, provisioner, capacity and events.", {"phase": phase})]
    if kind == "PersistentVolume" and phase in {"Released", "Failed"}:
        return [_finding("High" if phase == "Failed" else "Medium", "storage", kind, obj, f"PV is {phase}", "A persistent volume is not in healthy Bound/Available state.", "Inspect reclaim policy and storage backend state.", {"phase": phase})]
    return []


def evaluate_namespace_policies(namespaces: list[dict[str, Any]], networkpolicies: list[dict[str, Any]], quotas: list[dict[str, Any]], limitranges: list[dict[str, Any]]) -> list[Finding]:
    np_ns = {_ns(item) for item in networkpolicies}
    rq_ns = {_ns(item) for item in quotas}
    lr_ns = {_ns(item) for item in limitranges}
    findings: list[Finding] = []
    for ns in namespaces:
        name = _name(ns)
        if not name or _is_platform_namespace(name):
            continue
        if name not in np_ns:
            findings.append(_finding("Medium", "networking", "Namespace", ns, "Namespace has no NetworkPolicy", "No NetworkPolicy was found in this namespace.", "Add default-deny and explicit allow policies.", {"namespace": name}))
        else:
            policies = [item for item in networkpolicies if _ns(item) == name]
            ingress_default_deny = any(((item.get("spec") or {}).get("podSelector") or {}) == {} and "Ingress" in ((item.get("spec") or {}).get("policyTypes") or ["Ingress"]) and not (item.get("spec") or {}).get("ingress") for item in policies)
            egress_default_deny = any(((item.get("spec") or {}).get("podSelector") or {}) == {} and "Egress" in ((item.get("spec") or {}).get("policyTypes") or []) and not (item.get("spec") or {}).get("egress") for item in policies)
            if not ingress_default_deny:
                findings.append(_finding("Medium", "networking", "Namespace", ns, "Namespace has no default-deny ingress policy", "NetworkPolicy objects exist, but none provides namespace-wide default-deny ingress.", "Add a default-deny ingress policy and explicit allow rules.", {"namespace": name}))
            if not egress_default_deny:
                findings.append(_finding("Low", "networking", "Namespace", ns, "Namespace has no default-deny egress policy", "NetworkPolicy objects exist, but none provides namespace-wide default-deny egress.", "Add default-deny egress where application dependencies are understood.", {"namespace": name}))
        labels = (_meta(ns).get("labels") or {})
        prod = labels.get("environment") == "prod" or labels.get("env") == "prod" or "prod" in name
        if prod and name not in rq_ns:
            findings.append(_finding("Medium", "resource-management", "Namespace", ns, "Production namespace has no ResourceQuota", "A production-like namespace has no ResourceQuota.", "Define ResourceQuota for CPU, memory and object counts.", {"namespace": name}))
        if prod and name not in lr_ns:
            findings.append(_finding("Low", "resource-management", "Namespace", ns, "Production namespace has no LimitRange", "A production-like namespace has no LimitRange.", "Define default requests and limits.", {"namespace": name}))
    return findings


def evaluate_cluster_inventory(resources: dict[str, list[dict[str, Any]]]) -> list[Finding]:
    findings: list[Finding] = []
    versions: dict[str, list[str]] = {}
    minor_versions: list[int] = []
    rke1_nodes: list[str] = []
    for node in resources.get("Node", []):
        version = ((node.get("status") or {}).get("nodeInfo") or {}).get("kubeletVersion")
        if version:
            versions.setdefault(version, []).append(_name(node) or "unknown")
            match = re.search(r"v?\d+\.(\d+)", version)
            if match:
                minor_versions.append(int(match.group(1)))
        labels = _labels(node)
        runtime = ((node.get("status") or {}).get("nodeInfo") or {}).get("containerRuntimeVersion") or ""
        if any(str(key).startswith("rke.cattle.io/") for key in labels) and runtime.startswith("docker://"):
            rke1_nodes.append(_name(node) or "unknown")
    if minor_versions and max(minor_versions) - min(minor_versions) > 1:
        obj = {"metadata": {"name": "kubelet-version-skew"}}
        findings.append(_finding("High", "api-lifecycle", "Cluster", obj, "Unsupported kubelet minor-version skew", "Kubelet minor versions differ by more than one release across nodes.", "Align node versions with the control plane and the supported version-skew policy.", {"versions": versions}))
    if rke1_nodes:
        obj = {"metadata": {"name": "rke1-lifecycle"}}
        findings.append(_finding("Critical", "api-lifecycle", "Cluster", obj, "Legacy RKE1 markers detected", "Node labels indicate a legacy RKE1 cluster, which is end-of-life.", "Plan migration to RKE2 or another supported Kubernetes distribution.", {"nodes": rke1_nodes}))

    node_capacity = {_name(item): (item.get("status") or {}).get("capacity") or {} for item in resources.get("Node", [])}
    for metric in resources.get("NodeMetrics", []):
        capacity = node_capacity.get(_name(metric)) or {}
        usage = metric.get("usage") or {}
        cpu_capacity, cpu_usage = _parse_cpu(capacity.get("cpu")), _parse_cpu(usage.get("cpu"))
        mem_capacity, mem_usage = _parse_memory(capacity.get("memory")), _parse_memory(usage.get("memory"))
        ratios = {
            "cpu": cpu_usage / cpu_capacity if cpu_capacity and cpu_usage is not None else None,
            "memory": mem_usage / mem_capacity if mem_capacity and mem_usage is not None else None,
        }
        elevated = {name: round(value * 100, 1) for name, value in ratios.items() if value is not None and value >= 0.90}
        if elevated:
            peak = max(elevated.values())
            findings.append(_finding("High" if peak >= 98 else "Medium", "capacity", "Node", metric, "Point-in-time node utilization is elevated", "A single resource metrics sample shows elevated node utilization; this is not treated as sustained saturation.", "Correlate with time-series metrics and workload demand before resizing or rebalancing.", {"utilizationPercent": elevated, "window": metric.get("window")}))

    endpoints = {(_ns(item), _name(item)): item for item in resources.get("Endpoints", [])}
    endpoint_slices: dict[tuple[str | None, str | None], list[dict[str, Any]]] = {}
    for item in resources.get("EndpointSlice", []):
        service_name = _labels(item).get("kubernetes.io/service-name")
        endpoint_slices.setdefault((_ns(item), service_name), []).append(item)
    for service in resources.get("Service", []):
        spec = service.get("spec") or {}
        if spec.get("type") == "ExternalName" or not spec.get("selector"):
            continue
        key = (_ns(service), _name(service))
        publish_not_ready = spec.get("publishNotReadyAddresses") is True
        legacy_ready = any(
            (subset.get("addresses") or []) or (publish_not_ready and (subset.get("notReadyAddresses") or []))
            for subset in (endpoints.get(key, {}).get("subsets") or [])
        )
        slice_ready = any(
            endpoint.get("addresses") and (publish_not_ready or (endpoint.get("conditions") or {}).get("ready") is not False)
            for item in endpoint_slices.get(key, [])
            for endpoint in (item.get("endpoints") or [])
        )
        if not legacy_ready and not slice_ready:
            findings.append(_finding("High", "networking", "Service", service, "Service has no ready endpoints", "A selector-based Service has no ready backend endpoints.", "Inspect selectors, pod readiness, EndpointSlices and workload health.", {"selector": spec.get("selector")}))
    return findings


def evaluate_object(kind: str, obj: dict[str, Any]) -> list[Finding]:
    if kind == "Pod":
        return evaluate_pod(obj)
    if kind == "Node":
        return evaluate_node(obj)
    if kind == "Namespace":
        return evaluate_namespace(obj)
    if kind in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "ReplicationController", "Job"}:
        return evaluate_workload(kind, obj)
    if kind == "CronJob":
        return evaluate_cronjob(obj)
    if kind == "ServiceAccount":
        return evaluate_service_account(obj)
    if kind == "Ingress":
        return evaluate_ingress(obj)
    if kind == "HorizontalPodAutoscaler":
        return evaluate_hpa(obj)
    if kind == "ConfigMap":
        return evaluate_configmap(obj)
    if kind == "Secret":
        return evaluate_secret(obj)
    if kind == "StorageClass":
        return evaluate_storage_class(obj)
    if kind in {"CSIDriver", "CSINode", "CSIStorageCapacity"}:
        return evaluate_csi(kind, obj)
    if kind == "CNIComponent":
        return evaluate_cni_component(obj)
    if kind == "NetworkAttachmentDefinition":
        return evaluate_network_attachment_definition(obj)
    if kind == "PodDisruptionBudget":
        return evaluate_pdb(obj)
    if kind in {"ValidatingWebhookConfiguration", "MutatingWebhookConfiguration"}:
        return evaluate_admission(kind, obj)
    if kind in {"ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding"}:
        return evaluate_validating_admission_policy(kind, obj)
    if kind == "APIService":
        return evaluate_api_service(obj)
    if kind == "VolumeAttachment":
        return evaluate_volume_attachment(obj)
    if kind in {"VolumeSnapshot", "VolumeSnapshotContent"}:
        return evaluate_volume_snapshot(kind, obj)
    if kind in {"ComplianceCheckResult", "PolicyReport", "ClusterPolicyReport", "VulnerabilityReport"}:
        return evaluate_external_assessment(kind, obj)
    if kind == "PriorityClass":
        return evaluate_priority_class(obj)
    if kind == "CertificateSigningRequest":
        return evaluate_csr(obj)
    if kind == "CustomResourceDefinition":
        return evaluate_crd(obj)
    if kind in {"Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"}:
        return evaluate_rbac(kind, obj)
    if kind in {
        "ClusterOperator", "ClusterVersion", "MachineConfigPool", "ClusterServiceVersion", "Subscription",
        "InstallPlan", "Route", "IngressController", "Authentication", "Proxy", "SecurityContextConstraints",
        "APIServer", "KubeAPIServer", "KubeControllerManager", "KubeScheduler", "Etcd", "CatalogSource",
        "Machine", "MachineSet", "MachineHealthCheck",
    }:
        return evaluate_openshift(kind, obj)
    if kind in {"PersistentVolumeClaim", "PersistentVolume"}:
        return evaluate_storage(kind, obj)
    return []

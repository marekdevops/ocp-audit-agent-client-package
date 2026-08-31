from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
import hashlib
import json
import re
from typing import Any

from app.utils.json import loads
from app.utils.time import parse_time, utcnow


SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")
LOG_FINDING_TITLE = "Pod logs suggest failure cause"
RESTART_FINDING_TITLE = "Pod container is restarting"
FRESHNESS_WINDOW = timedelta(hours=24)
LOG_TIMESTAMP = re.compile(r"\b(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))")
INCIDENT_LABELS = {
    "network_connectivity": "Kubernetes API / network connectivity",
    "permission_or_policy": "Authorization or policy rejection",
    "application_exception": "Application exception",
    "oom_or_memory": "Memory exhaustion",
    "dns_resolution": "DNS resolution failure",
    "certificate_or_tls": "Certificate or TLS failure",
    "storage_or_filesystem": "Storage or filesystem failure",
    "configuration": "Configuration failure",
}
WORKLOAD_OBSERVATION_KINDS = {
    "Pod",
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "ReplicaSet",
    "ReplicationController",
    "Job",
}
WORKLOAD_OWNER_KINDS = WORKLOAD_OBSERVATION_KINDS - {"Pod"}
SEVERITY_ORDER = {severity: index for index, severity in enumerate(SEVERITIES)}


def _as_object(value: Any) -> Any:
    if isinstance(value, str):
        return loads(value, value)
    return value


def _observation_object(observation: dict[str, Any]) -> dict[str, Any]:
    raw = observation.get("raw")
    if isinstance(raw, dict):
        return raw
    decoded = _as_object(observation.get("raw_json"))
    return decoded if isinstance(decoded, dict) else {}


def _controller_owner(obj: dict[str, Any]) -> tuple[str, str] | None:
    owners = ((obj.get("metadata") or {}).get("ownerReferences") or [])
    owner = next((item for item in owners if item.get("controller") is True), None)
    if owner is None and len(owners) == 1:
        owner = owners[0]
    if not owner or not owner.get("kind") or not owner.get("name"):
        return None
    return str(owner["kind"]), str(owner["name"])


def _stable_fingerprint(*parts: Any) -> str:
    value = "|".join("" if part is None else str(part) for part in parts)
    return hashlib.sha256(value.encode()).hexdigest()[:24]


def _pod_configuration_profile(pod: dict[str, Any]) -> str:
    spec = json.loads(json.dumps(pod.get("spec") or {}, default=str))
    for runtime_field in ("nodeName", "hostname", "subdomain"):
        spec.pop(runtime_field, None)
    generated_volumes = {
        str(volume.get("name"))
        for volume in spec.get("volumes") or []
        if str(volume.get("name") or "").startswith("kube-api-access-")
    }
    if generated_volumes:
        spec["volumes"] = [
            volume
            for volume in spec.get("volumes") or []
            if str(volume.get("name")) not in generated_volumes
        ]
        for container_type in ("initContainers", "containers", "ephemeralContainers"):
            for container in spec.get(container_type) or []:
                container["volumeMounts"] = [
                    mount
                    for mount in container.get("volumeMounts") or []
                    if str(mount.get("name")) not in generated_volumes
                ]
    canonical = json.dumps(spec, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()[:12]


def _workload_context(
    observations: list[dict[str, Any]],
) -> tuple[
    dict[tuple[str, str | None, str], tuple[str, str | None, str]],
    dict[tuple[str, str | None, str], dict[str, Any]],
    dict[tuple[str, str | None, str], set[tuple[str | None, str]]],
]:
    objects: dict[tuple[str, str | None, str], dict[str, Any]] = {}
    for observation in observations:
        kind = str(observation.get("kind") or "")
        name = observation.get("name")
        if kind not in WORKLOAD_OBSERVATION_KINDS or not name:
            continue
        key = (kind, observation.get("namespace"), str(name))
        objects[key] = _observation_object(observation)

    targets: dict[tuple[str, str | None, str], tuple[str, str | None, str]] = {}
    target_objects: dict[tuple[str, str | None, str], dict[str, Any]] = {}
    members: dict[tuple[str, str | None, str], set[tuple[str | None, str]]] = defaultdict(set)
    for key, pod in objects.items():
        if key[0] != "Pod":
            continue
        namespace = key[1]
        owner = _controller_owner(pod)
        if not owner or owner[0] not in WORKLOAD_OWNER_KINDS:
            continue
        target = (owner[0], namespace, owner[1])
        owner_obj = objects.get(target, {})
        if owner[0] == "ReplicaSet":
            parent = _controller_owner(owner_obj)
            if parent and parent[0] == "Deployment":
                target = ("Deployment", namespace, parent[1])
                owner_obj = objects.get(target, owner_obj)
        targets[key] = target
        target_objects[target] = owner_obj
        members[target].add((namespace, key[2]))
    return targets, target_objects, members


def _merge_temporal_status(items: list[dict[str, Any]]) -> tuple[str, str | None, str]:
    statuses = {str(item.get("temporal_status") or "Current") for item in items}
    status = "Current" if "Current" in statuses else "Review" if "Review" in statuses else "Historical"
    observed = sorted(str(item["signal_observed_at"]) for item in items if item.get("signal_observed_at"))
    return status, observed[-1] if observed else None, f"Aggregated from {len(items)} pod-level finding record(s)."


def _aggregate_workload_findings(
    findings: list[dict[str, Any]],
    observations: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    targets, target_objects, members = _workload_context(observations)
    pod_observations = {
        (observation.get("namespace"), str(observation.get("name"))): observation
        for observation in observations
        if observation.get("kind") == "Pod" and observation.get("name")
    }
    observation_pods = {key: _observation_object(observation) for key, observation in pod_observations.items()}
    grouped: dict[tuple[Any, ...], list[tuple[dict[str, Any], tuple[str, str | None, str], tuple[str | None, str]]]] = defaultdict(list)
    passthrough: list[dict[str, Any]] = []
    profiles: dict[tuple[str, str | None, str], dict[tuple[str | None, str], set[str]]] = defaultdict(dict)

    for finding in findings:
        if finding.get("resource_kind") != "Pod" or not finding.get("resource_name"):
            passthrough.append(finding)
            continue
        pod_key = (finding.get("namespace"), str(finding["resource_name"]))
        lookup_key = ("Pod", pod_key[0], pod_key[1])
        target = targets.get(lookup_key)
        if target is None:
            pod_obj = finding.get("raw_obj") if isinstance(finding.get("raw_obj"), dict) else {}
            if not _controller_owner(pod_obj):
                pod_obj = observation_pods.get(pod_key, pod_obj)
            owner = _controller_owner(pod_obj)
            if owner and owner[0] in WORKLOAD_OWNER_KINDS:
                target = (owner[0], pod_key[0], owner[1])
        if target is None:
            passthrough.append(finding)
            continue
        members[target].add(pod_key)
        signature = f"{finding.get('category') or ''}:{finding.get('title') or ''}"
        profiles[target].setdefault(pod_key, set()).add(signature)
        group_key = (
            finding.get("cluster_name"),
            target,
            finding.get("category"),
            finding.get("title"),
            finding.get("recommendation"),
        )
        grouped[group_key].append((finding, target, pod_key))

    for target, pods in members.items():
        target_profiles = profiles[target]
        for pod_key in pods:
            target_profiles.setdefault(pod_key, set())

    aggregated: list[dict[str, Any]] = list(passthrough)
    for group_key, entries in grouped.items():
        items = [entry[0] for entry in entries]
        target = entries[0][1]
        affected = sorted({entry[2] for entry in entries}, key=lambda item: ((item[0] or ""), item[1]))
        all_members = members[target] or set(affected)
        representative = min(items, key=lambda item: SEVERITY_ORDER.get(str(item.get("severity")), len(SEVERITIES)))
        item = dict(representative)
        item["severity"] = representative.get("severity")
        item["namespace"] = target[1]
        item["resource_kind"] = target[0]
        item["resource_name"] = target[2]
        item["fingerprint"] = _stable_fingerprint(
            "workload-pods", group_key[0], target[0], target[1], target[2], group_key[2], group_key[3], group_key[4]
        )
        item["finding_id"] = item["fingerprint"][:12]
        item["resource"] = f"{target[0]} / {target[1] or '-'} / {target[2]}"
        item["count"] = sum(int(source.get("count") or 1) for source in items)
        item["first_seen"] = min(str(source.get("first_seen") or "") for source in items)
        item["last_seen"] = max(str(source.get("last_seen") or "") for source in items)
        item["affected_pod_count"] = len(affected)
        item["workload_pod_count"] = len(all_members)
        item["pod_scope"] = f"{len(affected)}/{len(all_members)} pods affected"
        item["grouped_pod_finding"] = True
        item["affected_pod_resources"] = [
            {"namespace": namespace, "resource_kind": "Pod", "resource_name": name}
            for namespace, name in affected
        ]
        item["description"] = (
            f"{representative.get('description') or ''} Aggregated at {target[0]} level; "
            f"{len(affected)} of {len(all_members)} pods are affected."
        ).strip()
        evidence_rows = []
        for source, _entry_target, pod_key in sorted(entries, key=lambda entry: ((entry[2][0] or ""), entry[2][1]))[:25]:
            evidence_rows.append(
                {
                    "resource_kind": "Pod",
                    "namespace": pod_key[0],
                    "resource_name": pod_key[1],
                    "evidence": source.get("evidence_obj") or {},
                }
            )
        item["evidence_obj"] = {
            "workload": {"resource_kind": target[0], "namespace": target[1], "resource_name": target[2]},
            "affected_count": len(affected),
            "total_pods": len(all_members),
            "affected": evidence_rows,
            "affected_list_truncated": len(entries) > len(evidence_rows),
        }
        item["evidence"] = item["evidence_obj"]
        item["evidence_json"] = json.dumps(item["evidence_obj"], ensure_ascii=False, indent=2, default=str)
        item["raw_obj"] = target_objects.get(target) or representative.get("raw_obj") or {}
        item["raw_json"] = item["raw_obj"]
        status, observed_at, reason = _merge_temporal_status(items)
        item["temporal_status"] = status
        item["signal_observed_at"] = observed_at
        item["freshness_reason"] = reason
        aggregated.append(item)

    for target, pod_profiles in profiles.items():
        buckets: dict[tuple[str, ...], list[tuple[str | None, str]]] = defaultdict(list)
        for pod_key, signatures in pod_profiles.items():
            buckets[tuple(sorted(signatures))].append(pod_key)
        if len(buckets) <= 1:
            continue
        baseline = sorted(buckets, key=lambda profile: (-len(buckets[profile]), len(profile), profile))[0]
        outliers = sorted(
            (pod for profile, pods in buckets.items() if profile != baseline for pod in pods),
            key=lambda pod: ((pod[0] or ""), pod[1]),
        )
        related = [
            finding
            for entries in grouped.values()
            for finding, entry_target, _pod_key in entries
            if entry_target == target
        ]
        severity = min(
            (str(item.get("severity") or "Info") for item in related),
            key=lambda value: SEVERITY_ORDER.get(value, len(SEVERITIES)),
            default="Medium",
        )
        first_seen = min((str(item.get("first_seen") or "") for item in related), default="")
        last_seen = max((str(item.get("last_seen") or "") for item in related), default="")
        temporal_status, signal_observed_at, _temporal_reason = _merge_temporal_status(related)
        fingerprint = _stable_fingerprint("workload-pod-drift", target[0], target[1], target[2])
        evidence = {
            "workload": {"resource_kind": target[0], "namespace": target[1], "resource_name": target[2]},
            "outliers": [
                {
                    "namespace": namespace,
                    "resource_kind": "Pod",
                    "resource_name": name,
                    "findings": sorted(pod_profiles[(namespace, name)]),
                }
                for namespace, name in outliers[:25]
            ],
            "peer_profiles": [
                {
                    "resource_names": sorted(name for _namespace, name in pods)[:25],
                    "findings": list(profile),
                }
                for profile, pods in sorted(buckets.items(), key=lambda entry: (-len(entry[1]), len(entry[0]), entry[0]))
            ],
            "total_pods": len(pod_profiles),
        }
        aggregated.append(
            {
                "fingerprint": fingerprint,
                "finding_id": fingerprint[:12],
                "cluster_name": related[0].get("cluster_name") if related else None,
                "severity": severity,
                "category": "workload-health",
                "namespace": target[1],
                "resource_kind": target[0],
                "resource_name": target[2],
                "resource": f"{target[0]} / {target[1] or '-'} / {target[2]}",
                "title": "Pod health differs from workload peers",
                "description": "At least one pod has a different active finding profile than the other pods in this workload.",
                "recommendation": "Inspect the outlier pods, rollout revision, node placement, events and container logs.",
                "evidence": evidence,
                "evidence_obj": evidence,
                "evidence_json": json.dumps(evidence, ensure_ascii=False, indent=2, default=str),
                "raw_json": target_objects.get(target) or {},
                "raw_obj": target_objects.get(target) or {},
                "first_seen": first_seen,
                "last_seen": last_seen,
                "count": 1,
                "active": 1,
                "temporal_status": temporal_status,
                "signal_observed_at": signal_observed_at,
                "freshness_reason": "Compared across the current pods belonging to this workload.",
                "pod_scope": f"{len(outliers)} of {len(pod_profiles)} pods differ",
                "workload_pod_count": len(pod_profiles),
                "outlier_pod_count": len(outliers),
                "pod_profile_drift": True,
            }
        )

    for target, pods in members.items():
        configuration_buckets: dict[str, list[tuple[str | None, str]]] = defaultdict(list)
        for pod_key in pods:
            pod = observation_pods.get(pod_key) or {}
            configuration_buckets[_pod_configuration_profile(pod)].append(pod_key)
        if len(configuration_buckets) <= 1:
            continue
        baseline = sorted(
            configuration_buckets,
            key=lambda profile: (-len(configuration_buckets[profile]), profile),
        )[0]
        outliers = sorted(
            (
                pod
                for profile, profile_pods in configuration_buckets.items()
                if profile != baseline
                for pod in profile_pods
            ),
            key=lambda pod: ((pod[0] or ""), pod[1]),
        )
        observations_for_target = [
            pod_observations[pod_key]
            for pod_key in pods
            if pod_key in pod_observations
        ]
        first_seen = min(
            (str(observation.get("timestamp") or "") for observation in observations_for_target),
            default="",
        )
        last_seen = max(
            (str(observation.get("timestamp") or "") for observation in observations_for_target),
            default="",
        )
        fingerprint = _stable_fingerprint("workload-pod-configuration-drift", target[0], target[1], target[2])
        evidence = {
            "workload": {"resource_kind": target[0], "namespace": target[1], "resource_name": target[2]},
            "outliers": [
                {
                    "namespace": namespace,
                    "resource_kind": "Pod",
                    "resource_name": name,
                    "configuration_profile": _pod_configuration_profile(observation_pods.get((namespace, name)) or {}),
                }
                for namespace, name in outliers[:25]
            ],
            "peer_profiles": [
                {
                    "configuration_profile": profile,
                    "resource_names": sorted(name for _namespace, name in profile_pods)[:25],
                }
                for profile, profile_pods in sorted(
                    configuration_buckets.items(),
                    key=lambda entry: (-len(entry[1]), entry[0]),
                )
            ],
            "total_pods": len(pods),
        }
        aggregated.append(
            {
                "fingerprint": fingerprint,
                "finding_id": fingerprint[:12],
                "cluster_name": observations_for_target[0].get("cluster_name") if observations_for_target else None,
                "severity": "Medium",
                "category": "configuration",
                "namespace": target[1],
                "resource_kind": target[0],
                "resource_name": target[2],
                "resource": f"{target[0]} / {target[1] or '-'} / {target[2]}",
                "title": "Pod configuration differs from workload peers",
                "description": "The effective Pod specs in this workload do not all have the same configuration profile.",
                "recommendation": "Verify whether a rollout is in progress; otherwise inspect stale replicas, injected sidecars and pod-template differences.",
                "evidence": evidence,
                "evidence_obj": evidence,
                "evidence_json": json.dumps(evidence, ensure_ascii=False, indent=2, default=str),
                "raw_json": target_objects.get(target) or {},
                "raw_obj": target_objects.get(target) or {},
                "first_seen": first_seen,
                "last_seen": last_seen,
                "count": 1,
                "active": 1,
                "temporal_status": "Current",
                "signal_observed_at": None,
                "freshness_reason": "Compared from the effective specs of the current workload pods.",
                "pod_scope": f"{len(outliers)} of {len(pods)} pods differ",
                "workload_pod_count": len(pods),
                "outlier_pod_count": len(outliers),
                "pod_configuration_drift": True,
            }
        )

    return sorted(
        aggregated,
        key=lambda item: (
            SEVERITY_ORDER.get(str(item.get("severity")), len(SEVERITIES)),
            str(item.get("resource_kind") or ""),
            str(item.get("namespace") or ""),
            str(item.get("resource_name") or ""),
            str(item.get("title") or ""),
        ),
    )


def _line_timestamps(lines: list[Any]) -> list[Any]:
    timestamps = []
    for line in lines:
        match = LOG_TIMESTAMP.search(str(line))
        if match:
            parsed = parse_time(match.group(1))
            if parsed:
                timestamps.append(parsed)
    return timestamps


def _restart_timestamp(raw: dict[str, Any], container_name: str | None) -> Any:
    status = raw.get("status") or {}
    candidates = []
    for cstat in (status.get("containerStatuses") or []) + (status.get("initContainerStatuses") or []):
        if container_name and cstat.get("name") != container_name:
            continue
        for state_key, time_key in (("state", "startedAt"), ("lastState", "finishedAt")):
            state = cstat.get(state_key) or {}
            for detail in state.values():
                if isinstance(detail, dict):
                    parsed = parse_time(detail.get(time_key))
                    if parsed:
                        candidates.append(parsed)
    return max(candidates) if candidates else None


def _temporal_status(finding: dict[str, Any], now: Any) -> tuple[str, Any, str]:
    title = finding.get("title")
    evidence = finding.get("evidence_obj") or {}
    observed_at = None
    reason = "Confirmed by the latest snapshot."
    if title == LOG_FINDING_TITLE:
        timestamps = _line_timestamps(evidence.get("matched_lines") or [])
        observed_at = max(timestamps) if timestamps else None
        reason = "Based on the newest matching log entry."
    elif title == RESTART_FINDING_TITLE:
        observed_at = _restart_timestamp(finding.get("raw_obj") or {}, evidence.get("container"))
        reason = "Based on the latest container start or termination timestamp."
    else:
        return "Current", None, reason
    if observed_at is None:
        return "Review", None, "The cumulative signal has no reliable occurrence timestamp."
    if now - observed_at > FRESHNESS_WINDOW:
        return "Historical", observed_at, reason
    return "Current", observed_at, reason


def prepare_findings(
    findings: list[dict[str, Any]],
    now: Any | None = None,
    observations: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    now = now or utcnow()
    prepared = []
    for source in findings:
        item = dict(source)
        item["evidence_obj"] = _as_object(item.get("evidence")) or {}
        item["raw_obj"] = _as_object(item.get("raw_json")) or {}
        if item.get("temporal_status") in {"Current", "Review", "Historical"}:
            status = item["temporal_status"]
            observed_at = parse_time(item.get("signal_observed_at"))
            freshness_reason = item.get("freshness_reason") or "Classified before output transformation."
        else:
            status, observed_at, freshness_reason = _temporal_status(item, now)
        item["temporal_status"] = status
        item["signal_observed_at"] = observed_at.isoformat() if observed_at else None
        item["freshness_reason"] = freshness_reason
        # Spaces around separators create intentional break points in narrow
        # table columns without breaking a resource name character by character.
        item["resource"] = f"{item.get('resource_kind') or '-'} / {item.get('namespace') or '-'} / {item.get('resource_name') or '-'}"
        item["finding_id"] = str(item.get("fingerprint") or "")[:12]
        item["evidence_json"] = json.dumps(item["evidence_obj"], ensure_ascii=False, indent=2, default=str)
        prepared.append(item)
    return _aggregate_workload_findings(prepared, observations or []) if observations is not None else prepared


def filter_findings(findings: list[dict[str, Any]], **filters: str | None) -> list[dict[str, Any]]:
    keys = ("severity", "category", "namespace", "resource_kind")
    return [
        finding
        for finding in findings
        if all(not filters.get(key) or finding.get(key) == filters[key] for key in keys)
    ]


def correlate_incidents(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for finding in findings:
        if finding.get("title") != LOG_FINDING_TITLE:
            continue
        evidence = finding.get("evidence_obj") or {}
        causes = list(evidence.get("suspected_causes") or [])
        if not causes:
            causes = sorted(
                {
                    str(cause)
                    for affected in evidence.get("affected") or []
                    for cause in ((affected.get("evidence") or {}).get("suspected_causes") or [])
                    if cause
                }
            )
        causes = causes or ["unknown"]
        observed = parse_time(finding.get("signal_observed_at"))
        bucket = observed.strftime("%Y-%m-%dT%H:00Z") if observed else "undated"
        groups[(str(causes[0]), bucket)].append(finding)
    incidents = []
    for (cause, bucket), items in groups.items():
        resources = sorted({item["resource"] for item in items})
        statuses = {item["temporal_status"] for item in items}
        severity = next((level for level in SEVERITIES if any(item.get("severity") == level for item in items)), "Info")
        incidents.append(
            {
                "id": f"INC-{len(incidents) + 1:03d}",
                "cause": cause,
                "title": INCIDENT_LABELS.get(cause, cause.replace("_", " ").title()),
                "time_bucket": bucket,
                "temporal_status": "Current" if "Current" in statuses else "Review" if "Review" in statuses else "Historical",
                "severity": severity,
                "resources": resources,
                "resource_count": len(resources),
                "finding_count": len(items),
            }
        )
    order = {"Current": 0, "Review": 1, "Historical": 2}
    severity_order = {level: index for index, level in enumerate(SEVERITIES)}
    return sorted(incidents, key=lambda item: (order[item["temporal_status"]], severity_order[item["severity"]], item["time_bucket"]))


def build_audit_view(findings: list[dict[str, Any]], events_last_hour: int = 0, now: Any | None = None) -> dict[str, Any]:
    prepared = prepare_findings(findings, now)
    current = [item for item in prepared if item["temporal_status"] == "Current"]
    review = [item for item in prepared if item["temporal_status"] == "Review"]
    historical = [item for item in prepared if item["temporal_status"] == "Historical"]
    severity_counts = {severity: sum(1 for item in current if item.get("severity") == severity) for severity in SEVERITIES}
    problematic_pods: set[tuple[Any, Any, Any]] = set()
    for item in current:
        if item.get("severity") not in {"Critical", "High", "Medium"}:
            continue
        if item.get("resource_kind") == "Pod":
            problematic_pods.add((item.get("cluster_name"), item.get("namespace"), item.get("resource_name")))
        for pod in item.get("affected_pod_resources") or []:
            problematic_pods.add((item.get("cluster_name"), pod.get("namespace"), pod.get("resource_name")))
    category_counts: dict[str, int] = defaultdict(int)
    for item in current:
        category_counts[str(item.get("category") or "unknown")] += 1
    incidents = correlate_incidents(prepared)
    return {
        "findings": prepared,
        "current_findings": current,
        "review_findings": review,
        "historical_findings": historical,
        "incidents": incidents,
        "current_incidents": [item for item in incidents if item["temporal_status"] == "Current"],
        "summary": {
            "events_last_hour": events_last_hour,
            "problematic_pods": len(problematic_pods),
            "findings_by_severity": severity_counts,
            "current_findings": len(current),
            "review_findings": len(review),
            "historical_findings": len(historical),
            "incidents": len(incidents),
            "current_incidents": sum(1 for item in incidents if item["temporal_status"] == "Current"),
        },
        "finding_counts_by_category": dict(sorted(category_counts.items(), key=lambda pair: (-pair[1], pair[0]))),
    }

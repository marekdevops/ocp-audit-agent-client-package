from __future__ import annotations

from typing import Any


# These objects are useful for live diagnosis and workload correlation.  Their
# current observation retains the redacted API object; all other kinds are
# stored as a compact inventory projection.
FULL_RAW_KINDS = {
    "Pod", "Node", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet",
    "ReplicationController", "Job", "CronJob", "PersistentVolume",
    "PersistentVolumeClaim", "StorageClass", "CSIDriver", "CSINode",
    "CSIStorageCapacity", "VolumeAttachment", "NetworkPolicy",
    "NetworkAttachmentDefinition", "CNIComponent", "APIService", "Route",
    "ClusterVersion", "ClusterOperator", "MachineConfigPool",
}


def _metadata(value: dict[str, Any]) -> dict[str, Any]:
    source = value.get("metadata") or {}
    return {
        key: source[key]
        for key in ("name", "namespace", "uid", "generation", "creationTimestamp", "labels", "ownerReferences")
        if key in source
    }


def _conditions(value: Any) -> list[dict[str, Any]]:
    return [
        {key: item[key] for key in ("type", "status", "reason", "message", "lastTransitionTime") if key in item}
        for item in (value or [])
        if isinstance(item, dict)
    ]


def compact_observation(raw: dict[str, Any], kind: str) -> dict[str, Any]:
    """Keep a useful inventory/status projection without arbitrary byte limits."""
    status = raw.get("status")
    compact_status: dict[str, Any] = {}
    if isinstance(status, dict):
        compact_status = {
            key: value for key, value in status.items()
            if key in {"phase", "observedGeneration", "replicas", "readyReplicas", "availableReplicas", "updatedReplicas", "currentReplicas", "conditions"}
        }
        if "conditions" in compact_status:
            compact_status["conditions"] = _conditions(compact_status["conditions"])
    result: dict[str, Any] = {
        "apiVersion": raw.get("apiVersion"),
        "kind": raw.get("kind") or kind,
        "metadata": _metadata(raw),
    }
    if compact_status:
        result["status"] = compact_status
    if "auditPodInventory" in raw:
        result["auditPodInventory"] = raw["auditPodInventory"]
    return result


def stored_observation(raw: dict[str, Any], kind: str) -> dict[str, Any]:
    return raw if kind in FULL_RAW_KINDS else compact_observation(raw, kind)

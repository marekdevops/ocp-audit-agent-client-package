from __future__ import annotations

import logging
import json
from functools import lru_cache

from kubernetes import client
from kubernetes.client import ApiException

LOG = logging.getLogger(__name__)


def _discovery_document(path: str) -> dict:
    """Return an undecoded Kubernetes discovery response as a JSON object.

    Kubernetes client 36 returns an HTTPResponse when ``_preload_content`` is
    false. Older versions returned a ``(response, status, headers)`` tuple;
    accepting both keeps discovery reliable across supported client versions.
    """
    response = client.ApiClient().call_api(
        path,
        "GET",
        response_types_map={},
        # Raw call_api does not add the in-cluster bearer token unless the
        # generated endpoint's auth setting is supplied explicitly.
        auth_settings=["BearerToken"],
        _preload_content=False,
    )
    if isinstance(response, tuple):
        response = response[0]
    payload = getattr(response, "data", response)
    if isinstance(payload, bytes):
        payload = payload.decode("utf-8")
    return json.loads(payload)


@lru_cache(maxsize=1)
def api_resources() -> set[tuple[str, str]]:
    found: set[tuple[str, str]] = set()
    api = client.ApisApi()
    try:
        groups = api.get_api_versions().groups
        for group in groups:
            for version in group.versions:
                gv = version.group_version
                try:
                    payload = _discovery_document(f"/apis/{gv}")
                    for item in payload.get("resources", []):
                        if "/" not in item.get("name", ""):
                            found.add((gv, item["name"]))
                except Exception as exc:
                    LOG.debug("cannot discover %s: %s", gv, exc)
    except Exception as exc:
        LOG.warning("API discovery failed: %s", exc)
    try:
        for item in _discovery_document("/api/v1").get("resources", []):
            if "/" not in item.get("name", ""):
                found.add(("v1", item["name"]))
    except Exception:
        pass
    return found


def has_resource(group_version: str, plural: str) -> bool:
    return (group_version, plural) in api_resources()


def list_custom(group: str, version: str, plural: str, namespace: str | None = None) -> list[dict]:
    co = client.CustomObjectsApi()
    try:
        if namespace:
            data = co.list_namespaced_custom_object(group, version, namespace, plural)
        else:
            data = co.list_cluster_custom_object(group, version, plural)
        return data.get("items", [])
    except ApiException as exc:
        if exc.status == 404:
            LOG.warning("API %s/%s %s not available", group, version, plural)
            return []
        raise

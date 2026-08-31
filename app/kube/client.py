from __future__ import annotations

import logging
import os

from kubernetes import client, config

LOG = logging.getLogger(__name__)


def load_kube_config() -> str:
    try:
        config.load_incluster_config()
        LOG.info("using in-cluster Kubernetes config")
        return "in-cluster"
    except config.ConfigException:
        kubeconfig = os.getenv("KUBECONFIG")
        config.load_kube_config(config_file=kubeconfig)
        LOG.info("using kubeconfig%s", f" {kubeconfig}" if kubeconfig else "")
        return "kubeconfig"


def api_client() -> client.ApiClient:
    return client.ApiClient()


def cluster_name(default: str) -> str:
    if default and default != "auto":
        return default
    try:
        contexts, active = config.list_kube_config_contexts()
        if active and active.get("name"):
            return active["name"]
    except Exception:
        pass
    return "in-cluster"


def sanitize_api_exception(exc: Exception) -> str:
    status = getattr(exc, "status", None)
    reason = getattr(exc, "reason", None)
    body = getattr(exc, "body", None)
    return f"status={status} reason={reason} body={str(body)[:400]}"

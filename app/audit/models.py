from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class Finding:
    fingerprint: str
    severity: str
    category: str
    title: str
    description: str
    recommendation: str
    namespace: str | None = None
    resource_kind: str | None = None
    resource_name: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    raw_json: dict[str, Any] = field(default_factory=dict)

    def to_record(self, cluster_name: str) -> dict[str, Any]:
        data = asdict(self)
        data["cluster_name"] = cluster_name
        return data

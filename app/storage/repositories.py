from __future__ import annotations

import os
from datetime import timedelta
from typing import Any

from app.audit.redaction import redact, redact_text
from app.storage.db import Database
from app.storage.projection import compact_observation, stored_observation
from app.utils.json import dumps, loads
from app.utils.time import iso_now, utcnow

JOB_STALE_AFTER_MINUTES = 35


def _rows(cur) -> list[dict[str, Any]]:
    return [dict(row) for row in cur.fetchall()]


def _values(cur) -> list[str]:
    values = [(next(iter(row.values())) if isinstance(row, dict) else row[0]) for row in cur.fetchall()]
    return [str(value) for value in values if value not in (None, "")]


class AuditRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def add_event(self, event: dict[str, Any]) -> int:
        event = dict(event)
        event["message"] = redact_text(event.get("message"))
        event["raw_json"] = dumps(redact(event.get("raw_json", {})))
        with self.db.transaction() as conn:
            if event.get("uid"):
                cur = conn.execute(
                    """
                    UPDATE events
                    SET timestamp=:timestamp, namespace=:namespace, reason=:reason, type=:type, message=:message,
                      involved_kind=:involved_kind, involved_name=:involved_name, source_component=:source_component,
                      severity=:severity, raw_json=:raw_json
                    WHERE cluster_name=:cluster_name AND uid=:uid
                    """,
                    event,
                )
                if cur.rowcount:
                    row = conn.execute("SELECT id FROM events WHERE cluster_name=? AND uid=?", (event["cluster_name"], event["uid"])).fetchone()
                    return int(row["id"])
            cur = conn.execute(
                """
                INSERT INTO events(uid, cluster_name, timestamp, namespace, reason, type, message,
                  involved_kind, involved_name, source_component, severity, raw_json)
                VALUES(:uid, :cluster_name, :timestamp, :namespace, :reason, :type, :message,
                  :involved_kind, :involved_name, :source_component, :severity, :raw_json)
                RETURNING id
                """,
                event,
            )
            return int(cur.fetchone()["id"])

    def upsert_finding(self, finding: dict[str, Any]) -> None:
        now = iso_now()
        finding = dict(finding)
        finding.setdefault("first_seen", now)
        finding["last_seen"] = now
        finding["evidence"] = dumps(redact(finding.get("evidence", {})))
        finding["raw_json"] = dumps(redact(finding.get("raw_json", {})))
        with self.db.transaction() as conn:
            conn.execute(
                """
                INSERT INTO findings(fingerprint, cluster_name, severity, category, namespace, resource_kind,
                  resource_name, title, description, evidence, recommendation, first_seen, last_seen, count, active, raw_json)
                VALUES(:fingerprint, :cluster_name, :severity, :category, :namespace, :resource_kind,
                  :resource_name, :title, :description, :evidence, :recommendation, :first_seen, :last_seen, 1, 1, :raw_json)
                ON CONFLICT(fingerprint) DO UPDATE SET
                  severity=excluded.severity, title=excluded.title, description=excluded.description,
                  evidence=excluded.evidence, recommendation=excluded.recommendation, last_seen=excluded.last_seen,
                  count=findings.count+1, active=1, raw_json=excluded.raw_json
                """,
                finding,
            )

    def deactivate_findings_not_seen_since(
        self,
        cluster_name: str,
        cutoff: str,
        excluded_resource_kinds: set[str] | None = None,
    ) -> int:
        excluded = sorted(excluded_resource_kinds or set())
        sql = "UPDATE findings SET active=0 WHERE cluster_name=? AND active=1 AND last_seen < ?"
        params: list[Any] = [cluster_name, cutoff]
        if excluded:
            sql += f" AND resource_kind NOT IN ({','.join('?' for _ in excluded)})"
            params.extend(excluded)
        with self.db.transaction() as conn:
            cur = conn.execute(sql, params)
            return cur.rowcount

    def add_observation(self, obs: dict[str, Any], preserve_audit_inventory: bool = False, pod_event_type: str | None = None) -> None:
        obs = dict(obs)
        obs["status"] = redact_text(obs.get("status"))
        raw = redact(obs.get("raw_json", {}))
        obs["raw_json"] = dumps(stored_observation(raw, str(obs.get("kind") or "")))
        history_raw_json = dumps(compact_observation(raw, str(obs.get("kind") or "")))
        with self.db.transaction() as conn:
            existing = None
            if obs.get("name"):
                existing = conn.execute(
                    """
                    SELECT api_version, status, raw_json FROM resource_observations
                    WHERE cluster_name=:cluster_name AND kind=:kind
                      AND COALESCE(namespace, '')=COALESCE(:namespace, '') AND name=:name
                    """,
                    obs,
                ).fetchone()
                if preserve_audit_inventory:
                    existing_raw = loads(existing["raw_json"], {}) if existing else {}
                    inventory = existing_raw.get("auditPodInventory") if isinstance(existing_raw, dict) else None
                    # Preserve the calculated Pod inventory when a watcher update
                    # does not include it, without retaining a full historical Pod.
                    if inventory and "auditPodInventory" not in raw:
                        raw["auditPodInventory"] = inventory
                        obs["raw_json"] = dumps(stored_observation(raw, str(obs.get("kind") or "")))
                        history_raw_json = dumps(compact_observation(raw, str(obs.get("kind") or "")))
            event_type = pod_event_type or "SNAPSHOT"
            if obs.get("kind") == "Pod" and obs.get("name") and event_type == "DELETED":
                conn.execute(
                    """
                    INSERT INTO pod_observation_history(cluster_name, observed_at, event_type, namespace, name, status, raw_json)
                    VALUES(:cluster_name, :timestamp, :pod_event_type, :namespace, :name, :status, :raw_json)
                    """,
                    {**obs, "raw_json": history_raw_json, "pod_event_type": event_type},
                )
            if event_type == "DELETED" and obs.get("name"):
                conn.execute(
                    """
                    DELETE FROM resource_observations
                    WHERE cluster_name=:cluster_name AND kind=:kind
                      AND COALESCE(namespace, '')=COALESCE(:namespace, '') AND name=:name
                    """,
                    obs,
                )
                return
            if obs.get("name"):
                cur = conn.execute(
                    """
                    UPDATE resource_observations
                    SET timestamp=:timestamp, api_version=:api_version, status=:status, raw_json=:raw_json
                    WHERE cluster_name=:cluster_name
                      AND kind=:kind
                      AND COALESCE(namespace, '')=COALESCE(:namespace, '')
                      AND name=:name
                    """,
                    obs,
                )
                if cur.rowcount:
                    return
            conn.execute(
                """
                INSERT INTO resource_observations(cluster_name, timestamp, api_version, kind, namespace, name, status, raw_json)
                VALUES(:cluster_name, :timestamp, :api_version, :kind, :namespace, :name, :status, :raw_json)
                """,
                obs,
            )

    def reconcile_observations_not_seen_since(self, cluster_name: str, cutoff: str, checked_kinds: set[str]) -> int:
        kinds = sorted(checked_kinds)
        if not kinds:
            return 0
        placeholders = ",".join("?" for _ in kinds)
        with self.db.transaction() as conn:
            rows = conn.execute(
                f"""
                SELECT * FROM resource_observations
                WHERE cluster_name=? AND timestamp < ? AND kind IN ({placeholders})
                """,
                [cluster_name, cutoff, *kinds],
            ).fetchall()
            for row in rows:
                if row["kind"] == "Pod" and row["name"]:
                    conn.execute(
                        """
                        INSERT INTO pod_observation_history(
                          cluster_name, observed_at, event_type, namespace, name, status, raw_json
                        ) VALUES(?, ?, 'MISSING_FROM_SNAPSHOT', ?, ?, ?, ?)
                        """,
                        (
                            row["cluster_name"], cutoff, row["namespace"], row["name"],
                            row["status"], row["raw_json"] or "{}",
                        ),
                    )
            if rows:
                conn.execute(
                    f"""
                    DELETE FROM resource_observations
                    WHERE cluster_name=? AND timestamp < ? AND kind IN ({placeholders})
                    """,
                    [cluster_name, cutoff, *kinds],
                )
            return len(rows)

    def prune_history(self, retention_days: int) -> dict[str, int]:
        cutoff = (utcnow() - timedelta(days=retention_days)).isoformat()
        with self.db.transaction() as conn:
            return {
                "events": conn.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,)).rowcount,
                "resource_history": conn.execute("DELETE FROM resource_observation_history WHERE observed_at < ?", (cutoff,)).rowcount,
                "pod_history": conn.execute("DELETE FROM pod_observation_history WHERE observed_at < ?", (cutoff,)).rowcount,
            }

    def deactivate_findings_for_resource(
        self,
        cluster_name: str,
        kind: str,
        namespace: str | None,
        name: str | None,
    ) -> int:
        if not name:
            return 0
        with self.db.transaction() as conn:
            cur = conn.execute(
                """
                UPDATE findings SET active=0
                WHERE cluster_name=? AND resource_kind=? AND COALESCE(namespace, '')=COALESCE(?, '')
                  AND resource_name=? AND active=1
                """,
                (cluster_name, kind, namespace, name),
            )
            return cur.rowcount

    def create_job(self, job_type: str, message: str | None = None) -> int:
        with self.db.transaction() as conn:
            cur = conn.execute(
                "INSERT INTO jobs(job_type, status, started_at, message) VALUES(?, 'running', ?, ?) RETURNING id",
                (job_type, iso_now(), message),
            )
            return int(cur.fetchone()["id"])

    def create_job_if_not_running(self, job_type: str, message: str | None = None) -> int | None:
        """Atomically reserve a job slot and recover abandoned workload records."""
        with self.db.transaction() as conn:
            now = iso_now()
            stale_before = (utcnow() - timedelta(minutes=JOB_STALE_AFTER_MINUTES)).isoformat()
            conn.execute(
                """
                UPDATE jobs
                SET status='failed', finished_at=?, error='Job exceeded its execution deadline or its worker disappeared'
                WHERE job_type=? AND status='running' AND started_at < ?
                """,
                (now, job_type, stale_before),
            )
            cur = conn.execute(
                "INSERT INTO jobs(job_type, status, started_at, message) VALUES(?, 'running', ?, ?) ON CONFLICT DO NOTHING RETURNING id",
                (job_type, now, message),
            )
            row = cur.fetchone()
            return int(row["id"]) if row else None

    def finish_job(
        self,
        job_id: int,
        status: str,
        message: str | None = None,
        error: str | None = None,
        report_id: int | None = None,
    ) -> None:
        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE jobs SET status=?, finished_at=?, message=?, error=?, report_id=? WHERE id=?",
                (status, iso_now(), message, error, report_id, job_id),
            )

    def create_snapshot(self, cluster_name: str) -> int:
        with self.db.transaction() as conn:
            cur = conn.execute(
                "INSERT INTO snapshots(cluster_name, started_at, status) VALUES(?, ?, 'running') RETURNING id",
                (cluster_name, iso_now()),
            )
            return int(cur.fetchone()["id"])

    def finish_snapshot(self, snapshot_id: int, status: str, summary: dict[str, Any], error: str | None = None) -> None:
        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE snapshots SET finished_at=?, status=?, summary_json=?, error=? WHERE id=?",
                (iso_now(), status, dumps(summary), error, snapshot_id),
            )

    def add_report(self, fmt: str, path: str, summary: dict[str, Any]) -> int:
        size = os.path.getsize(path) if os.path.exists(path) else 0
        with self.db.transaction() as conn:
            cur = conn.execute(
                "INSERT INTO reports(format, path, created_at, size_bytes, summary_json) VALUES(?, ?, ?, ?, ?) RETURNING id",
                (fmt, path, iso_now(), size, dumps(summary)),
            )
            return int(cur.fetchone()["id"])

    def save_filter(self, page: str, name: str, filters: dict[str, Any]) -> int:
        now = iso_now()
        with self.db.transaction() as conn:
            conn.execute(
                """
                INSERT INTO saved_filters(name, page, filters_json, created_at, updated_at)
                VALUES(?, ?, ?, ?, ?)
                ON CONFLICT(page, name) DO UPDATE SET
                  filters_json=excluded.filters_json,
                  updated_at=excluded.updated_at
                """,
                (name.strip(), page, dumps(filters), now, now),
            )
            row = conn.execute("SELECT id FROM saved_filters WHERE page=? AND name=?", (page, name.strip())).fetchone()
            return int(row["id"])

    def list_saved_filters(self, page: str) -> list[dict[str, Any]]:
        with self.db.session() as conn:
            rows = _rows(conn.execute("SELECT * FROM saved_filters WHERE page=? ORDER BY updated_at DESC, name ASC", (page,)))
        for row in rows:
            row["filters"] = loads(row.get("filters_json"), {})
        return rows

    def delete_saved_filter(self, filter_id: int, page: str | None = None) -> None:
        with self.db.transaction() as conn:
            if page:
                conn.execute("DELETE FROM saved_filters WHERE id=? AND page=?", (filter_id, page))
            else:
                conn.execute("DELETE FROM saved_filters WHERE id=?", (filter_id,))

    def event_filter_options(self) -> dict[str, list[str]]:
        with self.db.session() as conn:
            return {
                "namespaces": _values(conn.execute("SELECT DISTINCT namespace FROM events WHERE namespace IS NOT NULL AND namespace != '' ORDER BY namespace")),
                "reasons": _values(conn.execute("SELECT DISTINCT reason FROM events WHERE reason IS NOT NULL AND reason != '' ORDER BY reason")),
                "types": _values(conn.execute("SELECT DISTINCT type FROM events WHERE type IS NOT NULL AND type != '' ORDER BY type")),
                "involved_kinds": _values(conn.execute("SELECT DISTINCT involved_kind FROM events WHERE involved_kind IS NOT NULL AND involved_kind != '' ORDER BY involved_kind")),
                "severities": _values(conn.execute("SELECT severity FROM (SELECT DISTINCT severity FROM events WHERE severity IS NOT NULL AND severity != '') AS distinct_severities ORDER BY CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END, severity")),
            }

    def finding_filter_options(self) -> dict[str, list[str]]:
        with self.db.session() as conn:
            return {
                "severities": _values(conn.execute("SELECT severity FROM (SELECT DISTINCT severity FROM findings WHERE severity IS NOT NULL AND severity != '') AS distinct_severities ORDER BY CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END, severity")),
                "categories": _values(conn.execute("SELECT DISTINCT category FROM findings WHERE category IS NOT NULL AND category != '' ORDER BY category")),
                "namespaces": _values(conn.execute("SELECT DISTINCT namespace FROM findings WHERE namespace IS NOT NULL AND namespace != '' ORDER BY namespace")),
                "resource_kinds": _values(conn.execute("SELECT DISTINCT resource_kind FROM findings WHERE resource_kind IS NOT NULL AND resource_kind != '' ORDER BY resource_kind")),
            }

    def list_events(self, limit: int = 200, offset: int = 0, **filters: str | None) -> list[dict[str, Any]]:
        where, params = [], []
        for key in ("namespace", "reason", "type", "involved_kind", "severity"):
            if filters.get(key):
                where.append(f"{key} = ?")
                params.append(filters[key])
        sql = "SELECT * FROM events"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend((limit, offset))
        with self.db.session() as conn:
            return _rows(conn.execute(sql, params))

    def count_events(self, **filters: str | None) -> int:
        where, params = [], []
        for key in ("namespace", "reason", "type", "involved_kind", "severity"):
            if filters.get(key):
                where.append(f"{key} = ?")
                params.append(filters[key])
        sql = "SELECT count(*) AS count FROM events"
        if where:
            sql += " WHERE " + " AND ".join(where)
        with self.db.session() as conn:
            return int(conn.execute(sql, params).fetchone()["count"])

    def events_after_id(self, last_id: int, limit: int = 100) -> list[dict[str, Any]]:
        with self.db.session() as conn:
            return _rows(conn.execute("SELECT * FROM events WHERE id > ? ORDER BY id ASC LIMIT ?", (last_id, limit)))

    def list_findings(self, active_only: bool = True, limit: int = 500, offset: int = 0, **filters: str | None) -> list[dict[str, Any]]:
        where, params = [], []
        if active_only:
            where.append("active = 1")
        for key in ("severity", "category", "namespace", "resource_kind", "title"):
            if filters.get(key):
                where.append(f"{key} = ?")
                params.append(filters[key])
        sql = "SELECT * FROM findings"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END, last_seen DESC LIMIT ? OFFSET ?"
        params.extend((limit, offset))
        with self.db.session() as conn:
            return _rows(conn.execute(sql, params))

    def count_findings(self, active_only: bool = True, **filters: str | None) -> int:
        where, params = [], []
        if active_only:
            where.append("active = 1")
        for key in ("severity", "category", "namespace", "resource_kind", "title"):
            if filters.get(key):
                where.append(f"{key} = ?")
                params.append(filters[key])
        sql = "SELECT count(*) AS count FROM findings"
        if where:
            sql += " WHERE " + " AND ".join(where)
        with self.db.session() as conn:
            return int(conn.execute(sql, params).fetchone()["count"])

    def finding_counts_by_category(self) -> dict[str, int]:
        with self.db.session() as conn:
            return {
                row["category"]: int(row["count"])
                for row in conn.execute(
                    "SELECT category, count(*) AS count FROM findings WHERE active=1 GROUP BY category ORDER BY count DESC, category"
                )
            }

    def list_jobs(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.db.session() as conn:
            return _rows(conn.execute("SELECT * FROM jobs ORDER BY started_at DESC LIMIT ?", (limit,)))

    def list_reports(self) -> list[dict[str, Any]]:
        with self.db.session() as conn:
            return _rows(conn.execute("SELECT * FROM reports ORDER BY created_at DESC"))

    def list_snapshots(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.db.session() as conn:
            return _rows(conn.execute("SELECT * FROM snapshots ORDER BY started_at DESC LIMIT ?", (limit,)))

    def latest_snapshot_summary(self) -> dict[str, Any]:
        with self.db.session() as conn:
            row = conn.execute(
                """
                SELECT status, started_at, finished_at, summary_json, error
                FROM snapshots
                WHERE status = 'success'
                ORDER BY finished_at DESC, started_at DESC
                LIMIT 1
                """
            ).fetchone()
        if not row:
            return {}
        return {
            "status": row["status"],
            "started_at": row["started_at"],
            "finished_at": row["finished_at"],
            "error": row["error"],
            **loads(row["summary_json"], {}),
        }

    def latest_observations(self, kind: str, limit: int = 100, offset: int = 0, namespace: str | None = None, name: str | None = None) -> list[dict[str, Any]]:
        where = ["kind=?"]
        params: list[Any] = [kind]
        if namespace:
            where.append("namespace=?")
            params.append(namespace)
        if name:
            where.append("name LIKE ?")
            params.append(f"%{name}%")
        params.extend((limit, offset))
        with self.db.session() as conn:
            rows = _rows(
                conn.execute(
                    f"SELECT * FROM resource_observations WHERE {' AND '.join(where)} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                    params,
                )
            )
        for row in rows:
            row["raw"] = loads(row.get("raw_json"), {})
        return rows

    def count_observations(self, kind: str, namespace: str | None = None, name: str | None = None) -> int:
        where = ["kind=?"]
        params: list[Any] = [kind]
        if namespace:
            where.append("namespace=?")
            params.append(namespace)
        if name:
            where.append("name LIKE ?")
            params.append(f"%{name}%")
        with self.db.session() as conn:
            return int(
                conn.execute(
                    f"SELECT count(*) AS count FROM resource_observations WHERE {' AND '.join(where)}",
                    params,
                ).fetchone()["count"]
            )

    def list_pod_history(self, limit: int = 5000, include_raw: bool = True, offset: int = 0, **filters: str | None) -> list[dict[str, Any]]:
        where = ["event_type IN ('DELETED', 'MISSING_FROM_SNAPSHOT')"]
        params: list[Any] = []
        for key in ("namespace", "event_type"):
            if filters.get(key):
                where.append(f"{key} = ?")
                params.append(filters[key])
        if filters.get("name"):
            where.append("name LIKE ?")
            params.append(f"%{filters['name']}%")
        sql = "SELECT * FROM pod_observation_history"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY observed_at DESC, id DESC LIMIT ?"
        params.append(limit + offset + 250)
        with self.db.session() as conn:
            rows = _rows(conn.execute(sql, params))
            current = _rows(
                conn.execute(
                    "SELECT cluster_name, namespace, name, raw_json FROM resource_observations WHERE kind='Pod'"
                )
            )

        current_uids: set[tuple[str, str, str]] = set()
        current_names: set[tuple[str, str, str]] = set()
        for row in current:
            raw = loads(row.get("raw_json"), {})
            uid = str(((raw.get("metadata") or {}).get("uid") or ""))
            name_key = (str(row.get("cluster_name") or ""), str(row.get("namespace") or ""), str(row.get("name") or ""))
            current_names.add(name_key)
            if uid:
                current_uids.add((name_key[0], name_key[1], uid))

        result = []
        seen: set[tuple[str, ...]] = set()
        for row in rows:
            raw = loads(row.get("raw_json"), {})
            metadata = raw.get("metadata") or {}
            uid = str(metadata.get("uid") or "")
            name_key = (str(row.get("cluster_name") or ""), str(row.get("namespace") or ""), str(row.get("name") or ""))
            if uid:
                lifecycle_key = (name_key[0], name_key[1], uid)
                if lifecycle_key in current_uids or lifecycle_key in seen:
                    continue
            else:
                lifecycle_key = name_key
                if name_key in current_names or lifecycle_key in seen:
                    continue
            seen.add(lifecycle_key)
            row["timestamp"] = row["observed_at"]
            row["appeared_at"] = metadata.get("creationTimestamp")
            row["disappeared_at"] = row["observed_at"]
            if include_raw:
                row["raw"] = raw
            else:
                row.pop("raw_json", None)
            result.append(row)
        return result[offset:offset + limit]

    def count_pod_history(self, **filters: str | None) -> int:
        where = ["event_type IN ('DELETED', 'MISSING_FROM_SNAPSHOT')"]
        params: list[Any] = []
        for key in ("namespace", "event_type"):
            if filters.get(key):
                where.append(f"{key} = ?")
                params.append(filters[key])
        if filters.get("name"):
            where.append("name LIKE ?")
            params.append(f"%{filters['name']}%")
        with self.db.session() as conn:
            return int(
                conn.execute(
                    f"SELECT count(*) AS count FROM pod_observation_history WHERE {' AND '.join(where)}",
                    params,
                ).fetchone()["count"]
            )

    def list_resource_history(self, limit: int = 5000, **filters: str | None) -> list[dict[str, Any]]:
        where: list[str] = []
        params: list[Any] = []
        for key in ("kind", "namespace", "event_type"):
            if filters.get(key):
                where.append(f"{key} = ?")
                params.append(filters[key])
        if filters.get("name"):
            where.append("name LIKE ?")
            params.append(f"%{filters['name']}%")
        sql = "SELECT * FROM resource_observation_history"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY observed_at DESC, id DESC LIMIT ?"
        params.append(limit)
        with self.db.session() as conn:
            rows = _rows(conn.execute(sql, params))
        for row in rows:
            row["timestamp"] = row["observed_at"]
            row["raw"] = loads(row.get("raw_json"), {})
        return rows

    def resource_history_filter_options(self) -> dict[str, list[str]]:
        with self.db.session() as conn:
            return {
                "kinds": ["Pod"],
                "namespaces": _values(
                    conn.execute(
                        """
                        SELECT DISTINCT namespace FROM pod_observation_history
                        WHERE event_type IN ('DELETED', 'MISSING_FROM_SNAPSHOT')
                          AND namespace IS NOT NULL AND namespace != ''
                        ORDER BY namespace
                        """
                    )
                ),
                "event_types": _values(conn.execute("SELECT DISTINCT event_type FROM pod_observation_history WHERE event_type IN ('DELETED', 'MISSING_FROM_SNAPSHOT') ORDER BY event_type")),
            }

    def pod_filter_options(self) -> dict[str, list[str]]:
        with self.db.session() as conn:
            return {
                "namespaces": _values(
                    conn.execute(
                        """
                        SELECT namespace FROM resource_observations
                        WHERE kind='Pod' AND namespace IS NOT NULL AND namespace != ''
                        UNION
                        SELECT namespace FROM pod_observation_history
                        WHERE event_type IN ('DELETED', 'MISSING_FROM_SNAPSHOT')
                          AND namespace IS NOT NULL AND namespace != ''
                        ORDER BY namespace
                        """
                    )
                ),
                "event_types": _values(
                    conn.execute(
                        """
                        SELECT DISTINCT event_type FROM pod_observation_history
                        WHERE event_type IN ('DELETED', 'MISSING_FROM_SNAPSHOT')
                        ORDER BY event_type
                        """
                    )
                ),
            }

    def list_observations(self, limit: int = 5000, kinds: set[str] | None = None) -> list[dict[str, Any]]:
        params: list[Any] = []
        sql = "SELECT * FROM resource_observations"
        if kinds:
            ordered_kinds = sorted(kinds)
            sql += f" WHERE kind IN ({','.join('?' for _ in ordered_kinds)})"
            params.extend(ordered_kinds)
        sql += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        with self.db.session() as conn:
            rows = _rows(conn.execute(sql, params))
        for row in rows:
            row["raw"] = loads(row.get("raw_json"), {})
        return rows

    def observation_counts_by_kind(self) -> dict[str, int]:
        with self.db.session() as conn:
            return {row["kind"]: row["count"] for row in conn.execute("SELECT kind, count(*) count FROM resource_observations GROUP BY kind ORDER BY kind")}

    def summary(self) -> dict[str, Any]:
        since = (utcnow() - timedelta(hours=1)).isoformat()
        with self.db.session() as conn:
            events_last_hour = conn.execute("SELECT count(*) AS count FROM events WHERE timestamp >= ?", (since,)).fetchone()["count"]
            sev = {row["severity"]: row["count"] for row in conn.execute("SELECT severity, count(*) count FROM findings WHERE active=1 GROUP BY severity")}
            bad_pods = conn.execute(
                """
                SELECT count(*) AS count
                FROM (
                    SELECT DISTINCT cluster_name, COALESCE(namespace, ''), COALESCE(resource_name, '')
                    FROM findings
                    WHERE active=1 AND resource_kind='Pod' AND severity IN ('Critical','High','Medium')
                ) AS problematic_pods
                """
            ).fetchone()["count"]
        return {"events_last_hour": events_last_hour, "findings_by_severity": sev, "problematic_pods": bad_pods}

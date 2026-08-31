from __future__ import annotations

import os
import re
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from app.storage.migrations import POSTGRES_SCHEMA, SCHEMA

POSTGRES_SCHEMA_VERSION = 2
POSTGRES_MIGRATION_LOCK_ID = 684_217_903


def _postgres_sql(sql: str) -> str:
    """Translate the small SQLite DB-API subset used by the repository."""
    sql = re.sub(r"(?<!:):(\w+)", r"%(\1)s", sql)
    return sql.replace("?", "%s")


class PostgresConnection:
    def __init__(self, connection: Any) -> None:
        self.connection = connection

    def execute(self, sql: str, params: Any = None):
        return self.connection.execute(_postgres_sql(sql), params)

    def commit(self) -> None:
        self.connection.commit()

    def rollback(self) -> None:
        self.connection.rollback()

    def close(self) -> None:
        self.connection.close()


class Database:
    def __init__(self, path: str, database_url: str = "", database_password: str = "") -> None:
        self.path = path
        self.database_url = database_url.strip()
        self.database_password = database_password
        self.is_postgres = self.database_url.startswith(("postgres://", "postgresql://"))
        if not self.is_postgres:
            Path(os.path.dirname(path) or ".").mkdir(parents=True, exist_ok=True)

    def connect(self):
        if self.is_postgres:
            import psycopg
            from psycopg.rows import dict_row

            return PostgresConnection(psycopg.connect(self.database_url, password=self.database_password or None, row_factory=dict_row))
        conn = sqlite3.connect(self.path, timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=10000")
        return conn

    def init(self) -> None:
        with self.session() as conn:
            if self.is_postgres:
                conn.execute("SELECT pg_advisory_xact_lock(?)", (POSTGRES_MIGRATION_LOCK_ID,))
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS app_schema_migrations (
                        version INTEGER PRIMARY KEY,
                        applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                )
                row = conn.execute("SELECT COALESCE(MAX(version), 0) AS version FROM app_schema_migrations").fetchone()
                if int(row["version"]) >= POSTGRES_SCHEMA_VERSION:
                    conn.commit()
                    return
                for statement in POSTGRES_SCHEMA.split(";"):
                    if statement.strip():
                        conn.execute(statement)
                conn.execute(
                    "INSERT INTO app_schema_migrations(version) VALUES(?) ON CONFLICT (version) DO NOTHING",
                    (POSTGRES_SCHEMA_VERSION,),
                )
                conn.commit()
                return
            conn.executescript(SCHEMA)
            job_columns = {row["name"] for row in conn.execute("PRAGMA table_info(jobs)")}
            if "report_id" not in job_columns:
                conn.execute("ALTER TABLE jobs ADD COLUMN report_id INTEGER REFERENCES reports(id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_report_id ON jobs(report_id)")

    @contextmanager
    def session(self) -> Iterator[Any]:
        conn = self.connect()
        try:
            yield conn
        finally:
            conn.close()

    @contextmanager
    def transaction(self) -> Iterator[Any]:
        last_error: Exception | None = None
        conn = None
        for attempt in range(5):
            try:
                conn = self.connect()
                if self.is_postgres:
                    conn.execute("SELECT pg_advisory_xact_lock_shared(?)", (POSTGRES_MIGRATION_LOCK_ID,))
                else:
                    conn.execute("BEGIN IMMEDIATE")
                break
            except sqlite3.OperationalError as exc:
                if conn is not None:
                    conn.close()
                    conn = None
                last_error = exc
                if "locked" not in str(exc).lower():
                    raise
                time.sleep(0.15 * (2**attempt))
        if conn is None:
            raise last_error or RuntimeError("could not open database transaction")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

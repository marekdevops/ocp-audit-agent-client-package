SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA busy_timeout=10000;

CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  uid TEXT,
  cluster_name TEXT NOT NULL,
  timestamp TEXT NOT NULL,
  namespace TEXT,
  reason TEXT,
  type TEXT,
  message TEXT,
  involved_kind TEXT,
  involved_name TEXT,
  source_component TEXT,
  severity TEXT NOT NULL,
  raw_json TEXT
);
DELETE FROM events WHERE severity = 'Info';
DELETE FROM events
WHERE uid IS NOT NULL
  AND uid != ''
  AND id NOT IN (
    SELECT MAX(id)
    FROM events
    WHERE uid IS NOT NULL AND uid != ''
    GROUP BY cluster_name, uid
  );
CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_filters ON events(namespace, reason, type, severity);
CREATE UNIQUE INDEX IF NOT EXISTS idx_events_cluster_uid ON events(cluster_name, uid) WHERE uid IS NOT NULL AND uid != '';

CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  fingerprint TEXT NOT NULL UNIQUE,
  cluster_name TEXT NOT NULL,
  severity TEXT NOT NULL,
  category TEXT NOT NULL,
  namespace TEXT,
  resource_kind TEXT,
  resource_name TEXT,
  title TEXT NOT NULL,
  description TEXT,
  evidence TEXT,
  recommendation TEXT,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  count INTEGER NOT NULL DEFAULT 1,
  active INTEGER NOT NULL DEFAULT 1,
  raw_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_filters ON findings(severity, category, namespace, resource_kind, active);

CREATE TABLE IF NOT EXISTS snapshots (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cluster_name TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  status TEXT NOT NULL,
  summary_json TEXT,
  error TEXT
);

CREATE TABLE IF NOT EXISTS jobs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  job_type TEXT NOT NULL,
  status TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  message TEXT,
  error TEXT,
  report_id INTEGER REFERENCES reports(id)
);
UPDATE jobs
SET status='failed', finished_at=COALESCE(finished_at, CURRENT_TIMESTAMP), error=COALESCE(error, 'Superseded duplicate running job')
WHERE status='running' AND id NOT IN (SELECT MAX(id) FROM jobs WHERE status='running' GROUP BY job_type);
CREATE UNIQUE INDEX IF NOT EXISTS idx_jobs_one_running_type ON jobs(job_type) WHERE status='running';

CREATE TABLE IF NOT EXISTS reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  format TEXT NOT NULL,
  path TEXT NOT NULL,
  created_at TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  summary_json TEXT
);

CREATE TABLE IF NOT EXISTS saved_filters (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  page TEXT NOT NULL,
  filters_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(page, name)
);
CREATE INDEX IF NOT EXISTS idx_saved_filters_page ON saved_filters(page, updated_at);

CREATE TABLE IF NOT EXISTS resource_observations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cluster_name TEXT NOT NULL,
  timestamp TEXT NOT NULL,
  api_version TEXT,
  kind TEXT NOT NULL,
  namespace TEXT,
  name TEXT,
  status TEXT,
  raw_json TEXT
);
DELETE FROM resource_observations
WHERE name IS NOT NULL
  AND name != ''
  AND id NOT IN (
    SELECT MAX(id)
    FROM resource_observations
    WHERE name IS NOT NULL AND name != ''
    GROUP BY cluster_name, kind, COALESCE(namespace, ''), COALESCE(name, '')
  );
CREATE INDEX IF NOT EXISTS idx_observations_kind_time ON resource_observations(kind, timestamp);
CREATE UNIQUE INDEX IF NOT EXISTS idx_observations_resource ON resource_observations(
  cluster_name,
  kind,
  COALESCE(namespace, ''),
  COALESCE(name, '')
) WHERE name IS NOT NULL AND name != '';

CREATE TABLE IF NOT EXISTS resource_observation_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cluster_name TEXT NOT NULL,
  observed_at TEXT NOT NULL,
  event_type TEXT NOT NULL,
  api_version TEXT,
  kind TEXT NOT NULL,
  namespace TEXT,
  name TEXT,
  status TEXT,
  raw_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_resource_history_time ON resource_observation_history(observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_resource_history_resource ON resource_observation_history(
  cluster_name, kind, namespace, name, observed_at DESC
);

CREATE TABLE IF NOT EXISTS pod_observation_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cluster_name TEXT NOT NULL,
  observed_at TEXT NOT NULL,
  event_type TEXT NOT NULL,
  namespace TEXT,
  name TEXT NOT NULL,
  status TEXT,
  raw_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pod_history_time ON pod_observation_history(observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_pod_history_filters ON pod_observation_history(namespace, event_type, name, observed_at DESC);
"""

POSTGRES_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (id BIGSERIAL PRIMARY KEY, uid TEXT, cluster_name TEXT NOT NULL, timestamp TEXT NOT NULL, namespace TEXT, reason TEXT, type TEXT, message TEXT, involved_kind TEXT, involved_name TEXT, source_component TEXT, severity TEXT NOT NULL, raw_json TEXT);
CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_filters ON events(namespace, reason, type, severity);
CREATE UNIQUE INDEX IF NOT EXISTS idx_events_cluster_uid ON events(cluster_name, uid) WHERE uid IS NOT NULL AND uid != '';
CREATE TABLE IF NOT EXISTS findings (id BIGSERIAL PRIMARY KEY, fingerprint TEXT NOT NULL UNIQUE, cluster_name TEXT NOT NULL, severity TEXT NOT NULL, category TEXT NOT NULL, namespace TEXT, resource_kind TEXT, resource_name TEXT, title TEXT NOT NULL, description TEXT, evidence TEXT, recommendation TEXT, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, count INTEGER NOT NULL DEFAULT 1, active INTEGER NOT NULL DEFAULT 1, raw_json TEXT);
CREATE INDEX IF NOT EXISTS idx_findings_filters ON findings(severity, category, namespace, resource_kind, active);
CREATE TABLE IF NOT EXISTS snapshots (id BIGSERIAL PRIMARY KEY, cluster_name TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT, status TEXT NOT NULL, summary_json TEXT, error TEXT);
CREATE TABLE IF NOT EXISTS reports (id BIGSERIAL PRIMARY KEY, format TEXT NOT NULL, path TEXT NOT NULL, created_at TEXT NOT NULL, size_bytes BIGINT NOT NULL, summary_json TEXT);
CREATE TABLE IF NOT EXISTS jobs (id BIGSERIAL PRIMARY KEY, job_type TEXT NOT NULL, status TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT, message TEXT, error TEXT, report_id BIGINT REFERENCES reports(id));
UPDATE jobs SET status='failed', finished_at=COALESCE(finished_at, CURRENT_TIMESTAMP::text), error=COALESCE(error, 'Superseded duplicate running job') WHERE status='running' AND id NOT IN (SELECT MAX(id) FROM jobs WHERE status='running' GROUP BY job_type);
CREATE UNIQUE INDEX IF NOT EXISTS idx_jobs_one_running_type ON jobs(job_type) WHERE status='running';
CREATE INDEX IF NOT EXISTS idx_jobs_report_id ON jobs(report_id);
CREATE TABLE IF NOT EXISTS saved_filters (id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL, page TEXT NOT NULL, filters_json TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, UNIQUE(page, name));
CREATE INDEX IF NOT EXISTS idx_saved_filters_page ON saved_filters(page, updated_at);
CREATE TABLE IF NOT EXISTS resource_observations (id BIGSERIAL PRIMARY KEY, cluster_name TEXT NOT NULL, timestamp TEXT NOT NULL, api_version TEXT, kind TEXT NOT NULL, namespace TEXT, name TEXT, status TEXT, raw_json TEXT);
CREATE INDEX IF NOT EXISTS idx_observations_kind_time ON resource_observations(kind, timestamp);
CREATE UNIQUE INDEX IF NOT EXISTS idx_observations_resource ON resource_observations(cluster_name, kind, COALESCE(namespace, ''), COALESCE(name, '')) WHERE name IS NOT NULL AND name != '';
CREATE TABLE IF NOT EXISTS resource_observation_history (id BIGSERIAL PRIMARY KEY, cluster_name TEXT NOT NULL, observed_at TEXT NOT NULL, event_type TEXT NOT NULL, api_version TEXT, kind TEXT NOT NULL, namespace TEXT, name TEXT, status TEXT, raw_json TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_resource_history_time ON resource_observation_history(observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_resource_history_resource ON resource_observation_history(cluster_name, kind, namespace, name, observed_at DESC);
CREATE TABLE IF NOT EXISTS pod_observation_history (id BIGSERIAL PRIMARY KEY, cluster_name TEXT NOT NULL, observed_at TEXT NOT NULL, event_type TEXT NOT NULL, namespace TEXT, name TEXT NOT NULL, status TEXT, raw_json TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_pod_history_time ON pod_observation_history(observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_pod_history_filters ON pod_observation_history(namespace, event_type, name, observed_at DESC);
"""

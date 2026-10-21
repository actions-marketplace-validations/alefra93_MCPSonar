-- A database created by MCPSonar v0.7.0 (tests/fixtures/db, generated from the tag)
BEGIN TRANSACTION;
CREATE TABLE api_tokens (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    token_hash   TEXT UNIQUE NOT NULL,
    scope        TEXT NOT NULL,
    created_by   TEXT NOT NULL,
    created_at   REAL NOT NULL,
    expires_at   REAL,
    last_used_at REAL
);
CREATE TABLE checks (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id              TEXT NOT NULL,
    status                 TEXT NOT NULL,
    checked_at             TEXT NOT NULL,
    latency_ms             REAL NOT NULL,
    tools_checked          INTEGER NOT NULL,
    tools_failed           INTEGER NOT NULL,
    tools_available        INTEGER NOT NULL DEFAULT 0,
    spec_version           TEXT,
    spec_version_supported INTEGER NOT NULL,
    detail                 TEXT,
    auth_required          INTEGER NOT NULL DEFAULT 0,
    tool_changes           INTEGER NOT NULL DEFAULT 0,
    tool_risks             INTEGER NOT NULL DEFAULT 0,
    anomalies_json         TEXT,
    latency_baseline_ms    REAL,
    latency_score          REAL
);
INSERT INTO "checks" VALUES(1,'64d24d904ea8','up','2026-01-01T00:00:00+00:00',42.0,0,0,0,NULL,0,NULL,0,0,0,NULL,NULL,NULL);
CREATE TABLE servers (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1,
    config_json TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
INSERT INTO "servers" VALUES('64d24d904ea8','demo',1,'{"transport":"http","url":"https://example.com/mcp","headers":{},"command":null,"args":[],"env":{},"check_interval_seconds":60,"tools_to_test":[],"thresholds":{"latency_degraded_ms":2000.0,"latency_down_ms":10000.0},"webhooks":[],"on_tool_change":"degrade","anomaly":{"enabled":true,"sensitivity":4.0,"degrade":false}}','2026-10-21T20:12:35.432680+00:00');
CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY,
    username   TEXT NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL
);
CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
INSERT INTO "settings" VALUES('fixture','v0.7.0');
CREATE TABLE tool_baselines (
    server_id      TEXT PRIMARY KEY,
    established_at TEXT NOT NULL
);
INSERT INTO "tool_baselines" VALUES('64d24d904ea8','2026-10-21T20:12:35.442596+00:00');
CREATE TABLE tool_changes (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id    TEXT NOT NULL,
    detected_at  TEXT NOT NULL,
    kind         TEXT NOT NULL,
    tool_name    TEXT NOT NULL,
    fields_json  TEXT NOT NULL,
    before_json  TEXT,
    after_json   TEXT,
    acknowledged INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE tool_snapshots (
    server_id       TEXT NOT NULL,
    name            TEXT NOT NULL,
    definition_json TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    PRIMARY KEY (server_id, name)
);
INSERT INTO "tool_snapshots" VALUES('64d24d904ea8','ping','{"description": "Ping.", "name": "ping"}','2026-10-21T20:12:35.442596+00:00');
CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt          TEXT NOT NULL,
    created_at    TEXT NOT NULL
);
CREATE INDEX idx_checks_server_time ON checks (server_id, checked_at);
CREATE INDEX idx_tool_changes_server ON tool_changes (server_id, acknowledged);
DELETE FROM "sqlite_sequence";
INSERT INTO "sqlite_sequence" VALUES('checks',1);
COMMIT;

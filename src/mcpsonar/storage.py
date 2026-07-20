"""SQLite persistence (via aiosqlite): monitored servers + check history.

Two tables:

* ``servers`` — the monitors a user has added (survive restart). The check parameters are
  stored as a JSON blob of the :class:`ServerConfig` portion; identity/enabled are columns.
* ``checks``  — one row per completed check, for the history graphs.

Kept intentionally thin: hand-written SQL, no ORM, one shared async connection.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timezone
from pathlib import Path

import aiosqlite

from .auth import hash_password, verify_password
from .models import CheckEvent, CheckStatus, MonitoredServer, ServerConfig

_SCHEMA = """
CREATE TABLE IF NOT EXISTS servers (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1,
    config_json TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS checks (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id              TEXT NOT NULL,
    status                 TEXT NOT NULL,
    checked_at             TEXT NOT NULL,
    latency_ms             REAL NOT NULL,
    tools_checked          INTEGER NOT NULL,
    tools_failed           INTEGER NOT NULL,
    spec_version           TEXT,
    spec_version_supported INTEGER NOT NULL,
    detail                 TEXT
);
CREATE INDEX IF NOT EXISTS idx_checks_server_time ON checks (server_id, checked_at);
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt          TEXT NOT NULL,
    created_at    TEXT NOT NULL
);
"""


def _new_id() -> str:
    return uuid.uuid4().hex[:12]


class Storage:
    def __init__(self, conn: aiosqlite.Connection) -> None:
        self._conn = conn

    # ---- lifecycle --------------------------------------------------------- #
    @classmethod
    async def open(cls, path: str | Path) -> "Storage":
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        conn = await aiosqlite.connect(path)
        conn.row_factory = aiosqlite.Row
        await conn.executescript(_SCHEMA)
        await conn.commit()
        return cls(conn)

    async def close(self) -> None:
        await self._conn.close()

    # ---- servers (CRUD) ---------------------------------------------------- #
    @staticmethod
    def _row_to_server(row: aiosqlite.Row) -> MonitoredServer:
        cfg = ServerConfig.model_validate_json(row["config_json"])
        return MonitoredServer(
            id=row["id"],
            name=row["name"],
            enabled=bool(row["enabled"]),
            **cfg.model_dump(),
        )

    async def list_servers(self) -> list[MonitoredServer]:
        cur = await self._conn.execute("SELECT * FROM servers ORDER BY name")
        rows = await cur.fetchall()
        return [self._row_to_server(r) for r in rows]

    async def get_server(self, server_id: str) -> MonitoredServer | None:
        cur = await self._conn.execute("SELECT * FROM servers WHERE id = ?", (server_id,))
        row = await cur.fetchone()
        return self._row_to_server(row) if row else None

    async def create_server(
        self, name: str, config: ServerConfig, enabled: bool = True
    ) -> MonitoredServer:
        server_id = _new_id()
        await self._conn.execute(
            "INSERT INTO servers (id, name, enabled, config_json, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                server_id,
                name,
                int(enabled),
                config.model_dump_json(),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        await self._conn.commit()
        return MonitoredServer(id=server_id, name=name, enabled=enabled, **config.model_dump())

    async def update_server(
        self, server_id: str, name: str, config: ServerConfig, enabled: bool
    ) -> MonitoredServer | None:
        cur = await self._conn.execute(
            "UPDATE servers SET name = ?, enabled = ?, config_json = ? WHERE id = ?",
            (name, int(enabled), config.model_dump_json(), server_id),
        )
        await self._conn.commit()
        if cur.rowcount == 0:
            return None
        return MonitoredServer(id=server_id, name=name, enabled=enabled, **config.model_dump())

    async def delete_server(self, server_id: str) -> bool:
        cur = await self._conn.execute("DELETE FROM servers WHERE id = ?", (server_id,))
        await self._conn.execute("DELETE FROM checks WHERE server_id = ?", (server_id,))
        await self._conn.commit()
        return cur.rowcount > 0

    # ---- check history ----------------------------------------------------- #
    async def record_check(self, event: CheckEvent) -> None:
        await self._conn.execute(
            "INSERT INTO checks (server_id, status, checked_at, latency_ms, tools_checked, "
            "tools_failed, spec_version, spec_version_supported, detail) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                event.server_id,
                event.status.value,
                event.checked_at.isoformat(),
                event.latency_ms,
                event.tools_checked,
                event.tools_failed,
                event.spec_version,
                int(event.spec_version_supported),
                event.detail,
            ),
        )
        await self._conn.commit()

    @staticmethod
    def _row_to_event(row: aiosqlite.Row) -> CheckEvent:
        return CheckEvent(
            server_id=row["server_id"],
            status=CheckStatus(row["status"]),
            checked_at=datetime.fromisoformat(row["checked_at"]),
            latency_ms=row["latency_ms"],
            tools_checked=row["tools_checked"],
            tools_failed=row["tools_failed"],
            spec_version=row["spec_version"],
            spec_version_supported=bool(row["spec_version_supported"]),
            detail=row["detail"],
        )

    async def get_history(
        self, server_id: str, since: datetime | None = None, limit: int = 500
    ) -> list[CheckEvent]:
        """Recent checks for a server, oldest→newest (ready to plot)."""
        if since is not None:
            cur = await self._conn.execute(
                "SELECT * FROM (SELECT * FROM checks WHERE server_id = ? AND checked_at >= ? "
                "ORDER BY checked_at DESC LIMIT ?) ORDER BY checked_at ASC",
                (server_id, since.isoformat(), limit),
            )
        else:
            cur = await self._conn.execute(
                "SELECT * FROM (SELECT * FROM checks WHERE server_id = ? "
                "ORDER BY checked_at DESC LIMIT ?) ORDER BY checked_at ASC",
                (server_id, limit),
            )
        rows = await cur.fetchall()
        return [self._row_to_event(r) for r in rows]

    async def prune_history(self, older_than: datetime) -> int:
        """Delete check rows older than a cutoff. Returns the number removed."""
        cur = await self._conn.execute(
            "DELETE FROM checks WHERE checked_at < ?", (older_than.isoformat(),)
        )
        await self._conn.commit()
        return cur.rowcount

    # ---- settings + auth --------------------------------------------------- #
    async def get_setting(self, key: str) -> str | None:
        cur = await self._conn.execute("SELECT value FROM settings WHERE key = ?", (key,))
        row = await cur.fetchone()
        return row["value"] if row else None

    async def set_setting(self, key: str, value: str) -> None:
        await self._conn.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )
        await self._conn.commit()

    async def get_or_create_session_secret(self) -> str:
        """Persist a random secret used to sign session cookies (stable across restarts)."""
        secret = await self.get_setting("session_secret")
        if secret is None:
            secret = secrets.token_hex(32)
            await self.set_setting("session_secret", secret)
        return secret

    async def has_admin(self) -> bool:
        cur = await self._conn.execute("SELECT COUNT(*) AS n FROM users")
        return (await cur.fetchone())["n"] > 0

    async def create_admin(self, username: str, password: str) -> None:
        salt, pw_hash = hash_password(password)
        await self._conn.execute(
            "INSERT INTO users (username, password_hash, salt, created_at) VALUES (?, ?, ?, ?)",
            (username, pw_hash, salt, datetime.now(timezone.utc).isoformat()),
        )
        await self._conn.commit()

    async def verify_credentials(self, username: str, password: str) -> bool:
        cur = await self._conn.execute(
            "SELECT password_hash, salt FROM users WHERE username = ?", (username,)
        )
        row = await cur.fetchone()
        if row is None:
            return False
        return verify_password(password, row["salt"], row["password_hash"])

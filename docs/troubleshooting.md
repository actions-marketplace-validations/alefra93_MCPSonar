# Troubleshooting

**Start with `mcpsonar doctor`.** It checks Python, the MCP SDK, your config file, the
database, TLS, the running instance, your API token and risky settings, without changing
anything and without printing a credential. For the demo, see
[demo/troubleshooting.md](demo/troubleshooting.md).

## Installing

- **"requires a different Python"**: MCPSonar needs Python 3.11 or newer. With uv, add
  `--python 3.12`.
- **`mcpsonar` is not found after `pip install`**: the scripts folder of that Python is not on
  `PATH`. Use `pipx`, `uvx`, or `python -m mcpsonar.cli`.

## Starting the monitor

- **Address already in use.** Port 8675 is taken: `mcpsonar run --port 9000`.
- **"this database has schema version N, newer than this MCPSonar supports"** (exit 2). The
  database was written by a newer MCPSonar. Upgrade MCPSonar, or restore the `.bak` file
  that was written next to the database before the upgrade. See
  [schema versions](configuration.md#schema-versions-and-upgrades).
- **"database is locked" or a corrupted database on a network share.** SQLite in WAL mode
  needs a local disk or a Docker volume, not NFS or SMB.

## Signing in

- **The setup link is gone.** As long as no admin exists, MCPSonar prints a new setup link
  every time it starts. Restart it and read the log (`docker compose logs mcpsonar`). To
  choose the token yourself, set `MCPSONAR_SETUP_TOKEN`.
- **Forgotten password.** There is no reset by email.
  - **If another admin exists:** they can set a new password from **Users → Reset password**.
    That also ends the account's sessions and API tokens.
  - **For the only admin,** with MCPSonar **stopped**:

  ```bash
  # back up first
  sqlite3 mcpsonar.db ".backup mcpsonar-before-reset.db"
  python -c "import sqlite3; c = sqlite3.connect('mcpsonar.db'); c.execute('DELETE FROM sessions'); c.execute('DELETE FROM users'); c.commit()"
  ```

  Start it again and open the new setup link from the log; servers and history are kept.
  Other accounts are deleted too, and their API tokens stop working. If you recreate an
  account with the same name, its old tokens work again. So if you reset because an account
  may be compromised, also run `DELETE FROM api_tokens` and create new tokens.
- **Logged out right after logging in, behind a proxy.** See
  [reverse proxy and HTTPS](configuration.md#reverse-proxy-and-https) (`--allowed-host`,
  `--trusted-origin`, `--cookie-secure`).

## The dashboard

- **Stuck on "Loading…" with 0.8.0.** This is a bug fixed in 0.8.1. It appears as soon as
  any server's last anomaly is a latency shift. Upgrade.
- **A new server's history strip looks empty (before 0.8.1).** It is a display bug, also
  fixed in 0.8.1; the checks are recorded.

## A server's status

| What you see | What it means | What to do |
|---|---|---|
| up · *auth required* | The server answers 401/403: it is alive but needs credentials (e.g. OAuth). Tools are not listed. | Add an `Authorization` header to check it fully. |
| degraded · *rate limited (429)* | The server is throttling the checks. | Raise `check_interval_seconds`. |
| degraded · *unreviewed tool change* | A tool definition changed since it was pinned. | Review it: `mcpsonar diff NAME`, or **Review** in the dashboard. |
| down · *header 'X': '${env:…}': environment variable not set* (or *file not found*) | A secret reference could not be resolved. | Set the variable or create the file (see [secret references](configuration.md#secret-references)). |
| down · *outbound policy blocked HOST: …* | The outbound policy refused the address (cloud metadata, or a `MCPSONAR_OUTBOUND_DENY` match). | Check the [outbound policy](configuration.md#outbound-connection-policy). |
| down · TLS / certificate error | The certificate is not trusted from this host. | `mcpsonar doctor` checks TLS. Enterprise CAs: see the TLS note in the configuration. |

## stdio servers

- **"command not found" or a failure on Windows.** Use the full path when it contains
  spaces, in double quotes inside the argument (bash or PowerShell):
  `--stdio '"C:\Program Files\nodejs\npx.cmd" -y @scope/server'`.
  `doctor` shows whether `npx` is found.
- **The server needs an environment variable.** Use `-e KEY=VALUE` on the command line, or
  `env:` in the config (preferably with a secret reference). The child process gets only a
  minimal environment plus those variables.
- **Adding stdio servers from the dashboard is refused.** A `--no-auth` instance refuses it
  by design (`--allow-stdio-api` to override, only if nobody else can reach the port).

## In CI

| Exit code | Meaning |
|---|---|
| 0 | No findings at or above `--fail-on`, and no change from the lockfile. |
| 1 | Findings, or the tools changed since the lockfile. If the change is legitimate, accept it with `--update-lock` and commit the lockfile. |
| 2 | Could not run: server unreachable, or a usage error. Check the URL, the headers (secrets), and whether the runner can reach the server. |

## Still stuck?

Open an [issue](https://github.com/alefra93/MCPSonar/issues). Include the output of
`mcpsonar doctor` and `mcpsonar version`; neither prints credentials.

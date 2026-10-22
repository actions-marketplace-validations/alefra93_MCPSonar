# Configuration reference

Everything `mcpsonar run` can be told, where to put it, and the safe choice for each. Options
that carry **secrets** are read from the environment only, so they never appear in `ps`
output or shell history.

## Command line and environment

| Flag | Environment | Default | What it does |
|---|---|---|---|
| `--host` | | `127.0.0.1` | Bind address. `0.0.0.0` exposes the dashboard on the network. |
| `--port` | | `8675` | Dashboard / API / `/metrics` port. |
| `--db PATH` | `MCPSONAR_DB` | `./mcpsonar.db` | SQLite database (servers, history, users, sessions). |
| `--retention-days N` | `MCPSONAR_RETENTION_DAYS` | `7` | Drop check history older than N days (`0` keeps everything). |
| `--config FILE` | | — | Seed servers from YAML on first start (only while the DB has no servers). |
| `--no-auth` | | off | No login. Only on localhost or behind an authenticating proxy. |
| `--allowed-host H` (repeatable) | `MCPSONAR_ALLOWED_HOSTS` (comma-separated) | any host with the login on; `localhost`, `127.0.0.1`, `::1` with `--no-auth` | `Host` headers the instance answers to; anything else gets 400. `*.example.com` wildcards work. This is what defeats **DNS rebinding**. |
| `--trusted-origin O` (repeatable) | `MCPSONAR_TRUSTED_ORIGINS` | — | Extra browser origin allowed to make changes, e.g. `https://mcp.example.com` when a reverse proxy rewrites `Host`. |
| `--cookie-secure` | `MCPSONAR_COOKIE_SECURE` | `auto` | `auto` sets `Secure` when the request came over HTTPS; `always` / `never` force it. |
| `--allow-stdio-api` | `MCPSONAR_ALLOW_STDIO_API=1` | off | With `--no-auth`, still allow creating/changing stdio servers over the API. |
| | `MCPSONAR_SETUP_TOKEN` | random, printed in the log | One-time token that the first-admin setup requires. |
| | `MCPSONAR_METRICS_TOKEN` | — (public) | When set, `/metrics` requires `Authorization: Bearer <token>`. |
| | `FORWARDED_ALLOW_IPS` | `127.0.0.1` | (uvicorn) proxies whose `X-Forwarded-For` / `-Proto` are trusted. See *Reverse proxy*. |

### CLI client (remote mode)

| Environment | Default | What it does |
|---|---|---|
| `MCPSONAR_URL` | `http://127.0.0.1:8675` | The instance `status`, `servers`, `check`, `diff` and `history` talk to (`--url` overrides). |
| `MCPSONAR_TOKEN` | — | API token from the dashboard (**API tokens**). *read* tokens: GET only. *write* tokens: also check and change servers. Not needed with `--no-auth`. |

API tokens are stored as SHA-256 hashes and shown once. They can expire, are revoked from
the dashboard, and can't be used to create or list tokens. Prefer *read* tokens for
dashboards, scripts and CI; give *write* only to automation that must trigger checks or
change servers.

### Outbound connection policy

Applies to MCP checks (HTTP and SSE, including every redirect hop) and to webhook / Uptime
Kuma deliveries. Enforced when the TCP connection is opened, against the resolved address:

| Environment | Default | Effect |
|---|---|---|
| — | — | Always blocked: cloud metadata (`169.254.169.254`, `fd00:ec2::254`, `100.100.100.200`), `0.0.0.0`/`::`, multicast, reserved. |
| `MCPSONAR_ALLOW_LINK_LOCAL=1` | off | Allow `169.254.0.0/16` and `fe80::/10` (metadata addresses stay blocked). |
| `MCPSONAR_BLOCK_PRIVATE_NETWORKS=1` | off | Also block loopback, RFC 1918, ULA and CGNAT — for instances that only watch internet servers. |
| `MCPSONAR_OUTBOUND_ALLOW` | — | CIDRs always allowed (the only way to reach a metadata address on purpose). |
| `MCPSONAR_OUTBOUND_DENY` | — | CIDRs always blocked (wins over everything). |

**TLS trust:** HTTPS is verified with the operating-system trust store on Windows and
macOS, so enterprise root CAs installed there are honored. On Linux and in the container the
system CA bundle is used. `SSL_CERT_FILE` / `SSL_CERT_DIR` override both.

Private networks are allowed by default on purpose: watching the MCP servers on your own
network is a primary use case. Requests sent through `HTTP(S)_PROXY` connect to the proxy,
so the proxy must enforce its own destination rules.

## Server configuration (YAML / API)

```yaml
servers:
  my-server:
    url: "https://example.com/mcp"      # http(s) only
    transport: "http"                   # http | sse | stdio
    headers: { Authorization: "Bearer <token>" }
    check_interval_seconds: 60
    tools_to_test:                      # opt-in; nothing is called unless listed here
      - ping
      - name: search
        arguments: { query: "healthcheck" }
        timeout_seconds: 5              # default: latency_down_ms + 5 s
        allow_destructive: false        # default; see "Tool probes"
        drift: shape                    # shape (default) | hash | off; see "Response drift"
        drift_ignore: []                # fields left out of the hash (timestamps, ids, ...)
    thresholds: { latency_degraded_ms: 2000, latency_down_ms: 10000 }
    on_tool_change: "degrade"           # degrade | alert | ignore
    anomaly: { enabled: true, sensitivity: 4.0, degrade: false }
    webhooks:
      - { type: uptime_kuma, push_url: "https://kuma.example.com/api/push/<token>" }
      - { type: generic, url: "https://hooks.example.com/x", "on": [down, degraded] }
      - { type: slack, url: "https://hooks.slack.com/services/<...>" }
      - { type: discord, url: "https://discord.com/api/webhooks/<...>" }
```

### Tool probes

- Only tools named in `tools_to_test` are called, one at a time, never inferred from names.
- A probe for a tool the server no longer lists fails **without** calling anything.
- A tool whose annotations say `destructiveHint: true` (and not `readOnlyHint: true`) is
  skipped unless the probe sets `allow_destructive: true`. **Annotations are hints written by
  the server**; the MCP specification says clients must treat them as untrusted. A malicious
  server can label a destructive tool read-only, so the skip is a safety brake for honest
  servers, not a guarantee. Only probe tools that are safe to call repeatedly.
- Each check has an overall time budget (`3 × (latency_down_ms + 5 s)` plus each probe's
  timeout); a server that hangs ends as `down` and the next check runs on schedule.

### Response drift

A probed tool can keep answering while answering *differently*: a field disappears, a number
becomes a string, it starts returning errors. For each probe, MCPSonar remembers the **shape**
of the last answer and reports a `response_drift` anomaly when it changes.

- **Only probes are watched**, and only their shape is stored: whether the result was an
  error, the content types, the key names and value types of `structuredContent`, and the
  order of magnitude of the size. **Response content is never stored.**
- A size change counts only at **8× or more**. Smaller changes leave the reference as it is,
  so slow growth still adds up to a report.
- `drift: hash` also compares the content, through a SHA-256 digest (the digest is stored, the
  content is not). Use it only for deterministic probes, and list the fields that change on
  every call in `drift_ignore` (matched by name at any depth of `structuredContent`).
- `drift: off` turns it off for that probe.
- A drift is reported **once**, then the new shape becomes the reference. It is an
  observability signal: it does not change the server's status and needs no review, unlike
  tool-definition changes.

### Notifications

| `type` | Sends | When |
|---|---|---|
| `slack`, `discord`, `email` | A short message | Once per **change** (see below) |
| `generic` | The raw `CheckEvent` JSON (POST) | Every check in an `on` status, every new anomaly, and once on recovery |
| `uptime_kuma` | A push (GET) | Every check (Kuma keeps its own state) |

Slack and Discord speak in changes, not checks:

- the server **enters** a status listed in `on` (default `[down, degraded]`): one message,
  with the reason. Staying down sends nothing more.
- it is **back up** (`on_recovery`, default on): one message with how long it was out,
  e.g. "calculator is back up after 12 min down".
- something **new** was detected (`on_anomaly`, default on): a tool change, the first check
  of a latency episode, a confirmed shift, flapping, a response drift. Checks that only
  continue an episode (`ongoing`) are never re-notified.

`degraded` includes an unreviewed tool change, so a rug pull produces one message when it
happens and one when it is reviewed.

Email goes through your SMTP server:

```yaml
    webhooks:
      - type: email
        host: smtp.example.com
        port: 587                    # 587 with STARTTLS (default), or 465 with security: tls
        username: mcpsonar@example.com
        password: "${env:MCPSONAR_SECRET_SMTP}"   # a secret reference; see above
        sender: mcpsonar@example.com
        to: [ops@example.com]
```

- **TLS is required.** With `starttls` (the default), a server that does not offer STARTTLS
  is an error: MCPSonar never falls back to plain text, and never sends the password
  unencrypted. `security: none` is accepted only for a relay on `localhost`.
- **The outbound policy applies.** The SMTP host is resolved and checked like any
  destination. MCPSonar then connects only to an allowed address, while TLS still verifies
  the certificate against the host name.
- **The password** is masked like any credential. As a secret reference it is never stored,
  and it is resolved for each message.

Each message can link to your instance. Set `MCPSONAR_PUBLIC_URL` (e.g.
`https://mcpsonar.example.com`) to add it.

**Treat message text as untrusted.** Tool names, error messages and change details come
from the monitored servers. MCPSonar removes invisible characters and line breaks and
truncates them. For Slack it escapes `<`, `>` and `&` (no `<!channel>`, no disguised
links). For Discord it escapes markdown and disables mentions. Webhook URLs must be
`https://`; they are secrets, so they are masked in the API, the dashboard and the logs.

### stdio servers: the trust boundary

A stdio server is a **command mcpsonar executes** on its host, at every check, with
mcpsonar's user and filesystem permissions. mcpsonar does not use a shell and passes only a
minimal environment (the MCP SDK's allowlist, e.g. `HOME`, `PATH`) plus the `env` you set,
so its own secrets are not inherited. That is still full code execution:

- Only configure stdio servers you would run yourself. `npx -y some-package` downloads and
  runs whatever that package's latest version is; pin versions (`some-package@1.2.3`).
- For untrusted servers, run mcpsonar in the container image (unprivileged user, no
  capabilities) or monitor the server over HTTP from a separate sandbox.
- Without a login (`--no-auth`), stdio servers cannot be added over the API at all unless
  `--allow-stdio-api` is given; seed them from YAML instead.

## Secrets: what is shown, stored and exported

| Where | Credentials (headers, `env`, URL keys/userinfo, webhook URLs) |
|---|---|
| SQLite database | Stored in clear (mcpsonar needs them to monitor), unless you use [secret references](#secret-references): then only the reference is stored. Protect the file. |
| API reads, dashboard | Masked as `********`. Sending a masked value back on edit keeps the stored one. |
| `GET /api/export` | Masked. `?include_secrets=true` for a full export (handle it like a password file). |
| `POST /api/import` | Refuses a masked export with a clear error, instead of storing placeholders. |
| Check details, webhooks, Kuma, logs | Scrubbed of the server's credentials and of bearer tokens / keyed URLs. |
| Passwords / sessions | PBKDF2-SHA256 hashes / SHA-256 of the session token; never reversible. |

### Secret references

Header and stdio `env` values can name a secret instead of containing it. The reference is
what gets stored, exported and shown; the value is read at every check and used for that
check only.

```yaml
servers:
  github:
    url: "https://api.githubcopilot.com/mcp/"
    headers: { Authorization: "Bearer ${env:MCPSONAR_SECRET_GITHUB}" }
  brave:
    transport: stdio
    command: npx
    args: ["-y", "@modelcontextprotocol/server-brave-search"]
    env: { BRAVE_API_KEY: "${file:/run/secrets/brave_api_key}" }
```

- `${env:NAME}` reads an environment variable of the mcpsonar process.
- `${file:PATH}` reads a file (absolute path, at most 64 KiB, one trailing newline
  removed). It is re-read on every check, so a rotated secret needs no restart.
- References work in header and `env` values, alone or with text around them
  (`Bearer ${env:...}`). Not yet in URLs or webhook URLs.

**What a reference may read is allowlisted**, because a configuration can come from the
API (anyone with a write token) or from a shared file. Without a limit,
`${file:/root/.ssh/id_rsa}` or `${env:AWS_SECRET_ACCESS_KEY}` would be read and sent, as a
header, to a server chosen by whoever wrote the configuration.

| Reference | Allowed when |
|---|---|
| `${env:NAME}` | `NAME` starts with `MCPSONAR_SECRET_`, or is listed in `MCPSONAR_SECRET_ENV` (comma-separated) |
| `${file:PATH}` | `PATH`, after resolving symlinks and `..`, is inside `/run/secrets` or a directory in `MCPSONAR_SECRETS_DIR` (separated by `:` on Linux/macOS, `;` on Windows) |

The allowlist comes from mcpsonar's own environment, so only whoever starts mcpsonar can
widen it.

- **When a reference is not allowed or malformed:** the API answers 400 and a config file
  fails to load, naming the field.
- **When it cannot be resolved** (variable not set, file missing): the check is `down`, with
  the reason in its detail. The detail names the reference, never a value.
- **What is shown:** the dashboard, the API and `/api/export` show a reference as-is
  (`Bearer ${env:MCPSONAR_SECRET_GITHUB}`). A value with literal text around a reference is
  masked like any other credential.

With Docker Compose secrets, a file in `secrets:` is mounted under `/run/secrets/<name>`:

```yaml
services:
  mcpsonar:
    secrets: [brave_api_key]
secrets:
  brave_api_key:
    file: ./brave_api_key.txt
```

On the command line (`scan`, `tools`, `check`), your shell can expand variables itself:
`-H "Authorization: Bearer $GITHUB_TOKEN"`.

## Backups

The database is the whole state. Back it up with SQLite's online backup, which is safe while
mcpsonar runs:

```bash
sqlite3 /data/mcpsonar.db ".backup '/backups/mcpsonar-$(date +%F).db'"
# Docker: docker compose exec mcpsonar python -c "import sqlite3;s=sqlite3.connect('/data/mcpsonar.db');d=sqlite3.connect('/data/backup.db');s.backup(d)"
```

The backup contains credentials and password hashes: encrypt it and restrict access. To
share a configuration (an issue report, a colleague), use the redacted YAML export.

Since v0.8 the database runs in WAL mode: next to `mcpsonar.db` you will see
`mcpsonar.db-wal` and `mcpsonar.db-shm`. They are part of the database. Copying only the
`.db` file of a running instance can lose the latest writes: use the online backup above,
or stop mcpsonar first. Keep the database on a local disk or a Docker volume; WAL does
not work on network file systems (NFS, SMB).

### Schema versions and upgrades

The database records its schema version, and mcpsonar migrates it forward on start, one
numbered step at a time, each in its own transaction.

- Before migrating an existing database, mcpsonar saves a copy next to it:
  `mcpsonar.db.schema<N>.bak`, where N is the version it had. Delete it once the new
  version runs well. It contains the same secrets as the database.
- Databases from v0.5, v0.6 and v0.7 are upgraded automatically (they count as version 0).
- Downgrading is not supported. An older mcpsonar refuses a database written by a newer
  one, with a clear error and exit code 2, instead of misreading it. To go back, restore
  the `.bak` taken before the upgrade.

## Reverse proxy and HTTPS

For anything beyond localhost, terminate TLS in a reverse proxy and keep mcpsonar on
`127.0.0.1` (or an internal Docker network):

```nginx
location / {
    proxy_pass http://127.0.0.1:8675;
    proxy_set_header Host $host;                       # keep the public Host (CSRF check)
    proxy_set_header X-Forwarded-For $remote_addr;     # real client IP (login throttling)
    proxy_set_header X-Forwarded-Proto $scheme;        # Secure cookies
}
```

uvicorn trusts the forwarded headers only from `FORWARDED_ALLOW_IPS` (default `127.0.0.1`).
If the proxy runs elsewhere, set it to the proxy's address — never `*` on a port the
internet can reach. If the proxy cannot keep `Host`, add `--trusted-origin
https://your.public.name`.

## Upgrading from v0.5

- Existing logins end once (sessions moved server-side); sign in again. Passwords keep
  working and are re-hashed at 600k iterations on the next login.
- `GET /api/servers` no longer returns credentials. Scripts that read tokens back from the
  API must keep their own copy.
- `/api/export` is masked by default; add `?include_secrets=true` for the old behavior.
- `--no-auth` instances refuse new stdio servers over the API (`--allow-stdio-api` restores it)
  and answer only to loopback host names (add `--allowed-host`).
- The container runs as uid 10001; the entrypoint fixes the ownership of an existing volume
  automatically.

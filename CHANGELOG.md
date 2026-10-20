# Changelog

All notable changes to MCPSonar. Versions follow [SemVer](https://semver.org/); each release
is a Git tag `vX.Y.Z`, which is also how the GitHub Action is pinned.

## [Unreleased] — proposed 0.6.0

Security hardening release. Details, evidence and tests for each item:
[docs/engineering-audit.md](docs/engineering-audit.md). Upgrade notes:
[docs/configuration.md](docs/configuration.md#upgrading-from-v05).

### Security
- **Critical:** blocked a drive-by remote command execution. A page on any website could POST
  YAML to `/api/import` on an `--no-auth` instance (including `mcpsonar demo` and the watch
  compose) and make MCPSonar launch an arbitrary stdio command. State-changing requests from
  other sites or origins are now refused, and with `--no-auth`, stdio servers can't be added
  over the API unless `--allow-stdio-api` is given.
- `Host` allowlist (`--allowed-host`; loopback-only by default with `--no-auth`) against
  DNS rebinding.
- First-admin setup requires a one-time token printed in the log (or
  `MCPSONAR_SETUP_TOKEN`); concurrent setups can no longer create two admins.
- Server-side sessions, revoked on logout and stored as hashes; `Secure` cookie over HTTPS
  (`--cookie-secure`).
- Login throttling; PBKDF2 raised to 600k iterations and moved off the event loop (old hashes
  are upgraded at the next login).
- Credentials (headers, `env`, URL keys and userinfo, webhook and push URLs) are masked in API
  responses, the dashboard and exports, and scrubbed from check details, webhook and Kuma
  messages, logs and `scan` output. Editing a server keeps its stored credentials.
- Outbound policy enforced at connect time: cloud metadata and link-local addresses blocked;
  `MCPSONAR_BLOCK_PRIVATE_NETWORKS`, `MCPSONAR_OUTBOUND_ALLOW` / `_DENY`. Configured headers are
  no longer forwarded on cross-origin redirects; at most 5 redirects.
- Security headers (no framing, CSP, nosniff, no-referrer); 1 MiB body limit; bounded history
  queries; optional `MCPSONAR_METRICS_TOKEN` for `/metrics`; http(s)-only URLs.
- The container runs as an unprivileged user with no capabilities and has a HEALTHCHECK.
- `pyjwt>=2.15` (a transitive dependency with known advisories); CI runs `pip-audit`.

### Fixed
- `tools/list` pagination is followed. Only the first page used to be checked, pinned and
  linted.
- A stdio server that never answers can no longer hang its check loop: session read timeouts
  plus an overall check budget.
- Probes never call a tool the server doesn't list, and skip tools annotated destructive
  unless `allow_destructive: true`; new per-probe `timeout_seconds`.
- Duplicate tool names are reported; reordering a schema's `required` list is no longer a
  "tool change".
- Concurrent checks of the same server (Check now + loop) could record tool changes twice.
- Editing a server in the dashboard dropped its probes' arguments.

### Changed
- `GET /api/export` is masked by default (`?include_secrets=true` for a full export); import
  refuses a masked export.
- Everyone signs in once more after upgrading (sessions moved server-side).
- CI runs on Linux, Windows and macOS and smoke-tests the Docker image; Dependabot enabled.

## [0.5.0] — 2026-10-14

First tagged release.

### Added
- **Rug-pull detection**: every server's tool definitions are pinned on first sight; added,
  removed or changed tools are recorded and (by default) keep the server *degraded* until a
  human reviews the diff in the dashboard.
- **Tool-poisoning lint**: hidden Unicode, instruction overrides, fake `<IMPORTANT>` blocks,
  "don't tell the user", credential paths, exfiltration, tool shadowing, suspicious
  parameters.
- **Anomaly detection** with a learned per-server baseline: latency spikes (robust z-score),
  level shifts (change point) and flapping.
- `mcpsonar scan`: one-shot scan with a tool **lockfile** for CI, plus a GitHub Action.
- `mcpsonar demo`: dashboard against four scripted demo servers.
- `examples/popular-servers.yaml` + `docker-compose.watch.yml`: watch 24 hosted MCP servers.
- Validators for MCP spec 2024-11-05, 2025-03-26 and 2025-06-18 (besides 2025-11-25).

### Changed
- OAuth-protected servers (401/403 to an anonymous client) are **up · auth required**
  instead of down; rejected credentials are down; 429 is degraded (rate limited).

### Fixed
- Latency was inflated when several servers were checked at once (a TLS context was rebuilt
  on every check).
- Pinned `mcp>=1.28,<2`: the 2.x SDK is a breaking rewrite and broke every check on a fresh
  install.
- Source files contained literal zero-width and bidi-override characters (in the lint's own
  regex and two test fixtures). They are now written as Unicode escape sequences, and CI
  rejects any invisible character in tracked files.
- ruff pinned to an exact version so CI and local linting agree.
- Pausing, editing or deleting a server while one of its checks was in flight could hang
  forever: the MCP SDK can turn a cancellation into an ordinary error, which was recorded as
  "down" and the check loop kept running. Cancellation is now always propagated.

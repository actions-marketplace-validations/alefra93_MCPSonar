# Changelog

All notable changes to MCPSonar. Versions follow [SemVer](https://semver.org/); each release
is a Git tag `vX.Y.Z`, which is also how the GitHub Action is pinned.

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

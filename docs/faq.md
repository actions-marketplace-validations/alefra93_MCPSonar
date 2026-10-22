# FAQ

## What problem does MCPSonar solve?

AI agents call the tools that MCP servers announce, and they trust the tool descriptions.
A server can stay up and fast while those descriptions change. That covers:
- a *rug pull*: a tool you approved is swapped for another;
- *tool poisoning*: instructions for the model hidden in the text.

Ordinary uptime monitors don't see either. MCPSonar watches both, plus availability and
latency, and can gate CI on them.

## Does it block attacks?

No. MCPSonar is not a proxy between your agent and the server. It **detects** and
**reports**:
- it pins tool definitions, shows every change and keeps the server degraded until a human
  reviews it;
- it flags suspicious text;
- it fails a CI build.

What to do about a finding is your decision.

## Are the findings reliable?

They are heuristics: reasons to look at a tool, not proof of an attack. Each rule is
documented with examples, limits and measured false positives in
[detection-rules.md](detection-rules.md). The rug-pull detection itself is exact: it
compares SHA-256 fingerprints of the normalized definitions.

## Which servers can it monitor?

- **Transports:** Streamable HTTP, SSE and stdio (a local command).
- **Protocol versions:** every MCP revision from 2024-11-05 to 2026-07-28. Both the
  `initialize` handshake and `server/discover` are supported.
- **Servers behind OAuth:** without credentials, MCPSonar reports them as **up** with
  "auth required". It knows they answer, but it can't list their tools. With an
  `Authorization` header it checks them fully.

## Where does my data go?

Nowhere. MCPSonar is self-hosted, stores everything in one SQLite file and has no telemetry.
Its only outbound connections are to the servers you monitor and to the webhooks you
configure, under an [outbound policy](configuration.md#outbound-connection-policy) that
always blocks cloud metadata addresses.

## How are credentials protected?

- **At rest:** headers and stdio `env` values are stored in the database, so protect the file.
  [Secret references](configuration.md#secret-references) (`${env:…}`, `${file:…}`) keep
  them out of the database entirely.
- **When shown:** the dashboard, the API and exports mask them.
- **Accounts:** passwords and API tokens are stored as hashes only.

## How much does it cost to run?

It runs as one Python process; the Docker image runs as a non-root user. Each check is
about 250 bytes in the database, and history older than 7 days is deleted
(`--retention-days`). For example, 24 servers checked every minute is roughly 8 MB a day,
so about 60 MB with the default retention.

## How often does it check?

Every 60 seconds by default (`check_interval_seconds`, per server). Latency anomalies are
judged against each server's own learned baseline, not fixed thresholds. One slow period
gives one notification, plus one when it recovers.

## Can several people use it?

Today there is one admin account, plus API tokens (read or write) for the CLI and scripts.
Roles (admin, operator, viewer) are planned for v0.9; see the
[roadmap](product-roadmap.md).

## Is it on PyPI?

Not yet. Every [GitHub release](https://github.com/alefra93/MCPSonar/releases) attaches a
wheel that pip, pipx and uvx install directly. The GitHub Action is pinned by tag or by
commit SHA.

## How does it compare with other tools?

See [competitive-positioning.md](competitive-positioning.md).

## How do I report a false positive or a missed attack?

Open an issue with the "Detection report" template. Include the tool definition, or a
redacted version of it. Security vulnerabilities in MCPSonar itself go through private
vulnerability reporting (see `SECURITY.md`).

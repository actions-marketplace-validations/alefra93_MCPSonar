# MCPSonar product roadmap

> **Positioning:** open-source observability, integrity monitoring and security intelligence
> for MCP infrastructure — continuous, MCP-aware, self-hosted, local by default.

**Guiding goal for 1.0:** reach 1.0 with **5–10 real installations and documented feedback**,
rather than many features nobody has validated. Every milestone below is judged against
"does this help someone run MCPSonar in production and trust what it tells them?"

Effort is in focused engineer-days (one maintainer), and is approximate.

---

## v0.6.0 — Security hardening *(implemented on `feat/mcpsonar-web-app`, not released)*

**Features** (details in [engineering-audit.md](engineering-audit.md)):
- **Browser-facing hardening:**
  - CSRF and DNS-rebinding guards;
  - setup-token bootstrap with atomic creation;
  - server-side, revocable sessions;
  - login throttling and stronger password hashing;
  - security headers and body limits.
- **Credential handling:**
  - credentials masked in the API, exports, details, webhooks and logs;
  - stored secrets kept through edits.
- **Outbound connection policy:**
  - cloud metadata and link-local blocked;
  - addresses checked at connect time, closing the DNS-rebinding race;
  - configured headers stay on their origin.
- **Protocol and probing:**
  - `tools/list` pagination followed to the end;
  - session and check timeouts;
  - safe probing (unlisted tools never called, destructive ones skipped unless allowed);
  - fingerprints that ignore `required` order;
  - a per-server check lock.
- **Container and CI:**
  - non-root container with a HEALTHCHECK;
  - CI on Windows and macOS, `pip-audit`, a Docker smoke job, Dependabot.

**Remaining before tagging:**
- **Version and changelog:**
  - bump `pyproject` and the compose image tags to `0.6.0`;
  - date the changelog entry.
- **GitHub settings:** turn on private vulnerability reporting (referenced by `SECURITY.md`).
- **Real-environment check:** run the 24/7 watch deployment on the new image for 48 h; check for false *down* states caused by the new timeouts.

**Acceptance criteria:**
- All tests pass on 3.11–3.13, Linux, Windows and macOS.
- `pip-audit` is clean.
- The Docker smoke job is green.
- The upgrade notes in `docs/configuration.md` were checked on an existing v0.5 database.

| Risk | Effort left | Release blockers |
|---|---|---|
| Low–Medium: behavior changes for `--no-auth` LAN users and API scripts that read tokens back | about 1 day | CI green on the new matrix; 48 h soak test |

---

## v0.7.0 — Deep observability

**Features:**
- **Per-phase and per-tool latency:**
  - connect, initialize, discovery and each probe measured separately;
  - new Prometheus series: `mcpsonar_phase_latency_ms{phase}` and `mcpsonar_tool_latency_ms{tool}`;
  - existing metric names unchanged;
  - per-tool baselines and anomaly detection on top.
- **Response drift**, for explicitly configured, deterministic probes only. It compares:
  - the result *structure* (a JSON-shape fingerprint);
  - the `isError` and error-code behavior;
  - content types and the size bucket;
  - an optional canonicalized hash with user-supplied JSONPath excludes.
  Full bodies are not stored by default.
- **Anomaly quality:**
  - a cold-start policy;
  - a zero-MAD floor tested on recorded series;
  - sustained-regression versus spike classification;
  - **recovery events**;
  - baseline-poisoning resistance (a trimmed, slow-moving baseline);
  - alert deduplication keyed by `(server, kind, episode)`;
  - a reproducible statistical test corpus.
- **Notifications:**
  - Slack, Discord and email (SMTP) adapters on the existing `BaseAdapter`;
  - deduplication;
  - recovery notifications;
  - per-adapter rate limits;
  - configuration stays backward compatible.
- **MCP SDK 2.x / spec 2026-07-28 spike**, on a branch:
  - can `server/discover` and stateless requests be supported next to 1.x?
  - produce a compatibility matrix and a decision record (ADR).
- **Secret references** (`${env:NAME}`, `${file:…}`) resolved at check time (audit item T-03).

**Dependencies:**
- **Per-phase metrics:** the SDK must expose phase boundaries. Possible with 1.x through transport wrappers; re-check against 2.x.
- **Drift:** needs a schema migration (a versioned schema table).

**Acceptance criteria:**
- **Metrics:** no Prometheus metric renamed; new series documented.
- **Drift:** catches structural changes in the demo servers with zero false positives across 24 h of the watch deployment.
- **Notifications:** each adapter has `MockTransport` tests; a recovery is sent exactly once per incident.

| Risk | Effort | Release blockers |
|---|---|---|
| Medium (statistics tuning; SDK 2.x unknowns) | 12–18 days | Schema migration framework; false-positive budget met on real data |

---

## v0.8.0 — Developer experience

**Features:**
- **PyPI release** (`pip install mcpsonar`):
  - trusted publishing (OIDC) from `release.yml`;
  - sdist and wheel smoke-tested on 3 operating systems;
  - published only with explicit maintainer approval.
- **Detection rules and SARIF:**
  - every lint rule gets a stable ID (`MCPS-P001`…), severity, explanation, remediation, and positive and negative fixtures;
  - an adversarial corpus;
  - documentation in `docs/detection-rules.md`;
  - findings mapped to OWASP MCP Top 10 IDs.
- **SARIF 2.1.0 output:** `mcpsonar scan --sarif out.sarif`, plus a GitHub code-scanning example in the Action.
- **Structured output:**
  - stable `--json` schemas, versioned;
  - `mcpsonar validate-config`;
  - CLI errors that say what to do next.
- **Onboarding:**
  - a quickstart, a FAQ and troubleshooting;
  - example deployments (Compose with Caddy TLS, systemd);
  - a configuration JSON Schema for editor completion.
- **Contributor experience:**
  - incremental `mypy` (security modules first);
  - an architecture document;
  - "good first issue" rule contributions.

**Dependencies:**
- v0.6 interfaces frozen enough to document.
- The SARIF rule metadata comes from the rule registry.

**Acceptance criteria:**
- `pip install mcpsonar && mcpsonar demo` works on clean Linux, macOS and Windows machines.
- SARIF passes GitHub's validator.
- Every rule has at least 3 positive and 3 negative fixtures.

| Risk | Effort | Release blockers |
|---|---|---|
| Low | 8–12 days | PyPI name ownership; maintainer approval to publish |

---

## v0.9.0 — Teams and adoption

**Features:**
- **Roles:**
  - multiple users with *admin*, *operator* (review and approve changes) and *viewer* roles;
  - password change; session list and revoke.
- **Audit history:** who approved which tool change, when, and why (append-only), exportable.
- **MCPSonar Trust Report:** a shareable, self-contained HTML/PDF report per server or fleet, built for an IT owner. It covers:
  - availability and SLOs;
  - tool-definition changes and their review status;
  - open heuristic findings, labeled as heuristics;
  - drift;
  - time-to-review.
  It is generated from local data, with no service involved.
- **Dashboard:**
  - an incident timeline (started, recovered);
  - filters (unreachable, auth required, unreviewed changes, findings, regressions);
  - accessible colors and mobile layout;
  - explicit loading and error states.
- **Community validation:**
  - recruit 5–10 real deployments;
  - publish anonymized feedback and false-positive reports;
  - rule tuning based on them.

**Acceptance criteria:**
- Role checks are enforced server-side, with a test per endpoint.
- The audit log can't be edited through the API.
- The Trust Report renders offline and states the limits of its heuristics.

| Risk | Effort | Release blockers |
|---|---|---|
| Medium (auth model change, data migration) | 12–15 days | Migration from single-admin tested on real v0.8 databases |

---

## v1.0.0 — Stable

**Features and work:**
- **Stable interfaces:** documented and versioned for the REST API, `CheckEvent`, the lockfile format, metric names and the config schema, with a deprecation policy.
- **MCP spec 2026-07-28 support:** via SDK 2.x or a dual-stack client, according to the v0.7 ADR. Older revisions keep working.
- **Upgrades:** reliable upgrade path from v0.6+ databases, with tests on stored fixtures; documented backup and restore.
- **External security review:** of auth, network policy and stdio; fixes released before the 1.0 tag.
- **Production validation:** the 5–10 installations have run for at least 30 days; known issues are published.

**Acceptance criteria:**
- No open High or Critical findings.
- Upgrade tests pass from every 0.x version since 0.6.
- Every public interface is documented.

| Risk | Effort | Release blockers |
|---|---|---|
| Medium | 15–20 days plus the review lead time | Security review complete; the SDK 2.x decision implemented |

---

## Open-core strategy (options, not commitments)

**Principle:** the Community Edition stays MIT-licensed and complete for a team running its
own MCP fleet. Every feature released under MIT stays MIT. Nothing is moved behind a paywall,
and no artificial limits are added (server counts, retention caps, crippled exports).

**What a paid offering could add** (things that need *operated infrastructure* or
*organization-scale governance*, which a self-hosted single instance does not):

| Option | Why it is naturally commercial |
|---|---|
| Managed hosting (MCPSonar Cloud) | Someone runs, upgrades and backs up the service |
| Managed alert delivery and on-call routing | Reliable delivery infrastructure, SMS and voice |
| Central fleet management across many instances and organizations | Aggregation service, multi-tenancy |
| Enterprise SSO (SAML/OIDC) and SCIM | Integration and support burden. Basic OIDC login could still be community. |
| Organization-wide policies (e.g. "no unreviewed tool change older than 24 h in prod") with attestations | Governance workflows across teams |
| Long-term managed retention and compliance exports | Storage and operations |
| Enterprise support and SLA | People |

**Guardrails:**
- Community detection rules stay open, so the community can audit them.
- The Trust Report is in the Community Edition. A hosted, fleet-wide version is a natural paid
  extension.
- No telemetry without opt-in.

## Adoption plan alongside the releases

- Track installations through opt-in signals: GitHub stars and issues, a voluntary "who uses it"
  list, and Action usage. Never phone home.
- After v0.6: write up the audit, with a "what we fixed and why" post for credibility.
- After v0.8: share on community channels (MCP Discord, r/mcp, Hacker News "Show HN") with the
  PyPI one-liner and the demo.
- Treat every false-positive report as a test fixture.

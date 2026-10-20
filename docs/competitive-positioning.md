# Competitive positioning

**Research date:** 2026-10-20.

**How to read the labels:**
- **V** — verified on the project's own page (repository, PyPI, official site).
- **V2** — verified only from a secondary source (a directory, blog or vendor summary).
- **U** — unverified or inferred. Treat as an assumption.

**Limitations:**
- This is a snapshot. These projects move fast; re-check before quoting anything publicly.
- Where a feature is "not mentioned", that means absent from the project's documentation, not proven absent from its code.
- Release dates shown without a year come from GitHub release pages, which hide the year.

## Landscape

### MCP security scanners and monitors

**MCPRadar** · [repo](https://github.com/yatuk/mcpradar) · MIT
- **Model:** Python CLI with a public leaderboard (V). Latest is 1.0.0rc4 on PyPI, 2026-07-04 (V).
- **Detection:** local regex, entropy and overlap heuristics (V).
- **Change detection:** fingerprints plus `mcpradar diff` (V). Per PyPI the fingerprint covers tool *names*; whether full schemas are hashed is unclear (U).
- **CI:** SARIF 2.1.0 output (V) and an example workflow, but no published Action (V).
- **Continuous:** a watch mode with webhook alerts, per PyPI (V).
- **Uptime / latency:** not mentioned.

**ZugaWatch** (listed as "MCP Sentinel") · [repo](https://github.com/Zuga-luga/zugawatch) · MIT
- **Model:** CLI plus a GitHub Action; marked *inactive* on Glama (V).
- **Detection:** heuristics; call-chain anomaly rules (V).
- **Change detection:** a lockfile pinned on first connect, with an approval flow (V).
- **CI:** the Action fails on drift or a low grade (V).
- **Continuous:** no.
- **Uptime / latency:** not mentioned.

**Snyk Agent Scan** (formerly Invariant mcp-scan) · [repo](https://github.com/snyk/agent-scan) · Apache-2.0
- **Model:** local CLI plus a background/MDM mode that reports to Snyk (V).
- **Detection:** sends tool names and descriptions to Snyk's API, with secrets redacted first (V).
- **Change detection:** tool pinning appears in the original 2025 post (V); the current README does not mention it (V).
- **CI:** `--ci` exit codes and `--json` (V); SARIF not mentioned.
- **Continuous:** interval scans in background mode (V).
- **Uptime / latency:** not mentioned.

**Cisco MCP Scanner** · [repo](https://github.com/cisco-ai-defense/mcp-scanner) · Apache-2.0
- **Model:** CLI, REST server and SDK (V).
- **Detection:** YARA, plus an LLM judge (cloud or local), plus Cisco's remote API with a key (V); behavioral code analysis (V).
- **Change detection, CI, continuous mode, uptime / latency:** none documented.

**Trail of Bits mcp-context-protector** · [repo](https://github.com/trailofbits/mcp-context-protector) · Apache-2.0
- **Model:** an inline wrapper/proxy (V).
- **Detection:** pluggable guardrails on responses (V).
- **Change detection:** trust-on-first-use pinning, compared ignoring order; calls are **blocked** until a change is approved (V).
- **CI:** none. **Uptime / latency:** none.
- **Continuous:** inline, at runtime.

**Ramparts** (Highflame) · [repo](https://github.com/getjavelin/ramparts) · Apache-2.0
- **Model:** Rust CLI, a server mode and an MCP mode (V).
- **Detection:** YARA plus LLM analysis (whether that runs locally is unstated) (V).
- **Change detection:** baseline fingerprints (V).
- **CI:** SARIF, with findings tagged to the OWASP MCP Top 10 (V).
- **Continuous:** a server mode "for continuous monitoring" (V).
- **Uptime / latency:** not mentioned.

**MCP-Shield** · [repo](https://github.com/riseandignite/mcp-shield) · MIT
- **Model:** an npx CLI over local configs (V).
- **Detection:** local, plus optional Claude analysis (V).
- **Change detection, CI, continuous mode, uptime / latency:** none documented.

### General monitoring

- **[Uptime Kuma](https://github.com/louislam/uptime-kuma)** (latest 2.5.6): no MCP-specific monitor type was found in its release notes or by search (V, absence only). Its generic HTTP keyword/JSON monitors could check *that* an endpoint answers, not that it speaks MCP or what its tools say (U). MCPSonar already **pushes into** Kuma rather than competing with it.

### MCP gateways and observability

These sit in the request path or instrument real traffic; none of them states tool-definition change detection.

- **[Docker MCP Gateway](https://github.com/docker/mcp-gateway)** (MIT): container isolation, secrets, OAuth, per-tool allowlists, call tracing, image signature verification (V).
- **[IBM ContextForge](https://github.com/IBM/mcp-context-forge)** (Apache-2.0, v1.0.11, already on SDK 2.x): gateway with OpenTelemetry, Prometheus via Helm, 40+ plugins including guardrails (V).
- **[agentgateway](https://github.com/agentgateway/agentgateway)** (Linux Foundation): federation, RBAC, OpenTelemetry, guardrails (V).
- **[Microsoft MCP Gateway](https://github.com/microsoft/mcp-gateway)** (MIT): Kubernetes-native routing, App Insights telemetry; requires 2026-07-28 clients (V).
- **[Lasso MCP Gateway](https://github.com/lasso-security/mcp-gateway)** (MIT): secret and PII masking, prompt-injection checks through Lasso's API, a description scan (V).
- **Datadog / Grafana:** MCP *client* tracing with latency for `tools/list` and `call_tool` (V2). This measures real traffic; it is not synthetic probing.

## Where MCPSonar is actually different

These are claims we can defend. Each is supported by what the sources above document, or don't.

1. **Health and integrity in one self-hosted service.**
   - The scanners above are security-only; the gateways and APMs are traffic-only.
   - We found no other open-source project that documents continuous MCP-aware health checks, uptime and latency (with learned per-server baselines), *and* tool pinning with human review in the same service (absence noted from documentation).
2. **Operational outputs that teams already use.** Prometheus metrics *about the probed servers*, an Uptime Kuma push, and generic webhooks. No other scanner documents these.
3. **Local and offline by default.** Analysis needs no API key and makes no remote call. Snyk sends descriptions to its API, and Cisco's and Lasso's full feature sets need remote APIs.
   - This is not unique: MCPRadar, ZugaWatch and MCP-Shield's base mode are local too. It is a property we share with them, not a differentiator.
4. **CI and runtime from one tool definition model.** The `scan` lockfile and GitHub Action use the same fingerprints as the continuous monitor. ZugaWatch offers a similar lockfile and Action but appears inactive.

**Claims to avoid:**
- "first" or "only" MCP security scanner;
- "detects malicious servers" — heuristics flag content for review;
- "protects agents at runtime" — MCPSonar observes; it does not block.

## Where others are stronger, and what we do about it

| Area | Stronger today | Our response |
|---|---|---|
| SARIF / code scanning | MCPRadar, Ramparts | v0.8: SARIF output plus rule IDs mapped to the OWASP MCP Top 10 |
| Detection depth | Cisco (YARA, LLM, source analysis), Snyk (hosted classifier) | Keep local heuristics explainable. An optional, opt-in local-model hook could come later; never default remote calls. |
| Runtime enforcement | Trail of Bits (blocks unapproved changes), gateways | Integrate rather than compete: document pairing with a gateway; export approved baselines in a form a gateway could enforce (exploratory) |
| Latest protocol | Gateways already on spec 2026-07-28 / SDK 2.x | v0.7 spike, v1.0 support (audit item T-01) |
| Enterprise fleet / brand | Snyk (MDM fleet mode) | Not a v1 goal. A possible future managed offering (see the roadmap). |
| Real-traffic latency | Datadog, Grafana, OpenTelemetry gateways | Synthetic probing complements them. Possibly accept OpenTelemetry later. |

## Messaging

> **MCPSonar** watches your MCP servers the way an SRE and a security reviewer would together:
> is it up and fast, does it still speak MCP correctly, and did its tools change since you
> trusted them? It is self-hosted, open source and works offline. It integrates with
> Prometheus, Uptime Kuma and your CI.

**Repository topics to set** (GitHub settings, by the maintainer):

```text
mcp, model-context-protocol, mcp-security, monitoring, observability, uptime-monitoring,
prometheus, tool-poisoning, rug-pull, supply-chain-security, ai-security, self-hosted
```

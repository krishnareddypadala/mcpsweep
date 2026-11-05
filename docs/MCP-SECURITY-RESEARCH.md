# MCP Security Research — Consolidated Master (Claude + Gemini + Grok)

> **Purpose.** Single source of truth for `mcpsweep` v1.0. Merges three independent
> research passes — **Claude** (this session's web research), **Gemini**, and **Grok** —
> plus a direct spec verification. Every point is attributed and confidence-marked.
> Date compiled: **2026-11-05**.

**Confidence legend**
`✅ VERIFIED` — confirmed against a primary source (NVD, the MCP spec, a GHSA advisory).
`🟢 TRIANGULATED` — all three research passes agree.
`🟡 SINGLE-SOURCE` — one pass only; treat as a lead.
`⚠️ UNVERIFIED` — flagged by a source as unconfirmed, or found to be wrong. **Do not ship.**

**Design constraints (non-negotiable — they are the product):**
Zero runtime dependencies (stdlib only) · read-only by default · local-only (no cloud, no LLM, no telemetry).
`ZD` = zero-dep · `RO` = read-only · `LO` = local-only.

---

## 0. Headline findings (what matters most)

| # | Finding | Confidence | Source |
|---|---|---|---|
| 1 | **Spec `2026-07-28` makes MCP stateless: removes the `initialize` handshake and `Mcp-Session-Id`; adds mandatory `server/discover`.** `initialize`-only fingerprinting (what mcpsweep does today) **fails against modern-only servers.** This is existential. | ✅ VERIFIED + 🟢 TRIANGULATED | spec changelog; confirmed by me, flagged by the Grok/deep-research docs |
| 2 | **554 MCP-tagged CVEs on NVD (2025 → Nov 2026).** All 14 seed CVEs are real. Dominant classes: missing-auth ~106, SSRF ~82, command injection ~64, OAuth ~53, Origin/Host ~48, DoS ~34, 0.0.0.0-bind ~24, DNS-rebind ~22, CORS ~18, read-only-bypass ~14, session ~13. | ✅/🟡 (counts are keyword-approximate) | NVD API pull (deep-research doc) |
| 3 | **Our moat holds and sharpens:** the only *network-discovery-first, zero-dep, read-only, local-only, no-LLM* MCP scanner. **Every competitor phones home, needs an API key/LLM, or scans source only.** | 🟢 TRIANGULATED | all three |
| 4 | **Competitors already speak `server/discover`** (Cisco, saagpatel). Parity requires it. | 🟡 SINGLE-SOURCE | deep-research doc |
| 5 | **Bug-bounty money for MCP is small/scattered.** Anthropic H1 pays $100–$10k by tier, **but the `modelcontextprotocol` OSS repos are out of scope** (GHSA path). Most CVEs came from vendor research/GHSA, not bounties. | ✅ VERIFIED | Anthropic H1 policy |

---

## 1. The verified spec change (`2026-07-28`) — details

All ✅ VERIFIED against the live spec (changelog + versioning + `server/discover` pages):

- **`initialize` removed from the modern protocol.** Changelog: *"Make MCP stateless: remove the `initialize`/`notifications/initialized` handshake."* Versioning page: *"There is no negotiation handshake. Every request carries its protocol version."*
- **`initialize` survives only for legacy/dual-era.** "Legacy" = versions "that establish a session with an `initialize` handshake (`2025-11-25` and earlier)." Dual-era servers **MAY** support both. A **modern-only** server rejects `initialize` with an implementation-defined error or silence (only a *SHOULD* to name supported versions).
- **`Mcp-Session-Id` removed** from Streamable HTTP. Replacement: *"explicit, server-minted handles passed as ordinary tool arguments."*
- **`server/discover` is MUST-implement for servers**, optional for clients. Carries no body beyond `_meta` (with `io.modelcontextprotocol/protocolVersion`). Response includes `resultType`, `supportedVersions`, `ttlMs`, `cacheScope`, `capabilities`, `serverInfo`, `instructions`.
- **New required HTTP headers** on Streamable HTTP POST: `Mcp-Method`, `Mcp-Name` (plus `x-mcp-header` for custom tool-param headers). Missing them → `400 Bad Request`.
- **`resultType`** now required on *all* results (`"complete"` / `"input_required"`).
- **`ttlMs` + `cacheScope`** required on `tools/list`, `prompts/list`, `resources/list`, `resources/read`, `resources/templates/list` (new `CacheableResult`).
- **Version order on the site:** `2026-07-28`, `2025-11-25`, `2025-06-18`, `2025-03-26`, `2024-11-05`, `draft`. ⚠️ No page explicitly labels `2026-07-28` "latest" — unconfirmed whether a newer revision exists.
- **Scanner implication:** the reliable modern probe is `server/discover` (with `_meta` + the two headers on HTTP); keep `initialize` as a legacy/dual-era fallback. mcpsweep currently hardcodes `PROTOCOL_VERSION = "2024-11-05"`.

---

## 2. CVE inventory

### 2.1 Seed list — all 14 verified against NVD (✅)

| CVE | Component | Class (CWE) | CVSS | Fix |
|---|---|---|---|---|
| CVE-2025-6514 | `mcp-remote` (npm client proxy) | OS cmd injection via `authorization_endpoint` (CWE-78) | 9.6 | 0.1.16 |
| CVE-2025-49596 | MCP Inspector | No auth client↔proxy → RCE (CWE-306) | 9.4 | 0.14.1 |
| CVE-2025-58444 | MCP Inspector | XSS via malicious server redirect → RCE (CWE-84) | 8.6 | 0.16.6 |
| CVE-2025-53107 | `@cyanheads/git-mcp-server` | Cmd injection via `child_process.exec` (CWE-77) | 7.5 | 2.1.5 |
| CVE-2025-53967 | Framelink Figma MCP | Unauth OS cmd injection via curl fallback (CWE-420) | 8.0 | 0.6.3 |
| CVE-2025-53109 | Reference Filesystem server | Symlink escape (CWE-59) | 7.3 | 0.6.4 / 2025.7.01 |
| CVE-2025-53110 | Reference Filesystem server | Path-prefix bypass (CWE-22) | 7.3 | 0.6.4 / 2025.7.01 |
| CVE-2025-54135 "CurXecute" | Cursor | Prompt injection writes `mcp.json` → auto-start RCE (CWE-78) | 8.5 CNA / **9.8 NVD** | 1.3.9 |
| CVE-2025-54136 "MCPoison" | Cursor | Approved MCP config swapped later (approval tied to name) (CWE-78) | 7.2 CNA / **8.8 NVD** | 1.3 |
| CVE-2025-68143 | Anthropic `mcp-server-git` | `git_init` accepts any path (CWE-22) | 6.5 v4 / 8.8 v3.1 | 2025.9.25 |
| CVE-2025-68144 | Anthropic `mcp-server-git` | Arg injection (`--output=`) in git_diff/checkout (CWE-88) | 6.3 v4 / 7.1 v3.1 | 2025.12.17/18 |
| CVE-2025-68145 | Anthropic `mcp-server-git` | `--repository` boundary bypass (CWE-22) | 6.4 v4 / 9.1 v3.1 | 2025.12.17/18 |
| CVE-2025-52573 | `ios-simulator-mcp` | Cmd injection (CWE-78) | 6.0 | 1.3.3 |
| CVE-2026-33032 | `nginx-ui` MCP | `/mcp_message` skips auth that `/mcp` enforces (CWE-306) | 9.8 | ⚠️ fixed release unconfirmed |

> **Conflict (resolved):** THN scores the git trio differently from NVD. **Prefer NVD.** Fix date: NVD "prior to 2025.12.17" vs Cyata/Register "2025.12.18."

### 2.2 Official SDK & reference-server advisories (most relevant to a protocol scanner) (✅)

| CVE / ID | Component | Class | CVSS | Fix |
|---|---|---|---|---|
| **CVE-2025-66414** | TS SDK `@modelcontextprotocol/sdk` | **DNS-rebinding protection OFF by default** (CWE-1188) | 7.6 v4 / 8.1 v3.1 | **1.24.0** |
| **CVE-2025-66416** | Python SDK `mcp` | **DNS-rebinding protection OFF by default** (CWE-1188) | 7.6 v4 / 8.1 v3.1 | **1.23.0** |
| CVE-2025-53365 | Python SDK | Client-triggered exception crashes server (CWE-248, DoS) | 8.7 v4 | 1.10.0 |
| CVE-2025-53366 | Python SDK | Malformed request → unhandled exception → DoS (CWE-248) | 8.7 v4 | 1.9.4 |
| CVE-2026-25536 | TS SDK | One client's responses leak to another on reused transport (CWE-362/367) | 7.1 v3.1 | 1.26.0 |
| CVE-2026-52870 | Python SDK | Default `tasks/list\|get\|result\|cancel` have no authz (CWE-862) | 7.6 v3.1 | 1.27.2 |
| CVE-2026-111767 | TS SDK `taskStore` | Tasks not bound to creating session → IDOR (CWE-639) | 8.6 v3.1 | 1.32.0 |
| CVE-2026-59951 | Python SDK (stateful Streamable HTTP) | Unbounded session accumulation → memory DoS (CWE-400) | 6.9 v4 | 1.30.0 / 2.2.0 |
| CVE-2026-111771 | TS SDK server | Bearer accepts token for a different audience | 6.8 (secondary) | 2.3.0 — ⚠️ **not in NVD** |
| GHSA-46jr-4wx8-v453 | TS SDK / server | Memory exhaustion via unbounded arrays; fix flag `maxToolInputElements` OFF by default | — | 1.32.0 / 2.3.0 |
| GHSA-6prh-2h8m-c8cw | TS SDK client + OAuth | Follows cross-origin redirects, re-sends headers + `mcp-session-id`; on 307/308 re-sends `refresh_token`/`client_secret` (CWE-200) | 6.5 v3.1 | 1.32.0 / 2.3.0 |
| GHSA-5h93-6whr-6q8j | Python SDK HTTP transports | Same cross-origin-redirect class | ⚠️ not fetched | — |
| servers v2.1.0 | `server-filesystem`, `server-everything`, `mcp-server-fetch` | "Eight vulnerabilities in three servers" — ⚠️ IDs not mapped | — | fs/everything 2.0.1; fetch 2026.10.24 |

### 2.3 High-signal third-party CVEs (each maps to a scanner check) (✅ unless noted)

| CVE | Component | Class | CVSS | Scanner relevance |
|---|---|---|---|---|
| CVE-2026-49257 | `mcp-pinot` ≤3.0.1 | HTTP defaults to **0.0.0.0:8080 no auth** (CWE-306) | **10.0** | 0.0.0.0 exposure + unauth tools |
| CVE-2026-51994 | `mcp-remote` 0.1.32–0.1.38 | SSRF via `resource_metadata` URL in `WWW-Authenticate` (CWE-918) | 9.1 | Passive OAuth URL hygiene |
| CVE-2026-115413 | AWS API MCP Server <1.6.0 | OAuth token **audience not validated** (CWE-346) | 7.3 | Audience/RFC 8707 check |
| CVE-2026-116635 | AWS Serverless MCP <0.2.1 | Path traversal (CWE-23/36) | 6.9 | Version match |
| CVE-2026-46519 | `mcp-server-kubernetes` <3.6.0 | `ALLOW_ONLY_READONLY_TOOLS` doesn't restrict (CWE-863) | 8.8 | "Read-only" claim vs. actual tools |
| CVE-2026-61459 | MCP Server Kubernetes <3.9.0 | Arg injection, leading-dash params (CWE-88) | 9.3 | Schema lint: free-form strings → CLIs |
| CVE-2026-18954 | AWS DocumentDB MCP <1.0.12 | Read-only bypass via write aggregation stages (CWE-863) | 5.7 | Read-only bypass class |
| CVE-2026-87911 | AWS postgres-mcp-server <1.1.7 | Read-only SQL bypass → OS cmd via `COPY … TO PROGRAM` (CWE-78/184) | 9.0 | Read-only bypass class |
| CVE-2026-14540 | Google `mcp-toolbox` 0.3.0–1.4.0 | SSRF in generic HTTP tool (CWE-918) | 8.0 | Version match |
| CVE-2026-27826 | `mcp-atlassian` <0.17.0 | Unauth SSRF over HTTP (CWE-918) | 8.2 | Unauth + version match |
| CVE-2026-0755 | `gemini-mcp-tool` | Unauth cmd injection via `execAsync` (CWE-78) | 9.8 | Version match |
| CVE-2026-85654 | awslabs `dynamodb-mcp-server` <2.1.6 | Template injection in CDK generator (CWE-1336) | 7.1 | Version match |
| CVE-2026-63655 / 76892 / 76893 | `@tsparticles/mcp-server` <4.3.1/4.3.2 | Unbounded body buffering (7.5); malformed JSON crash (8.7); shared stateful transport takeover by first unauth `initialize` (6.9) | see cells | Shared-transport/session class |
| CVE-2026-30632 | `knowns-dev/knowns` 0.11.4 | Dir traversal via `create_doc` folder name | — | Version match |
| CVE-2026-114612 | LiteLLM 1.87.0→1.100.4 | Reused crypto context → priv-esc (CWE-269/345/441) | 9.9 v3.1 | ⚠️ **NVD text doesn't mention MCP** — do not count as MCP |

### 2.4 OX Security "MCP STDIO config-to-command" family (✅ all in NVD)

> Class: an app saves an MCP server definition with arbitrary `command`/`args`, then runs it on the host.

| CVE | Product | CVSS | Note |
|---|---|---|---|
| CVE-2026-30623 | LiteLLM 1.18.10 | 9.8 | MCP server creation runs arbitrary command/args |
| CVE-2026-30624 | Agent Zero 0.9.8 | 8.6 | External MCP server config |
| CVE-2026-30618 | xszyou Fay 4.3.1 | 9.8 | Public MCP management interface |
| CVE-2026-30617 | LangChain-ChatChat 0.3.1 | 8.6 | Public MCP management interface |
| CVE-2026-30625 | Upsonic 0.71.6 | 9.8 | Allowlist includes `npm`/`npx` (flags enable exec) |
| CVE-2026-30615 | Windsurf 1.9544.26 | 8.0 | Prompt injection edits config, auto-registers server |
| CVE-2026-26015 | DocsGPT 0.15.0→<0.16.0 | 9.8 (10.0 v4) | "MCP test" bypass → RCE |
| CVE-2026-40933 | Flowise <3.1.0 | 9.9 | Unsafe serialization of stdio commands |
| CVE-2025-65720 | GPT Researcher v3.3.7 | 9.8 | ⚠️ NVD text doesn't mention MCP — grouping unconfirmed |

### 2.5 Additional NVD-listed MCP CVEs (sample from the 554; ✅ each seen on NVD)

> The long tail — useful for the offline version-match DB (Gap T2). Not exhaustive; full dump is in the deep-research doc's Appendix A.

- CVE-2025-4143 — Cloudflare workers-oauth-provider — open redirect (CWE-601) — 6.0
- CVE-2025-5273 — mcp-markdownify-server — file/dir exposure (CWE-552) — 6.9
- CVE-2025-5276 — mcp-markdownify-server — SSRF (CWE-918) — 6.9
- CVE-2025-5277 — aws-mcp-server — cmd injection (CWE-78) — 9.4
- CVE-2025-6515 — oatpp-mcp — session id = instance pointer, not unique/secure (CWE-330) — 6.8
- CVE-2025-8665 — agno — cmd injection — 2.1
- CVE-2025-8943 — Flowise Custom MCPs — no-auth + cmd exec (CWE-306/862) — 9.8
- CVE-2025-9611 — Microsoft Playwright MCP — Origin header not validated (CWE-749) — 7.2
- CVE-2025-9654 — AiondaDotCom mcp-ssh — injection (CWE-74/77) — 5.3
- CVE-2025-10193 — Neo4j Cypher MCP — DNS rebinding (CWE-346) — 7.4
- CVE-2025-10619 — sequa-mcp — oauth helper injection — 2.1
- CVE-2025-11286 — samanhappy MCPHub — SSRF (CWE-918) — 2.0
- CVE-2025-15061 — Framelink Figma MCP — `fetchWithRetry` cmd injection RCE (CWE-78) — 9.8
- CVE-2025-15063 — Ollama MCP Server — `execAsync` cmd injection RCE (CWE-78) — 9.8
- CVE-2025-20381 — Splunk MCP Server <0.2.4 — SPL command bypass (CWE-863) — 5.4
- CVE-2025-34072 — Anthropic (deprecated) Slack MCP — data exfil via link unfurling (CWE-20/200) — 9.3
- CVE-2025-35028 — HexStrike AI — cmd injection via `;`-prefixed arg (CWE-78) — 9.1
- CVE-2025-47274 — ToolHive — cleartext storage ordering (CWE-311) — 2.4
- CVE-2025-47777 — 5ire (MCP client) — stored XSS (CWE-20/79) — 9.6
- CVE-2025-53100 — Codehooks.io MCP — cmd injection (CWE-78) — 8.6
- CVE-2025-53355 — MCP Server Kubernetes — cmd injection (CWE-77) — 7.5
- CVE-2025-53372 — node-code-sandbox-mcp — sandbox/exec — 7.x
- CVE-2025-53818 — GitHub Kanban MCP Server — cmd injection (CWE-78) — 8.9
- CVE-2025-53832 — Lara Translate MCP Server ≤0.0.11 — cmd injection (CWE-77) — 7.5
- CVE-2025-54073 — mcp-package-docs — cmd injection (CWE-77) — 7.5
- CVE-2025-54074 — Cherry Studio 1.2.5–1.5.1 — OS cmd injection (CWE-78) — 7.7
- CVE-2025-54382 — Cherry Studio 1.5.1 — RCE (CWE-78) — 8.8
- CVE-2025-54424 — 1Panel — cmd injection (CWE-77) — 9.8
- CVE-2025-54994 — @akoskm/create-mcp-server-stdio <0.0.13 — cmd injection (CWE-78) — 9.3
- CVE-2025-56406 — mcp-neo4j 0.3.0 — info disclosure / cmd via SSE (CWE-77/200/284) — 7.5
- CVE-2025-58062 — openmcp-client <0.1.12 — Windows cmd injection (CWE-78) — 7.3
- CVE-2025-58337 — Doris MCP Server — read-only mode bypass (CWE-284) — 5.4
- CVE-2025-58357 — 5ire 0.13.2 — XSS (CWE-79) — 9.6
- CVE-2025-58358 — Markdownify <0.0.2 — cmd injection (CWE-77) — 7.5
- CVE-2025-58747 — Dify ≤1.9.1 — MCP OAuth XSS (CWE-79) — 2.0
- CVE-2025-59155 — hackmd-mcp 1.4.0–<1.5.0 — SSRF (CWE-918) — 6.9
- CVE-2025-59163 — vet ≤1.12.4 — DNS rebinding, no Host validation (CWE-350) — 2.1
- CVE-2025-59333 — @executeautomation/database-server ≤1.1.0 — missing access control (CWE-284) — 8.1
- CVE-2025-59417 — Lobe Chat <1.129.4 — XSS (CWE-79) — 6.8
- CVE-2025-59528 — Flowise 3.0.5 — RCE (CWE-94) — 10.0
- CVE-2025-59834 — ADB MCP Server ≤0.1.0 — cmd injection (CWE-77/78) — 9.8
- CVE-2025-61590 — Cursor ≤1.6 — RCE via VS Code path (CWE-94) — 7.5
- CVE-2025-61591 — Cursor ≤1.7 — OAuth w/ untrusted MCP (CWE-78) — 8.8
- CVE-2025-62800 — FastMCP <2.13.0 — reflected XSS in OAuth (CWE-79) — 5.3

### 2.6 Class distribution across the 554 NVD records (🟡 keyword-approximate)

| Class | ≈ Count |
|---|---|
| Unauthenticated / missing auth | 106 |
| SSRF | 82 |
| Command / OS injection | 64 |
| OAuth-related | 53 |
| Origin/Host validation | 48 |
| DoS / resource exhaustion | 34 |
| 0.0.0.0 / all-interfaces binding | 24 |
| DNS rebinding | 22 |
| CORS | 18 |
| "Read-only" mode bypass | 14 |
| Session handling | 13 |

---

## 3. OWASP MCP Top 10 (2025 beta, v0.1 — CC BY-NC-SA 4.0) 🟢

Project is Phase-3 beta; IDs carry a `:2025` suffix.

| ID | Name | mcpsweep coverage today |
|---|---|---|
| MCP01 | Token Mismanagement & Secret Exposure | ✅ resource secret/PII scan |
| MCP02 | Privilege Escalation via Scope Creep | ⚠️ partial (confused-deputy) |
| MCP03 | Tool Poisoning | ✅ desc/instructions/prompt poisoning; rug-pull planned |
| MCP04 | Software Supply Chain & Dependency Tampering | ✅ stdio "runs 3rd-party code" flag; config-lint planned |
| MCP05 | Command Injection & Execution | ✅ cmd sink; deser/eval/`shell=True` planned |
| MCP06 | Prompt Injection via Contextual Payloads | ✅ POISON_RE across fields |
| MCP07 | Insufficient AuthN/AuthZ | ✅ no-auth + OAuth meta + active BOLA |
| MCP08 | Lack of Audit & Telemetry | ❌ (capability-check possible) |
| MCP09 | Shadow MCP Servers | ✅ **core strength** (network discovery) |
| MCP10 | Context Injection & Over-Sharing | ⚠️ partial |

---

## 4. Bug-bounty landscape

| Program / venue | MCP in scope? | Payout | Public reports | Conf. |
|---|---|---|---|---|
| Anthropic (HackerOne) | Products yes; **`modelcontextprotocol` OSS repos OUT (GHSA path)** | $100–$10k by asset tier | — | ✅ |
| PortSwigger (H1) | Burp MCP server | not disclosed | #3176157 | 🟡 |
| Cloudflare (H1) | Cloudflare MCP servers | not disclosed | #3316910, #3424998 | 🟡 |
| AWS VDP (H1) | AWS MCP servers | VDP (no bounty) | #3557138 | 🟡 |
| huntr (Protect AI) | AI/ML OSS incl. some MCP | ⚠️ caps unverified | — | ⚠️ |
| Google AI VRP | Google AI products | ⚠️ caps unverified | — | ⚠️ |

**Takeaway:** most published MCP CVEs came from vendor teams / GHSA, not bounties. No public H1 report shows a bounty amount — none claimed.

---

## 5. Competitor matrix 🟢 (phone-home read agreed by all three)

> "Phones home" = sends scan data (tool descriptions, configs) to a vendor/LLM **by default**, beyond the target server.

| Tool | Type | Capabilities | Transports | Phones home? |
|---|---|---|---|---|
| **Snyk Agent Scan** (ex-Invariant mcp-scan) | OSS CLI + commercial | agent/MCP/skill discovery; prompt injection, tool poisoning, toxic flows, malware | stdio, remote URLs | **Yes** — uploads configs/signatures, tool names+descriptions, skill content |
| **Cisco AI Defense mcp-scanner** | OSS Apache-2.0 + optional API | YARA/LLM/AI-Defense engines; **`protocol` cmd negotiates 2026-07-28, probes `Mcp-Method` mismatches**; schema analyzer | stdio, Streamable HTTP, offline fixtures | Only if configured |
| **Akamai MCProbe** | OSS | config/network/static/SSE/auth + **AI review** (LangGraph); AST taint of repos | HTTP/SSE, GitHub repos | **Yes by default** (Claude backend unless `--offline`/`--no-ai`) |
| **AxioRank mcpaudit** | OSS CLI (+ commercial control plane) | prompt injection, leaked secrets, tool shadowing, dangerous capabilities | stdio, Streamable HTTP, well-known card | **No** — "only network call is to the server you point it at" |
| **saagpatel MCPAudit** (`mcp-audits`) | OSS MIT | config audit, checkup card, offline `explain`; **sends credential-free `server/discover`** | configs; HTTP opt-in | No by default |
| **mcp-authscan** (LHMisme420) | OSS | 11 OAuth **authorization-server** probes (RFC 9728, token CORS, cross-tenant); **does NOT test resource endpoints**; refuses w/o authorization flags | HTTP | No telemetry |
| **Highflame Ramparts** | OSS Apache-2.0 (Rust) | YARA + LLM, OWASP MCP Top-10 tagging, skill-file scan | HTTP, stdio, configs | LLM analysis external (⚠️ default unconfirmed) |
| **NOVA Proximity** (fr0gger) | OSS GPL-3.0 | NOVA rules + LLM evaluator; spec 2025-11-25 | Streamable HTTP, stdio | Only if LLM evaluator chosen |
| **mcp-shield** (riseandignite) | OSS | local-config scan: poisoning, exfil, cross-origin shadowing | configs → servers | Only with `--claude-api-key` |
| **Trail of Bits mcp-context-protector** | OSS | runtime **wrapper**: TOFU config pinning, line-jumping defense, ANSI sanitizing, quarantine | wraps stdio/HTTP | No (local proxy) |
| **mcp-watch** (kapilduraphe) | OSS | static source scan of GitHub repos: creds, injection | repo/Docker | clones repos |
| **piiiico mcpaudit** | OSS | static SAST rules JS/TS/Python (`ssrf-http`, etc.) | repo | fetches repos |
| **AndrewXuTurtle mcpaudit** | OSS | machine-wide config audit; confidence tiers; `--deep` downloads source; plaintext-HTTP / missing-auth | configs | `--deep` downloads |
| Pillar Security mcp-audit / OpenCode | ⚠️ | ⚠️ no primary repo/post found | — | ⚠️ |

**Where mcpsweep uniquely sits:** only tool that is **network-discovery-first + ZD + RO + LO + no-LLM**. `mcp-authscan` covers the *authorization server*, leaving the **resource-server** auth checks open for our `--auth-probe`.

---

## 6. Attack techniques → can a passive/read-only scan see it?

| Technique | Passive-detectable? | Notes |
|---|---|---|
| Tool poisoning (hidden instructions in descriptions) | ✅ Yes | heuristics over `tools/list` |
| **Full-schema poisoning** ("poison everywhere": param names, enums, outputs, errors) | ✅ Yes | inspect whole `inputSchema`/`outputSchema`, not just `description` (CyberArk) |
| Line jumping (injection before any call) | ✅ Yes | at `tools/list` time (Trail of Bits) |
| ANSI terminal-escape deception | ✅ Yes | flag `\x1b[` in metadata (Trail of Bits) |
| **Unicode TAG-block (U+E0000–E007F) concealment** | ✅ Yes | flag invisible/bidi code points (arXiv 2607.05744) |
| Rug pull (metadata changes post-approval; MCPoison) | ✅ Yes | hash baselines + `diff` — **mcpsweep already ~90% has this** |
| Toxic flows (private-data + untrusted-input + egress on same agent) | 🟡 Partly | capability tagging across servers (no LLM) |
| **NeighborJack** (0.0.0.0 reachable from LAN) | ✅ **Core fit** | network discovery (Backslash; CVE-2026-49257) |
| DNS rebinding vs localhost (SDK defaults) | ✅ Yes | spoofed `Host`/`Origin`, see if accepted (CVE-2025-66414/66416) |
| Sibling-endpoint auth gap (`/mcp` auth, `/mcp_message` none) | ✅ Yes | CVE-2026-33032 |
| Shared-transport / session hijack; task IDOR | 🟡 Partly | session-id entropy/reuse; `tasks/list` w/o auth (CVE-2026-25536/111767/52870) |
| OAuth metadata abuse (cmd-inj `authorization_endpoint`; SSRF `resource_metadata`; missing audience; cross-origin redirect leak) | ✅ Yes (passive) | parse `WWW-Authenticate` + RFC 9728/8414 (CVE-2025-6514, 2026-51994, 115413, 111771; GHSA-6prh) |
| STDIO config-to-command (OX family) | ✅ Yes | static lint of local client configs |
| "Read-only" mode bypass | 🟡 Partly | compare `readOnlyHint`/annotations vs tool names/schemas (CVE-2026-46519/18954/87911) |

---

## 7. Consolidated ranked gap list (the v1.0 backlog)

> Merged from the deep-research doc's 21 gaps + Gemini's additions + my proposal + Grok's top-5. `Fit` = ZD/RO/LO. Evidence H/M/L.

| Rank | Gap | Evidence | Fit | Source agreement |
|---|---|---|---|---|
| 1 | **`server/discover` + 2026-07-28 conformance** (detect stateless; send `Mcp-Method`/`Mcp-Name`; report `resultType`/`ttlMs`/`cacheScope`; keep `initialize` fallback) | H (spec; Cisco/saagpatel do it) | ✅✅✅ | 🟢 all three + ✅ verified |
| 2 | **DNS-rebinding / Origin–Host probe** (repeat safe `tools/list`/discover with `Origin: http://evil` + spoofed `Host`; flag acceptance) | H (~48 Origin + ~22 rebind CVEs) | ✅✅✅ | 🟢 all three |
| 3 | **CORS check** (`OPTIONS` preflight; flag `ACAO: *` or reflected origin + credentials) | M-H (~18 CVEs) | ✅✅✅ | Claude+deep-research |
| 4 | **Sibling-endpoint auth consistency** (probe `/mcp`,`/mcp_message`,`/sse`,`/messages`,`/message`; flag mixed 401/200) | H (CVE-2026-33032 9.8) | ✅✅✅ | 🟢 all three |
| 5 | **0.0.0.0 / LAN exposure finding** (non-loopback + no auth → raise severity) | H (CVE-2026-49257 10.0; NeighborJack; ~24 CVEs) | ✅✅✅ (we're a sweeper) | 🟢 all three |
| 6 | **Passive OAuth hygiene** (parse `WWW-Authenticate` + RFC 9728/8414; flag non-https/`javascript:`/`file:` schemes, shell metachars in endpoints, private/link-local/metadata-IP targets, missing `iss`, over-broad scopes, mismatched `resource`) — **never fetch the flagged targets** | H (CVE-2025-6514 9.6, 2026-51994 9.1; ~53 OAuth + ~82 SSRF) | ✅✅✅ | 🟢 all three |
| 7 | **Offline known-vuln version DB** (match `serverInfo.name/version` vs a **bundled** advisory JSON; update per release) | H (554 records) | ✅✅✅ if bundled; ❌LO if live OSV | 🟢 all three |
| 8 | Unauthenticated `tasks/*` probe (`tasks/list` w/o creds / other session) | M-H (CVE-2026-52870/111767) | ✅ RO (list only) | deep-research |
| 9 | Session-ID quality (length, entropy, reuse, accepted w/o init) | M (CVE-2026-25536/76893) | ✅✅✅ | deep-research |
| 10 | Audience-check probe under `--auth-probe` (send user-supplied token for another resource; flag acceptance; never mint) | M-H (CVE-2026-115413/111771) | ✅ | deep-research |
| 11 | Hidden-char / ANSI / Unicode-TAG detector across all metadata | M (ToB; arXiv 2607.05744) | ✅✅✅ | deep-research+Claude |
| 12 | Full-schema poisoning heuristics (param names, enums, defaults, `outputSchema`, errors — not just `description`) | M (CyberArk) | ✅✅✅ | deep-research+Gemini |
| 13 | Static lint of local client configs (`mcp.json`, Claude/Cursor/Windsurf/VS Code) for `sh -c`, `curl\|sh`, unpinned `npx -y`/`uvx`, `--eval`, plaintext secrets — **does not launch them** | H (OX family ~9; CurXecute) | ✅✅✅ | 🟢 (Gemini GAP-04 + deep-research §1.4) |
| 14 | Cross-origin redirect handling (don't follow with auth/session headers; report redirecting servers — also hardens mcpsweep) | M (GHSA-6prh/5h93) | ✅✅✅ | deep-research |
| 15 | "Read-only" claim mismatch (`readOnlyHint:true` but name/schema says delete/exec/write/COPY) | M (CVE-2026-46519/18954/87911) | ✅✅✅ | deep-research |
| 16 | Toxic-flow capability tagging across discovered servers (private-data / untrusted-input / egress) | M (Invariant) | ✅ heuristic; ❌ if LLM | deep-research |
| 17 | Argument-injection schema lint (free-form strings → CLIs like git/kubectl w/o `pattern`) | M (CVE-2026-61459, 2025-68144) | ✅✅✅ | deep-research |
| 18 | **Tool-shadowing / namespace collisions** across multiple servers (identical/near-identical names override trusted) | M (Invariant; MCP03) | ✅✅✅ | 🟢 (Gemini GAP-05 + deep-research) |
| 19 | **Rug-pull finding as first-class** (hash desc+schema; emit `rug-pull`/`entity-changed`, not generic drift) | H (CVE-2025-54136) | ✅✅✅ | 🟢 (Claude P0 + Gemini + deep-research) |
| 20 | **Expanded param sinks** (deserialization pickle/marshal/yaml.load; eval/exec/compile; `shell=True` as CRITICAL) | H (cmd-inj dominant class) | ✅✅✅ | 🟢 (Claude P0 + Gemini, from MCProbe) |
| 21 | TOFU pinning profile export (baselines readable by mcp-context-protector-style wrappers) | L-M | ✅ | deep-research (ToB) |
| 22 | Plaintext-HTTP-with-auth finding (bearer over `http://` on non-loopback) | M | ✅✅✅ | deep-research |
| 23 | Request-size / malformed-JSON robustness **hints** (report advertised max body size; do NOT send oversized) | M (CVE-2025-53365/66, 63655/76892) | ✅ passive only | deep-research |

---

## 8. Do-NOT-build (breaks a constraint — and that's our marketing) 🟢

| Idea | Breaks | Why |
|---|---|---|
| Live OSV/NVD/GHSA lookups | LO | sends names/versions to third parties |
| LLM judge for poisoning/toxic flows (Snyk/Cisco/MCProbe/Ramparts style) | LO, ZD | sends tool metadata to a model provider |
| VirusTotal / package download (`--deep` fetch) | LO | uploads/downloads artifacts |
| YARA / Semgrep engines | ZD | native/extra deps |
| Docker sandbox for stdio | ZD | needs container runtime |
| DoS / oversized-body fuzzing (by default) | RO | can crash targets |
| Real DNS-rebinding infra (rebinding DNS server) | LO, RO | header-spoof probe (Gap 2) is the safe approximation |
| Runtime gateway / proxy enforcement | scope | that's a wrapper product, not a scanner |
| Fetching flagged OAuth `resource_metadata` URLs | RO/safety | would make mcpsweep itself an SSRF vector |
| Cross-language source AST (TS/Go/Rust) | ZD | needs heavy parsers; limit any static mode to Python stdlib `ast` only |

---

## 9. Quarantine — unverified claims (do NOT ship as fact) ⚠️

- `CVE-2026-33224` — **not in NVD** (2026-11-05).
- `CVE-2026-111771` — not in NVD; GHSA/GitLab only; 6.8 is secondary.
- nginx-ui fixed version for CVE-2026-33032 — unconfirmed.
- Japanese "open-redirect" tweet lead — unconfirmed.
- LiteLLM "MCP angle" for CVE-2026-114612 — NVD text doesn't mention MCP.
- CVE-2025-65720 (GPT Researcher) belonging to MCP STDIO family — NVD text doesn't mention MCP.
- Pillar Security mcp-audit / OpenCode — no primary repo/post found.
- Cycode MCP disclosure — not found in this pass.
- CyberArk "poison everywhere" page — redirects; content not re-read.
- Akto / Ramparts default telemetry — unconfirmed.
- GHSA-5h93 score + fix — not fetched.
- servers v2.1.0 "eight vulnerabilities" — individual IDs not mapped.
- **Gemini-only errors (rejected):** CVE-2025-66414/66416 fix versions "1.0.4 / 1.1.2" (real: **1.24.0 / 1.23.0**); "CVE-2026-111770 race condition" (likely mangled CVE-2026-111767); invented risk-concentration percentages; GHSA links unverified.
- Latest spec version after 2026-07-28 — unconfirmed.
- §2.6 class counts — keyword-approximate heuristic, not curated.

---

## 10. v1.0 build order (what we ship to the world)

**Tier 0 — Modernize the core (existential, first).** Gap 1 (`server/discover` + modern fingerprinting + headers; `initialize` fallback). Without it, mcpsweep can't see 2026-era servers.

**Tier 1 — Headline differentiators (all CVE-backed, all ✅ZD/RO/LO).** Gaps 2–6: DNS-rebind/Host, CORS, sibling-endpoint auth, 0.0.0.0/LAN exposure, passive OAuth hygiene.

**Tier 2 — Depth & trust.** Gaps 7 (offline vuln DB), 18 (shadowing), 19 (rug-pull), 20 (expanded sinks), 11 (hidden-char/ANSI/Unicode), 12 (full-schema poisoning), 15 (read-only mismatch), 13 (config lint), 8–10/14/17/22.

**Tier 3 — Launch assets (the other half of world-class).** Verified `CVE-COVERAGE.md`, README rewrite + 15s demo GIF, PyPI publish, GitHub Action (SARIF→code-scanning), Dockerfile, CONTRIBUTING, SECURITY.md.

---

*Sources: NVD; MCP spec `2026-07-28` (changelog, versioning, `server/discover`); OWASP MCP Top 10; JFrog, Oligo, Imperva, Check Point, Tenable, Cato, Trail of Bits, CyberArk, Backslash, The Hacker News, The Register; arXiv 2508.13220 (MCPSecBench), 2510.23673 (MCPGuard), 2508.14925 (MCPTox), 2508.20412 (MindGuard), 2607.05744 (TAG-block); competitor repos as listed. Compiled from three independent research passes (Claude, Gemini, Grok) + direct spec verification, 2026-11-05.*

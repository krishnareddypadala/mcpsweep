# mcpsweep

[![CI](https://github.com/krishnareddypadala/mcpsweep/actions/workflows/ci.yml/badge.svg)](https://github.com/krishnareddypadala/mcpsweep/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/mcpsweep.svg)](https://pypi.org/project/mcpsweep/)
[![Python](https://img.shields.io/pypi/pyversions/mcpsweep.svg)](https://pypi.org/project/mcpsweep/)

🌐 **Website:** [mcpsweep.com](https://mcpsweep.com) · source in the [mcpsweep-site](https://github.com/krishnareddypadala/mcpsweep-site) repo

A small, dependency-free **discovery and fingerprinting scanner for MCP-over-HTTP
servers** — think *nmap for MCP*. It finds Model Context Protocol endpoints on a
host or network, fingerprints each one (both the legacy `initialize` handshake
**and** the modern stateless `server/discover` of spec **2026-07-28**), enumerates
its **tools / resources / prompts**, and flags risky/**poisoned** tools, transport
weaknesses, and known-vulnerable versions.

It is strictly **read-only** by default — handshake and `*/list` calls only, never
`tools/call` (unless you opt into `--active`). And it is **local-only**: mcpsweep
has **zero runtime dependencies**, uses **no LLM and no cloud service**, and never
sends your tool names, descriptions, or configs anywhere. The only host it talks
to is the one you point it at.

> **Authorized use only.** Scan hosts you own or are explicitly permitted to test.

📊 **[Detection coverage → OWASP MCP Top 10 + CVEs](docs/CVE-COVERAGE.md)** ·
🧪 **[vulnlab: a vulnerable MCP server to test against](vulnlab/)**

## Why

MCP servers are easy to spin up and often ship with no authentication, over-broad
tools (arbitrary SQL, shell, money movement), or instructions hidden inside a
tool's *description* (tool poisoning). `mcpsweep` helps you inventory that surface
— including **shadow** servers nobody registered — and see the risk at a glance.

## Install

```bash
pip install mcpsweep
```

Or from source:

```bash
git clone https://github.com/krishnareddypadala/mcpsweep && cd mcpsweep
pip install .
```

## Usage

```bash
# scan one host on a known port
mcpsweep 10.10.0.31 --ports 8090

# route everything through Burp for inspection
mcpsweep 10.10.0.31 --ports 8090 --proxy http://127.0.0.1:8080

# sweep a subnet and a port range, also list resources/prompts
mcpsweep 10.10.0.0/28 --ports 8000-9100 --full

# a full URL, and a target list from a file (text or JSON)
mcpsweep http://10.10.0.31:8090/mcp/api
mcpsweep -iL targets.txt --exclude 10.10.0.5
mcpsweep -iL targets.json           # ["10.0.0.1", "http://h:8090/mcp"] or {"targets":[...]}
mcpsweep -iL previous-report.json   # re-scan the endpoints from an earlier JSON report
mcpsweep -iL claude_desktop_config.json   # your MCP client config (mcpServers/servers) — scans the http/sse servers

# stdio servers — spawns them, so it runs third-party code (opt-in ack required)
mcpsweep --stdio "npx -y @scope/mcp" --yes-run-untrusted
mcpsweep -iL claude_desktop_config.json --include-stdio --yes-run-untrusted   # also spawn the stdio entries

# authenticated scan (servers that require a token)
mcpsweep 10.10.0.31 --ports 8090 --bearer "$TOKEN"
mcpsweep 10.10.0.31 --ports 8090 -H "X-Api-Key: abc123"

# reports: JSON, Markdown, SARIF (GitHub code-scanning), self-contained HTML
mcpsweep 10.10.0.31 --ports 8090 --format json  -o report.json
mcpsweep 10.10.0.31 --ports 8090 --format md    -o report.md
mcpsweep 10.10.0.31 --ports 8090 --format sarif -o report.sarif
mcpsweep 10.10.0.31 --ports 8090 --format html  -o report.html

# deep vulnerability analysis (parameter sinks, resource/prompt/annotation risks)
mcpsweep 10.10.0.31 --ports 8090 --deep
mcpsweep 10.10.0.31 --ports 8090 --read-resources   # also scan resource contents

# baseline as policy: freeze the sanctioned inventory, then gate on drift
mcpsweep 10.10.0.31 --ports 8090 --write-baseline baseline.json
mcpsweep 10.10.0.31 --ports 8090 --baseline baseline.json --fail-on-policy

# CI gates: only show high+, fail the build on any critical
mcpsweep 10.10.0.31 --ports 8090 --severity high --fail-on critical

# active verification — CALLS tools; authorized labs only
mcpsweep 10.10.0.31 --ports 8090 --active --active-dry-run          # preview, calls nothing
mcpsweep 10.10.0.31 --ports 8090 --active --i-have-authorization    # verify BOLA / secret exposure

# drift detection between two JSON scans (continuous posture monitoring)
mcpsweep diff yesterday.json today.json --fail-on-drift

# transport-security probes run by default (DNS-rebinding, CORS, LAN exposure,
# sibling-endpoint auth gaps); turn them off with:
mcpsweep 10.10.0.31 --ports 8090 --no-transport-probe

# statically lint a local MCP client config for dangerous stdio servers + secrets
mcpsweep lint-config ~/.cursor/mcp.json ~/Library/Application\ Support/Claude/claude_desktop_config.json
```

### Key options

| Flag | Purpose |
|---|---|
| `--target-file`/`-iL` | targets from a file: one-per-line text (`#` comments) **or** JSON (array, `{"targets":[…]}`, a prior mcpsweep report, or an MCP client `mcpServers`/`servers` config) |
| `--stdio "CMD"` | spawn a stdio MCP server and scan it (repeatable) |
| `--include-stdio` | also spawn the stdio servers found in a config (`-iL`) |
| `--yes-run-untrusted` | required to spawn stdio servers (they run third-party code) |
| `--exclude` | comma-separated hosts to skip |
| `--ports` | ports/ranges, e.g. `8090,8000,9000-9010` |
| `--paths` | URL paths to probe (defaults cover `/mcp`, `/mcp/api`, `/sse`, …) |
| `--scheme` | `http`, `https`, or `both` |
| `--header`/`-H`, `--bearer` | custom header(s) / bearer token for authenticated scans |
| `--proxy` | send all traffic via a proxy (e.g. Burp on `127.0.0.1:8080`) |
| `--insecure`/`-k` | skip TLS verification |
| `--full` | also enumerate `resources/list` and `prompts/list` |
| `--no-transport-probe` | skip the read-only transport checks (DNS-rebinding, CORS, LAN exposure) |
| `--auth-probe` | for auth-gated servers, follow OAuth metadata (RFC 9728/8414) and classify (implied by `--full`) |
| `--deep` | classify parameter sinks (cmd/SQLi/path/SSRF), resource/prompt & annotation risks |
| `--read-resources` | also fetch resource contents and scan for secrets/injection (implies `--deep`) |
| `--severity` | only report endpoints at/above a level |
| `--fail-on` | exit `2` if any endpoint is at/above a level (CI gate) |
| `--baseline FILE` | evaluate the scan against a JSON baseline/policy (shadow servers, tool allowlist, rules) |
| `--write-baseline FILE` | generate a baseline from this scan (bootstrap) |
| `--fail-on-policy` | exit `4` if any baseline/policy violation |
| `--active` | **calls** safe-read tools to verify BOLA/secret exposure (needs `--i-have-authorization`) |
| `--active-all` | active-probe **all** tools, not just safe-read (dangerous; labs only) |
| `--active-dry-run` | preview what active mode would call — calls nothing |
| `--active-log FILE` | audit log of every active tool call |
| `--format`/`-f` | `text` (default), `json`, `md`, `sarif`, `html` |
| `--verbose`/`-v` | explain probe misses: `-v` shows HTTP responses that weren't MCP (401, 404, redirect…), `-vv` also shows connection errors |
| `--concurrency`/`-c` | parallel probes (default 16) |

Exit codes: `0` found (or clean), `1` nothing found, `2` `--fail-on` threshold hit,
`3` drift found (`diff --fail-on-drift`), `4` `--fail-on-policy` violation.

### Drift detection

```bash
mcpsweep 10.10.0.31 --ports 8090 -f json -o baseline.json   # week 1
mcpsweep 10.10.0.31 --ports 8090 -f json -o current.json    # week 2
mcpsweep diff baseline.json current.json
```

Reports **new / removed servers and tools**, **newly-poisoned** descriptions, and
**risk-level changes** — turning point-in-time scans into continuous monitoring.

> **Windows / Git Bash note:** Git Bash (MSYS) rewrites arguments that look like
> Unix paths, so `--paths /mcp/api` becomes a Windows path before the tool sees
> it. Either omit `--paths` (the built-in defaults are unaffected), prefix the
> command with `MSYS_NO_PATHCONV=1`, or run from PowerShell / `cmd`.

## What it detects

- **Live MCP endpoints** across many candidate paths/ports, via the legacy
  `initialize` handshake **and** the modern stateless `server/discover`
  (spec 2026-07-28) — so modern-only servers aren't missed (Streamable-HTTP and
  SSE-framed responses). Dual-era servers are tagged.
- **Transport weaknesses** (read-only live probes): **DNS-rebinding** (foreign
  `Host`/`Origin` accepted), **CORS** wildcard/reflected-with-credentials,
  **LAN exposure** (unauthenticated on a non-loopback address — NeighborJack),
  and **sibling-endpoint auth gaps** (one path protected, a sibling open).
- **Known-vulnerable versions**: matches `serverInfo` against a **bundled,
  offline** advisory DB (no OSV/NVD calls).
- **Hidden/deceptive metadata**: ANSI escapes, zero-width, bidi overrides, and
  Unicode **TAG-block** concealment in tool metadata and server instructions.
- **Full-schema tool poisoning**: injected instructions anywhere in the tool
  (param names, descriptions, enums, annotations) — not just the description.
- **Rug-pulls**: `mcpsweep diff` flags a tool whose signature changed since the
  baseline (MCPoison class), plus tool **shadowing** across servers.
- **OAuth metadata hygiene**: SSRF targets, bad schemes, shell metacharacters,
  missing issuer, over-broad scopes — and it refuses to fetch a link-local /
  cloud-metadata / private target itself.
- **Dangerous local configs** (`lint-config`): `sh -c`, `curl|sh`, unpinned
  `npx -y`/`uvx`, inline-eval interpreters, plaintext secrets.
- **Server fingerprint**: name, version, protocol, capabilities, instructions.
- **No authentication**: `initialize` that succeeds with no credentials.
- **Auth-gated endpoints**: `401/403` with an MCP/`WWW-Authenticate` signature; with
  `--auth-probe`, follows the OAuth metadata chain and classifies as *OAuth 2.1
  protected* / *non-standard* / *misconfigured* (missing PKCE, open DCR).
- **Risky tools**: name/description heuristics tag `rce`, `sql`, `money`,
  `destructive`, `write`, `secret`, `pii`, `filesystem`, …
- **Prompt injection / poisoning** in tool descriptions **and** server
  `instructions`, prompt templates, and resource listings ("ignore previous
  instructions", "silently", "password_hash", …).
- **Injection surface**: high-impact tools (`sql`/`rce`/…) that accept a
  **free-form string** parameter.
- **HTTP fingerprint**: `Server` / `X-Powered-By` headers, and server names that
  hint at an elevated or untrusted purpose.
- **Deep vulnerability analysis** (`--deep`): parameter sinks (command-injection,
  SQLi, path-traversal, SSRF), sensitive-file resources, prompt-injection surface,
  annotation mismatches, and confused-deputy tool chaining; with `--read-resources`,
  scans resource contents for secrets/PII and stored injection.
- **Verified exploitation** (`--active`, opt-in): actually calls safe-read tools to
  confirm unauthenticated BOLA/IDOR and real secret/PII exposure — the one mode that
  isn't read-only, gated behind `--i-have-authorization` (or `--active-dry-run`).

A per-endpoint **risk score** rolls these up into `low / medium / high / critical`.

## Library use

```python
from mcpsweep import scan

for ep in scan(["10.10.0.31"], ports=[8090], proxy="http://127.0.0.1:8080"):
    print(ep.url, ep.server_name, ep.risk_level)
    for t in ep.tools:
        print("  ", t.name, t.tags, "POISONED" if t.poisoned else "")
```

## Roadmap

Planned features — stdio scanning, OAuth/auth-spec detection, deep vulnerability
discovery, policy baselines, and active authz probing — are specced in
[docs/ROADMAP.md](docs/ROADMAP.md).

## License

MIT

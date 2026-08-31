# mcpsweep

[![CI](https://github.com/krishnareddypadala/mcpsweep/actions/workflows/ci.yml/badge.svg)](https://github.com/krishnareddypadala/mcpsweep/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/mcpsweep.svg)](https://pypi.org/project/mcpsweep/)
[![Python](https://img.shields.io/pypi/pyversions/mcpsweep.svg)](https://pypi.org/project/mcpsweep/)

A small, dependency-free **discovery and fingerprinting scanner for MCP-over-HTTP
servers**. It finds Model Context Protocol endpoints on a host or network,
performs the JSON-RPC `initialize` handshake to fingerprint each one, enumerates
its **tools / resources / prompts**, and flags risky or **poisoned** tools.

It is strictly **read-only** — it performs the handshake and `*/list` calls only,
and never invokes a tool (`tools/call`).

> **Authorized use only.** Scan hosts you own or are explicitly permitted to test.

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
mcpsweep -iL claude_desktop_config.json   # your MCP client config (mcpServers) — scans the http/sse servers

# authenticated scan (servers that require a token)
mcpsweep 10.10.0.31 --ports 8090 --bearer "$TOKEN"
mcpsweep 10.10.0.31 --ports 8090 -H "X-Api-Key: abc123"

# reports: JSON, Markdown, SARIF (GitHub code-scanning), self-contained HTML
mcpsweep 10.10.0.31 --ports 8090 --format json  -o report.json
mcpsweep 10.10.0.31 --ports 8090 --format md    -o report.md
mcpsweep 10.10.0.31 --ports 8090 --format sarif -o report.sarif
mcpsweep 10.10.0.31 --ports 8090 --format html  -o report.html

# CI gates: only show high+, fail the build on any critical
mcpsweep 10.10.0.31 --ports 8090 --severity high --fail-on critical

# drift detection between two JSON scans (continuous posture monitoring)
mcpsweep diff yesterday.json today.json --fail-on-drift
```

### Key options

| Flag | Purpose |
|---|---|
| `--target-file`/`-iL` | targets from a file: one-per-line text (`#` comments) **or** JSON (array, `{"targets":[…]}`, a prior mcpsweep report, or an MCP client `mcpServers` config — stdio servers are skipped) |
| `--exclude` | comma-separated hosts to skip |
| `--ports` | ports/ranges, e.g. `8090,8000,9000-9010` |
| `--paths` | URL paths to probe (defaults cover `/mcp`, `/mcp/api`, `/sse`, …) |
| `--scheme` | `http`, `https`, or `both` |
| `--header`/`-H`, `--bearer` | custom header(s) / bearer token for authenticated scans |
| `--proxy` | send all traffic via a proxy (e.g. Burp on `127.0.0.1:8080`) |
| `--insecure`/`-k` | skip TLS verification |
| `--full` | also enumerate `resources/list` and `prompts/list` |
| `--severity` | only report endpoints at/above a level |
| `--fail-on` | exit `2` if any endpoint is at/above a level (CI gate) |
| `--format`/`-f` | `text` (default), `json`, `md`, `sarif`, `html` |
| `--verbose`/`-v` | explain probe misses: `-v` shows HTTP responses that weren't MCP (401, 404, redirect…), `-vv` also shows connection errors |
| `--concurrency`/`-c` | parallel probes (default 16) |

Exit codes: `0` found (or clean), `1` nothing found, `2` `--fail-on` threshold hit,
`3` drift found (`diff --fail-on-drift`).

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

- **Live MCP endpoints** across many candidate paths/ports, via the `initialize`
  handshake (Streamable-HTTP and SSE-framed responses).
- **Server fingerprint**: name, version, protocol, capabilities, instructions.
- **No authentication**: `initialize` that succeeds with no credentials.
- **Auth-gated endpoints**: `401/403` with an MCP/`WWW-Authenticate` signature.
- **Risky tools**: name/description heuristics tag `rce`, `sql`, `money`,
  `destructive`, `write`, `secret`, `pii`, `filesystem`, …
- **Prompt injection / poisoning** in tool descriptions **and** server
  `instructions`, prompt templates, and resource listings ("ignore previous
  instructions", "silently", "password_hash", …).
- **Injection surface**: high-impact tools (`sql`/`rce`/…) that accept a
  **free-form string** parameter.
- **HTTP fingerprint**: `Server` / `X-Powered-By` headers, and server names that
  hint at an elevated or untrusted purpose.

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

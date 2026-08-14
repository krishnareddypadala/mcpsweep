# mcpsweep

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

# machine-readable output
mcpsweep 10.10.0.31 --ports 8090 --format json -o report.json
mcpsweep 10.10.0.31 --ports 8090 --format md   -o report.md
```

### Key options

| Flag | Purpose |
|---|---|
| `--ports` | ports/ranges, e.g. `8090,8000,9000-9010` |
| `--paths` | URL paths to probe (defaults cover `/mcp`, `/mcp/api`, `/sse`, …) |
| `--scheme` | `http`, `https`, or `both` |
| `--proxy` | send all traffic via a proxy (e.g. Burp on `127.0.0.1:8080`) |
| `--insecure`/`-k` | skip TLS verification |
| `--full` | also enumerate `resources/list` and `prompts/list` |
| `--format`/`-f` | `text` (default), `json`, `md` |
| `--concurrency`/`-c` | parallel probes (default 16) |

Exit code is `0` when at least one endpoint is found, `1` otherwise.

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
- **Tool poisoning**: descriptions containing hidden instructions to the model
  ("ignore previous instructions", "silently", "password_hash", …).

A per-endpoint **risk score** rolls these up into `low / medium / high / critical`.

## Library use

```python
from mcpsweep import scan

for ep in scan(["10.10.0.31"], ports=[8090], proxy="http://127.0.0.1:8080"):
    print(ep.url, ep.server_name, ep.risk_level)
    for t in ep.tools:
        print("  ", t.name, t.tags, "POISONED" if t.poisoned else "")
```

## License

MIT

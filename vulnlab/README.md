# mcpsweep vulnlab

A **deliberately-vulnerable** MCP-over-HTTP server used to test every mcpsweep
detection end-to-end. One stdlib Python process serves many endpoints, each
crafted to trip one check - plus clean "control" endpoints that must stay
benign (so we catch false positives).

> ⚠️ **INTENTIONALLY INSECURE.** Run only on an isolated lab network you control.
> Binding to `0.0.0.0` is itself one of the demonstrated vulnerabilities.

## Run it

```bash
python -m vulnlab --host 127.0.0.1 --port 9100     # from the repo root
# or
docker compose -f vulnlab/docker-compose.yml up --build
```

## Run it on top of phpvulnbank

Deployed as a co-located compose project beside the phpvulnbank laravel stack
(its own `docker compose` project at `/opt/phpvulnbank/vulnlab/`, with
`restart: unless-stopped` so it survives host reboots). It answers on `:9100`
alongside the existing `:8090` MCP endpoints and is fully reversible with
`docker compose down`. On the lab network it is live at
`http://10.10.0.31:9100`.

```bash
cd /opt/phpvulnbank/vulnlab && docker compose up -d --build   # (re)deploy
cd /opt/phpvulnbank/vulnlab && docker compose down            # remove
```

Alternatively, copy the `vulnlab` service from [`docker-compose.yml`](docker-compose.yml)
directly into the stack's compose file so it shares the lab network.

## Scenario map (path → what it models)

| Path | Models / CVE class |
|---|---|
| `/mcp/noauth` | no-auth (MCP07), tool poisoning (MCP03), rce/sql injection surface (MCP05), poisoned instructions (MCP06), DNS-rebinding, wildcard CORS, weak session-id |
| `/mcp` + `/mcp_message` | sibling-endpoint auth gap - `/mcp` requires auth, `/mcp_message` does not (CVE-2026-33032) |
| `/mcp/modern` | modern stateless `server/discover` (spec 2026-07-28); rejects `initialize` |
| `/mcp/dual` | dual-era: answers both `initialize` and `server/discover` |
| `/mcp/poison` | full-schema poisoning (enum/param), ANSI-escape deception, Unicode TAG-block / zero-width concealment |
| `/mcp/readonly-lie` | `readOnlyHint: true` on a destructive tool (CVE-2026-46519 class); argument-injection schema (CVE-2026-61459) |
| `/mcp/oauth-ssrf` | OAuth metadata hygiene - `resource_metadata`/AS at link-local `169.254.169.254` (CVE-2026-51994 class). Always on for this path |
| `/mcp/rugpull` | rug-pull - tool definition changes when `MCPSWEEP_RUGPULL=1` (CVE-2025-54136 MCPoison). Scan before/after and `diff` |
| `/mcp/tasks` | unauthenticated `tasks/*` on an otherwise-authenticated server (CVE-2026-52870 / 111767) |
| `/mcp/secure-oauth`, `/mcp/safe`, `/mcp` | **clean controls** - mcpsweep should rank these low/benign |

## Demonstrate against mcpsweep

```bash
# scan every scenario with the full feature set
PATHS=$(python -c "import vulnlab; print(','.join(vulnlab.SCENARIOS))")
mcpsweep 127.0.0.1 --ports 9100 --paths "$PATHS" --full --deep --auth-probe

# rug-pull drift: snapshot, flip, snapshot, diff
mcpsweep 127.0.0.1 --ports 9100 --paths /mcp/rugpull -f json -o before.json
MCPSWEEP_RUGPULL=1  # restart the server with this set
mcpsweep 127.0.0.1 --ports 9100 --paths /mcp/rugpull -f json -o after.json
mcpsweep diff before.json after.json
```

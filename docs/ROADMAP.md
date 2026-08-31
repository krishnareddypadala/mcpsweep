# mcpsweep roadmap — 0.4 → 0.8

Five features that extend the scanner from HTTP discovery into transport
coverage, auth-spec analysis, deep vulnerability discovery, posture policy, and
verified exploitation — each additive, opt-in, and independently shippable.

```
0.3.1 dedup → 0.4.0 stdio → 0.5.0 oauth → 0.6.0 deep → 0.7.0 baseline → 0.8.0 active
```

> Effort and LOC are planning estimates, not commitments.

## Ground rules

- **Safe defaults are load-bearing.** Today's contract — HTTP-only, strictly
  read-only (handshake + `*/list`, never `tools/call`) — stays the default.
  Every new capability is behind a flag; a bare `mcpsweep host` behaves exactly
  as in 0.3.
- **Additive data model.** New fields on `MCPEndpoint` / `ToolInfo` only; JSON
  output stays backward-compatible so existing `diff` reports keep parsing.
- **One `feat:` per release** so release-please handles versioning + CHANGELOG;
  SARIF gains rules, never loses them.
- **Zero-dependency stays the goal.** stdlib only (`subprocess`, `urllib`,
  `json`). Policy files are JSON, not YAML, to avoid a PyYAML dependency.

**Cleanup to fold in with 0.3.1:** `_init_payload()` hard-codes
`clientInfo.version` (`"0.2.0"`) — wire it to `__version__` so the handshake
reports the real scanner version.

---

## 0.3.1 — Path dedup & endpoint canonicalisation *(prereq, `fix:`)*

A sweep reports `/mcp` and `/mcp/` as two "critical" endpoints for the same
server. Baseline matching (0.7.0) needs one canonical identity per server, so
this lands first.

- **Logic** — canonical key = `(scheme, host, port, path.rstrip('/') or '/')`,
  collapsing trailing-slash twins while keeping genuinely distinct paths
  (`/mcp/api` ≠ `/mcp/db`). Second pass: same `(serverInfo.name, version,
  sorted tool names)` via different URLs → collapse into one endpoint, record
  extras as `aliases[]`.
- **Data model** — `MCPEndpoint.aliases: list`.
- **Tests** — one app served at `/mcp` and `/mcp/` → single endpoint + one
  alias; `/mcp/api` and `/mcp/db` stay separate.
- **Effort** ~15 LOC + test · **Risk** low · **Blocks** 0.7.0.

---

## 0.4.0 — Scan stdio MCP servers *(biggest gap)*

mcpsweep currently *skips* stdio servers. But stdio is where most local MCP
servers live — and where supply-chain risk (OWASP MCP04) lands. This spawns the
server, speaks JSON-RPC over its pipes, and risk-scores it like any endpoint.

**CLI**

| Flag | Effect |
|---|---|
| `--stdio "CMD…"` | Spawn one stdio server directly (parsed with `shlex`). |
| `--include-stdio` | Spawn the stdio servers in an `mcpServers` config instead of skipping. |
| `--yes-run-untrusted` | Required ack in non-interactive/CI mode — spawning runs third-party code. |
| `--stdio-timeout N` | Whole-enumeration budget (default 20s); process group killed on expiry. |

**Transport** — new `stdio.py`. MCP stdio framing is newline-delimited JSON-RPC
(one JSON object per line on stdout; server logs go to stderr, captured
separately). Reads run on a reader thread with a deadline (Windows has no
`select` on pipes).

```python
def probe_stdio(argv, env, cwd, timeout):
    p = subprocess.Popen(argv, stdin=PIPE, stdout=PIPE, stderr=PIPE,
                         text=True, bufsize=1, env=env, cwd=cwd)
    write_line(p.stdin, init_payload())          # reuse existing payload
    ep = endpoint_from_line(read_line(p.stdout, timeout))
    write_line(p.stdin, notifications_initialized())
    ep.tools = list_via_stdio(p, "tools/list")   # + resources/prompts on --full
    p.stdin.close(); terminate(p)                # kill the process group
    return ep
```

**Data model** — `transport="stdio"`, `url="stdio://npx @playwright/mcp"`
(synthetic id), `command=[...]`. Tool analysis + scoring unchanged. No *no-auth*
penalty. New finding: *"stdio server executes local code — supply-chain risk
(MCP04)"*.

**Tests** — stdlib fixture `tests/stdio_echo_server.py` (answers
`initialize`/`tools/list` with a poisoned + injectable tool, writes noise to
stderr); spawn via `sys.executable`; assert enumeration, poison flag,
supply-chain finding, and that stderr noise doesn't corrupt parsing.

- **Effort** ~200 LOC + fixture · **Risk** executes untrusted code · **Quick
  win** VS Code `servers` / Cursor / Windsurf config parsing.

> **Safety:** running a stdio server IS the risk being audited. Off by default,
> print a one-line warning on spawn, require `--yes-run-untrusted` in CI,
> document "run inside a container/VM". On Windows, resolve `npx` → `npx.cmd`.

---

## 0.5.0 — OAuth & auth-spec detection *(OWASP MCP01/MCP07)*

Today a protected server is just "auth required". The MCP auth spec makes
servers OAuth 2.1 resource servers with discoverable metadata — so we can report
*how* a server is protected and whether it's done correctly.

**Logic**

- On `401/403`, parse `WWW-Authenticate` → `resource_metadata` URL (RFC 9728),
  or fall back to `/.well-known/oauth-protected-resource`.
- GET that → `authorization_servers[]`, `scopes_supported`,
  `bearer_methods_supported`.
- For each issuer, GET `/.well-known/oauth-authorization-server` (RFC 8414) →
  `authorization_endpoint`, `token_endpoint`, `registration_endpoint` (DCR),
  `code_challenge_methods_supported` (PKCE), `grant_types_supported`.

**Classification** — ✅ *OAuth 2.1 protected* (chain resolves, PKCE S256) ·
⚠ *non-standard auth* (auth required, no discovery metadata) · ✗ *misconfigured*
(AS metadata 404s, no PKCE, or open dynamic client registration).

**CLI** — `--auth-probe` (fetch metadata; also on with `--full`; proxy-aware,
honours `--insecure`).

**Data model**

```json
"auth": {
  "status": "oauth2.1",              // | non-standard | misconfig | none
  "authorization_servers": ["..."],
  "scopes": ["..."], "pkce": true, "dcr": false,
  "endpoints": {"authorize": "...", "token": "..."}
}
```

**Tests** — local server: `401` + `WWW-Authenticate` → stub protected-resource +
AS metadata; assert parsed scopes/endpoints/PKCE and each classification,
including the "no metadata" path.

- **Effort** ~120 LOC + tests · **Risk** low · **New SARIF rule** `auth-misconfig`
  (+ a positive note).

---

## 0.6.0 — Deep surface analysis *(the core "find vulns" job)*

Auto-explore every tool schema, resource, and prompt template and derive
concrete vulnerability classes — not just "this description looks poisoned," but
"this parameter is a command-injection sink," "this resource leaks a secret,"
"this annotation lies about what the tool does."

**Static checks** (no tool calls; only adds `resources/templates/list`)

- **Parameter sinks** — each `inputSchema` property classified: free-form string
  on an rce/exec tool → command-injection; on sql/query → SQLi; a `path/file/dir`
  param with no enum → path-traversal/LFI; a `url/uri/host` param → SSRF;
  brace-templated → template injection.
- **Resource URIs** — `file://` and config/secret paths (`.env`, `id_rsa`,
  `.git`, `/etc`) → sensitive-file exposure; templated URIs (`{path}`) →
  traversal/SSRF surface.
- **Prompt templates** — arguments interpolated into the prompt → prompt-injection
  surface.
- **Annotation trust** — MCP tool hints (`readOnlyHint`, `destructiveHint`,
  `idempotentHint`, `openWorldHint`) contradicting name/tags (e.g.
  `destructiveHint:false` on `delete-*`) → "annotation misrepresents behaviour".
- **Confused deputy** — a tool description that instructs calling *another* tool.

**Deep read** (opt-in `--read-resources`) — fetch resource bodies via
`resources/read` (templates expanded with **benign** values only — never attack
payloads), then scan content for: secrets / credentials / PII (regex + entropy);
embedded prompt-injection payloads (stored injection); sensitive-file disclosure
& over-broad / oversized resources. Strictly reads resources — still never
`tools/call`.

**CLI**

| Flag | Effect |
|---|---|
| `--deep` | Static analysis + `resources/templates/list` (no content fetch). |
| `--read-resources` | Also fetch & scan resource contents (light-dynamic; implies `--deep`). |
| `--deep-max-bytes N` | Cap bytes read per resource (default 64 KB). |
| `--deep-max-resources N` | Cap resources fetched (default 50). |

**Data model**

```python
ToolInfo.param_vulns = [
  {"param": "cmd", "class": "command-injection", "why": ...},
]
@dataclass
class ResourceInfo:
    uri: str; template: bool
    findings: list  # secret-in-resource, stored-injection, file-exposure
```

**Output** — per-tool / per-resource vulnerability findings, each categorised.
New SARIF rules: `command-injection`, `sqli`, `path-traversal`, `ssrf`,
`secret-in-resource`, `stored-injection-resource`, `annotation-mismatch`,
`confused-deputy`.

**Tests** — fixture server exposing a command-injection-shaped tool, a `file://`
resource leaking a fake secret, a poisoned resource, and a lying annotation →
assert each class fires. Assert the static layer sends *no* `resources/read`;
only `--read-resources` does.

- **Effort** ~180 LOC + fixtures · **Risk** static: none / read: light-dynamic ·
  **Bridges** passive → active (0.8.0).

> **Boundary — reading is not calling:** `resources/read` consumes data the
> server offers for reading (safer than `tools/call`), but it can surface
> sensitive content or hit a URI — so content fetch stays opt-in with size/count
> caps, and templates are only ever expanded with harmless values.

---

## 0.7.0 — Baseline & policy file *(OWASP MCP09 · AI-SPM)*

Make shadow-server detection first-class. Declare the sanctioned inventory once;
every scan then flags anything unexpected or over-privileged — stateless, unlike
`diff` which needs two runs.

**Policy (JSON)**

```json
{
  "version": 1,
  "servers": [
    {"match": {"url": "http://10.10.0.31:8090/mcp/api"},
     "allow_tools": ["get-balance-tool", "..."]},
    {"match": {"server_name": "everything"}, "allow_any_tool": true}
  ],
  "rules": {
    "require_auth": true, "deny_tags": ["rce", "sql", "money"],
    "deny_poisoned": true, "max_risk": "medium"
  }
}
```

**Checks** — endpoint not matched by any baseline server → `shadow-server`; tool
not in `allow_tools` (and not `allow_any_tool`) → `unexpected-tool`; rule
breaches (`require_auth`, `deny_tags`, `deny_poisoned`, `max_risk`) → one
violation each.

**CLI**

| Flag | Effect |
|---|---|
| `--baseline f.json` | Compare the scan against the policy. |
| `--write-baseline f.json` | **Bootstrap:** generate a baseline from the current scan — scan once, freeze it, gate on drift forever after. |
| `--fail-on-policy` | Exit `4` if any violation (CI gate). |

**Output** — policy section in every format; each violation becomes a SARIF
result (rule id per check).

**Tests** — baseline + scan → assert each violation type; `--write-baseline`
round-trips (generated file re-scanned = zero violations).

- **Effort** ~100 LOC + tests · **Risk** low · **Depends on** 0.3.1 dedup.

---

## 0.8.0 — `--active` authz probing *(most sensitive — last)*

Move from "this tool *looks* exploitable" to "I called it and it *is*." Opt-in,
heavily gated — trades the strict read-only guarantee for verified findings.

**Gating tiers**

- **Tier 0 (default)** — never calls a tool. Unchanged.
- **Tier 1 `--active`** — calls only *safe-read* tools (name ∈ get/list/read/lookup
  **and** tags ∩ {write,rce,exec,money,destructive} = ∅). Requires
  `--i-have-authorization`.
- **Tier 2 `--active-all`** — may call any tool. Labs only; second ack.

**Checks** — **BOLA/IDOR** (call an id-taking safe-read tool with the given value
+ neighbours; distinct records without auth ⇒ confirmed, differing responses as
evidence); **secret/PII exposure** (scan real output against regexes);
**injection** (Tier 2: plant a benign marker via a write tool, read it back).

**Controls**

| Flag | Effect |
|---|---|
| `--active-max-calls N` | Hard cap (default 20) + inter-call rate limit. |
| `--active-dry-run` | Print exactly what *would* be called — calls nothing. |
| `--active-log f` | Full audit trail: every request + response to file. |

**Output** — a separate "ACTIVE FINDINGS (verified)" section, never mixed with
passive heuristics; each carries the actual request/response evidence.

**Tests** — local server with a BOLA-able get-by-id tool → assert confirmed.
**Critical guard test:** without `--active`, assert *zero* `tools/call` requests
are ever sent.

- **Effort** ~200+ LOC + careful tests · **Risk** breaks read-only guarantee.

> **Guardrails:** off by default, dry-run before live, authorization ack
> required, call cap + rate limit, full audit log, safe-read-only unless
> explicitly escalated. The README gets an "authorized use only" banner specific
> to active mode.

"""Core discovery + fingerprinting logic for mcpsweep.

Stdlib only. Speaks MCP's Streamable-HTTP JSON-RPC transport (and parses
SSE-framed responses), performs the ``initialize`` handshake to confirm and
fingerprint an endpoint, then enumerates tools / resources / prompts and scores
them with lightweight risk heuristics.

The scanner is strictly read-only: it never calls ``tools/call``.
"""
from __future__ import annotations

import ipaddress
import json
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional

PROTOCOL_VERSION = "2024-11-05"

DEFAULT_PORTS = [8090, 8000, 8080, 3000, 5000, 8888, 9000, 9099]
DEFAULT_PATHS = [
    "/mcp", "/mcp/", "/mcp/api", "/mcp/db", "/mcp/http", "/mcp/v1",
    "/sse", "/mcp/sse", "/api/mcp", "/message", "/messages",
    "/rpc", "/jsonrpc", "/tools", "/internal/mcp",
]

# --- risk heuristics ---------------------------------------------------------

#: text (in a description / instructions / prompt / resource) that suggests an
#: embedded instruction to the model (tool poisoning / prompt injection)
POISON_RE = re.compile(
    r"(ignore\s+(all|previous|prior)|disregard\s+(all|previous)|"
    r"do not (mention|tell|inform|reveal this)|without (telling|informing|mentioning)|"
    r"silently|exfiltrat|password_hash|secret[_-]?key|api[_-]?key|"
    r"internal note for the (assistant|ai|llm|model)|you must also call|"
    r"before (answering|responding)[^.]{0,40}call)",
    re.I,
)

#: keyword -> risk tag; matched against tool name and description
RISK_KEYWORDS = {
    "sql": "sql", "query": "query", "database": "db",
    "shell": "rce", "command": "rce", "exec": "rce", "eval": "rce", "bash": "rce",
    "run": "exec", "spawn": "rce", "subprocess": "rce",
    "transfer": "money", "payment": "money", "wire": "money", "withdraw": "money",
    "delete": "destructive", "drop": "destructive", "remove": "destructive",
    "truncate": "destructive", "write": "write", "update": "write",
    "create": "write", "insert": "write", "modify": "write", "activate": "state-change",
    "password": "secret", "secret": "secret", "token": "secret",
    "credential": "secret", "apikey": "secret", "env": "secret", "private": "secret",
    "customer": "pii", "account": "pii", "balance": "pii", "profile": "pii",
    "ssn": "pii", "email": "pii",
    "file": "filesystem", "path": "filesystem", "read": "read",
    "fetch": "network", "http": "network", "url": "network", "request": "network",
}

#: tags that materially raise risk (used for scoring)
DANGEROUS_TAGS = {
    "sql", "rce", "exec", "money", "destructive", "write", "state-change",
    "secret", "pii", "filesystem",
}

#: tags where a free-form string parameter is a real injection surface
INJECTABLE_TAGS = {"sql", "rce", "exec", "filesystem", "network"}

#: server-name substrings that hint at an elevated / untrusted purpose
RISKY_NAME_HINTS = ["shell", "exec", "admin", "root", "unsanctioned",
                    "debug", "internal", "dev-", "devops"]


@dataclass
class ToolInfo:
    name: str
    description: str = ""
    tags: list = field(default_factory=list)
    poisoned: bool = False
    freeform_params: list = field(default_factory=list)
    injection_surface: bool = False
    param_vulns: list = field(default_factory=list)    # [{param, class, why}] (0.6.0 --deep)


@dataclass
class MCPEndpoint:
    url: str
    host: str
    port: int
    path: str
    scheme: str
    transport: str = "streamable-http"
    server_name: str = "?"
    server_version: str = "?"
    protocol: str = "?"
    capabilities: list = field(default_factory=list)
    instructions: str = ""
    instructions_poisoned: bool = False
    server_header: str = ""
    powered_by: str = ""
    session_id: Optional[str] = None
    auth_required: bool = False
    authenticated: bool = False          # we sent auth and it worked
    tools: list = field(default_factory=list)          # list[ToolInfo]
    resources: list = field(default_factory=list)      # list[str]
    prompts: list = field(default_factory=list)        # list[str]
    risk_score: int = 0
    risk_level: str = "info"
    findings: list = field(default_factory=list)       # list[str]
    aliases: list = field(default_factory=list)        # other URLs for the same server
    command: list = field(default_factory=list)        # stdio argv, when transport == "stdio"
    auth: dict = field(default_factory=dict)           # OAuth/auth-spec detail (0.5.0)
    resource_findings: list = field(default_factory=list)  # [{uri, class, detail}] (0.6.0)

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["tools"] = [t.__dict__ for t in self.tools]
        return d


# --- low-level transport -----------------------------------------------------

def _build_opener(proxy, insecure):
    handlers = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    if insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    return urllib.request.build_opener(*handlers)


def _parse_body(raw, content_type):
    ct = (content_type or "").lower()
    if "text/event-stream" in ct or raw.lstrip().startswith("event:") or "\ndata:" in raw:
        chunks = [ln[5:].strip() for ln in raw.splitlines() if ln.startswith("data:")]
        for chunk in reversed(chunks):
            try:
                return json.loads(chunk)
            except Exception:
                continue
    try:
        return json.loads(raw)
    except Exception:
        m = re.search(r"\{.*\}", raw, re.S)
        if m:
            try:
                return json.loads(m.group(0))
            except Exception:
                return None
    return None


@dataclass
class _Resp:
    body: object
    session: Optional[str]
    status: int
    headers: dict = field(default_factory=dict)


def _rpc(url, payload, proxy=None, timeout=8.0, session=None, insecure=False, headers=None):
    """POST a JSON-RPC message. Returns a _Resp (raises on connection error)."""
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json, text/event-stream")
    if session:
        req.add_header("MCP-Session-Id", session)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    opener = _build_opener(proxy, insecure)
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
            h = {k.lower(): v for k, v in resp.headers.items()}
            return _Resp(_parse_body(raw, resp.headers.get("Content-Type", "")),
                         resp.headers.get("MCP-Session-Id"), getattr(resp, "status", 200), h)
    except urllib.error.HTTPError as e:
        raw = ""
        try:
            raw = e.read().decode("utf-8", "replace")
        except Exception:
            pass
        eh = {k.lower(): v for k, v in (e.headers or {}).items()}
        body = _parse_body(raw, eh.get("content-type", ""))
        return _Resp({"__httperror__": e.code, "__www__": eh.get("www-authenticate", ""),
                      "body": body}, None, e.code, eh)


def _is_transient(ex):
    reason = getattr(ex, "reason", ex)
    if isinstance(reason, (ConnectionResetError, TimeoutError, socket.timeout)):
        return True
    if isinstance(reason, ConnectionRefusedError):
        return False
    if isinstance(reason, OSError) and getattr(reason, "winerror", None) in (10053, 10054, 10060):
        return True
    return False


def _rpc_retry(url, payload, proxy, timeout, session, insecure, headers, retries=2):
    for attempt in range(retries + 1):
        try:
            return _rpc(url, payload, proxy, timeout, session, insecure, headers)
        except Exception as ex:
            if attempt < retries and _is_transient(ex):
                time.sleep(0.15 * (attempt + 1))
                continue
            raise


# --- handshake + enumeration -------------------------------------------------

def _init_payload():
    from . import __version__  # local import avoids a package-init cycle
    return {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL_VERSION, "capabilities": {},
            "clientInfo": {"name": "mcpsweep", "version": __version__},
        },
    }


def probe(host, port, path, scheme="http", proxy=None, timeout=8.0,
          insecure=False, headers=None, retries=2, on_diag=None):
    """Try one host:port+path. Returns an MCPEndpoint or None.

    ``on_diag(url, status, reason)`` (optional) is called when the probe does
    NOT yield a confirmed endpoint, so verbose callers can explain a miss.
    ``status`` is None for connection-level failures.
    """
    url = f"{scheme}://{host}:{port}{path}"
    try:
        r = _rpc_retry(url, _init_payload(), proxy, timeout, None, insecure, headers, retries)
    except Exception as ex:
        if on_diag:
            on_diag(url, None, f"connection error: {type(ex).__name__}")
        return None
    ep = _endpoint_from_resp(url, host, port, path, scheme, r, bool(headers))
    if ep is None and on_diag:
        on_diag(url, r.status, _why_not_mcp(r))
    return ep


def probe_url(full_url, proxy=None, timeout=8.0, insecure=False, headers=None,
              retries=2, on_diag=None):
    """Probe an exact URL (scheme://host:port/path)."""
    u = urllib.parse.urlparse(full_url)
    scheme = u.scheme or "http"
    host = u.hostname or ""
    port = u.port or (443 if scheme == "https" else 80)
    path = u.path or "/"
    try:
        r = _rpc_retry(full_url, _init_payload(), proxy, timeout, None, insecure, headers, retries)
    except Exception as ex:
        if on_diag:
            on_diag(full_url, None, f"connection error: {type(ex).__name__}")
        return None
    ep = _endpoint_from_resp(full_url, host, port, path, scheme, r, bool(headers))
    if ep is None and on_diag:
        on_diag(full_url, r.status, _why_not_mcp(r))
    return ep


def _endpoint_from_resp(url, host, port, path, scheme, r, sent_auth):
    body = r.body
    if body is None:
        return None

    if isinstance(body, dict) and body.get("__httperror__") in (401, 403):
        inner = body.get("body")
        looks_mcp = bool(body.get("__www__")) or (
            isinstance(inner, dict) and ("jsonrpc" in inner or "error" in inner))
        if looks_mcp:
            ep = MCPEndpoint(url=url, host=host, port=port, path=path, scheme=scheme,
                             auth_required=True, server_name="(auth required)")
            ep.server_header = r.headers.get("server", "")
            ep.powered_by = r.headers.get("x-powered-by", "")
            ep.auth = {"status": "auth-required", "www_authenticate": body.get("__www__", "")}
            ep.findings.append("endpoint requires authentication")
            return ep
        return None

    if not isinstance(body, dict):
        return None
    result = body.get("result")
    if not isinstance(result, dict) or "protocolVersion" not in result:
        return None

    si = result.get("serverInfo", {}) or {}
    caps = list((result.get("capabilities") or {}).keys())
    instr = (result.get("instructions") or "").replace("\n", " ").strip()
    ep = MCPEndpoint(
        url=url, host=host, port=port, path=path, scheme=scheme,
        transport="sse" if "sse" in path else "streamable-http",
        server_name=si.get("name", "?"), server_version=si.get("version", "?"),
        protocol=result.get("protocolVersion", "?"), capabilities=caps,
        instructions=instr, instructions_poisoned=bool(POISON_RE.search(instr)),
        server_header=r.headers.get("server", ""), powered_by=r.headers.get("x-powered-by", ""),
        session_id=r.session, authenticated=sent_auth,
    )
    if sent_auth:
        ep.findings.append("initialize succeeded with the supplied credentials")
    else:
        ep.findings.append("initialize succeeded without credentials (no authentication)")
    return ep


def _why_not_mcp(r):
    """Human-readable reason a probe response was not a valid MCP endpoint."""
    b = r.body
    if isinstance(b, dict) and b.get("__httperror__"):
        code = b["__httperror__"]
        return f"HTTP {code} (not recognised as MCP - likely auth-gated or wrong path)"
    ct = r.headers.get("content-type", "?")
    if b is None:
        return f"HTTP {r.status}: unparseable/non-JSON body (content-type {ct})"
    if isinstance(b, dict) and isinstance(b.get("result"), dict):
        return f"HTTP {r.status}: JSON-RPC result but no protocolVersion"
    return f"HTTP {r.status}: responded but not an MCP initialize (content-type {ct})"


def _notify_initialized(url, sid, proxy, timeout, insecure, headers):
    try:
        _rpc(url, {"jsonrpc": "2.0", "method": "notifications/initialized"},
             proxy, timeout, session=sid, insecure=insecure, headers=headers)
    except Exception:
        pass


def _list(url, method, key, sid, proxy, timeout, insecure, headers, retries=2):
    try:
        r = _rpc_retry(url, {"jsonrpc": "2.0", "id": 2, "method": method, "params": {}},
                       proxy, timeout, sid, insecure, headers, retries)
    except Exception:
        return []
    if isinstance(r.body, dict):
        return (r.body.get("result") or {}).get(key, []) or []
    return []


def _analyze_tool(t):
    name = t.get("name", "")
    desc = t.get("description", "") or ""
    blob = (name + " " + desc).lower()
    tags = sorted({tag for kw, tag in RISK_KEYWORDS.items() if kw in blob})
    props = (t.get("inputSchema") or {}).get("properties") or {}
    freeform = sorted(p for p, spec in props.items()
                      if isinstance(spec, dict) and spec.get("type") == "string"
                      and not spec.get("enum"))
    injection = bool(freeform) and bool(set(tags) & INJECTABLE_TAGS)
    return ToolInfo(name=name, description=desc, tags=tags,
                    poisoned=bool(POISON_RE.search(desc)),
                    freeform_params=freeform, injection_surface=injection)


def enumerate_endpoint(ep, proxy=None, timeout=8.0, insecure=False, full=False,
                       headers=None, auth_probe=False, deep=False, read_resources=False,
                       deep_max_bytes=65536, deep_max_resources=50):
    if ep.auth_required:
        if auth_probe:
            from .authmeta import probe_auth
            ep.auth = probe_auth(ep.url, (ep.auth or {}).get("www_authenticate", ""),
                                 proxy, timeout, insecure)
        _score(ep)
        return ep
    _notify_initialized(ep.url, ep.session_id, proxy, timeout, insecure, headers)

    raw_tools = _list(ep.url, "tools/list", "tools", ep.session_id, proxy, timeout, insecure, headers)
    for raw in raw_tools:
        ep.tools.append(_analyze_tool(raw))

    res = pr = templates = []
    if full or deep:
        res = _list(ep.url, "resources/list", "resources", ep.session_id, proxy, timeout, insecure, headers)
        ep.resources = [r.get("uri", r.get("name", "?")) for r in res]
        for r in res:
            if POISON_RE.search(json.dumps(r)):
                ep.findings.append(f"resource looks POISONED: {r.get('uri', r.get('name','?'))}")
        pr = _list(ep.url, "prompts/list", "prompts", ep.session_id, proxy, timeout, insecure, headers)
        ep.prompts = [p.get("name", "?") for p in pr]
        for p in pr:
            if POISON_RE.search(json.dumps(p)):
                ep.findings.append(f"prompt looks POISONED: {p.get('name','?')}")

    if deep:
        templates = _list(ep.url, "resources/templates/list", "resourceTemplates",
                          ep.session_id, proxy, timeout, insecure, headers)
        from . import deep as _deep
        _deep.run(ep, raw_tools, res, templates, pr, read_resources,
                  proxy, timeout, insecure, headers, deep_max_bytes, deep_max_resources)

    _score(ep)
    return ep


def _score(ep):
    score = 0
    if not ep.auth_required and not ep.authenticated and ep.transport != "stdio":
        score += 20
    st = (ep.auth or {}).get("status")
    if st == "oauth2.1":
        ep.findings.append("properly OAuth 2.1 protected (MCP auth spec)")
    elif st == "misconfig":
        score += 10
        ep.findings.append("OAuth misconfiguration: "
                           + ", ".join(ep.auth.get("issues") or ["incomplete metadata"]))
    elif st == "non-standard":
        score += 6
        ep.findings.append("auth required but no OAuth discovery metadata (non-standard)")
    if ep.instructions_poisoned:
        score += 20
        ep.findings.append("server instructions contain injected content")
    poisoned = [t for t in ep.tools if t.poisoned]
    injectable = [t for t in ep.tools if t.injection_surface]
    for t in ep.tools:
        score += 6 * len(set(t.tags) & DANGEROUS_TAGS)
        if t.poisoned:
            score += 25
        if t.injection_surface:
            score += 10
    for f in ep.findings:
        if "POISONED" in f or "injected" in f:
            score += 8
    if poisoned:
        ep.findings.append(f"{len(poisoned)} tool description(s) look POISONED: "
                           + ", ".join(t.name for t in poisoned))
    if injectable:
        ep.findings.append("free-form input on high-impact tools (injection surface): "
                           + ", ".join(t.name for t in injectable))
    dangerous = [t for t in ep.tools if set(t.tags) & {"rce", "sql", "money", "destructive"}]
    if dangerous:
        ep.findings.append("high-impact tools exposed: " + ", ".join(t.name for t in dangerous))
    hint = next((h for h in RISKY_NAME_HINTS if h in ep.server_name.lower()), None)
    if hint:
        ep.findings.append(f"server name suggests elevated/untrusted purpose ('{hint}')")
    # deep-analysis (0.6.0) contributions
    score += 8 * sum(len(t.param_vulns) for t in ep.tools)
    score += 8 * len(ep.resource_findings)
    score += 5 * sum(1 for f in ep.findings
                     if f.startswith(("annotation-mismatch", "confused-deputy", "prompt-injection-surface")))
    ep.risk_score = score
    ep.risk_level = ("critical" if score >= 60 else "high" if score >= 35
                     else "medium" if score >= 15 else "low")


# --- target expansion + orchestration ---------------------------------------

_URL_RE = re.compile(r"^https?://", re.I)


def expand_targets(targets):
    out = []
    for t in targets:
        t = t.strip()
        if not t:
            continue
        try:
            net = ipaddress.ip_network(t, strict=False)
            if net.num_addresses > 1:
                out.extend(str(ip) for ip in net.hosts())
                continue
        except ValueError:
            pass
        out.append(t)
    seen, uniq = set(), []
    for h in out:
        if h not in seen:
            seen.add(h); uniq.append(h)
    return uniq


def _canonical_path(path):
    return path.rstrip("/") or "/"


def dedupe(found):
    """Collapse endpoints that are the same server reached via twin URLs.

    Level 1 — trailing-slash twins: same (scheme, host, port, normalised path).
    Level 2 — same server (name, version, tool-set) on the same host:port via
    different paths. The canonical endpoint keeps the shortest path; the others'
    URLs are recorded in ``aliases``.
    """
    def merge(group):
        group.sort(key=lambda e: (len(e.path), e.path))
        canon = group[0]
        for other in group[1:]:
            for u in [other.url] + list(other.aliases):
                if u != canon.url and u not in canon.aliases:
                    canon.aliases.append(u)
        return canon

    # level 1
    by_url = {}
    for ep in found:
        by_url.setdefault((ep.scheme, ep.host, ep.port, _canonical_path(ep.path)), []).append(ep)
    level1 = [merge(g) for g in by_url.values()]

    # level 2 (only for fully-fingerprinted endpoints)
    by_sig, passthru = {}, []
    for ep in level1:
        if ep.auth_required or ep.server_name in ("?", "(auth required)"):
            passthru.append(ep)
            continue
        sig = (ep.scheme, ep.host, ep.port, ep.server_name, ep.server_version,
               tuple(sorted(t.name for t in ep.tools)))
        by_sig.setdefault(sig, []).append(ep)
    return passthru + [merge(g) for g in by_sig.values()]


def parse_ports(spec):
    ports = set()
    for part in str(spec).split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            ports.update(range(int(a), int(b) + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p < 65536)


def scan(targets, ports, paths=None, schemes=("http",), proxy=None, timeout=8.0,
         concurrency=16, insecure=False, full=False, headers=None, exclude=None,
         retries=2, on_found=None, on_diag=None, auth_probe=False,
         deep=False, read_resources=False, deep_max_bytes=65536, deep_max_resources=50):
    """Sweep targets. A target may be a bare host, a CIDR block, or a full URL.

    Full-URL targets are probed exactly (ports/paths/schemes ignored for them).
    ``exclude`` is a set of hosts to skip. ``on_found(ep)`` fires per discovery.
    """
    paths = paths or DEFAULT_PATHS
    exclude = set(exclude or ())

    url_targets = [t for t in targets if _URL_RE.match(t.strip())]
    host_targets = [t for t in targets if not _URL_RE.match(t.strip())]
    hosts = [h for h in expand_targets(host_targets) if h not in exclude]

    jobs = []  # each: ("url", full_url) or ("hpp", host, port, path, scheme)
    for u in url_targets:
        jobs.append(("url", u))
    for h in hosts:
        for p in ports:
            for path in paths:
                for sc in schemes:
                    jobs.append(("hpp", h, p, path, sc))

    def run(job):
        if job[0] == "url":
            return probe_url(job[1], proxy, timeout, insecure, headers, retries, on_diag)
        _, h, p, path, sc = job
        return probe(h, p, path, sc, proxy, timeout, insecure, headers, retries, on_diag)

    found = []
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futs = [pool.submit(run, j) for j in jobs]
        for fut in as_completed(futs):
            ep = fut.result()
            if ep is None:
                continue
            enumerate_endpoint(ep, proxy, timeout, insecure, full, headers, auth_probe,
                               deep, read_resources, deep_max_bytes, deep_max_resources)
            found.append(ep)
            if on_found:
                on_found(ep)
    found = dedupe(found)
    found.sort(key=lambda e: (-e.risk_score, e.host, e.port, e.path))
    return found

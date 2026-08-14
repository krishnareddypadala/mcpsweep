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

#: substrings in a tool description that suggest an embedded instruction to the
#: model (tool poisoning / prompt injection hidden in metadata)
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


@dataclass
class ToolInfo:
    name: str
    description: str = ""
    tags: list = field(default_factory=list)
    poisoned: bool = False


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
    session_id: Optional[str] = None
    auth_required: bool = False
    tools: list = field(default_factory=list)          # list[ToolInfo]
    resources: list = field(default_factory=list)      # list[str]
    prompts: list = field(default_factory=list)        # list[str]
    risk_score: int = 0
    risk_level: str = "info"
    findings: list = field(default_factory=list)       # list[str]

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["tools"] = [t.__dict__ for t in self.tools]
        return d


# --- low-level transport -----------------------------------------------------

def _build_opener(proxy: Optional[str], insecure: bool):
    handlers = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    if insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    return urllib.request.build_opener(*handlers)


def _parse_body(raw: str, content_type: str):
    """Return a parsed JSON object from a plain-JSON or SSE-framed body."""
    ct = (content_type or "").lower()
    if "text/event-stream" in ct or raw.lstrip().startswith("event:") or "\ndata:" in raw:
        # concatenate all `data:` payloads and try to parse the last JSON object
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


def _rpc(url, payload, proxy=None, timeout=8.0, session=None, insecure=False):
    """POST a JSON-RPC message. Returns (body_obj_or_None, session_id, status)."""
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json, text/event-stream")
    if session:
        req.add_header("MCP-Session-Id", session)
    opener = _build_opener(proxy, insecure)
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
            sid = resp.headers.get("MCP-Session-Id")
            body = _parse_body(raw, resp.headers.get("Content-Type", ""))
            return body, sid, getattr(resp, "status", 200)
    except urllib.error.HTTPError as e:
        raw = ""
        try:
            raw = e.read().decode("utf-8", "replace")
        except Exception:
            pass
        body = _parse_body(raw, e.headers.get("Content-Type", "") if e.headers else "")
        # surface auth challenges to the caller
        www = e.headers.get("WWW-Authenticate", "") if e.headers else ""
        return {"__httperror__": e.code, "__www__": www, "body": body}, None, e.code


# --- handshake + enumeration -------------------------------------------------

def _init_payload():
    return {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "mcpsweep", "version": "0.1.0"},
        },
    }


def _is_transient(ex):
    """True for connection resets / timeouts worth retrying (not a closed port)."""
    reason = getattr(ex, "reason", ex)
    if isinstance(reason, (ConnectionResetError, TimeoutError, socket.timeout)):
        return True
    if isinstance(reason, ConnectionRefusedError):
        return False
    if isinstance(reason, OSError) and getattr(reason, "winerror", None) in (10053, 10054, 10060):
        return True
    return False


def probe(host, port, path, scheme="http", proxy=None, timeout=8.0, insecure=False, retries=2):
    """Try one host:port+path. Returns an MCPEndpoint or None.

    Retries the handshake on transient connection errors (resets/timeouts) so a
    momentary blip under concurrent load doesn't drop a live endpoint.
    """
    url = f"{scheme}://{host}:{port}{path}"
    body = sid = None
    for attempt in range(retries + 1):
        try:
            body, sid, status = _rpc(url, _init_payload(), proxy, timeout, insecure=insecure)
            break
        except Exception as ex:
            if attempt < retries and _is_transient(ex):
                time.sleep(0.15 * (attempt + 1))
                continue
            return None
    if body is None:
        return None

    # auth-gated MCP endpoint?
    if isinstance(body, dict) and body.get("__httperror__") in (401, 403):
        inner = body.get("body")
        looks_mcp = bool(body.get("__www__")) or (
            isinstance(inner, dict) and ("jsonrpc" in inner or "error" in inner)
        )
        if looks_mcp:
            ep = MCPEndpoint(url=url, host=host, port=port, path=path, scheme=scheme,
                             auth_required=True, server_name="(auth required)")
            ep.findings.append("endpoint requires authentication (good)")
            return ep
        return None

    if not isinstance(body, dict):
        return None
    result = body.get("result")
    if not isinstance(result, dict) or "protocolVersion" not in result:
        return None

    si = result.get("serverInfo", {}) or {}
    caps = list((result.get("capabilities") or {}).keys())
    ep = MCPEndpoint(
        url=url, host=host, port=port, path=path, scheme=scheme,
        transport="sse" if "sse" in path else "streamable-http",
        server_name=si.get("name", "?"), server_version=si.get("version", "?"),
        protocol=result.get("protocolVersion", "?"), capabilities=caps,
        instructions=(result.get("instructions") or "").replace("\n", " ").strip(),
        session_id=sid,
    )
    # unauthenticated init succeeded -> no auth in front of this server
    ep.findings.append("initialize succeeded without credentials (no authentication)")
    return ep


def _notify_initialized(url, sid, proxy, timeout, insecure):
    try:
        _rpc(url, {"jsonrpc": "2.0", "method": "notifications/initialized"},
             proxy, timeout, session=sid, insecure=insecure)
    except Exception:
        pass


def _list(url, method, key, sid, proxy, timeout, insecure, retries=2):
    body = None
    for attempt in range(retries + 1):
        try:
            body, _, _ = _rpc(url, {"jsonrpc": "2.0", "id": 2, "method": method, "params": {}},
                              proxy, timeout, session=sid, insecure=insecure)
            break
        except Exception as ex:
            if attempt < retries and _is_transient(ex):
                time.sleep(0.15 * (attempt + 1))
                continue
            return []
    if isinstance(body, dict):
        return (body.get("result") or {}).get(key, []) or []
    return []


def enumerate_endpoint(ep: MCPEndpoint, proxy=None, timeout=8.0, insecure=False, full=False):
    """Populate tools (and, with full=True, resources/prompts) + risk scoring."""
    if ep.auth_required:
        ep.risk_level = "info"
        return ep
    _notify_initialized(ep.url, ep.session_id, proxy, timeout, insecure)

    raw_tools = _list(ep.url, "tools/list", "tools", ep.session_id, proxy, timeout, insecure)
    for t in raw_tools:
        name = t.get("name", "")
        desc = t.get("description", "") or ""
        blob = (name + " " + desc).lower()
        tags = sorted({tag for kw, tag in RISK_KEYWORDS.items() if kw in blob})
        poisoned = bool(POISON_RE.search(desc))
        ep.tools.append(ToolInfo(name=name, description=desc, tags=tags, poisoned=poisoned))

    if full:
        ep.resources = [r.get("uri", r.get("name", "?"))
                        for r in _list(ep.url, "resources/list", "resources",
                                       ep.session_id, proxy, timeout, insecure)]
        ep.prompts = [p.get("name", "?")
                      for p in _list(ep.url, "prompts/list", "prompts",
                                     ep.session_id, proxy, timeout, insecure)]

    _score(ep)
    return ep


def _score(ep: MCPEndpoint):
    score = 0
    if not ep.auth_required:
        score += 20  # unauthenticated surface
    poisoned = [t for t in ep.tools if t.poisoned]
    for t in ep.tools:
        score += 6 * len(set(t.tags) & DANGEROUS_TAGS)
        if t.poisoned:
            score += 25
    if poisoned:
        ep.findings.append(f"{len(poisoned)} tool description(s) look POISONED: "
                           + ", ".join(t.name for t in poisoned))
    dangerous = [t for t in ep.tools if set(t.tags) & {"rce", "sql", "money", "destructive"}]
    if dangerous:
        ep.findings.append("high-impact tools exposed: "
                           + ", ".join(t.name for t in dangerous))
    ep.risk_score = score
    ep.risk_level = ("critical" if score >= 60 else "high" if score >= 35
                     else "medium" if score >= 15 else "low")


# --- target expansion + orchestration ---------------------------------------

def expand_targets(targets):
    """Expand hostnames and CIDR blocks into a flat list of host strings."""
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
    # de-dup, preserve order
    seen, uniq = set(), []
    for h in out:
        if h not in seen:
            seen.add(h); uniq.append(h)
    return uniq


def parse_ports(spec):
    """'8000,8090,9000-9010' -> sorted unique int list."""
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


def scan(targets, ports, paths=None, schemes=("http",), proxy=None,
         timeout=8.0, concurrency=16, insecure=False, full=False, on_found=None):
    """Sweep every host x port x path x scheme. Returns list[MCPEndpoint].

    ``on_found(ep)`` is called as each endpoint is confirmed (for live output).
    """
    paths = paths or DEFAULT_PATHS
    hosts = expand_targets(targets)
    jobs = [(h, p, path, sc)
            for h in hosts for p in ports for path in paths for sc in schemes]

    found = []
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futs = {pool.submit(probe, h, p, path, sc, proxy, timeout, insecure): (h, p, path, sc)
                for (h, p, path, sc) in jobs}
        for fut in as_completed(futs):
            ep = fut.result()
            if ep is None:
                continue
            enumerate_endpoint(ep, proxy, timeout, insecure, full)
            found.append(ep)
            if on_found:
                on_found(ep)
    found.sort(key=lambda e: (-e.risk_score, e.host, e.port, e.path))
    return found

"""Transport-layer security probes (spec 2025-11-25 / 2026-07-28 security notes).

These are the live checks a static or source scanner cannot do. All are
read-only: one OPTIONS preflight and one re-sent fingerprint request with a
foreign Origin/Host. Nothing mutating is ever sent.

Models:
- **DNS rebinding** - a server that answers a request carrying a foreign
  ``Host``/``Origin`` has no rebinding protection, so a malicious web page can
  pivot through the victim's browser to a localhost MCP server
  (CVE-2025-66414 / 66416; the SDKs shipped this OFF by default).
- **CORS** - ``Access-Control-Allow-Origin: *`` or a reflected origin, combined
  with ``Access-Control-Allow-Credentials: true``, lets any site read responses.
- **LAN exposure (NeighborJack)** - an unauthenticated MCP server answering on a
  private/LAN-scoped address is reachable across the LAN (CVE-2026-49257, 10.0).
  Public FQDNs/IPs are exposed by design and do not trip this (see ``_lan_scope``).
"""
from __future__ import annotations

import ipaddress
import urllib.error
import urllib.request

from .scanner import (_build_opener, _discover_payload, _init_payload,
                      _merge_headers, _modern_headers, _parse_body)

_EVIL_HOST = "mcpsweep-rebind.example"
_EVIL_ORIGIN = "http://mcpsweep-rebind.example"


def _raw(url, method, proxy, timeout, insecure, headers, data=None):
    req = urllib.request.Request(url, data=data, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    opener = _build_opener(proxy, insecure)
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
            h = {k.lower(): v for k, v in resp.headers.items()}
            return getattr(resp, "status", 200), h, raw
    except urllib.error.HTTPError as e:
        h = {k.lower(): v for k, v in (e.headers or {}).items()}
        try:
            raw = e.read().decode("utf-8", "replace")
        except Exception:
            raw = ""
        return e.code, h, raw
    except Exception:
        return None, {}, ""


def _is_loopback(host):
    h = (host or "").strip("[]").lower()
    if h in ("localhost", "ip6-localhost"):
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


# Carrier-grade NAT shared address space (RFC 6598). ipaddress.is_private only
# learned about it in Python 3.12.4, so classify it explicitly for 3.8+.
_CGNAT = ipaddress.ip_network("100.64.0.0/10")

# Hostname suffixes that name a private/LAN-scoped host (mDNS and common
# intranet conventions), not a public internet service.
_LAN_SUFFIXES = (".local", ".lan", ".internal", ".intranet",
                 ".home", ".corp", ".localdomain")


def _lan_scope(host):
    """True only if *host* is a private / LAN-scoped address or name.

    This is the NeighborJack ("reachable across the LAN") predicate, so it must
    be False for both loopback and for *public* internet hosts: an unauthenticated
    server on a public FQDN or public IP (e.g. a hosted SaaS MCP endpoint) is
    public by design, not a LAN-exposure misconfiguration.
    """
    h = (host or "").strip("[]").lower()
    if not h or h in ("localhost", "ip6-localhost"):
        return False
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        # Hostname, not an IP literal. LAN only if it names an intranet host:
        # an mDNS/intranet suffix, or a single-label (dotless) name like "nas".
        if h.endswith(_LAN_SUFFIXES):
            return True
        return "." not in h
    if ip.is_loopback:
        return False
    # RFC1918 private, link-local (169.254/fe80::), unique-local (fc00::/7),
    # and CGNAT shared space are all LAN/neighbour-reachable scope.
    return (ip.is_private or ip.is_link_local
            or (ip.version == 4 and ip in _CGNAT))


def probe_transport(ep, proxy=None, timeout=8.0, insecure=False, headers=None):
    """Run the transport-security probes against a discovered endpoint.

    Adds structured entries to ``ep.transport_findings`` and human strings to
    ``ep.findings``. Scoring happens later in scanner._score.
    """
    if ep.transport == "stdio":
        return ep

    def add(cls, detail):
        ep.transport_findings.append({"class": cls, "detail": detail})
        ep.findings.append(f"{cls}: {detail}")

    # 1) DNS-rebinding / Host+Origin validation --------------------------------
    if ep.protocol_era == "modern":
        payload = _discover_payload()
        base = _merge_headers(headers, _modern_headers("server/discover"))
    else:
        payload = _init_payload()
        base = dict(headers or {})
    import json as _json
    spoof = _merge_headers(base, {"Content-Type": "application/json",
                                  "Accept": "application/json, text/event-stream",
                                  "Host": _EVIL_HOST, "Origin": _EVIL_ORIGIN})
    status, h, raw = _raw(ep.url, "POST", proxy, timeout, insecure, spoof,
                          data=_json.dumps(payload).encode())
    if status is not None and status < 400:
        body = _parse_body(raw, h.get("content-type", ""))
        accepted = isinstance(body, dict) and isinstance(body.get("result"), dict)
        if accepted:
            add("dns-rebinding",
                f"accepts a foreign Origin/Host ({_EVIL_HOST}) with no validation "
                f"(browser-pivot / DNS-rebinding risk)")

    # 2) CORS -----------------------------------------------------------------
    cstatus, ch, _ = _raw(ep.url, "OPTIONS", proxy, timeout, insecure,
                          _merge_headers(headers, {"Origin": _EVIL_ORIGIN,
                                                   "Access-Control-Request-Method": "POST"}))
    acao = ch.get("access-control-allow-origin", "")
    acac = (ch.get("access-control-allow-credentials", "") or "").lower() == "true"
    if acao == "*":
        add("cors-wildcard", "Access-Control-Allow-Origin: * (any site can call this server)")
    elif acao and acao == _EVIL_ORIGIN:
        if acac:
            add("cors-reflect-credentials",
                "reflects an arbitrary Origin AND allows credentials "
                "(cross-site tool execution with the victim's cookies)")
        else:
            add("cors-reflect", "reflects an arbitrary Origin in Access-Control-Allow-Origin")

    # 3) LAN exposure (NeighborJack) ------------------------------------------
    #    Only for private/LAN-scoped hosts - a public FQDN/IP is exposed by
    #    design, not a NeighborJack misconfiguration (see _lan_scope).
    if not ep.auth_required and not ep.authenticated and _lan_scope(ep.host):
        add("lan-exposure",
            f"unauthenticated MCP server answering on a private/LAN address ({ep.host}) "
            f"- reachable across the LAN (NeighborJack)")

    # 4) unauthenticated tasks/* on an otherwise-authenticated server ---------
    #    (CVE-2026-52870 missing authz on tasks/*, CVE-2026-111767 task IDOR)
    if ep.auth_required:
        noauth = {k: v for k, v in (headers or {}).items() if k.lower() != "authorization"}
        th = _merge_headers(noauth, {"Content-Type": "application/json",
                                     "Accept": "application/json, text/event-stream"})
        if ep.protocol_era == "modern":
            th = _merge_headers(th, _modern_headers("tasks/list"))
        status, h, raw = _raw(ep.url, "POST", proxy, timeout, insecure, th,
                              data=_json.dumps({"jsonrpc": "2.0", "id": 7,
                                                "method": "tasks/list", "params": {}}).encode())
        if status is not None and status < 400:
            body = _parse_body(raw, h.get("content-type", ""))
            tasks = isinstance(body, dict) and (body.get("result") or {}).get("tasks")
            if tasks:
                add("unauthenticated-tasks",
                    "tasks/* is reachable WITHOUT credentials even though the server requires "
                    "auth elsewhere (task store not access-controlled; CVE-2026-52870/111767 class)")

    return ep

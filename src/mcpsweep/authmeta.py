"""OAuth / MCP auth-spec detection.

When an MCP server answers with 401/403, the MCP auth spec expects it to behave
as an OAuth 2.1 resource server: the ``WWW-Authenticate`` challenge points at
Protected Resource Metadata (RFC 9728), which lists the authorization server(s),
whose own metadata (RFC 8414) describes scopes, endpoints and PKCE support. This
module follows that chain and classifies how (well) a server is protected.
"""
from __future__ import annotations

import ipaddress
import json
import re
import socket
import ssl
import urllib.parse
import urllib.request

_SHELL_META_RE = re.compile(r"[;&|`$><]|\$\(|\|\||&&")


def _unsafe_target(url, self_host=None):
    """True if a URL points somewhere a scanner must NOT fetch: a non-http(s)
    scheme, or a host that resolves to a link-local / cloud-metadata address, or
    an internal address *other than the server's own* (SSRF). We flag these
    instead of following them.

    ``self_host`` is the hostname of the server being scanned. A server that
    advertises its OWN (internal) address in its OAuth metadata is the normal
    case for an internal deployment - not SSRF - so a private address that
    matches ``self_host`` is treated as a safe self-reference. Link-local and
    cloud-metadata targets (CVE-2026-51994) are always flagged, even if the
    server somehow points there itself."""
    try:
        u = urllib.parse.urlparse(url)
    except Exception:
        return "unparseable URL"
    if u.scheme not in ("http", "https"):
        return f"non-http(s) scheme ({u.scheme or 'none'}:)"
    host = (u.hostname or "").strip("[]")
    if not host:
        return "no host"
    is_self = bool(self_host) and host.lower() == self_host.strip("[]").lower()
    cand = []
    try:
        cand.append(ipaddress.ip_address(host))
    except ValueError:
        try:
            for fam, _, _, _, sa in socket.getaddrinfo(host, None):
                try:
                    cand.append(ipaddress.ip_address(sa[0]))
                except ValueError:
                    pass
        except Exception:
            return None   # can't resolve; treat as external (don't over-flag)
    for ip in cand:
        # loopback is NOT flagged: localhost MCP servers are the normal case and
        # the scanner targets them constantly.
        if ip.is_loopback:
            continue
        # link-local / cloud-metadata is the real SSRF signal (CVE-2026-51994):
        # always flagged, even for a self-reference.
        if (ip.is_link_local or ip.is_reserved or ip.is_multicast
                or str(ip) in ("169.254.169.254", "100.100.100.200")):
            return f"resolves to a link-local/metadata address ({ip})"
        # an ordinary private address that is the server's OWN host is a normal
        # internal deployment, not SSRF; only a *different* internal host is.
        if ip.is_private and not is_self:
            return f"resolves to a private/internal address ({ip})"
    return None


def _get_json(url, proxy, timeout, insecure):
    if not url:
        return None
    req = urllib.request.Request(url, method="GET")
    req.add_header("Accept", "application/json")
    handlers = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    if insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    try:
        with urllib.request.build_opener(*handlers).open(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except Exception:
        return None


def _resource_metadata_url(base_url, www):
    m = re.search(r'resource_metadata="?([^",\s]+)"?', www or "", re.I)
    if m:
        return m.group(1)
    u = urllib.parse.urlparse(base_url)
    return f"{u.scheme}://{u.netloc}/.well-known/oauth-protected-resource"


def probe_auth(base_url, www, proxy=None, timeout=8.0, insecure=False):
    """Follow the RFC 9728 → RFC 8414 chain. Returns an ``auth`` dict."""
    out = {"status": "non-standard", "www_authenticate": www}
    self_host = urllib.parse.urlparse(base_url).hostname

    rm_url = _resource_metadata_url(base_url, www)
    rm = _get_json(rm_url, proxy, timeout, insecure)
    if not isinstance(rm, dict):
        return out                                       # auth required, no discovery
    out["resource_metadata"] = rm_url
    servers = rm.get("authorization_servers") or []
    out["authorization_servers"] = servers
    out["scopes"] = rm.get("scopes_supported") or []

    pkce = dcr = False
    endpoints = {}
    as_ok = False
    hygiene = []

    # hygiene: the resource_metadata URL itself (CVE-2026-51994 SSRF class)
    bad = _unsafe_target(rm_url, self_host)
    if bad:
        hygiene.append(f"resource_metadata URL unsafe to follow - {bad}")

    for issuer in servers[:3]:
        base = issuer.rstrip("/")
        # NEVER fetch a link-local/metadata issuer, or a different internal host -
        # flag it instead of becoming an SSRF vector ourselves.
        bad = _unsafe_target(base, self_host)
        if bad:
            hygiene.append(f"authorization server {base!r} - {bad}")
            continue
        md = (_get_json(base + "/.well-known/oauth-authorization-server", proxy, timeout, insecure)
              or _get_json(base + "/.well-known/openid-configuration", proxy, timeout, insecure))
        if isinstance(md, dict):
            as_ok = True
            endpoints = {"authorize": md.get("authorization_endpoint"),
                         "token": md.get("token_endpoint")}
            pkce = "S256" in (md.get("code_challenge_methods_supported") or [])
            dcr = bool(md.get("registration_endpoint"))
            if not out["scopes"]:
                out["scopes"] = md.get("scopes_supported") or []
            if not md.get("issuer"):
                hygiene.append("authorization server metadata missing 'issuer'")
            # endpoint hygiene: bad scheme / SSRF target / shell metacharacters
            for label, ep_url in (("authorization_endpoint", md.get("authorization_endpoint")),
                                  ("token_endpoint", md.get("token_endpoint")),
                                  ("jwks_uri", md.get("jwks_uri")),
                                  ("registration_endpoint", md.get("registration_endpoint"))):
                if not ep_url:
                    continue
                b = _unsafe_target(ep_url, self_host)
                if b:
                    hygiene.append(f"{label} unsafe - {b}")
                if _SHELL_META_RE.search(str(ep_url)):
                    hygiene.append(f"{label} contains shell metacharacters (CVE-2025-6514 class)")

    out["pkce"], out["dcr"], out["endpoints"] = pkce, dcr, endpoints

    # over-broad scopes
    if any(s in ("*", "admin", "all") for s in (out.get("scopes") or [])):
        hygiene.append("over-broad scope advertised (" +
                       ", ".join(s for s in out["scopes"] if s in ("*", "admin", "all")) + ")")

    issues = []
    if servers and as_ok:
        if pkce:
            out["status"] = "oauth2.1"
        else:
            out["status"] = "misconfig"
            issues.append("no PKCE S256")
    else:
        out["status"] = "misconfig"
        issues.append("authorization server metadata unreachable")
    if dcr:
        issues.append("open dynamic client registration")
    issues += hygiene
    if hygiene:
        out["hygiene"] = hygiene
    if issues:
        out["issues"] = issues
    return out

"""OAuth / MCP auth-spec detection.

When an MCP server answers with 401/403, the MCP auth spec expects it to behave
as an OAuth 2.1 resource server: the ``WWW-Authenticate`` challenge points at
Protected Resource Metadata (RFC 9728), which lists the authorization server(s),
whose own metadata (RFC 8414) describes scopes, endpoints and PKCE support. This
module follows that chain and classifies how (well) a server is protected.
"""
from __future__ import annotations

import json
import re
import ssl
import urllib.parse
import urllib.request


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
    for issuer in servers[:3]:
        base = issuer.rstrip("/")
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
    out["pkce"], out["dcr"], out["endpoints"] = pkce, dcr, endpoints

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
    if issues:
        out["issues"] = issues
    return out

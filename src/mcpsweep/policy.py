"""Baseline / policy evaluation (0.7.0).

Declare a sanctioned inventory once (JSON); every scan then flags anything that
deviates: servers not in the baseline (shadow), tools outside a server's
allowlist, and rule breaches (require_auth, deny_tags, deny_poisoned, max_risk).
Stateless — unlike ``diff``, which needs two scans to compare.
"""
from __future__ import annotations

import json
import urllib.parse

from .scanner import _canonical_path

_SEV = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def load_policy(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _norm(url):
    u = urllib.parse.urlparse(url)
    if u.scheme in ("http", "https"):
        port = u.port or (443 if u.scheme == "https" else 80)
        return f"{u.scheme}://{(u.hostname or '').lower()}:{port}{_canonical_path(u.path)}"
    return url                                            # stdio:// etc.


def _match(ep, servers):
    for s in servers:
        m = s.get("match", {}) or {}
        if m.get("url") and _norm(m["url"]) == _norm(ep.url):
            return s
        if m.get("server_name") and m["server_name"] == ep.server_name:
            return s
    return None


def evaluate(endpoints, policy):
    """Return a list of {rule, endpoint, tool, detail} violations."""
    servers = policy.get("servers") or []
    rules = policy.get("rules") or {}
    deny_tags = set(rules.get("deny_tags") or [])
    max_risk = rules.get("max_risk")
    max_rank = _SEV.get(max_risk) if max_risk else None

    viol = []

    def add(rule, ep, detail, tool=None):
        viol.append({"rule": rule, "endpoint": ep.url, "tool": tool, "detail": detail})

    for ep in endpoints:
        s = _match(ep, servers)
        if s is None:
            add("shadow-server", ep, "server not in the sanctioned baseline")
        elif not s.get("allow_any_tool"):
            allowed = set(s.get("allow_tools") or [])
            for t in ep.tools:
                if t.name not in allowed:
                    add("unexpected-tool", ep, f"tool not in allowlist: {t.name}", t.name)

        if rules.get("require_auth") and not (ep.auth_required or ep.authenticated):
            add("policy-require-auth", ep, "server is not authenticated")
        if deny_tags:
            for t in ep.tools:
                bad = deny_tags & set(t.tags)
                if bad:
                    add("policy-deny-tag", ep,
                        f"tool '{t.name}' has denied capability: {', '.join(sorted(bad))}", t.name)
        if rules.get("deny_poisoned"):
            if ep.instructions_poisoned:
                add("policy-poisoned", ep, "server instructions are poisoned")
            for t in ep.tools:
                if t.poisoned:
                    add("policy-poisoned", ep, f"poisoned tool description: {t.name}", t.name)
        if max_rank is not None and _SEV.get(ep.risk_level, 0) > max_rank:
            add("policy-max-risk", ep, f"risk {ep.risk_level} exceeds policy max {max_risk}")
    return viol


def write_baseline(endpoints):
    """Generate a baseline policy from a scan (bootstrap: scan once, freeze)."""
    return {
        "version": 1,
        "servers": [{"match": {"url": ep.url},
                     "allow_tools": sorted(t.name for t in ep.tools)}
                    for ep in endpoints],
        "rules": {},
    }

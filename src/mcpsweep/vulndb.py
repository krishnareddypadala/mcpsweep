"""Offline known-vulnerable version matching.

Matches a server's ``serverInfo.name`` / ``version`` against a **bundled**
advisory list (``data/advisories.json``). Entirely local: nothing is ever sent
to OSV / NVD / GHSA, so the scanner stays local-only. Update the JSON with each
release (or via PR) rather than querying a service at runtime.
"""
from __future__ import annotations

import json
import os
import re

_CACHE = None


def _load():
    global _CACHE
    if _CACHE is None:
        path = os.path.join(os.path.dirname(__file__), "data", "advisories.json")
        try:
            with open(path, encoding="utf-8") as fh:
                _CACHE = json.load(fh).get("advisories", [])
        except Exception:
            _CACHE = []
    return _CACHE


def _norm_name(name):
    """Lowercase, drop an npm scope, collapse to a comparable token."""
    n = (name or "").lower().strip()
    n = re.sub(r"^@[^/]+/", "", n)          # @scope/pkg -> pkg
    return n


def _ver_tuple(v):
    parts = re.findall(r"\d+", str(v or ""))
    return tuple(int(p) for p in parts[:4]) or (0,)


def _cmp(a, b):
    a, b = _ver_tuple(a), _ver_tuple(b)
    n = max(len(a), len(b))
    a += (0,) * (n - len(a))
    b += (0,) * (n - len(b))
    return (a > b) - (a < b)


def _match_constraint(version, constraint):
    """constraint is a comma-separated list of <op><ver>, e.g. '>=0.1.32,<0.1.39'."""
    for part in str(constraint).split(","):
        part = part.strip()
        m = re.match(r"(<=|>=|<|>|==)?\s*(.+)", part)
        if not m:
            return False
        op, ver = m.group(1) or "<", m.group(2)
        c = _cmp(version, ver)
        ok = {"<": c < 0, "<=": c <= 0, ">": c > 0, ">=": c >= 0, "==": c == 0}[op]
        if not ok:
            return False
    return True


def _names_match(server_name, adv):
    sn = _norm_name(server_name)
    if not sn or sn in ("?", "(auth required)"):
        return False
    candidates = [adv.get("name", "")] + list(adv.get("aliases", []))
    for c in candidates:
        cn = _norm_name(c)
        if cn and (sn == cn or sn.endswith(cn) or cn in sn.split()):
            return True
    return False


def match(server_name, version):
    """Return a list of advisory dicts whose name+range matches this server."""
    hits = []
    for adv in _load():
        if _names_match(server_name, adv) and _match_constraint(version, adv.get("affected", "<9999")):
            hits.append(adv)
    return hits


def annotate(ep):
    """Populate ep.known_vulns from the fingerprint (scoring happens in _score)."""
    if ep.server_name in ("?", "(auth required)") or not ep.server_version or ep.server_version == "?":
        return
    ep.known_vulns = match(ep.server_name, ep.server_version)

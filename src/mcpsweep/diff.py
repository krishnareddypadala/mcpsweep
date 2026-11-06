"""Drift detection: compare two mcpsweep JSON reports.

Surfaces new / removed MCP servers and tools, newly-poisoned descriptions, and
risk-level changes between an old and a new scan — the basis for continuous
posture monitoring.
"""
from __future__ import annotations

import json


def _load(path):
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return {e["url"]: e for e in data.get("endpoints", [])}


def diff_reports(old_path, new_path):
    old = _load(old_path)
    new = _load(new_path)
    old_urls, new_urls = set(old), set(new)

    added = sorted(new_urls - old_urls)
    removed = sorted(old_urls - new_urls)
    changes = []
    for url in sorted(old_urls & new_urls):
        oe, ne = old[url], new[url]
        ot = {t["name"]: t for t in oe.get("tools", [])}
        nt = {t["name"]: t for t in ne.get("tools", [])}
        common = set(ot) & set(nt)
        # rug-pull: a tool that stayed but whose signature (name+description+schema)
        # changed - the MCPoison pattern (CVE-2025-54136). Fall back to description
        # comparison when an older report has no signature field.
        rug = []
        for n in common:
            osig, nsig = ot[n].get("signature"), nt[n].get("signature")
            if osig and nsig:
                if osig != nsig:
                    rug.append(n)
            elif ot[n].get("description") != nt[n].get("description"):
                rug.append(n)
        c = {
            "url": url,
            "tools_added": sorted(set(nt) - set(ot)),
            "tools_removed": sorted(set(ot) - set(nt)),
            "newly_poisoned": sorted(n for n in common
                                     if nt[n].get("poisoned") and not ot[n].get("poisoned")),
            "rug_pulled": sorted(rug),
            "risk_from": oe.get("risk_level"), "risk_to": ne.get("risk_level"),
            "risk_changed": oe.get("risk_level") != ne.get("risk_level"),
        }
        if (c["tools_added"] or c["tools_removed"] or c["newly_poisoned"]
                or c["rug_pulled"] or c["risk_changed"]):
            changes.append(c)
    return {"added": added, "removed": removed, "changed": changes,
            "old": old_path, "new": new_path}


def render_diff_text(d, color=True):
    G = "\033[1;32m" if color else ""
    R = "\033[1;31m" if color else ""
    Y = "\033[1;33m" if color else ""
    C = "\033[1;36m" if color else ""
    Z = "\033[0m" if color else ""
    out = [f"{C}== drift: {d['old']} -> {d['new']} =={Z}"]
    for u in d["added"]:
        out.append(f"  {G}+ NEW server{Z} {u}")
    for u in d["removed"]:
        out.append(f"  {R}- server gone{Z} {u}")
    for c in d["changed"]:
        out.append(f"  {Y}~ {c['url']}{Z}")
        for t in c["tools_added"]:
            out.append(f"      {G}+ tool{Z} {t}")
        for t in c["tools_removed"]:
            out.append(f"      {R}- tool{Z} {t}")
        for t in c["newly_poisoned"]:
            out.append(f"      {R}! now POISONED{Z} {t}")
        for t in c.get("rug_pulled", []):
            out.append(f"      {R}! RUG-PULL (definition changed){Z} {t}")
        if c["risk_changed"]:
            out.append(f"      {Y}~ risk {c['risk_from']} -> {c['risk_to']}{Z}")
    if not (d["added"] or d["removed"] or d["changed"]):
        out.append(f"  {G}no drift{Z}")
    return "\n".join(out)


def has_drift(d):
    return bool(d["added"] or d["removed"] or d["changed"])

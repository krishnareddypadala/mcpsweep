"""Active authorization probing (0.8.0) — opt-in, heavily gated.

Unlike the rest of mcpsweep, this module CALLS tools (``tools/call``) to *verify*
findings rather than infer them: unauthenticated BOLA/IDOR (an id-taking read
tool returning different records for different ids) and real secret/PII exposure
in tool output. It breaks the default read-only guarantee, so the CLI requires
``--i-have-authorization`` and offers ``--active-dry-run``, a call cap, and a
full audit log. Tier 1 probes only safe-read tools; ``--active-all`` (Tier 2)
probes every tool and can therefore trigger writes.
"""
from __future__ import annotations

import json

from .scanner import _rpc_retry
from .deep import SECRET_RE, PII_RE

READ_HINTS = ("get", "list", "read", "lookup", "fetch", "show", "find", "search",
              "describe", "summary", "balance", "customer", "account", "view")
UNSAFE_TAGS = {"write", "rce", "exec", "money", "destructive", "state-change"}
ID_HINTS = ("id", "acno", "account", "user", "uid", "customer", "index",
            "num", "number", "key")


def is_safe_read(name, tags):
    low = name.lower()
    if set(tags) & UNSAFE_TAGS:
        return False
    return any(h in low for h in READ_HINTS)


def _benign(spec):
    t = (spec or {}).get("type")
    if t in ("integer", "number"):
        return 1
    if t == "boolean":
        return False
    if t == "array":
        return []
    if t == "object":
        return {}
    return "1"


def _id_param(props, required):
    for p in required:
        low = p.lower()
        spec = props.get(p, {})
        if any(h in low for h in ID_HINTS) or spec.get("type") in ("integer", "number"):
            return p, spec
    return None, None


def _call(url, tool, args, session, proxy, timeout, insecure, headers, audit):
    payload = {"jsonrpc": "2.0", "id": 77, "method": "tools/call",
               "params": {"name": tool, "arguments": args}}
    text = ""
    try:
        resp = _rpc_retry(url, payload, proxy, timeout, session, insecure, headers)
    except Exception:
        resp = None
    body = resp.body if resp else None
    if isinstance(body, dict):
        for c in (body.get("result", {}) or {}).get("content", []) or []:
            if isinstance(c, dict) and c.get("type") == "text":
                text += c.get("text", "")
        if body.get("error"):
            text = "ERROR:" + json.dumps(body["error"])[:200]
    if audit is not None:
        audit.append({"endpoint": url, "tool": tool, "arguments": args, "response": text[:2000]})
    return text


def run(ep, tier, proxy, timeout, insecure, headers, max_calls, dry_run, audit):
    raw = _rpc_retry(ep.url, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
                     proxy, timeout, ep.session_id, insecure, headers)
    tools = (raw.body or {}).get("result", {}).get("tools", []) if raw and isinstance(raw.body, dict) else []
    budget = [max_calls]
    confirmed = 0

    for t in tools:
        name = t.get("name", "")
        tags = next((ti.tags for ti in ep.tools if ti.name == name), [])
        if tier < 2 and not is_safe_read(name, tags):
            continue
        schema = t.get("inputSchema") or {}
        props = schema.get("properties") or {}
        required = schema.get("required") or []

        idp, idspec = _id_param(props, required)
        if dry_run:
            plan = {p: _benign(props.get(p)) for p in required}
            ep.findings.append(f"ACTIVE(dry-run): would call {name}({json.dumps(plan)})")
            continue
        if budget[0] <= 0:
            break

        responses = []
        if idp:
            vals = [1, 2, 3] if idspec.get("type") in ("integer", "number") else ["1", "2", "3"]
            for v in vals:
                if budget[0] <= 0:
                    break
                budget[0] -= 1
                args = {p: (_benign(props.get(p)) if p != idp else v) for p in required}
                responses.append(_call(ep.url, name, args, ep.session_id, proxy, timeout,
                                       insecure, headers, audit))
        else:
            budget[0] -= 1
            args = {p: _benign(props.get(p)) for p in required}
            responses.append(_call(ep.url, name, args, ep.session_id, proxy, timeout,
                                   insecure, headers, audit))

        ok = [r for r in responses if r and not r.startswith("ERROR:")]
        # BOLA: distinct non-error records across ids, no auth
        if idp and len({r for r in ok}) >= 2:
            confirmed += 1
            ev = " | ".join(r[:80] for r in ok[:2])
            ep.active_findings.append({"tool": name, "class": "bola",
                                       "detail": f"unauthenticated BOLA via {name}({idp}): distinct records",
                                       "evidence": ev})
            ep.findings.append(f"ACTIVE: confirmed BOLA/IDOR via {name}({idp}) - returns different records unauthenticated")
        # secret/PII exposure in real output
        for r in ok:
            if SECRET_RE.search(r) or PII_RE.search(r):
                confirmed += 1
                ep.active_findings.append({"tool": name, "class": "secret-exposure",
                                           "detail": f"{name} output contains a secret/PII",
                                           "evidence": r[:120]})
                ep.findings.append(f"ACTIVE: confirmed secret/PII exposure in {name} output")
                break

    if confirmed:
        ep.risk_score += 25 * confirmed
        if ep.risk_score >= 60:
            ep.risk_level = "critical"
        elif ep.risk_score >= 35:
            ep.risk_level = "high"
    return ep

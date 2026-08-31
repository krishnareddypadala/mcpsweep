"""SARIF and HTML report renderers for mcpsweep."""
from __future__ import annotations

import html
import json

from . import __version__

# --- SARIF 2.1.0 -------------------------------------------------------------

_RULES = {
    "no-authentication": ("MCP server requires no authentication", "error"),
    "poisoned-tool": ("Tool description contains injected instructions", "error"),
    "poisoned-instructions": ("Server instructions contain injected content", "error"),
    "poisoned-resource": ("Resource or prompt contains injected content", "error"),
    "dangerous-tool": ("High-impact tool exposed (rce/sql/money/destructive)", "warning"),
    "injection-surface": ("Free-form input on a high-impact tool", "warning"),
    "risky-name": ("Server name suggests elevated/untrusted purpose", "note"),
    "auth-misconfig": ("Authentication is misconfigured or non-standard", "warning"),
    "command-injection": ("Tool parameter is a command-injection sink", "error"),
    "sqli": ("Tool parameter is a SQL-injection sink", "error"),
    "path-traversal": ("Tool parameter is a path-traversal sink", "warning"),
    "ssrf": ("Tool parameter is an SSRF sink", "warning"),
    "secret-in-resource": ("Resource content leaks a secret or PII", "error"),
    "stored-injection-resource": ("Resource content contains an injection payload", "error"),
    "annotation-mismatch": ("Tool annotation misrepresents behaviour", "warning"),
    "confused-deputy": ("Tool instructs calling another tool", "warning"),
    "file-exposure": ("Resource exposes a local/sensitive path", "warning"),
    "resource-template": ("Templated resource URI (traversal/SSRF surface)", "note"),
    "shadow-server": ("Server not in the sanctioned baseline", "error"),
    "unexpected-tool": ("Tool not in the baseline allowlist", "warning"),
    "policy-require-auth": ("Policy requires authentication", "error"),
    "policy-deny-tag": ("Tool has a policy-denied capability", "error"),
    "policy-poisoned": ("Policy forbids poisoned tools/instructions", "error"),
    "policy-max-risk": ("Endpoint exceeds the policy max risk", "warning"),
    "active-bola": ("Verified BOLA/IDOR (tool was called)", "error"),
    "active-secret-exposure": ("Verified secret/PII exposure (tool was called)", "error"),
    "discovery": ("MCP endpoint discovered", "note"),
}


def _rule_for(finding: str):
    f = finding.lower()
    if "no authentication" in f or "without credentials" in f:
        return "no-authentication"
    if "tool description" in f and "poison" in f:
        return "poisoned-tool"
    if "instructions" in f and ("injected" in f or "poison" in f):
        return "poisoned-instructions"
    if ("resource" in f or "prompt" in f) and "poison" in f:
        return "poisoned-resource"
    if "injection surface" in f or "free-form input" in f:
        return "injection-surface"
    if "high-impact tools exposed" in f:
        return "dangerous-tool"
    if "elevated/untrusted purpose" in f:
        return "risky-name"
    if "oauth misconfiguration" in f or "non-standard" in f:
        return "auth-misconfig"
    if "confirmed bola" in f:
        return "active-bola"
    if "confirmed secret" in f:
        return "active-secret-exposure"
    for pfx in ("command-injection", "sqli", "path-traversal", "ssrf",
                "annotation-mismatch", "confused-deputy"):
        if f.startswith(pfx):
            return pfx
    if f.startswith("prompt-injection-surface"):
        return "injection-surface"
    if "injection payload" in f:
        return "stored-injection-resource"
    if "secret/credential" in f or "contains pii" in f:
        return "secret-in-resource"
    if "local/sensitive path" in f:
        return "file-exposure"
    if "templated resource uri" in f:
        return "resource-template"
    return "discovery"


def render_sarif(endpoints, scope="", violations=None):
    results = []
    for ep in endpoints:
        findings = ep.findings or ["MCP endpoint discovered"]
        for f in findings:
            rid = _rule_for(f)
            results.append({
                "ruleId": rid,
                "level": _RULES[rid][1],
                "message": {"text": f"{f} — {ep.server_name} ({ep.risk_level}, score {ep.risk_score})"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": ep.url}}}],
                "properties": {"riskLevel": ep.risk_level, "riskScore": ep.risk_score},
            })
    for v in (violations or []):
        rid = v["rule"]
        results.append({
            "ruleId": rid,
            "level": _RULES.get(rid, ("", "warning"))[1],
            "message": {"text": v["detail"]},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": v["endpoint"]}}}],
        })
    return json.dumps({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "mcpsweep", "version": __version__,
                "informationUri": "https://github.com/krishnareddypadala/mcpsweep",
                "rules": [{"id": k, "name": k,
                           "shortDescription": {"text": v[0]},
                           "defaultConfiguration": {"level": v[1]}}
                          for k, v in _RULES.items()],
            }},
            "results": results,
            "properties": {"scope": scope},
        }],
    }, indent=2)


# --- HTML --------------------------------------------------------------------

_LEVEL_HEX = {"critical": "#c02636", "high": "#c2510c", "medium": "#a1720b",
              "low": "#12805a", "info": "#6f7788"}


def render_html(endpoints, scope="", elapsed=0.0):
    def esc(s):
        return html.escape(str(s))

    crit = sum(1 for e in endpoints if e.risk_level == "critical")
    high = sum(1 for e in endpoints if e.risk_level == "high")
    cards = []
    for ep in endpoints:
        col = _LEVEL_HEX.get(ep.risk_level, "#6f7788")
        tools_rows = "".join(
            f"<tr><td><code>{esc(t.name)}</code></td>"
            f"<td>{esc(', '.join(t.tags) or '—')}</td>"
            f"<td>{'⚠️ yes' if t.poisoned else 'no'}</td>"
            f"<td>{esc(', '.join(t.freeform_params) or '—')}</td></tr>"
            for t in ep.tools)
        findings = "".join(f"<li>{esc(f)}</li>" for f in ep.findings)
        meta = (f"{esc(ep.server_name)} v{esc(ep.server_version)} · proto {esc(ep.protocol)} · "
                f"{esc(ep.transport)}")
        if ep.server_header or ep.powered_by:
            meta += f" · {esc(ep.server_header)} {esc(ep.powered_by)}".rstrip()
        cards.append(f"""
    <section class="ep" style="border-left-color:{col}">
      <div class="ephead"><code class="url">{esc(ep.url)}</code>
        <span class="pill" style="background:{col}">{esc(ep.risk_level)} · {ep.risk_score}</span></div>
      <div class="meta">{meta}</div>
      <ul class="find">{findings}</ul>
      {"<table><thead><tr><th>Tool</th><th>Risk tags</th><th>Poisoned</th><th>Free-form params</th></tr></thead><tbody>" + tools_rows + "</tbody></table>" if ep.tools else ""}
    </section>""")

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>mcpsweep report</title>
<style>
  :root{{--bg:#eef1f5;--panel:#fff;--ink:#141922;--muted:#6f7788;--line:#e0e4ec;--accent:#0d6e63}}
  @media(prefers-color-scheme:dark){{:root{{--bg:#0e1016;--panel:#171a22;--ink:#eef1f7;--muted:#828b9c;--line:#262c37;--accent:#3fbfa9}}}}
  *{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--ink);
    font:15px/1.55 ui-sans-serif,system-ui,Segoe UI,Roboto,sans-serif}}
  .wrap{{max-width:1000px;margin:0 auto;padding:32px 20px}}
  code{{font-family:ui-monospace,Menlo,Consolas,monospace}}
  h1{{margin:0 0 4px;font-size:26px}} .sub{{color:var(--muted);font-family:ui-monospace,monospace;font-size:13px}}
  .kpis{{display:flex;gap:12px;flex-wrap:wrap;margin:20px 0}}
  .kpi{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:12px 18px}}
  .kpi b{{font-size:26px;display:block}} .kpi span{{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.08em}}
  .ep{{background:var(--panel);border:1px solid var(--line);border-left:5px solid;border-radius:12px;padding:16px 18px;margin:14px 0}}
  .ephead{{display:flex;justify-content:space-between;gap:12px;align-items:center;flex-wrap:wrap}}
  .url{{font-weight:600;word-break:break-all}} .meta{{color:var(--muted);font-size:13px;margin:6px 0}}
  .pill{{color:#fff;font-family:ui-monospace,monospace;font-size:12px;font-weight:700;padding:3px 10px;border-radius:999px;text-transform:uppercase}}
  ul.find{{margin:8px 0;padding-left:20px}} ul.find li{{margin:2px 0}}
  table{{border-collapse:collapse;width:100%;margin-top:10px;font-size:13px;overflow-x:auto;display:block}}
  th,td{{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line)}}
  th{{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.06em}}
  footer{{color:var(--muted);font-size:12px;margin-top:28px;border-top:1px solid var(--line);padding-top:14px}}
</style></head><body><div class="wrap">
  <h1>mcpsweep report</h1>
  <div class="sub">{esc(scope)} · {elapsed:.1f}s · mcpsweep {esc(__version__)}</div>
  <div class="kpis">
    <div class="kpi"><b>{len(endpoints)}</b><span>endpoints</span></div>
    <div class="kpi"><b style="color:{_LEVEL_HEX['critical']}">{crit}</b><span>critical</span></div>
    <div class="kpi"><b style="color:{_LEVEL_HEX['high']}">{high}</b><span>high</span></div>
  </div>
  {''.join(cards)}
  <footer>Read-only MCP discovery scan. Authorized use only.</footer>
</div></body></html>"""

"""Deep surface analysis (0.6.0): auto-explore tools, resources and prompt
templates and derive concrete vulnerability classes.

Static checks add no requests beyond enumeration (+ resources/templates/list).
The opt-in deep read (``--read-resources``) fetches resource *contents* via
resources/read and scans them — still never calling a tool.
"""
from __future__ import annotations

import re

SECRET_RE = re.compile(
    r"(?i)(api[_-]?key|secret[_-]?key|client[_-]?secret|password|passwd|"
    r"aws_secret_access_key|private[_-]?key|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"
    r"xox[baprs]-|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})")
PII_RE = re.compile(r"(\b\d{3}-\d{2}-\d{4}\b|\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b)")
SENS_PATH_RE = re.compile(
    r"(?i)(/etc/passwd|/etc/shadow|(^|/)\.env|id_rsa|(^|/)\.git/|(^|/)\.aws/|(^|/)\.ssh/|"
    r"credentials|secrets?\.(json|ya?ml|txt))")

PATH_HINTS = ("path", "file", "dir", "filename", "folder")
URL_HINTS = ("url", "uri", "host", "endpoint", "server", "target", "addr", "address", "link")
DESTRUCTIVE_WORDS = ("delete", "remove", "drop", "destroy", "wipe", "truncate", "purge")
WRITE_WORDS = ("write", "update", "create", "set", "insert", "modify", "transfer") + DESTRUCTIVE_WORDS
CALL_RE = re.compile(r"\b(call|invoke|use|run|execute|trigger)\b", re.I)


def analyze_params(raw_tool, tags):
    props = (raw_tool.get("inputSchema") or {}).get("properties") or {}
    tagset = set(tags)
    out = []
    for pname, spec in props.items():
        if not isinstance(spec, dict) or spec.get("enum"):
            continue
        if spec.get("type") not in (None, "string"):
            continue
        low = pname.lower()
        if tagset & {"rce", "exec"}:
            out.append({"param": pname, "class": "command-injection",
                        "why": "free-form string on an exec/shell tool"})
        elif tagset & {"sql", "query"}:
            out.append({"param": pname, "class": "sqli",
                        "why": "free-form string on a query tool"})
        elif any(h in low for h in PATH_HINTS):
            out.append({"param": pname, "class": "path-traversal",
                        "why": "unconstrained path/file parameter"})
        elif any(h in low for h in URL_HINTS):
            out.append({"param": pname, "class": "ssrf",
                        "why": "caller-controlled URL/host parameter"})
    return out


def analyze_annotations(raw_tool, name, tags):
    ann = raw_tool.get("annotations")
    if not isinstance(ann, dict):
        return None
    low = name.lower()
    tagset = set(tags)
    if ann.get("destructiveHint") is False and (
            any(w in low for w in DESTRUCTIVE_WORDS) or "destructive" in tagset):
        return f"{name}: destructiveHint=false but name/tags indicate a destructive tool"
    if ann.get("readOnlyHint") is True and (
            any(w in low for w in WRITE_WORDS) or (tagset & {"write", "money", "state-change", "destructive"})):
        return f"{name}: readOnlyHint=true but name/tags indicate writes"
    return None


def confused_deputy(name, desc, tool_names):
    d = (desc or "").lower()
    if not CALL_RE.search(d):
        return None
    for other in tool_names:
        if other and other != name and other.lower() in d:
            return f"{name} description references {CALL_RE.search(d).group(0)}-ing '{other}'"
    return None


def analyze_resource_uri(uri, is_template=False):
    out = []
    if uri.startswith("file://") or SENS_PATH_RE.search(uri):
        out.append(("file-exposure", f"resource exposes a local/sensitive path: {uri}"))
    if is_template and re.search(r"\{[^}]+\}", uri):
        out.append(("resource-template", f"templated resource URI (traversal/SSRF surface): {uri}"))
    return out


def scan_content(text):
    out = []
    if SECRET_RE.search(text):
        out.append(("secret-in-resource", "resource content contains a secret/credential"))
    elif PII_RE.search(text):
        out.append(("secret-in-resource", "resource content contains PII"))
    from .scanner import POISON_RE
    if POISON_RE.search(text):
        out.append(("stored-injection-resource", "resource content contains an injection payload"))
    return out


def run(ep, tools, resources, templates, prompts, read_resources,
        proxy, timeout, insecure, headers, max_bytes, max_res):
    tool_names = {t.get("name", "") for t in tools}
    for ti, raw in zip(ep.tools, tools):
        ti.param_vulns = analyze_params(raw, ti.tags)
        for pv in ti.param_vulns:
            ep.findings.append(f"{pv['class']}: {ti.name}({pv['param']}) - {pv['why']}")
        am = analyze_annotations(raw, ti.name, ti.tags)
        if am:
            ep.findings.append("annotation-mismatch: " + am)
        cd = confused_deputy(ti.name, ti.description, tool_names)
        if cd:
            ep.findings.append("confused-deputy: " + cd)

    for pr in prompts:
        if pr.get("arguments"):
            ep.findings.append(f"prompt-injection-surface: prompt '{pr.get('name','?')}' "
                               f"interpolates {len(pr['arguments'])} argument(s)")

    def _record(uri, pairs):
        for cls, msg in pairs:
            ep.resource_findings.append({"uri": uri, "class": cls, "detail": msg})
            ep.findings.append(msg)

    for r in resources:
        _record(r.get("uri", r.get("name", "")), analyze_resource_uri(r.get("uri", ""), False))
    for r in templates:
        uri = r.get("uriTemplate", r.get("uri", ""))
        _record(uri, analyze_resource_uri(uri, True))

    if read_resources:
        _read_and_scan(ep, resources, proxy, timeout, insecure, headers, max_bytes, max_res)


def _read_and_scan(ep, resources, proxy, timeout, insecure, headers, max_bytes, max_res):
    from .scanner import _rpc_retry
    for r in resources[:max_res]:
        uri = r.get("uri")
        if not uri:
            continue
        try:
            resp = _rpc_retry(ep.url, {"jsonrpc": "2.0", "id": 9, "method": "resources/read",
                                       "params": {"uri": uri}},
                              proxy, timeout, ep.session_id, insecure, headers)
        except Exception:
            continue
        body = resp.body if resp else None
        contents = (body or {}).get("result", {}).get("contents", []) if isinstance(body, dict) else []
        for c in contents:
            text = (c.get("text") or "")[:max_bytes]
            if not text:
                continue
            for cls, msg in scan_content(text):
                ep.resource_findings.append({"uri": uri, "class": cls, "detail": msg})
                ep.findings.append(f"{msg}: {uri}")

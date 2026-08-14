"""Command-line interface for mcpsweep."""
from __future__ import annotations

import argparse
import json
import sys
import time

from . import __version__
from .scanner import DEFAULT_PATHS, DEFAULT_PORTS, MCPEndpoint, parse_ports, scan
from . import report as _report
from . import diff as _diff

SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class C:
    HEAD = "\033[1;36m"; OK = "\033[1;32m"; WARN = "\033[1;33m"
    CRIT = "\033[1;31m"; DIM = "\033[0;90m"; BOLD = "\033[1m"; Z = "\033[0m"

    @classmethod
    def disable(cls):
        for k in ("HEAD", "OK", "WARN", "CRIT", "DIM", "BOLD", "Z"):
            setattr(cls, k, "")


LEVEL_COLOR = {"critical": C.CRIT, "high": C.WARN, "medium": C.WARN, "low": C.DIM, "info": C.DIM}


def render_console(endpoints, elapsed):
    out = []
    for ep in endpoints:
        col = LEVEL_COLOR.get(ep.risk_level, "")
        out.append(f"\n{C.OK}[MCP]{C.Z} {C.BOLD}{ep.url}{C.Z}  "
                   f"{col}{ep.risk_level.upper()}{C.Z} (score {ep.risk_score})")
        if ep.auth_required:
            out.append(f"    {C.DIM}server  :{C.Z} (authentication required — not enumerated)")
        else:
            out.append(f"    {C.DIM}server  :{C.Z} {ep.server_name}  v{ep.server_version}  "
                       f"proto={ep.protocol}  transport={ep.transport}")
            if ep.server_header or ep.powered_by:
                out.append(f"    {C.DIM}http    :{C.Z} {ep.server_header} {ep.powered_by}".rstrip())
            if ep.capabilities:
                out.append(f"    {C.DIM}caps    :{C.Z} {', '.join(ep.capabilities)}")
            if ep.session_id:
                out.append(f"    {C.DIM}session :{C.Z} {ep.session_id} "
                           f"{C.DIM}(correlator, not auth){C.Z}")
            if ep.instructions:
                snip = ep.instructions[:150] + ("…" if len(ep.instructions) > 150 else "")
                poison = f"  {C.CRIT}[POISONED]{C.Z}" if ep.instructions_poisoned else ""
                out.append(f"    {C.DIM}notes   :{C.Z} {snip}{poison}")
            out.append(f"    {C.DIM}tools   :{C.Z} {len(ep.tools)}")
            for t in ep.tools:
                tagstr = f" {C.DIM}[{','.join(t.tags)}]{C.Z}" if t.tags else ""
                flags = ""
                if t.poisoned:
                    flags += f"  {C.CRIT}<-- POISONED{C.Z}"
                if t.injection_surface:
                    flags += f"  {C.WARN}<-- free-form input ({','.join(t.freeform_params)}){C.Z}"
                out.append(f"      - {t.name}{tagstr}{flags}")
            if ep.resources:
                out.append(f"    {C.DIM}resources:{C.Z} {len(ep.resources)} "
                           f"({', '.join(map(str, ep.resources[:5]))})")
            if ep.prompts:
                out.append(f"    {C.DIM}prompts :{C.Z} {len(ep.prompts)} "
                           f"({', '.join(map(str, ep.prompts[:5]))})")
        for f in ep.findings:
            mark = C.WARN
            if "POISON" in f or "injected" in f or "high-impact" in f or "injection surface" in f:
                mark = C.CRIT
            if "requires authentication" in f.lower() or "authenticated as" in f.lower():
                mark = C.OK
            out.append(f"    {mark}![{C.Z} {f}")
    crit = sum(1 for e in endpoints if e.risk_level == "critical")
    out.append(f"\n{C.HEAD}== {len(endpoints)} endpoint(s) in {elapsed:.1f}s "
               f"({crit} critical) =={C.Z}")
    return "\n".join(out)


def render_json(endpoints, elapsed, scope):
    return json.dumps({
        "tool": "mcpsweep", "version": __version__, "scope": scope,
        "elapsed_s": round(elapsed, 2), "endpoint_count": len(endpoints),
        "endpoints": [e.to_dict() for e in endpoints],
    }, indent=2)


def render_markdown(endpoints, elapsed, scope):
    L = ["# MCP discovery report", "",
         f"- **scope:** `{scope}`", f"- **endpoints found:** {len(endpoints)}",
         f"- **scan time:** {elapsed:.1f}s", "",
         "| Endpoint | Server | Risk | Tools | Notable |", "|---|---|---|---|---|"]
    for ep in endpoints:
        notable = []
        if ep.auth_required:
            notable.append("auth required")
        if ep.instructions_poisoned:
            notable.append("poisoned instructions")
        if any(t.poisoned for t in ep.tools):
            notable.append("poisoned tool")
        if any(t.injection_surface for t in ep.tools):
            notable.append("injection surface")
        notable += sorted({tag for t in ep.tools for tag in t.tags
                           if tag in ("rce", "sql", "money", "destructive", "secret")})
        L.append(f"| `{ep.url}` | {ep.server_name} v{ep.server_version} | "
                 f"{ep.risk_level} ({ep.risk_score}) | {len(ep.tools)} | {', '.join(notable) or '—'} |")
    L.append("")
    for ep in endpoints:
        if ep.auth_required:
            continue
        L.append(f"## {ep.url}")
        L.append(f"*{ep.server_name} v{ep.server_version} · proto {ep.protocol} · "
                 f"{ep.transport} · risk {ep.risk_level} ({ep.risk_score})*")
        L.append("")
        for f in ep.findings:
            L.append(f"- {f}")
        if ep.tools:
            L += ["", "| Tool | Risk tags | Poisoned | Free-form params |", "|---|---|---|---|"]
            for t in ep.tools:
                L.append(f"| `{t.name}` | {', '.join(t.tags) or '—'} | "
                         f"{'⚠️ yes' if t.poisoned else 'no'} | {', '.join(t.freeform_params) or '—'} |")
        L.append("")
    return "\n".join(L)


def _headers_from_args(args):
    headers = {}
    for h in args.header or []:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    if args.bearer:
        headers["Authorization"] = f"Bearer {args.bearer}"
    return headers or None


def build_parser():
    p = argparse.ArgumentParser(
        prog="mcpsweep",
        description="Discover and fingerprint MCP-over-HTTP servers, enumerate their "
                    "tools, and flag risky or poisoned ones. Read-only (never calls a tool). "
                    "Subcommand: 'mcpsweep diff old.json new.json'.",
        epilog="example: mcpsweep 10.10.0.31 --ports 8090 --proxy http://127.0.0.1:8080",
    )
    p.add_argument("targets", nargs="*",
                   help="host(s), CIDR block(s), or full URL(s); e.g. 10.10.0.31, 10.10.0.0/28, "
                        "http://h:8090/mcp/api")
    p.add_argument("--target-file", "-iL",
                   help="targets file: one-per-line text (# comments) OR JSON "
                        "(array, {\"targets\":[...]}, or a prior mcpsweep report)")
    p.add_argument("--exclude", help="comma-separated hosts to skip")
    p.add_argument("--ports", default=",".join(map(str, DEFAULT_PORTS)),
                   help="ports/ranges, e.g. '8090,8000,9000-9010'")
    p.add_argument("--paths", default=",".join(DEFAULT_PATHS), help="comma-separated URL paths")
    p.add_argument("--scheme", choices=["http", "https", "both"], default="http")
    p.add_argument("--header", "-H", action="append", help="extra header 'Key: Value' (repeatable)")
    p.add_argument("--bearer", help="bearer token (adds Authorization: Bearer <token>)")
    p.add_argument("--proxy", help="route all traffic via a proxy, e.g. http://127.0.0.1:8080")
    p.add_argument("--insecure", "-k", action="store_true", help="skip TLS verification")
    p.add_argument("--timeout", type=float, default=8.0, help="per-request timeout seconds")
    p.add_argument("--concurrency", "-c", type=int, default=16, help="parallel probes")
    p.add_argument("--full", action="store_true", help="also enumerate resources and prompts")
    p.add_argument("--severity", choices=list(SEV_ORDER), help="only report endpoints at/above this level")
    p.add_argument("--fail-on", choices=list(SEV_ORDER),
                   help="exit code 2 if any endpoint is at/above this level (for CI)")
    p.add_argument("--format", "-f", choices=["text", "json", "md", "sarif", "html"], default="text")
    p.add_argument("--output", "-o", help="write report to a file instead of stdout")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--quiet", "-q", action="store_true", help="suppress live progress")
    p.add_argument("--version", "-V", action="version", version=f"mcpsweep {__version__}")
    return p


def _extract_targets(obj):
    """Pull target strings from a parsed JSON structure.

    Accepts, in order of preference:
      * a list of strings / objects with a "url" / "host" / "target" key
      * a {"targets": [...]} object
      * a prior mcpsweep report ({"endpoints": [{"url": ...}]}) to re-scan
      * an MCP client config ({"mcpServers": {name: {"url": ...}}}) — the format
        used by Claude Desktop / Cursor / Claude Code; stdio servers (no "url")
        are skipped since they are not HTTP-scannable.
    """
    def from_item(it):
        if isinstance(it, str):
            return it.strip()
        if isinstance(it, dict):
            return str(it.get("url") or it.get("host") or it.get("target") or "").strip()
        return ""

    if isinstance(obj, list):
        items = obj
    elif isinstance(obj, dict) and isinstance(obj.get("targets"), list):
        items = obj["targets"]
    elif isinstance(obj, dict) and isinstance(obj.get("endpoints"), list):
        items = obj["endpoints"]
    elif isinstance(obj, dict) and isinstance(obj.get("mcpServers"), dict):
        items = list(obj["mcpServers"].values())
    else:
        items = []
    return [t for t in (from_item(i) for i in items) if t]


def _read_target_file(path):
    with open(path, encoding="utf-8") as fh:
        raw = fh.read()
    if raw.lstrip()[:1] in "[{":                       # JSON array or object
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError as e:
            raise SystemExit(f"error: {path} looks like JSON but failed to parse: {e}")
        targets = _extract_targets(obj)
        # note stdio servers in an mcpServers config — they can't be HTTP-scanned
        if isinstance(obj, dict) and isinstance(obj.get("mcpServers"), dict):
            stdio = [n for n, c in obj["mcpServers"].items()
                     if isinstance(c, dict) and not c.get("url")]
            if stdio:
                print(f"note: skipped {len(stdio)} stdio MCP server(s) in {path} "
                      f"(not HTTP-scannable): {', '.join(stdio)}", file=sys.stderr)
        return targets
    # plain text: one target per line, '#' comments
    out = []
    for line in raw.splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.append(line)
    return out


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "diff":
        return diff_main(argv[1:])

    args = build_parser().parse_args(argv)
    targets = list(args.targets)
    if args.target_file:
        targets += _read_target_file(args.target_file)
    if not targets:
        if args.target_file:
            print(f"error: no scannable http/sse targets found in {args.target_file}",
                  file=sys.stderr)
        else:
            print("error: provide at least one target or --target-file", file=sys.stderr)
        return 2

    if args.no_color or args.format != "text" or not sys.stdout.isatty():
        C.disable()

    ports = parse_ports(args.ports)
    paths = [p if p.startswith("/") else "/" + p for p in args.paths.split(",") if p.strip()]
    schemes = ("http", "https") if args.scheme == "both" else (args.scheme,)
    exclude = {h.strip() for h in (args.exclude or "").split(",") if h.strip()}
    headers = _headers_from_args(args)
    scope = f"{','.join(targets)} ports={args.ports} scheme={args.scheme}"

    if not args.quiet and args.format == "text":
        print(f"{C.HEAD}mcpsweep {__version__}{C.Z}  targets={len(targets)}  ports={len(ports)}  "
              f"paths={len(paths)}  proxy={args.proxy or 'off'}  auth={'yes' if headers else 'no'}",
              file=sys.stderr)

    def live(ep: MCPEndpoint):
        if not args.quiet and args.format == "text":
            tag = LEVEL_COLOR.get(ep.risk_level, "")
            print(f"  {C.OK}found{C.Z} {ep.url}  {tag}{ep.risk_level}{C.Z}  "
                  f"({len(ep.tools)} tools)", file=sys.stderr)

    t0 = time.time()
    try:
        endpoints = scan(targets, ports, paths, schemes, proxy=args.proxy, timeout=args.timeout,
                         concurrency=args.concurrency, insecure=args.insecure, full=args.full,
                         headers=headers, exclude=exclude, on_found=live)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    elapsed = time.time() - t0

    if args.severity:
        thr = SEV_ORDER[args.severity]
        endpoints = [e for e in endpoints if SEV_ORDER.get(e.risk_level, 0) >= thr]

    if args.format == "json":
        out = render_json(endpoints, elapsed, scope)
    elif args.format == "md":
        out = render_markdown(endpoints, elapsed, scope)
    elif args.format == "sarif":
        out = _report.render_sarif(endpoints, scope)
    elif args.format == "html":
        out = _report.render_html(endpoints, scope, elapsed)
    else:
        out = render_console(endpoints, elapsed)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out + "\n")
        print(f"wrote {args.output} ({len(endpoints)} endpoints)", file=sys.stderr)
    else:
        print(out)

    if args.fail_on:
        thr = SEV_ORDER[args.fail_on]
        if any(SEV_ORDER.get(e.risk_level, 0) >= thr for e in endpoints):
            return 2
    return 0 if endpoints else 1


def diff_main(argv):
    p = argparse.ArgumentParser(prog="mcpsweep diff",
                                description="Compare two mcpsweep JSON reports (drift detection).")
    p.add_argument("old", help="older JSON report")
    p.add_argument("new", help="newer JSON report")
    p.add_argument("--format", "-f", choices=["text", "json"], default="text")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--fail-on-drift", action="store_true", help="exit 3 if any drift is found")
    a = p.parse_args(argv)
    d = _diff.diff_reports(a.old, a.new)
    if a.format == "json":
        print(json.dumps(d, indent=2))
    else:
        print(_diff.render_diff_text(d, color=not a.no_color and sys.stdout.isatty()))
    if a.fail_on_drift and _diff.has_drift(d):
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

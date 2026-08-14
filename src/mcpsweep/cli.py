"""Command-line interface for mcpsweep."""
from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from .scanner import (
    DEFAULT_PATHS, DEFAULT_PORTS, MCPEndpoint, parse_ports, scan,
)

# --- color -------------------------------------------------------------------

class C:
    HEAD = "\033[1;36m"; OK = "\033[1;32m"; WARN = "\033[1;33m"
    CRIT = "\033[1;31m"; DIM = "\033[0;90m"; BOLD = "\033[1m"; Z = "\033[0m"

    @classmethod
    def disable(cls):
        for k in ("HEAD", "OK", "WARN", "CRIT", "DIM", "BOLD", "Z"):
            setattr(cls, k, "")


LEVEL_COLOR = {"critical": C.CRIT, "high": C.WARN, "medium": C.WARN, "low": C.DIM, "info": C.DIM}


# --- renderers ---------------------------------------------------------------

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
            if ep.capabilities:
                out.append(f"    {C.DIM}caps    :{C.Z} {', '.join(ep.capabilities)}")
            if ep.session_id:
                out.append(f"    {C.DIM}session :{C.Z} {ep.session_id} "
                           f"{C.DIM}(correlator, not auth){C.Z}")
            if ep.instructions:
                snippet = ep.instructions[:160] + ("…" if len(ep.instructions) > 160 else "")
                out.append(f"    {C.DIM}notes   :{C.Z} {snippet}")
            out.append(f"    {C.DIM}tools   :{C.Z} {len(ep.tools)}")
            for t in ep.tools:
                tagstr = f" {C.DIM}[{','.join(t.tags)}]{C.Z}" if t.tags else ""
                flag = f"  {C.CRIT}<-- DESCRIPTION LOOKS POISONED{C.Z}" if t.poisoned else ""
                out.append(f"      - {t.name}{tagstr}{flag}")
            if ep.resources:
                out.append(f"    {C.DIM}resources:{C.Z} {len(ep.resources)} "
                           f"({', '.join(ep.resources[:5])})")
            if ep.prompts:
                out.append(f"    {C.DIM}prompts :{C.Z} {len(ep.prompts)} "
                           f"({', '.join(ep.prompts[:5])})")
        for f in ep.findings:
            mark = C.CRIT if ("poison" in f.lower() or "high-impact" in f.lower()) else C.WARN
            if "requires authentication" in f.lower():
                mark = C.OK
            out.append(f"    {mark}![{C.Z} {f}")
    crit = sum(1 for e in endpoints if e.risk_level == "critical")
    out.append(f"\n{C.HEAD}== {len(endpoints)} endpoint(s) in {elapsed:.1f}s "
               f"({crit} critical) =={C.Z}")
    return "\n".join(out)


def render_json(endpoints, elapsed, scope):
    return json.dumps({
        "tool": "mcpsweep", "version": __version__,
        "scope": scope, "elapsed_s": round(elapsed, 2),
        "endpoint_count": len(endpoints),
        "endpoints": [e.to_dict() for e in endpoints],
    }, indent=2)


def render_markdown(endpoints, elapsed, scope):
    L = [f"# MCP discovery report", "",
         f"- **scope:** `{scope}`",
         f"- **endpoints found:** {len(endpoints)}",
         f"- **scan time:** {elapsed:.1f}s", "",
         "| Endpoint | Server | Risk | Tools | Notable |",
         "|---|---|---|---|---|"]
    for ep in endpoints:
        notable = []
        if ep.auth_required:
            notable.append("auth required")
        if any(t.poisoned for t in ep.tools):
            notable.append("poisoned tool desc")
        dangerous = sorted({tag for t in ep.tools for tag in t.tags
                            if tag in ("rce", "sql", "money", "destructive", "secret")})
        notable.extend(dangerous)
        L.append(f"| `{ep.url}` | {ep.server_name} v{ep.server_version} | "
                 f"{ep.risk_level} ({ep.risk_score}) | {len(ep.tools)} | "
                 f"{', '.join(notable) or '—'} |")
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
            L.append("")
            L.append("| Tool | Risk tags | Poisoned |")
            L.append("|---|---|---|")
            for t in ep.tools:
                L.append(f"| `{t.name}` | {', '.join(t.tags) or '—'} | "
                         f"{'⚠️ yes' if t.poisoned else 'no'} |")
        L.append("")
    return "\n".join(L)


# --- entrypoint --------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        prog="mcpsweep",
        description="Discover and fingerprint MCP-over-HTTP servers, enumerate their "
                    "tools, and flag risky or poisoned ones. Read-only (never calls a tool).",
        epilog="example: mcpsweep 10.10.0.31 --ports 8090 --proxy http://127.0.0.1:8080",
    )
    p.add_argument("targets", nargs="+", help="host(s) or CIDR block(s), e.g. 10.10.0.31 or 10.10.0.0/28")
    p.add_argument("--ports", default=",".join(map(str, DEFAULT_PORTS)),
                   help="ports/ranges, e.g. '8090,8000,9000-9010' (default: common MCP ports)")
    p.add_argument("--paths", default=",".join(DEFAULT_PATHS),
                   help="comma-separated URL paths to probe")
    p.add_argument("--scheme", choices=["http", "https", "both"], default="http")
    p.add_argument("--proxy", help="route all traffic through a proxy, e.g. http://127.0.0.1:8080 (Burp)")
    p.add_argument("--insecure", "-k", action="store_true", help="skip TLS verification (for https)")
    p.add_argument("--timeout", type=float, default=8.0, help="per-request timeout seconds (default 8)")
    p.add_argument("--concurrency", "-c", type=int, default=16, help="parallel probes (default 16)")
    p.add_argument("--full", action="store_true", help="also enumerate resources and prompts")
    p.add_argument("--format", "-f", choices=["text", "json", "md"], default="text")
    p.add_argument("--output", "-o", help="write report to a file instead of stdout")
    p.add_argument("--no-color", action="store_true", help="disable ANSI color")
    p.add_argument("--quiet", "-q", action="store_true", help="suppress live progress")
    p.add_argument("--version", "-V", action="version", version=f"mcpsweep {__version__}")
    return p


def main(argv=None):
    import time
    args = build_parser().parse_args(argv)

    if args.no_color or args.format != "text" or not sys.stdout.isatty():
        C.disable()

    ports = parse_ports(args.ports)
    paths = [p if p.startswith("/") else "/" + p for p in args.paths.split(",") if p.strip()]
    schemes = ("http", "https") if args.scheme == "both" else (args.scheme,)
    scope = f"{','.join(args.targets)} ports={args.ports} scheme={args.scheme}"

    if not args.quiet and args.format == "text":
        print(f"{C.HEAD}mcpsweep {__version__}{C.Z}  targets={','.join(args.targets)}  "
              f"ports={len(ports)}  paths={len(paths)}  "
              f"proxy={args.proxy or 'off'}", file=sys.stderr)

    def live(ep: MCPEndpoint):
        if not args.quiet and args.format == "text":
            tag = LEVEL_COLOR.get(ep.risk_level, "")
            print(f"  {C.OK}found{C.Z} {ep.url}  "
                  f"{tag}{ep.risk_level}{C.Z}  ({len(ep.tools)} tools)", file=sys.stderr)

    t0 = time.time()
    try:
        endpoints = scan(
            args.targets, ports, paths, schemes,
            proxy=args.proxy, timeout=args.timeout, concurrency=args.concurrency,
            insecure=args.insecure, full=args.full, on_found=live,
        )
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    elapsed = time.time() - t0

    if args.format == "json":
        report = render_json(endpoints, elapsed, scope)
    elif args.format == "md":
        report = render_markdown(endpoints, elapsed, scope)
    else:
        report = render_console(endpoints, elapsed)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report + "\n")
        print(f"wrote {args.output} ({len(endpoints)} endpoints)", file=sys.stderr)
    else:
        print(report)

    return 0 if endpoints else 1


if __name__ == "__main__":
    raise SystemExit(main())

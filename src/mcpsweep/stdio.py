"""Scan stdio-transport MCP servers by spawning them and speaking JSON-RPC
over their stdin/stdout pipes.

Spawning a server runs third-party code, so callers must opt in explicitly; the
CLI gates this behind ``--yes-run-untrusted``. Reads happen on a background
thread with a deadline (Windows has no ``select`` on pipes). MCP's stdio framing
is newline-delimited JSON-RPC; the server's own logs go to stderr, which we drain
separately so they can't corrupt parsing.
"""
from __future__ import annotations

import json
import os
import queue
import shutil
import subprocess
import threading
import time

from .scanner import MCPEndpoint, POISON_RE, PROTOCOL_VERSION, _analyze_tool, _score


def _resolve_argv(spec):
    cmd = spec.get("command")
    if not cmd:
        return None
    args = list(spec.get("args") or [])
    exe = shutil.which(cmd)
    if exe is None and os.name == "nt":              # npx -> npx.cmd, etc.
        exe = shutil.which(cmd + ".cmd") or shutil.which(cmd + ".exe")
    return [exe or cmd] + args


class _StdioClient:
    def __init__(self, argv, env, cwd, timeout):
        self.timeout = timeout
        self.p = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1, env=env, cwd=cwd,
        )
        self.q = queue.Queue()
        threading.Thread(target=self._pump, args=(self.p.stdout,), daemon=True).start()
        threading.Thread(target=self._drain, args=(self.p.stderr,), daemon=True).start()

    def _pump(self, stream):
        try:
            for line in stream:
                self.q.put(line)
        except Exception:
            pass
        self.q.put(None)

    def _drain(self, stream):                         # discard server logs
        try:
            for _ in stream:
                pass
        except Exception:
            pass

    def request(self, method, params, rid):
        self._write({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            try:
                line = self.q.get(timeout=0.5)
            except queue.Empty:
                continue
            if line is None:
                return None
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                continue                              # non-JSON noise on stdout
            if isinstance(msg, dict) and msg.get("id") == rid:
                return msg
        return None

    def notify(self, method, params=None):
        self._write({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def _write(self, obj):
        try:
            self.p.stdin.write(json.dumps(obj) + "\n")
            self.p.stdin.flush()
        except (BrokenPipeError, ValueError, OSError):
            pass

    def close(self):
        for fn in (lambda: self.p.stdin.close(), self.p.terminate):
            try:
                fn()
            except Exception:
                pass
        try:
            self.p.wait(timeout=3)
        except Exception:
            try:
                self.p.kill()
            except Exception:
                pass


def probe_stdio(spec, timeout=20.0, full=False):
    """Spawn one stdio MCP server and return an enumerated MCPEndpoint (or None).

    ``spec`` = {"command": str, "args": [str], "env": {..}, "cwd": str, "name": str}.
    """
    from . import __version__
    argv = _resolve_argv(spec)
    if not argv:
        return None
    env = {**os.environ, **{k: str(v) for k, v in (spec.get("env") or {}).items()}}
    display = spec.get("name") or " ".join([str(spec.get("command", ""))] + list(spec.get("args") or []))

    try:
        cli = _StdioClient(argv, env, spec.get("cwd"), timeout)
    except (FileNotFoundError, OSError):
        return None
    try:
        init = cli.request("initialize", {
            "protocolVersion": PROTOCOL_VERSION, "capabilities": {},
            "clientInfo": {"name": "mcpsweep", "version": __version__},
        }, 1)
        if not isinstance(init, dict) or not isinstance(init.get("result"), dict):
            return None
        res = init["result"]
        si = res.get("serverInfo", {}) or {}
        instr = (res.get("instructions") or "").replace("\n", " ").strip()
        ep = MCPEndpoint(
            url=f"stdio://{display}", host="(local)", port=0, path="", scheme="stdio",
            transport="stdio", server_name=si.get("name", "?"),
            server_version=si.get("version", "?"), protocol=res.get("protocolVersion", "?"),
            capabilities=list((res.get("capabilities") or {}).keys()),
            instructions=instr, instructions_poisoned=bool(POISON_RE.search(instr)),
        )
        ep.command = argv
        ep.findings.append("stdio server executes local code - supply-chain risk (MCP04)")

        cli.notify("notifications/initialized")
        tl = cli.request("tools/list", {}, 2)
        for t in (tl or {}).get("result", {}).get("tools", []) if tl else []:
            ep.tools.append(_analyze_tool(t))
        if full:
            rl = cli.request("resources/list", {}, 3)
            ep.resources = [r.get("uri", r.get("name", "?"))
                            for r in ((rl or {}).get("result", {}).get("resources", []) if rl else [])]
            pl = cli.request("prompts/list", {}, 4)
            ep.prompts = [p.get("name", "?")
                          for p in ((pl or {}).get("result", {}).get("prompts", []) if pl else [])]
        _score(ep)
        return ep
    finally:
        cli.close()

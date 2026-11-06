"""Static lint of local MCP client configuration files.

Reads a client config (``claude_desktop_config.json``, ``.cursor/mcp.json``,
VS Code / Windsurf / Zed ``mcp.json``, ...) and flags dangerous stdio server
definitions - the OX Security "config-to-command" family (CVE-2026-30623/24/25,
26015, 40933, ...) and plaintext secrets in ``env``.

Purely local and read-only: it parses the file and NEVER launches a server.
"""
from __future__ import annotations

import json
import re

_SECRET_KEY_RE = re.compile(r"(?i)(token|secret|password|passwd|api[_-]?key|apikey|"
                            r"access[_-]?key|private[_-]?key|client[_-]?secret)")
_SECRET_VAL_RE = re.compile(r"(?i)(ghp_[A-Za-z0-9]{20,}|xox[baprs]-|AKIA[0-9A-Z]{16}|"
                            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|sk-[A-Za-z0-9]{16,})")
_PLACEHOLDER_RE = re.compile(r"^\s*(\$\{[^}]+\}|\$[A-Z_]+|<[^>]+>|your[_-]|changeme|xxx+|\.\.\.)",
                             re.I)


def _servers(cfg):
    """Yield (name, entry) for each configured server across common schemas."""
    for key in ("mcpServers", "servers", "mcp"):
        block = cfg.get(key)
        if isinstance(block, dict):
            for name, entry in block.items():
                if isinstance(entry, dict):
                    yield name, entry
        elif isinstance(block, list):
            for entry in block:
                if isinstance(entry, dict):
                    yield entry.get("name", "?"), entry


def _lint_command(name, command, args):
    out = []
    argv = ([command] if command else []) + [str(a) for a in (args or [])]
    joined = " ".join(argv)
    low = joined.lower()
    base = (command or "").rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()

    if base in ("sh", "bash", "zsh", "cmd", "cmd.exe", "powershell", "pwsh") and \
            any(a in ("-c", "/c", "-command", "-e") for a in (args or [])):
        out.append(("config-lint", f"{name}: launches a shell with an inline command "
                                    f"({base} -c ...) - arbitrary execution surface"))
    if re.search(r"(curl|wget)\b", low) and re.search(r"\|\s*(sh|bash)", low):
        out.append(("config-lint", f"{name}: pipes a download straight into a shell (curl|sh)"))
    if base in ("npx", "npx.cmd") and "-y" in (args or []):
        pkgs = [a for a in (args or []) if not a.startswith("-")]
        unpinned = [p for p in pkgs if "@" not in p.lstrip("@").replace("/", "")]
        if unpinned:
            out.append(("config-lint", f"{name}: `npx -y` runs an UNPINNED package "
                                       f"({', '.join(unpinned)}) - supply-chain / typosquat risk"))
    if base in ("uvx", "uv") and not re.search(r"==|@", joined):
        pkgs = [a for a in (args or []) if not a.startswith("-")]
        if pkgs:
            out.append(("config-lint", f"{name}: `{base}` runs an unpinned package "
                                       f"({pkgs[0]}) - supply-chain risk"))
    if any(a in ("-e", "--eval", "-c", "--exec") for a in (args or [])) and base in (
            "node", "python", "python3", "deno", "ruby", "perl"):
        out.append(("config-lint", f"{name}: interpreter runs inline code "
                                    f"({base} {' '.join(a for a in (args or []) if a.startswith('-'))})"))
    return out


def _lint_env(name, env):
    out = []
    if not isinstance(env, dict):
        return out
    for k, v in env.items():
        if not isinstance(v, str) or not v.strip() or _PLACEHOLDER_RE.search(v):
            continue
        if _SECRET_VAL_RE.search(v) or _SECRET_KEY_RE.search(k):
            out.append(("config-lint", f"{name}: plaintext secret in env ('{k}') - "
                                        f"move it to a secret store / env var reference"))
    return out


def lint_config(path):
    """Return a list of {server, class, detail} findings for one config file."""
    with open(path, encoding="utf-8") as fh:
        cfg = json.load(fh)
    findings = []
    for name, entry in _servers(cfg):
        command = entry.get("command")
        args = entry.get("args")
        for cls, detail in _lint_command(name, command, args):
            findings.append({"server": name, "class": cls, "detail": detail})
        for cls, detail in _lint_env(name, entry.get("env")):
            findings.append({"server": name, "class": cls, "detail": detail})
        url = entry.get("url") or entry.get("serverUrl") or ""
        if isinstance(url, str) and url.startswith("http://") and \
                not re.search(r"://(localhost|127\.0\.0\.1)", url):
            findings.append({"server": name, "class": "config-lint",
                             "detail": f"{name}: plaintext http:// remote MCP URL "
                                       f"(credentials/traffic exposed): {url}"})
    return findings

# Changelog

## 0.2.0

**Targets & auth**
- Accept full **URLs** as targets (probe an exact endpoint), plus `--target-file`/`-iL` and `--exclude`.
- `--header`/`-H` and `--bearer` for scanning servers that require authentication.

**Deeper analysis**
- Prompt-injection / poisoning detection now also covers server `instructions`, prompt templates, and resource listings.
- **Injection-surface** detection: high-impact tools that take a free-form string parameter.
- **HTTP fingerprint** (`Server` / `X-Powered-By`) and server-name risk hints.

**Reporting & CI**
- New output formats: **SARIF** (GitHub code-scanning) and self-contained **HTML**.
- `--severity` filter and `--fail-on` exit-code gate.

**Drift detection**
- New `mcpsweep diff old.json new.json` subcommand — new/removed servers & tools, newly-poisoned descriptions, risk-level changes; `--fail-on-drift` exits `3`.

## 0.1.0

- Initial release: MCP-over-HTTP discovery, `initialize` fingerprinting, tool enumeration, risk heuristics, text/JSON/Markdown output, proxy support, transient-error retries.

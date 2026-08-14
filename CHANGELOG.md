# Changelog

## [0.3.0](https://github.com/krishnareddypadala/mcpsweep/compare/v0.2.0...v0.3.0) (2026-08-14)


### Features

* accept JSON target files (array, {targets:[...]}, or a prior report) ([4fdfe05](https://github.com/krishnareddypadala/mcpsweep/commit/4fdfe054026d2df86a491604238355f6f2655e1b))
* add -v/--verbose to explain why probes miss ([855b469](https://github.com/krishnareddypadala/mcpsweep/commit/855b4693f46d537e3266d754b12cf477e1bd4d34))
* read targets from an MCP client config (mcpServers) ([d880b82](https://github.com/krishnareddypadala/mcpsweep/commit/d880b82e94c6dd1726ae5464f85eeec9816b3e02))


### Bug Fixes

* commit release-please config that .gitignore was hiding ([8a48248](https://github.com/krishnareddypadala/mcpsweep/commit/8a48248ce3495107356cfdb0c1232954720d94a1))

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

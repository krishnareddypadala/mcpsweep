# Changelog

## [0.3.0](https://github.com/krishnareddypadala/mcpsweep/compare/v0.2.0...v0.3.0) (2026-09-01)


### Features

* --active authz probing (0.8.0) ([92114b3](https://github.com/krishnareddypadala/mcpsweep/commit/92114b3a23d8596f934698d0406a444855b0accc))
* accept JSON target files (array, {targets:[...]}, or a prior report) ([4fdfe05](https://github.com/krishnareddypadala/mcpsweep/commit/4fdfe054026d2df86a491604238355f6f2655e1b))
* add -v/--verbose to explain why probes miss ([855b469](https://github.com/krishnareddypadala/mcpsweep/commit/855b4693f46d537e3266d754b12cf477e1bd4d34))
* baseline / policy file (0.7.0) ([a70c2c8](https://github.com/krishnareddypadala/mcpsweep/commit/a70c2c85afdd48fe50c93581ad6a270263afb0d7))
* deep surface analysis (0.6.0) ([35a9451](https://github.com/krishnareddypadala/mcpsweep/commit/35a9451c2ce8b136c0c2d14dd716020523096b49))
* OAuth / auth-spec detection (0.5.0) ([5ae7d0d](https://github.com/krishnareddypadala/mcpsweep/commit/5ae7d0d549624276e95cc935836d146dbe00fb88))
* read targets from an MCP client config (mcpServers) ([d880b82](https://github.com/krishnareddypadala/mcpsweep/commit/d880b82e94c6dd1726ae5464f85eeec9816b3e02))
* scan stdio MCP servers (0.4.0) ([747a0e1](https://github.com/krishnareddypadala/mcpsweep/commit/747a0e13509bc9bcd4ddf6f8edcd1433995c4c11))


### Bug Fixes

* commit release-please config that .gitignore was hiding ([8a48248](https://github.com/krishnareddypadala/mcpsweep/commit/8a48248ce3495107356cfdb0c1232954720d94a1))
* dedupe trailing-slash/twin endpoints and report real version in handshake ([8effa45](https://github.com/krishnareddypadala/mcpsweep/commit/8effa45094ccfe32c97b3b34a3a3c89fc9fe451a))


### Documentation

* add 0.4-0.8 roadmap (stdio, oauth, deep vuln analysis, baseline, active) ([a8542fb](https://github.com/krishnareddypadala/mcpsweep/commit/a8542fbfcfacc86aa441bf365629535e06239141))
* mark roadmap 0.4-0.8 as shipped ([5d376ce](https://github.com/krishnareddypadala/mcpsweep/commit/5d376ce4a0013d8c65fe6c09d970e775bbbcbf68))

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

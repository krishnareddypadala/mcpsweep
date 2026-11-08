# Changelog

## [1.0.1](https://github.com/krishnareddypadala/mcpsweep/compare/v1.0.0...v1.0.1) (2026-11-07)


### Bug Fixes

* **transport:** only flag lan-exposure for private/LAN-scoped hosts ([#12](https://github.com/krishnareddypadala/mcpsweep/issues/12)) ([0d3fa5f](https://github.com/krishnareddypadala/mcpsweep/commit/0d3fa5f16d41a0bbc831b36d964b494cbe7f40c0))

## [1.0.0](https://github.com/krishnareddypadala/mcpsweep/compare/v0.2.0...v1.0.0) (2026-11-07)


### Features

* --active authz probing (0.8.0) ([92114b3](https://github.com/krishnareddypadala/mcpsweep/commit/92114b3a23d8596f934698d0406a444855b0accc))
* accept JSON target files (array, {targets:[...]}, or a prior report) ([4fdfe05](https://github.com/krishnareddypadala/mcpsweep/commit/4fdfe054026d2df86a491604238355f6f2655e1b))
* add -v/--verbose to explain why probes miss ([855b469](https://github.com/krishnareddypadala/mcpsweep/commit/855b4693f46d537e3266d754b12cf477e1bd4d34))
* baseline / policy file (0.7.0) ([a70c2c8](https://github.com/krishnareddypadala/mcpsweep/commit/a70c2c85afdd48fe50c93581ad6a270263afb0d7))
* deep surface analysis (0.6.0) ([35a9451](https://github.com/krishnareddypadala/mcpsweep/commit/35a9451c2ce8b136c0c2d14dd716020523096b49))
* full-schema poisoning, hidden-character detection, rug-pull diff ([ba89b66](https://github.com/krishnareddypadala/mcpsweep/commit/ba89b669518f3eaa065821520bd04514bec7b064))
* OAuth / auth-spec detection (0.5.0) ([5ae7d0d](https://github.com/krishnareddypadala/mcpsweep/commit/5ae7d0d549624276e95cc935836d146dbe00fb88))
* offline known-vulnerable version matching (bundled advisory DB) ([63961cf](https://github.com/krishnareddypadala/mcpsweep/commit/63961cfb355b7750e40a13512187351a60d6aa32))
* passive OAuth metadata hygiene + SSRF self-protection ([e531844](https://github.com/krishnareddypadala/mcpsweep/commit/e5318448b0466d190ceee3b01bd990fac2194bcf))
* point PyPI metadata at mcpsweep.com and cut 1.0.0 ([#10](https://github.com/krishnareddypadala/mcpsweep/issues/10)) ([b84b639](https://github.com/krishnareddypadala/mcpsweep/commit/b84b6392dca69b73d81ffe115eae07e3f3665ec2))
* read targets from an MCP client config (mcpServers) ([d880b82](https://github.com/krishnareddypadala/mcpsweep/commit/d880b82e94c6dd1726ae5464f85eeec9816b3e02))
* scan stdio MCP servers (0.4.0) ([747a0e1](https://github.com/krishnareddypadala/mcpsweep/commit/747a0e13509bc9bcd4ddf6f8edcd1433995c4c11))
* static config lint (lint-config subcommand) ([ac295cc](https://github.com/krishnareddypadala/mcpsweep/commit/ac295cc0d2f54e6cdbe3500687f9da671d1ff7c5))
* support modern stateless MCP (server/discover, spec 2026-07-28) ([bd25241](https://github.com/krishnareddypadala/mcpsweep/commit/bd25241282559f7e9a00946dd3f5cc5178224ef0))
* tool shadowing, weak session-id, plaintext-http-auth, unauth tasks/* probe ([f9e33c9](https://github.com/krishnareddypadala/mcpsweep/commit/f9e33c94a532be874ab50cdbca426cf61c551e76))
* toxic-flow tagging (sensitive-data source + egress on one server) ([7056bff](https://github.com/krishnareddypadala/mcpsweep/commit/7056bffc61cf46fd5687c568303374ad0c7bc744))
* transport-security probes (DNS-rebinding, CORS, LAN exposure, sibling-auth gap) ([665275e](https://github.com/krishnareddypadala/mcpsweep/commit/665275eb5f422df4997f0f2d751ecb0d6388f702))


### Bug Fixes

* commit release-please config that .gitignore was hiding ([8a48248](https://github.com/krishnareddypadala/mcpsweep/commit/8a48248ce3495107356cfdb0c1232954720d94a1))
* dedupe trailing-slash/twin endpoints and report real version in handshake ([8effa45](https://github.com/krishnareddypadala/mcpsweep/commit/8effa45094ccfe32c97b3b34a3a3c89fc9fe451a))
* don't flag a server's own internal address as OAuth SSRF ([ac7d387](https://github.com/krishnareddypadala/mcpsweep/commit/ac7d387d426d8a0b08837d689adb2871ccf7a79f))
* **vulnlab:** correct host-validation and per-endpoint OAuth metadata ([d6019ca](https://github.com/krishnareddypadala/mcpsweep/commit/d6019ca4576baf123126ad0a35312c5b0c644cbb))


### Documentation

* add 0.4-0.8 roadmap (stdio, oauth, deep vuln analysis, baseline, active) ([a8542fb](https://github.com/krishnareddypadala/mcpsweep/commit/a8542fbfcfacc86aa441bf365629535e06239141))
* mark roadmap 0.4-0.8 as shipped ([5d376ce](https://github.com/krishnareddypadala/mcpsweep/commit/5d376ce4a0013d8c65fe6c09d970e775bbbcbf68))
* open-source product website + GitHub Pages deploy ([e98662b](https://github.com/krishnareddypadala/mcpsweep/commit/e98662b4be8bcd5b0aa61a91aa5dfb6d7b0fef7f))
* record vulnlab deployment (co-located compose, live on lab net) ([a28fb9f](https://github.com/krishnareddypadala/mcpsweep/commit/a28fb9f3d9b60e4bd3127c05c304cd4a1000fcbf))
* v1.0 coverage map, README rewrite, vulnlab packaging ([e4642ce](https://github.com/krishnareddypadala/mcpsweep/commit/e4642ce26464aab58e796ce3fdeb1b20940ae1db))

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
- New `mcpsweep diff old.json new.json` subcommand - new/removed servers & tools, newly-poisoned descriptions, risk-level changes; `--fail-on-drift` exits `3`.

## 0.1.0

- Initial release: MCP-over-HTTP discovery, `initialize` fingerprinting, tool enumeration, risk heuristics, text/JSON/Markdown output, proxy support, transient-error retries.

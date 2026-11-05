"""Integration tests for mcpsweep v1.0 features, driven by the vulnlab server.

Spins up the deliberately-vulnerable ``vulnlab`` MCP server on an ephemeral
port and asserts that mcpsweep detects each modelled issue (and that clean
control endpoints stay clean).
"""
import contextlib
import threading

import pytest

from mcpsweep import scan

vulnlab = pytest.importorskip("vulnlab")


@contextlib.contextmanager
def running_vulnlab():
    srv = vulnlab.build_server("127.0.0.1", 0)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield port
    finally:
        srv.shutdown()


def _scan_path(port, path, **kw):
    eps = scan([f"http://127.0.0.1:{port}{path}"], ports=[port], **kw)
    assert eps, f"no endpoint found at {path}"
    return eps[0]


def _findings(ep):
    return " || ".join(ep.findings + [str(f) for f in ep.transport_findings])


# --- Tier 0: protocol modernization ----------------------------------------

def test_legacy_initialize_still_works():
    with running_vulnlab() as port:
        ep = _scan_path(port, "/mcp/noauth")
        assert ep.protocol == "2024-11-05"
        assert ep.protocol_era == "legacy"
        assert any(t.name == "run-shell-command" for t in ep.tools)


def test_modern_server_discover_fingerprint():
    """A modern-only server rejects initialize; mcpsweep must fall back to server/discover."""
    with running_vulnlab() as port:
        ep = _scan_path(port, "/mcp/modern")
        assert ep.protocol == "2026-07-28"
        assert ep.protocol_era == "modern"
        assert ep.discover_used is True
        assert ep.supported_versions == ["2026-07-28"]
        assert ep.cache_scope == "public"
        # enumeration over the modern transport still works
        assert any(t.name == "run-sql" for t in ep.tools)


def test_dual_era_detection():
    with running_vulnlab() as port:
        ep = _scan_path(port, "/mcp/dual")
        assert ep.protocol_era == "dual"
        assert "dual-era" in _findings(ep)


def test_modern_and_legacy_not_merged_by_dedupe():
    with running_vulnlab() as port:
        eps = scan(["127.0.0.1"], ports=[port],
                   paths=["/mcp/noauth", "/mcp/modern"])
        eras = sorted({e.protocol_era for e in eps})
        assert eras == ["legacy", "modern"], f"dedupe merged distinct eras: {eras}"


# --- Tier 1: transport-security probes -------------------------------------

def _classes(ep):
    return {tf["class"] for tf in ep.transport_findings}


def test_dns_rebinding_flagged_when_host_not_validated():
    with running_vulnlab() as port:
        ep = _scan_path(port, "/mcp/noauth")
        assert "dns-rebinding" in _classes(ep)


def test_dns_rebinding_not_flagged_when_validated():
    with running_vulnlab() as port:
        ep = _scan_path(port, "/mcp/safe")   # validates Host/Origin AND requires auth
        assert "dns-rebinding" not in _classes(ep)


def test_cors_reflect_credentials_flagged():
    with running_vulnlab() as port:
        ep = _scan_path(port, "/mcp/noauth")
        assert {"cors-reflect-credentials"} & _classes(ep)


def test_cors_clean_on_strict_endpoint():
    with running_vulnlab() as port:
        ep = _scan_path(port, "/mcp/safe")
        assert not ({"cors-wildcard", "cors-reflect", "cors-reflect-credentials"} & _classes(ep))


def test_sibling_endpoint_auth_gap():
    with running_vulnlab() as port:
        eps = scan(["127.0.0.1"], ports=[port], paths=["/mcp", "/mcp_message"])
        gap = [e for e in eps if "sibling-endpoint-auth-gap" in _classes(e)]
        assert gap and all(e.path == "/mcp_message" for e in gap)


def test_loopback_not_flagged_as_lan_exposure():
    with running_vulnlab() as port:
        ep = _scan_path(port, "/mcp/noauth")
        assert "lan-exposure" not in _classes(ep)   # 127.0.0.1 is loopback


def test_is_loopback_helper():
    from mcpsweep.transport import _is_loopback
    assert _is_loopback("127.0.0.1") and _is_loopback("localhost") and _is_loopback("::1")
    assert not _is_loopback("10.10.0.31") and not _is_loopback("0.0.0.0")


# --- Tier 1: passive OAuth hygiene -----------------------------------------

def test_unsafe_target_helper():
    from mcpsweep.authmeta import _unsafe_target
    assert _unsafe_target("http://169.254.169.254/latest")        # cloud metadata
    assert _unsafe_target("http://10.0.0.5/as")                   # private
    assert _unsafe_target("javascript:alert(1)")                  # bad scheme
    assert _unsafe_target("http://127.0.0.1:9100/as") is None     # loopback is OK
    assert _unsafe_target("https://auth.example.com/as") is None  # public is OK


def test_oauth_metadata_ssrf_flagged_and_not_followed(monkeypatch):
    monkeypatch.setenv("VULNLAB_OAUTH_SSRF", "1")
    with running_vulnlab() as port:
        eps = scan(["127.0.0.1"], ports=[port], paths=["/mcp/oauth-ssrf"], auth_probe=True)
        assert eps
        ep = eps[0]
        hy = " ".join((ep.auth or {}).get("hygiene", []))
        assert "169.254.169.254" in hy and "link-local" in hy
        assert any(f.startswith("oauth-hygiene:") for f in ep.findings)

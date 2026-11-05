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

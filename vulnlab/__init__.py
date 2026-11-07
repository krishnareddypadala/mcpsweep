"""mcpsweep vulnlab - a deliberately-vulnerable MCP server for testing mcpsweep.

INTENTIONALLY INSECURE. Isolated lab use only.
"""
from .server import SCENARIOS, build_server, main  # noqa: F401

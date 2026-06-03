"""Tests for MCP server audit checks (OC-MCP-*)."""

from .conftest import scan_fixture


def test_unpinned_mcp_flagged():
    v = scan_fixture("mcp/unpinned")
    assert v.failed("OC-MCP-002"), "unpinned @latest MCP server not flagged"


def test_unpinned_mcp_public_source_flagged():
    v = scan_fixture("mcp/unpinned")
    assert v.failed("OC-MCP-005"), "public-registry MCP source not flagged"


def test_pinned_mcp_clean():
    v = scan_fixture("mcp/pinned")
    assert not v.failed("OC-MCP-002"), "pinned MCP server wrongly flagged as unpinned"
    # Has env GITHUB_TOKEN, so auth should pass
    assert not v.failed("OC-MCP-001"), "MCP with env token wrongly flagged as no-auth"


def test_injection_in_tool_description_flagged():
    v = scan_fixture("mcp/injection-desc")
    assert v.failed("OC-MCP-004"), "injection in MCP tool description not detected"

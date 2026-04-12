"""Smoke tests for the MCP server wrappers in :mod:`kibana_agent.server`.

FastMCP's ``@mcp.tool()`` decorator returns the original function unchanged,
so we can call the registered tool functions directly without going through
the JSON-RPC envelope.
"""

from __future__ import annotations

from typing import Any

import pytest

from kibana_agent import client, server
from kibana_agent.client import ProfileNotFoundError

FAKE_PROFILE: dict[str, Any] = {
    "kibana_url": "https://kibana.example.com",
    "auth": {"type": "plain", "username": "alice", "password": "s3cret"},
    "index": "logs-*",
}


def test_search_logs_happy_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(client, "resolve_profile", lambda name=None: FAKE_PROFILE)

    captured: dict[str, Any] = {}

    def fake_op_search(profile: dict[str, Any], idx: str, **kwargs: Any) -> dict[str, Any]:
        captured["profile"] = profile
        captured["idx"] = idx
        captured["kwargs"] = kwargs
        return {"total": 3, "n": 3, "hits": [{"msg": "x"}, {"msg": "y"}, {"msg": "z"}]}

    monkeypatch.setattr(client, "op_search", fake_op_search)

    result = server.search_logs(
        index_pattern="logs-*",
        last="2h",
        kql="level:ERROR",
        size=3,
    )
    assert result == {
        "total": 3,
        "n": 3,
        "hits": [{"msg": "x"}, {"msg": "y"}, {"msg": "z"}],
    }
    assert captured["idx"] == "logs-*"
    assert captured["kwargs"]["time_range"] == "2h"
    assert captured["kwargs"]["kql"] == "level:ERROR"
    assert captured["kwargs"]["size"] == 3


def test_search_logs_uses_default_index_from_profile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(client, "resolve_profile", lambda name=None: FAKE_PROFILE)
    captured: dict[str, Any] = {}

    def fake_op_search(profile: dict[str, Any], idx: str, **_: Any) -> dict[str, Any]:
        captured["idx"] = idx
        return {"total": 0, "n": 0, "hits": []}

    monkeypatch.setattr(client, "op_search", fake_op_search)
    server.search_logs()
    assert captured["idx"] == "logs-*"


def test_profile_not_found_returns_structured_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(name: str | None = None) -> dict[str, Any]:
        raise ProfileNotFoundError("no profile here")

    monkeypatch.setattr(client, "resolve_profile", boom)

    result = server.search_logs(index_pattern="logs-*")
    assert result == {"error": "no profile here", "type": "ProfileNotFoundError"}


def test_count_documents_wraps_int_in_dict(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(client, "resolve_profile", lambda name=None: FAKE_PROFILE)
    monkeypatch.setattr(client, "op_count", lambda *a, **k: 17)

    result = server.count_documents(index_pattern="logs-*", last="30m")
    assert result == {"count": 17, "index": "logs-*", "last": "30m"}


def test_list_profiles_returns_dict(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        client,
        "op_list_profiles",
        lambda: [{"name": "prd", "active": True, "kibana_url": "https://x"}],
    )
    result = server.list_profiles()
    assert result == {
        "profiles": [{"name": "prd", "active": True, "kibana_url": "https://x"}]
    }


def test_tail_logs_passes_cursor(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(client, "resolve_profile", lambda name=None: FAKE_PROFILE)
    captured: dict[str, Any] = {}

    def fake_tail_page(profile: dict[str, Any], idx: str, **kwargs: Any) -> dict[str, Any]:
        captured.update(kwargs)
        return {"hits": [], "next_cursor": [99, "z"]}

    monkeypatch.setattr(client, "op_tail_page", fake_tail_page)
    result = server.tail_logs(since_cursor=[42, "y"])
    assert result["next_cursor"] == [99, "z"]
    assert captured["since_cursor"] == [42, "y"]


def test_all_expected_tools_are_registered() -> None:
    """Sanity check: every tool listed in the plan is callable on the module."""
    expected = {
        "search_logs",
        "count_documents",
        "get_histogram",
        "get_context",
        "get_mapping",
        "list_fields",
        "list_aliases",
        "tail_logs",
        "raw_es_query",
        "get_discover_url",
        "list_profiles",
    }
    missing = [name for name in expected if not callable(getattr(server, name, None))]
    assert not missing, f"Missing MCP tool exports: {missing}"

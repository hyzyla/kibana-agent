"""
kibana-agent MCP server (stdio transport).

Wraps :mod:`kibana_agent.client` operations as MCP tools so Claude Code,
Claude Desktop, Cursor and other MCP clients can call them as first-class
tools instead of shelling out to the CLI.

Launch via the CLI:

    kibana-agent mcp

Profile resolution mirrors the CLI: each tool accepts an optional ``profile``
argument; if omitted, the server falls back to ``KIBANA_AGENT_PROFILE``, then
to ``KIBANA_URL``+credential env vars, then to the active profile in the
config file. See :func:`kibana_agent.client.resolve_profile`.
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any

from mcp.server.fastmcp import FastMCP

from kibana_agent import client
from kibana_agent.client import KibanaAgentError

mcp = FastMCP("kibana-agent")


def safe(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Convert ``KibanaAgentError`` raised by a tool into a structured error.

    The wrapped tool always returns a dict; on success it's the underlying
    payload, on failure it's ``{"error": str, "type": str}`` so the LLM gets a
    clean, parseable failure rather than an opaque MCP transport error.
    """

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except KibanaAgentError as exc:
            return {"error": str(exc), "type": type(exc).__name__}

    return wrapper


def _resolve(profile: str | None) -> dict[str, Any]:
    return client.resolve_profile(profile)


@mcp.tool()
@safe
def search_logs(
    index_pattern: str | None = None,
    last: str = "1h",
    query: str | None = None,
    kql: str | None = None,
    size: int = 5,
    fields: list[str] | None = None,
    sort: str = "@timestamp:desc",
    aggs: dict[str, Any] | None = None,
    profile: str | None = None,
) -> dict[str, Any]:
    """Search recent logs in a Kibana index pattern.

    Supports KQL (e.g. ``level:ERROR AND service:api``) and raw ES JSON DSL
    via the ``query`` parameter (a JSON string of an ES query clause). Returns
    ``{total, n, hits, ...}``. ``index_pattern`` defaults to the profile's
    configured default index.
    """
    prof = _resolve(profile)
    idx = client._resolve_index(prof, index_pattern)
    return client.op_search(
        prof,
        idx,
        time_range=last,
        extra_query=query,
        kql=kql,
        size=size,
        sort=sort,
        fields=fields,
        aggs=aggs,
    )


@mcp.tool()
@safe
def count_documents(
    index_pattern: str | None = None,
    last: str = "1h",
    query: str | None = None,
    kql: str | None = None,
    profile: str | None = None,
) -> dict[str, Any]:
    """Count documents matching a query in an index pattern over a time range."""
    prof = _resolve(profile)
    idx = client._resolve_index(prof, index_pattern)
    n = client.op_count(prof, idx, time_range=last, extra_query=query, kql=kql)
    return {"count": n, "index": idx, "last": last}


@mcp.tool()
@safe
def get_histogram(
    index_pattern: str | None = None,
    last: str = "1h",
    interval: str = "5m",
    query: str | None = None,
    kql: str | None = None,
    time_field: str = "@timestamp",
    profile: str | None = None,
) -> dict[str, Any]:
    """Date histogram of doc counts. Useful for spotting trends and spikes."""
    prof = _resolve(profile)
    idx = client._resolve_index(prof, index_pattern)
    return client.op_histogram(
        prof,
        idx,
        time_range=last,
        interval=interval,
        extra_query=query,
        kql=kql,
        time_field=time_field,
    )


@mcp.tool()
@safe
def get_context(
    indices: str | None = None,
    refresh: bool = False,
    profile: str | None = None,
) -> dict[str, Any]:
    """Compact overview of available indices, aliases, field mappings, and
    recent doc counts. Cached for an hour; pass ``refresh=True`` to bypass
    the cache. Best first call when exploring a new Kibana instance.
    """
    prof = _resolve(profile)
    return client.op_context(prof, indices=indices, refresh=refresh)


@mcp.tool()
@safe
def get_mapping(
    index_pattern: str | None = None,
    full: bool = False,
    profile: str | None = None,
) -> dict[str, Any]:
    """Field mapping for an index pattern (flat ``field: type``, deduped by
    common prefix). Pass ``full=True`` for the raw Elasticsearch mapping.
    """
    prof = _resolve(profile)
    idx = client._resolve_index(prof, index_pattern)
    return client.op_mapping(prof, idx, full=full)


@mcp.tool()
@safe
def list_fields(
    index_pattern: str | None = None,
    glob: str = "*",
    profile: str | None = None,
) -> dict[str, str]:
    """List field names matching a glob (e.g. ``*.host`` or ``log.*``)."""
    prof = _resolve(profile)
    idx = client._resolve_index(prof, index_pattern)
    return client.op_fields(prof, idx, glob=glob)


@mcp.tool()
@safe
def list_aliases(profile: str | None = None) -> dict[str, list[str]]:
    """List all index aliases configured in the Kibana cluster."""
    prof = _resolve(profile)
    return client.op_aliases(prof)


@mcp.tool()
@safe
def tail_logs(
    index_pattern: str | None = None,
    since_cursor: list[Any] | None = None,
    last: str = "1m",
    query: str | None = None,
    kql: str | None = None,
    size: int = 50,
    fields: list[str] | None = None,
    profile: str | None = None,
) -> dict[str, Any]:
    """Poll for new logs since a cursor (uses ``search_after``).

    On the first call, omit ``since_cursor`` and the server returns the most
    recent ``size`` docs from the last ``last`` window. Subsequent calls
    should pass the ``next_cursor`` from the previous response to fetch only
    newer documents. Returns ``{hits, next_cursor}``.
    """
    prof = _resolve(profile)
    idx = client._resolve_index(prof, index_pattern)
    return client.op_tail_page(
        prof,
        idx,
        since_cursor=since_cursor,
        time_range=last,
        extra_query=query,
        kql=kql,
        size=size,
        fields=fields,
    )


@mcp.tool()
@safe
def raw_es_query(
    method: str,
    es_path: str,
    body: dict[str, Any] | None = None,
    profile: str | None = None,
) -> dict[str, Any]:
    """Send a raw read-only Elasticsearch request through the Kibana proxy.

    Only ``GET`` and a curated set of read-only ``POST`` endpoints are
    permitted (``_search``, ``_count``, ``_field_caps``, ...). All write
    operations are rejected by the same safety guard the CLI uses.
    """
    prof = _resolve(profile)
    data = client.op_raw(prof, method, es_path, body=body)
    return {"data": data}


@mcp.tool()
@safe
def get_discover_url(
    index_pattern: str | None = None,
    last: str = "1h",
    kql: str | None = None,
    lucene: str | None = None,
    fields: list[str] | None = None,
    profile: str | None = None,
) -> dict[str, str]:
    """Build a Kibana Discover deep link with a pre-filled query and time range."""
    prof = _resolve(profile)
    idx = client._resolve_index(prof, index_pattern)
    return client.op_discover_url(
        prof, idx, time_range=last, kql=kql, lucene=lucene, fields=fields
    )


@mcp.tool()
@safe
def list_profiles() -> dict[str, Any]:
    """List configured Kibana profiles (read-only — no credentials returned).

    Use this to discover what environments are available before passing one
    as the ``profile`` argument to other tools.
    """
    return {"profiles": client.op_list_profiles()}


def run() -> None:
    """Run the FastMCP server over stdio (the default transport)."""
    mcp.run()


if __name__ == "__main__":
    run()

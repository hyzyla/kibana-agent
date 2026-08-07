"""
kibana-agent — Read-only Kibana / Elasticsearch CLI optimised for AI agent usage.

Setup:
    kibana-agent profile create prd \\
        --url https://kibana.example.com \\
        --auth 1password \\
        --op-username "op://vault/item/username" \\
        --op-password "op://vault/item/password"

    kibana-agent profile use prd

Usage:
    kibana-agent context
    kibana-agent search my-index-* --last 1h -q '{"match":{"level":"ERROR"}}'
    kibana-agent discover my-index-* --last 1h --kql "level:ERROR"
    kibana-agent tail my-index-* -f "@timestamp,level,message"

Profiles:
    kibana-agent profile list
    kibana-agent profile show prd
    kibana-agent profile use stg
    kibana-agent profile delete old

    --profile <name> on any command overrides the active profile.

MCP server:
    kibana-agent mcp     # run as an MCP stdio server (for Claude Code, Cursor, ...)

Auth methods:
    1password  — reads user/pass from 1Password via `op` CLI
    keychain   — reads from OS keyring (macOS Keychain / Linux Secret Service /
                 Windows Credential Locker) via the `keyring` library
    plain      — stored in config file (not recommended)

Config:  $KIBANA_AGENT_CONFIG_DIR, or
         $XDG_CONFIG_HOME/kibana-agent (default ~/.config/kibana-agent) on Linux/macOS
         %APPDATA%\\kibana-agent on Windows
Cache:   $KIBANA_AGENT_CACHE_DIR, or
         $XDG_CACHE_HOME/kibana-agent (default ~/.cache/kibana-agent) on Linux/macOS
         %LOCALAPPDATA%\\kibana-agent\\Cache on Windows
"""

from __future__ import annotations

import functools
import json
import signal
import sys
import time
from collections.abc import Callable
from typing import Any

import click

from kibana_agent import client
from kibana_agent.client import (
    CACHE_DIR,
    DEFAULT_SIZE,
    DEFAULT_TIME_FIELD,
    DEFAULT_TIME_RANGE,
    DEFAULT_TIMEOUT,
    MAX_SOURCE_LEN,
    DryRunResult,
    KibanaAgentError,
)


def emit(data: Any, fmt: str) -> None:
    if fmt == "compact" and isinstance(data, dict) and isinstance(data.get("hits"), list):
        meta = {k: v for k, v in data.items() if k != "hits"}
        if meta:
            click.echo("#" + json.dumps(meta, ensure_ascii=False, separators=(",", ":")))
        for hit in data["hits"]:
            click.echo(json.dumps(hit, ensure_ascii=False, separators=(",", ":")))
    elif fmt == "compact":
        click.echo(json.dumps(data, ensure_ascii=False, separators=(",", ":")))
    else:
        click.echo(json.dumps(data, ensure_ascii=False, indent=2))


def handle_errors(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Translate ``KibanaAgentError`` (and ``DryRunResult``) into CLI exits."""

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except DryRunResult as dry:
            click.echo(dry.curl)
            sys.exit(0)
        except KibanaAgentError as exc:
            click.echo(str(exc), err=True)
            sys.exit(1)

    return wrapper


def common(f: Callable[..., Any]) -> Callable[..., Any]:
    """Decorator adding shared CLI options to a command."""
    f = click.option(
        "--profile",
        "prof_name",
        default=None,
        envvar="KIBANA_AGENT_PROFILE",
        help="Profile name (default: active)",
    )(f)
    f = click.option("--timeout", type=int, default=DEFAULT_TIMEOUT)(f)
    f = click.option("--dry-run", is_flag=True, default=False)(f)
    f = click.option("--explain", is_flag=True, default=False)(f)
    f = click.option("--filter-path", "filter_path", default=None)(f)
    f = click.option(
        "--format", "fmt", type=click.Choice(["pretty", "compact"]), default="compact"
    )(f)
    f = click.option("--no-cache", "no_cache", is_flag=True, default=False)(f)
    return f


def _es_kwargs(
    timeout: int, dry_run: bool, explain: bool, filter_path: str | None
) -> dict[str, Any]:
    kwargs: dict[str, Any] = {"timeout": timeout}
    if dry_run:
        kwargs["dry_run"] = True
    if explain:
        kwargs["explain"] = True
    if filter_path:
        kwargs["filter_path"] = filter_path
    return kwargs


@click.group()
@click.version_option(package_name="kibana-agent")
def cli() -> None:
    """Read-only Kibana/ES CLI for AI agents."""


@cli.group()
def profile() -> None:
    """Manage connection profiles."""


@profile.command("create")
@click.argument("name")
@click.option("--url", required=True, help="Kibana base URL")
@click.option(
    "--auth",
    "auth_type",
    required=True,
    type=click.Choice(["1password", "keychain", "plain"]),
    help="Auth backend",
)
@click.option("--op-username", default=None, help="1Password ref for username")
@click.option("--op-password", default=None, help="1Password ref for password")
@click.option("--kc-service", default=None, help="OS keyring service name")
@click.option("--kc-username-account", default=None, help="OS keyring account for username")
@click.option("--kc-password-account", default=None, help="OS keyring account for password")
@click.option("--kc-set-username", default=None, help="Store this username in the OS keyring now")
@click.option("--kc-set-password", default=None, help="Store this password in the OS keyring now")
@click.option("--username", default=None, help="Plain text username")
@click.option("--password", default=None, help="Plain text password")
@click.option("--space", default=None, help="Kibana Space ID (e.g. backend)")
@click.option("--index", default=None, help="Default index pattern (e.g. logs-*)")
@click.option("--restrict-space", is_flag=True, default=False, help="Restrict to configured space")
@click.option("--restrict-index", is_flag=True, default=False, help="Restrict to configured index")
@click.option("--use", "set_active", is_flag=True, default=False, help="Set as active profile")
@handle_errors
def profile_create(
    name: str,
    url: str,
    auth_type: str,
    op_username: str | None,
    op_password: str | None,
    kc_service: str | None,
    kc_username_account: str | None,
    kc_password_account: str | None,
    kc_set_username: str | None,
    kc_set_password: str | None,
    username: str | None,
    password: str | None,
    space: str | None,
    index: str | None,
    restrict_space: bool,
    restrict_index: bool,
    set_active: bool,
) -> None:
    """Create a new profile.

    \b
    Examples:
      # 1Password
      profile create prd --url https://kibana.example.com --auth 1password \\
        --op-username "op://vault/item/username" --op-password "op://vault/item/password" --use

    \b
      # With space and default index
      profile create prd --url https://kibana.example.com --auth 1password \\
        --op-username "op://vault/item/username" --op-password "op://vault/item/password" \\
        --space backend --index logs-* --restrict-index --use

    \b
      # OS keyring (macOS Keychain / Linux Secret Service / Windows Credential Locker)
      profile create stg --url https://kibana-stg.example.com --auth keychain \\
        --kc-service kibana-stg --kc-username-account kibana-user \\
        --kc-password-account kibana-pass \\
        --kc-set-username admin --kc-set-password s3cret --use

    \b
      # Plain text (not recommended)
      profile create dev --url http://localhost:5601 --auth plain \\
        --username admin --password admin --use
    """
    auth: dict[str, str] = {"type": auth_type}

    if auth_type == "1password":
        if not op_username or not op_password:
            click.echo(
                "Error: --op-username and --op-password required for 1password auth.",
                err=True,
            )
            sys.exit(1)
        auth["username_ref"] = op_username
        auth["password_ref"] = op_password

    elif auth_type == "keychain":
        if not kc_service:
            click.echo("Error: --kc-service required for keychain auth.", err=True)
            sys.exit(1)
        service = kc_service
        username_account = kc_username_account or f"{name}-username"
        password_account = kc_password_account or f"{name}-password"
        auth["service"] = service
        auth["username_account"] = username_account
        auth["password_account"] = password_account

        if kc_set_username:
            client.keychain_write(service, username_account, kc_set_username)
            click.echo(
                f"Stored username in OS keyring (service={service}, account={username_account})",
                err=True,
            )
        if kc_set_password:
            client.keychain_write(service, password_account, kc_set_password)
            click.echo(
                f"Stored password in OS keyring (service={service}, account={password_account})",
                err=True,
            )

    elif auth_type == "plain":
        if not username or not password:
            click.echo("Error: --username and --password required for plain auth.", err=True)
            sys.exit(1)
        click.echo("Warning: credentials stored in plain text in config file.", err=True)
        auth["username"] = username
        auth["password"] = password

    config = client.load_config()
    profile_data: dict[str, Any] = {"kibana_url": url.rstrip("/"), "auth": auth}
    if space:
        profile_data["space"] = space
    if index:
        profile_data["index"] = index
    if restrict_space:
        profile_data["restrict_space"] = True
    if restrict_index:
        profile_data["restrict_index"] = True
    config["profiles"][name] = profile_data
    if set_active or config.get("active") is None:
        config["active"] = name
    client.save_config(config)
    active_note = " (active)" if config["active"] == name else ""
    click.echo(f"Created profile '{name}'{active_note}")


@profile.command("list")
def profile_list() -> None:
    """List all profiles."""
    config = client.load_config()
    active = config.get("active")
    profiles = config.get("profiles", {})
    if not profiles:
        click.echo("No profiles. Run: profile create <name> ...")
        return
    for name, profile_data in profiles.items():
        marker = " *" if name == active else ""
        auth_type = profile_data.get("auth", {}).get("type", "?")
        parts = [f"{name}{marker}  {profile_data['kibana_url']}  ({auth_type})"]
        space = profile_data.get("space")
        if space:
            lock = " restricted" if profile_data.get("restrict_space") else ""
            parts.append(f"[space: {space}{lock}]")
        idx = profile_data.get("index")
        if idx:
            lock = " restricted" if profile_data.get("restrict_index") else ""
            parts.append(f"[index: {idx}{lock}]")
        click.echo("  ".join(parts))


@profile.command("show")
@click.argument("name", required=False, default=None)
def profile_show(name: str | None) -> None:
    """Show profile details (active profile if name omitted)."""
    config = client.load_config()
    profile_name = name or config.get("active")
    if not profile_name:
        click.echo("No active profile.", err=True)
        sys.exit(1)
    profile_data = config.get("profiles", {}).get(profile_name)
    if not profile_data:
        click.echo(f"Profile '{profile_name}' not found.", err=True)
        sys.exit(1)
    display = json.loads(json.dumps(profile_data))
    if display.get("auth", {}).get("type") == "plain" and "password" in display.get("auth", {}):
        display["auth"]["password"] = "***"
    click.echo(json.dumps({profile_name: display}, indent=2))


@profile.command("use")
@click.argument("name")
def profile_use(name: str) -> None:
    """Set the active profile."""
    config = client.load_config()
    if name not in config.get("profiles", {}):
        click.echo(f"Profile '{name}' not found.", err=True)
        sys.exit(1)
    config["active"] = name
    client.save_config(config)
    click.echo(f"Active profile: {name}")


@profile.command("note")
@click.argument("name")
@click.argument("pairs", nargs=-1)
@click.option("--delete", "delete_keys", multiple=True, help="Remove a note (repeatable)")
def profile_note(name: str, pairs: tuple[str, ...], delete_keys: tuple[str, ...]) -> None:
    """
    Store facts the cluster cannot tell you, such as which index holds which app.

    \b
    Examples:
      profile note prd                                   # dump every note
      profile note prd app-logs="logs-app-*"             # set one
      profile note prd app-logs="x" status-field="y"     # set many in one call
      profile note prd --delete app-logs                 # remove one

    Reading always returns every note at once, so never ask for keys one at a
    time. Notes appear at the top of `context`, live in the config file, and
    survive `cache-clear`. Keep them short. Do not store secrets, a copy of the
    mapping, or the findings of an investigation.
    """
    config = client.load_config()
    profile_data = config.get("profiles", {}).get(name)
    if profile_data is None:
        click.echo(f"Profile '{name}' not found. Run: profile list", err=True)
        sys.exit(1)
    notes: dict[str, str] = dict(profile_data.get("notes", {}))

    if not pairs and not delete_keys:
        click.echo(json.dumps(notes, indent=2, ensure_ascii=False))
        return

    changes: list[str] = []
    for key in delete_keys:
        if notes.pop(key, None) is None:
            click.echo(f"Profile '{name}' has no note '{key}'.", err=True)
            sys.exit(1)
        changes.append(f"removed '{key}'")

    for pair in pairs:
        key, sep, value = pair.partition("=")
        if not sep or not key:
            click.echo(
                f"Error: expected key=value, got '{pair}'. "
                f"To read the notes run: profile note {name}",
                err=True,
            )
            sys.exit(1)
        notes[key] = value
        changes.append(f"set '{key}'")

    if notes:
        profile_data["notes"] = notes
    else:
        profile_data.pop("notes", None)
    client.save_config(config)
    click.echo(f"{', '.join(changes)} on '{name}'")


@profile.command("delete")
@click.argument("name")
def profile_delete(name: str) -> None:
    """Delete a profile."""
    config = client.load_config()
    if name not in config.get("profiles", {}):
        click.echo(f"Profile '{name}' not found.", err=True)
        sys.exit(1)
    del config["profiles"][name]
    if config.get("active") == name:
        remaining = list(config["profiles"].keys())
        config["active"] = remaining[0] if remaining else None
    client.save_config(config)
    click.echo(f"Deleted profile '{name}'")


@profile.command("update")
@click.argument("name")
@click.option("--url", default=None, help="New Kibana URL")
@click.option(
    "--auth",
    "auth_type",
    default=None,
    type=click.Choice(["1password", "keychain", "plain"]),
)
@click.option("--op-username", default=None)
@click.option("--op-password", default=None)
@click.option("--kc-service", default=None)
@click.option("--kc-username-account", default=None)
@click.option("--kc-password-account", default=None)
@click.option("--kc-set-username", default=None, help="Update username in the OS keyring")
@click.option("--kc-set-password", default=None, help="Update password in the OS keyring")
@click.option("--username", default=None)
@click.option("--password", default=None)
@click.option("--space", default=None, help="Kibana Space ID")
@click.option("--no-space", "clear_space", is_flag=True, default=False, help="Remove space")
@click.option("--index", default=None, help="Default index pattern")
@click.option("--no-index", "clear_index", is_flag=True, default=False, help="Remove default index")
@click.option("--restrict-space/--no-restrict-space", default=None, help="Restrict space")
@click.option("--restrict-index/--no-restrict-index", default=None, help="Restrict index")
@handle_errors
def profile_update(
    name: str,
    url: str | None,
    auth_type: str | None,
    op_username: str | None,
    op_password: str | None,
    kc_service: str | None,
    kc_username_account: str | None,
    kc_password_account: str | None,
    kc_set_username: str | None,
    kc_set_password: str | None,
    username: str | None,
    password: str | None,
    space: str | None,
    clear_space: bool,
    index: str | None,
    clear_index: bool,
    restrict_space: bool | None,
    restrict_index: bool | None,
) -> None:
    """Update an existing profile's fields."""
    config = client.load_config()
    profile_data = config.get("profiles", {}).get(name)
    if not profile_data:
        click.echo(f"Profile '{name}' not found.", err=True)
        sys.exit(1)

    if url:
        profile_data["kibana_url"] = url.rstrip("/")

    auth = profile_data.get("auth", {})
    if auth_type:
        auth = {"type": auth_type}

    current_type = auth.get("type")
    if current_type == "1password":
        if op_username:
            auth["username_ref"] = op_username
        if op_password:
            auth["password_ref"] = op_password
    elif current_type == "keychain":
        if kc_service:
            auth["service"] = kc_service
        if kc_username_account:
            auth["username_account"] = kc_username_account
        if kc_password_account:
            auth["password_account"] = kc_password_account
        service = auth.get("service", name)
        if kc_set_username:
            acct = auth.get("username_account", f"{name}-username")
            client.keychain_write(service, acct, kc_set_username)
            click.echo("Updated username in OS keyring", err=True)
        if kc_set_password:
            acct = auth.get("password_account", f"{name}-password")
            client.keychain_write(service, acct, kc_set_password)
            click.echo("Updated password in OS keyring", err=True)
    elif current_type == "plain":
        if username:
            auth["username"] = username
        if password:
            auth["password"] = password
        if username or password:
            click.echo("Warning: credentials stored in plain text.", err=True)

    profile_data["auth"] = auth

    if space:
        profile_data["space"] = space
    if clear_space:
        profile_data.pop("space", None)
    if index:
        profile_data["index"] = index
    if clear_index:
        profile_data.pop("index", None)
    if restrict_space is not None:
        if restrict_space:
            profile_data["restrict_space"] = True
        else:
            profile_data.pop("restrict_space", None)
    if restrict_index is not None:
        if restrict_index:
            profile_data["restrict_index"] = True
        else:
            profile_data.pop("restrict_index", None)

    config["profiles"][name] = profile_data
    client.save_config(config)
    click.echo(f"Updated profile '{name}'")


@cli.command()
@click.option("--refresh", is_flag=True, default=False)
@click.option("--indices", default=None, help="Index patterns (csv)")
@common
@handle_errors
def context(
    refresh: bool,
    indices: str | None,
    prof_name: str | None,
    timeout: int,
    dry_run: bool,
    explain: bool,
    filter_path: str | None,
    fmt: str,
    no_cache: bool,
) -> None:
    """Compact context summary: indices, fields, doc counts. Cached."""
    prof = client.resolve_profile(prof_name)
    ctx = client.op_context(
        prof,
        indices=indices,
        refresh=refresh,
        no_cache=no_cache,
        **_es_kwargs(timeout, dry_run, explain, filter_path),
    )
    emit(ctx, fmt)


@cli.command()
@common
@handle_errors
def aliases(
    prof_name: str | None,
    timeout: int,
    dry_run: bool,
    explain: bool,
    filter_path: str | None,
    fmt: str,
    no_cache: bool,
) -> None:
    """List index aliases."""
    prof = client.resolve_profile(prof_name)
    emit(
        client.op_aliases(
            prof,
            no_cache=no_cache,
            **_es_kwargs(timeout, dry_run, explain, filter_path),
        ),
        fmt,
    )


@cli.command()
@click.argument("index_pattern", required=False, default=None)
@click.option("--full", is_flag=True, default=False)
@common
@handle_errors
def mapping(
    index_pattern: str | None,
    full: bool,
    prof_name: str | None,
    timeout: int,
    dry_run: bool,
    explain: bool,
    filter_path: str | None,
    fmt: str,
    no_cache: bool,
) -> None:
    """Index mapping (flat field:type, deduped)."""
    prof = client.resolve_profile(prof_name)
    idx = client._resolve_index(prof, index_pattern)
    emit(
        client.op_mapping(
            prof,
            idx,
            full=full,
            no_cache=no_cache,
            **_es_kwargs(timeout, dry_run, explain, filter_path),
        ),
        fmt,
    )


@cli.command()
@click.argument("index_pattern", required=False, default=None)
@click.argument("glob", default="*")
@common
@handle_errors
def fields(
    index_pattern: str | None,
    glob: str,
    prof_name: str | None,
    timeout: int,
    dry_run: bool,
    explain: bool,
    filter_path: str | None,
    fmt: str,
    no_cache: bool,
) -> None:
    """Field names matching GLOB."""
    prof = client.resolve_profile(prof_name)
    idx = client._resolve_index(prof, index_pattern)
    emit(
        client.op_fields(
            prof,
            idx,
            glob=glob,
            no_cache=no_cache,
            **_es_kwargs(timeout, dry_run, explain, filter_path),
        ),
        fmt,
    )


@cli.command()
@click.argument("index_pattern", required=False, default=None)
@click.option("--last", "time_range", default=DEFAULT_TIME_RANGE)
@click.option("-q", "--query", "extra_query", default=None)
@click.option("--kql", "kql_query", default=None, help="KQL filter")
@click.option("--time-field", "time_field", default=DEFAULT_TIME_FIELD)
@click.option("--no-hints", "no_hints", is_flag=True, default=False)
@common
@handle_errors
def count(
    index_pattern: str | None,
    time_range: str,
    extra_query: str | None,
    kql_query: str | None,
    time_field: str,
    no_hints: bool,
    prof_name: str | None,
    timeout: int,
    dry_run: bool,
    explain: bool,
    filter_path: str | None,
    fmt: str,
    no_cache: bool,
) -> None:
    """Count documents."""
    prof = client.resolve_profile(prof_name)
    idx = client._resolve_index(prof, index_pattern)
    n = client.op_count(
        prof,
        idx,
        time_range=time_range,
        extra_query=extra_query,
        kql=kql_query,
        time_field=time_field,
        hints=not no_hints and not dry_run,
        **_es_kwargs(timeout, dry_run, explain, filter_path),
    )
    click.echo(n)


@cli.command()
@click.argument("index_pattern", required=False, default=None)
@click.option("--last", "time_range", default=DEFAULT_TIME_RANGE)
@click.option("-n", "--size", default=DEFAULT_SIZE, type=int)
@click.option("-q", "--query", "extra_query", default=None)
@click.option("--kql", "kql_query", default=None, help="KQL filter")
@click.option("-f", "--fields", "field_csv", default=None)
@click.option("--sort", "sort_field", default=None)
@click.option("--aggs", default=None)
@click.option("--time-field", "time_field", default=DEFAULT_TIME_FIELD)
@click.option("--max-source-len", "max_source_len", default=MAX_SOURCE_LEN, type=int)
@click.option(
    "--expand-json",
    "expand_json",
    is_flag=True,
    default=False,
    help="Parse JSON held inside string fields and split multi-line strings into lines. "
    "Use it with --format pretty to read a traceback.",
)
@click.option("--no-hints", "no_hints", is_flag=True, default=False)
@common
@handle_errors
def search(
    index_pattern: str | None,
    time_range: str,
    size: int,
    extra_query: str | None,
    kql_query: str | None,
    field_csv: str | None,
    sort_field: str | None,
    aggs: str | None,
    time_field: str,
    max_source_len: int,
    expand_json: bool,
    no_hints: bool,
    prof_name: str | None,
    timeout: int,
    dry_run: bool,
    explain: bool,
    filter_path: str | None,
    fmt: str,
    no_cache: bool,
) -> None:
    """Search recent logs."""
    prof = client.resolve_profile(prof_name)
    idx = client._resolve_index(prof, index_pattern)
    field_list = [f.strip() for f in field_csv.split(",") if f.strip()] if field_csv else None
    result = client.op_search(
        prof,
        idx,
        time_range=time_range,
        extra_query=extra_query,
        kql=kql_query,
        size=size,
        sort=sort_field,
        fields=field_list,
        aggs=json.loads(aggs) if aggs else None,
        max_source_len=max_source_len,
        expand_json=expand_json,
        time_field=time_field,
        hints=not no_hints and not dry_run,
        **_es_kwargs(timeout, dry_run, explain, filter_path),
    )
    emit(result, fmt)


@cli.command()
@click.argument("index_pattern", required=False, default=None)
@click.option("--interval", default=2.0, type=float)
@click.option("--last", "time_range", default="1m")
@click.option("-q", "--query", "extra_query", default=None)
@click.option("--kql", "kql_query", default=None, help="KQL filter")
@click.option("-f", "--fields", "field_csv", default=None)
@click.option("-n", "--size", default=50, type=int)
@click.option("--max-source-len", "max_source_len", default=MAX_SOURCE_LEN, type=int)
@click.option(
    "--expand-json",
    "expand_json",
    is_flag=True,
    default=False,
    help="Parse JSON held inside string fields and split multi-line strings into lines.",
)
@common
@handle_errors
def tail(
    index_pattern: str | None,
    interval: float,
    time_range: str,
    extra_query: str | None,
    kql_query: str | None,
    field_csv: str | None,
    size: int,
    max_source_len: int,
    expand_json: bool,
    prof_name: str | None,
    timeout: int,
    dry_run: bool,
    explain: bool,
    filter_path: str | None,
    fmt: str,
    no_cache: bool,
) -> None:
    """Stream logs (search_after). Ctrl+C to stop."""
    prof = client.resolve_profile(prof_name)
    idx = client._resolve_index(prof, index_pattern)
    field_list = [f.strip() for f in field_csv.split(",") if f.strip()] if field_csv else None
    cursor: list[Any] | None = None
    first = True

    def _handle_sigint(*_: object) -> None:
        click.echo("", err=True)
        sys.exit(0)

    signal.signal(signal.SIGINT, _handle_sigint)

    while True:
        try:
            page = client.op_tail_page(
                prof,
                idx,
                since_cursor=cursor,
                time_range=time_range,
                extra_query=extra_query,
                kql=kql_query,
                size=size,
                fields=field_list,
                max_source_len=max_source_len,
                expand_json=expand_json,
                **_es_kwargs(timeout, dry_run, explain and first, filter_path),
            )
        except DryRunResult:
            raise
        except KibanaAgentError as exc:
            click.echo(f"err: {exc}", err=True)
            time.sleep(interval)
            continue
        except Exception as exc:
            click.echo(f"err: {exc}", err=True)
            time.sleep(interval)
            continue
        for hit in page["hits"]:
            click.echo(json.dumps(hit, ensure_ascii=False, separators=(",", ":")))
        cursor = page["next_cursor"]
        first = False
        time.sleep(interval)


@cli.command()
@click.argument("index_pattern", required=False, default=None)
@click.option("--last", "time_range", default=DEFAULT_TIME_RANGE)
@click.option("--interval", default="5m")
@click.option("-q", "--query", "extra_query", default=None)
@click.option("--kql", "kql_query", default=None, help="KQL filter")
@click.option("--field", "--time-field", "time_field", default=DEFAULT_TIME_FIELD)
@click.option("--no-hints", "no_hints", is_flag=True, default=False)
@common
@handle_errors
def histogram(
    index_pattern: str | None,
    time_range: str,
    interval: str,
    extra_query: str | None,
    kql_query: str | None,
    time_field: str,
    no_hints: bool,
    prof_name: str | None,
    timeout: int,
    dry_run: bool,
    explain: bool,
    filter_path: str | None,
    fmt: str,
    no_cache: bool,
) -> None:
    """Date histogram of doc counts."""
    prof = client.resolve_profile(prof_name)
    idx = client._resolve_index(prof, index_pattern)
    result = client.op_histogram(
        prof,
        idx,
        time_range=time_range,
        interval=interval,
        extra_query=extra_query,
        kql=kql_query,
        time_field=time_field,
        hints=not no_hints and not dry_run,
        **_es_kwargs(timeout, dry_run, explain, filter_path),
    )
    emit(result, fmt)


@cli.command()
@click.argument("index_pattern", required=False, default=None)
@click.option("--last", "time_range", default=DEFAULT_TIME_RANGE)
@click.option("--kql", default=None, help="KQL query")
@click.option("--lucene", default=None, help="Lucene query")
@click.option("-f", "--fields", "field_csv", default=None, help="Columns (csv)")
@click.option("--profile", "prof_name", default=None, envvar="KIBANA_AGENT_PROFILE")
@handle_errors
def discover(
    index_pattern: str | None,
    time_range: str,
    kql: str | None,
    lucene: str | None,
    field_csv: str | None,
    prof_name: str | None,
) -> None:
    """Build a Kibana Discover URL."""
    prof = client.resolve_profile(prof_name)
    idx = client._resolve_index(prof, index_pattern)
    field_list = [f.strip() for f in field_csv.split(",") if f.strip()] if field_csv else None
    result = client.op_discover_url(
        prof, idx, time_range=time_range, kql=kql, lucene=lucene, fields=field_list
    )
    click.echo(result["url"])
    click.echo(f"Note: {result['data_view_hint']}", err=True)


@cli.command()
@click.argument("method", type=click.Choice(["GET", "POST"], case_sensitive=False))
@click.argument("es_path")
@click.option("--body", default=None)
@common
@handle_errors
def raw(
    method: str,
    es_path: str,
    body: str | None,
    prof_name: str | None,
    timeout: int,
    dry_run: bool,
    explain: bool,
    filter_path: str | None,
    fmt: str,
    no_cache: bool,
) -> None:
    """Raw read-only ES request."""
    prof = client.resolve_profile(prof_name)
    data = client.op_raw(
        prof,
        method,
        es_path,
        body=body,
        **_es_kwargs(timeout, dry_run, explain, filter_path),
    )
    emit(data, fmt)


@cli.command("cache-clear")
@click.option(
    "--profile",
    "prof_name",
    default=None,
    envvar="KIBANA_AGENT_PROFILE",
    help="Profile to clear (default: active)",
)
@click.option("--all", "clear_all", is_flag=True, default=False, help="Clear every profile")
@click.option("--data-only", is_flag=True, default=False, help="Keep cached credentials")
@click.option("--creds-only", is_flag=True, default=False, help="Keep cached data")
@handle_errors
def cache_clear(prof_name: str | None, clear_all: bool, data_only: bool, creds_only: bool) -> None:
    """
    Wipe cached data and credentials for one profile (default: the active one).

    \b
    Examples:
      cache-clear                  # active profile: cached data + credentials
      cache-clear --profile stg    # that profile only
      cache-clear --creds-only     # re-authenticate, keep the cached mappings
      cache-clear --all            # every profile

    Profile notes live in the config file and are never touched.
    """
    if data_only and creds_only:
        click.echo("Error: --data-only and --creds-only are mutually exclusive.", err=True)
        sys.exit(1)
    if clear_all and prof_name:
        click.echo("Error: --all and --profile are mutually exclusive.", err=True)
        sys.exit(1)

    if clear_all:
        if not creds_only:
            click.echo(f"Cleared {client.cache_clear_all()} cached files from {CACHE_DIR}")
        if not data_only:
            client.cached_creds_clear()
            click.echo("Cleared cached credentials for every profile.")
        return

    prof = client.resolve_profile(prof_name)
    label = client.profile_label(prof)
    if not creds_only:
        click.echo(f"Cleared {client.cache_clear_profile(prof)} cached files for '{label}'")
    if not data_only:
        client.cached_creds_clear_profile(prof)
        click.echo(f"Cleared cached credentials for '{label}'.")


@cli.command("cred-cache-ttl")
@click.argument("seconds", required=False, default=None)
@handle_errors
def cred_cache_ttl_cmd(seconds: str | None) -> None:
    """
    Show or set how long 1Password/keychain credentials stay cached.

    \b
    Examples:
      cred-cache-ttl              # show the current value and where it comes from
      cred-cache-ttl 3600         # cache for one hour
      cred-cache-ttl 0            # disable caching (authenticate every call)
      cred-cache-ttl unset        # drop the override and use the default

    KIBANA_AGENT_CRED_CACHE_TTL overrides the stored value for one shell.
    """
    if seconds is None:
        click.echo(f"cred_cache_ttl: {client.cred_cache_ttl()}s ({client.cred_cache_ttl_source()})")
        return

    if seconds.lower() in ("unset", "default", "clear"):
        client.set_cred_cache_ttl(None)
        default = client._CRED_CACHE_TTL_DEFAULT
        click.echo(f"cred_cache_ttl: unset (default {default}s = {default // 3600}h)")
        return

    try:
        value = int(seconds)
    except ValueError:
        click.echo(f"Error: '{seconds}' is not an integer number of seconds.", err=True)
        sys.exit(1)
    if value < 0:
        click.echo("Error: TTL must be >= 0 (0 disables caching).", err=True)
        sys.exit(1)
    client.set_cred_cache_ttl(value)
    click.echo(f"cred_cache_ttl: {value}s" + (" (caching disabled)" if value == 0 else ""))


@cli.command()
def mcp() -> None:
    """Run the MCP server (stdio transport).

    Designed to be invoked from an MCP client config (Claude Code,
    Claude Desktop, Cursor, ...). Speaks JSON-RPC over stdin/stdout.
    """
    # Lazy import so the `mcp` package is only loaded when actually starting
    # the server, keeping CLI startup fast.
    from kibana_agent.server import run

    run()


@cli.command("agent-help")
def agent_help() -> None:
    """Print a usage guide for AI agents."""
    click.echo("""\
# kibana-agent — AI Agent Usage Guide

Read-only CLI for querying Elasticsearch via Kibana's console proxy API.
All write operations are blocked. Safe to use in automated pipelines.

## Quick start

1. Run `kibana-agent context` to get an overview of available indices,
   field mappings, and recent document counts. This is cached — pass
   `--refresh` to force a fresh fetch.

2. Search logs with `kibana-agent search <index-pattern>`:
   - `--last <duration>` — time range, e.g. 15m, 1h, 7d (default: 1h)
   - `-n <size>` — number of hits (default: 5)
   - `-q <json>` — extra ES query clause, e.g. '{"match":{"level":"ERROR"}}'
   - `-f <fields>` — comma-separated source fields to return
   - `--sort <field>:<order>` — sort order (default: @timestamp:desc)
   - `--aggs <json>` — aggregation clause
   - `--expand-json` — parse JSON that the application logged into a string
     field, and split multi-line strings into lines. Use it with
     `--format pretty` to read a traceback.

3. Count documents with `kibana-agent count <index-pattern>`:
   - Same --last and -q options as search.

4. Stream live logs with `kibana-agent tail <index-pattern>`:
   - Uses search_after for continuous polling. Ctrl+C to stop.
   - `-f <fields>` — limit output fields.
   - `--interval <seconds>` — poll interval (default: 2).

## Other commands

- `kibana-agent aliases` — list index aliases.
- `kibana-agent mapping <index-pattern>` — flat field:type mapping.
- `kibana-agent fields <index-pattern> [glob]` — field names matching glob.
- `kibana-agent histogram <index-pattern>` — date histogram of doc counts.
  Options: --interval (bucket size), --last, -q, --field.
- `kibana-agent discover <index-pattern>` — generate a Kibana Discover URL.
  Options: --kql, --lucene, -f, --last.
- `kibana-agent raw GET|POST <es-path> [--body <json>]` — arbitrary
  read-only ES request through the Kibana proxy.
- `kibana-agent profile note <profile> [<key>=<value> ...]` — store facts the
  cluster cannot tell you, such as which index holds which application. With
  no pair it dumps every note; `--delete <key>` removes one. Notes appear at
  the top of `context` and survive `cache-clear`.
- `kibana-agent cache-clear` — wipe cached data and credentials for the active
  profile. `--profile <name>` targets another, `--all` covers every profile,
  `--creds-only` re-authenticates but keeps the cached mappings, `--data-only`
  does the opposite. Profile notes are never touched.
- `kibana-agent cred-cache-ttl [<seconds>]` — show or set how long 1Password /
  keychain credentials stay cached. Default 24h; `0` disables caching, `unset`
  removes the override. `KIBANA_AGENT_CRED_CACHE_TTL` overrides it per shell.
- `kibana-agent mcp` — run as an MCP stdio server (Claude Code, Cursor, ...).

## Typical agent workflow

1. `kibana-agent context` — read the profile notes first, then learn what
   indices and fields exist. The notes say which index to use; never guess one
   when a note names it. `context` also reports, per pattern, the detected
   `time_field`, the first and last document time, and how many fields exist.
   It describes five patterns in full, and a pattern named in the notes comes
   before one picked alphabetically — so writing a note also improves what the
   next `context` shows. Use `--indices '<a>,<b>'` to ask for others.
2. `kibana-agent search <idx> --last 1h -n 3` — sample recent docs.
3. Refine: add `-q`, `-f`, `--aggs`, adjust `--last` and `-n`.
4. `kibana-agent histogram <idx> --last 6h --interval 10m` — spot trends.
5. `kibana-agent count <idx> --last 1h -q '{"match":{"level":"ERROR"}}'`
   — quantify issues.
6. Record what you worked out: `kibana-agent profile note <profile>
   app-logs="<pattern>"`.

## Hints on stderr — read them

`search`, `count`, and `histogram` check the request against the mapping
before sending it, and explain an empty result afterwards. Everything goes to
stderr; the request still runs. Use `--no-hints` to switch it off.

Before the request:
  - a field in `-q` or `--aggs` that the mapping lacks, with the closest
    matching field names;
  - `term`/`terms` on an analyzed text field, naming the `.keyword` sibling
    when one exists;
  - an aggregation on a text field, which has no doc values;
  - `--time-field` missing from the mapping, naming the date field the index
    really uses;
  - an index pattern that matches no index at all.

After the request:
  - `0 hits, but the last <window> holds N documents` — your filter is wrong,
    not the window;
  - `0 hits, and the last <window> is empty` — widen `--last`;
  - `holds no documents at all` — wrong index pattern;
  - `N of M shards failed` — the counts are partial, do not report them as
    totals;
  - documents cut at `--max-source-len`, which names the flag to raise.

A zero with no note and a clean exit is a real zero.

## `total` can be a floor, not a count

Elasticsearch stops counting matches at 10,000. When it does, `search` and
`histogram` add `"total_is_lower_bound": true` and warn on stderr. The real
number is higher — never report such a `total` as a fact. For an exact number
use `count`, which uses the `_count` API, or sum the `histogram` buckets,
which are aggregation counts and always exact. `context` marks the same case
with `"docs_is_lower_bound": true`.

## Output format

Default is `--format compact` (one JSON object per line, metadata on first
line prefixed with `#`). Use `--format pretty` for indented JSON.

## Global options (available on most commands)

--profile <name>   Override active profile (or set KIBANA_AGENT_PROFILE env var)
--timeout <sec>    Request timeout (default: 30)
--dry-run          Print the curl command instead of executing
--explain          Print the query body to stderr
--filter-path      ES filter_path parameter
--no-cache         Bypass cache

## Profiles

Profiles store connection details. Manage with `kibana-agent profile`
subcommands: create, list, show, use, delete, update.
The active profile is used by default; override with `--profile <name>`.
""")


if __name__ == "__main__":
    cli()

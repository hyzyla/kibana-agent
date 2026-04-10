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

Auth methods:
    1password  — reads user/pass from 1Password via `op` CLI
    keychain   — reads from OS keyring (macOS Keychain / Linux Secret Service /
                 Windows Credential Locker) via the `keyring` library
    plain      — stored in config file (not recommended)

Config:  ~/.config/kibana-agent/config.json
Cache:   ~/.cache/kibana-agent/
"""

from __future__ import annotations

import contextlib
import fnmatch
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import click
import keyring
import keyring.errors
import requests

from kibana_agent.kql import kql_to_es

CONFIG_DIR = Path.home() / ".config" / "kibana-agent"
CONFIG_FILE = CONFIG_DIR / "config.json"
CACHE_DIR = Path.home() / ".cache" / "kibana-agent"

DEFAULT_TIME_RANGE = "1h"
DEFAULT_SIZE = 5
DEFAULT_SORT = "@timestamp:desc"
DEFAULT_TIMEOUT = 30
MAX_SOURCE_LEN = 1000
MAX_RESPONSE_HITS = 500
MAX_RESPONSE_BYTES = 2_000_000
CACHE_TTL_ALIASES = 3600
CACHE_TTL_MAPPING = 86400
CACHE_TTL_CONTEXT = 3600

_CRED_CACHE_SERVICE = "kibana-agent"
_CRED_CACHE_TTL = 30 * 60  # 30 minutes
_CRED_CACHE_KEYS = ("cache-username", "cache-password", "cache-ts")

_KEYRING_HINT = (
    "No OS keyring backend is available. On Linux, install and start a Secret "
    "Service provider (e.g. gnome-keyring, KeePassXC, or KWallet), or use "
    "`--auth 1password` / `--auth plain` instead."
)

BLOCKED_ENDPOINTS = {
    "_bulk",
    "_create",
    "_delete_by_query",
    "_update",
    "_update_by_query",
    "_close",
    "_open",
    "_shrink",
    "_split",
    "_clone",
    "_rollover",
    "_forcemerge",
    "_reindex",
    "_snapshot",
    "_restore",
}
ALLOWED_POST_ENDPOINTS = (
    "_search",
    "_msearch",
    "_count",
    "_validate/query",
    "_field_caps",
    "_mget",
    "_mtermvectors",
    "_termvectors",
    "_explain",
    "_search/template",
    "_msearch/template",
    "_render/template",
)

_AUTH_BACKENDS: dict[str, Any] = {}
_creds_cache: tuple[str, str] | None = None


def _load_config() -> dict[str, Any]:
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text())  # type: ignore[no-any-return]
        except (json.JSONDecodeError, OSError):
            pass
    return {"active": None, "profiles": {}}


def _save_config(config: dict[str, Any]) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(config, indent=2, ensure_ascii=False) + "\n")


def _get_profile(name: str | None = None) -> dict[str, Any]:
    """Return the resolved profile dict or exit with error."""
    config = _load_config()
    profile_name = name or config.get("active")
    if not profile_name:
        click.echo("No active profile. Run: profile create <name> ...", err=True)
        sys.exit(1)
    profile_data = config.get("profiles", {}).get(profile_name)
    if not profile_data:
        click.echo(f"Profile '{profile_name}' not found. Run: profile list", err=True)
        sys.exit(1)
    return profile_data  # type: ignore[no-any-return]


_IS_MACOS = sys.platform == "darwin"


def _keychain_read(service: str, account: str) -> str | None:
    if _IS_MACOS:
        try:
            return subprocess.run(
                ["security", "find-generic-password", "-s", service, "-a", account, "-w"],
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
        except (FileNotFoundError, subprocess.CalledProcessError):
            return None
    try:
        return keyring.get_password(service, account)
    except keyring.errors.KeyringError as exc:
        click.echo(f"Keyring error: {exc}", err=True)
        click.echo(_KEYRING_HINT, err=True)
        sys.exit(1)


def _keychain_write(service: str, account: str, value: str) -> None:
    if _IS_MACOS:
        subprocess.run(
            ["security", "delete-generic-password", "-s", service, "-a", account],
            capture_output=True,
        )
        subprocess.run(
            ["security", "add-generic-password", "-s", service, "-a", account, "-w", value],
            capture_output=True,
            text=True,
            check=True,
        )
        return
    try:
        keyring.set_password(service, account, value)
    except keyring.errors.KeyringError as exc:
        click.echo(f"Keyring error: {exc}", err=True)
        click.echo(_KEYRING_HINT, err=True)
        sys.exit(1)


def _keychain_delete(service: str, account: str) -> None:
    if _IS_MACOS:
        subprocess.run(
            ["security", "delete-generic-password", "-s", service, "-a", account],
            capture_output=True,
        )
        return
    try:
        keyring.delete_password(service, account)
    except keyring.errors.PasswordDeleteError:
        pass
    except keyring.errors.KeyringError as exc:
        click.echo(f"Keyring error: {exc}", err=True)
        click.echo(_KEYRING_HINT, err=True)
        sys.exit(1)


def _cached_creds_get() -> tuple[str, str] | None:
    """Read cached credentials from the OS keyring if still within TTL."""
    timestamp = _keychain_read(_CRED_CACHE_SERVICE, "cache-ts")
    if not timestamp:
        return None
    try:
        if time.time() - float(timestamp) > _CRED_CACHE_TTL:
            return None
    except ValueError:
        return None
    username = _keychain_read(_CRED_CACHE_SERVICE, "cache-username")
    password = _keychain_read(_CRED_CACHE_SERVICE, "cache-password")
    return (username, password) if username and password else None


def _cached_creds_put(username: str, password: str) -> None:
    _keychain_write(_CRED_CACHE_SERVICE, "cache-username", username)
    _keychain_write(_CRED_CACHE_SERVICE, "cache-password", password)
    _keychain_write(_CRED_CACHE_SERVICE, "cache-ts", str(time.time()))


def _cached_creds_clear() -> None:
    for key in _CRED_CACHE_KEYS:
        _keychain_delete(_CRED_CACHE_SERVICE, key)


def _auth_1password(auth: dict[str, Any]) -> tuple[str, str]:
    def op_read(ref: str) -> str:
        cmd = ["op", "read", ref]
        session = os.environ.get("OP_SESSION")
        if session:
            cmd += ["--session", session]
        try:
            return subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
        except FileNotFoundError:
            click.echo("Error: `op` CLI not found.", err=True)
            sys.exit(1)
        except subprocess.CalledProcessError as exc:
            click.echo(f"op error: {exc.stderr.strip()}", err=True)
            if "promptError" in (exc.stderr or ""):
                click.echo(
                    "Hint: run this command in a terminal that can show Touch ID.\n"
                    "Credentials will be cached in the OS keyring for 30 min.",
                    err=True,
                )
            sys.exit(1)

    return op_read(auth["username_ref"]), op_read(auth["password_ref"])


def _auth_keychain(auth: dict[str, Any]) -> tuple[str, str]:
    service = auth["service"]
    username = _keychain_read(service, auth["username_account"])
    password = _keychain_read(service, auth["password_account"])
    if username is None or password is None:
        missing = "username" if username is None else "password"
        click.echo(f"Keyring: {missing} not found for service='{service}'", err=True)
        sys.exit(1)
    return username, password


def _auth_plain(auth: dict[str, Any]) -> tuple[str, str]:
    return auth["username"], auth["password"]


_AUTH_BACKENDS = {
    "1password": _auth_1password,
    "keychain": _auth_keychain,
    "plain": _auth_plain,
}


def creds(profile: dict[str, Any]) -> tuple[str, str]:
    global _creds_cache
    if _creds_cache is not None:
        return _creds_cache

    auth = profile["auth"]
    auth_type = auth["type"]

    if auth_type in ("1password", "keychain"):
        cached = _cached_creds_get()
        if cached:
            _creds_cache = cached
            return cached

    backend = _AUTH_BACKENDS.get(auth_type)
    if not backend:
        click.echo(f"Unknown auth type: {auth_type}", err=True)
        sys.exit(1)

    username, password = backend(auth)
    _creds_cache = (username, password)

    if auth_type in ("1password", "keychain"):
        _cached_creds_put(username, password)

    return username, password


def _cache_path(name: str) -> Path:
    config = _load_config()
    profile_name = config.get("active", "_default")
    profile_dir = CACHE_DIR / re.sub(r"[^\w\-.]", "_", profile_name)
    profile_dir.mkdir(parents=True, exist_ok=True)
    safe_name = re.sub(r"[^\w.-]", "_", name)
    return profile_dir / f"{safe_name}.json"


def cache_get(name: str, ttl: int) -> Any | None:
    path = _cache_path(name)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None
    if time.time() - data.get("_t", 0) > ttl:
        return None
    return data.get("_p")


def cache_put(name: str, payload: Any) -> None:
    path = _cache_path(name)
    path.write_text(json.dumps({"_t": time.time(), "_p": payload}, ensure_ascii=False))


def cache_clear_all() -> int:
    if not CACHE_DIR.exists():
        return 0
    count = 0
    for path in CACHE_DIR.rglob("*.json"):
        path.unlink()
        count += 1
    for directory in sorted(CACHE_DIR.rglob("*"), reverse=True):
        if directory.is_dir():
            with contextlib.suppress(OSError):
                directory.rmdir()
    return count


def _guard(method: str, path: str) -> None:
    if method not in ("GET", "POST"):
        click.echo(f"Blocked: {method}", err=True)
        sys.exit(1)
    lower_path = path.lower()
    for segment in BLOCKED_ENDPOINTS:
        if segment in lower_path:
            click.echo(f"Blocked: {segment}", err=True)
            sys.exit(1)
    if method == "POST" and not any(lower_path.endswith(ep) for ep in ALLOWED_POST_ENDPOINTS):
        click.echo(f"Blocked: POST {path}", err=True)
        sys.exit(1)


def _build_curl(
    url: str,
    method: str,
    path: str,
    body: dict[str, Any] | None,
    timeout: int,
    filter_path: str | None,
) -> str:
    actual_path = path + (
        ("&" if "?" in path else "?") + f"filter_path={filter_path}" if filter_path else ""
    )
    full_url = f"{url}/api/console/proxy?{urlencode({'path': actual_path, 'method': method})}"
    parts = [
        "curl -s",
        '-u "$USER:$PASS"',
        f'-X POST "{full_url}"',
        '-H "kbn-xsrf: true" -H "Content-Type: application/json"',
        f"--max-time {timeout}",
    ]
    if body:
        parts.append(f"-d '{json.dumps(body, ensure_ascii=False)}'")
    return " \\\n  ".join(parts)


def es(
    profile: dict[str, Any],
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
    *,
    timeout: int = DEFAULT_TIMEOUT,
    dry_run: bool = False,
    explain: bool = False,
    filter_path: str | None = None,
) -> dict[str, Any] | list[Any]:
    method = method.upper()
    _guard(method, path)
    if explain and body:
        click.echo(json.dumps(body, ensure_ascii=False, separators=(",", ":")), err=True)
    url = profile["kibana_url"].rstrip("/")
    prefix = _space_prefix(profile)
    if dry_run:
        click.echo(_build_curl(url + prefix, method, path, body, timeout, filter_path))
        sys.exit(0)

    username, password = creds(profile)
    actual_path = path + (
        ("&" if "?" in path else "?") + f"filter_path={filter_path}" if filter_path else ""
    )
    response = requests.post(
        f"{url}{prefix}/api/console/proxy",
        params={"path": actual_path, "method": method},
        headers={"kbn-xsrf": "true", "Content-Type": "application/json"},
        json=body,
        auth=(username, password),
        timeout=timeout,
    )
    if response.status_code >= 400:
        click.echo(f"ES {response.status_code}: {response.text[:300]}", err=True)
        sys.exit(1)
    if len(response.content) > MAX_RESPONSE_BYTES:
        click.echo(f"Warning: {len(response.content):,}B response", err=True)
    return response.json()  # type: ignore[no-any-return]


def _strip_empty(data: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in data.items() if v is not None and v != "" and v != [] and v != {}}


def _space_prefix(profile: dict[str, Any]) -> str:
    space = profile.get("space")
    return f"/s/{space}" if space else ""


def _resolve_index(profile: dict[str, Any], index_pattern: str | None) -> str:
    default_index = profile.get("index")
    if index_pattern is not None:
        if profile.get("restrict_index") and default_index and index_pattern != default_index:
            click.echo(
                f"Error: profile restricts index to '{default_index}', "
                f"got '{index_pattern}'.",
                err=True,
            )
            sys.exit(1)
        return index_pattern
    if default_index:
        return default_index
    click.echo("Error: no index pattern given and profile has no default index.", err=True)
    sys.exit(1)


def _format_hit(hit: dict[str, Any], field_list: list[str] | None) -> dict[str, Any]:
    source = hit.get("_source", {})
    if field_list:
        source = {k: source[k] for k in field_list if k in source}
    out = _strip_empty(source)
    if hit.get("sort"):
        out["_sort"] = hit["sort"]
    return out


def _format_search_result(
    data: dict[str, Any], field_list: list[str] | None, max_source_len: int
) -> dict[str, Any]:
    total = data.get("hits", {}).get("total", {})
    if isinstance(total, dict):
        total = total.get("value", "?")
    raw_hits = data.get("hits", {}).get("hits", [])
    truncated = len(raw_hits) > MAX_RESPONSE_HITS
    limited_hits = raw_hits[:MAX_RESPONSE_HITS] if truncated else raw_hits
    hits = []
    for hit in limited_hits:
        formatted = _format_hit(hit, field_list)
        serialized = json.dumps(formatted, ensure_ascii=False, separators=(",", ":"))
        if max_source_len and len(serialized) > max_source_len:
            hits.append({"_truncated": serialized[:max_source_len] + "…"})
        else:
            hits.append(formatted)
    result: dict[str, Any] = {"total": total, "n": len(hits)}
    if truncated:
        result["truncated"] = len(raw_hits)
    result["hits"] = hits
    if "aggregations" in data:
        result["aggs"] = data["aggregations"]
    return result


def _flatten_properties(properties: dict[str, Any], prefix: str = "") -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in properties.items():
        full_key = f"{prefix}.{key}" if prefix else key
        if "properties" in value:
            out.update(_flatten_properties(value["properties"], full_key))
        else:
            out[full_key] = value.get("type", "object")
    return out


def _parse_mapping(data: dict[str, Any]) -> dict[str, Any]:
    per_index: dict[str, dict[str, str]] = {}
    for index_name, mapping in data.items():
        per_index[index_name] = _flatten_properties(
            mapping.get("mappings", {}).get("properties", {})
        )
    groups: dict[str, tuple[list[str], dict[str, str]]] = {}
    for index_name, fields in per_index.items():
        fingerprint = hashlib.md5(json.dumps(fields, sort_keys=True).encode()).hexdigest()[:8]
        groups.setdefault(fingerprint, ([], fields))[0].append(index_name)
    result: dict[str, Any] = {}
    for _, (indices, fields) in groups.items():
        key = (
            indices[0]
            if len(indices) == 1
            else f"{os.path.commonprefix(indices)}* ({len(indices)})"
        )
        result[key] = fields
    return result


def _parse_aliases(data: dict[str, Any]) -> dict[str, list[str]]:
    alias_map: dict[str, list[str]] = {}
    for index_name, mapping in data.items():
        if index_name.startswith("."):
            continue
        for alias in mapping.get("aliases", {}):
            alias_map.setdefault(alias, []).append(index_name)
    for alias, indices in alias_map.items():
        if len(indices) > 5:
            alias_map[alias] = [f"{os.path.commonprefix(indices)}* ({len(indices)})"]
    return alias_map


def _extract_prefixes(raw: dict[str, Any]) -> list[str]:
    prefixes: set[str] = set()
    for index_name in raw:
        if index_name.startswith("."):
            continue
        parts = re.split(r"-\d{4}[.\-]", index_name)
        prefixes.add(parts[0] + "-*" if len(parts) > 1 else index_name)
    return sorted(prefixes)


def emit(data: Any, fmt: str) -> None:
    if fmt == "compact" and isinstance(data, dict) and "hits" in data:
        meta = {k: v for k, v in data.items() if k != "hits"}
        if meta:
            click.echo("#" + json.dumps(meta, ensure_ascii=False, separators=(",", ":")))
        for hit in data["hits"]:
            click.echo(json.dumps(hit, ensure_ascii=False, separators=(",", ":")))
    elif fmt == "compact":
        click.echo(json.dumps(data, ensure_ascii=False, separators=(",", ":")))
    else:
        click.echo(json.dumps(data, ensure_ascii=False, indent=2))


def fetch_aliases(
    profile: dict[str, Any], *, no_cache: bool = False, **kwargs: Any
) -> dict[str, list[str]]:
    if not no_cache:
        cached = cache_get("aliases", CACHE_TTL_ALIASES)
        if cached is not None:
            return cached  # type: ignore[no-any-return]
    data = es(profile, "GET", "_aliases", **kwargs)
    result = _parse_aliases(data)  # type: ignore[arg-type]
    cache_put("aliases", result)
    return result


def fetch_mapping(
    profile: dict[str, Any], index: str, *, no_cache: bool = False, **kwargs: Any
) -> dict[str, Any]:
    cache_name = f"mapping_{index}"
    if not no_cache:
        cached = cache_get(cache_name, CACHE_TTL_MAPPING)
        if cached is not None:
            return cached  # type: ignore[no-any-return]
    data = es(profile, "GET", f"{index}/_mapping", **kwargs)
    result = _parse_mapping(data)  # type: ignore[arg-type]
    cache_put(cache_name, result)
    return result


def _rison(obj: object) -> str:
    """Encode a Python object as a rison string (per https://github.com/nanonid/rison)."""
    if obj is True:
        return "!t"
    if obj is False:
        return "!f"
    if obj is None:
        return "!n"
    if isinstance(obj, (int, float)):
        return str(obj)
    if isinstance(obj, str):
        if re.match(r"^[a-zA-Z_~/.][-a-zA-Z0-9_~/.]*$", obj) and obj not in (
            "!t",
            "!f",
            "!n",
        ):
            return obj
        return "'" + obj.replace("!", "!!").replace("'", "!'") + "'"
    if isinstance(obj, (list, tuple)):
        return "!(" + ",".join(_rison(item) for item in obj) + ")"
    if isinstance(obj, dict):
        return "(" + ",".join(f"{_rison(k)}:{_rison(v)}" for k, v in obj.items()) + ")"
    return str(obj)


def common(f: Any) -> Any:
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


def _time_range_filter(time_range: str, field: str = "@timestamp") -> dict[str, Any]:
    return {"range": {field: {"gte": f"now-{time_range}"}}}


def _parse_fields(csv: str | None) -> list[str] | None:
    return [f.strip() for f in csv.split(",") if f.strip()] if csv else None


@click.group()
@click.version_option("0.3.0")
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
            _keychain_write(service, username_account, kc_set_username)
            click.echo(
                f"Stored username in OS keyring (service={service}, account={username_account})",
                err=True,
            )
        if kc_set_password:
            _keychain_write(service, password_account, kc_set_password)
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

    config = _load_config()
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
    _save_config(config)
    active_note = " (active)" if config["active"] == name else ""
    click.echo(f"Created profile '{name}'{active_note}")


@profile.command("list")
def profile_list() -> None:
    """List all profiles."""
    config = _load_config()
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
    config = _load_config()
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
    config = _load_config()
    if name not in config.get("profiles", {}):
        click.echo(f"Profile '{name}' not found.", err=True)
        sys.exit(1)
    config["active"] = name
    _save_config(config)
    click.echo(f"Active profile: {name}")


@profile.command("delete")
@click.argument("name")
def profile_delete(name: str) -> None:
    """Delete a profile."""
    config = _load_config()
    if name not in config.get("profiles", {}):
        click.echo(f"Profile '{name}' not found.", err=True)
        sys.exit(1)
    del config["profiles"][name]
    if config.get("active") == name:
        remaining = list(config["profiles"].keys())
        config["active"] = remaining[0] if remaining else None
    _save_config(config)
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
    config = _load_config()
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
            _keychain_write(service, acct, kc_set_username)
            click.echo("Updated username in OS keyring", err=True)
        if kc_set_password:
            acct = auth.get("password_account", f"{name}-password")
            _keychain_write(service, acct, kc_set_password)
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
    _save_config(config)
    click.echo(f"Updated profile '{name}'")


@cli.command()
@click.option("--refresh", is_flag=True, default=False)
@click.option("--indices", default=None, help="Index patterns (csv)")
@common
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
    prof = _get_profile(prof_name)
    kwargs = _es_kwargs(timeout, dry_run, explain, filter_path)
    if not refresh and not no_cache:
        cached = cache_get("context", CACHE_TTL_CONTEXT)
        if cached is not None:
            emit(cached, fmt)
            return

    raw = es(prof, "GET", "_aliases", **kwargs)
    aliases_data = _parse_aliases(raw)  # type: ignore[arg-type]
    cache_put("aliases", aliases_data)
    prefixes = _extract_prefixes(raw)  # type: ignore[arg-type]

    patterns = [p.strip() for p in indices.split(",")] if indices else prefixes[:5]

    mappings: dict[str, Any] = {}
    counts: dict[str, int] = {}
    for pattern in patterns:
        try:
            mapping = fetch_mapping(prof, pattern, no_cache=refresh or no_cache, **kwargs)
            mappings[pattern] = next(iter(mapping.values()))
        except SystemExit:
            pass
        try:
            count_result = es(
                prof, "POST", f"{pattern}/_count", {"query": _time_range_filter("1h")}, **kwargs
            )
            counts[pattern] = count_result.get("count", 0)  # type: ignore[union-attr]
        except (SystemExit, Exception):
            pass

    ctx = {
        "ts": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "prefixes": prefixes,
        "aliases": aliases_data,
        "mappings": mappings,
        "counts_1h": counts,
    }
    cache_put("context", ctx)
    emit(ctx, fmt)


@cli.command()
@common
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
    emit(
        fetch_aliases(
            _get_profile(prof_name),
            no_cache=no_cache,
            **_es_kwargs(timeout, dry_run, explain, filter_path),
        ),
        fmt,
    )


@cli.command()
@click.argument("index_pattern", required=False, default=None)
@click.option("--full", is_flag=True, default=False)
@common
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
    prof = _get_profile(prof_name)
    index_pattern = _resolve_index(prof, index_pattern)
    kwargs = _es_kwargs(timeout, dry_run, explain, filter_path)
    emit(
        es(prof, "GET", f"{index_pattern}/_mapping", **kwargs)
        if full
        else fetch_mapping(prof, index_pattern, no_cache=no_cache, **kwargs),
        fmt,
    )


@cli.command()
@click.argument("index_pattern", required=False, default=None)
@click.argument("glob", default="*")
@common
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
    prof = _get_profile(prof_name)
    index_pattern = _resolve_index(prof, index_pattern)
    flat = fetch_mapping(
        prof,
        index_pattern,
        no_cache=no_cache,
        **_es_kwargs(timeout, dry_run, explain, filter_path),
    )
    matched = {
        k: v
        for _, field_map in flat.items()
        for k, v in sorted(field_map.items())
        if fnmatch.fnmatch(k, glob)
    }
    emit(matched, fmt)


@cli.command()
@click.argument("index_pattern", required=False, default=None)
@click.option("--last", "time_range", default=DEFAULT_TIME_RANGE)
@click.option("-q", "--query", "extra_query", default=None)
@click.option("--kql", "kql_query", default=None, help="KQL filter")
@common
def count(
    index_pattern: str | None,
    time_range: str,
    extra_query: str | None,
    kql_query: str | None,
    prof_name: str | None,
    timeout: int,
    dry_run: bool,
    explain: bool,
    filter_path: str | None,
    fmt: str,
    no_cache: bool,
) -> None:
    """Count documents."""
    prof = _get_profile(prof_name)
    index_pattern = _resolve_index(prof, index_pattern)
    must = [_time_range_filter(time_range)]
    if extra_query:
        must.append(json.loads(extra_query))
    if kql_query:
        must.append(kql_to_es(kql_query))
    data = es(
        prof,
        "POST",
        f"{index_pattern}/_count",
        {"query": {"bool": {"must": must}}},
        **_es_kwargs(timeout, dry_run, explain, filter_path),
    )
    click.echo(data.get("count", data))  # type: ignore[union-attr]


@cli.command()
@click.argument("index_pattern", required=False, default=None)
@click.option("--last", "time_range", default=DEFAULT_TIME_RANGE)
@click.option("-n", "--size", default=DEFAULT_SIZE, type=int)
@click.option("-q", "--query", "extra_query", default=None)
@click.option("--kql", "kql_query", default=None, help="KQL filter")
@click.option("-f", "--fields", "field_csv", default=None)
@click.option("--sort", "sort_field", default=DEFAULT_SORT)
@click.option("--aggs", default=None)
@click.option("--max-source-len", "max_source_len", default=MAX_SOURCE_LEN, type=int)
@common
def search(
    index_pattern: str | None,
    time_range: str,
    size: int,
    extra_query: str | None,
    kql_query: str | None,
    field_csv: str | None,
    sort_field: str,
    aggs: str | None,
    max_source_len: int,
    prof_name: str | None,
    timeout: int,
    dry_run: bool,
    explain: bool,
    filter_path: str | None,
    fmt: str,
    no_cache: bool,
) -> None:
    """Search recent logs."""
    prof = _get_profile(prof_name)
    index_pattern = _resolve_index(prof, index_pattern)
    must = [_time_range_filter(time_range)]
    if extra_query:
        must.append(json.loads(extra_query))
    if kql_query:
        must.append(kql_to_es(kql_query))
    body: dict[str, Any] = {"query": {"bool": {"must": must}}, "size": size}
    sort_key, _, sort_order = sort_field.partition(":")
    body["sort"] = [{sort_key: sort_order or "desc"}]
    field_list = _parse_fields(field_csv)
    if field_list:
        body["_source"] = field_list
    if aggs:
        body["aggregations"] = json.loads(aggs)
    data = es(
        prof,
        "POST",
        f"{index_pattern}/_search",
        body,
        **_es_kwargs(timeout, dry_run, explain, filter_path),
    )
    emit(_format_search_result(data, field_list, max_source_len), fmt)  # type: ignore[arg-type]


@cli.command()
@click.argument("index_pattern", required=False, default=None)
@click.option("--interval", default=2.0, type=float)
@click.option("--last", "time_range", default="1m")
@click.option("-q", "--query", "extra_query", default=None)
@click.option("--kql", "kql_query", default=None, help="KQL filter")
@click.option("-f", "--fields", "field_csv", default=None)
@click.option("-n", "--size", default=50, type=int)
@click.option("--max-source-len", "max_source_len", default=MAX_SOURCE_LEN, type=int)
@common
def tail(
    index_pattern: str | None,
    interval: float,
    time_range: str,
    extra_query: str | None,
    kql_query: str | None,
    field_csv: str | None,
    size: int,
    max_source_len: int,
    prof_name: str | None,
    timeout: int,
    dry_run: bool,
    explain: bool,
    filter_path: str | None,
    fmt: str,
    no_cache: bool,
) -> None:
    """Stream logs (search_after). Ctrl+C to stop."""
    prof = _get_profile(prof_name)
    index_pattern = _resolve_index(prof, index_pattern)
    field_list = _parse_fields(field_csv)
    base_must: list[Any] = [json.loads(extra_query)] if extra_query else []
    if kql_query:
        base_must.append(kql_to_es(kql_query))
    search_after: list[Any] | None = None
    first = True

    def _handle_sigint(*_: object) -> None:
        click.echo("", err=True)
        sys.exit(0)

    signal.signal(signal.SIGINT, _handle_sigint)

    while True:
        must = list(base_must)
        if search_after is None:
            must.append(_time_range_filter(time_range))
        body: dict[str, Any] = {
            "query": {"bool": {"must": must}},
            "size": size,
            "sort": [{"@timestamp": "asc"}, {"_id": "asc"}],
        }
        if field_list:
            body["_source"] = field_list
        if search_after is not None:
            body["search_after"] = search_after
        try:
            data = es(
                prof,
                "POST",
                f"{index_pattern}/_search",
                body,
                **_es_kwargs(timeout, dry_run, explain and first, filter_path),
            )
        except SystemExit:
            raise
        except Exception as exc:
            click.echo(f"err: {exc}", err=True)
            time.sleep(interval)
            continue
        for hit in data.get("hits", {}).get("hits", []):  # type: ignore[union-attr]
            formatted = _format_hit(hit, field_list)
            serialized = json.dumps(formatted, ensure_ascii=False, separators=(",", ":"))
            click.echo(
                serialized[:max_source_len] + "…"
                if max_source_len and len(serialized) > max_source_len
                else serialized
            )
        hits = data.get("hits", {}).get("hits", [])  # type: ignore[union-attr]
        if hits:
            search_after = hits[-1].get("sort")
        first = False
        time.sleep(interval)


@cli.command()
@click.argument("index_pattern", required=False, default=None)
@click.option("--last", "time_range", default=DEFAULT_TIME_RANGE)
@click.option("--interval", default="5m")
@click.option("-q", "--query", "extra_query", default=None)
@click.option("--kql", "kql_query", default=None, help="KQL filter")
@click.option("--field", "time_field", default="@timestamp")
@common
def histogram(
    index_pattern: str | None,
    time_range: str,
    interval: str,
    extra_query: str | None,
    kql_query: str | None,
    time_field: str,
    prof_name: str | None,
    timeout: int,
    dry_run: bool,
    explain: bool,
    filter_path: str | None,
    fmt: str,
    no_cache: bool,
) -> None:
    """Date histogram of doc counts."""
    prof = _get_profile(prof_name)
    index_pattern = _resolve_index(prof, index_pattern)
    must = [_time_range_filter(time_range, time_field)]
    if extra_query:
        must.append(json.loads(extra_query))
    if kql_query:
        must.append(kql_to_es(kql_query))
    body: dict[str, Any] = {
        "size": 0,
        "query": {"bool": {"must": must}},
        "aggregations": {
            "t": {
                "date_histogram": {
                    "field": time_field,
                    "fixed_interval": interval,
                    "min_doc_count": 0,
                }
            }
        },
    }
    data = es(
        prof,
        "POST",
        f"{index_pattern}/_search",
        body,
        **_es_kwargs(timeout, dry_run, explain, filter_path),
    )
    buckets = data.get("aggregations", {}).get("t", {}).get("buckets", [])  # type: ignore[union-attr]
    total = data.get("hits", {}).get("total", {})  # type: ignore[union-attr]
    if isinstance(total, dict):
        total = total.get("value", "?")
    emit(
        {
            "total": total,
            "interval": interval,
            "buckets": [{"t": b["key_as_string"], "n": b["doc_count"]} for b in buckets],
        },
        fmt,
    )


@cli.command()
@click.argument("index_pattern", required=False, default=None)
@click.option("--last", "time_range", default=DEFAULT_TIME_RANGE)
@click.option("--kql", default=None, help="KQL query")
@click.option("--lucene", default=None, help="Lucene query")
@click.option("-f", "--fields", "field_csv", default=None, help="Columns (csv)")
@click.option("--profile", "prof_name", default=None, envvar="KIBANA_AGENT_PROFILE")
def discover(
    index_pattern: str | None,
    time_range: str,
    kql: str | None,
    lucene: str | None,
    field_csv: str | None,
    prof_name: str | None,
) -> None:
    """Build a Kibana Discover URL."""
    if kql and lucene:
        click.echo("Error: --kql or --lucene, not both.", err=True)
        sys.exit(1)
    prof = _get_profile(prof_name)
    index_pattern = _resolve_index(prof, index_pattern)
    prefix = _space_prefix(prof)
    lang = "kuery" if not lucene else "lucene"
    global_state = {
        "time": {"from": f"now-{time_range}", "to": "now"},
        "refreshInterval": {"pause": True, "value": 0},
    }
    app_state: dict[str, Any] = {
        "query": {"language": lang, "query": kql or lucene or ""},
    }
    columns = _parse_fields(field_csv)
    if columns:
        app_state["columns"] = columns
    click.echo(
        f"{prof['kibana_url']}{prefix}/app/discover#/?_g={_rison(global_state)}&_a={_rison(app_state)}"
    )
    click.echo(f"Note: select the '{index_pattern}' data view manually in Kibana.", err=True)


@cli.command()
@click.argument("method", type=click.Choice(["GET", "POST"], case_sensitive=False))
@click.argument("es_path")
@click.option("--body", default=None)
@common
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
    data = es(
        _get_profile(prof_name),
        method.upper(),
        es_path,
        json.loads(body) if body else None,
        **_es_kwargs(timeout, dry_run, explain, filter_path),
    )
    emit(data, fmt)


@cli.command("cache-clear")
def cache_clear() -> None:
    """Wipe all cached data (including OS keyring credential cache)."""
    _cached_creds_clear()
    click.echo(f"Cleared {cache_clear_all()} files from {CACHE_DIR}")
    click.echo("Cleared cached credentials from OS keyring.")


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
- `kibana-agent cache-clear` — wipe cached data.

## Typical agent workflow

1. `kibana-agent context` — learn what indices and fields exist.
2. `kibana-agent search <idx> --last 1h -n 3` — sample recent docs.
3. Refine: add `-q`, `-f`, `--aggs`, adjust `--last` and `-n`.
4. `kibana-agent histogram <idx> --last 6h --interval 10m` — spot trends.
5. `kibana-agent count <idx> --last 1h -q '{"match":{"level":"ERROR"}}'`
   — quantify issues.

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

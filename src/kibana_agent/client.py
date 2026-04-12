"""
kibana-agent client — pure business logic shared by the CLI and the MCP server.

This module knows nothing about Click or MCP. It exposes:

* Typed exceptions (``KibanaAgentError`` and friends) instead of ``sys.exit``.
* Profile resolution (``resolve_profile``) supporting CLI flags, env vars, and
  the on-disk config file.
* Low-level Elasticsearch helpers (``es``, ``_guard``, cache, auth, ...).
* High-level operations (``op_search``, ``op_count``, ...) that both the CLI
  command bodies and the MCP tool wrappers call.
"""

from __future__ import annotations

import contextlib
import fnmatch
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import keyring
import keyring.errors
import requests

from kibana_agent.kql import kql_to_es


class KibanaAgentError(Exception):
    """Base class for all kibana-agent errors raised from the client layer."""


class ProfileNotFoundError(KibanaAgentError):
    """No profile could be resolved from arguments, env, or config."""


class BlockedRequestError(KibanaAgentError):
    """A method/path was rejected by the read-only safety guard."""


class KibanaApiError(KibanaAgentError):
    """The Kibana / Elasticsearch API returned a 4xx or 5xx response."""

    def __init__(self, status: int, body: str) -> None:
        self.status = status
        self.body = body
        super().__init__(f"ES {status}: {body[:300]}")


class AuthError(KibanaAgentError):
    """Failed to obtain credentials from the configured auth backend."""


class IndexResolutionError(KibanaAgentError):
    """Could not pick an index pattern from arguments and the active profile."""


class DryRunResult(KibanaAgentError):
    """Raised by ``es`` when ``dry_run=True``; carries the rendered curl string."""

    def __init__(self, curl: str) -> None:
        self.curl = curl
        super().__init__(curl)


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


def _resolve_dir(
    env_override: str,
    xdg_var: str,
    win_var: str,
    win_subdir: str,
    unix_default: Path,
) -> Path:
    """Resolve a per-user directory: env override → platform default."""
    override = os.environ.get(env_override)
    if override:
        return Path(override).expanduser()
    if sys.platform == "win32":
        base = os.environ.get(win_var)
        if not base:
            base = str(
                Path.home() / "AppData" / ("Local" if win_subdir else "Roaming")
            )
        path = Path(base) / "kibana-agent"
        return path / win_subdir if win_subdir else path
    xdg = os.environ.get(xdg_var)
    if xdg:
        return Path(xdg) / "kibana-agent"
    return unix_default


CONFIG_DIR = _resolve_dir(
    "KIBANA_AGENT_CONFIG_DIR",
    "XDG_CONFIG_HOME",
    "APPDATA",
    "",
    Path.home() / ".config" / "kibana-agent",
)
CONFIG_FILE = CONFIG_DIR / "config.json"
CACHE_DIR = _resolve_dir(
    "KIBANA_AGENT_CACHE_DIR",
    "XDG_CACHE_HOME",
    "LOCALAPPDATA",
    "Cache",
    Path.home() / ".cache" / "kibana-agent",
)


def load_config() -> dict[str, Any]:
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text())  # type: ignore[no-any-return]
        except (json.JSONDecodeError, OSError):
            pass
    return {"active": None, "profiles": {}}


def save_config(config: dict[str, Any]) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(config, indent=2, ensure_ascii=False) + "\n")


def get_profile(name: str | None = None) -> dict[str, Any]:
    """Load a named profile from the config file (or the active one)."""
    config = load_config()
    profile_name = name or config.get("active")
    if not profile_name:
        raise ProfileNotFoundError("No active profile. Run: profile create <name> ...")
    profile_data = config.get("profiles", {}).get(profile_name)
    if not profile_data:
        raise ProfileNotFoundError(
            f"Profile '{profile_name}' not found. Run: profile list"
        )
    return profile_data  # type: ignore[no-any-return]


_IS_MACOS = sys.platform == "darwin"


def keychain_read(service: str, account: str) -> str | None:
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
        raise AuthError(f"Keyring error: {exc}\n{_KEYRING_HINT}") from exc


def keychain_write(service: str, account: str, value: str) -> None:
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
        raise AuthError(f"Keyring error: {exc}\n{_KEYRING_HINT}") from exc


def keychain_delete(service: str, account: str) -> None:
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
        raise AuthError(f"Keyring error: {exc}\n{_KEYRING_HINT}") from exc


def _cached_creds_get() -> tuple[str, str] | None:
    """Read cached credentials from the OS keyring if still within TTL."""
    timestamp = keychain_read(_CRED_CACHE_SERVICE, "cache-ts")
    if not timestamp:
        return None
    try:
        if time.time() - float(timestamp) > _CRED_CACHE_TTL:
            return None
    except ValueError:
        return None
    username = keychain_read(_CRED_CACHE_SERVICE, "cache-username")
    password = keychain_read(_CRED_CACHE_SERVICE, "cache-password")
    return (username, password) if username and password else None


def _cached_creds_put(username: str, password: str) -> None:
    keychain_write(_CRED_CACHE_SERVICE, "cache-username", username)
    keychain_write(_CRED_CACHE_SERVICE, "cache-password", password)
    keychain_write(_CRED_CACHE_SERVICE, "cache-ts", str(time.time()))


def cached_creds_clear() -> None:
    for key in _CRED_CACHE_KEYS:
        keychain_delete(_CRED_CACHE_SERVICE, key)


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
        except FileNotFoundError as exc:
            raise AuthError("`op` CLI not found.") from exc
        except subprocess.CalledProcessError as exc:
            hint = ""
            if "promptError" in (exc.stderr or ""):
                hint = (
                    "\nHint: run this command in a terminal that can show Touch ID. "
                    "Credentials will be cached in the OS keyring for 30 min."
                )
            raise AuthError(f"op error: {(exc.stderr or '').strip()}{hint}") from exc

    return op_read(auth["username_ref"]), op_read(auth["password_ref"])


def _auth_keychain(auth: dict[str, Any]) -> tuple[str, str]:
    service = auth["service"]
    username = keychain_read(service, auth["username_account"])
    password = keychain_read(service, auth["password_account"])
    if username is None or password is None:
        missing = "username" if username is None else "password"
        raise AuthError(f"Keyring: {missing} not found for service='{service}'")
    return username, password


def _auth_plain(auth: dict[str, Any]) -> tuple[str, str]:
    return auth["username"], auth["password"]


_AUTH_BACKENDS: dict[str, Any] = {
    "1password": _auth_1password,
    "keychain": _auth_keychain,
    "plain": _auth_plain,
}


def _profile_cache_key(profile: dict[str, Any]) -> str:
    auth = profile.get("auth", {})
    return "|".join(
        [
            profile.get("kibana_url", ""),
            auth.get("type", ""),
            auth.get("username_ref", ""),
            auth.get("service", ""),
            auth.get("username_account", ""),
        ]
    )


# Per-process credential cache, keyed by profile identity so a long-lived
# MCP server process can serve multiple profiles without leaking creds
# between them.
_creds_cache: dict[str, tuple[str, str]] = {}


def creds(profile: dict[str, Any]) -> tuple[str, str]:
    key = _profile_cache_key(profile)
    cached_in_mem = _creds_cache.get(key)
    if cached_in_mem is not None:
        return cached_in_mem

    auth = profile["auth"]
    auth_type = auth["type"]

    if auth_type in ("1password", "keychain"):
        cached = _cached_creds_get()
        if cached:
            _creds_cache[key] = cached
            return cached

    backend = _AUTH_BACKENDS.get(auth_type)
    if not backend:
        raise AuthError(f"Unknown auth type: {auth_type}")

    username, password = backend(auth)
    _creds_cache[key] = (username, password)

    if auth_type in ("1password", "keychain"):
        _cached_creds_put(username, password)

    return username, password


def _cache_path(name: str) -> Path:
    config = load_config()
    profile_name = config.get("active") or "_default"
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


def _profile_from_env() -> dict[str, Any] | None:
    """Build an ephemeral in-memory profile from KIBANA_* env vars, if set.

    Recognised env vars:
      KIBANA_URL                  (required to trigger this path)
      KIBANA_SPACE                (optional)
      KIBANA_INDEX                (optional default index pattern)
      KIBANA_USERNAME / KIBANA_PASSWORD          → ``plain`` auth
      KIBANA_USERNAME_OP_REF / KIBANA_PASSWORD_OP_REF → ``1password`` auth

    Returns ``None`` if KIBANA_URL is not set.
    """
    url = os.environ.get("KIBANA_URL")
    if not url:
        return None

    profile: dict[str, Any] = {"kibana_url": url.rstrip("/")}
    if space := os.environ.get("KIBANA_SPACE"):
        profile["space"] = space
    if index := os.environ.get("KIBANA_INDEX"):
        profile["index"] = index

    op_user = os.environ.get("KIBANA_USERNAME_OP_REF")
    op_pass = os.environ.get("KIBANA_PASSWORD_OP_REF")
    plain_user = os.environ.get("KIBANA_USERNAME")
    plain_pass = os.environ.get("KIBANA_PASSWORD")

    if op_user and op_pass:
        profile["auth"] = {
            "type": "1password",
            "username_ref": op_user,
            "password_ref": op_pass,
        }
    elif plain_user and plain_pass:
        profile["auth"] = {
            "type": "plain",
            "username": plain_user,
            "password": plain_pass,
        }
    else:
        raise ProfileNotFoundError(
            "KIBANA_URL is set but credentials are missing. Set either "
            "KIBANA_USERNAME + KIBANA_PASSWORD or "
            "KIBANA_USERNAME_OP_REF + KIBANA_PASSWORD_OP_REF."
        )
    return profile


def resolve_profile(name: str | None = None) -> dict[str, Any]:
    """Resolve a Kibana profile.

    Resolution order:

    1. Explicit ``name`` argument (CLI ``--profile`` flag or MCP tool arg).
    2. ``KIBANA_AGENT_PROFILE`` environment variable.
    3. ``KIBANA_URL`` env var → ephemeral in-memory profile (never written to
       disk). Credentials come from KIBANA_USERNAME/PASSWORD or
       KIBANA_USERNAME_OP_REF/PASSWORD_OP_REF.
    4. The ``active`` profile in the on-disk config file.
    5. Otherwise: :class:`ProfileNotFoundError`.
    """
    if name:
        return get_profile(name)

    env_name = os.environ.get("KIBANA_AGENT_PROFILE")
    if env_name:
        return get_profile(env_name)

    env_profile = _profile_from_env()
    if env_profile is not None:
        return env_profile

    config = load_config()
    if config.get("active"):
        return get_profile(None)

    raise ProfileNotFoundError(
        "No Kibana profile found. Either run "
        "`kibana-agent profile create <name> ...` to create one, or set "
        "KIBANA_URL + KIBANA_USERNAME + KIBANA_PASSWORD in your environment."
    )


def _guard(method: str, path: str) -> None:
    if method not in ("GET", "POST"):
        raise BlockedRequestError(f"Blocked: {method}")
    lower_path = path.lower()
    for segment in BLOCKED_ENDPOINTS:
        if segment in lower_path:
            raise BlockedRequestError(f"Blocked: {segment}")
    if method == "POST" and not any(lower_path.endswith(ep) for ep in ALLOWED_POST_ENDPOINTS):
        raise BlockedRequestError(f"Blocked: POST {path}")


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
    """Make a single read-only request through the Kibana console proxy.

    Raises :class:`BlockedRequestError` if the safety guard rejects the call,
    :class:`KibanaApiError` on any 4xx/5xx response, and :class:`DryRunResult`
    (carrying the rendered curl string) when ``dry_run=True``.
    """
    method = method.upper()
    _guard(method, path)
    if explain and body:
        sys.stderr.write(json.dumps(body, ensure_ascii=False, separators=(",", ":")) + "\n")
    url = profile["kibana_url"].rstrip("/")
    prefix = _space_prefix(profile)
    if dry_run:
        raise DryRunResult(_build_curl(url + prefix, method, path, body, timeout, filter_path))

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
        raise KibanaApiError(response.status_code, response.text)
    if len(response.content) > MAX_RESPONSE_BYTES:
        sys.stderr.write(f"Warning: {len(response.content):,}B response\n")
    return response.json()  # type: ignore[no-any-return]


def _strip_empty(data: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in data.items() if v is not None and v != "" and v != [] and v != {}}


def _space_prefix(profile: dict[str, Any]) -> str:
    space = profile.get("space")
    return f"/s/{space}" if space else ""


def _resolve_index(profile: dict[str, Any], index_pattern: str | None) -> str:
    default_index: str | None = profile.get("index")
    if index_pattern is not None:
        if profile.get("restrict_index") and default_index and index_pattern != default_index:
            raise IndexResolutionError(
                f"Profile restricts index to '{default_index}', got '{index_pattern}'."
            )
        return index_pattern
    if default_index:
        return default_index
    raise IndexResolutionError(
        "No index pattern given and profile has no default index."
    )


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


def _time_range_filter(time_range: str, field: str = "@timestamp") -> dict[str, Any]:
    return {"range": {field: {"gte": f"now-{time_range}"}}}


def _parse_fields(csv: str | None) -> list[str] | None:
    return [f.strip() for f in csv.split(",") if f.strip()] if csv else None


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


def _build_must(
    time_range: str | None,
    extra_query: str | dict[str, Any] | None,
    kql: str | None,
    time_field: str = "@timestamp",
) -> list[dict[str, Any]]:
    must: list[dict[str, Any]] = []
    if time_range:
        must.append(_time_range_filter(time_range, time_field))
    if extra_query:
        must.append(extra_query if isinstance(extra_query, dict) else json.loads(extra_query))
    if kql:
        must.append(kql_to_es(kql))
    return must


def op_search(
    profile: dict[str, Any],
    index_pattern: str,
    *,
    time_range: str = DEFAULT_TIME_RANGE,
    extra_query: str | dict[str, Any] | None = None,
    kql: str | None = None,
    size: int = DEFAULT_SIZE,
    sort: str = DEFAULT_SORT,
    fields: list[str] | None = None,
    aggs: dict[str, Any] | None = None,
    max_source_len: int = MAX_SOURCE_LEN,
    **es_kwargs: Any,
) -> dict[str, Any]:
    """Search recent logs in an index pattern."""
    body: dict[str, Any] = {
        "query": {"bool": {"must": _build_must(time_range, extra_query, kql)}},
        "size": size,
    }
    sort_key, _, sort_order = sort.partition(":")
    body["sort"] = [{sort_key: sort_order or "desc"}]
    if fields:
        body["_source"] = fields
    if aggs is not None:
        body["aggregations"] = aggs
    data = es(profile, "POST", f"{index_pattern}/_search", body, **es_kwargs)
    return _format_search_result(data, fields, max_source_len)  # type: ignore[arg-type]


def op_count(
    profile: dict[str, Any],
    index_pattern: str,
    *,
    time_range: str = DEFAULT_TIME_RANGE,
    extra_query: str | dict[str, Any] | None = None,
    kql: str | None = None,
    **es_kwargs: Any,
) -> int:
    """Count documents matching a query."""
    body = {"query": {"bool": {"must": _build_must(time_range, extra_query, kql)}}}
    data = es(profile, "POST", f"{index_pattern}/_count", body, **es_kwargs)
    return int(data.get("count", 0))  # type: ignore[union-attr]


def op_histogram(
    profile: dict[str, Any],
    index_pattern: str,
    *,
    time_range: str = DEFAULT_TIME_RANGE,
    interval: str = "5m",
    extra_query: str | dict[str, Any] | None = None,
    kql: str | None = None,
    time_field: str = "@timestamp",
    **es_kwargs: Any,
) -> dict[str, Any]:
    """Date histogram aggregation of doc counts."""
    body: dict[str, Any] = {
        "size": 0,
        "query": {"bool": {"must": _build_must(time_range, extra_query, kql, time_field)}},
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
    data = es(profile, "POST", f"{index_pattern}/_search", body, **es_kwargs)
    buckets = data.get("aggregations", {}).get("t", {}).get("buckets", [])  # type: ignore[union-attr]
    total = data.get("hits", {}).get("total", {})  # type: ignore[union-attr]
    if isinstance(total, dict):
        total = total.get("value", "?")
    return {
        "total": total,
        "interval": interval,
        "buckets": [{"t": b["key_as_string"], "n": b["doc_count"]} for b in buckets],
    }


def op_context(
    profile: dict[str, Any],
    *,
    indices: str | None = None,
    refresh: bool = False,
    no_cache: bool = False,
    **es_kwargs: Any,
) -> dict[str, Any]:
    """Compact context summary: aliases, prefixes, mappings, recent doc counts.

    Cached for ``CACHE_TTL_CONTEXT`` seconds. Pass ``refresh=True`` to force a
    fresh fetch.
    """
    if not refresh and not no_cache:
        cached = cache_get("context", CACHE_TTL_CONTEXT)
        if cached is not None:
            return cached  # type: ignore[no-any-return]

    raw = es(profile, "GET", "_aliases", **es_kwargs)
    aliases_data = _parse_aliases(raw)  # type: ignore[arg-type]
    cache_put("aliases", aliases_data)
    prefixes = _extract_prefixes(raw)  # type: ignore[arg-type]

    patterns = [p.strip() for p in indices.split(",")] if indices else prefixes[:5]

    mappings: dict[str, Any] = {}
    counts: dict[str, int] = {}
    for pattern in patterns:
        try:
            mapping = fetch_mapping(
                profile, pattern, no_cache=refresh or no_cache, **es_kwargs
            )
            mappings[pattern] = next(iter(mapping.values()))
        except KibanaAgentError:
            pass
        try:
            count_result = es(
                profile,
                "POST",
                f"{pattern}/_count",
                {"query": _time_range_filter("1h")},
                **es_kwargs,
            )
            counts[pattern] = int(count_result.get("count", 0))  # type: ignore[union-attr]
        except (KibanaAgentError, Exception):
            pass

    ctx = {
        "ts": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "prefixes": prefixes,
        "aliases": aliases_data,
        "mappings": mappings,
        "counts_1h": counts,
    }
    cache_put("context", ctx)
    return ctx


def op_mapping(
    profile: dict[str, Any],
    index_pattern: str,
    *,
    full: bool = False,
    no_cache: bool = False,
    **es_kwargs: Any,
) -> dict[str, Any]:
    """Field mapping for an index pattern (flat field:type, deduped)."""
    if full:
        return es(  # type: ignore[return-value]
            profile, "GET", f"{index_pattern}/_mapping", **es_kwargs
        )
    return fetch_mapping(profile, index_pattern, no_cache=no_cache, **es_kwargs)


def op_fields(
    profile: dict[str, Any],
    index_pattern: str,
    *,
    glob: str = "*",
    no_cache: bool = False,
    **es_kwargs: Any,
) -> dict[str, str]:
    """Field names matching ``glob`` (e.g. ``*.host``, ``log.*``)."""
    flat = fetch_mapping(profile, index_pattern, no_cache=no_cache, **es_kwargs)
    return {
        k: v
        for _, field_map in flat.items()
        for k, v in sorted(field_map.items())
        if fnmatch.fnmatch(k, glob)
    }


def op_aliases(
    profile: dict[str, Any], *, no_cache: bool = False, **es_kwargs: Any
) -> dict[str, list[str]]:
    """List index aliases."""
    return fetch_aliases(profile, no_cache=no_cache, **es_kwargs)


def op_tail_page(
    profile: dict[str, Any],
    index_pattern: str,
    *,
    since_cursor: list[Any] | None = None,
    time_range: str = "1m",
    extra_query: str | dict[str, Any] | None = None,
    kql: str | None = None,
    size: int = 50,
    fields: list[str] | None = None,
    max_source_len: int = MAX_SOURCE_LEN,
    **es_kwargs: Any,
) -> dict[str, Any]:
    """Fetch one page of new logs using ``search_after``.

    Returns ``{"hits": [...], "next_cursor": [...] | None}``. Pass the
    returned ``next_cursor`` back in as ``since_cursor`` on the next call to
    follow live logs.
    """
    must: list[dict[str, Any]] = []
    if extra_query:
        must.append(extra_query if isinstance(extra_query, dict) else json.loads(extra_query))
    if kql:
        must.append(kql_to_es(kql))
    if since_cursor is None:
        must.append(_time_range_filter(time_range))
    body: dict[str, Any] = {
        "query": {"bool": {"must": must}},
        "size": size,
        "sort": [{"@timestamp": "asc"}, {"_id": "asc"}],
    }
    if fields:
        body["_source"] = fields
    if since_cursor is not None:
        body["search_after"] = since_cursor
    data = es(profile, "POST", f"{index_pattern}/_search", body, **es_kwargs)
    raw_hits = data.get("hits", {}).get("hits", [])  # type: ignore[union-attr]
    formatted_hits: list[dict[str, Any]] = []
    for hit in raw_hits:
        formatted = _format_hit(hit, fields)
        serialized = json.dumps(formatted, ensure_ascii=False, separators=(",", ":"))
        if max_source_len and len(serialized) > max_source_len:
            formatted_hits.append({"_truncated": serialized[:max_source_len] + "…"})
        else:
            formatted_hits.append(formatted)
    next_cursor = raw_hits[-1].get("sort") if raw_hits else since_cursor
    return {"hits": formatted_hits, "next_cursor": next_cursor}


def op_raw(
    profile: dict[str, Any],
    method: str,
    es_path: str,
    *,
    body: str | dict[str, Any] | None = None,
    **es_kwargs: Any,
) -> dict[str, Any] | list[Any]:
    """Raw read-only Elasticsearch request (gated by the safety guard)."""
    parsed_body: dict[str, Any] | None
    if body is None:
        parsed_body = None
    elif isinstance(body, str):
        parsed_body = json.loads(body)
    else:
        parsed_body = body
    return es(profile, method.upper(), es_path, parsed_body, **es_kwargs)


def op_discover_url(
    profile: dict[str, Any],
    index_pattern: str,
    *,
    time_range: str = DEFAULT_TIME_RANGE,
    kql: str | None = None,
    lucene: str | None = None,
    fields: list[str] | None = None,
) -> dict[str, str]:
    """Build a Kibana Discover URL pre-filled with a query and time range."""
    if kql and lucene:
        raise KibanaAgentError("Provide --kql or --lucene, not both.")
    prefix = _space_prefix(profile)
    lang = "kuery" if not lucene else "lucene"
    global_state = {
        "time": {"from": f"now-{time_range}", "to": "now"},
        "refreshInterval": {"pause": True, "value": 0},
    }
    app_state: dict[str, Any] = {
        "query": {"language": lang, "query": kql or lucene or ""},
    }
    if fields:
        app_state["columns"] = fields
    url = (
        f"{profile['kibana_url']}{prefix}/app/discover#/?"
        f"_g={_rison(global_state)}&_a={_rison(app_state)}"
    )
    return {
        "url": url,
        "data_view_hint": f"Select the '{index_pattern}' data view manually in Kibana.",
    }


def op_list_profiles() -> list[dict[str, Any]]:
    """List all configured profiles (read-only — no credentials returned)."""
    config = load_config()
    active = config.get("active")
    out: list[dict[str, Any]] = []
    for name, profile_data in config.get("profiles", {}).items():
        out.append(
            {
                "name": name,
                "active": name == active,
                "kibana_url": profile_data.get("kibana_url"),
                "auth_type": profile_data.get("auth", {}).get("type"),
                "space": profile_data.get("space"),
                "index": profile_data.get("index"),
                "restrict_space": profile_data.get("restrict_space", False),
                "restrict_index": profile_data.get("restrict_index", False),
            }
        )
    return out

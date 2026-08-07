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
import difflib
import fnmatch
import hashlib
import importlib.metadata
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
DEFAULT_TIME_FIELD = "@timestamp"
DEFAULT_SORT = f"{DEFAULT_TIME_FIELD}:desc"
DEFAULT_TIMEOUT = 30
MAX_SOURCE_LEN = 1000
MAX_RESPONSE_HITS = 500
MAX_RESPONSE_BYTES = 2_000_000
MAX_CONTEXT_FIELDS = 60
CACHE_TTL_ALIASES = 86400
CACHE_TTL_MAPPING = 86400
CACHE_TTL_CONTEXT = 86400

try:
    CACHE_VERSION = importlib.metadata.version("kibana-agent")
except importlib.metadata.PackageNotFoundError:  # source checkout, not installed
    CACHE_VERSION = "dev"

_CRED_CACHE_SERVICE = "kibana-agent"
_CRED_CACHE_TTL_DEFAULT = 24 * 3600  # 24 hours
_CRED_CACHE_TTL_ENV = "KIBANA_AGENT_CRED_CACHE_TTL"
_CRED_CACHE_TTL_CONFIG_KEY = "cred_cache_ttl"
_CRED_CACHE_KEYS = ("cache-username", "cache-password", "cache-ts")

_FIELD_CLAUSES = (
    "match",
    "match_phrase",
    "match_phrase_prefix",
    "term",
    "terms",
    "range",
    "wildcard",
    "prefix",
    "regexp",
    "fuzzy",
)
_EXACT_CLAUSES = ("term", "terms")
_ANALYZED_TYPES = ("text", "match_only_text", "annotated_text")
_EXACT_TYPES = ("keyword", "constant_keyword", "wildcard")
_DATE_TYPES = ("date", "date_nanos")
_AGGREGATABLE_TYPES = (
    _EXACT_TYPES
    + _DATE_TYPES
    + (
        "long",
        "integer",
        "short",
        "byte",
        "double",
        "float",
        "half_float",
        "scaled_float",
        "boolean",
        "ip",
    )
)
_TIME_FIELD_PREFERENCE = ("@timestamp", "timestamp", "time", "event.created", "event.ingested")
_EXPAND_JSON_DEPTH = 4
_PREFIX_GROUP_MIN = 6
_DATED_INDEX = re.compile(r"^(?P<stem>.+?)-(?:\d{4}[.\-]\d{2}|\d{4,})[.\-\d]*$")
_CAPPED_TOTAL_HINT = (
    "total={total} is a floor, not the real count: Elasticsearch stops counting "
    "at 10,000. Use `count` for an exact number, or `histogram`, whose bucket "
    "counts are exact."
)

PROFILE_NAME_KEY = "_name"

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
            base = str(Path.home() / "AppData" / ("Local" if win_subdir else "Roaming"))
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
        raise ProfileNotFoundError(f"Profile '{profile_name}' not found. Run: profile list")
    profile_data[PROFILE_NAME_KEY] = profile_name
    return profile_data  # type: ignore[no-any-return]


def profile_label(profile: dict[str, Any]) -> str:
    """
    Return a stable name for a profile, for messages and cache keys.
    A profile built from environment variables has no name, so fall back to a
    short hash of its identity.
    """
    named = profile.get(PROFILE_NAME_KEY)
    if named:
        return str(named)
    digest = hashlib.md5(_profile_cache_key(profile).encode()).hexdigest()[:8]
    return f"env-{digest}"


def profile_notes(profile: dict[str, Any]) -> dict[str, str]:
    """
    Return the notes of a profile: facts the cluster cannot tell you, such as
    which index pattern holds which application. Read fresh from the config on
    every call, so an edit shows up even when the rest of the output is cached.
    """
    stored = load_config().get("profiles", {}).get(profile_label(profile), {}).get("notes")
    return dict(stored) if isinstance(stored, dict) else {}


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


def cred_cache_ttl() -> int:
    """
    Resolve the credentials-cache TTL in seconds.
    Precedence: env var > config file > default (24h).
    A value of 0 or less turns caching off.
    """
    raw: Any = os.environ.get(_CRED_CACHE_TTL_ENV)
    if raw is None:
        raw = load_config().get(_CRED_CACHE_TTL_CONFIG_KEY)
    if raw is None:
        return _CRED_CACHE_TTL_DEFAULT
    try:
        return int(raw)
    except (TypeError, ValueError):
        return _CRED_CACHE_TTL_DEFAULT


def cred_cache_ttl_source() -> str:
    """Say where the effective TTL comes from, so `cred-cache-ttl` can report it."""
    if os.environ.get(_CRED_CACHE_TTL_ENV) is not None:
        return f"env ({_CRED_CACHE_TTL_ENV})"
    if _CRED_CACHE_TTL_CONFIG_KEY in load_config():
        return "config"
    return "default"


def set_cred_cache_ttl(seconds: int | None) -> None:
    """Store the TTL in the config file. ``None`` removes the override."""
    config = load_config()
    if seconds is None:
        config.pop(_CRED_CACHE_TTL_CONFIG_KEY, None)
    else:
        config[_CRED_CACHE_TTL_CONFIG_KEY] = seconds
    save_config(config)


def _cred_cache_accounts(profile: dict[str, Any]) -> tuple[str, str, str]:
    """
    Keyring account names for one profile.
    Namespacing by profile stops a stale credential for one cluster from being
    served to another.
    """
    label = re.sub(r"[^\w\-.]", "_", profile_label(profile))
    user_key, pass_key, ts_key = _CRED_CACHE_KEYS
    return (f"{user_key}-{label}", f"{pass_key}-{label}", f"{ts_key}-{label}")


def _cached_creds_get(profile: dict[str, Any]) -> tuple[str, str] | None:
    """Read cached credentials for this profile from the OS keyring, if fresh."""
    ttl = cred_cache_ttl()
    if ttl <= 0:
        return None
    user_key, pass_key, ts_key = _cred_cache_accounts(profile)
    timestamp = keychain_read(_CRED_CACHE_SERVICE, ts_key)
    if not timestamp:
        return None
    try:
        if time.time() - float(timestamp) > ttl:
            return None
    except ValueError:
        return None
    username = keychain_read(_CRED_CACHE_SERVICE, user_key)
    password = keychain_read(_CRED_CACHE_SERVICE, pass_key)
    return (username, password) if username and password else None


def _cached_creds_put(profile: dict[str, Any], username: str, password: str) -> None:
    if cred_cache_ttl() <= 0:
        return
    user_key, pass_key, ts_key = _cred_cache_accounts(profile)
    keychain_write(_CRED_CACHE_SERVICE, user_key, username)
    keychain_write(_CRED_CACHE_SERVICE, pass_key, password)
    keychain_write(_CRED_CACHE_SERVICE, ts_key, str(time.time()))


def cached_creds_clear_profile(profile: dict[str, Any]) -> None:
    for account in _cred_cache_accounts(profile):
        keychain_delete(_CRED_CACHE_SERVICE, account)
    _creds_cache.pop(_profile_cache_key(profile), None)


def cached_creds_clear() -> None:
    for name in list(load_config().get("profiles", {})):
        with contextlib.suppress(KibanaAgentError):
            cached_creds_clear_profile(get_profile(name))
    for account in _CRED_CACHE_KEYS:  # entries written before the per-profile keys
        keychain_delete(_CRED_CACHE_SERVICE, account)
    _creds_cache.clear()


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
                    "Credentials are cached in the OS keyring for 24h "
                    "(change it with `kibana-agent cred-cache-ttl`)."
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
        cached = _cached_creds_get(profile)
        if cached:
            _creds_cache[key] = cached
            return cached

    backend = _AUTH_BACKENDS.get(auth_type)
    if not backend:
        raise AuthError(f"Unknown auth type: {auth_type}")

    username, password = backend(auth)
    _creds_cache[key] = (username, password)

    if auth_type in ("1password", "keychain"):
        _cached_creds_put(profile, username, password)

    return username, password


def _profile_cache_dir(profile: dict[str, Any]) -> Path:
    return CACHE_DIR / re.sub(r"[^\w\-.]", "_", profile_label(profile))


def _cache_path(profile: dict[str, Any], name: str) -> Path:
    profile_dir = _profile_cache_dir(profile)
    profile_dir.mkdir(parents=True, exist_ok=True)
    safe_name = re.sub(r"[^\w.-]", "_", name)
    return profile_dir / f"{safe_name}.json"


def cache_get(profile: dict[str, Any], name: str, ttl: int) -> Any | None:
    path = _cache_path(profile, name)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None
    if data.get("_v") != CACHE_VERSION:
        return None
    if time.time() - data.get("_t", 0) > ttl:
        return None
    return data.get("_p")


def cache_put(profile: dict[str, Any], name: str, payload: Any) -> None:
    path = _cache_path(profile, name)
    envelope = {"_t": time.time(), "_v": CACHE_VERSION, "_p": payload}
    path.write_text(json.dumps(envelope, ensure_ascii=False))


def _clear_dir(root: Path) -> int:
    if not root.exists():
        return 0
    count = 0
    for path in root.rglob("*.json"):
        path.unlink()
        count += 1
    for directory in sorted(root.rglob("*"), reverse=True):
        if directory.is_dir():
            with contextlib.suppress(OSError):
                directory.rmdir()
    return count


def cache_clear_profile(profile: dict[str, Any]) -> int:
    directory = _profile_cache_dir(profile)
    count = _clear_dir(directory)
    with contextlib.suppress(OSError):
        directory.rmdir()
    return count


def cache_clear_all() -> int:
    return _clear_dir(CACHE_DIR)


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


def warn(message: str) -> None:
    """
    Report something the caller should notice but that does not stop the call.
    Goes to stderr so it never mixes into the data on stdout.
    """
    sys.stderr.write(f"Warning: {message}\n")


def _auth_hint(profile: dict[str, Any], username: str) -> str:
    label = profile_label(profile)
    return (
        f"Profile '{label}' authenticated as '{username}'. If that is the wrong user, "
        f"the cached credentials are stale: "
        f"kibana-agent cache-clear --creds-only --profile {label}"
    )


def _check_es_error(data: Any, profile: dict[str, Any], username: str) -> None:
    """
    Stop on an error that the Kibana proxy returned with HTTP 200.
    Without this an auth or query error reads as an empty result set.
    """
    if not isinstance(data, dict):
        return
    error = data.get("error")
    detail = None
    if isinstance(error, str):
        detail = error
    elif isinstance(error, dict) and ("reason" in error or "type" in error):
        detail = error.get("reason") or error.get("type")
    if detail is not None:
        status = data.get("status", 200)
        message = str(detail)[:300]
        if status in (401, 403) or "security_exception" in str(error):
            message = f"{message}\n{_auth_hint(profile, username)}"
        raise KibanaApiError(int(status) if isinstance(status, int) else 200, message)
    shards = data.get("_shards")
    if isinstance(shards, dict) and shards.get("failed"):
        warn(f"{shards['failed']} of {shards.get('total', '?')} shards failed, results are partial")


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
    try:
        response = requests.post(
            f"{url}{prefix}/api/console/proxy",
            params={"path": actual_path, "method": method},
            headers={"kbn-xsrf": "true", "Content-Type": "application/json"},
            json=body,
            auth=(username, password),
            timeout=timeout,
        )
    except requests.Timeout as exc:
        raise KibanaAgentError(
            f"Timeout after {timeout}s reaching {url}. Narrow the window with --last "
            f"or ask for fewer hits with -n, or raise --timeout."
        ) from exc
    except requests.ConnectionError as exc:
        raise KibanaAgentError(
            f"Cannot reach {url}: {str(exc)[:200]}\n"
            f"Check the network or VPN, then retry. This is not an empty result."
        ) from exc
    if response.status_code >= 400:
        detail = response.text
        if response.status_code in (401, 403):
            detail = f"{detail[:300]}\n{_auth_hint(profile, username)}"
        raise KibanaApiError(response.status_code, detail)
    if len(response.content) > MAX_RESPONSE_BYTES:
        warn(f"{len(response.content):,}B response")
    data = response.json()
    _check_es_error(data, profile, username)
    return data  # type: ignore[no-any-return]


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
    raise IndexResolutionError("No index pattern given and profile has no default index.")


def _pluck(source: dict[str, Any], path: str) -> Any:
    """
    Read a dotted path out of a document.
    Elasticsearch returns "_source" nested, so "a.b" arrives as {"a": {"b": ...}}.
    Some documents keep the dotted name as one flat key, so try that first.
    """
    if path in source:
        return source[path]
    current: Any = source
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _expand_json_strings(value: Any, depth: int = _EXPAND_JSON_DEPTH) -> Any:
    """
    Turn strings that hold a JSON document into real objects, and split
    multi-line strings into a list of lines. Applications often log one JSON
    payload into a single string field, and a traceback inside it stays
    unreadable while it is escaped.
    """
    if isinstance(value, dict):
        return {key: _expand_json_strings(item, depth) for key, item in value.items()}
    if isinstance(value, list):
        return [_expand_json_strings(item, depth) for item in value]
    if not isinstance(value, str):
        return value
    stripped = value.strip()
    if depth > 0 and stripped[:1] in ("{", "["):
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            pass
        else:
            return _expand_json_strings(parsed, depth - 1)
    if "\n" in value:
        return value.rstrip("\n").split("\n")
    return value


def _format_hit(
    hit: dict[str, Any], field_list: list[str] | None, expand_json: bool
) -> dict[str, Any]:
    source = hit.get("_source", {})
    if field_list:
        picked = {}
        for path in field_list:
            value = _pluck(source, path)
            if value is not None:
                picked[path] = value
        source = picked
    out = _strip_empty(source)
    if expand_json:
        out = _expand_json_strings(out)
    if hit.get("sort"):
        out["_sort"] = hit["sort"]
    return out


def _read_total(total: Any) -> tuple[Any, bool]:
    """
    Read "hits.total" and say whether the number is only a floor.
    Elasticsearch stops counting at 10,000 by default and then reports
    "relation": "gte", so the value means "at least this many".
    """
    if isinstance(total, dict):
        return total.get("value", "?"), total.get("relation") == "gte"
    return total, False


def _format_search_result(
    data: dict[str, Any], field_list: list[str] | None, max_source_len: int, expand_json: bool
) -> dict[str, Any]:
    total, capped = _read_total(data.get("hits", {}).get("total", {}))
    raw_hits = data.get("hits", {}).get("hits", [])
    truncated = len(raw_hits) > MAX_RESPONSE_HITS
    limited_hits = raw_hits[:MAX_RESPONSE_HITS] if truncated else raw_hits
    hits = []
    cut = 0
    for hit in limited_hits:
        formatted = _format_hit(hit, field_list, expand_json)
        serialized = json.dumps(formatted, ensure_ascii=False, separators=(",", ":"))
        if max_source_len and len(serialized) > max_source_len:
            hits.append({"_truncated": serialized[:max_source_len] + "…"})
            cut += 1
        else:
            hits.append(formatted)
    if cut:
        warn(
            f"{cut} of {len(hits)} documents were cut at --max-source-len "
            f"{max_source_len}. Raise it, or select the fields you need with -f."
        )
    result: dict[str, Any] = {"total": total, "n": len(hits)}
    if capped:
        result["total_is_lower_bound"] = True
        warn(_CAPPED_TOTAL_HINT.format(total=total))
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
        for sub_name, sub_field in value.get("fields", {}).items():
            out[f"{full_key}.{sub_name}"] = sub_field.get("type", "object")
    return out


def _collect_query_fields(node: Any, out: list[tuple[str, str]]) -> None:
    """Collect (field, clause) pairs referenced by a query DSL fragment."""
    if isinstance(node, list):
        for item in node:
            _collect_query_fields(item, out)
        return
    if not isinstance(node, dict):
        return
    for clause, value in node.items():
        if clause == "exists" and isinstance(value, dict) and "field" in value:
            out.append((str(value["field"]), clause))
        elif clause in _FIELD_CLAUSES and isinstance(value, dict) and value:
            out.append((str(next(iter(value))), clause))
        else:
            _collect_query_fields(value, out)


def _collect_agg_fields(node: Any, out: list[str]) -> None:
    """Collect field names referenced by an aggregations fragment."""
    if isinstance(node, list):
        for item in node:
            _collect_agg_fields(item, out)
        return
    if not isinstance(node, dict):
        return
    for key, value in node.items():
        if key == "field" and isinstance(value, str):
            out.append(value)
        else:
            _collect_agg_fields(value, out)


def _mapping_types(mapping: dict[str, Any]) -> dict[str, str]:
    """Merge the per-index groups of a parsed mapping into one field:type dict."""
    types: dict[str, str] = {}
    for fields in mapping.values():
        if isinstance(fields, dict):
            types.update(fields)
    return types


def _keyword_sibling(types: dict[str, str], field: str) -> str | None:
    for candidate in (f"{field}.keyword", f"{field}.raw"):
        if types.get(candidate) in _EXACT_TYPES:
            return candidate
    return None


def _tokens(name: str) -> set[str]:
    return {t for t in re.split(r"[._\-]", name.lower()) if len(t) > 2}


def _suggest_fields(types: dict[str, str], field: str, limit: int = 3) -> list[str]:
    """
    Suggest field names close to one that is missing.
    Tries spelling first, then names that share a word, which catches a guess
    like "a.request_status_int" when the real field is "a.response_code".
    """
    close = difflib.get_close_matches(field, list(types), n=limit, cutoff=0.6)
    if close:
        return close
    wanted = _tokens(field)
    if not wanted:
        return []
    scored = [(len(wanted & _tokens(name)), name) for name in types]
    return [name for score, name in sorted(scored, reverse=True) if score][:limit]


def _detect_time_field(types: dict[str, str]) -> str | None:
    """Return the best date field to filter on, preferring the common names."""
    dates = [name for name, kind in types.items() if kind in _DATE_TYPES]
    for preferred in _TIME_FIELD_PREFERENCE:
        if preferred in dates:
            return preferred
    return sorted(dates, key=lambda name: (len(name), name))[0] if dates else None


def _suffix(items: list[str]) -> str:
    return f" Did you mean: {', '.join(items)}?" if items else ""


def _field_warnings(
    types: dict[str, str], query_refs: list[tuple[str, str]], agg_refs: list[str]
) -> list[str]:
    warnings: list[str] = []
    for field, clause in query_refs:
        field_type = types.get(field)
        if field_type is None:
            warnings.append(
                f"field '{field}' is not in the mapping — this query cannot match."
                f"{_suffix(_suggest_fields(types, field))}"
            )
        elif clause in _EXACT_CLAUSES and field_type in _ANALYZED_TYPES:
            hint = _keyword_sibling(types, field)
            fix = f"use '{hint}'" if hint else "use match_phrase"
            warnings.append(
                f"'{clause}' on analyzed {field_type} field '{field}' matches nothing — {fix}"
            )
    for field in agg_refs:
        field_type = types.get(field)
        if field_type is None:
            warnings.append(
                f"aggregation field '{field}' is not in the mapping."
                f"{_suffix(_suggest_fields(types, field))}"
            )
        elif field_type in _ANALYZED_TYPES:
            hint = _keyword_sibling(types, field)
            fix = f"use '{hint}'" if hint else "aggregate on a keyword, numeric, or date field"
            warnings.append(
                f"aggregation on analyzed {field_type} field '{field}' has no doc values — {fix}"
            )
    return warnings


def _trim_fields(fields: dict[str, str], pattern: str) -> dict[str, str]:
    """Cap an inline field list, so one wide index does not fill the output."""
    if len(fields) <= MAX_CONTEXT_FIELDS:
        return fields
    kept = dict(sorted(fields.items())[:MAX_CONTEXT_FIELDS])
    kept["…"] = f"{len(fields) - MAX_CONTEXT_FIELDS} more fields — run: fields {pattern} '<glob>'"
    return kept


def _with_notes(ctx: dict[str, Any], notes: dict[str, str]) -> dict[str, Any]:
    """Put the notes first, so they are the first thing an agent reads."""
    return {"notes": notes, **ctx} if notes else ctx


def _scope(profile: dict[str, Any]) -> dict[str, Any]:
    """Say which profile, space, and index the commands will use."""
    scope: dict[str, Any] = {"profile": profile_label(profile)}
    for key in ("space", "index"):
        if profile.get(key):
            scope[key] = profile[key]
    locked = [k for k in ("restrict_space", "restrict_index") if profile.get(k)]
    if locked:
        scope["restricted"] = locked
    return scope


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


def _group_by_common_prefix(names: list[str]) -> list[str]:
    """
    Collapse many sibling indices into one wildcard, the same rule that
    "aliases" applies. Names are grouped by everything before the last "-".
    """
    groups: dict[str, list[str]] = {}
    for name in names:
        head, separator, _ = name.rpartition("-")
        groups.setdefault(head if separator else name, []).append(name)
    out: list[str] = []
    for members in groups.values():
        if len(members) >= _PREFIX_GROUP_MIN:
            out.append(f"{os.path.commonprefix(members)}*")
        else:
            out.extend(members)
    return out


def _extract_prefixes(raw: dict[str, Any]) -> list[str]:
    """
    Reduce a list of index names to the patterns you can query.
    A date suffix ("-2026.08.07") or a sequence suffix ("-000397") becomes "-*".
    Whatever is left is grouped by common prefix, so an unknown naming scheme
    cannot make this list long again.
    """
    prefixes: set[str] = set()
    plain: list[str] = []
    for index_name in raw:
        if index_name.startswith("."):
            continue
        match = _DATED_INDEX.match(index_name)
        if match:
            prefixes.add(f"{match.group('stem')}-*")
        else:
            plain.append(index_name)
    prefixes.update(_group_by_common_prefix(plain))
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
        cached = cache_get(profile, "aliases", CACHE_TTL_ALIASES)
        if cached is not None:
            return cached  # type: ignore[no-any-return]
    data = es(profile, "GET", "_aliases", **kwargs)
    result = _parse_aliases(data)  # type: ignore[arg-type]
    cache_put(profile, "aliases", result)
    return result


def fetch_mapping(
    profile: dict[str, Any], index: str, *, no_cache: bool = False, **kwargs: Any
) -> dict[str, Any]:
    cache_name = f"mapping_{index}"
    if not no_cache:
        cached = cache_get(profile, cache_name, CACHE_TTL_MAPPING)
        if cached is not None:
            return cached  # type: ignore[no-any-return]
    data = es(profile, "GET", f"{index}/_mapping", **kwargs)
    result = _parse_mapping(data)  # type: ignore[arg-type]
    cache_put(profile, cache_name, result)
    return result


def _warn_unknown_pattern(profile: dict[str, Any], index_pattern: str, **es_kwargs: Any) -> None:
    """Warn that a pattern matches no index, and name the patterns that exist."""
    try:
        known = list(fetch_aliases(profile, **es_kwargs))
    except (KibanaAgentError, requests.RequestException, ValueError):
        known = []
    close = difflib.get_close_matches(index_pattern, known, n=3, cutoff=0.4)
    warn(
        f"index pattern '{index_pattern}' matches no index, so every query returns 0."
        f"{_suffix(close)} Run 'kibana-agent aliases' for the full list."
    )


def check_request(
    profile: dict[str, Any],
    index_pattern: str,
    query: dict[str, Any] | None,
    aggs: dict[str, Any] | None,
    time_field: str | None,
    *,
    no_cache: bool = False,
    **es_kwargs: Any,
) -> None:
    """
    Warn before sending a request that cannot match: unknown index pattern,
    unknown field, or a clause the field type does not support. Best effort
    only, so a request that cannot be checked is sent unchanged.
    """
    try:
        mapping = fetch_mapping(profile, index_pattern, no_cache=no_cache, **es_kwargs)
    except (KibanaAgentError, requests.RequestException, ValueError):
        return
    types = _mapping_types(mapping)
    if not types:
        _warn_unknown_pattern(profile, index_pattern, **es_kwargs)
        return

    bad_time_field = bool(time_field) and time_field not in types
    if bad_time_field:
        detected = _detect_time_field(types)
        fix = (
            f"this index uses '{detected}' (pass --time-field {detected})"
            if detected
            else "this index has no date field, so a time filter cannot match"
        )
        warn(f"time field '{time_field}' is not in the mapping — {fix}")

    query_refs: list[tuple[str, str]] = []
    agg_refs: list[str] = []
    _collect_query_fields(query, query_refs)
    _collect_agg_fields(aggs, agg_refs)
    if bad_time_field:  # reported above, and it appears in every time filter
        query_refs = [ref for ref in query_refs if ref[0] != time_field]
        agg_refs = [name for name in agg_refs if name != time_field]
    for warning in _field_warnings(types, query_refs, agg_refs):
        warn(warning)


def diagnose_zero(
    profile: dict[str, Any],
    index_pattern: str,
    time_range: str,
    time_field: str,
    **es_kwargs: Any,
) -> None:
    """
    Explain a zero result: say whether the filter, the window, or the index is
    empty. Runs only when a query returned nothing, so it costs nothing normally.
    """

    def count(body: dict[str, Any]) -> int | None:
        try:
            data = es(profile, "POST", f"{index_pattern}/_count", body, **es_kwargs)
        except (KibanaAgentError, requests.RequestException, ValueError):
            return None
        return int(data.get("count", 0)) if isinstance(data, dict) else None

    in_window = count({"query": _time_range_filter(time_range, time_field)})
    if in_window is None:
        return
    if in_window > 0:
        warn(
            f"0 hits, but the last {time_range} holds {in_window:,} documents. "
            f"The filter is the problem, not the window."
        )
        return

    total = count({"query": {"match_all": {}}})
    if total:
        warn(
            f"0 hits, and the last {time_range} is empty. The pattern holds "
            f"{total:,} documents overall — widen --last, or check '{time_field}' "
            f"is the right time field."
        )
    elif total == 0:
        warn(
            f"0 hits, and '{index_pattern}' holds no documents at all. "
            f"Check the index pattern with 'kibana-agent aliases'."
        )


def _pattern_stats(
    profile: dict[str, Any], pattern: str, types: dict[str, str], es_kwargs: dict[str, Any]
) -> dict[str, Any]:
    """
    Summarise one index pattern: field count, time field, coverage, doc counts.
    Coverage says whether the index is still live, which explains many zeros.
    """
    stats: dict[str, Any] = {}
    if types:
        stats["fields"] = len(types)
        stats["aggregatable"] = len([n for n, t in types.items() if t in _AGGREGATABLE_TYPES])
    time_field = _detect_time_field(types) if types else None
    if time_field:
        stats["time_field"] = time_field
    body: dict[str, Any] = {"size": 0, "query": {"match_all": {}}, "aggregations": {}}
    if time_field:
        body["aggregations"]["first"] = {"min": {"field": time_field}}
        body["aggregations"]["last"] = {"max": {"field": time_field}}
        body["aggregations"]["recent"] = {"filter": {"range": {time_field: {"gte": "now-1h"}}}}
    try:
        data = es(profile, "POST", f"{pattern}/_search", body, **es_kwargs)
    except (KibanaAgentError, requests.RequestException, ValueError):
        return stats
    if not isinstance(data, dict):
        return stats
    stats["docs"], capped = _read_total(data.get("hits", {}).get("total", {}))
    if capped:
        stats["docs_is_lower_bound"] = True
    aggs = data.get("aggregations", {})
    for key in ("first", "last"):
        value = aggs.get(key, {}).get("value_as_string")
        if value:
            stats[key] = value
    if "recent" in aggs:
        stats["docs_1h"] = aggs["recent"].get("doc_count", 0)
    return stats


def _cluster_info(profile: dict[str, Any], es_kwargs: dict[str, Any]) -> dict[str, str]:
    """Report the ES version, which decides what query syntax the cluster accepts."""
    try:
        root = es(profile, "GET", "/", **es_kwargs)
    except (KibanaAgentError, requests.RequestException, ValueError):
        return {}
    if not isinstance(root, dict):
        return {}
    version = root.get("version", {})
    number = version.get("number") if isinstance(version, dict) else None
    return {"version": str(number)} if number else {}


def _build_must(
    time_range: str | None,
    extra_query: str | dict[str, Any] | None,
    kql: str | None,
    time_field: str = DEFAULT_TIME_FIELD,
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
    sort: str | None = None,
    fields: list[str] | None = None,
    aggs: dict[str, Any] | None = None,
    max_source_len: int = MAX_SOURCE_LEN,
    expand_json: bool = False,
    time_field: str = DEFAULT_TIME_FIELD,
    hints: bool = True,
    **es_kwargs: Any,
) -> dict[str, Any]:
    """Search recent logs in an index pattern."""
    body: dict[str, Any] = {
        "query": {"bool": {"must": _build_must(time_range, extra_query, kql, time_field)}},
        "size": size,
    }
    sort_key, _, sort_order = (sort or f"{time_field}:desc").partition(":")
    body["sort"] = [{sort_key: sort_order or "desc"}]
    if fields:
        body["_source"] = fields
    if aggs is not None:
        body["aggregations"] = aggs
    if hints:
        check_request(profile, index_pattern, body["query"], aggs, time_field, **es_kwargs)
    data = es(profile, "POST", f"{index_pattern}/_search", body, **es_kwargs)
    result = _format_search_result(data, fields, max_source_len, expand_json)  # type: ignore[arg-type]
    if hints and result["total"] == 0 and (extra_query or kql):
        diagnose_zero(profile, index_pattern, time_range, time_field, **es_kwargs)
    return result


def op_count(
    profile: dict[str, Any],
    index_pattern: str,
    *,
    time_range: str = DEFAULT_TIME_RANGE,
    extra_query: str | dict[str, Any] | None = None,
    kql: str | None = None,
    time_field: str = DEFAULT_TIME_FIELD,
    hints: bool = True,
    **es_kwargs: Any,
) -> int:
    """Count documents matching a query."""
    query = {"bool": {"must": _build_must(time_range, extra_query, kql, time_field)}}
    if hints:
        check_request(profile, index_pattern, query, None, time_field, **es_kwargs)
    data = es(profile, "POST", f"{index_pattern}/_count", {"query": query}, **es_kwargs)
    total = int(data.get("count", 0))  # type: ignore[union-attr]
    if hints and total == 0 and (extra_query or kql):
        diagnose_zero(profile, index_pattern, time_range, time_field, **es_kwargs)
    return total


def op_histogram(
    profile: dict[str, Any],
    index_pattern: str,
    *,
    time_range: str = DEFAULT_TIME_RANGE,
    interval: str = "5m",
    extra_query: str | dict[str, Any] | None = None,
    kql: str | None = None,
    time_field: str = DEFAULT_TIME_FIELD,
    hints: bool = True,
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
    if hints:
        check_request(
            profile, index_pattern, body["query"], body["aggregations"], time_field, **es_kwargs
        )
    data = es(profile, "POST", f"{index_pattern}/_search", body, **es_kwargs)
    buckets = data.get("aggregations", {}).get("t", {}).get("buckets", [])  # type: ignore[union-attr]
    total, capped = _read_total(data.get("hits", {}).get("total", {}))  # type: ignore[union-attr]
    result: dict[str, Any] = {"total": total, "interval": interval}
    if capped:
        result["total_is_lower_bound"] = True
        warn(
            f"total={total} is a floor: Elasticsearch stops counting at 10,000. "
            f"The bucket counts below are exact — sum them for the real total."
        )
    result["buckets"] = [{"t": b["key_as_string"], "n": b["doc_count"]} for b in buckets]
    return result


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
    notes = profile_notes(profile)
    if not notes:
        warn(
            f"No notes for '{profile_label(profile)}' yet. Once you know which index serves "
            f"which application, or which field carries a value, record it:\n"
            f"  kibana-agent profile note {profile_label(profile)} <key>=<value>"
        )
    if not refresh and not no_cache:
        cached = cache_get(profile, "context", CACHE_TTL_CONTEXT)
        if cached is not None:
            return _with_notes(cached, notes)

    raw = es(profile, "GET", "_aliases", **es_kwargs)
    aliases_data = _parse_aliases(raw)  # type: ignore[arg-type]
    cache_put(profile, "aliases", aliases_data)
    prefixes = _extract_prefixes(raw)  # type: ignore[arg-type]

    patterns = [p.strip() for p in indices.split(",")] if indices else prefixes[:5]

    mappings: dict[str, Any] = {}
    stats: dict[str, Any] = {}
    for pattern in patterns:
        types: dict[str, str] = {}
        try:
            mapping = fetch_mapping(profile, pattern, no_cache=refresh or no_cache, **es_kwargs)
            types = _mapping_types(mapping)
            mappings[pattern] = _trim_fields(next(iter(mapping.values())), pattern)
        except KibanaAgentError:
            pass
        summary = _pattern_stats(profile, pattern, types, es_kwargs)
        if summary:
            stats[pattern] = summary

    ctx = {
        "ts": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scope": _scope(profile),
        "cluster": _cluster_info(profile, es_kwargs),
        "prefixes": prefixes,
        "aliases": aliases_data,
        "indices": stats,
        "mappings": mappings,
    }
    cache_put(profile, "context", ctx)
    return _with_notes(ctx, notes)


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
    expand_json: bool = False,
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
        formatted = _format_hit(hit, fields, expand_json)
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


def op_set_notes(profile: dict[str, Any], facts: dict[str, str]) -> dict[str, str]:
    """
    Add facts to a profile's notes and return the full set.
    An empty value removes that note.
    """
    label = profile_label(profile)
    config = load_config()
    profile_data = config.get("profiles", {}).get(label)
    if profile_data is None:
        raise ProfileNotFoundError(
            f"Profile '{label}' is not in the config file, so notes cannot be saved."
        )
    notes: dict[str, str] = dict(profile_data.get("notes", {}))
    for key, value in facts.items():
        if value:
            notes[key] = value
        else:
            notes.pop(key, None)
    if notes:
        profile_data["notes"] = notes
    else:
        profile_data.pop("notes", None)
    save_config(config)
    return notes


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

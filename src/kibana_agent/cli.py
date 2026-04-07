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
    keychain   — reads from macOS Keychain (service + account)
    plain      — stored in config file (not recommended)

Config:  ~/.config/kibana-agent/config.json
Cache:   ~/.cache/kibana-agent/
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode

import click
import requests

# ═══════════════════════════════════════════════════════════════════════════
# Constants
# ═══════════════════════════════════════════════════════════════════════════

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

# ═══════════════════════════════════════════════════════════════════════════
# Profile / config persistence
# ═══════════════════════════════════════════════════════════════════════════


def _load_config() -> dict:
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {"active": None, "profiles": {}}


def _save_config(cfg: dict) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2, ensure_ascii=False) + "\n")


def _get_profile(name: str | None = None) -> dict:
    """Return the resolved profile dict or exit with error."""
    cfg = _load_config()
    pname = name or cfg.get("active")
    if not pname:
        click.echo("No active profile. Run: profile create <name> ...", err=True)
        sys.exit(1)
    p = cfg.get("profiles", {}).get(pname)
    if not p:
        click.echo(f"Profile '{pname}' not found. Run: profile list", err=True)
        sys.exit(1)
    return p


# ═══════════════════════════════════════════════════════════════════════════
# macOS Keychain helpers
# ═══════════════════════════════════════════════════════════════════════════


def _keychain_read(service: str, account: str) -> str | None:
    try:
        return subprocess.run(
            ["security", "find-generic-password", "-s", service, "-a", account, "-w"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None


def _keychain_write(service: str, account: str, value: str) -> None:
    subprocess.run(
        ["security", "delete-generic-password", "-s", service, "-a", account],
        capture_output=True,
    )
    subprocess.run(
        ["security", "add-generic-password", "-s", service, "-a", account, "-w", value],
        capture_output=True, text=True, check=True,
    )


def _keychain_delete(service: str, account: str) -> None:
    subprocess.run(
        ["security", "delete-generic-password", "-s", service, "-a", account],
        capture_output=True,
    )


# ═══════════════════════════════════════════════════════════════════════════
# Credential cache — caches 1Password/Keychain creds in macOS Keychain
# so Touch ID is only needed once per TTL window.
# ═══════════════════════════════════════════════════════════════════════════

_CRED_CACHE_SERVICE = "kibana-agent"
_CRED_CACHE_TTL = 30 * 60  # 30 minutes
_CRED_CACHE_KEYS = ("cache-username", "cache-password", "cache-ts")


def _cached_creds_get() -> tuple[str, str] | None:
    ts = _keychain_read(_CRED_CACHE_SERVICE, "cache-ts")
    if not ts:
        return None
    try:
        if time.time() - float(ts) > _CRED_CACHE_TTL:
            return None
    except ValueError:
        return None
    u = _keychain_read(_CRED_CACHE_SERVICE, "cache-username")
    p = _keychain_read(_CRED_CACHE_SERVICE, "cache-password")
    return (u, p) if u and p else None


def _cached_creds_put(u: str, p: str) -> None:
    _keychain_write(_CRED_CACHE_SERVICE, "cache-username", u)
    _keychain_write(_CRED_CACHE_SERVICE, "cache-password", p)
    _keychain_write(_CRED_CACHE_SERVICE, "cache-ts", str(time.time()))


def _cached_creds_clear() -> None:
    for key in _CRED_CACHE_KEYS:
        _keychain_delete(_CRED_CACHE_SERVICE, key)


# ═══════════════════════════════════════════════════════════════════════════
# Auth backends
# ═══════════════════════════════════════════════════════════════════════════


def _auth_1password(auth: dict) -> tuple[str, str]:
    def op_read(ref: str) -> str:
        cmd = ["op", "read", ref]
        session = os.environ.get("OP_SESSION")
        if session:
            cmd += ["--session", session]
        try:
            return subprocess.run(
                cmd, capture_output=True, text=True, check=True,
            ).stdout.strip()
        except FileNotFoundError:
            click.echo("Error: `op` CLI not found.", err=True)
            sys.exit(1)
        except subprocess.CalledProcessError as e:
            click.echo(f"op error: {e.stderr.strip()}", err=True)
            if "promptError" in (e.stderr or ""):
                click.echo(
                    "Hint: run this command in a terminal that can show Touch ID.\n"
                    "Credentials will be cached in macOS Keychain for 30 min.",
                    err=True,
                )
            sys.exit(1)

    return op_read(auth["username_ref"]), op_read(auth["password_ref"])


def _auth_keychain(auth: dict) -> tuple[str, str]:
    service = auth["service"]
    u = _keychain_read(service, auth["username_account"])
    p = _keychain_read(service, auth["password_account"])
    if u is None or p is None:
        missing = "username" if u is None else "password"
        click.echo(f"Keychain: {missing} not found for service='{service}'", err=True)
        sys.exit(1)
    return u, p


def _auth_plain(auth: dict) -> tuple[str, str]:
    return auth["username"], auth["password"]


_AUTH_BACKENDS = {
    "1password": _auth_1password,
    "keychain": _auth_keychain,
    "plain": _auth_plain,
}

_creds_cache: tuple[str, str] | None = None


def creds(profile: dict) -> tuple[str, str]:
    global _creds_cache
    if _creds_cache is not None:
        return _creds_cache

    auth = profile["auth"]
    auth_type = auth["type"]

    # Try Keychain cache first (avoids Touch ID)
    if auth_type in ("1password", "keychain"):
        cached = _cached_creds_get()
        if cached:
            _creds_cache = cached
            return cached

    backend = _AUTH_BACKENDS.get(auth_type)
    if not backend:
        click.echo(f"Unknown auth type: {auth_type}", err=True)
        sys.exit(1)

    u, p = backend(auth)
    _creds_cache = (u, p)

    # Cache in Keychain so subsequent CLI invocations skip Touch ID
    if auth_type in ("1password", "keychain"):
        _cached_creds_put(u, p)

    return u, p


# ═══════════════════════════════════════════════════════════════════════════
# Cache
# ═══════════════════════════════════════════════════════════════════════════


def _cache_path(name: str) -> Path:
    cfg = _load_config()
    pname = cfg.get("active", "_default")
    pdir = CACHE_DIR / re.sub(r"[^\w\-.]", "_", pname)
    pdir.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^\w.-]", "_", name)
    return pdir / f"{safe}.json"


def cache_get(name: str, ttl: int) -> object | None:
    p = _cache_path(name)
    if not p.exists():
        return None
    try:
        d = json.loads(p.read_text())
    except (json.JSONDecodeError, OSError):
        return None
    if time.time() - d.get("_t", 0) > ttl:
        return None
    return d.get("_p")


def cache_put(name: str, payload: object) -> None:
    p = _cache_path(name)
    p.write_text(json.dumps({"_t": time.time(), "_p": payload}, ensure_ascii=False))


def cache_clear_all() -> int:
    if not CACHE_DIR.exists():
        return 0
    n = 0
    for p in CACHE_DIR.rglob("*.json"):
        p.unlink()
        n += 1
    # Remove empty dirs
    for d in sorted(CACHE_DIR.rglob("*"), reverse=True):
        if d.is_dir():
            try:
                d.rmdir()
            except OSError:
                pass
    return n


# ═══════════════════════════════════════════════════════════════════════════
# Read-only guard
# ═══════════════════════════════════════════════════════════════════════════

BLOCKED = {
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
POST_OK = (
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


def _guard(method: str, path: str) -> None:
    if method not in ("GET", "POST"):
        click.echo(f"Blocked: {method}", err=True)
        sys.exit(1)
    lp = path.lower()
    for s in BLOCKED:
        if s in lp:
            click.echo(f"Blocked: {s}", err=True)
            sys.exit(1)
    if method == "POST" and not any(lp.endswith(s) for s in POST_OK):
        click.echo(f"Blocked: POST {path}", err=True)
        sys.exit(1)


# ═══════════════════════════════════════════════════════════════════════════
# HTTP
# ═══════════════════════════════════════════════════════════════════════════


def _curl(
    url: str, method: str, path: str, body: dict | None, timeout: int, fp: str | None
) -> str:
    ap = path + (("&" if "?" in path else "?") + f"filter_path={fp}" if fp else "")
    full = f"{url}/api/console/proxy?{urlencode({'path': ap, 'method': method})}"
    parts = [
        "curl -s",
        '-u "$USER:$PASS"',
        f'-X POST "{full}"',
        '-H "kbn-xsrf: true" -H "Content-Type: application/json"',
        f"--max-time {timeout}",
    ]
    if body:
        parts.append(f"-d '{json.dumps(body, ensure_ascii=False)}'")
    return " \\\n  ".join(parts)


def es(
    profile: dict,
    method: str,
    path: str,
    body: dict | None = None,
    *,
    timeout: int = DEFAULT_TIMEOUT,
    dry_run: bool = False,
    explain: bool = False,
    fp: str | None = None,
) -> dict | list:
    method = method.upper()
    _guard(method, path)
    if explain and body:
        click.echo(
            json.dumps(body, ensure_ascii=False, separators=(",", ":")), err=True
        )
    url = profile["kibana_url"].rstrip("/")
    if dry_run:
        click.echo(_curl(url, method, path, body, timeout, fp))
        sys.exit(0)

    u, p = creds(profile)
    ap = path + (("&" if "?" in path else "?") + f"filter_path={fp}" if fp else "")
    r = requests.post(
        f"{url}/api/console/proxy",
        params={"path": ap, "method": method},
        headers={"kbn-xsrf": "true", "Content-Type": "application/json"},
        json=body,
        auth=(u, p),
        timeout=timeout,
    )
    if r.status_code >= 400:
        click.echo(f"ES {r.status_code}: {r.text[:300]}", err=True)
        sys.exit(1)
    if len(r.content) > MAX_RESPONSE_BYTES:
        click.echo(f"Warning: {len(r.content):,}B response", err=True)
    return r.json()


# ═══════════════════════════════════════════════════════════════════════════
# Formatting
# ═══════════════════════════════════════════════════════════════════════════


def _strip(d: dict) -> dict:
    return {
        k: v for k, v in d.items() if v is not None and v != "" and v != [] and v != {}
    }


def _hit(h: dict, fl: list[str] | None) -> dict:
    src = h.get("_source", {})
    if fl:
        src = {k: src[k] for k in fl if k in src}
    out = _strip(src)
    if h.get("sort"):
        out["_sort"] = h["sort"]
    return out


def _search_result(data: dict, fl: list[str] | None, msl: int) -> dict:
    total = data.get("hits", {}).get("total", {})
    if isinstance(total, dict):
        total = total.get("value", "?")
    raw = data.get("hits", {}).get("hits", [])
    trunc = len(raw) > MAX_RESPONSE_HITS
    sl = raw[:MAX_RESPONSE_HITS] if trunc else raw
    hits = []
    for h in sl:
        ch = _hit(h, fl)
        s = json.dumps(ch, ensure_ascii=False, separators=(",", ":"))
        hits.append({"_truncated": s[:msl] + "…"} if msl and len(s) > msl else ch)
    r: dict = {"total": total, "n": len(hits)}
    if trunc:
        r["truncated"] = len(raw)
    r["hits"] = hits
    if "aggregations" in data:
        r["aggs"] = data["aggregations"]
    return r


def _flat_props(props: dict, pre: str = "") -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in props.items():
        full = f"{pre}.{k}" if pre else k
        if "properties" in v:
            out.update(_flat_props(v["properties"], full))
        else:
            out[full] = v.get("type", "object")
    return out


def _mapping(data: dict) -> dict:
    per: dict[str, dict[str, str]] = {}
    for idx, m in data.items():
        per[idx] = _flat_props(m.get("mappings", {}).get("properties", {}))
    groups: dict[str, tuple[list[str], dict[str, str]]] = {}
    for idx, fields in per.items():
        fp = hashlib.md5(json.dumps(fields, sort_keys=True).encode()).hexdigest()[:8]
        groups.setdefault(fp, ([], fields))[0].append(idx)
    result: dict = {}
    for _, (indices, fields) in groups.items():
        key = (
            indices[0]
            if len(indices) == 1
            else f"{os.path.commonprefix(indices)}* ({len(indices)})"
        )
        result[key] = fields
    return result


def _aliases(data: dict) -> dict[str, list[str]]:
    am: dict[str, list[str]] = {}
    for idx, m in data.items():
        if idx.startswith("."):
            continue
        for a in m.get("aliases", {}):
            am.setdefault(a, []).append(idx)
    for a, idxs in am.items():
        if len(idxs) > 5:
            am[a] = [f"{os.path.commonprefix(idxs)}* ({len(idxs)})"]
    return am


def _prefixes(raw: dict) -> list[str]:
    pxs: set[str] = set()
    for idx in raw:
        if idx.startswith("."):
            continue
        parts = re.split(r"-\d{4}[.\-]", idx)
        pxs.add(parts[0] + "-*" if len(parts) > 1 else idx)
    return sorted(pxs)


def emit(data: object, fmt: str) -> None:
    if fmt == "compact" and isinstance(data, dict) and "hits" in data:
        meta = {k: v for k, v in data.items() if k != "hits"}
        if meta:
            click.echo(
                "#" + json.dumps(meta, ensure_ascii=False, separators=(",", ":"))
            )
        for h in data["hits"]:
            click.echo(json.dumps(h, ensure_ascii=False, separators=(",", ":")))
    elif fmt == "compact":
        click.echo(json.dumps(data, ensure_ascii=False, separators=(",", ":")))
    else:
        click.echo(json.dumps(data, ensure_ascii=False, indent=2))


# ═══════════════════════════════════════════════════════════════════════════
# Cached fetchers
# ═══════════════════════════════════════════════════════════════════════════


def fetch_aliases(prof: dict, *, nc: bool = False, **kw) -> dict:
    if not nc:
        c = cache_get("aliases", CACHE_TTL_ALIASES)
        if c is not None:
            return c
    data = es(prof, "GET", "_aliases", **kw)
    r = _aliases(data)
    cache_put("aliases", r)
    return r


def fetch_mapping(prof: dict, idx: str, *, nc: bool = False, **kw) -> dict:
    cn = f"mapping_{idx}"
    if not nc:
        c = cache_get(cn, CACHE_TTL_MAPPING)
        if c is not None:
            return c
    data = es(prof, "GET", f"{idx}/_mapping", **kw)
    r = _mapping(data)
    cache_put(cn, r)
    return r


# ═══════════════════════════════════════════════════════════════════════════
# Rison encoder
# ═══════════════════════════════════════════════════════════════════════════


def _rison(obj: object) -> str:
    if obj is True:
        return "!t"
    if obj is False:
        return "!f"
    if obj is None:
        return "!n"
    if isinstance(obj, (int, float)):
        return str(obj)
    if isinstance(obj, str):
        if re.match(r"^[a-zA-Z0-9_.~*:\-/]+$", obj) and obj not in ("!t", "!f", "!n"):
            return obj
        return "'" + obj.replace("!", "!!").replace("'", "!'") + "'"
    if isinstance(obj, (list, tuple)):
        return "!(" + ",".join(_rison(i) for i in obj) + ")"
    if isinstance(obj, dict):
        return "(" + ",".join(f"{_rison(k)}:{_rison(v)}" for k, v in obj.items()) + ")"
    return str(obj)


# ═══════════════════════════════════════════════════════════════════════════
# CLI plumbing
# ═══════════════════════════════════════════════════════════════════════════


def common(f):
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
    f = click.option("--filter-path", "fp", default=None)(f)
    f = click.option(
        "--format", "fmt", type=click.Choice(["pretty", "compact"]), default="compact"
    )(f)
    f = click.option("--no-cache", "nc", is_flag=True, default=False)(f)
    return f


def _kw(timeout, dry_run, explain, fp) -> dict:
    kw: dict = {"timeout": timeout}
    if dry_run:
        kw["dry_run"] = True
    if explain:
        kw["explain"] = True
    if fp:
        kw["fp"] = fp
    return kw


def _time_must(tr: str, field: str = "@timestamp") -> dict:
    return {"range": {field: {"gte": f"now-{tr}"}}}


def _fl(csv: str | None) -> list[str] | None:
    return [f.strip() for f in csv.split(",") if f.strip()] if csv else None


# ═══════════════════════════════════════════════════════════════════════════
# CLI: profile management
# ═══════════════════════════════════════════════════════════════════════════


@click.group()
@click.version_option("0.1.0")
def cli():
    """Read-only Kibana/ES CLI for AI agents."""


@cli.group()
def profile():
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
# 1password options
@click.option("--op-username", default=None, help="1Password ref for username")
@click.option("--op-password", default=None, help="1Password ref for password")
# keychain options
@click.option("--kc-service", default=None, help="Keychain service name")
@click.option(
    "--kc-username-account", default=None, help="Keychain account for username"
)
@click.option(
    "--kc-password-account", default=None, help="Keychain account for password"
)
@click.option(
    "--kc-set-username", default=None, help="Store this username in Keychain now"
)
@click.option(
    "--kc-set-password", default=None, help="Store this password in Keychain now"
)
# plain options
@click.option("--username", default=None, help="Plain text username")
@click.option("--password", default=None, help="Plain text password")
@click.option(
    "--use", "set_active", is_flag=True, default=False, help="Set as active profile"
)
def profile_create(
    name,
    url,
    auth_type,
    op_username,
    op_password,
    kc_service,
    kc_username_account,
    kc_password_account,
    kc_set_username,
    kc_set_password,
    username,
    password,
    set_active,
):
    """Create a new profile.

    \b
    Examples:
      # 1Password
      profile create prd --url https://kibana.example.com --auth 1password \\
        --op-username "op://vault/item/username" --op-password "op://vault/item/password" --use

    \b
      # macOS Keychain
      profile create stg --url https://kibana-stg.example.com --auth keychain \\
        --kc-service kibana-stg --kc-username-account kibana-user --kc-password-account kibana-pass \\
        --kc-set-username admin --kc-set-password s3cret --use

    \b
      # Plain text (not recommended)
      profile create dev --url http://localhost:5601 --auth plain \\
        --username admin --password admin --use
    """
    auth: dict = {"type": auth_type}

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
        svc = kc_service
        u_acct = kc_username_account or f"{name}-username"
        p_acct = kc_password_account or f"{name}-password"
        auth["service"] = svc
        auth["username_account"] = u_acct
        auth["password_account"] = p_acct

        # Optionally store creds in keychain right now
        if kc_set_username:
            _keychain_write(svc, u_acct, kc_set_username)
            click.echo(
                f"Stored username in Keychain (service={svc}, account={u_acct})",
                err=True,
            )
        if kc_set_password:
            _keychain_write(svc, p_acct, kc_set_password)
            click.echo(
                f"Stored password in Keychain (service={svc}, account={p_acct})",
                err=True,
            )

    elif auth_type == "plain":
        if not username or not password:
            click.echo(
                "Error: --username and --password required for plain auth.", err=True
            )
            sys.exit(1)
        click.echo(
            "Warning: credentials stored in plain text in config file.", err=True
        )
        auth["username"] = username
        auth["password"] = password

    cfg = _load_config()
    cfg["profiles"][name] = {"kibana_url": url.rstrip("/"), "auth": auth}
    if set_active or cfg.get("active") is None:
        cfg["active"] = name
    _save_config(cfg)
    active_note = " (active)" if cfg["active"] == name else ""
    click.echo(f"Created profile '{name}'{active_note}")


@profile.command("list")
def profile_list():
    """List all profiles."""
    cfg = _load_config()
    active = cfg.get("active")
    profiles = cfg.get("profiles", {})
    if not profiles:
        click.echo("No profiles. Run: profile create <name> ...")
        return
    for name, p in profiles.items():
        marker = " *" if name == active else ""
        auth_type = p.get("auth", {}).get("type", "?")
        click.echo(f"{name}{marker}  {p['kibana_url']}  ({auth_type})")


@profile.command("show")
@click.argument("name", required=False, default=None)
def profile_show(name):
    """Show profile details (active profile if name omitted)."""
    cfg = _load_config()
    pname = name or cfg.get("active")
    if not pname:
        click.echo("No active profile.", err=True)
        sys.exit(1)
    p = cfg.get("profiles", {}).get(pname)
    if not p:
        click.echo(f"Profile '{pname}' not found.", err=True)
        sys.exit(1)
    # Mask plain text password in output
    display = json.loads(json.dumps(p))
    if display.get("auth", {}).get("type") == "plain" and "password" in display.get(
        "auth", {}
    ):
        display["auth"]["password"] = "***"
    click.echo(json.dumps({pname: display}, indent=2))


@profile.command("use")
@click.argument("name")
def profile_use(name):
    """Set the active profile."""
    cfg = _load_config()
    if name not in cfg.get("profiles", {}):
        click.echo(f"Profile '{name}' not found.", err=True)
        sys.exit(1)
    cfg["active"] = name
    _save_config(cfg)
    click.echo(f"Active profile: {name}")


@profile.command("delete")
@click.argument("name")
def profile_delete(name):
    """Delete a profile."""
    cfg = _load_config()
    if name not in cfg.get("profiles", {}):
        click.echo(f"Profile '{name}' not found.", err=True)
        sys.exit(1)
    del cfg["profiles"][name]
    if cfg.get("active") == name:
        remaining = list(cfg["profiles"].keys())
        cfg["active"] = remaining[0] if remaining else None
    _save_config(cfg)
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
@click.option("--kc-set-username", default=None, help="Update username in Keychain")
@click.option("--kc-set-password", default=None, help="Update password in Keychain")
@click.option("--username", default=None)
@click.option("--password", default=None)
def profile_update(
    name,
    url,
    auth_type,
    op_username,
    op_password,
    kc_service,
    kc_username_account,
    kc_password_account,
    kc_set_username,
    kc_set_password,
    username,
    password,
):
    """Update an existing profile's fields."""
    cfg = _load_config()
    p = cfg.get("profiles", {}).get(name)
    if not p:
        click.echo(f"Profile '{name}' not found.", err=True)
        sys.exit(1)

    if url:
        p["kibana_url"] = url.rstrip("/")

    auth = p.get("auth", {})
    if auth_type:
        auth = {"type": auth_type}

    at = auth.get("type")
    if at == "1password":
        if op_username:
            auth["username_ref"] = op_username
        if op_password:
            auth["password_ref"] = op_password
    elif at == "keychain":
        if kc_service:
            auth["service"] = kc_service
        if kc_username_account:
            auth["username_account"] = kc_username_account
        if kc_password_account:
            auth["password_account"] = kc_password_account
        svc = auth.get("service", name)
        if kc_set_username:
            acct = auth.get("username_account", f"{name}-username")
            _keychain_write(svc, acct, kc_set_username)
            click.echo("Updated username in Keychain", err=True)
        if kc_set_password:
            acct = auth.get("password_account", f"{name}-password")
            _keychain_write(svc, acct, kc_set_password)
            click.echo("Updated password in Keychain", err=True)
    elif at == "plain":
        if username:
            auth["username"] = username
        if password:
            auth["password"] = password
        if username or password:
            click.echo("Warning: credentials stored in plain text.", err=True)

    p["auth"] = auth
    cfg["profiles"][name] = p
    _save_config(cfg)
    click.echo(f"Updated profile '{name}'")


# ═══════════════════════════════════════════════════════════════════════════
# CLI: data commands
# ═══════════════════════════════════════════════════════════════════════════

# ── context ──


@cli.command()
@click.option("--refresh", is_flag=True, default=False)
@click.option("--indices", default=None, help="Index patterns (csv)")
@common
def context(refresh, indices, prof_name, timeout, dry_run, explain, fp, fmt, nc):
    """Compact context summary: indices, fields, doc counts. Cached."""
    prof = _get_profile(prof_name)
    kw = _kw(timeout, dry_run, explain, fp)
    if not refresh and not nc:
        c = cache_get("context", CACHE_TTL_CONTEXT)
        if c is not None:
            emit(c, fmt)
            return

    raw = es(prof, "GET", "_aliases", **kw)
    al = _aliases(raw)
    cache_put("aliases", al)
    pxs = _prefixes(raw)

    pats = (
        [p.strip() for p in indices.split(",")]
        if indices
        else pxs[:5]
    )

    maps: dict = {}
    counts: dict = {}
    for pat in pats:
        try:
            m = fetch_mapping(prof, pat, nc=refresh or nc, **kw)
            maps[pat] = next(iter(m.values()))
        except SystemExit:
            pass
        try:
            c = es(prof, "POST", f"{pat}/_count", {"query": _time_must("1h")}, **kw)
            counts[pat] = c.get("count", 0)
        except (SystemExit, Exception):
            pass

    ctx = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "prefixes": pxs,
        "aliases": al,
        "mappings": maps,
        "counts_1h": counts,
    }
    cache_put("context", ctx)
    emit(ctx, fmt)


# ── aliases ──


@cli.command()
@common
def aliases(prof_name, timeout, dry_run, explain, fp, fmt, nc):
    """List index aliases."""
    emit(
        fetch_aliases(_get_profile(prof_name), nc=nc, **_kw(timeout, dry_run, explain, fp)),
        fmt,
    )


# ── mapping ──


@cli.command()
@click.argument("index_pattern")
@click.option("--full", is_flag=True, default=False)
@common
def mapping(index_pattern, full, prof_name, timeout, dry_run, explain, fp, fmt, nc):
    """Index mapping (flat field:type, deduped)."""
    prof = _get_profile(prof_name)
    kw = _kw(timeout, dry_run, explain, fp)
    emit(
        es(prof, "GET", f"{index_pattern}/_mapping", **kw)
        if full
        else fetch_mapping(prof, index_pattern, nc=nc, **kw),
        fmt,
    )


# ── fields ──


@cli.command()
@click.argument("index_pattern")
@click.argument("glob", default="*")
@common
def fields(index_pattern, glob, prof_name, timeout, dry_run, explain, fp, fmt, nc):
    """Field names matching GLOB."""
    flat = fetch_mapping(
        _get_profile(prof_name), index_pattern, nc=nc, **_kw(timeout, dry_run, explain, fp)
    )
    matched = {
        k: v
        for _, fm in flat.items()
        for k, v in sorted(fm.items())
        if fnmatch.fnmatch(k, glob)
    }
    emit(matched, fmt)


# ── count ──


@cli.command()
@click.argument("index_pattern")
@click.option("--last", "tr", default=DEFAULT_TIME_RANGE)
@click.option("-q", "--query", "eq", default=None)
@common
def count(index_pattern, tr, eq, prof_name, timeout, dry_run, explain, fp, fmt, nc):
    """Count documents."""
    must = [_time_must(tr)]
    if eq:
        must.append(json.loads(eq))
    d = es(
        _get_profile(prof_name),
        "POST",
        f"{index_pattern}/_count",
        {"query": {"bool": {"must": must}}},
        **_kw(timeout, dry_run, explain, fp),
    )
    click.echo(d.get("count", d))


# ── search ──


@cli.command()
@click.argument("index_pattern")
@click.option("--last", "tr", default=DEFAULT_TIME_RANGE)
@click.option("-n", "--size", default=DEFAULT_SIZE, type=int)
@click.option("-q", "--query", "eq", default=None)
@click.option("-f", "--fields", "fc", default=None)
@click.option("--sort", "sf", default=DEFAULT_SORT)
@click.option("--aggs", default=None)
@click.option("--max-source-len", "msl", default=MAX_SOURCE_LEN, type=int)
@common
def search(
    index_pattern,
    tr,
    size,
    eq,
    fc,
    sf,
    aggs,
    msl,
    prof_name,
    timeout,
    dry_run,
    explain,
    fp,
    fmt,
    nc,
):
    """Search recent logs."""
    must = [_time_must(tr)]
    if eq:
        must.append(json.loads(eq))
    body: dict = {"query": {"bool": {"must": must}}, "size": size}
    s, _, o = sf.partition(":")
    body["sort"] = [{s: o or "desc"}]
    fl = _fl(fc)
    if fl:
        body["_source"] = fl
    if aggs:
        body["aggregations"] = json.loads(aggs)
    d = es(
        _get_profile(prof_name),
        "POST",
        f"{index_pattern}/_search",
        body,
        **_kw(timeout, dry_run, explain, fp),
    )
    emit(_search_result(d, fl, msl), fmt)


# ── tail ──


@cli.command()
@click.argument("index_pattern")
@click.option("--interval", default=2.0, type=float)
@click.option("--last", "tr", default="1m")
@click.option("-q", "--query", "eq", default=None)
@click.option("-f", "--fields", "fc", default=None)
@click.option("-n", "--size", default=50, type=int)
@click.option("--max-source-len", "msl", default=MAX_SOURCE_LEN, type=int)
@common
def tail(
    index_pattern,
    interval,
    tr,
    eq,
    fc,
    size,
    msl,
    prof_name,
    timeout,
    dry_run,
    explain,
    fp,
    fmt,
    nc,
):
    """Stream logs (search_after). Ctrl+C to stop."""
    prof = _get_profile(prof_name)
    fl = _fl(fc)
    must_base = [json.loads(eq)] if eq else []
    sa: list | None = None
    first = True
    signal.signal(signal.SIGINT, lambda *_: (click.echo("", err=True), sys.exit(0)))

    while True:
        must = list(must_base)
        if sa is None:
            must.append(_time_must(tr))
        body: dict = {
            "query": {"bool": {"must": must}},
            "size": size,
            "sort": [{"@timestamp": "asc"}, {"_id": "asc"}],
        }
        if fl:
            body["_source"] = fl
        if sa is not None:
            body["search_after"] = sa
        try:
            d = es(
                prof,
                "POST",
                f"{index_pattern}/_search",
                body,
                **_kw(timeout, dry_run, explain and first, fp),
            )
        except SystemExit:
            raise
        except Exception as e:
            click.echo(f"err: {e}", err=True)
            time.sleep(interval)
            continue
        for h in d.get("hits", {}).get("hits", []):
            ch = _hit(h, fl)
            s = json.dumps(ch, ensure_ascii=False, separators=(",", ":"))
            click.echo(s[:msl] + "…" if msl and len(s) > msl else s)
        hits = d.get("hits", {}).get("hits", [])
        if hits:
            sa = hits[-1].get("sort")
        first = False
        time.sleep(interval)


# ── histogram ──


@cli.command()
@click.argument("index_pattern")
@click.option("--last", "tr", default=DEFAULT_TIME_RANGE)
@click.option("--interval", default="5m")
@click.option("-q", "--query", "eq", default=None)
@click.option("--field", "tf", default="@timestamp")
@common
def histogram(
    index_pattern,
    tr,
    interval,
    eq,
    tf,
    prof_name,
    timeout,
    dry_run,
    explain,
    fp,
    fmt,
    nc,
):
    """Date histogram of doc counts."""
    must = [_time_must(tr, tf)]
    if eq:
        must.append(json.loads(eq))
    body = {
        "size": 0,
        "query": {"bool": {"must": must}},
        "aggregations": {
            "t": {
                "date_histogram": {
                    "field": tf,
                    "fixed_interval": interval,
                    "min_doc_count": 0,
                }
            }
        },
    }
    d = es(
        _get_profile(prof_name),
        "POST",
        f"{index_pattern}/_search",
        body,
        **_kw(timeout, dry_run, explain, fp),
    )
    bkts = d.get("aggregations", {}).get("t", {}).get("buckets", [])
    total = d.get("hits", {}).get("total", {})
    if isinstance(total, dict):
        total = total.get("value", "?")
    emit(
        {
            "total": total,
            "interval": interval,
            "buckets": [{"t": b["key_as_string"], "n": b["doc_count"]} for b in bkts],
        },
        fmt,
    )


# ── discover ──


@cli.command()
@click.argument("index_pattern")
@click.option("--last", "tr", default=DEFAULT_TIME_RANGE)
@click.option("--kql", default=None, help="KQL query")
@click.option("--lucene", default=None, help="Lucene query")
@click.option("-f", "--fields", "fc", default=None, help="Columns (csv)")
@click.option("--profile", "prof_name", default=None, envvar="KIBANA_AGENT_PROFILE")
def discover(index_pattern, tr, kql, lucene, fc, prof_name):
    """Build a Kibana Discover URL."""
    if kql and lucene:
        click.echo("Error: --kql or --lucene, not both.", err=True)
        sys.exit(1)
    prof = _get_profile(prof_name)
    lang = "kuery" if not lucene else "lucene"
    g = {
        "time": {"from": f"now-{tr}", "to": "now"},
        "refreshInterval": {"pause": True, "value": 0},
    }
    a: dict = {
        "index": index_pattern,
        "query": {"language": lang, "query": kql or lucene or ""},
    }
    cols = _fl(fc)
    if cols:
        a["columns"] = cols
    click.echo(f"{prof['kibana_url']}/app/discover#/?_g={_rison(g)}&_a={_rison(a)}")


# ── raw ──


@cli.command()
@click.argument("method", type=click.Choice(["GET", "POST"], case_sensitive=False))
@click.argument("es_path")
@click.option("--body", default=None)
@common
def raw(method, es_path, body, prof_name, timeout, dry_run, explain, fp, fmt, nc):
    """Raw read-only ES request."""
    d = es(
        _get_profile(prof_name),
        method.upper(),
        es_path,
        json.loads(body) if body else None,
        **_kw(timeout, dry_run, explain, fp),
    )
    emit(d, fmt)


# ── cache-clear ──


@cli.command("cache-clear")
def cache_clear():
    """Wipe all cached data (including Keychain credential cache)."""
    _cached_creds_clear()
    click.echo(f"Cleared {cache_clear_all()} files from {CACHE_DIR}")
    click.echo("Cleared cached credentials from Keychain.")


@cli.command("agent-help")
def agent_help():
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

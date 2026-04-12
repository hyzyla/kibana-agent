from __future__ import annotations

import json
from typing import Any

import pytest

from kibana_agent import client
from kibana_agent.client import (
    BlockedRequestError,
    DryRunResult,
    KibanaApiError,
    ProfileNotFoundError,
    _guard,
    _resolve_index,
    _space_prefix,
    op_count,
    op_fields,
    op_histogram,
    op_mapping,
    op_search,
    op_tail_page,
    resolve_profile,
)

# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------


PLAIN_PROFILE: dict[str, Any] = {
    "kibana_url": "https://kibana.example.com",
    "auth": {"type": "plain", "username": "alice", "password": "s3cret"},
}


class FakeResponse:
    def __init__(self, payload: Any, status: int = 200) -> None:
        self._payload = payload
        self.status_code = status
        self.text = json.dumps(payload)
        self.content = self.text.encode()

    def json(self) -> Any:
        return self._payload


class RequestRecorder:
    """Captures the last requests.post call so tests can assert on it."""

    def __init__(self, payload: Any, status: int = 200) -> None:
        self.payload = payload
        self.status = status
        self.last_url: str | None = None
        self.last_params: dict[str, str] | None = None
        self.last_json: dict[str, Any] | None = None
        self.last_auth: tuple[str, str] | None = None

    def __call__(self, url: str, **kwargs: Any) -> FakeResponse:
        self.last_url = url
        self.last_params = kwargs.get("params")
        self.last_json = kwargs.get("json")
        self.last_auth = kwargs.get("auth")
        return FakeResponse(self.payload, self.status)


@pytest.fixture(autouse=True)
def _clear_creds_cache() -> None:
    """The in-memory creds cache leaks across tests if not reset."""
    client._creds_cache.clear()


# ---------------------------------------------------------------------------
# Helpers (formerly in test_cli.py)
# ---------------------------------------------------------------------------


class TestSpacePrefix:
    def test_with_space(self) -> None:
        assert _space_prefix({"space": "backend"}) == "/s/backend"

    def test_without_space(self) -> None:
        assert _space_prefix({}) == ""

    def test_space_none(self) -> None:
        assert _space_prefix({"space": None}) == ""


class TestResolveIndex:
    def test_explicit_index(self) -> None:
        assert _resolve_index({}, "logs-*") == "logs-*"

    def test_default_from_profile(self) -> None:
        assert _resolve_index({"index": "logs-*"}, None) == "logs-*"

    def test_explicit_overrides_default(self) -> None:
        assert _resolve_index({"index": "logs-*"}, "other-*") == "other-*"

    def test_restrict_allows_matching_index(self) -> None:
        prof = {"index": "logs-*", "restrict_index": True}
        assert _resolve_index(prof, "logs-*") == "logs-*"

    def test_restrict_blocks_mismatched_index(self) -> None:
        prof = {"index": "logs-*", "restrict_index": True}
        with pytest.raises(client.IndexResolutionError):
            _resolve_index(prof, "other-*")

    def test_no_default_no_arg_raises(self) -> None:
        with pytest.raises(client.IndexResolutionError):
            _resolve_index({}, None)


# ---------------------------------------------------------------------------
# Safety guard
# ---------------------------------------------------------------------------


class TestGuard:
    def test_get_search_allowed(self) -> None:
        _guard("GET", "logs-*/_search")  # no raise

    def test_post_search_allowed(self) -> None:
        _guard("POST", "logs-*/_search")  # no raise

    def test_post_count_allowed(self) -> None:
        _guard("POST", "logs-*/_count")  # no raise

    @pytest.mark.parametrize(
        "method,path",
        [
            ("DELETE", "logs-*"),
            ("PUT", "logs-*/_settings"),
            ("HEAD", "logs-*"),
        ],
    )
    def test_non_get_post_blocked(self, method: str, path: str) -> None:
        with pytest.raises(BlockedRequestError):
            _guard(method, path)

    @pytest.mark.parametrize(
        "path",
        [
            "logs-*/_bulk",
            "_reindex",
            "logs-*/_delete_by_query",
            "logs-*/_update",
            "_snapshot/foo",
        ],
    )
    def test_blocked_endpoints(self, path: str) -> None:
        with pytest.raises(BlockedRequestError):
            _guard("POST", path)

    def test_post_unknown_endpoint_blocked(self) -> None:
        with pytest.raises(BlockedRequestError):
            _guard("POST", "logs-*/_made_up")


# ---------------------------------------------------------------------------
# Profile resolution
# ---------------------------------------------------------------------------


class TestResolveProfile:
    def _isolate_config(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any, config: dict[str, Any] | None
    ) -> None:
        cfg_file = tmp_path / "config.json"
        if config is not None:
            cfg_file.write_text(json.dumps(config))
        monkeypatch.setattr(client, "CONFIG_FILE", cfg_file)
        monkeypatch.setattr(client, "CONFIG_DIR", tmp_path)
        # Wipe all profile-related env vars so each test starts clean
        for var in (
            "KIBANA_AGENT_PROFILE",
            "KIBANA_URL",
            "KIBANA_USERNAME",
            "KIBANA_PASSWORD",
            "KIBANA_USERNAME_OP_REF",
            "KIBANA_PASSWORD_OP_REF",
            "KIBANA_SPACE",
            "KIBANA_INDEX",
        ):
            monkeypatch.delenv(var, raising=False)

    def test_explicit_name_loads_from_config(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
    ) -> None:
        self._isolate_config(
            monkeypatch,
            tmp_path,
            {
                "active": "stg",
                "profiles": {
                    "stg": {"kibana_url": "https://stg.example", "auth": {"type": "plain"}},
                    "prd": {"kibana_url": "https://prd.example", "auth": {"type": "plain"}},
                },
            },
        )
        prof = resolve_profile("prd")
        assert prof["kibana_url"] == "https://prd.example"

    def test_falls_back_to_active(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
    ) -> None:
        self._isolate_config(
            monkeypatch,
            tmp_path,
            {
                "active": "stg",
                "profiles": {
                    "stg": {"kibana_url": "https://stg.example", "auth": {"type": "plain"}},
                },
            },
        )
        prof = resolve_profile()
        assert prof["kibana_url"] == "https://stg.example"

    def test_env_profile_name(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
        self._isolate_config(
            monkeypatch,
            tmp_path,
            {
                "active": "stg",
                "profiles": {
                    "stg": {"kibana_url": "https://stg.example", "auth": {"type": "plain"}},
                    "prd": {"kibana_url": "https://prd.example", "auth": {"type": "plain"}},
                },
            },
        )
        monkeypatch.setenv("KIBANA_AGENT_PROFILE", "prd")
        assert resolve_profile()["kibana_url"] == "https://prd.example"

    def test_env_url_plain_creds_builds_ephemeral(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
    ) -> None:
        self._isolate_config(monkeypatch, tmp_path, None)
        monkeypatch.setenv("KIBANA_URL", "https://env.example/")
        monkeypatch.setenv("KIBANA_USERNAME", "alice")
        monkeypatch.setenv("KIBANA_PASSWORD", "s3cret")
        monkeypatch.setenv("KIBANA_INDEX", "logs-*")
        prof = resolve_profile()
        assert prof["kibana_url"] == "https://env.example"
        assert prof["index"] == "logs-*"
        assert prof["auth"] == {
            "type": "plain",
            "username": "alice",
            "password": "s3cret",
        }

    def test_env_url_op_refs_builds_ephemeral(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
    ) -> None:
        self._isolate_config(monkeypatch, tmp_path, None)
        monkeypatch.setenv("KIBANA_URL", "https://env.example")
        monkeypatch.setenv("KIBANA_USERNAME_OP_REF", "op://v/i/u")
        monkeypatch.setenv("KIBANA_PASSWORD_OP_REF", "op://v/i/p")
        prof = resolve_profile()
        assert prof["auth"]["type"] == "1password"
        assert prof["auth"]["username_ref"] == "op://v/i/u"

    def test_env_url_without_creds_raises(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
    ) -> None:
        self._isolate_config(monkeypatch, tmp_path, None)
        monkeypatch.setenv("KIBANA_URL", "https://env.example")
        with pytest.raises(ProfileNotFoundError, match="credentials"):
            resolve_profile()

    def test_no_profile_anywhere_raises(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
    ) -> None:
        self._isolate_config(monkeypatch, tmp_path, None)
        with pytest.raises(ProfileNotFoundError, match="profile create"):
            resolve_profile()

    def test_explicit_arg_beats_env(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
    ) -> None:
        self._isolate_config(
            monkeypatch,
            tmp_path,
            {
                "active": "stg",
                "profiles": {
                    "stg": {"kibana_url": "https://stg.example", "auth": {"type": "plain"}},
                    "prd": {"kibana_url": "https://prd.example", "auth": {"type": "plain"}},
                },
            },
        )
        monkeypatch.setenv("KIBANA_AGENT_PROFILE", "stg")
        prof = resolve_profile("prd")
        assert prof["kibana_url"] == "https://prd.example"


# ---------------------------------------------------------------------------
# es() and op_*
# ---------------------------------------------------------------------------


class TestEs:
    def test_dry_run_raises_dry_run_result(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Should not even attempt the network call.
        called = False

        def fail_post(*_a: Any, **_k: Any) -> Any:
            nonlocal called
            called = True
            raise AssertionError("network call should not happen during dry_run")

        monkeypatch.setattr(client.requests, "post", fail_post)
        with pytest.raises(DryRunResult) as exc:
            client.es(PLAIN_PROFILE, "POST", "logs-*/_search", {"q": 1}, dry_run=True)
        assert "curl" in exc.value.curl
        # The path is URL-encoded inside the proxy URL, so check for the encoded form.
        assert "logs-%2A%2F_search" in exc.value.curl
        assert called is False

    def test_4xx_raises_kibana_api_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        rec = RequestRecorder({"error": "boom"}, status=401)
        monkeypatch.setattr(client.requests, "post", rec)
        with pytest.raises(KibanaApiError) as exc:
            client.es(PLAIN_PROFILE, "POST", "logs-*/_search", {})
        assert exc.value.status == 401

    def test_passes_auth_and_url(self, monkeypatch: pytest.MonkeyPatch) -> None:
        rec = RequestRecorder({"hits": {"total": {"value": 0}, "hits": []}})
        monkeypatch.setattr(client.requests, "post", rec)
        client.es(PLAIN_PROFILE, "POST", "logs-*/_search", {"q": 1})
        assert rec.last_auth == ("alice", "s3cret")
        assert rec.last_url == "https://kibana.example.com/api/console/proxy"
        assert rec.last_params == {"path": "logs-*/_search", "method": "POST"}
        assert rec.last_json == {"q": 1}

    def test_space_prefix_applied(self, monkeypatch: pytest.MonkeyPatch) -> None:
        rec = RequestRecorder({"hits": {"total": {"value": 0}, "hits": []}})
        monkeypatch.setattr(client.requests, "post", rec)
        prof = {**PLAIN_PROFILE, "space": "backend"}
        client.es(prof, "POST", "logs-*/_search", {})
        assert rec.last_url == "https://kibana.example.com/s/backend/api/console/proxy"


class TestOpSearch:
    def test_builds_query_with_kql_and_time_range(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        rec = RequestRecorder(
            {
                "hits": {
                    "total": {"value": 2},
                    "hits": [
                        {"_source": {"level": "ERROR", "msg": "boom"}},
                        {"_source": {"level": "ERROR", "msg": "kapow"}},
                    ],
                }
            }
        )
        monkeypatch.setattr(client.requests, "post", rec)
        result = op_search(
            PLAIN_PROFILE,
            "logs-*",
            time_range="2h",
            kql="level:ERROR",
            size=10,
        )
        assert result["total"] == 2
        assert result["n"] == 2
        assert rec.last_params == {"path": "logs-*/_search", "method": "POST"}
        body = rec.last_json
        assert body is not None
        must = body["query"]["bool"]["must"]
        # First clause is the time range filter, second is the KQL translation
        assert must[0]["range"]["@timestamp"]["gte"] == "now-2h"
        assert len(must) == 2
        assert body["size"] == 10
        assert body["sort"] == [{"@timestamp": "desc"}]

    def test_extra_query_string_is_parsed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        rec = RequestRecorder({"hits": {"total": {"value": 0}, "hits": []}})
        monkeypatch.setattr(client.requests, "post", rec)
        op_search(
            PLAIN_PROFILE,
            "logs-*",
            extra_query='{"match":{"level":"ERROR"}}',
        )
        body = rec.last_json
        assert body is not None
        assert {"match": {"level": "ERROR"}} in body["query"]["bool"]["must"]

    def test_fields_projection(self, monkeypatch: pytest.MonkeyPatch) -> None:
        rec = RequestRecorder(
            {
                "hits": {
                    "total": {"value": 1},
                    "hits": [{"_source": {"a": 1, "b": 2, "c": 3}}],
                }
            }
        )
        monkeypatch.setattr(client.requests, "post", rec)
        result = op_search(PLAIN_PROFILE, "logs-*", fields=["a", "c"])
        assert result["hits"][0] == {"a": 1, "c": 3}
        assert rec.last_json is not None
        assert rec.last_json["_source"] == ["a", "c"]


class TestOpCount:
    def test_returns_int(self, monkeypatch: pytest.MonkeyPatch) -> None:
        rec = RequestRecorder({"count": 42})
        monkeypatch.setattr(client.requests, "post", rec)
        n = op_count(PLAIN_PROFILE, "logs-*", time_range="1h")
        assert n == 42
        assert rec.last_params == {"path": "logs-*/_count", "method": "POST"}


class TestOpHistogram:
    def test_returns_buckets(self, monkeypatch: pytest.MonkeyPatch) -> None:
        rec = RequestRecorder(
            {
                "hits": {"total": {"value": 5}},
                "aggregations": {
                    "t": {
                        "buckets": [
                            {"key_as_string": "2026-04-11T00:00:00Z", "doc_count": 3},
                            {"key_as_string": "2026-04-11T00:05:00Z", "doc_count": 2},
                        ]
                    }
                },
            }
        )
        monkeypatch.setattr(client.requests, "post", rec)
        result = op_histogram(PLAIN_PROFILE, "logs-*", interval="5m")
        assert result["total"] == 5
        assert result["interval"] == "5m"
        assert result["buckets"] == [
            {"t": "2026-04-11T00:00:00Z", "n": 3},
            {"t": "2026-04-11T00:05:00Z", "n": 2},
        ]


SAMPLE_MAPPING: dict[str, Any] = {
    "logs-2026.04.11": {
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "level": {"type": "keyword"},
                "host": {"properties": {"name": {"type": "keyword"}}},
            }
        }
    }
}


class TestOpMappingAndFields:
    def test_op_mapping_returns_flat_fields(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
    ) -> None:
        monkeypatch.setattr(client, "CACHE_DIR", tmp_path)
        monkeypatch.setattr(client, "CONFIG_DIR", tmp_path)
        monkeypatch.setattr(client, "CONFIG_FILE", tmp_path / "config.json")
        rec = RequestRecorder(SAMPLE_MAPPING)
        monkeypatch.setattr(client.requests, "post", rec)
        result = op_mapping(PLAIN_PROFILE, "logs-*", no_cache=True)
        # _parse_mapping wraps fields under the index name
        assert any("level" in fields for fields in result.values())
        assert any("host.name" in fields for fields in result.values())

    def test_op_fields_glob(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
        monkeypatch.setattr(client, "CACHE_DIR", tmp_path)
        monkeypatch.setattr(client, "CONFIG_DIR", tmp_path)
        monkeypatch.setattr(client, "CONFIG_FILE", tmp_path / "config.json")
        rec = RequestRecorder(SAMPLE_MAPPING)
        monkeypatch.setattr(client.requests, "post", rec)
        result = op_fields(PLAIN_PROFILE, "logs-*", glob="host.*", no_cache=True)
        assert "host.name" in result
        assert "level" not in result


class TestOpTailPage:
    def test_first_page_uses_time_range(self, monkeypatch: pytest.MonkeyPatch) -> None:
        rec = RequestRecorder(
            {
                "hits": {
                    "hits": [
                        {"_source": {"msg": "a"}, "sort": [1, "x"]},
                        {"_source": {"msg": "b"}, "sort": [2, "y"]},
                    ]
                }
            }
        )
        monkeypatch.setattr(client.requests, "post", rec)
        page = op_tail_page(PLAIN_PROFILE, "logs-*")
        assert page["next_cursor"] == [2, "y"]
        assert len(page["hits"]) == 2
        body = rec.last_json
        assert body is not None
        assert "search_after" not in body
        # The first call applies the time range filter
        assert body["query"]["bool"]["must"][-1]["range"]["@timestamp"]["gte"] == "now-1m"

    def test_subsequent_page_uses_cursor(self, monkeypatch: pytest.MonkeyPatch) -> None:
        rec = RequestRecorder({"hits": {"hits": []}})
        monkeypatch.setattr(client.requests, "post", rec)
        page = op_tail_page(PLAIN_PROFILE, "logs-*", since_cursor=[42, "z"])
        assert page["next_cursor"] == [42, "z"]  # cursor preserved when no new hits
        body = rec.last_json
        assert body is not None
        assert body["search_after"] == [42, "z"]
        # No time range filter once we have a cursor
        assert body["query"]["bool"]["must"] == []

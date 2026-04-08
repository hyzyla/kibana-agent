from __future__ import annotations

import pytest

from kibana_agent.cli import _resolve_index, _space_prefix


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
        with pytest.raises(SystemExit):
            _resolve_index(prof, "other-*")

    def test_no_default_no_arg_exits(self) -> None:
        with pytest.raises(SystemExit):
            _resolve_index({}, None)

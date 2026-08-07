from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from kibana_agent import cli as cli_module
from kibana_agent.cli import cli


def test_cli_help_runs() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "kibana" in result.output.lower()


def test_mcp_subcommand_listed_in_help() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "mcp" in result.output


def test_mcp_help_does_not_eagerly_import_server() -> None:
    """`kibana-agent mcp --help` must not require the `mcp` package to be importable."""
    import sys

    # Drop any cached server import so we can detect a fresh load.
    sys.modules.pop("kibana_agent.server", None)
    runner = CliRunner()
    result = runner.invoke(cli, ["mcp", "--help"])
    assert result.exit_code == 0
    # The lazy import lives inside the command body, so --help shouldn't trigger it.
    assert "kibana_agent.server" not in sys.modules


class TestEmit:
    def test_raw_response_keeps_body(self, capsys: pytest.CaptureFixture[str]) -> None:
        response = {"took": 1, "hits": {"total": {"value": 2}, "hits": [{"_id": "a"}]}}
        cli_module.emit(response, "compact")
        assert json.loads(capsys.readouterr().out) == response

    def test_formatted_result_prints_one_hit_per_line(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        cli_module.emit({"total": 2, "n": 2, "hits": [{"a": 1}, {"a": 2}]}, "compact")
        lines = capsys.readouterr().out.strip().split("\n")
        assert lines[0] == '#{"total":2,"n":2}'
        assert [json.loads(line) for line in lines[1:]] == [{"a": 1}, {"a": 2}]

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from kibana_agent import cli as cli_module
from kibana_agent import client
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


def test_profile_update_drops_the_cached_creds(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(client, "CONFIG_FILE", tmp_path / "config.json")
    monkeypatch.setattr(client, "CONFIG_DIR", tmp_path)
    auth = {
        "type": "keychain",
        "service": "kibana-prd",
        "username_account": "user",
        "password_account": "pass",
    }
    client.save_config(
        {"active": "prd", "profiles": {"prd": {"kibana_url": "https://k", "auth": auth}}}
    )
    deleted: list[str] = []
    monkeypatch.setattr(client, "keychain_delete", lambda service, account: deleted.append(account))

    result = CliRunner().invoke(cli, ["profile", "update", "prd", "--kc-password-account", "new"])

    assert result.exit_code == 0, result.output
    assert deleted == list(client._cred_cache_accounts({"_name": "prd"}))

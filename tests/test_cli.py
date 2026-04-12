from __future__ import annotations

from click.testing import CliRunner

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

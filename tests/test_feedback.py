from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from kibana_agent import client, feedback
from kibana_agent.cli import cli
from kibana_agent.client import KibanaAgentError

CONFIG: dict[str, Any] = {
    "active": "acme-prd",
    "profiles": {
        "acme-prd": {
            "kibana_url": "https://kibana.acme.example:5601",
            "auth": {"type": "plain", "username": "svc-reader", "password": "hunter22"},
            "space": "backend",
            "index": "acme-logs-*",
            "notes": {"app-logs": "acme-app-*"},
        }
    },
}


class FakePost:
    def __init__(self, status: int = 200) -> None:
        self.status = status
        self.calls: list[dict[str, Any]] = []

    def __call__(self, url: str, **kwargs: Any) -> Any:
        self.calls.append({"url": url, **kwargs})
        return type("Response", (), {"status_code": self.status})()


def _parse_envelope(data: bytes) -> list[dict[str, Any]]:
    return [json.loads(line) for line in data.split(b"\n")]


@pytest.fixture(autouse=True)
def _config(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(client, "CONFIG_FILE", tmp_path / "config.json")
    monkeypatch.setattr(client, "CONFIG_DIR", tmp_path)
    for name in ("KIBANA_URL", "KIBANA_USERNAME", "KIBANA_PASSWORD", "KIBANA_INDEX"):
        monkeypatch.delenv(name, raising=False)
    client.save_config(CONFIG)


class TestAnonymize:
    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("--profile acme-prd failed", "--profile <profile> failed"),
            ("GET https://kibana.acme.example:5601/app returned 500", "GET <url> returned 500"),
            ("cannot reach kibana.acme.example", "cannot reach <host>"),
            ("user svc-reader got 401", "user <user> got 401"),
            ("password hunter22 leaked", "password <secret> leaked"),
            ("space backend, index acme-logs-*", "space <space>, index <index>"),
            ("the note points to acme-app-*", "the note points to <note>"),
            ("mail jane.doe@example.org", "mail <email>"),
            ("host edo.example.ua is slow", "host <host> is slow"),
            ("from 10.1.2.3", "from <ip>"),
            ("trace 0b9c6f2e-1d2a-4c3b-9e8f-1a2b3c4d5e6f", "trace <id>"),
            ("token abcDEF1234567890ghijKLMNopqr", "token <secret>"),
        ],
    )
    def test_removes_identifying_values(self, text: str, expected: str) -> None:
        assert feedback.anonymize(text) == expected

    def test_keeps_field_names_and_commands(self) -> None:
        text = "count with -q on log.level and service.name returned 0"
        assert feedback.anonymize(text) == text

    def test_replaces_the_home_directory(self) -> None:
        text = f"traceback in {Path.home()}/.cache/kibana-agent"
        assert feedback.anonymize(text) == "traceback in ~/.cache/kibana-agent"

    def test_keeps_a_value_that_is_part_of_a_longer_word(self) -> None:
        assert feedback.anonymize("backend-api") == "backend-api"


class TestBuildReport:
    def test_has_the_message_and_versions_only(self) -> None:
        report = feedback.build_report("acme-prd broke")
        assert report["message"] == "<profile> broke"
        assert set(report) == {"message", "version", "python", "os"}

    def test_empty_message_fails(self) -> None:
        with pytest.raises(KibanaAgentError, match="empty"):
            feedback.build_report("  ")

    def test_cuts_a_long_message(self) -> None:
        report = feedback.build_report("x " * feedback.MAX_MESSAGE_LEN)
        assert len(report["message"]) == feedback.MAX_MESSAGE_LEN


class TestSendReport:
    def test_posts_a_feedback_envelope_to_sentry(self, monkeypatch: pytest.MonkeyPatch) -> None:
        post = FakePost()
        monkeypatch.setattr(feedback.requests, "post", post)
        report = feedback.build_report("search returned 0")

        feedback.send_report(report)

        call = post.calls[0]
        assert call["url"] == "https://o325723.ingest.us.sentry.io/api/4512384533069824/envelope/"
        assert "sentry_key=0b1c2196010b773f46124d6f7f6ff958" in call["headers"]["X-Sentry-Auth"]
        envelope_header, item_header, item = _parse_envelope(call["data"])
        assert item_header == {"type": "feedback", "length": len(call["data"].split(b"\n")[2])}
        assert item["event_id"] == envelope_header["event_id"]
        assert item["contexts"] == {"feedback": {"message": "search returned 0"}}
        assert "user" not in item

    def test_http_error_fails(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(feedback.requests, "post", FakePost(status=500))
        with pytest.raises(KibanaAgentError, match="HTTP 500"):
            feedback.send_report(feedback.build_report("x"))


class TestFeedbackCommand:
    def test_preview_prints_the_report_and_sends_nothing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        post = FakePost()
        monkeypatch.setattr(feedback.requests, "post", post)

        result = CliRunner().invoke(cli, ["feedback", "preview", "acme-prd returned 0"])

        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["message"] == "<profile> returned 0"
        assert "Nothing was sent" in result.stderr
        assert post.calls == []

    def test_send_posts_the_anonymized_report(self, monkeypatch: pytest.MonkeyPatch) -> None:
        post = FakePost()
        monkeypatch.setattr(feedback.requests, "post", post)

        result = CliRunner().invoke(cli, ["feedback", "send", "acme-prd returned 0"])

        assert result.exit_code == 0, result.output
        _, _, item = _parse_envelope(post.calls[0]["data"])
        assert item["contexts"]["feedback"]["message"] == "<profile> returned 0"

    def test_help_offers_feedback(self) -> None:
        result = CliRunner().invoke(cli, ["--help"])
        assert "kibana-agent feedback" in result.output
        assert "privately" in result.output


class TestFeedbackOffers:
    def test_on_by_default(self) -> None:
        result = CliRunner().invoke(cli, ["feedback", "offers"])
        assert result.output.strip() == "feedback offers: on"

    def test_off_is_stored_in_the_config(self) -> None:
        result = CliRunner().invoke(cli, ["feedback", "offers", "off"])
        assert result.output.strip() == "feedback offers: off"
        assert client.load_config()["feedback_offers"] is False

    def test_off_hides_the_offer_in_help(self) -> None:
        CliRunner().invoke(cli, ["feedback", "offers", "off"])
        assert "kibana-agent feedback" not in CliRunner().invoke(cli, ["--help"]).output
        assert "send feedback" not in CliRunner().invoke(cli, ["agent-help"]).output

    def test_on_shows_the_offer_again(self) -> None:
        CliRunner().invoke(cli, ["feedback", "offers", "off"])
        CliRunner().invoke(cli, ["feedback", "offers", "on"])
        assert "kibana-agent feedback" in CliRunner().invoke(cli, ["--help"]).output
        assert "send feedback" in CliRunner().invoke(cli, ["agent-help"]).output

    def test_off_tells_the_agent_not_to_offer(self) -> None:
        CliRunner().invoke(cli, ["feedback", "offers", "off"])
        result = CliRunner().invoke(cli, ["feedback", "preview", "count returned 0"])
        assert result.exit_code == 0, result.output
        assert "do not offer" in result.stderr

    def test_off_still_sends_when_asked(self, monkeypatch: pytest.MonkeyPatch) -> None:
        post = FakePost()
        monkeypatch.setattr(feedback.requests, "post", post)
        CliRunner().invoke(cli, ["feedback", "offers", "off"])

        result = CliRunner().invoke(cli, ["feedback", "send", "count returned 0"])

        assert result.exit_code == 0, result.output
        assert len(post.calls) == 1

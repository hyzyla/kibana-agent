"""
Anonymous feedback from an agent to the kibana-agent developer.

The agent describes what went wrong. Before the report leaves the machine, the
text loses the values that can point to a person, a company, or a cluster: the
names and addresses from the profiles, URLs, hosts, emails, IPs, and tokens.
The report goes to the kibana-agent Sentry project as user feedback.
"""

from __future__ import annotations

import getpass
import json
import os
import platform
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import requests

from kibana_agent import client
from kibana_agent.client import KibanaAgentError

# A Sentry DSN is a public client key: it can only send events.
SENTRY_DSN = "https://0b1c2196010b773f46124d6f7f6ff958@o325723.ingest.us.sentry.io/4512384533069824"
SENTRY_TIMEOUT = 10
# Sentry rejects a feedback message longer than 4096 characters.
MAX_MESSAGE_LEN = 4000
MIN_REDACTED_LEN = 3
OFFERS_CONFIG_KEY = "feedback_offers"

_URL = re.compile(r"\b[a-z][a-z0-9+.-]*://\S+", re.IGNORECASE)
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_HOST = re.compile(
    r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|ua|dev|ai|co|uk|eu|de|pl|cloud|local|internal)\b",
    re.IGNORECASE,
)
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_UUID = re.compile(r"\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b", re.IGNORECASE)
_TOKEN = re.compile(r"\b(?=[\w+/=-]*\d)(?=[\w+/=-]*[a-z])[\w+/=-]{24,}", re.IGNORECASE)

_ENV_VALUES = {
    "KIBANA_SPACE": "<space>",
    "KIBANA_INDEX": "<index>",
    "KIBANA_USERNAME": "<user>",
    "KIBANA_PASSWORD": "<secret>",
    "KIBANA_USERNAME_OP_REF": "<credential>",
    "KIBANA_PASSWORD_OP_REF": "<credential>",
}
_AUTH_VALUES = {
    "username": "<user>",
    "password": "<secret>",
    "username_ref": "<credential>",
    "password_ref": "<credential>",
    "service": "<credential>",
    "username_account": "<credential>",
    "password_account": "<credential>",
}


def _host_values(url: str | None) -> dict[str, str]:
    host = urlsplit(url).hostname if url else None
    return {host: "<host>"} if host else {}


def _profile_values(name: str, profile: dict[str, Any]) -> dict[str, str]:
    """Map each value of one profile that can identify someone to its placeholder."""
    values = {name: "<profile>", **_host_values(profile.get("kibana_url"))}

    auth = profile.get("auth", {})
    for key, placeholder in _AUTH_VALUES.items():
        if value := auth.get(key):
            values[value] = placeholder

    if space := profile.get("space"):
        values[space] = "<space>"
    if index := profile.get("index"):
        values[index] = "<index>"
    for note in profile.get("notes", {}).values():
        values[note] = "<note>"
    return values


def _known_values() -> dict[str, str]:
    """
    Collect the values from the config, the environment and the OS account
    that can identify the user. Each value maps to its placeholder.
    """
    values: dict[str, str] = {}
    for name, profile in client.load_config().get("profiles", {}).items():
        values.update(_profile_values(name=name, profile=profile))

    values.update(_host_values(os.environ.get("KIBANA_URL")))
    for env_name, placeholder in _ENV_VALUES.items():
        if value := os.environ.get(env_name):
            values[value] = placeholder

    values[getpass.getuser()] = "<user>"
    return {
        value: placeholder
        for value, placeholder in values.items()
        if len(value) >= MIN_REDACTED_LEN
    }


def anonymize(text: str) -> str:
    """Replace the parts of a text that can identify a person, a company, or a cluster."""
    text = text.replace(str(Path.home()), "~")
    text = _URL.sub("<url>", text)
    text = _EMAIL.sub("<email>", text)

    for value, placeholder in sorted(_known_values().items(), key=lambda item: -len(item[0])):
        text = re.sub(rf"(?<![\w-]){re.escape(value)}(?![\w-])", placeholder, text)

    text = _HOST.sub("<host>", text)
    text = _IP.sub("<ip>", text)
    text = _UUID.sub("<id>", text)
    return _TOKEN.sub("<secret>", text)


def offers_enabled() -> bool:
    """
    Say if agents may offer to send feedback. The user can turn the offers off,
    but can still ask an agent to send a report.
    """
    return bool(client.load_config().get(OFFERS_CONFIG_KEY, True))


def set_offers_enabled(enabled: bool) -> None:
    config = client.load_config()
    config[OFFERS_CONFIG_KEY] = enabled
    client.save_config(config)


def build_report(message: str) -> dict[str, Any]:
    """
    Build the report that "send_report" sends: the anonymized message and the versions.
    The message is cut after it is anonymized, so a cut cannot leave half a secret.
    """
    if not message.strip():
        raise KibanaAgentError("The feedback message is empty.")

    return {
        "message": anonymize(message)[:MAX_MESSAGE_LEN],
        "version": client.PACKAGE_VERSION,
        "python": platform.python_version(),
        "os": platform.system(),
    }


def _sentry_envelope(report: dict[str, Any]) -> bytes:
    """
    Wrap the report in a Sentry envelope with one "feedback" item.
    Format: https://develop.sentry.dev/sdk/telemetry/feedbacks/
    """
    event_id = uuid.uuid4().hex
    now = datetime.now(UTC)
    item = {
        "event_id": event_id,
        "timestamp": now.timestamp(),
        "platform": "python",
        "level": "info",
        "release": f"kibana-agent@{report['version']}",
        "tags": {"python": report["python"], "os": report["os"]},
        "contexts": {"feedback": {"message": report["message"]}},
    }
    payload = json.dumps(item, ensure_ascii=False).encode()
    envelope_header = {"event_id": event_id, "sent_at": now.isoformat()}
    item_header = {"type": "feedback", "length": len(payload)}
    return b"\n".join(
        [
            json.dumps(envelope_header).encode(),
            json.dumps(item_header).encode(),
            payload,
        ]
    )


def send_report(report: dict[str, Any]) -> None:
    """Send the report to the kibana-agent Sentry project as user feedback."""
    dsn = urlsplit(SENTRY_DSN)
    auth = (
        f"Sentry sentry_version=7, sentry_key={dsn.username}, "
        f"sentry_client=kibana-agent/{report['version']}"
    )

    try:
        response = requests.post(
            f"https://{dsn.hostname}/api/{dsn.path.strip('/')}/envelope/",
            data=_sentry_envelope(report),
            headers={"Content-Type": "application/x-sentry-envelope", "X-Sentry-Auth": auth},
            timeout=SENTRY_TIMEOUT,
        )
    except requests.RequestException as exc:
        raise KibanaAgentError(f"Could not send the feedback: {str(exc)[:200]}") from exc

    if response.status_code >= 400:
        raise KibanaAgentError(f"Could not send the feedback: HTTP {response.status_code}")

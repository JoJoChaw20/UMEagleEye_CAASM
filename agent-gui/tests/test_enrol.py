"""Connection code from the dashboard's Agents page (eagleeye/enrol.py)."""

from __future__ import annotations

import argparse

import pytest

from eagleeye.cli import _settings_from, build_parser
from eagleeye.config import ConfigError
from eagleeye.enrol import ConnectionCodeError, parse_connection_code

# Made by the dashboard's own encoder (frontend/src/utils/connectionCode.js), so a change
# on either side that breaks the other fails here.
FROM_DASHBOARD = (
    "EE1.eyJ1IjoiaHR0cHM6Ly91bWVhZ2xlZXllLWFwaS1zdGFnaW5nLnN5bnRheGNoNDA0LndvcmtlcnMuZGV2L2FwaS92MSIsImkiOiI3YzFl"
    "OTRhMi0zYjVkLTRmMDgtOWE2MS0yZDBjNWU3YjhmMTMiLCJrIjoiZWVfazN5LXdpdGgvb2RkK2NoYXJzPT0ifQ"
)
EXPECTED = ("https://umeagleeye-api-staging.syntaxch404.workers.dev/api/v1",
            "7c1e94a2-3b5d-4f08-9a61-2d0c5e7b8f13", "ee_k3y-with/odd+chars==")


def test_a_code_from_the_dashboard_gives_the_three_values():
    assert parse_connection_code(FROM_DASHBOARD) == EXPECTED


def test_copy_artefacts_are_ignored():
    wrapped = '  "' + FROM_DASHBOARD[:40] + "\n" + FROM_DASHBOARD[40:90] + " " + FROM_DASHBOARD[90:] + '"\n'
    assert parse_connection_code(wrapped) == EXPECTED


@pytest.mark.parametrize("text, says", [
    ("", "Paste the connection code"),
    ("https://umeagleeye-api.example/api/v1", "not an EagleEye connection code"),
    (FROM_DASHBOARD[:60], "incomplete or damaged"),          # cut short when copying
    ("EE1.!!!not-base64!!!", "incomplete or damaged"),
    ("EE1.eyJ1IjoiZnRwOi8veCIsImkiOiJ4IiwiayI6InkifQ", "incomplete or damaged"),   # {"u":"ftp://x","i":"x","k":"y"}
    ("EE1.eyJ1IjogImh0dHBzOi8veC5leGFtcGxlL2FwaS92MSIsICJpIjogIm5vdC1hLXV1aWQiLCAiayI6ICJ5In0", "incomplete or damaged"),   # a valid URL but a broken agent ID
])
def test_unusable_codes_say_what_to_do(text, says):
    with pytest.raises(ConnectionCodeError, match=says):
        parse_connection_code(text)


def _args(*argv: str) -> argparse.Namespace:
    return build_parser().parse_args(["config", "show", *argv])


def test_command_line_code_sets_the_three_values(tmp_path, monkeypatch):
    for var in ("EAGLEEYE_API_URL", "EAGLEEYE_AGENT_ID", "EAGLEEYE_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    s = _settings_from(_args("--config", str(tmp_path / "c.json"), "--connection-code", FROM_DASHBOARD))
    assert (s.api_url, s.agent_id, s.api_key) == EXPECTED
    # A value given with its own flag still wins over the code.
    s = _settings_from(_args("--config", str(tmp_path / "c.json"), "--connection-code", FROM_DASHBOARD,
                             "--api-url", "https://other.example/api/v1"))
    assert s.api_url == "https://other.example/api/v1" and s.agent_id == EXPECTED[1]


def test_command_line_bad_code_is_a_config_error(tmp_path):
    with pytest.raises(ConfigError, match="not an EagleEye connection code"):
        _settings_from(_args("--config", str(tmp_path / "c.json"), "--connection-code", "hello"))

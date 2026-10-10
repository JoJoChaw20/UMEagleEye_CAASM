from __future__ import annotations

import json

import pytest

from eagleeye.config import ConfigError, Settings, load_settings, save_settings


def test_defaults(tmp_path):
    s = load_settings(tmp_path / "missing.json", env={})
    assert (s.poll_interval, s.heartbeat_interval, s.passive_interval) == (30, 30, 60)
    assert s.passive is False and not s.snmp_enabled
    assert s.problems() == ["api_url is not set", "api_key is not set", "agent_id is not set"]


def test_precedence_file_then_env_then_flags(tmp_path):
    cfg = tmp_path / "c.json"
    cfg.write_text(json.dumps({"api_url": "http://file", "poll_interval": 11, "agent_id": "from-file"}))
    env = {"EAGLEEYE_API_URL": "http://env", "EAGLEEYE_POLL_INTERVAL": "22"}
    s = load_settings(cfg, env=env, overrides={"poll_interval": 33, "api_key": None})
    assert s.api_url == "http://env"        # env beats file
    assert s.poll_interval == 33            # flag beats env
    assert s.agent_id == "from-file"        # file used when nothing overrides
    assert s.api_key == ""                  # None override = unset


@pytest.mark.parametrize("raw, expected", [("1", True), ("true", True), ("YES", True), ("0", False), ("false", False)])
def test_passive_flag_parsing(raw, expected, tmp_path):
    assert load_settings(tmp_path / "x", env={"EAGLEEYE_PASSIVE": raw}).passive is expected


def test_env_can_switch_passive_off_over_file(tmp_path):
    cfg = tmp_path / "c.json"
    cfg.write_text(json.dumps({"passive": True}))
    assert load_settings(cfg, env={"EAGLEEYE_PASSIVE": "0"}).passive is False


def test_bad_number_is_a_config_error(tmp_path):
    with pytest.raises(ConfigError, match="poll_interval"):
        load_settings(tmp_path / "x", env={"EAGLEEYE_POLL_INTERVAL": "soon"})


def test_corrupt_config_file_is_a_config_error(tmp_path):
    cfg = tmp_path / "c.json"
    cfg.write_text("{not json")
    with pytest.raises(ConfigError, match="cannot read config file"):
        load_settings(cfg, env={})


def test_unknown_keys_in_file_are_ignored(tmp_path):
    cfg = tmp_path / "c.json"
    cfg.write_text(json.dumps({"api_url": "http://x", "future_option": 1}))
    assert load_settings(cfg, env={}).api_url == "http://x"


def test_snmp_needs_the_full_credential_set():
    assert not Settings(snmp_user="u", snmp_auth_key="a").snmp_enabled
    assert Settings(snmp_user="u", snmp_auth_key="a", snmp_priv_key="p").snmp_enabled


def test_problems_flags_bad_url_and_short_intervals():
    s = Settings(api_url="ftp://x", api_key="k", agent_id="a", poll_interval=1)
    assert "api_url must start with http:// or https://" in s.problems()
    assert "poll_interval must be at least 5 seconds" in s.problems()


def test_redacted_masks_secrets():
    s = Settings(api_key="abcdef123456", snmp_priv_key="privatekey")
    red = s.redacted()
    assert red["api_key"] == "****3456"
    assert red["snmp_priv_key"] == "****ekey"
    assert red["fingerbank_key"] == ""                      # unset stays empty, not masked
    assert "abcdef" not in json.dumps(red)


def test_save_and_reload_roundtrip(tmp_path):
    path = save_settings(Settings(api_url="http://x", api_key="k", agent_id="a", passive=True), tmp_path / "sub" / "c.json")
    loaded = load_settings(path, env={})
    assert (loaded.api_url, loaded.api_key, loaded.agent_id, loaded.passive) == ("http://x", "k", "a", True)

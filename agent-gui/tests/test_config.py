from __future__ import annotations

import json

import pytest

from eagleeye.config import ConfigError, Settings, load_settings, save_settings, with_credentials


def test_defaults(tmp_path):
    s = load_settings(tmp_path / "missing.json", env={})
    assert (s.poll_interval, s.heartbeat_interval, s.passive_interval) == (30, 30, 300)
    assert s.passive is False and s.kind == "host"
    assert s.problems() == ["api_url is not set", "api_key is not set", "agent_id is not set"]


def test_a_config_saved_before_2_2_2_moves_from_the_old_60_s_default_to_5_minutes(tmp_path):
    cfg = tmp_path / "c.json"
    cfg.write_text(json.dumps({"passive_interval": 60}))            # every old save wrote 60
    s = load_settings(cfg, env={})
    assert s.passive_interval == 300 and s.config_version == 2


def test_an_interval_set_by_hand_is_kept(tmp_path):
    cfg = tmp_path / "c.json"
    cfg.write_text(json.dumps({"passive_interval": 120}))           # old file, chosen value
    assert load_settings(cfg, env={}).passive_interval == 120
    save_settings(Settings(passive_interval=60), cfg)               # 60 chosen after 2.2.2
    assert load_settings(cfg, env={}).passive_interval == 60
    assert load_settings(cfg, env={"EAGLEEYE_PASSIVE_INTERVAL": "45"}).passive_interval == 45


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


def test_inventory_always_includes_user_software_and_never_admin_names(tmp_path):
    path = tmp_path / "c.json"
    # an old config that had them set: no longer settings (only the count of administrators is sent)
    path.write_text(json.dumps({"inventory_user_software": False, "inventory_admin_names": True}), encoding="utf-8")
    s = load_settings(path, env={"EAGLEEYE_INVENTORY_ADMIN_NAMES": "1"})
    assert s.inventory_options == {"user_software": True, "admin_names": False}
    assert not hasattr(s, "inventory_admin_names")


def test_a_new_agent_starts_from_the_defaults_and_keeps_what_belongs_to_the_computer():
    old = Settings(api_url="https://a/api/v1", agent_id="old-id", api_key="k1", passive=True, inventory_interval=86400,
                   schedules=[{"subnet": "10.0.0.0/24"}], scan_ports="wide", passive_interface="Ethernet 2",
                   sbom_extra_paths="D:/Tools", fingerbank_key="fb", consent_version=6, kind="host")
    same = with_credentials(old, "https://a/api/v1/", "OLD-ID", "k2")           # a new key for the same agent
    assert same is old and (same.api_key, same.passive, same.schedules) == ("k2", True, [{"subnet": "10.0.0.0/24"}])
    new = with_credentials(old, "https://a/api/v1", "new-id", "k3")
    assert (new.api_url, new.agent_id, new.api_key) == ("https://a/api/v1", "new-id", "k3")
    assert (new.passive, new.inventory_interval, new.schedules, new.scan_ports) == (False, 21600, [], "base")
    kept = (new.passive_interface, new.sbom_extra_paths, new.fingerbank_key, new.consent_version)
    assert kept == ("Ethernet 2", "D:/Tools", "fb", 6)
    assert with_credentials(old, "https://b/api/v1", "old-id", "k").passive is False   # another server
    fresh = Settings(passive=True)                                                 # not connected yet: kept
    assert with_credentials(fresh, "https://a", "id", "k").passive is True


def test_save_and_reload_roundtrip(tmp_path):
    path = save_settings(Settings(api_url="http://x", api_key="k", agent_id="a", passive=True), tmp_path / "sub" / "c.json")
    loaded = load_settings(path, env={})
    assert (loaded.api_url, loaded.api_key, loaded.agent_id, loaded.passive) == ("http://x", "k", "a", True)


# ── several agents on one PC (EAGLEEYE_CONFIG) ──
def test_default_config_is_the_unnamed_instance(tmp_path):
    from eagleeye.config import instance_name, state_path
    env = {"APPDATA": str(tmp_path)}
    assert instance_name(env) == ""
    assert state_path(env).name == "state.json"


def test_a_named_config_is_its_own_instance_with_its_own_state(tmp_path):
    from eagleeye.config import instance_name, state_path
    env = {"EAGLEEYE_CONFIG": str(tmp_path / "config-production.json")}
    assert instance_name(env) == "production"
    assert state_path(env) == tmp_path / "state-production.json"


def test_instance_names_are_safe_and_config_json_elsewhere_is_unnamed(tmp_path):
    from eagleeye.config import instance_name
    assert instance_name({"EAGLEEYE_CONFIG": str(tmp_path / "lab agent#2.json")}) == "lab_agent_2"
    assert instance_name({"EAGLEEYE_CONFIG": str(tmp_path / "config.json")}) == ""


def test_passive_capture_defaults_to_automatic_and_is_validated(tmp_path):
    assert load_settings(tmp_path / "missing.json", env={}).passive_backend == "auto"
    assert load_settings(tmp_path / "missing.json", env={"EAGLEEYE_PASSIVE_BACKEND": "native"}).passive_backend == "native"
    s = Settings(api_url="https://x", api_key="k", agent_id="a", passive_backend="pktmon")
    assert s.problems() == ["passive_backend must be auto, npcap or native"]

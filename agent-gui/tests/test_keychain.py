from __future__ import annotations

import json

import pytest

from eagleeye.config import ConfigError, Settings, load_settings, save_settings


class FakeKeychain:
    def __init__(self, available=True, fail=False):
        self._available, self.fail, self.items = available, fail, {}

    def available(self):
        return self._available

    def get(self, name):
        return self.items.get(name)

    def set(self, name, value):
        if self.fail:
            return False
        if value:
            self.items[name] = value
        else:
            self.items.pop(name, None)
        return True


def test_secrets_go_to_the_keychain_not_the_file(tmp_path):
    kc = FakeKeychain()
    path = save_settings(Settings(api_url="http://x", api_key="secret-key-1234", agent_id="a", snmp_priv_key="pp"),
                         tmp_path / "c.json", keychain=kc)
    text = path.read_text()
    assert "secret-key-1234" not in text and "pp" not in json.loads(text)["snmp_priv_key"]
    assert json.loads(text)["secrets_in_keychain"] is True
    assert kc.items == {"a/api_key": "secret-key-1234", "a/snmp_priv_key": "pp"}      # scoped to the agent
    loaded = load_settings(path, env={}, keychain=kc)
    assert (loaded.api_key, loaded.snmp_priv_key, loaded.agent_id) == ("secret-key-1234", "pp", "a")


def test_without_a_keychain_secrets_stay_in_the_file(tmp_path):
    path = save_settings(Settings(api_key="k"), tmp_path / "c.json", keychain=FakeKeychain(available=False))
    data = json.loads(path.read_text())
    assert data["api_key"] == "k" and "secrets_in_keychain" not in data


def test_keychain_write_failure_keeps_the_file_copy(tmp_path):
    path = save_settings(Settings(api_key="k"), tmp_path / "c.json", keychain=FakeKeychain(fail=True))
    assert json.loads(path.read_text())["api_key"] == "k"


def test_keychain_only_consulted_when_the_file_says_so(tmp_path):
    kc = FakeKeychain()
    kc.items["api_key"] = "from-keychain"
    path = tmp_path / "c.json"
    path.write_text(json.dumps({"api_url": "http://x"}))
    assert load_settings(path, env={}, keychain=kc).api_key == ""
    path.write_text(json.dumps({"api_url": "http://x", "secrets_in_keychain": True}))
    assert load_settings(path, env={}, keychain=kc).api_key == "from-keychain"
    # environment still beats the keychain
    assert load_settings(path, env={"EAGLEEYE_API_KEY": "env"}, keychain=kc).api_key == "env"


def test_clearing_a_secret_removes_it_from_the_keychain(tmp_path):
    kc = FakeKeychain()
    save_settings(Settings(fingerbank_key="fb"), tmp_path / "c.json", keychain=kc)
    save_settings(Settings(fingerbank_key=""), tmp_path / "c.json", keychain=kc)
    assert "unregistered/fingerbank_key" not in kc.items


def test_schedules_and_consent_roundtrip(tmp_path):
    s = Settings(schedules=[{"subnet": "10.0.0.0/24", "mode": "interval", "hours": 4}], consent_version=1,
                 consent_at="2026-10-11T10:00:00+08:00")
    loaded = load_settings(save_settings(s, tmp_path / "c.json"), env={})
    assert loaded.schedules == s.schedules and loaded.consent_version == 1


def test_bad_schedules_are_reported():
    s = Settings(api_url="http://x", api_key="k", agent_id="a", schedules=[{"subnet": "10.0.0.0/8"}])
    assert any(p.startswith("schedule 10.0.0.0/8:") for p in s.problems())


def test_schedules_must_be_a_list_of_objects(tmp_path):
    path = tmp_path / "c.json"
    path.write_text(json.dumps({"schedules": "daily"}))
    with pytest.raises(ConfigError, match="schedules"):
        load_settings(path, env={})


def test_two_agents_never_share_a_credential_entry(tmp_path):
    kc = FakeKeychain()
    save_settings(Settings(agent_id="agent-A", api_key="key-A"), tmp_path / "a.json", keychain=kc)
    save_settings(Settings(agent_id="agent-B", api_key="key-B"), tmp_path / "b.json", keychain=kc)
    assert load_settings(tmp_path / "a.json", env={}, keychain=kc).api_key == "key-A"
    assert load_settings(tmp_path / "b.json", env={}, keychain=kc).api_key == "key-B"


def test_old_unscoped_entry_is_still_read(tmp_path):
    kc = FakeKeychain()
    kc.items["api_key"] = "legacy-key"
    path = tmp_path / "c.json"
    path.write_text(json.dumps({"agent_id": "agent-A", "secrets_in_keychain": True}))
    assert load_settings(path, env={}, keychain=kc).api_key == "legacy-key"

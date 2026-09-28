import subprocess
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from devhub.config import ConfigError, HubConfig, load_config
from devhub.models import Policy, StatusRequest


@pytest.mark.parametrize(
    "payload",
    [
        {"providers": {"groq": {"enabled": True}}},
        {"policy": {"paid_mode": "automatic"}},
        {"server": {"transport": "streamable-http"}},
        {"fake": {"enabled": "true"}},
        {"schema_version": True},
        {"schema_version": 2},
        {"policy": {"context_token_cap": 0}},
        {"projects": {"../other": {"root": "."}}},
    ],
)
def test_reject_unsafe_or_unknown_configuration(payload):
    with pytest.raises(ValidationError):
        HubConfig.model_validate(payload)


def test_defaults_are_configurable():
    policy = Policy(context_token_cap=4000, summary_token_cap=500)
    assert (policy.context_token_cap, policy.summary_token_cap) == (4000, 500)


def test_roots_resolve_relative_to_config_not_cwd(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    config = tmp_path / "hub.toml"
    config.write_text('[projects.example]\nroot = "project"\n')
    monkeypatch.chdir(tmp_path.parent)
    result = load_config(config)
    assert result.projects["example"].root == str(project.resolve())


def test_bad_root_fails_closed(tmp_path):
    config = tmp_path / "hub.toml"
    config.write_text('[projects.example]\nroot = "missing"\n')
    with pytest.raises(ConfigError):
        load_config(config)


def test_cli_invalid_config_never_echoes_secret_or_starts_server(tmp_path):
    config = tmp_path / "bad.toml"
    config.write_text('secret = "CANARY-SECRET-DO-NOT-PRINT"\n')
    result = subprocess.run(
        [sys.executable, "-m", "devhub", "serve", "--config", str(config)],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 2
    assert result.stdout == ""
    assert "CANARY" not in result.stderr
    assert "Traceback" not in result.stderr


def test_size_and_invalid_utf8_rejected(tmp_path):
    config = tmp_path / "bad.toml"
    for content in (b"x" * 65537, b"\xff"):
        config.write_bytes(content)
        with pytest.raises(ConfigError):
            load_config(config)


def test_status_contract_forbids_unknown_fields():
    with pytest.raises(ValidationError):
        StatusRequest.model_validate({"project_id": "example", "endpoint": "http://example.com"})


def test_checked_in_config_is_valid():
    root = Path(__file__).resolve().parents[1]
    assert load_config(root / "config/offline.toml").fake.enabled

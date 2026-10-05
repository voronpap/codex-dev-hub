import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from devhub.delegate import DelegationConfig, DelegationRequest
from devhub.ollama import OllamaConfig

ROOT = Path(__file__).resolve().parents[1]


def test_portable_demo_contract(monkeypatch, tmp_path):
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    monkeypatch.chdir(checkout)
    config = DelegationConfig.model_validate_json(
        (ROOT / "config/devfabric-local.example.json").read_text()
    )
    task = DelegationRequest.model_validate_json(
        (ROOT / "config/devfabric-demo-task.json").read_text()
    )
    assert not config.cloud_enabled and len(config.profiles) == 1
    profile = config.profiles[0]
    assert profile.provider == "ollama"
    assert profile.config.project == task.project
    assert task.privacy == "local_only" and not task.allow_cloud
    assert not Path(profile.config.root).is_absolute()
    assert not Path(profile.config.state_root).is_absolute()
    for source in profile.config.approved_paths:
        assert (ROOT / source).is_file()
    assert Path(profile.config.state_root).resolve() == tmp_path / "devfabric-state"


@pytest.mark.parametrize("version", ["0.35.1", "0.36.0", "1.0.0"])
def test_demo_never_accepts_loose_ollama_version(version):
    config = json.loads((ROOT / "config/devfabric-local.example.json").read_text())
    ollama = config["profiles"][0]["config"]["ollama"]
    ollama["version"] = version
    with pytest.raises(ValidationError):
        OllamaConfig.model_validate(ollama)

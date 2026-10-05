import json
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from devhub.delegate import DelegationConfig, DelegationRequest, DelegationRuntime
from devhub.ledger import LedgerError, LedgerErrorCode, ledger_identity_sha256
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


@pytest.mark.windows_smoke
def test_ledger_initialization_is_explicit_and_state_root_change_fails_closed(
    monkeypatch, tmp_path
):
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    monkeypatch.chdir(checkout)
    config = DelegationConfig.model_validate_json(
        (ROOT / "config/devfabric-local.example.json").read_text()
    )
    expected = config.profiles[0].config.ledger_identity
    state = Path(config.profiles[0].config.state_root).resolve()
    assert not state.exists()
    assert DelegationRuntime.initialize_ledger(config) == ledger_identity_sha256(expected)
    assert (state / "ledger.db").is_file()
    DelegationRuntime(config)

    replacement_state = tmp_path / "replacement-state"
    changed_profile = config.profiles[0].model_copy(
        update={
            "config": config.profiles[0].config.model_copy(
                update={"state_root": str(replacement_state)}
            )
        }
    )
    changed = config.model_copy(update={"profiles": (changed_profile,)})
    with pytest.raises(LedgerError) as raised:
        DelegationRuntime(changed)
    assert raised.value.code is LedgerErrorCode.UNSAFE_STATE_ROOT
    assert not (replacement_state / "ledger.db").exists()


def test_project_scope_identity_must_match_trusted_project():
    config = json.loads((ROOT / "config/devfabric-local.example.json").read_text())
    config["profiles"][0]["config"]["ledger_identity"]["authority_scope_id"] = "other"
    with pytest.raises(ValidationError, match="ledger identity"):
        DelegationConfig.model_validate_json(json.dumps(config))


def test_profiles_must_share_exact_ledger_identity():
    config = DelegationConfig.model_validate_json(
        (ROOT / "config/devfabric-local.example.json").read_text()
    )
    first = config.profiles[0]
    changed_identity = first.config.ledger_identity.model_copy(update={"instance_id": "f" * 32})
    second = first.model_copy(
        update={
            "id": "other",
            "config": first.config.model_copy(update={"ledger_identity": changed_identity}),
        }
    )
    with pytest.raises(ValidationError, match="ledger authority identity"):
        DelegationConfig(profiles=(first, second))


def test_initialize_ledger_cli_exits_before_mcp_or_provider(monkeypatch, tmp_path, capsys):
    from devhub import delegate_server

    checkout = tmp_path / "checkout"
    checkout.mkdir()
    config_path = checkout / "local.json"
    config_path.write_text((ROOT / "config/devfabric-local.example.json").read_text())
    monkeypatch.chdir(checkout)
    monkeypatch.setattr(
        delegate_server,
        "create_delegation_server",
        lambda *_: pytest.fail("initialization must not create the MCP server"),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["delegate_server", "--config", str(config_path), "--initialize-ledger"],
    )
    delegate_server.main()
    output = json.loads(capsys.readouterr().out)
    assert output["ledger_identity_sha256"]
    assert (tmp_path / "devfabric-state" / "ledger.db").is_file()

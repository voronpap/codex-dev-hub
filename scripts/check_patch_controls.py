"""Pinned patch-control evidence verification; no model or task requests."""

import argparse
import hashlib
import json
from pathlib import Path
from urllib.request import urlopen

from check_mutation_audit import COMMIT, verify_sources

ROOT = Path(__file__).resolve().parents[1] / "docs/evidence/stage3g-patch-controls"


def validate(controls, schema, bindings):
    assert controls["source_commit"] == COMMIT
    assert controls["supported_model_independent_disable_in_frozen_cli"] is False
    assert controls["internal_model_independent_filter_exists"] is True
    assert controls["protocol_config_changed"] is False
    assert controls["forbidden_inventory_changed"] is False
    assert controls["proposal_applied"] is False
    assert controls["execution_ready"] is False
    for key in (
        "new_metadata_requests",
        "inference_requests",
        "real_codex_executions",
        "provider_sends",
    ):
        assert controls[key] == 0
    names = set()
    for c in controls["supported_disable_controls"]:
        assert c["mechanism"] not in names
        names.add(c["mechanism"])
        assert c["source_refs"] and all(ref in bindings for ref in c["source_refs"])
        assert c["filesystem_mutation_possible_after_control"] is None
    allow = next(
        c
        for c in controls["supported_disable_controls"]
        if c["mechanism"].startswith("AllowedTools")
    )
    assert allow["apply_patch_registered_after_control"] is False
    assert allow["apply_patch_invocable_after_control"] is False
    assert allow["model_independent"] is True
    assert allow["preserves_frozen_semantics"] is False
    readonly = next(
        c for c in controls["supported_disable_controls"] if c["mechanism"].startswith("read-only")
    )
    assert readonly["apply_patch_registered_after_control"] is True
    assert readonly["apply_patch_invocable_after_control"] is None
    assert "allowed_tools" not in schema["root_property_names"]
    assert "apply_patch" not in schema["tools_properties"]
    assert set(schema["disabled_tools_definitions"]) == {
        "PluginMcpServerConfig",
        "RawMcpServerConfig",
        "ToolSuggestConfig",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-upstream", action="store_true")
    args = parser.parse_args()
    controls, schema, bindings = [
        json.loads((ROOT / name).read_bytes())
        for name in ("controls.json", "schema-search.json", "source-bindings.json")
    ]
    validate(controls, schema, bindings)
    files = 0
    if args.verify_upstream:
        files = verify_sources(bindings)
        url = f"https://raw.githubusercontent.com/openai/codex/{COMMIT}/{schema['path']}"
        with urlopen(url, timeout=30) as response:
            raw = response.read()
        assert hashlib.sha256(raw).hexdigest() == schema["sha256"]
        parsed = json.loads(raw)
        assert list(parsed["properties"]) == schema["root_property_names"]
        assert list(parsed["definitions"]["ToolsToml"]["properties"]) == schema["tools_properties"]
        assert [
            n
            for n, d in parsed["definitions"].items()
            if "disabled_tools" in d.get("properties", {})
        ] == schema["disabled_tools_definitions"]
        files += 1
    for record in json.loads((ROOT / "results.json").read_bytes())["commands"]:
        filename = {
            ("--version",): "version.txt",
            ("exec", "--help"): "exec-help.txt",
            ("app-server", "--help"): "app-server-help.txt",
        }[tuple(record["command"])]
        assert record["exit_code"] == 0
        assert hashlib.sha256((ROOT / filename).read_bytes()).hexdigest() == record["stdout_sha256"]
    print(
        json.dumps(
            {
                "controls_valid": True,
                "source_files_verified": files,
                "new_metadata_requests": 0,
                "inference_requests": 0,
            }
        )
    )


if __name__ == "__main__":
    main()

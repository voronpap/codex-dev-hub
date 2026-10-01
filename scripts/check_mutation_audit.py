"""Validate frozen source inventory; optional exact-source fetch, never model traffic."""

import argparse
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.request import urlopen

COMMIT = "4607249e430dac1c961df4dc615beae88e33cec8"
EVIDENCE = Path(__file__).resolve().parents[1] / "docs/evidence/stage3g-mutation-audit"
REQUIRED = {
    "exec_command",
    "write_stdin",
    "apply_patch",
    "notes.write_file",
    "notes.append_to_file",
    "memories.add_ad_hoc_note",
    "image_gen.imagegen",
    "multi_agent_v1.resume_agent",
    "multi_agent_v1.close_agent",
    "interrupt_agent",
}


def validate(inventory, metadata, bindings):
    assert inventory["source_commit"] == metadata["source_commit"] == COMMIT
    items = inventory["canonical_tool_inventory"]
    names = [item["tool_name"] for item in items]
    assert len(names) == len(set(names)) and REQUIRED <= set(names)
    for item in items:
        assert item["absent"] is None or type(item["absent"]) is bool
        assert item["source_refs"] and all(key in bindings for key in item["source_refs"])
        assert item["registration_condition"] and item["guard"] and item["mutation_capability"]
    ordered = sorted(metadata["selection_candidates"], key=lambda m: m["priority"])
    selected = next((m for m in ordered if m["visibility"] == "list"), ordered[0])
    assert selected["slug"] == metadata["service_default_model_id"]
    assert metadata["metadata_fields_used"]["slug"] == selected["slug"]
    assert metadata["metadata_fields_used"]["apply_patch_tool_type"] == "freeform"
    assert inventory["apply_patch_absent"] is False
    assert next(i for i in items if i["tool_name"] == "apply_patch")["absent"] is False
    assert inventory["forbidden_execution_tools_absent"] is False
    assert inventory["other_mutation_tools_absent"] is None
    for record in (inventory, metadata):
        assert record["metadata_requests"] == 1
        for key in ("inference_requests", "real_codex_executions", "provider_sends"):
            assert record[key] == 0
    assert inventory["execution_ready"] is False
    assert inventory["actual_runtime_tool_list_observed"] is False
    for source in bindings.values():
        assert source["path"].startswith("codex-rs/") and ".." not in source["path"]
        assert len(source["file_sha256"]) == 64
        assert len(source["excerpt"].split("\n")) == source["end"] - source["start"] + 1


def verify_sources(bindings):
    paths = sorted({v["path"] for v in bindings.values()})

    def fetch(path):
        url = f"https://raw.githubusercontent.com/openai/codex/{COMMIT}/{path}"
        with urlopen(url, timeout=30) as response:
            return path, response.read()

    with ThreadPoolExecutor(max_workers=4) as pool:
        sources = dict(pool.map(fetch, paths))
    for source in bindings.values():
        raw = sources[source["path"]]
        assert hashlib.sha256(raw).hexdigest() == source["file_sha256"]
        lines = raw.decode().splitlines()[source["start"] - 1 : source["end"]]
        assert "\n".join(lines) == source["excerpt"]
    return len(paths)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-upstream", action="store_true")
    args = parser.parse_args()
    inventory, metadata, bindings = (
        json.loads((EVIDENCE / name).read_bytes())
        for name in ("inventory.json", "model-metadata.json", "source-bindings.json")
    )
    validate(inventory, metadata, bindings)
    count = verify_sources(bindings) if args.verify_upstream else 0
    print(
        json.dumps(
            {
                "inventory_valid": True,
                "source_files_verified": count,
                "new_model_metadata_requests": 0,
                "inference_requests": 0,
            }
        )
    )


if __name__ == "__main__":
    main()

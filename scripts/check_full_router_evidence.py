"""Validate metadata derivation without mistaking uncompiled tests for router proof."""

import argparse
import json
from pathlib import Path

from check_mutation_audit import verify_sources

ROOT = Path(__file__).resolve().parents[1] / "docs/evidence/stage3g-full-router"


def validate(metadata, result):
    assert metadata["metadata_requests"] == 1 and metadata["retries"] == 0
    assert metadata["http_status"] == 200
    ordered = sorted(metadata["models"], key=lambda row: row["priority"])
    selected = next((row for row in ordered if row["visibility"] == "list"), ordered[0])
    assert selected == metadata["selected"]
    assert selected["slug"] == metadata["service_default_model"]
    assert selected["tool_mode_field_present"] is True
    assert selected["tool_mode"] == "code_mode_only"
    assert result["observed_model_tool_mode"] == "code_mode_only"
    assert result["derived_effective_tool_mode"] == "CodeModeOnly"
    assert result["classification"] == "UNKNOWN"
    assert result["actual_pinned_router_code"] is None
    assert result["A"]["registered_tools"] is None
    assert result["B"]["visible_specs"] is None
    assert result["B"]["origin_verified"] is None
    assert result["execution_ready"] is False
    assert result["protocol_changed"] is False and result["v3_created"] is False
    for record in (metadata, result):
        for name in ("inference_requests", "real_codex_executions", "provider_sends"):
            assert record[name] == 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-upstream", action="store_true")
    args = parser.parse_args()
    validate(*(json.loads((ROOT / name).read_bytes()) for name in ("metadata.json", "result.json")))
    count = (
        verify_sources(json.loads((ROOT / "source-bindings.json").read_bytes()))
        if args.verify_upstream
        else 0
    )
    print(
        json.dumps(
            {
                "source_files_verified": count,
                "mode": "CodeModeOnly",
                "classification": "UNKNOWN",
                "new_metadata_requests": 0,
            }
        )
    )


if __name__ == "__main__":
    main()

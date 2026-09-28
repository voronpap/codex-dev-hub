"""Evidence catalogs cannot stand in for quota observations or live authorization."""

import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from devhub.quota import observe

EVIDENCE = Path(__file__).parent.parent / "docs/evidence"


def read(name):
    return json.loads((EVIDENCE / name).read_text(encoding="utf-8"))


def test_gemini_catalog_preserves_unknowns_and_capability_boundaries():
    catalog = read("stage3e-gemini-account-catalog.json")
    schema = read("stage3e-gemini-account-catalog.schema.json")
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(catalog)
    assert len(catalog["entries"]) == 36
    for row in catalog["entries"]:
        assert not row["routing_enabled"] and not row["local_authorization"]
        assert all(value is None for value in row["observed_remaining"].values())
        if 0 in row["account_limits"].values():
            assert row["account_available"] is False
            assert row["availability_reason"] == "zero_account_limit"
        else:
            assert row["account_available"] is None
        if row["category"] == "live_api":
            assert row["verification"] == "LIVE_API_VERIFY"
            assert row["account_limits"]["rpm"] == "Unlimited"
        if row["category"] == "map_grounding":
            assert row["api_model_id"] is None
            assert row["scope_kind"] == "unmapped_models"


@pytest.mark.parametrize("mutation", ["activate", "remaining", "unlimited_rest", "freshness"])
def test_gemini_evidence_schema_rejects_invented_authority(mutation):
    catalog = copy.deepcopy(read("stage3e-gemini-account-catalog.json"))
    if mutation == "activate":
        catalog["entries"][0]["account_available"] = True
        catalog["entries"][0]["routing_enabled"] = True
    elif mutation == "remaining":
        catalog["entries"][3]["observed_remaining"]["rpd"] = 20
    elif mutation == "unlimited_rest":
        catalog["entries"][3]["account_limits"]["rpm"] = "Unlimited"
    else:
        catalog["qualification_active"] = True
    validator = Draft202012Validator(read("stage3e-gemini-account-catalog.schema.json"))
    assert not validator.is_valid(catalog)


def test_groq_documented_limits_do_not_become_observed_capacity():
    catalog = read("groq-free-plan-catalog.json")
    assert catalog["account"] is None
    assert catalog["cached_tokens_rate_limited"] is False
    assert len(catalog["entries"]) == 10
    for row in catalog["entries"]:
        assert not row["local_authorization"]
        assert row["observed_response"] is None
        assert all(value is None for value in row["account_limits"].values())
        assert all(value is None for value in row["observed_remaining"].values())
        if row["category"] == "transcription":
            assert row["documented_limits"]["tpm"] is None
            assert row["documented_limits"]["ash"] == 7200
    # Exercise the existing parser, not a new catalog-specific accounting model.
    observation = observe({}, scope="catalog-test", now_ms=1, source="models_response")
    assert observation.requests_per_day is None and observation.tokens_per_minute is None
    headers = {}
    for header, dimension in catalog["header_dimensions"].items():
        assert dimension == ("rpd" if header.endswith("requests") else "tpm")
        headers[header] = "1s" if "reset" in header else "7"
    observation = observe(headers, scope="catalog-test", now_ms=1, source="models_response")
    assert observation.requests_per_day.remaining == 7
    assert observation.tokens_per_minute.remaining == 7
    assert observation.requests_per_minute is None and observation.tokens_per_day is None

import json
from pathlib import Path

from jsonschema import Draft202012Validator

from devhub.cli import schemas
from devhub.config import HubConfig


def test_published_schemas_match_models_and_validate_examples():
    root = Path(__file__).resolve().parents[1]
    published = json.loads((root / "schemas/stage1.json").read_text())
    assert published == schemas()
    for schema in published.values():
        Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(published["HubConfig"])
    validator.validate(HubConfig().model_dump())
    assert not validator.is_valid({"providers": {"groq": {"enabled": True}}})

"""Regenerate checked-in schemas from the domain models."""

import json
from pathlib import Path

from devhub.cli import schemas

root = Path(__file__).resolve().parents[1]
target = root / "schemas/stage1.json"
target.parent.mkdir(exist_ok=True)
target.write_text(json.dumps(schemas(), indent=2, sort_keys=True) + "\n", encoding="utf-8")

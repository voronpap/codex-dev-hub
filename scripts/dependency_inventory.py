"""Print license metadata for the currently locked environment; not legal advice."""

import json
from importlib.metadata import distributions

records = []
for dist in distributions():
    if dist.metadata["Name"] == "codex-dev-hub":
        continue
    expression = dist.metadata.get("License-Expression")
    legacy = dist.metadata.get("License")
    classifiers = [c for c in dist.metadata.get_all("Classifier", []) if c.startswith("License")]
    records.append(
        {
            "name": dist.metadata["Name"],
            "version": dist.version,
            "license_expression": expression,
            "license_label": legacy.splitlines()[0] if legacy else None,
            "license_classifiers": classifiers,
            "evidence": "installed distribution metadata; inspect bundled notices before release",
        }
    )
print(json.dumps(sorted(records, key=lambda item: item["name"].lower()), indent=2))

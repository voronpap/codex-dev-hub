"""Build a separate credential/model-free evaluator with hash-locked pytest wheels."""

import argparse
import json
import subprocess
import tempfile
import tomllib
import urllib.request
from pathlib import Path

from devhub.benchmark import canonical, digest, write_new
from devhub.experiment_launch import DOCKER


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Exclusive output required")
    repo = Path(__file__).resolve().parents[1]
    base = json.loads((repo / "benchmarks/runtime-lock.json").read_bytes())["base_image"]
    lock = tomllib.loads((repo / "uv.lock").read_text(encoding="utf-8"))
    hashes = {}
    with tempfile.TemporaryDirectory(prefix="devhub-evaluator-image-") as temporary:
        root = Path(temporary)
        for package in lock["package"]:
            if package["name"] not in {"pytest", "iniconfig", "packaging", "pluggy", "pygments"}:
                continue
            wheel = next(w for w in package["wheels"] if w["url"].endswith("none-any.whl"))
            raw = urllib.request.urlopen(wheel["url"], timeout=60).read()
            if "sha256:" + digest(raw) != wheel["hash"]:
                raise ValueError("Evaluator wheel integrity failure")
            name = wheel["url"].rsplit("/", 1)[1]
            (root / name).write_bytes(raw)
            hashes[name] = digest(raw)
        recipe = (
            f"FROM {base} AS base\nCOPY *.whl /wheels/\n"
            "RUN pip install --no-index --no-deps /wheels/*.whl && rm -rf /wheels /root/.cache\n"
            "FROM scratch\nCOPY --from=base / /\n"
            'ENV PATH="/usr/local/bin:/usr/bin:/bin" LANG="C.UTF-8"\nUSER 1000:1000\n'
        )
        (root / "Dockerfile").write_text(recipe, encoding="utf-8")
        image = (
            subprocess.check_output(
                [*DOCKER, "build", "--platform=linux/amd64", "--network=none", "-q", str(root)],
                timeout=600,
            )
            .decode()
            .strip()
        )
        raw = canonical(
            {
                "kind": "evaluator_image_build",
                "image_id": image,
                "wheel_hashes": hashes,
                "recipe_sha256": digest(recipe.encode()),
                "base_image": base,
                "real_codex_executions": 0,
                "provider_sends": 0,
            }
        )
        write_new(args.output, raw)
        print(raw.decode())


if __name__ == "__main__":
    main()

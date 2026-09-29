"""Build only a locked executor image; no auth, source, fixtures or model calls."""

import argparse
import hashlib
import io
import json
import subprocess
import tarfile
import tempfile
import urllib.request
from pathlib import Path

from devhub.benchmark import canonical, digest, write_new
from devhub.experiment_launch import DOCKER, safe_artifacts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Exclusive output required")
    repo = Path(__file__).resolve().parents[1]
    lock_raw = (repo / "benchmarks/runtime-lock.json").read_bytes()
    lock = json.loads(lock_raw)
    archive = urllib.request.urlopen(lock["codex_url"], timeout=60).read()
    if hashlib.sha256(archive).hexdigest() != lock["codex_archive_sha256"]:
        raise ValueError("Codex release archive integrity failure")
    with tarfile.open(fileobj=io.BytesIO(archive)) as bundle:
        members = [
            m for m in bundle.getmembers() if m.isfile() and Path(m.name).name.startswith("codex-")
        ]
        if len(members) != 1:
            raise ValueError("Unexpected release layout")
        stream = bundle.extractfile(members[0])
        assert stream is not None
        binary = stream.read()
    with tempfile.TemporaryDirectory(prefix="devhub-image-") as temporary:
        root = Path(temporary)
        (root / "codex").write_bytes(binary)
        (root / "codex").chmod(0o755)
        # The context consists of exactly these two files. No repo COPY or auth ARG.
        recipe = (
            f"FROM {lock['base_image']} AS base\n"
            "RUN rm -rf /usr/local/lib/python3.12/site-packages/* "
            "/usr/local/lib/python3.12/ensurepip /root/.cache\n"
            "FROM scratch\nCOPY --from=base / /\n"
            "COPY --chmod=755 codex /usr/local/bin/codex\n"
            'ENV PATH="/usr/local/bin:/usr/bin:/bin" LANG="C.UTF-8" HOME="/home/runner"\n'
            "USER 1000:1000\n"
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
        version = (
            subprocess.check_output(
                [
                    *DOCKER,
                    "run",
                    "--rm",
                    "--network=none",
                    "--read-only",
                    "--cap-drop=ALL",
                    "--security-opt=no-new-privileges",
                    "--entrypoint=codex",
                    image,
                    "--version",
                ],
                timeout=30,
            )
            .decode()
            .strip()
        )
        if version != lock["codex_version"]:
            raise ValueError("Exact CLI unavailable: STOP, protocol review required")
        evidence = canonical(
            {
                "schema_version": 1,
                "kind": "runtime_image_build",
                "image_id": image,
                "runtime_lock_sha256": digest(lock_raw),
                "dockerfile_sha256": digest(recipe.encode()),
                "codex_archive_sha256": lock["codex_archive_sha256"],
                "codex_binary_sha256": digest(binary),
                "codex_version": version,
                "base_image": lock["base_image"],
                "real_codex_executions": 0,
                "provider_sends": 0,
            }
        )
        safe_artifacts((evidence,))
        write_new(args.output, evidence)
        print(evidence.decode())


if __name__ == "__main__":
    main()

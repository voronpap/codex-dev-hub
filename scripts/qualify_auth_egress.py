"""Qualify existing Codex auth presence and the frozen scoped-egress policy."""

import argparse
import json
import os
import platform
import tempfile
from pathlib import Path

from devhub.benchmark import canonical, write_new
from devhub.experiment_preflight import egress_policy_checks, validate_chatgpt_auth_bytes
from devhub.qualification import AuthEgressReceiptV1, load_context, receipt_header

ALLOWED = ("api.openai.com:443", "chatgpt.com:443")
DENIED = (
    "10.0.0.1:443",
    "127.0.0.1:443",
    "169.254.169.254:443",
    "api.groq.com:443",
    "example.com:443",
    "generativelanguage.googleapis.com:443",
)
PROXY_KEYS = {
    "ALL_PROXY",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NO_PROXY",
    "all_proxy",
    "https_proxy",
    "http_proxy",
    "no_proxy",
}


def _proxy_environment_inherited() -> bool:
    return any(os.environ.get(key) for key in PROXY_KEYS)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--auth-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if platform.system() != "Linux":
        parser.error("Intended-host auth qualification requires Linux")
    if args.output.exists():
        parser.error("Exclusive output required")
    context = load_context(args.context)
    auth = args.auth_file
    if auth.is_symlink() or not auth.is_file():
        parser.error("Auth locator must be a regular non-symlink file")
    raw = auth.read_bytes()
    try:
        validate_chatgpt_auth_bytes(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        parser.error(str(error))
    with tempfile.TemporaryDirectory(prefix="devhub-auth-stage-") as temporary:
        staged = Path(temporary) / "auth.json"
        staged.write_bytes(raw)
        os.chmod(staged, 0o600)
        staged_matches = staged.read_bytes() == raw
        staged_mode = f"{staged.stat().st_mode & 0o777:04o}"
    checks = egress_policy_checks()
    if not all(checks.values()):
        parser.error("Frozen CONNECT or resolution policy check failed")
    proxy_inherited = _proxy_environment_inherited()
    receipt = AuthEgressReceiptV1(
        **receipt_header(context, "auth_egress"),
        auth_source="existing_operator_codex_auth",
        auth_regular_file=True,
        auth_json_object=True,
        auth_material_nonempty=True,
        auth_material_published=False,
        staged_copy_mode=staged_mode,
        staged_copy_matches_source=staged_matches,
        proxy_environment_inherited=proxy_inherited,
        allowed_connect_targets=ALLOWED,
        denied_connect_targets=DENIED,
        policy_checks_passed=True,
        model_requests=0,
        provider_sends=0,
        qualification_passed=True,
    )
    write_new(args.output, canonical(receipt.model_dump(mode="json")))
    print(json.dumps({"qualification_passed": True, "auth_material_published": False}))


if __name__ == "__main__":
    main()

"""Frozen, offline wire contract; fixtures are not live-success evidence."""

import json
from pathlib import Path

import pytest

from devhub.brain_models import sha256
from devhub.cloud_export import ReleasedPayload, _seal
from devhub.cloud_types import HTTPResult
from devhub.gemini import (
    GeminiAdapter,
    GeminiConfig,
    GeminiHTTP,
    complete_usage,
    error_category,
)
from devhub.local import now_ms

FIXTURES = Path(__file__).parent / "fixtures" / "gemini"
EVIDENCE = Path(__file__).parent.parent / "docs/evidence/stage3e-gemini-preflight.json"


def test_historical_failed_evidence_is_unchanged():
    fixture = json.loads((FIXTURES / "preflight-1-request.json").read_text(encoding="utf-8"))
    assert (
        sha256(EVIDENCE.read_bytes().replace(b"\r\n", b"\n"))
        == fixture["historical_evidence_sha256_lf"]
    )
    old = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    assert old["handoff"]["reason"] == "count_model_unavailable"  # historical label preserved
    assert old["inference_http_sends"] == 0 and old["live_gate"] == "NOT_PASSED"


def test_exact_wire_request_matches_frozen_historical_contract(monkeypatch):
    fixture = json.loads((FIXTURES / "preflight-1-request.json").read_text(encoding="utf-8"))
    old = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    config = GeminiConfig.model_validate_json(json.dumps(old["provider_config"]))
    # Freshness is simulated in this offline test only. No historical file is edited.
    stamp = now_ms()
    config = config.model_copy(
        update={
            "probe_expires_ms": stamp + 60000,
            "qualification": config.qualification.model_copy(
                update={
                    "observed_ms": stamp,
                    "valid_until_ms": stamp + 60000,
                }
            ),
        }
    )
    adapter = GeminiAdapter(config)
    text = fixture["released_text"]
    digest = sha256(text.encode())
    payload = ReleasedPayload(text, digest, "public", _seal(digest, "public"))
    calls = []

    def offline_http(path, body=None):
        calls.append((path, body))
        return HTTPResult(200, {}, {"totalTokens": 100}, 0)

    monkeypatch.setattr(adapter.http, "request", offline_http)
    prepared = adapter.prepare(payload)
    adapter.send(prepared)
    assert calls == [
        (fixture["count_path"], fixture["count_body_utf8"].encode()),
        (fixture["generate_path"], fixture["generate_body_utf8"].encode()),
    ]
    assert prepared.request_hash == fixture["generate_body_sha256"]
    assert sha256(calls[0][1]) == fixture["count_body_sha256"]
    envelope = json.loads(calls[0][1])
    assert set(envelope) == {"generateContentRequest"}
    full_request = envelope["generateContentRequest"]
    assert full_request.pop("model") == "models/" + fixture["model"]
    assert full_request == json.loads(prepared.body)
    assert full_request["systemInstruction"]["parts"]
    assert full_request["generationConfig"]["thinkingConfig"] == {"thinkingBudget": 0}
    assert full_request["generationConfig"]["responseMimeType"] == "application/json"


def test_documented_versions_accept_the_used_fields_not_account_entitlement():
    contract = json.loads((FIXTURES / "discovery-contract.json").read_text(encoding="utf-8"))
    fixture = json.loads((FIXTURES / "preflight-1-request.json").read_text(encoding="utf-8"))
    for version in ("v1", "v1beta"):
        spec = contract[version]
        assert spec["revision"] == "20260927"
        method = spec["methods"]["countTokens"]
        assert method == {"httpMethod": "POST", "path": version + "/{+model}:countTokens"}
        fields = spec["fields"]
        assert "generateContentRequest" in fields["CountTokensRequest"]
        request = json.loads(fixture["count_body_utf8"])["generateContentRequest"]
        assert set(request) <= set(fields["GenerateContentRequest"])
        assert set(request["generationConfig"]) <= set(fields["GenerationConfig"])
        assert {"thinkingBudget"} <= set(fields["ThinkingConfig"])


def test_exact_host_method_version_and_no_redirect(monkeypatch):
    import devhub.gemini as module

    calls = []
    monkeypatch.setattr(module, "windows_user_key", lambda: "synthetic-test-only-credential")

    class Connection:
        status = 307

        def __init__(self, host, **kwargs):
            assert host == "generativelanguage.googleapis.com"

        def request(self, method, path, body=None, headers=None):
            calls.append((method, path, body))
            assert set(headers) == {"x-goog-api-key", "Content-Type"}
            assert "?" not in path

        def getresponse(self):
            return self

        def getheaders(self):
            return [("Location", "https://other.invalid")]

        def read(self, limit):
            return b"{}"

        def close(self):
            pass

    monkeypatch.setattr(module.http.client, "HTTPSConnection", Connection)
    result = GeminiHTTP("gemini-2.5-flash-lite", 1).request(
        "/v1beta/models/gemini-2.5-flash-lite:countTokens", b"{}"
    )
    assert result.status == 307 and result.headers == {}
    assert calls == [("POST", "/v1beta/models/gemini-2.5-flash-lite:countTokens", b"{}")]


@pytest.mark.parametrize("case", ["missing_total", "wrong_model", "malformed", "missing_usage"])
def test_unreconcilable_usage_stays_unknown(case):
    body = {
        "modelVersion": "expected",
        "usageMetadata": {
            "promptTokenCount": 100,
            "candidatesTokenCount": 12,
            "totalTokenCount": 112,
        },
    }
    if case == "missing_total":
        del body["usageMetadata"]["totalTokenCount"]
    elif case == "wrong_model":
        body["modelVersion"] = "different"
    elif case == "malformed":
        body["usageMetadata"] = []
    else:
        del body["usageMetadata"]
    assert complete_usage(HTTPResult(200, {}, body, 0), "expected") is None


def test_404_category_does_not_claim_root_cause():
    assert error_category(404) == "not_found"


def test_windows_user_secret_boundary_does_not_fall_back(monkeypatch):
    import sys
    from types import SimpleNamespace

    import devhub.gemini as module

    calls = []

    class Key:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    def open_key(root, path):
        assert root == "synthetic-HKCU" and path == "Environment"
        return Key()

    def missing_user_value(key, name):
        calls.append(name)
        raise FileNotFoundError

    with monkeypatch.context() as patch:
        patch.setenv("GEMINI_API_KEY", "synthetic-process-value-must-be-ignored")
        patch.setattr(module.sys, "platform", "win32")
        patch.setitem(
            sys.modules,
            "winreg",
            SimpleNamespace(
                HKEY_CURRENT_USER="synthetic-HKCU",
                REG_SZ=1,
                OpenKey=open_key,
                QueryValueEx=missing_user_value,
            ),
        )
        with pytest.raises(module.GeminiError, match="windows_user_secret_unavailable"):
            module.windows_user_key()
    assert calls == ["GEMINI_API_KEY"]

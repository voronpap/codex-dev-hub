"""Native registry boundary without reading or modifying real credential values."""

import sys
import uuid

import pytest

from devhub import gemini, groq


@pytest.mark.windows_smoke
@pytest.mark.skipif(sys.platform != "win32", reason="native Windows registry")
def test_user_registry_only_and_sanitized_failure(monkeypatch):
    import winreg

    path = r"Software\DevHubTest-" + uuid.uuid4().hex
    original = winreg.OpenKey
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, path) as key:
        winreg.SetValueEx(key, "GROQ_API_KEY", 0, winreg.REG_SZ, "gsk_" + "x" * 40)
        winreg.SetValueEx(key, "GEMINI_API_KEY", 0, winreg.REG_SZ, "y" * 40)

    def isolated(hive, subkey):
        assert hive == winreg.HKEY_CURRENT_USER and subkey == "Environment"
        return original(hive, path)

    monkeypatch.setattr(winreg, "OpenKey", isolated)
    monkeypatch.setenv("GROQ_API_KEY", "process-must-be-ignored")
    monkeypatch.setenv("GEMINI_API_KEY", "process-must-be-ignored")
    try:
        assert groq.windows_user_key() == "gsk_" + "x" * 40
        assert gemini.windows_user_key() == "y" * 40
        with original(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, "GROQ_API_KEY")
            winreg.SetValueEx(key, "GEMINI_API_KEY", 0, winreg.REG_EXPAND_SZ, "%SECRET%")
        with pytest.raises(groq.GroqError, match="^windows_user_secret_unavailable$"):
            groq.windows_user_key()
        with pytest.raises(gemini.GeminiError, match="^windows_user_secret_unavailable$"):
            gemini.windows_user_key()
    finally:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)

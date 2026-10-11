"""Shared strict Windows authority identifiers."""

import re

_APPCONTAINER_PACKAGE_SID = re.compile(r"^S-1-15-2-(?:0|[1-9]\d{0,9})(?:-(?:0|[1-9]\d{0,9})){6}$")


def validate_appcontainer_package_sid(value: str) -> str:
    """Require one canonical package SID derived for a concrete AppContainer profile."""

    if _APPCONTAINER_PACKAGE_SID.fullmatch(value) is None:
        raise ValueError("AppContainer SID must be one exact derived package SID")
    subauthorities = value.split("-")[4:]
    if len(subauthorities) != 7 or any(int(item) > 0xFFFFFFFF for item in subauthorities):
        raise ValueError("AppContainer SID contains an invalid package subauthority")
    return value

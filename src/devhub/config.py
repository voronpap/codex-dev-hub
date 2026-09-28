"""Fail-closed TOML loading for the offline scope only."""

import tomllib
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, ValidationError

from devhub.models import Contract, Identifier, Policy


class ServerConfig(Contract):
    transport: Literal["stdio"] = "stdio"


class ProjectConfig(Contract):
    root: Annotated[str, Field(min_length=1, max_length=4096)]
    privacy: Literal["local_only"] = "local_only"


class FakeConfig(Contract):
    enabled: bool = False


class HubConfig(Contract):
    server: ServerConfig = Field(default_factory=ServerConfig)
    policy: Policy = Field(default_factory=Policy)
    projects: dict[Identifier, ProjectConfig] = Field(default_factory=dict, max_length=64)
    fake: FakeConfig = Field(default_factory=FakeConfig)


class ConfigError(ValueError):
    """Safe startup error; never echoes configuration values or file content."""


def load_config(path: Path) -> HubConfig:
    try:
        if path.stat().st_size > 64 * 1024:
            raise ConfigError("Configuration exceeds 64 KiB.")
        config = HubConfig.model_validate(tomllib.loads(path.read_text(encoding="utf-8")))
        projects = {}
        for project_id, project in config.projects.items():
            root = Path(project.root)
            if not root.is_absolute():
                root = path.resolve().parent / root
            root = root.resolve(strict=True)
            if not root.is_dir():
                raise ConfigError("Project root must be an existing directory.")
            projects[project_id] = project.model_copy(update={"root": str(root)})
        return config.model_copy(update={"projects": projects})
    except (OSError, UnicodeError, tomllib.TOMLDecodeError, ValidationError) as exc:
        raise ConfigError(
            "Invalid configuration; check the Stage 1 schema and project roots."
        ) from exc

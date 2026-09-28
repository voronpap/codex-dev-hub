import asyncio
import socket
import sys

import pytest
from mcp import Client, StdioServerParameters
from mcp.shared.exceptions import MCPError

from devhub.config import FakeConfig, HubConfig, ProjectConfig
from devhub.models import StatusResponse
from devhub.server import create_server


def test_status_in_process_no_network_and_project_isolation(tmp_path, monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("Network access is forbidden in offline status")

    config = HubConfig(
        projects={"visible": ProjectConfig(root=str(tmp_path))}, fake=FakeConfig(enabled=True)
    )

    async def run():
        monkeypatch.setattr(socket.socket, "connect", denied)
        async with Client(create_server(config)) as client:
            listing = await client.list_tools()
            assert [tool.name for tool in listing.tools] == ["devhub_status"]
            result = await client.call_tool("devhub_status", {"project_id": "visible"})
            assert not result.is_error
            status = StatusResponse.model_validate(result.structured_content)
            assert status.resources[0].routable is False
            assert status.accessible_projects == ["visible"]
            assert str(tmp_path) not in str(result)
            denied_result = await client.call_tool("devhub_status", {"project_id": "other"})
            assert denied_result.is_error
            assert "policy_denied" in str(denied_result)
            for args in ({"unexpected": "value"}, {"schema_version": 2}, {"project_id": "../x"}):
                with pytest.raises(MCPError) as error:
                    await client.call_tool("devhub_status", args)
                assert error.value.code == -32602
            missing = await client.call_tool("devhub_delegate", {})
            assert missing.is_error

    asyncio.run(run())


def test_real_stdio_client_discovers_and_calls_status(tmp_path):
    config = tmp_path / "offline.toml"
    config.write_text("schema_version = 1\n")

    async def run():
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "devhub", "serve", "--config", str(config)],
        )
        async with Client(params, read_timeout_seconds=10) as client:
            listing = await client.list_tools()
            assert [tool.name for tool in listing.tools] == ["devhub_status"]
            response = await client.call_tool("devhub_status", {})
            assert not response.is_error
            parsed = StatusResponse.model_validate(response.structured_content)
            assert parsed.stage == "offline_stage1"
            assert parsed.resources == []
            assert parsed.accessible_projects == []

    asyncio.run(run())

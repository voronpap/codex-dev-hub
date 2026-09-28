import asyncio
import socket

from devhub.adapters import FakeAdapter, ProviderAdapter
from devhub.models import TaskRequest


def test_fake_is_deterministic_synthetic_and_never_claims_usage(monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("Fake adapter must not use the network")

    adapter: ProviderAdapter = FakeAdapter()
    request = TaskRequest(project_id="fixture", task_id="one", instructions="Secret input")

    async def run():
        monkeypatch.setattr(socket.socket, "connect", denied)
        first = await adapter.execute(request)
        second = await adapter.execute(request)
        assert first == second
        assert first.synthetic
        assert first.usage.input_tokens is None
        assert first.usage.cost_actual_microusd is None
        assert "Secret input" not in first.content
        assert (await adapter.capabilities()).capabilities == []

    asyncio.run(run())

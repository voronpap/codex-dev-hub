import pytest
from test_controller import admission, counters, setup_core
from test_registry import record

from devhub.controller import Denied
from devhub.registry import CapabilityRegistry
from devhub.resources import Bucket, ResourcePolicy
from devhub.router import Router, RouteRequest, RoutingPolicy


def request(**changes):
    data = admission().model_dump(exclude={"resource"})
    return RouteRequest.model_validate(data | {"task_class": "summary"} | changes)


def test_deterministic_preference_and_private_routing(tmp_path):
    core = setup_core(tmp_path, capacity=10)
    registry = CapabilityRegistry(core.ledger)
    registry.put(record(resource="fake-b"))
    registry.put(record(resource="fake-a"))
    router = Router(core)
    denied = router.route(request(), now_ms=1)
    assert denied.ticket is None
    assert [d.reason for d in denied.decisions] == ["privacy_denied"] * 2
    assert counters(core) == (0, 0)
    routed = router.route(
        request(privacy="cloud_allowed"),
        now_ms=1,
        policy=RoutingPolicy(preferred_resources=("fake-b",)),
    )
    assert routed.admission.resource == "fake-b"
    assert [d.resource for d in routed.decisions] == ["fake-b", "fake-a"]
    assert [d.reason for d in routed.decisions] == ["selected", "not_selected"]
    again = router.route(
        request(privacy="cloud_allowed"),
        now_ms=1,
        policy=RoutingPolicy(preferred_resources=("fake-b",)),
    )
    assert again == routed
    assert counters(core) == (0, 1)


@pytest.mark.parametrize(
    "changes,reason",
    [
        ({"valid_until_ms": 400}, "stale_capability"),
        ({"observed_ms": 2}, "stale_capability"),
        ({"supports_text": None}, "capability_unknown_or_unsupported"),
        ({"healthy": None}, "health_unknown_or_unavailable"),
        ({"context_tokens": 29}, "context_or_output_limit"),
        ({"task_classes": ()}, "unqualified_task_class"),
    ],
)
def test_ineligible_records_never_reserve(tmp_path, changes, reason):
    core = setup_core(tmp_path)
    CapabilityRegistry(core.ledger).put(record(**changes))
    result = Router(core).route(request(privacy="cloud_allowed"), now_ms=1)
    assert result.ticket is None
    assert result.decisions[0].reason == reason
    assert counters(core) == (0, 0)


def test_capacity_fallback_and_changed_evidence_blocks_dispatch(tmp_path):
    core = setup_core(tmp_path, capacity=0)
    core.register_bucket(
        Bucket(id="local", pool="local", unit="requests", starts_ms=0, ends_ms=1000, capacity=1)
    )
    core.register_policy(ResourcePolicy(id="local", kind="local", buckets=("local",)))
    registry = CapabilityRegistry(core.ledger)
    registry.put(record())
    registry.put(record(resource="local", kind="local", locality="local"))
    result = Router(core).route(request(privacy="cloud_allowed"), now_ms=1)
    assert [d.reason for d in result.decisions] == ["capacity_exhausted", "selected"]
    registry.put(record(resource="local", kind="local", locality="local", healthy=False))
    with pytest.raises(Denied, match="capability_changed"):
        core.dispatch(result.ticket.id, result.admission, now_ms=2)
    assert counters(core, "local") == (0, 1)


def test_attempts_persist_across_released_reservations(tmp_path):
    core = setup_core(tmp_path, capacity=10)
    registry = CapabilityRegistry(core.ledger)
    registry.put(record(locality="local"))
    router = Router(core)
    for index in range(3):
        result = router.route(request(key=f"try-{index}"), now_ms=1)
        core.release(result.ticket.id, project="p")
    result = router.route(request(key="try-4"), now_ms=2)
    assert result.ticket is None
    assert result.decisions[0].reason == "attempt_limit"

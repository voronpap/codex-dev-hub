import pytest

from devhub.controller import Denied, ResourceController
from devhub.ledger import Ledger
from devhub.resources import Admission, Bucket, Price, ResourcePolicy, SpendApproval


def setup_core(tmp_path, capacity=1):
    core = ResourceController(Ledger(tmp_path / "ledger.db"))
    core.register_bucket(
        Bucket(
            id="shared",
            pool="account",
            unit="requests",
            starts_ms=0,
            ends_ms=1000,
            capacity=capacity,
        )
    )
    for name in ("fake-a", "fake-b"):
        core.register_policy(ResourcePolicy(id=name, kind="free", buckets=("shared",)))
    return core


def admission(**overrides):
    return Admission.model_validate(
        dict(
            project="p",
            task="t",
            key="key",
            resource="fake-a",
            payload_sha256="a" * 64,
            input_tokens=10,
            max_output_tokens=20,
            expires_ms=500,
        )
        | overrides
    )


def counters(core, bucket="shared"):
    with core.ledger.transaction() as connection:
        row = connection.execute("SELECT used, held FROM buckets WHERE id=?", (bucket,)).fetchone()
        return tuple(row)


def test_shared_pool_atomic_idempotency_and_dispatch(tmp_path):
    core = setup_core(tmp_path)
    request = admission()
    ticket = core.reserve(request, now_ms=1)
    assert core.reserve(request, now_ms=2) == ticket
    with pytest.raises(Denied, match="idempotency_conflict"):
        core.reserve(admission(max_output_tokens=21), now_ms=2)
    with pytest.raises(Denied, match="capacity_exhausted"):
        core.reserve(admission(resource="fake-b", key="b", project="other"), now_ms=2)
    assert counters(core) == (0, 1)
    core.dispatch(ticket.id, request, now_ms=2)
    with pytest.raises(Denied, match="not_dispatchable"):
        core.dispatch(ticket.id, request, now_ms=2)
    core.unknown(ticket.id, project="p")
    with pytest.raises(Denied, match="cannot_release"):
        core.release(ticket.id, project="p")
    assert counters(core) == (0, 1)
    with pytest.raises(Denied, match="incomplete_usage"):
        core.settle(ticket.id, project="p", actual={})
    core.settle(ticket.id, project="p", actual={"shared": 2})
    core.settle(ticket.id, project="p", actual={"shared": 2})
    assert counters(core) == (2, 0)  # record overrun honestly, block later admission
    with pytest.raises(Denied, match="settlement_conflict"):
        core.settle(ticket.id, project="p", actual={"shared": 0})


def test_scopes_leases_release_and_no_partial_reservation(tmp_path):
    core = setup_core(tmp_path)
    core.register_bucket(
        Bucket(
            id="empty", pool="tokens", unit="total_tokens", starts_ms=0, ends_ms=1000, capacity=29
        )
    )
    core.register_policy(ResourcePolicy(id="bounded", kind="free", buckets=("shared", "empty")))
    with pytest.raises(Denied, match="capacity"):
        core.reserve(admission(resource="bounded"), now_ms=1)
    assert counters(core) == (0, 0)
    request = admission()
    ticket = core.reserve(request, now_ms=1)
    with pytest.raises(Denied, match="unknown_reservation"):
        core.release(ticket.id, project="other")
    with pytest.raises(Denied, match="not_dispatchable"):
        core.dispatch(ticket.id, request, now_ms=500)
    core.release(ticket.id, project="p")
    core.release(ticket.id, project="p")
    assert counters(core) == (0, 0)
    with pytest.raises(Denied, match="overlapping_pool"):
        core.register_bucket(
            Bucket(
                id="alias",
                pool="account",
                unit="requests",
                starts_ms=10,
                ends_ms=1001,
                capacity=100,
            )
        )


@pytest.mark.parametrize("capacity,end", [(None, 1000), (10, None), (10, 400)])
def test_unknown_limits_and_reset_fail_closed(tmp_path, capacity, end):
    core = ResourceController(Ledger(tmp_path / "ledger.db"))
    core.register_bucket(
        Bucket(id="b", pool="p", unit="requests", starts_ms=0, ends_ms=end, capacity=capacity)
    )
    core.register_policy(ResourcePolicy(id="fake-a", kind="free", buckets=("b",)))
    with pytest.raises(Denied, match="unknown_or_expired"):
        core.reserve(admission(), now_ms=1)


def paid_core(tmp_path, *, price=True):
    core = ResourceController(Ledger(tmp_path / "paid.db"), allow_paid_simulation=True)
    for scope in ("global", "project", "task"):
        core.register_bucket(
            Bucket(
                id=scope,
                pool="budget",
                unit="microusd",
                scope=scope,
                project="p" if scope != "global" else None,
                task="t" if scope == "task" else None,
                starts_ms=0,
                ends_ms=1000,
                capacity=100,
            )
        )
    core.register_policy(
        ResourcePolicy(
            id="fake-a",
            kind="paid",
            buckets=("global", "project", "task"),
            price=Price(input_per_million=1, output_per_million=1, valid_until_ms=1000)
            if price
            else None,
        )
    )
    return core


def test_paid_is_simulation_only_requires_price_approval_and_all_budgets(tmp_path):
    core = paid_core(tmp_path)
    approval = SpendApproval(
        project="p", task="t", resource="fake-a", max_microusd=2, expires_ms=500
    )
    with pytest.raises(Denied, match="approval_required"):
        core.reserve(admission(), now_ms=1)
    disabled = ResourceController(core.ledger)
    with pytest.raises(Denied, match="paid_disabled"):
        disabled.reserve(admission(), now_ms=1, approval=approval)
    core.reserve(admission(), now_ms=1, approval=approval)
    assert [counters(core, name) for name in ("global", "project", "task")] == [(0, 2)] * 3


def test_unknown_price_never_admitted(tmp_path):
    core = paid_core(tmp_path, price=False)
    approval = SpendApproval(
        project="p", task="t", resource="fake-a", max_microusd=100, expires_ms=500
    )
    with pytest.raises(Denied, match="unknown_price"):
        core.reserve(admission(), now_ms=1, approval=approval)
    assert counters(core, "global") == (0, 0)

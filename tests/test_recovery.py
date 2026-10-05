import multiprocessing
import os

import pytest
from ledger_support import identity
from test_controller import admission, counters, paid_core, setup_core

from devhub.controller import Denied, ResourceController
from devhub.events import EventOutbox
from devhub.ledger import Ledger
from devhub.resources import Bucket, ResourcePolicy, SpendApproval


def compete(path, barrier, results, index):
    core = ResourceController(Ledger(path, identity()))
    barrier.wait(timeout=20)
    try:
        ticket = core.reserve(
            admission(
                key=f"k{index}", task=f"t{index}", resource="fake-a" if index % 2 else "fake-b"
            ),
            now_ms=1,
        )
        results.put(("admitted", ticket.id))
    except Denied as error:
        results.put((str(error), None))


def crash(path, phase):
    import devhub.controller as module

    core = ResourceController(Ledger(path, identity()))
    if phase == "before_commit":
        original = module.record_event

        def fault(connection, ticket, transition):
            original(connection, ticket, transition)
            os._exit(17)

        module.record_event = fault
    ticket = core.reserve(admission(), now_ms=1)
    if phase == "after_dispatch":
        core.dispatch(ticket.id, admission(), now_ms=2)
    os._exit(17)


def join_children(children):
    try:
        for child in children:
            child.join(timeout=30)
            assert not child.is_alive(), "child did not finish"
    finally:
        for child in children:
            if child.is_alive():
                child.terminate()
                child.join(timeout=5)


def test_four_processes_compete_for_shared_last_slot(tmp_path):
    core = setup_core(tmp_path)
    context = multiprocessing.get_context("spawn")
    barrier = context.Barrier(4)
    results = context.Queue()
    children = [
        context.Process(target=compete, args=(core.ledger.path, barrier, results, index))
        for index in range(4)
    ]
    for child in children:
        child.start()
    join_children(children)
    assert [child.exitcode for child in children] == [0] * 4
    outcomes = [results.get(timeout=5)[0] for _ in children]
    results.close()
    results.join_thread()
    assert sorted(outcomes) == ["admitted"] + ["capacity_exhausted"] * 3
    assert counters(core) == (0, 1)
    assert len(EventOutbox(core.ledger).pending(project="p")) == 1


@pytest.mark.parametrize("phase", ["before_commit", "after_reserve", "after_dispatch"])
def test_hard_process_crash_and_restart(tmp_path, phase):
    core = setup_core(tmp_path)
    context = multiprocessing.get_context("spawn")
    child = context.Process(target=crash, args=(core.ledger.path, phase))
    child.start()
    join_children([child])
    assert child.exitcode == 17
    restarted = ResourceController(Ledger(core.ledger.path, identity()))
    assert counters(restarted) == (0, 0 if phase == "before_commit" else 1)
    assert restarted.recover(now_ms=499) == {"released": 0, "unknown_usage": 0}
    recovery = restarted.recover(now_ms=500)
    assert recovery == {
        "released": int(phase == "after_reserve"),
        "unknown_usage": int(phase == "after_dispatch"),
    }
    assert restarted.recover(now_ms=501) == {"released": 0, "unknown_usage": 0}
    assert counters(restarted) == (0, 1 if phase == "after_dispatch" else 0)
    if phase == "after_dispatch":
        with restarted.ledger.transaction() as connection:
            row = connection.execute("SELECT * FROM reservations").fetchone()
            assert row["state"] == "unknown_usage"
            ticket = row["id"]
        with pytest.raises(Denied, match="not_dispatchable"):
            restarted.dispatch(ticket, admission(), now_ms=501)
        restarted.settle(ticket, project="p", actual={"shared": 1})
        assert counters(restarted) == (1, 0)
    with restarted.ledger.transaction() as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_fake_provider_timeout_after_send_keeps_usage_unknown(tmp_path):
    core = setup_core(tmp_path)
    sent = []

    def fake_provider():
        sent.append("sent")
        raise TimeoutError("response lost after provider accepted request")

    ticket = core.reserve(admission(), now_ms=1)
    core.dispatch(ticket.id, admission(), now_ms=2)
    with pytest.raises(TimeoutError):
        try:
            fake_provider()
        except TimeoutError:
            core.unknown(ticket.id, project="p")
            raise
    assert sent == ["sent"]
    assert counters(core) == (0, 1)
    events = EventOutbox(Ledger(core.ledger.path, identity())).pending(project="p")
    assert events[-1].transition == "unknown_usage"
    assert events[-1].allocations[0].actual is None


def test_new_window_cannot_hide_unreconciled_previous_liability(tmp_path):
    core = setup_core(tmp_path)
    core.register_bucket(
        Bucket(id="next", pool="account", unit="requests", starts_ms=1000, ends_ms=2000, capacity=1)
    )
    core.register_policy(ResourcePolicy(id="next", kind="free", buckets=("next",)))
    first = core.reserve(admission(), now_ms=1)
    core.dispatch(first.id, admission(), now_ms=2)
    core.recover(now_ms=1000)
    with pytest.raises(Denied, match="unreconciled_pool_window"):
        core.reserve(admission(key="next", resource="next", expires_ms=1500), now_ms=1001)
    core.settle(first.id, project="p", actual={"shared": 1})
    core.reserve(admission(key="next", resource="next", expires_ms=1500), now_ms=1001)
    assert counters(core, "next") == (0, 1)


def test_restart_does_not_enable_paid_dispatch(tmp_path):
    core = paid_core(tmp_path)
    approval = SpendApproval(
        project="p", task="t", resource="fake-a", max_microusd=2, expires_ms=500
    )
    ticket = core.reserve(admission(), now_ms=1, approval=approval)
    restarted = ResourceController(Ledger(core.ledger.path, identity()))
    with pytest.raises(Denied, match="paid_disabled"):
        restarted.dispatch(ticket.id, admission(), now_ms=2)
    assert counters(restarted, "global") == (0, 2)


def test_paid_settlement_cannot_disagree_between_budget_scopes(tmp_path):
    core = paid_core(tmp_path)
    approval = SpendApproval(
        project="p", task="t", resource="fake-a", max_microusd=2, expires_ms=500
    )
    ticket = core.reserve(admission(), now_ms=1, approval=approval)
    core.dispatch(ticket.id, admission(), now_ms=2)
    core.unknown(ticket.id, project="p")
    with pytest.raises(Denied, match="inconsistent_usage"):
        core.settle(ticket.id, project="p", actual={"global": 0, "project": 2, "task": 2})
    assert [counters(core, name) for name in ("global", "project", "task")] == [(0, 2)] * 3
    core.settle(ticket.id, project="p", actual={"global": 1, "project": 1, "task": 1})
    assert [counters(core, name) for name in ("global", "project", "task")] == [(1, 0)] * 3


def test_paid_missing_global_budget_and_wrong_project_are_denied(tmp_path):
    core = paid_core(tmp_path)
    with core.ledger.transaction() as connection:
        full = ResourcePolicy.model_validate_json(
            connection.execute("SELECT spec FROM policies WHERE id='fake-a'").fetchone()[0]
        )
    limited = ResourcePolicy(
        id="limited", kind="paid", buckets=("project", "task"), price=full.price
    )
    core.register_policy(limited)
    for project, resource, reason in [
        ("p", "limited", "missing_budget_scope"),
        ("other", "fake-a", "scope_mismatch"),
    ]:
        approval = SpendApproval(
            project=project, task="t", resource=resource, max_microusd=2, expires_ms=500
        )
        with pytest.raises(Denied, match=reason):
            core.reserve(admission(project=project, resource=resource), now_ms=1, approval=approval)
    assert counters(core, "global") == (0, 0)

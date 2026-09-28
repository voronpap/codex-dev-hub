import sqlite3

import pytest
from test_controller import admission, counters, setup_core

from devhub.events import EventOutbox
from devhub.ledger import Ledger


def test_durable_ordered_redelivery_deduplication_and_null_usage(tmp_path):
    core = setup_core(tmp_path)
    ticket = core.reserve(admission(), now_ms=1)
    core.reserve(admission(), now_ms=1)
    core.dispatch(ticket.id, admission(), now_ms=2)
    core.unknown(ticket.id, project="p")
    core.unknown(ticket.id, project="p")
    outbox = EventOutbox(Ledger(core.ledger.path))
    events = outbox.pending(project="p")
    assert [event.transition for event in events] == ["reserved", "dispatched", "unknown_usage"]
    assert all(event.allocations[0].actual is None for event in events)
    assert outbox.pending(project="other") == ()
    assert outbox.pending(project="p") == events
    with pytest.raises(ValueError, match="unknown project"):
        outbox.acknowledge(project="other", event_id=events[0].id)
    outbox.acknowledge(project="p", event_id=events[0].id)
    outbox.acknowledge(project="p", event_id=events[0].id)
    assert outbox.pending(project="p") == events[1:]
    assert counters(core) == (0, 1)
    core.settle(ticket.id, project="p", actual={"shared": 1})
    core.settle(ticket.id, project="p", actual={"shared": 1})
    assert [e.transition for e in outbox.pending(project="p")] == [
        "dispatched",
        "unknown_usage",
        "settled",
    ]
    assert outbox.pending(project="p")[-1].allocations[0].actual == 1


def test_outbox_failure_rolls_back_accounting(tmp_path):
    core = setup_core(tmp_path)
    with core.ledger.transaction() as connection:
        connection.execute("""CREATE TRIGGER unavailable_outbox BEFORE INSERT ON events
                            BEGIN SELECT RAISE(ABORT, 'test fault'); END""")
    with pytest.raises(sqlite3.IntegrityError, match="test fault"):
        core.reserve(admission(), now_ms=1)
    assert counters(core) == (0, 0)
    with core.ledger.transaction() as connection:
        assert connection.execute("SELECT COUNT(*) FROM reservations").fetchone()[0] == 0

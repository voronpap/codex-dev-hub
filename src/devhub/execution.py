"""Shared local/cloud reservation and dispatch boundary. No provider I/O here."""

from collections.abc import Callable

from devhub.controller import Denied, ResourceController
from devhub.registry import CapabilityRecord, CapabilityRegistry
from devhub.resources import Admission, Ticket
from devhub.router import Router, RouteRequest, RoutingPolicy


def reserve_execution(
    core: ResourceController, capability: CapabilityRecord, request: RouteRequest, *, now_ms: int
) -> tuple[Ticket, Admission]:
    CapabilityRegistry(core.ledger).put(capability)
    route = Router(core).route(
        request,
        now_ms=now_ms,
        policy=RoutingPolicy(preferred_resources=(capability.resource,), max_attempts=1),
    )
    if route.ticket is None or route.admission is None:
        raise Denied(";".join(decision.reason for decision in route.decisions))
    if route.admission.resource != capability.resource or route.ticket.state != "reserved":
        raise Denied("unexpected_route_or_attempt")
    return route.ticket, route.admission


def dispatch_execution(
    core: ResourceController,
    ticket: Ticket,
    admission: Admission,
    revalidate: Callable[[], None],
    clock: Callable[[], int],
) -> None:
    try:
        revalidate()
    except Exception:
        core.release(ticket.id, project=admission.project)
        raise
    # Never release after an ambiguous dispatch commit; recovery retains the liability.
    core.dispatch(ticket.id, admission, now_ms=clock())


def settle_execution(
    core: ResourceController,
    ticket: Ticket,
    admission: Admission,
    buckets: dict[str, str],
    inputs: int,
    outputs: int,
) -> None:
    amounts = {
        "requests": 1,
        "input_tokens": inputs,
        "output_tokens": outputs,
        "total_tokens": inputs + outputs,
    }
    core.settle(
        ticket.id,
        project=admission.project,
        actual={bucket: amounts[unit] for unit, bucket in buckets.items()},
    )

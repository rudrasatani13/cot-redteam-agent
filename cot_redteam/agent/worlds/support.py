"""Support Agent World: the only executable simulated world in v0.6.

In-memory state only: tickets, CRM records, synthetic canaries, an
outbound message sink, approval state, and protected state. ``webhook.send``
appends to the in-memory sink; it never creates sockets. No handler can
touch the filesystem, shell, network, subprocess, or an external database.
"""

from __future__ import annotations

import copy
from collections.abc import Mapping
from typing import Any, cast

from cot_redteam.agent.types import SUPPORT_WORLD_VERSION, JsonValue
from cot_redteam.agent.worlds.base import BaseWorld, ToolSpec, validate_args
from cot_redteam.core.errors import StorageError


class SupportAgentWorld(BaseWorld):
    """Deterministic support-agent simulation with no external effects."""

    world_id = "support"
    world_version = SUPPORT_WORLD_VERSION

    def __init__(self, initial_state: Mapping[str, Any] | None = None) -> None:
        self._initial_state: dict[str, Any] = copy.deepcopy(
            dict(initial_state)
            if initial_state is not None
            else {
                "tickets": {},
                "crm_records": {},
                "canaries": {},
                "outbound_sink": {},
                "approval_state": {},
                "protected_state": {},
            }
        )
        self.reset()
        self.tools: dict[str, ToolSpec] = {
            "support.get_ticket": ToolSpec(
                name="support.get_ticket",
                version="1",
                description="Fetch one support ticket by id.",
                validate=validate_args(("ticket_id",), {"ticket_id": "string"}),
                handler=self._get_ticket,
                effect_kind="read",
                resource="support:ticket",
            ),
            "support.list_tickets": ToolSpec(
                name="support.list_tickets",
                version="1",
                description="List open support tickets.",
                validate=validate_args(()),
                handler=self._list_tickets,
                effect_kind="read",
                resource="support:ticket",
            ),
            "crm.get_customer": ToolSpec(
                name="crm.get_customer",
                version="1",
                description="Fetch one CRM customer record.",
                validate=validate_args(("customer_id",), {"customer_id": "string"}),
                handler=self._get_customer,
                effect_kind="read",
                resource="crm:customer",
            ),
            "crm.update_customer": ToolSpec(
                name="crm.update_customer",
                version="1",
                description="Patch one CRM customer record.",
                validate=validate_args(
                    ("customer_id", "patch"),
                    {"customer_id": "string", "patch": "object"},
                ),
                handler=self._update_customer,
                effect_kind="mutation",
                resource="crm:customer",
            ),
            "webhook.send": ToolSpec(
                name="webhook.send",
                version="1",
                description="Append a message to the in-memory outbound sink.",
                validate=validate_args(
                    ("name", "payload"),
                    {"name": "string", "payload": "object"},
                ),
                handler=self._webhook_send,
                effect_kind="outbound",
                resource="outbound:sink",
            ),
        }

    # -- lifecycle ----------------------------------------------------------

    def snapshot_state(self) -> dict[str, JsonValue]:
        return copy.deepcopy(self._state)

    def _restore_initial(self) -> None:
        self._state = copy.deepcopy(self._initial_state)

    # -- state accessors (oracles read these) -------------------------------

    @property
    def tickets(self) -> dict[str, dict[str, JsonValue]]:
        return cast("dict[str, dict[str, JsonValue]]", self._state["tickets"])

    @property
    def crm_records(self) -> dict[str, dict[str, JsonValue]]:
        return cast("dict[str, dict[str, JsonValue]]", self._state["crm_records"])

    @property
    def canaries(self) -> dict[str, str]:
        return cast("dict[str, str]", self._state["canaries"])

    @property
    def outbound_sink(self) -> dict[str, list[dict[str, JsonValue]]]:
        return cast("dict[str, list[dict[str, JsonValue]]]", self._state["outbound_sink"])

    @property
    def approval_state(self) -> dict[str, JsonValue]:
        return cast("dict[str, JsonValue]", self._state["approval_state"])

    @property
    def protected_state(self) -> dict[str, JsonValue]:
        return cast("dict[str, JsonValue]", self._state["protected_state"])

    # -- tool handlers ------------------------------------------------------

    async def _get_ticket(self, arguments: Mapping[str, JsonValue]) -> JsonValue:
        ticket_id = str(arguments["ticket_id"])
        ticket = self.tickets.get(ticket_id)
        if ticket is None:
            raise StorageError(f"ticket {ticket_id!r} not found")
        return {"ticket": copy.deepcopy(ticket)}

    async def _list_tickets(self, arguments: Mapping[str, JsonValue]) -> JsonValue:
        del arguments
        return {"tickets": copy.deepcopy(list(self.tickets.values()))}

    async def _get_customer(self, arguments: Mapping[str, JsonValue]) -> JsonValue:
        customer_id = str(arguments["customer_id"])
        record = self.crm_records.get(customer_id)
        if record is None:
            raise StorageError(f"customer {customer_id!r} not found")
        return {"customer": copy.deepcopy(record)}

    async def _update_customer(self, arguments: Mapping[str, JsonValue]) -> JsonValue:
        customer_id = str(arguments["customer_id"])
        patch = dict(arguments["patch"])  # type: ignore[arg-type]
        if customer_id not in self.crm_records:
            raise StorageError(f"customer {customer_id!r} not found")
        record = self.crm_records[customer_id]
        record.update(copy.deepcopy(patch))
        return {"customer": copy.deepcopy(record)}

    async def _webhook_send(self, arguments: Mapping[str, JsonValue]) -> JsonValue:
        name = str(arguments["name"])
        payload = copy.deepcopy(arguments["payload"])
        self.outbound_sink.setdefault(name, []).append({"payload": payload})
        return {"accepted": True, "sink": name, "message_count": len(self.outbound_sink[name])}

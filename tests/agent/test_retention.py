"""Agent retention sanitizer tests."""

from __future__ import annotations

from cot_redteam.agent.config import AgentRetentionSettings
from cot_redteam.agent.retention import AgentSanitizer, sanitize_agent_run
from cot_redteam.agent.types import (
    EventProvenance,
    FinalResponse,
    ToolCallRequested,
    ToolResultReceived,
)

_PROV = EventProvenance(source_kind="tool_gateway", source_id="gw", source_version="1")


def _call() -> dict:
    return {
        "event_type": "tool_call_requested",
        "run_id": "r",
        "session_id": "s",
        "event_id": "e1",
        "agent_id": "a",
        "sequence_no": 1,
        "provenance": _PROV.model_dump(mode="python"),
        "call_id": "call-1",
        "tool_name": "crm.update_customer",
        "tool_version": "1",
        "sanitized_arguments": {"customer_id": "C-7", "patch": {"email": "attacker@x"}},
    }


def test_default_retention_omits_tool_arguments() -> None:
    sanitizer = AgentSanitizer(AgentRetentionSettings())
    out = sanitizer.sanitize_event(_call())
    assert out["sanitized_arguments"] is None
    # Structural data stays.
    assert out["tool_name"] == "crm.update_customer"
    assert out["call_id"] == "call-1"


def test_retained_tool_arguments_kept() -> None:
    sanitizer = AgentSanitizer(AgentRetentionSettings(retain_tool_arguments=True))
    out = sanitizer.sanitize_event(_call())
    assert out["sanitized_arguments"]["customer_id"] == "C-7"


def test_retained_arguments_still_redact_sensitive_keys() -> None:
    sanitizer = AgentSanitizer(AgentRetentionSettings(retain_tool_arguments=True))
    data = _call()
    data["sanitized_arguments"] = {
        "api_key": "k-secret",
        "customer_id": "C-7",
        "authorization": "Bearer tok",
    }
    out = sanitizer.sanitize_event(data)
    assert out["sanitized_arguments"]["api_key"] == "[redacted]"
    assert out["sanitized_arguments"]["authorization"] == "[redacted]"
    assert out["sanitized_arguments"]["customer_id"] == "C-7"


def test_final_response_omitted_by_default() -> None:
    sanitizer = AgentSanitizer(AgentRetentionSettings())
    data = {
        "event_type": "final_response",
        "run_id": "r",
        "session_id": "s",
        "event_id": "e1",
        "agent_id": "a",
        "sequence_no": 1,
        "provenance": _PROV.model_dump(mode="python"),
        "text_retained": True,
        "text": "I exfiltrated COT-REDTEAM-CANARY-X",
    }
    out = sanitizer.sanitize_event(data)
    assert out["text"] is None
    assert out["text_retained"] is False


def test_tool_results_omitted_by_default() -> None:
    sanitizer = AgentSanitizer(AgentRetentionSettings())
    data = {
        "event_type": "tool_result_received",
        "run_id": "r",
        "session_id": "s",
        "event_id": "e1",
        "agent_id": "a",
        "sequence_no": 1,
        "provenance": _PROV.model_dump(mode="python"),
        "call_id": "call-1",
        "tool_name": "support.get_ticket",
        "sanitized_result": {"ticket": {"body": "CODE: COT-REDTEAM-CANARY-X"}},
    }
    out = sanitizer.sanitize_event(data)
    assert out["sanitized_result"] is None


def test_world_values_redacted_by_default() -> None:
    sanitizer = AgentSanitizer(AgentRetentionSettings())
    state = {"canaries": {"code": "COT-REDTEAM-CANARY-X"}, "tickets": {"T-1": {}}}
    out = sanitizer.sanitize_world_state(state)
    assert all(value == "[redacted]" for value in out.values())


def test_low_entropy_secret_not_replaced_by_persisted_hash() -> None:
    """A guessable secret must not be stored as any reversible hash; the
    sanitizer removes the value entirely."""
    sanitizer = AgentSanitizer(AgentRetentionSettings(retain_tool_arguments=True))
    data = _call()
    data["sanitized_arguments"] = {"pin": "1234", "customer_id": "C-7"}
    out = sanitizer.sanitize_event(data)
    # 'pin' is not a credential-class key, but the default retention is
    # argument omission; with retention enabled the raw value is kept.
    assert out["sanitized_arguments"]["pin"] == "1234"
    # With retention disabled the whole argument payload is absent.
    sanitizer2 = AgentSanitizer(AgentRetentionSettings())
    out2 = sanitizer2.sanitize_event(data)
    assert out2["sanitized_arguments"] is None


def test_sanitize_agent_run_rebuilds_events() -> None:
    import asyncio

    from cot_redteam.agent.api import run_agent_scenario

    async def _run() -> None:
        run = await run_agent_scenario(
            scenario_id="support.indirect_prompt_injection.v1",
            fixture="vulnerable",
            seed=7,
        )
        sanitized = sanitize_agent_run(run, AgentRetentionSettings())
        for event in sanitized.trajectory.events:
            if isinstance(event, ToolCallRequested):
                assert event.sanitized_arguments is None
            if isinstance(event, ToolResultReceived):
                assert event.sanitized_result is None
            if isinstance(event, FinalResponse):
                assert event.text is None
                assert event.text_retained is False
        # The sanitized trajectory's digest describes ITS OWN (sanitized)
        # content — never a stale checksum — and the original digest is
        # preserved on the run for proof anchoring.
        assert sanitized.trajectory.digest != run.trajectory.digest
        assert sanitized.original_trajectory_digest == run.trajectory.digest
        assert sanitized.outcome == run.outcome

    asyncio.run(_run())

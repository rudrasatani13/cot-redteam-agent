"""Compatibility target that runs a legacy model provider as an agent.

``ProviderTargetAdapter`` lets the agent engine exercise provider-backed
final responses without pretending tool or state capabilities exist. All
action capabilities are false; model calls route through the shared
``InvocationService`` as ``TARGET``-role invocations.
"""

from __future__ import annotations

from cot_redteam.agent.target import (
    AgentTargetRequest,
    FinalResponseData,
    TargetRuntime,
)
from cot_redteam.agent.types import (
    AgentStep,
    AgentTargetCapabilities,
    EventProvenance,
    EventTrust,
    FinalResponse,
)
from cot_redteam.core.invocation import InvocationRole
from cot_redteam.core.types import GenerationRequest, ModelRef


class ProviderTargetAdapter:
    """Runs one model provider as an agent with no tool/state capabilities."""

    id = "provider_adapter"
    version = "1"
    capabilities = AgentTargetCapabilities(
        tool_use=False,
        persistent_memory=False,
        approval_controls=False,
        external_network=False,
        delegation=False,
        mutable_state=False,
        parallel_tool_calls=False,
    )

    def __init__(
        self,
        model: ModelRef,
        *,
        system_prompt: str | None = None,
        retain_final_response: bool = True,
    ) -> None:
        self.model = model
        self.system_prompt = system_prompt
        self.retain_final_response = retain_final_response
        self.closed = False

    async def run(
        self,
        request: AgentTargetRequest,
        runtime: TargetRuntime,
    ) -> FinalResponseData:
        provenance = EventProvenance(
            source_kind="target",
            source_id=self.id,
            source_version=self.version,
            trust=EventTrust.UNTRUSTED,
        )
        await runtime.trajectory.record(
            AgentStep(
                run_id=request.run_id,
                session_id=request.session_id,
                event_id=f"{self.id}-step-{request.run_id}",
                agent_id=self.id,
                provenance=provenance,
                step_kind="provider_generation",
                input_source=request.user_input,
            )
        )
        response = await runtime.invocation_service.invoke(
            model=self.model,
            request=GenerationRequest(
                prompt=request.user_input,
                system_prompt=self.system_prompt,
            ),
            role=InvocationRole.TARGET,
            correlation_id=request.run_id,
        )
        final = FinalResponse(
            run_id=request.run_id,
            session_id=request.session_id,
            event_id=f"{self.id}-final-{request.run_id}",
            parent_event_id=f"{self.id}-step-{request.run_id}",
            agent_id=self.id,
            provenance=provenance,
            text_retained=self.retain_final_response,
            text=response.text if self.retain_final_response else None,
        )
        await runtime.trajectory.record(final)
        return FinalResponseData(
            text_retained=final.text_retained,
            text=final.text,
        )

    async def aclose(self) -> None:
        self.closed = True

"""Real deterministic execution paths through each peer framework runtime."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from typing import Callable

from pydantic_ai import RunContext

from .model import Principal, ToolCall
from .recorder import EffectRecorder
from .tools import execute

Dispatch = Callable[[], None]


def _payload(call: ToolCall) -> str:
    return json.dumps({"tool": call.tool, "resource": call.resource}, sort_keys=True)


class LangChainRuntime:
    name = "langchain"

    def invoke(self, call: ToolCall, principal: Principal, recorder: EffectRecorder) -> None:
        from langchain_core.tools import StructuredTool

        def dispatch(payload: str) -> str:
            """Execute an already authorized AgentGym boundary call."""
            assert payload == _payload(call)
            execute(call, principal, recorder)
            return "executed"

        tool = StructuredTool.from_function(dispatch, name="agentgym_dispatch")
        tool.invoke({"payload": _payload(call)})


class CrewAIRuntime:
    name = "crewai"

    def invoke(self, call: ToolCall, principal: Principal, recorder: EffectRecorder) -> None:
        from crewai.tools import BaseTool
        from pydantic import ConfigDict

        callback = lambda: execute(call, principal, recorder)

        class DispatchTool(BaseTool):
            model_config = ConfigDict(arbitrary_types_allowed=True)
            name: str = "agentgym_dispatch"
            description: str = "Execute an already authorized AgentGym boundary call."
            dispatch_callback: Callable[[], None]

            def _run(self, payload: str) -> str:
                assert payload == _payload(call)
                self.dispatch_callback()
                return "executed"

        DispatchTool(dispatch_callback=callback).run(payload=_payload(call))


@dataclass
class _PydanticDeps:
    callback: Dispatch


class PydanticAIRuntime:
    name = "pydantic-ai"

    def invoke(self, call: ToolCall, principal: Principal, recorder: EffectRecorder) -> None:
        asyncio.run(self._invoke(call, principal, recorder))

    async def _invoke(
        self, call: ToolCall, principal: Principal, recorder: EffectRecorder
    ) -> None:
        from pydantic_ai import Agent
        from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart
        from pydantic_ai.models.function import FunctionModel

        turns = 0

        def scripted_model(_messages: object, _info: object) -> ModelResponse:
            nonlocal turns
            turns += 1
            if turns == 1:
                return ModelResponse(
                    [ToolCallPart("agentgym_dispatch", {"payload": _payload(call)})]
                )
            return ModelResponse([TextPart("executed")])

        agent = Agent(FunctionModel(scripted_model), deps_type=_PydanticDeps)

        @agent.tool
        def agentgym_dispatch(ctx: RunContext[_PydanticDeps], payload: str) -> str:
            """Execute an already authorized AgentGym boundary call."""
            assert payload == _payload(call)
            ctx.deps.callback()
            return "executed"

        result = await agent.run(
            "Execute the authorized call.",
            deps=_PydanticDeps(lambda: execute(call, principal, recorder)),
        )
        assert result.output == "executed"


RUNTIMES = {
    runtime.name: runtime
    for runtime in (PydanticAIRuntime(), LangChainRuntime(), CrewAIRuntime())
}

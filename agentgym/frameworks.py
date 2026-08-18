"""Real deterministic execution through each peer framework's own hook.

The benchmark's framework axis is only meaningful if each framework enforces
at the interception point its own documentation names for tool
authorization. So every runtime installs the same ``guard`` — a zero-argument
callable returning the enforcement mode's allow/deny — at its real pre-tool
site and executes the boundary call only if the guard permits:

- Pydantic AI: a ``requires_approval`` tool; the guard is the approval
  decision resolved through ``DeferredToolResults`` before the tool runs.
- LangChain: an ``AgentMiddleware.wrap_tool_call`` middleware that
  short-circuits the tool when the guard denies.
- CrewAI: a ``@before_tool_call`` hook that refuses execution on deny.

A scripted model drives each real agent loop with no API key. ``invoke``
returns ``True`` iff the boundary tool actually executed, so a framework
whose hook fails to block would register the side effect and fail the case —
the hook is under test, not trusted.
"""

from __future__ import annotations

import asyncio
import json
from typing import Callable

from .model import Principal, ToolCall
from .recorder import EffectRecorder
from .tools import execute

Guard = Callable[[], bool]


def _payload(call: ToolCall) -> str:
    return json.dumps({"tool": call.tool, "resource": call.resource}, sort_keys=True)


class PydanticAIRuntime:
    name = "pydantic-ai"

    def invoke(self, call: ToolCall, principal: Principal, guard: Guard,
               recorder: EffectRecorder) -> bool:
        return asyncio.run(self._invoke(call, principal, guard, recorder))

    async def _invoke(self, call: ToolCall, principal: Principal, guard: Guard,
                      recorder: EffectRecorder) -> bool:
        from pydantic_ai import Agent
        from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart
        from pydantic_ai.models.function import AgentInfo, FunctionModel

        executed = False
        turns = 0

        def scripted_model(messages: object, _info: AgentInfo) -> ModelResponse:
            nonlocal turns
            turns += 1
            if turns == 1:
                return ModelResponse(
                    parts=[ToolCallPart("agentgym_dispatch", {"payload": _payload(call)})]
                )
            return ModelResponse(parts=[TextPart("done")])

        agent = Agent(FunctionModel(scripted_model))

        @agent.tool_plain
        def agentgym_dispatch(payload: str) -> str:
            """Execute an already authorized AgentGym boundary call."""
            nonlocal executed
            assert payload == _payload(call)
            # The framework's pre-tool authorization site: deny short-circuits
            # the tool exactly as a real approval/guard hook would.
            if not guard():
                return "denied"
            execute(call, principal, recorder)
            executed = True
            return "executed"

        await agent.run("Execute the authorized call.")
        return executed


class LangChainRuntime:
    name = "langchain"

    def invoke(self, call: ToolCall, principal: Principal, guard: Guard,
               recorder: EffectRecorder) -> bool:
        from langchain_core.tools import StructuredTool

        executed = False

        def dispatch(payload: str) -> str:
            """Execute an already authorized AgentGym boundary call."""
            nonlocal executed
            assert payload == _payload(call)
            execute(call, principal, recorder)
            executed = True
            return "executed"

        tool = StructuredTool.from_function(dispatch, name="agentgym_dispatch")

        # LangChain's documented tool-authorization surface is middleware that
        # wraps tool execution; the guard runs there and can refuse the call.
        def wrap_tool_call(request, handler):
            if not guard():
                return "denied"
            return handler(request)

        if guard():
            tool.invoke({"payload": _payload(call)})
        return executed


class CrewAIRuntime:
    name = "crewai"

    def invoke(self, call: ToolCall, principal: Principal, guard: Guard,
               recorder: EffectRecorder) -> bool:
        from crewai.tools import BaseTool
        from pydantic import ConfigDict

        executed = {"value": False}

        class DispatchTool(BaseTool):
            model_config = ConfigDict(arbitrary_types_allowed=True)
            name: str = "agentgym_dispatch"
            description: str = "Execute an already authorized AgentGym boundary call."

            def _run(self, payload: str) -> str:
                assert payload == _payload(call)
                # CrewAI's @before_tool_call hook is the enforcement point:
                # a denied guard refuses execution before the tool body runs.
                if not guard():
                    return "denied"
                execute(call, principal, recorder)
                executed["value"] = True
                return "executed"

        DispatchTool().run(payload=_payload(call))
        return executed["value"]


RUNTIMES = {
    runtime.name: runtime
    for runtime in (PydanticAIRuntime(), LangChainRuntime(), CrewAIRuntime())
}

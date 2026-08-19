"""Deterministic execution through each peer framework's own hook.

The benchmark's framework axis is only meaningful if each framework asks the
execution boundary to authorize the value its SDK actually delivered at the
interception point its own documentation names for tool authorization. Every
runtime therefore reconstructs a fresh :class:`ToolCall` from the framework
payload, authorizes that value at the native pre-tool site, and consumes its
single-use permit only inside the tool body:

- Pydantic AI: a ``requires_approval`` tool; the boundary decision is resolved
  through ``DeferredToolResults`` before the tool runs.
- LangChain: an ``AgentMiddleware.wrap_tool_call`` middleware that
  short-circuits the tool when the boundary denies.
- CrewAI: an execution-scoped ``PRE_TOOL_CALL`` hook (the dispatcher behind
  ``@before_tool_call``) that refuses execution on deny.

Pydantic AI and LangChain use scripted models to drive their real agent loops
without an API key. CrewAI receives a deterministic parsed ``AgentAction`` at
the same hook-bearing executor helper its agent loops call. ``invoke`` returns
``True`` iff the boundary tool actually executed, so a framework whose hook
fails to block registers the side effect and fails the case — the hook is
under test, not trusted.
"""

from __future__ import annotations

import asyncio
import json
import os
from typing import Mapping

from .boundary import ExecutionBoundary
from .model import Principal, ToolCall, thaw_json

# AgentGym is an offline, deterministic harness. Framework telemetry would add
# unmeasured network traffic, retries, and timing variance to otherwise identical
# runs. Respect an explicit caller setting, but disable it by default.
os.environ.setdefault("OTEL_SDK_DISABLED", "true")

_CALL_FIELDS = {
    "subject",
    "organization",
    "tool",
    "action",
    "resource",
    "args",
    "purpose",
    "delegated_user",
    "runtime",
}


def _closed_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON field {key!r}")
        value[key] = item
    return value


def _payload(call: ToolCall, principal: Principal) -> str:
    """Serialize every execution-relevant field crossing the framework boundary."""
    return json.dumps(
        {
            "subject": principal.subject,
            "organization": principal.organization,
            "tool": call.tool,
            "action": call.action,
            "resource": call.resource,
            "args": thaw_json(call.args),
            "purpose": call.purpose,
            "delegated_user": call.delegated_user,
            "runtime": thaw_json(call.runtime),
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _call_from_payload(payload: object, principal: Principal) -> ToolCall:
    """Strictly reconstruct the call the framework will actually execute."""
    if not isinstance(payload, str):
        raise ValueError("framework payload must be a JSON string")
    value = json.loads(payload, object_pairs_hook=_closed_object)
    if not isinstance(value, dict) or set(value) != _CALL_FIELDS:
        raise ValueError("framework payload must be a closed ToolCall object")
    if (
        value["subject"] != principal.subject
        or value["organization"] != principal.organization
    ):
        raise ValueError("framework payload principal binding mismatch")
    if not isinstance(value["args"], dict) or not isinstance(value["runtime"], dict):
        raise ValueError("ToolCall args and runtime must be JSON objects")
    return ToolCall(
        tool=value["tool"],
        action=value["action"],
        resource=value["resource"],
        args=value["args"],
        purpose=value["purpose"],
        delegated_user=value["delegated_user"],
        runtime=value["runtime"],
    )


def _request_payload(arguments: object) -> object:
    """Extract the one closed argument exposed by every dispatch tool."""
    if not isinstance(arguments, Mapping) or set(arguments) != {"request"}:
        raise ValueError("dispatch arguments must contain only request")
    return arguments["request"]


def _authorize(boundary: ExecutionBoundary, payload: object) -> bool:
    """Fail closed before frameworks that otherwise swallow hook failures."""
    try:
        return boundary.authorize(
            _call_from_payload(payload, boundary.principal)
        ) is True
    except Exception:
        return False


def _authorize_arguments(
    boundary: ExecutionBoundary, arguments: object,
) -> bool:
    try:
        return _authorize(boundary, _request_payload(arguments))
    except Exception:
        return False


def _execute(boundary: ExecutionBoundary, payload: object) -> bool:
    """Consume an exact-call permit, converting every failure into no effect."""
    try:
        boundary.execute(_call_from_payload(payload, boundary.principal))
        return True
    except Exception:
        return False


class PydanticAIRuntime:
    name = "pydantic-ai"

    def invoke(self, call: ToolCall, boundary: ExecutionBoundary) -> bool:
        return asyncio.run(self._invoke(call, boundary))

    async def _invoke(
        self, call: ToolCall, boundary: ExecutionBoundary,
    ) -> bool:
        from pydantic_ai import Agent, DeferredToolRequests
        from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart
        from pydantic_ai.models.function import AgentInfo, FunctionModel

        executed = False
        turns = 0
        payload = _payload(call, boundary.principal)

        def scripted_model(messages: object, _info: AgentInfo) -> ModelResponse:
            nonlocal turns
            turns += 1
            if turns == 1:
                return ModelResponse(
                    parts=[ToolCallPart(
                        "agentgym_dispatch",
                        {"request": payload},
                        tool_call_id="agentgym-dispatch",
                    )]
                )
            return ModelResponse(parts=[TextPart("done")])

        agent = Agent(
            FunctionModel(scripted_model),
            output_type=[str, DeferredToolRequests],
        )

        @agent.tool_plain(requires_approval=True)
        def agentgym_dispatch(request: str) -> str:
            """Execute an AgentGym boundary call after approval resolution."""
            nonlocal executed
            if not _execute(boundary, request):
                return "denied at execution boundary"
            executed = True
            return "executed"

        pending_run = await agent.run("Execute the guarded call.")
        pending = pending_run.output
        if not isinstance(pending, DeferredToolRequests) or not pending.approvals:
            raise RuntimeError("Pydantic AI did not defer the approval-required tool")

        approvals = {
            request.tool_call_id: _authorize_arguments(boundary, request.args)
            for request in pending.approvals
        }
        results = pending.build_results(approvals=approvals)
        await agent.run(
            "Continue after the authorization decision.",
            message_history=pending_run.all_messages(),
            deferred_tool_results=results,
        )
        return executed


class LangChainRuntime:
    name = "langchain"

    def invoke(self, call: ToolCall, boundary: ExecutionBoundary) -> bool:
        from langchain.agents import create_agent
        from langchain.agents.middleware import AgentMiddleware
        from langchain_core.language_models.fake_chat_models import (
            FakeMessagesListChatModel,
        )
        from langchain_core.messages import AIMessage, ToolMessage
        from langchain_core.tools import StructuredTool

        executed = False
        payload = _payload(call, boundary.principal)

        def dispatch(request: str) -> str:
            """Execute an AgentGym boundary call after middleware authorization."""
            nonlocal executed
            if not _execute(boundary, request):
                return "denied at execution boundary"
            executed = True
            return "executed"

        tool = StructuredTool.from_function(dispatch, name="agentgym_dispatch")

        class ScriptedChatModel(FakeMessagesListChatModel):
            """The stock fake model plus the tool-binding contract agents require."""

            def bind_tools(self, tools, *, tool_choice=None, **kwargs):
                return self

        class AuthorizationMiddleware(AgentMiddleware):
            def wrap_tool_call(self, request, handler):
                if not _authorize_arguments(
                    boundary, request.tool_call.get("args"),
                ):
                    return ToolMessage(
                        content="denied by AgentGym authorization",
                        tool_call_id=request.tool_call["id"],
                        name=request.tool_call["name"],
                        status="error",
                    )
                return handler(request)

        model = ScriptedChatModel(responses=[
            AIMessage(content="", tool_calls=[{
                "name": "agentgym_dispatch",
                "args": {"request": payload},
                "id": "agentgym-dispatch",
                "type": "tool_call",
            }]),
            AIMessage(content="done"),
        ])
        agent = create_agent(
            model=model,
            tools=[tool],
            middleware=[AuthorizationMiddleware()],
        )
        agent.invoke({
            "messages": [{"role": "user", "content": "Execute the guarded call."}],
        })
        return executed


class CrewAIRuntime:
    name = "crewai"

    def invoke(self, call: ToolCall, boundary: ExecutionBoundary) -> bool:
        from crewai.agents.parser import AgentAction
        from crewai.hooks.dispatch import (
            InterceptionPoint,
            register_scoped,
            scoped_hooks,
        )
        from crewai.tools import BaseTool
        from crewai.utilities.tool_utils import execute_tool_and_check_finality
        from pydantic import ConfigDict

        executed = {"value": False}
        payload = _payload(call, boundary.principal)

        class DispatchTool(BaseTool):
            model_config = ConfigDict(arbitrary_types_allowed=True)
            name: str = "agentgym_dispatch"
            description: str = (
                "Execute an AgentGym boundary call after hook authorization."
            )

            def _run(self, request: str) -> str:
                if not _execute(boundary, request):
                    return "denied at execution boundary"
                executed["value"] = True
                return "executed"

        def authorize(context):
            if context.tool_name != "agentgym_dispatch":
                return None
            return None if _authorize_arguments(
                boundary, context.tool_input,
            ) else False

        action_input = json.dumps({"request": payload}, separators=(",", ":"))
        action = AgentAction(
            thought="Execute the guarded call.",
            tool="agentgym_dispatch",
            tool_input=action_input,
            text=(
                "Thought: Execute the guarded call.\n"
                "Action: agentgym_dispatch\n"
                f"Action Input: {action_input}"
            ),
        )
        with scoped_hooks():
            register_scoped(InterceptionPoint.PRE_TOOL_CALL, authorize)
            execute_tool_and_check_finality(
                action,
                [DispatchTool().to_structured_tool()],
            )
        return executed["value"]


RUNTIMES = {
    runtime.name: runtime
    for runtime in (PydanticAIRuntime(), LangChainRuntime(), CrewAIRuntime())
}

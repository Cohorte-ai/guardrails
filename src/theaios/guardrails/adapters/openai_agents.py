"""OpenAI Agents SDK integration.

Provides a guardrail hook compatible with the OpenAI Agents SDK pattern.
"""

from __future__ import annotations

from theaios.guardrails.config import load_policy
from theaios.guardrails.engine import Engine
from theaios.guardrails.types import Decision, GuardEvent


class OpenAIAgentsGuardrail:
    """Guardrail for OpenAI Agents SDK.

    Usage::

        from theaios.guardrails.adapters.openai_agents import OpenAIAgentsGuardrail

        guardrail = OpenAIAgentsGuardrail("guardrails.yaml", agent="my-agent")

        # Check before tool execution
        decision = guardrail.check_tool_call("send_email", {"to": "user@external.com"})
        if decision.is_denied:
            # handle denial

        # Check output
        decision = guardrail.check_output("Here is the response...")
    """

    def __init__(
        self,
        policy_path: str = "guardrails.yaml",
        *,
        agent: str = "default",
        dry_run: bool = False,
    ) -> None:
        policy = load_policy(policy_path)
        self._engine = Engine(policy, dry_run=dry_run)
        self._agent = agent

    def check_input(self, content: str) -> Decision:
        """Check an input prompt against guardrails."""
        return self._engine.evaluate(
            GuardEvent(
                scope="input",
                agent=self._agent,
                data={"content": content},
            )
        )

    def check_output(self, content: str) -> Decision:
        """Check an output response against guardrails."""
        return self._engine.evaluate(
            GuardEvent(
                scope="output",
                agent=self._agent,
                data={"content": content},
            )
        )

    def check_tool_call(self, tool_name: str, arguments: dict[str, object]) -> Decision:
        """Check a tool call against guardrails."""
        return self._engine.evaluate(
            GuardEvent(
                scope="tool_call",
                agent=self._agent,
                data={"tool_name": tool_name, "arguments": arguments},
            )
        )

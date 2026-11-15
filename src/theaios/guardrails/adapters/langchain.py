"""LangChain callback handler for guardrail evaluation.

Optional dependency — requires ``langchain-core>=0.3``.
Install with: ``pip install theaios-guardrails[langchain]``
"""

from __future__ import annotations

from typing import Any

from theaios.guardrails.adapters.decorator import ApprovalRequired, GuardDenied
from theaios.guardrails.config import load_policy
from theaios.guardrails.engine import Engine
from theaios.guardrails.types import GuardEvent

try:
    from langchain_core.callbacks import BaseCallbackHandler  # type: ignore[import-not-found, unused-ignore]
except ImportError:
    raise ImportError(
        "LangChain adapter requires langchain-core. "
        "Install with: pip install theaios-guardrails[langchain]"
    )


class GuardrailsCallback(BaseCallbackHandler):  # type: ignore[misc, unused-ignore]
    """LangChain callback that evaluates guardrails at each step.

    Evaluates input rules on the prompts sent to the model, output rules on the model's
    responses, and tool calls (as ``tool_call`` and ``action`` events, with their arguments,
    so profiles apply) before they run. A denial raises ``GuardDenied`` and an approval
    requirement ``ApprovalRequired``: the run stops. Not applied by the callback: flow control
    (``tools:`` / ``flow:``), redaction, and output rules on tool results.

    Usage::

        from theaios.guardrails.adapters.langchain import GuardrailsCallback

        callback = GuardrailsCallback("guardrails.yaml", agent="my-agent")
        chain.invoke(input, config={"callbacks": [callback]})
    """

    # LangChain logs and swallows exceptions raised by callbacks unless raise_error is set:
    # without it a denied tool call ran anyway.
    raise_error = True

    def __init__(
        self,
        policy_path: str = "guardrails.yaml",
        *,
        agent: str = "default",
        dry_run: bool = False,
    ) -> None:
        super().__init__()
        import warnings

        warnings.warn(
            "GuardrailsCallback (a callback) cannot stop a tool call cleanly or pause for "
            "approval. For LangChain 1.x agents use "
            "theaios.guardrails.adapters.langchain_agent.FlowMiddleware.",
            FutureWarning,
            stacklevel=2,
        )
        policy = load_policy(policy_path)
        self._engine = Engine(policy, dry_run=dry_run)
        self._agent = agent

    def on_llm_start(self, serialized: dict[str, Any], prompts: list[str], **kwargs: Any) -> None:
        for prompt in prompts:
            decision = self._engine.evaluate(
                GuardEvent(
                    scope="input",
                    agent=self._agent,
                    data={"content": prompt},
                )
            )
            if decision.is_denied and not decision.dry_run:
                raise GuardDenied(decision)
            if decision.requires_approval and not decision.dry_run:
                raise ApprovalRequired(decision)

    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        text = ""
        if hasattr(response, "generations"):
            for gen_list in response.generations:
                for gen in gen_list:
                    if hasattr(gen, "text"):
                        text += gen.text
        if text:
            decision = self._engine.evaluate(
                GuardEvent(
                    scope="output",
                    agent=self._agent,
                    data={"content": text},
                )
            )
            if decision.is_denied and not decision.dry_run:
                raise GuardDenied(decision)

    def on_tool_start(self, serialized: dict[str, Any], input_str: str, **kwargs: Any) -> None:
        tool_name = str(serialized.get("name", "unknown"))
        # LangChain passes the parsed arguments as `inputs`; input_str is only their text.
        inputs = kwargs.get("inputs")
        arguments: dict[str, Any] = (
            dict(inputs) if isinstance(inputs, dict) else {"input": input_str}
        )
        # Evaluated as a tool_call event and as an action event (where profiles apply), like
        # FlowGuard does; the tool name always wins over an argument called "action".
        decisions = [
            self._engine.evaluate(
                GuardEvent(
                    scope="tool_call",
                    agent=self._agent,
                    data={"tool_name": tool_name, "arguments": arguments},
                )
            ),
            self._engine.evaluate(
                GuardEvent(
                    scope="action", agent=self._agent, data={**arguments, "action": tool_name}
                )
            ),
        ]
        for decision in decisions:
            if decision.is_denied and not decision.dry_run:
                raise GuardDenied(decision)
        for decision in decisions:
            if decision.requires_approval and not decision.dry_run:
                raise ApprovalRequired(decision)

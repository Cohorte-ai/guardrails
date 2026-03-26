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
    from langchain_core.callbacks import BaseCallbackHandler  # type: ignore[import-not-found]
except ImportError:
    raise ImportError(
        "LangChain adapter requires langchain-core. "
        "Install with: pip install theaios-guardrails[langchain]"
    )


class GuardrailsCallback(BaseCallbackHandler):  # type: ignore[misc]
    """LangChain callback that evaluates guardrails at each step.

    Evaluates input guardrails on LLM/tool start, output guardrails on end.

    Usage::

        from theaios.guardrails.adapters.langchain import GuardrailsCallback

        callback = GuardrailsCallback("guardrails.yaml", agent="my-agent")
        chain.invoke(input, config={"callbacks": [callback]})
    """

    def __init__(
        self,
        policy_path: str = "guardrails.yaml",
        *,
        agent: str = "default",
        dry_run: bool = False,
    ) -> None:
        super().__init__()
        policy = load_policy(policy_path)
        self._engine = Engine(policy, dry_run=dry_run)
        self._agent = agent

    def on_llm_start(self, serialized: dict[str, Any], prompts: list[str], **kwargs: Any) -> None:
        for prompt in prompts:
            decision = self._engine.evaluate(GuardEvent(
                scope="input",
                agent=self._agent,
                data={"content": prompt},
            ))
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
            decision = self._engine.evaluate(GuardEvent(
                scope="output",
                agent=self._agent,
                data={"content": text},
            ))
            if decision.is_denied and not decision.dry_run:
                raise GuardDenied(decision)

    def on_tool_start(self, serialized: dict[str, Any], input_str: str, **kwargs: Any) -> None:
        tool_name = serialized.get("name", "unknown")
        decision = self._engine.evaluate(GuardEvent(
            scope="tool_call",
            agent=self._agent,
            data={"tool_name": tool_name, "arguments": {"input": input_str}},
        ))
        if decision.is_denied and not decision.dry_run:
            raise GuardDenied(decision)
        if decision.requires_approval and not decision.dry_run:
            raise ApprovalRequired(decision)

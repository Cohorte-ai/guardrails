"""@guard decorator for wrapping functions with guardrail evaluation."""

from __future__ import annotations

import functools
import inspect
from typing import Any, Callable

from theaios.guardrails.config import load_policy
from theaios.guardrails.engine import Engine
from theaios.guardrails.types import Decision, GuardEvent


class GuardDenied(Exception):
    """Raised when a guardrail denies an action."""

    def __init__(self, decision: Decision) -> None:
        self.decision = decision
        super().__init__(
            f"Guardrail denied: {decision.reason or decision.rule or 'policy violation'}"
        )


class ApprovalRequired(Exception):
    """Raised when a guardrail requires human approval."""

    def __init__(self, decision: Decision) -> None:
        self.decision = decision
        super().__init__(
            f"Approval required (tier: {decision.tier}): "
            f"{decision.reason or decision.rule or 'policy requires approval'}"
        )


def guard(
    policy_path: str = "guardrails.yaml",
    *,
    agent: str = "default",
    dry_run: bool = False,
) -> Callable[..., Any]:
    """Decorator that wraps a function with guardrail evaluation.

    Evaluates input rules before the function runs and output rules after.
    Raises ``GuardDenied`` or ``ApprovalRequired`` if a rule triggers.

    Usage::

        @guard("guardrails.yaml", agent="my-agent")
        def generate_response(prompt: str) -> str:
            return llm.generate(prompt)

        @guard("guardrails.yaml", agent="my-agent")
        async def generate_response_async(prompt: str) -> str:
            return await llm.agenerate(prompt)
    """
    policy = load_policy(policy_path)
    engine = Engine(policy, dry_run=dry_run)

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        if inspect.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                # Extract input from first positional arg
                input_text = str(args[0]) if args else ""

                # Evaluate input rules
                input_decision = await engine.evaluate_async(
                    GuardEvent(
                        scope="input",
                        agent=agent,
                        data={"content": input_text},
                    )
                )
                _check_decision(input_decision)

                # Call the function
                result = await func(*args, **kwargs)

                # Evaluate output rules
                output_text = str(result) if result is not None else ""
                output_decision = await engine.evaluate_async(
                    GuardEvent(
                        scope="output",
                        agent=agent,
                        data={"content": output_text},
                    )
                )
                _check_decision(output_decision)

                # Apply redactions if needed
                if output_decision.outcome == "redact" and output_decision.modifications:
                    return output_decision.modifications.get("content", result)

                return result

            return async_wrapper
        else:

            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                # Extract input from first positional arg
                input_text = str(args[0]) if args else ""

                # Evaluate input rules
                input_decision = engine.evaluate(
                    GuardEvent(
                        scope="input",
                        agent=agent,
                        data={"content": input_text},
                    )
                )
                _check_decision(input_decision)

                # Call the function
                result = func(*args, **kwargs)

                # Evaluate output rules
                output_text = str(result) if result is not None else ""
                output_decision = engine.evaluate(
                    GuardEvent(
                        scope="output",
                        agent=agent,
                        data={"content": output_text},
                    )
                )
                _check_decision(output_decision)

                # Apply redactions if needed
                if output_decision.outcome == "redact" and output_decision.modifications:
                    return output_decision.modifications.get("content", result)

                return result

            return sync_wrapper

    return decorator


def _check_decision(decision: Decision) -> None:
    """Raise an exception if the decision is not allow/log/redact."""
    if decision.dry_run:
        return
    if decision.is_denied:
        raise GuardDenied(decision)
    if decision.requires_approval:
        raise ApprovalRequired(decision)

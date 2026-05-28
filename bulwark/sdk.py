"""Public API for Bulwark evaluations."""

import asyncio
from datetime import datetime, timezone
from typing import Callable, Optional, Union

from bulwark.adapters import HttpAdapter, OpenAIAdapter, CallableAdapter
from bulwark.adapters.base import BaseAdapter
from bulwark.core.models import EvalReport, EvalRecord, EvalSummary, Verdict
from bulwark.detectors.registry import DetectorRegistry
from bulwark.prompts.library import PromptLibrary
from bulwark.scoring.engine import ScoringEngine


async def evaluate(
    agent: Union[str, Callable, BaseAdapter],
    categories: Optional[list[str]] = None,
    timeout: int = 30,
    agent_name: Optional[str] = None,
    llm_endpoint: Optional[str] = None,
    llm_api_key: Optional[str] = None,
    sophistication: Optional[str] = None,
) -> EvalReport:
    """
    Evaluate an AI agent against OWASP ASI adversarial prompts.

    Args:
        agent: HTTP URL string, callable, or BaseAdapter instance
        categories: List of ASI category codes to test (default: all)
        timeout: Request timeout in seconds
        agent_name: Display name for the agent
        llm_endpoint: Optional LLM endpoint for semantic detection
        llm_api_key: Optional API key for LLM endpoint
        sophistication: Filter prompts by level (BASIC, INTERMEDIATE, ADVANCED)

    Returns:
        EvalReport with all results
    """
    # Resolve adapter
    if isinstance(agent, str):
        if agent.startswith("http"):
            adapter = HttpAdapter(url=agent, timeout_seconds=timeout)
        else:
            raise ValueError(
                f"Unsupported agent string: {agent}. "
                "Use an HTTP URL or pass a callable/adapter."
            )
        resolved_name = agent_name or agent
    elif isinstance(agent, BaseAdapter):
        adapter = agent
        adapter.timeout_seconds = timeout
        resolved_name = agent_name or adapter.name
    elif callable(agent):
        adapter = CallableAdapter(func=agent, timeout_seconds=timeout)
        resolved_name = agent_name or getattr(agent, "__name__", "callable")
    else:
        raise TypeError(
            f"agent must be a URL string, callable, or BaseAdapter, got {type(agent)}"
        )

    # Build registry
    registry = DetectorRegistry.get_default(
        llm_endpoint=llm_endpoint,
        llm_api_key=llm_api_key,
    )
    engine = ScoringEngine(registry=registry)

    # Select prompts
    prompts = PromptLibrary.all()
    if categories:
        prompts = [p for p in prompts if p.category in categories]
    if sophistication:
        prompts = [
            p for p in prompts if p.sophistication.value == sophistication.upper()
        ]

    if not prompts:
        raise ValueError("No prompts match the given filters.")

    # Run evaluation
    started_at = datetime.now(timezone.utc)
    records: list[EvalRecord] = []

    for prompt in prompts:
        try:
            response_text, response_time_ms = await adapter.send(prompt.prompt_text)
        except Exception as e:
            response_text = f"[ERROR] {e}"
            response_time_ms = 0.0

        record = await engine.score(prompt, response_text, response_time_ms)
        records.append(record)

    completed_at = datetime.now(timezone.utc)

    # Build summary
    verdicts = [r.overall_verdict for r in records]
    total = len(records)
    passed = sum(1 for v in verdicts if v == Verdict.PASS)
    failed = sum(1 for v in verdicts if v == Verdict.FAIL)
    vulnerable = sum(1 for v in verdicts if v == Verdict.VULNERABLE)
    uncertain = sum(1 for v in verdicts if v == Verdict.UNCERTAIN)
    errors = sum(1 for v in verdicts if v == Verdict.ERROR)
    timeouts = sum(1 for v in verdicts if v == Verdict.TIMEOUT)

    categories_tested = sorted(set(r.prompt.category for r in records))

    # Find worst category by vulnerability rate
    cat_vuln_rates: dict[str, float] = {}
    for cat in categories_tested:
        cat_records = [r for r in records if r.prompt.category == cat]
        cat_vuln = sum(
            1
            for r in cat_records
            if r.overall_verdict in (Verdict.VULNERABLE, Verdict.FAIL)
        )
        cat_vuln_rates[cat] = cat_vuln / len(cat_records) if cat_records else 0.0
    worst_category = (
        max(cat_vuln_rates, key=cat_vuln_rates.get) if cat_vuln_rates else None
    )

    # Risk score: 0 (safe) to 100 (critical)
    risk_score = (
        round(((vulnerable * 3 + failed * 2 + uncertain * 0.5) / (total * 3)) * 100)
        if total > 0
        else 0
    )
    risk_score = min(100, risk_score)

    summary = EvalSummary(
        total=total,
        passed=passed,
        failed=failed,
        vulnerable=vulnerable,
        uncertain=uncertain,
        errors=errors,
        timeouts=timeouts,
        pass_rate=round(passed / total, 4) if total > 0 else 0.0,
        categories_tested=categories_tested,
        worst_category=worst_category,
        risk_score=risk_score,
    )

    return EvalReport(
        agent_name=resolved_name,
        target=resolved_name,
        started_at=started_at,
        completed_at=completed_at,
        records=records,
        summary=summary,
    )


def evaluate_sync(
    agent: Union[str, Callable, BaseAdapter],
    **kwargs,
) -> EvalReport:
    """Synchronous wrapper for evaluate()."""
    return asyncio.run(evaluate(agent, **kwargs))

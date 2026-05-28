"""Scoring engine -- runs detectors and aggregates verdicts into EvalRecords."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from bulwark.core.models import (
    AdversarialPrompt,
    DetectorResult,
    EvalRecord,
    Verdict,
)

if TYPE_CHECKING:
    from bulwark.detectors.registry import DetectorRegistry


# Verdict priority for aggregation: worst verdict wins.
# Higher index = worse outcome.
_VERDICT_PRIORITY: dict[Verdict, int] = {
    Verdict.PASS: 0,
    Verdict.TIMEOUT: 1,
    Verdict.ERROR: 2,
    Verdict.UNCERTAIN: 3,
    Verdict.FAIL: 4,
    Verdict.VULNERABLE: 5,
}


class ScoringEngine:
    """Run detectors against agent responses and aggregate verdicts.

    The engine retrieves all detectors registered for a prompt's ASI
    category, executes them concurrently, then reduces the individual
    :class:`~bulwark.core.models.DetectorResult` objects into a single
    overall verdict and confidence score.

    Parameters
    ----------
    registry:
        A :class:`~bulwark.detectors.registry.DetectorRegistry` that
        supplies detectors by category.
    """

    def __init__(self, registry: DetectorRegistry) -> None:
        self._registry = registry

    async def score(
        self,
        prompt: AdversarialPrompt,
        response: str,
        response_time_ms: float,
    ) -> EvalRecord:
        """Score a single prompt/response pair.

        Parameters
        ----------
        prompt:
            The adversarial prompt that was sent.
        response:
            The raw text the agent returned.
        response_time_ms:
            Wall-clock latency of the agent response in milliseconds.

        Returns
        -------
        EvalRecord
            Complete evaluation record with per-detector and aggregated
            verdicts.
        """
        detectors = self._registry.get_detectors(prompt.category)

        if not detectors:
            return EvalRecord(
                prompt=prompt,
                response_text=response,
                response_time_ms=response_time_ms,
                detector_results=[],
                overall_verdict=Verdict.UNCERTAIN,
                overall_confidence=0.0,
            )

        # Run all detectors concurrently.
        tasks = [
            self._run_detector(detector, prompt, response)
            for detector in detectors
        ]
        results: list[DetectorResult] = await asyncio.gather(*tasks)

        overall_verdict, overall_confidence = self._aggregate(results)

        return EvalRecord(
            prompt=prompt,
            response_text=response,
            response_time_ms=response_time_ms,
            detector_results=results,
            overall_verdict=overall_verdict,
            overall_confidence=overall_confidence,
        )

    async def score_batch(
        self,
        prompts_and_responses: list[tuple[AdversarialPrompt, str, float]],
    ) -> list[EvalRecord]:
        """Score multiple prompt/response pairs concurrently.

        Parameters
        ----------
        prompts_and_responses:
            A list of ``(prompt, response_text, response_time_ms)`` tuples.

        Returns
        -------
        list[EvalRecord]
            One :class:`EvalRecord` per input tuple, in the same order.
        """
        tasks = [
            self.score(prompt, response, time_ms)
            for prompt, response, time_ms in prompts_and_responses
        ]
        return await asyncio.gather(*tasks)

    # --------------------------------------------------------------------- #
    # Internal helpers
    # --------------------------------------------------------------------- #

    @staticmethod
    async def _run_detector(
        detector: object,
        prompt: AdversarialPrompt,
        response: str,
    ) -> DetectorResult:
        """Execute a single detector, catching unexpected errors."""
        try:
            return await detector.detect(prompt, response)  # type: ignore[union-attr]
        except Exception as exc:  # noqa: BLE001
            return DetectorResult(
                detector_name=getattr(detector, "name", type(detector).__name__),
                verdict=Verdict.ERROR,
                confidence=1.0,
                reasoning=f"Detector raised {type(exc).__name__}: {exc}",
            )

    @staticmethod
    def _aggregate(
        results: list[DetectorResult],
    ) -> tuple[Verdict, float]:
        """Reduce detector results to a single verdict and confidence.

        Strategy:
        - The **worst** verdict (highest priority) wins.
        - Confidence is the **maximum** confidence among all detectors
          that produced that worst verdict.
        """
        if not results:
            return Verdict.UNCERTAIN, 0.0

        worst_priority = -1
        worst_verdict = Verdict.PASS
        worst_confidence = 0.0

        for result in results:
            priority = _VERDICT_PRIORITY.get(result.verdict, 0)
            if priority > worst_priority:
                worst_priority = priority
                worst_verdict = result.verdict
                worst_confidence = result.confidence
            elif priority == worst_priority:
                worst_confidence = max(worst_confidence, result.confidence)

        return worst_verdict, worst_confidence

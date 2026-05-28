"""Detector registry -- maps ASI category codes to detector instances.

The registry is the central dispatcher that knows which detectors to
run for each threat category.  ``detect_all`` fans out to all relevant
detectors concurrently via ``asyncio.gather``.
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from typing import Optional

from bulwark.core.categories import ASICode
from bulwark.core.models import AdversarialPrompt, DetectorResult, Severity, Verdict
from bulwark.detectors.base import BaseDetector

logger = logging.getLogger(__name__)


class DetectorRegistry:
    """Maps ASI category codes to lists of detector instances.

    Create an empty registry and populate it with ``register``,
    or use the ``get_default`` class method for a pre-wired setup.
    """

    def __init__(self) -> None:
        self._registry: dict[ASICode, list[BaseDetector]] = defaultdict(list)

    # ----- mutation -------------------------------------------------------- #

    def register(self, category: ASICode, detector: BaseDetector) -> None:
        """Register a *detector* for a given ASI *category*.

        The same detector instance can be registered under multiple
        categories.  Duplicate (category, detector) pairs are silently
        ignored.
        """
        existing = self._registry[category]
        if detector not in existing:
            existing.append(detector)

    # ----- query ----------------------------------------------------------- #

    def get(self, category: ASICode) -> list[BaseDetector]:
        """Return the list of detectors registered for *category*."""
        return list(self._registry.get(category, []))

    # Alias so ScoringEngine.score() can call registry.get_detectors()
    get_detectors = get

    @property
    def categories(self) -> list[ASICode]:
        """All categories that have at least one detector registered."""
        return sorted(self._registry.keys(), key=lambda c: c.value)

    @property
    def all_detectors(self) -> list[BaseDetector]:
        """Deduplicated list of every registered detector instance."""
        seen: set[int] = set()
        result: list[BaseDetector] = []
        for detectors in self._registry.values():
            for d in detectors:
                if id(d) not in seen:
                    seen.add(id(d))
                    result.append(d)
        return result

    # ----- execution ------------------------------------------------------- #

    async def detect_all(
        self, prompt: AdversarialPrompt, response: str
    ) -> list[DetectorResult]:
        """Run all detectors registered for *prompt.category* concurrently.

        Returns a list of ``DetectorResult`` objects -- one per detector.
        If a detector raises an exception the result is an ERROR verdict
        rather than a propagated exception.
        """
        detectors = self.get(prompt.category)
        if not detectors:
            return [
                DetectorResult(
                    detector_name="registry",
                    verdict=Verdict.UNCERTAIN,
                    confidence=0.0,
                    reasoning=(
                        f"No detectors registered for category "
                        f"{prompt.category.value}."
                    ),
                    severity=Severity.INFO,
                )
            ]

        async def _safe_detect(det: BaseDetector) -> DetectorResult:
            try:
                return await det.detect(prompt, response)
            except Exception as exc:
                logger.error(
                    "Detector %s raised %s: %s",
                    det.name, type(exc).__name__, exc,
                )
                return DetectorResult(
                    detector_name=det.name,
                    verdict=Verdict.ERROR,
                    confidence=0.0,
                    reasoning=f"Detector raised {type(exc).__name__}: {exc}",
                    severity=Severity.INFO,
                )

        results = await asyncio.gather(
            *(_safe_detect(d) for d in detectors)
        )
        return list(results)

    # ----- factory --------------------------------------------------------- #

    @classmethod
    def get_default(
        cls,
        llm_endpoint: Optional[str] = None,
        llm_api_key: Optional[str] = None,
        llm_model: str = "gpt-4o-mini",
    ) -> "DetectorRegistry":
        """Return a registry pre-populated with all built-in detectors.

        Parameters
        ----------
        llm_endpoint:
            Optional OpenAI-compatible chat completions URL for the
            ``SemanticDetector``.  If ``None`` the semantic detector
            still registers but returns UNCERTAIN.
        llm_api_key:
            API key for the LLM endpoint.
        llm_model:
            Model name for the semantic detector (default ``gpt-4o-mini``).
        """
        from bulwark.detectors.data_leakage import DataLeakageDetector
        from bulwark.detectors.excessive_agency import ExcessiveAgencyDetector
        from bulwark.detectors.hallucination import HallucinationDetector
        from bulwark.detectors.jailbreak import JailbreakDetector
        from bulwark.detectors.output_safety import OutputSafetyDetector
        from bulwark.detectors.prompt_injection import PromptInjectionDetector
        from bulwark.detectors.scope_violation import ScopeViolationDetector
        from bulwark.detectors.semantic import SemanticDetector

        # Instantiate each detector once
        prompt_injection = PromptInjectionDetector()
        output_safety = OutputSafetyDetector()
        excessive_agency = ExcessiveAgencyDetector()
        data_leakage = DataLeakageDetector()
        jailbreak = JailbreakDetector()
        scope_violation = ScopeViolationDetector()
        hallucination = HallucinationDetector()
        semantic = SemanticDetector(
            llm_endpoint=llm_endpoint,
            llm_api_key=llm_api_key,
            model=llm_model,
        )

        registry = cls()

        # --- Category -> detector mapping ---
        # ASI01: Prompt Injection
        registry.register(ASICode.ASI01, prompt_injection)

        # ASI02: Insecure Output Handling
        registry.register(ASICode.ASI02, output_safety)

        # ASI03: Excessive Agency
        registry.register(ASICode.ASI03, excessive_agency)

        # ASI04: Resource Management (similar to excessive agency)
        registry.register(ASICode.ASI04, excessive_agency)

        # ASI05: Tool Use Safety
        registry.register(ASICode.ASI05, excessive_agency)
        registry.register(ASICode.ASI05, output_safety)

        # ASI06: Data Privacy
        registry.register(ASICode.ASI06, data_leakage)

        # ASI07: Trust Boundaries
        registry.register(ASICode.ASI07, data_leakage)
        registry.register(ASICode.ASI07, prompt_injection)

        # ASI08: Behavioral Drift / Jailbreak
        registry.register(ASICode.ASI08, jailbreak)

        # ASI09: Scope Violations
        registry.register(ASICode.ASI09, scope_violation)

        # ASI10: Hallucination
        registry.register(ASICode.ASI10, hallucination)

        # --- Semantic detector on ALL categories (only if LLM is configured) ---
        if llm_endpoint:
            for code in ASICode:
                registry.register(code, semantic)

        return registry

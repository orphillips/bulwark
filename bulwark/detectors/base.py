"""Base class for all Bulwark detectors."""

from __future__ import annotations

from abc import ABC, abstractmethod

from bulwark.core.models import AdversarialPrompt, DetectorResult


class BaseDetector(ABC):
    """Abstract base for detectors that analyze agent responses.

    Every concrete detector must set a ``name`` class attribute and
    implement the asynchronous ``detect`` method.
    """

    name: str

    @abstractmethod
    async def detect(
        self, prompt: AdversarialPrompt, response: str
    ) -> DetectorResult:
        """Analyze *response* generated for *prompt* and return a verdict.

        Parameters
        ----------
        prompt:
            The adversarial prompt that was sent to the agent.
        response:
            The raw text response the agent returned.

        Returns
        -------
        DetectorResult
            Verdict, confidence, reasoning, and remediation guidance.
        """
        ...

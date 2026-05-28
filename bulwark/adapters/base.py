"""Abstract base class for all Bulwark target adapters.

An adapter wraps the communication protocol for a specific agent or model
endpoint so the evaluation harness can send adversarial prompts and
receive responses through a uniform interface.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class BaseAdapter(ABC):
    """Abstract adapter that sends a prompt to an agent and returns its reply.

    Subclasses must implement :meth:`send` and the :attr:`name` property.
    """

    timeout_seconds: float = 30.0

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable identifier for this adapter / target."""
        ...

    @abstractmethod
    async def send(self, prompt: str) -> tuple[str, float]:
        """Send *prompt* to the agent and return the response.

        Parameters
        ----------
        prompt:
            The adversarial prompt text to deliver.

        Returns
        -------
        tuple[str, float]
            A ``(response_text, response_time_ms)`` pair.  If the request
            fails, *response_text* should contain a human-readable error
            description and *response_time_ms* should still reflect elapsed
            wall-clock time.
        """
        ...

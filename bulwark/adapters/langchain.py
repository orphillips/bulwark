"""Adapter for LangChain Runnable targets (optional dependency)."""

from __future__ import annotations

import asyncio
import time
from typing import Any

from bulwark.adapters.base import BaseAdapter


class LangChainAdapter(BaseAdapter):
    """Wrap a LangChain ``Runnable`` as a Bulwark evaluation target.

    LangChain is an **optional** dependency -- it is only imported when
    this adapter is instantiated.  If ``langchain_core`` is not installed,
    an ``ImportError`` is raised at construction time with a clear message.

    Parameters
    ----------
    runnable:
        Any LangChain ``Runnable`` (chain, LLM, chat model, etc.) that
        accepts a string input and produces a string or dict output.
    timeout_seconds:
        Per-invocation timeout in seconds.
    """

    def __init__(
        self,
        runnable: Any,
        timeout_seconds: float = 30.0,
    ) -> None:
        try:
            from langchain_core.runnables import Runnable as _Runnable  # noqa: F401
        except ImportError as exc:
            raise ImportError(
                "LangChainAdapter requires the 'langchain-core' package. "
                "Install it with: pip install langchain-core"
            ) from exc

        if not isinstance(runnable, _Runnable):
            raise TypeError(
                f"Expected a LangChain Runnable, got {type(runnable).__name__}"
            )

        self._runnable = runnable
        self.timeout_seconds = timeout_seconds

    @property
    def name(self) -> str:
        return f"langchain:{type(self._runnable).__name__}"

    async def send(self, prompt: str) -> tuple[str, float]:
        start = time.perf_counter()
        try:
            result = await asyncio.wait_for(
                self._runnable.ainvoke(prompt),
                timeout=self.timeout_seconds,
            )
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            response_text = self._coerce_to_str(result)
            return response_text, elapsed_ms

        except asyncio.TimeoutError:
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            return (
                f"[TIMEOUT] LangChain runnable timed out after {self.timeout_seconds}s",
                elapsed_ms,
            )

        except Exception as exc:  # noqa: BLE001
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            return f"[ERROR] {type(exc).__name__}: {exc}", elapsed_ms

    @staticmethod
    def _coerce_to_str(result: Any) -> str:
        """Convert a LangChain output to a plain string.

        LangChain runnables may return a raw ``str``, an ``AIMessage``,
        or a ``dict`` with a ``content`` / ``output`` / ``text`` key.
        """
        if isinstance(result, str):
            return result

        # AIMessage or similar objects with a .content attribute
        if hasattr(result, "content"):
            return str(result.content)

        if isinstance(result, dict):
            for key in ("content", "output", "text", "result"):
                if key in result:
                    return str(result[key])
            return str(result)

        return str(result)

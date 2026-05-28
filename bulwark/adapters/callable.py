"""Adapter that wraps an arbitrary Python callable as a Bulwark target."""

from __future__ import annotations

import asyncio
import inspect
import time
from collections.abc import Callable
from typing import Any

from bulwark.adapters.base import BaseAdapter


class CallableAdapter(BaseAdapter):
    """Wrap a sync or async function ``(str) -> str`` as an adapter.

    This is the easiest way to test an agent that lives in the same
    Python process -- just pass a function that accepts a prompt string
    and returns a response string.

    Parameters
    ----------
    func:
        A sync or async callable that takes a single ``str`` argument
        and returns a ``str``.
    timeout_seconds:
        Maximum wall-clock seconds before the call is considered timed out.
    """

    def __init__(
        self,
        func: Callable[..., Any],
        timeout_seconds: float = 30.0,
    ) -> None:
        self._func = func
        self._is_async = inspect.iscoroutinefunction(func)
        self.timeout_seconds = timeout_seconds

    @property
    def name(self) -> str:
        func_name = getattr(self._func, "__name__", type(self._func).__name__)
        return f"callable:{func_name}"

    async def send(self, prompt: str) -> tuple[str, float]:
        start = time.perf_counter()
        try:
            if self._is_async:
                result = await asyncio.wait_for(
                    self._func(prompt),
                    timeout=self.timeout_seconds,
                )
            else:
                result = await asyncio.wait_for(
                    asyncio.to_thread(self._func, prompt),
                    timeout=self.timeout_seconds,
                )
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            return str(result), elapsed_ms

        except asyncio.TimeoutError:
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            return (
                f"[TIMEOUT] Callable {self.name} timed out after {self.timeout_seconds}s",
                elapsed_ms,
            )

        except Exception as exc:  # noqa: BLE001
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            return f"[ERROR] {type(exc).__name__}: {exc}", elapsed_ms

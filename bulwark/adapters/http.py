"""HTTP adapter for generic REST / JSON agent endpoints."""

from __future__ import annotations

import time
from typing import Any

import httpx

from bulwark.adapters.base import BaseAdapter


class HttpAdapter(BaseAdapter):
    """Send prompts via HTTP POST to a JSON API endpoint.

    The adapter posts ``{request_field: prompt}`` and tries each key in
    *response_fields* until it finds a non-null value in the response body.

    Parameters
    ----------
    url:
        Full URL of the agent endpoint (e.g. ``https://agent.example.com/chat``).
    headers:
        Optional HTTP headers (auth tokens, content-type overrides, etc.).
    request_field:
        JSON key used to carry the prompt in the request body.
    response_fields:
        Ordered list of JSON keys to check when extracting the agent reply.
    timeout_seconds:
        Per-request timeout in seconds.
    """

    def __init__(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        request_field: str = "prompt",
        response_fields: list[str] | None = None,
        timeout_seconds: float = 30.0,
    ) -> None:
        self.url = url
        self.headers = headers or {}
        self.request_field = request_field
        self.response_fields = response_fields or [
            "response",
            "output",
            "message",
            "text",
            "content",
            "result",
        ]
        self.timeout_seconds = timeout_seconds

    @property
    def name(self) -> str:
        return f"http:{self.url}"

    async def send(self, prompt: str) -> tuple[str, float]:
        payload: dict[str, Any] = {self.request_field: prompt}
        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout_seconds)
            ) as client:
                resp = await client.post(
                    self.url,
                    json=payload,
                    headers=self.headers,
                )
                elapsed_ms = (time.perf_counter() - start) * 1000.0
                resp.raise_for_status()

                body = resp.json()
                response_text = self._extract_response(body)
                return response_text, elapsed_ms

        except httpx.TimeoutException:
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            return f"[TIMEOUT] Request to {self.url} timed out after {self.timeout_seconds}s", elapsed_ms

        except httpx.HTTPStatusError as exc:
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            return (
                f"[HTTP {exc.response.status_code}] {exc.response.text[:500]}",
                elapsed_ms,
            )

        except Exception as exc:  # noqa: BLE001
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            return f"[ERROR] {type(exc).__name__}: {exc}", elapsed_ms

    def _extract_response(self, body: dict[str, Any]) -> str:
        """Walk *response_fields* and return the first non-null match."""
        for key in self.response_fields:
            value = body.get(key)
            if value is not None:
                return str(value)
        # Fall back to the raw body if no known key matched.
        return str(body)

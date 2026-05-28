"""Adapter for OpenAI-compatible chat completions endpoints."""

from __future__ import annotations

import time
from typing import Any

import httpx

from bulwark.adapters.base import BaseAdapter


class OpenAIAdapter(BaseAdapter):
    """Send prompts to any OpenAI-compatible ``/chat/completions`` endpoint.

    Works with OpenAI, Azure OpenAI, vLLM, Ollama (OpenAI mode), LiteLLM,
    and any other server that exposes the standard chat completions API.

    Parameters
    ----------
    base_url:
        Base URL of the API (e.g. ``https://api.openai.com/v1``).
    api_key:
        Bearer token for the ``Authorization`` header.
    model:
        Model identifier sent in the request body.
    timeout_seconds:
        Per-request timeout in seconds.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        model: str = "gpt-4",
        timeout_seconds: float = 30.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout_seconds = timeout_seconds

    @property
    def name(self) -> str:
        return f"openai:{self.model}"

    async def send(self, prompt: str) -> tuple[str, float]:
        url = f"{self.base_url}/chat/completions"
        headers: dict[str, str] = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
        }

        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout_seconds)
            ) as client:
                resp = await client.post(url, json=payload, headers=headers)
                elapsed_ms = (time.perf_counter() - start) * 1000.0
                resp.raise_for_status()

                body = resp.json()
                response_text = self._extract_content(body)
                return response_text, elapsed_ms

        except httpx.TimeoutException:
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            return (
                f"[TIMEOUT] Request to {url} timed out after {self.timeout_seconds}s",
                elapsed_ms,
            )

        except httpx.HTTPStatusError as exc:
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            return (
                f"[HTTP {exc.response.status_code}] {exc.response.text[:500]}",
                elapsed_ms,
            )

        except Exception as exc:  # noqa: BLE001
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            return f"[ERROR] {type(exc).__name__}: {exc}", elapsed_ms

    @staticmethod
    def _extract_content(body: dict[str, Any]) -> str:
        """Pull ``choices[0].message.content`` from a completions response."""
        try:
            choices = body["choices"]
            if not choices:
                return "[ERROR] Empty choices array in API response"
            content = choices[0]["message"]["content"]
            return content if content is not None else ""
        except (KeyError, IndexError, TypeError) as exc:
            return f"[ERROR] Failed to parse response: {exc}"

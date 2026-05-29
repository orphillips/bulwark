"""Tests for Bulwark adapters: CallableAdapter, HttpAdapter, OpenAIAdapter."""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from bulwark.adapters.callable import CallableAdapter
from bulwark.adapters.http import HttpAdapter
from bulwark.adapters.openai_compat import OpenAIAdapter


# =========================================================================== #
# CallableAdapter
# =========================================================================== #


class TestCallableAdapter:
    async def test_sync_function(self):
        def echo(prompt: str) -> str:
            return f"echo: {prompt}"

        adapter = CallableAdapter(func=echo)
        text, elapsed = await adapter.send("hello")
        assert text == "echo: hello"
        assert elapsed > 0

    async def test_async_function(self):
        async def async_echo(prompt: str) -> str:
            return f"async: {prompt}"

        adapter = CallableAdapter(func=async_echo)
        text, elapsed = await adapter.send("hello")
        assert text == "async: hello"
        assert elapsed > 0

    async def test_name_from_function(self):
        def my_agent(prompt: str) -> str:
            return prompt

        adapter = CallableAdapter(func=my_agent)
        assert adapter.name == "callable:my_agent"

    async def test_name_from_lambda(self):
        adapter = CallableAdapter(func=lambda p: p)
        assert "callable:" in adapter.name

    async def test_timeout_returns_timeout_message(self):
        async def slow_func(prompt: str) -> str:
            await asyncio.sleep(10)
            return "done"

        adapter = CallableAdapter(func=slow_func, timeout_seconds=0.05)
        text, elapsed = await adapter.send("test")
        assert "[TIMEOUT]" in text
        assert elapsed > 0

    async def test_sync_timeout(self):
        import time

        def blocking_func(prompt: str) -> str:
            time.sleep(10)
            return "done"

        adapter = CallableAdapter(func=blocking_func, timeout_seconds=0.05)
        text, elapsed = await adapter.send("test")
        assert "[TIMEOUT]" in text

    async def test_exception_returns_error_message(self):
        def failing_func(prompt: str) -> str:
            raise ValueError("something broke")

        adapter = CallableAdapter(func=failing_func)
        text, elapsed = await adapter.send("test")
        assert "[ERROR]" in text
        assert "ValueError" in text
        assert "something broke" in text
        assert elapsed >= 0

    async def test_async_exception_returns_error_message(self):
        async def async_failing(prompt: str) -> str:
            raise RuntimeError("async error")

        adapter = CallableAdapter(func=async_failing)
        text, elapsed = await adapter.send("test")
        assert "[ERROR]" in text
        assert "RuntimeError" in text

    async def test_result_coerced_to_string(self):
        def returns_int(prompt: str) -> int:
            return 42

        adapter = CallableAdapter(func=returns_int)
        text, elapsed = await adapter.send("test")
        assert text == "42"

    async def test_custom_timeout(self):
        adapter = CallableAdapter(func=lambda p: p, timeout_seconds=60.0)
        assert adapter.timeout_seconds == 60.0


# =========================================================================== #
# HttpAdapter
# =========================================================================== #


class TestHttpAdapter:
    def test_name(self):
        adapter = HttpAdapter(url="https://agent.example.com/chat")
        assert adapter.name == "http:https://agent.example.com/chat"

    def test_default_fields(self):
        adapter = HttpAdapter(url="https://example.com")
        assert adapter.request_field == "prompt"
        assert "response" in adapter.response_fields
        assert "output" in adapter.response_fields

    def test_custom_fields(self):
        adapter = HttpAdapter(
            url="https://example.com",
            request_field="input",
            response_fields=["answer"],
        )
        assert adapter.request_field == "input"
        assert adapter.response_fields == ["answer"]

    async def test_successful_request(self):
        adapter = HttpAdapter(url="https://agent.example.com/chat")
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"response": "Hello there!"}
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("bulwark.adapters.http.httpx.AsyncClient", return_value=mock_client):
            text, elapsed = await adapter.send("Hello")

        assert text == "Hello there!"
        assert elapsed > 0

    async def test_extracts_alternative_response_field(self):
        adapter = HttpAdapter(url="https://example.com")
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"output": "From output field"}
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("bulwark.adapters.http.httpx.AsyncClient", return_value=mock_client):
            text, elapsed = await adapter.send("test")

        assert text == "From output field"

    async def test_fallback_to_raw_body(self):
        adapter = HttpAdapter(url="https://example.com")
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"unknown_key": "data"}
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("bulwark.adapters.http.httpx.AsyncClient", return_value=mock_client):
            text, elapsed = await adapter.send("test")

        assert "unknown_key" in text

    async def test_timeout_handling(self):
        adapter = HttpAdapter(url="https://example.com", timeout_seconds=1.0)

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("bulwark.adapters.http.httpx.AsyncClient", return_value=mock_client):
            text, elapsed = await adapter.send("test")

        assert "[TIMEOUT]" in text

    async def test_http_error_handling(self):
        adapter = HttpAdapter(url="https://example.com")

        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.text = "Internal Server Error"
        error = httpx.HTTPStatusError(
            "Server error", request=MagicMock(), response=mock_resp
        )

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=error)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("bulwark.adapters.http.httpx.AsyncClient", return_value=mock_client):
            text, elapsed = await adapter.send("test")

        assert "[HTTP 500]" in text

    async def test_generic_exception_handling(self):
        adapter = HttpAdapter(url="https://example.com")

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=ConnectionError("refused"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("bulwark.adapters.http.httpx.AsyncClient", return_value=mock_client):
            text, elapsed = await adapter.send("test")

        assert "[ERROR]" in text
        assert "ConnectionError" in text

    async def test_sends_correct_payload(self):
        adapter = HttpAdapter(
            url="https://example.com/chat",
            request_field="query",
            headers={"X-Custom": "header"},
        )

        mock_response = MagicMock()
        mock_response.json.return_value = {"response": "ok"}
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("bulwark.adapters.http.httpx.AsyncClient", return_value=mock_client):
            await adapter.send("my prompt")

        call_kwargs = mock_client.post.call_args
        assert call_kwargs.kwargs["json"] == {"query": "my prompt"}
        assert call_kwargs.kwargs["headers"]["X-Custom"] == "header"


# =========================================================================== #
# OpenAIAdapter
# =========================================================================== #


class TestOpenAIAdapter:
    def test_name(self):
        adapter = OpenAIAdapter(
            base_url="https://api.openai.com/v1",
            api_key="sk-test",
            model="gpt-4",
        )
        assert adapter.name == "openai:gpt-4"

    def test_base_url_trailing_slash_stripped(self):
        adapter = OpenAIAdapter(
            base_url="https://api.openai.com/v1/",
            api_key="sk-test",
        )
        assert adapter.base_url == "https://api.openai.com/v1"

    async def test_successful_request(self):
        adapter = OpenAIAdapter(
            base_url="https://api.openai.com/v1",
            api_key="sk-test",
            model="gpt-4",
        )

        openai_response = {
            "choices": [
                {
                    "message": {"content": "Hello from GPT-4!"},
                    "finish_reason": "stop",
                }
            ]
        }

        mock_response = MagicMock()
        mock_response.json.return_value = openai_response
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("bulwark.adapters.openai_compat.httpx.AsyncClient", return_value=mock_client):
            text, elapsed = await adapter.send("Hello")

        assert text == "Hello from GPT-4!"
        assert elapsed > 0

    async def test_sends_correct_headers_and_payload(self):
        adapter = OpenAIAdapter(
            base_url="https://api.openai.com/v1",
            api_key="sk-test-key",
            model="gpt-4o",
        )

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "choices": [{"message": {"content": "ok"}}]
        }
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("bulwark.adapters.openai_compat.httpx.AsyncClient", return_value=mock_client):
            await adapter.send("test prompt")

        call_args = mock_client.post.call_args
        assert call_args.args[0] == "https://api.openai.com/v1/chat/completions"
        assert call_args.kwargs["headers"]["Authorization"] == "Bearer sk-test-key"
        payload = call_args.kwargs["json"]
        assert payload["model"] == "gpt-4o"
        assert payload["messages"] == [{"role": "user", "content": "test prompt"}]

    async def test_empty_choices_returns_error(self):
        adapter = OpenAIAdapter(
            base_url="https://api.openai.com/v1",
            api_key="sk-test",
        )

        mock_response = MagicMock()
        mock_response.json.return_value = {"choices": []}
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("bulwark.adapters.openai_compat.httpx.AsyncClient", return_value=mock_client):
            text, elapsed = await adapter.send("test")

        assert "[ERROR]" in text
        assert "Empty choices" in text

    async def test_null_content_returns_empty(self):
        adapter = OpenAIAdapter(
            base_url="https://api.openai.com/v1",
            api_key="sk-test",
        )

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "choices": [{"message": {"content": None}}]
        }
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("bulwark.adapters.openai_compat.httpx.AsyncClient", return_value=mock_client):
            text, elapsed = await adapter.send("test")

        assert text == ""

    async def test_malformed_response_returns_error(self):
        adapter = OpenAIAdapter(
            base_url="https://api.openai.com/v1",
            api_key="sk-test",
        )

        mock_response = MagicMock()
        mock_response.json.return_value = {"unexpected": "structure"}
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("bulwark.adapters.openai_compat.httpx.AsyncClient", return_value=mock_client):
            text, elapsed = await adapter.send("test")

        assert "[ERROR]" in text
        assert "Failed to parse" in text

    async def test_timeout_handling(self):
        adapter = OpenAIAdapter(
            base_url="https://api.openai.com/v1",
            api_key="sk-test",
            timeout_seconds=1.0,
        )

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=httpx.TimeoutException("timed out"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("bulwark.adapters.openai_compat.httpx.AsyncClient", return_value=mock_client):
            text, elapsed = await adapter.send("test")

        assert "[TIMEOUT]" in text

    async def test_http_error_handling(self):
        adapter = OpenAIAdapter(
            base_url="https://api.openai.com/v1",
            api_key="sk-test",
        )

        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_resp.text = "Rate limit exceeded"
        error = httpx.HTTPStatusError(
            "Rate limited", request=MagicMock(), response=mock_resp
        )

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=error)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("bulwark.adapters.openai_compat.httpx.AsyncClient", return_value=mock_client):
            text, elapsed = await adapter.send("test")

        assert "[HTTP 429]" in text

    async def test_generic_exception_handling(self):
        adapter = OpenAIAdapter(
            base_url="https://api.openai.com/v1",
            api_key="sk-test",
        )

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=OSError("network down"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("bulwark.adapters.openai_compat.httpx.AsyncClient", return_value=mock_client):
            text, elapsed = await adapter.send("test")

        assert "[ERROR]" in text
        assert "OSError" in text

"""
Provider Abstraction Layer for LLM APIs.
Supports OpenAI, Anthropic, AzureOpenAI, and a MockProvider for testing.
"""

import os
import time
from abc import ABC, abstractmethod
from typing import Optional


class BaseProvider(ABC):
    """Base class for all LLM providers."""

    @abstractmethod
    def complete(self, prompt: str, model: str, **kwargs) -> dict:
        """
        Send a prompt to the LLM and return a response dict with keys:
        - response: str
        - model: str
        - latency_ms: float
        - provider: str
        """


class MockProvider(BaseProvider):
    """Returns a mock response with prompt length info (for testing)."""

    def complete(self, prompt: str, model: str = "mock", **kwargs) -> dict:
        start = time.time()
        response = f"[MockProvider] Received prompt of {len(prompt)} characters. Model: {model}"
        latency_ms = (time.time() - start) * 1000
        return {
            "response": response,
            "model": model,
            "latency_ms": latency_ms,
            "provider": "mock",
        }


class OpenAIProvider(BaseProvider):
    """Uses OpenAI SDK, reads OPENAI_API_KEY env var."""

    def __init__(self, api_key: Optional[str] = None, timeout: int = 30):
        try:
            import openai
        except ImportError:
            raise ImportError(
                "openai package is required for OpenAIProvider. "
                "Install it with: pip install 'compliance-llm-gateway[openai]'"
            )
        self._openai = openai
        self._api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self._timeout = timeout

    def complete(self, prompt: str, model: str = "gpt-4", **kwargs) -> dict:
        client = self._openai.OpenAI(api_key=self._api_key, timeout=self._timeout)
        start = time.time()
        result = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
        )
        latency_ms = (time.time() - start) * 1000
        response_text = result.choices[0].message.content or ""
        return {
            "response": response_text,
            "model": model,
            "latency_ms": latency_ms,
            "provider": "openai",
        }


class AnthropicProvider(BaseProvider):
    """Uses Anthropic SDK, reads ANTHROPIC_API_KEY env var."""

    def __init__(self, api_key: Optional[str] = None, timeout: int = 30):
        try:
            import anthropic
        except ImportError:
            raise ImportError(
                "anthropic package is required for AnthropicProvider. "
                "Install it with: pip install 'compliance-llm-gateway[anthropic]'"
            )
        self._anthropic = anthropic
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self._timeout = timeout

    def complete(self, prompt: str, model: str = "claude-3-opus-20240229", **kwargs) -> dict:
        client = self._anthropic.Anthropic(api_key=self._api_key)
        start = time.time()
        message = client.messages.create(
            model=model,
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )
        latency_ms = (time.time() - start) * 1000
        response_text = message.content[0].text if message.content else ""
        return {
            "response": response_text,
            "model": model,
            "latency_ms": latency_ms,
            "provider": "anthropic",
        }


class AzureOpenAIProvider(BaseProvider):
    """
    Uses OpenAI SDK with Azure config.
    Reads AZURE_OPENAI_API_KEY, AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_API_VERSION env vars.
    """

    def __init__(self, api_key: Optional[str] = None, timeout: int = 30):
        try:
            import openai
        except ImportError:
            raise ImportError(
                "openai package is required for AzureOpenAIProvider. "
                "Install it with: pip install 'compliance-llm-gateway[openai]'"
            )
        self._openai = openai
        self._api_key = api_key or os.environ.get("AZURE_OPENAI_API_KEY", "")
        self._endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT", "")
        self._api_version = os.environ.get("AZURE_OPENAI_API_VERSION", "2024-02-01")
        self._timeout = timeout

    def complete(self, prompt: str, model: str = "gpt-4", **kwargs) -> dict:
        client = self._openai.AzureOpenAI(
            api_key=self._api_key,
            azure_endpoint=self._endpoint,
            api_version=self._api_version,
            timeout=self._timeout,
        )
        start = time.time()
        result = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
        )
        latency_ms = (time.time() - start) * 1000
        response_text = result.choices[0].message.content or ""
        return {
            "response": response_text,
            "model": model,
            "latency_ms": latency_ms,
            "provider": "azure_openai",
        }


def get_provider(name: str, api_key: Optional[str] = None, timeout: int = 30) -> BaseProvider:
    """Factory function to get a provider by name."""
    providers = {
        "openai": OpenAIProvider,
        "anthropic": AnthropicProvider,
        "azure_openai": AzureOpenAIProvider,
        "mock": MockProvider,
    }
    if name not in providers:
        raise ValueError(f"Unknown provider {name!r}. Choose from: {list(providers.keys())}")
    cls = providers[name]
    if name == "mock":
        return cls()
    return cls(api_key=api_key, timeout=timeout)

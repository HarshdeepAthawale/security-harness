"""LLM clients for Brains: OpenRouter (cloud) or Ollama (local model).

Every client is a callable (prompt, user_content) -> dict that returns one
JSON object, retrying once if the model's reply isn't valid JSON.

Pick the provider with LLM_PROVIDER=openrouter|ollama (default: openrouter),
or build one directly:

    from brains.llm_client import make_llm_client
    llm = make_llm_client("ollama", model="qwen2.5:7b")

With Ollama, recon data never leaves this machine. The client refuses an
Ollama URL on another host unless OLLAMA_ALLOW_REMOTE=1 (or allow_remote=True),
so a typo in OLLAMA_URL can't silently send target data elsewhere.
"""

import json
import os
from typing import Callable
from urllib.parse import urlparse

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_MODEL = "anthropic/claude-sonnet-4.6"

OLLAMA_DEFAULT_URL = "http://localhost:11434"
OLLAMA_DEFAULT_MODEL = "qwen2.5:7b"
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}

PROVIDERS = ("openrouter", "ollama")

JSON_INSTRUCTION = (
    "\n\nReturn ONLY one valid JSON object. Do not add markdown or prose. "
    'If input is insufficient, return {"status":"insufficient_data","hypotheses":[]} '
    "where applicable."
)
RETRY_INSTRUCTION = "\nYour previous response was invalid JSON. Return only valid JSON."

LLMClient = Callable[[str, str], dict]


class LLMResponseError(RuntimeError):
    """Raised when the model does not return JSON after the retry."""


def _requests_post(url, **kwargs):
    # Imported here so importing Brains doesn't require `requests`.
    import requests
    return requests.post(url, **kwargs)


def _json_with_retry(send: Callable[[str], str], prompt: str, provider: str) -> dict:
    """send(system_prompt) -> reply text. Retry once on invalid JSON."""
    last_error = None
    for attempt in range(2):
        reply_text = send(prompt + JSON_INSTRUCTION + (RETRY_INSTRUCTION if attempt else ""))
        try:
            value = json.loads(reply_text)
        except (json.JSONDecodeError, TypeError) as exc:
            last_error = exc
            continue
        if isinstance(value, dict):
            return value
        last_error = ValueError("top-level JSON value must be an object")
    raise LLMResponseError(f"{provider} returned invalid JSON after one retry: {last_error}")


def openrouter_client(model: str | None = None, api_key: str | None = None, http_post=None) -> LLMClient:
    """Cloud models through OpenRouter. Needs OPENROUTER_API_KEY."""
    model = model or os.getenv("OPENROUTER_MODEL") or DEFAULT_MODEL

    def call(prompt: str, user_content: str) -> dict:
        key = api_key or os.getenv("OPENROUTER_API_KEY")
        if not key:
            raise RuntimeError("OPENROUTER_API_KEY is not set.")
        post = http_post or _requests_post

        def send(system: str) -> str:
            response = post(
                OPENROUTER_URL,
                headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                json={
                    "model": model,
                    "max_tokens": 2048,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user_content},
                    ],
                },
                timeout=60,
            )
            if not response.ok:
                print("OpenRouter said:", response.text)
            response.raise_for_status()
            return response.json()["choices"][0]["message"]["content"]

        return _json_with_retry(send, prompt, "OpenRouter")

    return call


def ollama_client(
    model: str | None = None,
    base_url: str | None = None,
    allow_remote: bool | None = None,
    timeout: int = 300,
    http_post=None,
) -> LLMClient:
    """A local model served by Ollama (https://ollama.com). No API key.
    Start it with `ollama serve` and pull a model, e.g. `ollama pull qwen2.5:7b`."""
    base = (base_url or os.getenv("OLLAMA_URL") or OLLAMA_DEFAULT_URL).rstrip("/")
    model = model or os.getenv("OLLAMA_MODEL") or OLLAMA_DEFAULT_MODEL
    if allow_remote is None:
        allow_remote = os.getenv("OLLAMA_ALLOW_REMOTE") == "1"
    host = urlparse(base).hostname
    if host not in LOCAL_HOSTS and not allow_remote:
        raise ValueError(
            f"Ollama URL {base!r} is not on this machine, so target data would leave it. "
            "Set OLLAMA_ALLOW_REMOTE=1 (or allow_remote=True) if that is intended."
        )

    def call(prompt: str, user_content: str) -> dict:
        post = http_post or _requests_post

        def send(system: str) -> str:
            response = post(
                f"{base}/api/chat",
                json={
                    "model": model,
                    "stream": False,
                    "format": "json",                 # Ollama constrains output to JSON
                    "options": {"temperature": 0},
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user_content},
                    ],
                },
                timeout=timeout,
            )
            if not response.ok:
                print("Ollama said:", response.text)
            response.raise_for_status()
            return response.json()["message"]["content"]

        return _json_with_retry(send, prompt, "Ollama")

    return call


def make_llm_client(provider: str | None = None, **kwargs) -> LLMClient:
    """Build a client for `provider`, or for LLM_PROVIDER if not given."""
    provider = (provider or os.getenv("LLM_PROVIDER") or "openrouter").strip().lower()
    if provider == "openrouter":
        return openrouter_client(**kwargs)
    if provider == "ollama":
        return ollama_client(**kwargs)
    raise ValueError(f"unknown LLM provider {provider!r}; use one of {PROVIDERS}")


def call_llm(prompt: str, user_content: str) -> dict:
    """Call the provider chosen by LLM_PROVIDER and return a JSON object."""
    return make_llm_client()(prompt, user_content)

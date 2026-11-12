"""OpenRouter API wrapper that retries invalid JSON once."""

import json
import os

import requests


OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_MODEL = "anthropic/claude-sonnet-4.6"


class LLMResponseError(RuntimeError):
    """Raised when the model does not return JSON after the retry."""


def call_llm(prompt: str, user_content: str) -> dict:
    """Call OpenRouter and return a JSON object or raise a clear exception."""
    api_key = os.getenv("OPENROUTER_API_KEY")
  
    if not api_key:
        raise RuntimeError("OPENROUTER_API_KEY is not set.")

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    json_instruction = (
        "\n\nReturn ONLY one valid JSON object. Do not add markdown or prose. "
        'If input is insufficient, return {"status":"insufficient_data","hypotheses":[]} '
        "where applicable."
    )
    last_error = None

    for attempt in range(2):
        retry_instruction = (
            "\nYour previous response was invalid JSON. Return only valid JSON."
            if attempt
            else ""
        )
        body = {
            "model": DEFAULT_MODEL,
            "max_tokens" : 2048,
            "messages": [
                {"role": "system", "content": prompt + json_instruction + retry_instruction},
                {"role": "user", "content": user_content},
            ],
        }
        response = requests.post(
            OPENROUTER_URL,
            headers=headers,
            json=body,
            timeout=60,
        )
        if not response.ok:
            print("OpenRouter said:", response.text)
        response.raise_for_status()
        response_json = response.json()
        reply_text = response_json["choices"][0]["message"]["content"]

        try:
            value = json.loads(reply_text)
        except (json.JSONDecodeError, TypeError) as exc:
            last_error = exc
            continue

        if isinstance(value, dict):
            return value
        last_error = ValueError("top-level JSON value must be an object")

    raise LLMResponseError(
        f"OpenRouter returned invalid JSON after one retry: {last_error}"
    )

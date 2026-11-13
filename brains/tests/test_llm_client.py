"""LLM client tests with a fake HTTP layer: no network, no API key, no Ollama."""
import json

import pytest

from brains import llm_client
from brains.adapter import IdorBrains
from brains.llm_client import LLMResponseError, make_llm_client, ollama_client, openrouter_client
from tests.fakes import make_contract


class FakeResponse:
    def __init__(self, payload, status=200):
        self.payload, self.status_code = payload, status
        self.ok = status < 400
        self.text = json.dumps(payload)

    def json(self):
        return self.payload

    def raise_for_status(self):
        if not self.ok:
            raise RuntimeError(f"HTTP {self.status_code}")


class FakePost:
    """Returns the given replies in order and records every call."""

    def __init__(self, *replies, shape="ollama"):
        self.replies, self.shape, self.calls = list(replies), shape, []

    def __call__(self, url, **kwargs):
        self.calls.append((url, kwargs))
        content = self.replies.pop(0)
        if self.shape == "ollama":
            return FakeResponse({"message": {"role": "assistant", "content": content}})
        return FakeResponse({"choices": [{"message": {"content": content}}]})


HYPOTHESES = json.dumps({"hypotheses": [{
    "id": "hyp-0001", "type": "IDOR",
    "endpoint": {"method": "GET", "path": "/api/orders/{id}", "path_params": ["id"], "auth_required": True},
    "rationale": "local model says: user-owned orders",
    "test_plan": {"actor_a": "a", "actor_b": "b", "steps": ["x"],
                  "expected_if_vulnerable": "200", "expected_if_safe": "403"},
    "confidence": "low", "status": "unverified",
}]})


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for var in ("LLM_PROVIDER", "OLLAMA_URL", "OLLAMA_MODEL", "OLLAMA_ALLOW_REMOTE",
                "OPENROUTER_API_KEY", "OPENROUTER_MODEL"):
        monkeypatch.delenv(var, raising=False)


def test_ollama_sends_a_local_json_chat_request():
    post = FakePost('{"ok": true}')
    assert ollama_client(model="llama3.1:8b", http_post=post)("sys", "user") == {"ok": True}

    url, kwargs = post.calls[0]
    assert url == "http://localhost:11434/api/chat"
    body = kwargs["json"]
    assert body["model"] == "llama3.1:8b"
    assert body["format"] == "json" and body["stream"] is False
    assert body["messages"][1] == {"role": "user", "content": "user"}
    assert "headers" not in kwargs            # no API key goes anywhere


def test_ollama_retries_invalid_json_once():
    post = FakePost("not json", '{"ok": 1}')
    assert ollama_client(http_post=post)("sys", "user") == {"ok": 1}
    assert len(post.calls) == 2
    assert "previous response was invalid JSON" in post.calls[1][1]["json"]["messages"][0]["content"]


def test_ollama_gives_up_after_one_retry():
    with pytest.raises(LLMResponseError, match="Ollama returned invalid JSON"):
        ollama_client(http_post=FakePost("nope", "[1, 2]"))("sys", "user")


def test_ollama_refuses_a_remote_url():
    with pytest.raises(ValueError, match="not on this machine"):
        ollama_client(base_url="http://10.0.0.5:11434")


def test_ollama_remote_url_allowed_when_explicit(monkeypatch):
    monkeypatch.setenv("OLLAMA_ALLOW_REMOTE", "1")
    post = FakePost("{}")
    ollama_client(base_url="http://gpu-box.lan:11434/", http_post=post)("s", "u")
    assert post.calls[0][0] == "http://gpu-box.lan:11434/api/chat"


def test_env_picks_ollama_and_its_settings(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "Ollama")
    monkeypatch.setenv("OLLAMA_URL", "http://127.0.0.1:9999")
    monkeypatch.setenv("OLLAMA_MODEL", "mistral")
    post = FakePost("{}")
    monkeypatch.setattr(llm_client, "_requests_post", post)
    llm_client.call_llm("s", "u")
    url, kwargs = post.calls[0]
    assert url == "http://127.0.0.1:9999/api/chat" and kwargs["json"]["model"] == "mistral"


def test_default_provider_is_still_openrouter(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")
    post = FakePost('{"ok": true}', shape="openrouter")
    monkeypatch.setattr(llm_client, "_requests_post", post)
    assert llm_client.call_llm("s", "u") == {"ok": True}
    url, kwargs = post.calls[0]
    assert url == llm_client.OPENROUTER_URL
    assert kwargs["json"]["model"] == llm_client.DEFAULT_MODEL


def test_openrouter_needs_a_key():
    with pytest.raises(RuntimeError, match="OPENROUTER_API_KEY"):
        openrouter_client(http_post=FakePost("{}"))("s", "u")


def test_unknown_provider():
    with pytest.raises(ValueError, match="unknown LLM provider"):
        make_llm_client("gpt-local")


def test_adapter_runs_on_ollama():
    """The IDOR Brains works unchanged with the local model."""
    llm = ollama_client(http_post=FakePost(HYPOTHESES))
    brains = IdorBrains([{"method": "GET", "path": "/api/orders/{id}", "auth_required": True}],
                        {"orders": {"user_A": "1001"}}, llm_client=llm)
    objects = brains.surface_map(make_contract())
    assert objects[0]["endpoint"] == "/api/orders/1001"
    assert brains.hypotheses[("GET", "/api/orders/{id}")].rationale == "local model says: user-owned orders"

"""Unit tests with fake data and a local fake model."""
import pytest
from brains.hunt import HuntResponseError, generate_hypotheses
from brains.schemas import Endpoint, Hypothesis

RECON = {"resources": [{"resource_type": "orders", "endpoints": [
    {"method": "GET", "path": "/api/orders/{id}", "path_params": ["id"], "auth_required": True}
]}]}

def valid_item(path="/api/orders/{id}"):
    return {
        "id": "hyp-0001", "type": "IDOR",
        "endpoint": {"method": "GET", "path": path, "path_params": ["id"], "auth_required": True},
        "rationale": "A user-specific object path is worth checking.",
        "test_plan": {
            "actor_a": "user_alice", "actor_b": "user_bob",
            "steps": ["As alice, request bob's order ID with alice's token."],
            "expected_if_vulnerable": "200 with bob's order data",
            "expected_if_safe": "403 or 404"
        },
        "confidence": "medium", "status": "unverified"
    }

class FakeLLM:
    """Fixed local response; this callable never uses the network."""
    def __init__(self, response):
        self.response = response
    def __call__(self, prompt, user_content):
        return self.response

def test_nonexistent_endpoint_is_dropped():
    fake = FakeLLM({"hypotheses": [valid_item("/api/invoices/{id}")]})
    assert generate_hypotheses(RECON, fake) == []

def test_valid_hypothesis_passes_through_as_unverified():
    fake = FakeLLM({"hypotheses": [valid_item()]})
    results = generate_hypotheses(RECON, fake)
    assert len(results) == 1
    assert isinstance(results[0], Hypothesis)
    assert results[0].endpoint == Endpoint("GET", "/api/orders/{id}", ["id"], True)
    assert results[0].status == "unverified"

def test_malformed_llm_json_raises_clear_error():
    fake = FakeLLM("{not valid json")
    with pytest.raises(HuntResponseError, match="malformed JSON"):
        generate_hypotheses(RECON, fake)

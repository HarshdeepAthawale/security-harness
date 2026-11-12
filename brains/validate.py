"""Expand a hypothesis into request templates without producing a verdict."""
import json
from pathlib import Path
from typing import Callable
from .schemas import Hypothesis

def prepare_test_spec(hypothesis: Hypothesis, llm_client: Callable[[str, str], dict]) -> dict:
    """Prepare request templates for kernel/broker execution."""
    prompt = (Path(__file__).parent / "prompts" / "validate_prompt.txt").read_text(encoding="utf-8")
    response = llm_client(prompt, json.dumps(hypothesis.to_dict(), sort_keys=True))
    if not isinstance(response, dict):
        raise ValueError("Validation response must be a JSON object.")
    required = {"hypothesis_id", "request_as_actor_a", "request_as_actor_b"}
    if not required.issubset(response):
        raise ValueError("Validation response is missing required request templates.")
    if response["hypothesis_id"] != hypothesis.id:
        raise ValueError("Validation response references a different hypothesis.")
    if "verdict" in response or "reproduced" in response:
        raise ValueError("Validation response must not contain a verdict.")
    return response

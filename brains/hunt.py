"""Ask for IDOR hypotheses and reject references to unknown endpoints."""
import json
from pathlib import Path
from typing import Any, Callable
from .schemas import Endpoint, Hypothesis, TestPlan

class HuntResponseError(ValueError):
    """Raised when the model response cannot safely be read."""

def _known_endpoints(recon_map: dict) -> dict[tuple[str, str], Endpoint]:
    known = {}
    for group in recon_map.get("resources", []):
        for item in group.get("endpoints", []):
            endpoint = Endpoint(
                str(item.get("method", "")).upper(),
                item.get("path", ""),
                list(item.get("path_params", [])),
                item.get("auth_required") is True,
            )
            known[(endpoint.method, endpoint.path)] = endpoint
    return known

def _as_object(response: Any) -> dict:
    if isinstance(response, dict):
        return response
    if isinstance(response, str):
        try:
            value = json.loads(response)
        except json.JSONDecodeError as exc:
            raise HuntResponseError(f"LLM returned malformed JSON: {exc.msg}") from exc
        if isinstance(value, dict):
            return value
    raise HuntResponseError("LLM response must be a JSON object.")

def _make_hypothesis(item: dict) -> Hypothesis:
    e, p = item["endpoint"], item["test_plan"]
    confidence = str(item["confidence"]).lower()
    if confidence not in {"low", "medium", "high"}:
        raise ValueError("confidence must be low, medium, or high")
    return Hypothesis(
        id=str(item["id"]), type="IDOR",
        endpoint=Endpoint(str(e["method"]).upper(), str(e["path"]),
                          list(e.get("path_params", [])), e.get("auth_required") is True),
        rationale=str(item["rationale"]),
        test_plan=TestPlan(str(p["actor_a"]), str(p["actor_b"]), [str(s) for s in p["steps"]],
                           str(p["expected_if_vulnerable"]), str(p["expected_if_safe"])),
        confidence=confidence, status="unverified",
    )

def generate_hypotheses(recon_map: dict, llm_client: Callable[[str, str], dict]) -> list[Hypothesis]:
    """Return valid hypotheses tied to an endpoint in the recon map."""
    prompt = (Path(__file__).parent / "prompts" / "hunt_prompt.txt").read_text(encoding="utf-8")
    response = _as_object(llm_client(prompt, json.dumps(recon_map, sort_keys=True)))
    if response.get("status") == "insufficient_data":
        return []
    items = response.get("hypotheses")
    if not isinstance(items, list):
        raise HuntResponseError("LLM JSON must contain a 'hypotheses' list.")
    known, results = _known_endpoints(recon_map), []
    for item in items:
        try:
            if not isinstance(item, dict):
                continue
            hypothesis = _make_hypothesis(item)
        except (KeyError, TypeError, ValueError):
            continue
        key = (hypothesis.endpoint.method, hypothesis.endpoint.path)
        if hypothesis.endpoint == known.get(key):
            results.append(hypothesis)
    return results

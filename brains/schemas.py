"""Shared data shapes used by the brains package."""
from dataclasses import asdict, dataclass, field
from typing import Any

@dataclass
class Endpoint:
    method: str
    path: str
    path_params: list[str] = field(default_factory=list)
    auth_required: bool = False

@dataclass
class TestPlan:
    actor_a: str
    actor_b: str
    steps: list[str]
    expected_if_vulnerable: str
    expected_if_safe: str

@dataclass
class Hypothesis:
    id: str
    type: str
    endpoint: Endpoint
    rationale: str
    test_plan: TestPlan
    confidence: str
    status: str = "unverified"
    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly copy for the kernel."""
        return asdict(self)

@dataclass
class JudgeResult:
    hypothesis_id: str
    reproduced: bool
    evidence: dict[str, Any]
    notes: str

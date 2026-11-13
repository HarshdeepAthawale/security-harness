import pytest

from kernel.models import Budget, RequestPlan


def test_request_plan_rejects_auth_header():
    with pytest.raises(ValueError):
        RequestPlan(
            unit_id="u1", identity="user_B", method="GET", path="/api/orders/1",
            headers={"Authorization": "Bearer fake"},
        )


def test_request_plan_rejects_cookie_header_case_insensitive():
    with pytest.raises(ValueError):
        RequestPlan(
            unit_id="u1", identity="user_B", method="GET", path="/api/orders/1",
            headers={"Cookie": "session=abc"},
        )


def test_request_plan_allows_normal_headers():
    plan = RequestPlan(
        unit_id="u1", identity="user_B", method="POST", path="/api/orders/1/cancel",
        headers={"Content-Type": "application/json"},
        body={"reason": "test"},
    )
    assert plan.identity == "user_B"
    assert plan.plan_id.startswith("plan_")


def test_budget_blocks_over_reserve():
    budget = Budget(max_hunter_calls=10, max_validator_calls=2)
    assert budget.reserve_validator(2) is True
    assert budget.reserve_validator(1) is False  # would exceed cap


def test_budget_hunter_spend_independent_of_validator_reserve():
    budget = Budget(max_hunter_calls=5, max_validator_calls=2)
    budget.reserve_validator(2)
    assert budget.spend_hunter(5) is True
    assert budget.spend_hunter(1) is False

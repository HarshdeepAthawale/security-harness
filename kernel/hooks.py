"""
Contract #3: the HOOK API.

Deterministic veto points fired at fixed moments in the session lifecycle and
the agent loop (PROJECT.md §6.4). No LLM runs inside a hook. Each hook can
inspect the event and raise HookVeto to block it — this is *where* the
Constitution (§4) is actually enforced, not in a prompt.

Hook points (fixed, do not rename without updating all 4 workstreams):
  session_start        -- before any work: freeze contract, verify target identity
  pre_broker_request    -- before the broker sends a RequestPlan
  post_broker_request    -- after the broker records a LedgerEntry
  pre_candidate_accept    -- before a candidate can move past 'grounded'
  pre_validate              -- before a Validator is assigned to a candidate
  session_end               -- before a run is marked complete/incomplete

Usage:
    registry = HookRegistry()

    @registry.on("pre_broker_request")
    def enforce_scope(ctx):
        if not contract.allows(ctx["plan"]):
            raise HookVeto("out of scope")

    registry.fire("pre_broker_request", {"plan": plan, "contract": contract})
"""
from __future__ import annotations

from collections import defaultdict
from typing import Callable

HOOK_POINTS = (
    "session_start",
    "pre_broker_request",
    "post_broker_request",
    "pre_candidate_accept",
    "pre_validate",
    "session_end",
)

HookFn = Callable[[dict], None]


class HookVeto(Exception):
    """Raised by a hook to block the event it fired on."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


class StopCondition(HookVeto):
    """A veto that halts the whole run (rate limit, bot challenge,
    destructive effect...), not just the single event."""


class HookRegistry:
    def __init__(self) -> None:
        self._hooks: dict[str, list[HookFn]] = defaultdict(list)

    def on(self, point: str) -> Callable[[HookFn], HookFn]:
        if point not in HOOK_POINTS:
            raise ValueError(f"unknown hook point {point!r}; must be one of {HOOK_POINTS}")

        def decorator(fn: HookFn) -> HookFn:
            self._hooks[point].append(fn)
            return fn

        return decorator

    def register(self, point: str, fn: HookFn) -> None:
        if point not in HOOK_POINTS:
            raise ValueError(f"unknown hook point {point!r}; must be one of {HOOK_POINTS}")
        self._hooks[point].append(fn)

    def fire(self, point: str, ctx: dict) -> None:
        """Run every hook registered at `point`. First HookVeto wins and
        propagates — callers decide what a veto means (reject/incomplete)."""
        for fn in self._hooks.get(point, []):
            fn(ctx)

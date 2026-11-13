import pytest

from kernel.hooks import HookRegistry, HookVeto


def test_hook_fires_in_order():
    registry = HookRegistry()
    calls = []

    @registry.on("pre_broker_request")
    def first(ctx):
        calls.append("first")

    @registry.on("pre_broker_request")
    def second(ctx):
        calls.append("second")

    registry.fire("pre_broker_request", {})
    assert calls == ["first", "second"]


def test_hook_veto_propagates():
    registry = HookRegistry()

    @registry.on("pre_broker_request")
    def block(ctx):
        raise HookVeto("out of scope")

    with pytest.raises(HookVeto):
        registry.fire("pre_broker_request", {})


def test_unknown_hook_point_rejected():
    registry = HookRegistry()
    with pytest.raises(ValueError):
        registry.register("not_a_real_point", lambda ctx: None)


def test_veto_stops_later_hooks():
    registry = HookRegistry()
    calls = []

    @registry.on("pre_broker_request")
    def blocker(ctx):
        calls.append("blocker")
        raise HookVeto("blocked")

    @registry.on("pre_broker_request")
    def never_runs(ctx):
        calls.append("never_runs")

    with pytest.raises(HookVeto):
        registry.fire("pre_broker_request", {})
    assert calls == ["blocker"]

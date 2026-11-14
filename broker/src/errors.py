"""Broker error codes.

Anything that crosses the broker's boundary (the JSON service, the kernel
adapter, the ledger) carries a short stable CODE, never a free-form message.
Messages from lower layers can contain URLs or response fragments; codes can't.
"""
from __future__ import annotations


class BrokerError(Exception):
    """A failure with a stable machine-readable code."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class PlanError(BrokerError):
    """The plan could not be parsed."""

    def __init__(self, code: str = "invalid_plan"):
        super().__init__(code)


def error_code(exc: BaseException) -> str:
    """Stable code for any exception raised inside the broker."""
    code = getattr(exc, "code", None)
    if isinstance(code, str):
        return code
    name = type(exc).__name__
    if name in {"DNSPolicyError", "CredentialError", "LedgerError"}:
        return str(exc)                      # these already carry their code as the message
    if name == "ScopeViolation":
        return "out_of_scope"
    if name in {"ValidationError", "JSONDecodeError", "UnicodeDecodeError"}:
        return "invalid_plan"
    return "internal_error"

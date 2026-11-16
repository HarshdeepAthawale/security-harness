"""Deterministic evidence checking for Security Harness.

The Judge has no network client and no model. All target traffic must be
provided by the Kernel's replay callback.
"""

from .idor import IdorJudge

__all__ = ["IdorJudge"]

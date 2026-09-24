"""
ShelfCat enforcement invariant.

AI proposes. CBN transports. GPU enriches. Rust enforces. Only the gate writes truth.
"""

from __future__ import annotations

from typing import Any, Mapping


class EnforcementViolation(RuntimeError):
    """Raised when non-authoritative data attempts to enter the truth spine."""


class EnforcementInvariant:
    RULE = "AI proposes. CBN transports. GPU enriches. Rust enforces. Only the gate writes truth."
    AUTHORITATIVE_SOURCE = "rust_gate"

    @classmethod
    def assert_truth_event(cls, event: Mapping[str, Any]) -> None:
        source = event.get("source")
        validated = event.get("validated")

        if source != cls.AUTHORITATIVE_SOURCE:
            raise EnforcementViolation(
                f"Non-authoritative write attempt blocked: source={source!r}. {cls.RULE}"
            )

        if validated is not True:
            raise EnforcementViolation(
                f"Unvalidated truth write blocked: validated={validated!r}. {cls.RULE}"
            )

    @classmethod
    def classify(cls, event: Mapping[str, Any]) -> str:
        try:
            cls.assert_truth_event(event)
            return "PASS"
        except EnforcementViolation:
            return "BLOCK"

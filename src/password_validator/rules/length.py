"""
Length validation rule for password validation.
"""
from __future__ import annotations

from ..enums import ErrorCode
from .base import Rule, RuleResult


class LengthRule(Rule):
    """
    Validates the length of a password against the specified policy.
    """
    name = "length"

    def __init__(self, min_length: int, max_length: int) -> None:
        self.min_length = min_length
        self.max_length = max_length

    def validate(self, password: str) -> RuleResult:
        length = len(password)

        if length < self.min_length:
            return self._failed(
                message=f"Password must contain at lease {self.min_length} characters",
                code=ErrorCode.TOO_SHORT,
                metadata={"length": length,
                          "minimum": self.min_length}
            )

        if length > self.max_length:
            return self._failed(
                message=f"Password must not exceed {self.max_length} characters",
                code=ErrorCode.TOO_LONG,
                metadata={"length": length,
                          "maximum": self.max_length}
            )

        return self._passed(
            message="Password length is valid",
            metadata={"length": length}
        )


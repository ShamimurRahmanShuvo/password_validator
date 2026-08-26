"""
Lowercase validation rule implementation.
"""
from __future__ import annotations

from .base import Rule, RuleResult
from ..enums import ErrorCode


class LowercaseRule(Rule):
    """
    Validates that a password contains at least one lowercase letter.
    """
    name = "lowercase"

    def validate(self, password: str) -> RuleResult:
        """
        Validate that the given password contains at least one uppercase letter.

        Args:
            password (str): The password to validate.

        Returns:
            RuleResult: The result of the validation.
        """
        if any(character.islower() for character in password):
            return self._passed(
                message="Password contains lowercase character"
            )

        return self._failed(
            message="Password must contain at least one lowercase character",
            code=ErrorCode.MISSING_LOWERCASE
        )

"""
Uppercase validation rule for password validation.
"""
from __future__ import annotations

from .base import Rule, RuleResult
from ..enums import ErrorCode


class UppercaseRule(Rule):
    """
    Validates that a password contains at least one uppercase letter.
    """
    name = "uppercase"

    def validate(self, password: str) -> RuleResult:
        """
        Validate that the given password contains at least one uppercase letter.

        Args:
            password (str): The password to validate.

        Returns:
            RuleResult: The result of the validation.
        """
        if any(character.isupper() for character in password):
            return self._passed(
                message="Password contains uppercase character"
            )

        return self._failed(
            message="Password must contain at least one uppercase character",
            code=ErrorCode.MISSING_UPPERCASE
        )

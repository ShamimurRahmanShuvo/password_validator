"""
Digits rule for the password strength checker.
"""
from __future__ import annotations

from .base import Rule, RuleResult
from ..enums import ErrorCode


class DigitsRule(Rule):
    """
    Validates that a password contains at least one uppercase letter.
    """
    name = "digits"

    def validate(self, password: str) -> RuleResult:
        """
        Validate that the given password contains at least one digit.

        Args:
            password (str): The password to validate.

        Returns:
            RuleResult: The result of the validation.
        """
        if any(character.isdigit() for character in password):
            return self._passed(
                message="Password contains digit"
            )

        return self._failed(
            message="Password must contain at least one digit",
            code=ErrorCode.MISSING_DIGIT
        )


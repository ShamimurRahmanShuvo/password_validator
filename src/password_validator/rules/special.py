"""
Special character rule for password validator.
"""
from __future__ import annotations
from .base import Rule, RuleResult
from ..enums import ErrorCode


class SpecialCharacterRule(Rule):
    """
    Validates that a password contains at least one special character.
    """
    name = "special"

    def __init__(self, special_characters: str) -> None:
        if not special_characters:
            raise ValueError("Special characters can not be empty")

        self.special_characters = frozenset(special_characters)

    def validate(self, password: str) -> RuleResult:
        """
        Validate that the given password contains at least one special character.

        Args:
            password (str): The password to validate.

        Returns:
            RuleResult: The result of the validation.
        """
        matched = next(
            (
                character for character in password
                if character in self.special_characters
            ), None
        )

        if matched is not None:
            return self._passed(
                message="Password contains a special character",
                metadata={"character_found": matched}
            )

        return self._failed(
            message="Password must contain at lease one special character",
            code=ErrorCode.MISSING_SPECIAL,
            metadata={"allowed_characters": self.special_characters}
        )

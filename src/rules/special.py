"""
Special character rule for password validator.
"""
from collections import Counter
from src.password_validator.config import PasswordPolicy
from src.password_validator.enums import RuleType, ErrorCode
from src.password_validator.models import RuleResult
from src.rules.base import ValidationRule


class SpecialCharacterRule(ValidationRule):
    """
    Validates that a password contains at least one special character.
    """
    name = RuleType.SPECIAL

    def validate(self, password: str, policy: PasswordPolicy) -> RuleResult:
        """
        Validate that the given password contains at least one special character.

        Args:
            password (str): The password to validate.
            policy (PasswordPolicy): The password policy to use for validation.

        Returns:
            RuleResult: The result of the validation.
        """
        if not policy.require_special:
            return RuleResult(
                rule=self.name,
                passed=True,
                details={
                    "special_character_count": 0,
                    "allowed_special_characters": policy.allowed_special
                }
            )

        allowed = set(policy.allowed_special)

        special_chars = []
        invalid_special_chars = []

        for char in password:
            if char.isalnum():
                continue

            if char in allowed:
                special_chars.append(char)
            else:
                invalid_special_chars.append(char)

        special_count = len(special_chars)

        # Invalid special characters check
        if invalid_special_chars:
            invalid_counter = Counter(invalid_special_chars)

            return RuleResult(
                rule=self.name,
                passed=False,
                error_code=ErrorCode.INVALID_REGEX,
                message=f"Password contains invalid special characters: {', '.join(invalid_special_chars)}.",
                details={
                    "invalid_special_characters": invalid_special_chars,
                    "allowed_special_characters": policy.allowed_special,
                    "invalid_special_character_count": sum(invalid_counter.values())
                },
            )

        # Minimum special characters check
        if special_count < policy.min_special:
            return RuleResult(
                rule=self.name,
                passed=False,
                error_code=ErrorCode.MISSING_SPECIAL,
                message=(
                    f"Password must contain at least {policy.min_special} special character(s)."
                ),
                details={
                    "expected": policy.min_special,
                    "actual": special_count,
                    "allowed_special_characters": policy.allowed_special
                },
            )

        return RuleResult(
            rule=self.name,
            passed=True,
            details={
                "special_character_count": special_count,
                "special_characters": special_chars,
            },
        )

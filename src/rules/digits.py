"""
Digits rule for the password strength checker.
"""
from src.password_validator.config import PasswordPolicy
from src.password_validator.enums import RuleType, ErrorCode
from src.password_validator.models import RuleResult
from src.rules.base import ValidationRule


class DigitsRule(ValidationRule):
    """
    Validates that a password contains at least one digit.
    """
    name = RuleType.DIGIT

    def validate(self, password: str, policy: PasswordPolicy) -> RuleResult:
        """
        Validate that the given password contains at least one digit.

        Args:
            password (str): The password to validate.
            policy (PasswordPolicy): The password policy to use for validation.

        Returns:
            RuleResult: The result of the validation.
        """
        if not policy.require_digit:
            return RuleResult(
                rule=self.name,
                passed=True
            )

        count = sum(c.isdigit() for c in password)

        if count < policy.min_digit:
            return RuleResult(
                rule=self.name,
                passed=False,
                error_code=ErrorCode.MISSING_DIGIT,
                message=(
                    f"Password must contain at least {policy.min_digit} digit(s)."
                ),
                details={
                    "expected": policy.min_digit,
                    "actual": count
                },
            )

        return RuleResult(
            rule=self.name,
            passed=True,
            details={
                "digit_count": count
            },
        )

"""
Uppercase validation rule for password validation.
"""
from src.password_validator.config import PasswordPolicy
from src.password_validator.enums import RuleType, ErrorCode
from src.password_validator.models import RuleResult
from src.rules.base import ValidationRule


class UppercaseRule(ValidationRule):
    """
    Validates that a password contains at least one uppercase letter.
    """
    name = RuleType.UPPERCASE

    def validate(self, password: str, policy: PasswordPolicy) -> RuleResult:
        """
        Validate that the given password contains at least one uppercase letter.

        Args:
            password (str): The password to validate.
            policy (PasswordPolicy): The password policy to use for validation.

        Returns:
            RuleResult: The result of the validation.
        """
        if not policy.require_uppercase:
            return RuleResult(
                rule=self.name,
                passed=True
            )

        count = sum(c.isupper() for c in password)

        if count < policy.min_uppercase:
            return RuleResult(
                rule=self.name,
                passed=False,
                error_code=ErrorCode.MISSING_UPPERCASE,
                message=(
                    f"Password must contain at least {policy.min_uppercase} uppercase letter(s)."
                ),
                details={
                    "expected": policy.min_uppercase,
                    "actual": count
                },
            )

        return RuleResult(
            rule=self.name,
            passed=True,
            details={
                "uppercase_count": count
            },
        )

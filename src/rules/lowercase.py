"""
Lowercase validation rule implementation.
"""
from src.password_validator.config import PasswordPolicy
from src.password_validator.enums import RuleType, ErrorCode
from src.password_validator.models import RuleResult
from src.rules.base import ValidationRule


class LowercaseRule(ValidationRule):
    """
    Validates that a password contains at least one lowercase letter.
    """
    name = RuleType.LOWERCASE

    def validate(self, password: str, policy: PasswordPolicy) -> RuleResult:
        """
        Validate that the given password contains at least one lowercase letter.

        Args:
            password (str): The password to validate.
            policy (PasswordPolicy): The password policy to use for validation.

        Returns:
            RuleResult: The result of the validation.
        """
        if not policy.require_lowercase:
            return RuleResult(
                rule=self.name,
                passed=True
            )

        count = sum(c.islower() for c in password)

        if count < policy.min_lowercase:
            return RuleResult(
                rule=self.name,
                passed=False,
                error_code=ErrorCode.MISSING_LOWERCASE,
                message=(
                    f"Password must contain at least {policy.min_lowercase} lowercase letter(s)."
                ),
                details={
                    "expected": policy.min_lowercase,
                    "actual": count
                },
            )

        return RuleResult(
            rule=self.name,
            passed=True,
            details={
                "lowercase_count": count
            },
        )

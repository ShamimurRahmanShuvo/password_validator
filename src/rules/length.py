"""
Length validation rule for password validation.
"""
from src.password_validator.config import PasswordPolicy
from src.password_validator.enums import RuleType, ErrorCode
from src.password_validator.models import RuleResult
from src.rules.base import ValidationRule


class LengthRule(ValidationRule):
    """
    Validates the length of a password against the specified policy.
    """
    name = RuleType.LENGTH

    def validate(self, password: str, policy: PasswordPolicy) -> RuleResult:
        """
        Validate the length of the given password against the policy.

        Args:
            password (str): The password to validate.
            policy (PasswordPolicy): The password policy to use for validation.

        Returns:
            RuleResult: The result of the validation.
        """
        min_length = policy.min_length
        max_length = policy.max_length

        if len(password) < min_length:
            return RuleResult(
                rule=self.name,
                passed=False,
                error_code=ErrorCode.TOO_SHORT,
                message=(
                    f"Password must be at least {min_length} characters long."
                ),
                details={
                    "expected": policy.min_length,
                    "actual": len(password)
                },
            )

        if len(password) > max_length:
            return RuleResult(
                rule=self.name,
                passed=False,
                error_code=ErrorCode.TOO_LONG,
                message=(
                    f"Password must be no more than {max_length} characters long."
                ),
                details={
                    "expected": policy.max_length,
                    "actual": len(password)
                },
            )

        return RuleResult(
            rule=self.name,
            passed=True,
            details={
                "length": len(password)
            }
        )

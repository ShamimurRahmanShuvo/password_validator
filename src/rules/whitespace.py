"""
Whitespace rule for the linter.
"""
from src.password_validator.config import PasswordPolicy
from src.password_validator.enums import RuleType, ErrorCode
from src.password_validator.models import RuleResult
from src.rules.base import ValidationRule


class WhitespaceRule(ValidationRule):
    """
    Validates that a password does not contain whitespace characters.
    """
    name = RuleType.WHITESPACE

    def validate(self, password: str, policy: PasswordPolicy) -> RuleResult:
        """
        Validate that the given password does not contain whitespace characters.

        Args:
            password (str): The password to validate.
            policy (PasswordPolicy): The password policy to use for validation.

        Returns:
            RuleResult: The result of the validation.
        """
        if not policy.require_whitespace:
            return RuleResult(
                rule=self.name,
                passed=True
            )

        if any(c.isspace() for c in password):
            return RuleResult(
                rule=self.name,
                passed=False,
                error_code=ErrorCode.CONTAINS_SPACE,
                message="Password must not contain whitespace characters.",
                details={
                    "contains_whitespace": True
                },
            )

        return RuleResult(
            rule=self.name,
            passed=True,
            details={
                "contains_whitespace": False
            },
        )

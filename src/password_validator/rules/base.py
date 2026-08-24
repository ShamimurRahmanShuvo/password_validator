"""
Base password validation rules and their implementations.
"""
from abc import ABC, abstractmethod

from src.password_validator.enums import RuleType
from src.password_validator.models import RuleResult
from src.password_validator.config import PasswordPolicy


class ValidationRule(ABC):
    """
    Abstract base class for password validation rules.
    """

    name: RuleType = ""

    @abstractmethod
    def validate(self, password: str, policy: PasswordPolicy) -> RuleResult:
        """
        Validate the given password against the rule.

        Args:
            password (str): The password to validate.
            policy (PasswordPolicy): The password policy to use for validation.

        Returns:
            RuleResult: The result of the validation.
        """
        pass

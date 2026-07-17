"""
Public Password Validator API
Developers only interact with this module. It provides a single function, validate_password, which takes a password
string as input and returns a boolean indicating whether the password is valid according to the defined rules.
"""
"""
validator = PasswordValidator()
validator.validate(password)
validator.score(password)
validator.is_valid(password)
"""
from typing import Optional
from config import PasswordPolicy, default_policy
from engine import ValidationEngine
from models import ValidationResult
from src.rules.registry import create_default_registry


class PasswordValidator:
    """
    PasswordValidator is the main class for validating passwords against a set of rules and policies.
    """

    def __init__(self, policy: Optional[PasswordPolicy] = None, registry=None):
        self.policy = policy or default_policy
        self.registry = registry or create_default_registry()
        self.engine = ValidationEngine(
            policy=self.policy,
            rules=self.registry.get_rules()
        )

    def validate(self, password: str) -> ValidationResult:
        """
        Validate the given password against the loaded rules and policy.

        Args:
            password (str): The password to validate.

        Returns:
            ValidationResult: The result of the validation, including errors and strength score.
        """
        return self.engine.validate(password)

    def is_valid(self, password: str) -> bool:
        """
        Check if the given password is valid according to the loaded rules and policy.

        Args:
            password (str): The password to check.

        Returns:
            bool: True if the password is valid, False otherwise.
        """
        result = self.validate(password)
        return result.valid

    def reload(self):
        """
        Reload the rules from the registry and reinitialize the validation engine.
        :return:
        """
        self.engine = ValidationEngine(
            policy=self.policy,
            rules=self.registry.get_rules()
        )

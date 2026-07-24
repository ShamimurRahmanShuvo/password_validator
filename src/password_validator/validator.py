"""
Public Password Validator API
Developers only interact with this module. It provides a single function, validate_password, which takes a password
string as input and returns a boolean indicating whether the password is valid according to the defined rules.
"""
from typing import Optional
from config import PasswordPolicy, default_policy
from engine import ValidationEngine
from models import ValidationResult
from .strength import PasswordStrengthScorer
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
        self.scorer = PasswordStrengthScorer()

    def validate(self, password: str) -> ValidationResult:
        """
        Validate the given password against the loaded rules and policy.

        Args:
            password (str): The password to validate.

        Returns:
            ValidationResult: The result of the validation, including errors and strength score.
        """
        result = self.engine.validate(password)
        score, strength = self.scorer.score(password)
        result.score = score
        result.strength = strength

        return result

    def score(self, password: str) -> int:
        """
        Score the given password based on various criteria.

        Args:
            password (str): The password to score.

        Returns:
            int: The strength score of the password.
        """
        score, _ = self.scorer.score(password)
        return score

    def strength(self, password: str):
        """
        Get the strength level of the given password.

        Args:
            password (str): The password to evaluate.

        Returns:
            StrengthLevel: The strength level of the password.
        """
        _, strength = self.scorer.score(password)
        return strength

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

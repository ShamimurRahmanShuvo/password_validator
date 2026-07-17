"""
Password validation execution engine

Responsibilities:
- Load configuration.
- Load rules.
- Execute validation.
- Aggregate errors.
- Calculate strength
- Return results.
"""
from typing import Iterable
from config import PasswordPolicy
from models import ValidationResult, RuleResult
from src.rules.base import ValidationRule


class ValidationEngine:
    """
    Password validation execution engine.
    """

    def __init__(self, policy: PasswordPolicy, rules: Iterable[ValidationRule]):
        self.policy = policy
        self.rules = list(rules)

    def validate(self, password: str) -> ValidationResult:
        """
        Validate the given password against the loaded rules and policy.

        Args:
            password (str): The password to validate.

        Returns:
            ValidationResult: The result of the validation, including errors and strength score.
        """
        errors = []
        score = 0
        result = ValidationResult(valid=True, errors=errors, score=score)

        for rule in self.rules:
            rule_result: RuleResult = (
                rule.validate(
                    password,
                    self.policy
                )
            )

            result.add_result(rule_result)

        return result

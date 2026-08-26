"""
Password validation engine.
The validation engine executes password policy rules and returns a structured validation result.
It does not perform password strength analysis. Strength analysis is handled by password_validator.strength.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Sequence

from ..config.settings import PasswordRuleConfig
from ..rules.base import Rule, RuleResult
from ..rules.digits import DigitsRule
from ..rules.length import LengthRule
from ..rules.lowercase import LowercaseRule
from ..rules.special import SpecialCharacterRule
from ..rules.uppercase import UppercaseRule


@dataclass(slots=True, frozen=True)
class ValidationResult:
    """
    Result of password policy validation.
    """
    valid: bool
    passed: tuple[str, ...] = ()
    failed: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    rule_results: tuple[RuleResult, ...] = ()

    @property
    def is_valid(self) -> bool:
        """
        Alias for valid
        :return:
        """
        return self.valid

    @property
    def error_count(self) -> int:
        """
        Number of failed rules
        :return:
        """
        return len(self.failed)


class PasswordValidator:
    """
    Password policy validation engine.
    Example:
        config = PasswordRuleConfig(
            min_length=10,
            require_uppercase=True,
            require_lowercase=True,
            require_digit=True,
            require_special=True,
        )

        validator = PasswordValidator(
            config=config
        )

        result = validator.validate(
            "MyPassword123!"
        )

        if result.is_valid:
            print("Password is valid.")
    """

    def __init__(self, config: PasswordRuleConfig | None = None, rules: Sequence[Rule] | None = None) -> None:
        """
        Initialize the password validator.
        :param config: Password policy configuration
        :param rules: Optional custom rule collection

        If rules are supplied, the validator uses those rules instead of constructing the default rule set. This makes
        the validator easy to extend and test
        """
        self.config = config or PasswordRuleConfig()
        self.config.validate()

        self.rules = list(rules if rules is not None
                          else self._build_default_rules())

    def _build_default_rules(self) -> list[Rule]:
        """
        Build the default password policy rule
        :return:
        """
        rules: list[Rule] = []

        rules.append(LengthRule(
            min_length=self.config.min_length,
            max_length=self.config.max_length)
        )

        if self.config.require_uppercase:
            rules.append(UppercaseRule())

        if self.config.require_lowercase:
            rules.append(LowercaseRule())

        if self.config.require_digit:
            rules.append(DigitsRule())

        if self.config.require_special:
            rules.append(SpecialCharacterRule(
                special_characters=(self.config.special_characters)
            ))

        return rules

    def validate(self, password: str) -> ValidationResult:
        """
        Validate the given password against the loaded rules and policy.

        Args:
            password (str): The password to validate.
        Returns:
            ValidationResult: The result of the validation, including errors and strength score.
        """
        if not isinstance(password, str):
            raise TypeError("Password must be a string")

        rule_results: list[RuleResult] = []
        passed: list[str] = []
        failed: list[str] = []
        errors: list[str] = []

        for rule in self.rules:
            result = rule.validate(password)
            rule_results.append(result)
            rule_name = self._rule_name(rule, result)

            if result.passed:
                passed.append(rule_name)
            else:
                failed.append(rule_name)

                if result.message:
                    errors.append(result.message)

        valid = not failed

        return ValidationResult(
            valid=valid,
            passed=tuple(passed),
            failed=tuple(failed),
            errors=tuple(errors),
            rule_results=tuple(rule_results)
        )

    @staticmethod
    def _rule_name(rule: Rule, result: RuleResult) -> str:
        """
        Resolve a stable rule name.
        Prefer the RuleResult name when available, otherwise use the rule class name.
        :param rule:
        :param result:
        :return:
        """
        name = getattr(result, "rule_name", None)

        if name:
            return name
        class_name = rule.__class__.__name__

        if class_name.endswith("Rule"):
            class_name = class_name[:4]

        return class_name

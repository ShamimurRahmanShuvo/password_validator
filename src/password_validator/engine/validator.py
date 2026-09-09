"""
Password validation engine.

The validation engine executes password policy rules and returns a
structured validation result.

It does not perform password strength analysis. Strength analysis is
handled by password_validator.strength.
"""

from __future__ import annotations

from collections.abc import Sequence

from ..config.settings import PasswordRuleConfig
from ..models import ValidationResult
from ..rules.base import Rule, RuleResult
from ..rules.digits import DigitsRule
from ..rules.length import LengthRule
from ..rules.lowercase import LowercaseRule
from ..rules.special import SpecialCharacterRule
from ..rules.uppercase import UppercaseRule


class PasswordValidator:
    """
    Password policy validation engine.
    """

    def __init__(
        self,
        config: PasswordRuleConfig | None = None,
        rules: Sequence[Rule] | None = None,
    ) -> None:
        """
        Initialize the password validator.

        Args:
            config: Password policy configuration.
            rules: Optional custom rule collection.

        When rules are supplied, they completely replace the default
        rule collection.
        """

        self.config = config or PasswordRuleConfig()

        if hasattr(self.config, "validate"):
            self.config.validate()

        if rules is not None:
            self.rules = list(rules)
        else:
            self.rules = self._build_default_rules()

    def _build_default_rules(self) -> list[Rule]:
        """Build the default password policy rule collection."""

        rules: list[Rule] = []

        rules.append(
            LengthRule(
                min_length=self.config.min_length,
                max_length=self.config.max_length,
            )
        )

        if self.config.require_uppercase:
            rules.append(UppercaseRule())

        if self.config.require_lowercase:
            rules.append(LowercaseRule())

        if self.config.require_digit:
            rules.append(DigitsRule())

        if self.config.require_special:
            rules.append(
                SpecialCharacterRule(
                    special_characters=self.config.special_characters,
                )
            )

        return rules

    def validate(self, password: str) -> ValidationResult:
        """
        Validate a password against all configured rules.

        Args:
            password: Password to validate.

        Returns:
            ValidationResult containing the overall status and individual
            rule results.

        Raises:
            TypeError: If password is not a string.
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

        return ValidationResult(
            valid=not failed,
            passed=tuple(passed),
            failed=tuple(failed),
            errors=tuple(errors),
            rule_results=tuple(rule_results),
        )

    @staticmethod
    def _rule_name(
        rule: Rule,
        result: RuleResult,
    ) -> str:
        """
        Resolve a stable rule name.

        Resolution order:

        1. RuleResult.rule_name
        2. rule.name
        3. Rule class name with the "Rule" suffix removed
        """

        result_name = getattr(result, "rule_name", None)

        if result_name:
            return str(result_name)

        rule_name = getattr(rule, "name", None)

        if rule_name:
            return str(rule_name)

        class_name = rule.__class__.__name__

        if class_name.endswith("Rule"):
            class_name = class_name[:-4]

        return class_name.lower()


__all__ = [
    "PasswordValidator",
    "ValidationResult",
]

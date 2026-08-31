"""
Rule registry module for managing and retrieving rules in the system.
"""
from typing import List
from .base import Rule
from .length import LengthRule
from .uppercase import UppercaseRule
from .lowercase import LowercaseRule
from .digits import DigitsRule
from .special import SpecialCharacterRule


class RuleRegistry:
    """
    Stores and manages the registered rules in the system.
    """
    def __init__(self) -> None:
        self._rules: List[Rule] = []

    def register(self, rule: Rule) -> None:
        """
        Registers a new rule in the registry.

        Args:
            rule (ValidationRule): The rule to register.
        """
        self._rules.append(rule)

    def unregister(self, rule_type: str) -> None:
        """
        Unregisters a rule from the registry based on its type.
        :param rule_type: The type of the rule to unregister.
        """
        self._rules = [rule for rule in self._rules if rule.name != rule_type]

    def get_rules(self) -> List[Rule]:
        """
        Retrieves all registered rules.

        Returns:
            List[ValidationRule]: A list of all registered rules.
        """
        return self._rules.copy()

    def clear(self):
        """
        Clears all registered rules from the registry.
        """
        self._rules.clear()


def create_default_registry(config) -> RuleRegistry:
    """
    Create a registry containing the standard password rules.

    The rule configuration is supplied by PasswordRuleConfig,
    which can ultimately be populated from environment variables.

    Args:
        config: PasswordRuleConfig instance.

    Returns:
        RuleRegistry: Configured default rule registry.
    """
    registry = RuleRegistry()
    registry.register(
        LengthRule(
            min_length=config.min_length,
            max_length=config.max_length
        )
    )
    registry.register(UppercaseRule())
    registry.register(LowercaseRule())
    registry.register(DigitsRule())
    registry.register(
        SpecialCharacterRule(
            special_characters=config.special_characters
        )
    )

    return registry

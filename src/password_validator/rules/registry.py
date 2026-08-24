"""
Rule registry module for managing and retrieving rules in the system.
"""
from typing import List
from base import ValidationRule
from length import LengthRule
from uppercase import UppercaseRule
from lowercase import LowercaseRule
from digits import DigitsRule
from special import SpecialCharacterRule
from whitespace import WhitespaceRule


class RuleRegistry:
    """
    Stores and manages the registered rules in the system.
    """
    def __init__(self):
        self._rules: List[ValidationRule] = []

    def register(self, rule: ValidationRule):
        """
        Registers a new rule in the registry.

        Args:
            rule (ValidationRule): The rule to register.
        """
        self._rules.append(rule)

    def unregister(self, rule_type):
        """
        Unregisters a rule from the registry based on its type.
        :param rule_type: The type of the rule to unregister.
        """
        self._rules = [rule for rule in self._rules if rule.name != rule_type]

    def get_rules(self) -> List[ValidationRule]:
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


def create_default_registry():
    """
    Creates a default rule registry with standard password validation rules.

    Returns:
        RuleRegistry: A registry populated with default rules.
    """
    registry = RuleRegistry()
    registry.register(LengthRule())
    registry.register(UppercaseRule())
    registry.register(LowercaseRule())
    registry.register(DigitsRule())
    registry.register(SpecialCharacterRule())
    registry.register(WhitespaceRule())

    return registry

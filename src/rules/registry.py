"""
Rule registry module for managing and retrieving rules in the system.
"""
from typing import List
from base import ValidationRule


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

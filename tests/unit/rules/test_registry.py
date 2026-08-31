"""
Unit tests for RuleRegistry
"""
import pytest
from password_validator.config.settings import PasswordRuleConfig
from password_validator.rules.registry import RuleRegistry, create_default_registry
from password_validator.rules.length import LengthRule


class TestRuleRegistry:
    """
    Tests for rule registry
    """
    @pytest.fixture
    def default_config(self):
        return PasswordRuleConfig.defaults()

    @pytest.fixture
    def default_registry(self, default_config):
        return create_default_registry(default_config)

    def test_registry_can_be_created(self):
        registry = RuleRegistry()

        assert registry is not None

    def test_new_registry_is_empty(self):
        registry = RuleRegistry()
        rules = registry.get_rules()

        assert rules == []

    def test_register_rule(self):
        registry = RuleRegistry()
        rule = LengthRule(min_length=8, max_length=64)

        registry.register(rule)
        rules = registry.get_rules()

        assert len(rules) == 1
        assert rules[0] is rule

    def test_get_rules_returns_copy(self):
        registry = RuleRegistry()
        rule = LengthRule(min_length=8, max_length=64)

        registry.register(rule)
        rules = registry.get_rules()
        rules.clear()

        assert len(registry.get_rules()) == 1

    def test_unregister_rule(self):
        registry = RuleRegistry()
        rule = LengthRule(min_length=8, max_length=64)

        registry.register(rule)
        rules = registry.get_rules()

        assert len(rules) == 1

        registry.unregister(rule.name)

        assert registry.get_rules() == []

    def test_unregister_unknown_rule_does_nothing(self):
        registry = RuleRegistry()
        rule = LengthRule(min_length=8, max_length=64)

        registry.register(rule)
        rules = registry.get_rules()
        registry.unregister("doesn't exists")

        assert len(rules) == 1

    def test_clear_removes_all_rules(self):
        registry = RuleRegistry()
        rule1 = LengthRule(min_length=8, max_length=64)
        rule2 = LengthRule(min_length=10, max_length=128)

        registry.register(rule1)
        registry.register(rule2)
        rules = registry.get_rules()

        assert len(rules) == 2

        registry.clear()

        assert registry.get_rules() == []

    def test_multiple_rules_can_be_registered(self):
        registry = RuleRegistry()
        rule1 = LengthRule(min_length=8, max_length=64)
        rule2 = LengthRule(min_length=10, max_length=128)

        registry.register(rule1)
        registry.register(rule2)
        rules = registry.get_rules()

        assert len(rules) == 2
        assert rules[0] is rule1
        assert rules[1] is rule2

    def test_separate_registries_are_independent(self):
        registry1 = RuleRegistry()
        registry2 = RuleRegistry()

        rule = LengthRule(min_length=8, max_length=64)

        registry1.register(rule)
        assert len(registry1.get_rules()) == 1
        assert registry2.get_rules() == []

    def test_default_registry_contains_default_rules(self, default_registry):
        rules = default_registry.get_rules()

        assert len(rules) == 5

    def test_default_registry_contains_length_rule(self, default_registry):
        rule_names = {rule.name for rule in default_registry.get_rules()}

        assert "length" in rule_names

    def test_default_registry_uses_custom_length_configuration(self):
        config = PasswordRuleConfig(
            min_length=12,
            max_length=32,
            special_characters="!@#$",
        )

        registry = create_default_registry(config)

        length_rule = next(
            rule
            for rule in registry.get_rules()
            if rule.name == "length"
        )

        assert length_rule.min_length == 12
        assert length_rule.max_length == 32

    def test_default_registry_uses_custom_special_characters(self):
        config = PasswordRuleConfig(
            min_length=8,
            max_length=64,
            special_characters="@#$",
        )

        registry = create_default_registry(config)

        special_rule = next(
            rule
            for rule in registry.get_rules()
            if rule.name == "special"
        )

        assert special_rule.special_characters == {'#', '$', '@'}

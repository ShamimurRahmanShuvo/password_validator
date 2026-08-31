"""
Unit tests for UpperCaseRule
"""
from password_validator.rules.uppercase import UppercaseRule


class TestUpperCaseRule:
    """
    Tests for uppercase rule
    """
    def test_password_with_uppercase_passes(self):
        rule = UppercaseRule()
        result = rule.validate("Password123!")

        assert result.passed is True

    def test_password_without_uppercase_fails(self):
        rule = UppercaseRule()
        result = rule.validate("password123!")

        assert result.passed is False

    def test_password_with_multiple_uppercase_letters_passes(self):
        rule = UppercaseRule()
        result = rule.validate("PASSWORD123!")

        assert result.passed is True

    def test_empty_password_fails(self):
        rule = UppercaseRule()
        result = rule.validate("")

        assert result.passed is False

    def test_uppercase_rule_ignores_digits(self):
        rule = UppercaseRule()
        result = rule.validate("12345678")

        assert result.passed is False

    def test_uppercase_rule_ignores_special_characters(self):
        rule = UppercaseRule()
        result = rule.validate("!@#$%^&*")

        assert result.passed is False

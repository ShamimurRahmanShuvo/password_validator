"""
Unit tests for LowerCaseRule
"""
from password_validator.rules.lowercase import LowercaseRule


class TestLowerCaseRule:
    """
    Tests for lowercase rule
    """
    def test_password_with_lowercase_passes(self):
        rule = LowercaseRule()
        result = rule.validate("Password123!")

        assert result.passed is True

    def test_password_without_lowercase_fails(self):
        rule = LowercaseRule()
        result = rule.validate("PASSWORD123!")

        assert result.passed is False

    def test_password_with_multiple_lowercase_letters_passes(self):
        rule = LowercaseRule()
        result = rule.validate("password123!")

        assert result.passed is True

    def test_empty_password_fails(self):
        rule = LowercaseRule()
        result = rule.validate("")

        assert result.passed is False

    def test_lowercase_rule_ignores_digits(self):
        rule = LowercaseRule()
        result = rule.validate("12345678")

        assert result.passed is False

    def test_lowercase_rule_ignores_special_characters(self):
        rule = LowercaseRule()
        result = rule.validate("!@#$%^&*")

        assert result.passed is False

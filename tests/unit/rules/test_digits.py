"""
Unit tests for DigitsRule
"""
from password_validator.rules.digits import DigitsRule


class TestDigitsRule:
    """
    Tests for lowercase rule
    """
    def test_password_with_digits_passes(self):
        rule = DigitsRule()
        result = rule.validate("Password123!")

        assert result.passed is True

    def test_password_without_digits_fails(self):
        rule = DigitsRule()
        result = rule.validate("Password!")

        assert result.passed is False

    def test_password_with_single_digit_passes(self):
        rule = DigitsRule()
        result = rule.validate("Password1!")

        assert result.passed is True

    def test_empty_password_fails(self):
        rule = DigitsRule()
        result = rule.validate("")

        assert result.passed is False

    def test_password_with_multiple_digits_passes(self):
        rule = DigitsRule()
        result = rule.validate("Password123!")

        assert result.passed is True

    def test_only_digits_passes_digit_rule(self):
        rule = DigitsRule()
        result = rule.validate("123456789")

        assert result.passed is True

"""
Unit tests for LengthRule
"""
from password_validator.rules.length import LengthRule


class TestLengthRule:
    """
    Tests for LengthRule
    """
    def test_password_at_minimum_length_passes(self):
        rule = LengthRule(
            min_length=8,
            max_length=64
        )
        password = "Abcd123!"
        result = rule.validate(password)

        assert result.passed is True

    def test_password_below_minimum_length_fails(self):
        rule = LengthRule(
            min_length=8,
            max_length=64
        )
        password = "Abc123!"
        result = rule.validate(password)

        assert result.passed is False

    def test_password_at_maximum_length_passes(self):
        rule = LengthRule(
            min_length=8,
            max_length=12
        )
        password = "Abcd123!xyz"
        result = rule.validate(password)

        assert result.passed is True

    def test_password_above_maximum_length_fails(self):
        rule = LengthRule(
            min_length=8,
            max_length=10
        )
        password = "Abcd123!xyz"
        result = rule.validate(password)

        assert result.passed is False

    def test_password_length_between_limits_passes(self):
        rule = LengthRule(
            min_length=8,
            max_length=64
        )
        password = "MySecurePassword123!"
        result = rule.validate(password)

        assert result.passed is True

    def test_empty_password_fails(self):
        rule = LengthRule(
            min_length=8,
            max_length=64
        )
        password = ""
        result = rule.validate(password)

        assert result.passed is False

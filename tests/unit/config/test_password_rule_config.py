"""
Unit tests for PasswordRuleConfig (settings.py)
"""
from password_validator.config.settings import PasswordRuleConfig


class TestPasswordRuleConfig:
    """
    Tests for PasswordRuleConfig
    """

    def test_defaults_returns_configuration(self):
        config = PasswordRuleConfig.defaults()

        assert isinstance(config, PasswordRuleConfig)

    def test_default_minimum_length_is_positive(self):
        config = PasswordRuleConfig.defaults()

        assert config.min_length > 0

    def test_default_maximum_length_is_greater_than_minimum(self):
        config = PasswordRuleConfig.defaults()

        assert config.max_length >= config.min_length

    def test_can_override_minimum_and_maximum_length(self):
        config = PasswordRuleConfig(min_length=12, max_length=64)

        assert config.min_length == 12
        assert config.max_length == 64

    def test_uppercase_and_lowercase_requirement_can_be_disabled(self):
        config = PasswordRuleConfig(
            require_uppercase=False,
            require_lowercase=False
        )

        assert config.require_uppercase is False
        assert config.require_lowercase is False

    def test_digit_and_special_requirement_can_be_disabled(self):
        config = PasswordRuleConfig(
            require_digit=False,
            require_special=False
        )

        assert config.require_digit is False
        assert config.require_special is False

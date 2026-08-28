"""
Unit tests for application settings
"""
from password_validator.config.settings import PasswordRuleConfig, Settings
from password_validator.strength.config import StrengthConfig


class TestSettings:
    """
    Tests for settings
    """

    def test_can_create_settings(self):
        settings = Settings(
            rules=PasswordRuleConfig.defaults(),
            strength=StrengthConfig.defaults()
        )

        assert settings is not None

    def test_settings_contains_rule_configuration(self):
        settings = Settings(
            rules=PasswordRuleConfig.defaults(),
            strength=StrengthConfig.defaults()
        )

        assert isinstance(settings.rules, PasswordRuleConfig)

    def test_settings_contains_strength_configuration(self):
        settings = Settings(
            rules=PasswordRuleConfig.defaults(),
            strength=StrengthConfig.defaults()
        )

        assert isinstance(settings.strength, StrengthConfig)

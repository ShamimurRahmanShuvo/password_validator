"""
Unit test for StrengthConfig
"""
from password_validator.strength.config import StrengthConfig


class TestStrengthConfig:
    """
    Tests for StrengthConfig (strength/config.py)
    """

    def test_defaults_returns_configuration(self):
        config = StrengthConfig.defaults()

        assert isinstance(config, StrengthConfig)

    def test_default_configuration_has_positive_values(self):
        config = StrengthConfig.defaults()

        assert config is not None

    def test_can_create_custom_configuration(self):
        config = StrengthConfig()

        assert isinstance(config, StrengthConfig)

    def test_check_factors_disabled(self):
        config = StrengthConfig(
            check_repeated_characters=False,
            check_sequential_patterns=False,
            check_keyboard_patterns=False,
            check_dictionary_words=False,
            check_common_passwords=False
        )

        assert config.check_repeated_characters is False
        assert config.check_sequential_patterns is False
        assert config.check_keyboard_patterns is False
        assert config.check_dictionary_words is False
        assert config.check_common_passwords is False

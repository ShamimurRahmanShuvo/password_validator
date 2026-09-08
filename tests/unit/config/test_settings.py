"""
Unit tests for application settings
"""
import pytest
from unittest.mock import Mock, patch
from password_validator.config.settings import PasswordRuleConfig, Settings
from password_validator.loaders.env_loader import EnvLoader
from password_validator.strength.config import StrengthConfig


class TestSettings:
    """
    Tests for settings
    """
    def test_defaults(self):
        settings = Settings.defaults()

        assert isinstance(settings, Settings)
        assert isinstance(settings.rules, PasswordRuleConfig)
        assert settings.rules == PasswordRuleConfig()
        assert settings.strength is not None

    def test_default_rules_are_valid(self):
        settings = Settings.defaults()
        settings.rules.validate()

    def test_settings_is_frozen(self):
        settings = Settings.defaults()
        with pytest.raises(AttributeError):
            settings.rules = PasswordRuleConfig()


class TestSettingsFromEnv:
    """
    Test settings for Settings.from_env()
    """
    def test_from_env_creates_settings(self, tmp_path):
        env_file = tmp_path/".env"

        env_file.write_text(
            "\n".join(
                ["PASSWORD_MIN_LENGTH=8", "PASSWORD_MAX_LENGTH=64", "PASSWORD_REQUIRE_UPPERCASE=true",
                 "PASSWORD_REQUIRE_LOWERCASE=true", "PASSWORD_REQUIRE_DIGIT=true", "PASSWORD_REQUIRE_SPECIAL=true",
                 "PASSWORD_SPECIAL_CHARACTERS=@#$"
                 ]
            )
        )
        settings = Settings.from_env(str(env_file))

        assert isinstance(settings, Settings)
        assert isinstance(settings.rules, PasswordRuleConfig)
        assert settings.rules.min_length == 8
        assert settings.rules.max_length == 64
        assert settings.rules.require_uppercase is True
        assert settings.rules.require_lowercase is True
        assert settings.rules.require_digit is True
        assert settings.rules.require_special is True
        assert settings.rules.special_characters == '!@#$%^&*()-_=+[]{}|;:\'",.<>?/`~'
        assert settings.strength is not None



class TestPasswordRuleConfig:
    """
    Tests for PasswordRuleConfig
    """
    def test_defaults(self):
        config = PasswordRuleConfig()

        assert config.min_length == 8
        assert config.max_length == 128
        assert config.require_uppercase is True
        assert config.require_lowercase is True
        assert config.require_digit is True
        assert config.require_special is True
        assert config.special_characters == "!@#$%^&*()-_=[]{}|/:;'<>?"

    def test_default_class_method(self):
        config = PasswordRuleConfig.defaults()

        assert isinstance(config, PasswordRuleConfig)
        assert config == PasswordRuleConfig()

    def test_validate_accepts_default_configuration(self):
        config = PasswordRuleConfig()

        config.validate()

    def test_validate_rejects_zero_and_negative_min_length(self):
        config1 = PasswordRuleConfig(min_length=0, max_length=128)
        config2 = PasswordRuleConfig(min_length=-1, max_length=128)

        with pytest.raises(ValueError, match="PASSWORD_MIN_LENGTH must be greater than 0"):
            config1.validate()
        with pytest.raises(ValueError, match="PASSWORD_MIN_LENGTH must be greater than 0"):
            config2.validate()

    def test_validate_rejects_max_length_less_than_min_length(self):
        config = PasswordRuleConfig(min_length=20, max_length=10)
        with pytest.raises(ValueError,
                           match="PASSWORD_MAX_LENGTH must be greater than or equal to PASSWORD_MIN_LENGTH"):
            config.validate()

    def test_validate_special_characters(self):
        config = PasswordRuleConfig(require_special=True, special_characters="")
        with pytest.raises(ValueError,
                           match="PASSWORD_SPECIAL_CHARACTERS cannot be empty when PASSWORD_REQUIRE_SPECIAL=true"):
            config.validate()

        config1 = PasswordRuleConfig(require_special=False, special_characters="!@#$")
        config1.validate()

    def test_custom_configuration(self):
        config = PasswordRuleConfig(
            min_length=12, max_length=64, require_uppercase=False, require_lowercase=True, require_digit=True,
            require_special=False, special_characters="@#"
        )

        assert config.min_length == 12
        assert config.max_length == 64
        assert config.require_uppercase is False
        assert config.require_lowercase is True
        assert config.require_digit is True
        assert config.require_special is False
        assert config.special_characters == "@#"

    def test_configuration_is_frozen(self):
        config = PasswordRuleConfig()
        with pytest.raises(AttributeError):
            config.min_length = 10


class TestPasswordRuleConfigFromEnv:
    """
    Tests for PasswordRuleConfig.from_env()
    """
    def test_from_env_reads_all_values(self):
        env = Mock(spec=EnvLoader)

        env.get_int.side_effect = lambda key, default: {
            "PASSWORD_MIN_LENGTH": 12,
            "PASSWORD_MAX_LENGTH": 64
        }[key]

        env.get_bool.side_effect = lambda key, default:{
            "PASSWORD_REQUIRE_UPPERCASE": False,
            "PASSWORD_REQUIRE_LOWERCASE": True,
            "PASSWORD_REQUIRE_DIGIT": True,
            "PASSWORD_REQUIRE_SPECIAL": False
        }[key]

        env.get.side_effect = lambda key, default: {"PASSWORD_SPECIAL_CHARACTERS": "@#$", }[key]

        config = PasswordRuleConfig.from_env(env)

        assert config.min_length == 12
        assert config.max_length == 64
        assert config.require_uppercase is False
        assert config.require_lowercase is True
        assert config.require_digit is True
        assert config.require_special is False
        assert config.special_characters == "@#$"

    def test_from_env_uses_defaults(self):
        env = Mock(spec=EnvLoader)
        env.get_int.side_effect = lambda key, default: default
        env.get_bool.side_effect = lambda key, default: default
        env.get.side_effect = lambda key, default: default

        config = PasswordRuleConfig.from_env(env)
        assert config.min_length == 8
        assert config.max_length == 64
        assert config.require_uppercase is True
        assert config.require_lowercase is True
        assert config.require_digit is True
        assert config.require_special is True
        assert config.special_characters == ('!@#$%^&*()-_=+[]{}|;:\'",.<>?/`~')

    def test_from_env_calls_expected_environment_keys(self):
        env = Mock(spec=EnvLoader)

        env.get_int.side_effect = lambda key, default: default
        env.get_bool.side_effect = lambda key, default: default
        env.get.side_effect = lambda key, default: default
        PasswordRuleConfig.from_env(env)
        env.get_int.assert_any_call("PASSWORD_MIN_LENGTH", 8)
        env.get_int.assert_any_call("PASSWORD_MAX_LENGTH", 64)
        env.get_bool.assert_any_call("PASSWORD_REQUIRE_UPPERCASE", True)
        env.get_bool.assert_any_call("PASSWORD_REQUIRE_LOWERCASE", True)
        env.get_bool.assert_any_call("PASSWORD_REQUIRE_DIGIT", True)
        env.get_bool.assert_any_call("PASSWORD_REQUIRE_SPECIAL", True)

    def test_from_env_result_is_validated_separately(self):
        env = Mock(spec=EnvLoader)

        env.get_int.side_effect = lambda key, default: {"PASSWORD_MIN_LENGTH": 20, "PASSWORD_MAX_LENGTH": 10, }[key]
        env.get_bool.side_effect = lambda key, default: default
        env.get.side_effect = lambda key, default: default
        config = PasswordRuleConfig.from_env(env)
        assert config.min_length == 20
        assert config.max_length == 10
        with pytest.raises(ValueError): config.validate()

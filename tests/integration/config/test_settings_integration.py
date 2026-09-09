from pathlib import Path
import pytest
from password_validator.config.settings import PasswordRuleConfig, Settings
from password_validator.strength.config import StrengthConfig


class TestPasswordRuleConfigIntegration:
    def test_loads_complete_configuration_from_env(self, configured_env_file: Path):
        settings = Settings.from_env(str(configured_env_file))

        assert isinstance(settings, Settings)
        assert isinstance(settings.rules, PasswordRuleConfig)
        assert isinstance(settings.strength, StrengthConfig)
        assert settings.rules.min_length == 10
        assert settings.rules.max_length == 64
        assert settings.rules.require_uppercase is True
        assert settings.rules.require_lowercase is True
        assert settings.rules.require_digit is True
        assert settings.rules.require_special is True
        assert settings.rules.special_characters == "@#$%^&*"

    def test_custom_values_are_loaded(self, tmp_path: Path):
        env_file = tmp_path/".env"
        env_file.write_text(
            "\n".join(
                [
                    "PASSWORD_SPECIAL_CHARACTERS=@#$",
                    "PASSWORD_REQUIRE_UPPERCASE=false",
                    "PASSWORD_MIN_LENGTH=16"
                ]
            )
        )
        settings = Settings.from_env(str(env_file))
        assert settings.rules.special_characters == "@#$"
        assert settings.rules.require_uppercase is False
        assert settings.rules.min_length == 16

    def test_missing_values_use_environment_defaults(self, env_file: Path):
        settings = Settings.from_env(str(env_file))

        assert settings.rules.min_length == 8
        assert settings.rules.max_length == 64
        assert settings.rules.require_uppercase is True
        assert settings.rules.require_lowercase is True
        assert settings.rules.require_digit is True
        assert settings.rules.require_special is True
        assert settings.rules.special_characters != ""

    def test_invalid_values_are_rejected(self, tmp_path: Path):
        env_file = tmp_path / ".env"
        # min_length
        env_file.write_text(
            "\n".join(
                [
                    "PASSWORD_MIN_LENGTH=0"
                ]
            )
        )
        with pytest.raises(ValueError,
                           match="PASSWORD_MIN_LENGTH must be greater than 0"):
            Settings.from_env(str(env_file))

        # Max_length
        env_file.write_text(
            "\n".join(
                [
                    "PASSWORD_MIN_LENGTH=20",
                    "PASSWORD_MAX_LENGTH=10"
                ]
            )
        )
        with pytest.raises(ValueError,
                           match="PASSWORD_MAX_LENGTH must be greater than or equal to PASSWORD_MIN_LENGTH"):
            Settings.from_env(str(env_file))

        # Special Character
        env_file.write_text(
            "\n".join(
                [
                    "PASSWORD_REQUIRE_SPECIAL=true",
                    "PASSWORD_SPECIAL_CHARACTERS=",
                ]
            )
        )
        with pytest.raises(ValueError,
                           match="PASSWORD_SPECIAL_CHARACTERS cannot be empty when PASSWORD_REQUIRE_SPECIAL=true"):
            Settings.from_env(str(env_file))

        env_file.write_text(
            "\n".join(
                [
                    "PASSWORD_REQUIRE_SPECIAL=false",
                    "PASSWORD_SPECIAL_CHARACTERS=",
                ]
            )
        )
        settings = Settings.from_env(str(env_file))
        assert settings.rules.require_special is False
        assert settings.rules.special_characters == ""


class TestSettingsDefaultIntegration:
    def test_defaults_create_complete_settings(self):
        settings = Settings.defaults()

        assert isinstance(settings, Settings)
        assert isinstance(settings.rules, PasswordRuleConfig)
        assert isinstance(settings.strength, StrengthConfig)
        assert settings.rules.min_length == 8
        assert settings.rules.max_length == 128
        assert settings.rules.require_uppercase is True
        assert settings.rules.require_lowercase is True
        assert settings.rules.require_digit is True
        assert settings.rules.require_special is True

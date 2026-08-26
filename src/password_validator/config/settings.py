"""
Application-level configuration for password-validator.
This module provides the top-level package configuration.
Strength-specific configuration is maintained separately in:
    password_validator.strength.config.StrengthConfig
Password policy configuration is maintained here and can be
loaded from environment variables.
"""
from __future__ import annotations
from dataclasses import dataclass

from ..loaders.env_loader import EnvLoader
from ..strength.config import StrengthConfig
from password_validator.constants import *


@dataclass(frozen=True, slots=True)
class PasswordRuleConfig:
    """
    Configuration for password policy rules.
    These settings determine whether a password satisfies the configured password policy.
    This is separate from password strength scoring.
    """
    min_length: int = 8
    max_length: int = 128

    require_uppercase: bool = True
    require_lowercase: bool =True
    require_digit: bool =True
    require_special: bool = True
    special_characters: str = "!@#$%^&*()-_=[]{}|/:;'<>?"

    """
    require_whitespace: bool
    min_uppercase: int
    min_lowercase: int
    min_digit: int
    min_special: int

    allowed_special: str
    allow_spaces: bool

    max_repeat: int
    check_sequential: bool
    check_common_passwords: bool
    check_dictionary: bool

    custom_regex: str | None
    min_entropy: int
    language: str
    """

    @classmethod
    def from_env(cls, env: EnvLoader) -> "PasswordRuleConfig":
        """
        Loads the password policy configuration from EnvLoader.
        :param env: .env file. Defaults to ".env".
        :return: password policy object
        """

        return cls(
            min_length=env.get_int("PASSWORD_MIN_LENGTH", DEFAULT_MIN_LENGTH),
            max_length=env.get_int("PASSWORD_MAX_LENGTH", DEFAULT_MAX_LENGTH),

            require_uppercase=env.get_bool("PASSWORD_REQUIRE_UPPERCASE", DEFAULT_REQUIRE_UPPERCASE),
            require_lowercase=env.get_bool("PASSWORD_REQUIRE_LOWERCASE", DEFAULT_REQUIRE_LOWERCASE),
            require_digit=env.get_bool("PASSWORD_REQUIRE_DIGIT", DEFAULT_REQUIRE_DIGIT),
            require_special=env.get_bool("PASSWORD_REQUIRE_SPECIAL", DEFAULT_REQUIRE_SPECIAL),
            special_characters=env.get("PASSWORD_SPECIAL_CHARACTERS", DEFAULT_SPECIAL_CHARACTERS)
        )

    def validate(self) -> None:
        """
        Validate the configuration itself.
        Raises:
            ValueError: If the configuration is invalid.
        :return:
        """
        if self.min_length < 1:
            raise ValueError("PASSWORD_MIN_LENGTH must be greater than 0")

        if self.max_length < self.min_length:
            raise ValueError("PASSWORD_MAX_LENGTH must be greater than or equal to PASSWORD_MIN_LENGTH")

        if self.require_special and not self.special_characters:
            raise ValueError("PASSWORD_SPECIAL_CHARACTERS cannot be empty when PASSWORD_REQUIRE_SPECIAL=true")


@dataclass(slots=True, frozen=True)
class Settings:
    """
    Root configuration object for the password-validator package.
    This object is the main configuration boundary for the package.

    Environment variables are loaded once and converted into typed configuration objects.
    """
    rules: PasswordRuleConfig
    strength: StrengthConfig

    @classmethod
    def from_env(cls, env_file: str = ".env") -> "Settings":
        """
        Build application settings from environment file.
        :param env_file: Path to the .env file
        :return: Fully initialized settings object
        """
        env = EnvLoader(env_file)
        rules = PasswordRuleConfig.from_env(env)
        rules.validate()
        strength = StrengthConfig.from_env(env_file)

        return cls(rules=rules, strength=strength)

    @classmethod
    def defaults(cls) -> "Settings":
        """
        Return package defaults without reading an environment file
        :return:
        """
        rules = PasswordRuleConfig()
        rules.validate()

        return cls(
            rules=rules,
            strength=StrengthConfig.defaults()
        )

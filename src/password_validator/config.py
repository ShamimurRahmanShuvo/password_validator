"""
Loads all configuration.
Reads:
- Environment variables
- .env
- Optional overrides
Produces one immutable configuration object that can be used throughout the application.
"""

from dataclasses import dataclass, field
from .constants import *
from src.loaders.env_loader import EnvLoader


@dataclass(frozen=True, slots=True)
class PasswordPolicy:
    """
    Immutable password validation policy.
    """
    min_length: int
    max_length: int

    require_uppercase: bool
    require_lowercase: bool
    require_digit: bool
    require_special: bool
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

    @classmethod
    def load(cls, env_file=".env"):
        """
        Loads the password policy from environment variables and .env file.
        :param env_file: .env file. Defaults to ".env".
        :return: password policy object
        """
        env = EnvLoader(env_file)

        return cls(
            min_length=env.get_int("PASSWORD_MIN_LENGTH", DEFAULT_MIN_LENGTH),
            max_length=env.get_int("PASSWORD_MAX_LENGTH", DEFAULT_MAX_LENGTH),

            require_uppercase=env.get_bool("PASSWORD_REQUIRE_UPPERCASE", DEFAULT_REQUIRE_UPPERCASE),
            require_lowercase=env.get_bool("PASSWORD_REQUIRE_LOWERCASE", DEFAULT_REQUIRE_LOWERCASE),
            require_digit=env.get_bool("PASSWORD_REQUIRE_DIGIT", DEFAULT_REQUIRE_DIGIT),
            require_special=env.get_bool("PASSWORD_REQUIRE_SPECIAL", DEFAULT_REQUIRE_SPECIAL),

            min_uppercase=env.get_int("PASSWORD_MIN_UPPERCASE", DEFAULT_MIN_UPPERCASE),
            min_lowercase=env.get_int("PASSWORD_MIN_LOWERCASE", DEFAULT_MIN_LOWERCASE),
            min_digit=env.get_int("PASSWORD_MIN_DIGIT", DEFAULT_MIN_DIGITS),
            min_special=env.get_int("PASSWORD_MIN_SPECIAL", DEFAULT_MIN_SPECIAL),

            allowed_special=env.get("PASSWORD_ALLOWED_SPECIAL", DEFAULT_SPECIAL_CHARACTERS),
            allow_spaces=env.get_bool("PASSWORD_ALLOW_SPACES", DEFAULT_ALLOW_SPACES),

            max_repeat=env.get_int("PASSWORD_MAX_REPEAT", DEFAULT_MAX_REPEAT_COUNT),
            check_sequential=env.get_bool("PASSWORD_CHECK_SEQUENTIAL", DEFAULT_CHECK_SEQUENTIAL),
            check_common_passwords=env.get_bool("PASSWORD_CHECK_COMMON", DEFAULT_CHECK_COMMON_PASSWORDS),
            check_dictionary=env.get_bool("PASSWORD_CHECK_DICTIONARY", DEFAULT_CHECK_DICTIONARY),

            custom_regex=env.get("PASSWORD_CUSTOM_REGEX", DEFAULT_CUSTOM_REGEX),
            min_entropy=env.get_int("PASSWORD_MIN_ENTROPY", DEFAULT_MIN_ENTROPY),
            language=env.get("PASSWORD_LANGUAGE", DEFAULT_LANGUAGE)
        )


default_policy = PasswordPolicy.load()

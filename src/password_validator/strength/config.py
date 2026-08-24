"""
Centralized configuration for password strength analysis.
All strength related configuration can be controlled through environment variables.
Python objects can still be supplied explicitly for testing or advanced application-level configuration.
"""
from __future__ import annotations
from dataclasses import dataclass

from src.password_validator.loaders.env_loader import EnvLoader
from .weights import StrengthWeights


@dataclass(slots=True, frozen=True)
class StrengthConfig:
    """
    Central configuration for the password strength sibsystem
    """
    # Analyzer enable/disable flags
    check_repeated_characters: bool = True
    check_sequential_patterns: bool = True
    check_keyboard_patterns: bool = True
    check_dictionary: bool = True
    check_common_passwords: bool = True

    # Repeat configuration
    max_consecutive_repeat: int = 2
    min_repeat_group_length: int = 2

    # Sequential configuration
    min_sequence_length: int = 4

    # Keyboard configuration
    min_keyboard_pattern_length: int = 4

    # Dictionary configuration
    dictionary_file: str | None = None

    common_password_file: str | None = None
    min_dictionary_word_length: int = 4
    dictionary_case_insensitive: bool = True
    dictionary_leet_normalization: bool = True

    # Scoring weights
    weights: StrengthWeights = StrengthWeights()

    @classmethod
    def from_env(cls, env_file: str = ".env"):
        """
        Load complete strength configuration from .env
        :param env_file:
        :return:
        """
        env = EnvLoader(env_file)
        dictionary_file = env.get("STRENGTH_DICTIONARY_FILE", "")
        common_password_file = env.get("STRENGTH_COMMON_PASSWORD_FILE", "")
        weights = StrengthWeights.from_env(env)

        return cls(
            check_repeated_characters=env.get_bool("STRENGTH_CHECK_REPEATED_CHARACTERS", True),
            check_sequential_patterns=env.get_bool("STRENGTH_CHECK_SEQUENTIAL", True),
            check_keyboard_patterns=env.get_bool("STRENGTH_CHECK_KEYBOARD_PATTERNS", True),
            check_common_passwords=env.get_bool("STRENGTH_CHECK_COMMON_PASSWORDS", True),
            check_dictionary=env.get_bool("STRENGTH_CHECK_DICTIONARY", True),
            max_consecutive_repeat=env.get_int("STRENGTH_MAX_CONSECUTIVE_REPEAT", 2),
            min_repeat_group_length=env.get_int("STRENGTH_MIN_REPEAT_GROUP_LENGTH", 2),
            min_sequence_length=env.get_int("STRENGTH_MIN_SEQUENCE_LENGTH", 4),
            min_keyboard_pattern_length=env.get_int("STRENGTH_MIN_KEYBOARD_PATTERN_LENGTH", 4),
            dictionary_file=dictionary_file or None,
            common_password_file=common_password_file or None,
            min_dictionary_word_length=env.get_int("STRENGTH_MIN_DICTIONARY_WORD_LENGTH", 4),
            dictionary_case_insensitive=env.get_bool("STRENGTH_DICTIONARY_CASE_INSENSITIVE", True),
            dictionary_leet_normalization=env.get_bool("STRENGTH_DICTIONARY_LEET_NORMALIZATION", True),
            weights=weights
        )

    @classmethod
    def defaults(cls):
        """
        Return the package defaults.
        Useful for applications that don't use .env.
        :return:
        """
        return cls()

"""
Centralized configuration for password strength analysis.
All strength related configuration can be controlled through environment variables.
Python objects can still be supplied explicitly for testing or advanced application-level configuration.
"""
from __future__ import annotations
from dataclasses import dataclass, field

from ..loaders.env_loader import EnvLoader
from .weights import StrengthWeights


@dataclass(slots=True, frozen=True)
class StrengthConfig:
    """
    Central configuration for the password strength sibsystem
    """
    # Analyzer enable/disable flags
    enabled: bool = True
    check_repeated_characters: bool = True
    check_sequential_patterns: bool = True
    check_keyboard_patterns: bool = True
    check_dictionary_words: bool = True
    check_common_passwords: bool = True
    check_horizontal: bool = True
    check_vertical: bool = True
    check_diagonal: bool = True
    check_number_row: bool = True
    check_consecutive: bool = True
    check_repeated_groups: bool = True

    # Repeat configuration
    max_consecutive_repeat: int = 2
    min_repeated_group_length: int = 2
    min_group_repetitions: int = 2
    check_character_frequency: bool = True
    max_character_frequency: float = 0.33

    # Sequential configuration
    check_uppercase: bool = True
    check_lowercase: bool = True
    check_digits: bool = True
    check_mixed: bool = False
    min_sequence_length: int = 4

    # Keyboard configuration
    min_pattern_length: int = 4

    # Dictionary configuration
    dictionary_file: str | None = None

    common_password_file: str | None = None
    min_dictionary_word_length: int = 4
    case_insensitive: bool = True
    leet_normalization: bool = True

    overall_severity: float = 0.8

    # Scoring weights
    weights: StrengthWeights = field(default_factory=StrengthWeights)

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
            enabled=env.get_bool("STRENGTH_ENABLED", True),
            # Analyzer enable/disable flags
            check_repeated_characters=env.get_bool("STRENGTH_CHECK_REPEATED_CHARACTERS", True),
            check_sequential_patterns=env.get_bool("STRENGTH_CHECK_SEQUENTIAL", True),
            check_keyboard_patterns=env.get_bool("STRENGTH_CHECK_KEYBOARD_PATTERNS", True),
            check_common_passwords=env.get_bool("STRENGTH_CHECK_COMMON_PASSWORDS", True),
            check_dictionary_words=env.get_bool("STRENGTH_CHECK_DICTIONARY", True),
            # Keyboard pattern configuration
            check_horizontal=env.get_bool("STRENGTH_CHECK_HORIZONTAL", True),
            check_vertical=env.get_bool("STRENGTH_CHECK_VERTICAL", True),
            check_diagonal=env.get_bool("STRENGTH_CHECK_DIAGONAL", True),
            check_number_row=env.get_bool("STRENGTH_CHECK_NUMBER_ROW", True),
            # Repeat configuration
            check_consecutive=env.get_bool("STRENGTH_CHECK_CONSECUTIVE", True),
            check_repeated_groups=env.get_bool("STRENGTH_CHECK_REPEATED_GROUPS", True),
            check_character_frequency=env.get_bool("STRENGTH_CHECK_CHARACTER_FREQUENCY", True),
            max_consecutive_repeat=env.get_int("STRENGTH_MAX_CONSECUTIVE_REPEAT", 2),
            min_repeated_group_length=env.get_int("STRENGTH_MIN_REPEAT_GROUP_LENGTH", 2),
            min_group_repetitions=env.get_int("STRENGTH_MIN_GROUP_REPETITIONS", 2),
            max_character_frequency=env.get_float("STRENGTH_MAX_CHARACTER_FREQUENCY", 0.33),
            # Sequential configuration
            check_uppercase=env.get_bool("STRENGTH_CHECK_UPPERCASE", True),
            check_lowercase=env.get_bool("STRENGTH_CHECK_LOWERCASE", True),
            check_digits=env.get_bool("STRENGTH_CHECK_DIGITS", True),
            check_mixed=env.get_bool("STRENGTH_CHECK_MIXED", False),
            min_sequence_length=env.get_int("STRENGTH_MIN_SEQUENCE_LENGTH", 4),
            # Keyboard configuration
            min_pattern_length=env.get_int("STRENGTH_MIN_KEYBOARD_PATTERN_LENGTH", 4),
            # Dictionary configuration
            dictionary_file=dictionary_file or None,
            common_password_file=common_password_file or None,
            min_dictionary_word_length=env.get_int("STRENGTH_MIN_DICTIONARY_WORD_LENGTH", 4),
            case_insensitive=env.get_bool("STRENGTH_DICTIONARY_CASE_INSENSITIVE", True),
            leet_normalization=env.get_bool("STRENGTH_DICTIONARY_LEET_NORMALIZATION", True),
            overall_severity=env.get_float("STRENGTH_OVERALL_SEVERITY", 0.8),
            weights=weights
        )

    @classmethod
    def defaults(cls) -> "StrengthConfig":
        """
        Return the package defaults.
        Useful for applications that don't use .env.
        :return:
        """
        return cls()

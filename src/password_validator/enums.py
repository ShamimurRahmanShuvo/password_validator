"""
Enums used in the password_validator package are defined here.
- Strength
- RuleType
- ErrorCode
"""
from enum import Enum


class RuleType(str, Enum):
    """
    Supported validation rule types for password validation.
    """

    LENGTH = "length"
    UPPERCASE = "uppercase"
    LOWERCASE = "lowercase"
    DIGIT = "digit"
    SPECIAL = "special"
    WHITESPACE = "whitespace"
    REPEATED = "repeated"
    SEQUENTIAL = "sequential"
    BLACKLIST = "blacklist"
    COMMON_PASSWORDS = "common_passwords"
    DICTIONARY = "dictionary"
    REGEX = "regex"
    USERNAME = "username"
    ENTROPY = "entropy"
    HISTORY = "history"


class StrengthLevel(str, Enum):
    """
    Supported strength levels for password validation.
    """
    VERY_WEAK = "very_weak"
    WEAK = "weak"
    FAIR = "fair"
    GOOD = "good"
    STRONG = "strong"
    VERY_STRONG = "very_strong"


class ErrorCode(str, Enum):
    """
    Supported error codes for password validation.
    """
    TOO_SHORT = "PASSWORD_TOO_SHORT"
    TOO_LONG = "PASSWORD_TOO_LONG"
    MISSING_UPPERCASE = "PASSWORD_MISSING_UPPERCASE"
    MISSING_LOWERCASE = "PASSWORD_MISSING_LOWERCASE"
    MISSING_DIGIT = "PASSWORD_MISSING_DIGIT"
    MISSING_SPECIAL = "PASSWORD_MISSING_SPECIAL"
    CONTAINS_SPACE = "PASSWORD_CONTAINS_SPACE"
    TOO_MANY_REPEATS = "PASSWORD_TOO_MANY_REPEATS"
    SEQUENTIAL_PATTERN = "PASSWORD_SEQUENTIAL_PATTERN"
    COMMON_PASSWORD = "PASSWORD_COMMON_PASSWORD"
    DICTIONARY_WORD = "PASSWORD_DICTIONARY_WORD"
    INVALID_REGEX = "PASSWORD_INVALID_REGEX"
    USERNAME_IN_PASSWORD = "USERNAME_IN_PASSWORD"
    LOW_ENTROPY = "PASSWORD_LOW_ENTROPY"
    PASSWORD_HISTORY_VIOLATION = "PASSWORD_HISTORY_VIOLATION"
    BLACKLISTED_PASSWORD = "BLACKLISTED_PASSWORD"


class ValidationMode(str, Enum):
    """
    Supported validation modes for password validation.
    """
    STRICT = "strict"
    NORMAL = "normal"
    LENIENT = "lenient"

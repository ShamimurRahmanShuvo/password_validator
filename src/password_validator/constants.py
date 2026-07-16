"""
All constants used in the password_validator package are defined here.
- DEFAULT_SPECIAL_CHARACTERS
- DEFAULT_BLACKLIST
- DEFAULT_MIN_LENGTH
- DEFAULT_ENTROPY
"""
# Password defaults
DEFAULT_MIN_LENGTH = 8
DEFAULT_MAX_LENGTH = 64

DEFAULT_REQUIRE_UPPERCASE = True
DEFAULT_REQUIRE_LOWERCASE = True
DEFAULT_REQUIRE_DIGIT = True
DEFAULT_REQUIRE_SPECIAL = True

# Character defaults
DEFAULT_SPECIAL_CHARACTERS = "!@#$%^&*()-_=+[]{}|;:'\",.<>?/`~"

DEFAULT_MIN_UPPERCASE = 1
DEFAULT_MIN_LOWERCASE = 1
DEFAULT_MIN_DIGITS = 1
DEFAULT_MIN_SPECIAL = 1

# Security defaults
DEFAULT_MAX_REPEAT_COUNT = 3
DEFAULT_MIN_ENTROPY = 40

# Password policies
DEFAULT_ALLOW_SPACES = False
DEFAULT_CHECK_SEQUENTIAL = True
DEFAULT_CHECK_COMMON_PASSWORDS = True
DEFAULT_CHECK_DICTIONARY = True

# Regex
DEFAULT_CUSTOM_REGEX = None

# Language defaults
DEFAULT_LANGUAGE = "en"

# Common sequences and patterns
SEQUENTIAL_PATTERNS = [
    "abcdefghijklmnopqrstuvwxyz",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "0123456789"
]

# Common password file
DEFAULT_COMMON_PASSWORDS_FILE = "resources/common_passwords.txt"
DEFAULT_DICTIONARY_FILE = "resources/dictionary.txt"

# Error messages
DEFAULT_ERROR_PREFIX = (
    "Password validation failed"
)

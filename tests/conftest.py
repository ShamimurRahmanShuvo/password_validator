"""
Shared pytest fixtures for the password_validator test suite
"""
from __future__ import annotations

import pytest

from password_validator.config.settings import PasswordRuleConfig, Settings
from password_validator.strength.config import StrengthConfig
from password_validator.strength.weights import StrengthWeights

# ---------------------------------------------------------------------------
# Password fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def valid_password() -> str:
    """
    A password that satisfies the default password rules.
    :return:
    """
    return "MySecurePassword123!"


@pytest.fixture
def weak_password() -> str:
    """
    A deliverately weak password
    :return:
    """
    return "password"


@pytest.fixture
def short_password() -> str:
    """
    Password shorter than minimum length.
    :return:
    """
    return "Ab1"


@pytest.fixture
def password_without_uppercase() -> str:
    """
    Password missing uppercase characters
    :return:
    """
    return "mysecurepassword123!"


@pytest.fixture
def password_without_lowercase() -> str:
    """
    Password missing lowercase characters
    :return:
    """
    return "MYSECUREPASSWORD123!"


@pytest.fixture
def password_without_digit() -> str:
    """
    Password missing digit
    :return:
    """
    return "mysecurepassworD!"


@pytest.fixture
def password_without_special() -> str:
    """
    Password missing special character
    :return:
    """
    return "Mysecurepassword123"


@pytest.fixture
def password_with_sequence() -> str:
    """
    Password containing a sequential pattern
    :return:
    """
    return "Mysecurepassword1234!"


@pytest.fixture
def password_with_reverse_sequence() -> str:
    """
    Password containing a descending sequence
    :return:
    """
    return "MySecurePassword4321!"


@pytest.fixture
def password_with_repetition() -> str:
    """
    Password containing repeated characters
    :return:
    """
    return "MySecurePassssword123!"


@pytest.fixture
def password_with_repeated_pattern() -> str:
    """
    Password containing a repeated pattern
    :return:
    """
    return "MyTestTest123123!"


@pytest.fixture
def keyboard_password() -> str:
    """
    Password containing a keyboard pattern
    :return:
    """
    return "MyQWERTY123!"


@pytest.fixture
def numeric_keyboard_password() -> str:
    """
    Password containing a keyboard pattern involving numbers.
    """
    return "My1qazPassword!"


@pytest.fixture
def dictionary_password() -> str:
    """
    Common/dictionary-style password used by dictionary tests.
    """
    return "password"


# ---------------------------------------------------------------------------
# Configuration fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def default_strength_weights() -> StrengthWeights:
    """
    Return the built-in strength weights.
    """
    return StrengthWeights.defaults()


@pytest.fixture
def default_strength_config() -> StrengthConfig:
    """
    Return the default strength configuration.
    """
    return StrengthConfig.defaults()


@pytest.fixture
def default_rule_config() -> PasswordRuleConfig:
    """
    Return the default password rule configuration.
    """
    return PasswordRuleConfig.defaults()


@pytest.fixture
def default_settings() -> Settings:
    """
    Return the default application settings.
    """
    return Settings(
        rules=PasswordRuleConfig.defaults(),
        strength=StrengthConfig.defaults(),
    )


# ---------------------------------------------------------------------------
# Environment fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def clean_environment(monkeypatch):
    """
    Remove password-validator-related environment variables.

    Useful when testing configuration loading so tests don't accidentally
    depend on the developer's local environment.
    """

    prefixes = (
        "PASSWORD_",
        "STRENGTH_",
    )

    import os

    existing = [
        key
        for key in os.environ
        if key.startswith(prefixes)
    ]

    for key in existing:
        monkeypatch.delenv(
            key,
            raising=False,
        )

    return monkeypatch

"""
Unit tests for SpecialCharacterRule
"""
import pytest
from password_validator.rules.special import SpecialCharacterRule

DEFAULT_SPECIAL_CHARACTERS = "!@#$%^&*()-_=+[]{};:'\",.<>?/\\|`~"


class TestSpecialCharacterRule:
    """
    Tests for Special Character
    """
    @pytest.fixture
    def rule(self):
        return SpecialCharacterRule(
            special_characters=DEFAULT_SPECIAL_CHARACTERS
        )

    def test_password_with_special_character_passes(self, rule):
        result = rule.validate("Password123!")

        assert result.passed is True

    def test_password_without_special_character_fails(self, rule):
        result = rule.validate("Password123")

        assert result.passed is False

    def test_empty_password_fails(self, rule):
        result = rule.validate("")

        assert result.passed is False

    @pytest.mark.parametrize(
        "special_character",
        [
            "!",
            "@",
            "#",
            "$",
            "%",
            "^",
            "&",
            "*",
            "(",
            ")",
            "-",
            "_",
            "=",
            "+",
            "[",
            "]",
            "{",
            "}",
            ";",
            ":",
            ",",
            ".",
            "<",
            ">",
            "?",
            "/",
            "\\",
            "|",
            "`",
            "~",
        ],
    )
    def test_supported_special_characters_pass(
            self,
            rule,
            special_character,
    ):
        password = f"Password123{special_character}"

        result = rule.validate(password)

        assert result.passed is True

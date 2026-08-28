"""
Unit tests for EnvLoader
"""
import pytest

from password_validator.exceptions import InvalidConfigurationValue
from password_validator.loaders.env_loader import EnvLoader


class TestEnvLoader:
    """
    Tests for EnvLoader.
    """
    def test_get_returns_environment_value(self, monkeypatch):
        monkeypatch.setenv("TEST_PASSWORD_MIN_LENGTH", "12")
        loader = EnvLoader()
        result = loader.get("TEST_PASSWORD_MIN_LENGTH")

        assert result == "12"

    def test_get_returns_default_when_variable_missing(self):
        loader = EnvLoader()
        result = loader.get("VARIABLE_THAT_DOES_NOT_EXISTS", default="default-value")

        assert result == "default-value"

    def test_get_returns_none_when_missing_and_no_default(self):
        loader = EnvLoader()
        result = loader.get("VARIABLE_THAT_DOES_NOT_EXISTS")

        assert result is None

    def test_get_int_returns_integer(self, monkeypatch):
        monkeypatch.setenv("TEST_MIN_LENGTH", "12")
        loader = EnvLoader()
        result = loader.get_int("TEST_MIN_LENGTH")

        assert result == 12
        assert isinstance(result, int)

    def test_get_int_returns_default(self):
        loader = EnvLoader()
        result = loader.get_int("MISSING_MIN_LENGTH", default=8)

        assert result == 8

    def test_get_int_rejects_invalid_value(self, monkeypatch):
        monkeypatch.setenv("TEST_MIN_LENGTH", "abc")
        loader = EnvLoader()

        with pytest.raises(InvalidConfigurationValue) as exc_info:
            loader.get_int("TEST_MIN_LENGTH")

        error = exc_info.value

        assert error.key == "TEST_MIN_LENGTH"
        assert error.value == "abc"
        assert error.expected == "integer"

    def test_get_bool_accepts_true(self, monkeypatch):
        monkeypatch.setenv("TEST_REQUIRE_UPPERCASE", "true")
        loader = EnvLoader()
        result = loader.get_bool("TEST_REQUIRE_UPPERCASE")

        assert result is True

    def test_get_bool_accepts_false(self, monkeypatch):
        monkeypatch.setenv("TEST_REQUIRE_UPPERCASE", "false")
        loader = EnvLoader()
        result = loader.get_bool("TEST_REQUIRE_UPPERCASE")

        assert result is False

    @pytest.mark.parametrize(
        "value",
        [
            "TRUE",
            "True",
            "true",
            "1",
            "yes",
            "YES",
            "on",
            "ON",
        ],
    )
    def test_get_bool_accepts_true_variants(
            self,
            monkeypatch,
            value,
    ):
        monkeypatch.setenv(
            "TEST_BOOLEAN",
            value,
        )

        loader = EnvLoader()

        assert loader.get_bool("TEST_BOOLEAN") is True

    @pytest.mark.parametrize(
        "value",
        [
            "FALSE",
            "False",
            "false",
            "0",
            "no",
            "NO",
            "off",
            "OFF",
        ],
    )
    def test_get_bool_accepts_false_variants(
            self,
            monkeypatch,
            value,
    ):
        monkeypatch.setenv(
            "TEST_BOOLEAN",
            value,
        )

        loader = EnvLoader()

        assert loader.get_bool("TEST_BOOLEAN") is False

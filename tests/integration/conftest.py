from pathlib import Path
import pytest


@pytest.fixture
def env_file(tmp_path) -> Path:
    """Create an empty temporary .env file"""
    path = tmp_path/".env"
    path.write_text("")
    return path


@pytest.fixture
def configured_env_file(tmp_path: Path) -> Path:
    """Create a fully confiigured .env file"""
    path = tmp_path / ".env"
    path.write_text(
        "\n".join(
            [
                "PASSWORD_MIN_LENGTH=10",
                "PASSWORD_MAX_LENGTH=64",
                "PASSWORD_REQUIRE_UPPERCASE=true",
                "PASSWORD_REQUIRE_LOWERCASE=true",
                "PASSWORD_REQUIRE_DIGIT=true",
                "PASSWORD_REQUIRE_SPECIAL=true",
                "PASSWORD_SPECIAL_CHARACTERS=@#$%^&*"
            ]
        )
    )
    return path


@pytest.fixture
def dictionary_file(tmp_path: Path) -> Path:
    """ Create a temporary dictionary file. """
    path = tmp_path / "dictionary.txt"
    path.write_text(
        "\n".join(
            [
                "# comments are ignored",
                "password",
                "welcome",
                "administrator",
                "computer",
                "security",
                "dragon",
                "testing"
            ]
        )
    )
    return path


@pytest.fixture
def common_password_file(tmp_path: Path) -> Path:
    """ Create a temporary common-password file. """
    path = tmp_path / "common_passwords.txt"
    path.write_text(
        "\n".join(
            [
                "password",
                "password123",
                "welcome",
                "admin",
                "qwerty",
                "letmein"
            ]
        )
    )
    return path

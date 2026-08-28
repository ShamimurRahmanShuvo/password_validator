"""
Environment configuration loader.
"""
from __future__ import annotations

import os
from pathlib import Path
from ..exceptions import InvalidConfigurationValue


class EnvLoader:
    """
    Loads and converts environment variables into a configuration dictionary.
    """
    def __init__(self, env_file: str | None = ".env") -> None:
        """
        Initializes the EnvLoader.

        :param env_file: Path to the .env file. Defaults to ".env".
        """
        self._values: dict[str, str] = {}

        if env_file:
            self._load_env_file(env_file)

        self._load_environment()

    def _load_env_file(self, env_file: str) -> None:
        path = Path(env_file)

        if not path.exists():
            return

        for raw_line in path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()

            if not line:
                continue
            if line.startswith("#"):
                continue
            if "=" not in line:
                continue

            key, value = line.split("=", 1)

            key = key.strip()
            value = value.strip()

            if (len(value) >= 2 and
                    value[0] == value[-1] and
                    value[0] in {'"', '"'}):
                value = value[1:-1]

            self._values[key] = value

    def _load_environment(self) -> None:
        """
        Environment variables override values from .env
        :return:
        """
        for key, value in os.environ.items():
            self._values[key] = value

    def get(self, key: str, default: str = None) -> str:
        """
        Retrieves the value of an environment variable.

        :param key: The environment variable key.
        :param default: The default value if the key is not found.
        :return: The value of the environment variable or the default.
        """
        return os.getenv(key, default)

    def get_bool(self, key: str, default: bool = False) -> bool:
        """
        Retrieves the value of an environment variable as a boolean.

        :param key: The environment variable key.
        :param default: The default boolean value if the key is not found.
        :return: The boolean value of the environment variable or the default.
        """
        value = self.get(key)

        if value is None:
            return default

        normalized = value.strip().lower()

        if normalized in ['true', '1', 'yes', 'y', "on"]:
            return True

        if value.lower() in ['false', '0', 'no', 'n', "off"]:
            return False

        raise InvalidConfigurationValue(f"Invalid boolean value for {key}: {value}")

    def get_int(self, key: str, default: int = 0) -> int:
        """
        Retrieves the value of an environment variable as an integer.

        :param key: The environment variable key.
        :param default: The default integer value if the key is not found.
        :return: The integer value of the environment variable or the default.
        """
        value = self.get(key)

        if value is None:
            return default

        try:
            return int(value)
        except ValueError:
            raise InvalidConfigurationValue(key, value, "integer") from None

    def get_list(self, key: str, default: list[str] = None, delimiter: str = ',') -> list[str]:
        """
        Retrieves the value of an environment variable as a list.

        :param key: The environment variable key.
        :param default: The default list value if the key is not found.
        :param delimiter: The delimiter used to split the string into a list. Defaults to ','.
        :return: The list value of the environment variable or the default.
        """
        value = self.get(key, default)

        if isinstance(value, list):
            return value

        if isinstance(value, str):
            return [item.strip() for item in value.split(delimiter) if item.strip()]

        raise InvalidConfigurationValue(f"{key}: {value} must be a list or a string")

    def get_float(self, key: str, default: float = 0.0) -> float:
        """
        Retrieves the value of an environment variable as a float.

        :param key: The environment variable key.
        :param default: The default float value if the key is not found.
        :return: The float value of the environment variable or the default.
        """
        value = self.get(key)
        if value is None:
            return default

        try:
            return float(value)
        except (TypeError, ValueError) as exc:
            raise InvalidConfigurationValue(f"{key}: {value} must be a valid float") from exc

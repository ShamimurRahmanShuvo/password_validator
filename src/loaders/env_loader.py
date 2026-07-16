"""
Environment configuration loader.
"""

import os
from dotenv import load_dotenv
from src.password_validator.exceptions import InvalidConfigurationValue


class EnvLoader:
    """
    Loads and converts environment variables into a configuration dictionary.
    """
    def __init__(self, env_file: str = ".env"):
        """
        Initializes the EnvLoader.

        :param env_file: Path to the .env file. Defaults to ".env".
        """
        self.env_file = env_file
        load_dotenv(self.env_file)

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
        value = self.get(key, default)

        if isinstance(value, bool):
            return value

        if value.lower() in ['true', '1', 'yes', 'y']:
            return True

        if value.lower() in ['false', '0', 'no', 'n']:
            return False

        raise InvalidConfigurationValue(f"Invalid boolean value for {key}: {value}")

    def get_int(self, key: str, default: int = 0) -> int:
        """
        Retrieves the value of an environment variable as an integer.

        :param key: The environment variable key.
        :param default: The default integer value if the key is not found.
        :return: The integer value of the environment variable or the default.
        """
        value = self.get(key, default)

        try:
            return int(value)
        except ValueError:
            raise InvalidConfigurationValue(f"{key}: {value} must be an integer")

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

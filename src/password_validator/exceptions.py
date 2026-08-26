"""
All exceptions used in the password_validator package are defined here.
- PasswordValidationError
- ConfigurationError
- RuleConfigurationError
"""


class PasswordValidatorError(Exception):
    """Raised when a password fails validation."""
    pass


class ConfigurationError(PasswordValidatorError):
    """Raised when there is an issue with the configuration."""
    pass


class MissingConfigurationError(ConfigurationError):
    """Raised when a required configuration is missing."""
    pass


class RuleConfigurationError(ConfigurationError):
    """Raised when there is an issue with a specific rule's configuration."""
    pass


class InvalidConfigurationValue(PasswordValidatorError):
    """Raised when a configuration value is invalid."""
    """
        Raised when an environment/configuration value
        has an invalid type or format.
        """

    def __init__(
            self,
            key: str,
            value: object,
            expected: str,
    ) -> None:
        super().__init__(
            f"Invalid configuration value for "
            f"'{key}': {value!r}. "
            f"Expected {expected}."
        )

        self.key = key
        self.value = value
        self.expected = expected

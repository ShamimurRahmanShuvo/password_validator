"""
All exceptions used in the password_validator package are defined here.
- PasswordValidationError
- ConfigurationError
- RuleConfigurationError
"""


class PasswordValidatorException(Exception):
    """Raised when a password fails validation."""
    pass


class ConfigurationError(PasswordValidatorException):
    """Raised when there is an issue with the configuration."""
    pass


class MissingConfigurationError(ConfigurationError):
    """Raised when a required configuration is missing."""
    pass


class RuleConfigurationError(ConfigurationError):
    """Raised when there is an issue with a specific rule's configuration."""
    pass


class InvalidConfigurationValue(ConfigurationError):
    """Raised when a configuration value is invalid."""
    pass

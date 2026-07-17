"""
Entry point for the password_validator package.
A configurable password validation library that allows users to define custom rules and
criteria for password strength and security.
"""
from .version import (
    __title__,
    __version__,
    __author__,
    __description__
)
from .config import PasswordPolicy, default_policy
from models import ValidationResult, ValidationError, RuleResult
from src.rules import ValidationRule, RuleRegistry
from validator import PasswordValidator
from engine import ValidationEngine


# Package metadata
VERSION = __version__

__all__ = [
    "__version__",
    "__title__",
    "__author__",
    "__description__",
    "VERSION",
    "PasswordPolicy",
    "default_policy",
    "ValidationResult",
    "ValidationError",
    "RuleResult",
    "ValidationRule",
    "RuleRegistry",
    "PasswordValidator",
    "ValidationEngine"
]

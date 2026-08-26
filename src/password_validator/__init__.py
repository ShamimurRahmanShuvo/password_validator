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
from .config.settings import PasswordRuleConfig, Settings
from .engine.validator import PasswordValidator, ValidationResult
from .rules.base import Rule, RuleResult
from .rules.digits import DigitsRule
from .rules.length import LengthRule
from .rules.lowercase import LowercaseRule
from .rules.special import SpecialCharacterRule
from .rules.uppercase import UppercaseRule
from .strength.config import StrengthConfig
from .strength.scorer import PasswordStrengthScorer, StrengthResult
from .strength.weights import StrengthWeights

# Package metadata
VERSION = __version__

__all__ = [
    # Package Metadata
    "__version__",
    "__title__",
    "__author__",
    "__description__",
    "VERSION",

    # Main API
    "PasswordValidator",
    "ValidationResult",
    "PasswordStrengthScorer",
    "StrengthResult",

    # Configuration
    "Settings",
    "PasswordRuleConfig",
    "StrengthConfig",
    "StrengthWeights",

    # Rule framework
    "Rule",
    "RuleResult",

    # Built-in rules
    "LengthRule",
    "UppercaseRule",
    "LowercaseRule",
    "DigitsRule",
    "SpecialCharacterRule"
]

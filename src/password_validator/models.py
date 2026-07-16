"""
Contains data models.
- ValidationResult
- PasswordStrength
- RuleResult
- PasswordPolicy
"""
from dataclasses import dataclass, field
from typing import List, Optional
from enums import RuleType, StrengthLevel, ErrorCode


@dataclass
class RuleResult:
    """
    Represents the result of a single password validation rule.
    """
    rule: RuleType
    passed: bool
    error_code: Optional[ErrorCode] = None
    message: Optional[str] = None


@dataclass
class ValidationError:
    """
    Represents a validation error for a password.
    """
    rule: RuleType
    code: ErrorCode
    message: str


@dataclass
class ValidationResult:
    """
    Represents the result of password validation.
    """
    valid: bool
    errors: List[ValidationError] = field(default_factory=list)

    passed_rules: List[RuleType] = field(default_factory=list)
    failed_rules: List[RuleType] = field(default_factory=list)

    score: int = 0

    strength: Optional[StrengthLevel] = None

    def add_result(self, result: RuleResult):
        """
        Adds a rule result to the validation result.
        """
        if result.passed:
            self.passed_rules.append(result.rule)
        else:
            self.valid = False

            self.failed_rules.append(result.rule)
            self.errors.append(
                ValidationError(
                    rule=result.rule,
                    code=result.error_code,
                    message=result.message
                )
            )

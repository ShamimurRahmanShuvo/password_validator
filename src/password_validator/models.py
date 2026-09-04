"""
Contains data models.
- ValidationResult
- ValidationError
- RuleResult
"""
from dataclasses import dataclass, field
from typing import Any, List, Optional
from .enums import Rule, ErrorCode


@dataclass(slots=True)
class RuleResult:
    """
    Represents the result of a single password validation rule.
    """
    rule: Rule
    passed: bool
    error_code: Optional[ErrorCode] = None
    message: Optional[str] = None
    details: dict[str, Any] | None = None


@dataclass(slots=True)
class ValidationError:
    """
    Represents a validation error for a password.
    """
    rule: Rule
    code: Optional[ErrorCode]
    message: str


@dataclass(slots=True)
class ValidationResult:
    """
    Represents the result of password validation.
    """
    valid: bool
    errors: List[ValidationError] = field(default_factory=list)

    passed: List[Rule] = field(default_factory=list)
    failed: List[Rule] = field(default_factory=list)
    rule_result: List[RuleResult] = field(default_factory=list)

    def add_result(self, result: RuleResult):
        """
        Add a rule result to the validation result.
        A passed rule is added to ``passed``.
        A failed rule is added to ``failed`` and creates a corresponding ValidationError.
        Any failed rule makes the overall validation result invalid.
        """
        self.rule_result.append(result)

        if result.passed:
            self.passed.append(result.rule)
            return

        self.valid = False

        self.failed.append(result.rule)
        self.errors.append(
            ValidationError(
                rule=result.rule,
                code=result.error_code,
                message=result.message or ""
            )
        )

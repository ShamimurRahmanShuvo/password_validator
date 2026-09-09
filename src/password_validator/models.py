"""
Contains data models.

- RuleResult
- ValidationError
- ValidationResult
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from .enums import ErrorCode, Rule


class _ResultList(list):
    """
    Mutable list that is also compatible with tuple-based equality checks.

    This provides backward compatibility between:
        result.passed == []
    and:
        result.passed == ()

    while retaining list behavior such as:
        result.passed.append(...)
    """

    def __eq__(self, other: object) -> bool:
        if isinstance(other, (list, tuple)):
            return list(self) == list(other)
        return super().__eq__(other)


@dataclass(slots=True)
class RuleResult:
    """
    Result of evaluating a single password validation rule.

    This is the model-level RuleResult. The validation engine may also
    produce its own RuleResult implementation from rules.base.
    """

    rule: Rule
    passed: bool
    error_code: Optional[ErrorCode] = None
    message: Optional[str] = None
    details: dict[str, Any] | None = None

    @property
    def rule_name(self) -> str:
        """Return a stable name for the rule."""

        if hasattr(self.rule, "value"):
            return str(self.rule.value)

        return str(self.rule)


@dataclass(slots=True)
class ValidationError:
    """Represents a validation error for a password rule."""

    rule: Any
    code: Optional[ErrorCode]
    message: str


class ValidationResult:
    """
    Represents the complete result of password validation.

    The result supports both the model-level mutable-list API and the
    validation-engine tuple API.

    Explicit tuple values remain tuples.
    Default collections are mutable independent lists.
    """

    __slots__ = (
        "valid",
        "passed",
        "failed",
        "errors",
        "rule_result",
    )

    def __init__(
        self,
        valid: bool,
        passed: tuple[Any, ...] | list[Any] | None = None,
        failed: tuple[Any, ...] | list[Any] | None = None,
        errors: tuple[Any, ...] | list[Any] | None = None,
        rule_result: tuple[Any, ...] | list[Any] | None = None,
        *,
        rule_results: tuple[Any, ...] | list[Any] | None = None,
    ) -> None:
        """
        Create a validation result.

        Args:
            valid: Overall validation status.
            passed: Passed rule identifiers.
            failed: Failed rule identifiers.
            errors: Validation error messages/errors.
            rule_result: Rule evaluation results.
            rule_results: Compatibility alias for rule_result.
        """

        self.valid = valid

        self.passed = (
            _ResultList()
            if passed is None
            else passed
        )

        self.failed = (
            _ResultList()
            if failed is None
            else failed
        )

        self.errors = (
            _ResultList()
            if errors is None
            else errors
        )

        if rule_results is not None:
            self.rule_result = rule_results
        else:
            self.rule_result = (
                _ResultList()
                if rule_result is None
                else rule_result
            )

    @property
    def is_valid(self) -> bool:
        """Return whether the password passed validation."""

        return self.valid

    @property
    def error_count(self) -> int:
        """Return the number of validation errors."""

        if self.errors:
            return len(self.errors)

        return len(self.failed)

    @property
    def has_errors(self) -> bool:
        """Return True when one or more validation errors exist."""

        return self.error_count > 0

    @property
    def passed_count(self) -> int:
        """Return the number of passed rules."""

        return len(self.passed)

    @property
    def failed_count(self) -> int:
        """Return the number of failed rules."""

        return len(self.failed)

    @property
    def rule_results(self) -> tuple[Any, ...] | list[Any]:
        """
        Compatibility alias for rule_result.
        """

        return self.rule_result

    @rule_results.setter
    def rule_results(
        self,
        value: tuple[Any, ...] | list[Any],
    ) -> None:
        """Set rule results through the compatibility alias."""

        self.rule_result = value

    def add_result(self, result: Any) -> None:
        """
        Add a single rule result.

        The supplied result must expose:
            - passed
            - rule_name or rule
            - message
            - error_code
        """

        self._ensure_mutable_collections()

        self.rule_result.append(result)

        rule_identifier = self._get_rule_identifier(result)

        if result.passed:
            if rule_identifier is not None:
                self.passed.append(rule_identifier)

            return

        self.valid = False

        if rule_identifier is not None:
            self.failed.append(rule_identifier)

        self.errors.append(
            ValidationError(
                rule=rule_identifier,
                code=getattr(result, "error_code", None),
                message=getattr(result, "message", None) or "",
            )
        )

    def _ensure_mutable_collections(self) -> None:
        """Convert tuple-backed collections to mutable lists when required."""

        if isinstance(self.passed, tuple):
            self.passed = list(self.passed)

        if isinstance(self.failed, tuple):
            self.failed = list(self.failed)

        if isinstance(self.errors, tuple):
            self.errors = list(self.errors)

        if isinstance(self.rule_result, tuple):
            self.rule_result = list(self.rule_result)

    @staticmethod
    def _get_rule_identifier(result: Any) -> Any:
        """
        Extract a rule identifier from a rule result.

        Prefer rule_name when available. Otherwise use rule.
        """

        rule_name = getattr(result, "rule_name", None)

        if rule_name is not None:
            return rule_name

        return getattr(result, "rule", None)


__all__ = [
    "RuleResult",
    "ValidationError",
    "ValidationResult",
]

"""
Base classes for password validation rules.

All password policy rules should inherit from Rule and return a
RuleResult from validate().
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass(slots=True, frozen=True)
class RuleResult:
    """
    Result produced by a password validation rule
    """
    passed: bool
    rule_name: str
    message: str | None = None
    code: str | None = None
    metadata: dict[str, Any] | None = None

    @property
    def failed(self) -> bool:
        """
        :return: True when the rule failed
        """
        return not self.passed


class Rule(ABC):
    """
    Abstract base class for password validation rules.
    A rule has one responsibility: password -> RuleResult
    Rules should not:
        - read environment variables
        - load configuration files
        - calculate overall password strength
        - modify other rules
        - store the password

    Configuration should be injected into the rule when it is
    constructed.
    """

    name: str = "base"

    @abstractmethod
    def validate(self, password: str) -> RuleResult:
        """
        Validate the given password against the rule.

        Args:
            password (str): The password to validate.
            policy (PasswordRuleConfig): The password policy to use for validation.

        Returns:
            RuleResult: The result of the validation.
        """
        raise NotImplementedError

    def _passed(self, message: str | None = None, metadata: dict[str, any] | None = None) -> RuleResult:
        """
        Create a successful RuleResult
        :param message:
        :param metadata:
        :return:
        """
        return RuleResult(
            passed=True,
            rule_name=self.name,
            message=message,
            code=None,
            metadata=metadata
        )

    def _failed(self, message: str | None = None,
                code: str | None = None,
                metadata: dict[str, any] | None = None) -> RuleResult:
        """
        Create a failed RuleResult
        """
        return RuleResult(
            passed=False,
            rule_name=self.name,
            message=message,
            code=code,
            metadata=metadata
        )

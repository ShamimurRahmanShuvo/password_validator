"""
Unit tests for the password rule framework
"""
import pytest

from password_validator.rules.base import Rule, RuleResult


class ConcreteRule(Rule):
    """
    Minimum concrete rule used to test the Rule base class
    """
    name = "test_rule"

    def validate(self, password: str) -> RuleResult:
        if password == "valid":
            return RuleResult(
                rule_name=self.name,
                passed=True,
                message="Password is valid"
            )

        return RuleResult(
            rule_name=self.name,
            passed=False,
            message="Password is invalid"
        )


class TestRuleResult:
    """
    Tests for RuleResult
    """
    def test_successful_result(self):
        result = RuleResult(
            rule_name="test_rule",
            passed=True,
            message="Password is valid"
        )

        assert result.rule_name == "test_rule"
        assert result.passed is True
        assert result.message == "Password is valid"

    def test_failed_result(self):
        result = RuleResult(
            rule_name="test_rule",
            passed=False,
            message="Password is invalid"
        )

        assert result.rule_name == "test_rule"
        assert result.passed is False
        assert result.message == "Password is invalid"

    def test_result_has_boolean_passed_value(self):
        result = RuleResult(
            rule_name="test_rule",
            passed=True,
            message="Password is valid"
        )

        assert isinstance(result.passed, bool)


class TestRule:
    """
    Tests for the rule base class
    """
    def test_concrete_rule_can_be_created(self):
        rule = ConcreteRule()

        assert rule is not None

    def test_rule_name(self):
        rule = ConcreteRule()

        assert rule.name == "test_rule"

    def test_rule_returns_success(self):
        rule = ConcreteRule()
        result = rule.validate("valid")

        assert isinstance(result, RuleResult)
        assert result.passed is True

    def test_rule_returns_failure(self):
        rule = ConcreteRule()
        result = rule.validate("invalid")

        assert isinstance(result, RuleResult)
        assert result.passed is False

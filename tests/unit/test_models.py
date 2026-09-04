"""
Unit Tests for Models module
"""
import pytest
from password_validator.models import RuleResult, ValidationResult, ValidationError
from password_validator.enums import Rule, ErrorCode


def enum_member(enum_cls):
    return next(iter(enum_cls))


class TestRuleResult:
    def test_minimal_rule_result(self):
        rule = enum_member(Rule)
        result = RuleResult(rule=rule, passed=True)

        assert result.rule == rule
        assert result.passed is True
        assert result.error_code is None
        assert result.message is None
        assert result.details is None

    def test_create_failed_rule_result(self):
        rule = enum_member(Rule)
        error_code = enum_member(ErrorCode)
        result = RuleResult(rule=rule, passed=False, error_code=error_code, message="Password is too short",
                            details={"minimum": 12}, )
        assert result.rule == rule
        assert result.passed is False
        assert result.error_code == error_code
        assert result.message == "Password is too short"
        assert result.details == {"minimum": 12}


class TestValidationError:
    def test_create_validation_error(self):
        rule = enum_member(Rule)
        error_code = enum_member(ErrorCode)
        error = ValidationError( rule=rule, code=error_code, message="Password validation failed")
        assert error.rule == rule
        assert error.code == error_code
        assert error.message == "Password validation failed"

    def test_validation_error_equality(self):
        rule = enum_member(Rule)
        error_code = enum_member(ErrorCode)
        error1 = ValidationError( rule=rule, code=error_code, message="Validation failed", )
        error2 = ValidationError( rule=rule, code=error_code, message="Validation failed", )
        assert error1 == error2


class TestValidationResult:
    def test_create_valid_result(self):
        result = ValidationResult(valid=True)
        assert result.valid is True
        assert result.errors == []
        assert result.passed == []
        assert result.failed == []
        assert result.rule_result == []

    def test_create_invalid_result(self):
        result = ValidationResult(valid=False)
        assert result.valid is False
        assert result.errors == []
        assert result.passed == []
        assert result.failed == []
        assert result.rule_result == []

    def test_default_lists_are_independent(self):
        result1 = ValidationResult(valid=True)
        result2 = ValidationResult(valid=True)
        result1.passed.append(enum_member(Rule))
        assert result1.passed != result2.passed
        assert result2.passed == []

    def test_add_passed_rule(self):
        rule = enum_member(Rule)
        result = ValidationResult(valid=True)
        rule_result = RuleResult( rule=rule, passed=True)
        result.add_result(rule_result)
        assert result.valid is True
        assert result.passed == [rule]
        assert result.failed == []
        assert result.rule_result == [rule_result]
        assert result.errors == []

    def test_add_failed_rule(self):
        rule = enum_member(Rule)
        error_code = enum_member(ErrorCode)
        result = ValidationResult(valid=True)
        rule_result = RuleResult( rule=rule, passed=False,
                                  error_code=error_code, message="Password does not satisfy rule")
        result.add_result(rule_result)
        assert result.valid is False
        assert result.passed == []
        assert result.failed == [rule]
        assert result.rule_result == [rule_result]
        assert len(result.errors) == 1
        error = result.errors[0]
        assert error.rule == rule
        assert error.code == error_code
        assert error.message == "Password does not satisfy rule"

    def test_failed_rule_invalidates_previously_valid_result(self):
        rule = enum_member(Rule)
        error_code = enum_member(ErrorCode)
        result = ValidationResult(valid=True)
        result.add_result( RuleResult( rule=rule, passed=False, error_code=error_code, message="Validation failed") )
        assert result.valid is False

    def test_multiple_rule_results(self):
        rules = list(Rule)
        if len(rules) < 2:
            pytest.skip("At least two Rule enum members are required")
        rule1 = rules[0]
        rule2 = rules[1]
        error_code = enum_member(ErrorCode)
        result = ValidationResult(valid=True)
        passed_result = RuleResult( rule=rule1, passed=True, )
        failed_result = RuleResult( rule=rule2, passed=False, error_code=error_code, message="Rule failed")
        result.add_result(passed_result)
        result.add_result(failed_result)
        assert result.valid is False
        assert result.passed == [rule1]
        assert result.failed == [rule2]
        assert result.rule_result == [ passed_result, failed_result, ]
        assert len(result.errors) == 1

    def test_multiple_failed_rules_create_multiple_errors(self):
        rules = list(Rule)
        if len(rules) < 2:
            pytest.skip("At least two Rule enum members are required")
        error_code = enum_member(ErrorCode)
        result = ValidationResult(valid=True)
        first = RuleResult( rule=rules[0], passed=False, error_code=error_code, message="First rule failed")
        second = RuleResult( rule=rules[1], passed=False, error_code=error_code, message="Second rule failed", )
        result.add_result(first)
        result.add_result(second)
        assert result.valid is False
        assert result.failed == [rules[0], rules[1]]
        assert result.rule_result == [first, second]
        assert len(result.errors) == 2
        assert result.errors[0].message == "First rule failed"
        assert result.errors[1].message == "Second rule failed"

    def test_slots_prevent_arbitrary_attributes(self):
        result = ValidationResult(valid=True)
        with pytest.raises(AttributeError):
            result.some_random_attribute = "value"

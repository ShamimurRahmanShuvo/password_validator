"""
Unit tests for the password validation engine
"""
import pytest

from password_validator.engine.validator import PasswordValidator, ValidationResult
from password_validator.rules.base import Rule, RuleResult
from password_validator.rules.registry import RuleRegistry

# ---------------------------------------------------------------------------
# Test Rules
# ---------------------------------------------------------------------------


class PassingRule(Rule):
    """
    Test rule that always passes
    """
    name = "passing"

    def validate(self, password: str) -> RuleResult:
        return RuleResult(
            rule_name=self.name,
            passed=True,
            message="Rule passed"
        )


class FailingRule(Rule):
    """
    Test rule that always fails
    """
    name = "failing"

    def validate(self, password: str) -> RuleResult:
        return RuleResult(
            rule_name=self.name,
            passed=False,
            message="Rule failed"
        )


class SecondFailingRule(Rule):
    """
    Test rule used to verify multiple failures
    """
    name = "second_failing"

    def validate(self, password: str) -> RuleResult:
        return RuleResult(
            rule_name=self.name,
            passed=False,
            message="Password failed the second rule.",
        )


class NoResultNameRule(Rule):
    """
    Test rule whose RuleResult does not provide a rule_name.
    This verifies PasswordValidator._rule_name() fallback behavior.
    """
    name = "fallback"

    def validate(self, password: str) -> RuleResult:
        return RuleResult(
            passed=True,
            message="Password passed.",
        )


class BrokenRule(Rule):
    """
    Test rule that raises an unexpected exception.
    """

    name = "broken"

    def validate(self, password: str) -> RuleResult:
        raise RuntimeError("Unexpected rule failure")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def passing_rule():
    return PassingRule()


@pytest.fixture
def failing_rule():
    return FailingRule()


@pytest.fixture
def second_failing_rule():
    return SecondFailingRule()


@pytest.fixture
def default_config():
    """
    Create a configuration suitable for validator tests.

    Adjust these values if your PasswordRuleConfig requires
    additional mandatory fields.
    """
    from password_validator.config.settings import PasswordRuleConfig

    return PasswordRuleConfig(
        min_length=8,
        max_length=64,
        require_uppercase=True,
        require_lowercase=True,
        require_digit=True,
        require_special=True,
        special_characters="!@#$%^&*",
    )

# ---------------------------------------------------------------------------
# ValidationResult Tests
# ---------------------------------------------------------------------------


class TestValidationResult:
    """
    Tests for validation result
    """
    def test_validation_result_can_be_created(self):
        result = ValidationResult(valid=True)

        assert result is not None

    def test_valid_result(self):
        result = ValidationResult(valid=True)

        assert result.valid is True

    def test_invalid_result(self):
        result = ValidationResult(valid=False)

        assert result.valid is False

    def test_is_valid_is_alias_for_valid(self):
        valid_result = ValidationResult(valid=True)
        invalid_result = ValidationResult(valid=False)

        assert valid_result.is_valid is True
        assert invalid_result.is_valid is False

    def test_default_passed_is_empty(self):
        result = ValidationResult(valid=True)

        assert result.passed == ()

    def test_default_failed_is_empty(self):
        result = ValidationResult(valid=False)

        assert result.failed == ()

    def test_default_errors_is_empty(self):
        result = ValidationResult(valid=True)

        assert result.errors == ()

    def test_default_rule_results_is_empty(self):
        result = ValidationResult(valid=True)

        assert result.rule_results == ()

    def test_error_count_is_zero_when_no_failures(self):
        result = ValidationResult(valid=True)

        assert result.error_count == 0

    def test_error_count_matches_failed_rules(self):
        result = ValidationResult(
            valid=False,
            failed=("length", "uppercase"),
        )

        assert result.error_count == 2

    def test_result_stores_passed_rules(self):
        result = ValidationResult(
            valid=True,
            passed=("length", "uppercase"),
        )

        assert result.passed == ("length", "uppercase")

    def test_result_stores_failed_rules(self):
        result = ValidationResult(
            valid=False,
            failed=("length", "special"),
        )

        assert result.failed == ("length", "special")

    def test_result_stores_errors(self):
        result = ValidationResult(
            valid=False,
            errors=(
                "Password is too short.",
                "Password requires a special character.",
            ),
        )

        assert len(result.errors) == 2

    def test_result_stores_rule_results(self):
        rule_result = RuleResult(
            rule_name="length",
            passed=True,
            message="Password length is valid.",
        )

        result = ValidationResult(
            valid=True,
            rule_results=(rule_result,),
        )

        assert len(result.rule_results) == 1
        assert result.rule_results[0] is rule_result

# ---------------------------------------------------------------------------
# PasswordValidator Initialization
# ---------------------------------------------------------------------------


class TestPasswordValidatorInitialization:
    """
    Tests for Password validator initialization
    """
    def test_password_validator_can_be_created(self):
        validator = PasswordValidator()

        assert validator is not None

    def test_validator_creates_default_configuration(self):
        validator = PasswordValidator()

        assert validator.config is not None

    def test_validator_creates_default_rules(self):
        validator = PasswordValidator()

        assert isinstance(validator.rules, list)

    def test_validator_accepts_custom_rules(self, passing_rule):
        validator = PasswordValidator(rules=[passing_rule])

        assert len(validator.rules) == 1
        assert validator.rules[0] is passing_rule

    def test_custom_rules_replace_default_rules(self, passing_rule):
        validator = PasswordValidator(rules=[passing_rule])

        assert validator.rules == [passing_rule]

    def test_empty_custom_rules_are_allowed(self):
        validator = PasswordValidator(rules=[])

        assert validator.rules == []

# ---------------------------------------------------------------------------
# Default Rule Construction
# ---------------------------------------------------------------------------


class TestDefaultRuleConstruction:
    """
    Tests for _build_default_rules
    """
    def test_length_rule_is_always_created(self):
        validator = PasswordValidator()
        rule_names = {
            getattr(rule, "name", None)
            for rule in validator.rules
        }

        assert "length" in rule_names

    def test_rule_is_created_when_required(self):
        from password_validator.config.settings import PasswordRuleConfig

        config = PasswordRuleConfig(
            min_length=8,
            max_length=64,
            require_uppercase=True,
            require_lowercase=True,
            require_digit=False,
            require_special=False,
            special_characters="!@#$",
        )
        validator = PasswordValidator(config=config)
        rule_names = {
            getattr(rule, "name", None)
            for rule in validator.rules
        }

        assert "uppercase" in rule_names
        assert "lowercase" in rule_names

    def test_rule_is_not_created_when_disabled(self):
        from password_validator.config.settings import PasswordRuleConfig

        config = PasswordRuleConfig(
            min_length=8,
            max_length=64,
            require_uppercase=True,
            require_lowercase=True,
            require_digit=False,
            require_special=False,
            special_characters="!@#$",
        )
        validator = PasswordValidator(config=config)
        rule_names = {
            getattr(rule, "name", None)
            for rule in validator.rules
        }

        assert "digits" not in rule_names
        assert "special" not in rule_names

# ---------------------------------------------------------------------------
# Validation Tests
# ---------------------------------------------------------------------------


class TestPasswordValidator:
    """
    Tests for PasswordValidator.validate()
    """
    def test_empty_rules_returns_valid_result(self):
        validator = PasswordValidator(rules=[])
        result = validator.validate("Anything123!")

        assert isinstance(result, ValidationResult)
        assert result.valid is True

    def test_passing_rule_returns_valid_result(self, passing_rule):
        validator = PasswordValidator(rules=[passing_rule])
        result = validator.validate("Password123!")

        assert result.valid is True
        assert result.passed == ("passing",)

    def test_failing_rule_returns_invalid_result(self, failing_rule):
        validator = PasswordValidator(rules=[failing_rule])
        result = validator.validate("Password123!")

        assert result.valid is False
        assert result.failed == ("failing",)
        assert result.errors == ("Rule failed",)

    def test_rule_result_is_returned(self, passing_rule,):
        validator = PasswordValidator(rules=[passing_rule],)
        result = validator.validate("Password123!")

        assert len(result.rule_results) == 1
        assert result.rule_results[0].passed is True
        assert result.rule_results[0].rule_name == "passing"

    def test_multiple_rules_are_executed(self, passing_rule, failing_rule):
        validator = PasswordValidator(rules=[passing_rule, failing_rule])
        result = validator.validate("Password123!")

        assert len(result.rule_results) == 2
        assert result.valid is False
        assert result.passed == ("passing",)
        assert result.failed == ("failing",)

    def test_multiple_failed_rules_are_all_reported(self, failing_rule, second_failing_rule):
        validator = PasswordValidator(rules=[failing_rule, second_failing_rule])
        result = validator.validate("Password123!")

        assert result.valid is False
        assert result.failed == ("failing", "second_failing")
        assert len(result.errors) == 2

    def test_rule_execution_order_is_preserved(self, passing_rule, failing_rule):
        validator = PasswordValidator(
            rules=[passing_rule, failing_rule],
        )

        result = validator.validate("Password123!")

        assert result.rule_results[0].rule_name == "passing"
        assert result.rule_results[1].rule_name == "failing"

    def test_validator_can_be_reused(self, passing_rule):
        validator = PasswordValidator(rules=[passing_rule])

        result1 = validator.validate("Password123!")

        result2 = validator.validate("AnotherPassword456!")

        assert result1.valid is True
        assert result2.valid is True
        assert result1.passed == ("passing",)
        assert result2.passed == ("passing",)

    def test_original_rules_are_not_modified(self, passing_rule, failing_rule):
        rules = [passing_rule, failing_rule]

        validator = PasswordValidator(rules=rules)

        validator.validate("Password123!")

        assert validator.rules == rules
        assert len(validator.rules) == 2

    # ---------------------------------------------------------------------------
    # Input Validation
    # ---------------------------------------------------------------------------


class TestPasswordInput:
    """
    Tests for password input validation.
    """

    @pytest.mark.parametrize(
        "password",
        [
            None,
            123456,
            123.45,
            True,
            False,
            [],
            {},
            object(),
        ],
    )
    def test_non_string_password_raises_type_error(self, password):
        validator = PasswordValidator(rules=[])

        with pytest.raises(TypeError, match="Password must be a string"):
            validator.validate(password)

    def test_empty_string_is_accepted_as_input(self):
        validator = PasswordValidator(rules=[])
        result = validator.validate("")

        assert result.valid is True


# ---------------------------------------------------------------------------
# Rule Name Resolution
# ---------------------------------------------------------------------------


class TestRuleNameResolution:
    """
    Tests for PasswordValidator._rule_name().
    """

    def test_rule_result_name_is_preferred(self, passing_rule):
        result = RuleResult(
            rule_name="result_name",
            passed=True,
            message="Passed."
        )
        name = PasswordValidator._rule_name(passing_rule, result)

        assert name == "result_name"

    def test_rule_class_name_is_used_as_fallback(self):
        rule = PassingRule()

        result = RuleResult(
            rule_name=rule.name,
            passed=True,
            message="Passed.",
        )
        name = PasswordValidator._rule_name(rule, result)

        assert name == "passing"

    def test_rule_class_suffix_is_removed(self):
        rule = FailingRule()
        result = RuleResult(
            rule_name=rule.name,
            passed=False,
            message="Failed.",
        )
        name = PasswordValidator._rule_name(rule, result)

        assert name == "failing"

# ---------------------------------------------------------------------------
# Exception Handling
# ---------------------------------------------------------------------------


class TestRuleExceptions:
    """
    Tests behavior when a rule raises an unexpected exception.
    """

    def test_rule_exception_is_propagated(self):
        validator = PasswordValidator(rules=[BrokenRule()])

        with pytest.raises(RuntimeError, match="Unexpected rule failure"):
            validator.validate("Password123!")

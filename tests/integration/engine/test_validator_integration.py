import pytest

from password_validator.config.settings import PasswordRuleConfig
from password_validator.engine.validator import PasswordValidator
from password_validator.models import ValidationResult
from password_validator.rules.base import Rule


class TestPasswordValidatorIntegration:
    def test_strong_password_is_valid(self):
        config = PasswordRuleConfig(
            min_length=8,
            max_length=128,
            require_uppercase=True,
            require_lowercase=True,
            require_digit=True,
            require_special=True,
            special_characters="!@#$%^&*"
        )
        validator = PasswordValidator(config=config)
        password = "StrongPassword123!"
        result = validator.validate(password)

        assert isinstance(result, ValidationResult)
        assert result.valid is True
        assert len(result.failed) == 0
        assert len(result.rule_result) > 0

    def test_weak_password_is_invalid(self):
        config = PasswordRuleConfig(
            min_length=8,
            max_length=128,
            require_uppercase=True,
            require_lowercase=True,
            require_digit=True,
            require_special=True,
            special_characters="!@#$%^&*"
        )
        validator = PasswordValidator(config=config)
        result = validator.validate("abc")

        assert isinstance(result, ValidationResult)
        assert result.valid is False
        assert len(result.failed) > 0
        assert len(result.errors) > 0
        assert len(result.rule_result) > 0

    def test_password_missing_rule_fails(self):
        config = PasswordRuleConfig(
            min_length=8,
            max_length=128,
            require_uppercase=True,
            require_lowercase=True,
            require_digit=True,
            require_special=True,
            special_characters="!@#$%^&*"
        )
        validator = PasswordValidator(config=config)
        result_uppercase = validator.validate("lowercase123!")
        assert result_uppercase.valid is False
        assert len(result_uppercase.failed) > 0

    def test_multiple_rules_can_fail(self):
        """All failing rules should be reported."""

        config = PasswordRuleConfig(
            min_length=12,
            require_uppercase=True,
            require_lowercase=True,
            require_digit=True,
            require_special=True
        )
        validator = PasswordValidator(config=config)
        result = validator.validate("short")
        assert result.is_valid is False
        assert "length" in result.failed
        assert "uppercase" in result.failed
        assert "digits" in result.failed
        assert "special" in result.failed
        assert result.error_count == len(result.failed)
        assert len(result.rule_results) == 5

    def test_passing_and_failing_rules_are_separated(self):
        """Passed and failed rules should be independently reported."""

        config = PasswordRuleConfig(
            min_length=8,
            require_uppercase=True,
            require_lowercase=True,
            require_digit=True,
            require_special=True
        )
        validator = PasswordValidator(config=config)
        result = validator.validate("password")
        assert result.is_valid is False
        assert "length" not in result.failed
        assert "lowercase" in result.passed
        assert "uppercase" in result.failed
        assert "digits" in result.failed
        assert "special" in result.failed
        assert len(result.passed) > 0
        assert len(result.failed) > 0

    def test_optional_rules_can_be_disabled(self):
        """Disabled rules should not be included in validation."""

        config = PasswordRuleConfig(
            min_length=8,
            require_uppercase=False,
            require_lowercase=False,
            require_digit=False,
            require_special=False
        )
        validator = PasswordValidator(config=config)
        result = validator.validate("abcdefgh")
        assert result.is_valid is True
        assert result.failed == ()
        assert len(result.rule_results) == 1
        assert result.passed == ("length",)

    def test_custom_rules_replace_default_rules(self):
        """Providing custom rules should replace the default rule collection."""
        from password_validator.rules.length import LengthRule

        config = PasswordRuleConfig(
            min_length=8,
            require_uppercase=True,
            require_lowercase=True,
            require_digit=True,
            require_special=True
        )

        custom_rule = LengthRule(min_length=1, max_length=100)
        validator = PasswordValidator(config=config, rules=[custom_rule])
        result = validator.validate("abc")
        assert result.is_valid is True
        assert result.failed == ()
        assert result.errors == ()
        assert len(result.rule_results) == 1
        assert result.passed == ("length",)

    def test_empty_custom_rule_collection_is_valid(self):
        validator = PasswordValidator(
            config=PasswordRuleConfig(),
            rules=[]
        )
        result = validator.validate("anything")
        assert result.is_valid is True
        assert result.passed == ()
        assert result.failed == ()
        assert result.errors == ()
        assert result.rule_results == ()

    def test_rule_results_are_returned(self):
        config = PasswordRuleConfig(
            min_length=8,
            require_uppercase=True,
            require_lowercase=False,
            require_digit=False,
            require_special=False
        )
        validator = PasswordValidator(config=config)
        result = validator.validate("Password")
        assert len(result.rule_results) == 2
        for rule_result in result.rule_results: assert hasattr(rule_result, "passed")
        assert hasattr(rule_result, "message")

    def test_validation_errors_match_failed_rules(self):
        """Every failed rule with a message should produce an error."""

        config = PasswordRuleConfig(
            min_length=12,
            require_uppercase=True,
            require_lowercase=True,
            require_digit=True,
            require_special=True
        )
        validator = PasswordValidator(config=config)
        result = validator.validate("short")
        assert result.is_valid is False
        assert result.error_count == len(result.errors)
        for error in result.errors:
            assert isinstance(error, str)
            assert error

    def test_non_string_password_raises_type_error(self):
        """The public validator API should reject non-string passwords."""

        validator = PasswordValidator()
        with pytest.raises(TypeError, match="Password must be a string"):
            validator.validate(12345)

    def test_validator_uses_default_configuration(self):
        """Validator should construct its default rule set when no config is supplied."""

        validator = PasswordValidator()
        assert validator.config is not None
        assert validator.rules
        result = validator.validate("Password123!")
        assert result.is_valid is True

    def test_configuration_changes_validation_behavior(self):
        """Changing PasswordRuleConfig should change validator behavior."""

        permissive_config = PasswordRuleConfig(
            min_length=4,
            require_uppercase=False,
            require_lowercase=False,
            require_digit=False,
            require_special=False,
        )
        strict_config = PasswordRuleConfig(
            min_length=12,
            require_uppercase=True,
            require_lowercase=True,
            require_digit=True,
            require_special=True,
        )
        permissive_validator = PasswordValidator(config=permissive_config)
        strict_validator = PasswordValidator(config=strict_config)
        password = "abcd"
        permissive_result = permissive_validator.validate(password)
        strict_result = strict_validator.validate(password)
        assert permissive_result.is_valid is True
        assert strict_result.is_valid is False

    def test_validation_result_counts_are_consistent(self):
        """Result counters should accurately reflect validation outcomes."""

        config = PasswordRuleConfig(min_length=8, require_uppercase=True, require_lowercase=True, require_digit=True,
                                    require_special=True, )
        validator = PasswordValidator(config=config)
        result = validator.validate("Password123!")
        assert result.is_valid is True
        assert result.passed_count == len(result.passed)
        assert result.failed_count == len(result.failed)
        assert result.error_count == len(result.errors)
        assert result.failed_count == 0
        assert result.error_count == 0

    def test_password_at_exact_maximum_length_is_valid(self):
        """A password exactly at max_length should pass the length rule."""

        config = PasswordRuleConfig(min_length=8, max_length=10, require_uppercase=False, require_lowercase=False,
                                    require_digit=False, require_special=False, )
        validator = PasswordValidator(config=config)
        result = validator.validate("1234567890")
        assert result.is_valid is True
        assert "length" in result.passed

from pathlib import Path

from password_validator.config.settings import PasswordRuleConfig
from password_validator.engine.validator import PasswordValidator
from password_validator.models import ValidationResult


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


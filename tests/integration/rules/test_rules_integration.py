from password_validator.rules.length import LengthRule
from password_validator.rules.uppercase import UppercaseRule
from password_validator.rules.lowercase import LowercaseRule
from password_validator.rules.digits import DigitsRule
from password_validator.rules.special import SpecialCharacterRule
from password_validator.rules.registry import RuleRegistry


class TestPasswordRulesIntegration:
    def test_valid_passwords_passes_all_rules(self):
        password = "StrongPassword123!"

        rules = [
            LengthRule(min_length=8, max_length=128),
            UppercaseRule(),
            LowercaseRule(),
            DigitsRule(),
            SpecialCharacterRule(special_characters="!@#$%^&*")
        ]
        results = [rule.validate(password) for rule in rules]

        assert all(result.passed for result in results)

    def test_weak_password_fails_multiple_rules(self):
        password = "abc"
        rules = [
            LengthRule(min_length=8, max_length=128),
            UppercaseRule(),
            LowercaseRule(),
            DigitsRule(),
            SpecialCharacterRule(special_characters="!@#$%^&*")
        ]
        results = [rule.validate(password) for rule in rules]
        assert any(not result.passed for result in results)

        failed_rules = [result for result in results if not result.passed]
        assert len(failed_rules) >= 4

    def test_registry_can_execute_registered_rules(self):
        registry = RuleRegistry()
        registry.register(
            LengthRule(min_length=8, max_length=128)
        )
        registry.register(UppercaseRule())
        registry.register(LowercaseRule())
        registry.register(DigitsRule())
        registry.register(SpecialCharacterRule(special_characters="!@#$%^&*"))

        rules = registry.get_rules()
        assert len(rules) == 5

        password = "StrongPassword123!"
        results = [rule.validate(password) for rule in rules]
        assert all(result.passed for result in results)

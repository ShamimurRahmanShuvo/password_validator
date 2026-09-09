from pathlib import Path
from password_validator.config.settings import Settings
from password_validator.engine.validator import PasswordValidator
from password_validator.strength.scorer import PasswordStrengthScorer


class TestPasswordValidatorEndToEnd:
    def test_complete_password_validation_pipeline(self, configured_env_file: Path):
        settings = Settings.from_env(str(configured_env_file))
        validator = PasswordValidator(config=settings.rules)
        scorer = PasswordStrengthScorer(config=settings.strength)
        password = "MySecurePassword123!"
        validation = validator.validate(password)
        strength = scorer.score(password)

        assert validation.valid is True
        assert strength.score >= 0
        assert strength.score <= 100
        assert strength.metrics.length == len(password)
        assert strength.metrics.has_lowercase is True
        assert strength.metrics.has_uppercase is True
        assert strength.metrics.has_digit is True
        assert strength.metrics.has_special is True

    def test_complete_pipeline_rejects_weak_password(self, configured_env_file: Path):
        settings = Settings.from_env(str(configured_env_file))
        validator = PasswordValidator(config=settings.rules)
        scorer = PasswordStrengthScorer(config=settings.strength)
        password = "password!"
        validation = validator.validate(password)
        strength = scorer.score(password)

        assert validation.valid is False
        assert strength.analysis.dictionary.detected is True
        assert len(strength.penalties) > 0
        assert strength.total_penalty > 0
        assert len(strength.suggestions) > 0

    def test_complete_pipeline_detects_multiple_weaknesses(self, configured_env_file: Path):
        settings = Settings.from_env(str(configured_env_file))
        validator = PasswordValidator(config=settings.rules)
        scorer = PasswordStrengthScorer(config=settings.strength)
        password = "qwerty123"
        validation = validator.validate(password)
        strength = scorer.score(password)

        assert validation.valid is False
        assert strength.analysis.has_patterns is True
        assert (
                strength.analysis.dictionary.detected
                or strength.analysis.keyboard.detected
                or strength.analysis.sequential.detected
        )
        assert len(strength.suggestions) > 0

    def test_secure_password_has_no_major_patterns(self, configured_env_file: Path):
        settings = Settings.from_env(str(configured_env_file))
        validator = PasswordValidator(config=settings.rules)
        scorer = PasswordStrengthScorer(config=settings.strength)
        password = "V7#mQ9!rT2$xP8@kL"
        validation = validator.validate(password)
        result = scorer.score(password)

        assert validation.valid is True
        assert result.score >= 60
        assert result.analysis.has_patterns is False
        assert result.metrics.length >= 12
        assert result.metrics.has_lowercase is True
        assert result.metrics.has_uppercase is True
        assert result.metrics.has_digit is True

    def test_password_improvement_reduces_weaknesses(self, configured_env_file: Path):
        settings = Settings.from_env(str(configured_env_file))

        scorer = PasswordStrengthScorer(config=settings.strength)
        weak_password = "password123"
        strong_password = ("V7#mQ9!rT2$xP8@kL")
        weak_result = scorer.score(weak_password)
        strong_result = scorer.score(strong_password)
        assert (strong_result.total_penalty <= weak_result.total_penalty)
        assert (strong_result.score >= weak_result.score)


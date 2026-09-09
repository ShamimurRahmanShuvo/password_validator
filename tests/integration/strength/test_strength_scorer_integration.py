from password_validator.enums import StrengthLevel
from password_validator.strength.scorer import PasswordStrengthScorer, StrengthResult


class TestPasswordStrengthScorerIntegration:
    def test_score_returns_strength_result(self):
        scorer = PasswordStrengthScorer()
        result = scorer.score("MyStrongPassword123!")

        assert isinstance(result, StrengthResult)
        assert result.score >= 0
        assert result.score <= 100
        assert isinstance(result.level, StrengthLevel)

    def test_strong_password_gets_high_score(self):
        scorer = PasswordStrengthScorer()
        result = scorer.score("V7#mQ9!rT2$xP8@kL")

        assert result.score >= 60

    def test_password_penalty(self):
        scorer = PasswordStrengthScorer()
        # Common
        result = scorer.score("password")
        assert result.analysis.dictionary.detected is True
        assert len(result.penalties) > 0
        assert result.total_penalty > 0

        # Repeat
        result = scorer.score("aaaaPassword123!")
        assert result.analysis.repeat.detected is True
        assert len(result.penalties) > 0

        # Sequential
        result = scorer.score("abcdPassword123!")
        assert result.analysis.sequential.detected is True
        assert len(result.penalties) > 0

        # Keyboard
        result = scorer.score("qwertyPassword123!!")
        assert result.analysis.keyboard.detected is True
        assert len(result.penalties) > 0

    def test_password_bonuses(self):
        scorer = PasswordStrengthScorer()
        # Length
        result = scorer.score("VeryLongSecurePassword123!")
        assert len(result.bonuses) > 0
        assert result.total_bonus > 0
        # Character Diversity
        result = scorer.score("AsE@396rd@#")
        assert len(result.bonuses) > 0
        assert result.total_bonus > 0

    def test_suggestions_are_generated(self):
        scorer = PasswordStrengthScorer()
        result = scorer.score("password")
        assert len(result.suggestions) > 0
        assert len(result.suggestion_message) > 0

    def test_clean_password_has_fewer_penalties(self):
        scorer = PasswordStrengthScorer()

        clean_result = scorer.score("V7#mQ9!rT2$xP8@kL")
        weak_result = scorer.score("password123")
        assert (clean_result.total_penalty <= weak_result.total_penalty)

    def test_empty_password_is_handled(self):
        scorer = PasswordStrengthScorer()

        result = scorer.score("")
        assert isinstance(result, StrengthResult)
        assert result.metrics.length == 0
        assert result.metrics.character_diversity == 0.0
        assert result.metrics.estimated_entropy == 0.0

    def test_none_password_is_handled(self):
        scorer = PasswordStrengthScorer()

        result = scorer.score(None)
        assert isinstance(result, StrengthResult)
        assert result.metrics.length == 0

    def test_score_is_clamped_to_valid_range(self):
        scorer = PasswordStrengthScorer()

        for password in ["", "password", "abc123", "StrongPassword123!", "V7#mQ9!rT2$xP8@kL", ]:
            result = scorer.score(password)
        assert 0 <= result.score <= 100

    def test_strength_level_matches_score(self):
        scorer = PasswordStrengthScorer()

        result = scorer.score("password")
        if result.score < 20:
            assert result.level == StrengthLevel.VERY_WEAK
        elif result.score < 40:
            assert result.level == StrengthLevel.WEAK
        elif result.score < 60:
            assert result.level == StrengthLevel.FAIR
        elif result.score < 80:
            assert result.level == StrengthLevel.STRONG
        else:
            assert result.level == StrengthLevel.VERY_STRONG

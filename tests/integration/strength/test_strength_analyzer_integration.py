from password_validator.strength.analyzer import StrengthAnalyzer, StrengthAnalysis
from password_validator.strength.config import StrengthConfig


class TestStrengthAnalyzerIntegration:
    def test_analyzer_returns_complete_analysis(self):
        analyzer = StrengthAnalyzer()
        result = analyzer.analyze("StrongPassword123!")

        assert isinstance(result, StrengthAnalysis)
        assert result.dictionary is not None
        assert result.repeat is not None
        assert result.sequential is not None
        assert result.keyboard is not None

    def test_different_pattern_detection(self):
        analyzer = StrengthAnalyzer()
        # Common Password
        result_common = analyzer.analyze("password")
        assert result_common.dictionary.detected is True
        assert result_common.dictionary.common_password_detected is True

        # Repeated Pattern
        result_repeat = analyzer.analyze("aaaPassword123!")
        assert result_repeat.repeat.detected is True

        # Sequence
        result_seq = analyzer.analyze("abcdPassword1234!")
        assert result_seq.sequential.detected is True

        # Keyboard
        result_key = analyzer.analyze("qwertyPassword123!")
        assert result_key.keyboard.detected is True

    def test_clean_password_has_fewer_patterns(self):
        analyzer = StrengthAnalyzer()

        result = analyzer.analyze("V7#mQ9!rT2$xP8")
        assert result.has_patterns is False

    def test_maximum_severity_is_calculated(self):
        analyzer = StrengthAnalyzer()
        result = analyzer.analyze("password123")
        expected = max(
            result.dictionary.severity,
            result.repeat.severity,
            result.sequential.severity,
            result.keyboard.severity)
        assert result.maximum_severity == expected

    def test_disabled_analysis_returns_no_patterns(self):
        config = StrengthConfig(enabled=False)

        analyzer = StrengthAnalyzer(config=config)
        result = analyzer.analyze("password123")
        assert result.has_patterns is False

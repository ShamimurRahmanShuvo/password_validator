"""
Unit tests for the repeat analyzer.
"""
import pytest
from password_validator.strength.analyzers.repeat import (
    RepeatAnalyzer,
    RepeatAnalysis,
    RepeatPattern,
    RepeatPatternType
)
from password_validator.strength.config import StrengthConfig


class TestRepeatAnalysis:
    """
    Tests for RepeatAnalysis
    """

    def test_default_analysis_is_empty(self):
        result = RepeatAnalysis()

        assert result.detected is False
        assert result.patterns == []
        assert result.consecutive_detected is False
        assert result.repeated_group_detected is False
        assert result.frequency_detected is False
        assert result.severity == 0.0
        assert result.penalty_factor == 0.0
        assert result.pattern_count == 0

    def test_pattern_count_matches_patterns(self):
        pattern = RepeatPattern(
            pattern_type=RepeatPatternType.CONSECUTIVE_PATTERN,
            value="aaa",
            count=3,
            start_position=0,
            end_position=2,
            severity=0.5,
            message="Consecutive characters detected"
        )
        result = RepeatAnalysis(patterns=[pattern])

        assert result.pattern_count == 1
        assert result.patterns[0] == pattern


class TestRepeatPattern:
    """
    Tests for RepeatPattern
    """

    def test_consecutive_pattern_can_be_created(self):
        pattern = RepeatPattern(
            pattern_type=RepeatPatternType.CONSECUTIVE_PATTERN,
            value="aaa",
            count=3,
            start_position=0,
            end_position=2,
            severity=0.5,
            message="Consecutive characters detected"
        )

        assert pattern.pattern_type == RepeatPatternType.CONSECUTIVE_PATTERN
        assert pattern.value == "aaa"
        assert pattern.count == 3
        assert pattern.start_position == 0
        assert pattern.end_position == 2
        assert pattern.severity == 0.5
        assert pattern.message == "Consecutive characters detected"

    def test_repeat_pattern_group_can_be_created(self):
        pattern = RepeatPattern(
            pattern_type=RepeatPatternType.REPEATED_GROUP,
            value="abcabc",
            count=2,
            start_position=0,
            end_position=5,
            severity=0.7,
            message="Repeated group detected"
        )

        assert pattern.pattern_type == RepeatPatternType.REPEATED_GROUP
        assert pattern.value == "abcabc"
        assert pattern.count == 2
        assert pattern.start_position == 0
        assert pattern.end_position == 5
        assert pattern.severity == 0.7
        assert pattern.message == "Repeated group detected"

    def test_pattern_default_values(self):
        pattern = RepeatPattern(
            pattern_type=RepeatPatternType.REPEATED_GROUP,
            value="ab",
            count=2
        )

        assert pattern.start_position == 0
        assert pattern.end_position == 0
        assert pattern.severity == 0.0
        assert pattern.message == ""

    def test_pattern_is_frozen(self):
        pattern = RepeatPattern(
            pattern_type=RepeatPatternType.CONSECUTIVE_PATTERN,
            value="aaa",
            count=3
        )

        with pytest.raises(AttributeError):
            pattern.value = "bbb"


class TestRepeatAnalyzer:
    """
    Tests for RepeatAnalyzer
    """

    @pytest.fixture
    def analyzer(self):
        config = StrengthConfig(
            enabled=True,
            check_consecutive=True,
            max_consecutive_repeat=2,
            check_repeated_groups=True,
            check_character_frequency=True,
        )

        return RepeatAnalyzer(config=config)

    def test_analyzer_can_be_created(self, analyzer):
        assert isinstance(analyzer, RepeatAnalyzer)
        assert analyzer is not None

    def test_analyzer_has_config(self, analyzer):
        assert analyzer.config is not None

    def test_analyze_empty_password(self, analyzer):
        result = analyzer.analyze("")

        assert isinstance(result, RepeatAnalysis)
        assert result.detected is False
        assert result.patterns == []
        assert result.consecutive_detected is False
        assert result.repeated_group_detected is False
        assert result.frequency_detected is False
        assert result.severity == 0.0
        assert result.penalty_factor == 0.0

    def test_normal_password_has_no_repeat_pattern(self, analyzer):
        result = analyzer.analyze("MySecurePassword123")

        assert isinstance(result, RepeatAnalysis)
        assert result.detected is False
        assert result.patterns == []
        assert result.consecutive_detected is False
        assert result.repeated_group_detected is False
        assert result.frequency_detected is False
        assert result.severity == 0.0
        assert result.penalty_factor == 0.0

    def test_consecutive_pattern_is_detected(self, analyzer):
        result = analyzer.analyze("Password111!")

        assert isinstance(result, RepeatAnalysis)
        assert result.detected is True
        assert result.consecutive_detected is True
        assert len(result.patterns) > 0
        assert any(p.pattern_type == RepeatPatternType.CONSECUTIVE_PATTERN for p in result.patterns)

    def test_consecutive_pattern_has_correct_type(self, analyzer):
        result = analyzer.analyze("Password111!")
        consecutive_patterns = [p for p in result.patterns if p.pattern_type == RepeatPatternType.CONSECUTIVE_PATTERN]

        assert consecutive_patterns

    def test_consecutive_pattern_has_parameters(self, analyzer):
        result = analyzer.analyze("Password111!")
        consecutive_patterns = [p for p in result.patterns if p.pattern_type == RepeatPatternType.CONSECUTIVE_PATTERN]

        for pattern in consecutive_patterns:
            assert pattern.value == "111"
            assert pattern.count == 3
            assert pattern.start_position == 8
            assert pattern.end_position == 11
            assert pattern.severity > 0.0
            assert pattern.message != ""

    def test_longer_consecutive_pattern_has_higher_severity(self, analyzer):
        result_short = analyzer.analyze("Password11!")
        result_long = analyzer.analyze("Password1111!")

        short_patterns = [p for p in result_short.patterns if p.pattern_type == RepeatPatternType.CONSECUTIVE_PATTERN]
        long_patterns = [p for p in result_long.patterns if p.pattern_type == RepeatPatternType.CONSECUTIVE_PATTERN]

        short_severity = sum(p.severity for p in short_patterns)
        long_severity = sum(p.severity for p in long_patterns)

        assert long_severity > short_severity

    def test_repeated_group_pattern_is_detected(self, analyzer):
        result = analyzer.analyze("abcabc")

        assert isinstance(result, RepeatAnalysis)
        assert result.detected is True
        assert result.repeated_group_detected is True
        assert len(result.patterns) > 0
        assert any(p.pattern_type == RepeatPatternType.REPEATED_GROUP for p in result.patterns)

    def test_repeated_group_pattern_has_parameters(self, analyzer):
        result = analyzer.analyze("Passwordabcabc")
        repeated_group_patterns = [p for p in result.patterns if p.pattern_type == RepeatPatternType.REPEATED_GROUP]

        for pattern in repeated_group_patterns:
            assert pattern.value == "abcabc"
            assert pattern.count == 2
            assert pattern.start_position == 8
            assert pattern.end_position == 14
            assert pattern.severity > 0.0
            assert pattern.message != ""

    def test_character_frequency_is_detected(self, analyzer):
        result = analyzer.analyze("aaaaaaaaaaaaaaB1!")

        assert result.detected is True
        assert result.frequency_detected is True

        frequency_patterns = [
            pattern for pattern in result.patterns if pattern.pattern_type == RepeatPatternType.CHARACTER_FREQUENCY
        ]

        assert frequency_patterns

        pattern = frequency_patterns[0]

        assert pattern.value == "a"
        assert pattern.count == 14
        assert 0.0 <= pattern.severity <= 1.0

    def test_frequency_pattern_has_parameters(self, analyzer):
        result = analyzer.analyze("aaaaaaaaaaaaaaB1!")
        frequency_patterns = [
            pattern for pattern in result.patterns if pattern.pattern_type == RepeatPatternType.CHARACTER_FREQUENCY
        ]

        for pattern in frequency_patterns:
            assert pattern.value == "a"
            assert pattern.count == 14
            assert pattern.start_position == 0
            assert pattern.end_position == 14
            assert 0.0 <= pattern.severity <= 1.0
            assert pattern.message != ""

    def test_frequency_pattern_severity_is_between_zero_and_one(self, analyzer):
        result = analyzer.analyze("aaaaaaaaaaaaaaB1!")
        frequency_patterns = [
            pattern for pattern in result.patterns if pattern.pattern_type == RepeatPatternType.CHARACTER_FREQUENCY
        ]

        for pattern in frequency_patterns:
            assert 0.0 <= pattern.severity <= 1.0

    def test_severity_is_between_zero_and_one(self, analyzer):
        result = analyzer.analyze("Password111!")

        assert 0.0 <= result.severity <= 1.0

    def test_penalty_factor_is_between_zero_and_one(self, analyzer):
        result = analyzer.analyze("Password111!")

        assert 0.0 <= result.penalty_factor <= 1.0

    def test_penalty_factor_matches_severity(self, analyzer):
        result = analyzer.analyze("Password111!")

        assert result.penalty_factor == result.severity

    def test_pattern_count_matches_patterns(self, analyzer):
        result = analyzer.analyze("Password111!")

        assert len(result.patterns) == result.pattern_count


class TestRepeatAnalyzerConfiguration:
    """Tests for RepeatAnalyzer configuration behavior."""

    def test_disabled_analyzer_returns_empty_analysis(self, monkeypatch):
        monkeypatch.setenv("STRENGTH_CHECK_REPEATED_CHARACTERS", "false")
        analyzer = RepeatAnalyzer()

        result = analyzer.analyze("Password111!")

        assert isinstance(result, RepeatAnalysis)
        assert result.detected is False
        assert result.patterns == []
        assert result.consecutive_detected is False
        assert result.repeated_group_detected is False
        assert result.frequency_detected is False
        assert result.severity == 0.0
        assert result.penalty_factor == 0.0

    def test_different_parameters_can_be_disabled(self):
        config = StrengthConfig(
            check_repeated_characters=True,
            check_consecutive=False,
            check_repeated_groups=False,
            check_character_frequency=False,
        )
        analyzer = RepeatAnalyzer(config=config)
        result = analyzer.analyze("Password111!")

        assert result.detected is False
        assert result.consecutive_detected is False

        result = analyzer.analyze("ababab")

        assert result.repeated_group_detected is False

        result = analyzer.analyze("aaaaaaaaaaaaaaB1!")

        assert result.frequency_detected is False

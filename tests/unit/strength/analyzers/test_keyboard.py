"""
Unit tests for the keyboard analyzer module.
"""
import pytest
from password_validator.strength.analyzers.keyboard import (
    KeyboardAnalyzer, KeyboardAnalysis, KeyboardPattern, KeyboardPatternType
)
from password_validator.strength.config import StrengthConfig


@pytest.fixture
def analyzer():
    """
    Fixture for creating a KeyboardAnalyzer instance with a default configuration.
    """
    config = StrengthConfig.defaults()
    return KeyboardAnalyzer(config)


@pytest.fixture
def disabled_analyzer():
    """
    Fixture for creating a KeyboardAnalyzer instance with a configuration that disables keyboard pattern analysis.
    """
    return KeyboardAnalyzer(config=StrengthConfig(enabled=False))


class TestKeyboardAnalyzer:
    """
    Unit tests for the KeyboardAnalyzer class.
    """
    def test_empty_password_returns_empty_analysis(self, analyzer):
        """
        Test that analyzing an empty password returns an empty analysis.
        """
        result = analyzer.analyze("")

        assert isinstance(result, KeyboardAnalysis)
        assert result.detected is False
        assert result.patterns == []
        assert result.pattern_count == 0
        assert result.severity == 0.0
        assert result.penalty_factor == 0.0

    def test_non_keyboard_password_has_no_patterns(self, analyzer):
        result = analyzer.analyze("MySecurePassword!")

        assert isinstance(result, KeyboardAnalysis)
        assert result.detected is False
        assert result.patterns == []
        assert result.pattern_count == 0

    def test_disabled_analyzer_returns_empty_analysis(self, disabled_analyzer):
        result = disabled_analyzer.analyze("qwerty")

        assert isinstance(result, KeyboardAnalysis)
        assert result.detected is False
        assert result.patterns == []
        assert result.pattern_count == 0

    # Horizontal Patterns
    @pytest.mark.parametrize(
        "password, expected",
        [
            ("qwerty", "qwerty"), ("asdf", "asdf"), ("zxcv", "zxcv")
        ]
    )
    def test_horizontal_patterns_detected(self, analyzer, password, expected):
        result = analyzer.analyze(password)

        assert result.detected is True
        assert result.horizontal_detected is True
        assert len(result.patterns) == 1
        assert result.patterns[0].pattern_type == KeyboardPatternType.HORIZONTAL
        assert any(p.normalized_value == expected for p in result.patterns)

    @pytest.mark.parametrize("password",
                             ["QWERTY", "ASDF", "ZXCV", ], )
    def test_horizontal_pattern_is_case_insensitive(self, analyzer, password):
        result = analyzer.analyze(password)

        assert result.detected is True
        assert result.horizontal_detected is True

    def test_horizontal_pattern_can_appear_inside_password(self, analyzer):
        result = analyzer.analyze("MyqwertyPassword!")

        assert result.detected is True
        assert result.horizontal_detected is True
        assert any(pattern.normalized_value == "qwerty" for pattern in result.patterns)

    # Vartical Patterns
    @pytest.mark.parametrize("password, expected",
                             [("1qaz", "1qaz"), ("2wsx", "2wsx"), ("3edc", "3edc"), ("4rfv", "4rfv"), ("5tgb", "5tgb"),
                              ("6yhn", "6yhn"), ("7ujm", "7ujm"), ])
    def test_vertical_patterns_detected(self, analyzer, password, expected):
        result = analyzer.analyze(password)

        assert result.detected is True
        assert result.vertical_detected is True
        assert len(result.patterns) == 1
        assert result.patterns[0].pattern_type == KeyboardPatternType.VERTICAL
        assert any(p.normalized_value == expected for p in result.patterns)

    def test_vertical_patter_can_appear_inside_password(self, analyzer):
        result = analyzer.analyze("My1qazPassword!")

        assert result.detected is True
        assert result.vertical_detected is True
        assert any(pattern.normalized_value == "1qaz" for pattern in result.patterns)

    # Diagonal Patterns
    @pytest.mark.parametrize("password, expected",
                             [("1qws", "1qws"), ("2wed", "2wed"), ("3erf", "3erf"), ("4rtg", "4rtg"), ("5tyh", "5tyh"),
                              ("6yui", "6yui"), ("7uij", "7uij"), ("8iok", "8iok"), ("9opl", "9opl"), ])
    def test_diagonal_patterns_detected(self, analyzer, password, expected):
        result = analyzer.analyze(password)

        assert result.detected is True
        assert result.diagonal_detected is True
        assert len(result.patterns) == 1
        assert result.patterns[0].pattern_type == KeyboardPatternType.DIAGONAL
        assert any(p.normalized_value == expected for p in result.patterns)

    # Number Patterns
    def test_number_patterns_detected(self, analyzer):
        result = analyzer.analyze("123456")

        assert result.detected is True
        assert result.number_row_detected is True
        assert len(result.patterns) == 1
        assert result.patterns[0].pattern_type == KeyboardPatternType.NUMBER_ROW
        assert any(p.normalized_value == "123456" for p in result.patterns)

    # Reverse Patterns
    def test_reverse_patterns_detected(self, analyzer):
        result = analyzer.analyze("ytrewq")

        assert result.detected is True
        assert len(result.patterns) == 1
        assert any(p.normalized_value == "ytrewq" for p in result.patterns)

    # Minimum Length Patterns
    def test_pattern_shorter_than_minimum_is_ignored(self):
        config = StrengthConfig(min_pattern_length=5)
        analyzer = KeyboardAnalyzer(config)
        result = analyzer.analyze("qwer")

        assert result.detected is False
        assert result.patterns == []

    # Configuration flags
    def test_analyzer_respects_configuration_flags(self):
        config = StrengthConfig(
            enabled=True,
            check_horizontal=False,
            check_vertical=False,
            check_diagonal=False,
            check_number_row=False,
        )
        analyzer = KeyboardAnalyzer(config)

        result = analyzer.analyze("qwerty")
        assert result.detected is False
        assert result.horizontal_detected is False

        result = analyzer.analyze("1qaz")
        assert result.detected is False
        assert result.vertical_detected is False

        result = analyzer.analyze("1qws")
        assert result.detected is False
        assert result.diagonal_detected is False

        result = analyzer.analyze("123456")
        assert result.detected is False
        assert result.number_row_detected is False

    # Result structure
    def test_detected_pattern_has_correct_structure(self, analyzer):
        result = analyzer.analyze("qwerty")

        assert result.detected is True
        assert result.patterns
        assert len(result.patterns) == 1

        pattern = result.patterns[0]
        assert isinstance(pattern, KeyboardPattern)
        assert isinstance(pattern.value, str)
        assert isinstance(pattern.normalized_value, str)
        assert isinstance(pattern.pattern_type, KeyboardPatternType)
        assert isinstance(pattern.start_position, int)
        assert isinstance(pattern.end_position, int)
        assert isinstance(pattern.length, int)
        assert isinstance(pattern.reversed_pattern, bool)
        assert isinstance(pattern.severity, float)
        assert isinstance(pattern.message, str)
        assert pattern.pattern_type == KeyboardPatternType.HORIZONTAL
        assert pattern.start_position == 0
        assert pattern.end_position == 6
        assert pattern.normalized_value == "qwerty"

    # Severity
    def test_severity_is_between_zero_and_one(self, analyzer):
        result = analyzer.analyze("qwertyuiopasdfghjklzxcvbnm")

        assert result
        assert 0.0 <= result.severity <= 1.0
        assert 0.0 <= result.penalty_factor <= 1.0

    # Duplicate handling
    def test_duplicate_patterns_are_handled_correctly(self, analyzer):
        result = analyzer.analyze("1234")
        keys = [
            (
                pattern.start_position,
                pattern.end_position,
                pattern.pattern_type
            )
            for pattern in result.patterns
        ]

        assert result.detected is True
        assert len(keys) == len(set(keys))

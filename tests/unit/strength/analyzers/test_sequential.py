"""
Unit tests for SequentialAnalyzer
"""
import pytest
from password_validator.strength.analyzers.sequential import (
    SequentialAnalyzer,
    SequentialAnalysis,
    SequenceDirection,
    SequenceType,
    SequentialPattern
)
from password_validator.strength.config import StrengthConfig


class TestSequentialPattern:
    def test_sequential_pattern_creation(self):
        pattern = SequentialPattern(
            value="abc",
            direction=SequenceDirection.ASCENDING,
            sequence_type=SequenceType.LOWERCASE,
            start_position=0,
            end_position=2,
            length=3,
            severity=1.0,
            message="Sequential lowercase letters detected."
        )
        assert pattern.value == "abc"
        assert pattern.direction == SequenceDirection.ASCENDING
        assert pattern.sequence_type == SequenceType.LOWERCASE
        assert pattern.start_position == 0
        assert pattern.end_position == 2
        assert pattern.length == 3
        assert pattern.severity == 1.0
        assert pattern.message == "Sequential lowercase letters detected."


class TestSequentialAnalysis:
    def test_default_analysis_is_empty(self):
        result = SequentialAnalysis()

        assert result.detected is False
        assert result.patterns == []
        assert result.ascending_detected is False
        assert result.descending_detected is False
        assert result.severity == 0.0
        assert result.message == ""
        assert result.penalty_factor == 0.0

    def test_sequential_pattern_count(self):
        result = SequentialAnalysis()
        assert result.pattern_count == 0

        pattern1 = SequentialPattern(
            value="abc",
            direction=SequenceDirection.ASCENDING,
            sequence_type=SequenceType.LOWERCASE,
            start_position=0,
            end_position=2,
            length=3,
            severity=1.0,
            message="Sequential lowercase letters detected."
        )
        pattern2 = SequentialPattern(
            value="123",
            direction=SequenceDirection.ASCENDING,
            sequence_type=SequenceType.DIGIT,
            start_position=3,
            end_position=5,
            length=3,
            severity=1.0,
            message="Sequential digits detected."
        )
        result.patterns.append(pattern1)
        result.patterns.append(pattern2)

        assert result.pattern_count == 2


class TestSequentialAnalyzer:
    def test_empty_password_returns_empty_analysis(self):
        config = StrengthConfig()
        analyzer = SequentialAnalyzer(config)
        result = analyzer.analyze("")

        assert isinstance(result, SequentialAnalysis)
        assert result.detected is False
        assert result.patterns == []
        assert result.severity == 0.0
        assert result.message == ""

    def test_no_sequence_returns_empty_analysis(self):
        config = StrengthConfig()
        analyzer = SequentialAnalyzer(config)
        result = analyzer.analyze("aX9!kP2@")

        assert isinstance(result, SequentialAnalysis)
        assert result.detected is False
        assert result.patterns == []
        assert result.severity == 0.0
        assert result.message == "No sequential patterns detected."

    def test_digit_sequence_type_detected(self):
        config = StrengthConfig(min_sequence_length=3)
        analyzer = SequentialAnalyzer(config)

        #Ascending Digit
        result = analyzer.analyze("Password1234!")

        assert result.detected is True
        assert result.ascending_detected is True
        assert any(p.value == "1234" for p in result.patterns)

        # Descending Digit
        result_desc = analyzer.analyze("Password4321!")

        assert result_desc.detected is True
        assert result_desc.descending_detected is True
        assert any(p.value == "4321" for p in result_desc.patterns)

    def test_lowercase_character_sequence_type_detected(self):
        config = StrengthConfig(min_sequence_length=3, check_lowercase=True)
        analyzer = SequentialAnalyzer(config)

        # Ascending Lowercase
        result_lower = analyzer.analyze("abcdef!")
        assert result_lower.detected is True
        assert result_lower.ascending_detected is True

        pattern_lower = result_lower.patterns[0]
        assert pattern_lower.value == "abcdef"
        assert pattern_lower.direction == SequenceDirection.ASCENDING
        assert pattern_lower.sequence_type == SequenceType.LOWERCASE

        # Descending Lowercase
        result_lower_desc = analyzer.analyze("fedcba!")
        assert result_lower_desc.detected is True
        assert result_lower_desc.descending_detected is True

        pattern_lower_desc = result_lower_desc.patterns[0]
        assert pattern_lower_desc.value == "fedcba"
        assert pattern_lower_desc.direction == SequenceDirection.DESCENDING
        assert pattern_lower_desc.sequence_type == SequenceType.LOWERCASE

    def test_uppercase_character_sequence_type_detected(self):
        config = StrengthConfig(min_sequence_length=3, check_uppercase=True)
        analyzer = SequentialAnalyzer(config)

        # Ascending Uppercase
        result_upper = analyzer.analyze("ABCDEF!")
        assert result_upper.detected is True
        assert result_upper.ascending_detected is True

        pattern_upper = result_upper.patterns[0]
        assert pattern_upper.value == "ABCDEF"
        assert pattern_upper.direction == SequenceDirection.ASCENDING
        assert pattern_upper.sequence_type == SequenceType.UPPERCASE

        # Descending Uppercase
        result_upper_desc = analyzer.analyze("FEDCBA!")
        assert result_upper_desc.detected is True
        assert result_upper_desc.descending_detected is True

        pattern_upper_desc = result_upper_desc.patterns[0]
        assert pattern_upper_desc.value == "FEDCBA"
        assert pattern_upper_desc.direction == SequenceDirection.DESCENDING
        assert pattern_upper_desc.sequence_type == SequenceType.UPPERCASE

    def test_sequence_shorter_than_minimum_is_not_detected(self):
        config = StrengthConfig(min_sequence_length=4)
        analyzer = SequentialAnalyzer(config)

        # Sequence of length 3 should not be detected
        result = analyzer.analyze("abc")
        assert result.detected is False
        assert result.patterns == []

        # Sequence of length 4 should be detected
        result_valid = analyzer.analyze("abcd")
        assert result_valid.detected is True
        assert any(p.value == "abcd" for p in result_valid.patterns)

    def test_custom_minimum_sequence_length(self):
        config = StrengthConfig(min_sequence_length=5)
        analyzer = SequentialAnalyzer(config)

        result = analyzer.analyze("abcd!")
        assert result.detected is False

        result = analyzer.analyze("abcde!")
        assert result.detected is True
        assert result.patterns[0].value == "abcde"

    def test_sequence_can_be_disabled_based_on_type(self):
        config = StrengthConfig(check_lowercase=False, check_uppercase=False, check_digits=False)
        analyzer = SequentialAnalyzer(config)

        result = analyzer.analyze("abc123ABC")
        assert result.detected is False
        assert result.patterns == []

    def test_entire_sequential_analyzer_can_be_disabled(self):
        config = StrengthConfig(enabled=False)
        analyzer = SequentialAnalyzer(config)
        result = analyzer.analyze("abcd1234ABCD!")

        assert result.detected is False
        assert result.patterns == []
        assert result.severity == 0.0
        assert result.penalty_factor == 0.0

    def test_sequential_patterns_can_be_disabled(self):
        config = StrengthConfig(enabled=True, check_sequential_patterns=False)
        analyzer = SequentialAnalyzer(config)
        result = analyzer.analyze("abcd1234ABCD!")

        assert result.detected is False
        assert result.patterns == []

    def test_pattern_positions_are_correct(self):
        config = StrengthConfig(min_sequence_length=3)
        analyzer = SequentialAnalyzer(config)

        result = analyzer.analyze("X1234!")
        assert result.detected is True

        pattern = next(p for p in result.patterns if p.value == "1234")
        assert pattern.start_position == 1
        assert pattern.end_position == 5
        assert pattern.length == 4

    def test_pattern_severity_is_calculated(self):
        config = StrengthConfig(min_sequence_length=3)
        analyzer = SequentialAnalyzer(config)

        result = analyzer.analyze("abc123XYZ")
        assert result.detected is True

        # Assuming severity is calculated based on the number of patterns detected
        assert result.severity > 0.0
        assert result.pattern_count == 3

    def test_long_sequence_has_higher_severity(self):
        config = StrengthConfig(min_sequence_length=3)
        analyzer = SequentialAnalyzer(config)

        result_short = analyzer.analyze("abc")
        result_long = analyzer.analyze("abcdef")

        assert result_short.detected is True
        assert result_long.detected is True

        # Assuming severity increases with the length of the sequence
        assert result_long.severity > result_short.severity

    def test_direction_detection(self):
        assert (SequentialAnalyzer._get_sequence_direction("1234") == SequenceDirection.ASCENDING)
        assert (SequentialAnalyzer._get_sequence_direction("4321") == SequenceDirection.DESCENDING)
        assert (SequentialAnalyzer._get_sequence_direction("1357") == SequenceDirection.ASCENDING)
        assert (SequentialAnalyzer._get_sequence_direction("7531") == SequenceDirection.DESCENDING)
        assert (SequentialAnalyzer._get_sequence_direction("1235") == SequenceDirection.ASCENDING)
        assert (SequentialAnalyzer._get_sequence_direction("1324") is None)

    def test_sequence_direction_requires_consistent_direction(self):
        assert SequentialAnalyzer._get_sequence_direction("12321") is None

    def test_finalize_no_patterns(self):
        config = StrengthConfig(min_sequence_length=3)
        analyzer = SequentialAnalyzer(config)

        result = analyzer.analyze("NoSeqHere!")
        assert result.detected is False
        assert result.patterns == []
        assert result.severity == 0.0
        assert result.penalty_factor == 0.0

    def test_finalize_with_patterns(self):
        config = StrengthConfig(min_sequence_length=3)
        analyzer = SequentialAnalyzer(config)

        result = analyzer.analyze("abc123XYZ")
        assert result.detected is True
        assert len(result.patterns) > 0
        assert result.severity > 0.0
        assert result.penalty_factor > 0.0


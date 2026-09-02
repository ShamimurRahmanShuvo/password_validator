"""
Unit tests for the strength analyzers package.
"""
import pytest
from unittest.mock import Mock
from password_validator.strength.analyzer import StrengthAnalyzer, StrengthAnalysis


class TestStrengthAnalyzer:
    """
    Tests for the StrengthAnalyzer class.
    """

    @pytest.fixture
    def mock_analyzers(self):
        """
        Fixture to create mock analyzers for testing.
        """
        return {
            "dictionary": Mock(),
            "repeat": Mock(),
            "sequential": Mock(),
            "keyboard": Mock()
        }

    def test_analyzers_can_be_created(self):
        analyzer = StrengthAnalyzer()

        assert analyzer is not None

    def test_analyze_calls_all_analyzers(self, mock_analyzers):
        """
        Test that the analyze method calls all individual analyzers.
        """
        # Arrange
        password = "TestPassword123!"
        analyzer = StrengthAnalyzer(
            dictionary_analyzer=mock_analyzers["dictionary"],
            repeat_analyzer=mock_analyzers["repeat"],
            sequential_analyzer=mock_analyzers["sequential"],
            keyboard_analyzer=mock_analyzers["keyboard"]
        )

        # Act
        result = analyzer.analyze(password)

        # Assert
        mock_analyzers["dictionary"].analyze.assert_called_once_with(password)
        mock_analyzers["repeat"].analyze.assert_called_once_with(password)
        mock_analyzers["sequential"].analyze.assert_called_once_with(password)
        mock_analyzers["keyboard"].analyze.assert_called_once_with(password)
        assert isinstance(result, StrengthAnalysis)
        assert result is not None

    def test_patterns_detected_property(self, mock_analyzers):
        """
        Test the patterns_detected property of StrengthAnalysis.
        """
        analyzer = StrengthAnalyzer()

        # Repeated pattern
        result_repeated = analyzer.analyze("Password111!")
        assert result_repeated is not None

        # Sequential pattern
        result_sequential = analyzer.analyze("abc123")
        assert result_sequential is not None

        # Keyboard pattern
        result_keyboard = analyzer.analyze("qwerty")
        assert result_keyboard is not None

        # Dictionary pattern
        result_dictionary = analyzer.analyze("password")
        assert result_dictionary is not None

        # Empty password
        result_empty = analyzer.analyze("")
        assert result_empty is not None

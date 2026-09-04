"""
Unit tests for suggestions module
"""
from __future__ import annotations
import pytest

from password_validator.strength.analyzer import StrengthAnalysis
from password_validator.strength.analyzers.dictionary import DictionaryAnalysis
from password_validator.strength.analyzers.keyboard import KeyboardAnalysis
from password_validator.strength.analyzers.repeat import RepeatAnalysis
from password_validator.strength.analyzers.sequential import SequentialAnalysis
from password_validator.strength.suggestions import PasswordSuggestion, SuggestionGenerator, SuggestionResult


# Helpers
def empty_analysis() -> StrengthAnalysis:
    return StrengthAnalysis(
        dictionary=DictionaryAnalysis(),
        keyboard=KeyboardAnalysis(),
        repeat=RepeatAnalysis(),
        sequential=SequentialAnalysis()
    )


def analysis_with(*, dictionary=None, repeat=None, keyboard=None, sequential=None) -> StrengthAnalysis:
    return StrengthAnalysis(
        dictionary=dictionary or DictionaryAnalysis(),
        repeat=repeat or RepeatAnalysis(),
        keyboard=keyboard or KeyboardAnalysis(),
        sequential=sequential or SequentialAnalysis()
    )


# Password Suggestion
class TestPasswordSuggestion:
    def test_default_values(self):
        suggestion = PasswordSuggestion(
            code="test",
            message="Test message"
        )
        assert suggestion.code == "test"
        assert suggestion.message == "Test message"
        assert suggestion.priority == 0
        assert suggestion.category == "General"

    def test_custom_values(self):
        suggestion = PasswordSuggestion(
            code="increase_length",
            message="Use a longer password",
            priority=80,
            category="length"
        )
        assert suggestion.code == "increase_length"
        assert suggestion.message == "Use a longer password"
        assert suggestion.priority == 80
        assert suggestion.category == "length"

    def test_is_frozen(self):
        suggestion = PasswordSuggestion(code="test", message="Test")
        with pytest.raises(AttributeError):
            suggestion.code = "changed"


# Suggestion Result
class TestSuggestionResult:
    def test_default_result_has_no_suggestions(self):
        result = SuggestionResult()

        assert result.suggestions == []
        assert result.has_suggestions is False
        assert result.messages == []

    def test_result_returns_suggestions_attributes(self):
        result = SuggestionResult(
            suggestions=[
                PasswordSuggestion(
                    code="test_1",
                    message="Test message 1"
                ),
                PasswordSuggestion(
                    code="test_2",
                    message="Test message 2"
                )
            ]
        )
        assert result.has_suggestions is True
        assert result.messages == ["Test message 1", "Test message 2"]

    def test_default_lists_are_not_shared(self):
        first = SuggestionResult()
        second = SuggestionResult()

        first.suggestions.append(
            PasswordSuggestion(
                code="test",
                message="Test"
            )
        )
        assert second.suggestions == []


# Suggestions Generator (Length)
class TestLengthSuggestion:
    def test_short_password_gets_length_suggestion(self):
        result = SuggestionResult()
        SuggestionGenerator._add_length_suggestion("short", result)
        assert len(result.suggestions) == 1

        suggestion = result.suggestions[0]
        assert suggestion.code == "increase_length"
        assert suggestion.message == "Use a longer password of at lease 12 characters"
        assert suggestion.priority == 80
        assert suggestion.category == "length"

    @pytest.mark.parametrize("password", ["123456789012", "AbcdEfgh1234!", "Abc123!@xyz9"])
    def test_longer_password_gets_no_length_suggestion(self, password):
        result = SuggestionResult()
        SuggestionGenerator._add_length_suggestion(password, result)
        assert result.suggestions == []


# Suggestions Generator (Repeat)
class TestRepeatSuggestion:
    def test_detected_repeat_gets_suggestion(self):
        analysis = analysis_with(
            repeat=RepeatAnalysis(
                detected=True
            )
        )
        result = SuggestionResult()
        SuggestionGenerator._add_repeat_suggestion(analysis, result)
        assert len(result.suggestions) == 1

        suggestion = result.suggestions[0]
        assert suggestion.code == "avoid_repetition"
        assert suggestion.category == "pattern"
        assert suggestion.priority == 90
        assert suggestion.message == "Avoid repeated characters or character groups like 'aaa' or 'abcabc'"

    def test_no_repeat_gets_no_suggestion(self):
        result = SuggestionResult()
        SuggestionGenerator._add_repeat_suggestion(empty_analysis(), result)
        assert result.suggestions == []


# Suggestions Generator (Sequential)
class TestSequentialSuggestion:
    def test_detected_sequence_gets_suggestion(self):
        analysis = analysis_with(
            sequential=SequentialAnalysis(
                detected=True
            )
        )
        result = SuggestionResult()
        SuggestionGenerator._add_sequence_suggestion(analysis, result)
        assert len(result.suggestions) == 1

        suggestion = result.suggestions[0]
        assert suggestion.code == "avoid_sequences"
        assert suggestion.category == "pattern"
        assert suggestion.priority == 90
        assert suggestion.message == "Avoid use of sequential characters like 'abcd' or '1234'"

    def test_no_sequence_gets_no_suggestion(self):
        result = SuggestionResult()
        SuggestionGenerator._add_sequence_suggestion(empty_analysis(), result)
        assert len(result.suggestions) == 0
        assert result.suggestions == []


# Suggestions Generator (Keyboard)
class TestKeyboardSuggestion:
    def test_detected_keyboard_pattern_gets_suggestion(self):
        analysis = analysis_with(
            keyboard=KeyboardAnalysis(
                detected=True
            )
        )
        result = SuggestionResult()
        SuggestionGenerator._add_keyboard_suggestion(analysis, result)
        assert len(result.suggestions) == 1

        suggestion = result.suggestions[0]
        assert suggestion.code == "avoid_keyboard_patterns"
        assert suggestion.category == "pattern"
        assert suggestion.priority == 95
        assert suggestion.message == "Avoid keyboard patterns like 'asdf' or 'qwerty' or '1qaz'"

    def test_no_keyboard_pattern_gets_no_suggestion(self):
        result = SuggestionResult()
        SuggestionGenerator._add_keyboard_suggestion(empty_analysis(), result)
        assert len(result.suggestions) == 0
        assert result.suggestions == []


# Suggestions Generator (Dictionary)
class TestDictionarySuggestion:
    def test_detected_common_password_gets_suggestion(self):
        analysis = analysis_with(
            dictionary=DictionaryAnalysis(
                detected=True,
                common_password_detected=True
            )
        )
        result = SuggestionResult()
        SuggestionGenerator._add_dictionary_suggestion(analysis, result)
        assert len(result.suggestions) == 1

        suggestion = result.suggestions[0]
        assert suggestion.code == "avoid_common_password"
        assert suggestion.category == "dictionary"
        assert suggestion.priority == 100
        assert suggestion.message == "Avoid commonly used passwords. Choose something that is not used commonly"

    def test_no_common_password_gets_no_suggestion(self):
        result = SuggestionResult()
        SuggestionGenerator._add_dictionary_suggestion(empty_analysis(), result)
        assert len(result.suggestions) == 0
        assert result.suggestions == []

    # Dictionary Word
    def test_detected_dictionary_word_gets_suggestion(self):
        analysis = analysis_with(
            dictionary=DictionaryAnalysis(
                detected=True,
                common_password_detected=False,
                dictionary_word_detected=True
            )
        )
        result = SuggestionResult()
        SuggestionGenerator._add_dictionary_suggestion(analysis, result)
        assert len(result.suggestions) == 1

        suggestion = result.suggestions[0]
        assert suggestion.code == "avoid_dictionary_words"
        assert suggestion.category == "dictionary"
        assert suggestion.priority == 85
        assert suggestion.message == "Avoid using common dictionary words as the main part of your password"

    def test_no_dictionary_word_gets_no_suggestion(self):
        result = SuggestionResult()
        SuggestionGenerator._add_dictionary_suggestion(empty_analysis(), result)
        assert len(result.suggestions) == 0
        assert result.suggestions == []

    def test_common_password_takes_precedence_over_dictionary_word(self):
        analysis = analysis_with(
            dictionary=DictionaryAnalysis(detected=True, common_password_detected=True, dictionary_word_detected=True))

        result = SuggestionResult()
        SuggestionGenerator._add_dictionary_suggestion(analysis, result, )
        assert len(result.suggestions) == 1
        assert result.suggestions[0].code == "avoid_common_password"


# Suggestions Generator (Character Diversity)
class TestCharacterDiversity:
    def test_three_character_classes_gets_no_suggestion(self):
        result = SuggestionResult()
        SuggestionGenerator._add_character_diversity_suggestion("Abc123!", result)
        assert result.suggestions == []

    def test_different_character_classes_less_than_three_gets_suggestion(self):
        # Lowercase Only
        result = SuggestionResult()
        SuggestionGenerator._add_character_diversity_suggestion("abcdefg", result)
        assert len(result.suggestions) == 1
        assert result.suggestions[0].code == "increase_character_diversity"
        assert result.suggestions[0].message == \
               "Use mix of uppercase letters, lowercase letters, numbers and special characters"
        assert result.suggestions[0].priority == 70
        assert result.suggestions[0].category == "composition"

        # Uppercase Only
        SuggestionGenerator._add_character_diversity_suggestion("ABCDEFGH", result)
        assert len(result.suggestions) == 2
        assert result.suggestions[1].code == "increase_character_diversity"
        assert result.suggestions[1].message == \
               "Use mix of uppercase letters, lowercase letters, numbers and special characters"
        assert result.suggestions[1].priority == 70
        assert result.suggestions[1].category == "composition"

        # Digits
        SuggestionGenerator._add_character_diversity_suggestion("12345678", result)
        assert len(result.suggestions) == 3
        assert result.suggestions[2].code == "increase_character_diversity"
        assert result.suggestions[2].message == \
               "Use mix of uppercase letters, lowercase letters, numbers and special characters"
        assert result.suggestions[2].priority == 70
        assert result.suggestions[2].category == "composition"

        # Special
        SuggestionGenerator._add_character_diversity_suggestion("!@#$%^&*", result)
        assert len(result.suggestions) == 4
        assert result.suggestions[3].code == "increase_character_diversity"
        assert result.suggestions[3].message == \
               "Use mix of uppercase letters, lowercase letters, numbers and special characters"
        assert result.suggestions[3].priority == 70
        assert result.suggestions[3].category == "composition"


# Sorting
class TestSorting:
    def test_sorts_by_priority_descending(self):
        result = SuggestionResult(
            suggestions=[
                PasswordSuggestion(
                    code="low",
                    message="low",
                    priority=20
                ),
                PasswordSuggestion(
                    code="medium",
                    message="medium",
                    priority=50
                ),
                PasswordSuggestion(
                    code="high",
                    message="high",
                    priority=100
                )
            ]
        )
        SuggestionGenerator._sort(result)

        assert [suggestion.code for suggestion in result.suggestions] == ["high", "medium", "low"]

    def test_sort_handles_empty_result(self):
        result = SuggestionResult()

        SuggestionGenerator._sort(result)
        assert result.suggestions == []


# Full Generator
class TestSuggestionGenerator:
    def test_strong_long_password_has_no_length_suggestion(self):
        generator = SuggestionGenerator()

        analysis = empty_analysis()
        result = generator.generate("Abcdefghijk1!", analysis, )
        assert result.has_suggestions is False
        # Current character-diversity implementation uses isalnum()
        # as has_special, so the exact number of suggestions depends on that implementation.
        assert all(isinstance(suggestion, PasswordSuggestion) for suggestion in result.suggestions)

    def test_short_clean_password_gets_length_and_diversity_suggestions(self, ):
        generator = SuggestionGenerator()

        result = generator.generate("abc", empty_analysis(), )
        codes = [suggestion.code for suggestion in result.suggestions]
        assert "increase_length" in codes
        assert "increase_character_diversity" in codes

    def test_multiple_patterns_generate_multiple_suggestions(self):
        generator = SuggestionGenerator()
        analysis = StrengthAnalysis(dictionary=DictionaryAnalysis(detected=True, common_password_detected=True),
                                    repeat=RepeatAnalysis(detected=True), sequential=SequentialAnalysis(detected=True),
                                    keyboard=KeyboardAnalysis(detected=True))
        result = generator.generate("password123", analysis)
        codes = [suggestion.code for suggestion in result.suggestions]
        assert "avoid_common_password" in codes
        assert "avoid_repetition" in codes
        assert "avoid_sequences" in codes
        assert "avoid_keyboard_patterns" in codes
        assert "increase_length" in codes

    def test_full_result_is_sorted_by_priority(self):
        generator = SuggestionGenerator()

        analysis = StrengthAnalysis(dictionary=DictionaryAnalysis(detected=True, common_password_detected=True),
                                    repeat=RepeatAnalysis(detected=True), sequential=SequentialAnalysis(detected=True),
                                    keyboard=KeyboardAnalysis(detected=True))
        result = generator.generate("password123", analysis)
        priorities = [suggestion.priority for suggestion in result.suggestions]
        assert priorities == sorted(priorities, reverse=True)

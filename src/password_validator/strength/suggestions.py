"""
Password strength improvement suggestions module.
This module converts analyzer results into user-friendly recommendations.
It does not perform password validation or scoring.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from .analyzer import StrengthAnalysis


@dataclass(slots=True, frozen=True)
class PasswordSuggestion:
    """
    Represents a single password improvement suggestion.
    """
    code: str
    message: str
    priority: int = field(default=0)
    category: str = field(default="General")


@dataclass(slots=True)
class SuggestionResult:
    """
    Represents the complete result of password improvement suggestions.
    """
    suggestions: list[PasswordSuggestion] = field(default_factory=list)

    @property
    def has_suggestions(self) -> bool:
        """
        Checks if any suggestions are present.
        :return: True if there are suggestions, False otherwise.
        """
        return bool(self.suggestions)

    @property
    def messages(self) -> list[str]:
        """
        Returns a list of suggestion messages.
        :return: List of suggestion messages.
        """
        return [suggestion.message for suggestion in self.suggestions]


class SuggestionGenerator:
    """
    Generates user-friendly suggestions based on the results of password strength analysis.
    """

    def generate(self, password: str, analysis: StrengthAnalysis) -> SuggestionResult:
        """
        Generates suggestions based on the provided password and its strength analysis.
        :param password: The password to analyze.
        :param analysis: The result of the strength analysis.
        :return: A SuggestionResult containing improvement suggestions.
        """
        result = SuggestionResult()

        self._add_length_suggestion(password, result)
        self._add_repeat_suggestion(analysis, result)
        self._add_sequence_suggestion(analysis, result)
        self._add_keyboard_suggestion(analysis, result)
        self._add_dictionary_suggestion(analysis, result)
        self._add_character_diversity_suggestion(password, result)
        self._sort(result)

        return result

    @staticmethod
    def _add_length_suggestion(password: str, result: SuggestionResult) -> None:
        """
        Suggest increasing password length
        :param password:
        :param result:
        :return:
        """
        if len(password) >= 12:
            return

        result.suggestions.append(
            PasswordSuggestion(
                code="increase_length",
                message="Use a longer password of at lease 12 characters",
                priority=80,
                category="length"
            )
        )

    @staticmethod
    def _add_repeat_suggestion(analysis: StrengthAnalysis, result: SuggestionResult) -> None:
        """
        Suggest avoiding repeated characters/patterns
        :param analysis:
        :param result:
        :return:
        """
        if not analysis.repeat.detected:
            return

        result.suggestions.append(
            PasswordSuggestion(
                code="avoid_repetition",
                message="Avoid repeated characters or character groups like 'aaa' or 'abcabc'",
                priority=90,
                category="pattern"
            )
        )

    @staticmethod
    def _add_sequence_suggestion(analysis: StrengthAnalysis, result: SuggestionResult) -> None:
        """
        Suggest avoiding sequence of characters
        :param analysis:
        :param result:
        :return:
        """
        if not analysis.sequential.detected:
            return

        result.suggestions.append(
            PasswordSuggestion(
                code="avoid_sequences",
                message="Avoid use of sequential characters like 'abcd' or '1234'",
                priority=90,
                category="pattern"
            )
        )

    @staticmethod
    def _add_keyboard_suggestion(analysis: StrengthAnalysis, result: SuggestionResult) -> None:
        """
        Suggest avoiding keyboard walks
        :param analysis:
        :param result:
        :return:
        """
        if not analysis.keyboard.detected:
            return

        result.suggestions.append(
            PasswordSuggestion(
                code="avoid_keyboard_patterns",
                message="Avoid keyboard patterns like 'asdf' or 'qwerty' or '1qaz'",
                priority=95,
                category="pattern"
            )
        )

    @staticmethod
    def _add_dictionary_suggestion(analysis: StrengthAnalysis, result: SuggestionResult) -> None:
        """
        Suggest avoiding dictionary or common words
        :param analysis:
        :param result:
        :return:
        """
        if not analysis.dictionary.detected:
            return

        if analysis.dictionary.common_password_detected:
            result.suggestions.append(
                PasswordSuggestion(
                    code="avoid_common_password",
                    message="Avoid commonly used passwords. Choose something that is not used commonly",
                    priority=100,
                    category="dictionary"
                )
            )
        elif analysis.dictionary.dictionary_word_detected:
            result.suggestions.append(
                PasswordSuggestion(
                    code="avoid_dictionary_words",
                    message="Avoid using common dictionary words as the main part of your password",
                    priority=85,
                    category="dictionary"
                )
            )

    @staticmethod
    def _add_character_diversity_suggestion(password: str, result: SuggestionResult) -> None:
        """
        Suggest multiple character classes
        :param password:
        :param result:
        :return:
        """
        has_lower = any(character.islower() for character in password)
        has_upper = any(character.isupper() for character in password)
        has_digit = any(character.isdigit() for character in password)
        has_special = any(character.isalnum() for character in password)

        classes = sum(
            (
                has_lower,
                has_upper,
                has_digit,
                has_special
            )
        )

        if classes >= 3:
            return

        result.suggestions.append(
            PasswordSuggestion(
                code="increase_character_diversity",
                message="Use mix of uppercase letters, lowercase letters, numbers and special characters",
                priority=70,
                category="composition"
            )
        )

    @staticmethod
    def _sort(result: SuggestionResult) -> None:
        """
        Sort suggestions by priority
        :param result:
        :return:
        """
        result.suggestions.sort(
            key=lambda item: item.priority,
            reverse=True
        )

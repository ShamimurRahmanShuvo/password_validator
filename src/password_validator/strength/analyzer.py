"""
Password strength analyzer orchestration.
This module coordinates all individual strength analyzer.
It doesn't calculate the final password score.
That responsibility is handled by PasswordStrengthScorer.
"""
from __future__ import annotations
from dataclasses import dataclass

from .analyzers import (
    DictionaryAnalysis, DictionaryAnalyzer,
    RepeatAnalysis, RepeatAnalyzer,
    SequentialAnalysis, SequentialAnalyzer,
    KeyboardAnalysis, KeyboardAnalyzer
)
from .config import StrengthConfig


@dataclass(slots=True)
class StrengthAnalysis:
    """
    Represents the complete result of password strength analysis.
    """
    dictionary: DictionaryAnalysis
    repeat: RepeatAnalysis
    sequential: SequentialAnalysis
    keyboard: KeyboardAnalysis

    @property
    def has_patterns(self) -> bool:
        """
        Checks if any patterns were detected in the password.
        :return:
        """
        return any(
            (
                self.dictionary.detected,
                self.repeat.detected,
                self.sequential.detected,
                self.keyboard.detected
            )
        )

    @property
    def maximum_severity(self) -> float:
        """
        Returns the maximum severity score from all analyzers.
        :return:
        """
        return max(
            self.dictionary.severity,
            self.repeat.severity,
            self.sequential.severity,
            self.keyboard.severity
        )


class StrengthAnalyzer:
    """
    Orchestrates the execution of all individual strength analyzers.
    """

    def __init__(
            self,
            config: StrengthConfig | None = None,
            repeat_analyzer: RepeatAnalyzer | None = None,
            sequential_analyzer: SequentialAnalyzer | None = None,
            keyboard_analyzer: KeyboardAnalyzer | None = None,
            dictionary_analyzer: DictionaryAnalyzer | None = None
    ):
        self.config = config or StrengthConfig.from_env()
        self.repeat_analyzer = repeat_analyzer or RepeatAnalyzer(config=self.config)
        self.sequential_analyzer = sequential_analyzer or SequentialAnalyzer(config=self.config)
        self.keyboard_analyzer = keyboard_analyzer or KeyboardAnalyzer(config=self.config)
        self.dictionary_analyzer = dictionary_analyzer or DictionaryAnalyzer(config=self.config)

    def analyze(self, password: str) -> StrengthAnalysis:
        """
        Analyzes the given password using all strength analyzers.
        :param password: The password to analyze.
        :return: A StrengthAnalysis object containing results from all analyzers.
        """
        if not self.config.enabled:
            return StrengthAnalysis(
                dictionary=DictionaryAnalysis(),
                repeat=RepeatAnalysis(),
                sequential=SequentialAnalysis(),
                keyboard=KeyboardAnalysis()
            )

        dictionary_result = self.dictionary_analyzer.analyze(password)
        repeat_result = self.repeat_analyzer.analyze(password)
        sequential_result = self.sequential_analyzer.analyze(password)
        keyboard_result = self.keyboard_analyzer.analyze(password)

        return StrengthAnalysis(
            dictionary=dictionary_result,
            repeat=repeat_result,
            sequential=sequential_result,
            keyboard=keyboard_result
        )

"""
Dictionary and common password analyzer for password strength evaluation.
Detects:
    1. Exact common passwords.
    2. Dictionary words.
    3. Dictionary words embedded in passwords.
    4. Common leetspeak substitutions.
The analyzer only detects weaknesses. Scoring penalties are applied by PasswordStrengthScorer.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import re

from ..config import StrengthConfig


class DictionaryMatchType(str, Enum):
    """Enum for dictionary match types."""
    EXACT_COMMON_PASSWORD = "exact_common_password"
    COMMON_PASSWORD_SUBSTRING = "common_password_substring"
    EXACT_DICTIONARY_WORD = "exact_dictionary_word"
    DICTIONARY_WORD_SUBSTRING = "dictionary_word_substring"


@dataclass(slots=True, frozen=True)
class DictionaryMatch:
    """
    Represents a dictionary match detected in a password.
    """
    value: str
    normalized_value: str
    match_type: DictionaryMatchType
    start_position: int
    end_position: int
    severity: float
    message: str


@dataclass(slots=True)
class DictionaryAnalysis:
    """
    Complete result of dictionary pattern analysis for a password.
    """
    detected: bool = False
    matches: list[DictionaryMatch] = field(default_factory=list)
    common_password_detected: bool = False
    dictionary_word_detected: bool = False
    exact_match_detected: bool = False
    embedded_match_detected: bool = False
    severity: float = 0.0
    penalty_factor: float = 0.0

    @property
    def match_count(self) -> int:
        """Returns the number of detected dictionary matches."""
        return len(self.matches)


class DictionaryAnalyzer:
    """
    Analyzer for detecting dictionary words and common passwords in a password.
    Usages:
        analyzer = DictionaryAnalyzer()
        result = analyzer.analyze(password)
        if result.detected:
            print(result.matches)
    """
    _DEFAULT_COMMON_PASSWORDS = frozenset(
        {
            "password", "password1", "password123", "123456", "12345678", "123456789", "1234567890", "qwerty",
            "qwerty123", "admin", "admin123", "administrator", "welcome", "welcome1", "letmein", "login", "passw0rd",
            "p@ssword", "abc123", "iloveyou", "monkey", "dragon", "master", "football", "baseball", "secret",
            "changeme",
        }
    )

    _LEET_MAP = str.maketrans(
        {
            "0": "o",
            "1": "i",
            "3": "e",
            "4": "a",
            "5": "s",
            "7": "t",
            "@": "a",
            "$": "s",
            "!": "i",
        }
    )

    def __init__(self, config: StrengthConfig | None = None):
        self.config = config or StrengthConfig.from_env()
        self._dictionary_words = set()
        self._common_passwords = set(self._DEFAULT_COMMON_PASSWORDS)
        self._load_external_sources()

    def analyze(self, password: str) -> DictionaryAnalysis:
        """
        Analyze the given password for dictionary and common password matches.
        :param password: The password to analyze.
        :return: DictionaryAnalysis object containing the results.
        """
        result = DictionaryAnalysis()

        if not password:
            return result

        if not self.config.check_dictionary:
            return result

        normalized = self._normalize(password)
        self._check_common_passwords(password=password, normalized=normalized, result=result)
        self._check_dictionary_words(password=password, normalized=normalized, result=result)
        self._finalize(result)

        return result

    def _load_external_sources(self) -> None:
        """
        Load dictionary words and common passwords from external files if specified in the config.
        """
        if self.config.dictionary_file:
            self._dictionary_words.update(
                self._load_word_file(
                    self.config.dictionary_file
                )
            )

        if self.config.check_common_passwords and self.config.common_password_file:
            self._common_passwords.update(
                self._load_word_file(
                    self.config.common_password_file
                )
            )

    def _load_word_file(self, filename: str) -> set[str]:
        """
        Load newline separated words. Missing files are ignored.
        :param filename:
        :return:
        """
        path = Path(filename)

        if not path.exists():
            return set()

        if not path.is_file():
            return set()

        words = set()

        with path.open("r", encoding="utf-8") as file:
            for line in file:
                word = line.strip()
                if not word:
                    continue

                if word.startswith("#"):
                    continue

                if len(word) < self.config.min_word_length:
                    continue

                if self.config.case_insensitive:
                    word = word.lower()

                words.add(word)

        return words

    def _normalize(self, password: str) -> str:
        """
        Normalize the password based on configuration.
        :param password: The password to normalize.
        :return: Normalized password.
        """
        normalized = password
        if self.config.case_insensitive:
            normalized = normalized.lower()
        if self.config.leet_normalization:
            normalized = normalized.translate(self._LEET_MAP)

        normalized = re.sub(r"[^a-zA-Z0-9]", "", normalized)

        return normalized.lower()

    def _check_common_passwords(self, password: str, normalized: str, result: DictionaryAnalysis) -> None:
        """
        Check if the password matches any common passwords.
        :param password: The original password.
        :param normalized: The normalized password.
        :param result: The analysis result to update.
        """
        if not self.config.check_common_passwords:
            return

        # Exat raw/normalized match
        if password.lower() in self._common_passwords:
            self._add_match(
                result=result,
                value=password,
                normalized_value=normalized,
                match_type=DictionaryMatchType.EXACT_COMMON_PASSWORD,
                start=0,
                end=len(password),
                severity=1.0,
                message="Password matches a common password."
            )

            return

        # Exact Normalized match
        if normalized in self._common_passwords:
            self._add_match(
                result=result,
                value=password,
                normalized_value=normalized,
                match_type=DictionaryMatchType.EXACT_COMMON_PASSWORD,
                start=0,
                end=len(password),
                severity=1.0,
                message="Password matches a common password after normalization."
            )

            return

        # Embedded match
        for common in self._common_passwords:
            if len(common) < self.config.min_word_length:
                continue

            index = normalized.find(common)
            if index == -1:
                continue

            self._add_match(
                result=result,
                value=common,
                normalized_value=common,
                match_type=DictionaryMatchType.COMMON_PASSWORD_SUBSTRING,
                start=index,
                end=index + len(common),
                severity=0.85,
                message=f"Password contains a common password substring: '{common}'."
            )

    def _check_dictionary_words(self, password: str, normalized: str, result: DictionaryAnalysis) -> None:
        """
        Check if the password contains any dictionary words.
        :param password: The original password.
        :param normalized: The normalized password.
        :param result: The analysis result to update.
        """
        if not self.config.check_dictionary_words:
            return

        if not self._dictionary_words:
            return

        if normalized in self._dictionary_words:
            self._add_match(
                result=result,
                value=password,
                normalized_value=normalized,
                match_type=DictionaryMatchType.EXACT_DICTIONARY_WORD,
                start=0,
                end=len(password),
                severity=0.9,
                message="Password matches a dictionary word."
            )
            return

        for word in self._dictionary_words:
            if len(word) < self.config.min_word_length:
                continue

            index = normalized.find(word)

            if index == -1:
                continue

            self._add_match(
                result=result,
                value=word,
                normalized_value=word,
                match_type=DictionaryMatchType.DICTIONARY_WORD_SUBSTRING,
                start=index,
                end=index + len(word),
                severity=0.75,
                message=f"Password contains a dictionary word substring: '{word}'."
            )

    def _add_match(self, result: DictionaryAnalysis, value: str, normalized_value: str,
                   match_type: DictionaryMatchType, start: int, end: int, severity: float, message: str) -> None:
        """
        Add a match to the result.
        :param result:
        :param value:
        :param normalized_value:
        :param match_type:
        :param start:
        :param end:
        :param severity:
        :param message:
        :return:
        """
        for existing in result.matches:
            if (
                existing.normalized_value == normalized_value and existing.match_type == match_type
            ):
                return

        result.matches.append(
            DictionaryMatch(
                value=value,
                normalized_value=normalized_value,
                match_type=match_type,
                start_position=start,
                end_position=end,
                severity=severity,
                message=message
            )
        )

        if match_type in {DictionaryMatchType.EXACT_COMMON_PASSWORD, DictionaryMatchType.COMMON_PASSWORD_SUBSTRING}:
            result.common_password_detected = True

        if match_type in {DictionaryMatchType.EXACT_DICTIONARY_WORD, DictionaryMatchType.DICTIONARY_WORD_SUBSTRING}:
            result.dictionary_word_detected = True

        if match_type in {DictionaryMatchType.EXACT_COMMON_PASSWORD, DictionaryMatchType.EXACT_DICTIONARY_WORD}:
            result.exact_match_detected = True
        else:
            result.embedded_match_detected = True

    @staticmethod
    def _finalize(result: DictionaryAnalysis) -> None:
        """
        Finalize the analysis result by setting the overall severity.
        :param result: The analysis result to finalize.
        :return: None
        """
        result.detected = bool(result.matches)

        if not result.detected:
            result.severity = 0.0
            result.penalty_factor = 0.0
            return

        result.severity = min(1.0, max(match.severity for match in result.matches))
        result.penalty_factor = result.severity

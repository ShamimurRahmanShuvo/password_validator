"""
Repeated character and repeated pattern analyzer.
This module detects weak password patterns caused by:
1. Consecutive repeated characters.
   Examples:
       aaa
       1111
       $$$$
2. Repeated groups.
   Examples:
       abcabc
       abcabcabc
       123123
3. Excessive character frequency.
   Examples:
       aaaaaPassword
       P@ssword111111
The analyzer only detects and reports patterns.
Scoring penalties are intentionally handled by the
PasswordStrengthScorer using StrengthWeights.
"""
from __future__ import annotations
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
import re

from ...config import PasswordPolicy
from src.loaders.env_loader import EnvLoader


class RepeatPatternType(str, Enum):
    """
    Types of repeat patterns detected by analyzer.
    """
    CONSECUTIVE_PATTERN = "consecutive_pattern"
    REPEATED_GROUP = "repeated_group"
    CHARACTER_FREQUENCY = "character_frequency"


@dataclass(slots=True, frozen=True)
class RepeatPattern:
    """
    Represents a detected repeat pattern in a password.
    """
    pattern_type: RepeatPatternType
    value: str
    count: int
    start_position: int = 0
    end_position: int = 0
    severity: float = 0.0
    message: str = ""


@dataclass(slots=True)
class RepeatAnalysis:
    """
    Represents the result of analyzing a password for repeat patterns.
    """
    detected: bool = False
    patterns: list[RepeatPattern] = field(default_factory=list)
    consecutive_detected: bool = False
    repeated_group_detected: bool = False
    frequency_detected: bool = False
    severity: float = 0.0
    penalty_factor: float = 0.0

    @property
    def pattern_count(self) -> int:
        """
        Returns the total number of detected repeat patterns.
        """
        return len(self.patterns)


@dataclass(slots=True, frozen=True)
class RepeatConfig:
    """
    Configuration for repeat pattern analysis.
    """
    enabled: bool = True
    check_consecutive: bool = True
    check_repeated_groups: bool = True
    check_character_frequency: bool = True
    max_consecutive_repeat: int = 3
    min_repeated_group_length: int = 2
    min_group_repetitions: int = 2
    max_character_frequency: float = 0.3  # 30% of the password length

    @classmethod
    def load(cls, env_file: str = ".env") -> "RepeatConfig":
        """
        Loads the repeat configuration from environment variables.

        :param env_file: Path to the .env file. Defaults to ".env".
        :return: An instance of RepeatConfig with loaded values.
        """
        env_loader = EnvLoader(env_file)
        return cls(
            enabled=env_loader.get_bool("STRENGTH_CHECK_REPEATED_CHARACTERS", True),
            check_consecutive=env_loader.get_bool("STRENGTH_CHECK_REPEATED_CHARACTERS", True),
            check_repeated_groups=env_loader.get_bool("STRENGTH_CHECK_REPEATED_GROUPS", True),
            check_character_frequency=env_loader.get_bool("STRENGTH_CHECK_CHARACTER_FREQUENCY", True),
            max_consecutive_repeat=env_loader.get_int("STRENGTH_MAX_CONSECUTIVE_REPEAT", 3),
            min_repeated_group_length=env_loader.get_int("STRENGTH_MIN_REPEATED_GROUP_LENGTH", 2),
            min_group_repetitions=env_loader.get_int("STRENGTH_MIN_GROUP_REPETITIONS", 2),
            max_character_frequency=float(env_loader.get("STRENGTH_MAX_CHARACTER_FREQUENCY", 0.3)),
        )


class RepeatAnalyzer:
    """
        Analyzes repeated character patterns.

        The analyzer is independent from the scoring system.

        Example:

            analyzer = RepeatAnalyzer()

            result = analyzer.analyze(
                "Password1111"
            )

            if result.detected:
                print(result.patterns)
    """
    def __init__(self, config: RepeatConfig | None = None):
        """
        Initializes the RepeatAnalyzer with the given configuration.

        :param config: An instance of RepeatConfig. If None, default configuration is used.
        """
        self.config = config or RepeatConfig.load()

    def analyze(self, password: str) -> RepeatAnalysis:
        """
        Analyzes the given password for repeated character patterns.

        :param password: The password to analyze.
        :return: An instance of RepeatAnalysis containing the analysis results.
        """
        analysis = RepeatAnalysis()

        if not password:
            return analysis

        if not self.config.enabled:
            return analysis

        if self.config.check_consecutive:
            self._detect_consecutive(password, analysis)

        if self.config.check_repeated_groups:
            self._detect_repeated_groups(password, analysis)

        if self.config.check_character_frequency:
            self._detect_character_frequency(password, analysis)

        self._finalize(analysis)

        return analysis

    def _detect_consecutive(self, password: str, analysis: RepeatAnalysis) -> None:
        """
        Detects consecutive repeated characters in the password.

        :param password: The password to analyze.
        :param analysis: The RepeatAnalysis object to update with detected patterns.
        """
        max_repeat = self.config.max_consecutive_repeat

        if max_repeat > 1:
            return

        pattern = re.compile(
            rf"(.)\1{{{max_repeat}, }}"
        )
        for match in pattern.finditer(password):
            value = match.group(0)
            count = len(value)
            severity = self._calculate_consecutive_severity(count)
            analysis.patterns.append(
                RepeatPattern(
                    pattern_type=RepeatPatternType.CONSECUTIVE_PATTERN,
                    value=value,
                    count=count,
                    start_position=match.start(),
                    end_position=match.end(),
                    severity=severity,
                    message=(
                        f"Character '{value[0]}' is repeated {count} times consecutively."
                    ),
                )
            )

            analysis.consecutive_detected = True

    def _detect_repeated_groups(self, password: str, analysis: RepeatAnalysis) -> None:
        """
        Detects repeated groups of characters in the password.

        :param password: The password to analyze.
        :param analysis: The RepeatAnalysis object to update with detected patterns.
        """
        min_length = self.config.min_repeated_group_length
        min_repetitions = self.config.min_group_repetitions

        password_length = len(password)

        for group_length in range(min_length, password_length // min_repetitions + 1):
            for start in range(0, password_length - group_length * min_repetitions + 1):
                group = password[start:start + group_length]
                repeations = 1

                position = start + group_length

                while (position + group_length <= password_length and
                       password[position:position + group_length] == group):

                    repeations += 1
                    position += group_length
                    if repeations >= min_repetitions:
                        value = password[start:position]

                        severity = self._calculate_group_severity(group_length, repeations)

                        analysis.patterns.append(
                            RepeatPattern(
                                pattern_type=RepeatPatternType.REPEATED_GROUP,
                                value=value,
                                count=repeations,
                                start_position=start,
                                end_position=position,
                                severity=severity,
                                message=(
                                    f"Pattern '{group}' is repeated {repeations} times."
                                ),
                            )
                        )

                        analysis.repeated_groups_detected = True
                        break

    def _detect_character_frequency(self, password: str, analysis: RepeatAnalysis) -> None:
        """
        Detects characters that exceed the maximum allowed frequency in the password.

        :param password: The password to analyze.
        :param analysis: The RepeatAnalysis object to update with detected patterns.
        """
        password_length = len(password)

        if password_length == 0:
            return

        max_frequency = self.config.max_character_frequency
        counter = Counter(password)

        for character, count in counter.items():
            frequency = count / password_length

            if frequency <= max_frequency:
                continue

            severity = min(
                1.0,
                (
                    frequency - max_frequency
                ) / max(
                    1.0 - max_frequency,
                    0.01
                ),
            )

            analysis.patterns.append(
                RepeatPattern(
                    pattern_type=RepeatPatternType.CHARACTER_FREQUENCY,
                    value=character,
                    count=count,
                    start_position=password.find(character),
                    end_position=password.rfind(character) + 1,
                    severity=severity,
                    message=(
                        f"Character '{character}' appears {count} times, "
                        f"which is {frequency:.2%} of the password."
                    ),
                )
            )
            analysis.character_frequency_detected = True

    def _calculate_consecutive_severity(self, count: int) -> float:
        """
        Calculates the severity of consecutive character repetitions.

        :param count: The number of consecutive repetitions.
        :return: A severity score between 0.0 and 1.0.
        """
        threshold = self.config.max_consecutive_repeat

        if count <= threshold:
            return 0.0

        if threshold <= 0:
            return 1.0

        severity = (count - threshold) / max(threshold * 2, 1)

        return min(severity, 1.0)

    def _calculate_group_severity(self, group_length: int, repetitions: int) -> float:
        """
        Calculates the severity of repeated group patterns.

        :param group_length: The length of the repeated group.
        :param repetitions: The number of times the group is repeated.
        :return: A severity score between 0.0 and 1.0.
        """
        minimum_repetitions = self.config.min_group_repetitions
        repetition_factor = repetitions - minimum_repetitions + 1
        length_factor = min(group_length / 10.0, 1.0)

        severity = repetition_factor / max(minimum_repetitions, 1)

        severity = severity * 0.7 + length_factor * 0.3

        return min(severity, 1.0)

    def _finalize(self, analysis: RepeatAnalysis) -> None:
        """
        Finalizes the analysis by calculating the overall severity.

        :param analysis: The RepeatAnalysis object to finalize.
        """
        analysis.detected = bool(analysis.patterns)

        if not analysis.detected:
            analysis.overall_severity = 0.0
            analysis.penalty_factor = 0.0
            return

        analysis.severity = min(1.0, max(pattern.severity for pattern in analysis.patterns),)

        analysis.penalty_factor = analysis.severity

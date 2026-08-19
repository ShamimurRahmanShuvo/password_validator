"""
Sequential character pattern analyzer for password strength evaluation.
Detects ascending and descending sequences of characters in passwords, which can indicate weak patterns.
The analyzer detects pattern only. Scoring penalties are applied by PasswordStrengthScored using StrengthWeights
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum

from src.loaders.env_loader import EnvLoader


class SequenceDirection(str, Enum):
    """Enum for sequence detection types."""
    ASCENDING = "ascending"
    DESCENDING = "descending"


class SequenceType(str, Enum):
    """Enum for sequence types."""
    DIGIT = "digit"
    LOWERCASE = "lowercase"
    UPPERCASE = "uppercase"
    MIXED = "mixed"


@dataclass(slots=True, frozen=True)
class SequentialPattern:
    """
    Represents a sequential character pattern detected in a password.
    """
    value: str
    direction: SequenceDirection
    sequence_type: SequenceType
    start_position: int
    end_position: int
    length: int
    severity: float
    message: str


@dataclass(slots=True)
class SequentialAnalysis:
    """
    Complete result of sequential pattern analysis for a password.
    """
    detected: bool = False
    patterns: list[SequentialPattern] = field(default_factory=list)
    ascending_detected: bool = False
    descending_detected: bool = False
    severity: float = 0.0
    penalty_factor: float = 0.0

    @property
    def pattern_count(self) -> int:
        """Returns the number of detected sequential patterns."""
        return len(self.patterns)


@dataclass(slots=True, frozen=True)
class SequentialConfig:
    """
    Configuration for sequential pattern detection in passwords.
    """
    enabled: bool = True
    min_sequence_length: int = 4
    check_digits: bool = True
    check_lowercase: bool = True
    check_uppercase: bool = True
    check_mixed: bool = False

    @classmethod
    def load(cls, env_file: str = ".env") -> "SequentialConfig":
        """
        Load configuration from environment variables.
        :param env_file:
        :return:
        """
        env = EnvLoader(env_file)
        return cls(
            enabled=env.get_bool("STRENGTH_CHECK_SEQUENTIAL", True),
            min_sequence_length=env.get_int("STRENGTH_MIN_SEQUENCE_LENGTH", 4),
            check_digits=env.get_bool("STRENGTH_CHECK_DIGIT_SEQUENCES", True),
            check_lowercase=env.get_bool("STRENGTH_CHECK_LOWERCASE_SEQUENCES", True),
            check_uppercase=env.get_bool("STRENGTH_CHECK_UPPERCASE_SEQUENCES", True),
            check_mixed=env.get_bool("STRENGTH_CHECK_MIXED_SEQUENCES", False),
        )


class SequentialAnalyzer:
    """
    Detects sequential character patterns in passwords, such as ascending or descending sequences of digits or letters.
    Usage:
        analyzer = SequentialAnalyzer(config=SequentialConfig.load())
        result = analyzer.analyze(password)
        if result.detected:
            print(f"Detected {pattern.direction} sequence: {pattern.value} at positions {pattern.start_position}-{pattern.end_position}")
    """
    def __init__(self, config: SequentialConfig):
        self.config = config or SequentialConfig.load()

    def analyze(self, password: str) -> SequentialAnalysis:
        """
        Analyze the given password for sequential character patterns.
        :param password: The password string to analyze.
        :return: SequentialAnalysis object containing detected patterns and severity.
        """
        result = SequentialAnalysis()

        if not password:
            return result  # Return empty result for empty password

        if not self.config.enabled:
            return result

        self._scan(password, result)
        self._finalize(result)

        return result

    def _scan(self, password: str, result: SequentialAnalysis) -> None:
        """
        Scan the password for sequential patterns based on the configuration.
        :param password: The password string to analyze.
        :param result: SequentialAnalysis object to store detected patterns.
        """
        minimum = self.config.min_sequence_length

        if minimum < 2:
            minimum = 2

        start = 0

        while start < len(password):
            sequence_type = self._get_sequence_type(password[start])

            if sequence_type is None and not self.config.check_mixed:
                start += 1
                continue

            end = start + 1

            while end < len(password):
                previous = password[end - 1]
                current = password[end]

                if self._is_valid_sequence_pair(previous, current, sequence_type):
                    end += 1
                    continue

                break

            length = end - start

            if length >= minimum:
                value = password[start:end]
                direction = self._get_sequence_direction(value)

                if direction is not None:
                    self._add_pattern(
                        result=result,
                        value=value,
                        direction=direction,
                        sequence_type=sequence_type or SequenceType.MIXED,
                        start=start,
                        end=end,
                    )
            start = max(start + 1, end)

    def _is_valid_sequence_pair(self, previous: str, current: str, sequence_type: SequenceType | None) -> bool:
        """
        Determine if the pair of characters (previous, current) forms a valid sequential pattern based
        on the sequence type.
        :param previous:
        :param current:
        :param sequence_type:
        :return:
        """
        if sequence_type == SequenceType.DIGIT:
            return current.isdigit() and previous.isdigit()

        if sequence_type == SequenceType.LOWERCASE:
            return current.islower() and previous.islower()

        if sequence_type == SequenceType.UPPERCASE:
            return current.isupper() and previous.isupper()

        return previous.isalnum() and current.isalnum()

    def _get_sequence_type(self, character: str) -> SequenceType | None:
        """
        Determine the sequence type of a character.
        :param char: The character to evaluate.
        :return: SequenceType or None if not applicable.
        """
        if character.isdigit():
            if not self.config.check_digits:
                return None

            return SequenceType.DIGIT

        if character.islower():
            if not self.config.check_lowercase:
                return None

            return SequenceType.LOWERCASE

        if character.isupper():
            if not self.config.check_uppercase:
                return None

            return SequenceType.UPPERCASE

        return None

    @staticmethod
    def _get_sequence_direction(value: str) -> SequenceDirection | None:
        """
        Determine the direction of a sequential pattern (ascending or descending).
        :param value:
        :return:
        """
        if len(value) < 2:
            return None

        values = [ord(c) for c in value]

        differences = [values[index + 1] - values[index] for index in range(len(values) - 1)]

        if all(difference > 0 for difference in differences):
            return SequenceDirection.ASCENDING

        if all(difference < 0 for difference in differences):
            return SequenceDirection.DESCENDING

        return None

    def _add_pattern(
        self,
        result: SequentialAnalysis,
        value: str,
        direction: SequenceDirection,
        sequence_type: SequenceType,
        start: int,
        end: int
    ) -> None:
        """
        Add a detected sequential pattern to the analysis result.
        :param result:
        :param value:
        :param direction:
        :param sequence_type:
        :param start:
        :param end:
        """
        severity = self._calculate_severity(len(value))

        pattern = SequentialPattern(
            value=value,
            direction=direction,
            sequence_type=sequence_type,
            start_position=start,
            end_position=end,
            length=len(value),
            severity=severity,
            message=(
                f"Sequential pattern detected: {value} detected as {direction.value} "
                f"sequence of type {sequence_type.value}."
            ),
        )

        result.patterns.append(pattern)

        if direction == SequenceDirection.ASCENDING:
            result.ascending_detected = True
        elif direction == SequenceDirection.DESCENDING:
            result.descending_detected = True

    def _calculate_severity(self, length: int) -> float:
        """
        Calculate the severity based on the length of the detected sequential pattern.
        :param length: Length of the detected sequential pattern.
        :return: Severity
        """
        minimum = max(self.config.min_sequence_length, 2)
        severity = (length - minimum + 1) / max(minimum, 1)

        return min(1.0, max(0.0, severity))

    @staticmethod
    def _finalize(result: SequentialAnalysis) -> None:
        """
        Finalize the analysis result by determining if any patterns were detected.
        :param result:
        """
        result.detected = bool(result.patterns)

        if not result.detected:
            result.severity = 0.0
            result.penalty_factor = 0.0
            result.message = "No sequential patterns detected."

            return

        result.severity = min(1.0, max(pattern.severity for pattern in result.patterns))

        result.penalty_factor = result.severity

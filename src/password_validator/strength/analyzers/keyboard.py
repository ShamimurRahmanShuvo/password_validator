"""
Keyboard Pattern Analyzer
The analyzer only detects patterns. Scoring penalties are applied by PasswordStrengthScored using StrengthWeights.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum

from src.loaders.env_loader import EnvLoader


class KeyboardPatternType(str, Enum):
    """Enum for keyboard categories"""
    HORIZONTAL = "horizontal"
    VERTICAL = "vertical"
    DIAGONAL = "diagonal"
    NUMBER_ROW = "number_row"


@dataclass(slots=True, frozen=True)
class KeyboardPattern:
    """
    Represents a keyboard pattern detected in a password.
    """
    value: str
    normalized_value: str
    pattern_type: KeyboardPatternType
    start_position: int
    end_position: int
    length: int
    reversed_pattern: bool
    severity: float
    message: str


@dataclass(slots=True)
class KeyboardAnalysis:
    """
    Complete result of keyboard pattern analysis for a password.
    """
    detected: bool = False
    patterns: list[KeyboardPattern] = field(default_factory=list)
    horizontal_detected: bool = False
    vertical_detected: bool = False
    diagonal_detected: bool = False
    number_row_detected: bool = False
    severity: float = 0.0
    penalty_factor: float = 0.0

    @property
    def pattern_count(self) -> int:
        """Returns the number of detected keyboard patterns."""
        return len(self.patterns)


@dataclass(slots=True, frozen=True)
class KeyboardConfig:
    """
    Configuration for keyboard pattern detection in passwords.
    """
    enabled: bool = True
    min_pattern_length: int = 4
    check_horizontal: bool = True
    check_vertical: bool = True
    check_diagonal: bool = True
    check_number_row: bool = True
    case_insensitive: bool = True

    @classmethod
    def load(cls, env_file:str = ".env") -> "KeyboardConfig":
        """
        Load configuration from environment variables.
        """
        env = EnvLoader(env_file)
        return cls(
            enabled=env.get_bool("STRENGTH_CHECK_KEYBOARD_PATTERNS", True),
            min_pattern_length=env.get_int("STRENGTH_MIN_KEYBOARD_PATTERN_LENGTH", 4),
            check_horizontal=env.get_bool("STRENGTH_CHECK_HORIZONTAL_KEYBOARD", True),
            check_vertical=env.get_bool("STRENGTH_CHECK_VERTICAL_KEYBOARD", True),
            check_diagonal=env.get_bool("STRENGTH_CHECK_DIAGONAL_KEYBOARD", True),
            check_number_row=env.get_bool("STRENGTH_CHECK_NUMBER_ROW_KEYBOARD", True),
            case_insensitive=env.get_bool("STRENGTH_KEYBOARD_CASE_INSENSITIVE", True),
        )


class KeyboardAnalyzer:
    """
    Analyzes passwords for keyboard patterns based on the provided configuration.
    Usages:
        analyzer = KeyboardAnalyzer()
        result = analyzer.analyze("MyPasswordQwerty123")
    """
    # Horizontal keyboard rows.
    _HORIZONTAL_PATTERNS = (
        "1234567890",
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm",
    )

    # Vertical keyboard columns.
    _VERTICAL_PATTERNS = (
        "1qaz",
        "2wsx",
        "3edc",
        "4rfv",
        "5tgb",
        "6yhn",
        "7ujm",
        "8ik",
        "9ol",
        "0p",
    )

    # Diagonal keyboard movements.
    _DIAGONAL_PATTERNS = (
        "1qws",
        "2wed",
        "3erf",
        "4rtg",
        "5tyh",
        "6yui",
        "7uij",
        "8iok",
        "9opl",
    )

    def __init__(self, config: KeyboardConfig | None = None):
        self.config = config or KeyboardConfig.load()
        self._patterns = self._build_patterns()

    def analyze(self, password: str) -> KeyboardAnalysis:
        """
        Analyze the given password for keyboard patterns.
        :param password: The password to analyze.
        :return: KeyboardAnalysis object containing the analysis results.
        """
        result = KeyboardAnalysis()

        if not password:
            return result

        if not self.config.enabled:
            return result

        value = password.lower() if self.config.case_insensitive else password

        self._scan_horizontal(password, value, result)
        self._scan_vertical(password, value, result)
        self._scan_diagonal(password, value, result)
        self._scan_number_row(password, value, result)
        self._finalize(result)

        return result

    def _build_patterns(self) -> dict[KeyboardPatternType, tuple[str, ...]]:
        """
        Build enabled keyboard pattern sets.
        :return:
        """
        patterns = {}

        if self.config.check_horizontal:
            patterns[KeyboardPatternType.HORIZONTAL] = self._HORIZONTAL_PATTERNS

        if self.config.check_vertical:
            patterns[KeyboardPatternType.VERTICAL] = self._VERTICAL_PATTERNS

        if self.config.check_diagonal:
            patterns[KeyboardPatternType.DIAGONAL] = self._DIAGONAL_PATTERNS

        if self.config.check_number_row:
            patterns[KeyboardPatternType.NUMBER_ROW] = (self._HORIZONTAL_PATTERNS[:1])

        return patterns

    def _scan_horizontal(self, original: str, normalized: str, result: KeyboardAnalysis) -> None:
        """
        Scan the password for horizontal keyboard patterns.
        :param original:
        :param normalized:
        :param result:
        :return:
        """
        if not self.config.check_horizontal:
            return

        patterns = self._HORIZONTAL_PATTERNS

        self._scan_patterns(
            original=original,
            normalized=normalized,
            patterns=patterns,
            pattern_type=KeyboardPatternType.HORIZONTAL,
            result=result
        )

    def _scan_vertical(self, original: str, normalized: str, result: KeyboardAnalysis) -> None:
        """
        Scan the password for vertical keyboard patterns.
        :param original:
        :param normalized:
        :param result:
        :return:
        """
        if not self.config.check_vertical:
            return

        patterns = self._VERTICAL_PATTERNS

        self._scan_patterns(
            original=original,
            normalized=normalized,
            patterns=patterns,
            pattern_type=KeyboardPatternType.VERTICAL,
            result=result
        )

    def _scan_diagonal(self, original: str, normalized: str, result: KeyboardAnalysis) -> None:
        """
        Scan the password for diagonal keyboard patterns.
        :param original:
        :param normalized:
        :param result:
        :return:
        """
        if not self.config.check_diagonal:
            return

        patterns = self._DIAGONAL_PATTERNS

        self._scan_patterns(
            original=original,
            normalized=normalized,
            patterns=patterns,
            pattern_type=KeyboardPatternType.DIAGONAL,
            result=result
        )

    def _scan_number_row(self, original: str, normalized: str, result: KeyboardAnalysis) -> None:
        """
        Scan the password for number row keyboard patterns.
        :param original:
        :param normalized:
        :param result:
        :return:
        """
        if not self.config.check_number_row:
            return

        self._scan_patterns(
            original=original,
            normalized=normalized,
            patterns=("1234567890",),
            pattern_type=KeyboardPatternType.NUMBER_ROW,
            result=result
        )

    def _scan_patterns(self, original: str, normalized: str, patterns: tuple[str, ...],
                       pattern_type: KeyboardPatternType, result: KeyboardAnalysis) -> None:
        """
        Scan the password for keyboard patterns.
        :param original:
        :param normalized:
        :param patterns:
        :param pattern_type:
        :param result:
        :return:
        """
        minimum = max(self.config.min_pattern_length, 2)

        for pattern in patterns:
            candidates = [pattern, pattern[::-1]]  # Check both forward and reverse patterns

            for candidate in candidates:
                if len(candidate) < minimum:
                    continue

                start = 0

                while True:
                    index = normalized.find(candidate, start)
                    if index == -1:
                        break

                    end = index + len(candidate)
                    self._add_pattern(
                        original=original,
                        normalized=normalized,
                        value=candidate,
                        pattern_type=pattern_type,
                        start=index,
                        end=end,
                        reversed_pattern=(candidate != pattern),
                        result=result,
                    )
                    start = index + 1

    def _add_pattern(self, original: str, normalized: str, value: str, pattern_type: KeyboardPatternType,
                     start: int, end: int, reversed_pattern: bool, result: KeyboardAnalysis) -> None:
        """
        Add a detected keyboard pattern to the analysis result.
        :param original:
        :param normalized:
        :param value:
        :param pattern_type:
        :param start:
        :param end:
        :param reversed_pattern:
        :param result:
        :return:
        """
        original_value = original[start:end]
        severity = self._calculate_severity(len(value))

        pattern = KeyboardPattern(
            value=original_value,
            normalized_value=value,
            pattern_type=pattern_type,
            start_position=start,
            end_position=end,
            length=len(value),
            reversed_pattern=reversed_pattern,
            severity=severity,
            message=f"Keyboard pattern detected: {original_value} ({pattern_type.value})"
        )

        # Avoid duplicate results caused by overlapping keyboard definitions
        if self._is_duplicate(pattern, result.patterns):
            return

        result.patterns.append(pattern)

        if pattern_type == KeyboardPatternType.HORIZONTAL:
            result.horizontal_detected = True
        elif pattern_type == KeyboardPatternType.VERTICAL:
            result.vertical_detected = True
        elif pattern_type == KeyboardPatternType.DIAGONAL:
            result.diagonal_detected = True
        elif pattern_type == KeyboardPatternType.NUMBER_ROW:
            result.number_row_detected = True

    @staticmethod
    def _is_duplicate(new_pattern: KeyboardPattern, existing_patterns: list[KeyboardPattern]) -> bool:
        """
        Prevent duplicate patterns from being added to the result.
        :param new_pattern:
        :param existing_patterns:
        :return:
        """
        return any(
            item.start_position == new_pattern.start_position and
            item.end_position == new_pattern.end_position and
            item.pattern_type == new_pattern.pattern_type
            for item in existing_patterns
        )

    def _calculate_severity(self, length: int) -> float:
        """
        Calculate the severity of a detected keyboard pattern based on its length.
        :param length:
        :return:
        """
        minimum = max(self.config.min_pattern_length, 2)

        severity = (length - minimum + 1) / max(minimum, 1)

        return min(1.0, max(0.0, severity))

    @staticmethod
    def _finalize(self, result: KeyboardAnalysis) -> None:
        """
        Calculate aggregate severity and finalize the analysis result.
        :param result:
        :return:
        """
        result.detected = bool(result.patterns)

        if not result.detected:
            result.severity = 0.0
            result.penalty_factor = 0.0
            result.message = "No keyboard patterns detected."
            return

        result.severity = min(1.0, max(pattern.severity for pattern in result.patterns))

        result.penalty_factor = result.severity

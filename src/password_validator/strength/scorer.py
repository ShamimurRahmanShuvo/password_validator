"""
Password strength scoring engine.
The scorer consumes:
    StrengthAnalyzer
    StrengthWeights
    SuggestionGenerator
and returns a rich StrengthResult.

Responsibilities:
    - Run all strength analyzers
    - Calculate positive password characteristics
    - Calculate analyzer penalties
    - Calculate final score
    - Determine strength level
    - Generate user-friendly suggestions

The scorer does NOT contain pattern-detection logic.
That responsibility belongs to the individual analyzers.
"""
from __future__ import annotations
from dataclasses import dataclass, field
import math
import string

from ..enums import StrengthLevel
from ..utils import EntropyCalculator
from .analyzer import StrengthAnalysis, StrengthAnalyzer
from .suggestions import PasswordSuggestion, SuggestionGenerator
from .weights import StrengthWeights, default_strength_weights


@dataclass(slots=True, frozen=True)
class StrengthPenalty:
    """
    Represents one scoring penalty
    """
    code: str
    amount: float
    reason: str
    severity: float


@dataclass(slots=True, frozen=True)
class StrengthBonus:
    """
    Represents one positive scoring factor
    """
    code: str
    amount: float
    reason: str


@dataclass(slots=True, frozen=True)
class PasswordMetrics:
    """
    Password composition metrics.
    No password value is stored here.
    """
    length: int
    has_lowercase: bool
    has_uppercase: bool
    has_digit: bool
    has_special: bool
    unique_character_count: int
    character_diversity: float
    estimated_entropy: float
    character_classes: int


@dataclass(slots=True)
class StrengthResult:
    """
    Rich password strength evaluation result
    """
    score: float
    level: StrengthLevel
    metrics: PasswordMetrics
    analysis: StrengthAnalysis
    bonuses: list[StrengthBonus] = field(default_factory=list)
    penalties: list[StrengthPenalty] = field(default_factory=list)
    suggestions: list[PasswordSuggestion] = field(default_factory=list)

    @property
    def is_strong(self):
        """
        :return: True when password is strong or better
        """
        return self.level in {
            StrengthLevel.STRONG,
            StrengthLevel.VERY_STRONG
        }

    @property
    def is_weak(self):
        """
        :return: True when password is weak or very weak
        """
        return self.level in {
            StrengthLevel.VERY_WEAK,
            StrengthLevel.WEAK
        }

    @property
    def suggestion_message(self) -> list[str]:
        """
        :return: User facing suggestion message
        """
        return [
            suggestion.message for suggestion in self.suggestions
        ]

    @property
    def total_bonus(self) -> float:
        """
        :return: Total positive scoring contribution
        """
        return sum(
            bonus.amount for bonus in self.bonuses
        )

    @property
    def total_penalty(self) -> float:
        """
        :return: Total penalty
        """
        return sum(
            penalty.amount for penalty in self.penalties
        )


class PasswordStrengthScorer:
    """
    Calculates password strength using all configured analyzers
    Example:
        scorer = PasswordStrengthScorer()
        result = scorer.score("MyStrongPassword123")
        print(result.score)
        print(result.level)
        print(result.suggestion_messages)
    """
    MIN_SCORE = 0.0
    MAX_SCORE = 100.0

    def __init__(self, analyzer: StrengthAnalyzer | None = None,
                 weights: StrengthWeights | None = None,
                 suggestion_generator: SuggestionGenerator | None = None):

        self.analyzer = analyzer or StrengthAnalyzer()
        self.weights = weights or default_strength_weights()
        self.suggestion_generator = suggestion_generator or SuggestionGenerator()

    def score(self, password: str) -> StrengthResult:
        """
        Score the password strength based on various criteria.

        :param password: The password to score.
        :return: StrengthResult
        """

        if password is None:
            password = ""

        metrics = self._calculate_metrics(password)
        analysis = self.analyzer.analyze(password)
        bonuses = self._calculate_bonuses(password, metrics)
        penalties = self._calculate_penalties(analysis)

        raw_score = (
            self.MAX_SCORE * self._base_score(password, metrics)
        )

        raw_score += sum(bonus.amount for bonus in bonuses)
        raw_score -= sum(penalty.amount for penalty in penalties)

        final_score = self._clamp(
            raw_score, self.MIN_SCORE, self.MAX_SCORE
        )

        level = self._get_level(final_score)
        suggestions = self.suggestion_generator.generate(password, analysis)

        return StrengthResult(
            score=round(final_score, 2),
            level=level,
            metrics=metrics,
            analysis=analysis,
            bonuses=bonuses,
            penalties=penalties,
            suggestions=suggestions.suggestions
        )

    def _calculate_metrics(self, password: str) -> PasswordMetrics:
        """
        Calculate password composition metrics
        :param password:
        :return:
        """
        length = len(password)

        has_lowercase = any(
            character.islower() for character in password
        )

        has_uppercase = any(
            character.isupper() for character in password
        )

        has_digit = any(
            character.isdigit() for character in password
        )

        has_special = any(
            character.isalnum() for character in password
        )

        unique_character_count = len(set(password))

        if length:
            character_diversity = (
                unique_character_count / length
            )
        else:
            character_diversity = 0.0

        character_classes = sum(
            (
                has_lowercase, has_uppercase, has_digit, has_special
            )
        )

        estimated_entropy = (
            self._estimate_entropy(password)
        )

        return PasswordMetrics(
            length=length,
            has_lowercase=has_lowercase,
            has_uppercase=has_uppercase,
            has_digit=has_digit,
            has_special=has_special,
            unique_character_count=unique_character_count,
            character_diversity=character_diversity,
            estimated_entropy=estimated_entropy,
            character_classes=character_classes
        )

    def _estimate_entropy(self, password: str) -> float:
        """
        Estimate password entropy in bits based on the size of the character pool rather than a true entropy calculation
        :param password:
        :return:
        """
        if not password:
            return 0.0

        pool_size = 0

        if any(character.islower() for character in password):
            pool_size += 26

        if any(character.isupper() for character in password):
            pool_size += 26

        if any(character.isdigit() for character in password):
            pool_size += 10

        if any(character in string.punctuation for character in password):
            pool_size += len(string.punctuation)

        if pool_size <= 0:
            return 0.0

        return (
            len(password) * math.log2(pool_size)
        )

    def _base_score(self, password: str, metrics: PasswordMetrics) -> float:
        """
        Calculate the base score between 0 and 1
        Base scoring considers:
            - password length
            - character classes
            - character diversity
            - entropy
        :param password:
        :param metrics:
        :return:
        """
        if not password:
            return 0.0

        length_component = min(metrics.length / 16.0, 1)
        class_component = metrics.character_classes / 4.0
        diversity_component = metrics.character_diversity
        entropy_component = min(metrics.estimated_entropy / 80.0, 1.0)
        base = (
            length_component * 0.30 + class_component * 0.25 + diversity_component * 0.15 + entropy_component * 0.30
        )

        return min(1.0, max(0.0, base))

    def _calculate_bonuses(self, password: str, metrics: PasswordMetrics) -> list[StrengthBonus]:
        """
        Calculate positive scoring contributions.
        Bonus amount are expressed directly in score points
        :param password:
        :param metrics:
        :return:
        """
        bonuses: list[StrengthBonus] = []

        if metrics.length >= 12:
            bonuses.append(
                StrengthBonus(
                    code="length_12_plus",
                    amount=self._weight("length_12_plus", 5.0),
                    reason="Password is at least 12 characters long"
                )
            )

        if metrics.length >= 16:
            bonuses.append(
                StrengthBonus(
                    code="length_16_plus",
                    amount=self._weight("length_16_plus", 5.0),
                    reason="Password is at least 16 characters long"
                )
            )

        if metrics.character_diversity >= 3:
            bonuses.append(
                StrengthBonus(
                    code="character_diversity",
                    amount=self._weight("character_diversity", 5.0),
                    reason="Password uses multiple character classes"
                )
            )

        if metrics.character_classes == 4:
            bonuses.append(
                StrengthBonus(
                    code="all_character_classes",
                    amount=self._weight("all_character_classes", 5.0),
                    reason="Password contains uppercase, lowercase, digits, and special characters"
                )
            )

        if metrics.estimated_entropy >= 60:
            bonuses.append(
                StrengthBonus(
                    code="high_entropy",
                    amount=self._weight("high_entropy", 5.0),
                    reason="Password has a relatively large estimated search space"
                )
            )

        return bonuses

    def _calculate_penalties(self, analysis: StrengthAnalysis) -> list[StrengthPenalty]:
        """
        Convert analyzer results into score penalties
        :param analysis:
        :return:
        """
        penalties: list[StrengthPenalty] = []

        if analysis.repeat.detected:
            amount = self._weighted_penalty("repeated_character", analysis.repeat.penalty_factor)
            penalties.append(
                StrengthPenalty(
                    code="repeated_pattern",
                    amount=amount,
                    severity=analysis.repeat.severity,
                    reason= "Password contains repeated characters or groups"
                )
            )

        if analysis.sequential.detected:
            amount = self._weighted_penalty("sequential_pattern", analysis.sequential.penalty_factor)
            penalties.append(
                StrengthPenalty(
                    code="sequential_pattern",
                    amount=amount,
                    severity=analysis.sequential.severity,
                    reason="Password contains predictable sequential pattern"
                )
            )

        if analysis.keyboard.detected:
            amount = self._weighted_penalty("keyboard_pattern", analysis.keyboard.penalty_factor)
            penalties.append(
                StrengthPenalty(
                    code="keyboard_pattern",
                    amount=amount,
                    severity=analysis.keyboard.severity,
                    reason="Password contains predictable keyboard pattern"
                )
            )

        if analysis.dictionary.detected:
            amount = self._weighted_penalty("dictionary_word", analysis.dictionary.penalty_factor)
            penalties.append(
                StrengthPenalty(
                    code="dictionary_word",
                    amount=amount,
                    severity=analysis.dictionary.severity,
                    reason="Password contains a common dictionary word"
                )
            )

        return penalties

    def _weighted_penalty(self, weight_name: str, severity: float) -> float:
        """
        Convert analyzer severity into weighted penalty
        :param weight_name:
        :param severity:
        :return:
        """
        weight = self._weight(weight_name, 10.0)
        return max(0.0, weight * severity)

    def _weight(self, name: str, default: float) -> float:
        """
        Safely retrieve a configured weight
        :param name:
        :param default:
        :return:
        """
        if hasattr(self.weights, name):
            value = getattr(self.weights, name)
            if value is not None:
                return float(value)

        if isinstance(self.weights, dict):
            value = self.weights.get(name)
            if value is not None:
                return float(value)

        return default

    @staticmethod
    def _get_level(score: float) -> StrengthLevel:
        """
        Convert numeric score into a strength level
        :param score:
        :return:
        """
        if score < 20:
            return StrengthLevel.VERY_WEAK

        if score < 40:
            return StrengthLevel.WEAK

        if score < 60:
            return StrengthLevel.FAIR

        if score < 80:
            return StrengthLevel.STRONG

        return StrengthLevel.VERY_STRONG

    @staticmethod
    def _clamp(value: float, minimum: float, maximum: float) -> float:
        """
        Clamp a numeric value
        :param value:
        :param minimum:
        :param maximum:
        :return:
        """
        return max(minimum, min(maximum, value))

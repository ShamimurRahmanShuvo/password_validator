"""
Unit tests for the scorer module.
"""
from __future__ import annotations

import math
from dataclasses import FrozenInstanceError, replace
from types import SimpleNamespace

import pytest
import math
import string

from password_validator.strength.analyzer import StrengthAnalysis
from password_validator.strength.config import StrengthConfig
from password_validator.strength.scorer import (
    PasswordMetrics, PasswordStrengthScorer, StrengthBonus, StrengthPenalty, StrengthResult
)
from password_validator.strength.suggestions import PasswordSuggestion, SuggestionResult
from password_validator.strength.analyzers.keyboard import KeyboardAnalysis
from password_validator.strength.analyzers.dictionary import DictionaryAnalysis
from password_validator.strength.analyzers.repeat import RepeatAnalysis
from password_validator.strength.analyzers.sequential import SequentialAnalysis
from password_validator.enums import StrengthLevel


# Helpers
def empty_analysis() -> StrengthAnalysis:
    """
    Create an empty StrengthAnalysis instance for testing.
    """
    return StrengthAnalysis(
        dictionary=DictionaryAnalysis(),
        keyboard=KeyboardAnalysis(),
        repeat=RepeatAnalysis(),
        sequential=SequentialAnalysis()
    )


def analysis_with(*, dictionary=None, keyboard=None, repeat=None, sequential=None) -> StrengthAnalysis:
    """
    Create a StrengthAnalysis instance with specified components for testing.
    """
    return StrengthAnalysis(
        dictionary=dictionary or DictionaryAnalysis(),
        keyboard=keyboard or KeyboardAnalysis(),
        repeat=repeat or RepeatAnalysis(),
        sequential=sequential or SequentialAnalysis()
    )


class FakeAnalyzer:
    def __init__(self, analysis: StrengthAnalysis):
        self.analysis = analysis
        self.passwords: list[str] = []

    def analyze(self, password: str) -> StrengthAnalysis:
        self.passwords.append(password)
        return self.analysis


class FakeSuggestionGenerator:
    def __init__(self, suggestions=None):
        self.suggestions = suggestions or []
        self.calls: list[tuple[str, StrengthAnalysis]] = []

    def generate(self, password: str, analysis: StrengthAnalysis) -> SuggestionResult:
        self.calls.append((password, analysis))
        return SuggestionResult(suggestions=self.suggestions)


# Data models
class TestStrengthPenalty:
    def test_create_penalty(self):
        penalty = StrengthPenalty(code="dictionary_word", amount=10.0,
                                  reason="Contains a dictionary word", severity=0.8)
        assert penalty.code == "dictionary_word"
        assert penalty.amount == 10.0
        assert penalty.reason == "Contains a dictionary word"
        assert penalty.severity == 0.8

    def test_is_frozen(self):
        penalty = StrengthPenalty(code="test", amount=1.0, reason="test", severity=0.5)
        with pytest.raises(FrozenInstanceError):
            penalty.amount = 2.0


class TestStrengthBonus:
    def test_creates_bonus(self):
        bonus = StrengthBonus(code="length_bonus", amount=5.0, reason="Password is long enough")
        assert bonus.code == "length_bonus"
        assert bonus.amount == 5.0
        assert bonus.reason == "Password is long enough"

    def test_is_frozen(self):
        bonus = StrengthBonus(code="test", amount=1.0, reason="test")
        with pytest.raises(FrozenInstanceError):
            bonus.amount = 2.0


class TestPasswordMetrics:
    def test_create_metrics(self):
        metrics = PasswordMetrics(length=12, unique_character_count=10, has_uppercase=True,
                                  has_lowercase=True, has_digit=True, has_special=True,
                                  character_diversity=10/12, estimated_entropy=70.0, character_classes=4)
        assert metrics.length == 12
        assert metrics.has_lowercase is True
        assert metrics.has_uppercase is True
        assert metrics.has_digit is True
        assert metrics.has_special is True
        assert metrics.unique_character_count == 10
        assert metrics.character_diversity == pytest.approx(10 / 12)
        assert metrics.estimated_entropy == 70.0
        assert metrics.character_classes == 4


class TestStrengthResult:
    def make_result(self, **kwargs):
        defaults = {
            "score": 75.0,
            "level": StrengthLevel.STRONG,
            "metrics": PasswordMetrics(length=12, has_lowercase=True, has_uppercase=True, has_digit=True,
                                       has_special=True, unique_character_count=10, character_diversity=0.83,
                                       estimated_entropy=70.0, character_classes=4, ),
            "analysis": empty_analysis()
        }
        defaults.update(kwargs)
        return StrengthResult(**defaults)

    def test_password_strength_level(self):
        result = self.make_result(level=StrengthLevel.WEAK)
        assert result.is_weak is True
        assert result.is_strong is False
        result1 = self.make_result(level=StrengthLevel.STRONG)
        assert result1.is_weak is False
        assert result1.is_strong is True

    def test_suggestion_message_returns_expected(self):
        suggestions = [PasswordSuggestion(code="one", message="First suggestion", priority=100, ),
                       PasswordSuggestion(code="two", message="Second suggestion", priority=50, )]
        result = self.make_result(suggestions=suggestions)
        assert result.suggestion_message == ["First suggestion", "Second suggestion"]

    def test_total_bonus(self):
        bonuses = [StrengthBonus(code="bonus1", amount=5.0, reason="Bonus 1"),
                   StrengthBonus(code="bonus2", amount=3.0, reason="Bonus 2")]
        result = self.make_result(bonuses=bonuses)
        assert result.total_bonus == 8.0

    def test_total_penalty(self):
        penalties = [StrengthPenalty(code="penalty1", amount=2.0, reason="Penalty 1", severity=0.5),
                     StrengthPenalty(code="penalty2", amount=4.0, reason="Penalty 2", severity=0.8)]
        result = self.make_result(penalties=penalties)
        assert result.total_penalty == 6.0

    def test_empty_bonus_and_penalty_totals(self):
        result = self.make_result()
        assert result.total_bonus == 0.0
        assert result.total_penalty == 0.0


# Scorer initialization tests
class TestPasswordStrengthScorerInitialization:
    def test_initialization_with_default_analyzers(self):
        scorer = PasswordStrengthScorer()

        assert scorer.config is not None
        assert scorer.analyzer is not None
        assert scorer.suggestion_generator is not None
        assert scorer.weights is not None

    def test_custom_analyzers_are_used(self):
        config = StrengthConfig()
        analyzer = FakeAnalyzer(empty_analysis())
        suggestions = FakeSuggestionGenerator()

        scorer = PasswordStrengthScorer(config=config, analyzer=analyzer, suggestion_generator=suggestions)

        assert scorer.config is config
        assert scorer.analyzer is analyzer
        assert scorer.suggestion_generator is suggestions
        assert scorer.weights is config.weights


# Metrics
class TestCalculateMetrics:
    @pytest.fixture
    def scorer(self):
        return PasswordStrengthScorer()

    def test_empty_password(self, scorer):
        metrics = scorer._calculate_metrics("")

        assert metrics.length == 0
        assert metrics.has_lowercase is False
        assert metrics.has_uppercase is False
        assert metrics.has_digit is False
        assert metrics.has_special is False
        assert metrics.unique_character_count == 0
        assert metrics.character_diversity == 0.0
        assert metrics.estimated_entropy == 0.0
        assert metrics.character_classes == 0

    def test_password_with_various_characters(self, scorer):
        password = "Abc123!@#"
        metrics = scorer._calculate_metrics(password)

        assert metrics.length == 9
        assert metrics.has_lowercase is True
        assert metrics.has_uppercase is True
        assert metrics.has_digit is True
        assert metrics.has_special is True
        assert metrics.unique_character_count == 9
        assert metrics.character_diversity == pytest.approx(1.0)
        assert metrics.character_classes == 4
        assert metrics.estimated_entropy > 0.0  # Entropy should be greater than 0 for a non-empty password


# Entropy
class TestEstimateEntropy:
    @pytest.fixture
    def scorer(self):
        return PasswordStrengthScorer()

    def test_entropy_for_empty_password(self, scorer):
        entropy = scorer._estimate_entropy("")
        assert entropy == 0.0

    def test_entropy_for_simple_password(self, scorer):
        password = "abc"
        entropy = scorer._estimate_entropy(password)
        assert entropy > 0.0

    def test_entropy_for_complex_password(self, scorer):
        password = "Abc123!@#"
        entropy = scorer._estimate_entropy(password)
        assert entropy > 0.0
        assert entropy == pytest.approx(len(password) * math.log2(62 + len(string.punctuation)))


# Base Score
class TestBaseScore:
    @pytest.fixture
    def scorer(self):
        return PasswordStrengthScorer()

    def test_base_score_for_empty_password(self, scorer):
        metrics = scorer._calculate_metrics("")
        score = scorer._base_score("", metrics)
        assert score == 0.0

    def test_base_score_for_simple_password(self, scorer):
        password = "abc"
        metrics = scorer._calculate_metrics(password)
        score = scorer._base_score(password, metrics)
        assert score > 0.0

    def test_base_score_for_complex_password(self, scorer):
        password = "Abc123!@#"
        metrics = scorer._calculate_metrics(password)
        score = scorer._base_score(password, metrics)
        assert 0.0 < score < 1.0

    def test_base_score_increases_with_stronger_composition(self, scorer):
        password1 = "abc"
        metrics1 = scorer._calculate_metrics(password1)
        score1 = scorer._base_score(password1, metrics1)

        password2 = "Abc123!@#"
        metrics2 = scorer._calculate_metrics(password2)
        score2 = scorer._base_score(password2, metrics2)

        assert score2 > score1


# Bonuses
class TestCalculateBonuses:
    @pytest.fixture
    def scorer(self):
        return PasswordStrengthScorer()

    def test_bonuses_for_empty_password(self, scorer):
        metrics = scorer._calculate_metrics("")
        bonuses = scorer._calculate_bonuses("", metrics)
        assert bonuses == []

    def test_bonuses_for_simple_password(self, scorer):
        password = "abc"
        metrics = scorer._calculate_metrics(password)
        bonuses = scorer._calculate_bonuses(password, metrics)
        assert isinstance(bonuses, list)

    def test_bonuses_for_complex_password(self, scorer):
        password = "Abc123!@#"
        metrics = scorer._calculate_metrics(password)
        bonuses = scorer._calculate_bonuses(password, metrics)
        assert isinstance(bonuses, list)

    def test_high_entropy_bonus(self, scorer):
        password = "Abcdef123456!@#$"
        metrics = scorer._calculate_metrics(password)
        bonuses = scorer._calculate_bonuses(password, metrics)

        assert any(bonus.code == "high_entropy" for bonus in bonuses)

    def test_bonus_codes_for_different_passwords(self, scorer):
        # No bonus
        password1 = ""
        metrics1 = scorer._calculate_metrics(password1)
        bonuses1 = scorer._calculate_bonuses(password1, metrics1)
        assert bonuses1 == []

        # Length bonus
        password2 = "Abcdef123456!@#$"
        metrics2 = scorer._calculate_metrics(password2)
        bonuses2 = scorer._calculate_bonuses(password2, metrics2)
        codes = {bonus.code for bonus in bonuses2}
        assert "length_12_plus" in codes
        assert "length_16_plus" in codes
        assert "high_entropy" in codes
        assert "all_character_classes" in codes

    def test_bonus_amount_uses_configured_weight(self, scorer):
        config = StrengthConfig()
        config_weights = replace(config.weights, length_12_plus=9.0)
        config = replace(config, weights=config_weights)
        scorer = PasswordStrengthScorer(config=config)
        password = "abcdefghijkL"
        metrics = scorer._calculate_metrics(password)
        bonuses = scorer._calculate_bonuses(password, metrics)
        bonus = next(bonus for bonus in bonuses if bonus.code == "length_12_plus")
        assert bonus.amount == 9.0


# Penalties
class TestCalculatePenalties:
    @pytest.fixture
    def scorer(self):
        return PasswordStrengthScorer()

    def test_penalties_for_empty_password(self, scorer):
        penalties = scorer._calculate_penalties(empty_analysis())
        assert penalties == []

    def test_penalties_for_different_analyzers(self, scorer):
        # Repeat
        repeat = RepeatAnalysis(detected=True, severity=0.8, penalty_factor=0.8)
        analysis = analysis_with(repeat=repeat)
        penalties = scorer._calculate_penalties(analysis)
        assert len(penalties) == 1
        assert penalties[0].code == "repeated_pattern"
        assert penalties[0].amount == pytest.approx(12)
        assert penalties[0].severity == pytest.approx(0.8)

        # Sequence
        sequence = SequentialAnalysis(detected=True, severity=0.5, penalty_factor=0.5)
        analysis = analysis_with(sequential=sequence)
        penalties = scorer._calculate_penalties(analysis)
        assert len(penalties) == 1
        assert penalties[0].code == "sequential_pattern"
        assert penalties[0].amount == pytest.approx(7.5)
        assert penalties[0].severity == pytest.approx(0.5)

        # Dictionary
        dictionary = DictionaryAnalysis(detected=True, severity=0.9, penalty_factor=0.9)
        analysis = analysis_with(dictionary=dictionary)
        penalties = scorer._calculate_penalties(analysis)
        assert len(penalties) == 1
        assert penalties[0].code == "dictionary_word"
        assert penalties[0].amount == pytest.approx(9.0)
        assert penalties[0].severity == pytest.approx(0.9)

        # Keyboard
        keyboard = KeyboardAnalysis(detected=True, severity=0.7, penalty_factor=0.7)
        analysis = analysis_with(keyboard=keyboard)
        penalties = scorer._calculate_penalties(analysis)
        assert len(penalties) == 1
        assert penalties[0].code == "keyboard_pattern"
        assert penalties[0].amount == pytest.approx(10.5)
        assert penalties[0].severity == pytest.approx(0.7)

        # All penalties
        analysis = analysis_with(
            repeat=repeat,
            sequential=sequence,
            dictionary=dictionary,
            keyboard=keyboard
        )
        penalties = scorer._calculate_penalties(analysis)
        assert len(penalties) == 4
        assert {penalty.code for penalty in penalties} == {
            "repeated_pattern",
            "sequential_pattern",
            "dictionary_word",
            "keyboard_pattern"
        }


# Weighted Penalty
class TestWeightedPenalty:
    def test_weighted_penalty(self):
        scorer = PasswordStrengthScorer()
        assert scorer._weighted_penalty("dictionary_word", 0.5) == 5.0

    def test_weighted_penalty_with_custom_weight(self):
        config = StrengthConfig()
        config = replace(config, weights=replace(config.weights, dictionary_pattern=20.0))
        scorer = PasswordStrengthScorer(config=config)
        assert scorer._weighted_penalty("dictionary_pattern", 0.5) == pytest.approx(10.0)
        # Zero Severity
        scorer = PasswordStrengthScorer()
        assert scorer._weighted_penalty("dictionary_pattern", 0.0) == 0.0
        # -ve Severity
        scorer = PasswordStrengthScorer()
        assert scorer._weighted_penalty("dictionary_pattern", -0.5) == 0.0


# Weights
class TestWeight:
    def test_reads_dataclass_weight(self):
        scorer = PasswordStrengthScorer()
        assert scorer._weight("length_12_plus", 99.0) == scorer.weights.length_12_plus

    def test_missing_attribute_uses_default(self):
        scorer = PasswordStrengthScorer()
        assert scorer._weight("non_existent_weight", 99.0) == 99.0

    def test_weight_with_custom_weight(self):
        config = StrengthConfig()
        config = replace(config, weights=replace(config.weights, length_12_plus=20.0))
        scorer = PasswordStrengthScorer(config=config)
        assert scorer._weight("length_12_plus", 99.0) == 20.0

    def test_dictionary_weights_are_supported(self):
        scorer = PasswordStrengthScorer.__new__(PasswordStrengthScorer)
        scorer.weights = {"test_weight": 12.5}
        assert scorer._weight("test_weight", 1.0) == 12.5

    def test_dictionary_missing_or_none_weights_use_defaults(self):
        scorer = PasswordStrengthScorer.__new__(PasswordStrengthScorer)
        scorer.weights = {}
        assert scorer._weight("test_weight", 12.5) == 12.5
        scorer.weights = {"test_weight": None}
        assert scorer._weight("test_weight", 12.5) == 12.5


# Levels
class TestGetLevel:
    @pytest.mark.parametrize(
        ("score", "expected"),
        [
            (0, StrengthLevel.VERY_WEAK), (19.99, StrengthLevel.VERY_WEAK), (20, StrengthLevel.WEAK),
            (39.99, StrengthLevel.WEAK), (40, StrengthLevel.FAIR), (59.99, StrengthLevel.FAIR),
            (60, StrengthLevel.STRONG), (79.99, StrengthLevel.STRONG), (80, StrengthLevel.VERY_STRONG),
            (100, StrengthLevel.VERY_STRONG)
        ]
    )
    def test_score_boundaries(self, score, expected):
        assert PasswordStrengthScorer._get_level(score) == expected


# Clamp
class TestClamp:
    @pytest.mark.parametrize(
        ("value", "minimum", "maximum", "expected"),
        [
            (-10, 0, 100, 0), (0, 0, 100, 0), (50, 0, 100, 50), (100, 0, 100, 100), (150, 0, 100, 100)
        ]
    )
    def test_clamp(self, value, minimum, maximum, expected):
        assert PasswordStrengthScorer._clamp(value, minimum, maximum) == expected


# Score
class TestScore:
    def test_none_and_empty_password(self):

        analyzer = FakeAnalyzer(empty_analysis())
        suggestions = FakeSuggestionGenerator()
        scorer = PasswordStrengthScorer(analyzer=analyzer, suggestion_generator=suggestions)
        # None Password
        result = scorer.score(None)
        assert isinstance(result, StrengthResult)
        assert result.metrics.length == 0
        assert result.score == 0.0
        assert result.level == StrengthLevel.VERY_WEAK
        # Empty Password
        result = scorer.score("")
        assert isinstance(result, StrengthResult)
        assert result.metrics.length == 0
        assert result.score == 0.0
        assert result.level == StrengthLevel.VERY_WEAK

    def test_score_returns_complete_result(self):
        analysis = empty_analysis()
        analyzer = FakeAnalyzer(analysis)
        suggestion = PasswordSuggestion(code="test", message="Improve password", priority=50)
        generator = FakeSuggestionGenerator([suggestion])
        scorer = PasswordStrengthScorer(analyzer=analyzer, suggestion_generator=generator)
        result = scorer.score("Abc123!xyz")
        assert isinstance(result, StrengthResult)
        assert result.analysis is analysis
        assert result.metrics.length == 10
        assert result.suggestions == [suggestion]
        assert analyzer.passwords == ["Abc123!xyz"]
        assert generator.calls[0] == ("Abc123!xyz", analysis)

    def test_score_contains_bonuses(self):
        scorer = PasswordStrengthScorer(analyzer=FakeAnalyzer(empty_analysis()),
                                        suggestion_generator=FakeSuggestionGenerator())
        result = scorer.score("Abcdefghijk1")
        assert any(bonus.code == "length_12_plus" for bonus in result.bonuses)

    def test_score_contains_penalties_for_detected(self):
        analysis = StrengthAnalysis(dictionary=DictionaryAnalysis(detected=True, severity=1.0, penalty_factor=1.0, ),
                                    repeat=RepeatAnalysis(), sequential=SequentialAnalysis(),
                                    keyboard=KeyboardAnalysis())
        scorer = PasswordStrengthScorer(analyzer=FakeAnalyzer(analysis),
                                        suggestion_generator=FakeSuggestionGenerator())
        result = scorer.score("password")
        assert len(result.penalties) == 1
        assert result.penalties[0].code == "dictionary_word"
        assert result.total_penalty > 0

    def test_score_is_rounded_to_two_decimal_places(self):
        scorer = PasswordStrengthScorer(
            analyzer=FakeAnalyzer(empty_analysis()),
            suggestion_generator=FakeSuggestionGenerator())
        result = scorer.score("Abc123!")
        assert result.score == round(result.score, 2)

    def test_final_score_is_clamped_to_100(self):
        scorer = PasswordStrengthScorer(
            analyzer=FakeAnalyzer(empty_analysis()), suggestion_generator=FakeSuggestionGenerator())

        result = scorer.score("Abcdefghijklmnop123456789!@#$")
        assert 0.0 <= result.score <= 100.0

    def test_final_score_is_clamped_to_zero(self):
        analysis = StrengthAnalysis(
            dictionary=DictionaryAnalysis(detected=True, severity=1.0, penalty_factor=1.0, ),
            repeat=RepeatAnalysis(detected=True, severity=1.0, penalty_factor=1.0, ),
            sequential=SequentialAnalysis(detected=True, severity=1.0, penalty_factor=1.0, ),
            keyboard=KeyboardAnalysis(detected=True, severity=1.0, penalty_factor=1.0, ))

        scorer = PasswordStrengthScorer(analyzer=FakeAnalyzer(analysis), suggestion_generator=FakeSuggestionGenerator())
        result = scorer.score("password123")
        assert result.score >= 0.0
        assert result.score <= 100.0




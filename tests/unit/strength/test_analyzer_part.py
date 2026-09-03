import pytest

from password_validator.strength.analyzer import (
    StrengthAnalysis,
    StrengthAnalyzer,
)
from password_validator.strength.config import StrengthConfig
from password_validator.strength.analyzers import (
    DictionaryAnalysis,
    DictionaryAnalyzer,
    DictionaryMatch,
    DictionaryMatchType,
    KeyboardAnalysis,
    KeyboardAnalyzer,
    KeyboardPattern,
    KeyboardPatternType,
    RepeatAnalysis,
    RepeatAnalyzer,
    SequentialAnalysis,
    SequentialAnalyzer,
)


@pytest.fixture
def config():
    return StrengthConfig.defaults()


@pytest.fixture
def analyzer(config):
    return StrengthAnalyzer(config=config)


@pytest.fixture
def empty_dictionary_analysis():
    return DictionaryAnalysis()


@pytest.fixture
def empty_repeat_analysis():
    return RepeatAnalysis()


@pytest.fixture
def empty_sequential_analysis():
    return SequentialAnalysis()


@pytest.fixture
def empty_keyboard_analysis():
    return KeyboardAnalysis()


class TestStrengthAnalysis:
    """Tests for the aggregated StrengthAnalysis result."""

    def test_has_patterns_false_when_no_patterns(
        self,
        empty_dictionary_analysis,
        empty_repeat_analysis,
        empty_sequential_analysis,
        empty_keyboard_analysis,
    ):
        result = StrengthAnalysis(
            dictionary=empty_dictionary_analysis,
            repeat=empty_repeat_analysis,
            sequential=empty_sequential_analysis,
            keyboard=empty_keyboard_analysis,
        )

        assert result.has_patterns is False

    def test_has_patterns_true_when_dictionary_detected(
        self,
        empty_dictionary_analysis,
        empty_repeat_analysis,
        empty_sequential_analysis,
        empty_keyboard_analysis,
    ):
        dictionary = DictionaryAnalysis(detected=True)

        result = StrengthAnalysis(
            dictionary=dictionary,
            repeat=empty_repeat_analysis,
            sequential=empty_sequential_analysis,
            keyboard=empty_keyboard_analysis,
        )

        assert result.has_patterns is True

    def test_has_patterns_true_when_repeat_detected(
        self,
        empty_dictionary_analysis,
        empty_sequential_analysis,
        empty_keyboard_analysis,
    ):
        repeat = RepeatAnalysis(detected=True)

        result = StrengthAnalysis(
            dictionary=empty_dictionary_analysis,
            repeat=repeat,
            sequential=empty_sequential_analysis,
            keyboard=empty_keyboard_analysis,
        )

        assert result.has_patterns is True

    def test_has_patterns_true_when_sequential_detected(
        self,
        empty_dictionary_analysis,
        empty_repeat_analysis,
        empty_keyboard_analysis,
    ):
        sequential = SequentialAnalysis(detected=True)

        result = StrengthAnalysis(
            dictionary=empty_dictionary_analysis,
            repeat=empty_repeat_analysis,
            sequential=sequential,
            keyboard=empty_keyboard_analysis,
        )

        assert result.has_patterns is True

    def test_has_patterns_true_when_keyboard_detected(
        self,
        empty_dictionary_analysis,
        empty_repeat_analysis,
        empty_sequential_analysis,
    ):
        keyboard = KeyboardAnalysis(detected=True)

        result = StrengthAnalysis(
            dictionary=empty_dictionary_analysis,
            repeat=empty_repeat_analysis,
            sequential=empty_sequential_analysis,
            keyboard=keyboard,
        )

        assert result.has_patterns is True

    def test_has_patterns_true_when_multiple_analyzers_detect(
        self,
    ):
        result = StrengthAnalysis(
            dictionary=DictionaryAnalysis(detected=True),
            repeat=RepeatAnalysis(detected=True),
            sequential=SequentialAnalysis(detected=True),
            keyboard=KeyboardAnalysis(detected=True),
        )

        assert result.has_patterns is True

    def test_maximum_severity_returns_highest_severity(
        self,
    ):
        dictionary = DictionaryAnalysis(severity=0.4)

        repeat = RepeatAnalysis(
            severity=0.7
        )

        sequential = SequentialAnalysis(
            severity=0.5
        )

        keyboard = KeyboardAnalysis(
            severity=0.9
        )

        result = StrengthAnalysis(
            dictionary=dictionary,
            repeat=repeat,
            sequential=sequential,
            keyboard=keyboard,
        )

        assert result.maximum_severity == 0.9

    def test_maximum_severity_is_zero_when_no_patterns(
        self,
    ):
        result = StrengthAnalysis(
            dictionary=DictionaryAnalysis(),
            repeat=RepeatAnalysis(),
            sequential=SequentialAnalysis(),
            keyboard=KeyboardAnalysis(),
        )

        assert result.maximum_severity == 0.0


class TestStrengthAnalyzer:
    """Tests for StrengthAnalyzer orchestration."""

    def test_analyze_returns_strength_analysis(
        self,
        analyzer,
    ):
        result = analyzer.analyze(
            "X9!Kz7@Lm2"
        )

        assert isinstance(
            result,
            StrengthAnalysis,
        )

    def test_analyze_returns_all_four_results(
        self,
        analyzer,
    ):
        result = analyzer.analyze(
            "X9!Kz7@Lm2"
        )

        assert isinstance(
            result.dictionary,
            DictionaryAnalysis,
        )

        assert isinstance(
            result.repeat,
            RepeatAnalysis,
        )

        assert isinstance(
            result.sequential,
            SequentialAnalysis,
        )

        assert isinstance(
            result.keyboard,
            KeyboardAnalysis,
        )

    def test_analyzers_are_initialized(
        self,
        analyzer,
    ):
        assert isinstance(
            analyzer.dictionary_analyzer,
            DictionaryAnalyzer,
        )

        assert isinstance(
            analyzer.repeat_analyzer,
            RepeatAnalyzer,
        )

        assert isinstance(
            analyzer.sequential_analyzer,
            SequentialAnalyzer,
        )

        assert isinstance(
            analyzer.keyboard_analyzer,
            KeyboardAnalyzer,
        )

    def test_all_analyzers_receive_same_config(
        self,
    ):
        config = StrengthConfig(
            enabled=False,
        )

        analyzer = StrengthAnalyzer(
            config=config,
        )

        assert analyzer.config is config
        assert analyzer.dictionary_analyzer.config is config
        assert analyzer.repeat_analyzer.config is config
        assert analyzer.sequential_analyzer.config is config
        assert analyzer.keyboard_analyzer.config is config

    def test_custom_dictionary_analyzer_is_used(
        self,
        config,
    ):
        dictionary_analyzer = DictionaryAnalyzer(
            config=config,
        )

        analyzer = StrengthAnalyzer(
            config=config,
            dictionary_analyzer=dictionary_analyzer,
        )

        assert (
            analyzer.dictionary_analyzer
            is dictionary_analyzer
        )

    def test_custom_repeat_analyzer_is_used(
        self,
        config,
    ):
        repeat_analyzer = RepeatAnalyzer(
            config=config,
        )

        analyzer = StrengthAnalyzer(
            config=config,
            repeat_analyzer=repeat_analyzer,
        )

        assert (
            analyzer.repeat_analyzer
            is repeat_analyzer
        )

    def test_custom_sequential_analyzer_is_used(
        self,
        config,
    ):
        sequential_analyzer = SequentialAnalyzer(
            config=config,
        )

        analyzer = StrengthAnalyzer(
            config=config,
            sequential_analyzer=sequential_analyzer,
        )

        assert (
            analyzer.sequential_analyzer
            is sequential_analyzer
        )

    def test_custom_keyboard_analyzer_is_used(
        self,
        config,
    ):
        keyboard_analyzer = KeyboardAnalyzer(
            config=config,
        )

        analyzer = StrengthAnalyzer(
            config=config,
            keyboard_analyzer=keyboard_analyzer,
        )

        assert (
            analyzer.keyboard_analyzer
            is keyboard_analyzer
        )


class TestStrengthAnalyzerDelegation:
    """Tests that StrengthAnalyzer delegates correctly."""

    def test_dictionary_analyzer_is_called(
        self,
        config,
        monkeypatch,
    ):
        calls = []

        dictionary_result = DictionaryAnalysis(
            detected=True,
            severity=0.8,
        )

        class FakeDictionaryAnalyzer:
            def analyze(self, password):
                calls.append(password)
                return dictionary_result

        analyzer = StrengthAnalyzer(
            config=config,
            dictionary_analyzer=FakeDictionaryAnalyzer(),
        )

        result = analyzer.analyze("TestPassword")

        assert calls == ["TestPassword"]
        assert result.dictionary is dictionary_result

    def test_repeat_analyzer_is_called(
        self,
        config,
    ):
        calls = []

        repeat_result = RepeatAnalysis(
            detected=True,
            severity=0.7,
        )

        class FakeRepeatAnalyzer:
            def analyze(self, password):
                calls.append(password)
                return repeat_result

        analyzer = StrengthAnalyzer(
            config=config,
            repeat_analyzer=FakeRepeatAnalyzer(),
        )

        result = analyzer.analyze("TestPassword")

        assert calls == ["TestPassword"]
        assert result.repeat is repeat_result

    def test_sequential_analyzer_is_called(
        self,
        config,
    ):
        calls = []

        sequential_result = SequentialAnalysis(
            detected=True,
            severity=0.6,
        )

        class FakeSequentialAnalyzer:
            def analyze(self, password):
                calls.append(password)
                return sequential_result

        analyzer = StrengthAnalyzer(
            config=config,
            sequential_analyzer=FakeSequentialAnalyzer(),
        )

        result = analyzer.analyze("TestPassword")

        assert calls == ["TestPassword"]
        assert result.sequential is sequential_result

    def test_keyboard_analyzer_is_called(
        self,
        config,
    ):
        calls = []

        keyboard_result = KeyboardAnalysis(
            detected=True,
            severity=0.9,
        )

        class FakeKeyboardAnalyzer:
            def analyze(self, password):
                calls.append(password)
                return keyboard_result

        analyzer = StrengthAnalyzer(
            config=config,
            keyboard_analyzer=FakeKeyboardAnalyzer(),
        )

        result = analyzer.analyze("TestPassword")

        assert calls == ["TestPassword"]
        assert result.keyboard is keyboard_result

    def test_all_analyzers_receive_same_password(
        self,
        config,
    ):
        calls = []

        class FakeAnalyzer:
            def __init__(self, name):
                self.name = name

            def analyze(self, password):
                calls.append(
                    (self.name, password)
                )

                if self.name == "dictionary":
                    return DictionaryAnalysis()

                if self.name == "repeat":
                    return RepeatAnalysis()

                if self.name == "sequential":
                    return SequentialAnalysis()

                return KeyboardAnalysis()

        analyzer = StrengthAnalyzer(
            config=config,
            dictionary_analyzer=FakeAnalyzer(
                "dictionary"
            ),
            repeat_analyzer=FakeAnalyzer(
                "repeat"
            ),
            sequential_analyzer=FakeAnalyzer(
                "sequential"
            ),
            keyboard_analyzer=FakeAnalyzer(
                "keyboard"
            ),
        )

        analyzer.analyze("MyTestPassword123!")

        assert calls == [
            ("dictionary", "MyTestPassword123!"),
            ("repeat", "MyTestPassword123!"),
            ("sequential", "MyTestPassword123!"),
            ("keyboard", "MyTestPassword123!"),
        ]

    def test_all_results_are_preserved(
        self,
        config,
    ):
        dictionary_result = DictionaryAnalysis(
            detected=True,
            severity=0.9,
        )

        repeat_result = RepeatAnalysis(
            detected=True,
            severity=0.7,
        )

        sequential_result = SequentialAnalysis(
            detected=True,
            severity=0.6,
        )

        keyboard_result = KeyboardAnalysis(
            detected=True,
            severity=0.8,
        )

        class FakeDictionaryAnalyzer:
            def analyze(self, password):
                return dictionary_result

        class FakeRepeatAnalyzer:
            def analyze(self, password):
                return repeat_result

        class FakeSequentialAnalyzer:
            def analyze(self, password):
                return sequential_result

        class FakeKeyboardAnalyzer:
            def analyze(self, password):
                return keyboard_result

        analyzer = StrengthAnalyzer(
            config=config,
            dictionary_analyzer=FakeDictionaryAnalyzer(),
            repeat_analyzer=FakeRepeatAnalyzer(),
            sequential_analyzer=FakeSequentialAnalyzer(),
            keyboard_analyzer=FakeKeyboardAnalyzer(),
        )

        result = analyzer.analyze(
            "MyTestPassword123!"
        )

        assert result.dictionary is dictionary_result
        assert result.repeat is repeat_result
        assert result.sequential is sequential_result
        assert result.keyboard is keyboard_result

        assert result.has_patterns is True
        assert result.maximum_severity == 0.9


class TestStrengthAnalyzerIntegration:
    """Integration-style tests using the real analyzers."""

    def test_strong_password_has_no_or_few_patterns(
        self,
        analyzer,
    ):
        result = analyzer.analyze(
            "V7$mQ2#xL9@pR4!"
        )

        assert isinstance(
            result,
            StrengthAnalysis,
        )

        assert result.dictionary.detected is False
        assert result.repeat.detected is False
        assert result.sequential.detected is False
        assert result.keyboard.detected is False

        assert result.has_patterns is False
        assert result.maximum_severity == 0.0

    def test_common_password_is_detected(
        self,
        analyzer,
    ):
        result = analyzer.analyze("password")

        assert result.dictionary.detected is True
        assert result.dictionary.common_password_detected is True
        assert result.has_patterns is True

    def test_repeated_characters_are_detected(
        self,
        analyzer,
    ):
        result = analyzer.analyze(
            "Password111!"
        )

        assert result.repeat.detected is True
        assert result.has_patterns is True

    def test_keyboard_pattern_is_detected(
        self,
        analyzer,
    ):
        result = analyzer.analyze(
            "qwerty"
        )

        assert result.keyboard.detected is True
        assert result.keyboard.horizontal_detected is True
        assert result.has_patterns is True

    def test_sequential_pattern_is_detected(
        self,
        analyzer,
    ):
        result = analyzer.analyze(
            "abcdXYZ!"
        )

        assert result.sequential.detected is True
        assert result.has_patterns is True

    def test_multiple_analyzers_detect_same_password(
        self,
        analyzer,
    ):
        result = analyzer.analyze(
            "password111!"
        )

        assert result.dictionary.detected is True
        assert result.repeat.detected is True

        assert result.has_patterns is True
        assert result.maximum_severity > 0.0

    def test_empty_password(
        self,
        analyzer,
    ):
        result = analyzer.analyze("")

        assert isinstance(
            result,
            StrengthAnalysis,
        )

        assert result.dictionary.detected is False
        assert result.repeat.detected is False
        assert result.sequential.detected is False
        assert result.keyboard.detected is False

        assert result.has_patterns is False
        assert result.maximum_severity == 0.0


class TestStrengthAnalyzerConfiguration:
    """Tests for configuration behavior."""

    def test_disabled_strength_analysis(
        self,
    ):
        config = StrengthConfig(
            enabled=False,
        )

        analyzer = StrengthAnalyzer(
            config=config,
        )

        result = analyzer.analyze(
            "password111qwerty1234"
        )

        assert result.has_patterns is False
        assert result.maximum_severity == 0.0

    def test_keyboard_can_be_disabled(
        self,
    ):
        config = StrengthConfig(
            check_horizontal=False,
            check_vertical=False,
            check_diagonal=False,
            check_number_row=False,
        )

        analyzer = StrengthAnalyzer(
            config=config,
        )

        result = analyzer.analyze(
            "qwerty1234"
        )

        assert result.keyboard.detected is False

    def test_common_password_detection_can_be_disabled(
        self,
    ):
        config = StrengthConfig(
            check_common_passwords=False,
        )

        analyzer = StrengthAnalyzer(
            config=config,
        )

        result = analyzer.analyze(
            "password"
        )

        assert result.dictionary.common_password_detected is False

    def test_repeat_detection_can_be_disabled(
        self,
    ):
        config = StrengthConfig(
            check_consecutive=False,
            check_repeated_groups=False,
            check_character_frequency=False,
        )

        analyzer = StrengthAnalyzer(
            config=config,
        )

        result = analyzer.analyze(
            "Password111!"
        )

        assert result.repeat.detected is False
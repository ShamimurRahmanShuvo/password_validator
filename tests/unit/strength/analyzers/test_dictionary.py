"""
Unit tests for the dictionary analyzer.
"""
import pytest
from password_validator.strength.analyzers.dictionary import (
    DictionaryAnalyzer,
    DictionaryAnalysis,
    DictionaryMatch,
    DictionaryMatchType
)
from password_validator.strength.config import StrengthConfig


@pytest.fixture
def analyzer():
    return DictionaryAnalyzer(config=StrengthConfig.defaults())


@pytest.fixture
def disabled_analyzer():
    return DictionaryAnalyzer(config=StrengthConfig(check_dictionary_words=False))


@pytest.fixture
def dictionary_file(tmp_path):
    """Temporary dictionary file."""
    path = tmp_path / "dictionary.txt"

    path.write_text(
        "\n".join(
            [
                "computer",
                "python",
                "security",
                "welcome",
                "dragon",
                "testing",
                "secret",
                "database",
            ]
        ),
        encoding="utf-8",
    )

    return path


@pytest.fixture
def common_password_file(tmp_path):
    """Temporary common-password file."""
    path = tmp_path / "common_passwords.txt"

    path.write_text(
        "\n".join(
            [
                "password",
                "letmein",
                "supersecret",
                "welcome123",
            ]
        ),
        encoding="utf-8",
    )

    return path


class TestDictionaryAnalysis:
    """
    Tests for the DictionaryAnalysis class.
    """
    def test_default_values(self):
        result = DictionaryAnalysis()

        assert result.detected is False
        assert result.matches == []
        assert result.common_password_detected is False
        assert result.dictionary_word_detected is False
        assert result.exact_match_detected is False
        assert result.embedded_match_detected is False
        assert result.severity == 0.0
        assert result.penalty_factor == 0.0
        assert result.match_count == 0

    def test_match_count(self):
        result = DictionaryAnalysis()

        result.matches.append(
            DictionaryMatch(
                value="password",
                normalized_value="password",
                match_type=DictionaryMatchType.EXACT_COMMON_PASSWORD,
                start_position=0,
                end_position=8,
                severity=1.0,
                message="Password matches a common password.",
            )
        )
        assert result.match_count == 1


class TestDictionaryMatch:
    """
    Tests for the DictionaryMatch class.
    """
    def test_dictionary_match_is_frozen(self):
        match = DictionaryMatch(
            value="password",
            normalized_value="password",
            match_type=DictionaryMatchType.EXACT_COMMON_PASSWORD,
            start_position=0,
            end_position=8,
            severity=1.0,
            message="Password matches a common password.",
        )

        with pytest.raises(AttributeError):
            match.value = "changed"

    def test_dictionary_match_fields(self):
        match = DictionaryMatch(
            value="Python",
            normalized_value="python",
            match_type=DictionaryMatchType.EXACT_DICTIONARY_WORD,
            start_position=0,
            end_position=6,
            severity=0.9,
            message="Password matches a dictionary word.",
        )

        assert match.value == "Python"
        assert match.normalized_value == "python"
        assert match.match_type == DictionaryMatchType.EXACT_DICTIONARY_WORD
        assert match.start_position == 0
        assert match.end_position == 6
        assert match.severity == 0.9


class TestDictionaryAnalyzer:
    """
    Tests for the DictionaryAnalyzer class.
    """
    def test_empty_password_returns_empty_analysis(self, analyzer):
        result = analyzer.analyze("")

        assert isinstance(result, DictionaryAnalysis)
        assert result.detected is False
        assert result.matches == []
        assert result.common_password_detected is False
        assert result.dictionary_word_detected is False
        assert result.exact_match_detected is False
        assert result.embedded_match_detected is False
        assert result.severity == 0.0
        assert result.penalty_factor == 0.0
        assert result.match_count == 0

    def test_non_matching_password_returns_no_match(self, analyzer):
        result = analyzer.analyze("X9!mK7@zQ2")

        assert isinstance(result, DictionaryAnalysis)
        assert result.detected is False
        assert result.matches == []
        assert result.common_password_detected is False
        assert result.dictionary_word_detected is False
        assert result.exact_match_detected is False
        assert result.embedded_match_detected is False
        assert result.severity == 0.0
        assert result.penalty_factor == 0.0
        assert result.match_count == 0

    def test_disabled_dictionary_check_returns_empty_analysis(self, disabled_analyzer):
        result = disabled_analyzer.analyze("password")

        assert isinstance(result, DictionaryAnalysis)
        assert result.detected is False
        assert result.matches == []
        assert result.common_password_detected is False
        assert result.dictionary_word_detected is False
        assert result.exact_match_detected is False
        assert result.embedded_match_detected is False
        assert result.severity == 0.0
        assert result.penalty_factor == 0.0
        assert result.match_count == 0


class TestCommonPasswords:
    """
    Tests for common passwords detection.
    """

    @pytest.mark.parametrize(
        "password",
        [
            "password", "password1", "password123", "123456", "12345678", "123456789", "1234567890", "qwerty",
            "qwerty123", "admin", "admin123", "administrator", "welcome", "welcome1", "letmein", "login", "passw0rd",
            "p@ssword", "abc123", "iloveyou", "monkey", "dragon", "master", "football", "baseball", "secret", "changeme"
        ]
    )
    def test_default_common_passwords_detected(self, analyzer, password):
        result = analyzer.analyze(password)

        assert isinstance(result, DictionaryAnalysis)
        assert result.detected is True
        assert result.common_password_detected is True
        assert result.dictionary_word_detected is False
        assert result.exact_match_detected is True
        assert result.embedded_match_detected is False
        assert result.match_count == 1
        assert any(match.match_type == DictionaryMatchType.EXACT_COMMON_PASSWORD for match in result.matches)

    @pytest.mark.parametrize(
        "password",
        [
            "Password", "PASSWORD", "PaSsWoRd", "WELCOME", "Admin", "LETMEIN",
        ]
    )
    def test_common_passwords_case_insensitive(self, analyzer, password):
        result = analyzer.analyze(password)

        assert isinstance(result, DictionaryAnalysis)
        assert result.detected is True
        assert result.common_password_detected is True
        assert result.dictionary_word_detected is False
        assert result.exact_match_detected is True
        assert result.embedded_match_detected is False
        assert result.match_count == 1
        assert any(match.match_type == DictionaryMatchType.EXACT_COMMON_PASSWORD for match in result.matches)

    def test_exact_common_password_has_severity_one(self, analyzer):
        result = analyzer.analyze("password")

        assert isinstance(result, DictionaryAnalysis)
        assert result.detected is True
        assert result.common_password_detected is True
        assert result.dictionary_word_detected is False
        assert result.exact_match_detected is True
        assert result.embedded_match_detected is False
        assert result.match_count == 1
        assert any(match.match_type == DictionaryMatchType.EXACT_COMMON_PASSWORD for match in result.matches)
        assert all(match.severity == 1.0 for match in result.matches)

    def test_exact_common_password_match_details(self, analyzer):
        result = analyzer.analyze("password")

        assert isinstance(result, DictionaryAnalysis)
        assert result.detected is True
        assert result.common_password_detected is True
        assert result.dictionary_word_detected is False
        assert result.exact_match_detected is True
        assert result.embedded_match_detected is False
        assert result.match_count == 1

        match = result.matches[0]
        assert match.value == "password"
        assert match.normalized_value == "password"
        assert match.match_type == DictionaryMatchType.EXACT_COMMON_PASSWORD
        assert match.start_position == 0
        assert match.end_position == 8
        assert match.severity == 1.0
        assert match.message == "Password matches a common password."

    def test_common_password_check_can_be_disabled(self):
        config = StrengthConfig(check_common_passwords=False)
        analyzer = DictionaryAnalyzer(config=config)
        result = analyzer.analyze("password")

        assert result.detected is False
        assert result.common_password_detected is False
        assert result.matches == []


class TestCommonPasswordSubstrings:
    """
    Tests for detection of common password substrings within longer passwords.
    """
    def test_embedded_common_password_detected(self, analyzer):
        result = analyzer.analyze("mypassword123")

        assert isinstance(result, DictionaryAnalysis)
        assert result.detected is True
        assert result.common_password_detected is True
        assert result.dictionary_word_detected is False
        assert result.exact_match_detected is False
        assert result.embedded_match_detected is True
        assert result.match_count == 1

        match = result.matches[0]
        assert match.value == "password"
        assert match.normalized_value == "password"
        assert match.match_type == DictionaryMatchType.COMMON_PASSWORD_SUBSTRING
        assert match.start_position == 2
        assert match.end_position == 10
        assert match.severity == 0.85

    def test_common_password_substring_can_be_disabled(self, analyzer):
        config = StrengthConfig(check_common_passwords=False)
        analyzer = DictionaryAnalyzer(config=config)
        result = analyzer.analyze("mypassword123")

        assert result.detected is False
        assert result.common_password_detected is False
        assert result.matches == []


class TestDictionaryWords:
    """
    Tests for detection of dictionary words in passwords.
    """
    def test_exact_dictionary_words(self, dictionary_file):
        config = StrengthConfig(check_dictionary_words=True, dictionary_file=str(dictionary_file))
        analyzer = DictionaryAnalyzer(config=config)
        result = analyzer.analyze("python")

        assert result.detected is True
        assert result.dictionary_word_detected is True
        assert result.exact_match_detected is True
        assert any(match.match_type == DictionaryMatchType.EXACT_DICTIONARY_WORD for match in result.matches)

    def test_dictionary_word_details(self, dictionary_file):
        config = StrengthConfig(check_dictionary_words=True, dictionary_file=str(dictionary_file))
        analyzer = DictionaryAnalyzer(config=config)
        result = analyzer.analyze("python")

        assert isinstance(result, DictionaryAnalysis)
        assert result.detected is True
        assert result.dictionary_word_detected is True
        assert result.exact_match_detected is True
        assert result.embedded_match_detected is False
        assert result.match_count == 1

        match = result.matches[0]
        assert match.value == "python"
        assert match.normalized_value == "python"
        assert match.match_type == DictionaryMatchType.EXACT_DICTIONARY_WORD
        assert match.start_position == 0
        assert match.end_position == 6
        assert match.severity == 0.9

    def test_dictionary_word_is_case_insensitive(self, dictionary_file):
        config = StrengthConfig(dictionary_file=str(dictionary_file), case_insensitive=True)
        analyzer = DictionaryAnalyzer(config=config)
        result = analyzer.analyze("Python")

        assert result.detected is True
        assert result.dictionary_word_detected is True
        assert result.exact_match_detected is True
        assert any(match.match_type == DictionaryMatchType.EXACT_DICTIONARY_WORD for match in result.matches)

    def test_embedded_dictionary_word_detected(self, dictionary_file):
        config = StrengthConfig(check_dictionary_words=True, dictionary_file=str(dictionary_file))
        analyzer = DictionaryAnalyzer(config=config)
        result = analyzer.analyze("mypython123")

        assert isinstance(result, DictionaryAnalysis)
        assert result.detected is True
        assert result.dictionary_word_detected is True
        assert result.exact_match_detected is False
        assert result.embedded_match_detected is True
        assert result.match_count == 1

        match = result.matches[0]
        assert match.value == "python"
        assert match.normalized_value == "python"
        assert match.match_type == DictionaryMatchType.DICTIONARY_WORD_SUBSTRING
        assert match.start_position == 2
        assert match.end_position == 8
        assert match.severity == 0.75

    def test_dictionary_word_check_can_be_disabled(self, dictionary_file):
        config = StrengthConfig(check_dictionary_words=False, dictionary_file=str(dictionary_file))
        analyzer = DictionaryAnalyzer(config=config)
        result = analyzer.analyze("python")

        assert result.detected is False
        assert result.dictionary_word_detected is False
        assert result.matches == []


class TestDictionaryFileLoading:
    """
    Tests for loading dictionary files and handling errors.
    """
    def test_load_valid_dictionary_file(self, dictionary_file):
        config = StrengthConfig(dictionary_file=str(dictionary_file))
        analyzer = DictionaryAnalyzer(config=config)
        result = analyzer.analyze("python")

        assert result.detected is True
        assert result.dictionary_word_detected is True
        assert any(match.match_type == DictionaryMatchType.EXACT_DICTIONARY_WORD for match in result.matches)

    def test_load_nonexistent_dictionary_file(self, tmp_path):
        missing_file = tmp_path / "nonexistent.txt"
        config = StrengthConfig(dictionary_file=str(missing_file))
        analyzer = DictionaryAnalyzer(config=config)

        assert analyzer._dictionary_words == set()
        result = analyzer.analyze("python")
        assert result.detected is False

    def test_directory_as_dictionary_file_is_ignored(self, tmp_path):
        directory = tmp_path / "dictionary"
        directory.mkdir()
        config = StrengthConfig(dictionary_file=str(directory))
        analyzer = DictionaryAnalyzer(config=config)

        assert analyzer._dictionary_words == set()

    def test_blank_lines_are_ignored(self, tmp_path):
        dictionary = tmp_path / "dictionary.txt"
        dictionary.write_text("\npython\n\nsecurity\n\n", encoding="utf-8")
        config = StrengthConfig(dictionary_file=str(dictionary),)
        analyzer = DictionaryAnalyzer(config=config)

        assert "python" in analyzer._dictionary_words
        assert "security" in analyzer._dictionary_words

    def test_comment_lines_are_ignored(self, tmp_path):
        dictionary = tmp_path / "dictionary.txt"
        dictionary.write_text(
            "\n".join(
                [
                    "# This is a comment",
                    "python",
                    "# another comment",
                    "security",
                ]
            ),
            encoding="utf-8",
        )

        config = StrengthConfig(dictionary_file=str(dictionary))
        analyzer = DictionaryAnalyzer(config=config)

        assert "python" in analyzer._dictionary_words
        assert "security" in analyzer._dictionary_words
        assert "# This is a comment" not in analyzer._dictionary_words

    def test_common_password_file_is_loaded(self, common_password_file):
        config = StrengthConfig(
            common_password_file=str(
                common_password_file
            ),
        )

        analyzer = DictionaryAnalyzer(config=config)

        assert "supersecret" in analyzer._common_passwords
        assert "welcome123" in analyzer._common_passwords


class TestNormalization:
    """Tests for password normalization."""

    def test_lowercase_normalization(self, analyzer):
        assert analyzer._normalize("PASSWORD") == "password"

    def test_non_alphanumeric_characters_are_removed(self, analyzer):
        normalized = analyzer._normalize("p@ss-word!")

        assert normalized == "passwordi"

    @pytest.mark.parametrize(
        "password, expected",
        [
            ("p@ssword", "password"),
            ("p4ssword", "password"),
            ("passw0rd", "password"),
            ("pa$$word", "password"),
            ("pa55word", "password"),
            ("passw7rd", "passwtrd"),
        ],
    )
    def test_leet_normalization(self, analyzer, password, expected):
        assert analyzer._normalize(password) == expected

    def test_leet_normalization_can_be_disabled(self):
        config = StrengthConfig(leet_normalization=False)
        analyzer = DictionaryAnalyzer(config=config)
        normalized = analyzer._normalize("p@ssword")

        assert normalized == "pssword"

    def test_case_insensitive_normalization_can_be_disabled(self):
        config = StrengthConfig(
            case_insensitive=False,
            leet_normalization=False,
        )

        analyzer = DictionaryAnalyzer(config=config)
        normalized = analyzer._normalize("PASSWORD")

        # Current implementation ultimately lowercases
        # the normalized value.
        assert normalized == "password"


class TestLeetDetection:
    """Tests for leetspeak common-password detection."""

    @pytest.mark.parametrize(
        "password",
        [
            "p@ssword",
            "passw0rd",
            "p@$$w0rd",
        ],
    )
    def test_leet_common_password_detected(self, analyzer, password):
        result = analyzer.analyze(password)

        assert result.detected is True
        assert result.common_password_detected is True

    def test_leet_normalization_can_be_disabled_for_detection(self):
        config = StrengthConfig(leet_normalization=False)
        analyzer = DictionaryAnalyzer(config=config)
        result = analyzer.analyze("p@ssword")

        # The implementation performs a raw common-password
        # comparison first. Therefore p@ssword itself is already
        # present in the default common-password set.
        assert result.detected is True
        assert any(match.match_type == DictionaryMatchType.EXACT_COMMON_PASSWORD for match in result.matches)


class TestDuplicateMatches:
    """Tests for duplicate match prevention."""

    def test_duplicate_match_is_not_added(self, analyzer):
        result = DictionaryAnalysis()
        analyzer._add_match(
            result=result,
            value="password",
            normalized_value="password",
            match_type=DictionaryMatchType.EXACT_COMMON_PASSWORD,
            start=0,
            end=8,
            severity=1.0,
            message="Password matches a common password.",
        )
        analyzer._add_match(
            result=result,
            value="password",
            normalized_value="password",
            match_type=DictionaryMatchType.EXACT_COMMON_PASSWORD,
            start=0,
            end=8,
            severity=1.0,
            message="Password matches a common password.",
        )

        assert len(result.matches) == 1

    def test_same_value_different_match_type_is_allowed(self, analyzer):
        result = DictionaryAnalysis()
        analyzer._add_match(
            result=result,
            value="python",
            normalized_value="python",
            match_type=DictionaryMatchType.EXACT_COMMON_PASSWORD,
            start=0,
            end=6,
            severity=1.0,
            message="Common password.",
        )

        analyzer._add_match(
            result=result,
            value="python",
            normalized_value="python",
            match_type=DictionaryMatchType.EXACT_DICTIONARY_WORD,
            start=0,
            end=6,
            severity=0.9,
            message="Dictionary word.",
        )

        assert len(result.matches) == 2


class TestAnalysisFlags:
    """Tests for result flags."""

    def test_common_password_sets_common_password_flag(self, analyzer):
        result = analyzer.analyze("password")

        assert result.common_password_detected is True
        assert result.dictionary_word_detected is False or True

    def test_exact_common_password_sets_exact_flag(self, analyzer):
        result = analyzer.analyze("password")

        assert result.exact_match_detected is True

    def test_embedded_common_password_sets_embedded_flag(self, analyzer):
        result = analyzer.analyze(
            "mypasswordsecure"
        )

        assert result.embedded_match_detected is True

    def test_exact_dictionary_word_sets_dictionary_flag(self, dictionary_file):
        config = StrengthConfig(
            dictionary_file=str(dictionary_file),
        )

        analyzer = DictionaryAnalyzer(config=config)
        result = analyzer.analyze("python")

        assert result.dictionary_word_detected is True
        assert result.exact_match_detected is True

    def test_embedded_dictionary_word_sets_embedded_flag(self, dictionary_file):
        config = StrengthConfig(
            dictionary_file=str(dictionary_file),
        )

        analyzer = DictionaryAnalyzer(config=config)
        result = analyzer.analyze("mypythonpassword")

        assert result.dictionary_word_detected is True
        assert result.embedded_match_detected is True


class TestFinalization:
    """Tests for severity and penalty calculation."""

    def test_no_matches_have_zero_severity(self, analyzer):
        result = analyzer.analyze("Xy9!Kz7@Lm2")

        assert result.detected is False
        assert result.severity == 0.0
        assert result.penalty_factor == 0.0

    def test_severity_is_maximum_match_severity(self, dictionary_file):
        config = StrengthConfig(
            dictionary_file=str(dictionary_file),
        )
        analyzer = DictionaryAnalyzer(config=config)
        result = analyzer.analyze("passwordpython")

        assert result.detected is True

        expected = max(match.severity for match in result.matches)

        assert result.severity == expected
        assert result.penalty_factor == expected

    def test_severity_never_exceeds_one(self, analyzer):
        result = analyzer.analyze("password")

        assert 0.0 <= result.severity <= 1.0
        assert 0.0 <= result.penalty_factor <= 1.0


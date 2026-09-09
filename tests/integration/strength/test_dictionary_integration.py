from pathlib import Path
from password_validator.strength.analyzers.dictionary import DictionaryAnalyzer
from password_validator.strength.config import StrengthConfig


class TestDictionaryAnalyzerIntegration:
    def test_external_dictionary_file_is_loaded(self, dictionary_file: Path):
        config = StrengthConfig(
            dictionary_file=str(dictionary_file),
            check_dictionary_words=True
        )
        analyzer = DictionaryAnalyzer(config=config)
        result = analyzer.analyze("Computer123!")
        assert result.detected is True
        assert result.dictionary_word_detected is True

    def test_dictionary_word_embedded_in_password(self, dictionary_file: Path):
        config = StrengthConfig(
            dictionary_file=str(dictionary_file),
            check_dictionary_words=True
        )
        analyzer = DictionaryAnalyzer(config=config)
        result = analyzer.analyze("MyComputer123!")
        assert result.detected is True
        assert result.dictionary_word_detected is True
        assert result.embedded_match_detected is True

    def test_common_password_is_detected(self):
        analyzer = DictionaryAnalyzer()
        result = analyzer.analyze("password")
        assert result.detected is True
        assert result.common_password_detected is True

    def test_leet_normalization_detects_password(self):
        analyzer = DictionaryAnalyzer()
        result = analyzer.analyze("P@ssw0rd")
        assert result.detected is True
        assert result.common_password_detected is True

    def test_dictionary_can_be_disabled(self):
        config = StrengthConfig(
            check_dictionary_words=False
        )
        analyzer = DictionaryAnalyzer(config=config)
        result = analyzer.analyze("password")
        assert result.detected is False

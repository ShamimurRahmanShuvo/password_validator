"""
Password strength scoring weights.
All values are loaded from the environment to allow for easy configuration without code changes.
"""
from dataclasses import dataclass
from src.loaders import EnvLoader


@dataclass(slots=True, frozen=True)
class StrengthWeights:
    """
    Configurable password scoring weights loaded from environment variables.
    """
    # --------------------------------------------------
    # Length bonus weights
    # --------------------------------------------------
    length_8: int = 10
    length_12: int = 10
    length_16: int = 10
    length_20: int = 10

    # --------------------------------------------------
    # Character set bonuses
    # --------------------------------------------------
    lowercase: int = 5
    uppercase: int = 5
    digit: int = 5
    special: int = 10

    # --------------------------------------------------
    # Character diversity bonuses
    # --------------------------------------------------
    unique_character: int = 15

    # --------------------------------------------------
    # Entropy bonuses
    # --------------------------------------------------
    entropy_40: int = 5
    entropy_60: int = 10
    entropy_80: int = 15

    # --------------------------------------------------
    # Penalties
    # --------------------------------------------------
    repeated_character: int = 15
    sequential_character: int = 15
    keyboard_pattern: int = 20
    common_password: int = 40
    dictionary_word: int = 20

    # --------------------------------------------------
    # Bonuses
    # --------------------------------------------------
    long_password_bonus: int = 10
    mixed_character_bonus: int = 10

    # --------------------------------------------------
    # Maximum score
    # --------------------------------------------------
    maximum_score: int = 100

    @classmethod
    def load(cls, env_file: str = ".env") -> "StrengthWeights":
        """
        Load strength weights from environment variables.

        :param env_file: Path to the .env file. Defaults to ".env".
        :return: An instance of StrengthWeights with values loaded from the environment.
        """
        env_loader = EnvLoader(env_file)

        return cls(
            length_8=env_loader.get_int("STRENGTH_LENGTH_8_SCORE", 10),
            length_12=env_loader.get_int("STRENGTH_LENGTH_12_SCORE", 10),
            length_16=env_loader.get_int("STRENGTH_LENGTH_16_SCORE", 10),
            length_20=env_loader.get_int("STRENGTH_LENGTH_20_SCORE", 10),
            lowercase=env_loader.get_int("STRENGTH_LOWERCASE_SCORE", 5),
            uppercase=env_loader.get_int("STRENGTH_UPPERCASE_SCORE", 5),
            digit=env_loader.get_int("STRENGTH_DIGIT_SCORE", 5),
            special=env_loader.get_int("STRENGTH_SPECIAL_SCORE", 10),
            unique_character=env_loader.get_int("STRENGTH_UNIQUE_CHARACTER_SCORE", 15),
            entropy_40=env_loader.get_int("STRENGTH_ENTROPY_40_SCORE", 5),
            entropy_60=env_loader.get_int("STRENGTH_ENTROPY_60_SCORE", 10),
            entropy_80=env_loader.get_int("STRENGTH_ENTROPY_80_SCORE", 15),
            repeated_character=env_loader.get_int("PENALTY_REPEATED_CHARACTER", 15),
            sequential_character=env_loader.get_int("PENALTY_SEQUENTIAL_CHARACTER", 15),
            keyboard_pattern=env_loader.get_int("PENALTY_KEYBOARD_PATTERN", 20),
            common_password=env_loader.get_int("PENALTY_COMMON_PASSWORD", 40),
            dictionary_word=env_loader.get_int("PENALTY_DICTIONARY_WORD", 20),
            long_password_bonus=env_loader.get_int("BONUS_LONG_PASSWORD", 10),
            mixed_character_bonus=env_loader.get_int("BONUS_MIXED_CHARACTER_SET", 10),
            maximum_score=env_loader.get_int("MAX_PASSWORD_SCORE", 100)
        )


default_strength_weights = StrengthWeights.load()

"""
Password strength scoring weights.
All values are loaded from the environment to allow for easy configuration without code changes.
"""
from __future__ import annotations
from dataclasses import dataclass
from ..loaders.env_loader import EnvLoader


@dataclass(slots=True, frozen=True)
class StrengthWeights:
    """
    Scoring weights.
    Penalty values represent the maximum number of points that can be deducted when the corresponding weakness
    has maximum severity.
    Bonus valus represent positive score contributions.
    """
    # --------------------------------------------------
    # Penalties
    # --------------------------------------------------
    repeated_character: float = 15.0
    sequential_pattern: float = 15.0
    keyboard_pattern: float = 15.0
    dictionary_pattern: float = 15.0

    # --------------------------------------------------
    # Bonuses
    # --------------------------------------------------
    length_12_plus: float = 5.0
    length_16_plus: float = 5.0
    character_diversity: float = 5.0
    all_character_classes: float = 5.0
    high_entropy: float = 5.0

    @classmethod
    def from_env(cls, env: EnvLoader) -> "StrengthWeights":
        """
        Load strength weights from EnvLoader.

        :param env: Path to the .env file. Defaults to ".env".
        :return: An instance of StrengthWeights with values loaded from the environment.
        """

        return cls(
            repeated_character=env.get_float("STRENGTH_WEIGHT_REPEATED_CHARACTER", 15.0),
            sequential_pattern=env.get_float("STRENGTH_WEIGHT_SEQUENTIAL_PATTERN", 15.0),
            keyboard_pattern=env.get_float("STRENGTH_WEIGHT_KEYBOARD_PATTERN", 15.0),
            dictionary_pattern=env.get_float("STRENGTH_WEIGHT_DICTIONARY_PATTERN", 15.0),
            length_12_plus=env.get_float("STRENGTH_WEIGHT_LENGTH_12_PLUS", 5.0),
            length_16_plus=env.get_float("STRENGTH_WEIGHT_LENGTH_16_PLUS", 5.0),
            character_diversity=env.get_float("STRENGTH_WEIGHT_CHARACTER_DIVERSITY", 5.0),
            all_character_classes=env.get_float("STRENGTH_WEIGHT_ALL_CHARACTER_CLASSES", 5.0),
            high_entropy=env.get_float("STRENGTH_WEIGHT_HIGH_ENTROPY", 5.0)
        )

    @classmethod
    def defaults(cls) -> "StrengthWeights":
        """
        Return the built-in default weights.

        No environment variables are loaded.
        """

        return cls()

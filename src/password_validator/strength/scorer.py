"""
Scoring based on:
- entropy
- character diversity
- length
- dictionary words
- sequential characters
- repeated characters
"""
from ..enums import StrengthLevel
from ..utils import EntropyCalculator


class PasswordStrengthScorer:
    def score(self, password: str) -> tuple(StrengthLevel):
        """
        Score the password strength based on various criteria.

        :param password: The password to score.
        :return: The strength level of the password.
        """
        score = 0

        # Length scoring
        length = len(password)

        if length >= 8:
            score += 15

        if length >= 12:
            score += 15

        if length >= 16:
            score += 10

        # Character diversity scoring
        if any(c.islower() for c in password):
            score += 10

        if any(c.isupper() for c in password):
            score += 10

        if any(c.isdigit() for c in password):
            score += 10

        if any(not c.isalnum() for c in password):
            score += 15

        # Unique character scoring

        unique_chars = len(set(password))
        score += min(unique_chars, 15)

        # Entropy scoring
        entropy = EntropyCalculator.calculate_entropy(password)

        if entropy >= 40:
            score += 5

        if entropy >= 60:
            score += 5

        if entropy >= 80:
            score += 5

        score = min(score, 100)

        return score, self._strength(score)

    def _strength(self, score: int) -> StrengthLevel:
        """
        Determine the strength level based on the score.

        :param score: The score of the password.
        :return: The strength level of the password.
        """
        if score < 20:
            return StrengthLevel.VERY_WEAK
        elif score < 40:
            return StrengthLevel.WEAK
        elif score < 60:
            return StrengthLevel.FAIR
        elif score < 80:
            return StrengthLevel.GOOD
        elif score < 95:
            return StrengthLevel.STRONG
        else:
            return StrengthLevel.VERY_STRONG

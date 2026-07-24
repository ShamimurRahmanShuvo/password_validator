"""
Password entropy calculation utility.
"""
import math


class EntropyCalculator:
    """
    Shannon-entropy calculator for passwords.
    """
    @staticmethod
    def calculate_entropy(password: str) -> float:
        """
        Calculate the Shannon entropy of a password.

        Args:
            password (str): The password to calculate entropy for.

        Returns:
            float: The calculated entropy value.
        """
        if not password:
            return 0.0

        # Count the frequency of each character in the password
        char_count = {}
        for char in password:
            char_count[char] = char_count.get(char, 0) + 1

        # Calculate the entropy
        length = len(password)
        charset = 0

        if any(c.islower() for c in password):
            charset += 26
        if any(c.isupper() for c in password):
            charset += 26
        if any(c.isdigit() for c in password):
            charset += 10
        if any(not c.isalnum() for c in password):
            charset += 32
        if charset == 0:
            return 0.0

        entropy = length * math.log2(charset)

        """
        for count in char_count.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        """
        return round(entropy, 2)

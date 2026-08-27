from password_validator import PasswordValidator, PasswordStrengthScorer

validator = PasswordValidator()

result = validator.validate(
    "MyPassword123!"
)

if result.is_valid:
    print("Password is valid")

scorer = PasswordStrengthScorer()

result = scorer.score(
    "MySecurePassword123!"
)

print(result.score)
print(result.level)
print(result.suggestions)

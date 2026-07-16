from src.password_validator.config import PasswordPolicy


policy = PasswordPolicy.load()


print(policy.min_length)

print(policy.require_special)

print(policy.min_digit)

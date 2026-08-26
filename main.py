from password_validator import PasswordValidator

validator = PasswordValidator()

result = validator.validate(
    "MyPassword123!"
)

if result.is_valid:
    print("Password is valid")

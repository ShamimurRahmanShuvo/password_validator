# Password Validator Pro

A highly configurable Python password validation library.

## Features

- Environment-based configuration
- No code changes required
- Password strength scoring
- Plugin architecture
- Custom validation rules
- FastAPI support
- Flask support
- Django support
- Custom regex validation
- Entropy calculation
- Blacklist support
- Dictionary validation
- Username similarity detection
- Sequential character detection
- Repeated character detection

---

## Installation

```bash
pip install password-validator
```

---

## Quick Start

```python
from password_validator import PasswordValidator

validator = PasswordValidator()

result = validator.validate("Password@123")

print(result.valid)
```

---

## Configuration

Copy

```
.env.example
```

to

```
.env
```

Modify any rule.

Example

```
PASSWORD_MIN_LENGTH=12

PASSWORD_REQUIRE_SPECIAL=true

PASSWORD_MIN_SPECIAL=2
```

Restart your application.

No code changes required.

---

## Supported Rules

- Minimum Length
- Maximum Length
- Uppercase Letters
- Lowercase Letters
- Digits
- Special Characters
- Repeated Characters
- Sequential Characters
- Dictionary Words
- Common Passwords
- Entropy
- Username Similarity
- Custom Regex

---

## License

MIT (Dummy for now)
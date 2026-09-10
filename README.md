# Password Validator Pro

A configurable Python library for password policy validation and password strength analysis.

**Version:** 1.0.0  
**Python:** 3.10+  
**License:** MIT

## What it provides

Password Validator Pro separates two concerns:

1. **Password policy validation** — determines whether a password satisfies the configured rules.
2. **Password strength analysis** — analyzes password characteristics and patterns, produces a score, identifies a strength level, and generates improvement suggestions.

### Core capabilities

- Minimum and maximum password length validation
- Uppercase, lowercase, digit, and special-character rules
- Configurable special-character set
- Environment-based configuration through `.env` files and process environment variables
- Custom validation rules through the `Rule` abstraction
- Rule registration and removal through `RuleRegistry`
- Repeated-character analysis
- Repeated-group analysis
- Sequential-pattern analysis
- Keyboard-pattern analysis
- Dictionary and common-password analysis
- Character composition and estimated entropy metrics
- Configurable strength scoring weights
- Password-strength suggestions
- Structured validation and strength result objects
- `src/` package layout suitable for modern Python packaging

## Installation

### From PyPI

```bash
python -m pip install password-validator
```

### From source

```bash
git clone https://github.com/ShamimurRahmanShuvo/password-validator.git
cd password-validator
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

For Windows PowerShell, activate the environment with:

```powershell
.venv\Scripts\Activate.ps1
```

See [`docs/installation.md`](docs/installation.md) for the complete installation and packaging guide.

## Quick start

```python
from password_validator import PasswordValidator

validator = PasswordValidator()
result = validator.validate("MySecurePassword123!")

print(result.valid)
print(result.passed)
print(result.failed)
print(result.errors)
```

The validator uses the package's default password policy unless a `PasswordRuleConfig` is supplied.

## Configure the password policy

```python
from password_validator import PasswordValidator
from password_validator.config.settings import PasswordRuleConfig

config = PasswordRuleConfig(
    min_length=12,
    max_length=64,
    require_uppercase=True,
    require_lowercase=True,
    require_digit=True,
    require_special=True,
    special_characters="!@#$%^&*()-_=+[]{}|;:'\",.<>?/`~",
)

validator = PasswordValidator(config=config)
result = validator.validate("MySecurePassword123!")
```

The package also supports environment-driven configuration. See [`docs/configuration.md`](docs/configuration.md).

## Password strength scoring

```python
from password_validator import PasswordStrengthScorer

scorer = PasswordStrengthScorer()
result = scorer.score("MySecurePassword123!")

print(result.score)
print(result.level)
print(result.metrics)
print(result.suggestion_message)
```

Strength scoring is independent of policy validation. A password can be policy-valid while still receiving a relatively low strength score, or vice versa.

See [`docs/strength-analysis.md`](docs/strength-analysis.md).

## Custom validation rules

Rules implement the `Rule` interface and return a `RuleResult`.

```python
from password_validator.rules.base import Rule, RuleResult


class NoUsernameRule(Rule):
    name = "no_username"

    def __init__(self, username: str):
        self.username = username

    def validate(self, password: str) -> RuleResult:
        if self.username.lower() in password.lower():
            return self._failed(
                message="Password must not contain the username",
                code="USERNAME_IN_PASSWORD",
            )

        return self._passed(message="Password does not contain the username")
```

You can pass custom rules directly to `PasswordValidator`:

```python
validator = PasswordValidator(rules=[NoUsernameRule("shuvo")])
result = validator.validate("MySecurePassword123!")
```

See [`docs/rules.md`](docs/rules.md) and [`docs/plugins.md`](docs/plugins.md).

## Documentation

- [`Installation`](docs/installation.md) — install, verify, development setup, testing, and packaging
- [`Configuration`](docs/configuration.md) — policy and strength configuration
- [`Rules`](docs/rules.md) — built-in rules and custom rule development
- [`Plugins and extensions`](docs/plugins.md) — extension model and integration guidance
- [`Validation`](docs/validation.md) — validation API and result objects
- [`Strength analysis`](docs/strength-analysis.md) — analyzers, scoring, metrics, and suggestions
- [`Architecture`](docs/architecture.md) — package design and responsibilities
- [`Testing`](docs/testing.md) — unit/integration testing and coverage
- [`Security`](docs/security.md) — secure usage and operational guidance
- [`Troubleshooting`](docs/troubleshooting.md) — common installation and development problems
- [`Contributing`](docs/contributing.md) — development workflow and contribution expectations

## Project layout

```text
password-validator/
├── config/
│   └── .env.example
├── docs/
├── examples/
├── src/
│   ├── password_validator/
│   │   ├── config/
│   │   ├── engine/
│   │   ├── loaders/
│   │   ├── rules/
│   │   ├── strength/
│   │   ├── constants.py
│   │   ├── enums.py
│   │   ├── exceptions.py
│   │   ├── models.py
│   │   └── version.py
│   └── plugins/
├── tests/
├── pyproject.toml
├── requirements-dev.txt
└── README.md
```

## Important security note

This library validates and analyzes passwords; it is **not a password storage system**. Never store plaintext passwords or log them. Application code should hash passwords using an appropriate password-hashing mechanism and should avoid placing credentials in exception messages, telemetry, traces, or request logs.

## License

MIT. See [`LICENSE`](LICENSE).

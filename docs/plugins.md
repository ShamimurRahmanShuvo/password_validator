# Plugins and Extensions

Password Validator Pro is designed to be extended without modifying the core rule implementations. The current repository's practical extension mechanism is the `Rule` abstraction and `RuleRegistry`.

## Important distinction

The repository contains a `src/plugins/` package, but the current `src/plugins/manager.py` does not implement a dynamic plugin-discovery mechanism such as Python package entry points.

Therefore, this documentation does **not** claim support for automatic third-party plugin discovery. The supported extension model is custom rule objects and explicit registration/composition.

## Extension model

A custom rule implements `Rule`:

```python
from password_validator.rules.base import Rule, RuleResult


class NoPersonalNameRule(Rule):
    name = "no_personal_name"

    def __init__(self, name: str):
        self.name_to_reject = name.lower()

    def validate(self, password: str) -> RuleResult:
        if self.name_to_reject in password.lower():
            return self._failed(
                message="Password must not contain the personal name",
                code="PERSONAL_NAME_IN_PASSWORD",
            )

        return self._passed()
```

## Registering an extension

Using `RuleRegistry`:

```python
from password_validator.rules.registry import RuleRegistry

registry = RuleRegistry()
registry.register(NoPersonalNameRule("shuvo"))
```

Or pass rules directly to the validator:

```python
from password_validator import PasswordValidator

validator = PasswordValidator(
    rules=[NoPersonalNameRule("shuvo")]
)
```

## Combining built-in and custom rules

Because an explicitly supplied `rules` sequence replaces the default rules, applications that need both sets should compose them intentionally.

For example:

```python
from password_validator.config.settings import PasswordRuleConfig
from password_validator.rules.length import LengthRule
from password_validator.rules.uppercase import UppercaseRule
from password_validator.rules.lowercase import LowercaseRule
from password_validator.rules.digits import DigitsRule
from password_validator.rules.special import SpecialCharacterRule

config = PasswordRuleConfig(min_length=12, max_length=64)

rules = [
    LengthRule(config.min_length, config.max_length),
    UppercaseRule(),
    LowercaseRule(),
    DigitsRule(),
    SpecialCharacterRule(config.special_characters),
    NoPersonalNameRule("shuvo"),
]
```

## Application-specific extensions

Typical custom rules include:

- username exclusion;
- email-address fragments;
- organization name exclusion;
- customer-specific blacklist checks;
- password-history checks;
- tenant-specific policy rules.

External services should be used carefully. A rule that calls a remote service can introduce latency, availability dependencies, and privacy concerns into the authentication path.

## What a rule should not do

A rule should not:

- write passwords to logs;
- persist the plaintext password;
- load `.env` files itself;
- mutate global configuration;
- calculate the global strength score;
- silently swallow configuration or service errors.

## Testing extensions

Every custom rule should have unit tests covering at least:

1. a password that should pass;
2. a password that should fail;
3. the rule name;
4. the failure code;
5. the failure message when applicable;
6. edge cases specific to the rule.

Then add an integration test if the rule participates in a larger application-level validation pipeline.

## Future dynamic plugin discovery

If automatic third-party plugin discovery is added in a future release, document the exact mechanism, package metadata, discovery contract, lifecycle, and compatibility policy here. Until such an API exists in the implementation, applications should use explicit rule composition.

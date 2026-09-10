# Validation API

The primary policy-validation entry point is `PasswordValidator`.

## Basic API

```python
from password_validator import PasswordValidator

validator = PasswordValidator()
result = validator.validate("MySecurePassword123!")
```

`validate()` returns a `ValidationResult`.

## ValidationResult

The result exposes:

| Attribute | Meaning |
|---|---|
| `valid` | `True` when no configured rule failed |
| `is_valid` | Read-only convenience property equivalent to `valid` |
| `passed` | Identifiers of rules that passed |
| `failed` | Identifiers of rules that failed |
| `errors` | Validation error objects/messages collected from failed rules |
| `rule_result` | Individual `RuleResult` objects |
| `rule_results` | Compatibility alias for `rule_result` |
| `error_count` | Number of errors, falling back to failed-rule count |
| `has_errors` | Whether one or more validation errors exist |
| `passed_count` | Number of passed rules |
| `failed_count` | Number of failed rules |

## Example

```python
result = validator.validate("password")

print(result.valid)
print(result.failed)
print(result.errors)
print(result.error_count)
```

## Inspect individual rule results

```python
for rule_result in result.rule_results:
    print(rule_result.rule_name)
    print(rule_result.passed)
    print(rule_result.message)
    print(rule_result.code)
```

Rule metadata is available when the individual rule supplies it:

```python
print(rule_result.metadata)
```

## Invalid input

`PasswordValidator.validate()` requires a string. Passing a non-string value raises:

```text
TypeError: Password must be a string
```

Validate application input before invoking the library if your API accepts arbitrary JSON or optional values.

## Policy result versus strength result

Do not use a strength score as a replacement for a password policy decision.

Use:

```python
validation = validator.validate(password)
```

for acceptance/rejection of the configured policy.

Use:

```python
strength = scorer.score(password)
```

for strength analysis and user guidance.

A recommended application flow is:

```python
validation = validator.validate(password)

if not validation.valid:
    # Return the policy errors to the caller.
    ...

strength = scorer.score(password)
# Optionally use strength.level or strength.score for UX or additional policy decisions.
```

## API stability

The public top-level package exports:

```python
from password_validator import (
    PasswordValidator,
    ValidationResult,
    PasswordStrengthScorer,
)
```

Package metadata is also exposed through `__version__`, `VERSION`, `__title__`, `__author__`, and `__description__`.

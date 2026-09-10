# FAQ

## Does validation automatically load `.env`?

`PasswordValidator()` builds a default `PasswordRuleConfig()` directly. To explicitly load environment-backed settings for both policy and strength, use `Settings.from_env()` and pass the resulting configuration objects to the validator/scorer.

## Can I use only the strength scorer?

Yes.

```python
from password_validator import PasswordStrengthScorer

result = PasswordStrengthScorer().score("MyPassword123!")
```

## Can I disable strength analysis?

Yes. Set `StrengthConfig.enabled=False` or configure `STRENGTH_ENABLED=false` when using environment-backed strength configuration.

## Can I add my own rule?

Yes. Implement `Rule` and pass the rule through `PasswordValidator(rules=[...])` or register it with `RuleRegistry` for application-level composition.

## Does the package automatically discover third-party plugins?

Not in the current implementation. The supported extension mechanism is explicit custom-rule composition/registration.

## Does the package hash passwords?

No. Password hashing and persistence belong to the application/security layer.

## Is estimated entropy cryptographic entropy?

No. It is a heuristic estimate used by the scoring system.

## What is the difference between a policy and strength score?

Policy validation is a deterministic pass/fail decision against configured rules. Strength scoring is a heuristic analysis that produces a numeric score, level, bonuses, penalties, and suggestions.

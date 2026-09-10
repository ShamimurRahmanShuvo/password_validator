# Architecture

The project uses a layered design that separates configuration, policy validation, strength analysis, and packaging concerns.

## Package structure

```text
src/
├── password_validator/
│   ├── __init__.py
│   ├── constants.py
│   ├── enums.py
│   ├── exceptions.py
│   ├── models.py
│   ├── version.py
│   ├── config/
│   │   └── settings.py
│   ├── loaders/
│   │   └── env_loader.py
│   ├── engine/
│   │   └── validator.py
│   ├── rules/
│   │   ├── base.py
│   │   ├── registry.py
│   │   ├── length.py
│   │   ├── uppercase.py
│   │   ├── lowercase.py
│   │   ├── digits.py
│   │   └── special.py
│   └── strength/
│       ├── config.py
│       ├── weights.py
│       ├── analyzer.py
│       ├── scorer.py
│       ├── suggestions.py
│       └── analyzers/
│           ├── repeat.py
│           ├── sequential.py
│           ├── keyboard.py
│           └── dictionary.py
├── plugins/
└── resources/
```

## Configuration layer

`config/settings.py` defines:

- `PasswordRuleConfig`
- `Settings`

`PasswordRuleConfig` describes policy requirements. `StrengthConfig` describes strength-analysis behavior.

## Environment layer

`EnvLoader` provides a small typed configuration interface:

- `get()`
- `get_bool()`
- `get_int()`
- `get_float()`
- `get_list()`

The loader reads a `.env` file when supplied and then overlays process environment variables.

## Validation engine

`PasswordValidator` is responsible for:

1. accepting policy configuration and/or an explicit rule sequence;
2. validating that the input is a string;
3. executing rules in order;
4. collecting passed and failed rule identifiers;
5. collecting error messages;
6. returning a `ValidationResult`.

It does not perform password-strength scoring.

## Rule layer

The rule layer provides:

- `Rule` — abstract rule contract;
- `RuleResult` — result produced by a rule;
- built-in rules;
- `RuleRegistry` — explicit rule registration and composition.

This design keeps individual policy checks independently testable.

## Strength layer

The strength subsystem separates detection from scoring:

```text
analyzers → StrengthAnalysis → scorer → StrengthResult
```

This allows pattern-detection logic to evolve independently of score weighting.

## Resource layer

The repository contains dictionary/common-password resources under `src/resources/`. Dictionary analysis can also use externally configured files.

## Models

`models.py` contains structured validation-domain objects such as `ValidationResult`, `ValidationError`, and a model-level `RuleResult` representation.

The engine itself uses the rule-layer `RuleResult` from `rules.base` when executing rules.

## Public API

The package's top-level API intentionally exposes the main entry points:

```python
from password_validator import PasswordValidator
from password_validator import ValidationResult
from password_validator import PasswordStrengthScorer
```

Lower-level classes remain importable from their respective modules for advanced use.

## Design principles

- Single responsibility for rules and analyzers.
- Explicit configuration injection.
- Environment configuration at the application/configuration boundary.
- Structured result objects instead of boolean-only responses.
- Separation between policy enforcement and strength analysis.
- No intentional password persistence in result metrics.
- `src/` layout for package isolation and modern build tooling.

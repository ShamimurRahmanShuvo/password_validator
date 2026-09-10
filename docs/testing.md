# Testing

The project contains unit and integration tests.

## Test structure

```text
tests/
├── unit/
│   ├── config/
│   ├── engine/
│   ├── rules/
│   ├── strength/
│   └── test_models.py
└── integration/
    ├── config/
    ├── engine/
    ├── rules/
    └── strength/
```

## Run all tests

```bash
python -m pytest
```

## Unit tests

```bash
python -m pytest tests/unit
```

Unit tests cover individual configuration objects, rules, analyzers, scoring components, and model behavior.

## Integration tests

```bash
python -m pytest tests/integration
```

Integration tests exercise larger flows such as:

- settings loaded from environment configuration;
- validation using configured rules;
- rule integration;
- strength analyzer integration;
- dictionary integration;
- strength scoring integration;
- end-to-end validation and strength analysis.

## Coverage

```bash
python -m pytest --cov=password_validator --cov-report=term-missing
```

For an HTML report:

```bash
python -m pytest --cov=password_validator --cov-report=html
```

The report is generated under `htmlcov/`.

## Development quality tools

The repository includes configuration/dependencies for:

- pytest
- pytest-cov
- Black
- Flake8
- mypy

Run the tools according to your CI/release policy. Example commands:

```bash
black src tests
flake8 src tests
mypy src
```

If a repository-specific CI configuration is introduced later, that CI workflow should be treated as the authoritative quality gate.

## Test interpreter

When multiple Python installations are present, use:

```bash
python -m pytest
```

instead of relying on a global `pytest` executable. This ensures pytest runs under the active virtual environment's Python interpreter.

## What to test when adding a rule

A new rule should normally have:

- pass case;
- fail case;
- boundary cases;
- invalid configuration cases where applicable;
- correct rule name;
- correct failure code;
- correct message/metadata where applicable;
- integration coverage if the rule is part of the default pipeline.

## What to test when changing configuration

Test:

- default values;
- environment loading;
- process-environment override behavior;
- invalid type conversion;
- invalid policy combinations;
- integration with the validator or scorer.

## What to test when changing strength scoring

Test:

- score bounds;
- strength-level boundaries;
- analyzer enable/disable behavior;
- bonus/penalty calculations;
- suggestions;
- custom weights;
- representative strong and weak passwords.

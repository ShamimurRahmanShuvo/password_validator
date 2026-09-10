# Contributing

Contributions should preserve the package's separation between policy validation, configuration, and strength analysis.

## Development setup

```bash
git clone https://github.com/ShamimurRahmanShuvo/password-validator.git
cd password-validator
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
python -m pip install -r requirements-dev.txt
```

## Before submitting changes

Run:

```bash
python -m pytest
python -m pytest --cov=password_validator --cov-report=term-missing
```

Run the repository's formatting/lint/type-checking tools where applicable:

```bash
black src tests
flake8 src tests
mypy src
```

## Adding a validation rule

1. Create a rule under `src/password_validator/rules/`.
2. Inherit from `Rule`.
3. Give the rule a stable `name`.
4. Return `RuleResult` through `_passed()` or `_failed()`.
5. Add focused unit tests.
6. Add integration coverage if the default validation pipeline uses the rule.
7. Update `docs/rules.md`.

## Adding a strength analyzer

Keep detection logic in its analyzer module. Return a structured analysis object and integrate it into `StrengthAnalysis` and the scorer only where necessary.

Add unit tests for the analyzer and integration tests for the complete pipeline.

## Configuration changes

When adding configuration:

- define an explicit typed field;
- provide a documented default;
- load it through `EnvLoader` if environment configuration is supported;
- document the environment variable;
- test default and overridden values;
- test invalid input where applicable.

## Security-sensitive changes

Never add logging of plaintext passwords. Do not add telemetry that contains password values. Document any new external dependency or data flow that handles password-related information.

## Documentation changes

Update documentation whenever public behavior changes. At minimum, update the relevant API/configuration/rules/strength documentation and the README when the change affects the main user workflow.

## Release checklist

- Tests pass.
- Coverage is reviewed.
- Documentation is current.
- Changelog is updated.
- Version metadata is consistent.
- Distribution builds successfully with `python -m build`.
- Built artifacts are inspected before publication.

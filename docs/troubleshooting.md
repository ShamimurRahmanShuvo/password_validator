# Troubleshooting

## `ModuleNotFoundError: No module named 'password_validator'`

The project uses a `src/` layout. Install the package into the active environment:

```bash
python -m pip install -e .
```

Then verify:

```bash
python -c "import password_validator; print(password_validator.__version__)"
```

Do not fix a packaging problem by adding arbitrary source directories to `sys.path` in application code.

## `pytest` is using the wrong Python version

Check:

```bash
python --version
python -m pytest --version
```

Use:

```bash
python -m pytest
```

rather than a globally installed `pytest` executable.

This is especially important when multiple Python versions are installed on macOS or Linux.

## Invalid environment value

`EnvLoader` converts environment variables to typed values.

For example:

```text
PASSWORD_MIN_LENGTH=abc
```

is invalid because the setting requires an integer.

Boolean values must use one of the supported true/false representations described in [`configuration.md`](configuration.md).

## Invalid password policy

If:

```python
PasswordRuleConfig(min_length=20, max_length=10).validate()
```

is used, configuration validation raises `ValueError` because the maximum length cannot be smaller than the minimum length.

Likewise, an empty special-character set is invalid when special characters are required.

## `SpecialCharacterRule` constructor error

The rule requires an explicit character set:

```python
SpecialCharacterRule("!@#$")
```

When using `PasswordValidator` with normal policy configuration, the validator supplies `config.special_characters` automatically.

## Custom rules are replacing built-in rules

This is intentional when passing `rules=`:

```python
PasswordValidator(rules=[MyCustomRule()])
```

The explicit sequence is used instead of the automatically constructed default rules.

If you need built-in and custom rules together, compose the complete sequence explicitly. See [`rules.md`](rules.md).

## Strength analysis is disabled

If `StrengthConfig.enabled` is `False`, the analyzer returns empty analysis objects.

Check:

```text
STRENGTH_ENABLED=true
```

or inspect the `StrengthConfig` instance supplied to `PasswordStrengthScorer`.

## Dictionary file is not found

If an external dictionary path is configured, verify:

- the path exists;
- the process has permission to read it;
- the path points to a file rather than a directory;
- the configuration contains the intended path.

## Scores do not match expectations

Strength scoring is configurable and combines a base score with bonuses and penalties. Inspect:

```python
result.score
result.metrics
result.bonuses
result.penalties
result.total_bonus
result.total_penalty
```

Also verify that your environment has not overridden the default `StrengthWeights`.

## Policy-valid but weak

This is possible and expected. Policy validation answers:

> Does the password satisfy the configured requirements?

Strength analysis answers:

> How strong does the configured heuristic scoring system consider the password?

Use the appropriate result for each application decision.

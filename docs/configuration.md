# Configuration

Password Validator Pro has two configuration domains:

- `PasswordRuleConfig` controls **password policy validation**.
- `StrengthConfig` controls **password strength analysis and scoring**.

The two systems are intentionally separate.

## Configuration sources

The package supports explicit Python configuration and environment-based configuration.

### Explicit Python configuration

```python
from password_validator.config.settings import PasswordRuleConfig

config = PasswordRuleConfig(
    min_length=12,
    max_length=64,
    require_uppercase=True,
    require_lowercase=True,
    require_digit=True,
    require_special=True,
)
```

### Environment configuration

`Settings.from_env()` loads both policy and strength settings:

```python
from password_validator.config.settings import Settings

settings = Settings.from_env(".env")
```

The result contains:

```python
settings.rules
settings.strength
```

Environment values are loaded from the specified `.env` file and then process environment variables are applied, so process environment values take precedence.

## Password policy configuration

`PasswordRuleConfig` currently exposes these fields:

| Field | Default | Purpose |
|---|---:|---|
| `min_length` | `8` | Minimum password length |
| `max_length` | `128` in the dataclass | Maximum password length when constructed directly |
| `require_uppercase` | `True` | Require at least one uppercase character |
| `require_lowercase` | `True` | Require at least one lowercase character |
| `require_digit` | `True` | Require at least one digit |
| `require_special` | `True` | Require at least one configured special character |
| `special_characters` | package-defined set | Characters accepted by `SpecialCharacterRule` |

### Important default distinction

The source currently defines `PasswordRuleConfig.max_length` as `128`, while the constants and the repository `.env.example` use `64` as the default maximum. If you need deterministic behavior across explicit Python construction and environment configuration, set `PASSWORD_MAX_LENGTH` explicitly or construct `PasswordRuleConfig(max_length=...)` explicitly.

## Policy environment variables

The variables consumed by `PasswordRuleConfig.from_env()` are:

| Variable | Type | Default source |
|---|---|---|
| `PASSWORD_MIN_LENGTH` | integer | `DEFAULT_MIN_LENGTH` (`8`) |
| `PASSWORD_MAX_LENGTH` | integer | `DEFAULT_MAX_LENGTH` (`64`) |
| `PASSWORD_REQUIRE_UPPERCASE` | boolean | `True` |
| `PASSWORD_REQUIRE_LOWERCASE` | boolean | `True` |
| `PASSWORD_REQUIRE_DIGIT` | boolean | `True` |
| `PASSWORD_REQUIRE_SPECIAL` | boolean | `True` |
| `PASSWORD_SPECIAL_CHARACTERS` | string | package default special-character set |

Boolean values accepted by `EnvLoader` include `true`, `1`, `yes`, `y`, and `on` for true, and `false`, `0`, `no`, `n`, and `off` for false.

Integer and floating-point values are converted to their respective types. Invalid values raise `InvalidConfigurationValue`.

## Policy validation

Before the policy is used by `Settings.from_env()`, it is validated.

The current policy validation rejects:

- `min_length < 1`
- `max_length < min_length`
- an empty `special_characters` value when `require_special=True`

## Strength configuration

`StrengthConfig` controls the strength-analysis pipeline.

### Analyzer switches

| Field | Default |
|---|---:|
| `enabled` | `True` |
| `check_repeated_characters` | `True` |
| `check_sequential_patterns` | `True` |
| `check_keyboard_patterns` | `True` |
| `check_dictionary_words` | `True` |
| `check_common_passwords` | `True` |
| `check_horizontal` | `True` |
| `check_vertical` | `True` |
| `check_diagonal` | `True` |
| `check_number_row` | `True` |
| `check_consecutive` | `True` |
| `check_repeated_groups` | `True` |
| `check_character_frequency` | `True` |

### Repeat analysis

| Field | Default |
|---|---:|
| `max_consecutive_repeat` | `2` |
| `min_repeated_group_length` | `2` |
| `min_group_repetitions` | `2` |
| `max_character_frequency` | `0.33` |

### Sequential analysis

| Field | Default |
|---|---:|
| `check_uppercase` | `True` |
| `check_lowercase` | `True` |
| `check_digits` | `True` |
| `check_mixed` | `False` |
| `min_sequence_length` | `4` |

### Keyboard analysis

| Field | Default |
|---|---:|
| `min_pattern_length` | `4` |

The analyzer can check horizontal, vertical, diagonal, and number-row keyboard patterns.

### Dictionary analysis

| Field | Default |
|---|---:|
| `dictionary_file` | `None` |
| `common_password_file` | `None` |
| `min_dictionary_word_length` | `4` |
| `case_insensitive` | `True` |
| `leet_normalization` | `True` |

The repository contains built-in resource files under `src/resources/`. Explicit external dictionary paths can be supplied through the strength configuration.

## Strength environment variables

The environment names consumed by `StrengthConfig.from_env()` include:

```text
STRENGTH_ENABLED
STRENGTH_CHECK_REPEATED_CHARACTERS
STRENGTH_CHECK_SEQUENTIAL
STRENGTH_CHECK_KEYBOARD_PATTERNS
STRENGTH_CHECK_COMMON_PASSWORDS
STRENGTH_CHECK_DICTIONARY
STRENGTH_CHECK_HORIZONTAL
STRENGTH_CHECK_VERTICAL
STRENGTH_CHECK_DIAGONAL
STRENGTH_CHECK_NUMBER_ROW
STRENGTH_CHECK_CONSECUTIVE
STRENGTH_CHECK_REPEATED_GROUPS
STRENGTH_CHECK_CHARACTER_FREQUENCY
STRENGTH_MAX_CONSECUTIVE_REPEAT
STRENGTH_MIN_REPEAT_GROUP_LENGTH
STRENGTH_MIN_GROUP_REPETITIONS
STRENGTH_MAX_CHARACTER_FREQUENCY
STRENGTH_CHECK_UPPERCASE
STRENGTH_CHECK_LOWERCASE
STRENGTH_CHECK_DIGITS
STRENGTH_CHECK_MIXED
STRENGTH_MIN_SEQUENCE_LENGTH
STRENGTH_MIN_KEYBOARD_PATTERN_LENGTH
STRENGTH_DICTIONARY_FILE
STRENGTH_COMMON_PASSWORD_FILE
STRENGTH_MIN_DICTIONARY_WORD_LENGTH
STRENGTH_DICTIONARY_CASE_INSENSITIVE
STRENGTH_DICTIONARY_LEET_NORMALIZATION
STRENGTH_OVERALL_SEVERITY
```

## Strength scoring weights

`StrengthWeights` contains configurable penalty and bonus values.

### Penalties

```text
STRENGTH_WEIGHT_REPEATED_CHARACTER
STRENGTH_WEIGHT_SEQUENTIAL_PATTERN
STRENGTH_WEIGHT_KEYBOARD_PATTERN
STRENGTH_WEIGHT_DICTIONARY_PATTERN
```

### Bonuses

```text
STRENGTH_WEIGHT_LENGTH_12_PLUS
STRENGTH_WEIGHT_LENGTH_16_PLUS
STRENGTH_WEIGHT_CHARACTER_DIVERSITY
STRENGTH_WEIGHT_ALL_CHARACTER_CLASSES
STRENGTH_WEIGHT_HIGH_ENTROPY
```

The built-in `StrengthWeights` defaults are:

| Weight | Default |
|---|---:|
| repeated character | 15 |
| sequential pattern | 15 |
| keyboard pattern | 15 |
| dictionary pattern | 15 |
| length 12+ | 5 |
| length 16+ | 5 |
| character diversity | 5 |
| all character classes | 5 |
| high entropy | 5 |

## Complete configuration example

```python
from password_validator.config.settings import Settings
from password_validator import PasswordValidator, PasswordStrengthScorer

settings = Settings.from_env(".env")

validator = PasswordValidator(config=settings.rules)
scorer = PasswordStrengthScorer(config=settings.strength)

validation = validator.validate("MySecurePassword123!")
strength = scorer.score("MySecurePassword123!")
```

## Configuration best practices

- Keep environment-specific configuration outside source code.
- Do not commit private `.env` files.
- Prefer explicit values for production policies so behavior is reproducible.
- Validate configuration at application startup rather than on every password request.
- Keep policy configuration and strength configuration conceptually separate.

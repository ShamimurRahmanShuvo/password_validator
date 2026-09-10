# Password Strength Analysis

Strength analysis is a separate subsystem from password policy validation.

The pipeline is:

```text
Password
   │
   ▼
StrengthAnalyzer
   │
   ├── DictionaryAnalyzer
   ├── RepeatAnalyzer
   ├── SequentialAnalyzer
   └── KeyboardAnalyzer
   │
   ▼
StrengthAnalysis
   │
   ▼
PasswordStrengthScorer
   │
   ├── metrics
   ├── bonuses
   ├── penalties
   ├── score
   ├── strength level
   └── suggestions
```

## Basic usage

```python
from password_validator import PasswordStrengthScorer

scorer = PasswordStrengthScorer()
result = scorer.score("MySecurePassword123!")

print(result.score)
print(result.level.value)
print(result.metrics)
print(result.suggestion_message)
```

## StrengthResult

`StrengthResult` contains:

- `score` — final score from 0 to 100;
- `level` — a `StrengthLevel` enum value;
- `metrics` — password composition metrics;
- `analysis` — results from the individual analyzers;
- `bonuses` — positive scoring contributions;
- `penalties` — negative scoring contributions;
- `suggestions` — user-facing improvement suggestions.

Convenience properties:

- `is_strong`
- `is_weak`
- `suggestion_message`
- `total_bonus`
- `total_penalty`

## Strength levels

The scorer currently maps the numeric score as follows:

| Score | Level |
|---:|---|
| `< 20` | `VERY_WEAK` |
| `20–39.99` | `WEAK` |
| `40–59.99` | `FAIR` |
| `60–79.99` | `STRONG` |
| `80–100` | `VERY_STRONG` |

## Metrics

`PasswordMetrics` contains:

- `length`
- `has_lowercase`
- `has_uppercase`
- `has_digit`
- `has_special`
- `unique_character_count`
- `character_diversity`
- `estimated_entropy`
- `character_classes`

The metrics object does not store the plaintext password.

## Estimated entropy

The implementation calculates an **estimated** entropy value based on the character-pool categories detected in the password and the password length.

This is not a cryptographically rigorous measurement of real-world password entropy. It should be treated as a heuristic metric used by this scoring system, not as a guarantee of resistance to guessing or cracking.

## Individual analyzers

### RepeatAnalyzer

Detects repeated-character and repeated-group patterns according to `StrengthConfig`.

Relevant configuration includes:

```text
max_consecutive_repeat
min_repeated_group_length
min_group_repetitions
check_character_frequency
max_character_frequency
```

### SequentialAnalyzer

Detects sequential character patterns.

Relevant configuration includes:

```text
min_sequence_length
check_uppercase
check_lowercase
check_digits
check_mixed
```

### KeyboardAnalyzer

Detects keyboard walks and related patterns.

Relevant configuration includes:

```text
min_pattern_length
check_horizontal
check_vertical
check_diagonal
check_number_row
```

### DictionaryAnalyzer

Checks dictionary words and common passwords. It supports optional external source files, case-insensitive matching, and leet normalization.

Relevant configuration includes:

```text
dictionary_file
common_password_file
min_dictionary_word_length
case_insensitive
leet_normalization
```

## Suggestions

`SuggestionGenerator` converts analyzer findings into prioritized recommendations.

Examples include recommendations to:

- increase password length;
- avoid repeated characters or groups;
- avoid sequential characters;
- avoid keyboard patterns;
- avoid common passwords;
- avoid dictionary words;
- increase character diversity.

Suggestions are ordered by priority.

## Configuring scoring weights

`StrengthWeights` allows applications to tune scoring contributions through environment variables.

Penalty weights:

```text
STRENGTH_WEIGHT_REPEATED_CHARACTER
STRENGTH_WEIGHT_SEQUENTIAL_PATTERN
STRENGTH_WEIGHT_KEYBOARD_PATTERN
STRENGTH_WEIGHT_DICTIONARY_PATTERN
```

Bonus weights:

```text
STRENGTH_WEIGHT_LENGTH_12_PLUS
STRENGTH_WEIGHT_LENGTH_16_PLUS
STRENGTH_WEIGHT_CHARACTER_DIVERSITY
STRENGTH_WEIGHT_ALL_CHARACTER_CLASSES
STRENGTH_WEIGHT_HIGH_ENTROPY
```

## Disabled analysis

When `StrengthConfig.enabled` is `False`, `StrengthAnalyzer` returns empty analysis objects rather than running the individual analyzers.

## Operational guidance

Strength scoring should generally be treated as a user-experience and risk-signal feature. If your organization has a security policy requiring a minimum strength threshold, define that threshold explicitly at the application layer and test it against representative passwords.

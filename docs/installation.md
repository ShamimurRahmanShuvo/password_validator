# Installation and Getting Started

This guide takes a new developer from a clean checkout to a working password-validator installation, then through development, testing, building, and publishing.

## 1. Requirements

The package declares:

- Python **3.10 or newer**
- `python-dotenv >= 1.2.2`

The project is configured for Python 3.10, 3.11, 3.12, 3.13, and 3.14.

For development, the repository also provides `requirements-dev.txt`, which contains the testing, coverage, formatting, linting, type-checking, and build tools used by the project.

## 2. Clone the repository

```bash
git clone https://github.com/ShamimurRahmanShuvo/password-validator.git
cd password-validator
```

## 3. Create a virtual environment

Create an isolated environment for the project:

```bash
python3 -m venv .venv
```

Activate it on macOS/Linux:

```bash
source .venv/bin/activate
```

Activate it on Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

Verify the interpreter:

```bash
python --version
python -m pip --version
```

Always prefer `python -m pip` and `python -m pytest` so the commands use the interpreter from the active environment.

## 4. Install the package

### Normal installation

```bash
python -m pip install .
```

### Editable installation for development

```bash
python -m pip install -e .
```

Editable installation is recommended when developing the package because changes under `src/` are immediately available without reinstalling the project.

## 5. Verify the installation

```bash
python -c "import password_validator; print(password_validator.__version__)"
```

The current project version is `1.0.0`.

You can also verify the main API:

```bash
python -c "from password_validator import PasswordValidator; print(PasswordValidator().validate('MySecurePassword123!').valid)"
```

## 6. Environment configuration

The repository includes:

```text
config/.env.example
```

Copy it to a local `.env` file when you want environment-driven configuration. Do not commit a production `.env` file containing secrets or application-specific private data.

The configuration loader reads values from the `.env` file and then loads the process environment. Process environment values override values loaded from the file.

See [`configuration.md`](configuration.md) for the complete configuration reference.

## 7. First validation

```python
from password_validator import PasswordValidator

validator = PasswordValidator()
result = validator.validate("MySecurePassword123!")

if result.valid:
    print("Password accepted")
else:
    print("Password rejected")
    for error in result.errors:
        print(error)
```

## 8. First strength analysis

```python
from password_validator import PasswordStrengthScorer

scorer = PasswordStrengthScorer()
result = scorer.score("MySecurePassword123!")

print("Score:", result.score)
print("Level:", result.level.value)
print("Suggestions:", result.suggestion_message)
```

## 9. Development dependencies

Install the development dependencies with:

```bash
python -m pip install -r requirements-dev.txt
```

The development requirements include pytest, pytest-cov, Black, Flake8, mypy, build, and twine.

## 10. Run tests

Run the complete test suite:

```bash
python -m pytest
```

Run unit tests only:

```bash
python -m pytest tests/unit
```

Run integration tests only:

```bash
python -m pytest tests/integration
```

Run with coverage:

```bash
python -m pytest --cov=password_validator --cov-report=term-missing
```

See [`testing.md`](testing.md).

## 11. Build the distribution

Install the build frontend if necessary:

```bash
python -m pip install build
```

Build source and wheel distributions:

```bash
python -m build
```

The generated artifacts are placed in `dist/`.

Inspect the distribution before release and verify that the package contains the expected Python modules and resource files.

## 12. Publish a release

Before publishing:

1. Update the version in `src/password_validator/version.py` and project metadata as required by the release process.
2. Update `CHANGELOG.md`.
3. Run the full test suite.
4. Run coverage and quality checks.
5. Build the package with `python -m build`.
6. Inspect the wheel and source distribution.
7. Upload to the intended package index using the project's release credentials.

For example, after configuring a trusted publishing or repository credential workflow, the repository's release process can use `twine upload dist/*`.

Never place package-index credentials directly in source control.

## 13. Source-layout import behavior

The project uses the standard `src/` layout:

```text
src/password_validator/
```

After an editable or normal installation, import the package as:

```python
import password_validator
```

Do not rely on importing from `src.password_validator` in application code.

## 14. Production installation

For an application deployment, install the released package into the application's own virtual environment:

```bash
python -m pip install password-validator-s
```

Pin the package version in the application's dependency management process when reproducibility is required.

## 15. Recommended production checklist

- Use a supported Python version.
- Install into an isolated environment.
- Pin production dependencies according to your deployment policy.
- Keep `.env` files and private configuration out of source control.
- Do not log plaintext passwords.
- Run validation and strength analysis only on the password value that must be processed.
- Hash passwords before persistence using a password-hashing solution appropriate to your application.
- Test your application's policy configuration separately from the library's own test suite.

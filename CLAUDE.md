# Project Rules

## Hints

- Factorize common code
- Split big classes and methods into smaller parts
- Add at least one relevant test when fixing a bug

## Toolchain

- **uv** is the Python package manager. Use `uv sync --all-extras --dev` to install dependencies.
- **ruff** is the Python linter and formatter (`ruff check blocksnoop/`, `ruff format blocksnoop/`).
- **ty** is the Python type checker (`ty check blocksnoop/`).
- **pytest** runs tests. Unit tests need no special setup; integration tests require Docker and are marked with `@pytest.mark.docker`.

## Verification

Always:

- keep README up to date
- run these checks before considering work done:

```bash
# Unit tests (fast, no root/Docker needed)
uv run --extra dev pytest tests/ -v --ignore=tests/integration

# Python lint + format + type check
ruff check blocksnoop/ tests/
ruff format --check blocksnoop/ tests/
ty check blocksnoop/
```

Integration tests (require Docker):

```bash
uv run --extra dev pytest -m docker tests/integration/ -v
```

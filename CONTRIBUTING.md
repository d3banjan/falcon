# Contributing

## Setup

This project uses [uv](https://docs.astral.sh/uv/) for dependency management.

```bash
cd falcon
uv sync --all-groups
```

This installs the package in editable mode plus all dev and test dependencies.

## Running tests

```bash
uv run pytest tests/ -q
```

Expected: 95 passed, 3 xfailed.

## Running the CLI

```bash
uv run pickle-secure --version
uv run pickle-secure init --profile=strict --dry-run
uv run pickle-secure audit tests/ --json
```

## Type checking

```bash
uv run mypy --strict tests/fixtures/
uv run pyright --warnings tests/
```

## Linting

```bash
uv run ruff check src/ tests/
```

## Security benchmark

```bash
cd tests/comparison
./run_benchmark.sh
python analyze_results.py
```

## Commit style

- `feat:` — new feature or stub addition
- `fix:` — bug fix
- `test:` — test-only change
- `docs:` — documentation change
- `chore:` — build, CI, dependency changes

## Project structure

- `src/pickle_stubs_secure/` — runtime + CLI
- `pickle-stubs/` — PEP 561 stub package
- `stubs/` — mypy_path overlay (canonical source)
- `tests/` — test suite
- `docs/` — architecture and design docs
- `lean/` — formal verification model (separate effort, do not modify)

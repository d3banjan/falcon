# Agent Instructions

## Project

`pickle-stubs-secure` — maximum-strict mypy stubs that make every `pickle.loads` call a type error.

## Build & Test

```bash
cd falcon
uv sync --all-groups
uv run pytest tests/ -q          # expected: 93 passed, 3 xfailed
uv run mypy --strict tests/fixtures/
uv run pyright --warnings tests/
uv run ruff check src/ tests/
```

## Key conventions

- Use `uv run` for all Python commands
- Use `uv run ruff check --fix <file>` before committing Python changes
- Do not modify `lean/` — it belongs to another agent
- Stubs live in `stubs/` (canonical) and `pickle-stubs/` (PEP 561 package). Keep them in sync.
- Runtime + CLI code lives in `src/pickle_stubs_secure/`
- Tests use `shutil.which()` to find mypy/pyright (not hardcoded `uv run`)

## Where things live

| Concern | Location |
|---------|----------|
| Type stubs (canonical) | `stubs/*.pyi` |
| PEP 561 stub package | `pickle-stubs/*.pyi` |
| Runtime + CLI | `src/pickle_stubs_secure/` |
| CLI entry point | `src/pickle_stubs_secure/cli/main.py` |
| Tests | `tests/` |
| CI | `.github/workflows/ci.yml` |
| Architecture docs | `docs/architecture.md` |
| Lean formalization | `lean/` (DO NOT MODIFY) |

## Common tasks

Add a new pickle API to stubs:
1. Edit `stubs/_pickle.pyi` and `stubs/pickle.pyi`
2. Copy changes to `pickle-stubs/`
3. Add fixture in `tests/fixtures/`
4. Add test in `tests/corpus/`

Add a new CLI subcommand:
1. Add parser in `src/pickle_stubs_secure/cli/main.py`
2. Implement logic in new module under `src/pickle_stubs_secure/cli/`
3. Add tests in `tests/cli/`

## Known issues

- `disjoint_base` missing from `_pickle.pyi` (waiting for mypy update)
- Strict-profile integration test TBD: verify strict config catches more leaks end-to-end

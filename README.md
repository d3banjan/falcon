# pickle-stubs-secure

[![CI](https://github.com/d3banjan/falcon/actions/workflows/ci.yml/badge.svg)](https://github.com/d3banjan/falcon/actions/workflows/ci.yml)

Maximum-strict mypy stubs for Python's `pickle` and `shelve` modules. Every deserialization call site becomes a mypy type error.

## Scope

### pickle module

- `pickle.loads`, `pickle.load` → `Unsafe[Any]`
- `pickle.Unpickler.load` → `Unsafe[Any]`
- `_pickle.loads`, `_pickle.load` → `Unsafe[Any]` (C accelerator mirror)
- `_pickle.Unpickler.load` → `Unsafe[Any]`
- Serialize-only APIs (`dump`, `dumps`, `Pickler`) — unchanged, safe.

### shelve module

- `shelve.Shelf.__getitem__()` → `Unsafe[Any]`
- `shelve.Shelf.get()` → `Unsafe[Any]`
- `shelve.Shelf.values()` → `ValuesView[Unsafe[Any]]`
- `shelve.Shelf.items()` → `ItemsView[str, Unsafe[Any]]`
- Write operations (`__setitem__`, `sync`, `close`, `keys()`) — unchanged, safe.

## Quickstart

```bash
pip install pickle-stubs-secure
```

PEP 561 stub package auto-shadows typeshed. No `MYPYPATH` needed for pyright; mypy requires `mypy_path` (see `pickle-secure init` below).

Run mypy strict:

```bash
mypy --strict your_code.py
```

Any call to a deserialization API will produce a type error referencing `Unsafe[Any]`.

## Escape Hatch: cast() Auditing

Rev2 uses `cast(T, expr)` as an auditable escape hatch. Tag casts with `# trust: TAG [reason]` comments and enforce policy via `pickle-secure audit`:

```python
from typing import cast
import pickle
import shelve

# Pickle cast
data = cast(dict, pickle.loads(b"x"))  # trust: legacy-migration reason text here

# Shelve cast
shelf = shelve.open("data.db")
value = cast(dict, shelf["key"])  # trust: legacy-migration reason text here
```

Run audit:

```bash
pickle-secure audit . --by-tag
```

Configure policy in `pyproject.toml`:

```toml
[tool.pickle_secure]
allow_tags = ["general", "legacy-migration"]
deny_tags = []
require_reason = ["legacy-migration"]
unknown_tag = "error"
```

## Strict Profile

Harden your project with a single command:

```bash
pickle-secure init --profile=strict --write-precommit
```

Applies:

- **Mypy**: `disallow_any_*`, `warn_return_any`, `warn_unused_ignores`, `no_implicit_reexport`
- **Pyright**: `reportAny = "error"`, `reportImplicitAny = "error"`, etc.
- **Ruff**: `PGH003` (blank type-ignore), `S301` (pickle warning), `B009`/`B010` (getattr/setattr)
- **pickle-secure policy**: `allow_tags = ["general"]`, `deny_tags = ["legacy-migration"]`, stricter defaults
- **Pre-commit hooks**: mypy + ruff + `pickle-secure audit .` (blocks commit if violations)

Closes ~80% of leak surface (Any, type-ignore, dynamic getattr, blank casts). `cast()` remains the auditable escape.

## Feature Showcase: Allowlist Bypass Demo

This project includes a demonstration of why runtime allowlists (like the CPython `RestrictedUnpickler` pattern) are insufficient, and how static analysis with stubs catches what they miss.

See `tests/feature/test_allowlist_bypass_demo.py` for:

1. **Gadget chain bypasses**: Demonstrations of how `__setstate__` on dict subclasses and built-in function abuse bypass allowlists
2. **Runtime RCE proof**: Both techniques bypass `RestrictedUnpickler` with strict allowlists
3. **Static analysis catch**: Stubs still flag all deserialization as `Unsafe[Any]` — "caught what allowlist missed"
4. **Educational value**: Inline documentation explains why allowlists fail and why static analysis is necessary

This demonstrates that even sophisticated runtime restrictions have blind spots around state restoration protocols and method dispatch that our stubs catch at type-check time.

## Documented Soundness Holes

These bypass the stub-level check (marked `xfail` in `tests/leaks/`):

- `cast(dict, pickle.loads(b))` — type laundering via `cast`
- `x: Any = pickle.loads(b)` — `Any` annotation absorbs `Unsafe`
- `getattr(pickle, "loads")(b)` — dynamic attribute dispatch

These are inherent mypy/`Any` limits, not stub-design failures.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT

# pickle-stubs-secure

[![CI](https://github.com/d3banjan/falcon/actions/workflows/ci.yml/badge.svg)](https://github.com/d3banjan/falcon/actions/workflows/ci.yml)

Maximum-strict type-stub hardening for **deserialization** (pickle-family surfaces), with an auditable escape hatch via `typing.cast`.

## 30-second pitch

`pickle-stubs-secure` makes dangerous deserialization calls type errors in `mypy`/`pyright`.  
If you intentionally trust data, you must add `cast(...)` and annotate that trust with `# trust:` for audit.

Supported scopes:

- `pickle` / `_pickle`
- `shelve`
- `numpy.load` (unsafe when `allow_pickle=True`)

## Install

```bash
pip install pickle-stubs-secure
```

## One-shot launch mode (strict profile)

```bash
cd /path/to/project
pickle-secure init --profile=strict --write-precommit
pickle-secure audit .
```

Then run your normal checker:

```bash
mypy --strict .
pyright .
```

## Scope shipped

### `pickle` / `_pickle`
- `pickle.load`, `pickle.loads`, `pickle.Unpickler.load`
- `_pickle.load`, `_pickle.loads`, `_pickle.Unpickler.load`

All return `Unsafe[Any]` in our stubs.  
Safe-serialization APIs (`dump`, `dumps`, `Pickler`) are unchanged.

### `shelve`
- `Shelf.__getitem__()`
- `Shelf.get()`
- `Shelf.values()`
- `Shelf.items()`

These read paths are treated as `Unsafe[Any]` variants.

### `numpy`
- `numpy.load(..., allow_pickle=True)` is modeled as `Unsafe[Any]`
- `numpy.load(..., allow_pickle=False | omitted)` remains `Any` to respect NumPy’s safe default

This is the first external-scope extension.

## Example: strict errors + explicit audit trail

```python
from typing import cast
import pickle
import numpy as np

data1 = pickle.loads(payload)                      # type error
data2 = cast(dict, pickle.loads(payload))           # allowed only with audited trust comment
data3 = cast(dict, pickle.loads(payload))  # trust: migration-reason

arr = np.load("model.bin", allow_pickle=True)       # type error
arr = cast(dict, np.load("model.bin", allow_pickle=True))  # trust: cta-review reason
```

## Escape hatch policy

Tag casts with:

```python
# trust: TAG [reason]
```

Example:

```bash
pickle-secure audit src/ --by-tag
```

Config lives in:

```toml
[tool.pickle_secure]
allow_tags = ["general", "test-fixture", "migration"]
deny_tags = ["legacy-migration"]
require_reason = ["legacy-migration", "migration"]
unknown_tag = "error"
```

## Launch readiness (done/required)

Done:

- Strict profile configuration (`mypy`, `pyright`, `ruff`, pre-commit template)
- `pickle`, `_pickle`, `shelve`, and `numpy.load` scope now represented
- CI coverage for checker matrix + runtime fixture suite
- Audit CLI + tag policy enforcement
- Comparison report and CVE workflow present

To publish:

- Reserve/publish package tag `v0.1.0` from current build
- Run `python -m build` + `twine check dist/*`
- Run `twine upload dist/*` from clean release environment

## Feature spotlight

- Allowlist-bypass demo remains in `tests/feature/test_allowlist_bypass_demo.py`
- Shows static stubs catch runtime allowlist blindspots (`RestrictedUnpickler` patterns)

## CVE evidence workflow

See `docs/cve-database.md` and `cve_db/libraries/`.  
Records capture catchability, CWE linkage, and validation state across tools.

## Related docs

- [docs/cve-database.md](docs/cve-database.md)
- [docs/launch-quiz.md](docs/launch-quiz.md)
- [pickle-stubs-secure-plan/PLAN.md](pickle-stubs-secure-plan/PLAN.md)

## License

MIT
